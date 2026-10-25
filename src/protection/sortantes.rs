//! Qui parle à Internet ? Les connexions établies de cet ordinateur vers Internet, regroupées par programme, avec le
//! nom du serveur (DNS inverse). Repère un logiciel espion ou un mouchard : programme lancé depuis un dossier
//! temporaire ou les Téléchargements, programme effacé après son lancement, port connu des logiciels d'accès à
//! distance ou inhabituel, serveur sans nom. Les connexions des programmes d'autres comptes (système, services) sont
//! invisibles sans droits d'administrateur : comptées à part, jamais comme saines. Lecture seule : rien n'est coupé
//! ni bloqué.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::risk::Niveau;
use crate::socle::adresses::sur_internet;
use crate::ui::*;

mod resultat;

/// Une connexion établie vers un serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Connexion {
    pid: Option<u32>,
    /// Nom du programme ; `None` : programme d'un autre compte, invisible sans droits d'administrateur.
    programme: Option<String>,
    /// Chemin de l'exécutable, s'il a pu être lu.
    chemin: Option<String>,
    distante: IpAddr,
    port: u16,
    udp: bool,
}

impl Connexion {
    fn vers(distante: IpAddr, port: u16) -> Connexion {
        Connexion {
            pid: None,
            programme: None,
            chemin: None,
            distante,
            port,
            udp: false,
        }
    }
}

/// Grands hébergeurs, dont le nom inverse dit mal à qui l'on parle (« lhr25s34-in-f14.1e100.net » : Google). Une
/// ligne par entreprise : son nom | ses domaines.
const PROPRIETAIRES: &str = "\
Google | 1e100.net googleusercontent.com
YouTube | googlevideo.com
Akamai | akamaitechnologies.com akamai.net akamaiedge.net
Amazon AWS | amazonaws.com
Amazon CloudFront | cloudfront.net
Meta | fbcdn.net facebook.com
WhatsApp | whatsapp.net
Microsoft | msedge.net microsoft.com windows.net
Microsoft Azure | azure.com
Apple | apple.com aaplimg.com icloud.com
Cloudflare | cloudflare.com cloudflare.net
Fastly | fastly.net
Valve (Steam) | valve.net steamcontent.com steamserver.net
Netflix | nflxvideo.net
Spotify | spotify.com
GitHub | github.com";

// ───────────────────────────── Lecture des connexions ─────────────────────────────

/// « 140.82.112.4:443 », « [2606:4700::1111]:443 », « 192.168.1.2%wlan0:68 » → (adresse, port).
#[cfg(any(target_os = "macos", test))]
fn adresse_et_port(t: &str) -> Option<(IpAddr, u16)> {
    let (hote, port) = t.rsplit_once(':')?;
    let hote = hote.trim_start_matches('[').trim_end_matches(']');
    let hote = hote.split('%').next()?;
    Some((hote.parse().ok()?, port.parse().ok()?))
}

/// Une adresse de /proc/net : des mots de 32 bits en hexadécimal (un pour IPv4, quatre pour IPv6), chacun écrit tel que
/// la machine le range en mémoire. Ses octets, dans l'ordre de la machine, sont donc ceux du réseau.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn adresse_proc(hex: &str) -> Option<IpAddr> {
    if hex.is_empty() || !hex.len().is_multiple_of(8) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let octets: Vec<u8> = (0..hex.len())
        .step_by(8)
        .map(|i| u32::from_str_radix(&hex[i..i + 8], 16).map(u32::to_ne_bytes))
        .collect::<Result<Vec<_>, _>>()
        .ok()?
        .concat();
    match octets.len() {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(octets).ok()?)),
        16 => Some(IpAddr::from(<[u8; 16]>::try_from(octets).ok()?)),
        _ => None,
    }
}

/// Les connexions établies d'un fichier de /proc/net (tcp, tcp6, udp, udp6) : « sl locale distante état … uid délai
/// inode ». État 01 : établie (pour UDP, une prise reliée à un seul serveur, comme ss la montre). Le port est écrit en
/// hexadécimal, dans l'ordre humain. → (distante, port, inode de la prise).
#[cfg(any(target_os = "linux", test))]
fn lire_proc_net(texte: &str) -> Vec<(IpAddr, u16, u64)> {
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &"01" {
                return None;
            }
            let (adresse, port) = champs.get(2)?.split_once(':')?;
            if port.len() != 4 || !port.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some((
                adresse_proc(adresse)?,
                u16::from_str_radix(port, 16).ok()?,
                champs.get(9)?.parse().ok()?,
            ))
        })
        .collect()
}

/// Le programme de chaque prise réseau : `/proc/<pid>/fd/*` pointe vers « `socket:[inode]` ». Sans droits root, seuls
/// les programmes de ce compte se lisent, comme avec ss : ceux des autres comptes restent sans nom.
#[cfg(target_os = "linux")]
pub(crate) fn proprietaires() -> HashMap<u64, u32> {
    let mut liste = HashMap::new();
    for pid in crate::socle::processus::pids().unwrap_or_default() {
        let Ok(descripteurs) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue;
        };
        for d in descripteurs.flatten() {
            let inode = std::fs::read_link(d.path()).ok().and_then(|cible| {
                cible
                    .to_str()?
                    .strip_prefix("socket:[")?
                    .strip_suffix(']')?
                    .parse::<u64>()
                    .ok()
            });
            if let Some(inode) = inode {
                liste.entry(inode).or_insert(pid);
            }
        }
    }
    liste
}

/// Sortie de `lsof -nP -iTCP -sTCP:ESTABLISHED -F pcn` : un champ par ligne, « p » (processus), « c » (nom),
/// « n » (« locale->distante »).
#[cfg(any(target_os = "macos", test))]
fn lire_lsof(sortie: &str) -> Vec<Connexion> {
    let (mut pid, mut programme) = (None, None);
    let mut liste = Vec::new();
    for l in sortie.lines() {
        let mut lettres = l.chars();
        let champ = lettres.next();
        let valeur = lettres.as_str();
        match champ {
            Some('p') => {
                pid = valeur.parse().ok();
                programme = None;
            }
            Some('c') => programme = Some(affichable(valeur)),
            Some('n') => {
                if let Some((distante, port)) = valeur.split_once("->").and_then(|(_, d)| adresse_et_port(d)) {
                    liste.push(Connexion {
                        pid,
                        programme: programme.clone(),
                        ..Connexion::vers(distante, port)
                    });
                }
            }
            _ => {}
        }
    }
    liste
}

/// Connexions établies d'après `netstat -anp tcp` (macOS : « 142.250.1.1.443 », le port après le dernier point),
/// moins celles que lsof a rattachées à un programme : ce qui reste appartient à d'autres comptes.
#[cfg(any(target_os = "macos", test))]
fn invisibles(netstat: &str, visibles: &[Connexion]) -> Vec<Connexion> {
    let mut restantes: Vec<(IpAddr, u16)> = visibles.iter().map(|c| (c.distante, c.port)).collect();
    netstat
        .lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .filter_map(|l| {
            let distante = l.split_whitespace().nth(4)?;
            let (ip, port) = distante.rsplit_once('.')?;
            Some((ip.split('%').next()?.parse::<IpAddr>().ok()?, port.parse::<u16>().ok()?))
        })
        .filter(|cle| match restantes.iter().position(|v| v == cle) {
            Some(i) => {
                restantes.swap_remove(i);
                false
            }
            None => true,
        })
        .map(|(distante, port)| Connexion::vers(distante, port))
        .collect()
}

/// Lu dans /proc, sans lancer ss : rien à installer, et rien qu'un programme posé plus tôt dans le PATH puisse remplacer.
/// `None` : aucun fichier de /proc/net lisible.
#[cfg(target_os = "linux")]
fn connexions() -> Option<Vec<Connexion>> {
    let mut lues = Vec::new();
    let mut lisible = false;
    for (fichier, udp) in [("tcp", false), ("tcp6", false), ("udp", true), ("udp6", true)] {
        // tcp6 et udp6 manquent quand IPv6 est coupé : ce n'est pas une panne.
        if let Ok(texte) = std::fs::read_to_string(format!("/proc/net/{fichier}")) {
            lisible = true;
            lues.extend(lire_proc_net(&texte).into_iter().map(|(d, p, i)| (d, p, i, udp)));
        }
    }
    if !lisible {
        return None;
    }
    let proprietaires = if lues.is_empty() {
        HashMap::new()
    } else {
        proprietaires()
    };
    Some(
        lues.into_iter()
            .map(|(distante, port, inode, udp)| {
                let pid = proprietaires.get(&inode).copied();
                Connexion {
                    pid,
                    // Le nom court du programme, celui que ss montrait ; n'importe quel programme le choisit.
                    programme: pid.and_then(crate::socle::processus::nom_court).map(|n| affichable(&n)),
                    chemin: pid
                        .and_then(crate::socle::processus::programme)
                        .map(|c| c.display().to_string()),
                    udp,
                    ..Connexion::vers(distante, port)
                }
            })
            .collect(),
    )
}

/// Les processus qui ont une connexion TCP établie vers une autre machine (ni 127.0.0.1 ni ::1, IPv4 dans IPv6
/// comprise), lus dans /proc sans lancer ss : pour « Mon ordinateur est-il contrôlé ? ». Chaque processus qui tient la
/// prise compte, comme ss les montre tous (un programme et l'enfant qui l'a reçue). Sans droits root, seuls ceux de
/// ce compte se voient, comme avec ss. `None` : ni /proc/net/tcp ni tcp6 lisible.
#[cfg(target_os = "linux")]
pub(crate) fn processus_connectes() -> Option<BTreeSet<u32>> {
    let mut prises = std::collections::HashSet::new();
    let mut lisible = false;
    for fichier in ["tcp", "tcp6"] {
        if let Ok(texte) = std::fs::read_to_string(format!("/proc/net/{fichier}")) {
            lisible = true;
            prises.extend(
                lire_proc_net(&texte)
                    .into_iter()
                    .filter(|(ip, _, _)| !ip.to_canonical().is_loopback())
                    .map(|(_, _, inode)| inode),
            );
        }
    }
    if !lisible {
        return None;
    }
    let mut pids = BTreeSet::new();
    if prises.is_empty() {
        return Some(pids);
    }
    for pid in crate::socle::processus::pids()? {
        let tient = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .into_iter()
            .flatten()
            .flatten()
            .any(|d| {
                std::fs::read_link(d.path()).is_ok_and(|cible| {
                    cible
                        .to_str()
                        .and_then(|c| c.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok())
                        .is_some_and(|i| prises.contains(&i))
                })
            });
        if tient {
            pids.insert(pid);
        }
    }
    Some(pids)
}

/// Les processus qui ont une connexion TCP établie vers une autre machine (ni 127.0.0.1 ni ::1), lus par Windows sans
/// PowerShell : pour « Mon ordinateur est-il contrôlé ? ». `None` : aucune des deux tables lisible.
#[cfg(windows)]
pub(crate) fn processus_connectes() -> Option<std::collections::BTreeSet<u32>> {
    Some(
        crate::machine::windows::connexions::tcp_etablies()?
            .into_iter()
            .filter(|s| s.distante.is_some_and(|(ip, _)| !ip.is_loopback()))
            .map(|s| s.pid)
            .collect(),
    )
}

/// La table TCP brute d'une famille (2 : IPv4, 23 : IPv6), pour qui lit d'autres colonnes (le blocage : les ports
/// locaux des sessions à distance).
#[cfg(windows)]
pub(crate) fn table_tcp(famille: u32) -> Option<Vec<u8>> {
    crate::machine::windows::connexions::table_tcp(famille)
}

/// Lu par les fonctions de Windows, sans PowerShell : rien à lancer, et quelques millisecondes au lieu de secondes.
/// `None` : aucune des deux tables lisible.
#[cfg(windows)]
fn connexions() -> Option<Vec<Connexion>> {
    let lues: Vec<(IpAddr, u16, u32)> = crate::machine::windows::connexions::tcp_etablies()?
        .into_iter()
        .filter_map(|s| s.distante.map(|(ip, port)| (ip, port, s.pid)))
        .collect();
    if lues.is_empty() {
        return Some(Vec::new());
    }
    let noms: HashMap<u32, String> = crate::machine::windows::processus::liste()
        .into_iter()
        .map(|p| (p.pid, p.nom))
        .collect();
    let mut chemins: HashMap<u32, Option<String>> = HashMap::new();
    Some(
        lues.into_iter()
            .map(|(distante, port, pid)| Connexion {
                pid: Some(pid),
                programme: noms.get(&pid).filter(|n| !n.is_empty()).cloned(),
                chemin: chemins
                    .entry(pid)
                    .or_insert_with(|| crate::machine::windows::processus::chemin(pid))
                    .clone(),
                ..Connexion::vers(distante, port)
            })
            .collect(),
    )
}

/// macOS : les connexions établies des programmes lisibles (ceux du compte sans droits admin), lues au noyau
/// (libproc) ; lsof en secours tant que le test d'oracle de macos.yml n'a pas prouvé la lecture native, ou quand elle
/// est muette. Puis netstat, qui fait foi pour celles de tous les comptes (xinpcb_n est privé) : ce qui reste après
/// les programmes lus appartient à d'autres comptes.
#[cfg(target_os = "macos")]
fn connexions() -> Option<Vec<Connexion>> {
    use std::process::Command;
    let natives = crate::machine::macos::noyau::prises().map(|lues| {
        lues.prises
            .into_iter()
            .filter(|(_, _, p)| p.tcp && p.etat == crate::machine::darwin::TSI_S_ESTABLISHED)
            .map(|(pid, nom, p)| Connexion {
                pid: Some(pid),
                programme: Some(affichable(&nom)),
                ..Connexion::vers(p.distante, p.port_distant)
            })
            .collect::<Vec<_>>()
    });
    let mut liste = if let Some(l) = natives.filter(|l| !l.is_empty()) {
        l
    } else {
        // lsof répond 1 quand il ne trouve rien : une liste vide, pas une panne.
        let lsof = crate::commande::lancer(
            Command::new("lsof").args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"]),
            20,
        )?;
        lire_lsof(&lsof.sortie)
    };
    let pids: BTreeSet<u32> = liste.iter().filter_map(|c| c.pid).collect();
    // Le chemin de chaque programme, demandé au noyau (proc_pidpath), sans lancer ps pour chacun.
    let chemins: HashMap<u32, String> = pids
        .into_iter()
        .filter_map(|pid| {
            Some((
                pid,
                crate::socle::processus::programme(pid)?.to_string_lossy().into_owned(),
            ))
        })
        .collect();
    for c in &mut liste {
        c.chemin = c.pid.and_then(|p| chemins.get(&p).cloned());
    }
    // Sans netstat, les connexions des autres comptes manquent : la liste n'est pas entière, donc illisible (une liste
    // du seul compte dirait à tort « aucune connexion suspecte »).
    let n = crate::commande::lancer(Command::new("netstat").args(["-anp", "tcp"]), 15).filter(|r| r.code == Some(0))?;
    let autres = invisibles(&n.sortie, &liste);
    liste.extend(autres);
    Some(liste)
}

/// Une connexion établie, telle que « Logiciels espions » la compare aux serveurs connus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnexionVue {
    pub pid: Option<u32>,
    /// `None` : programme d'un autre compte, invisible sans droits d'administrateur.
    pub programme: Option<String>,
    pub chemin: Option<String>,
    pub distante: IpAddr,
    pub port: u16,
}

/// Les connexions en cours, lues par Vanguard lui-même (Linux : /proc ; Windows : les fonctions de Windows ; macOS :
/// libproc pour le compte, lsof en secours, netstat pour les autres comptes).
pub(crate) fn connexions_vues() -> Option<Vec<ConnexionVue>> {
    connexions().map(|liste| {
        liste
            .into_iter()
            .map(|c| ConnexionVue {
                pid: c.pid,
                programme: c.programme,
                chemin: c.chemin,
                distante: c.distante,
                port: c.port,
            })
            .collect()
    })
}

// ───────────────────────────── Jugement ─────────────────────────────

/// Le service derrière un port bien connu.
fn service(port: u16, udp: bool) -> Option<&'static str> {
    Some(match port {
        443 if udp => tr!("web (QUIC)", "web (QUIC)"),
        443 => "HTTPS",
        80 => "HTTP",
        853 => tr!("DNS chiffré", "encrypted DNS"),
        53 => "DNS",
        123 => tr!("heure (NTP)", "time (NTP)"),
        993 | 143 => tr!("courriel (IMAP)", "email (IMAP)"),
        465 | 587 | 25 => tr!("courriel (SMTP)", "email (SMTP)"),
        995 | 110 => tr!("courriel (POP3)", "email (POP3)"),
        22 => "SSH",
        9418 => "git",
        5222 | 5223 => tr!("messagerie, notifications", "messaging, notifications"),
        5228..=5230 => tr!("notifications Google", "Google notifications"),
        3478..=3481 | 19302..=19309 => tr!("appels (STUN)", "calls (STUN)"),
        1935 => tr!("vidéo en direct", "live video"),
        27015..=27050 => "Steam",
        3074 => "Xbox Live",
        1119 => "Battle.net",
        25565 => "Minecraft",
        8080 | 8443 | 8000 | 8008 | 8888 => tr!("web (port secondaire)", "web (secondary port)"),
        1883 | 8883 => tr!("objets connectés (MQTT)", "connected devices (MQTT)"),
        5938 => "TeamViewer",
        3389 => tr!("Bureau à distance", "Remote Desktop"),
        5900..=5903 => "VNC",
        9001 | 9030 | 9050 | 9150 => "Tor",
        6881..=6889 | 51413 => "BitTorrent",
        _ => return None,
    })
}

/// Ports des logiciels d'accès à distance malveillants et des réseaux de zombies (Metasploit, IRC, NetBus,
/// njRAT, Quasar, DarkComet…).
fn port_suspect(port: u16) -> bool {
    matches!(
        port,
        4444 | 1337 | 31337 | 6666..=6669 | 12345 | 54321 | 1177 | 5552 | 4782 | 1604
    )
}

/// Le dossier temporaire du compte, tel que le système le donne (TEMP sous Windows, TMPDIR ailleurs) : déplacé
/// (« C:\Temp » réglé par un administrateur, un autre disque), il ne se reconnaît pas à son chemin habituel, et un
/// programme lancé de là passerait inaperçu. `chemin` : en minuscules, barres obliques. Un dossier temporaire à la
/// racine d'un disque (« C:\ », « / ») ne compte pas : tout serait dedans.
fn dans_le_temporaire_du_compte(chemin: &str) -> bool {
    let temp = std::env::temp_dir().to_string_lossy().to_lowercase().replace('\\', "/");
    let temp = format!("{}/", temp.trim_end_matches('/'));
    temp.trim_matches('/').contains('/') && chemin.starts_with(&temp)
}

/// Un dossier d'où un vrai programme ne se lance pas d'habitude.
pub(crate) fn dossier_risque(chemin: &str, montages: &str) -> Option<&'static str> {
    let c = chemin.to_lowercase().replace('\\', "/");
    // macOS : une app téléchargée lancée sur place tourne depuis un dossier temporaire « AppTranslocation ».
    if c.contains("/apptranslocation/") || appimage(chemin, montages) {
        return None;
    }
    // Dossiers temporaires : à la racine sous Linux et macOS, sous le dossier du compte ou de Windows ailleurs. Sous
    // macOS, celui du compte ($TMPDIR) se lit sous deux noms : /var/folders est un lien vers /private/var/folders.
    let racines = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/private/tmp/",
        "/private/var/folders/",
        "/var/folders/",
    ];
    if racines.iter().any(|t| c.starts_with(t))
        || ["/appdata/local/temp/", "/windows/temp/"].iter().any(|t| c.contains(t))
        || dans_le_temporaire_du_compte(&c)
    {
        return Some(tr!("un dossier temporaire", "a temporary folder"));
    }
    if c.contains("/downloads/") || c.contains("/téléchargements/") {
        return Some(tr!("les Téléchargements", "Downloads"));
    }
    if c.contains("/users/public/") {
        return Some(tr!(
            "le dossier Public, partagé par tous les comptes",
            "the Public folder, shared by all accounts"
        ));
    }
    None
}

/// Linux : une AppImage tourne depuis son image, montée dans « `/tmp/.mount_<nom><code>` » le temps qu'elle tourne. Un
/// simple dossier de ce nom ne suffit pas : il faut qu'il soit monté (`montages` : le contenu de /proc/self/mounts).
pub(crate) fn appimage(chemin: &str, montages: &str) -> bool {
    let Some(reste) = chemin.strip_prefix("/tmp/.mount_") else {
        return false;
    };
    let point = format!("/tmp/.mount_{}", reste.split('/').next().unwrap_or_default());
    montages
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(point.as_str()))
}

/// L'image d'où tourne une AppImage, d'après son environnement (`/proc/<pid>/environ` : « APPIMAGE=…\0 »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn image_appimage(environ: &[u8]) -> Option<String> {
    environ
        .split(|&o| o == 0)
        .find_map(|v| v.strip_prefix(b"APPIMAGE="))
        .map(|chemin| String::from_utf8_lossy(chemin).into_owned())
        .filter(|chemin| chemin.starts_with('/'))
}

/// Un nouveau fichier qu'un programme lancé par la personne n'a pas pu poser : fichier et dossier à root, dossier que
/// ni le groupe ni les autres n'écrivent (/usr, /opt, /snap, /var/lib/flatpak d'ordinaire). Ailleurs (profil, /tmp),
/// un programme malveillant qui s'est effacé n'aurait qu'à reposer n'importe quel fichier à sa place.
#[cfg_attr(not(unix), allow(dead_code))]
fn hors_de_portee(proprietaire_fichier: u32, proprietaire_dossier: u32, mode_dossier: u32) -> bool {
    proprietaire_fichier == 0 && proprietaire_dossier == 0 && mode_dossier & 0o022 == 0
}

#[cfg(unix)]
fn pose_par_le_systeme(chemin: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(fichier), Some(Ok(dossier))) = (std::fs::metadata(chemin), chemin.parent().map(std::fs::metadata)) else {
        return false;
    };
    hors_de_portee(fichier.uid(), dossier.uid(), dossier.mode())
}

#[cfg(not(unix))]
fn pose_par_le_systeme(_: &std::path::Path) -> bool {
    false
}

/// Le nom à montrer pour un serveur : son domaine (« github.com »), ou l'entreprise derrière un grand hébergeur.
fn qui(nom: &str) -> String {
    let domaine = crate::protection::lien::domaine_enregistrable(nom);
    PROPRIETAIRES
        .lines()
        .find_map(|l| {
            let (qui, domaines) = l.split_once(" | ")?;
            domaines
                .split_whitespace()
                .any(|d| d == domaine)
                .then(|| qui.to_string())
        })
        .unwrap_or(domaine)
}

/// Les serveurs de commande de botnets connus, des deux listes d'abuse.ch : Feodo Tracker (CC0, sans clé) donne des
/// adresses, ThreatFox (avec la clé) des adresses avec leur port et le nom du logiciel malveillant, et des domaines.
#[derive(Debug, Default)]
struct Botnets {
    feodo: BTreeSet<IpAddr>,
    threatfox: HashMap<(IpAddr, u16), String>,
    /// Les noms de domaine des serveurs de commande (ThreatFox) ; `None` : liste pas vérifiée.
    domaines: Option<HashMap<String, String>>,
}

impl Botnets {
    /// Le serveur d'une connexion tel qu'il sera montré, s'il est sur une des listes. Une adresse IPv4 vue par une
    /// prise IPv6 (« ::ffff:192.0.2.1 ») est comparée sous sa forme IPv4, celle des listes.
    fn serveur(&self, c: &Connexion) -> Option<String> {
        let ip = c.distante.to_canonical();
        let adresse = SocketAddr::new(ip, c.port);
        match self.threatfox.get(&(ip, c.port)) {
            Some(famille) if famille.is_empty() => Some(format!("{adresse} (ThreatFox)")),
            Some(famille) => Some(format!("{adresse} ({famille}, ThreatFox)")),
            None => self.feodo.contains(&ip).then(|| format!("{ip} (Feodo Tracker)")),
        }
    }

    /// Un nom demandé par l'ordinateur, tel qu'il sera montré, s'il est celui d'un serveur de commande ou l'un de ses
    /// sous-domaines (« a.mal.example » quand la liste donne « mal.example »).
    fn domaine(&self, nom: &str) -> Option<String> {
        let nom = nom.trim_end_matches('.').to_lowercase();
        let domaines = self.domaines.as_ref()?;
        let famille = std::iter::successors(Some(nom.as_str()), |n| n.split_once('.').map(|(_, reste)| reste))
            .filter(|n| n.contains('.'))
            .find_map(|n| domaines.get(n))?;
        let nom = affichable(&nom);
        Some(if famille.is_empty() {
            format!("{nom} (ThreatFox)")
        } else {
            format!("{nom} ({famille}, ThreatFox)")
        })
    }
}

/// La liste de Feodo Tracker : une adresse IP par ligne, lignes « # » de commentaire. `None` pour tout autre texte :
/// la page d'un portail Wi-Fi (hôtel, gare) arrive à la place de la liste sans erreur, et ne doit pas passer pour une
/// liste vide, donc vérifiée. Fonction pure, testée sur un texte inventé (le conteneur ne peut pas joindre abuse.ch).
fn analyser_feodo(texte: &str) -> Option<BTreeSet<IpAddr>> {
    let lignes: Vec<&str> = texte.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    // abuse.ch ouvre toujours ses listes par un en-tête en commentaire.
    if !lignes.first()?.starts_with('#') {
        return None;
    }
    lignes
        .into_iter()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.parse().ok())
        .collect()
}

/// Au-delà, Feodo Tracker ne compte plus comme à jour : abuse.ch l'a laissée figée le 4 mars 2026, à une adresse.
const FEODO_FIGEE_JOURS: i64 = 30;

/// La demande de Feodo Tracker (sans clé) : la même pour le programme et pour les canaris de la veille de nuit
/// (`canaris`).
pub(crate) fn demande_feodo() -> crate::http::Demande<'static> {
    crate::http::Demande {
        taille_max: 256 << 20,
        ..crate::http::Demande::get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            Duration::from_secs(40),
        )
    }
}

/// La liste de Feodo Tracker se lit-elle comme le programme l'attend ? Avant de remplacer la copie gardée, et pour
/// les canaris de la veille de nuit.
pub(crate) fn feodo_lisible(octets: &[u8]) -> bool {
    analyser_feodo(&String::from_utf8_lossy(octets)).is_some()
}

/// La liste de Feodo Tracker, et le jour de sa dernière mise à jour si elle est figée (`figee_depuis`).
fn analyser_feodo_datee(texte: &str) -> Option<(BTreeSet<IpAddr>, Option<chrono::NaiveDate>)> {
    Some((
        analyser_feodo(texte)?,
        figee_depuis(texte, chrono::Local::now().date_naive()),
    ))
}

/// Le « Last updated » de l'en-tête d'une liste d'abuse.ch, s'il a plus de `FEODO_FIGEE_JOURS` à `aujourd_hui`. Sans
/// date lisible, rien n'est conclu : la liste sert comme avant.
fn figee_depuis(texte: &str, aujourd_hui: chrono::NaiveDate) -> Option<chrono::NaiveDate> {
    let date = texte.lines().take_while(|l| l.starts_with('#')).find_map(|l| {
        let apres = l.split_once("Last updated:")?.1.trim();
        chrono::NaiveDate::parse_from_str(apres.get(..10)?, "%Y-%m-%d").ok()
    })?;
    ((aujourd_hui - date).num_days() > FEODO_FIGEE_JOURS).then_some(date)
}

/// Sans ThreatFox (`domaines` à `None`), Feodo Tracker est la seule liste lue : figée, elle ne dédouane rien, et c'est
/// dit. Avec ThreatFox, qui suit les mêmes botnets à jour, elle sert encore sans rien promettre.
fn dire_feodo_figee(absentes: &mut Vec<String>, botnets: &Botnets, depuis: Option<chrono::NaiveDate>) {
    if let (None, Some(d)) = (&botnets.domaines, depuis) {
        absentes.push(trf!(
            "liste de Feodo Tracker figée depuis le {d} : abuse.ch ne la tient plus à jour",
            "Feodo Tracker list frozen since {d}: abuse.ch no longer updates it"
        ));
    }
}

/// En dessous, ThreatFox lui-même doute (50 : signalement pas encore confirmé) : une fausse alerte élevée ferait
/// couper Internet pour rien.
const THREATFOX_CONFIANCE: u8 = 75;

/// Les champs d'une ligne CSV d'abuse.ch : entre guillemets (« "" » pour un guillemet) ou nus, séparés par des
/// virgules suivies ou non d'espaces. `None` : guillemet pas fermé, ou texte collé après lui.
fn champs_csv(ligne: &str) -> Option<Vec<String>> {
    let mut champs = Vec::new();
    let mut reste = ligne.trim();
    loop {
        reste = reste.trim_start_matches(' ');
        if let Some(apres) = reste.strip_prefix('"') {
            let mut valeur = String::new();
            let mut caracteres = apres.char_indices().peekable();
            let fin = loop {
                let (i, c) = caracteres.next()?;
                if c != '"' {
                    valeur.push(c);
                } else if caracteres.next_if(|&(_, c)| c == '"').is_some() {
                    valeur.push('"');
                } else {
                    break i + 1;
                }
            };
            champs.push(valeur);
            reste = apres[fin..].trim_start_matches(' ');
        } else {
            let fin = reste.find(',').unwrap_or(reste.len());
            champs.push(reste[..fin].trim().to_string());
            reste = &reste[fin..];
        }
        match reste.strip_prefix(',') {
            Some(apres) => reste = apres,
            None if reste.is_empty() => return Some(champs),
            None => return None,
        }
    }
}

/// Les colonnes lues dans un export de ThreatFox, par leur nom (avec ceux qu'elles ont parfois ailleurs) : l'en-tête
/// décide, abuse.ch pouvant changer leur ordre d'un export à l'autre.
const COLONNES_THREATFOX: [&[&str]; 5] = [
    &["ioc_value", "ioc"],
    &["ioc_type"],
    &["threat_type"],
    &["malware_printable", "malware"],
    &["confidence_level", "confidence"],
];
/// Leurs places dans les exports d'avant le 21 oct. 2026, pour un export sans en-tête lisible.
const PLACES_THREATFOX: [usize; 5] = [2, 3, 4, 7, 9];

/// Les lignes d'un export CSV de ThreatFox d'un genre (« ip:port », « domain ») : (valeur lue par `lire`, nom du
/// logiciel malveillant, prêt à montrer), seulement les serveurs de commande (« botnet_cc ») assez sûrs ; les serveurs
/// de téléchargement (« payload_delivery ») n'ont pas leur place parmi eux. L'export complet mêle tous les genres :
/// les autres sont sautés. `None` pour tout autre texte (portail Wi-Fi, export dont plus de la moitié des lignes ne se
/// lisent pas), comme pour Feodo Tracker : jamais une liste vide, donc vérifiée, à sa place. Une ligne illisible seule
/// est sautée, sans faire tomber six mois de signalements.
fn lignes_threatfox<T>(texte: &str, genre: &str, lire: impl Fn(&str) -> Option<T>) -> Option<Vec<(T, String)>> {
    let lignes: Vec<&str> = texte.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    let premiere = *lignes.first()?;
    let noms = |l: &str| champs_csv(l.trim_start_matches('#').trim());
    // L'en-tête : parmi les premières lignes, celle qui nomme les colonnes, en commentaire ou non.
    let entete = lignes
        .iter()
        .take(20)
        .position(|l| noms(l).is_some_and(|n| n.iter().any(|c| c == "ioc_type")));
    let places = match entete {
        Some(i) => {
            let noms = noms(lignes[i])?;
            let mut places = [0; 5];
            for (place, possibles) in places.iter_mut().zip(COLONNES_THREATFOX) {
                *place = noms.iter().position(|n| possibles.contains(&n.as_str()))?;
            }
            places
        }
        // abuse.ch ouvre ses listes par un en-tête en commentaire ; sans lui, ce n'en est pas une.
        None if premiere.starts_with('#') => PLACES_THREATFOX,
        None => return None,
    };
    let (mut gardees, mut vues, mut illisibles) = (Vec::new(), 0usize, 0usize);
    for (i, ligne) in lignes.iter().enumerate() {
        if Some(i) == entete || ligne.starts_with('#') {
            continue;
        }
        vues += 1;
        let Some(champs) = champs_csv(ligne) else {
            illisibles += 1;
            continue;
        };
        let lu = |k: usize| champs.get(places[k]).map(String::as_str);
        let (Some(valeur), Some(genre_lu), Some(menace), Some(famille), Some(confiance)) =
            (lu(0), lu(1), lu(2), lu(3), lu(4))
        else {
            illisibles += 1;
            continue;
        };
        if genre_lu != genre || menace != "botnet_cc" {
            continue;
        }
        match (lire(valeur), confiance.parse::<u8>()) {
            (Some(lue), Ok(c)) if c >= THREATFOX_CONFIANCE => gardees.push((lue, famille_montree(famille))),
            (Some(_), Ok(_)) => {}
            _ => illisibles += 1,
        }
    }
    (illisibles * 2 <= vues).then_some(gardees)
}

/// N'importe qui signale à ThreatFox : le nom est montré tel quel seulement s'il est inoffensif, et court.
fn famille_montree(famille: &str) -> String {
    affichable(famille).chars().take(40).collect()
}

/// Les serveurs « ip:port » de l'export de ThreatFox : (adresse, port) → nom du logiciel malveillant.
fn analyser_threatfox(texte: &str) -> Option<HashMap<(IpAddr, u16), String>> {
    let lignes = lignes_threatfox(texte, "ip:port", |valeur| valeur.parse::<SocketAddr>().ok())?;
    Some(
        lignes
            .into_iter()
            .map(|(adresse, famille)| ((adresse.ip().to_canonical(), adresse.port()), famille))
            .collect(),
    )
}

/// Les domaines de l'export de ThreatFox (genre « domain ») : nom en minuscules → nom du logiciel malveillant.
fn analyser_domaines(texte: &str) -> Option<HashMap<String, String>> {
    let lignes = lignes_threatfox(texte, "domain", |nom| {
        let nom = nom.trim_end_matches('.').to_lowercase();
        (nom.contains('.') && !nom.contains([' ', '/', ':'])).then_some(nom)
    })?;
    Some(lignes.into_iter().collect())
}

/// Un serveur de ThreatFox gardé s'il est un serveur de commande assez sûr.
fn garder_threatfox(
    serveurs: &mut HashMap<(IpAddr, u16), String>,
    adresse: SocketAddr,
    menace: &str,
    famille: &str,
    confiance: u64,
) {
    if menace == "botnet_cc" && confiance >= u64::from(THREATFOX_CONFIANCE) {
        serveurs.insert((adresse.ip().to_canonical(), adresse.port()), famille_montree(famille));
    }
}

/// La réponse de l'API de ThreatFox (avec une clé) : les signalements des 7 derniers jours, tous genres confondus, en
/// JSON. Mêmes règles que l'export ; `None` pour une réponse qui n'en est pas une (portail Wi-Fi, refus).
fn analyser_threatfox_api(texte: &str) -> Option<HashMap<(IpAddr, u16), String>> {
    let reponse: serde_json::Value = serde_json::from_str(texte).ok()?;
    let mut serveurs = HashMap::new();
    match reponse["query_status"].as_str()? {
        "no_result" => return Some(serveurs),
        "ok" => {}
        _ => return None,
    }
    for ioc in reponse["data"].as_array()? {
        if ioc["ioc_type"] != "ip:port" {
            continue;
        }
        garder_threatfox(
            &mut serveurs,
            ioc["ioc"].as_str()?.parse().ok()?,
            ioc["threat_type"].as_str()?,
            ioc["malware_printable"].as_str().unwrap_or_default(),
            ioc["confidence_level"].as_u64()?,
        );
    }
    Some(serveurs)
}

/// Avec une clé, ThreatFox permet de redemander ses listes toutes les 5 minutes : un serveur de commande change
/// d'adresse en quelques jours. Ses exports restent à 12 heures (`lien::URLHAUS_FRAICHE`), comme avant.
const THREATFOX_CLE_FRAICHE: Duration = Duration::from_mins(5);

/// Une liste téléchargée (ou la copie d'avant), jugée : `Err` dit pourquoi elle ne sert pas (non vérifiée, trop
/// vieille, illisible). `analyser` : `None` pour ce qui n'est pas la liste attendue (portail Wi-Fi).
fn verifiee<T>(
    nom: &str,
    telechargee: Result<(Vec<u8>, Duration), crate::protection::abuse_ch::Echec>,
    analyser: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<T, String> {
    let (octets, age) = telechargee.map_err(|echec| {
        trf!(
            "liste de {nom} non vérifiée : {}",
            "{nom} list not checked: {}",
            echec.raison()
        )
    })?;
    if age > crate::protection::lien::URLHAUS_TROP_VIEILLE {
        return Err(trf!(
            "liste de {nom} trop vieille pour servir : rafraîchissement impossible",
            "{nom} list too old to use: could not refresh it"
        ));
    }
    analyser(&octets).ok_or_else(|| {
        trf!(
            "liste de {nom} illisible (page d'un portail Wi-Fi ?) : pas vérifiée",
            "{nom} list unreadable (a Wi-Fi portal page?): not checked"
        )
    })
}

/// Un texte d'abuse.ch, lu par `analyser`.
fn en_texte<T>(analyser: fn(&str) -> Option<T>) -> impl FnOnce(&[u8]) -> Option<T> {
    move |octets| analyser(&String::from_utf8_lossy(octets))
}

/// L'export complet de ThreatFox (une archive zip d'un CSV, tous genres mêlés, six mois de signalements), avec la
/// clé : ses serveurs « ip:port » et ses domaines, lus dans le même fichier.
type ExportThreatfox = (HashMap<(IpAddr, u16), String>, HashMap<String, String>);

/// Le même plafond que la liste de MalwareBazaar : 1 Gio laissait une archive de 1 Mo faire monter la mémoire à 4 Go
/// à chaque bilan (le CSV, sa copie en texte, puis ses deux lectures). Non vérifié : la taille réelle de full.csv chez
/// ThreatFox ; au-delà, l'export serait dit illisible, jamais tu.
const EXPORT_MAX: usize = crate::protection::empreintes::TEXTE_MAX;

fn analyser_export_threatfox(archive: &[u8]) -> Option<ExportThreatfox> {
    let csv = crate::protection::empreintes::premier_fichier_zip(archive, EXPORT_MAX)?;
    let texte = String::from_utf8_lossy(&csv);
    Some((analyser_threatfox(&texte)?, analyser_domaines(&texte)?))
}

/// Les serveurs de botnets des listes d'abuse.ch, téléchargées en même temps, et ce qui n'a pas pu être vérifié. Une
/// liste indisponible (sans clé, clé refusée, hors ligne, trop vieille) est dite : on ne conclut jamais que rien ne
/// parle à un botnet, et les autres servent quand même. Feodo Tracker se lit sans clé ; l'export de ThreatFox et son
/// API la demandent (l'API ne remonte que 7 jours, mais se redemande toutes les 5 minutes).
fn botnets() -> (Botnets, Vec<String>) {
    use crate::http::Demande;
    use crate::protection::abuse_ch::{self, Service};
    use crate::protection::lien::URLHAUS_FRAICHE;
    let cle = abuse_ch::cle();
    let (feodo, export, api) = std::thread::scope(|s| {
        let feodo = s.spawn(|| {
            let liste = crate::socle::cache::liste(
                demande_feodo(),
                ("feodo", "botnets.txt"),
                URLHAUS_FRAICHE,
                feodo_lisible,
            );
            verifiee("Feodo Tracker", liste.resultat(false), en_texte(analyser_feodo_datee))
        });
        let api = s.spawn(|| {
            cle.as_ref().map(|cle| {
                let demande = Demande {
                    entetes: vec![("Auth-Key", cle.clone())],
                    corps: Some(br#"{"query":"get_iocs","days":7}"#.to_vec()),
                    taille_max: 256 << 20,
                    ..Demande::get("https://threatfox-api.abuse.ch/api/v1/", Duration::from_secs(40))
                };
                let liste = crate::socle::cache::liste(
                    demande,
                    ("threatfox", abuse_ch::FICHIER_API),
                    THREATFOX_CLE_FRAICHE,
                    |o| analyser_threatfox_api(&String::from_utf8_lossy(o)).is_some(),
                );
                verifiee(
                    tr!("ThreatFox (7 jours)", "ThreatFox (7 days)"),
                    liste.resultat(true),
                    en_texte(analyser_threatfox_api),
                )
            })
        });
        let export = verifiee(
            "ThreatFox",
            abuse_ch::export(
                Service::ThreatFox,
                "full.csv.zip",
                ("threatfox", "export.zip"),
                (URLHAUS_FRAICHE, Duration::from_secs(120)),
                |o| analyser_export_threatfox(o).is_some(),
            ),
            analyser_export_threatfox,
        );
        let pas_verifiee = |nom| trf!("liste de {nom} pas vérifiée", "{nom} list not checked");
        (
            feodo.join().unwrap_or_else(|_| Err(pas_verifiee("Feodo Tracker"))),
            export,
            api.join().unwrap_or_else(|_| Some(Err(pas_verifiee("ThreatFox")))),
        )
    });
    let mut botnets = Botnets::default();
    let mut absentes = Vec::new();
    let mut figee = None;
    match feodo {
        Ok((liste, depuis)) => (botnets.feodo, figee) = (liste, depuis),
        Err(raison) => absentes.push(raison),
    }
    match export {
        Ok((serveurs, domaines)) => {
            botnets.threatfox.extend(serveurs);
            botnets.domaines = Some(domaines);
        }
        Err(raison) => absentes.push(raison),
    }
    match api {
        Some(Ok(serveurs)) => botnets.threatfox.extend(serveurs),
        Some(Err(raison)) => absentes.push(raison),
        // Sans clé, l'export l'a déjà dit : une seule fois.
        None => {}
    }
    dire_feodo_figee(&mut absentes, &botnets, figee);
    (botnets, absentes)
}

/// Les domaines des serveurs de commande de ThreatFox (export, avec la clé), pour le blocage par hosts. `Err` :
/// pourquoi ils ne sont pas lus.
pub(crate) fn domaines_de_commande() -> Result<Vec<String>, String> {
    let (b, absentes) = botnets();
    b.domaines
        .map(|d| d.into_keys().collect())
        .ok_or_else(|| absentes.join(" ; "))
}

/// Les serveurs de commande connus, pour qui n'a que l'adresse et le port d'une connexion (le veilleur, à la fin d'une
/// connexion brève : le noyau n'y donne pas le programme).
#[cfg(target_os = "linux")]
pub(crate) struct ServeursDeCommande(Botnets);

#[cfg(target_os = "linux")]
impl ServeursDeCommande {
    /// Le serveur tel qu'il est montré (« 203.0.113.7:443 (Emotet, ThreatFox) »), s'il est sur une des listes.
    pub(crate) fn serveur(&self, ip: IpAddr, port: u16) -> Option<String> {
        self.0.serveur(&Connexion::vers(ip, port))
    }

    /// Des listes inventées, pour les tests du veilleur.
    #[cfg(test)]
    pub(crate) fn pour_essai(feodo: &[IpAddr], threatfox: &[(IpAddr, u16, &str)]) -> ServeursDeCommande {
        ServeursDeCommande(Botnets {
            feodo: feodo.iter().copied().collect(),
            threatfox: threatfox
                .iter()
                .map(|&(ip, port, famille)| ((ip, port), famille.to_string()))
                .collect(),
            domaines: None,
        })
    }
}

/// Les listes déjà téléchargées par la surveillance ou le bilan, relues sans réseau : le veilleur tourne dans une
/// unité qui n'a pas le droit d'ouvrir une prise Internet (RestrictAddressFamilies), et ces listes sont déjà
/// rafraîchies par les autres. Leur âge est celui de leur sceau ; jugées comme à la passe (`verifiee`), et ce qui ne
/// sert pas est dit, jamais compté comme sain. Le refus de la copie des empreintes récentes de MalwareBazaar, que le
/// veilleur relit à part (`protection::sources`), est dit ici aussi : c'est la ligne des listes de son état.
#[cfg(target_os = "linux")]
pub(crate) fn serveurs_gardes() -> (ServeursDeCommande, Vec<String>) {
    let (serveurs, mut absentes) = serveurs_gardes_dans("feodo", "threatfox");
    if let Err(refus) = crate::socle::cache::gardee(
        ("malwarebazaar", "recentes.txt"),
        crate::protection::empreintes::TEXTE_MAX as u64,
    ) {
        absentes.push(trf!(
            "empreintes récentes de MalwareBazaar non vérifiées : {}",
            "recent MalwareBazaar fingerprints not checked: {}",
            refus.texte()
        ));
    }
    (serveurs, absentes)
}

/// `serveurs_gardes`, les listes lues sous `feodo` et `threatfox` (des dossiers à eux dans les tests).
#[cfg(target_os = "linux")]
fn serveurs_gardes_dans(feodo: &str, threatfox: &str) -> (ServeursDeCommande, Vec<String>) {
    // L'âge et le contenu d'après le sceau de la copie (`socle::cache::gardee`) : une liste vidée et datée dans le
    // futur par un autre programme ne passe plus pour vérifiée.
    let garde = |sous_dossier: &str, nom: &str| {
        crate::socle::cache::gardee((sous_dossier, nom), crate::socle::cache::LISTE_MAX)
    };
    let pas_encore = |nom: &str| {
        trf!(
            "liste de {nom} pas encore téléchargée : la surveillance ou le bilan la prennent",
            "{nom} list not downloaded yet: the monitoring or the check fetches it"
        )
    };
    let refusee = |nom: &str, refus: crate::socle::cache::Refus| {
        trf!(
            "liste de {nom} non vérifiée : {} (la surveillance ou le bilan la retéléchargent)",
            "{nom} list not checked: {} (the monitoring or the check downloads it again)",
            refus.texte()
        )
    };
    let avec_cle = crate::protection::abuse_ch::cle().is_some();
    let mut botnets = Botnets::default();
    let mut absentes = Vec::new();
    let mut figee = None;
    match garde(feodo, "botnets.txt") {
        Ok(Some(copie)) => match verifiee("Feodo Tracker", Ok(copie), en_texte(analyser_feodo_datee)) {
            Ok((liste, depuis)) => (botnets.feodo, figee) = (liste, depuis),
            Err(raison) => absentes.push(raison),
        },
        Ok(None) => absentes.push(pas_encore("Feodo Tracker")),
        Err(refus) => absentes.push(refusee("Feodo Tracker", refus)),
    }
    if avec_cle {
        match garde(threatfox, "export.zip") {
            Ok(Some(copie)) => match verifiee("ThreatFox", Ok(copie), analyser_export_threatfox) {
                Ok((serveurs, domaines)) => {
                    botnets.threatfox.extend(serveurs);
                    botnets.domaines = Some(domaines);
                }
                Err(raison) => absentes.push(raison),
            },
            Ok(None) => absentes.push(pas_encore("ThreatFox")),
            Err(refus) => absentes.push(refusee("ThreatFox", refus)),
        }
        let api = tr!("ThreatFox (7 jours)", "ThreatFox (7 days)");
        match garde(threatfox, crate::protection::abuse_ch::FICHIER_API) {
            Ok(Some(copie)) => match verifiee(api, Ok(copie), en_texte(analyser_threatfox_api)) {
                Ok(serveurs) => botnets.threatfox.extend(serveurs),
                Err(raison) => absentes.push(raison),
            },
            Ok(None) => absentes.push(pas_encore(api)),
            Err(refus) => absentes.push(refusee(api, refus)),
        }
    } else {
        // Sans clé, comme à la passe : la copie d'une ancienne clé ne sert pas, et c'est dit une fois.
        absentes.push(trf!(
            "liste de ThreatFox non vérifiée : {}",
            "ThreatFox list not checked: {}",
            crate::protection::abuse_ch::Echec::Manquante.raison()
        ));
    }
    dire_feodo_figee(&mut absentes, &botnets, figee);
    (ServeursDeCommande(botnets), absentes)
}

/// Les connexions d'une passe qui n'étaient pas déjà signalées à la passe d'avant (`avant` : une par ligne).
fn nouvelles_alertes<'a>(avant: &str, actuelles: &'a BTreeSet<String>) -> Vec<&'a String> {
    let deja: BTreeSet<&str> = avant.lines().collect();
    actuelles.iter().filter(|a| !deja.contains(a.as_str())).collect()
}

/// Les connexions vers un serveur de commande vues à la dernière passe de la surveillance, une par ligne : le
/// tableau de bord les montre comme encore en cours.
pub(crate) fn fichier_botnets() -> PathBuf {
    crate::socle::dossier_local().join(crate::sceau::BOTNETS)
}

/// Ce que cet ordinateur envoie en ce moment vers un serveur de commande connu, en lecture seule (rien d'écrit) :
/// pour l'audit du réseau et la surveillance. `None` : les connexions ne se lisent pas.
pub(crate) struct EnCours {
    /// « programme → serveur (famille, liste) », et les noms demandés qui sont ceux d'un serveur de commande.
    pub connexions: BTreeSet<String>,
    /// Les listes qui n'ont pas pu être vérifiées (hors ligne, téléchargement raté) : rien n'est conclu pour elles.
    pub listes_absentes: Vec<String>,
}

/// Les programmes qui parlent à un serveur de commande connu, d'après les connexions du moment et la mémoire DNS.
/// Les listes se rafraîchissent au même rythme que pour l'écran (elles ne disent à personne ce qu'on a trouvé).
pub(crate) fn botnets_en_cours() -> Option<EnCours> {
    let connexions = connexions()?;
    let (botnets, listes_absentes) = botnets();
    let mut actuelles: BTreeSet<String> = connexions
        .iter()
        .filter_map(|c| {
            let serveur = botnets.serveur(c)?;
            let programme = c
                .programme
                .clone()
                .unwrap_or_else(|| tr!("programme d'un autre compte", "another account's program").to_string());
            Some(format!("{programme} → {serveur}"))
        })
        .collect();
    // La mémoire DNS : sans droits sous Windows ; sous Linux, seulement quand la surveillance tourne en root.
    if let Ok(noms) = crate::protection::memoire_dns::noms() {
        actuelles.extend(
            noms.iter()
                .filter_map(|n| botnets.domaine(n))
                .map(|n| tr!("nom demandé : ", "name asked: ").to_string() + &n),
        );
    }
    Some(EnCours {
        connexions: actuelles,
        listes_absentes,
    })
}

/// Une connexion en cours vers un serveur de commande connu, pour le blocage (règle de pare-feu vers l'adresse).
pub(crate) struct VersBotnet {
    pub pid: Option<u32>,
    /// Le programme, prêt à montrer ; `None` : celui d'un autre compte, invisible sans droits.
    pub programme: Option<String>,
    /// Sous sa forme IPv4 quand une prise IPv6 la voit en « ::ffff:… » : celle que le pare-feu doit bloquer.
    pub adresse: IpAddr,
    /// Le serveur tel qu'il est montré : « 203.0.113.7:443 (Emotet, ThreatFox) ».
    pub serveur: String,
}

/// Les connexions en cours vers un serveur de commande connu (Feodo Tracker, ThreatFox), et les listes qui n'ont
/// pas pu être vérifiées. `None` : les connexions ne se lisent pas.
pub(crate) fn connexions_botnets() -> Option<(Vec<VersBotnet>, Vec<String>)> {
    let connexions = connexions()?;
    let (botnets, absentes) = botnets();
    let liste = connexions
        .iter()
        .filter_map(|c| {
            Some(VersBotnet {
                serveur: botnets.serveur(c)?,
                pid: c.pid,
                programme: c.programme.clone(),
                adresse: c.distante.to_canonical(),
            })
        })
        .collect();
    Some((liste, absentes))
}

/// Pour la surveillance horaire : les programmes qui parlent à un serveur de commande connu, en (titre, texte) de
/// notification. Sans les listes, rien n'est dit ici : l'écran dit, lui, ce qui n'a pas pu être vérifié. Une
/// connexion déjà signalée à la passe d'avant ne l'est pas deux fois.
/// Chaque alerte vient avec sa clé (`protection::normales`) : « botnet|programme → serveur ».
pub(crate) fn botnets_a_signaler() -> Vec<(String, String, String)> {
    let Some(en_cours) = botnets_en_cours() else {
        return Vec::new();
    };
    let actuelles = en_cours.connexions;
    let avant = deja_signalees();
    let alertes = nouvelles_alertes(&avant, &actuelles)
        .into_iter()
        .map(|a| {
            (
                format!("botnet|{a}"),
                tr!(
                    "Vanguard : programme relié à un botnet",
                    "Vanguard: program connected to a botnet"
                )
                .to_string(),
                trf!(
                    "{a} : un serveur de commande connu. Ouvrez « Après une infection » dans Vanguard : coupez Internet d'abord.",
                    "{a}: a known command server. Open “After an infection” in Vanguard: cut the Internet first."
                ),
            )
        })
        .collect();
    let _ = crate::sceau::ecrire(
        crate::sceau::BOTNETS,
        actuelles.into_iter().collect::<Vec<_>>().join("\n"),
    );
    alertes
}

/// Les connexions déjà notifiées à la passe d'avant. Une liste changée hors de Vanguard (un programme qui y plante son
/// serveur de commande pour ne plus être signalé), abîmée ou illisible ne vaut rien : tout est redit.
fn deja_signalees() -> String {
    match crate::sceau::lire(crate::sceau::BOTNETS) {
        crate::sceau::Lecture::Intact(o) => String::from_utf8_lossy(&o).into_owned(),
        _ => String::new(),
    }
}

/// Les noms demandés par l'ordinateur qui sont des hôtes d'URLhaus, prêts à montrer. Le nom exact seulement : un
/// sous-domaine malveillant ne rend pas suspect tout son domaine (hébergeurs, DNS dynamiques).
fn sites_dangereux(noms: &[String], hotes: &std::collections::HashSet<String>) -> BTreeSet<String> {
    sites_trouves(noms, hotes)
        .into_iter()
        .map(|n| format!("{} (URLhaus)", affichable(&n)))
        .collect()
}

/// Les noms demandés qui sont des hôtes d'URLhaus, tels quels (en minuscules, sans le point final).
fn sites_trouves(noms: &[String], hotes: &std::collections::HashSet<String>) -> BTreeSet<String> {
    noms.iter()
        .map(|n| n.trim_end_matches('.').to_lowercase())
        .filter(|n| hotes.contains(n))
        .collect()
}

/// Pour la surveillance horaire : les sites qui distribuent des logiciels malveillants que l'ordinateur a demandés
/// depuis la passe d'avant, en (titre, texte) de notification. Sans mémoire DNS ou sans liste, rien n'est dit ici :
/// l'écran « Qui parle à Internet ? » dit ce qui n'a pas pu être vérifié.
/// Chaque alerte vient avec sa clé (`protection::normales`) : « site|nom (URLhaus) ».
pub(crate) fn sites_dangereux_a_signaler() -> Vec<(String, String, String)> {
    let (Ok(noms), Ok((hotes, _))) = (
        crate::protection::memoire_dns::noms(),
        crate::protection::lien::hotes_urlhaus(),
    ) else {
        return Vec::new();
    };
    let actuels = sites_dangereux(&noms, &hotes);
    let avant = sites_d_avant(crate::sceau::lire(crate::sceau::SITES));
    let alertes = nouvelles_alertes(&avant, &actuels)
        .into_iter()
        .map(|site| {
            (
                format!("site|{site}"),
                tr!(
                    "Vanguard : site qui distribue des logiciels malveillants",
                    "Vanguard: site that distributes malware"
                )
                .to_string(),
                trf!(
                    "Cet ordinateur a demandé {site} : un téléchargement a pu suivre. Lancez un examen antivirus et regardez les fichiers téléchargés récemment.",
                    "This computer asked for {site}: a download may have followed. Run an antivirus scan and check recently downloaded files."
                ),
            )
        })
        .collect();
    let _ = crate::sceau::ecrire(crate::sceau::SITES, actuels.into_iter().collect::<Vec<_>>().join("\n"));
    alertes
}

/// Les sites déjà signalés, seulement tels que Vanguard les a notés : une ligne posée d'avance (le site qu'un
/// programme vient de demander) ne tait rien, et un fichier changé, adopté ou effacé avec les sceaux fait tout redire.
fn sites_d_avant(lu: crate::sceau::Lecture) -> String {
    match lu {
        crate::sceau::Lecture::Intact(o) => String::from_utf8_lossy(&o).into_owned(),
        _ => String::new(),
    }
}

/// Depuis le menu : l'écran, puis Entrée pour revenir, ou C pour donner ou retirer la clé abuse.ch (celle qui ouvre
/// les listes de ThreatFox). Le retour au menu se demande ici, pas après : une seule pause.
pub fn menu() {
    use crate::protection::abuse_ch;
    let botnet = afficher_et_juger();
    loop {
        let cle = abuse_ch::cle().is_some();
        let cle_texte = if cle {
            tr!("C pour retirer votre clé abuse.ch", "C to remove your abuse.ch key")
        } else {
            tr!(
                "C pour donner votre clé abuse.ch (gratuite)",
                "C to give your abuse.ch key (free)"
            )
        };
        // Un serveur de commande trouvé : le parcours qui dit quoi faire passe en premier.
        let cle_ligne = if cle {
            tr!("Retirer votre clé abuse.ch", "Remove your abuse.ch key")
        } else {
            tr!("Donner votre clé abuse.ch (gratuite)", "Give your abuse.ch key (free)")
        };
        let mut options = Vec::new();
        if botnet {
            options.push((
                "i",
                tr!("Après une infection, pas à pas", "After an infection, step by step"),
            ));
        }
        options.push(("c", cle_ligne));
        let invite = if botnet {
            trf!(
                "\n{GRIS}I : « Après une infection » · Entrée : revenir · C : clé abuse.ch…{RESET} ",
                "\n{GRIS}I: “After an infection” · Enter: go back · C: abuse.ch key…{RESET} "
            )
        } else {
            trf!(
                "\n{GRIS}Entrée pour revenir au menu, {cle_texte}…{RESET} ",
                "\n{GRIS}Enter to go back to the menu, {cle_texte}…{RESET} "
            )
        };
        match crate::selection::choisir_en_ligne(&options, &invite).as_deref() {
            Some("i") => {
                crate::depanner::infection::infection();
                return;
            }
            Some("c") if cle => abuse_ch::retirer(),
            Some("c") => {
                abuse_ch::donner();
            }
            _ => return,
        }
    }
}

/// Ce qui mérite l'attention dans les connexions d'un programme : (gravité, texte). `image` : celle d'une AppImage
/// (variable APPIMAGE), jugée à la place de son point de montage dans /tmp. `botnets` : les serveurs de commande de
/// botnets connus (sans une liste qui n'a pas pu être vérifiée ; l'absence est alors dite ailleurs, jamais ici).
fn signes(
    chemin: Option<&str>,
    connexions: &[(&Connexion, Option<&String>)],
    montages: &str,
    image: Option<&str>,
    botnets: &Botnets,
) -> Vec<(Niveau, String)> {
    let mut signes = Vec::new();
    // Un serveur de commande de botnet connu passe avant tout le reste : c'est le signe le plus grave.
    let vers_botnet: Vec<String> = connexions
        .iter()
        .filter_map(|(c, _)| botnets.serveur(c))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !vers_botnet.is_empty() {
        let adresses = resume(&vers_botnet, 4, ", ");
        signes.push((
            Niveau::Eleve,
            trf!(
                "Parle à un serveur de commande de botnet connu (listes d'abuse.ch) : {adresses}.",
                "Talks to a known botnet command server (abuse.ch lists): {adresses}."
            ),
        ));
    }
    if let Some(c) = chemin {
        // Un nouveau fichier à la même place, posé par le système : le programme a été mis à jour pendant qu'il
        // tournait (Firefox après une mise à jour du système), l'ancienne version reste en mémoire.
        match c.strip_suffix(" (deleted)") {
            Some(ancien) if pose_par_le_systeme(std::path::Path::new(ancien)) => signes.push((
                Niveau::Info,
                tr!(
                    "Mis à jour pendant qu'il tournait : l'ancienne version tourne encore, redémarrez-le.",
                    "Updated while running: the old version is still running, restart it."
                )
                .to_string(),
            )),
            Some(_) => signes.push((
                Niveau::Eleve,
                tr!(
                    "Programme effacé après son lancement : une ruse pour ne pas laisser de trace.",
                    "Program deleted after it started: a trick to leave no trace."
                )
                .to_string(),
            )),
            None => {}
        }
        let juge = image.filter(|_| appimage(c, montages)).unwrap_or(c);
        if let Some(ou) = dossier_risque(juge, montages) {
            signes.push((
                Niveau::Eleve,
                trf!(
                    "Lancé depuis {ou} : un vrai programme s'installe d'abord.",
                    "Started from {ou}: a real program gets installed first."
                ),
            ));
        }
    }
    let suspects: BTreeSet<u16> = connexions
        .iter()
        .map(|(c, _)| c.port)
        .filter(|p| port_suspect(*p))
        .collect();
    if !suspects.is_empty() {
        let ports = suspects.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
        signes.push((
            Niveau::Eleve,
            trf!(
                "Port {ports} : celui de logiciels d'accès à distance malveillants.",
                "Port {ports}: the one of malicious remote access tools."
            ),
        ));
    }
    // Un port inconnu en TCP mérite un regard ; en UDP, jeux et appels en prennent au hasard.
    let inconnus: BTreeSet<u16> = connexions
        .iter()
        .filter(|(c, _)| !c.udp && service(c.port, false).is_none() && !port_suspect(c.port))
        .map(|(c, _)| c.port)
        .collect();
    if !inconnus.is_empty() {
        let ports = resume(&inconnus.iter().map(u16::to_string).collect::<Vec<_>>(), 5, ", ");
        signes.push((
            Niveau::Moyen,
            trf!(
                "Port inhabituel ({ports}) : normal pour un jeu ou un logiciel de partage, étrange pour le reste.",
                "Unusual port ({ports}): normal for a game or a sharing program, odd for anything else."
            ),
        ));
    }
    let sans_nom = connexions.iter().filter(|(_, nom)| nom.is_none()).count();
    if sans_nom > 0 {
        signes.push((
            Niveau::Info,
            trf!(
                "{sans_nom} serveur(s) sans nom : courant pour les réseaux de diffusion, à rapprocher du reste.",
                "{sans_nom} server(s) without a name: common for delivery networks, to weigh with the rest."
            ),
        ));
    }
    signes
}

/// Noms inverses des adresses, demandés en parallèle au DNS du système ; ceux qui tardent plus de 4 secondes sont
/// laissés sans nom (un DNS lent ne doit pas tout figer). Le propriétaire de chaque adresse écrit son nom inverse :
/// lu prêt à montrer.
fn noms(adresses: &BTreeSet<IpAddr>) -> HashMap<IpAddr, String> {
    let (envoi, reception) = std::sync::mpsc::channel();
    for &ip in adresses {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            if let Some(nom) = dns_lookup::lookup_addr(&ip)
                .ok()
                .and_then(|n| crate::reseau::scan::nom_inverse(ip, &n))
            {
                let _ = envoi.send((ip, nom));
            }
        });
    }
    drop(envoi);
    let limite = Instant::now() + Duration::from_secs(4);
    let mut noms = HashMap::new();
    while let Some(reste) = limite.checked_duration_since(Instant::now()) {
        match reception.recv_timeout(reste) {
            Ok((ip, nom)) => {
                noms.insert(ip, nom);
            }
            Err(_) => break,
        }
    }
    noms
}

// ───────────────────────────── Relevé ─────────────────────────────

/// Les hôtes d'URLhaus, et une note sur leur âge ; `Err` : pourquoi la liste manque.
type Urlhaus = Result<(std::collections::HashSet<String>, Option<String>), String>;

/// Tout ce que l'écran et `--json` lisent, une fois, dans le même ordre : les listes des serveurs de commande, les
/// connexions vers Internet et le nom de leurs serveurs, la mémoire DNS et la liste d'URLhaus.
struct Releve {
    botnets: Botnets,
    /// Les listes qui n'ont pas pu être vérifiées : rien n'est conclu pour elles.
    listes_absentes: Vec<String>,
    /// Les connexions vers Internet ; `None` : elles ne se lisent pas.
    connexions: Option<Vec<Connexion>>,
    noms: HashMap<IpAddr, String>,
    /// /proc/self/mounts (Linux), pour juger les dossiers de lancement.
    montages: String,
    /// Les noms demandés récemment, ou pourquoi ils ne se lisent pas.
    memoire_dns: Result<Vec<String>, String>,
    /// Demandée seulement quand la mémoire DNS se lit.
    urlhaus: Option<Urlhaus>,
}

/// Le relevé. `annoncer_noms` est appelé avant de demander les noms des serveurs (l'écran dit d'attendre), avec leur
/// nombre ; jamais quand il n'y a aucune connexion.
fn relever(annoncer_noms: impl FnOnce(usize)) -> Releve {
    // Les listes des serveurs de botnets, une fois pour tout l'écran. Une liste indisponible : on le dira, et rien ne
    // sera dédouané pour autant.
    let (botnets, listes_absentes) = botnets();
    let connexions = connexions().map(|toutes| {
        toutes
            .into_iter()
            .filter(|c| sur_internet(c.distante))
            .collect::<Vec<_>>()
    });
    let adresses: BTreeSet<IpAddr> = connexions.iter().flatten().map(|c| c.distante).collect();
    let noms = if adresses.is_empty() {
        HashMap::new()
    } else {
        annoncer_noms(adresses.len());
        noms(&adresses)
    };
    let montages = if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/self/mounts").unwrap_or_default()
    } else {
        String::new()
    };
    let memoire_dns = crate::protection::memoire_dns::noms();
    let urlhaus = memoire_dns
        .as_ref()
        .ok()
        .map(|_| crate::protection::lien::hotes_urlhaus());
    Releve {
        botnets,
        listes_absentes,
        connexions,
        noms,
        montages,
        memoire_dns,
        urlhaus,
    }
}

/// Les connexions jugées : programme par programme (le pire d'abord), celles des autres comptes à part, et les
/// serveurs de commande de toutes (celles des autres comptes comprises : un programme du système détourné parle
/// aussi).
struct Analyse<'a> {
    programmes: Vec<Programme>,
    cachees: Vec<(&'a Connexion, Option<&'a String>)>,
    vers_botnets: BTreeSet<String>,
}

fn analyser(r: &Releve) -> Analyse<'_> {
    let connexions: &[Connexion] = r.connexions.as_deref().unwrap_or_default();
    let vers_botnets: BTreeSet<String> = connexions.iter().filter_map(|c| r.botnets.serveur(c)).collect();

    // Regroupées par programme ; celles des autres comptes à part.
    let mut groupes: Vec<Groupe> = Vec::new();
    let mut cachees: Vec<(&Connexion, Option<&String>)> = Vec::new();
    for c in connexions {
        let nom = r.noms.get(&c.distante);
        if c.programme.is_none() {
            cachees.push((c, nom));
            continue;
        }
        match groupes
            .iter_mut()
            .find(|g| g.programme == c.programme && g.chemin == c.chemin)
        {
            Some(g) => g.liste.push((c, nom)),
            None => groupes.push(Groupe {
                programme: c.programme.clone(),
                chemin: c.chemin.clone(),
                liste: vec![(c, nom)],
            }),
        }
    }
    let montages = r.montages.as_str();
    let mut programmes: Vec<Programme> = groupes
        .iter()
        .map(|g| {
            // Une AppImage : son image, lue dans l'environnement de son processus (le sien, donc lisible).
            let image = g
                .chemin
                .as_deref()
                .filter(|c| cfg!(target_os = "linux") && appimage(c, montages))
                .and_then(|_| g.liste.iter().find_map(|(c, _)| c.pid))
                .and_then(|pid| std::fs::read(format!("/proc/{pid}/environ")).ok())
                .and_then(|e| image_appimage(&e));
            let signes = signes(g.chemin.as_deref(), &g.liste, montages, image.as_deref(), &r.botnets);
            Programme {
                pire: signes.iter().map(|(n, _)| *n).filter(|n| *n > Niveau::Info).max(),
                nom: g.programme.clone().unwrap_or_default(),
                // Jugé tel quel (plus haut) ; montré, le chemin est rendu inoffensif.
                chemin: g.chemin.as_deref().map(affichable),
                signes,
                serveurs: serveurs(&g.liste),
                connexions: g.liste.len(),
            }
        })
        .collect();
    programmes.sort_by(|a, b| b.pire.cmp(&a.pire).then(b.connexions.cmp(&a.connexions)));
    Analyse {
        programmes,
        cachees,
        vers_botnets,
    }
}

// ───────────────────────────── Affichage ─────────────────────────────

/// Les connexions d'un même programme.
struct Groupe<'a> {
    programme: Option<String>,
    chemin: Option<String>,
    liste: Vec<(&'a Connexion, Option<&'a String>)>,
}

/// Un programme tel qu'il s'affiche : le pire de ses signes d'abord.
struct Programme {
    pire: Option<Niveau>,
    nom: String,
    chemin: Option<String>,
    signes: Vec<(Niveau, String)>,
    serveurs: String,
    connexions: usize,
}

/// La marque d'un programme : sans signe, ✔ seulement si son chemin a pu être examiné ; sinon « ? » (non vérifié).
fn marque(niveau: Option<Niveau>, chemin_lu: bool) -> String {
    match niveau {
        Some(n @ (Niveau::Eleve | Niveau::Critique)) => format!("{}✖{RESET}", couleur(n)),
        Some(Niveau::Moyen) => format!("{}⚠{RESET}", couleur(Niveau::Moyen)),
        _ if !chemin_lu => format!("{GRIS}?{RESET}"),
        _ => format!("{VERT}✔{RESET}"),
    }
}

/// Les serveurs d'un groupe de connexions, nommés et sans doublons : « github.com, Google, 203.0.113.5:4444 ».
fn serveurs(connexions: &[(&Connexion, Option<&String>)]) -> String {
    let mut vus = BTreeSet::new();
    let mut liste = Vec::new();
    for (c, nom) in connexions {
        let montre = match nom {
            Some(n) => qui(n),
            None => format!("{}:{}", c.distante, c.port),
        };
        if vus.insert(montre.clone()) {
            liste.push(montre);
        }
    }
    resume(&liste, 6, ", ")
}

/// Menu Antivirus et protection › Qui parle à Internet ?, ou `vanguard connexions-sortantes`.
pub fn afficher() {
    let _ = afficher_et_juger();
}

/// L'écran, puis : un programme parle-t-il à un serveur de commande connu ?
fn afficher_et_juger() -> bool {
    titre(tr!("Qui parle à Internet ?", "Who talks to the Internet?"));
    for ligne in envelopper(
        tr!(
            "Les connexions en cours de cet ordinateur vers Internet, programme par programme. Rien n'est coupé ni bloqué.",
            "This computer's current connections to the Internet, program by program. Nothing is cut or blocked."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    crate::protection::temps_reel::dire_si_coupee(crate::protection::temps_reel::Ou::Sortantes);
    println!();
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = relever(|n| {
        trp!(
            "  {GRIS}Noms des {} serveur(s)…{RESET}",
            "  {GRIS}Names of the {} server(s)…{RESET}",
            n
        );
    });
    let a = analyser(&r);
    crate::modele::resultat::verser(&resultat::resultat(&r, &a, debut));
    let mut trouves: Vec<String> = afficher_connexions(&r, &a).into_iter().collect();
    trouves.extend(afficher_memoire_dns(&r));
    // Ce qui n'a pas pu être vérifié est dit, jamais compté comme sain.
    for raison in &r.listes_absentes {
        afficher_aligne(&format!("  {GRIS}ℹ{RESET} "), raison, 4, GRIS);
    }
    if !trouves.is_empty() {
        let liste = resume(&trouves, 3, ", ");
        println!();
        for ligne in envelopper(
            &trf!(
                "⚠ Cet ordinateur parle à un serveur de commande de botnet, ou en a demandé le nom ({liste}) : quelqu'un peut le piloter. Coupez Internet d'abord (câble ou Wi-Fi), puis suivez « Après une infection » (Dépanner).",
                "⚠ This computer talks to a botnet command server, or asked for its name ({liste}): someone may be controlling it. Cut the Internet first (cable or Wi-Fi), then follow “After an infection” (Troubleshoot)."
            ),
            LARGEUR - 2,
        ) {
            println!("  {}{ligne}{RESET}", couleur(Niveau::Eleve));
        }
    }
    !trouves.is_empty()
}

/// Une mémoire DNS lue mais vide : rien à comparer, ce qui ne prouve rien (un autre résolveur répond peut-être).
fn memoire_dns_vide() -> &'static str {
    tr!(
        "Mémoire DNS vide : rien à comparer aux serveurs de commande ni à URLhaus (un autre résolveur, comme dnsmasq ou NextDNS, répond peut-être à sa place).",
        "DNS cache empty: nothing to compare with command servers or URLhaus (another resolver, such as dnsmasq or NextDNS, may answer instead)."
    )
}

/// La mémoire DNS comparée aux domaines des serveurs de commande : un programme qui a demandé le nom de son serveur il
/// y a une heure se voit, même si la connexion est fermée. Rend les noms trouvés.
fn afficher_memoire_dns(r: &Releve) -> Vec<String> {
    let botnets = &r.botnets;
    println!();
    match &r.memoire_dns {
        Err(raison) => {
            afficher_aligne(
                &format!("  {GRIS}ℹ{RESET} "),
                &trf!(
                    "Mémoire DNS pas vérifiée : {raison}.",
                    "DNS cache not checked: {raison}."
                ),
                4,
                GRIS,
            );
            Vec::new()
        }
        Ok(noms) if noms.is_empty() => {
            afficher_aligne(&format!("  {GRIS}?{RESET} "), memoire_dns_vide(), 4, GRIS);
            Vec::new()
        }
        Ok(noms) => {
            if let Some(urlhaus) = &r.urlhaus {
                afficher_sites_dangereux(noms, urlhaus);
            }
            let trouves: Vec<String> = noms
                .iter()
                .filter_map(|n| botnets.domaine(n))
                .map(|n| tr!("nom demandé : ", "name asked: ").to_string() + &n)
                .collect();
            if botnets.domaines.is_none() {
                // Liste indisponible : dit plus bas, rien n'est déclaré sain.
            } else if trouves.is_empty() {
                trp!(
                    "  {VERT}✔{RESET} Mémoire DNS : aucun des {} noms demandés récemment n'est un serveur de commande connu.",
                    "  {VERT}✔{RESET} DNS cache: none of the {} recently asked names is a known command server.",
                    noms.len()
                );
            } else {
                for t in &trouves {
                    println!("  {}✖{RESET} {t}", couleur(Niveau::Eleve));
                }
            }
            trouves
        }
    }
}

/// La mémoire DNS comparée aux hôtes d'URLhaus : un site qui distribue des logiciels malveillants, demandé récemment.
/// Sans la liste, c'est dit ; rien n'est déclaré sain.
fn afficher_sites_dangereux(noms: &[String], urlhaus: &Urlhaus) {
    let hotes = match urlhaus {
        Ok((h, note)) => {
            if let Some(n) = note {
                afficher_aligne(
                    &format!("  {GRIS}ℹ{RESET} "),
                    &trf!("liste d'URLhaus : {n}", "URLhaus list: {n}"),
                    4,
                    GRIS,
                );
            }
            h
        }
        Err(raison) => {
            afficher_aligne(&format!("  {GRIS}ℹ{RESET} "), raison, 4, GRIS);
            return;
        }
    };
    let trouves = sites_dangereux(noms, hotes);
    if trouves.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Mémoire DNS : aucun des {} noms demandés récemment ne distribue de logiciels malveillants (URLhaus).",
            "  {VERT}✔{RESET} DNS cache: none of the {} recently asked names distributes malware (URLhaus).",
            noms.len()
        );
        return;
    }
    let liste = trouves.iter().cloned().collect::<Vec<_>>().join(", ");
    afficher_aligne(
        &format!("  {}✖{RESET} ", couleur(Niveau::Eleve)),
        &trf!(
            "Site qui distribue des logiciels malveillants demandé récemment : {liste}. Un téléchargement a pu suivre : lancez un examen antivirus et regardez les fichiers téléchargés récemment.",
            "Site that distributes malware asked recently: {liste}. A download may have followed: run an antivirus scan and check recently downloaded files."
        ),
        4,
        "",
    );
}

/// Les connexions, programme par programme. Rend les serveurs de commande trouvés.
fn afficher_connexions(r: &Releve, a: &Analyse) -> BTreeSet<String> {
    let Some(connexions) = &r.connexions else {
        trp!(
            "  ✖ Impossible de lire les connexions de cet ordinateur.",
            "  ✖ Could not read this computer's connections."
        );
        return BTreeSet::new();
    };
    if connexions.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucune connexion vers Internet en ce moment.",
            "  {VERT}✔{RESET} No connection to the Internet right now."
        );
        return BTreeSet::new();
    }
    let (affiches, cachees) = (&a.programmes, &a.cachees);
    println!();
    let mut a_regarder = Vec::new();
    let mut chemins_invisibles = 0;
    for p in affiches {
        let n = p.connexions;
        println!(
            "  {} {ACCENT}{}{RESET} {GRIS}· {}{RESET}",
            marque(p.pire, p.chemin.is_some()),
            p.nom,
            trf!("{n} connexion(s)", "{n} connection(s)")
        );
        if let Some(c) = &p.chemin {
            afficher_aligne("      ", c, 6, GRIS);
        } else {
            chemins_invisibles += 1;
            afficher_aligne(
                "      ",
                tr!(
                    "chemin invisible sans droits d'administrateur (non vérifié)",
                    "path invisible without administrator rights (not checked)"
                ),
                6,
                GRIS,
            );
        }
        afficher_aligne("      → ", &p.serveurs, 8, "");
        for (niveau, texte) in &p.signes {
            let symbole = match niveau {
                Niveau::Info => format!("{GRIS}ℹ{RESET}"),
                Niveau::Moyen => format!("{}⚠{RESET}", couleur(*niveau)),
                n => format!("{}✖{RESET}", couleur(*n)),
            };
            afficher_aligne(&format!("      {symbole} "), texte, 8, "");
        }
        if p.pire.is_some() {
            a_regarder.push(p.nom.clone());
        }
    }
    if !cachees.is_empty() {
        println!(
            "  {GRIS}?{RESET} {}",
            trf!(
                "{} connexion(s) de programmes d'autres comptes (système, services)",
                "{} connection(s) from other accounts' programs (system, services)",
                cachees.len()
            )
        );
        afficher_aligne(
            "      ",
            tr!(
                "invisibles sans droits d'administrateur : non vérifiées, jamais comptées comme saines",
                "invisible without administrator rights: not checked, never counted as safe"
            ),
            6,
            GRIS,
        );
        afficher_aligne("      → ", &serveurs(cachees), 8, "");
    }

    println!();
    trp!(
        "  {} programme(s), {} connexion(s) vers Internet.",
        "  {} program(s), {} connection(s) to the Internet.",
        affiches.len(),
        connexions.len()
    );
    if !a_regarder.is_empty() {
        let liste = resume(&a_regarder, 4, ", ");
        for ligne in envelopper(
            &trf!(
                "À regarder de près : {liste}. Si vous ne connaissez pas un programme signalé, analysez-le (antivirus, YARA, même menu), puis désinstallez-le. Vanguard ne coupe rien.",
                "Worth a close look: {liste}. If you do not know a flagged program, scan it (antivirus, YARA, same menu), then uninstall it. Vanguard cuts nothing."
            ),
            LARGEUR - 2,
        ) {
            println!("  {ligne}");
        }
    }
    if !cachees.is_empty() || chemins_invisibles > 0 {
        let comment = if cfg!(windows) {
            tr!(
                "lancez Vanguard en administrateur (clic droit, « Exécuter en tant qu'administrateur »)",
                "run Vanguard as administrator (right-click, “Run as administrator”)"
            )
        } else {
            tr!(
                "sudo vanguard connexions-sortantes",
                "sudo vanguard outbound-connections"
            )
        };
        trp!(
            "  {GRIS}Pour tout voir : {comment}.{RESET}",
            "  {GRIS}To see everything: {comment}.{RESET}"
        );
    }
    a.vers_botnets.clone()
}

/// `vanguard connexions-sortantes --json` : le même relevé que l'écran, jugé en résultat et versé comme lui. Lecture
/// seule, aucune question : rien n'est coupé ni bloqué.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let r = relever(|_| {});
    let a = analyser(&r);
    let res = resultat::resultat(&r, &a, debut);
    crate::modele::resultat::verser(&res);
    println!("{}", crate::modele::resultat::json(&res));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un export qui annonce une ligne de plus que le plafond une fois décompressé (une archive « stockée », sans
    /// compression : un vrai CSV vide, puis un long commentaire) n'est pas lu ; juste au plafond, il l'est. Avant, il
    /// se décompressait jusqu'à 1 Gio.
    #[test]
    fn export_threatfox_borne_comme_malwarebazaar() {
        fn stockee(taille: usize) -> Vec<u8> {
            let nom = b"full.csv";
            let mut z = b"PK\x03\x04".to_vec();
            z.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
            z.extend_from_slice(&[0; 16]);
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z.extend_from_slice(nom);
            let debut = z.len();
            z.extend_from_slice(b"# ThreatFox\n#");
            z.resize(debut + taille, b'#');
            let central = z.len();
            let taille = u32::try_from(taille).unwrap().to_le_bytes();
            z.extend_from_slice(b"PK\x01\x02");
            z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
            z.extend_from_slice(&[0; 8]);
            z.extend_from_slice(&taille);
            z.extend_from_slice(&taille);
            z.extend_from_slice(&u16::try_from(nom.len()).unwrap().to_le_bytes());
            z.extend_from_slice(&[0; 12]);
            z.extend_from_slice(&0u32.to_le_bytes());
            z.extend_from_slice(nom);
            let taille_central = z.len() - central;
            z.extend_from_slice(b"PK\x05\x06");
            z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
            z.extend_from_slice(&u32::try_from(taille_central).unwrap().to_le_bytes());
            z.extend_from_slice(&u32::try_from(central).unwrap().to_le_bytes());
            z.extend_from_slice(&[0, 0]);
            z
        }
        assert!(analyser_export_threatfox(&stockee(64)).is_some());
        assert!(analyser_export_threatfox(&stockee(crate::protection::empreintes::TEXTE_MAX + 1)).is_none());
    }

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    /// Les vraies fonctions de Windows (sous Wine ici, puis dans la VM) : les tables se lisent, sans PowerShell.
    #[cfg(windows)]
    #[test]
    fn connexions_lues_par_windows() {
        assert!(table_tcp(2).is_some());
        assert!(connexions().is_some());
    }

    #[test]
    fn adresses() {
        assert_eq!(adresse_et_port("140.82.112.4:443"), Some((ip("140.82.112.4"), 443)));
        assert_eq!(
            adresse_et_port("[2606:4700::1111]:443"),
            Some((ip("2606:4700::1111"), 443))
        );
        assert_eq!(adresse_et_port("192.168.1.20%wlan0:68"), Some((ip("192.168.1.20"), 68)));
        assert_eq!(adresse_et_port("[fe80::1%wlan0]:22"), Some((ip("fe80::1"), 22)));
        assert_eq!(adresse_et_port("users:((x"), None);
    }

    #[test]
    fn proc_net_linux() {
        // Lignes à la forme de /proc/net, adresses écrites comme la machine les range (ici, celle qui fait les tests :
        // x86 ou ARM, petit-boutistes) : 127.0.0.1 est « 0100007F ».
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                   0: 1401A8C0:A8AC 0470528C:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0\n\
                   1: 0100007F:2CAA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   955        0 22541 2 0\n\
                   2: 1401A8C0:A8B6 097100CB:115C 01 00000000:00000000 00:00000000 00000000  1000        0 4300 1 0\n";
        let liste = lire_proc_net(tcp);
        assert_eq!(
            liste,
            [(ip("140.82.112.4"), 443, 4242), (ip("203.0.113.9"), 4444, 4300)]
        );
        let tcp6 = "  sl  local_address remote_address st\n\
                    0: 00000000000000000000000001000000:0277 B80D01200000000000000000020000A0:C350 01 0:0 00:0 0 1000 0 77 1\n";
        assert_eq!(lire_proc_net(tcp6), [(ip("2001:db8::a000:2"), 0xC350, 77)]);
        // Lignes tronquées ou piégées : sautées.
        assert_eq!(
            lire_proc_net("en-tête\n 0: 0100007F:0035 +100007F:01BB 01 0 0 0 0 0 1\n 1: x\n"),
            Vec::new()
        );
    }

    #[test]
    fn windows_et_macos() {
        let lsof = "p501\ncGoogle Chrome\nf23\nn192.168.1.20:50000->142.250.1.1:443\np777\ncssh\nf3\nn[2a01:db8::2]:50001->[2001:db8::7]:22\n";
        let m = lire_lsof(lsof);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].programme.as_deref(), Some("Google Chrome"));
        assert_eq!(m[0].pid, Some(501));
        assert_eq!(m[1].port, 22);
        let netstat = "Active Internet connections (including servers)\n\
                       tcp4 0 0 192.168.1.20.50000 142.250.1.1.443 ESTABLISHED\n\
                       tcp4 0 0 192.168.1.20.50010 17.253.1.1.443 ESTABLISHED\n\
                       tcp4 0 0 *.22 *.* LISTEN\n";
        let autres = invisibles(netstat, &m);
        assert_eq!(autres.len(), 1);
        assert_eq!(autres[0].distante, ip("17.253.1.1"));
        assert_eq!(autres[0].programme, None);
    }

    /// N'importe quel programme choisit son nom (et celui de son fichier) : piégé, le nom arrive inoffensif dans
    /// chaque lecture ; le chemin, lui, reste tel quel pour juger d'où le programme a été lancé.
    #[test]
    fn noms_de_programmes_pieges() {
        let lsof = lire_lsof("p501\ncChrome\x1b[8m\u{2066}\nf23\nn192.168.1.20:50000->142.250.1.1:443\n");
        assert_eq!(lsof[0].programme.as_deref(), Some("Chrome�[8m�"));
    }

    #[test]
    fn internet_ou_maison() {
        assert!(sur_internet(ip("140.82.112.4")));
        assert!(sur_internet(ip("2606:4700::1111")));
        assert!(sur_internet(ip("::ffff:140.82.112.4")));
        for local in [
            "192.168.1.1",
            "10.0.0.5",
            "127.0.0.1",
            "169.254.1.1",
            "100.100.1.1",
            "fe80::1",
            "fd00::1",
            "::1",
        ] {
            assert!(!sur_internet(ip(local)), "{local}");
        }
    }

    #[test]
    fn jugement() {
        assert_eq!(dossier_risque("/tmp/.x/miner", ""), Some("un dossier temporaire"));
        // macOS : le dossier temporaire du compte, sous ses deux noms.
        for t in ["/var/folders/ab/cdef/T/miner", "/private/var/folders/ab/cdef/T/miner"] {
            assert_eq!(dossier_risque(t, ""), Some("un dossier temporaire"), "{t}");
        }
        assert_eq!(
            dossier_risque("/home/alice/Téléchargements/outil", ""),
            Some("les Téléchargements")
        );
        assert_eq!(
            dossier_risque("C:\\Users\\alice\\AppData\\Local\\Temp\\a.exe", ""),
            Some("un dossier temporaire")
        );
        assert_eq!(
            dossier_risque("C:\\Users\\Public\\svc.exe", ""),
            Some("le dossier Public, partagé par tous les comptes")
        );
        assert_eq!(
            dossier_risque(
                "/private/var/folders/x/AppTranslocation/y/App.app/Contents/MacOS/App",
                ""
            ),
            None
        );
        assert_eq!(dossier_risque("/usr/lib/firefox/firefox", ""), None);
        // Le dossier temporaire du compte, où qu'il soit (TEMP déplacé sous Windows, TMPDIR ailleurs).
        let temp = std::env::temp_dir().join("x").join("outil.exe");
        assert_eq!(
            dossier_risque(&temp.to_string_lossy(), ""),
            Some("un dossier temporaire"),
            "{}",
            temp.display()
        );
        assert!(!dans_le_temporaire_du_compte("c:/"));
        assert_eq!(service(443, false), Some("HTTPS"));
        assert!(service(4444, false).is_none() && port_suspect(4444));
        let firefox = Connexion {
            pid: Some(4242),
            programme: Some("firefox".into()),
            chemin: Some("/usr/lib/firefox/firefox".into()),
            distante: ip("140.82.112.4"),
            port: 443,
            udp: false,
        };
        let nom = "lb-140-82-112-4-iad.github.com".to_string();
        assert_eq!(
            signes(
                firefox.chemin.as_deref(),
                &[(&firefox, Some(&nom))],
                "",
                None,
                &Botnets::default()
            ),
            Vec::new()
        );
        let piege = Connexion {
            chemin: Some("/tmp/.cache/x (deleted)".into()),
            port: 4444,
            ..firefox.clone()
        };
        let s = signes(
            piege.chemin.as_deref(),
            &[(&piege, None)],
            "",
            None,
            &Botnets::default(),
        );
        let niveaux: Vec<Niveau> = s.iter().map(|(n, _)| *n).collect();
        assert_eq!(niveaux, [Niveau::Eleve, Niveau::Eleve, Niveau::Eleve, Niveau::Info]);
        // Un jeu en UDP sur un port quelconque : rien à dire.
        let jeu = Connexion {
            port: 61234,
            udp: true,
            ..firefox.clone()
        };
        assert_eq!(
            signes(
                jeu.chemin.as_deref(),
                &[(&jeu, Some(&nom))],
                "",
                None,
                &Botnets::default()
            ),
            Vec::new()
        );
        let tcp = Connexion { port: 61234, ..firefox };
        assert_eq!(
            signes(
                tcp.chemin.as_deref(),
                &[(&tcp, Some(&nom))],
                "",
                None,
                &Botnets::default()
            )[0]
            .0,
            Niveau::Moyen
        );
    }

    #[test]
    fn sites_dangereux_par_nom_exact() {
        let hotes: std::collections::HashSet<String> =
            ["piege-exemple.com", "x.dyn-exemple.org"].map(String::from).into();
        let noms = [
            "Piege-Exemple.com.",
            "www.piege-exemple.com",
            "dyn-exemple.org",
            "x.dyn-exemple.org",
            "exemple.org",
        ]
        .map(String::from);
        let t = sites_dangereux(&noms, &hotes);
        // Le nom exact, quelle que soit sa casse ou son point final ; ni un sous-domaine, ni le domaine parent.
        assert_eq!(t.len(), 2, "{t:?}");
        assert!(t.iter().all(|s| s.ends_with("(URLhaus)")));
    }

    #[test]
    fn liste_de_botnets_decodee() {
        // Texte inventé (le conteneur ne peut pas joindre abuse.ch) : commentaires et lignes vides ignorés, IPv4 et
        // IPv6 gardées ; une liste sans adresse reste une liste.
        let texte = "# Feodo Tracker\n\n192.0.2.66\n198.51.100.7\n2001:db8::1\n";
        let liste = analyser_feodo(texte).unwrap();
        assert_eq!(liste.len(), 3);
        assert!(liste.contains(&ip("192.0.2.66")));
        assert!(liste.contains(&ip("2001:db8::1")));
        assert!(
            analyser_feodo("# Feodo Tracker\n# vide aujourd'hui\n")
                .unwrap()
                .is_empty()
        );
        // Autre chose qu'une liste (portail Wi-Fi, fichier vide, ligne illisible) : pas vérifiée, jamais vide.
        assert!(analyser_feodo("").is_none());
        assert!(analyser_feodo("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(analyser_feodo("# Feodo Tracker\n192.0.2.66\npas-une-ip\n").is_none());
    }

    #[test]
    fn feodo_figee_dite_sans_threatfox() {
        let jour = |d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap();
        let entete = "################\n# Feodo Tracker #\n# Last updated: 2026-03-04 14:28:39 UTC #\n#\n192.0.2.66\n";
        // Figée au-delà de 30 jours ; la veille de la limite, encore à jour ; sans date lisible, rien n'est conclu.
        assert_eq!(figee_depuis(entete, jour("2026-10-22")), Some(jour("2026-03-04")));
        assert_eq!(figee_depuis(entete, jour("2026-04-03")), None);
        assert_eq!(figee_depuis("# Feodo Tracker\n192.0.2.66\n", jour("2026-10-22")), None);
        assert_eq!(figee_depuis("# Last updated: hier\n", jour("2026-10-22")), None);
        // Une date plus bas que l'en-tête n'en est pas une.
        assert_eq!(
            figee_depuis("# Feodo\n192.0.2.66\n# Last updated: 2026-03-04\n", jour("2026-10-22")),
            None
        );
        // Sans ThreatFox, la liste figée est dite ; avec ses domaines (export lu), elle sert sans être dite.
        let mut absentes = Vec::new();
        dire_feodo_figee(&mut absentes, &Botnets::default(), Some(jour("2026-03-04")));
        assert!(
            absentes.len() == 1 && absentes[0].contains("2026-03-04"),
            "{absentes:?}"
        );
        let avec_threatfox = Botnets {
            domaines: Some(HashMap::new()),
            ..Botnets::default()
        };
        let mut absentes = Vec::new();
        dire_feodo_figee(&mut absentes, &avec_threatfox, Some(jour("2026-03-04")));
        dire_feodo_figee(&mut absentes, &Botnets::default(), None);
        assert!(absentes.is_empty(), "{absentes:?}");
    }

    #[test]
    fn connexion_vers_un_botnet_signalee() {
        let botnets = Botnets {
            feodo: BTreeSet::from([ip("203.0.113.9")]),
            ..Botnets::default()
        };
        let c = Connexion {
            pid: Some(10),
            programme: Some("inconnu".into()),
            chemin: Some("/usr/bin/inconnu".into()),
            distante: ip("203.0.113.9"),
            port: 443,
            udp: false,
        };
        let s = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &botnets);
        assert_eq!(s[0].0, Niveau::Eleve);
        assert!(s[0].1.contains("botnet") && s[0].1.contains("203.0.113.9"));
        // Même serveur, mais liste vide (indisponible) : aucune connexion n'est dédouanée ni accusée ici.
        let vide = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &Botnets::default());
        assert!(!vide.iter().any(|(_, t)| t.contains("botnet")));
    }

    #[test]
    fn liste_threatfox_decodee() {
        // Texte inventé, à la forme de l'export (fins de ligne Windows) : seuls les serveurs de commande assez sûrs
        // comptent, avec leur port et le nom du logiciel malveillant.
        let texte = concat!(
            "################################################################\r\n",
            "# ThreatFox IOCs: recent ip-port - CSV format                  #\r\n",
            "#\r\n",
            "# \"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\"\r\n",
            "\"2026-10-20 13:46:40\", \"1\", \"192.0.2.25:6662\", \"ip:port\", \"botnet_cc\", \"win.cobalt_strike\", \"BEACON\", \"Cobalt Strike\", \"\", \"75\", \"False\", \"None\", \"a, b\", \"0\", \"alice\"\r\n",
            "\"2026-10-20 13:30:04\", \"2\", \"[2001:db8::7]:2000\", \"ip:port\", \"botnet_cc\", \"win.nanocore\", \"\", \"Nanocore\u{1b}[2K RAT\", \"\", \"100\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
            "\"2026-10-20 12:00:00\", \"3\", \"198.51.100.3:80\", \"ip:port\", \"botnet_cc\", \"win.x\", \"\", \"Douteux\", \"\", \"50\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
            "\"2026-10-20 11:00:00\", \"4\", \"198.51.100.4:80\", \"ip:port\", \"payload_delivery\", \"win.y\", \"\", \"Téléchargeur\", \"\", \"100\", \"False\", \"None\", \"\", \"0\", \"bob\"\r\n",
        );
        let liste = analyser_threatfox(texte).unwrap();
        assert_eq!(liste.len(), 2);
        assert_eq!(liste[&(ip("192.0.2.25"), 6662)], "Cobalt Strike");
        // Un nom signalé par n'importe qui ne pilote pas le terminal.
        assert_eq!(liste[&(ip("2001:db8::7"), 2000)], "Nanocore\u{fffd}[2K RAT");
        // Une liste sans serveur reste une liste ; autre chose (portail Wi-Fi, ligne tronquée ou illisible) : pas
        // vérifiée, jamais vide.
        assert!(analyser_threatfox("# ThreatFox\r\n#\r\n").unwrap().is_empty());
        assert!(analyser_threatfox("").is_none());
        assert!(analyser_threatfox("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(analyser_threatfox("# ThreatFox\n\"2026-10-20\", \"1\", \"192.0.2.25:6662\"\n").is_none());
        assert!(
            analyser_threatfox(concat!(
                "# ThreatFox\n",
                "\"2026-10-20\", \"1\", \"pas-une-ip:80\", \"ip:port\", \"botnet_cc\", \"\", \"\", \"X\", \"\", \"75\"\n",
            ))
            .is_none()
        );
    }

    /// L'export complet avec clé (depuis le 21 oct. 2026) : un en-tête qui nomme les colonnes, dans un ordre qui peut
    /// changer, tous les genres mêlés ; les champs libres peuvent contenir des virgules et des guillemets.
    #[test]
    fn export_complet_de_threatfox_lu_par_son_entete() {
        assert_eq!(
            champs_csv(r#""a, b", "c ""d""",e,"#),
            Some(vec!["a, b".into(), "c \"d\"".into(), "e".into(), String::new()])
        );
        assert_eq!(champs_csv(r#""pas fermé"#), None);
        assert_eq!(champs_csv(r#""a"b"#), None);
        let texte = concat!(
            "\"ioc_id\",\"confidence_level\",\"ioc_type\",\"ioc_value\",\"threat_type\",\"malware_printable\",\"tags\"\r\n",
            "\"1\",\"100\",\"ip:port\",\"192.0.2.25:6662\",\"botnet_cc\",\"Cobalt Strike\",\"a, \"\"b\"\"\"\r\n",
            "\"2\",\"90\",\"domain\",\"Mal.Example.\",\"botnet_cc\",\"Vidar\",\"\"\r\n",
            "\"3\",\"100\",\"url\",\"https://198.51.100.9/x\",\"payload_delivery\",\"X\",\"\"\r\n",
            "\"4\",\"100\",\"ip:port\",\"198.51.100.4:80\",\"payload_delivery\",\"Y\",\"\"\r\n",
            "\"5\",\"50\",\"domain\",\"doute.example\",\"botnet_cc\",\"Z\",\"\"\r\n",
            "\"6\",\"100\",\"ip:port\",\"pas-une-ip:80\",\"botnet_cc\",\"W\",\"\"\r\n",
        );
        let serveurs = analyser_threatfox(texte).unwrap();
        assert_eq!(serveurs.len(), 1);
        assert_eq!(serveurs[&(ip("192.0.2.25"), 6662)], "Cobalt Strike");
        let domaines = analyser_domaines(texte).unwrap();
        assert_eq!(domaines.len(), 1);
        assert_eq!(domaines["mal.example"], "Vidar");
        // Un en-tête sans la colonne de confiance : pas une liste, jamais vide.
        assert!(analyser_threatfox(&texte.replace("confidence_level", "autre")).is_none());
        // Plus de la moitié des lignes illisibles : le format a changé, pas vérifiée.
        let abime = "\"ioc_type\",\"ioc_value\",\"threat_type\",\"malware_printable\",\"confidence_level\"\n\"ip:port\"\n\"ip:port\"\n";
        assert!(analyser_threatfox(abime).is_none());
    }

    #[test]
    fn reponse_de_l_api_threatfox_decodee() {
        // Réponse inventée, à la forme de celle de l'API : les autres genres (domaines, liens) sont sautés.
        let texte = r#"{"query_status": "ok", "data": [
            {"ioc": "192.0.2.25:6662", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "Cobalt Strike", "confidence_level": 75},
            {"ioc": "exemple.invalid", "ioc_type": "domain", "threat_type": "botnet_cc",
             "malware_printable": "X", "confidence_level": 100},
            {"ioc": "198.51.100.3:80", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "Douteux", "confidence_level": 50},
            {"ioc": "[2001:db8::7]:2000", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": null, "confidence_level": 100}
        ]}"#;
        let liste = analyser_threatfox_api(texte).unwrap();
        assert_eq!(liste.len(), 2);
        assert_eq!(liste[&(ip("192.0.2.25"), 6662)], "Cobalt Strike");
        assert_eq!(liste[&(ip("2001:db8::7"), 2000)], "");
        assert!(
            analyser_threatfox_api(r#"{"query_status": "no_result", "data": "Your search did not yield any results"}"#)
                .unwrap()
                .is_empty()
        );
        // Clé refusée, portail Wi-Fi, adresse illisible : pas vérifiée, jamais vide.
        assert!(analyser_threatfox_api(r#"{"query_status": "unknown_auth_key"}"#).is_none());
        assert!(analyser_threatfox_api("<html><body>Bienvenue au Salon</body></html>").is_none());
        assert!(
            analyser_threatfox_api(
                r#"{"query_status": "ok", "data": [{"ioc": "x:1", "ioc_type": "ip:port", "threat_type": "botnet_cc", "confidence_level": 100}]}"#
            )
            .is_none()
        );
    }

    #[test]
    fn domaines_de_threatfox() {
        let texte = concat!(
            "# ThreatFox IOCs: recent domains\r\n",
            "\"2026-10-20 14:29:08\", \"1\", \"mal.example\", \"domain\", \"botnet_cc\", \"win.vidar\", \"None\", \"Vidar\", \"\", \"100\", \"False\"\r\n",
            "\"2026-10-20 14:29:09\", \"2\", \"doute.example\", \"domain\", \"botnet_cc\", \"win.x\", \"None\", \"X\", \"\", \"50\", \"False\"\r\n",
        );
        let domaines = analyser_domaines(texte).unwrap();
        assert_eq!(domaines.len(), 1);
        // L'export complet mêle les genres : des liens n'y sont pas pris pour des domaines.
        assert!(
            analyser_domaines(&texte.replace("\"domain\"", "\"url\""))
                .unwrap()
                .is_empty()
        );
        let botnets = Botnets {
            domaines: Some(domaines),
            ..Botnets::default()
        };
        assert_eq!(
            botnets.domaine("mal.example").as_deref(),
            Some("mal.example (Vidar, ThreatFox)")
        );
        // Un sous-domaine, en majuscules, avec le point final du DNS : trouvé.
        assert_eq!(
            botnets.domaine("A.Mal.Example.").as_deref(),
            Some("a.mal.example (Vidar, ThreatFox)")
        );
        // Un nom qui finit pareil sans être un sous-domaine, ou un domaine parent : pas accusé.
        assert_eq!(botnets.domaine("normal.example"), None);
        assert_eq!(botnets.domaine("example"), None);
        assert_eq!(botnets.domaine("doute.example"), None);
        // Liste indisponible : rien n'est accusé ni dédouané ici.
        assert_eq!(Botnets::default().domaine("mal.example"), None);
    }

    #[test]
    fn botnet_signale_une_fois() {
        let actuelles = BTreeSet::from(["x → 192.0.2.25:6662 (Cobalt Strike, ThreatFox)".to_string()]);
        assert_eq!(nouvelles_alertes("", &actuelles).len(), 1);
        // Déjà vue à la passe d'avant : pas de deuxième notification ; une autre, si.
        assert_eq!(
            nouvelles_alertes("x → 192.0.2.25:6662 (Cobalt Strike, ThreatFox)", &actuelles).len(),
            0
        );
        assert_eq!(
            nouvelles_alertes("y → 198.51.100.1 (Feodo Tracker)", &actuelles).len(),
            1
        );
    }

    /// Un programme qui plante sa propre connexion dans la liste des déjà signalées ne se fait pas oublier : la
    /// liste changée hors de Vanguard ne vaut rien, la connexion est redite.
    #[test]
    fn liste_des_signalees_changee_a_cote_ignoree() {
        let vue = "x → 192.0.2.25:6662 (Cobalt Strike, ThreatFox)";
        crate::sceau::ecrire(crate::sceau::BOTNETS, vue).unwrap();
        assert_eq!(deja_signalees(), vue);
        let planquee = "y → 198.51.100.1 (Feodo Tracker)";
        std::fs::write(fichier_botnets(), format!("{vue}\n{planquee}")).unwrap();
        assert_eq!(deja_signalees(), "");
        let actuelles = BTreeSet::from([planquee.to_string()]);
        assert_eq!(nouvelles_alertes(&deja_signalees(), &actuelles).len(), 1);
        crate::sceau::effacer(crate::sceau::BOTNETS).unwrap();
    }

    /// Un site URLhaus écrit d'avance dans la liste des sites déjà signalés ne se fait pas oublier.
    #[test]
    fn sites_signales_poses_a_cote_ne_taisent_rien() {
        use crate::sceau::Lecture;
        let site = "malware.example (URLhaus)";
        let actuels = BTreeSet::from([site.to_string()]);
        assert_eq!(
            nouvelles_alertes(&sites_d_avant(Lecture::Intact(site.into())), &actuels),
            Vec::<&String>::new()
        );
        for lu in [
            Lecture::Falsifie(Some(site.into())),
            Lecture::Adopte(site.into()),
            Lecture::Inconnu,
            Lecture::Illisible("refusé".into()),
        ] {
            assert_eq!(nouvelles_alertes(&sites_d_avant(lu), &actuels).len(), 1);
        }
    }

    #[test]
    fn serveur_threatfox_reconnu_a_son_port() {
        let botnets = Botnets {
            threatfox: HashMap::from([((ip("192.0.2.25"), 6662), "Cobalt Strike".to_string())]),
            ..Botnets::default()
        };
        let vers = |distante: &str, port| Connexion {
            programme: Some("inconnu".into()),
            chemin: Some("/usr/bin/inconnu".into()),
            ..Connexion::vers(ip(distante), port)
        };
        let c = vers("192.0.2.25", 6662);
        let s = signes(c.chemin.as_deref(), &[(&c, None)], "", None, &botnets);
        assert_eq!(s[0].0, Niveau::Eleve);
        assert!(
            s[0].1.contains("192.0.2.25:6662 (Cobalt Strike, ThreatFox)"),
            "{}",
            s[0].1
        );
        // Même serveur vu par une prise IPv6 : la forme « ::ffff: » ne le cache pas.
        assert!(botnets.serveur(&vers("::ffff:192.0.2.25", 6662)).is_some());
        // Même adresse, autre port : un hébergeur partagé n'accuse pas tous ses clients.
        assert!(botnets.serveur(&vers("192.0.2.25", 443)).is_none());
    }

    // Linux : un programme mis à jour pendant qu'il tourne (Firefox après une mise à jour du système) a son ancien
    // fichier « (deleted) », mais un nouveau à la même place, installé par le système : une information. /usr/bin/env
    // appartient à root, dans un dossier que personne d'autre n'écrit.
    #[cfg(unix)]
    #[test]
    fn programme_du_systeme_mis_a_jour() {
        // Dans un espace de noms sans root (tests hors ligne : unshare -r), les fichiers de root paraissent à
        // « personne » : rien à essayer là.
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata("/usr/bin/env").map_or(true, |m| m.uid() != 0) {
            return crate::essais::saute("fichiers de root vus comme « personne » (unshare -r)");
        }
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let nom = "github.com".to_string();
        let s = signes(
            Some("/usr/bin/env (deleted)"),
            &[(&c, Some(&nom))],
            "",
            None,
            &Botnets::default(),
        );
        assert_eq!(s.iter().map(|(n, _)| *n).collect::<Vec<_>>(), [Niveau::Info]);
    }

    // Un fichier reposé là où la personne peut écrire (profil, dossier temporaire) ne prouve rien : un programme
    // malveillant qui s'est effacé n'aurait qu'à en reposer un. Le second signe vient du dossier temporaire du test.
    #[test]
    fn fichier_repose_par_la_personne() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let repose = dossier.join("firefox");
        std::fs::write(&repose, b"n'importe quoi").unwrap();
        // En root (ou root d'un espace de noms : tests hors ligne), ce que le test pose appartient à root : il ne peut
        // pas imiter « la personne ».
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if std::fs::metadata(&repose).is_ok_and(|m| m.uid() == 0) {
                let _ = std::fs::remove_dir_all(&dossier);
                return crate::essais::saute("en root : rien ne peut imiter la personne");
            }
        }
        let efface = format!("{} (deleted)", repose.display());
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let s = signes(Some(&efface), &[(&c, None)], "", None, &Botnets::default());
        assert_eq!(
            s.iter().map(|(n, _)| *n).take(2).collect::<Vec<_>>(),
            [Niveau::Eleve, Niveau::Eleve]
        );
        std::fs::remove_dir_all(&dossier).unwrap();
        // Plus rien à sa place : effacé pour de bon.
        let s = signes(Some(&efface), &[(&c, None)], "", None, &Botnets::default());
        assert_eq!(s[0].0, Niveau::Eleve);
    }

    // Fichier et dossier à root, dossier fermé au groupe et aux autres : hors de portée. /tmp appartient à root mais
    // tout le monde y écrit ; un fichier à la personne, ou un dossier qu'elle possède, non plus.
    #[test]
    fn portee_de_la_personne() {
        assert!(hors_de_portee(0, 0, 0o040_755));
        assert!(!hors_de_portee(0, 0, 0o041_777));
        assert!(!hors_de_portee(0, 0, 0o040_775));
        assert!(!hors_de_portee(1000, 0, 0o040_755));
        assert!(!hors_de_portee(0, 1000, 0o040_755));
    }

    // Une AppImage tourne depuis son image montée dans /tmp/.mount_* : pas un programme lancé d'un dossier temporaire.
    // Un simple dossier de ce nom, lui, n'est pas une image montée.
    /// Une AppImage montée se juge d'après son image (variable APPIMAGE de son environnement) : lancée depuis les
    /// Téléchargements, elle le dit ; rangée dans ~/Applications, rien à dire.
    #[test]
    fn appimage_jugee_d_apres_son_image() {
        let montages = "ArtCraft.AppImage /tmp/.mount_ArtCraXk2Pq fuse.ArtCraft.AppImage ro,nosuid,nodev 0 0\n";
        let monte = "/tmp/.mount_ArtCraXk2Pq/usr/bin/artcraft";
        let c = Connexion::vers(ip("140.82.112.4"), 443);
        let nom = "github.com".to_string();
        let telechargee = "/home/alice/Downloads/ArtCraft.AppImage";
        let niveaux = |image| {
            signes(Some(monte), &[(&c, Some(&nom))], montages, image, &Botnets::default())
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
        };
        assert_eq!(niveaux(Some(telechargee)), [Niveau::Eleve]);
        assert_eq!(niveaux(Some("/home/alice/Applications/ArtCraft.AppImage")), []);
        assert_eq!(niveaux(None), []);
        let environ = b"HOME=/home/alice\0APPIMAGE=/home/alice/Downloads/ArtCraft.AppImage\0APPDIR=/tmp/.mount_x\0";
        assert_eq!(image_appimage(environ).as_deref(), Some(telechargee));
        assert_eq!(image_appimage(b"HOME=/home/alice\0"), None);
    }

    #[test]
    fn appimage_montee() {
        let montages = "/dev/nvme0n1p2 / btrfs rw 0 0\n\
                        ArtCraft.AppImage /tmp/.mount_ArtCraXk2Pq fuse.ArtCraft.AppImage ro,nosuid,nodev 0 0\n";
        let appimage = "/tmp/.mount_ArtCraXk2Pq/usr/bin/artcraft";
        assert_eq!(dossier_risque(appimage, montages), None);
        assert_eq!(
            dossier_risque("/tmp/.mount_faux/miner", montages),
            Some("un dossier temporaire")
        );
        assert_eq!(dossier_risque(appimage, ""), Some("un dossier temporaire"));
    }

    #[test]
    fn noms_montres() {
        assert_eq!(qui("lhr25s34-in-f14.1e100.net"), "Google");
        assert_eq!(qui("lb-140-82-112-4-iad.github.com"), "GitHub");
        assert_eq!(qui("serveur.exemple.co.uk"), "exemple.co.uk");
    }

    #[test]
    fn chemin_invisible_jamais_coche() {
        assert!(marque(None, true).contains('✔'));
        assert!(marque(None, false).contains('?') && !marque(None, false).contains('✔'));
        assert!(marque(Some(Niveau::Eleve), false).contains('✖'));
    }

    /// Le veilleur relit les listes gardées sans réseau : une liste de Feodo Tracker posée sans sceau (vidée par un
    /// autre programme, datée dans le futur), ou effacée sous son sceau, n'est jamais crue vide, et c'est dit.
    #[cfg(target_os = "linux")]
    #[test]
    fn liste_gardee_forgee_dite_non_verifiee() {
        let (feodo, threatfox) = ("essai-feodo-gardee", "essai-threatfox-gardee");
        let d = crate::socle::dossier_local().join(feodo);
        std::fs::create_dir_all(&d).unwrap();
        let fichier = d.join("botnets.txt");
        std::fs::write(&fichier, b"# Feodo Tracker\n").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&fichier)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + Duration::from_hours(24 * 365))
            .unwrap();
        let (serveurs, absentes) = serveurs_gardes_dans(feodo, threatfox);
        assert!(serveurs.0.feodo.is_empty());
        let refus = crate::socle::cache::Refus::SansSceau.raison();
        assert!(
            absentes
                .iter()
                .any(|a| a.contains("Feodo Tracker") && a.contains(refus)),
            "{absentes:?}"
        );
        // Scellée par Vanguard puis effacée : pas « pas encore téléchargée », une copie effacée.
        crate::socle::cache::garder((feodo, "botnets.txt"), b"# Feodo Tracker\n").unwrap();
        std::fs::remove_file(&fichier).unwrap();
        let (_, absentes) = serveurs_gardes_dans(feodo, threatfox);
        let refus = crate::socle::cache::Refus::Effacee.raison();
        assert!(absentes.iter().any(|a| a.contains(refus)), "{absentes:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Propriétés des lectures des connexions, sur des sorties tirées au hasard : rien ne plante ; une connexion bien
/// écrite redonne son adresse, son port, son programme ; netstat ne compte jamais deux fois ce que lsof a vu.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;
    use std::net::SocketAddr;

    fn sortie() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}\u{202e}:%()\\[\\]\"|,=]{0,80}",
                "(tcp|udp) [0-9]+ [0-9]+ [0-9.:\\[\\]a-f%]{0,30} [0-9.:\\[\\]a-f%]{0,30}( users:\\(\\(\"[ -~]{0,10}\",pid=[0-9]{0,6},fd=[0-9]\\)\\))?",
                "[pcnf][ -~]{0,40}",
            ],
            0..12,
        )
        .prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lectures_sans_plantage(t in sortie()) {
            let _ = lire_proc_net(&t);
            let connexions = lire_lsof(&t);
            let _ = invisibles(&t, &connexions);
            for c in &connexions {
                prop_assert!(c.programme.as_deref().is_none_or(|p| !crate::ui::contient_un_piege(p)));
            }
        }

        #[test]
        fn adresse_redonnee(a in any::<SocketAddr>()) {
            // « 1.2.3.4:443 », « [2606:4700::1]:443 » : ce que ss et lsof écrivent.
            let lue = adresse_et_port(&a.to_string());
            prop_assert_eq!(lue, Some((a.ip(), a.port())));
        }

        #[test]
        fn proc_net_redonne_ses_valeurs(distante in any::<SocketAddr>(), inode in any::<u64>()) {
            // L'adresse écrite comme le noyau l'écrit : chaque mot de 32 bits tel que la machine le range.
            let hex: String = match distante.ip() {
                IpAddr::V4(v4) => format!("{:08X}", u32::from_ne_bytes(v4.octets())),
                IpAddr::V6(v6) => {
                    let o = v6.octets();
                    let mot = |i: usize| u32::from_ne_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
                    format!("{:08X}{:08X}{:08X}{:08X}", mot(0), mot(4), mot(8), mot(12))
                }
            };
            let ligne = format!("en-tête\n 0: 0100007F:0035 {hex}:{:04X} 01 0:0 00:0 0 1000 0 {inode} 1\n", distante.port());
            prop_assert_eq!(lire_proc_net(&ligne), [(distante.ip(), distante.port(), inode)]);
        }

        #[test]
        fn netstat_ne_compte_pas_deux_fois_ce_que_lsof_a_vu(
            vues in prop::collection::vec((any::<std::net::Ipv4Addr>(), any::<u16>()), 0..6),
            autres in prop::collection::vec((any::<std::net::Ipv4Addr>(), any::<u16>()), 0..6),
        ) {
            let lsof = vues.iter().map(|(ip, port)| format!("p1\ncx\nn10.0.0.2:50000->{ip}:{port}\n")).collect::<Vec<_>>().concat();
            let visibles = lire_lsof(&lsof);
            prop_assert_eq!(visibles.len(), vues.len());
            let netstat = vues
                .iter()
                .chain(&autres)
                .map(|(ip, port)| format!("tcp4 0 0 10.0.0.2.50000 {ip}.{port} ESTABLISHED\n"))
                .collect::<Vec<_>>()
                .concat();
            let restantes = invisibles(&netstat, &visibles);
            prop_assert_eq!(restantes.len(), autres.len());
        }
    }
}
