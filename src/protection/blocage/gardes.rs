//! Les garde-fous du blocage, en fonctions pures (testées sous Linux et sous Wine) : ce qui ne s'arrête, ne se met
//! en quarantaine ni ne se bloque jamais, même quand une liste ou une règle le désigne. Ce qu'ils refusent reste une
//! alerte, avec sa raison.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::machine::regles::Os;
use crate::tr;

/// Le noyau ou Idle (0), init, systemd ou launchd (1), System de Windows (4).
const PID_CRITIQUES: [u32; 3] = [0, 1, 4];

/// Les processus dont l'arrêt fait tomber le système ou la session (écran bleu, déconnexion), ou coupe une connexion
/// à distance : jamais arrêtés, même quand un programme ailleurs prend leur nom (une alerte le dit).
const NOMS_CRITIQUES: &[&str] = &[
    // Windows.
    "system",
    "idle",
    "registry",
    "secure system",
    "memory compression",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "lsaiso",
    "svchost",
    "dwm",
    "fontdrvhost",
    "msmpeng",
    // Linux et macOS.
    "systemd",
    "init",
    "kthreadd",
    "launchd",
    "kernel_task",
    "loginwindow",
    "windowserver",
    // Les sessions à distance en cours, de part et d'autre.
    "sshd",
    "sshd-session",
    "xrdp",
    "xrdp-sesman",
];

/// Le nom d'un processus comparé aux noms critiques : sans dossier, sans « .exe », en minuscules.
fn nom_simple(nom: &str) -> String {
    let fichier = nom.rsplit(['/', '\\']).next().unwrap_or(nom).trim().to_lowercase();
    fichier.strip_suffix(".exe").unwrap_or(&fichier).to_string()
}

/// Un programme du système : il ne s'arrête ni ne se met en quarantaine (une alerte seulement). Un chemin qui remonte
/// (« .. ») ne se juge pas : il est tenu pour du système.
pub(crate) fn dossier_systeme(chemin: &str, os: Os) -> bool {
    match os {
        Os::Windows => {
            let c = chemin.to_lowercase().replace('/', "\\");
            let c = c.strip_prefix(r"\\?\").unwrap_or(&c);
            if c.contains(r"\..\") {
                return true;
            }
            // « C:\Windows\… » quelle que soit la lettre du disque, et l'antivirus de Microsoft.
            let sans_lecteur = c
                .get(1..)
                .filter(|_| c.chars().next().is_some_and(|l| l.is_ascii_alphabetic()));
            sans_lecteur.is_some_and(|reste| {
                [
                    r":\windows\",
                    r":\program files\windows defender\",
                    r":\programdata\microsoft\windows defender\",
                ]
                .iter()
                .any(|d| reste.starts_with(d))
            })
        }
        Os::Linux | Os::MacOs | Os::Tous => {
            if chemin.contains("/../") || chemin.ends_with("/..") {
                return true;
            }
            let communs = [
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/lib/",
                "/usr/lib64/",
                "/usr/libexec/",
                "/usr/share/",
                "/bin/",
                "/sbin/",
                "/lib/",
                "/lib64/",
            ];
            let mac = ["/System/", "/Library/Apple/", "/private/var/db/"];
            communs.iter().any(|d| chemin.starts_with(d))
                || (os == Os::MacOs && mac.iter().any(|d| chemin.starts_with(d)))
        }
    }
}

/// Pourquoi ce processus ne doit jamais être arrêté, ou `None`. `intouchables` : Vanguard, ce qu'il a lancé et ce qui
/// le fait tourner (son terminal, sa session), d'après `chasse::en_marche`. Sans chemin lisible, rien ne s'arrête à
/// l'aveugle : un programme du système ne se reconnaîtrait pas.
pub(crate) fn processus_intouchable(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
    os: Os,
) -> Option<&'static str> {
    if PID_CRITIQUES.contains(&pid) || NOMS_CRITIQUES.contains(&nom_simple(nom).as_str()) {
        return Some(tr!(
            "processus critique du système : une alerte seulement",
            "critical system process: an alert only"
        ));
    }
    if intouchables.contains(&pid) || pid == std::process::id() {
        return Some(tr!(
            "Vanguard lui-même, ce qu'il a lancé ou ce qui le fait tourner (terminal, session)",
            "Vanguard itself, what it started or what runs it (terminal, session)"
        ));
    }
    let Some(chemin) = chemin else {
        return Some(tr!(
            "chemin du programme illisible sans droits d'administrateur : rien n'est arrêté à l'aveugle",
            "program path unreadable without administrator rights: nothing is stopped blindly"
        ));
    };
    if dossier_systeme(chemin, os) {
        return Some(tr!(
            "programme du système : une alerte seulement",
            "system program: an alert only"
        ));
    }
    None
}

/// Pourquoi ce processus ne doit jamais être GELÉ, ou `None`. Mêmes garde-fous que l'arrêt, sauf la règle « programme
/// du système » : geler python3 ou un outil du système est permis (c'est réversible et rien n'est effacé), l'arrêter
/// non. Jamais le noyau, init/systemd, le compositeur, la session, un terminal ou un shell (PID et noms critiques), ni
/// Vanguard et ce qu'il fait tourner : un bureau gelé ne pourrait plus cliquer « Reprendre ». Sans chemin lisible,
/// on ne gèle pas à l'aveugle.
#[cfg(target_os = "linux")]
pub(crate) fn processus_gelable(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
) -> Option<&'static str> {
    if PID_CRITIQUES.contains(&pid) || NOMS_CRITIQUES.contains(&nom_simple(nom).as_str()) {
        return Some(tr!(
            "processus critique du système : jamais gelé",
            "critical system process: never frozen"
        ));
    }
    if intouchables.contains(&pid) || pid == std::process::id() {
        return Some(tr!(
            "Vanguard lui-même, ce qu'il a lancé ou ce qui le fait tourner (terminal, session)",
            "Vanguard itself, what it started or what runs it (terminal, session)"
        ));
    }
    if chemin.is_none() {
        return Some(tr!(
            "chemin du programme illisible : rien n'est gelé à l'aveugle",
            "program path unreadable: nothing is frozen blindly"
        ));
    }
    None
}

/// Pourquoi ce fichier ne doit jamais être mis en quarantaine, ou `None` : un fichier du système, ou Vanguard.
pub(crate) fn fichier_intouchable(chemin: &str, os: Os, mon_programme: Option<&str>) -> Option<&'static str> {
    let meme = |m: &str| {
        if os == Os::Windows {
            m.eq_ignore_ascii_case(chemin)
        } else {
            m == chemin
        }
    };
    if mon_programme.is_some_and(meme) {
        return Some(tr!("Vanguard lui-même", "Vanguard itself"));
    }
    dossier_systeme(chemin, os).then_some(tr!(
        "fichier du système : une alerte seulement",
        "system file: an alert only"
    ))
}

/// Les résolveurs DNS publics les plus courants : les bloquer couperait Internet à toute la maison, même si une liste
/// les citait par erreur.
const DNS_PUBLICS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "45.90.28.0",
    "45.90.30.0",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
];

/// Une connexion TCP établie, telle que les garde-fous la jugent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Etablie {
    pub distante: IpAddr,
    pub port_local: u16,
    pub port_distant: u16,
    /// Le programme qui la tient, quand il se lit.
    pub programme: Option<String>,
    /// Elle appartient à un autre compte, ou à un compte qui ne se lit pas : le blocage automatique n'y touche pas.
    pub autre_compte: bool,
}

/// Les adresses que le blocage ne coupe pas, lues une fois par passage.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sessions {
    /// Celles des sessions à distance en cours : jamais coupées.
    pub sessions: Vec<IpAddr>,
    /// Celles où une connexion d'un autre compte est établie : jamais coupées tout seul, seulement d'un clic.
    pub autres_comptes: Vec<IpAddr>,
}

/// Pourquoi cette adresse ne doit pas être bloquée en sortie, ou `None`. `sessions` : ce que les connexions en cours
/// interdisent de couper ; `None` : illisibles, et rien n'est bloqué sans les connaître. `automatique` : le blocage se
/// fait sans clic, et ne touche alors jamais une adresse où un autre compte a une connexion établie.
pub(crate) fn adresse_intouchable(ip: IpAddr, sessions: Option<&Sessions>, automatique: bool) -> Option<&'static str> {
    let ip = ip.to_canonical();
    if !crate::socle::adresses::sur_internet(ip) {
        return Some(tr!(
            "adresse du réseau local ou de cet ordinateur : jamais bloquée",
            "address of the local network or of this computer: never blocked"
        ));
    }
    if DNS_PUBLICS.iter().any(|d| d.parse::<IpAddr>().is_ok_and(|d| d == ip)) {
        return Some(tr!(
            "serveur DNS public : le bloquer couperait Internet",
            "public DNS server: blocking it would cut the Internet"
        ));
    }
    match sessions {
        None => Some(tr!(
            "connexions à distance en cours illisibles : rien n'est bloqué sans savoir si l'une passe par là",
            "remote connections in progress unreadable: nothing is blocked without knowing whether one goes there"
        )),
        Some(s) if s.sessions.iter().any(|a| a.to_canonical() == ip) => Some(tr!(
            "une connexion à distance en cours (SSH, Bureau à distance, VPN, prise en main) passe par cette adresse : jamais coupée",
            "a remote connection in progress (SSH, Remote Desktop, VPN, remote control) goes through this address: never cut"
        )),
        Some(s) if automatique && s.autres_comptes.iter().any(|a| a.to_canonical() == ip) => Some(tr!(
            "un autre compte a une connexion établie avec cette adresse : jamais coupée toute seule, seulement d'un clic",
            "another account has a connection established with this address: never cut by itself, only with a click"
        )),
        Some(_) => None,
    }
}

/// Les ports de SSH et du Bureau à distance : jamais fermés en entrée, ce serait couper l'accès à distance.
const PORTS_DE_SESSION: [u16; 2] = [22, 3389];

pub(crate) fn port_intouchable(port: u16) -> Option<&'static str> {
    PORTS_DE_SESSION.contains(&port).then_some(tr!(
        "port de SSH ou du Bureau à distance : jamais fermé",
        "SSH or Remote Desktop port: never closed"
    ))
}

/// Les programmes d'accès à distance, de prise en main et de VPN : une connexion établie de l'un d'eux est une
/// session, quel que soit son port (SSH sur 2222, VNC, RustDesk, WireGuard…). Plus les VNC (« vnc* », « *vnc »).
const PROGRAMMES_DE_SESSION: &[&str] = &[
    "sshd",
    "sshd-session",
    "xrdp",
    "xrdp-sesman",
    "rustdesk",
    "anydesk",
    "parsec",
    "parsecd",
    "tailscaled",
    "tailscale",
    "wireguard",
    "wg",
    "wg-quick",
    "openvpn",
    "openvpn-gui",
    "openvpnserv",
    "mstsc",
    "teamviewer",
    "teamviewer_service",
];

fn programme_de_session(nom: &str) -> bool {
    let n = nom_simple(nom);
    PROGRAMMES_DE_SESSION.contains(&n.as_str()) || n.starts_with("vnc") || n.ends_with("vnc") || n.contains("vncserver")
}

/// Une connexion établie est-elle une session à distance : le port de SSH ou du Bureau à distance d'un côté ou de
/// l'autre, ou un programme d'accès à distance, de prise en main ou de VPN, quel que soit son port ?
pub(crate) fn est_session(e: &Etablie) -> bool {
    PORTS_DE_SESSION.contains(&e.port_local)
        || PORTS_DE_SESSION.contains(&e.port_distant)
        || e.programme.as_deref().is_some_and(programme_de_session)
}

/// Les adresses à ne pas couper, d'après les connexions établies et le client SSH de Vanguard.
pub(crate) fn juger_etablies(etablies: &[Etablie], client: Option<IpAddr>) -> Sessions {
    let mut s = Sessions::default();
    for e in etablies {
        let ip = e.distante.to_canonical();
        if est_session(e) {
            s.sessions.push(ip);
        }
        if e.autre_compte {
            s.autres_comptes.push(ip);
        }
    }
    s.sessions.extend(client.map(|c| c.to_canonical()));
    for liste in [&mut s.sessions, &mut s.autres_comptes] {
        liste.sort_unstable();
        liste.dedup();
    }
    s
}

/// L'adresse du client de la session SSH où tourne Vanguard (« SSH_CONNECTION=client port serveur port »), même sur
/// un autre port que 22.
pub(crate) fn client_ssh(valeur: &str) -> Option<IpAddr> {
    valeur
        .split_whitespace()
        .next()?
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_canonical())
}

/// Les connexions établies d'un fichier de /proc/net (tcp, tcp6) : « sl locale distante état … uid délai inode »,
/// état 01. `moi` : le compte de Vanguard ; `noms` : le programme de chaque prise (inode), quand il se lit.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn etablies_proc(texte: &str, moi: u32, noms: &std::collections::HashMap<u64, String>) -> Vec<Etablie> {
    let point = |t: &str| -> Option<(IpAddr, u16)> {
        let (adresse, port) = t.split_once(':')?;
        Some((
            crate::protection::sortantes::adresse_proc(adresse)?,
            u16::from_str_radix(port, 16).ok()?,
        ))
    };
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &"01" {
                return None;
            }
            let (_, port_local) = point(champs.get(1)?)?;
            let (distante, port_distant) = point(champs.get(2)?)?;
            let compte = champs.get(7).and_then(|u| u.parse::<u32>().ok());
            let inode = champs.get(9).and_then(|i| i.parse::<u64>().ok());
            Some(Etablie {
                distante: distante.to_canonical(),
                port_local,
                port_distant,
                programme: inode.and_then(|i| noms.get(&i).cloned()),
                autre_compte: compte != Some(moi),
            })
        })
        .collect()
}

/// Les connexions établies d'une table TCP de Windows (GetExtendedTcpTable, « propriétaire, toutes »), telle que la
/// rend `machine::windows::connexions::table_tcp` (la forme est lue par `connexions::lire_tcp`) : MIB_TCPROW_OWNER_PID
/// de 24 octets, MIB_TCP6ROW_OWNER_PID de 56. → (port local, adresse distante, port distant, processus).
#[cfg(any(windows, test))]
pub(crate) fn etablies_table(octets: &[u8], ipv6: bool) -> Vec<(u16, IpAddr, u16, u32)> {
    let mot = |o: &[u8], i: usize| o.get(i..i + 4).map(|m| u32::from_ne_bytes([m[0], m[1], m[2], m[3]]));
    let port = |o: &[u8], i: usize| o.get(i..i + 2).map(|m| u16::from_be_bytes([m[0], m[1]]));
    let (taille, port_local, adresse, port_distant, etat, processus) = if ipv6 {
        (56, 20, 24, 44, 48, 52)
    } else {
        (24, 8, 12, 16, 0, 20)
    };
    let Some(nombre) = mot(octets, 0) else {
        return Vec::new();
    };
    octets
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(taille)
        .take(usize::try_from(nombre).unwrap_or(usize::MAX))
        .filter(|l| mot(l, etat) == Some(5))
        .filter_map(|l| {
            let distante = if ipv6 {
                IpAddr::from(<[u8; 16]>::try_from(l.get(adresse..adresse + 16)?).ok()?)
            } else {
                IpAddr::from(<[u8; 4]>::try_from(l.get(adresse..adresse + 4)?).ok()?)
            };
            Some((
                port(l, port_local)?,
                distante.to_canonical(),
                port(l, port_distant)?,
                mot(l, processus)?,
            ))
        })
        .collect()
}

/// « 192.168.1.5.22 » (netstat de macOS) ou « 192.168.1.5:22 », « [2001:db8::7]:443 » (lsof) → (adresse, port).
#[cfg(any(target_os = "macos", test))]
fn point_texte(t: &str, separateur: char) -> Option<(IpAddr, u16)> {
    let (ip, port) = t.rsplit_once(separateur)?;
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    Some((
        ip.split('%').next()?.parse::<IpAddr>().ok()?.to_canonical(),
        port.parse().ok()?,
    ))
}

/// Les connexions établies sous macOS : toutes d'après `netstat -anp tcp` (« tcp4 0 0 192.168.1.5.22
/// 192.168.1.20.51234 ESTABLISHED »), et leur programme d'après `lsof -F pcn` (« p », « c », « n
/// locale->distante »), qui ne voit que celles de ce compte : une connexion que lsof ne voit pas est d'un autre.
#[cfg(test)]
pub(crate) fn etablies_macos(netstat: &str, lsof: &str) -> Vec<Etablie> {
    etablies_avec(netstat, &etablies_lsof(lsof))
}

/// Les connexions de ce compte d'après `lsof -F pcn` : (programme, port local, adresse distante, port distant).
#[cfg(any(target_os = "macos", test))]
fn etablies_lsof(lsof: &str) -> Vec<(String, u16, IpAddr, u16)> {
    let mut a_moi: Vec<(String, u16, IpAddr, u16)> = Vec::new();
    let mut programme = String::new();
    for l in lsof.lines() {
        let mut lettres = l.chars();
        match lettres.next() {
            Some('c') => programme = lettres.as_str().to_string(),
            Some('n') => {
                if let Some((locale, distante)) = lettres.as_str().split_once("->")
                    && let (Some((_, pl)), Some((ip, pd))) = (point_texte(locale, ':'), point_texte(distante, ':'))
                {
                    a_moi.push((programme.clone(), pl, ip, pd));
                }
            }
            _ => {}
        }
    }
    a_moi
}

/// Toutes les connexions établies de `netstat -anp tcp`, chacune avec son programme quand elle est dans `a_moi` (les
/// connexions lues de ce compte) ; les autres sont d'un autre compte.
#[cfg(any(target_os = "macos", test))]
fn etablies_avec(netstat: &str, a_moi: &[(String, u16, IpAddr, u16)]) -> Vec<Etablie> {
    netstat
        .lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (_, port_local) = point_texte(mots.get(3)?, '.')?;
            let (distante, port_distant) = point_texte(mots.get(4)?, '.')?;
            let mien = a_moi
                .iter()
                .find(|(_, pl, ip, pd)| *pl == port_local && *ip == distante && *pd == port_distant);
            Some(Etablie {
                distante,
                port_local,
                port_distant,
                programme: mien.map(|(p, ..)| p.clone()),
                autre_compte: mien.is_none(),
            })
        })
        .collect()
}

/// Ce que les connexions en cours interdisent de couper sur cet ordinateur : les sessions à distance, entrantes comme
/// sortantes, celle du client SSH de Vanguard, et les adresses des connexions d'autres comptes. `None` : la table des
/// connexions ne se lit pas.
pub(crate) fn sessions_a_distance() -> Option<Sessions> {
    let etablies = lire_etablies()?;
    let client = std::env::var("SSH_CONNECTION").ok().as_deref().and_then(client_ssh);
    Some(juger_etablies(&etablies, client))
}

#[cfg(target_os = "linux")]
fn lire_etablies() -> Option<Vec<Etablie>> {
    let noms: std::collections::HashMap<u64, String> = crate::protection::sortantes::proprietaires()
        .into_iter()
        .filter_map(|(inode, pid)| {
            let nom = crate::socle::processus::nom_court(pid)?;
            Some((inode, nom.trim_end().to_string()))
        })
        .collect();
    // SAFETY : geteuid ne prend aucun argument et ne touche aucune mémoire.
    let moi = unsafe { libc::geteuid() };
    let mut lisible = false;
    let mut etablies = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(t) = std::fs::read_to_string(f) {
            lisible = true;
            etablies.extend(etablies_proc(&t, moi, &noms));
        }
    }
    lisible.then_some(etablies)
}

#[cfg(windows)]
fn lire_etablies() -> Option<Vec<Etablie>> {
    use crate::machine::windows::processus;
    let v4 = crate::protection::sortantes::table_tcp(2).map(|t| etablies_table(&t, false));
    let v6 = crate::protection::sortantes::table_tcp(23).map(|t| etablies_table(&t, true));
    if v4.is_none() && v6.is_none() {
        return None;
    }
    let lignes: Vec<(u16, IpAddr, u16, u32)> = v4.into_iter().chain(v6).flatten().collect();
    let noms: std::collections::HashMap<u32, String> = processus::liste().into_iter().map(|p| (p.pid, p.nom)).collect();
    let moi = processus::compte_de(std::process::id());
    let mut comptes: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    Some(
        lignes
            .into_iter()
            .map(|(port_local, distante, port_distant, pid)| {
                let compte = comptes.entry(pid).or_insert_with(|| processus::compte_de(pid));
                Etablie {
                    distante,
                    port_local,
                    port_distant,
                    programme: noms.get(&pid).cloned(),
                    // Un compte qui ne se lit pas (System, un autre compte sans droits) compte comme un autre.
                    autre_compte: moi.is_empty() || compte.is_empty() || !compte.eq_ignore_ascii_case(&moi),
                }
            })
            .collect(),
    )
}

/// netstat fait foi pour les connexions de tous les comptes (xinpcb_n est privé) ; celles de ce compte se lisent au
/// noyau (libproc), lsof en secours tant que l'oracle de macos.yml n'a pas prouvé la lecture native.
#[cfg(target_os = "macos")]
fn lire_etablies() -> Option<Vec<Etablie>> {
    use std::process::Command;
    let n = crate::commande::lancer(Command::new("netstat").args(["-anp", "tcp"]), 15).filter(|r| r.code == Some(0))?;
    let natives: Option<Vec<(String, u16, IpAddr, u16)>> = crate::machine::macos::noyau::prises()
        .map(|lues| {
            lues.prises
                .into_iter()
                .filter(|(_, _, p)| p.tcp && p.etat == crate::machine::darwin::TSI_S_ESTABLISHED)
                .map(|(_, nom, p)| (nom, p.port_local, p.distante.to_canonical(), p.port_distant))
                .collect()
        })
        .filter(|l: &Vec<_>| !l.is_empty());
    let a_moi = natives.unwrap_or_else(|| {
        // lsof répond 1 quand il ne trouve rien : alors rien n'est à ce compte.
        let lsof = crate::commande::lancer(
            Command::new("lsof").args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"]),
            20,
        )
        .map(|r| r.sortie)
        .unwrap_or_default();
        etablies_lsof(&lsof)
    });
    Some(etablies_avec(&n.sortie, &a_moi))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    /// Garde-fou : jamais un processus critique (PID 0, 1, 4, ou nom critique), jamais Vanguard ni ce qui le fait
    /// tourner, jamais un programme du système, jamais un programme dont le chemin ne se lit pas.
    #[test]
    fn processus_jamais_arretes() {
        let rien = HashSet::new();
        let j = |pid, nom, chemin, os| processus_intouchable(pid, nom, chemin, &rien, os);
        for pid in [0, 1, 4] {
            assert!(j(pid, "x", Some("/home/alice/x"), Os::Linux).is_some(), "{pid}");
        }
        for nom in [
            "csrss.exe",
            "LSASS.EXE",
            "smss",
            "wininit.exe",
            "services.exe",
            "winlogon.exe",
            "svchost.exe",
            "systemd",
            "launchd",
            "kernel_task",
            "sshd",
        ] {
            // Même lancé hors de son dossier (un imposteur) : une alerte seulement, jamais d'arrêt.
            assert!(
                j(4242, nom, Some(r"C:\Users\alice\AppData\Local\Temp\x.exe"), Os::Windows).is_some(),
                "{nom}"
            );
        }
        assert!(j(4242, "outil", Some(r"C:\Windows\System32\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "outil", Some(r"\\?\D:\WINDOWS\SysWOW64\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "python3", Some("/usr/bin/python3.12"), Os::Linux).is_some());
        assert!(j(4242, "outil", Some("/System/Library/x"), Os::MacOs).is_some());
        assert!(j(4242, "outil", None, Os::Linux).is_some());
        // Vanguard, ce qu'il a lancé, son terminal : intouchables.
        let vanguard: HashSet<u32> = [4300, 4301, 4299].into();
        assert!(processus_intouchable(4300, "vanguard", Some("/home/alice/vanguard"), &vanguard, Os::Linux).is_some());
        assert!(processus_intouchable(std::process::id(), "x", Some("/home/alice/x"), &rien, Os::Linux).is_some());
        // Un programme ordinaire d'un dossier du compte : rien ne l'empêche.
        assert_eq!(
            j(
                4242,
                "mimikatz.exe",
                Some(r"C:\Users\alice\Downloads\mimikatz.exe"),
                Os::Windows
            ),
            None
        );
        assert_eq!(j(4242, "xmrig", Some("/home/alice/.cache/xmrig"), Os::Linux), None);
        assert_eq!(j(4242, "xmrig", Some("/usr/local/bin/xmrig"), Os::Linux), None);
    }

    #[test]
    fn dossiers_du_systeme() {
        assert!(dossier_systeme("/usr/lib/firefox/firefox", Os::Linux));
        assert!(dossier_systeme("/sbin/init", Os::Linux));
        assert!(dossier_systeme("/home/alice/../../usr/bin/x", Os::Linux));
        assert!(!dossier_systeme(
            "/home/alice/Téléchargements/facture.pdf.sh",
            Os::Linux
        ));
        assert!(!dossier_systeme("/opt/outil/outil", Os::Linux));
        // /System n'est du système que sous macOS ; /Library/Apple aussi.
        assert!(!dossier_systeme("/System/x", Os::Linux));
        assert!(dossier_systeme("/Library/Apple/System/x", Os::MacOs));
        assert!(!dossier_systeme("/Users/alice/Library/x", Os::MacOs));
        assert!(dossier_systeme(r"c:\windows\explorer.exe", Os::Windows));
        assert!(dossier_systeme("C:/Windows/System32/cmd.exe", Os::Windows));
        assert!(dossier_systeme(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            Os::Windows
        ));
        assert!(dossier_systeme(r"C:\Users\alice\..\..\Windows\x.exe", Os::Windows));
        assert!(!dossier_systeme(
            r"C:\Users\alice\AppData\Roaming\Windows\x.exe",
            Os::Windows
        ));
        assert!(!dossier_systeme(r"C:\ProgramData\Updater\x.exe", Os::Windows));
        assert!(!dossier_systeme("windows", Os::Windows));
    }

    #[test]
    fn fichiers_jamais_en_quarantaine() {
        assert!(fichier_intouchable("/usr/bin/curl", Os::Linux, None).is_some());
        assert!(fichier_intouchable("/home/alice/vanguard", Os::Linux, Some("/home/alice/vanguard")).is_some());
        assert!(
            fichier_intouchable(r"E:\VANGUARD.EXE", Os::Windows, Some(r"e:\vanguard.exe")).is_some(),
            "casse de Windows"
        );
        assert_eq!(
            fichier_intouchable("/home/alice/Téléchargements/x", Os::Linux, Some("/home/alice/vanguard")),
            None
        );
    }

    fn etablie(distante: &str, port_local: u16, port_distant: u16, programme: Option<&str>, autre: bool) -> Etablie {
        Etablie {
            distante: ip(distante),
            port_local,
            port_distant,
            programme: programme.map(str::to_string),
            autre_compte: autre,
        }
    }

    /// Garde-fou : jamais couper une connexion à distance en cours, ni bloquer le réseau local ou un DNS public.
    #[test]
    fn adresses_jamais_bloquees() {
        let sessions = Sessions {
            sessions: vec![ip("198.51.100.20")],
            autres_comptes: vec![ip("203.0.113.9")],
        };
        let s = Some(&sessions);
        for auto in [false, true] {
            assert!(adresse_intouchable(ip("198.51.100.20"), s, auto).is_some());
            assert!(adresse_intouchable(ip("::ffff:198.51.100.20"), s, auto).is_some());
            assert!(
                adresse_intouchable(ip("203.0.113.7"), None, auto).is_some(),
                "sessions illisibles"
            );
            assert!(adresse_intouchable(ip("192.168.1.1"), s, auto).is_some());
            assert!(adresse_intouchable(ip("127.0.0.1"), s, auto).is_some());
            assert!(adresse_intouchable(ip("8.8.8.8"), s, auto).is_some());
            assert!(adresse_intouchable(ip("2606:4700:4700::1111"), s, auto).is_some());
            assert_eq!(adresse_intouchable(ip("185.220.101.4"), s, auto), None);
        }
        // Défaut de la relecture : une connexion d'un autre compte vers l'adresse. Jamais coupée toute seule ;
        // d'un clic, oui.
        assert!(adresse_intouchable(ip("203.0.113.9"), s, true).is_some());
        assert_eq!(adresse_intouchable(ip("203.0.113.9"), s, false), None);
        assert!(port_intouchable(22).is_some() && port_intouchable(3389).is_some());
        assert_eq!(port_intouchable(11434), None);
    }

    /// Défaut de la relecture : une session n'était vue que sur les ports 22 et 3389. Un programme d'accès à
    /// distance, de prise en main ou de VPN en est une, quel que soit son port.
    #[test]
    fn sessions_par_le_programme_et_par_le_port() {
        let etablies = [
            etablie("192.168.1.20", 2222, 51234, Some("sshd"), true),
            etablie("198.51.100.30", 51000, 21118, Some("rustdesk"), false),
            etablie("198.51.100.31", 51001, 51820, Some("wireguard.exe"), false),
            etablie("198.51.100.32", 5901, 50000, Some("Xvnc"), false),
            etablie("198.51.100.33", 5900, 50001, Some("vncserver-x11"), false),
            etablie("198.51.100.34", 51002, 443, Some("tailscaled"), false),
            etablie("198.51.100.35", 3389, 50002, None, true),
            etablie("203.0.113.7", 51003, 443, Some("firefox"), false),
            etablie("203.0.113.8", 51004, 443, None, true),
        ];
        let s = juger_etablies(&etablies, Some(ip("198.51.100.40")));
        assert_eq!(
            s.sessions,
            [
                "192.168.1.20",
                "198.51.100.30",
                "198.51.100.31",
                "198.51.100.32",
                "198.51.100.33",
                "198.51.100.34",
                "198.51.100.35",
                "198.51.100.40",
            ]
            .map(ip)
        );
        assert_eq!(
            s.autres_comptes,
            ["192.168.1.20", "198.51.100.35", "203.0.113.8"].map(ip)
        );
        for nom in [
            "sshd",
            "anydesk.exe",
            "AnyDesk",
            "openvpn",
            "wg",
            "parsecd",
            "x11vnc",
            "vncserver",
        ] {
            assert!(programme_de_session(nom), "{nom}");
        }
        assert!(!programme_de_session("firefox") && !programme_de_session("ssh-agent"));
    }

    #[test]
    fn connexions_etablies_lues() {
        // Linux : la prise 11 est à ce compte (1000) et à sshd ; la 12 à root ; la 14 n'est pas établie.
        let proc = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0501A8C0:08AE 1401A8C0:C822 01 00000000:00000000 00:00000000 00000000  1000        0 11 1
   1: 0501A8C0:D431 07AB33CB:0016 01 00000000:00000000 00:00000000 00000000     0        0 12 1
   2: 0501A8C0:D432 04AB33CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 13 1
   3: 0501A8C0:0016 1501A8C0:C823 0A 00000000:00000000 00:00000000 00000000  1000        0 14 1
";
        let noms = [(11u64, "sshd".to_string())].into();
        let e = etablies_proc(proc, 1000, &noms);
        assert_eq!(
            e,
            [
                etablie("192.168.1.20", 2222, 0xC822, Some("sshd"), false),
                etablie("203.51.171.7", 0xD431, 22, None, true),
                etablie("203.51.171.4", 0xD432, 443, None, false),
            ]
        );
        let s = juger_etablies(&e, None);
        assert_eq!(s.sessions, [ip("192.168.1.20"), ip("203.51.171.7")]);
        assert_eq!(s.autres_comptes, [ip("203.51.171.7")]);
        // Windows : une session du Bureau à distance (port local 3389) en IPv4, et une connexion web.
        let mut table = 2u32.to_ne_bytes().to_vec();
        for (etat, local, distante, distant, pid) in [
            (5u32, 3389u16, [198, 51, 100, 9], 50_000u16, 1234u32),
            (5, 50_001, [203, 0, 113, 7], 443, 4321),
        ] {
            table.extend(etat.to_ne_bytes());
            table.extend([192, 168, 1, 5]);
            table.extend(u32::from(local).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(distante);
            table.extend(u32::from(distant).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(pid.to_ne_bytes());
        }
        assert_eq!(
            etablies_table(&table, false),
            [
                (3389, ip("198.51.100.9"), 50_000, 1234),
                (50_001, ip("203.0.113.7"), 443, 4321)
            ]
        );
        // macOS : netstat voit tout, lsof seulement ce compte.
        let netstat = "tcp4       0      0  192.168.1.5.22         192.168.1.20.51234     ESTABLISHED
tcp4       0      0  192.168.1.5.51000      203.0.113.7.443        ESTABLISHED
tcp6       0      0  2001:db8::5.51001      2001:db8::7.5938       ESTABLISHED
";
        let lsof = "p501\ncfirefox\nn192.168.1.5:51000->203.0.113.7:443\np502\ncTeamViewer\nn[2001:db8::5]:51001->[2001:db8::7]:5938\n";
        let e = etablies_macos(netstat, lsof);
        assert_eq!(
            e,
            [
                etablie("192.168.1.20", 22, 51234, None, true),
                etablie("203.0.113.7", 51000, 443, Some("firefox"), false),
                etablie("2001:db8::7", 51001, 5938, Some("TeamViewer"), false),
            ]
        );
        assert_eq!(
            juger_etablies(&e, None).sessions,
            [ip("192.168.1.20"), ip("2001:db8::7")]
        );
        assert_eq!(
            client_ssh("198.51.100.20 51234 192.168.1.5 22"),
            Some(ip("198.51.100.20"))
        );
        assert_eq!(client_ssh(""), None);
    }
}
