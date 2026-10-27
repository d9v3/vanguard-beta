//! DNS : quel serveur traduit les noms de sites pour cette machine, et répond-il honnêtement ?
//! Un DNS changé en douce (malware, box piratée, réseau piégé) envoie tes visites où il veut, même vers un faux
//! site de banque à la bonne adresse : c'est l'une des premières choses que modifie un malware.

use std::net::IpAddr;
use std::time::Duration;

use super::{Constat, alerte, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "DNS";

/// D'où vient un serveur DNS.
#[derive(Debug, PartialEq)]
enum Origine {
    /// Résolveur sur cette machine (systemd-resolved, NextDNS, dnscrypt-proxy…).
    Local,
    /// Box, routeur ou serveur du réseau local.
    Reseau,
    /// Service public connu.
    Connu(&'static str),
    /// Serveur d'Internet qui n'est dans aucune liste : souvent celui du fournisseur Internet.
    Inconnu,
}

/// Le DNS gratuit de l'ACEI, qui gère le .ca : « Privé » (…10, aucun filtre), « Protégé » (…20, sites malveillants
/// bloqués), « Famille » (…30, contenus pour adultes aussi).
pub(crate) fn bouclier_canadien() -> &'static str {
    tr!("Bouclier canadien de l'ACEI", "CIRA Canadian Shield")
}

/// Les adresses du Bouclier canadien qui filtrent (« Protégé », « Famille ») ; « Privé » ne filtre rien.
pub(crate) fn bouclier_canadien_filtrant(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(v4.octets(), [149, 112, 121 | 122, 20 | 30]),
        IpAddr::V6(v6) => matches!(v6.segments(), [0x2620, 0x10a, 0x80bb | 0x80bc, 0, 0, 0, 0, 0x20 | 0x30]),
    }
}

/// Services DNS publics reconnus à leur adresse.
fn fournisseur(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => match v4.octets() {
            [1, 1, 1, _] | [1, 0, 0, _] => Some("Cloudflare"),
            [8, 8, 8, 8] | [8, 8, 4, 4] => Some("Google"),
            [9, 9, 9, _] | [149, 112, 112, _] => Some("Quad9"),
            [208, 67, 222 | 220, _] => Some("OpenDNS"),
            [45, 90, 28 | 30, _] => Some("NextDNS"),
            [94, 140, 14 | 15, _] => Some("AdGuard DNS"),
            [194, 242, 2, _] => Some("Mullvad DNS"),
            [185, 228, 168 | 169, _] => Some("CleanBrowsing"),
            [76, 76, 2 | 10, _] => Some("Control D"),
            [100, 100, 100, 100] => Some("Tailscale"),
            [149, 112, 121 | 122, _] => Some(bouclier_canadien()),
            _ => None,
        },
        IpAddr::V6(v6) => match v6.segments() {
            [0x2606, 0x4700, ..] => Some("Cloudflare"),
            [0x2001, 0x4860, ..] => Some("Google"),
            [0x2620, 0xfe, ..] => Some("Quad9"),
            [0x2620, 0x119, ..] => Some("OpenDNS"),
            [0x2a07, 0xa8c0 | 0xa8c1, ..] => Some("NextDNS"),
            [0x2a10, 0x50c0, ..] => Some("AdGuard DNS"),
            [0x2a07, 0xe340, ..] => Some("Mullvad DNS"),
            [0x2620, 0x10a, 0x80bb | 0x80bc, ..] => Some(bouclier_canadien()),
            _ => None,
        },
    }
}

fn origine(ip: IpAddr) -> Origine {
    if ip.is_loopback() {
        return Origine::Local;
    }
    if let Some(nom) = fournisseur(ip) {
        return Origine::Connu(nom);
    }
    // Adresses partagées (CGNAT, VPN maillés) et site local fec0::/10 (les DNS que Windows se donne quand le réseau
    // n'en annonce aucun) comprises : la règle commune.
    if crate::socle::adresses::du_reseau(ip) {
        Origine::Reseau
    } else {
        Origine::Inconnu
    }
}

/// Adresse d'une ligne de configuration : « 1.1.1.1#cloudflare-dns.com » (DNS chiffré de resolved) ou
/// « fe80::1%3 » (zone IPv6) gardent seulement l'adresse.
fn adresse(texte: &str) -> Option<IpAddr> {
    texte
        .split(['#', '%'])
        .next()?
        .trim()
        .trim_matches(['[', ']'])
        .parse()
        .ok()
}

/// Serveurs listés par `resolvectl dns` (« Global: 127.0.0.1 », « Link 3 (wlan0): 10.0.0.1 »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn lire_resolvectl(sortie: &str) -> Vec<IpAddr> {
    sortie
        .lines()
        .filter_map(|l| l.split_once(':').map(|(_, reste)| reste))
        .flat_map(str::split_whitespace)
        .filter_map(adresse)
        .collect()
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn lire_resolv_conf(texte: &str) -> Vec<IpAddr> {
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(adresse)
        .collect()
}

/// Ce qu'on sait des serveurs DNS de la machine.
struct Serveurs {
    /// (adresse, réglée à la main) ; Linux ne dit pas d'où vient un serveur : toujours `false`.
    liste: Vec<(IpAddr, bool)>,
    /// Requêtes chiffrées (DNS over TLS, résolveur local chiffrant), quand on peut le savoir.
    chiffre: Option<bool>,
    /// Programme qui résout les noms en local (« NextDNS »…).
    resolveur_local: Option<&'static str>,
    /// Commande qui remet les DNS d'une interface en automatique (Windows), par adresse.
    remise: Vec<(IpAddr, String)>,
}

/// Les serveurs amont de systemd-resolved, qu'il réécrit à chaque changement (ceux de `resolvectl dns`).
#[cfg(target_os = "linux")]
pub(crate) const RESOLV_CONF_AMONT: &str = "/run/systemd/resolve/resolv.conf";

/// Résolveurs locaux connus : (service systemd ; nom affiché ; chiffre ses requêtes).
#[cfg(target_os = "linux")]
const RESOLVEURS: &[(&str, &str, bool)] = &[
    ("nextdns", "NextDNS", true),
    ("dnscrypt-proxy", "dnscrypt-proxy", true),
    ("stubby", "Stubby", true),
    ("cloudflared", "cloudflared", true),
    ("AdGuardHome", "AdGuard Home", false),
    ("unbound", "Unbound", false),
    ("dnsmasq", "dnsmasq", false),
    ("pihole-FTL", "Pi-hole", false),
];

#[cfg(target_os = "linux")]
fn serveurs() -> Option<Serveurs> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let mut liste = lire_resolv_conf(&conf);
    let mut chiffre = None;
    // 127.0.0.53 : systemd-resolved, qui transmet aux vrais serveurs. Il les écrit lui-même dans son
    // resolv.conf « amont » ; resolvectl ne sert plus qu'en secours, si ce fichier manque.
    if liste.iter().any(|ip| *ip == IpAddr::from([127, 0, 0, 53]))
        && let Some(vrais) = std::fs::read_to_string(RESOLV_CONF_AMONT)
            .ok()
            .map(|t| lire_resolv_conf(&t))
            .or_else(|| resolved_par_dbus().ok().map(|r| r.serveurs))
            .or_else(|| super::sortie("resolvectl", &["dns"]).map(|d| lire_resolvectl(&d)))
    {
        if !vrais.is_empty() {
            liste = vrais;
        }
        // DNS over TLS : l'état n'est écrit dans aucun fichier (resolved.conf dit la consigne, pas ce qui
        // tourne) ; resolved le dit par D-Bus, lien par lien. resolvectl status ne sert plus qu'en secours.
        chiffre = match resolved_par_dbus() {
            Ok(r) => r.chiffre,
            // resolved arrêté : rien de su, comme avant.
            Err(e) if crate::machine::linux::dbus::service_absent(&e.to_string()) => None,
            Err(_) => super::sortie("resolvectl", &["status"]).map(|s| s.contains("+DNSOverTLS")),
        };
    }
    let mut resolveur_local = None;
    if liste.iter().any(IpAddr::is_loopback) {
        // Le service actif, lu dans les groupes de contrôle de /proc (un seul passage) au lieu de systemctl
        // is-active, qui ne sert plus qu'en secours quand /proc cache les autres comptes. Un processus du même
        // nom hors du service (lancé à la main, conteneur, dnsmasq de libvirt) ne compte pas : il n'est pas le
        // DNS de la machine et ferait dire « chiffré » à tort. Le premier de la liste gagne, comme avant.
        let noms: Vec<&str> = RESOLVEURS.iter().map(|r| r.0).collect();
        // En secours, l'état que systemd tient lui-même (par le bus, sinon systemctl), pour tous à la fois.
        let actifs = crate::machine::linux::natif::services_actifs(&noms)
            .unwrap_or_else(|| crate::machine::linux::services_systemd_actifs(&noms));
        if let Some((_, nom, chiffrant)) = RESOLVEURS.iter().zip(actifs).find(|(_, actif)| *actif).map(|(r, _)| *r) {
            resolveur_local = Some(nom);
            if chiffrant {
                chiffre = Some(true);
            }
        }
    }
    Some(Serveurs {
        liste: liste.into_iter().map(|ip| (ip, false)).collect(),
        chiffre,
        resolveur_local,
        remise: Vec::new(),
    })
}

/// Ce que systemd-resolved dit par D-Bus : ses serveurs, et si toutes ses requêtes partent chiffrées.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq)]
struct Resolved {
    serveurs: Vec<IpAddr>,
    /// `Some(true)` : chaque lien qui porte des serveurs (et le réglage global, s'il en porte) est en DNS over TLS
    /// strict (« yes ») ; « opportunistic » retombe en clair si le serveur ne parle pas TLS : pas chiffré.
    chiffre: Option<bool>,
}

/// Le mode DNS over TLS d'un lien : le sien, sinon (vide) le réglage global, comme le fait resolved.
#[cfg(target_os = "linux")]
fn mode_effectif<'a>(lien: &'a str, global: &'a str) -> &'a str {
    if lien.is_empty() { global } else { lien }
}

/// Les serveurs de la propriété DNS du gestionnaire de resolved (`a(iiay)` : interface, famille, adresse), dans
/// l'ordre, avec l'interface de chacun (0 : réglage global).
#[cfg(target_os = "linux")]
fn serveurs_resolved(dns: &crate::machine::linux::dbus::Valeur) -> Vec<(i32, IpAddr)> {
    use crate::machine::linux::dbus::Valeur;
    dns.elements()
        .iter()
        .filter_map(|s| {
            let [Valeur::I32(lien), Valeur::I32(famille), octets] = s.elements() else {
                return None;
            };
            let o: Vec<u8> = octets
                .elements()
                .iter()
                .filter_map(|v| match v {
                    Valeur::Octet(o) => Some(*o),
                    _ => None,
                })
                .collect();
            let ip = match (*famille, o.len()) {
                (libc::AF_INET, 4) => IpAddr::from([o[0], o[1], o[2], o[3]]),
                (libc::AF_INET6, 16) => IpAddr::from(<[u8; 16]>::try_from(o.as_slice()).ok()?),
                _ => return None,
            };
            Some((*lien, ip))
        })
        .collect()
}

/// Le jugement « chiffré » d'après le mode global et celui de chaque lien qui porte des serveurs. Sans aucun serveur
/// connu, le réglage global seul.
#[cfg(target_os = "linux")]
fn chiffre_resolved(
    serveurs: &[(i32, IpAddr)],
    global: &str,
    mut mode_du_lien: impl FnMut(i32) -> Option<String>,
) -> Option<bool> {
    let mut liens: Vec<i32> = serveurs.iter().map(|(l, _)| *l).collect();
    liens.sort_unstable();
    liens.dedup();
    if liens.is_empty() {
        return Some(global == "yes");
    }
    let mut tous = true;
    for lien in liens {
        let mode = if lien == 0 {
            global.to_string()
        } else {
            mode_du_lien(lien)?
        };
        tous &= mode_effectif(&mode, global) == "yes";
    }
    Some(tous)
}

/// systemd-resolved lu par le client D-Bus maison (org.freedesktop.resolve1) au lieu de `resolvectl`.
#[cfg(target_os = "linux")]
fn resolved_par_dbus() -> Result<Resolved, crate::modele::Echec> {
    use crate::machine::linux::dbus::Bus;
    const RESOLVE1: &str = "org.freedesktop.resolve1";
    const CHEMIN: &str = "/org/freedesktop/resolve1";
    let echec = |e: String| crate::modele::Echec::echoue("dns/resolved", e);
    let mut bus = Bus::systeme().map_err(echec)?;
    let dns = bus
        .propriete(RESOLVE1, CHEMIN, "org.freedesktop.resolve1.Manager", "DNS")
        .map_err(echec)?;
    let global = bus
        .propriete(RESOLVE1, CHEMIN, "org.freedesktop.resolve1.Manager", "DNSOverTLS")
        .map_err(echec)?;
    let global = global.texte().unwrap_or_default().to_string();
    let serveurs = serveurs_resolved(&dns);
    // Le chemin d'un lien : son numéro, dont le premier chiffre est échappé (« 3 » → « _33 », sd_bus_path_encode).
    let chiffre = chiffre_resolved(&serveurs, &global, |lien| {
        let chemin = format!("{CHEMIN}/link/_3{lien}");
        bus.propriete(RESOLVE1, &chemin, "org.freedesktop.resolve1.Link", "DNSOverTLS")
            .ok()
            .and_then(|v| v.texte().map(String::from))
    });
    Ok(Resolved {
        serveurs: serveurs.into_iter().map(|(_, ip)| ip).collect(),
        chiffre,
    })
}

/// Serveurs de `scutil --dns` (« nameserver[0] : 10.0.0.1 »), section principale seulement : celle « for scoped
/// queries » répète les mêmes serveurs par interface.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn lire_scutil(sortie: &str) -> Vec<IpAddr> {
    let mut liste = Vec::new();
    for l in sortie.lines().take_while(|l| !l.contains("for scoped queries")) {
        if let Some((cle, valeur)) = l.split_once(':')
            && cle.trim().starts_with("nameserver[")
            && let Some(ip) = adresse(valeur.trim())
            && !liste.contains(&ip)
        {
            liste.push(ip);
        }
    }
    liste
}

/// Résolveurs locaux connus : (processus, nom affiché, chiffre ses requêtes).
#[cfg(target_os = "macos")]
const RESOLVEURS: &[(&str, &str, bool)] = &[
    ("nextdns", "NextDNS", true),
    ("dnscrypt-proxy", "dnscrypt-proxy", true),
    ("cloudflared", "cloudflared", true),
    ("AdGuardHome", "AdGuard Home", false),
    ("unbound", "Unbound", false),
    ("dnsmasq", "dnsmasq", false),
];

/// macOS : serveurs en service d'après configd (SCDynamicStore) ; un serveur est « réglé à la main » s'il figure dans
/// les réglages d'un service réseau actif (SCPreferences), sinon il vient de la box (DHCP). `scutil --dns` et
/// `networksetup` restent en secours tant que le test d'oracle de macos.yml n'a pas prouvé la lecture native.
#[cfg(target_os = "macos")]
fn serveurs() -> Option<Serveurs> {
    use super::macos::config_reseau;
    // Une liste native vide (configd sans résolveur, ou lecture qui ne comprend pas ce macOS) : scutil tranche.
    let liste = match config_reseau::dns_en_vigueur().filter(|l| !l.is_empty()) {
        Some(l) => l,
        None => lire_scutil(&super::sortie("scutil", &["--dns"])?),
    };
    // (nom du service, serveurs réglés à la main) des services actifs.
    let reglages: Vec<(String, Vec<IpAddr>)> = match config_reseau::services() {
        Some(s) => s.into_iter().filter(|s| s.actif).map(|s| (s.nom, s.dns)).collect(),
        None => super::sortie("networksetup", &["-listallnetworkservices"])
            .unwrap_or_default()
            .lines()
            .skip(1)
            // Un service désactivé commence par « * ».
            .filter(|l| !l.starts_with('*') && !l.trim().is_empty())
            .map(|service| {
                let dns = super::sortie("networksetup", &["-getdnsservers", service])
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|l| adresse(l.trim()))
                    .collect();
                (service.to_string(), dns)
            })
            .collect(),
    };
    let mut manuels: Vec<(IpAddr, String)> = Vec::new();
    for (service, dns) in &reglages {
        for ip in dns {
            let cite = crate::commande::sh_chaine(service);
            manuels.push((*ip, format!("sudo networksetup -setdnsservers {cite} empty")));
        }
    }
    let mut resolveur_local = None;
    let mut chiffre = None;
    if liste.iter().any(IpAddr::is_loopback)
        && let Some((_, nom, chiffrant)) = RESOLVEURS
            .iter()
            // Demandé au noyau ; pgrep -x en secours quand la liste des processus ne se lit pas.
            .find(|(p, _, _)| {
                super::macos::noyau::en_marche(p).unwrap_or_else(|| super::sortie("pgrep", &["-x", p]).is_some())
            })
    {
        resolveur_local = Some(*nom);
        if *chiffrant {
            chiffre = Some(true);
        }
    }
    Some(Serveurs {
        liste: liste
            .iter()
            .map(|ip| (*ip, manuels.iter().any(|(m, _)| m == ip)))
            .collect(),
        chiffre,
        resolveur_local,
        remise: manuels,
    })
}

/// Lignes « DNS|index|adresse|manuel » : les serveurs de chaque carte réseau active. « manuel » : l'adresse
/// est écrite dans le registre de la carte (NameServer), donc réglée à la main ou par un programme, pas par le DHCP.
#[cfg(windows)]
fn serveurs() -> Option<Serveurs> {
    let sortie = lignes_natives().or_else(lignes_powershell)?;
    let mut liste = Vec::new();
    let mut remise = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.trim().split('|').collect();
        if let ["DNS", index, ip, manuel] = c[..]
            && let Some(ip) = adresse(ip)
        {
            let manuel = manuel.eq_ignore_ascii_case("true");
            if !liste.contains(&(ip, manuel)) {
                liste.push((ip, manuel));
            }
            if manuel {
                remise.push((
                    ip,
                    format!("Set-DnsClientServerAddress -InterfaceIndex {index} -ResetServerAddresses"),
                ));
            }
        }
    }
    Some(Serveurs {
        liste,
        chiffre: None,
        resolveur_local: None,
        remise,
    })
}

/// Les mêmes lignes lues par GetAdaptersAddresses et le registre, sans PowerShell : les cartes actives que
/// Get-NetAdapter liste (ni boucle locale ni tunnel). `None` si Windows refuse la liste.
#[cfg(windows)]
fn lignes_natives() -> Option<String> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut lignes = Vec::new();
    for carte in super::windows::cartes::cartes()?
        .into_iter()
        .filter(|c| c.active && !c.cachee)
    {
        // IPv4 dans Tcpip, IPv6 dans Tcpip6 : Windows écrit chaque pile à part, et une carte sans IPv6 peut ne pas
        // avoir la seconde clé (aucun serveur fixé, donc).
        let fixe = |pile: &str| -> String {
            winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
                .open_subkey(format!(
                    r"SYSTEM\CurrentControlSet\Services\{pile}\Parameters\Interfaces\{}",
                    carte.guid
                ))
                .and_then(|c| c.get_value("NameServer"))
                .unwrap_or_default()
        };
        let (fixe4, fixe6) = (fixe("Tcpip"), fixe("Tcpip6"));
        for ip in &carte.dns {
            let manuel = reglee_a_la_main(&fixe4, &fixe6, *ip);
            lignes.push(format!("DNS|{}|{ip}|{manuel}", carte.index));
        }
    }
    Some(lignes.join("\n"))
}

#[cfg(windows)]
fn lignes_powershell() -> Option<String> {
    super::windows::ps(
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { $i = $_.InterfaceIndex; \
         $fixe = (Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$($_.InterfaceGuid)\" -ErrorAction SilentlyContinue).NameServer; \
         $fixe6 = (Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\$($_.InterfaceGuid)\" -ErrorAction SilentlyContinue).NameServer; \
         (Get-DnsClientServerAddress -InterfaceIndex $i -ErrorAction SilentlyContinue).ServerAddresses | ForEach-Object { $a = $_ -as [ipaddress]; \
         $f = if ($_ -match ':') { $fixe6 } else { $fixe }; \
         $m = $a -and @(\"$f\" -split '[ ,;]' | Where-Object { $_ -and ($_ -as [ipaddress]) -and ($_ -as [ipaddress]).Equals($a) }).Count -gt 0; \
         \"DNS|$i|$_|$m\" } }",
    )
}

/// `ip` est-elle écrite dans le NameServer de sa pile (Tcpip pour une IPv4, Tcpip6 pour une IPv6) ? Comparée adresse à
/// adresse, pas comme un morceau de texte : « 1.1.1.1 » n'est pas réglée à la main parce que « 1.1.1.10 » l'est, et
/// une IPv6 écrite autrement (zéros, majuscules) reste la même adresse.
#[cfg_attr(not(windows), allow(dead_code))]
fn reglee_a_la_main(fixe4: &str, fixe6: &str, ip: IpAddr) -> bool {
    let fixe = if ip.is_ipv6() { fixe6 } else { fixe4 };
    fixe.split([',', ' ', ';']).filter_map(adresse).any(|f| f == ip)
}

/// Ce que l'outil « DNS le plus rapide » doit savoir des serveurs DNS de cette machine.
pub(crate) struct Actuel {
    /// (adresse, réglée à la main).
    pub serveurs: Vec<(IpAddr, bool)>,
    /// Requêtes chiffrées, quand on peut le savoir.
    pub chiffre: Option<bool>,
    /// Programme qui résout les noms sur cet ordinateur (« NextDNS »…).
    pub resolveur_local: Option<&'static str>,
}

pub(crate) fn actuel() -> Option<Actuel> {
    serveurs().map(|s| Actuel {
        serveurs: s.liste,
        chiffre: s.chiffre,
        resolveur_local: s.resolveur_local,
    })
}

/// Le service public d'un serveur DNS, reconnu à son adresse (« Cloudflare », « NextDNS »…).
pub(crate) fn service_public(ip: IpAddr) -> Option<&'static str> {
    fournisseur(ip)
}

fn decrire(ip: IpAddr, s: &Serveurs) -> String {
    match origine(ip) {
        Origine::Local => match s.resolveur_local {
            Some(nom) => trf!("{nom} (sur cet ordinateur)", "{nom} (on this computer)"),
            None => trf!("résolveur local ({ip})", "local resolver ({ip})"),
        },
        Origine::Reseau => trf!("votre routeur ou votre réseau ({ip})", "your router or network ({ip})"),
        Origine::Connu(nom) => format!("{nom} ({ip})"),
        Origine::Inconnu => ip.to_string(),
    }
}

/// Constat sur les serveurs DNS utilisés.
fn constat_serveurs(s: &Serveurs) -> Constat {
    if s.liste.is_empty() {
        return alerte(
            CAT,
            Niveau::Info,
            tr!("Aucun serveur DNS configuré.", "No DNS server configured."),
        );
    }
    let mut noms: Vec<String> = Vec::new();
    for (ip, _) in &s.liste {
        let d = decrire(*ip, s);
        if !noms.contains(&d) {
            noms.push(d);
        }
    }
    let noms = noms.join(", ");
    let inconnus_manuels: Vec<IpAddr> = s
        .liste
        .iter()
        .filter(|(ip, manuel)| *manuel && origine(*ip) == Origine::Inconnu)
        .map(|(ip, _)| *ip)
        .collect();
    if !inconnus_manuels.is_empty() {
        let liste = inconnus_manuels
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let constat = alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "DNS réglé à la main vers un serveur inconnu : {liste}. Si vous ne l'avez pas choisi, un programme a pu le changer pour détourner vos visites.",
                "DNS manually set to an unknown server: {liste}. If you did not choose it, a program may have changed it to hijack your browsing."
            ),
        );
        let commandes: Vec<&str> = s
            .remise
            .iter()
            .filter(|(ip, _)| inconnus_manuels.contains(ip))
            .map(|(_, c)| c.as_str())
            .collect();
        if commandes.is_empty() {
            return constat;
        }
        let mut commandes = commandes;
        commandes.dedup();
        return constat.corriger(
            tr!(
                "Remettre le DNS en automatique (celui que donne le routeur)",
                "Set DNS back to automatic (the one the router provides)"
            ),
            &commandes,
        );
    }
    let chiffrement = match s.chiffre {
        Some(true) => tr!(", requêtes chiffrées", ", encrypted queries"),
        Some(false) => tr!(
            ", requêtes non chiffrées (votre fournisseur Internet voit les sites visités)",
            ", unencrypted queries (your Internet provider sees the sites you visit)"
        ),
        None => "",
    };
    if s.liste.iter().any(|(ip, _)| origine(*ip) == Origine::Inconnu) {
        return alerte(
            CAT,
            Niveau::Info,
            trf!(
                "DNS : {noms}{chiffrement}. Serveur hors des services connus : normal si c'est celui de votre fournisseur Internet.",
                "DNS: {noms}{chiffrement}. Server outside the known services: normal if it is your Internet provider's."
            ),
        );
    }
    ok(CAT, trf!("DNS : {noms}{chiffrement}.", "DNS: {noms}{chiffrement}."))
}

/// Un DNS qui ne bloque pas les sites dangereux : une information, et l'outil qui en pose un, annulable. Rien quand
/// il en bloque déjà, ou quand rien ne permet de le savoir (NextDNS, Pi-hole).
fn sans_blocage(s: &Serveurs) -> Option<Constat> {
    let a = Actuel {
        serveurs: s.liste.clone(),
        chiffre: s.chiffre,
        resolveur_local: s.resolveur_local,
    };
    let passerelle = crate::reseau::scan::passerelle().map(IpAddr::V4);
    if s.liste.is_empty() || crate::dns_rapide::bloque_les_dangereux(&a, passerelle) != Some(false) {
        return None;
    }
    Some(
        alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Votre DNS ne bloque pas les sites dangereux (hameçonnage, logiciels malveillants). Un DNS qui protège les arrête avant même la connexion : le Bouclier canadien « Protégé » de l'ACEI (gratuit, sans profilage) ou Quad9.",
                "Your DNS does not block dangerous sites (phishing, malware). A protective DNS stops them before the connection even starts: CIRA's Canadian Shield “Protected” (free, no profiling) or Quad9."
            ),
        )
        .manuel(
            tr!(
                "En poser un : « vanguard dns-rapide » (Optimiser), choisir le Bouclier canadien ou Quad9 ; il s'annule exactement",
                "Set one: “vanguard fast-dns” (Optimize), choose Canadian Shield or Quad9; it undoes exactly"
            ),
            &[],
        ),
    )
}

/// Un nom qui ne peut pas exister (16 chiffres hexadécimaux au hasard) : un DNS honnête répond « inconnu ». Rien n'y
/// nomme Vanguard : le DNS du fournisseur voit passer chaque question.
fn nom_inexistant() -> String {
    let graine = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            d.as_secs().wrapping_mul(1_000_000_007) ^ u64::from(d.subsec_nanos())
        })
        ^ u64::from(std::process::id());
    format!("x{graine:016x}.com")
}

/// Le DNS invente-t-il des réponses ? Il en donne une pour un site qui n'existe pas : fournisseur qui redirige les
/// erreurs vers ses pages de publicité, portail de Wi-Fi public, ou détournement. `None` : nom refusé, comme il
/// se doit, ou pas de réponse en 3 s (une vraie réponse « inconnu » vient presque toujours en moins d'une seconde ;
/// 5 s, avant, retenaient tout le bilan quand le réseau est cassé, un Wi-Fi connecté sans Internet par exemple).
fn reponse_inventee() -> Option<IpAddr> {
    use std::net::ToSocketAddrs;
    let nom = nom_inexistant();
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let reponse = (nom.as_str(), 80)
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .map(|a| a.ip());
        let _ = envoi.send(reponse);
    });
    reception.recv_timeout(Duration::from_secs(3)).ok().flatten()
}

pub fn dns() -> Vec<Constat> {
    // Le nom inventé se demande pendant la lecture des serveurs (un PowerShell sous Windows) : l'un n'attend plus
    // l'autre.
    // Hors ligne, rien ne part, même une question au DNS du fournisseur.
    let hors_ligne = crate::parametres::hors_ligne();
    let inventee = (!hors_ligne).then(|| std::thread::spawn(reponse_inventee));
    let mut constats = Vec::new();
    match serveurs() {
        Some(s) => {
            constats.push(constat_serveurs(&s));
            constats.extend(sans_blocage(&s));
            constats.extend(crate::protection::sites_bloques::constat(CAT));
        }
        None => constats.push(super::impossible(
            CAT,
            tr!("configuration DNS illisible", "DNS configuration unreadable"),
        )),
    }
    // Réponse pour un nom inexistant, sauf si le résolveur bloque en renvoyant 0.0.0.0 (listes de blocage).
    if hors_ligne {
        constats.push(super::impossible(
            CAT,
            tr!(
                "hors ligne : réponses inventées par le DNS non vérifiées",
                "offline: answers invented by the DNS not checked"
            ),
        ));
    }
    if let Some(ip) = inventee.and_then(|f| f.join().ok()).flatten()
        && !ip.is_unspecified()
    {
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Le DNS répond même pour un site qui n'existe pas (→ {ip}) : votre fournisseur redirige les erreurs vers ses pages, un portail Wi-Fi intercepte, ou quelqu'un détourne vos requêtes.",
                "The DNS answers even for a site that does not exist (→ {ip}): your provider redirects errors to its pages, a Wi-Fi portal intercepts, or someone is hijacking your queries."
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un DNS IPv6 fixé à la main est dans Tcpip6, pas dans Tcpip : il doit compter pour manuel ; et une adresse qui
    /// n'est qu'un morceau d'une autre (« 1.1.1.1 » dans « 1.1.1.10 ») ne compte pas.
    #[test]
    fn dns_regle_a_la_main_selon_la_pile() {
        let ip = |t: &str| t.parse::<IpAddr>().unwrap();
        assert!(reglee_a_la_main("", "2001:db8::53", ip("2001:db8::53")));
        assert!(reglee_a_la_main(
            "",
            "2001:DB8:0:0::53,2001:db8::54",
            ip("2001:db8::53")
        ));
        assert!(!reglee_a_la_main("2001:db8::53", "", ip("2001:db8::53")));
        assert!(reglee_a_la_main("192.0.2.53 192.0.2.54", "", ip("192.0.2.54")));
        assert!(!reglee_a_la_main("1.1.1.10", "", ip("1.1.1.1")));
        assert!(!reglee_a_la_main("192.0.2.53", "2001:db8::53", ip("192.0.2.1")));
        assert!(!reglee_a_la_main("", "", ip("2001:db8::53")));
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite), sans PowerShell : chaque ligne a la forme lue par
    /// `serveurs`.
    #[cfg(windows)]
    #[test]
    fn serveurs_lus_sans_powershell() {
        let lignes = lignes_natives().expect("cartes réseau");
        assert!(
            lignes
                .lines()
                .all(|l| l.starts_with("DNS|") && l.split('|').count() == 4),
            "{lignes}"
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn origine_des_serveurs() {
        assert_eq!(origine(ip("127.0.0.1")), Origine::Local);
        assert_eq!(origine(ip("::1")), Origine::Local);
        assert_eq!(origine(ip("10.0.0.1")), Origine::Reseau);
        assert_eq!(origine(ip("192.168.1.1")), Origine::Reseau);
        assert_eq!(origine(ip("fe80::1")), Origine::Reseau);
        assert_eq!(origine(ip("fd00::53")), Origine::Reseau);
        assert_eq!(origine(ip("fec0:0:0:ffff::1")), Origine::Reseau);
        assert_eq!(origine(ip("feff::1")), Origine::Reseau);
        assert_eq!(origine(ip("ff02::1")), Origine::Inconnu);
        assert_eq!(origine(ip("100.64.0.1")), Origine::Reseau);
        assert_eq!(origine(ip("100.100.100.100")), Origine::Connu("Tailscale"));
        assert_eq!(origine(ip("1.1.1.1")), Origine::Connu("Cloudflare"));
        assert_eq!(origine(ip("45.90.30.12")), Origine::Connu("NextDNS"));
        assert_eq!(origine(ip("2620:fe::fe")), Origine::Connu("Quad9"));
        assert_eq!(origine(ip("2a07:a8c1::ab")), Origine::Connu("NextDNS"));
        assert_eq!(origine(ip("203.0.113.53")), Origine::Inconnu);
        for a in [
            "149.112.121.10",
            "149.112.122.20",
            "2620:10a:80bb::30",
            "2620:10A:80BC::10",
        ] {
            assert_eq!(origine(ip(a)), Origine::Connu(bouclier_canadien()), "{a}");
        }
        assert!(
            bouclier_canadien_filtrant(ip("149.112.121.20")) && bouclier_canadien_filtrant(ip("2620:10a:80bc::30"))
        );
        assert!(
            !bouclier_canadien_filtrant(ip("149.112.121.10")) && !bouclier_canadien_filtrant(ip("2620:10a:80bb::10"))
        );
    }

    #[test]
    fn lecture_de_scutil() {
        let sortie = "DNS configuration\n\nresolver #1\n  search domain[0] : home\n  nameserver[0] : 10.0.0.1\n  \
                      nameserver[1] : 2001:db8::1\n  if_index : 14 (en0)\n\nresolver #2\n  domain   : local\n\n\
                      DNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 9.9.9.9\n";
        assert_eq!(lire_scutil(sortie), [ip("10.0.0.1"), ip("2001:db8::1")]);
    }

    #[test]
    fn lecture_des_configurations() {
        let conf = "# généré\nnameserver 127.0.0.53\noptions edns0 trust-ad\nnameserver fe80::1%wlan0\n";
        assert_eq!(lire_resolv_conf(conf), [ip("127.0.0.53"), ip("fe80::1")]);
        // Le fichier amont de resolved : au-delà de trois serveurs, un commentaire avant les suivants, qui
        // restent des serveurs.
        let amont = "nameserver 10.0.0.1\nnameserver 1.1.1.1\nnameserver 9.9.9.9\n# Too many DNS servers \
                     configured, the following entries may be ignored.\nnameserver 2001:db8::1\nsearch maison\n";
        assert_eq!(
            lire_resolv_conf(amont),
            [ip("10.0.0.1"), ip("1.1.1.1"), ip("9.9.9.9"), ip("2001:db8::1")]
        );
        let resolvectl =
            "Global: 127.0.0.1\nLink 2 (enp12s0):\nLink 3 (wlp13s0): 10.0.0.1 1.1.1.1#cloudflare-dns.com fe80::1%3\n";
        assert_eq!(
            lire_resolvectl(resolvectl),
            [ip("127.0.0.1"), ip("10.0.0.1"), ip("1.1.1.1"), ip("fe80::1")]
        );
    }

    /// La propriété DNS de resolved et les modes DNS over TLS, fabriqués : seul « yes » sur chaque lien qui porte des
    /// serveurs compte comme chiffré ; un lien en « no » sous un réglage global à « yes » ne l'est pas.
    #[cfg(target_os = "linux")]
    #[test]
    fn dns_over_tls_par_resolved() {
        use crate::machine::linux::dbus::Valeur as V;
        let serveur = |lien: i32, famille: i32, octets: &[u8]| {
            V::Structure(vec![
                V::I32(lien),
                V::I32(famille),
                V::Tableau(octets.iter().map(|o| V::Octet(*o)).collect()),
            ])
        };
        let mut v6 = [0u8; 16];
        v6[..2].copy_from_slice(&[0x20, 0x01]);
        let dns = V::Tableau(vec![
            serveur(0, libc::AF_INET, &[127, 0, 0, 1]),
            serveur(3, libc::AF_INET, &[10, 0, 0, 1]),
            serveur(3, libc::AF_INET6, &v6),
            // Famille et longueur qui ne vont pas ensemble : sautée.
            serveur(3, libc::AF_INET6, &[1, 2, 3, 4]),
        ]);
        let s = serveurs_resolved(&dns);
        assert_eq!(s.len(), 3);
        assert_eq!(s[1], (3, ip("10.0.0.1")));
        let mode = |m: &'static str| move |_| Some(m.to_string());
        assert_eq!(chiffre_resolved(&s, "yes", mode("")), Some(true));
        assert_eq!(chiffre_resolved(&s, "yes", mode("no")), Some(false));
        assert_eq!(chiffre_resolved(&s, "yes", mode("opportunistic")), Some(false));
        assert_eq!(
            chiffre_resolved(&s, "no", mode("yes")),
            Some(false),
            "le global porte un serveur"
        );
        assert_eq!(chiffre_resolved(&s[1..], "no", mode("yes")), Some(true));
        // Un lien illisible : rien de su, jamais « chiffré ».
        assert_eq!(chiffre_resolved(&s, "yes", |_| None), None);
        assert_eq!(chiffre_resolved(&[], "opportunistic", |_| None), Some(false));
    }

    /// L'oracle : resolved lu par D-Bus contre `resolvectl status` et `resolvectl dns`, sur cet ordinateur. resolvectl
    /// écrit « +DNSOverTLS » dès qu'un lien ou le global est strict ; la lecture native, plus stricte, ne dit
    /// « chiffré » que si tous le sont : elle ne peut dire oui quand l'outil dit non.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolved_comme_resolvectl() {
        // Deux lectures à des instants différents : des serveurs qui changent entre elles (bail DHCP, la CI de GitHub :
        // 1 par D-Bus, 0 par resolvectl) ne disent rien. D-Bus relu après resolvectl ; à l'identique, la comparaison vaut.
        let lire = || {
            resolved_par_dbus().map(|r| {
                let mut liste = r.serveurs.clone();
                liste.sort();
                liste.dedup();
                (liste, r)
            })
        };
        let mut stable = None;
        for _ in 0..5 {
            let (avant, natif) = match lire() {
                Ok(l) => l,
                Err(e) => return crate::essais::saute(&format!("resolved injoignable par D-Bus ({e})")),
            };
            let (Some(status), Some(dns)) = (
                super::super::sortie("resolvectl", &["status"]),
                super::super::sortie("resolvectl", &["dns"]),
            ) else {
                return crate::essais::saute("resolvectl absent");
            };
            if lire().is_ok_and(|(apres, _)| apres == avant) {
                stable = Some((natif, status, dns));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        let Some((natif, status, dns)) = stable else {
            return crate::essais::saute("serveurs DNS changés pendant chaque lecture");
        };
        let outil_chiffre = status.contains("+DNSOverTLS");
        if natif.chiffre == Some(true) {
            assert!(outil_chiffre, "chiffré pour D-Bus, pas pour resolvectl");
        }
        let mut a = natif.serveurs.clone();
        let mut b = lire_resolvectl(&dns);
        a.sort();
        a.dedup();
        b.sort();
        b.dedup();
        assert!(a == b, "serveurs : {} par D-Bus, {} par resolvectl", a.len(), b.len());
    }

    /// Sur cet ordinateur, le resolv.conf amont de resolved donne les serveurs de `resolvectl dns`.
    #[cfg(target_os = "linux")]
    #[test]
    fn serveurs_amont_comme_resolvectl() {
        crate::autotest::croisees::essayer("AUT-LNX-010");
    }

    /// Sur cet ordinateur, les résolveurs actifs lus dans /proc sont ceux de `systemctl is-active`, dans les deux
    /// sens : un processus du même nom hors du service ne compte pas plus pour l'un que pour l'autre.
    #[cfg(target_os = "linux")]
    #[test]
    fn resolveurs_comme_systemctl() {
        let noms: Vec<&str> = RESOLVEURS.iter().map(|r| r.0).collect();
        let Some(natif) = crate::machine::linux::natif::services_actifs(&noms) else {
            return crate::essais::saute("services illisibles par D-Bus");
        };
        for (service, actif) in noms.iter().zip(natif) {
            let Some(r) =
                crate::commande::lancer(std::process::Command::new("systemctl").args(["is-active", service]), 10)
            else {
                return crate::essais::saute("systemctl absent");
            };
            // Une réponse vide : systemctl n'a pas répondu à temps (machine chargée), rien à comparer.
            let etat = r.sortie.trim();
            if etat.is_empty() {
                continue;
            }
            assert_eq!(actif, etat == "active", "{service} : {etat}");
        }
    }

    #[test]
    fn dns_manuel_inconnu_signale() {
        let s = |liste: Vec<(IpAddr, bool)>| Serveurs {
            liste,
            chiffre: None,
            resolveur_local: None,
            remise: vec![(
                ip("45.13.105.2"),
                "Set-DnsClientServerAddress -InterfaceIndex 7 -ResetServerAddresses".into(),
            )],
        };
        let c = constat_serveurs(&s(vec![(ip("45.13.105.2"), true)]));
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.correctif.is_some());
        // Le même serveur donné par le réseau (DHCP) : sans doute celui du fournisseur, simple information.
        assert_eq!(
            constat_serveurs(&s(vec![(ip("45.13.105.2"), false)])).probleme,
            Some(Niveau::Info)
        );
        // Un service connu réglé à la main : un choix, pas un problème.
        assert_eq!(constat_serveurs(&s(vec![(ip("1.1.1.1"), true)])).probleme, None);
        let nom = nom_inexistant();
        assert!(
            nom.len() == 21 && nom.strip_suffix(".com").is_some() && !nom.contains("vanguard"),
            "{nom}"
        );
    }
}
