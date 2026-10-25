//! Le bail DHCP de cette machine : ce que la box (ou ce qui se fait passer pour elle) lui a distribué — adresse,
//! passerelle, serveur DHCP, serveurs DNS — et la configuration DNS effective de la machine. Tout est lu dans les
//! fichiers et le registre, sans programme externe : état de NetworkManager (`/run/NetworkManager/devices`, lisible
//! sans root), baux de systemd-networkd, de dhcpcd et de dhclient, registre Tcpip de Windows (winreg), baux et
//! réglages réseau de macOS (plist). Ce qui n'est pas lisible est rendu comme tel (`Err`), jamais inventé.
//! Lecture seule ; partagé par les domaines DNS/TLS et Segmentation de l'audit.

use std::net::IpAddr;

/// D'où vient un bail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    // Chaque source n'est construite que sous son système.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    NetworkManager,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Networkd,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Dhcpcd,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Dhclient,
    /// Registre de Windows (Tcpip\Parameters\Interfaces).
    #[cfg_attr(not(windows), allow(dead_code))]
    Registre,
    /// Baux du client DHCP de macOS.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    MacOs,
}

/// Un bail DHCP reçu par cette machine, tel que le client l'a gardé.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Bail {
    /// Carte réseau (« wlan0 », « en0 », ou le GUID de la carte sous Windows), quand la source la nomme.
    pub interface: Option<String>,
    pub source: Option<Source>,
    /// Adresse reçue.
    pub adresse: Option<IpAddr>,
    /// Le serveur DHCP (option 54) : la box, normalement.
    pub serveur: Option<IpAddr>,
    /// Passerelle distribuée (option 3, la première).
    pub passerelle: Option<IpAddr>,
    /// Serveurs DNS distribués (option 6), dans l'ordre.
    pub dns: Vec<IpAddr>,
    /// Domaine distribué (option 15), tel quel : à rendre affichable avant de le montrer.
    pub domaine: Option<String>,
    /// Fin du bail (secondes Unix), quand la source la donne.
    pub expire: Option<u64>,
}

impl Bail {
    /// Le bail est encore en cours (ou sa fin n'est pas connue).
    pub fn en_cours(&self, maintenant: u64) -> bool {
        self.expire.is_none_or(|fin| fin > maintenant)
    }
}

/// Réglages de systemd-resolved lus dans sa configuration (resolved.conf et ses compléments) : les valeurs
/// écrites de `DNSOverTLS=` et `DNSSEC=`, s'il y en a.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Resolved {
    pub dns_over_tls: Option<String>,
    pub dnssec: Option<String>,
}

/// Un serveur DoH déclaré à Windows (Dnscache, Windows 11) : adresse, drapeaux DohFlags, modèle d'adresse.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DohWindows {
    pub serveur: String,
    pub drapeaux: u64,
    pub modele: Option<String>,
}

/// La configuration DNS de la machine, lue sans programme externe ; complète `machine::dns::actuel()`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Configuration {
    /// Serveurs par fichier (Linux : « /etc/resolv.conf », « /run/systemd/resolve/resolv.conf » = ceux à qui
    /// systemd-resolved transmet) ou par carte réglée à la main (Windows : NameServer ; macOS : service réseau).
    pub serveurs: Vec<(String, Vec<IpAddr>)>,
    pub resolved: Option<Resolved>,
    /// Windows : serveurs DoH déclarés, et DoH automatique pour les serveurs connus (EnableAutoDoh).
    pub doh_windows: Vec<DohWindows>,
    pub doh_automatique_windows: Option<u32>,
    /// Windows 11 ou plus récent (le DoH du système existe) ; `None` : inconnu ou autre système.
    pub windows_11: Option<bool>,
}

fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Les adresses d'un texte (« 10.0.0.1 10.0.0.2 », « 10.0.0.1,10.0.0.2 »), dans l'ordre, sans doublon.
fn adresses(texte: &str) -> Vec<IpAddr> {
    let mut liste: Vec<IpAddr> = Vec::new();
    for mot in texte.split([' ', ',', ';', '\t']) {
        if let Ok(ip) = mot
            .trim()
            .trim_matches(['"', '[', ']'])
            .split('%')
            .next()
            .unwrap_or("")
            .parse()
            && !liste.contains(&ip)
        {
            liste.push(ip);
        }
    }
    liste
}

/// Un paquet DHCP (BOOTP, RFC 2131) gardé tel quel par dhcpcd (`.lease`) et par macOS (`PacketData`) : l'adresse
/// reçue (yiaddr), puis les options 3 (routeurs), 6 (DNS), 15 (domaine), 51 (durée), 54 (serveur).
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn paquet_dhcp(octets: &[u8], debut: Option<u64>) -> Option<Bail> {
    const COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
    if octets.len() < 240 || octets[236..240] != COOKIE || octets[0] != 2 {
        return None;
    }
    let v4 = |o: &[u8]| IpAddr::from([o[0], o[1], o[2], o[3]]);
    let mut bail = Bail {
        adresse: Some(v4(&octets[16..20])).filter(|ip| !ip.is_unspecified()),
        ..Bail::default()
    };
    let mut options = &octets[240..];
    while let Some((&code, reste)) = options.split_first() {
        match code {
            0 => {
                options = reste;
                continue;
            }
            255 => break,
            _ => {}
        }
        let (&longueur, reste) = reste.split_first()?;
        let valeur = reste.get(..usize::from(longueur))?;
        options = &reste[usize::from(longueur)..];
        match code {
            3 if valeur.len() >= 4 => bail.passerelle = Some(v4(valeur)),
            6 => bail.dns = valeur.as_chunks::<4>().0.iter().map(|o| IpAddr::from(*o)).collect(),
            15 => bail.domaine = Some(String::from_utf8_lossy(valeur).trim_end_matches('\0').to_string()),
            51 if valeur.len() == 4 => {
                let duree = u64::from(u32::from_be_bytes([valeur[0], valeur[1], valeur[2], valeur[3]]));
                bail.expire = debut.map(|d| d.saturating_add(duree));
            }
            54 if valeur.len() == 4 => bail.serveur = Some(v4(valeur)),
            _ => {}
        }
    }
    (bail.adresse.is_some() || bail.serveur.is_some()).then_some(bail)
}

/// Les lignes « nameserver » d'un resolv.conf.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn resolv_conf(texte: &str) -> Vec<IpAddr> {
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .flat_map(|reste| adresses(reste.split('#').next().unwrap_or("")))
        .collect()
}

/// L'état qu'écrit NetworkManager pour chaque carte (`/run/NetworkManager/devices/<index>`, lisible sans root) :
/// la section `[dhcp4]` reprend les options du bail en cours (`dhcp4.domain_name_servers=10.0.0.1 10.0.0.2`),
/// `[dhcp6]` celles de DHCPv6 s'il y en a. Un bail par section qui porte une adresse ou des serveurs.
#[cfg(any(target_os = "linux", test))]
fn etat_networkmanager(texte: &str) -> Vec<Bail> {
    let mut baux = Vec::new();
    let mut section = "";
    let mut courant: Option<Bail> = None;
    let fermer = |courant: &mut Option<Bail>, baux: &mut Vec<Bail>| {
        if let Some(b) = courant.take()
            && (b.adresse.is_some() || !b.dns.is_empty() || b.serveur.is_some())
        {
            baux.push(b);
        }
    };
    for ligne in texte.lines().map(str::trim) {
        if let Some(nom) = ligne.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            fermer(&mut courant, &mut baux);
            section = nom;
            if section == "dhcp4" || section == "dhcp6" {
                courant = Some(Bail {
                    source: Some(Source::NetworkManager),
                    ..Bail::default()
                });
            }
            continue;
        }
        let Some(b) = courant.as_mut() else { continue };
        let Some((cle, valeur)) = ligne.split_once('=') else {
            continue;
        };
        let cle = cle
            .strip_prefix(section)
            .and_then(|c| c.strip_prefix('.'))
            .unwrap_or(cle);
        match cle {
            "ip_address" | "ip6_address" => b.adresse = adresses(valeur).first().copied(),
            "dhcp_server_identifier" | "dhcp6_server_id" => b.serveur = adresses(valeur).first().copied(),
            "routers" => b.passerelle = adresses(valeur).first().copied(),
            "domain_name_servers" | "dhcp6_name_servers" => b.dns = adresses(valeur),
            "domain_name" | "dhcp6_domain_search" => b.domaine = Some(valeur.to_string()),
            "expiry" => b.expire = valeur.parse().ok(),
            _ => {}
        }
    }
    fermer(&mut courant, &mut baux);
    baux
}

/// Un bail au format de systemd (`/run/systemd/netif/leases/<index>` de networkd, `internal-*.lease` de
/// NetworkManager) : `CLÉ=valeur` ; `debut` (date du fichier) et `LIFETIME` donnent la fin.
#[cfg(any(target_os = "linux", test))]
fn bail_systemd(texte: &str, debut: Option<u64>) -> Option<Bail> {
    let mut bail = Bail {
        source: Some(Source::Networkd),
        ..Bail::default()
    };
    let mut duree = None;
    for ligne in texte.lines() {
        let Some((cle, valeur)) = ligne.split_once('=') else {
            continue;
        };
        match cle.trim() {
            "ADDRESS" => bail.adresse = adresses(valeur).first().copied(),
            "ROUTER" => bail.passerelle = adresses(valeur).first().copied(),
            "SERVER_ADDRESS" => bail.serveur = adresses(valeur).first().copied(),
            "DNS" => bail.dns = adresses(valeur),
            "DOMAINNAME" => bail.domaine = Some(valeur.trim().to_string()),
            "LIFETIME" => duree = valeur.trim().parse::<u64>().ok(),
            _ => {}
        }
    }
    if let (Some(d), Some(duree)) = (debut, duree) {
        bail.expire = Some(d.saturating_add(duree));
    }
    (bail.adresse.is_some() || bail.serveur.is_some()).then_some(bail)
}

/// Le dernier bail d'un fichier de dhclient (`lease { … option domain-name-servers 10.0.0.1,10.0.0.2; … }`).
#[cfg(any(target_os = "linux", test))]
fn bail_dhclient(texte: &str) -> Option<Bail> {
    let dernier = texte.rsplit("lease {").next()?;
    let mut bail = Bail {
        source: Some(Source::Dhclient),
        ..Bail::default()
    };
    for ligne in dernier.lines().map(|l| l.trim().trim_end_matches(';')) {
        let Some((cle, valeur)) = ligne.strip_prefix("option ").unwrap_or(ligne).split_once(' ') else {
            continue;
        };
        match cle {
            "interface" => bail.interface = Some(valeur.trim_matches('"').to_string()),
            "fixed-address" => bail.adresse = adresses(valeur).first().copied(),
            "routers" => bail.passerelle = adresses(valeur).first().copied(),
            "dhcp-server-identifier" => bail.serveur = adresses(valeur).first().copied(),
            "domain-name-servers" => bail.dns = adresses(valeur),
            "domain-name" => bail.domaine = Some(valeur.trim_matches('"').to_string()),
            _ => {}
        }
    }
    (bail.adresse.is_some() || bail.serveur.is_some()).then_some(bail)
}

/// `DNSOverTLS=` et `DNSSEC=` d'un resolved.conf (section `[Resolve]`) ; la dernière valeur écrite gagne.
#[cfg(any(target_os = "linux", test))]
fn resolved_conf(texte: &str, r: &mut Resolved) {
    let mut dans_resolve = false;
    for ligne in texte.lines().map(str::trim) {
        if ligne.starts_with('[') {
            dans_resolve = ligne.eq_ignore_ascii_case("[resolve]");
            continue;
        }
        if !dans_resolve || ligne.starts_with('#') || ligne.starts_with(';') {
            continue;
        }
        if let Some((cle, valeur)) = ligne.split_once('=') {
            let valeur = valeur.trim().to_string();
            match cle.trim() {
                "DNSOverTLS" => r.dns_over_tls = Some(valeur),
                "DNSSEC" => r.dnssec = Some(valeur),
                _ => {}
            }
        }
    }
}

/// Date de dernière écriture d'un fichier, en secondes Unix.
#[cfg(target_os = "linux")]
fn date_du_fichier(chemin: &std::path::Path) -> Option<u64> {
    std::fs::metadata(chemin)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Le nom de la carte d'index `index` (`/sys/class/net/<nom>/ifindex`).
#[cfg(target_os = "linux")]
fn nom_de_carte(index: &str) -> Option<String> {
    for e in std::fs::read_dir("/sys/class/net").ok()?.flatten() {
        let contenu = std::fs::read_to_string(e.path().join("ifindex")).unwrap_or_default();
        if contenu.trim() == index {
            return Some(e.file_name().to_string_lossy().into_owned());
        }
    }
    None
}

/// Les fichiers d'un dossier, triés par nom ; vide si le dossier ne se lit pas.
#[cfg(target_os = "linux")]
fn fichiers(dossier: &str) -> Vec<std::path::PathBuf> {
    let mut liste: Vec<std::path::PathBuf> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    liste.sort();
    liste
}

/// Linux : NetworkManager (état des cartes, puis ses fichiers de bail s'ils se lisent), systemd-networkd, dhcpcd.
/// `Err` : aucune source lisible (ni NetworkManager, ni networkd, ni dhcpcd, ou leurs dossiers interdits).
#[cfg(target_os = "linux")]
fn lire_systeme() -> Result<Vec<Bail>, String> {
    let mut baux = Vec::new();
    let mut interdits = Vec::new();
    for fichier in fichiers("/run/NetworkManager/devices") {
        let Ok(texte) = std::fs::read_to_string(&fichier) else {
            continue;
        };
        let index = fichier.file_name().map(|n| n.to_string_lossy().into_owned());
        let nom = index.as_deref().and_then(nom_de_carte).or(index);
        for mut b in etat_networkmanager(&texte) {
            b.interface.clone_from(&nom);
            baux.push(b);
        }
    }
    for fichier in fichiers("/run/systemd/netif/leases") {
        let Ok(texte) = std::fs::read_to_string(&fichier) else {
            continue;
        };
        if let Some(mut b) = bail_systemd(&texte, date_du_fichier(&fichier)) {
            let index = fichier.file_name().map(|n| n.to_string_lossy().into_owned());
            b.interface = index.as_deref().and_then(nom_de_carte).or(index);
            baux.push(b);
        }
    }
    // Baux gardés par NetworkManager (souvent réservés à root : alors rien, sans erreur si l'état des cartes a parlé).
    match std::fs::read_dir("/var/lib/NetworkManager") {
        Ok(entrees) => {
            for e in entrees.flatten() {
                let chemin = e.path();
                let nom = chemin.file_name().map(|n| n.to_string_lossy().into_owned());
                if chemin.extension().is_none_or(|x| !x.eq_ignore_ascii_case("lease")) {
                    continue;
                }
                let Ok(texte) = std::fs::read_to_string(&chemin) else {
                    continue;
                };
                let bail = if texte.contains("lease {") {
                    bail_dhclient(&texte)
                } else {
                    bail_systemd(&texte, date_du_fichier(&chemin)).map(|mut b| {
                        b.source = Some(Source::NetworkManager);
                        b
                    })
                };
                if let Some(mut b) = bail {
                    // « internal-<uuid>-<carte>.lease » : la carte est après le dernier tiret.
                    if b.interface.is_none() {
                        b.interface = nom
                            .as_deref()
                            .and_then(|n| n.strip_suffix(".lease"))
                            .and_then(|n| n.rsplit('-').next())
                            .map(str::to_string);
                    }
                    baux.push(b);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => interdits.push("/var/lib/NetworkManager"),
        Err(_) => {}
    }
    match std::fs::read_dir("/var/lib/dhcpcd") {
        Ok(entrees) => {
            for e in entrees.flatten() {
                let chemin = e.path();
                if chemin.extension().is_none_or(|x| !x.eq_ignore_ascii_case("lease")) {
                    continue;
                }
                let Ok(octets) = std::fs::read(&chemin) else { continue };
                if let Some(mut b) = paquet_dhcp(&octets, date_du_fichier(&chemin)) {
                    b.source = Some(Source::Dhcpcd);
                    b.interface = chemin
                        .file_stem()
                        .map(|n| n.to_string_lossy().into_owned())
                        .and_then(|n| n.split('-').next().map(str::to_string));
                    baux.push(b);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => interdits.push("/var/lib/dhcpcd"),
        Err(_) => {}
    }
    if baux.is_empty() {
        return Err(if interdits.is_empty() {
            crate::tr!(
                "aucun bail DHCP lisible (ni NetworkManager, ni systemd-networkd, ni dhcpcd)",
                "no readable DHCP lease (neither NetworkManager, systemd-networkd nor dhcpcd)"
            )
            .to_string()
        } else {
            crate::trf!(
                "baux DHCP réservés à root ({})",
                "DHCP leases readable only as root ({})",
                interdits.join(", ")
            )
        });
    }
    Ok(baux)
}

/// Linux : les serveurs de /etc/resolv.conf, ceux à qui systemd-resolved transmet (/run/systemd/resolve/resolv.conf),
/// et les réglages DNSOverTLS/DNSSEC de resolved.conf et de ses compléments (les derniers lus gagnent).
#[cfg(target_os = "linux")]
fn configuration_systeme() -> Configuration {
    let mut c = Configuration::default();
    for chemin in ["/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"] {
        if let Ok(texte) = std::fs::read_to_string(chemin) {
            c.serveurs.push((chemin.to_string(), resolv_conf(&texte)));
        }
    }
    let mut resolved = Resolved::default();
    let mut vu = false;
    let mut lire = |chemin: &std::path::Path| {
        if let Ok(texte) = std::fs::read_to_string(chemin) {
            vu = true;
            resolved_conf(&texte, &mut resolved);
        }
    };
    lire(std::path::Path::new("/etc/systemd/resolved.conf"));
    for dossier in [
        "/usr/lib/systemd/resolved.conf.d",
        "/run/systemd/resolved.conf.d",
        "/etc/systemd/resolved.conf.d",
    ] {
        for f in fichiers(dossier) {
            if f.extension().is_some_and(|x| x == "conf") {
                lire(&f);
            }
        }
    }
    if vu {
        c.resolved = Some(resolved);
    }
    c
}

/// Ce que le registre de Windows garde pour une carte réseau (Tcpip\Parameters\Interfaces\<GUID>).
#[cfg(any(windows, test))]
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct CarteRegistre {
    pub guid: String,
    pub enable_dhcp: Option<u32>,
    pub dhcp_ip_address: Option<String>,
    pub dhcp_server: Option<String>,
    /// Séparés par des espaces.
    pub dhcp_name_server: Option<String>,
    pub dhcp_default_gateway: Vec<String>,
    pub dhcp_domain: Option<String>,
    /// Serveurs réglés à la main ou par un programme (séparés par des virgules) : vide = ceux du DHCP.
    pub name_server: Option<String>,
    /// Fin du bail, secondes Unix.
    pub lease_terminates_time: Option<u32>,
}

/// Le bail d'une carte d'après ses valeurs de registre : seulement si le DHCP y est actif, avec une adresse reçue
/// et un bail encore en cours (le registre garde les cartes débranchées depuis longtemps).
#[cfg(any(windows, test))]
fn bail_du_registre(c: &CarteRegistre, maintenant: u64) -> Option<Bail> {
    if c.enable_dhcp == Some(0) {
        return None;
    }
    let adresse = c
        .dhcp_ip_address
        .as_deref()
        .and_then(|t| adresses(t).first().copied())?;
    if adresse.is_unspecified() {
        return None;
    }
    let bail = Bail {
        interface: Some(c.guid.clone()),
        source: Some(Source::Registre),
        adresse: Some(adresse),
        serveur: c.dhcp_server.as_deref().and_then(|t| adresses(t).first().copied()),
        passerelle: c
            .dhcp_default_gateway
            .first()
            .and_then(|t| adresses(t).first().copied()),
        dns: c.dhcp_name_server.as_deref().map(adresses).unwrap_or_default(),
        domaine: c.dhcp_domain.clone().filter(|d| !d.is_empty()),
        expire: c.lease_terminates_time.map(u64::from),
    };
    bail.en_cours(maintenant).then_some(bail)
}

#[cfg(windows)]
mod registre {
    use super::{Bail, CarteRegistre, Configuration, DohWindows, adresses};
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    const INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
    const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache";

    fn texte(cle: &RegKey, nom: &str) -> Option<String> {
        cle.get_value::<String, _>(nom).ok().filter(|v| !v.trim().is_empty())
    }

    /// Les cartes du registre, telles quelles.
    pub(super) fn cartes() -> Result<Vec<CarteRegistre>, String> {
        let racine = RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey(INTERFACES)
            .map_err(|_| {
                crate::tr!(
                    "cartes réseau absentes du registre",
                    "network adapters missing from the registry"
                )
                .to_string()
            })?;
        let mut liste = Vec::new();
        for guid in racine.enum_keys().flatten() {
            let Ok(cle) = racine.open_subkey(&guid) else { continue };
            liste.push(CarteRegistre {
                enable_dhcp: cle.get_value("EnableDHCP").ok(),
                dhcp_ip_address: texte(&cle, "DhcpIPAddress"),
                dhcp_server: texte(&cle, "DhcpServer"),
                dhcp_name_server: texte(&cle, "DhcpNameServer"),
                dhcp_default_gateway: cle
                    .get_value::<Vec<String>, _>("DhcpDefaultGateway")
                    .unwrap_or_default(),
                dhcp_domain: texte(&cle, "DhcpDomain"),
                name_server: texte(&cle, "NameServer"),
                lease_terminates_time: cle.get_value("LeaseTerminatesTime").ok(),
                guid,
            });
        }
        Ok(liste)
    }

    pub(super) fn baux() -> Result<Vec<Bail>, String> {
        let maintenant = super::maintenant();
        let baux: Vec<Bail> = cartes()?
            .iter()
            .filter_map(|c| super::bail_du_registre(c, maintenant))
            .collect();
        if baux.is_empty() {
            return Err(crate::tr!(
                "aucune carte avec un bail DHCP en cours dans le registre",
                "no adapter with a current DHCP lease in the registry"
            )
            .to_string());
        }
        Ok(baux)
    }

    /// Serveurs réglés à la main (NameServer), DoH déclaré (DohFlags par serveur), DoH automatique, Windows 11.
    pub(super) fn configuration() -> Configuration {
        let mut c = Configuration::default();
        for carte in cartes().unwrap_or_default() {
            if let Some(ns) = &carte.name_server {
                let liste = adresses(ns);
                if !liste.is_empty() {
                    c.serveurs.push((carte.guid.clone(), liste));
                }
            }
        }
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        if let Ok(parametres) = hklm.open_subkey(format!(r"{DNSCACHE}\Parameters")) {
            c.doh_automatique_windows = parametres.get_value("EnableAutoDoh").ok();
        }
        if let Ok(interfaces) = hklm.open_subkey(format!(r"{DNSCACHE}\InterfaceSpecificParameters")) {
            for guid in interfaces.enum_keys().flatten() {
                for famille in ["Doh", "Doh6"] {
                    let Ok(doh) = interfaces.open_subkey(format!(r"{guid}\DohInterfaceSettings\{famille}")) else {
                        continue;
                    };
                    for serveur in doh.enum_keys().flatten() {
                        let Ok(cle) = doh.open_subkey(&serveur) else { continue };
                        c.doh_windows.push(DohWindows {
                            drapeaux: cle.get_value::<u64, _>("DohFlags").unwrap_or(0),
                            modele: texte(&cle, "DohTemplate"),
                            serveur,
                        });
                    }
                }
            }
        }
        c.windows_11 = hklm
            .open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            .ok()
            .and_then(|cle| texte(&cle, "CurrentBuildNumber"))
            .and_then(|b| b.trim().parse::<u32>().ok())
            .map(|b| b >= 22000);
        c
    }
}

#[cfg(windows)]
fn lire_systeme() -> Result<Vec<Bail>, String> {
    registre::baux()
}

#[cfg(windows)]
fn configuration_systeme() -> Configuration {
    registre::configuration()
}

/// macOS : les baux du client DHCP (`/private/var/db/dhcpclient/leases/<carte>-…`, un plist avec le paquet reçu dans
/// `PacketData`), s'ils se lisent.
#[cfg(target_os = "macos")]
fn lire_systeme() -> Result<Vec<Bail>, String> {
    const DOSSIER: &str = "/private/var/db/dhcpclient/leases";
    let entrees = std::fs::read_dir(DOSSIER).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            crate::tr!(
                "baux DHCP de macOS réservés à root",
                "macOS DHCP leases readable only as root"
            )
            .to_string()
        } else {
            crate::tr!("aucun bail DHCP gardé par macOS", "no DHCP lease kept by macOS").to_string()
        }
    })?;
    let mut baux = Vec::new();
    for e in entrees.flatten() {
        let chemin = e.path();
        let Some(plist) = crate::plist::lire_fichier(&chemin)
            .ok()
            .and_then(crate::plist::Lu::valeur)
        else {
            continue;
        };
        if let Some(mut b) = bail_macos(&plist) {
            b.interface = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .and_then(|n| n.split('-').next().map(str::to_string));
            baux.push(b);
        }
    }
    if baux.is_empty() {
        return Err(crate::tr!("aucun bail DHCP lisible chez macOS", "no readable DHCP lease on macOS").to_string());
    }
    Ok(baux)
}

/// Un bail de macOS : le paquet DHCP reçu (`PacketData`) daté de `LeaseStartDate`.
#[cfg(any(target_os = "macos", test))]
fn bail_macos(plist: &crate::plist::Valeur) -> Option<Bail> {
    use crate::plist::Valeur;
    let Some(Valeur::Donnees(paquet)) = plist.cle("PacketData") else {
        return None;
    };
    // Dates d'Apple : secondes depuis le 1er janvier 2001. Un plist binaire abîmé peut en porter une démesurée
    // (1e300, l'infini) : passé 1e11 s (vers l'an 5170), elle est ignorée, comme absente. Ajoutée telle quelle, elle
    // débordait, et la version publiée, qui vérifie les dépassements, perdait les domaines Segmentation et DNS/TLS.
    let debut = match plist.cle("LeaseStartDate") {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // une date, pas un calcul
        Some(Valeur::Date(d)) if *d > 0.0 && *d < 1e11 => Some((*d as u64).saturating_add(978_307_200)),
        _ => None,
    };
    let mut bail = paquet_dhcp(paquet, debut)?;
    bail.source = Some(Source::MacOs);
    if bail.passerelle.is_none()
        && let Some(r) = plist.cle("RouterIPAddress").and_then(Valeur::texte)
    {
        bail.passerelle = r.parse().ok();
    }
    Some(bail)
}

/// macOS : les serveurs DNS réglés à la main par service réseau dans preferences.plist
/// (`NetworkServices › <id> › DNS › ServerAddresses`), nommés par `UserDefinedName`.
#[cfg(any(target_os = "macos", test))]
fn manuels_macos(plist: &crate::plist::Valeur) -> Vec<(String, Vec<IpAddr>)> {
    use crate::plist::Valeur;
    let Some(Valeur::Dico(services)) = plist.cle("NetworkServices") else {
        return Vec::new();
    };
    let mut liste = Vec::new();
    for (id, service) in services {
        let Some(serveurs) = service
            .cle("DNS")
            .and_then(|d| d.cle("ServerAddresses"))
            .and_then(Valeur::tableau)
        else {
            continue;
        };
        let adresses: Vec<IpAddr> = serveurs
            .iter()
            .filter_map(Valeur::texte)
            .filter_map(|t| t.trim().parse().ok())
            .collect();
        if adresses.is_empty() {
            continue;
        }
        let nom = service
            .cle("UserDefinedName")
            .and_then(Valeur::texte)
            .map_or_else(|| id.clone(), str::to_string);
        liste.push((nom, adresses));
    }
    liste
}

#[cfg(target_os = "macos")]
fn configuration_systeme() -> Configuration {
    let mut c = Configuration::default();
    if let Ok(texte) = std::fs::read_to_string("/etc/resolv.conf") {
        c.serveurs.push(("/etc/resolv.conf".to_string(), resolv_conf(&texte)));
    }
    let chemin = std::path::Path::new("/Library/Preferences/SystemConfiguration/preferences.plist");
    if let Some(plist) = crate::plist::lire_fichier(chemin)
        .ok()
        .and_then(crate::plist::Lu::valeur)
    {
        c.serveurs.extend(manuels_macos(&plist));
    }
    c
}

/// Les baux DHCP en cours de cette machine, ou pourquoi aucun ne se lit (à dire : « non vérifié »).
pub fn lire() -> Result<Vec<Bail>, String> {
    let maintenant = maintenant();
    let baux: Vec<Bail> = lire_systeme()?.into_iter().filter(|b| b.en_cours(maintenant)).collect();
    if baux.is_empty() {
        return Err(crate::tr!("aucun bail DHCP en cours", "no current DHCP lease").to_string());
    }
    Ok(baux)
}

/// La configuration DNS de la machine lue dans ses fichiers et son registre.
pub fn configuration() -> Configuration {
    configuration_systeme()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    #[test]
    fn etat_de_networkmanager() {
        let texte = "[device]\nmanaged=true\nconnection-uuid=0000-1\nnext-server=10.0.0.1\n\n[dhcp4]\n\
                     dhcp4.broadcast_address=10.0.0.255\ndhcp4.dhcp_lease_time=172800\n\
                     dhcp4.dhcp_server_identifier=10.0.0.1\ndhcp4.domain_name_servers=10.0.0.1 203.0.113.53\n\
                     dhcp4.expiry=1800000000\ndhcp4.host_name=salon\ndhcp4.ip_address=10.0.0.42\n\
                     dhcp4.routers=10.0.0.1\ndhcp4.subnet_mask=255.255.255.0\ndhcp4.domain_name=salon.lan\n\n\
                     [dhcp6]\ndhcp6.dhcp6_name_servers=fd00::1\ndhcp6.ip6_address=fd00::42\n";
        let baux = etat_networkmanager(texte);
        assert_eq!(baux.len(), 2);
        assert_eq!(
            baux[0],
            Bail {
                interface: None,
                source: Some(Source::NetworkManager),
                adresse: Some(ip("10.0.0.42")),
                serveur: Some(ip("10.0.0.1")),
                passerelle: Some(ip("10.0.0.1")),
                dns: vec![ip("10.0.0.1"), ip("203.0.113.53")],
                domaine: Some("salon.lan".into()),
                expire: Some(1_800_000_000),
            }
        );
        assert_eq!(baux[1].dns, [ip("fd00::1")]);
        assert_eq!(baux[1].adresse, Some(ip("fd00::42")));
        assert!(baux[0].en_cours(1_799_999_999) && !baux[0].en_cours(1_800_000_000));
        // Une carte sans bail (section [device] seule, ou [dhcp4] vide) : rien.
        assert_eq!(etat_networkmanager("[device]\nmanaged=true\n"), Vec::<Bail>::new());
        assert_eq!(etat_networkmanager("[dhcp4]\n"), Vec::<Bail>::new());
    }

    #[test]
    fn bail_de_systemd_et_de_dhclient() {
        let texte = "# This is private data. Do not parse.\nADDRESS=10.0.0.42\nNETMASK=255.255.255.0\n\
                     ROUTER=10.0.0.1\nSERVER_ADDRESS=10.0.0.1\nDNS=10.0.0.1 203.0.113.53\nDOMAINNAME=salon.lan\n\
                     LIFETIME=86400\nCLIENTID=01aabbcc\n";
        let b = bail_systemd(texte, Some(1_000)).unwrap();
        assert_eq!(
            (b.adresse, b.serveur, b.passerelle),
            (Some(ip("10.0.0.42")), Some(ip("10.0.0.1")), Some(ip("10.0.0.1")))
        );
        assert_eq!(b.dns, [ip("10.0.0.1"), ip("203.0.113.53")]);
        assert_eq!((b.domaine.as_deref(), b.expire), (Some("salon.lan"), Some(87_400)));
        assert!(bail_systemd("# vide\n", None).is_none());
        let dhclient = "lease {\n  interface \"eth0\";\n  fixed-address 10.0.0.9;\n  option routers 10.0.0.1;\n}\n\
                        lease {\n  interface \"wlan0\";\n  fixed-address 10.0.0.42;\n  option subnet-mask 255.255.255.0;\n\
                        option routers 10.0.0.1;\n  option domain-name-servers 10.0.0.1,203.0.113.53;\n\
                        option dhcp-server-identifier 10.0.0.1;\n  option domain-name \"salon.lan\";\n  expire 3 2026/10/21 10:00:00;\n}\n";
        let b = bail_dhclient(dhclient).unwrap();
        assert_eq!(b.interface.as_deref(), Some("wlan0"), "le dernier bail du fichier");
        assert_eq!(b.adresse, Some(ip("10.0.0.42")));
        assert_eq!(b.dns, [ip("10.0.0.1"), ip("203.0.113.53")]);
        assert_eq!(b.domaine.as_deref(), Some("salon.lan"));
        assert!(bail_dhclient("rien").is_none());
    }

    /// Un paquet DHCP ACK forgé : yiaddr 10.0.0.42, options routeur, DNS, domaine, durée, serveur, puis fin.
    fn paquet() -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 2;
        p[16..20].copy_from_slice(&[10, 0, 0, 42]);
        p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
        p.extend([53, 1, 5]);
        p.extend([3, 4, 10, 0, 0, 1]);
        p.extend([6, 8, 10, 0, 0, 1, 203, 0, 113, 53]);
        p.extend([15, 5, b's', b'a', b'l', b'o', b'n']);
        p.extend([51, 4, 0, 1, 0x51, 0x80]);
        p.extend([54, 4, 10, 0, 0, 1]);
        p.extend([0, 0, 255]);
        p
    }

    #[test]
    fn paquet_dhcp_lu() {
        let b = paquet_dhcp(&paquet(), Some(100)).unwrap();
        assert_eq!(b.adresse, Some(ip("10.0.0.42")));
        assert_eq!(b.passerelle, Some(ip("10.0.0.1")));
        assert_eq!(b.dns, [ip("10.0.0.1"), ip("203.0.113.53")]);
        assert_eq!(b.serveur, Some(ip("10.0.0.1")));
        assert_eq!(b.domaine.as_deref(), Some("salon"));
        assert_eq!(b.expire, Some(100 + 86_400));
        // Trop court, sans cookie, option dont la longueur déborde : rien, sans plantage.
        assert!(paquet_dhcp(&paquet()[..200], None).is_none());
        let mut sans_cookie = paquet();
        sans_cookie[236] = 0;
        assert!(paquet_dhcp(&sans_cookie, None).is_none());
        let mut deborde = paquet();
        deborde.truncate(246);
        deborde.extend([6, 200, 1, 2]);
        assert!(paquet_dhcp(&deborde, None).is_none());
        for n in 0..paquet().len() {
            let _ = paquet_dhcp(&paquet()[..n], None);
        }
    }

    #[test]
    fn bail_depuis_le_registre() {
        let carte = CarteRegistre {
            guid: "{0000-1}".into(),
            enable_dhcp: Some(1),
            dhcp_ip_address: Some("10.0.0.42".into()),
            dhcp_server: Some("10.0.0.1".into()),
            dhcp_name_server: Some("10.0.0.1 203.0.113.53".into()),
            dhcp_default_gateway: vec!["10.0.0.1".into()],
            dhcp_domain: Some("salon.lan".into()),
            name_server: Some("1.1.1.1,9.9.9.9".into()),
            lease_terminates_time: Some(2_000_000_000),
        };
        let b = bail_du_registre(&carte, 1_900_000_000).unwrap();
        assert_eq!(b.interface.as_deref(), Some("{0000-1}"));
        assert_eq!(b.dns, [ip("10.0.0.1"), ip("203.0.113.53")]);
        assert_eq!(b.passerelle, Some(ip("10.0.0.1")));
        assert_eq!(b.serveur, Some(ip("10.0.0.1")));
        assert_eq!(
            adresses(carte.name_server.as_deref().unwrap()),
            [ip("1.1.1.1"), ip("9.9.9.9")]
        );
        // Bail fini, DHCP coupé, carte sans adresse : rien.
        assert!(bail_du_registre(&carte, 2_000_000_001).is_none());
        let mut fixe = carte.clone();
        fixe.enable_dhcp = Some(0);
        assert!(bail_du_registre(&fixe, 0).is_none());
        let mut vide = carte.clone();
        vide.dhcp_ip_address = Some("0.0.0.0".into());
        assert!(bail_du_registre(&vide, 0).is_none());
    }

    #[test]
    fn fichiers_de_configuration() {
        assert_eq!(
            resolv_conf("# commentaire\nnameserver 127.0.0.53 # stub\noptions edns0\nnameserver fe80::1%wlan0\n"),
            [ip("127.0.0.53"), ip("fe80::1")]
        );
        let mut r = Resolved::default();
        resolved_conf(
            "[Resolve]\n#DNSOverTLS=no\nDNS=1.1.1.1\nDNSOverTLS=opportunistic\n[Autre]\nDNSSEC=yes\n",
            &mut r,
        );
        assert_eq!(r.dns_over_tls.as_deref(), Some("opportunistic"));
        assert_eq!(r.dnssec, None, "hors de la section [Resolve]");
        resolved_conf("[Resolve]\nDNSSEC=allow-downgrade\n", &mut r);
        assert_eq!(r.dnssec.as_deref(), Some("allow-downgrade"));
        assert_eq!(
            adresses("10.0.0.1, 10.0.0.2;[fd00::1] pas-une-adresse 10.0.0.1"),
            [ip("10.0.0.1"), ip("10.0.0.2"), ip("fd00::1")]
        );
    }

    #[test]
    fn plists_de_macos() {
        use crate::plist::Valeur;
        let bail = Valeur::Dico(vec![
            ("IPAddress".into(), Valeur::Texte("10.0.0.42".into())),
            ("LeaseStartDate".into(), Valeur::Date(800_000_000.0)),
            ("PacketData".into(), Valeur::Donnees(paquet())),
            ("RouterIPAddress".into(), Valeur::Texte("10.0.0.1".into())),
        ]);
        let b = bail_macos(&bail).unwrap();
        assert_eq!(b.source, Some(Source::MacOs));
        assert_eq!(b.dns, [ip("10.0.0.1"), ip("203.0.113.53")]);
        assert_eq!(b.expire, Some(800_000_000 + 978_307_200 + 86_400));
        assert!(bail_macos(&Valeur::Dico(vec![])).is_none());
        // Une date démesurée (plist binaire abîmé) : ignorée, le reste du bail lu. Elle débordait (« as u64 » sature,
        // puis l'addition), et le domaine entier devenait une erreur interne. proptest l'avait trouvée aussi (1e30).
        for demesuree in [1e300, f64::INFINITY, 1e30] {
            let bail = Valeur::Dico(vec![
                ("LeaseStartDate".into(), Valeur::Date(demesuree)),
                ("PacketData".into(), Valeur::Donnees(paquet())),
            ]);
            let b = bail_macos(&bail).unwrap();
            assert_eq!((b.expire, b.dns.len()), (None, 2), "{demesuree}");
        }
        let preferences = Valeur::Dico(vec![(
            "NetworkServices".into(),
            Valeur::Dico(vec![
                (
                    "A1".into(),
                    Valeur::Dico(vec![
                        ("UserDefinedName".into(), Valeur::Texte("Wi-Fi".into())),
                        (
                            "DNS".into(),
                            Valeur::Dico(vec![(
                                "ServerAddresses".into(),
                                Valeur::Tableau(vec![Valeur::Texte("9.9.9.9".into()), Valeur::Texte("x".into())]),
                            )]),
                        ),
                    ]),
                ),
                ("B2".into(), Valeur::Dico(vec![("DNS".into(), Valeur::Dico(vec![]))])),
            ]),
        )]);
        assert_eq!(
            manuels_macos(&preferences),
            [("Wi-Fi".to_string(), vec![ip("9.9.9.9")])]
        );
    }

    /// La vraie lecture sur cette machine : un bail ou une raison, une configuration, jamais un plantage.
    #[test]
    fn lecture_reelle_sans_plantage() {
        match lire() {
            Ok(baux) => assert!(baux.iter().all(|b| b.adresse.is_some() || b.serveur.is_some())),
            Err(raison) => assert_ne!(raison, ""),
        }
        let c = configuration();
        assert!(c.serveurs.iter().all(|(nom, _)| !nom.is_empty()));
    }
}

/// Ce que le serveur DHCP (la box, ou ce qui se fait passer pour elle) met dans un bail, et ce que les fichiers du
/// système en gardent : jamais de panique, une lecture bornée.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use crate::plist::Valeur;
    use proptest::prelude::*;

    /// Une valeur d'adresse : des adresses vraies (IPv4, IPv6 avec zone, entre crochets ou guillemets) séparées comme
    /// les fichiers le font, ou du texte quelconque.
    fn valeur() -> impl Strategy<Value = String> {
        let adresse = prop_oneof![
            any::<[u8; 4]>().prop_map(|o| IpAddr::from(o).to_string()),
            any::<[u8; 16]>().prop_map(|o| format!("[{}%wlan0]", IpAddr::from(o))),
            "[0-9a-f.:%\"\\[\\]]{0,20}",
            any::<String>(),
        ];
        prop::collection::vec(
            (adresse, prop::sample::select(vec![" ", ",", ";", "\t", "#", ""])),
            0..6,
        )
        .prop_map(|v| v.into_iter().map(|(a, s)| a + s).collect())
    }

    /// Les lignes d'un fichier de bail ou de réglages : sections, « clé=valeur » ou « option clé valeur; » aux clés
    /// connues (avec ou sans le préfixe de leur section), commentaires, et lignes quelconques.
    fn fichier() -> impl Strategy<Value = String> {
        let cles = prop::sample::select(vec![
            "ip_address",
            "dhcp4.ip_address",
            "dhcp6.ip6_address",
            "dhcp_server_identifier",
            "routers",
            "domain_name_servers",
            "dhcp6_name_servers",
            "domain_name",
            "expiry",
            "ADDRESS",
            "ROUTER",
            "SERVER_ADDRESS",
            "DNS",
            "DOMAINNAME",
            "LIFETIME",
            "DNSOverTLS",
            "DNSSEC",
            "nameserver",
        ]);
        let ligne = prop_oneof![
            prop::sample::select(vec![
                "[dhcp4]",
                "[dhcp6]",
                "[device]",
                "[Resolve]",
                "[",
                "lease {",
                "}",
                "#",
                ";"
            ])
            .prop_map(str::to_string),
            (cles.clone(), valeur()).prop_map(|(c, v)| format!("{c}={v}")),
            (cles, valeur()).prop_map(|(c, v)| format!("{c} {v}")),
            (
                prop::sample::select(vec![
                    "interface",
                    "fixed-address",
                    "routers",
                    "dhcp-server-identifier",
                    "domain-name-servers",
                    "domain-name",
                ]),
                valeur()
            )
                .prop_map(|(c, v)| format!("  option {c} {v};")),
            "(expiry|LIFETIME)=[0-9]{0,25}",
            any::<String>(),
        ];
        prop::collection::vec(ligne, 0..20).prop_map(|l| l.join("\n"))
    }

    /// Un paquet DHCP : l'en-tête BOOTP (réponse, cookie magique) puis des options aux longueurs vraies ou fausses ;
    /// ou des octets quelconques.
    fn paquet() -> impl Strategy<Value = Vec<u8>> {
        let option = (
            prop::sample::select(vec![0u8, 3, 6, 15, 51, 54, 255, 1, 128]),
            prop::collection::vec(any::<u8>(), 0..40),
            prop::option::of(any::<u8>()),
        )
            .prop_map(|(code, valeur, longueur)| {
                let mut o = vec![code, longueur.unwrap_or(u8::try_from(valeur.len()).unwrap_or(0))];
                o.extend(valeur);
                o
            });
        let construit = (any::<[u8; 4]>(), prop::collection::vec(option, 0..12)).prop_map(|(adresse, options)| {
            let mut p = vec![0u8; 240];
            p[0] = 2;
            p[16..20].copy_from_slice(&adresse);
            p[236..240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
            p.extend(options.concat());
            p
        });
        prop_oneof![construit, prop::collection::vec(any::<u8>(), 0..300)]
    }

    /// Le bail lu doit rester dans ce qu'un paquet peut porter : 63 serveurs DNS au plus (255 octets d'option).
    fn borne(b: &Bail) -> bool {
        b.dns.len() <= 64 && b.domaine.as_ref().is_none_or(|d| d.len() <= 3 * 255)
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn paquets_dhcp(p in paquet(), debut in prop::option::of(any::<u64>())) {
            if let Some(b) = paquet_dhcp(&p, debut) {
                prop_assert!(borne(&b));
            }
        }

        #[test]
        fn fichiers_de_bail_et_de_reglages(t in fichier(), debut in prop::option::of(any::<u64>()), maintenant: u64) {
            for b in etat_networkmanager(&t) {
                let _ = b.en_cours(maintenant);
            }
            let _ = bail_systemd(&t, debut);
            let _ = bail_dhclient(&t);
            let _ = resolv_conf(&t);
            let mut r = Resolved::default();
            resolved_conf(&t, &mut r);
        }

        /// Les valeurs du registre de Windows : écrites par le client DHCP d'après la box.
        #[test]
        fn registre_de_windows(
            enable_dhcp in prop::option::of(any::<u32>()),
            valeurs in prop::collection::vec(prop::option::of(valeur()), 5),
            passerelles in prop::collection::vec(valeur(), 0..3),
            lease_terminates_time in prop::option::of(any::<u32>()),
            maintenant: u64,
        ) {
            let c = CarteRegistre {
                guid: "{4D36E972-E325-11CE-BFC1-08002BE10318}".to_string(),
                enable_dhcp,
                dhcp_ip_address: valeurs[0].clone(),
                dhcp_server: valeurs[1].clone(),
                dhcp_name_server: valeurs[2].clone(),
                dhcp_default_gateway: passerelles,
                dhcp_domain: valeurs[3].clone(),
                name_server: valeurs[4].clone(),
                lease_terminates_time,
            };
            let _ = bail_du_registre(&c, maintenant);
        }

        /// Les plists de macOS : le paquet reçu, daté d'un réel quelconque (infini, NaN, négatif, démesuré), et les
        /// serveurs réglés à la main.
        #[test]
        fn plists_de_macos(
            p in paquet(),
            date in prop_oneof![any::<f64>(), Just(f64::INFINITY), Just(f64::MAX), Just(f64::NAN), 0.0..1e10f64],
            routeur in any::<String>(),
            nom in any::<String>(),
            serveurs in prop::collection::vec(valeur(), 0..4),
        ) {
            let bail = Valeur::Dico(vec![
                ("PacketData".to_string(), Valeur::Donnees(p)),
                ("LeaseStartDate".to_string(), Valeur::Date(date)),
                ("RouterIPAddress".to_string(), Valeur::Texte(routeur)),
            ]);
            if let Some(b) = bail_macos(&bail) {
                prop_assert!(borne(&b));
            }
            let services = Valeur::Dico(vec![(
                "NetworkServices".to_string(),
                Valeur::Dico(vec![(
                    "0F1E2D3C".to_string(),
                    Valeur::Dico(vec![
                        ("UserDefinedName".to_string(), Valeur::Texte(nom)),
                        (
                            "DNS".to_string(),
                            Valeur::Dico(vec![(
                                "ServerAddresses".to_string(),
                                Valeur::Tableau(serveurs.into_iter().map(Valeur::Texte).collect()),
                            )]),
                        ),
                    ]),
                )]),
            )]);
            let _ = manuels_macos(&services);
        }
    }
}
