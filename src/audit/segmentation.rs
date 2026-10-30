//! Segmentation du réseau local (règles COM-SEG-*) : les objets connectés partagent-ils le réseau des ordinateurs,
//! un réseau invité isole-t-il vraiment ses clients, qui distribue les adresses, combien d'appareils se présentent
//! comme routeur IPv6. Tout se lit depuis cette machine, sans sonde nouvelle ni essai de mot de passe : le scan
//! déjà fait et les tables du noyau. Ce qui ne se lit pas sur ce système est dit « non vérifié », jamais compté
//! sain. Les faux positifs connus (Pi-hole ou NAS en DHCP, changement de box, partage de connexion d'un téléphone,
//! appareils en Ethernet malgré l'isolation Wi-Fi) sont dits dans les messages.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::machine::{Constat, alerte, impossible, ok};
use crate::reseau::objets::{self, Genre};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Un appareil du réseau tel que ce domaine le regarde : ce que le scan en a lu, rien de plus.
pub struct Appareil {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    pub fabricant: Option<String>,
    pub nom: Option<String>,
    /// « surnom · nom · fabricant », ce que le scan affiche.
    pub titre: String,
    /// La box (la passerelle).
    pub boite: bool,
    pub tcp: Vec<u16>,
    /// Ce que l'appareil dit de lui-même (SNMP, UPnP, en-tête web).
    pub annonces: Vec<String>,
}

impl Appareil {
    /// Le type d'objet connecté reconnu (caméra, imprimante, télé…) ; `None` : box, ordinateur, téléphone ou
    /// appareil sans indice.
    pub fn genre(&self) -> Option<Genre> {
        let objet = objets::Appareil {
            ip: self.ip,
            titre: self.titre.clone(),
            boite: self.boite,
            fabricant: self.fabricant.clone(),
            nom: self.nom.clone(),
            tcp: self.tcp.clone(),
            annonces: self.annonces.clone(),
            dernier_vu: None,
        };
        objets::genre(&objet).filter(|g| *g != Genre::Boite)
    }

    /// Son nom, rendu inoffensif : il est choisi par l'appareil, pas par la personne.
    fn affiche(&self) -> String {
        let titre = if self.titre.is_empty() {
            self.ip.to_string()
        } else {
            self.titre.clone()
        };
        crate::ui::affichable(&titre)
    }
}

/// Un appareil qui se présente comme routeur IPv6 (route par défaut vers lui).
#[derive(Debug, PartialEq, Eq)]
pub struct RouteurIpv6 {
    pub adresse: Ipv6Addr,
    pub interface: String,
    /// Son adresse MAC quand l'adresse de lien local la contient (EUI-64).
    pub mac: Option<String>,
}

/// Un carnet de réseau déjà scanné : la MAC de sa box (la clé), le nom du Wi-Fi, l'adresse de la box.
pub struct Carnet {
    pub mac_boite: String,
    pub nom: Option<String>,
    pub ip_boite: Option<Ipv4Addr>,
}

/// Ce que le domaine regarde. Un champ à `None` est une lecture qui ne s'est pas faite sur ce système : la règle
/// le dit « non vérifié ».
pub struct Entree {
    pub appareils: Vec<Appareil>,
    /// Cet ordinateur.
    pub moi: Option<Ipv4Addr>,
    pub passerelle: Option<Ipv4Addr>,
    pub nom_reseau: Option<String>,
    /// Sur un réseau invité, reconnu à son nom (« invité », « guest »…) ; `None` : le nom du réseau est inconnu.
    pub invite: Option<bool>,
    /// Cet ordinateur est en Wi-Fi ; `None` : non lu sur ce système.
    pub en_wifi: Option<bool>,
    /// Le serveur qui a donné son adresse à cet ordinateur (bail DHCP) ; `None` : non lu.
    pub dhcp_serveur: Option<Ipv4Addr>,
    /// Les appareils qui se présentent comme routeur IPv6 ; `None` : non lu sur ce système.
    pub routeurs_ipv6: Option<Vec<RouteurIpv6>>,
    /// Les carnets des réseaux déjà scannés, pour reconnaître une box qui a changé d'adresse MAC.
    pub carnets: Vec<Carnet>,
}

/// Ce que le domaine regarde, tiré du contexte de l'audit : le scan, la passerelle, l'adresse de cet ordinateur, le
/// nom du réseau et le réseau invité (déclaré ou reconnu), plus le bail DHCP (`audit::bail`), les tables du noyau et
/// les carnets des réseaux déjà scannés.
pub fn entree(c: &super::Contexte) -> Entree {
    let appareils = c
        .scan
        .hotes
        .iter()
        .map(|h| Appareil {
            ip: h.ip,
            mac: h.mac.clone(),
            fabricant: h.fabricant.clone(),
            nom: h.nom.clone(),
            titre: h.titre(),
            boite: h.role == Some("passerelle"),
            tcp: h.ports.iter().filter(|p| !p.udp).map(|p| p.port).collect(),
            annonces: objets::annonces(&h.ports),
        })
        .collect();
    let nom_reseau = c.nom_reseau.map(str::to_string).or_else(|| c.scan.nom_reseau.clone());
    // Le serveur DHCP du bail en cours sur l'interface du réseau local (la première qui en a un en IPv4).
    let dhcp_serveur = super::bail::lire().ok().and_then(|baux| {
        baux.iter().find_map(|b| match b.serveur {
            Some(std::net::IpAddr::V4(ip)) => Some(ip),
            _ => None,
        })
    });
    Entree {
        appareils,
        moi: c.adresse_locale,
        passerelle: c.passerelle,
        invite: if c.invite {
            Some(true)
        } else {
            nom_reseau.as_deref().map(reseau_invite)
        },
        nom_reseau,
        en_wifi: en_wifi(),
        dhcp_serveur,
        routeurs_ipv6: routeurs_ipv6(),
        carnets: crate::reseau::resumes_des_carnets()
            .into_iter()
            .map(|(mac_boite, nom, ip_boite)| Carnet {
                mac_boite,
                nom,
                ip_boite,
            })
            .collect(),
    }
}

/// Les constats du domaine, dans l'ordre des règles.
/// Les règles d'intégrité ARP (`audit::arp`) font partie du domaine : elles suivent.
pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut liste = vec![
        objets_avec_les_ordinateurs(e),
        isolation(e),
        serveur_dhcp(e),
        deux_routeurs_ipv6(e),
    ];
    liste.extend(super::arp::constats(e));
    liste
}

/// Un réseau invité se reconnaît à son nom : « invité », « guest », « visiteur », ou un suffixe « -G ».
pub fn reseau_invite(nom: &str) -> bool {
    let n = nom.trim().to_lowercase();
    ["invit", "guest", "visiteur", "visitor"].iter().any(|m| n.contains(m)) || n.ends_with("-g") || n.ends_with("_g")
}

/// Jusqu'à cinq noms, puis « … » : une liste lisible dans un message.
pub fn liste_courte<'a>(noms: impl Iterator<Item = &'a str>) -> String {
    let noms: Vec<&str> = noms.collect();
    let mut texte = noms.iter().take(5).copied().collect::<Vec<_>>().join(", ");
    if noms.len() > 5 {
        texte.push_str(", …");
    }
    texte
}

/// COM-SEG-001 : des objets connectés (télé, caméra, prise, assistant…) sur le même réseau que les ordinateurs. Un
/// objet piraté y atteint tout ; un réseau invité ou « objets » de la box les en sépare. Un fabricant inconnu ou
/// une MAC aléatoire n'est jamais compté comme objet.
fn objets_avec_les_ordinateurs(e: &Entree) -> Constat {
    let objets: Vec<&Appareil> = e.appareils.iter().filter(|a| a.genre().is_some()).collect();
    let n = objets.len();
    if n == 0 {
        return Constat {
            regle: "COM-SEG-001",
            ..ok(
                "Réseau local",
                tr!(
                    "Aucun objet connecté reconnu sur le réseau de vos ordinateurs.",
                    "No connected device recognized on your computers' network."
                ),
            )
        };
    }
    let noms: Vec<String> = objets.iter().map(|a| a.affiche()).collect();
    let liste = liste_courte(noms.iter().map(String::as_str));
    let niveau = if n >= 3 { Niveau::Moyen } else { Niveau::Info };
    Constat {
        regle: "COM-SEG-001",
        ..alerte(
            "Réseau local",
            niveau,
            trf!(
                "Objets connectés sur le réseau de vos ordinateurs ({n}) : {liste}. Un objet piraté peut les atteindre. Si le routeur le permet, créez un réseau invité ou « objets » et mettez-y télés, prises, caméras et assistants ; gardez sur le réseau principal ce qui doit parler à vos ordinateurs (imprimante, Chromecast).",
                "Connected devices on your computers' network ({n}): {liste}. A hacked device can reach them. If the router allows it, create a guest or “devices” network and move TVs, plugs, cameras and assistants there; keep on the main network what must talk to your computers (printer, Chromecast)."
            ),
        )
    }
}

/// Ports d'un service qui prouve qu'un réseau invité n'isole rien : partage de fichiers, flux d'une caméra, page
/// d'administration, prise en main à distance, impression.
const SERVICES_DE_LA_MAISON: [u16; 11] = [22, 80, 139, 445, 554, 631, 3389, 5900, 8080, 8443, 9100];

/// COM-SEG-002 : depuis un réseau invité, les appareils de la maison ne devraient pas répondre ; s'ils répondent,
/// le réseau invité n'est pas séparé du principal. Sur le réseau principal, les appareils se voient entre eux :
/// c'est normal, et l'étanchéité du réseau invité ne se teste qu'en s'y connectant.
fn isolation(e: &Entree) -> Constat {
    let autres: Vec<&Appareil> = e.appareils.iter().filter(|a| !a.boite && Some(a.ip) != e.moi).collect();
    let n = autres.len();
    let nom = crate::ui::affichable(e.nom_reseau.as_deref().unwrap_or_default());
    if e.invite != Some(true) {
        let ethernet = match e.en_wifi {
            Some(false) => tr!(
                " Cet ordinateur est en Ethernet : l'isolation Wi-Fi d'un réseau invité ne s'y appliquerait pas.",
                " This computer is on Ethernet: a guest network's Wi-Fi isolation would not apply to it."
            ),
            _ => "",
        };
        return Constat {
            regle: "COM-SEG-002",
            ..alerte(
                "Réseau local",
                Niveau::Info,
                trf!(
                    "{n} appareil(s) se voient entre eux sur ce réseau : normal chez vous. L'étanchéité du réseau invité du routeur se teste en s'y connectant puis en relançant l'audit.{ethernet}",
                    "{n} device(s) can see each other on this network: normal at home. The router's guest network isolation is tested by joining it and running the audit again.{ethernet}"
                ),
            )
        };
    }
    if n == 0 {
        return Constat {
            regle: "COM-SEG-002",
            ..ok(
                "Réseau local",
                trf!(
                    "Depuis le réseau invité « {nom} », aucun appareil de votre domicile ne répond : il est bien séparé du réseau principal.",
                    "From the guest network “{nom}”, no household device answers: it is properly separated from the main network."
                ),
            )
        };
    }
    let noms: Vec<String> = autres.iter().map(|a| a.affiche()).collect();
    let liste = liste_courte(noms.iter().map(String::as_str));
    let services = autres
        .iter()
        .filter(|a| a.tcp.iter().any(|p| SERVICES_DE_LA_MAISON.contains(p)))
        .count();
    let niveau = if services > 0 { Niveau::Eleve } else { Niveau::Moyen };
    Constat {
        regle: "COM-SEG-002",
        ..alerte(
            "Réseau local",
            niveau,
            trf!(
                "Depuis le réseau invité « {nom} », {n} appareil(s) de votre domicile répondent encore ({liste}) : ce réseau n'est pas séparé du principal. Dans le routeur : réseau invité › activer l'isolation (« isolation des clients », accès au réseau local désactivé). Un appareil en Ethernet reste visible malgré l'isolation Wi-Fi.",
                "From the guest network “{nom}”, {n} household device(s) still answer ({liste}): this network is not separated from the main one. In the router: guest network › enable isolation (“client isolation”, local network access off). A device on Ethernet stays visible despite Wi-Fi isolation."
            ),
        )
    }
}

/// COM-SEG-004 : les adresses du réseau doivent venir de la box. Un autre appareil qui les distribue peut se faire
/// passer pour elle (sa passerelle, ses DNS) et voir passer le trafic ; un Pi-hole ou un NAS à soi, nommé dans le
/// carnet, est normal. Un second serveur DHCP concurrent ne se détecte qu'en écoutant le port 68 : non vérifié.
fn serveur_dhcp(e: &Entree) -> Constat {
    let Some(serveur) = e.dhcp_serveur else {
        return Constat {
            regle: "COM-SEG-004",
            ..impossible(
                "Réseau local",
                tr!(
                    "serveur DHCP non lu sur ce système",
                    "DHCP server not read on this system"
                ),
            )
        };
    };
    // « le routeur 10.0.0.1 », ou « le routeur » seul quand son adresse n'est pas connue.
    let boite = e.passerelle.map_or_else(String::new, |p| format!(" {p}"));
    if Some(serveur) == e.passerelle {
        return Constat {
            regle: "COM-SEG-004",
            ..ok(
                "Réseau local",
                trf!(
                    "Les adresses du réseau sont distribuées par le routeur ({serveur}).",
                    "Network addresses are handed out by the router ({serveur})."
                ),
            )
        };
    }
    let appareil = e.appareils.iter().find(|a| a.ip == serveur);
    let nomme = appareil.is_some_and(|a| !a.titre.is_empty());
    let qui = appareil.map_or_else(
        || tr!("appareil inconnu du scan", "device unknown to the scan").to_string(),
        Appareil::affiche,
    );
    let niveau = if nomme { Niveau::Info } else { Niveau::Moyen };
    Constat {
        regle: "COM-SEG-004",
        ..alerte(
            "Réseau local",
            niveau,
            trf!(
                "Les adresses du réseau sont distribuées par {serveur} ({qui}) et non par le routeur{boite} : si ce n'est pas un serveur à vous (Pi-hole, NAS, second routeur), un appareil peut se faire passer pour le routeur et voir passer votre trafic. Un second serveur DHCP concurrent ne se détecte pas d'ici.",
                "Network addresses are handed out by {serveur} ({qui}) and not by the router{boite}: if it is not a server of yours (Pi-hole, NAS, second router), a device may pose as the router and see your traffic. A competing second DHCP server cannot be detected from here."
            ),
        )
    }
}

/// Le texte d'un routeur IPv6 : son adresse, et sa MAC quand l'adresse la contient.
fn texte_routeur(r: &RouteurIpv6) -> String {
    match &r.mac {
        Some(mac) => format!("{} ({mac})", r.adresse),
        None => r.adresse.to_string(),
    }
}

/// COM-SEG-005 : un seul appareil doit se présenter comme routeur IPv6. Deux appareils (deux adresses MAC) qui
/// annoncent une route par défaut : l'un n'est pas la box, et le trafic IPv6 peut passer par lui. Une box qui a
/// deux adresses de lien local compte pour une (même MAC) ; sans MAC lisible, deux adresses sont dites telles quelles.
fn deux_routeurs_ipv6(e: &Entree) -> Constat {
    let Some(routeurs) = &e.routeurs_ipv6 else {
        return Constat {
            regle: "COM-SEG-005",
            ..impossible(
                "Réseau local",
                tr!(
                    "routes IPv6 non lues sur ce système",
                    "IPv6 routes not read on this system"
                ),
            )
        };
    };
    let mut distincts: Vec<&RouteurIpv6> = Vec::new();
    for r in routeurs {
        let meme = |d: &&RouteurIpv6| match (&d.mac, &r.mac) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => d.adresse == r.adresse,
        };
        if !distincts.iter().any(meme) {
            distincts.push(r);
        }
    }
    match distincts.as_slice() {
        [] => Constat {
            regle: "COM-SEG-005",
            ..ok(
                "Réseau local",
                tr!(
                    "Aucun appareil ne se présente comme routeur IPv6.",
                    "No device presents itself as the IPv6 router."
                ),
            )
        },
        [seul] => {
            let a = texte_routeur(seul);
            Constat {
                regle: "COM-SEG-005",
                ..ok(
                    "Réseau local",
                    trf!(
                        "Un seul routeur IPv6 annoncé : {a}.",
                        "A single IPv6 router announced: {a}."
                    ),
                )
            }
        }
        [premier, second, ..] => {
            let (a, b) = (texte_routeur(premier), texte_routeur(second));
            let mac = second
                .mac
                .as_deref()
                .unwrap_or(tr!("de cet appareil", "of that device"));
            Constat {
                regle: "COM-SEG-005",
                ..alerte(
                    "Réseau local",
                    Niveau::Moyen,
                    trf!(
                        "Deux appareils se présentent comme routeur IPv6 ({a} et {b}) : l'un n'est pas votre routeur, et votre trafic IPv6 peut passer par lui. Trouvez l'appareil à l'adresse MAC {mac} dans le carnet des appareils et débranchez-le ; si c'est un second routeur à vous, désactivez son IPv6 ou mettez-le en mode pont. Normal pendant un changement de routeur ou avec le partage de connexion d'un téléphone.",
                        "Two devices present themselves as the IPv6 router ({a} and {b}): one of them is not your router, and your IPv6 traffic may go through it. Find the device with MAC address {mac} in the device list and unplug it; if it is a second router of yours, disable its IPv6 or set it to bridge mode. Normal while replacing the router or when sharing a phone's connection."
                    ),
                )
            }
        }
    }
}

/// L'adresse MAC contenue dans une adresse IPv6 de lien local formée par EUI-64 (« ff:fe » au milieu, bit
/// universel/local inversé) ; `None` pour une adresse choisie autrement (aléatoire, stable).
#[cfg(any(target_os = "linux", test))]
pub fn mac_eui64(adresse: &Ipv6Addr) -> Option<String> {
    let o = adresse.octets();
    if o[0] != 0xfe || o[1] & 0xc0 != 0x80 || o[11] != 0xff || o[12] != 0xfe {
        return None;
    }
    Some(format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        o[8] ^ 0x02,
        o[9],
        o[10],
        o[13],
        o[14],
        o[15]
    ))
}

/// Les routeurs IPv6 de /proc/net/ipv6_route : les routes par défaut (destination ::/0) qui passent par une
/// passerelle (RTF_GATEWAY), sans doublon. Colonnes : destination, longueur, source, longueur, prochain saut,
/// métrique, références, usages, drapeaux, interface.
#[cfg(any(target_os = "linux", test))]
pub fn routeurs_ipv6_linux(table: &str) -> Vec<RouteurIpv6> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    let mut routeurs: Vec<RouteurIpv6> = Vec::new();
    for ligne in table.lines() {
        let c: Vec<&str> = ligne.split_whitespace().collect();
        // Dix colonnes au moins : destination, longueur, …, saut (5e), …, drapeaux (9e), interface (10e).
        let [destination, longueur, _, _, saut, _, _, _, drapeaux, interface, ..] = c[..] else {
            continue;
        };
        if longueur != "00" || destination.bytes().any(|b| b != b'0') {
            continue;
        }
        let Ok(drapeaux) = u32::from_str_radix(drapeaux, 16) else {
            continue;
        };
        if drapeaux & (RTF_UP | RTF_GATEWAY) != RTF_UP | RTF_GATEWAY {
            continue;
        }
        let Ok(saut) = u128::from_str_radix(saut, 16) else {
            continue;
        };
        let adresse = Ipv6Addr::from(saut);
        if adresse.is_unspecified()
            || routeurs
                .iter()
                .any(|r| r.adresse == adresse && r.interface == interface)
        {
            continue;
        }
        routeurs.push(RouteurIpv6 {
            adresse,
            interface: interface.to_string(),
            mac: mac_eui64(&adresse),
        });
    }
    routeurs
}

/// Les appareils qui se présentent comme routeur IPv6, lus dans les tables du noyau ; `None` ailleurs que sous
/// Linux (Windows : table des routes par iphlpapi, macOS : sysctl, à venir).
fn routeurs_ipv6() -> Option<Vec<RouteurIpv6>> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/net/ipv6_route")
            .ok()
            .map(|t| routeurs_ipv6_linux(&t))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// L'interface de la route par défaut dans /proc/net/route (Iface Destination Gateway Flags RefCnt Use Metric…),
/// la plus petite métrique d'abord, comme pour la passerelle.
#[cfg(any(target_os = "linux", test))]
pub fn interface_par_defaut_linux(table: &str) -> Option<String> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let hex = |i: usize| u32::from_str_radix(c.get(i)?, 16).ok();
            let (dest, gw, drapeaux) = (hex(1)?, hex(2)?, hex(3)?);
            let metrique: u32 = c.get(6)?.parse().ok()?;
            let utile = dest == 0 && gw != 0 && drapeaux & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY;
            let carte = (*c.first()?).to_string();
            utile.then_some((metrique, carte))
        })
        .min()
        .map(|(_, carte)| carte)
}

/// Cet ordinateur est-il en Wi-Fi : l'interface de la route par défaut a un dossier « wireless » dans /sys ;
/// `None` ailleurs que sous Linux (à venir : wlanapi, CoreWLAN, par le lot Wi-Fi).
fn en_wifi() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        let carte = interface_par_defaut_linux(&std::fs::read_to_string("/proc/net/route").ok()?)?;
        if carte.contains('/') || carte.contains("..") {
            return None;
        }
        Some(
            std::path::Path::new("/sys/class/net")
                .join(carte)
                .join("wireless")
                .exists(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Un appareil inventé du réseau « Salon » : adresse MAC au préfixe d'un fabricant, jamais une vraie adresse.
    pub(crate) fn appareil(ip: u8, mac: &str, fabricant: Option<&str>, nom: Option<&str>, tcp: &[u16]) -> Appareil {
        Appareil {
            ip: Ipv4Addr::new(192, 168, 50, ip),
            mac: Some(mac.to_string()),
            fabricant: fabricant.map(str::to_string),
            nom: nom.map(str::to_string),
            titre: [nom, fabricant].into_iter().flatten().collect::<Vec<_>>().join(" · "),
            boite: ip == 1,
            tcp: tcp.to_vec(),
            annonces: Vec::new(),
        }
    }

    pub(crate) fn entree(appareils: Vec<Appareil>) -> Entree {
        Entree {
            appareils,
            moi: Some(Ipv4Addr::new(192, 168, 50, 10)),
            passerelle: Some(Ipv4Addr::new(192, 168, 50, 1)),
            nom_reseau: Some("Salon".into()),
            invite: Some(false),
            en_wifi: Some(true),
            dhcp_serveur: Some(Ipv4Addr::new(192, 168, 50, 1)),
            routeurs_ipv6: Some(Vec::new()),
            carnets: Vec::new(),
        }
    }

    fn boite() -> Appareil {
        appareil(
            1,
            "e4:5d:51:10:20:30",
            Some("Sagemcom Broadband SAS"),
            Some("box"),
            &[80, 443],
        )
    }

    fn regle<'a>(constats: &'a [Constat], id: &str) -> &'a Constat {
        constats.iter().find(|c| c.regle == id).unwrap()
    }

    #[test]
    fn objets_sur_le_reseau_des_ordinateurs() {
        // Un PC seul avec la box : rien.
        let pc = appareil(10, "f0:18:98:aa:bb:cc", Some("Apple, Inc."), Some("portable"), &[22]);
        let c = constats(&entree(vec![boite(), pc]));
        assert_eq!(regle(&c, "COM-SEG-001").probleme, None);
        // Deux objets : information ; trois : moyen, et la liste les nomme.
        let tele = appareil(20, "d8:3a:dd:00:00:01", Some("Roku, Inc"), Some("Roku-Salon"), &[8060]);
        let prise = appareil(21, "24:0a:c4:00:00:02", Some("Espressif Inc."), None, &[80]);
        let imprimante = appareil(22, "00:1e:8f:00:00:03", Some("Canon Inc."), None, &[9100]);
        let c = constats(&entree(vec![boite(), tele.clone_pour_test(), prise.clone_pour_test()]));
        let seg = regle(&c, "COM-SEG-001");
        assert_eq!(seg.probleme, Some(Niveau::Info));
        assert!(seg.message.contains("Roku-Salon"), "{}", seg.message);
        let c = constats(&entree(vec![boite(), tele, prise, imprimante]));
        assert_eq!(regle(&c, "COM-SEG-001").probleme, Some(Niveau::Moyen));
        // Une MAC aléatoire sans indice n'est jamais un objet.
        let tel = appareil(
            30,
            "02:11:22:33:44:55",
            Some("MAC aléatoire (téléphone/tablette ?)"),
            None,
            &[],
        );
        let c = constats(&entree(vec![boite(), tel]));
        assert_eq!(regle(&c, "COM-SEG-001").probleme, None);
    }

    impl Appareil {
        fn clone_pour_test(&self) -> Appareil {
            Appareil {
                ip: self.ip,
                mac: self.mac.clone(),
                fabricant: self.fabricant.clone(),
                nom: self.nom.clone(),
                titre: self.titre.clone(),
                boite: self.boite,
                tcp: self.tcp.clone(),
                annonces: self.annonces.clone(),
            }
        }
    }

    #[test]
    fn isolation_du_reseau_invite() {
        let nas = appareil(
            40,
            "00:11:32:00:00:04",
            Some("Synology Incorporated"),
            Some("nas"),
            &[445, 5000],
        );
        let prise = appareil(21, "24:0a:c4:00:00:02", Some("Espressif Inc."), None, &[]);
        // Réseau principal : information seulement, et l'Ethernet est dit.
        let mut e = entree(vec![boite(), nas.clone_pour_test(), prise.clone_pour_test()]);
        e.en_wifi = Some(false);
        let seg = &constats(&e)[1];
        assert_eq!(
            (seg.regle, seg.probleme, seg.verifie),
            ("COM-SEG-002", Some(Niveau::Info), true)
        );
        assert!(seg.message.contains("Ethernet"));
        // Réseau invité : un partage SMB qui répond = élevé ; sans service = moyen ; personne = bien séparé.
        let mut e = entree(vec![boite(), nas, prise.clone_pour_test()]);
        e.nom_reseau = Some("Salon-Invités".into());
        e.invite = Some(true);
        let seg = &constats(&e)[1];
        assert_eq!(seg.probleme, Some(Niveau::Eleve));
        assert!(
            seg.message.contains("Salon-Invités") && seg.message.contains("nas"),
            "{}",
            seg.message
        );
        e.appareils = vec![boite(), prise];
        assert_eq!(constats(&e)[1].probleme, Some(Niveau::Moyen));
        e.appareils = vec![boite()];
        assert_eq!(constats(&e)[1].probleme, None);
        assert!(reseau_invite("Salon-Invités") && reseau_invite("Guest Wifi") && reseau_invite("Maison-G"));
        assert!(!reseau_invite("Salon") && !reseau_invite("Garage"));
    }

    #[test]
    fn serveur_dhcp_autre_que_la_box() {
        let pi = appareil(
            50,
            "dc:a6:32:00:00:05",
            Some("Raspberry Pi Trading Ltd"),
            Some("pihole"),
            &[53, 80],
        );
        let mut e = entree(vec![boite(), pi]);
        assert_eq!(constats(&e)[2].probleme, None);
        e.dhcp_serveur = None;
        assert!(!constats(&e)[2].verifie);
        // Un serveur nommé dans le carnet : information ; inconnu du scan : moyen.
        e.dhcp_serveur = Some(Ipv4Addr::new(192, 168, 50, 50));
        let seg = &constats(&e)[2];
        assert_eq!(seg.probleme, Some(Niveau::Info));
        assert!(seg.message.contains("pihole"), "{}", seg.message);
        e.dhcp_serveur = Some(Ipv4Addr::new(192, 168, 50, 77));
        assert_eq!(constats(&e)[2].probleme, Some(Niveau::Moyen));
    }

    const TABLE_IPV6: &str = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000e65d51fffe102030 00000400 00000001 00000000 00000003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000e65d51fffe102030 00000400 00000001 00000000 00000003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000f21898fffeaabbcc 00000400 00000001 00000000 00000003 wlan0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 wlan0
";

    #[test]
    fn deux_routeurs_ipv6_annonces() {
        let routeurs = routeurs_ipv6_linux(TABLE_IPV6);
        assert_eq!(routeurs.len(), 2, "{routeurs:?}");
        assert_eq!(routeurs[0].mac.as_deref(), Some("e4:5d:51:10:20:30"));
        assert_eq!(routeurs[1].mac.as_deref(), Some("f0:18:98:aa:bb:cc"));
        let mut e = entree(vec![boite()]);
        e.routeurs_ipv6 = Some(routeurs);
        let seg = &constats(&e)[3];
        assert_eq!(seg.probleme, Some(Niveau::Moyen));
        assert!(seg.message.contains("f0:18:98:aa:bb:cc"), "{}", seg.message);
        // Une box avec deux adresses de lien local (même MAC) compte pour une.
        e.routeurs_ipv6 = Some(vec![
            RouteurIpv6 {
                adresse: "fe80::e65d:51ff:fe10:2030".parse().unwrap(),
                interface: "wlan0".into(),
                mac: Some("e4:5d:51:10:20:30".into()),
            },
            RouteurIpv6 {
                adresse: "fe80::1".parse().unwrap(),
                interface: "wlan0".into(),
                mac: Some("E4:5D:51:10:20:30".into()),
            },
        ]);
        assert_eq!(constats(&e)[3].probleme, None);
        e.routeurs_ipv6 = Some(Vec::new());
        assert_eq!(constats(&e)[3].probleme, None);
        e.routeurs_ipv6 = None;
        assert!(!constats(&e)[3].verifie);
        assert_eq!(mac_eui64(&"fe80::1".parse().unwrap()), None);
        assert_eq!(mac_eui64(&"2001:db8::e65d:51ff:fe10:2030".parse().unwrap()), None);
    }

    #[test]
    fn interface_de_la_route_par_defaut() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0132A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
wlan0\t00000000\t0132A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
wlan0\t0032A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(interface_par_defaut_linux(table).as_deref(), Some("eth0"));
        assert_eq!(interface_par_defaut_linux("Iface\n"), None);
    }

    /// Sur cette machine, les lectures réelles répondent sans paniquer (les valeurs dépendent du réseau).
    #[test]
    fn lectures_reelles() {
        let _ = en_wifi();
        let _ = routeurs_ipv6();
        assert_eq!(
            liste_courte(["a", "b", "c", "d", "e", "f"].into_iter()),
            "a, b, c, d, e, …"
        );
    }
}
