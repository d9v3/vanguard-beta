//! L'état du mode Wi-Fi public : le réseau où il a été allumé et, pour chaque élément changé, sa valeur d'avant.
//! Scellé (`sceau::WIFI_PUBLIC`) : il est réécrivable par tout programme du compte et sa remise s'exécute en
//! administrateur. Seul un état intact est remis, et chaque valeur notée est encore validée sur un ensemble fermé
//! avant d'entrer dans une commande ; un élément qui ne se valide pas n'est jamais remis.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub(super) const VERSION: u32 = 1;

/// Où en est le mode. Tout ce qui n'est pas `Allume` après coup veut dire qu'une étape a été interrompue
/// (plantage, coupure, Ctrl-C) : l'état le dit au lancement suivant, et rien n'est refait sans accord.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Etape {
    Allumage,
    Allume,
    Portail,
    Extinction,
}

/// Le réseau du mode : son nom (affiché seulement), sa carte, et l'identité de sa connexion (Linux : l'UUID du profil
/// de NetworkManager ; Windows : le GUID de la carte ; macOS : le service réseau).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reseau {
    pub nom: String,
    pub interface: String,
    pub id: String,
}

/// Un élément changé par le mode, avec de quoi le remettre exactement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "genre", rename_all = "kebab-case")]
pub(crate) enum Element {
    /// Linux : la table nftables à part qui bloque les entrées de la carte Wi-Fi (absente avant, par construction).
    NftTable { interface: String },
    /// Linux : une unité de systemd masquée jusqu'au redémarrage (`mask --runtime --now`), et si elle tournait.
    UniteRuntime { unite: String, actif_avant: bool },
    /// Linux : une propriété du profil NetworkManager du réseau public, et sa valeur d'avant.
    Nm {
        uuid: String,
        propriete: String,
        avant: String,
    },
    /// Le DNS de la connexion, dans la forme de « DNS le plus rapide » (`optimiser`) : identité, saut de ligne,
    /// serveurs.
    Dns { avant: String },
    /// Windows : la catégorie du profil réseau (« Private » avant ; le mode met « Public »).
    Categorie { guid: String, avant: String },
    /// Windows : un paramètre du profil Public du pare-feu, et sa valeur d'avant.
    ProfilPublic { parametre: String, avant: String },
    /// Windows : NetBIOS de la carte (NetbiosOptions : 0 selon DHCP, 1 allumé ; le mode met 2).
    NetBios { carte: String, avant: u32 },
    /// macOS : une option du pare-feu applicatif (globalstate, blockall, stealthmode), « on » ou « off » avant.
    MacPareFeu { option: String, avant: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Etat {
    pub version: u32,
    pub etape: Etape,
    /// « AAAA-MM-JJ HH:MM », pour l'écran.
    pub depuis: String,
    /// Le démarrage du système où le mode a été allumé (Linux : boot_id) : un autre, et ce qui ne vit que jusqu'au
    /// redémarrage (table nft, masques runtime) est parti tout seul.
    #[serde(default)]
    pub demarrage: String,
    pub reseau: Reseau,
    /// `wifi-public portail` : le DNS chiffré est en « opportuniste » jusqu'à cette heure (secondes Unix).
    #[serde(default)]
    pub portail_jusqu_a: Option<i64>,
    /// Les entrées ne sont pas fermées par le mode (pas de nft, pare-feu illisible, commande refusée) : le menu et le
    /// bilan le disent, au lieu d'un « allumé » qui le laisserait croire.
    #[serde(default)]
    pub entrees_ouvertes: bool,
    pub elements: Vec<Element>,
}

impl Etat {
    pub(super) fn lire(octets: &[u8]) -> Option<Etat> {
        let e: Etat = serde_json::from_slice(octets).ok()?;
        (e.version == VERSION).then_some(e)
    }

    pub(super) fn octets(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }
}

/// Les unités que le mode peut masquer : l'annonce du nom de l'ordinateur (Avahi, wsdd) et le partage de fichiers
/// (Samba). Les sockets d'abord : une unité socket relancerait son service masqué.
pub(crate) const UNITES: [&str; 8] = [
    "avahi-daemon.socket",
    "avahi-daemon.service",
    "smb.service",
    "smbd.service",
    "nmb.service",
    "nmbd.service",
    "wsdd.service",
    "wsdd2.service",
];

/// Les propriétés d'un profil NetworkManager que le mode change, et les valeurs qu'elles peuvent avoir.
pub(crate) const PROPRIETES_NM: [(&str, &[&str]); 3] = [
    ("connection.mdns", &["default", "no", "resolve", "yes"]),
    ("connection.llmnr", &["default", "no", "resolve", "yes"]),
    ("connection.dns-over-tls", &["default", "no", "opportunistic", "yes"]),
];

/// Les paramètres du profil Public du pare-feu de Windows, et les valeurs qu'ils peuvent avoir.
pub(crate) const PARAMETRES_PROFIL: [(&str, &[&str]); 3] = [
    ("Enabled", &["True", "False", "NotConfigured"]),
    ("DefaultInboundAction", &["Allow", "Block", "NotConfigured"]),
    ("AllowInboundRules", &["True", "False", "NotConfigured"]),
];

pub(crate) const OPTIONS_MAC: [&str; 3] = ["globalstate", "blockall", "stealthmode"];

/// Un nom de carte réseau : il entre dans le script nft et dans les commandes.
pub(crate) fn interface_valide(t: &str) -> bool {
    (1..=15).contains(&t.len())
        && t.bytes()
            .all(|o| o.is_ascii_alphanumeric() || matches!(o, b'_' | b'.' | b'-'))
}

/// Un identifiant de connexion de NetworkManager (UUID 8-4-4-4-12).
pub(crate) fn uuid_valide(t: &str) -> bool {
    let morceaux: Vec<&str> = t.split('-').collect();
    morceaux.iter().map(|m| m.len()).eq([8, 4, 4, 4, 12])
        && morceaux.iter().all(|m| m.bytes().all(|o| o.is_ascii_hexdigit()))
}

/// Un GUID de Windows entre accolades : « {8-4-4-4-12} ».
pub(crate) fn guid_valide(t: &str) -> bool {
    t.strip_prefix('{')
        .and_then(|r| r.strip_suffix('}'))
        .is_some_and(uuid_valide)
}

/// Un nom de serveur pour le DNS chiffré (« protected.canadianshield.cira.ca »).
fn nom_valide(t: &str) -> bool {
    (1..=253).contains(&t.len())
        && t.split('.').all(|e| {
            (1..=63).contains(&e.len())
                && e.bytes()
                    .all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-')
        })
}

/// Un serveur DNS noté : une adresse IP, suivie sous Linux d'un « #nom » pour le DNS chiffré.
fn serveur_valide(t: &str, avec_nom: bool) -> bool {
    match t.split_once('#') {
        Some((ip, nom)) => avec_nom && ip.parse::<IpAddr>().is_ok() && nom_valide(nom),
        None => t.parse::<IpAddr>().is_ok(),
    }
}

fn liste_valide(t: &str, avec_nom: bool) -> bool {
    t.split(',')
        .filter(|s| !s.is_empty())
        .all(|s| serveur_valide(s, avec_nom))
}

/// Linux : « uuid\ndns4|ignore4|dns6|ignore6 » (forme d'`optimiser::linux`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn dns_valide_linux(v: &str) -> bool {
    let Some((uuid, reste)) = v.split_once('\n') else {
        return false;
    };
    let c: Vec<&str> = reste.split('|').collect();
    uuid_valide(uuid)
        && matches!(c.as_slice(), [dns4, ignore4, dns6, ignore6]
            if liste_valide(dns4, true)
                && liste_valide(dns6, true)
                && ["yes", "no"].contains(ignore4)
                && ["yes", "no"].contains(ignore6))
}

/// Windows : « {guid}\nv4|v6 » (forme d'`optimiser::windows`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn dns_valide_windows(v: &str) -> bool {
    let Some((guid, reste)) = v.split_once('\n') else {
        return false;
    };
    let c: Vec<&str> = reste.split('|').collect();
    guid_valide(guid) && c.len() == 2 && c.iter().all(|l| liste_valide(l, false))
}

/// macOS : « service\nserveurs » (forme d'`optimiser::macos`) ; le nom du service entre dans la commande entre
/// apostrophes.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn dns_valide_macos(v: &str) -> bool {
    let Some((service, liste)) = v.split_once('\n') else {
        return false;
    };
    (1..=64).contains(&service.chars().count())
        && !service.chars().any(char::is_control)
        && !liste.contains('|')
        && liste_valide(liste, false)
}

fn dns_valide(v: &str) -> bool {
    #[cfg(target_os = "linux")]
    return dns_valide_linux(v);
    #[cfg(windows)]
    return dns_valide_windows(v);
    #[cfg(target_os = "macos")]
    return dns_valide_macos(v);
}

fn dans(table: &[(&str, &[&str])], cle: &str, valeur: &str) -> bool {
    table.iter().any(|(c, valeurs)| *c == cle && valeurs.contains(&valeur))
}

impl Element {
    /// Toutes les valeurs notées sont-elles de celles qu'une commande peut recevoir ?
    pub(crate) fn valide(&self) -> bool {
        match self {
            Element::NftTable { interface } => interface_valide(interface),
            Element::UniteRuntime { unite, .. } => UNITES.contains(&unite.as_str()),
            Element::Nm { uuid, propriete, avant } => uuid_valide(uuid) && dans(&PROPRIETES_NM, propriete, avant),
            Element::Dns { avant } => dns_valide(avant),
            Element::Categorie { guid, avant } => guid_valide(guid) && avant == "Private",
            Element::ProfilPublic { parametre, avant } => dans(&PARAMETRES_PROFIL, parametre, avant),
            Element::NetBios { carte, avant } => guid_valide(carte) && *avant <= 1,
            Element::MacPareFeu { option, avant } => {
                OPTIONS_MAC.contains(&option.as_str()) && ["on", "off"].contains(&avant.as_str())
            }
        }
    }

    /// Ce qui identifie l'élément (sans sa valeur d'avant) : rallumer garde la valeur d'avant la plus ancienne.
    pub(crate) fn cle(&self) -> String {
        match self {
            Element::NftTable { .. } => "nft".to_string(),
            Element::UniteRuntime { unite, .. } => format!("unite:{unite}"),
            Element::Nm { uuid, propriete, .. } => format!("nm:{uuid}:{propriete}"),
            Element::Dns { avant } => format!("dns:{}", avant.split_once('\n').map_or("", |(id, _)| id)),
            Element::Categorie { guid, .. } => format!("categorie:{guid}"),
            Element::ProfilPublic { parametre, .. } => format!("profil:{parametre}"),
            Element::NetBios { carte, .. } => format!("netbios:{carte}"),
            Element::MacPareFeu { option, .. } => format!("alf:{option}"),
        }
    }

    /// Un pare-feu trouvé coupé : le mode l'allume et ne le recoupe jamais.
    pub(crate) fn jamais_remis(&self) -> bool {
        match self {
            Element::ProfilPublic { parametre, avant } => parametre == "Enabled" && avant == "False",
            Element::MacPareFeu { option, avant } => option == "globalstate" && avant == "off",
            _ => false,
        }
    }

    /// Ne vit que jusqu'au redémarrage.
    pub(crate) fn ephemere(&self) -> bool {
        matches!(self, Element::NftTable { .. } | Element::UniteRuntime { .. })
    }
}

/// Fusionne ce qui va être changé avec un état d'avant (rallumer un mode à moitié) : un élément déjà noté garde sa
/// valeur d'avant, la plus ancienne, sans quoi rallumer noterait comme « avant » ce que le mode a lui-même posé.
pub(crate) fn fusionner(anciens: &[Element], nouveaux: Vec<Element>) -> Vec<Element> {
    let mut tous: Vec<Element> = anciens.to_vec();
    for n in nouveaux {
        if !tous.iter().any(|a| a.cle() == n.cle()) {
            tous.push(n);
        }
    }
    tous
}

/// Les éléments à remettre, dans l'ordre inverse de l'allumage ; ceux qui ne se valident pas à part (jamais remis).
pub(crate) fn a_remettre(e: &Etat) -> (Vec<&Element>, Vec<&Element>) {
    let (valides, invalides): (Vec<&Element>, Vec<&Element>) = e.elements.iter().rev().partition(|x| x.valide());
    (valides, invalides)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn exemple() -> Etat {
        Etat {
            version: VERSION,
            etape: Etape::Allume,
            depuis: "2026-10-23 10:00".into(),
            demarrage: "b".into(),
            reseau: Reseau {
                nom: "Café du coin".into(),
                interface: "wlan0".into(),
                id: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
            },
            portail_jusqu_a: None,
            entrees_ouvertes: false,
            elements: vec![
                Element::NftTable {
                    interface: "wlan0".into(),
                },
                Element::UniteRuntime {
                    unite: "avahi-daemon.service".into(),
                    actif_avant: true,
                },
                Element::Nm {
                    uuid: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
                    propriete: "connection.mdns".into(),
                    avant: "default".into(),
                },
            ],
        }
    }

    #[test]
    fn aller_retour_et_ordre_inverse() {
        let e = exemple();
        let relu = Etat::lire(&e.octets()).unwrap();
        assert_eq!(relu, e);
        let texte = String::from_utf8(e.octets()).unwrap();
        assert!(
            texte.contains("\"genre\": \"nft-table\"") && texte.contains("\"etape\": \"allume\""),
            "{texte}"
        );
        let (valides, invalides) = a_remettre(&e);
        assert_eq!(invalides.len(), 0);
        assert_eq!(
            valides.first().map(|x| x.cle()),
            Some("nm:0b8c2f4e-1a2b-4c3d-9e8f-001122334455:connection.mdns".into())
        );
        assert_eq!(valides.last().map(|x| x.cle()), Some("nft".into()));
        // Une autre version, ou un texte qui n'en est pas un : rien n'est cru.
        let mut autre = e.clone();
        autre.version = 2;
        assert!(Etat::lire(&autre.octets()).is_none());
        assert!(Etat::lire(b"{ pas du json").is_none());
    }

    #[test]
    fn valeurs_hors_des_ensembles_fermes_refusees() {
        let refuses = [
            Element::NftTable {
                interface: "wlan0; rm -rf /".into(),
            },
            Element::NftTable {
                interface: "une-carte-bien-trop-longue".into(),
            },
            Element::NftTable {
                interface: String::new(),
            },
            Element::UniteRuntime {
                unite: "sshd.service".into(),
                actif_avant: true,
            },
            Element::Nm {
                uuid: "0b8c2f4e-1a2b-4c3d-9e8f-00112233445".into(),
                propriete: "connection.mdns".into(),
                avant: "no".into(),
            },
            Element::Nm {
                uuid: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
                propriete: "ipv4.method".into(),
                avant: "manual".into(),
            },
            Element::Nm {
                uuid: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
                propriete: "connection.mdns".into(),
                avant: "no' ; reboot".into(),
            },
            Element::Categorie {
                guid: "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}".into(),
                avant: "DomainAuthenticated".into(),
            },
            Element::Categorie {
                guid: "0B8C2F4E-1A2B-4C3D-9E8F-001122334455".into(),
                avant: "Private".into(),
            },
            Element::ProfilPublic {
                parametre: "Enabled".into(),
                avant: "$true".into(),
            },
            Element::ProfilPublic {
                parametre: "DefaultOutboundAction".into(),
                avant: "Allow".into(),
            },
            Element::NetBios {
                carte: "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}".into(),
                avant: 2,
            },
            Element::MacPareFeu {
                option: "allowsigned".into(),
                avant: "on".into(),
            },
            Element::MacPareFeu {
                option: "blockall".into(),
                avant: "1".into(),
            },
        ];
        for e in &refuses {
            assert!(!e.valide(), "{e:?}");
        }
        let acceptes = [
            Element::Categorie {
                guid: "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}".into(),
                avant: "Private".into(),
            },
            Element::ProfilPublic {
                parametre: "AllowInboundRules".into(),
                avant: "NotConfigured".into(),
            },
            Element::NetBios {
                carte: "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}".into(),
                avant: 0,
            },
            Element::MacPareFeu {
                option: "stealthmode".into(),
                avant: "off".into(),
            },
            Element::UniteRuntime {
                unite: "wsdd.service".into(),
                actif_avant: false,
            },
        ];
        for e in &acceptes {
            assert!(e.valide(), "{e:?}");
        }
        // Un état qui en contient un mauvais : celui-là seulement est mis à part, jamais remis.
        let mut e = exemple();
        e.elements.push(refuses[0].clone());
        let (valides, invalides) = a_remettre(&e);
        assert_eq!((valides.len(), invalides.len()), (3, 1));
    }

    #[test]
    fn dns_notes_par_systeme() {
        let u = "0b8c2f4e-1a2b-4c3d-9e8f-001122334455";
        assert!(dns_valide_linux(&format!(
            "{u}\n149.112.121.20#protected.canadianshield.cira.ca,149.112.122.20|yes|2620:10a:80bb::20|yes"
        )));
        assert!(dns_valide_linux(&format!("{u}\n|no||no")));
        for mauvais in [
            format!("{u}\n1.1.1.1;reboot|no||no"),
            format!("{u}\n1.1.1.1|peut-etre||no"),
            format!("{u}\n1.1.1.1#Nom'Bizarre|no||no"),
            format!("{u}\n|no|"),
            "pas-un-uuid\n|no||no".to_string(),
            "sans saut de ligne".to_string(),
        ] {
            assert!(!dns_valide_linux(&mauvais), "{mauvais}");
        }
        let g = "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}";
        assert!(dns_valide_windows(&format!("{g}\n149.112.121.20,149.112.122.20|")));
        assert!(dns_valide_windows(&format!("{g}\n|")));
        assert!(
            !dns_valide_windows(&format!("{g}\n1.1.1.1#nom|")),
            "pas de nom sous Windows"
        );
        assert!(!dns_valide_windows(&format!("{g}\n'); Remove-Item C:\\ #|")));
        assert!(dns_valide_macos("Wi-Fi\n149.112.121.20,2620:10a:80bb::20"));
        assert!(dns_valide_macos("Wi-Fi\n"));
        assert!(!dns_valide_macos("Wi-Fi\n1.1.1.1|2.2.2.2"));
        assert!(!dns_valide_macos("\n1.1.1.1"));
        assert!(!dns_valide_macos("Wi\u{7}Fi\n1.1.1.1"));
    }

    #[test]
    fn rallumer_garde_la_valeur_la_plus_ancienne() {
        let e = exemple();
        let nouveaux = vec![
            Element::Nm {
                uuid: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
                propriete: "connection.mdns".into(),
                // Relu pendant que le mode est à moitié en place : c'est la valeur du mode, pas celle d'avant.
                avant: "no".into(),
            },
            Element::NftTable {
                interface: "wlan0".into(),
            },
            Element::Nm {
                uuid: "0b8c2f4e-1a2b-4c3d-9e8f-001122334455".into(),
                propriete: "connection.llmnr".into(),
                avant: "default".into(),
            },
        ];
        let tous = fusionner(&e.elements, nouveaux);
        assert_eq!(tous.len(), 4);
        assert!(tous.contains(&e.elements[2]));
        assert!(
            !tous
                .iter()
                .any(|x| matches!(x, Element::Nm { avant, .. } if avant == "no"))
        );
    }

    #[test]
    fn pare_feu_coupe_jamais_recoupe() {
        let coupe = Element::ProfilPublic {
            parametre: "Enabled".into(),
            avant: "False".into(),
        };
        assert!(coupe.jamais_remis());
        let non_configure = Element::ProfilPublic {
            parametre: "Enabled".into(),
            avant: "NotConfigured".into(),
        };
        assert!(!non_configure.jamais_remis());
        assert!(
            Element::MacPareFeu {
                option: "globalstate".into(),
                avant: "off".into()
            }
            .jamais_remis()
        );
        assert!(
            !Element::MacPareFeu {
                option: "blockall".into(),
                avant: "off".into()
            }
            .jamais_remis()
        );
    }
}
