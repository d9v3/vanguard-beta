//! Box et objets connectés : ce que le scan du réseau sait déjà de la box (ce qu'elle annonce d'elle-même, souvent son
//! modèle et la version de son logiciel ; une administration en HTTP seul) et des objets du réseau (caméras,
//! imprimantes, NAS, télés, enceintes, consoles, domotique), reconnus à leur fabricant, à leur nom, à leurs ports
//! ouverts et à ce qu'ils annoncent. Rien n'est sondé en plus et aucun mot de passe n'est essayé (choix de
//! l'utilisateur) : le conseil de changer le mot de passe d'origine vient du type d'appareil, jamais d'une
//! vérification. La fin du suivi d'un appareil n'est pas dite : rien de ce que le scan lit ne la prouve.

use std::net::Ipv4Addr;

use crate::reseau::{PortOuvert, cameras, date_fr};
use crate::risk::Niveau;
use crate::ui::*;

/// Ce que Vanguard sait d'un appareil, par un scan qui vient de finir ou par le carnet du réseau.
pub struct Appareil {
    pub ip: Ipv4Addr,
    pub titre: String,
    /// La box du réseau (la passerelle).
    pub boite: bool,
    pub fabricant: Option<String>,
    pub nom: Option<String>,
    pub tcp: Vec<u16>,
    /// Ce que l'appareil dit de lui-même (SNMP, UPnP, en-tête web), le plus parlant d'abord.
    pub annonces: Vec<String>,
    /// Jour du dernier scan qui l'a vu (carnet seulement).
    pub dernier_vu: Option<String>,
}

/// Le type d'un appareil, dans l'ordre de l'affichage.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Genre {
    Boite,
    Camera,
    Imprimante,
    Nas,
    Diffusion,
    Enceinte,
    Console,
    Domotique,
}

impl Genre {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Genre::Boite => tr!("routeur", "router"),
            Genre::Camera => tr!("caméra", "camera"),
            Genre::Imprimante => tr!("imprimante", "printer"),
            Genre::Nas => tr!("NAS (stockage)", "NAS (storage)"),
            Genre::Diffusion => tr!("télé, diffusion", "TV, streaming"),
            Genre::Enceinte => tr!("enceinte", "speaker"),
            Genre::Console => tr!("console de jeu", "game console"),
            Genre::Domotique => tr!("domotique", "smart home"),
        }
    }

    /// Types d'appareils souvent livrés avec un mot de passe d'origine connu de tous (« admin », celui de la notice).
    pub(crate) fn mot_de_passe_d_origine(self) -> bool {
        matches!(self, Genre::Boite | Genre::Camera | Genre::Imprimante | Genre::Nas)
    }
}

/// Indices d'un type d'appareil, en minuscules : début du nom du fabricant (registre des adresses MAC), mot de ce
/// que l'appareil annonce, mot entier de son nom. Les fabricants qui font aussi des ordinateurs, des téléphones ou
/// des box (HP, Samsung, Sony, Google, Amazon, TP-Link…) n'y sont pas : leur seul nom ne dit rien.
struct Indices {
    genre: Genre,
    fabricants: &'static [&'static str],
    annonces: &'static [&'static str],
    noms: &'static [&'static str],
}

#[rustfmt::skip] // des listes de mots, que rustfmt étalerait sur cent lignes
const INDICES: &[Indices] = &[
    Indices { genre: Genre::Imprimante,
        fabricants: &["seiko epson", "brother industries", "kyocera corporation", "kyocera document", "lexmark",
                      "xerox", "ricoh", "canon inc"],
        annonces: &["printer", "jetdirect", "laserjet", "officejet", "deskjet", "pixma", "epson", "brother", "lexmark",
                    "xerox", "kyocera"],
        noms: &["printer", "imprimante"] },
    Indices { genre: Genre::Nas,
        fabricants: &["synology", "qnap", "asustor", "terramaster"],
        annonces: &["synology", "diskstation", "qnap", "my cloud", "mycloud", "asustor", "readynas", "truenas",
                    "openmediavault"],
        noms: &["nas", "diskstation", "mycloud", "truenas"] },
    Indices { genre: Genre::Diffusion,
        fabricants: &["roku"],
        annonces: &["roku", "chromecast", "bravia", "webos", "tizen", "android tv", "fire tv"],
        noms: &["chromecast", "roku", "tv", "appletv", "firetv", "bravia"] },
    Indices { genre: Genre::Enceinte,
        fabricants: &["sonos,", "sonos inc"],
        annonces: &["sonos"],
        noms: &["sonos"] },
    Indices { genre: Genre::Console,
        fabricants: &["nintendo", "sony interactive", "valve corporation"],
        annonces: &[],
        noms: &["xbox", "playstation", "ps4", "ps5", "steamdeck"] },
    Indices { genre: Genre::Domotique,
        fabricants: &["espressif", "tuya smart", "signify", "philips lighting", "allterco", "ecobee"],
        annonces: &["philips hue", "shelly", "tasmota", "esphome"],
        noms: &["shelly", "tasmota", "esphome", "hue"] },
];

/// Ports d'imprimante : impression directe (9100) et LPD (515), propres aux imprimantes.
const PORTS_IMPRIMANTE: [u16; 2] = [515, 9100];
/// Ports d'un ordinateur (SSH, partage Windows, bureau à distance, VNC, partage du Mac) : son port 631 est le partage
/// d'imprimantes du système, pas une imprimante.
const PORTS_ORDINATEUR: [u16; 7] = [22, 135, 139, 445, 548, 3389, 5900];
/// Une imprimante réseau a une page web (80 ou 443) à côté de son IPP (631) ; un portable Linux qui partage
/// CUPS sans SSH ni Samba n'a que 631 : il n'est pas une imprimante, et ne doit pas recevoir le conseil du mot de
/// passe d'origine.
const PORTS_PAGE_WEB: [u16; 2] = [80, 443];

/// Les mots entiers d'un nom (« Chromecast-Salon.local » → chromecast, salon, local).
fn mots(nom: &str) -> Vec<String> {
    nom.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}

/// Le type d'un appareil, s'il se reconnaît ; `None` : ordinateur, téléphone ou appareil sans indice.
pub fn genre(a: &Appareil) -> Option<Genre> {
    if a.boite {
        return Some(Genre::Boite);
    }
    let fabricant = a.fabricant.as_deref().unwrap_or_default().to_lowercase();
    let annonces: Vec<String> = a.annonces.iter().map(|t| t.to_lowercase()).collect();
    let nom = a.nom.as_deref().map(mots).unwrap_or_default();
    let tcp = |p: &u16| a.tcp.contains(p);
    let camera = a.fabricant.as_deref().and_then(cameras::fabricant_camera).is_some()
        || a.annonces.iter().any(|t| cameras::web_camera(t))
        || cameras::RTSP.iter().chain(&cameras::PORTS_CAMERA).any(tcp);
    if camera {
        return Some(Genre::Camera);
    }
    if PORTS_IMPRIMANTE.iter().any(tcp)
        || (tcp(&631) && PORTS_PAGE_WEB.iter().any(tcp) && !PORTS_ORDINATEUR.iter().any(tcp))
    {
        return Some(Genre::Imprimante);
    }
    // Google Cast (8008 et 8009 ensemble) : Chromecast, télé ou enceinte qui reçoit la diffusion.
    if tcp(&8008) && tcp(&8009) {
        return Some(Genre::Diffusion);
    }
    if tcp(&1400) && fabricant.starts_with("sonos") {
        return Some(Genre::Enceinte);
    }
    INDICES
        .iter()
        .find(|i| {
            i.fabricants.iter().any(|f| fabricant.starts_with(f))
                || annonces.iter().any(|t| i.annonces.iter().any(|m| t.contains(m)))
                || nom.iter().any(|m| i.noms.contains(&m.as_str()))
        })
        .map(|i| i.genre)
}

/// Ce qu'un appareil dit de lui-même dans le scan, le plus parlant d'abord : sa description SNMP, son serveur UPnP
/// (souvent le modèle et la version du logiciel d'une box), puis l'en-tête de ses pages web.
pub fn annonces(ports: &[PortOuvert]) -> Vec<String> {
    let udp = |n: u16| ports.iter().filter(move |p| p.udp && p.port == n);
    let web = ports
        .iter()
        .filter(|p| !p.udp && p.banniere.as_deref().is_some_and(|b| b.starts_with("HTTP · ")));
    let mut liste: Vec<String> = Vec::new();
    for p in udp(161).chain(udp(1900)).chain(web) {
        let texte = p.banniere.as_deref().unwrap_or_default();
        let texte = texte.strip_prefix("HTTP · ").unwrap_or(texte).trim();
        // Sans en-tête Server, le scan garde la ligne d'état (« HTTP/1.0 200 OK ») : elle ne dit rien de l'appareil.
        if !texte.is_empty() && !texte.starts_with("HTTP/") && !liste.iter().any(|t| t == texte) {
            liste.push(texte.to_string());
        }
    }
    liste
}

/// Le scan a trouvé la page d'administration en HTTP (80) et aucun HTTPS (443, ni 8443 où bien des box le
/// mettent) : le mot de passe passe peut-être en clair. « Peut-être » : la liste de ports choisie pour le scan n'a pas
/// forcément cherché le HTTPS, et le texte le dit.
fn admin_en_clair(a: &Appareil) -> bool {
    a.tcp.contains(&80) && !a.tcp.contains(&443) && !a.tcp.contains(&8443)
}

/// La section « Box et objets connectés ». `carnet` : lue dans le carnet du réseau (commande `objets`) et non dans
/// un scan qui vient de finir ; rien ne s'affiche alors en silence. Rend le nombre d'appareils reconnus.
pub fn afficher(appareils: &[Appareil], carnet: bool) -> usize {
    let mut reconnus: Vec<(Genre, &Appareil)> = appareils.iter().filter_map(|a| Some((genre(a)?, a))).collect();
    reconnus.sort_by_key(|(g, a)| (*g, a.ip));
    if reconnus.is_empty() && !carnet {
        return 0;
    }
    // La commande `objets` a déjà ce titre en tête d'écran.
    if !carnet {
        section(tr!("BOX ET OBJETS CONNECTÉS", "ROUTER AND CONNECTED DEVICES"));
    }
    if reconnus.is_empty() {
        afficher_aligne(
            "  ",
            tr!(
                "Aucun objet connecté reconnu (caméra, imprimante, NAS, télé…), ni le routeur.",
                "No connected device recognized (camera, printer, NAS, TV…), nor the router."
            ),
            2,
            GRIS,
        );
        return 0;
    }
    // Le dernier jour de scan : un appareil absent ce jour-là dit quand il a été vu.
    let dernier = appareils.iter().filter_map(|a| a.dernier_vu.as_deref()).max();
    for (g, a) in &reconnus {
        let vu = match (a.dernier_vu.as_deref(), dernier) {
            (Some(d), Some(max)) if d < max => {
                format!("  {DISCRET}{}{RESET}", trf!("vu le {}", "seen on {}", date_fr(d)))
            }
            _ => String::new(),
        };
        let titre = if a.titre.is_empty() {
            tr!("appareil inconnu", "unknown device")
        } else {
            &a.titre
        };
        println!(
            "  {ACCENT}●{RESET} {} {:<15} {}{vu}",
            ajuster(g.nom(), 18),
            a.ip.to_string(),
            ajuster(titre, 30)
        );
        if *g == Genre::Boite {
            if let Some(annonce) = a.annonces.first() {
                afficher_aligne(
                    &format!("      {DISCRET}{}{RESET} ", tr!("se présente :", "describes itself:")),
                    annonce,
                    6,
                    DISCRET,
                );
            }
            if admin_en_clair(a) {
                afficher_aligne(
                    &format!("      {}→{RESET} ", couleur(Niveau::Moyen)),
                    tr!(
                        "Sa page d'administration répond en HTTP et le scan n'a pas trouvé de HTTPS : son mot de passe passe peut-être en clair sur le réseau. Ouvrez-la depuis un câble plutôt que d'un Wi-Fi partagé, et activez HTTPS dans ses réglages s'il existe.",
                        "Its admin page answers over HTTP and the scan found no HTTPS: its password may travel in clear text on the network. Open it over a cable rather than a shared Wi-Fi, and turn on HTTPS in its settings if it exists."
                    ),
                    8,
                    "",
                );
            }
        }
    }
    let a_changer: Vec<Genre> = {
        let mut g: Vec<Genre> = reconnus
            .iter()
            .map(|(g, _)| *g)
            .filter(|g| g.mot_de_passe_d_origine())
            .collect();
        g.dedup();
        g
    };
    if !a_changer.is_empty() {
        println!();
        let liste = a_changer.iter().map(|g| g.nom()).collect::<Vec<_>>().join(", ");
        afficher_aligne(
            &format!("  {}→{RESET} ", couleur(Niveau::Moyen)),
            &trf!(
                "Mot de passe d'origine ({liste}) : ces appareils sortent souvent d'usine avec un mot de passe connu de tous (« admin », celui de la notice). S'il n'a jamais été changé, changez-le dans leur application ou leur page web. Conseil seulement : Vanguard n'en essaie aucun.",
                "Default password ({liste}): these devices often leave the factory with a password everyone knows (“admin”, the one in the manual). If it was never changed, change it in their app or web page. Advice only: Vanguard tries none.",
            ),
            4,
            "",
        );
    }
    reconnus.len()
}

/// Commande `objets` : la section d'après le dernier scan gardé de ce réseau, sans rien sonder.
pub fn montrer() {
    titre(tr!("BOX ET OBJETS CONNECTÉS", "ROUTER AND CONNECTED DEVICES"));
    let Some((nom_reseau, appareils)) = super::carnet_du_reseau() else {
        afficher_aligne(
            "  ",
            tr!(
                "Aucun scan gardé pour ce réseau : lancez d'abord « Scanner le réseau » (vanguard reseau), puis revenez ici.",
                "No scan kept for this network: first run “Scan the network” (vanguard network), then come back here."
            ),
            2,
            "",
        );
        return;
    };
    let quand = appareils
        .iter()
        .filter_map(|a| a.dernier_vu.as_deref())
        .max()
        .map(|d| trf!(" du {}", " of {}", date_fr(d)))
        .unwrap_or_default();
    let reseau = nom_reseau
        .map(|n| trf!(", réseau « {n} »", ", network “{n}”"))
        .unwrap_or_default();
    afficher_aligne(
        "  ",
        &trf!(
            "D'après le dernier scan{quand}{reseau}. Rien n'est sondé ici : pour les nouveautés, refaites un scan.",
            "From the last scan{quand}{reseau}. Nothing is probed here: for anything new, scan again."
        ),
        2,
        GRIS,
    );
    println!();
    afficher(&appareils, true);
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Les ports que le routeur ouvre vers Internet (UPnP) sont dans le scan du réseau, qui les demande au routeur.",
            "The ports the router opens to the Internet (UPnP) are in the network scan, which asks the router for them."
        ),
        2,
        DISCRET,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn appareil(fabricant: Option<&str>, nom: Option<&str>, tcp: &[u16], annonces: &[&str]) -> Appareil {
        Appareil {
            ip: Ipv4Addr::new(192, 168, 1, 20),
            titre: String::new(),
            boite: false,
            fabricant: fabricant.map(str::to_string),
            nom: nom.map(str::to_string),
            tcp: tcp.to_vec(),
            annonces: annonces.iter().map(|t| (*t).to_string()).collect(),
            dernier_vu: None,
        }
    }

    #[test]
    fn types_reconnus() {
        let g = |f, n, t: &[u16], a: &[&str]| genre(&appareil(f, n, t, a));
        assert_eq!(
            g(Some("Hangzhou Hikvision Digital Technology Co.,Ltd."), None, &[80], &[]),
            Some(Genre::Camera)
        );
        assert_eq!(g(None, None, &[554], &[]), Some(Genre::Camera));
        assert_eq!(g(None, None, &[80, 9100], &[]), Some(Genre::Imprimante));
        assert_eq!(
            g(Some("Seiko Epson Corporation"), None, &[80], &[]),
            Some(Genre::Imprimante)
        );
        assert_eq!(g(Some("Synology Incorporated"), None, &[5000], &[]), Some(Genre::Nas));
        assert_eq!(g(None, Some("DiskStation.local"), &[], &[]), Some(Genre::Nas));
        assert_eq!(
            g(Some("Google, Inc."), None, &[8008, 8009], &[]),
            Some(Genre::Diffusion)
        );
        assert_eq!(g(Some("Sonos, Inc."), None, &[1400], &[]), Some(Genre::Enceinte));
        assert_eq!(g(Some("Nintendo Co.,Ltd"), None, &[], &[]), Some(Genre::Console));
        assert_eq!(g(Some("Espressif Inc."), None, &[80], &[]), Some(Genre::Domotique));
        assert_eq!(g(None, Some("shelly-plug.local"), &[80], &[]), Some(Genre::Domotique));
        assert_eq!(
            g(None, None, &[80], &["Linux UPnP/1.0 Sonos/80.1-55014 (ZPS17)"]),
            Some(Genre::Enceinte)
        );
    }

    #[test]
    fn rien_sans_indice_sur() {
        let g = |f, n, t: &[u16]| genre(&appareil(f, n, t, &[]));
        // Un ordinateur qui partage ses imprimantes ouvre 631 : ce n'est pas une imprimante, même sans SSH ni
        // Samba (portable Linux avec CUPS seul). Une imprimante a sa page web à côté.
        assert_eq!(g(None, None, &[22, 631]), None);
        assert_eq!(g(None, None, &[631]), None);
        assert_eq!(g(None, None, &[80, 631]), Some(Genre::Imprimante));
        assert_eq!(g(None, None, &[9100]), Some(Genre::Imprimante));
        assert_eq!(g(Some("Hewlett Packard"), Some("portable-alice"), &[135, 445]), None);
        // Un indice du nom compte en mot entier, pas à l'intérieur d'un autre (« nas » dans « nastassia »).
        assert_eq!(g(None, Some("nastassia-pc"), &[]), None);
        assert_eq!(g(None, Some("atvb"), &[]), None);
        // SonoSite (matériel médical) n'est pas Sonos.
        assert_eq!(g(Some("SonoSite, Inc."), None, &[]), None);
        assert_eq!(g(None, None, &[]), None);
    }

    #[test]
    fn la_box_avant_tout() {
        let mut b = appareil(Some("Sagemcom Broadband SAS"), None, &[80, 554], &[]);
        b.boite = true;
        assert_eq!(genre(&b), Some(Genre::Boite));
        assert!(admin_en_clair(&b));
        // Le HTTPS d'une box est souvent sur 8443 : ce n'est pas « HTTP seulement ».
        b.tcp.push(8443);
        assert!(!admin_en_clair(&b));
        b.tcp.pop();
        b.tcp.push(443);
        assert!(!admin_en_clair(&b));
    }

    #[test]
    fn annonces_le_plus_parlant_d_abord() {
        let port = |port, udp, banniere: &str| PortOuvert {
            port,
            service: "",
            niveau: Niveau::Info,
            banniere: Some(banniere.to_string()),
            conseil: "",
            nouveau: false,
            programme: None,
            udp,
        };
        let ports = [
            port(80, false, "HTTP · lighttpd"),
            port(22, false, "SSH-2.0-dropbear"),
            port(1900, true, "Linux/4.1 UPnP/1.0 Livebox/6 2.10.3"),
            port(8080, false, "HTTP · lighttpd"),
            port(161, true, "Livebox 6 firmware 2.10.3"),
            port(8443, false, "HTTP · HTTP/1.0 200 OK"),
        ];
        assert_eq!(
            annonces(&ports),
            [
                "Livebox 6 firmware 2.10.3",
                "Linux/4.1 UPnP/1.0 Livebox/6 2.10.3",
                "lighttpd"
            ]
        );
    }

    #[test]
    fn seuls_certains_types_ont_un_mot_de_passe_d_origine() {
        assert!(Genre::Camera.mot_de_passe_d_origine() && Genre::Nas.mot_de_passe_d_origine());
        assert!(!Genre::Console.mot_de_passe_d_origine() && !Genre::Diffusion.mot_de_passe_d_origine());
    }
}
