//! Client UPnP IGD (Internet Gateway Device) en Rust pur, le même sur Linux, Windows et macOS : il demande à la box
//! ce qu'elle ouvre vers Internet, sans miniupnpc ni PowerShell. Trois étapes, chacune bornée : une recherche SSDP
//! (deux M-SEARCH en multidiffusion, les réponses lues 1,5 s), la description XML de la box (GET par `http_local`,
//! qui refuse toute adresse hors du réseau local), puis des actions SOAP de lecture seule : `GetExternalIPAddress`,
//! `GetStatusInfo`, et `GetGenericPortMappingEntry` entrée par entrée jusqu'à l'erreur 713 (fin de la liste) ou la
//! borne. Rien d'autre n'est envoyé à la box : aucune ouverture, aucune suppression. Tout ce que la box ou un
//! appareil écrit (nom, modèle, description d'une redirection) est rendu inoffensif avant d'être gardé.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::audit::http_local::{self, Adresse, Reponse};
use crate::ui::affichable;

/// Le groupe de multidiffusion du SSDP.
const GROUPE: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900);
/// Les réponses à une recherche sont lues jusqu'à la fin de ce délai (MX: 1 : une box répond en moins d'une seconde).
const ATTENTE_SSDP: Duration = Duration::from_millis(1500);
/// Délai d'une demande HTTP à la box (description, action SOAP).
const DELAI_HTTP: Duration = Duration::from_secs(5);
/// Toute la lecture tient en ce temps : une box répond en quelques dizaines de millisecondes, ou pas du tout.
const DUREE_MAX: Duration = Duration::from_secs(15);
/// Redirections lues au plus : une box de maison en a quelques-unes ; au-delà, « elle en a peut-être d'autres ».
pub const MAX_REDIRECTIONS: u32 = 200;
/// Box qui répondent à la recherche et dont la description est lue, au plus (deux routeurs, un routeur virtuel…).
const MAX_BOX: usize = 4;
/// Longueur gardée d'un texte écrit par la box ou un appareil.
const TEXTE_MAX: usize = 80;
/// Éléments XML lus au plus : une description de box en a quelques centaines, une réponse SOAP une dizaine.
const ELEMENTS_MAX: usize = 5000;

/// Ce que la box dit d'elle-même (description UPnP et en-tête SERVER du SSDP), prêt à montrer.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Description {
    /// L'adresse de la box sur le réseau local (celle qui sert sa description).
    pub adresse: Option<Ipv4Addr>,
    /// Le nom donné par le fabricant (« friendlyName » : « Freebox Server », « Livebox »…).
    pub nom: Option<String>,
    pub fabricant: Option<String>,
    pub modele: Option<String>,
    /// Numéro de modèle (« modelNumber »), souvent la version du logiciel de la box.
    pub version: Option<String>,
    /// En-tête SERVER du SSDP (« Linux/3.14 UPnP/1.0 MiniUPnPd/2.1 ») : le système et le logiciel UPnP de la box.
    pub serveur: Option<String>,
}

/// Une redirection de la box : port public → appareil du réseau. Adresse et description sont choisies par l'appareil
/// qui l'a demandée : gardées prêtes à montrer.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct Redirection {
    pub protocole: String,
    pub port_public: u16,
    pub appareil: String,
    pub port_appareil: u16,
    pub description: String,
    /// Durée du bail en secondes ; 0 : permanente.
    pub bail: u32,
    /// Seul hôte d'Internet admis ; vide : tout Internet.
    pub hote_distant: String,
    /// Désactivée dans la box : sans effet tant qu'elle le reste.
    pub active: bool,
}

/// Ce qu'une box IGD a répondu.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct Lecture {
    pub description: Description,
    /// L'adresse que la box dit avoir sur Internet.
    pub adresse_externe: Option<Ipv4Addr>,
    /// L'état de la connexion Internet selon la box (« Connected », « Disconnected »…).
    pub connexion: Option<String>,
    pub redirections: Vec<Redirection>,
    /// La box a répondu aux actions SOAP ; sinon ses redirections restent non vérifiées.
    pub lues: bool,
    /// La liste s'est arrêtée avant la fin (borne, refus en cours de route) : la box en a peut-être d'autres.
    pub tronquees: bool,
    /// D'autres appareils du réseau ont répondu comme une box IGD, ailleurs qu'à la passerelle : écartés, et
    /// suspects (un appareil qui se fait passer pour la box masquerait ses redirections, ou en inventerait).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ailleurs: Vec<Ipv4Addr>,
}

/// Le résultat d'une recherche de box.
#[derive(Debug, PartialEq, Eq)]
pub enum Decouverte {
    /// La question n'a pas pu partir (pas de réseau local, socket refusée) : non vérifié.
    NonVerifie,
    /// Aucune box IGD n'a répondu : UPnP coupé ou absent.
    Aucune,
    Trouvee(Box<Lecture>),
    /// La passerelle n'a pas répondu, mais d'autres appareils du réseau se disent box IGD (leurs adresses) : rien
    /// n'est cru d'eux.
    Ailleurs(Vec<Ipv4Addr>),
}

/// Une réponse SSDP à la recherche d'une box : où lire sa description, et ce qu'elle dit de son logiciel.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct ReponseSsdp {
    pub emplacement: String,
    pub serveur: Option<String>,
    /// L'adresse d'où la réponse est venue : celle de la description, sinon la réponse est écartée.
    pub source: Ipv4Addr,
}

/// Le service WAN de la box et l'adresse de son point de contrôle.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Service {
    /// « urn:schemas-upnp-org:service:WANIPConnection:1 » : le type sert d'espace de noms aux actions SOAP.
    pub genre: String,
    pub controle: String,
}

/// Cherche la box IGD du réseau local et lit ce qu'elle ouvre vers Internet. Lecture seule.
pub fn decouvrir() -> Decouverte {
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "maintenant + 15 s : loin de la limite d'Instant"
    )]
    let fin = Instant::now() + DUREE_MAX;
    let Some(reponses) = chercher() else {
        return Decouverte::NonVerifie;
    };
    let (de_la_box, ailleurs) = trier(reponses, crate::reseau::scan::passerelle());
    // Plusieurs réponses de la passerelle (deux versions de l'IGD) : la première dont les redirections se lisent ;
    // sinon la première, non vérifiée.
    let mut premiere = None;
    for r in de_la_box.iter().take(MAX_BOX) {
        let mut lecture = lire_box(r, fin);
        lecture.ailleurs.clone_from(&ailleurs);
        if lecture.lues {
            return Decouverte::Trouvee(Box::new(lecture));
        }
        premiere.get_or_insert(lecture);
    }
    match premiere {
        Some(l) => Decouverte::Trouvee(Box::new(l)),
        None if !ailleurs.is_empty() => Decouverte::Ailleurs(ailleurs),
        None => Decouverte::Aucune,
    }
}

/// Les réponses de la passerelle par défaut, et les adresses des autres appareils qui se disent box. N'importe quel
/// appareil du réseau entend la question et peut répondre avant la box (elle attend jusqu'à une seconde) : le
/// premier qui répondait était cru, et ses « 0 redirection » passaient pour une lecture vérifiée de la box. Sans
/// passerelle connue (route illisible), toutes sont gardées, comme avant : rien de mieux à quoi les comparer.
fn trier(reponses: Vec<ReponseSsdp>, passerelle: Option<Ipv4Addr>) -> (Vec<ReponseSsdp>, Vec<Ipv4Addr>) {
    let Some(passerelle) = passerelle else {
        return (reponses, Vec::new());
    };
    let (de_la_box, autres): (Vec<_>, Vec<_>) = reponses.into_iter().partition(|r| r.source == passerelle);
    let mut ailleurs: Vec<Ipv4Addr> = autres.into_iter().map(|r| r.source).collect();
    ailleurs.sort_unstable();
    ailleurs.dedup();
    (de_la_box, ailleurs)
}

/// La recherche SSDP : un M-SEARCH par version de l'IGD, les réponses lues jusqu'à la fin du délai, sans doublon.
/// `None` : la question n'a pas pu partir.
fn chercher() -> Option<Vec<ReponseSsdp>> {
    // Liée à l'adresse du réseau local quand elle est connue : la question part par cette interface (Linux et
    // Windows choisissent l'interface de l'adresse liée pour la multidiffusion), et non par un VPN ou un pont
    // virtuel qui tiendrait la route par défaut.
    let locale = crate::reseau::scan::reseau_local().map_or(Ipv4Addr::UNSPECIFIED, |(_, ip)| ip);
    let socket = UdpSocket::bind(SocketAddrV4::new(locale, 0))
        .or_else(|_| UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        .ok()?;
    // Une seule traversée de routeur : la question reste sur le réseau local.
    let _ = socket.set_multicast_ttl_v4(1);
    let mut reponses: Vec<ReponseSsdp> = Vec::new();
    let mut tampon = vec![0u8; 4096];
    for version in ["1", "2"] {
        let question = m_search(&format!("urn:schemas-upnp-org:device:InternetGatewayDevice:{version}"));
        if socket.send_to(question.as_bytes(), GROUPE).is_err() {
            // Rien n'est parti (pas de route vers le réseau local) : rien à conclure, sauf ce qui a déjà répondu.
            if reponses.is_empty() {
                return None;
            }
            break;
        }
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "maintenant + 1,5 s : loin de la limite d'Instant"
        )]
        let fin = Instant::now() + ATTENTE_SSDP;
        crate::reseau::nat::recevoir(&socket, fin, &mut tampon, |reponse, de| {
            if let std::net::IpAddr::V4(source) = de.ip()
                && let Some(r) = lire_reponse_ssdp(&String::from_utf8_lossy(reponse), source)
                && !reponses.iter().any(|v| v.emplacement == r.emplacement)
                && reponses.len() < 16
            {
                reponses.push(r);
            }
            None::<()>
        });
    }
    Some(reponses)
}

/// Le message M-SEARCH : « cherche les appareils de ce type, réponds dans la seconde ».
fn m_search(st: &str) -> String {
    format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n")
}

/// Une réponse SSDP (« HTTP/1.1 200 OK » et ses en-têtes) d'une box IGD venue de `source` : son LOCATION, qui doit
/// être une adresse du réseau local sur l'appareil même qui a répondu (jamais un autre, ni cette machine), et son
/// SERVER. Les réponses d'autres appareils (une télé, une imprimante répondent parfois à tout) sont écartées à leur ST.
pub(crate) fn lire_reponse_ssdp(texte: &str, source: Ipv4Addr) -> Option<ReponseSsdp> {
    let mut lignes = texte.lines();
    if !lignes.next()?.trim().to_ascii_uppercase().starts_with("HTTP/1.1 200") {
        return None;
    }
    let mut emplacement = None;
    let mut serveur = None;
    let mut igd = false;
    for l in lignes {
        let Some((cle, valeur)) = l.split_once(':') else {
            continue;
        };
        let valeur = valeur.trim();
        match cle.trim().to_ascii_lowercase().as_str() {
            "location" => emplacement = Some(valeur.to_string()),
            "server" => serveur = Some(texte_de_box(valeur)),
            "st" | "nt" => {
                igd = ["InternetGatewayDevice", "WANIPConnection", "WANPPPConnection"]
                    .iter()
                    .any(|s| valeur.contains(s));
            }
            _ => {}
        }
    }
    let emplacement = emplacement?;
    (igd && Adresse::lire(&emplacement).is_some_and(|a| a.ip == source)).then_some(ReponseSsdp {
        emplacement,
        serveur,
        source,
    })
}

/// Un texte écrit par la box ou un appareil, prêt à montrer : inoffensif et court.
fn texte_de_box(t: &str) -> String {
    affichable(t.trim()).chars().take(TEXTE_MAX).collect()
}

/// Lit la description d'une box, puis ses redirections par SOAP. La lecture reste non vérifiée (`lues` faux) dès
/// que la box ne répond pas : description illisible, aucun service WAN, SOAP refusé.
fn lire_box(ssdp: &ReponseSsdp, fin: Instant) -> Lecture {
    let mut lecture = Lecture {
        description: Description {
            adresse: Adresse::lire(&ssdp.emplacement).map(|a| a.ip),
            serveur: ssdp.serveur.clone(),
            ..Description::default()
        },
        adresse_externe: None,
        connexion: None,
        redirections: Vec::new(),
        lues: false,
        tronquees: false,
        ailleurs: Vec::new(),
    };
    let Some(base) = Adresse::lire(&ssdp.emplacement) else {
        return lecture;
    };
    let Some(reponse) = http_local::demander("GET", &ssdp.emplacement, &[], None, delai(fin)) else {
        return lecture;
    };
    if reponse.code != 200 {
        return lecture;
    }
    let (description, service) = lire_description(&reponse.texte(), &base);
    lecture.description = Description {
        serveur: ssdp.serveur.clone(),
        ..description
    };
    let Some(service) = service else {
        return lecture;
    };
    if let Some(r) = soap(&service, "GetExternalIPAddress", &[], fin) {
        lecture.adresse_externe = valeur(&r.texte(), "NewExternalIPAddress")
            .and_then(|v| v.parse().ok())
            .filter(|ip: &Ipv4Addr| !ip.is_unspecified());
    }
    if let Some(r) = soap(&service, "GetStatusInfo", &[], fin) {
        lecture.connexion = valeur(&r.texte(), "NewConnectionStatus").map(|v| texte_de_box(&v));
    }
    let (redirections, lues, tronquees) = lire_redirections(|i| {
        soap(
            &service,
            "GetGenericPortMappingEntry",
            &[("NewPortMappingIndex", &i.to_string())],
            fin,
        )
    });
    lecture.redirections = redirections;
    lecture.lues = lues;
    lecture.tronquees = tronquees;
    lecture
}

/// L'instant limite d'une demande HTTP : son délai, sans dépasser la fin de toute la lecture.
#[expect(
    clippy::arithmetic_side_effects,
    reason = "maintenant + 5 s : loin de la limite d'Instant"
)]
fn delai(fin: Instant) -> Instant {
    fin.min(Instant::now() + DELAI_HTTP)
}

/// Un élément XML, à plat.
#[derive(Debug, PartialEq, Eq)]
enum Noeud {
    Debut(String),
    Texte(String),
    Fin(String),
}

/// Les éléments d'un XML, à plat : début (nom local, sans préfixe d'espace de noms), texte (entités courantes
/// remplacées), fin. XML malformé : ce qui précède l'erreur. Borné : le XML vient de la box.
fn noeuds(xml: &str) -> Vec<Noeud> {
    use quick_xml::events::Event;
    let mut lecteur = quick_xml::Reader::from_str(xml);
    let mut noeuds = Vec::new();
    let mut texte = String::new();
    let mut elements = 0usize;
    while let Ok(evenement) = lecteur.read_event() {
        match evenement {
            Event::Eof => break,
            Event::Start(e) => {
                elements = elements.saturating_add(1);
                if elements > ELEMENTS_MAX {
                    break;
                }
                noeuds.push(Noeud::Debut(e.local_name().as_ref().to_string()));
                texte.clear();
            }
            Event::Empty(e) => {
                elements = elements.saturating_add(1);
                if elements > ELEMENTS_MAX {
                    break;
                }
                let nom = e.local_name().as_ref().to_string();
                noeuds.push(Noeud::Debut(nom.clone()));
                noeuds.push(Noeud::Fin(nom));
                texte.clear();
            }
            Event::End(e) => {
                if !texte.trim().is_empty() {
                    noeuds.push(Noeud::Texte(std::mem::take(&mut texte)));
                }
                texte.clear();
                noeuds.push(Noeud::Fin(e.local_name().as_ref().to_string()));
            }
            Event::Text(t) => texte.push_str(&t.xml10_content()),
            Event::CData(t) => texte.push_str(&t.into_inner()),
            Event::GeneralRef(r) => texte.push(match r.as_ref() {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                autre => caractere(autre).unwrap_or('\u{fffd}'),
            }),
            _ => {}
        }
    }
    noeuds
}

/// Une référence de caractère (« #x27 », « #39 »).
fn caractere(reference: &str) -> Option<char> {
    let code = match reference.strip_prefix("#x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => reference.strip_prefix('#')?.parse().ok()?,
    };
    char::from_u32(code)
}

/// Le texte du premier élément de ce nom (« <NewExternalIPAddress>203.0.113.7</NewExternalIPAddress> »).
pub(crate) fn valeur(xml: &str, nom: &str) -> Option<String> {
    valeur_parmi(&noeuds(xml), nom)
}

fn valeur_parmi(noeuds: &[Noeud], nom: &str) -> Option<String> {
    noeuds.windows(2).find_map(|w| match w {
        [Noeud::Debut(n), Noeud::Texte(t)] if n == nom => Some(t.trim().to_string()),
        _ => None,
    })
}

/// La description XML de la box : ce qu'elle dit d'elle-même (les champs du premier appareil, la racine), et son
/// service WAN (WANIPConnection de préférence, sinon WANPPPConnection) avec l'adresse de son point de contrôle,
/// résolue par rapport à `URLBase` (UPnP 1.0) ou à l'adresse de la description.
pub(crate) fn lire_description(xml: &str, base: &Adresse) -> (Description, Option<Service>) {
    let noeuds = noeuds(xml);
    let champ = |nom: &str| {
        valeur_parmi(&noeuds, nom)
            .map(|v| texte_de_box(&v))
            .filter(|v| !v.is_empty())
    };
    let description = Description {
        adresse: Some(base.ip),
        nom: champ("friendlyName"),
        fabricant: champ("manufacturer"),
        modele: champ("modelName"),
        version: champ("modelNumber"),
        serveur: None,
    };
    // URLBase et points de contrôle : chez l'appareil même de la description, jamais un autre (un tiers du réseau,
    // que Vanguard aurait sinon interrogé pour le compte de qui a répondu).
    let url_base = valeur_parmi(&noeuds, "URLBase")
        .and_then(|u| Adresse::lire(&u))
        .filter(|u| u.ip == base.ip)
        .unwrap_or_else(|| base.clone());
    // Les services, dans l'ordre : le type et le point de contrôle de chaque <service>.
    let mut services: Vec<(String, String)> = Vec::new();
    let mut en_cours: Option<(Option<String>, Option<String>)> = None;
    for (i, noeud) in noeuds.iter().enumerate() {
        match noeud {
            Noeud::Debut(n) if n == "service" => en_cours = Some((None, None)),
            Noeud::Fin(n) if n == "service" => {
                if let Some((Some(genre), Some(controle))) = en_cours.take() {
                    services.push((genre, controle));
                }
            }
            Noeud::Debut(n) => {
                if let (Some(champs), Some(Noeud::Texte(t))) =
                    (&mut en_cours, i.checked_add(1).and_then(|j| noeuds.get(j)))
                {
                    match n.as_str() {
                        "serviceType" => champs.0 = Some(t.trim().to_string()),
                        "controlURL" => champs.1 = Some(t.trim().to_string()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    // Le type du service devient un en-tête et un espace de noms de nos demandes : seulement les caractères
    // attendus d'un « urn:schemas-upnp-org:service:WANIPConnection:1 ».
    let propre = |g: &str| g.chars().all(|c| c.is_ascii_alphanumeric() || ":-._".contains(c));
    let service = ["WANIPConnection", "WANPPPConnection"]
        .iter()
        .find_map(|voulu| {
            services
                .iter()
                .find(|(g, c)| g.contains(voulu) && propre(g) && url_base.meme_hote(c))
        })
        .map(|(genre, controle)| Service {
            genre: genre.clone(),
            controle: url_base.resoudre(controle),
        });
    (description, service)
}

/// L'enveloppe SOAP d'une action UPnP : l'espace de noms est le type du service ; les arguments sont des nombres à
/// nous, jamais un texte venu d'ailleurs.
pub(crate) fn enveloppe(genre: &str, action: &str, arguments: &[(&str, &str)]) -> String {
    let arguments = arguments.iter().fold(String::new(), |mut s, (n, v)| {
        use std::fmt::Write as _;
        let _ = write!(s, "<{n}>{v}</{n}>");
        s
    });
    format!(
        "<?xml version=\"1.0\"?>\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body><u:{action} xmlns:u=\"{genre}\">{arguments}</u:{action}></s:Body></s:Envelope>"
    )
}

/// Une action SOAP vers le point de contrôle de la box. Une réponse, même en erreur (500 avec le code UPnP), prouve
/// que la box écoute ; `None` : pas de réponse.
fn soap(service: &Service, action: &str, arguments: &[(&str, &str)], fin: Instant) -> Option<Reponse> {
    let corps = enveloppe(&service.genre, action, arguments);
    let action_soap = format!("\"{}#{action}\"", service.genre);
    http_local::demander(
        "POST",
        &service.controle,
        &[
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPAction", &action_soap),
        ],
        Some(corps.as_bytes()),
        delai(fin),
    )
}

/// Le code d'une erreur UPnP dans une réponse SOAP (« <errorCode>713</errorCode> »).
pub(crate) fn erreur_soap(xml: &str) -> Option<u32> {
    valeur(xml, "errorCode")?.parse().ok()
}

/// Une redirection dans la réponse à GetGenericPortMappingEntry. `None` : il manque les champs qui la définissent
/// (réponse d'erreur, XML malformé).
pub(crate) fn redirection(xml: &str) -> Option<Redirection> {
    let noeuds = noeuds(xml);
    let champ = |nom: &str| valeur_parmi(&noeuds, nom).unwrap_or_default();
    let port_public = champ("NewExternalPort").parse().ok()?;
    let port_appareil = champ("NewInternalPort").parse().ok()?;
    let appareil = texte_de_box(&champ("NewInternalClient"));
    if appareil.is_empty() {
        return None;
    }
    Some(Redirection {
        protocole: texte_de_box(&champ("NewProtocol")).to_ascii_uppercase(),
        port_public,
        appareil,
        port_appareil,
        description: texte_de_box(&champ("NewPortMappingDescription")),
        bail: champ("NewLeaseDuration").parse().unwrap_or(0),
        hote_distant: texte_de_box(&champ("NewRemoteHost")),
        active: champ("NewEnabled") != "0",
    })
}

/// Les redirections, entrée par entrée, jusqu'à la fin de la liste (erreur 713), un refus ou la borne. Rend
/// (redirections, la box a répondu, liste incomplète). Un refus ou une réponse illisible dès la première entrée
/// laisse la lecture non vérifiée ; en cours de route, la liste est dite incomplète.
pub(crate) fn lire_redirections(mut demander: impl FnMut(u32) -> Option<Reponse>) -> (Vec<Redirection>, bool, bool) {
    let mut liste = Vec::new();
    for i in 0..MAX_REDIRECTIONS {
        let Some(reponse) = demander(i) else {
            let lues = !liste.is_empty();
            return (liste, lues, lues);
        };
        if reponse.code != 200 {
            if erreur_soap(&reponse.texte()) == Some(713) {
                return (liste, true, false);
            }
            let lues = !liste.is_empty();
            return (liste, lues, lues);
        }
        let Some(r) = redirection(&reponse.texte()) else {
            let lues = !liste.is_empty();
            return (liste, lues, lues);
        };
        liste.push(r);
    }
    (liste, true, true)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// La description d'une box de salon, à la forme de celles de MiniUPnPd : la racine, puis les appareils WAN
    /// emboîtés, le service WANIPConnection au fond.
    const DESCRIPTION: &str = "<?xml version=\"1.0\"?>\
        <root xmlns=\"urn:schemas-upnp-org:device-1-0\"><specVersion><major>1</major><minor>0</minor></specVersion>\
        <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>\
        <friendlyName>Box du salon</friendlyName><manufacturer>Sagemcom</manufacturer>\
        <modelName>F@st 5566 &amp; co</modelName><modelNumber>1.2.3</modelNumber><serialNumber>ABC123</serialNumber>\
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
        <controlURL>/ctl/L3F</controlURL></service></serviceList>\
        <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
        <friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer>\
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>\
        <controlURL>/ctl/CmnIfCfg</controlURL></service></serviceList>\
        <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
        <friendlyName>WANConnectionDevice</friendlyName>\
        <serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL>\
        <controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList>\
        </device></deviceList></device></deviceList><presentationURL>http://10.0.0.1/</presentationURL>\
        </device></root>";

    fn reponse_soap(action: &str, champs: &str) -> String {
        format!(
            "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
             <u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{champs}\
             </u:{action}Response></s:Body></s:Envelope>"
        )
    }

    fn entree(index: u32) -> String {
        let (proto, public, ip, port, description) = match index {
            0 => ("TCP", 8080, "10.0.0.30", 80, "Camera\x1b]52;c;eA==\x07 salon"),
            _ => ("UDP", 3074, "10.0.0.20", 3074, "Xbox SRA"),
        };
        reponse_soap(
            "GetGenericPortMappingEntry",
            &format!(
                "<NewRemoteHost></NewRemoteHost><NewExternalPort>{public}</NewExternalPort>\
                 <NewProtocol>{proto}</NewProtocol><NewInternalPort>{port}</NewInternalPort>\
                 <NewInternalClient>{ip}</NewInternalClient><NewEnabled>1</NewEnabled>\
                 <NewPortMappingDescription>{description}</NewPortMappingDescription>\
                 <NewLeaseDuration>3600</NewLeaseDuration>"
            ),
        )
    }

    const ERREUR_713: &str = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
        <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
        <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>713</errorCode>\
        <errorDescription>SpecifiedArrayIndexInvalid</errorDescription></UPnPError></detail></s:Fault></s:Body>\
        </s:Envelope>";

    fn http(code: u16, corps: &str) -> String {
        format!(
            "HTTP/1.1 {code} Reponse\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{corps}",
            corps.len()
        )
    }

    fn reponse_ok(corps: &str) -> Reponse {
        Reponse {
            code: 200,
            corps: corps.as_bytes().to_vec(),
        }
    }

    /// Un faux serveur HTTP sur cet ordinateur (127.0.0.1), comme le faux flux RTSP des caméras : il répond à chaque
    /// connexion d'après la demande reçue, puis rend les demandes. Rien ne sort sur le réseau.
    fn faux_serveur(repondre: impl Fn(&str) -> String + Send + 'static) -> (u16, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        ecoute.set_nonblocking(true).unwrap();
        let fil = std::thread::spawn(move || {
            let mut demandes = Vec::new();
            let fin = Instant::now() + Duration::from_secs(20);
            // Plus de client pendant une seconde après la dernière demande : la lecture est finie.
            let mut calme = Instant::now() + Duration::from_secs(1);
            while Instant::now() < fin && Instant::now() < calme {
                let Ok((mut c, _)) = ecoute.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                c.set_nonblocking(false).unwrap();
                c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut brut = Vec::new();
                let mut tampon = [0u8; 4096];
                // La demande entière : les en-têtes, puis le corps de la longueur annoncée.
                while let Ok(n @ 1..) = c.read(&mut tampon) {
                    brut.extend_from_slice(&tampon[..n]);
                    let texte = String::from_utf8_lossy(&brut);
                    if let Some((entetes, corps)) = texte.split_once("\r\n\r\n") {
                        let annoncee = entetes
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")?
                                    .trim()
                                    .parse()
                                    .ok()
                            })
                            .unwrap_or(0usize);
                        if corps.len() >= annoncee {
                            break;
                        }
                    }
                }
                let demande = String::from_utf8_lossy(&brut).into_owned();
                let _ = c.write_all(repondre(&demande).as_bytes());
                demandes.push(demande);
                calme = Instant::now() + Duration::from_secs(1);
            }
            demandes
        });
        (port, fil)
    }

    fn entre<'a>(texte: &'a str, debut: &str, fin: &str) -> &'a str {
        texte
            .split_once(debut)
            .and_then(|(_, r)| r.split_once(fin))
            .map_or("", |(v, _)| v)
    }

    /// La vraie lecture, contre une fausse box sur cet ordinateur : la description, puis les actions SOAP, chacune
    /// dans sa connexion, jusqu'à l'erreur 713 qui finit la liste.
    #[test]
    fn lecture_d_une_fausse_box() {
        let (port, serveur) = faux_serveur(|demande| {
            if demande.starts_with("GET /desc.xml ") {
                return http(200, DESCRIPTION);
            }
            if demande.contains("#GetExternalIPAddress\"") {
                return http(
                    200,
                    &reponse_soap(
                        "GetExternalIPAddress",
                        "<NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>",
                    ),
                );
            }
            if demande.contains("#GetStatusInfo\"") {
                return http(
                    200,
                    &reponse_soap(
                        "GetStatusInfo",
                        "<NewConnectionStatus>Connected</NewConnectionStatus>\
                         <NewLastConnectionError>ERROR_NONE</NewLastConnectionError><NewUptime>86400</NewUptime>",
                    ),
                );
            }
            if demande.contains("#GetGenericPortMappingEntry\"") {
                return match entre(demande, "<NewPortMappingIndex>", "</NewPortMappingIndex>") {
                    "0" => http(200, &entree(0)),
                    "1" => http(200, &entree(1)),
                    _ => http(500, ERREUR_713),
                };
            }
            http(404, "")
        });
        let ssdp = ReponseSsdp {
            emplacement: format!("http://127.0.0.1:{port}/desc.xml"),
            serveur: Some("Linux/5.4 UPnP/1.1 MiniUPnPd/2.2".into()),
            source: Ipv4Addr::LOCALHOST,
        };
        let lecture = lire_box(&ssdp, Instant::now() + Duration::from_secs(10));
        assert_eq!(
            lecture.description,
            Description {
                adresse: Some(Ipv4Addr::LOCALHOST),
                nom: Some("Box du salon".into()),
                fabricant: Some("Sagemcom".into()),
                modele: Some("F@st 5566 & co".into()),
                version: Some("1.2.3".into()),
                serveur: Some("Linux/5.4 UPnP/1.1 MiniUPnPd/2.2".into()),
            }
        );
        assert_eq!(lecture.adresse_externe, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(lecture.connexion.as_deref(), Some("Connected"));
        assert!(lecture.lues && !lecture.tronquees);
        assert_eq!(lecture.redirections.len(), 2);
        assert_eq!(
            lecture.redirections[0],
            Redirection {
                protocole: "TCP".into(),
                port_public: 8080,
                appareil: "10.0.0.30".into(),
                port_appareil: 80,
                // La description, choisie par l'appareil qui a demandé l'ouverture, arrive inoffensive.
                description: "Camera�]52;c;eA==� salon".into(),
                bail: 3600,
                hote_distant: String::new(),
                active: true,
            }
        );
        assert_eq!(
            (
                lecture.redirections[1].port_public,
                lecture.redirections[1].description.as_str()
            ),
            (3074, "Xbox SRA")
        );
        let demandes = serveur.join().unwrap();
        assert_eq!(demandes.len(), 6, "{demandes:#?}");
        assert!(demandes[0].starts_with(&format!("GET /desc.xml HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n")));
        assert!(
            demandes[1].starts_with("POST /ctl/IPConn HTTP/1.1\r\n"),
            "{}",
            demandes[1]
        );
        assert!(
            demandes[1].contains(
                "\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\n"
            )
        );
        assert!(demandes[1].contains(
            "<u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:GetExternalIPAddress>"
        ));
        assert!(demandes[3].contains("<NewPortMappingIndex>0</NewPortMappingIndex>"));
        assert!(demandes[5].contains("<NewPortMappingIndex>2</NewPortMappingIndex>"));
    }

    /// Une box qui se décrit mais sans service WAN, ou dont la description est illisible : rien n'est vérifié, et
    /// aucune action SOAP n'est tentée.
    #[test]
    fn box_sans_service_ou_illisible() {
        for (corps, nom) in [
            (
                "<root><device><friendlyName>Routeur sans WAN</friendlyName><serviceList><service>\
                 <serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
                 <controlURL>/ctl/L3F</controlURL></service></serviceList></device></root>",
                Some("Routeur sans WAN"),
            ),
            (
                "<root><device><friendlyName>Cassee</friendlyName><servi",
                Some("Cassee"),
            ),
            ("pas du xml du tout", None),
        ] {
            let (port, serveur) = faux_serveur(move |_| http(200, corps));
            let ssdp = ReponseSsdp {
                emplacement: format!("http://127.0.0.1:{port}/desc.xml"),
                serveur: None,
                source: Ipv4Addr::LOCALHOST,
            };
            let lecture = lire_box(&ssdp, Instant::now() + Duration::from_secs(10));
            assert!(!lecture.lues && lecture.redirections.is_empty());
            assert_eq!(lecture.description.nom.as_deref(), nom);
            assert_eq!(serveur.join().unwrap().len(), 1);
        }
        // Personne n'écoute : non vérifié, sans attendre.
        let libre = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = libre.local_addr().unwrap().port();
        drop(libre);
        let ssdp = ReponseSsdp {
            emplacement: format!("http://127.0.0.1:{port}/desc.xml"),
            serveur: None,
            source: Ipv4Addr::LOCALHOST,
        };
        let debut = Instant::now();
        assert!(!lire_box(&ssdp, Instant::now() + Duration::from_secs(10)).lues);
        assert!(debut.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn description_lue() {
        let base = Adresse::lire("http://10.0.0.1:5000/rootDesc.xml").unwrap();
        let (d, s) = lire_description(DESCRIPTION, &base);
        assert_eq!(d.nom.as_deref(), Some("Box du salon"));
        assert_eq!(d.fabricant.as_deref(), Some("Sagemcom"));
        assert_eq!(d.modele.as_deref(), Some("F@st 5566 & co"));
        assert_eq!(d.version.as_deref(), Some("1.2.3"));
        assert_eq!(d.adresse, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            s,
            Some(Service {
                genre: "urn:schemas-upnp-org:service:WANIPConnection:1".into(),
                controle: "http://10.0.0.1:5000/ctl/IPConn".into(),
            })
        );
        // URLBase (UPnP 1.0) et point de contrôle relatif ; WANPPPConnection faute de WANIPConnection ; un type de
        // service piégé (il deviendrait un en-tête) est écarté.
        let xml = "<root><URLBase>http://10.0.0.1:49152/upnp/</URLBase><device><friendlyName>Livebox</friendlyName>\
                   <serviceList><service><serviceType>urn:x:WANPPPConnection:1\r\nX: y</serviceType>\
                   <controlURL>ctl</controlURL></service><service>\
                   <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>\
                   <controlURL>control/WANPPPConnection</controlURL></service></serviceList></device></root>";
        let (d, s) = lire_description(xml, &base);
        assert_eq!(d.nom.as_deref(), Some("Livebox"));
        assert_eq!(
            s.unwrap().controle,
            "http://10.0.0.1:49152/upnp/control/WANPPPConnection"
        );
        // Un URLBase qui mènerait hors du réseau local est ignoré.
        let xml = "<root><URLBase>http://203.0.113.9/</URLBase><device><serviceList><service>\
                   <serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>\
                   <controlURL>/ctl</controlURL></service></serviceList></device></root>";
        assert_eq!(
            lire_description(xml, &base).1.unwrap().controle,
            "http://10.0.0.1:5000/ctl"
        );
        // Malformé : pas de service, pas de panique.
        assert_eq!(lire_description("<root><device><friendlyName>Box</frie", &base).1, None);
        assert_eq!(lire_description("", &base).1, None);
    }

    const BOX: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    /// Un appareil du réseau répond à la recherche avant la box : seule la passerelle est crue, les autres sont
    /// écartés et dits ; sans passerelle connue, rien de mieux qu'avant.
    #[test]
    fn seule_la_passerelle_est_la_box() {
        let reponse = |ip: [u8; 4]| ReponseSsdp {
            emplacement: format!("http://{}:5000/d.xml", Ipv4Addr::from(ip)),
            serveur: None,
            source: Ipv4Addr::from(ip),
        };
        let reponses = vec![reponse([10, 0, 0, 66]), reponse([10, 0, 0, 1]), reponse([10, 0, 0, 66])];
        let (box_, ailleurs) = trier(reponses.clone(), Some(BOX));
        assert_eq!(box_, vec![reponse([10, 0, 0, 1])]);
        assert_eq!(ailleurs, vec![Ipv4Addr::new(10, 0, 0, 66)]);
        let (box_, ailleurs) = trier(vec![reponse([10, 0, 0, 66])], Some(BOX));
        assert!(box_.is_empty() && ailleurs == [Ipv4Addr::new(10, 0, 0, 66)]);
        let (box_, ailleurs) = trier(reponses, None);
        assert_eq!((box_.len(), ailleurs.len()), (3, 0));
        // Un URLBase ou un point de contrôle chez un autre appareil du réseau : pas suivi.
        let base = Adresse::lire("http://10.0.0.1:5000/rootDesc.xml").unwrap();
        let service = |controle: &str| {
            format!(
                "<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1\
                 </serviceType><controlURL>{controle}</controlURL></service></serviceList></device></root>"
            )
        };
        assert!(lire_description(&service("http://10.0.0.20/ctl"), &base).1.is_none());
        assert!(
            lire_description(&service("http://127.0.0.1:8080/ctl"), &base)
                .1
                .is_none()
        );
        assert_eq!(
            lire_description(&service("/ctl"), &base).1.map(|s| s.controle),
            Some("http://10.0.0.1:5000/ctl".to_string())
        );
        let ailleurs = format!("<root><URLBase>http://10.0.0.20/</URLBase>{}", &service("ctl")[6..]);
        assert_eq!(
            lire_description(&ailleurs, &base).1.map(|s| s.controle),
            Some("http://10.0.0.1:5000/ctl".to_string())
        );
    }

    #[test]
    fn reponses_ssdp() {
        let r = lire_reponse_ssdp(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
             USN: uuid:1234::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\n\
             SERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\x1b[2K\r\nLocation: http://10.0.0.1:5000/rootDesc.xml\r\n\r\n",
            BOX,
        )
        .unwrap();
        assert_eq!(r.emplacement, "http://10.0.0.1:5000/rootDesc.xml");
        assert_eq!(r.serveur.as_deref(), Some("Linux/3.14 UPnP/1.0 MiniUPnPd/2.1�[2K"));
        // Une télé qui répond à tout, une box qui renvoie vers Internet, une recherche (pas une réponse) : écartées.
        for texte in [
            "HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\nLOCATION: http://10.0.0.5:8008/x\r\n\r\n",
            "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nLOCATION: http://203.0.113.1/d\r\n\r\n",
            "M-SEARCH * HTTP/1.1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
            "",
        ] {
            assert_eq!(lire_reponse_ssdp(texte, BOX), None, "{texte}");
        }
        // Un appareil du réseau qui envoie vers un autre (la box, ou cette machine) : écarté.
        let vers = |l: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: {l}\r\n\r\n"
            )
        };
        let piege = Ipv4Addr::new(10, 0, 0, 66);
        assert!(lire_reponse_ssdp(&vers("http://10.0.0.1:5000/rootDesc.xml"), piege).is_none());
        assert!(lire_reponse_ssdp(&vers("http://10.0.0.66:5000/d.xml"), piege).is_some());
        assert!(
            m_search("urn:schemas-upnp-org:device:InternetGatewayDevice:2")
                .ends_with("\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n")
        );
    }

    #[test]
    fn soap_lu_et_ecrit() {
        let e = enveloppe(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "GetGenericPortMappingEntry",
            &[("NewPortMappingIndex", "7")],
        );
        assert!(e.starts_with("<?xml version=\"1.0\"?><s:Envelope "));
        assert!(e.contains(
            "<u:GetGenericPortMappingEntry xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">\
             <NewPortMappingIndex>7</NewPortMappingIndex></u:GetGenericPortMappingEntry>"
        ));
        assert_eq!(erreur_soap(ERREUR_713), Some(713));
        assert_eq!(erreur_soap(&entree(0)), None);
        assert_eq!(
            valeur(
                &reponse_soap(
                    "GetExternalIPAddress",
                    "<NewExternalIPAddress> 100.64.12.34 </NewExternalIPAddress>"
                ),
                "NewExternalIPAddress"
            )
            .as_deref(),
            Some("100.64.12.34")
        );
        // Entités et références de caractères, texte en CDATA.
        assert_eq!(
            valeur("<a><b>x &amp; y &#x27;z&#39; <![CDATA[<c>]]></b></a>", "b").as_deref(),
            Some("x & y 'z' <c>")
        );
        assert_eq!(valeur("<a><b></b><c>v</c></a>", "b"), None);
        assert_eq!(valeur("<a><b>jamais fermé", "b"), None);
        let r = redirection(&entree(1)).unwrap();
        assert_eq!(
            (r.protocole.as_str(), r.port_public, r.appareil.as_str()),
            ("UDP", 3074, "10.0.0.20")
        );
        assert_eq!((r.port_appareil, r.bail, r.active), (3074, 3600, true));
        // Sans appareil ni port : pas une redirection.
        assert_eq!(redirection("<a><NewExternalPort>1</NewExternalPort></a>"), None);
        assert_eq!(redirection(ERREUR_713), None);
        let desactivee = entree(1).replace("<NewEnabled>1</NewEnabled>", "<NewEnabled>0</NewEnabled>");
        assert!(!redirection(&desactivee).unwrap().active);
    }

    /// La liste s'arrête à l'erreur 713, à un refus, à une réponse illisible ou à la borne : une box qui prétend en
    /// avoir dix mille n'est interrogée que `MAX_REDIRECTIONS` fois.
    #[test]
    fn fin_de_liste_et_borne() {
        let (liste, lues, tronquees) = lire_redirections(|i| match i {
            0 | 1 => Some(reponse_ok(&entree(i))),
            _ => Some(Reponse {
                code: 500,
                corps: ERREUR_713.as_bytes().to_vec(),
            }),
        });
        assert_eq!((liste.len(), lues, tronquees), (2, true, false));
        let mut appels = 0;
        let (liste, lues, tronquees) = lire_redirections(|i| {
            appels += 1;
            assert!(i < 10_000);
            Some(reponse_ok(&entree(1)))
        });
        assert_eq!((liste.len(), lues, tronquees), (200, true, true));
        assert_eq!(appels, 200);
        // Liste vide : vérifiée quand la box répond 713 dès la première entrée.
        let (liste, lues, _) = lire_redirections(|_| {
            Some(Reponse {
                code: 500,
                corps: ERREUR_713.as_bytes().to_vec(),
            })
        });
        assert_eq!((liste.len(), lues), (0, true));
        // Muette, refus (autre erreur) ou réponse illisible dès le début : non vérifiée.
        assert!(!lire_redirections(|_| None).1);
        let refus = "<e><errorCode>606</errorCode></e>";
        let (_, lues, _) = lire_redirections(|_| {
            Some(Reponse {
                code: 500,
                corps: refus.as_bytes().to_vec(),
            })
        });
        assert!(!lues);
        assert!(!lire_redirections(|_| Some(reponse_ok("<pas>du soap</pas>"))).1);
        // Refus en cours de route : ce qui précède, dit incomplet.
        let (liste, lues, tronquees) = lire_redirections(|i| if i == 0 { Some(reponse_ok(&entree(0))) } else { None });
        assert_eq!((liste.len(), lues, tronquees), (1, true, true));
    }
}

/// Ce que la box (ou un appareil qui se fait passer pour elle) peut répondre de pire : jamais de panique, et ce qui
/// en est gardé reste borné et inoffensif.
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use crate::ui::piege;
    use proptest::prelude::*;

    /// Un texte gardé de la box : court, sans caractère qui piloterait le terminal.
    fn montrable(t: &str) -> bool {
        t.chars().count() <= TEXTE_MAX && !t.chars().any(piege)
    }

    /// Du XML de box, ni ordonné ni équilibré : balises UPnP et SOAP connues (ouvrantes, fermantes, vides), entités et
    /// références de caractères valides ou non, CDATA, et du texte quelconque (UTF-8 multi-octets compris).
    fn xml() -> impl Strategy<Value = String> {
        let balises = prop::sample::select(vec![
            "root",
            "device",
            "friendlyName",
            "manufacturer",
            "modelName",
            "modelNumber",
            "URLBase",
            "serviceList",
            "service",
            "serviceType",
            "controlURL",
            "NewExternalIPAddress",
            "NewExternalPort",
            "NewInternalPort",
            "NewInternalClient",
            "NewProtocol",
            "NewPortMappingDescription",
            "NewLeaseDuration",
            "NewRemoteHost",
            "NewEnabled",
            "errorCode",
            "s:Envelope",
            "u:GetGenericPortMappingEntryResponse",
        ]);
        let bouts = prop::sample::select(vec![
            "&amp;",
            "&lt;",
            "&#x27;",
            "&#39;",
            "&#xD800;",
            "&#99999999999;",
            "&#x;",
            "&inconnue;",
            "&",
            "<![CDATA[",
            "]]>",
            "<?xml version=\"1.0\"?>",
            "<!--",
            "-->",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1\" x=\"",
            "http://10.0.0.1:5000/",
            "http://8.8.8.8/",
            "/ctl/IPConn",
            "65535",
            "70000",
            "-1",
            "192.168.1.20",
        ]);
        let contenu = prop_oneof![
            any::<String>(),
            "[0-9]{1,7}",
            "[ -~é😀\u{202e}\u{1b}]{0,100}",
            bouts.clone().prop_map(str::to_string),
        ];
        let morceau = prop_oneof![
            any::<String>(),
            "[ -~é€😀\u{202e}\u{1b}\t\r\n]{0,20}",
            (balises.clone(), 0..3u8).prop_map(|(b, forme)| match forme {
                0 => format!("<{b}>"),
                1 => format!("</{b}>"),
                _ => format!("<{b}/>"),
            }),
            // Un élément entier, pour aller jusqu'aux champs lus (port, client, service WAN).
            (balises, contenu.clone()).prop_map(|(b, c)| format!("<{b}>{c}</{b}>")),
            (contenu.clone(), contenu).prop_map(|(genre, controle)| format!(
                "<service><serviceType>{genre}</serviceType><controlURL>{controle}</controlURL></service>"
            )),
            bouts.prop_map(str::to_string),
        ];
        prop::collection::vec(morceau, 0..60).prop_map(|v| v.concat())
    }

    /// Un texte écrit par la box : quelconque, ou fait de caractères qui pilotent un terminal ou retournent le texte.
    fn texte() -> impl Strategy<Value = String> {
        prop_oneof![any::<String>(), "[ -~é😀\u{202e}\u{1b}\u{200b}<&]{0,120}"]
    }

    /// Une description de box bien formée, aux valeurs quelconques : nom, fabricant, URLBase, type et adresse du
    /// service (WAN ou non, avec des caractères qui sortiraient de l'en-tête SOAPAction), suivie de bruit.
    fn description() -> impl Strategy<Value = String> {
        let genre = prop_oneof![
            Just("urn:schemas-upnp-org:service:WANIPConnection:1".to_string()),
            Just("urn:schemas-upnp-org:service:WANPPPConnection:1".to_string()),
            texte().prop_map(|t| format!("WANIPConnection{t}")),
            texte(),
        ];
        let lien = prop_oneof![
            Just("/ctl/IPConn".to_string()),
            Just("http://10.0.0.1:5000/".to_string()),
            texte()
        ];
        (texte(), texte(), lien.clone(), genre, lien, xml()).prop_map(
            |(nom, fabricant, base, genre, controle, bruit)| {
                format!(
                    "<root><URLBase>{base}</URLBase><device><friendlyName>{nom}</friendlyName>\
                 <manufacturer>{fabricant}</manufacturer><serviceList><service><serviceType>{genre}</serviceType>\
                 <controlURL>{controle}</controlURL></service></serviceList></device>{bruit}</root>"
                )
            },
        )
    }

    /// Une réponse à GetGenericPortMappingEntry bien formée, aux valeurs quelconques (ports hors de 0..65535
    /// compris), suivie de bruit.
    fn reponse_soap() -> impl Strategy<Value = String> {
        let nombre = prop_oneof![3 => (0u32..70_000).prop_map(|n| n.to_string()), 1 => texte()];
        (nombre.clone(), nombre.clone(), texte(), texte(), texte(), nombre, xml()).prop_map(
            |(public, interne, client, description, protocole, bail, bruit)| {
                format!(
                    "<s:Envelope><s:Body><u:R><NewExternalPort>{public}</NewExternalPort>\
                     <NewInternalPort>{interne}</NewInternalPort><NewInternalClient>{client}</NewInternalClient>\
                     <NewPortMappingDescription>{description}</NewPortMappingDescription>\
                     <NewProtocol>{protocole}</NewProtocol><NewLeaseDuration>{bail}</NewLeaseDuration>{bruit}\
                     </u:R></s:Body></s:Envelope>"
                )
            },
        )
    }

    /// Une réponse SSDP : la ligne d'état, des en-têtes connus ou non, des valeurs quelconques.
    fn ssdp() -> impl Strategy<Value = String> {
        let ligne = prop_oneof![
            any::<String>(),
            Just("HTTP/1.1 200 OK".to_string()),
            Just("ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1".to_string()),
            "(LOCATION|Location|SERVER|NT|ST|location): ?[ -~é😀\u{202e}]{0,40}",
            "LOCATION: http://(10\\.0\\.0\\.1|192\\.168\\.1\\.1|8\\.8\\.8\\.8|é)(:[0-9]{0,6})?/[ -~é]{0,20}",
        ];
        prop::collection::vec(ligne, 0..10).prop_map(|l| l.join("\r\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn xml_de_la_box(x in prop_oneof![xml(), description(), reponse_soap()]) {
            let debuts = noeuds(&x).iter().filter(|n| matches!(n, Noeud::Debut(_))).count();
            prop_assert!(debuts <= ELEMENTS_MAX);
            let base = Adresse::lire("http://10.0.0.1:5000/rootDesc.xml").unwrap();
            let (description, service) = lire_description(&x, &base);
            for champ in [description.nom, description.fabricant, description.modele, description.version].iter().flatten() {
                prop_assert!(montrable(champ), "{champ:?}");
            }
            if let Some(s) = service {
                prop_assert!(s.genre.chars().all(|c| c.is_ascii_alphanumeric() || ":-._".contains(c)), "{:?}", s.genre);
            }
            if let Some(r) = redirection(&x) {
                for champ in [&r.protocole, &r.appareil, &r.description, &r.hote_distant] {
                    prop_assert!(montrable(champ), "{champ:?}");
                }
            }
            let _ = erreur_soap(&x);
            let _ = valeur(&x, "NewExternalIPAddress");
        }

        #[test]
        fn reponses_ssdp(t in ssdp()) {
            if let Some(r) = lire_reponse_ssdp(&t, Ipv4Addr::new(10, 0, 0, 1)) {
                prop_assert!(Adresse::lire(&r.emplacement).is_some_and(|a| a.ip == r.source));
                prop_assert!(r.serveur.as_deref().is_none_or(montrable));
            }
        }
    }

    // Deux cents lectures par cas : moins de cas.
    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, ..ProptestConfig::default() })]

        /// Une box qui répond toujours la même chose, quoi que ce soit : la liste reste bornée.
        #[test]
        fn redirections_bornees(x in prop_oneof![xml(), reponse_soap()], code in prop::sample::select(vec![200u16, 500])) {
            let (liste, _, _) = lire_redirections(|_| Some(Reponse { code, corps: x.clone().into_bytes() }));
            prop_assert!(liste.len() <= MAX_REDIRECTIONS as usize);
        }
    }
}
