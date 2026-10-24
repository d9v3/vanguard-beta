//! Domaine Appareils (code APP) : les objets connectés et les équipements de la maison — caméras, imprimantes, NAS,
//! télés et diffusion, enceintes, consoles, domotique — reconnus par `objets::genre` d'après le scan, sans rien
//! sonder de plus que la recherche des caméras (`cameras::chercher` : une demande de description RTSP sans mot de
//! passe, la recherche ONVIF). Jamais d'essai de mot de passe : le conseil du mot de passe d'origine vient du type
//! d'appareil. Règles : COM-APP-001 objet joignable depuis Internet (jointure avec les redirections de la box),
//! COM-APP-002 services d'administration ouverts sur un objet, COM-APP-003 ce que les objets envoient vers Internet
//! (pas observable d'ici : dit), COM-APP-004 mots de passe d'origine et mises à jour (conseil), COM-APP-005 caméras.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use super::{avec_regle, non_verifie};
use crate::machine::{Constat, alerte, ok};
use crate::reseau::{Hote, cameras, objets, upnp};
use crate::risk::{Niveau, info_port};
use crate::ui::*;

/// Ce que le domaine reçoit de l'audit, construit par `audit/mod.rs`.
pub struct Entree<'a> {
    pub hotes: &'a [Hote],
    /// Le carnet du réseau : un objet connu ici mais absent du scan (en veille) reste visé par une redirection.
    pub carnet: &'a [objets::Appareil],
    /// Les indices de caméras ; `None` : pas cherchées (passe rapide) ou recherche impossible.
    pub cameras: Option<&'a BTreeMap<Ipv4Addr, cameras::Indices>>,
    /// Les redirections de ports de la box ; `None` : non lues.
    pub redirections: Option<&'a [upnp::Redirection]>,
    pub passerelle: Option<Ipv4Addr>,
    pub adresse_locale: Option<Ipv4Addr>,
}

/// Un objet connecté : son adresse, son nom montré et son type.
pub struct Objet {
    pub ip: Ipv4Addr,
    pub nom: String,
    pub genre: objets::Genre,
    /// Connu par le carnet seulement (absent du scan d'aujourd'hui).
    pub du_carnet: bool,
}

/// « 10.0.0.9 (caméra salon · Hikvision) », ou l'adresse seule.
fn nom(ip: Ipv4Addr, titre: &str) -> String {
    if titre.is_empty() {
        ip.to_string()
    } else {
        format!("{ip} ({titre})")
    }
}

/// Les objets connectés du scan : la box, cet ordinateur, les ordinateurs et les téléphones n'en sont pas.
pub fn objets_du_scan(hotes: &[Hote]) -> Vec<Objet> {
    hotes
        .iter()
        .filter(|h| h.role.is_none())
        .filter_map(|h| {
            let genre = objets::genre(&super::appareil(h)).filter(|g| *g != objets::Genre::Boite)?;
            Some(Objet {
                ip: h.ip,
                nom: nom(h.ip, &h.titre()),
                genre,
                du_carnet: false,
            })
        })
        .collect()
}

/// Les objets du carnet que le scan n'a pas vus aujourd'hui (en veille, débranchés) : leurs ports sont ceux déjà vus.
pub fn objets_du_carnet(carnet: &[objets::Appareil], hotes: &[Hote]) -> Vec<Objet> {
    carnet
        .iter()
        .filter(|a| !a.boite && !hotes.iter().any(|h| h.ip == a.ip))
        .filter_map(|a| {
            let genre = objets::genre(a).filter(|g| *g != objets::Genre::Boite)?;
            Some(Objet {
                ip: a.ip,
                nom: nom(a.ip, &a.titre),
                genre,
                du_carnet: true,
            })
        })
        .collect()
}

/// Une redirection de la box qui vise un objet connecté : la jointure entre les redirections (Exposition, COM-EXP-001)
/// et les objets. Le domaine Exposition la réutilise telle quelle quand il lit les redirections nativement.
pub struct Joignable<'a> {
    pub redirection: &'a upnp::Redirection,
    pub objet: &'a Objet,
}

pub fn joignables<'a>(redirections: &'a [upnp::Redirection], objets: &'a [Objet]) -> Vec<Joignable<'a>> {
    redirections
        .iter()
        .filter_map(|r| {
            let ip: Ipv4Addr = r.appareil.parse().ok()?;
            let objet = objets.iter().find(|o| o.ip == ip)?;
            Some(Joignable { redirection: r, objet })
        })
        .collect()
}

/// Ports d'administration ou de flux d'un objet : exposés à Internet, c'est critique.
const SENSIBLES: [u16; 8] = [80, 8080, 23, 554, 37777, 34567, 445, 21];

/// COM-APP-001 : un objet joignable depuis Internet par une redirection de la box.
fn joignables_depuis_internet(e: &Entree, objets: &[Objet]) -> Vec<Constat> {
    let Some(redirections) = e.redirections else {
        return vec![non_verifie(
            "Appareils",
            "COM-APP-001",
            tr!(
                "Les redirections du routeur n'ont pas pu être lues : impossible de savoir si un objet est joignable depuis Internet (voir le domaine Exposition).",
                "The router's port forwardings could not be read: no way to know whether a device is reachable from the Internet (see the Exposure domain)."
            ),
        )];
    };
    let mut constats: Vec<Constat> = joignables(redirections, objets)
        .into_iter()
        .map(|j| {
            let (r, o) = (j.redirection, j.objet);
            let niveau = if SENSIBLES.contains(&r.port_appareil) {
                Niveau::Critique
            } else {
                Niveau::Eleve
            };
            let veille = if o.du_carnet {
                tr!(" (absent du scan d'aujourd'hui)", " (absent from today's scan)")
            } else {
                ""
            };
            alerte(
                "Appareils",
                niveau,
                trf!(
                    "{} ({}){veille} est joignable depuis Internet par le port {}/{} du routeur, vers son port {} ({}) : n'importe qui sur Internet peut tenter de s'y connecter ; une caméra ou un enregistreur ainsi exposé est la cible la plus courante des réseaux de machines zombies.",
                    "{} ({}){veille} can be reached from the Internet through the router's port {}/{}, to its port {} ({}): anyone on the Internet can try to connect; a camera or recorder exposed this way is the most common target of zombie networks.",
                    o.nom,
                    o.genre.nom(),
                    r.port_public,
                    r.protocole.to_lowercase(),
                    r.port_appareil,
                    info_port(r.port_appareil).service
                ),
            )
            .manuel(
                tr!(
                    "Retirez la redirection (ou coupez UPnP dans l'administration du routeur) ; si l'accès à distance est voulu, passez par l'application du fabricant ou un VPN vers le routeur, jamais par un port ouvert",
                    "Remove the forwarding (or turn UPnP off in the router's administration); if remote access is wanted, go through the maker's app or a VPN to the router, never through an open port"
                ),
                &[],
            )
        })
        .collect();
    if constats.is_empty() {
        constats.push(ok(
            "Appareils",
            if redirections.is_empty() {
                tr!(
                    "Aucune redirection du routeur ne vise un objet connecté (celles réglées à la main dans le routeur ne se lisent pas d'ici).",
                    "No router forwarding targets a connected device (those set by hand in the router cannot be read from here)."
                )
                .to_string()
            } else {
                trf!(
                    "Aucune des {} redirection(s) du routeur ne vise un objet connecté.",
                    "None of the router's {} forwarding(s) targets a connected device.",
                    redirections.len()
                )
            },
        ));
    }
    constats.into_iter().map(|c| avec_regle(c, "COM-APP-001")).collect()
}

/// Services d'administration qu'un objet offre à tout le réseau ; le niveau est celui du port dans `risk`, sauf
/// l'annonce UPnP, une simple information sur un objet.
const ADMINISTRATION: [u16; 8] = [23, 5555, 21, 161, 80, 8080, 1883, 1900];

/// COM-APP-002 : les services d'administration ouverts sur chaque objet du scan.
fn administrations_ouvertes(hotes: &[Hote], objets: &[Objet]) -> Vec<Constat> {
    let mut constats = Vec::new();
    for o in objets.iter().filter(|o| !o.du_carnet) {
        let Some(h) = hotes.iter().find(|h| h.ip == o.ip) else {
            continue;
        };
        let mut ouverts: Vec<_> = h
            .ports
            .iter()
            .filter(|p| ADMINISTRATION.contains(&p.port))
            .map(|p| (if p.port == 1900 { Niveau::Info } else { p.niveau }, p))
            .collect();
        if ouverts.is_empty() {
            continue;
        }
        ouverts.sort_by_key(|(n, p)| (std::cmp::Reverse(*n), p.port));
        let services: Vec<String> = ouverts
            .iter()
            .map(|(_, p)| format!("{} ({})", p.service, p.libelle()))
            .collect();
        let (pire, port) = ouverts[0];
        constats.push(
            alerte(
                "Appareils",
                pire,
                trf!(
                    "{} ({}) offre {} à tout le réseau : {}",
                    "{} ({}) offers {} to the whole network: {}",
                    o.nom,
                    o.genre.nom(),
                    services.join(", "),
                    port.conseil
                ),
            )
            .manuel(
                tr!(
                    "Dans l'application ou la page web de l'objet, coupez ce qui ne sert pas (Telnet, FTP, SNMP, débogage) et mettez-le à jour ; si rien ne se règle, mettez-le sur le réseau invité du routeur",
                    "In the device's app or web page, turn off what is not needed (Telnet, FTP, SNMP, debugging) and update it; if nothing can be set, put it on the router's guest network"
                ),
                &[],
            ),
        );
    }
    if constats.is_empty() {
        let n = objets.iter().filter(|o| !o.du_carnet).count();
        constats.push(ok(
            "Appareils",
            if n == 0 {
                tr!(
                    "Aucun objet connecté reconnu sur le réseau (caméra, imprimante, NAS, télé, enceinte, console, domotique).",
                    "No connected device recognized on the network (camera, printer, NAS, TV, speaker, console, smart home)."
                )
                .to_string()
            } else {
                trf!(
                    "Aucun des {n} objet(s) connecté(s) reconnu(s) n'offre d'administration à tout le réseau (Telnet, FTP, SNMP, débogage, web en clair).",
                    "None of the {n} recognized connected device(s) offers administration to the whole network (Telnet, FTP, SNMP, debugging, clear-text web)."
                )
            },
        ));
    }
    constats.into_iter().map(|c| avec_regle(c, "COM-APP-002")).collect()
}

/// COM-APP-003 : le trafic des objets vers Internet ne s'observe pas d'ici ; dit, jamais compté sain.
fn trafic_des_objets() -> Constat {
    non_verifie(
        "Appareils",
        "COM-APP-003",
        tr!(
            "Le trafic de chaque objet vers Internet n'est pas visible d'ici (il faudrait le routeur ou un miroir du réseau). Indices disponibles : l'adresse publique sur une liste noire (« Adresse sur liste noire ? », avec votre accord) et les redirections demandées par un objet (ci-dessus).",
            "Each device's traffic to the Internet is not visible from here (it would take the router or a network mirror). Available clues: the public address on a blocklist (“Address on blocklists?”, with your consent) and the forwardings requested by a device (above)."
        ),
    )
}

/// COM-APP-004 : les types d'appareils livrés avec un mot de passe d'usine connu de tous (box, caméra, imprimante,
/// NAS) : un conseil, jamais un essai.
fn mots_de_passe_d_origine(hotes: &[Hote]) -> Constat {
    let a_changer: Vec<String> = hotes
        .iter()
        .filter(|h| h.role != Some("cette machine"))
        .filter_map(|h| {
            let g = objets::genre(&super::appareil(h))?;
            g.mot_de_passe_d_origine()
                .then(|| format!("{} : {}", nom(h.ip, &h.titre()), g.nom()))
        })
        .collect();
    let constat = if a_changer.is_empty() {
        ok(
            "Appareils",
            tr!(
                "Aucun appareil du scan n'est d'un type livré avec un mot de passe d'usine connu de tous (routeur, caméra, imprimante, NAS).",
                "No device of the scan is of a type shipped with a factory password everyone knows (router, camera, printer, NAS)."
            ),
        )
    } else {
        alerte(
            "Appareils",
            Niveau::Info,
            trf!(
                "{} appareil(s) d'un type souvent livré avec un mot de passe d'usine connu de tous ({}) : s'il n'a jamais été changé, changez-le dans leur application ou leur page web, et vérifiez une mise à jour. Conseil seulement : Vanguard n'en essaie aucun.",
                "{} device(s) of a type often shipped with a factory password everyone knows ({}): if it was never changed, change it in their app or web page, and check for an update. Advice only: Vanguard tries none.",
                a_changer.len(),
                resume(&a_changer, 4, " ; ")
            ),
        )
    };
    avec_regle(constat, "COM-APP-004")
}

/// COM-APP-005 : les caméras probables du réseau ; un flux vidéo sans mot de passe est élevé, une caméra chez soi
/// n'est pas « cachée » : une information, avec le conseil de son mot de passe et de ses mises à jour.
fn cameras_du_reseau(e: &Entree) -> Vec<Constat> {
    let Some(indices) = e.cameras else {
        return vec![non_verifie(
            "Appareils",
            "COM-APP-005",
            tr!(
                "Caméras non cherchées (passe rapide, ou recherche impossible) : « vanguard audit-reseau » cherche les flux vidéo sans mot de passe.",
                "Cameras not searched (quick pass, or search impossible): “vanguard audit-reseau” looks for video streams without a password."
            ),
        )];
    };
    let mut constats: Vec<Constat> = indices
        .iter()
        .filter(|(ip, i)| {
            i.force() == Some(cameras::Force::Probable) && Some(**ip) != e.passerelle && Some(**ip) != e.adresse_locale
        })
        .map(|(ip, i)| {
            let titre = e.hotes.iter().find(|h| h.ip == *ip).map(Hote::titre).unwrap_or_default();
            let qui = nom(*ip, &titre);
            let details: Vec<String> = cameras::lignes_indices(i).into_iter().map(|(t, _)| t).collect();
            let details = details.join(" ; ");
            if i.rtsp.iter().any(|(_, f)| *f == cameras::Flux::Ouvert) {
                alerte(
                    "Appareils",
                    Niveau::Eleve,
                    trf!(
                        "Caméra {qui} : son flux vidéo (RTSP) se lit SANS mot de passe, n'importe qui sur ce réseau peut regarder ({details})."
                        ,
                        "Camera {qui}: its video stream (RTSP) can be read WITHOUT a password, anyone on this network can watch ({details})."
                    ),
                )
                .manuel(
                    tr!(
                        "Donnez-lui un mot de passe dans son application ou sa page web ; si elle ne le permet pas, remplacez-la ou mettez-la sur le réseau invité",
                        "Give it a password in its app or web page; if it does not allow one, replace it or put it on the guest network"
                    ),
                    &[],
                )
            } else {
                alerte(
                    "Appareils",
                    Niveau::Info,
                    trf!(
                        "Caméra sur votre réseau : {qui} ({details}). Vérifiez son mot de passe et ses mises à jour.",
                        "Camera on your network: {qui} ({details}). Check its password and its updates."
                    ),
                )
            }
        })
        .collect();
    if constats.is_empty() {
        constats.push(ok(
            "Appareils",
            tr!(
                "Aucun appareil du réseau ne ressemble à une caméra (fabricant, flux vidéo, recherche ONVIF, page web).",
                "No device on the network looks like a camera (maker, video stream, ONVIF discovery, web page)."
            ),
        ));
    }
    constats.into_iter().map(|c| avec_regle(c, "COM-APP-005")).collect()
}

pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut objets = objets_du_scan(e.hotes);
    objets.extend(objets_du_carnet(e.carnet, e.hotes));
    let mut constats = joignables_depuis_internet(e, &objets);
    constats.extend(administrations_ouvertes(e.hotes, &objets));
    constats.push(trafic_des_objets());
    constats.push(mots_de_passe_d_origine(e.hotes));
    constats.extend(cameras_du_reseau(e));
    constats
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::reseau::PortOuvert;
    use crate::risk::info_udp;

    pub(crate) fn port(p: u16, udp: bool) -> PortOuvert {
        let i = if udp { info_udp(p) } else { info_port(p) };
        PortOuvert {
            port: p,
            service: i.service,
            niveau: i.niveau,
            banniere: None,
            conseil: i.conseil,
            nouveau: false,
            programme: None,
            udp,
        }
    }

    pub(crate) fn hote(ip: &str, fabricant: Option<&str>, role: Option<&'static str>, ports: &[u16]) -> Hote {
        Hote {
            ip: ip.parse().unwrap(),
            nom: None,
            mac: Some(format!(
                "3c:22:fb:00:00:{:02x}",
                ip.rsplit('.').next().unwrap().parse::<u8>().unwrap()
            )),
            fabricant: fabricant.map(str::to_string),
            surnom: None,
            premier_vu: None,
            role,
            nouvelle: false,
            ports: ports.iter().map(|&p| port(p, matches!(p, 161 | 1900 | 5353))).collect(),
            alertes: Vec::new(),
            score: 100,
        }
    }

    /// Le réseau « Salon » inventé : une box, une caméra, une imprimante, un NAS, un PC, cette machine.
    fn salon() -> Vec<Hote> {
        vec![
            hote(
                "10.0.0.1",
                Some("Sagemcom Broadband SAS"),
                Some("passerelle"),
                &[80, 53],
            ),
            hote(
                "10.0.0.9",
                Some("Hangzhou Hikvision Digital Technology Co.,Ltd."),
                None,
                &[80, 554],
            ),
            hote("10.0.0.12", Some("Seiko Epson Corporation"), None, &[9100, 23, 80]),
            hote("10.0.0.20", Some("Synology Incorporated"), None, &[5000, 21, 1900]),
            hote("10.0.0.30", Some("Hewlett Packard"), None, &[135, 445]),
            hote("10.0.0.50", Some("Intel Corporate"), Some("cette machine"), &[22]),
        ]
    }

    fn redirection(public: u16, appareil: &str, port: u16) -> upnp::Redirection {
        upnp::Redirection {
            protocole: "TCP".into(),
            port_public: public,
            appareil: appareil.into(),
            port_appareil: port,
            description: String::new(),
            bail: 0,
            hote_distant: String::new(),
            active: true,
        }
    }

    fn entree<'a>(
        hotes: &'a [Hote],
        carnet: &'a [objets::Appareil],
        redirections: Option<&'a [upnp::Redirection]>,
        cameras: Option<&'a BTreeMap<Ipv4Addr, cameras::Indices>>,
    ) -> Entree<'a> {
        Entree {
            hotes,
            carnet,
            cameras,
            redirections,
            passerelle: Some("10.0.0.1".parse().unwrap()),
            adresse_locale: Some("10.0.0.50".parse().unwrap()),
        }
    }

    fn regle<'a>(constats: &'a [Constat], id: &str) -> Vec<&'a Constat> {
        constats.iter().filter(|c| c.regle == id).collect()
    }

    #[test]
    fn objets_reconnus_sans_la_box_ni_les_ordinateurs() {
        let hotes = salon();
        let objets = objets_du_scan(&hotes);
        let genres: Vec<(String, objets::Genre)> = objets.iter().map(|o| (o.ip.to_string(), o.genre)).collect();
        assert_eq!(
            genres,
            [
                ("10.0.0.9".to_string(), objets::Genre::Camera),
                ("10.0.0.12".to_string(), objets::Genre::Imprimante),
                ("10.0.0.20".to_string(), objets::Genre::Nas),
            ]
        );
        // Le carnet : une caméra en veille (absente du scan) compte, un appareil déjà vu au scan non.
        let carnet = vec![
            objets::Appareil {
                ip: "10.0.0.77".parse().unwrap(),
                titre: "caméra entrée".into(),
                boite: false,
                fabricant: Some("Zhejiang Dahua Technology Co., Ltd.".into()),
                nom: None,
                tcp: vec![37777],
                annonces: Vec::new(),
                dernier_vu: Some("2026-10-01".into()),
            },
            objets::Appareil {
                ip: "10.0.0.9".parse().unwrap(),
                titre: String::new(),
                boite: false,
                fabricant: Some("Hangzhou Hikvision Digital Technology Co.,Ltd.".into()),
                nom: None,
                tcp: vec![80],
                annonces: Vec::new(),
                dernier_vu: None,
            },
        ];
        let du_carnet = objets_du_carnet(&carnet, &hotes);
        assert_eq!(du_carnet.len(), 1);
        assert!(du_carnet[0].du_carnet && du_carnet[0].nom == "10.0.0.77 (caméra entrée)");
    }

    #[test]
    fn administrations_ouvertes_sur_les_objets() {
        let hotes = salon();
        let c = constats(&entree(&hotes, &[], Some(&[]), None));
        // Chaque constat porte sa règle, et chaque règle a sa fiche.
        for c in &c {
            assert!(c.regle.starts_with("COM-APP-"), "{}", c.message);
            assert!(
                crate::audit::fiches::FICHES.iter().any(|f| f.id == c.regle),
                "{} sans fiche",
                c.regle
            );
        }
        let admin = regle(&c, "COM-APP-002");
        let niveaux: Vec<(String, Option<Niveau>)> = admin
            .iter()
            .map(|c| (c.message.split(' ').next().unwrap().to_string(), c.probleme))
            .collect();
        // La caméra : web en clair (moyen, 554 n'est pas une administration) ; l'imprimante : Telnet (critique) ;
        // le NAS : FTP (élevé), l'annonce UPnP n'est qu'une information ; le PC et la box : rien.
        assert_eq!(
            niveaux,
            [
                ("10.0.0.9".to_string(), Some(Niveau::Moyen)),
                ("10.0.0.12".to_string(), Some(Niveau::Critique)),
                ("10.0.0.20".to_string(), Some(Niveau::Eleve)),
            ]
        );
        assert!(admin[1].message.contains("Telnet (23/tcp)") && admin[1].message.contains("HTTP (80/tcp)"));
        assert!(admin[2].message.contains("SSDP / UPnP (1900/udp)"));
        assert!(
            admin
                .iter()
                .all(|c| c.correctif.as_ref().is_some_and(|k| !k.automatique))
        );
        // Rien d'ouvert : un seul constat, qui va bien, avec le nombre d'objets.
        let calmes = vec![hote(
            "10.0.0.9",
            Some("Hangzhou Hikvision Digital Technology Co.,Ltd."),
            None,
            &[554],
        )];
        let c = administrations_ouvertes(&calmes, &objets_du_scan(&calmes));
        assert!(c.len() == 1 && c[0].probleme.is_none() && c[0].message.contains("1 objet"));
        // Le trafic des objets : jamais vérifié, dit.
        let tous = constats(&entree(&hotes, &[], Some(&[]), None));
        let trafic = regle(&tous, "COM-APP-003");
        assert!(trafic.len() == 1 && !trafic[0].verifie);
    }

    #[test]
    fn objet_joignable_depuis_internet() {
        let hotes = salon();
        let carnet = vec![objets::Appareil {
            ip: "10.0.0.77".parse().unwrap(),
            titre: "caméra entrée".into(),
            boite: false,
            fabricant: Some("Zhejiang Dahua Technology Co., Ltd.".into()),
            nom: None,
            tcp: vec![37777],
            annonces: Vec::new(),
            dernier_vu: Some("2026-10-01".into()),
        }];
        let redirections = [
            redirection(8080, "10.0.0.9", 80),      // caméra, port web : critique
            redirection(3074, "10.0.0.30", 3074),   // un PC : pas un objet, rien ici
            redirection(25565, "10.0.0.20", 25565), // NAS, port quelconque : élevé
            redirection(37777, "10.0.0.77", 37777), // caméra du carnet, en veille : critique
            redirection(80, "pas une adresse", 80),
        ];
        let c = constats(&entree(&hotes, &carnet, Some(&redirections), None));
        let j = regle(&c, "COM-APP-001");
        let niveaux: Vec<Option<Niveau>> = j.iter().map(|c| c.probleme).collect();
        assert_eq!(
            niveaux,
            [Some(Niveau::Critique), Some(Niveau::Eleve), Some(Niveau::Critique)]
        );
        assert!(j[0].message.contains("10.0.0.9") && j[0].message.contains("8080/tcp"));
        assert!(j[2].message.contains("absent du scan"));
        // Aucune redirection : ça va bien, et les redirections à la main sont dites illisibles.
        let c = constats(&entree(&hotes, &[], Some(&[]), None));
        let j = regle(&c, "COM-APP-001");
        assert!(j.len() == 1 && j[0].probleme.is_none() && j[0].message.contains("à la main"));
        // Redirections non lues : non vérifié, jamais « rien ».
        let c = constats(&entree(&hotes, &[], None, None));
        let j = regle(&c, "COM-APP-001");
        assert!(j.len() == 1 && !j[0].verifie);
    }

    #[test]
    fn mots_de_passe_d_origine_conseilles() {
        let hotes = salon();
        let c = mots_de_passe_d_origine(&hotes);
        assert_eq!((c.probleme, c.regle), (Some(Niveau::Info), "COM-APP-004"));
        // La box, la caméra, l'imprimante et le NAS ; pas le PC ni cette machine.
        assert!(c.message.starts_with("4 appareil(s)"), "{}", c.message);
        assert!(
            c.message.contains("10.0.0.1 (Sagemcom Broadband SAS) : routeur"),
            "{}",
            c.message
        );
        assert!(c.message.contains("10.0.0.20 (Synology Incorporated) : NAS (stockage)"));
        assert!(!c.message.contains("10.0.0.30") && !c.message.contains("10.0.0.50"));
        let pc = vec![hote("10.0.0.30", Some("Hewlett Packard"), None, &[445])];
        assert!(mots_de_passe_d_origine(&pc).probleme.is_none());
    }

    #[test]
    fn cameras_du_reseau_de_la_maison() {
        let hotes = salon();
        let mut indices = BTreeMap::new();
        indices.insert(
            "10.0.0.9".parse::<Ipv4Addr>().unwrap(),
            cameras::Indices {
                fabricant: Some("Hikvision"),
                rtsp: vec![(554, cameras::Flux::Ouvert)],
                ..cameras::Indices::default()
            },
        );
        indices.insert(
            "10.0.0.40".parse::<Ipv4Addr>().unwrap(),
            cameras::Indices {
                onvif: Some("IPC · DS-2CD2032".into()),
                rtsp: vec![(554, cameras::Flux::Protege)],
                ..cameras::Indices::default()
            },
        );
        // Un port « à vérifier » seul n'est pas une caméra ; la box n'en est jamais une.
        indices.insert(
            "10.0.0.41".parse::<Ipv4Addr>().unwrap(),
            cameras::Indices {
                ports: vec![2020],
                ..cameras::Indices::default()
            },
        );
        indices.insert(
            "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
            cameras::Indices {
                web: Some("HTTP · camera".into()),
                ..cameras::Indices::default()
            },
        );
        let c = regle(
            &constats(&entree(&hotes, &[], Some(&[]), Some(&indices))),
            "COM-APP-005",
        )
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
        assert_eq!(c.len(), 2, "{:?}", c.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("10.0.0.9") && c[0].message.contains("SANS mot de passe"));
        assert_eq!(c[1].probleme, Some(Niveau::Info));
        assert!(c[1].message.contains("10.0.0.40") && c[1].message.contains("DS-2CD2032"));
        // Pas cherchées : non vérifié ; cherchées sans rien trouver : ça va bien.
        let sans = regle(&constats(&entree(&hotes, &[], Some(&[]), None)), "COM-APP-005")
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        assert!(sans.len() == 1 && !sans[0].verifie);
        let vide = BTreeMap::new();
        let rien = cameras_du_reseau(&entree(&hotes, &[], Some(&[]), Some(&vide)));
        assert!(rien.len() == 1 && rien[0].probleme.is_none() && rien[0].verifie);
    }
}
