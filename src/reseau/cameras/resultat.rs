//! Le résultat de « Caméras cachées » (`modele::resultat`) : chaque appareil qui ressemble à une caméra, sans l'écran.
//! Versé au rapport (`examens/PRO-CCH-001.json`), au journal des événements, et rendu par `--json`.
//!
//! Des indices, jamais une preuve : un appareil « caméra probable » peut être autre chose, et une caméra en 4G ou qui
//! n'enregistre que sur sa carte mémoire n'apparaît sur aucun réseau. Ce que la recherche n'a pas pu voir (pas de
//! réseau, ONVIF qui n'est pas parti, appareils qui n'ont rien ouvert, flux dont la protection ne se lit pas) est dit
//! non vérifié, jamais compté sain.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::Ipv4Addr;

use super::{Flux, Force, Indices, Recherche, lignes_indices};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat, nom_sans_piege};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-CCH-001";

const CAT: &str = "Caméras cachées";

/// Au-delà, les appareils restants sont comptés en un constat : un réseau d'hôtel peut en montrer des centaines.
const APPAREILS_MAX: usize = 50;

/// Longueur d'un message au plus : les indices viennent du réseau (nom ONVIF, page web).
const MESSAGE_MAX: usize = 400;

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'une recherche commencée à `debut` ; `Err` : elle n'a pas pu se faire (pas de réseau local, plage
/// refusée), avec la raison.
pub(super) fn resultat(r: Result<&Recherche, &str>, debut: Debut) -> Resultat {
    let (constats, couverture) = match r {
        Ok(r) => juger(r),
        Err(pourquoi) => {
            let pourquoi = crate::modele::resultat::sans_piege(pourquoi, false);
            (
                vec![impossible_par(
                    CAT,
                    Raison::Echoue(pourquoi.clone()),
                    trf!("Non vérifié : {pourquoi}.", "Not checked: {pourquoi}."),
                )],
                Couverture {
                    verifies: 0,
                    non_verifies: vec![pourquoi],
                },
            )
        }
    };
    Resultat::nouveau(ID, debut, &constats, couverture)
}

/// Le niveau d'un appareil : un flux vidéo sans mot de passe est grave (n'importe qui sur le réseau regarde) ; une
/// caméra probable, moyen ; un port que les caméras ouvrent souvent, une simple information.
fn niveau(i: &Indices) -> Niveau {
    if i.rtsp.iter().any(|(_, f)| *f == Flux::Ouvert) {
        Niveau::Eleve
    } else if i.force() == Some(Force::Probable) {
        Niveau::Moyen
    } else {
        Niveau::Info
    }
}

/// Le constat d'un appareil, qui dit ses indices et qu'ils ne prouvent rien.
fn constat(ip: Ipv4Addr, i: &Indices) -> Constat {
    let indices: Vec<String> = lignes_indices(i).into_iter().map(|(t, _)| t).collect();
    let indices = indices.join(" ; ");
    let message = match i.force() {
        Some(Force::Probable) => trf!(
            "{ip} : caméra probable, d'après des indices qui ne sont pas une preuve ({indices}).",
            "{ip}: likely camera, from clues that are not proof ({indices})."
        ),
        _ => trf!(
            "{ip} : à vérifier, un seul indice faible ({indices}).",
            "{ip}: to check, a single weak clue ({indices})."
        ),
    };
    alerte(CAT, niveau(i), nom_sans_piege(&message, MESSAGE_MAX)).avec_objet(Objet::de("appareil", &ip.to_string()))
}

/// Le jugement d'une recherche : un constat par appareil qui ressemble à une caméra (les plus probables d'abord), et
/// ce qui n'a pas pu se voir.
pub(super) fn juger(r: &Recherche) -> (Vec<Constat>, Couverture) {
    let mut constats = Vec::new();
    let mut non_verifies = Vec::new();
    let mut liste: Vec<(&Ipv4Addr, &Indices)> = r.indices.iter().collect();
    liste.sort_by_key(|(ip, i)| (std::cmp::Reverse(niveau(i)), **ip));
    for (ip, i) in liste.iter().take(APPAREILS_MAX) {
        constats.push(constat(**ip, i));
        for (port, _) in i.rtsp.iter().filter(|(_, f)| *f == Flux::Inconnu) {
            non_verifies.push(trf!(
                "{ip} : la protection du flux vidéo (RTSP, port {port}) n'a pas pu se lire",
                "{ip}: the video stream's protection (RTSP, port {port}) could not be read"
            ));
        }
    }
    let restent = liste.get(APPAREILS_MAX..).unwrap_or_default();
    if let Some(pire) = restent.iter().map(|(_, i)| niveau(i)).max() {
        constats.push(alerte(
            CAT,
            pire,
            trf!(
                "Et {} autre(s) appareil(s) qui ressemblent à des caméras (liste limitée à {APPAREILS_MAX}).",
                "And {} other device(s) that look like cameras (list limited to {APPAREILS_MAX}).",
                restent.len()
            ),
        ));
    }
    if liste.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun appareil de ce réseau ne ressemble à une caméra. Une caméra en 4G, ou qui n'enregistre que sur sa carte mémoire, n'apparaît sur aucun réseau : cherchez aussi à l'œil.",
                "No device on this network looks like a camera. A camera on 4G, or recording only to its memory card, shows up on no network: also look with your eyes."
            ),
        ));
    }
    if !r.onvif {
        non_verifies.push(
            tr!(
                "la recherche ONVIF n'a pas pu partir : une caméra qui ne répond qu'à elle n'a pas été cherchée",
                "the ONVIF discovery could not be sent: a camera that answers only to it was not looked for"
            )
            .to_string(),
        );
    }
    if r.sans_reponse > 0 {
        non_verifies.push(trf!(
            "{} appareil(s) n'ont ouvert aucun des ports sondés et rien ne les désigne : une caméra derrière un pare-feu leur ressemblerait",
            "{} device(s) opened none of the probed ports and nothing points to them: a camera behind a firewall would look the same",
            r.sans_reponse
        ));
    }
    if r.appareils == 0 {
        non_verifies.push(
            tr!(
                "aucun appareil n'a répondu sur ce réseau",
                "no device answered on this network"
            )
            .to_string(),
        );
    }
    let verifies = u32::try_from(r.appareils.saturating_sub(r.sans_reponse)).unwrap_or(u32::MAX);
    (constats, Couverture { verifies, non_verifies })
}

/// L'adaptateur du corpus (`modele::corpus`) : une ligne `appareil|<ip>|<indice>…` par appareil, chaque indice
/// `fabricant=<nom du registre>`, `onvif=<nom>`, `rtsp=<port>:<ouvert|protege|inconnu>`, `port=<n>` ou
/// `web=<en-tête>`. Les adresses sont celles de la documentation (192.0.2.0/24).
#[cfg(test)]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let mut r = Recherche {
        onvif: true,
        ..Recherche::default()
    };
    for champs in e.de("appareil") {
        let Some(ip) = champs.first().and_then(|ip| ip.parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        r.appareils = r.appareils.saturating_add(1);
        let mut i = Indices::default();
        for (cle, valeur) in champs.iter().skip(1).filter_map(|c| c.split_once('=')) {
            match cle {
                "fabricant" => i.fabricant = super::fabricant_camera(valeur),
                "onvif" => i.onvif = Some(valeur.to_string()),
                "port" => i.ports.extend(valeur.parse::<u16>().ok()),
                "web" => i.web = super::web_camera(valeur).then(|| valeur.to_string()),
                "rtsp" => {
                    let Some((port, etat)) = valeur.split_once(':') else {
                        continue;
                    };
                    let flux = match etat {
                        "ouvert" => Flux::Ouvert,
                        "protege" => Flux::Protege,
                        _ => Flux::Inconnu,
                    };
                    i.rtsp.extend(port.parse::<u16>().ok().map(|p| (p, flux)));
                }
                _ => {}
            }
        }
        if i.force().is_some() {
            r.indices.insert(ip, i);
        }
    }
    juger(&r).0
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn ip(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, n)
    }

    #[test]
    fn pas_de_reseau_non_verifie() {
        let r = resultat(Err("pas de réseau local détecté"), debut());
        assert_eq!(r.outil, ID);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
    }

    /// Rien ne ressemble à une caméra et tout a été vu : sain, avec la limite (4G, carte mémoire) dans le message.
    #[test]
    fn rien_trouve_sain_avec_sa_limite() {
        let r = Recherche {
            appareils: 4,
            onvif: true,
            ..Recherche::default()
        };
        let res = resultat(Ok(&r), debut());
        assert_eq!(res.verdict(), "sain");
        assert!(res.constats[0].message.contains("4G"));
    }

    /// Les appareils muets et une recherche ONVIF qui n'est pas partie ne laissent jamais dire sain.
    #[test]
    fn ce_qui_n_a_pas_ete_vu() {
        let r = Recherche {
            appareils: 4,
            onvif: false,
            sans_reponse: 2,
            ..Recherche::default()
        };
        let res = resultat(Ok(&r), debut());
        assert_eq!(res.verdict(), "non-verifie");
        assert_eq!(res.couverture.non_verifies.len(), 2);
        assert_eq!(res.couverture.verifies, 2);
        let vide = resultat(
            Ok(&Recherche {
                onvif: true,
                ..Recherche::default()
            }),
            debut(),
        );
        assert_eq!(vide.verdict(), "non-verifie");
    }

    /// Un flux ouvert est grave et passe en tête ; une caméra probable dit que ce n'est pas une preuve ; un flux dont
    /// la protection ne se lit pas est un manque.
    #[test]
    fn appareils_juges() {
        let mut r = Recherche {
            appareils: 5,
            onvif: true,
            ..Recherche::default()
        };
        r.indices.insert(
            ip(10),
            Indices {
                ports: vec![2020],
                ..Indices::default()
            },
        );
        r.indices.insert(
            ip(20),
            Indices {
                rtsp: vec![(554, Flux::Ouvert), (8554, Flux::Inconnu)],
                ..Indices::default()
            },
        );
        r.indices.insert(
            ip(30),
            Indices {
                fabricant: Some("Hikvision"),
                ..Indices::default()
            },
        );
        let res = resultat(Ok(&r), debut());
        assert_eq!(res.verdict(), "probleme");
        let c = &res.constats;
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].niveau, Some(Niveau::Eleve));
        assert!(c[0].message.starts_with("192.0.2.20"));
        assert_eq!(c[1].niveau, Some(Niveau::Moyen));
        assert!(c[1].message.contains("pas une preuve"), "{}", c[1].message);
        assert_eq!(c[2].niveau, Some(Niveau::Info));
        assert_eq!(res.couverture.non_verifies.len(), 1);
        assert!(res.couverture.non_verifies[0].contains("8554"));
    }

    /// Au-delà du plafond, les appareils restants tiennent en un constat, à la gravité du pire.
    #[test]
    fn liste_bornee() {
        let mut r = Recherche {
            appareils: 70,
            onvif: true,
            ..Recherche::default()
        };
        for n in 1..=60 {
            r.indices.insert(
                ip(n),
                Indices {
                    ports: vec![2020],
                    ..Indices::default()
                },
            );
        }
        let res = resultat(Ok(&r), debut());
        assert_eq!(res.constats.len(), APPAREILS_MAX + 1);
        assert!(res.constats[APPAREILS_MAX].message.contains("10"));
    }

    /// Un nom venu du réseau ne passe jamais tel quel : ni échappement, ni message sans fin.
    #[test]
    fn indices_du_reseau_sans_piege() {
        let mut r = Recherche {
            appareils: 3,
            onvif: true,
            ..Recherche::default()
        };
        r.indices.insert(
            ip(40),
            Indices {
                onvif: Some(format!("\u{1b}[31m{}", "x".repeat(1000))),
                ..Indices::default()
            },
        );
        let res = resultat(Ok(&r), debut());
        let m = &res.constats[0].message;
        assert!(!m.contains('\u{1b}'));
        assert!(m.chars().count() <= MESSAGE_MAX + 1);
    }
}
