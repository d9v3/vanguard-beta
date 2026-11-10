//! Le résultat du Wi-Fi encombré (`modele::resultat`) : le signal de la connexion et le conseil de canal par bande,
//! les mêmes que l'écran (`super::analyse`). Versé au rapport (`examens/PRO-CAN-001.json`), au journal des
//! événements, et rendu par `--json`.
//!
//! Une liste de voisins douteuse (trop vieille, refusée par le système) ne désigne aucun canal : le conseil y est dit
//! non vérifié, jamais « déjà libre ». Le nom des réseaux (le sien, ceux des voisins) n'est pas écrit.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::{Analyse, Conseil5, Conseil24, Lecture, analyse, qualite, texte_5, texte_24};
use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-CAN-001";

const CAT: &str = "Canaux Wi-Fi";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'une lecture commencée à `debut` ; `Err` : pourquoi les réseaux Wi-Fi n'ont pas pu se lire.
pub(super) fn resultat(lecture: Result<&Lecture, String>, debut: Debut) -> Resultat {
    let (constats, couverture) = match lecture {
        Ok(l) => juger(l),
        Err(raison) => (
            vec![impossible_par(CAT, Raison::Echoue(raison.clone()), raison.clone())],
            Couverture {
                verifies: 0,
                non_verifies: vec![raison],
            },
        ),
    };
    Resultat::nouveau(ID, debut, &constats, couverture)
}

fn juger(l: &Lecture) -> (Vec<Constat>, Couverture) {
    let Analyse {
        active,
        canal_24,
        canal_5,
        conseil_24,
        conseil_5,
        ..
    } = analyse(l);
    let mut constats = Vec::new();
    let mut non_verifies = Vec::new();
    let mut verifies = 0u32;
    let mut compter = |c: Constat, constats: &mut Vec<Constat>| {
        constats.push(c);
        verifies = verifies.saturating_add(1);
    };
    let non_verifie = tr!(
        "Canal le plus libre : non vérifié, la liste des voisins n'est pas sûre.",
        "Freest channel: not verified, the list of neighbors is not reliable."
    );
    if let Some(r) = &l.reserve {
        non_verifies.push(trf!("canal le plus libre : {r}", "freest channel: {r}"));
    }
    let signal = Objet::de("wifi", "signal");
    if let Some(a) = active {
        if let Some(s) = a.signal {
            let texte = trf!("Signal du Wi-Fi : {s} % ({}).", "Wi-Fi signal: {s}% ({}).", qualite(s));
            let c = if s < 50 {
                alerte(CAT, Niveau::Info, texte)
            } else {
                ok(CAT, texte)
            };
            compter(c.avec_objet(signal), &mut constats);
        } else {
            non_verifies.push(
                tr!(
                    "signal de la connexion : le système ne le donne pas",
                    "connection signal: the system does not give it"
                )
                .to_string(),
            );
        }
    } else {
        constats.push(
            sans_objet(
                CAT,
                Absence::Inactif,
                tr!(
                    "Pas connecté en Wi-Fi : les conseils valent pour votre routeur, s'il est à portée.",
                    "Not connected over Wi-Fi: the advice applies to your router, if it is within range."
                ),
            )
            .avec_objet(signal),
        );
        non_verifies.push(
            tr!(
                "canal du routeur : pas connecté en Wi-Fi, le routeur n'est pas reconnu parmi les réseaux entendus",
                "router channel: not connected over Wi-Fi, the router is not recognized among the networks heard"
            )
            .to_string(),
        );
    }
    let bande = Objet::de("bande", "2.4GHz");
    let texte = texte_24(&conseil_24, non_verifie);
    match conseil_24 {
        Conseil24::NonVerifie => constats.push(echoue(l, texte).avec_objet(bande)),
        Conseil24::DejaLibre => compter(ok(CAT, texte).avec_objet(bande), &mut constats),
        Conseil24::Chevauche(..) | Conseil24::PlusLibre(_) => {
            compter(alerte(CAT, Niveau::Info, texte).avec_objet(bande), &mut constats);
        }
        // Le routeur n'émet pas dans cette bande, ou n'y est pas reconnu : le canal libre n'est qu'une information.
        Conseil24::SansRouteur(_) => {
            debug_assert!(canal_24.is_none());
            constats.push(sans_objet(CAT, Absence::Inactif, texte).avec_objet(bande));
        }
    }
    if let Some((conseil, libre)) = conseil_5 {
        let bande = Objet::de("bande", "5GHz");
        let texte = texte_5(&conseil, libre, non_verifie);
        match conseil {
            Conseil5::NonVerifie => constats.push(echoue(l, texte).avec_objet(bande)),
            Conseil5::DejaLibre => compter(ok(CAT, texte).avec_objet(bande), &mut constats),
            Conseil5::Bloc(..) if canal_5.is_some() => {
                compter(alerte(CAT, Niveau::Info, texte).avec_objet(bande), &mut constats);
            }
            Conseil5::Bloc(..) => constats.push(sans_objet(CAT, Absence::Inactif, texte).avec_objet(bande)),
        }
    }
    (constats, Couverture { verifies, non_verifies })
}

/// Le conseil d'une liste de voisins douteuse : non vérifié, pour la raison de la lecture.
fn echoue(l: &Lecture, texte: String) -> Constat {
    let raison = l.reserve.clone().unwrap_or_else(|| texte.clone());
    impossible_par(CAT, Raison::Echoue(raison), texte)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::wifi::{Bande, Borne};

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn borne(ssid: &str, bande: Bande, canal: u16, signal: u8, actif: bool) -> Borne {
        Borne {
            ssid: ssid.into(),
            bssid: String::new(),
            bande,
            canal,
            signal: Some(signal),
            actif,
        }
    }

    fn lecture(bornes: Vec<Borne>, reserve: Option<&str>) -> Lecture {
        Lecture {
            bornes,
            note: None,
            reserve: reserve.map(String::from),
        }
    }

    #[test]
    fn illisible_non_verifie() {
        let r = resultat(Err("Réseaux Wi-Fi illisibles : essai.".into()), debut());
        assert_eq!(r.outil, ID);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
    }

    /// Bon signal, canal déjà le plus libre dans les deux bandes : sain, et aucun nom de réseau écrit.
    #[test]
    fn deja_libre_sain() {
        let l = lecture(
            vec![
                borne("Salon-essai", Bande::G24, 1, 80, true),
                borne("Salon-essai", Bande::G5, 149, 70, false),
                borne("Voisin-essai", Bande::G24, 11, 60, false),
                borne("Voisin-essai", Bande::G5, 36, 60, false),
            ],
            None,
        );
        let r = resultat(Ok(&l), debut());
        assert_eq!(r.verdict(), "sain", "{:?}", r.couverture);
        assert_eq!(r.couverture.verifies, 3);
        assert!(r.constats.iter().all(|c| !c.message.contains("essai")));
    }

    /// Un canal qui chevauche et un signal faible : des conseils, de niveau information.
    #[test]
    fn conseils_en_information() {
        let l = lecture(
            vec![
                borne("Salon", Bande::G24, 3, 30, true),
                borne("Voisin", Bande::G24, 6, 90, false),
            ],
            None,
        );
        let r = resultat(Ok(&l), debut());
        assert_eq!(r.verdict(), "probleme");
        assert!(r.constats.iter().all(|c| c.niveau.is_none_or(|n| n == Niveau::Info)));
        assert_eq!(r.constats.iter().filter(|c| c.niveau.is_some()).count(), 2);
    }

    /// Une liste de voisins trop vieille : aucun canal n'est dit libre, le conseil est non vérifié.
    #[test]
    fn liste_douteuse_non_verifiee() {
        let l = lecture(
            vec![
                borne("Salon", Bande::G24, 1, 80, true),
                borne("Salon", Bande::G5, 36, 80, false),
            ],
            Some("la liste des réseaux voisins date de 25 min"),
        );
        let r = resultat(Ok(&l), debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 1);
        assert_eq!(
            r.constats
                .iter()
                .filter(|c| c.raison.as_deref() == Some("echoue"))
                .count(),
            2
        );
    }

    /// Pas connecté : le routeur n'est pas reconnu, rien n'est jugé sur son canal.
    #[test]
    fn pas_connecte() {
        let l = lecture(vec![borne("Voisin", Bande::G24, 6, 50, false)], None);
        let r = resultat(Ok(&l), debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
    }
}
