//! Le résultat de « Pourquoi c'est lent ? » (`modele::resultat`) : le jugement d'un instantané, sans l'écran. Versé
//! au rapport (`examens/PRO-LEN-001.json`), au journal des événements, et rendu par `--json`.
//!
//! Chaque conseil de l'écran devient un constat : un avertissement (⚠) un problème moyen, un conseil (l'ampoule) une
//! information. Une mesure qui manque (processeur, mémoire, disque, place, démarrage, durée allumée) est dite non
//! vérifiée : « rien ne force » ne vaut que pour ce qui a été mesuré.

use super::{Instantane, conseils, mesure_complete};
use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-LEN-001";

const CAT: &str = "Santé";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un instantané commencé à `debut` : ses conseils en constats, et ce qui a pu être mesuré. Les
/// programmes lancés à l'ouverture de session ne comptent pas parmi les points vérifiés : une liste vide ne dit pas
/// si elle a été lue ; ils ne parlent qu'au-delà d'un seuil, par leur conseil.
pub(super) fn resultat(i: &Instantane, debut: Debut) -> Resultat {
    let mut verifies = 0u32;
    let mut non_verifies = Vec::new();
    let mut constats: Vec<Constat> = Vec::new();
    let mut point = |mesure: bool, manque: &str| {
        if mesure {
            verifies += 1;
        } else {
            non_verifies.push(manque.to_string());
        }
    };
    point(
        i.processeur.is_some(),
        tr!("processeur non mesuré", "processor not measured"),
    );
    point(i.memoire.is_some(), tr!("mémoire non mesurée", "memory not measured"));
    point(
        i.disque.is_some(),
        tr!(
            "activité du disque non mesurable ici",
            "disk activity not measurable here"
        ),
    );
    point(
        i.place.is_some(),
        tr!(
            "place libre du disque du système non lue",
            "free space on the system disk not read"
        ),
    );
    point(
        i.allume_depuis.is_some(),
        tr!("durée depuis le démarrage non lue", "time since startup not read"),
    );
    match &i.demarrage {
        Ok(_) => verifies += 1,
        // macOS ne note pas la durée de son démarrage : rien à juger, ce n'est pas une lecture qui a échoué.
        Err(raison) if cfg!(target_os = "macos") => {
            constats.push(sans_objet(CAT, Absence::Plateforme, raison.clone()));
        }
        Err(raison) => non_verifies.push(trf!("durée du démarrage : {raison}", "startup duration: {raison}")),
    }
    let conseils = conseils(i);
    for k in &conseils {
        let niveau = if k.grave { Niveau::Moyen } else { Niveau::Info };
        constats.push(alerte(CAT, niveau, k.texte.clone()).avec_objet(Objet::de("mesure", k.sujet)));
    }
    if conseils.is_empty() {
        constats.push(if mesure_complete(i) {
            ok(
                CAT,
                tr!(
                    "Rien ne force en ce moment : si c'est lent par moments, relancez la mesure à ce moment-là.",
                    "Nothing is straining right now: if it is slow at times, run the measurement again at that moment."
                ),
            )
        } else {
            impossible_par(
                CAT,
                Raison::Illisible(
                    tr!("processeur ou mémoire non mesurés", "processor or memory not measured").to_string(),
                ),
                tr!(
                    "Mesure incomplète (processeur ou mémoire non mesurés) : rien n'est conclu, non vérifié.",
                    "Incomplete measurement (processor or memory not measured): nothing concluded, not verified."
                ),
            )
        });
    }
    Resultat::nouveau(ID, debut, &constats, Couverture { verifies, non_verifies })
}

#[cfg(test)]
mod tests {
    use super::super::Demarrage;
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Rien de mesuré : jamais sain.
    #[test]
    fn rien_de_mesure_non_verifie() {
        let r = resultat(&Instantane::default(), debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert!(r.constats.iter().any(|c| c.etat == "non-verifie"));
    }

    fn complet() -> Instantane {
        Instantane {
            processeur: Some(12.0),
            memoire: Some((16 << 30, 8 << 30)),
            disque: Some(3.0),
            place: Some((200 << 30, 500 << 30)),
            allume_depuis: Some(3600),
            demarrage: Ok(Demarrage {
                total: 20.0,
                etapes: String::new(),
                lents: Vec::new(),
            }),
            ..Instantane::default()
        }
    }

    #[test]
    fn tout_mesure_rien_ne_force() {
        let r = resultat(&complet(), debut());
        assert_eq!(r.couverture.verifies, 6);
        assert_eq!(r.verdict(), "sain");
    }

    /// La mémoire presque pleine est un avertissement à l'écran : un problème moyen, sur la mémoire.
    #[test]
    fn memoire_presque_pleine() {
        let i = Instantane {
            memoire: Some((16 << 30, 1 << 29)),
            ..complet()
        };
        let r = resultat(&i, debut());
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(r.pire(), Some(Niveau::Moyen));
        assert_eq!(r.constats[0].objet.as_deref(), Some("mesure:memoire"));
    }
}
