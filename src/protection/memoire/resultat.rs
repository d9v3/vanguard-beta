//! Le résultat de l'analyse de la mémoire des processus (`modele::resultat`, PRO-MEM-001), sans l'écran : chaque
//! correspondance et chaque masquage, et ce qui n'a pas pu être lu (processus fermés, lus en partie, images non
//! jugées, arrêt sur une borne). Rendu par `vanguard memoire --json` et versé au rapport. Rien trouvé dans une lecture
//! incomplète n'est jamais « sain ».

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::{Constat, alerte, impossible, impossible_par, ok};
use crate::modele::Raison;
use crate::modele::resultat::{Couverture, Resultat};
use crate::protection::yara::resultat::{Debut, INFOS_MAX, MANQUES_MAX, TROUVES_MAX, bornees};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-MEM-001";

const CAT: &str = "Mémoire des processus";

/// Ce que la lecture a relevé, en phrases prêtes à montrer (noms rendus affichables par l'appelant).
#[derive(Default, Debug)]
pub(crate) struct Releve {
    /// Les correspondances et les masquages : toujours élevés, à juger (un programme légitime peut porter une
    /// signature en mémoire).
    pub trouves: Vec<String>,
    /// Ce qui n'a pas pu être lu ou jugé.
    pub manques: Vec<String>,
    /// Ce qui est laissé par choix (Vanguard lui-même, LSASS, images du système) : dit, sans changer le verdict.
    pub notes: Vec<String>,
    /// Les processus lus : ce que l'analyse a vérifié.
    pub lus: usize,
}

/// Le résultat : une alerte par correspondance (bornées), sinon « rien trouvé » quand tout a été lu, ou « non vérifié ».
pub(crate) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    let trouves = bornees(&r.trouves, TROUVES_MAX, |n| {
        trf!(
            "{n} autre(s) correspondance(s), non détaillée(s) ici : l'analyse à l'écran les liste toutes.",
            "{n} other match(es), not detailed here: the on-screen scan lists them all."
        )
    });
    let mut constats: Vec<Constat> = trouves.into_iter().map(|t| alerte(CAT, Niveau::Eleve, t)).collect();
    if constats.is_empty() {
        constats.push(if r.manques.is_empty() && r.lus > 0 {
            ok(
                CAT,
                trf!(
                    "Aucune région de la mémoire des {} processus lus ne correspond aux règles (ce n'est pas une garantie).",
                    "No memory region of the {} processes read matches the rules (that is not a guarantee).",
                    r.lus
                ),
            )
        } else {
            impossible_par(
                CAT,
                Raison::Illisible(tr!("lecture incomplète", "incomplete read").to_string()),
                trf!(
                    "Rien trouvé dans les {} processus lus, mais la lecture est incomplète : rien n'est conclu pour le reste, non vérifié.",
                    "Nothing found in the {} processes read, but the read is incomplete: nothing is concluded for the rest, not verified.",
                    r.lus
                ),
            )
        });
    }
    constats.extend(
        bornees(&r.notes, INFOS_MAX, |n| {
            trf!(
                "Et {n} autre(s), non détaillé(s) ici.",
                "And {n} other(s), not detailed here."
            )
        })
        .into_iter()
        .map(|t| ok(CAT, t)),
    );
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: u32::try_from(r.lus).unwrap_or(u32::MAX),
            non_verifies: bornees(&r.manques, MANQUES_MAX, |n| {
                trf!(
                    "{n} autre(s) élément(s) non vérifié(s), non détaillé(s) ici.",
                    "{n} other item(s) not checked, not detailed here."
                )
            }),
        },
    )
}

/// Le résultat d'une analyse impossible (règles inutilisables) : rien de vérifié.
pub(crate) fn refuse(raison: &str, debut: Debut) -> Resultat {
    Resultat::nouveau(ID, debut, &[impossible(CAT, raison)], Couverture::default())
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

    /// Tout lu, rien trouvé : sain ; une note ne change rien ; un manque : non vérifié ; rien lu : non vérifié ; une
    /// correspondance : problème élevé ; un refus : non vérifié.
    #[test]
    fn trouve_rien_trouve_et_partiel() {
        let mut r = Releve {
            lus: 4,
            ..Releve::default()
        };
        r.notes.push("1 processus jamais lu, par choix".into());
        assert_eq!(resultat(&r, debut()).verdict(), "sain");
        r.manques.push("2 processus n'ont pas pu être lus".into());
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "non-verifie");
        assert_eq!(res.constats[0].etat, "non-verifie");
        assert_eq!(resultat(&Releve::default(), debut()).verdict(), "non-verifie");
        r.trouves.push("essai (PID 4242) : rançongiciel".into());
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(Niveau::Eleve));
        assert_eq!(refuse("règles inutilisables", debut()).verdict(), "non-verifie");
    }

    /// Les correspondances sont bornées, le reste compté.
    #[test]
    fn sortie_bornee() {
        let r = Releve {
            trouves: (0..TROUVES_MAX + 5).map(|i| format!("essai (PID {i})")).collect(),
            lus: 1,
            ..Releve::default()
        };
        let res = resultat(&r, debut());
        assert_eq!(res.constats.len(), TROUVES_MAX + 1);
        assert!(res.constats[TROUVES_MAX].message.starts_with("5 autre(s)"));
    }
}
