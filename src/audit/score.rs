//! La note d'un domaine de l'audit du réseau, et celle de l'ensemble. Même règle qu'au bilan de la machine : 100
//! moins les pénalités des constats (`Niveau::penalite`), borné à 0 ; et pas de note quand plus du tiers des
//! vérifications n'a pas pu se faire (le garde-fou d'`Audit::fiable`), sinon un domaine peu vérifié obtiendrait un
//! « A » rassurant. La note de l'audit est la plus basse des six, et aucune dès qu'un domaine n'en a pas.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::Constat;
use crate::risk::Niveau;

/// 100 moins les pénalités des constats vérifiés, borné à 0.
pub fn score(constats: &[Constat]) -> u32 {
    100u32.saturating_sub(
        constats
            .iter()
            .filter(|c| c.verifie)
            .filter_map(|c| c.probleme)
            .map(Niveau::penalite)
            .sum(),
    )
}

/// Le nombre de vérifications qui n'ont pas pu se faire.
pub fn non_verifies(constats: &[Constat]) -> usize {
    constats.iter().filter(|c| !c.verifie).count()
}

/// La note du domaine, ou `None` quand un tiers ou plus des vérifications n'a pas pu se faire (ou sans aucun
/// constat) : on montre alors « incomplet » et la liste des non vérifiés.
pub fn noter(constats: &[Constat]) -> Option<u32> {
    (!constats.is_empty() && non_verifies(constats).saturating_mul(3) < constats.len()).then(|| score(constats))
}

/// La note de l'audit : la plus basse des domaines, aucune dès qu'un domaine n'en a pas.
pub fn globale(scores: &[Option<u32>]) -> Option<u32> {
    scores.iter().copied().try_fold(100, |min, s| Some(min.min(s?)))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{alerte, ok};

    fn impossible() -> Constat {
        crate::machine::impossible("Postes", "essai")
    }

    #[test]
    fn score_borne_et_sans_les_non_verifies() {
        let constats = vec![
            ok("Postes", "bien"),
            alerte("Postes", Niveau::Critique, "a"),
            alerte("Postes", Niveau::Moyen, "b"),
            alerte("Postes", Niveau::Info, "c"),
        ];
        assert_eq!(score(&constats), 65);
        let beaucoup: Vec<Constat> = (0..5).map(|_| alerte("Postes", Niveau::Critique, "a")).collect();
        assert_eq!(score(&beaucoup), 0);
        // Un constat non vérifié ne pèse pas, même s'il porte un niveau.
        let mut n = alerte("Postes", Niveau::Critique, "x");
        n.verifie = false;
        assert_eq!(score(&[n]), 100);
        assert_eq!(score(&[]), 100);
    }

    #[test]
    fn pas_de_note_au_dela_du_tiers() {
        assert_eq!(noter(&[]), None);
        assert_eq!(noter(&[impossible()]), None);
        // Un sur trois : un tiers, pas de note ; un sur quatre : une note.
        assert_eq!(noter(&[ok("Postes", "a"), ok("Postes", "b"), impossible()]), None);
        assert_eq!(
            noter(&[
                ok("Postes", "a"),
                ok("Postes", "b"),
                alerte("Postes", Niveau::Moyen, "c"),
                impossible()
            ]),
            Some(95)
        );
        assert_eq!(noter(&[ok("Postes", "a")]), Some(100));
    }

    #[test]
    fn note_globale_la_plus_basse() {
        assert_eq!(globale(&[Some(90), Some(40), Some(100)]), Some(40));
        assert_eq!(globale(&[Some(90), None]), None);
        assert_eq!(globale(&[]), Some(100));
    }
}
