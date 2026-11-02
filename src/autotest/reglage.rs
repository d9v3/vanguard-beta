//! L'auto-réglage local du bilan : ce que Vanguard ajuste de lui-même, sur cet ordinateur, d'après les durées
//! mesurées de ses règles (`super::mesures`). Rien ne sort de l'ordinateur, rien ne passe par une IA.
//!
//! Ce qui peut bouger : l'**ordre de départ** des règles, la plus longue d'abord (médiane de la semaine), pour que le
//! bilan ne finisse pas sur elle. Les règles tournent toutes en même temps, chacune dans son fil ; l'ordre ne change
//! ni ce qu'elles rendent ni l'ordre affiché (celui des rangs).
//!
//! Ce qui ne bouge **jamais** ici : un seuil, un niveau, une règle ou une liste de détection, le blocage, la fraîcheur
//! des sources de menaces ; un bilan lance toujours toutes ses règles. Ce module n'importe ni `risk` ni un module de
//! détection (garde : `reglage_ne_touche_pas_la_detection`).

use std::collections::BTreeMap;

/// L'ordre de départ : les positions de `ids` (une par vérification, `None` pour une vérification sans règle du
/// registre), la plus longue médiane d'abord. Une règle jamais mesurée part après les mesurées, dans l'ordre des
/// rangs, comme deux règles de même médiane. Toujours une permutation de `0..ids.len()` : aucune règle perdue ni
/// lancée deux fois.
pub(crate) fn ordre_de_depart(ids: &[Option<&str>], medianes: &BTreeMap<String, u64>) -> Vec<usize> {
    let mut ordre: Vec<usize> = (0..ids.len()).collect();
    let duree = |i: &usize| ids.get(*i).copied().flatten().and_then(|id| medianes.get(id)).copied();
    // Tri stable : à égalité (ou sans mesure), l'ordre des rangs reste.
    ordre.sort_by_key(|i| std::cmp::Reverse(duree(i)));
    ordre
}

/// `depart` s'il est une permutation de `0..n`, sinon l'ordre des rangs : un ordre faux ne fait jamais sauter ni
/// doubler une règle.
pub(crate) fn permutation_ou_rangs(depart: Vec<usize>, n: usize) -> Vec<usize> {
    let mut vus = vec![false; n];
    let juste = depart.len() == n
        && depart.iter().all(|&i| match vus.get_mut(i) {
            Some(v) if !*v => {
                *v = true;
                true
            }
            _ => false,
        });
    if juste { depart } else { (0..n).collect() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn medianes(paires: &[(&str, u64)]) -> BTreeMap<String, u64> {
        paires.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn la_plus_longue_d_abord_puis_les_rangs() {
        let ids = [Some("A"), None, Some("B"), Some("C"), Some("D")];
        let m = medianes(&[("B", 9_000), ("D", 9_000), ("A", 100)]);
        // B et D ex aequo : dans l'ordre des rangs ; A mesurée avant la vérification sans règle et C jamais mesurée.
        assert_eq!(ordre_de_depart(&ids, &m), vec![2, 4, 0, 1, 3]);
        assert_eq!(ordre_de_depart(&ids, &BTreeMap::new()), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn un_ordre_faux_rend_les_rangs() {
        assert_eq!(permutation_ou_rangs(vec![2, 0, 1], 3), vec![2, 0, 1]);
        assert_eq!(permutation_ou_rangs(vec![0, 0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1, 3], 3), vec![0, 1, 2]);
    }

    /// Le module ne nomme rien de la détection : ni niveau de risque, ni module de règles ou de protection.
    #[test]
    fn reglage_ne_touche_pas_la_detection() {
        let source = include_str!("reglage.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        for interdit in [
            "risk",
            "Niveau",
            "protection",
            "regles_communes",
            "seuil",
            "SEUIL",
            "blocage",
        ] {
            assert!(!code.contains(interdit), "reglage.rs nomme « {interdit} »");
        }
    }

    proptest! {
        /// Quelles que soient les mesures, l'ordre de départ lance chaque vérification une fois et une seule.
        #[test]
        fn toujours_une_permutation(
            n in 0usize..80,
            mesures in proptest::collection::btree_map("[A-C]{1,2}", any::<u64>(), 0..12),
            noms in proptest::collection::vec(proptest::option::of("[A-C]{1,2}"), 80),
        ) {
            let ids: Vec<Option<&str>> = noms.iter().take(n).map(Option::as_deref).collect();
            let mut ordre = ordre_de_depart(&ids, &mesures);
            prop_assert_eq!(permutation_ou_rangs(ordre.clone(), ids.len()), ordre.clone());
            ordre.sort_unstable();
            prop_assert_eq!(ordre, (0..ids.len()).collect::<Vec<_>>());
        }
    }
}
