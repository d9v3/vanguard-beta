//! La découpe d'une liste de correctifs, commune à Windows (`gestes`, le processus élevé) et à Linux et macOS
//! (`machine::lancer_les_ordres`, l'assistant élevé) : où chaque correctif passe des lignes natives de Vanguard (des
//! gestes relus par celui qui agit) au reste (PowerShell sous Windows, bash ailleurs). Du code pur, lu aussi par le
//! banc de fuzzing (fuzz/fuzz_targets/gestes.rs et gestes_unix.rs).

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Un morceau d'une liste de correctifs : une suite de lignes natives (chacune désignée par son correctif et sa
/// place), ou un script fait des autres lignes qui se suivent (PowerShell sous Windows, bash ailleurs), correctif par
/// correctif.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Morceau {
    Natif(Vec<(usize, usize)>),
    Script(Vec<(usize, Vec<usize>)>),
}

/// Découpe des correctifs en morceaux, dans l'ordre : chaque correctif est coupé là où il passe du natif au reste
/// (sous Windows, le point de restauration en tête d'une réparation devient ainsi un geste natif à lui seul, avant le
/// script). Le résultat d'un correctif est le ET de ses morceaux ; un correctif vide n'en a aucun (rien à faire).
pub(crate) fn decouper(correctifs: &[Vec<String>], natif: impl Fn(&str) -> bool) -> Vec<Morceau> {
    let mut morceaux: Vec<Morceau> = Vec::new();
    for (i, c) in correctifs.iter().enumerate() {
        for (j, l) in c.iter().enumerate() {
            if natif(l) {
                match morceaux.last_mut() {
                    Some(Morceau::Natif(v)) => v.push((i, j)),
                    _ => morceaux.push(Morceau::Natif(vec![(i, j)])),
                }
                continue;
            }
            match morceaux.last_mut() {
                Some(Morceau::Script(v)) => match v.last_mut() {
                    Some((k, suite)) if *k == i => suite.push(j),
                    _ => v.push((i, vec![j])),
                },
                _ => morceaux.push(Morceau::Script(vec![(i, vec![j])])),
            }
        }
    }
    morceaux
}
