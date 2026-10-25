//! Les cas du corpus de détection propres à macOS (`modele::corpus`) : ils tournent sur le Mac de GitHub
//! (macos.yml), les données fabriquées données aux fonctions de jugement de parite.rs.

use crate::machine::Constat;
use crate::modele::corpus::{Entree, Juge};

pub(crate) const CAS: &[(&str, Juge)] = &[("MAC-PRS-002", elements_d_ouverture), ("MAC-PRS-003", crochets)];

/// MAC-PRS-002 : la sortie de « sfltool dumpbtm » telle quelle, lue en root.
fn elements_d_ouverture(e: &Entree) -> Vec<Constat> {
    super::parite::juger_btm(Some(&e.texte), true)
}

/// MAC-PRS-003 : `hook|crochet|script` et `extension|nom` (les extensions d'autorisation de tiers).
fn crochets(e: &Entree) -> Vec<Constat> {
    let hooks: Vec<(String, String)> = e
        .de("hook")
        .iter()
        .map(|c| (c[0].to_string(), c[1].to_string()))
        .collect();
    let extensions: Vec<String> = e.de("extension").iter().map(|c| c[0].to_string()).collect();
    super::parite::juger_crochets(&hooks, Some(&extensions), Some(&[]), &[])
}
