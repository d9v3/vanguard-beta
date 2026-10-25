//! Les cas du corpus de détection propres à macOS (`modele::corpus`) : ils tournent sur le Mac de GitHub
//! (macos.yml), les données fabriquées données aux fonctions de jugement de parite.rs.

use crate::machine::Constat;
use crate::modele::corpus::{Entree, Juge};

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("MAC-PRS-001", agents),
    ("MAC-PRS-002", elements_d_ouverture),
    ("MAC-PRS-003", crochets),
    ("MAC-PRV-002", sudo),
    ("MAC-SYS-003", extensions),
];

/// MAC-PRS-001 : le texte d'un fichier d'agent (plist XML), posé dans un dossier LaunchAgents jetable et lu comme au
/// bilan.
fn agents(e: &Entree) -> Vec<Constat> {
    let dossier = e.jetable("LaunchAgents");
    std::fs::write(dossier.join("com.exemple.corpus.plist"), &e.texte).unwrap();
    super::persistance::persistance_dans([(dossier.to_path_buf(), false)])
}

/// MAC-PRV-002 : la sortie de « sudo -n -l ».
fn sudo(e: &Entree) -> Vec<Constat> {
    crate::machine::unix::juger_sudo(&e.texte, super::privileges::tout_permis())
}

/// MAC-SYS-003 : `noyau|ligne de kmutil showloaded` et `systeme|ligne de systemextensionsctl list` (champs séparés
/// par des tabulations, écrites « \t »).
fn extensions(e: &Entree) -> Vec<Constat> {
    let texte = |genre: &str| -> String {
        e.de(genre)
            .iter()
            .map(|c| c.join("|").replace("\\t", "\t"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    vec![super::durcissement::juger_extensions(
        &texte("noyau"),
        &texte("systeme"),
    )]
}

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
