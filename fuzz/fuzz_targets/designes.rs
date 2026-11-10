//! Les fichiers que désigne une ligne signalée (src/machine/linux/designes.rs), lus depuis n'importe quel texte :
//! commande de service ou de raccourci, valeur de LD_PRELOAD, ligne de configuration. Jamais de panique ; au plus
//! `CHEMINS_MAX` chemins, chacun absolu, sans double, plus court que `CHEMIN_MAX`, sans caractère interdit.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/linux/designes.rs"]
mod designes;

use designes::{CHEMIN_MAX, CHEMINS_MAX, Designe};

fn verifier(d: &Designe) {
    if let Designe::Chemins(liste) = d {
        assert!(liste.len() <= CHEMINS_MAX, "{liste:?}");
        for (i, p) in liste.iter().enumerate() {
            assert!(p.starts_with('/'), "{p:?}");
            assert!(p.len() <= CHEMIN_MAX, "{}", p.len());
            assert!(!p.contains(['\0', '\n', '\r', '$', '`']), "{p:?}");
            assert!(!liste[..i].contains(p), "double : {p:?}");
        }
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let texte = String::from_utf8_lossy(octets);
    let (maison, ligne) = texte.split_once('\u{1}').unwrap_or(("/home/alice", &texte));
    verifier(&designes::commande(ligne, maison));
    verifier(&designes::bibliotheques(ligne, Some(maison)));
    verifier(&designes::bibliotheques(ligne, None));
    verifier(&designes::prechargement(ligne, maison));
});
