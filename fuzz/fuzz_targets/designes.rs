//! Les fichiers que désigne une ligne signalée (src/machine/linux/designes.rs), lus depuis n'importe quel texte :
//! commande de service ou de raccourci, valeur de LD_PRELOAD, ligne de configuration. Jamais de panique ; au plus
//! `CHEMINS_MAX` chemins (au moins un), chacun absolu, sans double, plus court que `CHEMIN_MAX`, sans caractère
//! interdit ni blanc trompeur (U+2003, U+00A0…), qui couperait les mots autrement que systemd et le shell.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/linux/designes.rs"]
mod designes;

use designes::{CHEMIN_MAX, CHEMINS_MAX, Contexte, Designe, Liste};

fn verifier(d: &Designe) {
    if let Designe::Chemins(liste) = d {
        assert!(!liste.is_empty() && liste.len() <= CHEMINS_MAX, "{liste:?}");
        for (i, p) in liste.iter().enumerate() {
            assert!(p.starts_with('/'), "{p:?}");
            assert!(p.len() <= CHEMIN_MAX, "{}", p.len());
            assert!(!p.contains(['\0', '\n', '\r', '$', '`']), "{p:?}");
            assert!(!p.contains(designes::trompeur) && !p.contains("//"), "{p:?}");
            assert!(!liste[..i].contains(p), "double : {p:?}");
        }
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let texte = String::from_utf8_lossy(octets);
    let (maison, ligne) = texte.split_once('\u{1}').unwrap_or(("/home/alice", &texte));
    for ctx in [Contexte::Unite(Some(maison)), Contexte::Unite(None), Contexte::Bureau, Contexte::Shell] {
        verifier(&designes::commande(ligne, ctx));
    }
    verifier(&designes::bibliotheques(ligne, Liste::Variable));
    verifier(&designes::bibliotheques(ligne, Liste::Fichier));
    verifier(&designes::prechargement(ligne));
});
