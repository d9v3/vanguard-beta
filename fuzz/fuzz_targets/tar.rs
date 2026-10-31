//! Les archives tar téléchargées (archive des avis de sécurité de Mozilla, par codeload) et les bases de pacman :
//! noms longs (pax, GNU), tailles en octal, archives coupées.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

/// Les bornes du lecteur (`archives::Bornes`), à la place où il les attend.
#[derive(Clone, Copy)]
pub struct Bornes {
    pub entrees: usize,
    pub fichier: usize,
    pub total: usize,
}

#[allow(dead_code)]
#[path = "../../src/archives/tar.rs"]
mod tar;

const BORNES: Bornes = Bornes {
    entrees: 20_000,
    fichier: 1 << 20,
    total: 64 << 20,
};

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let _ = tar::fichiers(octets, &BORNES, |_| true);
    let _ = tar::fichiers(octets, &BORNES, |nom| nom.ends_with(".yml"));
});
