//! La progression que `vanguard` écrit sur sa sortie des erreurs pour la fenêtre (fenetre/src/progression.rs) : quoi
//! qu'arrive sur ce tuyau, une ligne n'est une étape que de la forme exacte `@etape <fait>/<total> <libellé>`, avec
//! 1 ≤ total ≤ 9999, fait ≤ total, et un libellé nettoyé (sans caractère piégé), borné. Rien ne panique, la part faite
//! reste entre 0 et 1. Le premier octet choisit la langue.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (fenetre/src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../fenetre/src/langue.rs"]
mod langue;

#[allow(dead_code)]
#[path = "../../fenetre/src/nettoyage.rs"]
mod nettoyage;

#[allow(dead_code)]
#[path = "../../fenetre/src/progression.rs"]
mod progression;

use progression::{LIBELLE_MAX, NOMBRE_MAX, PREFIXE};

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, reste)) = donnees.split_first() else { return };
    langue::choisir(Some(langue & 1 == 1));
    let brut = String::from_utf8_lossy(reste);
    for ligne in std::iter::once(brut.as_ref()).chain(brut.lines()) {
        let Some(e) = progression::lire(ligne) else { continue };
        assert!(ligne.starts_with(PREFIXE), "{ligne:?}");
        assert!(e.total >= 1 && e.total <= NOMBRE_MAX && e.fait <= e.total, "{e:?}");
        assert!(e.libelle.chars().count() <= LIBELLE_MAX, "{e:?}");
        for c in e.libelle.chars() {
            assert!(nettoyage::rendu(c) == Some(c), "caractère piégé U+{:04X}", u32::from(c));
        }
        // Les nombres lus sont ceux écrits, en décimal sans zéro en tête.
        assert!(ligne.starts_with(&format!("{PREFIXE}{}/{}", e.fait, e.total)), "{ligne:?} → {e:?}");
        let part = e.part();
        assert!((0.0..=1.0).contains(&part), "{part}");
    }
});
