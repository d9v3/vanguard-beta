//! Le journal de l'Agent Vanguard (src/agent/journal.rs) : des lignes JSON chaînées, lues depuis n'importe quels
//! octets (ligne changée, retirée, texte libre, champ en trop, décision inconnue, journal démesuré). Rien n'est cru
//! d'une ligne qui n'est pas une entrée ; un journal rompu se voit ; ce que l'agent écrit se relit intact, tient dans
//! 1 Mio et ne garde rien de plus de 90 jours. L'empreinte est SHA-256 ici (BLAKE3 dans Vanguard) : la fonction est
//! un paramètre du module.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

// Chaque module y lit ses voisins par `super::`, ici la racine de la cible.
#[allow(dead_code)]
#[path = "../../src/agent/forme.rs"]
mod forme;
#[allow(dead_code)]
#[path = "../../src/agent/decision.rs"]
mod decision;
#[allow(dead_code)]
#[path = "../../src/agent/journal.rs"]
mod journal;

use journal::Fait;
use sha2::Digest;

fn h(o: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(o).into()
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let lu = journal::lire_de(octets, h);
    let lignes = octets.split(|&o| o == b'\n').filter(|l| !l.is_empty()).count();
    if octets.len() <= journal::TAILLE_MAX {
        assert_eq!(lu.entrees.len() + lu.refusees, lignes);
    }
    // L'agent n'écrit qu'après un journal intact : la suite se relit intacte, bornée.
    if lu.intact() {
        let quand = lu.entrees.last().map_or(1_800_000_000, |e| e.quand).saturating_add(60);
        let faits: Vec<Fait> = lu.entrees.iter().rev().take(3).map(|e| e.fait).chain([Fait::ToutRemis]).collect();
        let o = journal::ajouter(lu.entrees.clone(), &faits, quand, h);
        assert!(o.len() <= journal::TAILLE_MAX);
        let relu = journal::lire_de(&o, h);
        assert!(relu.intact(), "{relu:?}");
        assert_eq!(relu.entrees.last().map(|e| e.fait), Some(Fait::ToutRemis));
        let limite = quand.saturating_sub(journal::JOURS_GARDES * 86_400);
        assert!(relu.entrees.iter().all(|e| e.quand >= limite));
    }
});
