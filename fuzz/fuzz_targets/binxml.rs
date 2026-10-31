//! Le BinXml des journaux .evtx seul (src/journaux_windows/evtx/binxml.rs), sans les CRC qui écartent presque tout
//! morceau fabriqué au hasard : noms et définitions de gabarits désignés à n'importe quelle position du morceau,
//! jetons inattendus, gabarits qui se contiennent, imbrications et substitutions démultipliées.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/journaux_windows/evtx/mod.rs"]
mod evtx;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // Les deux premiers octets : où commence l'enregistrement dans le morceau ; le reste : le morceau.
    let (Some(&a), Some(&b)) = (octets.first(), octets.get(1)) else { return };
    let morceau = &octets[2..];
    let debut = usize::from(u16::from_le_bytes([a, b])) % (morceau.len() + 1);
    let bornes = evtx::Bornes {
        noeuds: 512,
        travail: 20_000,
        texte: 4096,
        texte_enregistrement: 1 << 16,
        ..evtx::Bornes::default()
    };
    let _ = evtx::rendre_binxml(morceau, debut, &bornes);
});
