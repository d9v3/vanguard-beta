//! La lecture du lot d'envoi de schéma 2 (src/compte_rendu/envoi.rs) : le relais et les outils de nuit relisent des
//! octets venus d'un ordinateur qu'ils ne connaissent pas. Jamais de panique ; un lot lu tient dans 96 Kio, se relit
//! égal et se réécrit à l'identique (une seule écriture par lot). Modules purs (les champs, la voie ouverte, le
//! lot), inclus sans cale.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/compte_rendu/champs.rs"]
mod champs;

#[allow(dead_code)]
#[path = "../../src/amelioration/texte.rs"]
mod texte;

#[allow(dead_code)]
#[path = "../../src/compte_rendu/envoi.rs"]
mod envoi;

// Les chemins du programme (`crate::compte_rendu::champs`, `crate::amelioration::texte`) retrouvés ici.
mod compte_rendu {
    pub(crate) use crate::champs;
}
mod amelioration {
    pub(crate) use crate::texte;
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(lot) = envoi::lire(octets) else {
        return;
    };
    let ecrit = lot.ecrire();
    assert!(ecrit.len() <= envoi::LOT_MAX, "{} octets", ecrit.len());
    let relu = envoi::lire(&ecrit).expect("un lot lu se relit");
    assert_eq!(relu, lot);
    assert_eq!(relu.ecrire(), ecrit, "deux écritures pour un même lot");
});
