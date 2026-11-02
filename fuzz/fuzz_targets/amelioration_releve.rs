//! La relecture du fichier du jour du relevé local (src/amelioration/releve.rs) : le programme relit
//! `amelioration/jours/AAAA-MM-JJ.json` sans confiance (un fichier abîmé ou trafiqué sur le disque). Jamais de
//! panique ; un jour relu se réécrit en 96 Kio au plus, se relit égal à ce qu'il écrit et se réécrit à l'identique.
//! Modules purs (les champs, la voie ouverte, le lot, le relevé), inclus sans cale.
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

#[allow(dead_code)]
#[path = "../../src/amelioration/releve.rs"]
mod releve;

// Les chemins du programme (`crate::compte_rendu::…`, `crate::amelioration::texte`) retrouvés ici.
mod compte_rendu {
    pub(crate) use crate::{champs, envoi};
}
mod amelioration {
    pub(crate) use crate::texte;
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let jour = releve::lire(octets);
    let ecrit = releve::Brouillon::de(&jour).ecrire();
    assert!(ecrit.len() <= releve::JOUR_MAX, "{} octets", ecrit.len());
    let relu = releve::lire(&ecrit);
    let mut brouillon = releve::Brouillon::de(&relu);
    assert_eq!(brouillon.releve(), relu, "un jour écrit ne se relit pas égal");
    assert_eq!(brouillon.ecrire(), ecrit, "deux écritures pour un même jour");
});
