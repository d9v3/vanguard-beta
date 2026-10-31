//! Les archives lues par Vanguard, écrites pour le projet et sans commande externe (ni zcat, ni tar, ni unzip) :
//! gzip (`gzip`), tar (`tar`) et zip (`zip`). Ce qu'elles contiennent vient d'ailleurs (base d'un dépôt, fichier
//! téléchargé) : chaque lecteur est borné en taille et en nombre d'entrées, et rend `None` au lieu de paniquer.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

pub(crate) mod crc32;
pub(crate) mod deflate;
pub(crate) mod gzip;
pub(crate) mod tar;
pub(crate) mod zip;

/// Les bornes d'une lecture : entrées parcourues, taille d'un fichier rendu, taille de tout ce qui est rendu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bornes {
    pub entrees: usize,
    pub fichier: usize,
    pub total: usize,
}
