//! Le socle : ce dont tout Vanguard se sert sans rien savoir du réseau, de la protection ni du bilan. Une règle
//! commune (une adresse est-elle sur Internet ? où est le dossier personnel ? comment lire /proc ?) vit ici une
//! fois, testée une fois, au lieu d'être recopiée dans chaque module avec ses petites différences.

pub(crate) mod adresses;
pub(crate) mod cache;
mod fichiers;
pub(crate) mod hachage;
pub(crate) mod jsonc;
pub(crate) mod personnel;
#[cfg(unix)]
pub(crate) mod processus;
pub(crate) mod systeme;

pub use fichiers::dossier_local;
#[cfg(all(unix, test))]
pub(crate) use fichiers::ecriture_sure_pour;
#[cfg(unix)]
pub use fichiers::proteger_dossier_local;
pub(crate) use fichiers::{
    ATTENTE_ECRITURE, ATTENTE_LECTURE, SansVerrou, Verrou, ecrire_atomique, ecrire_atomique_date, ecriture_sure,
    lire_ordinaire, lire_texte_ordinaire, nom_systeme, verrou_remplace,
};
#[cfg(unix)]
pub use personnel::volume;
pub use personnel::{maison, taille_lisible};
