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

/// Remet chaque octet à zéro par des écritures que le compilateur ne peut pas retirer : un simple `fill(0)` juste
/// avant la libération est une écriture sans lecteur, qu'il a le droit de supprimer.
pub(crate) fn effacer(octets: &mut [u8]) {
    let (blocs, reste) = octets.as_chunks_mut::<64>();
    for bloc in blocs {
        // SAFETY: `bloc` vient d'une référence exclusive : adresse valide, alignée (octets), initialisée, à nous seuls.
        unsafe { std::ptr::write_volatile(bloc, [0; 64]) };
    }
    for octet in reste {
        // SAFETY: comme plus haut, un seul octet.
        unsafe { std::ptr::write_volatile(octet, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
