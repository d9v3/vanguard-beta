//! Le socle : ce dont tout Vanguard se sert sans rien savoir du réseau, de la protection ni du bilan. Une règle
//! commune (une adresse est-elle sur Internet ? où est le dossier personnel ? comment lire /proc ?) vit ici une
//! fois, testée une fois, au lieu d'être recopiée dans chaque module avec ses petites différences.

pub(crate) mod adresses;
pub(crate) mod cache;
mod fichiers;
pub(crate) mod hachage;
#[cfg(unix)]
mod identite;
pub(crate) mod jsonc;
pub(crate) mod personnel;
#[cfg(unix)]
pub(crate) mod processus;
#[cfg(target_os = "linux")]
pub(crate) mod relro;
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
#[cfg(target_os = "linux")]
pub(crate) use identite::compte_d_en_face;
#[cfg(unix)]
pub(crate) use identite::{euid, uid};
#[cfg(unix)]
pub use personnel::volume;
pub use personnel::{maison, taille_lisible};

/// Remet chaque octet à zéro par des écritures que le compilateur ne peut pas retirer : un simple `fill(0)` juste
/// avant la libération est une écriture sans lecteur, qu'il a le droit de supprimer.
// écritures volatiles (std::ptr::write_volatile) : l'effacement des secrets.
#[allow(unsafe_code)]
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaque longueur autour des blocs de 64 octets est remise à zéro, et seulement elle : les octets voisins, hors
    /// de la tranche donnée, restent tels quels. Lancé sous Miri (outils/preuves.sh) : les deux écritures volatiles
    /// y sont vérifiées (adresse, alignement, bornes).
    #[test]
    fn effacer_remet_la_tranche_a_zero_et_rien_d_autre() {
        for n in [0, 1, 63, 64, 65, 128, 130] {
            let mut tampon = vec![0xA5u8; n + 2];
            if let Some(milieu) = tampon.get_mut(1..=n) {
                effacer(milieu);
            }
            assert_eq!(tampon[0], 0xA5, "{n}");
            assert_eq!(tampon[n + 1], 0xA5, "{n}");
            assert!(tampon[1..=n].iter().all(|&o| o == 0), "{n}");
        }
    }

    /// Les structures C que Vanguard remet à zéro par `std::mem::zeroed` avant de les confier au système (Linux,
    /// macOS) : zéro doit être une valeur permise pour chacune (aucune référence, aucun pointeur de fonction non nul,
    /// aucune énumération sans variante nulle). Sous Miri, une valeur interdite est une erreur ; la liste suit
    /// `grep -rn 'mem::zeroed' src`, une structure ajoutée là s'ajoute ici (celles de Windows : leurs modules).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn structures_c_mises_a_zero() {
        // std::mem::zeroed : l'essai (sous Miri) des structures C mises à zéro.
        #[allow(unsafe_code)]
        fn zero<T>() -> T {
            // SAFETY: c'est précisément ce que vérifie l'essai, sous Miri : zéro est une valeur permise de `T`.
            unsafe { std::mem::zeroed() }
        }
        let _: libc::statfs = zero();
        let _: libc::group = zero();
        let _: libc::passwd = zero();
        #[cfg(target_os = "linux")]
        {
            let _: libc::siginfo_t = zero();
            let _: libc::statvfs = zero();
            let _: libc::iwreq = zero();
            let _: libc::timex = zero();
            let _: libc::sockaddr_nl = zero();
            let _: libc::utsname = zero();
            let _: libc::sigaction = zero();
            let _: [libc::sigaction; 2] = zero();
        }
        #[cfg(target_os = "macos")]
        {
            let _: libc::proc_bsdinfo = zero();
        }
    }
}
