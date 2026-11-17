//! Le socle : ce dont tout Vanguard se sert sans rien savoir du réseau, de la protection ni du bilan. Une règle
//! commune (une adresse est-elle sur Internet ? où est le dossier personnel ? comment lire /proc ?) vit ici une
//! fois, testée une fois, au lieu d'être recopiée dans chaque module avec ses petites différences.

pub(crate) mod adresses;
pub(crate) mod cache;
pub(crate) mod canal_stdio;
pub(crate) mod chemins;
mod fichiers;
pub(crate) mod fil;
pub(crate) mod hachage;
#[cfg(unix)]
mod identite;
pub(crate) mod jsonc;
pub(crate) mod nombres;
pub(crate) mod personnel;
#[cfg(unix)]
pub(crate) mod processus;
// 64 bits seulement : il lit les en-têtes en Elf64_Phdr, et seul un programme x86-64 est livré.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod relro;
pub(crate) mod systeme;
// Linux et Windows seulement : la descente sans lien de la Console (openat ; FILE_FLAG_OPEN_REPARSE_POINT).
#[cfg(any(target_os = "linux", windows))]
pub(crate) mod ouvrir_console;
pub(crate) mod valeur_console;

pub use fichiers::dossier_local;
#[cfg(all(unix, test))]
pub(crate) use fichiers::ecriture_sure_pour;
#[cfg(unix)]
pub(crate) use fichiers::lire_ordinaire_au_bout;
#[cfg(unix)]
pub use fichiers::proteger_dossier_local;
pub(crate) use fichiers::{
    ATTENTE_ECRITURE, ATTENTE_LECTURE, SansVerrou, Verrou, du_systeme, ecrire_atomique, ecrire_atomique_date,
    ecriture_sure, lire_ordinaire, lire_texte_ordinaire, nom_systeme, ouvrir_ordinaire, parcourir_ordinaire,
    refus_du_systeme, verrou_remplace,
};
#[cfg(target_os = "linux")]
pub(crate) use identite::compte_d_en_face;
#[cfg(unix)]
pub(crate) use identite::{ecrivable, euid, uid};
#[cfg(unix)]
pub use personnel::volume;
pub use personnel::{maison, taille_lisible};
pub(crate) use personnel::{maison_du_compte, maison_inconnue};

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

/// Un nom de fichier prêt à montrer : tel quel en UTF-8 ; sinon chaque octet qui n'en est pas s'écrit `\xFF`. Converti
/// avec pertes (`to_string_lossy`), deux noms différents se montraient pareils (U+FFFD) ; ici ils restent distincts.
/// Pour l'affichage seulement : on compare et on ouvre avec le vrai nom (`OsStr`).
pub(crate) fn nom_montre(nom: &std::ffi::OsStr) -> String {
    use std::fmt::Write as _;
    if let Some(texte) = nom.to_str() {
        return texte.to_string();
    }
    let mut montre = String::new();
    for morceau in nom.as_encoded_bytes().utf8_chunks() {
        montre.push_str(morceau.valid());
        for octet in morceau.invalid() {
            let _ = write!(montre, "\\x{octet:02X}");
        }
    }
    montre
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Relecture 0.94 : un nom qui n'est pas en UTF-8 se montre échappé, distinct d'un autre ; en UTF-8, tel quel.
    #[cfg(unix)]
    #[test]
    fn nom_pas_en_utf8_montre_echappe() {
        use std::os::unix::ffi::OsStrExt;
        let (a, b) = (
            std::ffi::OsStr::from_bytes(b"cl\xE9.verrou"),
            std::ffi::OsStr::from_bytes(b"cl\xEA.verrou"),
        );
        assert_eq!(nom_montre(a), "cl\\xE9.verrou");
        assert_ne!(nom_montre(a), nom_montre(b));
        assert_eq!(nom_montre(std::ffi::OsStr::new("clé.verrou")), "clé.verrou");
    }

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

    /// Les structures C que Vanguard remet à zéro par `std::mem::zeroed` avant de les confier au système (Linux) : zéro
    /// doit être une valeur permise pour chacune (aucune référence, aucun pointeur de fonction non nul, aucune
    /// énumération sans variante nulle). Sous Miri, une valeur interdite est une erreur ; la liste suit `grep -rn
    /// 'mem::zeroed' src`, une structure ajoutée là s'ajoute ici (celles de Windows : leurs modules).
    #[cfg(target_os = "linux")]
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
    }
}
