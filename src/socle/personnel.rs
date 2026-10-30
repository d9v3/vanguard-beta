//! Le dossier personnel du compte, et la place sur les disques : lus par le nettoyage d'abord, d'où leur ancienne
//! place dans `nettoyer`, mais demandés partout (bilan, traces d'incident, protection, Gaming). Le dossier
//! personnel était relu dans une quarantaine d'endroits, chacun avec sa règle quand HOME manque.

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use crate::{tr, trf};

/// Un mégaoctet : en dessous, « moins de 1 Mo ».
const MEGA: u64 = 1 << 20;

/// Le dossier personnel du compte : HOME quand c'est un chemin complet, sinon (HOME vide, relatif ou absent : un
/// service, un `env -i`) celui que la base des comptes donne au compte, sous Linux et macOS ; sous Windows,
/// USERPROFILE quand HOME manque. `None` : aucun des deux, jamais un chemin vide, qui se lirait depuis le dossier
/// courant.
pub(crate) fn dossier_personnel() -> Option<PathBuf> {
    let complet = |v: std::ffi::OsString| Some(PathBuf::from(v)).filter(|d| d.is_absolute());
    let home = std::env::var_os("HOME").and_then(complet);
    #[cfg(unix)]
    // SAFETY: getuid lit le compte du processus, sans argument ni échec possible.
    let repli = || dossier_personnel_de(unsafe { libc::getuid() }).filter(|d| d.is_absolute());
    #[cfg(windows)]
    let repli = || std::env::var_os("USERPROFILE").and_then(complet);
    home.or_else(repli)
}

/// `dossier_personnel`, pour qui y joint un sous-dossier et lit ce qui s'y trouve : un chemin vide quand il n'y en a
/// aucun (ce que faisaient toutes les copies), qui ne mène qu'à des lectures ratées, dites par chacun.
pub fn maison() -> PathBuf {
    dossier_personnel().unwrap_or_default()
}

/// Le dossier personnel du compte `uid`, d'après la base des comptes du système.
#[cfg(unix)]
pub(crate) fn dossier_personnel_de(uid: libc::uid_t) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let mut tampon: Vec<libc::c_char> = vec![0; 16 << 10];
    // SAFETY: passwd n'a que des entiers et des pointeurs, valides à zéro ; getpwuid_r les remplit.
    let mut compte: libc::passwd = unsafe { std::mem::zeroed() };
    let mut trouve: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `compte`, `tampon` (avec sa vraie longueur) et `trouve` vivent jusqu'à la fin de la fonction ;
    // getpwuid_r n'écrit que dans eux.
    let r = unsafe { libc::getpwuid_r(uid, &raw mut compte, tampon.as_mut_ptr(), tampon.len(), &raw mut trouve) };
    if r != 0 || trouve.is_null() || compte.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir pointe dans `tampon`, encore vivant, et getpwuid_r l'a terminé par un zéro.
    let dossier = unsafe { std::ffi::CStr::from_ptr(compte.pw_dir) };
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(dossier.to_bytes())))
}

/// « 1.2 Go », « 340 Mo ».
pub fn taille_lisible(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // une taille affichée à un chiffre après la virgule
    let f = octets as f64;
    if octets >= 1 << 30 {
        trf!("{} Go", "{} GB", crate::langue::decimal(f / f64::from(1u32 << 30), 1))
    } else if octets >= MEGA {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        tr!("moins de 1 Mo", "less than 1 MB").into()
    }
}

/// Le volume qui contient `chemin`, vu par statvfs.
#[cfg(unix)]
pub(crate) fn statvfs(chemin: &Path) -> Option<libc::statvfs> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(chemin.as_os_str().as_bytes()).ok()?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` est une chaîne C valide pendant tout l'appel ; statvfs remplit `s` en entier quand elle réussit
    // (retour 0), et `s` n'est lue qu'après.
    unsafe {
        if libc::statvfs(c.as_ptr(), s.as_mut_ptr()) != 0 {
            return None;
        }
        Some(s.assume_init())
    }
}

/// Place libre et taille du volume qui contient `chemin`, en octets.
#[cfg(unix)]
pub fn volume(chemin: &Path) -> Option<(u64, u64)> {
    let s = statvfs(chemin)?;
    #[allow(clippy::useless_conversion)] // les types de statvfs changent d'un système à l'autre
    let bloc = u64::from(s.f_frsize);
    // Plafonnés comme les tailles de fichiers : un volume réseau ou FUSE (sshfs) dit ce que son serveur veut.
    #[allow(clippy::useless_conversion)]
    Some((
        u64::from(s.f_bavail).saturating_mul(bloc),
        u64::from(s.f_blocks).saturating_mul(bloc),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossier_personnel_toujours_complet() {
        // Les tests tournent sous un vrai compte : HOME ou la base des comptes donne un chemin complet.
        assert!(dossier_personnel().is_some_and(|d| d.is_absolute()));
        assert_eq!(maison(), dossier_personnel().unwrap());
    }

    #[test]
    fn tailles_lisibles() {
        assert_eq!(taille_lisible(0), "moins de 1 Mo");
        assert_eq!(taille_lisible(340 << 20), "340 Mo");
        assert_eq!(taille_lisible(3 << 29), "1,5 Go");
    }
}
