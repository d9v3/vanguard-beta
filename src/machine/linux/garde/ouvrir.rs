//! Les ouvertures du garde dans le dossier personnel du compte, qui le contrôle entièrement : par openat2, sous un
//! dossier de départ, sans lien symbolique, sans changer de système de fichiers (un montage FUSE du compte dans son
//! dossier ne se traverse pas), et le type du système de fichiers lu par fstatfs. Sans openat2 (noyau d'avant 5.6, ou
//! filtré), rien n'est ouvert : le garde vit sans listes plutôt que de suivre un lien.

// Ni débordement ni `as` : les tailles passées au noyau sont converties par `try_from`.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// La résolution exigée de chaque ouverture : rien au-dessus du départ, aucun lien, aucun autre système de fichiers.
const RESOLUTION: u64 = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS | libc::RESOLVE_NO_XDEV;

/// La structure `open_how` du noyau (include/uapi/linux/openat2.h), à nous : celle de libc ne se construit pas.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Ouvre `relatif` sous `depart`, en lecture, sans attendre (un tube) : un fichier ou, avec `dossier`, un dossier
/// (O_PATH : rien n'est demandé au système de fichiers pour l'ouvrir).
// FFI de libc : l'appel système openat2 (pas d'enveloppe dans libc), avec la structure open_how (OpenHow) à nous et un chemin en
// C vivant pendant l'appel ; le descripteur rendu est pris par OwnedFd ici même.
#[allow(unsafe_code)]
pub(crate) fn sous(depart: BorrowedFd<'_>, relatif: &Path, dossier: bool) -> io::Result<File> {
    if relatif.is_absolute() || relatif.as_os_str().is_empty() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let chemin =
        CString::new(relatif.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let drapeaux = if dossier {
        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
    } else {
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY
    };
    let how = OpenHow {
        flags: u64::try_from(drapeaux).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        mode: 0,
        resolve: RESOLUTION,
    };
    // SAFETY: `how` et `chemin` sont à nous, vivants pendant l'appel, et le noyau n'en garde rien ; la taille passée
    // est celle de `how` ; `depart` est un descripteur ouvert, emprunté pendant l'appel. Un résultat ≥ 0 est un
    // descripteur neuf, qui n'appartient qu'à l'OwnedFd qui le prend.
    let r = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            depart.as_raw_fd(),
            chemin.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(r).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: voir plus haut : `fd` est neuf et à nous seuls.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Le type (f_type) du système de fichiers qui porte `fd`.
// FFI de libc : fstatfs sur un descripteur ouvert, dans une structure statfs à nous.
#[allow(unsafe_code)]
pub(crate) fn type_fs(fd: BorrowedFd<'_>) -> io::Result<u64> {
    // SAFETY: statfs n'a que des entiers, valide à zéro ; fstatfs la remplit, `fd` est ouvert pendant l'appel.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: voir plus haut ; le noyau ne garde pas le pointeur.
    let r = unsafe { libc::fstatfs(fd.as_raw_fd(), &raw mut s) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    // f_type est signé sur certaines architectures : sa valeur, lue comme les 64 bits qu'elle est.
    Ok(u64::from_ne_bytes(s.f_type.to_ne_bytes()))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn openat2_ne_suit_ni_lien_ni_remontee() {
        let d = crate::essais::Jetable::nouveau("garde-ouvrir");
        std::fs::create_dir(d.join("a")).unwrap();
        std::fs::write(d.join("a/f"), b"x").unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("lien")).unwrap();
        std::os::unix::fs::symlink(d.join("a/f"), d.join("a/lf")).unwrap();
        let depart = File::open(&*d).unwrap();
        match sous(depart.as_fd(), Path::new("a/f"), false) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) || e.raw_os_error() == Some(libc::EPERM) => {
                return crate::essais::saute("openat2 absent ou filtré ici");
            }
            Err(e) => panic!("{e}"),
        }
        assert!(sous(depart.as_fd(), Path::new("a"), true).is_ok());
        // Un lien au milieu ou à la fin, une remontée, un chemin absolu ou vide : refusés.
        for refuse in ["lien/f", "a/lf", "../x", "a/../../x"] {
            assert!(sous(depart.as_fd(), Path::new(refuse), false).is_err(), "{refuse}");
        }
        assert!(sous(depart.as_fd(), &d.join("a/f"), false).is_err());
        assert!(sous(depart.as_fd(), Path::new(""), false).is_err());
        assert!(type_fs(depart.as_fd()).unwrap() != 0);
    }
}
