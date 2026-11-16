//! Un fichier en mémoire scellé (memfd), pour lancer la fenêtre depuis les octets vérifiés et non depuis son chemin
//! (`lancer_fenetre`) : une fois scellé, ni ce programme ni un autre ne peut plus le changer, l'agrandir ou le
//! raccourcir, ni retirer les sceaux. Trois appels à libc, ici seulement.

use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::modele::Echec;

/// Les sceaux posés : plus d'écriture, ni plus grand, ni plus petit, et plus aucun sceau à changer.
const SCEAUX: libc::c_int = libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL;

/// Un memfd qui contient `octets`, scellé. `MFD_EXEC` d'abord : un noyau réglé `vm.memfd_noexec=1` ferait sinon un
/// memfd qu'on ne peut pas lancer ; un noyau d'avant la 6.3, qui ne le connaît pas, le refuse (EINVAL) et le fait sans.
/// Réglé `vm.memfd_noexec=2`, le noyau refuse tout memfd exécutable : l'erreur est rendue, la fenêtre n'est pas lancée.
pub(crate) fn scelle(nom: &str, octets: &[u8]) -> Result<File, Echec> {
    let nom = std::ffi::CString::new(nom).map_err(|e| Echec::echoue("fenetre/sceller", e.to_string()))?;
    let base = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    let mut fd = creer(&nom, base | libc::MFD_EXEC);
    if fd.as_ref().is_err_and(|e| e.raw_os_error() == Some(libc::EINVAL)) {
        fd = creer(&nom, base);
    }
    let mut f = File::from(fd.map_err(|e| Echec::echoue("fenetre/sceller", format!("memfd_create : {e}")))?);
    f.write_all(octets)
        .map_err(|e| Echec::echoue("fenetre/sceller", e.to_string()))?;
    if fcntl(&f, libc::F_ADD_SEALS, SCEAUX) != 0 {
        return Err(Echec::echoue(
            "fenetre/sceller",
            format!("F_ADD_SEALS : {}", std::io::Error::last_os_error()),
        ));
    }
    // Relus : seuls comptent les sceaux que le noyau dit posés.
    if sceaux(&f)? & SCEAUX != SCEAUX {
        return Err(Echec::refuse("fenetre/sceller", "sceaux incomplets"));
    }
    Ok(f)
}

/// Les sceaux que le noyau dit posés sur `f`.
pub(crate) fn sceaux(f: &File) -> Result<libc::c_int, Echec> {
    let s = fcntl(f, libc::F_GET_SEALS, 0);
    if s < 0 {
        return Err(Echec::echoue(
            "fenetre/sceller",
            format!("F_GET_SEALS : {}", std::io::Error::last_os_error()),
        ));
    }
    Ok(s)
}

// FFI de libc : fcntl (sceaux d'un memfd) n'a pas d'équivalent dans std.
#[allow(unsafe_code)]
fn fcntl(f: &File, commande: libc::c_int, argument: libc::c_int) -> libc::c_int {
    // SAFETY: F_ADD_SEALS et F_GET_SEALS sur un descripteur ouvert que `f` garde, avec un entier : aucune mémoire
    // touchée.
    unsafe { libc::fcntl(f.as_raw_fd(), commande, argument) }
}

// FFI de libc : memfd_create n'a pas d'équivalent dans std.
#[allow(unsafe_code)]
fn creer(nom: &std::ffi::CStr, drapeaux: libc::c_uint) -> std::io::Result<OwnedFd> {
    // SAFETY: `nom` est une chaîne terminée par un zéro, vivante pendant l'appel ; memfd_create ne fait que la lire.
    let fd = unsafe { libc::memfd_create(nom.as_ptr(), drapeaux) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être rendu par memfd_create, ouvert et à personne d'autre : OwnedFd le fermera, une fois.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
