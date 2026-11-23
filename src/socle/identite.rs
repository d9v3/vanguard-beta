//! Le compte du processus (getuid, geteuid), ce qu'il peut écrire (faccessat) et, sous Linux, le programme à l'autre
//! bout d'une prise Unix (SO_PEERCRED, SO_PEERPIDFD) : quelques appels à libc, une fois ici, pour que les modules qui
//! s'en servent (dont le client D-Bus que lit le banc de fuzzing) restent sans `unsafe`.

// FFI de libc : getuid, geteuid, faccessat et getsockopt n'ont pas d'équivalent sûr dans std.
#![allow(unsafe_code)]

/// Le compte réel du processus.
pub(crate) fn uid() -> u32 {
    // SAFETY: getuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
    unsafe { libc::getuid() }
}

/// Le compte effectif du processus (0 : root, ou root d'un espace de noms).
pub(crate) fn euid() -> u32 {
    // SAFETY: geteuid ne prend aucun argument, ne touche aucune mémoire et ne peut pas échouer.
    unsafe { libc::geteuid() }
}

/// Le compte effectif peut-il écrire à `chemin` ? Le noyau en juge avec tout ce qu'il sait (droits étendus, ACL,
/// capacités), ce que le propriétaire et les bits de droits seuls ne disent pas. Une question qui échoue autrement
/// que par un refus net (EACCES, EPERM, système en lecture seule) répond oui : qui s'en sert pour accorder sa
/// confiance doit échouer fermé.
pub(crate) fn ecrivable(chemin: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c) = std::ffi::CString::new(chemin.as_os_str().as_bytes()) else {
        return true;
    };
    // SAFETY: `c` est une chaîne terminée par un zéro, vivante pendant l'appel ; faccessat ne fait que la lire.
    let r = unsafe { libc::faccessat(libc::AT_FDCWD, c.as_ptr(), libc::W_OK, libc::AT_EACCESS) };
    r == 0
        || !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES | libc::EPERM | libc::EROFS)
        )
}

/// Le compte du programme à l'autre bout de la prise (SO_PEERCRED), tel que le noyau le connaît ; `None` si la
/// question échoue.
#[cfg(target_os = "linux")]
pub(crate) fn compte_d_en_face(s: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut taille = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
    // SAFETY: getsockopt écrit au plus `taille` octets dans `cred`, une structure à nous vivante pendant l'appel, sur
    // une prise ouverte que `s` garde.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut taille,
        )
    };
    (r == 0).then_some(cred.uid)
}

/// Le processus et le compte à l'autre bout de la prise (SO_PEERCRED), tels que le noyau les a notés quand il s'est
/// branché (pour un serveur : quand il s'est mis à écouter) ; `None` si la question échoue.
#[cfg(target_os = "linux")]
pub(crate) fn processus_d_en_face(s: &std::os::unix::net::UnixStream) -> Option<(i32, u32)> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut taille = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
    // SAFETY: getsockopt écrit au plus `taille` octets dans `cred`, une structure à nous vivante pendant l'appel, sur
    // une prise ouverte que `s` garde.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut taille,
        )
    };
    (r == 0 && cred.pid > 0).then_some((cred.pid, cred.uid))
}

/// Un descripteur qui tient le processus à l'autre bout de la prise (SO_PEERPIDFD, Linux 6.5 et plus) : tant qu'il
/// est ouvert, il désigne ce processus-là, jamais un autre qui aurait repris son numéro. `None` sur un noyau plus
/// ancien ou si la question échoue.
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_d_en_face(s: &std::os::unix::net::UnixStream) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // include/uapi/asm-generic/socket.h ; la caisse libc ne l'exporte pas encore pour Linux.
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut fd: libc::c_int = -1;
    let mut taille = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: getsockopt écrit au plus `taille` octets (un entier) dans `fd`, à nous et vivant pendant l'appel, sur une
    // prise ouverte que `s` garde.
    let r = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&raw mut fd).cast(),
            &raw mut taille,
        )
    };
    if r != 0 || fd < 0 {
        return None;
    }
    // SAFETY: le noyau vient de créer ce descripteur pour nous (O_CLOEXEC) ; personne d'autre ne le possède, il est
    // refermé une seule fois, par l'OwnedFd.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Le processus tenu par `pidfd` vit-il encore ? pidfd_send_signal avec le signal 0 ne lui envoie rien : il dit
/// seulement si le processus existe (ESRCH sinon).
#[cfg(target_os = "linux")]
pub(crate) fn pidfd_vivant(pidfd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    // SAFETY: appel système sans mémoire à nous (info nulle), sur un descripteur ouvert que `pidfd` garde ; le signal 0
    // ne fait que vérifier.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    r == 0
}

#[cfg(test)]
mod tests {
    /// Le compte effectif et le compte réel sont ceux que le système donne au processus des essais : les mêmes que
    /// le propriétaire d'un fichier qu'il vient de créer (effectif) et, hors programme setuid, l'un égal à l'autre.
    #[test]
    fn comptes_du_processus() {
        use std::os::unix::fs::MetadataExt;
        let dossier = crate::socle::dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join(format!("identite-{}", std::process::id()));
        std::fs::write(&f, b"").unwrap();
        assert_eq!(std::fs::metadata(&f).unwrap().uid(), super::euid());
        let _ = std::fs::remove_file(&f);
        assert_eq!(super::uid(), super::euid());
    }

    /// Un fichier à soi s'écrit ; un dossier fermé à tous (000) ne s'écrit pas, sauf en root (qui passe outre).
    #[test]
    fn ecrivable_par_le_compte() {
        use std::os::unix::fs::PermissionsExt;
        let d = crate::essais::Jetable::nouveau("ecrivable");
        let f = d.join("f");
        std::fs::write(&f, b"").unwrap();
        assert!(super::ecrivable(&f));
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o444)).unwrap();
        if super::euid() == 0 {
            return crate::essais::saute("en root, un fichier en lecture seule s'écrit quand même");
        }
        assert!(!super::ecrivable(&f));
        assert!(
            super::ecrivable(&d.join("absent")),
            "une question qui échoue répond oui"
        );
    }

    /// Les deux bouts d'une paire de prises sont au même compte : le nôtre.
    #[cfg(target_os = "linux")]
    #[test]
    fn compte_d_en_face_d_une_paire() {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        assert_eq!(super::compte_d_en_face(&a), Some(super::euid()));
        assert_eq!(super::compte_d_en_face(&b), Some(super::euid()));
    }
}
