//! Le compte du processus (getuid, geteuid), ce qu'il peut écrire (faccessat) et, sous Linux, le compte du programme à
//! l'autre bout d'une prise Unix (SO_PEERCRED) : quatre appels à libc, une fois ici, pour que les modules qui s'en
//! servent (dont le client D-Bus que lit le banc de fuzzing) restent sans `unsafe`.

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
