//! Le compte du processus (getuid, geteuid), ce qu'il peut écrire (faccessat) et, sous Linux, le programme à l'autre
//! bout d'une prise Unix (SO_PEERCRED ; et, octet par octet, le processus qui l'a envoyé : SCM_CREDENTIALS,
//! SCM_PIDFD) : quelques appels à libc, une fois ici, pour que les modules qui s'en servent (dont le client D-Bus que
//! lit le banc de fuzzing) restent sans `unsafe`.

// FFI de libc : getuid, geteuid, faccessat, getsockopt, socket, connect et recvmsg n'ont pas d'équivalent sûr dans
// std.
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

/// SO_PASSPIDFD et SCM_PIDFD (include/uapi/asm-generic/socket.h, Linux 6.5) : la caisse libc ne les exporte pas
/// encore pour Linux.
#[cfg(target_os = "linux")]
const SO_PASSPIDFD: libc::c_int = 76;
#[cfg(target_os = "linux")]
const SCM_PIDFD: libc::c_int = 0x04;

/// Se branche à la prise `chemin` en demandant d'abord au noyau (SO_PASSCRED, SO_PASSPIDFD) d'attacher à chaque
/// octet reçu le processus qui l'a envoyé. Posé avant `connect` : le noyau décide à l'envoi s'il attache ces
/// témoins, donc un octet envoyé dès l'acceptation doit déjà les trouver demandés. Une erreur `Unsupported` : ce
/// noyau ne sait pas tenir l'expéditeur (SO_PASSPIDFD, Linux 6.5).
#[cfg(target_os = "linux")]
pub(crate) fn brancher_avec_temoins(chemin: &std::path::Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: socket ne lit aucune mémoire à nous ; le descripteur rendu (s'il est valide) n'est qu'à nous.
    let brut = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if brut < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `brut` vient d'être créé, valide, à personne d'autre : l'OwnedFd le referme une seule fois.
    let fd = unsafe { OwnedFd::from_raw_fd(brut) };
    let oui: libc::c_int = 1;
    let taille_oui = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).map_err(std::io::Error::other)?;
    for (option, sans) in [(libc::SO_PASSCRED, false), (SO_PASSPIDFD, true)] {
        // SAFETY: setsockopt lit `taille_oui` octets (un entier) à `oui`, à nous et vivant pendant l'appel.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw const oui).cast(),
                taille_oui,
            )
        };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            return Err(if sans && e.raw_os_error() == Some(libc::ENOPROTOOPT) {
                std::io::Error::from(std::io::ErrorKind::Unsupported)
            } else {
                e
            });
        }
    }
    let octets = chemin.as_os_str().as_bytes();
    // SAFETY: sockaddr_un est fait d'entiers et d'un tableau d'octets : tout à zéro est une valeur valide.
    let mut adresse: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    // Le chemin et son zéro final doivent tenir dans sun_path.
    if octets.len() >= adresse.sun_path.len() || octets.contains(&0) {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    adresse.sun_family = libc::sa_family_t::try_from(libc::AF_UNIX).map_err(std::io::Error::other)?;
    for (case, &o) in adresse.sun_path.iter_mut().zip(octets) {
        *case = libc::c_char::from_ne_bytes([o]);
    }
    let taille = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>()).map_err(std::io::Error::other)?;
    // SAFETY: connect lit `taille` octets à `adresse`, une structure à nous vivante pendant l'appel, sur le
    // descripteur que `fd` garde.
    let r = unsafe { libc::connect(fd.as_raw_fd(), (&raw const adresse).cast(), taille) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(std::os::unix::net::UnixStream::from(fd))
}

/// Un octet reçu, avec le processus qui l'a envoyé, tel que le noyau l'a noté à l'envoi.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct Expediteur {
    /// L'octet.
    pub(crate) octet: u8,
    /// Son numéro (SCM_CREDENTIALS), vu depuis ce processus.
    pub(crate) pid: i32,
    /// Son compte (SCM_CREDENTIALS).
    pub(crate) uid: u32,
    /// Un descripteur qui le tient (SCM_PIDFD) : tant qu'il est ouvert, il ne désigne que ce processus-là.
    pub(crate) pidfd: std::os::fd::OwnedFd,
}

/// Lit un octet d'une prise branchée par `brancher_avec_temoins`, avec son expéditeur. Refusé (erreur) : fin de flux,
/// témoins absents ou tronqués, ou des descripteurs joints (SCM_RIGHTS, jamais attendus ici : refermés aussitôt).
/// Les délais de lecture de la prise s'appliquent.
#[cfg(target_os = "linux")]
pub(crate) fn recevoir_avec_temoins(s: &std::os::unix::net::UnixStream) -> std::io::Result<Expediteur> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut octet = 0u8;
    let mut morceau = libc::iovec {
        iov_base: (&raw mut octet).cast(),
        iov_len: 1,
    };
    // Place pour les témoins (ucred, un pidfd) et pour quelques descripteurs qu'un expéditeur hostile joindrait :
    // ils sont reçus pour être refermés, et un surplus est tronqué (MSG_CTRUNC : refusé). Aligné sur 8 octets.
    let mut controle = [0u64; 64];
    // SAFETY: msghdr est fait d'entiers et de pointeurs : tout à zéro (pointeurs nuls) est une valeur valide.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut morceau;
    message.msg_iovlen = 1;
    message.msg_control = controle.as_mut_ptr().cast();
    message.msg_controllen = std::mem::size_of_val(&controle)
        .try_into()
        .map_err(std::io::Error::other)?;
    // SAFETY: recvmsg écrit au plus 1 octet dans `octet` (par `morceau`) et au plus `msg_controllen` octets dans
    // `controle`, tous à nous et vivants pendant l'appel ; MSG_CMSG_CLOEXEC : les descripteurs reçus ne passent pas
    // à un programme lancé.
    let n = unsafe { libc::recvmsg(s.as_raw_fd(), &raw mut message, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut temoins: Option<libc::ucred> = None;
    let mut pidfd: Option<OwnedFd> = None;
    let mut joints = false;
    // SAFETY: `message` vient d'être rempli par recvmsg ; CMSG_FIRSTHDR et CMSG_NXTHDR ne rendent que des en-têtes
    // dans `controle` (ou nul), bornés par msg_controllen.
    let mut entete = unsafe { libc::CMSG_FIRSTHDR(&raw const message) };
    while !entete.is_null() {
        // SAFETY: `entete` est non nul et pointe un en-tête entier dans `controle` (garanti par CMSG_*HDR).
        let (niveau, genre, longueur) = unsafe { ((*entete).cmsg_level, (*entete).cmsg_type, (*entete).cmsg_len) };
        // SAFETY: les données suivent l'en-tête dans le même tampon.
        let donnees = unsafe { libc::CMSG_DATA(entete) };
        let debut = donnees.addr().saturating_sub(entete.addr());
        // Jamais au-delà du tampon, quoi que dise l'en-tête.
        let fin_du_tampon = controle
            .as_ptr()
            .addr()
            .saturating_add(std::mem::size_of_val(&controle));
        let utiles = usize::try_from(longueur)
            .unwrap_or(0)
            .saturating_sub(debut)
            .min(fin_du_tampon.saturating_sub(donnees.addr()));
        if niveau == libc::SOL_SOCKET {
            let entier = std::mem::size_of::<libc::c_int>();
            match genre {
                libc::SCM_RIGHTS | SCM_PIDFD => {
                    // SAFETY: `utiles` octets de données suivent l'en-tête (cmsg_len), dans `controle` (borné plus
                    // haut), vivant et non modifié pendant cet emprunt.
                    let octets = unsafe { std::slice::from_raw_parts(donnees.cast_const(), utiles) };
                    for brut in octets.chunks_exact(entier) {
                        let Ok(brut) = <[u8; 4]>::try_from(brut).map(libc::c_int::from_ne_bytes) else {
                            continue;
                        };
                        if brut < 0 {
                            continue;
                        }
                        // SAFETY: le noyau vient d'installer ce descripteur pour nous ; personne d'autre ne le
                        // possède : l'OwnedFd le referme une seule fois (aussitôt pour ce qui n'est pas gardé).
                        let fd = unsafe { OwnedFd::from_raw_fd(brut) };
                        if genre == SCM_PIDFD && pidfd.is_none() {
                            pidfd = Some(fd);
                        } else {
                            joints = true;
                        }
                    }
                }
                libc::SCM_CREDENTIALS if utiles >= std::mem::size_of::<libc::ucred>() => {
                    // SAFETY: une ucred entière suit l'en-tête (vérifié par `utiles`) ; lecture non alignée.
                    temoins = Some(unsafe { donnees.cast::<libc::ucred>().read_unaligned() });
                }
                _ => {}
            }
        }
        // SAFETY: comme CMSG_FIRSTHDR : l'en-tête suivant dans `controle`, ou nul.
        entete = unsafe { libc::CMSG_NXTHDR(&raw const message, entete) };
    }
    let refus = |quoi: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, quoi.to_string());
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    if message.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(refus("MSG_CTRUNC"));
    }
    if joints {
        return Err(refus("SCM_RIGHTS"));
    }
    let (Some(c), Some(pidfd)) = (temoins, pidfd) else {
        return Err(refus("SCM_CREDENTIALS/SCM_PIDFD"));
    };
    Ok(Expediteur {
        octet,
        pid: c.pid,
        uid: c.uid,
        pidfd,
    })
}

/// Un octet attend-il déjà dans la prise ? Regardé sans le prendre ni attendre (MSG_PEEK, MSG_DONTWAIT), et sans
/// place pour les témoins : le noyau n'installe alors aucun descripteur (il marque seulement MSG_CTRUNC). `Ok(false)`
/// : rien n'attend ; la fin de flux compte comme « rien » (la lecture qui suit la dira).
#[cfg(target_os = "linux")]
pub(crate) fn octet_en_attente(s: &std::os::unix::net::UnixStream) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    let mut octet = 0u8;
    // SAFETY: recv écrit au plus 1 octet dans `octet`, à nous et vivant pendant l'appel ; MSG_PEEK le laisse dans la
    // prise, MSG_DONTWAIT n'attend pas.
    let n = unsafe {
        libc::recv(
            s.as_raw_fd(),
            (&raw mut octet).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if n < 0 {
        let e = std::io::Error::last_os_error();
        return if e.kind() == std::io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(e)
        };
    }
    Ok(n > 0)
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
