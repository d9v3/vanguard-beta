//! Arrêter un processus désigné par son numéro ET par son programme, dans Vanguard lui-même (ou dans son assistant
//! élevé), sans shell ni kill externe. Entre le moment où le programme est relu et celui où le signal part, le
//! numéro ne doit pas pouvoir passer à un autre programme :
//! - Linux (noyau 5.3 et plus) : un pidfd ouvert d'abord (pidfd_open) désigne CE processus ; le programme est relu
//!   (`/proc/<pid>/exe`), puis un signal 0 par le pidfd vérifie que le même processus vit encore (tant qu'il vit, même
//!   zombie, son numéro ne peut pas être repris), et SIGKILL part par le même pidfd. Sa fin se lit sur le pidfd
//!   (lisible à la mort). Noyau plus ancien : kill(2) juste après la relecture, la fenêtre de course reste, très courte.
//! - macOS : pas de pidfd. L'heure de démarrage du processus (proc_pidinfo, PROC_PIDTBSDINFO) est lue avant et après
//!   la relecture du programme (proc_pidpath) : un numéro repris entre-temps aurait une autre heure.
//! - Windows : la poignée qui lit le chemin est celle qui arrête (`processus::terminer_si`).

use crate::modele::Echec;

const OU: &str = "blocage/arret";

/// Arrête `pid` s'il fait toujours tourner `attendu` (« (deleted) » compris sous Linux : effacé depuis). `Err` : ce
/// qui l'a empêché, prêt à montrer ; rien n'est alors arrêté.
pub(crate) fn arreter(pid: u32, attendu: &str) -> Result<(), Echec> {
    #[cfg(target_os = "linux")]
    {
        linux::arreter(pid, attendu)
    }
    #[cfg(target_os = "macos")]
    {
        macos::arreter(pid, attendu)
    }
    #[cfg(windows)]
    {
        if crate::machine::windows::processus::terminer_si(pid, attendu) {
            Ok(())
        } else {
            Err(Echec::refuse(
                OU,
                crate::tr!(
                    "refusé par Windows, déjà fini, ou le numéro désigne un autre programme : rien n'est arrêté",
                    "refused by Windows, already ended, or the number points to another program: nothing is stopped"
                ),
            ))
        }
    }
}

#[cfg(unix)]
fn reaffecte(pid: u32) -> Echec {
    Echec::refuse(
        OU,
        crate::trf!(
            "le PID {pid} désigne maintenant un autre programme (ou plus aucun) : rien n'est arrêté",
            "PID {pid} now points to another program (or none): nothing is stopped"
        ),
    )
}

/// Le programme lu est-il celui attendu ? Sous Linux, un programme effacé depuis se lit « … (deleted) ».
#[cfg(any(unix, test))]
fn meme_programme(lu: &str, attendu: &str) -> bool {
    lu == attendu || lu.strip_suffix(" (deleted)") == Some(attendu)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    use super::{meme_programme, reaffecte};
    use crate::modele::Echec;

    /// pidfd_open(2), ou l'errno.
    fn ouvrir(pid: u32) -> Result<OwnedFd, i32> {
        let pid = libc::pid_t::try_from(pid).map_err(|_| libc::EINVAL)?;
        // SAFETY: pidfd_open ne lit aucune mémoire ; un descripteur rendu (≥ 0) est à nous seuls, confié à OwnedFd.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
        let fd = i32::try_from(fd).unwrap_or(-1);
        if fd < 0 {
            return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO));
        }
        // SAFETY: voir ci-dessus.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// pidfd_send_signal(2), ou l'errno.
    fn signal(fd: &OwnedFd, sig: i32) -> Result<(), i32> {
        // SAFETY: un descripteur à nous, vivant ; aucune information de signal (pointeur nul permis), drapeaux nuls.
        let r = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO))
        }
    }

    fn programme(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|c| c.to_string_lossy().into_owned())
    }

    fn refus(errno: i32) -> Echec {
        Echec::echoue(
            super::OU,
            crate::trf!(
                "le signal d'arrêt est refusé : {}",
                "the stop signal is refused: {}",
                std::io::Error::from_raw_os_error(errno)
            ),
        )
    }

    pub(super) fn arreter(pid: u32, attendu: &str) -> Result<(), Echec> {
        let fd = match ouvrir(pid) {
            Ok(fd) => fd,
            Err(libc::ESRCH) => return Err(reaffecte(pid)),
            // Noyau sans pidfd (avant 5.3) : relu puis tué aussitôt, comme avant.
            Err(libc::ENOSYS) => return sans_pidfd(pid, attendu),
            Err(e) => return Err(refus(e)),
        };
        if !programme(pid).is_some_and(|p| meme_programme(&p, attendu)) {
            return Err(reaffecte(pid));
        }
        // Toujours le processus du pidfd ? Sinon le programme relu était celui d'un autre, venu sur le même numéro.
        if signal(&fd, 0).is_err() {
            return Err(reaffecte(pid));
        }
        signal(&fd, libc::SIGKILL).map_err(refus)?;
        // Sa fin : le pidfd devient lisible à la mort (5 s au plus ; au-delà, l'appelant attend encore).
        let mut attente = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: un seul pollfd à nous, vivant pendant l'appel.
        unsafe { libc::poll(&raw mut attente, 1, 5000) };
        Ok(())
    }

    fn sans_pidfd(pid: u32, attendu: &str) -> Result<(), Echec> {
        if !programme(pid).is_some_and(|p| meme_programme(&p, attendu)) {
            return Err(reaffecte(pid));
        }
        let pid = libc::pid_t::try_from(pid).map_err(|_| reaffecte(0))?;
        // SAFETY: kill ne lit aucune mémoire.
        if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(refus(
                std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use super::{meme_programme, reaffecte};
    use crate::modele::Echec;

    /// Les informations BSD d'un processus (proc_pidinfo, PROC_PIDTBSDINFO).
    pub(crate) fn infos(pid: u32) -> Option<libc::proc_bsdinfo> {
        let pid = libc::c_int::try_from(pid).ok()?;
        // SAFETY: proc_bsdinfo n'a que des entiers et des tableaux d'octets : zéro est une valeur valide.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let taille = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: `info` est à nous, de la taille annoncée, vivant pendant l'appel.
        let lu = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), taille) };
        (lu == taille).then_some(info)
    }

    fn programme(pid: u32) -> Option<String> {
        let pid = libc::c_int::try_from(pid).ok()?;
        let mut tampon = vec![0u8; 4096];
        let taille = u32::try_from(tampon.len()).ok()?;
        // SAFETY: le tampon est à nous, de la taille annoncée ; proc_pidpath y écrit au plus `taille` octets.
        let n = unsafe { libc::proc_pidpath(pid, tampon.as_mut_ptr().cast(), taille) };
        let n = usize::try_from(n).ok().filter(|n| *n > 0)?;
        tampon.truncate(n);
        String::from_utf8(tampon).ok()
    }

    pub(super) fn arreter(pid: u32, attendu: &str) -> Result<(), Echec> {
        let depart = |i: &libc::proc_bsdinfo| (i.pbi_start_tvsec, i.pbi_start_tvusec);
        let avant = infos(pid).ok_or_else(|| reaffecte(pid))?;
        if !programme(pid).is_some_and(|p| meme_programme(&p, attendu)) {
            return Err(reaffecte(pid));
        }
        let apres = infos(pid).ok_or_else(|| reaffecte(pid))?;
        if depart(&avant) != depart(&apres) {
            return Err(reaffecte(pid));
        }
        let pid = libc::pid_t::try_from(pid).map_err(|_| reaffecte(0))?;
        // SAFETY: kill ne lit aucune mémoire.
        if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            Ok(())
        } else {
            Err(Echec::echoue(
                super::OU,
                crate::trf!(
                    "le signal d'arrêt est refusé : {}",
                    "the stop signal is refused: {}",
                    std::io::Error::last_os_error()
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programme_compare() {
        assert!(meme_programme("/home/alice/.cache/x", "/home/alice/.cache/x"));
        assert!(meme_programme("/home/alice/.cache/x (deleted)", "/home/alice/.cache/x"));
        assert!(!meme_programme("/usr/bin/sshd", "/home/alice/.cache/x"));
        assert!(!meme_programme(
            "/home/alice/.cache/x (deleted) (deleted)",
            "/home/alice/.cache/x"
        ));
    }

    /// Un processus enfant créé par le test, arrêté par son numéro et son programme ; avec un autre programme
    /// attendu, il survit. Rien d'autre n'est visé.
    #[cfg(unix)]
    #[test]
    fn arret_d_un_enfant_et_refus_si_autre_programme() {
        use std::os::unix::process::ExitStatusExt;
        let mut enfant = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = enfant.id();
        // spawn peut rendre la main avant l'exec du fils : on attend qu'il fasse tourner sleep.
        let moi = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        let debut = std::time::Instant::now();
        let programme = loop {
            match crate::protection::blocage::chemin_du_processus(pid) {
                Some(p) if p != moi => break p,
                _ => assert!(debut.elapsed().as_secs() < 10, "le fils ne passe pas à sleep"),
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert!(arreter(pid, "/autre/programme").is_err());
        assert!(
            enfant.try_wait().unwrap().is_none(),
            "un autre programme attendu : il vit encore"
        );
        arreter(pid, &programme).unwrap();
        let statut = enfant.wait().unwrap();
        assert_eq!(statut.signal(), Some(libc::SIGKILL));
        // Fini et ramassé : le numéro ne désigne plus rien.
        assert!(arreter(pid, &programme).is_err());
    }
}
