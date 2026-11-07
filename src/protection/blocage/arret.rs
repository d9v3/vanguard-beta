//! Arrêter un processus désigné par son numéro ET par son programme, dans Vanguard lui-même (ou dans son assistant
//! élevé), sans shell ni kill externe. Entre le moment où le programme est relu et celui où le signal part, le
//! numéro ne doit pas pouvoir passer à un autre programme :
//! - Linux (noyau 5.3 et plus) : un pidfd ouvert d'abord (pidfd_open) désigne CE processus ; le programme est relu
//!   (`/proc/<pid>/exe`), puis un signal 0 par le pidfd vérifie que le même processus vit encore (tant qu'il vit, même
//!   zombie, son numéro ne peut pas être repris), et SIGKILL part par le même pidfd. Sa fin se lit sur le pidfd
//!   (lisible à la mort). Noyau plus ancien : kill(2) juste après la relecture, la fenêtre de course reste, très courte.
//! - Windows : la poignée qui lit le chemin est celle qui arrête (`processus::terminer_si`).

// FFI de libc : pidfd_open (syscall), poll et kill.
#![allow(unsafe_code)]

use std::collections::HashSet;

use super::gardes::{self, Decision};
use crate::machine::regles::Os;
use crate::modele::Echec;

const OU: &str = "blocage/arret";

/// Ce que devient une signature illisible à cet arrêt (défense D6a, choix 3.1).
pub(crate) enum Confirmation<'a> {
    /// Geste automatique, ou ordre remis sans `demande` : illisible refuse, personne ne confirme.
    Jamais,
    /// Demandé par la personne : illisible se montre, puis se confirme d'une vraie console. Les gardes des
    /// processus vitaux (`intouchables`, `os`), comme celle des sessions, passent AVANT la question.
    Demandee { intouchables: &'a HashSet<u32>, os: Os },
}

/// Arrête `pid` s'il fait toujours tourner `attendu` (« (deleted) » compris sous Linux : effacé depuis). `Ok(Some)` :
/// la note d'un arrêt confirmé malgré une signature illisible, à garder au journal. `Err` : ce qui l'a empêché, prêt
/// à montrer ; rien n'est alors arrêté.
pub(crate) fn arreter(pid: u32, attendu: &str, confirmation: &Confirmation<'_>) -> Result<Option<String>, Echec> {
    // Le dernier mot, juste avant le signal, sur des sessions relues : quel que soit le chemin qui mène ici, ce qui
    // descend d'une session à distance n'est jamais arrêté.
    if let Some(raison) = session(pid) {
        return Err(Echec::refuse(OU, raison));
    }
    let signature = gardes::signature_lue(attendu);
    let decision = match confirmation {
        Confirmation::Jamais => gardes::signature_intouchable(signature).map_or(Decision::Permis, Decision::Refuse),
        Confirmation::Demandee { intouchables, os } => gardes::decider_signature(
            signature,
            vital(pid, attendu, intouchables, *os),
            true,
            gardes::console_reelle(),
        ),
    };
    match decision {
        Decision::Refuse(raison) => Err(Echec::refuse(OU, raison)),
        Decision::Permis => arreter_sans_question(pid, attendu).map(|()| None),
        #[cfg(windows)]
        Decision::Demander(raison) => {
            let Confirmation::Demandee { intouchables, os } = confirmation else {
                return Err(Echec::refuse(OU, crate::tr!("rien n'est arrêté", "nothing is stopped")));
            };
            windows::confirmer_puis_arreter(pid, attendu, raison, intouchables, *os).map(Some)
        }
        // Rien ne se lit illisible ailleurs que sous Windows : refusé, au cas où.
        #[cfg(not(windows))]
        Decision::Demander(raison) => Err(Echec::refuse(
            OU,
            crate::trf!(
                "signature illisible ({}) : rien n'est arrêté",
                "unreadable signature ({}): nothing is stopped",
                raison.texte()
            ),
        )),
    }
}

/// La garde des sessions à distance, sur des sessions relues.
fn session(pid: u32) -> Option<&'static str> {
    gardes::lignee_de_session(pid, gardes::sessions_a_distance().as_ref())
}

/// La garde des processus vitaux (PID et noms critiques, Vanguard et ce qui le fait tourner, dossiers du système),
/// sur le nom du fichier et, sous Windows, celui de la liste des processus.
fn vital(pid: u32, attendu: &str, intouchables: &HashSet<u32>, os: Os) -> Option<&'static str> {
    let fichier = std::path::Path::new(attendu)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned());
    #[cfg(windows)]
    let liste = crate::machine::windows::processus::liste()
        .into_iter()
        .find(|p| p.pid == pid)
        .map(|p| p.nom);
    #[cfg(not(windows))]
    let liste: Option<String> = None;
    [fichier, liste]
        .iter()
        .flatten()
        .find_map(|nom| gardes::processus_intouchable(pid, nom, Some(attendu), intouchables, os))
}

/// L'arrêt lui-même, les gardes passées.
fn arreter_sans_question(pid: u32, attendu: &str) -> Result<(), Echec> {
    #[cfg(target_os = "linux")]
    {
        linux::arreter(pid, attendu)
    }
    #[cfg(windows)]
    {
        if crate::machine::windows::processus::terminer_si(pid, attendu) {
            Ok(())
        } else {
            Err(windows::refuse_par_windows())
        }
    }
}

/// Sous Windows : la signature illisible montrée, la réponse demandée, puis l'arrêt seulement si le processus est
/// toujours celui que la personne a vu.
#[cfg(windows)]
mod windows {
    use std::collections::HashSet;

    use super::{OU, session, vital};
    use crate::machine::regles::Os;
    use crate::machine::windows::processus;
    use crate::modele::Echec;
    use crate::protection::blocage::gardes::{self, Identite, Illisibilite, Portrait};
    use crate::{tr, trf};

    pub(super) fn refuse_par_windows() -> Echec {
        Echec::refuse(
            OU,
            tr!(
                "refusé par Windows, déjà fini, ou le numéro désigne un autre programme : rien n'est arrêté",
                "refused by Windows, already ended, or the number points to another program: nothing is stopped"
            ),
        )
    }

    /// Montre pourquoi la signature ne se lit pas et ce qu'on sait du programme, demande « Arrêter quand même ? »,
    /// puis relit tout avant d'arrêter. Le processus est tenu (poignée ouverte) de la lecture jusqu'à l'arrêt :
    /// Windows ne redonne pas son numéro à un autre tant qu'elle vit. La réponse « o » ne vaut que pour lui.
    pub(super) fn confirmer_puis_arreter(
        pid: u32,
        attendu: &str,
        raison: Illisibilite,
        intouchables: &HashSet<u32>,
        os: Os,
    ) -> Result<String, Echec> {
        let tenu = processus::Tenu::ouvrir(pid).map_err(|_| refuse_par_windows())?;
        let avant = Identite {
            pid,
            creation: tenu.creation(),
            chemin: tenu.chemin(),
        };
        if !avant.chemin.as_deref().is_some_and(|c| c.eq_ignore_ascii_case(attendu)) {
            return Err(Echec::refuse(
                OU,
                trf!(
                    "le PID {pid} désigne maintenant un autre programme : rien n'est arrêté",
                    "PID {pid} now points to another program: nothing is stopped"
                ),
            ));
        }
        let portrait = portrait(pid, &tenu, attendu);
        if !gardes::montrer_et_confirmer(
            raison,
            &portrait,
            tr!("\n  Arrêter quand même ? [o/N] : ", "\n  Stop it anyway? [y/N]: "),
        ) {
            return Err(Echec::refuse(
                OU,
                tr!(
                    "vous avez répondu non : rien n'est arrêté",
                    "you answered no: nothing is stopped"
                ),
            ));
        }
        // Relu après la réponse, qui a pu attendre longtemps : le même processus (heure de création), le même
        // programme, une signature qui n'est pas devenue Microsoft, et aucune garde qui refuse maintenant.
        let apres = Identite {
            pid,
            creation: processus::creation(pid),
            chemin: processus::chemin(pid),
        };
        let garde = session(pid).or_else(|| vital(pid, attendu, intouchables, os));
        gardes::confirmation_tient(&avant, &apres, gardes::signature_lue(attendu), garde, OU)?;
        if !processus::terminer_si(pid, attendu) {
            return Err(refuse_par_windows());
        }
        drop(tenu);
        Ok(gardes::note_confirmee(false, raison, portrait.sha256.as_deref()))
    }

    /// Ce que Windows dit du processus : compte, parent, heure de lancement, ligne de commande (par WMI ; illisible
    /// pour un autre compte sans droits), puis le fichier.
    fn portrait(pid: u32, tenu: &processus::Tenu, chemin: &str) -> Portrait {
        let liste = processus::liste();
        let creation = tenu.creation();
        let parent = liste.iter().find(|p| p.pid == pid).map(|p| p.parent).and_then(|pp| {
            Some(gardes::Parent {
                nom: liste.iter().find(|p| p.pid == pp)?.nom.clone(),
                pid: pp,
                filiation: gardes::filiation(processus::creation(pp), creation),
            })
        });
        let ligne = crate::machine::windows::wmi::requete(
            r"root\cimv2",
            "Win32_Process",
            &format!("ProcessId = {pid}"),
            &["CommandLine"],
        )
        .and_then(|lignes| lignes.first()?.get("CommandLine")?.texte().map(str::to_string))
        .filter(|l| !l.is_empty());
        let compte = Some(processus::compte_de(pid)).filter(|c| !c.is_empty());
        Portrait {
            processus: true,
            pid: Some(pid),
            compte,
            parent,
            lancement: creation.and_then(filetime_vers_heure).map(gardes::date_locale),
            ligne,
            ..gardes::portrait_de_fichier(std::path::Path::new(chemin))
        }
    }

    /// Une FILETIME (centaines de nanosecondes depuis 1601) en heure du système.
    fn filetime_vers_heure(f: u64) -> Option<std::time::SystemTime> {
        const ECART_1601_1970: u64 = 11_644_473_600;
        let secondes = (f / 10_000_000).checked_sub(ECART_1601_1970)?;
        std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secondes))
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
        assert!(arreter(pid, "/autre/programme", &Confirmation::Jamais).is_err());
        assert!(
            enfant.try_wait().unwrap().is_none(),
            "un autre programme attendu : il vit encore"
        );
        // Lancé depuis une session à distance (cargo test par SSH), la garde d'ascendance refuse à juste titre :
        // l'arrêt ne se vérifie alors pas ici.
        if super::super::gardes::lignee_de_session(pid, super::super::gardes::sessions_a_distance().as_ref()).is_some()
        {
            let _ = enfant.kill();
            let _ = enfant.wait();
            return crate::essais::saute("lancé depuis une session à distance");
        }
        assert_eq!(arreter(pid, &programme, &Confirmation::Jamais).unwrap(), None);
        let statut = enfant.wait().unwrap();
        assert_eq!(statut.signal(), Some(libc::SIGKILL));
        // Fini et ramassé : le numéro ne désigne plus rien.
        assert!(arreter(pid, &programme, &Confirmation::Jamais).is_err());
    }
}
