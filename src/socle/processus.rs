//! La liste des processus sous Linux et macOS, comme `machine::windows::processus` sous Windows. Linux la lit dans
//! /proc, macOS la demande au noyau (proc_listallpids, proc_pidpath) ; une douzaine de modules faisaient chacun leur
//! parcours de /proc, avec chacun sa règle quand il ne se lisait pas : une liste vide, que rien ne distinguait d'un
//! ordinateur où rien ne tourne. Ici, une liste illisible est `None`, à dire « non vérifié ».

// FFI de libc : kill, proc_listallpids et proc_pidpath.
#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;

/// Les numéros des processus ; `None` : la liste ne se lit pas (pas de /proc, appel refusé), à dire non vérifiée.
#[cfg(target_os = "linux")]
pub(crate) fn pids() -> Option<Vec<u32>> {
    pids_dans(Path::new("/proc"))
}

/// Les numéros des processus de `proc` (un /proc monté ailleurs, ou fabriqué pour un test) : ses dossiers dont le
/// nom n'est fait que de chiffres. « self » et « thread-self » ne sont pas des processus de plus.
#[cfg(target_os = "linux")]
pub(crate) fn pids_dans(proc: &Path) -> Option<Vec<u32>> {
    let mut pids: Vec<u32> = std::fs::read_dir(proc)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let nom = e.file_name();
            let nom = nom.to_str()?;
            nom.bytes().all(|o| o.is_ascii_digit()).then(|| nom.parse().ok())?
        })
        .collect();
    pids.sort_unstable();
    Some(pids)
}

/// Le nom court du processus (`/proc/<pid>/comm` : 15 octets au plus, choisi par le programme lui-même, donc à rendre
/// inoffensif avant de l'afficher). `None` : parti entre-temps, ou illisible.
#[cfg(target_os = "linux")]
pub(crate) fn nom_court(pid: u32) -> Option<String> {
    let nom = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    Some(nom.trim_end_matches('\n').to_string())
}

/// Le programme que le processus fait tourner. Linux : `/proc/<pid>/exe`, lisible pour les processus de son compte
/// seulement (ceux des autres comptes, en root) ; un programme effacé du disque garde son chemin suivi de
/// « (deleted) ». macOS : demandé au noyau.
pub(crate) fn programme(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
    #[cfg(target_os = "macos")]
    {
        let mut tampon = vec![0u8; 4096];
        let taille = u32::try_from(tampon.len()).ok()?;
        // SAFETY: proc_pidpath écrit au plus `taille` octets dans `tampon` et rend leur nombre (0 : refus).
        let lus = unsafe { libc::proc_pidpath(libc::c_int::try_from(pid).ok()?, tampon.as_mut_ptr().cast(), taille) };
        let chemin = String::from_utf8_lossy(tampon.get(..usize::try_from(lus).ok()?)?).into_owned();
        chemin.starts_with('/').then(|| PathBuf::from(chemin))
    }
}

/// Les arguments du processus (`/proc/<pid>/cmdline`, séparés par des octets nuls), lus avec pertes s'ils ne sont pas
/// de l'UTF-8 ; vide : processus du noyau, parti, ou illisible.
#[cfg(target_os = "linux")]
pub(crate) fn arguments(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|&o| o == 0)
        .filter(|a| !a.is_empty())
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// /proc cache-t-il les processus des autres comptes (option « hidepid » du montage) ? Une liste lue alors ne montre
/// que ceux de ce compte : à dire, plutôt que de juger l'ordinateur sur une partie.
#[cfg(target_os = "linux")]
pub(crate) fn autres_comptes_caches() -> bool {
    hidepid(&std::fs::read_to_string("/proc/self/mounts").unwrap_or_default())
}

/// L'option hidepid du montage de /proc, dans le texte de /proc/self/mounts : « hidepid=2 », « hidepid=invisible »
/// cachent ; « hidepid=0 » ou « hidepid=off » non.
#[cfg(target_os = "linux")]
fn hidepid(montages: &str) -> bool {
    montages
        .lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            let (_, point, genre, options) = (c.next()?, c.next()?, c.next()?, c.next()?);
            (point == "/proc" && genre == "proc").then_some(options)
        })
        .any(|options| {
            options
                .split(',')
                .filter_map(|o| o.strip_prefix("hidepid="))
                .any(|v| !matches!(v, "0" | "off"))
        })
}

/// Les numéros des processus, demandés au noyau ; `None` : l'appel n'a rien rendu (Vanguard au moins tourne, donc
/// une liste vide est un échec).
#[cfg(target_os = "macos")]
pub(crate) fn pids() -> Option<Vec<u32>> {
    let mut pids: Vec<libc::c_int> = vec![0; 8192];
    let taille = libc::c_int::try_from(pids.len() * std::mem::size_of::<libc::c_int>()).ok()?;
    // SAFETY: proc_listallpids écrit au plus `taille` octets dans `pids` et rend le nombre de processus écrits.
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), taille) };
    let n = usize::try_from(n).unwrap_or(0).min(pids.len());
    let liste: Vec<u32> = pids.iter().take(n).filter_map(|&p| u32::try_from(p).ok()).collect();
    (!liste.is_empty()).then_some(liste)
}

/// Gèle un processus (SIGSTOP) : il cesse d'agir sans que rien ne soit effacé, sa mémoire reste. Réversible par
/// `reprendre`. Rend `false` si l'envoi a échoué (numéro parti, pas les droits). Utilisé par le veilleur
/// anti-rançongiciel (Linux).
#[cfg(target_os = "linux")]
pub(crate) fn geler(pid: u32) -> bool {
    envoyer_signal(pid, libc::SIGSTOP)
}

/// Reprend un processus gelé (SIGCONT).
#[cfg(target_os = "linux")]
pub(crate) fn reprendre(pid: u32) -> bool {
    envoyer_signal(pid, libc::SIGCONT)
}

/// Un processus est-il gelé ? (son état est « T » dans `/proc/<pid>/stat`) : sert à regeler ce qu'un SIGCONT d'un tiers
/// aurait repris. `None` : parti ou illisible.
#[cfg(target_os = "linux")]
pub(crate) fn est_gele(pid: u32) -> Option<bool> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    etat_du_stat(&stat).map(|e| e == 'T' || e == 't')
}

/// Le champ « état » de `/proc/<pid>/stat` (3e champ), après le nom entre parenthèses — qui peut contenir des espaces
/// et des parenthèses, d'où la recherche de la DERNIÈRE « ) ».
#[cfg(target_os = "linux")]
pub(crate) fn etat_du_stat(stat: &str) -> Option<char> {
    let apres = &stat[stat.rfind(')')? + 1..];
    apres.split_whitespace().next()?.chars().next()
}

#[cfg(target_os = "linux")]
fn envoyer_signal(pid: u32, signal: libc::c_int) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: kill n'envoie qu'un signal à un numéro de processus et ne touche aucune mémoire.
    unsafe { libc::kill(pid, signal) == 0 }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn etat_dans_stat() {
        assert_eq!(etat_du_stat("123 (bash) S 1 123 123 0 -1 4194304"), Some('S'));
        // Un nom avec parenthèses et espaces : on lit après la dernière « ) ».
        assert_eq!(etat_du_stat("123 (a b) c) T 1 1"), Some('T'));
        assert_eq!(etat_du_stat("sans parenthese"), None);
    }

    #[test]
    fn pids_d_un_proc_fabrique() {
        let d = std::env::temp_dir().join(format!("vanguard-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for n in ["1", "412", "self", "thread-self", "sys", "12a"] {
            std::fs::create_dir_all(d.join(n)).unwrap();
        }
        assert_eq!(pids_dans(&d), Some(vec![1, 412]));
        assert_eq!(pids_dans(&d.join("absent")), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ce processus se trouve lui-même, avec son nom et son programme.
    #[test]
    fn soi_dans_la_liste() {
        let moi = std::process::id();
        assert!(pids().is_some_and(|l| l.contains(&moi)));
        assert!(nom_court(moi).is_some_and(|n| !n.is_empty() && !n.ends_with('\n')));
        assert_eq!(programme(moi), std::env::current_exe().ok());
        assert!(arguments(moi).first().is_some_and(|a| !a.is_empty()));
        assert_eq!(nom_court(u32::MAX), None);
    }

    #[test]
    fn montage_hidepid() {
        let proc = |o: &str| format!("sysfs /sys sysfs rw 0 0\nproc /proc proc rw,nosuid,{o} 0 0\n");
        assert!(hidepid(&proc("hidepid=2")) && hidepid(&proc("hidepid=invisible,gid=10")));
        assert!(!hidepid(&proc("relatime")) && !hidepid(&proc("hidepid=0")) && !hidepid(&proc("hidepid=off")));
        // Un autre /proc (celui d'un conteneur) ne compte pas.
        assert!(!hidepid("proc /srv/x/proc proc rw,hidepid=2 0 0\n"));
    }
}
