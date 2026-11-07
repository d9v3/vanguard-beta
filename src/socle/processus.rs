//! La liste des processus sous Linux, comme `machine::windows::processus` sous Windows. Linux la lit dans
//! /proc ; une douzaine de modules faisaient chacun leur
//! parcours de /proc, avec chacun sa règle quand il ne se lisait pas : une liste vide, que rien ne distinguait d'un
//! ordinateur où rien ne tourne. Ici, une liste illisible est `None`, à dire « non vérifié ».

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]
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
/// « (deleted) ».
pub(crate) fn programme(pid: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
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
    let (_, apres) = stat.rsplit_once(')')?;
    apres.split_whitespace().next()?.chars().next()
}

/// Le départ d'un processus, 22e champ de `/proc/<pid>/stat` (en tops d'horloge depuis le démarrage), lu après la
/// DERNIÈRE « ) » comme l'état. Avec le PID, il désigne un processus sans ambiguïté : un numéro repris par un autre
/// processus a un autre départ, alors qu'un `exec` garde le sien.
#[cfg(target_os = "linux")]
pub(crate) fn debut_du_stat(stat: &str) -> Option<u64> {
    let (_, apres) = stat.rsplit_once(')')?;
    apres.split_whitespace().nth(19)?.parse().ok()
}

/// Le départ du processus `pid` ; `None` : parti ou illisible.
#[cfg(target_os = "linux")]
pub(crate) fn debut(pid: u32) -> Option<u64> {
    debut_du_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Les quatre comptes de la ligne « Uid: » de `/proc/<pid>/status` (réel, effectif, sauvé, système de fichiers) sont-ils
/// tous `uid` ? Un programme setuid lancé depuis ce compte a un autre compte effectif : il n'est pas « du compte », et
/// ce n'est pas au veilleur, sans droits, de l'arrêter.
#[cfg(target_os = "linux")]
pub(crate) fn tout_au_compte(status: &str, uid: u32) -> bool {
    let Some(ligne) = status.lines().find_map(|l| l.strip_prefix("Uid:")) else {
        return false;
    };
    let comptes: Vec<&str> = ligne.split_whitespace().collect();
    comptes.len() == 4 && comptes.iter().all(|c| c.parse::<u32>().ok() == Some(uid))
}

/// Un programme lancé, tenu par son inode : le lien `/proc/<pid>/exe` ouvert en O_PATH désigne le fichier que le noyau
/// a lancé, même effacé ou remplacé depuis sur le disque, sans rien y lire (O_PATH n'appelle pas l'ouverture du système
/// de fichiers : un montage FUSE qui ne répond pas ne fige pas le veilleur). Le haché, c'est lui, jamais le chemin relu.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct Tenu {
    pub(crate) pid: u32,
    /// Le départ du processus (`debut`) : ce qui sera gelé doit être ce processus-là.
    pub(crate) debut: u64,
    /// Tous ses comptes sont celui de ce processus-ci (`tout_au_compte`).
    pub(crate) du_compte: bool,
    exe: std::fs::File,
}

#[cfg(target_os = "linux")]
impl Tenu {
    /// Le lien ouvert en O_PATH : il se lit en le rouvrant par `/proc/self/fd/<n>` (voir `protection::sources`), et
    /// `metadata()` donne l'inode lancé.
    pub(crate) fn exe(&self) -> &std::fs::File {
        &self.exe
    }
}

/// Tient le programme du processus `pid` : son départ, puis son programme ouvert, puis ses comptes, puis son départ
/// relu. Le même départ avant et après : le programme ouvert est bien celui de ce processus (un numéro repris entre
/// les deux aurait un autre départ). `None` : parti, d'un autre compte que /proc ne nous ouvre pas, ou repris.
#[cfg(target_os = "linux")]
pub(crate) fn tenir(pid: u32) -> Option<Tenu> {
    use std::os::unix::fs::OpenOptionsExt;
    let avant = debut(pid)?;
    let exe = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH)
        .open(format!("/proc/{pid}/exe"))
        .ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    if debut(pid)? != avant {
        return None;
    }
    Some(Tenu {
        pid,
        debut: avant,
        du_compte: tout_au_compte(&status, crate::socle::uid()),
        exe,
    })
}

/// Gèle le processus `pid` seulement s'il est encore celui qui a démarré à `debut` : le signal part par un pidfd
/// (pidfd_send_signal), qui ne peut pas atteindre un autre processus, ouvert AVANT de relire le départ. Si le départ
/// lu après l'ouverture est le bon, le pidfd désigne ce processus (né avant l'ouverture, il portait déjà ce numéro).
/// Sans pidfd (noyau d'avant 5.3, filtre d'appels), rien n'est gelé : jamais de signal envoyé au numéro seul ici.
#[cfg(target_os = "linux")]
pub(crate) fn geler_si(pid: u32, debut_attendu: u64) -> bool {
    signaler_si(pid, debut_attendu, libc::SIGSTOP)
}

/// Arrête (SIGKILL) le processus `pid` seulement s'il est encore celui qui a démarré à `debut`, par un pidfd comme
/// `geler_si` : un numéro repris entre le gel et l'arrêt (un programme du compte suspendu par Ctrl-Z, gelé lui aussi)
/// n'est jamais tué à sa place.
#[cfg(target_os = "linux")]
pub(crate) fn tuer_si(pid: u32, debut_attendu: u64) -> bool {
    signaler_si(pid, debut_attendu, libc::SIGKILL)
}

/// Reprend (SIGCONT) le processus `pid` seulement s'il est encore celui qui a démarré à `debut`, par un pidfd comme
/// `geler_si` : la suspension d'un programme menaçant se lève sur ce processus-là, jamais sur un numéro repris.
#[cfg(target_os = "linux")]
pub(crate) fn reprendre_si(pid: u32, debut_attendu: u64) -> bool {
    signaler_si(pid, debut_attendu, libc::SIGCONT)
}

/// `signal` au processus `pid` par un pidfd, seulement s'il a démarré à `debut_attendu` (voir `geler_si`).
#[cfg(target_os = "linux")]
fn signaler_si(pid: u32, debut_attendu: u64, signal: libc::c_int) -> bool {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let Ok(p) = libc::pid_t::try_from(pid) else {
        return false;
    };
    // SAFETY: pidfd_open ne lit aucune mémoire ; un descripteur rendu (≥ 0) est à nous seuls, confié à OwnedFd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, p, 0u32) };
    let Some(fd) = i32::try_from(fd).ok().filter(|&f| f >= 0) else {
        return false;
    };
    // SAFETY: voir ci-dessus : ce descripteur vient d'être rendu par le noyau et n'appartient à rien d'autre.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    if debut(pid) != Some(debut_attendu) {
        return false;
    }
    // SAFETY: un descripteur à nous, vivant ; aucune information de signal (pointeur nul permis), drapeaux nuls.
    let r = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    r == 0
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
#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
mod tests {
    use super::*;

    /// Le départ se lit après la DERNIÈRE « ) » : un nom de programme qui en contient une (choisi par lui) ne décale
    /// pas les champs.
    #[test]
    fn debut_dans_stat() {
        let champs = |debut: &str| format!("S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {debut} 19 20");
        assert_eq!(debut_du_stat(&format!("42 (bash) {}", champs("8812"))), Some(8812));
        assert_eq!(debut_du_stat(&format!("42 (a) 1 2) {}", champs("77"))), Some(77));
        assert_eq!(debut_du_stat("42 (court) S 1 2"), None);
        assert_eq!(debut_du_stat(&format!("42 (x) {}", champs("-3"))), None);
    }

    /// Un programme setuid lancé depuis le compte (compte effectif autre) n'est pas « du compte ».
    #[test]
    fn comptes_du_status() {
        assert!(tout_au_compte(
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\n",
            1000
        ));
        assert!(!tout_au_compte("Uid:\t1000\t0\t0\t0\n", 1000));
        assert!(!tout_au_compte("Uid:\t0\t0\t0\t0\n", 1000));
        assert!(!tout_au_compte("Uid:\t1000\t1000\n", 1000));
        assert!(!tout_au_compte("Gid:\t1000\t1000\t1000\t1000\n", 1000));
    }

    /// Ce processus se tient lui-même (son programme, son départ, son compte) ; un départ faux ne gèle rien : le
    /// numéro seul ne suffit jamais à envoyer le signal.
    #[test]
    fn tenir_soi_et_ne_geler_ni_tuer_que_le_bon_depart() {
        use std::os::unix::fs::MetadataExt;
        let moi = std::process::id();
        let t = tenir(moi).expect("ce processus se tient");
        assert_eq!(t.pid, moi);
        assert!(t.du_compte);
        assert_eq!(Some(t.debut), debut(moi));
        let lance = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
        let tenu = t.exe().metadata().unwrap();
        assert_eq!((tenu.dev(), tenu.ino()), (lance.dev(), lance.ino()));
        assert!(tenir(u32::MAX).is_none());
        assert!(!geler_si(u32::MAX, 0));

        // Un enfant qui dort : un départ faux (celui d'un numéro repris) ne lui envoie rien ; le bon le gèle.
        let Ok(mut enfant) = std::process::Command::new("sleep").arg("30").spawn() else {
            return crate::essais::saute("sleep ne se lance pas");
        };
        let pid = enfant.id();
        let mut depart = None;
        for _ in 0..200 {
            if est_gele(pid) == Some(false) && nom_court(pid).as_deref() == Some("sleep") {
                depart = debut(pid);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let faux = depart.map(|d| geler_si(pid, d.wrapping_add(1)));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let gele_par_le_faux = est_gele(pid);
        let bon = depart.map(|d| geler_si(pid, d));
        // Le gel se fait quand le noyau sert l'enfant : un instant après le signal.
        let mut gele_par_le_bon = est_gele(pid);
        for _ in 0..200 {
            if gele_par_le_bon != Some(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            gele_par_le_bon = est_gele(pid);
        }
        // L'arrêt de même : un départ faux ne tue rien (l'enfant reste là, gelé), le bon le tue.
        // La reprise de même : un départ faux ne reprend rien, le bon reprend ; puis regelé pour la suite.
        let repris_par_le_faux = depart.map(|d| reprendre_si(pid, d.wrapping_add(1)));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let gele_apres_le_faux = est_gele(pid);
        let repris_par_le_bon = depart.map(|d| reprendre_si(pid, d));
        let mut repris = est_gele(pid);
        for _ in 0..200 {
            if repris != Some(true) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            repris = est_gele(pid);
        }
        let regele = depart.map(|d| geler_si(pid, d));
        for _ in 0..200 {
            if est_gele(pid) != Some(false) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let tue_par_le_faux = depart.map(|d| tuer_si(pid, d.wrapping_add(1)));
        let encore_la = est_gele(pid);
        let tue_par_le_bon = depart.map(|d| tuer_si(pid, d));
        let _ = enfant.kill();
        let fin = enfant.wait().ok();
        assert!(depart.is_some(), "l'enfant ne se lit pas");
        assert_eq!((faux, gele_par_le_faux), (Some(false), Some(false)));
        assert_eq!((bon, gele_par_le_bon), (Some(true), Some(true)));
        assert_eq!((repris_par_le_faux, gele_apres_le_faux), (Some(false), Some(true)));
        assert_eq!(
            (repris_par_le_bon, repris, regele),
            (Some(true), Some(false), Some(true))
        );
        assert_eq!((tue_par_le_faux, encore_la), (Some(false), Some(true)));
        assert_eq!(tue_par_le_bon, Some(true));
        assert_eq!(
            fin.and_then(|f| std::os::unix::process::ExitStatusExt::signal(&f)),
            Some(libc::SIGKILL)
        );
        assert!(!tuer_si(u32::MAX, 0));
        assert!(!reprendre_si(u32::MAX, 0));
    }

    #[test]
    fn etat_dans_stat() {
        assert_eq!(etat_du_stat("123 (bash) S 1 123 123 0 -1 4194304"), Some('S'));
        // Un nom avec parenthèses et espaces : on lit après la dernière « ) ».
        assert_eq!(etat_du_stat("123 (a b) c) T 1 1"), Some('T'));
        assert_eq!(etat_du_stat("sans parenthese"), None);
    }

    #[test]
    fn pids_d_un_proc_fabrique() {
        let d = crate::essais::temporaire().join(format!("vanguard-proc-{}", std::process::id()));
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
