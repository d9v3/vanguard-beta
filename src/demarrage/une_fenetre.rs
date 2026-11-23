//! Une seule fenêtre, côté `vanguard` : avant d'ouvrir une fenêtre, demander à celle qui est déjà ouverte (même
//! compte, même session graphique) de revenir devant. La règle commune est dans `socle::une_fenetre`.
//!
//! Frontière de confiance : le programme qui écoute au bout du canal n'est cru que s'il est prouvé être la fenêtre de
//! Vanguard que ce programme-ci aurait lancée. Sous Linux : le même compte (SO_PEERCRED), et l'image qui tourne
//! (`/proc/<pid>/exe`) a l'empreinte gravée dans ce programme, le processus étant tenu par un pidfd (SO_PEERPIDFD)
//! pendant toute la lecture : son numéro ne peut pas passer à un autre. Sous Windows : le processus serveur du tube
//! (GetNamedPipeServerProcessId), tenu ouvert, est du même compte et de la même session, son image est la fenêtre
//! posée à côté de ce programme, et le fichier à ce chemin a l'empreinte gravée. Rien n'est envoyé avant ; un échec
//! est dit, et la fenêtre s'ouvre comme avant (le choix le plus sûr : un imposteur ne peut ni recevoir quoi que ce
//! soit, ni empêcher la vraie fenêtre de s'ouvrir, et la nouvelle prend sa place).
//!
//! Deux lancements en même temps : un verrou par session, tenu par l'appelant jusqu'à ce que la fenêtre lancée dise
//! « ouverte » ; le second attend, puis la trouve et la ramène.

use std::path::Path;

use crate::socle::une_fenetre as regle;
use crate::tr;

/// Le plus long qu'un lancement attend le verrou d'un autre : le temps que la fenêtre de l'autre s'ouvre, et un peu.
const ATTENTE_VERROU: std::time::Duration = std::time::Duration::from_secs(25);

/// Ce qu'a donné la demande.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Issue {
    /// La fenêtre déjà ouverte, vérifiée, a répondu « ok » : rien à lancer.
    Ramenee,
    /// Aucune fenêtre n'écoute : la lancer.
    Personne,
    /// Quelque chose écoute, mais ce n'est pas la fenêtre de Vanguard (ou elle ne se laisse pas vérifier) : rien
    /// n'est envoyé ; la raison.
    Refusee(String),
    /// Le canal ne peut pas être sûr ici (dossier de session absent ou ouvert à d'autres, noyau trop ancien…) : il
    /// n'est pas utilisé ; la raison.
    Indisponible(String),
}

/// Une demande faite, avec le verrou qui ordonne les lancements de la session : à garder jusqu'à ce que la fenêtre
/// lancée (si elle l'est) ait dit « ouverte ».
pub(super) struct Tour {
    pub(super) issue: Issue,
    _verrou: Option<crate::socle::Verrou>,
}

/// Demande à la fenêtre déjà ouverte de revenir devant, si c'est bien elle (`attendue` : l'empreinte gravée de la
/// fenêtre ; `fenetre` : son chemin à côté de ce programme, que Windows compare à l'image du serveur).
pub(super) fn ramener(attendue: &[u8; 32], fenetre: &Path) -> Tour {
    #[cfg(target_os = "linux")]
    let (issue, verrou) = {
        let _ = fenetre;
        linux::ramener(attendue)
    };
    #[cfg(windows)]
    let (issue, verrou) = windows::ramener(attendue, fenetre);
    Tour { issue, _verrou: verrou }
}

/// La raison, en mots, d'un dossier refusé.
#[cfg(unix)]
fn raison_dossier(r: regle::Refus) -> String {
    match r {
        regle::Refus::PasUnDossier => tr!(
            "le dossier de session n'est pas un dossier",
            "the session folder is not a folder"
        ),
        regle::Refus::Lien => tr!("le dossier de session est un lien", "the session folder is a link"),
        regle::Refus::AutreCompte => tr!(
            "le dossier de session est à un autre compte",
            "the session folder belongs to another account"
        ),
        regle::Refus::Ouvert => tr!(
            "le dossier de session est ouvert à d'autres comptes",
            "the session folder is open to other accounts"
        ),
        regle::Refus::SansSession => tr!(
            "XDG_RUNTIME_DIR absent ou relatif",
            "XDG_RUNTIME_DIR missing or relative"
        ),
        regle::Refus::Illisible => tr!(
            "le dossier de session ne se crée pas ou ne se lit pas",
            "the session folder cannot be created or read"
        ),
    }
    .to_string()
}

/// L'empreinte SHA-256 d'un fichier ouvert, lu jusqu'au bout, `max` octets au plus (au-delà : refusé).
fn empreinte(mut f: std::fs::File, max: u64) -> std::io::Result<[u8; 32]> {
    use sha2::Digest;
    use std::io::Read;
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 1 << 16];
    let mut total: u64 = 0;
    loop {
        let n = f.read(&mut tampon)?;
        let Some(lus) = tampon.get(..n).filter(|l| !l.is_empty()) else {
            break;
        };
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > max {
            return Err(std::io::Error::other(tr!("image trop grande", "image too large")));
        }
        h.update(lus);
    }
    Ok(h.finalize().into())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use super::{Issue, regle};
    use crate::{tr, trf};

    pub(super) fn ramener(attendue: &[u8; 32]) -> (Issue, Option<crate::socle::Verrou>) {
        let variable = |nom: &str| std::env::var(nom).ok();
        ramener_dans(
            std::env::var_os("XDG_RUNTIME_DIR"),
            variable("WAYLAND_DISPLAY").as_deref(),
            variable("DISPLAY").as_deref(),
            attendue,
        )
    }

    /// `ramener`, avec le dossier de session et les noms d'affichage donnés (les essais en donnent des jetables).
    pub(super) fn ramener_dans(
        runtime: Option<std::ffi::OsString>,
        wayland: Option<&str>,
        display: Option<&str>,
        attendue: &[u8; 32],
    ) -> (Issue, Option<crate::socle::Verrou>) {
        let moi = crate::socle::uid();
        let dossier = match regle::dossier_prive(runtime, moi) {
            Ok(d) => d,
            Err(r) => return (Issue::Indisponible(super::raison_dossier(r)), None),
        };
        let Some(nom) = regle::nom_prise(wayland, display) else {
            return (
                Issue::Indisponible(
                    tr!(
                        "session graphique sans nom simple",
                        "graphical session without a plain name"
                    )
                    .into(),
                ),
                None,
            );
        };
        let verrou =
            crate::socle::Verrou::prendre(&dossier, &regle::nom_verrou(&nom), false, super::ATTENTE_VERROU).ok();
        let issue = joindre(&dossier.join(&nom), attendue, moi);
        (issue, verrou)
    }

    /// Joint la prise, vérifie qui écoute, et seulement alors demande « montre-toi ». Puis, sous Hyprland, le focus
    /// à la fenêtre de ce processus-là (la fenêtre ne peut pas le prendre elle-même : son bac à sable lui interdit
    /// la prise de Hyprland).
    pub(super) fn joindre(prise: &Path, attendue: &[u8; 32], moi: u32) -> Issue {
        let flux = match connecter(prise) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Issue::Personne;
            }
            Err(e) => {
                return Issue::Indisponible(trf!("canal injoignable : {}", "channel unreachable: {}", e));
            }
        };
        let pid = match verifier(&flux, attendue, moi) {
            Ok(pid) => pid,
            Err(issue) => return issue,
        };
        if !echanger(flux) {
            return Issue::Indisponible(
                tr!("la fenêtre ouverte n'a pas répondu", "the open window did not answer").into(),
            );
        }
        let _ = crate::fenetre::ramener_hyprland(pid);
        Issue::Ramenee
    }

    /// Se branche à la prise dans un fil, `DELAI` au plus : une prise dont la file est pleine ne fige pas le
    /// lancement.
    fn connecter(prise: &Path) -> std::io::Result<UnixStream> {
        let (envoi, reception) = std::sync::mpsc::channel();
        let p = prise.to_path_buf();
        crate::socle::fil::lancer("une-fenetre", move || {
            let _ = envoi.send(UnixStream::connect(p));
        })?;
        reception
            .recv_timeout(regle::DELAI)
            .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut)))
    }

    /// Qui écoute ? Le pid du processus si c'est la fenêtre de Vanguard de ce compte, sinon l'issue (refusée ou
    /// indisponible) : rien n'a été envoyé.
    pub(super) fn verifier(flux: &UnixStream, attendue: &[u8; 32], moi: u32) -> Result<i32, Issue> {
        let refus = |r: String| Err(Issue::Refusee(r));
        // Sans pidfd, le numéro du processus pourrait passer à un autre pendant la lecture de son image : pas de
        // canal plutôt qu'un canal moins sûr.
        let Some(pidfd) = crate::socle::pidfd_d_en_face(flux) else {
            return Err(Issue::Indisponible(
                tr!(
                    "ce noyau ne dit pas quel processus écoute (SO_PEERPIDFD, Linux 6.5)",
                    "this kernel does not tell which process listens (SO_PEERPIDFD, Linux 6.5)"
                )
                .into(),
            ));
        };
        let Some((pid, compte)) = crate::socle::processus_d_en_face(flux) else {
            return refus(
                tr!(
                    "le processus qui écoute est inconnu",
                    "the listening process is unknown"
                )
                .into(),
            );
        };
        if compte != moi {
            return refus(trf!(
                "le processus {} qui écoute est d'un autre compte",
                "listening process {} belongs to another account",
                pid
            ));
        }
        if pid_du_pidfd(&pidfd) != Some(pid) {
            return refus(trf!(
                "le processus {} qui écoute ne se laisse pas tenir",
                "listening process {} cannot be held",
                pid
            ));
        }
        let lue = std::fs::File::open(format!("/proc/{pid}/exe"))
            .and_then(|f| super::empreinte(f, super::super::lancer_fenetre::TAILLE_MAX));
        // Toujours le même processus après la lecture : le pidfd le tenait, il vit encore.
        if !crate::socle::pidfd_vivant(&pidfd) {
            return refus(trf!(
                "le processus {} qui écoute est parti pendant la vérification",
                "listening process {} left during the check",
                pid
            ));
        }
        match lue {
            Ok(e) if &e == attendue => Ok(pid),
            Ok(_) => refus(trf!(
                "le processus {} qui écoute n'est pas la fenêtre de Vanguard (empreinte différente)",
                "listening process {} is not the Vanguard window (different fingerprint)",
                pid
            )),
            Err(e) => refus(trf!(
                "l'image du processus {} qui écoute est illisible : {}",
                "the image of listening process {} is unreadable: {}",
                pid,
                e
            )),
        }
    }

    /// Le numéro du processus que tient `pidfd`, lu dans /proc/self/fdinfo (« Pid: »).
    fn pid_du_pidfd(pidfd: &std::os::fd::OwnedFd) -> Option<i32> {
        use std::os::fd::AsRawFd;
        let texte = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).ok()?;
        texte
            .lines()
            .find_map(|l| l.strip_prefix("Pid:"))
            .and_then(|n| n.trim().parse::<i32>().ok())
            .filter(|&n| n > 0)
    }

    /// Un octet « montre-toi », un octet « ok » attendu ; `DELAI` au plus pour chacun.
    fn echanger(mut flux: UnixStream) -> bool {
        if flux.set_read_timeout(Some(regle::DELAI)).is_err() || flux.set_write_timeout(Some(regle::DELAI)).is_err() {
            return false;
        }
        if flux.write_all(&[regle::DEMANDE]).is_err() {
            return false;
        }
        let mut reponse = [0u8; 1];
        flux.read_exact(&mut reponse).is_ok() && reponse == [regle::REPONSE]
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;

    use super::{Issue, regle};
    use crate::machine::windows::une_fenetre as tube;
    use crate::{tr, trf};

    pub(super) fn ramener(attendue: &[u8; 32], fenetre: &Path) -> (Issue, Option<crate::socle::Verrou>) {
        let Some(sid) = crate::machine::windows::processus::sid() else {
            return (
                Issue::Indisponible(tr!("compte illisible", "account unreadable").into()),
                None,
            );
        };
        let Some(session) = tube::session_de(std::process::id()) else {
            return (
                Issue::Indisponible(tr!("session illisible", "session unreadable").into()),
                None,
            );
        };
        let Some(nom) = regle::nom_tube(&sid, session) else {
            return (
                Issue::Indisponible(tr!("compte illisible", "account unreadable").into()),
                None,
            );
        };
        let verrou = crate::socle::Verrou::prendre(
            &crate::socle::dossier_local(),
            &format!("fenetre-{session}.verrou"),
            false,
            super::ATTENTE_VERROU,
        )
        .ok();
        (joindre(&nom, &sid, session, attendue, fenetre), verrou)
    }

    /// Ouvre le tube, vérifie son serveur, et seulement alors demande « montre-toi ».
    pub(super) fn joindre(nom: &str, sid: &str, session: u32, attendue: &[u8; 32], fenetre: &Path) -> Issue {
        let client = match tube::Client::ouvrir(nom) {
            Ok(Some(c)) => c,
            Ok(None) => return Issue::Personne,
            Err(e) => return Issue::Indisponible(trf!("canal injoignable : {}", "channel unreachable: {}", e)),
        };
        let pid = match verifier(&client, sid, session, attendue, fenetre) {
            Ok(pid) => pid,
            Err(issue) => return issue,
        };
        // Le droit de passer devant, donné à la fenêtre (sans effet si ce programme-ci ne l'a pas lui-même).
        tube::permettre_premier_plan(pid);
        if client.echanger() {
            Issue::Ramenee
        } else {
            Issue::Indisponible(tr!("la fenêtre ouverte n'a pas répondu", "the open window did not answer").into())
        }
    }

    /// Le serveur du tube est-il la fenêtre de Vanguard de ce compte et de cette session ? Son pid, sinon l'issue :
    /// rien n'a été envoyé.
    pub(super) fn verifier(
        client: &tube::Client,
        sid: &str,
        session: u32,
        attendue: &[u8; 32],
        fenetre: &Path,
    ) -> Result<u32, Issue> {
        let refus = |r: String| Err(Issue::Refusee(r));
        let Some(pid) = client.pid_du_serveur() else {
            return refus(
                tr!(
                    "le processus qui écoute est inconnu",
                    "the listening process is unknown"
                )
                .into(),
            );
        };
        let tenu = match crate::machine::windows::processus::Tenu::ouvrir(pid) {
            Ok(t) => t,
            Err(e) => {
                return refus(trf!(
                    "le processus {} qui écoute ne s'ouvre pas : {}",
                    "listening process {} does not open: {}",
                    pid,
                    e
                ));
            }
        };
        // Le processus tenu, le tube toujours branché : son serveur vit encore, c'est donc bien lui que la poignée
        // tient (un numéro n'est redonné qu'après la fin du processus, et la poignée du tube ne s'hérite pas).
        if !client.branche() {
            return refus(trf!(
                "le processus {} qui écoute est parti pendant la vérification",
                "listening process {} left during the check",
                pid
            ));
        }
        if tenu.sid().ok().as_deref() != Some(sid) {
            return refus(trf!(
                "le processus {} qui écoute est d'un autre compte",
                "listening process {} belongs to another account",
                pid
            ));
        }
        if tube::session_de(pid) != Some(session) {
            return refus(trf!(
                "le processus {} qui écoute est d'une autre session",
                "listening process {} belongs to another session",
                pid
            ));
        }
        let image = tenu.chemin().map(std::path::PathBuf::from);
        let attendu = std::fs::canonicalize(fenetre).ok();
        let canon = image.as_deref().and_then(|i| std::fs::canonicalize(i).ok());
        let meme = |a: &Path, b: &Path| {
            a.as_os_str().to_string_lossy().to_lowercase() == b.as_os_str().to_string_lossy().to_lowercase()
        };
        match (&canon, &attendu) {
            (Some(i), Some(a)) if meme(i, a) => {}
            _ => {
                return refus(trf!(
                    "le processus {} qui écoute n'est pas la fenêtre posée à côté de ce programme ({})",
                    "listening process {} is not the window next to this program ({})",
                    pid,
                    image.as_deref().map_or_default(|i| i.display().to_string())
                ));
            }
        }
        // Le fichier de cette image, ouvert sans partage d'écriture : ses octets ne changent pas pendant la lecture.
        let lue = {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x1;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(fenetre)
                .and_then(|f| super::empreinte(f, super::super::lancer_fenetre::TAILLE_MAX))
        };
        match lue {
            Ok(e) if &e == attendue => Ok(pid),
            Ok(_) => refus(trf!(
                "le processus {} qui écoute n'est pas la fenêtre de Vanguard (empreinte différente)",
                "listening process {} is not the Vanguard window (different fingerprint)",
                pid
            )),
            Err(e) => refus(trf!(
                "l'image du processus {} qui écoute est illisible : {}",
                "the image of listening process {} is unreadable: {}",
                pid,
                e
            )),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
// Les aides des essais (hors `#[test]`) échouent comme eux : par unwrap.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::linux::{joindre, ramener_dans};
    use super::{Issue, regle};
    use crate::socle::une_fenetre::SOUS_DOSSIER;
    use std::io::{BufRead, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    /// Ce que joue `joue_l_ecoute` : le rôle, puis ses paramètres.
    const ROLE: &str = "VANGUARD_ESSAI_UNE_FENETRE";
    /// Le dossier de session jetable donné aux rôles.
    const RUNTIME: &str = "VANGUARD_ESSAI_RUNTIME";
    /// Le fichier où l'écoute note chaque octet reçu.
    const TRACE: &str = "VANGUARD_ESSAI_TRACE";
    /// Le nom de session (WAYLAND_DISPLAY) des essais.
    const SESSION: &str = "essai-0";

    /// Un dossier de session jetable, court (une prise Unix tient en 108 octets), à ce compte : 0700.
    fn runtime() -> crate::essais::Jetable {
        let d = crate::essais::Jetable::garder(PathBuf::from("/tmp").join(crate::essais::nom_unique("uf")));
        std::fs::set_permissions(&*d, std::fs::Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn prise(runtime: &Path) -> PathBuf {
        runtime
            .join(SOUS_DOSSIER)
            .join(regle::nom_prise(Some(SESSION), None).unwrap())
    }

    /// L'empreinte de ce programme d'essai : celle d'une « vraie fenêtre » quand il joue l'écoute.
    fn empreinte_de_l_essai() -> [u8; 32] {
        super::empreinte(std::fs::File::open(std::env::current_exe().unwrap()).unwrap(), u64::MAX).unwrap()
    }

    /// Relance ce programme d'essai dans le rôle `role` (un second vrai processus).
    fn jouer(role: &str, runtime: &Path, trace: &Path) -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "demarrage::une_fenetre::tests::joue_l_ecoute",
                "--ignored",
                "--nocapture",
                "--quiet",
                "--test-threads=1",
            ])
            .env(ROLE, role)
            .env(RUNTIME, runtime)
            .env(TRACE, trace)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    /// Lit la sortie du rôle jusqu'à une ligne qui commence par `vu:` ; rend ce qui suit.
    fn attendre_ligne(enfant: &mut Child) -> String {
        let sortie = enfant.stdout.as_mut().unwrap();
        let mut lignes = std::io::BufReader::new(sortie).lines();
        lignes
            .find_map(|l| l.ok().and_then(|l| l.strip_prefix("vu:").map(str::to_string)))
            .unwrap_or_default()
    }

    /// Une écoute qui note chaque octet reçu et répond « ok » à la demande, jusqu'à ce que son entrée se ferme.
    fn ecouter(prise: &Path, trace: &Path) {
        let _ = std::fs::remove_file(prise);
        let ecoute = UnixListener::bind(prise).unwrap();
        ecoute.set_nonblocking(true).unwrap();
        println!("vu:pret");
        std::io::stdout().flush().unwrap();
        let fin = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fin.clone();
        std::thread::spawn(move || {
            let _ = std::io::stdin().read(&mut [0u8; 1]);
            f.store(true, std::sync::atomic::Ordering::Release);
        });
        while !fin.load(std::sync::atomic::Ordering::Acquire) {
            let Ok((mut flux, _)) = ecoute.accept() else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            flux.set_nonblocking(false).unwrap();
            flux.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut octet = [0u8; 1];
            if flux.read_exact(&mut octet).is_ok() {
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(trace)
                    .unwrap()
                    .write_all(&octet)
                    .unwrap();
                if octet == [regle::DEMANDE] {
                    let _ = flux.write_all(&[regle::REPONSE]);
                }
            }
        }
    }

    /// Les rôles des essais, joués par une relance de ce programme ; ne fait rien sans `ROLE`.
    #[test]
    #[ignore = "lancé seulement par les essais d'une seule fenêtre, comme second processus"]
    fn joue_l_ecoute() {
        let (Ok(role), Some(runtime), Some(trace)) =
            (std::env::var(ROLE), std::env::var_os(RUNTIME), std::env::var_os(TRACE))
        else {
            return;
        };
        let (runtime, trace) = (PathBuf::from(runtime), PathBuf::from(trace));
        match role.as_str() {
            // La fenêtre (ou un imposteur : c'est l'empreinte attendue par l'autre côté qui en décide).
            "ecoute" => {
                std::fs::create_dir_all(prise(&runtime).parent().unwrap()).unwrap();
                ecouter(&prise(&runtime), &trace);
            }
            // Un lancement de `vanguard` : ramène la fenêtre, ou, s'il n'y en a pas, « l'ouvre » (écoute lui-même,
            // sous son verrou, comme la vraie fenêtre lancée qui dit « ouverte » avant que le verrou soit rendu).
            "lanceur" => {
                let (issue, verrou) = ramener_dans(
                    Some(runtime.clone().into()),
                    Some(SESSION),
                    None,
                    &empreinte_de_l_essai(),
                );
                match issue {
                    Issue::Ramenee => println!("vu:ramenee"),
                    Issue::Personne => {
                        let p = prise(&runtime);
                        let _ = std::fs::remove_file(&p);
                        let ecoute = UnixListener::bind(&p).unwrap();
                        std::thread::sleep(Duration::from_millis(300));
                        drop(verrou);
                        println!("vu:lancee");
                        std::io::stdout().flush().unwrap();
                        for flux in ecoute.incoming().take(1) {
                            let mut flux = flux.unwrap();
                            let mut octet = [0u8; 1];
                            if flux.read_exact(&mut octet).is_ok() && octet == [regle::DEMANDE] {
                                let _ = flux.write_all(&[regle::REPONSE]);
                            }
                        }
                    }
                    autre => println!("vu:{autre:?}"),
                }
            }
            _ => {}
        }
    }

    fn trace_de(trace: &Path) -> Vec<u8> {
        std::fs::read(trace).unwrap_or_default()
    }

    fn arreter(mut enfant: Child) {
        drop(enfant.stdin.take());
        let _ = enfant.wait();
    }

    /// La fenêtre déjà ouverte (un autre processus, de l'empreinte attendue, du même compte) reçoit la demande,
    /// répond, et le lancement ne rouvre rien.
    #[test]
    fn la_vraie_fenetre_est_ramenee() {
        let d = runtime();
        let trace = d.join("trace");
        let mut ecoute = jouer("ecoute", &d, &trace);
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        let issue = joindre(&prise(&d), &empreinte_de_l_essai(), crate::socle::uid());
        assert_eq!(issue, Issue::Ramenee);
        assert_eq!(trace_de(&trace), [regle::DEMANDE]);
        arreter(ecoute);
    }

    /// Un autre programme qui écoute à la place de la fenêtre (empreinte différente) : refusé, et il ne reçoit
    /// pas un octet.
    #[test]
    fn un_imposteur_ne_recoit_rien() {
        let d = runtime();
        let trace = d.join("trace");
        let mut ecoute = jouer("ecoute", &d, &trace);
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        let mut autre = empreinte_de_l_essai();
        autre[0] ^= 1;
        let issue = joindre(&prise(&d), &autre, crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("empreinte") || r.contains("fingerprint")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(trace_de(&trace).is_empty(), "l'imposteur a reçu {:?}", trace_de(&trace));
        arreter(ecoute);
    }

    /// Un écouteur d'un autre compte (le compte attendu n'est pas le sien) : refusé, rien envoyé.
    #[test]
    fn un_autre_compte_ne_recoit_rien() {
        let d = runtime();
        let trace = d.join("trace");
        let mut ecoute = jouer("ecoute", &d, &trace);
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        let issue = joindre(&prise(&d), &empreinte_de_l_essai(), crate::socle::uid().wrapping_add(1));
        assert!(matches!(&issue, Issue::Refusee(_)), "{issue:?}");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(trace_de(&trace), Vec::<u8>::new());
        arreter(ecoute);
    }

    /// Un dossier de session ouvert à d'autres (0755), ou à un autre compte : le canal n'est pas utilisé, même si
    /// une vraie fenêtre y écoute ; le lancement rouvre une fenêtre (Indisponible), sans rien envoyer.
    #[test]
    fn un_dossier_mal_protege_est_refuse() {
        let d = runtime();
        let trace = d.join("trace");
        let mut ecoute = jouer("ecoute", &d, &trace);
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        for (dossier, mode) in [(d.to_path_buf(), 0o755), (d.join(SOUS_DOSSIER), 0o750)] {
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(mode)).unwrap();
            let (issue, _) = ramener_dans(Some(d.as_os_str().into()), Some(SESSION), None, &empreinte_de_l_essai());
            assert!(matches!(&issue, Issue::Indisponible(_)), "{mode:o} {issue:?}");
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (issue, _) = ramener_dans(None, Some(SESSION), None, &empreinte_de_l_essai());
        assert!(matches!(&issue, Issue::Indisponible(_)), "{issue:?}");
        let (issue, _) = ramener_dans(Some("relatif".into()), Some(SESSION), None, &empreinte_de_l_essai());
        assert!(matches!(&issue, Issue::Indisponible(_)), "{issue:?}");
        assert_eq!(trace_de(&trace), Vec::<u8>::new());
        // Remis à 0700 : la même fenêtre est ramenée (l'essai refusait bien pour le dossier).
        let (issue, _) = ramener_dans(Some(d.as_os_str().into()), Some(SESSION), None, &empreinte_de_l_essai());
        assert_eq!(issue, Issue::Ramenee);
        arreter(ecoute);
    }

    /// Un dossier de session qui est un lien (vers un dossier privé) : refusé.
    #[test]
    fn un_lien_de_session_est_refuse() {
        let d = runtime();
        let lien = d.join("lien");
        let vrai = d.join("vrai");
        std::fs::create_dir(&vrai).unwrap();
        std::fs::set_permissions(&vrai, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        let (issue, _) = ramener_dans(Some(lien.into()), Some(SESSION), None, &empreinte_de_l_essai());
        assert!(matches!(&issue, Issue::Indisponible(_)), "{issue:?}");
    }

    /// Personne n'écoute : le lancement ouvre la fenêtre.
    #[test]
    fn sans_fenetre_personne() {
        let d = runtime();
        let (issue, verrou) = ramener_dans(Some(d.as_os_str().into()), Some(SESSION), None, &empreinte_de_l_essai());
        assert_eq!(issue, Issue::Personne);
        assert!(verrou.is_some());
    }

    /// Deux lancements en même temps (deux processus) : un seul ouvre la fenêtre, l'autre la ramène.
    #[test]
    fn deux_lancements_une_fenetre() {
        let d = runtime();
        let trace = d.join("trace");
        let mut a = jouer("lanceur", &d, &trace);
        let mut b = jouer("lanceur", &d, &trace);
        let (fil_a, fil_b) = (
            std::thread::spawn(move || (attendre_ligne(&mut a), a)),
            std::thread::spawn(move || (attendre_ligne(&mut b), b)),
        );
        let (ra, a) = fil_a.join().unwrap();
        let (rb, b) = fil_b.join().unwrap();
        let mut vus = [ra, rb];
        vus.sort();
        assert_eq!(vus, ["lancee".to_string(), "ramenee".to_string()]);
        arreter(a);
        arreter(b);
    }
}
