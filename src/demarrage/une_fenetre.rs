//! Une seule fenêtre, côté `vanguard` : avant d'ouvrir une fenêtre, demander à celle qui est déjà ouverte (même
//! compte, même session graphique) de revenir devant. La règle commune est dans `socle::une_fenetre`.
//!
//! Frontière de confiance : le programme qui répond au bout du canal n'est cru que s'il est prouvé être la fenêtre
//! de Vanguard que ce programme-ci aurait lancée. La demande n'est envoyée qu'après cette preuve ; un échec est dit,
//! et une fenêtre s'ouvre (un imposteur refusé n'empêche pas la vraie fenêtre de s'ouvrir ; sous Linux, elle prend
//! sa place). La demande porte un nombre aléatoire frais que la réponse doit reprendre, et un octet qui attendait
//! déjà dans le canal avant elle est refusé : une réponse écrite d'avance, ou par un autre programme qui n'a pas lu
//! la demande, ne passe pas.
//!
//! Linux : c'est le processus qui parle qui est vérifié, pas celui qui a ouvert l'écoute (qui peut avoir passé la
//! prise à un autre, puis être devenu la vraie image par exec). La fenêtre envoie d'abord un octet d'accueil ; le
//! noyau y attache son expéditeur (SCM_CREDENTIALS, SCM_PIDFD, demandés avant la connexion), que nul ne peut forger
//! sans être root de son espace de noms. Cet expéditeur doit être du même compte et du même espace de noms
//! utilisateur (un espace de noms à soi permettrait de faire mentir `/proc/<pid>/exe`, PR_SET_MM_EXE_FILE), tenu par
//! son pidfd pendant toute la lecture, et son image (`/proc/<pid>/exe`) doit avoir l'empreinte gravée dans ce
//! programme. Chaque octet de la réponse doit venir du même processus, et son image doit être encore le même
//! fichier après la réponse (un exec entre la vérification et la réponse est refusé). Windows : le tube doit avoir
//! ce compte pour propriétaire et pour seul nom de sa liste d'accès (un autre compte qui aurait pris le nom ne passe
//! pas), son processus serveur, tenu ouvert jusqu'à la fin, est du même compte, de la même session et d'un niveau
//! d'intégrité au moins égal, et le fichier de son image a l'empreinte gravée (une autre copie de la même version
//! est la même fenêtre).
//!
//! Hors garantie (MODELE-DE-MENACE.md) : un programme du même compte qui pilote la vraie image (ptrace, LD_PRELOAD,
//! un exec puis un retour à la vraie image entre la réponse et le dernier contrôle, ou sur Windows un fichier
//! remplacé après le lancement) ; la vraie fenêtre figée.
//!
//! Deux lancements en même temps : un verrou par session, tenu par l'appelant jusqu'à ce que la fenêtre lancée dise
//! « ouverte » ; le second attend, puis la trouve et la ramène. Un verrou qui ne se prend pas est dit.

use std::path::Path;

use crate::socle::une_fenetre as regle;
use crate::tr;

/// Le premier essai du verrou : au-delà, un autre lancement est en cours, et c'est dit avant d'attendre le reste.
const PREMIERE_ATTENTE: std::time::Duration = std::time::Duration::from_secs(1);
/// Le plus long qu'un lancement attend le verrou d'un autre, en tout : tout le temps que l'autre attend sa fenêtre
/// (`ATTENTE`), et un peu plus. Au-delà, il essaie quand même le canal, puis ouvre une fenêtre (et le dit).
const ATTENTE_VERROU: std::time::Duration =
    super::lancer_fenetre::ATTENTE.saturating_add(std::time::Duration::from_secs(5));

/// Le plus long que `vanguard` attend l'accueil : la fenêtre sert un client à la fois, et en garde un au plus
/// `DELAI + VERIFICATION` (lire sa demande), plus sa cadence (0,3 s) et l'attente de sa fenêtre (0,75 s), plus
/// `DELAI` (répondre ; sous Windows, attendre que le client ferme) : environ 7 s. Un lancement qui arrive pendant ce
/// temps attend son tour, plus une marge.
const ATTENTE_ACCUEIL: std::time::Duration = regle::DELAI
    .saturating_add(regle::VERIFICATION)
    .saturating_add(regle::DELAI)
    .saturating_add(std::time::Duration::from_secs(2));

/// Le plus long que `vanguard` attend la vérification de ce qui écoute (se joindre, lire l'accueil, faire
/// l'empreinte de l'image). Dans les essais seulement, 60 s : leur « fenêtre » est leur propre programme d'essai, de
/// plusieurs centaines de Mio, dont l'empreinte se fait pendant que d'autres essais tournent (comme `TAILLE_MAX`).
const BORNE_VERIFICATION: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(60)
} else {
    ATTENTE_ACCUEIL.saturating_add(regle::VERIFICATION)
};

/// Ce qu'a donné la demande.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Issue {
    /// La fenêtre déjà ouverte, vérifiée, a répondu « ok » : rien à lancer. Vrai : Hyprland a répondu « ok » à
    /// la demande de focus ; faux : elle a seulement été priée de revenir devant (le bureau en décide).
    Ramenee(bool),
    /// Aucune fenêtre n'écoute : la lancer.
    Personne,
    /// Quelque chose écoute, mais ce n'est pas la fenêtre de Vanguard (ou elle ne se laisse pas vérifier) : la
    /// demande n'est pas envoyée ; la raison.
    Refusee(String),
    /// Le canal ne peut pas être sûr ici (dossier de session absent ou ouvert à d'autres, noyau trop ancien…) : la
    /// raison.
    Indisponible(String),
    /// Ce qui écoute n'a pas répondu à temps, ou la fenêtre vérifiée n'a pas été ramenée (muette, sans fenêtre
    /// sous Hyprland, partie) : une nouvelle s'ouvre, mais sans lui prendre sa prise (ce peut être la vraie). La
    /// raison.
    SansReponse(String),
}

/// Une demande faite, avec le verrou qui ordonne les lancements de la session : à garder jusqu'à ce que la fenêtre
/// lancée (si elle l'est) ait dit « ouverte ».
pub(super) struct Tour {
    pub(super) issue: Issue,
    /// Le verrou, ou pourquoi il n'est pas tenu (l'ordre des lancements n'est alors pas garanti : à dire).
    pub(super) verrou: Result<crate::socle::Verrou, String>,
}

/// Demande à la fenêtre déjà ouverte de revenir devant, si c'est bien elle (`attendue` : l'empreinte gravée de la
/// fenêtre).
pub(super) fn ramener(attendue: &[u8; 32]) -> Tour {
    #[cfg(target_os = "linux")]
    let (issue, verrou) = linux::ramener(attendue);
    #[cfg(windows)]
    let (issue, verrou) = windows::ramener(attendue);
    Tour { issue, verrou }
}

/// Le verrou des lancements de la session : un premier essai court, puis, s'il est tenu, une ligne pour dire
/// qu'on attend, et le reste de l'attente. L'échec, typé, s'il ne se prend pas.
fn prendre_verrou(dossier: &Path, nom: &str) -> Result<crate::socle::Verrou, crate::modele::Echec> {
    use crate::modele::Echec;
    use crate::socle::{SansVerrou, Verrou};
    match Verrou::prendre(dossier, nom, false, PREMIERE_ATTENTE) {
        Ok(v) => return Ok(v),
        Err(SansVerrou::Impossible(e)) => return Err(Echec::echoue("fenetre/verifier", e)),
        Err(SansVerrou::Occupe) => {}
    }
    eprintln!(
        "{}",
        tr!(
            "Un autre lancement de Vanguard est en cours : attente de sa fenêtre…",
            "Another Vanguard launch is under way: waiting for its window…"
        )
    );
    Verrou::prendre(dossier, nom, false, ATTENTE_VERROU.saturating_sub(PREMIERE_ATTENTE)).map_err(|e| match e {
        SansVerrou::Occupe => Echec::echoue(
            "fenetre/verifier",
            tr!(
                "un autre lancement tient le verrou depuis trop longtemps",
                "another launch has held the lock for too long"
            ),
        ),
        SansVerrou::Impossible(e) => Echec::echoue("fenetre/verifier", e),
    })
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
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use super::{Issue, regle};
    use crate::{tr, trf};

    pub(super) fn ramener(attendue: &[u8; 32]) -> (Issue, Result<crate::socle::Verrou, String>) {
        let variable = |nom: &str| std::env::var(nom).ok();
        ramener_dans(
            std::env::var_os("XDG_RUNTIME_DIR"),
            variable("WAYLAND_DISPLAY").as_deref(),
            variable("DISPLAY").as_deref(),
            attendue,
            &crate::fenetre::ramener_hyprland,
        )
    }

    /// Ce qui ramène, sous Hyprland, la fenêtre d'un processus (les essais en donnent un faux : ils ne touchent pas
    /// au bureau de la personne).
    pub(super) type Bureau<'a> = &'a dyn Fn(i32) -> crate::fenetre::Hyprland;

    /// `ramener`, avec le dossier de session, les noms d'affichage et le bureau donnés (les essais en donnent des
    /// jetables).
    pub(super) fn ramener_dans(
        runtime: Option<std::ffi::OsString>,
        wayland: Option<&str>,
        display: Option<&str>,
        attendue: &[u8; 32],
        bureau: Bureau<'_>,
    ) -> (Issue, Result<crate::socle::Verrou, String>) {
        let sans_verrou = |r: &str| Err(r.to_string());
        let moi = crate::socle::uid();
        let dossier = match regle::dossier_prive(runtime, moi) {
            Ok(d) => d,
            Err(r) => {
                let r = super::raison_dossier(r);
                return (Issue::Indisponible(r.clone()), sans_verrou(&r));
            }
        };
        let Some(nom) = regle::nom_prise(wayland, display) else {
            let r = tr!(
                "session graphique sans nom simple",
                "graphical session without a plain name"
            );
            return (Issue::Indisponible(r.into()), sans_verrou(r));
        };
        let verrou = super::prendre_verrou(&dossier, &regle::nom_verrou(&nom)).map_err(String::from);
        let issue = joindre(&dossier.join(&nom), attendue, moi, bureau);
        (issue, verrou)
    }

    /// Joint la prise, vérifie qui parle, et seulement alors demande « montre-toi ». Puis, sous Hyprland, le focus
    /// à la fenêtre de ce processus-là (la fenêtre ne peut pas le prendre elle-même : son bac à sable lui interdit
    /// la prise de Hyprland). Une fenêtre vérifiée qui n'est pas ramenée garde sa prise (`SansReponse`).
    pub(super) fn joindre(prise: &Path, attendue: &[u8; 32], moi: u32, bureau: Bureau<'_>) -> Issue {
        let (flux, accueil, image) = match verifie(prise, attendue, moi) {
            Ok(v) => v,
            Err(issue) => return issue,
        };
        if let Err(issue) = echanger(flux, &accueil, image) {
            return issue;
        }
        let issue = demander_au_bureau(accueil.pid, bureau);
        // Partie pendant ce temps : rien n'a été ramené, quoi qu'ait dit le bureau.
        if !crate::socle::pidfd_vivant(&accueil.pidfd) {
            return Issue::SansReponse(trf!(
                "le processus {} de la fenêtre est parti",
                "window process {} left",
                accueil.pid
            ));
        }
        issue
    }

    /// Le focus à la fenêtre du processus `pid`, sous Hyprland. Elle vient de répondre : sa fenêtre peut ne pas
    /// encore être connue du bureau (une fenêtre qui s'ouvre) ; redemandé toutes les `PAS` pendant `ATTENTE` au plus.
    fn demander_au_bureau(pid: i32, bureau: Bureau<'_>) -> Issue {
        const PAS: std::time::Duration = std::time::Duration::from_millis(200);
        const ATTENTE: std::time::Duration = std::time::Duration::from_secs(2);
        let debut = std::time::Instant::now();
        loop {
            match bureau(pid) {
                crate::fenetre::Hyprland::Absent => return Issue::Ramenee(false),
                crate::fenetre::Hyprland::Ramenee => return Issue::Ramenee(true),
                crate::fenetre::Hyprland::SansFenetre if debut.elapsed() < ATTENTE => std::thread::sleep(PAS),
                crate::fenetre::Hyprland::SansFenetre => {
                    return Issue::SansReponse(trf!(
                        "aucune fenêtre du processus {} sous Hyprland",
                        "no window of process {} under Hyprland",
                        pid
                    ));
                }
            }
        }
    }

    /// Se branche, lit l'accueil et vérifie son expéditeur, dans un fil, `BORNE_VERIFICATION` au plus : une prise
    /// à la file pleine, un processus muet ou une image lente à lire ne figent pas le lancement. Un fil abandonné
    /// ne peut plus rien envoyer : la prise ne revient qu'ici, et la demande ne part que d'ici.
    fn verifie(prise: &Path, attendue: &[u8; 32], moi: u32) -> Result<Verifie, Issue> {
        let (envoi, reception) = std::sync::mpsc::channel();
        let (p, a) = (prise.to_path_buf(), *attendue);
        let fil = crate::socle::fil::lancer("une-fenetre", move || {
            let _ = envoi.send(brancher_et_verifier(&p, &a, moi));
        });
        // Un échec passager d'ici (fil, connexion, délai) n'est pas une raison de retirer la prise de la fenêtre
        // qui l'a peut-être : `SansReponse`, la nouvelle fenêtre s'ouvre sans la prendre.
        if let Err(e) = fil {
            return Err(Issue::SansReponse(trf!(
                "canal injoignable : {}",
                "channel unreachable: {}",
                e
            )));
        }
        reception.recv_timeout(super::BORNE_VERIFICATION).unwrap_or_else(|_| {
            Err(Issue::SansReponse(
                tr!(
                    "la fenêtre ouverte n'a pas répondu à temps",
                    "the open window did not answer in time"
                )
                .into(),
            ))
        })
    }

    /// Ce que donne une vérification réussie : la prise, l'accueil (son expéditeur, tenu) et l'identité de l'image
    /// vérifiée.
    type Verifie = (UnixStream, crate::socle::Expediteur, Image);

    fn brancher_et_verifier(prise: &Path, attendue: &[u8; 32], moi: u32) -> Result<Verifie, Issue> {
        let flux = match crate::socle::brancher_avec_temoins(prise) {
            Ok(f) => f,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Err(Issue::Personne);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                return Err(Issue::Indisponible(
                    tr!(
                        "ce noyau ne dit pas quel processus parle (SO_PASSPIDFD, Linux 6.5)",
                        "this kernel does not tell which process speaks (SO_PASSPIDFD, Linux 6.5)"
                    )
                    .into(),
                ));
            }
            Err(e) => {
                return Err(Issue::SansReponse(trf!(
                    "canal injoignable : {}",
                    "channel unreachable: {}",
                    e
                )));
            }
        };
        // Celui qui a ouvert l'écoute (SO_PEERCRED) : du même compte aussi, sinon rien n'est lu de plus.
        if crate::socle::compte_d_en_face(&flux) != Some(moi) {
            return Err(Issue::Refusee(
                tr!(
                    "la prise est ouverte par un autre compte",
                    "the socket is opened by another account"
                )
                .into(),
            ));
        }
        if flux.set_read_timeout(Some(super::ATTENTE_ACCUEIL)).is_err() {
            return Err(Issue::SansReponse(
                tr!("canal injoignable", "channel unreachable").into(),
            ));
        }
        let accueil = match crate::socle::recevoir_avec_temoins(&flux) {
            Ok(a) => a,
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                return Err(Issue::Refusee(trf!(
                    "l'accueil reçu ne dit pas qui parle ({})",
                    "the greeting received does not tell who speaks ({})",
                    e
                )));
            }
            Err(e) => {
                return Err(Issue::SansReponse(trf!(
                    "la fenêtre ouverte n'a pas accueilli : {}",
                    "the open window did not greet: {}",
                    e
                )));
            }
        };
        if accueil.octet != regle::ACCUEIL {
            return Err(Issue::Refusee(
                tr!(
                    "l'accueil reçu n'est pas celui de la fenêtre",
                    "the greeting received is not the window's"
                )
                .into(),
            ));
        }
        let image = verifier(&accueil, attendue, moi)?;
        Ok((flux, accueil, image))
    }

    /// L'identité d'un fichier (volume, numéro) : celle de l'image vérifiée, comparée de nouveau après la réponse.
    pub(super) type Image = (u64, u64);

    /// Ce qui a été lu du processus qui parle, pour `juger`.
    pub(super) struct Faits {
        pub(super) uid: u32,
        pub(super) pid: i32,
        /// Le processus que tient le pidfd reçu avec l'accueil.
        pub(super) pid_du_pidfd: Option<i32>,
        /// Son espace de noms utilisateur est-il le nôtre ?
        pub(super) meme_espace: bool,
        /// L'empreinte de son image, lue par le descripteur ouvert sur `/proc/<pid>/exe`.
        pub(super) empreinte: std::io::Result<[u8; 32]>,
        /// Vit-il encore après les lectures (le pidfd le tient : c'est le même processus) ?
        pub(super) vivant: bool,
    }

    /// Le processus qui a envoyé l'accueil est-il la fenêtre de Vanguard de ce compte ? Lit les faits, puis les
    /// juge ; l'identité de l'image vérifiée, ou l'issue (refusée) : rien n'a été envoyé.
    pub(super) fn verifier(accueil: &crate::socle::Expediteur, attendue: &[u8; 32], moi: u32) -> Result<Image, Issue> {
        use std::os::unix::fs::MetadataExt;
        let pid = accueil.pid;
        let pid_du_pidfd = pid_du_pidfd(&accueil.pidfd);
        let espace = |chemin: String| std::fs::read_link(chemin).ok();
        let meme_espace = matches!(
            (espace(format!("/proc/{pid}/ns/user")), espace("/proc/self/ns/user".into())),
            (Some(lui), Some(nous)) if lui == nous
        );
        // L'image n'est lue que d'un processus qui a passé les contrôles simples (son coût, et rien à lire d'un
        // autre compte).
        let mut image = None;
        let empreinte = if accueil.uid == moi && pid > 0 && pid_du_pidfd == Some(pid) && meme_espace {
            std::fs::File::open(format!("/proc/{pid}/exe")).and_then(|f| {
                let m = f.metadata()?;
                image = Some((m.dev(), m.ino()));
                super::empreinte(f, super::super::lancer_fenetre::TAILLE_MAX)
            })
        } else {
            Err(std::io::Error::other("non lue"))
        };
        let faits = Faits {
            uid: accueil.uid,
            pid,
            pid_du_pidfd,
            meme_espace,
            empreinte,
            vivant: crate::socle::pidfd_vivant(&accueil.pidfd),
        };
        juger(&faits, attendue, moi)?;
        image.ok_or_else(|| Issue::Refusee(tr!("image illisible", "unreadable image").into()))
    }

    /// Le jugement des faits, sans rien lire (essayé cas par cas) : chaque contrôle a son refus.
    pub(super) fn juger(f: &Faits, attendue: &[u8; 32], moi: u32) -> Result<(), Issue> {
        let refus = |r: String| Err(Issue::Refusee(r));
        let pid = f.pid;
        if f.uid != moi {
            return refus(trf!(
                "le processus {} qui parle est d'un autre compte",
                "speaking process {} belongs to another account",
                pid
            ));
        }
        if pid <= 0 || f.pid_du_pidfd != Some(pid) {
            return refus(trf!(
                "le processus {} qui parle ne se laisse pas tenir",
                "speaking process {} cannot be held",
                pid
            ));
        }
        // Un espace de noms utilisateur à lui (root dedans) lui permettrait de faire pointer son `/proc/<pid>/exe`
        // sur la vraie image (PR_SET_MM_EXE_FILE) : seul le nôtre est cru. La fenêtre n'en crée pas (Landlock).
        if !f.meme_espace {
            return refus(trf!(
                "le processus {} qui parle est dans un autre espace de noms",
                "speaking process {} is in another namespace",
                pid
            ));
        }
        if !f.vivant {
            return refus(trf!(
                "le processus {} qui parle est parti pendant la vérification",
                "speaking process {} left during the check",
                pid
            ));
        }
        match &f.empreinte {
            Ok(e) if e == attendue => Ok(()),
            Ok(_) => refus(trf!(
                "le processus {} qui parle n'est pas la fenêtre de cette version de Vanguard (empreinte différente : \
                 un autre programme, ou une autre version)",
                "speaking process {} is not the window of this Vanguard version (different fingerprint: another \
                 program, or another version)",
                pid
            )),
            Err(e) => refus(trf!(
                "l'image du processus {} qui parle est illisible : {}",
                "the image of speaking process {} is unreadable: {}",
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

    /// La demande, « montre-toi » et un nombre aléatoire frais ; la réponse attendue, « ok » et le même nombre,
    /// `DELAI` au plus en tout. Chaque octet de la réponse doit venir du processus vérifié (celui de l'accueil,
    /// toujours tenu), et son image doit être encore celle qui a été vérifiée (pas un exec entre-temps). Un octet
    /// qui attendait déjà avant la demande ne peut pas en être la réponse : refusé, la demande n'est pas envoyée.
    fn echanger(mut flux: UnixStream, accueil: &crate::socle::Expediteur, image: Image) -> Result<(), Issue> {
        use std::os::unix::fs::MetadataExt;
        let muette = || {
            Err(Issue::SansReponse(
                tr!("la fenêtre ouverte n'a pas répondu", "the open window did not answer").into(),
            ))
        };
        match crate::socle::octet_en_attente(&flux) {
            Ok(false) => {}
            Ok(true) => {
                return Err(Issue::Refusee(
                    tr!(
                        "une réponse attendait déjà dans le canal avant la demande",
                        "an answer was already waiting in the channel before the request"
                    )
                    .into(),
                ));
            }
            Err(_) => return muette(),
        }
        let mut jeton = [0u8; regle::JETON];
        if getrandom::fill(&mut jeton).is_err() {
            return Err(Issue::SansReponse(
                tr!(
                    "aucun nombre aléatoire pour la demande",
                    "no random number for the request"
                )
                .into(),
            ));
        }
        if flux.set_write_timeout(Some(regle::DELAI)).is_err() || flux.write_all(&regle::demande(&jeton)).is_err() {
            return muette();
        }
        let fin = std::time::Instant::now()
            .checked_add(regle::DELAI)
            .unwrap_or_else(std::time::Instant::now);
        let mut lu = Vec::with_capacity(regle::TAILLE);
        while lu.len() < regle::TAILLE {
            let reste = fin.saturating_duration_since(std::time::Instant::now());
            if reste.is_zero() || flux.set_read_timeout(Some(reste)).is_err() {
                return muette();
            }
            let octet = match crate::socle::recevoir_avec_temoins(&flux) {
                Ok(o) => o,
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    return Err(Issue::Refusee(trf!(
                        "la réponse reçue ne dit pas qui parle ({})",
                        "the answer received does not tell who speaks ({})",
                        e
                    )));
                }
                Err(_) => return muette(),
            };
            if octet.pid != accueil.pid || pid_du_pidfd(&octet.pidfd) != Some(accueil.pid) {
                return Err(Issue::Refusee(trf!(
                    "la réponse vient du processus {}, pas du processus vérifié {}",
                    "the answer comes from process {}, not from the checked process {}",
                    octet.pid,
                    accueil.pid
                )));
            }
            lu.push(octet.octet);
        }
        let encore = std::fs::metadata(format!("/proc/{}/exe", accueil.pid)).map(|m| (m.dev(), m.ino()));
        if !crate::socle::pidfd_vivant(&accueil.pidfd) {
            return Err(Issue::SansReponse(trf!(
                "le processus {} de la fenêtre est parti",
                "window process {} left",
                accueil.pid
            )));
        }
        if encore.ok() != Some(image) {
            return Err(Issue::Refusee(trf!(
                "le processus {} qui parle a changé d'image depuis sa vérification",
                "speaking process {} changed image since its check",
                accueil.pid
            )));
        }
        if regle::reponse_juste(&lu, &jeton) {
            Ok(())
        } else {
            Err(Issue::Refusee(
                tr!(
                    "la réponse ne reprend pas le nombre de la demande",
                    "the answer does not repeat the request's number"
                )
                .into(),
            ))
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::path::Path;

    use super::{Issue, regle};
    use crate::machine::windows::processus::Tenu;
    use crate::machine::windows::une_fenetre as tube;
    use crate::{tr, trf};

    pub(super) fn ramener(attendue: &[u8; 32]) -> (Issue, Result<crate::socle::Verrou, String>) {
        let indisponible = |r: &str| (Issue::Indisponible(r.into()), Err(r.to_string()));
        let Some(sid) = crate::machine::windows::processus::sid() else {
            return indisponible(tr!("compte illisible", "account unreadable"));
        };
        let Some(session) = tube::session_de(std::process::id()) else {
            return indisponible(tr!("session illisible", "session unreadable"));
        };
        let Some(nom) = regle::nom_tube(&sid, session) else {
            return indisponible(tr!("compte illisible", "account unreadable"));
        };
        let verrou = super::prendre_verrou(&crate::socle::dossier_local(), &format!("fenetre-{session}.verrou"))
            .map_err(String::from);
        (joindre(&nom, &sid, session, attendue), verrou)
    }

    /// Ouvre le tube, vérifie son serveur, et seulement alors demande « montre-toi » ; le tout dans un fil, borné :
    /// un serveur muet, une image lente à lire ou une écriture qui ne passe pas ne figent pas le lancement. Un fil
    /// abandonné n'envoie la demande qu'à un serveur vérifié.
    pub(super) fn joindre(nom: &str, sid: &str, session: u32, attendue: &[u8; 32]) -> Issue {
        let (envoi, reception) = std::sync::mpsc::channel();
        let (n, s, a) = (nom.to_string(), sid.to_string(), *attendue);
        let fil = crate::socle::fil::lancer("une-fenetre", move || {
            let _ = envoi.send(dialoguer(&n, &s, session, &a));
        });
        if let Err(e) = fil {
            return Issue::Indisponible(trf!("canal injoignable : {}", "channel unreachable: {}", e));
        }
        // Ouvrir (occupé : `ATTENTE_ACCUEIL`), vérifier, puis l'échange (`DELAI`).
        let borne = super::BORNE_VERIFICATION.saturating_add(regle::DELAI);
        reception.recv_timeout(borne).unwrap_or_else(|_| {
            Issue::SansReponse(
                tr!(
                    "la fenêtre ouverte n'a pas répondu à temps",
                    "the open window did not answer in time"
                )
                .into(),
            )
        })
    }

    fn dialoguer(nom: &str, sid: &str, session: u32, attendue: &[u8; 32]) -> Issue {
        let client = match tube::Client::ouvrir(nom, super::ATTENTE_ACCUEIL) {
            Ok(Some(c)) => c,
            Ok(None) => return Issue::Personne,
            // La liste d'accès du tube refuse ce compte : un autre compte a pris le nom, ou la fenêtre tourne en
            // administrateur (un jeton élevé n'ouvre pas son tube à un jeton ordinaire). Rien ne dit lequel.
            Err(e) if e.raw_os_error() == Some(tube::ACCES_REFUSE) => {
                return Issue::Refusee(
                    tr!(
                        "le canal refuse ce compte (sans doute un autre compte qui a pris son nom, ou une fenêtre \
                         lancée en administrateur)",
                        "the channel refuses this account (probably another account that took its name, or a \
                         window started as administrator)"
                    )
                    .into(),
                );
            }
            Err(e) if e.raw_os_error() == Some(tube::TUBE_OCCUPE) => {
                return Issue::SansReponse(tr!("le canal est resté occupé", "the channel stayed busy").into());
            }
            Err(e) => return Issue::Indisponible(trf!("canal injoignable : {}", "channel unreachable: {}", e)),
        };
        // `tenu` garde le processus vérifié (son numéro n'est pas redonné) jusqu'après la demande.
        let (pid, tenu) = match verifier(&client, sid, session, attendue) {
            Ok(v) => v,
            Err(issue) => return issue,
        };
        let mut jeton = [0u8; regle::JETON];
        if getrandom::fill(&mut jeton).is_err() {
            return Issue::SansReponse(
                tr!(
                    "aucun nombre aléatoire pour la demande",
                    "no random number for the request"
                )
                .into(),
            );
        }
        // Le droit de passer devant, donné à la fenêtre (sans effet si ce programme-ci ne l'a pas lui-même).
        tube::permettre_premier_plan(pid);
        let echange = client.echanger(&jeton);
        drop(tenu);
        match echange {
            // Windows ne dit pas si la fenêtre est vraiment passée devant (il peut seulement la faire clignoter).
            tube::Echange::Repondu => Issue::Ramenee(false),
            tube::Echange::Muet => {
                Issue::SansReponse(tr!("la fenêtre ouverte n'a pas répondu", "the open window did not answer").into())
            }
            tube::Echange::AttendaitDeja => Issue::Refusee(
                tr!(
                    "une réponse attendait déjà dans le canal avant la demande",
                    "an answer was already waiting in the channel before the request"
                )
                .into(),
            ),
            tube::Echange::MauvaisNombre => Issue::Refusee(
                tr!(
                    "la réponse ne reprend pas le nombre de la demande",
                    "the answer does not repeat the request's number"
                )
                .into(),
            ),
        }
    }

    /// Le serveur du tube est-il la fenêtre de Vanguard de ce compte et de cette session ? Son pid et le processus
    /// tenu, sinon l'issue : rien n'a été envoyé.
    pub(super) fn verifier(
        client: &tube::Client,
        sid: &str,
        session: u32,
        attendue: &[u8; 32],
    ) -> Result<(u32, Tenu), Issue> {
        let refus = |r: String| Err(Issue::Refusee(r));
        // Le tube lui-même d'abord : créé par ce compte, pour ce compte seul. Le numéro de son créateur, lu ensuite,
        // peut avoir été redonné à un autre processus ; un tube de ce compte ne vient que de ce compte.
        if let Err(r) = client.proprietaire_et_acces_a(sid) {
            return refus(r.into());
        }
        let Some(pid) = client.pid_du_serveur() else {
            return refus(
                tr!(
                    "le processus qui écoute est inconnu",
                    "the listening process is unknown"
                )
                .into(),
            );
        };
        let tenu = match Tenu::ouvrir(pid) {
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
        // Le processus tenu, le tube toujours branché : son serveur vit encore. La poignée du tube ne s'hérite pas et
        // un numéro n'est redonné qu'après la fin du processus ; reste le cas d'une poignée passée exprès à un complice
        // (DuplicateHandle) avant la fin de l'imposteur, noté dans « Pas garanti » du modèle de menace.
        if !client.branche() {
            return refus(trf!(
                "le processus {} qui écoute est parti pendant la vérification",
                "listening process {} left during the check",
                pid
            ));
        }
        match tenu.sid() {
            Ok(lui) if lui == sid => {}
            Ok(_) => {
                return refus(trf!(
                    "le processus {} qui écoute est d'un autre compte",
                    "listening process {} belongs to another account",
                    pid
                ));
            }
            Err(e) => {
                return refus(trf!(
                    "le compte du processus {} qui écoute est illisible : {}",
                    "the account of listening process {} is unreadable: {}",
                    pid,
                    e
                ));
            }
        }
        if tube::session_de(pid) != Some(session) {
            return refus(trf!(
                "le processus {} qui écoute est d'une autre session",
                "listening process {} belongs to another session",
                pid
            ));
        }
        // Un serveur d'un niveau d'intégrité plus bas (un programme du même compte bridé, « Low ») ne parle pas pour
        // la fenêtre, qui tourne au niveau du compte.
        match (tenu.integrite(), crate::machine::windows::processus::integrite()) {
            (Ok(lui), Ok(moi)) if lui >= moi => {}
            (Ok(lui), Ok(moi)) => {
                return refus(trf!(
                    "le processus {} qui écoute a un niveau d'intégrité plus bas ({:#x} < {:#x})",
                    "listening process {} has a lower integrity level ({:#x} < {:#x})",
                    pid,
                    lui,
                    moi
                ));
            }
            (Err(e), _) | (_, Err(e)) => {
                return refus(trf!(
                    "le niveau d'intégrité du processus {} qui écoute est illisible : {}",
                    "the integrity level of listening process {} is unreadable: {}",
                    pid,
                    e
                ));
            }
        }
        // Le fichier de l'image du serveur, ouvert sans partage d'écriture : ses octets ne changent pas pendant la
        // lecture, et c'est leur empreinte qui compte (une autre copie de la même version, ailleurs, est la même
        // fenêtre). Limite (MODELE-DE-MENACE.md) : c'est le fichier présent à ce chemin qui est lu, pas l'image
        // chargée en mémoire.
        let Some(image) = tenu.chemin() else {
            return refus(trf!(
                "l'image du processus {} qui écoute est inconnue",
                "the image of listening process {} is unknown",
                pid
            ));
        };
        let lu = {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 0x1;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .open(Path::new(&image))
        };
        match lu.and_then(|f| super::empreinte(f, super::super::lancer_fenetre::TAILLE_MAX)) {
            Ok(e) if &e == attendue => Ok((pid, tenu)),
            Ok(_) => refus(trf!(
                "le processus {} qui écoute n'est pas la fenêtre de cette version de Vanguard (empreinte différente : \
                 un autre programme, ou une autre version)",
                "listening process {} is not the window of this Vanguard version (different fingerprint: another \
                 program, or another version)",
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
    use crate::fenetre::Hyprland;
    use crate::socle::une_fenetre::SOUS_DOSSIER;
    use std::io::{BufRead, Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::OnceLock;
    use std::time::Duration;

    /// Ce que joue `joue_l_ecoute` : le rôle, puis ses paramètres.
    const ROLE: &str = "VANGUARD_ESSAI_UNE_FENETRE";
    /// Le dossier de session jetable donné aux rôles.
    const RUNTIME: &str = "VANGUARD_ESSAI_RUNTIME";
    /// Le fichier où l'écoute note chaque octet reçu.
    const TRACE: &str = "VANGUARD_ESSAI_TRACE";
    /// Le descripteur (prise d'écoute ou connexion) passé à un rôle par son parent.
    const DESCRIPTEUR: &str = "VANGUARD_ESSAI_FD";
    /// Le nom de session (WAYLAND_DISPLAY) des essais.
    const SESSION: &str = "essai-0";
    /// Le délai de lecture des rôles : large, leurs clients font l'empreinte d'un gros programme d'essai.
    const LENT: Duration = Duration::from_secs(60);

    /// Le bureau des essais : pas Hyprland (jamais celui de la personne).
    fn hors_hyprland(_: i32) -> Hyprland {
        Hyprland::Absent
    }

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
        static E: OnceLock<[u8; 32]> = OnceLock::new();
        *E.get_or_init(|| {
            super::empreinte(std::fs::File::open(std::env::current_exe().unwrap()).unwrap(), u64::MAX).unwrap()
        })
    }

    /// Une copie de ce programme d'essai avec un octet de plus : elle tourne pareil, mais son empreinte n'est pas
    /// l'attendue (un autre programme du même compte). Faite une fois, sur le disque des essais (pas dans /tmp).
    fn copie_modifiee() -> PathBuf {
        static C: OnceLock<PathBuf> = OnceLock::new();
        C.get_or_init(|| {
            let c = crate::essais::temporaire().join(crate::essais::nom_unique("une-fenetre-copie"));
            std::fs::copy(std::env::current_exe().unwrap(), &c).unwrap();
            std::fs::OpenOptions::new()
                .append(true)
                .open(&c)
                .unwrap()
                .write_all(&[0])
                .unwrap();
            std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o700)).unwrap();
            c
        })
        .clone()
    }

    /// La commande qui relance `programme` (ce programme d'essai ou sa copie) dans le rôle `role`.
    fn commande(programme: &Path, role: &str, runtime: &Path, trace: &Path) -> Command {
        let mut c = Command::new(programme);
        c.args([
            "--exact",
            "demarrage::une_fenetre::tests::joue_l_ecoute",
            "--ignored",
            "--nocapture",
            "--quiet",
            "--test-threads=1",
        ])
        .env(ROLE, role)
        .env(RUNTIME, runtime)
        .env(TRACE, trace);
        c
    }

    /// Relance ce programme d'essai dans le rôle `role` (un second vrai processus).
    fn jouer(role: &str, runtime: &Path, trace: &Path) -> Child {
        demarrer(commande(&std::env::current_exe().unwrap(), role, runtime, trace))
    }

    fn demarrer(mut c: Command) -> Child {
        c.stdin(Stdio::piped())
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

    fn noter(trace: &Path, octet: u8) {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(trace)
            .unwrap()
            .write_all(&[octet])
            .unwrap();
    }

    fn dire(ligne: &str) {
        println!("vu:{ligne}");
        std::io::stdout().flush().unwrap();
    }

    /// Lit la demande, la note ; la réponse juste (« ok » et le même nombre) si c'en est une.
    fn lire_et_repondre(flux: &mut UnixStream, trace: &Path) {
        if let Some(jeton) = lire_la_demande(flux, trace) {
            let _ = flux.write_all(&regle::reponse(&jeton));
        }
    }

    /// Lit `TAILLE` octets (ou ce qui vient avant la fin), les note ; le nombre, si c'est une demande.
    fn lire_la_demande(flux: &mut UnixStream, trace: &Path) -> Option<[u8; regle::JETON]> {
        flux.set_read_timeout(Some(LENT)).unwrap();
        let mut lu = Vec::new();
        let mut octet = [0u8; 1];
        while lu.len() < regle::TAILLE && flux.read_exact(&mut octet).is_ok() {
            noter(trace, octet[0]);
            lu.push(octet[0]);
        }
        regle::jeton_de_la_demande(&lu)
    }

    /// La trace d'une demande reçue : « montre-toi » suivi d'un nombre.
    fn est_une_demande(trace: &[u8]) -> bool {
        trace.len() == regle::TAILLE && trace.first() == Some(&regle::DEMANDE)
    }

    /// La fenêtre en petit : l'accueil, puis un octet lu et noté, « ok » à la demande.
    fn servir(mut flux: UnixStream, trace: &Path) {
        flux.set_nonblocking(false).unwrap();
        if flux.write_all(&[regle::ACCUEIL]).is_ok() {
            lire_et_repondre(&mut flux, trace);
        }
    }

    /// Un drapeau levé quand l'entrée du rôle se ferme (l'essai a fini avec lui).
    fn fin_de_l_entree() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        let fin = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let f = fin.clone();
        std::thread::spawn(move || {
            let _ = std::io::stdin().read(&mut [0u8; 1]);
            f.store(true, std::sync::atomic::Ordering::Release);
        });
        fin
    }

    /// Accepte les connexions de `ecoute` jusqu'à la fin de l'entrée, chacune passée à `chacune`.
    fn accepter(ecoute: &UnixListener, mut chacune: impl FnMut(UnixStream)) {
        ecoute.set_nonblocking(true).unwrap();
        let fin = fin_de_l_entree();
        while !fin.load(std::sync::atomic::Ordering::Acquire) {
            match ecoute.accept() {
                Ok((flux, _)) => chacune(flux),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    /// Le descripteur `fd` passera à un processus lancé (il ne se ferme plus à l'exec).
    // raison : fcntl, pour qu'un descripteur passe à un enfant (std n'a rien pour cela).
    #[allow(unsafe_code)]
    fn transmissible(fd: &impl std::os::fd::AsRawFd) {
        // SAFETY: fcntl lit et pose les drapeaux d'un descripteur ouvert, tenu par l'appelant ; aucune mémoire à nous.
        let ok = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, 0) } == 0;
        assert!(ok);
    }

    /// Le descripteur reçu du parent (variable `DESCRIPTEUR`), à ce rôle seul désormais.
    // raison : un descripteur hérité devient un objet de std (from_raw_fd).
    #[allow(unsafe_code)]
    fn herite() -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        let fd: i32 = std::env::var(DESCRIPTEUR).unwrap().parse().unwrap();
        // SAFETY: le parent a laissé ce descripteur ouvert exprès pour ce rôle, qui est le seul à s'en servir ici.
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
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
        let lier = || {
            let p = prise(&runtime);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let _ = std::fs::remove_file(&p);
            UnixListener::bind(&p).unwrap()
        };
        match role.as_str() {
            // La fenêtre (ou un imposteur : c'est l'empreinte attendue par l'autre côté qui en décide).
            "ecoute" => {
                let ecoute = lier();
                dire("pret");
                accepter(&ecoute, |flux| servir(flux, &trace));
            }
            // Accepte, mais ne dit jamais rien.
            "dort" => {
                let ecoute = lier();
                dire("pret");
                let mut tenus = Vec::new();
                accepter(&ecoute, |flux| tenus.push(flux));
            }
            // Accueille, puis meurt aussitôt : le client tient un processus parti.
            "accueille-et-meurt" => {
                let ecoute = lier();
                dire("pret");
                let (mut flux, _) = ecoute.accept().unwrap();
                let _ = flux.write_all(&[regle::ACCUEIL]);
                std::process::exit(0);
            }
            // Le contournement d'avant ce lot : ce processus (la bonne image) ouvre l'écoute, puis la passe à un autre
            // programme (la copie modifiée) qui, lui, accepte et parle. SO_PEERCRED nommerait ce processus-ci.
            "passeur" => {
                let ecoute = lier();
                transmissible(&ecoute);
                let mut c = commande(&copie_modifiee(), "parle-a-sa-place", &runtime, &trace);
                c.env(DESCRIPTEUR, std::os::fd::AsRawFd::as_raw_fd(&ecoute).to_string())
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::null());
                let mut enfant = c.spawn().unwrap();
                drop(ecoute);
                let fin = fin_de_l_entree();
                while !fin.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                let _ = enfant.kill();
                let _ = enfant.wait();
            }
            "parle-a-sa-place" => {
                let ecoute = UnixListener::from(herite());
                dire("pret");
                for flux in ecoute.incoming() {
                    servir(flux.unwrap(), &trace);
                }
            }
            // Ce processus (la bonne image) accueille, puis un autre (la copie modifiée) lit la demande et répond.
            "accueil-puis-un-autre" => {
                // La copie (le programme d'essai entier) se fait avant « pret » : faite après l'accueil, sous la
                // charge des autres essais, elle mangeait le `DELAI` de la réponse et l'essai voyait une fenêtre muette.
                let copie = copie_modifiee();
                let ecoute = lier();
                dire("pret");
                accepter(&ecoute, |mut flux| {
                    flux.set_nonblocking(false).unwrap();
                    if flux.write_all(&[regle::ACCUEIL]).is_err() {
                        return;
                    }
                    transmissible(&flux);
                    let mut c = commande(&copie, "repond-a-sa-place", &runtime, &trace);
                    c.env(DESCRIPTEUR, std::os::fd::AsRawFd::as_raw_fd(&flux).to_string())
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null());
                    let mut enfant = c.spawn().unwrap();
                    drop(flux);
                    let _ = enfant.wait();
                });
            }
            "repond-a-sa-place" => {
                let mut flux = UnixStream::from(herite());
                lire_et_repondre(&mut flux, &trace);
            }
            // Un premier octet qui n'est pas l'accueil, avec de vrais témoins.
            "accueil-faux" => {
                let ecoute = lier();
                dire("pret");
                accepter(&ecoute, |mut flux| {
                    flux.set_nonblocking(false).unwrap();
                    if flux.write_all(b"X").is_ok() {
                        lire_et_repondre(&mut flux, &trace);
                    }
                });
            }
            // Une réponse envoyée d'avance, juste après l'accueil, avant toute demande ; puis la vraie réponse.
            "repond-d-avance" => {
                let ecoute = lier();
                dire("pret");
                accepter(&ecoute, |mut flux| {
                    flux.set_nonblocking(false).unwrap();
                    if flux.write_all(&[regle::ACCUEIL, regle::REPONSE]).is_ok() {
                        lire_et_repondre(&mut flux, &trace);
                    }
                });
            }
            // Lit la demande, mais répond « ok » sans son nombre (un nombre deviné : des zéros).
            "repond-sans-le-jeton" => {
                let ecoute = lier();
                dire("pret");
                accepter(&ecoute, |mut flux| {
                    flux.set_nonblocking(false).unwrap();
                    if flux.write_all(&[regle::ACCUEIL]).is_ok() && lire_la_demande(&mut flux, &trace).is_some() {
                        let _ = flux.write_all(&regle::reponse(&[0; regle::JETON]));
                    }
                });
            }
            // Constat 27 : la bonne image accueille, attend que la demande soit là (sans la lire), puis devient un
            // autre programme (exec de la copie modifiée, même processus, même pidfd) qui lit la demande et répond
            // juste.
            "accueille-puis-change-d-image" => {
                use std::os::unix::process::CommandExt;
                // Avant « pret », comme pour « accueil-puis-un-autre ».
                let copie = copie_modifiee();
                let ecoute = lier();
                dire("pret");
                ecoute.set_nonblocking(false).unwrap();
                let (mut flux, _) = ecoute.accept().unwrap();
                flux.set_nonblocking(false).unwrap();
                if flux.write_all(&[regle::ACCUEIL]).is_err() {
                    return;
                }
                let debut = std::time::Instant::now();
                while !crate::socle::octet_en_attente(&flux).unwrap() {
                    assert!(debut.elapsed() < LENT, "aucune demande");
                    std::thread::sleep(Duration::from_millis(5));
                }
                transmissible(&flux);
                let mut c = commande(&copie, "repond-a-sa-place", &runtime, &trace);
                c.env(DESCRIPTEUR, std::os::fd::AsRawFd::as_raw_fd(&flux).to_string());
                let erreur = c.exec();
                panic!("exec : {erreur}");
            }
            // Un lancement de `vanguard` : ramène la fenêtre, ou, s'il n'y en a pas, « l'ouvre » : comme la vraie
            // fenêtre, elle tarde à écouter (vérification, démarrage), sous le verrou, rendu après « ouverte ».
            "lanceur" => {
                let (issue, verrou) = ramener_dans(
                    Some(runtime.clone().into()),
                    Some(SESSION),
                    None,
                    &empreinte_de_l_essai(),
                    &hors_hyprland,
                );
                match issue {
                    Issue::Ramenee(_) => dire("ramenee"),
                    Issue::Personne => {
                        std::thread::sleep(Duration::from_millis(400));
                        let ecoute = lier();
                        drop(verrou);
                        dire("lancee");
                        accepter(&ecoute, |flux| servir(flux, &trace));
                    }
                    autre => dire(&format!("{autre:?}")),
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

    /// Un rôle lancé, prêt ; l'issue de `joindre` sur sa prise, avec l'empreinte `attendue` et le compte `moi`.
    fn joindre_le_role(d: &Path, role: &str, attendue: &[u8; 32], moi: u32) -> (Issue, Child) {
        let mut enfant = jouer(role, d, &d.join("trace"));
        assert_eq!(attendre_ligne(&mut enfant), "pret");
        (joindre(&prise(d), attendue, moi, &hors_hyprland), enfant)
    }

    /// La fenêtre déjà ouverte (un autre processus, de l'empreinte attendue, du même compte) reçoit la demande,
    /// répond, et le lancement ne rouvre rien.
    #[test]
    fn la_vraie_fenetre_est_ramenee() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "ecoute", &empreinte_de_l_essai(), crate::socle::uid());
        if matches!(&issue, Issue::Indisponible(r) if r.contains("SO_PASSPIDFD")) {
            arreter(ecoute);
            return crate::essais::saute("noyau sans SO_PASSPIDFD (Linux 6.5)");
        }
        assert_eq!(issue, Issue::Ramenee(false));
        assert!(
            est_une_demande(&trace_de(&d.join("trace"))),
            "{:?}",
            trace_de(&d.join("trace"))
        );
        arreter(ecoute);
    }

    /// Sous Hyprland, sans fenêtre à ce processus : rien n'est dit ramené (la demande est faite, mais une fenêtre
    /// s'ouvre) ; avec sa fenêtre trouvée : ramenée, confirmé.
    #[test]
    fn hyprland_decide_de_ce_qui_est_ramene() {
        let d = runtime();
        let mut ecoute = jouer("ecoute", &d, &d.join("trace"));
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        let moi = crate::socle::uid();
        let issue = joindre(&prise(&d), &empreinte_de_l_essai(), moi, &|_| Hyprland::SansFenetre);
        assert!(matches!(&issue, Issue::SansReponse(_)), "{issue:?}");
        let issue = joindre(&prise(&d), &empreinte_de_l_essai(), moi, &|_| Hyprland::Ramenee);
        assert_eq!(issue, Issue::Ramenee(true));
        arreter(ecoute);
    }

    /// Un autre programme qui écoute à la place de la fenêtre (empreinte différente) : refusé, et il ne reçoit
    /// pas un octet.
    #[test]
    fn un_imposteur_ne_recoit_rien() {
        let d = runtime();
        let mut autre = empreinte_de_l_essai();
        autre[0] ^= 1;
        let (issue, ecoute) = joindre_le_role(&d, "ecoute", &autre, crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("empreinte") || r.contains("fingerprint")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            trace_de(&d.join("trace")).is_empty(),
            "l'imposteur a reçu {:?}",
            trace_de(&d.join("trace"))
        );
        arreter(ecoute);
    }

    /// Constats 1 et 22 : la bonne image ouvre l'écoute, puis un autre programme (empreinte différente) accepte et
    /// parle à sa place. C'est celui qui parle qui est vérifié : refusé, et il ne reçoit pas la demande.
    #[test]
    fn celui_qui_parle_est_verifie_pas_celui_qui_ecoute() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "passeur", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("empreinte") || r.contains("fingerprint")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            trace_de(&d.join("trace")).is_empty(),
            "l'autre programme a reçu {:?}",
            trace_de(&d.join("trace"))
        );
        arreter(ecoute);
    }

    /// La bonne image accueille, puis un autre processus lit la demande et répond « ok » : la réponse ne vient pas
    /// du processus vérifié, refusée (une fenêtre s'ouvre).
    #[test]
    fn la_reponse_doit_venir_du_processus_verifie() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(
            &d,
            "accueil-puis-un-autre",
            &empreinte_de_l_essai(),
            crate::socle::uid(),
        );
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("vérifié") || r.contains("checked")),
            "{issue:?}"
        );
        arreter(ecoute);
    }

    /// Constat 2 : la vraie image, mais dans un espace de noms utilisateur à elle (où elle serait root et pourrait
    /// faire mentir son `/proc/<pid>/exe`) : refusée, rien envoyé.
    #[test]
    fn un_autre_espace_de_noms_est_refuse() {
        let unshare = Command::new("unshare")
            .args(["-r", "true"])
            .stderr(Stdio::null())
            .status();
        if !unshare.is_ok_and(|s| s.success()) {
            return crate::essais::saute("unshare -r indisponible (espaces de noms utilisateur fermés)");
        }
        let d = runtime();
        let trace = d.join("trace");
        let vraie = commande(&std::env::current_exe().unwrap(), "ecoute", &d, &trace);
        let mut c = Command::new("unshare");
        c.arg("-r").arg("--").arg(vraie.get_program()).args(vraie.get_args());
        for (cle, valeur) in vraie.get_envs() {
            if let Some(v) = valeur {
                c.env(cle, v);
            }
        }
        let mut ecoute = demarrer(c);
        assert_eq!(attendre_ligne(&mut ecoute), "pret");
        let issue = joindre(&prise(&d), &empreinte_de_l_essai(), crate::socle::uid(), &hors_hyprland);
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("espace de noms") || r.contains("namespace")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(trace_de(&trace).is_empty(), "reçu {:?}", trace_de(&trace));
        arreter(ecoute);
    }

    /// Un écouteur d'un autre compte (le compte attendu n'est pas le sien) : refusé, rien envoyé.
    #[test]
    fn un_autre_compte_ne_recoit_rien() {
        let d = runtime();
        let moi = crate::socle::uid().wrapping_add(1);
        let (issue, ecoute) = joindre_le_role(&d, "ecoute", &empreinte_de_l_essai(), moi);
        assert!(matches!(&issue, Issue::Refusee(_)), "{issue:?}");
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(trace_de(&d.join("trace")), Vec::<u8>::new());
        arreter(ecoute);
    }

    /// Un processus qui accepte mais ne dit rien : abandonné après le délai, une fenêtre s'ouvre ; le lancement
    /// n'est pas figé.
    #[test]
    fn un_ecouteur_muet_ne_fige_rien() {
        let d = runtime();
        let debut = std::time::Instant::now();
        let (issue, ecoute) = joindre_le_role(&d, "dort", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(matches!(&issue, Issue::SansReponse(_)), "{issue:?}");
        assert!(
            debut.elapsed() < super::ATTENTE_ACCUEIL + Duration::from_secs(5),
            "{:?}",
            debut.elapsed()
        );
        arreter(ecoute);
    }

    /// Un processus qui accueille puis meurt : jamais dit ramené. Le moment de sa mort n'est pas réglable d'ici
    /// (l'accueil part avant, la vérification tourne dans le fil du client) : mort pendant la vérification, il est
    /// refusé (Refusee) ; mort juste après, il ne répond pas à l'échange (SansReponse). Les deux rouvrent une
    /// fenêtre ; exiger l'un des deux ferait un essai qui échoue selon la charge de la machine.
    #[test]
    fn un_processus_parti_est_refuse() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "accueille-et-meurt", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(matches!(&issue, Issue::Refusee(_) | Issue::SansReponse(_)), "{issue:?}");
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
        let essayer = |runtime: Option<std::ffi::OsString>| {
            ramener_dans(runtime, Some(SESSION), None, &empreinte_de_l_essai(), &hors_hyprland).0
        };
        for (dossier, mode) in [(d.to_path_buf(), 0o755), (d.join(SOUS_DOSSIER), 0o750)] {
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(mode)).unwrap();
            let issue = essayer(Some(d.as_os_str().into()));
            assert!(matches!(&issue, Issue::Indisponible(_)), "{mode:o} {issue:?}");
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert!(matches!(essayer(None), Issue::Indisponible(_)));
        assert!(matches!(essayer(Some("relatif".into())), Issue::Indisponible(_)));
        assert_eq!(trace_de(&trace), Vec::<u8>::new());
        // Remis à 0700 : la même fenêtre est ramenée (l'essai refusait bien pour le dossier).
        assert_eq!(essayer(Some(d.as_os_str().into())), Issue::Ramenee(false));
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
        let (issue, _) = ramener_dans(
            Some(lien.into()),
            Some(SESSION),
            None,
            &empreinte_de_l_essai(),
            &hors_hyprland,
        );
        assert!(matches!(&issue, Issue::Indisponible(_)), "{issue:?}");
    }

    /// Personne n'écoute (aucune prise, ou la prise d'une fenêtre fermée) : le lancement ouvre la fenêtre, verrou
    /// tenu.
    #[test]
    fn sans_fenetre_personne() {
        let d = runtime();
        let essayer = || {
            ramener_dans(
                Some(d.as_os_str().into()),
                Some(SESSION),
                None,
                &empreinte_de_l_essai(),
                &hors_hyprland,
            )
        };
        let (issue, verrou) = essayer();
        assert_eq!(issue, Issue::Personne);
        assert!(verrou.is_ok());
        drop(verrou);
        // La prise d'une fenêtre fermée : le fichier reste, personne n'écoute (ECONNREFUSED).
        drop(UnixListener::bind(prise(&d)).unwrap());
        assert!(prise(&d).exists());
        let (issue, verrou) = essayer();
        assert_eq!(issue, Issue::Personne);
        assert!(verrou.is_ok());
    }

    /// Constats 1 et 27 : la bonne image accueille, puis devient un autre programme par exec (même processus,
    /// même pidfd) qui lit la demande et répond juste : jamais ramenée. Refusée parce que l'image a changé depuis
    /// sa vérification.
    #[test]
    fn accueille_puis_change_d_image() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(
            &d,
            "accueille-puis-change-d-image",
            &empreinte_de_l_essai(),
            crate::socle::uid(),
        );
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("changé d'image") || r.contains("changed image")),
            "{issue:?}"
        );
        arreter(ecoute);
    }

    /// Constat 1 : une réponse qui attendait déjà avant la demande (envoyée juste après l'accueil) : refusée, la
    /// demande n'est pas envoyée.
    #[test]
    fn une_reponse_d_avance_est_refusee() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "repond-d-avance", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("attendait") || r.contains("waiting")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            trace_de(&d.join("trace")).is_empty(),
            "reçu {:?}",
            trace_de(&d.join("trace"))
        );
        arreter(ecoute);
    }

    /// Constat 1 : « ok » sans le nombre de la demande : refusé.
    #[test]
    fn une_reponse_sans_le_nombre_est_refusee() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "repond-sans-le-jeton", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("nombre") || r.contains("number")),
            "{issue:?}"
        );
        arreter(ecoute);
    }

    /// Constat 31 : un premier octet qui n'est pas l'accueil, même de la bonne image : refusé, rien envoyé.
    #[test]
    fn un_accueil_faux_est_refuse() {
        let d = runtime();
        let (issue, ecoute) = joindre_le_role(&d, "accueil-faux", &empreinte_de_l_essai(), crate::socle::uid());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains("n'est pas celui") || r.contains("is not the window's")),
            "{issue:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            trace_de(&d.join("trace")).is_empty(),
            "reçu {:?}",
            trace_de(&d.join("trace"))
        );
        arreter(ecoute);
    }

    /// Constat 31 : chaque contrôle du jugement a son refus, essayé seul (un fait faux à la fois).
    #[test]
    fn chaque_controle_du_jugement_refuse_son_cas() {
        use super::linux::{Faits, juger};
        let attendue = [7u8; 32];
        let moi = 1000;
        let bons = || Faits {
            uid: moi,
            pid: 42,
            pid_du_pidfd: Some(42),
            meme_espace: true,
            empreinte: Ok(attendue),
            vivant: true,
        };
        assert_eq!(juger(&bons(), &attendue, moi), Ok(()));
        let motif = |f: Faits, fr: &str, en: &str| {
            let issue = juger(&f, &attendue, moi);
            assert!(
                matches!(&issue, Err(Issue::Refusee(r)) if r.contains(fr) || r.contains(en)),
                "{fr} : {issue:?}"
            );
        };
        motif(Faits { uid: moi + 1, ..bons() }, "autre compte", "another account");
        motif(
            Faits {
                pid_du_pidfd: Some(43),
                ..bons()
            },
            "tenir",
            "held",
        );
        motif(
            Faits {
                pid_du_pidfd: None,
                ..bons()
            },
            "tenir",
            "held",
        );
        motif(
            Faits {
                pid: 0,
                pid_du_pidfd: Some(0),
                ..bons()
            },
            "tenir",
            "held",
        );
        motif(
            Faits {
                meme_espace: false,
                ..bons()
            },
            "espace de noms",
            "namespace",
        );
        motif(
            Faits {
                vivant: false,
                ..bons()
            },
            "parti",
            "left",
        );
        motif(
            Faits {
                empreinte: Ok([8; 32]),
                ..bons()
            },
            "empreinte",
            "fingerprint",
        );
        motif(
            Faits {
                empreinte: Err(std::io::Error::other("essai")),
                ..bons()
            },
            "illisible",
            "unreadable",
        );
    }

    /// Deux lancements en même temps (deux processus) : un seul ouvre la fenêtre, l'autre la ramène. La fenêtre
    /// lancée tarde à écouter (comme la vraie) : sans le verrou, les deux ouvriraient.
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

/// Les essais du client Windows : un tube servi par un fil de ce programme d'essai, qui joue la « fenêtre » (son
/// image est le programme d'essai lui-même). Sous Wine, ce qui ne s'y imite pas (sécurité du tube, numéro du
/// serveur) fait sauter l'essai en le disant ; sur le vrai Windows, rien n'est sauté.
#[cfg(all(test, windows))]
// Les aides des essais (hors `#[test]`) échouent comme eux : par unwrap.
#[allow(clippy::unwrap_used)]
mod essais_windows {
    use super::windows::joindre;
    use super::{Issue, regle};
    use std::sync::OnceLock;
    use std::sync::mpsc::Receiver;

    /// Le serveur des essais, en appels directs à Windows (le vrai est dans `vanguard-fenetre`).
    // raison : CreateNamedPipeW et ConnectNamedPipe, que std n'offre pas ; poignées gardées par `File`.
    #[allow(unsafe_code)]
    mod serveur {
        use std::ffi::c_void;
        use std::io::{Read, Write};
        use std::os::windows::io::FromRawHandle;
        use std::sync::mpsc::Receiver;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateNamedPipeW(
                nom: *const u16,
                ouverture: u32,
                mode: u32,
                instances: u32,
                sortie: u32,
                entree: u32,
                attente: u32,
                securite: *const Securite,
            ) -> *mut c_void;
            fn ConnectNamedPipe(tube: *mut c_void, chevauchement: *mut c_void) -> i32;
            fn LocalFree(memoire: *mut c_void) -> *mut c_void;
            fn GetModuleHandleW(nom: *const u16) -> *mut c_void;
            fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
        }
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
                texte: *const u16,
                revision: u32,
                descripteur: *mut *mut c_void,
                taille: *mut u32,
            ) -> i32;
        }

        /// SECURITY_ATTRIBUTES.
        #[repr(C)]
        struct Securite {
            taille: u32,
            descripteur: *mut c_void,
            heritable: i32,
        }

        fn large(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        /// Ce programme tourne-t-il sous Wine (ntdll y exporte `wine_get_version`) ?
        pub(super) fn sous_wine() -> bool {
            let ntdll = large("ntdll.dll");
            // SAFETY: deux chaînes terminées par un zéro, vivantes pendant les appels ; rien n'est appelé par le
            // pointeur rendu, seulement comparé à nul.
            unsafe {
                let module = GetModuleHandleW(ntdll.as_ptr());
                !module.is_null() && !GetProcAddress(module, c"wine_get_version".as_ptr().cast()).is_null()
            }
        }

        /// Ce que joue le serveur des essais.
        #[derive(Clone, Copy)]
        pub(super) enum Jeu {
            /// La fenêtre : la réponse juste à la demande.
            Juste,
            /// « ok » envoyé d'avance, dès le branchement, puis la réponse juste.
            Davance,
            /// « ok » sans le nombre de la demande.
            SansLeNombre,
        }

        /// Crée le tube `nom` (une instance, liste d'accès `sddl`) et le sert une fois dans un fil, selon `jeu` : les
        /// octets reçus, ou `None` si le client est parti sans rien écrire.
        pub(super) fn servir_une_fois(nom: &str, sddl: &str, jeu: Jeu) -> Receiver<Option<Vec<u8>>> {
            const OUVERTURE: u32 = 0x3 | 0x0008_0000;
            const MODE: u32 = 0x8;
            let mut descripteur: *mut c_void = std::ptr::null_mut();
            let texte = large(sddl);
            // SAFETY: `texte` est terminé par un zéro et vit pendant l'appel ; le descripteur est rendu plus bas.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    texte.as_ptr(),
                    1,
                    &raw mut descripteur,
                    std::ptr::null_mut(),
                )
            } != 0;
            assert!(ok && !descripteur.is_null(), "SDDL refusé : {sddl}");
            let securite = Securite {
                taille: u32::try_from(std::mem::size_of::<Securite>()).unwrap(),
                descripteur,
                heritable: 0,
            };
            let n = large(nom);
            // SAFETY: `n` et `securite` vivent pendant l'appel ; le descripteur est rendu une fois, après (le tube
            // en a sa copie) ; la poignée rendue est gardée plus bas par un `File`, qui la referme une seule fois.
            let poignee = unsafe {
                let p = CreateNamedPipeW(n.as_ptr(), OUVERTURE, MODE, 1, 64, 64, 0, &raw const securite);
                LocalFree(descripteur);
                p
            };
            assert!(!poignee.is_null() && poignee as isize != -1, "tube non créé : {nom}");
            // SAFETY: la poignée vient d'être créée, elle n'est à personne d'autre.
            let mut tube = unsafe { std::fs::File::from_raw_handle(poignee) };
            let (envoi, reception) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                use std::os::windows::io::AsRawHandle;
                // SAFETY: la poignée est ouverte tant que `tube` vit ; attente simple, sans chevauchement. Un client
                // branché entre la création et l'attente (ERROR_PIPE_CONNECTED) se lit pareil.
                let _ = unsafe { ConnectNamedPipe(tube.as_raw_handle(), std::ptr::null_mut()) };
                if matches!(jeu, Jeu::Davance) {
                    let _ = tube.write_all(&[super::regle::REPONSE]);
                }
                let mut lu = Vec::new();
                let mut octet = [0u8; 1];
                while lu.len() < super::regle::TAILLE && matches!(tube.read(&mut octet), Ok(1)) {
                    lu.push(octet[0]);
                }
                if let Some(jeton) = super::regle::jeton_de_la_demande(&lu) {
                    let jeton = if matches!(jeu, Jeu::SansLeNombre) {
                        [0; super::regle::JETON]
                    } else {
                        jeton
                    };
                    let _ = tube.write_all(&super::regle::reponse(&jeton));
                    // Attendre que le client ait lu et soit parti : la réponse n'est pas perdue à la fermeture.
                    let _ = tube.read(&mut octet);
                }
                let _ = envoi.send((!lu.is_empty()).then_some(lu));
            });
            reception
        }
    }

    fn sid() -> String {
        crate::machine::windows::processus::sid().unwrap()
    }

    fn session() -> u32 {
        crate::machine::windows::une_fenetre::session_de(std::process::id()).unwrap()
    }

    /// Un nom de tube d'essai (jamais celui de la vraie fenêtre).
    fn nom() -> String {
        format!(r"\\.\pipe\{}", crate::essais::nom_unique("une-fenetre"))
    }

    fn essai() -> std::path::PathBuf {
        std::env::current_exe().unwrap()
    }

    /// L'empreinte de ce programme d'essai : celle d'une « vraie fenêtre » quand un de ses fils sert le tube.
    fn empreinte_de_l_essai() -> [u8; 32] {
        static E: OnceLock<[u8; 32]> = OnceLock::new();
        *E.get_or_init(|| super::empreinte(std::fs::File::open(essai()).unwrap(), u64::MAX).unwrap())
    }

    /// Ce que Wine ne sait pas imiter rend l'essai muet : sauté (seulement sous Wine), avec la raison. Sur le vrai
    /// Windows, la vraie fenêtre doit être ramenée.
    fn sous_wine_sans_conclure(issue: &Issue) -> bool {
        if matches!(issue, Issue::Ramenee(false)) || !serveur::sous_wine() {
            return false;
        }
        crate::essais::saute(&format!("Wine ne rend pas ce que le client vérifie ({issue:?})"));
        true
    }

    /// Le tube de la vraie fenêtre, servi, puis joint avec la vraie empreinte : il doit être ramené. Faux si Wine
    /// ne sait pas conclure (l'essai appelant saute : ses refus ne prouveraient rien).
    fn la_reference_passe() -> bool {
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::Juste);
        let issue = joindre(&n, &sid(), session(), &empreinte_de_l_essai());
        if sous_wine_sans_conclure(&issue) {
            return false;
        }
        assert_eq!(issue, Issue::Ramenee(false));
        let lu = recu.recv().unwrap().unwrap();
        assert!(
            lu.len() == regle::TAILLE && lu.first() == Some(&regle::DEMANDE),
            "{lu:?}"
        );
        true
    }

    /// Le refus attendu, et rien n'a été envoyé au serveur.
    fn refuse_sans_rien_envoyer(issue: &Issue, recu: &Receiver<Option<Vec<u8>>>, motif: &str) {
        assert!(
            matches!(issue, Issue::Refusee(r) if r.contains(motif)),
            "refus attendu ({motif}), obtenu {issue:?}"
        );
        assert_eq!(recu.recv().unwrap(), None, "le serveur a reçu quelque chose");
    }

    #[test]
    fn la_vraie_fenetre_est_ramenee() {
        // Elle vérifie elle-même, ou saute sous Wine en le disant.
        la_reference_passe();
    }

    #[test]
    fn sans_tube_personne() {
        assert_eq!(
            joindre(&nom(), &sid(), session(), &empreinte_de_l_essai()),
            Issue::Personne
        );
    }

    #[test]
    fn une_autre_empreinte_ne_recoit_rien() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::Juste);
        let issue = joindre(&n, &sid(), session(), &[7; 32]);
        refuse_sans_rien_envoyer(&issue, &recu, "empreinte");
    }

    #[test]
    fn une_autre_session_ne_recoit_rien() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::Juste);
        let issue = joindre(&n, &sid(), session().wrapping_add(1), &empreinte_de_l_essai());
        refuse_sans_rien_envoyer(&issue, &recu, crate::tr!("autre session", "another session"));
    }

    /// Un tube que le client croit d'un autre compte (le SID d'exemple de la documentation de Microsoft, jamais
    /// celui de la machine).
    #[test]
    fn un_autre_compte_ne_recoit_rien() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::Juste);
        let issue = joindre(
            &n,
            "S-1-5-21-1004336348-1177238915-682003330-1001",
            session(),
            &empreinte_de_l_essai(),
        );
        refuse_sans_rien_envoyer(
            &issue,
            &recu,
            crate::tr!("appartient à un autre compte", "belongs to another account"),
        );
    }

    /// Une liste d'accès ouverte à d'autres (tout le monde, en plus de ce compte) : refusée.
    #[test]
    fn une_liste_d_acces_trop_large_ne_recoit_rien() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let s = sid();
        let recu = serveur::servir_une_fois(&n, &format!("O:{s}D:P(A;;GA;;;{s})(A;;GA;;;WD)"), serveur::Jeu::Juste);
        let issue = joindre(&n, &s, session(), &empreinte_de_l_essai());
        refuse_sans_rien_envoyer(
            &issue,
            &recu,
            crate::tr!("nomme un autre compte", "names another account"),
        );
    }

    /// Un tube sans liste d'accès (ouvert à tous) : refusé.
    #[test]
    fn un_tube_sans_liste_d_acces_ne_recoit_rien() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let s = sid();
        let recu = serveur::servir_une_fois(&n, &format!("O:{s}D:NO_ACCESS_CONTROL"), serveur::Jeu::Juste);
        let issue = joindre(&n, &s, session(), &empreinte_de_l_essai());
        // Windows en fait une liste absente (« ouvert à tous ») ; Wine, une liste vide (« illisible ») : refusé
        // pareil.
        refuse_sans_rien_envoyer(&issue, &recu, crate::tr!("canal", "channel"));
    }

    /// Constat 1 : une réponse qui attendait avant la demande : refusée, la demande n'est pas envoyée.
    #[test]
    fn une_reponse_d_avance_est_refusee() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::Davance);
        let issue = joindre(&n, &sid(), session(), &empreinte_de_l_essai());
        refuse_sans_rien_envoyer(&issue, &recu, crate::tr!("attendait", "waiting"));
    }

    /// Constat 1 : « ok » sans le nombre de la demande : refusé.
    #[test]
    fn une_reponse_sans_le_nombre_est_refusee() {
        if !la_reference_passe() {
            return;
        }
        let n = nom();
        let recu = serveur::servir_une_fois(&n, &regle::sddl(&sid()).unwrap(), serveur::Jeu::SansLeNombre);
        let issue = joindre(&n, &sid(), session(), &empreinte_de_l_essai());
        assert!(
            matches!(&issue, Issue::Refusee(r) if r.contains(crate::tr!("nombre", "number"))),
            "{issue:?}"
        );
        assert!(recu.recv().unwrap().is_some());
    }
}
