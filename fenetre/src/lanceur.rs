//! Lancer `vanguard` avec une commande de la liste fermée (`commandes`) ou un changement au démarrage de forme fermée
//! (`demarrage --retirer|--remettre <empreinte> --json`), et rien d'autre : le programme voisin (le
//! fichier `vanguard` posé dans le même dossier que la fenêtre, jamais cherché dans le PATH ni désigné par une
//! variable), sans shell, avec ses arguments fixés dans le code, l'entrée fermée (il ne peut rien demander), ses
//! sorties lues en fond et bornées, un délai, et un arrêt qui tue tout son groupe (Linux).
//!
//! C'est l'équivalent, pour la fenêtre, de `commande::lancer` dans Vanguard : un enfant qui ne finit pas, qui écrit
//! sans fin ou qui garde ses sorties ouvertes ne bloque ni n'épuise la fenêtre.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use crate::commandes::Lancement;
// Ici d'abord, puis dans `commandes`, que le banc de fuzzing peut lire (pas d'unsafe) avec `protocole`.
pub use crate::commandes::{Fin, Issue};

/// La sortie (JSON) relue au plus : 16 Mio. Au-delà, l'enfant est arrêté et rien n'est montré.
pub const SORTIE_MAX: usize = 16 * 1024 * 1024;
/// Une ligne des erreurs gardée au plus (octets) ; le reste de la ligne est jeté.
const LIGNE_ERREUR_MAX: usize = 4096;
/// Lignes des erreurs relayées au plus par tâche.
const LIGNES_ERREUR_MAX: usize = 2000;
/// Après la fin de l'enfant, le temps laissé aux lecteurs pour finir (une sortie gardée ouverte par un petit-enfant).
const FIN_LECTURE: Duration = Duration::from_secs(2);
/// Entre la demande d'arrêt (SIGTERM) et l'arrêt forcé (SIGKILL).
const GRACE: Duration = Duration::from_millis(1500);
/// Le pas de la surveillance de l'enfant.
const PAS: Duration = Duration::from_millis(50);

/// Le programme `vanguard` voisin de la fenêtre, et le compte à qui il doit être (celui de la fenêtre, ou root).
#[derive(Clone, Debug)]
pub struct Programme {
    chemin: PathBuf,
    proprietaire: u32,
}

impl Programme {
    /// `vanguard` (`vanguard.exe` sous Windows) dans le dossier de la fenêtre. Jamais le PATH, jamais une variable
    /// d'environnement : une fenêtre lancée d'un dossier piégé ne doit pas lancer un autre programme.
    pub fn voisin() -> Result<Programme, String> {
        let soi = std::env::current_exe().map_err(|e| e.to_string())?;
        let dossier = soi
            .parent()
            .ok_or_else(|| crate::tr!("dossier introuvable", "folder not found").to_string())?;
        #[cfg(unix)]
        let proprietaire = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&soi).map_err(|e| e.to_string())?.uid()
        };
        #[cfg(not(unix))]
        let proprietaire = 0;
        Programme::dans(dossier, proprietaire)
    }

    /// `proprietaire` : le compte à qui est la fenêtre elle-même (Linux) ; `vanguard` doit être à lui ou à root.
    pub(crate) fn dans(dossier: &Path, proprietaire: u32) -> Result<Programme, String> {
        let nom = if cfg!(windows) { "vanguard.exe" } else { "vanguard" };
        let p = Programme {
            chemin: dossier.join(nom),
            proprietaire,
        };
        p.verifier()?;
        Ok(p)
    }

    /// Pour les captures de la fenêtre : un `vanguard` qui n'existe pas, que `verifier` refuse avant tout lancement.
    #[cfg(test)]
    pub fn factice() -> Programme {
        Programme {
            chemin: PathBuf::from("/nonexistent/vanguard-des-captures/vanguard"),
            proprietaire: u32::MAX,
        }
    }

    /// La garde (`refus_chemin`), rejouée juste avant chaque lancement : la fenêtre reste ouverte des heures et relit
    /// les événements toutes les minutes, le fichier vérifié à l'ouverture a pu changer depuis.
    pub fn verifier(&self) -> Result<(), String> {
        let nom = self
            .chemin
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match refus_chemin(&self.chemin, self.proprietaire) {
            None => Ok(()),
            Some(Refus::Absent) => Err(crate::trf!(
                "« {} » est introuvable à côté de la fenêtre",
                "“{}” was not found next to the window",
                nom
            )),
            Some(Refus::Raison(raison)) => Err(crate::trf!(
                "« {} » à côté de la fenêtre n'est pas lancé : {}",
                "“{}” next to the window is not started: {}",
                nom,
                raison
            )),
        }
    }
}

/// Pourquoi le `vanguard` voisin n'est pas lancé.
#[derive(Debug, PartialEq, Eq)]
enum Refus {
    Absent,
    Raison(&'static str),
}

/// Le fichier, puis chacun des dossiers qui le contiennent jusqu'à la racine. Un lien n'est jamais suivi
/// (`symlink_metadata`) : il est refusé. Le chemin vient de `current_exe`, déjà résolu sous Linux.
#[cfg(unix)]
fn refus_chemin(chemin: &Path, proprietaire: u32) -> Option<Refus> {
    let Ok(m) = std::fs::symlink_metadata(chemin) else {
        return Some(Refus::Absent);
    };
    if let Some(r) = refus(&m, proprietaire) {
        return Some(Refus::Raison(r));
    }
    for d in chemin.ancestors().skip(1).filter(|d| !d.as_os_str().is_empty()) {
        let Ok(m) = std::fs::symlink_metadata(d) else {
            return Some(Refus::Raison(crate::tr!(
                "un dossier illisible",
                "an unreadable folder"
            )));
        };
        if let Some(r) = refus_dossier(&m, proprietaire) {
            return Some(Refus::Raison(r));
        }
    }
    None
}

#[cfg(not(unix))]
fn refus_chemin(chemin: &Path, _proprietaire: u32) -> Option<Refus> {
    let Ok(m) = std::fs::symlink_metadata(chemin) else {
        return Some(Refus::Absent);
    };
    (!m.file_type().is_file()).then(|| Refus::Raison(crate::tr!("pas un fichier ordinaire", "not a regular file")))
}

/// Pourquoi le `vanguard` voisin n'est pas lancé, s'il y a une raison : la même règle que Vanguard pour la fenêtre
/// (src/demarrage/lancer_fenetre.rs). Sous Linux, un vrai fichier (pas un lien), au compte de la fenêtre ou à root, que
/// ni le groupe ni les autres ne peuvent modifier : sinon un autre compte pourrait y mettre un faux `vanguard` dont
/// la fenêtre afficherait les « tout va bien ».
#[cfg(unix)]
fn refus(m: &std::fs::Metadata, proprietaire: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_file() {
        return Some(crate::tr!("pas un fichier ordinaire", "not a regular file"));
    }
    if m.uid() != proprietaire && m.uid() != 0 {
        return Some(crate::tr!("à un autre compte", "owned by another account"));
    }
    if m.mode() & 0o022 != 0 {
        return Some(crate::tr!(
            "modifiable par d'autres comptes",
            "writable by other accounts"
        ));
    }
    None
}

/// Un dossier du chemin : un vrai dossier, au même compte ou à root, que ni le groupe ni les autres ne peuvent
/// modifier, sauf s'il est « collant » (sticky, comme /tmp : les autres comptes n'y renomment ni n'y effacent ce
/// qui n'est pas à eux). Sinon un autre compte pourrait renommer le fichier ou le dossier et en poser un faux.
#[cfg(unix)]
fn refus_dossier(m: &std::fs::Metadata, proprietaire: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_dir() {
        return Some(crate::tr!(
            "un dossier du chemin est un lien",
            "a folder on the path is a link"
        ));
    }
    if m.uid() != proprietaire && m.uid() != 0 {
        return Some(crate::tr!(
            "un dossier du chemin est à un autre compte",
            "a folder on the path is owned by another account"
        ));
    }
    if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Some(crate::tr!(
            "un dossier du chemin est modifiable par d'autres comptes",
            "a folder on the path is writable by other accounts"
        ));
    }
    None
}

/// Ce qu'une tâche envoie à la fenêtre.
#[derive(Clone, Debug)]
pub enum Message {
    /// Une ligne écrite sur la sortie des erreurs (progression, avertissement), nettoyée.
    Ligne(String),
    /// `vanguard` est lancé, sous ce numéro de processus : noté dans les coulisses, rien d'autre.
    Lance(u32),
    Fin(Fin),
}

/// Une commande (ou un changement) en cours.
pub struct Tache {
    pub lancement: Lancement,
    pub debut: Instant,
    arret: Arc<AtomicBool>,
    recu: mpsc::Receiver<Message>,
    /// Sous Linux, son numéro auprès du relais (`relais`), qui la lance hors du bac à sable de la fenêtre.
    #[cfg(target_os = "linux")]
    relayee: Option<u32>,
}

/// Réveille la fenêtre quand un message arrive (elle ne redessine pas sans cela).
pub type Reveil = Arc<dyn Fn() + Send + Sync>;

/// Où une tâche rend ses messages, de n'importe quel fil : la fenêtre (une file et son réveil) ou le relais (le
/// tuyau vers la fenêtre).
pub type Rendre = Arc<dyn Fn(Message) + Send + Sync>;

impl Tache {
    /// Lance `lancement` en fond. Le résultat arrive par `recevoir`, toujours terminé par un `Message::Fin`. Sous
    /// Linux, c'est le relais qui lance, quand la fenêtre en a un (`relais::separer`) : la fenêtre est alors dans son
    /// bac à sable, et `vanguard` lancé d'elle en hériterait.
    pub fn lancer(programme: &Programme, lancement: Lancement, anglais: bool, reveil: &Reveil) -> Tache {
        #[cfg(target_os = "linux")]
        if let Some(r) = crate::relais::client() {
            return r.lancer(lancement, anglais, reveil);
        }
        let arret = Arc::new(AtomicBool::new(false));
        let (envoi, recu) = mpsc::channel();
        let programme = programme.clone();
        let a = Arc::clone(&arret);
        let rendre: Rendre = {
            let envoi = envoi.clone();
            let reveil = Arc::clone(reveil);
            Arc::new(move |m| {
                let _ = envoi.send(m);
                reveil();
            })
        };
        let lance = std::thread::Builder::new()
            .name("vanguard-tache".into())
            .spawn(move || {
                let fin = surveiller(&programme, lancement, anglais, &a, &rendre);
                rendre(Message::Fin(fin));
            });
        if let Err(e) = lance {
            let _ = envoi.send(Message::Fin(Fin {
                lancement,
                code: None,
                sortie: Vec::new(),
                issue: Issue::Impossible(e.to_string()),
                duree: Duration::ZERO,
            }));
            reveil();
        }
        Tache {
            lancement,
            debut: Instant::now(),
            arret,
            recu,
            #[cfg(target_os = "linux")]
            relayee: None,
        }
    }

    /// Une tâche lancée par le relais : ses messages arrivent par `recu`, son arrêt est demandé au relais.
    #[cfg(target_os = "linux")]
    pub fn relayee(lancement: Lancement, id: u32, recu: mpsc::Receiver<Message>) -> Tache {
        Tache {
            lancement,
            debut: Instant::now(),
            arret: Arc::new(AtomicBool::new(false)),
            recu,
            relayee: Some(id),
        }
    }

    /// Demande l'arrêt : le groupe de l'enfant reçoit SIGTERM, puis SIGKILL après un court délai.
    pub fn arreter(&self) {
        self.arret.store(true, Ordering::Relaxed);
        #[cfg(target_os = "linux")]
        if let (Some(id), Some(r)) = (self.relayee, crate::relais::client()) {
            r.arreter(id);
        }
    }

    /// Lancée par le relais (Linux, fenêtre dans son bac à sable), ou par la fenêtre elle-même.
    // raison : hors de Linux, il n'y a pas de relais ; la même signature partout garde un seul appel.
    #[cfg_attr(not(target_os = "linux"), allow(clippy::unused_self))]
    pub fn par_le_relais(&self) -> bool {
        #[cfg(target_os = "linux")]
        return self.relayee.is_some();
        #[cfg(not(target_os = "linux"))]
        false
    }

    pub fn arret_demande(&self) -> bool {
        self.arret.load(Ordering::Relaxed)
    }

    /// Les messages arrivés depuis le dernier appel.
    pub fn recevoir(&self) -> Vec<Message> {
        self.recu.try_iter().collect()
    }
}

fn preparer(chemin: &Path, lancement: Lancement, anglais: bool) -> Command {
    let mut c = Command::new(chemin);
    c.args(lancement.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Du texte simple : pas de couleurs ni de séquences de terminal (nettoyées de toute façon).
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .env("VANGUARD_LANG", if anglais { "en" } else { "fr" })
        // La progression sur la sortie des erreurs (`@etape 3/9 …`), lue strictement par `progression::lire` ; la
        // sortie, elle, reste le JSON seul.
        .env(crate::progression::VARIABLE, "1");
    if let Some(d) = chemin.parent() {
        c.current_dir(d);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Son propre groupe : Arrêter tue aussi ce que `vanguard` a lancé.
        c.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW : pas de console qui s'ouvre et se ferme à chaque commande.
        c.creation_flags(0x0800_0000);
    }
    c
}

/// Lance `lancement`, la surveille jusqu'à sa fin et la rend ; ses lignes d'erreur passent par `rendre` en chemin
/// (pas la fin : l'appelant la rend lui-même).
pub fn surveiller(
    programme: &Programme,
    lancement: Lancement,
    anglais: bool,
    arret: &AtomicBool,
    rendre: &Rendre,
) -> Fin {
    let debut = Instant::now();
    let fin = |code, sortie, issue| Fin {
        lancement,
        code,
        sortie,
        issue,
        duree: debut.elapsed(),
    };
    // Une commande d'un autre système n'est jamais lancée, même demandée par son rang (le relais lit la fenêtre comme
    // un inconnu) : la fenêtre ne la montre pas, ceci tient même si elle la demandait.
    if !lancement.sur_ce_systeme() {
        return fin(
            None,
            Vec::new(),
            Issue::Impossible(crate::tr!("pas sur ce système", "not on this system").into()),
        );
    }
    // La garde rejouée juste avant le lancement (voir `Programme::verifier`).
    if let Err(e) = programme.verifier() {
        return fin(None, Vec::new(), Issue::Impossible(e));
    }
    let mut enfant = match preparer(&programme.chemin, lancement, anglais).spawn() {
        Ok(e) => e,
        Err(e) => {
            return fin(
                None,
                Vec::new(),
                Issue::Impossible(crate::nettoyage::nom(&e.to_string(), 200)),
            );
        }
    };
    let groupe = Groupe::de(&enfant);
    // Après l'objet de travail (Windows) : rien ne doit allonger l'instant où `vanguard` n'y est pas encore.
    rendre(Message::Lance(enfant.id()));
    let trop = Arc::new(AtomicBool::new(false));
    let abandon = Arc::new(AtomicBool::new(false));
    let (sortie_envoi, sortie_recu) = mpsc::channel();
    if let Some(s) = enfant.stdout.take() {
        let trop = Arc::clone(&trop);
        let s = Lecteur {
            source: s,
            abandon: Arc::clone(&abandon),
        };
        let _ = std::thread::Builder::new()
            .name("vanguard-sortie".into())
            .spawn(move || {
                let (octets, depasse) = lire_borne(s, SORTIE_MAX);
                if depasse {
                    trop.store(true, Ordering::Relaxed);
                }
                let _ = sortie_envoi.send(octets);
            });
    }
    let erreurs = enfant.stderr.take().and_then(|e| {
        let e = Lecteur {
            source: e,
            abandon: Arc::clone(&abandon),
        };
        let rendre = Arc::clone(rendre);
        std::thread::Builder::new()
            .name("vanguard-erreurs".into())
            .spawn(move || {
                lire_lignes(e, LIGNE_ERREUR_MAX, LIGNES_ERREUR_MAX, |l| {
                    if !l.is_empty() {
                        rendre(Message::Ligne(l));
                    }
                });
            })
            .ok()
    });
    let delai = lancement.delai();
    let issue = loop {
        match fini(&mut enfant) {
            Ok(true) => break Issue::Terminee,
            Ok(false) => {}
            Err(e) => {
                arreter(&mut enfant, &groupe);
                break Issue::Impossible(crate::nettoyage::nom(&e.to_string(), 200));
            }
        }
        let issue = if arret.load(Ordering::Relaxed) {
            Some(Issue::Arretee)
        } else if trop.load(Ordering::Relaxed) {
            Some(Issue::TropLongue)
        } else if debut.elapsed() >= delai {
            Some(Issue::DelaiDepasse)
        } else {
            None
        };
        if let Some(i) = issue {
            arreter(&mut enfant, &groupe);
            break i;
        }
        std::thread::sleep(PAS);
    };
    // Jusqu'ici, `vanguard` n'est jamais récolté (Linux : waitid avec WNOWAIT) : son numéro, qui est aussi celui de
    // son groupe, reste pris, et chaque killpg ci-dessous ne peut viser que ce groupe-là, jamais un autre processus
    // qui aurait reçu ce numéro après lui. Seul le `wait` de la fin le récolte, après le dernier killpg.
    // La sortie : ce que le lecteur a lu. Un petit-enfant qui la garderait ouverte est tué avec le groupe. Un
    // processus sorti du groupe de lui-même (setsid) échapperait à killpg : la tâche finit quand même (« sortie
    // jamais fermée ») et les lecteurs lâchent leur bout du tuyau (`abandon`, plus bas). Aucune commande de la liste
    // ne lance un tel processus (seuls le bilan complet, `vanguard plugins` et la surveillance lancent des plugins
    // par setsid).
    let sortie = if let Ok(s) = sortie_recu.recv_timeout(FIN_LECTURE) {
        Some(s)
    } else {
        groupe.tuer(true);
        sortie_recu.recv_timeout(FIN_LECTURE).ok()
    };
    // Rien du groupe ne survit à la commande, même un petit-enfant qui a fermé ses sorties ; puis la récolte.
    groupe.tuer(true);
    let code = enfant.wait().ok().and_then(|s| s.code());
    // Les dernières lignes d'erreur déjà écrites sont lues ; passé FIN_LECTURE, les lecteurs abandonnent (Linux) :
    // un processus qui garderait une sortie ouverte n'y retient ni un fil ni un tuyau de la fenêtre.
    let attente = Instant::now();
    while erreurs.as_ref().is_some_and(|f| !f.is_finished()) && attente.elapsed() < FIN_LECTURE {
        std::thread::sleep(PAS);
    }
    abandon.store(true, Ordering::Relaxed);
    let issue = if issue == Issue::Terminee && trop.load(Ordering::Relaxed) {
        Issue::TropLongue
    } else {
        issue
    };
    match (issue, sortie) {
        (Issue::Terminee, Some(s)) => fin(code, s, Issue::Terminee),
        (Issue::Terminee, None) => fin(
            code,
            Vec::new(),
            Issue::Impossible(crate::tr!("sortie jamais fermée", "output never closed").into()),
        ),
        (i, _) => fin(None, Vec::new(), i),
    }
}

/// Une sortie de l'enfant, lue jusqu'à sa fin ou jusqu'à `abandon` (Linux : l'attente se fait par poll, par pas
/// de 100 ms, pour voir l'abandon ; le lecteur rend alors une fin, et le tuyau se ferme avec lui). Sous Windows, une
/// lecture ordinaire : un enfant de `vanguard` qui garderait la sortie ouverte est tué avec son objet de travail à la
/// fin de la commande, et la lecture finit avec lui (s'il a pu y être mis, voir `travail`).
struct Lecteur<R> {
    source: R,
    abandon: Arc<AtomicBool>,
}

#[cfg(unix)]
impl<R: Read + std::os::fd::AsRawFd> Read for Lecteur<R> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.abandon.load(Ordering::Relaxed) {
                return Ok(0);
            }
            if signal::lisible(self.source.as_raw_fd(), 100)? {
                return self.source.read(tampon);
            }
        }
    }
}

#[cfg(not(unix))]
impl<R: Read> Read for Lecteur<R> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        let _ = &self.abandon;
        self.source.read(tampon)
    }
}

/// Arrête l'enfant : SIGTERM au groupe, puis SIGKILL après `GRACE` (Linux) ; sous Windows, tout son objet de
/// travail (`travail`), ou `vanguard` seul si Windows l'a refusé. Ne le récolte pas : `surveiller` tue encore ce qui
/// reste du groupe, puis le récolte.
fn arreter(enfant: &mut Child, groupe: &Groupe) {
    groupe.tuer(false);
    let debut = Instant::now();
    while debut.elapsed() < GRACE {
        if matches!(fini(enfant), Ok(true)) {
            return;
        }
        std::thread::sleep(PAS);
    }
    groupe.tuer(true);
    let _ = enfant.kill();
}

/// L'enfant est-il fini ? Sous Linux, sans le récolter (waitid, WNOWAIT) : tant qu'il ne l'est pas, son numéro reste
/// pris et killpg ne peut pas tomber sur un autre groupe. Jamais `try_wait` ici, qui le récolterait.
#[cfg(unix)]
fn fini(enfant: &mut Child) -> std::io::Result<bool> {
    signal::fini_sans_recolter(enfant.id())
}

/// Sous Windows, `Child` garde le handle du processus : le récolter ne libère pas son numéro pour un autre.
#[cfg(not(unix))]
fn fini(enfant: &mut Child) -> std::io::Result<bool> {
    enfant.try_wait().map(|s| s.is_some())
}

/// Ce que `vanguard` a lancé avec lui : son groupe de processus (Linux, le numéro de `vanguard`) ou son objet de
/// travail (Windows).
#[cfg(unix)]
struct Groupe(Option<i32>);

#[cfg(unix)]
impl Groupe {
    fn de(enfant: &Child) -> Groupe {
        Groupe(i32::try_from(enfant.id()).ok().filter(|g| *g > 1))
    }

    fn tuer(&self, force: bool) {
        if let Some(g) = self.0 {
            signal::groupe(g, if force { libc::SIGKILL } else { libc::SIGTERM });
        }
    }
}

#[cfg(windows)]
struct Groupe(Option<crate::travail::Travail>);

#[cfg(windows)]
impl Groupe {
    fn de(enfant: &Child) -> Groupe {
        Groupe(crate::travail::Travail::pour(enfant))
    }

    /// Windows n'a pas de demande polie à envoyer à un programme sans fenêtre : arrêter, c'est tuer.
    fn tuer(&self, _force: bool) {
        if let Some(t) = &self.0 {
            t.tuer();
        }
    }
}

#[cfg(unix)]
mod signal {
    // raison : FFI de killpg (libc), pour arrêter tout le groupe de l'enfant, que std ne sait pas faire.
    #[allow(unsafe_code)]
    pub fn groupe(groupe: i32, sig: i32) {
        // SAFETY: killpg ne reçoit que deux entiers et ne touche aucune mémoire de ce programme ; le groupe est celui
        // de l'enfant (process_group(0) le crée avec son numéro), toujours > 1 (vérifié par l'appelant).
        let _ = unsafe { libc::killpg(groupe, sig) };
    }

    // raison : FFI de poll (libc), pour attendre une sortie avec un délai, ce que std ne sait pas faire sur un tuyau.
    #[allow(unsafe_code)]
    pub fn lisible(fd: i32, ms: i32) -> std::io::Result<bool> {
        let mut attente = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll lit et écrit cette seule structure, à nous, vivante pendant l'appel (nombre : 1) ; le
        // descripteur est celui du tuyau, gardé ouvert par l'appelant.
        let r = unsafe { libc::poll(&raw mut attente, 1, ms) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            return if e.kind() == std::io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(e)
            };
        }
        // Données, fin (POLLHUP) ou erreur : la lecture qui suit ne bloque pas et le dira.
        Ok(r > 0 && attente.revents != 0)
    }

    // raison : FFI de waitid (libc), pour savoir l'enfant fini sans le récolter, ce que std ne sait pas faire.
    #[allow(unsafe_code)]
    pub fn fini_sans_recolter(pid: u32) -> std::io::Result<bool> {
        let id: libc::id_t = pid;
        // SAFETY: siginfo_t est une structure C sans pointeur, valide remplie de zéros ; waitid l'écrit (taille connue)
        // et ne garde rien. P_PID vise ce seul enfant, WNOHANG ne bloque pas, WNOWAIT le laisse à récolter par wait.
        let (r, info) = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let r = libc::waitid(
                libc::P_PID,
                id,
                &raw mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            );
            (r, info)
        };
        if r != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: si_pid lit un champ de l'union que waitid vient de remplir (0 tant que l'enfant n'a pas fini).
        Ok(unsafe { info.si_pid() } != 0)
    }
}

/// Lit au plus `max` octets ; `true` si la source en avait plus (le reste n'est pas lu : l'enfant sera arrêté).
pub fn lire_borne(r: impl Read, max: usize) -> (Vec<u8>, bool) {
    let mut v = Vec::new();
    let limite = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let _ = r.take(limite).read_to_end(&mut v);
    if v.len() > max {
        v.truncate(max);
        (v, true)
    } else {
        (v, false)
    }
}

/// Lit des lignes, chacune coupée à `max_octets` (le reste de la ligne jeté) et nettoyée, `max_lignes` au plus ;
/// au-delà, la source est lue jusqu'au bout sans rien garder (l'enfant ne doit pas bloquer sur un tuyau plein).
pub fn lire_lignes(mut r: impl Read, max_octets: usize, max_lignes: usize, mut f: impl FnMut(String)) {
    let mut ligne: Vec<u8> = Vec::new();
    let mut lignes = 0usize;
    let mut bloc = [0u8; 8192];
    let mut rendre = |ligne: &mut Vec<u8>, lignes: &mut usize| {
        if *lignes < max_lignes {
            f(crate::nettoyage::ligne(&String::from_utf8_lossy(ligne)));
        }
        *lignes = lignes.saturating_add(1);
        ligne.clear();
    };
    loop {
        let n = match r.read(&mut bloc) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        for &o in bloc.get(..n).unwrap_or(&[]) {
            if o == b'\n' {
                rendre(&mut ligne, &mut lignes);
            } else if ligne.len() < max_octets {
                ligne.push(o);
            }
        }
    }
    if !ligne.is_empty() {
        rendre(&mut ligne, &mut lignes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::commandes::{Changement, Commande, Empreinte, Sorte};

    #[test]
    fn la_sortie_est_bornee() {
        assert_eq!(lire_borne(&b"abc"[..], 3), (b"abc".to_vec(), false));
        assert_eq!(lire_borne(&b"abcd"[..], 3), (b"abc".to_vec(), true));
        assert_eq!(lire_borne(&b""[..], 3), (Vec::new(), false));
    }

    #[test]
    fn les_lignes_sont_bornees_et_propres() {
        let mut vues = Vec::new();
        let source = format!("une\n{}\n\u{1b}[31mrouge\u{1b}[0m\r\nfin", "x".repeat(10_000));
        lire_lignes(source.as_bytes(), 10, 100, |l| vues.push(l));
        assert_eq!(vues, ["une", "xxxxxxxxxx", "rouge", "fin"]);
        let mut n = 0;
        lire_lignes("a\n".repeat(50).as_bytes(), 10, 5, |_| n += 1);
        assert_eq!(n, 5);
    }

    #[test]
    fn seul_le_voisin_est_lance() {
        let d = std::env::temp_dir().join(format!("vanguard-fenetre-essai-{}", std::process::id()));
        // Un dossier qui n'existe pas : rien, jamais le PATH.
        assert!(Programme::dans(&d, 0).is_err());
    }

    /// Un `vanguard` que d'autres comptes pourraient remplacer n'est pas lancé, ni un lien, ni celui d'un autre compte.
    #[cfg(unix)]
    #[test]
    fn un_vanguard_modifiable_par_d_autres_est_refuse() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(format!("droits-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("vanguard");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let moi = std::fs::metadata(&f).unwrap().uid();
        let droits = |mode| std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        droits(0o755);
        let p = Programme::dans(&d, moi).unwrap();
        // Le dossier : modifiable par d'autres, refusé ; collant (sticky, comme /tmp), permis.
        let dossier = |mode| std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
        dossier(0o775);
        assert!(Programme::dans(&d, moi).is_err());
        dossier(0o1777);
        assert!(Programme::dans(&d, moi).is_ok());
        dossier(0o755);
        // Changé après l'ouverture : la garde rejouée avant le lancement le voit, et rien n'est lancé.
        droits(0o775);
        assert!(p.verifier().is_err());
        let rien: Reveil = Arc::new(|| {});
        let t = Tache::lancer(&p, Commande::Bilan.into(), false, &rien);
        let debut = Instant::now();
        let fin = loop {
            if let Some(Message::Fin(f)) = t.recevoir().into_iter().find(|m| matches!(m, Message::Fin(_))) {
                break f;
            }
            assert!(debut.elapsed() < Duration::from_secs(10), "jamais fini");
            std::thread::sleep(PAS);
        };
        assert!(matches!(fin.issue, Issue::Impossible(_)), "{:?}", fin.issue);
        assert!(Programme::dans(&d, moi).is_err());
        droits(0o757);
        assert!(Programme::dans(&d, moi).is_err());
        droits(0o755);
        if moi != 0 {
            assert!(Programme::dans(&d, moi.wrapping_add(1)).is_err());
        }
        std::fs::rename(&f, d.join("vrai")).unwrap();
        std::os::unix::fs::symlink(d.join("vrai"), &f).unwrap();
        assert!(Programme::dans(&d, moi).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un faux `vanguard` (un script) : la vraie suite lancée, attendue, arrêtée, sans rien toucher hors de target/.
    #[cfg(unix)]
    const FAUX: &str = r#"#!/bin/sh
# L'entrée est fermée : rien ne peut y être lu.
[ -z "$(cat)" ] || exit 9
case "$1 $2" in
"audit --json") echo "une ligne d'erreur" >&2; printf '{"score": 90, "fiable": true, "constats": [], "langue": "%s"}' "$VANGUARD_LANG" ;;
"protection --json") sleep 30 & echo $! > petit-enfant; sleep 30 ;;
"evenements --json") yes ;;
"diagnostic --json") sleep 30 & printf '{}' ;;
"test-connexion --json") sleep 30 >/dev/null 2>&1 & echo $! > reste; printf '{}' ;;
"acces-a-distance --json") setsid sleep 30 & echo $! > evade; printf '{}' ;;
"demarrage --retirer"|"demarrage --remettre") [ "$#" = 4 ] && [ "$4" = "--json" ] || exit 8
  printf '{"geste": "%s %s", "issue": "refuse"}' "$2" "$3"; exit 1 ;;
*) exit 7 ;;
esac
"#;

    #[cfg(unix)]
    fn attendre(t: &Tache) -> (Vec<String>, Fin) {
        let debut = Instant::now();
        let mut lignes = Vec::new();
        while debut.elapsed() < Duration::from_secs(20) {
            for m in t.recevoir() {
                match m {
                    Message::Ligne(l) => lignes.push(l),
                    Message::Lance(pid) => assert_ne!(pid, 0),
                    Message::Fin(f) => return (lignes, f),
                }
            }
            std::thread::sleep(PAS);
        }
        panic!("la tâche n'a jamais fini");
    }

    /// Le processus existe-t-il encore (un zombie ne compte pas) ?
    #[cfg(unix)]
    fn vivant(pid: &str) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, r)| !r.starts_with('Z')))
    }

    /// Les fils lecteurs encore là (leur nom, coupé à 15 octets par Linux).
    #[cfg(unix)]
    fn lecteurs() -> usize {
        std::fs::read_dir("/proc/self/task").map_or(0, |d| {
            d.flatten()
                .filter(|t| {
                    std::fs::read_to_string(t.path().join("comm"))
                        .is_ok_and(|n| n.starts_with("vanguard-sortie") || n.starts_with("vanguard-erreur"))
                })
                .count()
        })
    }

    /// Un seul essai pour les quatre cas : le script est écrit une fois avant tout lancement (sinon un autre essai
    /// qui lance un programme pendant l'écriture le rendrait « occupé », ETXTBSY).
    #[cfg(unix)]
    #[test]
    fn lance_attend_arrete_et_borne() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("essais-fenetre")
            .join(std::process::id().to_string());
        std::fs::create_dir_all(&d).unwrap();
        let script = d.join("vanguard");
        std::fs::write(&script, FAUX).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
        let moi = std::fs::metadata(&d).unwrap().uid();
        let p = Programme::dans(&d, moi).unwrap();
        let rien: Reveil = Arc::new(|| {});

        // Terminée : la sortie entière, la ligne d'erreur à part, la langue passée.
        let (lignes, f) = attendre(&Tache::lancer(&p, Commande::Bilan.into(), true, &rien));
        assert_eq!(f.issue, Issue::Terminee);
        assert_eq!(f.code, Some(0));
        assert!(String::from_utf8_lossy(&f.sortie).contains(r#""langue": "en""#));
        assert_eq!(lignes, ["une ligne d'erreur"]);

        // Arrêtée : le groupe entier part, le petit-enfant aussi.
        let t = Tache::lancer(&p, Commande::Protection.into(), false, &rien);
        let debut = Instant::now();
        while !d.join("petit-enfant").exists() && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(PAS);
        }
        t.arreter();
        let (_, f) = attendre(&t);
        assert_eq!(f.issue, Issue::Arretee);
        assert!(f.duree < Duration::from_secs(10));
        let pid = std::fs::read_to_string(d.join("petit-enfant")).unwrap();
        let pid = pid.trim();
        let debut = Instant::now();
        while vivant(pid) && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(PAS);
        }
        assert!(!vivant(pid), "le petit-enfant {pid} vit encore");

        // Trop longue : arrêtée à SORTIE_MAX, rien de gardé.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Evenements.into(), false, &rien));
        assert_eq!(f.issue, Issue::TropLongue);
        assert_eq!(f.sortie, b"");

        // Un petit-enfant garde la sortie ouverte après la fin : il est tué, la sortie lue est rendue.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Diagnostic.into(), false, &rien));
        assert_eq!(f.issue, Issue::Terminee);
        assert_eq!(f.sortie, b"{}");

        // Un petit-enfant laissé en fond, sorties fermées : la commande finit normalement, il ne lui survit pas.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::TestConnexion.into(), false, &rien));
        assert_eq!(
            (f.issue, f.code, f.sortie.as_slice()),
            (Issue::Terminee, Some(0), &b"{}"[..])
        );
        let pid = std::fs::read_to_string(d.join("reste")).unwrap();
        let pid = pid.trim();
        let debut = Instant::now();
        while vivant(pid) && debut.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(PAS);
        }
        assert!(!vivant(pid), "le petit-enfant {pid} vit encore");

        // Un processus sorti du groupe (setsid) garde les sorties ouvertes : la tâche finit, et les lecteurs lâchent
        // le tuyau au lieu de rester bloqués.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::AccesADistance.into(), false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        let debut = Instant::now();
        while lecteurs() > 0 && debut.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(PAS);
        }
        assert_eq!(lecteurs(), 0, "un lecteur attend encore");
        let evade = std::fs::read_to_string(d.join("evade")).unwrap();
        let _ = std::process::Command::new("kill").arg(evade.trim()).status();

        // Une commande que le script ne connaît pas : son code de sortie est rendu tel quel.
        let (_, f) = attendre(&Tache::lancer(&p, Commande::Lenteur.into(), false, &rien));
        assert_eq!(f.code, Some(7));

        // Un changement : exactement `demarrage --retirer|--remettre <32 hex> --json`, rien de plus.
        for (sorte, mot) in [(Sorte::Retirer, "--retirer"), (Sorte::Remettre, "--remettre")] {
            let empreinte = Empreinte::depuis_octets([0xab; 16]);
            let ch = Lancement::Changement(Changement { sorte, empreinte });
            let (_, f) = attendre(&Tache::lancer(&p, ch, false, &rien));
            assert_eq!(f.code, Some(1), "{mot}");
            assert_eq!(
                String::from_utf8_lossy(&f.sortie),
                format!(r#"{{"geste": "{mot} {}", "issue": "refuse"}}"#, "ab".repeat(16))
            );
            assert_eq!(f.lancement, ch);
        }

        // Une commande d'un autre système : rien n'est lancé (le script aurait rendu 7).
        let (_, f) = attendre(&Tache::lancer(&p, Commande::JournauxWindows.into(), false, &rien));
        assert!(matches!(f.issue, Issue::Impossible(_)), "{:?}", f.issue);
        assert_eq!(f.code, None);

        // Les coulisses de la fenêtre, par le même chemin que l'écran : la commande exacte, le chemin, le pid, la fin,
        // la ligne d'erreur et la sortie. Les commandes du lancement sont arrêtées d'abord (le faux protection dort).
        let mut a = crate::appli::Appli::nouvelle(Ok(p.clone()), Arc::clone(&rien));
        a.arreter();
        let debut = Instant::now();
        while a.taches() > 0 && debut.elapsed() < Duration::from_secs(10) {
            a.avancer();
            std::thread::sleep(PAS);
        }
        a.demander(Commande::Bilan);
        let debut = Instant::now();
        while a.taches() > 0 && debut.elapsed() < Duration::from_secs(20) {
            a.avancer();
            std::thread::sleep(PAS);
        }
        let c = &a.coulisses;
        let b = c.passages().back().unwrap();
        assert_eq!(b.ligne, "vanguard audit --json");
        assert_eq!(b.chemin, crate::coulisses::Chemin::Direct);
        assert!(b.pid.is_some_and(|n| n > 0), "{:?}", b.pid);
        let fin = b.fin.as_ref().unwrap();
        assert_eq!(fin.code, Some(0));
        assert!(fin.taille > 0);
        let textes: Vec<&str> = c.notes().iter().map(|n| n.texte.as_str()).collect();
        assert!(textes.contains(&"une ligne d'erreur"), "{textes:?}");
        assert!(textes.iter().any(|t| t.contains(r#""score": 90"#)), "{textes:?}");
        // La première, arrêtée, a aussi son pid et sa fin.
        let premiere = c.passages().front().unwrap();
        assert_eq!(premiere.ligne, "vanguard protection --json");
        assert!(premiere.pid.is_some() && premiere.fin.is_some(), "{premiere:?}");
        let _ = std::fs::remove_dir_all(&d);
    }
}
