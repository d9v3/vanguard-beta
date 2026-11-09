//! Le temps réel des fichiers (Linux, sans droits) : les dossiers du compte où arrivent les menaces (Téléchargements,
//! Bureau, ~/.local/bin, ~/.config/autostart : ceux de l'analyse « Rapide », `antivirus::ENDROITS_A_RISQUE`) sont
//! marqués par fanotify, et chaque fichier qui y est fermé après écriture ou qui y arrive par renommage est relu et
//! jugé par le moteur de Vanguard (`moteur::examiner_ouvert`), puis suivi par le blocage (`blocage::en_direct`).
//!
//! Sans droits (Linux 5.13 et plus) : un groupe de NOTIFICATION (FAN_CLASS_NOTIF), qui ne retient jamais rien ;
//! l'identification par dossier et nom (FAN_REPORT_DFID_NAME), la seule permise, sans descripteur ouvert par le noyau ;
//! des marques d'INODE seulement. Une marque d'inode ne voit que les enfants DIRECTS du dossier marqué : ni ses
//! sous-dossiers, ni un autre dossier, ni un fichier lancé sans être écrit ici, ni ce qui était là avant le démarrage
//! du veilleur (l'analyse « Rapide » les voit ; la passe horaire reprend les fichiers de la semaine posés dans ces
//! dossiers, `menaces::telecharges`). Un groupe par dossier : le dossier de chaque
//! événement est celui du groupe, sans `open_by_handle_at` (réservé à root) ; le chemin est refait comme dossier +
//! nom, et le fichier est rouvert SOUS le descripteur du dossier, sans suivre aucun lien, fichier ordinaire seulement.
//! Le verdict porte sur le contenu lu, jamais sur le nom.
//!
//! Deux fils : le lecteur lit les événements et les range dans une file bornée (les écritures répétées d'un même
//! fichier y sont regroupées) ; l'examinateur prend chaque fichier une fois le calme revenu, et rend ses menaces au
//! veilleur, qui décide du débit des alertes et de la suite. Ce qui est sauté (file pleine, débordement du noyau,
//! trop gros, illisible, parti avant lecture, pause) est compté et dit non vérifié, jamais sain. Les écritures du
//! veilleur lui-même (le noyau ne donne le PID que des siennes) ne sont jamais examinées.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::{HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::machine::linux::fanotify::{self, Groupe, lecture};
use crate::machine::linux::garde::ouvrir;
use crate::protection::heuristiques::Lieu;
use crate::protection::moteur::{self, Resultat, Sources, Verdict};
use crate::protection::quarantaine::Identite;
use crate::{tr, trf};

/// Les fichiers en attente d'examen, au plus : au-delà, un fichier de plus est compté non vérifié.
pub(crate) const FILE_MAX: usize = 256;
/// Le calme attendu après la dernière écriture d'un fichier avant de l'examiner : ses écritures répétées n'en font
/// qu'un examen.
pub(crate) const CALME: Duration = Duration::from_secs(1);
/// Un fichier réécrit sans cesse est examiné quand même au bout de ce temps.
pub(crate) const ATTENTE_MAX: Duration = Duration::from_secs(30);
/// La taille au-delà de laquelle un fichier n'est pas lu (compté « trop gros », non vérifié ; la passe horaire reprend
/// ceux de la semaine de ces dossiers jusqu'à 64 Mio). Le fichier est lu en mémoire, et le veilleur tient en 128 Mo
/// (MemoryMax) avec tout le reste : 32 Mio, plus 32 Mio au plus de parties extraites (`bornes`). Jamais plus que
/// l'empreinte relue avant la quarantaine.
pub(crate) const TAILLE_MAX: u64 = 32 << 20;
const _: () = assert!(TAILLE_MAX <= crate::protection::blocage::en_direct::TAILLE_MAX);
/// Le temps du moteur pour un fichier.
const DELAI_EXAMEN: Duration = Duration::from_secs(15);
/// Les empreintes récentes de MalwareBazaar sont relues sur le disque à ce rythme (la surveillance les rafraîchit).
const RELIRE_SOURCES: Duration = Duration::from_hours(6);

/// Les bornes du moteur dans le veilleur : celles des analyses à la demande, resserrées pour tenir en 128 Mo. Une
/// archive ou un document qui les dépasse est dit lu en partie (non vérifié), jamais sain.
fn bornes() -> crate::analyse::Bornes {
    crate::analyse::Bornes {
        taille_fichier: TAILLE_MAX,
        taille_partie: 16 << 20,
        produits: 32 << 20,
        seuil_taux: 8 << 20,
        texte: 4 << 20,
        delai: DELAI_EXAMEN,
        ..crate::analyse::Bornes::default()
    }
}
/// Les menaces examinées en attente de leur suite dans le veilleur, au plus.
const CANAL: usize = 64;
/// L'attente du lecteur entre deux regards sur l'arrêt et la pause.
const BATTEMENT_MS: i32 = 500;
/// Le repos du lecteur après une lecture du groupe en erreur.
const REPOS_APRES_ERREUR: Duration = Duration::from_millis(100);

// ───────────────────────────── Dossiers surveillés ─────────────────────────────

/// Les dossiers à surveiller, tels qu'ils existent maintenant : (chemin réel, nom à montrer). Téléchargements d'abord
/// (celui que déclare le bureau, user-dirs.dirs), puis la liste de l'analyse « Rapide » ; chaque dossier une fois
/// (même inode : un lien vers un autre de la liste).
pub(crate) fn dossiers() -> Vec<(PathBuf, String)> {
    a_surveiller()
        .into_iter()
        .map(|(chemin, nom, _)| (chemin, nom))
        .collect()
}

/// Comme [`dossiers`], avec pour chacun s'il est Téléchargements (lieu des heuristiques, fichiers en cours).
pub(crate) fn a_surveiller() -> Vec<(PathBuf, String, bool)> {
    candidats(
        &crate::socle::maison(),
        crate::protection::telechargement::dossier_telechargements(),
    )
}

/// Pur, sauf la lecture des dossiers : (chemin réel, nom à montrer, est Téléchargements).
fn candidats(maison: &Path, telechargements: Option<PathBuf>) -> Vec<(PathBuf, String, bool)> {
    let mut vus = HashSet::new();
    let mut liste = Vec::new();
    let mut ajouter = |chemin: PathBuf, telech: bool| {
        // Le chemin réel : une marque porte sur l'inode, et le chemin refait (dossier + nom) ne doit traverser aucun
        // lien pour désigner le même fichier au moment de la quarantaine.
        let Ok(reel) = std::fs::canonicalize(&chemin) else {
            return;
        };
        let Ok(meta) = std::fs::metadata(&reel) else {
            return;
        };
        if !meta.is_dir() || !vus.insert((meta.dev(), meta.ino())) {
            return;
        }
        let nom = if telech {
            tr!("Téléchargements", "Downloads").to_string()
        } else {
            match chemin.strip_prefix(maison) {
                Ok(r) => format!("~/{}", crate::ui::chemin_affichable(r)),
                Err(_) => crate::ui::chemin_affichable(&chemin),
            }
        };
        liste.push((reel, nom, telech));
    };
    if let Some(t) = telechargements {
        ajouter(t, true);
    }
    for d in crate::protection::antivirus::ENDROITS_A_RISQUE {
        let telech = matches!(d, "Downloads" | "Téléchargements");
        ajouter(maison.join(d), telech);
    }
    liste
}

/// Un nom d'enfant venu du noyau, avant d'être joint au dossier : un seul élément de chemin. Les octets ne sont pas
/// forcément de l'UTF-8 (un nom de fichier Linux en est rarement garanti) : ils restent tels quels pour ouvrir, et ne
/// sont montrés que par `affichable`.
pub(crate) fn nom_acceptable(nom: &[u8]) -> bool {
    !nom.is_empty()
        && nom.len() <= lecture::NOM_MAX
        && !nom.contains(&b'/')
        && !nom.contains(&0)
        && nom != b"."
        && nom != b".."
}

// ───────────────────────────── File d'attente ─────────────────────────────

/// Ce que devient un événement rangé dans la file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ajout {
    Nouveau,
    /// Le fichier attendait déjà : regroupé, un seul examen.
    Regroupe,
    /// File pleine : non vérifié.
    Pleine,
}

#[derive(Debug)]
struct Entree {
    dossier: usize,
    nom: Vec<u8>,
    premier: Instant,
    dernier: Instant,
}

/// La file bornée des fichiers à examiner, un par (dossier, nom).
#[derive(Debug)]
pub(crate) struct Attente {
    file: VecDeque<Entree>,
    max: usize,
}

impl Attente {
    pub(crate) fn new(max: usize) -> Attente {
        Attente {
            file: VecDeque::new(),
            max,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.file.len()
    }

    pub(crate) fn ajouter(&mut self, dossier: usize, nom: &[u8], quand: Instant) -> Ajout {
        if let Some(e) = self.file.iter_mut().find(|e| e.dossier == dossier && e.nom == nom) {
            e.dernier = e.dernier.max(quand);
            return Ajout::Regroupe;
        }
        if self.file.len() >= self.max {
            return Ajout::Pleine;
        }
        self.file.push_back(Entree {
            dossier,
            nom: nom.to_vec(),
            premier: quand,
            dernier: quand,
        });
        Ajout::Nouveau
    }

    /// Le premier fichier prêt (calme depuis `CALME`, ou en attente depuis `ATTENTE_MAX`) : (dossier, nom, dernière
    /// écriture).
    pub(crate) fn prendre_pret(&mut self, maintenant: Instant) -> Option<(usize, Vec<u8>, Instant)> {
        let i = self.file.iter().position(|e| pret(e, maintenant))?;
        self.file.remove(i).map(|e| (e.dossier, e.nom, e.dernier))
    }

    /// Le temps avant que le prochain fichier soit prêt ; `None` : file vide.
    pub(crate) fn prochain(&self, maintenant: Instant) -> Option<Duration> {
        self.file
            .iter()
            .map(|e| {
                let calme = CALME.saturating_sub(maintenant.saturating_duration_since(e.dernier));
                let butoir = ATTENTE_MAX.saturating_sub(maintenant.saturating_duration_since(e.premier));
                calme.min(butoir)
            })
            .min()
    }

    fn vider(&mut self) -> usize {
        let n = self.file.len();
        self.file.clear();
        n
    }
}

fn pret(e: &Entree, maintenant: Instant) -> bool {
    maintenant.saturating_duration_since(e.dernier) >= CALME
        || maintenant.saturating_duration_since(e.premier) >= ATTENTE_MAX
}

// ───────────────────────────── Compteurs et relevé ─────────────────────────────

/// Les compteurs partagés par les deux fils et le veilleur.
#[derive(Debug, Default)]
pub(crate) struct Compteurs {
    pub evenements: AtomicU64,
    pub examines: AtomicU64,
    pub sains: AtomicU64,
    /// Verdict « non vérifié » du moteur (une partie ou une source manquait), ou contenu changé avant la quarantaine.
    pub non_verifies: AtomicU64,
    pub trop_gros: AtomicU64,
    pub illisibles: AtomicU64,
    pub partis: AtomicU64,
    pub file_pleine: AtomicU64,
    /// Débordements de la file du noyau (FAN_Q_OVERFLOW) : un nombre inconnu d'événements perdus chacun.
    pub debordements: AtomicU64,
    /// Tampons du noyau mal formés : la fin du tampon est perdue.
    pub defauts: AtomicU64,
    pub en_pause: AtomicU64,
    /// Liens, tubes, dossiers et noms refusés : rien à lire ici (un lien n'est jamais suivi).
    pub ecartes: AtomicU64,
    pub en_cours: AtomicU64,
    pub propres: AtomicU64,
    /// Dossiers surveillés remplacés ou supprimés sous leur nom (un `mv` puis un `mkdir`) : ce qui y est arrivé
    /// avant la nouvelle marque n'a pas été vu.
    pub remplaces: AtomicU64,
    pub latence_max_ms: AtomicU64,
    pub latence_totale_ms: AtomicU64,
    /// La mémoire prise par le chargement des sources (Kio, différence de VmRSS), si elle a pu être lue.
    pub sources_kio: AtomicU64,
    pub sources_chargees: AtomicBool,
}

fn plus(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

fn lu(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

/// Ce que le veilleur écrit dans son état : ce qui est surveillé, ce qui a été vu, ce qui n'a pas pu être vérifié.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(crate) struct Releve {
    /// Le temps réel des fichiers tourne (au moins un dossier marqué).
    pub actif: bool,
    /// Les dossiers surveillés, prêts à montrer.
    pub dossiers: Vec<String>,
    /// Les dossiers qui n'ont pas pu être marqués, avec la raison, prêts à montrer.
    pub refuses: Vec<String>,
    /// Pourquoi rien n'est surveillé (noyau trop ancien, fanotify refusé, aucun dossier) ; `None` : il tourne.
    pub sans: Option<String>,
    /// Arrêté par le filtre d'appels système (ou sans pouvoir le sonder) alors que la personne l'avait voulu : le bilan
    /// le dit comme un problème, avec « vanguard veilleur on ».
    pub a_rallumer: bool,
    pub evenements: u64,
    pub examines: u64,
    pub sains: u64,
    /// Menaces rendues au veilleur (certain, famille, suspect).
    pub menaces: u64,
    /// Mis en quarantaine tout seuls.
    pub isoles: u64,
    /// Tout ce qui n'a pas pu être vérifié : verdict non vérifié, trop gros, illisible, parti, file pleine, pause,
    /// en cours de téléchargement.
    pub non_verifies: u64,
    pub trop_gros: u64,
    pub illisibles: u64,
    pub partis: u64,
    pub file_pleine: u64,
    pub debordements: u64,
    pub defauts: u64,
    pub en_pause: u64,
    pub ecartes: u64,
    pub en_cours: u64,
    pub propres: u64,
    pub remplaces: u64,
    /// Les dossiers remplacés ou supprimés qui n'ont pas pu être marqués de nouveau : plus surveillés.
    pub perdus: Vec<String>,
    pub latence_max_ms: u64,
    pub latence_moyenne_ms: u64,
    pub sources_kio: Option<u64>,
}

impl Releve {
    /// Le nombre de fichiers non vérifiés, sans compter les débordements (de taille inconnue, dits à part). Un
    /// fichier en cours de téléchargement (« .part ») en est : il n'est examiné qu'à son renommage final, qui peut
    /// ne jamais venir (un « x.part » lancé tel quel).
    fn non_verifies_de(c: &Compteurs, suites: u64) -> u64 {
        [
            lu(&c.non_verifies),
            lu(&c.trop_gros),
            lu(&c.illisibles),
            lu(&c.partis),
            lu(&c.file_pleine),
            lu(&c.en_pause),
            lu(&c.en_cours),
            suites,
        ]
        .iter()
        .fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Ce que l'alerte horaire du veilleur compte : les fichiers non vérifiés, sauf ceux en cours de téléchargement
    /// (examinés à leur renommage final, et un téléchargement long en ferait une alerte par heure) et ceux de la
    /// pause (voulue, et déjà dite) ; plus les débordements du noyau, de taille inconnue.
    pub(crate) fn a_signaler(&self) -> u64 {
        self.non_verifies
            .saturating_sub(self.en_cours)
            .saturating_sub(self.en_pause)
            .saturating_add(self.debordements)
            .saturating_add(self.defauts)
    }

    /// La phrase de l'état, pour le constat du veilleur et le menu.
    pub(crate) fn phrase(&self) -> String {
        if let Some(sans) = &self.sans {
            return trf!(
                "Temps réel des fichiers : arrêté ({sans}).",
                "Real-time file scanning: stopped ({sans})."
            );
        }
        if !self.actif {
            return tr!(
                "Temps réel des fichiers : pas encore démarré.",
                "Real-time file scanning: not started yet."
            )
            .to_string();
        }
        let mut t = trf!(
            "Temps réel des fichiers : {} (fichiers posés directement dedans, pas les sous-dossiers) ; {} examiné(s), {} menace(s), {} mis en quarantaine.",
            "Real-time file scanning: {} (files placed directly in them, not subfolders); {} scanned, {} threat(s), {} quarantined.",
            self.dossiers.join(", "),
            self.examines,
            self.menaces,
            self.isoles
        );
        if self.examines > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "De l'arrivée au verdict : {} ms en moyenne, {} ms au plus (dont l'attente qu'un fichier cesse de changer).",
                "From arrival to verdict: {} ms on average, {} ms at most (including the wait for a file to stop changing).",
                self.latence_moyenne_ms,
                self.latence_max_ms
            ));
        }
        if let Some(kio) = self.sources_kio {
            t.push(' ');
            t.push_str(&trf!(
                "Signatures en mémoire : {} Mio.",
                "Signatures in memory: {} MiB.",
                kio.div_ceil(1024)
            ));
        }
        if self.non_verifies > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "{} non vérifié(s) (trop gros, illisibles, partis, file pleine, en pause, ou en cours de téléchargement et examinés seulement à leur renommage final) : jamais comptés sains.",
                "{} not verified (too large, unreadable, gone, queue full, paused, or still downloading and scanned only at their final rename): never counted as clean.",
                self.non_verifies
            ));
        }
        if self.debordements > 0 || self.defauts > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "{} débordement(s) du noyau : des fichiers n'ont pas été vus, la passe horaire reprend ceux de la semaine.",
                "{} kernel overflow(s): some files were not seen, the hourly pass picks up this week's.",
                self.debordements.saturating_add(self.defauts)
            ));
        }
        if !self.refuses.is_empty() {
            t.push(' ');
            t.push_str(&trf!(
                "Non surveillé(s) : {}.",
                "Not watched: {}.",
                self.refuses.join(" ; ")
            ));
        }
        if !self.perdus.is_empty() {
            t.push(' ');
            t.push_str(&trf!(
                "Dossier remplacé ou supprimé, plus surveillé : {}.",
                "Folder replaced or deleted, no longer watched: {}.",
                self.perdus.join(", ")
            ));
        }
        if self.remplaces > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "{} dossier(s) remplacé(s) sous leur nom : ce qui y est arrivé avant la nouvelle marque n'a pas été vu.",
                "{} folder(s) replaced under their name: what arrived there before the new mark was not seen.",
                self.remplaces
            ));
        }
        t
    }
}

/// VmRSS du processus, en Kio.
fn rss_kio() -> Option<u64> {
    let t = std::fs::read_to_string("/proc/self/status").ok()?;
    t.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
}

// ───────────────────────────── Surveillance ─────────────────────────────

/// Un dossier marqué : son descripteur (ouvert par Vanguard, sous lequel chaque nom est rouvert), son chemin réel et
/// son nom à montrer. Le descripteur change quand le dossier est remplacé sous son nom (`suivre_le_dossier`).
#[derive(Debug)]
struct Marque {
    fd: RwLock<File>,
    chemin: PathBuf,
    nom: String,
    telechargements: bool,
    /// Le dossier a été remplacé ou supprimé et n'a pas pu être marqué de nouveau : rien n'y est vu.
    perdu: AtomicBool,
}

impl Marque {
    fn nouvelle(fd: File, chemin: PathBuf, nom: String, telechargements: bool) -> Marque {
        Marque {
            fd: RwLock::new(fd),
            chemin,
            nom,
            telechargements,
            perdu: AtomicBool::new(false),
        }
    }
}

/// Une menace examinée, rendue au veilleur pour sa suite.
#[derive(Debug)]
pub(crate) struct Examine {
    pub chemin: PathBuf,
    pub ou: String,
    pub resultat: Resultat,
    /// L'identité du fichier lu (fstat du descripteur examiné) : la quarantaine n'isole que lui.
    pub identite: Identite,
}

/// La surveillance en marche : ses deux fils, la file et les compteurs.
pub(crate) struct Surveillance {
    arret: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    attente: Arc<(Mutex<Attente>, Condvar)>,
    pub(crate) compteurs: Arc<Compteurs>,
    recus: Receiver<Examine>,
    fils: Vec<JoinHandle<()>>,
    marques: Arc<Vec<Marque>>,
    dossiers: Vec<String>,
    refuses: Vec<String>,
    /// Une erreur du lecteur (groupe en erreur) : il s'est arrêté.
    erreur: Arc<Mutex<Option<String>>>,
    menaces: u64,
    isoles: u64,
    suites_non_verifiees: u64,
}

/// La raison d'un refus de fanotify, prête à montrer.
fn raison_refus(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::EPERM) => tr!(
            "fanotify refusé à un compte ordinaire (noyau d'avant 5.13, ou fermé par le système)",
            "fanotify refused to an ordinary account (kernel before 5.13, or closed by the system)"
        )
        .to_string(),
        Some(libc::EINVAL | libc::ENOSYS) => tr!(
            "noyau trop ancien pour fanotify sans droits (5.13 et plus)",
            "kernel too old for unprivileged fanotify (5.13 and later)"
        )
        .to_string(),
        Some(libc::EMFILE) => tr!(
            "trop de groupes fanotify pour ce compte",
            "too many fanotify groups for this account"
        )
        .to_string(),
        Some(libc::ENOSPC) => tr!(
            "trop de marques fanotify pour ce compte",
            "too many fanotify marks for this account"
        )
        .to_string(),
        _ => crate::ui::affichable(&e.to_string()),
    }
}

/// Pourquoi rien n'est surveillé : un texte prêt à montrer (déjà traduit et rendu affichable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refus(pub String);

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Les sources du moteur du temps réel et ses empreintes récentes (`moteur::sources_du_temps_reel`), rechargées toutes
/// les `RELIRE_SOURCES`.
pub(crate) type Charger =
    Box<dyn FnMut() -> (Sources<'static>, Option<crate::protection::empreintes::Empreintes>) + Send>;

impl Surveillance {
    /// Marque `dossiers` (chemin réel, nom à montrer, est Téléchargements) et démarre les deux fils. `charger` rend
    /// les sources du moteur, chargées une fois dans le fil de l'examinateur. Erreur : rien n'est surveillé, et
    /// pourquoi (prêt à montrer) ; les dossiers refusés un à un sont dits dans le relevé.
    pub(crate) fn demarrer(dossiers: Vec<(PathBuf, String, bool)>, charger: Charger) -> Result<Surveillance, Refus> {
        if dossiers.is_empty() {
            return Err(Refus(
                tr!("aucun dossier à surveiller", "no folder to watch").to_string(),
            ));
        }
        let mut groupes = Vec::new();
        let mut marques = Vec::new();
        let mut refuses = Vec::new();
        for (chemin, nom, telechargements) in dossiers {
            // Ouvert en lecture (fanotify_mark refuse O_PATH), sans suivre de lien : le chemin réel est déjà résolu.
            let fd = match std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
                .open(&chemin)
            {
                Ok(f) => f,
                Err(e) => {
                    refuses.push(format!("{nom} : {}", crate::ui::affichable(&e.to_string())));
                    continue;
                }
            };
            let groupe = match Groupe::ouvrir_notification() {
                Ok(g) => g,
                // Le groupe lui-même refusé : aucun dossier ne le sera mieux.
                Err(e) if groupes.is_empty() => return Err(Refus(raison_refus(&e))),
                Err(e) => {
                    refuses.push(format!("{nom} : {}", raison_refus(&e)));
                    continue;
                }
            };
            if let Err(e) = groupe.marquer_dossier(fd.as_fd()) {
                refuses.push(format!("{nom} : {}", raison_refus(&e)));
                continue;
            }
            groupes.push(groupe);
            marques.push(Marque::nouvelle(fd, chemin, nom, telechargements));
        }
        if groupes.is_empty() {
            return Err(Refus(trf!(
                "aucun dossier n'a pu être marqué ({})",
                "no folder could be marked ({})",
                refuses.join(" ; ")
            )));
        }
        let noms = marques.iter().map(|m| m.nom.clone()).collect();
        let marques = Arc::new(marques);
        let arret = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let attente = Arc::new((Mutex::new(Attente::new(FILE_MAX)), Condvar::new()));
        let compteurs = Arc::new(Compteurs::default());
        let erreur = Arc::new(Mutex::new(None));
        let (envoi, recus) = mpsc::sync_channel(CANAL);
        let lecteur = {
            let (arret, pause, attente, compteurs, marques, erreur) = (
                arret.clone(),
                pause.clone(),
                attente.clone(),
                compteurs.clone(),
                marques.clone(),
                erreur.clone(),
            );
            std::thread::Builder::new()
                .name("vanguard-fichiers-lecteur".into())
                .spawn(move || lire(&groupes, &marques, &arret, &pause, &attente, &compteurs, &erreur))
        };
        let examinateur = {
            let (arret, pause, attente, compteurs, erreur_examen, marques) = (
                arret.clone(),
                pause.clone(),
                attente.clone(),
                compteurs.clone(),
                erreur.clone(),
                marques.clone(),
            );
            std::thread::Builder::new()
                .name("vanguard-fichiers-examen".into())
                .spawn(move || {
                    let partage = Partage {
                        marques: &marques,
                        arret: &arret,
                        pause: &pause,
                        attente: &attente,
                        compteurs: &compteurs,
                        erreur: &erreur_examen,
                    };
                    examiner(charger, &partage, &envoi);
                })
        };
        let mut fils = Vec::new();
        for f in [lecteur, examinateur] {
            match f {
                Ok(f) => fils.push(f),
                Err(e) => {
                    arret.store(true, Ordering::SeqCst);
                    attente.1.notify_all();
                    for f in fils {
                        let _ = f.join();
                    }
                    return Err(Refus(crate::ui::affichable(&e.to_string())));
                }
            }
        }
        Ok(Surveillance {
            arret,
            pause,
            attente,
            compteurs,
            recus,
            fils,
            marques,
            dossiers: noms,
            refuses,
            erreur,
            menaces: 0,
            isoles: 0,
            suites_non_verifiees: 0,
        })
    }

    /// Met en pause (coupure du temps réel) ou reprend : en pause, ce qui arrive est compté non vérifié, jamais
    /// examiné, et la file est vidée.
    pub(crate) fn mettre_en_pause(&self, pause: bool) {
        self.pause.store(pause, Ordering::SeqCst);
        if pause && let Ok(mut a) = self.attente.0.lock() {
            let n = a.vider();
            self.compteurs
                .en_pause
                .fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
        }
    }

    /// La prochaine menace examinée, sans attendre.
    pub(crate) fn recevoir(&self) -> Option<Examine> {
        self.recus.try_recv().ok()
    }

    /// Note la suite donnée à une menace.
    pub(crate) fn noter_suite(&mut self, fait: crate::protection::blocage::en_direct::Fait) {
        use crate::protection::blocage::en_direct::Suite;
        self.menaces = self.menaces.saturating_add(1);
        if fait.isole {
            self.isoles = self.isoles.saturating_add(1);
        }
        if fait.suite == Suite::NonVerifie {
            self.suites_non_verifiees = self.suites_non_verifiees.saturating_add(1);
        }
    }

    /// Note une menace reçue pendant la pause : non vérifiée, sans suite.
    pub(crate) fn noter_en_pause(&self) {
        plus(&self.compteurs.en_pause);
    }

    /// Le relevé pour l'état du veilleur.
    pub(crate) fn releve(&self) -> Releve {
        let c = &self.compteurs;
        let examines = lu(&c.examines);
        let erreur = self
            .erreur
            .lock()
            .ok()
            .and_then(|e| e.clone())
            .or_else(|| fil_arrete(&self.fils, &self.arret));
        Releve {
            actif: erreur.is_none(),
            dossiers: self.dossiers.clone(),
            refuses: self.refuses.clone(),
            sans: erreur,
            a_rallumer: false,
            evenements: lu(&c.evenements),
            examines,
            sains: lu(&c.sains),
            menaces: self.menaces,
            isoles: self.isoles,
            non_verifies: Releve::non_verifies_de(c, self.suites_non_verifiees),
            trop_gros: lu(&c.trop_gros),
            illisibles: lu(&c.illisibles),
            partis: lu(&c.partis),
            file_pleine: lu(&c.file_pleine),
            debordements: lu(&c.debordements),
            defauts: lu(&c.defauts),
            en_pause: lu(&c.en_pause),
            ecartes: lu(&c.ecartes),
            en_cours: lu(&c.en_cours),
            propres: lu(&c.propres),
            remplaces: lu(&c.remplaces),
            perdus: self
                .marques
                .iter()
                .filter(|m| m.perdu.load(Ordering::Relaxed))
                .map(|m| m.nom.clone())
                .collect(),
            latence_max_ms: lu(&c.latence_max_ms),
            latence_moyenne_ms: lu(&c.latence_totale_ms).checked_div(examines).unwrap_or(0),
            sources_kio: c.sources_chargees.load(Ordering::Relaxed).then(|| lu(&c.sources_kio)),
        }
    }
}

/// Un fil sorti sans que l'arrêt soit demandé (une panique, une erreur non prévue) : le temps réel ne tourne plus, et
/// l'état le dit au lieu de compter des dossiers surveillés que plus rien ne lit.
fn fil_arrete(fils: &[JoinHandle<()>], arret: &AtomicBool) -> Option<String> {
    if arret.load(Ordering::SeqCst) {
        return None;
    }
    let fini = fils.iter().find(|f| f.is_finished())?;
    Some(match fini.thread().name() {
        Some("vanguard-fichiers-lecteur") => tr!("lecteur des événements arrêté", "event reader stopped").to_string(),
        Some("vanguard-fichiers-examen") => tr!("examinateur arrêté", "scanner stopped").to_string(),
        _ => tr!("fil arrêté", "thread stopped").to_string(),
    })
}

impl Drop for Surveillance {
    fn drop(&mut self) {
        self.arret.store(true, Ordering::SeqCst);
        self.attente.1.notify_all();
        for f in self.fils.drain(..) {
            let _ = f.join();
        }
    }
}

// ───────────────────────────── Le lecteur ─────────────────────────────

/// Un fichier en cours de téléchargement dans Téléchargements (« x.exe.part ») : renommé à la fin, il sera vu alors.
fn en_cours(m: &Marque, nom: &[u8]) -> bool {
    m.telechargements && crate::protection::telechargement::en_cours(&String::from_utf8_lossy(nom))
}

fn lire(
    groupes: &[Groupe],
    marques: &[Marque],
    arret: &AtomicBool,
    pause: &AtomicBool,
    attente: &(Mutex<Attente>, Condvar),
    compteurs: &Compteurs,
    erreur: &Mutex<Option<String>>,
) {
    let mut tampon = vec![0u8; fanotify::TAMPON];
    let refs: Vec<&Groupe> = groupes.iter().collect();
    let battement = Duration::from_millis(BATTEMENT_MS.unsigned_abs().into());
    let mut suivis_a = Instant::now();
    while !arret.load(Ordering::SeqCst) {
        if suivis_a.elapsed() >= battement {
            suivis_a = Instant::now();
            for (groupe, marque) in groupes.iter().zip(marques) {
                suivre_le_dossier(groupe, marque, compteurs);
            }
        }
        let prets = match fanotify::attendre_groupes(&refs, BATTEMENT_MS) {
            Ok(p) => p,
            Err(e) => {
                if let Ok(mut x) = erreur.lock() {
                    *x = Some(trf!(
                        "erreur de lecture de fanotify ({})",
                        "fanotify read error ({})",
                        crate::ui::affichable(&e.to_string())
                    ));
                }
                return;
            }
        };
        for (i, pret) in prets.into_iter().enumerate() {
            let (Some(groupe), Some(marque)) = (groupes.get(i), marques.get(i)) else {
                continue;
            };
            if !pret {
                continue;
            }
            let Ok(n) = groupe.lire(&mut tampon) else {
                plus(&compteurs.defauts);
                // Une erreur qui dure (le groupe dit prêt, la lecture échoue chaque fois) ferait sinon tourner ce fil
                // à vide, un cœur entier pris : un court repos, et le compte des défauts le dit.
                std::thread::sleep(REPOS_APRES_ERREUR);
                continue;
            };
            let l = lecture::evenements_nommes(tampon.get(..n).unwrap_or_default());
            if l.defaut.is_some() {
                plus(&compteurs.defauts);
            }
            let maintenant = Instant::now();
            let en_pause = pause.load(Ordering::SeqCst);
            let mut nouveau = false;
            for ev in l.evenements {
                plus(&compteurs.evenements);
                match ranger(&ev, marque, en_pause) {
                    Rangement::Compter(compteur) => plus(compteur.de(compteurs)),
                    Rangement::Attendre(nom) => {
                        let ajout = attente
                            .0
                            .lock()
                            .map_or(Ajout::Pleine, |mut a| a.ajouter(i, &nom, maintenant));
                        match ajout {
                            Ajout::Nouveau => nouveau = true,
                            Ajout::Regroupe => {}
                            Ajout::Pleine => plus(&compteurs.file_pleine),
                        }
                    }
                }
            }
            if nouveau {
                attente.1.notify_all();
            }
        }
    }
}

/// Le dossier marqué est-il encore celui qui porte son nom ? Un `mv Téléchargements x` puis un `mkdir
/// Téléchargements` laisse la marque sur l'ancien : le nouveau serait muet. Comparé à chaque battement (dev, inode
/// du descripteur contre ceux du chemin, sans suivre de lien) ; remplacé, il est compté, le nouveau est marqué et
/// l'ancien démarqué ; impossible (supprimé, lien, refusé), le dossier est dit perdu jusqu'à ce qu'il revienne.
fn suivre_le_dossier(groupe: &Groupe, marque: &Marque, compteurs: &Compteurs) {
    let identite = |m: &std::fs::Metadata| (m.dev(), m.ino());
    let actuel = marque
        .fd
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .metadata()
        .map(|m| identite(&m))
        .ok();
    let au_chemin = std::fs::symlink_metadata(&marque.chemin).ok();
    if let (Some(a), Some(c)) = (actuel, au_chemin.as_ref())
        && c.is_dir()
        && identite(c) == a
    {
        return;
    }
    if !marque.perdu.swap(true, Ordering::Relaxed) {
        plus(&compteurs.remplaces);
    }
    if !au_chemin.is_some_and(|c| c.is_dir()) {
        return;
    }
    let Ok(nouveau) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&marque.chemin)
    else {
        return;
    };
    if groupe.marquer_dossier(nouveau.as_fd()).is_err() {
        return;
    }
    let ancien = std::mem::replace(&mut *marque.fd.write().unwrap_or_else(PoisonError::into_inner), nouveau);
    // L'ancien, déplacé ailleurs, ne parle plus : ses noms se liraient sous le nouveau dossier.
    let _ = groupe.retirer_dossier(ancien.as_fd());
    marque.perdu.store(false, Ordering::Relaxed);
}

/// Le compteur d'un événement qui n'est pas examiné.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Compteur {
    Debordement,
    Pause,
    Propre,
    Ecarte,
    EnCours,
    Defaut,
}

impl Compteur {
    fn de(self, c: &Compteurs) -> &AtomicU64 {
        match self {
            Compteur::Debordement => &c.debordements,
            Compteur::Pause => &c.en_pause,
            Compteur::Propre => &c.propres,
            Compteur::Ecarte => &c.ecartes,
            Compteur::EnCours => &c.en_cours,
            Compteur::Defaut => &c.defauts,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Rangement {
    Compter(Compteur),
    Attendre(Vec<u8>),
}

/// Pur, hors `en_cours` : ce que devient un événement lu.
fn ranger(ev: &lecture::Nomme, m: &Marque, en_pause: bool) -> Rangement {
    if ev.masque & fanotify::DEBORDEMENT != 0 {
        return Rangement::Compter(Compteur::Debordement);
    }
    if en_pause {
        return Rangement::Compter(Compteur::Pause);
    }
    // Le noyau ne donne à un groupe sans droits que le PID de ses propres événements : une écriture du veilleur.
    if ev.pid != 0 {
        return Rangement::Compter(Compteur::Propre);
    }
    if ev.masque & fanotify::DOSSIER != 0 {
        return Rangement::Compter(Compteur::Ecarte);
    }
    let Some(nom) = &ev.nom else {
        return Rangement::Compter(Compteur::Defaut);
    };
    if !nom_acceptable(nom) {
        return Rangement::Compter(Compteur::Ecarte);
    }
    if en_cours(m, nom) {
        return Rangement::Compter(Compteur::EnCours);
    }
    Rangement::Attendre(nom.clone())
}

// ───────────────────────────── L'examinateur ─────────────────────────────

/// Ce que l'examinateur partage avec le lecteur et le veilleur.
struct Partage<'a> {
    marques: &'a [Marque],
    arret: &'a AtomicBool,
    pause: &'a AtomicBool,
    attente: &'a (Mutex<Attente>, Condvar),
    compteurs: &'a Compteurs,
    erreur: &'a Mutex<Option<String>>,
}

/// Les sources chargées, ou `None` si leur chargement a paniqué : jamais la mort du veilleur.
type Chargees = Option<(Sources<'static>, Option<crate::protection::empreintes::Empreintes>)>;

fn charger_sans_paniquer(charger: &mut Charger) -> Chargees {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(charger)).ok()
}

fn examiner(mut charger: Charger, p: &Partage<'_>, envoi: &SyncSender<Examine>) {
    let compteurs = p.compteurs;
    let avant = rss_kio();
    let Some((mut base, mut recentes)) = charger_sans_paniquer(&mut charger) else {
        // Rien ne s'examine sans sources : dit « arrêté », jamais sain ; le reste du veilleur continue.
        if let Ok(mut x) = p.erreur.lock() {
            *x = Some(tr!("sources non chargées", "sources not loaded").to_string());
        }
        return;
    };
    if let (Some(a), Some(b)) = (avant, rss_kio()) {
        compteurs.sources_kio.store(b.saturating_sub(a), Ordering::Relaxed);
        compteurs.sources_chargees.store(true, Ordering::Relaxed);
    }
    let mut chargees_a = Instant::now();
    while let Some((i, nom, dernier)) = prochain(p.arret, p.attente) {
        let Some(marque) = p.marques.get(i) else {
            continue;
        };
        if p.pause.load(Ordering::SeqCst) {
            plus(&compteurs.en_pause);
            continue;
        }
        // Les empreintes récentes changent chaque jour : relues de temps en temps ; un rechargement qui échoue garde
        // les sources d'avant.
        if chargees_a.elapsed() >= RELIRE_SOURCES {
            if let Some((b, r)) = charger_sans_paniquer(&mut charger) {
                (base, recentes) = (b, r);
            }
            chargees_a = Instant::now();
        }
        let sources = Sources {
            malwarebazaar: recentes.as_ref(),
            lieu: marque.telechargements.then_some(Lieu::Telechargements),
            manquantes: base.manquantes.clone(),
            reserves: base.reserves.clone(),
            ..base
        };
        let Some((r, identite)) = examiner_un(marque, &nom, &sources, compteurs) else {
            continue;
        };
        let ms = u64::try_from(Instant::now().saturating_duration_since(dernier).as_millis()).unwrap_or(u64::MAX);
        compteurs.latence_max_ms.fetch_max(ms, Ordering::Relaxed);
        let total = lu(&compteurs.latence_totale_ms).saturating_add(ms);
        compteurs.latence_totale_ms.store(total, Ordering::Relaxed);
        match r.verdict() {
            Verdict::Sain => plus(&compteurs.sains),
            Verdict::NonVerifie(_) => plus(&compteurs.non_verifies),
            Verdict::Certain(..) | Verdict::Famille(..) | Verdict::Suspect(_) => {
                let mut x = Examine {
                    chemin: marque.chemin.join(OsStr::from_bytes(&nom)),
                    ou: marque.nom.clone(),
                    resultat: r,
                    identite,
                };
                // Le veilleur prend la suite à son rythme : file pleine, on attend, sans jamais bloquer l'arrêt.
                loop {
                    match envoi.try_send(x) {
                        Ok(()) => break,
                        Err(TrySendError::Full(y)) if !p.arret.load(Ordering::SeqCst) => {
                            x = y;
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    }
}

/// Le prochain fichier prêt, en attendant ; `None` : arrêt demandé.
fn prochain(arret: &AtomicBool, attente: &(Mutex<Attente>, Condvar)) -> Option<(usize, Vec<u8>, Instant)> {
    let mut a = attente.0.lock().ok()?;
    loop {
        if arret.load(Ordering::SeqCst) {
            return None;
        }
        let maintenant = Instant::now();
        if let Some(x) = a.prendre_pret(maintenant) {
            return Some(x);
        }
        let attendre = a
            .prochain(maintenant)
            .unwrap_or(Duration::from_millis(500))
            .clamp(Duration::from_millis(10), Duration::from_millis(500));
        a = attente.1.wait_timeout(a, attendre).ok()?.0;
    }
}

/// Rouvre `nom` sous le dossier marqué, sans suivre aucun lien, et l'examine s'il est un fichier ordinaire de taille
/// bornée ; rend aussi l'identité du fichier lu. `None` : sauté, et compté.
fn examiner_un(m: &Marque, nom: &[u8], sources: &Sources<'_>, c: &Compteurs) -> Option<(Resultat, Identite)> {
    let ouvert = {
        let fd = m.fd.read().unwrap_or_else(PoisonError::into_inner);
        ouvrir::sous(fd.as_fd(), Path::new(OsStr::from_bytes(nom)), false)
    };
    let f = match ouvert {
        Ok(f) => f,
        Err(e) => {
            match e.raw_os_error() {
                Some(libc::ENOENT) => plus(&c.partis),
                // Un lien (RESOLVE_NO_SYMLINKS, O_NOFOLLOW) : rien à lire ici, jamais suivi.
                Some(libc::ELOOP | libc::EXDEV) => plus(&c.ecartes),
                _ => plus(&c.illisibles),
            }
            return None;
        }
    };
    let Ok(meta) = f.metadata() else {
        plus(&c.illisibles);
        return None;
    };
    if !meta.is_file() {
        plus(&c.ecartes);
        return None;
    }
    if meta.len() > TAILLE_MAX {
        plus(&c.trop_gros);
        return None;
    }
    let identite = Identite::de(&meta);
    let chemin = m.chemin.join(OsStr::from_bytes(nom));
    plus(&c.examines);
    let r = moteur::examiner_ouvert(f, &chemin, sources, bornes()).ok();
    if r.is_none() {
        plus(&c.illisibles);
    }
    r.map(|r| (r, identite))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn sources_essai() -> Sources<'static> {
        Sources {
            yara: None,
            malwarebazaar: None,
            clamav: None,
            heuristiques: true,
            lieu: Some(Lieu::Ordinaire),
            normale: |_| false,
            manquantes: Vec::new(),
            reserves: Vec::new(),
        }
    }

    fn elf_marque() -> Vec<u8> {
        let mut elf = crate::protection::heuristiques::corpus::elf_sain();
        elf.extend(crate::protection::sources::marque_d_essai());
        elf
    }

    fn marque(d: &Path, telechargements: bool) -> Marque {
        Marque::nouvelle(
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(d)
                .unwrap(),
            d.to_path_buf(),
            "Salon".into(),
            telechargements,
        )
    }

    /// Un nom venu du noyau : un seul élément, jamais « . », « .. », un « / » ou un NUL ; les octets non UTF-8
    /// restent permis (un nom Linux n'est que des octets).
    #[test]
    fn noms_pieges() {
        assert!(nom_acceptable(b"facture.pdf"));
        assert!(nom_acceptable(b"\xff\xfe-alice.exe"));
        assert!(nom_acceptable(&[b'a'; 255]));
        for n in [
            &b""[..],
            b".",
            b"..",
            b"../x",
            b"a/b",
            b"/etc",
            b"a\0b",
            &[b'a'; 256][..],
        ] {
            assert!(!nom_acceptable(n), "{n:?}");
        }
    }

    /// File bornée : les écritures répétées d'un même fichier sont regroupées ; au-delà du maximum, « pleine » ; un
    /// fichier n'est prêt qu'après le calme, ou au plus tard après l'attente maximale.
    #[test]
    fn file_bornee_et_regroupement() {
        let t0 = Instant::now();
        let mut a = Attente::new(2);
        assert_eq!(a.ajouter(0, b"a", t0), Ajout::Nouveau);
        assert_eq!(a.ajouter(0, b"a", t0 + Duration::from_millis(500)), Ajout::Regroupe);
        assert_eq!(a.ajouter(1, b"a", t0), Ajout::Nouveau, "même nom, autre dossier");
        assert_eq!(a.ajouter(0, b"b", t0), Ajout::Pleine);
        assert_eq!(a.len(), 2);
        // À t0 + 1,2 s : (1, a) est calme, (0, a) a été réécrit à 0,5 s.
        let t = t0 + Duration::from_millis(1200);
        assert_eq!(a.prochain(t), Some(Duration::ZERO));
        assert_eq!(a.prendre_pret(t).map(|x| (x.0, x.1)), Some((1, b"a".to_vec())));
        assert_eq!(a.prendre_pret(t), None);
        assert_eq!(a.prochain(t), Some(Duration::from_millis(300)));
        // Réécrit sans cesse : prêt quand même après ATTENTE_MAX.
        let mut tard = t0;
        for k in 1..=40u64 {
            tard = t0 + Duration::from_millis(k * 900);
            a.ajouter(0, b"a", tard);
            if a.prendre_pret(tard).is_some() {
                break;
            }
        }
        assert!(tard.duration_since(t0) >= ATTENTE_MAX);
        assert!(tard.duration_since(t0) < ATTENTE_MAX + Duration::from_secs(1));
        assert_eq!(a.len(), 0);
        assert_eq!(a.prochain(tard), None);
        assert_eq!(a.ajouter(0, b"c", tard), Ajout::Nouveau);
        assert_eq!(a.vider(), 1);
    }

    /// Le rangement d'un événement : débordement compté, pause comptée, écriture du veilleur jamais examinée,
    /// dossier et nom piégé écartés, fichier en cours de téléchargement attendu à son renommage.
    #[test]
    fn evenements_ranges() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let telech = marque(&d, true);
        let bureau = marque(&d, false);
        let ev = |masque: u64, pid: i32, nom: Option<&[u8]>| lecture::Nomme {
            masque,
            pid,
            nom: nom.map(<[u8]>::to_vec),
        };
        let ecrit = libc::FAN_CLOSE_WRITE;
        assert_eq!(
            ranger(&ev(fanotify::DEBORDEMENT, 0, None), &telech, false),
            Rangement::Compter(Compteur::Debordement)
        );
        assert_eq!(
            ranger(&ev(fanotify::DEBORDEMENT, 0, None), &telech, true),
            Rangement::Compter(Compteur::Debordement),
            "un débordement reste dit, même en pause"
        );
        assert_eq!(
            ranger(&ev(ecrit, 0, Some(b"a.exe")), &telech, true),
            Rangement::Compter(Compteur::Pause)
        );
        assert_eq!(
            ranger(&ev(ecrit, 4242, Some(b"a.exe")), &telech, false),
            Rangement::Compter(Compteur::Propre)
        );
        assert_eq!(
            ranger(
                &ev(libc::FAN_MOVED_TO | fanotify::DOSSIER, 0, Some(b"sous")),
                &telech,
                false
            ),
            Rangement::Compter(Compteur::Ecarte)
        );
        assert_eq!(
            ranger(&ev(ecrit, 0, None), &telech, false),
            Rangement::Compter(Compteur::Defaut)
        );
        assert_eq!(
            ranger(&ev(ecrit, 0, Some(b"../../.bashrc")), &telech, false),
            Rangement::Compter(Compteur::Ecarte)
        );
        assert_eq!(
            ranger(&ev(ecrit, 0, Some(b"x.exe.part")), &telech, false),
            Rangement::Compter(Compteur::EnCours)
        );
        // « .tmp » n'est pas un suffixe de navigateur : n'importe quel programme l'écrit, et il est examiné.
        assert_eq!(
            ranger(&ev(ecrit, 0, Some(b"x.exe.tmp")), &telech, false),
            Rangement::Attendre(b"x.exe.tmp".to_vec())
        );
        // Ailleurs que dans Téléchargements, « .part » ne protège rien : examiné.
        assert_eq!(
            ranger(&ev(ecrit, 0, Some(b"x.exe.part")), &bureau, false),
            Rangement::Attendre(b"x.exe.part".to_vec())
        );
        assert_eq!(
            ranger(&ev(libc::FAN_MOVED_TO, 0, Some(b"\xffalice.exe")), &telech, false),
            Rangement::Attendre(b"\xffalice.exe".to_vec())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L'examen d'un nom : un lien n'est jamais suivi, un tube n'est pas attendu, un fichier trop gros n'est pas lu,
    /// un fichier parti est compté ; un nom non UTF-8 est lu par ses octets ; la marque d'essai dans un exécutable
    /// est certaine.
    #[test]
    fn examen_d_un_nom() {
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let surveille = marque(&dossier, true);
        let sources = sources_essai();
        let compteurs = Compteurs::default();
        std::fs::write(ailleurs.join("cible"), elf_marque()).unwrap();
        std::os::unix::fs::symlink(ailleurs.join("cible"), dossier.join("lien")).unwrap();
        assert!(examiner_un(&surveille, b"lien", &sources, &compteurs).is_none());
        assert_eq!(lu(&compteurs.ecartes), 1);
        crate::essais::tube_nomme(&dossier.join("tube")).unwrap();
        assert!(examiner_un(&surveille, b"tube", &sources, &compteurs).is_none());
        assert_eq!(lu(&compteurs.ecartes), 2);
        let gros = File::create(dossier.join("gros")).unwrap();
        gros.set_len(TAILLE_MAX + 1).unwrap();
        assert!(examiner_un(&surveille, b"gros", &sources, &compteurs).is_none());
        assert_eq!(lu(&compteurs.trop_gros), 1);
        assert!(examiner_un(&surveille, b"parti", &sources, &compteurs).is_none());
        assert_eq!(lu(&compteurs.partis), 1);
        let nom = b"\xfe\xffalice";
        std::fs::write(dossier.join(OsStr::from_bytes(nom)), elf_marque()).unwrap();
        let (r, identite) = examiner_un(&surveille, nom, &sources, &compteurs).unwrap();
        assert!(matches!(r.verdict(), Verdict::Certain(..)), "{:?}", r.verdict());
        // L'identité rendue est celle du fichier lu, sous son nom.
        let lue = std::fs::symlink_metadata(dossier.join(OsStr::from_bytes(nom))).unwrap();
        assert_eq!(identite, Identite::de(&lue));
        assert_eq!(identite.liens, 1);
        std::fs::write(dossier.join("note.txt"), b"Liste du Salon").unwrap();
        assert_eq!(
            examiner_un(&surveille, b"note.txt", &sources, &compteurs)
                .unwrap()
                .0
                .verdict(),
            Verdict::Sain
        );
        assert_eq!(lu(&compteurs.examines), 2);
        let _ = std::fs::remove_dir_all(&dossier);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// Les dossiers : seulement ceux qui existent, chacun une fois (un lien vers un autre de la liste), le chemin
    /// réel, Téléchargements nommé comme tel.
    #[test]
    fn dossiers_candidats() {
        let maison = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::create_dir_all(maison.join("Téléchargements")).unwrap();
        std::fs::create_dir_all(maison.join(".local/bin")).unwrap();
        std::os::unix::fs::symlink(maison.join("Téléchargements"), maison.join("Downloads")).unwrap();
        // Un fichier au nom d'un dossier : écarté.
        std::fs::write(maison.join("Bureau"), b"").unwrap();
        let reel = std::fs::canonicalize(&maison).unwrap();
        let l = candidats(&maison, Some(maison.join("Downloads")));
        assert_eq!(
            l,
            vec![
                (
                    reel.join("Téléchargements"),
                    tr!("Téléchargements", "Downloads").to_string(),
                    true
                ),
                (reel.join(".local/bin"), "~/.local/bin".to_string(), false),
            ]
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// La phrase de l'état : les dossiers, « pas les sous-dossiers », et ce qui n'a pas été vérifié, jamais tu.
    #[test]
    fn phrase_du_releve() {
        let mut r = Releve {
            actif: true,
            dossiers: vec!["~/Salon".into()],
            examines: 3,
            ..Releve::default()
        };
        let p = r.phrase();
        assert!(p.contains("~/Salon"), "{p}");
        // La latence et la taille des sources : montrées, pas seulement écrites dans l'état.
        r.latence_moyenne_ms = 1001;
        r.latence_max_ms = 1500;
        r.sources_kio = Some(30_860);
        let p = r.phrase();
        assert!(p.contains("1001 ms") && p.contains("1500 ms"), "{p}");
        assert!(
            p.contains(tr!("Signatures en mémoire : 31 Mio", "Signatures in memory: 31 MiB")),
            "{p}"
        );
        assert!(!p.contains(tr!("non vérifié", "not verified")), "{p}");
        r.non_verifies = 2;
        r.debordements = 1;
        let p = r.phrase();
        assert!(p.contains(tr!("2 non vérifié", "2 not verified")), "{p}");
        assert!(p.contains(tr!("débordement", "overflow")), "{p}");
        r.sans = Some("noyau".into());
        assert!(r.phrase().contains("noyau"));
        // Un fichier en cours de téléchargement, examiné seulement à son renommage : compté non vérifié, et dit.
        let c = Compteurs::default();
        plus(&c.en_cours);
        plus(&c.trop_gros);
        assert_eq!(Releve::non_verifies_de(&c, 1), 3);
        let r = Releve {
            actif: true,
            non_verifies: Releve::non_verifies_de(&c, 0),
            ..Releve::default()
        };
        assert!(
            r.phrase()
                .contains(tr!("en cours de téléchargement", "still downloading")),
            "{}",
            r.phrase()
        );
    }

    /// Le vrai fanotify, sans droits, sur un dossier jetable seulement : un fichier copié par un autre processus est
    /// vu, examiné et rendu certain ; un fichier arrivé par renommage aussi ; une écriture de ce processus est
    /// comptée « propre », jamais examinée.
    #[test]
    fn vrai_fanotify_dossier_jetable() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        std::fs::write(ailleurs.join("source"), elf_marque()).unwrap();
        // Une écriture de ce processus dans le dossier marqué : comptée propre.
        std::fs::write(d.join("propre.txt"), b"Salon").unwrap();
        let cp = std::process::Command::new("cp")
            .arg(ailleurs.join("source"))
            .arg(d.join("copie.bin"))
            .status()
            .unwrap();
        assert!(cp.success());
        std::fs::write(ailleurs.join("deplace.bin"), elf_marque()).unwrap();
        let mv = std::process::Command::new("mv")
            .arg(ailleurs.join("deplace.bin"))
            .arg(d.join("deplace.bin"))
            .status()
            .unwrap();
        assert!(mv.success());
        let mut vus = Vec::new();
        let fin = Instant::now() + Duration::from_secs(20);
        while vus.len() < 2 && Instant::now() < fin {
            if let Some(x) = s.recevoir() {
                vus.push(x);
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let mut noms: Vec<PathBuf> = vus.iter().map(|x| x.chemin.clone()).collect();
        noms.sort();
        assert_eq!(noms, vec![reel.join("copie.bin"), reel.join("deplace.bin")]);
        for x in &vus {
            assert!(matches!(x.resultat.verdict(), Verdict::Certain(..)));
            assert_eq!(x.ou, "Salon");
        }
        let r = s.releve();
        assert!(r.actif && r.sans.is_none());
        assert_eq!(r.examines, 2, "{r:?}");
        assert!(r.propres >= 1, "{r:?}");
        assert_eq!(r.non_verifies, 0, "{r:?}");
        assert!(r.latence_max_ms >= u64::try_from(CALME.as_millis()).unwrap(), "{r:?}");
        // En pause : rien n'est examiné, tout est compté.
        s.mettre_en_pause(true);
        let cp = std::process::Command::new("cp")
            .arg(ailleurs.join("source"))
            .arg(d.join("pendant-la-pause.bin"))
            .status()
            .unwrap();
        assert!(cp.success());
        let fin = Instant::now() + Duration::from_secs(10);
        while s.releve().en_pause == 0 && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(50));
        }
        let r = s.releve();
        assert_eq!(r.en_pause, 1, "{r:?}");
        assert_eq!(r.examines, 2, "{r:?}");
        assert!(r.non_verifies >= 1);
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// Un dossier marqué remplacé sous son nom (mv puis mkdir, dans un dossier jetable) : compté, dit, et le nouveau
    /// dossier est marqué ; ce qui y arrive ensuite est examiné, ce qui arrive dans l'ancien ne l'est plus. Supprimé
    /// sans retour : dit « plus surveillé », jusqu'à ce qu'il revienne.
    #[test]
    fn dossier_remplace_puis_supprime() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let parent = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&parent).unwrap().join("Salon");
        std::fs::create_dir(&reel).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        let attendre = |fini: &dyn Fn(&Releve) -> bool| {
            let fin = Instant::now() + Duration::from_secs(10);
            while !fini(&s.releve()) && Instant::now() < fin {
                std::thread::sleep(Duration::from_millis(50));
            }
            s.releve()
        };
        let ancien = parent.join("Salon.ancien");
        std::fs::rename(&reel, &ancien).unwrap();
        std::fs::create_dir(&reel).unwrap();
        let r = attendre(&|r| r.remplaces >= 1 && r.perdus.is_empty());
        assert_eq!(r.remplaces, 1, "{r:?}");
        assert!(r.perdus.is_empty(), "{r:?}");
        assert!(r.phrase().contains(tr!("remplacé", "replaced")), "{}", r.phrase());
        // Le nouveau dossier parle ; l'ancien, démarqué, se tait.
        std::fs::write(ailleurs.join("source"), elf_marque()).unwrap();
        for cible in [ancien.join("vieux.bin"), reel.join("neuf.bin")] {
            let cp = std::process::Command::new("cp")
                .arg(ailleurs.join("source"))
                .arg(&cible)
                .status()
                .unwrap();
            assert!(cp.success());
        }
        let mut vus = Vec::new();
        let fin = Instant::now() + Duration::from_secs(10);
        while Instant::now() < fin {
            if let Some(x) = s.recevoir() {
                vus.push(x.chemin);
            } else if !vus.is_empty() {
                // Laisse une chance à un second événement, qui ne doit pas venir.
                std::thread::sleep(Duration::from_millis(2500));
                while let Some(x) = s.recevoir() {
                    vus.push(x.chemin);
                }
                break;
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert_eq!(vus, vec![reel.join("neuf.bin")]);
        // Supprimé sans retour : plus surveillé, et dit.
        std::fs::remove_dir_all(&reel).unwrap();
        let r = attendre(&|r| !r.perdus.is_empty());
        assert_eq!(r.perdus, vec!["Salon".to_string()], "{r:?}");
        assert_eq!(r.remplaces, 2, "{r:?}");
        assert!(
            r.phrase().contains(tr!("plus surveillé", "no longer watched")),
            "{}",
            r.phrase()
        );
        // Revenu : marqué de nouveau.
        std::fs::create_dir(&reel).unwrap();
        let r = attendre(&|r| r.perdus.is_empty());
        assert!(r.perdus.is_empty(), "{r:?}");
        assert_eq!(r.remplaces, 2, "{r:?}");
        drop(s);
        let _ = std::fs::remove_dir_all(&parent);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// Un chargement des sources qui panique (mémoire, base illisible) : « sources non chargées », dit à l'état ;
    /// le fil meurt seul, la surveillance et le veilleur restent, et l'arrêt se fait sans attendre.
    #[test]
    fn sources_non_chargees_sans_mourir() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel, "Salon".into(), false)],
            Box::new(|| panic!("essai : chargement des sources en échec")),
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        let fin = Instant::now() + Duration::from_secs(10);
        while s.releve().sans.is_none() && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(20));
        }
        let r = s.releve();
        assert_eq!(
            r.sans.as_deref(),
            Some(tr!("sources non chargées", "sources not loaded")),
            "{r:?}"
        );
        assert!(!r.actif);
        assert!(r.phrase().contains(tr!("sources non chargées", "sources not loaded")));
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fil mort sans arrêt demandé (ici, une panique) se voit dans l'état ; l'arrêt demandé, lui, n'est pas une
    /// panne.
    #[test]
    fn fil_mort_dit_arrete() {
        let mort = std::thread::Builder::new()
            .name("vanguard-fichiers-examen".into())
            .spawn(|| panic!("essai : l'examinateur meurt"))
            .unwrap();
        let (tenir, attendre) = mpsc::channel::<()>();
        let vivant = std::thread::Builder::new()
            .name("vanguard-fichiers-lecteur".into())
            .spawn(move || {
                let _ = attendre.recv();
            })
            .unwrap();
        let fils = vec![vivant, mort];
        let fin = Instant::now() + Duration::from_secs(10);
        while !fils[1].is_finished() && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(10));
        }
        let arret = AtomicBool::new(false);
        assert_eq!(
            fil_arrete(&fils, &arret).as_deref(),
            Some(tr!("examinateur arrêté", "scanner stopped"))
        );
        arret.store(true, Ordering::SeqCst);
        assert_eq!(fil_arrete(&fils, &arret), None);
        arret.store(false, Ordering::SeqCst);
        assert_eq!(fil_arrete(&fils[..1], &arret), None);
        drop(tenir);
        for f in fils {
            let _ = f.join();
        }
    }
}
