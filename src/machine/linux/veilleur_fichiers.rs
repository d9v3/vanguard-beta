//! Le temps réel des fichiers (Linux, sans droits) : les dossiers du compte où arrivent les menaces (Téléchargements,
//! Bureau, ~/.local/bin, ~/.config/autostart : ceux de l'analyse « Rapide », `antivirus::ENDROITS_A_RISQUE`) sont
//! marqués par fanotify, et chaque fichier qui y est fermé après écriture ou qui y arrive par renommage est relu et
//! jugé par le moteur de Vanguard (`moteur::examiner_ouvert`), puis suivi par le blocage (`blocage::en_direct`).
//!
//! Sans droits (Linux 5.13 et plus) : un groupe de NOTIFICATION (FAN_CLASS_NOTIF), qui ne retient jamais rien ;
//! l'identification par dossier et nom (FAN_REPORT_DFID_NAME), la seule permise, sans descripteur ouvert par le noyau ;
//! des marques d'INODE seulement. Une marque d'inode ne voit que les enfants DIRECTS du dossier marqué : ni ses
//! sous-dossiers, ni un autre dossier, ni un fichier lancé sans être écrit ici. Ce qui y est arrivé sans être vu
//! (file pleine, débordement du noyau, arrêt du veilleur, pause) est repris par une RELECTURE du dossier (`relire`) :
//! un nom perdu par file pleine est repris tel quel ; un débordement ou un défaut fait relire tout le dossier, sauf
//! ce qui a déjà été examiné sain tel quel (inode et ctime) ; au démarrage et après une pause, les fichiers changés
//! depuis le dernier moment où le temps réel était à jour (sept jours au plus ; la passe horaire reprend aussi ceux de
//! la semaine, `menaces::telecharges`). Le ctime (que personne ne règle à la main) date de la dernière ÉCRITURE, pas
//! de la fermeture : un fichier écrit avant l'arrêt du veilleur et fermé pendant lui échappe à la relecture du
//! démarrage ; la passe horaire reste le filet. Un groupe par dossier : le dossier de chaque
//! événement est celui du groupe, sans `open_by_handle_at` (réservé à root) ; le chemin est refait comme dossier +
//! nom, et le fichier est rouvert SOUS le descripteur du dossier, sans suivre aucun lien, fichier ordinaire seulement.
//! Le verdict porte sur le contenu lu, jamais sur le nom.
//!
//! Deux fils : le lecteur lit les événements et les range dans une file bornée (les écritures répétées d'un même
//! fichier y sont regroupées) ; l'examinateur prend chaque fichier une fois le calme revenu, et rend ses menaces au
//! veilleur, qui décide du débit des alertes et de la suite. Ce qui est sauté (trop gros, illisible, parti avant
//! lecture, pause) est compté et dit non vérifié, jamais sain ; une perte (file pleine, débordement) reste dite tant
//! que la relecture de son dossier n'est pas finie, et le bilan la compte comme un problème. Les écritures du
//! veilleur lui-même (le noyau ne donne le PID que des siennes) ne sont jamais examinées.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::OsStr;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
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
/// Les places de la file gardées aux événements en direct : une relecture ne prend que le reste.
const RESERVE_DIRECT: usize = FILE_MAX / 4;
/// Une relecture d'un même dossier au plus à ce rythme (et seulement si la file a de la place).
const RYTHME_RELECTURE: Duration = Duration::from_secs(2);
/// Un dossier de plus d'entrées n'est pas relu (chaque relecture les lirait toutes) : dit, et réessayé à ce rythme.
const LISTE_MAX: usize = 50_000;
const RYTHME_TROP_GRAND: Duration = Duration::from_mins(1);
/// Une relecture qui n'a pas pu avancer depuis ce temps (la file tenue pleine par une rafale qui dure) prend aussi les
/// places gardées au direct : une rafale sans fin ne retarde pas la reprise sans fin.
const FAMINE: Duration = Duration::from_secs(30);
/// Moins de fichiers que ça mis en file par passe : la relecture est dite lente, et compte vers la famine (une place
/// libre par passe ne la remet pas à zéro).
const PASSE_LENTE: u64 = 16;
/// Un dossier trop grand pour être listé, avec une perte : réessayé ce nombre de fois (une par minute), puis
/// abandonné et dit.
const ESSAIS_TROP_GRAND: u32 = 3;
/// Une perte abandonnée (dossier trop grand) est retentée à ce rythme : le dossier a pu redevenir listable.
const REESSAI_ABANDON: Duration = Duration::from_hours(1);
/// Un fichier examiné il y a moins que ça n'est pas sauté par une relecture : une écriture par projection partagée
/// (mmap) change le contenu sans changer le ctime ; seule l'écriture suivante le change. La fenêtre ne couvre que
/// les relectures proches de l'examen ; au-delà, le filet est la fermeture de la dernière référence et la passe
/// horaire.
const FENETRE_MMAP: Duration = Duration::from_secs(60);
/// Les noms perdus (file pleine) retenus par dossier ; au-delà, tout le dossier est relu.
const NOMS_PERDUS_MAX: usize = 4096;
/// Les fichiers examinés retenus par dossier (nom, inode, ctime) : une relecture ne réexamine pas un fichier qui n'a
/// pas changé depuis. Au-delà, la mémoire repart à vide (des réexamens, jamais un oubli).
const MEMOIRE_MAX: usize = 4096;
/// La marge prise en arrière d'une perte, en secondes : un fichier écrit juste avant l'événement perdu, l'examen en
/// cours au moment d'un arrêt, une horloge un peu décalée.
pub(crate) const MARGE_RELECTURE: i64 = 120;
/// Au démarrage, la relecture ne remonte jamais plus loin (en secondes) : sept jours, ceux de la passe horaire.
pub(crate) const RELECTURE_MAX: i64 = 7 * 24 * 3600;
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
    /// Depuis quand (secondes depuis 1970) ce fichier attend d'être examiné : l'événement, ou le ctime d'un fichier
    /// repris par une relecture. Tant qu'il est en file, le temps réel n'est pas à jour au-delà.
    depuis: i64,
    /// Venu d'un événement direct (pas d'une relecture) : compte pour la famine (voir `suivre_famine`).
    direct: bool,
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

    /// Pour les essais : un ajout dont le moment d'origine est maintenant.
    #[cfg(test)]
    pub(crate) fn ajouter(&mut self, dossier: usize, nom: &[u8], quand: Instant) -> Ajout {
        self.ajouter_depuis(dossier, nom, quand, secondes())
    }

    /// `ajouter`, avec le moment d'où le fichier attend (`Entree::depuis`).
    fn ajouter_depuis(&mut self, dossier: usize, nom: &[u8], quand: Instant, depuis: i64) -> Ajout {
        self.ajouter_entree(dossier, nom, quand, depuis, false)
    }

    /// Un ajout venu d'un événement direct.
    fn ajouter_direct(&mut self, dossier: usize, nom: &[u8], quand: Instant, depuis: i64) -> Ajout {
        self.ajouter_entree(dossier, nom, quand, depuis, true)
    }

    fn ajouter_entree(&mut self, dossier: usize, nom: &[u8], quand: Instant, depuis: i64, direct: bool) -> Ajout {
        if let Some(e) = self.file.iter_mut().find(|e| e.dossier == dossier && e.nom == nom) {
            e.dernier = e.dernier.max(quand);
            e.depuis = e.depuis.min(depuis);
            e.direct |= direct;
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
            depuis,
            direct,
        });
        Ajout::Nouveau
    }

    /// Le premier fichier prêt (calme depuis `CALME`, ou en attente depuis `ATTENTE_MAX`) : (dossier, nom, dernière
    /// écriture).
    pub(crate) fn prendre_pret(&mut self, maintenant: Instant) -> Option<(usize, Vec<u8>, Instant, i64)> {
        let i = self.file.iter().position(|e| pret(e, maintenant))?;
        self.file.remove(i).map(|e| (e.dossier, e.nom, e.dernier, e.depuis))
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

    /// Le plus ancien moment d'où un fichier en file attend (`Entree::depuis`) ; `None` : file vide.
    fn plus_ancien(&self) -> Option<i64> {
        self.file.iter().map(|e| e.depuis).min()
    }

    /// Vide la file ; rend chaque dossier et nom qui y attendait.
    fn vider(&mut self) -> Vec<(usize, Vec<u8>)> {
        self.file.drain(..).map(|e| (e.dossier, e.nom)).collect()
    }

    /// Les événements directs en file tiennent-ils une bonne part de la réserve ? Sinon, une relecture lente ne
    /// l'est pas à cause du temps réel, et n'a pas à lui prendre ses places.
    fn direct_presse(&self) -> bool {
        self.file.iter().filter(|e| e.direct).count() >= RESERVE_DIRECT / 2
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
    /// Les fichiers mis en file par une relecture de dossier.
    pub repris: AtomicU64,
    /// Le fichier en cours d'examen attend depuis ce moment (`Entree::depuis`) ; 0 : aucun. Changé sous le verrou de
    /// la file : un fichier sorti de la file pour l'examen compte toujours quelque part.
    pub en_examen_depuis: AtomicI64,
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

/// Pourquoi le filtre d'appels système a coupé le temps réel des fichiers (`veilleur::fanotify_permis`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Coupure {
    /// La sonde n'a pas pu tourner (la raison du système, telle quelle).
    NonVerifie(String),
    /// Interdit, et l'unité du veilleur absente ou illisible.
    UniteAbsente,
    /// Interdit par une unité qui n'est pas celle de Vanguard.
    UniteEtrangere,
    /// L'unité posée permet fanotify, mais le filtre en vigueur non.
    PasRechargee,
    /// L'unité posée vient d'une version d'avant.
    VersionAvant,
}

impl Coupure {
    /// La cause, dans la langue de qui la lit.
    pub(crate) fn cause(&self) -> String {
        match self {
            Coupure::NonVerifie(r) => {
                let r = crate::ui::affichable(r);
                trf!(
                    "fanotify non essayé : la sonde du filtre d'appels système n'a pas pu tourner ({r}) ; « vanguard veilleur on » le relance",
                    "fanotify not tried: the system call filter probe could not run ({r}); “vanguard watcher on” restarts it"
                )
            }
            Coupure::UniteAbsente => tr!(
                "un filtre d'appels système interdit fanotify à ce processus, et l'unité du veilleur est absente ou illisible ; « vanguard veilleur on » la pose",
                "a system call filter forbids fanotify to this process, and the watcher unit is missing or unreadable; “vanguard watcher on” puts it in place"
            )
            .to_string(),
            Coupure::UniteEtrangere => tr!(
                "l'unité posée n'est pas celle de Vanguard et son filtre d'appels système interdit fanotify",
                "the unit in place is not Vanguard's and its system call filter forbids fanotify"
            )
            .to_string(),
            Coupure::PasRechargee => tr!(
                "l'unité posée permet fanotify, mais le filtre en vigueur l'interdit (unité pas rechargée, ou un ajout local) ; « vanguard veilleur on » la recharge",
                "the unit in place allows fanotify, but the filter in force forbids it (unit not reloaded, or a local addition); “vanguard watcher on” reloads it"
            )
            .to_string(),
            Coupure::VersionAvant => tr!(
                "l'unité posée vient d'une version d'avant et ne permet pas fanotify ; « vanguard veilleur on » la remet à jour, un seul accord",
                "the unit in place comes from an earlier version and does not allow fanotify; “vanguard watcher on” updates it, one consent"
            )
            .to_string(),
        }
    }
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
    /// le dit comme un problème, avec « vanguard veilleur on ». Gardée en code, pas en texte : l'écran la dit dans SA
    /// langue, même quand le service tourne dans une autre (une unité d'avant, sans VANGUARD_LANG).
    pub coupure: Option<Coupure>,
    pub evenements: u64,
    pub examines: u64,
    pub sains: u64,
    /// Menaces rendues au veilleur (certain, famille, suspect).
    pub menaces: u64,
    /// Mis en quarantaine tout seuls.
    pub isoles: u64,
    /// Tout ce qui n'a pas pu être vérifié : verdict non vérifié, trop gros, illisible, parti, pause, en cours de
    /// téléchargement. Une perte (file pleine, débordement) n'en est pas : elle est dans `a_reprendre` tant que la
    /// relecture de son dossier n'est pas finie.
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
    /// Les dossiers en cours de relecture (perte, démarrage, fin de pause), prêts à montrer.
    pub relectures: Vec<String>,
    /// Les dossiers trop grands pour être relus (plus de `LISTE_MAX` entrées) : leur relecture ne finit pas.
    pub trop_grands: Vec<String>,
    /// Les dossiers trop grands dont une perte n'a pas pu être reprise (relecture abandonnée après quelques essais) :
    /// ce qui y est arrivé sans être vu n'est pas examiné, jusqu'à une relecture complète réussie.
    pub abandons: Vec<String>,
    /// Les chemins de ces dossiers, dans le même ordre : ce qui est gardé au redémarrage (le nom montré change avec
    /// la langue, et un dossier refusé au démarrage n'a pas de marque).
    pub abandons_chemins: Vec<PathBuf>,
    /// Les pertes (fichier sans place dans la file, débordement du noyau, tampon perdu) que les relectures en cours
    /// n'ont pas encore reprises : ce qui y est arrivé n'est pas encore relu.
    pub a_reprendre: u64,
    /// Les fichiers mis en file par une relecture, en tout.
    pub repris: u64,
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
            lu(&c.en_pause),
            lu(&c.en_cours),
            suites,
        ]
        .iter()
        .fold(0u64, |a, b| a.saturating_add(*b))
    }

    /// Ce que l'alerte horaire du veilleur compte : les fichiers non vérifiés, sauf ceux en cours de téléchargement
    /// (examinés à leur renommage final, et un téléchargement long en ferait une alerte par heure) et ceux de la
    /// pause (voulue, et déjà dite) ; plus les pertes pas encore reprises par une relecture (une perte reprise a été
    /// examinée : le compte redescend).
    pub(crate) fn a_signaler(&self) -> u64 {
        self.non_verifies
            .saturating_sub(self.en_cours)
            .saturating_sub(self.en_pause)
            .saturating_add(self.a_reprendre)
            .saturating_add(u64::try_from(self.abandons.len()).unwrap_or(u64::MAX))
    }

    /// Des fichiers arrivés sans être vus ne sont pas encore examinés (pertes à reprendre) : le bilan le compte comme
    /// un problème, pas comme une remarque. Un dossier trop grand pour la relecture du démarrage, sans perte, n'est
    /// pas un problème (un Téléchargements de 60 000 fichiers ne doit pas tenir le bilan en alerte à chaque
    /// démarrage), seulement non vérifié (`incomplet`) ; avec une perte, il est compté ici, même abandonné.
    pub(crate) fn en_retard(&self) -> bool {
        self.a_reprendre > 0 || !self.abandons.is_empty()
    }

    /// Une partie de ce qui est arrivé n'a pas été relue (une perte pas reprise, ou un dossier trop grand pour être
    /// relu) : le bilan ne la dit pas vérifiée.
    pub(crate) fn incomplet(&self) -> bool {
        self.en_retard() || !self.trop_grands.is_empty()
    }

    /// La phrase de l'état, pour le constat du veilleur et le menu.
    pub(crate) fn phrase(&self) -> String {
        if let Some(c) = &self.coupure {
            let sans = c.cause();
            return trf!(
                "Temps réel des fichiers : arrêté ({sans}).",
                "Real-time file scanning: stopped ({sans})."
            );
        }
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
                "{} non vérifié(s) (trop gros, illisibles, partis, en pause, ou en cours de téléchargement et examinés seulement à leur renommage final) : jamais comptés sains.",
                "{} not verified (too large, unreadable, gone, paused, or still downloading and scanned only at their final rename): never counted as clean.",
                self.non_verifies
            ));
        }
        let pertes = self
            .file_pleine
            .saturating_add(self.debordements)
            .saturating_add(self.defauts);
        if pertes > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "{} perte(s) (file pleine ou débordement du noyau) : chaque fois, le dossier est relu et ce qui y a changé remis en file ; ce qui n'est pas encore repris est dit ci-dessous.",
                "{} loss(es) (queue full or kernel overflow): each time, the folder is read again and what changed there queued again; what is not picked up yet is stated below.",
                pertes
            ));
        }
        if !self.relectures.is_empty() {
            t.push(' ');
            let dossiers = self.relectures.join(", ");
            if self.a_reprendre > 0 {
                t.push_str(&trf!(
                    "Relecture en cours ({dossiers}) : {} perte(s) pas encore reprise(s), ce qui est arrivé là n'est pas encore relu en entier, jamais compté sain.",
                    "Reading again ({dossiers}): {} loss(es) not yet picked up, what arrived there is not fully read again yet, never counted as clean.",
                    self.a_reprendre
                ));
            } else {
                t.push_str(&trf!(
                    "Relecture en cours ({dossiers}) : les fichiers arrivés pendant l'arrêt ou la pause (sept jours au plus) sont examinés.",
                    "Reading again ({dossiers}): the files that arrived while stopped or paused (seven days at most) are being scanned."
                ));
            }
        }
        if !self.trop_grands.is_empty() {
            t.push(' ');
            t.push_str(&trf!(
                "Trop d'entrées pour être relu(s) : {} ; ce qui y est arrivé pendant un arrêt ou sans être vu n'est pas relu, « vanguard audit » fait un bilan complet.",
                "Too many entries to be read again: {}; what arrived there while stopped or unseen is not read again, “vanguard audit” runs a full check.",
                self.trop_grands.join(", ")
            ));
        }
        if !self.abandons.is_empty() {
            t.push(' ');
            t.push_str(&trf!(
                "Perte pas reprise, dossier trop grand : {} ; des fichiers y sont arrivés sans être vus ni examinés.",
                "Loss not picked up, folder too large: {}; files arrived there without being seen or scanned.",
                self.abandons.join(", ")
            ));
        }
        if self.repris > 0 {
            t.push(' ');
            t.push_str(&trf!(
                "{} fichier(s) repris par relecture.",
                "{} file(s) picked up by reading again.",
                self.repris
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
    /// La relecture à faire, et celles demandées pendant qu'une lecture du dossier tourne.
    relecture: Mutex<Relecture>,
    /// Les pertes depuis le début de la relecture en cours, remises à zéro quand elle finit (sous le verrou de
    /// `relecture`).
    a_reprendre: AtomicU64,
    /// Les fichiers examinés (sains, non vérifiés, trop gros : pas les menaces), leur état d'alors (inode, ctime) et
    /// le moment de l'examen : une relecture saute ceux qui n'ont pas changé.
    examines: Mutex<HashMap<Vec<u8>, Note>>,
    /// Plus de `LISTE_MAX` entrées à la dernière relecture : elle ne peut pas finir.
    trop_grand: AtomicBool,
    /// Les essais de relecture d'un dossier trop grand avec une perte, depuis la dernière liste réussie.
    essais_trop_grand: AtomicU32,
    /// Une perte abandonnée parce que le dossier est trop grand : ce qui y est arrivé n'est pas repris. Effacé par
    /// une relecture complète réussie.
    perte_abandonnee: AtomicBool,
    /// Le moment du dernier abandon d'une perte : retentée après `REESSAI_ABANDON` (`None` : tout de suite).
    abandon_a: Mutex<Option<Instant>>,
}

/// L'état de la relecture d'un dossier.
#[derive(Debug, Default)]
struct Relecture {
    /// Les fichiers changés après ce curseur sont à relire ; `None` : le dossier est à jour.
    curseur: Option<Curseur>,
    /// Une lecture du dossier tourne (`relire`, hors du verrou) : une demande arrivée pendant elle va dans `pendant`,
    /// sinon la fin de cette lecture l'effacerait.
    en_lecture: bool,
    /// Le plus ancien point demandé pendant la lecture en cours.
    pendant: Option<Curseur>,
    /// Les noms perdus (file pleine) : relus quel que soit leur ctime (un fichier écrit, gardé ouvert, fermé
    /// pendant une rafale a un ctime plus ancien que la perte).
    noms: BTreeSet<Vec<u8>>,
    /// Une perte sans nom (débordement, défaut, trop de noms) attend : la relecture doit lister le dossier, un
    /// dossier trop grand n'est pas abandonné tout de suite. Effacé quand le curseur l'est.
    perte_sans_nom: bool,
}

/// Le plus ancien des deux points (`None` : aucun).
fn plus_ancien(a: Option<Curseur>, b: Curseur) -> Curseur {
    a.map_or(b.clone(), |a| a.min(b))
}

/// Où en est la relecture d'un dossier : le changement (ctime, secondes et nanosecondes), puis le nom, du dernier
/// fichier mis en file. Seuls les fichiers APRÈS lui sont pris : chaque relecture avance, même à ctime égal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Curseur {
    s: i64,
    ns: i64,
    nom: Vec<u8>,
}

impl Curseur {
    /// Tous les fichiers changés à partir de la seconde `s` (un nom n'est jamais vide).
    fn depuis(s: i64) -> Curseur {
        Curseur {
            s,
            ns: 0,
            nom: Vec::new(),
        }
    }
}

/// Le moment présent, en secondes depuis 1970 (l'horloge de ctime).
fn secondes() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

impl Marque {
    fn nouvelle(fd: File, chemin: PathBuf, nom: String, telechargements: bool) -> Marque {
        Marque {
            fd: RwLock::new(fd),
            chemin,
            nom,
            telechargements,
            perdu: AtomicBool::new(false),
            relecture: Mutex::new(Relecture::default()),
            a_reprendre: AtomicU64::new(0),
            examines: Mutex::new(HashMap::new()),
            trop_grand: AtomicBool::new(false),
            essais_trop_grand: AtomicU32::new(0),
            perte_abandonnee: AtomicBool::new(false),
            abandon_a: Mutex::new(None),
        }
    }

    /// Le dossier est à relire à partir de la seconde `s` : le plus ancien des deux points l'emporte (une perte ne
    /// fait jamais avancer une relecture en cours).
    fn relire_depuis(&self, s: i64) {
        self.relecture
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .demander(Curseur::depuis(s));
    }

    /// Une perte dont on ne connaît pas les noms (débordement du noyau, tampon illisible) : tout le dossier est relu,
    /// quel que soit le ctime ; la mémoire des examens évite de tout réexaminer.
    fn perte(&self) {
        let mut r = self.relecture.lock().unwrap_or_else(PoisonError::into_inner);
        r.demander(Curseur::depuis(i64::MIN));
        // Comptée une fois tant qu'elle attend : une panne qui dure ne la gonfle pas.
        if !r.perte_sans_nom {
            r.perte_sans_nom = true;
            self.essais_trop_grand.store(0, Ordering::Relaxed);
            plus(&self.a_reprendre);
        }
    }

    /// Un nom retiré de la file sans examen (pause) : repris tel quel, sans lister le dossier ; pas une perte, tant
    /// que la liste des noms a de la place.
    fn reprendre_nom(&self, nom: &[u8]) {
        let mut r = self.relecture.lock().unwrap_or_else(PoisonError::into_inner);
        if r.noms.contains(nom) {
            return;
        }
        if r.noms.len() < NOMS_PERDUS_MAX {
            r.noms.insert(nom.to_vec());
            return;
        }
        drop(r);
        self.nom_perdu(nom);
    }

    /// Une perte abandonnée depuis `REESSAI_ABANDON` : redemandée (le dossier a pu redevenir listable). Vrai : elle
    /// l'a été.
    fn relancer_abandon(&self, maintenant: Instant) -> bool {
        if !self.perte_abandonnee.load(Ordering::Relaxed) || self.en_relecture() {
            return false;
        }
        let mut quand = self.abandon_a.lock().unwrap_or_else(PoisonError::into_inner);
        if quand.is_some_and(|a| maintenant.saturating_duration_since(a) < REESSAI_ABANDON) {
            return false;
        }
        *quand = None;
        drop(quand);
        self.perte();
        true
    }

    /// Un fichier sans place dans la file : son nom est gardé et relu tel quel ; trop de noms, tout le dossier.
    fn nom_perdu(&self, nom: &[u8]) {
        let mut r = self.relecture.lock().unwrap_or_else(PoisonError::into_inner);
        if r.noms.contains(nom) {
            return;
        }
        if r.noms.len() >= NOMS_PERDUS_MAX {
            r.demander(Curseur::depuis(i64::MIN));
            if r.perte_sans_nom {
                return;
            }
            r.perte_sans_nom = true;
            self.essais_trop_grand.store(0, Ordering::Relaxed);
        } else {
            r.noms.insert(nom.to_vec());
        }
        plus(&self.a_reprendre);
    }

    fn en_relecture(&self) -> bool {
        let r = self.relecture.lock().unwrap_or_else(PoisonError::into_inner);
        r.curseur.is_some() || !r.noms.is_empty()
    }

    /// Note un fichier examiné au verdict définitif (sain, trop gros), avec son état d'alors.
    fn noter_examine(&self, nom: &[u8], meta: &std::fs::Metadata) {
        self.noter_examine_a(nom, meta, Instant::now(), true);
    }

    /// Note un fichier non vérifié ou illisible : sauté par les relectures un temps seulement, sinon un attaquant qui
    /// provoque des pertes à volonté ferait réexaminer sans fin des fichiers lents (délai dépassé), et le temps réel
    /// attendrait derrière eux ; mais réexaminé plus tard, car la cause peut passer.
    fn noter_passager(&self, nom: &[u8], meta: &std::fs::Metadata) {
        self.noter_examine_a(nom, meta, Instant::now(), false);
    }

    fn noter_examine_a(&self, nom: &[u8], meta: &std::fs::Metadata, quand: Instant, definitif: bool) {
        let mut x = self.examines.lock().unwrap_or_else(PoisonError::into_inner);
        if x.len() >= MEMOIRE_MAX && !x.contains_key(nom) {
            x.clear();
        }
        x.insert(
            nom.to_vec(),
            ((meta.ino(), meta.ctime(), meta.ctime_nsec()), quand, definitif),
        );
    }

    /// Les sources du moteur sont rechargées : ce qui n'a pas pu être vérifié mérite un nouvel examen.
    fn oublier_passagers(&self) {
        self.examines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, (_, _, definitif)| *definitif);
    }

    /// Ce fichier a-t-il été examiné tel qu'il est (même inode, même ctime) ? Une écriture, un renommage ou un
    /// changement de droits changent le ctime, qu'un programme sans droits ne remet pas en arrière.
    /// Pas dans la minute qui suit l'examen (voir `FENETRE_MMAP`).
    fn deja_examine(&self, nom: &[u8], meta: &std::fs::Metadata) -> bool {
        self.examines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(nom)
            .is_some_and(|(x, quand, definitif)| {
                *x == (meta.ino(), meta.ctime(), meta.ctime_nsec())
                    && quand.elapsed() >= FENETRE_MMAP
                    && (*definitif || quand.elapsed() < RELIRE_SOURCES)
            })
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
    /// Le début de la pause en cours (secondes depuis 1970) : à sa fin, chaque dossier est relu depuis lui.
    pause_debut: AtomicI64,
    /// Les pertes abandonnées d'avant le redémarrage dont le dossier n'est pas marqué cette fois : toujours dites.
    abandons_anciens: Vec<(String, PathBuf)>,
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
    /// les sources du moteur, chargées une fois dans le fil de l'examinateur. `relire_depuis` (secondes depuis 1970) :
    /// chaque dossier est relu pour les fichiers changés depuis ce moment, arrivés pendant que rien ne les voyait.
    /// Erreur : rien n'est surveillé, et pourquoi (prêt à montrer) ; les dossiers refusés un à un sont dits dans le
    /// relevé.
    pub(crate) fn demarrer(
        dossiers: Vec<(PathBuf, String, bool)>,
        charger: Charger,
        relire_depuis: Option<i64>,
    ) -> Result<Surveillance, Refus> {
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
            let m = Marque::nouvelle(fd, chemin, nom, telechargements);
            // Après la marque : ce qui arrive ensuite est vu en direct, ce qui était là avant est relu.
            if let Some(s) = relire_depuis {
                m.relire_depuis(s);
            }
            marques.push(m);
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
            pause_debut: AtomicI64::new(0),
            abandons_anciens: Vec::new(),
        })
    }

    /// Les pertes abandonnées d'avant un redémarrage (dossiers trop grands, gardés dans l'état) : toujours dites,
    /// et retentées dès que le dossier n'est plus en relecture ; sinon l'alerte s'oublierait à chaque redémarrage.
    /// Un dossier qui n'est pas marqué cette fois garde son alerte telle quelle.
    pub(crate) fn reprendre_abandons(&mut self, noms: &[String], chemins: &[PathBuf]) {
        for (nom, chemin) in noms.iter().zip(chemins) {
            if let Some(m) = self.marques.iter().find(|m| m.chemin == *chemin) {
                m.perte_abandonnee.store(true, Ordering::Relaxed);
                *m.abandon_a.lock().unwrap_or_else(PoisonError::into_inner) = None;
            } else if !self.abandons_anciens.iter().any(|(_, c)| c == chemin) {
                self.abandons_anciens.push((nom.clone(), chemin.clone()));
            }
        }
    }

    /// Met en pause (coupure du temps réel) ou reprend : en pause, ce qui arrive est compté non vérifié, jamais
    /// examiné ; ce qui attendait dans la file est gardé par son nom ; à la reprise, ces noms sont repris et chaque
    /// dossier est relu depuis le début de la pause.
    pub(crate) fn mettre_en_pause(&self, pause: bool) {
        let avant = self.pause.swap(pause, Ordering::SeqCst);
        if pause && !avant {
            self.pause_debut.store(secondes(), Ordering::SeqCst);
        }
        if !pause && avant {
            // Sept jours au plus, comme au démarrage : au-delà, la passe complète reste le filet.
            let debut = self
                .pause_debut
                .load(Ordering::SeqCst)
                .saturating_sub(MARGE_RELECTURE)
                .max(secondes().saturating_sub(RELECTURE_MAX));
            for m in self.marques.iter() {
                m.relire_depuis(debut);
            }
        }
        if pause && let Ok(mut a) = self.attente.0.lock() {
            // Ce qui attendait (venu d'une relecture, son ctime peut être bien plus ancien que la pause) n'est pas
            // jeté : repris par son nom à la reprise, même dans un dossier trop grand pour être listé.
            rendre_a_la_relecture(&self.marques, a.vider());
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

    /// Jusqu'où (secondes depuis 1970) tout ce qui est arrivé dans les dossiers a été vu et mis en file : le
    /// prochain démarrage relit à partir de là. `None` : pas à jour (pause, relecture en cours), le point d'avant
    /// reste. La file compte : un fichier en attente n'est pas encore examiné.
    pub(crate) fn vu_jusqu_a(&self) -> Option<i64> {
        if self.pause.load(Ordering::SeqCst) || self.marques.iter().any(Marque::en_relecture) {
            return None;
        }
        // Sous le verrou de la file : un fichier passe de la file à l'examen sous lui, il est compté d'un côté ou
        // de l'autre, jamais entre les deux.
        let a = self.attente.0.lock().ok()?;
        let examen = self.compteurs.en_examen_depuis.load(Ordering::SeqCst);
        let mut point = secondes();
        if let Some(d) = a.plus_ancien() {
            point = point.min(d);
        }
        if examen != 0 {
            point = point.min(examen);
        }
        Some(point)
    }

    /// Le relevé pour l'état du veilleur.
    pub(crate) fn releve(&self) -> Releve {
        let c = &self.compteurs;
        let abandons: Vec<(String, PathBuf)> = self
            .marques
            .iter()
            .filter(|m| m.perte_abandonnee.load(Ordering::Relaxed))
            .map(|m| (m.nom.clone(), m.chemin.clone()))
            .chain(self.abandons_anciens.iter().cloned())
            .collect();
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
            coupure: None,
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
            relectures: self
                .marques
                .iter()
                .filter(|m| m.en_relecture())
                .map(|m| m.nom.clone())
                .collect(),
            trop_grands: self
                .marques
                .iter()
                .filter(|m| m.trop_grand.load(Ordering::Relaxed))
                .map(|m| m.nom.clone())
                .collect(),
            abandons: abandons.iter().map(|(n, _)| n.clone()).collect(),
            abandons_chemins: abandons.into_iter().map(|(_, c)| c).collect(),
            a_reprendre: self
                .marques
                .iter()
                .fold(0u64, |a, m| a.saturating_add(lu(&m.a_reprendre))),
            repris: lu(&c.repris),
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
    // La prochaine relecture permise de chaque dossier.
    let mut relire_a = vec![Instant::now(); groupes.len()];
    // Depuis quand chaque relecture avance au compte-gouttes : au-delà de FAMINE, elle prend aussi les places gardées
    // au temps réel, sinon un flot tenu juste sous la réserve la repousserait sans fin (voir `suivre_famine`).
    let mut affame: Vec<Option<Instant>> = vec![None; groupes.len()];
    while !arret.load(Ordering::SeqCst) {
        if suivis_a.elapsed() >= battement {
            suivis_a = Instant::now();
            let en_pause = pause.load(Ordering::SeqCst);
            for (i, (groupe, marque)) in groupes.iter().zip(marques).enumerate() {
                suivre_le_dossier(groupe, marque, compteurs);
                if !en_pause
                    && marque.relancer_abandon(Instant::now())
                    && let Some(quand) = relire_a.get_mut(i)
                {
                    // Une perte abandonnée est retentée : sa relecture part tout de suite.
                    *quand = Instant::now();
                }
                if let Some(quand) = relire_a.get_mut(i)
                    && !en_pause
                    && Instant::now() >= *quand
                {
                    let tour = Tour {
                        sans_reserve: affame
                            .get(i)
                            .copied()
                            .flatten()
                            .is_some_and(|a| en_famine(a, Instant::now())),
                        ..Tour::NORMAL
                    };
                    let repris_avant = lu(&compteurs.repris);
                    let presse = attente.0.lock().is_ok_and(|a| a.direct_presse());
                    let fait = relire(i, marque, attente, compteurs, tour);
                    let mis = lu(&compteurs.repris).saturating_sub(repris_avant);
                    if let Some(a) = affame.get_mut(i) {
                        *a = suivre_famine(*a, marque.en_relecture(), presse, mis, Instant::now());
                    }
                    let rythme = if fait == Relu::TropGrand {
                        RYTHME_TROP_GRAND
                    } else {
                        RYTHME_RELECTURE
                    };
                    *quand = Instant::now().checked_add(rythme).unwrap_or_else(Instant::now);
                }
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
                marque.perte();
                // Une erreur qui dure (le groupe dit prêt, la lecture échoue chaque fois) ferait sinon tourner ce fil
                // à vide, un cœur entier pris : un court repos, et le compte des défauts le dit.
                std::thread::sleep(REPOS_APRES_ERREUR);
                continue;
            };
            let l = lecture::evenements_nommes(tampon.get(..n).unwrap_or_default());
            if l.defaut.is_some() {
                plus(&compteurs.defauts);
                marque.perte();
            }
            let maintenant = Instant::now();
            let en_pause = pause.load(Ordering::SeqCst);
            let mut nouveau = false;
            for ev in l.evenements {
                plus(&compteurs.evenements);
                match ranger(&ev, marque, en_pause) {
                    Rangement::Compter(compteur) => {
                        plus(compteur.de(compteurs));
                        // Un nombre inconnu d'événements perdus, ou un événement sans nom : tout le dossier est relu
                        // (un fichier fermé maintenant a pu être écrit bien avant : son ctime ne borne rien) ; ce qui
                        // a déjà été examiné tel quel est sauté.
                        if matches!(compteur, Compteur::Debordement | Compteur::Defaut) {
                            marque.perte();
                        }
                    }
                    Rangement::Attendre(nom) => {
                        // Le moment d'origine est le ctime, s'il est plus ancien : un fichier écrit longtemps avant
                        // sa fermeture, perdu dans la file par un arrêt, doit encore tomber dans la relecture du
                        // démarrage (lu avant de prendre la file, comme pour les noms perdus).
                        let depuis = origine(ctime_de(marque, &nom));
                        let ajout = attente
                            .0
                            .lock()
                            .map_or(Ajout::Pleine, |mut a| a.ajouter_direct(i, &nom, maintenant, depuis));
                        match ajout {
                            Ajout::Nouveau => nouveau = true,
                            Ajout::Regroupe => {}
                            Ajout::Pleine => {
                                plus(&compteurs.file_pleine);
                                // Le nom est connu : lui seul est repris, quel que soit son ctime.
                                marque.nom_perdu(&nom);
                            }
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
    // Le nouveau dossier a pu être préparé ailleurs puis mis à sa place : ses fichiers gardent leur ctime d'avant.
    // Tout y est relu, sans limite de temps.
    marque.perte();
}

/// Les fichiers retirés de la file sans examen (pause) : repris par leur nom.
fn rendre_a_la_relecture(marques: &[Marque], retires: Vec<(usize, Vec<u8>)>) {
    for (i, nom) in retires {
        if let Some(m) = marques.get(i) {
            m.reprendre_nom(&nom);
        }
    }
}

/// Le moment d'origine d'un fichier d'après son ctime : jamais dans le futur, ni avant la fenêtre de relecture
/// (un vieux fichier rouvert en écriture ne doit pas faire relire des années).
fn origine(ctime: Option<i64>) -> i64 {
    let maintenant = secondes();
    ctime.map_or(maintenant, |c| {
        c.clamp(maintenant.saturating_sub(RELECTURE_MAX), maintenant)
    })
}

/// Depuis quand la relecture d'un dossier avance au compte-gouttes (moins de `PASSE_LENTE` fichiers par passe)
/// parce que le temps réel tient la file (`direct_presse`) : une place de temps en temps ne remet pas l'attente à
/// zéro. Une fois en famine, elle le reste tant que le flot direct dure : en sortir à la première passe rapide la
/// ferait retomber aussitôt sous lui. Un examen simplement lent (grosses photos, processeur bridé) n'est pas une
/// famine : la relecture n'a pas à prendre les places du temps réel, qui tomberait alors en « file pleine ».
fn suivre_famine(
    depuis: Option<Instant>,
    en_relecture: bool,
    direct_presse: bool,
    mis: u64,
    maintenant: Instant,
) -> Option<Instant> {
    match depuis {
        _ if !en_relecture || !direct_presse => None,
        Some(a) if en_famine(a, maintenant) => Some(a),
        _ if mis >= PASSE_LENTE => None,
        Some(a) => Some(a),
        None => Some(maintenant),
    }
}

fn en_famine(depuis: Instant, maintenant: Instant) -> bool {
    maintenant.saturating_duration_since(depuis) >= FAMINE
}

/// Un fichier examiné : son état d'alors (inode, ctime en secondes et nanosecondes) et le moment de l'examen.
/// L'état d'un fichier examiné (inode, ctime), le moment de l'examen, et si son verdict est définitif (sain, trop
/// gros) ou passager (non vérifié, illisible : périmé après `RELIRE_SOURCES` ou au rechargement des sources).
type Note = ((u64, i64, i64), Instant, bool);

/// Ce qu'a fait une relecture.
#[derive(Debug, PartialEq, Eq)]
enum Relu {
    /// Rien à relire, ou pas de place dans la file, ou dossier illisible.
    Rien,
    /// Une partie mise en file : la suite au prochain tour.
    EnPartie,
    /// Tout ce qui restait est en file : le dossier est à jour.
    Fini,
    /// Trop d'entrées : le dossier n'est pas listé.
    TropGrand,
}

/// Comment relire : les places gardées au direct (sauf en famine), et le nombre d'entrées au-delà duquel le dossier
/// n'est pas listé.
#[derive(Clone, Copy, Debug)]
struct Tour {
    sans_reserve: bool,
    liste_max: usize,
}

impl Tour {
    const NORMAL: Tour = Tour {
        sans_reserve: false,
        liste_max: LISTE_MAX,
    };

    fn place(self, a: &Attente) -> usize {
        let reserve = if self.sans_reserve { 0 } else { RESERVE_DIRECT };
        a.max.saturating_sub(reserve).saturating_sub(a.file.len())
    }
}

/// Relit un dossier à reprendre : d'abord les noms perdus, tels quels ; puis les fichiers ordinaires changés après
/// son curseur, du plus ancien changement au plus récent, autant que la file en laisse. Le curseur avance jusqu'au
/// dernier mis en file ; une demande arrivée pendant ce temps garde son point.
fn relire(i: usize, m: &Marque, attente: &(Mutex<Attente>, Condvar), compteurs: &Compteurs, tour: Tour) -> Relu {
    if attente.0.lock().map_or(0, |a| tour.place(&a)) == 0 {
        return Relu::Rien;
    }
    let (curseur, noms) = {
        let mut etat = m.relecture.lock().unwrap_or_else(PoisonError::into_inner);
        if etat.curseur.is_none() && etat.noms.is_empty() {
            return Relu::Rien;
        }
        etat.en_lecture = true;
        etat.pendant = None;
        (etat.curseur.clone(), etat.noms.iter().cloned().collect::<Vec<_>>())
    };
    let (mis, tous_les_noms) = remettre_les_noms(i, m, &noms, attente, compteurs, tour);
    let du_debut = curseur.as_ref().is_some_and(|c| c.s == i64::MIN);
    let (fait, apres) = match curseur {
        None => (Relu::Fini, None),
        // La file est déjà pleine : le dossier n'est pas listé pour rien.
        Some(c) if !tous_les_noms => (Relu::Rien, Some(c)),
        Some(c) => relire_a_partir(i, m, &c, attente, compteurs, tour),
    };
    let mut etat = m.relecture.lock().unwrap_or_else(PoisonError::into_inner);
    for nom in &mis {
        etat.noms.remove(nom);
    }
    let avait_perte = etat.perte_sans_nom;
    let fini = etat.finir(apres, du_debut);
    if !fini && avait_perte && !etat.perte_sans_nom {
        // La perte sans nom (comptée une fois) n'attend plus ; restent les noms ou une demande ordinaire.
        let _ = m
            .a_reprendre
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_sub(1)));
    }
    if fini {
        m.a_reprendre.store(0, Ordering::Relaxed);
        // Un dossier trop grand abandonné n'est pas « fini » : il n'a pas été lu, et ne se relit qu'à son rythme.
        return if fait == Relu::TropGrand {
            Relu::TropGrand
        } else {
            Relu::Fini
        };
    }
    match fait {
        Relu::TropGrand => Relu::TropGrand,
        _ if !mis.is_empty() => Relu::EnPartie,
        Relu::Fini => Relu::EnPartie,
        autre => autre,
    }
}

/// Met en file les noms perdus, tant qu'il y a de la place ; rend ceux qui y sont, et si tous y sont.
fn remettre_les_noms(
    i: usize,
    m: &Marque,
    noms: &[Vec<u8>],
    attente: &(Mutex<Attente>, Condvar),
    compteurs: &Compteurs,
    tour: Tour,
) -> (Vec<Vec<u8>>, bool) {
    if noms.is_empty() {
        return (Vec::new(), true);
    }
    // Le ctime de chacun (lu avant de prendre la file) : le temps réel n'est pas à jour au-delà tant qu'il attend.
    // Seulement ce qui a une place : une file presque pleine ne fait pas lire des milliers de noms pour un seul.
    let place = attente.0.lock().map_or(0, |a| tour.place(&a));
    let depuis: Vec<i64> = noms.iter().take(place).map(|n| origine(ctime_de(m, n))).collect();
    let mut mis = Vec::new();
    let Ok(mut a) = attente.0.lock() else {
        return (mis, false);
    };
    let maintenant = Instant::now();
    for (nom, d) in noms.iter().zip(depuis) {
        if tour.place(&a) == 0 {
            break;
        }
        match a.ajouter_depuis(i, nom, maintenant, d) {
            Ajout::Nouveau => plus(&compteurs.repris),
            Ajout::Regroupe => {}
            Ajout::Pleine => break,
        }
        mis.push(nom.clone());
    }
    // Les noms au-delà des places (jamais lus) ne sont pas en file non plus.
    let complet = mis.len() == noms.len();
    drop(a);
    attente.1.notify_all();
    (mis, complet)
}

/// Le ctime d'un nom du dossier marqué, sans suivre de lien.
fn ctime_de(m: &Marque, nom: &[u8]) -> Option<i64> {
    let fd = m.fd.read().unwrap_or_else(PoisonError::into_inner);
    let chemin = Path::new(&format!("/proc/self/fd/{}", fd.as_raw_fd())).join(OsStr::from_bytes(nom));
    std::fs::symlink_metadata(chemin).ok().map(|x| x.ctime())
}

impl Relecture {
    /// Le dossier est à relire à partir de `c` : le plus ancien point l'emporte ; pendant une lecture, la demande
    /// est aussi gardée à part pour sa fin.
    fn demander(&mut self, c: Curseur) {
        self.curseur = Some(plus_ancien(self.curseur.take(), c.clone()));
        if self.en_lecture {
            self.pendant = Some(plus_ancien(self.pendant.take(), c));
        }
    }

    /// La fin d'une lecture du dossier : `apres` est ce qui lui reste (`None` : tout est en file). Une demande
    /// arrivée pendant elle (une fin de pause, une perte) garde son point. Vrai : le dossier est à jour (plus de
    /// curseur ni de nom perdu).
    ///
    /// `depuis_min` : la lecture partait du début (`i64::MIN`) et n'a rien laissé : tout est en file, ou elle est
    /// abandonnée (dossier trop grand, `perte_abandonnee` prend le relais) ; la perte sans nom n'attend donc plus,
    /// même si une demande ordinaire est arrivée pendant elle (une nouvelle perte garde le drapeau).
    fn finir(&mut self, apres: Option<Curseur>, depuis_min: bool) -> bool {
        self.en_lecture = false;
        let pendant = self.pendant.take();
        let perte_pendant = pendant.as_ref().is_some_and(|p| p.s == i64::MIN);
        let tout_lu = apres.is_none();
        self.curseur = match (apres, pendant) {
            (Some(a), p) => Some(plus_ancien(p, a)),
            (None, p) => p,
        };
        if self.curseur.is_none() || (depuis_min && tout_lu && !perte_pendant) {
            self.perte_sans_nom = false;
        }
        self.curseur.is_none() && self.noms.is_empty()
    }
}

/// Une lecture du dossier depuis `curseur` : met en file ce qui tient, et rend ce qui a été fait avec le curseur qui
/// reste (`None` : tout est en file).
fn relire_a_partir(
    i: usize,
    m: &Marque,
    curseur: &Curseur,
    attente: &(Mutex<Attente>, Condvar),
    compteurs: &Compteurs,
    tour: Tour,
) -> (Relu, Option<Curseur>) {
    let candidats = match lister(m, curseur, tour.liste_max) {
        Ok(c) => c,
        // Illisible (dossier supprimé, /proc absent) : rien n'est mis en file, le curseur reste et le bilan le dit.
        Err(Liste::Illisible) => return (Relu::Rien, Some(curseur.clone())),
        Err(Liste::TropGrand) => {
            m.trop_grand.store(true, Ordering::Relaxed);
            // Sans perte sans nom (relecture du démarrage, de fin de pause, d'un fichier parti ; les noms perdus sont
            // repris sans lister) : abandonnée, dite et comptée non vérifiée au bilan. Avec une : réessayée quelques
            // fois, puis abandonnée aussi, et le bilan la garde en alerte (`perte_abandonnee`) : sinon un dossier
            // gonflé tiendrait tout le temps réel « pas à jour » pour toujours.
            let avec_perte = m
                .relecture
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .perte_sans_nom;
            // Seuls les essais avec une perte comptent : un abandon sans perte ne rapproche pas le suivant.
            let essais = if avec_perte {
                m.essais_trop_grand.fetch_add(1, Ordering::Relaxed).saturating_add(1)
            } else {
                0
            };
            let abandon = !avec_perte || essais >= ESSAIS_TROP_GRAND;
            if abandon && avec_perte {
                m.perte_abandonnee.store(true, Ordering::Relaxed);
                *m.abandon_a.lock().unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
            }
            return (Relu::TropGrand, (!abandon).then(|| curseur.clone()));
        }
    };
    m.trop_grand.store(false, Ordering::Relaxed);
    m.essais_trop_grand.store(0, Ordering::Relaxed);
    if curseur.s == i64::MIN {
        m.perte_abandonnee.store(false, Ordering::Relaxed);
    } else if m.perte_abandonnee.load(Ordering::Relaxed) {
        // Le dossier se liste de nouveau : la perte abandonnée est reprise, depuis le début, à la passe suivante.
        m.perte();
    }
    let (mut dernier, mut complet) = (None, true);
    let Ok(mut a) = attente.0.lock() else {
        return (Relu::Rien, Some(curseur.clone()));
    };
    let maintenant = Instant::now();
    for x in candidats {
        if tour.place(&a) == 0 {
            complet = false;
            break;
        }
        match a.ajouter_depuis(i, &x.nom, maintenant, x.s) {
            Ajout::Nouveau => plus(&compteurs.repris),
            Ajout::Regroupe => {}
            Ajout::Pleine => {
                complet = false;
                break;
            }
        }
        dernier = Some(x);
    }
    drop(a);
    attente.1.notify_all();
    match (complet, dernier) {
        (true, _) => (Relu::Fini, None),
        (false, Some(d)) => (Relu::EnPartie, Some(d)),
        (false, None) => (Relu::Rien, Some(curseur.clone())),
    }
}

/// Pourquoi un dossier n'a pas été listé.
#[derive(Debug, PartialEq, Eq)]
enum Liste {
    Illisible,
    TropGrand,
}

/// Les fichiers ordinaires du dossier marqué changés après `curseur` et pas déjà examinés tels quels, triés ; lus par
/// le descripteur de la marque (le dossier marqué lui-même, même si un autre a pris son nom), sans suivre aucun lien.
fn lister(m: &Marque, curseur: &Curseur, max: usize) -> Result<Vec<Curseur>, Liste> {
    let lecture = {
        let fd = m.fd.read().unwrap_or_else(PoisonError::into_inner);
        std::fs::read_dir(format!("/proc/self/fd/{}", fd.as_raw_fd()))
    };
    let lecture = lecture.map_err(|_| Liste::Illisible)?;
    let mut candidats = Vec::new();
    for (n, entree) in lecture.enumerate() {
        if n >= max {
            return Err(Liste::TropGrand);
        }
        let Ok(entree) = entree else {
            continue;
        };
        let nom = entree.file_name().as_bytes().to_vec();
        if !nom_acceptable(&nom) || en_cours(m, &nom) {
            continue;
        }
        // Sans suivre de lien : un lien, un tube ou un dossier n'a rien à lire ici.
        let Ok(meta) = entree.metadata() else {
            continue;
        };
        if !meta.is_file() || m.deja_examine(&nom, &meta) {
            continue;
        }
        let x = Curseur {
            s: meta.ctime(),
            ns: meta.ctime_nsec(),
            nom,
        };
        if x > *curseur {
            candidats.push(x);
        }
    }
    candidats.sort();
    Ok(candidats)
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
    while let Some((i, nom, dernier, depuis)) = prochain(p.arret, p.attente, &compteurs.en_examen_depuis) {
        let Some(marque) = p.marques.get(i) else {
            continue;
        };
        if p.pause.load(Ordering::SeqCst) {
            // Pris juste avant que la pause vide la file : rendu à la relecture, comme le reste de la file.
            rendre_a_la_relecture(p.marques, vec![(i, nom)]);
            continue;
        }
        // Les empreintes récentes changent chaque jour : relues de temps en temps ; un rechargement qui échoue garde
        // les sources d'avant.
        if chargees_a.elapsed() >= RELIRE_SOURCES {
            if let Some((b, r)) = charger_sans_paniquer(&mut charger) {
                (base, recentes) = (b, r);
                for m in p.marques {
                    m.oublier_passagers();
                }
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
        let Some((r, identite)) = examiner_un(marque, &nom, &sources, compteurs, depuis) else {
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

/// Le prochain fichier prêt, en attendant ; `None` : arrêt demandé. `en_examen` porte, sous le verrou de la file,
/// le moment d'origine du fichier rendu (0 : aucun), pour que `vu_jusqu_a` le compte encore pendant son examen.
fn prochain(
    arret: &AtomicBool,
    attente: &(Mutex<Attente>, Condvar),
    en_examen: &AtomicI64,
) -> Option<(usize, Vec<u8>, Instant, i64)> {
    let mut a = attente.0.lock().ok()?;
    en_examen.store(0, Ordering::SeqCst);
    loop {
        if arret.load(Ordering::SeqCst) {
            return None;
        }
        let maintenant = Instant::now();
        if let Some((i, nom, dernier, depuis)) = a.prendre_pret(maintenant) {
            en_examen.store(depuis, Ordering::SeqCst);
            return Some((i, nom, dernier, depuis));
        }
        let attendre = a
            .prochain(maintenant)
            .unwrap_or(Duration::from_millis(500))
            .clamp(Duration::from_millis(10), Duration::from_millis(500));
        a = attente.1.wait_timeout(a, attendre).ok()?.0;
    }
}

/// Rouvre `nom` sous le dossier marqué, sans suivre aucun lien, et l'examine s'il est un fichier ordinaire de taille
/// bornée ; rend aussi l'identité du fichier lu. `None` : sauté, et compté. `depuis` : son moment d'origine dans la
/// file.
fn examiner_un(
    m: &Marque,
    nom: &[u8],
    sources: &Sources<'_>,
    c: &Compteurs,
    depuis: i64,
) -> Option<(Resultat, Identite)> {
    let ouvert = {
        let fd = m.fd.read().unwrap_or_else(PoisonError::into_inner);
        ouvrir::sous(fd.as_fd(), Path::new(OsStr::from_bytes(nom)), false)
    };
    let f = match ouvert {
        Ok(f) => f,
        Err(e) => {
            match e.raw_os_error() {
                Some(libc::ENOENT) => {
                    plus(&c.partis);
                    // Parti, ou jamais là sous ce nom (O_TMPFILE puis linkat donne un événement au nom anonyme) : le
                    // dossier est relu depuis le moment de l'événement (pas de l'examen : une file chargée l'a fait
                    // attendre), ce qui y est arrivé sous un autre nom est repris.
                    m.relire_depuis(depuis.min(secondes()).saturating_sub(MARGE_RELECTURE));
                }
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
        // Déjà dit trop gros : une relecture ne le recompte pas tant qu'il est tel quel.
        m.noter_examine(nom, &meta);
        return None;
    }
    let identite = Identite::de(&meta);
    let chemin = m.chemin.join(OsStr::from_bytes(nom));
    // Le ctime lu avant l'examen : changé pendant lui, le fichier ne sera pas pris pour déjà examiné.
    let lu_avant = meta.clone();
    plus(&c.examines);
    let pour_le_cache = f.try_clone().ok();
    let r = moteur::examiner_ouvert(f, &chemin, sources, bornes()).ok();
    if let Some(f) = pour_le_cache {
        fanotify::oublier_du_cache(&f);
    }
    // Un fichier sain est retenu : une relecture saute ce qui est encore tel quel. Une menace ne l'est jamais : elle
    // est réexaminée, donc redite. Un non-vérifié ou un illisible l'est un temps (`noter_passager`) : la cause peut
    // passer (délai dépassé sous charge, sources manquantes rechargées).
    match &r {
        None => {
            plus(&c.illisibles);
            m.noter_passager(nom, &lu_avant);
        }
        Some(fait) => match fait.verdict() {
            Verdict::Sain => m.noter_examine(nom, &lu_avant),
            Verdict::NonVerifie(_) => m.noter_passager(nom, &lu_avant),
            _ => {}
        },
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
    use std::os::unix::fs::PermissionsExt;

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
        assert_eq!(a.vider(), vec![(0, b"c".to_vec())]);
        assert_eq!(a.len(), 0);
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
        assert!(examiner_un(&surveille, b"lien", &sources, &compteurs, secondes()).is_none());
        assert_eq!(lu(&compteurs.ecartes), 1);
        crate::essais::tube_nomme(&dossier.join("tube")).unwrap();
        assert!(examiner_un(&surveille, b"tube", &sources, &compteurs, secondes()).is_none());
        assert_eq!(lu(&compteurs.ecartes), 2);
        let gros = File::create(dossier.join("gros")).unwrap();
        gros.set_len(TAILLE_MAX + 1).unwrap();
        assert!(examiner_un(&surveille, b"gros", &sources, &compteurs, secondes()).is_none());
        assert_eq!(lu(&compteurs.trop_gros), 1);
        // Trop gros : retenu, une perte ne le recompte pas tant qu'il est tel quel.
        assert!(surveille.examines.lock().unwrap().contains_key(b"gros".as_slice()));
        assert!(examiner_un(&surveille, b"parti", &sources, &compteurs, secondes()).is_none());
        assert_eq!(lu(&compteurs.partis), 1);
        // Parti avant son examen : le dossier est relu depuis le moment d'origine du fichier (un remplaçant écrit
        // entre-temps est vu), pas depuis maintenant.
        surveille.relecture.lock().unwrap().curseur = None;
        let vieux = secondes() - 3_600;
        assert!(examiner_un(&surveille, b"parti", &sources, &compteurs, vieux).is_none());
        assert_eq!(
            surveille.relecture.lock().unwrap().curseur,
            Some(Curseur::depuis(vieux - MARGE_RELECTURE))
        );
        surveille.relecture.lock().unwrap().curseur = None;
        let nom = b"\xfe\xffalice";
        std::fs::write(dossier.join(OsStr::from_bytes(nom)), elf_marque()).unwrap();
        let (r, identite) = examiner_un(&surveille, nom, &sources, &compteurs, secondes()).unwrap();
        assert!(matches!(r.verdict(), Verdict::Certain(..)), "{:?}", r.verdict());
        // L'identité rendue est celle du fichier lu, sous son nom.
        let lue = std::fs::symlink_metadata(dossier.join(OsStr::from_bytes(nom))).unwrap();
        assert_eq!(identite, Identite::de(&lue));
        assert_eq!(identite.liens, 1);
        std::fs::write(dossier.join("note.txt"), b"Liste du Salon").unwrap();
        assert_eq!(
            examiner_un(&surveille, b"note.txt", &sources, &compteurs, secondes())
                .unwrap()
                .0
                .verdict(),
            Verdict::Sain
        );
        assert_eq!(lu(&compteurs.examines), 2);
        // Une menace n'est jamais retenue : une relecture la réexamine, et la redit.
        let x = surveille.examines.lock().unwrap();
        assert!(x.contains_key(b"note.txt".as_slice()));
        assert!(!x.contains_key(nom.as_slice()));
        drop(x);
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
        // QEMU (AV5, C) : la cause d'une coupure par le filtre est dite dans la langue de l'écran, pas dans celle du
        // service qui l'a écrite (une unité d'avant, sans VANGUARD_LANG).
        r.sans = Some("TEXTE-DU-SERVICE".into());
        r.coupure = Some(Coupure::VersionAvant);
        let p = r.phrase();
        assert!(!p.contains("TEXTE-DU-SERVICE"), "{p}");
        assert!(p.contains(tr!("version d'avant", "earlier version")), "{p}");
        // Relu de l'état écrit : la coupure y reste un code.
        let relu: Releve = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(relu.coupure, Some(Coupure::VersionAvant));
        r.coupure = None;
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

    /// A (relecture AV5) : le curseur range par ctime, nanosecondes puis nom ; une demande garde le plus ancien point ;
    /// une perte compte jusqu'à la fin de la relecture.
    #[test]
    fn curseur_et_demandes_de_relecture() {
        let c = |s, ns, nom: &[u8]| Curseur {
            s,
            ns,
            nom: nom.to_vec(),
        };
        assert!(c(1, 5, b"b") < c(2, 0, b"a"));
        assert!(c(2, 0, b"z") < c(2, 1, b"a"));
        assert!(c(2, 1, b"a") < c(2, 1, b"b"));
        // Un nom n'est jamais vide : « depuis » prend tout ce qui a changé à partir de cette seconde.
        assert!(Curseur::depuis(2) < c(2, 0, b"a"));
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let m = marque(&d, false);
        assert!(!m.en_relecture());
        m.relire_depuis(100);
        m.relire_depuis(200);
        assert_eq!(m.relecture.lock().unwrap().curseur, Some(Curseur::depuis(100)));
        m.perte();
        assert_eq!(m.relecture.lock().unwrap().curseur, Some(Curseur::depuis(i64::MIN)));
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        // Un nom perdu est gardé une fois, et compté une fois.
        m.nom_perdu(b"x");
        m.nom_perdu(b"x");
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 2);
        assert_eq!(m.relecture.lock().unwrap().noms.len(), 1);
        // Une demande pendant une lecture : gardée à part, et la fin de la lecture ne l'efface pas.
        let mut r = Relecture {
            curseur: Some(c(10, 0, b"a")),
            en_lecture: true,
            pendant: None,
            noms: BTreeSet::new(),
            perte_sans_nom: false,
        };
        assert!(r.finir(None, false));
        // Un nom perdu pas encore en file : le dossier n'est pas à jour.
        r.noms.insert(b"x".to_vec());
        r.en_lecture = true;
        assert!(!r.finir(None, false));
        r.noms.clear();
        r.en_lecture = true;
        r.pendant = Some(Curseur::depuis(5));
        assert!(!r.finir(None, false));
        assert_eq!(r.curseur, Some(Curseur::depuis(5)));
        r.en_lecture = true;
        r.pendant = Some(Curseur::depuis(50));
        assert!(!r.finir(Some(c(20, 0, b"x")), false));
        assert_eq!(r.curseur, Some(c(20, 0, b"x")));
        assert!(!r.en_lecture && r.pendant.is_none());
        // M7 : une lecture complète depuis le début reprend la perte sans nom, même si une demande ordinaire est
        // arrivée pendant elle ; une nouvelle perte pendant elle garde le drapeau.
        r.curseur = Some(Curseur::depuis(i64::MIN));
        r.perte_sans_nom = true;
        r.en_lecture = true;
        r.pendant = Some(Curseur::depuis(50));
        assert!(!r.finir(None, true));
        assert!(!r.perte_sans_nom);
        assert_eq!(r.curseur, Some(Curseur::depuis(50)));
        r.perte_sans_nom = true;
        r.en_lecture = true;
        r.pendant = Some(Curseur::depuis(i64::MIN));
        assert!(!r.finir(None, true));
        assert!(r.perte_sans_nom);
        // Pas finie (un reste) : le drapeau reste.
        r.en_lecture = true;
        assert!(!r.finir(Some(c(20, 0, b"x")), true));
        assert!(r.perte_sans_nom);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A : une relecture avec peu de place avance par étapes, sans rien prendre deux fois, puis finit ; liens,
    /// dossiers et téléchargements en cours sont laissés ; les pertes ne sont remises à zéro qu'à la fin.
    #[test]
    fn relecture_par_etapes() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        for n in 0..25 {
            std::fs::write(d.join(format!("f{n:02}")), b"Salon").unwrap();
        }
        std::fs::create_dir(d.join("sous-dossier")).unwrap();
        std::os::unix::fs::symlink(d.join("f00"), d.join("lien")).unwrap();
        std::fs::write(d.join("x.exe.part"), b"Salon").unwrap();
        let m = marque(&d, true);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Rien);
        m.perte();
        let mut pris: Vec<Vec<u8>> = Vec::new();
        let vider = |pris: &mut Vec<Vec<u8>>| {
            let mut a = attente.0.lock().unwrap();
            pris.extend(a.file.drain(..).map(|e| e.nom));
        };
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::EnPartie);
        assert_eq!(attente.0.lock().unwrap().len(), 10);
        // Les places gardées au direct ne sont jamais prises.
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Rien);
        assert!(m.en_relecture());
        vider(&mut pris);
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::EnPartie);
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        vider(&mut pris);
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        vider(&mut pris);
        assert!(!m.en_relecture());
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        pris.sort();
        let attendus: Vec<Vec<u8>> = (0..25).map(|n| format!("f{n:02}").into_bytes()).collect();
        assert_eq!(pris, attendus);
        assert_eq!(c.repris.load(Ordering::Relaxed), 25);
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Rien);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A : la phrase et le compte de l'alerte horaire disent les pertes pas encore reprises ; le bilan les compte.
    #[test]
    fn pertes_dites_et_comptees() {
        let mut r = Releve {
            actif: true,
            dossiers: vec!["~/Salon".into()],
            ..Releve::default()
        };
        assert!(!r.en_retard());
        r.file_pleine = 3;
        r.debordements = 1;
        r.relectures = vec!["~/Salon".into()];
        r.a_reprendre = 4;
        let p = r.phrase();
        assert!(p.contains(tr!("4 perte(s)", "4 loss(es)")), "{p}");
        assert!(p.contains(tr!("Relecture en cours", "Reading again")), "{p}");
        assert!(r.en_retard());
        assert_eq!(r.a_signaler(), 4);
        // Un dossier trop grand pour la relecture du démarrage, sans perte : dit, sans tenir le bilan en alerte.
        r.a_reprendre = 0;
        r.trop_grands = vec!["~/Salon".into()];
        assert!(!r.en_retard());
        // … mais pas vérifié.
        assert!(r.incomplet());
        assert!(r.phrase().contains("vanguard audit"), "{}", r.phrase());
    }

    /// Défaut 1 (relecture Fable) : un nom perdu par file pleine est repris même si son ctime est plus ancien que
    /// tout point de relecture (écrit, gardé ouvert, fermé pendant une rafale) ; l'entrée porte ce ctime.
    #[test]
    fn nom_perdu_repris_quel_que_soit_le_ctime() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::write(d.join("vieux"), b"Salon").unwrap();
        std::fs::write(d.join("autre"), b"Salon").unwrap();
        let ctime = std::fs::symlink_metadata(d.join("vieux")).unwrap().ctime();
        let m = marque(&d, false);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        m.relire_depuis(secondes() + 3600);
        m.nom_perdu(b"vieux");
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        let a = attente.0.lock().unwrap();
        let noms: Vec<&[u8]> = a.file.iter().map(|e| e.nom.as_slice()).collect();
        assert_eq!(noms, vec![b"vieux".as_slice()]);
        assert_eq!(a.plus_ancien(), Some(ctime));
        drop(a);
        assert!(!m.en_relecture());
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Défaut 3 : un dossier illisible ne finit pas la relecture : le curseur et la perte restent, puis lisible, il
    /// finit.
    #[test]
    fn dossier_illisible_garde_sa_relecture() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::write(d.join("f"), b"Salon").unwrap();
        let m = marque(&d, false);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&d).is_ok() {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("droits ignorés (root ?) : le dossier reste lisible");
        }
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        m.perte();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Rien);
        assert!(m.en_relecture());
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Défaut 5 : un dossier trop grand, sans perte, n'est pas relu sans fin (abandon, dit) ; avec une perte, la
    /// relecture reste demandée ; une liste réussie efface « trop grand ».
    #[test]
    fn dossier_trop_grand() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        for n in 0..5 {
            std::fs::write(d.join(format!("f{n}")), b"Salon").unwrap();
        }
        let m = marque(&d, false);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        let petit = Tour {
            sans_reserve: false,
            liste_max: 3,
        };
        m.relire_depuis(0);
        assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
        assert!(!m.en_relecture());
        assert!(m.trop_grand.load(Ordering::Relaxed));
        m.perte();
        assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
        assert!(m.en_relecture());
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        assert!(!m.trop_grand.load(Ordering::Relaxed));
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        // N4 : une perte dans un dossier qui reste trop grand : réessayée, puis abandonnée et gardée en alerte.
        m.perte();
        for _ in 1..ESSAIS_TROP_GRAND {
            assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
            assert!(m.en_relecture());
            assert!(!m.perte_abandonnee.load(Ordering::Relaxed));
        }
        assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
        assert!(
            !m.en_relecture(),
            "abandonnée : le temps réel n'est plus tenu en retard"
        );
        assert!(m.perte_abandonnee.load(Ordering::Relaxed));
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        // Une relecture partielle ne l'efface pas ; une relecture complète réussie, si.
        attente.0.lock().unwrap().file.clear();
        m.relire_depuis(secondes());
        // M2 : le dossier se liste de nouveau : la perte abandonnée est redemandée depuis le début.
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::EnPartie);
        assert!(m.perte_abandonnee.load(Ordering::Relaxed));
        assert!(m.relecture.lock().unwrap().perte_sans_nom);
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        assert!(!m.perte_abandonnee.load(Ordering::Relaxed));
        // M9 : des abandons sans perte ne rapprochent pas l'abandon d'une perte.
        attente.0.lock().unwrap().file.clear();
        for _ in 0..ESSAIS_TROP_GRAND {
            m.relire_depuis(0);
            assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
        }
        assert_eq!(m.essais_trop_grand.load(Ordering::Relaxed), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// N2 : un nom perdu (repris sans lister) ne retient pas l'abandon d'un dossier trop grand relu sans perte.
    #[test]
    fn nom_perdu_ne_retient_pas_l_abandon() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        for n in 0..5 {
            std::fs::write(d.join(format!("f{n}")), b"Salon").unwrap();
        }
        let m = marque(&d, false);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        let petit = Tour {
            sans_reserve: false,
            liste_max: 3,
        };
        m.nom_perdu(b"f0");
        m.relire_depuis(0);
        assert_eq!(relire(0, &m, &attente, &c, petit), Relu::TropGrand);
        assert!(!m.en_relecture());
        assert!(!m.perte_abandonnee.load(Ordering::Relaxed));
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 0);
        assert_eq!(c.repris.load(Ordering::Relaxed), 1, "le nom perdu est repris");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une perte sans nom est comptée une fois tant qu'elle attend ; au-delà de `NOMS_PERDUS_MAX` noms, le dossier
    /// entier est relu, compté une fois aussi.
    #[test]
    fn pertes_sans_nom_comptees_une_fois() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let m = marque(&d, false);
        m.perte();
        m.perte();
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        assert!(!m.relecture.lock().unwrap().perte_sans_nom);
        m.perte();
        assert_eq!(
            m.a_reprendre.load(Ordering::Relaxed),
            1,
            "une nouvelle perte est comptée"
        );
        let m = marque(&d, false);
        for n in 0..NOMS_PERDUS_MAX {
            m.nom_perdu(format!("n{n}").as_bytes());
        }
        let max = u64::try_from(NOMS_PERDUS_MAX).unwrap();
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), max);
        assert!(!m.relecture.lock().unwrap().perte_sans_nom);
        m.nom_perdu(b"de-trop");
        m.nom_perdu(b"encore");
        let r = m.relecture.lock().unwrap();
        assert!(r.perte_sans_nom);
        assert_eq!(r.curseur, Some(Curseur::depuis(i64::MIN)));
        drop(r);
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), max + 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// N3 : ce que la pause retire de la file est rendu à la relecture, depuis le plus ancien moment d'origine.
    #[test]
    fn pause_rend_la_file_a_la_relecture() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let marques = vec![marque(&d, false), marque(&d, false)];
        let mut a = Attente::new(RESERVE_DIRECT + 10);
        a.ajouter_depuis(0, b"a", Instant::now(), 1_000);
        a.ajouter_depuis(0, b"b", Instant::now(), 500);
        a.ajouter_depuis(1, b"c", Instant::now(), 2_000);
        rendre_a_la_relecture(&marques, a.vider());
        assert_eq!(a.len(), 0);
        // M3 : repris par leur nom, sans lister le dossier (qui peut être trop grand pour l'être).
        let noms = |m: &Marque| m.relecture.lock().unwrap().noms.clone();
        assert_eq!(noms(&marques[0]), BTreeSet::from([b"a".to_vec(), b"b".to_vec()]));
        assert_eq!(noms(&marques[1]), BTreeSet::from([b"c".to_vec()]));
        assert_eq!(marques[0].relecture.lock().unwrap().curseur, None);
        assert_eq!(marques[0].a_reprendre.load(Ordering::Relaxed), 0, "pas une perte");
        // Un dossier trop grand : les noms rendus sont relus quand même.
        let petit = Tour {
            sans_reserve: false,
            liste_max: 1,
        };
        std::fs::write(d.join("a"), b"Salon").unwrap();
        std::fs::write(d.join("b"), b"Salon").unwrap();
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        assert_eq!(relire(0, &marques[0], &attente, &c, petit), Relu::Fini);
        assert_eq!(attente.0.lock().unwrap().len(), 2);
        // Plus de noms que la liste n'en garde : une perte, comptée une fois.
        let m = &marques[1];
        // Il y a déjà « c ».
        for n in 1..NOMS_PERDUS_MAX {
            m.reprendre_nom(format!("n{n}").as_bytes());
        }
        assert!(!m.relecture.lock().unwrap().perte_sans_nom);
        m.reprendre_nom(b"de trop");
        assert!(m.relecture.lock().unwrap().perte_sans_nom);
        assert_eq!(m.a_reprendre.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// M6 : des noms au-delà des places ne sont pas dits « tous en file ».
    #[test]
    fn noms_au_dela_des_places() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let m = marque(&d, false);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 2)), Condvar::new());
        let c = Compteurs::default();
        let noms: Vec<Vec<u8>> = (0..5).map(|n| format!("n{n}").into_bytes()).collect();
        let (mis, complet) = remettre_les_noms(0, &m, &noms, &attente, &c, Tour::NORMAL);
        assert_eq!(mis.len(), 2);
        assert!(!complet);
        let (mis, complet) = remettre_les_noms(0, &m, &noms[2..], &attente, &c, Tour::NORMAL);
        assert!(mis.is_empty() && !complet, "file pleine : rien n'est dit en file");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// M8 : le moment d'origine tient dans la fenêtre de relecture.
    #[test]
    fn origine_bornee() {
        let t = secondes();
        assert!((t..=t + 1).contains(&origine(None)));
        assert!((t - RELECTURE_MAX..=t - RELECTURE_MAX + 1).contains(&origine(Some(0))));
        assert!((t..=t + 1).contains(&origine(Some(i64::MAX))));
        assert_eq!(origine(Some(t - 60)), t - 60);
    }

    /// M2 : une perte abandonnée est retentée après `REESSAI_ABANDON` (tout de suite si son moment est inconnu,
    /// comme après un redémarrage), jamais pendant une relecture.
    #[test]
    fn perte_abandonnee_retentee() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let m = marque(&d, false);
        let t = Instant::now();
        assert!(!m.relancer_abandon(t), "rien d'abandonné");
        m.perte_abandonnee.store(true, Ordering::Relaxed);
        *m.abandon_a.lock().unwrap() = Some(t);
        assert!(!m.relancer_abandon(t + Duration::from_secs(60)));
        assert!(m.relancer_abandon(t + REESSAI_ABANDON));
        assert!(m.relecture.lock().unwrap().perte_sans_nom);
        assert!(!m.relancer_abandon(t + REESSAI_ABANDON * 2), "déjà en relecture");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// N6 : la famine compte les passes lentes, pas seulement les vides ; une fois en famine, elle le reste jusqu'à
    /// la fin de la relecture.
    #[test]
    fn famine_des_passes_lentes() {
        let t = Instant::now();
        let plus_tard = t + FAMINE;
        assert_eq!(
            suivre_famine(None, true, true, 1, t),
            Some(t),
            "une place par passe : lente"
        );
        assert_eq!(
            suivre_famine(Some(t), true, true, 1, t + Duration::from_secs(1)),
            Some(t)
        );
        assert_eq!(
            suivre_famine(Some(t), true, true, PASSE_LENTE, t + Duration::from_secs(1)),
            None
        );
        assert!(!en_famine(t, t + Duration::from_secs(29)));
        assert!(en_famine(t, plus_tard));
        assert_eq!(
            suivre_famine(Some(t), true, true, PASSE_LENTE, plus_tard),
            Some(t),
            "gardée"
        );
        assert_eq!(
            suivre_famine(Some(t), false, true, 0, plus_tard),
            None,
            "relecture finie"
        );
        assert_eq!(suivre_famine(None, false, true, 0, t), None);
        // M1 : sans flot direct, un examen lent n'est pas une famine (la réserve reste au temps réel).
        assert_eq!(suivre_famine(None, true, false, 1, t), None);
        assert_eq!(suivre_famine(Some(t), true, false, 0, plus_tard), None);
        let mut a = Attente::new(FILE_MAX);
        for n in 0..RESERVE_DIRECT {
            a.ajouter_depuis(0, format!("r{n}").as_bytes(), t, 0);
        }
        assert!(!a.direct_presse(), "des reprises, pas du direct");
        for n in 0..RESERVE_DIRECT / 2 - 1 {
            a.ajouter_direct(0, format!("d{n}").as_bytes(), t, 0);
        }
        assert!(!a.direct_presse());
        a.ajouter_direct(0, b"r0", t, 0);
        assert!(a.direct_presse(), "un regroupement direct compte");
    }

    /// Défaut 4 : une file tenue dans les places gardées au direct bloque la relecture ; en famine, elle les prend.
    #[test]
    fn famine_prend_les_places_gardees() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::write(d.join("f"), b"Salon").unwrap();
        let m = marque(&d, false);
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 5)), Condvar::new());
        {
            let mut a = attente.0.lock().unwrap();
            for n in 0..10 {
                assert_eq!(
                    a.ajouter(1, format!("direct{n}").as_bytes(), Instant::now()),
                    Ajout::Nouveau
                );
            }
        }
        let c = Compteurs::default();
        m.perte();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Rien);
        let affame = Tour {
            sans_reserve: true,
            liste_max: LISTE_MAX,
        };
        assert_eq!(relire(0, &m, &attente, &c, affame), Relu::Fini);
        assert_eq!(c.repris.load(Ordering::Relaxed), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Défaut 2 : la file garde le plus ancien moment d'origine (regroupement compris) ; le fichier rendu à
    /// l'examen reste compté jusqu'au suivant.
    #[test]
    fn moment_d_origine_de_la_file_et_de_l_examen() {
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let avant = Instant::now().checked_sub(Duration::from_secs(3600)).unwrap();
        {
            let mut a = attente.0.lock().unwrap();
            assert_eq!(a.plus_ancien(), None);
            a.ajouter_depuis(0, b"a", avant, 100);
            a.ajouter_depuis(0, b"b", avant, 50);
            a.ajouter_depuis(0, b"a", avant, 30);
            assert_eq!(a.plus_ancien(), Some(30));
        }
        let arret = AtomicBool::new(false);
        let en_examen = AtomicI64::new(0);
        let (_, nom, _, depuis) = prochain(&arret, &attente, &en_examen).unwrap();
        let attendu = if nom == b"a" { 30 } else { 50 };
        assert_eq!(en_examen.load(Ordering::SeqCst), attendu);
        assert_eq!(depuis, attendu);
        arret.store(true, Ordering::SeqCst);
        assert!(prochain(&arret, &attente, &en_examen).is_none());
        assert_eq!(en_examen.load(Ordering::SeqCst), 0);
    }

    /// Défaut 6 : un fichier examiné sain tel quel est sauté par une relecture ; réécrit, il est repris.
    #[test]
    fn deja_examine_saute_a_la_relecture() {
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        std::fs::write(d.join("vu"), b"Salon").unwrap();
        std::fs::write(d.join("neuf"), b"Salon").unwrap();
        let m = marque(&d, false);
        let meta = std::fs::symlink_metadata(d.join("vu")).unwrap();
        // Examiné à l'instant : pas sauté (une écriture par mmap n'a peut-être pas encore changé le ctime).
        m.noter_examine(b"vu", &meta);
        assert!(!m.deja_examine(b"vu", &meta));
        let il_y_a = Instant::now().checked_sub(FENETRE_MMAP).unwrap();
        m.noter_examine_a(b"vu", &meta, il_y_a, true);
        assert!(m.deja_examine(b"vu", &meta));
        // N1 : un non-vérifié est sauté un temps, puis réexaminé ; un rechargement des sources l'oublie.
        let meta_neuf = std::fs::symlink_metadata(d.join("neuf")).unwrap();
        m.noter_examine_a(b"neuf", &meta_neuf, il_y_a, false);
        assert!(m.deja_examine(b"neuf", &meta_neuf));
        if let Some(vieux) = Instant::now().checked_sub(RELIRE_SOURCES) {
            m.noter_examine_a(b"neuf", &meta_neuf, vieux, false);
            assert!(!m.deja_examine(b"neuf", &meta_neuf), "périmé");
            m.noter_examine_a(b"vu", &meta, vieux, true);
            assert!(m.deja_examine(b"vu", &meta), "un sain ne se périme pas");
            m.noter_examine_a(b"vu", &meta, il_y_a, true);
        }
        m.noter_examine_a(b"neuf", &meta_neuf, il_y_a, false);
        m.oublier_passagers();
        assert!(!m.deja_examine(b"neuf", &meta_neuf));
        assert!(m.deja_examine(b"vu", &meta));
        let attente = (Mutex::new(Attente::new(RESERVE_DIRECT + 10)), Condvar::new());
        let c = Compteurs::default();
        m.perte();
        assert_eq!(relire(0, &m, &attente, &c, Tour::NORMAL), Relu::Fini);
        let noms: Vec<Vec<u8>> = attente.0.lock().unwrap().file.drain(..).map(|e| e.nom).collect();
        assert_eq!(noms, vec![b"neuf".to_vec()]);
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(d.join("vu"), b"Salon2").unwrap();
        let meta = std::fs::symlink_metadata(d.join("vu")).unwrap();
        assert!(!m.deja_examine(b"vu", &meta));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Attend que le relevé remplisse `ok`, `fin` au plus ; rend le dernier relevé.
    fn attendre_releve(s: &Surveillance, fin: Duration, ok: impl Fn(&Releve) -> bool) -> Releve {
        let fin = Instant::now() + fin;
        loop {
            let r = s.releve();
            if ok(&r) || Instant::now() >= fin {
                return r;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// La prochaine menace rendue, `fin` au plus.
    fn attendre_menace(s: &Surveillance, fin: Duration) -> Option<Examine> {
        let fin = Instant::now() + fin;
        while Instant::now() < fin {
            if let Some(x) = s.recevoir() {
                return Some(x);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Défaut 7 (relecture Fable) : un fichier créé par O_TMPFILE puis lié (linkat) donne un événement au nom
    /// anonyme, « parti » ; le dossier est alors relu et le vrai fichier examiné.
    #[test]
    fn vrai_fanotify_o_tmpfile_linkat() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        std::fs::write(ailleurs.join("source"), elf_marque()).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
            None,
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        let st = std::process::Command::new("python3")
            .arg("-I")
            .arg("-c")
            .arg("import os,sys\nd=sys.argv[1]\nfd=os.open(d, os.O_TMPFILE|os.O_WRONLY, 0o644)\nos.write(fd, open(sys.argv[2],'rb').read())\nos.link(f'/proc/self/fd/{fd}', d+'/tmpfile.bin')\nos.close(fd)\n")
            .arg(&d)
            .arg(ailleurs.join("source"))
            .status();
        if !st.is_ok_and(|x| x.success()) {
            drop(s);
            let _ = std::fs::remove_dir_all(&d);
            let _ = std::fs::remove_dir_all(&ailleurs);
            return crate::essais::saute("python3 ou O_TMPFILE indisponible ici");
        }
        let menace = attendre_menace(&s, Duration::from_secs(20));
        let r = s.releve();
        let menace = menace.unwrap_or_else(|| panic!("fichier lié jamais examiné : {r:?}"));
        assert_eq!(menace.chemin, reel.join("tmpfile.bin"));
        assert!(matches!(menace.resultat.verdict(), Verdict::Certain(..)));
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// Fin de pause : ce qui est arrivé pendant la pause (compté non vérifié) est relu et examiné à la reprise.
    #[test]
    fn vrai_fanotify_fin_de_pause_relue() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        std::fs::write(ailleurs.join("source"), elf_marque()).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
            None,
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        s.mettre_en_pause(true);
        let cp = std::process::Command::new("cp")
            .arg(ailleurs.join("source"))
            .arg(d.join("en-pause.bin"))
            .status()
            .unwrap();
        assert!(cp.success());
        let r = attendre_releve(&s, Duration::from_secs(10), |r| r.en_pause > 0);
        assert!(r.en_pause > 0, "{r:?}");
        assert!(s.recevoir().is_none());
        s.mettre_en_pause(false);
        let menace = attendre_menace(&s, Duration::from_secs(20));
        let r = s.releve();
        let menace = menace.unwrap_or_else(|| panic!("fichier de la pause jamais examiné : {r:?}"));
        assert_eq!(menace.chemin, reel.join("en-pause.bin"));
        assert!(r.repris > 0, "{r:?}");
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// G (relecture AV5) : un fichier arrivé pendant l'arrêt du veilleur (avant la marque) est examiné au démarrage ;
    /// pendant cette relecture, le temps réel ne se dit pas à jour.
    #[test]
    fn vrai_fanotify_arrive_pendant_l_arret() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        std::fs::write(d.join("pendant-l-arret.bin"), elf_marque()).unwrap();
        std::fs::write(d.join("ancien.txt"), b"Salon").unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
            Some(secondes().saturating_sub(MARGE_RELECTURE)),
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        assert_eq!(s.vu_jusqu_a(), None);
        let mut vus = Vec::new();
        let fin = Instant::now() + Duration::from_secs(30);
        while vus.is_empty() && Instant::now() < fin {
            match s.recevoir() {
                Some(x) => vus.push(x),
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        assert_eq!(vus.len(), 1, "{:?}", s.releve());
        assert_eq!(vus[0].chemin, reel.join("pendant-l-arret.bin"));
        assert!(matches!(vus[0].resultat.verdict(), Verdict::Certain(..)));
        let fin = Instant::now() + Duration::from_secs(10);
        while s.vu_jusqu_a().is_none() && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(s.vu_jusqu_a().is_some(), "{:?}", s.releve());
        let r = s.releve();
        assert_eq!(r.repris, 2, "{r:?}");
        assert!(r.relectures.is_empty() && !r.en_retard(), "{r:?}");
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A (relecture AV5) : une inondation de fichiers sains par un autre processus remplit la file ; la menace
    /// déposée juste après n'y entre pas, mais la relecture la reprend et elle est examinée. Le temps réel n'est plus
    /// aveuglé par une rafale.
    #[test]
    fn vrai_fanotify_inondation_puis_menace() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let ailleurs = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        std::fs::write(ailleurs.join("source"), elf_marque()).unwrap();
        let s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
            None,
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        let inonder = std::process::Command::new("sh")
            .arg("-c")
            .arg(r#"cd "$1" && i=0 && while [ $i -lt 400 ]; do echo Salon > "sain-$i.txt"; i=$((i+1)); done && cp "$2" menace.bin"#)
            .arg("sh")
            .arg(&d)
            .arg(ailleurs.join("source"))
            .status()
            .unwrap();
        assert!(inonder.success());
        let fin = Instant::now() + Duration::from_secs(90);
        let mut menace = None;
        while menace.is_none() && Instant::now() < fin {
            match s.recevoir() {
                Some(x) => menace = Some(x),
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let r = s.releve();
        let menace = menace.unwrap_or_else(|| panic!("menace jamais examinée : {r:?}"));
        assert_eq!(menace.chemin, reel.join("menace.bin"));
        assert!(r.file_pleine > 0, "l'inondation n'a pas rempli la file : {r:?}");
        assert!(r.repris > 0, "rien n'a été repris par relecture : {r:?}");
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
        let _ = std::fs::remove_dir_all(&ailleurs);
    }

    /// N3 : une perte abandonnée d'avant le redémarrage est reprise par le chemin de son dossier (pas par son nom
    /// montré, qui change avec la langue) ; celle d'un dossier pas marqué cette fois reste dite.
    #[test]
    fn abandons_repris_par_le_chemin() {
        if let Err(e) = Groupe::ouvrir_notification() {
            return crate::essais::saute(&format!("fanotify sans droits refusé par ce noyau : {e}"));
        }
        let d = crate::protection::isoler::dossier_jetable().unwrap();
        let reel = std::fs::canonicalize(&d).unwrap();
        let mut s = match Surveillance::demarrer(
            vec![(reel.clone(), "Salon".into(), false)],
            Box::new(|| (sources_essai(), None)),
            None,
        ) {
            Ok(s) => s,
            Err(e) => return crate::essais::saute(&format!("marque refusée : {e}")),
        };
        let ailleurs = PathBuf::from("/nulle-part/alice");
        s.reprendre_abandons(
            &["Living room".into(), "Alice".into()],
            &[reel.clone(), ailleurs.clone()],
        );
        let r = s.releve();
        assert_eq!(r.abandons, vec!["Salon".to_string(), "Alice".to_string()]);
        assert_eq!(r.abandons_chemins, vec![reel, ailleurs]);
        drop(s);
        let _ = std::fs::remove_dir_all(&d);
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
            None,
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
            None,
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
            None,
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
