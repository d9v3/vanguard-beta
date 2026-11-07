//! Le service du garde (`vanguard garde-servir`, lancé par systemd seulement, en root avec CAP_SYS_ADMIN).
//!
//! Les fils :
//! - le LECTEUR (le fil principal) lit le groupe fanotify, et n'ouvre jamais de fichier : une ouverture par le garde
//!   dans un système de fichiers marqué pourrait produire sa propre demande. Il bat le chien de garde : il ne fait
//!   donc aucun appel qui puisse attendre un système de fichiers (L-2), pas même un fstat. Il permet tout de suite ses
//!   propres lancements, met chaque autre demande en attente et la confie au tri ;
//! - le fil du TRI lit la clé du fichier (fstat, fstatfs), permet tout de suite ce que le cache sait propre (servi en
//!   premier), et confie le reste à la file des fils de décision ; s'il reste pris, le délai permet ce qui attend, et
//!   sa file pleine, le lecteur permet et confie au rattrapage ;
//! - deux fils de DÉCISION hachent le descripteur rendu par le noyau (borné à 64 Mio, au-delà : permis et noté) et
//!   jugent (`decision`) ; leur nombre borne les hachages concurrents ;
//! - le fil du DÉLAI permet toute demande sans verdict après 250 ms (P9), et la note ; elle reste dans la file et
//!   est jugée quand même : son verdict va au cache, et un fichier certain passé ainsi est dit (alerte haute) ;
//! - le fil de RATTRAPAGE juge de même, après coup, les demandes permises parce que la file était pleine ; sa file à
//!   lui est courte, et pleine, la demande n'est que comptée (le travail d'après coup reste borné) ;
//! - le fil d'ENTRETIEN marque les montages faits plus tard, relit les réglages, écrit etat.json et evenements.jsonl,
//!   et envoie WATCHDOG=1 tant que le lecteur bat (un lecteur figé : systemd tue le garde, et la fermeture du groupe
//!   laisse passer tout ce qui attend) ; il n'attend jamais rien du dossier du compte ;
//! - un fil des LISTES, lancé par l'entretien, relit l'ensemble CERTAIN dans le dossier du compte (openat2) ; s'il
//!   reste bloqué, l'entretien le dit, puis l'abandonne et en lance un autre, au plus `LECTEURS_MAX` en vie. Ce qui
//!   est lu s'ajoute à l'union gardée en root (`listes::unir`), relue avant READY=1 au démarrage ;
//! - le fil des SIGNAUX : à SIGTERM, tout ce qui attend est permis, puis le garde sort.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::machine::linux::fanotify::{self, Groupe, Marques, Montages, lecture};

use super::attente::{Attentes, DELAI};
use super::cache::{Cache, Cle, Connu};
use super::decision::{self, Certitude, Exception, Faits, Lancement, Mode, Verdict};
use super::listes::{self, Certain, Hache};
use super::notifier::Notifier;
use super::sortie::{self, Compteurs, Etat, Evenement};
use super::{LISTE_MD5, LISTE_SHA256, Reglages};
use crate::tr;

/// Un fichier plus gros n'est pas haché à temps : permis, noté « non vérifié ».
pub(crate) const HACHAGE_MAX: u64 = 64 << 20;
/// Les fils de décision.
const DECIDEURS: usize = 2;
/// La file vers les fils de décision ; pleine, la demande est permise, notée, et confiée au rattrapage.
const FILE: usize = 256;
/// La file du rattrapage (un seul fil) ; pleine, la demande permise n'est que comptée.
const RATTRAPAGE: usize = 32;
/// Les événements gardés en mémoire avant d'être écrits ; au-delà, ils sont comptés sans être écrits.
const EVENEMENTS_EN_FILE: usize = 1024;
/// Le lecteur bat au moins toutes ces millisecondes.
const BATTEMENT_MS: i32 = 500;
/// Un lecteur muet depuis plus longtemps n'envoie plus WATCHDOG=1 (WatchdogSec=5).
const LECTEUR_MUET: Duration = Duration::from_secs(3);
/// Les listes sont regardées à cette fréquence (leur date et leur taille), les réglages à chaque seconde.
const LISTES_TOUTES_LES: Duration = Duration::from_secs(5);

/// Les codes de sortie.
const SORTIE_ARRET: i32 = 0;
const SORTIE_PAS_ROOT: i32 = 2;
const SORTIE_GROUPE: i32 = 3;
const SORTIE_LECTURE: i32 = 4;

/// Les réglages et l'ensemble CERTAIN en vigueur.
#[derive(Default)]
struct Config {
    reglages: Option<Reglages>,
    certain: Certain,
    permises: HashSet<[u8; 32]>,
    vanguard: HashSet<[u8; 32]>,
    alertes: Vec<String>,
    /// Par liste (SHA-256, MD5) : ce que la dernière liste du compte n'a plus, ce que l'union pleine n'a pas pris.
    retirees: [u64; 2],
    bloquees: [u64; 2],
    /// Par liste : ce que la dernière lecture a ajouté à l'union.
    ajoutees: [u64; 2],
    /// La croissance anormale depuis la dernière pose ou mise à jour (N-1), gardée en root (`CROISSANCE`).
    croissance: u64,
}

impl Config {
    fn mode(&self, maintenant: u64) -> Mode {
        Mode {
            refus: self.reglages.as_ref().is_some_and(|r| r.refus),
            en_pause: self.reglages.as_ref().is_some_and(|r| r.en_pause(maintenant)),
        }
    }
}

#[derive(Default)]
struct Compteurs2 {
    demandes: AtomicU64,
    cache: AtomicU64,
    hachees: AtomicU64,
    notees: AtomicU64,
    refusees: AtomicU64,
    delais: AtomicU64,
    non_verifiees: AtomicU64,
    file_pleine: AtomicU64,
    debordements: AtomicU64,
    evenements_perdus: AtomicU64,
    certains_passes: AtomicU64,
    rattrapages_perdus: AtomicU64,
}

fn plus(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

impl Compteurs2 {
    fn lire(&self) -> Compteurs {
        let l = |c: &AtomicU64| c.load(Ordering::Relaxed);
        Compteurs {
            demandes: l(&self.demandes),
            cache: l(&self.cache),
            hachees: l(&self.hachees),
            notees: l(&self.notees),
            refusees: l(&self.refusees),
            delais: l(&self.delais),
            non_verifiees: l(&self.non_verifiees),
            file_pleine: l(&self.file_pleine),
            debordements: l(&self.debordements),
            certains_passes: l(&self.certains_passes),
            rattrapages_perdus: l(&self.rattrapages_perdus),
        }
    }
}

/// Ce que les fils partagent.
struct Partage {
    groupe: Groupe,
    attentes: Mutex<Attentes<File>>,
    config: RwLock<Config>,
    cache: Mutex<Cache>,
    compteurs: Compteurs2,
    /// Le dernier tour du lecteur, en millisecondes depuis `debut`.
    battement: AtomicU64,
    debut: Instant,
    evenements: SyncSender<Evenement>,
    arret: AtomicBool,
}

/// Une demande confiée au tri, puis aux fils de décision.
struct Demande {
    fd: i32,
    fichier: Arc<File>,
    pid: i32,
    /// Lue par le tri ou le rattrapage (`preparer`), jamais par le lecteur (L-2) ; `None` : pas encore lue.
    cle: Option<Cle>,
    /// Déjà hachée (en cache, et certaine) : seulement les exceptions et le mode à juger.
    connu: Option<Connu>,
}

fn verrou<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Partage {
    fn noter(&self, e: Evenement) {
        if self.evenements.try_send(e).is_err() {
            plus(&self.compteurs.evenements_perdus);
        }
    }

    /// Répond, si personne ne l'a fait : vrai si c'est cette réponse qui part.
    fn repondre(&self, fd: i32, fichier: &Arc<File>, permettre: bool) -> bool {
        if !verrou(&self.attentes).prendre(fd, fichier) {
            return false;
        }
        let _ = self.groupe.repondre(fichier.as_fd(), permettre, !permettre);
        true
    }

    /// Permet tout ce qui attend (l'arrêt, ou une lecture fautive).
    fn tout_permettre(&self) {
        let restes = verrou(&self.attentes).toutes();
        for (_, f) in restes {
            let _ = self.groupe.repondre(f.as_fd(), true, false);
        }
    }

    fn battre(&self) {
        let ms = u64::try_from(self.debut.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.battement.store(ms, Ordering::Relaxed);
    }

    fn lecteur_muet(&self) -> bool {
        let dernier = Duration::from_millis(self.battement.load(Ordering::Relaxed));
        self.debut.elapsed().saturating_sub(dernier) > LECTEUR_MUET
    }
}

fn evenement(genre: &str) -> Evenement {
    Evenement {
        t: super::maintenant(),
        genre: genre.into(),
        ..Evenement::default()
    }
}

/// Le chemin d'un descripteur, tel que le noyau le donne (readlink n'ouvre rien).
fn chemin_de(fd: i32) -> String {
    std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Le nom (comm) d'un processus, pour l'affichage seulement : le processus le choisit (`prctl`), il ne décide rien.
fn nom_de(pid: i32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|n| n.trim_end().to_string())
        .unwrap_or_default()
}

/// Un lecteur de `fichier` par position (pread), borné à sa taille : la position du descripteur n'est jamais partagée.
struct ParPosition<'a> {
    fichier: &'a File,
    position: u64,
    fin: u64,
}

impl Read for ParPosition<'_> {
    fn read(&mut self, tampon: &mut [u8]) -> std::io::Result<usize> {
        let reste = usize::try_from(self.fin.saturating_sub(self.position)).unwrap_or(usize::MAX);
        let n = tampon.len().min(reste);
        let Some(morceau) = tampon.get_mut(..n) else {
            return Ok(0);
        };
        if morceau.is_empty() {
            return Ok(0);
        }
        let lu = self.fichier.read_at(morceau, self.position)?;
        self.position = self.position.saturating_add(u64::try_from(lu).unwrap_or(u64::MAX));
        Ok(lu)
    }
}

/// La clé d'un fichier lancé, lue sur son descripteur (fstat, fstatfs) : ces appels peuvent attendre le système de
/// fichiers, ils ne se font jamais sur le fil lecteur (L-2). `None` : illisible.
fn cle_de(fichier: &File) -> Option<Cle> {
    let m = fichier.metadata().ok()?;
    Some(Cle {
        dev: m.dev(),
        ino: m.ino(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
        taille: m.size(),
        // Un appel de plus par lancement, sans attente : le type du système de fichiers du fichier lui-même.
        fiable: super::cache::ctime_fiable(super::ouvrir::type_fs(fichier.as_fd()).ok()),
    })
}

/// Lit la clé de la demande (si ce n'est fait) et y cherche le verdict au cache. Faux : la demande est répondue
/// (permise : propre en cache, ou illisible) ; vrai : elle reste à juger.
fn preparer(p: &Partage, d: &mut Demande) -> bool {
    let cle = if let Some(c) = d.cle {
        c
    } else {
        let Some(c) = cle_de(&d.fichier) else {
            plus(&p.compteurs.non_verifiees);
            p.repondre(d.fd, &d.fichier, true);
            return false;
        };
        d.cle = Some(c);
        c
    };
    let connu = verrou(&p.cache).lire(&cle);
    if connu.is_some_and(|c| c.certain.is_none()) {
        plus(&p.compteurs.cache);
        p.repondre(d.fd, &d.fichier, true);
        return false;
    }
    d.connu = connu;
    true
}

/// Confie une demande à `vers` (le tri, ou les fils de décision) ; sa file pleine, elle est permise sans attendre (P9)
/// et confiée au rattrapage, qui la juge après coup (M-N2) ; la file du rattrapage pleine, elle n'est que comptée.
/// Rien ici n'attend un système de fichiers : le lecteur s'en sert.
fn confier(p: &Partage, d: Demande, vers: &SyncSender<Demande>, vers_rattrapage: &SyncSender<Demande>) {
    if let Err(TrySendError::Full(d) | TrySendError::Disconnected(d)) = vers.try_send(d) {
        plus(&p.compteurs.file_pleine);
        if p.repondre(d.fd, &d.fichier, true) {
            let mut e = evenement("file-pleine");
            e.pid = d.pid;
            p.noter(e);
        }
        if vers_rattrapage.try_send(d).is_err() {
            plus(&p.compteurs.rattrapages_perdus);
        }
    }
}

/// Le fil du tri.
fn trier(
    p: &Partage,
    file: &Receiver<Demande>,
    vers_decideurs: &SyncSender<Demande>,
    vers_rattrapage: &SyncSender<Demande>,
) {
    while let Ok(mut d) = file.recv() {
        if preparer(p, &mut d) {
            confier(p, d, vers_decideurs, vers_rattrapage);
        }
    }
}

/// Juge une demande et y répond, si personne ne l'a fait. Déjà permise (le délai, la file pleine), elle est jugée
/// quand même : le verdict va au cache (le lancement suivant est jugé tout de suite), et un fichier certain qui aurait
/// été refusé est compté (`certains_passes`, alerte haute) et noté.
fn decider(p: &Partage, d: &Demande) {
    let Some(cle) = d.cle else {
        // Jamais : `preparer` la lit avant.
        p.repondre(d.fd, &d.fichier, true);
        return;
    };
    let connu = if let Some(c) = d.connu {
        c
    } else {
        if cle.taille > HACHAGE_MAX {
            plus(&p.compteurs.non_verifiees);
            if p.repondre(d.fd, &d.fichier, true) {
                let mut e = evenement("non-verifie");
                e.pid = d.pid;
                e.chemin = sortie::borner(&chemin_de(d.fd));
                e.taille = Some(cle.taille);
                p.noter(e);
            }
            return;
        }
        let lecteur = ParPosition {
            fichier: &d.fichier,
            position: 0,
            fin: cle.taille,
        };
        let Some(h) = listes::hacher(lecteur) else {
            plus(&p.compteurs.non_verifiees);
            p.repondre(d.fd, &d.fichier, true);
            return;
        };
        plus(&p.compteurs.hachees);
        let c = juger_hache(p, &h);
        verrou(&p.cache).noter(cle, c);
        c
    };
    let Some(certitude) = connu.certain else {
        p.repondre(d.fd, &d.fichier, true);
        return;
    };
    let chemin = chemin_de(d.fd);
    let nom = nom_de(d.pid);
    let (verdict, de_vanguard) = {
        let config = p.config.read().unwrap_or_else(PoisonError::into_inner);
        let de_vanguard = config.vanguard.contains(&connu.sha256);
        let faits = Faits {
            certain: Some(certitude),
            permise: config.permises.contains(&connu.sha256),
            exception: None,
        };
        let mode = config.mode(super::maintenant());
        (decision::juger(faits, mode), de_vanguard)
    };
    // Les exceptions ne sont cherchées que pour ce qui serait noté (rare) : elles lisent /proc.
    let verdict = match verdict {
        Verdict::Observe(cert) | Verdict::Refuse(cert) => {
            let meta = d.fichier.metadata().ok();
            let lancement = Lancement {
                chemin: &chemin,
                uid: meta.as_ref().map_or(u32::MAX, MetadataExt::uid),
                mode: meta.as_ref().map_or(0o777, MetadataExt::mode),
                de_vanguard,
                pid: u32::try_from(d.pid).unwrap_or(u32::MAX),
            };
            match decision::exception(&lancement) {
                Some(x) => Verdict::Epargne(cert, x),
                None => verdict,
            }
        }
        autre => autre,
    };
    let a_temps = p.repondre(d.fd, &d.fichier, verdict.permet());
    plus(&p.compteurs.notees);
    if a_temps && !verdict.permet() {
        plus(&p.compteurs.refusees);
    }
    if !a_temps && !verdict.permet() {
        plus(&p.compteurs.certains_passes);
    }
    let mut e = evenement(if a_temps { verdict.nom() } else { "delai" });
    e.certitude = Some(nom_certitude(certitude).into());
    e.exception = match verdict {
        Verdict::Epargne(_, x) => Some(nom_exception(x).into()),
        _ => None,
    };
    e.pid = d.pid;
    e.chemin = sortie::borner(&chemin);
    e.sha256 = crate::protection::empreintes::hex(&connu.sha256);
    if !a_temps {
        e.trop_tard = Some(verdict.nom().into());
    }
    if !nom.is_empty() {
        e.lanceur = Some(sortie::borner(&nom));
    }
    p.noter(e);
}

fn juger_hache(p: &Partage, h: &Hache) -> Connu {
    let config = p.config.read().unwrap_or_else(PoisonError::into_inner);
    Connu {
        sha256: h.sha256,
        certain: config.certain.juger(h),
    }
}

fn nom_certitude(c: Certitude) -> &'static str {
    match c {
        Certitude::Liste => "liste",
        Certitude::Essai => "essai",
    }
}

fn nom_exception(e: Exception) -> &'static str {
    match e {
        Exception::Systeme => "systeme",
        Exception::Vanguard => "vanguard",
        Exception::Critique => "critique",
    }
}

/// Un fil de décision.
fn decideur(p: &Partage, file: &Mutex<Receiver<Demande>>) {
    loop {
        let d = verrou(file).recv();
        match d {
            Ok(d) => decider(p, &d),
            Err(_) => return,
        }
    }
}

/// Le fil du rattrapage : les demandes permises par la file pleine, jugées après coup, une à la fois.
fn rattraper(p: &Partage, file: &Receiver<Demande>) {
    while let Ok(mut d) = file.recv() {
        if preparer(p, &mut d) {
            decider(p, &d);
        }
    }
}

/// Le fil du délai.
fn delai(p: &Partage) {
    while !p.arret.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(25));
        let retard = verrou(&p.attentes).en_retard(Instant::now(), DELAI);
        for (fd, f) in retard {
            let _ = p.groupe.repondre(f.as_fd(), true, false);
            plus(&p.compteurs.delais);
            let mut e = evenement("delai");
            e.chemin = sortie::borner(&chemin_de(fd));
            p.noter(e);
        }
    }
}

/// La signature d'un fichier, pour savoir s'il a changé.
/// mtime (s, ns), inode, taille.
type Signature = (i64, i64, u64, u64);

fn signature(chemin: &Path) -> Option<Signature> {
    let m = std::fs::symlink_metadata(chemin).ok()?;
    Some((m.mtime(), m.mtime_nsec(), m.ino(), m.len()))
}

/// Une lecture des listes, faite dans un fil à part.
struct ListesLues {
    dossier: PathBuf,
    compte: u32,
    resultats: Vec<Result<(listes::Signature, Option<listes::ListeSha256>), String>>,
}

/// Relit les réglages (s'ils ont changé) et les listes (si elles ont changé, ou leur dossier) ; vide le cache.
///
/// Les listes sont dans le dossier personnel du compte, qu'il contrôle : leur lecture peut bloquer (un montage qui ne
/// répond plus, quoi qu'openat2 refuse d'en traverser). Elle se fait donc dans un fil à part, un seul à la fois ;
/// l'entretien n'attend jamais sa réponse et continue d'envoyer WATCHDOG=1. Une lecture sans réponse depuis
/// `LISTES_DELAI` est dite dans etat.json ; les listes d'avant restent en vigueur.
struct Relecture {
    reglages: Option<Signature>,
    /// Le dossier, le compte et l'identité des deux listes lues la dernière fois.
    listes: Option<(PathBuf, u32, [Option<listes::Signature>; 2])>,
    derniere: Option<Instant>,
    en_cours: Option<(Receiver<ListesLues>, Instant)>,
    /// Le dossier de l'union, à root (DOSSIER_ETAT).
    union: PathBuf,
    /// Les fils des listes en vie, abandonnés compris.
    vivants: Arc<AtomicUsize>,
}

/// Une lecture des listes sans réponse depuis plus longtemps est dite.
const LISTES_DELAI: Duration = Duration::from_secs(10);
/// … et abandonnée, depuis plus longtemps encore : une autre peut partir (son fil reste compté tant qu'il vit).
const LISTES_ABANDON: Duration = Duration::from_secs(30);
/// Les fils des listes en vie, au plus : un gelé et un neuf. Chacun peut tenir deux listes en mémoire (MemoryMax).
const LECTEURS_MAX: usize = 2;

/// Un fil des listes en vie : compté à sa création, décompté quand il se termine (ou s'il n'a pas pu partir).
struct Vivant(Arc<AtomicUsize>);

impl Vivant {
    /// Un de plus, s'il en reste la place.
    fn prendre(vivants: &Arc<AtomicUsize>) -> Option<Vivant> {
        vivants
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < LECTEURS_MAX).then(|| n.saturating_add(1))
            })
            .ok()
            .map(|_| Vivant(Arc::clone(vivants)))
    }
}

impl Drop for Vivant {
    fn drop(&mut self) {
        let _ = self
            .0
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| Some(n.saturating_sub(1)));
    }
}

/// Ce que l'entretien fait d'une lecture sans réponse depuis `attente` : la dire, l'abandonner (f2).
fn sans_reponse(attente: Duration) -> (bool, bool) {
    (attente > LISTES_DELAI, attente > LISTES_ABANDON)
}

/// Les deux listes, dans l'ordre des résultats d'une lecture : SHA-256, puis MD5.
const NOMS: [&str; 2] = [LISTE_SHA256, LISTE_MD5];

fn liste_de(c: &Certain, i: usize) -> Option<&listes::ListeSha256> {
    if i == 0 { c.sha256.as_ref() } else { c.md5.as_ref() }
}

fn poser_liste(c: &mut Certain, i: usize, l: listes::ListeSha256) {
    if i == 0 {
        c.sha256 = Some(l);
    } else {
        c.md5 = Some(l);
    }
}

impl Relecture {
    fn nouvelle(union: PathBuf) -> Relecture {
        Relecture {
            reglages: None,
            listes: None,
            derniere: None,
            en_cours: None,
            union,
            vivants: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// L'union gardée en root, relue avant READY=1 (f1) : un disque local à root, jamais le dossier du compte, donc
    /// sans attente possible de lui. Les listes du compte s'y ajoutent ensuite.
    fn charger_union(&self, p: &Partage) {
        let ([sha256, md5], mut alertes) = listes::charger_union(&self.union, NOMS);
        let (croissance, alerte) = listes::charger_croissance(&self.union, super::CROISSANCE);
        alertes.extend(alerte);
        let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
        c.certain = Certain { sha256, md5 };
        c.croissance = croissance;
        // Préfixe « union » : ces alertes-là restent (celles des listes du compte sont remplacées à chaque lecture).
        c.alertes.extend(alertes.into_iter().map(|a| format!("union {a}")));
    }

    /// Les réglages (/etc/vanguard, à root) : relus tout de suite s'ils ont changé. Vrai s'ils ont changé.
    fn relire_reglages(&mut self, p: &Partage, premiere: bool) -> bool {
        let sig = signature(Path::new(super::REGLAGES));
        if !premiere && sig == self.reglages {
            return false;
        }
        self.reglages = sig;
        let lus = crate::socle::lire_ordinaire(Path::new(super::REGLAGES), super::REGLAGES_TAILLE_MAX)
            .ok()
            .and_then(|o| String::from_utf8(o).ok())
            .and_then(|t| Reglages::lire(&t));
        let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
        c.alertes.retain(|a| !a.starts_with("reglages"));
        if lus.is_none() {
            c.alertes.push(format!(
                "reglages: {} absent ou illisible (observation)",
                super::REGLAGES
            ));
        }
        let empreintes = |v: &[String]| v.iter().filter_map(|e| super::empreinte_de(e)).collect();
        c.permises = lus.as_ref().map(|r| empreintes(&r.permises)).unwrap_or_default();
        c.vanguard = lus.as_ref().map(|r| empreintes(&r.vanguard)).unwrap_or_default();
        c.reglages = lus;
        drop(c);
        verrou(&p.cache).vider();
        true
    }

    /// Un tour de l'entretien : jamais bloquant.
    fn faire(&mut self, p: &Partage) {
        if self.relire_reglages(p, false) {
            // D'autres réglages : les listes sont relues en entier.
            self.listes = None;
            self.derniere = None;
        }
        if let Some((recu, depuis)) = &self.en_cours {
            match recu.try_recv() {
                Ok(lues) => {
                    self.en_cours = None;
                    self.appliquer(p, lues);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    let attente = depuis.elapsed();
                    let (dire, abandonner) = sans_reponse(attente);
                    if dire {
                        alerter_listes(
                            p,
                            vec![format!(
                                "liste: lecture sans réponse depuis {} s (listes d'avant en vigueur)",
                                attente.as_secs()
                            )],
                        );
                    }
                    if !abandonner {
                        return;
                    }
                    // Abandonnée : son fil reste compté dans `vivants` tant qu'il vit ; une autre lecture peut partir.
                    self.en_cours = None;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => self.en_cours = None,
            }
        }
        if self.derniere.is_some_and(|d| d.elapsed() < LISTES_TOUTES_LES) {
            return;
        }
        self.derniere = Some(Instant::now());
        let (compte, dossier) = {
            let c = p.config.read().unwrap_or_else(PoisonError::into_inner);
            match &c.reglages {
                Some(r) => (r.compte, PathBuf::from(&r.listes)),
                None => return,
            }
        };
        let avant = match &self.listes {
            Some((d, c, sigs)) if *d == dossier && *c == compte => *sigs,
            _ => [None, None],
        };
        let Some(vivant) = Vivant::prendre(&self.vivants) else {
            alerter_listes(
                p,
                vec![format!(
                    "liste: {LECTEURS_MAX} lectures sans réponse, aucune autre n'est lancée (listes d'avant en vigueur)"
                )],
            );
            return;
        };
        let (vers, recu) = std::sync::mpsc::sync_channel(1);
        let lancer = std::thread::Builder::new().name("garde-listes".into()).spawn(move || {
            let _vivant = vivant;
            let resultats = match listes::depart(&dossier, compte) {
                Ok((depart, relatif)) => [LISTE_SHA256, LISTE_MD5]
                    .iter()
                    .zip(avant)
                    .map(|(nom, a)| listes::lire_sous(&depart, &relatif.join(nom), compte, a))
                    .collect(),
                Err(e) => vec![Err(e.clone()), Err(e)],
            };
            let _ = vers.send(ListesLues {
                dossier,
                compte,
                resultats,
            });
        });
        if lancer.is_ok() {
            self.en_cours = Some((recu, Instant::now()));
        }
    }

    /// Met en vigueur ce qu'un fil a lu ; une liste refusée laisse l'ancienne.
    fn appliquer(&mut self, p: &Partage, lues: ListesLues) {
        let a_jour = {
            let c = p.config.read().unwrap_or_else(PoisonError::into_inner);
            c.reglages
                .as_ref()
                .is_some_and(|r| r.compte == lues.compte && Path::new(&r.listes) == lues.dossier)
        };
        if !a_jour {
            // Les réglages ont changé pendant la lecture : la suivante lira le bon dossier.
            return;
        }
        let mut alertes = Vec::new();
        let mut sigs = [None, None];
        let mut changees = false;
        for (i, r) in lues.resultats.into_iter().enumerate().take(2) {
            match r {
                Ok((sig, l)) => {
                    if let Some(s) = sigs.get_mut(i) {
                        *s = Some(sig);
                    }
                    let Some(l) = l else { continue };
                    // M-N1 : la liste du compte s'ajoute à l'union ; ce qu'elle n'a plus reste, et est compté. Seul
                    // l'entretien change l'ensemble : l'union lue ici est encore celle en vigueur à l'écriture.
                    let u = {
                        let c = p.config.read().unwrap_or_else(PoisonError::into_inner);
                        listes::unir(liste_de(&c.certain, i), l, listes::union_max())
                    };
                    if let Some(nouvelle) = u.liste {
                        if let Some(nom) = NOMS.get(i) {
                            // N-1 : un ajout bien au-delà de la croissance normale depuis la dernière (la date de
                            // l'union, à root) est compté et gardé ; il est dit jusqu'à la prochaine mise à jour.
                            let depuis = std::fs::metadata(self.union.join(nom))
                                .and_then(|m| m.modified())
                                .ok()
                                .and_then(|t| t.elapsed().ok());
                            let anormale = listes::croissance_anormale(u.ajoutees, depuis);
                            if anormale > 0 {
                                let total = {
                                    let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
                                    c.croissance = c.croissance.saturating_add(anormale);
                                    c.croissance
                                };
                                if let Err(e) = listes::ecrire_croissance(&self.union, super::CROISSANCE, total) {
                                    alertes
                                        .push(format!("liste: {}: {e}", self.union.join(super::CROISSANCE).display()));
                                }
                            }
                            if let Err(e) = listes::ecrire_union(&self.union, nom, &nouvelle) {
                                alertes.push(format!("liste: {}: {e}", self.union.join(nom).display()));
                            }
                        }
                        changees = true;
                        let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
                        poser_liste(&mut c.certain, i, nouvelle);
                    }
                    let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
                    let c = &mut *c;
                    if let (Some(r), Some(b), Some(a)) =
                        (c.retirees.get_mut(i), c.bloquees.get_mut(i), c.ajoutees.get_mut(i))
                    {
                        (*r, *b, *a) = (u.retirees, u.bloquees, u.ajoutees);
                    }
                }
                Err(e) => alertes.push(format!("liste: {e}")),
            }
        }
        self.listes = Some((lues.dossier, lues.compte, sigs));
        alerter_listes(p, alertes);
        if changees {
            verrou(&p.cache).vider();
        }
    }
}

/// Remplace les alertes des listes.
fn alerter_listes(p: &Partage, alertes: Vec<String>) {
    let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
    c.alertes.retain(|a| !a.starts_with("liste"));
    c.alertes.extend(alertes);
}

/// Écrit etat.json d'un coup.
fn ecrire_etat(p: &Partage, demarre: u64, marques: &Marques) {
    let (
        refus,
        pause_jusqu_a,
        certain,
        mut alertes,
        listes_retirees,
        listes_bloquees,
        listes_ajoutees,
        listes_croissance,
    ) = {
        let c = p.config.read().unwrap_or_else(PoisonError::into_inner);
        let somme = |v: [u64; 2]| v.iter().fold(0u64, |a, n| a.saturating_add(*n));
        (
            c.reglages.as_ref().is_some_and(|r| r.refus),
            c.reglages.as_ref().and_then(|r| r.pause_jusqu_a),
            u64::try_from(c.certain.nombre()).unwrap_or(u64::MAX),
            c.alertes.clone(),
            somme(c.retirees),
            somme(c.bloquees),
            somme(c.ajoutees),
            c.croissance,
        )
    };
    alertes.extend(
        marques
            .echecs
            .iter()
            .take(16)
            .map(|(point, e)| format!("marque: {}: {e}", sortie::borner(point))),
    );
    let perdus = p.compteurs.evenements_perdus.load(Ordering::Relaxed);
    if perdus > 0 {
        alertes.push(format!("evenements: {perdus} non écrits (file pleine)"));
    }
    let debut_ms = p.battement.load(Ordering::Relaxed);
    let etat = Etat {
        version: env!("CARGO_PKG_VERSION").into(),
        pid: std::process::id(),
        demarre,
        battement: demarre.saturating_add(debut_ms / 1000),
        refus,
        pause_jusqu_a,
        certain,
        alertes,
        marques: u64::try_from(marques.marques.len()).unwrap_or(u64::MAX),
        compteurs: p.compteurs.lire(),
        listes_retirees,
        listes_bloquees,
        listes_ajoutees,
        listes_croissance,
    };
    let Ok(texte) = serde_json::to_vec(&etat) else {
        return;
    };
    // 0644 par l'UMask=0022 de l'unité : le compte le lit. Sur /run (tmpfs), l'écriture jusqu'au disque ne coûte rien.
    let _ = crate::socle::ecrire_atomique(Path::new(super::ETAT), texte);
}

/// Le fil d'entretien.
fn entretien(
    p: &Partage,
    evenements: &Receiver<Evenement>,
    notifier: &Notifier,
    mut marques: Marques,
    mut relecture: Relecture,
) {
    let demarre = super::maintenant();
    let mut montages = Montages::ouvrir().ok();
    while !p.arret.load(Ordering::Relaxed) {
        let change = if let Some(m) = &montages {
            m.attendre(1000).unwrap_or(false)
        } else {
            std::thread::sleep(Duration::from_secs(1));
            false
        };
        if change
            && let Some(m) = &mut montages
            && let Ok(info) = m.lire()
        {
            marques.oublier_demontes(&info);
            for nouveau in marques.completer(&p.groupe, &info) {
                let mut e = evenement("montage");
                e.chemin = sortie::borner(&nouveau.point);
                e.systeme = Some(nouveau.genre);
                p.noter(e);
            }
        }
        relecture.faire(p);
        let mut lignes = String::new();
        while let Ok(e) = evenements.try_recv() {
            lignes.push_str(&sortie::ligne(&e));
        }
        if !lignes.is_empty() {
            let _ = sortie::ajouter(
                Path::new(super::EVENEMENTS),
                Path::new(super::EVENEMENTS_ANCIENS),
                &lignes,
            );
        }
        ecrire_etat(p, demarre, &marques);
        if !p.lecteur_muet() {
            notifier.envoyer("WATCHDOG=1");
        }
    }
}

/// Le masque des signaux d'arrêt, posé avant de créer les fils (qui en héritent) : seul le fil des signaux les reçoit.
// FFI de libc : sigemptyset, sigaddset et pthread_sigmask sur un sigset_t à nous.
#[allow(unsafe_code)]
fn masquer_arret() -> std::io::Result<libc::sigset_t> {
    // SAFETY: sigset_t n'a que des entiers, valide à zéro ; sigemptyset l'initialise avant tout usage.
    let mut ensemble: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `ensemble` est à nous, vivant pendant les appels ; les numéros de signaux sont valides ;
    // pthread_sigmask ne garde aucun pointeur, et l'ancien masque n'est pas demandé (null).
    let r = unsafe {
        libc::sigemptyset(&raw mut ensemble);
        libc::sigaddset(&raw mut ensemble, libc::SIGTERM);
        libc::sigaddset(&raw mut ensemble, libc::SIGINT);
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const ensemble, std::ptr::null_mut())
    };
    if r == 0 {
        Ok(ensemble)
    } else {
        Err(std::io::Error::from_raw_os_error(r))
    }
}

/// Attend un signal du masque.
// FFI de libc : sigwait sur un sigset_t à nous.
#[allow(unsafe_code)]
fn attendre_signal(ensemble: &libc::sigset_t) -> i32 {
    let mut signal: libc::c_int = 0;
    // SAFETY: `ensemble` et `signal` sont à nous, vivants pendant l'appel ; sigwait n'en garde rien.
    let r = unsafe { libc::sigwait(ensemble, &raw mut signal) };
    if r == 0 { signal } else { 0 }
}

/// Le service. Rend le code de sortie.
pub(crate) fn servir() -> i32 {
    if crate::socle::euid() != 0 {
        eprintln!(
            "{}",
            tr!(
                "vanguard garde-servir est lancé par systemd (vanguard-garde.service), en root seulement.",
                "vanguard garde-servir is started by systemd (vanguard-garde.service), as root only."
            )
        );
        return SORTIE_PAS_ROOT;
    }
    let notifier = Notifier::depuis_environnement();
    let ensemble = match masquer_arret() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("garde: masque des signaux: {e}");
            return SORTIE_GROUPE;
        }
    };
    let groupe = match Groupe::ouvrir(true) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("garde: fanotify_init: {e}");
            return SORTIE_GROUPE;
        }
    };
    let (vers_sortie, evenements) = std::sync::mpsc::sync_channel(EVENEMENTS_EN_FILE);
    let p = Arc::new(Partage {
        groupe,
        attentes: Mutex::new(Attentes::default()),
        config: RwLock::new(Config::default()),
        cache: Mutex::new(Cache::default()),
        compteurs: Compteurs2::default(),
        battement: AtomicU64::new(0),
        debut: Instant::now(),
        evenements: vers_sortie,
        arret: AtomicBool::new(false),
    });
    // Les réglages et l'union des listes reçues (à root, sur un disque local) avant la première marque : le mode et
    // l'ensemble CERTAIN d'avant sont en vigueur dès la première demande (f1). Les listes du compte, dans son dossier,
    // viennent après READY=1, dans un fil à part : un dossier qui ne répond pas laisse le garde vivant, avec l'union.
    let mut relecture = Relecture::nouvelle(PathBuf::from(super::DOSSIER_ETAT));
    relecture.relire_reglages(&p, true);
    relecture.charger_union(&p);
    let mut marques = Marques::default();
    let info = Montages::ouvrir().and_then(|mut m| m.lire()).unwrap_or_default();
    marques.completer(&p.groupe, &info);
    if marques.marques.is_empty() {
        eprintln!("garde: aucun système de fichiers marqué");
        return SORTIE_GROUPE;
    }
    let mut e = evenement("demarrage");
    e.demarrage = Some(sortie::Demarrage {
        marques: u64::try_from(marques.marques.len()).unwrap_or(u64::MAX),
        refuses: u64::try_from(marques.echecs.len()).unwrap_or(u64::MAX),
        pidfd: p.groupe.options.pidfd,
        audit: p.groupe.options.audit,
    });
    p.noter(e);

    let (vers_decideurs, file) = std::sync::mpsc::sync_channel::<Demande>(FILE);
    let file = Arc::new(Mutex::new(file));
    for _ in 0..DECIDEURS {
        let (p, file) = (Arc::clone(&p), Arc::clone(&file));
        std::thread::spawn(move || decideur(&p, &file));
    }
    let (vers_rattrapage, rattrapage) = std::sync::mpsc::sync_channel::<Demande>(RATTRAPAGE);
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || rattraper(&p, &rattrapage));
    }
    let (vers_tri, tri) = std::sync::mpsc::sync_channel::<Demande>(FILE);
    {
        let (p, vers_rattrapage) = (Arc::clone(&p), vers_rattrapage.clone());
        std::thread::spawn(move || trier(&p, &tri, &vers_decideurs, &vers_rattrapage));
    }
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || delai(&p));
    }
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || {
            let notifier = Notifier::depuis_environnement();
            entretien(&p, &evenements, &notifier, marques, relecture);
        });
    }
    {
        let p = Arc::clone(&p);
        std::thread::spawn(move || {
            loop {
                let s = attendre_signal(&ensemble);
                if s == libc::SIGTERM || s == libc::SIGINT {
                    break;
                }
            }
            p.arret.store(true, Ordering::Relaxed);
            Notifier::depuis_environnement().envoyer("STOPPING=1");
            p.tout_permettre();
            // La fermeture du groupe, à la sortie, permet ce qui a été lu sans être encore en attente.
            std::process::exit(SORTIE_ARRET);
        });
    }
    p.battre();
    notifier.envoyer("READY=1");
    lire(&p, &vers_tri, &vers_rattrapage)
}

/// Le fil lecteur ; ne rend la main que sur une lecture fautive.
fn lire(p: &Partage, vers_tri: &SyncSender<Demande>, vers_rattrapage: &SyncSender<Demande>) -> i32 {
    let moi = i32::try_from(std::process::id()).unwrap_or(-1);
    let mut tampon = vec![0u8; fanotify::TAMPON];
    loop {
        p.battre();
        match p.groupe.attendre(BATTEMENT_MS) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => {
                eprintln!("garde: poll: {e}");
                p.tout_permettre();
                return SORTIE_LECTURE;
            }
        }
        let n = match p.groupe.lire(&mut tampon) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                eprintln!("garde: read: {e}");
                p.tout_permettre();
                return SORTIE_LECTURE;
            }
        };
        let lu = lecture::evenements(tampon.get(..n).unwrap_or_default());
        for ev in lu.evenements {
            recevoir(p, vers_tri, vers_rattrapage, &ev, moi);
        }
        if let Some(d) = lu.defaut {
            eprintln!("garde: lecture fautive: {d:?}");
            p.tout_permettre();
            return SORTIE_LECTURE;
        }
    }
}

/// Une demande lue : rien ici n'attend un système de fichiers (L-2, `le_lecteur_n_attend_aucun_fichier`).
fn recevoir(
    p: &Partage,
    vers_tri: &SyncSender<Demande>,
    vers_rattrapage: &SyncSender<Demande>,
    ev: &lecture::Evenement,
    moi: i32,
) {
    // Le pidfd ne sert pas : le processus attend son exec, son numéro ne peut pas être repris.
    drop(ev.pidfd.and_then(fanotify::prendre));
    if ev.masque & fanotify::DEBORDEMENT != 0 {
        plus(&p.compteurs.debordements);
        p.noter(evenement("debordement"));
    }
    let Some(fd) = fanotify::prendre(ev.fd) else {
        return;
    };
    if ev.masque & fanotify::OUVERTURE_EXEC_PERM == 0 {
        return;
    }
    plus(&p.compteurs.demandes);
    let fichier = Arc::new(File::from(fd));
    let permettre_ici = |p: &Partage| {
        let _ = p.groupe.repondre(fichier.as_fd(), true, false);
    };
    if ev.pid == moi {
        permettre_ici(p);
        return;
    }
    verrou(&p.attentes).ajouter(ev.fd, Arc::clone(&fichier), Instant::now());
    let demande = Demande {
        fd: ev.fd,
        fichier,
        pid: ev.pid,
        cle: None,
        connu: None,
    };
    confier(p, demande, vers_tri, vers_rattrapage);
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_par_position_bornee() {
        let d = crate::essais::Jetable::nouveau("garde-servir");
        let chemin = d.join("f");
        std::fs::write(&chemin, b"0123456789").unwrap();
        let f = File::open(&chemin).unwrap();
        let mut lu = Vec::new();
        ParPosition {
            fichier: &f,
            position: 0,
            fin: 4,
        }
        .read_to_end(&mut lu)
        .unwrap();
        assert_eq!(lu, b"0123");
        // Le même fichier haché par position et en entier : la même empreinte.
        let h = listes::hacher(ParPosition {
            fichier: &f,
            position: 0,
            fin: 10,
        })
        .unwrap();
        assert_eq!(h, listes::hacher(&b"0123456789"[..]).unwrap());
    }

    #[test]
    fn sans_root_le_service_refuse_de_partir() {
        if crate::socle::euid() == 0 {
            return crate::essais::saute("lancé en root : le garde ne tourne jamais sur ce PC hors VM");
        }
        assert_eq!(servir(), SORTIE_PAS_ROOT);
    }

    /// f2 : une lecture gelée est dite à 10 s, abandonnée à 30 s ; les fils des listes en vie sont bornés, et un fil
    /// qui finit (ou qui n'a pas pu partir) rend sa place.
    #[test]
    fn lecture_gelee_abandonnee_et_fils_bornes() {
        assert_eq!(sans_reponse(Duration::from_secs(5)), (false, false));
        assert_eq!(sans_reponse(Duration::from_secs(11)), (true, false));
        assert_eq!(sans_reponse(Duration::from_secs(31)), (true, true));
        let vivants = Arc::new(AtomicUsize::new(0));
        let un = Vivant::prendre(&vivants).unwrap();
        let deux = Vivant::prendre(&vivants).unwrap();
        assert!(Vivant::prendre(&vivants).is_none());
        assert_eq!(vivants.load(Ordering::Relaxed), LECTEURS_MAX);
        drop(un);
        let trois = std::thread::spawn({
            let v = Vivant::prendre(&vivants).unwrap();
            move || drop(v)
        });
        trois.join().unwrap();
        assert_eq!(vivants.load(Ordering::Relaxed), 1);
        drop(deux);
        assert_eq!(vivants.load(Ordering::Relaxed), 0);
    }

    /// M-N1 et f1 : l'union relue au démarrage est en vigueur avant toute liste du compte, et une liste vide ne la
    /// réduit pas (le reste de `appliquer` passe par `listes::unir`, essayé à part).
    #[test]
    fn l_union_relue_et_jamais_reduite() {
        let d = crate::essais::Jetable::nouveau("garde-servir-union");
        let union = listes::ListeSha256::lire([[1u8; 32], [2u8; 32]].concat()).unwrap();
        listes::ecrire_union(&d, LISTE_SHA256, &union).unwrap();
        let (lues, alertes) = listes::charger_union(&d, NOMS);
        assert!(alertes.is_empty(), "{alertes:?}");
        let mut c = Certain {
            sha256: None,
            md5: None,
        };
        let [sha256, md5] = lues;
        c.sha256 = sha256;
        c.md5 = md5;
        assert_eq!(c.nombre(), 2);
        let vide = listes::ListeSha256::lire(Vec::new()).unwrap();
        let u = listes::unir(liste_de(&c, 0), vide, listes::union_max());
        assert!(u.liste.is_none());
        assert_eq!(u.retirees, 2);
        assert!(liste_de(&c, 1).is_none());
        poser_liste(&mut c, 1, listes::ListeSha256::lire([3u8; 32].to_vec()).unwrap());
        assert_eq!(c.nombre(), 3);
    }

    /// N-1 : une liste du compte qui ajoute d'un coup bien plus que la croissance normale est comptée, gardée en root
    /// et relue au démarrage ; un rafraîchissement ordinaire est compté comme ajout, sans croissance anormale.
    #[test]
    fn la_croissance_anormale_est_gardee() {
        let d = crate::essais::Jetable::nouveau("garde-servir-croissance");
        let (p, _evenements) = partage(&[[0xff; 32]]);
        let union = liste_de(&p.config.read().unwrap().certain, 0)
            .unwrap()
            .empreintes()
            .as_flattened()
            .to_vec();
        listes::ecrire_union(&d, LISTE_SHA256, &listes::ListeSha256::lire(union).unwrap()).unwrap();
        let liste = |n: u64| {
            let mut e: Vec<[u8; 32]> = (0..n)
                .map(|i| {
                    let mut x = [0u8; 32];
                    x[..8].copy_from_slice(&i.to_be_bytes());
                    x
                })
                .collect();
            e.push([0xff; 32]);
            listes::ListeSha256::lire(e.concat()).unwrap()
        };
        let lues = |l: listes::ListeSha256| ListesLues {
            dossier: PathBuf::from("/home/alice/listes"),
            compte: 4242,
            resultats: vec![Ok(((1, 0, 1, 32), Some(l))), Ok(((1, 0, 2, 0), None))],
        };
        let mut r = Relecture::nouvelle(d.to_path_buf());
        let gonfle = listes::CROISSANCE_PAR_JOUR + 1_000;
        r.appliquer(&p, lues(liste(gonfle)));
        {
            let c = p.config.read().unwrap();
            assert_eq!((c.ajoutees[0], c.croissance), (gonfle, gonfle));
            assert_eq!(c.certain.nombre(), usize::try_from(gonfle + 1).unwrap());
        }
        // Le même jour, cinq de plus : un ajout ordinaire.
        r.appliquer(&p, lues(liste(gonfle + 5)));
        assert_eq!(p.config.read().unwrap().ajoutees[0], 5);
        assert_eq!(p.config.read().unwrap().croissance, gonfle);
        // Au redémarrage, l'alerte est toujours là.
        let (p2, _e2) = partage(&[]);
        Relecture::nouvelle(d.to_path_buf()).charger_union(&p2);
        let c = p2.config.read().unwrap();
        assert_eq!(
            (c.croissance, c.certain.nombre()),
            (gonfle, usize::try_from(gonfle + 6).unwrap())
        );
        assert!(c.alertes.is_empty(), "{:?}", c.alertes);
    }

    /// Un partage d'essai : un groupe sur /dev/null, en refus, avec `certain` comme liste.
    fn partage(certain: &[[u8; 32]]) -> (Partage, Receiver<Evenement>) {
        let nul = File::options().write(true).open("/dev/null").unwrap();
        let (vers, evenements) = std::sync::mpsc::sync_channel(64);
        let mut tries = certain.to_vec();
        tries.sort_unstable();
        let config = Config {
            reglages: Some(Reglages {
                version: super::super::VERSION_REGLAGES,
                compte: 4242,
                listes: "/home/alice/listes".into(),
                refus: true,
                pause_jusqu_a: None,
                permises: Vec::new(),
                vanguard: Vec::new(),
            }),
            certain: Certain {
                sha256: listes::ListeSha256::lire(tries.concat()),
                md5: None,
            },
            ..Config::default()
        };
        let p = Partage {
            groupe: Groupe::pour_essai(std::os::fd::OwnedFd::from(nul)),
            attentes: Mutex::new(Attentes::default()),
            config: RwLock::new(config),
            cache: Mutex::new(Cache::default()),
            compteurs: Compteurs2::default(),
            battement: AtomicU64::new(0),
            debut: Instant::now(),
            evenements: vers,
            arret: AtomicBool::new(false),
        };
        (p, evenements)
    }

    /// Une demande pour le fichier `nom` de `d`, écrit avec `contenu`.
    fn demande(d: &Path, nom: &str, contenu: &[u8]) -> Demande {
        use std::os::fd::AsRawFd;
        let chemin = d.join(nom);
        std::fs::write(&chemin, contenu).unwrap();
        let fichier = Arc::new(File::open(&chemin).unwrap());
        let m = fichier.metadata().unwrap();
        Demande {
            fd: fichier.as_raw_fd(),
            fichier,
            pid: i32::MAX,
            cle: Some(Cle {
                dev: m.dev(),
                ino: m.ino(),
                ctime: m.ctime(),
                ctime_ns: m.ctime_nsec(),
                taille: m.size(),
                fiable: true,
            }),
            connu: None,
        }
    }

    /// M-N2 : une demande déjà permise (délai, file pleine) est jugée quand même ; certaine, elle est comptée et dite,
    /// et son verdict va au cache ; à temps, elle est refusée sans être comptée comme passée.
    #[test]
    fn deja_permise_jugee_apres_coup() {
        let dossier = crate::essais::Jetable::nouveau("garde-servir-rattrapage");
        let d: &Path = &dossier;
        let contenu = b"un programme malveillant invente pour l'essai";
        let empreinte = listes::hacher(&contenu[..]).unwrap().sha256;
        let (p, evenements) = partage(&[empreinte]);
        // Déjà permise : n'attend plus.
        let tard = demande(d, "tard", contenu);
        decider(&p, &tard);
        let k = p.compteurs.lire();
        assert_eq!((k.certains_passes, k.refusees, k.hachees), (1, 0, 1));
        let connu = verrou(&p.cache).lire(&tard.cle.unwrap()).unwrap();
        assert!(connu.certain.is_some());
        let e = evenements.try_recv().unwrap();
        assert_eq!((e.genre.as_str(), e.trop_tard.as_deref()), ("delai", Some("refuse")));
        // Le lancement suivant : jugé depuis le cache, à temps, refusé.
        let suivant = Demande {
            connu: Some(connu),
            ..demande(d, "suivant", contenu)
        };
        verrou(&p.attentes).ajouter(suivant.fd, Arc::clone(&suivant.fichier), Instant::now());
        decider(&p, &suivant);
        let k = p.compteurs.lire();
        assert_eq!((k.certains_passes, k.refusees, k.hachees), (1, 1, 1));
        assert!(!verrou(&p.attentes).contient(suivant.fd, &suivant.fichier));
        // Propre et déjà permis : haché, gardé au cache comme propre, rien de compté.
        let propre = demande(d, "propre", b"un programme propre invente");
        decider(&p, &propre);
        assert!(verrou(&p.cache).lire(&propre.cle.unwrap()).unwrap().certain.is_none());
        assert_eq!(p.compteurs.lire().certains_passes, 1);
    }

    /// M-N2 : le fil du rattrapage juge ce que la file pleine a permis, une demande à la fois, puis s'arrête avec sa
    /// file ; sa file est bornée.
    #[test]
    fn le_rattrapage_juge_apres_coup_et_reste_borne() {
        let d = crate::essais::Jetable::nouveau("garde-servir-rattrapage-fil");
        let contenu = b"un autre programme malveillant invente";
        let h = listes::hacher(&contenu[..]).unwrap();
        let (p, _evenements) = partage(&[h.sha256]);
        let (vers, file) = std::sync::mpsc::sync_channel::<Demande>(RATTRAPAGE);
        let mut pleine = 0;
        for i in 0..=RATTRAPAGE {
            if vers.try_send(demande(&d, &format!("f{i}"), contenu)).is_err() {
                pleine += 1;
            }
        }
        assert_eq!(pleine, 1);
        drop(vers);
        rattraper(&p, &file);
        assert_eq!(p.compteurs.lire().certains_passes, RATTRAPAGE as u64);
    }

    /// L-2 : le fil lecteur (celui qui bat le chien de garde) ne fait aucun appel qui puisse attendre un système de
    /// fichiers : ni fstat, ni fstatfs, ni lecture de /proc, ni hachage ; le tri s'en charge.
    #[test]
    fn le_lecteur_n_attend_aucun_fichier() {
        let source = include_str!("servir.rs");
        for f in ["fn lire(", "fn recevoir(", "fn confier("] {
            let debut = source.find(f).unwrap();
            let fin = debut + source[debut..].find("\n}\n").unwrap();
            let corps = &source[debut..fin];
            for interdit in [
                "metadata",
                "type_fs",
                "cle_de",
                "preparer",
                "fstat",
                "chemin_de",
                "nom_de",
                "hacher",
                "read_link",
                "read_to_string",
                "File::open",
                "p.cache",
            ] {
                assert!(!corps.contains(interdit), "{f} : {interdit}");
            }
        }
    }

    /// L-2 : le tri lit la clé et sert le cache ; une demande propre en cache est permise sans aller plus loin, une
    /// inconnue reste à juger avec sa clé.
    #[test]
    fn le_tri_lit_la_cle_et_sert_le_cache() {
        let d = crate::essais::Jetable::nouveau("garde-servir-tri");
        let (p, _evenements) = partage(&[]);
        let mut inconnue = Demande {
            cle: None,
            ..demande(&d, "inconnue", b"un programme propre invente")
        };
        verrou(&p.attentes).ajouter(inconnue.fd, Arc::clone(&inconnue.fichier), Instant::now());
        assert!(preparer(&p, &mut inconnue));
        let cle = inconnue.cle.unwrap();
        assert_eq!(cle.taille, 27);
        decider(&p, &inconnue);
        assert!(!verrou(&p.attentes).contient(inconnue.fd, &inconnue.fichier));
        // Relancé : le même fichier, propre au cache, permis par le tri.
        let fichier = Arc::new(File::open(d.join("inconnue")).unwrap());
        let mut revue = Demande {
            fd: std::os::fd::AsRawFd::as_raw_fd(&*fichier),
            fichier,
            pid: i32::MAX,
            cle: None,
            connu: None,
        };
        verrou(&p.attentes).ajouter(revue.fd, Arc::clone(&revue.fichier), Instant::now());
        assert!(!preparer(&p, &mut revue));
        assert_eq!(revue.cle, Some(cle));
        assert_eq!(p.compteurs.lire().cache, 1);
        assert!(!verrou(&p.attentes).contient(revue.fd, &revue.fichier));
        // Une file pleine : permise tout de suite, confiée au rattrapage ; pleine aussi, comptée.
        let (vers, _file) = std::sync::mpsc::sync_channel::<Demande>(0);
        let (vers_r, file_r) = std::sync::mpsc::sync_channel::<Demande>(1);
        let a = demande(&d, "a", b"a");
        verrou(&p.attentes).ajouter(a.fd, Arc::clone(&a.fichier), Instant::now());
        confier(&p, a, &vers, &vers_r);
        confier(&p, demande(&d, "b", b"b"), &vers, &vers_r);
        let k = p.compteurs.lire();
        assert_eq!((k.file_pleine, k.rattrapages_perdus), (2, 1));
        assert!(file_r.try_recv().is_ok());
    }

    #[test]
    fn le_nom_d_un_processus_et_ses_noms_de_session() {
        assert_ne!(nom_de(i32::try_from(std::process::id()).unwrap()), "");
        assert_eq!(nom_de(-1), "");
        assert_eq!(chemin_de(-1), "");
    }
}
