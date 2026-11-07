//! Le service du garde (`vanguard garde-servir`, lancé par systemd seulement, en root avec CAP_SYS_ADMIN).
//!
//! Les fils :
//! - le LECTEUR (le fil principal) lit le groupe fanotify, et n'ouvre jamais de fichier : une ouverture par le garde
//!   dans un système de fichiers marqué pourrait produire sa propre demande. Il permet tout de suite ses propres
//!   lancements et ceux dont l'inode est en cache comme propre (servis en premier), et confie le reste à la file ;
//! - deux fils de DÉCISION hachent le descripteur rendu par le noyau (borné à 64 Mio, au-delà : permis et noté) et
//!   jugent (`decision`) ; leur nombre borne les hachages concurrents ;
//! - le fil du DÉLAI permet toute demande sans verdict après 250 ms (P9), et la note ;
//! - le fil d'ENTRETIEN marque les montages faits plus tard, relit les réglages, écrit etat.json et evenements.jsonl,
//!   et envoie WATCHDOG=1 tant que le lecteur bat (un lecteur figé : systemd tue le garde, et la fermeture du groupe
//!   laisse passer tout ce qui attend) ; il n'attend jamais rien du dossier du compte ;
//! - un fil des LISTES, lancé par l'entretien, relit l'ensemble CERTAIN dans le dossier du compte (openat2) ; s'il
//!   reste bloqué, l'entretien le dit et n'en lance pas d'autre ;
//! - le fil des SIGNAUX : à SIGTERM, tout ce qui attend est permis, puis le garde sort.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
/// La file vers les fils de décision ; pleine, la demande est permise et notée.
const FILE: usize = 256;
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

/// Une demande confiée aux fils de décision.
struct Demande {
    fd: i32,
    fichier: Arc<File>,
    pid: i32,
    cle: Cle,
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

/// Juge une demande et y répond.
fn decider(p: &Partage, d: &Demande) {
    // Déjà permise par le délai : rien à faire.
    if !verrou(&p.attentes).contient(d.fd, &d.fichier) {
        return;
    }
    let connu = if let Some(c) = d.connu {
        c
    } else {
        if d.cle.taille > HACHAGE_MAX {
            plus(&p.compteurs.non_verifiees);
            if p.repondre(d.fd, &d.fichier, true) {
                let mut e = evenement("non-verifie");
                e.pid = d.pid;
                e.chemin = sortie::borner(&chemin_de(d.fd));
                e.detail = format!("{} octets", d.cle.taille);
                p.noter(e);
            }
            return;
        }
        let lecteur = ParPosition {
            fichier: &d.fichier,
            position: 0,
            fin: d.cle.taille,
        };
        let Some(h) = listes::hacher(lecteur) else {
            plus(&p.compteurs.non_verifiees);
            p.repondre(d.fd, &d.fichier, true);
            return;
        };
        plus(&p.compteurs.hachees);
        let c = juger_hache(p, &h);
        verrou(&p.cache).noter(d.cle, c);
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
        e.detail = format!("verdict trop tard : {}", verdict.nom());
    } else if !nom.is_empty() {
        e.detail = format!("lancé par {}", sortie::borner(&nom));
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
}

/// Une lecture des listes sans réponse depuis plus longtemps est dite.
const LISTES_DELAI: Duration = Duration::from_secs(10);

impl Relecture {
    fn nouvelle() -> Relecture {
        Relecture {
            reglages: None,
            listes: None,
            derniere: None,
            en_cours: None,
        }
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
                    if attente > LISTES_DELAI {
                        alerter_listes(
                            p,
                            vec![format!(
                                "liste: lecture sans réponse depuis {} s (listes d'avant en vigueur)",
                                attente.as_secs()
                            )],
                        );
                    }
                    return;
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
        let (vers, recu) = std::sync::mpsc::sync_channel(1);
        let lancer = std::thread::Builder::new().name("garde-listes".into()).spawn(move || {
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
                    if let Some(l) = l {
                        changees = true;
                        let mut c = p.config.write().unwrap_or_else(PoisonError::into_inner);
                        if i == 0 {
                            c.certain.sha256 = Some(l);
                        } else {
                            c.certain.md5 = Some(l);
                        }
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
    let (refus, pause_jusqu_a, certain, mut alertes) = {
        let c = p.config.read().unwrap_or_else(PoisonError::into_inner);
        (
            c.reglages.as_ref().is_some_and(|r| r.refus),
            c.reglages.as_ref().and_then(|r| r.pause_jusqu_a),
            u64::try_from(c.certain.nombre()).unwrap_or(u64::MAX),
            c.alertes.clone(),
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
                e.detail = nouveau.genre;
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
    // Les réglages (à root) avant la première marque : le mode est connu dès la première demande. Les listes, dans le
    // dossier du compte, viennent après READY=1, dans un fil à part : un dossier qui ne répond pas laisse le garde
    // vivant, sans listes (seule la marque d'essai est alors certaine).
    let mut relecture = Relecture::nouvelle();
    relecture.relire_reglages(&p, true);
    let mut marques = Marques::default();
    let info = Montages::ouvrir().and_then(|mut m| m.lire()).unwrap_or_default();
    marques.completer(&p.groupe, &info);
    if marques.marques.is_empty() {
        eprintln!("garde: aucun système de fichiers marqué");
        return SORTIE_GROUPE;
    }
    let mut e = evenement("demarrage");
    e.detail = format!(
        "{} systèmes de fichiers marqués, {} refusés ; pidfd {}, audit {}",
        marques.marques.len(),
        marques.echecs.len(),
        p.groupe.options.pidfd,
        p.groupe.options.audit
    );
    p.noter(e);

    let (vers_decideurs, file) = std::sync::mpsc::sync_channel::<Demande>(FILE);
    let file = Arc::new(Mutex::new(file));
    for _ in 0..DECIDEURS {
        let (p, file) = (Arc::clone(&p), Arc::clone(&file));
        std::thread::spawn(move || decideur(&p, &file));
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
    lire(&p, &vers_decideurs)
}

/// Le fil lecteur ; ne rend la main que sur une lecture fautive.
fn lire(p: &Partage, vers_decideurs: &SyncSender<Demande>) -> i32 {
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
            recevoir(p, vers_decideurs, &ev, moi);
        }
        if let Some(d) = lu.defaut {
            eprintln!("garde: lecture fautive: {d:?}");
            p.tout_permettre();
            return SORTIE_LECTURE;
        }
    }
}

/// Une demande lue.
fn recevoir(p: &Partage, vers_decideurs: &SyncSender<Demande>, ev: &lecture::Evenement, moi: i32) {
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
    let Ok(m) = fichier.metadata() else {
        plus(&p.compteurs.non_verifiees);
        permettre_ici(p);
        return;
    };
    let cle = Cle {
        dev: m.dev(),
        ino: m.ino(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
        taille: m.size(),
    };
    let connu = verrou(&p.cache).lire(&cle);
    if connu.is_some_and(|c| c.certain.is_none()) {
        plus(&p.compteurs.cache);
        permettre_ici(p);
        return;
    }
    verrou(&p.attentes).ajouter(ev.fd, Arc::clone(&fichier), Instant::now());
    let demande = Demande {
        fd: ev.fd,
        fichier,
        pid: ev.pid,
        cle,
        connu,
    };
    if let Err(TrySendError::Full(d) | TrySendError::Disconnected(d)) = vers_decideurs.try_send(demande) {
        plus(&p.compteurs.file_pleine);
        if p.repondre(d.fd, &d.fichier, true) {
            let mut e = evenement("file-pleine");
            e.pid = d.pid;
            p.noter(e);
        }
    }
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

    #[test]
    fn le_nom_d_un_processus_et_ses_noms_de_session() {
        assert_ne!(nom_de(i32::try_from(std::process::id()).unwrap()), "");
        assert_eq!(nom_de(-1), "");
        assert_eq!(chemin_de(-1), "");
    }
}
