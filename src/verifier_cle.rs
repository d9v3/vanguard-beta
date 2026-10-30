//! Vérifier ma clé : une clé USB ou un disque externe tient-il ce qu'il annonce ? Les fausses clés (une puce de 16 Go
//! vendue « 1 To ») acceptent tout ce qu'on leur écrit et rendent n'importe quoi au-delà de leur vraie taille ; une
//! clé qui meurt rend des blocs faux ou illisibles. Vanguard écrit dans l'espace libre, dans un dossier à lui, un
//! contenu déterministe (chaque bloc porte l'essai, son fichier et son numéro), relit tout en contournant le cache du
//! système (sinon on relirait la mémoire de l'ordinateur et une fausse clé passerait pour bonne : fsync puis
//! `posix_fadvise DONTNEED` sous Linux, `F_NOCACHE` sous macOS, `FILE_FLAG_NO_BUFFERING` sous Windows), mesure les
//! vitesses d'écriture et de lecture, puis efface tout. Une marge est laissée libre ; jamais sur la clé VANGUARD ni sur
//! le disque du système ; rien n'est écrit sans être montré et accepté ; Échap ou Ctrl-C arrêtent et nettoient. Mode
//! rapide (un quart de l'espace libre : repère les fausses clés courantes, dont la vraie capacité est bien moindre
//! que l'annoncée, et mesure la vitesse) ou complet (tout l'espace libre : la seule preuve).

use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::selection::{Ligne, choisir};
use crate::socle::taille_lisible;
use crate::ui::*;

const MIO: u64 = 1 << 20;
const GIO: u64 = 1 << 30;
/// Le dossier de l'essai, à la racine du disque ; ce qui reste d'un essai interrompu se reconnaît à ce préfixe.
const PREFIXE_DOSSIER: &str = "Vanguard-verification-";
/// Ce qu'on laisse libre : au moins ça, ou 1 % du libre.
const MARGE_MIN: u64 = 64 * MIO;
/// En dessous, pas de place pour un essai qui veuille dire quelque chose.
const MINIMUM: u64 = 16 * MIO;
/// Alignement des tampons : Windows exige, sans cache, des tampons et des tailles alignés sur le secteur (4 Kio au plus).
const ALIGNEMENT: usize = 4096;

/// Les tailles d'un essai : un bloc (écrit, relu, jugé d'un coup) et un fichier (FAT32 refuse 4 Gio et plus).
#[derive(Clone, Copy, Debug)]
pub struct Parametres {
    pub bloc: u64,
    pub fichier: u64,
}

impl Parametres {
    /// 4 Mio : assez gros pour la vitesse, assez fin pour situer une erreur ; 1 Gio par fichier.
    const REELS: Parametres = Parametres {
        bloc: 4 * MIO,
        fichier: GIO,
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Rapide,
    Complete,
}

/// Ce qu'on va écrire : combien, en combien de fichiers, et ce qui restera libre.
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    octets: u64,
    fichiers: u64,
    marge: u64,
}

/// Le plan selon la place libre : tout sauf la marge en mode complet ; un quart (au moins 2 Gio, s'ils sont là) en
/// mode rapide. `None` : trop peu de place pour que l'essai veuille dire quelque chose.
fn plan(libre: u64, mode: Mode, p: &Parametres) -> Option<Plan> {
    let marge = MARGE_MIN.max(libre / 100);
    let disponible = libre.saturating_sub(marge) / p.bloc * p.bloc;
    if disponible < MINIMUM.max(2 * p.bloc) {
        return None;
    }
    let octets = match mode {
        Mode::Complete => disponible,
        Mode::Rapide => (disponible / 4).max(2 * GIO).min(disponible) / p.bloc * p.bloc,
    };
    Some(Plan {
        octets,
        fichiers: octets.div_ceil(p.fichier),
        marge,
    })
}

// ───────────────────────────── Le contenu ─────────────────────────────

/// Les 16 octets répétés dans un bloc : l'identifiant de l'essai, le numéro du fichier, le numéro du bloc. Un bloc
/// relu qui porte un autre numéro vient d'ailleurs sur la puce : la signature d'une fausse clé, qui écrit les
/// nouveaux blocs par-dessus les anciens une fois sa vraie taille dépassée.
fn motif(essai: u64, fichier: u32, bloc: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[..8].copy_from_slice(&essai.to_le_bytes());
    m[8..12].copy_from_slice(&fichier.to_le_bytes());
    m[12..].copy_from_slice(&bloc.to_le_bytes());
    m
}

fn remplir(tampon: &mut [u8], essai: u64, fichier: u32, bloc: u32) {
    let m = motif(essai, fichier, bloc);
    for (o, v) in tampon.iter_mut().zip(m.iter().cycle()) {
        *o = *v;
    }
}

/// Ce qu'un bloc relu dit.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verdict {
    Bon,
    /// Le contenu d'un autre bloc de cet essai : les données se sont recouvertes (fausse capacité).
    AutreBloc {
        fichier: u32,
        bloc: u32,
    },
    /// Ni le bon contenu ni celui d'un autre bloc : zéros, bruit, ancien contenu.
    Faux,
}

fn juger(tampon: &[u8], essai: u64, fichier: u32, bloc: u32) -> Verdict {
    let attendu = motif(essai, fichier, bloc);
    if !tampon.is_empty() && tampon.iter().zip(attendu.iter().cycle()).all(|(a, b)| a == b) {
        return Verdict::Bon;
    }
    // Un autre bloc du même essai, entier et cohérent : les 16 premiers octets le nomment, le reste doit le répéter.
    let Some(premier) = tampon.first_chunk::<16>() else {
        return Verdict::Faux;
    };
    if premier[..8] == essai.to_le_bytes() && tampon.iter().zip(premier.iter().cycle()).all(|(a, b)| a == b) {
        return Verdict::AutreBloc {
            fichier: u32::from_le_bytes(premier[8..12].try_into().unwrap_or_default()),
            bloc: u32::from_le_bytes(premier[12..].try_into().unwrap_or_default()),
        };
    }
    Verdict::Faux
}

/// Un tampon de `taille` octets aligné sur `ALIGNEMENT` : (mémoire, début de la partie alignée).
fn tampon(taille: usize) -> (Vec<u8>, usize) {
    let v = vec![0u8; taille + ALIGNEMENT];
    let debut = (ALIGNEMENT - (v.as_ptr().addr() % ALIGNEMENT)) % ALIGNEMENT;
    (v, debut)
}

// ───────────────────────────── L'essai ─────────────────────────────

/// Où en est l'essai, pour l'affichage et pour l'arrêt demandé.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Ecriture,
    Lecture,
}

/// Appelé à chaque bloc : la phase, ce qui est fait, le total. Rend `true` pour arrêter.
type Controle<'a> = &'a mut dyn FnMut(Phase, u64, u64) -> bool;

/// Ce que l'écriture a laissé.
#[derive(Debug, Default)]
struct Ecriture {
    /// Les fichiers écrits et leur taille réelle (le dernier peut être court : arrêt, place manquante, erreur).
    fichiers: Vec<(PathBuf, u64)>,
    octets: u64,
    duree: Duration,
    /// L'erreur qui a arrêté l'écriture avant la fin, s'il y en a eu une.
    erreur: Option<std::io::Error>,
    arretee: bool,
}

/// Ce que la relecture a trouvé.
#[derive(Debug, Default, PartialEq, Eq)]
struct Lecture {
    octets: u64,
    duree: Duration,
    /// Blocs qui portent le contenu d'un autre bloc.
    recouverts: u64,
    /// Blocs faux (ni le bon contenu ni celui d'un autre bloc).
    faux: u64,
    /// Blocs que le disque n'a pas pu rendre (erreur de lecture, fichier raccourci).
    illisibles: u64,
    /// Position (en octets depuis le début de l'essai) du premier bloc qui n'est pas bon.
    premier_defaut: Option<u64>,
    arretee: bool,
}

impl Lecture {
    fn defauts(&self) -> u64 {
        self.recouverts + self.faux + self.illisibles
    }
}

fn ouvrir_en_ecriture(chemin: &Path) -> std::io::Result<File> {
    let f = OpenOptions::new().write(true).create_new(true).open(chemin)?;
    // macOS : sans cache dès l'écriture ; Linux : sans effet ici (les pages sont retirées après fsync).
    crate::copier::sans_cache(&f);
    Ok(f)
}

/// Lecture qui contourne le cache du système : Windows ouvre sans mise en mémoire (tampons et tailles alignés sur le
/// secteur) ; Linux retire du cache les pages du fichier, propres depuis le fsync ; macOS lit sans cache.
fn ouvrir_en_lecture(chemin: &Path) -> std::io::Result<File> {
    #[cfg(windows)]
    let f = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_NO_BUFFERING)
            .open(chemin)?
    };
    #[cfg(not(windows))]
    let f = File::open(chemin)?;
    crate::copier::sans_cache(&f);
    Ok(f)
}

/// Écrit `octets` dans `dossier`, en fichiers numérotés, chaque fichier synchronisé puis sorti du cache.
fn ecrire(dossier: &Path, octets: u64, p: &Parametres, essai: u64, controle: Controle<'_>) -> Ecriture {
    let debut = Instant::now();
    let mut e = Ecriture::default();
    #[allow(clippy::cast_possible_truncation)]
    let (mut memoire, decalage) = tampon(p.bloc as usize);
    let mut reste = octets;
    let mut numero: u32 = 0;
    'fichiers: while reste > 0 {
        let chemin = dossier.join(format!("verif-{:04}.bin", numero + 1));
        let mut f = match ouvrir_en_ecriture(&chemin) {
            Ok(f) => f,
            Err(err) => {
                e.erreur = Some(err);
                break;
            }
        };
        let taille_fichier = reste.min(p.fichier);
        let mut ecrit_ici = 0;
        let mut bloc: u32 = 0;
        while ecrit_ici < taille_fichier {
            if controle(Phase::Ecriture, e.octets, octets) {
                e.arretee = true;
            }
            if e.arretee {
                let _ = f.sync_all();
                e.fichiers.push((chemin, ecrit_ici));
                break 'fichiers;
            }
            #[allow(clippy::cast_possible_truncation)]
            let taille_bloc = (taille_fichier - ecrit_ici).min(p.bloc) as usize;
            #[expect(
                clippy::indexing_slicing,
                reason = "tampon() alloue p.bloc + ALIGNEMENT octets, decalage < ALIGNEMENT, taille_bloc <= p.bloc"
            )]
            let zone = &mut memoire[decalage..decalage + taille_bloc];
            remplir(zone, essai, numero, bloc);
            if let Err(err) = f.write_all(zone) {
                let _ = f.sync_all();
                e.fichiers.push((chemin, ecrit_ici));
                e.erreur = Some(err);
                break 'fichiers;
            }
            ecrit_ici += taille_bloc as u64;
            e.octets += taille_bloc as u64;
            bloc += 1;
        }
        if let Err(err) = f.sync_all() {
            e.fichiers.push((chemin, ecrit_ici));
            e.erreur = Some(err);
            break;
        }
        crate::copier::sans_cache(&f);
        e.fichiers.push((chemin, ecrit_ici));
        reste -= ecrit_ici;
        numero += 1;
    }
    e.duree = debut.elapsed();
    e
}

/// Relit tout ce qui a été écrit, bloc par bloc, et juge chaque bloc.
fn relire(fichiers: &[(PathBuf, u64)], p: &Parametres, essai: u64, controle: Controle<'_>) -> Lecture {
    let debut = Instant::now();
    let total: u64 = fichiers.iter().map(|(_, t)| t).sum();
    let mut l = Lecture::default();
    #[allow(clippy::cast_possible_truncation)]
    let (mut memoire, decalage) = tampon(p.bloc as usize);
    let mut position = 0u64;
    let defaut = |l: &mut Lecture, position: u64| {
        if l.premier_defaut.is_none() {
            l.premier_defaut = Some(position);
        }
    };
    'fichiers: for (numero, (chemin, taille)) in fichiers.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let numero = numero as u32;
        let mut f = ouvrir_en_lecture(chemin).ok();
        let mut lu_ici = 0u64;
        let mut bloc: u32 = 0;
        while lu_ici < *taille {
            if controle(Phase::Lecture, l.octets, total) {
                l.arretee = true;
                break 'fichiers;
            }
            #[allow(clippy::cast_possible_truncation)]
            let taille_bloc = (*taille - lu_ici).min(p.bloc) as usize;
            #[expect(
                clippy::indexing_slicing,
                reason = "tampon() alloue p.bloc + ALIGNEMENT octets, decalage < ALIGNEMENT, taille_bloc <= p.bloc"
            )]
            let zone = &mut memoire[decalage..decalage + taille_bloc];
            let lu = f
                .as_mut()
                .map_or(Ok(false), |f| lire_exactement(f, zone))
                .map_err(|_| ());
            if lu == Ok(true) {
                match juger(zone, essai, numero, bloc) {
                    Verdict::Bon => {}
                    Verdict::AutreBloc { .. } => {
                        l.recouverts += 1;
                        defaut(&mut l, position);
                    }
                    Verdict::Faux => {
                        l.faux += 1;
                        defaut(&mut l, position);
                    }
                }
            } else {
                // Fichier plus court qu'écrit, ou erreur du disque : le bloc est perdu, le fichier n'est plus lu.
                l.illisibles += ((*taille - lu_ici).div_ceil(p.bloc)).max(1);
                defaut(&mut l, position);
                position += *taille - lu_ici;
                l.octets += *taille - lu_ici;
                continue 'fichiers;
            }
            lu_ici += taille_bloc as u64;
            l.octets += taille_bloc as u64;
            position += taille_bloc as u64;
            bloc += 1;
        }
    }
    l.duree = debut.elapsed();
    l
}

/// Remplit `t` en entier : `Ok(false)` si le fichier finit avant.
fn lire_exactement(f: &mut File, t: &mut [u8]) -> std::io::Result<bool> {
    let mut fait = 0;
    while let Some(reste) = t.get_mut(fait..).filter(|r| !r.is_empty()) {
        match f.read(reste) {
            Ok(0) => return Ok(false),
            Ok(n) => fait += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// Un fichier d'essai de Vanguard : « verif-0001.bin ».
fn fichier_d_essai(nom: &str) -> bool {
    nom.strip_prefix("verif-")
        .and_then(|r| r.strip_suffix(".bin"))
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|o| o.is_ascii_digit()))
}

/// Efface le dossier de l'essai : ses fichiers d'essai seulement, puis le dossier s'il est vide. Quelqu'un a pu ranger
/// autre chose dans un dossier au nom de l'essai : cela reste, et l'effacement du dossier le dit (« pas vide »).
fn nettoyer(dossier: &Path) -> std::io::Result<()> {
    if !dossier.is_dir() {
        return Ok(());
    }
    for e in std::fs::read_dir(dossier)?.flatten() {
        let nom = e.file_name().to_string_lossy().into_owned();
        if fichier_d_essai(&nom) && e.file_type().is_ok_and(|t| t.is_file()) {
            std::fs::remove_file(e.path())?;
        }
    }
    std::fs::remove_dir(dossier)
}

/// Les dossiers d'essais interrompus à la racine de ce disque.
fn restes(racine: &Path) -> Vec<PathBuf> {
    let mut r: Vec<PathBuf> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name().is_some_and(|n| {
                    // Restes d'une vérification d'avant le changement de nom aussi (`passage`).
                    let n = n.to_string_lossy();
                    crate::passage::les_deux(PREFIXE_DOSSIER)
                        .iter()
                        .any(|p| n.starts_with(p.as_str()))
                })
        })
        .collect();
    r.sort();
    r
}

// ───────────────────────────── Les conclusions ─────────────────────────────

/// Ce que l'essai conclut, à montrer.
#[derive(Debug, PartialEq, Eq)]
enum Conclusion {
    /// Mode complet, tout bon : la capacité est prouvée (libre vérifié, déjà occupé non vérifié).
    Prouvee { verifie: u64, occupe: u64 },
    /// Mode rapide, tout bon : au moins ça de réel.
    AuMoins { verifie: u64, annonce: u64 },
    /// Des blocs recouverts : fausse clé ; sa vraie taille est à peu près là où ça a commencé.
    FausseCle { vraie: u64, annonce: u64 },
    /// Des blocs faux ou illisibles sans recouvrement : la clé lâche.
    Defaillante { defauts: u64, premier: u64 },
    /// La place a manqué bien avant ce qui était annoncé libre.
    PlaceManquante { ecrit: u64, prevu: u64 },
    /// Arrêté avant d'avoir conclu.
    Interrompue { verifie: u64 },
}

fn conclure(mode: Mode, prevu: u64, occupe: u64, total: u64, e: &Ecriture, l: &Lecture) -> Conclusion {
    if l.recouverts > 0 {
        return Conclusion::FausseCle {
            vraie: occupe + l.premier_defaut.unwrap_or(0),
            annonce: total,
        };
    }
    if l.defauts() > 0 {
        return Conclusion::Defaillante {
            defauts: l.defauts(),
            premier: occupe + l.premier_defaut.unwrap_or(0),
        };
    }
    if e.arretee || l.arretee {
        return Conclusion::Interrompue { verifie: l.octets };
    }
    // Une place qui manque de plus de 5 % par rapport à l'annonce : la table du disque ment ou est abîmée.
    if e.erreur.is_some() && e.octets < prevu - prevu / 20 {
        return Conclusion::PlaceManquante { ecrit: e.octets, prevu };
    }
    match mode {
        Mode::Complete => Conclusion::Prouvee {
            verifie: l.octets,
            occupe,
        },
        Mode::Rapide => Conclusion::AuMoins {
            verifie: l.octets,
            annonce: total,
        },
    }
}

/// « 24 Mo/s » : un débit.
fn debit(octets: u64, duree: Duration) -> String {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let par_seconde = (octets as f64 / duree.as_secs_f64().max(0.001)) as u64;
    if par_seconde >= GIO {
        #[allow(clippy::cast_precision_loss)]
        let go = par_seconde as f64 / GIO as f64;
        trf!("{} Go/s", "{} GB/s", crate::langue::decimal(go, 1))
    } else {
        trf!("{} Mo/s", "{} MB/s", par_seconde / MIO)
    }
}

/// Ce que vaut ce débit d'écriture, pour qui ne connaît pas les chiffres.
fn qualifier_ecriture(octets: u64, duree: Duration) -> &'static str {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let mo_s = (octets as f64 / duree.as_secs_f64().max(0.001) / MIO as f64) as u64;
    match mo_s {
        0..5 => tr!(
            "très lent, même pour une clé USB 2.0 : elle est usée ou de mauvaise qualité",
            "very slow, even for a USB 2.0 stick: it is worn or of poor quality"
        ),
        5..30 => tr!("une clé USB ordinaire", "an ordinary USB stick"),
        30..120 => tr!(
            "une bonne clé USB 3 ou un disque dur externe",
            "a good USB 3 stick or an external hard disk"
        ),
        _ => tr!("un SSD externe", "an external SSD"),
    }
}

/// « environ 12 min » : le temps d'écrire puis de relire `octets` à ce débit (en octets par seconde).
fn duree_estimee(octets: u64, debit: u64) -> String {
    let secondes = octets.saturating_mul(2) / debit.max(1);
    if secondes < 90 {
        trf!("environ {secondes} s", "about {secondes} s")
    } else if secondes < 5400 {
        trf!("environ {} min", "about {} min", secondes.div_ceil(60))
    } else {
        #[allow(clippy::cast_precision_loss)]
        let heures = secondes as f64 / 3600.0;
        trf!("environ {} h", "about {} h", crate::langue::decimal(heures, 1))
    }
}

// ───────────────────────────── L'affichage ─────────────────────────────

/// Le clavier pendant l'essai : mode brut pour lire Échap et Ctrl-C sans Entrée, rendu à la fin. Dans un vrai
/// terminal seulement.
struct Clavier {
    brut: bool,
}

impl Clavier {
    fn prendre() -> Clavier {
        let terminal = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
        Clavier {
            brut: terminal && crossterm::terminal::enable_raw_mode().is_ok(),
        }
    }

    /// Échap ou Ctrl-C tapé depuis la dernière fois.
    fn arret_demande(&self) -> bool {
        use crossterm::event::{Event, KeyCode, KeyModifiers, poll, read};
        if !self.brut {
            return false;
        }
        let mut arret = false;
        while poll(Duration::ZERO).unwrap_or(false) {
            if let Ok(Event::Key(k)) = read() {
                let ctrl_c = k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL);
                arret |= k.code == KeyCode::Esc || ctrl_c;
            }
        }
        arret
    }
}

impl Drop for Clavier {
    fn drop(&mut self) {
        if self.brut {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// La ligne d'avancement, au plus deux fois par seconde.
struct Avancement {
    debut_phase: Instant,
    phase: Option<Phase>,
    dernier: Option<Instant>,
    terminal: bool,
}

impl Avancement {
    fn nouveau() -> Avancement {
        Avancement {
            debut_phase: Instant::now(),
            phase: None,
            dernier: None,
            terminal: std::io::stdout().is_terminal(),
        }
    }

    fn montrer(&mut self, phase: Phase, fait: u64, total: u64) {
        if self.phase != Some(phase) {
            self.phase = Some(phase);
            self.debut_phase = Instant::now();
        }
        if !self.terminal || self.dernier.is_some_and(|d| d.elapsed() < Duration::from_millis(500)) {
            return;
        }
        self.dernier = Some(Instant::now());
        let ecoule = self.debut_phase.elapsed();
        let nom = match phase {
            Phase::Ecriture => tr!("Écriture", "Writing"),
            Phase::Lecture => tr!("Relecture", "Reading back"),
        };
        let mut texte = trf!(
            "{nom} {} / {} · {}",
            "{nom} {} / {} · {}",
            taille_lisible(fait),
            taille_lisible(total),
            debit(fait, ecoule)
        );
        if fait > 0 && ecoule > Duration::from_secs(5) {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let reste = (ecoule.as_secs_f64() * (total - fait) as f64 / fait as f64) as u64;
            texte.push_str(&trf!(" · reste {}", " · {} left", minutes(reste)));
        }
        texte.push_str(&trf!("   {GRIS}Échap : arrêter{RESET}", "   {GRIS}Esc: stop{RESET}"));
        print!("\r  {texte}\x1b[K");
        let _ = std::io::stdout().flush();
    }

    /// Termine la ligne d'avancement.
    fn finir(&self) {
        if self.terminal {
            print!("\r\x1b[K");
            let _ = std::io::stdout().flush();
        }
    }
}

/// « 3 min », « 1 h 20 », « 40 s ».
fn minutes(secondes: u64) -> String {
    if secondes < 60 {
        format!("{secondes} s")
    } else if secondes < 3600 {
        format!("{} min", secondes.div_ceil(60))
    } else {
        format!("{} h {:02}", secondes / 3600, (secondes % 3600) / 60)
    }
}

fn bon(texte: &str) {
    afficher_aligne(&format!("  {VERT}✔{RESET} "), texte, 4, "");
}

fn mauvais(texte: &str) {
    afficher_aligne(
        &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
        texte,
        4,
        "",
    );
}

fn info(texte: &str) {
    afficher_aligne(
        &format!("  {}ℹ{RESET} ", couleur(crate::risk::Niveau::Info)),
        texte,
        4,
        "",
    );
}

/// Le disque à vérifier, parmi ceux qui sont branchés (jamais la clé VANGUARD ni le disque du système : la liste de
/// Copier mes fichiers les exclut déjà).
fn choisir_disque() -> Option<crate::copier::Disque> {
    let liste = crate::copier::disques();
    if liste.is_empty() {
        mauvais(tr!(
            "Aucune clé ni disque externe à vérifier (la clé VANGUARD et le disque du système ne comptent pas). Branchez la clé, attendez qu'elle apparaisse, puis recommencez.",
            "No USB stick or external disk to check (the VANGUARD key and the system disk do not count). Plug in the stick, wait for it to appear, then start again."
        ));
        return None;
    }
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("QUELLE CLÉ", "WHICH DRIVE"))),
    ];
    for (i, d) in liste.iter().enumerate() {
        let place = trf!(
            "{} libres sur {}",
            "{} free out of {}",
            taille_lisible(d.libre),
            taille_lisible(d.total)
        );
        lignes.push(Ligne::choix(&(i + 1).to_string(), &d.nom, &place));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let invite = tr!(
        "  Numéro de la clé (Entrée pour revenir) : ",
        "  Drive number (Enter to go back): "
    );
    let choix = choisir(&lignes, invite, "1", tr!("revenir", "back"))?;
    let i = choix.trim().parse::<usize>().ok()?.checked_sub(1)?;
    liste.into_iter().nth(i)
}

/// La place (libre, totale) de ce disque, relue après le ménage : la liste des disques la connaît sur les trois systèmes.
fn place(racine: &Path) -> Option<(u64, u64)> {
    crate::copier::disques()
        .into_iter()
        .find(|d| d.racine == racine)
        .map(|d| (d.libre, d.total))
}

/// Le disque branché qui contient ce chemin ; sinon pourquoi on refuse.
fn disque_de(chemin: &Path) -> Result<crate::copier::Disque, String> {
    let reel = chemin.canonicalize().unwrap_or_else(|_| chemin.to_path_buf());
    let reel = PathBuf::from(reel.to_string_lossy().trim_start_matches(r"\\?\"));
    crate::copier::disques()
        .into_iter()
        .find(|d| reel.starts_with(&d.racine))
        .ok_or_else(|| {
            trf!(
                "{} n'est pas sur une clé ou un disque externe branché (la clé VANGUARD et le disque du système sont exclus).",
                "{} is not on a plugged-in USB stick or external disk (the VANGUARD key and the system disk are excluded).",
                chemin_affichable(chemin)
            )
        })
}

/// Le mode : rapide ou complet, avec ce que chacun écrirait.
fn choisir_mode(libre: u64) -> Option<Mode> {
    let p = &Parametres::REELS;
    let rapide = plan(libre, Mode::Rapide, p)?;
    let complete = plan(libre, Mode::Complete, p)?;
    if rapide.octets == complete.octets {
        return Some(Mode::Complete);
    }
    let lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("QUELLE VÉRIFICATION", "WHICH CHECK"))),
        Ligne::choix(
            "1",
            tr!("Rapide", "Quick"),
            &trf!("{} écrits", "{} written", taille_lisible(rapide.octets)),
        ),
        Ligne::Texte(format!(
            "      {GRIS}{}{RESET}",
            tr!(
                "un quart de l'espace libre : vitesse, fausses clés courantes",
                "a quarter of the free space: speed, common fake drives"
            )
        )),
        Ligne::choix(
            "2",
            tr!("Complète", "Full"),
            &trf!("{} écrits", "{} written", taille_lisible(complete.octets)),
        ),
        Ligne::Texte(format!(
            "      {GRIS}{}{RESET}",
            tr!(
                "tout l'espace libre : la seule preuve de la capacité",
                "all the free space: the only proof of the capacity"
            )
        )),
        Ligne::choix("↵", tr!("Revenir", "Back"), ""),
        Ligne::Texte(String::new()),
    ];
    let choix = choisir(
        &lignes,
        tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    )?;
    match choix.trim() {
        "1" => Some(Mode::Rapide),
        "2" => Some(Mode::Complete),
        _ => None,
    }
}

fn identifiant_d_essai() -> u64 {
    let mut octets = [0u8; 8];
    if getrandom::fill(&mut octets).is_err() {
        // Sans générateur : l'heure, qui change d'un essai à l'autre ; c'est tout ce qu'on demande à cet identifiant.
        octets = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
            .to_le_bytes();
    }
    u64::from_le_bytes(octets)
}

/// « vanguard verifier-cle `[dossier]` » : sans dossier, la clé se choisit parmi celles qui sont branchées.
pub fn commande(dossier: Option<&Path>) {
    presenter();
    let disque = match dossier.map(disque_de) {
        None => choisir_disque(),
        Some(d) => d.inspect_err(|e| mauvais(e)).ok(),
    };
    let Some(disque) = disque else { return };
    let racine = disque.racine.clone();
    println!();
    proposer_d_effacer_les_restes(&racine);
    let Some((libre, total)) = place(&racine) else {
        mauvais(tr!(
            "Place libre illisible sur ce disque.",
            "Free space unreadable on this disk."
        ));
        return;
    };
    let occupe = total.saturating_sub(libre);
    let Some(mode) = choisir_mode(libre) else {
        if plan(libre, Mode::Complete, &Parametres::REELS).is_none() {
            mauvais(&trf!(
                "Trop peu de place libre ({}) : libérez de la place ou videz la clé, puis recommencez.",
                "Too little free space ({}): free up space or empty the drive, then start again.",
                taille_lisible(libre)
            ));
        }
        return;
    };
    let p = Parametres::REELS;
    let Some(plan) = plan(libre, mode, &p) else { return };
    if !annoncer(&disque, mode, &plan, &p, libre, total) {
        return;
    }
    let essai = identifiant_d_essai();
    let dossier = racine.join(format!("{PREFIXE_DOSSIER}{essai:016x}"));
    if let Err(e) = std::fs::create_dir(&dossier) {
        mauvais(&trf!(
            "Impossible de créer le dossier de l'essai : {e}",
            "Could not create the check folder: {e}"
        ));
        return;
    }
    println!();
    let (ecriture, lecture) = essayer(&dossier, &plan, &p, essai);
    let menage = nettoyer(&dossier);
    annoncer_le_resultat(mode, plan.octets, occupe, total, &ecriture, &lecture);
    annoncer_le_menage(&menage, &dossier);
}

/// Le titre et ce que fait la vérification, avant de choisir le disque.
fn presenter() {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("VÉRIFIER MA CLÉ", "CHECK MY DRIVE")),
        &format!(
            "{GRIS}{}{RESET}",
            tr!(
                "écrit dans le libre, puis efface",
                "writes in the free space, then erases"
            )
        ),
    );
    afficher_aligne(
        "  ",
        tr!(
            "Une fausse clé annonce 1 To et n'en a que 16 Go : elle accepte tout et rend n'importe quoi au-delà. Vanguard écrit dans l'espace libre un contenu qu'il saura reconnaître, relit tout en contournant la mémoire de l'ordinateur, mesure les vitesses, puis efface tout. Vos fichiers ne sont pas touchés.",
            "A fake drive claims 1 TB and has only 16 GB: it accepts everything and returns garbage beyond that. Vanguard writes recognizable content into the free space, reads it all back bypassing the computer's memory, measures the speeds, then erases everything. Your files are not touched."
        ),
        2,
        GRIS,
    );
}

/// Ce qu'un essai interrompu (débranchement, fermeture) a laissé : à nous, repris avant de compter la place.
fn proposer_d_effacer_les_restes(racine: &Path) {
    let restes = restes(racine);
    if restes.is_empty() {
        return;
    }
    let noms: Vec<String> = restes.iter().map(|r| chemin_affichable(r)).collect();
    info(&trf!(
        "Un essai interrompu a laissé ses fichiers sur ce disque : {}.",
        "An interrupted check left its files on this disk: {}.",
        noms.join(", ")
    ));
    if demander(tr!("  Les effacer ? [o/N] : ", "  Erase them? [y/N]: ")).oui() {
        for r in &restes {
            match nettoyer(r) {
                Ok(()) => bon(&trf!("{} effacé.", "{} erased.", chemin_affichable(r))),
                Err(e) => mauvais(&trf!("{} : {e}", "{}: {e}", chemin_affichable(r))),
            }
        }
    }
}

/// Ce qui va être écrit, où, combien de temps ça prendra ; `true` si la personne accepte de commencer.
fn annoncer(disque: &crate::copier::Disque, mode: Mode, plan: &Plan, p: &Parametres, libre: u64, total: u64) -> bool {
    let occupe = total.saturating_sub(libre);
    section(tr!("CE QUE VANGUARD VA FAIRE", "WHAT VANGUARD WILL DO"));
    let genre = crate::copier::genre_du_volume(&disque.racine).unwrap_or_default();
    afficher_aligne(
        "  ",
        &trf!(
            "Écrire {} dans un dossier « {PREFIXE_DOSSIER}… » à la racine de « {} » ({} libres sur {}, {} déjà occupés), en laissant {} libres. Puis tout relire, puis tout effacer.",
            "Write {} into a “{PREFIXE_DOSSIER}…” folder at the root of “{}” ({} free out of {}, {} already used), leaving {} free. Then read everything back, then erase everything.",
            taille_lisible(plan.octets),
            disque.nom,
            taille_lisible(libre),
            taille_lisible(total),
            taille_lisible(occupe),
            taille_lisible(plan.marge)
        ),
        2,
        "",
    );
    afficher_aligne(
        "  ",
        &trf!(
            "Durée : {} pour une clé USB ordinaire (20 Mo/s), {} pour une clé USB 3 ou un disque dur (100 Mo/s). Échap ou Ctrl-C arrêtent et effacent ce qui a été écrit.",
            "Duration: {} for an ordinary USB stick (20 MB/s), {} for a USB 3 stick or a hard disk (100 MB/s). Esc or Ctrl-C stop and erase what was written.",
            duree_estimee(plan.octets, 20 * MIO),
            duree_estimee(plan.octets, 100 * MIO)
        ),
        2,
        GRIS,
    );
    if mode == Mode::Rapide {
        afficher_aligne(
            "  ",
            tr!(
                "Rapide : repère une fausse clé dont la vraie capacité est inférieure au quart de l'annoncée (le cas courant) ; la vérification complète seule prouve toute la capacité.",
                "Quick: spots a fake drive whose real capacity is below a quarter of the claimed one (the common case); only the full check proves the whole capacity."
            ),
            2,
            GRIS,
        );
    }
    if crate::copier::limite_4_go(&genre) && p.fichier >= 4 * GIO {
        info(tr!("FAT32 : fichiers de 1 Go.", "FAT32: 1 GB files."));
    }
    demander(tr!("\n  Commencer ? [o/N] : ", "\n  Start? [y/N]: ")).oui()
}

/// L'écriture puis la relecture, avec l'avancement à l'écran ; Échap ou Ctrl-C arrêtent l'une ou l'autre.
fn essayer(dossier: &Path, plan: &Plan, p: &Parametres, essai: u64) -> (Ecriture, Lecture) {
    let clavier = Clavier::prendre();
    let mut avancement = Avancement::nouveau();
    let mut controle = |phase: Phase, fait: u64, total: u64| {
        avancement.montrer(phase, fait, total);
        clavier.arret_demande()
    };
    let ecriture = ecrire(dossier, plan.octets, p, essai, &mut controle);
    let lecture = if ecriture.arretee {
        Lecture {
            arretee: true,
            ..Lecture::default()
        }
    } else {
        relire(&ecriture.fichiers, p, essai, &mut controle)
    };
    avancement.finir();
    (ecriture, lecture)
}

/// Le verdict de l'essai, puis ce qui l'a arrêté et les vitesses mesurées.
fn annoncer_le_resultat(mode: Mode, prevu: u64, occupe: u64, total: u64, ecriture: &Ecriture, lecture: &Lecture) {
    section(tr!("RÉSULTAT", "RESULT"));
    match conclure(mode, prevu, occupe, total, ecriture, lecture) {
        Conclusion::Prouvee { verifie, occupe } => bon(&trf!(
            "Capacité confirmée : {} écrits et relus sans une erreur ({} déjà occupés par vos fichiers, non vérifiés).",
            "Capacity confirmed: {} written and read back without a single error ({} already used by your files, not checked).",
            taille_lisible(verifie),
            taille_lisible(occupe)
        )),
        Conclusion::AuMoins { verifie, annonce } => bon(&trf!(
            "Au moins {} réels sur {} annoncés : {} écrits et relus sans erreur. La vérification complète prouverait le reste.",
            "At least {} real out of {} claimed: {} written and read back without error. The full check would prove the rest.",
            taille_lisible(verifie),
            taille_lisible(annonce),
            taille_lisible(verifie)
        )),
        Conclusion::FausseCle { vraie, annonce } => {
            mauvais(&trf!(
                "FAUSSE CLÉ : elle annonce {} mais n'en a qu'environ {}. Au-delà, ce qu'on écrit remplace ce qui est déjà dessus ({} blocs relus portaient le contenu d'un autre bloc). Tout fichier qu'on y met au-delà de cette taille est perdu, sans prévenir.",
                "FAKE DRIVE: it claims {} but only has about {}. Beyond that, what is written replaces what is already on it ({} blocks read back held another block's content). Any file put on it beyond that size is lost, without warning.",
                taille_lisible(annonce),
                taille_lisible(vraie),
                lecture.recouverts
            ));
            info(tr!(
                "Gardez la preuve (cet écran) pour le vendeur ou la plateforme ; n'y stockez rien d'important.",
                "Keep the proof (this screen) for the seller or the platform; store nothing important on it."
            ));
        }
        Conclusion::Defaillante { defauts, premier } => mauvais(&trf!(
            "{defauts} bloc(s) faux ou illisibles (le premier vers {}) : la clé est en train de lâcher. Copiez ce qu'elle contient ailleurs dès maintenant, puis ne lui confie plus rien.",
            "{defauts} wrong or unreadable block(s) (the first around {}): the drive is failing. Copy what it holds elsewhere right now, then trust it with nothing more.",
            taille_lisible(premier)
        )),
        Conclusion::PlaceManquante { ecrit, prevu } => mauvais(&trf!(
            "La place a manqué après {} alors que {} devaient être libres : la table du disque ment ou est abîmée (fausse clé, ou système de fichiers à refaire).",
            "Space ran out after {} while {} were supposed to be free: the disk's table lies or is damaged (fake drive, or file system to rebuild).",
            taille_lisible(ecrit),
            taille_lisible(prevu)
        )),
        Conclusion::Interrompue { verifie } => info(&trf!(
            "Arrêté à votre demande : {} écrits, {} relus sans erreur. Rien n'est prouvé au-delà.",
            "Stopped at your request: {} written, {} read back without error. Nothing is proven beyond that.",
            taille_lisible(ecriture.octets),
            taille_lisible(verifie)
        )),
    }
    if let Some(e) = &ecriture.erreur {
        info(&trf!(
            "L'écriture s'est arrêtée après {} : {e}",
            "Writing stopped after {}: {e}",
            taille_lisible(ecriture.octets)
        ));
    }
    if ecriture.octets > 0 && ecriture.duree > Duration::ZERO {
        info(&trf!(
            "Écriture : {} ({}).",
            "Writing: {} ({}).",
            debit(ecriture.octets, ecriture.duree),
            qualifier_ecriture(ecriture.octets, ecriture.duree)
        ));
    }
    if lecture.octets > 0 && lecture.duree > Duration::ZERO {
        info(&trf!(
            "Lecture : {}.",
            "Reading: {}.",
            debit(lecture.octets, lecture.duree)
        ));
    }
}

/// Ce que dit le ménage : la clé est comme avant, ou le dossier de l'essai est à effacer à la main.
fn annoncer_le_menage(menage: &std::io::Result<()>, dossier: &Path) {
    match menage {
        Ok(()) => bon(tr!(
            "Tout ce que Vanguard a écrit est effacé ; la clé est comme avant.",
            "Everything Vanguard wrote is erased; the drive is as before."
        )),
        Err(e) => mauvais(&trf!(
            "Le dossier de l'essai n'a pas pu être effacé ({e}) : supprimez {} vous-même.",
            "The check folder could not be erased ({e}): delete {} yourself.",
            chemin_affichable(dossier)
        )),
    }
}

pub fn menu() {
    commande(None);
}

#[cfg(test)]
mod tests {
    use super::*;

    const PETIT: Parametres = Parametres {
        bloc: 64 * 1024,
        fichier: 256 * 1024,
    };

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-verif-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sans_arret(_: Phase, _: u64, _: u64) -> bool {
        false
    }

    #[test]
    fn le_menage_n_efface_que_les_fichiers_d_essai() {
        let d = std::env::temp_dir().join(format!("vanguard-verif-menage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("verif-0001.bin"), b"x").unwrap();
        std::fs::write(d.join("verif-0002.bin"), b"x").unwrap();
        std::fs::write(d.join("photos.zip"), b"a moi").unwrap();
        // Un fichier à garder : le dossier reste, avec lui, et c'est une erreur dite.
        assert!(nettoyer(&d).is_err());
        assert!(d.join("photos.zip").is_file() && !d.join("verif-0001.bin").exists());
        std::fs::remove_file(d.join("photos.zip")).unwrap();
        nettoyer(&d).unwrap();
        assert!(!d.exists());
        assert!(
            fichier_d_essai("verif-0042.bin") && !fichier_d_essai("verif-.bin") && !fichier_d_essai("verif-1.bin.txt")
        );
    }

    #[test]
    fn le_plan_laisse_une_marge_et_arrondit_au_bloc() {
        let p = &Parametres::REELS;
        // Trop peu de place : pas d'essai.
        assert_eq!(plan(10 * MIO, Mode::Complete, p), None);
        assert_eq!(plan(MARGE_MIN + MINIMUM - 1, Mode::Complete, p), None);
        // 32 Gio libres : tout sauf 1 % (plus que 64 Mio), en fichiers de 1 Gio.
        let c = plan(32 * GIO, Mode::Complete, p).unwrap();
        assert_eq!(c.marge, 32 * GIO / 100);
        assert_eq!(c.octets, (32 * GIO - c.marge) / p.bloc * p.bloc);
        assert_eq!(c.fichiers, c.octets.div_ceil(GIO));
        assert_eq!(c.octets % p.bloc, 0);
        // Rapide : un quart, au moins 2 Gio.
        let r = plan(32 * GIO, Mode::Rapide, p).unwrap();
        assert_eq!(r.octets, c.octets / 4 / p.bloc * p.bloc);
        let petit = plan(3 * GIO, Mode::Rapide, p).unwrap();
        assert_eq!(petit.octets, 2 * GIO);
        // Moins de 2 Gio disponibles : rapide = complète.
        let mini = plan(GIO, Mode::Rapide, p).unwrap();
        assert_eq!(mini.octets, plan(GIO, Mode::Complete, p).unwrap().octets);
        assert_eq!(plan(GIO, Mode::Complete, p).unwrap().marge, MARGE_MIN);
    }

    #[test]
    fn le_contenu_se_reconnait_et_se_distingue() {
        let mut t = vec![0u8; 4096 + 8];
        remplir(&mut t, 7, 2, 5);
        assert_eq!(juger(&t, 7, 2, 5), Verdict::Bon);
        // Le bloc d'un autre endroit du même essai : recouvrement.
        assert_eq!(juger(&t, 7, 0, 1), Verdict::AutreBloc { fichier: 2, bloc: 5 });
        // Un autre essai : faux, pas un recouvrement.
        assert_eq!(juger(&t, 8, 2, 5), Verdict::Faux);
        // Des zéros, ou un bloc abîmé au milieu : faux.
        assert_eq!(juger(&vec![0u8; 4096], 7, 2, 5), Verdict::Faux);
        t[2000] ^= 0xff;
        assert_eq!(juger(&t, 7, 2, 5), Verdict::Faux);
        assert_eq!(juger(&[], 7, 2, 5), Verdict::Faux);
        // Le motif porte bien les trois nombres.
        let m = motif(0x0102_0304_0506_0708, 9, 10);
        assert_eq!(&m[..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&m[8..12], &9u32.to_le_bytes());
        assert_eq!(&m[12..], &10u32.to_le_bytes());
    }

    #[test]
    fn tampon_aligne() {
        let (v, d) = tampon(100_000);
        assert_eq!(v[d..].as_ptr() as usize % ALIGNEMENT, 0);
        assert!(v.len() - d >= 100_000);
    }

    #[test]
    fn ecrit_relit_et_efface() {
        let base = jetable("bon");
        let dossier = base.join(format!("{PREFIXE_DOSSIER}essai"));
        std::fs::create_dir(&dossier).unwrap();
        let octets = 640 * 1024; // 2 fichiers pleins et un demi
        let mut phases = Vec::new();
        let mut controle = |phase: Phase, fait: u64, total: u64| {
            phases.push((phase, fait, total));
            false
        };
        let e = ecrire(&dossier, octets, &PETIT, 42, &mut controle);
        assert!(e.erreur.is_none() && !e.arretee, "{e:?}");
        assert_eq!(e.octets, octets);
        assert_eq!(
            e.fichiers.iter().map(|(_, t)| *t).collect::<Vec<_>>(),
            [256 * 1024, 256 * 1024, 128 * 1024]
        );
        assert!(
            e.fichiers
                .iter()
                .all(|(c, t)| std::fs::metadata(c).unwrap().len() == *t)
        );
        let l = relire(&e.fichiers, &PETIT, 42, &mut controle);
        assert_eq!(l.octets, octets);
        assert_eq!(l.defauts(), 0);
        assert_eq!(l.premier_defaut, None);
        assert!(!l.arretee);
        // Le contrôle a vu les deux phases, avec le bon total.
        assert!(phases.iter().any(|(p, _, t)| *p == Phase::Ecriture && *t == octets));
        assert!(phases.iter().any(|(p, _, t)| *p == Phase::Lecture && *t == octets));
        assert_eq!(restes(&base), vec![dossier.clone()]);
        nettoyer(&dossier).unwrap();
        assert!(!dossier.exists());
        assert_eq!(restes(&base).len(), 0);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn fausse_cle_et_blocs_faux_reperes() {
        let base = jetable("fausse");
        let dossier = base.join("essai");
        std::fs::create_dir(&dossier).unwrap();
        let e = ecrire(&dossier, 512 * 1024, &PETIT, 42, &mut sans_arret);
        assert_eq!(e.fichiers.len(), 2);
        // Le 2e bloc du 2e fichier porte le contenu du 1er bloc du 1er fichier : recouvrement.
        let debut = usize::try_from(PETIT.bloc).unwrap();
        let mut bloc = vec![0u8; debut];
        remplir(&mut bloc, 42, 0, 0);
        let mut contenu = std::fs::read(&e.fichiers[1].0).unwrap();
        contenu[debut..2 * debut].copy_from_slice(&bloc);
        // Le dernier bloc du 2e fichier : des zéros.
        let fin = contenu.len();
        contenu[fin - debut..].fill(0);
        std::fs::write(&e.fichiers[1].0, &contenu).unwrap();
        let l = relire(&e.fichiers, &PETIT, 42, &mut sans_arret);
        assert_eq!(l.recouverts, 1);
        assert_eq!(l.faux, 1);
        assert_eq!(l.illisibles, 0);
        assert_eq!(l.premier_defaut, Some(256 * 1024 + PETIT.bloc));
        // La conclusion : fausse clé, vraie taille = occupé + position du premier défaut.
        let c = conclure(Mode::Complete, 512 * 1024, 1000, 1_000_000, &e, &l);
        assert_eq!(
            c,
            Conclusion::FausseCle {
                vraie: 1000 + 256 * 1024 + PETIT.bloc,
                annonce: 1_000_000
            }
        );
        // Un fichier raccourci : ses blocs manquants sont illisibles, la lecture continue au fichier suivant.
        let premier = std::fs::read(&e.fichiers[0].0).unwrap();
        std::fs::write(&e.fichiers[0].0, &premier[..debut]).unwrap();
        let l = relire(&e.fichiers, &PETIT, 42, &mut sans_arret);
        assert_eq!(l.illisibles, 3);
        assert_eq!(l.premier_defaut, Some(PETIT.bloc));
        assert_eq!(l.octets, 512 * 1024);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn arret_demande_pendant_l_ecriture() {
        let base = jetable("arret");
        let dossier = base.join("essai");
        std::fs::create_dir(&dossier).unwrap();
        let mut blocs = 0;
        let mut controle = |_: Phase, _: u64, _: u64| {
            blocs += 1;
            blocs > 3
        };
        let e = ecrire(&dossier, 1024 * 1024, &PETIT, 1, &mut controle);
        assert!(e.arretee);
        assert_eq!(e.octets, 3 * PETIT.bloc);
        assert_eq!(e.fichiers.len(), 1);
        assert_eq!(std::fs::metadata(&e.fichiers[0].0).unwrap().len(), 3 * PETIT.bloc);
        let l = Lecture {
            arretee: true,
            ..Lecture::default()
        };
        assert_eq!(
            conclure(Mode::Rapide, 1024 * 1024, 0, 2_000_000, &e, &l),
            Conclusion::Interrompue { verifie: 0 }
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn conclusions_selon_le_mode_et_la_place() {
        let bonne = Lecture {
            octets: 1000,
            ..Lecture::default()
        };
        let e = Ecriture {
            octets: 1000,
            ..Ecriture::default()
        };
        assert_eq!(
            conclure(Mode::Complete, 1000, 500, 2000, &e, &bonne),
            Conclusion::Prouvee {
                verifie: 1000,
                occupe: 500
            }
        );
        assert_eq!(
            conclure(Mode::Rapide, 1000, 500, 2000, &e, &bonne),
            Conclusion::AuMoins {
                verifie: 1000,
                annonce: 2000
            }
        );
        // La place a manqué bien avant : table abîmée ou fausse ; de peu : on conclut quand même.
        let courte = Ecriture {
            octets: 600,
            erreur: Some(std::io::Error::from(std::io::ErrorKind::StorageFull)),
            ..Ecriture::default()
        };
        assert_eq!(
            conclure(Mode::Complete, 1000, 0, 2000, &courte, &bonne),
            Conclusion::PlaceManquante {
                ecrit: 600,
                prevu: 1000
            }
        );
        let presque = Ecriture {
            octets: 980,
            erreur: Some(std::io::Error::from(std::io::ErrorKind::StorageFull)),
            ..Ecriture::default()
        };
        assert!(matches!(
            conclure(Mode::Complete, 1000, 0, 2000, &presque, &bonne),
            Conclusion::Prouvee { .. }
        ));
        let abimee = Lecture {
            octets: 1000,
            faux: 2,
            illisibles: 1,
            premier_defaut: Some(300),
            ..Lecture::default()
        };
        assert_eq!(
            conclure(Mode::Complete, 1000, 100, 2000, &e, &abimee),
            Conclusion::Defaillante {
                defauts: 3,
                premier: 400
            }
        );
    }

    #[test]
    fn debits_durees_et_qualites() {
        assert_eq!(debit(100 * MIO, Duration::from_secs(4)), "25 Mo/s");
        assert_eq!(debit(3 * GIO, Duration::from_secs(1)), "3,0 Go/s");
        assert_eq!(duree_estimee(600 * MIO, 20 * MIO), "environ 60 s");
        assert_eq!(duree_estimee(10 * GIO, 20 * MIO), "environ 18 min");
        assert_eq!(duree_estimee(500 * GIO, 20 * MIO), "environ 14,2 h");
        assert_eq!(minutes(45), "45 s");
        assert_eq!(minutes(130), "3 min");
        assert_eq!(minutes(4000), "1 h 06");
        assert!(qualifier_ecriture(2 * MIO, Duration::from_secs(1)).contains("lent"));
        assert!(qualifier_ecriture(20 * MIO, Duration::from_secs(1)).contains("ordinaire"));
        assert!(qualifier_ecriture(60 * MIO, Duration::from_secs(1)).contains("USB 3"));
        assert!(qualifier_ecriture(400 * MIO, Duration::from_secs(1)).contains("SSD"));
    }

    /// Les vraies tailles (blocs de 4 Mio, lecture sans cache) sur un petit essai : le chemin réel, de bout en bout.
    #[test]
    fn tailles_reelles_sur_un_petit_essai() {
        let base = jetable("reel");
        let dossier = base.join("essai");
        std::fs::create_dir(&dossier).unwrap();
        let p = Parametres::REELS;
        let e = ecrire(&dossier, 12 * MIO, &p, 3, &mut sans_arret);
        assert!(e.erreur.is_none(), "{:?}", e.erreur);
        assert_eq!(e.fichiers.len(), 1);
        let l = relire(&e.fichiers, &p, 3, &mut sans_arret);
        assert_eq!((l.octets, l.defauts()), (12 * MIO, 0));
        nettoyer(&dossier).unwrap();
        assert!(!dossier.exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn un_chemin_hors_des_disques_est_refuse() {
        // Le dossier temporaire est sur le disque du système, ou dans un dossier que la liste n'a pas : refusé.
        let r = disque_de(&std::env::temp_dir());
        if let Err(e) = r {
            assert!(e.contains("exclus") || e.contains("excluded"), "{e}");
        }
        assert_ne!(identifiant_d_essai(), identifiant_d_essai());
    }
}
