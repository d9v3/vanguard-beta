//! Scan YARA de la mémoire des processus en marche : les 308 règles de `yara` appliquées aux régions privées ou
//! exécutables de chaque programme, là où vit un logiciel malveillant « sans fichier » (chargeur réfléchi, shellcode,
//! programme effacé du disque mais encore en marche, exécutable déballé que son emballage cachait sur le disque).
//! Lecture seule, à la demande seulement, jamais en fond : aucun processus n'est touché. Sous Windows, LSASS, les
//! processus protégés et les processus critiques ne sont jamais lus (lire LSASS est le geste d'un voleur de mots de
//! passe, que Defender bloque) ; un nom ne suffit pas à écarter un processus : seul le programme de System32 qui le
//! porte l'est, et un autre qui prend ce nom est lu et signalé (masquage). Sous Linux et macOS, le nom d'un processus
//! est choisi par le programme lui-même : rien n'est écarté sur lui, seul Vanguard ne se lit pas. Rien de ce qui est
//! lu n'est gardé nulle part : seulement la règle, le PID, le programme et l'adresse. Ce qui n'a pas pu être lu est
//! dit, jamais compté comme sain. Sur macOS, la mémoire d'autrui demande des droits spéciaux (task_for_pid) : non
//! vérifié, dit tel quel.

use std::time::{Duration, Instant};

use crate::protection::moteur_yara::Regles;
use crate::protection::yara;
use crate::ui::*;

/// Une région plus grosse n'est pas lue (tas de navigateurs et de jeux) : les charges malveillantes sont petites, et
/// la région est comptée comme non lue. C'est aussi la taille du tampon de lecture, fixée une fois pour toutes.
const TAILLE_REGION_MAX: usize = 64 << 20;
/// Lu au plus par processus, puis en tout ; au-delà, on s'arrête et on dit ce qui manque.
const PAR_PROCESSUS_MAX: u64 = 512 << 20;
const TOTAL_MAX: u64 = 4 << 30;
const DUREE_MAX: Duration = Duration::from_secs(300);
const DELAI_PAR_REGION: Duration = Duration::from_secs(10);

/// Les processus critiques de Windows, jamais lus : LSASS et son isolat (les mots de passe), le noyau et ses
/// processus critiques (en tuer un arrête Windows ; les lire ne sert à rien). Seconde barrière derrière le niveau de
/// protection, mais un nom se choisit : seul le programme de System32 qui le porte est écarté (`trier`).
const CRITIQUES: &[&str] = &[
    "lsass",
    "lsaiso",
    "system",
    "secure system",
    "idle",
    "registry",
    "csrss",
    "smss",
    "wininit",
    "services",
    "memcompression",
    "memory compression",
];

/// Un processus en marche : son numéro et son nom, prêt à montrer.
struct Processus {
    pid: u32,
    nom: String,
}

/// Une région de mémoire : son adresse et sa taille.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Region {
    pub debut: u64,
    pub taille: u64,
}

/// Le nom d'un processus critique de Windows, quelle que soit sa casse.
fn critique(nom: &str) -> bool {
    CRITIQUES.iter().any(|c| nom.eq_ignore_ascii_case(c))
}

/// Sous Windows, où est le programme d'un processus au nom critique : le dossier System32 et le chemin complet du
/// programme, chacun `None` s'il ne se lit pas (pour un autre nom, rien n'est demandé).
#[derive(Debug, Default)]
struct Lieux {
    system32: Option<String>,
    programme: Option<String>,
}

/// Le sort d'un processus, décidé avant toute lecture.
#[derive(Debug, PartialEq)]
enum Tri {
    /// Jamais lu, par choix.
    Exclu,
    Lire,
    /// Le nom d'un processus critique de Windows porté par un programme hors de System32 : un masquage (MITRE ATT&CK
    /// T1036.005). Lu comme les autres, et signalé.
    Masque,
    /// Un nom critique dont le programme ne se lit pas (droits, processus du noyau sans fichier) : seul son niveau de
    /// protection peut l'écarter. Sinon il n'est pas ouvert en lecture (ce peut être le vrai LSASS) et il compte comme
    /// non lu : jamais sain sur son seul nom.
    Incertain,
}

/// Le programme est-il exactement `<System32>\<nom>.exe` ? Comparé tel que Windows écrit les deux chemins, sans casse
/// pour les lettres ASCII seulement : « SysWOW64 », un sous-dossier, « ..\ », un nom court ou un flux sont ailleurs.
fn a_sa_place(nom: &str, programme: &str, system32: &str) -> bool {
    let attendu = format!(r"{}\{nom}.exe", system32.trim_end_matches('\\'));
    !system32.is_empty() && programme.eq_ignore_ascii_case(&attendu)
}

/// Vanguard lui-même (`moi`) n'est jamais lu, partout. `windows` : `None` sous Linux et macOS, où le nom (comm, ps)
/// est choisi par le programme : rien d'autre n'est écarté. Sous Windows, Idle (0) et System (4) sont écartés par leur
/// numéro, et un nom critique ne l'est que si son programme est celui de System32.
fn trier(pid: u32, nom: &str, moi: u32, windows: Option<&Lieux>) -> Tri {
    if pid == moi {
        return Tri::Exclu;
    }
    let Some(lieux) = windows else {
        return Tri::Lire;
    };
    if pid == 0 || pid == 4 {
        return Tri::Exclu;
    }
    if !critique(nom) {
        return Tri::Lire;
    }
    // Un « chemin » sans « \ » n'est pas un fichier : les processus minimaux du noyau (Registry, MemCompression) n'en
    // ont pas.
    let programme = lieux.programme.as_deref().filter(|p| p.contains('\\'));
    match (lieux.system32.as_deref(), programme) {
        (Some(system32), Some(programme)) if a_sa_place(nom, programme, system32) => Tri::Exclu,
        (Some(_), Some(_)) => Tri::Masque,
        _ => Tri::Incertain,
    }
}

/// Une région de Windows à lire (VirtualQueryEx : état, protection, type) : validée (MEM_COMMIT), lisible (ni
/// PAGE_NOACCESS ni PAGE_GUARD, qui ferait une exception dans le programme lu), et privée (MEM_PRIVATE : tas, piles,
/// VirtualAlloc, là où un chargeur pose son code) ou mappée exécutable. Une image (MEM_IMAGE) est un fichier mappé,
/// déjà le domaine du scan de fichiers.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn region_windows(etat: u32, protection: u32, sorte: u32) -> bool {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    const EXECUTABLES: u32 = 0xF0;
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;
    let acces = protection & 0xFF;
    etat == MEM_COMMIT
        && acces != 0
        && acces != PAGE_NOACCESS
        && protection & PAGE_GUARD == 0
        && (sorte == MEM_PRIVATE || (sorte == MEM_MAPPED && protection & EXECUTABLES != 0))
}

/// Une ligne de /proc/<pid>/maps, retenue si la région est lisible et anonyme (tas, piles, VirtualAlloc de Linux :
/// mmap sans fichier) ou si son fichier a été effacé (« (deleted) », memfd : le programme qui tourne n'existe plus
/// sur le disque). Un fichier mappé encore présent est le domaine du scan de fichiers ; vdso, vvar et vsyscall sont au
/// noyau.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn region_linux(ligne: &str) -> Option<Region> {
    let mut champs = ligne.splitn(6, ' ');
    let (adresses, droits) = (champs.next()?, champs.next()?);
    let chemin = champs.nth(3).map(str::trim).unwrap_or_default();
    if !droits.starts_with('r') {
        return None;
    }
    let anonyme =
        chemin.is_empty() || chemin == "[heap]" || chemin.starts_with("[stack") || chemin.starts_with("[anon");
    let efface = chemin.ends_with(" (deleted)") || chemin.starts_with("/memfd:");
    if !(anonyme || efface) {
        return None;
    }
    let (debut, fin) = adresses.split_once('-')?;
    let (debut, fin) = (u64::from_str_radix(debut, 16).ok()?, u64::from_str_radix(fin, 16).ok()?);
    (fin > debut).then(|| Region {
        debut,
        taille: fin - debut,
    })
}

/// Ce que les bornes décident pour une région.
#[derive(Debug, PartialEq)]
enum Decision {
    Lire,
    /// Trop grosse : sautée, dite.
    Sauter,
    /// Ce processus a eu sa part : le reste de ses régions est sauté, dit.
    ProcessusPlein,
    /// Le temps ou le total est atteint : tout s'arrête, dit.
    Arret,
}

fn decider(taille: u64, lu_processus: u64, lu_total: u64, ecoule: Duration) -> Decision {
    if ecoule >= DUREE_MAX || lu_total >= TOTAL_MAX {
        Decision::Arret
    } else if taille > TAILLE_REGION_MAX as u64 {
        Decision::Sauter
    } else if lu_processus + taille > PAR_PROCESSUS_MAX {
        Decision::ProcessusPlein
    } else {
        Decision::Lire
    }
}

/// Ce qu'a donné la lecture d'un processus : les règles trouvées avec leur région, les octets lus, les régions
/// sautées ou illisibles, celles lues seulement jusqu'à un trou (une partie libérée entre la liste des régions et leur
/// lecture : le reste n'est pas lu), et si une borne générale a tout arrêté.
#[derive(Debug, Default, PartialEq)]
struct Lecture {
    trouves: Vec<(String, Region)>,
    octets: u64,
    sautees: usize,
    partielles: usize,
    arret: bool,
}

impl Lecture {
    /// Tout ce qui devait être lu ne l'a pas été : le processus compte comme lu en partie, jamais comme lu en entier.
    fn incomplete(&self) -> bool {
        self.sautees > 0 || self.partielles > 0
    }
}

/// Le tampon de lecture : sa taille est fixée à sa création (la plus grosse région lue) et ne change jamais. Un
/// tampon qui grandit est recopié ailleurs, et l'ancien bloc, libéré sans être effacé, garde la mémoire lue. Il est
/// effacé en entier quand il disparaît, même après une panique.
struct Tampon(Box<[u8]>);

impl Tampon {
    fn nouveau(taille: usize) -> Tampon {
        Tampon(vec![0; taille].into_boxed_slice())
    }
}

impl Drop for Tampon {
    fn drop(&mut self) {
        effacer(&mut self.0);
    }
}

/// Remet chaque octet à zéro par des écritures que le compilateur ne peut pas retirer : un simple `fill(0)` juste
/// avant la libération est une écriture sans lecteur, qu'il a le droit de supprimer.
fn effacer(octets: &mut [u8]) {
    let (blocs, reste) = octets.as_chunks_mut::<64>();
    for bloc in blocs {
        // SAFETY : `bloc` vient d'une référence exclusive : adresse valide, alignée (octets), initialisée, à nous seuls.
        unsafe { std::ptr::write_volatile(bloc, [0; 64]) };
    }
    for octet in reste {
        // SAFETY : comme plus haut, un seul octet.
        unsafe { std::ptr::write_volatile(octet, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Lit les régions par `lire`, chacune dans le début de `tampon` (jamais agrandi : une région plus grande est sautée),
/// et leur applique les règles, dans les bornes, chaque région comme un fichier à part (une chaîne à cheval sur deux
/// régions n'est pas vue, comme avec YARA-X). `lire` rend le nombre d'octets lus (0 : rien). `lu_total` et `debut` :
/// ce qui a déjà été lu dans les processus d'avant, et le départ de l'analyse. Une région que le moteur n'a pas pu
/// finir (délai, ou panique sur un contenu piégé) est comptée sautée : jamais lue en entier pour rien.
fn analyser_regions(
    regles: &Regles,
    regions: &[Region],
    tampon: &mut [u8],
    mut lire: impl FnMut(&Region, &mut [u8]) -> usize,
    lu_total: u64,
    debut: Instant,
) -> Lecture {
    let mut lecture = Lecture::default();
    for (i, region) in regions.iter().enumerate() {
        match decider(
            region.taille,
            lecture.octets,
            lu_total + lecture.octets,
            debut.elapsed(),
        ) {
            Decision::Arret => {
                lecture.arret = true;
                lecture.sautees += regions.len() - i;
                break;
            }
            Decision::ProcessusPlein => {
                lecture.sautees += regions.len() - i;
                break;
            }
            Decision::Sauter => lecture.sautees += 1,
            Decision::Lire => {
                let Some(zone) = usize::try_from(region.taille).ok().and_then(|t| tampon.get_mut(..t)) else {
                    lecture.sautees += 1;
                    continue;
                };
                let lus = lire(region, zone).min(zone.len());
                if lus == 0 {
                    lecture.sautees += 1;
                    continue;
                }
                if lus < zone.len() {
                    lecture.partielles += 1;
                }
                lecture.octets += lus as u64;
                let echeance = Instant::now() + DELAI_PAR_REGION;
                let zone = &zone[..lus];
                match crate::journal::rattraper(std::panic::AssertUnwindSafe(|| {
                    regles.analyser_tampon(zone, Some(echeance))
                })) {
                    Ok(Ok(trouvees)) => lecture
                        .trouves
                        .extend(trouvees.into_iter().map(|k| (regles.nom(k).to_string(), *region))),
                    _ => lecture.sautees += 1,
                }
            }
        }
    }
    lecture
}

/// Comment un processus s'est ouvert.
enum Acces {
    /// Protégé par Windows (PPL) ou niveau illisible : exclu par choix, jamais lu.
    #[cfg_attr(not(windows), allow(dead_code))]
    Protege,
    /// Le système refuse (droits insuffisants) : non lu, dit.
    Refuse,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    Ouvert(plateforme::Lecteur),
}

#[cfg(target_os = "linux")]
mod plateforme {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use super::{Acces, Processus, Region, region_linux};

    /// Les processus de /proc, nom d'après `comm` (choisi par le programme : rendu inoffensif).
    pub(super) fn processus() -> Vec<Processus> {
        crate::socle::processus::pids()
            .unwrap_or_default()
            .into_iter()
            .map(|pid| Processus {
                pid,
                nom: crate::ui::affichable(crate::socle::processus::nom_court(pid).unwrap_or_default().trim()),
            })
            .collect()
    }

    /// /proc/<pid>/maps pour les régions, /proc/<pid>/mem pour les lire : le noyau refuse l'ouverture de `mem` sans
    /// le droit de tracer le processus (autre compte, ou Yama ptrace_scope ≥ 1 hors de ses descendants).
    pub(super) fn ouvrir(pid: u32) -> Acces {
        let Ok(cartes) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            return Acces::Refuse;
        };
        match File::open(format!("/proc/{pid}/mem")) {
            Ok(fichier) => Acces::Ouvert(Lecteur {
                fichier,
                regions: cartes.lines().filter_map(region_linux).collect(),
            }),
            Err(_) => Acces::Refuse,
        }
    }

    /// Aucun niveau de protection ici : le tri n'en demande jamais (rien n'y est « incertain »).
    pub(super) fn protege(_pid: u32) -> bool {
        false
    }

    pub(super) struct Lecteur {
        fichier: File,
        regions: Vec<Region>,
    }

    impl Lecteur {
        pub(super) fn regions(&self) -> Vec<Region> {
            self.regions.clone()
        }

        /// Lit le début d'une région dans `zone` (de sa taille) et rend le nombre d'octets lus : 0 si rien n'a pu
        /// l'être (région disparue entre-temps). Une lecture partielle est gardée telle quelle : ce qui est lu est
        /// analysé.
        pub(super) fn lire(&self, region: &Region, zone: &mut [u8]) -> usize {
            let mut fait = 0usize;
            while fait < zone.len() {
                match self.fichier.read_at(&mut zone[fait..], region.debut + fait as u64) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => fait += n,
                }
            }
            fait
        }
    }
}

#[cfg(windows)]
mod plateforme {
    use super::{Acces, Lieux, Processus, critique};
    use crate::machine::windows::{memoire, processus};

    pub(super) type Lecteur = memoire::Lecteur;

    /// Toolhelp32, sans rien ouvrir ; seul un nom critique fait ensuite lire le chemin de son programme (`lieux`).
    pub(super) fn processus() -> Vec<Processus> {
        processus::liste()
            .into_iter()
            .map(|p| Processus { pid: p.pid, nom: p.nom })
            .collect()
    }

    /// Le dossier System32 et le chemin du programme, demandés pour un nom critique seulement : le chemin se lit avec
    /// les seuls droits « limités », comme dans le Gestionnaire des tâches, jamais avec le droit de lire la mémoire.
    pub(super) fn lieux(pid: u32, nom: &str) -> Lieux {
        if !critique(nom) {
            return Lieux::default();
        }
        Lieux {
            system32: memoire::system32(),
            programme: processus::chemin(pid),
        }
    }

    /// Le niveau de protection seul, pour un processus au nom critique dont le programme ne se lit pas : protégé, il
    /// est écarté par son niveau ; sinon, ou illisible, il n'est pas lu.
    pub(super) fn protege(pid: u32) -> bool {
        memoire::protege(pid) == Some(true)
    }

    /// Le niveau de protection d'abord, avec les seuls droits « limités » ; PROCESS_VM_READ seulement ensuite, et
    /// seulement sans protection.
    pub(super) fn ouvrir(pid: u32) -> Acces {
        match memoire::protege(pid) {
            None => Acces::Refuse,
            Some(true) => Acces::Protege,
            Some(false) => Lecteur::ouvrir(pid).map_or(Acces::Refuse, Acces::Ouvert),
        }
    }
}

#[cfg(target_os = "macos")]
mod plateforme {
    use super::{Acces, Processus, Region};

    /// La liste des processus, pour dire combien ne sont pas lus : task_for_pid demande root et un droit spécial que
    /// Vanguard n'a pas ; rien n'est lu, rien n'est conclu. Demandée au noyau, `ps` en secours.
    pub(super) fn processus() -> Vec<Processus> {
        if let Some(liste) = crate::machine::macos::noyau::processus(false) {
            return liste
                .iter()
                .map(|p| Processus {
                    pid: p.pid,
                    nom: crate::ui::affichable(&p.nom()),
                })
                .collect();
        }
        let mut ps = std::process::Command::new("ps");
        ps.args(["-axo", "pid=,comm="]);
        let Some(resultat) = crate::commande::lancer(&mut ps, 10) else {
            return Vec::new();
        };
        resultat
            .sortie
            .lines()
            .filter_map(|l| {
                let (pid, nom) = l.trim().split_once(' ')?;
                Some(Processus {
                    pid: pid.parse().ok()?,
                    nom: crate::ui::affichable(nom.trim()),
                })
            })
            .collect()
    }

    pub(super) fn ouvrir(_pid: u32) -> Acces {
        Acces::Refuse
    }

    /// Aucun niveau de protection ici : le tri n'en demande jamais (rien n'y est « incertain »).
    pub(super) fn protege(_pid: u32) -> bool {
        false
    }

    /// Jamais construit ici (`Infallible`) : la forme attendue par le reste du module.
    #[allow(dead_code)]
    pub(super) struct Lecteur(std::convert::Infallible);

    impl Lecteur {
        pub(super) fn regions(&self) -> Vec<Region> {
            match self.0 {}
        }

        pub(super) fn lire(&self, _region: &Region, _zone: &mut [u8]) -> usize {
            match self.0 {}
        }
    }
}

/// Une correspondance : la règle, le processus, la région. Rien du contenu lu.
#[derive(Debug, PartialEq)]
struct Trouve {
    regle: String,
    pid: u32,
    programme: String,
    region: Region,
}

/// Un programme qui porte le nom d'un processus critique de Windows hors de System32 (T1036.005).
#[derive(Debug, PartialEq)]
struct Masque {
    pid: u32,
    programme: String,
    chemin: String,
}

/// Le bilan de l'analyse : combien de processus lus, non lus (droits), exclus par choix, lus en partie, si une
/// borne a tout arrêté, les règles que le moteur a refusées (non vérifiées), les correspondances et les masquages.
#[derive(Debug, Default, PartialEq)]
struct Bilan {
    regles_refusees: usize,
    lus: usize,
    non_lus: usize,
    exclus: usize,
    incomplets: usize,
    arrete: bool,
    trouves: Vec<Trouve>,
    masques: Vec<Masque>,
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Sain,
    /// Rien trouvé, mais tout n'a pas été lu : pas de ✔.
    Incomplet,
    Trouve,
}

/// Le jugement : sain seulement si tout ce qui devait être lu l'a été. Les exclus par choix ne rendent pas l'analyse
/// incomplète (ils sont dits à part), mais zéro processus lu, si.
fn verdict(bilan: &Bilan) -> Verdict {
    if !bilan.trouves.is_empty() || !bilan.masques.is_empty() {
        Verdict::Trouve
    } else if bilan.lus == 0 || bilan.non_lus > 0 || bilan.incomplets > 0 || bilan.arrete || bilan.regles_refusees > 0 {
        Verdict::Incomplet
    } else {
        Verdict::Sain
    }
}

/// Tous les processus, un seul fil : la lecture de la mémoire d'autrui ne se parallélise pas (pression sur le
/// système, ordre lisible). Après un arrêt sur une borne, les processus restants sont comptés non lus.
fn parcourir(regles: &Regles) -> Bilan {
    let moi = std::process::id();
    let debut = Instant::now();
    let mut bilan = Bilan {
        regles_refusees: regles.refus().len(),
        ..Bilan::default()
    };
    let mut lu_total = 0u64;
    let mut tampon = Tampon::nouveau(TAILLE_REGION_MAX);
    let liste = plateforme::processus();
    trp!(
        "  {} processus en marche ; lecture seule, au plus {} minutes…",
        "  {} running processes; read-only, at most {} minutes…",
        liste.len(),
        DUREE_MAX.as_secs() / 60
    );
    let mut restants = liste.iter();
    for p in restants.by_ref() {
        #[cfg(windows)]
        let lieux = Some(plateforme::lieux(p.pid, &p.nom));
        #[cfg(not(windows))]
        let lieux: Option<Lieux> = None;
        match trier(p.pid, &p.nom, moi, lieux.as_ref()) {
            Tri::Exclu => {
                bilan.exclus += 1;
                continue;
            }
            Tri::Incertain => {
                if plateforme::protege(p.pid) {
                    bilan.exclus += 1;
                } else {
                    bilan.non_lus += 1;
                }
                continue;
            }
            Tri::Masque => bilan.masques.push(Masque {
                pid: p.pid,
                programme: p.nom.clone(),
                chemin: lieux.and_then(|l| l.programme).unwrap_or_default(),
            }),
            Tri::Lire => {}
        }
        match plateforme::ouvrir(p.pid) {
            Acces::Protege => bilan.exclus += 1,
            Acces::Refuse => bilan.non_lus += 1,
            Acces::Ouvert(lecteur) => {
                let regions = lecteur.regions();
                let lecture = analyser_regions(
                    regles,
                    &regions,
                    &mut tampon.0,
                    |r, z| lecteur.lire(r, z),
                    lu_total,
                    debut,
                );
                lu_total += lecture.octets;
                bilan.lus += 1;
                if lecture.incomplete() {
                    bilan.incomplets += 1;
                }
                bilan
                    .trouves
                    .extend(lecture.trouves.into_iter().map(|(regle, region)| Trouve {
                        regle,
                        pid: p.pid,
                        programme: p.nom.clone(),
                        region,
                    }));
                if lecture.arret {
                    bilan.arrete = true;
                    break;
                }
            }
        }
    }
    bilan.non_lus += restants.count();
    bilan
}

fn avertir(texte: &str) {
    for (i, ligne) in envelopper(texte, LARGEUR - 4).iter().enumerate() {
        println!("  {} {ligne}", if i == 0 { "⚠" } else { " " });
    }
}

fn afficher(bilan: &Bilan, regles: &Regles) {
    println!();
    if let Some(texte) = yara::non_verifiees(regles) {
        avertir(&trf!(
            "{texte}. Rien n'est conclu pour elles.",
            "{texte}. Nothing is concluded for them."
        ));
    }
    if bilan.exclus > 0 {
        let texte = if cfg!(windows) {
            trf!(
                "{} processus jamais lus, par choix : LSASS et les processus critiques de Windows (leur programme de System32), les processus protégés, Vanguard lui-même.",
                "{} processes never read, by design: LSASS and critical Windows processes (their System32 program), protected processes, Vanguard itself.",
                bilan.exclus
            )
        } else {
            trf!(
                "{} processus jamais lu, par choix : Vanguard lui-même.",
                "{} process never read, by design: Vanguard itself.",
                bilan.exclus
            )
        };
        for ligne in envelopper(&texte, LARGEUR - 2) {
            println!("  {GRIS}{ligne}{RESET}");
        }
    }
    if bilan.non_lus > 0 {
        // Déjà en administrateur, conseiller de relancer en administrateur serait faux : sous Windows, les processus des
        // services restent fermés sans le privilège de débogage, que Vanguard refuse exprès de prendre.
        let texte = if crate::traces::privilegie() {
            trf!(
                "{} processus n'ont pas pu être lus, même en administrateur : le système les ferme à qui n'a pas le privilège de débogage, que Vanguard ne prend pas exprès. Rien n'est conclu pour eux.",
                "{} processes could not be read, even as administrator: the system closes them to anyone without the debug privilege, which Vanguard deliberately does not take. Nothing is concluded for them.",
                bilan.non_lus
            )
        } else {
            trf!(
                "{} processus n'ont pas pu être lus (droits insuffisants : relancez en administrateur ou root) : rien n'est conclu pour eux.",
                "{} processes could not be read (insufficient rights: run again as administrator or root): nothing is concluded for them.",
                bilan.non_lus
            )
        };
        avertir(&texte);
    }
    if bilan.incomplets > 0 {
        avertir(&trf!(
            "{} processus lus en partie : régions de plus de {} Mio, au-delà de {} Mio par processus, ou disparues entre-temps, en tout ou en partie.",
            "{} processes partly read: regions over {} MiB, beyond {} MiB per process, or gone in the meantime, wholly or in part.",
            bilan.incomplets,
            TAILLE_REGION_MAX >> 20,
            PAR_PROCESSUS_MAX >> 20
        ));
    }
    if bilan.arrete {
        avertir(&trf!(
            "Arrêt sur une borne ({} minutes ou {} Gio lus) : le reste n'a pas été lu.",
            "Stopped at a limit ({} minutes or {} GiB read): the rest was not read.",
            DUREE_MAX.as_secs() / 60,
            TOTAL_MAX >> 30
        ));
    }
    match verdict(bilan) {
        Verdict::Sain => trp!(
            "  {VERT}✔{RESET} Aucune région de la mémoire des {} processus lus ne correspond aux 308 règles.",
            "  {VERT}✔{RESET} No memory region of the {} processes read matches the 308 rules.",
            bilan.lus
        ),
        Verdict::Incomplet => trp!(
            "  Rien trouvé dans les {} processus lus ; analyse incomplète, voir plus haut.",
            "  Nothing found in the {} processes read; incomplete scan, see above.",
            bilan.lus
        ),
        Verdict::Trouve => {
            for m in &bilan.masques {
                trp!(
                    "  {}✖{RESET} {} (PID {}) : nom d'un processus de Windows, porté par un programme hors de System32 (masquage, T1036.005)",
                    "  {}✖{RESET} {} (PID {}): a Windows process name, carried by a program outside System32 (masquerading, T1036.005)",
                    couleur(crate::risk::Niveau::Eleve),
                    m.programme,
                    m.pid
                );
                println!("      {GRIS}{}{RESET}", couper(&affichable(&m.chemin), LARGEUR - 6));
            }
            for t in &bilan.trouves {
                println!(
                    "  {}✖{RESET} {} (PID {}) : {} ({})",
                    couleur(crate::risk::Niveau::Eleve),
                    t.programme,
                    t.pid,
                    yara::famille(&t.regle),
                    t.regle
                );
                println!(
                    "      {GRIS}{}{RESET}",
                    trf!(
                        "région 0x{:x}, {} Kio",
                        "region 0x{:x}, {} KiB",
                        t.region.debut,
                        t.region.taille >> 10
                    )
                );
            }
            println!();
            for ligne in envelopper(
                tr!(
                    "Rien n'a été arrêté : c'est une alerte, à juger. Un programme légitime peut porter une signature en mémoire (antivirus, outils de sécurité, navigateur ouvert sur une page qui parle de ces menaces). Notez le programme et son PID ; en cas de doute, coupez Internet, puis collectez les traces (Suis-je infecté ?).",
                    "Nothing was stopped: this is an alert, for you to judge. A legitimate program can carry a signature in memory (antivirus, security tools, a browser open on a page about these threats). Note the program and its PID; when in doubt, cut the Internet, then collect the traces (Am I infected?)."
                ),
                LARGEUR - 2,
            ) {
                println!("  {ligne}");
            }
        }
    }
}

/// Menu Antivirus et protection › Mémoire des processus, et `vanguard memoire`.
pub fn analyser() {
    titre(tr!("Mémoire des processus", "Process memory"));
    for ligne in envelopper(
        tr!(
            "Lecture seule de la mémoire des programmes en marche, à la recherche des 308 règles YARA : un logiciel malveillant sans fichier ne vit que là. LSASS, les processus protégés et critiques de Windows ne sont jamais lus (un programme qui prend leur nom hors de System32, si) ; rien de ce qui est lu n'est gardé.",
            "Read-only pass over the memory of running programs, looking for the 308 YARA rules: fileless malware lives nowhere else. LSASS, protected and critical Windows processes are never read (a program taking their name outside System32 is); nothing read is kept."
        ),
        LARGEUR - 2,
    ) {
        println!("  {ligne}");
    }
    if cfg!(target_os = "macos") {
        avertir(tr!(
            "Sur macOS, la mémoire d'un autre processus ne se lit pas sans un droit spécial (task_for_pid) : non vérifié, rien n'est conclu.",
            "On macOS, another process's memory cannot be read without a special right (task_for_pid): not verified, nothing is concluded."
        ));
    }
    let regles = match yara::regles() {
        Ok(r) => r,
        Err(e) => {
            println!(
                "  ✖ {}",
                trf!(
                    "Règles YARA impossibles à compiler : {e}",
                    "YARA rules could not be compiled: {e}"
                )
            );
            return;
        }
    };
    afficher(&parcourir(regles), regles);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sous Linux et macOS, le nom (comm, ps) est choisi par le programme : un maliciel qui s'appelle « lsass » ou
    /// « services » est lu comme les autres ; seul Vanguard, par son numéro, ne l'est pas.
    #[test]
    fn tri_sans_windows() {
        let moi = 4242;
        assert_eq!(trier(moi, "vanguard", moi, None), Tri::Exclu);
        assert_eq!(trier(moi, "lsass", moi, None), Tri::Exclu);
        for nom in [
            "lsass",
            "LSASS",
            "services",
            "csrss",
            "System",
            "Idle",
            "Secure System",
            "firefox",
        ] {
            assert_eq!(trier(700, nom, moi, None), Tri::Lire, "{nom}");
        }
        // 0 et 4 ne sont Idle et System que sous Windows (sous Linux, dans un conteneur, le 4 est un programme).
        assert_eq!(trier(0, "Idle", moi, None), Tri::Lire);
        assert_eq!(trier(4, "System", moi, None), Tri::Lire);
    }

    /// Sous Windows, un nom critique n'écarte que le programme de System32 qui le porte ; ailleurs, c'est un masquage,
    /// lu et signalé ; sans chemin lisible, seul le niveau de protection peut l'écarter.
    #[test]
    fn tri_sous_windows() {
        let moi = 4242;
        let lieux = |programme: &str| Lieux {
            system32: Some(r"C:\WINDOWS\system32".into()),
            programme: Some(programme.into()),
        };
        let rien = Lieux::default();
        assert_eq!(trier(moi, "vanguard", moi, Some(&rien)), Tri::Exclu);
        assert_eq!(trier(0, "Idle", moi, Some(&rien)), Tri::Exclu);
        assert_eq!(trier(4, "System", moi, Some(&rien)), Tri::Exclu);
        // À sa place, quelle que soit la casse : écarté.
        let vrai = lieux(r"C:\Windows\System32\lsass.exe");
        assert_eq!(trier(700, "lsass", moi, Some(&vrai)), Tri::Exclu);
        assert_eq!(trier(701, "LSASS", moi, Some(&vrai)), Tri::Exclu);
        let services = lieux(r"c:\windows\SYSTEM32\Services.EXE");
        assert_eq!(trier(702, "services", moi, Some(&services)), Tri::Exclu);
        // Le même nom ailleurs : lu et signalé (T1036.005).
        for ailleurs in [
            r"C:\Users\alice\AppData\Roaming\lsass.exe",
            r"C:\Windows\SysWOW64\lsass.exe",
            r"C:\Windows\System32\drivers\lsass.exe",
            r"C:\Windows\System32\..\Temp\lsass.exe",
            r"C:\WINDOW~1\System32\lsass.exe",
            r"C:\Windows\System32\lsass.exe:cache",
            r"D:\Windows\System32\lsass.exe",
        ] {
            assert_eq!(
                trier(703, "lsass", moi, Some(&lieux(ailleurs))),
                Tri::Masque,
                "{ailleurs}"
            );
        }
        // Le bon dossier, un autre programme : « services » n'est pas « svchost ».
        let autre = lieux(r"C:\Windows\System32\svchost.exe");
        assert_eq!(trier(704, "services", moi, Some(&autre)), Tri::Masque);
        // Un processus du noyau n'a pas de programme : son nom porté par un programme est un masquage.
        assert_eq!(
            trier(
                705,
                "Secure System",
                moi,
                Some(&lieux(r"C:\ProgramData\Secure System.exe"))
            ),
            Tri::Masque
        );
        // Chemin illisible, « chemin » sans fichier (processus minimal du noyau), System32 inconnu : incertain.
        let illisible = Lieux {
            system32: Some(r"C:\Windows\System32".into()),
            programme: None,
        };
        assert_eq!(trier(707, "lsass", moi, Some(&illisible)), Tri::Incertain);
        assert_eq!(trier(708, "Registry", moi, Some(&lieux("Registry"))), Tri::Incertain);
        let sans_system32 = Lieux {
            system32: None,
            programme: Some(r"C:\Windows\System32\lsass.exe".into()),
        };
        assert_eq!(trier(709, "lsass", moi, Some(&sans_system32)), Tri::Incertain);
        // Un nom ordinaire est lu, sans rien demander de plus.
        assert_eq!(trier(710, "firefox", moi, Some(&rien)), Tri::Lire);
        assert_eq!(trier(711, "services-web", moi, Some(&rien)), Tri::Lire);
    }

    #[test]
    fn programme_a_sa_place() {
        assert!(a_sa_place(
            "lsass",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32"
        ));
        assert!(a_sa_place(
            "lsass",
            r"C:\Windows\System32\lsass.exe",
            r"C:\Windows\System32\"
        ));
        assert!(!a_sa_place("lsass", r"C:\Windows\System32\lsass.exe", ""));
        assert!(!a_sa_place("lsass", r"\lsass.exe", ""));
        assert!(!a_sa_place("lsass", r"C:\Windows\System32\lsass.exe", r"C:\Windows"));
        assert!(!a_sa_place(
            "lsass",
            r"C:\Windows\System32\lsass",
            r"C:\Windows\System32"
        ));
        // Pas de pliage de casse hors ASCII : « ſ » (s long, « S » en majuscule) n'est pas « s ».
        assert!(!a_sa_place(
            "lsass",
            "C:\\Windows\\\u{17f}ystem32\\lsass.exe",
            r"C:\Windows\System32"
        ));
    }

    #[test]
    fn regions_de_windows() {
        const COMMIT: u32 = 0x1000;
        const PRIVEE: u32 = 0x2_0000;
        const MAPPEE: u32 = 0x4_0000;
        const IMAGE: u32 = 0x100_0000;
        // Tas en lecture-écriture, pile, et surtout une page RWX privée : un chargeur.
        assert!(region_windows(COMMIT, 0x04, PRIVEE));
        assert!(region_windows(COMMIT, 0x40, PRIVEE));
        // Mappée exécutable : lue ; mappée en lecture seule (fichier de données) : non.
        assert!(region_windows(COMMIT, 0x20, MAPPEE));
        assert!(!region_windows(COMMIT, 0x02, MAPPEE));
        // Une image mappée (DLL, programme) est le domaine du scan de fichiers, même exécutable.
        assert!(!region_windows(COMMIT, 0x20, IMAGE));
        // Réservée, libre, sans accès, page de garde (lire ferait une exception dans le programme lu) : non.
        assert!(!region_windows(0x2000, 0x04, PRIVEE));
        assert!(!region_windows(0x10000, 0x04, PRIVEE));
        assert!(!region_windows(COMMIT, 0x01, PRIVEE));
        assert!(!region_windows(COMMIT, 0x04 | 0x100, PRIVEE));
        assert!(!region_windows(COMMIT, 0, PRIVEE));
    }

    #[test]
    fn regions_de_linux() {
        let heap = region_linux("55d4c0a00000-55d4c0a21000 rw-p 00000000 00:00 0                          [heap]");
        assert_eq!(
            heap,
            Some(Region {
                debut: 0x55d4_c0a0_0000,
                taille: 0x21000
            })
        );
        assert!(region_linux("7f3a00000000-7f3a00021000 rw-p 00000000 00:00 0 ").is_some());
        assert!(
            region_linux("7f3a00000000-7f3a00021000 rwxp 00000000 00:00 0                          [stack]").is_some()
        );
        assert!(
            region_linux("7f3a00000000-7f3a00021000 rw-p 00000000 00:00 0                          [anon:scudo]")
                .is_some()
        );
        // Un programme effacé qui tourne encore, un memfd : exactement ce qu'on cherche.
        assert!(region_linux("5600000000-5600021000 r-xp 00000000 103:02 1234      /tmp/.x/agent (deleted)").is_some());
        assert!(region_linux("7f3a00000000-7f3a00021000 r-xp 00000000 00:05 77   /memfd:a (deleted)").is_some());
        // Un fichier mappé encore présent (scan de fichiers), le noyau, une région illisible : non.
        assert!(region_linux("7f3a00000000-7f3a00021000 r-xp 00000000 103:02 1234      /usr/lib/libc.so.6").is_none());
        assert!(
            region_linux("7fff00000000-7fff00002000 r-xp 00000000 00:00 0                          [vdso]").is_none()
        );
        assert!(
            region_linux("7fff00000000-7fff00002000 r--p 00000000 00:00 0                          [vvar]").is_none()
        );
        assert!(region_linux("7f3a00000000-7f3a00021000 ---p 00000000 00:00 0 ").is_none());
        assert!(region_linux("7f3a00021000-7f3a00000000 rw-p 00000000 00:00 0 ").is_none());
        assert!(region_linux("").is_none());
    }

    #[test]
    fn bornes() {
        let rien = Duration::ZERO;
        assert_eq!(decider(4096, 0, 0, rien), Decision::Lire);
        assert_eq!(decider(TAILLE_REGION_MAX as u64, 0, 0, rien), Decision::Lire);
        assert_eq!(decider(TAILLE_REGION_MAX as u64 + 1, 0, 0, rien), Decision::Sauter);
        assert_eq!(
            decider(4096, PAR_PROCESSUS_MAX - 4095, 0, rien),
            Decision::ProcessusPlein
        );
        assert_eq!(decider(4096, 0, TOTAL_MAX, rien), Decision::Arret);
        assert_eq!(decider(4096, 0, 0, DUREE_MAX), Decision::Arret);
        // Les bornes à l'œuvre : une région trop grosse sautée, puis la part du processus atteinte (le reste sauté
        // sans être lu) ; et un arrêt général, sans rien lire.
        let max = TAILLE_REGION_MAX as u64;
        let mut regions = vec![Region {
            debut: 0,
            taille: max + 1,
        }];
        regions.extend((0..9).map(|i| Region {
            debut: i * max,
            taille: max,
        }));
        let vides = regles("rule Rien { condition: false }");
        let mut tampon = Tampon::nouveau(TAILLE_REGION_MAX);
        let remplir = |_: &Region, z: &mut [u8]| z.len();
        let lecture = analyser_regions(&vides, &regions, &mut tampon.0, remplir, 0, Instant::now());
        assert_eq!(
            lecture,
            Lecture {
                trouves: vec![],
                octets: PAR_PROCESSUS_MAX,
                sautees: 2,
                partielles: 0,
                arret: false
            }
        );
        let lecture = analyser_regions(
            &vides,
            &regions,
            &mut tampon.0,
            |_, _| panic!(),
            TOTAL_MAX,
            Instant::now(),
        );
        assert!(lecture.arret && lecture.sautees == 10);
        // Une région illisible est sautée, dite ; une lue sans correspondance compte ses octets.
        let petites = [Region { debut: 0, taille: 8 }, Region { debut: 8, taille: 8 }];
        let mut tour = 0;
        let lecture = analyser_regions(
            &vides,
            &petites,
            &mut tampon.0,
            |_, z| {
                tour += 1;
                z.copy_from_slice(b"12345678");
                if tour > 1 { z.len() } else { 0 }
            },
            0,
            Instant::now(),
        );
        assert_eq!(
            lecture,
            Lecture {
                trouves: vec![],
                octets: 8,
                sautees: 1,
                partielles: 0,
                arret: false
            }
        );
    }

    fn regles(source: &str) -> Regles {
        let r = Regles::compiler(source);
        assert_eq!(r.refus(), [], "{source}");
        r
    }

    /// Le tampon garde sa taille : une région plus grande que lui est sautée, jamais lue dans un tampon agrandi ; ce
    /// qui est lu est analysé dans sa seule longueur lue ; et l'effacement le remet à zéro en entier.
    #[test]
    fn tampon_fixe_puis_efface() {
        let essai = regles(r#"rule Ancien { strings: $a = "ancien" condition: $a }"#);
        let mut tampon = Tampon::nouveau(100);
        let regions = [
            Region { debut: 0, taille: 64 },
            Region { debut: 64, taille: 16 },
            Region { debut: 80, taille: 101 },
        ];
        let mut tour = 0;
        let lecture = analyser_regions(
            &essai,
            &regions,
            &mut tampon.0,
            |_, z| {
                tour += 1;
                if tour == 1 {
                    // La première région laisse « ancien » dans le tampon, après ce que lira la seconde.
                    z.fill(b'x');
                    z[8..14].copy_from_slice(b"ancien");
                    z.len()
                } else {
                    z[..4].copy_from_slice(b"neuf");
                    4
                }
            },
            0,
            Instant::now(),
        );
        assert_eq!(tour, 2, "la région de 101 octets ne doit pas être lue");
        assert_eq!(lecture.octets, 68);
        assert_eq!(lecture.sautees, 1);
        // La seconde n'a rendu que 4 octets sur 16 : lue en partie, et le processus avec elle.
        assert_eq!(lecture.partielles, 1);
        assert!(lecture.incomplete());
        assert_eq!(lecture.trouves, [("Ancien".to_string(), regions[0])]);
        assert_eq!(tampon.0.len(), 100);
        effacer(&mut tampon.0);
        assert!(tampon.0.iter().all(|&o| o == 0));
        let mut impair = vec![0xA5u8; 64 * 3 + 7];
        effacer(&mut impair);
        assert!(impair.iter().all(|&o| o == 0));
    }

    #[test]
    fn verdicts() {
        let mut bilan = Bilan {
            lus: 3,
            ..Bilan::default()
        };
        assert_eq!(verdict(&bilan), Verdict::Sain);
        bilan.exclus = 5;
        assert_eq!(verdict(&bilan), Verdict::Sain);
        bilan.non_lus = 1;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.non_lus = 0;
        bilan.incomplets = 1;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.incomplets = 0;
        bilan.arrete = true;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.arrete = false;
        bilan.lus = 0;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        // Une règle refusée par le moteur n'a rien vérifié : pas de ✔.
        bilan.lus = 3;
        bilan.regles_refusees = 1;
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.regles_refusees = 0;
        bilan.lus = 0;
        // Un masquage seul suffit à l'alerte, même sans règle trouvée.
        bilan.masques.push(Masque {
            pid: 2,
            programme: "lsass".into(),
            chemin: r"C:\Users\alice\lsass.exe".into(),
        });
        assert_eq!(verdict(&bilan), Verdict::Trouve);
        bilan.masques.clear();
        bilan.trouves.push(Trouve {
            regle: "X".into(),
            pid: 1,
            programme: "a".into(),
            region: Region::default(),
        });
        assert_eq!(verdict(&bilan), Verdict::Trouve);
    }

    /// Le vrai services.exe (Wine en lance un aussi) est écarté par son programme de System32, chemins lus comme
    /// Windows les donne ; s'il ne se lit pas (sans droits d'administrateur), seul son niveau de protection décidera.
    #[cfg(windows)]
    #[test]
    fn le_vrai_services_est_a_sa_place() {
        let system32 = crate::machine::windows::memoire::system32().expect("System32 se lit");
        assert!(system32.to_ascii_lowercase().ends_with(r"\system32"), "{system32}");
        let moi = std::process::id();
        for p in crate::machine::windows::processus::liste() {
            if !p.nom.eq_ignore_ascii_case("services") {
                continue;
            }
            let lieux = plateforme::lieux(p.pid, &p.nom);
            let attendu = match lieux.programme.as_deref() {
                Some(chemin) if chemin.contains('\\') => Tri::Exclu,
                _ => Tri::Incertain,
            };
            assert_eq!(trier(p.pid, &p.nom, moi, Some(&lieux)), attendu, "{lieux:?}");
        }
    }

    /// La mémoire de CE processus de test, et de lui seul, lue comme celle d'un autre (/proc/self/mem ; sous Windows,
    /// OpenProcess sur son propre numéro, sans passer par le niveau de protection, que Wine ne dit pas) : la liste des
    /// régions contient celle d'une chaîne construite à l'exécution et posée sur le tas, et une règle d'essai la
    /// retrouve en la lisant. Seules les pages de la chaîne sont lues : quand toute la suite tourne, les autres tests,
    /// dans le même processus, libèrent de la mémoire entre la liste des régions et leur lecture ; la région de la
    /// marque perdait alors son début (lecture impossible, région sautée) ou un morceau avant elle (lecture arrêtée
    /// au trou), et la règle ne la trouvait plus. Les pages de la marque, elles, restent là tant qu'elle vit.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn sa_propre_memoire() {
        const PAGE: u64 = 4096;
        let marque = std::hint::black_box(["vanguard", "essai", "memoire", "7f3a9c"].join("-"));
        let (adresse, longueur) = (marque.as_ptr() as u64, marque.len() as u64);
        let essai = regles(&format!(
            r#"rule Essai_Memoire {{ strings: $a = "{marque}" condition: $a }}"#
        ));
        let moi = std::process::id();
        #[cfg(target_os = "linux")]
        let Acces::Ouvert(lecteur) = plateforme::ouvrir(moi) else {
            panic!("/proc/self/mem doit s'ouvrir");
        };
        #[cfg(windows)]
        let lecteur = plateforme::Lecteur::ouvrir(moi).expect("son propre processus doit s'ouvrir");
        let regions = lecteur.regions();
        let contenante = regions
            .iter()
            .find(|r| r.debut <= adresse && adresse + longueur <= r.debut + r.taille)
            .unwrap_or_else(|| panic!("aucune région ne contient la marque ({adresse:#x}) : {regions:x?}"));
        let debut = (adresse / PAGE * PAGE).max(contenante.debut);
        let fin = (adresse + longueur)
            .next_multiple_of(PAGE)
            .min(contenante.debut + contenante.taille);
        let pages = [Region {
            debut,
            taille: fin - debut,
        }];
        let mut tampon = Tampon::nouveau(usize::try_from(pages[0].taille).unwrap());
        let lecture = analyser_regions(
            &essai,
            &pages,
            &mut tampon.0,
            |r, z| lecteur.lire(r, z),
            0,
            Instant::now(),
        );
        assert_eq!(
            lecture,
            Lecture {
                trouves: vec![("Essai_Memoire".into(), pages[0])],
                octets: pages[0].taille,
                sautees: 0,
                partielles: 0,
                arret: false
            },
            "marque à {adresse:#x}"
        );
        // Ce processus est exclu du parcours général, sur tous les systèmes : Vanguard ne se lit pas lui-même.
        assert_eq!(trier(moi, "vanguard", moi, None), Tri::Exclu);
        assert_eq!(trier(moi, "vanguard", moi, Some(&Lieux::default())), Tri::Exclu);
        std::hint::black_box(&marque);
    }
}
