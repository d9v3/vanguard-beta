//! Scan YARA de la mémoire des processus en marche : les 308 règles de `yara` appliquées aux régions privées ou
//! exécutables de chaque programme, là où vit un logiciel malveillant « sans fichier » (chargeur réfléchi, shellcode,
//! programme effacé du disque mais encore en marche, exécutable déballé que son emballage cachait sur le disque), et
//! aux images chargées (programmes, bibliothèques) que leur fichier ne suffit plus à juger : fichier effacé ou sur un
//! système de fichiers en mémoire (tmpfs), pages de code modifiées en mémoire (une DLL réécrite après son
//! chargement). Une image ou une allocation se lit d'un seul tenant, ses régions recollées à leur place : les règles
//! voient son en-tête et son code ensemble (`Bloc`). Ce qui n'a pas pu être jugé est compté, jamais sain.
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
/// Les processus lus en partie nommés à l'écran ; les autres sont comptés.
const NOMS_MAX: usize = 5;

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

/// Des régions lues ensemble dans un seul tampon, chacune à sa place : les régions d'une même image ou d'une même
/// allocation. Lues une à une, l'en-tête (« MZ », ELF) et le code d'une image ne se voyaient jamais ensemble, et 286
/// des 308 règles exigent l'en-tête. Les trous entre elles se lisent comme des zéros.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Bloc {
    /// (région, position dans le tampon), par position croissante.
    pub morceaux: Vec<(Region, u64)>,
    /// La taille du tampon : jusqu'à la fin du morceau qui finit le plus loin.
    pub taille: u64,
    /// Disposition chargée (Windows : positions comptées depuis la base de l'allocation) : pe.entry_point y est une
    /// RVA, comme pour libyara en mémoire, et aussi une position de fichier quand le bloc commence par « MZ » (un PE
    /// gardé tel que sur le disque). Sinon (Linux : positions dans le fichier), une position de fichier.
    pub chargee: bool,
}

impl Bloc {
    pub(crate) fn seule(region: Region, chargee: bool) -> Bloc {
        Bloc {
            morceaux: vec![(region, 0)],
            taille: region.taille,
            chargee,
        }
    }

    /// Les octets à lire : la somme des morceaux, sans les trous.
    fn a_lire(&self) -> u64 {
        self.morceaux.iter().map(|(r, _)| r.taille).sum()
    }

    /// La place à montrer : l'adresse du premier morceau, sur la taille du tampon.
    fn region(&self) -> Region {
        Region {
            debut: self.morceaux.first().map_or(0, |(r, _)| r.debut),
            taille: self.taille,
        }
    }
}

/// Les morceaux d'une même image ou allocation, (région, position), en un bloc s'il tient dans le tampon et n'est pas
/// fait surtout de trous (une réservation de tas de 60 Mio dont 1 Mio est validé ne se lit pas comme 60 Mio de
/// zéros) ; sinon chacun seul, comme avant.
pub(crate) fn regrouper(mut morceaux: Vec<(Region, u64)>, chargee: bool) -> Vec<Bloc> {
    morceaux.sort_by_key(|&(_, position)| position);
    let fin = morceaux
        .iter()
        .map(|(r, p)| p.saturating_add(r.taille))
        .max()
        .unwrap_or(0);
    let somme: u64 = morceaux.iter().map(|(r, _)| r.taille).sum();
    if morceaux.len() > 1 && fin <= TAILLE_REGION_MAX as u64 && fin <= somme.saturating_mul(4) + (1 << 20) {
        return vec![Bloc {
            morceaux,
            taille: fin,
            chargee,
        }];
    }
    morceaux.into_iter().map(|(r, _)| Bloc::seule(r, chargee)).collect()
}

/// Les morceaux d'une image à lire avec son en-tête : recollés à leurs positions (`regrouper`) ; sinon (des trous
/// démesurés, comme un code mappé loin de l'en-tête dans le fichier, ou une image plus grande que le tampon), tassés
/// bout à bout s'ils tiennent dans le tampon, et l'image est dite morcelée (le booléen rendu). Les règles y voient
/// encore l'en-tête avec le code, mais les positions ne sont plus celles de l'image : une règle qui vise le point
/// d'entrée peut s'y tromper, et rien n'est conclu (`Releve::images_morcelees`, pas de ✔). Lues chacune à part, comme
/// `regrouper` le ferait, l'en-tête et le code ne se verraient plus jamais ensemble, et sans que rien ne le dise.
pub(crate) fn recoller_image(morceaux: Vec<(Region, u64)>, chargee: bool) -> (Vec<Bloc>, bool) {
    let blocs = regrouper(morceaux, chargee);
    if blocs.len() <= 1 {
        return (blocs, false);
    }
    let somme: u64 = blocs.iter().map(Bloc::a_lire).sum();
    if somme > TAILLE_REGION_MAX as u64 {
        return (blocs, true);
    }
    // `regrouper` rend les morceaux seuls par position croissante : l'en-tête, à la position 0, reste en tête.
    let mut position = 0u64;
    let morceaux = blocs
        .into_iter()
        .flat_map(|b| b.morceaux)
        .map(|(r, _)| {
            let p = position;
            position += r.taille;
            (r, p)
        })
        .collect();
    (
        vec![Bloc {
            morceaux,
            taille: somme,
            chargee,
        }],
        true,
    )
}

/// Une image chargée hors des dossiers du système, intacte (son fichier est là, rien n'y a changé en mémoire) : aucun
/// scan de fichiers ne la couvre forcément (un programme lancé de ~/.cache ou de /var/tmp), elle se lit donc en
/// mémoire, une seule fois pour tous les processus qui la chargent (même fichier, mêmes pages) : `cle` la nomme
/// (Linux : périphérique, inode, chemin, dates de modification et de changement ; Windows : volume, identifiant du
/// fichier, date d'écriture), `None` quand le fichier ne se confirme pas : elle se lit alors dans chaque processus.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ImageHorsSysteme {
    pub cle: Option<String>,
    pub blocs: Vec<Bloc>,
    pub morcelee: bool,
    /// Linux, un fichier mappé sans aucune région exécutable : une donnée (un journal, une archive lue par mmap)
    /// tant que le début de cette région (le mappage du début du fichier) n'est pas un en-tête ELF ou PE ; elle n'est
    /// alors ni lue ni dite morcelée. `None` : une image de code.
    pub entete_a_verifier: Option<Region>,
}

/// Un en-tête d'exécutable : ELF ou PE (« MZ »).
fn entete_de_code(octets: &[u8]) -> bool {
    octets.starts_with(b"\x7fELF") || octets.starts_with(b"MZ")
}

/// Ce que le relevé des régions d'un processus a retenu : les blocs à lire, et les images chargées qui n'ont pas pu
/// être jugées (fichier ou pages modifiées illisibles) : ni lues ni écartées, elles empêchent le ✔.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Releve {
    pub blocs: Vec<Bloc>,
    pub images_non_verifiees: usize,
    /// Les images du système non lues : leur fichier est dans un dossier du système (que seul l'administrateur
    /// change), et rien n'y a changé en mémoire.
    pub images_laissees: usize,
    /// Les images lues tassées, pas à leurs positions (`recoller_image`) : rien n'est conclu pour elles.
    pub images_morcelees: usize,
    /// Les images intactes hors des dossiers du système, à lire si aucun autre processus ne l'a déjà fait.
    pub hors_systeme: Vec<ImageHorsSysteme>,
}

impl Releve {
    /// Ajoute aux blocs à lire les images hors du système que `vues` n'a pas encore, en comptant les morcelées ; une
    /// donnée mappée (`entete_a_verifier`, dont `est_du_code` ne voit pas l'en-tête) est laissée. Rend les clés
    /// prises : `vues` ne les reçoit qu'une fois le processus lu en entier (`lire_processus`), sans quoi un processus
    /// leurre qui mappe la même image et atteint sa borne la ferait passer pour lue dans tous les autres.
    fn prendre_hors_systeme(
        &mut self,
        vues: &std::collections::HashSet<String>,
        mut est_du_code: impl FnMut(&Region) -> bool,
    ) -> Vec<String> {
        let mut prises = Vec::new();
        for image in std::mem::take(&mut self.hors_systeme) {
            if image
                .cle
                .as_ref()
                .is_some_and(|c| vues.contains(c) || prises.contains(c))
            {
                continue;
            }
            if image.entete_a_verifier.is_some_and(|r| !est_du_code(&r)) {
                continue;
            }
            self.blocs.extend(image.blocs);
            self.images_morcelees += usize::from(image.morcelee);
            prises.extend(image.cle);
        }
        prises
    }
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
/// VirtualAlloc, là où un chargeur pose son code) ou mappée exécutable. Une image (MEM_IMAGE) se juge à part
/// (`image_windows`).
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn region_windows(etat: u32, protection: u32, sorte: u32) -> bool {
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;
    const EXECUTABLES: u32 = 0xF0;
    lisible_windows(etat, protection)
        && (sorte == MEM_PRIVATE || (sorte == MEM_MAPPED && protection & EXECUTABLES != 0))
}

/// Validée et lisible sans exception dans le programme lu.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn lisible_windows(etat: u32, protection: u32) -> bool {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;
    let acces = protection & 0xFF;
    etat == MEM_COMMIT && acces != 0 && acces != PAGE_NOACCESS && protection & PAGE_GUARD == 0
}

/// Une image chargée de Windows (MEM_IMAGE) : `Some(true)` à lire en entier, `Some(false)` intacte (laissée si son
/// fichier est dans un dossier du système, `image_du_systeme_windows`, lue une fois sinon), `None` non vérifiée. `fichier_present` : son fichier est là ET son en-tête est celui de l'image (`Some
/// (false)` : absent, ou un autre en-tête). Écartée seulement si c'est le cas et qu'aucune de ses pages de code n'est
/// privée : la réécriture d'une DLL chargée (pages copiées à l'écriture, devenues privées), une image d'un fichier
/// effacé, ou d'un fichier réécrit depuis, vivent en MEM_IMAGE, sur un fichier sain ou absent, que ni le scan de
/// fichiers ni celui des régions privées ne voyaient. Une page de code en lecture-écriture-exécution
/// (PAGE_EXECUTE_READWRITE) n'est pas celle d'une image intacte : lue aussi.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn image_windows(fichier_present: Option<bool>, pages_privees: Option<bool>, rwx: bool) -> Option<bool> {
    if fichier_present == Some(false) || pages_privees == Some(true) || rwx {
        return Some(true);
    }
    (fichier_present == Some(true) && pages_privees == Some(false)).then_some(false)
}

/// Le chemin ouvrable d'une image (« \\?\GLOBALROOT\Device\HarddiskVolume3\… » ou « \\?\C:\… ») est-il dans un
/// dossier du système de Windows, que seul l'administrateur change ? `racines` : le volume du système sous ses deux
/// formes (« \\?\GLOBALROOT\Device\HarddiskVolume3 », « \\?\C: »), `windows` : le dossier de Windows sur ce volume
/// (« \Windows »), d'après GetSystemDirectoryW. Retenus : System32, SysWOW64, WinSxS, Microsoft.NET, SystemApps et les
/// deux Program Files ; écartés : les sous-dossiers que tout compte peut écrire (Tasks, spool\drivers\color,
/// com\dmp, Tracing…), un « .. », et un « : » (flux de données secondaire). Ce qui n'est pas retenu se lit.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn image_du_systeme_windows(chemin: &str, racines: &[String], windows: &str) -> bool {
    const SOUS_WINDOWS: &[&str] = &[
        "system32\\",
        "syswow64\\",
        "winsxs\\",
        "microsoft.net\\",
        "systemapps\\",
    ];
    const PROGRAMMES: &[&str] = &["\\program files\\", "\\program files (x86)\\"];
    const INSCRIPTIBLES: &[&str] = &[
        "tasks\\",
        "tasks_migrated\\",
        "spool\\drivers\\color\\",
        "spool\\printers\\",
        "spool\\servers\\",
        "com\\dmp\\",
        "fxstmp\\",
        "microsoft\\crypto\\rsa\\machinekeys\\",
        "catroot2\\",
        "tracing\\",
        "temp\\",
        "debug\\",
        "logfiles\\",
    ];
    let bas = chemin.to_lowercase();
    let Some(reste) = racines.iter().find_map(|r| bas.strip_prefix(r.to_lowercase().as_str())) else {
        return false;
    };
    if reste.contains([':', '/']) || reste.split('\\').any(|p| p == ".." || p == ".") {
        return false;
    }
    if PROGRAMMES.iter().any(|p| reste.starts_with(p)) {
        return true;
    }
    let windows = format!("{}\\", windows.to_lowercase().trim_end_matches('\\'));
    reste.strip_prefix(windows.as_str()).is_some_and(|dans| {
        SOUS_WINDOWS.iter().any(|d| {
            dans.strip_prefix(d)
                .is_some_and(|sous| !INSCRIPTIBLES.iter().any(|i| sous.starts_with(i)))
        })
    })
}

/// Les en-têtes PE de la première page d'une image en mémoire et du début de son fichier disent-ils la même chose ?
/// Comparés : la date de liaison et le nombre de sections (COFF), le point d'entrée, la taille de l'image et la somme
/// de contrôle (en-tête facultatif), et la table des sections ; pas l'adresse de base, que le chargeur réécrit en
/// mémoire quand il déplace l'image. `None` : l'un des deux n'est pas un PE lisible.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn entetes_pe_concordent(memoire: &[u8], fichier: &[u8]) -> Option<bool> {
    fn champs(o: &[u8]) -> Option<Vec<&[u8]>> {
        if o.get(..2)? != b"MZ" {
            return None;
        }
        let pe = usize::try_from(u32::from_le_bytes(o.get(0x3C..0x40)?.try_into().ok()?)).ok()?;
        if o.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let sections = usize::from(u16::from_le_bytes(o.get(pe + 6..pe + 8)?.try_into().ok()?));
        let facultatif = usize::from(u16::from_le_bytes(o.get(pe + 20..pe + 22)?.try_into().ok()?));
        let opt = pe + 24;
        let table = opt.checked_add(facultatif)?;
        Some(vec![
            o.get(pe + 6..pe + 12)?,
            o.get(opt + 16..opt + 20)?,
            o.get(opt + 56..opt + 60)?,
            o.get(opt + 64..opt + 68)?,
            o.get(table..table.checked_add(sections.checked_mul(40)?)?)?,
        ])
    }
    Some(champs(memoire)? == champs(fichier)?)
}

/// Une entrée de `/proc/<pid>/smaps` : l'en-tête (celui de maps) et le champ « Anonymous » (pages privées, copiées à
/// l'écriture ou jamais adossées à un fichier).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq)]
struct Mappage {
    region: Region,
    lisible: bool,
    executable: bool,
    decalage: u64,
    peripherique: (u32, u32),
    inode: u64,
    chemin: String,
    anonyme_ko: u64,
}

/// L'en-tête d'une entrée de smaps (« debut-fin droits décalage majeur:mineur inode chemin »), nombres en hexadécimal
/// sauf l'inode ; `None` pour une ligne de champ (« Rss: 4 kB »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn entete_linux(ligne: &str) -> Option<Mappage> {
    let mut champs = ligne.splitn(6, ' ');
    let (adresses, droits, decalage, peripherique, inode) = (
        champs.next()?,
        champs.next()?,
        champs.next()?,
        champs.next()?,
        champs.next()?,
    );
    let chemin = champs.next().map(str::trim).unwrap_or_default().to_string();
    let (debut, fin) = adresses.split_once('-')?;
    let (debut, fin) = (u64::from_str_radix(debut, 16).ok()?, u64::from_str_radix(fin, 16).ok()?);
    let (majeur, mineur) = peripherique.split_once(':')?;
    let &[lis, _, exec, _] = droits.as_bytes() else {
        return None;
    };
    if fin <= debut {
        return None;
    }
    Some(Mappage {
        region: Region {
            debut,
            taille: fin - debut,
        },
        lisible: lis == b'r',
        executable: exec == b'x',
        decalage: u64::from_str_radix(decalage, 16).ok()?,
        peripherique: (
            u32::from_str_radix(majeur, 16).ok()?,
            u32::from_str_radix(mineur, 16).ok()?,
        ),
        inode: inode.parse().ok()?,
        chemin,
        anonyme_ko: 0,
    })
}

/// Les systèmes de fichiers de `/proc/<pid>/mountinfo` dont le contenu ne vient pas d'un disque local, par numéro de
/// périphérique : en mémoire (tmpfs, ramfs : le scan de fichiers ne couvre ni /dev/shm, ni /tmp, ni /run/user), servis
/// par un programme (FUSE, qu'un compte monte lui-même et qui peut rendre un contenu au chargeur et un autre à une
/// lecture ultérieure) ou par le réseau. Une image qui y est mappée se lit en mémoire.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn en_memoire_linux(mountinfo: &str) -> Vec<(u32, u32)> {
    mountinfo
        .lines()
        .filter_map(|ligne| {
            let (avant, apres) = ligne.split_once(" - ")?;
            let genre = apres.split(' ').next()?;
            let ailleurs = matches!(genre, "tmpfs" | "ramfs" | "9p" | "cifs" | "smb3" | "nfs" | "nfs4")
                || genre == "fuse"
                || genre.starts_with("fuse.")
                || genre == "fuseblk";
            if !ailleurs {
                return None;
            }
            let (majeur, mineur) = avant.split(' ').nth(2)?.split_once(':')?;
            Some((majeur.parse().ok()?, mineur.parse().ok()?))
        })
        .collect()
}

/// Les blocs à lire d'après `/proc/<pid>/smaps`. Retenus : les régions anonymes (tas, piles, mmap sans fichier) ; une
/// région de fichier dont des pages sont privées (« Anonymous » non nul : modifiée en mémoire, même si le fichier
/// sur le disque est sain) ; et, lues en entier, recollées à leur position dans le fichier, les images d'un fichier
/// effacé (« (deleted) », memfd), posé sur un système de fichiers en mémoire (`en_memoire`), ou dont une région
/// exécutable a des pages privées (code réécrit). Vdso, vvar et vsyscall sont au noyau. `en_memoire` : `None` si
/// mountinfo ne s'est pas lu, et une image de fichier qui n'est pas retenue pour une autre raison est alors non
/// vérifiée, jamais écartée. Une image intacte d'un disque n'est laissée que si `disque` (chemin, inode) la dit
/// dans un dossier du système (`fichier_linux`) ; ailleurs, elle se lit (`ImageHorsSysteme`) si elle a du code : une
/// région exécutable, ou un en-tête ELF ou PE au début du fichier ; un fichier de données mappé (un journal) ne se
/// lit pas et n'est jamais dit morcelé.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn releve_linux(
    smaps: &str,
    en_memoire: Option<&[(u32, u32)]>,
    disque: fn(&str, u64) -> SurLeDisque,
) -> Releve {
    let mut mappages: Vec<Mappage> = Vec::new();
    for ligne in smaps.lines() {
        if let Some(m) = entete_linux(ligne) {
            mappages.push(m);
        } else if let (Some(m), Some(valeur)) = (mappages.last_mut(), ligne.strip_prefix("Anonymous:")) {
            m.anonyme_ko = valeur.trim().trim_end_matches("kB").trim().parse().unwrap_or(0);
        }
    }
    let mut releve = Releve::default();
    // Les mappages d'un même fichier sont rassemblés où qu'ils soient dans la liste : d'autres régions entre l'en-tête
    // et le code d'une image ne la coupent pas en deux.
    let mut images: Vec<Vec<Mappage>> = Vec::new();
    let mut rang: std::collections::HashMap<((u32, u32), u64, String), usize> = std::collections::HashMap::new();
    for m in mappages {
        // Une région ni lisible ni exécutable (garde, réservation) n'a rien à lire. Une région exécutable sans droit
        // de lecture se lit quand même par /proc/<pid>/mem : elle est gardée.
        if !m.lisible && !m.executable {
            continue;
        }
        let anonyme = m.chemin.is_empty()
            || m.chemin == "[heap]"
            || m.chemin.starts_with("[stack")
            || m.chemin.starts_with("[anon");
        if anonyme {
            releve.blocs.push(Bloc::seule(m.region, false));
            continue;
        }
        if m.chemin.starts_with('[') {
            continue;
        }
        let cle = (m.peripherique, m.inode, m.chemin.clone());
        let k = *rang.entry(cle).or_insert_with(|| {
            images.push(Vec::new());
            images.len() - 1
        });
        #[expect(
            clippy::indexing_slicing,
            reason = "k vient de `rang`, qui ne garde que des indices de `images` au moment où il les pousse ; `images` ne fait que grandir"
        )]
        images[k].push(m);
    }
    for groupe in images {
        // Un groupe naît avec sa première région : jamais vide, et un groupe vide n'aurait rien à analyser.
        let Some(premier) = groupe.first() else {
            continue;
        };
        let efface = premier.chemin.ends_with(" (deleted)") || premier.chemin.starts_with("/memfd:");
        let hors_disque = en_memoire.map(|e| e.contains(&premier.peripherique));
        let reecrit = groupe.iter().any(|m| m.executable && m.anonyme_ko > 0);
        let morceaux = || groupe.iter().map(|m| (m.region, m.decalage)).collect();
        if efface || reecrit || hors_disque == Some(true) {
            let (blocs, morcelee) = recoller_image(morceaux(), false);
            releve.blocs.extend(blocs);
            releve.images_morcelees += usize::from(morcelee);
            continue;
        }
        releve.blocs.extend(
            groupe
                .iter()
                .filter(|m| m.anonyme_ko > 0)
                .map(|m| Bloc::seule(m.region, false)),
        );
        if hors_disque.is_none() {
            releve.images_non_verifiees += 1;
            continue;
        }
        let fichier = disque(&premier.chemin, premier.inode);
        if fichier.du_systeme {
            releve.images_laissees += 1;
            continue;
        }
        // Sans région exécutable : une donnée mappée, sauf si le début du fichier (mappé) est un en-tête ELF ou PE ;
        // sans le début du fichier, rien n'en fait une image. Laissée sans être comptée, comme le début mappé sans
        // droit de lecture (PROT_NONE, `est_du_code` ne le lit pas) : rien ne s'exécute d'une page sans « x », et le
        // jour où le processus la rend exécutable, le relevé suivant la lit comme une image.
        let entete_a_verifier = if groupe.iter().any(|m| m.executable) {
            None
        } else if let Some(m) = groupe.iter().find(|m| m.decalage == 0) {
            Some(m.region)
        } else {
            continue;
        };
        let (blocs, morcelee) = recoller_image(morceaux(), false);
        releve.hors_systeme.push(ImageHorsSysteme {
            cle: fichier.dates.map(|(modification, changement)| {
                format!(
                    "{}:{}:{}:{modification}:{changement}:{}",
                    premier.peripherique.0, premier.peripherique.1, premier.inode, premier.chemin
                )
            }),
            blocs,
            morcelee,
            entete_a_verifier,
        });
    }
    releve
}

/// Un chemin dans un dossier du système, que seul root change : /usr (et /bin, /lib… qui y mènent souvent), le
/// magasin de Nix, les applications Flatpak et Snap installées pour tout le système. Pas /opt (des installateurs y
/// donnent souvent la main à un compte), ni /tmp, /var/tmp, /home. Un « .. » n'y entre pas.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn image_du_systeme_linux(chemin: &str) -> bool {
    const DOSSIERS: &[&str] = &[
        "/usr/",
        "/lib/",
        "/lib32/",
        "/lib64/",
        "/libx32/",
        "/bin/",
        "/sbin/",
        "/nix/store/",
        "/var/lib/flatpak/",
        "/snap/",
    ];
    DOSSIERS.iter().any(|d| chemin.starts_with(d)) && !chemin.split('/').any(|p| p == ".." || p == ".")
}

/// Ce que le disque dit du fichier d'une image (`fichier_linux`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct SurLeDisque {
    /// Un fichier d'un dossier du système (`image_du_systeme_linux`), confirmé par son inode.
    pub du_systeme: bool,
    /// Ses dates de modification et de changement (en nanosecondes), quand le chemin mène bien au fichier mappé :
    /// elles entrent dans la clé d'une image hors du système, qu'un fichier réécrit sur place ne reprenne pas.
    pub dates: Option<(i128, i128)>,
}

/// L'image (chemin et inode, d'après smaps) : son chemin, vu d'ici, mène-t-il bien à ce fichier, et dans un dossier
/// du système ? Un processus dans son propre espace de noms peut monter un fichier de son compte sur /usr/lib/… : son
/// chemin y ment, mais l'inode ne concorde pas avec le vrai. Le numéro de périphérique ne se compare pas : sur btrfs,
/// smaps donne celui du système de fichiers, stat celui du sous-volume. « /run/host/… » est la racine de l'hôte que
/// le bac à sable de Steam (pressure-vessel) montre à ses jeux : « /run/host/usr/lib/x » est « /usr/lib/x » d'ici,
/// s'il en a l'inode.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn fichier_linux(chemin: &str, inode: u64) -> SurLeDisque {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let confirme = |c: &str| {
            std::fs::metadata(c)
                .ok()
                .filter(|m| m.is_file() && m.ino() == inode)
                .map(|m| {
                    let ns = |s: i64, n: i64| i128::from(s) * 1_000_000_000 + i128::from(n);
                    (ns(m.mtime(), m.mtime_nsec()), ns(m.ctime(), m.ctime_nsec()))
                })
        };
        if let Some(dates) = confirme(chemin) {
            return SurLeDisque {
                du_systeme: image_du_systeme_linux(chemin),
                dates: Some(dates),
            };
        }
        let hote = chemin.strip_prefix("/run/host").filter(|c| image_du_systeme_linux(c));
        SurLeDisque {
            du_systeme: hote.is_some_and(|c| confirme(c).is_some()),
            dates: None,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (chemin, inode);
        SurLeDisque::default()
    }
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

/// `taille` : celle du tampon (régions et trous) ; `a_lire` : les octets à lire, comptés dans les bornes de lecture.
fn decider(taille: u64, a_lire: u64, lu_processus: u64, lu_total: u64, ecoule: Duration) -> Decision {
    if ecoule >= DUREE_MAX || lu_total >= TOTAL_MAX {
        Decision::Arret
    } else if taille > TAILLE_REGION_MAX as u64 {
        Decision::Sauter
    } else if lu_processus + a_lire > PAR_PROCESSUS_MAX {
        Decision::ProcessusPlein
    } else {
        Decision::Lire
    }
}

/// Ce qu'a donné la lecture d'un processus : les règles trouvées avec leur région, les octets lus, les régions
/// sautées ou illisibles (dont celles trop grosses pour le tampon), celles lues seulement jusqu'à un trou (une partie
/// libérée entre la liste des régions et leur lecture : le reste n'est pas lu), et si une borne générale a tout
/// arrêté.
#[derive(Debug, Default, PartialEq)]
struct Lecture {
    trouves: Vec<(String, Region)>,
    octets: u64,
    sautees: usize,
    trop_grosses: usize,
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
        crate::socle::effacer(&mut self.0);
    }
}

/// Lit les blocs par `lire`, région par région, chacune à sa place dans le début de `tampon` (jamais agrandi : un
/// bloc plus grand est sauté), et leur applique les règles, dans les bornes, chaque bloc comme un fichier à part (une
/// chaîne à cheval sur deux blocs n'est pas vue, comme avec YARA-X). `lire` rend le nombre d'octets lus (0 : rien).
/// `lu_total` et `debut` : ce qui a déjà été lu dans les processus d'avant, et le départ de l'analyse. Un bloc que le
/// moteur n'a pas pu finir (délai, ou panique sur un contenu piégé) est compté sauté : jamais lu en entier pour rien.
fn analyser_regions(
    regles: &Regles,
    blocs: &[Bloc],
    tampon: &mut [u8],
    mut lire: impl FnMut(&Region, &mut [u8]) -> usize,
    lu_total: u64,
    debut: Instant,
) -> Lecture {
    let mut lecture = Lecture::default();
    for (i, bloc) in blocs.iter().enumerate() {
        match decider(
            bloc.taille,
            bloc.a_lire(),
            lecture.octets,
            lu_total + lecture.octets,
            debut.elapsed(),
        ) {
            Decision::Arret => {
                lecture.arret = true;
                lecture.sautees += blocs.len() - i;
                break;
            }
            Decision::ProcessusPlein => {
                lecture.sautees += blocs.len() - i;
                break;
            }
            Decision::Sauter => {
                lecture.sautees += 1;
                lecture.trop_grosses += 1;
            }
            Decision::Lire => {
                let Some(zone) = usize::try_from(bloc.taille).ok().and_then(|t| tampon.get_mut(..t)) else {
                    lecture.sautees += 1;
                    continue;
                };
                let recolle = bloc.morceaux.len() > 1;
                // Les trous d'un bloc recollé se lisent comme des zéros, jamais comme le reste d'une région d'avant.
                if recolle {
                    zone.fill(0);
                }
                let (mut lus, mut entier, mut fin) = (0usize, true, 0usize);
                for (region, position) in &bloc.morceaux {
                    let place = usize::try_from(*position)
                        .ok()
                        .zip(usize::try_from(region.taille).ok())
                        .and_then(|(p, t)| Some(p..p.checked_add(t)?));
                    let Some(dest) = place.clone().and_then(|p| zone.get_mut(p)) else {
                        entier = false;
                        continue;
                    };
                    let n = lire(region, dest).min(dest.len());
                    if n < dest.len() {
                        entier = false;
                        if recolle {
                            dest.iter_mut().skip(n).for_each(|o| *o = 0);
                        }
                    }
                    lus += n;
                    fin = fin.max(place.map_or(0, |p| p.start + n));
                }
                if lus == 0 {
                    lecture.sautees += 1;
                    continue;
                }
                if !entier {
                    lecture.partielles += 1;
                }
                lecture.octets += lus as u64;
                let echeance = Instant::now() + DELAI_PAR_REGION;
                // `fin` ne dépasse pas la fin d'une place prise dans `zone` ; sinon le bloc serait compté sauté.
                let Some(zone) = (if recolle { Some(&*zone) } else { zone.get(..fin) }) else {
                    lecture.sautees += 1;
                    continue;
                };
                match crate::journal::rattraper(std::panic::AssertUnwindSafe(|| {
                    let tel_quel = regles.analyser_tampon(zone, Some(echeance))?;
                    // Une allocation qui commence par « MZ » peut garder un PE chargé (sections à leur RVA) ou tel
                    // que sur le disque (un tampon de téléchargeur) : les deux lectures de pe.entry_point sont faites.
                    if !(bloc.chargee && zone.starts_with(b"MZ")) {
                        return Ok::<_, crate::protection::motifs::Echec>(tel_quel);
                    }
                    let mut toutes = regles.analyser_image(zone, Some(echeance))?;
                    toutes.extend(tel_quel.into_iter().filter(|k| !toutes.contains(k)).collect::<Vec<_>>());
                    toutes.sort_unstable();
                    Ok(toutes)
                })) {
                    Ok(Ok(trouvees)) => lecture
                        .trouves
                        .extend(trouvees.into_iter().map(|k| (regles.nom(k).to_string(), bloc.region()))),
                    _ => lecture.sautees += 1,
                }
            }
        }
    }
    lecture
}

/// Les blocs d'un processus lus (`analyser_regions`), avec les images hors du système que `vues` n'a pas encore
/// (`Releve::prendre_hors_systeme`, leur en-tête lu par `lire` quand il faut le voir) ; leurs clés n'entrent dans
/// `vues` que si tout a été lu. `depuis` : ce qui a déjà été lu, et le départ de l'analyse.
fn lire_processus(
    regles: &Regles,
    releve: &mut Releve,
    vues: &mut std::collections::HashSet<String>,
    tampon: &mut [u8],
    mut lire: impl FnMut(&Region, &mut [u8]) -> usize,
    (lu_total, debut): (u64, Instant),
) -> Lecture {
    let prises = releve.prendre_hors_systeme(vues, |r| {
        let mut entete = [0u8; 4];
        let debut = Region {
            debut: r.debut,
            taille: 4,
        };
        lire(&debut, &mut entete) == entete.len() && entete_de_code(&entete)
    });
    let lecture = analyser_regions(regles, &releve.blocs, tampon, &mut lire, lu_total, debut);
    if !lecture.incomplete() && !lecture.arret {
        vues.extend(prises);
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

    use super::{Acces, Processus, Region, Releve, en_memoire_linux, fichier_linux, releve_linux};

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

    /// Un fichier de /proc lu au plus (smaps d'un navigateur : quelques Mio).
    const PROC_MAX: u64 = 256 << 20;

    /// Un fichier de /proc, en entier ou pas du tout : coupé à la borne, la liste des régions serait partielle et le
    /// processus compté lu ; plus grand, il n'est pas lu (le processus compte alors parmi les non lus).
    fn lire_proc(chemin: &str) -> Option<String> {
        use std::io::Read;
        let mut texte = String::new();
        File::open(chemin)
            .ok()?
            .take(PROC_MAX + 1)
            .read_to_string(&mut texte)
            .ok()?;
        (texte.len() as u64 <= PROC_MAX).then_some(texte)
    }

    /// `/proc/<pid>/smaps` pour les régions (et leurs pages privées), mountinfo pour les systèmes de fichiers en
    /// mémoire, `/proc/<pid>/mem` pour les lire : le noyau refuse l'ouverture de `mem` et de `smaps` sans le droit de
    /// tracer le processus (autre compte, ou Yama ptrace_scope ≥ 1 hors de ses descendants).
    pub(super) fn ouvrir(pid: u32) -> Acces {
        let Some(cartes) = lire_proc(&format!("/proc/{pid}/smaps")) else {
            return Acces::Refuse;
        };
        let en_memoire = lire_proc(&format!("/proc/{pid}/mountinfo")).map(|m| en_memoire_linux(&m));
        match File::open(format!("/proc/{pid}/mem")) {
            Ok(fichier) => Acces::Ouvert(Lecteur {
                fichier,
                releve: releve_linux(&cartes, en_memoire.as_deref(), fichier_linux),
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
        releve: Releve,
    }

    impl Lecteur {
        pub(super) fn regions(&self) -> Releve {
            self.releve.clone()
        }

        /// Lit le début d'une région dans `zone` (de sa taille) et rend le nombre d'octets lus : 0 si rien n'a pu
        /// l'être (région disparue entre-temps). Une lecture partielle est gardée telle quelle : ce qui est lu est
        /// analysé.
        pub(super) fn lire(&self, region: &Region, zone: &mut [u8]) -> usize {
            let mut fait = 0usize;
            while let Some(reste) = zone.get_mut(fait..).filter(|r| !r.is_empty()) {
                match self.fichier.read_at(reste, region.debut + fait as u64) {
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
        pub(super) fn regions(&self) -> super::Releve {
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

/// Le bilan de l'analyse : combien de processus lus, non lus (droits), exclus par choix, lus en partie (et lesquels),
/// les régions trop grosses, les images non jugées, morcelées ou du système non lues, si une borne a tout arrêté, les
/// règles que le moteur a refusées (non vérifiées), les correspondances et les masquages.
#[derive(Debug, Default, PartialEq)]
struct Bilan {
    regles_refusees: usize,
    lus: usize,
    non_lus: usize,
    exclus: usize,
    incomplets: usize,
    /// Les processus lus en partie (ou dont une image n'a pas été jugée), nommés : les premiers seulement.
    noms_incomplets: Vec<String>,
    /// Les régions plus grosses que le tampon, jamais lues.
    trop_grosses: usize,
    /// Les images chargées qui n'ont pas pu être jugées (`Releve`).
    images_non_verifiees: usize,
    /// Les images du système non lues (`Releve`).
    images_laissees: usize,
    /// Les images lues tassées, pas à leurs positions (`Releve`).
    images_morcelees: usize,
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
    } else if bilan.lus == 0
        || bilan.non_lus > 0
        || bilan.incomplets > 0
        || bilan.images_non_verifiees > 0
        || bilan.images_morcelees > 0
        || bilan.arrete
        || bilan.regles_refusees > 0
    {
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
    let mut vues = std::collections::HashSet::new();
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
                let mut releve = lecteur.regions();
                let lecture = lire_processus(
                    regles,
                    &mut releve,
                    &mut vues,
                    &mut tampon.0,
                    |r, z| lecteur.lire(r, z),
                    (lu_total, debut),
                );
                lu_total += lecture.octets;
                bilan.lus += 1;
                bilan.trop_grosses += lecture.trop_grosses;
                bilan.images_non_verifiees += releve.images_non_verifiees;
                bilan.images_laissees += releve.images_laissees;
                bilan.images_morcelees += releve.images_morcelees;
                if lecture.incomplete() {
                    bilan.incomplets += 1;
                }
                if (lecture.incomplete() || releve.images_non_verifiees > 0 || releve.images_morcelees > 0)
                    && bilan.noms_incomplets.len() < NOMS_MAX
                {
                    bilan.noms_incomplets.push(p.nom.clone());
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
    let mut noms = bilan.noms_incomplets.join(", ");
    if bilan.noms_incomplets.len() >= NOMS_MAX {
        noms.push('…');
    }
    if bilan.incomplets > 0 {
        avertir(&trf!(
            "{} processus lus en partie ({noms}) : régions de plus de {} Mio, au-delà de {} Mio par processus, ou disparues entre-temps, en tout ou en partie.",
            "{} processes partly read ({noms}): regions over {} MiB, beyond {} MiB per process, or gone in the meantime, wholly or in part.",
            bilan.incomplets,
            TAILLE_REGION_MAX >> 20,
            PAR_PROCESSUS_MAX >> 20
        ));
    }
    if bilan.trop_grosses > 0 {
        avertir(&trf!(
            "Régions de plus de {1} Mio jamais lues : {0}. Ce qui serait caché dans l'une d'elles n'est pas vu.",
            "Regions over {1} MiB never read: {0}. Whatever might be hidden in one of them is not seen.",
            bilan.trop_grosses,
            TAILLE_REGION_MAX >> 20
        ));
    }
    if bilan.images_non_verifiees > 0 {
        avertir(&trf!(
            "Images chargées (programmes, bibliothèques) qu'on n'a pas pu juger : {}. Rien ne dit si elles ont été modifiées en mémoire ; rien n'est conclu pour elles.",
            "Loaded images (programs, libraries) that could not be judged: {}. Nothing tells whether they were modified in memory; nothing is concluded for them.",
            bilan.images_non_verifiees
        ));
    }
    if bilan.images_morcelees > 0 {
        avertir(&trf!(
            "Images chargées lues hors de leur disposition : {} (code loin de l'en-tête dans le fichier, ou image trop grosse). Les règles y voient l'en-tête avec le code, mais une règle qui vise le point d'entrée peut s'y tromper : rien n'est conclu pour elles.",
            "Loaded images read out of their layout: {} (code far from the header in the file, or image too large). Rules see the header with the code, but a rule aimed at the entry point may be misled: nothing is concluded for them.",
            bilan.images_morcelees
        ));
    }
    if bilan.images_laissees > 0 {
        for ligne in envelopper(
            &trf!(
                "Images chargées du système non lues : {} (leur fichier est dans un dossier du système, que seul l'administrateur change, et rien n'y a été modifié en mémoire ; ce fichier n'est pas analysé ici).",
                "System loaded images not read: {} (their file is in a system folder, which only the administrator changes, and nothing in them was modified in memory; that file is not analysed here).",
                bilan.images_laissees
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{ligne}{RESET}");
        }
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
// FFI de libc : mmap et munmap, pour les images de fichier que lisent les essais.
#[allow(unsafe_code)]
mod tests {
    use super::*;

    /// Le tri des images de `releve_linux` pour les essais : le chemin seul, sans rien demander au disque ; le fichier
    /// est toujours confirmé, aux mêmes dates.
    fn systeme(chemin: &str, _inode: u64) -> SurLeDisque {
        SurLeDisque {
            du_systeme: image_du_systeme_linux(chemin),
            dates: Some((1, 2)),
        }
    }

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

    /// Une entrée de smaps : l'en-tête de maps, puis les champs (seul « Anonymous » compte ici).
    fn smaps(entete: &str, anonyme_ko: u64) -> String {
        format!("{entete}\nSize:  64 kB\nRss:  4 kB\nAnonymous:  {anonyme_ko} kB\nVmFlags: rd mr\n")
    }

    #[test]
    fn regions_anonymes_de_linux() {
        let texte = [
            smaps(
                "55d4c0a00000-55d4c0a21000 rw-p 00000000 00:00 0                          [heap]",
                132,
            ),
            smaps("7f3a00000000-7f3a00021000 rw-p 00000000 00:00 0 ", 0),
            smaps(
                "7f3b00000000-7f3b00021000 rwxp 00000000 00:00 0                          [stack]",
                4,
            ),
            smaps(
                "7f3c00000000-7f3c00021000 rw-p 00000000 00:00 0                          [anon:scudo]",
                0,
            ),
            // Le noyau, une région illisible, une ligne abîmée : rien.
            smaps(
                "7fff00000000-7fff00002000 r-xp 00000000 00:00 0                          [vdso]",
                0,
            ),
            smaps(
                "7fff10000000-7fff10002000 r--p 00000000 00:00 0                          [vvar]",
                0,
            ),
            smaps("7f3d00000000-7f3d00021000 ---p 00000000 00:00 0 ", 0),
            smaps("7f3e00021000-7f3e00000000 rw-p 00000000 00:00 0 ", 0),
        ]
        .concat();
        let releve = releve_linux(&texte, Some(&[]), systeme);
        let debuts: Vec<u64> = releve.blocs.iter().map(|b| b.morceaux[0].0.debut).collect();
        assert_eq!(
            debuts,
            [0x55d4_c0a0_0000, 0x7f3a_0000_0000, 0x7f3b_0000_0000, 0x7f3c_0000_0000]
        );
        assert_eq!(
            releve.blocs[0],
            Bloc::seule(
                Region {
                    debut: 0x55d4_c0a0_0000,
                    taille: 0x21000
                },
                false
            )
        );
        assert_eq!(releve.images_non_verifiees, 0);
    }

    /// Les mappages de fichiers : laissés au scan de fichiers seulement quand rien ne les distingue de leur fichier
    /// sur le disque. Une page de code privée (réécrite en mémoire), un fichier effacé, un memfd ou un tmpfs : toute
    /// l'image se lit, recollée à ses positions dans le fichier ; une page de données privée seule se lit seule.
    #[test]
    fn images_de_linux() {
        let libc = [
            smaps(
                "7f0000000000-7f0000028000 r--p 00000000 103:02 1234      /usr/lib/libc.so.6",
                0,
            ),
            smaps(
                "7f0000028000-7f00001b0000 r-xp 00028000 103:02 1234      /usr/lib/libc.so.6",
                0,
            ),
            smaps(
                "7f00001b0000-7f00001b1000 ---p 001b0000 103:02 1234      /usr/lib/libc.so.6",
                0,
            ),
            smaps(
                "7f00001b1000-7f00001b5000 r--p 001b0000 103:02 1234      /usr/lib/libc.so.6",
                16,
            ),
            smaps(
                "7f00001b5000-7f00001b7000 rw-p 001b4000 103:02 1234      /usr/lib/libc.so.6",
                8,
            ),
        ]
        .concat();
        // Intacte, sauf ses données relogées (privées) : celles-ci seules, chacune à part.
        let releve = releve_linux(&libc, Some(&[]), systeme);
        let seules: Vec<u64> = releve.blocs.iter().map(|b| b.morceaux[0].0.debut).collect();
        assert_eq!(seules, [0x7f00_001b_1000, 0x7f00_001b_5000]);
        assert!(releve.blocs.iter().all(|b| b.morceaux.len() == 1));
        // Le code réécrit (page privée dans r-xp) : l'image entière, recollée par décalage dans le fichier.
        let reecrite = libc.replace(
            "r-xp 00028000 103:02 1234      /usr/lib/libc.so.6\nSize:  64 kB\nRss:  4 kB\nAnonymous:  0 kB",
            "r-xp 00028000 103:02 1234      /usr/lib/libc.so.6\nSize:  64 kB\nRss:  4 kB\nAnonymous:  4 kB",
        );
        let releve = releve_linux(&reecrite, Some(&[]), systeme);
        assert_eq!(releve.blocs.len(), 1, "{:x?}", releve.blocs);
        let positions: Vec<u64> = releve.blocs[0].morceaux.iter().map(|(_, p)| *p).collect();
        assert_eq!(positions, [0, 0x28000, 0x1b_0000, 0x1b_4000]);
        assert_eq!(releve.blocs[0].taille, 0x1b_6000);
        assert!(!releve.blocs[0].chargee);
        // Effacé, memfd : lus en entier aussi.
        for chemin in ["/tmp/.x/agent (deleted)", "/memfd:a (deleted)"] {
            let texte = [
                smaps(&format!("5600000000-5600001000 r--p 00000000 00:05 77   {chemin}"), 0),
                smaps(&format!("5600001000-5600003000 r-xp 00001000 00:05 77   {chemin}"), 0),
            ]
            .concat();
            let releve = releve_linux(&texte, Some(&[]), systeme);
            assert_eq!(releve.blocs.len(), 1, "{chemin}");
            assert_eq!(releve.blocs[0].morceaux.len(), 2, "{chemin}");
        }
        // Sur un tmpfs (périphérique 0:38 dans mountinfo), même intact.
        let tmpfs = smaps("5600000000-5600001000 r-xp 00000000 00:26 9   /dev/shm/x", 0);
        let mountinfo =
            "30 1 0:38 / /dev/shm rw,nosuid shared:5 - tmpfs tmpfs rw\n31 1 103:2 / / rw - ext4 /dev/x rw\n";
        let en_memoire = en_memoire_linux(mountinfo);
        assert_eq!(en_memoire, [(0, 38)]);
        assert_eq!(releve_linux(&tmpfs, Some(&en_memoire), systeme).blocs.len(), 1);
        // Ailleurs que sur un tmpfs, intact mais hors des dossiers du système : à lire une fois pour tous.
        let releve = releve_linux(&tmpfs, Some(&[]), systeme);
        assert_eq!((releve.blocs.len(), releve.hors_systeme.len()), (0, 1));
        // mountinfo illisible : une image qui n'est retenue pour rien d'autre est non vérifiée, jamais écartée.
        let releve = releve_linux(&tmpfs, None, systeme);
        assert_eq!((releve.blocs.len(), releve.images_non_verifiees), (0, 1));
        // Deux fichiers qui se suivent : deux images.
        let deux = [
            smaps("5600000000-5600001000 r-xp 00000000 00:05 77   /a (deleted)", 0),
            smaps("5600001000-5600002000 r-xp 00000000 00:05 78   /b (deleted)", 0),
        ]
        .concat();
        assert_eq!(releve_linux(&deux, Some(&[]), systeme).blocs.len(), 2);
        // L'en-tête et le code d'une même image séparés par une région anonyme : toujours une seule image.
        let separee = [
            smaps("5600000000-5600001000 r--p 00000000 00:05 77   /a (deleted)", 0),
            smaps("5600001000-5600002000 rw-p 00000000 00:00 0 ", 4),
            smaps("5600002000-5600003000 r-xp 00001000 00:05 77   /a (deleted)", 0),
        ]
        .concat();
        let releve = releve_linux(&separee, Some(&[]), systeme);
        let image: Vec<&Bloc> = releve.blocs.iter().filter(|b| b.morceaux.len() == 2).collect();
        assert_eq!(image.len(), 1, "{:x?}", releve.blocs);
        // Une région exécutable sans droit de lecture se lit par /proc/<pid>/mem : gardée.
        let sans_lecture = smaps("7f5000000000-7f5000001000 --xp 00000000 00:00 0 ", 4);
        assert_eq!(releve_linux(&sans_lecture, Some(&[]), systeme).blocs.len(), 1);
        // Une bibliothèque intacte d'un disque : laissée au scan de fichiers, et comptée.
        assert_eq!(releve_linux(&libc, Some(&[]), systeme).images_laissees, 1);
        // Servie par FUSE : lue en mémoire.
        let fuse = "40 1 0:50 / /home/alice/m rw - fuse.sshfs x rw\n";
        assert_eq!(en_memoire_linux(fuse), [(0, 50)]);
    }

    /// Un regroupement qui tiendrait mal (trop grand, ou fait surtout de trous) se lit région par région.
    #[test]
    fn regroupements() {
        let r = |debut: u64, taille: u64| Region { debut, taille };
        let deux = regrouper(vec![(r(0x2000, 0x1000), 0x1000), (r(0x1000, 0x1000), 0)], true);
        assert_eq!(deux.len(), 1);
        assert_eq!(deux[0].morceaux[0].1, 0);
        assert_eq!((deux[0].taille, deux[0].chargee), (0x2000, true));
        let troue = regrouper(vec![(r(0, 0x1000), 0), (r(0x300_0000, 0x1000), 0x300_0000)], true);
        assert_eq!(troue.len(), 2);
        let max = TAILLE_REGION_MAX as u64;
        let enorme = regrouper(vec![(r(0, max), 0), (r(max, 0x1000), max)], false);
        assert_eq!(enorme.len(), 2);
    }

    /// L'en-tête d'une image en mémoire comparé à celui de son fichier : l'adresse de base réécrite par le chargeur ne
    /// compte pas ; une autre date de liaison, un autre point d'entrée ou une autre table des sections (un fichier
    /// réécrit après le chargement), si.
    #[test]
    fn entetes_de_l_image_et_du_fichier() {
        let fichier = crate::pe::essais::pe(&crate::pe::essais::Fabrique::default());
        let opt = 0x40 + 24;
        let mut memoire = fichier.clone();
        memoire[opt + 24..opt + 32].copy_from_slice(&0x7FF6_1234_0000u64.to_le_bytes());
        assert_eq!(entetes_pe_concordent(&memoire, &fichier), Some(true));
        for (position, longueur) in [(0x40 + 8, 4), (opt + 16, 4), (opt + 56, 4), (opt + 240 + 12, 4)] {
            let mut autre = fichier.clone();
            autre[position] ^= 0x10;
            assert_eq!(
                entetes_pe_concordent(&memoire, &autre),
                Some(false),
                "{position:#x}/{longueur}"
            );
        }
        assert_eq!(entetes_pe_concordent(b"pas un PE", &fichier), None);
        assert_eq!(entetes_pe_concordent(&memoire, &fichier[..0x50]), None);
    }

    /// Une allocation privée qui garde un PE tel que sur le disque (sections à leur position de fichier) : « at
    /// pe.entry_point » s'y lit aussi, à côté de la lecture en RVA.
    #[test]
    fn pe_tel_quel_dans_une_allocation_privee() {
        let mut fichier = crate::pe::essais::pe(&crate::pe::essais::Fabrique::default());
        let opt = 0x40 + 24;
        fichier[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        fichier[0x200..0x204].copy_from_slice(b"ENTR");
        let essai = regles(r#"import "pe" rule entree { strings: $a = "ENTR" condition: $a at pe.entry_point }"#);
        let region = Region {
            debut: 0x1_0000,
            taille: fichier.len() as u64,
        };
        let mut tampon = Tampon::nouveau(fichier.len());
        let remplir = |_: &Region, z: &mut [u8]| {
            z.copy_from_slice(&fichier);
            z.len()
        };
        let lecture = analyser_regions(
            &essai,
            &[Bloc::seule(region, true)],
            &mut tampon.0,
            remplir,
            0,
            Instant::now(),
        );
        assert_eq!(lecture.trouves.len(), 1, "{lecture:?}");
    }

    /// Sur un vrai Windows : kernel32, chargée dans ce processus et intacte, a son fichier, le même en-tête et aucune
    /// page de code privée, et elle est dans System32 : laissée. Sous Wine (qui charge les PE lui-même), sauté.
    #[cfg(windows)]
    #[test]
    fn kernel32_intacte_est_laissee() {
        if crate::journal::sous_wine() {
            return crate::essais::saute("Wine charge les PE lui-même");
        }
        let lecteur = plateforme::Lecteur::ouvrir(std::process::id()).expect("son propre processus doit s'ouvrir");
        let releve = lecteur.regions();
        assert!(
            releve.images_laissees > 0,
            "aucune image du système laissée : {releve:?}"
        );
    }

    /// Windows : une image chargée n'est jugée intacte que si son fichier est là et qu'aucune page de code n'est
    /// privée ; ce qui ne se sait pas est non vérifié.
    #[test]
    fn images_de_windows() {
        assert_eq!(image_windows(Some(true), Some(false), false), Some(false));
        assert_eq!(image_windows(Some(true), Some(true), false), Some(true));
        assert_eq!(image_windows(Some(false), Some(false), false), Some(true));
        assert_eq!(image_windows(Some(false), None, false), Some(true));
        assert_eq!(image_windows(Some(true), None, false), None);
        assert_eq!(image_windows(None, Some(false), false), None);
        assert_eq!(image_windows(None, None, true), Some(true));
        assert_eq!(image_windows(Some(true), Some(false), true), Some(true));
    }

    /// Campagne n° 4 (M3) : le code d'une image effacée mappé loin de son en-tête dans le fichier (2 Mio pour 8 Kio
    /// lus) défaisait le recollage, et l'en-tête et le code se lisaient chacun seul, sans rien dire. Ils se lisent
    /// maintenant tassés dans un seul bloc, où la règle (en-tête ELF ET marque) les voit ensemble, et l'image est dite
    /// morcelée (pas de ✔). Le témoin, code à 0x1000 dans le fichier : recollé à sa place, rien de dit.
    #[test]
    fn code_eloigne_de_l_en_tete() {
        let image = |decalage: &str| {
            [
                smaps("5600000000-5600001000 r--p 00000000 00:05 77   /tmp/x (deleted)", 0),
                smaps(
                    &format!("5600001000-5600002000 r-xp {decalage} 00:05 77   /tmp/x (deleted)"),
                    0,
                ),
            ]
            .concat()
        };
        let temoin = releve_linux(&image("00001000"), Some(&[]), systeme);
        assert_eq!((temoin.blocs.len(), temoin.images_morcelees), (1, 0));
        let eloigne = releve_linux(&image("00200000"), Some(&[]), systeme);
        assert_eq!((eloigne.blocs.len(), eloigne.images_morcelees), (1, 1), "{eloigne:x?}");
        let bloc = &eloigne.blocs[0];
        let positions: Vec<u64> = bloc.morceaux.iter().map(|(r, p)| r.debut + *p).collect();
        assert_eq!(positions, [0x56_0000_0000, 0x56_0000_2000]);
        assert_eq!(bloc.taille, 0x2000);
        let essai =
            regles(r#"rule elf_et_code { strings: $a = "MARQUE-CODE" condition: uint32(0) == 0x464C457F and $a }"#);
        let remplir = |r: &Region, z: &mut [u8]| {
            z.fill(0x90);
            if r.debut == 0x56_0000_0000 {
                z[..4].copy_from_slice(b"\x7fELF");
            } else {
                z[16..27].copy_from_slice(b"MARQUE-CODE");
            }
            z.len()
        };
        let mut tampon = Tampon::nouveau(0x4000);
        let lecture = analyser_regions(&essai, &eloigne.blocs, &mut tampon.0, remplir, 0, Instant::now());
        assert_eq!(lecture.trouves.len(), 1, "{lecture:?}");
        // Plus gros que le tampon : chacun seul, mais dit.
        let max = TAILLE_REGION_MAX as u64;
        let r = |debut, taille| Region { debut, taille };
        let (blocs, morcelee) = recoller_image(vec![(r(0, max), 0), (r(max, 0x1000), max)], false);
        assert_eq!((blocs.len(), morcelee), (2, true));
        let mut bilan = Bilan {
            lus: 1,
            images_morcelees: 1,
            ..Bilan::default()
        };
        assert_eq!(verdict(&bilan), Verdict::Incomplet);
        bilan.images_morcelees = 0;
        assert_eq!(verdict(&bilan), Verdict::Sain);
    }

    /// Campagne n° 4, deuxième relecture (M4) : un processus leurre qui mappe la même image qu'un autre et remplit
    /// sa part avant elle (les images hors du système se lisent en dernier) ne la fait pas passer pour lue : elle
    /// n'est comptée vue qu'après un processus lu en entier, et se lit dans le suivant.
    #[test]
    fn image_hors_du_systeme_apres_un_leurre() {
        let image = [
            smaps(
                "5600000000-5600001000 r--p 00000000 103:02 77   /home/alice/.cache/agent",
                0,
            ),
            smaps(
                "5600001000-5600002000 r-xp 00001000 103:02 77   /home/alice/.cache/agent",
                0,
            ),
        ]
        .concat();
        let region = TAILLE_REGION_MAX as u64;
        let pleines = PAR_PROCESSUS_MAX / region;
        let mut leurre = image.clone();
        for i in 0..pleines {
            let debut = 0x7f00_0000_0000 + i * region;
            leurre += &smaps(&format!("{debut:x}-{:x} rw-p 00000000 00:00 0 ", debut + region), 4);
        }
        let rien = regles("rule Rien { condition: false }");
        let mut tampon = Tampon::nouveau(TAILLE_REGION_MAX);
        let mut vues = std::collections::HashSet::new();
        let tout = |_: &Region, z: &mut [u8]| z.len();
        let mut a = releve_linux(&leurre, Some(&[]), systeme);
        let lecture = lire_processus(&rien, &mut a, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
        assert!(lecture.incomplete(), "{lecture:?}");
        assert_eq!(vues.len(), 0);
        let mut b = releve_linux(&image, Some(&[]), systeme);
        let lecture = lire_processus(&rien, &mut b, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
        assert_eq!((b.blocs.len(), lecture.octets, vues.len()), (1, 0x2000, 1));
        // Le même chemin, réécrit sur place (autres dates) : une autre clé, relu.
        let reecrit = |_: &str, _: u64| SurLeDisque {
            du_systeme: false,
            dates: Some((3, 4)),
        };
        let mut c = releve_linux(&image, Some(&[]), reecrit);
        lire_processus(&rien, &mut c, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
        assert_eq!((c.blocs.len(), vues.len()), (1, 2));
        // Sans dates (le chemin ne mène plus au fichier mappé) : pas de clé, lu dans chaque processus.
        let perdu = |_: &str, _: u64| SurLeDisque::default();
        for _ in 0..2 {
            let mut d = releve_linux(&image, Some(&[]), perdu);
            lire_processus(&rien, &mut d, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
            assert_eq!((d.blocs.len(), vues.len()), (1, 2));
        }
    }

    /// Campagne n° 4, deuxième relecture (M3, M4) : un fichier de données mappé hors du système, sans région
    /// exécutable (un journal de systemd, lu par fenêtres), n'est ni lu ni dit morcelé ; avec un en-tête ELF ou PE au
    /// début du fichier, c'est une image (chargée sans x, ou à l'exécution retirée) : elle se lit.
    #[test]
    fn donnees_mappees_hors_du_systeme() {
        let journal = "/var/log/journal/a/system.journal";
        let fenetres = [
            smaps(&format!("7f00000000-7f00800000 r--s 00000000 103:02 9   {journal}"), 0),
            smaps(&format!("7f10000000-7f10800000 r--s 05000000 103:02 9   {journal}"), 0),
        ]
        .concat();
        let rien = regles("rule Rien { condition: false }");
        let mut tampon = Tampon::nouveau(TAILLE_REGION_MAX);
        let mut vues = std::collections::HashSet::new();
        let entetes: [(&[u8], usize); 4] = [(b"LPKSHHRH", 0), (b"\x7fELF\x02", 1), (b"MZ\x90\0", 1), (b"", 0)];
        for (entete, lus) in entetes {
            let mut releve = releve_linux(&fenetres, Some(&[]), systeme);
            assert_eq!(releve.hors_systeme.len(), 1, "{releve:x?}");
            let lire = |r: &Region, z: &mut [u8]| {
                if r.debut == 0x7f_0000_0000 && z.len() == 4 {
                    let n = entete.len().min(4);
                    z[..n].copy_from_slice(&entete[..n]);
                    return n;
                }
                z.len()
            };
            let lecture = lire_processus(&rien, &mut releve, &mut vues, &mut tampon.0, lire, (0, Instant::now()));
            assert_eq!((releve.blocs.len(), releve.images_morcelees), (lus, lus), "{entete:?}");
            assert_eq!(lecture.octets > 0, lus > 0, "{entete:?}");
            vues.clear();
        }
        // Sans le début du fichier, rien n'en fait une image : laissé sans lecture.
        let milieu = smaps(&format!("7f10000000-7f10800000 r--s 05000000 103:02 9   {journal}"), 0);
        assert_eq!(releve_linux(&milieu, Some(&[]), systeme).hors_systeme.len(), 0);
    }

    /// Campagne n° 4 (M4) : une image intacte hors des dossiers du système (un programme lancé de ~/.cache) était
    /// « laissée au scan de fichiers », que rien ne faisait. Elle se lit maintenant en mémoire, une fois pour tous les
    /// processus qui la chargent ; une bibliothèque de /usr, intacte, reste seule laissée.
    #[test]
    fn image_hors_du_systeme() {
        let image = |chemin: &str| {
            [
                smaps(&format!("5600000000-5600001000 r--p 00000000 103:02 77   {chemin}"), 0),
                smaps(&format!("5600001000-5600002000 r-xp 00001000 103:02 77   {chemin}"), 0),
            ]
            .concat()
        };
        let mut releve = releve_linux(&image("/home/alice/.cache/agent"), Some(&[]), systeme);
        assert_eq!(
            (releve.images_laissees, releve.hors_systeme.len()),
            (0, 1),
            "{releve:x?}"
        );
        let rien = regles("rule Rien { condition: false }");
        let mut tampon = Tampon::nouveau(0x4000);
        let mut vues = std::collections::HashSet::new();
        let tout = |_: &Region, z: &mut [u8]| z.len();
        let lecture = lire_processus(&rien, &mut releve, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
        assert_eq!(releve.blocs.len(), 1);
        assert_eq!(releve.blocs[0].morceaux.len(), 2);
        assert_eq!((lecture.octets, vues.len()), (0x2000, 1));
        // Le même fichier dans un autre processus : déjà lu.
        let mut autre = releve_linux(&image("/home/alice/.cache/agent"), Some(&[]), systeme);
        lire_processus(&rien, &mut autre, &mut vues, &mut tampon.0, tout, (0, Instant::now()));
        assert_eq!(autre.blocs.len(), 0);
        let libc = releve_linux(&image("/usr/lib/libc.so.6"), Some(&[]), systeme);
        assert_eq!(
            (libc.images_laissees, libc.hors_systeme.len(), libc.blocs.len()),
            (1, 0, 0)
        );
        for chemin in [
            "/usr/lib/libc.so.6",
            "/usr/local/bin/x",
            "/nix/store/a/lib/b.so",
            "/lib64/ld.so",
        ] {
            assert!(image_du_systeme_linux(chemin), "{chemin}");
        }
        for chemin in [
            "/home/alice/.cache/a",
            "/var/tmp/a",
            "/opt/a/b.so",
            "/usr/../home/alice/a",
            "/usrx/a",
            "/tmp/a",
        ] {
            assert!(!image_du_systeme_linux(chemin), "{chemin}");
        }
    }

    /// Le vrai tri, sur le disque : un fichier de /usr ne compte que si l'inode de smaps est le sien (un fichier d'un
    /// compte monté sur /usr/lib/… dans un autre espace de noms garde son propre inode).
    #[cfg(target_os = "linux")]
    #[test]
    fn fichier_du_systeme_par_son_inode() {
        use std::os::unix::fs::MetadataExt;
        let Some(chemin) = ["/usr/bin/sh", "/usr/bin/env", "/usr/bin/ls"]
            .into_iter()
            .find(|c| std::path::Path::new(c).is_file())
        else {
            return crate::essais::saute("aucun programme de /usr/bin");
        };
        let inode = std::fs::metadata(chemin).unwrap().ino();
        assert!(fichier_linux(chemin, inode).du_systeme);
        assert!(fichier_linux(chemin, inode).dates.is_some());
        assert!(!fichier_linux(chemin, inode ^ 1).du_systeme);
        assert_eq!(fichier_linux(chemin, inode ^ 1).dates, None);
        // Le bac à sable de Steam montre l'hôte sous /run/host : le même fichier, s'il en a l'inode, sans dates (la
        // clé ne se confirme pas d'ici : l'image se lirait dans chaque processus si elle n'était pas du système).
        let hote = format!("/run/host{chemin}");
        assert!(fichier_linux(&hote, inode).du_systeme);
        assert!(!fichier_linux(&hote, inode ^ 1).du_systeme);
        assert!(!fichier_linux("/run/host/home/alice/x.so", inode).du_systeme);
    }

    /// Windows : seuls les dossiers du système, sur le volume du système, sont laissés ; leurs sous-dossiers que tout
    /// compte peut écrire, un autre volume, un « .. » ou un flux secondaire se lisent.
    #[test]
    fn images_du_systeme_de_windows() {
        let racines = [
            r"\\?\C:".to_string(),
            r"\\?\GLOBALROOT\Device\HarddiskVolume3".to_string(),
        ];
        let windows = r"\WINDOWS";
        for chemin in [
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
            r"\\?\C:\Windows\SysWOW64\ntdll.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\WinSxS\amd64_x\comctl32.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Program Files\App\a.dll",
        ] {
            assert!(image_du_systeme_windows(chemin, &racines, windows), "{chemin}");
        }
        for chemin in [
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume30\Windows\System32\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume4\Windows\System32\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32\spool\drivers\color\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32\Tasks\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\Temp\a.dll",
            r"\\?\GLOBALROOT\Device\HarddiskVolume3\Windows\System32\..\Temp\a.dll",
            r"\\?\C:\Windows\System32\a.dll:flux",
            r"\\?\D:\Windows\System32\a.dll",
        ] {
            assert!(!image_du_systeme_windows(chemin, &racines, windows), "{chemin}");
        }
    }

    /// La preuve de la campagne d'attaque n° 3, refaite avec des données fabriquées : un ELF dont l'en-tête et le code
    /// sont dans deux régions. Lues une à une, la règle (en-tête ELF ET marque dans le code) ne correspond jamais ;
    /// recollées, si. Les trous se lisent comme des zéros, pas comme un reste du tampon.
    #[test]
    fn regions_recollees() {
        let essai = regles(
            r#"rule elf_et_code { strings: $a = "MARQUE-CODE" condition: uint32(0) == 0x464C457F and $a }
               rule reste { strings: $r = "RESTE" condition: $r }"#,
        );
        let entete = Region {
            debut: 0x5000_0000,
            taille: 0x1000,
        };
        let code = Region {
            debut: 0x5000_2000,
            taille: 0x1000,
        };
        let remplir = |r: &Region, z: &mut [u8]| {
            z.fill(0x90);
            if r.debut == entete.debut {
                z[..4].copy_from_slice(b"\x7fELF");
            } else {
                z[16..27].copy_from_slice(b"MARQUE-CODE");
            }
            z.len()
        };
        let mut tampon = Tampon::nouveau(0x4000);
        tampon.0.fill(b'R');
        tampon.0[0x1800..0x1805].copy_from_slice(b"RESTE");
        let une_a_une = [Bloc::seule(entete, false), Bloc::seule(code, false)];
        let lecture = analyser_regions(&essai, &une_a_une, &mut tampon.0, remplir, 0, Instant::now());
        assert_eq!(lecture.trouves, []);
        tampon.0[0x1800..0x1805].copy_from_slice(b"RESTE");
        let recolle = regrouper(vec![(entete, 0), (code, 0x2000)], false);
        let lecture = analyser_regions(&essai, &recolle, &mut tampon.0, remplir, 0, Instant::now());
        assert_eq!(
            lecture.trouves,
            [(
                "elf_et_code".to_string(),
                Region {
                    debut: entete.debut,
                    taille: 0x3000
                }
            )]
        );
        assert_eq!((lecture.octets, lecture.sautees, lecture.partielles), (0x2000, 0, 0));
    }

    /// De vraies régions de ce processus de test : un fichier fabriqué (en-tête ELF, marque dans sa seconde page),
    /// mappé en deux régions puis effacé, comme un programme qui s'efface après s'être lancé. Le relevé de smaps le
    /// retient en entier, recollé, et la règle (en-tête ET marque) le retrouve ; une page de données d'un fichier
    /// présent, modifiée en mémoire (copiée à l'écriture), est retenue aussi, alors que le fichier est sain.
    #[cfg(target_os = "linux")]
    #[test]
    fn image_effacee_et_page_modifiee_de_ce_processus() {
        use std::os::fd::AsRawFd;
        const PAGE: usize = 4096;
        let dossier = crate::protection::isoler::dossier_jetable().unwrap();
        let marque = ["vanguard", "image", "effacee", "41c7"].join("-");
        let mut contenu = vec![0u8; 2 * PAGE];
        contenu[..4].copy_from_slice(b"\x7fELF");
        contenu[PAGE + 64..PAGE + 64 + marque.len()].copy_from_slice(marque.as_bytes());
        let chemin = dossier.join("essai-image");
        std::fs::write(&chemin, &contenu).unwrap();
        let fichier = std::fs::File::open(&chemin).unwrap();
        // SAFETY: mmap d'un fichier à nous, en lecture seule et privé, sans adresse imposée ; les deux régions sont
        // retirées par munmap avant la fin du test, et rien ne les lit par un pointeur Rust.
        let (premiere, seconde) = unsafe {
            let premiere = libc::mmap(
                std::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                fichier.as_raw_fd(),
                0,
            );
            assert_ne!(premiere, libc::MAP_FAILED);
            // La seconde page remappée seule à sa place, d'autres droits (sinon le noyau fusionne les deux) : deux
            // régions du même fichier, comme les segments d'un ELF.
            let seconde = libc::mmap(
                premiere.cast::<u8>().add(PAGE).cast(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                fichier.as_raw_fd(),
                libc::off_t::try_from(PAGE).unwrap(),
            );
            assert_ne!(seconde, libc::MAP_FAILED);
            (premiere, seconde)
        };
        drop(fichier);
        std::fs::remove_file(&chemin).unwrap();
        // Une page de données d'un fichier toujours là, modifiée en mémoire.
        let sain = dossier.join("essai-sain");
        std::fs::write(&sain, vec![0u8; PAGE]).unwrap();
        let f = std::fs::OpenOptions::new().read(true).open(&sain).unwrap();
        // SAFETY: comme plus haut, une page privée, écrite par son pointeur dans ses limites, puis retirée.
        let donnees = unsafe {
            let p = libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                f.as_raw_fd(),
                0,
            );
            assert_ne!(p, libc::MAP_FAILED);
            p.cast::<u8>().write_volatile(1);
            p
        };
        let essai = regles(&format!(
            r#"rule image_effacee {{ strings: $a = "{marque}" condition: uint32(0) == 0x464C457F and $a }}"#
        ));
        let Acces::Ouvert(lecteur) = plateforme::ouvrir(std::process::id()) else {
            panic!("/proc/self doit s'ouvrir");
        };
        let releve = lecteur.regions();
        let image: Vec<Bloc> = releve
            .blocs
            .iter()
            .filter(|b| b.morceaux.iter().any(|(r, _)| r.debut == premiere as u64))
            .cloned()
            .collect();
        assert_eq!(image.len(), 1, "{:x?}", releve.blocs);
        assert_eq!(image[0].morceaux.len(), 2);
        assert!(releve.blocs.iter().any(|b| b.morceaux[0].0.debut == donnees as u64));
        let mut tampon = Tampon::nouveau(2 * PAGE);
        let lecture = analyser_regions(
            &essai,
            &image,
            &mut tampon.0,
            |r, z| lecteur.lire(r, z),
            0,
            Instant::now(),
        );
        assert_eq!(lecture.trouves.len(), 1, "{lecture:?}");
        // SAFETY: les régions mappées plus haut, de leurs tailles, retirées une seule fois.
        unsafe {
            libc::munmap(premiere, PAGE);
            libc::munmap(seconde, PAGE);
            libc::munmap(donnees, PAGE);
        }
        let _ = std::fs::remove_dir_all(&dossier);
    }

    #[test]
    fn bornes() {
        let rien = Duration::ZERO;
        assert_eq!(decider(4096, 4096, 0, 0, rien), Decision::Lire);
        let max = TAILLE_REGION_MAX as u64;
        assert_eq!(decider(max, max, 0, 0, rien), Decision::Lire);
        assert_eq!(decider(max + 1, max + 1, 0, 0, rien), Decision::Sauter);
        assert_eq!(
            decider(4096, 4096, PAR_PROCESSUS_MAX - 4095, 0, rien),
            Decision::ProcessusPlein
        );
        // Un bloc recollé compte ce qu'il lit, pas ses trous.
        assert_eq!(decider(max, 4096, PAR_PROCESSUS_MAX - 4096, 0, rien), Decision::Lire);
        assert_eq!(decider(4096, 4096, 0, TOTAL_MAX, rien), Decision::Arret);
        assert_eq!(decider(4096, 4096, 0, 0, DUREE_MAX), Decision::Arret);
        // Les bornes à l'œuvre : une région trop grosse sautée, puis la part du processus atteinte (le reste sauté
        // sans être lu) ; et un arrêt général, sans rien lire.
        let mut regions = vec![Bloc::seule(
            Region {
                debut: 0,
                taille: max + 1,
            },
            false,
        )];
        regions.extend((0..9).map(|i| {
            Bloc::seule(
                Region {
                    debut: i * max,
                    taille: max,
                },
                false,
            )
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
                trop_grosses: 1,
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
        let petites = [
            Bloc::seule(Region { debut: 0, taille: 8 }, false),
            Bloc::seule(Region { debut: 8, taille: 8 }, false),
        ];
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
                trop_grosses: 0,
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
            Bloc::seule(Region { debut: 0, taille: 64 }, false),
            Bloc::seule(Region { debut: 64, taille: 16 }, false),
            Bloc::seule(Region { debut: 80, taille: 101 }, false),
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
        assert_eq!(lecture.trouves, [("Ancien".to_string(), regions[0].region())]);
        assert_eq!(tampon.0.len(), 100);
        crate::socle::effacer(&mut tampon.0);
        assert!(tampon.0.iter().all(|&o| o == 0));
        let mut impair = vec![0xA5u8; 64 * 3 + 7];
        crate::socle::effacer(&mut impair);
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
        let regions: Vec<Region> = lecteur
            .regions()
            .blocs
            .iter()
            .flat_map(|b| b.morceaux.iter().map(|(r, _)| *r))
            .collect();
        let contenante = regions
            .iter()
            .find(|r| r.debut <= adresse && adresse + longueur <= r.debut + r.taille)
            .unwrap_or_else(|| panic!("aucune région ne contient la marque ({adresse:#x}) : {regions:x?}"));
        let debut = (adresse / PAGE * PAGE).max(contenante.debut);
        let fin = (adresse + longueur)
            .next_multiple_of(PAGE)
            .min(contenante.debut + contenante.taille);
        let page = Region {
            debut,
            taille: fin - debut,
        };
        let pages = [Bloc::seule(page, cfg!(windows))];
        let mut tampon = Tampon::nouveau(usize::try_from(page.taille).unwrap());
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
                trouves: vec![("Essai_Memoire".into(), page)],
                octets: page.taille,
                sautees: 0,
                trop_grosses: 0,
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
