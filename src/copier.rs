//! Copier mes fichiers : Documents, Images, Bureau, Vidéos et Musique vers un disque externe, avant une réparation
//! risquée, une réinstallation ou un ordinateur qu'on rend. La copie va dans un dossier daté ; la place nécessaire est
//! comparée à la place libre avant de commencer ; chaque fichier est relu après la copie et son empreinte BLAKE3
//! comparée à celle de l'original. Rien n'est jamais effacé ni écrasé : un fichier différent déjà sur le disque garde
//! sa place, la copie prend un autre nom (« photo (2).jpg »). Une copie interrompue (disque débranché, Ctrl-C)
//! reprend là où elle s'est arrêtée : ce qui est déjà copié, à l'identique, n'est pas recopié. Jamais vers la clé
//! VANGUARD ni vers le disque du système.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::selection::{Case, Ligne, choisir, cocher};
use crate::socle::taille_lisible;
use crate::ui::*;

/// Témoin d'une copie pas finie, dans son dossier daté : sa présence propose la reprise.
const TEMOIN: &str = ".vanguard-copie-en-cours";
/// Fichier en cours d'écriture : renommé seulement une fois complet, il n'est jamais pris pour une vraie copie.
const PARTIEL: &str = ".vanguard-partiel";
const COMPTE_RENDU: &str = "vanguard-copie.txt";
/// Début du nom des dossiers datés, en français puis en anglais (une copie se reprend dans les deux langues).
const PREFIXES: [&str; 2] = ["Vanguard-copie-", "Vanguard-copy-"];

/// Un dossier de copie, y compris d'une version d'avant le changement de nom (`passage`).
fn de_copie(nom: &str) -> bool {
    PREFIXES
        .iter()
        .flat_map(|p| crate::passage::les_deux(p))
        .any(|p| nom.starts_with(&p))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sorte {
    Documents,
    Images,
    Bureau,
    Videos,
    Musique,
}

/// Où trouver chaque dossier : user-dirs.dirs, puis noms usuels (Linux) ; registre, puis profil (Windows) ; macOS.
#[rustfmt::skip] // une ligne par dossier, que rustfmt étalerait sur huit
const DOSSIERS: [(Sorte, &str, &[&str], [&str; 3]); 5] = [
    (Sorte::Documents, "XDG_DOCUMENTS_DIR", &["Documents"], ["Personal", "Documents", "Documents"]),
    (Sorte::Images, "XDG_PICTURES_DIR", &["Images", "Pictures"], ["My Pictures", "Pictures", "Pictures"]),
    (Sorte::Bureau, "XDG_DESKTOP_DIR", &["Bureau", "Desktop"], ["Desktop", "Desktop", "Desktop"]),
    (Sorte::Videos, "XDG_VIDEOS_DIR", &["Vidéos", "Videos"], ["My Video", "Videos", "Movies"]),
    (Sorte::Musique, "XDG_MUSIC_DIR", &["Musique", "Music"], ["My Music", "Music", "Music"]),
];

impl Sorte {
    pub(crate) fn nom(self) -> &'static str {
        match self {
            Sorte::Documents => tr!("Documents", "Documents"),
            Sorte::Images => tr!("Images", "Pictures"),
            Sorte::Bureau => tr!("Bureau", "Desktop"),
            Sorte::Videos => tr!("Vidéos", "Videos"),
            Sorte::Musique => tr!("Musique", "Music"),
        }
    }
}

/// Les dossiers personnels qui existent, chacun avec son chemin dans la langue du système.
pub(crate) fn sources() -> Vec<(Sorte, PathBuf)> {
    let mut liste: Vec<(Sorte, PathBuf)> = Vec::new();
    for (sorte, ..) in DOSSIERS {
        // Deux sortes au même endroit (Bureau non configuré = dossier personnel) : une seule fois.
        if let Some(chemin) = chemin_de(sorte).filter(|c| c.is_dir() && liste.iter().all(|(_, vu)| vu != c)) {
            liste.push((sorte, chemin));
        }
    }
    liste
}

#[cfg(target_os = "linux")]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(_, cle, noms, _) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    let maison = crate::socle::maison();
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let declares = std::fs::read_to_string(config.join("user-dirs.dirs")).unwrap_or_default();
    crate::protection::pieges::dossier_declare(&declares, cle, &maison)
        .or_else(|| noms.iter().map(|n| maison.join(n)).find(|d| d.is_dir()))
}

/// Windows : les dossiers déclarés pour le compte (déplacés dans OneDrive le cas échéant), sinon ceux du profil.
#[cfg(windows)]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(.., [valeur, profil, _]) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")
        .ok()
        .and_then(|k| k.get_value::<String, _>(valeur).ok())
        .map(|c| PathBuf::from(crate::protection::pieges::developper(&c)))
        .or_else(|| std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(profil)))
}

#[cfg(target_os = "macos")]
fn chemin_de(sorte: Sorte) -> Option<PathBuf> {
    let &(.., [_, _, nom]) = DOSSIERS.iter().find(|d| d.0 == sorte)?;
    Some(crate::socle::maison().join(nom))
}

pub struct Disque {
    pub racine: PathBuf,
    pub nom: String,
    pub libre: u64,
    pub total: u64,
}

/// La clé VANGUARD (ou sa partition des journaux), reconnue à ses témoins.
pub(crate) fn est_la_cle(racine: &Path) -> bool {
    [crate::reseau::TEMOIN_CLE, crate::journal::TEMOIN]
        .iter()
        .any(|t| racine.join(t).is_file())
}

/// Le volume de `p` porte-t-il le système ou le dossier personnel ? `None` : le volume ne peut pas être lu.
#[cfg(target_os = "linux")]
fn sur_le_systeme(p: &Path) -> Option<bool> {
    let montages = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    sur_le_systeme_selon(&montages, &p.canonicalize().ok()?, &crate::socle::maison())
}

/// D'après /proc/self/mountinfo : le système de fichiers (« majeur:mineur ») du montage le plus profond qui contient
/// chaque chemin. `st_dev` ne suffit pas : chaque sous-volume d'un btrfs a le sien, et /var/log ou un sous-volume
/// monté dans /mnt passait pour un autre disque.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sur_le_systeme_selon(montages: &str, p: &Path, maison: &Path) -> Option<bool> {
    let volume = |chemin: &Path| montage(montages, chemin).map(|(dev, _)| dev);
    let v = volume(p)?;
    Some([volume(Path::new("/")), volume(maison)].contains(&Some(v)))
}

/// Le montage le plus profond qui contient `chemin`, d'après /proc/self/mountinfo : (majeur:mineur, type de système
/// de fichiers, écrit après « - »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn montage<'a>(montages: &'a str, chemin: &Path) -> Option<(&'a str, &'a str)> {
    montages
        .lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace().skip(2);
            let dev = c.next()?;
            let point = PathBuf::from(sans_echappements(c.nth(1)?));
            let genre = l.split(" - ").nth(1)?.split_whitespace().next()?;
            chemin.starts_with(&point).then_some((point, dev, genre))
        })
        // Le plus long ; à longueur égale, le dernier monté, qui recouvre les autres.
        .max_by_key(|(point, ..)| point.as_os_str().len())
        .map(|(_, dev, genre)| (dev, genre))
}

/// Un système de fichiers qui ne garde pas un fichier de 4 Go ou plus : FAT32 (« vfat » sous Linux, « msdos » sous
/// macOS, « FAT32 » sous Windows).
pub(crate) fn limite_4_go(genre: &str) -> bool {
    matches!(genre.to_ascii_lowercase().as_str(), "vfat" | "msdos" | "fat32" | "fat")
}

/// Le type du système de fichiers de `p` ; `None` s'il ne se lit pas.
#[cfg(target_os = "linux")]
pub(crate) fn genre_du_volume(p: &Path) -> Option<String> {
    let montages = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    montage(&montages, &p.canonicalize().ok()?).map(|(_, genre)| genre.to_string())
}

#[cfg(target_os = "macos")]
pub(crate) fn genre_du_volume(p: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    // SAFETY : `statfs` est une structure C de nombres et de tableaux de caractères, valide à zéro.
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY : `c` est une chaîne C terminée par un zéro, `s` une structure à nous, écrite par statfs seulement.
    if unsafe { libc::statfs(c.as_ptr(), &raw mut s) } != 0 {
        return None;
    }
    // SAFETY : statfs a rempli f_fstypename, une chaîne terminée par un zéro dans son tableau.
    let nom = unsafe { std::ffi::CStr::from_ptr(s.f_fstypename.as_ptr()) };
    Some(nom.to_string_lossy().into_owned())
}

#[cfg(windows)]
pub(crate) fn genre_du_volume(p: &Path) -> Option<String> {
    let lecteur: String = p
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .take(3)
        .collect();
    if let Some(l) = crate::machine::windows::lecteurs::lecteur(Path::new(&lecteur)) {
        return Some(l.format).filter(|f| !f.is_empty());
    }
    let format = crate::machine::windows::ps(&format!(
        "[IO.DriveInfo]::new('{}').DriveFormat",
        crate::commande::ps_texte(&lecteur)
    ))?;
    Some(format.trim().to_string()).filter(|f| !f.is_empty())
}

/// Les fichiers de 4 Go ou plus des dossiers choisis : un disque en FAT32 ne peut pas les recevoir.
fn gros_fichiers(dossiers: &[(Sorte, PathBuf)]) -> Vec<PathBuf> {
    let mut gros = Vec::new();
    let mut a_voir: Vec<PathBuf> = dossiers.iter().map(|(_, d)| d.clone()).collect();
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(m) = e.path().symlink_metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() && m.len() > u64::from(u32::MAX) {
                gros.push(e.path());
            }
        }
    }
    gros
}

/// Un chemin de /proc/mounts ou mountinfo : l'espace, la tabulation, le saut de ligne et la barre oblique inverse y
/// sont écrits en octal (« \040 » pour l'espace).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn sans_echappements(t: &str) -> String {
    let mut sortie = Vec::with_capacity(t.len());
    let octets = t.as_bytes();
    let mut i = 0;
    while i < octets.len() {
        let code = octets
            .get(i + 1..i + 4)
            .and_then(|o| u8::from_str_radix(std::str::from_utf8(o).ok()?, 8).ok());
        match (octets[i], code) {
            (b'\\', Some(c)) => {
                sortie.push(c);
                i += 4;
            }
            (o, _) => {
                sortie.push(o);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// macOS : chaque volume a son `st_dev` (les volumes d'un même conteneur APFS aussi, mais le compte est sur celui des
/// données, comparé lui aussi).
#[cfg(target_os = "macos")]
fn sur_le_systeme(p: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    let volume = |p: &Path| std::fs::metadata(p).ok().map(|m| m.dev());
    let v = volume(p)?;
    Some([volume(Path::new("/")), volume(&crate::socle::maison())].contains(&Some(v)))
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux et macOS, où le volume peut être illisible
fn sur_le_systeme(p: &Path) -> Option<bool> {
    let lecteur: String = p
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .chars()
        .take(2)
        .collect();
    let systeme = std::env::var("SystemDrive").map_or("C:".into(), |s| s.to_uppercase());
    Some(lecteur.to_uppercase() == systeme)
}

/// Linux : les systèmes de fichiers montés pour l'utilisateur (/run/media, /media, /mnt), modifiables, hors du disque
/// du système et du dossier personnel, et pas la clé.
#[cfg(target_os = "linux")]
pub(crate) fn disques() -> Vec<Disque> {
    const SYSTEMES: &[&str] = &[
        "vfat", "exfat", "ntfs", "ntfs3", "fuseblk", "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "hfsplus", "udf",
    ];
    let montages = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    // Les autres partitions de la clé VANGUARD (VTOYEFI, WIN11, MACOS…) n'ont pas son témoin, mais sont sur le même
    // support : elles ne sont pas un disque où copier ou écrire des essais.
    let de_la_cle: Vec<String> = montages
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let (source, point) = (*c.first()?, *c.get(1)?);
            est_la_cle(Path::new(&sans_echappements(point)))
                .then(|| disque_de_la_partition(source))
                .flatten()
        })
        .collect();
    let mut liste = Vec::new();
    for l in montages.lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let [source, point, genre, options, ..] = c[..] else {
            continue;
        };
        if disque_de_la_partition(source).is_some_and(|d| de_la_cle.contains(&d)) {
            continue;
        }
        let point = PathBuf::from(sans_echappements(point));
        let monte_pour_l_utilisateur = ["/run/media/", "/media/", "/mnt/"]
            .iter()
            .any(|d| point.starts_with(d) && point.as_os_str().len() > d.len());
        if monte_pour_l_utilisateur
            && SYSTEMES.contains(&genre)
            && !options.split(',').any(|o| o == "ro")
            && !est_la_cle(&point)
            && sur_le_systeme(&point) == Some(false)
            && let Some((libre, total)) = crate::socle::volume(&point)
        {
            // Le nom d'un disque vient de son étiquette, choisie par qui l'a formaté : lu prêt à montrer.
            let nom = affichable(&point.file_name().unwrap_or_default().to_string_lossy());
            liste.push(Disque {
                racine: point,
                nom,
                libre,
                total,
            });
        }
    }
    liste
}

/// Linux : le disque qui porte une partition (« /dev/sda5 » → « sda », « /dev/nvme0n1p1 » → « nvme0n1 »), d'après
/// /sys/class/block ; un périphérique sans partition est son propre disque.
#[cfg(target_os = "linux")]
fn disque_de_la_partition(source: &str) -> Option<String> {
    let nom = Path::new(source)
        .canonicalize()
        .ok()?
        .file_name()?
        .to_string_lossy()
        .into_owned();
    let sys = Path::new("/sys/class/block").join(&nom);
    if sys.join("partition").exists() {
        let parent = std::fs::canonicalize(&sys)
            .ok()?
            .parent()?
            .file_name()?
            .to_string_lossy()
            .into_owned();
        Some(parent)
    } else {
        sys.exists().then_some(nom)
    }
}

/// macOS : « /dev/disk4s1 on /Volumes/VANGUARD (…) » (sortie de mount) → (point de montage, « disk4 »).
#[cfg(any(target_os = "macos", test))]
fn disques_de_mount(sortie: &str) -> Vec<(PathBuf, String)> {
    sortie
        .lines()
        .filter_map(|l| {
            let (source, reste) = l.split_once(" on ")?;
            let point = reste.rsplit_once(" (")?.0;
            let nom = source.strip_prefix("/dev/")?;
            // « disk4s1 » → « disk4 » : le dernier « s » suivi de chiffres est la partition.
            let disque = match nom.rfind('s') {
                Some(i) if i > 4 && nom[i + 1..].chars().all(|c| c.is_ascii_digit()) && i + 1 < nom.len() => &nom[..i],
                _ => nom,
            };
            Some((PathBuf::from(point), disque.to_string()))
        })
        .collect()
}

#[cfg(target_os = "macos")]
pub(crate) fn disques() -> Vec<Disque> {
    use std::os::unix::fs::MetadataExt;
    let systeme = std::fs::metadata("/").ok().map(|m| m.dev());
    // Les autres partitions de la clé VANGUARD (MACOS…), sur le même support qu'elle : exclues aussi.
    let montages = crate::commande::lancer(&mut std::process::Command::new("mount"), 10)
        .map(|r| disques_de_mount(&r.sortie))
        .unwrap_or_default();
    let de_la_cle: Vec<&String> = montages
        .iter()
        .filter(|(point, _)| est_la_cle(point))
        .map(|(_, d)| d)
        .collect();
    let sur_la_cle = |racine: &Path| {
        montages
            .iter()
            .any(|(point, d)| point == racine && de_la_cle.contains(&d))
    };
    std::fs::read_dir("/Volumes")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let (racine, nom) = (e.path(), e.file_name().to_string_lossy().into_owned());
            let dev = std::fs::metadata(&racine).ok()?.dev();
            if Some(dev) == systeme || nom.starts_with("com.apple.") || est_la_cle(&racine) || sur_la_cle(&racine) {
                return None;
            }
            let (libre, total) = crate::socle::volume(&racine)?;
            Some(Disque {
                racine,
                nom: affichable(&nom),
                libre,
                total,
            })
        })
        .collect()
}

/// Windows : les lecteurs prêts, amovibles ou fixes, sauf celui du système et la clé.
#[cfg(windows)]
pub(crate) fn disques() -> Vec<Disque> {
    // Lus par kernel32 ; PowerShell seulement si la liste revient vide (le lecteur du système y est toujours).
    let natifs: Vec<String> = crate::machine::windows::lecteurs::lecteurs()
        .iter()
        .map(|l| {
            let disque = l.disque.map(|n| n.to_string()).unwrap_or_default();
            let etiquette = l.etiquette.replace('|', " ");
            format!("{}|{etiquette}|{}|{}|{disque}", l.racine.display(), l.libre, l.total)
        })
        .collect();
    let lecteurs = if natifs.is_empty() {
        crate::machine::windows::ps(
            "[IO.DriveInfo]::GetDrives() | Where-Object { $_.IsReady -and ($_.DriveType -eq 'Removable' -or $_.DriveType -eq 'Fixed') } | \
             ForEach-Object { $n = (Get-Partition -DriveLetter $_.Name[0] -ErrorAction SilentlyContinue).DiskNumber; \
             \"$($_.Name)|$($_.VolumeLabel)|$($_.AvailableFreeSpace)|$($_.TotalSize)|$n\" }",
        )
    } else {
        Some(natifs.join("\n"))
    };
    let texte = lecteurs.unwrap_or_default();
    let systeme = std::env::var("SystemDrive").map_or("C:".into(), |s| s.to_uppercase());
    let mut liste = lire_lecteurs(&texte, &systeme);
    // Les autres partitions de la clé VANGUARD (WIN11…) sont sur le même disque qu'elle : exclues aussi.
    let numeros = disques_des_lecteurs(&texte);
    let numero = |d: &Disque| numeros.iter().find(|(r, _)| *r == d.racine).map(|(_, n)| n.clone());
    let de_la_cle: Vec<String> = liste
        .iter()
        .filter(|d| est_la_cle(&d.racine))
        .filter_map(numero)
        .collect();
    liste.retain(|d| !est_la_cle(&d.racine) && !numero(d).is_some_and(|n| de_la_cle.contains(&n)));
    liste
}

/// Windows : (lecteur, numéro de son disque) d'après le 5e champ des lignes de `disques`.
#[cfg(any(windows, test))]
fn disques_des_lecteurs(texte: &str) -> Vec<(PathBuf, String)> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.trim().split('|').collect();
            let numero = c.get(4)?.trim();
            (!numero.is_empty()).then(|| (PathBuf::from(c[0]), numero.to_string()))
        })
        .collect()
}

/// « E:\|Sauvegarde|1000|2000 » par ligne, sans le lecteur du système (« C: »).
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_lecteurs(texte: &str, systeme: &str) -> Vec<Disque> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.trim().split('|').collect();
            let [racine, etiquette, libre, total, ..] = c[..] else {
                return None;
            };
            let lettre = racine.trim_end_matches('\\');
            if lettre.to_uppercase() == systeme.trim_end_matches('\\') {
                return None;
            }
            Some(Disque {
                racine: PathBuf::from(racine),
                nom: affichable(&match etiquette {
                    "" => lettre.to_string(),
                    _ => format!("{etiquette} ({lettre})"),
                }),
                libre: libre.parse().ok()?,
                total: total.parse().ok()?,
            })
        })
        .collect()
}

/// Nombre de fichiers et octets d'un dossier, sous-dossiers compris, sans suivre les liens. Les octets sont plafonnés
/// à `u64::MAX` : quelques fichiers creux, qui annoncent des exaoctets sans rien occuper, feraient paniquer la somme
/// dans la version publiée (`nettoyer::somme`).
fn mesurer(dossier: &Path) -> (u64, u64) {
    let (mut fichiers, mut octets) = (0, 0_u64);
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let Ok(m) = e.path().symlink_metadata() else { continue };
            if m.is_dir() {
                a_voir.push(e.path());
            } else if m.is_file() {
                fichiers += 1;
                octets = octets.saturating_add(m.len());
            }
        }
    }
    (fichiers, octets)
}

/// Ce qui s'est passé pendant la copie.
#[derive(Default, Debug)]
pub struct Bilan {
    pub copies: u64,
    /// Déjà sur le disque, à l'identique (reprise) : pas recopiés.
    pub deja: u64,
    pub octets: u64,
    /// Copiés sous un autre nom : (original, copie). Un fichier différent occupait déjà la place, ou le nom n'est pas
    /// permis sur ce disque (« : » sur un disque formaté pour Windows).
    pub renommes: Vec<(PathBuf, PathBuf)>,
    pub echecs: Vec<(PathBuf, String)>,
    /// Liens symboliques : ce sont des raccourcis, pas des fichiers ; non copiés.
    pub liens: u64,
}

/// Affichage de l'avancement, au plus deux fois par seconde (seulement dans un vrai terminal).
struct Avancement {
    total_fichiers: u64,
    total_octets: u64,
    fichiers: u64,
    octets: u64,
    debut: Instant,
    dernier: Instant,
    terminal: bool,
}

impl Avancement {
    /// `fin` : le dernier affichage, toujours montré, qui termine la ligne.
    fn montrer(&mut self, fin: bool) {
        if !self.terminal || (!fin && self.dernier.elapsed() < Duration::from_millis(500)) {
            return;
        }
        self.dernier = Instant::now();
        #[allow(clippy::cast_precision_loss)]
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let debit = taille_lisible((self.octets as f64 / self.debut.elapsed().as_secs_f64().max(0.1)) as u64);
        let texte = trf!(
            "{} / {} fichiers · {} / {} · {debit}/s",
            "{} / {} files · {} / {} · {debit}/s",
            self.fichiers,
            self.total_fichiers,
            taille_lisible(self.octets),
            taille_lisible(self.total_octets)
        );
        print!("\r  {texte}\x1b[K{}", if fin { "\n" } else { "" });
        let _ = std::io::stdout().flush();
    }
}

/// Un nom permis partout (FAT, exFAT, NTFS) : les caractères interdits par Windows remplacés par « _ », sans point
/// ni espace à la fin.
fn nom_permis(nom: &str) -> String {
    let propre = nom.replace(|c: char| c.is_control() || "<>:\"/\\|?*".contains(c), "_");
    let propre = propre.trim_end_matches(['.', ' ']);
    if propre.is_empty() { "_".into() } else { propre.into() }
}

/// « photo.jpg » → « photo (2).jpg », « photo (3).jpg »… : le premier nom libre du dossier.
fn nom_libre(dossier: &Path, nom: &str) -> PathBuf {
    let (base, extension) = match nom.rsplit_once('.') {
        Some((base, extension)) if !base.is_empty() => (base, format!(".{extension}")),
        _ => (nom, String::new()),
    };
    (2..=9999)
        .map(|n| dossier.join(format!("{base} ({n}){extension}")))
        .find(|p| std::fs::symlink_metadata(p).is_err())
        .unwrap_or_else(|| dossier.join(nom))
}

pub(crate) fn empreinte(chemin: &Path) -> std::io::Result<blake3::Hash> {
    Ok(blake3::Hasher::new().update_reader(File::open(chemin)?)?.finalize())
}

/// L'empreinte relue sur le disque, pas dans la mémoire où la copie vient de passer : sans cela, une erreur
/// d'écriture du disque passerait inaperçue. Linux : les pages du fichier, propres après `sync_all`, sont retirées du
/// cache avant de lire ; macOS : lecture sans cache. Windows : voir l'autre version, juste en dessous.
#[cfg(not(windows))]
pub(crate) fn empreinte_relue(chemin: &Path) -> std::io::Result<blake3::Hash> {
    let f = File::open(chemin)?;
    sans_cache(&f);
    Ok(blake3::Hasher::new().update_reader(f)?.finalize())
}

/// Windows n'a pas de conseil « retire ces pages du cache » : une lecture ordinaire rendrait les pages que la copie
/// vient d'y laisser, identiques à l'original même si la clé (capacité truquée, disque qui perd des écritures) a
/// gardé n'importe quoi. Le fichier est donc ouvert sans mise en mémoire (`FILE_FLAG_NO_BUFFERING`), ce qui oblige
/// à lire dans un tampon aligné, par tailles et à des positions multiples du secteur : des blocs de 1 Mio, multiples
/// de tout secteur réel, le dernier rendant seulement ce qui reste.
#[cfg(windows)]
pub(crate) fn empreinte_relue(chemin: &Path) -> std::io::Result<blake3::Hash> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_NO_BUFFERING)
        .open(chemin)?;
    let taille = f.metadata()?.len();
    let mut memoire = vec![0u8; BLOC_RELU + ALIGNEMENT_RELU];
    let debut = memoire.as_ptr().align_offset(ALIGNEMENT_RELU);
    let tampon = &mut memoire[debut..debut + BLOC_RELU];
    let mut h = blake3::Hasher::new();
    let mut lu = 0u64;
    while lu < taille {
        let n = f.read(tampon)?;
        if n == 0 {
            // Plus court que sa taille annoncée : l'empreinte diffère, la copie est vue abîmée.
            break;
        }
        lu += n as u64;
        // Une lecture courte avant la fin laisserait la suivante à une position que Windows refuse sans cache :
        // mieux vaut le dire que de relire ce morceau par le cache et le croire vérifié.
        if n % ALIGNEMENT_RELU != 0 && lu < taille {
            return Err(std::io::Error::other(tr!(
                "relecture sans cache interrompue au milieu du fichier",
                "uncached read-back stopped in the middle of the file"
            )));
        }
        h.update(&tampon[..n]);
    }
    Ok(h.finalize())
}

/// Lecture sans cache de Windows : taille de chaque lecture, et alignement de l'adresse du tampon. 4 Kio couvre les
/// secteurs de 512 octets comme ceux de 4 Kio ; 1 Mio en est un multiple.
#[cfg(windows)]
const BLOC_RELU: usize = 1 << 20;
#[cfg(windows)]
const ALIGNEMENT_RELU: usize = 4096;

#[cfg(target_os = "linux")]
pub(crate) fn sans_cache(f: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY : un descripteur ouvert, gardé par `f` pendant l'appel ; posix_fadvise ne fait que conseiller le noyau
    // (retirer du cache les pages propres du fichier) et n'écrit dans aucune mémoire de ce programme.
    unsafe {
        libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn sans_cache(f: &File) {
    use std::os::fd::AsRawFd;
    // SAFETY : un descripteur ouvert, gardé par `f` pendant l'appel ; F_NOCACHE change seulement la façon dont le
    // système lit ce fichier, sans toucher à la mémoire de ce programme.
    unsafe {
        libc::fcntl(f.as_raw_fd(), libc::F_NOCACHE, 1);
    }
}

#[cfg(windows)]
pub(crate) fn sans_cache(_: &File) {}

/// Copie `source` vers `cible` (qui n'existe pas) en passant par un fichier partiel, puis vérifie.
fn copier_vers(source: &Path, cible: &Path) -> std::io::Result<()> {
    let nom = cible.file_name().unwrap_or_default().to_string_lossy();
    // Le partiel porte un nom court tiré du vrai : « .<nom>.vanguard-partiel » dépassait 255 octets pour un nom long.
    let partiel = cible.with_file_name(format!(".{}{PARTIEL}", &blake3::hash(nom.as_bytes()).to_hex()[..16]));
    // Un partiel laissé par une copie interrompue est à nous : on le remplace, et celui des versions d'avant
    // (« .<nom>.vanguard-partiel ») ne reste pas en plan.
    let _ = std::fs::remove_file(&partiel);
    let _ = std::fs::remove_file(cible.with_file_name(format!(".{nom}{PARTIEL}")));
    let mut entree = File::open(source)?;
    let mut sortie = OpenOptions::new().write(true).create_new(true).open(&partiel)?;
    // Le partiel se ferme à la fin de l'écriture, réussie ou non : il peut alors être renommé ou retiré.
    let ecrit = (move || -> std::io::Result<blake3::Hash> {
        let (mut h, mut tampon) = (blake3::Hasher::new(), vec![0u8; 1 << 20]);
        loop {
            let n = entree.read(&mut tampon)?;
            if n == 0 {
                break;
            }
            h.update(&tampon[..n]);
            sortie.write_all(&tampon[..n])?;
        }
        // Sur le disque, pas seulement en mémoire : un disque débranché juste après ne doit rien perdre.
        sortie.sync_all()?;
        if let Ok(date) = std::fs::metadata(source).and_then(|m| m.modified()) {
            let _ = sortie.set_modified(date);
        }
        // Personne n'a pris la place entre-temps : sinon, renommer l'écraserait.
        if std::fs::symlink_metadata(cible).is_ok() {
            return Err(std::io::Error::new(ErrorKind::AlreadyExists, "occupé"));
        }
        Ok(h.finalize())
    })();
    let original = ecrit.inspect_err(|_| {
        let _ = std::fs::remove_file(&partiel);
    })?;
    std::fs::rename(&partiel, cible)?;
    // Relue sur le disque : une copie différente de l'original n'est pas gardée.
    if empreinte_relue(cible)? != original {
        let _ = std::fs::remove_file(cible);
        return Err(std::io::Error::other(tr!(
            "la copie relue diffère de l'original",
            "the copy read back differs from the original"
        )));
    }
    Ok(())
}

/// `copie` est-elle `source`, à l'identique (taille, puis empreinte) ?
fn identiques(copie: &Path, source: &Path) -> bool {
    let taille = std::fs::metadata(source).map_or(u64::MAX, |s| s.len());
    std::fs::symlink_metadata(copie).is_ok_and(|m| m.is_file() && m.len() == taille)
        && matches!((empreinte(copie), empreinte(source)), (Ok(a), Ok(b)) if a == b)
}

/// Un fichier : déjà là à l'identique (rien à faire), ou copié, sous son nom ou un autre.
fn copier_fichier(source: &Path, dossier: &Path, bilan: &mut Bilan) {
    let nom = source.file_name().unwrap_or_default().to_string_lossy();
    let mut cible = dossier.join(&*nom);
    if std::fs::symlink_metadata(&cible).is_ok() {
        // Sous son nom, ou sous un autre nom pris lors d'une copie interrompue (« photo (2).jpg ») : déjà là.
        let (base, extension) = match nom.rsplit_once('.') {
            Some((base, extension)) if !base.is_empty() => (base, format!(".{extension}")),
            _ => (&*nom, String::new()),
        };
        let deja_copie = std::iter::once(cible.clone())
            .chain((2..=9999).map(|n| dossier.join(format!("{base} ({n}){extension}"))))
            .take_while(|p| std::fs::symlink_metadata(p).is_ok())
            .any(|p| identiques(&p, source));
        if deja_copie {
            bilan.deja += 1;
            bilan.octets = bilan
                .octets
                .saturating_add(std::fs::metadata(source).map_or(0, |m| m.len()));
            return;
        }
        cible = nom_libre(dossier, &nom);
    }
    let mut essai = copier_vers(source, &cible);
    // Nom refusé par ce disque (« : », « ? » sur un disque formaté pour Windows) : un nom permis partout.
    let permis = nom_permis(&nom);
    if let Err(e) = &essai
        && matches!(e.kind(), ErrorKind::InvalidInput | ErrorKind::InvalidFilename)
        && permis != nom
    {
        cible = dossier.join(&permis);
        if std::fs::symlink_metadata(&cible).is_ok() {
            cible = nom_libre(dossier, &permis);
        }
        essai = copier_vers(source, &cible);
    }
    match essai {
        Ok(()) => {
            bilan.copies += 1;
            bilan.octets = bilan
                .octets
                .saturating_add(std::fs::metadata(&cible).map_or(0, |m| m.len()));
            if cible.file_name() != source.file_name() {
                bilan.renommes.push((source.to_path_buf(), cible));
            }
        }
        Err(e) => bilan.echecs.push((source.to_path_buf(), e.to_string())),
    }
}

fn copier_arbre(source: &Path, cible: &Path, bilan: &mut Bilan, avancement: &mut Avancement) {
    let mut a_voir = vec![(source.to_path_buf(), cible.to_path_buf())];
    while let Some((de, vers)) = a_voir.pop() {
        let entrees = std::fs::create_dir_all(&vers).and_then(|()| std::fs::read_dir(&de));
        let Ok(entrees) = entrees.inspect_err(|e| bilan.echecs.push((de, e.to_string()))) else {
            continue;
        };
        for e in entrees.flatten() {
            let chemin = e.path();
            let Ok(m) = chemin.symlink_metadata() else { continue };
            if m.is_symlink() {
                bilan.liens += 1;
            } else if m.is_dir() {
                a_voir.push((chemin, vers.join(nom_permis(&e.file_name().to_string_lossy()))));
            } else if m.is_file() {
                copier_fichier(&chemin, &vers, bilan);
                avancement.fichiers += 1;
                avancement.octets = avancement.octets.saturating_add(m.len());
                avancement.montrer(false);
            }
        }
    }
}

/// Le dossier daté où copier : celui d'une copie interrompue à reprendre (le plus récent), sinon un nouveau.
fn dossier_de_copie(racine: &Path, reprendre: impl Fn(&str) -> bool) -> PathBuf {
    let interrompue = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let nom = p.file_name().unwrap_or_default().to_string_lossy();
            de_copie(&nom) && crate::passage::les_deux(TEMOIN).iter().any(|t| p.join(t).is_file())
        })
        .max()
        .filter(|d| reprendre(&d.file_name().unwrap_or_default().to_string_lossy()));
    if let Some(d) = interrompue {
        // Interrompue sous l'ancien nom (`passage`) : son témoin prend le nouveau, que la fin de la copie retire.
        let _ = std::fs::rename(d.join(crate::passage::ancien(TEMOIN)), d.join(TEMOIN));
        return d;
    }
    let date = chrono::Local::now().format("%Y-%m-%d");
    let base = trf!("Vanguard-copie-{}", "Vanguard-copy-{}", date);
    std::iter::once(racine.join(&base))
        .chain((2..=999).map(|n| racine.join(format!("{base}-{n}"))))
        .find(|d| std::fs::symlink_metadata(d).is_err())
        .unwrap_or_else(|| racine.join(base))
}

fn copier(choisis: &[(Sorte, PathBuf)], dossier: &Path, total: (u64, u64)) -> Bilan {
    let mut bilan = Bilan::default();
    let mut avancement = Avancement {
        total_fichiers: total.0,
        total_octets: total.1,
        fichiers: 0,
        octets: 0,
        debut: Instant::now(),
        dernier: Instant::now(),
        terminal: std::io::stdout().is_terminal(),
    };
    if let Err(e) = std::fs::create_dir_all(dossier)
        .and_then(|()| std::fs::write(dossier.join(TEMOIN), chrono::Local::now().to_rfc3339()))
    {
        bilan.echecs.push((dossier.to_path_buf(), e.to_string()));
        return bilan;
    }
    for (sorte, source) in choisis {
        let nom = source.file_name().map_or(sorte.nom().into(), |n| n.to_string_lossy());
        copier_arbre(source, &dossier.join(nom_permis(&nom)), &mut bilan, &mut avancement);
    }
    avancement.montrer(true);
    let _ = std::fs::write(dossier.join(COMPTE_RENDU), compte_rendu(choisis, &bilan));
    // Tout est copié : la copie n'est plus « en cours ». Avec des échecs, le témoin reste, pour réessayer.
    if bilan.echecs.is_empty() {
        let _ = std::fs::remove_file(dossier.join(TEMOIN));
    }
    bilan
}

fn compte_rendu(choisis: &[(Sorte, PathBuf)], b: &Bilan) -> String {
    use std::fmt::Write as _;
    let mut t = format!(
        "{} — Vanguard {} — {}\n\n",
        tr!("Copie de fichiers", "File copy"),
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d %H:%M")
    );
    for (s, chemin) in choisis {
        let _ = writeln!(t, "{} : {}", s.nom(), chemin.display());
    }
    let resume = trf!(
        "{} fichier(s) copié(s), {} déjà présent(s) à l'identique, {} lien(s) non copié(s), {} échec(s).",
        "{} file(s) copied, {} already there unchanged, {} link(s) not copied, {} failure(s).",
        b.copies,
        b.deja,
        b.liens,
        b.echecs.len()
    );
    let _ = writeln!(t, "\n{resume}");
    let autre_nom = tr!("Autre nom", "Other name");
    for (de, vers) in &b.renommes {
        let _ = writeln!(t, "{autre_nom} : {} → {}", de.display(), vers.display());
    }
    for (chemin, erreur) in &b.echecs {
        let _ = writeln!(t, "{} : {} ({erreur})", tr!("Échec", "Failed"), chemin.display());
    }
    t
}

/// Le chemin désigné en ligne de commande, s'il est un dossier d'un autre disque que celui du système (et pas la
/// clé, ni l'un des dossiers copiés : la copie s'y copierait elle-même).
fn destination_permise(chemin: &Path, sources: &[(Sorte, PathBuf)]) -> Result<PathBuf, String> {
    let chemin = chemin
        .canonicalize()
        .map_err(|e| trf!("{} : {e}", "{}: {e}", chemin_affichable(chemin)))?;
    if !chemin.is_dir() {
        let dossier = chemin_affichable(&chemin);
        return Err(trf!("{} n'est pas un dossier.", "{} is not a folder.", dossier));
    }
    let refus = if chemin.ancestors().any(est_la_cle) {
        tr!(
            "La clé VANGUARD n'est pas un disque de copie.",
            "The VANGUARD key is not a copy disk."
        )
    } else if sources
        .iter()
        .any(|(_, s)| s.canonicalize().is_ok_and(|s| chemin.starts_with(s)))
    {
        tr!(
            "Ce dossier est dans un des dossiers à copier.",
            "This folder is inside one of the folders to copy."
        )
    } else if sur_le_systeme(&chemin) == Some(true) {
        tr!(
            "Ce dossier est sur le disque du système : une copie n'y protège de rien.",
            "This folder is on the system disk: a copy there protects from nothing."
        )
    } else {
        return Ok(chemin);
    };
    Err(refus.into())
}

/// `chemin` est-il sur le lecteur `racine` (« E:\ ») ? Une destination tapée en ligne de commande sort de
/// `canonicalize` en forme étendue (« \\?\E:\Sauvegarde ») : `Path::starts_with` compare les préfixes tels quels, et
/// « \\?\E: » n'y vaut pas « E: », si bien qu'aucun disque ne correspondait et que la place libre n'était jamais
/// vérifiée. La lettre, elle, est la même sous les deux formes.
#[cfg(windows)]
fn meme_lecteur(chemin: &Path, racine: &Path) -> bool {
    use std::path::{Component, Prefix};
    let lettre = |p: &Path| match p.components().next() {
        Some(Component::Prefix(x)) => match x.kind() {
            Prefix::Disk(l) | Prefix::VerbatimDisk(l) => Some(l.to_ascii_uppercase()),
            _ => None,
        },
        _ => None,
    };
    lettre(chemin).is_some_and(|l| lettre(racine) == Some(l))
}

fn choisir_disque() -> Option<PathBuf> {
    let liste = disques();
    if liste.is_empty() {
        let aucun = tr!(
            "Aucun disque externe branché (la clé VANGUARD et le disque du système ne comptent pas). Branchez un disque ou une clé assez grande, attendez qu'il apparaisse, puis recommencez.",
            "No external disk plugged in (the VANGUARD key and the system disk do not count). Plug in a large enough disk or USB stick, wait for it to appear, then start again."
        );
        afficher_aligne("  ✖ ", aucun, 4, "");
        return None;
    }
    let mut lignes = vec![
        Ligne::Texte(String::new()),
        Ligne::Texte(ligne_section(tr!("OÙ COPIER", "WHERE TO COPY"))),
    ];
    for (i, d) in liste.iter().enumerate() {
        let (libre, total) = (taille_lisible(d.libre), taille_lisible(d.total));
        let place = trf!("{} libres sur {}", "{} free out of {}", libre, total);
        lignes.push(Ligne::choix(&(i + 1).to_string(), &d.nom, &place));
    }
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let invite = tr!(
        "  Numéro du disque (Entrée pour revenir) : ",
        "  Disk number (Enter to go back): "
    );
    let choix = choisir(&lignes, invite, "1", tr!("revenir", "back"))?;
    let i = choix.trim().parse::<usize>().ok()?.checked_sub(1)?;
    liste.into_iter().nth(i).map(|d| d.racine)
}

/// « vanguard copier-fichiers [destination] » ; sans destination, le disque se choisit parmi ceux qui sont branchés.
pub fn commande(destination: Option<&Path>) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("COPIER MES FICHIERS", "COPY MY FILES")),
        &format!("{GRIS}{}{RESET}", tr!("rien n'est effacé", "nothing is deleted")),
    );
    let sources = sources();
    if sources.is_empty() {
        trp!(
            "  Aucun dossier personnel trouvé (Documents, Images…).",
            "  No personal folder found (Documents, Pictures…)."
        );
        return;
    }
    let racine = match destination.map(|d| destination_permise(d, &sources)) {
        None => choisir_disque(),
        Some(permise) => permise.inspect_err(|e| println!("  ✖ {e}")).ok(),
    };
    let Some(racine) = racine else { return };
    trp!(
        "  {DISCRET}Mesure des dossiers…{RESET}",
        "  {DISCRET}Measuring the folders…{RESET}"
    );
    let mesures: Vec<(u64, u64)> = sources.iter().map(|(_, c)| mesurer(c)).collect();
    let cases: Vec<Case> = sources
        .iter()
        .zip(&mesures)
        .map(|((s, chemin), &(n, octets))| Case {
            texte: s.nom().to_string(),
            precision: trf!("{} · {n} fichier(s)", "{} · {n} file(s)", taille_lisible(octets)),
            detail: chemin_affichable(chemin),
            cochee: n > 0,
            recommandee: n > 0,
            fixe: false,
        })
        .collect();
    let entete = [
        String::new(),
        ligne_titre(tr!("Quels dossiers copier ?", "Which folders to copy?")),
        trf!(
            "  {GRIS}Vers : {}{RESET}",
            "  {GRIS}To: {}{RESET}",
            chemin_affichable(&racine)
        ),
        String::new(),
    ];
    let Some(coches) = cocher(&entete, &cases) else { return };
    let (choisis, tailles): (Vec<_>, Vec<(u64, u64)>) = sources
        .into_iter()
        .zip(mesures)
        .zip(coches)
        .filter_map(|(choisi, coche)| coche.then_some(choisi))
        .unzip();
    let total = tailles.iter().fold((0_u64, 0_u64), |(n, o), (f, b)| {
        (n.saturating_add(*f), o.saturating_add(*b))
    });
    if choisis.is_empty() {
        trp!("  Rien à copier.", "  Nothing to copy.");
        return;
    }
    let dossier = dossier_de_copie(&racine, |nom| {
        // Un dossier du disque de destination, qui peut être celui de n'importe qui.
        let nom = affichable(nom);
        demander(&trf!(
            "\n  Une copie commencée n'est pas finie ({nom}). La reprendre ? [O/n] : ",
            "\n  A started copy is not finished ({nom}). Resume it? [Y/n]: "
        ))
        .chars()
        .next()
        .is_none_or(|c| matches!(c, 'o' | 'O' | 'y' | 'Y'))
    });
    // En reprise, ce qui est déjà copié ne reprend pas de place.
    let deja = if dossier.is_dir() { mesurer(&dossier).1 } else { 0 };
    #[cfg(unix)]
    let libre = crate::socle::volume(&racine).map(|(libre, _)| libre);
    #[cfg(windows)]
    let libre = disques()
        .into_iter()
        .find(|d| meme_lecteur(&racine, &d.racine))
        .map(|d| d.libre);
    let besoin = total.1.saturating_sub(deja);
    if libre.is_none() {
        // Sans la place libre, la copie se lance quand même (le disque plein se verra en échecs), mais pas en silence.
        trp!(
            "\n  ⚠ La place libre de ce disque ne se lit pas : elle n'a pas pu être comparée aux {} à copier.",
            "\n  ⚠ This disk's free space cannot be read: it could not be compared with the {} to copy.",
            taille_lisible(besoin)
        );
    }
    if let Some(libre) = libre
        && besoin > libre
    {
        trp!(
            "\n  ✖ Pas assez de place : il faut {}, le disque n'a que {} de libre. Décochez des dossiers, ou prenez un disque plus grand.",
            "\n  ✖ Not enough space: {} needed, the disk only has {} free. Uncheck some folders, or use a larger disk.",
            taille_lisible(besoin),
            taille_lisible(libre)
        );
        return;
    }
    trp!(
        "\n  {} fichier(s), {} → {}",
        "\n  {} file(s), {} → {}",
        total.0,
        taille_lisible(total.1),
        chemin_affichable(&dossier)
    );
    if genre_du_volume(&racine).is_some_and(|g| limite_4_go(&g)) {
        let gros = gros_fichiers(&choisis);
        if let Some(exemple) = gros.first() {
            afficher_aligne(
                "  ⚠ ",
                &trf!(
                    "{} fichier(s) de 4 Go ou plus (dont {}) : ce disque, en FAT32, ne peut pas les recevoir ; ils iront dans les échecs. Un disque en exFAT ou NTFS les accepte.",
                    "{} file(s) of 4 GB or more (including {}): this disk, in FAT32, cannot hold them; they will end up in the failures. A disk in exFAT or NTFS accepts them.",
                    gros.len(),
                    chemin_affichable(exemple)
                ),
                4,
                "",
            );
        }
    }
    if !demander(tr!("  Copier ? [o/N] : ", "  Copy? [y/N]: ")).oui() {
        trp!("  Annulé.", "  Cancelled.");
        return;
    }
    let debut = Instant::now();
    afficher_bilan(&copier(&choisis, &dossier, total), &dossier, debut.elapsed());
}

fn afficher_bilan(b: &Bilan, dossier: &Path, duree: Duration) {
    println!();
    if b.echecs.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Copie terminée et vérifiée : {} fichier(s) copié(s), {} déjà là à l'identique, {} en {} s.",
            "  {VERT}✔{RESET} Copy finished and checked: {} file(s) copied, {} already there unchanged, {} in {} s.",
            b.copies,
            b.deja,
            taille_lisible(b.octets),
            duree.as_secs()
        );
    } else {
        trp!(
            "  ⚠ Copie terminée avec {} échec(s) : {} fichier(s) copié(s), {} déjà là. Relancez la copie pour réessayer les fichiers ratés.",
            "  ⚠ Copy finished with {} failure(s): {} file(s) copied, {} already there. Run the copy again to retry the failed files.",
            b.echecs.len(),
            b.copies,
            b.deja
        );
        for (chemin, erreur) in b.echecs.iter().take(5) {
            afficher_aligne("    ✖ ", &format!("{} ({erreur})", chemin_affichable(chemin)), 6, GRIS);
        }
    }
    if !b.renommes.is_empty() {
        trp!(
            "  {} fichier(s) copié(s) sous un autre nom (place déjà prise, ou nom refusé par ce disque) : voir {COMPTE_RENDU}.",
            "  {} file(s) copied under another name (place already taken, or name refused by this disk): see {COMPTE_RENDU}.",
            b.renommes.len()
        );
    }
    if b.liens > 0 {
        trp!(
            "  {GRIS}{} raccourci(s) (liens) non copié(s) : ce ne sont pas des fichiers.{RESET}",
            "  {GRIS}{} shortcut(s) (links) not copied: they are not files.{RESET}",
            b.liens
        );
    }
    trp!(
        "  {GRIS}Dans : {}{RESET}",
        "  {GRIS}In: {}{RESET}",
        chemin_affichable(dossier)
    );
}

pub fn menu() {
    commande(None);
}

// ───────────────────────────── Vérifier une copie (test de restauration) ─────────────────────────────

/// Combien de fichiers relire : assez pour voir un disque qui perd des données, sans relire des heures de vidéos.
const ECHANTILLON: usize = 40;

/// Le résultat d'une relecture.
#[derive(Debug, Default, PartialEq, Eq)]
struct Relecture {
    identiques: usize,
    /// L'original a changé depuis la copie (normal pour un document qu'on continue d'écrire).
    modifies_depuis: usize,
    /// Plus d'original à comparer (supprimé ou déplacé depuis) : la copie, elle, s'est relue.
    sans_original: usize,
    /// La copie diffère de l'original sans qu'il ait changé, ou ne se relit pas : le disque perd des données.
    abimes: Vec<(PathBuf, String)>,
}

/// Les dossiers copiés, d'après le compte rendu : (nom du sous-dossier dans la copie, dossier d'origine).
fn sources_du_compte_rendu(texte: &str) -> Vec<(String, PathBuf)> {
    texte
        .lines()
        .skip(2)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let (_, chemin) = l.split_once(" : ")?;
            let chemin = PathBuf::from(chemin.trim());
            let nom = nom_permis(&chemin.file_name()?.to_string_lossy());
            Some((nom, chemin))
        })
        .collect()
}

/// Un fichier plus gros n'entre pas dans l'échantillon : relu deux fois (copie sans cache, puis original), une image
/// de machine virtuelle de 40 Go prendrait une heure sur une clé lente. Il est compté, et le nombre est dit.
const TAILLE_RELUE_MAX: u64 = 1 << 30;

/// Les fichiers d'une copie (sans le compte rendu, le témoin ni un fichier partiel), relatifs à son dossier, et
/// combien de gros fichiers (plus de `TAILLE_RELUE_MAX`) ont été laissés de côté.
fn fichiers_de_la_copie(dossier: &Path) -> (Vec<PathBuf>, usize) {
    let mut trouves = Vec::new();
    let mut gros = 0;
    let mut a_voir = vec![PathBuf::new()];
    while let Some(relatif) = a_voir.pop() {
        for e in std::fs::read_dir(dossier.join(&relatif))
            .into_iter()
            .flatten()
            .flatten()
        {
            let nom = e.file_name().to_string_lossy().into_owned();
            let chemin = relatif.join(&nom);
            let Ok(meta) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if meta.is_dir() {
                a_voir.push(chemin);
            } else if meta.is_file()
                && !(relatif.as_os_str().is_empty()
                    && [COMPTE_RENDU, TEMOIN]
                        .iter()
                        .any(|f| crate::passage::les_deux(f).contains(&nom)))
                && !crate::passage::les_deux(PARTIEL)
                    .iter()
                    .any(|p| nom.ends_with(p.as_str()))
            {
                if meta.len() > TAILLE_RELUE_MAX {
                    gros += 1;
                } else {
                    trouves.push(chemin);
                }
            }
            if trouves.len() >= 200_000 {
                return (trouves, gros);
            }
        }
    }
    trouves.sort();
    (trouves, gros)
}

/// Au plus `n` fichiers répartis sur toute la copie (le premier, le dernier, et à intervalles réguliers entre).
pub(crate) fn echantillon(fichiers: &[PathBuf], n: usize) -> Vec<&PathBuf> {
    if fichiers.len() <= n {
        return fichiers.iter().collect();
    }
    (0..n).map(|i| &fichiers[i * (fichiers.len() - 1) / (n - 1)]).collect()
}

/// Relit les fichiers choisis de la copie, en contournant le cache, et compare chacun à son original.
fn relire(
    dossier: &Path,
    choisis: &[&PathBuf],
    sources: &[(String, PathBuf)],
    copie_le: std::time::SystemTime,
) -> Relecture {
    let mut r = Relecture::default();
    for relatif in choisis {
        let copie = dossier.join(relatif);
        let relue = match empreinte_relue(&copie) {
            Ok(h) => h,
            Err(e) => {
                r.abimes.push(((*relatif).clone(), e.to_string()));
                continue;
            }
        };
        let mut morceaux = relatif.components();
        let premier = morceaux.next().map(|c| c.as_os_str().to_string_lossy().into_owned());
        let original = premier
            .and_then(|p| sources.iter().find(|(nom, _)| *nom == p))
            .map(|(_, source)| source.join(morceaux.as_path()));
        let Some(original) = original.filter(|o| o.is_file()) else {
            r.sans_original += 1;
            continue;
        };
        match empreinte(&original) {
            Ok(h) if h == relue => r.identiques += 1,
            Ok(_)
                if std::fs::metadata(&original)
                    .and_then(|m| m.modified())
                    .is_ok_and(|m| m > copie_le) =>
            {
                r.modifies_depuis += 1;
            }
            Ok(_) => r.abimes.push((
                (*relatif).clone(),
                tr!(
                    "différent de l'original, qui n'a pas changé",
                    "different from the original, which has not changed"
                )
                .to_string(),
            )),
            Err(_) => r.sans_original += 1,
        }
    }
    r
}

/// La copie à vérifier : `chemin` s'il en est une, sinon la plus récente qu'il contient.
fn copie_a_verifier(chemin: &Path) -> Option<PathBuf> {
    let est_une_copie = |p: &Path| {
        let nom = p.file_name().unwrap_or_default().to_string_lossy();
        de_copie(&nom)
            && crate::passage::les_deux(COMPTE_RENDU)
                .iter()
                .any(|f| p.join(f).is_file())
    };
    if est_une_copie(chemin) {
        return Some(chemin.to_path_buf());
    }
    std::fs::read_dir(chemin)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| est_une_copie(p))
        .max()
}

/// « Vérifier une copie » (menu Données, `vanguard verifier-copie [dossier]`) : un test de restauration. Des fichiers
/// répartis sur toute la copie sont relus sur le disque, cache contourné, et comparés à leur original. Rien n'est
/// écrit ni effacé.
pub fn verifier_copie(destination: Option<&Path>) {
    println!();
    cadre(
        &format!("{ACCENT}{}{RESET}", tr!("VÉRIFIER UNE COPIE", "CHECK A COPY")),
        &format!("{GRIS}{}{RESET}", tr!("relue et comparée", "read back and compared")),
    );
    let racine = match destination {
        Some(d) => Some(d.to_path_buf()),
        None => choisir_disque(),
    };
    let Some(racine) = racine else { return };
    let Some(dossier) = copie_a_verifier(&racine) else {
        trp!(
            "  ✖ Aucune copie de Vanguard ici ({}) : « Copier mes fichiers » en fait une.",
            "  ✖ No Vanguard copy here ({}): “Copy my files” makes one.",
            chemin_affichable(&racine)
        );
        return;
    };
    // Une copie faite avant le changement de nom a son compte rendu sous l'ancien nom (`passage`).
    let compte_rendu = crate::passage::les_deux(COMPTE_RENDU)
        .iter()
        .map(|f| dossier.join(f))
        .find(|f| f.is_file())
        .unwrap_or_else(|| dossier.join(COMPTE_RENDU));
    let sources = sources_du_compte_rendu(&std::fs::read_to_string(&compte_rendu).unwrap_or_default());
    let copie_le = std::fs::metadata(&compte_rendu)
        .and_then(|m| m.modified())
        .unwrap_or(std::time::UNIX_EPOCH);
    let (fichiers, gros) = fichiers_de_la_copie(&dossier);
    let choisis = echantillon(&fichiers, ECHANTILLON);
    trp!(
        "  Copie : {}
  {} fichier(s) relu(s) sur {}, répartis sur toute la copie…",
        "  Copy: {}
  {} file(s) read back out of {}, spread over the whole copy…",
        chemin_affichable(&dossier),
        choisis.len(),
        fichiers.len()
    );
    if crate::passage::les_deux(TEMOIN)
        .iter()
        .any(|t| dossier.join(t).is_file())
    {
        trp!(
            "  {}⚠{RESET} Cette copie n'est pas finie : relancez « Copier mes fichiers » vers ce disque pour la reprendre.",
            "  {}⚠{RESET} This copy is not finished: run “Copy my files” to this disk again to resume it.",
            couleur(crate::risk::Niveau::Moyen)
        );
    }
    let r = relire(&dossier, &choisis, &sources, copie_le);
    println!();
    for (relatif, raison) in &r.abimes {
        println!(
            "  {}✖{RESET} {} : {}",
            couleur(crate::risk::Niveau::Eleve),
            chemin_affichable(relatif),
            affichable(raison)
        );
    }
    trp!(
        "  {} identique(s) à l'original, {} original(aux) modifié(s) depuis la copie, {} sans original à comparer.",
        "  {} identical to the original, {} original(s) changed since the copy, {} without an original to compare.",
        r.identiques,
        r.modifies_depuis,
        r.sans_original
    );
    if gros > 0 {
        trp!(
            "  {gros} gros fichier(s) (plus de 1 Gio) non relu(s) : trop longs à comparer.",
            "  {gros} large file(s) (over 1 GiB) not read back: too long to compare."
        );
    }
    if choisis.is_empty() && gros > 0 {
        // Rien de relu : la copie n'est pas vide, mais rien ne permet de dire qu'elle se relit.
        trp!(
            "  ⚠ Aucun fichier relu : la copie n'a que de gros fichiers, elle n'est pas vérifiée.",
            "  ⚠ No file read back: the copy only has large files, it is not checked."
        );
    } else if choisis.is_empty() {
        trp!("  ✖ La copie est vide.", "  ✖ The copy is empty.");
    } else if r.abimes.is_empty() {
        trp!(
            "  {VERT}✔{RESET} La copie se relit : vos fichiers se récupéreraient.",
            "  {VERT}✔{RESET} The copy reads back: your files could be recovered."
        );
    } else {
        for l in envelopper(
            tr!(
                "Des fichiers de la copie ne se relisent pas tels qu'ils ont été copiés : ce disque perd des données. Refaites la copie sur un autre disque, et faites vérifier celui-ci (Diagnostic, état SMART).",
                "Some files of the copy do not read back as they were copied: this disk loses data. Make the copy again on another disk, and have this one checked (Diagnostic, SMART status)."
            ),
            LARGEUR - 4,
        ) {
            println!("  {l}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les sous-volumes d'un même btrfs (/, /home, /var/log) ont chacun leur `st_dev` : ils comptaient pour d'autres
    /// disques, et une copie vers /var/log ou un sous-volume monté dans /mnt était acceptée. Le montage qui contient
    /// le chemin, lui, dit le vrai système de fichiers.
    #[cfg(target_os = "linux")]
    #[test]
    fn sous_volumes_du_systeme() {
        let montages = "23 1 0:30 /@ / rw,relatime shared:1 - btrfs /dev/mapper/root rw\n\
                        24 23 0:30 /@home /home rw,relatime shared:2 - btrfs /dev/mapper/root rw\n\
                        25 23 0:30 /@log /var/log rw,relatime shared:3 - btrfs /dev/mapper/root rw\n\
                        26 23 0:30 /@sauve /mnt/sauve rw,relatime shared:4 - btrfs /dev/mapper/root rw\n\
                        90 23 8:17 / /run/media/alice/Mon\\040disque rw,nosuid - exfat /dev/sdb1 rw\n";
        let maison = Path::new("/home/alice");
        let systeme = |p: &str| sur_le_systeme_selon(montages, Path::new(p), maison);
        assert_eq!(systeme("/var/log/copie"), Some(true));
        assert_eq!(systeme("/mnt/sauve"), Some(true));
        assert_eq!(systeme("/home/alice/Documents"), Some(true));
        assert_eq!(systeme("/run/media/alice/Mon disque/x"), Some(false));
        // Un nom qui commence pareil n'est pas sous ce montage.
        assert_eq!(systeme("/run/media/alice/Mon disque2"), Some(true));
    }

    /// Les quatre échappements de /proc/mounts, et un « \\ » qui n'en est pas un (gardé tel quel).
    #[test]
    fn chemins_de_montage_decodes() {
        assert_eq!(
            sans_echappements(r"/run/media/alice/Mon\040disque\011a\012b\134c"),
            "/run/media/alice/Mon disque\ta\nb\\c"
        );
        assert_eq!(sans_echappements(r"/mnt/a\9"), r"/mnt/a\9");
        assert_eq!(sans_echappements("/mnt/été"), "/mnt/été");
    }

    /// En reprise, une copie déjà faite sous un autre nom (« a (2).txt ») est reconnue : pas de troisième copie.
    #[test]
    fn reprise_d_une_copie_renommee() {
        let d = jetable("reprise-renommee");
        let (source, cible) = (d.join("source"), d.join("cible"));
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::write(source.join("a.txt"), "à copier").unwrap();
        std::fs::write(cible.join("a.txt"), "un autre fichier").unwrap();
        std::fs::write(cible.join("a (2).txt"), "à copier").unwrap();
        let mut bilan = Bilan::default();
        copier_fichier(&source.join("a.txt"), &cible, &mut bilan);
        assert_eq!((bilan.deja, bilan.copies), (1, 0), "{bilan:?}");
        assert!(!cible.join("a (3).txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un nom proche de la limite (255 octets) se copie : le fichier partiel ne doit pas allonger le nom au-delà.
    #[cfg(unix)]
    #[test]
    fn nom_long_copie() {
        let d = jetable("nom-long");
        let (source, cible) = (d.join("source"), d.join("cible"));
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&cible).unwrap();
        let nom = format!("{}.txt", "n".repeat(240));
        std::fs::write(source.join(&nom), "long").unwrap();
        let mut bilan = Bilan::default();
        copier_fichier(&source.join(&nom), &cible, &mut bilan);
        assert_eq!(bilan.copies, 1, "{bilan:?}");
        assert_eq!(std::fs::read_to_string(cible.join(&nom)).unwrap(), "long");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La relecture sans cache donne la même empreinte que la lecture ordinaire.
    #[test]
    fn relecture_sans_cache() {
        let d = jetable("sans-cache");
        let f = d.join("a.bin");
        // Une taille qui n'est pas un multiple du secteur : sans cache, Windows lit par blocs alignés et la dernière
        // lecture, courte, rend le reste.
        let contenu: Vec<u8> = (0..(3 << 20) + 1234u32)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        std::fs::write(&f, &contenu).unwrap();
        // Ouvert en écriture : Windows refuse de vider sur le disque un fichier ouvert en lecture seule.
        OpenOptions::new().write(true).open(&f).unwrap().sync_all().unwrap();
        assert_eq!(empreinte_relue(&f).unwrap(), blake3::hash(&contenu));
        let vide = d.join("vide.bin");
        std::fs::write(&vide, b"").unwrap();
        assert_eq!(empreinte_relue(&vide).unwrap(), blake3::hash(b""));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fichier de plus de 1 Gio n'est pas relu, mais il est compté : « Vérifier une copie » reste rapide et le dit.
    #[test]
    fn gros_fichiers_hors_echantillon() {
        let d = jetable("gros-copie");
        std::fs::create_dir_all(d.join("Vidéos")).unwrap();
        std::fs::write(d.join("Vidéos/court.txt"), b"court").unwrap();
        // Fichier creux : 1 Gio + 1 octet annoncés, presque rien d'écrit sur le disque.
        let gros = File::create(d.join("Vidéos/machine.img")).unwrap();
        gros.set_len(TAILLE_RELUE_MAX + 1).unwrap();
        drop(gros);
        let (fichiers, gros) = fichiers_de_la_copie(&d);
        assert_eq!(fichiers, [Path::new("Vidéos").join("court.txt")]);
        assert_eq!(gros, 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une destination tapée en ligne de commande sort de `canonicalize` en « \\?\E:\… » : elle doit retrouver le
    /// lecteur « E:\ » de la liste des disques, sinon la place libre n'est pas vérifiée.
    #[cfg(windows)]
    #[test]
    fn meme_lecteur_sous_forme_etendue() {
        let e = Path::new(r"E:\");
        assert!(meme_lecteur(Path::new(r"\\?\E:\Sauvegarde"), e));
        assert!(meme_lecteur(Path::new(r"e:\Sauvegarde"), e));
        assert!(meme_lecteur(Path::new(r"E:\"), e));
        assert!(!meme_lecteur(Path::new(r"\\?\F:\Sauvegarde"), e));
        assert!(!meme_lecteur(Path::new(r"\\?\UNC\nas\partage"), e));
        // La vraie chaîne : un dossier créé puis canonisé, comme le fait `destination_permise`.
        let d = jetable("lecteur");
        let canonique = d.canonicalize().unwrap();
        let lecteur: String = canonique
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .chars()
            .take(3)
            .collect();
        assert!(meme_lecteur(&canonique, Path::new(&lecteur)), "{canonique:?}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Vers une clé en FAT32, les fichiers de 4 Go ou plus sont trouvés avant de commencer.
    #[test]
    fn fichiers_trop_gros_pour_fat32() {
        assert!(limite_4_go("vfat") && limite_4_go("msdos") && limite_4_go("FAT32"));
        assert!(!limite_4_go("exfat") && !limite_4_go("NTFS") && !limite_4_go("btrfs"));
        let montages = "23 1 0:30 /@ / rw - btrfs /dev/mapper/root rw\n\
                        90 23 8:17 / /run/media/alice/CLE rw,nosuid - vfat /dev/sdb1 rw\n";
        assert_eq!(
            montage(montages, Path::new("/run/media/alice/CLE/x")),
            Some(("8:17", "vfat"))
        );
        assert_eq!(montage(montages, Path::new("/home/alice")), Some(("0:30", "btrfs")));
        let d = jetable("gros");
        let videos = d.join("Vidéos");
        std::fs::create_dir_all(videos.join("vacances")).unwrap();
        // Creux : 4 Go annoncés, rien d'écrit sur le disque.
        File::create(videos.join("vacances/film.mkv"))
            .unwrap()
            .set_len(4 << 30)
            .unwrap();
        std::fs::write(videos.join("petit.mp4"), b"x").unwrap();
        assert_eq!(
            gros_fichiers(&[(Sorte::Videos, videos.clone())]),
            [videos.join("vacances/film.mkv")]
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-copie-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn avancement() -> Avancement {
        Avancement {
            total_fichiers: 0,
            total_octets: 0,
            fichiers: 0,
            octets: 0,
            debut: Instant::now(),
            dernier: Instant::now(),
            terminal: false,
        }
    }

    #[test]
    fn copie_verifiee_puis_reprise_sans_rien_ecraser() {
        let base = jetable("arbre");
        let source = base.join("Documents");
        std::fs::create_dir_all(source.join("factures/2026")).unwrap();
        std::fs::write(source.join("lettre.txt"), "Bonjour alice").unwrap();
        std::fs::write(source.join("factures/2026/janvier.pdf"), vec![7u8; 3 << 20]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc/hostname", source.join("raccourci")).unwrap();
        let cible = base.join("disque/Vanguard-copie-2026-10-18/Documents");
        let mut b = Bilan::default();
        copier_arbre(&source, &cible, &mut b, &mut avancement());
        assert_eq!((b.copies, b.deja, b.echecs.len()), (2, 0, 0), "{b:?}");
        assert_eq!(
            std::fs::read(cible.join("factures/2026/janvier.pdf")).unwrap(),
            vec![7u8; 3 << 20]
        );
        #[cfg(unix)]
        assert_eq!(b.liens, 1);
        // Aucun fichier partiel ne reste.
        assert!(!cible.join(format!(".lettre.txt{PARTIEL}")).exists());
        // Reprise : ce qui est déjà là à l'identique n'est pas recopié.
        let mut reprise = Bilan::default();
        copier_arbre(&source, &cible, &mut reprise, &mut avancement());
        assert_eq!((reprise.copies, reprise.deja), (0, 2), "{reprise:?}");
        // L'original a changé : la copie d'avant reste, la nouvelle prend un autre nom.
        std::fs::write(source.join("lettre.txt"), "Bonjour bob").unwrap();
        let mut change = Bilan::default();
        copier_arbre(&source, &cible, &mut change, &mut avancement());
        assert_eq!(
            std::fs::read_to_string(cible.join("lettre.txt")).unwrap(),
            "Bonjour alice"
        );
        assert_eq!(
            std::fs::read_to_string(cible.join("lettre (2).txt")).unwrap(),
            "Bonjour bob"
        );
        assert_eq!(change.renommes.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn partiel_d_une_copie_interrompue_remplace() {
        let base = jetable("partiel");
        std::fs::write(base.join("photo.jpg"), b"image entiere").unwrap();
        let cible = base.join("copie");
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::write(cible.join(format!(".photo.jpg{PARTIEL}")), b"ima").unwrap();
        let mut b = Bilan::default();
        copier_fichier(&base.join("photo.jpg"), &cible, &mut b);
        assert_eq!(b.copies, 1);
        assert_eq!(std::fs::read(cible.join("photo.jpg")).unwrap(), b"image entiere");
        assert!(!cible.join(format!(".photo.jpg{PARTIEL}")).exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn noms_et_dossiers_dates() {
        assert_eq!(nom_permis("réunion : bilan?.txt"), "réunion _ bilan_.txt");
        assert_eq!(nom_permis("fin. "), "fin");
        assert_eq!(nom_permis("::"), "__");
        let base = jetable("dates");
        std::fs::write(base.join("photo.jpg"), b"x").unwrap();
        std::fs::write(base.join("photo (2).jpg"), b"x").unwrap();
        assert_eq!(nom_libre(&base, "photo.jpg"), base.join("photo (3).jpg"));
        assert_eq!(nom_libre(&base, "LISEZMOI"), base.join("LISEZMOI (2)"));
        // Une copie interrompue se propose ; refusée, un nouveau dossier daté.
        let interrompue = base.join("Vanguard-copie-2026-10-01");
        std::fs::create_dir_all(&interrompue).unwrap();
        std::fs::write(interrompue.join(TEMOIN), "").unwrap();
        assert_eq!(dossier_de_copie(&base, |_| true), interrompue);
        let nouveau = dossier_de_copie(&base, |_| false);
        assert!(
            nouveau
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("Vanguard-copie-")
        );
        assert_ne!(nouveau, interrompue);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn copie_complete_avec_compte_rendu() {
        let base = jetable("complete");
        let source = base.join("Images");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("vacances.png"), b"png").unwrap();
        let dossier = base.join("disque/Vanguard-copie-2026-10-18");
        let b = copier(&[(Sorte::Images, source.clone())], &dossier, (1, 3));
        assert_eq!(b.copies, 1);
        assert!(dossier.join("Images/vacances.png").is_file());
        // Finie sans échec : plus de témoin, un compte rendu.
        assert!(!dossier.join(TEMOIN).exists());
        assert!(
            std::fs::read_to_string(dossier.join(COMPTE_RENDU))
                .unwrap()
                .contains("1 fichier(s) copié(s)")
        );
        assert_eq!(mesurer(&source), (1, 3));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Quatre fichiers creux de 4 Eio chacun (sans rien occuper : tmpfs, btrfs, XFS, APFS) dépassent un u64. La mesure
    /// d'avant la copie les plafonne : sa somme ordinaire paniquait dans les tests comme dans la version publiée, qui
    /// vérifie les dépassements. Un système de fichiers qui refuse une telle taille (ext4, NTFS) : rien à mesurer.
    #[cfg(unix)]
    #[test]
    fn des_fichiers_creux_ne_font_pas_deborder_la_mesure() {
        let d = jetable("creux");
        let creux = (0..4).all(|i| {
            std::fs::File::create(d.join(format!("creux{i}")))
                .and_then(|f| f.set_len(1 << 62))
                .is_ok()
        });
        if creux {
            assert_eq!(mesurer(&d), (4, u64::MAX));
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn partitions_de_la_cle_reconnues_par_leur_disque() {
        let mount = "/dev/disk1s1 on / (apfs, local, read-only)\n\
                     /dev/disk4s1 on /Volumes/VANGUARD (exfat, local, nodev, nosuid, read-only)\n\
                     /dev/disk4s5 on /Volumes/WIN11 (msdos, local)\n\
                     /dev/disk5s1 on /Volumes/Mon disque (hfs, local)\n";
        let d = disques_de_mount(mount);
        assert_eq!(d[1], (PathBuf::from("/Volumes/VANGUARD"), "disk4".to_string()));
        assert_eq!(d[2].1, "disk4");
        assert_eq!(d[3], (PathBuf::from("/Volumes/Mon disque"), "disk5".to_string()));
        let w =
            disques_des_lecteurs("E:\\|VANGUARD|1|2|1\nF:\\|WIN11|3|4|1\nG:\\|Sauvegarde|5|6|2\nH:\\|Réseau|7|8|\n");
        assert_eq!(w.len(), 3);
        assert_eq!(w[1], (PathBuf::from("F:\\"), "1".to_string()));
        // Le 5e champ ne gêne pas la lecture des lecteurs.
        assert_eq!(lire_lecteurs("E:\\|VANGUARD|1|2|1\n", "C:").len(), 1);
    }

    #[test]
    fn copie_relue_et_comparee() {
        let base = jetable("relecture");
        let source = base.join("Documents");
        std::fs::create_dir_all(source.join("sous")).unwrap();
        for i in 0..5 {
            std::fs::write(source.join(format!("f{i}.txt")), format!("contenu {i}")).unwrap();
        }
        std::fs::write(source.join("sous/a.txt"), b"a").unwrap();
        let disque = base.join("disque");
        let dossier = disque.join("Vanguard-copie-2026-10-18");
        let b = copier(&[(Sorte::Documents, source.clone())], &dossier, (6, 0));
        assert_eq!(b.copies, 6);
        assert_eq!(copie_a_verifier(&disque), Some(dossier.clone()));
        let sources = sources_du_compte_rendu(&std::fs::read_to_string(dossier.join(COMPTE_RENDU)).unwrap());
        assert_eq!(sources, [("Documents".to_string(), source.clone())]);
        let (fichiers, gros) = fichiers_de_la_copie(&dossier);
        assert_eq!((fichiers.len(), gros), (6, 0), "{fichiers:?}");
        let copie_le = std::fs::metadata(dossier.join(COMPTE_RENDU))
            .unwrap()
            .modified()
            .unwrap();
        let tous: Vec<&PathBuf> = fichiers.iter().collect();
        assert_eq!(
            relire(&dossier, &tous, &sources, copie_le),
            Relecture {
                identiques: 6,
                ..Relecture::default()
            }
        );
        // La copie abîmée (même date d'original) se voit ; un original disparu ne compte pas contre la copie.
        std::fs::write(dossier.join("Documents/f1.txt"), b"abime").unwrap();
        std::fs::remove_file(source.join("f2.txt")).unwrap();
        let r = relire(&dossier, &tous, &sources, std::time::SystemTime::now());
        assert_eq!((r.identiques, r.sans_original, r.abimes.len()), (4, 1, 1), "{r:?}");
        // Un original modifié après la copie : normal, pas une copie abîmée.
        let r = relire(&dossier, &tous, &sources, std::time::UNIX_EPOCH);
        assert_eq!((r.modifies_depuis, r.abimes.len()), (1, 0), "{r:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn echantillon_reparti() {
        let f: Vec<PathBuf> = (0..100).map(|i| PathBuf::from(format!("{i:03}"))).collect();
        let e = echantillon(&f, 5);
        assert_eq!(e.len(), 5);
        assert_eq!((e[0], e[4]), (&f[0], &f[99]));
        assert_eq!(echantillon(&f[..3], 5).len(), 3);
    }

    #[test]
    fn destination_refusee_dans_les_dossiers_copies() {
        let base = jetable("refus");
        let documents = base.join("Documents");
        std::fs::create_dir_all(documents.join("sauvegardes")).unwrap();
        let sources = [(Sorte::Documents, documents.clone())];
        assert!(destination_permise(&documents.join("sauvegardes"), &sources).is_err());
        assert!(destination_permise(&base.join("absent"), &sources).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lecteurs_de_windows() {
        let d = lire_lecteurs(
            "C:\\|Windows|1000|2000\nE:\\|Sauvegarde|500|1000\nF:\\||10|20\nG:\\|x|abc|20\n",
            "C:",
        );
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].nom, "Sauvegarde (E:)");
        assert_eq!(d[1].nom, "F:");
        assert_eq!(d[0].libre, 500);
        // L'étiquette d'un disque branché, choisie par qui l'a formaté : piégée, elle arrive inoffensive.
        let d = lire_lecteurs("E:\\|Sauve\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}|500|1000\n", "C:");
        assert_eq!(d[0].nom, "Sauve�]52;c;eA==��[2K�� (E:)");
    }

    #[test]
    fn noms_reprises_et_refus_cas_limites() {
        let base = jetable("limites");
        assert_eq!(nom_libre(&base, ".bashrc"), base.join(".bashrc (2)"));
        assert_eq!(nom_libre(&base, "archive.tar.gz"), base.join("archive.tar (2).gz"));
        assert_eq!(nom_libre(&base, "fin."), base.join("fin (2)."));
        assert_eq!(nom_permis("a\tb\u{7f}c"), "a_b_c");
        assert_eq!(nom_permis(". ."), "_");
        // La plus récente des copies interrompues, quelle que soit la langue ; un dossier sans témoin n'en est pas une.
        for nom in [
            "Vanguard-copie-2026-10-01",
            "Vanguard-copy-2026-10-02",
            "Vanguard-copy-2026-10-03",
        ] {
            std::fs::create_dir_all(base.join(nom)).unwrap();
        }
        std::fs::write(base.join("Vanguard-copie-2026-10-01").join(TEMOIN), "").unwrap();
        std::fs::write(base.join("Vanguard-copy-2026-10-02").join(TEMOIN), "").unwrap();
        let proposee = std::cell::RefCell::new(String::new());
        let reprise = dossier_de_copie(&base, |nom| {
            *proposee.borrow_mut() = nom.to_string();
            true
        });
        assert_eq!(reprise, base.join("Vanguard-copy-2026-10-02"));
        assert_eq!(*proposee.borrow(), "Vanguard-copy-2026-10-02");
        // Le lecteur du système est écarté, en minuscules comme avec sa barre.
        let d = lire_lecteurs("c:\\|Windows|1|2\nD:\\|Données|3|4\n", "C:\\");
        assert_eq!((d.len(), d[0].nom.as_str(), d[0].total), (1, "Données (D:)", 4));
        // Refus : un fichier, la clé VANGUARD et ses sous-dossiers.
        let cle = base.join("cle");
        std::fs::create_dir_all(cle.join("sous")).unwrap();
        std::fs::write(cle.join(crate::reseau::TEMOIN_CLE), "").unwrap();
        std::fs::write(base.join("note.txt"), "x").unwrap();
        let refus = destination_permise(&base.join("note.txt"), &[]).unwrap_err();
        assert!(refus.ends_with("note.txt n'est pas un dossier."), "{refus}");
        assert_eq!(
            destination_permise(&cle.join("sous"), &[]).unwrap_err(),
            "La clé VANGUARD n'est pas un disque de copie."
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
