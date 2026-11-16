//! L'ouverture du fichier que la Console fait lire (`vanguard console verifier-fichier -- <chemin>`, et
//! `courriel-suspect`, `verifier-moi`) : une seule, et c'est ce qui est ouvert qui est jugé, puis lu. Juger un chemin
//! puis le rouvrir laissait un écart : un dossier remplacé entre les deux par un lien vers ~/.ssh faisait lire la clé.
//!
//! D'abord le jugement sur le texte seul (`valeur_console::juger_lexical`) : hors des endroits permis, rien n'est
//! regardé sur le disque. Puis une descente depuis la racine permise, un nom à la fois, chaque dossier ouvert à partir
//! du précédent sans jamais suivre de lien (Linux : openat et O_NOFOLLOW à chaque nom ; Windows : NtCreateFile relatif
//! à la poignée du dossier précédent, FILE_OPEN_REPARSE_POINT, chaque dossier tenu avec un accès de liste, qui fait
//! appliquer son partage sans suppression : nul ne le renomme tant qu'on lit). Le fichier ouvert doit être ordinaire,
//! à un seul nom (un lien physique vers
//! ~/.ssh/id_ed25519 posé dans Téléchargements est un autre nom du même fichier), et son chemin réel, relu sur ce qu'on
//! tient (/proc/self/fd, GetFinalPathNameByHandleW), est jugé une seconde fois contre les mêmes endroits.
//!
//! Pourquoi une descente par openat plutôt qu'openat2 (RESOLVE_NO_SYMLINKS) : la structure open_how ne se construit pas
//! depuis libc sous musl (`garde::ouvrir` déclare la sienne), openat2 manque (ENOSYS) avant Linux 5.6 et sous certains
//! filtres seccomp, ce qui demanderait de toute façon la descente en secours, et RESOLVE_NO_XDEV refuserait les
//! supports amovibles montés sous /run/media. La descente donne la même garantie : « .. » est refusé sur le texte, et
//! chaque nom est ouvert sans suivre de lien (un lien « magique » de /proc est un lien comme un autre).

use std::ffi::OsStr;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::socle::valeur_console::{self, Racine, Refus};

/// Un fichier ouvert une seule fois et jugé sur ce qui est ouvert : seul `fichier` est lu, jamais `chemin` rouvert.
pub(crate) struct FichierJuge {
    /// Le fichier, ouvert en lecture.
    pub(crate) fichier: File,
    /// Sa taille, lue sur le descripteur à l'ouverture.
    pub(crate) taille: u64,
    /// Son chemin réel, relu sur le descripteur : pour nommer et montrer seulement.
    pub(crate) chemin: PathBuf,
    /// Le dossier qui le contient, tenu ouvert : la liste d'empreintes publiée à côté se lit par lui (`lire_voisin`).
    dossier: systeme::Dossier,
}

impl std::fmt::Debug for FichierJuge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FichierJuge")
            .field("taille", &self.taille)
            .field("chemin", &self.chemin)
            .finish_non_exhaustive()
    }
}

/// Les étapes de la descente, pour les essais qui changent le disque entre deux (`crochet`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Etape {
    /// La racine permise vient d'être ouverte.
    Racine,
    /// Le dossier numéro n après la racine vient d'être ouvert.
    Dossier(usize),
    /// Le fichier vient d'être ouvert, rien n'est encore jugé.
    Fichier,
}

/// Ce qu'un essai fait à chaque étape de la descente.
#[cfg(test)]
pub(crate) type Crochet = Box<dyn FnMut(Etape)>;

#[cfg(test)]
thread_local! {
    /// Le crochet de ce fil seulement.
    static CROCHET: std::cell::RefCell<Option<Crochet>> = const { std::cell::RefCell::new(None) };
}

/// Pose (ou retire) ce qu'un essai fait à chaque étape de la descente de ce fil.
#[cfg(test)]
pub(crate) fn poser_crochet(f: Option<Crochet>) {
    CROCHET.with(|c| *c.borrow_mut() = f);
}

/// Une étape de la descente : rien hors des essais.
fn crochet(etape: Etape) {
    #[cfg(test)]
    CROCHET.with(|c| {
        if let Some(f) = c.borrow_mut().as_mut() {
            f(etape);
        }
    });
    #[cfg(not(test))]
    let _ = etape;
}

/// Juge `texte` puis ouvre le fichier qu'il désigne, une seule fois, et le juge encore sur ce qui est ouvert : la
/// forme et la place sur le texte seul, puis la descente sans lien depuis la racine permise, un fichier ordinaire à un
/// seul nom, et son chemin réel relu sous un endroit permis, hors de tout dossier caché.
pub(crate) fn ouvrir_juge(texte: &str, maison: &Path, racines: &[Racine]) -> Result<FichierJuge, Refus> {
    let (racine, reste) = valeur_console::juger_lexical(texte, maison, racines)?;
    let noms: Vec<&OsStr> = reste.iter().collect();
    let Some((dernier, dossiers)) = noms.split_last() else {
        return Err(Refus::HorsDesEndroits);
    };
    let (fichier, dossier) = systeme::descendre(&racine.reelle, dossiers, dernier)?;
    crochet(Etape::Fichier);
    let meta = fichier.metadata().map_err(|_| Refus::Illisible)?;
    if !meta.is_file() {
        return Err(Refus::PasUnFichier);
    }
    match systeme::noms(&fichier, &meta) {
        Some(1) => {}
        Some(0) => return Err(Refus::Introuvable),
        Some(_) => return Err(Refus::PlusieursNoms),
        None => return Err(Refus::NonVerifie),
    }
    let chemin = systeme::chemin_reel(&fichier).ok_or(Refus::NonVerifie)?;
    valeur_console::situer(&chemin, racines)?;
    Ok(FichierJuge {
        fichier,
        taille: meta.len(),
        chemin,
        dossier,
    })
}

impl FichierJuge {
    /// Le fichier `nom` du même dossier (une liste d'empreintes publiée à côté), ouvert par le dossier tenu, sans
    /// suivre de lien : un fichier ordinaire à un seul nom, d'au plus `max` octets.
    pub(crate) fn lire_voisin(&self, nom: &str, max: u64) -> std::io::Result<Vec<u8>> {
        let pas_ordinaire = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                crate::tr!("pas un simple fichier", "not a plain file"),
            )
        };
        let f = systeme::voisin(&self.dossier, OsStr::new(nom))?;
        let meta = f.metadata()?;
        if !meta.is_file() || systeme::noms(&f, &meta) != Some(1) {
            return Err(pas_ordinaire());
        }
        if meta.len() > max {
            return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
        }
        let mut octets = Vec::new();
        f.take(max.saturating_add(1)).read_to_end(&mut octets)?;
        if u64::try_from(octets.len()).unwrap_or(u64::MAX) > max {
            return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
        }
        Ok(octets)
    }
}

/// Le refus d'une ouverture ratée : absent, sinon illisible.
fn refus_d_erreur(e: &std::io::Error) -> Refus {
    match e.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => Refus::Introuvable,
        _ => Refus::Illisible,
    }
}

#[cfg(target_os = "linux")]
mod systeme {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::os::fd::{AsFd as _, AsRawFd as _};
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{Etape, Refus, crochet, refus_d_erreur};
    use crate::machine::linux::garde::ouvrir::un_element;

    /// Un dossier traversé : O_PATH (rien n'est lu), sans suivre de lien ; ouvert ainsi, un lien est ouvert lui-même
    /// et se reconnaît à fstat.
    const DOSSIER: i32 = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    /// Le fichier lu : sans suivre de lien (ELOOP), sans attendre (un tube nommé), sans devenir le terminal.
    const FICHIER: i32 = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    /// Le dossier qui contient le fichier, tenu ouvert (O_PATH).
    pub(super) struct Dossier(File);

    /// La descente : la racine ouverte par son chemin (elle-même pas un lien ; le chemin au-dessus est celui de la
    /// maison résolue, et le second jugement le revoit), puis chaque nom ouvert sous le précédent.
    pub(super) fn descendre(racine: &Path, dossiers: &[&OsStr], dernier: &OsStr) -> Result<(File, Dossier), Refus> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let mut courant = options.open(racine).map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => Refus::Lien,
            _ => refus_d_erreur(&e),
        })?;
        crochet(Etape::Racine);
        for (n, nom) in dossiers.iter().enumerate() {
            let suivant = un_element(courant.as_fd(), nom, DOSSIER).map_err(|e| refus_d_erreur(&e))?;
            let m = suivant.metadata().map_err(|_| Refus::Illisible)?;
            if m.file_type().is_symlink() {
                return Err(Refus::Lien);
            }
            if !m.is_dir() {
                return Err(Refus::Introuvable);
            }
            courant = suivant;
            crochet(Etape::Dossier(n));
        }
        let fichier = un_element(courant.as_fd(), dernier, FICHIER).map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => Refus::Lien,
            _ => refus_d_erreur(&e),
        })?;
        Ok((fichier, Dossier(courant)))
    }

    /// Le nombre de noms (liens physiques) du fichier ouvert.
    #[allow(clippy::unnecessary_wraps)] // même signature que sous Windows, où la lecture peut échouer
    pub(super) fn noms(_: &File, meta: &std::fs::Metadata) -> Option<u64> {
        Some(meta.nlink())
    }

    /// Le chemin réel de ce qui est ouvert, relu par le noyau sur le descripteur.
    pub(super) fn chemin_reel(f: &File) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{}", f.as_raw_fd())).ok()
    }

    /// Un nom du dossier tenu, ouvert sous lui comme le fichier.
    pub(super) fn voisin(d: &Dossier, nom: &OsStr) -> std::io::Result<File> {
        un_element(d.0.as_fd(), nom, FICHIER)
    }
}

#[cfg(windows)]
mod systeme {
    use std::ffi::{OsStr, c_void};
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::path::{Component, Path, PathBuf};

    use super::{Etape, Refus, crochet, juger_attributs, refus_d_erreur};

    const FILE_LIST_DIRECTORY: u32 = 0x0001;
    const FILE_TRAVERSE: u32 = 0x0020;
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    /// Un dossier tenu : le lister, le traverser, lire ses attributs. Lister compte pour Windows comme une lecture
    /// (FILE_READ_DATA) : c'est ce qui fait appliquer le partage ci-dessous. Un accès aux attributs seul ne le fait pas
    /// appliquer, et laissait renommer un dossier pourtant « tenu ».
    const ACCES_DOSSIER: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    /// Lecture et écriture partagées, jamais la suppression : tant qu'on tient un nom avec un accès de lecture, nul ne
    /// l'ouvre pour le renommer ni l'effacer (il faudrait l'accès DELETE, que ce partage refuse).
    const PARTAGE: u32 = 0x0001 | 0x0002;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    /// Ne pas rapatrier un fichier en ligne seulement (OneDrive) : l'ouvrir le ferait télécharger.
    const FILE_FLAG_OPEN_NO_RECALL: u32 = 0x0010_0000;
    const DRAPEAUX: u32 = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_NO_RECALL;
    const ATTRIBUT_DOSSIER: u32 = 0x10;

    // NtCreateFile (learn.microsoft.com, « NtCreateFile function (winternl.h) ») : disposition et options.
    const FILE_OPEN: u32 = 1;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x0000_4000;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_OPEN_NO_RECALL: u32 = 0x0040_0000;
    const OBJ_CASE_INSENSITIVE: u32 = 0x40;
    // Les NTSTATUS d'un nom absent (STATUS_OBJECT_NAME_NOT_FOUND, _PATH_NOT_FOUND, STATUS_NOT_A_DIRECTORY).
    const ABSENTS: [u32; 3] = [0xC000_0034, 0xC000_003A, 0xC000_0103];

    /// Le dossier qui contient le fichier, et chaque nom de la descente tenu ouvert, de la racine du lecteur à lui
    /// (le dernier).
    pub(super) struct Dossier {
        tenus: Vec<File>,
    }

    /// Les attributs et l'étiquette de point d'analyse de ce qui est ouvert (FileAttributeTagInfo).
    #[repr(C)]
    #[derive(Default)]
    struct AttributsEtiquette {
        attributs: u32,
        etiquette: u32,
    }

    /// FileAttributeTagInfo, dans FILE_INFO_BY_HANDLE_CLASS.
    const ATTRIBUTS_ETIQUETTE: u32 = 9;

    /// UNICODE_STRING : longueurs en octets, sans zéro final.
    #[repr(C)]
    struct TexteNt {
        longueur: u16,
        maximum: u16,
        tampon: *mut u16,
    }

    /// OBJECT_ATTRIBUTES : le nom, relatif au dossier `racine` (une poignée ouverte).
    #[repr(C)]
    struct AttributsObjet {
        longueur: u32,
        racine: *mut c_void,
        nom: *const TexteNt,
        attributs: u32,
        descripteur: *mut c_void,
        qualite: *mut c_void,
    }

    /// IO_STATUS_BLOCK.
    #[repr(C)]
    struct EtatEs {
        etat: isize,
        information: usize,
    }

    // FFI de kernel32 : les attributs et l'étiquette de point d'analyse d'une poignée ouverte.
    #[allow(unsafe_code)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            fichier: *mut c_void,
            classe: u32,
            information: *mut c_void,
            taille: u32,
        ) -> i32;
    }

    // FFI de ntdll : NtCreateFile, la seule façon d'ouvrir un nom sous une poignée de dossier (l'équivalent d'openat).
    #[allow(unsafe_code)]
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            poignee: *mut *mut c_void,
            acces: u32,
            objet: *const AttributsObjet,
            etat: *mut EtatEs,
            taille: *const i64,
            attributs: u32,
            partage: u32,
            disposition: u32,
            options: u32,
            ea: *mut c_void,
            longueur_ea: u32,
        ) -> i32;
    }

    /// Les attributs et l'étiquette de ce qui est ouvert.
    // FFI de kernel32 : GetFileInformationByHandleEx(FileAttributeTagInfo).
    #[allow(unsafe_code)]
    fn attributs(f: &File) -> Option<(u32, u32)> {
        let mut info = AttributsEtiquette::default();
        let taille = u32::try_from(std::mem::size_of::<AttributsEtiquette>()).ok()?;
        // SAFETY: la poignée vient d'un fichier ouvert qui vit pendant l'appel ; `info` est une FILE_ATTRIBUTE_TAG_INFO
        // à nous, de la taille passée, que l'appel remplit sans en sortir.
        let ok = unsafe {
            GetFileInformationByHandleEx(f.as_raw_handle(), ATTRIBUTS_ETIQUETTE, (&raw mut info).cast(), taille)
        } != 0;
        ok.then_some((info.attributs, info.etiquette))
    }

    /// La racine du lecteur (« C:\ »), ouverte elle-même, tenue comme un dossier.
    fn ouvrir_lecteur(chemin: &Path) -> Result<File, Refus> {
        let f = std::fs::OpenOptions::new()
            .access_mode(ACCES_DOSSIER)
            .share_mode(PARTAGE)
            .custom_flags(DRAPEAUX)
            .open(chemin)
            .map_err(|e| refus_d_erreur(&e))?;
        let (attributs, etiquette) = attributs(&f).ok_or(Refus::NonVerifie)?;
        juger_attributs(attributs, etiquette, false)?;
        if attributs & ATTRIBUT_DOSSIER == 0 {
            return Err(Refus::Introuvable);
        }
        Ok(f)
    }

    /// Un nom simple sous le dossier tenu `dessus`, ouvert par NtCreateFile relativement à lui (jamais par un chemin
    /// complet, qui se relirait depuis la racine), lui-même (FILE_OPEN_REPARSE_POINT : un lien ou une jonction est
    /// ouvert, pas suivi), puis jugé sur ses attributs. `lire` : un fichier, en lecture ; sinon un dossier, tenu
    /// (`ACCES_DOSSIER`). Ni FILE_DIRECTORY_FILE ni FILE_NON_DIRECTORY_FILE : un lien s'ouvre ainsi tel quel et se dit
    /// lien ; ce qui est ouvert est jugé ensuite.
    // FFI de ntdll : NtCreateFile ; la poignée rendue devient un File, fermé une fois.
    #[allow(unsafe_code)]
    pub(super) fn ouvrir_sous(dessus: &File, nom: &OsStr, lire: bool, sous_racine: bool) -> Result<(File, u32), Refus> {
        let mut large: Vec<u16> = nom.encode_wide().collect();
        let point = u16::from(b'.');
        let interdit = |c: &u16| [u16::from(b'\\'), u16::from(b'/'), u16::from(b':'), 0].contains(c);
        if large.is_empty() || large == [point] || large == [point, point] || large.iter().any(interdit) {
            return Err(Refus::Forme);
        }
        let octets = large
            .len()
            .checked_mul(2)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or(Refus::Forme)?;
        let texte = TexteNt {
            longueur: octets,
            maximum: octets,
            tampon: large.as_mut_ptr(),
        };
        let objet = AttributsObjet {
            longueur: u32::try_from(std::mem::size_of::<AttributsObjet>()).map_err(|_| Refus::NonVerifie)?,
            racine: dessus.as_raw_handle(),
            nom: &raw const texte,
            attributs: OBJ_CASE_INSENSITIVE,
            descripteur: std::ptr::null_mut(),
            qualite: std::ptr::null_mut(),
        };
        let options = FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_NO_RECALL;
        let (acces, options) = if lire {
            (FILE_GENERIC_READ, options)
        } else {
            (ACCES_DOSSIER, options | FILE_OPEN_FOR_BACKUP_INTENT)
        };
        let mut poignee: *mut c_void = std::ptr::null_mut();
        let mut etat = EtatEs {
            etat: 0,
            information: 0,
        };
        // SAFETY: `objet` et le `texte` qu'il désigne (sur `large`, vivant, de la longueur dite) vivent pendant
        // l'appel ; `dessus` est une poignée de dossier ouverte, tenue par l'appelant ; `poignee` et `etat` sont à
        // nous ; ni taille ni attributs étendus (pointeurs nuls, longueur 0), comme le veut FILE_OPEN.
        let r = unsafe {
            NtCreateFile(
                &raw mut poignee,
                acces,
                &raw const objet,
                &raw mut etat,
                std::ptr::null(),
                0,
                PARTAGE,
                FILE_OPEN,
                options,
                std::ptr::null_mut(),
                0,
            )
        };
        if r < 0 || poignee.is_null() {
            let code = u32::from_ne_bytes(r.to_ne_bytes());
            return Err(if ABSENTS.contains(&code) {
                Refus::Introuvable
            } else {
                Refus::Illisible
            });
        }
        // SAFETY: NtCreateFile a réussi : `poignee` est une poignée de fichier ouverte, à nous seuls ; le File la
        // fermera une fois.
        let f = unsafe { File::from_raw_handle(poignee) };
        let (attributs, etiquette) = attributs(&f).ok_or(Refus::NonVerifie)?;
        juger_attributs(attributs, etiquette, sous_racine)?;
        Ok((f, attributs))
    }

    /// La descente depuis la racine du lecteur : chaque nom ouvert sous le dossier tenu juste avant, jusqu'à la racine
    /// permise (aucun lien, aucune jonction, un fichier en ligne seulement non plus), puis chaque nom sous elle (ni
    /// caché ni système non plus), tous tenus jusqu'à la fin de la lecture. Rien n'est résolu d'avance : une jonction
    /// en route pourrait mener à un partage, que le système contacterait.
    pub(super) fn descendre(racine: &Path, dossiers: &[&OsStr], dernier: &OsStr) -> Result<(File, Dossier), Refus> {
        let mut composants = racine.components();
        let (Some(Component::Prefix(p)), Some(Component::RootDir)) = (composants.next(), composants.next()) else {
            return Err(Refus::Reseau);
        };
        if !matches!(p.kind(), std::path::Prefix::Disk(_)) {
            return Err(Refus::Reseau);
        }
        let mut lecteur = PathBuf::from(p.as_os_str());
        lecteur.push(std::path::MAIN_SEPARATOR_STR);
        let mut tenus = vec![ouvrir_lecteur(&lecteur)?];
        let suivant = |tenus: &[File], nom: &OsStr, sous_racine: bool| -> Result<File, Refus> {
            let dessus = tenus.last().ok_or(Refus::NonVerifie)?;
            let (f, attributs) = ouvrir_sous(dessus, nom, false, sous_racine)?;
            if attributs & ATTRIBUT_DOSSIER == 0 {
                return Err(Refus::Introuvable);
            }
            Ok(f)
        };
        for c in composants {
            let Component::Normal(nom) = c else {
                return Err(Refus::Forme);
            };
            let f = suivant(&tenus, nom, false)?;
            tenus.push(f);
        }
        crochet(Etape::Racine);
        for (n, nom) in dossiers.iter().enumerate() {
            let f = suivant(&tenus, nom, true)?;
            tenus.push(f);
            crochet(Etape::Dossier(n));
        }
        let dessus = tenus.last().ok_or(Refus::NonVerifie)?;
        let (fichier, attributs) = ouvrir_sous(dessus, dernier, true, true)?;
        if attributs & ATTRIBUT_DOSSIER != 0 {
            return Err(Refus::PasUnFichier);
        }
        Ok((fichier, Dossier { tenus }))
    }

    /// Le nombre de noms (liens physiques) du fichier ouvert.
    pub(super) fn noms(f: &File, _: &std::fs::Metadata) -> Option<u64> {
        crate::machine::windows::information_fichier(f).map(|(_, liens)| u64::from(liens))
    }

    /// Le chemin final de ce qui est ouvert (GetFinalPathNameByHandleW), sans « \\?\ » ; jamais un partage.
    pub(super) fn chemin_reel(f: &File) -> Option<PathBuf> {
        crate::machine::windows::chemin_final(f).map(PathBuf::from)
    }

    /// Un nom du dossier tenu, ouvert sous lui comme le fichier (lui-même, jugé sur ses attributs).
    pub(super) fn voisin(d: &Dossier, nom: &OsStr) -> std::io::Result<File> {
        let pas_ordinaire = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                crate::tr!("pas un simple fichier", "not a plain file"),
            )
        };
        let dessus = d.tenus.last().ok_or_else(pas_ordinaire)?;
        match ouvrir_sous(dessus, nom, true, true) {
            Ok((f, attributs)) if attributs & ATTRIBUT_DOSSIER == 0 => Ok(f),
            Err(Refus::Introuvable) => Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            _ => Err(pas_ordinaire()),
        }
    }
}

/// Juge les attributs d'un nom ouvert sous Windows. Un fichier en ligne seulement (hors ligne, rapatrié à l'ouverture
/// ou à la lecture) : non vérifié, jamais téléchargé. Un point d'analyse qui n'est pas celui des fichiers en nuage
/// (OneDrive) : un lien, une jonction ou une étiquette inconnue, jamais suivi. Sous la racine permise, un nom caché ou
/// système compte comme un dossier caché.
#[cfg(any(windows, test))]
fn juger_attributs(attributs: u32, etiquette: u32, sous_racine: bool) -> Result<(), Refus> {
    const CACHE: u32 = 0x2;
    const SYSTEME: u32 = 0x4;
    const POINT_D_ANALYSE: u32 = 0x400;
    const HORS_LIGNE: u32 = 0x1000;
    const RAPATRIE_A_L_OUVERTURE: u32 = 0x4_0000;
    const RAPATRIE_A_LA_LECTURE: u32 = 0x40_0000;
    // IO_REPARSE_TAG_CLOUD, et ses variantes CLOUD_1 à CLOUD_F (le chiffre du milieu).
    let nuage = etiquette & 0xFFFF_0FFF == 0x9000_001A;
    if attributs & (HORS_LIGNE | RAPATRIE_A_L_OUVERTURE | RAPATRIE_A_LA_LECTURE) != 0 {
        return Err(Refus::EnLigneSeulement);
    }
    if attributs & POINT_D_ANALYSE != 0 && !nuage {
        return Err(Refus::Lien);
    }
    if sous_racine && attributs & (CACHE | SYSTEME) != 0 {
        return Err(Refus::Cache);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les attributs d'un nom sous Windows : un fichier en nuage présent passe ; en ligne seulement, il est non
    /// vérifié ; un lien, une jonction ou une étiquette inconnue ne passent pas ; caché ou système, seulement au-dessus
    /// de la racine.
    #[test]
    fn les_attributs_windows_se_jugent() {
        const NUAGE: u32 = 0x9000_001A;
        const NUAGE_3: u32 = 0x9000_301A;
        const PA: u32 = 0x400;
        assert_eq!(juger_attributs(0x20, 0, true), Ok(()));
        assert_eq!(juger_attributs(0x20 | PA, NUAGE, true), Ok(()));
        assert_eq!(juger_attributs(0x10 | PA, NUAGE_3, true), Ok(()));
        for bit in [0x1000, 0x4_0000, 0x40_0000] {
            assert_eq!(
                juger_attributs(0x20 | PA | bit, NUAGE, true),
                Err(Refus::EnLigneSeulement),
                "{bit:X}"
            );
            assert_eq!(
                juger_attributs(0x20 | bit, 0, false),
                Err(Refus::EnLigneSeulement),
                "{bit:X}"
            );
        }
        // Lien symbolique, point de montage (jonction), étiquette inconnue.
        for etiquette in [0xA000_000C, 0xA000_0003, 0x8000_0017, 0x1234_5678, 0] {
            assert_eq!(
                juger_attributs(0x10 | PA, etiquette, false),
                Err(Refus::Lien),
                "{etiquette:X}"
            );
        }
        assert_eq!(juger_attributs(0x10 | 0x2, 0, true), Err(Refus::Cache));
        assert_eq!(juger_attributs(0x10 | 0x4, 0, true), Err(Refus::Cache));
        assert_eq!(juger_attributs(0x10 | 0x2 | 0x4, 0, false), Ok(()));
    }

    /// Un banc jetable d'« alice » : Téléchargements avec x.pdf et sous/y.pdf, et ~/.ssh avec une fausse clé et un
    /// y.pdf secret ; seul Téléchargements est permis.
    #[cfg(target_os = "linux")]
    struct Banc {
        d: PathBuf,
        maison: PathBuf,
        tele: PathBuf,
        racines: Vec<Racine>,
    }

    #[cfg(target_os = "linux")]
    impl Banc {
        fn nouveau(nom: &str) -> Banc {
            let d = crate::essais::temporaire().join(format!("ouvrir-console-{nom}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let d = d.canonicalize().unwrap();
            let maison = d.join("alice");
            let tele = maison.join("Téléchargements");
            std::fs::create_dir_all(tele.join("sous")).unwrap();
            std::fs::create_dir_all(maison.join(".ssh")).unwrap();
            std::fs::write(tele.join("x.pdf"), b"%PDF-1.7 facture").unwrap();
            std::fs::write(tele.join("sous/y.pdf"), b"%PDF-1.7 releve").unwrap();
            std::fs::write(maison.join(".ssh/id_ed25519"), b"fausse cle").unwrap();
            std::fs::write(maison.join(".ssh/y.pdf"), b"fausse cle aussi").unwrap();
            let racines = vec![Racine::meme(tele.clone())];
            Banc {
                d,
                maison,
                tele,
                racines,
            }
        }

        fn ouvrir(&self, texte: &str) -> Result<FichierJuge, Refus> {
            let r = ouvrir_juge(texte, &self.maison, &self.racines);
            poser_crochet(None);
            r
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Banc {
        fn drop(&mut self) {
            poser_crochet(None);
            let _ = std::fs::remove_dir_all(&self.d);
        }
    }

    /// Ce qui est jugé est ce qui est lu : x.pdf ouvert et jugé, puis remplacé par un lien vers ~/.ssh ; l'empreinte
    /// et le courriel se lisent encore sur ce qui a été ouvert, jamais sur la clé.
    #[cfg(target_os = "linux")]
    #[test]
    fn seul_ce_qui_est_ouvert_est_lu() {
        use crate::protection::telechargement::{Algo, calculer, calculer_juge};
        let b = Banc::nouveau("descripteur");
        std::fs::write(b.d.join("temoin"), b"%PDF-1.7 facture").unwrap();
        let attendu = calculer(&b.d.join("temoin"), Algo::Sha256).unwrap();
        let juge = b.ouvrir("~/Téléchargements/x.pdf").unwrap();
        assert_eq!(juge.chemin, b.tele.join("x.pdf"));
        std::fs::remove_file(b.tele.join("x.pdf")).unwrap();
        std::os::unix::fs::symlink(b.maison.join(".ssh/id_ed25519"), b.tele.join("x.pdf")).unwrap();
        assert_eq!(calculer_juge(&juge, Algo::Sha256).ok(), Some(attendu.clone()));
        assert_eq!(calculer_juge(&juge, Algo::Sha256).ok(), Some(attendu));
        assert_eq!(
            crate::protection::courriel_suspect::octets_juges(&juge).as_deref(),
            Some(&b"%PDF-1.7 facture"[..])
        );
    }

    /// Un dossier du chemin remplacé par un lien vers ~/.ssh juste après l'ouverture de la racine (l'écart qu'un
    /// jugement puis une réouverture laissait) : la descente ne le suit pas.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_dossier_change_en_lien_pendant_la_descente_est_refuse() {
        let b = Banc::nouveau("course-dossier");
        let (tele, ssh) = (b.tele.clone(), b.maison.join(".ssh"));
        poser_crochet(Some(Box::new(move |e| {
            if e == Etape::Racine {
                std::fs::rename(tele.join("sous"), tele.join("sous-vrai")).unwrap();
                std::os::unix::fs::symlink(&ssh, tele.join("sous")).unwrap();
            }
        })));
        assert_eq!(b.ouvrir("~/Téléchargements/sous/y.pdf").err(), Some(Refus::Lien));
    }

    /// Le fichier déplacé dans ~/.ssh entre son ouverture et son jugement : son chemin réel, relu sur le descripteur,
    /// n'est plus sous un endroit permis.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_fichier_deplace_apres_l_ouverture_est_rejuge() {
        let b = Banc::nouveau("course-fichier");
        let (tele, ssh) = (b.tele.clone(), b.maison.join(".ssh"));
        poser_crochet(Some(Box::new(move |e| {
            if e == Etape::Fichier {
                std::fs::rename(tele.join("x.pdf"), ssh.join("x.pdf")).unwrap();
            }
        })));
        assert_eq!(b.ouvrir("~/Téléchargements/x.pdf").err(), Some(Refus::HorsDesEndroits));
    }

    /// ~/Documents lié à ~/Nextcloud/Documents : la racine est la cible, résolue une fois quand les racines sont
    /// faites. Le lien changé ensuite vers ~/.ssh ne fait rien lire de ~/.ssh ; la cible changée en lien est refusée.
    #[cfg(target_os = "linux")]
    #[test]
    fn une_racine_liee_se_lit_par_sa_cible_resolue_une_fois() {
        use std::os::unix::fs::symlink;
        let mut b = Banc::nouveau("racine-liee");
        let cible = b.maison.join("Nextcloud/Documents");
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::write(cible.join("a.pdf"), b"%PDF-1.7 contrat").unwrap();
        symlink("Nextcloud/Documents", b.maison.join("Documents")).unwrap();
        b.racines = valeur_console::racines_linux(&b.maison, "", None);
        assert_eq!(b.ouvrir("~/Documents/a.pdf").unwrap().chemin, cible.join("a.pdf"));
        std::fs::remove_file(b.maison.join("Documents")).unwrap();
        symlink(".ssh", b.maison.join("Documents")).unwrap();
        assert_eq!(b.ouvrir("~/Documents/id_ed25519").err(), Some(Refus::Introuvable));
        std::fs::rename(&cible, b.maison.join("Nextcloud/vrai")).unwrap();
        symlink(b.maison.join(".ssh"), &cible).unwrap();
        assert_eq!(b.ouvrir("~/Documents/id_ed25519").err(), Some(Refus::Lien));
    }

    /// Un lien physique vers la clé posé dans Téléchargements est un autre nom du même fichier : refusé.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_lien_physique_est_refuse() {
        let b = Banc::nouveau("lien-physique");
        std::fs::hard_link(b.maison.join(".ssh/id_ed25519"), b.tele.join("cle.pdf")).unwrap();
        assert_eq!(b.ouvrir("~/Téléchargements/cle.pdf").err(), Some(Refus::PlusieursNoms));
    }

    /// Le reste des refus de la descente : un lien au bout ou en route, un tube nommé (sans attendre), un dossier, un
    /// absent ; hors des endroits, le même refus que le fichier existe ou non ; la liste d'empreintes voisine posée en
    /// lien n'est pas lue.
    #[cfg(target_os = "linux")]
    #[test]
    fn la_descente_refuse_ce_qui_n_est_pas_un_fichier_permis() {
        use std::os::unix::fs::symlink;
        let b = Banc::nouveau("refus");
        symlink(b.maison.join(".ssh/id_ed25519"), b.tele.join("cle.pdf")).unwrap();
        symlink(b.maison.join(".ssh"), b.tele.join("ssh")).unwrap();
        let tube = std::process::Command::new("mkfifo").arg(b.tele.join("tube")).status();
        assert!(tube.is_ok_and(|s| s.success()), "mkfifo");
        for (texte, refus) in [
            ("~/Téléchargements/cle.pdf", Refus::Lien),
            ("~/Téléchargements/ssh/y.pdf", Refus::Lien),
            ("~/Téléchargements/tube", Refus::PasUnFichier),
            ("~/Téléchargements/sous", Refus::PasUnFichier),
            ("~/Téléchargements/absent.pdf", Refus::Introuvable),
            ("~/Téléchargements/absent/y.pdf", Refus::Introuvable),
            ("~/.ssh/id_ed25519", Refus::HorsDesEndroits),
            ("~/.ssh/absent", Refus::HorsDesEndroits),
        ] {
            assert_eq!(b.ouvrir(texte).err(), Some(refus), "{texte}");
        }
        let juge = b.ouvrir("~/Téléchargements/sous/y.pdf").unwrap();
        assert_eq!(juge.taille, 15);
        std::fs::write(b.tele.join("sous/SHA256SUMS"), b"abc  y.pdf\n").unwrap();
        assert_eq!(juge.lire_voisin("SHA256SUMS", 1024).unwrap(), b"abc  y.pdf\n");
        std::fs::remove_file(b.tele.join("sous/SHA256SUMS")).unwrap();
        symlink(b.maison.join(".ssh/id_ed25519"), b.tele.join("sous/SHA256SUMS")).unwrap();
        assert!(juge.lire_voisin("SHA256SUMS", 1024).is_err());
    }

    /// Le banc sous Windows : dans le dossier temporaire de Windows (sur C:, dans le préfixe jetable sous Wine), où la
    /// descente part d'une lettre de lecteur ; `essais::temporaire` passerait par Z:, la racine Unix montée par Wine.
    #[cfg(windows)]
    fn banc_windows(nom: &str) -> (PathBuf, PathBuf, Vec<Racine>) {
        let d = std::env::temp_dir().join(format!("vanguard-ouvrir-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let maison = d.join("alice");
        let tele = maison.join("Downloads");
        std::fs::create_dir_all(tele.join("sous")).unwrap();
        std::fs::create_dir_all(maison.join(".ssh")).unwrap();
        std::fs::write(tele.join("x.pdf"), b"%PDF-1.7 facture").unwrap();
        std::fs::write(maison.join(".ssh").join("id_ed25519"), b"fausse cle").unwrap();
        (d, maison, vec![Racine::meme(tele)])
    }

    /// Sous Windows : le fichier s'ouvre et se lit par sa poignée ; tant qu'il est tenu, ni lui ni le dossier
    /// au-dessus ne s'effacent ni ne se renomment (aucun partage de suppression) ; un lien physique est refusé ; un
    /// nom caché aussi ; et une racine qui n'est pas sur un disque n'est jamais ouverte.
    #[cfg(windows)]
    #[test]
    fn la_descente_windows_tient_et_juge() {
        let (d, maison, racines) = banc_windows("descente");
        let tele = racines[0].reelle.clone();
        let juge = ouvrir_juge(&tele.join("x.pdf").to_string_lossy(), &maison, &racines).unwrap();
        assert_eq!(
            crate::protection::courriel_suspect::octets_juges(&juge).as_deref(),
            Some(&b"%PDF-1.7 facture"[..])
        );
        assert!(std::fs::remove_file(tele.join("x.pdf")).is_err());
        // Un dossier tenu avec un accès de liste, sans partage de suppression : ni Windows ni Wine ne le renomment
        // (un accès aux attributs seul ne faisait pas appliquer le partage).
        assert!(std::fs::rename(&tele, maison.join("Downloads-vrai")).is_err());
        drop(juge);
        std::fs::hard_link(maison.join(".ssh").join("id_ed25519"), tele.join("cle.pdf")).unwrap();
        assert_eq!(
            ouvrir_juge(&tele.join("cle.pdf").to_string_lossy(), &maison, &racines).err(),
            Some(Refus::PlusieursNoms)
        );
        let reseau = [Racine::meme(PathBuf::from(r"\\127.0.0.1\absent\Downloads"))];
        assert_eq!(
            systeme::descendre(&reseau[0].reelle, &[], OsStr::new("x.pdf")).err(),
            Some(Refus::Reseau)
        );
        poser_crochet(None);
        let cache = tele.join("cache.pdf");
        std::fs::write(&cache, b"x").unwrap();
        let attrib = std::process::Command::new("attrib").arg("+h").arg(&cache).status();
        if attrib.is_ok_and(|s| s.success()) {
            assert_eq!(
                ouvrir_juge(&cache.to_string_lossy(), &maison, &racines).err(),
                Some(Refus::Cache)
            );
        } else {
            crate::essais::saute("attrib absent : l'attribut caché n'est pas essayé");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sous Windows : un nom s'ouvre sous la poignée du dossier, jamais par son chemin complet. Le dossier `sous`,
    /// ouvert ici avec un partage de suppression (pour que Wine laisse le renommer), renommé, et un autre `sous\y.pdf`
    /// posé à sa place : c'est le premier qui est lu. Une ouverture par chemin lirait le fichier posé. Un nom qui
    /// n'est pas simple est refusé avant toute ouverture.
    #[cfg(windows)]
    #[test]
    fn un_nom_s_ouvre_sous_la_poignee_du_dossier() {
        use std::io::Read as _;
        use std::os::windows::fs::OpenOptionsExt as _;
        let (d, _, racines) = banc_windows("poignee");
        let tele = racines[0].reelle.clone();
        std::fs::write(tele.join("sous").join("y.pdf"), b"%PDF-1.7 releve").unwrap();
        let tenu = std::fs::OpenOptions::new()
            .access_mode(0x0001 | 0x0020 | 0x0080 | 0x0010_0000)
            .share_mode(0x7)
            .custom_flags(0x0200_0000)
            .open(tele.join("sous"))
            .unwrap();
        std::fs::rename(tele.join("sous"), tele.join("sous-vrai")).unwrap();
        std::fs::create_dir(tele.join("sous")).unwrap();
        std::fs::write(tele.join("sous").join("y.pdf"), b"%PDF-1.7 piege").unwrap();
        let (mut f, _) = systeme::ouvrir_sous(&tenu, OsStr::new("y.pdf"), true, true).unwrap();
        let mut lu = Vec::new();
        f.read_to_end(&mut lu).unwrap();
        assert_eq!(lu, b"%PDF-1.7 releve");
        for nom in ["", ".", "..", r"..\x.pdf", "a/b", "c:x", "a\0b"] {
            assert_eq!(
                systeme::ouvrir_sous(&tenu, OsStr::new(nom), true, true).err(),
                Some(Refus::Forme),
                "{nom:?}"
            );
        }
        assert_eq!(
            systeme::ouvrir_sous(&tenu, OsStr::new("absent.pdf"), true, true).err(),
            Some(Refus::Introuvable)
        );
        drop((f, tenu));
        let _ = std::fs::remove_dir_all(&d);
    }
}
