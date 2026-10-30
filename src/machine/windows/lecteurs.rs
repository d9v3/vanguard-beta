//! Les lecteurs de Windows (C:, E:…) lus par kernel32 sans PowerShell : ce que `[IO.DriveInfo]`, `Get-Volume` et
//! `Get-Partition` donnaient (sorte, étiquette, place, système de fichiers, numéro du disque).

use std::ffi::c_void;
use std::path::{Path, PathBuf};

/// Un lecteur prêt (un disque est dedans).
#[derive(Debug, Clone)]
pub(crate) struct Lecteur {
    /// « E:\ ».
    pub racine: PathBuf,
    pub amovible: bool,
    pub etiquette: String,
    /// La place que ce compte peut utiliser (AvailableFreeSpace), puis la taille du lecteur.
    pub libre: u64,
    pub total: u64,
    /// « NTFS », « FAT32 », « exFAT ».
    pub format: String,
    /// Le numéro du disque qui porte le lecteur (DiskNumber de Get-Partition).
    pub disque: Option<u32>,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(racine: *const u16) -> u32;
    fn GetVolumeInformationW(
        racine: *const u16,
        etiquette: *mut u16,
        taille_etiquette: u32,
        serie: *mut u32,
        longueur_max: *mut u32,
        drapeaux: *mut u32,
        format: *mut u16,
        taille_format: u32,
    ) -> i32;
    fn GetDiskFreeSpaceExW(racine: *const u16, disponible: *mut u64, total: *mut u64, libre: *mut u64) -> i32;
    fn SetThreadErrorMode(nouveau: u32, ancien: *mut u32) -> i32;
    fn CreateFileW(
        nom: *const u16,
        acces: u32,
        partage: u32,
        securite: *mut c_void,
        creation: u32,
        drapeaux: u32,
        modele: *mut c_void,
    ) -> *mut c_void;
    fn DeviceIoControl(
        appareil: *mut c_void,
        code: u32,
        entree: *mut c_void,
        taille_entree: u32,
        sortie: *mut c_void,
        taille_sortie: u32,
        rendus: *mut u32,
        recouvrement: *mut c_void,
    ) -> i32;
    fn CloseHandle(objet: *mut c_void) -> i32;
}

fn large(t: &str) -> Vec<u16> {
    t.encode_utf16().chain([0]).collect()
}

fn texte(t: &[u16]) -> String {
    String::from_utf16_lossy(t.split(|&c| c == 0).next().unwrap_or(t))
}

/// Un lecteur par sa racine (« E:\ ») s'il est prêt, sinon `None` (lecteur de cartes vide, réseau coupé).
pub(crate) fn lecteur(racine: &Path) -> Option<Lecteur> {
    const AMOVIBLE: u32 = 2;
    const SANS_FENETRE_D_ERREUR: u32 = 0x1;
    let r = racine.to_string_lossy();
    // Seulement « X: » ou « X:\… » : un chemin réseau (« UNC\nas\partage ») n'est pas le lecteur U:.
    let mut caracteres = r.chars();
    let lettre = caracteres.next().filter(char::is_ascii_alphabetic)?;
    if caracteres.next() != Some(':') {
        return None;
    }
    let r = large(&format!("{lettre}:\\"));
    let (mut etiquette, mut format) = (vec![0u16; 261], vec![0u16; 261]);
    let (mut serie, mut longueur, mut drapeaux) = (0u32, 0u32, 0u32);
    let (mut disponible, mut total, mut libre) = (0u64, 0u64, 0u64);
    let mut ancien = 0u32;
    // SAFETY: la racine est terminée par un zéro et vit pendant les appels ; Windows écrit au plus 261 caractères
    // dans chaque tampon, qui les a, et un nombre dans chaque variable. Le mode d'erreur du fil (pas de fenêtre « Il
    // n'y a pas de disque dans le lecteur ») est remis comme avant.
    let pret = unsafe {
        SetThreadErrorMode(SANS_FENETRE_D_ERREUR, &raw mut ancien);
        let pret = GetVolumeInformationW(
            r.as_ptr(),
            etiquette.as_mut_ptr(),
            261,
            &raw mut serie,
            &raw mut longueur,
            &raw mut drapeaux,
            format.as_mut_ptr(),
            261,
        ) != 0
            && GetDiskFreeSpaceExW(r.as_ptr(), &raw mut disponible, &raw mut total, &raw mut libre) != 0;
        SetThreadErrorMode(ancien, std::ptr::null_mut());
        pret
    };
    if !pret {
        return None;
    }
    // SAFETY: la racine est terminée par un zéro et vit pendant l'appel.
    let sorte = unsafe { GetDriveTypeW(r.as_ptr()) };
    Some(Lecteur {
        racine: PathBuf::from(format!("{lettre}:\\")),
        amovible: sorte == AMOVIBLE,
        etiquette: texte(&etiquette),
        libre: disponible,
        total,
        format: texte(&format),
        disque: numero_du_disque(lettre),
    })
}

/// Les lecteurs prêts, fixes ou amovibles (ni réseau, ni CD, ni disque en mémoire), dans l'ordre des lettres.
pub(crate) fn lecteurs() -> Vec<Lecteur> {
    const AMOVIBLE: u32 = 2;
    const FIXE: u32 = 3;
    // SAFETY: sans paramètre ; rend un masque d'un bit par lettre.
    let masque = unsafe { GetLogicalDrives() };
    (0u8..26)
        .filter(|i| masque & (1 << i) != 0)
        .map(|i| char::from(b'A' + i))
        .filter(|l| {
            let r = large(&format!("{l}:\\"));
            // SAFETY: la racine est terminée par un zéro et vit pendant l'appel.
            matches!(unsafe { GetDriveTypeW(r.as_ptr()) }, AMOVIBLE | FIXE)
        })
        .filter_map(|l| lecteur(Path::new(&format!("{l}:\\"))))
        .collect()
}

/// Le numéro du disque physique d'un lecteur (IOCTL_STORAGE_GET_DEVICE_NUMBER, sans droits particuliers).
fn numero_du_disque(lettre: char) -> Option<u32> {
    const LIRE_ECRIRE_PARTAGES: u32 = 0x1 | 0x2;
    const EXISTANT: u32 = 3;
    const NUMERO: u32 = 0x002D_1080;
    #[repr(C)]
    #[derive(Default)]
    struct Numero {
        sorte: u32,
        disque: u32,
        partition: u32,
    }
    let nom = large(&format!(r"\\.\{lettre}:"));
    let mut n = Numero::default();
    let mut rendus = 0u32;
    // SAFETY: le nom vit pendant l'appel ; la poignée (INVALID_HANDLE_VALUE : refus, vérifié) est fermée une seule
    // fois ; Windows écrit au plus la taille de `n` dans `n`.
    unsafe {
        let appareil = CreateFileW(
            nom.as_ptr(),
            0,
            LIRE_ECRIRE_PARTAGES,
            std::ptr::null_mut(),
            EXISTANT,
            0,
            std::ptr::null_mut(),
        );
        if appareil.is_null() || appareil as isize == -1 {
            return None;
        }
        let lu = DeviceIoControl(
            appareil,
            NUMERO,
            std::ptr::null_mut(),
            0,
            (&raw mut n).cast(),
            u32::try_from(std::mem::size_of::<Numero>()).unwrap_or(0),
            &raw mut rendus,
            std::ptr::null_mut(),
        ) != 0;
        CloseHandle(appareil);
        lu.then_some(n.disque)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un chemin réseau (ce qu'il reste de « \\?\UNC\nas\partage ») n'est pas le lecteur U:.
    #[test]
    fn chemin_reseau_pas_un_lecteur() {
        assert!(lecteur(Path::new("UNC")).is_none());
        assert!(lecteur(Path::new(r"UNC\nas\partage")).is_none());
        assert!(lecteur(Path::new("")).is_none());
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : le lecteur du système est prêt, a une taille, et
    /// les lecteurs listés sont fixes ou amovibles.
    #[test]
    fn lecteurs_lus_par_windows() {
        let systeme = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let c = lecteur(Path::new(&systeme)).expect("lecteur du système");
        assert!(c.total > 0 && c.libre <= c.total, "{c:?}");
        assert!(lecteurs().iter().any(|l| l.racine == c.racine));
        assert!(lecteur(Path::new("")).is_none());
    }
}
