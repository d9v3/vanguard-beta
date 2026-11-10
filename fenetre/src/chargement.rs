//! Windows : d'où viennent les DLL de la fenêtre. Comme `vanguard.exe` (src/machine/windows/chargement.rs, d'où ce
//! module est recopié : la fenêtre est un programme à part, sans le code du moteur), deux gardes.
//!
//! 1. La configuration de chargement du programme (IMAGE_LOAD_CONFIG_DIRECTORY64), pour un seul champ :
//!    DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32. Sans lui, le chargeur cherche les DLL importées qui ne sont
//!    pas des « DLL connues » d'abord à côté du programme, avant sa première ligne : une DLL posée dans
//!    Téléchargements ou sur la clé USB, à côté de vanguard-fenetre.exe, tournerait dans la fenêtre. GNU ld remplit le
//!    répertoire « Load Config » du PE dès qu'un symbole `_load_config_used` existe (fenetre/build.rs l'exige).
//! 2. Les DLL chargées après le démarrage, par leur nom (opengl32.dll, que glutin ouvre par LoadLibraryW, n'est pas
//!    une « DLL connue ») : SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), première ligne de `main`.
//!
//! `vanguard deploiement verifier-binaire --attendu windows` relit le champ dans le .exe compilé (outils/verifier.sh).

/// LOAD_LIBRARY_SEARCH_SYSTEM32 : une DLL cherchée par son nom ne vient que de System32 (la valeur de src/pe.rs).
const SYSTEM32_SEULEMENT: u16 = 0x800;

/// IMAGE_LOAD_CONFIG_DIRECTORY64 jusqu'à GuardFlags (148 octets, la forme de Windows 8.1) : tout à zéro (ni cookie,
/// ni SafeSEH, ni CFG), sauf la taille et DependentLoadFlags.
#[repr(C)]
pub(crate) struct ConfigurationDeChargement {
    taille: u32,
    horodatage: u32,
    versions: [u16; 2],
    drapeaux_globaux: [u32; 2],
    delai_sections_critiques: u32,
    /// DeCommitFreeBlockThreshold … ProcessAffinityMask.
    seuils: [u64; 6],
    drapeaux_du_tas: u32,
    version_csd: u16,
    drapeaux_des_dependances: u16,
    /// EditList, SecurityCookie, SEHandlerTable, SEHandlerCount et les quatre champs de CFG.
    pointeurs: [u64; 8],
    drapeaux_de_garde: u32,
}

/// Taille annoncée : jusqu'à GuardFlags compris (sans le bourrage final de la structure Rust).
const TAILLE: u32 = 148;

// Le nom est imposé par l'éditeur de liens ; `#[used]` le garde même si rien ne le lit.
#[allow(non_upper_case_globals)]
// `#[unsafe(no_mangle)]` : le nom _load_config_used est imposé par l'éditeur de liens de Windows.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
#[used]
pub(crate) static _load_config_used: ConfigurationDeChargement = ConfigurationDeChargement {
    taille: TAILLE,
    horodatage: 0,
    versions: [0; 2],
    drapeaux_globaux: [0; 2],
    delai_sections_critiques: 0,
    seuils: [0; 6],
    drapeaux_du_tas: 0,
    version_csd: 0,
    drapeaux_des_dependances: SYSTEM32_SEULEMENT,
    pointeurs: [0; 8],
    drapeaux_de_garde: 0,
};

// FFI de kernel32 : SetDefaultDllDirectories.
#[allow(unsafe_code)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetDefaultDllDirectories(drapeaux: u32) -> i32;
}

/// Toute DLL chargée par son nom après ce point (par la fenêtre ou une bibliothèque) ne vient que de System32. Rend
/// faux si Windows a refusé : la fenêtre ne s'ouvre pas alors (main.rs), plutôt que de charger opengl32.dll d'à côté.
// FFI de kernel32 : un simple réglage du processus.
#[allow(unsafe_code)]
pub(crate) fn system32_seulement() -> bool {
    // SAFETY: simple réglage du processus, sans pointeur ; la fonction existe depuis Windows 8 (KB2533623 pour 7).
    unsafe { SetDefaultDllDirectories(u32::from(SYSTEM32_SEULEMENT)) != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_structure_a_la_forme_de_windows() {
        assert_eq!(
            std::mem::offset_of!(ConfigurationDeChargement, drapeaux_des_dependances),
            78
        );
        assert_eq!(std::mem::offset_of!(ConfigurationDeChargement, drapeaux_de_garde), 144);
        assert!(std::mem::size_of::<ConfigurationDeChargement>() >= TAILLE as usize);
        assert_eq!(_load_config_used.drapeaux_des_dependances, 0x800);
    }
}
