//! La configuration de chargement du programme Windows (IMAGE_LOAD_CONFIG_DIRECTORY64), pour un seul champ :
//! DependentLoadFlags = LOAD_LIBRARY_SEARCH_SYSTEM32. Sans lui, le chargeur cherche les DLL importées qui ne sont pas
//! des « DLL connues » (iphlpapi, userenv, wevtapi…) d'abord à côté du programme, avant même sa première ligne : une
//! DLL posée dans Téléchargements ou sur la clé USB tournerait dans Vanguard, et en administrateur quand Vanguard se
//! relance pour une correction (eleve.rs). Aucun contrôle fait par le programme ne peut fermer ça : il arrive trop
//! tard. Avec ce champ (Windows 10 1607 et plus), les imports ne viennent que de System32.
//!
//! GNU ld n'a pas d'option pour ce champ, mais il remplit le répertoire « Load Config » du PE dès qu'un symbole
//! `_load_config_used` existe, avec la taille lue dans son premier mot ; le CRT de MinGW n'en fournit pas. Un test lit
//! le programme compilé pour vérifier que le champ y est bien ; le déploiement le relit dans vanguard.exe (`crate::pe`).

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

// La valeur vient du module commun, celui que le déploiement relit sous Linux : les deux ne peuvent pas diverger.
use crate::pe::SYSTEM32_SEULEMENT;

/// Taille annoncée : jusqu'à GuardFlags compris (sans le bourrage final de la structure Rust).
pub(crate) const TAILLE: u32 = 148;

// Le nom est imposé par l'éditeur de liens ; `#[used]` le garde même si rien ne le lit.
#[allow(non_upper_case_globals)]
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
    }

    /// Le programme compilé (ici, celui des tests, fait du même code) porte bien le champ : sans lui, une DLL posée à
    /// côté de Vanguard serait chargée avant sa première ligne.
    #[test]
    fn le_programme_ne_charge_ses_dll_que_depuis_system32() {
        let exe = std::env::current_exe().unwrap();
        let gardes = crate::pe::gardes(&exe).unwrap_or_else(|e| panic!("{}: {e:?}", exe.display()));
        assert_eq!(
            gardes.load_config,
            Some(crate::pe::LoadConfig {
                taille_repertoire: TAILLE,
                taille: TAILLE,
                drapeaux: SYSTEM32_SEULEMENT
            })
        );
        assert!(gardes.load_config.is_some_and(|c| c.system32_seulement()));
    }
}
