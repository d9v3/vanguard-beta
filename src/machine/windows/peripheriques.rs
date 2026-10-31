//! Les périphériques présents d'une classe (cartes graphiques, cartes son…), lus par SetupAPI sans PowerShell ni WMI :
//! leur nom, la clé de leur pilote dans le registre (version, date) et s'ils fonctionnent. Ce que Win32_VideoController
//! et Win32_SoundDevice listent, sans les appareils débranchés dont Windows garde le pilote.

// FFI de setupapi et cfgmgr32 : SetupDiGetClassDevsW, CM_Get_DevNode_Status…
#![allow(unsafe_code)]

use std::ffi::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// Cartes graphiques : {4d36e968-e325-11ce-bfc1-08002be10318}.
pub(crate) const AFFICHAGE: Guid = Guid {
    data1: 0x4d36_e968,
    data2: 0xe325,
    data3: 0x11ce,
    data4: [0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18],
};

/// Son, vidéo et jeu (ce que Win32_SoundDevice liste) : {4d36e96c-e325-11ce-bfc1-08002be10318}.
pub(crate) const SON: Guid = Guid {
    data1: 0x4d36_e96c,
    ..AFFICHAGE
};

#[repr(C)]
struct InfoAppareil {
    taille: u32,
    classe: Guid,
    instance: u32,
    reserve: usize,
}

#[link(name = "setupapi")]
unsafe extern "system" {
    fn SetupDiGetClassDevsW(
        classe: *const Guid,
        enumerateur: *const u16,
        fenetre: *mut c_void,
        drapeaux: u32,
    ) -> *mut c_void;
    fn SetupDiEnumDeviceInfo(liste: *mut c_void, index: u32, info: *mut InfoAppareil) -> i32;
    fn SetupDiGetDeviceRegistryPropertyW(
        liste: *mut c_void,
        info: *mut InfoAppareil,
        propriete: u32,
        sorte: *mut u32,
        tampon: *mut u8,
        taille: u32,
        requise: *mut u32,
    ) -> i32;
    fn SetupDiDestroyDeviceInfoList(liste: *mut c_void) -> i32;
}

#[link(name = "cfgmgr32")]
unsafe extern "system" {
    fn CM_Get_DevNode_Status(etat: *mut u32, probleme: *mut u32, instance: u32, drapeaux: u32) -> u32;
}

/// Un périphérique présent.
pub(crate) struct Peripherique {
    /// Nom affiché (nom convivial, sinon description du pilote), tel que le pilote le donne.
    pub nom: String,
    /// Sa clé sous `HKLM\SYSTEM\CurrentControlSet\Control\Class` (« {4d36e968-…}\0000 »), où vivent DriverVersion et
    /// DriverDate ; vide sans pilote installé.
    pub pilote: String,
    /// Démarré sans problème signalé (Status « OK » de WMI).
    pub marche: bool,
}

/// Les périphériques présents de la classe ; `None` si SetupAPI refuse la liste (l'appelant ne conclut pas).
pub(crate) fn presents(classe: &Guid) -> Option<Vec<Peripherique>> {
    const PRESENTS: u32 = 0x2;
    const INVALIDE: isize = -1;
    const DESCRIPTION: u32 = 0x0;
    const PILOTE: u32 = 0x9;
    const NOM_CONVIVIAL: u32 = 0xC;
    const DEMARRE: u32 = 0x8;
    // SAFETY: la classe vit pendant l'appel ; la liste rendue (refus = INVALID_HANDLE_VALUE, vérifié) est détruite une
    // seule fois, à la fin. Chaque `InfoAppareil` est initialisé avec sa taille, comme SetupAPI l'exige.
    unsafe {
        let liste = SetupDiGetClassDevsW(classe, std::ptr::null(), std::ptr::null_mut(), PRESENTS);
        if liste.is_null() || liste as isize == INVALIDE {
            return None;
        }
        let mut appareils = Vec::new();
        for index in 0.. {
            let mut info = InfoAppareil {
                taille: u32::try_from(std::mem::size_of::<InfoAppareil>()).unwrap_or(0),
                classe: *classe,
                instance: 0,
                reserve: 0,
            };
            if SetupDiEnumDeviceInfo(liste, index, &raw mut info) == 0 {
                break;
            }
            let nom = propriete(liste, &mut info, NOM_CONVIVIAL)
                .or_else(|| propriete(liste, &mut info, DESCRIPTION))
                .unwrap_or_default();
            let pilote = propriete(liste, &mut info, PILOTE).unwrap_or_default();
            let (mut etat, mut probleme) = (0u32, 0u32);
            let marche = CM_Get_DevNode_Status(&raw mut etat, &raw mut probleme, info.instance, 0) == 0
                && etat & DEMARRE != 0
                && probleme == 0;
            appareils.push(Peripherique { nom, pilote, marche });
        }
        SetupDiDestroyDeviceInfoList(liste);
        Some(appareils)
    }
}

/// Une propriété texte d'un appareil (REG_SZ) ; `None` si elle manque.
///
/// # Safety
/// `liste` et `info` viennent de SetupDiGetClassDevsW et SetupDiEnumDeviceInfo, encore valides.
unsafe fn propriete(liste: *mut c_void, info: &mut InfoAppareil, propriete: u32) -> Option<String> {
    let mut requise = 0u32;
    let mut sorte = 0u32;
    // SAFETY: premier appel sans tampon pour la taille en octets (refus attendu) ; le second écrit au plus `taille`
    // octets dans `tampon`, qui les a, alignés pour des caractères UTF-16.
    unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            liste,
            info,
            propriete,
            &raw mut sorte,
            std::ptr::null_mut(),
            0,
            &raw mut requise,
        );
        if requise == 0 {
            return None;
        }
        let mut tampon = vec![0u16; usize::try_from(requise.div_ceil(2)).ok()?];
        let taille = u32::try_from(tampon.len() * 2).ok()?;
        if SetupDiGetDeviceRegistryPropertyW(
            liste,
            info,
            propriete,
            &raw mut sorte,
            tampon.as_mut_ptr().cast(),
            taille,
            &raw mut requise,
        ) == 0
        {
            return None;
        }
        Some(texte(&tampon)).filter(|t| !t.is_empty())
    }
}

/// Un texte UTF-16 arrêté au premier zéro.
fn texte(large: &[u16]) -> String {
    String::from_utf16_lossy(large.split(|&c| c == 0).next().unwrap_or(large))
        .trim()
        .to_string()
}

/// La clé du pilote d'un appareil, ouverte en lecture ; `None` sans pilote.
pub(crate) fn cle_du_pilote(p: &Peripherique) -> Option<winreg::RegKey> {
    if p.pilote.is_empty() || p.pilote.contains("..") {
        return None;
    }
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SYSTEM\CurrentControlSet\Control\Class\{}", p.pilote))
        .ok()
}

/// « 1-10-2025 » (DriverDate, mois-jour-année, sans zéros) → « 2025-01-10 ».
pub(crate) fn date_du_pilote(texte: &str) -> Option<String> {
    let mut c = texte.trim().split('-').map(|x| x.parse::<u32>().ok());
    let (mois, jour, annee) = (c.next()??, c.next()??, c.next()??);
    if c.next().is_some() {
        return None;
    }
    chrono::NaiveDate::from_ymd_opt(i32::try_from(annee).ok()?, mois, jour).map(|d| d.format("%Y-%m-%d").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_des_pilotes() {
        assert_eq!(date_du_pilote("1-10-2025").as_deref(), Some("2025-01-10"));
        assert_eq!(date_du_pilote("12-31-2024").as_deref(), Some("2024-12-31"));
        assert_eq!(date_du_pilote("13-1-2024"), None);
        assert_eq!(date_du_pilote("1-10"), None);
        assert_eq!(date_du_pilote("1-10-2025-1"), None);
        assert_eq!(date_du_pilote(""), None);
    }

    #[test]
    fn textes_larges() {
        let t: Vec<u16> = "Carte\0reste".encode_utf16().collect();
        assert_eq!(texte(&t), "Carte");
        assert_eq!(texte(&[]), "");
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : la liste se lit, sans planter.
    #[test]
    fn peripheriques_lus_par_windows() {
        for classe in [&AFFICHAGE, &SON] {
            if let Some(liste) = presents(classe) {
                for p in &liste {
                    let _ = cle_du_pilote(p);
                }
            }
        }
    }
}
