//! Les imprimantes de Windows lues sans PowerShell : EnumPrintersW (nom, état, travaux en attente, port), l'imprimante
//! par défaut (GetDefaultPrinterW) et l'adresse des ports TCP/IP standard (registre). Ce que Get-Printer,
//! Get-PrintJob, Get-PrinterPort et Win32_Printer donnaient.

use std::ffi::c_void;

/// Une imprimante installée.
pub(crate) struct Imprimante {
    pub nom: String,
    /// En pause ou hors ligne.
    pub en_pause: bool,
    /// L'adresse de son port réseau (« 192.168.1.20 ») ; vide pour l'USB ou un port sans adresse.
    pub hote: String,
    pub en_attente: usize,
    pub par_defaut: bool,
}

/// PRINTER_INFO_2W de winspool.h.
#[repr(C)]
struct Info2 {
    serveur: *const u16,
    nom: *const u16,
    partage: *const u16,
    port: *const u16,
    pilote: *const u16,
    commentaire: *const u16,
    lieu: *const u16,
    mode: *const c_void,
    separateur: *const u16,
    processeur: *const u16,
    format: *const u16,
    parametres: *const u16,
    securite: *const c_void,
    attributs: u32,
    priorite: u32,
    priorite_par_defaut: u32,
    debut: u32,
    fin: u32,
    etat: u32,
    travaux: u32,
    pages_par_minute: u32,
}

#[link(name = "winspool")]
unsafe extern "system" {
    fn EnumPrintersW(
        sorte: u32,
        nom: *const u16,
        niveau: u32,
        tampon: *mut u8,
        taille: u32,
        requis: *mut u32,
        rendus: *mut u32,
    ) -> i32;
    fn GetDefaultPrinterW(nom: *mut u16, taille: *mut u32) -> i32;
}

/// Un texte UTF-16 terminé par un zéro, lu sur 32 767 caractères au plus.
///
/// # Safety
/// `p` est nul, ou désigne un texte terminé par un zéro qui vit pendant l'appel.
unsafe fn texte(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY: la borne est testée avant chaque lecture ; le texte se termine par un zéro (contrat de l'appelant).
    unsafe {
        while n < 32_767 && *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Les imprimantes de l'ordinateur et les connexions de ce compte (comme Get-Printer). Spouleur arrêté : la liste est
/// vide, comme le script la rendait.
pub(crate) fn imprimantes() -> Vec<Imprimante> {
    const LOCALES_ET_CONNEXIONS: u32 = 0x2 | 0x4;
    const EN_PAUSE: u32 = 0x1;
    const HORS_LIGNE: u32 = 0x80;
    /// PRINTER_ATTRIBUTE_WORK_OFFLINE : ce que Paramètres affiche « Hors ligne » (« Utiliser l'imprimante hors
    /// connexion », ou posé par le spouleur quand le port ne répond plus) ; Status reste alors à 0.
    const TRAVAIL_HORS_LIGNE: u32 = 0x400;
    let defaut = imprimante_par_defaut();
    let (mut requis, mut rendus) = (0u32, 0u32);
    // SAFETY: premier appel sans tampon pour la taille (refus attendu) ; le second écrit au plus `taille` octets dans
    // `tampon`, aligné pour les structures, qui les a. Les `rendus` structures sont lues seulement si elles tiennent
    // dans ce que Windows a écrit ; leurs textes vivent dans le tampon.
    unsafe {
        EnumPrintersW(
            LOCALES_ET_CONNEXIONS,
            std::ptr::null(),
            2,
            std::ptr::null_mut(),
            0,
            &raw mut requis,
            &raw mut rendus,
        );
        let Ok(octets) = usize::try_from(requis) else {
            return Vec::new();
        };
        if octets == 0 || octets > 16 << 20 {
            return Vec::new();
        }
        let mut tampon = vec![0u64; octets.div_ceil(8)];
        if EnumPrintersW(
            LOCALES_ET_CONNEXIONS,
            std::ptr::null(),
            2,
            tampon.as_mut_ptr().cast(),
            requis,
            &raw mut requis,
            &raw mut rendus,
        ) == 0
        {
            return Vec::new();
        }
        let n = usize::try_from(rendus).unwrap_or(0);
        if n.checked_mul(std::mem::size_of::<Info2>())
            .is_none_or(|t| t > tampon.len() * 8)
        {
            return Vec::new();
        }
        std::slice::from_raw_parts(tampon.as_ptr().cast::<Info2>(), n)
            .iter()
            .map(|i| {
                let nom = texte(i.nom);
                Imprimante {
                    en_pause: i.etat & (EN_PAUSE | HORS_LIGNE) != 0 || i.attributs & TRAVAIL_HORS_LIGNE != 0,
                    hote: hote_du_port(&texte(i.port)),
                    en_attente: usize::try_from(i.travaux).unwrap_or(0),
                    par_defaut: defaut.as_deref() == Some(nom.as_str()),
                    nom,
                }
            })
            .collect()
    }
}

/// Le nom de l'imprimante par défaut de ce compte ; `None` s'il n'y en a pas.
fn imprimante_par_defaut() -> Option<String> {
    let mut taille = 0u32;
    // SAFETY: premier appel sans tampon pour la taille en caractères (refus attendu) ; le second écrit au plus
    // `taille` caractères dans `nom`, qui les a.
    unsafe {
        GetDefaultPrinterW(std::ptr::null_mut(), &raw mut taille);
        if taille == 0 || taille > 32_767 {
            return None;
        }
        let mut nom = vec![0u16; usize::try_from(taille).ok()?];
        if GetDefaultPrinterW(nom.as_mut_ptr(), &raw mut taille) == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(nom.split(|&c| c == 0).next().unwrap_or(&nom)))
    }
}

/// L'adresse d'un port TCP/IP standard (PrinterHostAddress) : son nom d'hôte, sinon son adresse IP ; vide pour un autre
/// port (USB, WSD, fichier).
fn hote_du_port(port: &str) -> String {
    if port.is_empty() || port.contains('\\') {
        return String::new();
    }
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(
            r"SYSTEM\CurrentControlSet\Control\Print\Monitors\Standard TCP/IP Port\Ports\{port}"
        ))
        .ok()
        .and_then(|c| {
            ["HostName", "IPAddress"]
                .iter()
                .find_map(|v| c.get_value::<String, _>(v).ok().filter(|h| !h.trim().is_empty()))
        })
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le lecteur de texte UTF-16 (exercé sous Miri par outils/preuves.sh) : nul, vide, terminé, et la borne de
    /// 32 767 caractères respectée sans lire au-delà.
    #[test]
    fn texte_utf16_nul_termine_et_borne() {
        let t: Vec<u16> = "Imprimante é".encode_utf16().chain([0, 0x41]).collect();
        let mut long = vec![0x41u16; 32_768];
        long.push(0);
        // SAFETY: pointeur nul, ou tampons terminés par un zéro qui vivent pendant les appels.
        unsafe {
            assert_eq!(texte(std::ptr::null()), "");
            assert_eq!(texte([0u16].as_ptr()), "");
            assert_eq!(texte(t.as_ptr()), "Imprimante é");
            assert_eq!(texte(long.as_ptr()).len(), 32_767);
        }
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : la liste se lit sans planter, au plus une imprimante
    /// par défaut.
    #[test]
    fn imprimantes_lues_par_windows() {
        let l = imprimantes();
        assert!(l.iter().filter(|i| i.par_defaut).count() <= 1);
        assert!(l.iter().all(|i| !i.nom.is_empty()));
        assert_eq!(hote_du_port(r"..\..\x"), "");
        assert_eq!(hote_du_port("USB001"), "");
    }
}
