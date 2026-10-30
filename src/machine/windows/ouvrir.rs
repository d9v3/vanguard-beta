//! Ouvrir un fichier, un dossier ou une adresse avec le programme que Windows y associe, par ShellExecuteExW plutôt
//! que `cmd /C start` : cmd remplaçait encore les « %VAR% » d'un lien ou d'un chemin (« %USERPROFILE% » dans une
//! adresse était réécrit), et plus rien ne passe par un interprète de commandes.
//!
//! ShellExecute peut déléguer à des extensions du Shell qui veulent COM en appartement à un seul fil (STA) : chaque
//! ouverture a son propre fil, où COM est ouvert ainsi, sans dépendre de l'appartement du fil appelant (un fil WMI
//! est en MTA). L'appelant n'attend pas que l'application associée démarre, comme avec `start` ; seul `attendre`,
//! à la fin du programme, laisse aux ouvertures en cours le temps d'aboutir avant que le processus ne disparaisse.
//!
//! Comme `start`, « open » sur un programme le lancerait : les appelants ne passent que des pages et des dossiers
//! écrits par Vanguard, des adresses de ses listes fermées et des pages de réglages de Windows, jamais un chemin
//! choisi par quelqu'un d'autre.

use std::ffi::c_void;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::System::Com::{
    COINIT, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};

#[link(name = "shell32")]
unsafe extern "system" {
    /// shellapi.h : BOOL ShellExecuteExW(SHELLEXECUTEINFOW *). Déclarée ici aussi (eleve.rs a la sienne, pour
    /// « runas ») : l'élévation reste dans son module.
    fn ShellExecuteExW(info: *mut InfoOuverture) -> i32;
}

/// SHELLEXECUTEINFOW (112 octets en 64 bits, hInstApp à 56 : vérifié contre shellapi.h de MinGW).
#[repr(C)]
struct InfoOuverture {
    taille: u32,
    masque: u32,
    fenetre: *mut c_void,
    verbe: *const u16,
    fichier: *const u16,
    parametres: *const u16,
    dossier: *const u16,
    affichage: i32,
    instance: *mut c_void,
    liste: *mut c_void,
    classe: *const u16,
    cle: *mut c_void,
    raccourci: u32,
    icone: *mut c_void,
    processus: *mut c_void,
}

const SW_SHOWNORMAL: i32 = 1;
/// SEE_MASK_NOASYNC : ce fil n'a pas de boucle de messages et finit juste après l'appel ; sans ce drapeau, une
/// ouverture confiée à DDE pourrait ne jamais aboutir (SHELLEXECUTEINFOW, remarques).
const SANS_ASYNCHRONE: u32 = 0x100;

/// Les ouvertures lancées et pas encore attendues.
static EN_COURS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// Un texte en UTF-16 terminé par un zéro ; `None` s'il contient lui-même un zéro, qui couperait la cible sans le dire.
fn large(texte: &str) -> Option<Vec<u16>> {
    (!texte.contains('\0')).then(|| texte.encode_utf16().chain(Some(0)).collect())
}

/// Ouvre `cible` (fichier, dossier, adresse) ; `parametres` seulement pour un programme du système à qui les passer
/// (control.exe, par son chemin entier). Ne rend rien : en cas d'échec, Windows montre lui-même son message (pas de
/// SEE_MASK_FLAG_NO_UI).
pub(crate) fn ouvrir(cible: &str, parametres: Option<&str>) {
    let Some(fichier) = large(cible) else {
        return;
    };
    let parametres = match parametres.map(large) {
        Some(None) => return,
        Some(Some(p)) => Some(p),
        None => None,
    };
    let fil = std::thread::Builder::new().name("ouvrir".into()).spawn(move || {
        let verbe: Vec<u16> = "open\0".encode_utf16().collect();
        // SAFETY: fil créé pour cette seule ouverture ; l'appartement n'est rendu que s'il a été ouvert ici.
        let com =
            unsafe { CoInitializeEx(None, COINIT(COINIT_APARTMENTTHREADED.0 | COINIT_DISABLE_OLE1DDE.0)) }.is_ok();
        let mut info = InfoOuverture {
            taille: u32::try_from(std::mem::size_of::<InfoOuverture>()).unwrap_or(0),
            masque: SANS_ASYNCHRONE,
            fenetre: std::ptr::null_mut(),
            verbe: verbe.as_ptr(),
            fichier: fichier.as_ptr(),
            parametres: parametres.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
            dossier: std::ptr::null(),
            affichage: SW_SHOWNORMAL,
            instance: std::ptr::null_mut(),
            liste: std::ptr::null_mut(),
            classe: std::ptr::null(),
            cle: std::ptr::null_mut(),
            raccourci: 0,
            icone: std::ptr::null_mut(),
            processus: std::ptr::null_mut(),
        };
        // SAFETY: la structure est à nous, de la taille qu'elle annonce ; les textes qu'elle pointe sont à ce fil,
        // terminés par un zéro et vivants pendant l'appel, synchrone avec SEE_MASK_NOASYNC. Sans
        // SEE_MASK_NOCLOSEPROCESS, aucune poignée n'est rendue.
        unsafe {
            ShellExecuteExW(&raw mut info);
        }
        if com {
            // SAFETY: rend l'appartement ouvert par le CoInitializeEx réussi de ce même fil.
            unsafe { CoUninitialize() };
        }
    });
    if let Ok(fil) = fil
        && let Ok(mut en_cours) = EN_COURS.lock()
    {
        en_cours.retain(|f| !f.is_finished());
        en_cours.push(fil);
    }
}

/// Laisse aux ouvertures en cours jusqu'à `delai` pour aboutir : à la fin du programme, un fil encore en route
/// disparaîtrait avec le processus, et la page ne s'ouvrirait jamais.
pub(crate) fn attendre(delai: Duration) {
    let fils = EN_COURS.lock().map(|mut f| std::mem::take(&mut *f)).unwrap_or_default();
    let fin = Instant::now() + delai;
    for fil in fils {
        while !fil.is_finished() && Instant::now() < fin {
            std::thread::sleep(Duration::from_millis(20));
        }
        if fil.is_finished() {
            let _ = fil.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textes_larges() {
        assert_eq!(large("ab"), Some(vec![u16::from(b'a'), u16::from(b'b'), 0]));
        // « %PATH% » reste du texte : plus aucun interprète ne le remplace.
        assert_eq!(
            large("https://exemple.org/%PATH%").map(|l| String::from_utf16_lossy(&l[..l.len() - 1])),
            Some("https://exemple.org/%PATH%".into())
        );
        assert_eq!(large("a\0b"), None);
        assert_eq!(std::mem::size_of::<InfoOuverture>(), 112);
        assert_eq!(std::mem::offset_of!(InfoOuverture, instance), 56);
        // Sans ouverture en cours, rien à attendre.
        attendre(Duration::from_millis(1));
    }
}
