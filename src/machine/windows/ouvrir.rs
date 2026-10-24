//! Ouvrir un fichier, un dossier ou une adresse avec le programme que Windows y associe, par ShellExecuteW plutôt
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
    /// shellapi.h : HINSTANCE ShellExecuteW(HWND, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, INT).
    fn ShellExecuteW(
        fenetre: *mut c_void,
        verbe: *const u16,
        fichier: *const u16,
        parametres: *const u16,
        dossier: *const u16,
        montrer: i32,
    ) -> *mut c_void;
}

const SW_SHOWNORMAL: i32 = 1;

/// Les ouvertures lancées et pas encore attendues.
static EN_COURS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// Un texte en UTF-16 terminé par un zéro ; `None` s'il contient lui-même un zéro, qui couperait la cible sans le dire.
fn large(texte: &str) -> Option<Vec<u16>> {
    (!texte.contains('\0')).then(|| texte.encode_utf16().chain(Some(0)).collect())
}

/// Ouvre `cible` (fichier, dossier, adresse) ; `parametres` seulement pour un programme du système à qui les passer
/// (control.exe). Ne rend rien : en cas d'échec, Windows montre lui-même son message.
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
        // SAFETY : fil créé pour cette seule ouverture ; l'appartement n'est rendu que s'il a été ouvert ici.
        let com =
            unsafe { CoInitializeEx(None, COINIT(COINIT_APARTMENTTHREADED.0 | COINIT_DISABLE_OLE1DDE.0)) }.is_ok();
        // SAFETY : les trois textes sont à nous, terminés par un zéro et vivants pendant l'appel ; les pointeurs nuls
        // (fenêtre, paramètres absents, dossier) sont permis par shellapi.h. Le résultat n'est qu'un code, jamais un
        // module à libérer.
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verbe.as_ptr(),
                fichier.as_ptr(),
                parametres.as_ref().map_or(std::ptr::null(), Vec::as_ptr),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
        if com {
            // SAFETY : rend l'appartement ouvert par le CoInitializeEx réussi de ce même fil.
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
        // Sans ouverture en cours, rien à attendre.
        attendre(Duration::from_millis(1));
    }
}
