//! Les journaux d'événements copiés en .evtx et leur taille, par l'API des journaux de Windows (wevtapi) au lieu de
//! `wevtutil epl` et `wevtutil gli` : EvtExportLog écrit le même fichier, EvtOpenLog et EvtGetLogInfo
//! (EvtLogFileSize) disent la taille, sans texte traduit à lire ni page de code de la console. Un fichier à part,
//! avec ses propres déclarations : la lecture vivante des journaux (`evenements.rs`) suit son propre chemin.

use std::ffi::c_void;
use std::path::Path;
use std::time::Duration;

#[link(name = "wevtapi")]
unsafe extern "system" {
    /// winevt.h : BOOL EvtExportLog(EVT_HANDLE Session, LPCWSTR Path, LPCWSTR Query, LPCWSTR TargetFilePath, DWORD).
    fn EvtExportLog(
        session: *mut c_void,
        chemin: *const u16,
        requete: *const u16,
        fichier: *const u16,
        drapeaux: u32,
    ) -> i32;
    /// winevt.h : EVT_HANDLE EvtOpenLog(EVT_HANDLE Session, LPCWSTR Path, DWORD Flags).
    fn EvtOpenLog(session: *mut c_void, chemin: *const u16, drapeaux: u32) -> *mut c_void;
    /// winevt.h : BOOL EvtGetLogInfo(EVT_HANDLE, EVT_LOG_PROPERTY_ID, DWORD, PEVT_VARIANT, PDWORD).
    fn EvtGetLogInfo(journal: *mut c_void, propriete: u32, taille: u32, valeur: *mut c_void, utilise: *mut u32) -> i32;
    /// winevt.h : BOOL EvtClose(EVT_HANDLE).
    fn EvtClose(objet: *mut c_void) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
}

/// EvtExportLogChannelPath et EvtOpenChannelPath : `chemin` nomme un canal (« Security »), pas un fichier.
const CANAL: u32 = 1;
/// EvtLogFileSize (EVT_LOG_PROPERTY_ID).
const TAILLE_DU_FICHIER: u32 = 3;
/// EvtVarTypeUInt64.
const ENTIER_64: u32 = 10;

/// EVT_VARIANT : la valeur (8 octets), le nombre d'éléments, le genre (16 octets).
#[repr(C)]
#[derive(Default)]
struct Variante {
    valeur: u64,
    _nombre: u32,
    genre: u32,
}

fn large(texte: &str) -> Option<Vec<u16>> {
    (!texte.contains('\0')).then(|| texte.encode_utf16().chain(Some(0)).collect())
}

/// Pourquoi un export n'a pas abouti.
#[derive(Debug, PartialEq)]
pub(crate) enum Refus {
    /// Le code de Windows (GetLastError) : 5, accès refusé ; 15007, canal introuvable ; un autre, une autre raison.
    Code(u32),
    /// Pas de réponse dans le délai : la copie continue peut-être, elle n'est pas comptée.
    Delai,
}

/// Copie les événements du canal `journal` qui répondent à la requête XPath `requete` dans `fichier` (chemin
/// absolu, qui ne doit pas exister), comme `wevtutil epl`. L'appel, sans délai à lui, tourne dans un fil, attendu au
/// plus `delai` : un export qui finit après le délai écrit quand même son fichier, que l'appelant place hors du
/// dossier où il le compte.
pub(crate) fn exporter(journal: &str, requete: &str, fichier: &Path, delai: Duration) -> Result<(), Refus> {
    // ERROR_INVALID_PARAMETER : un texte qui contient un zéro n'est pas envoyé à Windows.
    const PARAMETRE_REFUSE: u32 = 87;
    let fichier = std::path::absolute(fichier).map_err(|_| Refus::Code(PARAMETRE_REFUSE))?;
    let (Some(canal), Some(requete), Some(cible)) = (large(journal), large(requete), large(&fichier.to_string_lossy()))
    else {
        return Err(Refus::Code(PARAMETRE_REFUSE));
    };
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("export-journal".into())
        .spawn(move || {
            // SAFETY : session nulle (cet ordinateur) ; les trois textes sont à ce fil, terminés par un zéro et
            // vivants pendant l'appel, synchrone ; GetLastError est lu juste après, dans le même fil.
            let code = unsafe {
                if EvtExportLog(
                    std::ptr::null_mut(),
                    canal.as_ptr(),
                    requete.as_ptr(),
                    cible.as_ptr(),
                    CANAL,
                ) != 0
                {
                    0
                } else {
                    GetLastError()
                }
            };
            let _ = envoi.send(code);
        })
        .map_err(|_| Refus::Code(0))?;
    match reception.recv_timeout(delai) {
        Ok(0) => Ok(()),
        Ok(code) => Err(Refus::Code(code)),
        Err(_) => Err(Refus::Delai),
    }
}

/// La taille du fichier d'un canal, en octets, comme « fileSize » de `wevtutil gli` ; `None` : canal introuvable,
/// accès refusé, ou une réponse d'un autre genre.
pub(crate) fn taille(journal: &str) -> Option<u64> {
    let canal = large(journal)?;
    // SAFETY : session nulle ; le nom est à nous, terminé par un zéro. La poignée rendue est vérifiée non nulle et
    // fermée une fois, après la dernière lecture.
    unsafe {
        let poignee = EvtOpenLog(std::ptr::null_mut(), canal.as_ptr(), CANAL);
        if poignee.is_null() {
            return None;
        }
        let mut v = Variante::default();
        let mut utilise = 0u32;
        let lu = EvtGetLogInfo(
            poignee,
            TAILLE_DU_FICHIER,
            u32::try_from(std::mem::size_of::<Variante>()).unwrap_or(0),
            (&raw mut v).cast(),
            &raw mut utilise,
        ) != 0;
        EvtClose(poignee);
        (lu && v.genre == ENTIER_64).then_some(v.valeur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EVT_VARIANT comme winevt.h le range (vérifié contre les en-têtes de MinGW).
    #[test]
    fn variante_a_sa_forme() {
        assert_eq!(std::mem::size_of::<Variante>(), 16);
        assert_eq!(std::mem::offset_of!(Variante, genre), 12);
        assert_eq!(large("a\0"), None);
    }

    /// Les vraies fonctions (Wine ici, la VM ensuite) : un canal qui n'existe pas est refusé, sans planter ni fichier.
    #[test]
    fn canal_inconnu_refuse() {
        let d = std::env::temp_dir().join(format!("vanguard-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("x.evtx");
        let r = exporter("Canal-Inconnu-De-Vanguard", "*", &f, Duration::from_secs(20));
        if r.is_ok() {
            let _ = std::fs::remove_dir_all(&d);
            return crate::essais::saute("wevtapi dit réussir pour un canal inconnu (ébauche de Wine)");
        }
        assert!(taille("Canal-Inconnu-De-Vanguard").is_none());
        let _ = std::fs::remove_dir_all(&d);
    }
}
