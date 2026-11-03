//! Le journal d'événements de Windows (Application, source « Vanguard ») : une entrée par baisse faite par le
//! processus élevé, lisible dans l'Observateur d'événements même si Vanguard ou son dossier disparaît. Une baisse
//! laisse ainsi une trace hors de Vanguard : quelqu'un qui aurait poussé la personne à confirmer ne peut pas
//! l'effacer en retirant Vanguard.
//!
//! Au mieux : un journal qui refuse n'empêche ni ne défait le geste, déjà relu et noté (`choix_avant`).

// FFI de Windows (advapi32) : RegisterEventSourceW, ReportEventW, DeregisterEventSource.
#![allow(unsafe_code)]

use std::ffi::c_void;

use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegisterEventSourceW(serveur: *const u16, source: *const u16) -> *mut c_void;
    fn ReportEventW(
        journal: *mut c_void,
        genre: u16,
        categorie: u16,
        evenement: u32,
        sid: *mut c_void,
        nombre: u16,
        taille: u32,
        textes: *const *const u16,
        donnees: *const c_void,
    ) -> i32;
    fn DeregisterEventSource(journal: *mut c_void) -> i32;
}

/// La source, sous Application.
const SOURCE: &str = "Vanguard";
const CLE_SOURCE: &str = r"SYSTEM\CurrentControlSet\Services\EventLog\Application\Vanguard";
/// EVENTLOG_WARNING_TYPE : une baisse de protection voulue, à voir, sans être une erreur.
const AVERTISSEMENT: u16 = 2;
/// L'identifiant de l'entrée : EventCreate.exe porte les messages 1 à 1000 au texte « %1 », si bien que
/// l'Observateur d'événements montre le texte tel quel, sans fichier de messages propre à Vanguard.
const EVENEMENT: u32 = 1;
/// Le plus long texte écrit : ReportEventW refuse au-delà de 31 839 caractères.
const TEXTE_MAX: usize = 4000;

fn large(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Inscrit la source si elle manque (fichier de messages : EventCreate.exe de Windows, sous System32). Une valeur
/// déjà là n'est pas réécrite.
fn inscrire() {
    let Ok((cle, _)) = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(CLE_SOURCE, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
    else {
        return;
    };
    if cle.get_raw_value("EventMessageFile").is_err() {
        let _ = cle.set_raw_value(
            "EventMessageFile",
            &winreg::RegValue {
                bytes: large(r"%SystemRoot%\System32\EventCreate.exe")
                    .iter()
                    .flat_map(|u| u.to_le_bytes())
                    .collect::<Vec<u8>>()
                    .into(),
                vtype: winreg::enums::REG_EXPAND_SZ,
            },
        );
    }
    if cle.get_raw_value("TypesSupported").is_err() {
        let _ = cle.set_value("TypesSupported", &7u32);
    }
}

/// Écrit une entrée d'avertissement ; faux si Windows l'a refusée.
pub(crate) fn avertir(texte: &str) -> bool {
    inscrire();
    let texte: String = texte.chars().filter(|c| !c.is_control()).take(TEXTE_MAX).collect();
    let (source, texte) = (large(SOURCE), large(&texte));
    let textes = [texte.as_ptr()];
    // SAFETY: `source` est une chaîne large terminée par un zéro, vivante pendant l'appel ; un serveur nul désigne cet
    // ordinateur.
    let journal = unsafe { RegisterEventSourceW(std::ptr::null(), source.as_ptr()) };
    if journal.is_null() {
        return false;
    }
    // SAFETY: `journal` vient de RegisterEventSourceW et n'est pas nul ; `textes` tient un pointeur vers `texte`,
    // chaîne large terminée par un zéro, tous deux vivants pendant l'appel ; aucun SID ni donnée brute.
    let ecrit = unsafe {
        ReportEventW(
            journal,
            AVERTISSEMENT,
            0,
            EVENEMENT,
            std::ptr::null_mut(),
            1,
            0,
            textes.as_ptr(),
            std::ptr::null(),
        )
    } != 0;
    // SAFETY: `journal` vient de RegisterEventSourceW, fermé une seule fois, ici.
    unsafe { DeregisterEventSource(journal) };
    ecrit
}
