//! Windows : chaque `vanguard` lancé par la fenêtre est mis dans son propre objet de travail (job object), ce que
//! Windows a de plus proche du groupe de processus de Linux. Tout ce que `vanguard` lance ensuite y entre de lui-même
//! et n'en sort pas (ni JOB_OBJECT_LIMIT_BREAKAWAY_OK ni SILENT_BREAKAWAY_OK) : Arrêter, le délai dépassé et la fin
//! de la commande arrêtent tout l'objet (TerminateJobObject), pas seulement `vanguard`. Et si la fenêtre elle-même
//! s'arrête, même brutalement, Windows ferme son dernier handle de l'objet et tue ce qui y reste
//! (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
//!
//! Limite : `vanguard` est mis dans l'objet juste après son lancement (std ne sait pas le créer suspendu puis le
//! reprendre) ; un processus qu'il lancerait dans ce court intervalle, avant même sa première ligne, n'y serait pas.
//! Si Windows refuse l'objet (une fenêtre déjà dans un objet qui interdit l'imbrication, avant Windows 8), Arrêter
//! revient à ne tuer que `vanguard`, comme avant.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::process::Child;

/// JobObjectExtendedLimitInformation.
const LIMITES_ETENDUES: i32 = 9;
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
const TUER_A_LA_FERMETURE: u32 = 0x2000;

/// JOBOBJECT_BASIC_LIMIT_INFORMATION (64 octets en 64 bits).
#[repr(C)]
#[derive(Default)]
struct LimitesDeBase {
    temps_par_processus: i64,
    temps_du_travail: i64,
    drapeaux: u32,
    memoire_min: usize,
    memoire_max: usize,
    processus_max: u32,
    affinite: usize,
    priorite: u32,
    classe: u32,
}

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION (144 octets en 64 bits) : les limites de base, les compteurs d'entrées-sorties
/// (IO_COUNTERS, six u64) et quatre tailles de mémoire.
#[repr(C)]
#[derive(Default)]
struct LimitesEtendues {
    base: LimitesDeBase,
    entrees_sorties: [u64; 6],
    memoires: [usize; 4],
}

// La forme que Windows attend, vérifiée à la compilation (aucun essai ne tourne sous Windows ici).
const _: () = assert!(std::mem::size_of::<LimitesDeBase>() == 64);
const _: () = assert!(std::mem::size_of::<LimitesEtendues>() == 144);

// raison : FFI de kernel32 (objets de travail), que std ne sait pas faire.
#[allow(unsafe_code)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateJobObjectW(attributs: *const core::ffi::c_void, nom: *const u16) -> RawHandle;
    fn SetInformationJobObject(travail: RawHandle, classe: i32, info: *const core::ffi::c_void, taille: u32) -> i32;
    fn AssignProcessToJobObject(travail: RawHandle, processus: RawHandle) -> i32;
    fn TerminateJobObject(travail: RawHandle, code: u32) -> i32;
}

/// L'objet de travail d'un `vanguard` lancé. Le relâcher (Drop) tue ce qui y reste.
pub struct Travail(OwnedHandle);

impl Travail {
    /// Un objet neuf, sans nom (personne d'autre ne peut l'ouvrir par son nom), réglé pour tuer à la fermeture, et
    /// `enfant` mis dedans. `None` si Windows refuse l'une des trois étapes.
    // raison : FFI de kernel32 (création, réglage et affectation d'un objet de travail).
    #[allow(unsafe_code)]
    pub fn pour(enfant: &Child) -> Option<Travail> {
        // SAFETY: deux pointeurs nuls permis (sécurité par défaut, sans nom) ; rend un handle à nous, ou nul.
        let h = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if h.is_null() {
            return None;
        }
        // SAFETY: `h` vient d'être créé, n'est à personne d'autre et n'est fermé que par cet OwnedHandle.
        let travail = Travail(unsafe { OwnedHandle::from_raw_handle(h) });
        let mut limites = LimitesEtendues::default();
        limites.base.drapeaux = TUER_A_LA_FERMETURE;
        let taille = u32::try_from(std::mem::size_of::<LimitesEtendues>()).ok()?;
        // SAFETY: la structure a la forme de JOBOBJECT_EXTENDED_LIMIT_INFORMATION (tailles vérifiées plus haut), vit
        // pendant l'appel, qui la lit seulement ; le handle de l'objet est ouvert.
        let regle = unsafe {
            SetInformationJobObject(
                travail.0.as_raw_handle(),
                LIMITES_ETENDUES,
                (&raw const limites).cast(),
                taille,
            )
        };
        // SAFETY: deux handles ouverts : l'objet, et le processus que `Child` garde ouvert (droits complets, donnés
        // par CreateProcess).
        if regle == 0 || unsafe { AssignProcessToJobObject(travail.0.as_raw_handle(), enfant.as_raw_handle()) } == 0 {
            return None;
        }
        Some(travail)
    }

    /// Tue tout ce qui est dans l'objet : `vanguard` et ce qu'il a lancé.
    // raison : FFI de kernel32 (TerminateJobObject).
    #[allow(unsafe_code)]
    pub fn tuer(&self) {
        // SAFETY: le handle de l'objet est ouvert tant que `self` vit ; l'appel ne touche aucune mémoire du programme.
        let _ = unsafe { TerminateJobObject(self.0.as_raw_handle(), 1) };
    }
}
