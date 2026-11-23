//! Une seule fenêtre, sous Windows : le client du tube nommé de la fenêtre déjà ouverte (`demarrage::une_fenetre`
//! le vérifie et décide). Seulement les appels au système : ouvrir le tube, dire qui le sert, échanger deux octets.

// FFI de kernel32 et user32 : tube nommé (GetNamedPipeServerProcessId, PeekNamedPipe), session d'un processus,
// droit de passer au premier plan.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::time::{Duration, Instant};

use crate::socle::une_fenetre as regle;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetNamedPipeServerProcessId(tube: *mut c_void, pid: *mut u32) -> i32;
    fn PeekNamedPipe(
        tube: *mut c_void,
        tampon: *mut c_void,
        taille: u32,
        lus: *mut u32,
        disponibles: *mut u32,
        restant: *mut u32,
    ) -> i32;
    fn ProcessIdToSessionId(pid: u32, session: *mut u32) -> i32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn AllowSetForegroundWindow(pid: u32) -> i32;
}

/// ERROR_PIPE_BUSY : le tube existe, son unique instance est occupée par un autre client.
const TUBE_OCCUPE: i32 = 231;
/// SECURITY_IDENTIFICATION : le serveur peut savoir qui nous sommes, jamais agir en notre nom.
const IDENTIFICATION_SEULEMENT: u32 = 0x0001_0000;

/// La session Windows du processus `pid` ; `None` si Windows refuse.
pub(crate) fn session_de(pid: u32) -> Option<u32> {
    let mut session = u32::MAX;
    // SAFETY: ProcessIdToSessionId écrit un u32 dans `session`, à nous et vivant pendant l'appel.
    let ok = unsafe { ProcessIdToSessionId(pid, &raw mut session) } != 0;
    ok.then_some(session)
}

/// Permet au processus `pid` de passer au premier plan (effet seulement si ce programme-ci en a le droit).
pub(crate) fn permettre_premier_plan(pid: u32) {
    // SAFETY: AllowSetForegroundWindow ne prend qu'un numéro et ne touche aucune mémoire à nous.
    unsafe {
        AllowSetForegroundWindow(pid);
    }
}

/// Le bout client du tube.
pub(crate) struct Client(std::fs::File);

impl Client {
    /// Ouvre le tube `nom` ; `Ok(None)` s'il n'existe pas (aucune fenêtre). Occupé : réessayé `DELAI` au plus.
    pub(crate) fn ouvrir(nom: &str) -> std::io::Result<Option<Client>> {
        use std::os::windows::fs::OpenOptionsExt;
        let fin = Instant::now().checked_add(regle::DELAI).unwrap_or_else(Instant::now);
        loop {
            let essai = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .security_qos_flags(IDENTIFICATION_SEULEMENT)
                .open(nom);
            match essai {
                Ok(f) => return Ok(Some(Client(f))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) if e.raw_os_error() == Some(TUBE_OCCUPE) && Instant::now() < fin => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn poignee(&self) -> *mut c_void {
        self.0.as_raw_handle()
    }

    /// Le processus qui sert le tube ; `None` si Windows refuse.
    pub(crate) fn pid_du_serveur(&self) -> Option<u32> {
        let mut pid = 0u32;
        // SAFETY: la poignée est ouverte tant que `self` vit ; l'appel écrit un u32 dans `pid`, à nous.
        let ok = unsafe { GetNamedPipeServerProcessId(self.poignee(), &raw mut pid) } != 0;
        (ok && pid != 0).then_some(pid)
    }

    /// Octets en attente de lecture ; `None` si le tube est rompu (le serveur parti).
    fn disponibles(&self) -> Option<u32> {
        let mut disponibles = 0u32;
        // SAFETY: la poignée est ouverte tant que `self` vit ; aucun tampon (pointeurs nuls, taille 0), seul le
        // nombre d'octets disponibles est écrit, dans un u32 à nous.
        let ok = unsafe {
            PeekNamedPipe(
                self.poignee(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &raw mut disponibles,
                std::ptr::null_mut(),
            )
        } != 0;
        ok.then_some(disponibles)
    }

    /// Le tube est-il toujours branché à son serveur ?
    pub(crate) fn branche(&self) -> bool {
        self.disponibles().is_some()
    }

    /// Un octet « montre-toi », un octet « ok » attendu, `DELAI` au plus (attendu par PeekNamedPipe : une lecture
    /// directe sur un tube muet ne rendrait jamais la main).
    pub(crate) fn echanger(mut self) -> bool {
        if self.0.write_all(&[regle::DEMANDE]).is_err() {
            return false;
        }
        let fin = Instant::now().checked_add(regle::DELAI).unwrap_or_else(Instant::now);
        loop {
            match self.disponibles() {
                Some(0) if Instant::now() < fin => std::thread::sleep(Duration::from_millis(20)),
                None | Some(0) => return false,
                Some(_) => break,
            }
        }
        let mut reponse = [0u8; 1];
        self.0.read_exact(&mut reponse).is_ok() && reponse == [regle::REPONSE]
    }
}
