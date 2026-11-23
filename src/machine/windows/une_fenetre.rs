//! Une seule fenêtre, sous Windows : le client du tube nommé de la fenêtre déjà ouverte (`demarrage::une_fenetre`
//! le vérifie et décide). Seulement les appels au système : ouvrir le tube, lire son propriétaire et sa liste d'accès,
//! dire qui le sert, reconnaître un fichier, échanger deux octets.

// FFI de kernel32, advapi32 et user32 : tube nommé (GetNamedPipeServerProcessId, PeekNamedPipe), descripteur de
// sécurité du tube, identité d'un fichier, session d'un processus, droit de passer au premier plan.
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
    fn LocalFree(memoire: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetSecurityInfo(
        objet: *mut c_void,
        genre: u32,
        quoi: u32,
        proprietaire: *mut *mut c_void,
        groupe: *mut *mut c_void,
        acces: *mut *mut c_void,
        audit: *mut *mut c_void,
        descripteur: *mut *mut c_void,
    ) -> u32;
    fn GetAclInformation(liste: *mut c_void, information: *mut u32, taille: u32, classe: u32) -> i32;
    fn GetAce(liste: *mut c_void, rang: u32, entree: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, texte: *mut *mut u16) -> i32;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn AllowSetForegroundWindow(pid: u32) -> i32;
}

/// ERROR_PIPE_BUSY : le tube existe, son unique instance est occupée par un autre client.
const TUBE_OCCUPE: i32 = 231;
/// ERROR_ACCESS_DENIED à l'ouverture : le tube existe, mais sa liste d'accès n'est pas pour ce compte (un autre
/// compte a pris le nom).
pub(crate) const ACCES_REFUSE: i32 = 5;
/// SECURITY_ANONYMOUS : le serveur ne peut ni agir en notre nom, ni même savoir qui nous sommes par le jeton (il
/// n'en a pas besoin : un octet, une réponse).
const ANONYME: u32 = 0;

/// L'identité d'un fichier ouvert : numéro de série de son volume et numéro du fichier dans ce volume (deux chemins,
/// lien ou casse différente, mènent au même fichier si et seulement si elle est la même). `None` si Windows refuse.
pub(crate) fn identite(fichier: &std::fs::File) -> Option<(u32, u64)> {
    super::memoire::identite_de_fichier(fichier.as_raw_handle())
}

/// Ouvre `chemin` sans droit de lecture ni d'écriture et en partageant tout : seulement pour en lire l'identité,
/// sans gêner (ni être gêné par) qui le tient, un antivirus compris.
pub(crate) fn ouvrir_pour_identite(chemin: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    const TOUT_PARTAGER: u32 = 0x7;
    std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(TOUT_PARTAGER)
        .open(chemin)
}

/// Le SID en texte d'un SID que Windows a rendu ; `None` s'il ne se lit pas.
///
/// # Safety
/// `sid` est nul ou pointe un SID valide, vivant pendant l'appel.
unsafe fn sid_en_texte(sid: *mut c_void) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut texte: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` est valide (contrat de la fonction) ; la chaîne allouée (terminée par un zéro) est lue jusqu'à
    // son zéro, puis rendue une seule fois par LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &raw mut texte) == 0 || texte.is_null() {
            return None;
        }
        let mut n = 0usize;
        while *texte.add(n) != 0 {
            n += 1;
        }
        let lu = String::from_utf16_lossy(std::slice::from_raw_parts(texte, n));
        LocalFree(texte.cast());
        Some(lu)
    }
}

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
                .security_qos_flags(ANONYME)
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

    /// Le tube a-t-il ce compte (`sid`) pour propriétaire, et une liste d'accès qui ne nomme que lui, en
    /// autorisation ? Sinon la raison, en mots. Un autre compte ne peut pas donner notre SID pour propriétaire à un
    /// objet qu'il crée (sans privilège d'administrateur) : un tube qui passe a été créé par ce compte.
    pub(crate) fn proprietaire_et_acces_a(&self, sid: &str) -> Result<(), crate::modele::Echec> {
        const OBJET_DU_NOYAU: u32 = 6;
        const PROPRIETAIRE: u32 = 0x1;
        const LISTE_D_ACCES: u32 = 0x4;
        let (mut proprietaire, mut liste, mut descripteur) =
            (std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: la poignée est ouverte tant que `self` vit (ouverte en lecture : READ_CONTROL compris) ; Windows
        // écrit trois pointeurs, à nous. Le propriétaire et la liste pointent dans le descripteur alloué, rendu une
        // seule fois par LocalFree à la fin de ce bloc, après toutes les lectures.
        unsafe {
            let erreur = GetSecurityInfo(
                self.poignee(),
                OBJET_DU_NOYAU,
                PROPRIETAIRE | LISTE_D_ACCES,
                &raw mut proprietaire,
                std::ptr::null_mut(),
                &raw mut liste,
                std::ptr::null_mut(),
                &raw mut descripteur,
            );
            if erreur != 0 || descripteur.is_null() {
                return Err(refus(crate::trf!(
                    "sécurité du canal illisible (erreur {})",
                    "channel security unreadable (error {})",
                    erreur
                )));
            }
            let verdict = juger_securite(proprietaire, liste, sid);
            LocalFree(descripteur);
            verdict
        }
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

/// Un canal refusé, sa phrase déjà dans la langue de l'interface : typé (`Echec`), pas en texte nu.
fn refus(phrase: impl Into<String>) -> crate::modele::Echec {
    crate::modele::Echec::refuse("fenetre/verifier", phrase)
}

/// Le jugement de `proprietaire_et_acces_a`, sur les pointeurs rendus par GetSecurityInfo.
///
/// # Safety
/// `proprietaire` et `liste` sont nuls ou pointent un SID et une ACL valides, vivants pendant l'appel.
unsafe fn juger_securite(proprietaire: *mut c_void, liste: *mut c_void, sid: &str) -> Result<(), crate::modele::Echec> {
    /// AclSizeInformation, pour GetAclInformation.
    const TAILLE_DE_LA_LISTE: u32 = 2;
    /// ACCESS_ALLOWED_ACE_TYPE.
    const AUTORISATION: u8 = 0;
    // SAFETY: contrat de la fonction : le propriétaire est nul ou un SID valide.
    let lui = unsafe { sid_en_texte(proprietaire) };
    if lui.as_deref() != Some(sid) {
        return Err(refus(crate::trf!(
            "le canal appartient à un autre compte ({})",
            "the channel belongs to another account ({})",
            lui.unwrap_or_default()
        )));
    }
    // Une liste absente ouvre l'objet à tous.
    if liste.is_null() {
        return Err(refus(crate::tr!(
            "le canal est ouvert à tous",
            "the channel is open to everyone"
        )));
    }
    // ACL_SIZE_INFORMATION : nombre d'entrées, octets utilisés, octets libres.
    let mut taille = [0u32; 3];
    // SAFETY: `liste` est une ACL valide (contrat) ; Windows écrit douze octets dans `taille`, à nous.
    let lue = unsafe { GetAclInformation(liste, taille.as_mut_ptr(), 12, TAILLE_DE_LA_LISTE) } != 0;
    let [entrees, _, _] = taille;
    if !lue || entrees == 0 {
        return Err(refus(crate::tr!(
            "liste d'accès du canal illisible",
            "channel access list unreadable"
        )));
    }
    for rang in 0..entrees {
        let mut entree: *mut c_void = std::ptr::null_mut();
        // SAFETY: `rang` est sous le nombre d'entrées lu ; Windows écrit un pointeur vers l'entrée, dans l'ACL.
        if unsafe { GetAce(liste, rang, &raw mut entree) } == 0 || entree.is_null() {
            return Err(refus(crate::tr!(
                "liste d'accès du canal illisible",
                "channel access list unreadable"
            )));
        }
        // ACE_HEADER : genre (un octet), drapeaux, taille ; puis, pour une autorisation (ACCESS_ALLOWED_ACE), le
        // masque des droits (quatre octets), puis le SID, à l'octet 8.
        // SAFETY: `entree` pointe une entrée de l'ACL valide, dont l'en-tête (quatre octets) se lit toujours ; le
        // SID n'est lu qu'après avoir vu une autorisation, qui en porte un à l'octet 8.
        let (genre, nomme) = unsafe {
            let genre = *entree.cast::<u8>();
            let nomme = if genre == AUTORISATION {
                sid_en_texte(entree.cast::<u8>().add(8).cast())
            } else {
                None
            };
            (genre, nomme)
        };
        if genre != AUTORISATION || nomme.as_deref() != Some(sid) {
            return Err(refus(crate::trf!(
                "la liste d'accès du canal nomme un autre compte ({})",
                "the channel access list names another account ({})",
                nomme.unwrap_or_default()
            )));
        }
    }
    Ok(())
}
