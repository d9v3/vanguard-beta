//! Une seule fenêtre, sous Windows : le client du tube nommé de la fenêtre déjà ouverte (`demarrage::une_fenetre`
//! le vérifie et décide). Seulement les appels au système : ouvrir le tube, lire son propriétaire et sa liste d'accès,
//! dire qui le sert, reconnaître un fichier, échanger la demande et sa réponse.

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
pub(crate) const TUBE_OCCUPE: i32 = 231;
/// ERROR_ACCESS_DENIED à l'ouverture : le tube existe, mais sa liste d'accès n'est pas pour ce compte (un autre
/// compte a pris le nom).
pub(crate) const ACCES_REFUSE: i32 = 5;
/// SECURITY_ANONYMOUS : le serveur ne peut ni agir en notre nom, ni même savoir qui nous sommes par le jeton (il
/// n'en a pas besoin : un octet, une réponse).
const ANONYME: u32 = 0;

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
    /// Ouvre le tube `nom` ; `Ok(None)` s'il n'existe pas (aucune fenêtre). Occupé (la fenêtre sert un autre
    /// client, environ 7 s au plus : voir `ATTENTE_ACCUEIL`) : réessayé `attente` au plus.
    pub(crate) fn ouvrir(nom: &str, attente: Duration) -> std::io::Result<Option<Client>> {
        use std::os::windows::fs::OpenOptionsExt;
        let fin = Instant::now().checked_add(attente).unwrap_or_else(Instant::now);
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
            let lue = lire_securite(proprietaire, liste);
            LocalFree(descripteur);
            juger_securite(&lue, sid).map_err(|r| refus(r.phrase()))
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

    /// La demande (« montre-toi » et le nombre `jeton`), puis la réponse, `TAILLE` octets attendus `DELAI` au plus
    /// en tout (attendus par PeekNamedPipe : une lecture directe sur un tube muet ne rendrait jamais la main). Un
    /// octet qui attendait déjà avant la demande ne peut pas en être la réponse : la demande n'est pas envoyée.
    pub(crate) fn echanger(mut self, jeton: &[u8; regle::JETON]) -> Echange {
        match self.disponibles() {
            Some(0) => {}
            Some(_) => return Echange::AttendaitDeja,
            None => return Echange::Muet,
        }
        if self.0.write_all(&regle::demande(jeton)).is_err() {
            return Echange::Muet;
        }
        let fin = Instant::now().checked_add(regle::DELAI).unwrap_or_else(Instant::now);
        let mut lu = Vec::with_capacity(regle::TAILLE);
        while lu.len() < regle::TAILLE {
            match self.disponibles() {
                Some(0) if Instant::now() < fin => std::thread::sleep(Duration::from_millis(20)),
                None | Some(0) => return Echange::Muet,
                Some(_) => {
                    let mut octet = [0u8; 1];
                    if self.0.read_exact(&mut octet).is_err() {
                        return Echange::Muet;
                    }
                    lu.extend_from_slice(&octet);
                }
            }
        }
        if regle::reponse_juste(&lu, jeton) {
            Echange::Repondu
        } else {
            Echange::MauvaisNombre
        }
    }
}

/// Ce qu'a donné `Client::echanger`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Echange {
    /// « ok » et le nombre de la demande.
    Repondu,
    /// Rien, ou pas tout, à temps ; ou le tube rompu.
    Muet,
    /// Un octet attendait avant la demande : elle n'est pas envoyée.
    AttendaitDeja,
    /// Une réponse qui ne reprend pas le nombre de la demande.
    MauvaisNombre,
}

/// Un canal refusé, sa phrase déjà dans la langue de l'interface : typé (`Echec`), pas en texte nu.
fn refus(phrase: impl Into<String>) -> crate::modele::Echec {
    crate::modele::Echec::refuse("fenetre/verifier", phrase)
}

/// La liste d'accès du tube, lue.
#[derive(Debug)]
pub(crate) enum Liste {
    /// Pas de liste : l'objet est ouvert à tous.
    Absente,
    /// Windows n'a pas su la lire.
    Illisible,
    /// Chaque entrée : son genre (0 : une autorisation) et, pour une autorisation, le SID qu'elle nomme.
    Entrees(Vec<(u8, Option<String>)>),
}

/// Le propriétaire et la liste d'accès du tube, lus.
#[derive(Debug)]
pub(crate) struct Securite {
    pub(crate) proprietaire: Option<String>,
    pub(crate) liste: Liste,
}

/// Pourquoi la sécurité du tube est refusée (un motif par contrôle).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RefusTube {
    AutreProprietaire(String),
    OuvertATous,
    Illisible,
    Vide,
    PasUneAutorisation,
    AutreCompte(String),
}

impl RefusTube {
    fn phrase(&self) -> String {
        match self {
            RefusTube::AutreProprietaire(lui) => crate::trf!(
                "le canal appartient à un autre compte ({})",
                "the channel belongs to another account ({})",
                lui
            ),
            RefusTube::OuvertATous => {
                crate::tr!("le canal est ouvert à tous", "the channel is open to everyone").into()
            }
            RefusTube::Illisible => {
                crate::tr!("liste d'accès du canal illisible", "channel access list unreadable").into()
            }
            RefusTube::Vide => crate::tr!("liste d'accès du canal vide", "channel access list empty").into(),
            RefusTube::PasUneAutorisation => crate::tr!(
                "la liste d'accès du canal a une entrée qui n'est pas une autorisation",
                "the channel access list has an entry that is not an allowance"
            )
            .into(),
            RefusTube::AutreCompte(nomme) => crate::trf!(
                "la liste d'accès du canal nomme un autre compte ({})",
                "the channel access list names another account ({})",
                nomme
            ),
        }
    }
}

/// Le jugement de `proprietaire_et_acces_a`, sans rien lire (essayé cas par cas) : ce compte pour propriétaire, et
/// une liste d'accès faite seulement d'autorisations pour lui.
pub(crate) fn juger_securite(lue: &Securite, sid: &str) -> Result<(), RefusTube> {
    if lue.proprietaire.as_deref() != Some(sid) {
        return Err(RefusTube::AutreProprietaire(
            lue.proprietaire.clone().unwrap_or_default(),
        ));
    }
    let entrees = match &lue.liste {
        Liste::Absente => return Err(RefusTube::OuvertATous),
        Liste::Illisible => return Err(RefusTube::Illisible),
        Liste::Entrees(e) if e.is_empty() => return Err(RefusTube::Vide),
        Liste::Entrees(e) => e,
    };
    for (genre, nomme) in entrees {
        if *genre != AUTORISATION {
            return Err(RefusTube::PasUneAutorisation);
        }
        if nomme.as_deref() != Some(sid) {
            return Err(RefusTube::AutreCompte(nomme.clone().unwrap_or_default()));
        }
    }
    Ok(())
}

/// ACCESS_ALLOWED_ACE_TYPE.
const AUTORISATION: u8 = 0;

/// Lit le propriétaire et la liste d'accès rendus par GetSecurityInfo.
///
/// # Safety
/// `proprietaire` et `liste` sont nuls ou pointent un SID et une ACL valides, vivants pendant l'appel.
unsafe fn lire_securite(proprietaire: *mut c_void, liste: *mut c_void) -> Securite {
    /// AclSizeInformation, pour GetAclInformation.
    const TAILLE_DE_LA_LISTE: u32 = 2;
    // SAFETY: contrat de la fonction : le propriétaire est nul ou un SID valide.
    let proprietaire = unsafe { sid_en_texte(proprietaire) };
    if liste.is_null() {
        return Securite {
            proprietaire,
            liste: Liste::Absente,
        };
    }
    let illisible = |proprietaire| Securite {
        proprietaire,
        liste: Liste::Illisible,
    };
    // ACL_SIZE_INFORMATION : nombre d'entrées, octets utilisés, octets libres.
    let mut taille = [0u32; 3];
    // SAFETY: `liste` est une ACL valide (contrat) ; Windows écrit douze octets dans `taille`, à nous.
    if unsafe { GetAclInformation(liste, taille.as_mut_ptr(), 12, TAILLE_DE_LA_LISTE) } == 0 {
        return illisible(proprietaire);
    }
    let [nombre, _, _] = taille;
    let mut entrees = Vec::new();
    for rang in 0..nombre {
        let mut entree: *mut c_void = std::ptr::null_mut();
        // SAFETY: `rang` est sous le nombre d'entrées lu ; Windows écrit un pointeur vers l'entrée, dans l'ACL.
        if unsafe { GetAce(liste, rang, &raw mut entree) } == 0 || entree.is_null() {
            return illisible(proprietaire);
        }
        // ACE_HEADER : genre (un octet), drapeaux, taille ; puis, pour une autorisation (ACCESS_ALLOWED_ACE), le
        // masque des droits (quatre octets), puis le SID, à l'octet 8.
        // SAFETY: `entree` pointe une entrée de l'ACL valide, dont l'en-tête (quatre octets) se lit toujours ; le
        // SID n'est lu qu'après avoir vu une autorisation, qui en porte un à l'octet 8.
        let lue = unsafe {
            let genre = *entree.cast::<u8>();
            let nomme = if genre == AUTORISATION {
                sid_en_texte(entree.cast::<u8>().add(8).cast())
            } else {
                None
            };
            (genre, nomme)
        };
        entrees.push(lue);
    }
    Securite {
        proprietaire,
        liste: Liste::Entrees(entrees),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOI: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const AUTRE: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";

    fn lue(proprietaire: Option<&str>, liste: Liste) -> Securite {
        Securite {
            proprietaire: proprietaire.map(String::from),
            liste,
        }
    }

    fn autorise(sid: &str) -> (u8, Option<String>) {
        (AUTORISATION, Some(sid.into()))
    }

    /// Constat 32 : chaque contrôle du tube a son refus ; retirer l'un d'eux fait passer son cas.
    #[test]
    fn chaque_controle_du_tube_refuse_son_cas() {
        let bon = || Liste::Entrees(vec![autorise(MOI)]);
        assert_eq!(juger_securite(&lue(Some(MOI), bon()), MOI), Ok(()));
        assert_eq!(
            juger_securite(&lue(Some(AUTRE), bon()), MOI),
            Err(RefusTube::AutreProprietaire(AUTRE.into()))
        );
        assert_eq!(
            juger_securite(&lue(None, bon()), MOI),
            Err(RefusTube::AutreProprietaire(String::new()))
        );
        assert_eq!(
            juger_securite(&lue(Some(MOI), Liste::Absente), MOI),
            Err(RefusTube::OuvertATous)
        );
        assert_eq!(
            juger_securite(&lue(Some(MOI), Liste::Illisible), MOI),
            Err(RefusTube::Illisible)
        );
        assert_eq!(
            juger_securite(&lue(Some(MOI), Liste::Entrees(Vec::new())), MOI),
            Err(RefusTube::Vide)
        );
        // Un refus (ACCESS_DENIED_ACE_TYPE, 1) nommant ce compte : pas une autorisation.
        assert_eq!(
            juger_securite(&lue(Some(MOI), Liste::Entrees(vec![autorise(MOI), (1, None)])), MOI),
            Err(RefusTube::PasUneAutorisation)
        );
        assert_eq!(
            juger_securite(
                &lue(Some(MOI), Liste::Entrees(vec![autorise(MOI), autorise(AUTRE)])),
                MOI
            ),
            Err(RefusTube::AutreCompte(AUTRE.into()))
        );
        assert_eq!(
            juger_securite(&lue(Some(MOI), Liste::Entrees(vec![(AUTORISATION, None)])), MOI),
            Err(RefusTube::AutreCompte(String::new()))
        );
    }
}
