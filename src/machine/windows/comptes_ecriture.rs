//! Désactiver un compte local (`vanguard:compte-desactiver <RID>`, grammaire de `gestes.rs`), dans le processus élevé,
//! par netapi32 (NetUserSetInfo niveau 1008), sans PowerShell.
//!
//! Le processus élevé relit tout avant d'écrire : les comptes, le bilan des comptes (la ligne doit y être proposée,
//! automatiquement), les administrateurs et les programmes ouverts. Il refuse la personne, son propre compte, le
//! dernier administrateur actif, un compte réservé de Windows et un compte sous lequel tourne un programme (une
//! session ouverte sur l'écran, par le Bureau à distance ou SSH en dépend) : `gestes::refus_desactivation`. Après
//! l'écriture, le compte est relu : seul le drapeau relu compte. Le geste ne donne de droits à personne ; il n'est pas
//! défait par Vanguard (une protection), la personne peut réactiver le compte dans Windows.

// FFI de netapi32 et wtsapi32 : NetUserGetInfo, NetUserSetInfo, WTSEnumerateProcessesExW.
#![allow(unsafe_code)]

use super::comptes::{self, NetApiBufferFree, NetUserGetInfo, NetUserSetInfo, large, sid_texte};
use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, EtatCompte, RefusCompte};
use crate::ui::{tr, trf};

/// UF_SCRIPT : exigé par NetUserSetInfo dans les drapeaux d'un compte.
const SCRIPT: u32 = 0x1;
/// UF_ACCOUNTDISABLE.
const DESACTIVE: u32 = 0x2;
/// UF_LOCKOUT et UF_PASSWORD_EXPIRED : un administrateur verrouillé ou au mot de passe expiré n'ouvre pas de session
/// tout de suite ; il ne compte pas comme « un autre administrateur actif ».
const INUTILISABLE: u32 = DESACTIVE | 0x10 | 0x0080_0000;

/// USER_INFO_20 de lmaccess.h (32 octets en 64 bits) : les drapeaux et le RID du compte.
#[repr(C)]
struct Utilisateur20 {
    _nom: *const u16,
    _nom_complet: *const u16,
    _commentaire: *const u16,
    drapeaux: u32,
    rid: u32,
}

/// WTS_PROCESS_INFO_EXW de wtsapi32.h (64 octets en 64 bits) : la session et le SID du compte de chaque programme.
#[repr(C)]
struct ProgrammeWts {
    session: u32,
    pid: u32,
    _nom: *const u16,
    sid: *mut std::ffi::c_void,
    _fils: u32,
    _poignees: u32,
    _pagination: u32,
    _pagination_max: u32,
    _memoire: u32,
    _memoire_max: u32,
    _temps_utilisateur: i64,
    _temps_noyau: i64,
}

#[link(name = "wtsapi32")]
unsafe extern "system" {
    fn WTSEnumerateProcessesExW(
        serveur: *mut std::ffi::c_void,
        niveau: *mut u32,
        session: u32,
        programmes: *mut *mut u16,
        nombre: *mut u32,
    ) -> i32;
    fn WTSFreeMemoryExW(genre: u32, memoire: *mut std::ffi::c_void, nombre: u32) -> i32;
}

/// Désactive le compte local de ce RID, signalé par le bilan relu ; `personne` : le SID de la personne.
pub(super) fn desactiver(rid: u32, personne: Option<&str>) -> Resultat {
    let Some(liste) = comptes::comptes_natifs() else {
        return Resultat::echec(
            None,
            tr!(
                "comptes illisibles, rien changé",
                "accounts unreadable, nothing changed"
            )
            .to_string(),
        );
    };
    let cibles: Vec<&comptes::Compte> = liste
        .iter()
        .filter(|c| gestes::rid_local(&c.sid) == Some(rid))
        .collect();
    if let [c] = cibles.as_slice()
        && !c.actif
    {
        return Resultat::rien(trf!(
            "« {} » est déjà désactivé, rien changé",
            "“{}” is already disabled, nothing changed",
            crate::ui::affichable(&c.nom)
        ));
    }
    let trouves: Vec<&str> = cibles.iter().map(|c| c.sid.as_str()).collect();
    let ligne = gestes::Acte::CompteDesactiver(rid).ligne();
    let signale = signale(&liste, personne, &ligne);
    let admins = comptes::administrateurs_sid();
    let est_admin = |sid: &str| {
        admins
            .as_ref()
            .is_some_and(|a| a.iter().any(|x| x.eq_ignore_ascii_case(sid)))
    };
    let cible = trouves.first().copied().unwrap_or_default();
    let soi = super::processus::sid();
    let etat = EtatCompte {
        rid,
        trouves: &trouves,
        personne,
        soi: soi.as_deref(),
        signale,
        // Administrateurs illisibles : le compte compte comme administrateur, et aucun autre ne compte.
        administrateur: admins.is_none() || est_admin(cible),
        autres_administrateurs: liste
            .iter()
            .filter(|c| c.actif && !c.sid.eq_ignore_ascii_case(cible) && est_admin(&c.sid) && utilisable(c))
            .count(),
        programmes: programmes().and_then(|p| programme_du_compte(&p, cible)),
    };
    if let Some(refus) = gestes::refus_desactivation(&etat) {
        return Resultat::echec(None, pourquoi(refus));
    }
    let Some(nom) = cibles.first().map(|c| c.nom.clone()) else {
        return Resultat::echec(None, pourquoi(RefusCompte::Introuvable));
    };
    // Relu juste avant d'écrire : une session ouverte entre-temps (Bureau à distance, SSH) refuse encore.
    match programmes().and_then(|p| programme_du_compte(&p, cible)) {
        Some(false) => {}
        Some(true) => return Resultat::echec(None, pourquoi(RefusCompte::SessionOuverte)),
        None => return Resultat::echec(None, pourquoi(RefusCompte::ProgrammesIllisibles)),
    }
    ecrire(&nom, rid)
}

/// Un autre administrateur compte-t-il pour garder l'ordinateur administrable ? Ses drapeaux relus ne le disent ni
/// désactivé, ni verrouillé, ni au mot de passe expiré ; illisibles : non.
fn utilisable(c: &comptes::Compte) -> bool {
    gestes::rid_local(&c.sid)
        .and_then(|rid| drapeaux(&large(&c.nom), rid))
        .is_some_and(|d| d & INUTILISABLE == 0)
}

/// Le bilan des comptes refait sur la lecture d'à l'instant propose-t-il cette ligne, automatiquement ?
fn signale(liste: &[comptes::Compte], personne: Option<&str>, ligne: &str) -> bool {
    let lignes: Vec<String> = liste
        .iter()
        .map(|c| {
            let oui_non = |b: bool| if b { "True" } else { "False" };
            format!(
                "{}|{}|{}|{}",
                oui_non(c.actif),
                oui_non(c.mot_de_passe_exige),
                c.sid,
                c.nom
            )
        })
        .collect();
    let lignes: Vec<&str> = lignes.iter().map(String::as_str).collect();
    comptes::juger_comptes(&lignes, personne, None).iter().any(|c| {
        c.correctif
            .as_ref()
            .is_some_and(|k| k.automatique && k.commandes.iter().any(|x| x == ligne))
    })
}

/// Lit les drapeaux du compte par son nom, en vérifiant son RID ; `None` si Windows refuse ou si le RID diffère.
fn drapeaux(nom: &[u16], rid: u32) -> Option<u32> {
    let mut info: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: NetUserGetInfo niveau 20 écrit un USER_INFO_20 alloué par Windows (que `Utilisateur20` reproduit), lu
    // tant qu'il vit puis rendu une seule fois.
    unsafe {
        let code = NetUserGetInfo(std::ptr::null(), nom.as_ptr(), 20, &raw mut info);
        if code != 0 || info.is_null() {
            if !info.is_null() {
                NetApiBufferFree(info);
            }
            return None;
        }
        let u = info.cast::<Utilisateur20>().read_unaligned();
        NetApiBufferFree(info);
        (u.rid == rid).then_some(u.drapeaux)
    }
}

/// Lève le drapeau « compte désactivé », puis relit.
fn ecrire(nom: &str, rid: u32) -> Resultat {
    let nom_large = large(nom);
    let Some(avant) = drapeaux(&nom_large, rid) else {
        return Resultat::echec(
            None,
            tr!(
                "compte illisible ou renommé entre-temps, rien changé",
                "account unreadable or renamed meanwhile, nothing changed"
            )
            .to_string(),
        );
    };
    let note = avant_notable(&format!("{} : drapeaux 0x{avant:08x}", crate::ui::affichable(nom)));
    let nouveaux: u32 = avant | DESACTIVE | SCRIPT;
    let mut erreur = 0u32;
    // SAFETY: USER_INFO_1008 est un seul DWORD (les drapeaux), lu par Windows pendant l'appel ; `erreur` reçoit
    // l'indice d'un paramètre refusé.
    let code = unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            nom_large.as_ptr(),
            1008,
            (&raw const nouveaux).cast(),
            &raw mut erreur,
        )
    };
    if code != 0 {
        return Resultat::echec(
            Some(note),
            trf!(
                "Windows refuse de désactiver le compte (code {code})",
                "Windows refuses to disable the account (code {code})"
            ),
        );
    }
    match drapeaux(&nom_large, rid) {
        Some(d) if d & DESACTIVE != 0 => Resultat::fait(note),
        Some(_) => Resultat::echec(
            Some(note),
            tr!(
                "le compte est relu encore actif : rien n'est compté comme fait",
                "the account reads back still enabled: nothing is counted as done"
            )
            .to_string(),
        ),
        None => Resultat::echec(
            Some(note),
            tr!(
                "compte illisible après l'écriture : rien n'est compté comme fait",
                "account unreadable after writing: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

/// Les programmes ouverts de toutes les sessions : (session, SID du compte, `None` si Windows ne le dit pas).
/// `None` si la liste ne se lit pas.
fn programmes() -> Option<Vec<(u32, Option<String>)>> {
    const TOUTES_LES_SESSIONS: u32 = 0xFFFF_FFFE;
    /// WTSTypeProcessInfoLevel1.
    const NIVEAU_1: u32 = 1;
    let mut niveau = NIVEAU_1;
    let mut tampon: *mut u16 = std::ptr::null_mut();
    let mut nombre = 0u32;
    // SAFETY: le serveur nul est cet ordinateur ; au niveau 1, Windows écrit un tableau de `nombre`
    // WTS_PROCESS_INFO_EXW (que `ProgrammeWts` reproduit), lu tant qu'il vit, SID compris, puis rendu une seule fois
    // par WTSFreeMemoryExW avec le même genre et le même nombre.
    unsafe {
        let lu = WTSEnumerateProcessesExW(
            std::ptr::null_mut(),
            &raw mut niveau,
            TOUTES_LES_SESSIONS,
            &raw mut tampon,
            &raw mut nombre,
        ) != 0;
        if !lu || tampon.is_null() {
            return None;
        }
        let mut liste = Vec::with_capacity(nombre as usize);
        let mut lisible = niveau == NIVEAU_1;
        if lisible {
            for i in 0..nombre as usize {
                let p = tampon
                    .cast::<std::ffi::c_void>()
                    .cast::<ProgrammeWts>()
                    .add(i)
                    .read_unaligned();
                let sid = if p.sid.is_null() { None } else { sid_texte(p.sid) };
                // Un SID présent qui ne se convertit pas : la liste n'est pas sûre.
                if !p.sid.is_null() && sid.is_none() {
                    lisible = false;
                }
                // Le processus inactif (0) et System (4) n'ont pas de compte à eux.
                if p.pid != 0 && p.pid != 4 {
                    liste.push((p.session, sid));
                }
            }
        }
        WTSFreeMemoryExW(NIVEAU_1, tampon.cast(), nombre);
        lisible.then_some(liste)
    }
}

/// Un programme tourne-t-il sous ce compte ? Un programme sans SID lisible dans une session ouverte (1 et plus) laisse
/// la question sans réponse (`None`) ; dans la session 0 (services, programmes protégés de Windows), il compte comme
/// un programme du système : les programmes de SSH y tournent aussi, mais sous un compte que Windows dit toujours.
fn programme_du_compte(liste: &[(u32, Option<String>)], cible: &str) -> Option<bool> {
    let mut inconnu = false;
    for (session, sid) in liste {
        match sid {
            Some(s) if s.eq_ignore_ascii_case(cible) => return Some(true),
            None if *session != 0 => inconnu = true,
            Some(_) | None => {}
        }
    }
    (!inconnu).then_some(false)
}

/// Le refus dit à la personne.
fn pourquoi(refus: RefusCompte) -> String {
    match refus {
        RefusCompte::PersonneIllisible => tr!(
            "votre compte ne se lit pas dans le jeton de Vanguard : refusé, rien changé",
            "your account cannot be read from Vanguard's token: refused, nothing changed"
        ),
        RefusCompte::Introuvable => tr!(
            "aucun compte local (ou plus d'un) n'a ce numéro : refusé, rien changé",
            "no local account (or more than one) has this number: refused, nothing changed"
        ),
        RefusCompte::CompteEnCours => tr!(
            "c'est le compte en cours d'utilisation : refusé, rien changé",
            "this is the account in use: refused, nothing changed"
        ),
        RefusCompte::Reserve => tr!(
            "compte réservé de Windows : refusé, rien changé",
            "reserved Windows account: refused, nothing changed"
        ),
        RefusCompte::NonSignale => tr!(
            "le bilan ne propose pas de désactiver ce compte : refusé, rien changé",
            "the scan does not offer to disable this account: refused, nothing changed"
        ),
        RefusCompte::DernierAdministrateur => tr!(
            "c'est le dernier administrateur actif de l'ordinateur : refusé, rien changé",
            "this is the computer's last active administrator: refused, nothing changed"
        ),
        RefusCompte::ProgrammesIllisibles => tr!(
            "les programmes ouverts ne se lisent pas (une session à distance en dépend peut-être) : refusé, rien changé",
            "open programs cannot be read (a remote session may depend on this account): refused, nothing changed"
        ),
        RefusCompte::SessionOuverte => tr!(
            "un programme tourne sous ce compte (session ouverte, Bureau à distance ou SSH) : fermez-la d'abord ; refusé, rien changé",
            "a program runs under this account (open session, Remote Desktop or SSH): close it first; refused, nothing changed"
        ),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formes_de_windows() {
        assert_eq!(std::mem::size_of::<Utilisateur20>(), 32);
        assert_eq!(std::mem::offset_of!(Utilisateur20, drapeaux), 24);
        assert_eq!(std::mem::offset_of!(Utilisateur20, rid), 28);
        assert_eq!(std::mem::size_of::<ProgrammeWts>(), 64);
        assert_eq!(std::mem::offset_of!(ProgrammeWts, sid), 16);
    }

    /// Une session ouverte sous le compte (sur l'écran, Bureau à distance, ou SSH dans la session 0) empêche de le
    /// désactiver ; un programme sans compte lisible dans une session ouverte laisse la question sans réponse.
    #[test]
    fn programmes_du_compte() {
        let alice = "S-1-5-21-1-2-3-1001";
        let systeme = (0, Some("S-1-5-18".to_string()));
        assert_eq!(programme_du_compte(std::slice::from_ref(&systeme), alice), Some(false));
        // SSH : sshd lance les programmes du compte dans la session 0.
        assert_eq!(
            programme_du_compte(&[systeme.clone(), (0, Some(alice.to_lowercase()))], alice),
            Some(true)
        );
        // Bureau à distance : session 2.
        assert_eq!(programme_du_compte(&[(2, Some(alice.to_string()))], alice), Some(true));
        // Sans SID dans la session 0 (programmes protégés de Windows) : du système.
        assert_eq!(programme_du_compte(&[systeme.clone(), (0, None)], alice), Some(false));
        // Sans SID dans une session ouverte : illisible, donc refusé.
        assert_eq!(programme_du_compte(&[systeme, (1, None)], alice), None);
        // Le compte trouvé l'emporte : refusé de toute façon.
        assert_eq!(
            programme_du_compte(&[(1, None), (1, Some(alice.to_string()))], alice),
            Some(true)
        );
    }

    #[test]
    fn chaque_refus_est_dit() {
        for r in [
            RefusCompte::PersonneIllisible,
            RefusCompte::Introuvable,
            RefusCompte::CompteEnCours,
            RefusCompte::Reserve,
            RefusCompte::NonSignale,
            RefusCompte::DernierAdministrateur,
            RefusCompte::ProgrammesIllisibles,
            RefusCompte::SessionOuverte,
        ] {
            assert!(pourquoi(r).contains("rien chang") || pourquoi(r).contains("nothing changed"));
        }
    }
}
