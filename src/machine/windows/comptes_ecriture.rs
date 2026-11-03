//! Désactiver un compte local (`vanguard:compte-desactiver <RID>`, grammaire de `gestes.rs`), dans le processus élevé,
//! par netapi32 (NetUserSetInfo niveau 1008), sans PowerShell.
//!
//! Le processus élevé relit tout avant d'écrire : les comptes, le bilan des comptes (la ligne doit y être proposée,
//! automatiquement), les administrateurs et les programmes ouverts. Il refuse la personne, son propre compte, le
//! dernier administrateur actif, un compte réservé de Windows et un compte sous lequel tourne un programme (une
//! session ouverte sur l'écran, par le Bureau à distance ou SSH en dépend) : `gestes::refus_desactivation`. Après
//! l'écriture, le compte est relu : seul le drapeau relu compte. Le geste ne donne de droits à personne ; il n'est pas
//! défait par Vanguard (une protection), la personne peut réactiver le compte dans Windows.
//!
//! Poser un mot de passe sur un compte local qui n'en exige pas (`vanguard:compte-mot-de-passe <RID>`, défense D6b,
//! R43) : le bilan relu doit le proposer ; jamais sur un compte Microsoft (Windows gère ce mot de passe en ligne),
//! jamais pendant une session à distance ou SSH ouverte sur ce compte (`gestes::refus_session_mdp`, relu juste avant
//! d'écrire). Le mot de passe se tape deux fois dans la console du processus élevé, sans écho ; jamais par le tube,
//! jamais dans la liste des changements ni un journal ; ses tampons sont mis à zéro juste après NetUserSetInfo niveau
//! 1003. Le drapeau « mot de passe non exigé » n'est retiré qu'ensuite. Non annulable : question « non annulable ».

// FFI de netapi32, wtsapi32 et kernel32 : NetUserGetInfo, NetUserSetInfo, WTSEnumerateProcessesExW,
// WTSQuerySessionInformationW, ReadConsoleW.
#![allow(unsafe_code)]

use super::comptes::{self, NetApiBufferFree, NetUserGetInfo, NetUserSetInfo, large, sid_texte};
use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, EtatCompte, RefusCompte, RefusSessionMdp};
use crate::ui::{tr, trf, trp};

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
    fn WTSQuerySessionInformationW(
        serveur: *mut std::ffi::c_void,
        session: u32,
        classe: u32,
        tampon: *mut *mut u16,
        octets: *mut u32,
    ) -> i32;
    fn WTSFreeMemory(memoire: *mut std::ffi::c_void);
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetStdHandle(quelle: u32) -> *mut std::ffi::c_void;
    fn GetConsoleMode(console: *mut std::ffi::c_void, mode: *mut u32) -> i32;
    fn SetConsoleMode(console: *mut std::ffi::c_void, mode: u32) -> i32;
    fn ReadConsoleW(
        console: *mut std::ffi::c_void,
        tampon: *mut u16,
        a_lire: u32,
        lus: *mut u32,
        controle: *const std::ffi::c_void,
    ) -> i32;
}

/// UF_PASSWD_NOTREQD : « mot de passe non exigé ».
const NON_EXIGE: u32 = 0x20;

/// USER_INFO_24 de lmaccess.h (32 octets en 64 bits) : le compte est-il lié à un compte Microsoft ?
#[repr(C)]
struct Utilisateur24 {
    identite_en_ligne: i32,
    _drapeaux: u32,
    _fournisseur: *const u16,
    _nom_en_ligne: *const u16,
    _sid: *mut std::ffi::c_void,
}

/// USER_INFO_1003 : le nouveau mot de passe.
#[repr(C)]
struct Utilisateur1003 {
    mot_de_passe: *const u16,
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

/// Un mot de passe tapé : ses caractères, mis à zéro quand il disparaît.
struct Secret(Vec<u16>);

impl Secret {
    fn effacer(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.effacer();
    }
}

/// Le plus long mot de passe accepté (Windows en garde 256 caractères, LM20_PWLEN… PWLEN).
const MOT_DE_PASSE_MAX: usize = 256;

/// Ce que la saisie a donné : le mot de passe (sans le retour à la ligne), ou pourquoi il n'est pas pris.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Saisie {
    Illisible,
    Vide,
    TropLong,
    Different,
}

/// Les deux saisies jugées : la même, non vide, pas plus longue que `MOT_DE_PASSE_MAX`, sans caractère nul (il
/// couperait le mot de passe donné à Windows).
fn juger_saisies(a: &[u16], b: &[u16]) -> Result<(), Saisie> {
    if a.is_empty() {
        return Err(Saisie::Vide);
    }
    if a.len() > MOT_DE_PASSE_MAX || a.contains(&0) {
        return Err(Saisie::TropLong);
    }
    if a != b {
        return Err(Saisie::Different);
    }
    Ok(())
}

/// Une ligne lue par ReadConsoleW, sans le retour à la ligne (CR LF, ou LF seul) ; `None` si la ligne n'est pas
/// finie (plus longue que le tampon).
fn sans_fin_de_ligne(lus: &[u16]) -> Option<&[u16]> {
    let fin = lus.iter().position(|&c| c == u16::from(b'\n'))?;
    let ligne = lus.get(..fin)?;
    Some(ligne.strip_suffix(&[u16::from(b'\r')]).unwrap_or(ligne))
}

/// Les drapeaux d'un compte une fois le mot de passe posé : « non exigé » retiré, UF_SCRIPT gardé (NetUserSetInfo
/// l'exige), rien d'autre ne change.
fn drapeaux_exiges(d: u32) -> u32 {
    (d & !NON_EXIGE) | SCRIPT
}

/// Lit une ligne dans la console du processus, sans écho (le mode d'avant est remis) ; `Illisible` si l'entrée n'est
/// pas une console ou si la lecture échoue. Une ligne trop longue est lue jusqu'au bout puis refusée (`TropLong`).
fn lire_masque() -> Result<Secret, Saisie> {
    const ENTREE_STANDARD: u32 = 0xFFFF_FFF6;
    /// ENABLE_ECHO_INPUT.
    const ECHO: u32 = 0x4;
    // SAFETY: simple lecture d'une poignée du processus, sans pointeur.
    let entree = unsafe { GetStdHandle(ENTREE_STANDARD) };
    if entree.is_null() || entree as isize == -1 {
        return Err(Saisie::Illisible);
    }
    let mut mode = 0u32;
    // SAFETY: `entree` est la poignée d'entrée du processus, `mode` une variable vivante pendant l'appel ; une poignée
    // qui n'est pas une console fait échouer l'appel.
    if unsafe { GetConsoleMode(entree, &raw mut mode) } == 0 {
        return Err(Saisie::Illisible);
    }
    // SAFETY: la même poignée, un mode sans pointeur.
    if unsafe { SetConsoleMode(entree, mode & !ECHO) } == 0 {
        return Err(Saisie::Illisible);
    }
    let mut tampon = Secret(vec![0u16; MOT_DE_PASSE_MAX + 2]);
    let mut lu = None;
    let mut trop_long = false;
    loop {
        let mut n = 0u32;
        let capacite = u32::try_from(tampon.0.len()).unwrap_or(0);
        // SAFETY: `tampon` a `capacite` caractères, vivants pendant l'appel ; Windows en écrit au plus autant et dit
        // combien dans `n` ; pas de contrôle de lecture (nul).
        let ok = unsafe { ReadConsoleW(entree, tampon.0.as_mut_ptr(), capacite, &raw mut n, std::ptr::null()) } != 0;
        let n = usize::try_from(n).unwrap_or(0).min(tampon.0.len());
        if !ok || n == 0 {
            break;
        }
        let lus = tampon.0.get(..n).unwrap_or_default();
        if let Some(ligne) = sans_fin_de_ligne(lus) {
            if !trop_long {
                lu = Some(Secret(ligne.to_vec()));
            }
            break;
        }
        // Pas de fin de ligne : la suite viendra au prochain appel ; le mot de passe est trop long.
        trop_long = true;
        tampon.0.fill(0);
    }
    // SAFETY: la même poignée, le mode lu plus haut.
    unsafe { SetConsoleMode(entree, mode) };
    println!();
    if trop_long {
        return Err(Saisie::TropLong);
    }
    lu.ok_or(Saisie::Illisible)
}

/// Le compte est-il lié à un compte Microsoft (USER_INFO_24) ? `None` si Windows ne le dit pas.
fn compte_microsoft(nom: &[u16]) -> Option<bool> {
    let mut info: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: NetUserGetInfo niveau 24 écrit un USER_INFO_24 alloué par Windows (que `Utilisateur24` reproduit), lu
    // tant qu'il vit puis rendu une seule fois.
    unsafe {
        let code = NetUserGetInfo(std::ptr::null(), nom.as_ptr(), 24, &raw mut info);
        if code != 0 || info.is_null() {
            if !info.is_null() {
                NetApiBufferFree(info);
            }
            return None;
        }
        let u = info.cast::<Utilisateur24>().read_unaligned();
        NetApiBufferFree(info);
        Some(u.identite_en_ligne != 0)
    }
}

/// Le protocole d'une session (WTSClientProtocolType : 0 la console, 2 le Bureau à distance) ; `None` illisible.
fn protocole(session: u32) -> Option<u16> {
    /// WTSClientProtocolType.
    const PROTOCOLE: u32 = 16;
    let mut tampon: *mut u16 = std::ptr::null_mut();
    let mut octets = 0u32;
    // SAFETY: le serveur nul est cet ordinateur ; Windows alloue un USHORT dans `tampon` (`octets` en dit la taille),
    // lu s'il en a au moins deux, puis rendu une seule fois par WTSFreeMemory.
    unsafe {
        let ok = WTSQuerySessionInformationW(
            std::ptr::null_mut(),
            session,
            PROTOCOLE,
            &raw mut tampon,
            &raw mut octets,
        ) != 0;
        if !ok || tampon.is_null() {
            return None;
        }
        let p = (octets >= 2).then(|| tampon.read_unaligned());
        WTSFreeMemory(tampon.cast());
        p
    }
}

/// La garde de session du mot de passe, sur la lecture d'à l'instant : `None` si rien ne s'y oppose.
fn refus_session(sid: &str) -> Option<Resultat> {
    gestes::refus_session_mdp(programmes().as_deref(), sid, protocole).map(|r| {
        Resultat::echec(
            None,
            match r {
                RefusSessionMdp::ADistance => tr!(
                    "une session à distance (Bureau à distance, SSH) ou un service tourne sous ce compte : Vanguard n'y pose pas de mot de passe pendant qu'elle est ouverte ; rien changé",
                    "a remote session (Remote Desktop, SSH) or a service runs under this account: Vanguard does not set a password while it is open; nothing changed"
                ),
                RefusSessionMdp::Illisible => tr!(
                    "les sessions de ce compte ne se lisent pas (une session à distance en dépend peut-être) : refusé, rien changé",
                    "this account's sessions cannot be read (a remote session may depend on it): refused, nothing changed"
                ),
            }
            .to_string(),
        )
    })
}

fn echec(fr: &str, en: &str) -> Resultat {
    Resultat::echec(None, if crate::langue::anglais() { en } else { fr }.to_string())
}

/// Pose un mot de passe sur le compte local de ce RID (signalé par le bilan relu : il n'en exige pas), puis exige
/// toujours un mot de passe pour lui ; `personne` : le SID de la personne.
pub(super) fn poser_mot_de_passe(rid: u32, personne: Option<&str>) -> Resultat {
    let Some(liste) = comptes::comptes_natifs() else {
        return echec(
            "comptes illisibles, rien changé",
            "accounts unreadable, nothing changed",
        );
    };
    let cibles: Vec<&comptes::Compte> = liste
        .iter()
        .filter(|c| gestes::rid_local(&c.sid) == Some(rid))
        .collect();
    let [c] = cibles.as_slice() else {
        return Resultat::echec(None, pourquoi(RefusCompte::Introuvable));
    };
    let nom = c.nom.clone();
    let sid = c.sid.clone();
    let affiche = crate::ui::affichable(&nom);
    if c.mot_de_passe_exige {
        return Resultat::rien(trf!(
            "« {affiche} » exige déjà un mot de passe, rien changé",
            "“{affiche}” already requires a password, nothing changed"
        ));
    }
    if !signale(&liste, personne, &gestes::Acte::CompteMotDePasse(rid).ligne()) {
        return Resultat::echec(
            None,
            tr!(
                "le bilan ne propose pas de mot de passe pour ce compte : refusé, rien changé",
                "the scan does not offer a password for this account: refused, nothing changed"
            )
            .to_string(),
        );
    }
    let nom_large = large(&nom);
    let Some(avant) = drapeaux(&nom_large, rid) else {
        return echec(
            "compte illisible ou renommé entre-temps, rien changé",
            "account unreadable or renamed meanwhile, nothing changed",
        );
    };
    let note = avant_notable(&format!("{affiche} : drapeaux 0x{avant:08x}"));
    if compte_microsoft(&nom_large) == Some(true) {
        return Resultat::echec(
            Some(note),
            tr!(
                "compte lié à un compte Microsoft : son mot de passe se change en ligne (account.microsoft.com) ou dans Paramètres > Comptes, pas par Vanguard ; rien changé",
                "account linked to a Microsoft account: its password is changed online (account.microsoft.com) or in Settings > Accounts, not by Vanguard; nothing changed"
            )
            .to_string(),
        );
    }
    if let Some(r) = refus_session(&sid) {
        return r;
    }
    // Jamais par le tube : le mot de passe se tape ici, dans la console de cette fenêtre.
    if !super::eleve::console_reelle() {
        return echec(
            "le mot de passe se tape seulement dans la fenêtre administrateur de Vanguard (pas de console ici) : rien changé",
            "the password is typed only in Vanguard's administrator window (no console here): nothing changed",
        );
    }
    let question = trf!(
        "  Poser un mot de passe sur « {affiche} », puis l'exiger toujours.\n  Il remplace celui que le compte aurait déjà ; un programme ou une tâche qui ouvre ce compte devra recevoir le nouveau. Retenez-le : Vanguard ne le garde nulle part.\n  Le poser, non annulable ? [o/N] : ",
        "  Set a password on “{affiche}”, then always require one.\n  It replaces any password the account already has; a program or task that signs in to this account will need the new one. Remember it: Vanguard keeps it nowhere.\n  Set it, not undoable? [y/N]: "
    );
    if !crate::machine::reglages::confirmer(true, &question, crate::ui::demander_ou_defaut) {
        return Resultat::echec(
            Some(note),
            tr!("non confirmé : rien changé", "not confirmed: nothing changed").to_string(),
        );
    }
    print!(
        "{}",
        tr!(
            "  Nouveau mot de passe (rien ne s'affiche) : ",
            "  New password (nothing is shown): "
        )
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let premier = lire_masque();
    print!(
        "{}",
        tr!("  Le même, une seconde fois : ", "  The same, a second time: ")
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let second = lire_masque();
    let jugees = match (&premier, &second) {
        (Ok(a), Ok(b)) => juger_saisies(&a.0, &b.0),
        (Err(e), _) | (_, Err(e)) => Err(*e),
    };
    drop(second);
    let premier = match (jugees, premier) {
        (Ok(()), Ok(p)) => p,
        (Err(e), _) | (Ok(()), Err(e)) => {
            return Resultat::echec(
                Some(note),
                match e {
                    Saisie::Illisible => tr!("saisie illisible : rien changé", "input unreadable: nothing changed"),
                    Saisie::Vide => tr!("mot de passe vide : rien changé", "empty password: nothing changed"),
                    Saisie::TropLong => tr!(
                        "mot de passe trop long ou caractère interdit : rien changé",
                        "password too long or forbidden character: nothing changed"
                    ),
                    Saisie::Different => tr!(
                        "les deux saisies diffèrent : rien changé",
                        "the two entries differ: nothing changed"
                    ),
                }
                .to_string(),
            );
        }
    };
    // Relu juste avant d'écrire : une session ouverte pendant la saisie refuse encore.
    if let Some(r) = refus_session(&sid) {
        return r;
    }
    let mut avec_nul = Secret(premier.0.clone());
    drop(premier);
    avec_nul.0.push(0);
    let info = Utilisateur1003 {
        mot_de_passe: avec_nul.0.as_ptr(),
    };
    let mut erreur = 0u32;
    // SAFETY: USER_INFO_1003 est un pointeur vers le mot de passe terminé par un nul, vivant pendant l'appel (`info` et
    // `avec_nul` sont gardés jusqu'après) ; `erreur` reçoit l'indice d'un paramètre refusé.
    let code = unsafe {
        NetUserSetInfo(
            std::ptr::null(),
            nom_large.as_ptr(),
            1003,
            (&raw const info).cast(),
            &raw mut erreur,
        )
    };
    let _ = &info;
    drop(avec_nul);
    if code != 0 {
        return Resultat::echec(
            Some(note),
            match code {
                // NERR_PasswordTooShort : la stratégie des mots de passe le refuse (longueur, complexité, historique).
                2245 => tr!(
                    "Windows refuse ce mot de passe (trop court, pas assez complexe, ou déjà utilisé) : rien changé",
                    "Windows refuses this password (too short, not complex enough, or used before): nothing changed"
                )
                .to_string(),
                _ => trf!(
                    "Windows refuse de poser le mot de passe (code {code}) : rien changé",
                    "Windows refuses to set the password (code {code}): nothing changed"
                ),
            },
        );
    }
    trp!("  Mot de passe posé.", "  Password set.");
    // Le drapeau seulement après : un compte sans mot de passe qui « l'exigerait » se dirait sain.
    let Some(d) = drapeaux(&nom_large, rid) else {
        return Resultat::echec(
            Some(note),
            tr!(
                "mot de passe posé, mais le compte ne se relit pas : le réglage « mot de passe non exigé » reste peut-être",
                "password set, but the account cannot be read back: the “password not required” setting may remain"
            )
            .to_string(),
        );
    };
    let nouveaux = drapeaux_exiges(d);
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
    match (code, drapeaux(&nom_large, rid)) {
        (0, Some(relu)) if relu & NON_EXIGE == 0 => Resultat::fait(note),
        _ => Resultat::echec(
            Some(note),
            trf!(
                "mot de passe posé, mais Windows n'exige pas encore de mot de passe pour ce compte (code {code}) : relancez le bilan",
                "password set, but Windows does not require a password for this account yet (code {code}): run the scan again"
            ),
        ),
    }
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
    fn formes_du_mot_de_passe() {
        assert_eq!(std::mem::size_of::<Utilisateur24>(), 32);
        assert_eq!(std::mem::offset_of!(Utilisateur24, identite_en_ligne), 0);
        assert_eq!(std::mem::size_of::<Utilisateur1003>(), 8);
    }

    fn u(t: &str) -> Vec<u16> {
        t.encode_utf16().collect()
    }

    /// La ligne tapée perd son retour à la ligne (CR LF ou LF), rien d'autre ; sans fin de ligne, elle n'est pas
    /// finie.
    #[test]
    fn fin_de_ligne_retiree() {
        assert_eq!(sans_fin_de_ligne(&u("abc\r\n")), Some(u("abc").as_slice()));
        assert_eq!(sans_fin_de_ligne(&u("a b\n")), Some(u("a b").as_slice()));
        assert_eq!(sans_fin_de_ligne(&u("\r\n")), Some(&[][..]));
        assert_eq!(sans_fin_de_ligne(&u(" x\r\r\n")), Some(u(" x\r").as_slice()));
        assert_eq!(sans_fin_de_ligne(&u("abc")), None);
    }

    /// Vide, différent, trop long ou avec un nul : refusé.
    #[test]
    fn saisies_jugees() {
        assert_eq!(juger_saisies(&u("Été 2026!"), &u("Été 2026!")), Ok(()));
        assert_eq!(juger_saisies(&[], &[]), Err(Saisie::Vide));
        assert_eq!(juger_saisies(&u("a"), &u("b")), Err(Saisie::Different));
        assert_eq!(juger_saisies(&u("a"), &u("a ")), Err(Saisie::Different));
        let long = vec![u16::from(b'x'); MOT_DE_PASSE_MAX + 1];
        assert_eq!(juger_saisies(&long, &long), Err(Saisie::TropLong));
        let juste = vec![u16::from(b'x'); MOT_DE_PASSE_MAX];
        assert_eq!(juger_saisies(&juste, &juste), Ok(()));
        assert_eq!(juger_saisies(&[97, 0, 98], &[97, 0, 98]), Err(Saisie::TropLong));
    }

    /// Seul « non exigé » tombe ; UF_SCRIPT est toujours là ; « désactivé » et le reste ne bougent pas.
    #[test]
    fn drapeaux_apres_le_mot_de_passe() {
        assert_eq!(drapeaux_exiges(0x221), 0x201);
        assert_eq!(drapeaux_exiges(0x20), 0x1);
        assert_eq!(drapeaux_exiges(0x2 | 0x20 | 0x1_0000), 0x2 | 0x1 | 0x1_0000);
        assert_eq!(drapeaux_exiges(0x201), 0x201);
    }

    #[test]
    fn secret_mis_a_zero() {
        let mut s = Secret(u("motdepasse"));
        s.effacer();
        assert!(s.0.iter().all(|&c| c == 0));
        assert_eq!(s.0.len(), 10);
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
