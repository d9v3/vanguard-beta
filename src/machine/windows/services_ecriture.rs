//! Les actes du processus élevé (`eleve`, lignes `vanguard:service`, `vanguard:vider`…), faits sans PowerShell :
//! un service de la table arrêté (ses dépendants actifs d'abord, comme `Stop-Service -Force`), démarré, redémarré ou
//! changé de type de démarrage, auprès du gestionnaire de services (advapi32) ; un dossier de Windows vidé ou un cache
//! mis de côté (`vidage`), depuis le dossier de Windows lu à GetSystemDirectoryW, jamais dans l'environnement.
//!
//! Chaque attente est bornée (30 secondes, quel que soit le délai que le service annonce) : un service qui ne
//! s'arrête pas fait un échec lisible, jamais une fenêtre figée.

// FFI d'advapi32 : le gestionnaire de services en écriture (ChangeServiceConfigW, ControlService, StartServiceW,
// QueryServiceStatusEx, EnumDependentServicesW).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::corrections::Resultat;
use crate::machine::gestes::{Acte, Action, GesteService};
use crate::machine::vidage;
use crate::modele::Echec;
use crate::ui::{tr, trf};

/// Le contexte des échecs, au journal.
const CONTEXTE: &str = "services";

/// SERVICE_STATUS.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct EtatDuService {
    sorte: u32,
    etat: u32,
    acceptes: u32,
    code: u32,
    code_du_service: u32,
    etape: u32,
    attente: u32,
}

/// SERVICE_STATUS_PROCESS (QueryServiceStatusEx, SC_STATUS_PROCESS_INFO).
#[repr(C)]
#[derive(Default)]
struct EtatDuProcessus {
    sorte: u32,
    etat: u32,
    acceptes: u32,
    code: u32,
    code_du_service: u32,
    etape: u32,
    attente: u32,
    pid: u32,
    drapeaux: u32,
}

/// ENUM_SERVICE_STATUSW ; les noms sont rangés dans le même tampon, après les structures.
#[repr(C)]
struct Dependant {
    nom: *const u16,
    nom_affiche: *const u16,
    etat: EtatDuService,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, base: *const u16, acces: u32) -> *mut c_void;
    fn OpenServiceW(gestionnaire: *mut c_void, nom: *const u16, acces: u32) -> *mut c_void;
    fn CloseServiceHandle(objet: *mut c_void) -> i32;
    fn ChangeServiceConfigW(
        service: *mut c_void,
        sorte: u32,
        demarrage: u32,
        erreurs: u32,
        programme: *const u16,
        groupe: *const u16,
        etiquette: *mut u32,
        dependances: *const u16,
        compte: *const u16,
        mot_de_passe: *const u16,
        nom_affiche: *const u16,
    ) -> i32;
    fn ControlService(service: *mut c_void, ordre: u32, etat: *mut EtatDuService) -> i32;
    fn StartServiceW(service: *mut c_void, nombre: u32, arguments: *const *const u16) -> i32;
    fn QueryServiceStatusEx(service: *mut c_void, niveau: u32, tampon: *mut u8, taille: u32, besoin: *mut u32) -> i32;
    fn EnumDependentServicesW(
        service: *mut c_void,
        etat: u32,
        tampon: *mut Dependant,
        taille: u32,
        besoin: *mut u32,
        rendus: *mut u32,
    ) -> i32;
}

// Les droits demandés, au plus juste pour chaque acte.
const CONNEXION: u32 = 0x1;
const LIRE_LA_CONFIG: u32 = 0x1;
const CHANGER_LA_CONFIG: u32 = 0x2;
const LIRE_L_ETAT: u32 = 0x4;
const ENUMERER_LES_DEPENDANTS: u32 = 0x8;
const DEMARRER: u32 = 0x10;
const ARRETER: u32 = 0x20;

/// SERVICE_NO_CHANGE : ce que ChangeServiceConfigW laisse tel quel.
const SANS_CHANGEMENT: u32 = 0xFFFF_FFFF;
const ORDRE_D_ARRET: u32 = 1;
/// SERVICE_ACTIVE : seuls les dépendants qui tournent sont à arrêter.
const ACTIFS: u32 = 1;
const NIVEAU_PROCESSUS: u32 = 0;
const TAILLE_ETAT: u32 = 36;
const _: () = assert!(size_of::<EtatDuProcessus>() == 36);

const ARRETE: u32 = 1;
const DEMARRAGE_EN_COURS: u32 = 2;
const EN_MARCHE: u32 = 4;

const DEJA_EN_MARCHE: i32 = 1056;
const DESACTIVE: i32 = 1058;
const INTROUVABLE: i32 = 1060;
const NE_PEUT_PAS_MAINTENANT: i32 = 1061;
const PAS_ACTIF: i32 = 1062;
const PLUS_DE_DONNEES: i32 = 234;

/// Au-delà, un service ne s'est pas arrêté ou démarré : échec lisible, plutôt qu'une fenêtre figée.
const DELAI: Duration = Duration::from_secs(30);

/// Une poignée du gestionnaire de services, fermée une seule fois, à la fin de sa portée.
struct Poignee(*mut c_void);

impl Drop for Poignee {
    fn drop(&mut self) {
        // SAFETY: la poignée vient d'OpenSCManagerW ou d'OpenServiceW, non nulle (vérifié à sa création), et n'est
        // fermée qu'ici, une fois.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn derniere_erreur() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn gestionnaire() -> Result<Poignee, Echec> {
    // SAFETY: deux pointeurs nuls (cette machine, la base active) : rien d'autre n'est lu.
    let g = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), CONNEXION) };
    if g.is_null() {
        return Err(echoue(trf!(
            "le gestionnaire de services ne répond pas (code {})",
            "the service manager does not answer (code {})",
            derniere_erreur()
        )));
    }
    Ok(Poignee(g))
}

/// Le service, ouvert avec ces seuls droits ; `Ok(None)` : il n'existe pas sur ce PC.
fn ouvrir(g: &Poignee, nom: &str, droits: u32) -> Result<Option<Poignee>, Echec> {
    let large: Vec<u16> = nom.encode_utf16().chain([0]).collect();
    // SAFETY: la poignée du gestionnaire est valide pendant l'appel ; le nom est terminé par un zéro et vit pendant
    // l'appel.
    let s = unsafe { OpenServiceW(g.0, large.as_ptr(), droits) };
    if !s.is_null() {
        return Ok(Some(Poignee(s)));
    }
    match derniere_erreur() {
        INTROUVABLE => Ok(None),
        code => Err(echoue(trf!(
            "le service {nom} ne s'ouvre pas (code {code})",
            "the {nom} service cannot be opened (code {code})"
        ))),
    }
}

fn etat(s: &Poignee, nom: &str) -> Result<EtatDuProcessus, Echec> {
    let mut e = EtatDuProcessus::default();
    let mut besoin = 0u32;
    // SAFETY: `e` a la forme de SERVICE_STATUS_PROCESS (neuf u32, taille vérifiée à la compilation), vit pendant
    // l'appel, et la taille passée est la sienne ; la poignée a le droit SERVICE_QUERY_STATUS.
    let lu = unsafe { QueryServiceStatusEx(s.0, NIVEAU_PROCESSUS, (&raw mut e).cast(), TAILLE_ETAT, &raw mut besoin) };
    if lu == 0 {
        return Err(echoue(trf!(
            "l'état du service {nom} ne se lit pas (code {})",
            "the state of the {nom} service cannot be read (code {})",
            derniere_erreur()
        )));
    }
    Ok(e)
}

/// Attend que le service soit dans l'état `voulu`, 30 secondes au plus. Le pas suit le délai que le service annonce
/// (un dixième, comme l'exemple de Microsoft), borné entre 250 ms et 1 s : ni boucle serrée, ni sommeil de plusieurs
/// secondes sur la foi d'un nombre que le service choisit.
fn attendre(s: &Poignee, nom: &str, voulu: u32) -> Result<(), Echec> {
    let debut = Instant::now();
    loop {
        let e = etat(s, nom)?;
        if e.etat == voulu {
            return Ok(());
        }
        // Attendu en marche, il s'est arrêté : le démarrage a échoué, son code le dit.
        if voulu == EN_MARCHE && e.etat == ARRETE {
            return Err(echoue(trf!(
                "le service {nom} s'est arrêté pendant son démarrage (code {})",
                "the {nom} service stopped while starting (code {})",
                e.code
            )));
        }
        if debut.elapsed() >= DELAI {
            return Err(echoue(if voulu == ARRETE {
                trf!(
                    "le service {nom} ne s'est pas arrêté en {} secondes ; redémarrez l'ordinateur, puis relancez la correction",
                    "the {nom} service did not stop within {} seconds; restart the computer, then run the fix again",
                    DELAI.as_secs()
                )
            } else {
                trf!(
                    "le service {nom} n'a pas démarré en {} secondes ; redémarrez l'ordinateur, puis relancez la correction",
                    "the {nom} service did not start within {} seconds; restart the computer, then run the fix again",
                    DELAI.as_secs()
                )
            }));
        }
        let pas =
            Duration::from_millis(u64::from(e.attente / 10)).clamp(Duration::from_millis(250), Duration::from_secs(1));
        std::thread::sleep(pas);
    }
}

/// Les dépendants actifs du service, dans l'ordre où Windows les donne (celui où les arrêter : un dépendant d'un
/// dépendant avant lui).
fn dependants_actifs(s: &Poignee, nom: &str) -> Result<Vec<String>, Echec> {
    // Bien au-delà de ce que rend une vraie machine ; plus, la réponse n'est pas crue.
    const TAMPON_MAX: usize = 256 * 1024;
    let echec = |code: i32| {
        echoue(trf!(
            "les services qui dépendent de {nom} ne se lisent pas (code {code})",
            "the services that depend on {nom} cannot be read (code {code})"
        ))
    };
    let mut besoin = 0u32;
    let mut rendus = 0u32;
    // SAFETY: premier appel sans tampon (taille 0) : seule la taille nécessaire est écrite, dans `besoin` ; la
    // poignée a le droit SERVICE_ENUMERATE_DEPENDENTS.
    let fait =
        unsafe { EnumDependentServicesW(s.0, ACTIFS, std::ptr::null_mut(), 0, &raw mut besoin, &raw mut rendus) };
    if fait != 0 {
        // Réussi sans tampon : aucun dépendant actif.
        return Ok(Vec::new());
    }
    let code = derniere_erreur();
    if code != PLUS_DE_DONNEES {
        return Err(echec(code));
    }
    let voulu = usize::try_from(besoin).map_err(|_| echec(code))?;
    if voulu > TAMPON_MAX {
        return Err(echec(code));
    }
    // Des u64 : le tampon est aligné pour les structures et leurs pointeurs.
    let mut tampon = vec![0u64; voulu.div_ceil(8)];
    let octets = tampon.len() * 8;
    let taille = u32::try_from(octets).map_err(|_| echec(code))?;
    // SAFETY: le tampon fait `octets` octets, la taille passée, aligné sur 8, et vit pendant l'appel.
    let fait = unsafe {
        EnumDependentServicesW(
            s.0,
            ACTIFS,
            tampon.as_mut_ptr().cast(),
            taille,
            &raw mut besoin,
            &raw mut rendus,
        )
    };
    if fait == 0 {
        return Err(echec(derniere_erreur()));
    }
    let rendus = usize::try_from(rendus).map_err(|_| echec(0))?;
    if rendus.checked_mul(size_of::<Dependant>()).is_none_or(|t| t > octets) {
        return Err(echec(0));
    }
    let debut = tampon.as_ptr().addr();
    let fin = debut + octets;
    // SAFETY: l'appel a réussi ; le tampon (aligné sur 8, initialisé) commence par `rendus` structures, dont la taille
    // totale est vérifiée plus petite que lui.
    let liste = unsafe { std::slice::from_raw_parts(tampon.as_ptr().cast::<Dependant>(), rendus) };
    // Un nom de la réponse : son pointeur doit tomber dans le tampon, aligné, et la lecture s'arrête au premier zéro
    // ou à la fin du tampon, jamais au-delà.
    let texte = |p: *const u16| -> Option<String> {
        let a = p.addr();
        if p.is_null() || a < debut || a >= fin || !a.is_multiple_of(2) {
            return None;
        }
        // SAFETY: [a, fin) est dans le tampon (borne vérifiée juste au-dessus), aligné sur 2, initialisé.
        let mots = unsafe { std::slice::from_raw_parts(p, (fin - a) / 2) };
        let nom = String::from_utf16_lossy(mots.split(|&m| m == 0).next().unwrap_or(mots));
        (!nom.is_empty()).then_some(nom)
    };
    liste.iter().map(|d| texte(d.nom).ok_or_else(|| echec(0))).collect()
}

/// Envoie l'ordre d'arrêt ; `Ok(false)` : il était déjà arrêté.
fn envoyer_l_arret(s: &Poignee, nom: &str) -> Result<bool, Echec> {
    let mut e = EtatDuService::default();
    // SAFETY: la poignée a le droit SERVICE_STOP ; `e` a la forme de SERVICE_STATUS et vit pendant l'appel.
    if unsafe { ControlService(s.0, ORDRE_D_ARRET, &raw mut e) } != 0 {
        return Ok(true);
    }
    match derniere_erreur() {
        PAS_ACTIF => Ok(false),
        // Déjà en train de s'arrêter : il n'y a plus qu'à attendre.
        NE_PEUT_PAS_MAINTENANT if etat(s, nom)?.etat != EN_MARCHE => Ok(true),
        code => Err(echoue(trf!(
            "le service {nom} refuse de s'arrêter (code {code})",
            "the {nom} service refuses to stop (code {code})"
        ))),
    }
}

enum Arret {
    Absent,
    DejaArrete,
    /// Arrêté, avec les dépendants qu'il a fallu arrêter d'abord.
    Arrete(Vec<String>),
}

/// Arrête le service, ses dépendants actifs d'abord (chacun attendu), comme `Stop-Service -Force`.
fn arreter(g: &Poignee, nom: &str) -> Result<Arret, Echec> {
    let Some(s) = ouvrir(g, nom, ARRETER | LIRE_L_ETAT | ENUMERER_LES_DEPENDANTS)? else {
        return Ok(Arret::Absent);
    };
    if etat(&s, nom)?.etat == ARRETE {
        return Ok(Arret::DejaArrete);
    }
    let mut arretes = Vec::new();
    for d in dependants_actifs(&s, nom)? {
        // Disparu ou arrêté entre-temps : rien à faire pour lui, ni à relancer ensuite.
        let Some(ds) = ouvrir(g, &d, ARRETER | LIRE_L_ETAT)? else {
            continue;
        };
        if envoyer_l_arret(&ds, &d)? {
            attendre(&ds, &d, ARRETE)?;
            arretes.push(d);
        }
    }
    if envoyer_l_arret(&s, nom)? {
        attendre(&s, nom, ARRETE)?;
    }
    Ok(Arret::Arrete(arretes))
}

enum Demarrage {
    Absent,
    DejaEnMarche,
    Demarre,
}

fn demarrer(g: &Poignee, nom: &str) -> Result<Demarrage, Echec> {
    let Some(s) = ouvrir(g, nom, DEMARRER | LIRE_L_ETAT)? else {
        return Ok(Demarrage::Absent);
    };
    if etat(&s, nom)?.etat == EN_MARCHE {
        return Ok(Demarrage::DejaEnMarche);
    }
    // SAFETY: la poignée a le droit SERVICE_START ; aucun argument (0, pointeur nul).
    if unsafe { StartServiceW(s.0, 0, std::ptr::null()) } == 0 {
        return match derniere_erreur() {
            DEJA_EN_MARCHE => Ok(Demarrage::DejaEnMarche),
            DESACTIVE => Err(echoue(trf!(
                "le service {nom} est désactivé : il ne peut pas démarrer (code {DESACTIVE})",
                "the {nom} service is disabled: it cannot start (code {DESACTIVE})"
            ))),
            code => Err(echoue(trf!(
                "le service {nom} refuse de démarrer (code {code})",
                "the {nom} service refuses to start (code {code})"
            ))),
        };
    }
    // Un démarrage déjà en cours (lancé par un autre) compte aussi : on attend qu'il aboutisse.
    let e = etat(&s, nom)?;
    if e.etat != EN_MARCHE && e.etat != DEMARRAGE_EN_COURS && e.etat != ARRETE {
        return Err(echoue(trf!(
            "le service {nom} est dans un état inattendu ({})",
            "the {nom} service is in an unexpected state ({})",
            e.etat
        )));
    }
    attendre(&s, nom, EN_MARCHE)?;
    Ok(Demarrage::Demarre)
}

enum Reglage {
    Absent,
    Deja,
    Change,
}

/// Le type de démarrage (2 automatique, 3 manuel, 4 désactivé), et rien d'autre. Automatique ne touche pas au
/// démarrage différé (DelayedAutostart, que seul ChangeServiceConfig2W règle) : UsoSvc est en automatique différé
/// d'origine, il le reste.
fn regler(g: &Poignee, nom: &str, demarrage: u32) -> Result<Reglage, Echec> {
    let Some(s) = ouvrir(g, nom, CHANGER_LA_CONFIG | LIRE_LA_CONFIG)? else {
        return Ok(Reglage::Absent);
    };
    if super::gestionnaire::demarrage(nom) == Some(demarrage) {
        return Ok(Reglage::Deja);
    }
    // SAFETY: la poignée a le droit SERVICE_CHANGE_CONFIG ; SERVICE_NO_CHANGE pour la sorte et les erreurs, et des
    // pointeurs nuls pour le reste : ni programme, ni groupe, ni étiquette, ni dépendances, ni compte, ni mot de
    // passe, ni nom affiché ne changent.
    let fait = unsafe {
        ChangeServiceConfigW(
            s.0,
            SANS_CHANGEMENT,
            demarrage,
            SANS_CHANGEMENT,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if fait == 0 {
        return Err(echoue(trf!(
            "le type de démarrage du service {nom} n'a pas changé (code {})",
            "the startup type of the {nom} service did not change (code {})",
            derniere_erreur()
        )));
    }
    Ok(Reglage::Change)
}

fn absent(nom: &str) -> Echec {
    Echec::refuse(
        CONTEXTE,
        trf!(
            "le service {nom} n'existe pas sur ce PC",
            "the {nom} service does not exist on this PC"
        ),
    )
}

/// Un échec du gestionnaire de services, dit tel quel (la phrase porte déjà le code de Windows).
fn echoue(phrase: String) -> Echec {
    Echec::echoue(CONTEXTE, phrase)
}

/// Ce que le service devient ; `Ok` : la précision à dire (vide : rien de plus que « OK »).
fn service(s: &GesteService) -> Result<String, Echec> {
    let g = gestionnaire()?;
    let nom = s.nom;
    let liste = |l: &[String]| {
        l.iter()
            .map(|n| crate::ui::affichable(n))
            .collect::<Vec<_>>()
            .join(", ")
    };
    match s.action {
        Action::Arreter => Ok(match arreter(&g, nom)? {
            Arret::Absent => tr!("service absent : rien à arrêter", "service missing: nothing to stop").to_string(),
            Arret::DejaArrete => tr!("déjà arrêté", "already stopped").to_string(),
            Arret::Arrete(d) if d.is_empty() => String::new(),
            Arret::Arrete(d) => trf!(
                "arrêtés d'abord, parce qu'ils en dépendent : {}",
                "stopped first, because they depend on it: {}",
                liste(&d)
            ),
        }),
        Action::Demarrer => match demarrer(&g, nom)? {
            Demarrage::Absent => Err(absent(nom)),
            Demarrage::DejaEnMarche => Ok(tr!("déjà démarré", "already running").to_string()),
            Demarrage::Demarre => Ok(String::new()),
        },
        Action::Redemarrer => {
            let dependants = match arreter(&g, nom)? {
                Arret::Absent => return Err(absent(nom)),
                Arret::DejaArrete => Vec::new(),
                Arret::Arrete(d) => d,
            };
            if let Demarrage::Absent = demarrer(&g, nom)? {
                return Err(absent(nom));
            }
            // Relancés dans l'ordre inverse de l'arrêt : chacun après ceux dont il dépend.
            let mut rates = Vec::new();
            for d in dependants.iter().rev() {
                match demarrer(&g, d) {
                    Ok(Demarrage::Demarre | Demarrage::DejaEnMarche) => {}
                    Ok(Demarrage::Absent) => rates.push(absent(d).to_string()),
                    Err(e) => rates.push(e.to_string()),
                }
            }
            if !rates.is_empty() {
                return Err(echoue(trf!(
                    "{nom} redémarré, mais pas tout ce qui en dépend : {}",
                    "{nom} restarted, but not everything that depends on it: {}",
                    rates.join(" ; ")
                )));
            }
            Ok(if dependants.is_empty() {
                String::new()
            } else {
                trf!(
                    "relancés aussi, parce qu'ils en dépendent : {}",
                    "also restarted, because they depend on it: {}",
                    liste(&dependants)
                )
            })
        }
        Action::Desactive => Ok(match regler(&g, nom, 4)? {
            Reglage::Absent => tr!(
                "service absent : rien à désactiver",
                "service missing: nothing to disable"
            )
            .to_string(),
            Reglage::Deja => tr!("déjà désactivé", "already disabled").to_string(),
            Reglage::Change => String::new(),
        }),
        Action::Manuel | Action::Auto => {
            let (demarrage, deja) = if s.action == Action::Manuel {
                (3, tr!("déjà en manuel", "already manual"))
            } else {
                (2, tr!("déjà en automatique", "already automatic"))
            };
            match regler(&g, nom, demarrage)? {
                Reglage::Absent => Err(absent(nom)),
                Reglage::Deja => Ok(deja.to_string()),
                Reglage::Change => Ok(String::new()),
            }
        }
        Action::Reactiver => {
            if ouvrir(&g, nom, LIRE_LA_CONFIG)?.is_none() {
                return Err(absent(nom));
            }
            match super::gestionnaire::demarrage(nom) {
                Some(4) => match regler(&g, nom, 3)? {
                    Reglage::Absent => Err(absent(nom)),
                    Reglage::Deja | Reglage::Change => {
                        Ok(tr!("était désactivé : remis en manuel", "was disabled: set back to manual").to_string())
                    }
                },
                Some(_) => Ok(tr!("pas désactivé : rien à changer", "not disabled: nothing to change").to_string()),
                None => Err(echoue(trf!(
                    "le type de démarrage du service {nom} ne se lit pas",
                    "the startup type of the {nom} service cannot be read"
                ))),
            }
        }
    }
}

/// Le dossier de Windows : le parent de System32 (GetSystemDirectoryW), jamais une variable d'environnement, que le
/// compte qui a lancé Vanguard choisit.
fn dossier_windows() -> Result<PathBuf, Echec> {
    crate::commande::dossier_systeme()
        .parent()
        .filter(|p| p.is_absolute() && p.parent().is_some())
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| {
            echoue(
                tr!(
                    "le dossier de Windows est introuvable",
                    "the Windows folder cannot be found"
                )
                .to_string(),
            )
        })
}

/// Le dossier de la file d'impression sous celui de Windows, en dossiers : DefaultSpoolDirectory du spouleur
/// (absent : `System32\spool\PRINTERS`), refusé s'il n'est pas vraiment sous le dossier de Windows.
fn file_d_impression(windows: &std::path::Path) -> Result<Vec<String>, Echec> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    let lu: Option<String> = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Control\Print\Printers", KEY_READ)
        .ok()
        .and_then(|k| k.get_value("DefaultSpoolDirectory").ok())
        .filter(|c: &String| !c.trim().is_empty());
    // Une valeur écrite « %SystemRoot%\… » (REG_EXPAND_SZ, que winreg rend telle quelle) : le dossier de Windows pris
    // par ce processus, jamais l'environnement. Tout autre `%` reste, et `sous_windows` le refuse.
    let lu = lu.map(|c| vidage::developper_windows(&c, &windows.to_string_lossy()));
    let chemin = lu.unwrap_or_else(|| format!(r"{}\System32\spool\PRINTERS", windows.display()));
    vidage::sous_windows(&windows.to_string_lossy(), &chemin).ok_or_else(|| {
        Echec::refuse(
            CONTEXTE,
            trf!(
                "le dossier de la file d'impression ({}) n'est pas sous celui de Windows : refusé, rien n'est effacé",
                "the print queue folder ({}) is not under the Windows folder: refused, nothing is deleted",
                crate::ui::affichable(&chemin)
            ),
        )
    })
}

/// Fait un acte de la liste ; la précision (« déjà arrêté », « 12 retirés… ») part au parent avec le « ok ».
pub(crate) fn faire(acte: &Acte) -> Resultat {
    let r = match acte {
        Acte::Service(s) => service(s),
        Acte::Vider(v) => dossier_windows().and_then(|w| vidage::vider_sous(&w, *v)),
        Acte::ViderFileImpression => {
            dossier_windows().and_then(|w| file_d_impression(&w).and_then(|relatif| vidage::vider_file(&w, &relatif)))
        }
        Acte::MettreDeCote(c) => dossier_windows()
            .and_then(|w| vidage::mettre_de_cote(&w, *c, &chrono::Local::now().format("%Y%m%d%H%M").to_string())),
    };
    match r {
        Ok(note) => Resultat {
            reussi: true,
            avant: None,
            raison: note,
        },
        Err(e) => Resultat {
            reussi: false,
            avant: None,
            raison: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_structures_ont_la_taille_de_windows() {
        assert_eq!(size_of::<EtatDuService>(), 28);
        assert_eq!(size_of::<EtatDuProcessus>(), 36);
        // Deux pointeurs puis SERVICE_STATUS, arrondi à l'alignement d'un pointeur.
        #[cfg(target_pointer_width = "64")]
        assert_eq!(size_of::<Dependant>(), 48);
        #[cfg(target_pointer_width = "32")]
        assert_eq!(size_of::<Dependant>(), 36);
    }

    /// Le vrai gestionnaire de services (Wine ici, la VM ensuite), sur un service qui n'existe pas : rien n'est
    /// changé nulle part. Arrêter ou désactiver un absent, c'est fait (rien à faire) ; le démarrer ou le mettre en
    /// manuel, non.
    #[test]
    fn un_service_absent() {
        let geste = |action| GesteService {
            nom: "VanguardServiceInexistant",
            action,
            durcit: false,
            affaiblit: false,
        };
        if gestionnaire().is_err() {
            return crate::essais::saute("gestionnaire de services injoignable");
        }
        for action in [Action::Arreter, Action::Desactive] {
            assert!(service(&geste(action)).is_ok(), "{action:?}");
        }
        for action in [
            Action::Demarrer,
            Action::Redemarrer,
            Action::Manuel,
            Action::Auto,
            Action::Reactiver,
        ] {
            let r = service(&geste(action));
            assert!(
                r.as_ref().is_err_and(|e| e.to_string().contains("n'existe pas")),
                "{action:?} {r:?}"
            );
        }
    }
}
