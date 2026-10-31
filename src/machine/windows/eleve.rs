//! Le processus élevé qui applique les corrections natives (`corrections`) et les ordres du blocage
//! (`protection::blocage::ordres`) : Vanguard se relance lui-même en administrateur (une seule demande UAC, qui
//! nomme Vanguard et non « Windows PowerShell »), avec la sous-commande cachée `appliquer-eleve`. Le parent, non
//! élevé, prépare la liste ; le fils, élevé, la relit contre la liste fermée (les ordres reparsés, puis rejugés par
//! lui-même), la montre, attend Entrée dans sa propre console, puis fait chaque geste et répond ligne à ligne.
//!
//! Une liste qui mêle ces gestes à des commandes PowerShell passe aussi par lui, toujours en une seule demande UAC :
//! le parent écrit les commandes PowerShell dans un script (.ps1, lisible, comme avant) et n'envoie que son empreinte
//! SHA-256 et son chemin (`vanguard:script`). Le fils lit le script en mémoire, vérifie l'empreinte, et le lance
//! lui-même dans sa console, par l'amorce de `windows::amorce_admin`, qui relit à son tour les octets en mémoire et
//! refuse tout autre contenu que celui de l'empreinte : jamais le chemin seul, jamais un script changé entre-temps.
//!
//! La frontière entre les deux : un tube nommé au nom aléatoire, créé par le parent AVANT la relance, à instance
//! unique (personne ne peut en créer une deuxième et se faire passer pour le serveur), aux clients distants refusés
//! et à la DACL explicite. Le parent n'accepte que le client dont le PID est celui du processus qu'il vient de lancer ;
//! le fils n'accepte qu'un serveur dont le PID est celui annoncé et dont le programme a la même empreinte SHA-256 que
//! le sien. Un tube anonyme hérité ne marcherait pas : un processus « runas » est créé par le service AppInfo, il
//! n'hérite rien de nous. Pendant que la demande d'administrateur attend, le parent garde son propre fichier ouvert
//! sans partage de suppression : ni lui ni ses dossiers parents ne peuvent être renommés ou remplacés (même sur une
//! clé USB), et son contenu est déjà verrouillé par l'image chargée. Le processus élevé n'écrit aucun fichier dans
//! un dossier du compte : ses réponses passent par le tube.

// FFI de Windows (kernel32, advapi32, shell32, COM) : tube nommé, élévation, GetProcAddress (transmute).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Once;

use windows::Win32::Security::{
    ACL, ACL_REVISION, AddAccessAllowedAce, CreateWellKnownSid, InitializeAcl, InitializeSecurityDescriptor,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SetSecurityDescriptorDacl, SetSecurityDescriptorGroup,
    SetSecurityDescriptorOwner, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalServiceSid,
    WinLocalSystemSid, WinNetworkServiceSid, WinSelfSid,
};
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, COM_RIGHTS_EXECUTE, COM_RIGHTS_EXECUTE_LOCAL, CoInitializeEx, CoInitializeSecurity,
    EOAC_DISABLE_AAA, EOAC_NO_CUSTOM_MARSHAL, EOLE_AUTHENTICATION_CAPABILITIES, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_IMP_LEVEL_IDENTIFY,
};

use super::corrections::{self, Correction, Resultat};
use crate::machine::gestes;
use crate::protection::blocage::ordres::{self, Ordre};
use crate::ui::{GRIS, RESET, VERT, tr, trf, trp};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateNamedPipeW(
        nom: *const u16,
        acces: u32,
        mode: u32,
        instances: u32,
        sortie: u32,
        entree: u32,
        delai: u32,
        securite: *const Securite,
    ) -> *mut c_void;
    fn ConnectNamedPipe(tube: *mut c_void, recouvrement: *mut c_void) -> i32;
    fn DisconnectNamedPipe(tube: *mut c_void) -> i32;
    fn GetNamedPipeClientProcessId(tube: *mut c_void, pid: *mut u32) -> i32;
    fn GetNamedPipeServerProcessId(tube: *mut c_void, pid: *mut u32) -> i32;
    fn WaitNamedPipeW(nom: *const u16, delai: u32) -> i32;
    fn GetLastError() -> u32;
    fn GetProcessId(processus: *mut c_void) -> u32;
    fn WaitForSingleObject(objet: *mut c_void, delai: u32) -> u32;
    fn LoadLibraryExW(nom: *const u16, fichier: *mut c_void, drapeaux: u32) -> *mut c_void;
    fn SetDefaultDllDirectories(drapeaux: u32) -> i32;
    fn GetProcAddress(module: *mut c_void, nom: *const u8) -> *mut c_void;
    fn SetHandleInformation(objet: *mut c_void, masque: u32, drapeaux: u32) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        texte: *const u16,
        revision: u32,
        descripteur: *mut *mut c_void,
        taille: *mut u32,
    ) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteExW(info: *mut InfoLancement) -> i32;
}

/// SECURITY_ATTRIBUTES.
#[repr(C)]
struct Securite {
    taille: u32,
    descripteur: *mut c_void,
    heritable: i32,
}

/// SHELLEXECUTEINFOW (112 octets en 64 bits).
#[repr(C)]
struct InfoLancement {
    taille: u32,
    masque: u32,
    fenetre: *mut c_void,
    verbe: *const u16,
    fichier: *const u16,
    parametres: *const u16,
    dossier: *const u16,
    affichage: i32,
    instance: *mut c_void,
    liste: *mut c_void,
    classe: *const u16,
    cle: *mut c_void,
    raccourci: u32,
    icone: *mut c_void,
    processus: *mut c_void,
}

/// RESTOREPOINTINFOW et STATEMGRSTATUS (srrestoreptapi.h).
#[repr(C)]
struct PointInfo {
    evenement: u32,
    genre: u32,
    sequence: i64,
    description: [u16; 256],
}
/// STATEMGRSTATUS, déclarée en #pragma pack(1) dans srrestoreptapi.h : 12 octets, la séquence à l'octet 4.
#[repr(C, packed)]
struct PointEtat {
    statut: u32,
    sequence: i64,
}

const POIGNEE_INVALIDE: *mut c_void = -1isize as *mut c_void;
/// Sortie du fils : la liste reçue n'est pas celle de Vanguard (rien n'a été fait).
const LISTE_REFUSEE: i32 = 8;
/// Sortie du fils : le canal ne mène pas au Vanguard qui l'a lancé (rien n'a été fait).
const CANAL_REFUSE: i32 = 9;
/// La dernière ligne de chaque sens du dialogue.
const FIN: &str = "fin";
/// La plus longue ligne admise : celle d'un ordre (un chemin de programme), plus longue qu'un identifiant.
const LIGNE_MAX: usize = ordres::LIGNE_MAX;
/// Au-delà, une liste n'est pas celle d'une session de Vanguard (« Tout remettre comme avant » peut en compter
/// plusieurs dizaines).
const LIGNES_MAX: usize = ordres::LIGNES_MAX;
// La grammaire (`gestes::valider`, lue aussi par le banc de fuzzing, sans dépendance) a ses propres bornes : les mêmes.
const _: () = assert!(gestes::LIGNE_MAX == LIGNE_MAX && gestes::LIGNES_MAX == LIGNES_MAX);
/// Au-delà, ce n'est pas un script de correction de Vanguard (quelques dizaines de Kio) : il n'est ni montré ni lancé.
const SCRIPT_MAX: u64 = 16 << 20;
/// HANDLE_FLAG_INHERIT : la poignée passe au processus créé avec l'héritage des poignées (SetHandleInformation).
const HERITEE: u32 = 0x1;

/// Une ligne de la liste, relue.
pub(crate) enum Element {
    Correction(&'static Correction),
    Ordre(Ordre),
    /// Un script PowerShell à lancer seulement si ses octets ont son empreinte (SHA-256, hexadécimal majuscule).
    Script(gestes::Script),
    /// Un programme fixe de Windows (DISM, sfc…), lancé par son chemin complet avec les arguments de la table.
    Programme(gestes::Appel),
}

impl Element {
    fn texte(&self) -> String {
        match self {
            Element::Correction(c) => c.texte().to_string(),
            Element::Ordre(o) => o.texte(),
            Element::Script(s) => trf!(
                "Lancer le script PowerShell {} (vérifié par son empreinte {}…)",
                "Run the PowerShell script {} (checked by its fingerprint {}…)",
                crate::ui::affichable(&s.chemin),
                s.empreinte.get(..12).unwrap_or_default()
            ),
            Element::Programme(a) => corrections::texte_programme(a),
        }
    }
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre (`gestes::valider`) ; `None`
/// dès qu'une ligne n'est ni une correction de la table, ni un ordre du blocage permis sous Windows, ni un script à
/// empreinte, ni un programme fixe, qu'il y en a trop, ou qu'une correction ou un script revient (une liste de
/// Vanguard ne fait jamais deux fois le même). Le parent l'appelle avant la demande d'administrateur, le fils à la
/// réception : la même relecture des deux côtés.
pub(crate) fn valider(lignes: &[String]) -> Option<Vec<Element>> {
    let mut vues = std::collections::HashSet::new();
    let liste = gestes::valider(lignes, |l| {
        if let Some(c) = corrections::analyser(l) {
            // Une correction de la table ne revient jamais deux fois dans une liste de Vanguard ; un ordre, si
            // (deux blocages notés de la même adresse) : le second dit « déjà retirée ».
            return vues.insert(c.id).then_some(Element::Correction(c));
        }
        ordres::analyser(l).filter(Ordre::permis_ici).map(Element::Ordre)
    })?;
    Some(
        liste
            .into_iter()
            .map(|l| match l {
                gestes::Ligne::Autre(e) => e,
                gestes::Ligne::Script(s) => Element::Script(s),
                gestes::Ligne::Programme(a) => Element::Programme(a),
            })
            .collect(),
    )
}

fn large(t: &str) -> Vec<u16> {
    std::ffi::OsStr::new(t).encode_wide().chain(Some(0)).collect()
}

fn nom_du_tube(canal: &str) -> String {
    format!(r"\\.\pipe\vanguard-{canal}")
}

/// Un nom de canal est 32 chiffres hexadécimaux, tirés au hasard par le parent : tout autre argument est refusé
/// avant même d'ouvrir quoi que ce soit.
fn canal_valide(canal: &str) -> bool {
    canal.len() == 32 && canal.bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f'))
}

/// L'empreinte SHA-256 d'un programme, pour reconnaître « le même Vanguard » de part et d'autre du tube.
fn empreinte(chemin: &std::path::Path) -> Option<String> {
    std::fs::read(chemin).ok().map(|o| super::sha256_hex(&o))
}

/// Réponse du fils pour une correction : « ok avant=1 », « echec raison… ».
fn ligne_resultat(r: &Resultat) -> String {
    match (&r.reussi, &r.avant) {
        (true, Some(avant)) => format!("ok avant={avant}"),
        // Fait, mais sans point de restauration : la personne l'a accepté ; c'est noté, ce n'est pas un échec.
        (true, None) if r.raison == sans_point_accepte() => SANS_POINT.to_string(),
        // Un ordre réussi avec sa précision (« déjà retirée »).
        (true, None) if !r.raison.is_empty() => format!("ok note={}", r.raison.replace(['\r', '\n'], " ")),
        (true, None) => "ok".to_string(),
        (false, _) => format!("echec {}", r.raison.replace(['\r', '\n'], " ")),
    }
}

/// Ce que le parent retient d'une réponse : réussie ?, et la valeur d'avant à noter dans « Ce que Vanguard a changé ».
pub(crate) struct Reponse {
    pub reussi: bool,
    pub avant: Option<String>,
    /// À noter à côté de la commande (point de restauration manquant, accepté ; précision d'un ordre).
    pub note: Option<String>,
    /// Pour un script : son code de sortie, quand il n'est pas 0.
    pub code: Option<i32>,
    /// Pour un script en échec : l'état de chaque correctif, dans l'ordre, tel que le script l'a écrit dans le tube
    /// (un correctif sans état n'a pas été fait).
    pub etats: Option<Vec<bool>>,
}

/// La réponse d'un point de restauration manquant que la personne a accepté.
const SANS_POINT: &str = "ok sans-point";

fn lire_reponse(ligne: &str) -> Reponse {
    let reussi = ligne == "ok" || ligne.starts_with("ok ");
    let avant = ligne.strip_prefix("ok avant=").map(str::to_string);
    let note = if ligne == SANS_POINT {
        Some(sans_point_accepte().to_string())
    } else {
        ligne.strip_prefix("ok note=").map(str::to_string)
    };
    let code = ligne
        .strip_prefix("echec code=")
        .and_then(|c| c.split(' ').next()?.parse().ok());
    Reponse {
        reussi,
        avant,
        note,
        code,
        etats: gestes::etats_du_script(ligne),
    }
}

/// Une réponse « non fait ».
fn non_faite() -> Reponse {
    Reponse {
        reussi: false,
        avant: None,
        note: None,
        code: None,
        etats: None,
    }
}

// ---------------------------------------------------------------- le parent

/// Applique une liste (gestes natifs, scripts, programmes) avec les droits d'administrateur : en place si ce
/// processus est déjà élevé, sinon par une relance élevée de Vanguard. Une réponse par ligne, dans l'ordre reçu.
/// `None` : rien n'a été fait, et la raison est dite (liste refusée, DLL à côté du programme, relance impossible) ;
/// l'appelant ne repasse jamais par une autre demande d'administrateur (un attaquant qui provoquerait le repli
/// retrouverait le vieux chemin). Une demande d'administrateur refusée n'est pas `None` : tout est « non fait », sans
/// redemander.
pub(crate) fn appliquer(lignes: &[String]) -> Option<Vec<Reponse>> {
    if lignes.len() > LIGNES_MAX {
        trp!(
            "    Trop d'étapes d'un coup ({} ; {LIGNES_MAX} au plus) : rien n'a été fait. Appliquez-les en plusieurs fois.",
            "    Too many steps at once ({}; {LIGNES_MAX} at most): nothing was done. Apply them in several goes.",
            lignes.len()
        );
        return None;
    }
    // La même relecture que celle du fils, AVANT de demander quoi que ce soit : une liste qu'il refuserait n'ouvre pas
    // une demande d'administrateur pour rien. Le message d'antivirus reste au fils, le seul endroit où il a un sens
    // (la liste a changé en route).
    if valider(lignes).is_none() {
        trp!(
            "    Cette liste n'a pas la forme que Vanguard administrateur accepte : rien n'a été fait, aucune demande d'administrateur.",
            "    This list does not have the form Vanguard as administrator accepts: nothing was done, no administrator prompt."
        );
        return None;
    }
    if super::processus::eleve() {
        return Some(appliquer_en_place(lignes));
    }
    let mut aleatoire = [0u8; 16];
    if getrandom::fill(&mut aleatoire).is_err() {
        return relance_impossible("aléa", "randomness");
    }
    let canal = aleatoire.iter().fold(String::with_capacity(32), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    });
    let Some(serveur) = Serveur::creer(&canal) else {
        return relance_impossible("tube", "pipe");
    };
    let Ok(exe) = std::env::current_exe() else {
        return relance_impossible("chemin du programme", "program path");
    };
    // La vraie garde contre une DLL posée à côté du programme est dans le PE lui-même (chargement.rs : imports pris
    // dans System32 seulement). Elle n'existe qu'à partir de Windows 10 1607 : en plus, une DLL déjà là arrête tout,
    // sans autre demande d'administrateur.
    if let Some(dll) = exe.parent().and_then(dll_a_cote) {
        trp!(
            "    {dll} est à côté de Vanguard : par prudence, rien n'est fait en administrateur. Placez vanguard.exe seul dans un dossier à lui, puis recommencez.",
            "    {dll} sits next to Vanguard: to be safe, nothing is done as administrator. Put vanguard.exe alone in a folder of its own, then try again."
        );
        return None;
    }
    // Ouvert sans partage de suppression tant que le fils n'a pas répondu : ni renommage ni remplacement possibles.
    let Ok(_verrou) = ({
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new().read(true).share_mode(1).open(&exe)
    }) else {
        return relance_impossible("verrou du programme", "program lock");
    };
    trp!(
        "    {GRIS}Une fenêtre Vanguard administrateur s'ouvre, montre la liste et attend Entrée ; attendez qu'elle se ferme.{RESET}",
        "    {GRIS}A Vanguard administrator window opens, shows the list and waits for Enter; wait for it to close.{RESET}"
    );
    let parametres = format!("appliquer-eleve --canal {canal} --parent {}", std::process::id());
    let fils = match relancer_eleve(&exe, &parametres) {
        Ok(f) => f,
        Err(1223) => {
            trp!(
                "    Demande d'administrateur refusée : rien n'a été modifié.",
                "    Administrator prompt refused: nothing was changed."
            );
            return Some(lignes.iter().map(|_| non_faite()).collect());
        }
        Err(code) => {
            trp!(
                "    Impossible de relancer Vanguard en administrateur (erreur Windows {code}) : rien n'a été modifié.",
                "    Could not relaunch Vanguard as administrator (Windows error {code}): nothing was changed."
            );
            return None;
        }
    };
    let pid = fils.pid();
    // Si le fils meurt sans s'être branché, l'attente du serveur ne finirait jamais : un fil le surveille et, à sa
    // mort, se branche lui-même pour la débloquer (le serveur reconnaît alors son propre PID).
    let nom = nom_du_tube(&canal);
    let veilleur = std::thread::spawn(move || {
        fils.attendre();
        let _ = std::fs::OpenOptions::new().read(true).write(true).open(&nom);
    });
    let reponses = serveur.dialoguer(pid, lignes);
    drop(serveur);
    let _ = veilleur.join();
    Some(reponses.unwrap_or_else(|| lignes.iter().map(|_| non_faite()).collect()))
}

/// La relance élevée ne peut pas se préparer : on le dit, rien n'est fait, et aucune autre demande d'administrateur ne
/// prend le relais.
fn relance_impossible(fr: &str, en: &str) -> Option<Vec<Reponse>> {
    trp!(
        "    Vanguard administrateur ne peut pas se préparer ({}) : rien n'a été modifié.",
        "    Vanguard as administrator cannot get ready ({}): nothing was changed.",
        if crate::langue::anglais() { en } else { fr }
    );
    None
}

/// Déjà administrateur : chaque geste est fait ici, montré au passage, les ordres rejugés comme par le fils.
fn appliquer_en_place(lignes: &[String]) -> Vec<Reponse> {
    let Some(liste) = valider(lignes) else {
        return lignes.iter().map(|_| non_faite()).collect();
    };
    let juge = ordres::Juge::lire(None);
    let mut reponses = Vec::with_capacity(liste.len());
    let mut arret = false;
    for e in &liste {
        let r = if arret { refusee() } else { faire(e, &juge) };
        arret |= !r.reussi && est_point(e);
        reponses.push(lire_reponse(&ligne_resultat(&r)));
    }
    reponses
}

fn est_point(e: &Element) -> bool {
    matches!(e, Element::Correction(c) if matches!(c.geste, corrections::Geste::PointDeRestauration))
}

/// Le nom d'une bibliothèque (.dll, .drv) dans ce dossier, s'il y en a une ; un dossier illisible compte comme suspect.
fn dll_a_cote(dossier: &std::path::Path) -> Option<String> {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return Some(dossier.display().to_string());
    };
    entrees
        .flatten()
        .map(|e| e.path())
        .find(|chemin| {
            chemin
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("dll") || ext.eq_ignore_ascii_case("drv"))
        })
        .map(|chemin| chemin.file_name().unwrap_or_default().to_string_lossy().into_owned())
}

/// Le processus lancé élevé, à attendre.
struct Fils(OwnedHandle);

impl Fils {
    fn pid(&self) -> u32 {
        // SAFETY: la poignée est valide tant que `self` vit.
        unsafe { GetProcessId(self.0.as_raw_handle()) }
    }
    fn attendre(&self) {
        // SAFETY: idem ; INFINITE, la fenêtre est visible et c'est la personne qui la ferme.
        unsafe { WaitForSingleObject(self.0.as_raw_handle(), u32::MAX) };
    }
}

/// Relance ce programme avec « runas » (la demande d'administrateur) et rend le processus ; l'erreur Windows sinon
/// (1223 : la personne a refusé).
fn relancer_eleve(exe: &std::path::Path, parametres: &str) -> Result<Fils, u32> {
    const SANS_FERMER_PROCESSUS: u32 = 0x40;
    const SYNCHRONE: u32 = 0x100;
    const SANS_DIALOGUE_D_ERREUR: u32 = 0x400;
    let verbe = large("runas");
    let fichier: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let parametres = large(parametres);
    let mut info = InfoLancement {
        taille: u32::try_from(std::mem::size_of::<InfoLancement>()).map_err(|_| 0u32)?,
        masque: SANS_FERMER_PROCESSUS | SYNCHRONE | SANS_DIALOGUE_D_ERREUR,
        fenetre: std::ptr::null_mut(),
        verbe: verbe.as_ptr(),
        fichier: fichier.as_ptr(),
        parametres: parametres.as_ptr(),
        dossier: std::ptr::null(),
        affichage: 1,
        instance: std::ptr::null_mut(),
        liste: std::ptr::null_mut(),
        classe: std::ptr::null(),
        cle: std::ptr::null_mut(),
        raccourci: 0,
        icone: std::ptr::null_mut(),
        processus: std::ptr::null_mut(),
    };
    // SAFETY: la structure a la taille et la disposition de SHELLEXECUTEINFOW ; les chaînes sont terminées par un
    // zéro et vivent pendant l'appel. La poignée du processus (demandée par le masque, vérifiée non nulle) est à nous
    // et fermée une seule fois, par OwnedHandle.
    unsafe {
        if ShellExecuteExW(&raw mut info) == 0 || info.processus.is_null() {
            return Err(GetLastError());
        }
        Ok(Fils(OwnedHandle::from_raw_handle(info.processus)))
    }
}

/// Le serveur du tube, côté parent.
struct Serveur {
    tube: OwnedHandle,
}

impl Serveur {
    /// Crée le tube : instance unique et première (un nom déjà pris, même par hasard, est une erreur), clients de
    /// cet ordinateur seulement, accès au compte, à SYSTEM et aux administrateurs, à personne d'autre.
    fn creer(canal: &str) -> Option<Self> {
        const ACCES_DUPLEX: u32 = 0x3;
        const PREMIERE_INSTANCE: u32 = 0x0008_0000;
        const SANS_CLIENT_DISTANT: u32 = 0x8;
        let sid = super::processus::sid()?;
        let sddl = large(&format!("D:P(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)"));
        let nom = large(&nom_du_tube(canal));
        // Avant l'allocation du descripteur : un `?` plus bas le laisserait à Windows.
        let taille = u32::try_from(std::mem::size_of::<Securite>()).ok()?;
        let mut descripteur: *mut c_void = std::ptr::null_mut();
        // SAFETY: le descripteur alloué par Windows (vérifié non nul) vit pendant CreateNamedPipeW, puis est rendu
        // une seule fois par LocalFree. La poignée du tube (vérifiée) est fermée une seule fois, par OwnedHandle.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &raw mut descripteur,
                std::ptr::null_mut(),
            ) == 0
                || descripteur.is_null()
            {
                return None;
            }
            let securite = Securite {
                taille,
                descripteur,
                heritable: 0,
            };
            let tube = CreateNamedPipeW(
                nom.as_ptr(),
                ACCES_DUPLEX | PREMIERE_INSTANCE,
                SANS_CLIENT_DISTANT,
                1,
                4096,
                4096,
                0,
                &raw const securite,
            );
            super::processus::LocalFree(descripteur);
            if tube.is_null() || tube == POIGNEE_INVALIDE {
                return None;
            }
            Some(Self {
                tube: OwnedHandle::from_raw_handle(tube),
            })
        }
    }

    /// Attend le fils, et lui seul : un autre client (ou le veilleur, quand le fils est mort) est débranché.
    fn attendre_le_fils(&self, pid: u32) -> bool {
        const DEJA_BRANCHE: u32 = 535;
        let moi = std::process::id();
        for _ in 0..8 {
            let mut client = 0u32;
            // SAFETY: la poignée du tube est valide tant que `self` vit ; `client` est un entier à nous.
            let branche = unsafe {
                let r = ConnectNamedPipe(self.tube.as_raw_handle(), std::ptr::null_mut());
                (r != 0 || GetLastError() == DEJA_BRANCHE)
                    && GetNamedPipeClientProcessId(self.tube.as_raw_handle(), &raw mut client) != 0
            };
            if branche && client == pid {
                return true;
            }
            if !branche || client == moi {
                return false;
            }
            crate::journal::erreur(
                "Correction élevée",
                &format!("un client inattendu (PID {client}) s'est branché sur le canal : débranché"),
            );
            // SAFETY: idem.
            unsafe { DisconnectNamedPipe(self.tube.as_raw_handle()) };
        }
        false
    }

    /// Envoie la liste, lit une réponse par ligne ; `None` si le fils n'a pas répondu jusqu'au bout.
    fn dialoguer(&self, pid: u32, lignes: &[String]) -> Option<Vec<Reponse>> {
        if !self.attendre_le_fils(pid) {
            return None;
        }
        // Une copie de la poignée (DuplicateHandle), fermée par le File : chacune a un seul propriétaire. Si la copie
        // échoue, le Serveur lâché ferme le tube et le fils lit une fin de flux : la correction échoue, sans blocage.
        let fichier = std::fs::File::from(self.tube.try_clone().ok()?);
        let mut ecrivain = &fichier;
        let envoi: String = lignes
            .iter()
            .map(|l| format!("{l}\n"))
            .chain(Some(format!("{FIN}\n")))
            .collect();
        ecrivain.write_all(envoi.as_bytes()).ok()?;
        ecrivain.flush().ok()?;
        let mut reponses = Vec::with_capacity(lignes.len());
        for ligne in lire_lignes(&fichier)? {
            reponses.push(lire_reponse(&ligne));
        }
        (reponses.len() == lignes.len()).then_some(reponses)
    }
}

/// Les lignes reçues jusqu'à « fin », bornées en nombre et en longueur ; `None` si le flux s'arrête avant.
fn lire_lignes(source: impl Read) -> Option<Vec<String>> {
    let mut lecteur = BufReader::new(source.take(u64::try_from((LIGNES_MAX + 1) * (LIGNE_MAX + 1)).ok()?));
    let mut lignes = Vec::new();
    loop {
        let mut ligne = String::new();
        if lecteur.read_line(&mut ligne).ok()? == 0 {
            return None;
        }
        let ligne = ligne.trim_end_matches(['\r', '\n']).to_string();
        if ligne == FIN {
            return Some(lignes);
        }
        if ligne.len() > LIGNE_MAX || lignes.len() >= LIGNES_MAX {
            return None;
        }
        lignes.push(ligne);
    }
}

// ------------------------------------------------------------------ le fils

/// LOAD_LIBRARY_SEARCH_SYSTEM32 : une DLL cherchée par son nom ne vient que de System32.
const CHARGER_DE_SYSTEM32: u32 = 0x800;

/// L'accord avant d'appliquer en administrateur : Entrée seule ou un oui. Toute autre réponse (« n », « annuler »,
/// « cancel », « q », une faute de frappe) annule : devant un geste qui modifie la machine, le doute ne l'applique pas.
fn accepte(accord: &str) -> bool {
    accord.trim().is_empty() || crate::langue::oui(accord)
}

/// La sous-commande `appliquer-eleve` : rend le code de sortie du processus.
pub(crate) fn executer(canal: &str, parent: u32) -> i32 {
    // Le programme tourne souvent depuis une clé USB ou Téléchargements : une DLL posée à côté de lui ne doit jamais
    // être chargée avec les droits d'administrateur. Toute charge à venir, même par une bibliothèque, ira dans System32.
    // SAFETY: simple réglage du processus, sans pointeur.
    unsafe {
        SetDefaultDllDirectories(CHARGER_DE_SYSTEM32);
    }
    trp!(
        "Vanguard applique une correction (administrateur).",
        "Vanguard is applying a fix (administrator)."
    );
    if !super::processus::eleve() {
        trp!(
            "Ce processus n'a pas les droits d'administrateur : rien n'est fait.",
            "This process has no administrator rights: nothing is done."
        );
        return CANAL_REFUSE;
    }
    let Some(tube) = ouvrir_le_canal(canal, parent) else {
        trp!(
            "Le canal ne mène pas au Vanguard qui a demandé la correction : rien n'est fait.",
            "The channel does not lead to the Vanguard that asked for the fix: nothing is done."
        );
        attendre_entree_pour_fermer();
        return CANAL_REFUSE;
    };
    let mut tube = tube;
    let Some(lignes) = lire_lignes(&tube) else {
        return CANAL_REFUSE;
    };
    let Some(liste) = valider(&lignes) else {
        trp!(
            "La liste reçue n'est pas une liste de corrections de Vanguard : rien n'est fait. Un autre programme y a touché : lancez une analyse antivirus.",
            "The list received is not a Vanguard fix list: nothing is done. Another program touched it: run an antivirus scan."
        );
        let _ = tube.write_all(format!("{FIN}\n").as_bytes());
        attendre_entree_pour_fermer();
        return LISTE_REFUSEE;
    };
    // Chaque script est lu et vérifié avant d'être montré : ce que l'Entrée autorise est exactement ce qui sera lancé.
    // Illisible ou changé depuis son écriture, la liste entière est refusée, sans rien demander.
    let montre = match a_montrer(&liste) {
        Ok(m) => m,
        Err(chemin) => {
            trp!(
                "Le script de correction {} ne se lit plus ou a changé depuis que Vanguard l'a écrit : rien n'est fait, rien n'est demandé. Un autre programme y a touché : lancez une analyse antivirus, puis relancez la correction.",
                "The fix script {} can no longer be read or has changed since Vanguard wrote it: nothing is done, nothing is asked. Another program touched it: run an antivirus scan, then run the fix again.",
                crate::ui::affichable(&chemin)
            );
            let _ = tube.write_all(format!("{FIN}\n").as_bytes());
            attendre_entree_pour_fermer();
            return LISTE_REFUSEE;
        }
    };
    println!();
    trp!("Ce qui va être fait :", "What will be done:");
    for (texte, lignes) in &montre {
        println!("  · {texte}");
        for l in lignes {
            println!("    {GRIS}{l}{RESET}");
        }
    }
    println!();
    let accord = crate::ui::demander(tr!(
        "Appuyez sur Entrée pour appliquer ; toute autre réponse qu'oui annule : ",
        "Press Enter to apply; any answer other than yes cancels: "
    ));
    let mut code = 0;
    let mut arret = !accepte(&accord);
    if arret {
        trp!("Annulé : rien n'a été modifié.", "Cancelled: nothing was changed.");
    }
    // Ce que le fils lit lui-même de l'ordinateur pour rejuger les ordres : sessions à distance, processus protégés.
    let juge = ordres::Juge::lire(Some(parent));
    for e in &liste {
        let r = if arret { refusee() } else { faire(e, &juge) };
        if !r.reussi {
            code = 1;
            // Sans point de restauration, et la personne ne veut pas continuer sans : tout le reste est abandonné.
            arret |= est_point(e);
        }
        if tube.write_all(format!("{}\n", ligne_resultat(&r)).as_bytes()).is_err() {
            // Le parent n'entend plus : ce qui suivrait serait changé sans être noté dans « Ce que Vanguard a changé ».
            code = CANAL_REFUSE;
            break;
        }
    }
    let _ = tube.write_all(format!("{FIN}\n").as_bytes());
    let _ = tube.flush();
    drop(tube);
    println!();
    if code == 0 {
        trp!("{VERT}Terminé.{RESET}", "{VERT}Finished.{RESET}");
    } else {
        trp!(
            "Terminé, avec au moins une étape en échec.",
            "Finished, with at least one failed step."
        );
    }
    attendre_entree_pour_fermer();
    code
}

/// Les octets d'un script de la liste, lus une seule fois (ni lien, ni tube, ni fichier démesuré), rendus seulement
/// s'ils ont l'empreinte de la ligne ; `None` sinon.
fn lire_script_verifie(chemin: &str, empreinte: &str) -> Option<Vec<u8>> {
    let o = crate::socle::lire_ordinaire(std::path::Path::new(chemin), SCRIPT_MAX).ok()?;
    (super::sha256_hex(&o) == empreinte).then_some(o)
}

/// Ce que la console montre avant l'accord : le texte de chaque geste et, pour un script, ses lignes vérifiées.
/// `Err(chemin)` dès qu'un script est illisible ou n'a plus son empreinte : montrer autre chose que ce qui sera
/// lancé (ou rien) ferait accepter à l'aveugle.
fn a_montrer(liste: &[Element]) -> Result<Vec<(String, Vec<String>)>, String> {
    liste
        .iter()
        .map(|e| {
            let lignes = match e {
                Element::Script(s) => {
                    let o = lire_script_verifie(&s.chemin, &s.empreinte).ok_or_else(|| s.chemin.clone())?;
                    String::from_utf8_lossy(&o)
                        .trim_start_matches('\u{feff}')
                        .lines()
                        .map(crate::ui::affichable)
                        .collect()
                }
                _ => Vec::new(),
            };
            Ok((e.texte(), lignes))
        })
        .collect()
}

fn attendre_entree_pour_fermer() {
    let _ = crate::ui::demander(tr!("Appuyez sur Entrée pour fermer : ", "Press Enter to close: "));
}

/// Une correction non faite parce qu'on s'est arrêté avant.
fn refusee() -> Resultat {
    Resultat {
        reussi: false,
        avant: None,
        raison: tr!("non faite (arrêt demandé)", "not done (stopped as asked)").to_string(),
    }
}

/// Fait un geste de la liste, en l'annonçant, puis « OK » ou l'erreur : une fenêtre muette ne se distingue pas d'une
/// fenêtre figée. Un ordre est d'abord rejugé ici.
fn faire(e: &Element, juge: &ordres::Juge) -> Resultat {
    println!("{GRIS}> {}  {}{RESET}", chrono::Local::now().format("%H:%M"), e.texte());
    let r = match e {
        Element::Correction(c) => corrections::appliquer(c),
        Element::Ordre(o) => {
            let r = match ordres::juger(o, juge) {
                Some(refus) => ordres::Resultat::echec(refus),
                None => ordres::faire(o),
            };
            Resultat {
                reussi: r.reussi,
                avant: None,
                raison: if r.reussi { r.note.unwrap_or_default() } else { r.raison },
            }
        }
        Element::Script(s) => lancer_script(&s.chemin, &s.empreinte),
        Element::Programme(a) => lancer_programme(a),
    };
    if r.reussi {
        match &r.avant {
            Some(avant) => trp!(
                "  {VERT}OK{RESET} (avant : {avant})",
                "  {VERT}OK{RESET} (before: {avant})"
            ),
            None if !r.raison.is_empty() && r.raison != sans_point_accepte() => {
                trp!("  {VERT}OK{RESET} ({})", "  {VERT}OK{RESET} ({})", r.raison);
            }
            None => trp!("  {VERT}OK{RESET}", "  {VERT}OK{RESET}"),
        }
    } else {
        trp!("  Échec : {}", "  Failed: {}", r.raison);
    }
    r
}

/// Le script PowerShell d'une liste mêlée : lu ici en mémoire, son empreinte vérifiée, puis lancé dans cette console
/// par l'amorce, qui relit les octets et refuse tout autre contenu. Un lien, un dossier ou un fichier changé : refusé.
/// Le script répond correctif par correctif dans un tube anonyme créé ici et hérité par PowerShell (variable
/// `VANGUARD_RESULTATS` : la valeur de la poignée) : ni journal ni fichier de résultats dans le dossier du compte, que
/// ce compte pourrait réécrire. En échec, les états lus partent au parent (`echec code=N etats=101`).
fn lancer_script(chemin: &str, empreinte: &str) -> Resultat {
    let refus = |raison: String| Resultat {
        reussi: false,
        avant: None,
        raison,
    };
    // Ni lien, ni tube, ni fichier démesuré : ouvert sans suivre de lien, jugé sur ce qui est ouvert.
    if lire_script_verifie(chemin, empreinte).is_none() {
        return refus(format!(
            "code={} {}",
            super::SCRIPT_MODIFIE,
            tr!(
                "script modifié ou supprimé depuis son écriture : rien n'est lancé",
                "script modified or deleted since it was written: nothing is run"
            )
        ));
    }
    let tube = std::io::pipe().ok().filter(|(_, w)| heritable(w));
    let mut commande = super::powershell_eleve();
    commande.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &super::amorce_admin(chemin, empreinte),
    ]);
    // Sans tube, la variable est retirée : une valeur venue de l'environnement du compte ne désigne pas une poignée.
    match &tube {
        Some((_, w)) => commande.env(super::VARIABLE_RESULTATS, w.as_raw_handle().addr().to_string()),
        None => commande.env_remove(super::VARIABLE_RESULTATS),
    };
    let fils = commande.spawn();
    // Le parent ferme sa copie de l'écrivain : la fin de lecture vient quand PowerShell (et ce qu'il a lancé) a fermé
    // la sienne.
    let lecteur = tube.map(|(r, w)| {
        drop(w);
        let (envoi, reception) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for l in std::io::BufReader::new(r.take(1 << 16)).lines() {
                let Ok(l) = l else { break };
                let etat = match l.trim() {
                    "ok" => true,
                    "echec" => false,
                    _ => continue,
                };
                if envoi.send(etat).is_err() {
                    break;
                }
            }
        });
        reception
    });
    let statut = fils.and_then(|mut f| f.wait());
    // Un programme lancé par le script et resté en vie garde l'écrivain ouvert : on ne l'attend pas au-delà de 2 s.
    let mut etats = Vec::new();
    if let Some(reception) = lecteur {
        while let Ok(e) = reception.recv_timeout(std::time::Duration::from_secs(2)) {
            if etats.len() >= gestes::ETATS_MAX {
                break;
            }
            etats.push(e);
        }
    }
    match statut.ok().and_then(|s| s.code()) {
        Some(0) => Resultat {
            reussi: true,
            avant: None,
            raison: String::new(),
        },
        Some(c) => refus(gestes::raison_du_script(c, &etats)),
        None => refus(tr!("PowerShell ne s'est pas lancé", "PowerShell did not start").to_string()),
    }
}

/// Rend la poignée héritable par le prochain processus créé (std les crée toutes non héritables).
fn heritable(w: &std::io::PipeWriter) -> bool {
    // SAFETY: la poignée est valide tant que `w` vit (emprunté pendant l'appel) ; SetHandleInformation ne lit ni
    // n'écrit aucune mémoire de ce processus, il change un drapeau de l'objet noyau.
    unsafe { SetHandleInformation(w.as_raw_handle(), HERITEE, HERITEE) != 0 }
}

/// Un programme fixe de la table (`gestes::PROGRAMMES`), lancé par son chemin complet : System32 pris à Windows
/// (GetSystemDirectoryW), le lecteur système tiré de ce même chemin, jamais de l'environnement ni du PATH, que le
/// compte qui a lancé Vanguard peut régler. Sa sortie s'affiche telle quelle dans cette console.
fn lancer_programme(a: &gestes::Appel) -> Resultat {
    let refus = |raison: String| Resultat {
        reussi: false,
        avant: None,
        raison,
    };
    let systeme = crate::commande::dossier_systeme();
    let Some(lecteur) = systeme
        .to_str()
        .and_then(|s| s.get(..2))
        .filter(|l| l.as_bytes().first().is_some_and(u8::is_ascii_alphabetic) && l.ends_with(':'))
    else {
        return refus(tr!("lecteur système introuvable", "system drive not found").to_string());
    };
    let exe = match a.programme.dossier {
        gestes::Dossier::Systeme32 => systeme.join(a.programme.exe),
        gestes::Dossier::Defender => {
            std::path::PathBuf::from(format!(r"{lecteur}\{}\{}", gestes::DOSSIER_DEFENDER, a.programme.exe))
        }
    };
    // Le même environnement réduit que PowerShell : DISM ou sfc ne doivent rien charger de ce que le compte a posé.
    let mut commande = std::process::Command::new(&exe);
    super::environnement::reduire(&mut commande);
    match commande.args(a.arguments(lecteur)).status() {
        Ok(s) => match s.code() {
            Some(3010) if a.reussite(3010) => Resultat {
                reussi: true,
                avant: None,
                raison: tr!("redémarrage nécessaire", "restart needed").to_string(),
            },
            Some(c) if a.reussite(c) => Resultat {
                reussi: true,
                avant: None,
                raison: String::new(),
            },
            Some(c) => refus(format!("code={c}")),
            None => refus(tr!("arrêté sans code de sortie", "stopped without an exit code").to_string()),
        },
        Err(_) => refus(trf!(
            "{} ne s'est pas lancé",
            "{} did not start",
            crate::ui::affichable(&exe.to_string_lossy())
        )),
    }
}

/// Se branche sur le tube du parent, puis vérifie que le serveur est bien le processus annoncé et que son programme
/// est le même que celui-ci (même empreinte).
fn ouvrir_le_canal(canal: &str, parent: u32) -> Option<std::fs::File> {
    const OCCUPE: u32 = 231;
    if !canal_valide(canal) || parent == 0 {
        return None;
    }
    let nom = nom_du_tube(canal);
    let nom_large = large(&nom);
    let mut tube = None;
    for _ in 0..10 {
        match std::fs::OpenOptions::new().read(true).write(true).open(&nom) {
            Ok(f) => {
                tube = Some(f);
                break;
            }
            Err(e) if e.raw_os_error() == Some(i32::try_from(OCCUPE).ok()?) => {
                // SAFETY: chaîne terminée par un zéro, vivante pendant l'appel.
                unsafe { WaitNamedPipeW(nom_large.as_ptr(), 30_000) };
            }
            Err(_) => return None,
        }
    }
    let tube = tube?;
    let mut serveur = 0u32;
    // SAFETY: poignée valide (le File vit) ; `serveur` est un entier à nous.
    if unsafe { GetNamedPipeServerProcessId(tube.as_raw_handle(), &raw mut serveur) } == 0 || serveur != parent {
        return None;
    }
    let moi = std::env::current_exe().ok()?;
    let chemin_parent = std::path::PathBuf::from(super::processus::chemin(parent)?);
    (empreinte(&moi)? == empreinte(&chemin_parent)?).then_some(tube)
}

/// Ce qui est noté quand la personne a accepté de continuer sans point de restauration.
pub(crate) fn sans_point_accepte() -> &'static str {
    tr!("sans point de restauration, accepté", "no restore point, accepted")
}

/// Point de restauration par srclient.dll (chargée à la demande : absente, rien ne manque au programme). Impossible,
/// quelle qu'en soit la raison (protection du système coupée sur C:, ou srclient.dll ou sa fonction absente : Windows
/// Server, Windows allégés) : on le dit et on demande s'il faut continuer sans. Windows ne crée qu'un point par 24 h :
/// le plus récent sert alors, l'appel réussit sans en créer.
pub(crate) fn point_de_restauration() -> (bool, String) {
    match poser_le_point() {
        Ok(()) => (true, String::new()),
        Err(raison) => continuer_sans_point(&raison, crate::ui::demander),
    }
}

/// Le point ne s'est pas posé : la raison, puis la même question pour toutes les raisons. `demander` pose la question
/// et rend la réponse (le terminal ; une réponse écrite dans les tests).
fn continuer_sans_point(raison: &str, demander: impl FnOnce(&str) -> String) -> (bool, String) {
    trp!(
        "  Point de restauration impossible ({}).",
        "  Restore point not possible ({}).",
        raison
    );
    let reponse = demander(tr!(
        "  Continuer sans point de restauration ? [o/N] : ",
        "  Continue without a restore point? [y/N]: "
    ));
    if crate::langue::oui(&reponse) {
        // Pas de point, accepté : la suite continue, et « Ce que Vanguard a changé » le note.
        (true, sans_point_accepte().to_string())
    } else {
        (false, tr!("arrêté à votre demande", "stopped as you asked").to_string())
    }
}

/// Les comptes à qui COM permet de rappeler ce processus : les Administrateurs (aussi propriétaire et groupe du
/// descripteur), Service local, Service réseau, le compte lui-même (« principal self ») et Système.
const COMPTES_COM: [WELL_KNOWN_SID_TYPE; 5] = [
    WinBuiltinAdministratorsSid,
    WinLocalServiceSid,
    WinNetworkServiceSid,
    WinSelfSid,
    WinLocalSystemSid,
];

/// Le descripteur de sécurité COM que l'exemple de Microsoft donne à tout processus qui appelle SRSetRestorePoint,
/// sous forme absolue : CoInitializeSecurity refuse la forme relative que rend
/// ConvertStringSecurityDescriptorToSecurityDescriptor. Il équivaut au SDDL
/// « O:BAG:BAD:(A;;0x3;;;BA)(A;;0x3;;;LS)(A;;0x3;;;NS)(A;;0x3;;;PS)(A;;0x3;;;SY) » : les droits COM d'exécution, à
/// distance et en local (COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL), à ces seuls comptes. Ses SID et sa liste
/// d'accès vivent avec lui, dans une boîte qui ne bouge plus : le descripteur absolu pointe dessus.
struct DescripteurCom {
    /// SECURITY_MAX_SID_SIZE (68 octets) chacun, alignés sur 8.
    sids: [[u64; 9]; COMPTES_COM.len()],
    /// L'en-tête (8 octets) et cinq entrées de 8 octets plus leur SID : 228 octets au plus.
    acl: [u64; 32],
    descripteur: SECURITY_DESCRIPTOR,
}

impl DescripteurCom {
    fn nouveau() -> windows::core::Result<Box<DescripteurCom>> {
        /// SECURITY_DESCRIPTOR_REVISION.
        const REVISION: u32 = 1;
        let mut d = Box::new(DescripteurCom {
            sids: [[0; 9]; COMPTES_COM.len()],
            acl: [0; 32],
            descripteur: SECURITY_DESCRIPTOR::default(),
        });
        let taille_sid = u32::try_from(size_of::<[u64; 9]>()).unwrap_or(0);
        let taille_acl = u32::try_from(size_of::<[u64; 32]>()).unwrap_or(0);
        let acl: *mut ACL = (&raw mut d.acl).cast();
        let descripteur = PSECURITY_DESCRIPTOR((&raw mut d.descripteur).cast());
        // SAFETY: chaque SID est écrit dans son propre tampon, de la taille annoncée ; la liste d'accès dans le sien,
        // de la taille annoncée et aligné sur 8 octets (InitializeAcl demande 4). Tous les pointeurs viennent de
        // `&raw mut` (ou de `ptr::from_mut`, pour les SID) sur des champs de la boîte, qui ne bouge plus : le
        // descripteur absolu, qui ne garde que des pointeurs vers les SID et la liste, reste valide tant qu'elle vit.

        unsafe {
            // Un tampon par compte : `sids` en a autant que COMPTES_COM, par son type.
            for (compte, sid) in COMPTES_COM.into_iter().zip(&mut d.sids) {
                let mut taille = taille_sid;
                CreateWellKnownSid(
                    compte,
                    None,
                    Some(PSID(std::ptr::from_mut(sid).cast())),
                    &raw mut taille,
                )?;
            }
            InitializeAcl(acl, taille_acl, ACL_REVISION)?;
            for sid in &mut d.sids {
                AddAccessAllowedAce(
                    acl,
                    ACL_REVISION,
                    COM_RIGHTS_EXECUTE | COM_RIGHTS_EXECUTE_LOCAL,
                    PSID(std::ptr::from_mut(sid).cast()),
                )?;
            }
            let administrateurs = PSID((&raw mut d.sids[0]).cast());
            InitializeSecurityDescriptor(descripteur, REVISION)?;
            SetSecurityDescriptorOwner(descripteur, Some(administrateurs), false)?;
            SetSecurityDescriptorGroup(descripteur, Some(administrateurs), false)?;
            SetSecurityDescriptorDacl(descripteur, true, Some(acl), false)?;
        }
        Ok(d)
    }

    fn pointeur(&mut self) -> PSECURITY_DESCRIPTOR {
        PSECURITY_DESCRIPTOR((&raw mut self.descripteur).cast())
    }
}

/// COM et sa sécurité, une seule fois pour tout le processus élevé, avant le premier point de restauration. La
/// documentation de Microsoft (« Using System Restore », citée de mémoire) le demande à tout processus qui appelle
/// SRSetRestorePoint, pour que Service réseau, Service local et Système puissent le rappeler : CoInitializeEx en
/// appartement multithread, puis CoInitializeSecurity avec un descripteur explicite (`DescripteurCom`), -1 (COM
/// choisit les services d'authentification), RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IDENTIFY et
/// EOAC_DISABLE_AAA | EOAC_NO_CUSTOM_MARSHAL. Comme dans l'exemple, un échec est sans suite : le point est tenté quand
/// même (COM déjà dans un autre appartement, ou sécurité déjà fixée : RPC_E_TOO_LATE).
fn initialiser_com() {
    static UNE_FOIS: Once = Once::new();
    UNE_FOIS.call_once(|| {
        // SAFETY: sans réserve, en appartement multithread ; jamais refermé : il vaut pour tout le processus élevé.
        if unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_err() {
            return;
        }
        let Ok(descripteur) = DescripteurCom::nouveau() else {
            return;
        };
        // Gardé pour toute la vie du processus : l'exemple de Microsoft libère le sien aussitôt (COM en garde une
        // copie), mais quelques centaines d'octets valent la certitude.
        let descripteur = Box::leak(descripteur);
        // SAFETY: descripteur absolu valide (ci-dessus), qui ne sera jamais libéré ; aucune liste d'authentification,
        // pointeurs réservés nuls.
        let _ = unsafe {
            CoInitializeSecurity(
                Some(descripteur.pointeur()),
                -1,
                None,
                None,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IDENTIFY,
                None,
                EOLE_AUTHENTICATION_CAPABILITIES(EOAC_DISABLE_AAA.0 | EOAC_NO_CUSTOM_MARSHAL.0),
                None,
            )
        };
    });
}

/// Pose le point (début puis fin du changement) ; `Err` : pourquoi il ne l'est pas, prêt à montrer.
fn poser_le_point() -> Result<(), String> {
    const DEBUT: u32 = 100;
    const FIN_CHANGEMENT: u32 = 101;
    const REGLAGES: u32 = 12;
    type Poser = unsafe extern "system" fn(*mut PointInfo, *mut PointEtat) -> i32;
    let description = trf!("Vanguard : avant une correction", "Vanguard: before a fix");
    let mut info = PointInfo {
        evenement: DEBUT,
        genre: REGLAGES,
        sequence: 0,
        description: [0; 256],
    };
    for (place, c) in info.description.iter_mut().zip(description.encode_utf16().take(255)) {
        *place = c;
    }
    let mut etat = PointEtat { statut: 0, sequence: 0 };
    initialiser_com();
    let bibliotheque = large("srclient.dll");
    // SAFETY: la bibliothèque et la fonction sont vérifiées non nulles avant l'appel ; la signature est celle de
    // SRSetRestorePointW ; les deux structures ont la disposition attendue et vivent pendant l'appel. Un deuxième appel
    // ferme le changement (séquence rendue par le premier).
    let pose = unsafe {
        let module = LoadLibraryExW(bibliotheque.as_ptr(), std::ptr::null_mut(), CHARGER_DE_SYSTEM32);
        if module.is_null() {
            return Err(trf!(
                "srclient.dll absente de ce Windows",
                "srclient.dll missing from this Windows"
            ));
        }
        let adresse = GetProcAddress(module, c"SRSetRestorePointW".as_ptr().cast());
        if adresse.is_null() {
            return Err(trf!(
                "SRSetRestorePointW absente de srclient.dll",
                "SRSetRestorePointW missing from srclient.dll"
            ));
        }
        let poser: Poser = std::mem::transmute::<*mut c_void, Poser>(adresse);
        let ok = poser(&raw mut info, &raw mut etat) != 0;
        if ok {
            info.evenement = FIN_CHANGEMENT;
            let sequence = etat.sequence; // copie : jamais de référence vers un champ packed
            info.sequence = sequence;
            poser(&raw mut info, &raw mut etat);
        }
        ok
    };
    if pose {
        return Ok(());
    }
    Err(trf!(
        "erreur {} : protection du système désactivée sur C: ?",
        "error {}: system protection turned off on C:?",
        { etat.statut }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La liste du fils : corrections, ordres du blocage permis sous Windows, scripts à empreinte et programmes fixes,
    /// sous leur seule forme ; tout le reste refusé en entier.
    #[test]
    fn la_liste_mele_corrections_ordres_et_script() {
        use gestes::ligne_script;
        let empreinte = "A".repeat(64);
        let script = ligne_script(
            &empreinte,
            r"C:\Users\alice\AppData\Local\Vanguard\corrections\correction-1.ps1",
        );
        // Seul : accepté (toutes les listes passent par le fils) ; hors du dossier des corrections ou sous un autre
        // nom : refusé.
        assert!(matches!(
            valider(std::slice::from_ref(&script)).as_deref(),
            Some([Element::Script(_)])
        ));
        let point = corrections::POINT.to_string();
        assert!(valider(&[point.clone(), ligne_script(&empreinte, r"C:\Temp\correction-1.ps1")]).is_none());
        assert!(valider(&[point, ligne_script(&empreinte, r"C:\x\corrections\autre.ps1")]).is_none());
        let bonne = vec![
            corrections::POINT.to_string(),
            "vanguard:bloquer-sortie windows 203.0.113.7".to_string(),
            "vanguard:arreter-processus 4242 433a5c782e657865".to_string(),
            script.clone(),
            gestes::ligne_programme("sfc-scannow", None),
        ];
        let v = valider(&bonne).unwrap();
        assert!(matches!(v[0], Element::Correction(_)));
        assert!(matches!(&v[1], Element::Ordre(Ordre::BloquerSortie { .. })));
        assert!(matches!(&v[3], Element::Script(s) if s.chemin.ends_with("correction-1.ps1")));
        assert!(matches!(&v[4], Element::Programme(a) if a.programme.id == "sfc-scannow"));
        for hostile in [
            // Un ordre d'un autre système, un script à empreinte en minuscules, un chemin relatif ou sans .ps1, des
            // octets du chemin en majuscules, une ligne en double.
            vec!["vanguard:bloquer-sortie nftables 203.0.113.7".to_string()],
            vec![ligne_script(&"a".repeat(64), r"C:\x.ps1")],
            vec![ligne_script(&empreinte, r"x.ps1")],
            vec![ligne_script(&empreinte, r"C:\x.exe")],
            vec![script.to_uppercase()],
            vec![script.clone(), script.clone()],
            vec![format!("{script} ")],
            // Le point deux fois (une correction ne revient jamais), un programme hors table ou avec un argument.
            vec![corrections::POINT.to_string(), corrections::POINT.to_string()],
            vec!["vanguard:programme cmd".to_string()],
            vec![format!("{} /x", gestes::ligne_programme("sfc-scannow", None))],
        ] {
            assert!(valider(&hostile).is_none(), "{hostile:?}");
        }
    }

    /// Un script dont les octets ne sont plus ceux de l'empreinte n'est jamais lancé (PowerShell n'est pas appelé).
    #[test]
    fn un_script_change_n_est_pas_lance() {
        let d = crate::essais::temporaire().join(format!("vanguard-script-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let chemin = d.join("correction-essai.ps1");
        std::fs::write(&chemin, b"Write-Host 'change'").unwrap();
        let attendue = super::super::sha256_hex(b"Write-Host 'ecrit'");
        let r = lancer_script(&chemin.display().to_string(), &attendue);
        assert!(
            !r.reussi && r.raison.starts_with(&format!("code={}", super::super::SCRIPT_MODIFIE)),
            "{}",
            r.raison
        );
        assert_eq!(
            lire_reponse(&ligne_resultat(&r)).code,
            Some(super::super::SCRIPT_MODIFIE)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Avant l'accord, un script illisible ou changé fait refuser toute la liste (rien n'est montré, rien demandé) ;
    /// un script intact est montré tel qu'il sera lancé.
    #[test]
    fn un_script_change_est_refuse_avant_l_accord() {
        let d = std::env::temp_dir().join(format!("vanguard-montrer-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let chemin = d.join("correction-1.ps1");
        let ecrit = "\u{feff}Write-Host 'ecrit'\r\nexit 0\r\n";
        std::fs::write(&chemin, ecrit).unwrap();
        let script = |empreinte: String| {
            vec![
                Element::Correction(corrections::analyser(corrections::POINT).unwrap()),
                Element::Script(gestes::Script {
                    empreinte,
                    chemin: chemin.display().to_string(),
                }),
            ]
        };
        let bonne = super::super::sha256_hex(ecrit.as_bytes());
        let m = a_montrer(&script(bonne.clone())).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].1, Vec::<String>::new());
        assert_eq!(m[1].1, ["Write-Host 'ecrit'", "exit 0"]);
        // Changé après son écriture : refusé, et le chemin est dit.
        std::fs::write(&chemin, "Write-Host 'change'").unwrap();
        assert_eq!(a_montrer(&script(bonne.clone())), Err(chemin.display().to_string()));
        // Disparu : refusé aussi (avant, la liste était montrée sans le script, puis l'Entrée demandée).
        std::fs::remove_file(&chemin).unwrap();
        assert!(a_montrer(&script(bonne)).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn l_accord_avant_d_appliquer() {
        for oui in ["", "  \n", "o", "oui", "O", "y", "yes", "Yes\r\n"] {
            assert!(accepte(oui), "{oui:?}");
        }
        for non in ["n", "non", "no", "annuler", "cancel", "q", "stop", "non.", "ok"] {
            assert!(!accepte(non), "{non:?}");
        }
    }

    #[test]
    fn une_dll_a_cote_du_programme_se_voit() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-dll-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::write(dossier.join("vanguard.exe"), b"").unwrap();
        assert_eq!(dll_a_cote(&dossier), None);
        std::fs::write(dossier.join("USERENV.DLL"), b"").unwrap();
        assert_eq!(dll_a_cote(&dossier).as_deref(), Some("USERENV.DLL"));
        std::fs::remove_dir_all(&dossier).unwrap();
        assert!(dll_a_cote(&dossier).is_some());
    }

    #[test]
    fn le_canal_a_une_forme_fixe() {
        assert!(canal_valide("0123456789abcdef0123456789abcdef"));
        for mauvais in [
            "",
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "../0123456789abcdef0123456789abc",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(!canal_valide(mauvais), "{mauvais}");
        }
        assert_eq!(nom_du_tube("ab"), r"\\.\pipe\vanguard-ab");
    }

    #[test]
    fn les_reponses_se_lisent() {
        let r = lire_reponse("ok avant=1");
        assert!(r.reussi && r.avant.as_deref() == Some("1"));
        let r = lire_reponse("ok");
        assert!(r.reussi && r.avant.is_none());
        assert!(!lire_reponse("echec relu 0 au lieu de 1").reussi);
        assert!(!lire_reponse("okay").reussi);
        let sans_point = Resultat {
            reussi: true,
            avant: None,
            raison: sans_point_accepte().into(),
        };
        let r = lire_reponse(&ligne_resultat(&sans_point));
        assert!(r.reussi && r.avant.is_none() && r.note.as_deref() == Some(sans_point_accepte()));
        assert!(lire_reponse("ok").note.is_none());
        assert!(!lire_reponse("").reussi);
        let aller_retour = ligne_resultat(&Resultat {
            reussi: false,
            avant: Some("1".into()),
            raison: "a\r\nb".into(),
        });
        assert_eq!(aller_retour, "echec a  b");
        let r = lire_reponse("echec code=1 etats=101");
        assert!(!r.reussi && r.code == Some(1) && r.etats == Some(vec![true, false, true]));
        assert!(lire_reponse("echec code=1").etats.is_none());
    }

    /// Les lignes reçues s'arrêtent à « fin » et sont bornées : un flux sans fin, trop long ou trop fourni est refusé.
    #[test]
    fn la_lecture_est_bornee() {
        let flux = b"vanguard:rdp-nla\r\nvanguard:wdigest-coupe\nfin\nautre\n";
        assert_eq!(
            lire_lignes(&flux[..]).unwrap(),
            ["vanguard:rdp-nla", "vanguard:wdigest-coupe"]
        );
        assert!(lire_lignes(&b"vanguard:rdp-nla\n"[..]).is_none());
        let longue = format!("{}\nfin\n", "a".repeat(LIGNE_MAX + 1));
        assert!(lire_lignes(longue.as_bytes()).is_none());
        let fournie = format!("{}fin\n", "x\n".repeat(LIGNES_MAX + 1));
        assert!(lire_lignes(fournie.as_bytes()).is_none());
        let sans_fin = "x\n".repeat(100_000);
        assert!(lire_lignes(sans_fin.as_bytes()).is_none());
    }

    /// srclient.dll ou sa fonction absente (Windows Server, Windows allégés) passe par la même question que l'échec de
    /// poser : la raison est dite, puis « o » continue sans point (noté), tout le reste arrête.
    #[test]
    fn sans_point_la_question_est_posee() {
        for raison in [
            "srclient.dll absente de ce Windows",
            "SRSetRestorePointW absente de srclient.dll",
            "erreur 1058 : protection du système désactivée sur C: ?",
        ] {
            let mut posee = None;
            let (continuer, note) = continuer_sans_point(raison, |question| {
                posee = Some(question.to_string());
                "o".into()
            });
            assert!(continuer && note == sans_point_accepte(), "{raison}");
            assert!(posee.is_some_and(|q| q.contains("[o/N]") || q.contains("[y/N]")));
            for refus in ["", "n", "non"] {
                let (continuer, note) = continuer_sans_point(raison, |_| refus.into());
                assert!(!continuer && note != sans_point_accepte(), "{raison} / {refus:?}");
            }
        }
    }

    /// Le descripteur COM construit à la main est exactement celui du SDDL de l'exemple de Microsoft : les deux,
    /// rendus en SDDL par Windows (ou Wine) lui-même, sont identiques.
    #[test]
    fn le_descripteur_com_est_celui_de_microsoft() {
        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descripteur: *mut c_void,
                revision: u32,
                parties: u32,
                texte: *mut *mut u16,
                taille: *mut u32,
            ) -> i32;
        }
        /// Propriétaire, groupe et DACL.
        const PARTIES: u32 = 1 | 2 | 4;
        let en_sddl = |descripteur: *mut c_void| {
            let mut texte = std::ptr::null_mut();
            // SAFETY: descripteur valide pendant l'appel ; Windows alloue le texte (terminé par un zéro), lu jusqu'au
            // zéro puis rendu par LocalFree, une seule fois.
            unsafe {
                assert_ne!(
                    ConvertSecurityDescriptorToStringSecurityDescriptorW(
                        descripteur,
                        1,
                        PARTIES,
                        &raw mut texte,
                        std::ptr::null_mut()
                    ),
                    0
                );
                let mut longueur = 0;
                while *texte.add(longueur) != 0 {
                    longueur += 1;
                }
                let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(texte, longueur));
                super::super::processus::LocalFree(texte.cast());
                sddl
            }
        };
        let mut construit = DescripteurCom::nouveau().expect("descripteur COM");
        let attendu = large("O:BAG:BAD:(A;;0x3;;;BA)(A;;0x3;;;LS)(A;;0x3;;;NS)(A;;0x3;;;PS)(A;;0x3;;;SY)");
        let mut relatif = std::ptr::null_mut();
        // SAFETY: chaîne terminée par un zéro ; le descripteur rendu est libéré par LocalFree, une seule fois.
        let reference = unsafe {
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    attendu.as_ptr(),
                    1,
                    &raw mut relatif,
                    std::ptr::null_mut()
                ),
                0
            );
            let sddl = en_sddl(relatif);
            super::super::processus::LocalFree(relatif);
            sddl
        };
        assert_eq!(en_sddl(construit.pointeur().0), reference);
        assert!(reference.starts_with("O:BAG:BAD:"), "{reference}");
    }

    #[test]
    fn les_structures_ont_la_taille_de_windows() {
        assert_eq!(std::mem::size_of::<InfoLancement>(), 112);
        assert_eq!(std::mem::size_of::<Securite>(), 24);
        assert_eq!(std::mem::size_of::<PointInfo>(), 528);
        assert_eq!(std::mem::size_of::<PointEtat>(), 12);
        assert_eq!(std::mem::offset_of!(PointEtat, sequence), 4);
    }
}
