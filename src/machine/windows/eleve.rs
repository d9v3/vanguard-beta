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
//! n'hérite rien de nous. Pendant que la demande d'administrateur attend, le parent tient le chemin qu'elle va relire
//! (`tenir_le_programme`) : chaque dossier vérifié sans point d'analyse (jonction, lien) et ouvert sans partage de
//! suppression, puis son fichier, aux octets du programme qui tourne, chacun à l'endroit nommé pour Windows (une
//! lettre de lecteur redéfinie par le compte est refusée) ; ni renommage, ni remplacement, ni jonction possibles avant
//! la réponse (même dans une copie sous le dossier du compte, même sur une clé USB), revu juste avant « runas ». La
//! commande de « runas » est prise dans la classe des programmes de la machine (HKLM), jamais dans celle du compte.
//! Le processus élevé n'écrit aucun fichier dans un dossier du compte : ses réponses passent par le tube.

// FFI de Windows (kernel32, advapi32, shell32) : tube nommé, élévation.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use super::corrections::{self, Correction, Resultat};
use crate::machine::gestes;
use crate::modele::Echec;
use crate::protection::blocage::ordres::{self, Ordre};
use crate::ui::{ACCENT, GRIS, RESET, VERT, tr, trf, trp};

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
    fn PeekNamedPipe(
        tube: *mut c_void,
        tampon: *mut c_void,
        taille: u32,
        lus: *mut u32,
        disponibles: *mut u32,
        restants: *mut u32,
    ) -> i32;
    fn GetLastError() -> u32;
    fn GetProcessId(processus: *mut c_void) -> u32;
    fn WaitForSingleObject(objet: *mut c_void, delai: u32) -> u32;
    fn SetDefaultDllDirectories(drapeaux: u32) -> i32;
    fn SetHandleInformation(objet: *mut c_void, masque: u32, drapeaux: u32) -> i32;
    fn GetStdHandle(quelle: u32) -> *mut c_void;
    fn GetConsoleMode(console: *mut c_void, mode: *mut u32) -> i32;
    fn GetFinalPathNameByHandleW(fichier: *mut c_void, tampon: *mut u16, taille: u32, drapeaux: u32) -> u32;
    fn GetFileInformationByHandleEx(fichier: *mut c_void, classe: u32, tampon: *mut c_void, taille: u32) -> i32;
    #[cfg(test)]
    fn DefineDosDeviceW(drapeaux: u32, nom: *const u16, cible: *const u16) -> i32;
    #[cfg(test)]
    fn GetLogicalDrives() -> u32;
    #[cfg(test)]
    fn DeviceIoControl(
        appareil: *mut c_void,
        code: u32,
        entree: *mut c_void,
        taille_entree: u32,
        sortie: *mut c_void,
        taille_sortie: u32,
        rendus: *mut u32,
        recouvrement: *mut c_void,
    ) -> i32;
}

use super::securite::{ConvertStringSecurityDescriptorToSecurityDescriptorW, Securite};

#[link(name = "shell32")]
unsafe extern "system" {
    fn ShellExecuteExW(info: *mut InfoLancement) -> i32;
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
/// STD_INPUT_HANDLE ((DWORD)-10) : l'entrée standard du processus.
const ENTREE_STANDARD: u32 = 0xFFFF_FFF6;

/// L'entrée est-elle une vraie console (GetConsoleMode réussit) ? Une réponse qui arrive par un tube ou un fichier
/// n'a pas été tapée par la personne devant cette fenêtre : la question d'une baisse y vaut non.
pub(crate) fn console_reelle() -> bool {
    // SAFETY: simple lecture d'une poignée du processus, sans pointeur.
    let entree = unsafe { GetStdHandle(ENTREE_STANDARD) };
    if entree.is_null() || entree == POIGNEE_INVALIDE {
        return false;
    }
    let mut mode = 0u32;
    // SAFETY: `entree` est la poignée d'entrée du processus, `mode` une variable vivante pendant l'appel ; une poignée
    // qui n'est pas une console fait échouer l'appel, sans rien écrire ailleurs.
    unsafe { GetConsoleMode(entree, &raw mut mode) != 0 }
}

/// Une ligne de la liste, relue.
pub(crate) enum Element {
    Correction(&'static Correction),
    Ordre(Ordre),
    /// Un script PowerShell à lancer seulement si ses octets ont son empreinte (SHA-256, hexadécimal majuscule).
    Script(gestes::Script),
    /// Un programme fixe de Windows (DISM, sfc…), lancé par son chemin complet avec les arguments de la table.
    Programme(gestes::Appel),
    /// Un acte sur un service ou un dossier de Windows (`services_ecriture`), fait sans PowerShell.
    Acte(gestes::Acte),
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
            Element::Acte(a) => corrections::texte_acte(a),
        }
    }
}

/// La liste telle que le processus élevé la recevra, validée ligne à ligne, dans l'ordre (`gestes::valider`) ; `None`
/// dès qu'une ligne n'est ni une correction de la table, ni un ordre du blocage permis sous Windows, ni un script à
/// empreinte, ni un programme fixe, ni un acte de la table, qu'il y en a trop, ou qu'une correction ou un script
/// revient (une liste de Vanguard ne fait jamais deux fois le même). Le parent l'appelle avant la demande
/// d'administrateur, le fils à la réception : la même relecture des deux côtés.
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
                gestes::Ligne::Acte(a) => Element::Acte(a),
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

/// Réponse du fils pour une correction : « ok avant=1 », « ok rien=déjà 1… », « echec raison… ».
fn ligne_resultat(r: &Resultat) -> String {
    match (&r.reussi, &r.avant) {
        // Une baisse faite : sa valeur d'avant est notée dans ChoixAvant (« Rallumer » la remet).
        (true, Some(avant)) if r.raison == corrections::NOTE_CHOIX => {
            format!(
                "ok avant={} {}",
                avant.replace(['\r', '\n'], " "),
                corrections::NOTE_CHOIX
            )
        }
        (true, Some(avant)) => format!("ok avant={}", avant.replace(['\r', '\n'], " ")),
        // Déjà bon, rien d'écrit : le parent ne le note pas parmi ce que Vanguard a changé.
        (true, None) if r.rien => format!("ok rien={}", r.raison.replace(['\r', '\n'], " ")),
        // Fait, mais sans point de restauration : la personne l'a accepté ; c'est noté, ce n'est pas un échec.
        (true, None) if r.raison == sans_point_accepte() => SANS_POINT.to_string(),
        // Un ordre réussi avec sa précision (« déjà retirée »).
        (true, None) if !r.raison.is_empty() => format!("ok note={}", r.raison.replace(['\r', '\n'], " ")),
        (true, None) => "ok".to_string(),
        (false, _) if r.raison == arret_demande() => ARRETEE.to_string(),
        // La valeur d'avant n'a pas pu être notée : aucun geste. Si c'est la borne des notes de ChoixAvant, le parent
        // note son remède à côté de la ligne (contre-relecture D8, C2) ; sinon rien à noter chez lui.
        (false, None) if r.raison.contains(crate::machine::choix_avant::trop_de_notes()) => ECHEC_NOTE_TROP.to_string(),
        (false, _) if r.raison.starts_with(corrections::echec_note()) => ECHEC_NOTE.to_string(),
        (false, _) if r.raison.starts_with(au_redemarrage()) => AU_REDEMARRAGE.to_string(),
        // Un échec qui a déjà touché quelque chose (racine retirée d'un seul magasin, valeur relue autre) : la valeur
        // d'avant va au parent, notée à côté de la ligne en échec ; la raison reste dans la console du fils.
        (false, Some(avant)) => format!("echec avant={}", avant.replace(['\r', '\n'], " ")),
        (false, None) => format!("echec {}", r.raison.replace(['\r', '\n'], " ")),
    }
}

/// Ce que le parent retient d'une réponse : réussie ?, et la valeur d'avant à noter dans « Ce que Vanguard a changé ».
#[allow(clippy::struct_excessive_bools)] // des états lus dans le tube, chacun pour lui-même
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
    /// Non fait parce que la personne s'est arrêtée (point de restauration refusé, accord refusé) : pas un échec.
    pub arretee: bool,
    /// Laissé à la personne (chkdsk 3 : disque à vérifier par chkdsk /f) : pas fait, pas un échec non plus.
    pub au_redemarrage: bool,
    /// Déjà bon, rien d'écrit (« ok rien=… ») : réussi, mais rien n'a changé.
    pub rien: bool,
}

/// La réponse d'un point de restauration manquant que la personne a accepté.
const SANS_POINT: &str = "ok sans-point";
/// La réponse d'un geste non fait parce que la personne s'est arrêtée.
const ARRETEE: &str = "echec arret";
/// La réponse d'une baisse non faite faute d'avoir pu noter sa valeur d'avant (rien n'a été écrit).
const ECHEC_NOTE: &str = "echec note";
/// La même, parce que la clé des notes est pleine : le parent note le remède (`choix_avant::trop_de_notes`) à côté de
/// la ligne, au lieu d'un échec sans suite.
const ECHEC_NOTE_TROP: &str = "echec note=trop";

/// La réponse d'un geste laissé à la personne (chkdsk 3).
const AU_REDEMARRAGE: &str = "echec redemarrage";

/// Le début de la raison d'un programme laissé à la personne (suivi de son code).
fn au_redemarrage() -> &'static str {
    tr!("disque à vérifier", "disk to check")
}

/// La raison d'un geste non fait parce que la personne s'est arrêtée : point de restauration refusé, puis tout ce qui
/// suit ; ou accord refusé.
fn arret_demande() -> &'static str {
    tr!("arrêté à votre demande", "stopped as you asked")
}

/// La valeur d'avant d'une baisse notée (« defender-pua=1 note=choix ») : seulement si ce qui précède « = » est
/// l'identifiant d'un choix ; une autre valeur d'avant qui finirait par le même mot reste entière.
fn avant_choix(avant: &str) -> Option<&str> {
    let v = avant.strip_suffix(corrections::NOTE_CHOIX)?.strip_suffix(' ')?;
    let (id, valeur) = v.split_once('=')?;
    (gestes::IdChoix::lire(id).is_some() && crate::machine::choix_avant::lire_valeur(valeur).is_some()).then_some(v)
}

fn lire_reponse(ligne: &str) -> Reponse {
    let reussi = ligne == "ok" || ligne.starts_with("ok ");
    let brut = ligne.strip_prefix("ok avant=");
    let choix = brut.and_then(avant_choix);
    let avant = choix
        .or(brut)
        .or_else(|| ligne.strip_prefix("echec avant="))
        .map(str::to_string);
    let rien = ligne.strip_prefix("ok rien=");
    let note = if choix.is_some() {
        Some(corrections::NOTE_CHOIX.to_string())
    } else if ligne == SANS_POINT {
        Some(sans_point_accepte().to_string())
    } else if ligne == ECHEC_NOTE_TROP {
        Some(crate::machine::choix_avant::trop_de_notes().to_string())
    } else {
        ligne.strip_prefix("ok note=").or(rien).map(str::to_string)
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
        arretee: ligne == ARRETEE,
        au_redemarrage: ligne == AU_REDEMARRAGE,
        rien: rien.is_some(),
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
        arretee: false,
        au_redemarrage: false,
        rien: false,
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
            "    Vanguard a refusé sa propre liste de corrections avant de demander les droits d'administrateur : rien n'a été fait. Mettez Vanguard à jour ; si cela revient, signalez-le.",
            "    Vanguard refused its own list of fixes before asking for administrator rights: nothing was done. Update Vanguard; if it happens again, report it (the error log keeps a trace)."
        );
        crate::journal::erreur(
            crate::compte_rendu::Contexte::VanguardAdministrateur,
            "liste refusée avant la demande (forme inattendue)",
        );
        return None;
    }
    // Les choix de Defender partent dans une liste à eux, après les autres (P7) : chaque liste est montrée et jugée à
    // part, sous une seule demande d'administrateur ; une liste mêlée serait refusée par le fils.
    let groupes = gestes::separer_choix(lignes);
    let (envoi, ordre) = gestes::joindre_listes(lignes, &groupes);
    if envoi.len() > LIGNES_MAX {
        trp!(
            "    Trop d'étapes d'un coup ({} ; {LIGNES_MAX} au plus) : rien n'a été fait. Appliquez-les en plusieurs fois.",
            "    Too many steps at once ({}; {LIGNES_MAX} at most): nothing was done. Apply them in several goes.",
            envoi.len()
        );
        return None;
    }
    let remettre = |reponses: Vec<Reponse>| {
        gestes::remettre_en_ordre(&ordre, reponses).unwrap_or_else(|| lignes.iter().map(|_| non_faite()).collect())
    };
    if super::processus::eleve() {
        return Some(remettre(appliquer_en_place(&envoi)));
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
    // Chaque dossier du chemin, puis le fichier, tenus jusqu'à la réponse du fils : le chemin que « runas » relira est
    // celui qui a été vérifié.
    let tenu = match tenir_le_programme(&exe) {
        Ok(t) => t,
        Err(ecart) => return chemin_refuse(&exe, &ecart),
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
    // Le fichier tenu doit être le programme qui tourne (empreinte prise au démarrage) : un autre programme du compte
    // a pu le remplacer avant qu'il soit tenu, et c'est lui qui recevrait les droits d'administrateur.
    if !crate::protection::cle::meme_que_soi(&tenu.fichier) {
        trp!(
            "    ✖ Le fichier de Vanguard n'est plus le programme qui tourne ({}) : rien n'est fait en administrateur. Relancez Vanguard, puis recommencez.",
            "    ✖ Vanguard's file is no longer the running program ({}): nothing is done as administrator. Restart Vanguard, then try again.",
            exe.display()
        );
        return None;
    }
    // Revu juste avant « runas » : le fichier a pu devenir un point d'analyse malgré la poignée.
    if let Err(ecart) = tenu.encore_sur() {
        return chemin_refuse(&exe, &ecart);
    }
    trp!(
        "    {GRIS}Une fenêtre Vanguard administrateur s'ouvre, montre la liste et attend Entrée ; attendez qu'elle se ferme.{RESET}",
        "    {GRIS}A Vanguard administrator window opens, shows the list and waits for Enter; wait for it to close.{RESET}"
    );
    let parametres = format!("appliquer-eleve --canal {canal} --parent {}", std::process::id());
    let fils = match relancer_eleve(&exe, &parametres) {
        Ok(f) => f,
        Err(1223) => {
            trp!(
                "    Demande d'administrateur refusée. Rien n'a changé : il faut l'accord d'un administrateur de ce PC.",
                "    Administrator prompt refused. Nothing changed: an administrator of this PC must approve."
            );
            return Some(lignes.iter().map(|_| lire_reponse(ARRETEE)).collect());
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
    let reponses = serveur.dialoguer(pid, &envoi, ordre.len());
    drop(serveur);
    let _ = veilleur.join();
    Some(reponses.map_or_else(|| lignes.iter().map(|_| non_faite()).collect(), remettre))
}

/// Le chemin du programme ne peut pas être tenu tel quel : on dit pourquoi et quoi faire, rien n'est fait en
/// administrateur.
fn chemin_refuse(exe: &std::path::Path, ecart: &Ecart) -> Option<Vec<Reponse>> {
    trp!(
        "    ✖ Le chemin de Vanguard ({}) {}. Rien n'est fait en administrateur : un chemin qui n'est pas tenu tel quel pourrait mener un autre programme du compte aux droits d'administrateur. {}",
        "    ✖ Vanguard's path ({}) {}. Nothing is done as administrator: a path that is not held as is could lead another program of this account to administrator rights. {}",
        exe.display(),
        ecart.dire(),
        ecart.conseil()
    );
    crate::journal::erreur(
        crate::compte_rendu::Contexte::VanguardAdministrateur,
        &format!("relance refusée : chemin du programme non sûr ({})", ecart.genre()),
    );
    None
}

/// La relance élevée ne peut pas se préparer : on le dit, rien n'est fait, et aucune autre demande d'administrateur ne
/// prend le relais.
fn relance_impossible(fr: &str, en: &str) -> Option<Vec<Reponse>> {
    trp!(
        "    Vanguard n'a pas pu préparer sa fenêtre administrateur : rien n'a été modifié. Redémarrez l'ordinateur, puis relancez la correction. (détail : {})",
        "    Vanguard could not prepare its administrator window: nothing was changed. Restart the computer, then run the fix again. (detail: {})",
        if crate::langue::anglais() { en } else { fr }
    );
    crate::journal::erreur(
        crate::compte_rendu::Contexte::VanguardAdministrateur,
        &format!("relance impossible : {fr}"),
    );
    None
}

/// Les listes d'un envoi (`gestes::decouper_listes`), chacune validée ; `None` si l'envoi n'a pas cette forme.
fn valider_listes(envoi: &[String]) -> Option<Vec<Vec<Element>>> {
    gestes::decouper_listes(envoi)?.iter().map(|l| valider(l)).collect()
}

/// Déjà administrateur : chaque geste est fait ici, montré au passage, les ordres rejugés comme par le fils. Une
/// liste de baisses est montrée et demandée ici, comme dans la fenêtre administrateur ; une liste mêlée, refusée.
/// Les réponses suivent l'ordre de l'envoi, sans les séparateurs.
fn appliquer_en_place(envoi: &[String]) -> Vec<Reponse> {
    let Some(listes) = valider_listes(envoi) else {
        return envoi
            .iter()
            .filter(|l| *l != gestes::SUITE)
            .map(|_| non_faite())
            .collect();
    };
    let juge = ordres::Juge::lire(None);
    // Vanguard administrateur lui-même : son propre compte.
    let compte = super::processus::sid()
        .ok_or_else(|| tr!("SID illisible dans le jeton", "SID unreadable in the token").to_string());
    let mut reponses = Vec::with_capacity(envoi.len());
    // Sans point de restauration, et la personne ne veut pas continuer sans : tout le reste est abandonné, listes
    // suivantes comprises.
    let mut abandon = false;
    for liste in &listes {
        let Some((sens, baisse)) = juger_liste(liste, &compte) else {
            dire_melee();
            reponses.extend(liste.iter().map(|_| lire_reponse(&ligne_resultat(&melee()))));
            continue;
        };
        let mut arret = abandon;
        if baisse && !arret {
            let montre: Vec<(String, Vec<String>)> = liste.iter().map(|e| (e.texte(), Vec::new())).collect();
            montrer(&montre, &sens);
            arret = !question(liste, &sens, true, false);
            if arret {
                dire_annule(true);
            }
        }
        for ((e, bilan), s) in liste.iter().zip(bilans(liste, &compte)).zip(&sens) {
            let r = if arret {
                refusee()
            } else {
                faire(e, &juge, &compte, bilan, s.as_ref().map(|(m, _)| *m))
            };
            if !r.reussi && est_point(e) {
                arret = true;
                abandon = true;
            }
            reponses.push(lire_reponse(&ligne_resultat(&r)));
        }
    }
    super::defender_ecriture::nettoyer_notes();
    reponses
}

/// Le sens de chaque ligne d'une liste, relu ici juste avant de la montrer, avec la ligne « nom : actuelle → VISÉE »
/// d'un choix (`None` pour ce qui n'en est pas un) ; puis vrai pour une liste de baisses. `None` : la liste mêle une
/// baisse à un autre geste, refusée sans rien demander (le parent ne l'envoie jamais ainsi).
type Jugement = (Vec<Option<(gestes::Montre, String)>>, bool);

fn juger_liste(liste: &[Element], compte: &Result<String, String>) -> Option<Jugement> {
    let personne = compte.as_deref().ok();
    let sens: Vec<Option<(gestes::Montre, String)>> = liste
        .iter()
        .map(|e| match e {
            // Une remise de réglage ou de chemin de service (D6b) : une baisse, montrée puis confirmée.
            Element::Acte(a) => super::defender_ecriture::juger(a)
                .or_else(|| super::reglages_ecriture::juger(a, personne))
                .or_else(|| baisse_par_type(a)),
            _ => None,
        })
        .collect();
    let seuls: Vec<Option<gestes::Sens>> = sens.iter().map(|s| s.as_ref().map(|(m, _)| m.sens)).collect();
    let baisse = gestes::liste_pure(&seuls).ok()?;
    Some((sens, baisse))
}

/// Une ligne qui baisse la protection par sa nature (`Acte::baisse_par_type` : le profil Public ou un réseau en
/// Privé remis comme avant le mode Wi-Fi public, un lancement jugé suspect remis), montrée comme une baisse ; `None`
/// pour un autre acte.
fn baisse_par_type(a: &gestes::Acte) -> Option<(gestes::Montre, String)> {
    use gestes::Acte;
    if !a.baisse_par_type() {
        return None;
    }
    let texte = match a {
        // Chaque texte tient dans la ligne de `montrer`, sous son retrait et avant « (baisse la protection) ».
        Acte::PareFeuPublic(_) => tr!(
            "profil Public : plus d'entrées permises",
            "Public profile: more inbound allowed"
        ),
        Acte::ReseauCategorie(_) => tr!(
            "réseau rangé en Privé (plus le profil Public)",
            "network set to Private (no Public profile)"
        ),
        Acte::RunRemettre(_)
        | Acte::TacheReactiver(_)
        | Acte::DemarrageRemettre(..)
        | Acte::WmiAbonnementRemettre(_) => {
            tr!(
                "un lancement jugé suspect revient",
                "a startup entry judged suspicious comes back"
            )
        }
        _ => tr!("un état d'avant revient", "a previous state comes back"),
    };
    Some((
        gestes::Montre {
            sens: gestes::Sens::Baisse,
            lue: None,
        },
        texte.to_string(),
    ))
}

/// La raison d'une liste mêlée, pour chacune de ses lignes.
fn melee() -> Resultat {
    Resultat::echec(
        None,
        tr!(
            "liste refusée : elle mêle des changements qui baissent votre protection à d'autres gestes ; rien n'est fait",
            "list refused: it mixes changes that lower your protection with other steps; nothing is done"
        )
        .to_string(),
    )
}

fn dire_melee() {
    trp!(
        "Liste refusée : elle mêle des changements qui baissent votre protection à d'autres gestes. Rien n'est fait, rien n'est demandé.",
        "List refused: it mixes changes that lower your protection with other steps. Nothing is done, nothing is asked."
    );
}

fn dire_annule(baisse: bool) {
    if baisse {
        trp!("Rien n'est baissé.", "Nothing is lowered.");
    } else {
        trp!("Annulé : rien n'a été modifié.", "Cancelled: nothing was changed.");
    }
}

/// Ce qui va être fait, avec, pour un choix, sa valeur actuelle et la visée, et ce qui baisse la protection en clair.
fn montrer(montre: &[(String, Vec<String>)], sens: &[Option<(gestes::Montre, String)>]) {
    println!();
    trp!("Ce qui va être fait :", "What will be done:");
    for ((texte, lignes), s) in montre.iter().zip(sens.iter().chain(std::iter::repeat(&None))) {
        println!("  · {texte}");
        for l in lignes {
            println!("    {GRIS}{l}{RESET}");
        }
        match s.as_ref().map(|(m, t)| (m.sens, t)) {
            Some((gestes::Sens::Baisse, t)) => trp!(
                "    {ACCENT}{}  (baisse la protection){RESET}",
                "    {ACCENT}{}  (lowers protection){RESET}",
                t
            ),
            Some((gestes::Sens::Rien, t)) => trp!(
                "    {GRIS}{}  (déjà ainsi : rien à écrire){RESET}",
                "    {GRIS}{}  (already so: nothing to write){RESET}",
                t
            ),
            Some((gestes::Sens::Renforce, t)) => crate::ui::afficher_aligne("    ", t, 4, GRIS),
            None => {}
        }
    }
    println!();
}

/// Ce qui reste actif après la baisse de `id`, coupé pour tenir dans `ui::LARGEUR` sous un retrait de deux colonnes
/// (une console de 80 colonnes couperait sinon au milieu d'un mot).
fn lignes_protege(id: gestes::IdChoix) -> Vec<String> {
    crate::ui::envelopper(
        crate::options_defense::protege_encore(id),
        crate::ui::LARGEUR.saturating_sub(2),
    )
}

/// La liste ajoute-t-elle une exclusion large, ou permet-elle largement un programme malgré l'accès contrôlé aux
/// dossiers (un interpréteur, un joker) ? La question le dit alors plus fort (R8).
fn liste_large(liste: &[Element]) -> bool {
    liste.iter().any(|e| match e {
        Element::Acte(gestes::Acte::DefenderExclusionAjouter(g, x)) => gestes::exclusion_large(*g, x.texte()),
        Element::Acte(gestes::Acte::DefenderDossiersAutoriser(x)) => {
            gestes::exclusion_large(gestes::GenreExclusion::Processus, x.texte())
        }
        _ => false,
    })
}

/// L'accord d'une liste. Une liste de baisses : ce qui reste actif, l'avertissement du temps réel (P10), puis la
/// question des baisses (`choix_avant::demander_baisse` : un oui tapé dans une vraie console, défaut non). Une autre
/// liste : dans la fenêtre administrateur (`fils`), Entrée ou oui ; déjà administrateur, l'accord a été donné avant.
fn question(liste: &[Element], sens: &[Option<(gestes::Montre, String)>], baisse: bool, fils: bool) -> bool {
    if !baisse {
        return !fils
            || accepte(&crate::ui::demander(tr!(
                "Appuyez sur Entrée pour appliquer ; toute autre réponse qu'oui annule : ",
                "Press Enter to apply; any answer other than yes cancels: "
            )));
    }
    let mut baisses: Vec<gestes::IdChoix> = Vec::new();
    let large = liste_large(liste);
    for (e, s) in liste.iter().zip(sens) {
        if let (
            Element::Acte(a),
            Some((
                gestes::Montre {
                    sens: gestes::Sens::Baisse,
                    ..
                },
                _,
            )),
        ) = (e, s)
            && let Some((id, _)) = a.choix()
            && !baisses.contains(&id)
        {
            baisses.push(id);
        }
    }
    for id in &baisses {
        for l in lignes_protege(*id) {
            println!("  {GRIS}{l}{RESET}");
        }
    }
    if !baisses.is_empty() {
        trp!(
            "  {GRIS}« Rallumer » dans Vanguard (Options de défense) remet chacun.{RESET}",
            "  {GRIS}“Turn back on” in Vanguard (Defense options) restores each one.{RESET}"
        );
    }
    if large {
        for l in crate::ui::envelopper(
            crate::options_defense::avertissement_large(),
            crate::ui::LARGEUR.saturating_sub(2),
        ) {
            println!("  {ACCENT}{l}{RESET}");
        }
    }
    if baisses.contains(&gestes::IdChoix::Defender(gestes::ReglageDefender::TempsReel)) {
        trp!(
            "  {ACCENT}Defender peut juger ce geste suspect et signaler Vanguard.{RESET} Vanguard ne contourne jamais Defender : s'il refuse (protection contre les falsifications), rien n'est baissé.",
            "  {ACCENT}Defender may judge this step suspicious and flag Vanguard.{RESET} Vanguard never bypasses Defender: if it refuses (Tamper Protection), nothing is lowered."
        );
    }
    crate::machine::choix_avant::demander_baisse(console_reelle(), crate::ui::demander_ou_defaut)
}

/// Le bilan refait ici pour chaque correction de la table, tous avant le premier geste : un geste de la liste ne
/// change pas le jugement d'un autre (aie-machine, puis aie-compte). Ce qui n'est pas une correction de la table a
/// son propre rejugement (ordres, actes).
fn bilans(liste: &[Element], compte: &Result<String, String>) -> Vec<corrections::Bilan> {
    liste
        .iter()
        .map(|e| match e {
            Element::Correction(c) => corrections::rejuger(c, compte),
            _ => corrections::Bilan::Signale,
        })
        .collect()
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

/// Pourquoi le chemin du programme ne peut pas être tenu.
#[derive(Debug)]
enum Ecart {
    /// Pas `X:\…` sans `..` : partage `\\serveur\…`, chemin relatif ou forme que le processus élevé relirait autrement.
    PasUnDisque,
    /// L'élément tenu n'est pas, pour Windows, à l'endroit nommé : la lettre du lecteur mène ailleurs pour ce compte
    /// (lecteur réseau, `subst`, lettre redéfinie par un programme du compte) ou le chemin a un nom court.
    Ailleurs(std::path::PathBuf),
    /// Un dossier ou le fichier est un point d'analyse, avec son étiquette (jonction, lien, dossier du nuage…).
    PointDAnalyse(std::path::PathBuf, u32),
    /// Un élément n'a pas le genre attendu (un fichier au milieu, un dossier au bout).
    Genre(std::path::PathBuf),
    /// Un élément ne s'ouvre pas sans partage de suppression, avec l'erreur Windows : absent, illisible pour ce compte,
    /// ou déjà ouvert par un autre programme qui en bloque le partage.
    Inouvrable(std::path::PathBuf, Option<i32>),
}

/// IO_REPARSE_TAG_MOUNT_POINT : jonction ou point de montage d'un volume.
const ETIQUETTE_JONCTION: u32 = 0xA000_0003;
/// IO_REPARSE_TAG_SYMLINK.
const ETIQUETTE_LIEN: u32 = 0xA000_000C;

/// IO_REPARSE_TAG_CLOUD et ses variantes (0x9000_X01A) : fichiers et dossiers d'un service du nuage (OneDrive…).
fn etiquette_du_nuage(etiquette: u32) -> bool {
    etiquette & 0xFFFF_0FFF == 0x9000_001A
}

impl Ecart {
    fn dire(&self) -> String {
        match self {
            Self::PasUnDisque => tr!(
                "n'est pas un chemin complet sur un disque de ce PC",
                "is not a full path on a disk of this PC"
            )
            .to_string(),
            Self::Ailleurs(c) => trf!(
                "ne mène pas où il le dit : pour Windows, {} est ailleurs (lecteur réseau, lecteur créé par subst, lettre redéfinie pour ce compte ou nom court)",
                "does not lead where it says: for Windows, {} is elsewhere (network drive, drive made by subst, letter redefined for this account or short name)",
                c.display()
            ),
            Self::PointDAnalyse(c, ETIQUETTE_JONCTION) => trf!(
                "passe par {} : une jonction (ou un point de montage)",
                "goes through {}: a junction (or a mount point)",
                c.display()
            ),
            Self::PointDAnalyse(c, ETIQUETTE_LIEN) => trf!(
                "passe par {} : un lien symbolique",
                "goes through {}: a symbolic link",
                c.display()
            ),
            Self::PointDAnalyse(c, e) if etiquette_du_nuage(*e) => trf!(
                "passe par {} : un dossier synchronisé avec le nuage (OneDrive ou autre), que son service peut changer à tout moment",
                "goes through {}: a folder synced with the cloud (OneDrive or other), which its service can change at any time",
                c.display()
            ),
            Self::PointDAnalyse(c, e) => trf!(
                "passe par {} : un point d'analyse de Windows (étiquette {:#010x}), qui peut mener ailleurs",
                "goes through {}: a Windows reparse point (tag {:#010x}), which can lead elsewhere",
                c.display(),
                e
            ),
            Self::Genre(c) => trf!("a un élément inattendu : {}", "has an unexpected item: {}", c.display()),
            Self::Inouvrable(c, Some(2 | 3)) => trf!(
                "ne peut pas être tenu : {} est absent",
                "cannot be held: {} is missing",
                c.display()
            ),
            Self::Inouvrable(c, Some(5)) => trf!(
                "ne peut pas être tenu : {} refuse la lecture à ce compte",
                "cannot be held: {} denies reading to this account",
                c.display()
            ),
            Self::Inouvrable(c, Some(32 | 33)) => trf!(
                "ne peut pas être tenu : {} est déjà ouvert par un autre programme, qui en bloque le partage",
                "cannot be held: {} is already open in another program, which blocks sharing it",
                c.display()
            ),
            Self::Inouvrable(c, Some(code)) => trf!(
                "ne peut pas être tenu : {} ne s'ouvre pas (erreur Windows {})",
                "cannot be held: {} does not open (Windows error {})",
                c.display(),
                code
            ),
            Self::Inouvrable(c, None) => trf!(
                "ne peut pas être tenu : {} ne s'ouvre pas",
                "cannot be held: {} does not open",
                c.display()
            ),
        }
    }

    /// Ce que la personne peut faire : seulement ce qui règle cet écart-là.
    fn conseil(&self) -> &'static str {
        match self {
            Self::PointDAnalyse(_, e) if etiquette_du_nuage(*e) => tr!(
                "Placez vanguard.exe dans un dossier hors du nuage (par exemple C:\\Outils\\Vanguard), puis recommencez.",
                "Put vanguard.exe in a folder outside the cloud (for example C:\\Tools\\Vanguard), then try again."
            ),
            Self::Inouvrable(_, Some(32 | 33)) => tr!(
                "Fermez le programme qui tient ce dossier ouvert (ou redémarrez l'ordinateur), puis recommencez.",
                "Close the program holding this folder open (or restart the computer), then try again."
            ),
            Self::Inouvrable(_, Some(5)) => tr!(
                "Placez vanguard.exe dans un dossier que ce compte peut lire, puis recommencez.",
                "Put vanguard.exe in a folder this account can read, then try again."
            ),
            _ => tr!(
                "Placez vanguard.exe dans un dossier ordinaire d'un disque de ce PC (sans lien ni jonction), puis recommencez.",
                "Put vanguard.exe in a plain folder on a disk of this PC (no link or junction), then try again."
            ),
        }
    }

    /// Pour le journal, sans chemin (il porterait le nom du compte).
    fn genre(&self) -> String {
        match self {
            Self::PasUnDisque => "pas un disque".to_string(),
            Self::Ailleurs(_) => "lecteur qui mène ailleurs".to_string(),
            Self::PointDAnalyse(_, e) => format!("point d'analyse {e:#010x}"),
            Self::Genre(_) => "genre inattendu".to_string(),
            Self::Inouvrable(_, Some(code)) => format!("non tenable, erreur {code}"),
            Self::Inouvrable(_, None) => "non tenable".to_string(),
        }
    }
}

/// Le programme à relancer en administrateur, tenu jusqu'à la réponse du fils.
struct ProgrammeTenu {
    /// Chaque dossier du chemin, de la racine exclue au dossier du programme, avec le chemin qui l'a nommé.
    dossiers: Vec<(std::path::PathBuf, std::fs::File)>,
    chemin: std::path::PathBuf,
    fichier: std::fs::File,
}

impl ProgrammeTenu {
    /// Juste avant « runas » : chaque élément tenu est encore à l'endroit nommé, sans point d'analyse. Le fichier peut
    /// en devenir un malgré la poignée (il suffit de l'accès « écrire les attributs », que le partage ne compare pas).
    fn encore_sur(&self) -> Result<(), Ecart> {
        for (chemin, f) in self
            .dossiers
            .iter()
            .map(|(c, f)| (c, f))
            .chain(std::iter::once((&self.chemin, &self.fichier)))
        {
            verifier_l_element(chemin, f)?;
        }
        Ok(())
    }
}

/// Les attributs et l'étiquette de point d'analyse lus par la poignée (FILE_ATTRIBUTE_TAG_INFO).
fn attributs_et_etiquette(f: &std::fs::File) -> Option<(u32, u32)> {
    const CLASSE_ATTRIBUTS_ET_ETIQUETTE: u32 = 9;
    let mut info = [0u32; 2];
    // SAFETY: la poignée vit pendant l'appel ; le tampon de 8 octets a la taille de FILE_ATTRIBUTE_TAG_INFO (deux
    // DWORD) et Windows n'y écrit pas plus que la taille donnée.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            f.as_raw_handle(),
            CLASSE_ATTRIBUTS_ET_ETIQUETTE,
            info.as_mut_ptr().cast(),
            8,
        )
    };
    (ok != 0).then_some((info[0], info[1]))
}

/// Le chemin où Windows place l'élément ouvert, lettre comprise (`\\?\` retiré), lu par la poignée et non par un nom :
/// la lettre vient du gestionnaire des volumes, pas de la table des lecteurs du compte.
fn chemin_final(f: &std::fs::File) -> Option<std::ffi::OsString> {
    use std::os::windows::ffi::OsStringExt;
    let mut tampon = vec![0u16; 1024];
    for _ in 0..2 {
        let taille = u32::try_from(tampon.len()).ok()?;
        // SAFETY: la poignée vit pendant l'appel ; Windows écrit au plus `taille` caractères dans le tampon.
        // Drapeaux 0 : nom normalisé, volume nommé par sa lettre (VOLUME_NAME_DOS).
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle(), tampon.as_mut_ptr(), taille, 0) };
        let n = usize::try_from(n).ok()?;
        if n == 0 {
            return None;
        }
        if let Some(texte) = tampon.get(..n).filter(|_| n < tampon.len()) {
            let sans = texte.strip_prefix(&[u16::from(b'\\'), u16::from(b'\\'), u16::from(b'?'), u16::from(b'\\')][..]);
            return Some(std::ffi::OsString::from_wide(sans.unwrap_or(texte)));
        }
        tampon = vec![0u16; n + 1];
    }
    None
}

/// Deux chemins de Windows égaux à la casse près.
fn meme_chemin(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    let haut = |c: &std::ffi::OsStr| c.to_string_lossy().to_uppercase();
    haut(a) == haut(b)
}

/// Un élément ouvert sans suivre de point d'analyse : il n'en est pas un, et Windows le place à `chemin`.
fn verifier_l_element(chemin: &std::path::Path, f: &std::fs::File) -> Result<(), Ecart> {
    const POINT_D_ANALYSE: u32 = 0x400;
    let Some((attributs, etiquette)) = attributs_et_etiquette(f) else {
        return Err(Ecart::Inouvrable(chemin.to_path_buf(), None));
    };
    if attributs & POINT_D_ANALYSE != 0 {
        return Err(Ecart::PointDAnalyse(chemin.to_path_buf(), etiquette));
    }
    if !chemin_final(f).is_some_and(|c| meme_chemin(&c, chemin.as_os_str())) {
        return Err(Ecart::Ailleurs(chemin.to_path_buf()));
    }
    Ok(())
}

/// Tient le chemin `exe` que « runas » va relire : chaque dossier, de haut en bas, ouvert sans suivre de point
/// d'analyse (FILE_FLAG_OPEN_REPARSE_POINT) et vérifié par sa poignée, sans partage de suppression ; puis le fichier,
/// en lecture partagée seule. Tant que les poignées vivent, aucun dossier ne peut être renommé ni effacé (il faut
/// l'accès « suppression », que la poignée refuse de partager), ni devenir une jonction (un dossier doit être vide
/// pour cela, et chacun contient le suivant) ; le fichier ne peut être ni changé, ni renommé, mais il pourrait devenir
/// un point d'analyse : `ProgrammeTenu::encore_sur` le revoit juste avant « runas ». Le processus élevé ne fait pas
/// ce contrôle lui-même : un programme substitué ne le ferait pas.
///
/// La lettre du lecteur se résout par la table des lecteurs du compte, qu'un programme du compte peut changer sans
/// droits (DefineDosDevice, subst) ; elle n'est donc pas crue : chaque élément tenu doit être, pour Windows, à
/// l'endroit nommé, lettre comprise (`chemin_final`, lu par la poignée). Un lecteur réseau, un subst ou une lettre
/// redéfinie qui mène ailleurs est refusé.
fn tenir_le_programme(exe: &std::path::Path) -> Result<ProgrammeTenu, Ecart> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Component, Prefix};
    const PARTAGE_LECTURE: u32 = 0x1;
    const PARTAGE_ECRITURE: u32 = 0x2;
    const SEMANTIQUE_DE_SAUVEGARDE: u32 = 0x0200_0000;
    const OUVRIR_LE_POINT: u32 = 0x0020_0000;
    let mut composants = exe.components();
    let (Some(Component::Prefix(lecteur)), Some(Component::RootDir)) = (composants.next(), composants.next()) else {
        return Err(Ecart::PasUnDisque);
    };
    let reste: Vec<Component> = composants.collect();
    if !matches!(lecteur.kind(), Prefix::Disk(_))
        || reste.is_empty()
        || reste.iter().any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(Ecart::PasUnDisque);
    }
    let mut chemin = std::path::PathBuf::from(lecteur.as_os_str());
    chemin.push(Component::RootDir);
    let mut dossiers = Vec::with_capacity(reste.len());
    for (i, c) in reste.iter().enumerate() {
        chemin.push(c);
        let dossier = i + 1 < reste.len();
        // Lecture (lister un dossier) : un accès que Windows compare aux partages, au contraire d'une simple lecture
        // des attributs, qui n'empêcherait aucun renommage.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(if dossier {
                PARTAGE_LECTURE | PARTAGE_ECRITURE
            } else {
                PARTAGE_LECTURE
            })
            .custom_flags(OUVRIR_LE_POINT | SEMANTIQUE_DE_SAUVEGARDE)
            .open(&chemin)
            .map_err(|e| Ecart::Inouvrable(chemin.clone(), e.raw_os_error()))?;
        verifier_l_element(&chemin, &f)?;
        let m = f
            .metadata()
            .map_err(|e| Ecart::Inouvrable(chemin.clone(), e.raw_os_error()))?;
        if dossier != m.is_dir() || (!dossier && !m.is_file()) {
            return Err(Ecart::Genre(chemin));
        }
        if dossier {
            dossiers.push((chemin.clone(), f));
        } else {
            return Ok(ProgrammeTenu {
                dossiers,
                chemin,
                fichier: f,
            });
        }
    }
    Err(Ecart::PasUnDisque)
}

/// La clé de classe des programmes de la machine (HKLM\Software\Classes\exefile), en lecture : « runas » y prend sa
/// commande, et non dans la vue fusionnée des classes, où HKCU\Software\Classes (écrit par tout programme du compte,
/// sans droits) passe avant et pourrait faire élever un autre programme que celui qui est tenu.
fn cle_des_programmes() -> std::io::Result<winreg::RegKey> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"Software\Classes\exefile", KEY_READ | KEY_WOW64_64KEY)
}

/// SHELLEXECUTEINFOW de la relance : la commande de « runas » prise dans la clé `classe` (celle de la machine), la
/// poignée du processus gardée, aucune boîte d'erreur. Les chaînes, terminées par un zéro, doivent vivre jusqu'au
/// lancement.
fn info_de_lancement(
    verbe: &[u16],
    fichier: &[u16],
    parametres: &[u16],
    dossier: &[u16],
    classe: &winreg::RegKey,
) -> Result<InfoLancement, u32> {
    // SEE_MASK_CLASSKEY : la commande du verbe est lue dans `cle`, la clé de la machine, et nulle part ailleurs.
    const CLASSE_PAR_CLE: u32 = 0x3;
    const SANS_FERMER_PROCESSUS: u32 = 0x40;
    const SYNCHRONE: u32 = 0x100;
    const SANS_DIALOGUE_D_ERREUR: u32 = 0x400;
    Ok(InfoLancement {
        taille: u32::try_from(std::mem::size_of::<InfoLancement>()).map_err(|_| 0u32)?,
        masque: CLASSE_PAR_CLE | SANS_FERMER_PROCESSUS | SYNCHRONE | SANS_DIALOGUE_D_ERREUR,
        fenetre: std::ptr::null_mut(),
        verbe: verbe.as_ptr(),
        fichier: fichier.as_ptr(),
        parametres: parametres.as_ptr(),
        dossier: dossier.as_ptr(),
        affichage: 1,
        instance: std::ptr::null_mut(),
        liste: std::ptr::null_mut(),
        classe: std::ptr::null(),
        cle: classe.raw_handle().cast(),
        raccourci: 0,
        icone: std::ptr::null_mut(),
        processus: std::ptr::null_mut(),
    })
}

/// Relance ce programme avec « runas » (la demande d'administrateur) et rend le processus ; l'erreur Windows sinon
/// (1223 : la personne a refusé).
fn relancer_eleve(exe: &std::path::Path, parametres: &str) -> Result<Fils, u32> {
    let classe = cle_des_programmes().map_err(|e| e.raw_os_error().and_then(|c| u32::try_from(c).ok()).unwrap_or(0))?;
    let verbe = large("runas");
    let fichier: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let parametres = large(parametres);
    // Le fils démarre dans System32, pas dans le dossier d'où Vanguard est parti (Téléchargements, clé USB) : rien
    // de ce que le compte y a posé n'est trouvé par un nom relatif, ni par lui ni par ce qu'il lance.
    let dossier: Vec<u16> = crate::commande::dossier_systeme()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut info = info_de_lancement(&verbe, &fichier, &parametres, &dossier, &classe)?;
    // SAFETY: la structure a la taille et la disposition de SHELLEXECUTEINFOW ; les chaînes sont terminées par un
    // zéro et vivent pendant l'appel, comme la clé de classe (`classe`, fermée par winreg après). La poignée du
    // processus (demandée par le masque, vérifiée non nulle) est à nous et fermée une seule fois, par OwnedHandle.
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
                crate::compte_rendu::Contexte::CorrectionElevee,
                &format!("un client inattendu (PID {client}) s'est branché sur le canal : débranché"),
            );
            // SAFETY: idem.
            unsafe { DisconnectNamedPipe(self.tube.as_raw_handle()) };
        }
        false
    }

    /// Envoie la liste, lit une réponse par ligne ; `None` si le fils n'a pas répondu jusqu'au bout.
    /// Envoie les lignes (listes séparées par `SUITE`) et lit les réponses : `attendues`, une par ligne d'une liste,
    /// dans l'ordre d'envoi ; `None` si le compte n'y est pas.
    fn dialoguer(&self, pid: u32, lignes: &[String], attendues: usize) -> Option<Vec<Reponse>> {
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
        (reponses.len() == attendues).then_some(reponses)
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
    // Le dossier de départ demandé à ShellExecuteExW est System32 ; s'il n'a pas été suivi, il l'est ici.
    let _ = std::env::set_current_dir(crate::commande::dossier_systeme());
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
    let Some((tube, parent_tenu)) = ouvrir_le_canal(canal, parent) else {
        trp!(
            "Le canal ne mène pas au Vanguard qui a demandé la correction : rien n'est fait.",
            "The channel does not lead to the Vanguard that asked for the fix: nothing is done."
        );
        attendre_entree_pour_fermer();
        return CANAL_REFUSE;
    };
    let mut tube = tube;
    // Le compte de la personne, lu tout de suite par la poignée tenue, puis passé tel quel : jamais relu plus tard par
    // un numéro de processus que Windows aurait pu redonner.
    let compte = parent_tenu.sid().map_err(|e| e.to_string());
    // Ce que le fils lit lui-même de l'ordinateur pour rejuger les ordres : les processus protégés dès maintenant, le
    // parent tenu ; les sessions à distance, relues après l'accord.
    let mut juge = ordres::Juge::lire(Some(parent));
    let Some(lignes) = lire_lignes(&tube) else {
        return CANAL_REFUSE;
    };
    let Some(listes) = valider_listes(&lignes) else {
        trp!(
            "La liste reçue n'est pas une liste de corrections de Vanguard : rien n'est fait. Un autre programme y a touché : lancez une analyse antivirus.",
            "The list received is not a Vanguard fix list: nothing is done. Another program touched it: run an antivirus scan."
        );
        let _ = tube.write_all(format!("{FIN}\n").as_bytes());
        attendre_entree_pour_fermer();
        return LISTE_REFUSEE;
    };
    // Chaque script est lu et vérifié avant d'être montré : ce que l'Entrée autorise est exactement ce qui sera lancé.
    // Illisible ou changé depuis son écriture, l'envoi entier est refusé, sans rien demander.
    let montres = match listes.iter().map(|l| a_montrer(l)).collect::<Result<Vec<_>, _>>() {
        Ok(m) => m,
        Err(raison) => {
            trp!(
                "{} : rien n'est fait, rien n'est demandé.",
                "{}: nothing is done, nothing is asked.",
                raison
            );
            let _ = tube.write_all(format!("{FIN}\n").as_bytes());
            attendre_entree_pour_fermer();
            return LISTE_REFUSEE;
        }
    };
    let mut code = 0;
    // Un échec qui n'est pas un arrêt voulu par la personne : lui seul fait dire « au moins une étape en échec ».
    let mut echec = false;
    let mut a_finir = false;
    // Sans point de restauration, et la personne ne veut pas continuer sans : tout le reste est abandonné, listes
    // suivantes comprises (sans leur question).
    let mut abandon = false;
    // Chaque liste (P7 : les choix de Defender à part) est jugée, montrée et demandée à son tour, juste avant ses
    // gestes : la valeur relue pour juger une baisse est celle de l'instant de la question.
    'listes: for (liste, montre) in listes.iter().zip(&montres) {
        let Some((sens, baisse)) = juger_liste(liste, &compte) else {
            dire_melee();
            code = 1;
            echec = true;
            for _ in liste {
                if tube
                    .write_all(format!("{}\n", ligne_resultat(&melee())).as_bytes())
                    .is_err()
                {
                    code = CANAL_REFUSE;
                    break 'listes;
                }
            }
            continue;
        };
        let mut arret = abandon;
        if !arret {
            montrer(montre, &sens);
            arret = !question(liste, &sens, baisse, true);
            if arret {
                dire_annule(baisse);
            } else if !tube_ouvert(&tube) {
                // Le Vanguard qui a demandé s'est fermé pendant la lecture : rien de ce qui serait fait ne pourrait être
                // noté dans « Ce que Vanguard a changé ».
                trp!(
                    "Le Vanguard qui a demandé la correction s'est fermé : rien n'est fait.",
                    "The Vanguard that asked for the fix has closed: nothing is done."
                );
                attendre_entree_pour_fermer();
                return CANAL_REFUSE;
            }
        }
        juge.relire_sessions();
        for ((e, bilan), s) in liste.iter().zip(bilans(liste, &compte)).zip(&sens) {
            let r = if arret {
                refusee()
            } else {
                faire(e, &juge, &compte, bilan, s.as_ref().map(|(m, _)| *m))
            };
            if !r.reussi {
                code = 1;
                echec |= r.raison != arret_demande() && !r.raison.starts_with(au_redemarrage());
                a_finir |= r.raison.starts_with(au_redemarrage());
                if est_point(e) {
                    arret = true;
                    abandon = true;
                }
            }
            if tube.write_all(format!("{}\n", ligne_resultat(&r)).as_bytes()).is_err() {
                // Le parent n'entend plus : ce qui suivrait serait changé sans être noté dans « Ce que Vanguard a changé ».
                code = CANAL_REFUSE;
                break 'listes;
            }
        }
    }
    super::defender_ecriture::nettoyer_notes();
    let _ = tube.write_all(format!("{FIN}\n").as_bytes());
    let _ = tube.flush();
    drop(tube);
    drop(parent_tenu);
    println!();
    if code == 0 {
        trp!("{VERT}Terminé.{RESET}", "{VERT}Finished.{RESET}");
    } else if code == 1 && !echec && a_finir {
        trp!(
            "Terminé : une étape reste à faire de votre côté (voir ci-dessus).",
            "Finished: one step is left for you to do (see above)."
        );
    } else if code == 1 && !echec {
        trp!(
            "Arrêté à votre demande : rien de plus n'a été modifié.",
            "Stopped as you asked: nothing more was changed."
        );
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

/// Ce que la console montre avant l'accord : le texte de chaque geste et, pour un script, ses lignes vérifiées ; pour
/// le hosts, la différence lue et jugée ici. `Err(raison)` dès qu'un script est illisible ou n'a plus son empreinte,
/// ou que le hosts préparé est refusé : montrer autre chose que ce qui sera fait (ou rien) ferait accepter à l'aveugle.
fn a_montrer(liste: &[Element]) -> Result<Vec<(String, Vec<String>)>, crate::modele::Echec> {
    liste
        .iter()
        .map(|e| {
            let lignes = match e {
                Element::Script(s) => {
                    let o = lire_script_verifie(&s.chemin, &s.empreinte).ok_or_else(|| {
                        crate::modele::Echec::refuse("eleve/montrer", trf!(
                            "Le script de correction {} ne se lit plus ou a changé depuis que Vanguard l'a écrit. Un autre programme y a touché : lancez une analyse antivirus, puis relancez la correction",
                            "The fix script {} can no longer be read or has changed since Vanguard wrote it. Another program touched it: run an antivirus scan, then run the fix again",
                            crate::ui::affichable(&s.chemin)
                        ))
                    })?;
                    String::from_utf8_lossy(&o)
                        .trim_start_matches('\u{feff}')
                        .lines()
                        .map(crate::ui::affichable)
                        .collect()
                }
                Element::Acte(gestes::Acte::HostsEcrire(h)) => super::reseau_ecriture::montrer_hosts(h)
                    .map_err(|r| {
                        crate::modele::Echec::refuse(
                            "eleve/hosts",
                            trf!("Fichier hosts refusé : {r}", "Hosts file refused: {r}"),
                        )
                    })?,
                _ => Vec::new(),
            };
            Ok((e.texte(), lignes))
        })
        .collect()
}

/// Le geste couperait-il une session à distance en cours (ou des connexions qui ne se lisent pas) ?
fn coupe(touche_le_reseau: bool, juge: &ordres::Juge) -> bool {
    gestes::coupe_une_session(touche_le_reseau, super::session_a_distance(), juge.sessions_en_cours())
}

fn refus_session() -> Resultat {
    Resultat {
        reussi: false,
        rien: false,
        avant: None,
        raison: tr!(
            "une connexion à distance est en cours (Bureau à distance, SSH), ou les connexions ne se lisent pas : ce geste la couperait, refusé",
            "a remote connection is in progress (Remote Desktop, SSH), or connections cannot be read: this step would cut it, refused"
        )
        .to_string(),
    }
}

fn attendre_entree_pour_fermer() {
    let _ = crate::ui::demander(tr!("Appuyez sur Entrée pour fermer : ", "Press Enter to close: "));
}

/// Une correction non faite parce qu'on s'est arrêté avant.
fn refusee() -> Resultat {
    Resultat {
        reussi: false,
        rien: false,
        avant: None,
        raison: arret_demande().to_string(),
    }
}

/// Fait un geste de la liste, en l'annonçant, puis « OK » ou l'erreur : une fenêtre muette ne se distingue pas d'une
/// fenêtre figée. Un ordre est d'abord rejugé ici.
/// `compte` : le SID de la personne, lu dans le jeton du Vanguard qui a lancé ce processus (tenu par une poignée dès
/// le tube vérifié), ou dans le sien quand Vanguard est lui-même administrateur ; l'erreur de lecture sinon.
/// `bilan` : celui de `bilans`, pour une correction de la table.
/// `montre` : le sens d'un choix et la valeur relue tels qu'ils ont été montrés avant l'accord, rejugés juste avant
/// d'écrire.
fn faire(
    e: &Element,
    juge: &ordres::Juge,
    compte: &Result<String, String>,
    bilan: corrections::Bilan,
    montre: Option<gestes::Montre>,
) -> Resultat {
    println!("{GRIS}> {}  {}{RESET}", chrono::Local::now().format("%H:%M"), e.texte());
    let r = match e {
        Element::Correction(c) => corrections::appliquer(c, compte, bilan),
        Element::Ordre(o) => {
            let r = match ordres::juger(o, juge) {
                Some(refus) => ordres::Resultat::echec(refus),
                None => ordres::faire(o, juge),
            };
            Resultat {
                reussi: r.reussi,
                rien: false,
                avant: None,
                raison: if r.reussi { r.note.unwrap_or_default() } else { r.raison },
            }
        }
        Element::Script(s) => lancer_script(&s.chemin, &s.empreinte),
        // Rendre ou redemander l'adresse, changer le DNS d'une carte : jamais pendant une session à distance, relue
        // après l'accord (le parent le refuse aussi, mais une ligne forgée ne passe pas par lui).
        Element::Programme(a) if coupe(a.coupe_le_reseau(), juge) => refus_session(),
        Element::Acte(a) if coupe(a.touche_le_reseau(), juge) => refus_session(),
        Element::Programme(a) => apres_sfc(a, lancer_programme(a)),
        Element::Acte(a) => super::defender_ecriture::faire_choix(a, montre)
            .unwrap_or_else(|| super::services_ecriture::faire(a, compte)),
    };
    if r.reussi {
        match &r.avant {
            Some(avant) if r.raison == corrections::NOTE_CHOIX => trp!(
                "  {VERT}OK{RESET} (avant : {avant} ; noté, « Rallumer » le remet)",
                "  {VERT}OK{RESET} (before: {avant}; noted, “Turn back on” restores it)"
            ),
            Some(avant) => trp!(
                "  {VERT}OK{RESET} (avant : {avant})",
                "  {VERT}OK{RESET} (before: {avant})"
            ),
            None if !r.raison.is_empty() && r.raison != sans_point_accepte() => {
                trp!("  {VERT}OK{RESET} ({})", "  {VERT}OK{RESET} ({})", r.raison);
            }
            None => trp!("  {VERT}OK{RESET}", "  {VERT}OK{RESET}"),
        }
    } else if let Some(code) = r.raison.strip_prefix(au_redemarrage()) {
        // Seul chkdsk /scan a un code « reste à faire » dans la table (`gestes::PROGRAMMES`).
        let conseil = crate::machine::conseil_chkdsk(crate::commande::lecteur_systeme().unwrap_or("C:"));
        trp!(
            "  {ACCENT}Disque à vérifier{RESET} : chkdsk n'a pas pu tout vérifier, ou a trouvé des erreurs qu'il ne répare pas pendant que Windows tourne ; {}. ({})",
            "  {ACCENT}Disk to check{RESET}: chkdsk could not check everything, or found errors it does not repair while Windows runs; {}. ({})",
            conseil,
            code.trim()
        );
    } else if r.raison == arret_demande() {
        trp!(
            "  Arrêté à votre demande : la suite n'est pas faite.",
            "  Stopped as you asked: the rest is not done."
        );
    } else {
        trp!("  Échec : {}", "  Failed: {}", echec_lisible(e, &r.raison));
    }
    r
}

/// Un échec dit à la personne : ce qui s'est passé, quoi faire, le détail technique entre parenthèses. La raison
/// elle-même (« code=1 etats=101 ») part telle quelle au parent, qui la relit : seul l'affichage change.
fn echec_lisible(e: &Element, raison: &str) -> String {
    let Some((code, suite)) = raison
        .strip_prefix("code=")
        .map(|r| r.split_once(' ').unwrap_or((r, "")))
        .and_then(|(c, suite)| Some((c.parse::<i32>().ok()?, suite)))
    else {
        return raison.to_string();
    };
    match e {
        Element::Script(_) if code == super::SCRIPT_MODIFIE => trf!(
            "le script de correction a changé ou disparu depuis que Vanguard l'a écrit : rien n'a été lancé. Un autre programme y a touché : lancez une analyse antivirus, puis relancez la correction. (code {code})",
            "the fix script changed or disappeared since Vanguard wrote it: nothing was run. Another program touched it: run an antivirus scan, then run the fix again. (code {code})"
        ),
        Element::Script(_) if code == super::LANGAGE_RESTREINT => trf!(
            "PowerShell est en mode restreint sur ce PC (stratégie de sécurité) : Vanguard ne peut pas y vérifier son script, rien n'a été lancé. Faites cette correction à la main ou demandez à qui gère ce PC. (code {code})",
            "PowerShell is in restricted mode on this PC (security policy): Vanguard cannot verify its script there, nothing was run. Make this fix by hand or ask whoever manages this PC. (code {code})"
        ),
        Element::Script(_) if code == crate::reparer::SANS_POINT_ARRETE => trf!(
            "arrêté à votre demande, sans point de restauration : rien n'a changé. (code {code})",
            "stopped as you asked, without a restore point: nothing was changed. (code {code})"
        ),
        Element::Script(_) => {
            let detail = match suite.strip_prefix("etats=") {
                Some(etats) if !etats.is_empty() => format!("code {code}, {etats}"),
                _ => format!("code {code}"),
            };
            trf!(
                "une ou plusieurs étapes n'ont pas abouti ; le message de chacune est juste au-dessus. Relancez la correction ; si l'échec revient, redémarrez l'ordinateur puis réessayez. ({detail})",
                "one or more steps did not succeed; the message of each is just above. Run the fix again; if it fails again, restart the computer and try once more. ({detail})"
            )
        }
        Element::Programme(a) => trf!(
            "{} a fini en erreur ; son message est juste au-dessus. Redémarrez l'ordinateur, puis relancez la correction. (code {code})",
            "{} ended with an error; its message is just above. Restart the computer, then run the fix again. (code {code})",
            a.programme.exe
        ),
        _ => raison.to_string(),
    }
}

/// Le script PowerShell d'une liste mêlée : lu ici en mémoire, son empreinte vérifiée, puis lancé dans cette console
/// par l'amorce, qui relit les octets et refuse tout autre contenu. Un lien, un dossier ou un fichier changé : refusé.
/// Le script répond correctif par correctif dans un tube anonyme créé ici et hérité par PowerShell (variable
/// `VANGUARD_RESULTATS` : la valeur de la poignée) : ni journal ni fichier de résultats dans le dossier du compte, que
/// ce compte pourrait réécrire. En échec, les états lus partent au parent (`echec code=N etats=101`).
fn lancer_script(chemin: &str, empreinte: &str) -> Resultat {
    let refus = |raison: String| Resultat {
        reussi: false,
        rien: false,
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
    let fils = crate::coulisses::Suivie::spawn_suivi(&mut commande);
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
            rien: false,
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
        rien: false,
        avant: None,
        raison,
    };
    let Some(mut commande) = commande_du_programme(a) else {
        return refus(tr!("lecteur système introuvable", "system drive not found").to_string());
    };
    let exe = std::path::PathBuf::from(commande.get_program());
    match crate::coulisses::Suivie::status_suivi(&mut commande) {
        Ok(s) => match s.code() {
            Some(3010) if a.reussite(3010) => Resultat {
                reussi: true,
                rien: false,
                avant: None,
                raison: tr!("redémarrage nécessaire", "restart needed").to_string(),
            },
            Some(c) if a.reussite(c) => Resultat {
                reussi: true,
                rien: false,
                avant: None,
                raison: String::new(),
            },
            // Ni fait ni échoué : la personne doit lancer chkdsk /f (chkdsk 3). Pas compté fait, dit à part.
            Some(c) if a.au_redemarrage(c) => refus(format!("{} code={c}", au_redemarrage())),
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

/// sfc /scanfile : le code de sfc ne suffit pas, le programme d'accessibilité est relu. Encore une copie, ou
/// illisible : échec dit clairement (la raison de sfc gardée devant) ; plus une copie : remis, quel que soit le code.
fn apres_sfc(a: &gestes::Appel, r: Resultat) -> Resultat {
    let (true, Some(nom)) = (a.programme.id == gestes::SFC_FICHIER, a.nom) else {
        return r;
    };
    match super::portes::apres_sfc(nom, super::portes::copie_de(nom)) {
        None => Resultat {
            reussi: true,
            rien: false,
            avant: None,
            raison: if r.reussi { r.raison } else { String::new() },
        },
        Some(echec) => Resultat {
            reussi: false,
            rien: false,
            avant: None,
            raison: if r.raison.is_empty() {
                echec
            } else {
                format!("{} ; {echec}", r.raison)
            },
        },
    }
}

/// La commande d'un programme fixe, prête à lancer : son chemin complet, ses arguments, l'environnement réduit
/// (DISM ou sfc ne doivent rien charger de ce que le compte a posé) et System32 pour dossier courant. `None` : le
/// lecteur système ne se lit pas.
fn commande_du_programme(a: &gestes::Appel) -> Option<std::process::Command> {
    let systeme = crate::commande::dossier_systeme();
    let lecteur = crate::commande::lecteur_systeme()?;
    let exe = match a.programme.dossier {
        gestes::Dossier::Systeme32 => systeme.join(a.programme.exe),
        gestes::Dossier::Defender => {
            std::path::PathBuf::from(format!(r"{lecteur}\{}\{}", gestes::DOSSIER_DEFENDER, a.programme.exe))
        }
    };
    let mut commande = std::process::Command::new(exe);
    super::environnement::reduire(&mut commande)
        .current_dir(systeme)
        .args(a.arguments(lecteur, &systeme.to_string_lossy()));
    Some(commande)
}

/// Se branche sur le tube du parent, puis vérifie que le serveur est bien le processus annoncé et que son programme
/// est le même que celui-ci (même empreinte). Le parent est rendu tenu par une poignée, ouverte dès son numéro
/// vérifié : tant qu'elle vit, ce numéro ne passe à aucun autre processus, et ce qui est lu par elle (son programme,
/// son compte) est le sien.
fn ouvrir_le_canal(canal: &str, parent: u32) -> Option<(std::fs::File, super::processus::Tenu)> {
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
    let tenu = super::processus::Tenu::ouvrir(parent).ok()?;
    let moi = std::env::current_exe().ok()?;
    let chemin_parent = std::path::PathBuf::from(tenu.chemin()?);
    if empreinte(&moi)? != empreinte(&chemin_parent)? {
        return None;
    }
    // Le tube est encore ouvert de l'autre côté, la poignée déjà tenue : le parent n'a pas fini entre la lecture de
    // son numéro et l'ouverture de la poignée (un autre processus qui l'aurait repris ne tient pas ce tube).
    tube_ouvert(&tube).then_some((tube, tenu))
}

/// L'autre bout du tube est-il encore ouvert ? Rien n'est lu (PeekNamedPipe sans tampon) ; un parent fini le ferme.
fn tube_ouvert(tube: &std::fs::File) -> bool {
    let mut disponibles = 0u32;
    // SAFETY: poignée valide (le File vit) ; aucun tampon donné (taille 0), seul un entier à nous est écrit.
    unsafe {
        PeekNamedPipe(
            tube.as_raw_handle(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            &raw mut disponibles,
            std::ptr::null_mut(),
        ) != 0
    }
}

/// Ce qui est noté quand la personne a accepté de continuer sans point de restauration.
pub(crate) fn sans_point_accepte() -> &'static str {
    tr!("sans point de restauration, accepté", "no restore point, accepted")
}

/// Point de restauration par WMI (SystemRestore.CreateRestorePoint, celui de Checkpoint-Computer) : c'est le service
/// WMI qui le crée. SRSetRestorePointW appelé d'ici commençait bien le cliché, que VSS abandonnait (événement 8193,
/// QueryFullProcessImageNameW, poignée invalide) : aucun point gardé, et un plus ancien parfois effacé. Windows ne
/// crée qu'un point par 24 h et répond quand même « succès » : seul un numéro neuf dans la liste des points, relue
/// après, prouve le point. Sans lui, quelle qu'en soit la raison, on la dit et on demande s'il faut continuer sans.
pub(crate) fn point_de_restauration() -> (bool, String) {
    match poser_le_point() {
        Ok(()) => (true, String::new()),
        Err(raison) => continuer_sans_point(&raison.to_string(), crate::ui::demander),
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
        (false, arret_demande().to_string())
    }
}

/// Espace de noms et classe WMI des points de restauration.
const ESPACE_POINTS: &str = r"root\default";
const CLASSE_POINTS: &str = "SystemRestore";
/// Le point demande un cliché du disque : une douzaine de secondes sur la VM, bien plus sur un disque lent.
const DELAI_POINT: std::time::Duration = std::time::Duration::from_secs(300);
/// Windows ne crée pas de point s'il en a un de moins d'un jour (SystemRestorePointCreationFrequency absente).
const UN_JOUR: u64 = 24 * 3600;

/// Un point de la liste de Windows : son numéro et son âge en secondes (`None` : date illisible).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Point {
    sequence: i64,
    age: Option<u64>,
}

/// La liste des points ; `None` : illisible (WMI absent, refus, délai).
fn points() -> Option<Vec<Point>> {
    let maintenant = chrono::Utc::now();
    let lignes = super::wmi::requete(ESPACE_POINTS, CLASSE_POINTS, "", &["SequenceNumber", "CreationTime"])?;
    Some(
        lignes
            .iter()
            .filter_map(|l| {
                Some(Point {
                    sequence: l.get("SequenceNumber")?.entier()?,
                    age: l
                        .get("CreationTime")
                        .and_then(super::wmi::Valeur::texte)
                        .and_then(|date| super::wmi::secondes_depuis(date, maintenant)),
                })
            })
            .collect(),
    )
}

/// Demande le point, puis le cherche dans la liste ; `Err` : pourquoi il n'y est pas, prêt à montrer.
fn poser_le_point() -> Result<(), Echec> {
    /// BEGIN_SYSTEM_CHANGE et MODIFY_SETTINGS : ceux de Checkpoint-Computer, qui ne ferme pas le changement.
    const DEBUT: i32 = 100;
    const REGLAGES: i32 = 12;
    use super::wmi::{Parametre, Retour};
    let avant = points();
    let description = trf!("Vanguard : avant une correction", "Vanguard: before a fix");
    let retour = super::wmi::methode(
        ESPACE_POINTS,
        CLASSE_POINTS,
        "CreateRestorePoint",
        vec![
            ("Description", Parametre::Texte(description)),
            ("RestorePointType", Parametre::Entier(REGLAGES)),
            ("EventType", Parametre::Entier(DEBUT)),
        ],
        DELAI_POINT,
    );
    let mut apres = None;
    // Accepté sans code de retour lisible (`Accepte`) : seule la liste des points dit s'il est fait.
    if matches!(retour, Retour::Valeur(0) | Retour::Accepte) && avant.is_some() {
        // La liste peut ne montrer le point qu'un peu après la réponse : relue quelques fois, 20 s au plus.
        for essai in 0..10 {
            if essai > 0 {
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            apres = points();
            if let (Some(a), Some(p)) = (&avant, &apres)
                && est_neuf(a, p)
            {
                break;
            }
        }
    }
    juger_le_point(avant.as_deref(), retour, apres.as_deref())
}

/// Un point plus récent que tous ceux d'avant est dans la liste.
fn est_neuf(avant: &[Point], apres: &[Point]) -> bool {
    let plus_haut = avant.iter().map(|p| p.sequence).max();
    apres.iter().any(|p| plus_haut.is_none_or(|h| p.sequence > h))
}

/// `Ok` seulement si un point neuf est dans la liste ; sinon la raison. `retour` : ce qu'a rendu CreateRestorePoint ;
/// `avant`, `apres` : la liste des points (`None` : illisible).
fn juger_le_point(avant: Option<&[Point]>, retour: super::wmi::Retour, apres: Option<&[Point]>) -> Result<(), Echec> {
    use super::wmi::{CLASSE_ABSENTE, Retour};
    let phrase = match (retour, avant, apres) {
        (Retour::SansReponse, ..) => trf!(
            "Windows n'a pas répondu à temps (WMI SystemRestore, {} min)",
            "Windows did not answer in time (WMI SystemRestore, {} min)",
            DELAI_POINT.as_secs() / 60
        ),
        (Retour::Refuse(code), ..) if CLASSE_ABSENTE.contains(&code) => trf!(
            "ce Windows n'a pas les points de restauration (WMI SystemRestore absent)",
            "this Windows has no restore points (WMI SystemRestore missing)"
        ),
        // Passe 11 de la VM : VSS coupé, la demande est refusée par une erreur, pas laissée sans réponse.
        (Retour::Refuse(code), ..) => trf!(
            "Windows a refusé la demande (code 0x{:08X}) : protection du système ou service VSS coupés ?",
            "Windows refused the request (code 0x{:08X}): system protection or VSS service turned off?",
            code
        ),
        (Retour::Valeur(n), ..) if n != 0 => trf!(
            "erreur {} : protection du système désactivée sur C: ?",
            "error {}: system protection turned off on C:?",
            n
        ),
        (_, Some(avant), Some(apres)) if est_neuf(avant, apres) => return Ok(()),
        (_, Some(_), Some(apres)) => match apres.iter().filter_map(|p| p.age).filter(|&a| a < UN_JOUR).min() {
            Some(age) => trf!(
                "Windows l'a sauté : il n'en fait qu'un par 24 h, et le dernier a {}",
                "Windows skipped it: it makes only one per 24 h, and the last one is {} old",
                duree(age)
            ),
            None => trf!(
                "Windows a répondu sans garder le point",
                "Windows answered without keeping the point"
            ),
        },
        _ => trf!(
            "liste des points illisible : point pas vérifié",
            "restore point list unreadable: point not checked"
        ),
    };
    Err(Echec::echoue(CONTEXTE_POINT, phrase))
}

/// Un âge lisible : « 40 min », « 3 h ».
fn duree(secondes: u64) -> String {
    if secondes < 3600 {
        format!("{} min", secondes / 60)
    } else {
        format!("{} h", secondes / 3600)
    }
}

/// Le contexte des échecs du point de restauration.
const CONTEXTE_POINT: &str = "restauration/point";

#[cfg(test)]
mod tests {
    use super::*;

    /// Un dossier `vrai` avec un programme (de faux octets suffisent : seul le chemin est jugé ici). Dans le dossier
    /// temporaire de Windows, pas sous `essais::temporaire` : sous Wine, celui-ci passe par Z:, où chaque point de
    /// montage de Linux (/home) se montre en point d'analyse et serait refusé à juste titre. Par son nom long : un
    /// dossier temporaire au nom court (C:\Users\RUNNER~1\…) serait refusé, lui aussi à juste titre.
    fn programme_jetable(nom: &str) -> (crate::essais::Jetable, std::path::PathBuf) {
        let temporaire = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let temporaire = temporaire
            .to_str()
            .and_then(|t| t.strip_prefix(r"\\?\"))
            .map_or_else(|| temporaire.clone(), std::path::PathBuf::from);
        let d = crate::essais::Jetable::garder(temporaire.join(crate::essais::nom_unique(nom)));
        let vrai = d.join("vrai");
        std::fs::create_dir_all(&vrai).unwrap();
        std::fs::write(vrai.join("vanguard.exe"), b"MZ").unwrap();
        (d, vrai)
    }

    /// Le lien `lien` est-il vu comme un point d'analyse ? Sinon (Wine qui ne le montrerait pas), l'essai ne prouve rien.
    fn lien_vu(lien: &std::path::Path) -> bool {
        use std::os::windows::fs::MetadataExt;
        std::fs::symlink_metadata(lien).is_ok_and(|m| m.file_attributes() & 0x400 != 0)
    }

    /// #22 : un dossier du chemin qui est un lien (comme une jonction) ferait relire à « runas » un autre dossier que
    /// celui vérifié : refusé, le lien nommé ; le même programme par son vrai chemin est tenu.
    #[test]
    fn dossier_par_un_lien_refuse() {
        let (d, vrai) = programme_jetable("eleve-lien-dossier");
        let lien = d.join("lien");
        if std::os::windows::fs::symlink_dir(&vrai, &lien).is_err() || !lien_vu(&lien) {
            return crate::essais::saute("lien symbolique de dossier impossible ou invisible ici");
        }
        match tenir_le_programme(&lien.join("vanguard.exe")) {
            Err(Ecart::PointDAnalyse(c, _)) => assert_eq!(c, lien),
            autre => panic!("lien de dossier accepté : {:?}", autre.map(|_| ())),
        }
        assert!(tenir_le_programme(&vrai.join("vanguard.exe")).is_ok());
    }

    /// #22 : le programme lui-même par un lien symbolique : refusé.
    #[test]
    fn fichier_par_un_lien_refuse() {
        let (_d, vrai) = programme_jetable("eleve-lien-fichier");
        let lien = vrai.join("autre.exe");
        if std::os::windows::fs::symlink_file(vrai.join("vanguard.exe"), &lien).is_err() || !lien_vu(&lien) {
            return crate::essais::saute("lien symbolique de fichier impossible ou invisible ici");
        }
        assert!(matches!(tenir_le_programme(&lien), Err(Ecart::PointDAnalyse(c, _)) if c == lien));
    }

    /// #22 : chaque dossier du chemin est tenu, pas seulement le dernier : un par dossier, chacun à son endroit ; tant
    /// qu'ils le sont, ni le dossier du programme ni celui au-dessus ne se renomment ; lâchés, ils se renomment.
    #[test]
    fn chaque_dossier_du_chemin_est_tenu() {
        let (d, vrai) = programme_jetable("eleve-tenu");
        let exe = vrai.join("vanguard.exe");
        let tenu = tenir_le_programme(&exe).unwrap();
        let attendus: Vec<_> = exe.ancestors().skip(1).filter(|a| a.parent().is_some()).collect();
        assert_eq!(tenu.dossiers.len(), attendus.len());
        for ((chemin, f), attendu) in tenu.dossiers.iter().zip(attendus.iter().rev()) {
            assert_eq!(chemin, attendu);
            assert!(
                chemin_final(f).is_some_and(|c| meme_chemin(&c, attendu.as_os_str())),
                "{chemin:?}"
            );
        }
        assert!(std::fs::rename(&vrai, d.join("ailleurs")).is_err());
        let a_cote = d.with_file_name(crate::essais::nom_unique("eleve-tenu-ailleurs"));
        assert!(std::fs::rename(&d, &a_cote).is_err(), "le dossier au-dessus se renomme");
        drop(tenu);
        assert!(std::fs::rename(&vrai, d.join("ailleurs")).is_ok());
    }

    /// Constats 1, 2, 4 et 10 : une lettre que ce compte fait mener ailleurs (ici par subst, sans droits) passe pour un
    /// disque à la lecture du texte ; par sa poignée, le programme est ailleurs : refusé, la lettre nommée.
    #[test]
    fn une_lettre_qui_mene_ailleurs_est_refusee() {
        const RETIRER: u32 = 0x2;
        struct Lettre(Vec<u16>);
        impl Drop for Lettre {
            fn drop(&mut self) {
                // SAFETY: le nom est terminé par un zéro ; retirer la définition posée par l'essai, rien d'autre.
                unsafe { DefineDosDeviceW(RETIRER, self.0.as_ptr(), std::ptr::null()) };
            }
        }
        if crate::commande::sous_wine() {
            // Wine résout les lettres par le dossier dosdevices de son préfixe, pas par la table des lecteurs, et son
            // GetFinalPathNameByHandleW rend le chemin tel qu'ouvert (même un nom court) : rien n'y serait éprouvé.
            return crate::essais::saute("Wine rend le chemin tel qu'ouvert : éprouvé sur un vrai Windows seulement");
        }
        let (d, _vrai) = programme_jetable("eleve-lettre");
        // SAFETY: GetLogicalDrives ne prend rien et rend un masque.
        let prises = unsafe { GetLogicalDrives() };
        let Some(libre) = (b'M'..=b'Y').rev().find(|l| prises & (1 << (l - b'A')) == 0) else {
            return crate::essais::saute("aucune lettre de lecteur libre");
        };
        let nom = format!("{}:", char::from(libre));
        let cible = large(&d.to_string_lossy());
        let lettre = Lettre(large(&nom));
        // SAFETY: les deux chaînes sont terminées par un zéro et vivent pendant l'appel.
        if unsafe { DefineDosDeviceW(0, lettre.0.as_ptr(), cible.as_ptr()) } == 0 {
            return crate::essais::saute("subst impossible ici");
        }
        let exe = std::path::PathBuf::from(format!(r"{nom}\vrai\vanguard.exe"));
        let attendu = std::path::PathBuf::from(format!(r"{nom}\vrai"));
        if std::fs::metadata(&exe).is_err() {
            return crate::essais::saute("la lettre posée ne mène pas au dossier ici");
        }
        match tenir_le_programme(&exe) {
            Err(Ecart::Ailleurs(c)) => assert_eq!(c, attendu),
            autre => panic!("lettre qui mène ailleurs acceptée : {:?}", autre.map(|_| ())),
        }
        drop(lettre);
    }

    /// Constat 9 : le fichier tenu devient un lien symbolique après son ouverture (l'accès « écrire les attributs »
    /// passe malgré la poignée) : la revue d'avant « runas » le refuse.
    #[test]
    fn un_fichier_devenu_lien_est_refuse() {
        use std::os::windows::fs::OpenOptionsExt;
        const ECRIRE_ATTRIBUTS: u32 = 0x100;
        const POSER_UN_POINT: u32 = 0x0009_00A4;
        let (_d, vrai) = programme_jetable("eleve-devenu-lien");
        let exe = vrai.join("vanguard.exe");
        let tenu = tenir_le_programme(&exe).unwrap();
        assert!(tenu.encore_sur().is_ok());
        let Ok(autre) = std::fs::OpenOptions::new()
            .access_mode(ECRIRE_ATTRIBUTS)
            .share_mode(0x7)
            .custom_flags(0x0020_0000)
            .open(&exe)
        else {
            return crate::essais::saute("ouverture pour écrire les attributs impossible ici");
        };
        // REPARSE_DATA_BUFFER d'un lien symbolique relatif vers « autre.exe » (nom de substitution puis d'affichage).
        let cible: Vec<u16> = "autre.exe".encode_utf16().collect();
        let octets = u16::try_from(cible.len() * 2).unwrap();
        let mut tampon = Vec::new();
        tampon.extend_from_slice(&ETIQUETTE_LIEN.to_le_bytes());
        tampon.extend_from_slice(&(12 + 2 * octets).to_le_bytes());
        tampon.extend_from_slice(&0u16.to_le_bytes());
        for v in [0, octets, octets, octets] {
            tampon.extend_from_slice(&v.to_le_bytes());
        }
        tampon.extend_from_slice(&1u32.to_le_bytes());
        for _ in 0..2 {
            tampon.extend(cible.iter().flat_map(|c| c.to_le_bytes()));
        }
        let mut rendus = 0u32;
        // SAFETY: la poignée et le tampon vivent pendant l'appel ; aucune sortie demandée.
        let ok = unsafe {
            DeviceIoControl(
                autre.as_raw_handle(),
                POSER_UN_POINT,
                tampon.as_mut_ptr().cast(),
                u32::try_from(tampon.len()).unwrap(),
                std::ptr::null_mut(),
                0,
                &raw mut rendus,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return crate::essais::saute("poser un point d'analyse sur un fichier est impossible ici");
        }
        drop(autre);
        assert!(
            matches!(tenu.encore_sur(), Err(Ecart::PointDAnalyse(c, _)) if c == exe),
            "fichier devenu lien accepté"
        );
    }

    /// Constats 3 et 6 : la cause d'une ouverture refusée est dite telle quelle (absent, déjà ouvert par un autre
    /// programme), avec un conseil qui la règle, et le journal garde l'erreur Windows.
    #[test]
    fn l_ouverture_refusee_dit_sa_cause() {
        use std::os::windows::fs::OpenOptionsExt;
        let (_d, vrai) = programme_jetable("eleve-inouvrable");
        let absent = vrai.join("absent.exe");
        match tenir_le_programme(&absent) {
            Err(e @ Ecart::Inouvrable(_, Some(2 | 3))) => {
                assert!(
                    e.dire().contains("absent") || e.dire().contains("missing"),
                    "{}",
                    e.dire()
                );
            }
            autre => panic!("absent mal dit : {:?}", autre.map(|_| ())),
        }
        let Ok(bloque) = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(0x0200_0000)
            .open(&vrai)
        else {
            return crate::essais::saute("ouvrir un dossier sans partage est impossible ici");
        };
        match tenir_le_programme(&vrai.join("vanguard.exe")) {
            Err(e @ Ecart::Inouvrable(_, Some(32))) => {
                let dit = e.dire();
                assert!(dit.contains("déjà ouvert") || dit.contains("already open"), "{dit}");
                assert!(!dit.contains("absent") && !dit.contains("missing"), "{dit}");
                assert!(e.conseil().contains("Fermez") || e.conseil().contains("Close"));
                assert_eq!(e.genre(), "non tenable, erreur 32");
            }
            autre => panic!("dossier bloqué mal dit : {:?}", autre.map(|_| ())),
        }
        drop(bloque);
    }

    /// Constat 5 : un dossier du nuage (OneDrive) est refusé pour ce qu'il est, pas comme « une jonction » ; une
    /// étiquette inconnue n'est pas dite jonction non plus.
    #[test]
    fn chaque_point_d_analyse_se_dit_pour_ce_qu_il_est() {
        let c = std::path::PathBuf::from(r"C:\Users\alice\OneDrive");
        for etiquette in [0x9000_001A, 0x9000_101A, 0x9000_F01A] {
            let e = Ecart::PointDAnalyse(c.clone(), etiquette);
            assert!(e.dire().contains("nuage") || e.dire().contains("cloud"), "{}", e.dire());
            assert!(!e.dire().contains("jonction") && !e.dire().contains("junction"));
            assert!(e.conseil().contains("hors du nuage") || e.conseil().contains("outside the cloud"));
        }
        let jonction = Ecart::PointDAnalyse(c.clone(), ETIQUETTE_JONCTION).dire();
        assert!(jonction.contains("jonction") || jonction.contains("junction"));
        let inconnue = Ecart::PointDAnalyse(c, 0x8000_0017).dire();
        assert!(!inconnue.contains("jonction") && !inconnue.contains("junction") && inconnue.contains("0x80000017"));
    }

    /// Constat 8 : « runas » prend sa commande dans la clé de la machine (SEE_MASK_CLASSKEY), jamais dans la vue
    /// fusionnée où une association posée sous HKCU\Software\Classes par un programme du compte passerait avant.
    #[test]
    fn runas_lit_la_classe_de_la_machine() {
        use winreg::enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER};
        let Ok(classe) = cle_des_programmes() else {
            return crate::essais::saute("pas de classe exefile sous HKLM ici");
        };
        let rien = [0u16];
        let info = info_de_lancement(&rien, &rien, &rien, &rien, &classe).unwrap();
        assert_eq!(info.masque & 0xF, 0x3, "SEE_MASK_CLASSKEY absent");
        assert_eq!(
            info.cle,
            classe.raw_handle().cast(),
            "la clé passée n'est pas celle de la machine"
        );
        assert!(info.classe.is_null());
        // Une sous-clé posée sous HKCU (dans le préfixe jetable de Wine seulement : jamais sur un vrai Windows) se
        // voit dans la vue fusionnée, pas dans la clé lue.
        if !crate::commande::sous_wine() {
            return crate::essais::saute("piège sous HKCU\\Software\\Classes posé sous Wine seulement");
        }
        let marque = crate::essais::nom_unique("vanguard-essai");
        let piege = format!(r"Software\Classes\exefile\{marque}");
        let compte = winreg::RegKey::predef(HKEY_CURRENT_USER);
        compte.create_subkey(&piege).unwrap();
        let fusion_le_voit = winreg::RegKey::predef(HKEY_CLASSES_ROOT)
            .open_subkey(format!(r"exefile\{marque}"))
            .is_ok();
        let machine_le_voit = cle_des_programmes().unwrap().open_subkey(&marque).is_ok();
        let _ = compte.delete_subkey_all(&piege);
        if !fusion_le_voit {
            return crate::essais::saute("Wine ne fusionne pas HKCU dans les classes : le piège ne prouverait rien");
        }
        assert!(!machine_le_voit, "la clé lue voit l'association du compte");
    }

    /// #22 : seul un chemin complet d'un disque, sans `..`, est relancé : un partage `\\serveur\…`, un chemin relatif
    /// ou une forme `\\?\` seraient relus autrement par le processus élevé (une lettre mappée vers le réseau est
    /// refusée plus loin, par sa poignée : `une_lettre_qui_mene_ailleurs_est_refusee`).
    #[test]
    fn chemin_hors_disque_refuse() {
        for c in [
            r"\\serveur\partage\vanguard.exe",
            r"vanguard.exe",
            r"C:vanguard.exe",
            r"\vanguard.exe",
            r"C:\Outils\..\vanguard.exe",
            r"\\?\C:\Outils\vanguard.exe",
            r"\\.\C:\Outils\vanguard.exe",
            r"C:\",
        ] {
            assert!(
                matches!(tenir_le_programme(std::path::Path::new(c)), Err(Ecart::PasUnDisque)),
                "{c}"
            );
        }
    }

    /// R8 : permettre un interpréteur ou un joker malgré l'accès contrôlé aux dossiers est large, comme une exclusion
    /// large ; un programme précis ne l'est pas.
    #[test]
    fn permettre_un_interpreteur_est_large() {
        let liste = |l: Option<String>| vec![Element::Acte(gestes::analyser_acte(&l.unwrap()).unwrap())];
        for p in [r"C:\Windows\System32\cmd.exe", r"C:\Outils\*"] {
            assert!(liste_large(&liste(gestes::ligne_autoriser_dossiers(p))), "{p}");
        }
        assert!(!liste_large(&liste(gestes::ligne_autoriser_dossiers(
            r"C:\Windows\System32\notepad.exe"
        ))));
        assert!(liste_large(&liste(gestes::ligne_ajout_exclusion(
            gestes::GenreExclusion::Chemin,
            "C:\\"
        ))));
    }

    /// D8 (W1, W2) : la remise du profil Public, d'un réseau en Privé ou d'un lancement suspect est jugée comme une
    /// baisse : seule ou avec d'autres baisses, une liste de baisses (la question [o/N]) ; mêlée à une correction
    /// ordinaire, refusée en entier. La remise durcie du profil Public reste une ligne ordinaire.
    #[test]
    fn les_remises_qui_baissent_sont_demandees_et_jamais_melees() {
        use gestes::{Categorie, ReglagePublic, ValeurPublic};
        let el = |l: &Option<String>| Element::Acte(gestes::analyser_acte(l.as_ref().unwrap()).unwrap());
        let compte: Result<String, String> = Err(String::new());
        let baisses = [
            gestes::ligne_pare_feu_public(&[(ReglagePublic::EntrantBloque, ValeurPublic::Non)]),
            gestes::ligne_pare_feu_public(&[(ReglagePublic::ReglesEntrantes, ValeurPublic::Oui)]),
            gestes::ligne_reseau_categorie("{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}", Categorie::Prive),
            gestes::ligne_demarrage_remettre(
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.lnk",
                None,
                false,
            ),
        ];
        let actif = Some(gestes::PARE_FEU_ACTIF.to_string());
        for b in &baisses {
            let (sens, baisse) = juger_liste(&[el(b)], &compte).expect("seule, une liste de baisses");
            assert!(baisse, "{b:?}");
            let Some(Some((m, texte))) = sens.first() else {
                panic!("{b:?} : aucun sens");
            };
            assert_eq!(m.sens, gestes::Sens::Baisse, "{b:?}");
            // La ligne de `montrer` : quatre colonnes, le texte, puis « (baisse la protection) ».
            let suite = crate::ui::largeur_affichee(tr!("  (baisse la protection)", "  (lowers protection)"));
            assert!(
                4 + crate::ui::largeur_affichee(texte) + suite <= crate::ui::LARGEUR,
                "{texte}"
            );
            assert!(juger_liste(&[el(&actif), el(b)], &compte).is_none(), "mêlée : {b:?}");
            assert!(juger_liste(&[el(b), el(&actif)], &compte).is_none(), "mêlée : {b:?}");
        }
        let toutes: Vec<Element> = baisses.iter().map(el).collect();
        assert!(juger_liste(&toutes, &compte).is_some_and(|(_, baisse)| baisse));
        let durcie = gestes::ligne_pare_feu_public(&[
            (ReglagePublic::EntrantBloque, ValeurPublic::Oui),
            (ReglagePublic::ReglesEntrantes, ValeurPublic::Non),
        ]);
        let (sens, baisse) = juger_liste(&[el(&durcie), el(&actif)], &compte).unwrap();
        assert!(!baisse && sens.iter().all(Option::is_none));
    }

    /// Ce qui reste actif après une baisse tient dans la largeur de l'écran, sous son retrait, pour chaque réglage des
    /// choix : coupé aux espaces, sans rien perdre.
    #[test]
    fn protege_encore_tient_dans_la_largeur() {
        let mut ids: Vec<gestes::IdChoix> = gestes::ReglageDefender::TOUS
            .iter()
            .map(|r| gestes::IdChoix::Defender(*r))
            .collect();
        ids.extend(gestes::ASR_TOUTES.iter().copied().map(gestes::IdChoix::Asr));
        let mut coupes = 0;
        for id in ids {
            let lignes = lignes_protege(id);
            assert!(!lignes.is_empty(), "{id:?}");
            for l in &lignes {
                assert!(
                    crate::ui::largeur_affichee(l).saturating_add(2) <= crate::ui::LARGEUR,
                    "{id:?} : {l:?}"
                );
            }
            assert_eq!(
                lignes.join(" "),
                crate::options_defense::protege_encore(id)
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            coupes += usize::from(lignes.len() > 1);
        }
        assert!(
            coupes > 0,
            "aucun texte assez long pour être coupé : l'essai ne vérifie plus rien"
        );
    }

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
    /// Un geste non fait parce que la personne s'est arrêtée (point refusé, puis tout ce qui suit ; accord refusé) part
    /// au parent comme « arrêté », dans les deux langues ; un vrai échec, jamais.
    #[test]
    fn l_arret_demande_part_au_parent() {
        let verifier = || {
            assert_eq!(ligne_resultat(&refusee()), ARRETEE);
            let (continuer, raison) = continuer_sans_point("protection coupée", |_| "n".into());
            let point = Resultat {
                reussi: continuer,
                rien: false,
                avant: None,
                raison,
            };
            assert_eq!(ligne_resultat(&point), ARRETEE);
            assert!(lire_reponse(ARRETEE).arretee && !lire_reponse(ARRETEE).reussi);
            let echec = Resultat {
                reussi: false,
                rien: false,
                avant: None,
                raison: "code=2".into(),
            };
            assert!(!lire_reponse(&ligne_resultat(&echec)).arretee);
            // chkdsk 3 : « disque à vérifier », ni arrêt ni échec ordinaire.
            let a_finir = Resultat {
                reussi: false,
                rien: false,
                avant: None,
                raison: format!("{} code=3", au_redemarrage()),
            };
            assert_eq!(ligne_resultat(&a_finir), AU_REDEMARRAGE);
            let r = lire_reponse(AU_REDEMARRAGE);
            assert!(r.au_redemarrage && !r.arretee && !r.reussi);
            assert!(!lire_reponse(&ligne_resultat(&echec)).au_redemarrage);
        };
        verifier();
        crate::langue::en_anglais(verifier);
    }

    /// Un échec se dit en phrase, avec quoi faire, le détail entre parenthèses : jamais « code=1 etats=101 » seul.
    #[test]
    fn un_echec_se_dit_en_phrase() {
        let script = valider(&[gestes::ligne_script(
            &"A".repeat(64),
            r"C:\Users\alice\AppData\Local\Vanguard\corrections\correction-1.ps1",
        )])
        .and_then(|mut v| v.pop())
        .expect("script accepté");
        let sfc = Element::Programme(gestes::analyser_programme("vanguard:programme sfc-scannow").expect("sfc"));
        let verifier = |anglais: bool| {
            let t = echec_lisible(&script, &gestes::raison_du_script(1, &[true, false, true]));
            assert!(!t.contains("code=") && !t.contains("etats="), "{t}");
            assert!(t.ends_with("(code 1, 101)"), "{t}");
            assert!(
                t.contains(if anglais { "just above" } else { "juste au-dessus" }),
                "{t}"
            );
            let t = echec_lisible(
                &script,
                &format!("code={} script modifié", super::super::SCRIPT_MODIFIE),
            );
            assert!(
                t.contains(if anglais { "antivirus scan" } else { "analyse antivirus" }) && t.ends_with("(code 6)")
            );
            let t = echec_lisible(&sfc, "code=2");
            assert!(t.starts_with("sfc.exe ") && t.ends_with("(code 2)"), "{t}");
            assert!(
                t.contains(if anglais {
                    "Restart the computer"
                } else {
                    "Redémarrez l'ordinateur"
                }),
                "{t}"
            );
            // Une raison déjà en mots passe telle quelle.
            assert_eq!(
                echec_lisible(&sfc, "sfc.exe ne s'est pas lancé"),
                "sfc.exe ne s'est pas lancé"
            );
        };
        verifier(false);
        crate::langue::en_anglais(|| verifier(true));
    }

    #[test]
    fn un_script_change_est_refuse_avant_l_accord() {
        let d = crate::essais::temporaire().join(format!("vanguard-montrer-{}", std::process::id()));
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
        let change = script(bonne.clone());
        assert!(
            a_montrer(&change)
                .unwrap_err()
                .to_string()
                .contains(&chemin.display().to_string())
        );
        // Disparu : refusé aussi (avant, la liste était montrée sans le script, puis l'Entrée demandée).
        std::fs::remove_file(&chemin).unwrap();
        assert!(a_montrer(&script(bonne)).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Ce que le fils lance part de System32, avec l'environnement réduit seulement : un programme fixe comme le script.
    #[test]
    fn le_fils_lance_depuis_system32_sans_l_environnement_du_compte() {
        let systeme = crate::commande::dossier_systeme();
        let script = super::super::powershell_eleve();
        let a = gestes::analyser_programme(&gestes::ligne_programme("sfc-scannow", None)).unwrap();
        let programme = commande_du_programme(&a).unwrap();
        for c in [&script, &programme] {
            assert_eq!(c.get_current_dir(), Some(systeme), "{c:?}");
            let modules = c.get_envs().find(|(n, _)| *n == "PSModulePath").and_then(|(_, v)| v);
            assert!(
                modules.is_some_and(|m| !m.to_string_lossy().contains("Documents")),
                "{c:?}"
            );
            assert!(c.get_envs().all(|(n, _)| n != "COR_PROFILER" && n != "Path"), "{c:?}");
        }
        assert_eq!(programme.get_program(), systeme.join("sfc.exe").as_os_str());
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
            rien: false,
            avant: None,
            raison: sans_point_accepte().into(),
        };
        let r = lire_reponse(&ligne_resultat(&sans_point));
        assert!(r.reussi && r.avant.is_none() && r.note.as_deref() == Some(sans_point_accepte()));
        assert!(lire_reponse("ok").note.is_none());
        assert!(!lire_reponse("").reussi);
        let aller_retour = ligne_resultat(&Resultat {
            reussi: false,
            rien: false,
            avant: Some("1".into()),
            raison: "a\r\nb".into(),
        });
        assert_eq!(aller_retour, "echec avant=1");
        let r = lire_reponse(&aller_retour);
        assert!(!r.reussi && r.avant.as_deref() == Some("1") && !r.arretee && r.code.is_none());
        let sans_avant = ligne_resultat(&Resultat::echec(None, "a\r\nb".into()));
        assert_eq!(sans_avant, "echec a  b");
        assert!(lire_reponse(&sans_avant).avant.is_none());
        // Déjà bon, rien d'écrit : réussi, dit rien (le parent ne le note pas parmi ce que Vanguard a changé).
        let deja = ligne_resultat(&Resultat::rien("déjà 1,\nrien d'écrit".into()));
        assert_eq!(deja, "ok rien=déjà 1, rien d'écrit");
        let r = lire_reponse(&deja);
        assert!(r.reussi && r.rien && r.avant.is_none() && r.note.as_deref() == Some("déjà 1, rien d'écrit"));
        assert!(!lire_reponse("ok note=déjà retirée").rien);
        assert!(!lire_reponse("ok avant=1").rien);
        let r = lire_reponse("echec code=1 etats=101");
        assert!(!r.reussi && r.code == Some(1) && r.etats == Some(vec![true, false, true]));
        assert!(lire_reponse("echec code=1").etats.is_none());
    }

    /// Une baisse faite part au parent avec sa valeur d'avant et « note=choix » ; une note impossible part en
    /// « echec note », sans valeur d'avant (rien n'a été écrit). Une autre valeur d'avant qui finirait par le même mot
    /// reste entière.
    #[test]
    fn une_baisse_notee_se_lit() {
        let faite = Resultat {
            reussi: true,
            rien: false,
            avant: Some("defender-pua=1".into()),
            raison: corrections::NOTE_CHOIX.into(),
        };
        let l = ligne_resultat(&faite);
        assert_eq!(l, "ok avant=defender-pua=1 note=choix");
        let r = lire_reponse(&l);
        assert!(r.reussi && !r.rien && r.avant.as_deref() == Some("defender-pua=1"));
        assert_eq!(r.note.as_deref(), Some(corrections::NOTE_CHOIX));
        let asr = "ok avant=asr-56a863a9-875e-4185-98a7-b882c64b5ce5=absente note=choix";
        assert_eq!(
            lire_reponse(asr).avant.as_deref(),
            Some("asr-56a863a9-875e-4185-98a7-b882c64b5ce5=absente")
        );
        // Pas l'identifiant d'un choix, ou valeur qui n'est pas un nombre écrit par Vanguard : pris tel quel.
        for autre in [
            "ok avant=1 note=choix",
            "ok avant=defender-inconnu=1 note=choix",
            "ok avant=defender-pua=+1 note=choix",
        ] {
            let r = lire_reponse(autre);
            assert_eq!(r.avant.as_deref(), autre.strip_prefix("ok avant="), "{autre}");
            assert!(r.note.is_none(), "{autre}");
        }
        let note = ligne_resultat(&Resultat::echec(None, corrections::echec_note().into()));
        assert_eq!(note, ECHEC_NOTE);
        let r = lire_reponse(&note);
        assert!(!r.reussi && r.avant.is_none() && !r.arretee && r.note.is_none());
        // Relecture D8 (N1) : la raison gardée (la borne des notes et son remède) reste dans la console du fils.
        // Contre-relecture (C2) : le parent la reçoit aussi, par une ligne fixe, et note le remède dans sa langue à
        // côté de la ligne en échec ; une autre note manquée reste « echec note », sans note.
        let pleine = crate::modele::Echec::refuse("essai", crate::machine::choix_avant::trop_de_notes());
        let raison = corrections::echec_note_de(Some(&pleine));
        assert!(
            raison.starts_with(corrections::echec_note()) && raison.contains("Rallumer"),
            "{raison}"
        );
        let trop = ligne_resultat(&Resultat::echec(None, raison));
        assert_eq!(trop, ECHEC_NOTE_TROP);
        let r = lire_reponse(&trop);
        assert!(!r.reussi && r.avant.is_none() && !r.arretee && !r.au_redemarrage);
        assert_eq!(r.note.as_deref(), Some(crate::machine::choix_avant::trop_de_notes()));
        let autre = corrections::echec_note_de(Some(&crate::modele::Echec::refuse("essai", "disque plein")));
        assert_eq!(ligne_resultat(&Resultat::echec(None, autre)), ECHEC_NOTE);
    }

    /// Le tube porte au plus deux listes séparées par « suite » (P7), chacune validée comme une liste seule ; une
    /// liste vide, une troisième ou « suite » seule sont refusées, et « suite » n'est jamais une ligne d'une liste.
    #[test]
    fn les_listes_du_tube() {
        use gestes::{ChoixDefender, IdChoix, ReglageDefender, SUITE};
        let l = |s: &str| s.to_string();
        let baisse = gestes::ligne_baisse_defender(ReglageDefender::Pua, ChoixDefender::Coupe).unwrap();
        let rallumer = gestes::ligne_rallumer(IdChoix::Defender(ReglageDefender::Pua));
        assert!(valider(&[l(SUITE)]).is_none());
        let deux = [l("vanguard:rdp-nla"), rallumer.clone(), l(SUITE), baisse.clone()];
        let listes = valider_listes(&deux).expect("deux listes");
        assert_eq!(listes.iter().map(Vec::len).collect::<Vec<_>>(), [2, 1]);
        assert_eq!(valider_listes(&[l("vanguard:rdp-nla")]).map(|v| v.len()), Some(1));
        for refusee in [
            vec![l(SUITE)],
            vec![l(SUITE), baisse.clone()],
            vec![baisse.clone(), l(SUITE)],
            vec![l("vanguard:rdp-nla"), l(SUITE), l(SUITE), baisse.clone()],
            vec![
                l("vanguard:rdp-nla"),
                l(SUITE),
                rallumer.clone(),
                l(SUITE),
                baisse.clone(),
            ],
            vec![l("vanguard:rdp-nla"), l(SUITE), l("vanguard:inconnu")],
        ] {
            assert!(valider_listes(&refusee).is_none(), "{refusee:?}");
        }
        // Le parent envoie les choix à part, et remet les réponses à leur place d'origine.
        let lignes = [baisse.clone(), l("vanguard:rdp-nla"), rallumer];
        let (envoi, ordre) = gestes::joindre_listes(&lignes, &gestes::separer_choix(&lignes));
        assert_eq!(envoi, [l("vanguard:rdp-nla"), lignes[2].clone(), l(SUITE), baisse]);
        assert_eq!(ordre, [1, 2, 0]);
        assert_eq!(
            gestes::remettre_en_ordre(&ordre, vec!["b", "c", "a"]),
            Some(vec!["a", "b", "c"])
        );
        assert_eq!(gestes::remettre_en_ordre(&ordre, vec!["b", "c"]), None);
        assert_eq!(gestes::remettre_en_ordre(&[0, 0], vec!["a", "b"]), None);
        assert_eq!(gestes::remettre_en_ordre(&[0, 5], vec!["a", "b"]), None);
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

    /// WMI sans réponse (Windows Server, Windows allégés), point sauté ou refusé : la même question pour tous : la raison est dite, puis « o » continue sans point (noté), tout le reste arrête.
    #[test]
    fn sans_point_la_question_est_posee() {
        for raison in [
            "Windows n'a pas répondu à temps (WMI SystemRestore, 5 min)",
            "Windows l'a sauté : il n'en fait qu'un par 24 h, et le dernier a 3 h",
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

    /// Seul un numéro neuf dans la liste compte : la règle des 24 h répond « succès » sans point (VM, 1er nov.), et
    /// une liste illisible n'est jamais un point vérifié.
    #[test]
    fn le_point_n_est_ok_que_s_il_est_dans_la_liste() {
        use crate::machine::windows::wmi::Retour::{Refuse, SansReponse, Valeur};
        let p = |sequence, age| Point {
            sequence,
            age: Some(age),
        };
        let avant = [p(25, 90_000), p(26, 3 * 3600)];
        assert_eq!(
            juger_le_point(Some(&avant), Valeur(0), Some(&[avant[0], avant[1], p(27, 5)])),
            Ok(())
        );
        assert_eq!(juger_le_point(Some(&[]), Valeur(0), Some(&[p(1, 5)])), Ok(()));
        let raison = |retour, apres: Option<&[Point]>| {
            juger_le_point(Some(&avant), retour, apres)
                .expect_err("pas de point neuf = échec")
                .to_string()
        };
        let sautee = raison(Valeur(0), Some(&avant));
        assert!(sautee.contains("24 h") && sautee.contains("3 h"), "{sautee}");
        let perdu = raison(Valeur(0), Some(&[p(25, 90_000)]));
        assert!(!perdu.contains("24 h"), "{perdu}");
        assert!(raison(Valeur(1058), Some(&avant)).contains("1058"));
        let delai = raison(SansReponse, None);
        let refus = raison(Refuse(0x8004_2302_u32.cast_signed()), None);
        let absent = raison(Refuse(crate::machine::windows::wmi::CLASSE_ABSENTE[1]), None);
        assert!(refus.contains("0x80042302"), "{refus}");
        assert!(!delai.contains("0x") && !absent.contains("0x"), "{delai} / {absent}");
        assert!(delai != refus && refus != absent && delai != absent);
        let illisible = raison(Valeur(0), None);
        assert!(juger_le_point(None, Valeur(0), Some(&[p(27, 5)])).is_err());
        // Accepté sans code de retour lisible (`wmi::Retour::Accepte`) : la liste seule le dit, dans les deux sens.
        let sans_retour = crate::machine::windows::wmi::Retour::Accepte;
        assert_eq!(
            juger_le_point(Some(&avant), sans_retour, Some(&[avant[0], avant[1], p(27, 5)])),
            Ok(())
        );
        assert!(raison(sans_retour, Some(&avant)).contains("24 h"));
        assert!(raison(sans_retour, None).contains("illisible") || raison(sans_retour, None).contains("unreadable"));
        assert!(
            [sautee.as_str(), perdu.as_str(), illisible.as_str()]
                .iter()
                .all(|r| !r.is_empty())
        );
        assert_ne!(sautee, perdu);
        assert_ne!(perdu, illisible);
        assert_eq!(duree(2400), "40 min");
        assert_eq!(duree(3 * 3600 + 59), "3 h");
    }

    #[test]
    fn les_structures_ont_la_taille_de_windows() {
        assert_eq!(std::mem::size_of::<InfoLancement>(), 112);
        assert_eq!(std::mem::size_of::<Securite>(), 24);
    }
}
