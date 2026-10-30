//! Les processus de Windows, lus et arrêtés par ses fonctions (Toolhelp32, OpenProcess) au lieu de tasklist, taskkill
//! et whoami : rien à lancer, quelques millisecondes, et des noms qui ne dépendent pas de la langue de la console.

use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(drapeaux: u32, processus: u32) -> *mut c_void;
    fn Process32FirstW(instantane: *mut c_void, entree: *mut Entree) -> i32;
    fn Process32NextW(instantane: *mut c_void, entree: *mut Entree) -> i32;
    fn OpenProcess(acces: u32, heriter: i32, processus: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(processus: *mut c_void, drapeaux: u32, nom: *mut u16, taille: *mut u32) -> i32;
    fn TerminateProcess(processus: *mut c_void, code: u32) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(objet: *mut c_void) -> i32;
    /// Partagé avec `comptes` : une seule déclaration de chaque import.
    pub(super) fn LocalFree(memoire: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(processus: *mut c_void, acces: u32, jeton: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        jeton: *mut c_void,
        classe: u32,
        information: *mut c_void,
        taille: u32,
        rendue: *mut u32,
    ) -> i32;
    pub(super) fn ConvertSidToStringSidW(sid: *mut c_void, texte: *mut *mut u16) -> i32;
}

/// PROCESSENTRY32W (tlhelp32.h).
#[repr(C)]
struct Entree {
    taille: u32,
    utilisations: u32,
    processus: u32,
    tas: usize,
    module: u32,
    fils: u32,
    parent: u32,
    priorite: i32,
    drapeaux: u32,
    fichier: [u16; 260],
}

/// Un processus : son numéro, celui de son parent, et son nom tel que tasklist et Get-Process le montraient.
pub(crate) struct Processus {
    pub pid: u32,
    pub parent: u32,
    pub nom: String,
}

/// Le nom d'un programme tel que Windows le donne (« firefox.exe ») : sans « .exe », quelle que soit sa casse, et prêt
/// à montrer (n'importe quel programme choisit le nom de son fichier). Le processus 0 est « Idle », comme dans tasklist.
pub(crate) fn nom_du_fichier(pid: u32, fichier: &[u16]) -> String {
    if pid == 0 {
        return "Idle".into();
    }
    // Jusqu'au premier zéro, ou tout le tampon s'il n'y en a pas.
    let nom = String::from_utf16_lossy(fichier.split(|&c| c == 0).next().unwrap_or(fichier));
    let court = match nom.len().checked_sub(4) {
        Some(i) if nom.get(i..).is_some_and(|e| e.eq_ignore_ascii_case(".exe")) => &nom[..i],
        _ => &nom,
    };
    crate::ui::affichable(court)
}

/// Tous les processus, lus sans droits d'administrateur (comme le Gestionnaire des tâches). Vide si Windows refuse.
pub(crate) fn liste() -> Vec<Processus> {
    const INSTANTANE_PROCESSUS: u32 = 2;
    let mut liste = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot rend un instantané (ou INVALID_HANDLE_VALUE, -1, vérifié), refermé une seule
    // fois plus bas. `entree` est une PROCESSENTRY32W dont le champ de taille est rempli, comme Windows l'exige ; il la
    // remplit à chaque appel, sans rien garder.
    unsafe {
        let instantane = CreateToolhelp32Snapshot(INSTANTANE_PROCESSUS, 0);
        if instantane as isize == -1 {
            return liste;
        }
        let mut entree: Entree = std::mem::zeroed();
        entree.taille = u32::try_from(std::mem::size_of::<Entree>()).unwrap_or(0);
        let mut suivant = Process32FirstW(instantane, &raw mut entree) != 0;
        while suivant {
            liste.push(Processus {
                pid: entree.processus,
                parent: entree.parent,
                nom: nom_du_fichier(entree.processus, &entree.fichier),
            });
            suivant = Process32NextW(instantane, &raw mut entree) != 0;
        }
        CloseHandle(instantane);
    }
    liste
}

/// Le chemin complet du programme d'un processus. Les droits « limités » suffisent pour la plupart, même d'un autre
/// compte ; un processus protégé (System, antivirus) refuse : `None`.
pub(crate) fn chemin(processus: u32) -> Option<String> {
    const INFORMATION_LIMITEE: u32 = 0x1000;
    let mut tampon = vec![0u16; 32_768];
    let mut taille = u32::try_from(tampon.len()).ok()?;
    // SAFETY: la poignée vient d'OpenProcess (nulle : refus, vérifié) et n'est refermée qu'une fois.
    // QueryFullProcessImageNameW écrit au plus `taille` caractères dans `tampon`, puis le nombre écrit dans `taille`.
    unsafe {
        let poignee = OpenProcess(INFORMATION_LIMITEE, 0, processus);
        if poignee.is_null() {
            return None;
        }
        let lu = QueryFullProcessImageNameW(poignee, 0, tampon.as_mut_ptr(), &raw mut taille) != 0;
        CloseHandle(poignee);
        // Les `taille` caractères écrits, jamais au-delà du tampon.
        lu.then(|| String::from_utf16_lossy(tampon.get(..usize::try_from(taille).unwrap_or(0)).unwrap_or(&tampon)))
    }
}

/// Arrête un processus tout de suite (comme taskkill /f). Réservé à ce que la personne a accepté, ou aux commandes
/// que Vanguard a lui-même lancées. `false` : refusé ou déjà fini.
pub(crate) fn terminer(processus: u32) -> bool {
    const ARRET: u32 = 0x0001;
    // SAFETY: la poignée vient d'OpenProcess (nulle : refus, vérifié) et n'est refermée qu'une fois.
    unsafe {
        let poignee = OpenProcess(ARRET, 0, processus);
        if poignee.is_null() {
            return false;
        }
        let arrete = TerminateProcess(poignee, 1) != 0;
        CloseHandle(poignee);
        arrete
    }
}

/// Le tampon d'une information du jeton, pour les `rendue` octets annoncés par Windows : des u64 (alignés sur 8 pour
/// les structures), et la longueur à lui donner, qui reste `rendue`. Une classe de taille fixe refuse un tampon plus
/// grand (TokenElevation, 4 octets : ERROR_BAD_LENGTH avec 8, vu en administrateur dans la VM) ; Wine l'accepte.
fn tampon_du_jeton(rendue: u32) -> (Vec<u64>, u32) {
    (
        vec![0u64; usize::try_from(rendue.div_ceil(8)).unwrap_or(0).max(1)],
        rendue,
    )
}

/// Arrête un processus seulement s'il fait encore tourner le programme `attendu` (casse ignorée) : le chemin est lu
/// par la poignée même qui arrête, le numéro ne peut pas passer à un autre programme entre les deux. `false` : refusé,
/// déjà fini, ou un autre programme.
pub(crate) fn terminer_si(processus: u32, attendu: &str) -> bool {
    const ARRET_ET_LECTURE: u32 = 0x0001 | 0x1000;
    let mut tampon = vec![0u16; 32_768];
    let mut taille = u32::try_from(tampon.len()).unwrap_or(0);
    // SAFETY: la poignée vient d'OpenProcess (nulle : refus, vérifié) et n'est refermée qu'une fois.
    // QueryFullProcessImageNameW écrit au plus `taille` caractères dans `tampon`, puis le nombre écrit dans `taille`.
    unsafe {
        let poignee = OpenProcess(ARRET_ET_LECTURE, 0, processus);
        if poignee.is_null() {
            return false;
        }
        let lu = QueryFullProcessImageNameW(poignee, 0, tampon.as_mut_ptr(), &raw mut taille) != 0;
        // Les `taille` caractères écrits, jamais au-delà du tampon.
        let chemin = String::from_utf16_lossy(tampon.get(..usize::try_from(taille).unwrap_or(0)).unwrap_or(&tampon));
        let arrete = lu && chemin.eq_ignore_ascii_case(attendu) && TerminateProcess(poignee, 1) != 0;
        CloseHandle(poignee);
        arrete
    }
}

/// Ce compte a-t-il le droit d'arrêter ce processus ? La poignée d'arrêt est demandée puis refermée aussitôt, sans
/// rien arrêter : le blocage le sait avant de commencer, pour ne rien faire à moitié.
pub(crate) fn peut_terminer(processus: u32) -> bool {
    const ARRET: u32 = 0x0001;
    // SAFETY: la poignée vient d'OpenProcess (nulle : refus, vérifié) et n'est refermée qu'une fois.
    unsafe {
        let poignee = OpenProcess(ARRET, 0, processus);
        if poignee.is_null() {
            return false;
        }
        CloseHandle(poignee);
        true
    }
}

/// Une information du jeton de ce processus (GetTokenInformation), dans un tampon aligné ; `None` si Windows refuse.
fn jeton(classe: u32) -> Option<Vec<u64>> {
    const LECTURE: u32 = 0x0008;
    let mut poignee = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess rend une pseudo-poignée, sans rien à fermer. Le jeton ouvert (vérifié) est fermé une
    // seule fois. Le premier appel donne la taille ; le second écrit au plus `place` octets (la taille annoncée) dans
    // `tampon`, qui en a au moins autant, aligné sur 8 octets pour les structures qu'il contient.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), LECTURE, &raw mut poignee) == 0 {
            return None;
        }
        let mut taille = 0u32;
        GetTokenInformation(poignee, classe, std::ptr::null_mut(), 0, &raw mut taille);
        let (mut tampon, place) = tampon_du_jeton(taille);
        let lu = GetTokenInformation(poignee, classe, tampon.as_mut_ptr().cast(), place, &raw mut taille) != 0;
        CloseHandle(poignee);
        lu.then_some(tampon)
    }
}

/// Lancé en administrateur (jeton élevé) ? Un compte administrateur sans élévation (UAC) répond non : il ne lit pas le
/// journal Security, ni root/subscription.
pub(crate) fn eleve() -> bool {
    const ELEVATION: u32 = 20;
    jeton(ELEVATION).is_some_and(|t| t.first().is_some_and(|&m| m & 0xFFFF_FFFF != 0))
}

/// Comme `eleve`, mais un jeton illisible compte pour élevé : pour un garde-fou, qui doit échouer fermé (les
/// extensions ne tournent jamais en administrateur sans qu'on le demande).
pub(crate) fn eleve_ou_inconnu() -> bool {
    const ELEVATION: u32 = 20;
    jeton(ELEVATION).is_none_or(|t| t.first().is_none_or(|&m| m & 0xFFFF_FFFF != 0))
}

/// Le type d'élévation du jeton (TokenElevationType) : 1, aucun jeton séparé (UAC coupé, compte Administrateur
/// intégré : ce compte n'a pas de jeton ordinaire) ; 2, le jeton élevé d'une session qui a aussi un jeton ordinaire ;
/// 3, ce jeton ordinaire. `None` si Windows refuse.
pub(crate) fn type_d_elevation() -> Option<u32> {
    const TYPE_D_ELEVATION: u32 = 18;
    jeton(TYPE_D_ELEVATION).and_then(|t| t.first().and_then(|&m| u32::try_from(m & 0xFFFF_FFFF).ok()))
}

/// Le SID du compte de ce processus (« S-1-5-21-… »), comme « whoami /user » le donne. Seulement des chiffres et des
/// tirets après « S-1- » : il entre tel quel dans une commande PowerShell.
pub(crate) fn sid() -> Option<String> {
    const UTILISATEUR: u32 = 1;
    let tampon = jeton(UTILISATEUR)?;
    let mut texte: *mut u16 = std::ptr::null_mut();
    // SAFETY: TOKEN_USER commence par un SID_AND_ATTRIBUTES, dont le premier champ est le pointeur vers le SID, dans le
    // même tampon (vivant pendant l'appel). ConvertSidToStringSidW alloue la chaîne (terminée par un zéro), lue puis
    // rendue une seule fois par LocalFree.
    let sid = unsafe {
        let pointeur = tampon.as_ptr().cast::<*mut c_void>().read();
        if pointeur.is_null() || ConvertSidToStringSidW(pointeur, &raw mut texte) == 0 || texte.is_null() {
            return None;
        }
        let mut fin = 0;
        while fin < 256 && *texte.add(fin) != 0 {
            fin += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(texte, fin));
        LocalFree(texte.cast());
        sid
    };
    sid_valide(&sid).then_some(sid)
}

/// Le compte d'un processus (« DOMAINE\\nom »), lu dans son jeton, comme Get-Process -IncludeUserName ; vide si son
/// jeton ne s'ouvre pas (processus d'un autre compte sans droits administrateur, processus protégé).
pub(crate) fn compte_de(pid: u32) -> String {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};
    // SAFETY: chaque poignée ouverte est fermée une fois ; le tampon du jeton est aligné (u64) et sa taille rendue
    // par Windows est vérifiée AVANT d'y lire le TOKEN_USER ; les tampons des noms ont la taille annoncée à Windows.
    unsafe {
        let Ok(processus) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return String::new();
        };
        let mut jeton = HANDLE::default();
        let ouvert = OpenProcessToken(processus, TOKEN_QUERY, &raw mut jeton).is_ok();
        let _ = CloseHandle(processus);
        if !ouvert {
            return String::new();
        }
        let mut tampon = [0u64; 64];
        let mut taille = 0u32;
        let lu = GetTokenInformation(
            jeton,
            TokenUser,
            Some(tampon.as_mut_ptr().cast()),
            u32::try_from(size_of_val(&tampon)).unwrap_or(0),
            &raw mut taille,
        )
        .is_ok();
        let _ = CloseHandle(jeton);
        if !lu || (taille as usize) < size_of::<TOKEN_USER>() {
            return String::new();
        }
        let sid = tampon.as_ptr().cast::<TOKEN_USER>().read().User.Sid;
        let (mut nom, mut domaine) = ([0u16; 256], [0u16; 256]);
        let (mut n, mut d) = (256u32, 256u32);
        let mut sorte = SID_NAME_USE::default();
        if LookupAccountSidW(
            None,
            sid,
            Some(windows::core::PWSTR(nom.as_mut_ptr())),
            &raw mut n,
            Some(windows::core::PWSTR(domaine.as_mut_ptr())),
            &raw mut d,
            &raw mut sorte,
        )
        .is_err()
        {
            return String::new();
        }
        // Les `longueur` caractères rendus, jamais au-delà du tampon.
        let texte = |t: &[u16], longueur: u32| String::from_utf16_lossy(t.get(..longueur as usize).unwrap_or(t));

        let (nom, domaine) = (texte(&nom, n), texte(&domaine, d));
        if domaine.is_empty() {
            nom
        } else {
            format!("{domaine}\\{nom}")
        }
    }
}

fn sid_valide(sid: &str) -> bool {
    sid.strip_prefix("S-1-")
        .is_some_and(|c| !c.is_empty() && c.chars().all(|c| c.is_ascii_digit() || c == '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le compte de ce processus se lit dans son jeton (sous Wine aussi) ; un numéro qui n'existe pas : vide.
    #[test]
    fn compte_d_un_processus() {
        assert_ne!(compte_de(std::process::id()), "");
        assert_eq!(compte_de(u32::MAX - 3), "");
    }

    #[test]
    fn noms_des_fichiers() {
        let f = |n: &str| n.encode_utf16().chain([0, 0x41]).collect::<Vec<u16>>();
        assert_eq!(nom_du_fichier(4242, &f("firefox.exe")), "firefox");
        assert_eq!(nom_du_fichier(5, &f("SVCHOST.EXE")), "SVCHOST");
        assert_eq!(nom_du_fichier(4, &f("System")), "System");
        assert_eq!(nom_du_fichier(0, &f("[System Process]")), "Idle");
        assert_eq!(nom_du_fichier(7, &f("a.exe.exe")), "a.exe");
        // Un nom piégé ne pilote pas le terminal.
        assert_eq!(
            nom_du_fichier(8, &f("fire\x1b]0;x\x07fox.exe")),
            "fire\u{fffd}]0;x\u{fffd}fox"
        );
    }

    /// La longueur donnée à Windows est celle qu'il a annoncée, jamais le tampon arrondi à 8 : avec 8 octets pour les 4
    /// de TokenElevation, Windows refusait, et Vanguard en administrateur se croyait sans droits (corrections natives
    /// jamais faites, « relance en administrateur » dit à qui l'était déjà).
    #[test]
    fn jeton_lu_avec_la_taille_annoncee() {
        const ELEVATION: u32 = 20;
        for rendue in [4, 8, 12, 44] {
            let (tampon, longueur) = tampon_du_jeton(rendue);
            assert_eq!(longueur, rendue);
            assert!(tampon.len() * 8 >= usize::try_from(rendue).unwrap());
        }
        assert_eq!(tampon_du_jeton(0), (vec![0], 0));
        assert!(
            jeton(ELEVATION).is_some(),
            "TokenElevation illisible avec sa taille exacte"
        );
    }

    #[test]
    fn sid_verifie() {
        assert!(sid_valide("S-1-5-21-1004336348-1177238915-682003330-1001"));
        assert!(!sid_valide("S-1-5-21'; Remove-Item C:\\"));
        assert!(!sid_valide("S-1-"));
        assert!(!sid_valide(""));
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : ce processus se trouve, avec son parent et son
    /// chemin ; un numéro qui n'existe pas ne s'arrête pas.
    #[test]
    fn processus_lus_par_windows() {
        let moi = std::process::id();
        let liste = liste();
        assert!(liste.iter().any(|p| p.pid == moi && !p.nom.is_empty()));
        assert!(chemin(moi).is_some_and(|c| c.to_lowercase().ends_with(".exe")));
        assert!(!terminer(u32::MAX - 3));
        let _ = eleve();
        assert!(sid().is_none_or(|s| sid_valide(&s)));
    }
}
