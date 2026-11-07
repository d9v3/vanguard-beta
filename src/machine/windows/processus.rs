//! Les processus de Windows, lus et arrêtés par ses fonctions (Toolhelp32, OpenProcess) au lieu de tasklist, taskkill
//! et whoami : rien à lancer, quelques millisecondes, et des noms qui ne dépendent pas de la langue de la console.

// FFI de kernel32 et advapi32 : processus et jetons (CreateToolhelp32Snapshot, OpenProcessToken…).
#![allow(unsafe_code)]

use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(drapeaux: u32, processus: u32) -> *mut c_void;
    fn Process32FirstW(instantane: *mut c_void, entree: *mut Entree) -> i32;
    fn Process32NextW(instantane: *mut c_void, entree: *mut Entree) -> i32;
    fn OpenProcess(acces: u32, heriter: i32, processus: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(processus: *mut c_void, drapeaux: u32, nom: *mut u16, taille: *mut u32) -> i32;
    fn TerminateProcess(processus: *mut c_void, code: u32) -> i32;
    fn GetProcessTimes(
        processus: *mut c_void,
        creation: *mut [u32; 2],
        fin: *mut [u32; 2],
        noyau: *mut [u32; 2],
        utilisateur: *mut [u32; 2],
    ) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn CloseHandle(objet: *mut c_void) -> i32;
    fn Thread32First(instantane: *mut c_void, entree: *mut EntreeFil) -> i32;
    fn Thread32Next(instantane: *mut c_void, entree: *mut EntreeFil) -> i32;
    fn OpenThread(acces: u32, heriter: i32, fil: u32) -> *mut c_void;
    fn SuspendThread(fil: *mut c_void) -> u32;
    fn ResumeThread(fil: *mut c_void) -> u32;
    fn GetProcessIdOfThread(fil: *mut c_void) -> u32;
    /// Partagé avec `comptes` : une seule déclaration de chaque import.
    pub(super) fn LocalFree(memoire: *mut c_void) -> *mut c_void;
}

// Suspendre et reprendre tous les fils d'un processus d'un seul appel : non documentées, mais stables depuis Windows XP
// et utilisées par le Gestionnaire des tâches (« Suspendre ») comme par Process Explorer.
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtSuspendProcess(processus: *mut c_void) -> i32;
    fn NtResumeProcess(processus: *mut c_void) -> i32;
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

/// THREADENTRY32 (tlhelp32.h).
#[repr(C)]
struct EntreeFil {
    taille: u32,
    utilisations: u32,
    fil: u32,
    processus: u32,
    priorite: i32,
    delta: i32,
    drapeaux: u32,
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
    Tenu::ouvrir(processus).ok()?.chemin()
}

/// L'heure de création d'un processus (FILETIME, en centaines de nanosecondes) : avec le numéro, elle distingue un
/// processus d'un autre venu sur le même numéro. `None` : Windows refuse (processus fini, protégé, d'un autre compte).
pub(crate) fn creation(processus: u32) -> Option<u64> {
    Tenu::ouvrir(processus).ok()?.creation()
}

/// Un processus tenu par une poignée de lecture limitée (PROCESS_QUERY_LIMITED_INFORMATION) : tant qu'elle vit,
/// Windows ne redonne pas son numéro à un autre processus, et ce qui est lu par elle (programme, compte) est celui de
/// ce processus-là, même s'il a fini entre-temps. Le processus élevé tient ainsi le Vanguard qui l'a lancé.
pub(crate) struct Tenu(*mut c_void);

impl Tenu {
    /// Ouvre le processus `pid` ; l'erreur de Windows s'il refuse (processus fini, protégé).
    pub(crate) fn ouvrir(pid: u32) -> std::io::Result<Tenu> {
        const INFORMATION_LIMITEE: u32 = 0x1000;
        Tenu::ouvrir_avec(pid, INFORMATION_LIMITEE)
    }

    /// Ouvre le processus `pid` avec les droits `acces` (qui doivent comprendre la lecture limitée, 0x1000, pour lire
    /// son chemin et son heure de création).
    // FFI : OpenProcess, la poignée gardée par la valeur rendue.
    #[allow(unsafe_code)]
    fn ouvrir_avec(pid: u32, acces: u32) -> std::io::Result<Tenu> {
        // SAFETY: OpenProcess ne lit rien de notre mémoire ; une poignée nulle (refus) n'est jamais gardée, une autre
        // l'est par `Tenu`, qui la referme une seule fois (Drop).
        let poignee = unsafe { OpenProcess(acces, 0, pid) };
        if poignee.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Tenu(poignee))
        }
    }

    /// Son heure de création, lue par la poignée ; `None` si Windows refuse.
    // FFI : GetProcessTimes sur la poignée tenue.
    #[allow(unsafe_code)]
    pub(crate) fn creation(&self) -> Option<u64> {
        let (mut creation, mut fin, mut noyau, mut utilisateur) = ([0u32; 2], [0u32; 2], [0u32; 2], [0u32; 2]);
        // SAFETY: la poignée est ouverte tant que `self` vit ; GetProcessTimes écrit une FILETIME (deux u32, poids
        // faible d'abord) dans chacun des quatre tableaux, à nous et vivants pendant l'appel.
        let lu = unsafe {
            GetProcessTimes(
                self.0,
                &raw mut creation,
                &raw mut fin,
                &raw mut noyau,
                &raw mut utilisateur,
            )
        } != 0;
        (lu && creation != [0, 0]).then(|| (u64::from(creation[1]) << 32) | u64::from(creation[0]))
    }

    /// Le chemin complet de son programme, lu par la poignée ; `None` si Windows refuse.
    // FFI : QueryFullProcessImageNameW sur la poignée tenue.
    #[allow(unsafe_code)]
    pub(crate) fn chemin(&self) -> Option<String> {
        let mut tampon = vec![0u16; 32_768];
        let mut taille = u32::try_from(tampon.len()).ok()?;
        // SAFETY: la poignée est ouverte tant que `self` vit. QueryFullProcessImageNameW écrit au plus `taille`
        // caractères dans `tampon`, puis le nombre écrit dans `taille`.
        let lu = unsafe { QueryFullProcessImageNameW(self.0, 0, tampon.as_mut_ptr(), &raw mut taille) } != 0;
        // Les `taille` caractères écrits, jamais au-delà du tampon.
        lu.then(|| String::from_utf16_lossy(tampon.get(..usize::try_from(taille).unwrap_or(0)).unwrap_or(&tampon)))
    }

    /// Le SID de son compte, lu dans son jeton par la poignée ; l'erreur, avec son code.
    pub(crate) fn sid(&self) -> std::io::Result<String> {
        const UTILISATEUR: u32 = 1;
        let tampon = jeton_de(Some(self), UTILISATEUR)?;
        sid_du_jeton(&tampon).ok_or_else(|| {
            std::io::Error::other(crate::tr!("SID illisible dans le jeton", "SID unreadable in the token"))
        })
    }
}

impl Drop for Tenu {
    // FFI : CloseHandle de la poignée tenue.
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: la poignée vient d'OpenProcess (non nulle, vérifié par `ouvrir`) et n'est refermée qu'ici, une fois.
        unsafe {
            CloseHandle(self.0);
        }
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

/// Les droits d'une poignée de suspension : suspendre et reprendre (PROCESS_SUSPEND_RESUME), lire le chemin et
/// l'heure de création (PROCESS_QUERY_LIMITED_INFORMATION).
const SUSPENSION_ET_LECTURE: u32 = 0x0800 | 0x1000;
/// Un fil se suspend et se reprend (THREAD_SUSPEND_RESUME) ; on vérifie aussi à qui il est (THREAD_QUERY_LIMITED…).
const FIL_SUSPENSION: u32 = 0x0002 | 0x0800;
/// Ce que SuspendThread et ResumeThread rendent en cas d'échec ((DWORD) -1).
const ECHEC_FIL: u32 = u32::MAX;
/// Au plus tant de passes pour rattraper les fils nés pendant la suspension (un tiers peut en créer un dans le
/// processus suspendu, CreateRemoteThread) ; au-delà, la suspension est dite instable.
const PASSES_MAX: usize = 8;

/// Une poignée de suspension (`SUSPENSION_ET_LECTURE`) ouverte sur `processus`, gardée seulement s'il fait encore
/// tourner `attendu` (casse ignorée) et, si elle est connue, depuis la même heure de création : c'est elle qui lit,
/// suspend et reprend, le numéro ne peut pas passer à un autre processus entre la lecture et le geste.
fn suspensible(processus: u32, attendu: &str, creation: Option<u64>) -> Option<Tenu> {
    let tenu = Tenu::ouvrir_avec(processus, SUSPENSION_ET_LECTURE).ok()?;
    let meme = tenu.chemin().is_some_and(|c| c.eq_ignore_ascii_case(attendu))
        && creation.is_none_or(|c| tenu.creation() == Some(c));
    meme.then_some(tenu)
}

/// Les fils du processus `processus`, d'un instantané Toolhelp32. Vide si Windows refuse.
// FFI : CreateToolhelp32Snapshot, Thread32First et Thread32Next.
#[allow(unsafe_code)]
fn fils(processus: u32) -> Vec<u32> {
    const INSTANTANE_FILS: u32 = 4;
    let mut liste = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot rend un instantané (ou INVALID_HANDLE_VALUE, -1, vérifié), refermé une seule
    // fois plus bas. `entree` est une THREADENTRY32 dont le champ de taille est rempli, comme Windows l'exige.
    unsafe {
        let instantane = CreateToolhelp32Snapshot(INSTANTANE_FILS, 0);
        if instantane as isize == -1 {
            return liste;
        }
        let mut entree: EntreeFil = std::mem::zeroed();
        entree.taille = u32::try_from(std::mem::size_of::<EntreeFil>()).unwrap_or(0);
        let mut suivant = Thread32First(instantane, &raw mut entree) != 0;
        while suivant {
            if entree.processus == processus {
                liste.push(entree.fil);
            }
            suivant = Thread32Next(instantane, &raw mut entree) != 0;
        }
        CloseHandle(instantane);
    }
    liste
}

/// Le compte de suspension du fil `fil` du processus `processus` (0 : il tourne), lu en le suspendant puis en le
/// reprenant aussitôt (Windows ne le donne pas autrement) ; s'il tournait et que `suspendre` est vrai, il reste
/// suspendu. `None` : fil fini, d'un autre processus (numéro repris), ou refusé.
// FFI : OpenThread, GetProcessIdOfThread, SuspendThread, ResumeThread et CloseHandle.
#[allow(unsafe_code)]
fn compte_du_fil(processus: u32, fil: u32, suspendre: bool) -> Option<u32> {
    // SAFETY: OpenThread ne lit rien de notre mémoire ; une poignée nulle (refus) n'est pas utilisée, une autre est
    // refermée une seule fois avant de rendre. Les appels sur la poignée n'écrivent rien chez nous.
    unsafe {
        let poignee = OpenThread(FIL_SUSPENSION, 0, fil);
        if poignee.is_null() {
            return None;
        }
        let compte = if GetProcessIdOfThread(poignee) == processus {
            let avant = SuspendThread(poignee);
            if avant != ECHEC_FIL && !crate::protection::blocage::suspension::comptes::reste_suspendu(avant, suspendre)
            {
                ResumeThread(poignee);
            }
            (avant != ECHEC_FIL).then_some(avant)
        } else {
            None
        };
        CloseHandle(poignee);
        compte
    }
}

/// Une passe sur les fils : suspend chacun de ceux qui tournent encore (`suspendre`) ou les compte seulement. Rend le
/// nombre de fils trouvés tournants et le nombre lus.
fn passe(processus: u32, suspendre: bool) -> (usize, usize) {
    let mut tournants = 0usize;
    let mut lus = 0usize;
    for fil in fils(processus) {
        if let Some(compte) = compte_du_fil(processus, fil, suspendre) {
            lus = lus.saturating_add(1);
            if compte == 0 {
                tournants = tournants.saturating_add(1);
            }
        }
    }
    (tournants, lus)
}

/// Suspend le processus `processus` seulement s'il fait encore tourner `attendu` (et, si donnée, depuis `creation`) :
/// la poignée qui lit le chemin et l'heure de création est celle qui suspend (NtSuspendProcess, une suspension à
/// chaque fil d'un coup), puis des passes fil par fil rattrapent ceux nés pendant (au plus `PASSES_MAX`), jusqu'à
/// une passe qui n'en trouve aucun qui tourne. Rend l'heure de création lue par cette poignée ; `None` : refusé, fini,
/// un autre programme, heure illisible, ou instable (des fils naissent sans cesse).
// FFI : NtSuspendProcess sur la poignée vérifiée.
#[allow(unsafe_code)]
pub(crate) fn suspendre_si(processus: u32, attendu: &str, creation: Option<u64>) -> Option<u64> {
    let tenu = suspensible(processus, attendu, creation)?;
    // Sans heure de création, le bilan ne saurait pas reconnaître ce processus : rien n'est suspendu.
    let lue = tenu.creation()?;
    // SAFETY: la poignée est ouverte, avec le droit de suspendre, tant que `tenu` vit ; l'appel ne lit rien chez nous.
    if unsafe { NtSuspendProcess(tenu.0) } < 0 {
        return None;
    }
    rattraper(processus).then_some(lue)
}

/// Des passes jusqu'à ce qu'aucun fil ne tourne (au plus `PASSES_MAX`, puis une lecture) : vrai si c'est le cas.
fn rattraper(processus: u32) -> bool {
    for _ in 0..PASSES_MAX {
        if passe(processus, true).0 == 0 {
            return true;
        }
    }
    passe(processus, false).0 == 0
}

/// Resuspend ce qu'un tiers a repris d'un processus déjà suspendu par Vanguard : seulement les fils qui tournent, un
/// par un, sans NtSuspendProcess (qui ajouterait une suspension à chaque fil, que la reprise de Vanguard ne retirerait
/// pas : `suspension::comptes`). Même vérification que `suspendre_si` ; rend l'heure de création.
pub(crate) fn resuspendre_si(processus: u32, attendu: &str, creation: Option<u64>) -> Option<u64> {
    let tenu = suspensible(processus, attendu, creation)?;
    let lue = tenu.creation()?;
    rattraper(processus).then_some(lue)
}

/// Reprend le processus `processus` suspendu par `suspendre_si`, seulement s'il fait encore tourner `attendu` (et, si
/// donnée, depuis `creation`) : NtResumeProcess retire une suspension à chaque fil suspendu, la seule que Vanguard y a
/// mise (les fils rattrapés un par un et les resuspensions n'en mettent qu'à ceux qui tournaient). Un fil que son
/// programme ou un tiers tient aussi suspendu le reste. `false` : refusé, fini ou un autre programme.
// FFI : NtResumeProcess sur la poignée vérifiée.
#[allow(unsafe_code)]
pub(crate) fn reprendre_si(processus: u32, attendu: &str, creation: Option<u64>) -> bool {
    let Some(tenu) = suspensible(processus, attendu, creation) else {
        return false;
    };
    // SAFETY: la poignée est ouverte, avec le droit de reprendre, tant que `tenu` vit ; l'appel ne lit rien chez nous.
    unsafe { NtResumeProcess(tenu.0) >= 0 }
}

/// Ce qu'on lit du processus `processus` noté avec `attendu` et `creation` (voir `suspension::Lu`). La poignée tenue
/// pendant la lecture : le numéro ne peut pas être repris, ses fils sont bien les siens.
pub(crate) fn etat_si(
    processus: u32,
    attendu: &str,
    creation: Option<u64>,
) -> crate::protection::blocage::suspension::Lu {
    use crate::protection::blocage::suspension::Lu;
    /// ERROR_INVALID_PARAMETER : plus aucun processus à ce numéro.
    const AUCUN: i32 = 87;
    let tenu = match Tenu::ouvrir_avec(processus, SUSPENSION_ET_LECTURE) {
        Ok(t) => t,
        Err(e) if e.raw_os_error() == Some(AUCUN) => return Lu::Fini,
        // Refusé : un processus élevé ou d'un autre compte, peut-être toujours suspendu.
        Err(_) => return Lu::Illisible,
    };
    match tenu.chemin() {
        None => return Lu::Illisible,
        Some(c) if !c.eq_ignore_ascii_case(attendu) => return Lu::Autre,
        Some(_) => {}
    }
    if let Some(attendue) = creation {
        match tenu.creation() {
            None => return Lu::Illisible,
            Some(c) if c != attendue => return Lu::Autre,
            Some(_) => {}
        }
    }
    if fils(processus).is_empty() {
        return Lu::Fini;
    }
    match passe(processus, false) {
        (_, 0) => Lu::Illisible,
        (0, _) => Lu::Gele,
        (t, l) if t == l => Lu::Tourne,
        _ => Lu::EnPartie,
    }
}

/// Ce compte a-t-il le droit de suspendre ce processus ? La poignée de suspension est demandée puis refermée aussitôt.
pub(crate) fn peut_suspendre(processus: u32) -> bool {
    const SUSPENSION: u32 = 0x0800;
    // SAFETY: la poignée vient d'OpenProcess (nulle : refus, vérifié) et n'est refermée qu'une fois.
    unsafe {
        let poignee = OpenProcess(SUSPENSION, 0, processus);
        if poignee.is_null() {
            return false;
        }
        CloseHandle(poignee);
        true
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
    jeton_de(None, classe).ok()
}

/// Une information du jeton du processus tenu (`None` : ce processus), dans un tampon aligné ; l'erreur de Windows
/// s'il refuse (processus d'un autre compte sans SeDebugPrivilege actif), lue dès l'appel refusé.
// FFI : OpenProcessToken et GetTokenInformation.
#[allow(unsafe_code)]
fn jeton_de(processus: Option<&Tenu>, classe: u32) -> std::io::Result<Vec<u64>> {
    const LECTURE: u32 = 0x0008;
    let mut poignee = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess rend une pseudo-poignée, sans rien à fermer ; celle d'un `Tenu` reste ouverte tant
    // qu'il vit (emprunté ici). Le jeton ouvert (vérifié) est fermé une seule fois. Le premier appel donne la taille ;
    // le second écrit au plus `place` octets (la taille annoncée) dans `tampon`, qui en a au moins autant, aligné sur
    // 8 octets pour les structures qu'il contient.
    unsafe {
        let processus = match processus {
            None => GetCurrentProcess(),
            Some(t) => t.0,
        };
        if OpenProcessToken(processus, LECTURE, &raw mut poignee) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut taille = 0u32;
        GetTokenInformation(poignee, classe, std::ptr::null_mut(), 0, &raw mut taille);
        let (mut tampon, place) = tampon_du_jeton(taille);
        let lu = GetTokenInformation(poignee, classe, tampon.as_mut_ptr().cast(), place, &raw mut taille) != 0;
        let refus = std::io::Error::last_os_error();
        CloseHandle(poignee);
        if lu { Ok(tampon) } else { Err(refus) }
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
    sid_du_jeton(&jeton(UTILISATEUR)?)
}

/// Le SID d'un TOKEN_USER lu par `jeton_de`, en texte vérifié.
// FFI : ConvertSidToStringSidW et LocalFree, sur le SID du tampon.
#[allow(unsafe_code)]
fn sid_du_jeton(tampon: &[u64]) -> Option<String> {
    // Le pointeur du SID est le premier mot du tampon : un tampon vide n'en a pas.
    tampon.first()?;
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
    use crate::protection::blocage::suspension::Lu;

    /// PROCESSENTRY32W mise à zéro avant Process32FirstW (exercé sous Miri par outils/preuves.sh) : zéro est une
    /// valeur permise de chaque champ, et la taille est celle de tlhelp32.h sur x86_64.
    #[test]
    fn entree_mise_a_zero() {
        // SAFETY: c'est ce que vérifie l'essai : la structure n'a que des entiers et un tableau d'entiers.
        let entree: Entree = unsafe { std::mem::zeroed() };
        assert_eq!(entree.fichier, [0; 260]);
        assert_eq!(std::mem::size_of::<Entree>(), 568);
    }

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
        // Le SID d'un processus tenu par sa poignée : celui de ce processus est le même que par son propre jeton ; un
        // numéro qui n'existe pas ne s'ouvre pas.
        let tenu = Tenu::ouvrir(moi).unwrap();
        assert_eq!(tenu.sid().ok(), sid());
        assert!(tenu.chemin().is_some_and(|c| c.to_lowercase().ends_with(".exe")));
        assert!(Tenu::ouvrir(u32::MAX - 3).is_err());
    }

    /// THREADENTRY32 de tlhelp32.h : 28 octets.
    #[test]
    fn entree_de_fil() {
        assert_eq!(std::mem::size_of::<EntreeFil>(), 28);
    }

    /// Un enfant jetable pour l'essai de suspension : ce binaire d'essais, qui ne fait que dormir.
    #[test]
    #[ignore = "lancé seulement comme enfant par suspension_d_un_enfant"]
    fn enfant_qui_dort() {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }

    /// Suspendu seulement s'il fait tourner le programme attendu et depuis la bonne heure de création ; repris de
    /// même ; un programme ou une heure faux ne touche à rien. Ce binaire d'essais, relancé, sert d'enfant jetable.
    #[test]
    fn suspension_d_un_enfant() {
        let Ok(moi) = std::env::current_exe() else {
            return crate::essais::saute("binaire d'essais introuvable");
        };
        let Ok(mut enfant) = std::process::Command::new(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::windows::processus::tests::enfant_qui_dort",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        else {
            return crate::essais::saute("l'enfant ne se lance pas");
        };
        let pid = enfant.id();
        let mut lu = None;
        for _ in 0..200 {
            lu = chemin(pid).zip(creation(pid));
            if lu.as_ref().is_some_and(|(c, _)| etat_si(pid, c, None) == Lu::Tourne) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let Some((programme, nee)) = lu else {
            let _ = enfant.kill();
            return crate::essais::saute("l'enfant ne se lit pas");
        };
        let autre = suspendre_si(pid, r"C:\autre\programme.exe", None);
        let mauvaise_heure = suspendre_si(pid, &programme, Some(nee.wrapping_add(1)));
        let libre = etat_si(pid, &programme, Some(nee));
        let suspendu = suspendre_si(pid, &programme, Some(nee));
        let fige = etat_si(pid, &programme, Some(nee));
        let autre_lu = etat_si(pid, r"C:\autre\programme.exe", Some(nee));
        let resuspendu = resuspendre_si(pid, &programme, Some(nee));
        let repris_faux = reprendre_si(pid, r"C:\autre\programme.exe", None);
        let toujours = etat_si(pid, &programme, Some(nee));
        // Une seule reprise suffit, même après une resuspension (qui n'ajoute rien à un fil suspendu).
        let repris = reprendre_si(pid, &programme, Some(nee));
        let apres = etat_si(pid, &programme, Some(nee));
        let _ = enfant.kill();
        let _ = enfant.wait();
        assert_eq!((autre, mauvaise_heure, libre), (None, None, Lu::Tourne));
        assert_eq!((suspendu, fige, autre_lu), (Some(nee), Lu::Gele, Lu::Autre));
        assert_eq!(resuspendu, Some(nee));
        assert_eq!((repris_faux, toujours), (false, Lu::Gele));
        assert_eq!((repris, apres), (true, Lu::Tourne));
        assert!(suspendre_si(u32::MAX - 3, &programme, None).is_none());
        assert_eq!(etat_si(u32::MAX - 3, &programme, None), Lu::Fini);
        assert!(!peut_suspendre(u32::MAX - 3));
    }
}
