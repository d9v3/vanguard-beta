//! Lectures demandées au noyau de macOS, sans lancer d'outil : processus et prises réseau (libproc), arguments et
//! heure de démarrage (sysctl), table de routage et voisins (sysctl PF_ROUTE), échange, état de SIP
//! (csr_get_active_config), options du prochain démarrage (IORegistry), identifiant de l'ordinateur, montages.
//! Les octets rendus sont lus par `machine::darwin`, testé sous Linux sur des octets fixes.
//!
//! Tant que les tests d'oracle de `.github/workflows/macos.yml` (ce module, plus bas) n'ont pas prouvé chaque lecture
//! sur un vrai Mac contre l'outil d'Apple (ps, lsof, netstat, arp, csrutil, nvram, sysctl, ioreg), l'outil reste en
//! secours là où la lecture native ne répond pas : chaque fonction rend `None` quand elle n'a rien pu lire, jamais une
//! liste vide qui passerait pour « rien d'anormal ».

use std::ffi::{CStr, c_char, c_int, c_void};
use std::net::Ipv4Addr;

use crate::machine::darwin::{self, Court, PriseNoyau, Route, Voisin};

/// Un sysctl par son MIB (tableau d'entiers), avec la taille demandée d'abord au noyau (bornée à 64 Mo). `None` :
/// refusé, absent, ou vide.
pub(crate) fn sysctl_mib(mib: &mut [c_int], taille_max: usize) -> Option<Vec<u8>> {
    let n = libc::c_uint::try_from(mib.len()).ok()?;
    let mut taille: libc::size_t = 0;
    // SAFETY : mib vit pendant l'appel et compte `n` entiers ; sans tampon (pointeur nul), sysctl n'écrit que la
    // taille voulue dans `taille`.
    let code = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            n,
            std::ptr::null_mut(),
            &raw mut taille,
            std::ptr::null_mut(),
            0,
        )
    };
    if code != 0 || taille == 0 || taille > taille_max {
        return None;
    }
    // La table peut grandir entre les deux appels : un peu de marge.
    taille = taille.saturating_add(taille / 8).min(taille_max);
    let mut tampon = vec![0u8; taille];
    // SAFETY : tampon de `taille` octets, vivant pendant l'appel ; le noyau n'écrit pas au-delà et redit dans
    // `taille` ce qu'il a écrit.
    let code = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            n,
            tampon.as_mut_ptr().cast(),
            &raw mut taille,
            std::ptr::null_mut(),
            0,
        )
    };
    if code != 0 || taille == 0 {
        return None;
    }
    tampon.truncate(taille);
    Some(tampon)
}

// ───────────────────────────── Processus ─────────────────────────────

/// Les numéros de tous les processus (proc_listallpids, qui rend un nombre de processus, pas d'octets). Le tampon
/// suit la taille que le noyau annonce ; plein, il est agrandi, car une liste coupée cacherait les derniers venus.
/// `None` : rien lu (Vanguard au moins tourne, donc une liste vide est un échec).
pub(crate) fn pids() -> Option<Vec<u32>> {
    // SAFETY : sans tampon, proc_listallpids rend seulement le nombre de processus à prévoir (avec une marge).
    let annonce = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    let mut place = usize::try_from(annonce).unwrap_or(0).max(256) + 64;
    for _ in 0..4 {
        let mut pids: Vec<c_int> = vec![0; place];
        let taille = c_int::try_from(pids.len() * size_of::<c_int>()).ok()?;
        // SAFETY : proc_listallpids écrit au plus `taille` octets dans `pids` et rend le nombre de numéros écrits.
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), taille) };
        let n = usize::try_from(n).ok()?;
        if n < place {
            let liste: Vec<u32> = pids[..n].iter().filter_map(|&p| u32::try_from(p).ok()).collect();
            return (!liste.is_empty()).then_some(liste);
        }
        place *= 2;
    }
    None
}

/// Ce que tout compte lit d'un processus (PROC_PIDT_SHORTBSDINFO) ; `None` : parti, ou réponse d'une autre forme.
pub(crate) fn court(pid: u32) -> Option<Court> {
    let mut tampon = [0u8; size_of::<darwin::ProcBsdShortinfo>()];
    let taille = c_int::try_from(tampon.len()).ok()?;
    // SAFETY : proc_pidinfo écrit au plus `taille` octets dans `tampon` et rend leur nombre (0 : refus ou parti).
    let lus = unsafe {
        libc::proc_pidinfo(
            c_int::try_from(pid).ok()?,
            darwin::PROC_PIDT_SHORTBSDINFO,
            0,
            tampon.as_mut_ptr().cast(),
            taille,
        )
    };
    darwin::lire_shortbsdinfo(tampon.get(..usize::try_from(lus).ok()?)?, pid)
}

/// L'heure de démarrage du processus (secondes depuis 1970, microsecondes), par sysctl KERN_PROC_PID, lisible pour
/// tous les comptes, comme `ps -o lstart`.
pub(crate) fn debut(pid: u32) -> Option<(i64, u32)> {
    let mut mib = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        c_int::try_from(pid).ok()?,
    ];
    darwin::debut_kinfo(&sysctl_mib(&mut mib, 4096)?, pid)
}

/// Les arguments du processus (KERN_PROCARGS2) ; le noyau ne les donne que pour les processus du compte (tous en
/// root), comme à `ps`. `None` : refusé, parti, ou illisible.
pub(crate) fn arguments(pid: u32) -> Option<Vec<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, c_int::try_from(pid).ok()?];
    darwin::lire_procargs2(&sysctl_mib(&mut mib, 4 << 20)?).map(|(_, args)| args)
}

/// Le chemin du programme du processus (proc_pidpath, lisible pour tous les comptes).
pub(crate) fn chemin(pid: u32) -> Option<String> {
    crate::socle::processus::programme(pid).map(|c| c.to_string_lossy().into_owned())
}

/// Les enfants directs d'un processus (proc_listchildpids). `None` : l'appel a échoué (pas « aucun enfant »).
pub(crate) fn enfants(pid: u32) -> Option<Vec<u32>> {
    let parent = libc::pid_t::try_from(pid).ok()?;
    let mut place = 64usize;
    for _ in 0..6 {
        let mut pids: Vec<c_int> = vec![0; place];
        let taille = c_int::try_from(pids.len() * size_of::<c_int>()).ok()?;
        // SAFETY : proc_listchildpids écrit au plus `taille` octets dans `pids` et rend le nombre de numéros écrits
        // (-1 : échec).
        let n = unsafe { libc::proc_listchildpids(parent, pids.as_mut_ptr().cast(), taille) };
        let n = usize::try_from(n).ok()?;
        if n < place {
            return Some(
                pids[..n]
                    .iter()
                    .filter_map(|&p| u32::try_from(p).ok())
                    .filter(|&p| p != 0)
                    .collect(),
            );
        }
        place *= 4;
    }
    None
}

/// Le nom d'un compte d'après son numéro (getpwuid_r) ; `None` : inconnu (le numéro se montre alors tel quel).
pub(crate) fn compte(uid: u32) -> Option<String> {
    let mut tampon: Vec<c_char> = vec![0; 16 * 1024];
    // SAFETY : une struct passwd faite de nombres et de pointeurs, que getpwuid_r remplit avant toute lecture.
    let mut entree: libc::passwd = unsafe { std::mem::zeroed() };
    let mut trouve: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY : tampon, entree et trouve vivent pendant l'appel ; getpwuid_r n'écrit que dans les tailles données.
    let code = unsafe { libc::getpwuid_r(uid, &raw mut entree, tampon.as_mut_ptr(), tampon.len(), &raw mut trouve) };
    if code != 0 || trouve.is_null() || entree.pw_name.is_null() {
        return None;
    }
    // SAFETY : pw_name est une chaîne C terminée par un nul, rangée dans tampon, encore vivant.
    let nom = unsafe { CStr::from_ptr(entree.pw_name) }.to_string_lossy().into_owned();
    (!nom.is_empty()).then_some(nom)
}

/// Les comptes de l'annuaire local (getpwent) : (nom, numéro), 10 000 au plus. getpwent n'est pas réentrant : un seul
/// fil à la fois, par un verrou.
pub(crate) fn comptes() -> Vec<(String, u32)> {
    static VERROU: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _garde = VERROU.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut liste = Vec::new();
    // SAFETY : setpwent, getpwent et endpwent dans ce seul fil (verrou) ; l'entrée rendue reste valable jusqu'à
    // l'appel suivant et elle est lue tout de suite (pointeur non nul vérifié, chaîne C terminée par un nul).
    unsafe {
        libc::setpwent();
        while liste.len() < 10_000 {
            let e = libc::getpwent();
            if e.is_null() {
                break;
            }
            if !(*e).pw_name.is_null() {
                liste.push((CStr::from_ptr((*e).pw_name).to_string_lossy().into_owned(), (*e).pw_uid));
            }
        }
        libc::endpwent();
    }
    liste
}

/// Une session ouverte, celle que montre `who`.
#[derive(Debug, Clone)]
pub(crate) struct Session {
    pub compte: String,
    pub ligne: String,
    pub hote: String,
    /// Son ouverture, à l'heure locale (« 2026-10-24 09:12 »).
    pub depuis: String,
}

/// Les sessions ouvertes (getutxent, USER_PROCESS), ce que liste `who`.
pub(crate) fn sessions_ouvertes() -> Vec<Session> {
    static VERROU: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _garde = VERROU.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let texte = |c: &[c_char]| {
        // SAFETY : un c_char a la taille et l'alignement d'un octet.
        let o: &[u8] = unsafe { std::slice::from_raw_parts(c.as_ptr().cast(), c.len()) };
        let fin = o.iter().position(|&x| x == 0).unwrap_or(o.len());
        String::from_utf8_lossy(&o[..fin]).into_owned()
    };
    let mut liste = Vec::new();
    // SAFETY : setutxent, getutxent et endutxent dans ce seul fil (verrou) ; l'entrée rendue reste valable jusqu'à
    // l'appel suivant, lue tout de suite (pointeur non nul vérifié) ; ses champs sont des tableaux de taille fixe,
    // lus jusqu'au premier nul ou à leur fin.
    unsafe {
        libc::setutxent();
        while liste.len() < 10_000 {
            let e = libc::getutxent();
            if e.is_null() {
                break;
            }
            let e = &*e;
            if e.ut_type != libc::USER_PROCESS {
                continue;
            }
            liste.push(Session {
                compte: texte(&e.ut_user),
                ligne: texte(&e.ut_line),
                hote: texte(&e.ut_host),
                depuis: chrono::DateTime::from_timestamp(e.ut_tv.tv_sec, 0)
                    .map(|d| d.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_default(),
            });
        }
        libc::endutxent();
    }
    liste
}

/// Un processus lu au noyau. Les champs que le noyau réserve au compte du processus (arguments) manquent pour les
/// autres comptes sans droits d'administrateur ; c'est dit par `None`, jamais par un texte vide.
#[derive(Debug, Clone)]
pub(crate) struct Processus {
    pub pid: u32,
    pub ppid: u32,
    /// Le compte effectif, celui que montre `ps -o user`.
    pub uid: u32,
    pub comm: String,
    pub chemin: Option<String>,
    pub debut: Option<(i64, u32)>,
    pub arguments: Option<Vec<String>>,
}

impl Processus {
    /// Sa ligne de commande, les arguments séparés par une espace, comme `ps -o args`.
    pub(crate) fn ligne(&self) -> Option<String> {
        self.arguments.as_ref().filter(|a| !a.is_empty()).map(|a| a.join(" "))
    }

    /// Sa naissance en UTC, à la microseconde.
    pub(crate) fn ne(&self) -> Option<chrono::NaiveDateTime> {
        let (s, us) = self.debut?;
        chrono::DateTime::from_timestamp(s, us.saturating_mul(1000)).map(|d| d.naive_utc())
    }

    /// Le nom de son programme : celui de son fichier, sinon le nom court du noyau.
    pub(crate) fn nom(&self) -> String {
        self.chemin
            .as_deref()
            .and_then(|c| c.rsplit('/').next())
            .filter(|n| !n.is_empty())
            .map_or_else(|| self.comm.clone(), str::to_string)
    }
}

/// Tous les processus, avec leurs arguments quand le noyau les donne (`avec_arguments`). `None` : la liste ne se lit
/// pas, ou Vanguard ne s'y trouve pas lui-même (une lecture qui manque le processus qui la fait n'est pas fiable).
pub(crate) fn processus(avec_arguments: bool) -> Option<Vec<Processus>> {
    let moi = std::process::id();
    let liste: Vec<Processus> = pids()?
        .into_iter()
        .filter_map(|pid| {
            let c = court(pid)?;
            Some(Processus {
                pid,
                ppid: c.ppid,
                uid: c.uid,
                comm: c.comm,
                chemin: chemin(pid),
                debut: debut(pid),
                arguments: if avec_arguments { arguments(pid) } else { None },
            })
        })
        .collect();
    liste.iter().any(|p| p.pid == moi).then_some(liste)
}

/// Un programme de ce nom court du noyau (p_comm, 16 caractères au plus, ce que compare `pgrep -x`) tourne-t-il ?
/// `None` : la liste ne se lit pas (on ne sait pas, à demander à pgrep).
pub(crate) fn en_marche(nom: &str) -> Option<bool> {
    let pids = pids()?;
    // Un nom de plus de 16 caractères est tronqué par le noyau.
    let court_cherche: String = nom.chars().take(16).collect();
    Some(
        pids.into_iter()
            .any(|pid| court(pid).is_some_and(|c| c.comm == court_cherche)),
    )
}

// ───────────────────────────── Prises réseau ─────────────────────────────

/// Les prises IP lisibles des processus, avec leur processus. `refuses` : les processus dont le noyau a refusé la
/// liste des descripteurs (ceux des autres comptes, sans droits d'administrateur) ; leurs prises manquent, comme à
/// lsof.
#[derive(Debug, Default)]
pub(crate) struct Prises {
    pub prises: Vec<(u32, String, PriseNoyau)>,
    pub refuses: usize,
}

/// Les descripteurs ouverts d'un processus (PROC_PIDLISTFDS), en (numéro, sorte). `None` : refusé ou parti.
fn descripteurs(pid: c_int) -> Option<Vec<(c_int, u32)>> {
    // SAFETY : sans tampon, proc_pidinfo rend seulement la taille à prévoir (avec une marge).
    let annonce = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    let annonce = usize::try_from(annonce).ok().filter(|&n| n > 0)?;
    let taille = annonce.min(8 << 20);
    let mut tampon = vec![0u8; taille];
    // SAFETY : tampon de `taille` octets, vivant pendant l'appel ; proc_pidinfo n'écrit pas au-delà et rend le
    // nombre d'octets écrits.
    let lus = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            tampon.as_mut_ptr().cast(),
            c_int::try_from(taille).ok()?,
        )
    };
    let lus = usize::try_from(lus).ok().filter(|&n| n > 0 && n <= taille)?;
    // `struct proc_fdinfo` : un int32 (le numéro) et un uint32 (la sorte), 8 octets.
    Some(
        tampon[..lus - lus % 8]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|m| {
                (
                    c_int::from_ne_bytes([m[0], m[1], m[2], m[3]]),
                    u32::from_ne_bytes([m[4], m[5], m[6], m[7]]),
                )
            })
            .collect(),
    )
}

/// La prise IP d'un descripteur (PROC_PIDFDSOCKETINFO) ; `None` : pas une prise IP, ou réponse d'une autre taille.
fn prise(pid: c_int, fd: c_int) -> Option<PriseNoyau> {
    let mut tampon = vec![0u8; size_of::<darwin::SocketFdinfo>()];
    let taille = c_int::try_from(tampon.len()).ok()?;
    // SAFETY : proc_pidfdinfo écrit au plus `taille` octets dans `tampon` et rend leur nombre (0 : refus).
    let lus = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            darwin::PROC_PIDFDSOCKETINFO,
            tampon.as_mut_ptr().cast(),
            taille,
        )
    };
    darwin::lire_socket_fdinfo(tampon.get(..usize::try_from(lus).ok()?)?)
}

/// Les prises réseau de tous les processus lisibles. `None` : la liste des processus ne se lit pas, ou les
/// descripteurs de Vanguard lui-même ne se lisent pas (le noyau refuse alors tout : la lecture native est muette, et
/// l'appelant passe à lsof).
pub(crate) fn prises() -> Option<Prises> {
    let moi = c_int::try_from(std::process::id()).ok()?;
    descripteurs(moi)?;
    let mut lues = Prises::default();
    for pid in pids()? {
        let Ok(p) = c_int::try_from(pid) else { continue };
        let Some(liste) = descripteurs(p) else {
            lues.refuses += 1;
            continue;
        };
        let socket = u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap_or(2);
        let mut nom = None;
        for (fd, _) in liste.into_iter().filter(|(_, sorte)| *sorte == socket) {
            if let Some(x) = prise(p, fd) {
                let nom = nom
                    .get_or_insert_with(|| {
                        let comm = court(pid).map(|c| c.comm).unwrap_or_default();
                        chemin(pid)
                            .as_deref()
                            .and_then(|c| c.rsplit('/').next())
                            .filter(|n| !n.is_empty())
                            .map_or(comm, str::to_string)
                    })
                    .clone();
                lues.prises.push((pid, nom, x));
            }
        }
    }
    Some(lues)
}

// ───────────────────────────── Routes et voisins ─────────────────────────────

/// La table de routage IPv4 (NET_RT_DUMP), ou ses entrées d'un drapeau (NET_RT_FLAGS). `None` : refusée.
fn routes_ipv4(drapeau: Option<c_int>) -> Option<Vec<Route>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        if drapeau.is_some() {
            libc::NET_RT_FLAGS
        } else {
            libc::NET_RT_DUMP
        },
        drapeau.unwrap_or(0),
    ];
    // Une table vide est une réponse : sysctl rend alors 0 octet, que sysctl_mib dit `None`.
    Some(darwin::lire_routes(&sysctl_mib(&mut mib, 64 << 20)?))
}

/// La passerelle par défaut en IPv4, celle de `route -n get default`. `None` : table illisible, ou aucune route par
/// défaut.
pub(crate) fn passerelle() -> Option<Ipv4Addr> {
    darwin::passerelle_par_defaut(&routes_ipv4(None)?)
}

/// Les voisins du réseau local (table ARP), ceux d'`arp -an`. `None` : table illisible.
pub(crate) fn voisins() -> Option<Vec<Voisin>> {
    routes_ipv4(Some(darwin::RTF_LLINFO)).map(|r| darwin::voisins(&r))
}

/// Toutes les routes IPv4, pour les traces.
pub(crate) fn routes() -> Option<Vec<Route>> {
    routes_ipv4(None)
}

// ───────────────────────────── Système ─────────────────────────────

/// L'échange (vm.swapusage) : (total, utilisé) en octets.
pub(crate) fn echange() -> Option<(u64, u64)> {
    darwin::lire_xsw_usage(&super::sysctl("vm.swapusage")?)
}

/// La configuration active de SIP (csr_get_active_config, de libsystem_kernel). Fonction privée d'Apple, absente des
/// en-têtes publics : cherchée à l'exécution (dlsym) pour que Vanguard démarre encore si une version de macOS la
/// retire. `None` : symbole absent ou appel refusé ; csrutil prend alors le relais.
pub(crate) fn sip() -> Option<u32> {
    type CsrGetActiveConfig = unsafe extern "C" fn(*mut u32) -> c_int;
    // SAFETY : dlsym avec RTLD_DEFAULT cherche le symbole dans les bibliothèques déjà chargées ; le nom est une chaîne
    // C terminée par un nul.
    let symbole = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"csr_get_active_config".as_ptr()) };
    if symbole.is_null() {
        return None;
    }
    // SAFETY : csr_get_active_config(csr_config_t *) d'après sys/csr.h de XNU, csr_config_t étant un uint32_t ; le
    // symbole trouvé est cette fonction de libsystem_kernel.
    let fonction = unsafe { std::mem::transmute::<*mut c_void, CsrGetActiveConfig>(symbole) };
    let mut config: u32 = 0;
    // SAFETY : config vit pendant l'appel ; la fonction écrit un uint32_t et rend 0 en cas de succès.
    (unsafe { fonction(&raw mut config) } == 0).then_some(config)
}

mod iokit {
    use std::ffi::c_char;

    use system_configuration::core_foundation::base::{CFAllocatorRef, CFTypeRef};
    use system_configuration::core_foundation::string::CFStringRef;

    #[link(name = "IOKit", kind = "framework")]
    unsafe extern "C" {
        /// IOKitLib.h : `io_registry_entry_t IORegistryEntryFromPath(mach_port_t, const io_string_t)`.
        pub(super) fn IORegistryEntryFromPath(main_port: u32, path: *const c_char) -> u32;
        /// IOKitLib.h : `CFTypeRef IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef,
        /// IOOptionBits)`, à libérer par CFRelease.
        pub(super) fn IORegistryEntryCreateCFProperty(
            entry: u32,
            key: CFStringRef,
            allocator: CFAllocatorRef,
            options: u32,
        ) -> CFTypeRef;
        /// IOKitLib.h : `kern_return_t IOObjectRelease(io_object_t)`.
        pub(super) fn IOObjectRelease(object: u32) -> i32;
    }
}

/// La variable NVRAM « boot-args » : absente (le cas normal), ou son texte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OptionsNvram {
    Absentes,
    Posees(String),
}

/// Les options du PROCHAIN démarrage (la variable NVRAM « boot-args », lue dans IODeviceTree:/options comme le fait
/// `nvram`). `None` : la NVRAM ne se lit pas, `nvram` prend le relais.
pub(crate) fn options_prochain_demarrage() -> Option<OptionsNvram> {
    use system_configuration::core_foundation::base::{CFType, TCFType};
    use system_configuration::core_foundation::data::CFData;
    use system_configuration::core_foundation::string::CFString;
    // SAFETY : le chemin est une chaîne C terminée par un nul ; 0 (MACH_PORT_NULL, kIOMainPortDefault) désigne le
    // port principal par défaut. L'entrée rendue est libérée plus bas par IOObjectRelease.
    let entree = unsafe { iokit::IORegistryEntryFromPath(0, c"IODeviceTree:/options".as_ptr()) };
    if entree == 0 {
        return None;
    }
    let cle = CFString::from_static_string("boot-args");
    // SAFETY : entree est valide jusqu'à IOObjectRelease ; cle vit pendant l'appel ; allocateur nul = celui par
    // défaut, aucune option.
    let brut =
        unsafe { iokit::IORegistryEntryCreateCFProperty(entree, cle.as_concrete_TypeRef(), std::ptr::null(), 0) };
    // SAFETY : l'entrée vient d'IORegistryEntryFromPath et n'est plus utilisée après.
    unsafe { iokit::IOObjectRelease(entree) };
    if brut.is_null() {
        return Some(OptionsNvram::Absentes);
    }
    // SAFETY : la propriété est créée pour nous (« Create ») : CFType la libère (CFRelease) quand il disparaît.
    let valeur = unsafe { CFType::wrap_under_create_rule(brut) };
    if let Some(t) = valeur.downcast::<CFString>() {
        return Some(OptionsNvram::Posees(t.to_string()));
    }
    let d = valeur.downcast::<CFData>()?;
    let octets = d.bytes();
    let fin = octets.iter().position(|&o| o == 0).unwrap_or(octets.len());
    Some(OptionsNvram::Posees(
        String::from_utf8_lossy(&octets[..fin]).into_owned(),
    ))
}

/// Les options du démarrage EN COURS (kern.bootargs). `Some("")` : aucune ; `None` : illisible.
pub(crate) fn options_demarrage_en_cours() -> Option<String> {
    let octets = super::sysctl_ou_vide("kern.bootargs")?;
    let fin = octets.iter().position(|&o| o == 0).unwrap_or(octets.len());
    Some(String::from_utf8_lossy(&octets[..fin]).trim().to_string())
}

/// L'identifiant de l'ordinateur (gethostuuid), écrit comme l'IOPlatformUUID d'ioreg. Pas encore employé pour
/// l'empreinte de la machine : le test d'oracle de macos.yml doit d'abord prouver l'égalité des deux chaînes.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn uuid_machine() -> Option<String> {
    let mut id = [0u8; 16];
    let delai = libc::timespec { tv_sec: 5, tv_nsec: 0 };
    // SAFETY : id fait 16 octets (uuid_t), delai vit pendant l'appel.
    (unsafe { libc::gethostuuid(id.as_mut_ptr(), &raw const delai) } == 0).then(|| darwin::uuid_comme_ioreg(&id))
}

/// Un volume monté : son appareil, son point de montage, lecture seule ou non.
#[derive(Debug, Clone)]
pub(crate) struct Montage {
    pub source: String,
    pub point: String,
    pub lecture_seule: bool,
}

/// Les volumes montés (getmntinfo, MNT_NOWAIT : sans réveiller un volume réseau qui ne répond plus), ce que liste
/// `mount`. `None` : illisible.
pub(crate) fn montages() -> Option<Vec<Montage>> {
    let mut tableau: *mut libc::statfs = std::ptr::null_mut();
    // SAFETY : getmntinfo fait pointer `tableau` sur un tableau qu'il garde lui-même (à ne pas libérer) et rend son
    // nombre d'éléments (0 : échec).
    let n = unsafe { libc::getmntinfo(&raw mut tableau, libc::MNT_NOWAIT) };
    let n = usize::try_from(n).ok().filter(|&n| n > 0 && n < 100_000)?;
    if tableau.is_null() {
        return None;
    }
    // SAFETY : `n` éléments valides à partir de `tableau`, d'après getmntinfo, lus avant tout autre appel qui le
    // réécrirait.
    let liste = unsafe { std::slice::from_raw_parts(tableau, n) };
    let texte = |c: &[c_char]| {
        // SAFETY : un c_char a la taille et l'alignement d'un octet.
        let o: &[u8] = unsafe { std::slice::from_raw_parts(c.as_ptr().cast(), c.len()) };
        let fin = o.iter().position(|&x| x == 0).unwrap_or(o.len());
        String::from_utf8_lossy(&o[..fin]).into_owned()
    };
    Some(
        liste
            .iter()
            .map(|m| Montage {
                source: texte(&m.f_mntfromname),
                point: texte(&m.f_mntonname),
                lecture_seule: u64::from(m.f_flags) & u64::try_from(libc::MNT_RDONLY).unwrap_or(1) != 0,
            })
            .collect(),
    )
}
