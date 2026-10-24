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

/// Un sysctl par son MIB (tableau d'entiers), avec la taille demandée d'abord au noyau, bornée à `taille_max`.
/// `marge` : un huitième de plus pour une table qui peut grandir entre les deux appels (routes, processus) ; sans
/// marge pour KERN_PROCARGS2, que le noyau refuse au-delà de ARG_MAX. `None` : refusé, absent, ou vide.
pub(crate) fn sysctl_mib(mib: &mut [c_int], taille_max: usize, marge: bool) -> Option<Vec<u8>> {
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
    if marge {
        taille = taille.saturating_add(taille / 8).min(taille_max);
    }
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
    darwin::debut_kinfo(&sysctl_mib(&mut mib, 4096, true)?, pid)
}

/// Le chemin du programme lancé et les arguments (KERN_PROCARGS2), que le noyau ne donne que pour les processus du
/// compte (tous en root), comme à `ps` ; `None` : refusé, parti, ou illisible. Le chemin sert quand proc_pidpath ne le donne plus
/// (programme effacé du disque).
fn chemin_et_arguments(pid: u32) -> Option<(String, Vec<String>)> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, c_int::try_from(pid).ok()?];
    darwin::lire_procargs2(&sysctl_mib(&mut mib, 4 << 20, false)?)
}

/// Le chemin du programme du processus (proc_pidpath, lisible pour tous les comptes).
pub(crate) fn chemin(pid: u32) -> Option<String> {
    crate::socle::processus::programme(pid).map(|c| c.to_string_lossy().into_owned())
}

/// Les enfants directs d'un processus (proc_listchildpids). `None` : l'appel a échoué (pas « aucun enfant »).
pub(crate) fn enfants(pid: u32) -> Option<Vec<u32>> {
    let parent = libc::pid_t::try_from(pid).ok()?;
    // proc_listchildpids rend 0 aussi bien pour « aucun enfant » que pour un échec (libproc.c) : le processus doit
    // d'abord se lire, sinon c'est un échec, à confier à pgrep.
    court(pid)?;
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
            let lance = if avec_arguments { chemin_et_arguments(pid) } else { None };
            // proc_pidpath ne donne plus le chemin d'un programme effacé : celui qu'a noté exec, quand il se lit.
            let chemin = chemin(pid).or_else(|| lance.as_ref().map(|(c, _)| c.clone()).filter(|c| c.starts_with('/')));
            Some(Processus {
                pid,
                ppid: c.ppid,
                uid: c.uid,
                comm: c.comm,
                chemin,
                debut: debut(pid),
                arguments: lance.map(|(_, a)| a),
            })
        })
        .collect();
    liste.iter().any(|p| p.pid == moi).then_some(liste)
}

/// Un programme de ce nom court du noyau (p_comm, ce que compare `pgrep -x`) tourne-t-il ? `None` : la liste ne se
/// lit pas (on ne sait pas, à demander à pgrep). Les appelants cherchent des noms de 15 caractères au plus.
pub(crate) fn en_marche(nom: &str) -> Option<bool> {
    let pids = pids()?;
    // proc_pidshortbsdinfo coupe le nom à 15 caractères (le 16e octet est le nul).
    let court_cherche: String = nom.chars().take(15).collect();
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
#[allow(clippy::struct_field_names)] // « prises » : ce qu'elles sont, à côté de leurs refus
pub(crate) struct Prises {
    pub prises: Vec<(u32, String, PriseNoyau)>,
    pub refuses: usize,
    /// Les prises dont la réponse n'a pas la taille de `socket_fdinfo` : une structure qui aurait changé avec macOS.
    pub illisibles: usize,
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

/// La prise IP d'un descripteur (PROC_PIDFDSOCKETINFO) : `Ok(None)` pour une prise qui n'est pas IP ou un descripteur
/// fermé entre-temps, `Err` pour une réponse d'une autre taille que `socket_fdinfo`.
fn prise(pid: c_int, fd: c_int) -> Result<Option<PriseNoyau>, ()> {
    let mut tampon = vec![0u8; size_of::<darwin::SocketFdinfo>()];
    let taille = c_int::try_from(tampon.len()).map_err(|_| ())?;
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
    match usize::try_from(lus) {
        Ok(0) => Ok(None),
        Ok(n) if n == tampon.len() => Ok(darwin::lire_socket_fdinfo(&tampon)),
        _ => Err(()),
    }
}

/// Les prises réseau de tous les processus lisibles. `None` : la liste des processus ne se lit pas, les descripteurs
/// de Vanguard lui-même ne se lisent pas (le noyau refuse alors tout), ou des prises ont répondu sous une autre forme
/// sans qu'aucune ne se lise : la lecture native est muette, et l'appelant passe à lsof.
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
            let x = match prise(p, fd) {
                Ok(Some(x)) => x,
                Ok(None) => continue,
                Err(()) => {
                    lues.illisibles += 1;
                    continue;
                }
            };
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
    (lues.illisibles == 0 || !lues.prises.is_empty()).then_some(lues)
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
    Some(darwin::lire_routes(&sysctl_mib(&mut mib, 64 << 20, true)?))
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
    // Vide : CFDataGetBytePtr peut rendre un pointeur nul, que bytes() prendrait pour une tranche.
    if d.is_empty() {
        return Some(OptionsNvram::Posees(String::new()));
    }
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
    // getmntinfo rend un tableau qu'il garde dans la bibliothèque et réécrit au prochain appel : un seul fil à la
    // fois, de l'appel à la fin de la copie.
    static VERROU: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _garde = VERROU.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut tableau: *mut libc::statfs = std::ptr::null_mut();
    // SAFETY : getmntinfo fait pointer `tableau` sur un tableau qu'il garde lui-même (à ne pas libérer) et rend son
    // nombre d'éléments (0 : échec).
    let n = unsafe { libc::getmntinfo(&raw mut tableau, libc::MNT_NOWAIT) };
    let n = usize::try_from(n).ok().filter(|&n| n > 0 && n < 100_000)?;
    if tableau.is_null() {
        return None;
    }
    // SAFETY : `n` éléments valides à partir de `tableau`, d'après getmntinfo, lus et copiés sous le verrou, avant
    // tout autre appel de ce module qui le réécrirait.
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

/// Tests d'oracle : la lecture native contre l'outil d'Apple qui fait foi, sur le Mac de GitHub (`cargo test` de
/// .github/workflows/macos.yml). C'est leur passage qui autorise, plus tard, à retirer l'outil gardé en secours.
#[cfg(test)]
mod oracles {
    use std::process::Command;

    use super::*;

    fn outil(programme: &str, args: &[&str]) -> Option<String> {
        crate::commande::lancer(Command::new(programme).args(args).env("LC_ALL", "C"), 60)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    }

    /// Ce processus, son parent et launchd : mêmes parent, compte, heure de démarrage et programme que `ps`.
    #[test]
    fn processus_contre_ps() {
        let natifs = processus(true).expect("liste native des processus");
        let moi = std::process::id();
        let parent = natifs
            .iter()
            .find(|p| p.pid == moi)
            .map(|p| p.ppid)
            .expect("Vanguard dans la liste");
        for pid in [moi, parent, 1] {
            let p = natifs.iter().find(|p| p.pid == pid).expect("processus stable vu");
            let ps = outil("ps", &["-o", "ppid=,uid=,lstart=", "-p", &pid.to_string()]).expect("ps");
            let mots: Vec<&str> = ps.split_whitespace().collect();
            assert_eq!(mots[0].parse::<u32>().unwrap(), p.ppid, "parent de {pid}");
            assert_eq!(mots[1].parse::<u32>().unwrap(), p.uid, "compte de {pid}");
            // « Sat Oct 24 10:00:00 2026 », à l'heure locale : comparé à la seconde près.
            let lstart = mots[2..7].join(" ");
            let lu = chrono::NaiveDateTime::parse_from_str(&lstart, "%a %b %d %H:%M:%S %Y").expect("lstart");
            let (s, _) = p.debut.expect("heure de démarrage native");
            let local = chrono::DateTime::from_timestamp(s, 0)
                .unwrap()
                .with_timezone(&chrono::Local)
                .naive_local();
            assert!((local - lu).num_seconds().abs() <= 1, "{pid} : {local} contre {lu}");
        }
        // Le programme et les arguments de ce processus.
        let p = natifs.iter().find(|p| p.pid == moi).unwrap();
        let args = outil("ps", &["-ww", "-o", "args=", "-p", &moi.to_string()]).unwrap();
        assert_eq!(p.arguments.as_ref().unwrap().join(" "), args.trim());
        // Le même fichier (appareil et nœud), quel que soit le chemin qui y mène (liens, firmlinks de macOS).
        {
            use std::os::unix::fs::MetadataExt;
            let lu = std::fs::metadata(p.chemin.as_deref().expect("chemin natif")).unwrap();
            let attendu = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
            assert_eq!((lu.dev(), lu.ino()), (attendu.dev(), attendu.ino()), "{:?}", p.chemin);
        }
        // Tous les numéros de ps (moins les zombies, que le noyau ne décrit plus, et ceux nés ou morts entre les deux
        // lectures) sont dans la liste native.
        let ps: Vec<u32> = outil("ps", &["-axo", "pid=,stat="])
            .unwrap()
            .lines()
            .filter_map(|l| {
                let (pid, etat) = l.trim().split_once(char::is_whitespace)?;
                (!etat.trim_start().starts_with('Z')).then(|| pid.parse().ok())?
            })
            .collect();
        let apres: Vec<u32> = pids().unwrap();
        let manquants: Vec<u32> = ps
            .iter()
            .filter(|p| !natifs.iter().any(|n| n.pid == **p) && apres.contains(p))
            .copied()
            .collect();
        assert!(
            manquants.len() <= 3,
            "processus de ps absents de la lecture native : {manquants:?}"
        );
    }

    /// pgrep -x et la recherche native par nom court disent la même chose ; les enfants de launchd aussi.
    #[test]
    fn noms_et_enfants_contre_pgrep() {
        for nom in ["launchd", "nexistepasvanguard"] {
            let pgrep = crate::commande::lancer(Command::new("pgrep").args(["-x", nom]), 20)
                .unwrap()
                .code
                == Some(0);
            assert_eq!(en_marche(nom), Some(pgrep), "{nom}");
        }
        let natifs: Vec<u32> = enfants(1).expect("enfants de launchd");
        let pgrep: Vec<u32> = outil("pgrep", &["-P", "1"])
            .unwrap()
            .split_whitespace()
            .filter_map(|p| p.parse().ok())
            .collect();
        let communs = pgrep.iter().filter(|p| natifs.contains(p)).count();
        assert!(
            communs + 3 >= pgrep.len(),
            "{} de {} enfants de launchd",
            communs,
            pgrep.len()
        );
    }

    /// Des prises ouvertes par ce test (TCP IPv4 en écoute et établie, TCP IPv6 en écoute sur ::1 et sur toutes les
    /// adresses, UDP IPv4 et IPv6) : la lecture native les voit toutes, avec ce processus, comme lsof ; netstat voit
    /// les mêmes ports. Puis chaque prise IP que lsof donne pour ce processus est dans la lecture native (les autres
    /// tests du même processus en ouvrent et en ferment : seules celles encore là après coup comptent).
    #[test]
    fn prises_contre_lsof_et_netstat() {
        use std::net::{TcpListener, TcpStream, UdpSocket};
        let serveur = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = serveur.local_addr().unwrap().port();
        let client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (_accepte, _) = serveur.accept().unwrap();
        let local = client.local_addr().unwrap().port();
        let boucle6 = TcpListener::bind("[::1]:0").unwrap();
        let tout6 = TcpListener::bind("[::]:0").unwrap();
        let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
        let udp6 = UdpSocket::bind("[::1]:0").unwrap();
        let (p6, pt6) = (boucle6.local_addr().unwrap().port(), tout6.local_addr().unwrap().port());
        let (pu4, pu6) = (udp4.local_addr().unwrap().port(), udp6.local_addr().unwrap().port());
        let lues = prises().expect("prises natives");
        assert_eq!(lues.illisibles, 0, "réponses d'une autre taille que socket_fdinfo");
        let moi = std::process::id();
        let a_moi: Vec<&PriseNoyau> = lues
            .prises
            .iter()
            .filter(|(p, ..)| *p == moi)
            .map(|(_, _, x)| x)
            .collect();
        let ecoute = |port: u16, ip: &str| {
            a_moi
                .iter()
                .any(|x| x.tcp && x.etat == darwin::TSI_S_LISTEN && x.port_local == port && x.locale.to_string() == ip)
        };
        assert!(ecoute(port, "127.0.0.1"), "{a_moi:?}");
        assert!(ecoute(p6, "::1"), "{a_moi:?}");
        assert!(
            a_moi
                .iter()
                .any(|x| x.tcp && x.port_local == pt6 && x.locale.is_unspecified()),
            "{a_moi:?}"
        );
        assert!(
            a_moi.iter().any(|x| x.tcp
                && x.etat == darwin::TSI_S_ESTABLISHED
                && x.port_local == local
                && x.port_distant == port)
        );
        assert!(
            a_moi
                .iter()
                .any(|x| !x.tcp && x.port_local == pu4 && x.locale.to_string() == "127.0.0.1")
        );
        assert!(
            a_moi
                .iter()
                .any(|x| !x.tcp && x.port_local == pu6 && x.locale.to_string() == "::1")
        );
        let lsof = outil("lsof", &["-nP", "-a", "-p", &moi.to_string(), "-i"]).expect("lsof");
        assert!(lsof.contains(&format!("127.0.0.1:{port} (LISTEN)")), "{lsof}");
        assert!(
            lsof.contains(&format!("127.0.0.1:{local}->127.0.0.1:{port} (ESTABLISHED)")),
            "{lsof}"
        );
        assert!(lsof.contains(&format!("[::1]:{p6} (LISTEN)")), "{lsof}");
        // Chaque prise de lsof (« TCP 127.0.0.1:5000 (LISTEN) », « UDP [::1]:5353 ») : son port local est vu par le
        // noyau, si elle existe encore après la lecture native.
        let apres = prises().unwrap();
        let ports_natifs: Vec<u16> = a_moi.iter().map(|x| x.port_local).collect();
        for l in lsof.lines().skip(1) {
            let Some(nom) = l.split_whitespace().rev().find(|m| m.contains(':')) else {
                continue;
            };
            let locale = nom.split("->").next().unwrap_or_default();
            let Some(p) = locale.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()) else {
                continue;
            };
            let encore = apres.prises.iter().any(|(q, _, x)| *q == moi && x.port_local == p);
            assert!(
                !encore || ports_natifs.contains(&p),
                "{l} : absente de la lecture native"
            );
        }
        let netstat = outil("netstat", &["-an", "-p", "tcp"]).unwrap();
        assert!(netstat.contains(&format!("127.0.0.1.{port}")), "{netstat}");
    }

    /// Passerelle et voisins : les mêmes que `route -n get default` et `arp -an`.
    #[test]
    fn routes_contre_route_et_arp() {
        let route = outil("route", &["-n", "get", "default"]);
        let attendue = route.as_deref().and_then(|r| {
            r.lines()
                .find_map(|l| l.trim().strip_prefix("gateway:"))
                .and_then(|g| g.trim().parse::<Ipv4Addr>().ok())
        });
        assert_eq!(passerelle(), attendue, "{route:?}");
        let arp = outil("arp", &["-an"]).unwrap_or_default();
        let complets = || arp.lines().filter(|l| !l.contains("incomplete"));
        // Une table vide se lit aussi « rien » (None) : un Mac sans aucun voisin n'a rien à comparer.
        let Some(voisins) = voisins() else {
            if complets().next().is_none() {
                crate::essais::saute("aucun voisin dans la table ARP de ce Mac");
                return;
            }
            panic!("table ARP native illisible, alors qu'arp -an en voit : {arp}");
        };
        for l in complets() {
            // « ? (192.168.64.1) at 1a:2b:3c:4d:5e:6f on en0 ifscope [ethernet] »
            let Some(ip) = l
                .split_once('(')
                .and_then(|(_, r)| r.split_once(')'))
                .and_then(|(ip, _)| ip.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            assert!(
                voisins.iter().any(|v| v.ip == ip),
                "{ip} vu par arp, pas par la lecture native"
            );
        }
    }

    /// SIP : la configuration lue (0 = entière) dit la même chose que `csrutil status`.
    #[test]
    fn sip_contre_csrutil() {
        let config = sip().expect("csr_get_active_config");
        let texte = outil("csrutil", &["status"]).expect("csrutil");
        let entier = texte.contains("status: enabled.");
        assert_eq!(config == 0, entier, "config 0x{config:x} ; csrutil : {texte}");
    }

    /// Les options de démarrage : la NVRAM lue comme `nvram boot-args`, et kern.bootargs comme `sysctl -n`.
    #[test]
    fn options_de_demarrage_contre_nvram_et_sysctl() {
        let nvram = crate::commande::lancer(Command::new("nvram").arg("boot-args"), 20).unwrap();
        let Some(natif) = options_prochain_demarrage() else {
            // Une machine sans NVRAM lisible (certaines machines virtuelles) : nvram le dit aussi.
            assert!(
                nvram.erreurs.contains("not supported"),
                "{} {}",
                nvram.sortie,
                nvram.erreurs
            );
            return crate::essais::saute("NVRAM absente de ce Mac");
        };
        match natif {
            OptionsNvram::Absentes => {
                assert_ne!(nvram.code, Some(0), "{}", nvram.sortie);
                assert!(nvram.erreurs.contains("not found"), "{}", nvram.erreurs);
            }
            OptionsNvram::Posees(t) => {
                assert_eq!(
                    nvram.sortie.trim().strip_prefix("boot-args").map(str::trim),
                    Some(t.trim())
                );
            }
        }
        let sysctl = outil("sysctl", &["-n", "kern.bootargs"]).unwrap();
        assert_eq!(options_demarrage_en_cours().as_deref(), Some(sysctl.trim()));
    }

    /// L'échange et la mémoire libre : les mêmes que `sysctl vm.swapusage` et `memory_pressure`.
    #[test]
    fn echange_et_memoire_contre_sysctl() {
        let (total, _) = echange().expect("vm.swapusage");
        let texte = outil("sysctl", &["-n", "vm.swapusage"]).unwrap();
        let mo: f64 = texte
            .split("total = ")
            .nth(1)
            .unwrap()
            .split('M')
            .next()
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        #[allow(clippy::cast_precision_loss)]
        let natif = total as f64 / 1_048_576.0;
        assert!((natif - mo).abs() < 1.0, "{natif} contre {texte}");
        let niveau = super::super::sysctl_nombre("kern.memorystatus_level").expect("kern.memorystatus_level");
        let pression = outil("memory_pressure", &[]).unwrap();
        let pct: u64 = pression
            .lines()
            .find_map(|l| l.strip_prefix("System-wide memory free percentage:"))
            .unwrap()
            .trim()
            .trim_end_matches('%')
            .parse()
            .unwrap();
        assert!(niveau.abs_diff(pct) <= 5, "{niveau} contre {pct}");
    }

    /// L'identifiant de l'ordinateur : la chaîne de gethostuuid est exactement l'IOPlatformUUID d'ioreg. Tant que ce
    /// test n'a pas passé sur le Mac de GitHub, l'empreinte de la machine reste calculée sur la sortie d'ioreg.
    #[test]
    fn uuid_contre_ioreg() {
        let ioreg = outil("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).unwrap();
        let attendu = ioreg
            .lines()
            .find(|l| l.contains("\"IOPlatformUUID\""))
            .and_then(|l| l.rsplit('"').nth(1))
            .unwrap()
            .to_string();
        assert_eq!(uuid_machine().as_deref(), Some(attendu.as_str()));
    }

    /// Les volumes montés : ceux de `mount`.
    #[test]
    fn montages_contre_mount() {
        // mount d'abord : un volume monté entre les deux lectures (image de simulateur) est alors vu par le noyau.
        let mount = outil("mount", &[]).unwrap();
        let natifs = montages().expect("getmntinfo");
        for l in mount.lines() {
            // « /dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled) »
            let Some((source, reste)) = l.split_once(" on ") else {
                continue;
            };
            let Some((point, options)) = reste.rsplit_once(" (") else {
                continue;
            };
            // Démonté entre les deux lectures : rien à comparer.
            let Some(m) = natifs.iter().find(|m| m.point == point) else {
                continue;
            };
            assert_eq!(m.source, source);
            assert_eq!(m.lecture_seule, options.contains("read-only"), "{l}");
        }
    }
}
