//! Les garde-fous du blocage, en fonctions pures (testées sous Linux et sous Wine) : ce qui ne s'arrête, ne se met
//! en quarantaine ni ne se bloque jamais, même quand une liste ou une règle le désigne. Ce qu'ils refusent reste une
//! alerte, avec sa raison.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::machine::regles::Os;
use crate::tr;

/// Le noyau ou Idle (0), init, systemd ou launchd (1), System de Windows (4).
const PID_CRITIQUES: [u32; 3] = [0, 1, 4];

/// Les processus dont l'arrêt fait tomber le système ou la session (écran bleu, déconnexion), ou coupe une connexion
/// à distance : jamais arrêtés, même quand un programme ailleurs prend leur nom (une alerte le dit).
const NOMS_CRITIQUES: &[&str] = &[
    // Windows.
    "system",
    "idle",
    "registry",
    "secure system",
    "memory compression",
    "smss",
    "csrss",
    "wininit",
    "winlogon",
    "services",
    "lsass",
    "lsaiso",
    "svchost",
    "dwm",
    "fontdrvhost",
    "msmpeng",
    // Linux et macOS.
    "systemd",
    "init",
    "kthreadd",
    "launchd",
    "kernel_task",
    "loginwindow",
    "windowserver",
    // Les sessions à distance en cours, de part et d'autre.
    "sshd",
    "sshd-session",
    "xrdp",
    "xrdp-sesman",
];

/// Le nom d'un processus comparé aux noms critiques : sans dossier, sans « .exe », en minuscules.
fn nom_simple(nom: &str) -> String {
    let fichier = nom.rsplit(['/', '\\']).next().unwrap_or(nom).trim().to_lowercase();
    fichier.strip_suffix(".exe").unwrap_or(&fichier).to_string()
}

/// Un programme du système : il ne s'arrête ni ne se met en quarantaine (une alerte seulement). Un chemin qui remonte
/// (« .. ») ne se juge pas : il est tenu pour du système.
pub(crate) fn dossier_systeme(chemin: &str, os: Os) -> bool {
    match os {
        Os::Windows => {
            let c = chemin.to_lowercase().replace('/', "\\");
            let c = c.strip_prefix(r"\\?\").unwrap_or(&c);
            if c.contains(r"\..\") {
                return true;
            }
            // « C:\Windows\… » quelle que soit la lettre du disque, et l'antivirus de Microsoft.
            let sans_lecteur = c
                .get(1..)
                .filter(|_| c.chars().next().is_some_and(|l| l.is_ascii_alphabetic()));
            sans_lecteur.is_some_and(|reste| {
                [
                    r":\windows\",
                    r":\program files\windows defender\",
                    r":\programdata\microsoft\windows defender\",
                ]
                .iter()
                .any(|d| reste.starts_with(d))
            })
        }
        Os::Linux | Os::MacOs | Os::Tous => {
            if chemin.contains("/../") || chemin.ends_with("/..") {
                return true;
            }
            let communs = [
                "/usr/bin/",
                "/usr/sbin/",
                "/usr/lib/",
                "/usr/lib64/",
                "/usr/libexec/",
                "/usr/share/",
                "/bin/",
                "/sbin/",
                "/lib/",
                "/lib64/",
            ];
            let mac = ["/System/", "/Library/Apple/", "/private/var/db/"];
            communs.iter().any(|d| chemin.starts_with(d))
                || (os == Os::MacOs && mac.iter().any(|d| chemin.starts_with(d)))
        }
    }
}

/// Pourquoi ce processus ne doit jamais être arrêté, ou `None`. `intouchables` : Vanguard, ce qu'il a lancé et ce qui
/// le fait tourner (son terminal, sa session), d'après `chasse::en_marche`. Sans chemin lisible, rien ne s'arrête à
/// l'aveugle : un programme du système ne se reconnaîtrait pas.
pub(crate) fn processus_intouchable(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
    os: Os,
) -> Option<&'static str> {
    processus_intouchable_selon(pid, nom, chemin, intouchables, os, &chemin_long)
}

/// `processus_intouchable`, le chemin long (`long`) donné : les essais en posent un sans Windows.
fn processus_intouchable_selon(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
    os: Os,
    long: &dyn Fn(&str) -> Option<String>,
) -> Option<&'static str> {
    if PID_CRITIQUES.contains(&pid) || NOMS_CRITIQUES.contains(&nom_simple(nom).as_str()) {
        return Some(tr!(
            "processus critique du système : une alerte seulement",
            "critical system process: an alert only"
        ));
    }
    if intouchables.contains(&pid) || pid == std::process::id() {
        return Some(tr!(
            "Vanguard lui-même, ce qu'il a lancé ou ce qui le fait tourner (terminal, session)",
            "Vanguard itself, what it started or what runs it (terminal, session)"
        ));
    }
    let Some(chemin) = chemin else {
        return Some(tr!(
            "chemin du programme illisible sans droits d'administrateur : rien n'est arrêté à l'aveugle",
            "program path unreadable without administrator rights: nothing is stopped blindly"
        ));
    };
    jugees_les_deux_formes(chemin, os, long, |c| {
        dossier_systeme(c, os).then_some(tr!(
            "programme du système : une alerte seulement",
            "system program: an alert only"
        ))
    })
}

/// Le chemin long canonique demandé à Windows ; ailleurs, aucun (les noms courts 8.3 n'existent que sous Windows).
fn chemin_long(chemin: &str) -> Option<String> {
    #[cfg(windows)]
    {
        crate::machine::windows::environnement::chemin_long(chemin)
    }
    #[cfg(not(windows))]
    {
        let _ = chemin;
        None
    }
}

/// Un nom court 8.3 de Windows dans le chemin (« JEANDU~1 », « PROGRA~2.EXE ») : un « ~ » suivi d'un chiffre.
fn a_un_nom_court(chemin: &str) -> bool {
    chemin.split(['\\', '/']).any(|nom| {
        nom.char_indices()
            .any(|(i, c)| c == '~' && nom[i + 1..].starts_with(|d: char| d.is_ascii_digit()))
    })
}

/// Le jugement `juge` du chemin tel qu'il est écrit, puis, sous Windows, de son chemin long (GetLongPathNameW) : les
/// règles sont écrites en noms longs, et « C:\PROGRA~1\WINDOW~1\MsMpEng.exe » ou « C:\Users\JEANDU~1\… » leur
/// échapperaient. Protégé sous l'une ou l'autre forme : refusé. Un nom court dont le chemin long ne se lit pas : refusé
/// aussi, rien ne se juge à l'aveugle (défense D6a).
fn jugees_les_deux_formes(
    chemin: &str,
    os: Os,
    long: &dyn Fn(&str) -> Option<String>,
    juge: impl Fn(&str) -> Option<&'static str>,
) -> Option<&'static str> {
    if let Some(raison) = juge(chemin) {
        return Some(raison);
    }
    if os != Os::Windows {
        return None;
    }
    match long(chemin) {
        Some(long) => juge(&long),
        None if a_un_nom_court(chemin) => Some(tr!(
            "chemin court (8.3) dont le chemin long ne se lit pas : rien n'est fait à l'aveugle",
            "short (8.3) path whose long path cannot be read: nothing is done blindly"
        )),
        None => None,
    }
}

/// Pourquoi ce processus ne doit jamais être GELÉ, ou `None`. Mêmes garde-fous que l'arrêt, sauf la règle « programme
/// du système » : geler python3 ou un outil du système est permis (c'est réversible et rien n'est effacé), l'arrêter
/// non. Jamais le noyau, init/systemd, le compositeur, la session, un terminal ou un shell (PID et noms critiques), ni
/// Vanguard et ce qu'il fait tourner : un bureau gelé ne pourrait plus cliquer « Reprendre ». Sans chemin lisible,
/// on ne gèle pas à l'aveugle.
#[cfg(target_os = "linux")]
pub(crate) fn processus_gelable(
    pid: u32,
    nom: &str,
    chemin: Option<&str>,
    intouchables: &HashSet<u32>,
) -> Option<&'static str> {
    if PID_CRITIQUES.contains(&pid) || NOMS_CRITIQUES.contains(&nom_simple(nom).as_str()) {
        return Some(tr!(
            "processus critique du système : jamais gelé",
            "critical system process: never frozen"
        ));
    }
    if intouchables.contains(&pid) || pid == std::process::id() {
        return Some(tr!(
            "Vanguard lui-même, ce qu'il a lancé ou ce qui le fait tourner (terminal, session)",
            "Vanguard itself, what it started or what runs it (terminal, session)"
        ));
    }
    if chemin.is_none() {
        return Some(tr!(
            "chemin du programme illisible : rien n'est gelé à l'aveugle",
            "program path unreadable: nothing is frozen blindly"
        ));
    }
    None
}

/// Pourquoi ce fichier ne doit jamais être mis en quarantaine, ou `None` : un fichier du système, ou Vanguard.
pub(crate) fn fichier_intouchable(chemin: &str, os: Os, mon_programme: Option<&str>) -> Option<&'static str> {
    fichier_intouchable_selon(chemin, os, mon_programme, &chemin_long)
}

/// `fichier_intouchable`, le chemin long (`long`) donné : les essais en posent un sans Windows. Vanguard aussi se
/// compare sous ses deux formes, lancé qu'il a pu être par un chemin court.
fn fichier_intouchable_selon(
    chemin: &str,
    os: Os,
    mon_programme: Option<&str>,
    long: &dyn Fn(&str) -> Option<String>,
) -> Option<&'static str> {
    let mut miens: Vec<String> = mon_programme.iter().map(|m| (*m).to_string()).collect();
    if os == Os::Windows {
        miens.extend(mon_programme.and_then(long));
    }
    jugees_les_deux_formes(chemin, os, long, |c| {
        let meme = |m: &String| {
            if os == Os::Windows {
                m.eq_ignore_ascii_case(c)
            } else {
                m == c
            }
        };
        if miens.iter().any(meme) {
            return Some(tr!("Vanguard lui-même", "Vanguard itself"));
        }
        dossier_systeme(c, os).then_some(tr!(
            "fichier du système : une alerte seulement",
            "system file: an alert only"
        ))
    })
}

/// Les résolveurs DNS publics les plus courants : les bloquer couperait Internet à toute la maison, même si une liste
/// les citait par erreur.
const DNS_PUBLICS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "45.90.28.0",
    "45.90.30.0",
    "2606:4700:4700::1111",
    "2606:4700:4700::1001",
    "2001:4860:4860::8888",
    "2001:4860:4860::8844",
    "2620:fe::fe",
    "2620:fe::9",
];

/// Une connexion TCP établie, telle que les garde-fous la jugent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Etablie {
    pub distante: IpAddr,
    pub port_local: u16,
    pub port_distant: u16,
    /// Le programme qui la tient, quand il se lit.
    pub programme: Option<String>,
    /// Elle appartient à un autre compte, ou à un compte qui ne se lit pas : le blocage automatique n'y touche pas.
    pub autre_compte: bool,
}

/// Les adresses et les ports que le blocage ne coupe pas, lus une fois par passage.
// `sessions.sessions` : le nom lu partout depuis le début ; le lint ne s'en plaint qu'à partir de trois champs.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Sessions {
    /// Celles des sessions à distance en cours : jamais coupées.
    pub sessions: Vec<IpAddr>,
    /// Celles où une connexion d'un autre compte est établie : jamais coupées tout seul, seulement d'un clic.
    pub autres_comptes: Vec<IpAddr>,
    /// Les ports locaux des sessions en cours (VNC sur 5900, RustDesk…) : jamais fermés en entrée pendant qu'elles
    /// durent, une règle Block coupant aussi ce qui est établi.
    pub ports_locaux: Vec<u16>,
}

/// Pourquoi cette adresse ne doit pas être bloquée en sortie, ou `None`. `sessions` : ce que les connexions en cours
/// interdisent de couper ; `None` : illisibles, et rien n'est bloqué sans les connaître. `automatique` : le blocage se
/// fait sans clic, et ne touche alors jamais une adresse où un autre compte a une connexion établie.
pub(crate) fn adresse_intouchable(ip: IpAddr, sessions: Option<&Sessions>, automatique: bool) -> Option<&'static str> {
    let ip = ip.to_canonical();
    if !crate::socle::adresses::sur_internet(ip) {
        return Some(tr!(
            "adresse du réseau local ou de cet ordinateur : jamais bloquée",
            "address of the local network or of this computer: never blocked"
        ));
    }
    if DNS_PUBLICS.iter().any(|d| d.parse::<IpAddr>().is_ok_and(|d| d == ip)) {
        return Some(tr!(
            "serveur DNS public : le bloquer couperait Internet",
            "public DNS server: blocking it would cut the Internet"
        ));
    }
    match sessions {
        None => Some(tr!(
            "connexions à distance en cours illisibles : rien n'est bloqué sans savoir si l'une passe par là",
            "remote connections in progress unreadable: nothing is blocked without knowing whether one goes there"
        )),
        Some(s) if s.sessions.iter().any(|a| a.to_canonical() == ip) => Some(tr!(
            "une connexion à distance en cours (SSH, Bureau à distance, VPN, prise en main) passe par cette adresse : jamais coupée",
            "a remote connection in progress (SSH, Remote Desktop, VPN, remote control) goes through this address: never cut"
        )),
        Some(s) if automatique && s.autres_comptes.iter().any(|a| a.to_canonical() == ip) => Some(tr!(
            "un autre compte a une connexion établie avec cette adresse : jamais coupée toute seule, seulement d'un clic",
            "another account has a connection established with this address: never cut by itself, only with a click"
        )),
        Some(_) => None,
    }
}

/// Les ports de SSH et du Bureau à distance : jamais fermés en entrée, ce serait couper l'accès à distance.
const PORTS_DE_SESSION: [u16; 2] = [22, 3389];

pub(crate) fn port_intouchable(port: u16) -> Option<&'static str> {
    PORTS_DE_SESSION.contains(&port).then_some(tr!(
        "port de SSH ou du Bureau à distance : jamais fermé",
        "SSH or Remote Desktop port: never closed"
    ))
}

/// Pourquoi ce port ne doit pas être fermé en entrée, ou `None` : celui de SSH ou du Bureau à distance, toujours ;
/// celui d'une session à distance en cours (prise en main sur 5900, RustDesk…), tant qu'elle dure ; tout port si les
/// connexions en cours ne se lisent pas (`sessions` à `None`), rien n'étant fermé sans les connaître.
pub(crate) fn port_a_garder(port: u16, sessions: Option<&Sessions>) -> Option<&'static str> {
    port_intouchable(port).or_else(|| match sessions {
        None => Some(tr!(
            "connexions en cours illisibles : aucun port n'est fermé sans savoir s'il porte une session à distance",
            "current connections unreadable: no port is closed without knowing whether it carries a remote session"
        )),
        Some(s) if s.ports_locaux.contains(&port) => Some(tr!(
            "une session à distance passe en ce moment par ce port : pas fermé, pour ne pas la couper",
            "a remote session is going through this port right now: not closed, so as not to cut it"
        )),
        Some(_) => None,
    })
}

/// Les programmes d'accès à distance, de prise en main et de VPN : une connexion établie de l'un d'eux est une
/// session, quel que soit son port (SSH sur 2222, VNC, RustDesk, WireGuard…). Plus les VNC (« vnc* », « *vnc »).
const PROGRAMMES_DE_SESSION: &[&str] = &[
    "sshd",
    "sshd-session",
    "xrdp",
    "xrdp-sesman",
    "rustdesk",
    "anydesk",
    // Windows : Assistance rapide, ConnectWise ScreenConnect, Splashtop ; VPN ZeroTier, GlobalProtect, Cisco Secure
    // Client (AnyConnect), FortiClient.
    "quickassist",
    "screenconnect.clientservice",
    "srservice",
    "zerotier-one",
    "zerotier-one_x64",
    "pangps",
    "vpnagent",
    "fortisslvpndaemon",
    "parsec",
    "parsecd",
    "tailscaled",
    "tailscale",
    "wireguard",
    "wg",
    "wg-quick",
    "openvpn",
    "openvpn-gui",
    "openvpnserv",
    "mstsc",
    "teamviewer",
    "teamviewer_service",
    // Le service de TeamViewer sous Linux.
    "teamviewerd",
    // Les bureaux à distance de KDE et de GNOME, NoMachine, Chrome Remote Desktop, MeshCentral et DWService. Le nom
    // vient de /proc/<pid>/comm, coupé à 15 caractères : « gnome-remote-desktop » s'y lit « gnome-remote-de ».
    "krfb",
    "vino-server",
    "gnome-remote-de",
    "nxserver",
    "nxd",
    "nxnode",
    "remoting_host",
    "chrome-remote-d",
    "meshagent",
    "dwagent",
];

/// `nom` (un nom de programme ou un chemin, « .exe » ou non) est-il un programme d'accès à distance, de prise en main
/// ou de VPN ? Aussi la garde de session du chemin des services (défense D6b).
pub(crate) fn programme_de_session(nom: &str) -> bool {
    let n = nom_simple(nom);
    PROGRAMMES_DE_SESSION.contains(&n.as_str()) || n.starts_with("vnc") || n.ends_with("vnc") || n.contains("vncserver")
}

/// Une connexion établie est-elle une session à distance : le port de SSH ou du Bureau à distance d'un côté ou de
/// l'autre, ou un programme d'accès à distance, de prise en main ou de VPN, quel que soit son port ? `port_rdp` : le
/// PortNumber de RDP-Tcp (`port_rdp_lu`), le port réel du Bureau à distance quand il n'est pas 3389 ; sa connexion
/// est tenue par svchost, qu'aucun nom de programme ne reconnaît : une connexion sur ce port local est une session.
pub(crate) fn est_session(e: &Etablie, port_rdp: Option<u16>) -> bool {
    PORTS_DE_SESSION.contains(&e.port_local)
        || PORTS_DE_SESSION.contains(&e.port_distant)
        || PORTS_WINRM.contains(&e.port_local)
        || port_rdp.is_some_and(|p| p != 0 && e.port_local == p)
        || e.programme.as_deref().is_some_and(programme_de_session)
}

/// Le port du Bureau à distance d'après la valeur PortNumber de RDP-Tcp : `None` si elle manque, vaut 0 ou dépasse
/// un port. 3389 est gardé de toute façon (`PORTS_DE_SESSION`).
#[cfg(any(windows, test))]
pub(crate) fn port_rdp_lu(valeur: Option<u32>) -> Option<u16> {
    valeur.and_then(|n| u16::try_from(n).ok()).filter(|&n| n != 0)
}

/// PortNumber de RDP-Tcp est là mais ne se lit pas (droits, type) : le port réel du Bureau à distance n'est pas sûr.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PortIllisible;

/// Le port du Bureau à distance d'après la lecture de PortNumber : `port_rdp_lu` si elle est lue ou manque
/// (NotFound), `PortIllisible` si elle est là mais ne se lit pas.
#[cfg(any(windows, test))]
pub(crate) fn port_rdp_de(lu: std::io::Result<u32>) -> Result<Option<u16>, PortIllisible> {
    match lu {
        Ok(n) => Ok(port_rdp_lu(Some(n))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PortIllisible),
    }
}

/// Le PortNumber de RDP-Tcp de cet ordinateur ; illisible, aucun (3389 reste gardé).
#[cfg(windows)]
pub(crate) fn port_rdp() -> Option<u16> {
    port_rdp_de(crate::machine::windows::port_bureau_a_distance())
        .ok()
        .flatten()
}

/// WinRM (PowerShell à distance), HTTP et HTTPS : sa connexion est tenue par System (HTTP.sys), qu'aucun nom de
/// programme ne reconnaît ; une connexion entrante sur ces ports est une session.
const PORTS_WINRM: [u16; 2] = [5985, 5986];

/// Les tunnels (VPN) et les clients d'une session sortante : leurs connexions partent de cet ordinateur, et le réseau
/// redémarré ne coupe personne qui y serait entré. Ils restent des sessions pour le blocage (`est_session`).
#[cfg(any(target_os = "linux", test))]
const SORTANTS: &[&str] = &[
    "tailscaled",
    "tailscale",
    "wireguard",
    "wg",
    "wg-quick",
    "openvpn",
    "openvpn-gui",
    "openvpnserv",
    "mstsc",
];

/// Une connexion établie est-elle une session à distance ENTRANTE, qu'un réseau redémarré couperait : SSH ou Bureau
/// à distance sur un port local en écoute (22, 3389 : quelqu'un s'y est connecté), ou un programme de prise en main
/// (sshd sur un autre port, VNC, RustDesk, AnyDesk, TeamViewer…). Ni un VPN ni un client SSH qui part d'ici.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn session_entrante(e: &Etablie, en_ecoute: &[u16]) -> bool {
    (PORTS_DE_SESSION.contains(&e.port_local) && en_ecoute.contains(&e.port_local))
        || e.programme
            .as_deref()
            .is_some_and(|p| programme_de_session(p) && !SORTANTS.contains(&nom_simple(p).as_str()))
}

/// Les ports locaux en écoute d'un fichier de /proc/net (tcp, tcp6) : état 0A.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn en_ecoute_proc(texte: &str) -> Vec<u16> {
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &"0A" {
                return None;
            }
            let (_, port) = champs.get(1)?.split_once(':')?;
            u16::from_str_radix(port, 16).ok()
        })
        .collect()
}

/// Une session à distance entrante est-elle ouverte sur cet ordinateur (`session_entrante`, ou Vanguard lancé
/// depuis SSH) ? `None` : les connexions ne se lisent pas, et l'assistant élevé ne redémarre alors pas le réseau.
#[cfg(target_os = "linux")]
pub(crate) fn session_entrante_ouverte() -> Option<bool> {
    let etablies = lire_etablies()?;
    let mut en_ecoute = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        match std::fs::read_to_string(f) {
            Ok(texte) => en_ecoute.extend(en_ecoute_proc(&texte)),
            // IPv6 coupé au démarrage (ipv6.disable=1) : pas de tcp6, donc rien n'y écoute.
            Err(e) if f.ends_with('6') && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return None,
        }
    }
    let depuis_ssh = std::env::var("SSH_CONNECTION").is_ok_and(|v| client_ssh(&v).is_some());
    Some(depuis_ssh || etablies.iter().any(|e| session_entrante(e, &en_ecoute)))
}

/// Les adresses à ne pas couper, d'après les connexions établies, le client SSH de Vanguard et le port réel du
/// Bureau à distance (`port_rdp`, PortNumber de RDP-Tcp).
pub(crate) fn juger_etablies(etablies: &[Etablie], client: Option<IpAddr>, port_rdp: Option<u16>) -> Sessions {
    let mut s = Sessions::default();
    for e in etablies {
        let ip = e.distante.to_canonical();
        if est_session(e, port_rdp) {
            s.sessions.push(ip);
            s.ports_locaux.push(e.port_local);
        }
        if e.autre_compte {
            s.autres_comptes.push(ip);
        }
    }
    s.sessions.extend(client.map(|c| c.to_canonical()));
    for liste in [&mut s.sessions, &mut s.autres_comptes] {
        liste.sort_unstable();
        liste.dedup();
    }
    s.ports_locaux.sort_unstable();
    s.ports_locaux.dedup();
    s
}

/// L'adresse du client de la session SSH où tourne Vanguard (« SSH_CONNECTION=client port serveur port »), même sur
/// un autre port que 22.
pub(crate) fn client_ssh(valeur: &str) -> Option<IpAddr> {
    valeur
        .split_whitespace()
        .next()?
        .parse::<IpAddr>()
        .ok()
        .map(|a| a.to_canonical())
}

/// Les connexions établies d'un fichier de /proc/net (tcp, tcp6) : « sl locale distante état … uid délai inode »,
/// état 01. `moi` : le compte de Vanguard ; `noms` : le programme de chaque prise (inode), quand il se lit.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn etablies_proc(texte: &str, moi: u32, noms: &std::collections::HashMap<u64, String>) -> Vec<Etablie> {
    let point = |t: &str| -> Option<(IpAddr, u16)> {
        let (adresse, port) = t.split_once(':')?;
        Some((
            crate::protection::sortantes::adresse_proc(adresse)?,
            u16::from_str_radix(port, 16).ok()?,
        ))
    };
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &"01" {
                return None;
            }
            let (_, port_local) = point(champs.get(1)?)?;
            let (distante, port_distant) = point(champs.get(2)?)?;
            let compte = champs.get(7).and_then(|u| u.parse::<u32>().ok());
            let inode = champs.get(9).and_then(|i| i.parse::<u64>().ok());
            Some(Etablie {
                distante: distante.to_canonical(),
                port_local,
                port_distant,
                programme: inode.and_then(|i| noms.get(&i).cloned()),
                autre_compte: compte != Some(moi),
            })
        })
        .collect()
}

/// Les connexions établies d'une table TCP de Windows (GetExtendedTcpTable, « propriétaire, toutes »), telle que la
/// rend `machine::windows::connexions::table_tcp` (la forme est lue par `connexions::lire_tcp`) : MIB_TCPROW_OWNER_PID
/// de 24 octets, MIB_TCP6ROW_OWNER_PID de 56. → (port local, adresse distante, port distant, processus).
#[cfg(any(windows, test))]
pub(crate) fn etablies_table(octets: &[u8], ipv6: bool) -> Vec<(u16, IpAddr, u16, u32)> {
    let mot = |o: &[u8], i: usize| o.get(i..)?.first_chunk::<4>().map(|m| u32::from_ne_bytes(*m));
    let port = |o: &[u8], i: usize| o.get(i..)?.first_chunk::<2>().map(|m| u16::from_be_bytes(*m));
    let (taille, port_local, adresse, port_distant, etat, processus) = if ipv6 {
        (56, 20, 24, 44, 48, 52)
    } else {
        (24, 8, 12, 16, 0, 20)
    };
    let Some(nombre) = mot(octets, 0) else {
        return Vec::new();
    };
    octets
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(taille)
        .take(usize::try_from(nombre).unwrap_or(usize::MAX))
        .filter(|l| mot(l, etat) == Some(5))
        .filter_map(|l| {
            let distante = if ipv6 {
                IpAddr::from(<[u8; 16]>::try_from(l.get(adresse..adresse + 16)?).ok()?)
            } else {
                IpAddr::from(<[u8; 4]>::try_from(l.get(adresse..adresse + 4)?).ok()?)
            };
            Some((
                port(l, port_local)?,
                distante.to_canonical(),
                port(l, port_distant)?,
                mot(l, processus)?,
            ))
        })
        .collect()
}

/// « 192.168.1.5.22 » (netstat de macOS) ou « 192.168.1.5:22 », « [2001:db8::7]:443 » (lsof) → (adresse, port).
#[cfg(any(target_os = "macos", test))]
fn point_texte(t: &str, separateur: char) -> Option<(IpAddr, u16)> {
    let (ip, port) = t.rsplit_once(separateur)?;
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    Some((
        ip.split('%').next()?.parse::<IpAddr>().ok()?.to_canonical(),
        port.parse().ok()?,
    ))
}

/// Les connexions établies sous macOS : toutes d'après `netstat -anp tcp` (« tcp4 0 0 192.168.1.5.22
/// 192.168.1.20.51234 ESTABLISHED »), et leur programme d'après `lsof -F pcn` (« p », « c », « n
/// locale->distante »), qui ne voit que celles de ce compte : une connexion que lsof ne voit pas est d'un autre.
#[cfg(test)]
pub(crate) fn etablies_macos(netstat: &str, lsof: &str) -> Vec<Etablie> {
    etablies_avec(netstat, &etablies_lsof(lsof))
}

/// Les connexions de ce compte d'après `lsof -F pcn` : (programme, port local, adresse distante, port distant).
#[cfg(any(target_os = "macos", test))]
fn etablies_lsof(lsof: &str) -> Vec<(String, u16, IpAddr, u16)> {
    let mut a_moi: Vec<(String, u16, IpAddr, u16)> = Vec::new();
    let mut programme = String::new();
    for l in lsof.lines() {
        let mut lettres = l.chars();
        match lettres.next() {
            Some('c') => programme = lettres.as_str().to_string(),
            Some('n') => {
                if let Some((locale, distante)) = lettres.as_str().split_once("->")
                    && let (Some((_, pl)), Some((ip, pd))) = (point_texte(locale, ':'), point_texte(distante, ':'))
                {
                    a_moi.push((programme.clone(), pl, ip, pd));
                }
            }
            _ => {}
        }
    }
    a_moi
}

/// Toutes les connexions établies de `netstat -anp tcp`, chacune avec son programme quand elle est dans `a_moi` (les
/// connexions lues de ce compte) ; les autres sont d'un autre compte.
#[cfg(any(target_os = "macos", test))]
fn etablies_avec(netstat: &str, a_moi: &[(String, u16, IpAddr, u16)]) -> Vec<Etablie> {
    netstat
        .lines()
        .filter(|l| l.contains("ESTABLISHED"))
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            let (_, port_local) = point_texte(mots.get(3)?, '.')?;
            let (distante, port_distant) = point_texte(mots.get(4)?, '.')?;
            let mien = a_moi
                .iter()
                .find(|(_, pl, ip, pd)| *pl == port_local && *ip == distante && *pd == port_distant);
            Some(Etablie {
                distante,
                port_local,
                port_distant,
                programme: mien.map(|(p, ..)| p.clone()),
                autre_compte: mien.is_none(),
            })
        })
        .collect()
}

/// Ce que les connexions en cours interdisent de couper sur cet ordinateur : les sessions à distance, entrantes comme
/// sortantes, celle du client SSH de Vanguard, et les adresses des connexions d'autres comptes. `None` : la table des
/// connexions ne se lit pas, ou le port réel du Bureau à distance non plus (`port_rdp_de`).
pub(crate) fn sessions_a_distance() -> Option<Sessions> {
    #[cfg(windows)]
    let port = port_rdp_de(crate::machine::windows::port_bureau_a_distance()).ok()?;
    #[cfg(not(windows))]
    let port = None;
    let etablies = lire_etablies()?;
    let client = std::env::var("SSH_CONNECTION").ok().as_deref().and_then(client_ssh);
    Some(juger_etablies(&etablies, client, port))
}

#[cfg(target_os = "linux")]
fn lire_etablies() -> Option<Vec<Etablie>> {
    let noms: std::collections::HashMap<u64, String> = crate::protection::sortantes::proprietaires()
        .into_iter()
        .filter_map(|(inode, pid)| {
            let nom = crate::socle::processus::nom_court(pid)?;
            Some((inode, nom.trim_end().to_string()))
        })
        .collect();
    let moi = crate::socle::euid();
    let mut lisible = false;
    let mut etablies = Vec::new();
    for f in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(t) = std::fs::read_to_string(f) {
            lisible = true;
            etablies.extend(etablies_proc(&t, moi, &noms));
        }
    }
    lisible.then_some(etablies)
}

#[cfg(windows)]
fn lire_etablies() -> Option<Vec<Etablie>> {
    use crate::machine::windows::processus;
    let v4 = crate::protection::sortantes::table_tcp(2).map(|t| etablies_table(&t, false));
    let v6 = crate::protection::sortantes::table_tcp(23).map(|t| etablies_table(&t, true));
    if v4.is_none() && v6.is_none() {
        return None;
    }
    let lignes: Vec<(u16, IpAddr, u16, u32)> = v4.into_iter().chain(v6).flatten().collect();
    let noms: std::collections::HashMap<u32, String> = processus::liste().into_iter().map(|p| (p.pid, p.nom)).collect();
    let moi = processus::compte_de(std::process::id());
    let mut comptes: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    Some(
        lignes
            .into_iter()
            .map(|(port_local, distante, port_distant, pid)| {
                let compte = comptes.entry(pid).or_insert_with(|| processus::compte_de(pid));
                Etablie {
                    distante,
                    port_local,
                    port_distant,
                    programme: noms.get(&pid).cloned(),
                    // Un compte qui ne se lit pas (System, un autre compte sans droits) compte comme un autre.
                    autre_compte: moi.is_empty() || compte.is_empty() || !compte.eq_ignore_ascii_case(&moi),
                }
            })
            .collect(),
    )
}

/// netstat fait foi pour les connexions de tous les comptes (xinpcb_n est privé) ; celles de ce compte se lisent au
/// noyau (libproc), lsof en secours tant que l'oracle de macos.yml n'a pas prouvé la lecture native.
#[cfg(target_os = "macos")]
fn lire_etablies() -> Option<Vec<Etablie>> {
    use std::process::Command;
    let n = crate::commande::lancer(Command::new("netstat").args(["-anp", "tcp"]), 15).filter(|r| r.code == Some(0))?;
    let natives: Option<Vec<(String, u16, IpAddr, u16)>> = crate::machine::macos::noyau::prises()
        .map(|lues| {
            lues.prises
                .into_iter()
                .filter(|(_, _, p)| p.tcp && p.etat == crate::machine::darwin::TSI_S_ESTABLISHED)
                .map(|(_, nom, p)| (nom, p.port_local, p.distante.to_canonical(), p.port_distant))
                .collect()
        })
        .filter(|l: &Vec<_>| !l.is_empty());
    let a_moi = natives.unwrap_or_else(|| {
        // lsof répond 1 quand il ne trouve rien : alors rien n'est à ce compte.
        let lsof = crate::commande::lancer(
            Command::new("lsof").args(["-nP", "-iTCP", "-sTCP:ESTABLISHED", "-F", "pcn"]),
            20,
        )
        .map(|r| r.sortie)
        .unwrap_or_default();
        etablies_lsof(&lsof)
    });
    Some(etablies_avec(&n.sortie, &a_moi))
}

/// Les hôtes des sessions à distance : SSH (le serveur, et le processus de chaque connexion depuis OpenSSH 9.8),
/// WinRM (PowerShell à distance, winrs), le Bureau à distance (RemoteApp de Windows, xrdp de Linux). Ce qu'ils font
/// tourner EST la session : rien de ce qui descend d'eux n'est arrêté (défense D6a).
const HOTES_DE_SESSION: &[&str] = &[
    "sshd",
    "sshd-session",
    "wsmprovhost",
    "winrshost",
    "rdpinit",
    "rdpshell",
    "xrdp",
    "xrdp-sesman",
];

/// Au-delà, la lignée n'est plus suivie : elle reste incertaine (une boucle de numéros repris ne finit jamais).
const PROFONDEUR_MAX: usize = 64;

/// Un processus de l'instantané, tel que la garde d'ascendance le lit.
pub(crate) struct Fiche {
    pub parent: u32,
    pub nom: String,
    /// L'heure de création, dans l'unité du système (FILETIME sous Windows, tops depuis le démarrage sous Linux,
    /// microsecondes sous macOS) ; `None` : illisible.
    pub creation: Option<u64>,
}

/// Pourquoi ce processus ne doit pas être arrêté parce qu'il descend d'un hôte de session à distance, ou `None`.
/// `fiche` : le processus d'un numéro dans l'instantané (`None` : fini). Un parent n'est le vrai parent que s'il a été
/// créé avant l'enfant : sinon son numéro a été repris par un autre, la chaîne est coupée, et pendant une session à
/// distance (`aucune_session` faux : en cours ou illisible) ce qui ne se prouve pas hors d'elle n'est pas arrêté. Une
/// heure illisible rend la lignée incertaine de même, mais la remontée continue : un hôte plus haut refuse toujours.
pub(crate) fn ascendance_de_session(
    pid: u32,
    fiche: impl Fn(u32) -> Option<Fiche>,
    aucune_session: bool,
) -> Option<&'static str> {
    let incertaine = || {
        (!aucune_session).then(|| {
            tr!(
                "lignée du processus incertaine (numéro repris ou heure illisible) pendant une session à distance : rien n'est arrêté",
                "process lineage uncertain (reused number or unreadable time) during a remote session: nothing is stopped"
            )
        })
    };
    let Some(mut enfant) = fiche(pid) else {
        return Some(tr!(
            "le processus ne se lit plus dans la liste des processus : rien n'est arrêté",
            "the process can no longer be read in the process list: nothing is stopped"
        ));
    };
    let mut courant = pid;
    let mut vus = HashSet::from([pid]);
    let mut douteuse = false;
    for _ in 0..PROFONDEUR_MAX {
        let p = enfant.parent;
        // La racine (Idle, le noyau) : la lignée est lue jusqu'au bout.
        if p == 0 || p == courant {
            return if douteuse { incertaine() } else { None };
        }
        // Une boucle ne vient que de numéros repris.
        if !vus.insert(p) {
            return incertaine();
        }
        // Un parent fini : la lignée s'arrête là, aucun hôte vivant au-dessus par elle.
        let Some(parent) = fiche(p) else {
            return if douteuse { incertaine() } else { None };
        };
        // Même un parent douteux qui porte le nom d'un hôte refuse : la prudence ne coûte qu'un arrêt.
        if HOTES_DE_SESSION.contains(&nom_simple(&parent.nom).as_str()) {
            return Some(tr!(
                "lancé depuis une session à distance (SSH, WinRM, Bureau à distance) : jamais arrêté, une alerte seulement",
                "started from a remote session (SSH, WinRM, Remote Desktop): never stopped, an alert only"
            ));
        }
        match (parent.creation, enfant.creation) {
            // Égal permis : les tops de Linux durent 10 ms, un parent et son enfant peuvent y naître ensemble.
            (Some(a), Some(b)) if a <= b => {}
            // Né après l'enfant : un autre processus a repris le numéro du vrai parent, fini.
            (Some(_), Some(_)) => return incertaine(),
            _ => douteuse = true,
        }
        courant = p;
        enfant = parent;
    }
    incertaine()
}

/// Les sessions lues permettent-elles de dire qu'aucune session à distance n'est en cours ? Illisibles : non.
pub(crate) fn aucune_session(sessions: Option<&Sessions>) -> bool {
    sessions.is_some_and(|s| s.sessions.is_empty())
}

/// Le nom, le parent et l'heure de départ d'un `/proc/<pid>/stat` : le nom entre la première « ( » et la dernière
/// « ) » (il peut en contenir), puis l'état, le parent (2e champ) et le départ (22e champ du fichier).
#[cfg(any(target_os = "linux", test))]
fn fiche_du_stat(stat: &str) -> Option<Fiche> {
    let (avant, apres) = stat.rsplit_once(')')?;
    let nom = avant.split_once('(')?.1.to_string();
    let mut champs = apres.split_whitespace();
    let parent = champs.nth(1)?.parse().ok()?;
    let creation = champs.nth(17).and_then(|c| c.parse().ok());
    Some(Fiche { parent, nom, creation })
}

/// La garde d'ascendance, lue sur ce système : un instantané des processus (Toolhelp32 et GetProcessTimes sous
/// Windows, `/proc` sous Linux, proc_pidinfo sous macOS).
pub(crate) fn lignee_de_session(pid: u32, sessions: Option<&Sessions>) -> Option<&'static str> {
    let aucune = aucune_session(sessions);
    #[cfg(windows)]
    {
        use crate::machine::windows::processus;
        let instantane: std::collections::HashMap<u32, (u32, String)> = processus::liste()
            .into_iter()
            .map(|p| (p.pid, (p.parent, p.nom)))
            .collect();
        ascendance_de_session(
            pid,
            |p| {
                let (parent, nom) = instantane.get(&p)?.clone();
                Some(Fiche {
                    parent,
                    nom,
                    creation: processus::creation(p),
                })
            },
            aucune,
        )
    }
    #[cfg(target_os = "linux")]
    {
        ascendance_de_session(
            pid,
            |p| fiche_du_stat(&std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?),
            aucune,
        )
    }
    #[cfg(target_os = "macos")]
    {
        ascendance_de_session(
            pid,
            |p| {
                let i = super::arret::macos::infos(p)?;
                let nom: Vec<u8> = i
                    .pbi_comm
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c.cast_unsigned())
                    .collect();
                let creation = i
                    .pbi_start_tvsec
                    .checked_mul(1_000_000)?
                    .checked_add(i.pbi_start_tvusec);
                Some(Fiche {
                    parent: i.pbi_ppid,
                    nom: String::from_utf8_lossy(&nom).into_owned(),
                    creation,
                })
            },
            aucune,
        )
    }
}

/// Ce que Windows dit de la signature d'un fichier (défense D6a). Une signature ne fait que REFUSER : aucun geste
/// n'est permis parce qu'un fichier n'est pas signé.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Signature {
    /// Dans un catalogue signé par Microsoft, ou signé par Microsoft dans sa table des certificats ; vérifiée.
    Microsoft,
    /// Non signé, ou par un autre, ou une signature qui ne se vérifie pas (une fausse « Microsoft » comprise).
    Autre,
    /// Le fichier, sa signature ou les catalogues de Windows ne se lisent pas.
    Illisible,
}

/// Pourquoi ce fichier signé ne doit être ni arrêté ni mis en quarantaine, ou `None`.
#[cfg(any(windows, test))]
pub(crate) fn signature_intouchable(s: Signature) -> Option<&'static str> {
    match s {
        Signature::Microsoft => Some(tr!(
            "signé par Microsoft : traité comme du système, une alerte seulement",
            "signed by Microsoft: treated as part of the system, an alert only"
        )),
        Signature::Illisible => Some(tr!(
            "signature du fichier illisible (le fichier ou les catalogues de Windows) : rien n'est fait à l'aveugle",
            "file signature unreadable (the file or the Windows catalogs): nothing is done blindly"
        )),
        Signature::Autre => None,
    }
}

/// Le sujet d'un certificat signataire est-il celui de Microsoft (« O=Microsoft Corporation, CN=Microsoft Windows ») ?
#[cfg(any(windows, test))]
pub(crate) fn sujet_microsoft(sujet: &str) -> bool {
    sujet.to_lowercase().contains("microsoft")
}

/// Un code rendu par WinVerifyTrust dit-il que le fichier ne s'est pas LU (et non qu'il n'est pas signé, ou mal) ?
/// CRYPT_E_FILE_ERROR, et toute erreur de Windows (HRESULT de la famille 7 : accès refusé, partage, mémoire…).
#[cfg(any(windows, test))]
pub(crate) fn verification_illisible(code: i32) -> bool {
    let code = code.cast_unsigned();
    code == 0x8009_2003 || code & 0xFFFF_0000 == 0x8007_0000
}

/// La signature d'un fichier d'après ses deux voies, chacune `Ok(signé Microsoft)` ou `Err` (illisible) : signé
/// Microsoft par l'une suffit ; sinon une voie illisible rend le tout illisible.
#[cfg(any(windows, test))]
pub(crate) fn signature_de(catalogue: Result<bool, ()>, integree: Result<bool, ()>) -> Signature {
    if catalogue == Ok(true) || integree == Ok(true) {
        Signature::Microsoft
    } else if catalogue.is_err() || integree.is_err() {
        Signature::Illisible
    } else {
        Signature::Autre
    }
}

/// La garde de signature, lue sur ce système : sous Windows seulement (ailleurs, aucune signature ne se lit ici).
pub(crate) fn signature_systeme(chemin: &str) -> Option<&'static str> {
    #[cfg(windows)]
    {
        signature_intouchable(crate::machine::windows::signature::lire(std::path::Path::new(chemin)))
    }
    #[cfg(not(windows))]
    {
        let _ = chemin;
        None
    }
}

/// Pourquoi Vanguard administrateur n'écrit pas la quarantaine dans `dossier`, ou `None` (défense D6a). Le dossier
/// local est dans le profil d'un compte, où un programme de ce compte pose d'avance un lien ou une jonction (vers
/// System32) : chaque dossier, de celui de la quarantaine jusqu'à la racine du profil `profil` comprise, doit être un
/// vrai dossier (`lien` : en est-il un ?), et le tout dans ce profil. `absents_permis` : avant leur création, un
/// dossier qui manque encore est permis (il est relu après).
#[cfg(any(windows, test))]
pub(crate) fn destination_de_quarantaine(
    dossier: &std::path::Path,
    profil: &std::path::Path,
    lien: impl Fn(&std::path::Path) -> std::io::Result<bool>,
    absents_permis: bool,
) -> Option<&'static str> {
    use std::path::Component;
    let bas = |p: &std::path::Path| -> Vec<String> {
        p.components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect()
    };
    let (d, p) = (bas(dossier), bas(profil));
    let remonte = dossier
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir));
    if remonte || p.is_empty() || d.len() < p.len() || d.get(..p.len()) != Some(&p[..]) {
        return Some(tr!(
            "la quarantaine n'est pas dans le profil du compte qui a ouvert Vanguard en administrateur : rien n'est déplacé",
            "the quarantine is not inside the profile of the account that opened Vanguard as administrator: nothing is moved"
        ));
    }
    for a in dossier.ancestors().take(d.len() - p.len() + 1) {
        match lien(a) {
            Ok(false) => {}
            Ok(true) => {
                return Some(tr!(
                    "un dossier du chemin de la quarantaine est un lien ou une jonction : Vanguard administrateur n'y écrit pas, rien n'est déplacé",
                    "a folder on the quarantine path is a link or a junction: Vanguard as administrator does not write there, nothing is moved"
                ));
            }
            Err(e) if absents_permis && e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Some(tr!(
                    "un dossier du chemin de la quarantaine ne se lit pas : rien n'est déplacé",
                    "a folder on the quarantine path cannot be read: nothing is moved"
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    /// Garde de signature (défense D6a) : signé Microsoft ou illisible, refusé ; non signé ou autre, rien de plus
    /// n'est permis ni refusé par elle.
    #[test]
    fn signature_ne_fait_que_refuser() {
        assert!(signature_intouchable(Signature::Microsoft).is_some());
        assert!(signature_intouchable(Signature::Illisible).is_some());
        assert_eq!(signature_intouchable(Signature::Autre), None);
        assert_eq!(signature_de(Ok(true), Ok(false)), Signature::Microsoft);
        assert_eq!(signature_de(Ok(false), Ok(true)), Signature::Microsoft);
        // Microsoft par une voie, l'autre illisible : refusé de toute façon.
        assert_eq!(signature_de(Err(()), Ok(true)), Signature::Microsoft);
        assert_eq!(signature_de(Err(()), Ok(false)), Signature::Illisible);
        assert_eq!(signature_de(Ok(false), Err(())), Signature::Illisible);
        assert_eq!(signature_de(Ok(false), Ok(false)), Signature::Autre);
        for sujet in [
            "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows",
            "CN=Microsoft Windows Hardware Compatibility Publisher",
            "cn=MICROSOFT windows publisher",
        ] {
            assert!(sujet_microsoft(sujet), "{sujet}");
        }
        assert!(!sujet_microsoft("C=US, O=Mozilla Corporation, CN=Mozilla Corporation"));
        assert!(!sujet_microsoft(""));
        // Fichier illisible, partage refusé : illisible. Pas de signature, signature fausse ou chaîne non approuvée :
        // une signature qui ne se vérifie pas n'en est pas une.
        for code in [0x8009_2003u32, 0x8007_0005, 0x8007_0020] {
            assert!(verification_illisible(code.cast_signed()), "{code:x}");
        }
        for code in [0x800B_0100u32, 0x8009_6010, 0x800B_0109, 0x800B_0003, 0x800B_0101] {
            assert!(!verification_illisible(code.cast_signed()), "{code:x}");
        }
    }

    /// Garde de la quarantaine écrite en administrateur (défense D6a) : un lien ou une jonction n'importe où entre la
    /// quarantaine et la racine du profil refuse ; hors du profil, ou un « .. », aussi ; un dossier illisible aussi.
    #[test]
    fn quarantaine_jamais_par_un_lien() {
        use std::path::{Path, PathBuf};
        let profil = Path::new("/p/alice");
        let q = profil
            .join("AppData")
            .join("Local")
            .join("vanguard")
            .join("quarantaine");
        // `liens(n)` : seul le dossier nommé `n` est un lien.
        let liens =
            |n: &'static str| move |a: &Path| -> std::io::Result<bool> { Ok(a.file_name().is_some_and(|f| f == n)) };
        assert_eq!(destination_de_quarantaine(&q, profil, liens("aucun"), false), None);
        for lien in ["quarantaine", "vanguard", "Local", "AppData", "alice"] {
            assert!(
                destination_de_quarantaine(&q, profil, liens(lien), false).is_some(),
                "{lien}"
            );
            assert!(
                destination_de_quarantaine(&q, profil, liens(lien), true).is_some(),
                "{lien}"
            );
        }
        // Au-dessus du profil (C:\Users) : pas jugé ici.
        assert_eq!(destination_de_quarantaine(&q, profil, liens("p"), false), None);
        // La casse du profil (Windows ne la distingue pas).
        assert_eq!(
            destination_de_quarantaine(&q, Path::new("/P/ALICE"), liens("aucun"), false),
            None
        );
        // Hors du profil (LOCALAPPDATA redirigé), ou qui remonte.
        let ailleurs = PathBuf::from("/d/vanguard/quarantaine");
        assert!(destination_de_quarantaine(&ailleurs, profil, liens("aucun"), false).is_some());
        let remonte = profil.join("..").join("bob").join("quarantaine");
        assert!(destination_de_quarantaine(&remonte, profil, liens("aucun"), false).is_some());
        assert!(destination_de_quarantaine(&q, Path::new(""), liens("aucun"), false).is_some());
        // Absent : permis seulement avant la création ; illisible : refusé.
        let absent = |a: &Path| -> std::io::Result<bool> {
            if a.ends_with("quarantaine") {
                Err(std::io::ErrorKind::NotFound.into())
            } else {
                Ok(false)
            }
        };
        assert_eq!(destination_de_quarantaine(&q, profil, absent, true), None);
        assert!(destination_de_quarantaine(&q, profil, absent, false).is_some());
        let refuse = |_: &Path| -> std::io::Result<bool> { Err(std::io::ErrorKind::PermissionDenied.into()) };
        assert!(destination_de_quarantaine(&q, profil, refuse, true).is_some());
    }

    /// Un instantané d'essai : (pid, parent, nom, création).
    fn instantane<'a>(v: &'a [(u32, u32, &'a str, Option<u64>)]) -> impl Fn(u32) -> Option<Fiche> + 'a {
        move |p| {
            v.iter().find(|f| f.0 == p).map(|&(_, parent, nom, creation)| Fiche {
                parent,
                nom: nom.to_string(),
                creation,
            })
        }
    }

    /// Garde d'ascendance (défense D6a) : un descendant de sshd, sshd-session, wsmprovhost, winrshost ou de l'hôte
    /// RemoteApp n'est jamais arrêté, à n'importe quelle profondeur ; un processus ordinaire l'est.
    #[test]
    fn descendant_d_une_session_jamais_arrete() {
        for hote in [
            "sshd",
            "sshd-session.exe",
            "wsmprovhost.exe",
            "WinRSHost.exe",
            "rdpinit.exe",
            "rdpshell.exe",
            "xrdp-sesman",
        ] {
            let v = [
                (4, 0, "System", Some(1)),
                (600, 4, "services", Some(2)),
                (700, 600, hote, Some(3)),
                (800, 700, "cmd.exe", Some(4)),
                (900, 800, "malware.exe", Some(5)),
            ];
            for sans_session in [true, false] {
                assert!(
                    ascendance_de_session(900, instantane(&v), sans_session).is_some(),
                    "{hote}"
                );
                assert!(
                    ascendance_de_session(800, instantane(&v), sans_session).is_some(),
                    "{hote}"
                );
            }
        }
        // Lancé par l'Explorateur : arrêté, session en cours ou non.
        let v = [
            (4, 0, "System", Some(1)),
            (500, 4, "winlogon", Some(2)),
            (1200, 999, "explorer.exe", Some(5)),
            (1300, 1200, "malware.exe", Some(9)),
        ];
        assert_eq!(ascendance_de_session(1300, instantane(&v), true), None);
        assert_eq!(ascendance_de_session(1300, instantane(&v), false), None);
        // Linux : lancé par systemd, rien ne l'empêche.
        let v = [(1, 0, "systemd", Some(0)), (2000, 1, "xmrig", Some(50))];
        assert_eq!(ascendance_de_session(2000, instantane(&v), false), None);
        // Le processus visé ne se lit plus : rien n'est arrêté.
        assert!(ascendance_de_session(77, instantane(&v), true).is_some());
    }

    /// Un numéro repris : le « parent » est né après l'enfant. La chaîne est coupée : pendant une session à distance
    /// (ou des sessions illisibles), refusé ; sans aucune session, l'arrêt reste permis.
    #[test]
    fn numero_repris_chaine_coupee() {
        let v = [
            (4, 0, "System", Some(1)),
            (700, 4, "outil.exe", Some(100)),
            (900, 700, "malware.exe", Some(50)),
        ];
        assert!(ascendance_de_session(900, instantane(&v), false).is_some());
        assert_eq!(ascendance_de_session(900, instantane(&v), true), None);
        // Même un faux parent nommé sshd refuse.
        let v = [
            (4, 0, "System", Some(1)),
            (700, 4, "sshd", Some(100)),
            (900, 700, "x", Some(50)),
        ];
        assert!(ascendance_de_session(900, instantane(&v), true).is_some());
        // Une boucle de numéros repris : incertaine.
        let v = [(10, 20, "a", Some(5)), (20, 10, "b", Some(5))];
        assert!(ascendance_de_session(10, instantane(&v), false).is_some());
        assert_eq!(ascendance_de_session(10, instantane(&v), true), None);
        // Égal : permis (les tops de Linux).
        let v = [
            (1, 0, "systemd", Some(0)),
            (30, 1, "bash", Some(7)),
            (31, 30, "x", Some(7)),
        ];
        assert_eq!(ascendance_de_session(31, instantane(&v), false), None);
    }

    /// Une heure de création illisible : la lignée est incertaine (refusée pendant une session), mais la remontée
    /// continue et un hôte au-dessus refuse toujours. Une lignée trop longue l'est aussi.
    #[test]
    fn heure_illisible_et_lignee_trop_longue() {
        let v = [
            (4, 0, "System", Some(1)),
            (700, 4, "svchost.exe", None),
            (900, 700, "malware.exe", Some(50)),
        ];
        assert!(ascendance_de_session(900, instantane(&v), false).is_some());
        assert_eq!(ascendance_de_session(900, instantane(&v), true), None);
        let v = [
            (4, 0, "System", Some(1)),
            (650, 4, "wsmprovhost.exe", Some(2)),
            (700, 650, "cmd.exe", None),
            (900, 700, "malware.exe", Some(50)),
        ];
        assert!(ascendance_de_session(900, instantane(&v), true).is_some());
        let mut longue: Vec<(u32, u32, &str, Option<u64>)> = (1..=100u32).map(|p| (p, p + 1, "x", Some(0))).collect();
        longue.push((101, 0, "racine", Some(0)));
        assert!(ascendance_de_session(1, instantane(&longue), false).is_some());
        assert_eq!(ascendance_de_session(1, instantane(&longue), true), None);
        // Des sessions illisibles ne prouvent pas qu'il n'y en a aucune.
        assert!(!aucune_session(None));
        assert!(aucune_session(Some(&Sessions::default())));
        let en_cours = Sessions {
            sessions: vec![ip("192.0.2.7")],
            ..Sessions::default()
        };
        assert!(!aucune_session(Some(&en_cours)));
    }

    /// `/proc/<pid>/stat` : le nom (même avec « ) » et des espaces), le parent et le départ.
    #[test]
    fn fiche_lue_du_stat() {
        let f =
            fiche_du_stat("4242 (a) b (c)) S 17 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 98765 1 2").unwrap();
        assert_eq!((f.parent, f.nom.as_str(), f.creation), (17, "a) b (c)", Some(98765)));
        let f = fiche_du_stat("7 (sshd-session) S 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12 0").unwrap();
        assert_eq!((f.parent, f.nom.as_str(), f.creation), (1, "sshd-session", Some(12)));
        // Coupé avant le départ : heure illisible, pas inventée.
        assert_eq!(fiche_du_stat("7 (x) S 1 7").unwrap().creation, None);
        assert!(fiche_du_stat("7 x S 1").is_none());
    }

    /// Garde-fou : jamais un processus critique (PID 0, 1, 4, ou nom critique), jamais Vanguard ni ce qui le fait
    /// tourner, jamais un programme du système, jamais un programme dont le chemin ne se lit pas.
    #[test]
    fn processus_jamais_arretes() {
        let rien = HashSet::new();
        let j = |pid, nom, chemin, os| processus_intouchable(pid, nom, chemin, &rien, os);
        for pid in [0, 1, 4] {
            assert!(j(pid, "x", Some("/home/alice/x"), Os::Linux).is_some(), "{pid}");
        }
        for nom in [
            "csrss.exe",
            "LSASS.EXE",
            "smss",
            "wininit.exe",
            "services.exe",
            "winlogon.exe",
            "svchost.exe",
            "systemd",
            "launchd",
            "kernel_task",
            "sshd",
        ] {
            // Même lancé hors de son dossier (un imposteur) : une alerte seulement, jamais d'arrêt.
            assert!(
                j(4242, nom, Some(r"C:\Users\alice\AppData\Local\Temp\x.exe"), Os::Windows).is_some(),
                "{nom}"
            );
        }
        assert!(j(4242, "outil", Some(r"C:\Windows\System32\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "outil", Some(r"\\?\D:\WINDOWS\SysWOW64\outil.exe"), Os::Windows).is_some());
        assert!(j(4242, "python3", Some("/usr/bin/python3.12"), Os::Linux).is_some());
        assert!(j(4242, "outil", Some("/System/Library/x"), Os::MacOs).is_some());
        assert!(j(4242, "outil", None, Os::Linux).is_some());
        // Vanguard, ce qu'il a lancé, son terminal : intouchables.
        let vanguard: HashSet<u32> = [4300, 4301, 4299].into();
        assert!(processus_intouchable(4300, "vanguard", Some("/home/alice/vanguard"), &vanguard, Os::Linux).is_some());
        assert!(processus_intouchable(std::process::id(), "x", Some("/home/alice/x"), &rien, Os::Linux).is_some());
        // Un programme ordinaire d'un dossier du compte : rien ne l'empêche.
        assert_eq!(
            j(
                4242,
                "mimikatz.exe",
                Some(r"C:\Users\alice\Downloads\mimikatz.exe"),
                Os::Windows
            ),
            None
        );
        assert_eq!(j(4242, "xmrig", Some("/home/alice/.cache/xmrig"), Os::Linux), None);
        assert_eq!(j(4242, "xmrig", Some("/usr/local/bin/xmrig"), Os::Linux), None);
    }

    #[test]
    fn dossiers_du_systeme() {
        assert!(dossier_systeme("/usr/lib/firefox/firefox", Os::Linux));
        assert!(dossier_systeme("/sbin/init", Os::Linux));
        assert!(dossier_systeme("/home/alice/../../usr/bin/x", Os::Linux));
        assert!(!dossier_systeme(
            "/home/alice/Téléchargements/facture.pdf.sh",
            Os::Linux
        ));
        assert!(!dossier_systeme("/opt/outil/outil", Os::Linux));
        // /System n'est du système que sous macOS ; /Library/Apple aussi.
        assert!(!dossier_systeme("/System/x", Os::Linux));
        assert!(dossier_systeme("/Library/Apple/System/x", Os::MacOs));
        assert!(!dossier_systeme("/Users/alice/Library/x", Os::MacOs));
        assert!(dossier_systeme(r"c:\windows\explorer.exe", Os::Windows));
        assert!(dossier_systeme("C:/Windows/System32/cmd.exe", Os::Windows));
        assert!(dossier_systeme(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
            Os::Windows
        ));
        assert!(dossier_systeme(r"C:\Users\alice\..\..\Windows\x.exe", Os::Windows));
        assert!(!dossier_systeme(
            r"C:\Users\alice\AppData\Roaming\Windows\x.exe",
            Os::Windows
        ));
        assert!(!dossier_systeme(r"C:\ProgramData\Updater\x.exe", Os::Windows));
        assert!(!dossier_systeme("windows", Os::Windows));
    }

    #[test]
    fn fichiers_jamais_en_quarantaine() {
        assert!(fichier_intouchable("/usr/bin/curl", Os::Linux, None).is_some());
        assert!(fichier_intouchable("/home/alice/vanguard", Os::Linux, Some("/home/alice/vanguard")).is_some());
        assert!(
            fichier_intouchable(r"E:\VANGUARD.EXE", Os::Windows, Some(r"e:\vanguard.exe")).is_some(),
            "casse de Windows"
        );
        assert_eq!(
            fichier_intouchable("/home/alice/Téléchargements/x", Os::Linux, Some("/home/alice/vanguard")),
            None
        );
    }

    #[test]
    fn chemin_court_juge_aussi_en_long() {
        let rien = HashSet::new();
        // Ce que Windows dirait des chemins longs de ces noms courts.
        let long = |c: &str| -> Option<String> {
            match c {
                r"C:\PROGRA~1\WINDOW~1\MsMpEng.exe" => Some(r"C:\Program Files\Windows Defender\MsMpEng.exe".into()),
                r"C:\Users\JEANDU~1\AppData\Local\Temp\x.exe" => {
                    Some(r"C:\Users\Jean Dupont\AppData\Local\Temp\x.exe".into())
                }
                r"C:\Users\JEANDU~1\AppData\Local\Temp\vanguard.exe" => {
                    Some(r"C:\Users\Jean Dupont\AppData\Local\Temp\vanguard.exe".into())
                }
                r"C:\WINDOW~1\System32\outil.exe" => Some(r"C:\Windows\System32\outil.exe".into()),
                _ => None,
            }
        };
        let p = |c| processus_intouchable_selon(4242, "outil", Some(c), &rien, Os::Windows, &long);
        let f = |c, mien| fichier_intouchable_selon(c, Os::Windows, mien, &long);
        // Protégé sous sa forme longue : refusé sous sa forme courte.
        assert!(p(r"C:\PROGRA~1\WINDOW~1\MsMpEng.exe").is_some());
        assert!(p(r"C:\WINDOW~1\System32\outil.exe").is_some());
        assert!(f(r"C:\PROGRA~1\WINDOW~1\MsMpEng.exe", None).is_some());
        // Vanguard, désigné par un chemin court, ou lancé par un chemin court : lui-même.
        let mien = r"C:\Users\Jean Dupont\AppData\Local\Temp\vanguard.exe";
        assert!(f(r"C:\Users\JEANDU~1\AppData\Local\Temp\vanguard.exe", Some(mien)).is_some());
        assert!(f(mien, Some(r"C:\Users\JEANDU~1\AppData\Local\Temp\vanguard.exe")).is_some());
        // Un nom court dont le chemin long ne se lit pas : refusé, sans rien juger à l'aveugle.
        assert!(p(r"C:\PROGRA~2\inconnu.exe").is_some());
        assert!(f(r"C:\Users\BOB~12\x.exe", None).is_some());
        // Protégé sous la forme écrite, quel que soit le chemin long : refusé (la forme longue ne permet jamais).
        let menteur = |_: &str| Some(r"C:\Users\alice\x.exe".to_string());
        assert!(
            processus_intouchable_selon(4242, "outil", Some(r"C:\Windows\x.exe"), &rien, Os::Windows, &menteur)
                .is_some()
        );
        // Un programme ordinaire du dossier temporaire, nom court ou non : rien ne l'empêche.
        assert_eq!(p(r"C:\Users\JEANDU~1\AppData\Local\Temp\x.exe"), None);
        assert_eq!(f(r"C:\Users\JEANDU~1\AppData\Local\Temp\x.exe", Some(mien)), None);
        assert_eq!(p(r"C:\Users\alice\Downloads\x~y.exe"), None);
        // Hors de Windows, pas de nom court : un « ~1 » se juge tel qu'il est écrit.
        let linux = processus_intouchable_selon(4242, "x", Some("/home/alice/a~1/x"), &rien, Os::Linux, &long);
        assert_eq!(linux, None);
        assert!(a_un_nom_court(r"C:\PROGRA~1\x") && a_un_nom_court("JEANDU~1") && !a_un_nom_court(r"C:\a~b\c~"));
    }

    fn etablie(distante: &str, port_local: u16, port_distant: u16, programme: Option<&str>, autre: bool) -> Etablie {
        Etablie {
            distante: ip(distante),
            port_local,
            port_distant,
            programme: programme.map(str::to_string),
            autre_compte: autre,
        }
    }

    /// WinRM (PowerShell à distance) : sa connexion entrante, tenue par System, est une session (le pare-feu la
    /// garde) ; un client WinRM qui part d'ici n'en est pas une par ce port.
    #[test]
    fn winrm_entrant_est_une_session() {
        for port in [5985, 5986] {
            assert!(est_session(
                &etablie("198.51.100.20", port, 51234, Some("System"), true),
                None
            ));
            assert!(!est_session(
                &etablie("198.51.100.20", 51234, port, Some("powershell"), false),
                None
            ));
        }
        let s = juger_etablies(
            &[etablie("198.51.100.20", 5985, 51234, Some("System"), true)],
            None,
            None,
        );
        assert_eq!(s.ports_locaux, vec![5985]);
    }

    /// Le Bureau à distance sur un port personnalisé (PortNumber de RDP-Tcp) : sa connexion, tenue par svchost, est
    /// une session (adresse gardée, port local gardé) ; sans PortNumber lu, ou à 0, rien ne change ; 3389 reste une
    /// session quel que soit PortNumber, et une connexion sortante dont le port DISTANT est ce port n'en devient pas
    /// une par lui (renforcement seulement : rien de ce qui était une session ne cesse de l'être).
    #[test]
    fn bureau_a_distance_sur_un_autre_port() {
        let rdp = etablie("198.51.100.30", 3390, 51234, Some("svchost"), true);
        assert!(!est_session(&rdp, None));
        assert!(!est_session(&rdp, Some(0)));
        assert!(est_session(&rdp, Some(3390)));
        assert!(!est_session(&rdp, Some(3391)));
        let sortante = etablie("198.51.100.30", 51234, 3390, Some("svchost"), false);
        assert!(!est_session(&sortante, Some(3390)));
        let classique = etablie("198.51.100.31", 3389, 51235, Some("svchost"), true);
        for port in [None, Some(0), Some(3390)] {
            assert!(est_session(&classique, port), "{port:?}");
        }
        let s = juger_etablies(&[rdp.clone(), classique.clone()], None, Some(3390));
        assert_eq!(s.ports_locaux, vec![3389, 3390]);
        assert_eq!(s.sessions, vec![ip("198.51.100.30"), ip("198.51.100.31")]);
        let sans = juger_etablies(&[rdp, classique], None, None);
        assert_eq!(sans.ports_locaux, vec![3389]);
        assert_eq!(sans.sessions, vec![ip("198.51.100.31")]);
    }

    /// PortNumber de RDP-Tcp : absent, 0 ou plus grand qu'un port ne donne aucun port ; sinon, le port.
    #[test]
    fn port_rdp_du_registre() {
        assert_eq!(port_rdp_lu(None), None);
        assert_eq!(port_rdp_lu(Some(0)), None);
        assert_eq!(port_rdp_lu(Some(70_000)), None);
        assert_eq!(port_rdp_lu(Some(3389)), Some(3389));
        assert_eq!(port_rdp_lu(Some(3390)), Some(3390));
    }

    /// PortNumber présent mais illisible (droits, type) : le port n'est pas sûr, les sessions ne se lisent pas ;
    /// absent : aucun port de plus que 3389.
    #[test]
    fn port_rdp_illisible_rend_les_sessions_illisibles() {
        use std::io::{Error, ErrorKind};
        assert_eq!(port_rdp_de(Ok(3390)), Ok(Some(3390)));
        assert_eq!(port_rdp_de(Ok(0)), Ok(None));
        assert_eq!(port_rdp_de(Err(Error::from(ErrorKind::NotFound))), Ok(None));
        assert_eq!(
            port_rdp_de(Err(Error::from(ErrorKind::PermissionDenied))),
            Err(PortIllisible)
        );
        assert_eq!(
            port_rdp_de(Err(Error::from(ErrorKind::InvalidData))),
            Err(PortIllisible)
        );
    }

    /// Le réseau redémarré par l'assistant élevé : seules les sessions ENTRANTES le retiennent (SSH ou Bureau à
    /// distance sur un port local en écoute, un programme de prise en main) ; ni un VPN, ni un SSH qui part d'ici.
    #[test]
    fn sessions_entrantes_seulement() {
        let ecoute = [22, 631];
        // Quelqu'un est entré par SSH ; puis un SSH qui part d'ici vers un serveur (port distant 22).
        assert!(session_entrante(
            &etablie("198.51.100.20", 22, 51234, None, true),
            &ecoute
        ));
        assert!(!session_entrante(
            &etablie("198.51.100.20", 51234, 22, Some("ssh"), false),
            &ecoute
        ));
        // Le port 3389 sans rien à l'écoute dessus : pas une session entrante.
        assert!(!session_entrante(
            &etablie("198.51.100.20", 3389, 51234, None, true),
            &ecoute
        ));
        // Les tunnels : jamais une session entrante, quel que soit leur nom de programme.
        for vpn in ["tailscaled", "openvpn", "wireguard", "wg-quick", "/usr/sbin/openvpn"] {
            assert!(
                !session_entrante(&etablie("198.51.100.20", 41641, 41641, Some(vpn), true), &ecoute),
                "{vpn}"
            );
            // Ils restent des sessions pour le blocage, qui ne coupe pas l'adresse.
            assert!(
                est_session(&etablie("198.51.100.20", 41641, 41641, Some(vpn), true), None),
                "{vpn}"
            );
        }
        // La prise en main, et sshd sur un autre port : des sessions entrantes. Les bureaux à distance de KDE et de
        // GNOME (nom coupé à 15 caractères par /proc), NoMachine et Chrome Remote Desktop aussi.
        for p in [
            "rustdesk",
            "anydesk",
            "teamviewerd",
            "x11vnc",
            "sshd-session",
            "krfb",
            "gnome-remote-de",
            "nxd",
            "chrome-remote-d",
        ] {
            assert!(
                session_entrante(&etablie("198.51.100.20", 2222, 51234, Some(p), true), &ecoute),
                "{p}"
            );
        }
        // Les ports en écoute de /proc/net/tcp : état 0A seulement.
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0 100 0 0 10 0
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0 100 0 0 10 0
   2: 0501A8C0:0016 1401A8C0:C822 01 00000000:00000000 00:00000000 00000000     0        0 3 1 0 100 0 0 10 0
";
        assert_eq!(en_ecoute_proc(tcp), [22, 631]);
    }

    /// Garde-fou : jamais couper une connexion à distance en cours, ni bloquer le réseau local ou un DNS public.
    #[test]
    fn adresses_jamais_bloquees() {
        let sessions = Sessions {
            sessions: vec![ip("198.51.100.20")],
            autres_comptes: vec![ip("203.0.113.9")],
            ports_locaux: Vec::new(),
        };
        let s = Some(&sessions);
        for auto in [false, true] {
            assert!(adresse_intouchable(ip("198.51.100.20"), s, auto).is_some());
            assert!(adresse_intouchable(ip("::ffff:198.51.100.20"), s, auto).is_some());
            assert!(
                adresse_intouchable(ip("203.0.113.7"), None, auto).is_some(),
                "sessions illisibles"
            );
            assert!(adresse_intouchable(ip("192.168.1.1"), s, auto).is_some());
            assert!(adresse_intouchable(ip("127.0.0.1"), s, auto).is_some());
            assert!(adresse_intouchable(ip("8.8.8.8"), s, auto).is_some());
            assert!(adresse_intouchable(ip("2606:4700:4700::1111"), s, auto).is_some());
            assert_eq!(adresse_intouchable(ip("185.220.101.4"), s, auto), None);
        }
        // Défaut de la relecture : une connexion d'un autre compte vers l'adresse. Jamais coupée toute seule ;
        // d'un clic, oui.
        assert!(adresse_intouchable(ip("203.0.113.9"), s, true).is_some());
        assert_eq!(adresse_intouchable(ip("203.0.113.9"), s, false), None);
        assert!(port_intouchable(22).is_some() && port_intouchable(3389).is_some());
        assert_eq!(port_intouchable(11434), None);
    }

    /// Défaut de la relecture : une session n'était vue que sur les ports 22 et 3389. Un programme d'accès à
    /// distance, de prise en main ou de VPN en est une, quel que soit son port.
    #[test]
    fn sessions_par_le_programme_et_par_le_port() {
        let etablies = [
            etablie("192.168.1.20", 2222, 51234, Some("sshd"), true),
            etablie("198.51.100.30", 51000, 21118, Some("rustdesk"), false),
            etablie("198.51.100.31", 51001, 51820, Some("wireguard.exe"), false),
            etablie("198.51.100.32", 5901, 50000, Some("Xvnc"), false),
            etablie("198.51.100.33", 5900, 50001, Some("vncserver-x11"), false),
            etablie("198.51.100.34", 51002, 443, Some("tailscaled"), false),
            etablie("198.51.100.35", 3389, 50002, None, true),
            etablie("203.0.113.7", 51003, 443, Some("firefox"), false),
            etablie("203.0.113.8", 51004, 443, None, true),
        ];
        let s = juger_etablies(&etablies, Some(ip("198.51.100.40")), None);
        assert_eq!(
            s.sessions,
            [
                "192.168.1.20",
                "198.51.100.30",
                "198.51.100.31",
                "198.51.100.32",
                "198.51.100.33",
                "198.51.100.34",
                "198.51.100.35",
                "198.51.100.40",
            ]
            .map(ip)
        );
        assert_eq!(
            s.autres_comptes,
            ["192.168.1.20", "198.51.100.35", "203.0.113.8"].map(ip)
        );
        for nom in [
            "sshd",
            "anydesk.exe",
            "AnyDesk",
            "openvpn",
            "wg",
            "parsecd",
            "x11vnc",
            "vncserver",
            r"C:\Windows\System32\QuickAssist.exe",
            "SRService.exe",
            "ScreenConnect.ClientService.exe",
            "vpnagent.exe",
        ] {
            assert!(programme_de_session(nom), "{nom}");
        }
        assert!(!programme_de_session("firefox") && !programme_de_session("ssh-agent"));
    }

    /// La garde de session du chemin des services (défense D6b) reconnaît les outils d'accès à distance et les VPN
    /// tiers par le programme qu'ils lancent, tel que le registre l'écrit.
    #[test]
    fn programmes_de_session_lus_d_un_chemin_de_service() {
        use crate::machine::gestes::programme_du_chemin;
        for chemin in [
            r#""C:\Program Files (x86)\AnyDesk\AnyDesk.exe" --service"#,
            r#""C:\Program Files\TeamViewer\TeamViewer_Service.exe""#,
            r#""C:\Program Files\OpenVPN\bin\openvpnserv.exe""#,
            r#""C:\Program Files\Tailscale\tailscaled.exe""#,
            r#""C:\Program Files\WireGuard\wireguard.exe" /tunnelservice "C:\x.conf""#,
            r#""C:\Program Files\RustDesk\rustdesk.exe" --service"#,
            r"C:\Windows\System32\OpenSSH\sshd.exe",
        ] {
            assert!(programme_de_session(programme_du_chemin(chemin)), "{chemin}");
        }
        assert!(!programme_de_session(programme_du_chemin(
            r#""C:\Program Files\Outil\svc.exe" -k"#
        )));
    }

    #[test]
    fn connexions_etablies_lues() {
        // Linux : la prise 11 est à ce compte (1000) et à sshd ; la 12 à root ; la 14 n'est pas établie.
        let proc = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0501A8C0:08AE 1401A8C0:C822 01 00000000:00000000 00:00000000 00000000  1000        0 11 1
   1: 0501A8C0:D431 07AB33CB:0016 01 00000000:00000000 00:00000000 00000000     0        0 12 1
   2: 0501A8C0:D432 04AB33CB:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 13 1
   3: 0501A8C0:0016 1501A8C0:C823 0A 00000000:00000000 00:00000000 00000000  1000        0 14 1
";
        let noms = [(11u64, "sshd".to_string())].into();
        let e = etablies_proc(proc, 1000, &noms);
        assert_eq!(
            e,
            [
                etablie("192.168.1.20", 2222, 0xC822, Some("sshd"), false),
                etablie("203.51.171.7", 0xD431, 22, None, true),
                etablie("203.51.171.4", 0xD432, 443, None, false),
            ]
        );
        let s = juger_etablies(&e, None, None);
        assert_eq!(s.sessions, [ip("192.168.1.20"), ip("203.51.171.7")]);
        assert_eq!(s.autres_comptes, [ip("203.51.171.7")]);
        // Windows : une session du Bureau à distance (port local 3389) en IPv4, et une connexion web.
        let mut table = 2u32.to_ne_bytes().to_vec();
        for (etat, local, distante, distant, pid) in [
            (5u32, 3389u16, [198, 51, 100, 9], 50_000u16, 1234u32),
            (5, 50_001, [203, 0, 113, 7], 443, 4321),
        ] {
            table.extend(etat.to_ne_bytes());
            table.extend([192, 168, 1, 5]);
            table.extend(u32::from(local).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(distante);
            table.extend(u32::from(distant).to_be_bytes()[2..].iter().chain(&[0, 0]));
            table.extend(pid.to_ne_bytes());
        }
        assert_eq!(
            etablies_table(&table, false),
            [
                (3389, ip("198.51.100.9"), 50_000, 1234),
                (50_001, ip("203.0.113.7"), 443, 4321)
            ]
        );
        // macOS : netstat voit tout, lsof seulement ce compte.
        let netstat = "tcp4       0      0  192.168.1.5.22         192.168.1.20.51234     ESTABLISHED
tcp4       0      0  192.168.1.5.51000      203.0.113.7.443        ESTABLISHED
tcp6       0      0  2001:db8::5.51001      2001:db8::7.5938       ESTABLISHED
";
        let lsof = "p501\ncfirefox\nn192.168.1.5:51000->203.0.113.7:443\np502\ncTeamViewer\nn[2001:db8::5]:51001->[2001:db8::7]:5938\n";
        let e = etablies_macos(netstat, lsof);
        assert_eq!(
            e,
            [
                etablie("192.168.1.20", 22, 51234, None, true),
                etablie("203.0.113.7", 51000, 443, Some("firefox"), false),
                etablie("2001:db8::7", 51001, 5938, Some("TeamViewer"), false),
            ]
        );
        assert_eq!(
            juger_etablies(&e, None, None).sessions,
            [ip("192.168.1.20"), ip("2001:db8::7")]
        );
        assert_eq!(
            client_ssh("198.51.100.20 51234 192.168.1.5 22"),
            Some(ip("198.51.100.20"))
        );
        assert_eq!(client_ssh(""), None);
    }
}
