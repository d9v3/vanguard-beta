//! Les garde-fous du blocage, en fonctions pures (testées sous Linux et sous Wine) : ce qui ne s'arrête, ne se met
//! en quarantaine ni ne se bloque jamais, même quand une liste ou une règle le désigne. Ce qu'ils refusent reste une
//! alerte, avec sa raison.

use std::collections::HashSet;
use std::net::IpAddr;

use crate::machine::regles::Os;
use crate::{tr, trf};

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

/// Une connexion établie est-elle une session SSH ENTRANTE : sur un port local de sshd (22, ou ceux de sshd_config),
/// ou tenue par sshd lui-même (sshd, sshd-session). Ni un client SSH qui part d'ici, ni le Bureau à distance : c'est
/// sshd qu'un redémarrage couperait (défense D6c).
#[cfg(any(windows, test))]
pub(crate) fn session_ssh_entrante(e: &Etablie, ports_sshd: &[u16]) -> bool {
    e.port_local == 22
        || ports_sshd.contains(&e.port_local)
        || e.programme
            .as_deref()
            .is_some_and(|p| matches!(nom_simple(p).as_str(), "sshd" | "sshd-session"))
}

/// Une session SSH entrante est-elle ouverte sur cet ordinateur (`session_ssh_entrante`, ou Vanguard lancé depuis
/// SSH) ? `None` : les connexions ne se lisent pas, et sshd n'est alors ni redémarré ni privé des mots de passe.
#[cfg(windows)]
pub(crate) fn session_ssh_ouverte(ports_sshd: &[u16]) -> Option<bool> {
    if std::env::var("SSH_CONNECTION").is_ok_and(|v| client_ssh(&v).is_some()) {
        return Some(true);
    }
    // Les deux tables exigées : une session SSH en IPv6 seulement ne se verrait pas si sa table manquait.
    lire_etablies_win(true).map(|l| l.iter().any(|e| session_ssh_entrante(e, ports_sshd)))
}

/// Les tables lues suffisent-elles ? Pour sshd (`les_deux`), chacune : une table illisible pourrait tenir la session
/// qu'un redémarrage couperait (relecture D6c) ; ailleurs, une seule.
#[cfg(any(windows, test))]
fn tables_suffisantes(v4: bool, v6: bool, les_deux: bool) -> bool {
    if les_deux { v4 && v6 } else { v4 || v6 }
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
    lire_etablies_win(false)
}

/// Les connexions établies d'IPv4 et d'IPv6 ; `les_deux` : `None` dès qu'une des deux tables manque.
#[cfg(windows)]
fn lire_etablies_win(les_deux: bool) -> Option<Vec<Etablie>> {
    use crate::machine::windows::processus;
    let v4 = crate::protection::sortantes::table_tcp(2).map(|t| etablies_table(&t, false));
    let v6 = crate::protection::sortantes::table_tcp(23).map(|t| etablies_table(&t, true));
    if !tables_suffisantes(v4.is_some(), v6.is_some(), les_deux) {
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

/// `ascendance_selon`, lue comme sous Windows (un parent absent est fini), sans racine.
#[cfg(test)]
pub(crate) fn ascendance_de_session(
    pid: u32,
    fiche: impl Fn(u32) -> Option<Fiche>,
    aucune_session: bool,
) -> Option<&'static str> {
    ascendance_selon(pid, fiche, aucune_session, Lecture::default())
}

/// Comment lire la lignée, selon le système et l'appelant.
#[derive(Clone, Copy, Default)]
pub(crate) struct Lecture {
    /// Sous Unix, un orphelin est rattaché à init (ou à un « subreaper ») : un parent absent de la liste n'y est pas
    /// fini, il est caché (/proc monté avec hidepid) ou illisible, et la lignée en devient incertaine. Seul init (1),
    /// racine de tout, la finit sans se lire. Sous Windows, aucun rattachement : un parent fini manque, tout
    /// simplement (défense D6a, relecture).
    pub parent_absent_cache: bool,
    /// Une lignée gelée (rançongiciel) : sa racine, jugée elle-même par le blocage, finit la lecture ; seul ce qui est
    /// entre le membre et elle compte (un shell de session pris dans le même groupe en est hors).
    pub racine: Option<u32>,
}

/// Pourquoi ce processus ne doit pas être arrêté parce qu'il descend d'un hôte de session à distance, ou `None`.
/// `fiche` : le processus d'un numéro dans l'instantané (`None` : fini, ou caché selon `lecture`). Un parent n'est le
/// vrai parent que s'il a été créé avant l'enfant : sinon son numéro a été repris par un autre, la chaîne est coupée,
/// et pendant une session à distance (`aucune_session` faux : en cours ou illisible) ce qui ne se prouve pas hors
/// d'elle n'est pas arrêté. Une heure illisible rend la lignée incertaine de même, mais la remontée continue : un hôte
/// plus haut refuse toujours.
pub(crate) fn ascendance_selon(
    pid: u32,
    fiche: impl Fn(u32) -> Option<Fiche>,
    aucune_session: bool,
    lecture: Lecture,
) -> Option<&'static str> {
    let incertaine = || {
        (!aucune_session).then(|| {
            tr!(
                "lignée du processus incertaine (numéro repris, parent ou heure illisible) pendant une session à distance : rien n'est arrêté",
                "process lineage uncertain (reused number, unreadable parent or time) during a remote session: nothing is stopped"
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
        if lecture.racine == Some(p) {
            return if douteuse { incertaine() } else { None };
        }
        let Some(parent) = fiche(p) else {
            if lecture.parent_absent_cache && p != 1 {
                return incertaine();
            }
            // Un parent fini : la lignée s'arrête là, aucun hôte vivant au-dessus par elle.
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
    lignee_lue(pid, sessions, None)
}

/// La garde d'ascendance d'un membre d'une lignée gelée, lue jusqu'à sa `racine` seulement (voir `Lecture`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn lignee_de_session_sous(pid: u32, racine: u32, sessions: Option<&Sessions>) -> Option<&'static str> {
    lignee_lue(pid, sessions, Some(racine))
}

fn lignee_lue(pid: u32, sessions: Option<&Sessions>, racine: Option<u32>) -> Option<&'static str> {
    let aucune = aucune_session(sessions);
    let lecture = Lecture {
        parent_absent_cache: cfg!(unix),
        racine,
    };
    #[cfg(windows)]
    {
        use crate::machine::windows::processus;
        let instantane: std::collections::HashMap<u32, (u32, String)> = processus::liste()
            .into_iter()
            .map(|p| (p.pid, (p.parent, p.nom)))
            .collect();
        ascendance_selon(
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
            lecture,
        )
    }
    #[cfg(target_os = "linux")]
    {
        ascendance_selon(
            pid,
            |p| fiche_du_stat(&std::fs::read_to_string(format!("/proc/{p}/stat")).ok()?),
            aucune,
            lecture,
        )
    }
    #[cfg(target_os = "macos")]
    {
        ascendance_selon(
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
            lecture,
        )
    }
}

/// Ce que Windows dit de la signature d'un fichier (défense D6a). Une signature ne PERMET jamais rien : aucun geste
/// n'est ouvert parce qu'un fichier n'est pas signé. Signé Microsoft refuse ; illisible refuse tout geste automatique,
/// et demande à la personne, devant une vraie console, de confirmer ce qu'elle a demandé elle-même (choix 3.1).
#[cfg_attr(not(windows), allow(dead_code))] // ailleurs que sous Windows, rien ne se lit : seuls les essais la font
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Signature {
    /// Dans un catalogue signé par Microsoft, ou signé par Microsoft dans sa table des certificats ; vérifiée.
    Microsoft,
    /// Non signé, ou par un autre, ou une signature qui ne se vérifie pas (une fausse « Microsoft » comprise).
    Autre,
    /// Le fichier, sa signature ou les catalogues de Windows ne se lisent pas, et pourquoi.
    Illisible(Illisibilite),
}

/// Pourquoi une signature ne se lit pas, d'après le code de Windows : montré à la personne avant qu'elle confirme.
/// Un maliciel s'y rend illisible exprès (fichier ouvert sans partage, image renommée, CryptSvc coupé).
#[cfg_attr(not(windows), allow(dead_code))] // comme `Signature`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Illisibilite {
    /// Partage refusé ou fichier verrouillé (ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION).
    Verrouille,
    /// Accès refusé (ERROR_ACCESS_DENIED).
    AccesRefuse,
    /// Fichier ou dossier introuvable : effacé, renommé ou déplacé depuis le lancement.
    Absent,
    /// Le service de chiffrement (CryptSvc) ne répond pas : arrêté, désactivé, ou son point d'appel absent.
    CryptSvc,
    /// Un catalogue de Windows ne se lit pas, sans code plus précis.
    Catalogues,
    /// La signature se vérifie, mais son signataire ou sa chaîne ne se lit pas.
    Signataire,
    /// Un autre code de Windows.
    Code(u32),
    /// Une erreur de lecture sans code de Windows (erreur faite par la bibliothèque, pas par le système).
    SansCode,
}

impl Illisibilite {
    /// La raison, en mots simples, prête à montrer.
    pub(crate) fn texte(self) -> String {
        match self {
            Illisibilite::Verrouille => tr!(
                "le fichier est verrouillé : un programme le tient ouvert sans permettre de le lire (souvent le programme lui-même)",
                "the file is locked: a program holds it open without allowing it to be read (often the program itself)"
            )
            .to_string(),
            Illisibilite::AccesRefuse => tr!(
                "accès refusé : ce compte n'a pas le droit de lire le fichier",
                "access denied: this account may not read the file"
            )
            .to_string(),
            Illisibilite::Absent => tr!(
                "le fichier n'est plus là : effacé, renommé ou déplacé depuis le lancement du programme",
                "the file is gone: deleted, renamed or moved since the program started"
            )
            .to_string(),
            Illisibilite::CryptSvc => tr!(
                "le service de chiffrement de Windows (CryptSvc) ne répond pas : arrêté ou bloqué",
                "the Windows cryptographic service (CryptSvc) is not responding: stopped or blocked"
            )
            .to_string(),
            Illisibilite::Catalogues => tr!(
                "les catalogues de signatures de Windows ne se lisent pas",
                "the Windows signature catalogs cannot be read"
            )
            .to_string(),
            Illisibilite::Signataire => tr!(
                "la signature est là, mais son signataire ou sa chaîne de certificats ne se lit pas",
                "the signature is there, but its signer or its certificate chain cannot be read"
            )
            .to_string(),
            Illisibilite::Code(c) => trf!(
                "Windows a rendu une autre erreur (code 0x{c:08X})",
                "Windows returned another error (code 0x{c:08X})"
            ),
            Illisibilite::SansCode => tr!(
                "la lecture du fichier a échoué sans code d'erreur de Windows",
                "reading the file failed without a Windows error code"
            )
            .to_string(),
        }
    }
}

/// La raison d'un code de Windows (Win32, ou HRESULT de la famille 7 qui le porte), ou `None` : un code inconnu, que
/// l'appelant dit tel quel (`Code`) ou rattache à ce qu'il lisait (`Catalogues`).
#[cfg_attr(not(windows), allow(dead_code))] // comme `Signature`
pub(crate) fn illisibilite_connue(code: u32) -> Option<Illisibilite> {
    let win32 = if code & 0xFFFF_0000 == 0x8007_0000 {
        code & 0xFFFF
    } else {
        code
    };
    match win32 {
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION.
        32 | 33 => Some(Illisibilite::Verrouille),
        5 => Some(Illisibilite::AccesRefuse),
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND.
        2 | 3 => Some(Illisibilite::Absent),
        // ERROR_SERVICE_DISABLED, ERROR_SERVICE_NOT_ACTIVE, RPC_S_SERVER_UNAVAILABLE, EPT_S_NOT_REGISTERED.
        1058 | 1062 | 1722 | 1753 => Some(Illisibilite::CryptSvc),
        _ => None,
    }
}

/// La raison d'une erreur de lecture du fichier, d'après son code système s'il y en a un : sans code (erreur faite
/// par la bibliothèque), le dire, plutôt qu'un « code 0x00000000 » qui ne veut rien dire.
#[cfg_attr(not(windows), allow(dead_code))] // comme `Signature`
pub(crate) fn raison_de_lecture(code: Option<u32>) -> Illisibilite {
    code.map_or(Illisibilite::SansCode, |c| {
        illisibilite_connue(c).unwrap_or(Illisibilite::Code(c))
    })
}

/// Pourquoi ce fichier signé ne doit être ni arrêté ni mis en quarantaine SANS la personne, ou `None` : signé
/// Microsoft, toujours ; illisible, quand personne ne peut confirmer (geste automatique, pas de vraie console).
pub(crate) fn signature_intouchable(s: Signature) -> Option<String> {
    match s {
        Signature::Microsoft => Some(signe_microsoft().to_string()),
        Signature::Illisible(r) => Some(illisible_sans_confirmation(r)),
        Signature::Autre => None,
    }
}

fn signe_microsoft() -> &'static str {
    tr!(
        "signé par Microsoft : traité comme du système, une alerte seulement",
        "signed by Microsoft: treated as part of the system, an alert only"
    )
}

/// Le refus d'une signature illisible quand personne ne peut confirmer : il dit quoi faire.
fn illisible_sans_confirmation(r: Illisibilite) -> String {
    trf!(
        "signature du fichier illisible ({}) : rien n'est fait à l'aveugle sans vous ; à faire à la main depuis Vanguard, dans une vraie fenêtre (Bloquer et réagir › Blocage des menaces), qui vous montrera pourquoi et vous demandera de confirmer",
        "file signature unreadable ({}): nothing is done blindly without you; do it by hand from Vanguard, in a real window (Block and respond › Threat blocking), which will show you why and ask you to confirm",
        r.texte()
    )
}

/// Le sujet d'un certificat signataire est-il celui de Microsoft (« O=Microsoft Corporation, CN=Microsoft Windows ») ?
#[cfg(any(windows, test))]
pub(crate) fn sujet_microsoft(sujet: &str) -> bool {
    sujet.to_lowercase().contains("microsoft")
}

/// La racine de Microsoft au bout de la chaîne d'un signataire, lue par CERT_CHAIN_POLICY_MICROSOFT_ROOT.
#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Racine {
    /// Une racine « produit » de Microsoft (la politique sans drapeau) : celle de Windows (Root Certificate
    /// Authority 2010) et les plus anciennes. Windows peut en compter d'autres que Wine (racines ECC 2017 et 2018 ?) :
    /// au pire un programme de Microsoft signé sous l'une d'elles sort « Autre » ; un tiers y reste exclu par son
    /// sujet et ses usages (`signe_par_microsoft`).
    Produit,
    /// Seulement la racine « application », Microsoft Root Certificate Authority 2011 (drapeau
    /// CHECK_APPLICATION_ROOT) : Edge, Office, Teams, signés par Microsoft Code Signing PCA 2011. La politique
    /// sans drapeau ne la compte pas : sans elle, msedge.exe n'était pas « signé Microsoft » (VM, D6a 3b).
    Application,
    /// Aucune racine de Microsoft.
    Aucune,
}

/// MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG : la politique vérifie « à la place » la racine
/// application, Microsoft Root Certificate Authority 2011 (Edge, Office, Teams). Jamais ENABLE_TEST_ROOT
/// (0x0001_0000), qui ajoute les racines d'essai de Microsoft : elles signent n'importe quoi en laboratoire.
#[cfg(any(windows, test))]
pub(crate) const RACINE_APPLICATION: u32 = 0x0002_0000;

/// La racine d'une chaîne, `lire` rendant la politique CERT_CHAIN_POLICY_MICROSOFT_ROOT lue avec ces drapeaux
/// (`None` : illisible) : sans drapeau d'abord, puis avec la seule racine application si la première dit non.
/// Passée en paramètre pour que l'essai voie les drapeaux demandés, jamais la racine d'essai (relecture, B3).
#[cfg(any(windows, test))]
pub(crate) fn racine_lue(mut lire: impl FnMut(u32) -> Option<bool>) -> Option<Racine> {
    let produit = lire(0);
    let application = if produit == Some(false) {
        lire(RACINE_APPLICATION)
    } else {
        None
    };
    racine_selon(produit, application)
}

/// La racine d'après les deux lectures de la politique : sans drapeau, puis avec CHECK_APPLICATION_ROOT (jamais
/// avec la racine d'essai, ENABLE_TEST_ROOT). `None` : la première ne se lit pas (chaîne illisible). La seconde
/// illisible : pas de racine application, jamais « Microsoft » par défaut.
#[cfg(any(windows, test))]
fn racine_selon(produit: Option<bool>, application: Option<bool>) -> Option<Racine> {
    Some(if produit? {
        Racine::Produit
    } else if application == Some(true) {
        Racine::Application
    } else {
        Racine::Aucune
    })
}

/// Les attributs d'un sujet X.500 tel que l'écrit CertGetNameStringW (« C=US, …, O=…, CN=… ») : la clé en
/// majuscules, la valeur sans ses guillemets. Une valeur qui contient une virgule, un point-virgule, un « + » ou
/// un « = » y est entre guillemets (ses guillemets doublés) : elle ne coupe pas le sujet, sinon
/// « CN="x, O=Microsoft Corporation" » se lirait comme deux attributs. « + » sépare les attributs d'un même RDN.
#[cfg(any(windows, test))]
fn attributs(sujet: &str) -> Vec<(String, String)> {
    let mut morceaux = Vec::new();
    let mut courant = String::new();
    let mut entre_guillemets = false;
    let mut car = sujet.chars().peekable();
    while let Some(c) = car.next() {
        match c {
            '"' if entre_guillemets && car.peek() == Some(&'"') => {
                car.next();
                courant.push('"');
            }
            '"' => entre_guillemets = !entre_guillemets,
            ',' | ';' | '+' if !entre_guillemets => morceaux.push(std::mem::take(&mut courant)),
            _ => courant.push(c),
        }
    }
    morceaux.push(courant);
    morceaux
        .iter()
        .filter_map(|m| {
            let (cle, valeur) = m.split_once('=')?;
            Some((cle.trim().to_uppercase(), valeur.trim().to_string()))
        })
        .collect()
}

/// Les seuls signataires « Microsoft » sous une racine produit, par égalité du CN (casse ignorée) : « Microsoft
/// Windows » (fichiers et catalogues de Windows), « Microsoft Windows Publisher » (composants de Windows signés
/// hors catalogue), « Microsoft Corporation » (Office, outils, Code Signing PCA 2010). Une liste BLANCHE : la
/// famille « Third Party Component CA » de Microsoft a plusieurs signataires qui signent pour autrui (Hardware
/// Compatibility, Software Compatibility, Third Party Application Component…) et peut en gagner sans préavis ;
/// une liste noire ne se prouve pas complète (relecture de la racine 2011, B1). Les autres signataires de
/// Microsoft (Dynamic Code Publisher, Windows Kits Publisher, HAL Publisher…) ne sont pas « Microsoft » : le
/// moindre mal, les fichiers des dossiers de Windows restant intouchables par leur chemin (`fichier_intouchable`).
#[cfg(any(windows, test))]
const SIGNATAIRES_PRODUIT: [&str; 3] = [
    "Microsoft Windows",
    "Microsoft Windows Publisher",
    "Microsoft Corporation",
];

/// Les signataires au nom de Microsoft qui signent le travail d'AUTRES éditeurs, sous une racine de Microsoft :
/// pilotes WHQL et attestés (« Microsoft Windows Hardware Compatibility Publisher » : des pilotes malveillants
/// l'ont obtenu par le programme matériel de Microsoft), composants tiers poussés par Windows Update (« Microsoft
/// Windows Software Compatibility Publisher »), pilotes ELAM des antivirus (« … Early Launch Anti-malware
/// Publisher »), composants tiers (« Microsoft Windows Third Party Application Component », « Microsoft 3rd Party
/// Application Component »). Microsoft en garantit la provenance, pas l'auteur : pas d'immunité « Microsoft ».
/// Aussi ceux de Microsoft passés par là (pilotes Surface, l'ELAM de Defender, WdBoot.sys hors de Windows) :
/// choisi, le moindre mal. Redondant avec `SIGNATAIRES_PRODUIT`, gardé si elle s'élargit. En minuscules,
/// cherchés dans le CN.
#[cfg(any(windows, test))]
const SIGNATAIRES_POUR_AUTRUI: [&str; 4] = ["compatibility", "early launch", "third party", "3rd party"];

/// Les usages (EKU) du même travail pour autrui, s'ils sont dans le certificat : pilote WHQL (311.10.3.5),
/// pilote attesté (311.10.3.5.1), pilote ELAM (311.61.4.1), paquet du Microsoft Store (311.76.3.1, signé par
/// Microsoft pour l'éditeur du paquet).
#[cfg(any(windows, test))]
const USAGES_POUR_AUTRUI: [&str; 4] = [
    "1.3.6.1.4.1.311.10.3.5",
    "1.3.6.1.4.1.311.10.3.5.1",
    "1.3.6.1.4.1.311.61.4.1",
    "1.3.6.1.4.1.311.76.3.1",
];

/// L'usage « signature de code » (EKU id-kp-codeSigning).
#[cfg(any(windows, test))]
const SIGNATURE_DE_CODE: &str = "1.3.6.1.5.5.7.3.3";

/// Un signataire vérifié est-il Microsoft ? Son sujet ET la racine de sa chaîne : un sujet se forge (une autorité
/// faite maison, posée dans le magasin Root du compte sans droits ni invite, signe « CN=Microsoft Windows »), une
/// racine de Microsoft non (`racine_microsoft` : CERT_CHAIN_POLICY_MICROSOFT_ROOT, défense D6a, relecture).
/// Le sujet : un seul O, « Microsoft Corporation », un seul CN, qui n'est pas un signataire pour autrui ; aucun
/// usage pour autrui (`usages` : les EKU du certificat, vide s'il n'en dit pas). Sous une racine produit, le CN
/// est l'un de `SIGNATAIRES_PRODUIT` ; sous la seule racine 2011, plus strict : CN « Microsoft Corporation »
/// (Microsoft Code Signing PCA 2011) et l'usage signature de code.
#[cfg(any(windows, test))]
pub(crate) fn signe_par_microsoft(sujet: &str, usages: &[&str], racine: Racine) -> bool {
    // `sujet_microsoft` d'abord : le tri grossier d'avant, que le sujet lu attribut par attribut resserre.
    if racine == Racine::Aucune || !sujet_microsoft(sujet) {
        return false;
    }
    let attributs = attributs(sujet);
    let valeurs = |cle: &str| -> Vec<&str> {
        attributs
            .iter()
            .filter(|(k, _)| k == cle)
            .map(|(_, v)| v.as_str())
            .collect()
    };
    let (os, cns) = (valeurs("O"), valeurs("CN"));
    let ([o], [cn]) = (os.as_slice(), cns.as_slice()) else {
        return false;
    };
    let cn_min = cn.to_lowercase();
    if !o.eq_ignore_ascii_case("Microsoft Corporation")
        || SIGNATAIRES_POUR_AUTRUI.iter().any(|s| cn_min.contains(s))
        || usages.iter().any(|u| USAGES_POUR_AUTRUI.contains(u))
    {
        return false;
    }
    match racine {
        Racine::Produit => SIGNATAIRES_PRODUIT.iter().any(|s| cn.eq_ignore_ascii_case(s)),
        Racine::Application => cn.eq_ignore_ascii_case("Microsoft Corporation") && usages.contains(&SIGNATURE_DE_CODE),
        Racine::Aucune => false,
    }
}

/// Un code rendu par WinVerifyTrust dit-il que le fichier ne s'est pas LU (et non qu'il n'est pas signé, ou mal) ?
/// CRYPT_E_FILE_ERROR, et toute erreur de Windows (HRESULT de la famille 7 : accès refusé, partage, mémoire…).
#[cfg(any(windows, test))]
pub(crate) fn verification_illisible(code: i32) -> bool {
    let code = code.cast_unsigned();
    code == 0x8009_2003 || code & 0xFFFF_0000 == 0x8007_0000
}

/// La signature d'un fichier d'après ses deux voies, chacune `Ok(signé Microsoft)` ou `Err(pourquoi illisible)` :
/// signé Microsoft par l'une suffit ; sinon une voie illisible rend le tout illisible (CryptSvc d'abord, la cause la
/// plus utile à dire ; puis la signature intégrée, lue sur le fichier même).
#[cfg(any(windows, test))]
pub(crate) fn signature_de(catalogue: Result<bool, Illisibilite>, integree: Result<bool, Illisibilite>) -> Signature {
    if catalogue == Ok(true) || integree == Ok(true) {
        return Signature::Microsoft;
    }
    match (catalogue, integree) {
        (Err(Illisibilite::CryptSvc), _) | (_, Err(Illisibilite::CryptSvc)) => {
            Signature::Illisible(Illisibilite::CryptSvc)
        }
        (_, Err(r)) | (Err(r), _) => Signature::Illisible(r),
        _ => Signature::Autre,
    }
}

/// La signature de `chemin`, lue sur ce système : sous Windows seulement (ailleurs, aucune ne se lit : « autre »,
/// qui n'ouvre aucun geste de plus).
pub(crate) fn signature_lue(chemin: &str) -> Signature {
    #[cfg(windows)]
    {
        crate::machine::windows::signature::lire(std::path::Path::new(chemin))
    }
    #[cfg(not(windows))]
    {
        let _ = chemin;
        Signature::Autre
    }
}

/// Ce que la garde de signature dit avant de préparer un arrêt ou une quarantaine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Avant {
    /// Refusé, avec la raison.
    Refuse(String),
    /// Illisible, demandé par la personne : la question sera posée là où le geste se fait.
    Confirmera,
    /// Rien à dire.
    Rien,
}

/// La garde de signature avant de préparer un geste (défense D6a, choix 3.1). Signé Microsoft refuse partout.
/// Illisible : demandé par la personne (`automatique` faux), la question viendra là où le geste se fait (ici, ou
/// Vanguard administrateur, qui relit avec ses droits) ; automatique, refusé ici (`ici`), ou laissé à Vanguard
/// administrateur, qui le refuse (l'ordre part sans `demande`) : le compte de ce Vanguard-ci ne lit souvent pas le
/// programme d'un autre compte.
pub(crate) fn signature_avant_remise(s: Signature, ici: bool, automatique: bool) -> Avant {
    match s {
        Signature::Microsoft => Avant::Refuse(signe_microsoft().to_string()),
        Signature::Autre => Avant::Rien,
        Signature::Illisible(_) if !automatique => Avant::Confirmera,
        Signature::Illisible(_) if !ici => Avant::Rien,
        Signature::Illisible(r) => Avant::Refuse(illisible_sans_confirmation(r)),
    }
}

/// L'étape montrée quand la signature ne se lit pas d'ici, pour un geste demandé.
pub(crate) fn etape_confirmera(quarantaine: bool) -> String {
    if quarantaine {
        tr!(
            "La signature du fichier ne se lit pas : avant de le mettre de côté, Vanguard vous montrera pourquoi et vous demandera de confirmer (non par défaut)",
            "The file's signature cannot be read: before setting it aside, Vanguard will show you why and ask you to confirm (no by default)"
        )
        .to_string()
    } else {
        tr!(
            "La signature du programme ne se lit pas d'ici : avant de l'arrêter, Vanguard vous montrera pourquoi et vous demandera de confirmer (non par défaut)",
            "The program's signature cannot be read from here: before stopping it, Vanguard will show you why and ask you to confirm (no by default)"
        )
        .to_string()
    }
}

/// Ce que la garde de signature décide au moment du geste.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Refuse(String),
    /// Illisible, et la personne peut confirmer : montrer pourquoi, puis demander.
    Demander(Illisibilite),
    Permis,
}

/// La garde de signature au moment du geste (défense D6a, choix 3.1). `autre_garde` : le refus d'une garde qui passe
/// AVANT la question (session à distance, processus vital) ; la question n'est jamais posée pour ce qu'une autre
/// garde refuse. `demande` : la personne l'a demandé elle-même ; `console` : la réponse viendra d'une vraie console.
pub(crate) fn decider_signature(s: Signature, autre_garde: Option<&str>, demande: bool, console: bool) -> Decision {
    if let Some(r) = autre_garde {
        // Les deux refusent : dire les deux, la signature Microsoft étant souvent la raison la plus parlante.
        if s == Signature::Microsoft {
            return Decision::Refuse(format!("{r} ; {}", signe_microsoft()));
        }
        return Decision::Refuse(r.to_string());
    }
    match s {
        Signature::Microsoft => Decision::Refuse(signe_microsoft().to_string()),
        Signature::Autre => Decision::Permis,
        Signature::Illisible(r) if demande && console => Decision::Demander(r),
        Signature::Illisible(r) => Decision::Refuse(illisible_sans_confirmation(r)),
    }
}

/// La question [o/N] (même règle que les baisses de D2) : seul « o » (« y ») vaut oui ; Entrée, la fin de l'entrée,
/// une erreur de lecture (`demander` rend alors une réponse vide) et tout le reste valent non. Sans vraie console, la
/// question n'est même pas posée : une réponse arrivée par un tube n'a pas été tapée par la personne.
pub(crate) fn confirmer(console: bool, question: &str, demander: impl FnOnce(&str) -> String) -> bool {
    if !console {
        crate::ui::afficher_aligne(
            "    ",
            tr!(
                "L'entrée n'est pas une console : la réponse vaut non, rien n'est fait.",
                "The input is not a console: the answer is no, nothing is done."
            ),
            4,
            "",
        );
        return false;
    }
    crate::langue::oui(&demander(question))
}

/// L'entrée de ce Vanguard est-elle une vraie console (sous Windows, GetConsoleMode : pas un tube, pas un fichier) ?
pub(crate) fn console_reelle() -> bool {
    #[cfg(windows)]
    {
        crate::machine::windows::eleve::console_reelle()
    }
    #[cfg(not(windows))]
    {
        use std::io::IsTerminal as _;
        std::io::stdin().is_terminal()
    }
}

/// Ce qui désigne un processus, lu avant la question puis relu après la réponse.
#[cfg_attr(not(windows), allow(dead_code))] // relu par l'arrêt de Windows ; ailleurs, les essais seulement
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Identite {
    pub pid: u32,
    /// Heure de création (FILETIME) : un numéro repris a une autre heure.
    pub creation: Option<u64>,
    pub chemin: Option<String>,
}

/// La réponse « o » tient-elle encore, relue juste avant l'arrêt ? Elle ne vaut que pour CE processus, faisant
/// tourner CE programme, toujours illisible ou autre : un numéro repris, une autre image, une signature devenue
/// Microsoft lisible, ou une garde qui refuse maintenant (session ouverte depuis) l'annulent. `Err` : pourquoi,
/// au contexte `ou` de l'appelant.
#[cfg_attr(not(windows), allow(dead_code))] // comme `Identite`
pub(crate) fn confirmation_tient(
    avant: &Identite,
    apres: &Identite,
    signature: Signature,
    autre_garde: Option<&str>,
    ou: &'static str,
) -> Result<(), crate::modele::Echec> {
    let refus = |r: String| Err(crate::modele::Echec::refuse(ou, r));
    if let Some(r) = autre_garde {
        return refus(r.to_string());
    }
    let meme_heure = avant.creation.is_some() && avant.creation == apres.creation;
    if avant.pid != apres.pid || !meme_heure {
        return refus(trf!(
            "le PID {} désigne maintenant un autre processus : la réponse ne vaut pas pour lui, rien n'est arrêté",
            "PID {} now points to another process: the answer does not apply to it, nothing is stopped",
            avant.pid
        ));
    }
    let meme_image = matches!((&avant.chemin, &apres.chemin), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b));
    if !meme_image {
        return refus(tr!(
            "le processus fait maintenant tourner un autre programme : la réponse ne vaut pas pour lui, rien n'est arrêté",
            "the process now runs another program: the answer does not apply to it, nothing is stopped"
        )
        .to_string());
    }
    if signature == Signature::Microsoft {
        return refus(signe_microsoft().to_string());
    }
    Ok(())
}

/// Ce que Vanguard sait d'un programme (ou d'un fichier) à la signature illisible, montré avant la question. Chaque
/// texte vient du programme ou du système de fichiers, donc de n'importe qui : nettoyé et borné à l'affichage.
#[derive(Clone, Debug, Default)]
pub(crate) struct Portrait {
    /// Un processus (pid, compte, parent, lancement, ligne de commande) ou seulement un fichier.
    pub processus: bool,
    pub nom: Option<String>,
    pub chemin: Option<String>,
    pub pid: Option<u32>,
    pub compte: Option<String>,
    pub parent: Option<Parent>,
    pub lancement: Option<String>,
    pub ligne: Option<String>,
    pub taille: Option<u64>,
    pub date: Option<String>,
    pub sha256: Option<String>,
}

/// Le parent d'un processus montré dans le portrait : son nom, son numéro, et ce qu'on a pu vérifier.
#[derive(Clone, Debug)]
pub(crate) struct Parent {
    pub nom: String,
    pub pid: u32,
    pub filiation: Filiation,
}

/// Le processus qui porte le numéro du parent est-il bien le parent ?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Filiation {
    /// Né avant l'enfant : c'est lui.
    Vrai,
    /// Né après l'enfant : le vrai parent a fini, son numéro est repris par un autre.
    Repris,
    /// Une des deux heures de lancement ne se lit pas (processus protégé, autre compte) : on ne peut pas le dire.
    Inverifiable,
}

/// La filiation d'après les heures de création (FILETIME) du parent et de l'enfant. Une heure illisible ne dit pas
/// que le parent a fini : un processus protégé est bien vivant, seulement fermé à ce compte.
#[cfg_attr(not(windows), allow(dead_code))] // lu par l'arrêt de Windows ; ailleurs, les essais seulement
pub(crate) fn filiation(parent: Option<u64>, enfant: Option<u64>) -> Filiation {
    match (parent, enfant) {
        (Some(a), Some(b)) if a <= b => Filiation::Vrai,
        (Some(_), Some(_)) => Filiation::Repris,
        _ => Filiation::Inverifiable,
    }
}

/// Au-delà de cette taille, l'empreinte d'un fichier n'est pas calculée avant la question : la personne attendrait
/// sans savoir pourquoi (plusieurs secondes sur un disque lent).
pub(crate) const EMPREINTE_MAX: u64 = 256 * 1024 * 1024;

/// L'empreinte d'un fichier de cette taille se calcule-t-elle avant la question ? Taille illisible : non, le fichier
/// ne se lira pas mieux.
pub(crate) fn empreinte_a_calculer(taille: Option<u64>) -> bool {
    taille.is_some_and(|t| t <= EMPREINTE_MAX)
}

/// La mise de côté échouera-t-elle d'office ? `code` : l'erreur système de l'essai d'ouverture du fichier pour le
/// déplacer (`None` : il s'est ouvert). Partage ou verrou refusé : un programme en marche le tient ouvert, Windows
/// refusera le déplacement ; inutile de demander « o » pour échouer ensuite. `Some` : pourquoi, et quoi faire.
pub(crate) fn mise_de_cote_bloquee(code: Option<u32>) -> Option<String> {
    (illisibilite_connue(code?) == Some(Illisibilite::Verrouille)).then(|| {
        tr!(
            "le fichier est tenu ouvert par un programme en marche : Windows ne permet pas de le déplacer. Arrêtez d'abord ce programme (« Bloquer » l'arrête avant de mettre le fichier de côté), puis recommencez",
            "the file is held open by a running program: Windows does not allow moving it. Stop that program first (\"Block\" stops it before setting the file aside), then try again"
        )
        .to_string()
    })
}

/// Un texte hostile prêt à montrer : caractères de contrôle, séquences ANSI et bidi rendus visibles (« � »), longueur
/// bornée à `colonnes`.
pub(crate) fn propre(texte: &str, colonnes: usize) -> String {
    crate::ui::couper(&crate::ui::affichable(texte), colonnes)
}

/// Les lignes à montrer avant la question : pourquoi la signature ne se lit pas, puis le portrait.
pub(crate) fn lignes_du_portrait(raison: Illisibilite, p: &Portrait) -> Vec<String> {
    let inconnu = || tr!("inconnu", "unknown").to_string();
    let texte = |v: &Option<String>, n: usize| v.as_deref().map_or_else(inconnu, |t| propre(t, n));
    let mut lignes = vec![trf!(
        "Pourquoi la signature ne se lit pas : {}",
        "Why the signature cannot be read: {}",
        raison.texte()
    )];
    lignes.push(trf!("Nom : {}", "Name: {}", texte(&p.nom, 80)));
    lignes.push(trf!("Chemin : {}", "Path: {}", texte(&p.chemin, 300)));
    if p.processus {
        lignes.push(trf!(
            "PID : {}",
            "PID: {}",
            p.pid.map_or_else(inconnu, |n| n.to_string())
        ));
        lignes.push(trf!("Compte : {}", "Account: {}", texte(&p.compte, 80)));
        lignes.push(trf!(
            "Parent : {}",
            "Parent: {}",
            p.parent.as_ref().map_or_else(inconnu, |pa| {
                let (nom, pid) = (propre(&pa.nom, 80), pa.pid);
                match pa.filiation {
                    Filiation::Vrai => format!("{nom} (PID {pid})"),
                    Filiation::Repris => trf!(
                        "fini (son numéro, PID {pid}, est repris par un autre)",
                        "ended (its number, PID {pid}, is reused by another)"
                    ),
                    Filiation::Inverifiable => trf!(
                        "{nom} (PID {pid}), sans pouvoir vérifier que c'est bien lui (heure de lancement illisible)",
                        "{nom} (PID {pid}), without being able to check it is really the parent (start time unreadable)"
                    ),
                }
            })
        ));
        lignes.push(trf!("Lancé le : {}", "Started: {}", texte(&p.lancement, 40)));
        lignes.push(trf!(
            "Ligne de commande : {}",
            "Command line: {}",
            p.ligne
                .as_deref()
                .map_or_else(|| tr!("illisible", "unreadable").to_string(), |t| propre(t, 300))
        ));
    }
    let date = p.date.as_deref().map(|d| propre(d, 40));
    lignes.push(match (p.taille, date) {
        (None, None) => tr!("Fichier : illisible", "File: unreadable").to_string(),
        (Some(t), Some(d)) => trf!("Fichier : {t} octets, modifié le {d}", "File: {t} bytes, modified {d}"),
        (Some(t), None) => trf!(
            "Fichier : {t} octets, date de modification illisible",
            "File: {t} bytes, modification date unreadable"
        ),
        (None, Some(d)) => trf!(
            "Fichier : taille illisible, modifié le {d}",
            "File: size unreadable, modified {d}"
        ),
    });
    let sans_empreinte = if p.sha256.is_none() && p.taille.is_some() && !empreinte_a_calculer(p.taille) {
        trf!(
            "non calculée (fichier de plus de {} Mo : trop long à lire avant la question)",
            "not computed (file over {} MB: too long to read before the question)",
            EMPREINTE_MAX / (1024 * 1024)
        )
    } else {
        tr!("illisible", "unreadable").to_string()
    };
    lignes.push(trf!(
        "SHA-256 : {}",
        "SHA-256: {}",
        p.sha256.as_deref().map_or(sans_empreinte, |t| propre(t, 64))
    ));
    lignes
}

/// Montre pourquoi la signature ne se lit pas et le portrait, puis pose `question` ; `true` seulement sur « o ».
pub(crate) fn montrer_et_confirmer(raison: Illisibilite, p: &Portrait, question: &str) -> bool {
    println!();
    for l in lignes_du_portrait(raison, p) {
        crate::ui::afficher_aligne("    ", &l, 6, "");
    }
    confirmer(console_reelle(), question, crate::ui::demander_ou_defaut)
}

/// Le portrait d'un fichier : son nom, son chemin long (pas 8.3), sa taille et sa date, son SHA-256 s'il se lit.
pub(crate) fn portrait_de_fichier(chemin: &std::path::Path) -> Portrait {
    let texte = chemin.to_string_lossy().into_owned();
    #[cfg(windows)]
    let long = crate::machine::windows::environnement::chemin_long(&texte).unwrap_or(texte);
    #[cfg(not(windows))]
    let long = texte;
    let meta = std::fs::metadata(chemin).ok();
    let taille = meta.as_ref().map(std::fs::Metadata::len);
    Portrait {
        nom: chemin.file_name().map(|n| n.to_string_lossy().into_owned()),
        taille,
        date: meta.and_then(|m| m.modified().ok()).map(date_locale),
        sha256: empreinte_a_calculer(taille)
            .then(|| crate::protection::empreintes::sha256(chemin))
            .flatten()
            .map(|e| crate::protection::empreintes::hex(&e)),
        chemin: Some(long),
        ..Portrait::default()
    }
}

/// Une heure du système, à l'heure de cet ordinateur.
pub(crate) fn date_locale(t: std::time::SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(t)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// Ce qui est noté au journal d'un geste confirmé malgré une signature illisible : la raison, et l'empreinte si le
/// fichier se lisait.
pub(crate) fn note_confirmee(quarantaine: bool, raison: Illisibilite, sha256: Option<&str>) -> String {
    let empreinte = sha256.unwrap_or("illisible");
    if quarantaine {
        format!(
            "quarantaine confirmée malgré une signature illisible ({}) ; SHA-256 {empreinte}",
            raison.texte()
        )
    } else {
        format!(
            "arrêt confirmé malgré une signature illisible ({}) ; SHA-256 {empreinte}",
            raison.texte()
        )
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
        // Sans personne pour confirmer (geste automatique, pas de vraie console) : Microsoft et illisible refusent,
        // et le refus d'illisible dit quoi faire ; autre ne refuse pas (et n'ouvre rien de plus).
        assert!(signature_intouchable(Signature::Microsoft).is_some());
        let illisible = signature_intouchable(Signature::Illisible(Illisibilite::Verrouille)).unwrap();
        assert!(
            illisible.contains("à la main") || illisible.contains("by hand"),
            "{illisible}"
        );
        assert_eq!(signature_intouchable(Signature::Autre), None);
        assert_eq!(signature_de(Ok(true), Ok(false)), Signature::Microsoft);
        assert_eq!(signature_de(Ok(false), Ok(true)), Signature::Microsoft);
        // Microsoft par une voie, l'autre illisible : refusé de toute façon.
        let r = Illisibilite::Catalogues;
        assert_eq!(signature_de(Err(r), Ok(true)), Signature::Microsoft);
        assert_eq!(signature_de(Err(r), Ok(false)), Signature::Illisible(r));
        assert_eq!(signature_de(Ok(false), Err(r)), Signature::Illisible(r));
        assert_eq!(signature_de(Ok(false), Ok(false)), Signature::Autre);
        // Les deux illisibles : CryptSvc d'abord, sinon la signature intégrée (lue sur le fichier même).
        assert_eq!(
            signature_de(Err(Illisibilite::CryptSvc), Err(Illisibilite::Verrouille)),
            Signature::Illisible(Illisibilite::CryptSvc)
        );
        assert_eq!(
            signature_de(Err(Illisibilite::Catalogues), Err(Illisibilite::Verrouille)),
            Signature::Illisible(Illisibilite::Verrouille)
        );
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

    /// Relecture de D6a : un sujet « Microsoft » ne suffit pas, il faut une racine de Microsoft au bout de la chaîne
    /// (une autorité faite maison, posée dans le magasin du compte, se vérifie, mais n'en est pas une).
    #[test]
    fn signature_microsoft_par_sa_racine() {
        let sujet = "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows";
        assert!(signe_par_microsoft(sujet, &[], Racine::Produit));
        assert!(!signe_par_microsoft(sujet, &[], Racine::Aucune));
        assert!(!signe_par_microsoft(
            "C=US, O=Mozilla Corporation, CN=Mozilla Corporation",
            &[],
            Racine::Produit
        ));
    }

    /// Défense D6a, racine 2011 : Edge, Office et Teams (Code Signing PCA 2011, racine application) sont Microsoft ;
    /// ceux que Microsoft signe pour d'autres éditeurs (WHQL, attestés, ELAM, composants tiers, Store) ne le sont
    /// sous aucune racine ; un sujet qui se joue des guillemets ou double son O non plus.
    #[test]
    fn signature_microsoft_racine_application_et_signataires_pour_autrui() {
        const CODE: &str = "1.3.6.1.5.5.7.3.3";
        let windows = "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Windows";
        let corporation = "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation";
        let systeme = ["1.3.6.1.4.1.311.10.3.6", CODE];
        // Les deux lectures de la politique : la première illisible rend la chaîne illisible ; la seconde ne compte
        // que si la première dit non, et illisible elle ne donne jamais la racine application.
        assert_eq!(racine_selon(None, Some(true)), None);
        assert_eq!(racine_selon(Some(true), None), Some(Racine::Produit));
        assert_eq!(racine_selon(Some(true), Some(false)), Some(Racine::Produit));
        assert_eq!(racine_selon(Some(false), Some(true)), Some(Racine::Application));
        assert_eq!(racine_selon(Some(false), Some(false)), Some(Racine::Aucune));
        assert_eq!(racine_selon(Some(false), None), Some(Racine::Aucune));
        // Windows sous sa racine, Edge sous la racine 2011.
        assert!(signe_par_microsoft(windows, &systeme, Racine::Produit));
        assert!(signe_par_microsoft(corporation, &[CODE], Racine::Produit));
        assert!(signe_par_microsoft(corporation, &[CODE], Racine::Application));
        assert!(signe_par_microsoft(
            "C=US; O=Microsoft Corporation + OU=MOPR; CN=Microsoft Corporation",
            &[CODE],
            Racine::Application
        ));
        // Racine 2011 : un autre CN, ou sans l'usage signature de code (ou sans usage du tout), n'est pas Microsoft.
        assert!(!signe_par_microsoft(windows, &systeme, Racine::Application));
        assert!(!signe_par_microsoft(corporation, &[], Racine::Application));
        assert!(!signe_par_microsoft(
            corporation,
            &["1.3.6.1.4.1.311.10.3.6"],
            Racine::Application
        ));
        // Signés par Microsoft pour d'autres éditeurs : sous aucune racine, par leur CN ou par leur usage.
        for cn in [
            "Microsoft Windows Hardware Compatibility Publisher",
            "Microsoft Windows Early Launch Anti-malware Publisher",
            "Microsoft Windows Third Party Application Component",
            "Microsoft 3rd Party Application Component",
        ] {
            let sujet = format!("C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN={cn}");
            for racine in [Racine::Produit, Racine::Application] {
                assert!(!signe_par_microsoft(&sujet, &[CODE], racine), "{cn}");
            }
        }
        for usage in [
            "1.3.6.1.4.1.311.10.3.5",
            "1.3.6.1.4.1.311.10.3.5.1",
            "1.3.6.1.4.1.311.61.4.1",
            "1.3.6.1.4.1.311.76.3.1",
        ] {
            assert!(
                !signe_par_microsoft(windows, &[usage, CODE], Racine::Produit),
                "{usage}"
            );
            assert!(
                !signe_par_microsoft(corporation, &[CODE, usage], Racine::Application),
                "{usage}"
            );
        }
        // Le sujet lu entier, guillemets compris : un O caché dans une valeur, ou deux O, ou deux CN, ne passent pas.
        for sujet in [
            "C=US, O=Evil, CN=\"x, O=Microsoft Corporation\"",
            "C=US, O=\"Evil, O=Microsoft Corporation\", CN=Microsoft Corporation",
            "C=US, O=\"Microsoft Corporation, Inc\", CN=Microsoft Corporation",
            "C=US, O=Microsoft Corporation, O=Evil, CN=Microsoft Corporation",
            "C=US, O=Microsoft Corporation, CN=Microsoft Corporation, CN=Evil",
            "C=US, O=Microsoft Corporation",
            "CN=Microsoft Windows",
            "C=US, O=Microsoft, CN=Microsoft Windows",
            "",
        ] {
            for racine in [Racine::Produit, Racine::Application] {
                assert!(!signe_par_microsoft(sujet, &[CODE], racine), "{sujet}");
            }
        }
        // Une valeur entre guillemets, guillemets doublés compris, se lit entière.
        assert_eq!(
            attributs("O=\"Microsoft Corporation\", CN=\"a \"\"b\"\", c\""),
            vec![
                ("O".to_string(), "Microsoft Corporation".to_string()),
                ("CN".to_string(), "a \"b\", c".to_string())
            ]
        );
        assert!(signe_par_microsoft(
            "O=\"Microsoft Corporation\", CN=Microsoft Windows",
            &[],
            Racine::Produit
        ));
    }

    /// Relecture de la racine 2011, B3 : la politique est lue sans drapeau, puis avec la seule racine application
    /// si la première dit non ; jamais avec la racine d'essai (ENABLE_TEST_ROOT, 0x0001_0000).
    #[test]
    fn racine_lue_jamais_la_racine_d_essai() {
        let lire = |reponses: Vec<Option<bool>>| {
            let mut reponses = reponses.into_iter();
            let mut drapeaux = Vec::new();
            let racine = racine_lue(|d| {
                drapeaux.push(d);
                reponses.next().flatten()
            });
            (racine, drapeaux)
        };
        let deux = vec![0, RACINE_APPLICATION];
        assert_eq!(lire(vec![Some(true)]), (Some(Racine::Produit), vec![0]));
        assert_eq!(lire(vec![None]), (None, vec![0]));
        assert_eq!(
            lire(vec![Some(false), Some(true)]),
            (Some(Racine::Application), deux.clone())
        );
        assert_eq!(
            lire(vec![Some(false), Some(false)]),
            (Some(Racine::Aucune), deux.clone())
        );
        assert_eq!(lire(vec![Some(false), None]), (Some(Racine::Aucune), deux));
        assert_eq!(RACINE_APPLICATION, 0x0002_0000);
        assert_eq!(RACINE_APPLICATION & 0x0001_0000, 0);
    }

    /// Relecture de la racine 2011, B1, B2, B6 : sous une racine produit, seuls trois signataires sont Microsoft
    /// (liste blanche) ; « Software Compatibility Publisher » (composants tiers de Windows Update) et un signataire
    /// inconnu ne le sont pas, avec ou sans usages ; ceux de Microsoft passés par WHQL ou ELAM non plus (choisi).
    #[test]
    fn signature_microsoft_liste_blanche_sous_la_racine_produit() {
        const CODE: &str = "1.3.6.1.5.5.7.3.3";
        const ELAM: &str = "1.3.6.1.4.1.311.61.4.1";
        let sujet = |cn: &str| format!("C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN={cn}");
        for cn in [
            "Microsoft Windows",
            "Microsoft Windows Publisher",
            "Microsoft Corporation",
        ] {
            assert!(signe_par_microsoft(&sujet(cn), &[CODE], Racine::Produit), "{cn}");
        }
        for cn in [
            "Microsoft Windows Software Compatibility Publisher",
            "Microsoft Windows Nouveau Publisher",
            "Microsoft Windows 3rd party Component",
            "MICROSOFT WINDOWS HARDWARE COMPATIBILITY PUBLISHER",
            "Microsoft Windows Publisher Extra",
        ] {
            for usages in [&[][..], &[CODE][..]] {
                for racine in [Racine::Produit, Racine::Application] {
                    assert!(!signe_par_microsoft(&sujet(cn), usages, racine), "{cn}");
                }
            }
        }
        // L'ELAM de Defender (WdBoot.sys) : signé pour le démarrage anticipé, pas « Microsoft » (choisi).
        assert!(!signe_par_microsoft(
            &sujet("Microsoft Windows Early Launch Anti-malware Publisher"),
            &[ELAM, CODE],
            Racine::Produit
        ));
        // Un guillemet jamais fermé, « Microsoft » dans OU seulement, un paquet Store d'un tiers.
        for (s, usages) in [
            ("C=US, CN=\"Microsoft Corporation, O=Microsoft Corporation", &[CODE][..]),
            (
                "C=US, O=Evil, OU=Microsoft Corporation, CN=Microsoft Corporation",
                &[CODE][..],
            ),
            (
                "C=SE, O=Spotify AB, OU=Microsoft Store, CN=Spotify AB",
                &[CODE, "1.3.6.1.4.1.311.76.3.1"][..],
            ),
        ] {
            for racine in [Racine::Produit, Racine::Application] {
                assert!(!signe_par_microsoft(s, usages, racine), "{s}");
            }
        }
    }

    /// Relecture de D6a : avant de remettre un arrêt à Vanguard administrateur, une signature illisible ici ne refuse
    /// pas (l'administrateur la relit avec ses droits et refuse s'il ne la lit pas non plus) ; arrêté ici, elle refuse.
    /// Microsoft refuse toujours, Autre jamais.
    #[test]
    fn signature_illisible_rejugee_par_l_administrateur() {
        let illisible = Signature::Illisible(Illisibilite::Verrouille);
        // Automatique : refusé ici ; remis à Vanguard administrateur, qui le refuse (ordre sans `demande`).
        assert_eq!(signature_avant_remise(illisible, false, true), Avant::Rien);
        assert!(matches!(
            signature_avant_remise(illisible, true, true),
            Avant::Refuse(_)
        ));
        // Demandé par la personne (choix 3.1) : la question viendra là où le geste se fait, ici ou remis.
        for ici in [false, true] {
            assert_eq!(signature_avant_remise(illisible, ici, false), Avant::Confirmera);
        }
        for ici in [false, true] {
            for automatique in [false, true] {
                assert!(matches!(
                    signature_avant_remise(Signature::Microsoft, ici, automatique),
                    Avant::Refuse(_)
                ));
                assert_eq!(signature_avant_remise(Signature::Autre, ici, automatique), Avant::Rien);
            }
        }
    }

    /// Rançongiciel (geste automatique) + signature illisible : refusé à chaque étape (préparé ici, rejugé par
    /// Vanguard administrateur, au moment du geste), même devant une vraie console, sans jamais poser la question.
    #[test]
    fn rancongiciel_automatique_et_illisible_refuse() {
        for r in [Illisibilite::Verrouille, Illisibilite::Absent, Illisibilite::CryptSvc] {
            let illisible = Signature::Illisible(r);
            // Préparé ici, ou rejugé par l'administrateur (`ordres::juger` : l'ordre part sans `demande`).
            assert!(matches!(
                signature_avant_remise(illisible, true, true),
                Avant::Refuse(_)
            ));
            // Au moment du geste : `Confirmation::Jamais`, la garde sans question.
            assert!(signature_intouchable(illisible).is_some());
            for console in [false, true] {
                assert!(matches!(
                    decider_signature(illisible, None, false, console),
                    Decision::Refuse(_)
                ));
            }
        }
    }

    /// La raison d'une signature illisible, d'après le code de Windows (Win32 ou HRESULT 0x8007xxxx).
    #[test]
    fn illisibilite_d_apres_le_code() {
        for (code, attendu) in [
            (32, Illisibilite::Verrouille),
            (0x8007_0020, Illisibilite::Verrouille),
            (0x8007_0021, Illisibilite::Verrouille),
            (5, Illisibilite::AccesRefuse),
            (0x8007_0005, Illisibilite::AccesRefuse),
            (2, Illisibilite::Absent),
            (0x8007_0003, Illisibilite::Absent),
            (1722, Illisibilite::CryptSvc),
            (0x8007_06BA, Illisibilite::CryptSvc),
            (0x8007_06D9, Illisibilite::CryptSvc),
            (0x8007_0422, Illisibilite::CryptSvc),
            (0x8007_0426, Illisibilite::CryptSvc),
        ] {
            assert_eq!(illisibilite_connue(code), Some(attendu), "{code:x}");
        }
        for code in [0, 0x8009_2003, 0x8007_000E, 0x800B_0100] {
            assert_eq!(illisibilite_connue(code), None, "{code:x}");
        }
        assert!(Illisibilite::Code(0x8009_2003).texte().contains("0x80092003"));
    }

    /// Choix 3.1 : illisible + demandé + vraie console = question ; sans console, ou automatique (rançongiciel,
    /// protection active, nuit) = refus qui dit de le faire à la main.
    #[test]
    fn illisible_demande_en_console_pose_la_question() {
        let r = Illisibilite::Verrouille;
        let illisible = Signature::Illisible(r);
        assert_eq!(decider_signature(illisible, None, true, true), Decision::Demander(r));
        for (demande, console) in [(true, false), (false, true), (false, false)] {
            let Decision::Refuse(raison) = decider_signature(illisible, None, demande, console) else {
                panic!("{demande} {console}");
            };
            assert!(raison.contains("à la main") || raison.contains("by hand"), "{raison}");
        }
        assert_eq!(decider_signature(Signature::Autre, None, true, true), Decision::Permis);
        assert_eq!(
            decider_signature(Signature::Autre, None, false, false),
            Decision::Permis
        );
    }

    /// Microsoft lisible, session à distance, processus vital : refus SANS question, même illisible et demandé.
    #[test]
    fn les_autres_gardes_refusent_sans_question() {
        assert!(matches!(
            decider_signature(Signature::Microsoft, None, true, true),
            Decision::Refuse(_)
        ));
        // Un programme lancé depuis WinRM (wsmprovhost), parent vivant né avant lui.
        let session = ascendance_de_session(
            4242,
            |p| match p {
                4242 => Some(Fiche {
                    parent: 100,
                    nom: "outil.exe".into(),
                    creation: Some(20),
                }),
                100 => Some(Fiche {
                    parent: 0,
                    nom: "wsmprovhost.exe".into(),
                    creation: Some(10),
                }),
                _ => None,
            },
            false,
        );
        assert!(session.is_some());
        let vital = processus_intouchable(
            4242,
            "lsass.exe",
            Some(r"C:\Users\alice\lsass.exe"),
            &HashSet::new(),
            Os::Windows,
        );
        assert!(vital.is_some());
        for garde in [session, vital] {
            let d = decider_signature(Signature::Illisible(Illisibilite::Verrouille), garde, true, true);
            assert_eq!(d, Decision::Refuse(garde.unwrap().to_string()));
        }
    }

    /// Seul « o » (ou « y ») arrête ; Entrée, fin de l'entrée ou erreur de lecture (réponse vide), le reste : non.
    /// Sans vraie console, la question n'est même pas posée.
    #[test]
    fn seul_o_confirme() {
        for oui in ["o", "O", "oui", "y", "yes", " o "] {
            assert!(confirmer(true, "?", |_| oui.to_string()), "{oui}");
        }
        for non in ["", "n", "non", "no", "0", "oo", "\x1b[A", "ok"] {
            assert!(!confirmer(true, "?", |_| non.to_string()), "{non:?}");
        }
        let mut posee = false;
        assert!(!confirmer(false, "?", |_| {
            posee = true;
            "o".to_string()
        }));
        assert!(!posee);
    }

    /// La réponse ne vaut que pour le processus vu : un PID repris (autre heure de création), une autre image, une
    /// signature devenue Microsoft lisible, ou une garde qui refuse maintenant, et rien n'est arrêté.
    #[test]
    fn la_reponse_ne_vaut_que_pour_le_processus_vu() {
        let avant = Identite {
            pid: 4242,
            creation: Some(133_000_000_000_000_000),
            chemin: Some(r"C:\Users\alice\AppData\Local\Temp\outil.exe".into()),
        };
        let illisible = Signature::Illisible(Illisibilite::Verrouille);
        assert_eq!(
            confirmation_tient(&avant, &avant.clone(), illisible, None, "essai"),
            Ok(())
        );
        let casse = Identite {
            chemin: Some(r"c:\users\alice\appdata\local\temp\OUTIL.EXE".into()),
            ..avant.clone()
        };
        assert_eq!(
            confirmation_tient(&avant, &casse, Signature::Autre, None, "essai"),
            Ok(())
        );
        let repris = Identite {
            creation: Some(133_000_000_000_000_001),
            ..avant.clone()
        };
        let autre_image = Identite {
            chemin: Some(r"C:\Users\alice\autre.exe".into()),
            ..avant.clone()
        };
        let illisible_apres = Identite {
            creation: None,
            ..avant.clone()
        };
        let sans_chemin = Identite {
            chemin: None,
            ..avant.clone()
        };
        for apres in [&repris, &autre_image, &illisible_apres, &sans_chemin] {
            assert!(
                confirmation_tient(&avant, apres, illisible, None, "essai").is_err(),
                "{apres:?}"
            );
        }
        assert!(confirmation_tient(&avant, &avant, Signature::Microsoft, None, "essai").is_err());
        assert!(confirmation_tient(&avant, &avant, illisible, Some("session"), "essai").is_err());
        let sans_heure = Identite {
            creation: None,
            ..avant.clone()
        };
        assert!(confirmation_tient(&sans_heure, &sans_heure, illisible, None, "essai").is_err());
    }

    /// Un nom, un chemin ou une ligne de commande hostiles (séquence ANSI, retour chariot, très long) sont nettoyés et
    /// bornés avant d'être montrés.
    #[test]
    fn portrait_hostile_nettoye() {
        let long = "A".repeat(5000);
        let p = Portrait {
            processus: true,
            nom: Some("ok\x1b[2K\rmicrosoft.exe".into()),
            chemin: Some(format!("C:\\x\\{long}\u{202e}exe.txt")),
            pid: Some(4242),
            compte: Some("PC\\alice\x1b]52;c;aGk=\x07".into()),
            parent: Some(Parent {
                nom: "explorer\n✔ sain".into(),
                pid: 100,
                filiation: Filiation::Vrai,
            }),
            lancement: Some("2026-11-03 10:00:00".into()),
            ligne: Some(format!("outil.exe {long}\r\n")),
            taille: Some(1234),
            date: Some("2026-11-03".into()),
            sha256: None,
        };
        let lignes = lignes_du_portrait(Illisibilite::Verrouille, &p);
        for l in &lignes {
            assert!(!crate::ui::contient_un_piege(l), "{l:?}");
            assert!(crate::ui::largeur_affichee(l) <= 340, "{}", l.len());
        }
        let tout = lignes.join("\n");
        assert!(tout.contains("4242") && tout.contains("1234"));
        assert!(tout.contains("illisible") || tout.contains("unreadable"));
        // Un fichier seulement : ni PID ni compte.
        let fichier = Portrait { processus: false, ..p };
        assert!(lignes_du_portrait(Illisibilite::Absent, &fichier).len() < lignes.len());
        // La note du journal : la raison et l'empreinte, si elle est connue.
        let n = note_confirmee(false, Illisibilite::Verrouille, Some("ab12"));
        assert!(n.starts_with("arrêt confirmé") && n.contains("ab12"));
        assert!(note_confirmee(true, Illisibilite::Absent, None).contains("SHA-256 illisible"));
    }

    /// Relecture de D6a-signature (M1) : un parent dont l'heure de lancement ne se lit pas (processus protégé, autre
    /// compte) n'est pas dit « fini » ; seul un parent né après l'enfant l'est.
    #[test]
    fn parent_illisible_n_est_pas_fini() {
        assert_eq!(filiation(Some(10), Some(20)), Filiation::Vrai);
        assert_eq!(filiation(Some(20), Some(20)), Filiation::Vrai);
        assert_eq!(filiation(Some(30), Some(20)), Filiation::Repris);
        for (p, e) in [(None, Some(20)), (Some(10), None), (None, None)] {
            assert_eq!(filiation(p, e), Filiation::Inverifiable, "{p:?} {e:?}");
        }
        let avec = |filiation| {
            let p = Portrait {
                processus: true,
                parent: Some(Parent {
                    nom: "services.exe".into(),
                    pid: 700,
                    filiation,
                }),
                ..Portrait::default()
            };
            lignes_du_portrait(Illisibilite::Verrouille, &p).join("\n")
        };
        let protege = avec(Filiation::Inverifiable);
        assert!(protege.contains("services.exe") && protege.contains("700"), "{protege}");
        assert!(!protege.contains("fini") && !protege.contains("ended"), "{protege}");
        let repris = avec(Filiation::Repris);
        assert!(repris.contains("fini") || repris.contains("ended"), "{repris}");
        assert!(!repris.contains("services.exe"), "{repris}");
    }

    /// Relecture de D6a-signature (M2, M3) : taille et date illisibles se disent en une fois ; un fichier trop gros
    /// n'est pas lu en entier avant la question, et le portrait dit pourquoi l'empreinte manque.
    #[test]
    fn portrait_du_fichier_sans_taille_ni_empreinte() {
        let vide = lignes_du_portrait(Illisibilite::Absent, &Portrait::default()).join("\n");
        assert!(
            vide.contains("Fichier : illisible") || vide.contains("File: unreadable"),
            "{vide}"
        );
        assert!(!vide.contains("inconnu, modifié le inconnu"), "{vide}");
        let sans_date = Portrait {
            taille: Some(12),
            ..Portrait::default()
        };
        let l = lignes_du_portrait(Illisibilite::Absent, &sans_date).join("\n");
        assert!(l.contains("12") && (l.contains("date de modification illisible") || l.contains("date unreadable")));
        assert!(empreinte_a_calculer(Some(0)));
        assert!(empreinte_a_calculer(Some(EMPREINTE_MAX)));
        assert!(!empreinte_a_calculer(Some(EMPREINTE_MAX + 1)));
        assert!(!empreinte_a_calculer(None));
        let gros = Portrait {
            taille: Some(EMPREINTE_MAX + 1),
            ..Portrait::default()
        };
        let l = lignes_du_portrait(Illisibilite::Verrouille, &gros).join("\n");
        assert!(l.contains("non calculée") || l.contains("not computed"), "{l}");
        // Pour de vrai : un petit fichier a son empreinte ; un absent, aucune, sans attendre.
        let dossier = crate::socle::dossier_local().join("essai-portrait");
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("petit.bin");
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            portrait_de_fichier(&f).sha256.as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(portrait_de_fichier(&dossier.join("absent.bin")).sha256, None);
    }

    /// Relecture de D6a-signature (M6, M7, M8) : un fichier tenu ouvert sans partage ne reçoit pas la question
    /// « Mettre de côté ? » (le déplacement échouerait) ; une erreur sans code ne s'affiche pas « code 0 » ; un fichier
    /// signé Microsoft et refusé par une autre garde dit les deux raisons.
    #[test]
    fn mineurs_de_la_relecture_d6a_signature() {
        for code in [32, 33, 0x8007_0020] {
            let r = mise_de_cote_bloquee(Some(code)).unwrap();
            assert!(
                r.contains("Arrêtez d'abord") || r.contains("Stop that program first"),
                "{r}"
            );
        }
        for code in [None, Some(5), Some(2), Some(0)] {
            assert_eq!(mise_de_cote_bloquee(code), None, "{code:?}");
        }
        assert_eq!(raison_de_lecture(None), Illisibilite::SansCode);
        assert!(!Illisibilite::SansCode.texte().contains("0x"));
        assert_eq!(raison_de_lecture(Some(32)), Illisibilite::Verrouille);
        assert_eq!(raison_de_lecture(Some(0x8009_2003)), Illisibilite::Code(0x8009_2003));
        let Decision::Refuse(r) = decider_signature(Signature::Microsoft, Some("fichier du système"), true, true)
        else {
            panic!("Microsoft et une autre garde : refus");
        };
        assert!(r.contains("fichier du système") && (r.contains("Microsoft")), "{r}");
    }

    /// Relecture de D6a : sous Unix (orphelins rattachés à init), un parent absent est caché (hidepid) ou illisible,
    /// pas fini : pendant une session, la lignée est incertaine et rien n'est arrêté. init (1) illisible finit la
    /// lignée. Sous Windows, un parent absent est fini.
    #[test]
    fn parent_cache_pendant_une_session() {
        // bash (900) sous sshd-session (850), que ce compte ne voit pas.
        let v = [(900, 850, "bash", Some(30))];
        let unix = Lecture {
            parent_absent_cache: true,
            racine: None,
        };
        assert!(ascendance_selon(900, instantane(&v), false, unix).is_some());
        assert_eq!(ascendance_selon(900, instantane(&v), true, unix), None);
        assert_eq!(ascendance_selon(900, instantane(&v), false, Lecture::default()), None);
        // Sous init caché (systemd --user, rattaché à 1) : la lignée finit là.
        let w = [(900, 1, "systemd", Some(30))];
        assert_eq!(ascendance_selon(900, instantane(&w), false, unix), None);
    }

    /// Relecture de D6a : un membre d'une lignée gelée est lu jusqu'à sa racine seulement. Ce qu'elle a lancé n'est pas
    /// une session (même si elle en descend : elle est jugée elle-même) ; un shell de session pris dans son groupe
    /// sans descendre d'elle reste intouché.
    #[test]
    fn membre_gele_lu_jusqu_a_sa_racine() {
        let v = [
            (1, 0, "systemd", Some(1)),
            (10, 1, "sshd", Some(2)),
            (20, 10, "sshd-session", Some(3)),
            (30, 20, "bash", Some(4)),
            (40, 30, "chiffreur", Some(5)),
            (50, 40, "enfant", Some(6)),
        ];
        let sous = |racine| Lecture {
            parent_absent_cache: true,
            racine: Some(racine),
        };
        assert_eq!(ascendance_selon(50, instantane(&v), false, sous(40)), None);
        assert!(ascendance_selon(30, instantane(&v), false, sous(40)).is_some());
        // Sans racine, le même enfant descend de la session.
        assert!(ascendance_selon(50, instantane(&v), false, Lecture::default()).is_some());
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

    /// sshd redémarré ou privé des mots de passe (défense D6c) : une session SSH entrante l'interdit, sur 22, sur un
    /// port de sshd_config ou tenue par sshd ; ni un SSH qui part d'ici, ni le Bureau à distance (l'auteur essaie
    /// par RDP).
    #[test]
    fn sessions_ssh_entrantes() {
        assert!(session_ssh_entrante(
            &etablie("198.51.100.20", 22, 51234, None, true),
            &[]
        ));
        assert!(session_ssh_entrante(
            &etablie("198.51.100.20", 2222, 51234, None, true),
            &[2222]
        ));
        for p in ["sshd", r"C:\Windows\System32\OpenSSH\sshd-session.exe", "SSHD.EXE"] {
            assert!(
                session_ssh_entrante(&etablie("198.51.100.20", 4000, 51234, Some(p), true), &[]),
                "{p}"
            );
        }
        assert!(!session_ssh_entrante(
            &etablie("198.51.100.20", 51234, 22, Some("ssh.exe"), false),
            &[]
        ));
        assert!(!session_ssh_entrante(
            &etablie("198.51.100.20", 3389, 51234, Some("svchost"), true),
            &[22]
        ));
        assert!(!session_ssh_entrante(
            &etablie("198.51.100.20", 2222, 51234, None, true),
            &[22]
        ));
    }

    /// Pour sshd, une table TCP illisible (IPv4 ou IPv6) rend la session illisible : une session en IPv6 seulement y
    /// échapperait, et sshd serait redémarré (relecture D6c). Pour le reste, une table suffit, comme avant.
    #[test]
    fn sshd_exige_les_deux_tables() {
        assert!(tables_suffisantes(true, true, true));
        assert!(!tables_suffisantes(true, false, true));
        assert!(!tables_suffisantes(false, true, true));
        assert!(!tables_suffisantes(false, false, true));
        assert!(tables_suffisantes(true, false, false));
        assert!(tables_suffisantes(false, true, false));
        assert!(!tables_suffisantes(false, false, false));
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
