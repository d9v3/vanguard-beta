//! Base de connaissances : service attendu sur chaque port et niveau de risque.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Niveau {
    Info,
    Moyen,
    Eleve,
    Critique,
}

impl Niveau {
    pub fn libelle(self) -> &'static str {
        match self {
            Niveau::Info => "INFO",
            Niveau::Moyen => crate::tr!("MOYEN", "MEDIUM"),
            Niveau::Eleve => crate::tr!("ÉLEVÉ", "HIGH"),
            Niveau::Critique => crate::tr!("CRITIQUE", "CRITICAL"),
        }
    }

    pub fn penalite(self) -> u32 {
        match self {
            Niveau::Info => 0,
            Niveau::Moyen => 5,
            Niveau::Eleve => 15,
            Niveau::Critique => 30,
        }
    }
}

pub struct InfoPort {
    pub service: &'static str,
    pub niveau: Niveau,
    pub conseil: &'static str,
}

/// Ports scannés par défaut (TCP courants sur un réseau domestique).
pub const PORTS_COURANTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 389, 443, 445, 465, 512, 513, 514, 515, 548, 554, 587,
    631, 636, 873, 993, 995, 1080, 1433, 1521, 1723, 1883, 2049, 2375, 2376, 3000, 3128, 3306, 3389, 3689, 4444, 5000,
    5001, 5432, 5555, 5900, 5901, 6379, 6443, 7000, 7070, 7547, 8000, 8008, 8009, 8080, 8081, 8086, 8088, 8123, 8200,
    8443, 8888, 9000, 9090, 9100, 9200, 9443, 10000, 11211, 27017, 32400, 49152, 62078,
];

/// Ports UDP sondés : services qui répondent à une requête de leur protocole (voir `scan::scanner_udp`).
pub const PORTS_UDP: &[u16] = &[53, 123, 137, 161, 1900, 5353];

/// Service et risque d'un port UDP qui a répondu.
pub fn info_udp(port: u16) -> InfoPort {
    use Niveau::{Eleve, Info, Moyen};
    let (service, niveau, conseil) = match port {
        53 => (
            "DNS",
            Info,
            crate::tr!(
                "Résout les noms : normal sur le routeur. Sur un autre appareil, à reconnaître (Pi-hole, serveur…).",
                "Resolves names: normal on the router. On another device, make sure you know it (Pi-hole, server…)."
            ),
        ),
        123 => (
            "NTP",
            Info,
            crate::tr!(
                "Donne l'heure au réseau : sans danger.",
                "Gives the time to the network: harmless."
            ),
        ),
        137 => (
            "NetBIOS",
            Moyen,
            crate::tr!(
                "Vieux protocole Windows qui annonce le nom de l'appareil à tout le réseau. À couper s'il ne sert pas.",
                "Old Windows protocol announcing the device name to the whole network. Turn it off if unused."
            ),
        ),
        161 => (
            "SNMP",
            Eleve,
            crate::tr!(
                "Répond avec le mot de passe par défaut « public » : livre sa configuration à tout le réseau, parfois la laisse modifier. Changez la communauté SNMP ou coupez SNMP dans l'appareil.",
                "Answers with the default password “public”: gives its configuration to the whole network, sometimes lets it be changed. Change the SNMP community or turn SNMP off on the device."
            ),
        ),
        1900 => (
            "SSDP / UPnP",
            Moyen,
            crate::tr!(
                "Annonce l'appareil par UPnP ; sur le routeur, permet aux appareils d'ouvrir des ports vers Internet tout seuls. À couper s'il ne sert pas.",
                "Announces the device over UPnP; on the router, lets devices open ports to the Internet by themselves. Turn it off if unused."
            ),
        ),
        5353 => (
            "mDNS (Bonjour)",
            Info,
            crate::tr!(
                "Annonce ses services (AirPlay, imprimante, Chromecast) : normal sur un réseau domestique.",
                "Announces its services (AirPlay, printer, Chromecast): normal on a home network."
            ),
        ),
        _ => (inconnu(), Info, ""),
    };
    InfoPort {
        service,
        niveau,
        conseil,
    }
}

/// Ports utilisés pour savoir si une machine est en ligne.
pub const PORTS_DECOUVERTE: &[u16] = &[80, 443, 22, 445, 139, 53, 8080, 62078, 7000, 8009];

/// Ports où l'on envoie une requête HTTP pour lire l'en-tête `Server`.
pub const PORTS_HTTP: &[u16] = &[
    80, 81, 3000, 5000, 7547, 8000, 8008, 8080, 8081, 8086, 8088, 8123, 8888, 9000, 9090, 10000, 32400,
];

/// Nom du service d'un port inconnu (comparé ailleurs : toujours passer par cette fonction).
pub fn inconnu() -> &'static str {
    crate::tr!("Inconnu", "Unknown")
}

pub fn info_port(port: u16) -> InfoPort {
    use Niveau::{Critique, Eleve, Info, Moyen};
    let (service, niveau, conseil) = match port {
        21 => (
            "FTP",
            Eleve,
            crate::tr!(
                "Identifiants et fichiers circulent en clair. Préférer SFTP.",
                "Logins and files travel in clear text. Prefer SFTP."
            ),
        ),
        22 => (
            "SSH",
            Info,
            crate::tr!(
                "OK si authentification par clé et mot de passe désactivé.",
                "OK if key authentication is used and password login is disabled."
            ),
        ),
        23 => (
            "Telnet",
            Critique,
            crate::tr!(
                "Protocole en clair, très ciblé par les botnets. À désactiver.",
                "Clear-text protocol, heavily targeted by botnets. Disable it."
            ),
        ),
        25 | 465 | 587 => (
            "SMTP",
            Moyen,
            crate::tr!(
                "Serveur mail : vérifier qu'il n'est pas un relais ouvert.",
                "Mail server: make sure it is not an open relay."
            ),
        ),
        53 => (
            "DNS",
            Info,
            crate::tr!(
                "Normal sur le routeur ; suspect sur une autre machine.",
                "Normal on the router; suspicious on another machine."
            ),
        ),
        80 | 81 => (
            "HTTP",
            Moyen,
            crate::tr!(
                "Interface web non chiffrée : mots de passe visibles sur le réseau.",
                "Unencrypted web interface: passwords visible on the network."
            ),
        ),
        88 => (
            "Kerberos",
            Info,
            crate::tr!("Service d'authentification.", "Authentication service."),
        ),
        110 | 143 => (
            "POP3/IMAP",
            Moyen,
            crate::tr!("Mail en clair ; préférer 993/995.", "Clear-text mail; prefer 993/995."),
        ),
        111 => (
            "rpcbind",
            Eleve,
            crate::tr!(
                "Expose les services RPC/NFS. À fermer si inutile.",
                "Exposes RPC/NFS services. Close it if unused."
            ),
        ),
        135 => (
            "MS-RPC",
            Eleve,
            crate::tr!(
                "Service Windows souvent exploité. Ne pas exposer.",
                "Frequently exploited Windows service. Do not expose it."
            ),
        ),
        139 => (
            "NetBIOS",
            Eleve,
            crate::tr!(
                "Partage Windows ancien (SMBv1 possible). Désactiver NetBIOS.",
                "Old Windows sharing (SMBv1 possible). Disable NetBIOS."
            ),
        ),
        389 => (
            "LDAP",
            Moyen,
            crate::tr!(
                "Annuaire en clair ; préférer LDAPS (636).",
                "Clear-text directory; prefer LDAPS (636)."
            ),
        ),
        443 | 8443 | 9443 => (
            "HTTPS",
            Info,
            crate::tr!(
                "Web chiffré. Vérifier que l'interface est à jour.",
                "Encrypted web. Make sure the interface is up to date."
            ),
        ),
        445 => (
            "SMB",
            Eleve,
            crate::tr!(
                "Partage de fichiers (WannaCry…). Désactiver SMBv1, mots de passe forts.",
                "File sharing (WannaCry…). Disable SMBv1, use strong passwords."
            ),
        ),
        512..=514 => (
            "rsh/rlogin",
            Critique,
            crate::tr!(
                "Accès distant sans chiffrement, obsolète. À désactiver.",
                "Unencrypted, obsolete remote access. Disable it."
            ),
        ),
        515 | 631 => (
            crate::tr!("Impression", "Printing"),
            Moyen,
            crate::tr!(
                "Imprimante/CUPS : vérifier le firmware et l'accès admin.",
                "Printer/CUPS: check the firmware and admin access."
            ),
        ),
        548 => (
            "AFP",
            Moyen,
            crate::tr!(
                "Partage Apple obsolète. Préférer SMB récent.",
                "Obsolete Apple sharing. Prefer a recent SMB."
            ),
        ),
        554 => (
            "RTSP",
            Moyen,
            crate::tr!(
                "Flux vidéo (caméra IP ?). Vérifier qu'il exige un mot de passe.",
                "Video stream (IP camera?). Make sure it requires a password."
            ),
        ),
        636 => ("LDAPS", Info, crate::tr!("Annuaire chiffré.", "Encrypted directory.")),
        873 => (
            "rsync",
            Eleve,
            crate::tr!(
                "Démon rsync : souvent sans authentification.",
                "rsync daemon: often without authentication."
            ),
        ),
        993 | 995 => ("IMAPS/POP3S", Info, crate::tr!("Mail chiffré.", "Encrypted mail.")),
        1080 | 3128 => (
            "Proxy",
            Eleve,
            crate::tr!(
                "Proxy ouvert : peut servir de rebond. Restreindre l'accès.",
                "Open proxy: can be used as a relay. Restrict access."
            ),
        ),
        1433 => (
            "MS-SQL",
            Eleve,
            crate::tr!(
                "Base de données exposée sur le réseau.",
                "Database exposed on the network."
            ),
        ),
        1521 => (
            "Oracle DB",
            Eleve,
            crate::tr!(
                "Base de données exposée sur le réseau.",
                "Database exposed on the network."
            ),
        ),
        1723 => (
            "PPTP",
            Eleve,
            crate::tr!(
                "VPN au chiffrement cassé. Passer à WireGuard/OpenVPN.",
                "VPN with broken encryption. Switch to WireGuard/OpenVPN."
            ),
        ),
        1883 => (
            "MQTT",
            Moyen,
            crate::tr!(
                "Domotique : vérifier qu'une authentification est exigée.",
                "Home automation: make sure authentication is required."
            ),
        ),
        2049 => (
            "NFS",
            Eleve,
            crate::tr!(
                "Partage NFS : vérifier /etc/exports (pas de * en rw).",
                "NFS share: check /etc/exports (no * with rw)."
            ),
        ),
        2375 => (
            "Docker API",
            Critique,
            crate::tr!(
                "API Docker sans TLS = accès root à la machine. Fermer immédiatement.",
                "Docker API without TLS = root access to the machine. Close it now."
            ),
        ),
        2376 => (
            "Docker API TLS",
            Moyen,
            crate::tr!(
                "API Docker chiffrée : vérifier les certificats clients.",
                "Encrypted Docker API: check the client certificates."
            ),
        ),
        3000 | 5000 | 5001 | 8000 | 8081 | 8088 | 8888 | 9000 | 9090 => (
            "Web/app",
            Moyen,
            crate::tr!(
                "Service web de dev ou d'admin : vérifier qu'il doit être joignable.",
                "Development or admin web service: make sure it should be reachable."
            ),
        ),
        3031 => (
            crate::tr!("Événements Apple à distance", "Remote Apple Events"),
            Eleve,
            crate::tr!(
                "Un autre ordinateur pilote les apps de ce Mac par AppleScript, avec un mot de passe du Mac. À couper si inutile.",
                "Another computer drives this Mac's apps through AppleScript, with a Mac password. Turn it off if unused."
            ),
        ),
        3283 => (
            crate::tr!("Gestion à distance Apple", "Apple Remote Management"),
            Moyen,
            crate::tr!(
                "Prise en main du Mac à distance (Apple Remote Desktop). À couper si personne ne gère ce Mac.",
                "Remote control of the Mac (Apple Remote Desktop). Turn it off if nobody manages this Mac."
            ),
        ),
        3306 => (
            "MySQL",
            Eleve,
            crate::tr!(
                "Base de données exposée sur le réseau.",
                "Database exposed on the network."
            ),
        ),
        3389 => (
            "RDP",
            Eleve,
            crate::tr!(
                "Bureau à distance Windows, très attaqué. NLA + mot de passe fort.",
                "Windows Remote Desktop, heavily attacked. Use NLA + a strong password."
            ),
        ),
        3689 => (
            "DAAP/iTunes",
            Info,
            crate::tr!("Partage multimédia Apple.", "Apple media sharing."),
        ),
        4444 => (
            crate::tr!("Inconnu (4444)", "Unknown (4444)"),
            Critique,
            crate::tr!(
                "Port typique de backdoor/Metasploit. À investiguer.",
                "Typical backdoor/Metasploit port. Investigate."
            ),
        ),
        5432 => (
            "PostgreSQL",
            Eleve,
            crate::tr!(
                "Base de données exposée sur le réseau.",
                "Database exposed on the network."
            ),
        ),
        5555 => (
            "ADB Android",
            Critique,
            crate::tr!(
                "Débogage Android ouvert = contrôle total de l'appareil.",
                "Open Android debugging = full control of the device."
            ),
        ),
        5900 | 5901 => (
            "VNC",
            Eleve,
            crate::tr!(
                "Bureau à distance souvent mal protégé. Mot de passe fort ou tunnel SSH.",
                "Remote desktop often poorly protected. Strong password or SSH tunnel."
            ),
        ),
        6379 => (
            "Redis",
            Critique,
            crate::tr!(
                "Redis souvent sans mot de passe = exécution de code possible.",
                "Redis often has no password = code execution possible."
            ),
        ),
        6443 => (
            "Kubernetes API",
            Moyen,
            crate::tr!(
                "API Kubernetes : vérifier l'authentification.",
                "Kubernetes API: check authentication."
            ),
        ),
        7000 | 7070 => (
            "AirPlay",
            Info,
            crate::tr!("Diffusion Apple/AirPlay.", "Apple/AirPlay streaming."),
        ),
        7547 => (
            "TR-069",
            Eleve,
            crate::tr!(
                "Gestion à distance du FAI, historiquement vulnérable.",
                "ISP remote management, historically vulnerable."
            ),
        ),
        8008 | 8009 => (
            "Chromecast",
            Info,
            crate::tr!("Appareil Google Cast.", "Google Cast device."),
        ),
        8080 => (
            "HTTP alt",
            Moyen,
            crate::tr!(
                "Interface web non chiffrée (proxy, admin, caméra…).",
                "Unencrypted web interface (proxy, admin, camera…)."
            ),
        ),
        8086 => (
            "InfluxDB",
            Moyen,
            crate::tr!(
                "Base de séries temporelles : vérifier l'authentification.",
                "Time-series database: check authentication."
            ),
        ),
        8123 => (
            "Home Assistant",
            Info,
            crate::tr!(
                "Domotique : garder à jour, activer la 2FA.",
                "Home automation: keep it updated, enable 2FA."
            ),
        ),
        8200 => (
            "Vault/DLNA",
            Moyen,
            crate::tr!("Vérifier l'authentification.", "Check authentication."),
        ),
        9100 => (
            crate::tr!("Impression RAW", "RAW printing"),
            Moyen,
            crate::tr!(
                "N'importe qui peut envoyer des impressions.",
                "Anyone can send print jobs."
            ),
        ),
        9200 => (
            "Elasticsearch",
            Critique,
            crate::tr!(
                "Souvent sans authentification : fuite de données.",
                "Often without authentication: data leak."
            ),
        ),
        10000 => (
            "Webmin",
            Eleve,
            crate::tr!(
                "Admin système web, cible fréquente. Garder à jour.",
                "Web system admin, frequent target. Keep it updated."
            ),
        ),
        11211 => (
            "Memcached",
            Critique,
            crate::tr!(
                "Sans authentification, utilisé pour l'amplification DDoS.",
                "No authentication, used for DDoS amplification."
            ),
        ),
        27017 => (
            "MongoDB",
            Critique,
            crate::tr!(
                "Souvent sans authentification : fuite de données.",
                "Often without authentication: data leak."
            ),
        ),
        32400 => (
            "Plex",
            Info,
            crate::tr!("Serveur multimédia Plex.", "Plex media server."),
        ),
        49152 => (
            "UPnP",
            Moyen,
            crate::tr!(
                "UPnP/IGD : peut ouvrir des ports sur le routeur. Désactiver si inutile.",
                "UPnP/IGD: can open ports on the router. Disable it if unused."
            ),
        ),
        62078 => (
            "iPhone sync",
            Info,
            crate::tr!(
                "Appareil iOS (synchronisation lockdownd).",
                "iOS device (lockdownd sync)."
            ),
        ),
        // Services surtout UDP, vus par l'audit de la machine.
        69 => (
            "TFTP",
            Eleve,
            crate::tr!(
                "Transfert de fichiers sans aucune authentification. À désactiver.",
                "File transfer with no authentication at all. Disable it."
            ),
        ),
        123 => (
            "NTP",
            Info,
            crate::tr!("Synchronisation de l'heure.", "Time synchronization."),
        ),
        137 | 138 => (
            "NetBIOS",
            Moyen,
            crate::tr!(
                "Ancien partage Windows/Samba : à couper si inutile.",
                "Old Windows/Samba sharing: turn it off if unused."
            ),
        ),
        161 => (
            "SNMP",
            Eleve,
            crate::tr!(
                "Supervision réseau : avec la communauté « public », n'importe qui lit la configuration.",
                "Network monitoring: with the “public” community, anyone can read the configuration."
            ),
        ),
        500 | 4500 => (
            "VPN IPsec",
            Info,
            crate::tr!(
                "VPN IPsec : normal si vous l'utilisez.",
                "IPsec VPN: normal if you use it."
            ),
        ),
        1900 => (
            "UPnP/SSDP",
            Moyen,
            crate::tr!(
                "Découverte UPnP : à couper si aucun appareil n'en a besoin.",
                "UPnP discovery: turn it off if no device needs it."
            ),
        ),
        3702 => (
            "WS-Discovery",
            Info,
            crate::tr!(
                "Découverte d'imprimantes et de partages.",
                "Printer and share discovery."
            ),
        ),
        5353 => (
            "mDNS",
            Info,
            crate::tr!(
                "Découverte locale (Avahi, Bonjour) : normal sur un réseau domestique.",
                "Local discovery (Avahi, Bonjour): normal on a home network."
            ),
        ),
        5355 => (
            "LLMNR",
            Moyen,
            crate::tr!(
                "Résolution de noms locale, usurpable par une machine du réseau : à désactiver si possible.",
                "Local name resolution, spoofable by any machine on the network: disable it if possible."
            ),
        ),
        51820 => (
            "WireGuard",
            Info,
            crate::tr!(
                "VPN WireGuard : normal si vous l'utilisez.",
                "WireGuard VPN: normal if you use it."
            ),
        ),
        5040 | 5050 => (
            "Windows CDP",
            Info,
            crate::tr!(
                "Plateforme d'appareils connectés de Windows (normal).",
                "Windows Connected Devices Platform (normal)."
            ),
        ),
        5357 => (
            "Windows WSD",
            Info,
            crate::tr!(
                "Découverte réseau de Windows (imprimantes, partages) : normal sur un réseau privé.",
                "Windows network discovery (printers, shares): normal on a private network."
            ),
        ),
        7680 => (
            "Windows Update P2P",
            Info,
            crate::tr!(
                "Optimisation de la distribution de Windows Update (normal).",
                "Windows Update delivery optimization (normal)."
            ),
        ),
        1716 => (
            "KDE Connect",
            Info,
            crate::tr!(
                "Liaison téléphone/PC : n'apparier que vos propres appareils.",
                "Phone/PC link: only pair your own devices."
            ),
        ),
        11434 => (
            "Ollama",
            Eleve,
            crate::tr!(
                "API d'IA locale sans authentification : ne l'exposer qu'en 127.0.0.1.",
                "Local AI API without authentication: only expose it on 127.0.0.1."
            ),
        ),
        27036 | 27037 => (
            "Steam Remote Play",
            Info,
            crate::tr!(
                "Diffusion locale Steam. Désactivable dans Steam > Remote Play.",
                "Steam local streaming. Can be turned off in Steam > Remote Play."
            ),
        ),
        27500 => (
            "Passim (fwupd)",
            Info,
            crate::tr!(
                "Partage des fichiers de firmware de fwupd avec les autres PC du réseau. Inutile chez soi : sudo systemctl disable --now passim.",
                "Shares fwupd firmware files with the other PCs on the network. Not needed at home: sudo systemctl disable --now passim."
            ),
        ),
        57621 => (
            "Spotify Connect",
            Info,
            crate::tr!(
                "Découverte Spotify sur le réseau local.",
                "Spotify discovery on the local network."
            ),
        ),
        _ => (
            inconnu(),
            Moyen,
            crate::tr!(
                "Service non identifié : vérifier ce qui écoute.",
                "Unidentified service: check what is listening."
            ),
        ),
    };
    InfoPort {
        service,
        niveau,
        conseil,
    }
}

/// Reconnaît un service d'après ce qu'il annonce, quel que soit son port.
/// Retourne le port « type » de ce service, dont on reprend le nom et le niveau de risque.
pub fn identifier(banniere: &str) -> Option<u16> {
    let l = banniere.to_ascii_lowercase();
    let d = |p: &str| l.starts_with(p);
    Some(match () {
        () if d("ssh-") => 22,
        () if d("http · ") => 8080,
        () if d("220") && l.contains("ftp") => 21,
        () if d("220") && (l.contains("smtp") || l.contains("mail")) => 25,
        () if d("+ok") => 110,
        () if d("* ok") => 143,
        () if d("-noauth") || d("+pong") || (d("-err") && l.contains("redis")) => 6379,
        () if d("rfb ") => 5900,
        () if l.contains("mysql_native_password") || l.contains("mariadb") => 3306,
        () => return None,
    })
}

/// Note globale à partir d'un score sur 100.
pub fn note(score: u32) -> &'static str {
    match score {
        90..=100 => "A",
        75..=89 => "B",
        60..=74 => "C",
        40..=59 => "D",
        _ => "F",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_reconnus_a_leur_banniere() {
        assert_eq!(identifier("SSH-2.0-OpenSSH_9.8"), Some(22));
        assert_eq!(identifier("220 (vsFTPd 2.3.4)"), Some(21));
        assert_eq!(identifier("220 mail.exemple.fr ESMTP Postfix"), Some(25));
        assert_eq!(identifier("HTTP · nginx/1.27"), Some(8080));
        assert_eq!(identifier("-NOAUTH Authentication required."), Some(6379));
        assert_eq!(identifier("RFB 003.008"), Some(5900));
        assert_eq!(identifier("bonjour"), None);
    }

    #[test]
    fn partages_du_mac_reconnus() {
        assert_eq!(info_port(3031).niveau, Niveau::Eleve);
        assert_eq!(info_port(3283).niveau, Niveau::Moyen);
        assert_ne!(info_port(3031).service, inconnu());
    }

    #[test]
    fn notes() {
        assert_eq!(note(100), "A");
        assert_eq!(note(75), "B");
        assert_eq!(note(60), "C");
        assert_eq!(note(40), "D");
        assert_eq!(note(0), "F");
    }
}
