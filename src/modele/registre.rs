//! Le registre des préfixes d'identifiants, et les identifiants des outils et des surveillances. Les règles du bilan
//! se déclarent avec `regle!` (machine/regles.rs), celles de l'audit du réseau dans `audit::fiches`, celles des
//! journaux d'événements de Windows dans `journaux_windows::regles::jeu` ; un même test les
//! parcourt avec ceux-ci (`machine::regles::tous_les_identifiants`) : un identifiant n'existe qu'une fois, toutes
//! familles confondues, et le JSON comme l'historique ne peuvent pas rattacher un constat à la mauvaise règle.

/// Les préfixes connus et ce qu'ils désignent (français, anglais).
pub(crate) const PREFIXES: &[(&str, (&str, &str))] = &[
    ("LNX", ("règles du bilan sous Linux", "check rules on Linux")),
    ("WIN", ("règles du bilan sous Windows", "check rules on Windows")),
    ("MAC", ("règles du bilan sous macOS", "check rules on macOS")),
    (
        "COM",
        (
            "règles communes du bilan et de l'audit du réseau",
            "common check rules and network audit rules",
        ),
    ),
    (
        "PRO",
        (
            "outils lancés seuls (protection, réseau, dépannage)",
            "tools run on their own (protection, network, troubleshooting)",
        ),
    ),
    (
        "EVT",
        ("règles des journaux d'événements de Windows", "Windows event log rules"),
    ),
    ("SUR", ("surveillance horaire", "hourly monitoring")),
    ("VEI", ("veilleur", "watcher")),
    (
        "AUT",
        (
            "autodiagnostic de Vanguard et ses lectures croisées",
            "Vanguard self-test and its cross-checks",
        ),
    ),
];

/// Un identifiant hors des règles : un outil de protection lancé seul, ou ce que la surveillance et le veilleur
/// notifient. Réservé ici pour que les étapes suivantes (journal, résultats des outils) n'en inventent pas un autre.
pub(crate) struct Outil {
    pub id: &'static str,
    /// Le module qui le porte.
    #[cfg_attr(not(test), allow(dead_code))] // lu par les tests ; le journal (E3) s'en servira
    pub module: &'static str,
    pub sujet: (&'static str, &'static str),
}

#[rustfmt::skip] // une ligne par outil, que rustfmt étalerait
pub(crate) const OUTILS: &[Outil] = &[
    Outil { id: "PRO-ANV-001", module: "protection::antivirus", sujet: ("recherche de malwares par le moteur du système", "malware scan by the system's engine") },
    Outil { id: "PRO-YAR-001", module: "protection::yara", sujet: ("analyse YARA d'un fichier ou d'un dossier", "YARA scan of a file or folder") },
    Outil { id: "PRO-MEM-001", module: "protection::memoire", sujet: ("analyse YARA de la mémoire des processus", "YARA scan of process memory") },
    Outil { id: "PRO-CAM-001", module: "protection::camera", sujet: ("qui se sert de la caméra et du micro", "who uses the camera and microphone") },
    Outil { id: "PRO-ACC-001", module: "protection::acces", sujet: ("accès des applications à la vie privée", "app access to private data") },
    Outil { id: "PRO-GIT-001", module: "protection::secrets_git", sujet: ("secrets dans l'historique des dépôts git", "secrets in git repository history") },
    Outil { id: "PRO-CTN-001", module: "protection::conteneurs", sujet: ("failles des images de conteneurs", "container image vulnerabilities") },
    Outil { id: "PRO-LIE-001", module: "protection::lien", sujet: ("lien reçu examiné sans l'ouvrir", "received link examined without opening it") },
    Outil { id: "PRO-COU-001", module: "protection::courriel_suspect", sujet: ("courriel suspect lu comme une donnée", "suspicious email read as data") },
    Outil { id: "PRO-ESP-001", module: "protection::espions", sujet: ("signes d'un logiciel espion", "signs of stalkerware") },
    Outil { id: "PRO-PER-001", module: "protection::perimes", sujet: ("logiciels pas à jour et failles exploitées", "outdated software and exploited flaws") },
    Outil { id: "PRO-TEL-001", module: "protection::telechargement", sujet: ("fichier téléchargé vérifié", "downloaded file checked") },
    Outil { id: "SUR-MAC-001", module: "reseau::surveillance", sujet: ("problème apparu sur cet ordinateur", "problem appeared on this computer") },
    Outil { id: "SUR-FIC-001", module: "protection::integrite", sujet: ("fichier critique changé", "critical file changed") },
    Outil { id: "SUR-TEL-001", module: "protection::telechargement", sujet: ("programme arrivé dans Téléchargements", "program arrived in Downloads") },
    Outil { id: "SUR-BOT-001", module: "protection::sortantes", sujet: ("connexion à un serveur de botnet", "connection to a botnet server") },
    Outil { id: "SUR-PAS-001", module: "reseau::surveillance", sujet: ("routeur qui change d'adresse MAC", "router changing MAC address") },
    Outil { id: "SUR-EMP-001", module: "reseau::empoisonnement", sujet: ("empoisonnement ARP sur le réseau", "ARP poisoning on the network") },
    Outil { id: "SUR-APP-001", module: "reseau::surveillance", sujet: ("appareil inconnu sur le réseau", "unknown device on the network") },
    Outil { id: "SUR-PRT-001", module: "reseau::surveillance", sujet: ("port nouvellement ouvert", "newly opened port") },
    Outil { id: "SUR-WIF-001", module: "reseau::surveillance", sujet: ("Wi-Fi moins protégé qu'avant", "Wi-Fi less protected than before") },
    Outil { id: "SUR-BLO-001", module: "protection::blocage", sujet: ("menace bloquée ou non bloquée", "threat blocked or not blocked") },
    Outil { id: "VEI-PRG-001", module: "machine::linux::veilleur", sujet: ("programme bref vu par le veilleur", "short-lived program seen by the watcher") },
    Outil { id: "VEI-CNX-001", module: "machine::linux::veilleur", sujet: ("connexion brève vue par le veilleur", "short connection seen by the watcher") },
    Outil { id: "AUT-VAN-001", module: "autotest", sujet: ("autodiagnostic de Vanguard", "Vanguard self-test") },
    Outil { id: "VEI-RAN-001", module: "protection::rancongiciel", sujet: ("rafale de chiffrement vue par le veilleur", "encryption burst seen by the watcher") },
    Outil { id: "VEI-RAN-002", module: "protection::rancongiciel", sujet: ("copies de secours effacées", "backup copies deleted") },
    Outil { id: "VEI-RAN-003", module: "protection::rancongiciel", sujet: ("fichier-piège touché en direct", "decoy file touched live") },
    Outil { id: "VEI-EXF-001", module: "protection::rancongiciel", sujet: ("exfiltration de fichiers personnels", "exfiltration of personal files") },
    Outil { id: "PRO-DIA-001", module: "diagnostic", sujet: ("diagnostic de l'ordinateur : matériel, système, problèmes récents", "computer diagnostics: hardware, system, recent problems") },
    Outil { id: "PRO-LEN-001", module: "lenteur", sujet: ("ce qui rend l'ordinateur lent", "what makes the computer slow") },
    Outil { id: "PRO-SOR-001", module: "protection::sortantes", sujet: ("programmes qui parlent à Internet", "programs talking to the Internet") },
    Outil { id: "PRO-DIS-001", module: "protection::distance", sujet: ("logiciels de prise de contrôle à distance", "remote control software") },
    Outil { id: "PRO-CNX-001", module: "reseau::connexion", sujet: ("test de connexion pour le jeu", "connection test for gaming") },
    Outil { id: "PRO-LNO-001", module: "reseau::listes_noires", sujet: ("adresse Internet publique sur une liste noire", "public Internet address on a blocklist") },
    Outil { id: "PRO-EVT-001", module: "journaux_windows::regles", sujet: ("traces d'attaque dans les journaux d'événements de Windows", "attack traces in Windows event logs") },
    Outil { id: "PRO-OBJ-001", module: "reseau::objets", sujet: ("routeur et objets connectés du dernier scan", "router and connected devices from the last scan") },
];
