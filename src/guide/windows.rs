//! Guide : les commandes de Windows 10 et 11, par programme. Toutes se tapent dans PowerShell (le terminal par
//! défaut) ; les programmes classiques (ipconfig, sfc, netsh…) marchent aussi dans l'invite de commandes.

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    Programme {
        nom: "winget",
        role: ("installer, mettre à jour", "install, update"),
        executable: "winget",
        commandes: &[
            voir(
                "winget upgrade",
                "Les programmes qui ont une mise à jour.",
                "Programs that have an update.",
            ),
            changer("winget upgrade --all", "Les met tous à jour.", "Updates them all."),
            voir(
                "winget search <nom>",
                "Cherche un programme ; son identifiant est dans la colonne Id.",
                "Searches for a program; its identifier is in the Id column.",
            ),
            changer(
                "winget install --id <id> --exact",
                "Installe un programme par son identifiant (ex. Mozilla.Firefox).",
                "Installs a program by its identifier (e.g. Mozilla.Firefox).",
            ),
            changer(
                "winget uninstall --id <id> --exact",
                "Désinstalle un programme.",
                "Uninstalls a program.",
            ),
            voir("winget list", "Les programmes installés.", "Installed programs."),
            voir(
                "winget export -o apps.json",
                "La liste des programmes installés, pour les réinstaller ailleurs.",
                "The list of installed programs, to reinstall them elsewhere.",
            )
            .sauf(Obstacle::Fichier),
            changer(
                "winget import -i apps.json",
                "Réinstalle les programmes de cette liste.",
                "Reinstalls the programs in that list.",
            ),
        ],
    },
    Programme {
        nom: "ms-settings",
        role: ("ouvrir une page des Paramètres", "open a Settings page"),
        executable: "",
        commandes: &[
            voir(
                "start ms-settings:windowsupdate",
                "Ouvre Windows Update.",
                "Opens Windows Update.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:network-status",
                "Ouvre l'état du réseau, avec la réinitialisation du réseau.",
                "Opens network status, with network reset.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:windowsdefender",
                "Ouvre Sécurité Windows.",
                "Opens Windows Security.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:storagesense",
                "Ouvre le stockage : ce qui prend la place.",
                "Opens storage: what takes up the space.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:appsfeatures",
                "Ouvre la liste des applications installées.",
                "Opens the list of installed apps.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:startupapps",
                "Ouvre les applications lancées au démarrage.",
                "Opens startup apps.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "start ms-settings:troubleshoot",
                "Ouvre les utilitaires de résolution des problèmes.",
                "Opens the troubleshooters.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "sfc, DISM",
        role: ("réparer Windows (administrateur)", "repair Windows (administrator)"),
        executable: "sfc",
        commandes: &[
            changer(
                "sfc /scannow",
                "Vérifie les fichiers de Windows et remplace ceux qui sont abîmés.",
                "Checks Windows files and replaces the damaged ones.",
            ),
            voir(
                "DISM /Online /Cleanup-Image /ScanHealth",
                "Vérifie l'image de Windows, sans rien réparer.",
                "Checks the Windows image, repairing nothing.",
            )
            .sauf(Obstacle::Longue),
            changer(
                "DISM /Online /Cleanup-Image /RestoreHealth",
                "Répare l'image de Windows : à lancer avant sfc quand sfc n'y arrive pas.",
                "Repairs the Windows image: run it before sfc when sfc cannot.",
            ),
            changer(
                "DISM /Online /Cleanup-Image /StartComponentCleanup",
                "Fait de la place : retire les anciennes versions des composants.",
                "Frees space: removes old versions of components.",
            ),
        ],
    },
    Programme {
        nom: "chkdsk",
        role: ("erreurs et réparation du disque", "disk errors and repair"),
        executable: "chkdsk",
        commandes: &[
            voir(
                "chkdsk C:",
                "Cherche les erreurs du disque C:, sans rien réparer.",
                "Looks for errors on disk C:, repairing nothing.",
            )
            .sauf(Obstacle::Longue),
            changer(
                "chkdsk C: /f",
                "Répare les erreurs ; pour C:, au prochain redémarrage.",
                "Repairs the errors; for C:, at the next restart.",
            ),
            changer(
                "chkdsk C: /r",
                "Répare aussi les secteurs défectueux (plusieurs heures).",
                "Also repairs bad sectors (several hours).",
            ),
        ],
    },
    Programme {
        nom: "ipconfig",
        role: ("adresses, routeur, DNS", "addresses, router, DNS"),
        executable: "ipconfig",
        commandes: &[
            voir(
                "ipconfig /all",
                "Adresse, routeur (passerelle), DNS et adresse MAC de chaque carte réseau.",
                "Address, router (gateway), DNS and MAC address of each network card.",
            ),
            changer("ipconfig /flushdns", "Vide le cache DNS.", "Clears the DNS cache."),
            changer(
                "ipconfig /release",
                "Rend l'adresse donnée par le routeur (le réseau se coupe).",
                "Gives back the address from the router (the network goes down).",
            ),
            changer(
                "ipconfig /renew",
                "Redemande une adresse au routeur.",
                "Asks the router for a new address.",
            ),
            voir(
                "ipconfig /displaydns",
                "Les noms trouvés récemment par le DNS.",
                "Names recently resolved by DNS.",
            ),
        ],
    },
    Programme {
        nom: "netsh",
        role: ("Wi-Fi, pare-feu, pile réseau", "Wi-Fi, firewall, network stack"),
        executable: "netsh",
        commandes: &[
            voir(
                "netsh winsock show catalog",
                "Le catalogue Winsock : chaque fournisseur réseau et sa DLL (mswsock d'origine).",
                "The Winsock catalog: each network provider and its DLL (mswsock by default).",
            ),
            voir(
                "netsh wlan show interfaces",
                "Le Wi-Fi connecté : signal, débit, canal, sécurité.",
                "The connected Wi-Fi: signal, speed, channel, security.",
            ),
            voir(
                "netsh wlan show profiles",
                "Les Wi-Fi enregistrés.",
                "Saved Wi-Fi networks.",
            ),
            voir(
                "netsh wlan show profile name=\"<nom>\" key=clear",
                "Le mot de passe d'un Wi-Fi enregistré (administrateur).",
                "A saved Wi-Fi network's password (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "netsh wlan show wlanreport",
                "Rapport des connexions Wi-Fi des derniers jours, en HTML (administrateur).",
                "Report of the last days' Wi-Fi connections, in HTML (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "netsh advfirewall show allprofiles",
                "L'état du pare-feu pour chaque profil.",
                "The firewall's state for each profile.",
            ),
            changer(
                "netsh winsock reset",
                "Remet à zéro le catalogue des connexions réseau ; redémarrer ensuite.",
                "Resets the network connection catalog; restart afterwards.",
            ),
            changer(
                "netsh int ip reset",
                "Remet à zéro les réglages TCP/IP ; redémarrer ensuite.",
                "Resets the TCP/IP settings; restart afterwards.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : réseau",
        role: ("cartes, connexions, DNS", "cards, connections, DNS"),
        executable: "",
        commandes: &[
            voir(
                "Get-NetIPConfiguration",
                "Le résumé de chaque carte réseau : adresse, routeur, DNS.",
                "Each network card's summary: address, router, DNS.",
            ),
            voir(
                "Get-NetAdapter",
                "Les cartes réseau, leur état et leur vitesse.",
                "Network cards, their state and speed.",
            ),
            voir(
                "Test-NetConnection <site> -Port 443",
                "Le site répond-il, et sur ce port ?",
                "Does the site answer, and on this port?",
            ),
            voir(
                "Resolve-DnsName <site>",
                "L'adresse d'un site d'après le DNS.",
                "A site's address according to DNS.",
            ),
            voir(
                "Get-NetTCPConnection -State Listen",
                "Les ports en écoute sur cet ordinateur.",
                "Listening ports on this computer.",
            ),
            changer(
                "Restart-NetAdapter -Name \"<nom>\"",
                "Coupe puis rallume une carte réseau (administrateur ; son nom : Get-NetAdapter).",
                "Turns a network card off and on (administrator; its name: Get-NetAdapter).",
            ),
        ],
    },
    Programme {
        nom: "tracert, pathping",
        role: ("le chemin jusqu'à un site", "the path to a site"),
        executable: "tracert",
        commandes: &[
            voir(
                "tracert <site>",
                "Le chemin jusqu'à un site, routeur par routeur.",
                "The path to a site, router by router.",
            ),
            voir(
                "pathping <site>",
                "Le même chemin, avec les pertes à chaque étape (quelques minutes).",
                "The same path, with the losses at each hop (a few minutes).",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : Defender",
        role: ("antivirus Microsoft Defender", "Microsoft Defender antivirus"),
        executable: "",
        commandes: &[
            voir(
                "Get-MpComputerStatus",
                "L'état de l'antivirus : protection en temps réel, date des signatures.",
                "Antivirus status: real-time protection, signature date.",
            ),
            changer(
                "Update-MpSignature",
                "Met à jour les signatures.",
                "Updates the signatures.",
            ),
            changer(
                "Start-MpScan -ScanType QuickScan",
                "Analyse rapide ; ce qui est trouvé part en quarantaine.",
                "Quick scan; what is found goes to quarantine.",
            ),
            changer(
                "Start-MpScan -ScanType FullScan",
                "Analyse complète (longue).",
                "Full scan (long).",
            ),
            changer(
                "Start-MpScan -ScanType CustomScan -ScanPath <dossier>",
                "Analyse un dossier ou une clé USB.",
                "Scans a folder or a USB drive.",
            ),
            voir(
                "Get-MpThreatDetection",
                "Les menaces trouvées récemment.",
                "Recently found threats.",
            ),
            changer(
                "Start-MpWDOScan",
                "Redémarre et analyse avant que Windows démarre : contre les virus qui se cachent.",
                "Restarts and scans before Windows starts: against malware that hides.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : services",
        role: ("services et programmes en marche", "services and running programs"),
        executable: "",
        commandes: &[
            voir(
                "Get-Service | Where-Object Status -eq Running",
                "Les services qui tournent.",
                "Running services.",
            ),
            voir("Get-Service <nom>", "L'état d'un service.", "A service's state."),
            changer(
                "Restart-Service <nom>",
                "Redémarre un service (administrateur).",
                "Restarts a service (administrator).",
            ),
            voir(
                "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
                "Les 10 programmes qui ont pris le plus de processeur.",
                "The 10 programs that used the most CPU.",
            ),
            voir(
                "Get-Process | Sort-Object WS -Descending | Select-Object -First 10",
                "Les 10 qui prennent le plus de mémoire.",
                "The 10 using the most memory.",
            ),
            changer(
                "Stop-Process -Name <nom>",
                "Ferme un programme (nom sans .exe) ; il perd ce qui n'est pas enregistré.",
                "Closes a program (name without .exe); it loses what is not saved.",
            ),
        ],
    },
    Programme {
        nom: "tasklist, taskkill",
        role: ("programmes en marche", "running programs"),
        executable: "tasklist",
        commandes: &[
            voir("tasklist", "Les programmes en marche.", "Running programs."),
            voir(
                "tasklist /svc",
                "Les services portés par chaque programme.",
                "The services hosted by each program.",
            ),
            changer(
                "taskkill /IM <programme>.exe /F",
                "Force un programme figé à se fermer.",
                "Forces a frozen program to close.",
            ),
            voir(
                "Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine",
                "Chaque programme avec sa ligne de commande : PowerShell caché (-enc), script téléchargé (DownloadString).",
                "Each program with its command line: hidden PowerShell (-enc), downloaded script (DownloadString).",
            ),
        ],
    },
    Programme {
        nom: "systeminfo, msinfo32, dxdiag",
        role: ("système et matériel", "system and hardware"),
        executable: "systeminfo",
        commandes: &[
            voir(
                "systeminfo",
                "Version de Windows, date d'installation, mémoire, correctifs.",
                "Windows version, install date, memory, hotfixes.",
            ),
            voir(
                "winver",
                "La version exacte de Windows, dans une fenêtre.",
                "The exact Windows version, in a window.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "msinfo32",
                "Informations système : matériel, pilotes, démarrage sécurisé.",
                "System Information: hardware, drivers, Secure Boot.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "dxdiag",
                "Carte graphique, DirectX, son : à joindre à une demande d'aide pour un jeu.",
                "Graphics card, DirectX, sound: attach it to a help request for a game.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "Get-CimInstance Win32_BIOS",
                "La version du BIOS et le numéro de série.",
                "The BIOS version and the serial number.",
            ),
        ],
    },
    Programme {
        nom: "powercfg",
        role: ("batterie, veille, énergie", "battery, sleep, power"),
        executable: "powercfg",
        commandes: &[
            voir(
                "powercfg /batteryreport",
                "Rapport de la batterie en HTML (usure, autonomie), écrit dans le dossier courant.",
                "Battery report in HTML (wear, runtime), written to the current folder.",
            )
            .sauf(Obstacle::Fichier),
            voir(
                "powercfg /requests",
                "Ce qui empêche la mise en veille (administrateur).",
                "What prevents sleep (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "powercfg /lastwake",
                "Ce qui a réveillé l'ordinateur la dernière fois.",
                "What woke the computer up last time.",
            ),
            voir(
                "powercfg /energy",
                "Diagnostic de l'énergie en HTML, après une minute d'observation (administrateur).",
                "Power diagnostics in HTML, after a minute of watching (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            changer(
                "powercfg /hibernate off",
                "Coupe la veille prolongée et rend la place de hiberfil.sys ; coupe aussi le démarrage rapide.",
                "Turns hibernation off and frees hiberfil.sys space; also turns off fast startup.",
            ),
        ],
    },
    Programme {
        nom: "PowerShell : disques",
        role: ("santé et place des disques", "disk health and space"),
        executable: "",
        commandes: &[
            voir(
                "Get-PhysicalDisk | Format-Table FriendlyName, MediaType, HealthStatus",
                "Chaque disque, son type (SSD, HDD) et sa santé.",
                "Each disk, its type (SSD, HDD) and health.",
            ),
            voir(
                "Get-PhysicalDisk | Get-StorageReliabilityCounter",
                "Usure, température et erreurs de chaque disque (administrateur).",
                "Each disk's wear, temperature and errors (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "Get-Volume",
                "La place libre de chaque lecteur.",
                "Free space on each drive.",
            ),
            voir(
                "Repair-Volume -DriveLetter C -Scan",
                "Cherche les erreurs du disque C: sans le bloquer (administrateur).",
                "Looks for errors on C: without locking it (administrator).",
            )
            .sauf(Obstacle::Longue),
            voir(
                "Optimize-Volume -DriveLetter C -Analyze -Verbose",
                "Le disque a-t-il besoin d'être optimisé (TRIM, défragmentation) ? (administrateur)",
                "Does the drive need optimizing (TRIM, defragmentation)? (administrator)",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "diskmgmt.msc",
                "La gestion des disques, dans une fenêtre.",
                "Disk Management, in a window.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "manage-bde",
        role: ("chiffrement BitLocker", "BitLocker encryption"),
        executable: "manage-bde",
        commandes: &[
            voir(
                "manage-bde -status",
                "Le chiffrement BitLocker de chaque lecteur (administrateur).",
                "BitLocker encryption of each drive (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "manage-bde -protectors -get C:",
                "La clé de récupération de C: (administrateur) : à garder ailleurs que sur ce PC.",
                "C:'s recovery key (administrator): keep it somewhere other than this PC.",
            )
            .sauf(Obstacle::Administrateur),
        ],
    },
    Programme {
        nom: "Get-WinEvent, perfmon",
        role: ("erreurs, plantages, fiabilité", "errors, crashes, reliability"),
        executable: "",
        commandes: &[
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 20",
                "Les 20 dernières erreurs du système.",
                "The last 20 system errors.",
            ),
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='System';Id=41} -MaxEvents 5",
                "Les arrêts brutaux : coupure de courant, écran bleu, gel.",
                "Unexpected shutdowns: power cut, blue screen, freeze.",
            ),
            voir(
                "perfmon /rel",
                "Le moniteur de fiabilité : plantages et erreurs, jour par jour.",
                "Reliability Monitor: crashes and errors, day by day.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "eventvwr",
                "L'Observateur d'événements, dans une fenêtre.",
                "Event Viewer, in a window.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 9",
                "Les derniers mots de passe ratés (administrateur) : une rafale depuis une même adresse, c'est quelqu'un qui essaie.",
                "The latest failed passwords (administrator): a burst from one address is someone trying.",
            )
            .sauf(Obstacle::Administrateur),
        ],
    },
    Programme {
        nom: "rstrui, Checkpoint-Computer",
        role: ("points de restauration", "restore points"),
        executable: "rstrui",
        commandes: &[
            changer(
                "rstrui",
                "Ramène le système à un point de restauration (fenêtre).",
                "Brings the system back to a restore point (window).",
            ),
            voir(
                "Get-ComputerRestorePoint",
                "Les points de restauration (administrateur).",
                "Restore points (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            changer(
                "Checkpoint-Computer -Description \"<texte>\"",
                "Crée un point de restauration (administrateur ; un toutes les 24 heures au plus).",
                "Creates a restore point (administrator; at most one every 24 hours).",
            ),
        ],
    },
    Programme {
        nom: "shutdown",
        role: ("redémarrer, éteindre, dépanner", "restart, shut down, troubleshoot"),
        executable: "shutdown",
        commandes: &[
            changer("shutdown /r /t 0", "Redémarre tout de suite.", "Restarts right away."),
            changer(
                "shutdown /r /o /t 0",
                "Redémarre vers le dépannage : mode sans échec, restauration, réparation du démarrage.",
                "Restarts into troubleshooting: safe mode, restore, startup repair.",
            ),
            changer(
                "shutdown /s /t 0",
                "Éteint complètement, sans le démarrage rapide.",
                "Shuts down completely, without fast startup.",
            ),
        ],
    },
    Programme {
        nom: "Get-LocalUser, net user",
        role: ("comptes et administrateurs", "accounts and administrators"),
        executable: "",
        commandes: &[
            voir(
                "Get-LocalUser",
                "Les comptes de l'ordinateur, actifs ou non.",
                "The computer's accounts, enabled or not.",
            ),
            voir(
                "Get-LocalGroupMember -SID S-1-5-32-544",
                "Les comptes administrateurs, dans toutes les langues de Windows.",
                "Administrator accounts, in every Windows language.",
            ),
            voir(
                "net user <nom>",
                "Un compte en détail : dernière connexion, mot de passe…",
                "An account in detail: last logon, password…",
            ),
            changer(
                "net user <nom> /active:no",
                "Désactive un compte sans l'effacer (administrateur).",
                "Disables an account without deleting it (administrator).",
            ),
        ],
    },
    Programme {
        nom: "Get-ScheduledTask, msconfig",
        role: ("ce qui se lance au démarrage", "what starts at boot"),
        executable: "",
        commandes: &[
            voir(
                "Get-CimInstance Win32_StartupCommand | Format-List Name, Command",
                "Les programmes lancés à l'ouverture de session.",
                "Programs started at sign-in.",
            ),
            voir(
                "Get-ScheduledTask | Where-Object State -ne Disabled",
                "Les tâches planifiées actives.",
                "Active scheduled tasks.",
            ),
            voir(
                "taskmgr",
                "Le Gestionnaire des tâches (Ctrl+Maj+Échap), avec la page du démarrage.",
                "Task Manager (Ctrl+Shift+Esc), with its startup page.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "msconfig",
                "Configuration du système : démarrage sélectif, mode sans échec (fenêtre).",
                "System Configuration: selective startup, safe mode (window).",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "Get-ChildItem, robocopy",
        role: ("chercher et copier des fichiers", "find and copy files"),
        executable: "",
        commandes: &[
            voir(
                "Get-ChildItem -Recurse -Filter \"*<mot>*\"",
                "Cherche un fichier par son nom, ici et dans les sous-dossiers.",
                "Finds a file by name, here and in the subfolders.",
            ),
            voir(
                "Select-String -Path *.txt -Pattern \"<texte>\"",
                "Cherche un texte dans des fichiers.",
                "Searches for text in files.",
            ),
            changer(
                "robocopy <source> <destination> /E /Z",
                "Copie un dossier entier ; reprend où elle s'était arrêtée.",
                "Copies a whole folder; resumes where it stopped.",
            ),
            voir(
                "explorer .",
                "Ouvre le dossier courant dans l'Explorateur.",
                "Opens the current folder in File Explorer.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "wsl",
        role: ("Linux dans Windows (WSL)", "Linux inside Windows (WSL)"),
        executable: "wsl",
        commandes: &[
            voir(
                "wsl --status",
                "WSL est-il installé, et en quelle version ?",
                "Is WSL installed, and which version?",
            ),
            voir(
                "wsl --list --verbose",
                "Les distributions Linux installées, et leur état.",
                "Installed Linux distributions, and their state.",
            ),
            voir(
                "wsl --list --online",
                "Les distributions qu'on peut installer.",
                "Distributions available to install.",
            ),
            changer(
                "wsl --install",
                "Installe WSL et Ubuntu (puis redémarrage).",
                "Installs WSL and Ubuntu (then restart).",
            ),
            changer(
                "wsl --install -d <nom>",
                "Installe une autre distribution (Debian, openSUSE…).",
                "Installs another distribution (Debian, openSUSE…).",
            ),
            changer("wsl --update", "Met à jour WSL.", "Updates WSL."),
            changer(
                "wsl --shutdown",
                "Arrête toutes les distributions : libère leur mémoire.",
                "Stops all distributions: frees their memory.",
            ),
        ],
    },
    Programme {
        nom: "Get-DnsClient, arp, netstat",
        role: ("DNS, voisins, connexions", "DNS, neighbors, connections"),
        executable: "",
        commandes: &[
            voir(
                "netstat -ano | findstr :11434",
                "Ollama écoute-t-il au-delà de 127.0.0.1 ? 0.0.0.0 : ouvert à tout le réseau.",
                "Does Ollama listen beyond 127.0.0.1? 0.0.0.0: open to the whole network.",
            ),
            voir(
                "Get-DnsClientServerAddress -AddressFamily IPv4",
                "Les serveurs DNS de chaque carte.",
                "Each card's DNS servers.",
            ),
            changer(
                "Clear-DnsClientCache",
                "Vide le cache DNS (comme ipconfig /flushdns).",
                "Empties the DNS cache (like ipconfig /flushdns).",
            ),
            voir(
                "Get-NetRoute -DestinationPrefix 0.0.0.0/0",
                "La passerelle par défaut : l'adresse du routeur.",
                "The default gateway: the router's address.",
            ),
            voir(
                "arp -a",
                "Les appareils vus récemment sur le réseau local.",
                "Devices seen recently on the local network.",
            ),
            voir(
                "netstat -ano | findstr LISTENING",
                "Les ports en écoute, et le numéro du programme (PID).",
                "Listening ports, and the program's number (PID).",
            ),
            voir(
                "Get-NetTCPConnection -State Established",
                "Les connexions ouvertes en ce moment.",
                "Connections open right now.",
            ),
            voir(
                "getmac /v",
                "L'adresse MAC de chaque carte.",
                "Each card's MAC address.",
            ),
        ],
    },
    Programme {
        nom: "Get-PnpDevice, pnputil",
        role: ("pilotes et périphériques", "drivers and devices"),
        executable: "pnputil",
        commandes: &[
            voir(
                "Get-PnpDevice -Status ERROR",
                "Les périphériques en erreur : pilote manquant ou en panne.",
                "Devices in error: missing or broken driver.",
            ),
            voir(
                "Get-PnpDevice -Class Display",
                "La carte graphique et son état.",
                "The graphics card and its state.",
            ),
            voir("driverquery", "Les pilotes installés.", "Installed drivers."),
            voir(
                "driverquery /si",
                "Les pilotes et leur signature (IsSigned) : un pilote non signé est à regarder.",
                "Drivers and their signature (IsSigned): an unsigned driver deserves a look.",
            ),
            voir(
                "pnputil /enum-drivers",
                "Les paquets de pilotes ajoutés (oemNN.inf).",
                "Added driver packages (oemNN.inf).",
            )
            .sauf(Obstacle::Administrateur),
            changer(
                "pnputil /delete-driver <nom> /uninstall",
                "Retire un paquet de pilote (oemNN.inf).",
                "Removes a driver package (oemNN.inf).",
            ),
            voir("devmgmt.msc", "Le Gestionnaire de périphériques.", "Device Manager.").sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "sc.exe, schtasks",
        role: ("services et tâches planifiées", "services and scheduled tasks"),
        executable: "schtasks",
        commandes: &[
            voir(
                "sc.exe query <service>",
                "L'état d'un service (sc.exe : dans PowerShell, sc seul est autre chose).",
                "A service's state (sc.exe: in PowerShell, sc alone is something else).",
            ),
            voir(
                "sc.exe qc <service>",
                "Comment il démarre, et son programme.",
                "How it starts, and its program.",
            ),
            changer(
                "sc.exe config <service> start= disabled",
                "Empêche un service de démarrer.",
                "Prevents a service from starting.",
            ),
            voir(
                "schtasks /query /fo TABLE",
                "Les tâches planifiées.",
                "Scheduled tasks.",
            ),
            changer(
                "schtasks /change /tn \"<nom>\" /disable",
                "Désactive une tâche planifiée.",
                "Disables a scheduled task.",
            ),
        ],
    },
    Programme {
        nom: "gpresult, bcdedit, reagentc",
        role: ("stratégies et démarrage", "policies and boot"),
        executable: "gpresult",
        commandes: &[
            voir(
                "gpresult /r",
                "Les stratégies appliquées à l'ordinateur et à votre compte.",
                "Policies applied to the computer and your account.",
            ),
            changer(
                "gpupdate /force",
                "Réapplique les stratégies.",
                "Reapplies the policies.",
            ),
            voir("bcdedit /enum", "Les entrées de démarrage.", "Boot entries.").sauf(Obstacle::Administrateur),
            voir(
                "reagentc /info",
                "L'environnement de récupération est-il prêt ?",
                "Is the recovery environment ready?",
            )
            .sauf(Obstacle::Administrateur),
            changer("reagentc /enable", "Le réactive.", "Turns it back on."),
        ],
    },
    Programme {
        nom: "Get-FileHash, icacls",
        role: ("empreintes, droits des fichiers", "hashes, file permissions"),
        executable: "",
        commandes: &[
            voir(
                "Get-FileHash <fichier>",
                "L'empreinte SHA-256 d'un fichier, à comparer avec celle que donne l'éditeur.",
                "A file's SHA-256 hash, to compare with the one the publisher gives.",
            ),
            voir(
                "icacls <fichier>",
                "Qui peut lire ou modifier un fichier.",
                "Who can read or change a file.",
            ),
            changer(
                "takeown /f <fichier>",
                "Se rend propriétaire d'un fichier (terminal administrateur).",
                "Takes ownership of a file (administrator terminal).",
            ),
            voir(
                "Get-Item <fichier> -Stream *",
                "Les flux d'un fichier, dont la marque « téléchargé d'Internet » (Zone.Identifier).",
                "A file's streams, including the “downloaded from the Internet” mark (Zone.Identifier).",
            ),
            changer(
                "Unblock-File <fichier>",
                "Retire cette marque : seulement pour un fichier sûr.",
                "Removes that mark: only for a safe file.",
            ),
        ],
    },
    Programme {
        nom: "Get-AppxPackage, wsreset",
        role: ("applications du Microsoft Store", "Microsoft Store apps"),
        executable: "",
        commandes: &[
            voir(
                "Get-AppxPackage | Select Name, Version",
                "Les applications du Store installées pour votre compte.",
                "Store apps installed for your account.",
            ),
            voir(
                "Get-AppxPackage *<nom>*",
                "Une application du Store, par son nom.",
                "A Store app, by its name.",
            ),
            changer(
                "Get-AppxPackage *<nom>* | Remove-AppxPackage",
                "La désinstalle.",
                "Uninstalls it.",
            ),
            changer(
                "wsreset",
                "Remet à zéro le Microsoft Store qui ne s'ouvre plus.",
                "Resets a Microsoft Store that no longer opens.",
            ),
        ],
    },
    Programme {
        nom: "reg",
        role: ("le registre", "the registry"),
        executable: "reg",
        commandes: &[
            voir(
                "reg query <clé>",
                "Les valeurs d'une clé du registre (HKCU\\Software\\…).",
                "A registry key's values (HKCU\\Software\\…).",
            ),
            voir(
                r"reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "Paquets de LSA : Notification Packages (filtres de mot de passe) = scecli d'origine.",
                "LSA packages: Notification Packages (password filters) = scecli by default.",
            ),
            voir(
                r"reg query HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors /s",
                "Les moniteurs d'impression et leur DLL (Driver) : un chemin complet est à regarder.",
                "Print monitors and their DLL (Driver): a full path deserves a look.",
            ),
            changer(
                "reg export <clé> <fichier>.reg",
                "Sauvegarde une clé avant de la modifier.",
                "Backs up a key before changing it.",
            ),
            changer(
                "reg import <fichier>.reg",
                "La remet comme avant.",
                "Puts it back as before.",
            ),
        ],
    },
    Programme {
        nom: "Get-NetConnectionProfile",
        role: ("réseau public ou privé", "public or private network"),
        executable: "",
        commandes: &[
            voir(
                "Get-NetConnectionProfile",
                "Chaque réseau : public (fermé aux autres appareils) ou privé.",
                "Each network: public (closed to other devices) or private.",
            ),
            changer(
                "Set-NetConnectionProfile -Name <nom> -NetworkCategory Public",
                "Passe un réseau en public, plus sûr hors de chez soi (terminal administrateur).",
                "Makes a network public, safer away from home (administrator terminal).",
            ),
        ],
    },
    Programme {
        nom: "Get-SmbShare",
        role: ("dossiers partagés", "shared folders"),
        executable: "",
        commandes: &[
            voir(
                "Get-SmbShare",
                "Les dossiers partagés ; ceux finissant par $ sont ceux de Windows (administrateur).",
                "Shared folders; those ending with $ are Windows' own (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "Get-SmbShareAccess -Name <nom>",
                "Qui peut ouvrir un partage, et avec quels droits (administrateur).",
                "Who can open a share, and with which rights (administrator).",
            )
            .sauf(Obstacle::Administrateur),
        ],
    },
    Programme {
        nom: "Get-Tpm, tpm.msc",
        role: ("puce de sécurité TPM", "TPM security chip"),
        executable: "",
        commandes: &[
            voir(
                "Get-Tpm",
                "La puce TPM : présente, prête, activée (administrateur).",
                "The TPM chip: present, ready, enabled (administrator).",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "tpm.msc",
                "La console de la puce TPM, avec sa version.",
                "The TPM chip console, with its version.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "Get-AuthenticodeSignature",
        role: ("signature d'un programme", "a program's signature"),
        executable: "",
        commandes: &[voir(
            "Get-AuthenticodeSignature <fichier> | Format-List",
            "Qui a signé un programme, et si la signature est valide (Status : Valid).",
            "Who signed a program, and whether the signature is valid (Status: Valid).",
        )],
    },
    Programme {
        nom: "cipher, mdsched",
        role: ("espace libre, mémoire vive", "free space, memory"),
        executable: "cipher",
        commandes: &[
            changer(
                "cipher /w:C:\\",
                "Écrase l'espace libre du disque C : ce qui a été effacé ne se récupère plus (long).",
                "Overwrites drive C's free space: what was deleted can no longer be recovered (long).",
            ),
            changer(
                "mdsched",
                "Teste la mémoire vive au prochain redémarrage (Diagnostic de la mémoire Windows).",
                "Tests the memory at the next restart (Windows Memory Diagnostic).",
            ),
        ],
    },
];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("Windows Update, winget, Defender", "Windows Update, winget, Defender"),
        executable: "",
        commandes: &[
            voir(
                "start ms-settings:windowsupdate",
                "Windows Update : rechercher, installer, redémarrer quand il le demande.",
                "Windows Update: check, install, restart when it asks.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "winget upgrade",
                "Les logiciels qui ont une mise à jour.",
                "Software that has an update.",
            ),
            changer("winget upgrade --all", "Les met tous à jour.", "Updates them all."),
            changer(
                "Update-MpSignature",
                "Les définitions de Microsoft Defender (terminal administrateur).",
                "Microsoft Defender's definitions (administrator terminal).",
            ),
            voir(
                "Get-HotFix | Sort-Object InstalledOn -Desc | Select -First 5",
                "Les dernières mises à jour de Windows installées, avec leur date.",
                "The latest Windows updates installed, with their date.",
            ),
            changer(
                "shutdown /r /t 0",
                "Redémarre pour finir les installations.",
                "Restarts to finish the installations.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : réparer Windows",
        role: ("DISM, sfc, disque, démarrage", "DISM, sfc, disk, boot"),
        executable: "",
        commandes: &[
            changer(
                "DISM /Online /Cleanup-Image /RestoreHealth",
                "D'abord, répare l'image de Windows depuis Windows Update (terminal administrateur, 10 à 30 min).",
                "First, repairs the Windows image from Windows Update (administrator terminal, 10 to 30 min).",
            ),
            changer(
                "sfc /scannow",
                "Puis vérifie et répare les fichiers de Windows.",
                "Then checks and repairs Windows files.",
            ),
            voir(
                "Select-String $env:windir\\Logs\\CBS\\CBS.log '\\[SR\\]' | Select -Last 20",
                "Ce que sfc a trouvé et réparé, d'après son journal.",
                "What sfc found and repaired, according to its log.",
            )
            .sauf(Obstacle::Administrateur),
            changer(
                "chkdsk C: /f",
                "Le disque : acceptez la vérification au prochain redémarrage (O).",
                "The disk: accept the check at the next restart (Y).",
            ),
            changer(
                "shutdown /r /o /t 0",
                "Ne démarre plus bien ? Redémarre vers les options de dépannage (réparation du démarrage, restauration).",
                "Won't boot properly? Restarts into the troubleshooting options (startup repair, restore).",
            ),
            changer(
                "rstrui",
                "Ou revient à un point de restauration d'avant la panne.",
                "Or goes back to a restore point from before the problem.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : réseau",
        role: ("Wi-Fi, DNS, pile réseau", "Wi-Fi, DNS, network stack"),
        executable: "",
        commandes: &[
            voir(
                "ipconfig /all",
                "L'état des cartes : adresse (169.254… : le routeur ne répond pas), passerelle, DNS.",
                "The cards' state: address (169.254…: the router does not answer), gateway, DNS.",
            ),
            voir(
                "Test-NetConnection 1.1.1.1",
                "Internet répond-il, sans passer par le DNS ?",
                "Does the Internet answer, without going through DNS?",
            ),
            voir("Resolve-DnsName example.com", "Le DNS répond-il ?", "Does DNS answer?"),
            changer("ipconfig /flushdns", "Vide le cache DNS.", "Empties the DNS cache."),
            changer(
                "ipconfig /release; ipconfig /renew",
                "Redemande une adresse au routeur.",
                "Asks the router for a new address.",
            ),
            changer(
                "netsh winsock reset",
                "Toujours rien : remet à zéro la pile réseau (terminal administrateur)…",
                "Still nothing: resets the network stack (administrator terminal)…",
            ),
            changer("netsh int ip reset", "…et TCP/IP…", "…and TCP/IP…"),
            changer("shutdown /r /t 0", "…puis redémarre.", "…then restart."),
        ],
    },
    Programme {
        nom: "Pas à pas : faire de la place",
        role: ("disque C: plein", "C: drive full"),
        executable: "",
        commandes: &[
            voir(
                "Get-PSDrive C",
                "La place utilisée et libre sur C:.",
                "Used and free space on C:.",
            ),
            voir(
                "(gci ~\\Downloads -Recurse | measure Length -Sum).Sum / 1GB",
                "La taille des Téléchargements, en Go.",
                "The size of Downloads, in GB.",
            ),
            voir(
                "start ms-settings:storagesense",
                "Le stockage : fichiers temporaires, Assistant stockage.",
                "Storage: temporary files, Storage Sense.",
            )
            .sauf(Obstacle::Fenetre),
            changer(
                "Remove-Item $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue",
                "Vide votre dossier temporaire (ce qui sert encore reste).",
                "Empties your temporary folder (what is still in use stays).",
            ),
            changer(
                "DISM /Online /Cleanup-Image /StartComponentCleanup",
                "Retire les anciennes versions des composants de Windows (terminal administrateur).",
                "Removes old versions of Windows components (administrator terminal).",
            ),
            changer(
                "powercfg /hibernate off",
                "Supprime le fichier de veille prolongée (plusieurs Go) ; la veille prolongée disparaît.",
                "Deletes the hibernation file (several GB); hibernation goes away.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : sécurité",
        role: ("Defender, pare-feu, comptes", "Defender, firewall, accounts"),
        executable: "",
        commandes: &[
            voir(
                "Get-MpComputerStatus | Select *Enabled",
                "Defender : chaque protection est-elle active (True) ?",
                "Defender: is each protection on (True)?",
            ),
            changer(
                "Update-MpSignature",
                "Met ses définitions à jour.",
                "Updates its definitions.",
            ),
            changer(
                "Start-MpScan -ScanType QuickScan",
                "Une analyse rapide.",
                "A quick scan.",
            ),
            voir("Get-MpThreatDetection", "Ce qu'il a trouvé.", "What it found."),
            voir(
                "Get-NetFirewallProfile | Select Name, Enabled",
                "Le pare-feu est-il actif pour chaque profil ?",
                "Is the firewall on for each profile?",
            ),
            voir(
                "Get-LocalGroupMember -SID S-1-5-32-544",
                "Qui est administrateur : un compte inconnu là est une alerte.",
                "Who is an administrator: an unknown account there is a warning.",
            ),
            voir(
                "Confirm-SecureBootUEFI",
                "Secure Boot est-il actif ?",
                "Is Secure Boot on?",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "Get-BitLockerVolume",
                "Le chiffrement BitLocker de chaque disque.",
                "Each disk's BitLocker encryption.",
            )
            .sauf(Obstacle::Administrateur),
        ],
    },
    Programme {
        nom: "Pas à pas : lenteur",
        role: ("processeur, mémoire, démarrage", "processor, memory, startup"),
        executable: "",
        commandes: &[
            voir(
                "Get-Process | Sort-Object CPU -Descending | Select-Object -First 10",
                "Ce qui use le plus le processeur.",
                "What uses the processor the most.",
            ),
            voir(
                "Get-Process | Sort-Object WS -Descending | Select-Object -First 10",
                "Ce qui prend le plus de mémoire.",
                "What takes the most memory.",
            ),
            voir(
                "start ms-settings:startupapps",
                "Les applications au démarrage : coupez celles dont vous n'avez pas besoin.",
                "Startup apps: turn off those you do not need.",
            )
            .sauf(Obstacle::Fenetre),
            voir(
                "Get-PhysicalDisk | Format-Table FriendlyName, MediaType, HealthStatus",
                "Le disque est-il sain, et est-ce un SSD ?",
                "Is the disk healthy, and is it an SSD?",
            ),
            voir(
                "Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 20",
                "Les dernières erreurs du système.",
                "The latest system errors.",
            ),
            voir(
                "powercfg /requests",
                "Ce qui empêche la mise en veille.",
                "What prevents sleep.",
            )
            .sauf(Obstacle::Administrateur),
        ],
    },
];
