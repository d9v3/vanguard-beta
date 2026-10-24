//! Guide : les commandes de macOS, par programme. « en0 » est en général le Wi-Fi d'un portable (la liste :
//! networksetup -listallhardwareports).

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    Programme {
        nom: "softwareupdate",
        role: ("mises à jour de macOS", "macOS updates"),
        executable: "softwareupdate",
        commandes: &[
            voir(
                "softwareupdate --list",
                "Les mises à jour de macOS disponibles, avec leur étiquette.",
                "Available macOS updates, with their label.",
            ),
            changer(
                "sudo softwareupdate --install \"<étiquette>\"",
                "Installe une mise à jour précise ; --all prendrait aussi une nouvelle version de macOS.",
                "Installs one update; --all would also take a new macOS version.",
            ),
            voir(
                "softwareupdate --history",
                "Les mises à jour déjà installées.",
                "Updates already installed.",
            ),
        ],
    },
    Programme {
        nom: "brew",
        role: ("logiciels (Homebrew)", "software (Homebrew)"),
        executable: "brew",
        commandes: &[
            changer(
                "brew update && brew upgrade",
                "Met à jour Homebrew, puis tout ce qu'il a installé.",
                "Updates Homebrew, then everything it installed.",
            ),
            changer(
                "brew install <paquet>",
                "Installe un outil en ligne de commande.",
                "Installs a command-line tool.",
            ),
            changer(
                "brew install --cask <app>",
                "Installe une application (ex. firefox).",
                "Installs an app (e.g. firefox).",
            ),
            changer("brew uninstall <paquet>", "Désinstalle.", "Uninstalls."),
            voir("brew search <mot>", "Cherche un paquet.", "Searches for a package."),
            voir("brew outdated", "Ce qui a une mise à jour.", "What has an update."),
            voir(
                "brew doctor",
                "Les problèmes de Homebrew, et comment les régler.",
                "Homebrew's problems, and how to fix them.",
            ),
            changer(
                "brew cleanup",
                "Efface les anciennes versions et les téléchargements.",
                "Deletes old versions and downloads.",
            ),
        ],
    },
    Programme {
        nom: "diskutil",
        role: ("disques et volumes", "disks and volumes"),
        executable: "diskutil",
        commandes: &[
            voir(
                "diskutil list",
                "Les disques et leurs volumes.",
                "Disks and their volumes.",
            ),
            voir(
                "diskutil info disk0 | grep -i smart",
                "La santé SMART du disque interne (Verified : bon).",
                "The internal disk's SMART status (Verified: good).",
            ),
            voir(
                "diskutil verifyVolume /",
                "Vérifie le volume du système sans le démonter.",
                "Checks the system volume without unmounting it.",
            )
            .sauf(Obstacle::Longue),
            changer(
                "diskutil repairVolume <disque>",
                "Répare un volume ; celui du Mac, depuis le mode de récupération.",
                "Repairs a volume; the Mac's own, from Recovery.",
            ),
            voir(
                "diskutil apfs list",
                "Les conteneurs APFS et la place de chaque volume.",
                "APFS containers and each volume's space.",
            ),
            changer(
                "diskutil eject <disque>",
                "Éjecte proprement une clé ou un disque externe.",
                "Safely ejects a USB drive or an external disk.",
            ),
        ],
    },
    Programme {
        nom: "tmutil",
        role: ("Time Machine (sauvegardes)", "Time Machine (backups)"),
        executable: "tmutil",
        commandes: &[
            voir(
                "tmutil status",
                "Une sauvegarde est-elle en cours ?",
                "Is a backup running?",
            ),
            voir(
                "tmutil latestbackup",
                "La dernière sauvegarde Time Machine.",
                "The latest Time Machine backup.",
            ),
            changer(
                "tmutil startbackup",
                "Lance une sauvegarde maintenant.",
                "Starts a backup now.",
            ),
            voir(
                "tmutil listlocalsnapshots /",
                "Les instantanés locaux du disque du Mac.",
                "Local snapshots of the Mac's disk.",
            ),
            changer(
                "tmutil localsnapshot",
                "Crée un instantané local, gardé 24 heures.",
                "Creates a local snapshot, kept 24 hours.",
            ),
        ],
    },
    Programme {
        nom: "networksetup",
        role: ("réglages du réseau", "network settings"),
        executable: "networksetup",
        commandes: &[
            voir(
                "networksetup -listallhardwareports",
                "Les cartes réseau et leur nom (en0, en1…).",
                "Network cards and their names (en0, en1…).",
            ),
            voir(
                "networksetup -getinfo Wi-Fi",
                "L'adresse, le masque et le routeur du Wi-Fi.",
                "Wi-Fi address, mask and router.",
            ),
            voir(
                "networksetup -getdnsservers Wi-Fi",
                "Les DNS réglés pour le Wi-Fi.",
                "The DNS set for Wi-Fi.",
            ),
            changer(
                "sudo networksetup -setdnsservers Wi-Fi empty",
                "Remet les DNS donnés par le routeur.",
                "Goes back to the DNS given by the router.",
            ),
        ],
    },
    Programme {
        nom: "ipconfig, scutil, dscacheutil",
        role: ("adresse, DNS, proxy", "address, DNS, proxy"),
        executable: "scutil",
        commandes: &[
            voir(
                "ipconfig getifaddr en0",
                "L'adresse IP de la carte en0.",
                "The IP address of card en0.",
            ),
            voir("scutil --dns", "Les DNS vraiment utilisés.", "The DNS actually used."),
            voir("scutil --proxy", "Les proxys réglés.", "The configured proxies."),
            changer(
                "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
                "Vide le cache DNS.",
                "Clears the DNS cache.",
            ),
            changer(
                "sudo ipconfig set en0 DHCP",
                "Redemande une adresse au routeur.",
                "Asks the router for a new address.",
            ),
        ],
    },
    Programme {
        nom: "wdutil, networkQuality",
        role: ("Wi-Fi et débit", "Wi-Fi and speed"),
        executable: "networkQuality",
        commandes: &[
            voir(
                "sudo wdutil info",
                "Diagnostic du Wi-Fi : signal, bruit, canal, débit.",
                "Wi-Fi diagnostics: signal, noise, channel, rate.",
            ),
            voir(
                "networkQuality",
                "Test de débit et de réactivité de la connexion (macOS 12 et plus).",
                "Connection speed and responsiveness test (macOS 12 and later).",
            ),
        ],
    },
    Programme {
        nom: "lsof",
        role: ("ports et fichiers ouverts", "open ports and files"),
        executable: "lsof",
        commandes: &[
            voir(
                "lsof -nP -iTCP:11434 -sTCP:LISTEN",
                "Ollama écoute-t-il au-delà de 127.0.0.1 ? * : ouvert à tout le réseau.",
                "Does Ollama listen beyond 127.0.0.1? *: open to the whole network.",
            ),
            voir(
                "sudo lsof -nP -iTCP -sTCP:LISTEN",
                "Les ports en écoute et leur programme.",
                "Listening ports and their program.",
            ),
            voir(
                "lsof -nP -i",
                "Les connexions réseau de vos programmes.",
                "Your programs' network connections.",
            ),
            voir(
                "lsof <fichier>",
                "Qui utilise ce fichier ou ce volume (une clé qui refuse de s'éjecter).",
                "Who is using this file or volume (a drive that will not eject).",
            ),
        ],
    },
    Programme {
        nom: "system_profiler, sw_vers",
        role: ("système et matériel", "system and hardware"),
        executable: "system_profiler",
        commandes: &[
            voir("sw_vers", "La version de macOS.", "The macOS version."),
            voir(
                "system_profiler SPHardwareDataType",
                "Modèle, processeur, mémoire, et le numéro de série (à ne pas publier).",
                "Model, processor, memory, and the serial number (not to publish).",
            ),
            voir(
                "system_profiler SPPowerDataType",
                "La batterie : nombre de cycles, état (Normal, Réparation recommandée).",
                "The battery: cycle count, condition (Normal, Service Recommended).",
            ),
            voir(
                "system_profiler SPStorageDataType",
                "Les volumes et leur place.",
                "Volumes and their space.",
            ),
            voir(
                "system_profiler SPAirPortDataType",
                "Le Wi-Fi : carte, réseau connecté, réseaux voisins.",
                "Wi-Fi: card, connected network, nearby networks.",
            ),
        ],
    },
    Programme {
        nom: "pmset",
        role: ("batterie et veille", "battery and sleep"),
        executable: "pmset",
        commandes: &[
            voir("pmset -g batt", "La charge de la batterie.", "The battery charge."),
            voir(
                "pmset -g assertions",
                "Ce qui empêche la mise en veille.",
                "What prevents sleep.",
            ),
        ],
    },
    Programme {
        nom: "fdesetup, csrutil, spctl",
        role: ("chiffrement, SIP, Gatekeeper", "encryption, SIP, Gatekeeper"),
        executable: "spctl",
        commandes: &[
            voir(
                "fdesetup status",
                "FileVault (le chiffrement du disque) est-il actif ?",
                "Is FileVault (disk encryption) on?",
            ),
            voir(
                "csrutil status",
                "La protection de l'intégrité du système (SIP) est-elle active ?",
                "Is System Integrity Protection (SIP) on?",
            ),
            voir(
                "spctl --status",
                "Gatekeeper, qui contrôle les applications téléchargées, est-il actif ?",
                "Is Gatekeeper, which checks downloaded apps, on?",
            ),
            voir(
                "spctl -a -vv <app>",
                "Gatekeeper accepterait-il cette application, et qui l'a signée ?",
                "Would Gatekeeper accept this app, and who signed it?",
            ),
            voir(
                "codesign -dv --verbose=2 <app>",
                "La signature d'une application, en détail.",
                "An app's signature, in detail.",
            ),
        ],
    },
    Programme {
        nom: "socketfilterfw",
        role: ("pare-feu de macOS", "macOS firewall"),
        executable: "/usr/libexec/ApplicationFirewall/socketfilterfw",
        commandes: &[
            voir(
                "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                "Le pare-feu est-il actif ?",
                "Is the firewall on?",
            ),
            changer(
                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                "Active le pare-feu.",
                "Turns the firewall on.",
            ),
            changer(
                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on",
                "Mode furtif : le Mac ne répond plus aux sondes du réseau.",
                "Stealth mode: the Mac no longer answers network probes.",
            ),
        ],
    },
    Programme {
        nom: "launchctl",
        role: ("services et démarrage", "services and startup"),
        executable: "launchctl",
        commandes: &[
            voir(
                "launchctl list",
                "Les services de votre session.",
                "Your session's services.",
            ),
            voir(
                "ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons",
                "Ce qui se lance tout seul ; un nom inconnu mérite un coup d'œil.",
                "What starts by itself; an unknown name is worth a look.",
            ),
            changer(
                "launchctl bootout gui/$(id -u)/<service>",
                "Arrête un service de votre session.",
                "Stops a service of your session.",
            ),
        ],
    },
    Programme {
        nom: "log",
        role: ("journaux et plantages", "logs and crashes"),
        executable: "log",
        commandes: &[
            voir(
                "log show --last 1h --predicate 'messageType == error'",
                "Les erreurs de la dernière heure.",
                "Errors from the last hour.",
            ),
            voir(
                "log show --last boot --predicate 'messageType == fault'",
                "Les fautes graves depuis le démarrage.",
                "Serious faults since boot.",
            ),
            voir(
                "ls ~/Library/Logs/DiagnosticReports",
                "Les rapports de plantage des applications.",
                "Apps' crash reports.",
            ),
            voir(
                "open -a Console",
                "La Console : journaux et rapports, dans une fenêtre.",
                "Console: logs and reports, in a window.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "top, ps, killall",
        role: ("programmes en marche", "running programs"),
        executable: "top",
        commandes: &[
            voir(
                "top -o cpu",
                "Les programmes en direct, triés par processeur (q pour quitter).",
                "Programs, live, sorted by CPU (q to quit).",
            )
            .sauf(Obstacle::PleinEcran),
            voir(
                "ps aux | sort -nrk 4 | head",
                "Ceux qui prennent le plus de mémoire.",
                "The ones using the most memory.",
            ),
            voir(
                "open -a \"Activity Monitor\"",
                "Le Moniteur d'activité.",
                "Activity Monitor.",
            )
            .sauf(Obstacle::Fenetre),
            changer(
                "killall <programme>",
                "Ferme un programme par son nom.",
                "Closes a program by name.",
            ),
            changer(
                "killall Finder",
                "Relance le Finder quand il est figé.",
                "Restarts the Finder when it is frozen.",
            ),
            changer("killall Dock", "Relance le Dock.", "Restarts the Dock."),
            voir(
                "ps -axww -o pid,args",
                "Chaque programme avec sa ligne de commande : curl passé à sh, base64 -D, lancé de /tmp.",
                "Each program with its command line: curl piped to sh, base64 -D, started from /tmp.",
            ),
        ],
    },
    Programme {
        nom: "mdfind, mdutil",
        role: ("recherche Spotlight", "Spotlight search"),
        executable: "mdfind",
        commandes: &[
            voir(
                "mdfind \"<mot>\"",
                "Cherche comme Spotlight, dans le terminal.",
                "Searches like Spotlight, in the terminal.",
            ),
            voir(
                "mdfind -name \"<nom>\"",
                "Cherche un fichier par son nom.",
                "Finds a file by name.",
            ),
            voir(
                "mdutil -s /",
                "L'indexation de Spotlight est-elle active ?",
                "Is Spotlight indexing on?",
            ),
            changer(
                "sudo mdutil -E /",
                "Refait l'index de Spotlight, quand la recherche ne trouve plus rien.",
                "Rebuilds the Spotlight index, when search no longer finds anything.",
            ),
        ],
    },
    Programme {
        nom: "xattr",
        role: ("quarantaine des téléchargements", "download quarantine"),
        executable: "xattr",
        commandes: &[
            voir(
                "xattr -l <fichier>",
                "Les attributs d'un fichier, dont la quarantaine d'un téléchargement.",
                "A file's attributes, including a download's quarantine.",
            ),
            changer(
                "xattr -d com.apple.quarantine <fichier>",
                "Retire la quarantaine : seulement pour un programme sûr.",
                "Removes the quarantine: only for a safe program.",
            ),
        ],
    },
    Programme {
        nom: "defaults",
        role: ("réglages cachés de macOS", "hidden macOS settings"),
        executable: "defaults",
        commandes: &[
            voir(
                "defaults read com.apple.finder AppleShowAllFiles",
                "Le Finder montre-t-il les fichiers cachés ?",
                "Does Finder show hidden files?",
            ),
            changer(
                "defaults write com.apple.finder AppleShowAllFiles -bool true",
                "Les montre (puis killall Finder).",
                "Shows them (then killall Finder).",
            ),
            voir(
                "defaults read /Library/Preferences/com.apple.loginwindow",
                "Les réglages de la fenêtre de connexion (ouverture automatique…).",
                "The login window's settings (automatic login…).",
            ),
        ],
    },
    Programme {
        nom: "caffeinate, pmset",
        role: ("veille et énergie", "sleep and power"),
        executable: "caffeinate",
        commandes: &[
            voir("pmset -g", "Les réglages d'énergie.", "Power settings."),
            voir(
                "pmset -g log | grep -i -E 'wake|sleep' | tail -20",
                "Les dernières mises en veille et sorties de veille.",
                "The latest sleeps and wakes.",
            ),
            changer(
                "caffeinate -d",
                "Garde l'écran allumé tant qu'elle tourne (Ctrl-C pour arrêter).",
                "Keeps the screen on while it runs (Ctrl-C to stop).",
            ),
        ],
    },
    Programme {
        nom: "dscl, id",
        role: ("comptes du Mac", "Mac accounts"),
        executable: "dscl",
        commandes: &[
            voir(
                "dscl . list /Users | grep -v '^_'",
                "Les comptes, sans ceux du système.",
                "Accounts, without the system ones.",
            ),
            voir("id", "Votre compte et ses groupes.", "Your account and its groups."),
            changer(
                "sudo dscl . -delete /Groups/admin GroupMembership <utilisateur>",
                "Retire un compte des administrateurs.",
                "Removes an account from the administrators.",
            ),
        ],
    },
    Programme {
        nom: "profiles, systemextensionsctl",
        role: ("profils, extensions système", "profiles, system extensions"),
        executable: "profiles",
        commandes: &[
            voir(
                "sudo profiles list",
                "Les profils de configuration installés : d'une entreprise, ou d'un logiciel malveillant.",
                "Installed configuration profiles: from a company, or from malware.",
            ),
            voir(
                "systemextensionsctl list",
                "Les extensions système (antivirus, VPN…).",
                "System extensions (antivirus, VPN…).",
            ),
            voir(
                "kmutil showloaded | grep -v com.apple",
                "Les extensions du noyau de tiers.",
                "Third-party kernel extensions.",
            ),
        ],
    },
    Programme {
        nom: "sysctl, vm_stat",
        role: ("processeur, mémoire", "processor, memory"),
        executable: "sysctl",
        commandes: &[
            voir("sysctl -n machdep.cpu.brand_string", "Le processeur.", "The processor."),
            voir(
                "sysctl -n hw.memsize",
                "La mémoire vive, en octets.",
                "Memory, in bytes.",
            ),
            voir("vm_stat", "L'usage de la mémoire, par pages.", "Memory use, by pages."),
            voir(
                "uptime",
                "Depuis quand le Mac tourne, et sa charge.",
                "How long the Mac has been running, and its load.",
            ),
        ],
    },
    Programme {
        nom: "sfltool",
        role: ("ce qui se lance tout seul", "what starts by itself"),
        executable: "sfltool",
        commandes: &[voir(
            "sudo sfltool dumpbtm",
            "Tout ce qui se lance tout seul : ouverture de session, tâches de fond (macOS 13 et plus).",
            "Everything that starts by itself: login items, background tasks (macOS 13 and later).",
        )],
    },
    Programme {
        nom: "tccutil",
        role: ("accès caméra, micro, écran", "camera, mic, screen access"),
        executable: "tccutil",
        commandes: &[
            changer(
                "tccutil reset Camera",
                "Retire la caméra à toutes les apps : chacune redemandera l'accès.",
                "Takes the camera away from every app: each will ask again.",
            ),
            changer(
                "tccutil reset Microphone",
                "Pareil pour le micro.",
                "The same for the microphone.",
            ),
            changer(
                "tccutil reset ScreenCapture",
                "Pareil pour l'enregistrement de l'écran.",
                "The same for screen recording.",
            ),
        ],
    },
    Programme {
        nom: "shasum",
        role: ("empreinte d'un fichier", "a file's fingerprint"),
        executable: "shasum",
        commandes: &[voir(
            "shasum -a 256 <fichier>",
            "L'empreinte SHA-256 d'un fichier, à comparer à celle du site.",
            "A file's SHA-256 fingerprint, to compare with the site's.",
        )],
    },
    Programme {
        nom: "nettop",
        role: ("trafic réseau par programme", "network traffic per program"),
        executable: "nettop",
        commandes: &[
            voir(
                "nettop -P -L 1",
                "Le trafic réseau de chaque programme, relevé une fois.",
                "Each program's network traffic, measured once.",
            ),
            voir(
                "nettop -P",
                "Le même, en direct (q pour quitter).",
                "The same, live (q to quit).",
            )
            .sauf(Obstacle::PleinEcran),
        ],
    },
];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("macOS, Homebrew, App Store", "macOS, Homebrew, App Store"),
        executable: "softwareupdate",
        commandes: &[
            voir(
                "softwareupdate --list",
                "Les mises à jour de macOS disponibles.",
                "Available macOS updates.",
            ),
            changer(
                "sudo softwareupdate --install --all --restart",
                "Les installe, puis redémarre.",
                "Installs them, then restarts.",
            ),
            voir(
                "brew outdated",
                "Les logiciels de Homebrew à mettre à jour.",
                "Homebrew software to update.",
            ),
            changer("brew update && brew upgrade", "Les met à jour.", "Updates them."),
            changer(
                "brew cleanup",
                "Retire les anciennes versions.",
                "Removes old versions.",
            ),
            voir(
                "open -a \"App Store\"",
                "Les applications de l'App Store se mettent à jour dans l'App Store.",
                "App Store apps update in the App Store.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "Pas à pas : réparer le disque",
        role: ("vérifier, réparer, récupérer", "check, repair, recover"),
        executable: "diskutil",
        commandes: &[
            voir(
                "diskutil list",
                "Les disques et leurs volumes.",
                "Disks and their volumes.",
            ),
            voir(
                "diskutil verifyVolume /",
                "Vérifie le disque du système (le Mac ralentit quelques minutes).",
                "Checks the system disk (the Mac slows down for a few minutes).",
            )
            .sauf(Obstacle::Longue),
            changer(
                "diskutil repairVolume <disque>",
                "Répare un disque externe.",
                "Repairs an external disk.",
            ),
            changer(
                "sudo shutdown -r now",
                "Le disque du système se répare depuis la récupération : redémarrez en tenant Cmd+R (Apple : le bouton).",
                "The system disk is repaired from recovery: restart holding Cmd+R (Apple chip: the button).",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : réseau",
        role: ("Wi-Fi, DNS, adresse", "Wi-Fi, DNS, address"),
        executable: "networksetup",
        commandes: &[
            voir(
                "networksetup -listallhardwareports",
                "Les cartes réseau et leurs noms (en0…).",
                "Network cards and their names (en0…).",
            ),
            voir(
                "ipconfig getifaddr en0",
                "L'adresse de la carte Wi-Fi ; rien : pas connecté.",
                "The Wi-Fi card's address; nothing: not connected.",
            ),
            voir(
                "scutil --dns | head -20",
                "Les serveurs DNS utilisés.",
                "The DNS servers in use.",
            ),
            changer(
                "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder",
                "Vide le cache DNS.",
                "Empties the DNS cache.",
            ),
            changer(
                "sudo ipconfig set en0 DHCP",
                "Redemande une adresse au routeur.",
                "Asks the router for a new address.",
            ),
            changer(
                "networksetup -setairportpower en0 off",
                "Éteint le Wi-Fi…",
                "Turns Wi-Fi off…",
            ),
            changer(
                "networksetup -setairportpower en0 on",
                "…et le rallume.",
                "…and back on.",
            ),
            voir(
                "networkQuality",
                "Mesure le débit et la réactivité de la connexion.",
                "Measures the connection's speed and responsiveness.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : faire de la place",
        role: ("disque plein", "full disk"),
        executable: "tmutil",
        commandes: &[
            voir("df -h /", "La place libre.", "Free space."),
            voir(
                "du -sh ~/Library/Caches",
                "Le cache des applications.",
                "The apps' cache.",
            ),
            voir("du -sh ~/Downloads", "Les Téléchargements.", "Downloads."),
            voir(
                "tmutil listlocalsnapshots /",
                "Les instantanés locaux de Time Machine, qui prennent de la place.",
                "Local Time Machine snapshots, which take space.",
            ),
            changer(
                "sudo tmutil thinlocalsnapshots / 20000000000 4",
                "Libère jusqu'à 20 Go de ces instantanés.",
                "Frees up to 20 GB of those snapshots.",
            ),
            changer(
                "brew cleanup -s",
                "Vide le cache de Homebrew.",
                "Empties Homebrew's cache.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : sécurité",
        role: ("FileVault, pare-feu, Gatekeeper", "FileVault, firewall, Gatekeeper"),
        executable: "spctl",
        commandes: &[
            voir(
                "fdesetup status",
                "FileVault chiffre-t-il le disque ?",
                "Does FileVault encrypt the disk?",
            ),
            voir(
                "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate",
                "Le pare-feu est-il actif ?",
                "Is the firewall on?",
            ),
            changer(
                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                "L'active.",
                "Turns it on.",
            ),
            voir(
                "spctl --status",
                "Gatekeeper vérifie-t-il les applications ?",
                "Does Gatekeeper check apps?",
            ),
            voir(
                "csrutil status",
                "La protection de l'intégrité du système (SIP) est-elle active ?",
                "Is System Integrity Protection (SIP) on?",
            ),
            voir(
                "dscl . -read /Groups/admin GroupMembership",
                "Qui est administrateur.",
                "Who is an administrator.",
            ),
            voir(
                "profiles status -type enrollment",
                "Ce Mac est-il géré par une organisation (MDM) ?",
                "Is this Mac managed by an organization (MDM)?",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : Time Machine",
        role: ("sauvegarder et vérifier", "back up and check"),
        executable: "tmutil",
        commandes: &[
            voir(
                "tmutil destinationinfo",
                "Où vont les sauvegardes.",
                "Where backups go.",
            ),
            voir(
                "tmutil status",
                "Une sauvegarde est-elle en cours ?",
                "Is a backup running?",
            ),
            voir("tmutil latestbackup", "La dernière sauvegarde.", "The latest backup."),
            changer("tmutil startbackup", "En lance une maintenant.", "Starts one now."),
            voir("tmutil listbackups", "Toutes les sauvegardes.", "All backups."),
            changer(
                "sudo tmutil enable",
                "Réactive les sauvegardes automatiques.",
                "Turns automatic backups back on.",
            ),
        ],
    },
];
