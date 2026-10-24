//! Guide : les commandes communes à toutes les distributions de Linux, puis ce que plusieurs partagent (ufw,
//! firewalld) et openSUSE, rangé dans « Autres Linux ». Chaque distribution a son fichier (arch, omarchy, fedora,
//! debian).

use super::{Obstacle, Programme, changer, voir};

/// Les programmes de toutes les distributions : chaque Linux du guide les montre après les siens.
pub const COMMUNS: &[Programme] = &[
    Programme {
        nom: "systemctl",
        role: ("services : état, démarrage", "services: status, start, stop"),
        executable: "systemctl",
        commandes: &[
            voir("systemctl --failed", "Les services en échec.", "Failed services."),
            voir(
                "systemctl status <service>",
                "État d'un service, avec ses dernières lignes de journal.",
                "A service's status, with its latest log lines.",
            ),
            voir(
                "systemctl list-units --type=service --state=running",
                "Les services qui tournent.",
                "Running services.",
            ),
            voir(
                "systemctl list-timers",
                "Les minuteries : ce qui se lance tout seul, et quand.",
                "Timers: what starts by itself, and when.",
            ),
            voir(
                "systemctl --user status <service>",
                "Un service de votre session plutôt que du système.",
                "A service of your session rather than of the system.",
            ),
            changer(
                "sudo systemctl restart <service>",
                "Redémarre un service.",
                "Restarts a service.",
            ),
            changer(
                "sudo systemctl enable --now <service>",
                "Lance un service et le garde au démarrage.",
                "Starts a service and keeps it at boot.",
            ),
            changer(
                "sudo systemctl disable --now <service>",
                "Arrête un service et le retire du démarrage.",
                "Stops a service and removes it from boot.",
            ),
            changer(
                "sudo systemctl daemon-reload",
                "Relit les fichiers des services après une modification.",
                "Reloads the service files after a change.",
            ),
            voir(
                "systemd-analyze blame",
                "Ce qui ralentit le démarrage, du plus lent au plus rapide.",
                "What slows down boot, slowest first.",
            ),
            voir(
                "systemd-analyze security",
                "L'exposition de chaque service : plus la note est haute, moins il est enfermé.",
                "Each service's exposure: the higher the score, the less it is confined.",
            ),
            voir(
                "systemd-analyze security <service>",
                "Le détail pour un service : ce qui le protège, ce qui lui manque.",
                "The details for one service: what protects it, what it lacks.",
            ),
        ],
    },
    Programme {
        nom: "journalctl, coredumpctl",
        role: ("journaux, plantages", "logs, crashes"),
        executable: "journalctl",
        commandes: &[
            voir(
                "journalctl -b -p err",
                "Les erreurs depuis le démarrage (avec sudo si le journal du système ne s'affiche pas).",
                "Errors since boot (with sudo if the system log does not show).",
            ),
            voir(
                "journalctl -b -1 -p warning",
                "Les avertissements du démarrage précédent : après un plantage ou un gel.",
                "Warnings from the previous boot: after a crash or a freeze.",
            ),
            voir(
                "journalctl -f",
                "Le journal en direct (Ctrl-C pour arrêter).",
                "The log, live (Ctrl-C to stop).",
            ),
            voir(
                "journalctl -u <service> -n 50",
                "Les 50 dernières lignes d'un service.",
                "A service's last 50 lines.",
            ),
            voir(
                "journalctl -k -b",
                "Les messages du noyau : pilotes, matériel, disques.",
                "Kernel messages: drivers, hardware, disks.",
            ),
            voir(
                "journalctl --since \"1 hour ago\"",
                "Tout ce qui s'est passé depuis une heure.",
                "Everything from the last hour.",
            ),
            voir(
                "journalctl --list-boots",
                "Les démarrages enregistrés.",
                "Recorded boots.",
            ),
            voir(
                "journalctl --disk-usage",
                "La place prise par les journaux.",
                "The space taken by the logs.",
            ),
            changer(
                "sudo journalctl --vacuum-time=2weeks",
                "Efface les journaux de plus de deux semaines.",
                "Deletes logs older than two weeks.",
            ),
            voir(
                "coredumpctl list",
                "Les programmes qui ont planté, avec la date.",
                "Programs that crashed, with the date.",
            ),
            voir(
                "coredumpctl info <programme>",
                "Le détail du dernier plantage de ce programme.",
                "Details of this program's last crash.",
            ),
            voir(
                "journalctl -u sshd | grep Failed",
                "Les mots de passe SSH ratés (ssh au lieu de sshd sous Debian et Ubuntu ; sudo si rien ne s'affiche).",
                "Failed SSH passwords (ssh instead of sshd on Debian and Ubuntu; sudo if nothing shows).",
            ),
            voir(
                "journalctl -u sshd | grep Accepted",
                "Les connexions SSH acceptées : depuis une adresse qui ratait juste avant, un mot de passe deviné.",
                "Accepted SSH sign-ins: from an address that was failing just before, a guessed password.",
            ),
        ],
    },
    Programme {
        nom: "flatpak",
        role: ("applications Flatpak", "Flatpak apps"),
        executable: "flatpak",
        commandes: &[
            voir(
                "flatpak list --app",
                "Les applications Flatpak installées.",
                "Installed Flatpak apps.",
            ),
            changer("flatpak update", "Les met à jour.", "Updates them."),
            voir(
                "flatpak search <mot>",
                "Cherche une application (Flathub).",
                "Searches for an app (Flathub).",
            ),
            changer(
                "flatpak install flathub <id>",
                "Installe une application (ex. org.mozilla.firefox).",
                "Installs an app (e.g. org.mozilla.firefox).",
            ),
            changer(
                "flatpak uninstall <id>",
                "Désinstalle une application.",
                "Removes an app.",
            ),
            changer(
                "flatpak uninstall --unused",
                "Retire les bibliothèques qui ne servent plus.",
                "Removes libraries no longer used.",
            ),
            voir(
                "flatpak info --show-permissions <id>",
                "Ce qu'une application a le droit de faire : fichiers, réseau, caméra…",
                "What an app is allowed to do: files, network, camera…",
            ),
        ],
    },
    Programme {
        nom: "ip, ss",
        role: ("adresses, routes, ports ouverts", "addresses, routes, open ports"),
        executable: "ip",
        commandes: &[
            voir(
                "ip -br a",
                "L'adresse de chaque carte réseau, en bref.",
                "Each network card's address, in brief.",
            ),
            voir(
                "ip route",
                "Les routes : « default via » donne l'adresse du routeur.",
                "Routes: “default via” gives the router's address.",
            ),
            voir(
                "ip neigh",
                "Les appareils vus récemment sur le réseau (table ARP).",
                "Devices recently seen on the network (ARP table).",
            ),
            voir(
                "ip -s link",
                "Les compteurs de chaque carte : octets, erreurs, pertes.",
                "Each card's counters: bytes, errors, drops.",
            ),
            voir(
                "ss -ltnp | grep -E ':(11434|1234|8188|7860) '",
                "Un serveur d'IA (Ollama, LM Studio, ComfyUI) ouvert au-delà de 127.0.0.1 ?",
                "An AI server (Ollama, LM Studio, ComfyUI) open beyond 127.0.0.1?",
            ),
            voir(
                "ss -tulpn",
                "Les ports en écoute et leur programme (avec sudo : tous les programmes).",
                "Listening ports and their program (with sudo: every program).",
            ),
            voir(
                "ss -tp",
                "Les connexions TCP en cours et leur programme.",
                "Current TCP connections and their program.",
            ),
        ],
    },
    Programme {
        nom: "nmcli",
        role: ("Wi-Fi et connexions", "Wi-Fi and connections"),
        executable: "nmcli",
        commandes: &[
            voir(
                "nmcli device status",
                "L'état de chaque carte réseau.",
                "Each network card's state.",
            ),
            voir(
                "nmcli device wifi list",
                "Les Wi-Fi à portée, avec leur signal et leur sécurité.",
                "Wi-Fi networks in range, with their signal and security.",
            ),
            voir(
                "nmcli connection show",
                "Les connexions enregistrées.",
                "Saved connections.",
            ),
            changer(
                "nmcli --ask device wifi connect \"<nom>\"",
                "Se connecte à un Wi-Fi ; le mot de passe est demandé.",
                "Connects to a Wi-Fi network; the password is asked.",
            ),
            changer(
                "nmcli networking off && nmcli networking on",
                "Coupe puis rallume tout le réseau.",
                "Turns all networking off, then on again.",
            ),
        ],
    },
    Programme {
        nom: "resolvectl",
        role: ("DNS (systemd-resolved)", "DNS (systemd-resolved)"),
        executable: "resolvectl",
        commandes: &[
            voir(
                "resolvectl status",
                "Les serveurs DNS de chaque carte réseau.",
                "Each network card's DNS servers.",
            ),
            voir(
                "resolvectl query <site>",
                "L'adresse d'un site, et le serveur DNS qui a répondu.",
                "A site's address, and the DNS server that answered.",
            ),
            changer(
                "sudo resolvectl flush-caches",
                "Vide le cache DNS.",
                "Clears the DNS cache.",
            ),
        ],
    },
    Programme {
        nom: "lsblk, df, du",
        role: ("disques, partitions, place", "disks, partitions, space"),
        executable: "lsblk",
        commandes: &[
            voir(
                "lsblk -f",
                "Disques et partitions : système de fichiers, place, montage.",
                "Disks and partitions: file system, space, mount point.",
            ),
            voir(
                "lsblk -d -o NAME,SIZE,MODEL,ROTA",
                "Le modèle de chaque disque (ROTA 0 : SSD).",
                "Each disk's model (ROTA 0: SSD).",
            ),
            voir("df -h", "La place libre sur chaque disque.", "Free space on each disk."),
            voir(
                "du -sh * | sort -h",
                "La taille de chaque dossier ici, du plus petit au plus gros.",
                "The size of each folder here, smallest first.",
            ),
            voir(
                "sudo du -xh --max-depth=2 / | sort -h | tail -20",
                "Les 20 plus gros dossiers du système.",
                "The system's 20 largest folders.",
            ),
        ],
    },
    Programme {
        nom: "smartctl",
        role: ("santé des disques (smartmontools)", "disk health (smartmontools)"),
        executable: "smartctl",
        commandes: &[
            voir(
                "sudo smartctl -H /dev/<disque>",
                "Le verdict de santé d'un disque (PASSED : bon). Son nom, sda ou nvme0n1, vient de lsblk.",
                "A disk's health verdict (PASSED: good). Its name, sda or nvme0n1, comes from lsblk.",
            ),
            voir(
                "sudo smartctl -a /dev/<disque>",
                "Tout : heures d'usage, secteurs réalloués, usure, erreurs.",
                "Everything: hours of use, reallocated sectors, wear, errors.",
            ),
            voir(
                "sudo smartctl -t short /dev/<disque>",
                "Lance un court test du disque (2 minutes), lu ensuite avec -a.",
                "Starts a short disk self-test (2 minutes), read afterwards with -a.",
            ),
        ],
    },
    Programme {
        nom: "btrfs, fsck",
        role: ("vérifier un système de fichiers", "check a file system"),
        executable: "fsck",
        commandes: &[
            voir(
                "sudo btrfs filesystem usage /",
                "La vraie place libre sur btrfs (df peut se tromper).",
                "The real free space on btrfs (df can be wrong).",
            ),
            voir(
                "sudo btrfs device stats /",
                "Les erreurs de lecture et d'écriture vues sur le disque.",
                "Read and write errors seen on the disk.",
            ),
            changer(
                "sudo btrfs scrub start -B /",
                "Relit et vérifie toutes les données ; répare ce qui peut l'être.",
                "Rereads and checks all the data; repairs what can be repaired.",
            ),
            changer(
                "sudo fsck -f /dev/<partition>",
                "Vérifie et répare une partition NON montée, depuis une clé de secours ; jamais une partition en service.",
                "Checks and repairs an UNMOUNTED partition, from a rescue USB; never a partition in use.",
            ),
        ],
    },
    Programme {
        nom: "snapper, timeshift",
        role: ("instantanés du système", "system snapshots"),
        executable: "snapper",
        commandes: &[
            voir(
                "sudo snapper list",
                "Les instantanés (Omarchy, openSUSE) ; on revient à l'un d'eux depuis le menu de démarrage.",
                "Snapshots (Omarchy, openSUSE); you go back to one from the boot menu.",
            ),
            changer(
                "sudo snapper create --description \"<texte>\"",
                "Crée un instantané avant une manipulation risquée.",
                "Creates a snapshot before a risky operation.",
            ),
            voir(
                "sudo timeshift --list",
                "Les instantanés de Timeshift (Mint, Ubuntu).",
                "Timeshift snapshots (Mint, Ubuntu).",
            ),
            changer(
                "sudo timeshift --create --comments \"<texte>\"",
                "Crée un instantané avec Timeshift.",
                "Creates a snapshot with Timeshift.",
            ),
            changer(
                "sudo timeshift --restore",
                "Revient à un instantané (il est demandé lequel).",
                "Goes back to a snapshot (asks which one).",
            ),
        ],
    },
    Programme {
        nom: "hostnamectl, lspci, inxi",
        role: ("système et matériel", "system and hardware"),
        executable: "hostnamectl",
        commandes: &[
            voir(
                "hostnamectl",
                "Le nom de l'ordinateur, le système, le noyau, le modèle.",
                "The computer's name, system, kernel, model.",
            ),
            voir(
                "cat /etc/os-release",
                "La distribution et sa version exactes.",
                "The exact distribution and version.",
            ),
            voir("uname -r", "La version du noyau.", "The kernel version."),
            voir(
                "lscpu",
                "Le processeur : modèle, cœurs, fréquences.",
                "The processor: model, cores, frequencies.",
            ),
            voir(
                "lspci -k",
                "Les cartes internes (graphique, réseau, son) et le pilote de chacune.",
                "Internal cards (graphics, network, sound) and each one's driver.",
            ),
            voir("lsusb", "Les appareils USB branchés.", "Plugged-in USB devices."),
            voir(
                "inxi -Fxz",
                "Tout le matériel d'un coup, à copier dans un forum ; -z masque ce qui est personnel.",
                "All the hardware at once, to paste in a forum; -z hides what is personal.",
            ),
        ],
    },
    Programme {
        nom: "sensors, upower",
        role: ("températures, batterie", "temperatures, battery"),
        executable: "sensors",
        commandes: &[
            voir(
                "sensors",
                "Les températures et les ventilateurs (lm_sensors).",
                "Temperatures and fans (lm_sensors).",
            ),
            voir(
                "upower -i $(upower -e | grep BAT)",
                "La batterie : charge, usure (energy-full face à energy-full-design).",
                "The battery: charge, wear (energy-full versus energy-full-design).",
            ),
        ],
    },
    Programme {
        nom: "fwupdmgr",
        role: ("mises à jour du firmware", "firmware updates"),
        executable: "fwupdmgr",
        commandes: &[
            voir(
                "fwupdmgr get-devices",
                "Les appareils dont le firmware se met à jour : BIOS, SSD, station d'accueil…",
                "Devices whose firmware can be updated: BIOS, SSD, dock…",
            ),
            voir(
                "fwupdmgr refresh",
                "Télécharge la liste des firmwares récents.",
                "Downloads the list of recent firmware.",
            )
            .sauf(Obstacle::Administrateur),
            voir(
                "fwupdmgr get-updates",
                "Les mises à jour de firmware disponibles.",
                "Available firmware updates.",
            ),
            changer(
                "fwupdmgr update",
                "Les installe ; un redémarrage peut suivre.",
                "Installs them; a restart may follow.",
            ),
        ],
    },
    Programme {
        nom: "top, ps, kill",
        role: ("programmes en marche, mémoire", "running programs, memory"),
        executable: "ps",
        commandes: &[
            voir(
                "top",
                "Les programmes en direct (q pour quitter ; htop, s'il est installé, est plus lisible).",
                "Programs, live (q to quit; htop, if installed, is easier to read).",
            )
            .sauf(Obstacle::PleinEcran),
            voir(
                "ps aux --sort=-%mem | head",
                "Ceux qui prennent le plus de mémoire.",
                "The ones using the most memory.",
            ),
            voir(
                "ps aux --sort=-%cpu | head",
                "Ceux qui prennent le plus de processeur.",
                "The ones using the most CPU.",
            ),
            voir(
                "free -h",
                "La mémoire vive utilisée et libre, et le swap.",
                "Used and free memory, and swap.",
            ),
            voir(
                "pgrep -a <nom>",
                "Trouve un programme en marche par son nom, avec son numéro (PID).",
                "Finds a running program by name, with its number (PID).",
            ),
            changer(
                "kill <PID>",
                "Demande à un programme de se fermer.",
                "Asks a program to close.",
            ),
            changer(
                "kill -9 <PID>",
                "Le force à se fermer : il perd ce qui n'est pas enregistré.",
                "Forces it to close: it loses what is not saved.",
            ),
            changer(
                "pkill <nom>",
                "Ferme tous les programmes de ce nom.",
                "Closes every program with this name.",
            ),
            voir(
                "ps -eo pid,args",
                "Chaque programme avec sa ligne de commande : curl ou wget passé à sh, base64 -d, lancé de /tmp.",
                "Each program with its command line: curl or wget piped to sh, base64 -d, started from /tmp.",
            ),
        ],
    },
    Programme {
        nom: "sudo, chmod, chown",
        role: ("comptes et droits", "accounts and permissions"),
        executable: "sudo",
        commandes: &[
            voir(
                "id",
                "Votre compte et vos groupes (wheel ou sudo : administrateur).",
                "Your account and groups (wheel or sudo: administrator).",
            ),
            voir(
                "sudo -l",
                "Ce que vous avez le droit de faire avec sudo.",
                "What you are allowed to do with sudo.",
            ),
            voir(
                "who",
                "Qui est connecté en ce moment, sur l'écran ou à distance.",
                "Who is logged in right now, on screen or remotely.",
            ),
            voir(
                "ls -l <fichier>",
                "Les droits d'un fichier : rwx pour vous, votre groupe, les autres.",
                "A file's permissions: rwx for you, your group, the others.",
            ),
            changer(
                "chmod 600 <fichier>",
                "Rend un fichier lisible par vous seul (clé, mot de passe).",
                "Makes a file readable by you only (key, password).",
            ),
            changer(
                "sudo chown -R $USER: <dossier>",
                "Vous rend propriétaire d'un dossier, après un sudo de trop.",
                "Makes you the owner of a folder, after one sudo too many.",
            ),
            changer("passwd", "Change votre mot de passe.", "Changes your password."),
        ],
    },
    Programme {
        nom: "find, grep",
        role: ("chercher fichiers et textes", "find files and text"),
        executable: "find",
        commandes: &[
            voir(
                "find ~ -iname \"*<mot>*\"",
                "Cherche un fichier par son nom dans votre dossier personnel.",
                "Finds a file by name in your home folder.",
            ),
            voir(
                "find ~ -type f -size +1G",
                "Les fichiers de plus de 1 Go.",
                "Files larger than 1 GB.",
            ),
            voir(
                "find ~ -type f -mtime -1",
                "Les fichiers modifiés depuis 24 heures.",
                "Files changed in the last 24 hours.",
            ),
            voir(
                "grep -rni \"<texte>\" <dossier>",
                "Cherche un texte dans les fichiers d'un dossier.",
                "Searches for text in a folder's files.",
            ),
            voir(
                "journalctl -b | grep -i <mot>",
                "Filtre ce qu'une commande affiche (ici le journal) : seules les lignes avec ce mot restent.",
                "Filters what a command shows (here the log): only the lines with this word stay.",
            ),
        ],
    },
    Programme {
        nom: "rsync",
        role: ("copier, sauvegarder des dossiers", "copy, back up folders"),
        executable: "rsync",
        commandes: &[
            changer(
                "rsync -a --info=progress2 <source>/ <destination>/",
                "Copie un dossier entier ; relancée, elle ne recopie que ce qui manque.",
                "Copies a whole folder; run again, it only copies what is missing.",
            ),
            voir(
                "rsync -a --delete --dry-run <source>/ <destination>/",
                "Montre ce qu'un miroir exact effacerait ; sans --dry-run, il l'efface vraiment.",
                "Shows what an exact mirror would delete; without --dry-run, it really deletes it.",
            ),
        ],
    },
    Programme {
        nom: "timedatectl, loginctl",
        role: ("heure, langue, sessions", "time, language, sessions"),
        executable: "timedatectl",
        commandes: &[
            voir(
                "timedatectl",
                "L'heure, le fuseau, et la synchronisation par le réseau (NTP).",
                "The time, the time zone, and network synchronization (NTP).",
            ),
            changer(
                "sudo timedatectl set-timezone <nom>",
                "Change le fuseau horaire (America/Toronto, Europe/Paris…).",
                "Changes the time zone (America/Toronto, Europe/Paris…).",
            ),
            changer(
                "sudo timedatectl set-ntp true",
                "Remet l'heure à jour toute seule, par le réseau.",
                "Keeps the time up to date by itself, through the network.",
            ),
            voir(
                "localectl",
                "La langue et le clavier du système.",
                "The system's language and keyboard.",
            ),
            voir(
                "loginctl list-sessions",
                "Les sessions ouvertes, sur l'écran ou à distance.",
                "Open sessions, on screen or remote.",
            ),
            changer(
                "loginctl terminate-session <id>",
                "Ferme une session.",
                "Ends a session.",
            ),
        ],
    },
    Programme {
        nom: "dmesg, lsmod, modprobe",
        role: ("noyau et pilotes", "kernel and drivers"),
        executable: "dmesg",
        commandes: &[
            voir(
                "sudo dmesg --level=err,warn | tail -30",
                "Les erreurs et avertissements du noyau depuis le démarrage (matériel, pilotes).",
                "Kernel errors and warnings since boot (hardware, drivers).",
            ),
            voir(
                "lsmod | head -30",
                "Les modules (pilotes) chargés dans le noyau.",
                "The modules (drivers) loaded in the kernel.",
            ),
            voir(
                "modinfo <module>",
                "Le détail d'un module : version, options, matériel pris en charge.",
                "A module's details: version, options, supported hardware.",
            ),
            changer(
                "sudo modprobe -r <module> && sudo modprobe <module>",
                "Recharge un pilote qui ne répond plus (Wi-Fi, son).",
                "Reloads a driver that no longer answers (Wi-Fi, sound).",
            ),
            voir(
                "cat /proc/cmdline",
                "Les options données au noyau au démarrage.",
                "The options given to the kernel at boot.",
            ),
            voir(
                "uname -a",
                "Le noyau, sa version, l'architecture.",
                "The kernel, its version, the architecture.",
            ),
        ],
    },
    Programme {
        nom: "rfkill, iw, bluetoothctl",
        role: ("Wi-Fi et Bluetooth bloqués ?", "blocked Wi-Fi and Bluetooth?"),
        executable: "rfkill",
        commandes: &[
            voir(
                "rfkill list",
                "Ce qui est bloqué : Wi-Fi, Bluetooth (bouton, mode avion).",
                "What is blocked: Wi-Fi, Bluetooth (switch, airplane mode).",
            ),
            changer("sudo rfkill unblock all", "Débloque tout.", "Unblocks everything."),
            voir(
                "iw dev",
                "Les cartes Wi-Fi et leur état.",
                "Wi-Fi cards and their state.",
            ),
            voir(
                "iw dev <interface> link",
                "La connexion Wi-Fi d'une carte (wlan0…) : réseau, signal, débit.",
                "A card's Wi-Fi connection (wlan0…): network, signal, rate.",
            ),
            voir(
                "bluetoothctl devices",
                "Les appareils Bluetooth connus.",
                "Known Bluetooth devices.",
            ),
            changer(
                "bluetoothctl connect <adresse>",
                "Se connecte à un appareil Bluetooth.",
                "Connects to a Bluetooth device.",
            ),
            changer(
                "bluetoothctl remove <adresse>",
                "L'oublie, pour l'appairer à nouveau.",
                "Forgets it, to pair it again.",
            ),
        ],
    },
    Programme {
        nom: "dig, tracepath, mtr",
        role: ("DNS et chemin vers un site", "DNS and path to a site"),
        executable: "dig",
        commandes: &[
            voir(
                "dig <site>",
                "La réponse du DNS pour un nom, en détail.",
                "The DNS answer for a name, in detail.",
            ),
            voir(
                "dig @1.1.1.1 <site>",
                "La même chose avec un autre serveur DNS (Cloudflare) : le vôtre répond-il mal ?",
                "The same with another DNS server (Cloudflare): does yours answer badly?",
            ),
            voir(
                "tracepath <site>",
                "Le chemin jusqu'à un site, routeur après routeur.",
                "The path to a site, router after router.",
            ),
            voir(
                "mtr -rwc 10 <site>",
                "Le chemin et les pertes à chaque étape, sur 10 essais.",
                "The path and the losses at each step, over 10 tries.",
            ),
            voir(
                "ss -s",
                "Le résumé des connexions ouvertes.",
                "A summary of open connections.",
            ),
        ],
    },
    Programme {
        nom: "findmnt, blkid, mount",
        role: ("partitions montées", "mounted partitions"),
        executable: "findmnt",
        commandes: &[
            voir(
                "findmnt -D",
                "Les systèmes de fichiers montés, avec leur place.",
                "Mounted file systems, with their space.",
            ),
            voir(
                "sudo blkid",
                "L'identifiant (UUID) et le type de chaque partition.",
                "Each partition's identifier (UUID) and type.",
            ),
            voir(
                "cat /etc/fstab",
                "Ce qui se monte au démarrage.",
                "What mounts at boot.",
            ),
            changer(
                "sudo mount /dev/<partition> /mnt",
                "Monte une partition dans /mnt.",
                "Mounts a partition on /mnt.",
            ),
            changer("sudo umount /mnt", "La démonte.", "Unmounts it."),
        ],
    },
    Programme {
        nom: "nvme, hdparm",
        role: ("santé et vitesse des SSD", "SSD health and speed"),
        executable: "nvme",
        commandes: &[
            voir(
                "sudo nvme smart-log /dev/nvme0",
                "La santé d'un SSD NVMe : usure, température, erreurs.",
                "An NVMe SSD's health: wear, temperature, errors.",
            ),
            voir(
                "sudo hdparm -t /dev/<disque>",
                "La vitesse de lecture d'un disque.",
                "A disk's read speed.",
            ),
        ],
    },
    Programme {
        nom: "uptime, vmstat, swapon",
        role: ("charge, mémoire, échange", "load, memory, swap"),
        executable: "vmstat",
        commandes: &[
            voir(
                "uptime",
                "Depuis quand l'ordinateur tourne, et sa charge.",
                "How long the computer has been running, and its load.",
            ),
            voir(
                "vmstat 1 5",
                "La mémoire, le processeur et les échanges, cinq secondes de suite.",
                "Memory, processor and swapping, five seconds in a row.",
            ),
            voir(
                "swapon --show",
                "L'espace d'échange (swap) et ce qui en est utilisé.",
                "The swap space and how much is used.",
            ),
            voir(
                "cat /proc/pressure/memory",
                "La pression sur la mémoire : le système attend-il après elle ?",
                "Memory pressure: is the system waiting on it?",
            ),
        ],
    },
    Programme {
        nom: "last, w",
        role: ("qui s'est connecté, et quand", "who logged in, and when"),
        executable: "last",
        commandes: &[
            voir(
                "last -n 20",
                "Les dernières connexions et redémarrages.",
                "The latest logins and restarts.",
            ),
            voir(
                "sudo lastb -n 20",
                "Les connexions refusées (mots de passe faux) : des essais à la chaîne sont une attaque.",
                "Refused logins (wrong passwords): a run of tries is an attack.",
            ),
            voir(
                "w",
                "Qui est connecté maintenant, et ce qu'il fait.",
                "Who is logged in now, and what they are doing.",
            ),
        ],
    },
    Programme {
        nom: "useradd, usermod, chage",
        role: ("comptes et groupes", "accounts and groups"),
        executable: "useradd",
        commandes: &[
            voir("groups", "Vos groupes.", "Your groups."),
            voir(
                "getent group sudo wheel",
                "Qui peut utiliser sudo (groupes sudo ou wheel).",
                "Who can use sudo (sudo or wheel groups).",
            ),
            changer(
                "sudo useradd -m <utilisateur>",
                "Crée un compte, avec son dossier personnel.",
                "Creates an account, with its home folder.",
            ),
            changer(
                "sudo passwd <utilisateur>",
                "Lui donne un mot de passe.",
                "Gives it a password.",
            ),
            changer(
                "sudo usermod -aG <groupe> <utilisateur>",
                "Ajoute un compte à un groupe (wheel, docker…).",
                "Adds an account to a group (wheel, docker…).",
            ),
            changer(
                "sudo passwd -l <utilisateur>",
                "Verrouille un compte.",
                "Locks an account.",
            ),
            voir(
                "sudo chage -l <utilisateur>",
                "Quand son mot de passe expire.",
                "When its password expires.",
            ),
        ],
    },
    Programme {
        nom: "crontab",
        role: ("tâches planifiées (cron)", "scheduled tasks (cron)"),
        executable: "crontab",
        commandes: &[
            voir("crontab -l", "Vos tâches planifiées.", "Your scheduled tasks."),
            changer("crontab -e", "Les modifie.", "Edits them."),
            voir(
                "ls /etc/cron.d /etc/cron.daily",
                "Les tâches planifiées du système.",
                "The system's scheduled tasks.",
            ),
        ],
    },
    Programme {
        nom: "sysctl",
        role: ("réglages du noyau", "kernel settings"),
        executable: "sysctl",
        commandes: &[
            voir(
                "sysctl <nom>",
                "La valeur d'un réglage du noyau (net.ipv4.ip_forward…).",
                "A kernel setting's value (net.ipv4.ip_forward…).",
            ),
            voir(
                "sysctl -a 2>/dev/null | grep <mot>",
                "Les réglages dont le nom contient ce mot.",
                "The settings whose name contains this word.",
            ),
            changer(
                "sudo sysctl -w <nom>=<valeur>",
                "Le change jusqu'au redémarrage.",
                "Changes it until restart.",
            ),
        ],
    },
    Programme {
        nom: "stat, file, sha256sum",
        role: ("fichiers : type, empreinte", "files: type, hash"),
        executable: "file",
        commandes: &[
            voir(
                "file <fichier>",
                "Le vrai type d'un fichier, quel que soit son nom.",
                "A file's real type, whatever its name.",
            ),
            voir(
                "stat <fichier>",
                "Taille, droits, dates de modification et d'accès.",
                "Size, permissions, change and access dates.",
            ),
            voir(
                "sha256sum <fichier>",
                "Son empreinte SHA-256, à comparer avec celle que donne l'éditeur.",
                "Its SHA-256 hash, to compare with the one the publisher gives.",
            ),
            voir(
                "lsattr <fichier>",
                "Ses attributs spéciaux (i : immuable, même pour root).",
                "Its special attributes (i: immutable, even for root).",
            ),
        ],
    },
    Programme {
        nom: "zip, unzip",
        role: ("archives .zip", ".zip archives"),
        executable: "unzip",
        commandes: &[
            voir(
                "unzip -l <archive>.zip",
                "Le contenu d'une archive, sans l'extraire.",
                "An archive's content, without extracting it.",
            ),
            changer(
                "unzip <archive>.zip -d <dossier>",
                "L'extrait dans un dossier.",
                "Extracts it into a folder.",
            ),
            changer(
                "zip -r <archive>.zip <dossier>",
                "Met un dossier dans une archive.",
                "Puts a folder into an archive.",
            ),
        ],
    },
    Programme {
        nom: "nft, iptables",
        role: ("règles du pare-feu du noyau", "kernel firewall rules"),
        executable: "nft",
        commandes: &[
            voir(
                "sudo nft list ruleset",
                "Toutes les règles du pare-feu du noyau (nftables), sous ufw ou firewalld.",
                "All kernel firewall rules (nftables), beneath ufw or firewalld.",
            ),
            voir(
                "sudo iptables -L -n -v",
                "Les règles iptables, sur les systèmes plus anciens.",
                "The iptables rules, on older systems.",
            ),
        ],
    },
    Programme {
        nom: "fail2ban-client",
        role: ("bannir les attaques répétées", "ban repeated attacks"),
        executable: "fail2ban-client",
        commandes: &[
            voir(
                "sudo fail2ban-client status",
                "Les surveillances actives (sshd…).",
                "Active watches (sshd…).",
            ),
            voir(
                "sudo fail2ban-client status sshd",
                "Les adresses bannies pour trop d'essais SSH.",
                "Addresses banned for too many SSH tries.",
            ),
            changer(
                "sudo fail2ban-client set sshd unbanip <adresse>",
                "Débannit une adresse (la vôtre, par erreur).",
                "Unbans an address (yours, by mistake).",
            ),
        ],
    },
    Programme {
        nom: "cryptsetup",
        role: ("disques chiffrés (LUKS)", "encrypted disks (LUKS)"),
        executable: "cryptsetup",
        commandes: &[
            voir(
                "lsblk -o NAME,TYPE,FSTYPE | grep -i crypt",
                "Les volumes chiffrés ouverts.",
                "Open encrypted volumes.",
            ),
            voir(
                "sudo cryptsetup luksDump /dev/<partition>",
                "Les emplacements de clé d'une partition chiffrée.",
                "An encrypted partition's key slots.",
            ),
            changer(
                "sudo cryptsetup luksAddKey /dev/<partition>",
                "Ajoute une phrase de secours, gardée à part.",
                "Adds a backup passphrase, kept apart.",
            ),
        ],
    },
    Programme {
        nom: "wpctl, pactl",
        role: ("son (PipeWire)", "sound (PipeWire)"),
        executable: "wpctl",
        commandes: &[
            voir(
                "wpctl status",
                "Cartes son, sorties et entrées, et celles par défaut (*).",
                "Sound cards, outputs and inputs, and the default ones (*).",
            ),
            changer(
                "wpctl set-default <id>",
                "Choisit la sortie ou l'entrée par défaut (numéro de wpctl status).",
                "Picks the default output or input (number from wpctl status).",
            ),
            voir("pactl list short sinks", "Les sorties son.", "Sound outputs."),
            changer(
                "systemctl --user restart pipewire wireplumber",
                "Relance le son.",
                "Restarts sound.",
            ),
        ],
    },
    Programme {
        nom: "lpstat, cancel",
        role: ("imprimantes et file d'attente", "printers and queue"),
        executable: "lpstat",
        commandes: &[
            voir(
                "lpstat -p -d",
                "Les imprimantes, et celle par défaut.",
                "Printers, and the default one.",
            ),
            voir(
                "lpstat -o",
                "Les documents en attente d'impression.",
                "Documents waiting to print.",
            ),
            changer(
                "cancel -a",
                "Annule toutes les impressions en attente.",
                "Cancels all waiting print jobs.",
            ),
            changer(
                "sudo systemctl restart cups",
                "Relance le service d'impression.",
                "Restarts the print service.",
            ),
        ],
    },
    Programme {
        nom: "powerprofilesctl, tlp-stat",
        role: ("profils d'énergie, batterie", "power profiles, battery"),
        executable: "powerprofilesctl",
        commandes: &[
            voir(
                "powerprofilesctl",
                "Le profil d'énergie actuel, et les autres.",
                "The current power profile, and the others.",
            ),
            changer(
                "powerprofilesctl set performance",
                "Passe en performance (power-saver : économie).",
                "Switches to performance (power-saver: saving).",
            ),
            voir(
                "sudo tlp-stat -b",
                "La batterie vue par TLP : usure, cycles.",
                "The battery as TLP sees it: wear, cycles.",
            ),
        ],
    },
    Programme {
        nom: "efibootmgr, mokutil, bootctl",
        role: ("démarrage UEFI, Secure Boot", "UEFI boot, Secure Boot"),
        executable: "efibootmgr",
        commandes: &[
            voir(
                "efibootmgr -v",
                "Les entrées de démarrage UEFI, et leur ordre.",
                "UEFI boot entries, and their order.",
            ),
            voir("mokutil --sb-state", "Secure Boot est-il actif ?", "Is Secure Boot on?"),
            voir(
                "bootctl status",
                "Le chargeur de démarrage et l'état du micrologiciel.",
                "The boot loader and the firmware's state.",
            ),
        ],
    },
    Programme {
        nom: "nvidia-smi, vulkaninfo",
        role: ("carte graphique et pilotes", "graphics card and drivers"),
        executable: "lspci",
        commandes: &[
            voir(
                "lspci -k | grep -A3 -iE 'vga|3d'",
                "La carte graphique, et le pilote qu'elle utilise.",
                "The graphics card, and the driver it uses.",
            ),
            voir(
                "nvidia-smi",
                "Une carte NVIDIA : pilote, mémoire, température, programmes.",
                "An NVIDIA card: driver, memory, temperature, programs.",
            ),
            voir(
                "glxinfo -B",
                "La carte qui affiche, et son pilote OpenGL.",
                "The card that displays, and its OpenGL driver.",
            ),
            voir(
                "vulkaninfo --summary",
                "Vulkan, pour les jeux : cartes et pilotes.",
                "Vulkan, for games: cards and drivers.",
            ),
        ],
    },
    Programme {
        nom: "dkms",
        role: ("pilotes construits par noyau", "drivers built per kernel"),
        executable: "dkms",
        commandes: &[
            voir(
                "dkms status",
                "Les pilotes construits pour chaque noyau (NVIDIA, VirtualBox…).",
                "Drivers built for each kernel (NVIDIA, VirtualBox…).",
            ),
            changer(
                "sudo dkms autoinstall",
                "Les reconstruit pour le noyau actuel.",
                "Rebuilds them for the current kernel.",
            ),
        ],
    },
    Programme {
        nom: "lynis",
        role: ("audit de sécurité complet", "full security audit"),
        executable: "lynis",
        commandes: &[
            voir(
                "sudo lynis audit system --quick",
                "Passe tout le système en revue ; avertissements et suggestions à la fin.",
                "Reviews the whole system; warnings and suggestions at the end.",
            ),
            voir(
                "sudo grep -E '^(warning|suggestion)' /var/log/lynis-report.dat",
                "Les avertissements et suggestions du dernier audit, à relire.",
                "The warnings and suggestions of the latest audit, to read again.",
            ),
            voir(
                "sudo lynis show details <id>",
                "Le détail d'un test cité par l'audit (SSH-7408…).",
                "The details of a test named by the audit (SSH-7408…).",
            ),
        ],
    },
    Programme {
        nom: "getcap",
        role: ("droits spéciaux des programmes", "programs' special rights"),
        executable: "getcap",
        commandes: &[
            voir(
                "find / -xdev -perm -4000 -type f 2>/dev/null",
                "Les programmes qui tournent avec les droits de leur propriétaire (SUID), root le plus souvent.",
                "Programs that run with their owner's rights (SUID), most often root.",
            ),
            voir(
                "getcap -r /usr /opt 2>/dev/null",
                "Les programmes dotés de capacités : une partie des droits de root.",
                "Programs given capabilities: part of root's rights.",
            ),
        ],
    },
    Programme {
        nom: "faillock",
        role: ("comptes bloqués", "locked accounts"),
        executable: "faillock",
        commandes: &[
            voir(
                "sudo faillock --user <utilisateur>",
                "Les mots de passe ratés qui comptent pour bloquer ce compte.",
                "The failed passwords that count toward locking this account.",
            ),
            changer(
                "sudo faillock --user <utilisateur> --reset",
                "Débloque un compte bloqué après trop de mots de passe faux.",
                "Unlocks an account locked after too many wrong passwords.",
            ),
        ],
    },
    Programme {
        nom: "clamscan, freshclam",
        role: ("antivirus ClamAV", "ClamAV antivirus"),
        executable: "clamscan",
        commandes: &[
            changer(
                "sudo freshclam",
                "Met à jour les signatures de virus (le service clamav-freshclam le fait déjà s'il tourne).",
                "Updates the virus signatures (the clamav-freshclam service already does if it runs).",
            ),
            voir(
                "clamscan -r -i <dossier>",
                "Cherche des virus dans un dossier ; seuls les fichiers infectés s'affichent.",
                "Scans a folder for viruses; only infected files are shown.",
            ),
            voir(
                "clamscan -i <fichier>",
                "Un seul fichier, par exemple un téléchargement.",
                "A single file, for example a download.",
            ),
        ],
    },
    Programme {
        nom: "gpg",
        role: ("signatures des téléchargements", "download signatures"),
        executable: "gpg",
        commandes: &[
            voir(
                "gpg --verify <fichier>.sig <fichier>",
                "Vérifie qu'un téléchargement (image ISO…) est bien signé par son auteur.",
                "Checks that a download (ISO image…) is really signed by its author.",
            ),
            changer(
                "gpg --recv-keys <clé>",
                "Récupère la clé publique de l'auteur ; son identifiant est donné sur le site du projet.",
                "Fetches the author's public key; its identifier is given on the project's site.",
            ),
            voir(
                "gpg --list-keys",
                "Les clés publiques gardées.",
                "The public keys kept.",
            ),
        ],
    },
    Programme {
        nom: "wg",
        role: ("tunnels VPN WireGuard", "WireGuard VPN tunnels"),
        executable: "wg",
        commandes: &[
            voir(
                "sudo wg show",
                "Les tunnels ouverts : pairs, dernier contact, données échangées.",
                "Open tunnels: peers, latest contact, data exchanged.",
            ),
            changer(
                "sudo wg-quick up <interface>",
                "Ouvre le tunnel décrit dans /etc/wireguard/<interface>.conf.",
                "Opens the tunnel described in /etc/wireguard/<interface>.conf.",
            ),
            changer("sudo wg-quick down <interface>", "Le ferme.", "Closes it."),
        ],
    },
    Programme {
        nom: "openssl",
        role: ("certificats d'un site", "a site's certificates"),
        executable: "openssl",
        commandes: &[
            voir(
                "openssl s_client -connect <site>:443 -brief </dev/null",
                "Le chiffrement d'un site, et si son certificat se vérifie.",
                "A site's encryption, and whether its certificate checks out.",
            ),
            voir(
                "openssl x509 -in <fichier> -noout -subject -issuer -dates",
                "Un certificat enregistré : pour qui, par qui, jusqu'à quand.",
                "A saved certificate: for whom, by whom, until when.",
            ),
        ],
    },
];

/// openSUSE, et ce que le guide ne range pas à part : les programmes communs y suffisent.
pub const AUTRES: &[Programme] = &[ZYPPER, FIREWALLD];

/// Les paquets d'openSUSE.
const ZYPPER: Programme = Programme {
    nom: "zypper",
    role: ("paquets : openSUSE", "packages: openSUSE"),
    executable: "zypper",
    commandes: &[
        changer(
            "sudo zypper refresh && sudo zypper update",
            "Met à jour openSUSE Leap.",
            "Updates openSUSE Leap.",
        ),
        changer(
            "sudo zypper dup",
            "Met à jour Tumbleweed, jusqu'à sa dernière version.",
            "Updates Tumbleweed, up to its latest snapshot.",
        ),
        changer(
            "sudo zypper install <paquet>",
            "Installe un paquet.",
            "Installs a package.",
        ),
        changer(
            "sudo zypper remove <paquet>",
            "Désinstalle un paquet.",
            "Removes a package.",
        ),
        voir("zypper search <mot>", "Cherche un paquet.", "Searches for a package."),
        voir(
            "zypper list-updates",
            "Les mises à jour disponibles.",
            "Available updates.",
        ),
        voir(
            "zypper list-patches --category security",
            "Les correctifs de sécurité qui manquent.",
            "Missing security patches.",
        ),
        voir(
            "zypper info <paquet>",
            "Ce que contient un paquet : version, taille, dépôt.",
            "What a package holds: version, size, repository.",
        ),
        voir(
            "zypper search -i <mot>",
            "Les paquets installés dont le nom contient ce mot.",
            "Installed packages whose name contains this word.",
        ),
        voir(
            "zypper repos -d",
            "Les dépôts, avec leur adresse et leur priorité.",
            "Repositories, with their address and priority.",
        ),
        voir(
            "sudo zypper ps -s",
            "Les programmes qui tournent encore avec des fichiers remplacés par la mise à jour : à redémarrer.",
            "Programs still running with files replaced by the update: to restart.",
        ),
        changer(
            "sudo zypper patch",
            "N'installe que les correctifs (Leap).",
            "Installs the patches only (Leap).",
        ),
        changer(
            "sudo zypper addlock <paquet>",
            "Bloque un paquet à sa version.",
            "Locks a package at its version.",
        ),
        voir("zypper locks", "Les paquets bloqués.", "Locked packages."),
        changer(
            "sudo transactional-update dup",
            "Met à jour une édition atomique (MicroOS, Aeon), prise en compte au redémarrage.",
            "Updates an atomic edition (MicroOS, Aeon), applied at the next restart.",
        ),
    ],
};

/// Le pare-feu d'Ubuntu, de Mint et d'Omarchy.
pub(super) const UFW: Programme = Programme {
    nom: "ufw",
    role: ("pare-feu (Ubuntu, Mint, Omarchy)", "firewall (Ubuntu, Mint, Omarchy)"),
    executable: "ufw",
    commandes: &[
        voir(
            "sudo ufw status verbose",
            "L'état du pare-feu et ses règles.",
            "The firewall's state and rules.",
        ),
        changer(
            "sudo ufw enable",
            "Active le pare-feu ; les connexions entrantes sont refusées par défaut.",
            "Turns the firewall on; incoming connections are refused by default.",
        ),
        changer(
            "sudo ufw allow <port>/tcp",
            "Ouvre un port en entrée.",
            "Opens an incoming port.",
        ),
        changer(
            "sudo ufw deny <port>/tcp",
            "Bloque un port en entrée.",
            "Blocks an incoming port.",
        ),
        changer(
            "sudo ufw delete allow <port>/tcp",
            "Retire la règle qui ouvrait ce port.",
            "Removes the rule that opened this port.",
        ),
        voir(
            "sudo ufw status numbered",
            "Les règles, numérotées.",
            "The rules, numbered.",
        ),
        changer(
            "sudo ufw delete <numéro>",
            "Retire la règle de ce numéro.",
            "Removes the rule with this number.",
        ),
        changer(
            "sudo ufw default deny incoming",
            "Refuse par défaut tout ce qui entre.",
            "Refuses everything coming in by default.",
        ),
        changer("sudo ufw allow ssh", "Ouvre SSH (port 22).", "Opens SSH (port 22)."),
        changer(
            "sudo ufw limit ssh",
            "Ouvre SSH en freinant les essais de mot de passe à la chaîne.",
            "Opens SSH while slowing down repeated password attempts.",
        ),
        changer(
            "sudo ufw allow from <adresse>",
            "Laisse entrer ce qui vient d'une adresse ou d'un réseau (192.168.1.0/24).",
            "Lets in what comes from an address or a network (192.168.1.0/24).",
        ),
        changer(
            "sudo ufw logging on",
            "Note les connexions bloquées dans le journal.",
            "Logs the blocked connections.",
        ),
    ],
};

/// Le pare-feu de Fedora et d'openSUSE.
pub(super) const FIREWALLD: Programme = Programme {
    nom: "firewall-cmd",
    role: ("pare-feu firewalld (Fedora, SUSE)", "firewalld firewall (Fedora, SUSE)"),
    executable: "firewall-cmd",
    commandes: &[
        voir(
            "firewall-cmd --state",
            "Le pare-feu tourne-t-il ?",
            "Is the firewall running?",
        ),
        voir(
            "firewall-cmd --list-all",
            "La zone par défaut : services et ports ouverts.",
            "The default zone: open services and ports.",
        ),
        changer(
            "sudo firewall-cmd --permanent --add-port=<port>/tcp",
            "Ouvre un port en entrée, pris en compte après --reload.",
            "Opens an incoming port, applied after --reload.",
        ),
        changer(
            "sudo firewall-cmd --reload",
            "Applique les règles enregistrées.",
            "Applies the saved rules.",
        ),
        changer(
            "sudo systemctl enable --now firewalld",
            "Rallume firewalld s'il a été arrêté.",
            "Turns firewalld back on if it was stopped.",
        ),
        voir(
            "firewall-cmd --get-active-zones",
            "Les zones actives, et les cartes réseau de chacune.",
            "The active zones, and the network cards of each.",
        ),
        voir(
            "firewall-cmd --get-default-zone",
            "La zone par défaut (souvent public, ou FedoraWorkstation).",
            "The default zone (often public, or FedoraWorkstation).",
        ),
        voir(
            "firewall-cmd --list-services",
            "Les services ouverts dans la zone par défaut.",
            "The services open in the default zone.",
        ),
        voir(
            "firewall-cmd --get-services",
            "Les noms de services connus (ssh, http, samba…).",
            "The known service names (ssh, http, samba…).",
        ),
        changer(
            "sudo firewall-cmd --permanent --add-service=<service>",
            "Ouvre un service pour de bon (puis --reload).",
            "Opens a service for good (then --reload).",
        ),
        changer(
            "sudo firewall-cmd --permanent --remove-service=<service>",
            "Referme un service (puis --reload).",
            "Closes a service again (then --reload).",
        ),
    ],
};

/// Les marches à suivre d'openSUSE : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("zypper : Leap ou Tumbleweed", "zypper: Leap or Tumbleweed"),
        executable: "zypper",
        commandes: &[
            changer("sudo zypper refresh", "Relit les dépôts.", "Rereads the repositories."),
            voir("zypper list-updates", "Ce qui va changer.", "What will change."),
            changer("sudo zypper update", "Leap : met à jour.", "Leap: updates."),
            changer(
                "sudo zypper dup",
                "Tumbleweed : passe à l'état suivant de la distribution ; toujours dup, jamais update.",
                "Tumbleweed: moves to the distribution's next state; always dup, never update.",
            ),
            voir(
                "sudo zypper ps -s",
                "Les programmes à redémarrer.",
                "Programs to restart.",
            ),
            changer(
                "systemctl reboot",
                "Redémarre si le noyau a changé.",
                "Restarts if the kernel changed.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : revenir en arrière",
        role: ("snapper, avant une mise à jour", "snapper, before an update"),
        executable: "snapper",
        commandes: &[
            voir(
                "sudo snapper list",
                "Les instantanés : zypper en prend un avant et un après chaque opération.",
                "Snapshots: zypper takes one before and one after each operation.",
            ),
            voir(
                "sudo snapper status <numéro>..<numéro>",
                "Ce qui a changé entre deux instantanés.",
                "What changed between two snapshots.",
            ),
            changer("sudo snapper undochange <numéro>..<numéro>", "L'annule.", "Undoes it."),
            changer(
                "sudo snapper rollback <numéro>",
                "Revient au système d'un instantané, puis redémarre ; GRUB propose aussi les instantanés.",
                "Goes back to a snapshot's system, then restart; GRUB also offers the snapshots.",
            ),
        ],
    },
];
