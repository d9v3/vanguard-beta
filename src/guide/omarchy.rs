//! Guide : Omarchy, c'est-à-dire Arch Linux avec le bureau Hyprland tout réglé : ses commandes, puis pacman, yay et
//! ufw, partagés avec Arch.

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    OMARCHY_CLI,
    APPARENCE,
    MATERIEL,
    super::arch::PACMAN,
    super::arch::YAY,
    super::linux::UFW,
    RESEAU,
    INSTALLER,
];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("omarchy update, puis redémarrer", "omarchy update, then restart"),
        executable: "omarchy",
        commandes: &[
            voir(
                "omarchy update available",
                "Une nouvelle version d'Omarchy est-elle sortie ?",
                "Is a new Omarchy version out?",
            ),
            changer(
                "omarchy update",
                "Met tout à jour (Omarchy, paquets, AUR), avec un instantané pris avant.",
                "Updates everything (Omarchy, packages, AUR), with a snapshot taken first.",
            ),
            voir(
                "omarchy update analyze logs",
                "Cherche les pannes connues dans le journal de cette mise à jour.",
                "Looks for known failures in this update's log.",
            ),
            voir(
                "pacman -Q linux && uname -r",
                "Le noyau installé, puis celui qui tourne : s'ils diffèrent, redémarrez.",
                "The installed kernel, then the running one: if they differ, restart.",
            ),
            changer(
                "omarchy system reboot",
                "Redémarre en fermant proprement les fenêtres.",
                "Restarts after closing the windows cleanly.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : dépanner",
        role: ("Wi-Fi, son, barre, instantané", "Wi-Fi, sound, bar, snapshot"),
        executable: "omarchy",
        commandes: &[
            voir(
                "omarchy debug --print --no-sudo",
                "Les informations utiles pour demander de l'aide (matériel, versions, journaux).",
                "The useful information to ask for help (hardware, versions, logs).",
            )
            .sauf(Obstacle::Fichier),
            changer(
                "omarchy restart wifi",
                "Le Wi-Fi ne marche plus : le débloque et le relance.",
                "Wi-Fi stopped working: unblocks and restarts it.",
            ),
            changer(
                "omarchy restart audio",
                "Plus de son : relance le son et les cartes son USB bloquées.",
                "No sound: restarts audio and stuck USB sound cards.",
            ),
            changer(
                "omarchy restart bluetooth",
                "Le Bluetooth ne répond plus : le débloque et le relance.",
                "Bluetooth no longer answers: unblocks and restarts it.",
            ),
            changer(
                "omarchy restart shell",
                "La barre ou le menu ne répondent plus : les relance.",
                "The bar or menu no longer answer: restarts them.",
            ),
            changer(
                "omarchy refresh config <fichier>",
                "Un réglage cassé : remet ce fichier par défaut (le vôtre gardé en copie).",
                "A broken setting: resets this file to default (yours kept as a copy).",
            ),
            changer(
                "omarchy snapshot restore",
                "En dernier recours : revient à un instantané d'avant la panne (aussi au démarrage, dans Limine).",
                "Last resort: goes back to a snapshot from before the problem (also at boot, in Limine).",
            ),
        ],
    },
];

/// La commande omarchy : mises à jour, paquets, instantanés, dépannage.
const OMARCHY_CLI: Programme = Programme {
    nom: "omarchy",
    role: ("Omarchy : mises à jour, réglages", "Omarchy: updates, settings"),
    executable: "omarchy",
    commandes: &[
        changer(
            "omarchy update",
            "Met à jour Omarchy et le système, instantané et migrations compris.",
            "Updates Omarchy and the system, snapshot and migrations included.",
        ),
        voir(
            "omarchy update available",
            "Une nouvelle version d'Omarchy est-elle sortie ?",
            "Is a new Omarchy version out?",
        ),
        voir(
            "omarchy update analyze logs",
            "Cherche les pannes connues dans le journal de la dernière mise à jour.",
            "Looks for known failures in the last update's log.",
        ),
        changer(
            "omarchy pkg add <paquet>",
            "Installe un paquet s'il manque.",
            "Installs a package if it is missing.",
        ),
        changer(
            "omarchy pkg drop <paquet>",
            "Désinstalle un paquet.",
            "Removes a package.",
        ),
        changer(
            "omarchy snapshot create",
            "Crée un instantané du système (snapper).",
            "Creates a system snapshot (snapper).",
        ),
        changer(
            "omarchy snapshot restore",
            "Revient à un instantané.",
            "Goes back to a snapshot.",
        ),
        changer(
            "omarchy restart wifi",
            "Débloque et relance le Wi-Fi.",
            "Unblocks and restarts Wi-Fi.",
        ),
        changer(
            "omarchy restart audio",
            "Relance le son, et les cartes son USB bloquées.",
            "Restarts audio, and stuck USB sound cards.",
        ),
        changer(
            "omarchy restart bluetooth",
            "Débloque et relance le Bluetooth.",
            "Unblocks and restarts Bluetooth.",
        ),
        changer(
            "omarchy restart shell",
            "Relance la barre d'Omarchy.",
            "Restarts the Omarchy bar.",
        ),
        voir(
            "omarchy debug --print --no-sudo",
            "Les informations de dépannage, à joindre à une demande d'aide (relisez-les avant).",
            "Troubleshooting information, to attach to a help request (read it first).",
        )
        .sauf(Obstacle::Fichier),
        voir(
            "omarchy commands",
            "Toutes les commandes d'Omarchy.",
            "Every Omarchy command.",
        ),
        changer(
            "omarchy pkg install",
            "Choisit des paquets à installer dans une liste filtrée au clavier.",
            "Picks packages to install from a list filtered as you type.",
        ),
        changer(
            "omarchy pkg aur install",
            "Pareil pour les paquets de l'AUR.",
            "Same for AUR packages.",
        ),
        changer(
            "omarchy pkg remove",
            "Choisit des paquets à retirer.",
            "Picks packages to remove.",
        ),
        voir(
            "omarchy channel current",
            "Le canal des mises à jour d'Omarchy : stable, rc, edge ou dev.",
            "Omarchy's update channel: stable, rc, edge or dev.",
        ),
        changer(
            "omarchy channel set stable",
            "Revient au canal stable.",
            "Goes back to the stable channel.",
        ),
        changer(
            "omarchy refresh config <fichier>",
            "Remet un fichier de réglages d'Omarchy par défaut ; le vôtre est gardé en copie.",
            "Resets an Omarchy settings file to default; yours is kept as a copy.",
        ),
        changer(
            "omarchy reinstall configs",
            "Remet TOUS les réglages d'Omarchy par défaut : vos changements sont perdus.",
            "Resets ALL Omarchy settings to default: your changes are lost.",
        ),
        changer(
            "omarchy reinstall pkgs",
            "Réinstalle tous les paquets d'Omarchy.",
            "Reinstalls all Omarchy packages.",
        ),
        changer(
            "omarchy setup security sshd",
            "Installe le serveur SSH, ouvre le pare-feu et autorise une clé.",
            "Installs the SSH server, opens the firewall and authorizes a key.",
        ),
        changer(
            "omarchy setup security fingerprint",
            "Le lecteur d'empreintes pour sudo, polkit et le verrouillage.",
            "The fingerprint reader for sudo, polkit and the lock screen.",
        ),
        changer(
            "omarchy hibernation setup",
            "Met en place la veille prolongée (espace d'échange et reprise au démarrage).",
            "Sets up hibernation (swap space and resume at boot).",
        ),
        changer(
            "omarchy system lock",
            "Verrouille l'ordinateur et éteint l'écran.",
            "Locks the computer and turns the screen off.",
        ),
        changer(
            "omarchy system reboot",
            "Redémarre en fermant proprement les fenêtres.",
            "Restarts after closing the windows cleanly.",
        ),
        voir(
            "omarchy version",
            "La version d'Omarchy installée.",
            "The installed Omarchy version.",
        ),
        voir(
            "omarchy version pkgs",
            "Quand les paquets du système ont été mis à jour pour la dernière fois.",
            "When the system packages were last upgraded.",
        ),
        changer(
            "omarchy update firmware",
            "Met à jour le firmware (BIOS, SSD, souris…) par fwupd.",
            "Updates the firmware (BIOS, SSD, mouse…) with fwupd.",
        ),
        changer(
            "omarchy update keyring",
            "Erreur de signature pendant une mise à jour : réinstalle les trousseaux d'Omarchy et d'Arch.",
            "Signature error during an update: reinstalls the Omarchy and Arch keyrings.",
        ),
        changer(
            "omarchy update time",
            "L'heure est fausse (erreurs de certificats) : relance sa synchronisation.",
            "The time is wrong (certificate errors): restarts its synchronization.",
        ),
        changer(
            "omarchy update orphan pkgs",
            "Montre les paquets que plus rien n'utilise, et propose de les retirer.",
            "Shows the packages nothing uses any more, and offers to remove them.",
        ),
        changer(
            "omarchy update pkg prune",
            "Fait de la place : retire les anciennes versions gardées dans le cache de pacman.",
            "Frees space: removes the old versions kept in pacman's cache.",
        ),
        changer(
            "omarchy migrate",
            "Applique les migrations d'Omarchy restées en attente.",
            "Applies the pending Omarchy migrations.",
        ),
        changer(
            "omarchy refresh pacman",
            "Remet les dépôts et réglages de pacman d'Omarchy, puis met tout à jour.",
            "Restores Omarchy's pacman repositories and settings, then updates everything.",
        ),
        changer(
            "omarchy setup security fido2",
            "Une clé de sécurité FIDO2 (YubiKey…) pour sudo et polkit.",
            "A FIDO2 security key (YubiKey…) for sudo and polkit.",
        ),
        changer(
            "omarchy remove security sshd",
            "Coupe le serveur SSH et referme le pare-feu (les clés autorisées, au choix).",
            "Turns off the SSH server and closes the firewall (authorized keys, your choice).",
        ),
        changer(
            "omarchy remove security sudoless docker",
            "Retire le compte du groupe docker : ce groupe vaut root sans mot de passe.",
            "Removes the account from the docker group: that group is root without a password.",
        ),
        voir(
            "omarchy windows vm status",
            "L'état de la machine virtuelle Windows d'Omarchy.",
            "The state of Omarchy's Windows virtual machine.",
        ),
        changer(
            "omarchy windows vm launch",
            "Démarre la machine virtuelle Windows et s'y connecte.",
            "Starts the Windows virtual machine and connects to it.",
        ),
        changer(
            "omarchy reminder 25 Pause",
            "Une notification dans 25 minutes ; omarchy reminder show dit ceux qui attendent.",
            "A notification in 25 minutes; omarchy reminder show lists the pending ones.",
        ),
        changer(
            "omarchy default browser <navigateur>",
            "Le navigateur par défaut : firefox, chromium, brave, chrome…",
            "The default browser: firefox, chromium, brave, chrome…",
        ),
        changer(
            "omarchy setup factory reset",
            "Remet l'ordinateur comme à l'installation : tout ce qui a été changé est perdu.",
            "Puts the computer back as freshly installed: everything changed is lost.",
        ),
    ],
};

/// Thèmes, polices et confort de l'écran.
const APPARENCE: Programme = Programme {
    nom: "omarchy theme, font, toggle",
    role: ("thèmes, polices, écran", "themes, fonts, screen"),
    executable: "omarchy",
    commandes: &[
        voir("omarchy theme list", "Les thèmes disponibles.", "Available themes."),
        voir("omarchy theme current", "Le thème actuel.", "The current theme."),
        changer(
            "omarchy theme set <nom>",
            "Change de thème partout : bureau, terminal, éditeur.",
            "Switches theme everywhere: desktop, terminal, editor.",
        ),
        changer(
            "omarchy theme install <adresse>",
            "Installe un thème depuis un dépôt git.",
            "Installs a theme from a git repository.",
        ),
        changer(
            "omarchy theme update",
            "Met à jour les thèmes installés depuis git.",
            "Updates the themes installed from git.",
        ),
        changer(
            "omarchy theme bg next",
            "Passe au fond d'écran suivant du thème.",
            "Moves to the theme's next background.",
        ),
        voir(
            "omarchy font list",
            "Les polices à chasse fixe disponibles.",
            "Available monospace fonts.",
        ),
        voir("omarchy font current", "La police actuelle.", "The current font."),
        changer(
            "omarchy font set <nom>",
            "Change la police du terminal et du bureau.",
            "Changes the terminal and desktop font.",
        ),
        changer(
            "omarchy toggle nightlight",
            "Allume ou éteint la lumière du soir (moins de bleu).",
            "Turns the night light (less blue) on or off.",
        ),
        changer(
            "omarchy toggle idle",
            "Garde l'écran allumé, ou le laisse à nouveau se mettre en veille.",
            "Keeps the screen on, or lets it sleep again.",
        ),
        changer(
            "omarchy toggle notification silencing",
            "Coupe ou rétablit les notifications (ne pas déranger).",
            "Silences or restores notifications (do not disturb).",
        ),
        changer(
            "omarchy display text size 16",
            "Le texte partout (barre, applications, terminal) à 16 px ; 12 par défaut, reset y revient.",
            "Text everywhere (bar, apps, terminal) at 16 px; 12 by default, reset goes back.",
        ),
        changer(
            "omarchy toggle bar",
            "Cache ou montre la barre.",
            "Hides or shows the bar.",
        ),
        voir(
            "omarchy plymouth current",
            "Le thème de l'écran de démarrage (celui du mot de passe du disque).",
            "The boot screen theme (the disk password one).",
        ),
        changer(
            "omarchy plymouth set by theme <thème>",
            "L'écran de démarrage aux couleurs d'un thème d'Omarchy.",
            "The boot screen in the colors of an Omarchy theme.",
        ),
        changer(
            "omarchy plymouth reset",
            "Remet l'écran de démarrage et celui de connexion d'origine.",
            "Restores the original boot and login screens.",
        ),
        changer(
            "omarchy webapp install",
            "Fait d'un site une application, avec son icône dans le lanceur.",
            "Turns a website into an app, with its icon in the launcher.",
        ),
        changer(
            "omarchy webapp remove",
            "Retire une de ces applications web.",
            "Removes one of these web apps.",
        ),
        changer(
            "omarchy default terminal <terminal>",
            "Le terminal par défaut : alacritty, foot, ghostty ou kitty.",
            "The default terminal: alacritty, foot, ghostty or kitty.",
        ),
        voir(
            "omarchy launch about",
            "Le résumé de l'ordinateur (fastfetch) : système, processeur, mémoire, écran.",
            "The computer summary (fastfetch): system, processor, memory, screen.",
        )
        .sauf(Obstacle::PleinEcran),
    ],
};

/// Le matériel vu par Omarchy.
const MATERIEL: Programme = Programme {
    nom: "omarchy hw, drive, battery",
    role: ("matériel, disques, énergie", "hardware, disks, power"),
    executable: "omarchy",
    commandes: &[
        voir(
            "omarchy battery status",
            "La batterie : pourcentage, et ce que l'ordinateur consomme ou charge.",
            "The battery: percentage, and what the computer draws or charges.",
        ),
        voir(
            "omarchy drive info <disque>",
            "Taille, modèle et points de montage d'un disque (/dev/nvme0n1…).",
            "Size, model and mount points of a disk (/dev/nvme0n1…).",
        ),
        changer(
            "omarchy drive password",
            "Change la phrase de chiffrement d'un disque.",
            "Changes a disk's encryption passphrase.",
        ),
        voir(
            "omarchy powerprofiles list",
            "Les profils d'énergie disponibles.",
            "Available power profiles.",
        ),
        changer(
            "omarchy powerprofiles set ac performance",
            "Le profil performance quand l'ordinateur est branché, gardé ensuite.",
            "The performance profile when plugged in, kept afterwards.",
        ),
        changer(
            "omarchy bluetooth power off",
            "Éteint le Bluetooth, et s'en souvient au démarrage.",
            "Turns Bluetooth off, and remembers it at boot.",
        ),
        changer(
            "omarchy dns Cloudflare",
            "Passe le DNS à Cloudflare ; omarchy dns DHCP revient à celui du routeur.",
            "Switches DNS to Cloudflare; omarchy dns DHCP goes back to the router's.",
        ),
        changer(
            "omarchy restart trackpad",
            "Relance le pavé tactile qui ne répond plus.",
            "Restarts a touchpad that no longer responds.",
        ),
        voir(
            "omarchy disk speedtest",
            "Mesure la vitesse de lecture et d'écriture du disque, dans le dossier courant.",
            "Measures the disk's read and write speed, in the current folder.",
        )
        .sauf(Obstacle::Fichier),
        changer(
            "omarchy hibernation remove",
            "Retire la veille prolongée (espace d'échange et reprise au démarrage).",
            "Removes hibernation (swap space and resume at boot).",
        ),
        voir(
            "omarchy debug idle",
            "L'écran ne se verrouille pas ou ne s'éteint pas : ce que disent la veille et le verrouillage.",
            "The screen does not lock or turn off: what idle and lock say.",
        ),
        changer(
            "omarchy brightness display +10%",
            "Plus de luminosité sur l'écran actif (-10% pour moins).",
            "More brightness on the focused screen (-10% for less).",
        ),
        changer(
            "omarchy brightness keyboard cycle",
            "Change le rétroéclairage du clavier, d'un cran.",
            "Steps the keyboard backlight.",
        ),
        changer(
            "omarchy toggle touchpad off",
            "Coupe le pavé tactile (on pour le rallumer).",
            "Turns the touchpad off (on to turn it back on).",
        ),
        changer(
            "omarchy bluetooth device connect <adresse>",
            "Connecte un appareil Bluetooth déjà jumelé (pair, disconnect, forget aussi).",
            "Connects an already paired Bluetooth device (pair, disconnect, forget too).",
        ),
        changer(
            "omarchy toggle hybrid gpu",
            "Portable à deux cartes graphiques : passe de la carte intégrée à la dédiée, et inversement.",
            "Laptop with two graphics cards: switches between the integrated and dedicated one.",
        ),
    ],
};

/// Le réseau et le partage vus par Omarchy.
const RESEAU: Programme = Programme {
    nom: "omarchy network, capture",
    role: ("réseau, partage, captures", "network, sharing, captures"),
    executable: "omarchy",
    commandes: &[
        voir(
            "omarchy network status --verbose",
            "La connexion active : Wi-Fi ou câble, adresse, force du signal, délai vers le routeur et Internet.",
            "The active connection: Wi-Fi or cable, address, signal strength, delay to the router and Internet.",
        ),
        voir(
            "omarchy network speedtest down",
            "Mesure la vitesse de téléchargement (up pour l'envoi).",
            "Measures the download speed (up for upload).",
        ),
        voir(
            "omarchy network password <interface>",
            "Affiche le mot de passe du Wi-Fi actuel (wlan0…), pour le donner à un invité.",
            "Shows the current Wi-Fi password (wlan0…), to give it to a guest.",
        ),
        changer(
            "omarchy network band 5",
            "Garde le Wi-Fi sur la bande 5 GHz (2.4, 6 ou auto aussi).",
            "Keeps Wi-Fi on the 5 GHz band (2.4, 6 or auto too).",
        ),
        changer(
            "omarchy share file <fichier>",
            "Envoie un fichier à un appareil proche par LocalSend (folder, clipboard aussi).",
            "Sends a file to a nearby device with LocalSend (folder, clipboard too).",
        ),
        changer(
            "omarchy tailscale send <machine> <fichier>",
            "Envoie un fichier à un de vos appareils Tailscale (Taildrop).",
            "Sends a file to one of your Tailscale devices (Taildrop).",
        ),
        changer(
            "omarchy capture screenshot region",
            "Capture une partie de l'écran.",
            "Captures part of the screen.",
        ),
        changer(
            "omarchy capture text",
            "Lit le texte d'une partie de l'écran (OCR) et le copie.",
            "Reads the text in part of the screen (OCR) and copies it.",
        ),
        changer(
            "omarchy capture qr",
            "Lit un code QR affiché à l'écran.",
            "Reads a QR code shown on screen.",
        ),
        changer(
            "omarchy capture screenrecording --with-microphone-audio",
            "Filme l'écran avec le micro ; --stop-recording l'arrête.",
            "Records the screen with the microphone; --stop-recording stops it.",
        ),
        changer(
            "omarchy transcode <fichier>",
            "Convertit une photo ou une vidéo pour la partager : format et taille au choix.",
            "Converts a photo or a video for sharing: format and size of your choice.",
        ),
    ],
};

/// Les programmes qu'Omarchy sait installer tout réglés, et retirer.
const INSTALLER: Programme = Programme {
    nom: "omarchy install, remove",
    role: ("installer jeux, services", "install games, services"),
    executable: "omarchy",
    commandes: &[
        changer(
            "omarchy install gaming steam",
            "Steam, avec les pilotes graphiques qu'il faut pour cet ordinateur.",
            "Steam, with the graphics drivers this computer needs.",
        ),
        changer(
            "omarchy install gaming heroic",
            "Heroic : les jeux Epic, GOG et Amazon.",
            "Heroic: Epic, GOG and Amazon games.",
        ),
        changer(
            "omarchy install gaming lutris",
            "Lutris, Wine et DXVK pour les jeux Windows (Battle.net, EA, Ubisoft…).",
            "Lutris, Wine and DXVK for Windows games (Battle.net, EA, Ubisoft…).",
        ),
        changer(
            "omarchy install gaming xbox-controllers",
            "Les manettes Xbox (pilote xpadneo), pour Steam et les émulateurs.",
            "Xbox controllers (xpadneo driver), for Steam and emulators.",
        ),
        changer(
            "omarchy install browser <navigateur>",
            "Installe un navigateur : firefox, chrome, brave, edge ou zen.",
            "Installs a browser: firefox, chrome, brave, edge or zen.",
        ),
        changer(
            "omarchy install service tailscale",
            "Tailscale : un réseau privé entre vos appareils, où qu'ils soient.",
            "Tailscale: a private network between your devices, wherever they are.",
        ),
        changer(
            "omarchy install service signal",
            "La messagerie Signal.",
            "The Signal messenger.",
        ),
        changer(
            "omarchy install dev-env <langage>",
            "Un environnement de programmation : python, node, rust, go, java…",
            "A programming environment: python, node, rust, go, java…",
        ),
        changer(
            "omarchy install preinstalls",
            "Remet les applications livrées avec Omarchy.",
            "Restores the apps shipped with Omarchy.",
        ),
        changer(
            "omarchy remove preinstalls",
            "Retire les applications livrées avec Omarchy (applications web, outils du terminal).",
            "Removes the apps shipped with Omarchy (web apps, terminal tools).",
        ),
        changer(
            "omarchy remove gaming steam",
            "Retire Steam AVEC ses jeux et leurs réglages.",
            "Removes Steam WITH its games and their settings.",
        ),
    ],
};
