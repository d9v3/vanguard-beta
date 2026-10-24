//! Guide : Debian, Ubuntu et leurs dérivées (Mint, Pop!_OS) : apt et dpkg, snap, AppArmor, les versions, les mises à
//! jour automatiques, et les marches à suivre.

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[
    APT,
    DPKG,
    SNAP,
    super::linux::UFW,
    APPARMOR,
    VERSIONS,
    AUTO,
    NEEDRESTART,
];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("apt, snap, Flatpak", "apt, snap, Flatpak"),
        executable: "apt",
        commandes: &[
            changer(
                "sudo apt update",
                "Relit les listes des dépôts.",
                "Rereads the repository lists.",
            ),
            voir("apt list --upgradable", "Ce qui va changer.", "What will change."),
            changer("sudo apt upgrade", "Met à jour les paquets.", "Updates the packages."),
            changer(
                "sudo apt full-upgrade",
                "Puis ce qui demande d'ajouter ou de retirer des paquets (nouveau noyau).",
                "Then what needs packages added or removed (new kernel).",
            ),
            changer(
                "sudo apt autoremove",
                "Retire ce qui ne sert plus (anciens noyaux).",
                "Removes what is no longer used (old kernels).",
            ),
            changer("sudo snap refresh", "Les snaps (Ubuntu).", "The snaps (Ubuntu)."),
            changer("flatpak update", "Les applications Flatpak.", "The Flatpak apps."),
            voir(
                "cat /var/run/reboot-required",
                "« System restart required » : redémarrez. Fichier absent : pas besoin.",
                "“System restart required”: restart. File missing: no need.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : installer",
        role: ("apt, Flatpak ou snap", "apt, Flatpak or snap"),
        executable: "apt",
        commandes: &[
            changer(
                "sudo apt update",
                "D'abord, les listes à jour.",
                "First, up-to-date lists.",
            ),
            voir(
                "apt search <mot>",
                "Cherche dans les dépôts de la distribution.",
                "Searches the distribution's repositories.",
            ),
            voir(
                "apt show <paquet>",
                "Ce que fait le paquet, sa taille, ses dépendances.",
                "What the package does, its size, its dependencies.",
            ),
            changer("sudo apt install <paquet>", "L'installe.", "Installs it."),
            voir(
                "flatpak search <mot>",
                "Absent ou trop ancien ? Une application Flatpak, plus récente.",
                "Missing or too old? A Flatpak app, more recent.",
            ),
            voir("snap find <mot>", "Ou un snap (Ubuntu).", "Or a snap (Ubuntu)."),
            changer(
                "sudo apt purge <paquet>",
                "Pour le retirer, réglages compris.",
                "To remove it, settings included.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : réparer apt",
        role: ("verrou, paquets cassés, dépôts", "lock, broken packages, repos"),
        executable: "apt",
        commandes: &[
            voir(
                "pgrep -a 'apt|dpkg'",
                "« Could not get lock » : un apt tourne déjà (souvent les mises à jour automatiques) ; attendez.",
                "“Could not get lock”: an apt is already running (often automatic updates); wait.",
            ),
            changer(
                "sudo dpkg --configure -a",
                "Une installation interrompue : la reprend.",
                "An interrupted installation: resumes it.",
            ),
            changer(
                "sudo apt --fix-broken install",
                "Des dépendances cassées : les répare.",
                "Broken dependencies: repairs them.",
            ),
            changer(
                "sudo apt clean && sudo apt update",
                "Des erreurs de téléchargement (« Hash Sum mismatch ») : repart d'un cache vide.",
                "Download errors (“Hash Sum mismatch”): starts again from an empty cache.",
            ),
            voir(
                "ls /etc/apt/sources.list.d/",
                "Une erreur 404 ou de clé : un dépôt ajouté en est souvent la cause.",
                "A 404 or key error: an added repository is often the cause.",
            ),
            changer(
                "sudo add-apt-repository --remove ppa:<nom>",
                "Retire le PPA fautif.",
                "Removes the faulty PPA.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : nouvelle version",
        role: ("Ubuntu ou Debian suivante", "next Ubuntu or Debian"),
        executable: "apt",
        commandes: &[
            voir("lsb_release -a", "Votre version.", "Your release."),
            changer(
                "sudo apt update && sudo apt full-upgrade",
                "D'abord, tout à jour.",
                "First, everything up to date.",
            ),
            voir(
                "do-release-upgrade -c",
                "Ubuntu : une version suivante est-elle prête ?",
                "Ubuntu: is a next release ready?",
            ),
            changer(
                "sudo do-release-upgrade",
                "Ubuntu : passe à la suivante (gardez l'ordinateur branché).",
                "Ubuntu: moves to the next one (keep the computer plugged in).",
            ),
            voir(
                "xdg-open https://www.debian.org/releases/stable/releasenotes",
                "Debian : les notes de publication, qui disent comment passer à la suivante.",
                "Debian: the release notes, which explain how to move to the next one.",
            )
            .sauf(Obstacle::Fenetre),
        ],
    },
    Programme {
        nom: "Pas à pas : pare-feu",
        role: ("ufw : activer, ouvrir, refermer", "ufw: enable, open, close"),
        executable: "apt",
        commandes: &[
            voir(
                "sudo ufw status verbose",
                "Le pare-feu est-il actif ? (Il ne l'est pas après l'installation.)",
                "Is the firewall on? (It is not after installation.)",
            ),
            changer(
                "sudo apt install ufw",
                "L'installe s'il manque (Debian).",
                "Installs it if missing (Debian).",
            ),
            changer(
                "sudo ufw default deny incoming",
                "Refuse tout ce qui entre…",
                "Refuses everything coming in…",
            ),
            changer(
                "sudo ufw allow ssh",
                "…sauf ce que vous voulez ouvrir (ici SSH).",
                "…except what you want to open (here SSH).",
            ),
            changer(
                "sudo ufw enable",
                "Active le pare-feu, aussi au démarrage.",
                "Turns the firewall on, at boot too.",
            ),
            voir(
                "sudo ufw status numbered",
                "Les règles numérotées…",
                "The numbered rules…",
            ),
            changer("sudo ufw delete <numéro>", "…pour en retirer une.", "…to remove one."),
        ],
    },
    Programme {
        nom: "Pas à pas : mises à jour auto",
        role: ("sécurité installée toute seule", "security installed by itself"),
        executable: "apt",
        commandes: &[
            changer(
                "sudo apt install unattended-upgrades",
                "L'outil des mises à jour automatiques (déjà là sous Ubuntu).",
                "The automatic updates tool (already there on Ubuntu).",
            ),
            changer(
                "sudo dpkg-reconfigure -plow unattended-upgrades",
                "Les active : répondez Oui.",
                "Turns them on: answer Yes.",
            ),
            voir(
                "systemctl status unattended-upgrades",
                "Le service tourne-t-il ?",
                "Is the service running?",
            ),
            voir(
                "sudo unattended-upgrade --dry-run --debug",
                "Ce qu'il installerait maintenant.",
                "What it would install now.",
            ),
            voir(
                "tail -30 /var/log/unattended-upgrades/unattended-upgrades.log",
                "Ce qu'il a déjà installé.",
                "What it already installed.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : faire de la place",
        role: ("apt, snaps, journaux", "apt, snaps, logs"),
        executable: "apt",
        commandes: &[
            voir(
                "df -h /",
                "La place libre sur le disque du système.",
                "Free space on the system disk.",
            ),
            changer(
                "sudo apt autoremove --purge",
                "Retire les paquets inutiles et leurs réglages (anciens noyaux).",
                "Removes unneeded packages and their settings (old kernels).",
            ),
            changer(
                "sudo apt clean",
                "Vide le cache des paquets.",
                "Empties the package cache.",
            ),
            voir(
                "snap list --all | grep disabled",
                "Les anciennes versions de snaps gardées.",
                "Old snap versions kept.",
            ),
            changer(
                "sudo snap set system refresh.retain=2",
                "N'en garde que deux par snap.",
                "Keeps only two per snap.",
            ),
            voir(
                "journalctl --disk-usage",
                "La place prise par les journaux.",
                "Space taken by the logs.",
            ),
            changer(
                "sudo journalctl --vacuum-size=200M",
                "Ne garde que 200 Mo de journaux.",
                "Keeps only 200 MB of logs.",
            ),
        ],
    },
];

/// Les paquets de Debian et d'Ubuntu.
const APT: Programme = Programme {
    nom: "apt, dpkg",
    role: ("paquets : Debian, Ubuntu, Mint", "packages: Debian, Ubuntu, Mint"),
    executable: "apt",
    commandes: &[
        changer(
            "sudo apt update && sudo apt upgrade",
            "Relit la liste des paquets, puis met tout à jour.",
            "Refreshes the package list, then updates everything.",
        ),
        changer(
            "sudo apt install <paquet>",
            "Installe un paquet.",
            "Installs a package.",
        ),
        changer(
            "sudo apt remove <paquet>",
            "Désinstalle un paquet ; sa configuration reste.",
            "Removes a package; its configuration stays.",
        ),
        changer(
            "sudo apt purge <paquet>",
            "Désinstalle un paquet et sa configuration.",
            "Removes a package and its configuration.",
        ),
        changer(
            "sudo apt autoremove",
            "Retire les paquets devenus inutiles (la liste est montrée avant).",
            "Removes packages no longer needed (the list is shown first).",
        ),
        voir("apt search <mot>", "Cherche un paquet.", "Searches for a package."),
        voir(
            "apt show <paquet>",
            "Ce qu'on sait d'un paquet.",
            "What is known about a package.",
        ),
        voir(
            "apt list --upgradable",
            "Les mises à jour disponibles (après apt update).",
            "Available updates (after apt update).",
        ),
        changer(
            "sudo apt --fix-broken install",
            "Répare les dépendances cassées.",
            "Repairs broken dependencies.",
        ),
        changer(
            "sudo apt update",
            "Relit la liste des paquets des dépôts : toujours avant d'installer ou de mettre à jour.",
            "Rereads the repositories' package lists: always before installing or updating.",
        ),
        changer(
            "sudo apt full-upgrade",
            "Met à jour même quand il faut ajouter ou retirer des paquets (nouveau noyau, transitions).",
            "Updates even when packages must be added or removed (new kernel, transitions).",
        ),
        voir(
            "apt policy <paquet>",
            "Les versions disponibles d'un paquet, et le dépôt de chacune.",
            "A package's available versions, and the repository of each.",
        ),
        voir("apt list --installed", "Les paquets installés.", "Installed packages."),
        voir(
            "apt-cache rdepends --installed <paquet>",
            "Ce qui dépend de ce paquet : à lire avant de le retirer.",
            "What depends on this package: to read before removing it.",
        ),
        voir(
            "apt-mark showmanual",
            "Les paquets installés exprès.",
            "Packages installed on purpose.",
        ),
        changer(
            "sudo apt-mark hold <paquet>",
            "Bloque un paquet à sa version actuelle (unhold pour le libérer).",
            "Holds a package at its current version (unhold to release it).",
        ),
        voir("apt-mark showhold", "Les paquets bloqués.", "Held packages."),
        changer(
            "sudo apt clean",
            "Vide le cache des paquets téléchargés.",
            "Empties the downloaded packages cache.",
        ),
        voir(
            "apt changelog <paquet>",
            "Ce qui a changé dans un paquet, version par version.",
            "What changed in a package, version by version.",
        ),
        voir(
            "apt-cache policy",
            "Tous les dépôts utilisés, avec leur priorité.",
            "All the repositories in use, with their priority.",
        ),
        voir(
            "ls /etc/apt/sources.list.d/",
            "Les dépôts ajoutés : PPA, logiciels de tiers.",
            "Added repositories: PPAs, third-party software.",
        ),
        voir(
            "tail -30 /var/log/apt/history.log",
            "Les dernières opérations d'apt : quoi, quand, par quelle commande.",
            "apt's latest operations: what, when, by which command.",
        ),
    ],
};

/// dpkg : les paquets .deb, en détail.
const DPKG: Programme = Programme {
    nom: "dpkg",
    role: ("paquets .deb, en détail", ".deb packages, in detail"),
    executable: "dpkg",
    commandes: &[
        voir(
            "dpkg -l | grep -i <mot>",
            "Les paquets installés dont le nom contient ce mot.",
            "Installed packages whose name contains this word.",
        ),
        voir("dpkg -L <paquet>", "Les fichiers d'un paquet.", "A package's files."),
        voir(
            "dpkg -S <fichier>",
            "Le paquet qui a installé ce fichier.",
            "The package that installed this file.",
        ),
        changer(
            "sudo dpkg --configure -a",
            "Termine une installation interrompue.",
            "Finishes an interrupted installation.",
        ),
        changer(
            "sudo dpkg -i <fichier>",
            "Installe un fichier .deb téléchargé ; sudo apt -f install complète ses dépendances.",
            "Installs a downloaded .deb file; sudo apt -f install completes its dependencies.",
        ),
        voir(
            "dpkg --audit",
            "Les paquets mal installés ou à moitié configurés.",
            "Packages badly installed or half configured.",
        ),
        voir(
            "debsums -s",
            "Les fichiers de paquets modifiés depuis l'installation (paquet debsums).",
            "Package files changed since installation (debsums package).",
        ),
    ],
};

/// Les applications Snap (Ubuntu).
const SNAP: Programme = Programme {
    nom: "snap",
    role: ("applications Snap (Ubuntu)", "Snap apps (Ubuntu)"),
    executable: "snap",
    commandes: &[
        voir("snap list", "Les Snap installés.", "Installed snaps."),
        changer("sudo snap refresh", "Les met à jour.", "Updates them."),
        voir("snap find <mot>", "Cherche un Snap.", "Searches for a snap."),
        changer("sudo snap install <paquet>", "Installe un Snap.", "Installs a snap."),
        changer("sudo snap remove <paquet>", "Désinstalle un Snap.", "Removes a snap."),
        voir(
            "snap refresh --list",
            "Les snaps qui ont une mise à jour.",
            "Snaps that have an update.",
        ),
        changer(
            "sudo snap revert <paquet>",
            "Revient à la version d'avant d'un snap.",
            "Goes back to a snap's previous version.",
        ),
        voir(
            "snap changes",
            "Les dernières opérations des snaps.",
            "The latest snap operations.",
        ),
        voir(
            "snap connections <paquet>",
            "Les accès d'un snap : fichiers, caméra, réseau…",
            "A snap's permissions: files, camera, network…",
        ),
        voir(
            "snap info <paquet>",
            "Le détail d'un snap : éditeur, versions, canaux.",
            "A snap's details: publisher, versions, channels.",
        ),
        voir(
            "snap list --all | grep disabled",
            "Les anciennes versions gardées, qui prennent de la place.",
            "The old versions kept, which take space.",
        ),
        changer(
            "sudo snap set system refresh.retain=2",
            "N'en garde que deux par snap.",
            "Keeps only two per snap.",
        ),
    ],
};

/// AppArmor : le confinement des programmes de Debian et d'Ubuntu.
const APPARMOR: Programme = Programme {
    nom: "aa-status, aa-complain",
    role: ("AppArmor : protège les programmes", "AppArmor: program confinement"),
    executable: "aa-status",
    commandes: &[
        voir(
            "sudo aa-status",
            "Les profils AppArmor chargés, et les programmes qu'ils protègent.",
            "The loaded AppArmor profiles, and the programs they protect.",
        ),
        voir(
            "sudo journalctl -k | grep -i 'apparmor=\"DENIED\"' | tail",
            "Ce qu'AppArmor a refusé récemment.",
            "What AppArmor denied recently.",
        ),
        changer(
            "sudo aa-complain <programme>",
            "Laisse faire un programme en notant ce qui aurait été refusé (pour tester).",
            "Lets a program run while logging what would have been denied (for testing).",
        ),
        changer(
            "sudo aa-enforce <programme>",
            "Remet son profil en mode qui bloque.",
            "Puts its profile back in blocking mode.",
        ),
    ],
};

/// Les versions de Debian et d'Ubuntu, et les pilotes d'Ubuntu.
const VERSIONS: Programme = Programme {
    nom: "lsb_release, ubuntu-drivers",
    role: ("version, pilotes, PPA", "release, drivers, PPAs"),
    executable: "lsb_release",
    commandes: &[
        voir(
            "lsb_release -a",
            "La distribution et sa version.",
            "The distribution and its release.",
        ),
        voir(
            "cat /etc/debian_version",
            "La version de Debian (ou celle sur laquelle repose Ubuntu).",
            "The Debian release (or the one Ubuntu is based on).",
        ),
        voir(
            "do-release-upgrade -c",
            "Une nouvelle version d'Ubuntu est-elle disponible ?",
            "Is a new Ubuntu release available?",
        ),
        changer(
            "sudo do-release-upgrade",
            "Passe à la version suivante d'Ubuntu, après une mise à jour complète.",
            "Moves to the next Ubuntu release, after a full update.",
        ),
        voir(
            "ubuntu-drivers devices",
            "Les pilotes recommandés pour ce matériel (NVIDIA, Wi-Fi).",
            "The drivers recommended for this hardware (NVIDIA, Wi-Fi).",
        ),
        changer(
            "sudo ubuntu-drivers install",
            "Installe les pilotes recommandés.",
            "Installs the recommended drivers.",
        ),
        changer(
            "sudo add-apt-repository ppa:<nom>",
            "Ajoute un PPA, un dépôt de tiers : seulement s'il est connu et sûr.",
            "Adds a PPA, a third-party repository: only if it is known and safe.",
        ),
        changer(
            "sudo add-apt-repository --remove ppa:<nom>",
            "Retire un PPA.",
            "Removes a PPA.",
        ),
    ],
};

/// Les mises à jour de sécurité automatiques de Debian et d'Ubuntu.
const AUTO: Programme = Programme {
    nom: "unattended-upgrades",
    role: ("mises à jour automatiques", "automatic updates"),
    executable: "unattended-upgrade",
    commandes: &[
        voir(
            "systemctl status unattended-upgrades",
            "Le service des mises à jour automatiques tourne-t-il ?",
            "Is the automatic updates service running?",
        ),
        voir(
            "tail -30 /var/log/unattended-upgrades/unattended-upgrades.log",
            "Ce qu'il a installé dernièrement.",
            "What it installed lately.",
        ),
        voir(
            "sudo unattended-upgrade --dry-run --debug",
            "Ce qu'il installerait maintenant, sans rien faire.",
            "What it would install now, without doing anything.",
        ),
        changer(
            "sudo dpkg-reconfigure -plow unattended-upgrades",
            "Active les mises à jour de sécurité automatiques.",
            "Turns automatic security updates on.",
        ),
    ],
};

const NEEDRESTART: Programme = Programme {
    nom: "needrestart",
    role: ("services à relancer", "services to restart"),
    executable: "needrestart",
    commandes: &[voir(
        "sudo needrestart -r l",
        "Les services et le noyau à relancer après des mises à jour, sans rien relancer.",
        "Services and kernel to restart after updates, without restarting anything.",
    )],
};
