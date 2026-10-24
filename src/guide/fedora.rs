//! Guide : Fedora (et RHEL, Rocky, Alma) : dnf et rpm, SELinux, firewalld, les éditions atomiques, et les marches
//! à suivre.

use super::{Obstacle, Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[DNF, RPM, SELINUX, super::linux::FIREWALLD, OSTREE];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("dnf, Flatpak, firmware", "dnf, Flatpak, firmware"),
        executable: "dnf",
        commandes: &[
            voir("dnf check-upgrade", "Ce qui va changer.", "What will change."),
            changer(
                "sudo dnf upgrade --refresh",
                "Met tout le système à jour, listes des dépôts relues.",
                "Updates the whole system, repository lists reread.",
            ),
            voir(
                "flatpak remote-ls --updates",
                "Les applications Flatpak qui ont une mise à jour.",
                "Flatpak apps that have an update.",
            ),
            changer("flatpak update", "Les met à jour.", "Updates them."),
            voir(
                "fwupdmgr get-updates",
                "Des mises à jour du firmware (BIOS, disque, dock) ?",
                "Firmware updates (BIOS, disk, dock)?",
            ),
            changer("sudo fwupdmgr update", "Les installe.", "Installs them."),
            changer(
                "systemctl reboot",
                "Redémarre si le noyau a changé.",
                "Restarts if the kernel changed.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : nouvelle version",
        role: ("passer à la Fedora suivante", "move to the next Fedora"),
        executable: "dnf",
        commandes: &[
            voir("rpm -E %fedora", "Votre version de Fedora.", "Your Fedora release."),
            changer(
                "sudo dnf upgrade --refresh",
                "D'abord, tout à jour.",
                "First, everything up to date.",
            ),
            changer(
                "sudo dnf system-upgrade download --releasever=<numéro>",
                "Télécharge la version suivante (votre version + 1).",
                "Downloads the next release (your release + 1).",
            ),
            changer(
                "sudo dnf system-upgrade reboot",
                "Redémarre pour l'installer ; ne coupez pas l'ordinateur pendant.",
                "Restarts to install it; do not turn the computer off meanwhile.",
            ),
            changer(
                "sudo dnf distro-sync",
                "Après : aligne ce qui serait resté en arrière.",
                "Afterwards: aligns anything left behind.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : NVIDIA et codecs",
        role: ("RPM Fusion : pilote, vidéo", "RPM Fusion: driver, video"),
        executable: "dnf",
        commandes: &[
            voir(
                "lspci -k | grep -A3 -iE 'vga|3d'",
                "La carte graphique, et le pilote qu'elle utilise maintenant.",
                "The graphics card, and the driver it uses now.",
            ),
            voir(
                "xdg-open https://rpmfusion.org/Configuration",
                "Ouvre la page d'RPM Fusion, le dépôt des logiciels non libres : sa commande d'installation, à copier.",
                "Opens the RPM Fusion page, the repository of non-free software: its install command, to copy.",
            )
            .sauf(Obstacle::Fenetre),
            changer(
                "sudo dnf install akmod-nvidia",
                "Le pilote NVIDIA, depuis RPM Fusion.",
                "The NVIDIA driver, from RPM Fusion.",
            ),
            voir(
                "modinfo -F version nvidia",
                "Attendez qu'il soit construit (quelques minutes) : sa version s'affiche quand il est prêt.",
                "Wait until it is built (a few minutes): its version shows when it is ready.",
            ),
            changer(
                "sudo dnf swap ffmpeg-free ffmpeg --allowerasing",
                "Les codecs vidéo complets, depuis RPM Fusion.",
                "The full video codecs, from RPM Fusion.",
            ),
            changer("systemctl reboot", "Redémarre.", "Restarts."),
            voir(
                "nvidia-smi",
                "Le pilote marche-t-il ? La carte, sa mémoire, sa température.",
                "Does the driver work? The card, its memory, its temperature.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : SELinux",
        role: ("comprendre un refus", "understand a denial"),
        executable: "sestatus",
        commandes: &[
            voir(
                "getenforce",
                "SELinux bloque-t-il (Enforcing) ?",
                "Is SELinux blocking (Enforcing)?",
            ),
            voir(
                "sudo ausearch -m avc -ts recent",
                "Ce qu'il vient de refuser, et à quel programme.",
                "What it just denied, and to which program.",
            ),
            voir(
                "sudo sealert -a /var/log/audit/audit.log",
                "L'explication, et la correction proposée.",
                "The explanation, and the suggested fix.",
            ),
            changer(
                "sudo restorecon -Rv <dossier>",
                "Le plus souvent : de mauvaises étiquettes, à remettre.",
                "Most often: wrong labels, to restore.",
            ),
            changer(
                "sudo setsebool -P <nom> on",
                "Sinon, le réglage booléen que propose sealert.",
                "Otherwise, the boolean setting sealert suggests.",
            ),
            changer(
                "sudo setenforce 0",
                "Pour vérifier que c'est bien lui : permissif jusqu'au redémarrage, puis setenforce 1.",
                "To check it really is SELinux: permissive until restart, then setenforce 1.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : pare-feu",
        role: ("firewalld, par zones", "firewalld, by zones"),
        executable: "firewall-cmd",
        commandes: &[
            voir(
                "firewall-cmd --state",
                "Le pare-feu tourne-t-il ?",
                "Is the firewall running?",
            ),
            voir(
                "firewall-cmd --get-active-zones",
                "Les zones actives, et les cartes réseau de chacune.",
                "The active zones, and the network cards of each.",
            ),
            voir(
                "firewall-cmd --list-all",
                "Ce que la zone par défaut laisse entrer.",
                "What the default zone lets in.",
            ),
            changer(
                "sudo firewall-cmd --permanent --add-service=<service>",
                "Ouvre un service (ssh, samba…), pour de bon…",
                "Opens a service (ssh, samba…), for good…",
            ),
            changer("sudo firewall-cmd --reload", "…et l'applique.", "…and applies it."),
            changer(
                "sudo firewall-cmd --permanent --remove-service=<service>",
                "Referme un service.",
                "Closes a service again.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : faire de la place",
        role: ("dnf, Flatpak, journaux", "dnf, Flatpak, logs"),
        executable: "dnf",
        commandes: &[
            voir(
                "df -h /",
                "La place libre sur le disque du système.",
                "Free space on the system disk.",
            ),
            changer(
                "sudo dnf autoremove",
                "Retire les paquets devenus inutiles.",
                "Removes packages no longer needed.",
            ),
            changer("sudo dnf clean all", "Vide le cache de dnf.", "Empties dnf's cache."),
            changer(
                "flatpak uninstall --unused",
                "Retire les environnements Flatpak plus utilisés.",
                "Removes the Flatpak runtimes no longer used.",
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
            voir(
                "du -sh ~/.cache",
                "Le cache de vos programmes, souvent gros (navigateurs).",
                "Your programs' cache, often big (browsers).",
            ),
        ],
    },
];

/// Les paquets de Fedora.
const DNF: Programme = Programme {
    nom: "dnf",
    role: ("paquets : Fedora, RHEL", "packages: Fedora, RHEL"),
    executable: "dnf",
    commandes: &[
        changer(
            "sudo dnf upgrade --refresh",
            "Met tout le système à jour.",
            "Updates the whole system.",
        ),
        changer(
            "sudo dnf install <paquet>",
            "Installe un paquet.",
            "Installs a package.",
        ),
        changer(
            "sudo dnf remove <paquet>",
            "Désinstalle un paquet.",
            "Removes a package.",
        ),
        voir("dnf search <mot>", "Cherche un paquet.", "Searches for a package."),
        voir(
            "dnf provides <fichier>",
            "Le paquet qui fournit ce fichier.",
            "The package that provides this file.",
        ),
        voir(
            "dnf check-upgrade",
            "Les mises à jour disponibles.",
            "Available updates.",
        ),
        voir(
            "dnf history list",
            "L'historique des installations et des mises à jour.",
            "History of installs and updates.",
        ),
        changer(
            "sudo dnf history undo <numéro>",
            "Annule une opération de cet historique.",
            "Undoes an operation from that history.",
        ),
        changer(
            "sudo dnf autoremove",
            "Retire les paquets devenus inutiles.",
            "Removes packages no longer needed.",
        ),
        voir(
            "dnf info <paquet>",
            "Ce que contient un paquet : version, taille, dépôt, description.",
            "What a package holds: version, size, repository, description.",
        ),
        voir("dnf list --installed", "Les paquets installés.", "Installed packages."),
        voir("dnf repolist", "Les dépôts activés.", "Enabled repositories."),
        voir(
            "dnf updateinfo list --security",
            "Les mises à jour de sécurité en attente.",
            "Pending security updates.",
        ),
        changer(
            "sudo dnf upgrade --security",
            "N'installe que les mises à jour de sécurité.",
            "Installs the security updates only.",
        ),
        voir(
            "dnf needs-restarting -r",
            "Après des mises à jour : faut-il redémarrer, et à cause de quels paquets ?",
            "After updates: is a restart needed, and because of which packages?",
        ),
        voir(
            "dnf needs-restarting -s",
            "Les services à relancer, sans redémarrer tout l'ordinateur.",
            "The services to restart, without restarting the whole computer.",
        ),
        changer(
            "sudo dnf reinstall <paquet>",
            "Réinstalle un paquet abîmé.",
            "Reinstalls a damaged package.",
        ),
        changer(
            "sudo dnf downgrade <paquet>",
            "Revient à la version d'avant d'un paquet.",
            "Goes back to a package's previous version.",
        ),
        voir(
            "dnf history info <numéro>",
            "Le détail d'une opération de l'historique : ce qui a été installé, retiré, mis à jour.",
            "The details of a history operation: what was installed, removed, updated.",
        ),
        changer(
            "sudo dnf distro-sync",
            "Aligne chaque paquet sur la version des dépôts : répare après un mélange de dépôts.",
            "Aligns every package on the repository version: repairs after mixing repositories.",
        ),
        changer(
            "sudo dnf clean all",
            "Vide le cache de dnf, quand les dépôts semblent bloqués.",
            "Empties dnf's cache, when repositories seem stuck.",
        ),
        changer(
            "sudo dnf system-upgrade download --releasever=<numéro>",
            "Télécharge la prochaine version de Fedora (ex. 43), après une mise à jour complète.",
            "Downloads the next Fedora release (e.g. 43), after a full update.",
        ),
        changer(
            "sudo dnf system-upgrade reboot",
            "Redémarre pour l'installer : l'écran reste un moment noir, c'est normal.",
            "Restarts to install it: the screen stays black for a while, that is normal.",
        ),
    ],
};

/// rpm : les paquets installés, en détail.
const RPM: Programme = Programme {
    nom: "rpm",
    role: ("paquets installés, en détail", "installed packages, in detail"),
    executable: "rpm",
    commandes: &[
        voir(
            "rpm -qa | grep -i <mot>",
            "Les paquets installés dont le nom contient ce mot.",
            "Installed packages whose name contains this word.",
        ),
        voir(
            "rpm -qi <paquet>",
            "Le détail d'un paquet installé : version, date d'installation, origine.",
            "An installed package's details: version, install date, origin.",
        ),
        voir("rpm -ql <paquet>", "Les fichiers d'un paquet.", "A package's files."),
        voir(
            "rpm -qf <fichier>",
            "Le paquet auquel appartient un fichier.",
            "The package a file belongs to.",
        ),
        voir(
            "rpm -V <paquet>",
            "Vérifie un paquet : les fichiers modifiés depuis l'installation.",
            "Checks a package: the files changed since installation.",
        ),
        voir(
            "rpm -qa --last | head -20",
            "Les derniers paquets installés ou mis à jour, avec la date.",
            "The latest packages installed or updated, with the date.",
        ),
        voir(
            "rpm -E %fedora",
            "Le numéro de votre version de Fedora.",
            "Your Fedora release number.",
        ),
    ],
};

/// SELinux : la protection des services de Fedora.
const SELINUX: Programme = Programme {
    nom: "sestatus, ausearch",
    role: ("SELinux : protection des services", "SELinux: service protection"),
    executable: "sestatus",
    commandes: &[
        voir(
            "sestatus",
            "SELinux est-il actif, en mode « enforcing » (il bloque) ou « permissive » (il note seulement) ?",
            "Is SELinux on, in “enforcing” mode (it blocks) or “permissive” (it only logs)?",
        ),
        voir(
            "getenforce",
            "Le mode de SELinux, en un mot.",
            "SELinux's mode, in one word.",
        ),
        voir(
            "sudo ausearch -m avc -ts recent",
            "Ce que SELinux a bloqué récemment : souvent la cause d'une « permission refusée » inexpliquée.",
            "What SELinux blocked recently: often the cause of an unexplained “permission denied”.",
        ),
        voir(
            "sudo sealert -a /var/log/audit/audit.log",
            "Explique chaque refus et propose la correction (paquet setroubleshoot).",
            "Explains each denial and suggests the fix (setroubleshoot package).",
        ),
        voir(
            "ls -Z <fichier>",
            "L'étiquette SELinux d'un fichier : un fichier déplacé garde souvent la mauvaise.",
            "A file's SELinux label: a moved file often keeps the wrong one.",
        ),
        changer(
            "sudo restorecon -Rv <dossier>",
            "Remet les bonnes étiquettes dans un dossier : répare la plupart des refus.",
            "Restores the right labels in a folder: fixes most denials.",
        ),
        voir(
            "getsebool -a | grep <mot>",
            "Les réglages booléens de SELinux, et leur état.",
            "SELinux's boolean settings, and their state.",
        ),
        changer(
            "sudo setsebool -P <nom> on",
            "Active un réglage booléen pour de bon (ex. httpd_can_network_connect).",
            "Turns a boolean setting on for good (e.g. httpd_can_network_connect).",
        ),
        changer(
            "sudo setenforce 0",
            "Mode permissif jusqu'au redémarrage : pour vérifier que SELinux bloque, jamais pour de bon.",
            "Permissive mode until restart: to check whether SELinux blocks, never for good.",
        ),
        changer(
            "sudo setenforce 1",
            "Revient au mode qui bloque.",
            "Goes back to the blocking mode.",
        ),
    ],
};

/// Les éditions atomiques de Fedora (Silverblue, Kinoite) et leurs conteneurs.
const OSTREE: Programme = Programme {
    nom: "rpm-ostree, toolbox",
    role: ("éditions atomiques (Silverblue)", "atomic editions (Silverblue)"),
    executable: "rpm-ostree",
    commandes: &[
        voir(
            "rpm-ostree status",
            "Systèmes atomiques (Silverblue, Kinoite) : l'image en service et la précédente.",
            "Atomic systems (Silverblue, Kinoite): the image in use and the previous one.",
        ),
        changer(
            "sudo rpm-ostree upgrade",
            "Prépare l'image suivante, active au prochain démarrage.",
            "Prepares the next image, active at the next boot.",
        ),
        changer(
            "sudo rpm-ostree rollback",
            "Revient à l'image précédente au prochain démarrage.",
            "Goes back to the previous image at the next boot.",
        ),
        changer(
            "sudo rpm-ostree install <paquet>",
            "Ajoute un paquet au système, pris en compte au redémarrage.",
            "Adds a package to the system, applied at the next restart.",
        ),
        changer(
            "sudo rpm-ostree reset",
            "Retire tous les paquets ajoutés.",
            "Removes all the added packages.",
        ),
        voir("toolbox list", "Les conteneurs toolbox.", "The toolbox containers."),
        changer(
            "toolbox create",
            "Crée un conteneur où installer des outils avec dnf, sans toucher au système.",
            "Creates a container to install tools with dnf, without touching the system.",
        ),
        voir(
            "toolbox enter",
            "Y entre : un terminal où dnf marche comme d'habitude.",
            "Enters it: a terminal where dnf works as usual.",
        )
        .sauf(Obstacle::PleinEcran),
    ],
};
