//! Guide : Arch Linux et ses dérivées (Manjaro, EndeavourOS) : pacman et l'AUR, leur entretien, le noyau, et les
//! marches à suivre. Omarchy reprend pacman et yay.

use super::{Programme, changer, voir};

pub const PROGRAMMES: &[Programme] = &[PACMAN, YAY, CONTRIB, NOYAU, super::linux::UFW, SBCTL];

/// Les marches à suivre : chaque étape est une commande expliquée, dans l'ordre.
pub const PAS_A_PAS: &[Programme] = &[
    Programme {
        nom: "Pas à pas : mettre à jour",
        role: ("pacman -Syu, AUR, .pacnew", "pacman -Syu, AUR, .pacnew"),
        executable: "pacman",
        commandes: &[
            voir(
                "yay -Pw",
                "D'abord les nouvelles d'Arch : certaines mises à jour demandent une action à la main.",
                "Arch news first: some updates need a manual action.",
            ),
            voir(
                "checkupdates",
                "Ce qui va changer, sans rien toucher.",
                "What will change, without touching anything.",
            ),
            changer(
                "sudo pacman -Syu",
                "Met tout à jour d'un coup. Jamais à moitié (pacman -Sy seul) : ça casse les dépendances.",
                "Updates everything at once. Never halfway (pacman -Sy alone): it breaks dependencies.",
            ),
            changer("yay -Sua", "Puis les paquets de l'AUR.", "Then the AUR packages."),
            voir(
                "pacdiff -o",
                "Les réglages .pacnew laissés par la mise à jour : à comparer avec les vôtres (sudo pacdiff).",
                "The .pacnew settings left by the update: to compare with yours (sudo pacdiff).",
            ),
            voir(
                "pacman -Q linux && uname -r",
                "Le noyau installé, puis celui qui tourne : s'ils diffèrent, redémarrez.",
                "The installed kernel, then the running one: if they differ, restart.",
            ),
            changer("systemctl reboot", "Redémarre pour finir.", "Restarts to finish."),
        ],
    },
    Programme {
        nom: "Pas à pas : installer",
        role: ("dépôts, Flatpak, puis l'AUR", "repositories, Flatpak, then AUR"),
        executable: "pacman",
        commandes: &[
            voir(
                "pacman -Ss <mot>",
                "Cherche d'abord dans les dépôts officiels.",
                "Searches the official repositories first.",
            ),
            voir(
                "pacman -Si <paquet>",
                "Ce que contient le paquet : version, taille, dépendances.",
                "What the package holds: version, size, dependencies.",
            ),
            changer("sudo pacman -S <paquet>", "L'installe.", "Installs it."),
            voir(
                "flatpak search <mot>",
                "Absent des dépôts ? Une application Flatpak, isolée du système.",
                "Not in the repositories? A Flatpak app, isolated from the system.",
            ),
            voir(
                "yay -Ss <mot>",
                "Sinon l'AUR : des paquets écrits par la communauté, sans contrôle d'Arch.",
                "Otherwise the AUR: packages written by the community, not checked by Arch.",
            ),
            voir(
                "yay -Gp <paquet>",
                "Lisez son PKGBUILD avant : c'est le script qui le construit sur votre ordinateur.",
                "Read its PKGBUILD first: it is the script that builds it on your machine.",
            ),
            changer("yay -S <paquet>", "Puis installez-le.", "Then install it."),
            changer(
                "sudo pacman -Rns <paquet>",
                "Pour le retirer, avec ses dépendances devenues inutiles.",
                "To remove it, with its dependencies no longer needed.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : faire de la place",
        role: ("cache de pacman, orphelins", "pacman cache, orphans"),
        executable: "pacman",
        commandes: &[
            voir(
                "df -h /",
                "La place libre sur le disque du système.",
                "Free space on the system disk.",
            ),
            voir(
                "du -sh /var/cache/pacman/pkg",
                "La place prise par les paquets téléchargés.",
                "Space taken by downloaded packages.",
            ),
            voir(
                "paccache -dk2",
                "Ce que le nettoyage retirerait : tout sauf les deux dernières versions.",
                "What cleaning would remove: everything but the two latest versions.",
            ),
            changer("sudo paccache -rk2", "Le fait.", "Does it."),
            voir(
                "pacman -Qdtq",
                "Les orphelins : installés comme dépendances, plus utilisés par rien.",
                "Orphans: installed as dependencies, no longer used by anything.",
            ),
            changer(
                "sudo pacman -Rns $(pacman -Qdtq)",
                "Les retire (relisez la liste avant).",
                "Removes them (read the list first).",
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
    Programme {
        nom: "Pas à pas : réparer",
        role: ("mise à jour ou démarrage ratés", "failed update or boot"),
        executable: "pacman",
        commandes: &[
            voir(
                "tail -40 /var/log/pacman.log",
                "Ce que pacman a fait en dernier : la mise à jour s'est-elle arrêtée en route ?",
                "What pacman did last: did the update stop halfway?",
            ),
            changer(
                "sudo pacman -Sy archlinux-keyring && sudo pacman -Su",
                "Erreur de signature (« invalid or corrupted package ») : renouvelle les clés, puis finit.",
                "Signature error (“invalid or corrupted package”): renews the keys, then finishes.",
            ),
            voir(
                "pgrep -a pacman",
                "« unable to lock database » : un pacman tourne-t-il ? Rien ne s'affiche : le verrou est un reste.",
                "“unable to lock database”: is a pacman running? Nothing shows: the lock is a leftover.",
            ),
            changer(
                "sudo rm /var/lib/pacman/db.lck",
                "Retire alors le verrou resté.",
                "Then removes the leftover lock.",
            ),
            changer(
                "sudo pacman -U /var/cache/pacman/pkg/<paquet>-<version>*.pkg.tar.zst",
                "Une mise à jour casse un programme : revenez à sa version d'avant, gardée dans le cache.",
                "An update breaks a program: go back to its previous version, kept in the cache.",
            ),
            changer(
                "mount /dev/<partition> /mnt",
                "Ne démarre plus ? Depuis la clé d'installation d'Arch, montez la partition du système…",
                "Won't boot? From the Arch install key, mount the system partition…",
            ),
            changer("arch-chroot /mnt", "…entrez dans votre système…", "…enter your system…"),
            changer(
                "pacman -Syu",
                "…finissez la mise à jour interrompue…",
                "…finish the interrupted update…",
            ),
            changer(
                "mkinitcpio -P",
                "…refaites l'image de démarrage, puis redémarrez.",
                "…rebuild the boot image, then restart.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : pare-feu",
        role: ("ufw : bloquer ce qui entre", "ufw: block what comes in"),
        executable: "pacman",
        commandes: &[
            voir(
                "sudo ufw status verbose",
                "Le pare-feu est-il là, et actif ?",
                "Is the firewall there, and active?",
            ),
            changer(
                "sudo pacman -S ufw",
                "L'installe s'il manque.",
                "Installs it if missing.",
            ),
            changer(
                "sudo ufw default deny incoming",
                "Refuse tout ce qui entre…",
                "Refuses everything coming in…",
            ),
            changer(
                "sudo ufw default allow outgoing",
                "…laisse sortir…",
                "…lets traffic out…",
            ),
            changer(
                "sudo ufw allow ssh",
                "…sauf ce que vous voulez ouvrir (ici SSH, si vous vous y connectez à distance).",
                "…except what you want to open (here SSH, if you connect remotely).",
            ),
            changer("sudo ufw enable", "Active le pare-feu.", "Turns the firewall on."),
            changer(
                "sudo systemctl enable --now ufw",
                "Et le garde au démarrage.",
                "And keeps it at boot.",
            ),
        ],
    },
    Programme {
        nom: "Pas à pas : NVIDIA",
        role: ("pilote de la carte graphique", "graphics card driver"),
        executable: "pacman",
        commandes: &[
            voir(
                "lspci -k | grep -A3 -iE 'vga|3d'",
                "La carte graphique, et le pilote qu'elle utilise maintenant.",
                "The graphics card, and the driver it uses now.",
            ),
            changer(
                "sudo pacman -S nvidia-open nvidia-utils",
                "Le pilote des cartes NVIDIA récentes (GTX 16xx, RTX) ; avec un autre noyau, nvidia-open-dkms.",
                "The driver for recent NVIDIA cards (GTX 16xx, RTX); with another kernel, nvidia-open-dkms.",
            ),
            changer(
                "sudo pacman -S lib32-nvidia-utils",
                "Pour les jeux 32 bits (Steam) : le dépôt multilib doit être activé.",
                "For 32-bit games (Steam): the multilib repository must be enabled.",
            ),
            changer(
                "sudo mkinitcpio -P",
                "Refait l'image de démarrage avec le pilote.",
                "Rebuilds the boot image with the driver.",
            ),
            changer("systemctl reboot", "Redémarre.", "Restarts."),
            voir(
                "nvidia-smi",
                "Le pilote marche-t-il ? La carte, sa mémoire, sa température, ce qui l'utilise.",
                "Does the driver work? The card, its memory, its temperature, what uses it.",
            ),
        ],
    },
];

/// Les paquets des dépôts officiels.
pub(super) const PACMAN: Programme = Programme {
    nom: "pacman",
    role: ("paquets : Arch, Manjaro, Omarchy", "packages: Arch, Manjaro, Omarchy"),
    executable: "pacman",
    commandes: &[
        changer(
            "sudo pacman -Syu",
            "Met tout le système à jour (sous Omarchy : omarchy update).",
            "Updates the whole system (on Omarchy: omarchy update).",
        ),
        changer("sudo pacman -S <paquet>", "Installe un paquet.", "Installs a package."),
        changer(
            "sudo pacman -Rns <paquet>",
            "Désinstalle un paquet et ses dépendances devenues inutiles.",
            "Removes a package and the dependencies it no longer needs.",
        ),
        voir(
            "pacman -Ss <mot>",
            "Cherche un paquet dans les dépôts.",
            "Searches the repositories for a package.",
        ),
        voir(
            "pacman -Qi <paquet>",
            "Un paquet installé : version, taille, dépendances.",
            "An installed package: version, size, dependencies.",
        ),
        voir(
            "pacman -Qo <fichier>",
            "Le paquet qui a installé ce fichier.",
            "The package that installed this file.",
        ),
        voir(
            "pacman -Qdtq",
            "Les paquets orphelins : installés pour un autre, plus utilisés.",
            "Orphan packages: installed for another one, no longer used.",
        ),
        voir(
            "pacman -Qm",
            "Les paquets installés hors des dépôts (AUR, à la main).",
            "Packages installed outside the repositories (AUR, by hand).",
        ),
        voir(
            "checkupdates",
            "Les mises à jour disponibles, sans rien installer (pacman-contrib).",
            "Available updates, installing nothing (pacman-contrib).",
        ),
        changer(
            "sudo paccache -rk2",
            "Garde les deux dernières versions des paquets téléchargés, efface les autres.",
            "Keeps the last two versions of downloaded packages, deletes the others.",
        ),
        changer(
            "sudo rm /var/lib/pacman/db.lck",
            "Débloque pacman après un arrêt brutal, seulement si aucun pacman ne tourne.",
            "Unlocks pacman after a crash, only if no pacman is running.",
        ),
        voir(
            "pacman -Si <paquet>",
            "Ce que contient un paquet des dépôts, avant de l'installer : version, taille, dépendances.",
            "What a repository package holds, before installing it: version, size, dependencies.",
        ),
        voir(
            "pacman -Ql <paquet>",
            "Les fichiers qu'un paquet a installés.",
            "The files a package installed.",
        ),
        voir(
            "pacman -Qe",
            "Les paquets installés exprès, sans leurs dépendances.",
            "Packages installed on purpose, without their dependencies.",
        ),
        voir(
            "pacman -Qu",
            "Les paquets qui ont une mise à jour, d'après la dernière synchronisation.",
            "Packages that have an update, according to the last sync.",
        ),
        voir(
            "pacman -F <fichier>",
            "Le paquet qui fournit un fichier, même s'il n'est pas installé (après sudo pacman -Fy).",
            "The package that provides a file, even if not installed (after sudo pacman -Fy).",
        ),
        changer(
            "sudo pacman -Fy",
            "Télécharge la liste des fichiers de tous les paquets, pour pacman -F.",
            "Downloads the file lists of all packages, for pacman -F.",
        ),
        voir(
            "sudo pacman -Qkk <paquet>",
            "Vérifie les fichiers d'un paquet : ce qui a été modifié ou manque.",
            "Checks a package's files: what was changed or is missing.",
        ),
        changer(
            "sudo pacman -U <fichier>",
            "Installe un paquet depuis un fichier, par exemple une version d'avant gardée dans /var/cache/pacman/pkg.",
            "Installs a package from a file, for example an earlier version kept in /var/cache/pacman/pkg.",
        ),
        voir(
            "tail -40 /var/log/pacman.log",
            "Les dernières opérations de pacman, datées : installé, mis à jour, retiré.",
            "pacman's latest operations, dated: installed, updated, removed.",
        ),
        changer(
            "sudo pacman -Sy archlinux-keyring && sudo pacman -Su",
            "Renouvelle les clés de signature, puis finit la mise à jour : la réponse aux erreurs de signature.",
            "Renews the signing keys, then finishes the update: the answer to signature errors.",
        ),
    ],
};

/// Les paquets de l'AUR.
pub(super) const YAY: Programme = Programme {
    nom: "yay",
    role: ("paquets de l'AUR (Arch)", "AUR packages (Arch)"),
    executable: "yay",
    commandes: &[
        changer(
            "yay",
            "Met à jour le système et les paquets de l'AUR.",
            "Updates the system and the AUR packages.",
        ),
        changer(
            "yay -S <paquet>",
            "Installe depuis l'AUR : lisez le PKGBUILD avant, personne ne l'a vérifié pour vous.",
            "Installs from the AUR: read the PKGBUILD first, nobody checked it for you.",
        ),
        voir(
            "yay -Ss <mot>",
            "Cherche dans les dépôts et dans l'AUR.",
            "Searches the repositories and the AUR.",
        ),
        changer(
            "yay -Yc",
            "Retire les dépendances devenues inutiles.",
            "Removes dependencies no longer needed.",
        ),
        voir(
            "yay -Pw",
            "Les nouvelles d'Arch : à lire avant une grosse mise à jour, certaines demandent une action.",
            "Arch news: read them before a big update, some need an action.",
        ),
        voir(
            "yay -Qua",
            "Les paquets de l'AUR qui ont une mise à jour.",
            "AUR packages that have an update.",
        ),
        changer(
            "yay -Sua",
            "Met à jour les paquets de l'AUR seulement.",
            "Updates the AUR packages only.",
        ),
        voir(
            "yay -Gp <paquet>",
            "Le PKGBUILD d'un paquet de l'AUR : le script qui le construit, à lire avant d'installer.",
            "An AUR package's PKGBUILD: the script that builds it, to read before installing.",
        ),
        voir(
            "yay -Ps",
            "Des statistiques : nombre de paquets, place prise, les plus gros.",
            "Statistics: number of packages, space used, the biggest ones.",
        ),
    ],
};

/// pacman-contrib et reflector : l'entretien de pacman.
const CONTRIB: Programme = Programme {
    nom: "paccache, pacdiff, reflector",
    role: ("cache, réglages, miroirs", "cache, settings, mirrors"),
    executable: "paccache",
    commandes: &[
        voir(
            "paccache -dk2",
            "Ce que le nettoyage du cache retirerait : tout sauf les deux dernières versions de chaque paquet.",
            "What cleaning the cache would remove: all but the two latest versions of each package.",
        ),
        changer(
            "sudo paccache -ruk0",
            "Retire du cache les paquets déjà désinstallés.",
            "Removes uninstalled packages from the cache.",
        ),
        changer(
            "sudo systemctl enable --now paccache.timer",
            "Nettoie le cache toute seule, chaque semaine.",
            "Cleans the cache by itself, every week.",
        ),
        voir(
            "pacdiff -o",
            "Les fichiers .pacnew et .pacsave laissés par les mises à jour : des réglages à comparer avec les vôtres.",
            "The .pacnew and .pacsave files left by updates: settings to compare with yours.",
        ),
        changer(
            "sudo pacdiff",
            "Les compare un par un (avec vim -d, ou le programme de DIFFPROG), pour garder, remplacer ou fusionner.",
            "Compares them one by one (with vim -d, or the DIFFPROG program), to keep, replace or merge.",
        ),
        voir(
            "cat /etc/pacman.d/mirrorlist",
            "Les miroirs utilisés, dans l'ordre.",
            "The mirrors in use, in order.",
        ),
        changer(
            "sudo reflector --latest 20 --sort rate --save /etc/pacman.d/mirrorlist",
            "Garde les 20 miroirs les plus rapides : des téléchargements plus vifs, moins d'erreurs de miroir.",
            "Keeps the 20 fastest mirrors: quicker downloads, fewer mirror errors.",
        ),
    ],
};

/// Le noyau et l'image de démarrage.
const NOYAU: Programme = Programme {
    nom: "mkinitcpio, linux-lts",
    role: ("noyau et démarrage", "kernel and boot"),
    executable: "mkinitcpio",
    commandes: &[
        voir(
            "pacman -Q linux && uname -r",
            "Le noyau installé, puis celui qui tourne : s'ils diffèrent, un redémarrage s'impose.",
            "The installed kernel, then the running one: if they differ, restart.",
        ),
        voir(
            "ls /boot",
            "Les noyaux et images de démarrage présents.",
            "The kernels and boot images present.",
        ),
        changer(
            "sudo mkinitcpio -P",
            "Refait l'image de démarrage de chaque noyau : après un changement de pilote ou de chiffrement.",
            "Rebuilds the boot image of every kernel: after a driver or encryption change.",
        ),
        changer(
            "sudo pacman -S linux-lts",
            "Installe un second noyau, au long cours : un secours si le noyau à jour ne démarre plus.",
            "Installs a second, long-term kernel: a fallback if the updated kernel no longer boots.",
        ),
    ],
};

const SBCTL: Programme = Programme {
    nom: "sbctl",
    role: ("Secure Boot sur Arch", "Secure Boot on Arch"),
    executable: "sbctl",
    commandes: &[
        voir(
            "sudo sbctl status",
            "Secure Boot : actif ou non, mode configuration, clés installées.",
            "Secure Boot: on or off, setup mode, keys installed.",
        ),
        voir(
            "sudo sbctl verify",
            "Les fichiers de démarrage : signés ou non.",
            "Boot files: signed or not.",
        ),
        changer(
            "sudo sbctl sign -s <fichier>",
            "Signe un fichier de démarrage, et le resignera à chaque mise à jour.",
            "Signs a boot file, and will sign it again at each update.",
        ),
    ],
};
