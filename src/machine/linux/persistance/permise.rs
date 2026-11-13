//! La liste permise des lignes de démarrage (vérification 3) : Vanguard ne se tait que sur une ligne dont il
//! reconnaît ENTIÈREMENT la forme comme sûre. Le shell, systemd et Lua ont trop de façons de lancer un programme pour
//! toutes les nommer ; une liste de formes suspectes se contourne toujours. Ici, on décrit ce qui est sûr : une suite
//! de commandes simples faites de mots sans caractère actif du shell, dont chaque programme est un chemin absolu sûr
//! ou un nom trouvé dans les dossiers du système, chaque enveloppe connue (env, setsid, uwsm app --, terminal…) lue
//! par sa forme exacte, chaque argument sans chemin vers un dossier temporaire, caché ou relatif. Tout le reste est un
//! constat « non lue » (`Ecart`), jamais un silence. Un filet textuel (`filet`), indépendant de toute analyse, lève
//! aussi toute ligne dont le texte brut nomme un dossier temporaire ou caché.
//!
//! Pour une unité systemd du compte, chaque clé doit être dans une liste fermée par section (`directive`), ses
//! dépendances vers des unités nommées sans chemin ni code, ses variables et fichiers de variables vérifiés.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::*;

/// Une ligne plus longue ne se lit pas (vérification 3, S15 : le découpage d'une ligne géante prenait des minutes) :
/// constat, jamais silence.
pub(super) const LIGNE_MAX: usize = 8192;

/// Au plus autant de lignes l'une dans l'autre (« sh -c "… sh -c '…'" », lanceurs d'Omarchy qui en lancent un autre).
const PROFONDEUR_MAX: u32 = 6;

/// Les programmes à plusieurs noms (un seul fichier, l'outil choisi d'après le nom sous lequel il est lancé) qui
/// tiennent lieu d'env selon le système : coreutils (uutils, Ubuntu 25.10), busybox, toybox. Pas NixOS (W-7,
/// relecture 0.95) : /nix/store s'écrit par un groupe et rsync, findmnt n'y sont pas dans /usr/bin, la sauvegarde
/// y reste donc levée.
const MULTI_APPELS: [&str; 3] = ["coreutils", "busybox", "toybox"];

/// Un fichier de variables d'unité plus gros n'est pas une configuration : non vérifiable.
const VARIABLES_MAX: u64 = 1024 * 1024;

/// Pourquoi une ligne n'entre pas dans la liste permise : la raison de son constat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ecart {
    /// Le texte brut nomme un dossier temporaire ou caché (`filet`).
    Filet,
    /// Une forme du shell ou de systemd hors de la liste : tube, redirection, sous-commande, joker, variable, bloc,
    /// commande interne du shell, guillemet non fermé.
    Forme,
    /// Un programme qui n'est ni un chemin absolu sûr ni un nom trouvé dans les dossiers du système.
    Programme,
    /// Un programme qui en lance un autre d'une façon que Vanguard ne lit pas.
    Lanceur,
    /// Une variable sans valeur connue, ou une variable qui change ce qui se lance.
    Variable,
    /// Un chemin relatif ou caché en argument (« ./ », « ../ », « .x/ »).
    Chemin,
    /// Une ligne trop longue (`LIGNE_MAX`).
    Longue,
    /// Une clé d'unité hors de la liste, ou une valeur qui ne se vérifie pas.
    Directive,
    /// Un fichier de variables d'unité qui ne se lit pas entier.
    Fichier,
    /// La sauvegarde de Vanguard à sa forme exacte, mais sa destination (ou un dossier entre le disque et elle) est un
    /// lien, n'est pas un dossier ou n'est pas sur le disque : rsync écrirait ailleurs (relecture 0.94, C-2).
    Destination,
    /// La sauvegarde de Vanguard à sa forme exacte, mais sa destination ne se voit pas (disque débranché, dossier
    /// absent ou illisible) : où elle écrira n'est pas vérifié (relecture 0.94, C-2).
    DestinationNonVue,
    /// La sauvegarde de Vanguard à sa forme exacte, mais un fichier de réglages de popt du compte (~/.popt) est là,
    /// est un lien ou ne se lit pas : rsync le lit au départ, et une ligne « rsync exec -a … » lui fait lancer un
    /// autre programme à la place de la copie (D-1).
    Popt,
    /// La sauvegarde de Vanguard à sa forme exacte, mais un fichier de réglages de popt du système (/etc/popt,
    /// /usr/etc/popt, un dossier popt.d non vide) est là sans être à root seul (`de_root_seul`) : le compte, ou ce qui
    /// tourne sous lui, peut y faire lancer un autre programme à rsync (D-1).
    PoptDuSysteme,
    /// Une information, pas un constat : la sauvegarde de Vanguard à sa forme exacte, un fichier de réglages de popt
    /// du système là et à root seul. rsync le lit ; ce qu'il lui fait faire n'est pas vérifié, et seul root l'écrit.
    PoptDuSystemeARoot,
    /// Une information, pas un constat : la sauvegarde de Vanguard à sa forme exacte, son disque débranché (rien n'est
    /// monté à sa racine). Sa destination n'est pas vue ; rien ne se copie sans le disque (sa condition `findmnt`) ;
    /// elle se revoit au prochain bilan disque branché.
    DisqueDebranche,
    /// La sauvegarde de Vanguard à sa forme exacte, mais un complément du compte (« vanguard-sauvegarde.service.d »,
    /// « service.d »…) s'y ajoute : il peut changer son environnement (HOME, donc le ~/.popt que lit rsync) ou ce
    /// qu'elle lance (D-1).
    Complement,
    /// La sauvegarde de Vanguard à sa forme exacte, mais un fichier de variables du gestionnaire de systemd du compte
    /// (environment.d, user.conf et ses compléments, pam_env, uwsm), que le compte peut écrire, nomme HOME ou une
    /// variable que lisent rsync, findmnt ou le chargeur de programmes, ou ne se lit pas : HOME changé fait lire à
    /// rsync un autre ~/.popt (relecture 0.94, F-1).
    Environnement,
    /// Une information, pas un constat : la sauvegarde de Vanguard à la forme exacte de la 0.94, sans « env -i ».
    /// rsync et findmnt y gardent l'environnement du gestionnaire de session, dont ce qui est posé en cours de
    /// session sans fichier (`systemctl --user set-environment`) : pas vérifié. La remettre la pose sous la forme
    /// de la 0.95.
    AncienneForme,
    /// La sauvegarde de Vanguard à sa forme exacte, mais son rsync, son findmnt ou son env n'est pas un programme que
    /// seul root peut changer (`programme_de_root_seul`) : un fichier du compte qui porte leur nom (relecture 0.94,
    /// F-4).
    ProgrammeDuCompte,
    /// La sauvegarde de Vanguard à sa forme exacte, mais ce qui est monté à la racine de son disque est un système de
    /// fichiers FUSE (« fuse », « fuse.* ») : un programme du compte peut le poser lui-même sur ce dossier, sous un nom
    /// de source qui imite le disque attendu par findmnt, et il écrit où il veut (relecture 0.94, D-3).
    DisqueFuse,
    /// La sauvegarde de Vanguard à sa forme exacte, mais le disque monté à sa racine est une image (périphérique
    /// boucle, directement, sous un chiffrement ou en partition) adossée à un fichier que le compte peut changer : udisks
    /// la monte sans droits d'administrateur, sous le nom de disque attendu (relecture 0.95, V-7).
    DisqueImage,
    /// Un argument nomme un lieu de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.bashrc…) ou un
    /// dossier qui en contient (~/.config) : la ligne peut y copier, déplacer ou lier un lancement à chaque passage
    /// (« cp -r … ~/.config/autostart ») ; ce qu'elle y pose ne se voit qu'après (point 12, 0.95).
    LieuDeDemarrage,
    /// Un argument mène à un fichier du compte à plusieurs liens physiques, et son autre nom n'a pas pu être cherché
    /// dans les lieux de démarrage du compte, pour la raison donnée (A-3, revérification 6 : la cause se dit).
    AutreNomNonCherche(LieuxNonLus),
    /// Un argument relatif, et le dossier de départ de la ligne (WorkingDirectory=, Path=) ne se résout pas : le
    /// fichier qu'il vise n'est pas vérifié, et peut être un lieu de démarrage du compte (B-2, revérification 7 :
    /// la vraie raison se dit, avec l'argument, `Systeme::raison_dite`).
    DossierDeDepart,
}

/// A-3 (revérification 6) : pourquoi les lieux de démarrage du compte n'ont pas pu être lus en entier pour y chercher
/// l'autre nom d'un fichier à plusieurs liens physiques (`Systeme::noms_des_lieux`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LieuxNonLus {
    /// Plus de `NOMS_LUS_MAX` entrées.
    Entrees,
    /// Un dossier plus profond que `PROFONDEUR_DES_LIEUX`.
    Profondeur,
    /// Une lecture qui échoue autrement que par une absence (droits, lien en boucle, disque).
    Lecture,
    /// Un lien absolu sous une racine d'essai : il se suivrait hors d'elle (Z-3).
    HorsRacine,
}

impl Ecart {
    /// Une information, pas un constat : la ligne entre dans la liste permise, ce qui n'a pas été vu se dit à part.
    pub(super) fn information(self) -> bool {
        matches!(
            self,
            Ecart::DisqueDebranche | Ecart::PoptDuSystemeARoot | Ecart::AncienneForme
        )
    }

    /// La raison du constat, telle qu'elle se montre.
    pub(super) fn raison(self) -> &'static str {
        match self {
            Ecart::Filet => tr!(
                "ligne qui nomme un dossier temporaire ou caché (/tmp, /dev/shm, /run/user, ~/.x, ./, ../, %t…) : ce qu'elle lance de là n'est pas vérifié",
                "line naming a temporary or hidden folder (/tmp, /dev/shm, /run/user, ~/.x, ./, ../, %t…): what it starts from there is not checked"
            ),
            Ecart::Forme => tr!(
                "ligne non lue : sa forme (tube, redirection, sous-commande, joker, variable, bloc ou commande interne du shell) n'est pas une forme que Vanguard reconnaît comme sûre ; ce qu'elle lance n'est pas vérifié",
                "line not read: its form (pipe, redirection, substitution, wildcard, variable, block or shell builtin) is not one Vanguard recognises as safe; what it starts is not checked"
            ),
            Ecart::Programme => tr!(
                "ligne non lue : un programme qu'elle lance n'est ni un chemin absolu sûr ni un programme trouvé dans les dossiers du système ; ce qui se lance n'est pas vérifié",
                "line not read: a program it starts is neither a safe absolute path nor a program found in the system folders; what starts is not checked"
            ),
            Ecart::Lanceur => tr!(
                "ligne non lue : un programme qu'elle lance en lance un autre d'une façon que Vanguard ne lit pas (lanceur, interpréteur, terminal ou option inconnue) ; ce qui se lance n'est pas vérifié",
                "line not read: a program it starts launches another in a way Vanguard does not read (launcher, interpreter, terminal or unknown option); what starts is not checked"
            ),
            Ecart::Variable => tr!(
                "ligne non lue : une variable sans valeur connue, ou qui change ce qui se lance (HOME, PATH, LD_*, BASH_ENV…) ; ce qui se lance n'est pas vérifié",
                "line not read: a variable without a known value, or one that changes what starts (HOME, PATH, LD_*, BASH_ENV…); what starts is not checked"
            ),
            Ecart::Chemin => tr!(
                "ligne non lue : un chemin relatif (« ./ », « ../ », « .x/ », lu depuis le dossier courant) ; ce qui se lance n'est pas vérifié",
                "line not read: a relative path (“./”, “../”, “.x/”, read from the current folder); what starts is not checked"
            ),
            Ecart::Longue => tr!(
                "ligne non lue : trop longue pour être lue (plus de 8192 caractères) ; ce qu'elle lance n'est pas vérifié",
                "line not read: too long to be read (more than 8192 characters); what it starts is not checked"
            ),
            Ecart::Directive => tr!(
                "réglage d'unité non lu : clé hors de la liste de ce que Vanguard reconnaît comme sûr, ou valeur qui ne se vérifie pas (section, dépendance, entrée ou sortie, variable) ; ce qu'il change n'est pas vérifié",
                "unit setting not read: key outside the list of what Vanguard recognises as safe, or a value that cannot be checked (section, dependency, input or output, variable); what it changes is not checked"
            ),
            Ecart::Fichier => tr!(
                "fichier de variables d'unité non vérifiable (joker, chemin relatif, illisible ou trop gros) : les variables qu'il pose ne sont pas vérifiées",
                "unit environment file cannot be checked (wildcard, relative path, unreadable or too large): the variables it sets are not checked"
            ),
            Ecart::Destination => tr!(
                "sauvegarde de Vanguard dont le dossier de destination sur le disque est un lien, passe par un lien ou mène hors du disque : rsync copierait ailleurs que sur le disque ; où elle copie n'est pas vérifié",
                "Vanguard backup whose destination folder on the disk is a link, goes through a link or leads off the disk: rsync would copy somewhere other than the disk; where it copies is not checked"
            ),
            Ecart::DestinationNonVue => tr!(
                "sauvegarde de Vanguard dont le dossier de destination ne se voit pas (disque débranché, dossier absent ou illisible) : s'il est un lien, non vérifié ; brancher le disque, puis refaire le bilan",
                "Vanguard backup whose destination folder cannot be seen (disk unplugged, folder missing or unreadable): whether it is a link, not checked; plug the disk in, then run the check again"
            ),
            Ecart::Popt => tr!(
                "sauvegarde de Vanguard alors qu'un fichier ~/.popt est là (ou un lien, ou illisible) : rsync le lit au départ, et une ligne « rsync exec … » y lui fait lancer un autre programme à la place de la copie ; ce que lance la sauvegarde n'est pas vérifié",
                "Vanguard backup while a ~/.popt file is present (or a link, or unreadable): rsync reads it at start, and a “rsync exec …” line in it makes it start another program instead of the copy; what the backup starts is not checked"
            ),
            Ecart::PoptDuSysteme => tr!(
                "sauvegarde de Vanguard non vérifiée : un fichier de réglages de popt du système qui n'est pas à root seul est là (/etc/popt, /usr/etc/popt ou un dossier popt.d non vide) ; rsync le lit au départ, et une ligne « rsync exec … » y lui fait lancer un autre programme",
                "Vanguard backup not checked: a system popt settings file that is not root-only is present (/etc/popt, /usr/etc/popt or a non-empty popt.d folder); rsync reads it at start, and a “rsync exec …” line in it makes it start another program"
            ),
            Ecart::PoptDuSystemeARoot => tr!(
                "sauvegarde de Vanguard reconnue, mais un fichier de réglages de popt du système (à root) est là (/etc/popt, /usr/etc/popt ou popt.d) : rsync le lit au départ, et ce qu'il lui fait faire est non vérifié",
                "Vanguard backup recognised, but a system popt settings file (root's) is present (/etc/popt, /usr/etc/popt or popt.d): rsync reads it at start, and what it makes rsync do is not checked"
            ),
            Ecart::DisqueDebranche => tr!(
                "sauvegarde de Vanguard reconnue, disque débranché : sa destination n'a pas été vue (rien ne se copie sans le disque : la sauvegarde vérifie d'abord qu'il est monté) ; elle sera revue au prochain bilan, disque branché",
                "Vanguard backup recognised, disk unplugged: its destination was not seen (nothing is copied without the disk: the backup first checks that it is mounted); it will be checked again at the next check, disk plugged in"
            ),
            Ecart::Complement => tr!(
                "sauvegarde de Vanguard changée par un complément du compte (dossier « .service.d ») : il peut changer son environnement (HOME, donc le ~/.popt que lit rsync) ou ce qu'elle lance ; ce n'est plus la forme que Vanguard pose",
                "Vanguard backup changed by an account drop-in (“.service.d” folder): it can change its environment (HOME, hence the ~/.popt rsync reads) or what it starts; it is no longer the form Vanguard sets up"
            ),
            Ecart::AncienneForme => tr!(
                "sauvegarde de Vanguard posée avant la 0.95 : rsync et findmnt y gardent les variables de la session, dont celles posées en cours de session, que le bilan ne voit pas ; non vérifié. Pour la forme qui les vide (« env -i »), annulez-la puis remettez-la : « vanguard sauvegarde-auto »",
                "Vanguard backup set up before 0.95: rsync and findmnt keep the session variables there, including those set during the session, which the check cannot see; not verified. For the form that clears them (“env -i”), undo it then set it up again: “vanguard auto-backup”"
            ),
            Ecart::ProgrammeDuCompte => tr!(
                "sauvegarde de Vanguard dont rsync, findmnt ou env n'est pas un programme que seul root peut changer (un fichier du compte, ou dans un dossier qu'il peut écrire, qui porte leur nom) : ce que lance la sauvegarde n'est pas vérifié",
                "Vanguard backup whose rsync, findmnt or env is not a program only root can change (a file of the account, or in a folder it can write, bearing their name): what the backup starts is not checked"
            ),
            Ecart::DisqueFuse => tr!(
                "sauvegarde de Vanguard dont le disque est un montage FUSE (un montage qu'un programme du compte peut poser lui-même à la place du disque) : où rsync copie n'est pas vérifié",
                "Vanguard backup whose disk is a FUSE mount (a mount an account program can set up itself in place of the disk): where rsync copies is not checked"
            ),
            Ecart::DisqueImage => tr!(
                "sauvegarde de Vanguard dont le disque est une image (périphérique boucle) adossée à un fichier que le compte peut changer (udisks la monte sans droits d'administrateur, sous le nom du disque attendu) : où rsync copie n'est pas vérifié",
                "Vanguard backup whose disk is an image (loop device) backed by a file the account can change (udisks mounts it without admin rights, under the expected disk name): where rsync copies is not checked"
            ),
            Ecart::LieuDeDemarrage => tr!(
                "ligne qui nomme un lieu de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) ou un dossier qui en contient (~/.config), écrit tel quel, relatif à son dossier courant ou par un lien qui y mène, ou dont un chemin ne se suit pas avec certitude (lien ou dossier illisible, passage par /proc, fichier dont un autre nom (lien physique) est dans un tel lieu, variable inconnue, trop de séparateurs) : elle peut y copier, déplacer ou lier un lancement à chaque passage ; ce qu'elle y pose n'est pas vérifié, donc pas passé sous silence (limite : une copie sur le dossier personnel entier n'est pas comptée)",
                "line naming an account startup place (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) or a folder holding one (~/.config), written as is, relative to its working folder or through a link leading there, or with a path that cannot be followed with certainty (unreadable link or folder, a pass through /proc, a file whose other name (hard link) is in such a place, unknown variable, too many separators): it can copy, move or link a launch there on every run; what it puts there is not checked, so not kept quiet (limit: a copy onto the whole home folder is not counted)"
            ),
            Ecart::DossierDeDepart => tr!(
                "dossier de départ (WorkingDirectory= ou Path=) non vérifié : un argument relatif peut viser un autre fichier, dont un lieu de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.bashrc…) ; non vérifié, donc pas passé sous silence",
                "working folder (WorkingDirectory= or Path=) not verified: a relative argument can point to another file, including an account startup place (~/.config/autostart, ~/.config/systemd, ~/.bashrc…); not verified, so not kept quiet"
            ),
            Ecart::AutreNomNonCherche(LieuxNonLus::Entrees) => tr!(
                "ligne dont un chemin mène à un fichier du compte qui a un autre nom (lien physique) ; cet autre nom n'a pas pu être cherché dans les lieux de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) : ils comptent plus de 4096 entrées. S'il y est, la ligne peut y écrire un lancement à chaque passage ; non vérifié, donc pas passé sous silence",
                "line with a path leading to an account file that has another name (hard link); that other name could not be looked for in the account startup places (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…): they hold more than 4096 entries. If it is there, the line can write a launch there on every run; not verified, so not kept quiet"
            ),
            Ecart::AutreNomNonCherche(LieuxNonLus::Profondeur) => tr!(
                "ligne dont un chemin mène à un fichier du compte qui a un autre nom (lien physique) ; cet autre nom n'a pas pu être cherché dans les lieux de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) : un dossier y est à plus de 8 niveaux de profondeur. S'il y est, la ligne peut y écrire un lancement à chaque passage ; non vérifié, donc pas passé sous silence",
                "line with a path leading to an account file that has another name (hard link); that other name could not be looked for in the account startup places (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…): a folder there is more than 8 levels deep. If it is there, the line can write a launch there on every run; not verified, so not kept quiet"
            ),
            Ecart::AutreNomNonCherche(LieuxNonLus::Lecture) => tr!(
                "ligne dont un chemin mène à un fichier du compte qui a un autre nom (lien physique) ; cet autre nom n'a pas pu être cherché dans les lieux de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) : une entrée ne s'y lit pas (droits, lien en boucle, erreur du disque). S'il y est, la ligne peut y écrire un lancement à chaque passage ; non vérifié, donc pas passé sous silence",
                "line with a path leading to an account file that has another name (hard link); that other name could not be looked for in the account startup places (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…): an entry there cannot be read (permissions, link loop, disk error). If it is there, the line can write a launch there on every run; not verified, so not kept quiet"
            ),
            Ecart::AutreNomNonCherche(LieuxNonLus::HorsRacine) => tr!(
                "ligne dont un chemin mène à un fichier du compte qui a un autre nom (lien physique) ; cet autre nom n'a pas pu être cherché dans les lieux de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…) : un lien absolu y mène hors de l'arborescence examinée. S'il y est, la ligne peut y écrire un lancement à chaque passage ; non vérifié, donc pas passé sous silence",
                "line with a path leading to an account file that has another name (hard link); that other name could not be looked for in the account startup places (~/.config/autostart, ~/.config/systemd, ~/.config/hypr, ~/.bashrc…): an absolute link there leads outside the examined tree. If it is there, the line can write a launch there on every run; not verified, so not kept quiet"
            ),
            Ecart::Environnement => tr!(
                "sauvegarde de Vanguard : un fichier de variables de la session du compte (~/.config/environment.d, ~/.config/systemd/user.conf, ~/.pam_environment, ~/.config/uwsm/env…) nomme HOME ou une variable que lisent rsync, findmnt ou le chargeur de programmes (LD_*, RSYNC_*, POPT*, LIBMOUNT_*, BLKID_*…), ou le cache (inclusion d'un autre fichier, nom construit, « eval »), ou ne se lit pas : il peut changer ce que la sauvegarde lit ou lance (un autre ~/.popt) ; non vérifié, donc pas passé sous silence",
                "Vanguard backup: an account session variable file (~/.config/environment.d, ~/.config/systemd/user.conf, ~/.pam_environment, ~/.config/uwsm/env…) names HOME or a variable read by rsync, findmnt or the program loader (LD_*, RSYNC_*, POPT*, LIBMOUNT_*, BLKID_*…), or hides it (inclusion of another file, built name, “eval”), or cannot be read: it can change what the backup reads or starts (another ~/.popt); not verified, so not kept quiet"
            ),
        }
    }
}

/// Y-3, A-3 : les noms des fichiers à plusieurs liens physiques des lieux de démarrage du compte, par (appareil,
/// inode), ou pourquoi ils n'ont pas pu être lus en entier.
pub(super) type NomsDesLieux = Result<NomsLus, LieuxNonLus>;

/// Y-3 : les noms lus, par (appareil, inode).
pub(super) type NomsLus = std::collections::HashMap<(u64, u64), String>;

/// Où chercher les programmes et les fichiers : la racine lue (une arborescence fabriquée dans les essais), le dossier
/// personnel lu (« ~ », « $HOME ») et les dossiers personnels où un dossier caché se juge (`chemin_cache_chez`).
pub(super) struct Systeme<'a> {
    pub(super) racine: &'a Path,
    pub(super) maison: &'a str,
    pub(super) maisons: &'a [&'a str],
    /// Le dossier courant de la ligne, d'où se lit un argument relatif (X-3) : `None`, le dossier personnel (une
    /// unité du compte sans WorkingDirectory=, Hyprland) ; sinon un chemin écrit (« / », « ~/x », « /x »), ou un
    /// texte qui ne se résout pas (`CODE_INCONNU`) : un relatif n'y est alors pas vérifié.
    pub(super) courant: Option<&'a str>,
    /// Y-3 : les fichiers à plusieurs liens physiques des lieux de démarrage du compte, par (appareil, inode), et un
    /// de leurs noms ; lus une fois, au premier fichier à deux noms rencontré (`noms_des_lieux`).
    pub(super) noms_des_lieux: std::cell::OnceCell<NomsDesLieux>,
    /// B-2 (revérification 7) : le premier argument relatif jugé depuis un dossier de départ inconnu
    /// (`Ecart::DossierDeDepart`), que la raison nomme (`raison_dite`).
    pub(super) relatif: std::cell::OnceCell<String>,
}

/// Les dossiers où un nom de programme nu se cherche : le PATH par défaut du système (jamais celui de la ligne), et
/// les exports de Flatpak.
const DOSSIERS_SYSTEME: [&str; 7] = [
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
    "/var/lib/flatpak/exports/bin",
];

/// Les dossiers du compte qu'une session met d'ordinaire dans le PATH (programmes du compte, Omarchy installé par
/// git, Rust) : visibles, non cachés au sens de `DOSSIERS_CACHES_NORMAUX`.
const DOSSIERS_DU_COMPTE: [&str; 4] = [
    ".local/bin",
    ".local/share/omarchy/bin",
    ".cargo/bin",
    ".local/share/flatpak/exports/bin",
];

impl Systeme<'_> {
    /// Un chemin absolu de l'ordinateur, lu sous la racine (le dossier personnel y est déjà).
    fn sous(&self, chemin: &str) -> std::path::PathBuf {
        let p = Path::new(chemin);
        if self.racine.as_os_str().is_empty() || self.racine == Path::new("/") || p.starts_with(self.racine) {
            p.to_path_buf()
        } else {
            self.racine.join(p.strip_prefix("/").unwrap_or(p))
        }
    }

    /// Un fichier (exécutable, si demandé) à ce chemin absolu.
    fn fichier(&self, chemin: &str, executable: bool) -> bool {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(self.sous(chemin))
            .is_ok_and(|m| m.is_file() && (!executable || m.permissions().mode() & 0o111 != 0))
    }

    /// Un dossier à ce chemin absolu.
    fn dossier(&self, chemin: &str) -> bool {
        std::fs::metadata(self.sous(chemin)).is_ok_and(|m| m.is_dir())
    }

    /// Un nom nu de programme trouvé dans les dossiers du système ou du compte (`DOSSIERS_SYSTEME`,
    /// `DOSSIERS_DU_COMPTE`).
    fn trouve(&self, nom: &str) -> bool {
        if nom.is_empty() || nom.contains('/') || nom == "." || nom == ".." {
            return false;
        }
        DOSSIERS_SYSTEME
            .iter()
            .any(|d| self.fichier(&format!("{d}/{nom}"), true))
            || DOSSIERS_DU_COMPTE
                .iter()
                .any(|d| self.fichier(&format!("{}/{d}/{nom}", self.maison), true))
    }

    /// Un chemin absolu, simplifié, hors d'un dossier temporaire, caché ou de /proc ; sinon l'écart.
    fn chemin_sur(&self, p: &str, argument: bool) -> Result<String, Ecart> {
        if !p.starts_with('/') {
            return Err(Ecart::Chemin);
        }
        let simple = chemin_simplifie(p);
        if simple.starts_with("/proc/") || simple == "/proc" || self.cache(&simple, argument) {
            return Err(Ecart::Filet);
        }
        Ok(simple)
    }

    /// Un chemin (absolu, « ~/… », « $HOME/… », « %h/… ») dans un dossier temporaire ou caché ; un dossier (« / » en
    /// fin, ou existant) se juge par ce qu'il contient.
    fn cache(&self, p: &str, argument: bool) -> bool {
        if cache_ou_temporaire(p, self.maisons, argument) {
            return true;
        }
        let dossier = p.ends_with('/') || (p.starts_with('/') && self.dossier(&chemin_simplifie(p)));
        dossier && cache_ou_temporaire(&format!("{}/x", p.trim_end_matches('/')), self.maisons, argument)
    }

    /// Le programme d'une commande : un chemin absolu sûr (hors d'un dossier temporaire, caché ou de /proc), ou un nom
    /// nu trouvé. Un chemin absolu absent ne lance rien aujourd'hui ; le jour où il existe, les règles d'avant lisent
    /// son contenu (`designes`) au bilan suivant : il n'est pas « non lu ». Un dossier, lui, n'est pas un programme.
    fn programme(&self, p: &str) -> Result<(), Ecart> {
        if p.contains('/') {
            let simple = self.chemin_sur(p, false)?;
            return if self.dossier(&simple) {
                Err(Ecart::Programme)
            } else {
                Ok(())
            };
        }
        if self.trouve(p) { Ok(()) } else { Err(Ecart::Programme) }
    }

    /// Le dossier `destination` d'un disque monté à `racine` sous /run/media, /media ou /mnt (deux chemins nets,
    /// `sauvegarde::sauvegarde_posee`), vu sans détour : chaque dossier sous /run/media, /media ou /mnt jusqu'à lui
    /// existe et n'est pas un lien, et ceux sous le disque sont sur le même système de fichiers que lui (un montage
    /// posé par le compte, FUSE, y mènerait ailleurs comme un lien). Sinon `Ecart::Destination` ; un dossier qui ne
    /// se voit pas (disque débranché, absent, illisible) : `Ecart::DestinationNonVue`, jamais un silence.
    ///
    /// Débranché (`Ecart::DisqueDebranche`, une information) : un dossier jusqu'à la racine du disque comprise
    /// n'existe pas (rien ne peut y être monté), ou la racine existe mais n'est le point de montage de rien
    /// (`/proc/self/mountinfo` lu en entier) et un dossier sous elle n'existe pas. Monté, ou montage qui ne se lit pas,
    /// et un dossier qui ne se voit pas : `Ecart::DestinationNonVue`, levé.
    fn destination_sur_le_disque(&self, racine: &str, destination: &str) -> Result<(), Ecart> {
        use std::os::unix::fs::MetadataExt as _;
        let base = ["/run/media/", "/media/", "/mnt/"]
            .into_iter()
            .find(|b| racine.starts_with(b))
            .ok_or(Ecart::Destination)?;
        let sous_le_disque = destination
            .strip_prefix(racine)
            .and_then(|r| r.strip_prefix('/'))
            .ok_or(Ecart::Destination)?;
        let jusqu_au_disque = racine.strip_prefix(base).ok_or(Ecart::Destination)?;
        let mut chemin = base.trim_end_matches('/').to_string();
        let mut disque = None;
        for m in jusqu_au_disque.split('/').chain(sous_le_disque.split('/')) {
            chemin.push('/');
            chemin.push_str(m);
            let lu = match std::fs::symlink_metadata(self.sous(&chemin)) {
                Ok(lu) => lu,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.debranche(racine, &chemin) => {
                    return Err(Ecart::DisqueDebranche);
                }
                Err(_) => return Err(Ecart::DestinationNonVue),
            };
            if lu.file_type().is_symlink() || !lu.is_dir() {
                return Err(Ecart::Destination);
            }
            match disque {
                None if chemin == racine => disque = Some(lu.dev()),
                Some(d) if lu.dev() != d => return Err(Ecart::Destination),
                _ => {}
            }
        }
        disque.ok_or(Ecart::Destination)?;
        self.disque_monte(racine)
    }

    /// Ce qui est monté à `racine`, d'après /proc/self/mountinfo lu en entier : le dernier montage posé à ce point,
    /// celui qu'on voit (D-3). FUSE (« fuse », « fuse.* ») : `Ecart::DisqueFuse`, levé ; « fuseblk » (ntfs-3g, sur un
    /// vrai périphérique) passe. Rien n'y est monté : `Ecart::DisqueDebranche` (findmnt ne laisse rien passer, une
    /// information). Liste illisible ou ligne sans type : `Ecart::DestinationNonVue`, jamais un silence. Une image du
    /// compte montée là : `image_du_compte` (V-7).
    fn disque_monte(&self, racine: &str) -> Result<(), Ecart> {
        let texte = std::fs::read_to_string(self.sous("/proc/self/mountinfo")).map_err(|_| Ecart::DestinationNonVue)?;
        let Some(ligne) = texte
            .lines()
            .rev()
            .find(|l| point_de_montage(l).is_some_and(|m| m == racine))
        else {
            return Err(Ecart::DisqueDebranche);
        };
        match ligne.split_once(" - ").and_then(|(_, s)| s.split(' ').next()) {
            None | Some("") => Err(Ecart::DestinationNonVue),
            Some(t) if t == "fuse" || t.starts_with("fuse.") => Err(Ecart::DisqueFuse),
            Some(_) => self.image_du_compte(ligne),
        }
    }

    /// Le montage `ligne` (de /proc/self/mountinfo) vient-il d'une image du compte (V-7, relecture 0.95) ? Les
    /// périphériques sous le montage se suivent dans /sys : son numéro (/sys/dev/block/MAJ:MIN, absent pour un numéro
    /// 0:N comme btrfs), le nom de sa source (/sys/class/block/…, /dev/mapper/x suivi jusqu'à dm-N), puis ce qu'il
    /// recouvre (slaves : un chiffrement sur une image). Chacun, et son parent (une partition d'une image), est une
    /// boucle s'il a loop/backing_file : ce fichier doit être à root seul (`de_root_seul`), sinon `Ecart::DisqueImage`,
    /// levé. Une boucle (numéro 7:N ou source /dev/loop*) dont aucun fichier ne se lit, un /sys qui ne se lit pas, ou
    /// dont aucun premier nœud n'existe (W-6) : `Ecart::DestinationNonVue`. Limite : un montage posé seulement le temps de la copie n'est pas vu.
    fn image_du_compte(&self, ligne: &str) -> Result<(), Ecart> {
        let numero = ligne.split(' ').nth(2).unwrap_or("");
        let source = ligne
            .split_once(" - ")
            .and_then(|(_, s)| s.split(' ').nth(1))
            .unwrap_or("");
        let mut a_voir: Vec<std::path::PathBuf> = Vec::new();
        if !numero.is_empty() && !numero.starts_with("0:") {
            a_voir.push(self.sous(&format!("/sys/dev/block/{numero}")));
        }
        if let Some(nom) = source.strip_prefix("/dev/") {
            let reel = std::fs::canonicalize(self.sous(source)).ok();
            let nom = reel
                .as_deref()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .unwrap_or_else(|| nom.rsplit('/').next().unwrap_or(nom));
            a_voir.push(self.sous(&format!("/sys/class/block/{nom}")));
        }
        // W-6 (relecture 0.95) : un /sys caché ou non monté rend chaque lecture « absente » ; sans un premier nœud
        // vu (le numéro ou le nom du disque), rien ne dit que le disque n'est pas une image.
        if !a_voir.is_empty() && !a_voir.iter().any(|d| std::fs::symlink_metadata(d).is_ok()) {
            return Err(Ecart::DestinationNonVue);
        }
        let boucle = numero.starts_with("7:") || source.starts_with("/dev/loop");
        let mut adossee = false;
        let mut vus: u32 = 0;
        while let Some(d) = a_voir.pop() {
            vus = vus.saturating_add(1);
            if vus > 64 {
                return Err(Ecart::DestinationNonVue);
            }
            for haut in [d.clone(), d.join("..")] {
                match std::fs::read_to_string(haut.join("loop/backing_file")) {
                    Ok(f) => {
                        adossee = true;
                        let f = f.trim_end_matches('\n');
                        if f.is_empty() || !super::de_root_seul(&self.sous(f)) {
                            return Err(Ecart::DisqueImage);
                        }
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Ecart::DestinationNonVue),
                    Err(_) => {}
                }
            }
            match std::fs::read_dir(d.join("slaves")) {
                Ok(l) => a_voir.extend(l.flatten().map(|e| e.path())),
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(Ecart::DestinationNonVue),
                Err(_) => {}
            }
        }
        if boucle && !adossee {
            return Err(Ecart::DestinationNonVue);
        }
        Ok(())
    }

    /// Le disque de `racine` n'est pas branché, vu du dossier `absent` qui n'existe pas : `absent` est la racine ou un
    /// dossier au-dessus d'elle (aucun montage sans son dossier), ou la liste des montages se lit et aucun n'est à
    /// `racine`. Liste illisible : rien ne dit qu'il est débranché.
    fn debranche(&self, racine: &str, absent: &str) -> bool {
        if racine == absent || racine.strip_prefix(absent).is_some_and(|r| r.starts_with('/')) {
            return true;
        }
        std::fs::read_to_string(self.sous("/proc/self/mountinfo"))
            .is_ok_and(|t| !t.lines().any(|l| point_de_montage(l).is_some_and(|m| m == racine)))
    }

    /// Les fichiers de réglages de popt que rsync lit au départ (D-1 ; popt 1.19, `poptReadDefaultConfig`, vu sur
    /// rsync 3.5.1 avec un programme témoin) : `<sysconfdir>/popt`, chaque fichier de `<sysconfdir>/popt.d`, puis
    /// `$HOME/.popt`. Le `sysconfdir` dépend de la compilation de popt : /usr/etc ici (Arch), /etc ailleurs ; les deux
    /// sont lus. Un ~/.popt du compte (de chaque dossier personnel connu) là sous toute forme (fichier, lien, dossier),
    /// ou qui ne se voit pas : `Ecart::Popt`, levé ; rien ne dit qu'il ne lance pas un autre programme. Un fichier du
    /// système là (popt, ou un dossier popt.d non vide) : à root seul, avec son dossier, une information
    /// (`Ecart::PoptDuSystemeARoot`) ; sinon, ou un popt.d illisible, `Ecart::PoptDuSysteme`, levé. Jamais un silence.
    fn reglages_de_popt(&self) -> Result<Option<Ecart>, Ecart> {
        let la = |chemin: &str| match std::fs::symlink_metadata(self.sous(chemin)) {
            Ok(_) => true,
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        };
        let mut maisons: Vec<&str> = self.maisons.to_vec();
        maisons.push(self.maison);
        if maisons
            .iter()
            .any(|m| la(&format!("{}/.popt", m.trim_end_matches('/'))))
        {
            return Err(Ecart::Popt);
        }
        let mut a_root = Vec::new();
        for etc in ["/etc", "/usr/etc"] {
            let fichier = format!("{etc}/popt");
            if la(&fichier) {
                a_root.push(super::de_root_seul(&self.sous(&fichier)));
            }
            let dossier = format!("{etc}/popt.d");
            if la(&dossier) {
                let entrees: Vec<_> = std::fs::read_dir(self.sous(&dossier))
                    .map_err(|_| Ecart::PoptDuSysteme)?
                    .map(|e| e.map(|e| e.path()))
                    .collect::<Result<_, _>>()
                    .map_err(|_| Ecart::PoptDuSysteme)?;
                if !entrees.is_empty() {
                    a_root.push(super::de_root_seul(&self.sous(&dossier)));
                    a_root.extend(entrees.iter().map(|e| super::de_root_seul(e)));
                }
            }
        }
        popt_du_systeme(&a_root)
    }

    /// Le nom du fichier que lance vraiment ce programme, ses liens suivis (« ~/.local/bin/outil » → « bash ») ;
    /// `None` s'il n'existe pas ou ne se suit pas.
    fn nom_reel(&self, p: &str) -> Option<String> {
        let chemin = if p.contains('/') {
            self.sous(&chemin_simplifie(p))
        } else {
            DOSSIERS_SYSTEME
                .iter()
                .map(|d| format!("{d}/{p}"))
                .chain(DOSSIERS_DU_COMPTE.iter().map(|d| format!("{}/{d}/{p}", self.maison)))
                .find(|c| self.fichier(c, true))
                .map(|c| self.sous(&c))?
        };
        let reel = std::fs::canonicalize(chemin).ok()?;
        Some(reel.file_name()?.to_string_lossy().into_owned())
    }
}

/// Un chemin dans un dossier temporaire (lui-même compris : « /tmp » seul), le dossier courant ou les descripteurs
/// d'un processus, ou un dossier caché d'un dossier personnel.
fn cache_ou_temporaire(p: &str, maisons: &[&str], argument: bool) -> bool {
    let simple = chemin_simplifie(p);
    let net = sans_racine_de_proc(&simple);
    temporaire(net) || temporaire(&format!("{net}/")) || chemin_cache_chez(&simple, maisons, argument).is_some()
}

/// Le filet textuel (vérification 3, point 2), indépendant de toute analyse : le texte brut d'une ligne nomme-t-il un
/// dossier temporaire ou caché (/tmp, /var/tmp, /dev/shm, /run/user, /proc/…/root|cwd, ~/.x, $HOME/.x, ./, ../,
/// « .x/ » lu depuis la maison ; pour systemd, %t, %T, %V) ? Un chemin construit (printf, variables) n'y est pas :
/// la ligne n'est alors pas simple, donc « non lue ».
pub(super) fn filet(texte: &str, systemd: bool, maisons: &[&str]) -> bool {
    morceaux(texte).any(|m| morceau_cache(m, systemd, maisons))
}

/// Les morceaux d'un texte où le filet cherche un chemin : coupé sur les blancs, guillemets et ce qui sépare une
/// option de sa valeur ou deux commandes, l'option collée devant ôtée (`sans_option`).
fn morceaux(texte: &str) -> impl Iterator<Item = &str> {
    texte
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '"' | '\''
                        | '\\'
                        | ';'
                        | '&'
                        | '|'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | ','
                        | '='
                        | ':'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '`'
                )
        })
        .map(sans_option)
}

/// Un morceau de ligne (`filet`) qui mène à un dossier temporaire ou caché.
fn morceau_cache(m: &str, systemd: bool, maisons: &[&str]) -> bool {
    if m.is_empty() {
        return false;
    }
    if systemd && ["%t", "%T", "%V"].iter().any(|c| m.starts_with(c)) {
        return true;
    }
    if relatif_dangereux(m) {
        return true;
    }
    // Un dossier seul se juge par ce qu'il contient (« make -C ~/.x », vérification 3, S9).
    m.starts_with(['/', '~', '$', '%'])
        && (cache_ou_temporaire(m, maisons, true)
            || cache_ou_temporaire(&format!("{}/x", m.trim_end_matches('/')), maisons, true))
}

/// « . », « .. », « ./x », « ../x », ou « .x/… » (un dossier caché lu depuis le dossier courant, la maison d'un
/// service) hors des dossiers cachés ordinaires.
fn relatif_dangereux(m: &str) -> bool {
    if m == "." || m == ".." || m.starts_with("./") || m.starts_with("../") {
        return true;
    }
    m.starts_with('.') && m.contains('/') && chemin_cache(&format!("~/{m}"), "", true).is_some()
}

/// Un morceau sans l'option collée devant (« -S/tmp/x » → « /tmp/x », « --x/y » laissé tel quel).
fn sans_option(m: &str) -> &str {
    if !m.starts_with('-') {
        return m;
    }
    let Some(debut) = m.find(['/', '~', '.', '$', '%']) else {
        return m;
    };
    let option = m.get(..debut).unwrap_or_default();
    if option.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        m.get(debut..).unwrap_or(m)
    } else {
        m
    }
}

/// Ce qui sépare une option de sa valeur, ou deux valeurs, dans un argument (`argument_sur`).
fn separe(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '=' | ':' | ',' | ';' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '|' | '&' | '`'
        )
}

/// Au plus autant de séparateurs dans un argument dont les recollages se suivent (`argument_sur`) : au-delà, l'endroit
/// où il mène n'est pas vérifié.
const SEPARATEURS_MAX: usize = 32;

/// Un argument d'un programme : chacun de ses morceaux (coupé sur ce qui sépare une option de sa valeur ou deux
/// valeurs) sans chemin relatif dangereux ni chemin vers un dossier temporaire ou caché ; et ni lui, ni aucun de ses
/// recollages (morceaux voisins avec leurs séparateurs : un nom de dossier peut contenir « , », « = », « : » ou une
/// espace), ne mène à un lieu de démarrage du compte (X-3, relecture 0.95 : juger les seuls morceaux se contournait).
/// Trop de séparateurs pour tout suivre : non vérifié.
fn argument_sur(s: &Systeme, a: &str) -> Result<(), Ecart> {
    for m in a.split(separe) {
        let m = sans_option(m);
        if m.is_empty() {
            continue;
        }
        if relatif_dangereux(m) {
            return Err(Ecart::Chemin);
        }
        if m.starts_with(['/', '~', '$', '%']) && s.cache(m, true) {
            return Err(Ecart::Filet);
        }
    }
    let coupes: Vec<(usize, usize)> = a
        .char_indices()
        .filter(|(_, c)| separe(*c))
        .map(|(i, c)| (i, i.saturating_add(c.len_utf8())))
        .collect();
    if coupes.len() > SEPARATEURS_MAX {
        return Err(Ecart::LieuDeDemarrage);
    }
    // Les dossiers personnels tels qu'écrits et tels qu'ils sont vraiment (une maison atteinte par un lien), lus une
    // fois pour tous les recollages.
    let mut maisons: Vec<String> = s.maisons.iter().map(|m| (*m).to_string()).collect();
    maisons.extend(
        s.maisons
            .iter()
            .filter(|m| !m.is_empty())
            .filter_map(|m| s.chemin_reel(m).ok()),
    );
    let maisons: Vec<&str> = maisons.iter().map(String::as_str).collect();
    let debuts: Vec<usize> = std::iter::once(0)
        .chain(coupes.iter().map(|(_, apres)| *apres))
        .collect();
    let fins: Vec<usize> = coupes
        .iter()
        .map(|(avant, _)| *avant)
        .chain(std::iter::once(a.len()))
        .collect();
    for d in &debuts {
        for f in fins.iter().filter(|f| *f > d) {
            let m = sans_option(a.get(*d..*f).unwrap_or_default());
            if m.is_empty() {
                continue;
            }
            if let Some(e) = s.mene_a_un_lieu(m, &maisons) {
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Le plus de liens suivis pour un chemin (celui du noyau, ELOOP) : au-delà, le chemin n'est pas vérifié.
const LIENS_SUIVIS: u32 = 40;

impl Systeme<'_> {
    /// B-2 (revérification 7) : la raison d'un `ecart` telle qu'elle se montre pour cette ligne : pour
    /// `Ecart::DossierDeDepart`, la `cle` du dossier de départ (« Path= », « WorkingDirectory= ») et l'argument
    /// relatif (`relatif`, rendu affichable et coupé à 80 caractères) ; sinon `Ecart::raison`.
    pub(super) fn raison_dite(&self, ecart: Ecart, cle: &str) -> std::borrow::Cow<'static, str> {
        match (ecart, self.relatif.get()) {
            (Ecart::DossierDeDepart, Some(x)) => {
                // Coupé à 80 caractères, la coupure marquée d'un « … » (revérification 8).
                let coupe = x.chars().nth(80).is_some();
                let mut x = crate::ui::affichable(&x.chars().take(80).collect::<String>());
                if coupe {
                    x.push('…');
                }
                std::borrow::Cow::Owned(trf!(
                    "dossier de départ ({cle}) non vérifié : l'argument relatif « {x} » peut viser un autre fichier, dont un lieu de démarrage du compte (~/.config/autostart, ~/.config/systemd, ~/.bashrc…) ; non vérifié, donc pas passé sous silence",
                    "working folder ({cle}) not verified: the relative argument \"{x}\" can point to another file, including an account startup place (~/.config/autostart, ~/.config/systemd, ~/.bashrc…); not verified, so not kept quiet"
                ))
            }
            _ => std::borrow::Cow::Borrowed(ecart.raison()),
        }
    }

    /// Un morceau d'argument qui mène à un lieu de démarrage du compte (W-3, relecture 0.95) : par son texte, puis par
    /// l'endroit où il mène vraiment (ses liens suivis, `chemin_reel`), jugé contre les dossiers personnels tels
    /// qu'écrits et tels qu'ils sont vraiment (X-3 : une maison atteinte par un lien). Un morceau relatif
    /// (« .config/autostart », « lien ») se lit depuis le dossier courant de la ligne (`courant` : WorkingDirectory=
    /// d'une unité, Path= d'une entrée de bureau ; le dossier personnel sinon, celui d'une unité du compte sans
    /// WorkingDirectory=, systemd.exec(5)). Ce qui ne se suit pas avec certitude compte : non vérifié, donc pas tu
    /// (trop de liens, lien ou dossier illisible, saut par /proc ou /dev/fd, fichier dont un autre nom est dans un
    /// lieu, variable inconnue, dossier courant qui ne se résout pas). Une option (« -r ») n'est pas un chemin. Le
    /// constat revient (`Some`) : `Ecart::LieuDeDemarrage`, `Ecart::AutreNomNonCherche` avec sa cause quand c'est
    /// l'autre nom d'un fichier qui n'a pas pu être cherché (A-3), ou `Ecart::DossierDeDepart` pour un morceau
    /// relatif depuis un dossier courant qui ne se résout pas, le morceau gardé dans `relatif` (B-2).
    fn mene_a_un_lieu(&self, m: &str, maisons: &[&str]) -> Option<Ecart> {
        let lieu = Some(Ecart::LieuDeDemarrage);
        if m.starts_with('-') {
            return None;
        }
        let ecrit = if m.starts_with(['/', '~', '$', '%']) {
            m.to_string()
        } else {
            match self.courant {
                None => format!("~/{m}"),
                Some(d) if d.contains(CODE_INCONNU) => {
                    let _ = self.relatif.set(m.to_string());
                    return Some(Ecart::DossierDeDepart);
                }
                Some(d) => format!("{}/{m}", d.trim_end_matches('/')),
            }
        };
        if lieu_de_demarrage(&ecrit, maisons) {
            return lieu;
        }
        let Some(depart) = self.developpe(&ecrit) else {
            // Une variable que Vanguard ne connaît pas mène où elle veut ; un autre code se juge par son texte.
            return lieu.filter(|_| ecrit.starts_with('$'));
        };
        let reel = match self.chemin_reel(&depart) {
            Ok(reel) => reel,
            Err(Some(cause)) => return Some(Ecart::AutreNomNonCherche(cause)),
            Err(None) => return lieu,
        };
        lieu.filter(|_| {
            lieu_de_demarrage(&reel, maisons) || lieu_de_demarrage(&self.sous(&reel).to_string_lossy(), maisons)
        })
    }

    /// Un chemin écrit (« ~/… », « $HOME/… », « %h/… », « $XDG_CONFIG_HOME/… », « /… ») en chemin absolu de l'ordinateur ; `None`
    /// pour une autre variable ou un autre code, que le texte seul juge.
    fn developpe(&self, p: &str) -> Option<String> {
        if p.starts_with('/') {
            return Some(p.to_string());
        }
        let maison = self.maison.trim_end_matches('/');
        PREFIXES_DU_COMPTE.iter().find_map(|(d, vers)| {
            let reste = if p == d.trim_end_matches('/') {
                ""
            } else {
                p.strip_prefix(d)?
            };
            Some(format!("{maison}/{vers}{reste}"))
        })
    }

    /// Le chemin réel de `p` (absolu, de l'ordinateur) : chaque partie lue sous la racine, un lien remplacé par sa
    /// cible (absolue : lue sous la racine ; relative : depuis son dossier), « .. » appliqué au chemin déjà suivi.
    /// Une partie absente, ou sous un fichier qui n'est pas un dossier, arrête le suivi : le programme de la ligne
    /// ne la traverse pas non plus, et le reste se colle tel quel. Une erreur (non vérifié) : plus de `LIENS_SUIVIS`
    /// liens, un lien qui ne se lit pas, toute autre erreur de lecture (pas le droit, montage qui répond mal : X-4),
    /// un passage par /proc/self, /proc/thread-self, `/proc/<nombre>` ou /dev/fd (il dépend du processus qui lit : X-3,
    /// Y-2), ou
    /// les lieux de démarrage qui ne se lisent pas en entier quand le fichier final, du propriétaire du dossier
    /// personnel, a plusieurs liens physiques (X-3). Si l'autre nom de ce fichier est dans un lieu de démarrage, c'est
    /// ce nom qui revient ; sinon, le fichier compte pour lui-même (Y-3). L'erreur porte la cause quand ce sont les
    /// lieux qui n'ont pas pu être lus (`Err(Some(…))`, A-3) ; `Err(None)` pour le reste.
    fn chemin_reel(&self, p: &str) -> Result<String, Option<LieuxNonLus>> {
        use std::os::unix::fs::MetadataExt as _;
        let racine = self.racine.to_string_lossy();
        let racine = racine.trim_end_matches('/');
        let p = if racine.is_empty() {
            p
        } else {
            p.strip_prefix(racine).filter(|r| r.starts_with('/')).unwrap_or(p)
        };
        let mut reste: Vec<String> = p.split('/').rev().map(str::to_string).collect();
        let mut fait = String::new();
        let mut liens: u32 = 0;
        // Le propriétaire du dossier personnel : un fichier à lui peut avoir un autre nom (lien physique).
        let compte = std::fs::metadata(self.sous(self.maison)).map(|m| m.uid()).ok();
        while let Some(partie) = reste.pop() {
            if partie.is_empty() || partie == "." {
                continue;
            }
            if partie == ".." {
                let fin = fait.rfind('/').unwrap_or(0);
                fait.truncate(fin);
                continue;
            }
            let essai = format!("{fait}/{partie}");
            // Y-2 (revérification 4) : « /proc/self », « /proc/thread-self », « /proc/<nombre> » et « /dev/fd »
            // dépendent du processus qui lit (son dossier courant, sa racine, ses fichiers ouverts), pas de celui que
            // lance la ligne : rien ne se suit dessous. `essai` est déjà net (« . », parties vides et « .. »
            // appliqués), si bien que « /proc/self/./cwd » ou « /proc/self/task/../cwd » s'y arrêtent aussi.
            if par_un_processus(&essai) {
                return Err(None);
            }
            let lu = self.sous(&essai);
            match std::fs::symlink_metadata(&lu) {
                Ok(md) if md.file_type().is_symlink() => {
                    liens = liens.saturating_add(1);
                    if liens > LIENS_SUIVIS {
                        return Err(None);
                    }
                    let cible = std::fs::read_link(&lu).map_err(|_| None)?;
                    let cible = cible.to_str().ok_or(None)?;
                    if cible.starts_with('/') {
                        fait.clear();
                    }
                    reste.extend(cible.split('/').rev().map(str::to_string));
                }
                Ok(md)
                    if reste.iter().all(|r| r.is_empty() || r == ".")
                        && !md.is_dir()
                        && md.nlink() > 1
                        && compte.is_none_or(|u| md.uid() == u) =>
                {
                    // Y-3 : son autre nom compte s'il est dans un lieu de démarrage ; un autre nom ordinaire, non.
                    match self.noms_des_lieux().map_err(Some)?.get(&(md.dev(), md.ino())) {
                        Some(nom) => return Ok(nom.clone()),
                        None => fait = essai,
                    }
                }
                Ok(_) => fait = essai,
                Err(e)
                    if !matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    return Err(None);
                }
                Err(_) => {
                    fait = essai;
                    while let Some(partie) = reste.pop() {
                        fait.push('/');
                        fait.push_str(&partie);
                    }
                    // Le même passage écrit sous un début absent (ici, une racine d'essai sans /proc).
                    if par_un_processus(&fait) {
                        return Err(None);
                    }
                }
            }
        }
        Ok(if fait.is_empty() { "/".to_string() } else { fait })
    }
}

/// Y-3 : le plus d'entrées lues dans les lieux de démarrage du compte, et la plus grande profondeur sous l'un d'eux,
/// pour y chercher l'autre nom d'un fichier à plusieurs liens physiques. Au-delà, rien n'est vérifié.
const NOMS_LUS_MAX: usize = 4096;
const PROFONDEUR_DES_LIEUX: u32 = 8;

impl Systeme<'_> {
    /// Y-3 : les fichiers à plusieurs liens physiques des lieux de démarrage du compte (`LIEUX_DE_DEMARRAGE` sous
    /// chaque dossier personnel), par (appareil, inode). Chaque lien se suit, le lieu (un ~/.bashrc lien vers des
    /// dotfiles) comme ce qu'il contient (un fichier ou un sous-dossier lié : il se lit à l'ouverture), un dossier
    /// une seule fois. Une erreur (non vérifié, sa cause dite : A-3) : plus de `NOMS_LUS_MAX` entrées, un dossier
    /// plus profond que `PROFONDEUR_DES_LIEUX`, une lecture qui échoue autrement que par une absence, ou un lien
    /// absolu sous une racine d'essai (il se suivrait hors d'elle : Z-3).
    fn noms_des_lieux(&self) -> Result<&NomsLus, LieuxNonLus> {
        self.noms_des_lieux
            .get_or_init(|| self.lire_noms_des_lieux())
            .as_ref()
            .map_err(|e| *e)
    }

    fn lire_noms_des_lieux(&self) -> NomsDesLieux {
        use std::os::unix::fs::MetadataExt as _;
        let mut noms = std::collections::HashMap::new();
        let mut lus: usize = 0;
        let mut pile: Vec<(std::path::PathBuf, String, u32)> = Vec::new();
        for m in self.maisons.iter().filter(|m| !m.is_empty()) {
            let m = m.trim_end_matches('/');
            for l in LIEUX_DE_DEMARRAGE {
                let nom = format!("{m}/{l}");
                pile.push((self.sous(&nom), nom, 0));
            }
        }
        // Les dossiers déjà lus (un lien peut ramener à un dossier vu : une boucle, ou deux lieux qui n'en font qu'un).
        let mut dossiers_lus: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        let racine_vraie = self.racine.as_os_str().is_empty() || self.racine == Path::new("/");
        while let Some((chemin, nom, profondeur)) = pile.pop() {
            lus = lus.saturating_add(1);
            if lus > NOMS_LUS_MAX {
                return Err(LieuxNonLus::Entrees);
            }
            // Z-3 (revérification 5) : les liens se suivent par le système ; sous une racine d'essai, un lien absolu
            // mènerait hors d'elle : non vérifié.
            if !racine_vraie && std::fs::read_link(&chemin).is_ok_and(|c| c.is_absolute()) {
                return Err(LieuxNonLus::HorsRacine);
            }
            // Z-2 (revérification 5) : chaque lien se suit, le lieu comme ce qu'il contient (un sous-dossier lié par
            // un gestionnaire de dotfiles se lit aussi) ; une cible qui ne se lit pas, sauf absente : non vérifié.
            let md = match std::fs::metadata(&chemin) {
                Ok(md) => md,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(LieuxNonLus::Lecture),
            };
            if md.is_dir() {
                if !dossiers_lus.insert((md.dev(), md.ino())) {
                    continue;
                }
                if profondeur >= PROFONDEUR_DES_LIEUX {
                    return Err(LieuxNonLus::Profondeur);
                }
                for entree in std::fs::read_dir(&chemin).map_err(|_| LieuxNonLus::Lecture)? {
                    let entree = entree.map_err(|_| LieuxNonLus::Lecture)?;
                    let suite = format!("{nom}/{}", entree.file_name().to_string_lossy());
                    pile.push((entree.path(), suite, profondeur.saturating_add(1)));
                }
                continue;
            }
            if md.nlink() > 1 {
                noms.insert((md.dev(), md.ino()), nom);
            }
        }
        Ok(noms)
    }
}

/// Y-2 : vrai si le chemin, une fois net (« . » et parties vides sautés, « .. » appliqués), passe par /proc/self,
/// /proc/thread-self, `/proc/<nombre>` ou /dev/fd : ce qu'il y a dessous dépend du processus qui lit.
fn par_un_processus(chemin: &str) -> bool {
    let mut net: Vec<&str> = Vec::new();
    for partie in chemin.split('/') {
        match partie {
            "" | "." => continue,
            ".." => {
                net.pop();
                continue;
            }
            _ => net.push(partie),
        }
        let processus = match net.as_slice() {
            ["dev", "fd"] => true,
            ["proc", n] => *n == "self" || *n == "thread-self" || n.bytes().all(|b| b.is_ascii_digit()),
            _ => false,
        };
        if processus {
            return true;
        }
    }
    false
}

/// Les débuts d'un chemin écrit qui désignent un dossier du compte, et ce qu'ils valent sous son dossier personnel :
/// la maison (« ~ », « $HOME », « %h ») et ses réglages (« $XDG_CONFIG_HOME » : ~/.config par défaut). Les autres
/// codes de systemd (%E, %S…) sont déjà remplacés par leur valeur avant la liste permise (`developper_codes`).
const PREFIXES_DU_COMPTE: [(&str, &str); 6] = [
    ("~/", ""),
    ("$HOME/", ""),
    ("${HOME}/", ""),
    ("%h/", ""),
    ("$XDG_CONFIG_HOME/", ".config/"),
    ("${XDG_CONFIG_HOME}/", ".config/"),
];

/// Les lieux du compte (sous son dossier personnel) dont le contenu se lance ou se lit tout seul à l'ouverture de la
/// session : dossiers d'entrées et d'unités, fichiers de variables, profils des shells, réglages de Hyprland et les
/// modules d'Omarchy (sauf le thème, qu'une ligne lit souvent), ceux des autres bureaux (KDE, Sway, niri, i3, labwc,
/// river, Openbox, LXDE, la session X). Un chemin sous l'un d'eux, ou l'un d'eux, compte. Limite dite : le dossier
/// personnel entier (« cp -r … ~ ») n'y est pas, trop de lignes ordinaires le nomment.
const LIEUX_DE_DEMARRAGE: [&str; 38] = [
    ".config/autostart",
    ".config/autostart-scripts",
    ".config/plasma-workspace",
    ".config/sway",
    ".config/niri",
    ".config/i3",
    ".config/labwc",
    ".config/river",
    ".config/openbox",
    ".config/lxsession",
    ".xinitrc",
    ".xsession",
    ".config/systemd",
    ".local/share/systemd",
    ".config/environment.d",
    ".config/hypr",
    ".config/uwsm",
    ".config/fish",
    ".config/default",
    ".local/share/dbus-1",
    ".local/state/default",
    ".local/state/hypr",
    ".local/state/omarchy/toggles",
    ".local/state/omarchy/workspace-layouts",
    ".pam_environment",
    ".popt",
    ".profile",
    ".bash_profile",
    ".bash_login",
    ".bashrc",
    ".bash_logout",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".xprofile",
    ".xsessionrc",
];

/// Les dossiers du compte qui contiennent un lieu de démarrage : nommés seuls (« cp -r … ~/.config »), une copie y
/// pose aussi bien un lancement. Le dossier personnel lui-même n'y est pas (trop de lignes ordinaires le nomment).
const PARENTS_DE_LIEUX: [&str; 5] = [
    ".config",
    ".local",
    ".local/share",
    ".local/state",
    ".local/state/omarchy",
];

/// Un chemin (« ~/… », « $HOME/… », « %h/… », sous un dossier personnel de `maisons` ou celui d'un autre compte) qui
/// mène à un lieu de démarrage du compte (`LIEUX_DE_DEMARRAGE`) ou à un dossier qui en contient (`PARENTS_DE_LIEUX`).
fn lieu_de_demarrage(p: &str, maisons: &[&str]) -> bool {
    let simple = chemin_simplifie(p);
    let net = sans_racine_de_proc(&simple);
    let net = net.trim_end_matches('/');
    let mut relatifs: Vec<String> = PREFIXES_DU_COMPTE
        .iter()
        .filter_map(|(d, vers)| {
            if net == d.trim_end_matches('/') {
                return Some(vers.trim_end_matches('/').to_string());
            }
            net.strip_prefix(d).map(|r| format!("{vers}{r}"))
        })
        .collect();
    for m in maisons.iter().filter(|m| !m.is_empty()) {
        relatifs.extend(
            net.strip_prefix(&format!("{}/", m.trim_end_matches('/')))
                .map(str::to_string),
        );
        relatifs.extend(maison_d_un_compte(net, m).map(str::to_string));
    }
    relatifs.iter().map(String::as_str).any(|r| {
        PARENTS_DE_LIEUX.contains(&r)
            || LIEUX_DE_DEMARRAGE
                .iter()
                .any(|l| r == *l || r.strip_prefix(l).is_some_and(|x| x.starts_with('/')))
    })
}

/// Un mot d'une commande simple, coupé comme le coupe le shell.
struct Mot {
    texte: String,
    /// Le premier « = » du mot est hors guillemets, et rien avant lui n'est cité : une affectation possible.
    egal: bool,
}

/// Une commande simple : ses mots, et si elle redirige une sortie (vers /dev/null seulement).
#[derive(Default)]
struct Simple {
    mots: Vec<Mot>,
    redirigee: bool,
}

/// L'état du découpage d'une ligne (`couper`).
#[derive(Default)]
struct Lexeur {
    commandes: Vec<Simple>,
    courante: Simple,
    mot: String,
    dans: bool,
    cite: bool,
    egal: Option<bool>,
    /// Le prochain mot est la cible d'une redirection de sortie.
    cible: bool,
}

impl Lexeur {
    fn pousser(&mut self, c: char, cite: bool) {
        if c == '=' && self.egal.is_none() {
            self.egal = Some(!cite && !self.cite);
        }
        self.mot.push(c);
        self.dans = true;
    }

    fn finir(&mut self) -> Result<(), Ecart> {
        if !self.dans {
            return Ok(());
        }
        let texte = std::mem::take(&mut self.mot);
        let egal = self.egal.take() == Some(true);
        self.dans = false;
        self.cite = false;
        if self.cible {
            self.cible = false;
            return if texte == "/dev/null" {
                Ok(())
            } else {
                Err(Ecart::Forme)
            };
        }
        self.courante.mots.push(Mot { texte, egal });
        Ok(())
    }

    fn separer(&mut self) -> Result<(), Ecart> {
        self.finir()?;
        if self.cible || self.courante.mots.is_empty() {
            return Err(Ecart::Forme);
        }
        self.commandes.push(std::mem::take(&mut self.courante));
        Ok(())
    }

    fn terminer(mut self) -> Result<Vec<Simple>, Ecart> {
        self.finir()?;
        if self.cible || (self.courante.mots.is_empty() && self.courante.redirigee) {
            return Err(Ecart::Forme);
        }
        if !self.courante.mots.is_empty() {
            self.commandes.push(std::mem::take(&mut self.courante));
        }
        if self.commandes.is_empty() {
            return Err(Ecart::Forme);
        }
        Ok(self.commandes)
    }
}

/// Après « $ » : « HOME » ou « {HOME} » seuls, remplacés par le dossier personnel ; toute autre variable, « $( »,
/// « $(( », « $'…' » : hors liste. Rend la position après le nom.
fn dollar(c: &[char], i: usize, l: &mut Lexeur, maison: &str) -> Result<usize, Ecart> {
    let suite: String = c.get(i..).unwrap_or_default().iter().take(6).collect();
    let n = if suite.starts_with("{HOME}") {
        6
    } else if suite.starts_with("HOME")
        && !c
            .get(i.saturating_add(4))
            .is_some_and(|x| x.is_ascii_alphanumeric() || *x == '_')
    {
        4
    } else {
        return Err(Ecart::Forme);
    };
    for x in maison.chars() {
        l.pousser(x, true);
    }
    Ok(i.saturating_add(n))
}

/// Les commandes simples d'une ligne de shell, coupées comme `/bin/sh -c` les coupe, si chaque caractère actif est
/// dans la liste : « ; », « & », « && », « || », fin de ligne entre deux commandes ; guillemets ; « ~ » et
/// « $HOME » ; une sortie redirigée vers /dev/null ou un descripteur (« 2>&1 »). Tout le reste (« | », « < »,
/// « $( », accents graves, parenthèses, accolades, jokers, « ! » et « # » en tête de mot, autre variable, caractère
/// trompeur) : `Ecart::Forme`.
#[allow(clippy::many_single_char_names)] // un lexeur : c, l, i, x se lisent mieux courts
fn couper(ligne: &str, maison: &str) -> Result<Vec<Simple>, Ecart> {
    if ligne.chars().any(|c| c != '\n' && designes::trompeur(c)) {
        return Err(Ecart::Forme);
    }
    let c: Vec<char> = ligne.chars().collect();
    let mut l = Lexeur::default();
    let mut i = 0_usize;
    let fin_de_mot = |x: Option<&char>| x.is_none_or(|y| matches!(y, ' ' | '\t' | '\n' | ';' | '&' | '|' | '>'));
    while let Some(&x) = c.get(i) {
        i = i.saturating_add(1);
        let suivant = c.get(i).copied();
        match x {
            ' ' | '\t' => l.finir()?,
            '\n' | ';' => l.separer()?,
            '&' => match suivant {
                Some('&') => {
                    i = i.saturating_add(1);
                    l.separer()?;
                }
                Some('>') => {
                    l.finir()?;
                    i = i.saturating_add(1);
                    if c.get(i) == Some(&'>') {
                        i = i.saturating_add(1);
                    }
                    if l.cible {
                        return Err(Ecart::Forme);
                    }
                    l.cible = true;
                    l.courante.redirigee = true;
                }
                _ => l.separer()?,
            },
            '|' if suivant == Some('|') => {
                i = i.saturating_add(1);
                l.separer()?;
            }
            '>' => {
                if l.dans && !l.cite && l.mot.bytes().all(|b| b.is_ascii_digit()) {
                    l.mot.clear();
                    l.dans = false;
                    l.egal = None;
                } else {
                    l.finir()?;
                }
                if l.cible {
                    return Err(Ecart::Forme);
                }
                l.courante.redirigee = true;
                match c.get(i) {
                    Some('>' | '|') => {
                        i = i.saturating_add(1);
                        l.cible = true;
                    }
                    Some('&') => {
                        i = i.saturating_add(1);
                        let debut = i;
                        while c.get(i).is_some_and(char::is_ascii_digit) {
                            i = i.saturating_add(1);
                        }
                        if i == debut {
                            if c.get(i) != Some(&'-') {
                                return Err(Ecart::Forme);
                            }
                            i = i.saturating_add(1);
                        }
                        if !fin_de_mot(c.get(i)) {
                            return Err(Ecart::Forme);
                        }
                    }
                    _ => l.cible = true,
                }
            }
            '|' | '<' | '(' | ')' | '`' | '*' | '?' | '[' | '{' | '}' => return Err(Ecart::Forme),
            '#' | '!' if !l.dans => return Err(Ecart::Forme),
            '~' if !l.dans => {
                if !(suivant == Some('/') || fin_de_mot(suivant.as_ref())) {
                    return Err(Ecart::Forme);
                }
                for y in maison.chars() {
                    l.pousser(y, true);
                }
            }
            '$' => i = dollar(&c, i, &mut l, maison)?,
            '\'' => {
                l.cite = true;
                l.dans = true;
                loop {
                    let y = *c.get(i).ok_or(Ecart::Forme)?;
                    i = i.saturating_add(1);
                    if y == '\'' {
                        break;
                    }
                    l.pousser(y, true);
                }
            }
            '"' => {
                l.cite = true;
                l.dans = true;
                loop {
                    let y = *c.get(i).ok_or(Ecart::Forme)?;
                    i = i.saturating_add(1);
                    match y {
                        '"' => break,
                        '\\' => {
                            let z = *c.get(i).ok_or(Ecart::Forme)?;
                            i = i.saturating_add(1);
                            match z {
                                '$' | '`' | '"' | '\\' => l.pousser(z, true),
                                '\n' => return Err(Ecart::Forme),
                                _ => {
                                    l.pousser('\\', true);
                                    l.pousser(z, true);
                                }
                            }
                        }
                        '$' => i = dollar(&c, i, &mut l, maison)?,
                        '`' => return Err(Ecart::Forme),
                        _ => l.pousser(y, true),
                    }
                }
            }
            '\\' => {
                let z = *c.get(i).ok_or(Ecart::Forme)?;
                i = i.saturating_add(1);
                if z == '\n' {
                    return Err(Ecart::Forme);
                }
                l.cite = true;
                l.pousser(z, true);
            }
            _ => l.pousser(x, false),
        }
    }
    l.terminer()
}

/// Les mots du shell qui, en tête d'une commande, changent comment la suite se lit (dossier courant, fonctions,
/// alias, variables, pièges, blocs) : hors liste.
const MOTS_DU_SHELL: [&str; 58] = [
    "cd",
    "pushd",
    "popd",
    "eval",
    "trap",
    "builtin",
    "alias",
    "unalias",
    "source",
    ".",
    "export",
    "declare",
    "typeset",
    "readonly",
    "local",
    "hash",
    "mapfile",
    "readarray",
    "enable",
    "set",
    "shopt",
    "unset",
    "command",
    "ulimit",
    "umask",
    "read",
    "let",
    "fc",
    "bind",
    "complete",
    "compgen",
    "history",
    "getopts",
    "coproc",
    "function",
    "time",
    "select",
    "case",
    "for",
    "while",
    "until",
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "do",
    "done",
    "esac",
    "[[",
    "]]",
    "!",
    "exit",
    "return",
    "shift",
    "wait",
    "type",
    "jobs",
];

/// Une ligne de shell (Hyprland « exec », un appel Lua qui lance, la valeur de « sh -c ») : chaque commande simple
/// reconnue comme sûre, sinon l'écart de la première qui ne l'est pas.
pub(super) fn ligne_shell(s: &Systeme, ligne: &str) -> Result<(), Ecart> {
    ligne_a(s, ligne, 0)
}

fn ligne_a(s: &Systeme, ligne: &str, profondeur: u32) -> Result<(), Ecart> {
    if profondeur > PROFONDEUR_MAX {
        return Err(Ecart::Forme);
    }
    if ligne.len() > LIGNE_MAX {
        return Err(Ecart::Longue);
    }
    for simple in couper(ligne, s.maison)? {
        commande_du_shell(s, &simple, profondeur)?;
    }
    Ok(())
}

/// Une commande simple du shell : ses affectations en tête (`affectation_sure`), un « exec » sans redirection, puis
/// ce qu'elle lance (`lancee`).
fn commande_du_shell(s: &Systeme, simple: &Simple, profondeur: u32) -> Result<(), Ecart> {
    let mut k = 0_usize;
    while let Some(m) = simple.mots.get(k) {
        let Some((nom, valeur)) = m.egal.then(|| affectation(&m.texte)).flatten() else {
            break;
        };
        affectation_sure(s, nom, valeur)?;
        k = k.saturating_add(1);
    }
    let mut reste: Vec<String> = simple
        .mots
        .get(k..)
        .unwrap_or_default()
        .iter()
        .map(|m| m.texte.clone())
        .collect();
    if reste.first().is_some_and(|m| m == "exec") {
        if simple.redirigee || reste.get(1).is_some_and(|m| m.starts_with('-')) {
            return Err(Ecart::Forme);
        }
        reste = reste.get(1..).unwrap_or_default().to_vec();
    }
    let premier = reste.first().ok_or(Ecart::Forme)?;
    if MOTS_DU_SHELL.contains(&premier.as_str()) {
        return Err(Ecart::Forme);
    }
    lancee(s, &reste, profondeur)
}

/// Une variable qui change ce qui se lance ou d'où le code se charge : jamais posée par une ligne reconnue sûre.
fn variable_refusee(nom: &str) -> bool {
    const NOMS: [&str; 22] = [
        "HOME",
        "PATH",
        "ENV",
        "BASH_ENV",
        "IFS",
        "CDPATH",
        "GLOBIGNORE",
        "PROMPT_COMMAND",
        "EXECIGNORE",
        "BASH_XTRACEFD",
        "ZDOTDIR",
        "TMPDIR",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_DIRS",
        "XDG_DATA_DIRS",
        "ELECTRON_RUN_AS_NODE",
        "LD_PRELOAD",
        "LD_AUDIT",
    ];
    NOMS.contains(&nom)
        || nom.starts_with("LD_")
        || nom.starts_with("DYLD_")
        || nom.starts_with("DBUS_")
        || variable_d_injection(nom)
        || variable_de_programme(nom)
}

/// Une affectation « NOM=valeur » en tête d'une commande, ou donnée à env : un nom qui ne change pas ce qui se lance,
/// une valeur sans chemin dangereux.
fn affectation_sure(s: &Systeme, nom: &str, valeur: &str) -> Result<(), Ecart> {
    if variable_refusee(nom) {
        return Err(Ecart::Variable);
    }
    argument_sur(s, valeur)
}

/// Les programmes qui en lancent un autre, ou du code, d'après leurs arguments, en plus de `designes::lanceur` et de
/// `enveloppe` : hors liste, sauf forme exacte lue plus haut (`lancee`).
const AUTRES_LANCEURS: [&str; 34] = [
    "prlimit",
    "setarch",
    "linux32",
    "linux64",
    "i386",
    "x86_64",
    "run0",
    "swaymsg",
    "gtk-launch",
    "gtk4-launch",
    "dex",
    "unbuffer",
    "watchexec",
    "numactl",
    "cgexec",
    "sshpass",
    "xdotool",
    "ydotool",
    "entr",
    "nvidia-offload",
    "switcherooctl",
    "kstart",
    "kstart5",
    "kstart6",
    "kioclient",
    "kioclient5",
    "exo-open",
    "gdbus",
    "dbus-send",
    "busctl",
    "qdbus",
    "socat",
    "systemd-run",
    "app2unit",
];

/// Les terminaux dont la forme se lit (`terminal`).
const TERMINAUX: [&str; 10] = [
    "alacritty",
    "kitty",
    "foot",
    "footclient",
    "ghostty",
    "wezterm",
    "konsole",
    "gnome-terminal",
    "xterm",
    "xfce4-terminal",
];

/// Ce que lance une commande (ses mots : programme puis arguments), si sa forme est reconnue sûre : le programme
/// (`Systeme::programme`), puis selon lui (enveloppe connue, interpréteur, terminal…), ou ses arguments sans chemin
/// dangereux pour un programme ordinaire.
fn lancee(s: &Systeme, mots: &[String], profondeur: u32) -> Result<(), Ecart> {
    if profondeur > PROFONDEUR_MAX {
        return Err(Ecart::Forme);
    }
    let (programme, args) = mots.split_first().ok_or(Ecart::Forme)?;
    s.programme(programme)?;
    let ecrit = crate::machine::chasse::nom_de_fichier(programme);
    // Un lien vers un interpréteur, un lanceur ou un terminal se lit comme lui : le nom écrit ne le cache pas.
    let reel = s.nom_reel(programme);
    let nom = match reel.as_deref() {
        Some(r)
            if r != ecrit
                && (designes::interpreteur(r).is_some()
                    || designes::lanceur(r)
                    || enveloppe(r)
                    || AUTRES_LANCEURS.contains(&r)
                    || TERMINAUX.contains(&r)) =>
        {
            r
        }
        _ => ecrit,
    };
    let p = profondeur.saturating_add(1);
    match nom {
        "env" => env(s, args, p),
        "nohup" | "gamemoderun" | "prime-run" => apres_options(s, args, &[], &[], p),
        "setsid" => apres_options(s, args, &["-f", "-w", "-c", "--fork", "--wait", "--ctty"], &[], p),
        "nice" => apres_options(s, args, &[], &["-n", "--adjustment"], p),
        "ionice" => apres_options(s, args, &["-t", "--ignore"], &["-c", "-n", "--class", "--classdata"], p),
        "stdbuf" => apres_options(s, args, &[], &["-i", "-o", "-e", "--input", "--output", "--error"], p),
        "systemd-cat" => apres_options(
            s,
            args,
            &["--level-prefix"],
            &["-t", "-p", "--identifier", "--priority", "--stderr-priority"],
            p,
        ),
        "mangohud" => apres_options(s, args, &["--dlsym"], &[], p),
        "timeout" => timeout(s, args, p),
        "gamescope" => gamescope(s, args, p),
        "uwsm-app" => uwsm_app(s, args, p),
        "uwsm" => uwsm(s, args, p),
        "xdg-terminal-exec" => terminal_xdg(s, args, p),
        "hyprctl" => hyprctl(s, args),
        "flatpak" => flatpak(s, args),
        "systemctl" => systemctl(s, args),
        "dbus-update-activation-environment" => dbus_update(s, args),
        "swayidle" => swayidle(s, args, p),
        "wl-paste" => wl_paste(s, args, p),
        "xss-lock" => xss_lock(s, args, p),
        // « daemon » est aussi le nom d'un lanceur : la forme exacte de playerctld, reconnue telle quelle.
        "playerctld" if args.iter().all(|a| a == "daemon") => Ok(()),
        n if n.starts_with("omarchy-") => omarchy(s, n, args, p),
        n if TERMINAUX.contains(&n) => terminal(s, n, args, p),
        _ => match designes::interpreteur(nom) {
            Some(true) => shell(s, args, p),
            Some(false) => interprete(s, args),
            None if designes::lanceur(nom) || enveloppe(nom) || AUTRES_LANCEURS.contains(&nom) => Err(Ecart::Lanceur),
            None => ordinaire(s, args),
        },
    }
}

/// Une commande de la sauvegarde que Vanguard pose, reconnue à ses `mots` exacts (`Codes::sauvegarde`) : le vrai
/// `nom` (rsync, findmnt : écrit sous ce nom et, liens suivis, ce fichier-là) à un emplacement permis, des chemins
/// sans dossier dangereux. Ailleurs, rsync reste un lanceur (« -e », « --rsh », « --rsync-path », « --filter ») :
/// aucune autre forme ne se tait (relecture 0.94, S-1). Un faux findmnt (true) rendrait la condition « bon disque
/// monté » toujours vraie (C-2).
///
/// `env` : la forme de la 0.95, « `"<env>" -i` » devant ; env doit être le vrai env, comme rsync et findmnt. Un env
/// écrit sous ce nom mais qui est un lien vers un programme à plusieurs noms (`MULTI_APPELS` : uutils sur Ubuntu,
/// busybox ; pas NixOS, où la sauvegarde reste levée), qui choisit ce qu'il fait d'après le nom écrit, passe s'il est à root seul ; jamais un fichier
/// du compte, jamais pour rsync ou findmnt.
fn sauvegarde_posee(s: &Systeme, mots: &[String], nom: &str, env: bool) -> Result<(), Ecart> {
    let vrai = |programme: &String, nom: &str| {
        s.programme(programme)?;
        let reel = s.nom_reel(programme);
        let multi = nom == "env" && reel.as_deref().is_some_and(|r| MULTI_APPELS.contains(&r));
        if crate::machine::chasse::nom_de_fichier(programme) != nom || (reel.as_deref() != Some(nom) && !multi) {
            return Err(Ecart::Lanceur);
        }
        // Le nom ne suffit pas : un ~/bin/rsync du compte le porte aussi (F-4).
        if !super::programme_de_root_seul(s.racine, &s.sous(&chemin_simplifie(programme))) {
            return Err(Ecart::ProgrammeDuCompte);
        }
        Ok(())
    };
    let mots = if env {
        let [e, i, reste @ ..] = mots else {
            return Err(Ecart::Forme);
        };
        vrai(e, "env")?;
        if i != "-i" {
            return Err(Ecart::Lanceur);
        }
        reste
    } else {
        mots
    };
    let (programme, args) = mots.split_first().ok_or(Ecart::Forme)?;
    vrai(programme, nom)?;
    args.iter().try_for_each(|a| argument_sur(s, a))
}

/// Les arguments d'un programme ordinaire : sans chemin dangereux, sans programme ni ligne de commande en argument
/// (un programme inconnu qui lancerait ses arguments se lit comme un lanceur).
fn ordinaire(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    for a in args {
        argument_sur(s, a)?;
        let nom = crate::machine::chasse::nom_de_fichier(a);
        if designes::interpreteur(a).is_some() || designes::lanceur(a) || enveloppe(a) || AUTRES_LANCEURS.contains(&nom)
        {
            return Err(Ecart::Lanceur);
        }
        if a.contains([' ', '\t']) && (a.contains([';', '|', '`']) || a.contains("&&") || a.contains("$(")) {
            return Err(Ecart::Lanceur);
        }
    }
    Ok(())
}

/// Une enveloppe qui prend des options puis lance la suite : `drapeaux` (sans valeur), `valeurs` (avec une valeur,
/// séparée, après « = » ou collée à une option courte) ; « -- » finit les options. Une option inconnue : lanceur.
fn apres_options(
    s: &Systeme,
    args: &[String],
    drapeaux: &[&str],
    valeurs: &[&str],
    profondeur: u32,
) -> Result<(), Ecart> {
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        if a == "--" {
            return lancee(s, args.get(i.saturating_add(1)..).unwrap_or_default(), profondeur);
        }
        if !a.starts_with('-') || a == "-" {
            return lancee(s, args.get(i..).unwrap_or_default(), profondeur);
        }
        i = i.saturating_add(1);
        if drapeaux.contains(&a.as_str()) {
            continue;
        }
        if valeurs.contains(&a.as_str()) {
            argument_sur(s, args.get(i).ok_or(Ecart::Forme)?)?;
            i = i.saturating_add(1);
            continue;
        }
        if let Some((cle, v)) = a.split_once('=')
            && valeurs.contains(&cle)
        {
            argument_sur(s, v)?;
            continue;
        }
        if !a.starts_with("--")
            && let Some(courte) = a.get(..2)
            && valeurs.contains(&courte)
        {
            argument_sur(s, a.get(2..).unwrap_or_default())?;
            continue;
        }
        // « nice -5 » : la priorité en option.
        if valeurs.contains(&"-n")
            && a.get(1..)
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        return Err(Ecart::Lanceur);
    }
    Err(Ecart::Forme)
}

/// « env » : « -u NOM », « NOM=valeur » (`affectation_sure`), puis la commande ; « -i », « - », « -S », « -C »,
/// « -P » et toute autre option : lanceur (environnement vidé, ligne recoupée, dossier changé, PATH changé).
fn env(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    let mut options = true;
    while let Some(a) = args.get(i) {
        i = i.saturating_add(1);
        if options {
            match a.as_str() {
                "--" => {
                    options = false;
                    continue;
                }
                "-u" | "--unset" => {
                    let nom = args.get(i).ok_or(Ecart::Forme)?;
                    if affectation(&format!("{nom}=")).is_none() {
                        return Err(Ecart::Variable);
                    }
                    i = i.saturating_add(1);
                    continue;
                }
                "-0" | "--null" | "-v" | "--debug" => continue,
                _ if a.starts_with("--unset=") => continue,
                _ if a.starts_with('-') => return Err(Ecart::Lanceur),
                _ => {}
            }
        }
        if let Some((nom, valeur)) = affectation(a) {
            affectation_sure(s, nom, valeur)?;
            continue;
        }
        return lancee(s, args.get(i.saturating_sub(1)..).unwrap_or_default(), profondeur);
    }
    Ok(())
}

/// « `timeout [options] durée commande` ».
fn timeout(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        i = i.saturating_add(1);
        match a.as_str() {
            "--preserve-status" | "--foreground" | "-v" | "--verbose" => {}
            "-s" | "--signal" | "-k" | "--kill-after" => {
                argument_sur(s, args.get(i).ok_or(Ecart::Forme)?)?;
                i = i.saturating_add(1);
            }
            _ if a.starts_with("--signal=") || a.starts_with("--kill-after=") => {}
            "--" => {}
            _ if a.starts_with('-') => return Err(Ecart::Lanceur),
            duree => {
                if !duree
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, '.' | 's' | 'm' | 'h' | 'd'))
                {
                    return Err(Ecart::Lanceur);
                }
                return lancee(s, args.get(i..).unwrap_or_default(), profondeur);
            }
        }
    }
    Err(Ecart::Forme)
}

/// « `gamescope [options] -- commande` » : sans « -- », la suite ne se sépare pas des options.
fn gamescope(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let Some(fin) = args.iter().position(|a| a == "--") else {
        return Err(Ecart::Lanceur);
    };
    for a in args.get(..fin).unwrap_or_default() {
        argument_sur(s, a)?;
    }
    lancee(s, args.get(fin.saturating_add(1)..).unwrap_or_default(), profondeur)
}

/// « uwsm-app [-s tranche] [-t genre] [-a nom] [-u unité] [-d description] [-S sortie] [-T] [--] commande » : une
/// entrée de bureau (« x.desktop », « x.desktop:action ») lance ce que dit son fichier, non lu ici ; « -p »
/// (propriété d'unité) et toute autre option : lanceur.
fn uwsm_app(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    let mut debut = None;
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "--" => {
                debut = Some(i.saturating_add(1));
                break;
            }
            "-s" | "-t" | "-a" | "-u" | "-d" | "-S" => {
                argument_sur(s, args.get(i.saturating_add(1)).ok_or(Ecart::Forme)?)?;
                i = i.saturating_add(2);
            }
            "-T" => i = i.saturating_add(1),
            _ if a.starts_with('-') => return Err(Ecart::Lanceur),
            _ => {
                debut = Some(i);
                break;
            }
        }
    }
    let commande = args.get(debut.ok_or(Ecart::Forme)?..).unwrap_or_default();
    let premier = commande.first().ok_or(Ecart::Forme)?;
    if premier.ends_with(".desktop") || premier.contains(".desktop:") {
        return Err(Ecart::Lanceur);
    }
    lancee(s, commande, profondeur)
}

/// « uwsm app … » (`uwsm_app`), « uwsm finalize [NOM…] » ; tout le reste : lanceur.
fn uwsm(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    match args.split_first() {
        Some((sous, reste)) if sous == "app" => uwsm_app(s, reste, profondeur),
        Some((sous, reste)) if sous == "finalize" => {
            for nom in reste {
                if affectation(&format!("{nom}=")).is_none() || variable_refusee(nom) {
                    return Err(Ecart::Variable);
                }
            }
            Ok(())
        }
        _ => Err(Ecart::Lanceur),
    }
}

/// « `xdg-terminal-exec [--app-id=…] [--title=…] [--hold] [-e] [commande]` » : sans commande, le shell du terminal ;
/// « --dir » (dossier courant changé) et toute autre option : lanceur.
fn terminal_xdg(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        if a == "-e" || a == "--" {
            let reste = args.get(i.saturating_add(1)..).unwrap_or_default();
            return if reste.is_empty() {
                Err(Ecart::Forme)
            } else {
                lancee(s, reste, profondeur)
            };
        }
        if !a.starts_with('-') {
            return lancee(s, args.get(i..).unwrap_or_default(), profondeur);
        }
        i = i.saturating_add(1);
        if a == "--hold" {
            continue;
        }
        if let Some(v) = a.strip_prefix("--app-id=").or_else(|| a.strip_prefix("--title=")) {
            argument_sur(s, v)?;
            continue;
        }
        return Err(Ecart::Lanceur);
    }
    Ok(())
}

/// « hyprctl … » : un répartiteur qui lance (« exec », « execr », une expression Lua « hl.dsp.… ( … ) »), « keyword »,
/// « --batch », « eval », « plugin » : lanceur ; le reste, ses arguments sans chemin dangereux.
fn hyprctl(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    let mut dispatch = false;
    for a in args {
        let minuscules = a.to_ascii_lowercase();
        if minuscules.contains("exec")
            || ["keyword", "--batch", "-b", "eval", "plugin"].contains(&minuscules.as_str())
            || (dispatch && a.contains('('))
        {
            return Err(Ecart::Lanceur);
        }
        dispatch |= a == "dispatch";
        argument_sur(s, a)?;
    }
    Ok(())
}

/// « `flatpak run [--branch=…] [--arch=…] [--command=programme] [--file-forwarding] id.de.l.app [arguments]` » :
/// l'application par son identifiant (au moins trois noms séparés par des points), comme l'écrivent les fichiers
/// qu'exporte Flatpak (« @@u », « @@ » : les fichiers donnés). Un programme de « --command » qui est un shell, un
/// interpréteur ou un lanceur, toute autre option (qui élargirait le bac à sable) ou sous-commande : lanceur.
fn flatpak(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    let (sous, reste) = args.split_first().ok_or(Ecart::Forme)?;
    if sous != "run" {
        return Err(Ecart::Lanceur);
    }
    let mut app = false;
    for a in reste {
        if app {
            if a != "@@" && a != "@@u" {
                argument_sur(s, a)?;
            }
            continue;
        }
        if let Some(c) = a.strip_prefix("--command=") {
            let nom = crate::machine::chasse::nom_de_fichier(c);
            if c.is_empty()
                || (c.contains('/') && !c.starts_with("/app/"))
                || designes::interpreteur(c).is_some()
                || designes::lanceur(c)
                || enveloppe(c)
                || AUTRES_LANCEURS.contains(&nom)
            {
                return Err(Ecart::Lanceur);
            }
            continue;
        }
        if a.starts_with("--branch=") || a.starts_with("--arch=") || a == "--file-forwarding" {
            argument_sur(s, a)?;
            continue;
        }
        if a.starts_with('-') {
            return Err(Ecart::Lanceur);
        }
        let morceaux: Vec<&str> = a.split('.').collect();
        if morceaux.len() < 3
            || !morceaux
                .iter()
                .all(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        {
            return Err(Ecart::Lanceur);
        }
        app = true;
    }
    if app { Ok(()) } else { Err(Ecart::Forme) }
}

/// « systemctl [--user] [--no-block] [-q] verbe [unités | variables] » : démarrer, arrêter, relancer une unité
/// nommée (son fichier, s'il est du compte, est jugé à part) ; poser ou importer des variables qui ne changent pas ce
/// qui se lance. Tout autre verbe ou option : lanceur.
fn systemctl(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    const VERBES: [&str; 16] = [
        "start",
        "stop",
        "restart",
        "reload",
        "try-restart",
        "reload-or-restart",
        "try-reload-or-restart",
        "is-active",
        "is-enabled",
        "is-failed",
        "status",
        "kill",
        "reset-failed",
        "import-environment",
        "set-environment",
        "unset-environment",
    ];
    let mut verbe: Option<&str> = None;
    for a in args {
        if ["--user", "--no-block", "-q", "--quiet", "--no-ask-password", "--wait"].contains(&a.as_str()) {
            continue;
        }
        if a.starts_with('-') {
            return Err(Ecart::Lanceur);
        }
        let Some(v) = verbe else {
            if !VERBES.contains(&a.as_str()) {
                return Err(Ecart::Lanceur);
            }
            verbe = Some(a.as_str());
            continue;
        };
        match v {
            "set-environment" => {
                let (nom, valeur) = affectation(a).ok_or(Ecart::Variable)?;
                affectation_sure(s, nom, valeur)?;
            }
            "import-environment" | "unset-environment" => {
                if affectation(&format!("{a}=")).is_none() || variable_refusee(a) {
                    return Err(Ecart::Variable);
                }
            }
            _ => {
                if a.is_empty()
                    || !a
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | ':' | '\\'))
                {
                    return Err(Ecart::Lanceur);
                }
            }
        }
    }
    if verbe.is_some() { Ok(()) } else { Err(Ecart::Lanceur) }
}

/// « dbus-update-activation-environment [--systemd] [--all] [--verbose] [NOM | NOM=valeur…] ».
fn dbus_update(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    for a in args {
        if ["--systemd", "--all", "--verbose"].contains(&a.as_str()) {
            continue;
        }
        if a.starts_with('-') {
            return Err(Ecart::Lanceur);
        }
        match affectation(a) {
            Some((nom, valeur)) => affectation_sure(s, nom, valeur)?,
            None if affectation(&format!("{a}=")).is_some() && !variable_refusee(a) => {}
            None => return Err(Ecart::Variable),
        }
    }
    Ok(())
}

/// « swayidle [-w] [-d] [-S siège] évènement… » : chaque commande d'un évènement (« timeout N cmd [resume cmd] »,
/// « before-sleep cmd », « after-resume cmd », « lock cmd », « unlock cmd ») est une ligne de shell (swayidle la passe
/// à « sh -c ») ; « -C » (un fichier de configuration non lu) : lanceur.
fn swayidle(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    let ligne = |i: usize| -> Result<(), Ecart> { ligne_a(s, args.get(i).ok_or(Ecart::Forme)?, profondeur) };
    while let Some(a) = args.get(i) {
        match a.as_str() {
            "-w" | "-d" => i = i.saturating_add(1),
            "-S" => {
                argument_sur(s, args.get(i.saturating_add(1)).ok_or(Ecart::Forme)?)?;
                i = i.saturating_add(2);
            }
            "timeout" => {
                let n = args.get(i.saturating_add(1)).ok_or(Ecart::Forme)?;
                if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Ecart::Forme);
                }
                ligne(i.saturating_add(2))?;
                i = i.saturating_add(3);
                if args.get(i).is_some_and(|r| r == "resume") {
                    ligne(i.saturating_add(1))?;
                    i = i.saturating_add(2);
                }
            }
            "before-sleep" | "after-resume" | "lock" | "unlock" => {
                ligne(i.saturating_add(1))?;
                i = i.saturating_add(2);
            }
            "idlehint" => i = i.saturating_add(2),
            _ => return Err(Ecart::Lanceur),
        }
    }
    Ok(())
}

/// « wl-paste [--type t] [--primary] [--no-newline] [--seat s] --watch commande ».
fn wl_paste(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        i = i.saturating_add(1);
        match a.as_str() {
            "-w" | "--watch" => return lancee(s, args.get(i..).unwrap_or_default(), profondeur),
            "-t" | "--type" | "-s" | "--seat" => {
                argument_sur(s, args.get(i).ok_or(Ecart::Forme)?)?;
                i = i.saturating_add(1);
            }
            "-p" | "--primary" | "-n" | "--no-newline" | "-l" | "--list-types" => {}
            _ if a.starts_with("--type=") || a.starts_with("--seat=") => argument_sur(s, a)?,
            _ => return Err(Ecart::Lanceur),
        }
    }
    Ok(())
}

/// « xss-lock [--transfer-sleep-lock] [-l] [-v] [-q] -- commande ».
fn xss_lock(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        i = i.saturating_add(1);
        match a.as_str() {
            "--" => return lancee(s, args.get(i..).unwrap_or_default(), profondeur),
            "--transfer-sleep-lock" | "-l" | "--ignore-sleep" | "-v" | "--verbose" | "-q" | "--quiet" => {}
            _ => return Err(Ecart::Lanceur),
        }
    }
    Err(Ecart::Forme)
}

/// Un argument qu'un script d'Omarchy repasse au shell (« eval ») : un seul mot sans caractère actif.
fn mot_inerte(a: &str) -> bool {
    !a.is_empty()
        && !a.chars().any(|c| {
            c.is_whitespace()
                || matches!(
                    c,
                    ';' | '&'
                        | '|'
                        | '$'
                        | '`'
                        | '('
                        | ')'
                        | '<'
                        | '>'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '\\'
                        | '\''
                        | '"'
                        | '!'
                        | '#'
                        | '~'
                )
        })
}

/// Les lanceurs d'Omarchy (/usr/bin/omarchy-*, lus le 11 nov. 2026) : ce que chacun fait de ses arguments.
/// « `omarchy-launch-or-focus motif [commande]` » évalue la commande (« eval exec setsid … »), ou « uwsm-app -- motif »
/// sans elle ; « omarchy-launch-or-focus-tui » évalue « omarchy-launch-tui $@ » ; « omarchy-launch-tui
/// [--app-id=…] programme args » lance le programme dans un terminal ; « omarchy-launch-terminal [--pid=…] args »
/// passe ses arguments à xdg-terminal-exec ; « omarchy-launch-floating-terminal-with-presentation args » les passe à
/// « bash -c ». Un autre script « omarchy-* » : des arguments d'un seul mot sans caractère actif ; les options d'un
/// navigateur (« --renderer-cmd-prefix »…) en lancent un autre : lanceur.
fn omarchy(s: &Systeme, nom: &str, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    match nom {
        "omarchy-launch-or-focus" => {
            let motif = args.first().ok_or(Ecart::Forme)?;
            argument_sur(s, motif)?;
            for a in args.get(2..).unwrap_or_default() {
                argument_sur(s, a)?;
            }
            match args.get(1) {
                Some(commande) => ligne_a(s, commande, profondeur),
                None => ligne_a(s, &format!("uwsm-app -- {motif}"), profondeur),
            }
        }
        "omarchy-launch-or-focus-tui" => ligne_a(s, &format!("omarchy-launch-tui {}", args.join(" ")), profondeur),
        "omarchy-launch-or-focus-webapp" => {
            for a in args.get(1..).unwrap_or_default() {
                if !mot_inerte(a) || a.starts_with('-') {
                    return Err(Ecart::Lanceur);
                }
            }
            for a in args {
                if !mot_inerte(a) {
                    return Err(Ecart::Lanceur);
                }
                argument_sur(s, a)?;
            }
            Ok(())
        }
        "omarchy-launch-tui" => {
            let reste = match args.first() {
                Some(a) if a.starts_with("--app-id=") => {
                    argument_sur(s, a)?;
                    args.get(1..).unwrap_or_default()
                }
                _ => args,
            };
            lancee(s, reste, profondeur)
        }
        "omarchy-launch-terminal" => {
            let reste = match args.first() {
                Some(a) if a.starts_with("--pid=") => {
                    argument_sur(s, a)?;
                    args.get(1..).unwrap_or_default()
                }
                _ => args,
            };
            terminal_xdg(s, reste, profondeur)
        }
        "omarchy-launch-floating-terminal-with-presentation" => ligne_a(s, &args.join(" "), profondeur),
        _ => {
            let navigateur = nom.contains("webapp") || nom.contains("browser");
            for a in args {
                argument_sur(s, a)?;
                if navigateur && a.starts_with('-') && !["--private", "--new-window"].contains(&a.as_str()) {
                    return Err(Ecart::Lanceur);
                }
                if a.contains(['$', '`', ';', '|', '&']) && !navigateur {
                    return Err(Ecart::Lanceur);
                }
            }
            Ok(())
        }
    }
}

/// Les options sans valeur des terminaux connus.
const DRAPEAUX_TERMINAL: [&str; 20] = [
    "--hold",
    "-H",
    "--server",
    "-s",
    "--maximized",
    "-m",
    "--fullscreen",
    "-F",
    "--login-shell",
    "-L",
    "--single-instance",
    "-1",
    "--detach",
    "--daemon",
    "--no-wait",
    "-q",
    "--quiet",
    "--tab",
    "--window",
    "--print-errors",
];

/// Les options à valeur des terminaux connus (titre, classe, police, configuration, dossier courant…).
const VALEURS_TERMINAL: [&str; 32] = [
    "--class",
    "--title",
    "-T",
    "-t",
    "--app-id",
    "-a",
    "--name",
    "--working-directory",
    "--directory",
    "-D",
    "-d",
    "--config",
    "--config-file",
    "-c",
    "--instance-group",
    "--session",
    "--position",
    "--start-as",
    "--listen-on",
    "--font",
    "-f",
    "--window-size-pixels",
    "-w",
    "--window-size-chars",
    "-W",
    "--log-level",
    "--term",
    "-o",
    "--option",
    "--override",
    "--socket",
    "--profile",
];

/// Un terminal connu : ses options connues, puis la commande (« -e », « -x », « --command », « -- », ou en position
/// pour kitty et foot) ; sans commande, son shell. Une option qui pose le shell ou une commande du terminal
/// (« -o shell=… »), une sous-commande (« kitty +kitten », « kitty @ », « alacritty msg », « wezterm cli ») ou une
/// option inconnue : lanceur.
fn terminal(s: &Systeme, nom: &str, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut args = args;
    match (nom, args.first().map(String::as_str)) {
        ("kitty", Some(a)) if a.starts_with('+') || a == "@" => return Err(Ecart::Lanceur),
        ("alacritty", Some("msg")) => return Err(Ecart::Lanceur),
        ("wezterm", Some("start")) => args = args.get(1..).unwrap_or_default(),
        ("wezterm", Some(a)) if !a.starts_with('-') => return Err(Ecart::Lanceur),
        _ => {}
    }
    let lance = |a: &str| {
        let m = a.to_ascii_lowercase();
        m.contains("shell") || m.contains("command") || m.contains("exec") || m.contains("launch")
    };
    let mut i = 0_usize;
    while let Some(a) = args.get(i) {
        if ["-e", "-x", "--command", "--", "--exec"].contains(&a.as_str()) {
            let reste = args.get(i.saturating_add(1)..).unwrap_or_default();
            return if reste.is_empty() {
                Err(Ecart::Forme)
            } else {
                lancee(s, reste, profondeur)
            };
        }
        if !a.starts_with('-') {
            return lancee(s, args.get(i..).unwrap_or_default(), profondeur);
        }
        i = i.saturating_add(1);
        if DRAPEAUX_TERMINAL.contains(&a.as_str()) {
            continue;
        }
        if VALEURS_TERMINAL.contains(&a.as_str()) {
            let v = args.get(i).ok_or(Ecart::Forme)?;
            if lance(v) {
                return Err(Ecart::Lanceur);
            }
            argument_sur(s, v)?;
            i = i.saturating_add(1);
            continue;
        }
        if let Some((cle, v)) = a.split_once('=')
            && (VALEURS_TERMINAL.contains(&cle) || (nom == "ghostty" && cle.starts_with("--")))
        {
            if lance(a) {
                return Err(Ecart::Lanceur);
            }
            argument_sur(s, v)?;
            continue;
        }
        return Err(Ecart::Lanceur);
    }
    Ok(())
}

/// Un shell : ses options sûres (« -e », « -u », « -x », « -v », « -l », « --login », « --norc », « --noprofile »),
/// puis « -c ligne » (lue comme une ligne de shell) ou un script en chemin absolu sûr. Un shell qui lit son entrée,
/// ou toute autre option (« -O », « -o », « +B », « --rcfile ») : hors liste.
fn shell(s: &Systeme, args: &[String], profondeur: u32) -> Result<(), Ecart> {
    let mut i = 0_usize;
    let mut c = false;
    while let Some(a) = args.get(i) {
        if a == "--" {
            i = i.saturating_add(1);
            break;
        }
        if ["--login", "--norc", "--noprofile"].contains(&a.as_str()) {
            i = i.saturating_add(1);
            continue;
        }
        if let Some(lettres) = a.strip_prefix('-')
            && !lettres.is_empty()
            && lettres.chars().all(|x| "euxvlc".contains(x))
        {
            c |= lettres.contains('c');
            i = i.saturating_add(1);
            continue;
        }
        if a.starts_with(['-', '+']) {
            return Err(Ecart::Lanceur);
        }
        break;
    }
    let reste = args.get(i..).unwrap_or_default();
    let (premier, apres) = reste.split_first().ok_or(Ecart::Forme)?;
    for a in apres {
        argument_sur(s, a)?;
    }
    if c {
        return ligne_a(s, premier, profondeur);
    }
    script(s, premier)
}

/// Un interpréteur qui n'est pas un shell (python, perl, node…) : un script en chemin absolu sûr, sans option avant
/// (« -c », « -m », « -e »… lisent du code d'ailleurs).
fn interprete(s: &Systeme, args: &[String]) -> Result<(), Ecart> {
    let (premier, apres) = args.split_first().ok_or(Ecart::Lanceur)?;
    if premier.starts_with('-') {
        return Err(Ecart::Lanceur);
    }
    for a in apres {
        argument_sur(s, a)?;
    }
    script(s, premier)
}

/// Le script d'un interpréteur : un fichier existant à un chemin absolu sûr.
fn script(s: &Systeme, p: &str) -> Result<(), Ecart> {
    let simple = s.chemin_sur(p, false)?;
    if s.fichier(&simple, false) {
        Ok(())
    } else {
        Err(Ecart::Programme)
    }
}

/// Les fichiers de popt du système trouvés, chacun à root seul ou non : aucun, rien ; tous à root seul, une
/// information ; un seul qui ne l'est pas, levé.
pub(super) fn popt_du_systeme(a_root: &[bool]) -> Result<Option<Ecart>, Ecart> {
    match a_root {
        [] => Ok(None),
        _ if a_root.iter().all(|r| *r) => Ok(Some(Ecart::PoptDuSystemeARoot)),
        _ => Err(Ecart::PoptDuSysteme),
    }
}

/// Le point de montage (cinquième champ) d'une ligne de /proc/self/mountinfo, ses « \\ooo » (espace, tabulation,
/// saut de ligne, barre oblique inverse) remis ; `None` pour une ligne qui n'a pas cette forme.
pub(super) fn point_de_montage(ligne: &str) -> Option<String> {
    let brut = ligne.split(' ').nth(4)?;
    let mut sortie = String::with_capacity(brut.len());
    let mut reste = brut;
    while let Some((avant, apres)) = reste.split_once('\\') {
        sortie.push_str(avant);
        sortie.push(char::from(u8::from_str_radix(apres.get(..3)?, 8).ok()?));
        reste = apres.get(3..)?;
    }
    sortie.push_str(reste);
    Some(sortie)
}

/// Une valeur Exec de systemd (ou de .desktop : `codes` absents, « $ » littéral) : ses codes « % » développés, ses
/// commandes coupées comme systemd les coupe (`commandes_de_systemd_brutes`), les préfixes lus (« | » : lancée par
/// un shell, hors liste ; « : » : pas de variable développée ; « @ » : le nom donné au programme ôté), les variables
/// remplacées par leur valeur connue (`Codes::variables`, « HOME » par le dossier personnel), puis chaque commande
/// jugée comme `lancee`.
///
/// Les informations de `exec_systemd_note` : la première rendue en écart (un appelant qui ne les dit pas à part ne
/// les tait jamais).
pub(super) fn exec_systemd(s: &Systeme, valeur: &str, codes: Option<&Codes>) -> Result<(), Ecart> {
    let mut notes = Vec::new();
    exec_systemd_note(s, valeur, codes, &mut notes)?;
    notes.first().map_or(Ok(()), |n| Err(*n))
}

/// `exec_systemd`, les informations (`Ecart::information`) notées dans `notes` au lieu d'arrêter : la ligne entre dans
/// la liste permise, et ce qui n'a pas été vu se dit à part. Une information n'est jamais rendue en `Err`.
pub(super) fn exec_systemd_note(
    s: &Systeme,
    valeur: &str,
    codes: Option<&Codes>,
    notes: &mut Vec<Ecart>,
) -> Result<(), Ecart> {
    if valeur.len() > LIGNE_MAX {
        return Err(Ecart::Longue);
    }
    let developpee = match codes {
        Some(c) => developper_codes(valeur, c).ok_or(Ecart::Forme)?,
        None => valeur.to_string(),
    };
    for brute in commandes_de_systemd_brutes(&developpee).ok_or(Ecart::Forme)? {
        let (premier, reste) = brute.split_first().ok_or(Ecart::Forme)?;
        let net = premier.trim_start_matches(['-', '@', '+', '!', ':', '|']);
        let prefixes = premier
            .get(..premier.len().saturating_sub(net.len()))
            .unwrap_or_default();
        if prefixes.contains('|') {
            return Err(Ecart::Lanceur);
        }
        let reste = if prefixes.contains('@') {
            reste.get(1..).unwrap_or_default()
        } else {
            reste
        };
        let mut mots = vec![net.to_string()];
        mots.extend(reste.iter().cloned());
        // Un code inconnu (« %i », « %n ») reste un mot qu'aucun programme ne porte ni qu'aucun shell ne lit
        // (`designes::trompeur`) : il n'est permis qu'en argument d'un programme ordinaire.
        let mots = if codes.is_none() || prefixes.contains(':') {
            mots
        } else {
            variables_de_systemd(&mots, codes.map(|c| &c.variables), s.maison)?
        };
        if let Some(p) = codes.and_then(|c| c.sauvegarde.as_ref()) {
            if codes.is_some_and(|c| c.sauvegarde_completee) {
                return Err(Ecart::Complement);
            }
            if codes.is_some_and(|c| c.sauvegarde_environnement) {
                return Err(Ecart::Environnement);
            }
            // La forme exacte ne tient que les mots : où rsync écrit se juge sur le disque (C-2).
            if p.rsync == mots {
                sauvegarde_posee(s, &mots, "rsync", p.env.is_some())?;
                notes.extend(s.reglages_de_popt()?);
                if p.env.is_none() {
                    notes.push(Ecart::AncienneForme);
                }
                match s.destination_sur_le_disque(&p.racine, &p.destination) {
                    Err(e) if e.information() => notes.push(e),
                    r => r?,
                }
                continue;
            }
            if p.findmnt == mots {
                sauvegarde_posee(s, &mots, "findmnt", p.env.is_some())?;
                continue;
            }
        }
        lancee(s, &mots, 0)?;
    }
    Ok(())
}

/// Les mots d'une commande de systemd, leurs variables remplacées comme il les remplace : « $NOM » seul est coupé en
/// mots, « ${NOM} » reste un mot, « $$ » est « $ ». Une variable sans valeur connue, à plusieurs valeurs
/// (`CODE_INCONNU`) ou dont la valeur garde un « $ » : `Ecart::Variable`.
fn variables_de_systemd(
    mots: &[String],
    variables: Option<&std::collections::BTreeMap<String, String>>,
    maison: &str,
) -> Result<Vec<String>, Ecart> {
    let valeur = |nom: &str| -> Result<String, Ecart> {
        let v = match variables.and_then(|v| v.get(nom)) {
            Some(v) => v.clone(),
            None if nom == "HOME" => maison.to_string(),
            None if ["USER", "LOGNAME"].contains(&nom) => "x".to_string(),
            None => return Err(Ecart::Variable),
        };
        if v.contains(['$', CODE_INCONNU]) {
            return Err(Ecart::Variable);
        }
        Ok(v)
    };
    let mut sortie = Vec::with_capacity(mots.len());
    for m in mots {
        if !m.contains('$') {
            sortie.push(m.clone());
            continue;
        }
        if let Some(nom) = m.strip_prefix('$')
            && affectation(&format!("{nom}=")).is_some()
        {
            sortie.extend(valeur(nom)?.split_whitespace().map(str::to_string));
            continue;
        }
        let mut mot = String::with_capacity(m.len());
        let mut reste = m.as_str();
        while let Some(i) = reste.find('$') {
            mot.push_str(reste.get(..i).unwrap_or_default());
            let apres = reste.get(i.saturating_add(1)..).unwrap_or_default();
            if let Some(r) = apres.strip_prefix('$') {
                mot.push('$');
                reste = r;
            } else if let Some((nom, r)) = apres.strip_prefix('{').and_then(|x| x.split_once('}')) {
                if affectation(&format!("{nom}=")).is_none() {
                    return Err(Ecart::Variable);
                }
                mot.push_str(&valeur(nom)?);
                reste = r;
            } else {
                return Err(Ecart::Variable);
            }
        }
        mot.push_str(reste);
        sortie.push(mot);
    }
    Ok(sortie)
}

/// Les clés de `[Unit]` reconnues sûres : décrire, ordonner, dépendre d'unités nommées, borner, conditionner
/// (« Condition… », « Assert… », « StartLimit… » en plus).
const CLES_UNIT: &[&str] = &[
    "Description",
    "Documentation",
    "After",
    "Before",
    "Wants",
    "Requires",
    "Requisite",
    "BindsTo",
    "PartOf",
    "Upholds",
    "Conflicts",
    "OnFailure",
    "OnSuccess",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "OnFailureJobMode",
    "IgnoreOnIsolate",
    "StopWhenUnneeded",
    "RefuseManualStart",
    "RefuseManualStop",
    "AllowIsolate",
    "DefaultDependencies",
    "CollectMode",
    "FailureAction",
    "SuccessAction",
    "FailureActionExitStatus",
    "SuccessActionExitStatus",
    "JobTimeoutSec",
    "JobRunningTimeoutSec",
    "JobTimeoutAction",
    "SourcePath",
    "RequiresMountsFor",
    "WantsMountsFor",
    "SurviveFinalKillSignal",
];

/// Les clés de ressources (toutes dans `CLES_SERVICE`) dont la valeur peut être un pourcentage, que systemd lit sans
/// développer de code « % ».
const POURCENTS: &[&str] = &[
    "CPUQuota",
    "MemoryHigh",
    "MemoryMax",
    "MemoryLow",
    "MemoryMin",
    "MemorySwapMax",
    "MemoryZSwapMax",
    "TasksMax",
    "ManagedOOMMemoryPressureLimit",
];

/// Un pourcentage écrit exactement : des chiffres, une partie décimale facultative, puis « % » (« 20% », « 12.5% »).
fn pourcentage(valeur: &str) -> bool {
    let Some(nombre) = valeur.strip_suffix('%') else {
        return false;
    };
    let (entier, decimales) = nombre.split_once('.').unwrap_or((nombre, "0"));
    let chiffres = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    chiffres(entier) && chiffres(decimales)
}

/// Les clés d'exécution et de bornes communes à `[Service]`, `[Socket]` et `[Scope]` reconnues sûres : relance, temps,
/// signaux, priorité, journal, ressources, durcissement (qui ne fait que retirer des droits), dossiers nommés
/// (« RuntimeDirectory= » : un nom sous le dossier de systemd), variables vérifiées (`variable_d_unite_sure`).
/// « Limit… » et « StartLimit… » en plus.
const CLES_SERVICE: &[&str] = &[
    "Type",
    "ExitType",
    "RemainAfterExit",
    "GuessMainPID",
    "PIDFile",
    "BusName",
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
    "Restart",
    "RestartSec",
    "RestartSteps",
    "RestartMaxDelaySec",
    "RestartMode",
    "RestartPreventExitStatus",
    "RestartForceExitStatus",
    "SuccessExitStatus",
    "TimeoutSec",
    "TimeoutStartSec",
    "TimeoutStopSec",
    "TimeoutAbortSec",
    "TimeoutStartFailureMode",
    "TimeoutStopFailureMode",
    "RuntimeMaxSec",
    "RuntimeRandomizedExtraSec",
    "WatchdogSec",
    "NotifyAccess",
    "FileDescriptorStoreMax",
    "FileDescriptorStorePreserve",
    "KillMode",
    "KillSignal",
    "RestartKillSignal",
    "FinalKillSignal",
    "WatchdogSignal",
    "SendSIGKILL",
    "SendSIGHUP",
    "Delegate",
    "DelegateSubgroup",
    "AddRef",
    "Slice",
    "Nice",
    "IOSchedulingClass",
    "IOSchedulingPriority",
    "CPUSchedulingPolicy",
    "CPUSchedulingPriority",
    "CPUSchedulingResetOnFork",
    "OOMScoreAdjust",
    "OOMPolicy",
    "Environment",
    "EnvironmentFile",
    "PassEnvironment",
    "UnsetEnvironment",
    "WorkingDirectory",
    "StandardInput",
    "StandardOutput",
    "StandardError",
    "SyslogIdentifier",
    "SyslogLevel",
    "SyslogFacility",
    "SyslogLevelPrefix",
    "LogLevelMax",
    "LogRateLimitIntervalSec",
    "LogRateLimitBurst",
    "TTYPath",
    "TTYReset",
    "TTYVHangup",
    "TTYVTDisallocate",
    "UMask",
    "KeyringMode",
    "MemoryAccounting",
    "MemoryHigh",
    "MemoryMax",
    "MemoryLow",
    "MemoryMin",
    "MemorySwapMax",
    "MemoryZSwapMax",
    "CPUAccounting",
    "CPUWeight",
    "StartupCPUWeight",
    "CPUQuota",
    "CPUQuotaPeriodSec",
    "AllowedCPUs",
    "IOAccounting",
    "IOWeight",
    "StartupIOWeight",
    "TasksAccounting",
    "TasksMax",
    "IPAccounting",
    "IPAddressAllow",
    "IPAddressDeny",
    "ManagedOOMMemoryPressure",
    "ManagedOOMMemoryPressureLimit",
    "ManagedOOMSwap",
    "ManagedOOMPreference",
    "NoNewPrivileges",
    "PrivateTmp",
    "PrivateDevices",
    "PrivateNetwork",
    "PrivateUsers",
    "PrivateIPC",
    "PrivateMounts",
    "ProtectSystem",
    "ProtectHome",
    "ProtectProc",
    "ProcSubset",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectKernelLogs",
    "ProtectControlGroups",
    "ProtectClock",
    "ProtectHostname",
    "RestrictNamespaces",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "RestrictAddressFamilies",
    "LockPersonality",
    "MemoryDenyWriteExecute",
    "RemoveIPC",
    "SystemCallArchitectures",
    "SystemCallFilter",
    "SystemCallErrorNumber",
    "CapabilityBoundingSet",
    // Vide seulement (point 11, 0.95) : la forme des unités de Vanguard, qui vide les droits ambiants ; toute valeur
    // en donne (« ~… » : tous sauf ceux-là), jugée dans `directive`.
    "AmbientCapabilities",
    "ReadOnlyPaths",
    "ReadWritePaths",
    "InaccessiblePaths",
    "RuntimeDirectory",
    "StateDirectory",
    "CacheDirectory",
    "LogsDirectory",
    "ConfigurationDirectory",
    "RuntimeDirectoryMode",
    "StateDirectoryMode",
    "CacheDirectoryMode",
    "LogsDirectoryMode",
    "ConfigurationDirectoryMode",
    "RuntimeDirectoryPreserve",
];

/// Les clés de `[Install]`, `[Timer]`, `[Path]`, `[Socket]` (en plus des communes), `[Slice]`, `[Scope]` et
/// `[D-BUS Service]` reconnues sûres.
const CLES_INSTALL: &[&str] = &["WantedBy", "RequiredBy", "UpheldBy", "Also", "Alias", "DefaultInstance"];
const CLES_TIMER: &[&str] = &[
    "OnActiveSec",
    "OnBootSec",
    "OnStartupSec",
    "OnUnitActiveSec",
    "OnUnitInactiveSec",
    "OnCalendar",
    "AccuracySec",
    "RandomizedDelaySec",
    "RandomizedOffsetSec",
    "FixedRandomDelay",
    "DeferReactivation",
    "OnClockChange",
    "OnTimezoneChange",
    "Persistent",
    "WakeSystem",
    "RemainAfterElapse",
    "Unit",
];
const CLES_PATH: &[&str] = &[
    "PathExists",
    "PathExistsGlob",
    "PathChanged",
    "PathModified",
    "DirectoryNotEmpty",
    "Unit",
    "MakeDirectory",
    "DirectoryMode",
    "TriggerLimitIntervalSec",
    "TriggerLimitBurst",
];
const CLES_SOCKET: &[&str] = &[
    "ListenStream",
    "ListenDatagram",
    "ListenSequentialPacket",
    "ListenFIFO",
    "ListenSpecial",
    "ListenNetlink",
    "Accept",
    "Service",
    "SocketMode",
    "SocketUser",
    "SocketGroup",
    "DirectoryMode",
    "RemoveOnStop",
    "Symlinks",
    "FileDescriptorName",
    "PassCredentials",
    "PassSecurity",
    "PassPacketInfo",
    "ReceiveBuffer",
    "SendBuffer",
    "Backlog",
    "MaxConnections",
    "MaxConnectionsPerSource",
    "KeepAlive",
    "NoDelay",
    "Priority",
    "FlushPending",
    "Writable",
    "TriggerLimitIntervalSec",
    "TriggerLimitBurst",
    "PollLimitIntervalSec",
    "PollLimitBurst",
];
const CLES_DBUS: &[&str] = &["Name", "Exec", "User", "SystemdService", "AssumedAppArmorLabel"];

/// Les clés qui nomment d'autres unités : un nom sans chemin ni code ; pour celles qui en démarrent une, pas
/// d'instance d'un modèle (« a@b.service » : le modèle reçoit l'instance en « %i », vérification 3, P9).
const DEPENDANCES: &[&str] = &[
    "After",
    "Before",
    "Wants",
    "Requires",
    "Requisite",
    "BindsTo",
    "PartOf",
    "Upholds",
    "Conflicts",
    "OnFailure",
    "OnSuccess",
    "PropagatesReloadTo",
    "ReloadPropagatedFrom",
    "PropagatesStopTo",
    "StopPropagatedFrom",
    "WantedBy",
    "RequiredBy",
    "UpheldBy",
    "Also",
    "Alias",
    "Unit",
    "Service",
    "SystemdService",
    "Slice",
];
pub(super) const DEMARRENT: &[&str] = &[
    "Wants",
    "Requires",
    "Requisite",
    "BindsTo",
    "Upholds",
    "OnFailure",
    "OnSuccess",
    "Unit",
    "Service",
    "SystemdService",
    "Also",
    "UpheldBy",
];

/// Les clés dont la valeur ne lance rien et ne se lit pas comme du code (texte, dépendances, conditions, prises et
/// fichiers de systemd, dossiers bornés), ou qui se vérifient à part (Exec, variables) : le filet n'y cherche pas
/// de chemin. Une prise dans le dossier de session (« ListenStream=%t/x.sock ») est la forme ordinaire.
fn sans_filet(cle: &str) -> bool {
    const CLES: &[&str] = &[
        "Description",
        "Documentation",
        "SourcePath",
        "Name",
        "SyslogIdentifier",
        "Environment",
        "EnvironmentFile",
        "WorkingDirectory",
        "PIDFile",
        "ReadOnlyPaths",
        "ReadWritePaths",
        "InaccessiblePaths",
        "Symlinks",
        "DirectoryNotEmpty",
        "TTYPath",
    ];
    CLES.contains(&cle)
        || DEPENDANCES.contains(&cle)
        || ["Condition", "Assert", "Exec", "Listen", "Path"]
            .iter()
            .any(|d| cle.starts_with(d))
}

/// Une ligne d'unité (ou d'ajout, ou de service D-Bus) du compte, dans sa `section` : sa clé dans la liste fermée de
/// la section, sa valeur vérifiée (dépendances, entrée et sorties, dossier courant, variables, fichier de variables),
/// sans chemin temporaire ou caché hors des clés de `sans_filet` ; sinon l'écart. Une section « X-… » ou une clé
/// « X-… » : ignorées par systemd. Les lignes Exec sont acceptées ici et jugées chacune comme une commande lancée.
pub(super) fn directive(s: &Systeme, codes: &Codes, section: Option<&str>, ligne: &str) -> Result<(), Ecart> {
    let (cle, valeur) = ligne.split_once('=').ok_or(Ecart::Directive)?;
    let cle = cle.trim_matches([' ', '\t']);
    let valeur = valeur.trim_matches([' ', '\t']);
    let section = section.ok_or(Ecart::Directive)?;
    if section.starts_with("X-") || cle.starts_with("X-") {
        return Ok(());
    }
    let prefixee = |debuts: &[&str]| debuts.iter().any(|d| cle.starts_with(d));
    let ressource = || {
        CLES_SERVICE.contains(&cle)
            && ["Memory", "CPU", "IO", "Tasks", "ManagedOOM", "Allowed", "IP", "Startup"]
                .iter()
                .any(|d| cle.starts_with(d))
    };
    let permise = match section {
        "Unit" => CLES_UNIT.contains(&cle) || prefixee(&["Condition", "Assert", "StartLimit"]),
        "Service" => CLES_SERVICE.contains(&cle) || prefixee(&["Limit", "StartLimit"]),
        "Socket" => CLES_SOCKET.contains(&cle) || CLES_SERVICE.contains(&cle) || prefixee(&["Limit"]),
        "Scope" => {
            ressource()
                || [
                    "Slice",
                    "Delegate",
                    "DelegateSubgroup",
                    "KillMode",
                    "KillSignal",
                    "FinalKillSignal",
                    "SendSIGKILL",
                    "SendSIGHUP",
                    "TimeoutStopSec",
                    "RuntimeMaxSec",
                    "RuntimeRandomizedExtraSec",
                    "OOMPolicy",
                    "AddRef",
                ]
                .contains(&cle)
        }
        "Slice" => ressource(),
        "Install" => CLES_INSTALL.contains(&cle),
        "Timer" => CLES_TIMER.contains(&cle),
        "Path" => CLES_PATH.contains(&cle),
        "D-BUS Service" => CLES_DBUS.contains(&cle),
        _ => false,
    };
    if !permise {
        return Err(Ecart::Directive);
    }
    // Une limite de ressource en pourcentage (« CPUQuota=20% ») : systemd n'y développe aucun code, le « % » final
    // est l'unité. La forme exacte seule (chiffres, une décimale facultative, « % ») ; toute autre valeur à « % »
    // (« CPUQuota=%h ») reste non lue.
    if POURCENTS.contains(&cle) && valeur.contains('%') {
        return if pourcentage(valeur) {
            Ok(())
        } else {
            Err(Ecart::Directive)
        };
    }
    if DEPENDANCES.contains(&cle) {
        for nom in valeur.split_whitespace() {
            let instance = nom.split_once('@').is_some_and(|(_, apres)| !apres.starts_with('.'));
            if nom.contains(['%', '/', '$', '\\']) || (DEMARRENT.contains(&cle) && instance) {
                return Err(Ecart::Directive);
            }
        }
        return Ok(());
    }
    let valeur = developper_codes(valeur, codes).ok_or(Ecart::Directive)?;
    match cle {
        "Environment" => {
            for mot in commandes_de_systemd_brutes(&valeur)
                .ok_or(Ecart::Directive)?
                .into_iter()
                .flatten()
            {
                let (nom, v) = affectation(&mot).ok_or(Ecart::Directive)?;
                variable_d_unite_sure(s, nom, v)?;
            }
        }
        "EnvironmentFile" => {
            for (nom, v) in variables_d_un_fichier(s, &valeur)? {
                variable_d_unite_sure(s, &nom, &v)?;
            }
        }
        "AmbientCapabilities" if !valeur.is_empty() => return Err(Ecart::Directive),
        "PassEnvironment" | "UnsetEnvironment" => {
            for nom in valeur.split_whitespace() {
                if affectation(&format!("{nom}=")).is_none() || (cle == "PassEnvironment" && variable_refusee(nom)) {
                    return Err(Ecart::Directive);
                }
            }
        }
        "StandardInput" => {
            if !["null", "tty", "tty-force", "tty-fail", ""].contains(&valeur.as_str()) {
                return Err(Ecart::Directive);
            }
        }
        "StandardOutput" | "StandardError" => {
            if ["file:", "append:", "truncate:", "fd:"]
                .iter()
                .any(|p| valeur.starts_with(p))
            {
                return Err(Ecart::Directive);
            }
        }
        "WorkingDirectory" => {
            let d = valeur.trim_start_matches('-');
            if d.contains(CODE_INCONNU) {
                return Err(Ecart::Directive);
            }
            if d != "~" && !d.is_empty() {
                let d = d
                    .strip_prefix("~/")
                    .map_or_else(|| d.to_string(), |r| format!("{}/{r}", s.maison));
                s.chemin_sur(&d, true)?;
                if s.cache(&format!("{}/", d.trim_end_matches('/')), true) {
                    return Err(Ecart::Filet);
                }
            }
        }
        _ => {}
    }
    if !sans_filet(cle) && filet(&valeur, true, s.maisons) {
        return Err(Ecart::Filet);
    }
    Ok(())
}

/// Une variable posée par une unité du compte (« Environment= », ou son fichier de variables) : une variable de
/// recherche ou d'injection n'a que des chemins absolus (un morceau relatif ou vide se lit depuis le dossier courant,
/// la maison : vérification 3, P4) ; une variable qui nomme un programme (EDITOR, SSH_ASKPASS…) nomme un seul
/// programme trouvé ; « unixexec: » dans l'adresse d'un bus lance un programme ; une valeur qui garde un « $ » ou un
/// code inconnu ne se connaît pas. Le filet en plus, sauf pour une prise du dossier de session
/// (« SSH_AUTH_SOCK=%t/… », « DBUS_SESSION_BUS_ADDRESS=unix:path=%t/bus »).
fn variable_d_unite_sure(s: &Systeme, nom: &str, valeur: &str) -> Result<(), Ecart> {
    let valeur = valeur.trim_matches(|c| c == '"' || c == '\'');
    if nom.starts_with("DBUS_") && valeur.contains("unixexec:") {
        return Err(Ecart::Directive);
    }
    let recherche = nom == "PATH" || nom.ends_with("PATH") || variable_d_injection(nom);
    let sensible = recherche || variable_de_programme(nom) || variable_refusee(nom);
    if sensible && valeur.contains(['$', CODE_INCONNU]) {
        return Err(Ecart::Variable);
    }
    if recherche {
        for m in valeur.split([':', ';']) {
            if !m.starts_with('/') && !m.starts_with("~/") {
                return Err(Ecart::Chemin);
            }
        }
    }
    if variable_de_programme(nom) {
        if valeur.split_whitespace().nth(1).is_some() {
            return Err(Ecart::Variable);
        }
        s.programme(valeur).map_err(|_| Ecart::Variable)?;
    }
    let prise = !sensible || nom.starts_with("DBUS_");
    let prise = prise
        && ["SOCK", "SOCKET", "_ADDRESS", "DISPLAY"]
            .iter()
            .any(|x| nom.ends_with(x));
    let dangereux = morceaux(valeur)
        .any(|m| morceau_cache(m, true, s.maisons) && !(prise && m.starts_with("/run/user/") && !m.contains("/../")));
    if dangereux {
        return Err(Ecart::Filet);
    }
    Ok(())
}

/// Les variables d'un fichier de variables d'unité (« EnvironmentFile= », chemin absolu, « - » en tête : facultatif),
/// lu entier (`lire_variables`) ; un fichier absent ne pose rien. Un chemin à joker, relatif ou à code inconnu, un
/// fichier illisible ou trop gros : `Ecart::Fichier` (vérification 3, P5 : jamais un plafond muet).
fn variables_d_un_fichier(s: &Systeme, valeur: &str) -> Result<Vec<(String, String)>, Ecart> {
    let chemin = valeur.strip_prefix('-').unwrap_or(valeur);
    if chemin.contains(['*', '?', '[', CODE_INCONNU]) || !chemin.starts_with('/') {
        return Err(Ecart::Fichier);
    }
    if filet(chemin, true, s.maisons) {
        return Err(Ecart::Filet);
    }
    lire_variables(&s.sous(&chemin_simplifie(chemin)))
}

/// Les variables d'un fichier de variables d'unité, lu sous la racine, comme systemd le lit (`variables_de_texte`).
/// Absent : aucune. Illisible ou plus gros que `VARIABLES_MAX` : `Ecart::Fichier`.
pub(super) fn lire_variables(chemin: &Path) -> Result<Vec<(String, String)>, Ecart> {
    let lu = match temoins::lire_borne(chemin, VARIABLES_MAX) {
        Ok(lu) => lu,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(Ecart::Fichier),
    };
    if !lu.entier {
        return Err(Ecart::Fichier);
    }
    Ok(variables_de_texte(&String::from_utf8_lossy(&lu.octets)))
}

/// `lire_variables` sur un texte déjà lu. On réunit deux lectures pour ne jamais voir MOINS de variables qu'avant
/// (R-3, lot 096) : celle, fidèle à systemd (`variables_comme_systemd`), et l'ancienne (`variables_recollees`),
/// gardée telle quelle. L'ancienne recollait toute ligne finie par « \ » à la suivante, commentaire ou clé sans « = »
/// compris : un « LD_PRELOAD=… » caché derrière « # …\ », derrière une ligne de remplissage « FOO\ » (ronde 3, N1)
/// ou après un « \r » nu échappait au juge des unités permises, et l'unité passait pour sûre à tort. Elle ne
/// défaisait pas non plus les « \x » d'une valeur (N2). La lecture fidèle voit tout cela.
pub(super) fn variables_de_texte(texte: &str) -> Vec<(String, String)> {
    let mut variables = variables_comme_systemd(texte);
    for v in variables_recollees(texte) {
        if !variables.contains(&v) {
            variables.push(v);
        }
    }
    variables
}

/// La variable d'une ligne « [export ] NOM=valeur » : « export » ôté, guillemets simples ou doubles autour de la
/// valeur ôtés. Sans « = » : rien.
fn affectation_de_variable(ligne: &str) -> Option<(String, String)> {
    let l = ligne.trim();
    let l = l.strip_prefix("export ").unwrap_or(l).trim_start();
    let (nom, valeur) = l.split_once('=')?;
    Some((nom.trim().to_string(), sans_guillemets(valeur.trim()).to_string()))
}

/// Une valeur sans les guillemets simples ou doubles qui l'entourent, s'il y en a une paire.
fn sans_guillemets(valeur: &str) -> &str {
    valeur
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| valeur.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(valeur)
}

/// Où en est la lecture d'un fichier de variables, état pour état comme `parse_env_file_internal` de systemd.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EtatDeVariables {
    /// Début de ligne : blancs sautés ; « # » ou « ; » ouvre un commentaire.
    AvantCle,
    /// Dans le nom : « \ » y est un caractère ordinaire ; une fin de ligne sans « = » oublie tout.
    Cle,
    /// Après « = », avant le premier caractère de la valeur (ou après un morceau entre guillemets).
    AvantValeur,
    /// Valeur sans guillemets.
    Valeur,
    /// Juste après un « \ » d'une valeur sans guillemets.
    ValeurEchappee,
    /// Entre guillemets simples : rien n'est défait.
    Simples,
    /// Entre guillemets doubles.
    Doubles,
    /// Juste après un « \ » entre guillemets doubles.
    DoublesEchappes,
    /// Commentaire : finit à la première fin de ligne, même après un « \ » (systemd 254 et suivants).
    Commentaire,
}

/// Fins de ligne de systemd (`NEWLINE`) : « \r » nu compte.
const FINS_DE_SYSTEMD: [char; 2] = ['\n', '\r'];

/// Les variables lues comme systemd lit un fichier de variables (« EnvironmentFile= ») : la machine à états de
/// `parse_env_file_internal` (`src/basic/env-file.c`), portée état pour état et comparée au vrai lecteur de systemd
/// 262.1 (ronde 3 du lot 096, bac à sable). La continuation (« \ » en fin de ligne) n'existe QUE dans une valeur :
/// avant le premier « = », « \ » est un caractère ordinaire et la fin de ligne remet tout à zéro (N1). Les
/// échappements d'une valeur sont défaits selon l'état : hors guillemets « \x » vaut « x » ; entre guillemets doubles,
/// seuls « \" \\ \` \$ » perdent leur « \ » ; entre guillemets simples, rien (N2). Chaque variable sort sous sa forme
/// défaite (celle que le service reçoit) et, si elle diffère, sous sa forme brute (texte écrit, continuations
/// recollées, guillemets d'autour ôtés) : les deux se jugent. systemd rejette ensuite les noms invalides et un fichier
/// hors UTF-8 ; ici on garde tout (lecture avec pertes) : on voit plus, jamais moins.
fn variables_comme_systemd(texte: &str) -> Vec<(String, String)> {
    use EtatDeVariables::{
        AvantCle, AvantValeur, Cle, Commentaire, Doubles, DoublesEchappes, Simples, Valeur, ValeurEchappee,
    };
    let blanc = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r');
    let mut out = Vec::new();
    let mut etat = AvantCle;
    let (mut cle, mut valeur, mut brut) = (String::new(), String::new(), String::new());
    // Où couper les blancs de fin du nom et de la valeur (`last_key_whitespace`, `last_value_whitespace`).
    let (mut fin_de_cle, mut fin_de_valeur): (Option<usize>, Option<usize>) = (None, None);
    let mut pousser =
        |cle: &mut String, valeur: &mut String, brut: &mut String, fin_de_cle: Option<usize>, coupe: Option<usize>| {
            if let Some(n) = fin_de_cle {
                cle.truncate(n);
            }
            if let Some(n) = coupe {
                valeur.truncate(n);
            }
            let brute = sans_guillemets(brut.trim_matches(blanc)).to_string();
            let defaite = std::mem::take(valeur);
            if brute != defaite {
                out.push((cle.clone(), brute));
            }
            out.push((std::mem::take(cle), defaite));
            brut.clear();
        };
    for c in texte.chars() {
        match etat {
            AvantCle if c == '#' || c == ';' => etat = Commentaire,
            AvantCle if !blanc(c) => {
                etat = Cle;
                fin_de_cle = None;
                cle.push(c);
            }
            AvantCle => {}
            Cle if FINS_DE_SYSTEMD.contains(&c) => {
                etat = AvantCle;
                cle.clear();
            }
            Cle if c == '=' => {
                etat = AvantValeur;
                fin_de_valeur = None;
            }
            Cle => {
                if !blanc(c) {
                    fin_de_cle = None;
                } else if fin_de_cle.is_none() {
                    fin_de_cle = Some(cle.len());
                }
                cle.push(c);
            }
            AvantValeur if FINS_DE_SYSTEMD.contains(&c) => {
                etat = AvantCle;
                pousser(&mut cle, &mut valeur, &mut brut, fin_de_cle, None);
            }
            AvantValeur => {
                brut.push(c);
                match c {
                    '\'' => etat = Simples,
                    '"' => etat = Doubles,
                    '\\' => etat = ValeurEchappee,
                    _ if !blanc(c) => {
                        etat = Valeur;
                        valeur.push(c);
                    }
                    _ => {}
                }
            }
            Valeur if FINS_DE_SYSTEMD.contains(&c) => {
                etat = AvantCle;
                pousser(&mut cle, &mut valeur, &mut brut, fin_de_cle, fin_de_valeur);
            }
            Valeur if c == '\\' => {
                brut.push(c);
                etat = ValeurEchappee;
                fin_de_valeur = None;
            }
            Valeur => {
                brut.push(c);
                if !blanc(c) {
                    fin_de_valeur = None;
                } else if fin_de_valeur.is_none() {
                    fin_de_valeur = Some(valeur.len());
                }
                valeur.push(c);
            }
            ValeurEchappee => {
                etat = Valeur;
                if FINS_DE_SYSTEMD.contains(&c) {
                    // Une continuation : le « \ » et la fin de ligne disparaissent, dans les deux formes.
                    brut.pop();
                } else {
                    brut.push(c);
                    valeur.push(c);
                }
            }
            Simples => {
                brut.push(c);
                if c == '\'' {
                    etat = AvantValeur;
                } else {
                    valeur.push(c);
                }
            }
            Doubles => {
                brut.push(c);
                match c {
                    '"' => etat = AvantValeur,
                    '\\' => etat = DoublesEchappes,
                    _ => valeur.push(c),
                }
            }
            DoublesEchappes => {
                etat = Doubles;
                if matches!(c, '"' | '\\' | '`' | '$') {
                    brut.push(c);
                    valeur.push(c);
                } else if c == '\n' {
                    brut.pop();
                } else {
                    brut.push(c);
                    valeur.push('\\');
                    valeur.push(c);
                }
            }
            Commentaire if FINS_DE_SYSTEMD.contains(&c) => etat = AvantCle,
            Commentaire => {}
        }
    }
    // Fin du fichier dans une valeur : elle compte (les blancs de fin ne s'ôtent que hors guillemets) ; dans un nom
    // sans « = » ou un commentaire : rien.
    if !matches!(etat, AvantCle | Cle | Commentaire) {
        let coupe = if etat == Valeur { fin_de_valeur } else { None };
        pousser(&mut cle, &mut valeur, &mut brut, fin_de_cle, coupe);
    }
    out
}

/// L'ancienne lecture, gardée pour la réunion (ne jamais voir moins qu'avant) : toute ligne finie par « \ » est
/// recollée à la suivante AVANT de chercher un commentaire, puis le commentaire générique saute la ligne recollée.
fn variables_recollees(texte: &str) -> Vec<(String, String)> {
    let mut lignes: Vec<String> = Vec::new();
    let mut courante = String::new();
    for l in texte.lines() {
        let l = l.strip_suffix('\r').unwrap_or(l);
        if let Some(debut) = l.strip_suffix('\\') {
            courante.push_str(debut);
            continue;
        }
        courante.push_str(l);
        lignes.push(std::mem::take(&mut courante));
    }
    if !courante.is_empty() {
        lignes.push(courante);
    }
    lignes
        .iter()
        .filter(|l| !commentaire(l))
        .filter_map(|l| affectation_de_variable(l))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Ecart, LieuxNonLus, NOMS_LUS_MAX, PROFONDEUR_DES_LIEUX};

    /// A-3 (revérification 6) : chaque cause des lieux non lus se dit, en français et en anglais, avec les vraies
    /// bornes ; les quatre textes diffèrent entre eux et du constat général, et aucun n'est une simple information.
    #[test]
    fn la_cause_des_lieux_non_lus_se_dit() {
        let causes = [
            LieuxNonLus::Entrees,
            LieuxNonLus::Profondeur,
            LieuxNonLus::Lecture,
            LieuxNonLus::HorsRacine,
        ];
        for (anglais, nom, entrees, niveaux) in [
            (
                false,
                "lien physique",
                format!("{NOMS_LUS_MAX} entrées"),
                format!("{PROFONDEUR_DES_LIEUX} niveaux"),
            ),
            (
                true,
                "hard link",
                format!("{NOMS_LUS_MAX} entries"),
                format!("{PROFONDEUR_DES_LIEUX} levels"),
            ),
        ] {
            let lire = |e: Ecart| {
                if anglais {
                    crate::langue::en_anglais(|| e.raison())
                } else {
                    e.raison()
                }
            };
            let textes: Vec<&str> = causes.map(|c| lire(Ecart::AutreNomNonCherche(c))).to_vec();
            assert!(textes.iter().all(|t| t.contains(nom)), "{textes:#?}");
            assert!(textes.first().is_some_and(|t| t.contains(&entrees)), "{textes:#?}");
            assert!(textes.get(1).is_some_and(|t| t.contains(&niveaux)), "{textes:#?}");
            let differents: std::collections::BTreeSet<&str> = textes.iter().copied().collect();
            assert_eq!(differents.len(), causes.len());
            assert!(!differents.contains(lire(Ecart::LieuDeDemarrage)));
        }
        assert!(causes.iter().all(|c| !Ecart::AutreNomNonCherche(*c).information()));
    }

    /// R-3 (lot 096) : un « LD_PRELOAD=… » caché derrière un commentaire fini par « \ », ou après un « \r » nu, est
    /// bien lu — comme systemd lit un fichier de variables. L'ancienne lecture recollait le commentaire à la ligne
    /// suivante et jugeait le tout commentaire, cachant la variable au juge des unités permises. Un vrai commentaire
    /// (sans « \ ») reste sauté, « ; » aussi, et une vraie valeur continuée (« \ » en fin de ligne de valeur) se
    /// recolle toujours.
    #[test]
    fn variable_cachee_derriere_un_commentaire_vue() {
        use super::variables_de_texte;
        let cle = ("LD_PRELOAD".to_string(), "/home/alice/.x/l.so".to_string());
        // Commentaire fini par « \ » : systemd le ferme sur sa ligne ; la variable d'après compte.
        assert!(variables_de_texte("# note \\\nLD_PRELOAD=/home/alice/.x/l.so\n").contains(&cle));
        // « \r » nu comme fin de ligne : la variable après le commentaire compte.
        assert!(variables_de_texte("# note\rLD_PRELOAD=/home/alice/.x/l.so\n").contains(&cle));
        // Un vrai commentaire (sans « \ ») reste sauté ; seule la variable d'après est lue.
        let v = variables_de_texte("# juste un commentaire\nLD_PRELOAD=/home/alice/.x/l.so\n");
        assert_eq!(v, vec![cle.clone()]);
        // « ; » est aussi un commentaire de systemd.
        assert!(
            !variables_de_texte("; LD_PRELOAD=/x\n")
                .iter()
                .any(|(n, _)| n == "LD_PRELOAD")
        );
        // Une vraie valeur finie par « \ » se recolle à la suivante.
        assert_eq!(
            variables_de_texte("FOO=a\\\nbar\n"),
            vec![("FOO".to_string(), "abar".to_string())]
        );
    }

    /// Ronde 3 du lot 096 (N1) : avant le premier « = » d'une ligne, « \ » est un caractère comme un autre pour
    /// systemd (`env-file.c`, état « clé ») et la fin de ligne remet tout à zéro : une ligne de remplissage sans « = »
    /// finie par « \ » n'avale PAS la ligne suivante. Vanguard la recollait, et « LD_PRELOAD=… » devenait la clé
    /// « FOOLD_PRELOAD » : l'unité se taisait. Mesuré sur le lecteur de systemd 262.1 (bac à sable, faux /etc).
    #[test]
    fn continuation_seulement_dans_une_valeur() {
        use super::variables_de_texte;
        let cle = ("LD_PRELOAD".to_string(), "/usr/lib/x.so".to_string());
        for devant in [
            "FOO\\\n",
            "un mot\\\\\\\n",
            "\\\n",
            "  FOO \\\n",
            "FOO\\\r\n",
            "FOO\\\r",
        ] {
            let texte = format!("{devant}LD_PRELOAD=/usr/lib/x.so\n");
            assert!(variables_de_texte(&texte).contains(&cle), "{texte:?}");
        }
        // Témoin : dans une valeur, la continuation existe bien (la ligne d'après fait partie de la valeur).
        let v = variables_de_texte("FOO=a\\\nLD_PRELOAD=/usr/lib/x.so\n");
        assert!(
            v.contains(&("FOO".to_string(), "aLD_PRELOAD=/usr/lib/x.so".to_string())),
            "{v:?}"
        );
    }

    /// Ronde 3 du lot 096 (N2) : les échappements d'une valeur sont défaits comme systemd les défait, selon l'état :
    /// hors guillemets, « \x » vaut « x » ; entre guillemets doubles, seuls « \" \\ \` \$ » perdent leur « \ » ; entre
    /// guillemets simples, rien. La forme défaite (celle que le service reçoit) ET la forme brute sont rendues : un
    /// juge qui ne voyait que « /home/alice/\.x » ne voyait pas le dossier caché « /home/alice/.x ».
    #[test]
    fn echappements_defaits_comme_systemd() {
        use super::variables_de_texte;
        let paire = |n: &str, v: &str| (n.to_string(), v.to_string());
        let v = variables_de_texte("PATH=/home/alice/\\.x:/usr/bin\n");
        assert!(v.contains(&paire("PATH", "/home/alice/.x:/usr/bin")), "{v:?}");
        assert!(v.contains(&paire("PATH", "/home/alice/\\.x:/usr/bin")), "{v:?}");
        let v = variables_de_texte("LD_LIBRARY_PATH=/tm\\p/.x\n");
        assert!(v.contains(&paire("LD_LIBRARY_PATH", "/tmp/.x")), "{v:?}");
        // Entre guillemets doubles, « \. » reste tel quel ; « \" » et « \$ » perdent leur « \ ».
        let v = variables_de_texte("A=\"/home/alice/\\.x\"\nB=\"x\\\"y\\$z\"\n");
        assert!(v.contains(&paire("A", "/home/alice/\\.x")), "{v:?}");
        assert!(v.contains(&paire("B", "x\"y$z")), "{v:?}");
        // Entre guillemets simples, rien n'est défait ; deux morceaux entre guillemets se collent.
        let v = variables_de_texte("A='\\.x'\nB=\"a\" 'b'\n");
        assert!(v.contains(&paire("A", "\\.x")), "{v:?}");
        assert!(v.contains(&paire("B", "ab")), "{v:?}");
        // Blancs de fin ôtés hors guillemets, gardés dedans ; nom rogné ; « \ » + espace garde l'espace.
        let v = variables_de_texte("  A  =  x y  \nB=' x '\nC=x\\ \n");
        assert!(v.contains(&paire("A", "x y")), "{v:?}");
        assert!(v.contains(&paire("B", " x ")), "{v:?}");
        assert!(v.contains(&paire("C", "x ")), "{v:?}");
        // « \ » à la toute fin du fichier : la valeur sans lui.
        assert!(variables_de_texte("A=x\\").contains(&paire("A", "x")));
        // Un fichier ordinaire, sans « \ » ni guillemets : une seule paire par variable, les deux formes égales.
        assert_eq!(
            variables_de_texte("LANG=C\n# note\nTZ=America/Montreal\n"),
            vec![paire("LANG", "C"), paire("TZ", "America/Montreal")]
        );
    }

    /// Ronde 3 du lot 096 (N6) : la réunion avec l'ancienne lecture tient. Ces formes, systemd ne les pose pas (la
    /// clé « LD_PRE\ » s'arrête à sa ligne ; « export X » n'est pas un nom), mais l'ancienne lecture les voyait :
    /// on ne voit jamais moins qu'avant. Sans la réunion, elles disparaissaient sans qu'aucun essai le dise.
    #[test]
    fn la_reunion_garde_l_ancienne_lecture() {
        use super::variables_de_texte;
        let cle = ("LD_PRELOAD".to_string(), "/tmp/x.so".to_string());
        for texte in ["LD_PRE\\\nLOAD=/tmp/x.so\n", "export LD_PRELOAD=/tmp/x.so\n"] {
            assert!(variables_de_texte(texte).contains(&cle), "{texte:?}");
        }
    }
}
