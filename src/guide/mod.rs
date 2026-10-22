//! Guide des commandes : les commandes utiles de chaque système, rangées par système puis par programme, chacune
//! expliquée. Linux se lit par distribution (Omarchy, Arch, Fedora, Debian et Ubuntu, les autres) : chacune montre ses
//! programmes à elle, puis ceux communs à toutes. On trouve une commande en tapant ce qu'on cherche (« wifi »,
//! « disque ») : la recherche des menus la propose au fil de la frappe, et la prédiction complète le mot. Chaque
//! commande a sa page : la copier, pour la taper ici ou chez la personne qu'on aide, ou la lancer ici quand elle ne
//! fait que lire (`lancement`). Tous les systèmes se lisent partout : sous Linux, on peut lire les commandes de
//! Windows.

mod arch;
mod debian;
mod fedora;
mod lancement;
mod linux;
mod macos;
mod omarchy;
mod tldr;
mod tous;
mod windows;

pub(crate) use tldr::cle::sur_la_cle as tldr_sur_la_cle;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::risk::Niveau;
use crate::selection::{Ligne, choisir, correspond, simplifier};
use crate::ui::*;

/// Renouvelle les exemples de tldr-pages de plus d'une semaine, sans ouvrir le guide (surveillance, entretien) : il
/// les a frais à son ouverture. Les commandes vérifiées du guide, elles, font partie de Vanguard et arrivent avec ses
/// mises à jour.
pub fn renouveler_exemples() {
    tldr::renouveler_maintenant();
}

/// Un système du guide. Linux se lit par distribution ; `Linux` lui-même ne paraît pas au menu : c'est le système des
/// programmes communs à toutes, montrés avec chacune.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Systeme {
    Omarchy,
    Arch,
    Fedora,
    /// Debian, Ubuntu, Mint.
    Debian,
    /// openSUSE, et les distributions que le guide ne range pas à part.
    AutresLinux,
    Windows,
    MacOs,
    /// Les commandes qui s'écrivent pareil sous les trois.
    Tous,
    /// Les programmes communs à toutes les distributions.
    Linux,
    /// Les pages de tldr-pages, téléchargées chaque semaine : à copier seulement.
    Tldr,
    /// Les commandes de Vanguard, un programme par groupe du menu : générées depuis le menu et la ligne de commande
    /// (`crate::programmes_vanguard`), jamais écrites à la main.
    Vanguard,
}

/// Les systèmes du menu, dans l'ordre : leur rang fait leur touche (« 3 » : Fedora).
pub const SYSTEMES: [Systeme; 10] = [
    Systeme::Omarchy,
    Systeme::Arch,
    Systeme::Fedora,
    Systeme::Debian,
    Systeme::AutresLinux,
    Systeme::Windows,
    Systeme::MacOs,
    Systeme::Tous,
    Systeme::Tldr,
    // En fin : les numéros d'avant (6 Windows 11, 9 tldr…) ne bougent pas.
    Systeme::Vanguard,
];

/// La distribution de cet ordinateur, lue une fois.
static DISTRIBUTION: OnceLock<Systeme> = OnceLock::new();

impl Systeme {
    /// Celui sur lequel tourne Vanguard : sa distribution, sous Linux.
    fn actuel() -> Systeme {
        if cfg!(windows) {
            Systeme::Windows
        } else if cfg!(target_os = "macos") {
            Systeme::MacOs
        } else {
            *DISTRIBUTION.get_or_init(|| {
                // Une Omarchy qui se dit Arch se reconnaît à son outil.
                match distribution(crate::socle::systeme::os_release()) {
                    Systeme::Arch if installe_ici("omarchy") => Systeme::Omarchy,
                    d => d,
                }
            })
        }
    }

    /// Une distribution de Linux, ou les programmes communs à toutes.
    fn linux(self) -> bool {
        matches!(
            self,
            Systeme::Omarchy
                | Systeme::Arch
                | Systeme::Fedora
                | Systeme::Debian
                | Systeme::AutresLinux
                | Systeme::Linux
        )
    }

    /// Ses commandes sont-elles faites pour cet ordinateur ? Celles d'une distribution valent pour toutes (le guide
    /// dit si le programme manque), celles de tous les systèmes aussi.
    fn d_ici(self) -> bool {
        let ici = Systeme::actuel();
        matches!(self, Systeme::Tous | Systeme::Vanguard) || self == ici || (self.linux() && ici.linux())
    }

    fn nom(self) -> &'static str {
        match self {
            Systeme::Omarchy => "Omarchy",
            Systeme::Arch => "Arch",
            Systeme::Fedora => "Fedora",
            Systeme::Debian => "Debian, Ubuntu",
            Systeme::AutresLinux => tr!("Autres Linux", "Other Linux"),
            Systeme::Windows => "Windows 11",
            Systeme::MacOs => "macOS",
            Systeme::Tous => tr!("Tous les systèmes", "All systems"),
            Systeme::Linux => "Linux",
            Systeme::Tldr => "tldr-pages",
            Systeme::Vanguard => tr!("Commandes de Vanguard", "Vanguard commands"),
        }
    }

    /// Ce qui le désigne dans « vanguard guide <système> », sans accents ni majuscules.
    fn mots(self) -> &'static [&'static str] {
        match self {
            Systeme::Omarchy => &["omarchy"],
            Systeme::Arch => &["arch", "manjaro", "endeavouros", "cachyos"],
            Systeme::Fedora => &["fedora", "rhel", "centos"],
            Systeme::Debian => &["debian", "ubuntu", "mint"],
            Systeme::AutresLinux => &["opensuse", "suse", "autres", "other"],
            Systeme::Windows => &["windows", "win", "windows11"],
            Systeme::MacOs => &["macos", "mac", "osx"],
            Systeme::Tous => &["tous", "all", "general"],
            Systeme::Linux => &["linux"],
            Systeme::Tldr => &["tldr"],
            Systeme::Vanguard => &["vanguard", "commandes", "commands"],
        }
    }

    /// Ses programmes à lui : ceux d'une distribution, sans les communs.
    fn propres(self) -> &'static [Programme] {
        match self {
            Systeme::Omarchy => omarchy::PROGRAMMES,
            Systeme::Arch => arch::PROGRAMMES,
            Systeme::Fedora => fedora::PROGRAMMES,
            Systeme::Debian => debian::PROGRAMMES,
            Systeme::AutresLinux => linux::AUTRES,
            Systeme::Windows => windows::PROGRAMMES,
            Systeme::MacOs => macos::PROGRAMMES,
            Systeme::Tous => tous::PROGRAMMES,
            Systeme::Linux => linux::COMMUNS,
            // Ses pages se téléchargent : `programmes` les prend dans `tldr`.
            Systeme::Tldr => &[],
            Systeme::Vanguard => crate::programmes_vanguard(),
        }
    }

    /// Ses marches à suivre : des programmes dont chaque commande est une étape, dans l'ordre.
    fn pas_a_pas(self) -> &'static [Programme] {
        match self {
            Systeme::Omarchy => omarchy::PAS_A_PAS,
            Systeme::Arch => arch::PAS_A_PAS,
            Systeme::Fedora => fedora::PAS_A_PAS,
            Systeme::Debian => debian::PAS_A_PAS,
            Systeme::Windows => windows::PAS_A_PAS,
            Systeme::MacOs => macos::PAS_A_PAS,
            Systeme::AutresLinux => linux::PAS_A_PAS,
            Systeme::Tous => tous::PAS_A_PAS,
            _ => &[],
        }
    }

    /// Ce qu'il faut savoir de lui avant ses commandes : ses outils, ses habitudes, ses pièges.
    fn presentation(self) -> &'static str {
        match self {
            Systeme::Omarchy => tr!(
                "Omarchy, c'est Arch Linux avec le bureau Hyprland tout réglé. Tout se met à jour par omarchy update, qui prend un instantané avant ; le menu Omarchy (Super+Alt+Espace) règle et dépanne le reste. Ce qui vaut pour Arch vaut aussi ici.",
                "Omarchy is Arch Linux with the Hyprland desktop fully set up. Everything updates through omarchy update, which takes a snapshot first; the Omarchy menu (Super+Alt+Space) sets up and troubleshoots the rest. What holds for Arch holds here too."
            ),
            Systeme::Arch => tr!(
                "Arch est « en continu » : toujours à jour, sans grande mise à niveau. Les paquets viennent des dépôts officiels (pacman) et de l'AUR, écrits par la communauté (yay : à lire avant d'installer). Règle d'or : tout mettre à jour d'un coup, jamais à moitié, et lire les nouvelles d'Arch avant.",
                "Arch is rolling: always up to date, with no big release upgrade. Packages come from the official repositories (pacman) and from the AUR, written by the community (yay: read them before installing). Golden rule: update everything at once, never halfway, and read the Arch news first."
            ),
            Systeme::Fedora => tr!(
                "Fedora sort une version tous les six mois. Paquets RPM par dnf ; pilotes NVIDIA et codecs par le dépôt RPM Fusion ; applications aussi en Flatpak. SELinux protège les services : une « permission refusée » inexpliquée vient souvent de lui. Pare-feu : firewalld, par zones.",
                "Fedora releases every six months. RPM packages through dnf; NVIDIA drivers and codecs through the RPM Fusion repository; apps also as Flatpak. SELinux protects services: an unexplained “permission denied” often comes from it. Firewall: firewalld, by zones."
            ),
            Systeme::Debian => tr!(
                "Debian et Ubuntu (Mint, Pop!_OS…) : paquets .deb par apt, stables et testés ; toujours apt update avant d'installer. Ubuntu ajoute les snaps et les PPA, des dépôts de tiers (prudence). Le pare-feu ufw est coupé après l'installation ; AppArmor confine les programmes.",
                "Debian and Ubuntu (Mint, Pop!_OS…): .deb packages through apt, stable and tested; always apt update before installing. Ubuntu adds snaps and PPAs, third-party repositories (be careful). The ufw firewall is off after installation; AppArmor confines programs."
            ),
            Systeme::AutresLinux => tr!(
                "openSUSE et les autres distributions : paquets par zypper (openSUSE), pare-feu firewalld, instantanés snapper. Les programmes communs à Linux, plus bas, valent partout.",
                "openSUSE and the other distributions: packages through zypper (openSUSE), firewalld firewall, snapper snapshots. The programs common to Linux, below, work everywhere."
            ),
            Systeme::Windows => tr!(
                "Windows 11 (et 10) : logiciels par winget ou le Microsoft Store, mises à jour par Windows Update, sécurité par Microsoft Defender. Les commandes se tapent dans le Terminal (PowerShell).",
                "Windows 11 (and 10): software through winget or the Microsoft Store, updates through Windows Update, security through Microsoft Defender. Commands are typed in the Terminal (PowerShell)."
            ),
            Systeme::MacOs => tr!(
                "macOS : logiciels par l'App Store ou Homebrew (brew), mises à jour par softwareupdate, sauvegardes par Time Machine. sudo demande le mot de passe de votre session.",
                "macOS: software through the App Store or Homebrew (brew), updates through softwareupdate, backups through Time Machine. sudo asks for your session password."
            ),
            Systeme::Tous => tr!(
                "Les commandes qui s'écrivent pareil sous Linux, Windows et macOS : réseau, connexions à distance, projets git, et Vanguard lui-même en ligne de commande.",
                "The commands typed the same way on Linux, Windows and macOS: network, remote connections, git projects, and Vanguard itself from the command line."
            ),
            Systeme::Linux => tr!(
                "Les programmes communs à toutes les distributions de Linux.",
                "The programs common to every Linux distribution."
            ),
            Systeme::Vanguard => tr!(
                "Chaque commande de Vanguard, rangée comme le menu : ce qu'elle fait et sa place au menu. Le détail d'une commande : vanguard <commande> --help.",
                "Every Vanguard command, sorted like the menu: what it does and its place in the menu. The detail of a command: vanguard <command> --help."
            ),
            Systeme::Tldr => tr!(
                "Les exemples de tldr-pages (tldr.sh), des milliers de commandes écrites et tenues à jour par une communauté, sous licence CC BY 4.0 (creativecommons.org/licenses/by/4.0) ; Vanguard en adapte la mise en forme. Il les télécharge chaque semaine, mais ne les a pas vérifiées : elles se copient, et ne se lancent pas d'ici.",
                "The examples of tldr-pages (tldr.sh), thousands of commands written and kept up to date by a community, under the CC BY 4.0 license (creativecommons.org/licenses/by/4.0); Vanguard adapts their layout. It downloads them every week, but has not checked them: they can be copied, and do not run from here."
            ),
        }
    }

    /// Les programmes de son menu, chacun avec le système sous lequel il s'affiche : ses marches à suivre, ses
    /// programmes, puis, pour une distribution, les communs à toutes (sous « Linux »).
    fn programmes(self) -> Vec<(Systeme, &'static Programme)> {
        if self == Systeme::Tldr {
            return tldr::pages()
                .iter()
                .map(|page| (page.systeme, &page.programme))
                .collect();
        }
        let mut programmes: Vec<_> = self
            .pas_a_pas()
            .iter()
            .chain(self.propres())
            .map(|p| (self, p))
            .collect();
        if self.linux() && self != Systeme::Linux {
            programmes.extend(linux::COMMUNS.iter().map(|p| (Systeme::Linux, p)));
        }
        programmes
    }

    /// Où taper les commandes de ce système.
    fn terminal(self) -> &'static str {
        match self {
            Systeme::Omarchy => tr!("Terminal : Super+Entrée.", "Terminal: Super+Enter."),
            Systeme::Arch | Systeme::Fedora | Systeme::Debian | Systeme::AutresLinux | Systeme::Linux => tr!(
                "Terminal : Ctrl+Alt+T sur la plupart des bureaux, Super+Entrée sous Omarchy.",
                "Terminal: Ctrl+Alt+T on most desktops, Super+Enter on Omarchy."
            ),
            Systeme::Windows => tr!(
                "Terminal : Windows+X, puis Terminal (Windows 11) ou Windows PowerShell (Windows 10) ; leur version « (admin) » pour les commandes marquées ⚠.",
                "Terminal: Windows+X, then Terminal (Windows 11) or Windows PowerShell (Windows 10); their “(Admin)” version for the commands marked ⚠."
            ),
            Systeme::MacOs => tr!(
                "Terminal : Cmd+Espace, taper « Terminal », puis Entrée.",
                "Terminal: Cmd+Space, type “Terminal”, then Enter."
            ),
            Systeme::Tous | Systeme::Tldr | Systeme::Vanguard => tr!(
                "Dans tout terminal : Tab complète un nom, ↑ rappelle la commande d'avant, Ctrl-C arrête celle en cours.",
                "In any terminal: Tab completes a name, ↑ brings back the previous command, Ctrl-C stops the running one."
            ),
        }
    }

    /// Précision de sa ligne au menu (33 caractères au plus).
    fn apercu(self) -> &'static str {
        match self {
            Systeme::Omarchy => "omarchy, pacman, yay, ufw…",
            Systeme::Arch => "pacman, yay (AUR), Manjaro…",
            Systeme::Fedora => "dnf, rpm-ostree, firewalld…",
            Systeme::Debian => "apt, dpkg, snap, ufw, Mint…",
            Systeme::AutresLinux => tr!("openSUSE : zypper, firewalld…", "openSUSE: zypper, firewalld…"),
            Systeme::Windows => "winget, sfc, DISM, PowerShell…",
            Systeme::MacOs => "brew, diskutil, Time Machine…",
            Systeme::Tous => "Vanguard, ping, ssh, git, curl…",
            Systeme::Linux => "systemctl, journalctl, ip, nmcli…",
            Systeme::Tldr => tr!("des milliers d'exemples, à copier", "thousands of examples, to copy"),
            Systeme::Vanguard => tr!("par groupe du menu", "by menu group"),
        }
    }
}

/// La distribution d'après /etc/os-release : son ID, puis ceux dont elle dérive (ID_LIKE). Une distribution que le
/// guide ne range pas à part va dans « Autres Linux ».
fn distribution(os_release: &str) -> Systeme {
    let valeur = |cle: &str| {
        os_release
            .lines()
            .find_map(|l| l.trim().strip_prefix(cle)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches(['"', '\'']).to_lowercase())
            .unwrap_or_default()
    };
    let (id, semblables) = (valeur("ID"), valeur("ID_LIKE"));
    std::iter::once(id.as_str())
        .chain(semblables.split_whitespace())
        .find_map(|nom| match nom {
            "omarchy" => Some(Systeme::Omarchy),
            "arch" | "manjaro" | "endeavouros" | "cachyos" | "garuda" | "artix" => Some(Systeme::Arch),
            "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "nobara" => Some(Systeme::Fedora),
            "debian" | "ubuntu" | "linuxmint" | "pop" | "elementary" | "zorin" | "kali" | "raspbian" => {
                Some(Systeme::Debian)
            }
            _ => None,
        })
        .unwrap_or(Systeme::AutresLinux)
}

/// Un programme et ses commandes.
pub struct Programme {
    /// Tel qu'on le tape (« systemctl »), ou les programmes voisins réunis (« lsblk, df, du »).
    pub nom: &'static str,
    /// À quoi il sert, en français et en anglais : la précision de sa ligne au menu (33 caractères au plus).
    pub role: (&'static str, &'static str),
    /// Le fichier qui dit s'il est installé ici (nom cherché dans le PATH, ou chemin complet) ; vide : toujours là
    /// (commandes de PowerShell, Vanguard lui-même).
    pub executable: &'static str,
    pub commandes: &'static [Commande],
}

pub struct Commande {
    /// Telle qu'on la tape ; « <…> » : à remplacer (traduit à l'affichage en anglais, voir `A_REMPLACER`).
    pub ligne: &'static str,
    /// Telle qu'on la tape en anglais quand elle change (sous-commandes de Vanguard) ; vide sinon.
    pub ligne_en: &'static str,
    /// Ce qu'elle fait, en français et en anglais.
    pub texte: (&'static str, &'static str),
    /// Elle change quelque chose (réglage, fichier, paquet, service) : marquée ⚠.
    pub modifie: bool,
    /// Ce qui empêche Vanguard de la lancer ici, même si elle ne change rien.
    pub obstacle: Obstacle,
}

/// Ce qui empêche Vanguard de lancer lui-même une commande qui ne change rien : elle se tape alors dans un terminal
/// (`lancement::obstacle`). Une commande précédée de sudo demande les droits d'administrateur sans qu'on le dise.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Obstacle {
    Aucun,
    /// Elle ouvre une fenêtre (Paramètres, msinfo32, Moniteur d'activité) et n'écrit rien ici.
    Fenetre,
    /// Elle occupe tout le terminal (top).
    PleinEcran,
    /// Elle écrit un fichier de rapport dans le dossier courant.
    Fichier,
    /// Elle demande les droits d'administrateur (fenêtre de mot de passe).
    Administrateur,
    /// Elle prend plusieurs minutes, avec les droits d'administrateur (DISM, chkdsk).
    Longue,
    /// Elle vient de tldr-pages : Vanguard ne l'a pas vérifiée.
    NonVerifiee,
}

impl Commande {
    /// La même commande, que Vanguard ne lance pas ici pour cette raison.
    pub const fn sauf(self, obstacle: Obstacle) -> Commande {
        Commande { obstacle, ..self }
    }
}

/// Une commande qui lit ou montre, sans rien changer.
pub const fn voir(ligne: &'static str, fr: &'static str, en: &'static str) -> Commande {
    Commande {
        ligne,
        ligne_en: "",
        texte: (fr, en),
        modifie: false,
        obstacle: Obstacle::Aucun,
    }
}

/// Une commande qui change quelque chose.
pub const fn changer(ligne: &'static str, fr: &'static str, en: &'static str) -> Commande {
    Commande {
        ligne,
        ligne_en: "",
        texte: (fr, en),
        modifie: true,
        obstacle: Obstacle::Aucun,
    }
}

/// Une commande qui ne s'écrit pas pareil en anglais (sous-commandes de Vanguard).
pub const fn traduite(
    ligne: &'static str,
    ligne_en: &'static str,
    fr: &'static str,
    en: &'static str,
    modifie: bool,
) -> Commande {
    Commande {
        ligne,
        ligne_en,
        texte: (fr, en),
        modifie,
        obstacle: Obstacle::Aucun,
    }
}

/// Ce que le guide dit d'une commande de Vanguard (français, anglais) : un test d'un autre module vérifie ainsi que
/// l'explication suit son code.
#[cfg(test)]
pub(crate) fn explication_vanguard(ligne: &str) -> Option<(&'static str, &'static str)> {
    tous::PROGRAMMES
        .iter()
        .filter(|p| p.nom == "vanguard" || p.nom.starts_with("vanguard : "))
        .flat_map(|p| p.commandes)
        .find(|c| c.ligne == ligne)
        .map(|c| c.texte)
}

/// Les mots à remplacer dans les commandes, et leur nom en anglais.
const A_REMPLACER: &[(&str, &str)] = &[
    ("<adresse>", "<address>"),
    ("<app>", "<app>"),
    ("<archive>", "<archive>"),
    ("<clé>", "<key>"),
    ("<destination>", "<destination>"),
    ("<disque>", "<disk>"),
    ("<dossier>", "<folder>"),
    ("<fichier>", "<file>"),
    ("<groupe>", "<group>"),
    ("<id>", "<id>"),
    ("<interface>", "<interface>"),
    ("<ip>", "<ip>"),
    ("<langage>", "<language>"),
    ("<machine>", "<machine>"),
    ("<module>", "<module>"),
    ("<mot>", "<word>"),
    ("<navigateur>", "<browser>"),
    ("<nom>", "<name>"),
    ("<numéro>", "<number>"),
    ("<paquet>", "<package>"),
    ("<partition>", "<partition>"),
    ("<PID>", "<PID>"),
    ("<port>", "<port>"),
    ("<programme>", "<program>"),
    ("<routeur>", "<router>"),
    ("<service>", "<service>"),
    ("<site>", "<site>"),
    ("<source>", "<source>"),
    ("<terminal>", "<terminal>"),
    ("<texte>", "<text>"),
    ("<thème>", "<theme>"),
    ("<utilisateur>", "<user>"),
    ("<valeur>", "<value>"),
    ("<version>", "<version>"),
    ("<étiquette>", "<label>"),
];

/// Les noms de programme qui se traduisent ; les autres sont des noms de commandes, les mêmes dans les deux langues.
const NOMS_EN: &[(&str, &str)] = &[
    ("vanguard : sécurité", "vanguard: security"),
    ("vanguard : dépannage", "vanguard: troubleshooting"),
    ("PowerShell : réseau", "PowerShell: network"),
    ("PowerShell : Defender", "PowerShell: Defender"),
    ("PowerShell : services", "PowerShell: services"),
    ("PowerShell : disques", "PowerShell: disks"),
    ("Pas à pas : mettre à jour", "Step by step: update"),
    ("Pas à pas : installer", "Step by step: install"),
    ("Pas à pas : faire de la place", "Step by step: free up space"),
    ("Pas à pas : réparer", "Step by step: repair"),
    ("Pas à pas : réparer apt", "Step by step: repair apt"),
    ("Pas à pas : pare-feu", "Step by step: firewall"),
    ("Pas à pas : NVIDIA", "Step by step: NVIDIA"),
    ("Pas à pas : NVIDIA et codecs", "Step by step: NVIDIA and codecs"),
    ("Pas à pas : nouvelle version", "Step by step: new release"),
    ("Pas à pas : SELinux", "Step by step: SELinux"),
    ("Pas à pas : mises à jour auto", "Step by step: auto updates"),
    ("Pas à pas : dépanner", "Step by step: troubleshoot"),
    ("Pas à pas : réparer Windows", "Step by step: repair Windows"),
    ("Pas à pas : réseau", "Step by step: network"),
    ("Pas à pas : sécurité", "Step by step: security"),
    ("Pas à pas : lenteur", "Step by step: slowness"),
    ("Pas à pas : réparer le disque", "Step by step: repair the disk"),
    ("Pas à pas : Time Machine", "Step by step: Time Machine"),
    ("Pas à pas : revenir en arrière", "Step by step: roll back"),
    ("Pas à pas : clé SSH", "Step by step: SSH key"),
    ("Pas à pas : git", "Step by step: git"),
];

/// Ses noms dans les deux langues, pour la recherche.
fn noms_du_programme(p: &Programme) -> String {
    match NOMS_EN.iter().find(|(fr, _)| *fr == p.nom) {
        Some((fr, en)) => format!("{fr} {en}"),
        None => p.nom.to_string(),
    }
}

/// Le nom d'un programme dans la langue de l'interface.
fn nom(p: &Programme) -> &'static str {
    if !crate::langue::anglais() {
        return p.nom;
    }
    NOMS_EN.iter().find(|(fr, _)| *fr == p.nom).map_or(p.nom, |(_, en)| en)
}

fn dans_la_langue(t: (&'static str, &'static str)) -> &'static str {
    if crate::langue::anglais() { t.1 } else { t.0 }
}

/// La commande telle qu'elle s'affiche dans la langue de l'interface.
fn ligne(c: &Commande) -> String {
    if !crate::langue::anglais() {
        return c.ligne.to_string();
    }
    if !c.ligne_en.is_empty() {
        return c.ligne_en.to_string();
    }
    en_anglais(c.ligne)
}

fn en_anglais(ligne: &str) -> String {
    A_REMPLACER
        .iter()
        .fold(ligne.to_string(), |l, (fr, en)| l.replace(fr, en))
}

/// Ce que la recherche trouve dans une commande sans l'afficher : l'autre langue, et son explication dans les deux.
fn mots_de_la_commande(c: &Commande) -> String {
    format!("{} {} {} {}", c.ligne_en, en_anglais(c.ligne), c.texte.0, c.texte.1)
}

/// Le programme est-il installé ici ?
fn installe(p: &Programme) -> bool {
    p.executable.is_empty() || installe_ici(p.executable)
}

/// Ce fichier est-il là ? Cherché dans le PATH, et dans les dossiers des outils d'administration que le PATH d'un
/// compte ordinaire omet parfois (Debian), ou de Homebrew (macOS) ; un chemin complet, tel quel.
fn installe_ici(executable: &str) -> bool {
    // Un lien vers un programme compte : les alias d'applications de Windows (winget) en sont, illisibles comme
    // fichiers ordinaires.
    let existe = |chemin: &Path| std::fs::symlink_metadata(chemin).is_ok_and(|m| !m.is_dir());
    if executable.starts_with('/') {
        return existe(Path::new(executable));
    }
    let mut dossiers: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|chemins| std::env::split_paths(&chemins).collect())
        .unwrap_or_default();
    if cfg!(unix) {
        dossiers.extend(
            [
                "/usr/sbin",
                "/sbin",
                "/usr/local/sbin",
                "/opt/homebrew/bin",
                "/usr/local/bin",
            ]
            .map(PathBuf::from),
        );
    }
    let noms: Vec<String> = if cfg!(windows) {
        [".exe", ".com", ".cmd", ".bat"]
            .iter()
            .map(|e| format!("{executable}{e}"))
            .collect()
    } else {
        vec![executable.to_string()]
    };
    dossiers.iter().any(|d| noms.iter().any(|n| existe(&d.join(n))))
}

/// Absent de cet ordinateur : seulement dit pour les commandes faites pour lui (sur Linux, on ne sait rien d'un
/// Windows).
fn absent(s: Systeme, p: &Programme) -> bool {
    s.d_ici() && !installe(p)
}

/// ⚠ en couleur si la commande change quelque chose, une espace sinon : les commandes restent alignées.
fn marque(c: &Commande) -> String {
    if c.modifie {
        format!("{}⚠{RESET}", couleur(Niveau::Moyen))
    } else {
        " ".to_string()
    }
}

/// Une commande et son explication, pour `vanguard guide` en ligne de commande.
fn afficher_commande(c: &Commande) {
    println!("  {} {GRAS}{}{RESET}", marque(c), ligne(c));
    for l in envelopper(dans_la_langue(c.texte), LARGEUR - 6) {
        println!("      {GRIS}{l}{RESET}");
    }
}

/// Les façons de remplir le presse-papier sous Linux et macOS, à essayer dans l'ordre : des scripts `sh` qui
/// reçoivent le texte en premier argument (« $1 »), jamais mêlé au script, pour qu'aucun caractère de la commande ne
/// s'y exécute. Leurs sorties vont à /dev/null : wl-copy et xclip restent en fond pour servir le presse-papier, et
/// garderaient sinon ouverte la sortie que lit `commande::lancer`.
#[cfg(any(not(windows), test))]
fn scripts_presse_papier(macos: bool, wayland: bool, x11: bool) -> Vec<&'static str> {
    let mut scripts = Vec::new();
    if macos {
        scripts.push("printf %s \"$1\" | pbcopy");
    }
    if wayland {
        scripts.push("wl-copy -- \"$1\" >/dev/null 2>&1");
    }
    if x11 {
        scripts.push("printf %s \"$1\" | xclip -selection clipboard >/dev/null 2>&1");
        scripts.push("printf %s \"$1\" | xsel --clipboard --input >/dev/null 2>&1");
    }
    scripts
}

/// Met `texte` dans le presse-papier par l'outil du système (Set-Clipboard, pbcopy, wl-copy, xclip ou xsel). Faux
/// si aucun n'a marché : pas de bureau (SSH, console), ou outil absent.
fn copier(texte: &str) -> bool {
    #[cfg(windows)]
    {
        let script = format!("Set-Clipboard -Value {}", crate::commande::ps_chaine(texte));
        crate::commande::lancer(
            crate::machine::windows::powershell().args(["-NoProfile", "-NonInteractive", "-Command", &script]),
            15,
        )
        .is_some_and(|r| r.code == Some(0))
    }
    #[cfg(not(windows))]
    {
        let present = |variable: &str| std::env::var_os(variable).is_some_and(|v| !v.is_empty());
        scripts_presse_papier(
            cfg!(target_os = "macos"),
            present("WAYLAND_DISPLAY"),
            present("DISPLAY"),
        )
        .into_iter()
        .any(|script| {
            crate::commande::lancer(std::process::Command::new("sh").args(["-c", script, "sh", texte]), 5)
                .is_some_and(|r| r.code == Some(0))
        })
    }
}

/// Un programme et toutes ses commandes, pour `vanguard guide` en ligne de commande.
fn afficher_programme(s: Systeme, p: &Programme) {
    titre(&format!("{} › {}", s.nom(), nom(p)));
    let installe = if absent(s, p) {
        tr!(" (pas installé ici)", " (not installed here)")
    } else {
        ""
    };
    println!("  {GRIS}{}{installe}{RESET}\n", dans_la_langue(p.role));
    for c in p.commandes {
        afficher_commande(c);
    }
}

/// Ce que veulent dire ⚠ et « <…> », et où taper les commandes de ce système.
fn legende(s: Systeme) -> Vec<String> {
    let texte = format!(
        "{} {}",
        tr!(
            "⚠ : la commande change quelque chose (souvent avec les droits d'administrateur). <…> : à remplacer.",
            "⚠: the command changes something (often with administrator rights). <…>: to replace."
        ),
        s.terminal()
    );
    envelopper(&texte, LARGEUR - 2)
        .into_iter()
        .map(|l| format!("  {GRIS}{l}{RESET}"))
        .collect()
}

/// Le cadre en tête d'un écran du guide : « VANGUARD › Guide › Fedora › dnf », et `droite` à droite.
fn entete(chemin: &[&str], droite: &str) -> Vec<Ligne> {
    let fil = |depart: String, reste: &[&str]| {
        reste
            .iter()
            .fold(depart, |g, morceau| format!("{g} {GRIS}›{RESET} {morceau}"))
    };
    let complet = lignes_cadre(&fil(format!("{ACCENT}VANGUARD{RESET}"), chemin), droite);
    // Au plus long chemin, le nom du programme en tête cède sa place : le reste du fil se lit en entier.
    let lignes = match chemin.split_first() {
        Some((premier, reste)) if complet.iter().any(|l| largeur_affichee(l) > LARGEUR) => {
            lignes_cadre(&fil((*premier).to_string(), reste), droite)
        }
        _ => complet,
    };
    lignes.into_iter().map(Ligne::Texte).collect()
}

/// La commande sur une ligne de menu, ⚠ devant si elle change quelque chose (une espace sinon : les commandes d'un
/// programme commencent à la même colonne), coupée pour tenir après la touche.
fn ligne_de_menu(c: &Commande) -> String {
    format!("{} {}", marque(c), couper(&ligne(c), LARGEUR - 9))
}

/// Un texte en gris sur des lignes de menu, décalé de `retrait` espaces.
fn lignes_grises(texte: &str, retrait: usize) -> Vec<Ligne> {
    envelopper(texte, LARGEUR - retrait)
        .into_iter()
        .map(|l| Ligne::Texte(format!("{}{GRIS}{l}{RESET}", " ".repeat(retrait))))
        .collect()
}

/// Les commandes d'un programme comme lignes que seule la recherche montre : `avant` précède leur numéro (« 2.4. » :
/// « 2.4.1 »), `chemin` dit où elles sont (vide dans le menu de leur système).
fn lignes_des_commandes(avant: &str, chemin: &str, p: &Programme) -> Vec<Ligne> {
    p.commandes
        .iter()
        .enumerate()
        .map(|(k, c)| {
            let texte = format!("{}{}", if c.modifie { "⚠ " } else { "" }, ligne(c));
            Ligne::cachee(&format!("{avant}{}", k + 1), chemin, &texte, dans_la_langue(c.texte)).avec_mots(&format!(
                "{} {}",
                mots_de_la_commande(c),
                noms_du_programme(p)
            ))
        })
        .collect()
}

/// Une page de programme du guide : le système sous lequel elle s'affiche (Linux pour un programme commun), et son
/// chemin au menu (rang du système, rang du programme dans le menu du système, à partir de 0).
#[derive(Clone, Copy)]
struct Page {
    systeme: Systeme,
    rang_systeme: usize,
    rang_programme: usize,
    programme: &'static Programme,
}

/// Les systèmes dans l'ordre de la recherche : celui de cet ordinateur, les commandes de tous les systèmes, puis les
/// autres. Arch passe avant Omarchy : ailleurs que sous Omarchy, ce qu'elles partagent (pacman, yay) se range sous
/// Arch.
fn ordre_de_recherche() -> Vec<Systeme> {
    let mut ordre = vec![Systeme::actuel(), Systeme::Tous];
    for s in [
        Systeme::Arch,
        Systeme::Fedora,
        Systeme::Debian,
        Systeme::AutresLinux,
        Systeme::Omarchy,
        Systeme::Windows,
        Systeme::MacOs,
        Systeme::Vanguard,
    ] {
        if !ordre.contains(&s) {
            ordre.push(s);
        }
    }
    ordre
}

/// Chaque programme du guide une seule fois, dans l'ordre de la recherche : un programme que plusieurs
/// distributions montrent (pacman, ufw, les communs) se range sous la première. Il se reconnaît à son nom et à son
/// rôle : les marches à suivre de chaque distribution portent le même nom (« Pas à pas : mettre à jour »).
fn pages() -> Vec<Page> {
    let mut vus = HashSet::new();
    let mut pages = Vec::new();
    for s in ordre_de_recherche() {
        let Some(rang_systeme) = SYSTEMES.iter().position(|x| *x == s) else {
            continue;
        };
        for (rang_programme, (systeme, programme)) in s.programmes().into_iter().enumerate() {
            if vus.insert((programme.nom, programme.role.0)) {
                pages.push(Page {
                    systeme,
                    rang_systeme,
                    rang_programme,
                    programme,
                });
            }
        }
    }
    pages
}

/// Ce que la recherche d'un menu trouve dans le guide : chaque système (« <cle>.3 »), chaque programme
/// (« <cle>.3.1 » : Fedora, 1er programme) et chaque commande (« <cle>.3.1.2 »), ceux de cet ordinateur d'abord.
/// `cle` : la touche du guide dans ce menu, vide dans le menu du guide lui-même (« 3.1.2 »).
pub fn lignes_de_recherche(cle: &str) -> Vec<Ligne> {
    let guide = tr!("Guide", "Guide");
    let (avant, racine) = if cle.is_empty() {
        (String::new(), String::new())
    } else {
        (format!("{cle}."), format!("{guide} › "))
    };
    let mut lignes = Vec::new();
    if !cle.is_empty() {
        for (i, s) in SYSTEMES.iter().enumerate() {
            lignes.push(
                Ligne::cachee(&format!("{avant}{}", i + 1), &format!("{guide} ›"), s.nom(), s.apercu())
                    .avec_mots(&s.mots().join(" ")),
            );
        }
    }
    for page in pages() {
        let p = page.programme;
        let cle_programme = format!("{avant}{}.{}", page.rang_systeme + 1, page.rang_programme + 1);
        let chemin = format!("{racine}{} ›", page.systeme.nom());
        lignes.push(
            Ligne::cachee(&cle_programme, &chemin, nom(p), dans_la_langue(p.role)).avec_mots(&noms_du_programme(p)),
        );
        lignes.extend(lignes_des_commandes(&format!("{cle_programme}."), &chemin, p));
    }
    lignes
}

/// « 3.1.2 » → (3, Some(1), Some(2)) ; « 3.1 » → (3, Some(1), None) ; « 3 » → (3, None, None) : un chemin dans le
/// guide, tapé ou trouvé par la recherche.
pub fn chemin(texte: &str) -> Option<(usize, Option<usize>, Option<usize>)> {
    let mut parties = texte.trim().split('.').map(|n| n.parse::<usize>().ok());
    let systeme = parties.next()??;
    let programme = match parties.next() {
        Some(p) => Some(p?),
        None => None,
    };
    let commande = match parties.next() {
        Some(c) => Some(c?),
        None => None,
    };
    parties.next().is_none().then_some((systeme, programme, commande))
}

/// Ouvre une page du guide trouvée par la recherche : un système (1 à 8), l'un de ses programmes, ou l'une de ses
/// commandes.
pub fn ouvrir(systeme: usize, programme: Option<usize>, commande: Option<usize>) {
    let Some(&s) = systeme.checked_sub(1).and_then(|i| SYSTEMES.get(i)) else {
        return;
    };
    let programmes = s.programmes();
    let Some(&(proprietaire, p)) = programme.and_then(|j| j.checked_sub(1)).and_then(|j| programmes.get(j)) else {
        menu_systeme(s);
        return;
    };
    match commande.and_then(|k| k.checked_sub(1)).and_then(|k| p.commandes.get(k)) {
        Some(c) => montrer_commande(proprietaire, p, c),
        None => montrer_programme(proprietaire, p),
    }
}

/// La place d'un programme (et d'une de ses commandes, à partir de 1) au guide : « 6.7 », « 6.7.2 ». Un commun à
/// Linux se dit dans la distribution de cet ordinateur s'il y est, sinon la première qui le montre ; tldr à part.
fn place(s: Systeme, p: &Programme, commande: Option<usize>) -> Option<String> {
    let candidats: Vec<(usize, Systeme)> = SYSTEMES
        .iter()
        .enumerate()
        // Une page de tldr-pages se range sous tldr (9), son système propriétaire étant sa plateforme.
        .filter(|(_, x)| **x != Systeme::Tldr || tldr::plateforme(p).is_some())
        .map(|(rang, x)| (rang, *x))
        .collect();
    let rang_de = |x: Systeme| x.programmes().iter().position(|(_, q)| std::ptr::eq(*q, p));
    let (systeme, programme) = candidats
        .iter()
        .find(|(_, x)| *x == Systeme::actuel() || *x == s)
        .and_then(|(rang, x)| rang_de(*x).map(|r| (*rang, r)))
        .or_else(|| candidats.iter().find_map(|(rang, x)| rang_de(*x).map(|r| (*rang, r))))?;
    Some(match commande {
        Some(numero) => format!("{}.{}.{numero}", systeme + 1, programme + 1),
        None => format!("{}.{}", systeme + 1, programme + 1),
    })
}

/// Le chemin mène-t-il à une page (système, programme, commande) ?
fn page_existe(systeme: usize, programme: Option<usize>, commande: Option<usize>) -> bool {
    let Some(&s) = systeme.checked_sub(1).and_then(|i| SYSTEMES.get(i)) else {
        return false;
    };
    let Some(j) = programme else {
        return true;
    };
    let programmes = s.programmes();
    let Some((_, p)) = j.checked_sub(1).and_then(|j| programmes.get(j)) else {
        return false;
    };
    commande.is_none_or(|k| (1..=p.commandes.len()).contains(&k))
}

/// Le pied de page d'un écran du guide : son chemin au menu et sa commande (« Chemin : 10.6.7.2 · vanguard guide
/// 6.7.2 »), pour apprendre le raccourci.
fn pied_de_page(s: Systeme, p: &Programme, commande: Option<usize>) -> Option<String> {
    let ici = place(s, p, commande)?;
    let cle = crate::cle_du_guide();
    Some(trf!(
        "Chemin : {cle}.{ici} · vanguard guide {ici}",
        "Path: {cle}.{ici} · vanguard guide {ici}"
    ))
}

/// Le chemin d'un programme en tête de ses écrans : « Guide › Fedora › dnf », ou « tldr-pages › linux › tar ».
fn chemin_affiche(s: Systeme, p: &Programme) -> [&'static str; 3] {
    match tldr::plateforme(p) {
        Some(plateforme) => ["tldr-pages", plateforme, nom(p)],
        None => [tr!("Guide", "Guide"), s.nom(), nom(p)],
    }
}

/// Une commande sur des lignes de `largeur` colonnes au plus : celles de tldr-pages sont parfois longues, et un mot
/// trop long (une adresse) est coupé lui aussi, pour que l'écran ne déborde jamais.
fn lignes_de_commande(commande: &str, largeur: usize) -> Vec<String> {
    let mut lignes = Vec::new();
    for l in envelopper(commande, largeur) {
        let mut reste: Vec<char> = l.chars().collect();
        while largeur_affichee(&reste.iter().collect::<String>()) > largeur {
            let mut morceau = String::new();
            while let Some(&c) = reste.first() {
                if largeur_affichee(&morceau) + largeur_car(c) > largeur {
                    break;
                }
                morceau.push(c);
                reste.remove(0);
            }
            lignes.push(morceau);
        }
        lignes.push(reste.into_iter().collect());
    }
    lignes
}

/// Une réponse qui revient en arrière : rien, « ↵ » ou « q ».
fn revenir(choix: &str) -> bool {
    choix.is_empty() || choix == "↵" || choix.eq_ignore_ascii_case("q")
}

/// Une commande seule : ce qu'elle fait, puis la copier, ou la lancer ici quand elle ne fait que lire.
fn montrer_commande(s: Systeme, p: &Programme, c: &Commande) {
    let raison = lancement::pourquoi_pas(s, p, c);
    let rang = p.commandes.iter().position(|x| std::ptr::eq(x, c)).map_or(0, |i| i + 1);
    let chemin = chemin_affiche(s, p);
    let droite = trf!("{rang} sur {}", "{rang} of {}", p.commandes.len());
    let commande = ligne(c);
    let mut dernier = String::from(if raison.is_none() { "2" } else { "1" });
    let mut message: Option<String> = None;
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes = entete(&chemin, &droite);
        let avertissement = if c.modifie {
            format!("{}⚠{RESET} ", couleur(Niveau::Moyen))
        } else {
            String::new()
        };
        for (i, l) in lignes_de_commande(&commande, LARGEUR - 4).iter().enumerate() {
            let debut = if i == 0 { avertissement.as_str() } else { "" };
            lignes.push(Ligne::Texte(format!("  {debut}{GRAS}{l}{RESET}")));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.extend(
            envelopper(dans_la_langue(c.texte), LARGEUR - 4)
                .into_iter()
                .map(|l| Ligne::Texte(format!("  {l}"))),
        );
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::Texte(if c.obstacle == Obstacle::NonVerifiee {
            format!(
                "  {}●{RESET} {}",
                couleur(Niveau::Moyen),
                tr!(
                    "Exemple de tldr-pages : Vanguard ne sait pas ce qu'il change.",
                    "A tldr-pages example: Vanguard does not know what it changes."
                )
            )
        } else if c.modifie {
            format!(
                "  {}⚠{RESET} {}",
                couleur(Niveau::Moyen),
                tr!(
                    "Elle change quelque chose, souvent avec les droits d'administrateur.",
                    "It changes something, often with administrator rights."
                )
            )
        } else {
            format!(
                "  {VERT}✔{RESET} {}",
                tr!(
                    "Elle ne fait que lire : rien ne change.",
                    "It only reads: nothing changes."
                )
            )
        }));
        lignes.extend(lignes_grises(s.terminal(), 2));
        if let Some(r) = &raison {
            lignes.extend(lignes_grises(
                &trf!("Pas lancée d'ici. {r}", "Not run from here. {r}"),
                2,
            ));
        }
        if let Some(pied) = pied_de_page(s, p, Some(rang)) {
            lignes.extend(lignes_grises(&pied, 2));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix(
            "1",
            tr!("Copier", "Copy"),
            tr!("pour la coller dans un terminal", "to paste it in a terminal"),
        ));
        if raison.is_none() {
            lignes.push(Ligne::choix(
                "2",
                tr!("Lancer ici", "Run here"),
                tr!("sa sortie s'affiche ici", "its output shows here"),
            ));
        }
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        if let Some(m) = &message {
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::Texte(m.clone()));
        }
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            tr!("  Choix (Entrée pour revenir) : ", "  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        match choix.trim() {
            "1" => {
                dernier = "1".to_string();
                message = Some(if copier(&commande) {
                    trf!(
                        "  {VERT}✔{RESET} Copiée : {GRAS}{commande}{RESET}",
                        "  {VERT}✔{RESET} Copied: {GRAS}{commande}{RESET}"
                    )
                } else {
                    // Sans presse-papier (pas de bureau, outil absent), la commande reste à sélectionner à la souris.
                    format!(
                        "  {}✖{RESET} {}",
                        couleur(Niveau::Moyen),
                        tr!(
                            "Presse-papier inaccessible ici : sélectionnez la commande à la souris.",
                            "Clipboard unavailable here: select the command with the mouse."
                        )
                    )
                });
            }
            "2" if raison.is_none() => {
                dernier = "2".to_string();
                message = None;
                print!("\x1b[2J\x1b[H");
                for l in lignes_cadre(
                    &chemin.iter().fold(format!("{ACCENT}VANGUARD{RESET}"), |g, morceau| {
                        format!("{g} {GRIS}›{RESET} {morceau}")
                    }),
                    &droite,
                ) {
                    println!("{l}");
                }
                println!();
                lancement::lancer_ici(c);
            }
            choix if revenir(choix) => return,
            _ => {}
        }
    }
}

/// Une marche à suivre (« Pas à pas : … ») plutôt qu'un programme : ses commandes sont des étapes.
fn est_un_pas_a_pas(p: &Programme) -> bool {
    SYSTEMES
        .iter()
        .any(|s| s.pas_a_pas().iter().any(|g| std::ptr::eq(g, p)))
}

/// Un programme à l'écran : chaque commande, son explication dessous. ↑ ↓ et Entrée (ou son numéro) ouvrent sa page ;
/// taper un mot cherche parmi elles.
fn montrer_programme(s: Systeme, p: &Programme) {
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let n = p.commandes.len();
        let droite = if est_un_pas_a_pas(p) {
            trf!("{n} étapes", "{n} steps")
        } else {
            trf!("{n} commandes", "{n} commands")
        };
        let mut lignes = entete(&chemin_affiche(s, p), &droite);
        let installe = if absent(s, p) {
            tr!(" (pas installé ici)", " (not installed here)")
        } else {
            ""
        };
        // Le rôle d'une page de tldr-pages est sa description entière : sur plusieurs lignes au besoin.
        lignes.extend(lignes_grises(&format!("{}{installe}", dans_la_langue(p.role)), 2));
        lignes.extend(legende(s).into_iter().map(Ligne::Texte));
        lignes.push(Ligne::Texte(String::new()));
        for (i, c) in p.commandes.iter().enumerate() {
            lignes.push(Ligne::choix(&(i + 1).to_string(), &ligne_de_menu(c), "").avec_mots(&mots_de_la_commande(c)));
            lignes.extend(lignes_grises(dans_la_langue(c.texte), 9));
        }
        if let Some(pied) = pied_de_page(s, p, None) {
            lignes.push(Ligne::Texte(String::new()));
            lignes.extend(lignes_grises(&pied, 2));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        let Some(choix) = choisir(
            &lignes,
            tr!(
                "  Numéro de la commande (Entrée pour revenir) : ",
                "  Command number (Enter to go back): "
            ),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim();
        match choix
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| p.commandes.get(i))
        {
            Some(c) => {
                dernier = choix.to_string();
                montrer_commande(s, p, c);
            }
            None if revenir(choix) => return,
            None => {}
        }
    }
}

/// Les programmes d'un système : en choisir un, ou taper un mot pour trouver une commande parmi toutes les siennes
/// (« 4.2 » : 4e programme, 2e commande). Une distribution montre les siens, puis ceux communs à Linux.
fn menu_systeme(s: Systeme) {
    let programmes = s.programmes();
    let mut dernier = String::from("1");
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes = entete(
            &[tr!("Guide", "Guide"), s.nom()],
            &trf!("{} programmes", "{} programs", programmes.len()),
        );
        lignes.extend(lignes_grises(s.presentation(), 2));
        lignes.extend(legende(s).into_iter().map(Ligne::Texte));
        // Des sections quand il y en a plusieurs : marches à suivre, programmes du système, communs à Linux.
        let sections = s.linux() || !s.pas_a_pas().is_empty() || s == Systeme::Tldr;
        if !sections {
            lignes.push(Ligne::Texte(String::new()));
        }
        if s == Systeme::Tldr && programmes.is_empty() {
            lignes.push(Ligne::Texte(String::new()));
            lignes.extend(lignes_grises(
                if tldr::en_cours() {
                    tr!(
                        "Téléchargement en cours : revenez dans un instant.",
                        "Downloading: come back in a moment."
                    )
                } else {
                    tr!(
                        "Pas encore téléchargées : elles arrivent toutes seules quand Internet répond, à l'ouverture du guide.",
                        "Not downloaded yet: they come by themselves when the Internet answers, when the guide opens."
                    )
                },
                2,
            ));
        }
        // La place qui reste pour la précision, après la touche et le nom (tldr-pages en a des milliers).
        let largeur_touche = programmes.len().to_string().len().max(2);
        // Comme `selection::colonne` : le nom le plus long tel qu'affiché, « (absent) » compris là où il paraît.
        let marque_absent = largeur_affichee(tr!(" (absent)", " (missing)"));
        let plus_long = programmes
            .iter()
            .map(|&(proprietaire, p)| {
                let absent = s != Systeme::Tldr && absent(proprietaire, p);
                largeur_affichee(nom(p)) + if absent { marque_absent } else { 0 }
            })
            .max()
            .unwrap_or(0);
        let colonne = (plus_long + 2).clamp(36, 48);
        let place = LARGEUR.saturating_sub(5 + largeur_touche + colonne).max(10);
        let tldr = s == Systeme::Tldr;
        let pages_tldr = if tldr { tldr::pages() } else { &[] };
        let mut section = None;
        for (j, &(proprietaire, p)) in programmes.iter().enumerate() {
            let titre = if tldr {
                pages_tldr.get(j).map_or("", |page| page.plateforme).to_uppercase()
            } else if est_un_pas_a_pas(p) {
                tr!("PAS À PAS", "STEP BY STEP").to_string()
            } else if proprietaire == Systeme::Linux {
                tr!("COMMUNS À LINUX", "COMMON TO LINUX").to_string()
            } else {
                s.nom().to_uppercase()
            };
            if sections && section.as_ref() != Some(&titre) {
                lignes.push(Ligne::Texte(String::new()));
                lignes.push(Ligne::Texte(ligne_section(&titre)));
                section = Some(titre);
            }
            // Sauf pour tldr-pages : des milliers de pages, la plupart pour des programmes qu'on n'a pas.
            let nom = if !tldr && absent(proprietaire, p) {
                format!("{} {DISCRET}{}{RESET}", nom(p), tr!("(absent)", "(missing)"))
            } else {
                nom(p).to_string()
            };
            let mots = if tldr {
                // Une page de tldr-pages se trouve aussi par ses exemples : leurs commandes ne sont pas des lignes à
                // part (des dizaines de milliers).
                p.commandes
                    .iter()
                    .map(|c| format!("{} {}", c.texte.0, c.ligne))
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                noms_du_programme(p)
            };
            lignes.push(
                Ligne::choix(&(j + 1).to_string(), &nom, &couper(dans_la_langue(p.role), place)).avec_mots(&mots),
            );
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        // Taper un mot trouve aussi chaque commande de ce système.
        if !tldr {
            for (j, (_, p)) in programmes.iter().enumerate() {
                lignes.extend(lignes_des_commandes(&format!("{}.", j + 1), "", p));
            }
        }
        let Some(choix) = choisir(
            &lignes,
            tr!(
                "  Numéro du programme, ou un mot à chercher (Entrée pour revenir) : ",
                "  Program number, or a word to look for (Enter to go back): "
            ),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim();
        let mut parties = choix.split('.').map(|n| n.parse::<usize>().ok()?.checked_sub(1));
        let programme = parties.next().flatten().and_then(|j| programmes.get(j));
        match (programme, parties.next(), parties.next()) {
            (Some(&(proprietaire, p)), None, None) => {
                dernier = choix.to_string();
                montrer_programme(proprietaire, p);
            }
            (Some(&(proprietaire, p)), Some(k), None) => {
                if let Some(c) = k.and_then(|k| p.commandes.get(k)) {
                    montrer_commande(proprietaire, p, c);
                }
            }
            _ if revenir(choix) => return,
            _ => {}
        }
    }
}

/// Une commande trouvée, avec son système et son programme.
type Trouvee = (Systeme, &'static Programme, &'static Commande);

/// Les commandes où paraissent tous les mots de `recherche` : dans la commande, son explication (en français comme en
/// anglais), le nom ou le rôle de son programme. Même règle que la recherche des menus (`selection::correspond`).
fn trouver(recherche: &str) -> Vec<Trouvee> {
    pages()
        .into_iter()
        .flat_map(|page| {
            page.programme
                .commandes
                .iter()
                .map(move |c| (page.systeme, page.programme, c))
        })
        .filter(|(_, p, c)| {
            let texte = [
                c.ligne,
                c.ligne_en,
                &en_anglais(c.ligne),
                c.texte.0,
                c.texte.1,
                &noms_du_programme(p),
                p.role.0,
                p.role.1,
            ]
            .join(" ");
            correspond(recherche, &simplifier(&texte))
        })
        .collect()
}

fn afficher_resultats(recherche: &str, trouvees: &[Trouvee]) {
    if trouvees.is_empty() {
        afficher_aligne(
            "  ",
            &trf!(
                "Rien trouvé pour « {recherche} ». Essayez un autre mot : disque, wifi, dns, mise à jour…",
                "Nothing found for “{recherche}”. Try another word: disk, wifi, dns, update…"
            ),
            2,
            GRIS,
        );
        return;
    }
    trp!(
        "  {} commande(s) pour « {recherche} » :",
        "  {} command(s) for “{recherche}”:",
        trouvees.len()
    );
    let mut programme_en_cours: Option<(Systeme, &str)> = None;
    for &(s, p, c) in trouvees {
        if programme_en_cours != Some((s, p.nom)) {
            println!("\n  {ACCENT}{} › {}{RESET}", s.nom(), nom(p));
            programme_en_cours = Some((s, p.nom));
        }
        afficher_commande(c);
    }
}

/// Le guide au menu : taper ce qu'on cherche, ou choisir un système.
pub fn menu() {
    // Les pages de tldr-pages avant leur téléchargement : le menu les affiche de toute façon, et en les chargeant, tldr
    // retient quelles archives se lisent ; le fil d'arrière-plan ne relit que celles qui restent inconnues. Dans
    // l'autre ordre, les deux fils lisaient les mêmes archives en même temps, le double sur une clé lente.
    tldr::pages();
    tldr::renouveler_en_fond();
    let total: usize = pages().iter().map(|page| page.programme.commandes.len()).sum();
    // Le curseur sur le système de cet ordinateur, marqué « (ce système) ».
    let mut dernier = SYSTEMES
        .iter()
        .position(|s| *s == Systeme::actuel())
        .map_or_else(|| "1".to_string(), |i| (i + 1).to_string());
    loop {
        print!("\x1b[2J\x1b[H");
        let mut lignes = entete(
            &[tr!("Guide des commandes", "Command guide")],
            &trf!("{total} commandes vérifiées", "{total} checked commands"),
        );
        lignes.extend(lignes_grises(
            tr!(
                "Choisissez un système, ou tapez un mot (wifi, disque, mise à jour…) : les commandes paraissent au fil de la frappe. Une commande se copie, ou se lance ici si elle ne fait que lire.",
                "Choose a system, or type a word (wifi, disk, update…): commands show up as you type. A command can be copied, or run here if it only reads."
            ),
            2,
        ));
        lignes.push(Ligne::Texte(String::new()));
        for (i, s) in SYSTEMES.iter().enumerate() {
            let nom = if *s == Systeme::actuel() {
                trf!("{} (ce système)", "{} (this system)", s.nom())
            } else {
                s.nom().to_string()
            };
            let apercu = if *s == Systeme::Tldr {
                apercu_tldr()
            } else {
                s.apercu().to_string()
            };
            lignes.push(Ligne::choix(&(i + 1).to_string(), &nom, &apercu).avec_mots(&s.mots().join(" ")));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        lignes.push(Ligne::Texte(String::new()));
        lignes.extend(lignes_de_recherche(""));
        lignes.extend(lignes_de_tldr());
        let Some(choix) = choisir(
            &lignes,
            tr!(
                "  Choix, ou un mot à chercher (Entrée pour revenir) : ",
                "  Choice, or a word to look for (Enter to go back): "
            ),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        match chemin(&choix) {
            Some((s, None, None)) => {
                if (1..=SYSTEMES.len()).contains(&s) {
                    dernier.clone_from(&choix);
                }
                ouvrir(s, None, None);
            }
            Some((s, p, c)) => ouvrir(s, p, c),
            None if revenir(&choix) => return,
            None => {}
        }
    }
}

/// La ligne de tldr-pages au menu du guide : combien de commandes, de quand ; ou où en est leur téléchargement.
fn apercu_tldr() -> String {
    let pages = tldr::pages();
    match tldr::date_en_clair() {
        Some(date) if !pages.is_empty() => {
            let n: usize = pages.iter().map(|page| page.programme.commandes.len()).sum();
            trf!("{n} exemples, du {date}", "{n} examples, from {date}")
        }
        _ if tldr::en_cours() => tr!("téléchargement en cours…", "downloading…").to_string(),
        _ => tr!("à télécharger (Internet)", "to download (Internet)").to_string(),
    }
}

/// Les pages de tldr-pages pour la recherche du menu du guide : une ligne par page (« 9.1234 »), trouvée aussi par
/// les explications de ses exemples.
fn lignes_de_tldr() -> Vec<Ligne> {
    let Some(rang) = SYSTEMES.iter().position(|s| *s == Systeme::Tldr) else {
        return Vec::new();
    };
    tldr::pages()
        .iter()
        .enumerate()
        .map(|(j, page)| {
            let p = &page.programme;
            let explications: Vec<&str> = p.commandes.iter().map(|c| c.texte.0).collect();
            Ligne::cachee(
                &format!("{}.{}", rang + 1, j + 1),
                &format!("tldr › {} ›", page.plateforme),
                p.nom,
                p.role.0,
            )
            .avec_mots(&explications.join(" "))
        })
        .collect()
}

/// Le système désigné par un mot (« mac », « Fedora », « tous », « linux » pour les programmes communs).
fn systeme(mot: &str) -> Option<Systeme> {
    let m = simplifier(mot);
    SYSTEMES
        .into_iter()
        .chain([Systeme::Linux])
        .find(|s| s.mots().contains(&m.as_str()))
}

/// Les programmes qui portent ce nom (« winget », ou l'un de ceux réunis : « du » dans « lsblk, df, du »).
fn programmes_nommes(tape: &str) -> Vec<(Systeme, &'static Programme)> {
    let n = simplifier(tape);
    pages()
        .into_iter()
        .filter(|page| {
            page.programme
                .nom
                .split(',')
                .any(|morceau| simplifier(morceau.trim()) == n)
        })
        .map(|page| (page.systeme, page.programme))
        .collect()
}

/// « vanguard guide [quoi] » : sans rien, le menu ; un système, toutes ses commandes ; un programme, les siennes ;
/// sinon, la recherche de ces mots.
pub fn executer(quoi: &str, sommaire: bool) {
    let quoi = quoi.trim();
    if quoi.is_empty() {
        menu();
        return;
    }
    // « vanguard guide 6.7.2 » : la page de ce chemin, comme au menu (10.6.7.2, que le pied de page cite aussi : un
    // chemin à quatre nombres commence par la touche du guide).
    let sans_cle = quoi
        .strip_prefix(&format!("{}.", crate::cle_du_guide()))
        .filter(|reste| reste.split('.').count() == 3)
        .unwrap_or(quoi);
    if sans_cle.starts_with(|c: char| c.is_ascii_digit())
        && let Some((s, p, c)) = chemin(sans_cle)
    {
        if page_existe(s, p, c) {
            ouvrir(s, p, c);
        } else {
            trp!(
                "  Aucune page du guide à ce chemin : « {} ». vanguard guide <système> --sommaire donne les chemins.",
                "  No guide page at this path: “{}”. vanguard guide <system> --summary gives the paths.",
                affichable(quoi)
            );
            std::process::exit(1);
        }
        return;
    }
    if let Some(s) = systeme(quoi)
        && sommaire
    {
        titre(&trf!("Guide des commandes › {}", "Command guide › {}", s.nom()));
        for (proprietaire, p) in s.programmes() {
            // Le chemin de la page, celui que le menu et « vanguard guide <chemin> » ouvrent (les communs à Linux se
            // disent dans une distribution).
            let ici = place(proprietaire, p, None).unwrap_or_else(|| "?".to_string());
            println!(
                "  {GRAS}{:<7}{RESET}{:<28} {GRIS}{}{RESET}",
                ici,
                couper(nom(p), 28),
                dans_la_langue(p.role)
            );
        }
        return;
    }
    if let Some(s) = systeme(quoi) {
        if s == Systeme::Tldr {
            titre("tldr-pages");
            afficher_aligne("  ", s.presentation(), 2, GRIS);
            afficher_aligne("  ", &apercu_tldr(), 2, "");
            return;
        }
        titre(&trf!("Guide des commandes › {}", "Command guide › {}", s.nom()));
        afficher_aligne("  ", s.presentation(), 2, GRIS);
        for l in legende(s) {
            println!("{l}");
        }
        for (proprietaire, p) in s.programmes() {
            afficher_programme(proprietaire, p);
        }
        return;
    }
    let nommes = programmes_nommes(quoi);
    if nommes.is_empty() {
        titre(tr!("Guide des commandes", "Command guide"));
        afficher_resultats(quoi, &trouver(quoi));
    } else {
        for (s, p) in nommes {
            afficher_programme(s, p);
        }
    }
    // Et les pages de tldr-pages de ce nom (« tar » : celle de tous les systèmes, celle de Linux…).
    let voulu = simplifier(quoi);
    for page in tldr::pages()
        .iter()
        .filter(|page| simplifier(page.programme.nom) == voulu)
    {
        titre(&format!("tldr-pages › {} › {}", page.plateforme, page.programme.nom));
        afficher_aligne("  ", page.programme.role.0, 2, GRIS);
        println!();
        for c in page.programme.commandes {
            for l in envelopper(c.ligne, LARGEUR - 4) {
                println!("    {GRAS}{l}{RESET}");
            }
            for l in envelopper(c.texte.0, LARGEUR - 6) {
                println!("      {GRIS}{l}{RESET}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les chemins que d'autres citent (le test de la VM, le CHANGELOG, l'aide) ne changent jamais de sens : un
    /// système ou un programme ajouté va en fin de liste.
    #[test]
    fn chemins_figes() {
        let systeme = |n: usize| SYSTEMES[n - 1];
        assert_eq!(
            [systeme(6), systeme(7), systeme(8), systeme(9), systeme(10)],
            [
                Systeme::Windows,
                Systeme::MacOs,
                Systeme::Tous,
                Systeme::Tldr,
                Systeme::Vanguard
            ]
        );
        let programme = |s: usize, p: usize| systeme(s).programmes()[p - 1].1.nom;
        assert_eq!(programme(6, 7), "winget");
        assert_eq!(programme(6, 11), "ipconfig");
        assert_eq!(programme(6, 36), "Get-NetConnectionProfile");
    }

    /// Les commandes de Vanguard (10.10) : chaque commande visible y est, une fois.
    #[test]
    fn chaque_commande_dans_commandes_de_vanguard() {
        use clap::CommandFactory;
        let lignes: Vec<&str> = Systeme::Vanguard
            .programmes()
            .iter()
            .flat_map(|(_, p)| p.commandes.iter().map(|c| c.ligne))
            .collect();
        for c in crate::Args::command()
            .get_subcommands()
            .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        {
            let voulu = format!("vanguard {}", c.get_name());
            assert_eq!(lignes.iter().filter(|l| **l == voulu).count(), 1, "{voulu}");
        }
    }

    /// Chaque commande du guide une fois, avec le système sous lequel elle s'affiche.
    fn toutes() -> impl Iterator<Item = Trouvee> {
        pages().into_iter().flat_map(|page| {
            page.programme
                .commandes
                .iter()
                .map(move |c| (page.systeme, page.programme, c))
        })
    }

    /// Les systèmes du menu, et celui des programmes communs à Linux.
    fn tous_les_systemes() -> impl Iterator<Item = Systeme> {
        SYSTEMES.into_iter().chain([Systeme::Linux])
    }

    /// Les « <…> » d'une commande.
    fn a_remplacer(ligne: &str) -> Vec<&str> {
        ligne
            .match_indices('<')
            .filter_map(|(debut, _)| ligne[debut..].find('>').map(|fin| &ligne[debut..=debut + fin]))
            .collect()
    }

    #[test]
    fn chaque_programme_tient_dans_son_menu() {
        for s in tous_les_systemes() {
            assert!(largeur_affichee(s.apercu()) <= 33, "{}", s.apercu());
            let mut noms = std::collections::HashSet::new();
            for (_, p) in s.programmes() {
                assert!(noms.insert(p.nom), "{} : deux fois dans {}", p.nom, s.nom());
                assert!(!p.commandes.is_empty(), "{} n'a pas de commande", p.nom);
                assert!(largeur_affichee(p.nom) <= 30, "{} : nom trop long", p.nom);
                // « PowerShell : réseau » se traduit ; « lsblk, df, du » est fait de noms de commandes.
                if p.nom.contains(" : ") {
                    assert!(NOMS_EN.iter().any(|(fr, _)| *fr == p.nom), "{} sans nom anglais", p.nom);
                }
                for r in [p.role.0, p.role.1] {
                    assert!(
                        !r.is_empty() && largeur_affichee(r) <= 33,
                        "{} : « {r} » trop long",
                        p.nom
                    );
                }
            }
        }
    }

    #[test]
    fn chaque_commande_est_expliquee_et_tient_dans_76_colonnes() {
        for (s, p, c) in toutes() {
            let ou = format!("{} › {} : {}", s.nom(), p.nom, c.ligne);
            assert!(
                !c.texte.0.is_empty() && !c.texte.1.is_empty(),
                "{ou} : explication manquante"
            );
            // Deux espaces, la marque ⚠, un espace, puis la commande, en entier sur sa ligne.
            for l in [c.ligne.to_string(), c.ligne_en.to_string(), en_anglais(c.ligne)] {
                assert!(largeur_affichee(&l) <= LARGEUR - 4, "{ou} : trop longue ({l})");
            }
            for t in [c.texte.0, c.texte.1] {
                assert!(
                    envelopper(t, LARGEUR - 6).len() <= 2,
                    "{ou} : explication de plus de deux lignes"
                );
            }
        }
    }

    #[test]
    fn le_presse_papier_suit_le_bureau() {
        assert_eq!(scripts_presse_papier(false, false, false), [] as [&str; 0]);
        assert!(scripts_presse_papier(true, false, false)[0].contains("pbcopy"));
        let linux = scripts_presse_papier(false, true, true);
        assert!(linux[0].contains("wl-copy") && linux[1].contains("xclip") && linux[2].contains("xsel"));
    }

    /// La commande copiée arrive telle quelle à l'outil : ni « $( ) », ni apostrophe, ni « ; » ne s'exécutent. `cat`
    /// prend la place de pbcopy pour lire ce qu'il reçoit.
    #[cfg(unix)]
    #[test]
    fn la_commande_copiee_reste_du_texte() {
        let piege = r#"-n echo "$(touch /tmp/x)" '; echo INJECTE; ' `id` $HOME \ <fichier>"#;
        let script = scripts_presse_papier(true, false, false)[0].replace("pbcopy", "cat");
        let r =
            crate::commande::lancer(std::process::Command::new("sh").args(["-c", &script, "sh", piege]), 5).unwrap();
        assert_eq!((r.code, r.sortie.as_str()), (Some(0), piege));
    }

    #[test]
    fn chaque_mot_a_remplacer_a_son_nom_anglais() {
        for (s, p, c) in toutes() {
            for mot in a_remplacer(c.ligne) {
                assert!(
                    A_REMPLACER.iter().any(|(fr, _)| *fr == mot),
                    "{} › {} : « {mot} » sans traduction",
                    s.nom(),
                    p.nom
                );
            }
            assert!(!en_anglais(c.ligne).contains("<numéro>"));
        }
        assert_eq!(en_anglais("sudo pacman -S <paquet>"), "sudo pacman -S <package>");
    }

    /// Une apostrophe ou un guillemet oublié ne se verrait que chez quelqu'un, en tapant la commande.
    #[cfg(unix)]
    #[test]
    fn les_commandes_de_linux_et_macos_sont_du_shell_valide() {
        for (s, p, c) in toutes().filter(|(s, ..)| *s != Systeme::Windows) {
            let mut l = c.ligne.to_string();
            for mot in a_remplacer(c.ligne) {
                l = l.replace(mot, &mot[1..mot.len() - 1].replace(' ', "_"));
            }
            let valide = std::process::Command::new("bash")
                .args(["-n", "-c", &l])
                .status()
                .is_ok_and(|st| st.success());
            assert!(valide, "{} › {} : {l}", s.nom(), p.nom);
        }
    }

    #[test]
    fn les_commandes_de_tous_les_systemes_marchent_aussi_sous_windows_powershell() {
        // PowerShell 5.1 ne connaît ni « && » ni « || », et « curl » y est un autre programme (Invoke-WebRequest).
        for (_, p, c) in toutes().filter(|(s, ..)| *s == Systeme::Tous) {
            assert!(
                !c.ligne.contains("&&") && !c.ligne.contains("||"),
                "{} : {}",
                p.nom,
                c.ligne
            );
        }
        for (_, p, c) in toutes().filter(|(s, ..)| *s == Systeme::Windows) {
            assert!(
                !c.ligne.contains("&&") && !c.ligne.contains("||"),
                "{} : {}",
                p.nom,
                c.ligne
            );
        }
    }

    #[test]
    fn recherche_sans_accents_ni_majuscules() {
        let noms = |r: &str| trouver(r).iter().map(|(s, p, _)| (*s, p.nom)).collect::<Vec<_>>();
        assert!(
            noms("ECHEC").iter().any(|(_, n)| *n == "systemctl"),
            "« échec » sans accent"
        );
        assert!(
            noms("wifi").iter().any(|(s, _)| *s == Systeme::Windows),
            "« Wi-Fi » sans tiret"
        );
        // Tous les mots comptent.
        let sante_disque = noms("sante disque");
        assert!(sante_disque.iter().any(|(_, n)| *n == "smartctl"));
        assert!(sante_disque.iter().all(|(_, n)| *n != "winget"));
        // Un mot court commence un mot : « ip » trouve ip, ipconfig, pas « description ».
        assert!(noms("ip").iter().any(|(_, n)| n.starts_with("ip")));
        assert!(trouver("").is_empty() && trouver("zzzqqq").is_empty());
        assert_eq!(simplifier("Wi-Fi, Échec, cœur"), "wifi, echec, coeur");
    }

    #[test]
    fn systeme_ou_programme_par_son_nom() {
        assert_eq!(systeme("Mac"), Some(Systeme::MacOs));
        assert_eq!(systeme("tous"), Some(Systeme::Tous));
        assert_eq!(systeme("winget"), None);
        assert_eq!(programmes_nommes("WINGET").len(), 1);
        // Un des programmes réunis sous un même nom.
        assert!(programmes_nommes("du").iter().any(|(s, _)| *s == Systeme::Linux));
        assert!(programmes_nommes("pas-un-programme").is_empty());
    }

    #[test]
    fn programme_present_ou_non() {
        let p = |executable| Programme {
            nom: "essai",
            role: ("essai", "test"),
            executable,
            commandes: &[],
        };
        assert!(installe(&p("")));
        assert!(!installe(&p("vanguard-programme-qui-n-existe-pas")));
        #[cfg(unix)]
        {
            assert!(installe(&p("sh")));
            assert!(installe(&p("/bin/sh")));
        }
    }

    #[test]
    fn chemins_du_guide() {
        assert_eq!(chemin("3"), Some((3, None, None)));
        assert_eq!(chemin(" 3.1 "), Some((3, Some(1), None)));
        assert_eq!(chemin("3.1.2"), Some((3, Some(1), Some(2))));
        for faux in ["", "x", "3.", "3.x", "3.1.", "3.1.2.4", ".1"] {
            assert_eq!(chemin(faux), None, "{faux}");
        }
    }

    /// Chaque commande a sa ligne de recherche, une seule, et sa touche mène à elle.
    #[test]
    fn chaque_commande_se_trouve_et_s_ouvre_par_son_chemin() {
        let lignes = lignes_de_recherche("10");
        let mut touches = HashSet::new();
        let mut commandes = 0;
        for l in &lignes {
            let Ligne::Cachee { touche, texte, .. } = l else {
                panic!("le guide n'ajoute que des lignes cachées");
            };
            assert!(touches.insert(touche.clone()), "{touche} deux fois");
            let (s, p, c) = chemin(touche.strip_prefix("10.").unwrap()).unwrap();
            let systeme = SYSTEMES[s - 1];
            let Some(p) = p else { continue };
            let (_, programme) = systeme.programmes()[p - 1];
            let Some(c) = c else {
                assert_eq!(texte, nom(programme));
                continue;
            };
            let commande = &programme.commandes[c - 1];
            assert_eq!(texte.trim_start_matches("⚠ "), ligne(commande));
            commandes += 1;
        }
        assert_eq!(commandes, toutes().count());
        // Dans le menu du guide, les mêmes lignes, sans les systèmes, ni « 10. ».
        let du_guide = lignes_de_recherche("");
        assert_eq!(du_guide.len(), lignes.len() - SYSTEMES.len());
    }

    /// Ce que plusieurs distributions montrent (pacman sous Omarchy et Arch) ne s'écrit qu'une fois, et la recherche
    /// ne le compte qu'une fois : deux programmes du même nom sont le même.
    #[test]
    fn les_programmes_partages_sont_les_memes() {
        let mut vus: std::collections::HashMap<(&str, &str), Vec<&str>> = std::collections::HashMap::new();
        for s in tous_les_systemes() {
            for p in s.propres().iter().chain(s.pas_a_pas()) {
                let lignes: Vec<&str> = p.commandes.iter().map(|c| c.ligne).collect();
                if let Some(deja) = vus.insert((p.nom, p.role.0), lignes.clone()) {
                    assert_eq!(deja, lignes, "deux programmes « {} » différents", p.nom);
                }
            }
        }
        // Une distribution : les siens d'abord, puis les communs, sous « Linux ».
        let fedora = Systeme::Fedora.programmes();
        assert_eq!(fedora[0].1.nom, "Pas à pas : mettre à jour");
        assert!(fedora.iter().any(|(_, p)| p.nom == "dnf"));
        assert_eq!(fedora.last().unwrap().0, Systeme::Linux);
        assert!(
            Systeme::Windows
                .programmes()
                .iter()
                .all(|(s, _)| *s == Systeme::Windows)
        );
    }

    #[test]
    fn distribution_d_apres_os_release() {
        let os = |texte: &str| distribution(texte);
        assert_eq!(os("NAME=\"Omarchy\"\nID=omarchy\nID_LIKE=arch\n"), Systeme::Omarchy);
        assert_eq!(os("ID=arch\n"), Systeme::Arch);
        assert_eq!(os("ID=endeavouros\nID_LIKE=arch\n"), Systeme::Arch);
        assert_eq!(os("ID=fedora\nVERSION_ID=43\n"), Systeme::Fedora);
        assert_eq!(os("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n"), Systeme::Fedora);
        assert_eq!(os("ID=debian\n"), Systeme::Debian);
        assert_eq!(os("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"), Systeme::Debian);
        assert_eq!(
            os("ID=\"opensuse-tumbleweed\"\nID_LIKE=\"opensuse suse\"\n"),
            Systeme::AutresLinux
        );
        assert_eq!(os("ID=nixos\n"), Systeme::AutresLinux);
        assert_eq!(os(""), Systeme::AutresLinux);
        // VERSION_ID ou ID_LIKE ne passent pas pour ID.
        assert_eq!(os("VERSION_ID=arch\nID_LIKE=debian\nID=pop\n"), Systeme::Debian);
    }

    #[test]
    fn ce_que_vanguard_lance_ici() {
        let trouve = |l: &str| toutes().find(|(_, _, c)| c.ligne == l).unwrap().2;
        for l in [
            "ip -br a",
            "journalctl -f",
            "Get-NetAdapter",
            "ping 1.1.1.1",
            "tmutil status",
        ] {
            assert_eq!(lancement::obstacle(trouve(l)), None, "{l}");
        }
        for l in [
            "top",
            "sudo ufw status verbose",
            "fwupdmgr refresh",
            "msinfo32",
            "start ms-settings:windowsupdate",
            "powercfg /batteryreport",
            "chkdsk C:",
            "open -a Console",
        ] {
            assert!(lancement::obstacle(trouve(l)).is_some(), "{l}");
        }
        // Une commande qui change quelque chose, ou à compléter, ne se lance jamais d'ici.
        for (_, _, c) in toutes() {
            if c.modifie || c.ligne.contains('<') || c.ligne.starts_with("vanguard") {
                assert!(lancement::obstacle(c).is_some(), "{}", c.ligne);
            }
        }
    }

    /// Une commande qui ouvre une fenêtre ou prend tout le terminal le dit, même ajoutée plus tard.
    #[test]
    fn les_fenetres_et_le_plein_ecran_sont_marques() {
        for (s, _, c) in toutes() {
            let premier = c.ligne.split_whitespace().next().unwrap_or("").to_lowercase();
            let fenetre = [
                "start", "open", "explorer", "msinfo32", "dxdiag", "perfmon", "eventvwr", "taskmgr", "msconfig",
                "winver", "control", "mmc", "rstrui",
            ]
            .contains(&premier.as_str())
                || Path::new(&premier)
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("msc"));
            if fenetre && !c.modifie && !c.ligne.contains('<') {
                assert_eq!(c.obstacle, Obstacle::Fenetre, "{} › {}", s.nom(), c.ligne);
            }
            if ["top", "htop", "btop", "less", "more", "nano", "vi", "vim"].contains(&premier.as_str()) {
                assert_eq!(c.obstacle, Obstacle::PleinEcran, "{} › {}", s.nom(), c.ligne);
            }
        }
    }

    /// Une commande dont le texte dit qu'elle demande l'administrateur ne se lance pas d'ici, même ajoutée plus tard :
    /// sous Windows, rien ne le voit tout seul (seul sudo est reconnu). Elle change quelque chose, ou elle est marquée
    /// (Longue : plusieurs minutes, administrateur compris).
    #[test]
    fn les_commandes_administrateur_sont_marquees() {
        for (s, _, c) in toutes() {
            let administrateur = [c.texte.0, c.texte.1].iter().any(|t| {
                t.contains("(administrat")
                    || t.contains("terminal administrateur")
                    || t.contains("administrator terminal")
            });
            if administrateur {
                assert!(
                    c.modifie || matches!(c.obstacle, Obstacle::Administrateur | Obstacle::Longue),
                    "{} › {} : administrateur dans son texte, sans .sauf(Obstacle::Administrateur)",
                    s.nom(),
                    c.ligne
                );
            }
        }
    }

    /// Le test de la VM Windows (outils/test-windows/test.ps1) ouvre le guide par des chemins tapés : ils doivent mener
    /// aux commandes qu'il attend. Une marche à suivre ajoutée décale les numéros, et la passe de la VM ne le dirait
    /// que le jour de la publication.
    #[cfg(unix)]
    #[test]
    fn les_chemins_du_test_de_la_vm_menent_aux_bonnes_commandes() {
        let script =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/outils/test-windows/test.ps1")).unwrap();
        for (tape, attendue) in [
            ("10.6.7.2", "winget upgrade --all"),
            ("10.6.11.1", "ipconfig /all"),
            ("10.6.36.1", "Get-NetConnectionProfile"),
        ] {
            assert!(script.contains(&format!("\"{tape}`n")), "test.ps1 n'ouvre plus {tape}");
            let (s, p, c) = chemin(tape.strip_prefix("10.").unwrap()).unwrap();
            let (_, programme) = SYSTEMES[s - 1].programmes()[p.unwrap() - 1];
            assert_eq!(programme.commandes[c.unwrap() - 1].ligne, attendue, "{tape}");
        }
    }

    /// Le cadre d'une page de programme ou de commande tient dans 76 colonnes, même au plus long chemin.
    #[test]
    fn chaque_en_tete_tient_dans_76_colonnes() {
        for page in pages() {
            let p = page.programme;
            for droite in [
                format!("{} commandes", p.commandes.len()),
                format!("{0} sur {0}", p.commandes.len()),
            ] {
                for l in entete(&["Guide", page.systeme.nom(), nom(p)], &droite) {
                    let Ligne::Texte(l) = l else { unreachable!() };
                    assert!(
                        largeur_affichee(&l) <= LARGEUR,
                        "{} › {} : {l}",
                        page.systeme.nom(),
                        p.nom
                    );
                }
            }
        }
    }
}
