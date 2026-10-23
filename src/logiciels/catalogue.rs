//! Les logiciels proposés : les meilleurs de chaque usage, libres pour la plupart, chacun avec sa source officielle
//! sur chaque système. Identifiants vérifiés en octobre 2026 : paquets des distributions (Repology, dépôts
//! officiels), Flathub, Homebrew et le dépôt winget de Microsoft. Absent d'une distribution, un logiciel passe par
//! Flathub ; un logiciel qui ne convient pas à un système n'y est pas proposé (VeraCrypt sur Mac demande une
//! extension du noyau qui oblige à baisser la sécurité du système, qBittorrent n'y passe plus la vérification
//! d'Apple).

use crate::ui::tr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Categorie {
    Internet,
    Echanges,
    Securite,
    Bureautique,
    Multimedia,
    Creation,
    Systeme,
    Programmation,
}

impl Categorie {
    pub const TOUTES: [Categorie; 8] = [
        Categorie::Internet,
        Categorie::Echanges,
        Categorie::Securite,
        Categorie::Bureautique,
        Categorie::Multimedia,
        Categorie::Creation,
        Categorie::Systeme,
        Categorie::Programmation,
    ];

    pub fn titre(self) -> &'static str {
        match self {
            Categorie::Internet => tr!("Navigateurs et courriel", "Browsers and email"),
            Categorie::Echanges => tr!("Messagerie et partage", "Messaging and sharing"),
            Categorie::Securite => tr!("Sécurité et vie privée", "Security and privacy"),
            Categorie::Bureautique => tr!("Bureautique et lecture", "Office and reading"),
            Categorie::Multimedia => tr!("Vidéo et musique", "Video and music"),
            Categorie::Creation => tr!("Images et création", "Images and design"),
            Categorie::Systeme => tr!("Outils système", "System tools"),
            Categorie::Programmation => tr!("Programmation", "Programming"),
        }
    }
}

/// Un logiciel : à quoi il sert, sa licence, et comment l'installer sur chaque système.
pub struct Logiciel {
    pub nom: &'static str,
    pub categorie: Categorie,
    pub role: (&'static str, &'static str),
    /// Licence libre (identifiant SPDX) ; `None` : gratuit, mais pas libre.
    pub licence: Option<&'static str>,
    /// Fait partie du pack de départ (un navigateur, les mots de passe, la vidéo, la bureautique, les archives).
    pub recommande: bool,
    /// Paquets pour pacman, apt, dnf, zypper (vide : pas dans la distribution, ou pas complet, voir `flatpak`).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub paquets: [&'static [&'static str]; 4],
    /// Identifiant Flathub, quand la distribution n'a pas le logiciel.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub flatpak: Option<&'static str>,
    /// Linux : programmes qui le trahissent s'il a été installé autrement (AUR, paquet de l'éditeur, Snap).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub commandes: &'static [&'static str],
    /// Identifiant winget, et le début du nom affiché dans « Applications installées ».
    #[cfg_attr(not(windows), allow(dead_code))]
    pub winget: Option<(&'static str, &'static str)>,
    /// macOS : application Homebrew (cask) et début du nom de l'app dans /Applications.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub mac: Option<(&'static str, &'static str)>,
}

const AUCUN: [&[&str]; 4] = [&[], &[], &[], &[]];

/// Applications Flathub qui ne sont pas la version libre du logiciel (l'éditeur y publie sa version commerciale) :
/// installé par là, le logiciel se dit « pas libre », quelle que soit sa licence ailleurs.
pub const FLATHUB_PAS_LIBRE: &[&str] = &["com.bitwarden.desktop"];

pub const CATALOGUE: &[Logiciel] = &[
    // ── Navigateurs et courriel ──
    Logiciel {
        nom: "Firefox",
        categorie: Categorie::Internet,
        role: (
            "Navigateur web rapide, qui respecte la vie privée.",
            "Fast web browser that respects your privacy.",
        ),
        licence: Some("MPL-2.0"),
        recommande: true,
        paquets: [&["firefox"], &["firefox-esr"], &["firefox"], &["MozillaFirefox"]],
        flatpak: Some("org.mozilla.firefox"),
        commandes: &["firefox", "firefox-esr"],
        winget: Some(("Mozilla.Firefox", "Mozilla Firefox")),
        mac: Some(("firefox", "Firefox")),
    },
    Logiciel {
        nom: "Brave",
        categorie: Categorie::Internet,
        role: (
            "Navigateur qui bloque d'office les publicités et les pisteurs.",
            "Browser that blocks ads and trackers out of the box.",
        ),
        licence: Some("MPL-2.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("com.brave.Browser"),
        commandes: &["brave", "brave-browser"],
        winget: Some(("Brave.Brave", "Brave")),
        mac: Some(("brave-browser", "Brave Browser")),
    },
    Logiciel {
        nom: "LibreWolf",
        categorie: Categorie::Internet,
        role: (
            "Firefox renforcé : pisteurs bloqués, aucune télémétrie.",
            "Hardened Firefox: trackers blocked, no telemetry.",
        ),
        licence: Some("MPL-2.0"),
        recommande: false,
        paquets: [&["librewolf"], &[], &[], &[]],
        flatpak: Some("io.gitlab.librewolf-community"),
        commandes: &["librewolf"],
        winget: Some(("LibreWolf.LibreWolf", "LibreWolf")),
        mac: Some(("librewolf", "LibreWolf")),
    },
    Logiciel {
        nom: "Google Chrome",
        categorie: Categorie::Internet,
        role: ("Navigateur web de Google.", "Google's web browser."),
        licence: None,
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("com.google.Chrome"),
        commandes: &["google-chrome-stable", "google-chrome"],
        winget: Some(("Google.Chrome", "Google Chrome")),
        mac: Some(("google-chrome", "Google Chrome")),
    },
    Logiciel {
        nom: "Thunderbird",
        categorie: Categorie::Internet,
        role: (
            "Courriel, agenda et contacts, pour tous vos comptes.",
            "Email, calendar and contacts, for all your accounts.",
        ),
        licence: Some("MPL-2.0"),
        recommande: false,
        paquets: [
            &["thunderbird"],
            &["thunderbird"],
            &["thunderbird"],
            &["MozillaThunderbird"],
        ],
        flatpak: Some("org.mozilla.Thunderbird"),
        commandes: &["thunderbird"],
        winget: Some(("Mozilla.Thunderbird", "Mozilla Thunderbird")),
        mac: Some(("thunderbird", "Thunderbird")),
    },
    // ── Messagerie et partage ──
    Logiciel {
        nom: "Signal",
        categorie: Categorie::Echanges,
        role: (
            "Messagerie chiffrée de bout en bout (se relie à votre téléphone).",
            "End-to-end encrypted messaging (links to your phone).",
        ),
        licence: Some("AGPL-3.0"),
        recommande: false,
        paquets: [&["signal-desktop"], &[], &[], &[]],
        flatpak: Some("org.signal.Signal"),
        commandes: &["signal-desktop"],
        winget: Some(("OpenWhisperSystems.Signal", "Signal")),
        mac: Some(("signal", "Signal")),
    },
    Logiciel {
        nom: "Discord",
        categorie: Categorie::Echanges,
        role: (
            "Discussion écrite et vocale (jeux, amis).",
            "Text and voice chat (games, friends).",
        ),
        licence: None,
        recommande: false,
        paquets: [&["discord"], &[], &[], &[]],
        flatpak: Some("com.discordapp.Discord"),
        commandes: &["discord"],
        winget: Some(("Discord.Discord", "Discord")),
        mac: Some(("discord", "Discord")),
    },
    Logiciel {
        nom: "LocalSend",
        categorie: Categorie::Echanges,
        role: (
            "Envoie fichiers et photos aux appareils du réseau local, sans Internet ni compte.",
            "Sends files and photos to devices on the local network, no Internet or account needed.",
        ),
        licence: Some("Apache-2.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("org.localsend.localsend_app"),
        commandes: &["localsend", "localsend_app"],
        winget: Some(("LocalSend.LocalSend", "LocalSend")),
        mac: Some(("localsend", "LocalSend")),
    },
    Logiciel {
        nom: "qBittorrent",
        categorie: Categorie::Echanges,
        role: (
            "Téléchargement par torrent, sans publicité.",
            "Torrent downloads, ad-free.",
        ),
        licence: Some("GPL-2.0-or-later"),
        recommande: false,
        paquets: [&["qbittorrent"], &["qbittorrent"], &["qbittorrent"], &["qbittorrent"]],
        flatpak: Some("org.qbittorrent.qBittorrent"),
        commandes: &["qbittorrent"],
        winget: Some(("qBittorrent.qBittorrent", "qBittorrent")),
        mac: None,
    },
    // ── Sécurité et vie privée ──
    Logiciel {
        nom: "Bitwarden",
        categorie: Categorie::Securite,
        role: (
            "Gestionnaire de mots de passe synchronisé : un mot de passe différent par site.",
            "Synced password manager: a different password for each site.",
        ),
        // winget et Homebrew installent encore la version GPL-3.0, Flathub la version commerciale (voir
        // FLATHUB_PAS_LIBRE) : Bitwarden a annoncé le 9 octobre 2026 une licence commerciale pour ses applications
        // distribuées. À revérifier à chaque version.
        licence: Some("GPL-3.0"),
        recommande: true,
        // Pas le paquet d'Arch : extra/bitwarden est resté en 2026.3.1, marqué périmé depuis juin 2026.
        paquets: AUCUN,
        flatpak: Some("com.bitwarden.desktop"),
        commandes: &["bitwarden", "bitwarden-desktop"],
        winget: Some(("Bitwarden.Bitwarden", "Bitwarden")),
        mac: Some(("bitwarden", "Bitwarden")),
    },
    Logiciel {
        nom: "KeePassXC",
        categorie: Categorie::Securite,
        role: (
            "Coffre de mots de passe hors ligne, dans un fichier chiffré qui vous appartient.",
            "Offline password vault, in an encrypted file that stays yours.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        // Debian l'a coupé en deux : le paquet « keepassxc » n'a plus le lien avec le navigateur, Flathub l'a.
        paquets: [&["keepassxc"], &[], &["keepassxc"], &["keepassxc"]],
        flatpak: Some("org.keepassxc.KeePassXC"),
        commandes: &["keepassxc"],
        winget: Some(("KeePassXCTeam.KeePassXC", "KeePassXC")),
        mac: Some(("keepassxc", "KeePassXC")),
    },
    Logiciel {
        nom: "VeraCrypt",
        categorie: Categorie::Securite,
        role: (
            "Chiffre une clé USB, un disque externe ou un coffre. Disque système : BitLocker ou LUKS.",
            "Encrypts a USB stick, an external drive or a vault. System drive: BitLocker or LUKS.",
        ),
        // VeraCrypt ne chiffre pas le disque système de Linux, et sous Windows BitLocker suit tout seul les
        // changements du démarrage sécurisé : le disque système se chiffre avec l'outil du système.
        licence: Some("Apache-2.0 + TrueCrypt-3.0"),
        recommande: false,
        // Un Flatpak ne peut pas monter de volume chiffré : seulement le paquet de la distribution.
        paquets: [&["veracrypt"], &[], &[], &[]],
        flatpak: None,
        commandes: &["veracrypt"],
        winget: Some(("IDRIX.VeraCrypt", "VeraCrypt")),
        mac: None,
    },
    Logiciel {
        nom: "Cryptomator",
        categorie: Categorie::Securite,
        role: (
            "Chiffre vos fichiers avant qu'ils partent dans le nuage (Drive, Dropbox, OneDrive…).",
            "Encrypts your files before they go to the cloud (Drive, Dropbox, OneDrive…).",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("org.cryptomator.Cryptomator"),
        commandes: &["cryptomator"],
        winget: Some(("Cryptomator.Cryptomator", "Cryptomator")),
        mac: Some(("cryptomator", "Cryptomator")),
    },
    Logiciel {
        nom: "Tor Browser",
        categorie: Categorie::Securite,
        role: (
            "Navigation anonyme par le réseau Tor.",
            "Anonymous browsing through the Tor network.",
        ),
        licence: Some("MPL-2.0"),
        recommande: false,
        // Debian le range dans « contrib », pas activé d'office : Flathub (publié par le projet Tor).
        paquets: [
            &["torbrowser-launcher"],
            &[],
            &["torbrowser-launcher"],
            &["torbrowser-launcher"],
        ],
        flatpak: Some("org.torproject.torbrowser-launcher"),
        commandes: &["torbrowser-launcher"],
        winget: Some(("TorProject.TorBrowser", "Tor Browser")),
        mac: Some(("tor-browser", "Tor Browser")),
    },
    Logiciel {
        nom: "Proton VPN",
        categorie: Categorie::Securite,
        role: (
            "VPN gratuit et sans limite de données, de Proton (Suisse).",
            "Free VPN with no data cap, by Proton (Switzerland).",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        // Ailleurs qu'Arch, Proton passe par son propre dépôt : rien d'officiel à installer d'ici.
        paquets: [&["proton-vpn-gtk-app"], &[], &[], &[]],
        flatpak: None,
        commandes: &["protonvpn-app"],
        winget: Some(("Proton.ProtonVPN", "Proton VPN")),
        mac: Some(("protonvpn", "ProtonVPN")),
    },
    Logiciel {
        nom: "Wireshark",
        categorie: Categorie::Securite,
        role: (
            "Analyse ce qui passe sur le réseau, paquet par paquet (pour utilisateurs avancés).",
            "Inspects network traffic, packet by packet (for advanced users).",
        ),
        licence: Some("GPL-2.0"),
        recommande: false,
        paquets: [
            &["wireshark-qt"],
            &["wireshark"],
            &["wireshark"],
            &["wireshark", "wireshark-ui-qt"],
        ],
        flatpak: None,
        commandes: &["wireshark"],
        winget: Some(("WiresharkFoundation.Wireshark", "Wireshark")),
        mac: Some(("wireshark-app", "Wireshark")),
    },
    // ── Bureautique et lecture ──
    Logiciel {
        nom: "LibreOffice",
        categorie: Categorie::Bureautique,
        role: (
            "Bureautique complète : texte, tableur, présentations ; ouvre les fichiers Office.",
            "Full office suite: documents, spreadsheets, presentations; opens Office files.",
        ),
        licence: Some("MPL-2.0"),
        recommande: true,
        paquets: [
            &["libreoffice-fresh"],
            &["libreoffice"],
            &["libreoffice"],
            &["libreoffice"],
        ],
        flatpak: Some("org.libreoffice.LibreOffice"),
        commandes: &["libreoffice", "soffice"],
        winget: Some(("TheDocumentFoundation.LibreOffice", "LibreOffice")),
        mac: Some(("libreoffice", "LibreOffice")),
    },
    Logiciel {
        nom: "ONLYOFFICE",
        categorie: Categorie::Bureautique,
        role: (
            "Bureautique à l'allure de Microsoft Office, très fidèle aux fichiers .docx et .xlsx.",
            "Office suite that looks like Microsoft Office, very faithful to .docx and .xlsx files.",
        ),
        licence: Some("AGPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("org.onlyoffice.desktopeditors"),
        commandes: &["onlyoffice-desktopeditors", "desktopeditors"],
        winget: Some(("ONLYOFFICE.DesktopEditors", "ONLYOFFICE")),
        mac: Some(("onlyoffice", "ONLYOFFICE")),
    },
    Logiciel {
        nom: "SumatraPDF",
        categorie: Categorie::Bureautique,
        role: (
            "Lecteur de PDF, livres et BD, très léger et rapide.",
            "Very light and fast reader for PDFs, e-books and comics.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("SumatraPDF.SumatraPDF", "SumatraPDF")),
        mac: None,
    },
    Logiciel {
        nom: "Calibre",
        categorie: Categorie::Bureautique,
        role: (
            "Bibliothèque de livres numériques : range, convertit, envoie vers la liseuse.",
            "E-book library: organizes, converts, sends to your e-reader.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["calibre"], &["calibre"], &["calibre"], &["calibre"]],
        flatpak: Some("com.calibre_ebook.calibre"),
        commandes: &["calibre"],
        winget: Some(("calibre.calibre", "calibre")),
        mac: Some(("calibre", "calibre")),
    },
    Logiciel {
        nom: "Joplin",
        categorie: Categorie::Bureautique,
        role: (
            "Notes et listes synchronisées, chiffrées de bout en bout si vous le voulez.",
            "Synced notes and to-do lists, end-to-end encrypted if you wish.",
        ),
        licence: Some("AGPL-3.0-or-later"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("net.cozic.joplin_desktop"),
        commandes: &[],
        winget: Some(("Joplin.Joplin", "Joplin")),
        mac: Some(("joplin", "Joplin")),
    },
    // ── Vidéo et musique ──
    Logiciel {
        nom: "VLC",
        categorie: Categorie::Multimedia,
        role: (
            "Lit toutes les vidéos et musiques, sans rien installer de plus.",
            "Plays every video and music file, nothing else to install.",
        ),
        licence: Some("GPL-2.0"),
        recommande: true,
        paquets: [&["vlc"], &["vlc"], &["vlc"], &["vlc"]],
        flatpak: Some("org.videolan.VLC"),
        commandes: &["vlc"],
        winget: Some(("VideoLAN.VLC", "VLC media player")),
        mac: Some(("vlc", "VLC")),
    },
    Logiciel {
        nom: "OBS Studio",
        categorie: Categorie::Multimedia,
        role: (
            "Enregistrer l'écran et diffuser en direct.",
            "Record the screen and stream live.",
        ),
        licence: Some("GPL-2.0"),
        recommande: false,
        paquets: [&["obs-studio"], &["obs-studio"], &["obs-studio"], &["obs-studio"]],
        flatpak: Some("com.obsproject.Studio"),
        commandes: &["obs"],
        winget: Some(("OBSProject.OBSStudio", "OBS Studio")),
        mac: Some(("obs", "OBS")),
    },
    Logiciel {
        nom: "Audacity",
        categorie: Categorie::Multimedia,
        role: (
            "Enregistre et retouche le son : voix, musique, podcasts.",
            "Records and edits audio: voice, music, podcasts.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["audacity"], &["audacity"], &["audacity"], &["audacity"]],
        flatpak: Some("org.audacityteam.Audacity"),
        commandes: &["audacity"],
        winget: Some(("Audacity.Audacity", "Audacity")),
        mac: Some(("audacity", "Audacity")),
    },
    Logiciel {
        nom: "HandBrake",
        categorie: Categorie::Multimedia,
        role: (
            "Convertit et compresse les vidéos (pour le téléphone, le web…).",
            "Converts and compresses videos (for phones, the web…).",
        ),
        licence: Some("GPL-2.0"),
        recommande: false,
        // Fedora et openSUSE ne l'ont que dans des dépôts tiers : Flathub (publié par HandBrake).
        paquets: [&["handbrake"], &["handbrake"], &[], &[]],
        flatpak: Some("fr.handbrake.ghb"),
        commandes: &["ghb"],
        winget: Some(("HandBrake.HandBrake", "HandBrake")),
        mac: Some(("handbrake-app", "HandBrake")),
    },
    Logiciel {
        nom: "Kdenlive",
        categorie: Categorie::Multimedia,
        role: (
            "Montage vidéo complet : pistes, effets, titres, transitions.",
            "Full video editor: tracks, effects, titles, transitions.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["kdenlive"], &["kdenlive"], &["kdenlive"], &["kdenlive"]],
        flatpak: Some("org.kde.kdenlive"),
        commandes: &["kdenlive"],
        winget: Some(("KDE.Kdenlive", "Kdenlive")),
        mac: Some(("kdenlive", "kdenlive")),
    },
    // ── Images et création ──
    Logiciel {
        nom: "GIMP",
        categorie: Categorie::Creation,
        role: (
            "Retouche photo et création d'images, l'équivalent libre de Photoshop.",
            "Photo retouching and image creation, the free counterpart of Photoshop.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["gimp"], &["gimp"], &["gimp"], &["gimp"]],
        flatpak: Some("org.gimp.GIMP"),
        commandes: &["gimp"],
        winget: Some(("GIMP.GIMP.3", "GIMP")),
        mac: Some(("gimp", "GIMP")),
    },
    Logiciel {
        nom: "Inkscape",
        categorie: Categorie::Creation,
        role: (
            "Dessin vectoriel : logos, affiches, schémas (format SVG).",
            "Vector drawing: logos, posters, diagrams (SVG).",
        ),
        licence: Some("GPL-2.0-or-later"),
        recommande: false,
        paquets: [&["inkscape"], &["inkscape"], &["inkscape"], &["inkscape"]],
        flatpak: Some("org.inkscape.Inkscape"),
        commandes: &["inkscape"],
        winget: Some(("Inkscape.Inkscape", "Inkscape")),
        mac: Some(("inkscape", "Inkscape")),
    },
    Logiciel {
        nom: "Krita",
        categorie: Categorie::Creation,
        role: (
            "Peinture et dessin numériques, avec tablette graphique.",
            "Digital painting and drawing, with graphics tablet support.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["krita"], &["krita"], &["krita"], &["krita"]],
        flatpak: Some("org.kde.krita"),
        commandes: &["krita"],
        winget: Some(("KDE.Krita", "Krita")),
        mac: Some(("krita", "krita")),
    },
    Logiciel {
        nom: "Blender",
        categorie: Categorie::Creation,
        role: (
            "3D complète : modélisation, animation, rendu, montage.",
            "Complete 3D: modeling, animation, rendering, editing.",
        ),
        licence: Some("GPL-3.0-or-later"),
        recommande: false,
        // openSUSE n'a que des paquets par version (« blender-5.2 ») : Flathub.
        paquets: [&["blender"], &["blender"], &["blender"], &[]],
        flatpak: Some("org.blender.Blender"),
        commandes: &["blender"],
        winget: Some(("BlenderFoundation.Blender", "Blender")),
        mac: Some(("blender", "Blender")),
    },
    Logiciel {
        nom: "ShareX",
        categorie: Categorie::Creation,
        role: (
            "Captures et vidéos de l'écran, annotées et partagées d'un raccourci.",
            "Screenshots and screen recordings, annotated and shared with one shortcut.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("ShareX.ShareX", "ShareX")),
        mac: None,
    },
    // ── Outils système ──
    Logiciel {
        nom: "7-Zip",
        categorie: Categorie::Systeme,
        role: (
            "Ouvre et crée les archives (zip, 7z, rar…).",
            "Opens and creates archives (zip, 7z, rar…).",
        ),
        licence: Some("LGPL-2.1"),
        recommande: true,
        paquets: [&["7zip"], &["7zip"], &["7zip"], &["7zip"]],
        flatpak: None,
        commandes: &["7z", "7zz"],
        winget: Some(("7zip.7zip", "7-Zip")),
        mac: None,
    },
    Logiciel {
        nom: "Keka",
        categorie: Categorie::Systeme,
        role: (
            "Ouvre et crée les archives (zip, 7z, rar…) : le 7-Zip du Mac.",
            "Opens and creates archives (zip, 7z, rar…): the Mac's 7-Zip.",
        ),
        licence: None,
        recommande: true,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: None,
        mac: Some(("keka", "Keka")),
    },
    Logiciel {
        nom: "BleachBit",
        categorie: Categorie::Systeme,
        role: (
            "Libère de la place et efface les traces : caches, historiques, fichiers temporaires.",
            "Frees space and erases traces: caches, histories, temporary files.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: [&["bleachbit"], &["bleachbit"], &["bleachbit"], &["bleachbit"]],
        flatpak: None,
        commandes: &["bleachbit"],
        winget: Some(("BleachBit.BleachBit", "BleachBit")),
        mac: None,
    },
    Logiciel {
        nom: "PowerToys",
        categorie: Categorie::Systeme,
        role: (
            "Outils pratiques de Microsoft : raccourcis, fenêtres, couleurs, renommage…",
            "Handy Microsoft tools: shortcuts, windows, colors, renaming…",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("Microsoft.PowerToys", "PowerToys")),
        mac: None,
    },
    Logiciel {
        nom: "CrystalDiskInfo",
        categorie: Categorie::Systeme,
        role: (
            "Santé des disques (SMART) : prévient avant une panne.",
            "Drive health (SMART): warns before a failure.",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("CrystalDewWorld.CrystalDiskInfo", "CrystalDiskInfo")),
        mac: None,
    },
    Logiciel {
        nom: "WinDirStat",
        categorie: Categorie::Systeme,
        role: (
            "Montre ce qui remplit le disque, dossier par dossier.",
            "Shows what fills the disk, folder by folder.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("WinDirStat.WinDirStat", "WinDirStat")),
        mac: None,
    },
    Logiciel {
        nom: "Rufus",
        categorie: Categorie::Systeme,
        role: (
            "Crée une clé USB d'installation de Windows ou de Linux. Sans icône : Windows + R, puis « rufus ».",
            "Creates a Windows or Linux install USB stick. No icon: Windows + R, then “rufus”.",
        ),
        licence: Some("GPL-3.0-or-later"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("Rufus.Rufus", "Rufus")),
        mac: None,
    },
    Logiciel {
        nom: "Mission Center",
        categorie: Categorie::Systeme,
        role: (
            "Gestionnaire des tâches : processeur, mémoire, disques, carte graphique.",
            "Task manager: CPU, memory, drives, graphics card.",
        ),
        licence: Some("GPL-3.0-or-later"),
        recommande: false,
        paquets: [&["mission-center"], &[], &[], &[]],
        flatpak: Some("io.missioncenter.MissionCenter"),
        commandes: &["missioncenter"],
        winget: None,
        mac: None,
    },
    Logiciel {
        nom: "Rectangle",
        categorie: Categorie::Systeme,
        role: (
            "Range les fenêtres au clavier ou en les glissant vers les bords de l'écran.",
            "Arranges windows with shortcuts or by dragging them to the screen edges.",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: None,
        mac: Some(("rectangle", "Rectangle")),
    },
    Logiciel {
        nom: "Stats",
        categorie: Categorie::Systeme,
        role: (
            "Processeur, mémoire, réseau et températures dans la barre des menus.",
            "CPU, memory, network and temperatures in the menu bar.",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: None,
        mac: Some(("stats", "Stats")),
    },
    // ── Programmation ──
    Logiciel {
        nom: "VSCodium",
        categorie: Categorie::Programmation,
        role: (
            "Éditeur de code : Visual Studio Code, sans la télémétrie de Microsoft.",
            "Code editor: Visual Studio Code, without Microsoft's telemetry.",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: Some("com.vscodium.codium"),
        commandes: &["codium"],
        winget: Some(("VSCodium.VSCodium", "VSCodium")),
        mac: Some(("vscodium", "VSCodium")),
    },
    Logiciel {
        nom: "Git",
        categorie: Categorie::Programmation,
        role: (
            "Suivi des versions du code, indispensable pour programmer.",
            "Version control for code, essential for programming.",
        ),
        licence: Some("GPL-2.0"),
        recommande: false,
        paquets: [&["git"], &["git"], &["git"], &["git"]],
        flatpak: None,
        commandes: &["git"],
        winget: Some(("Git.Git", "Git")),
        mac: None,
    },
    Logiciel {
        nom: "Notepad++",
        categorie: Categorie::Programmation,
        role: (
            "Éditeur de texte léger, qui colore le code.",
            "Lightweight text editor with code highlighting.",
        ),
        licence: Some("GPL-3.0"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        winget: Some(("Notepad++.Notepad++", "Notepad++")),
        mac: None,
    },
    Logiciel {
        nom: "Windows Terminal",
        categorie: Categorie::Programmation,
        role: (
            "Terminal moderne à onglets : PowerShell, invite de commandes, WSL.",
            "Modern tabbed terminal: PowerShell, Command Prompt, WSL.",
        ),
        licence: Some("MIT"),
        recommande: false,
        paquets: AUCUN,
        flatpak: None,
        commandes: &[],
        // Application du Store (MSIX) : reconnue par le nom de son paquet, pas dans « Applications installées ».
        winget: Some(("Microsoft.WindowsTerminal", "Microsoft.WindowsTerminal")),
        mac: None,
    },
];
