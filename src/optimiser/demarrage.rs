//! Programmes au démarrage : ceux qui se lancent à l'ouverture de session, retirés ou remis après accord. Chacun est
//! un réglage hors catalogue (« demarrage:<identité> ») : la valeur d'avant est notée, il s'annule exactement, un par
//! un dans cette liste ou tous par « Tout remettre comme avant ». Le programme reste installé et se lance à la main.
//! Ce qui protège ou fait marcher l'ordinateur (Vanguard, antivirus, pare-feu, pilotes, accessibilité, composants du
//! bureau) est montré sans être proposé.

use std::borrow::Cow;

use super::{Categorie, Etat, Historique, Reglage, charger, confirmer_et_executer, etat, executer, systeme};
use crate::selection::{Case, cocher};
use crate::ui::*;

/// Préfixe des réglages de démarrage dans l'historique des réglages (reglages.json).
pub(super) const PREFIXE: &str = "demarrage:";

/// Un programme lancé à l'ouverture de session, tel que le système de cette machine le décrit.
pub struct Programme {
    /// Nom affiché (« Discord »).
    pub nom: String,
    /// Ce qui est lancé (commande, fichier), pour le reconnaître.
    pub commande: String,
    /// Se lance en ce moment à l'ouverture de session.
    pub actif: bool,
    /// Programme de toute la machine : la fenêtre administrateur s'ouvrira (Windows).
    pub machine: bool,
    /// Composant de la session du bureau (GNOME, KDE…) : à garder.
    pub bureau: bool,
    /// Ce qui le retire, et le remet.
    pub changement: systeme::Changement,
}

/// Le réglage qui retire ce programme du démarrage. Le nom, écrit par qui a posé l'entrée, est montré rendu
/// inoffensif ; le changement, lui, vise la vraie entrée.
fn reglage(nom: &str, changement: systeme::Changement) -> Option<Reglage> {
    let nom = affichable(nom);
    Some(Reglage {
        id: Cow::Owned(format!("{PREFIXE}{}", changement.identite_demarrage()?)),
        // Hors des menus de catégorie : la catégorie ne sert pas.
        categorie: Categorie::Confort,
        titre: Cow::Owned(trf!("{nom} (au démarrage)", "{nom} (at startup)")),
        effet: tr!(
            "Ne se lance plus à l'ouverture de session ; il reste installé et se lance à la main.",
            "No longer starts at login; it stays installed and starts by hand."
        ),
        prudence: None,
        recommande: false,
        changements: vec![changement],
    })
}

/// Les programmes que Vanguard a retirés du démarrage, rebâtis d'après leurs notes : pour les remettre (« Tout remettre
/// comme avant », ou cette liste), même s'ils ne se lancent plus et n'apparaissent donc plus ailleurs.
pub(super) fn notes(h: &Historique) -> Vec<Reglage> {
    h.reglages
        .keys()
        .filter_map(|cle| {
            let identite = cle.strip_prefix(PREFIXE)?;
            let c = systeme::Changement::demarrage_depuis(identite)?;
            reglage(&systeme::Changement::nom_demarrage(identite), c)
        })
        .collect()
}

/// Pourquoi un programme reste au démarrage, s'il le doit : il protège ou fait marcher l'ordinateur. Comparé en
/// minuscules au nom et à la commande ; un motif court est un mot entier (« avg » ne doit pas trouver « savgame »).
#[cfg_attr(target_os = "linux", allow(dead_code))] // Linux : `classer`, qui ajoute le paquet
pub(crate) fn a_garder(nom: &str, commande: &str, bureau: bool) -> Option<&'static str> {
    a_garder_hors_pare_feu(nom, commande, bureau).or_else(|| {
        (!cfg!(target_os = "linux") && nom_de_pare_feu(nom, commande))
            .then(|| tr!("à garder : sécurité", "keep: security"))
    })
}

/// Des motifs de pare-feu (ou d'interfaces de pare-feu) dans le nom ou la commande. Sous Windows et macOS, ils gardent
/// l'élément (« sécurité ») ; sous Linux, le nom seul ne prouve rien : seul le paquet qui fournit le programme le
/// reconnaît (`classer`), et ces motifs ne servent qu'à refuser quand ce paquet ne se lit pas.
#[rustfmt::skip]
const PARE_FEU: &[&str] = &["firewall", "firewalld", "gufw", "ufw", "opensnitch", "little snitch", "lulu", "nftables"];

/// Les paquets de pare-feu de Linux (Debian, Fedora, Arch, openSUSE) et de leurs interfaces.
#[rustfmt::skip]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PAQUETS_PARE_FEU: &[&str] = &[
    "ufw", "gufw", "firewalld", "firewall-applet", "firewall-config", "firewalld-applet", "python3-firewall",
    "python-firewall", "nftables", "opensnitch", "opensnitch-ui", "python3-opensnitch-ui", "plasma-firewall",
];

/// Un mot-motif, comme `a_garder` le compare : six lettres au moins, ou une espace ou un tiret, dans le texte ; plus
/// court, un mot entier.
fn motifs_trouves(nom: &str, commande: &str, motifs: &[&str]) -> bool {
    let texte = format!("{nom} {commande}").to_lowercase();
    let mots: Vec<&str> = texte.split(|c: char| !c.is_alphanumeric()).collect();
    motifs.iter().any(|m| {
        if m.len() < 6 && !m.contains([' ', '-']) {
            mots.contains(m)
        } else {
            texte.contains(m)
        }
    })
}

fn nom_de_pare_feu(nom: &str, commande: &str) -> bool {
    motifs_trouves(nom, commande, PARE_FEU)
}

/// Ce qui reste au démarrage, hors pare-feu : antivirus et autres protections, Vanguard, pilotes, accessibilité,
/// bureau.
fn a_garder_hors_pare_feu(nom: &str, commande: &str, bureau: bool) -> Option<&'static str> {
    const VANGUARD: &[&str] = &["vanguard"];
    // Des listes de motifs, que rustfmt étalerait sur une ligne chacun.
    #[rustfmt::skip]
    const SECURITE: &[&str] = &[
        "securityhealth", "windows security", "defender", "msmpeng", "smartscreen", "mcafee", "norton", "symantec",
        "avast", "avg", "avira", "bitdefender", "eset", "kaspersky", "avp", "malwarebytes", "mbam", "sophos",
        "trendmicro", "trend micro", "f-secure", "webroot", "clamav", "clamtk",
        // Notifications d'AppArmor (Ubuntu), contrôle des clés USB.
        "apparmor", "usbguard",
        // Protections d'entreprise et autres antivirus.
        "crowdstrike", "csfalcon", "sentinelone", "cylance", "carbon black", "cbdefense", "comodo", "zonealarm",
        "panda", "emsisoft", "antivirus", "gdata", "avktray", "hitmanpro", "zemana", "acronis", "forticlient",
        "globalprotect", "zscaler", "netskope",
        // Mac : Intego, ClamXAV, les outils d'Objective-See (BlockBlock, KnockKnock, LuLu…).
        "intego", "virusbarrier", "clamxav", "objective-see", "blockblock",
        // Un VPN qui démarre avec la session protège la connexion (souvent avec un coupe-circuit).
        "wireguard", "openvpn", "protonvpn", "mullvad", "nordvpn", "expressvpn", "surfshark",
    ];
    #[rustfmt::skip]
    const PILOTES: &[&str] = &[
        "realtek", "rtkaud", "rtkngui", "ravcpl", "ravbg", "synaptics", "syntp", "etdctrl", "elantech", "igfx", "hkcmd",
        "nvidia", "nvbackend", "radeon", "amdrsserv", "wacom",
    ];
    #[rustfmt::skip]
    const ACCESSIBILITE: &[&str] = &[
        "narrator", "magnify", "osk", "sapisvr", "nvda", "jaws", "zoomtext", "orca", "onboard", "at-spi",
        "accessibility", "voiceover", "atbroker", "utilman",
    ];
    #[rustfmt::skip]
    const BUREAU: &[&str] = &[
        "pipewire", "wireplumber", "pulseaudio", "xdg-desktop-portal", "gnome-keyring", "polkit", "dbus", "gsd",
        "settingsdaemon", "plasmashell", "kded", "ksmserver",
    ];
    let texte = format!("{nom} {commande}").to_lowercase();
    // Les mots vides ne gênent pas : aucun motif n'est vide.
    let mots: Vec<&str> = texte.split(|c: char| !c.is_alphanumeric()).collect();
    // Un motif d'au moins six lettres, ou avec une espace ou un tiret, se cherche dans le texte ; plus court, c'est un
    // mot entier.
    let entier = |m: &str| m.len() < 6 && !m.contains([' ', '-']);
    let cherche = |m: &&str| if entier(m) { mots.contains(m) } else { texte.contains(m) };
    let trouve = |motifs: &[&str]| motifs.iter().any(cherche);
    // La sécurité d'abord : un antivirus reste « sécurité », quel que soit son nom.
    #[rustfmt::skip] // une ligne par raison, que rustfmt étalerait
    let raisons = [
        (trouve(SECURITE), tr!("à garder : sécurité", "keep: security")),
        (trouve(VANGUARD), tr!("à garder : Vanguard", "keep: Vanguard")),
        (trouve(PILOTES), tr!("à garder : pilote", "keep: driver")),
        (trouve(ACCESSIBILITE), tr!("à garder : accessibilité", "keep: accessibility")),
        (bureau || trouve(BUREAU), tr!("à garder : le bureau", "keep: desktop")),
    ];
    raisons.into_iter().find_map(|(oui, raison)| oui.then_some(raison))
}

/// Ce que la liste fait d'un programme : le garder (montré, jamais proposé), le proposer comme pare-feu (le retirer
/// est une baisse, avec sa question), ou comme n'importe quel programme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Garde {
    Garder(&'static str),
    PareFeu,
    Ordinaire,
}

/// Sous Linux : le programme lancé (premier mot de la commande) et le paquet qui le fournit. Sous Windows et macOS :
/// `a_garder`, comme avant.
fn classer(p: &Programme) -> Garde {
    #[cfg(target_os = "linux")]
    {
        classer_linux(
            &p.nom,
            &p.commande,
            p.bureau,
            chemin_reel,
            crate::machine::linux::etat_paquet,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        a_garder(&p.nom, &p.commande, p.bureau).map_or(Garde::Ordinaire, Garde::Garder)
    }
}

/// Le premier mot d'une ligne `Exec=` ou `ExecStart=` : préfixes de systemd (`-`, `@`, `:`, `+`, `!`) et guillemets
/// ôtés. `None` : vide, ou une enveloppe (env, un shell, une affectation `NOM=valeur`) qui cache le vrai programme.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn executable(commande: &str) -> Option<&str> {
    let premier = commande
        .trim()
        .trim_start_matches(['-', '@', ':', '+', '!'])
        .split_whitespace()
        .next()?
        .trim_matches(['"', '\'']);
    let base = premier.rsplit('/').next().unwrap_or(premier);
    let enveloppe = matches!(
        base,
        "env"
            | "sh"
            | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "nohup"
            | "setsid"
            | "flatpak"
            | "snap"
            | "python3"
            | "python"
    ) || premier.contains('=')
        || premier.is_empty();
    (!enveloppe).then_some(premier)
}

/// Le vrai chemin du programme : absolu tel quel, sinon cherché dans les dossiers du système (jamais dans le PATH du
/// compte, que n'importe quel programme peut allonger), puis liens résolus.
#[cfg(target_os = "linux")]
fn chemin_reel(programme: &str) -> Option<std::path::PathBuf> {
    const DOSSIERS: [&str; 6] = [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ];
    let p = std::path::Path::new(programme);
    let trouve = if p.is_absolute() {
        Some(p.to_path_buf())
    } else if programme.contains('/') {
        None
    } else {
        DOSSIERS
            .iter()
            .map(|d| std::path::Path::new(d).join(programme))
            .find(|c| c.is_file())
    }?;
    std::fs::canonicalize(trouve).ok().filter(|c| c.is_file())
}

/// Pure : `chemin` trouve le programme, `paquet` dit qui le fournit. Le nom seul ne fait jamais un pare-feu : un faux
/// « ufw » posé dans le dossier du compte est un programme comme un autre. Paquet illisible, fichier du paquet
/// modifié, ou programme qu'on ne peut pas suivre (enveloppe, introuvable), avec un nom de pare-feu : traité comme le
/// vrai pare-feu par prudence (R15), donc gardé, et c'est dit.
#[cfg(target_os = "linux")]
fn classer_linux(
    nom: &str,
    commande: &str,
    bureau: bool,
    chemin: impl Fn(&str) -> Option<std::path::PathBuf>,
    paquet: impl Fn(&std::path::Path) -> crate::machine::linux::EtatPaquet,
) -> Garde {
    use crate::machine::linux::EtatPaquet;
    if let Some(r) = a_garder_hors_pare_feu(nom, commande, bureau) {
        return Garde::Garder(r);
    }
    let illisible = || {
        if nom_de_pare_feu(nom, commande) {
            Garde::Garder(tr!("pare-feu ? paquet illisible", "firewall? package unreadable"))
        } else {
            Garde::Ordinaire
        }
    };
    let Some(reel) = executable(commande).and_then(&chemin) else {
        return illisible();
    };
    match paquet(&reel) {
        EtatPaquet::Intact(n) if PAQUETS_PARE_FEU.contains(&n.as_str()) => Garde::PareFeu,
        EtatPaquet::Modifie(n) if PAQUETS_PARE_FEU.contains(&n.as_str()) => {
            Garde::Garder(tr!("pare-feu : fichier modifié", "firewall: file modified"))
        }
        EtatPaquet::Illisible => illisible(),
        EtatPaquet::Aucun | EtatPaquet::Intact(_) | EtatPaquet::Modifie(_) => Garde::Ordinaire,
    }
}

/// La question de baisse (§2.0), posée sur le terminal de la personne (/dev/tty), jamais sur l'entrée du programme :
/// une réponse glissée dans un tube ne compte pas. Entrée, ou pas de terminal : non.
#[cfg(target_os = "linux")]
fn baisse_acceptee(noms: &[&str]) -> bool {
    println!();
    for n in noms {
        afficher_aligne(
            "    − ",
            &trf!(
                "{n} (pare-feu) : se lance à l'ouverture de session → NE SE LANCE PLUS",
                "{n} (firewall): starts at login → NO LONGER STARTS"
            ),
            6,
            "",
        );
    }
    afficher_aligne(
        "  ",
        tr!(
            "Le pare-feu du système garde ses règles ; ce programme (son interface ou ses questions) ne se lance plus.",
            "The system firewall keeps its rules; this program (its window or its questions) no longer starts."
        ),
        2,
        GRIS,
    );
    let question = tr!(
        "\n  Ces changements rendent votre ordinateur MOINS protégé.\n  Les avez-vous demandés vous-même, dans Vanguard, à l'instant ? Si ce n'est pas vous, répondez N.\n  Faire ces changements ? [o/N] :",
        "\n  These changes make your computer LESS protected.\n  Did you ask for them yourself, in Vanguard, just now? If it was not you, answer N.\n  Make these changes? [y/N]:"
    );
    match crate::machine::assistant::question_au_terminal(question) {
        Ok(Some(r)) => crate::langue::oui(&r),
        Ok(None) => false,
        Err(()) => {
            trp!(
                "  ✖ Aucun terminal où demander : rien n'est retiré.",
                "  ✖ No terminal to ask on: nothing is removed."
            );
            false
        }
    }
}

/// Une liste pure (§2.0) : le retrait d'un pare-feu part seul, jamais mêlé à d'autres changements.
fn liste_admise(baisses: usize, changements: usize) -> bool {
    baisses == 0 || (baisses == 1 && changements == 1)
}

#[cfg(target_os = "linux")]
fn baisse_ok(noms: &[&str]) -> bool {
    baisse_acceptee(noms)
}

/// Hors de Linux, aucun programme n'est « pare-feu » ici (`classer`) : jamais appelé ; refusé par prudence.
#[cfg(not(target_os = "linux"))]
fn baisse_ok(_noms: &[&str]) -> bool {
    false
}

/// Ce que Vanguard ne retire pas d'ici, et où le faire.
fn ailleurs() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Les tâches planifiées et les services ne sont pas dans cette liste : Gestionnaire des tâches, ou Virus et logiciels espions › Analyse antivirus › Analyse rapide (revue du démarrage).",
            "Scheduled tasks and services are not in this list: Task Manager, or Viruses and spyware › Antivirus scan › Quick scan (startup review)."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Éléments de connexion et agents de tout l'ordinateur : Réglages Système › Général › Ouverture (« − » pour retirer). Ils demandent un geste dans les Réglages ou l'administrateur. Les agents qui ne partent qu'à la demande ou à heure fixe ne sont pas dans cette liste.",
            "Login items and machine-wide agents: System Settings › General › Login Items (“−” to remove). They need a step in Settings or an administrator. Agents that only start on demand or on a schedule are not in this list."
        )
    } else {
        tr!(
            "Ce que lance la configuration du bureau (exec-once de Hyprland, par exemple), les services du système, et les entrées qui sont des liens (dotfiles, home-manager) : dans leurs fichiers.",
            "What the desktop configuration starts (Hyprland's exec-once, for example), system services, and entries that are links (dotfiles, home-manager): in their files."
        )
    }
}

// ── Windows : comme le Gestionnaire des tâches ──────────────────────────────────────────────────────────────────

/// Où Windows note les programmes de démarrage désactivés, sous HKCU (le compte) ou HKLM (la machine), puis Run,
/// Run32 ou StartupFolder.
#[cfg(windows)]
pub(super) const APPROUVES: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

/// Les listes de StartupApproved que Vanguard touche (une note ne doit pas en viser une autre).
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn liste_approuvee(l: &str) -> Option<&'static str> {
    ["Run", "Run32", "StartupFolder"].into_iter().find(|x| *x == l)
}

pub(super) fn hex(octets: &[u8]) -> String {
    use std::fmt::Write;
    octets.iter().fold(String::with_capacity(octets.len() * 2), |mut s, o| {
        let _ = write!(s, "{o:02x}");
        s
    })
}

pub(super) fn octets(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Désactivé pour Windows : premier octet impair (03, 07). Pair (02, 06) ou valeur absente : activé.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn desactive_windows(hex: &str) -> bool {
    octets(hex).and_then(|o| o.first().copied()).is_some_and(|b| b & 1 == 1)
}

/// Ce qu'écrit le Gestionnaire des tâches pour désactiver un programme : 03 00 00 00, puis l'heure du changement
/// (FILETIME : centaines de nanosecondes depuis 1601), en hexadécimal.
#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn valeur_desactivee(quand: std::time::SystemTime) -> String {
    const DE_1601_A_1970: u64 = 116_444_736_000_000_000;
    let depuis_1970 = quand.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let temps = u64::try_from(depuis_1970.as_nanos() / 100).unwrap_or(0) + DE_1601_A_1970;
    let mut o = vec![3, 0, 0, 0];
    o.extend_from_slice(&temps.to_le_bytes());
    hex(&o)
}

// ── macOS : agents de launchd du compte ─────────────────────────────────────────────────────────────────────────

/// Un nom d'agent de launchd (« com.exemple.agent ») : il entre tel quel dans une commande.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn label_valide(t: &str) -> bool {
    !t.is_empty() && t.len() <= 255 && t.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
}

/// Les réglages de launchd pour ce compte, d'après `launchctl print-disabled gui/<uid>` : nom de l'agent → désactivé.
/// « "com.x" => disabled » ou « => enabled » (« => true » ou « => false » sur les anciens macOS). Un agent absent de
/// la liste suit la clé « Disabled » de son plist.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn etats_launchd(texte: &str) -> std::collections::HashMap<String, bool> {
    texte
        .lines()
        .filter_map(|l| {
            let (label, etat) = l.trim().split_once("=>")?;
            let desactive = match etat.trim() {
                "disabled" | "true" => true,
                "enabled" | "false" => false,
                _ => return None,
            };
            Some((label.trim().trim_matches('"').to_string(), desactive))
        })
        .collect()
}

/// La valeur d'une clé extraite par `plutil -extract <clé> xml1` : le premier élément sous `<plist …>` (« `<true/>` »,
/// « `<dict>` »…).
fn valeur_plist(xml: &str) -> Option<&str> {
    let apres = &xml[xml.find("<plist")?..];
    let apres = apres[apres.find('>')? + 1..].trim_start();
    let fin = apres.find('>')? + 1;
    Some(&apres[..fin])
}

/// Un agent du compte se lance-t-il à l'ouverture de session ? `run_at_load`, `keep_alive` : ces clés de son plist,
/// extraites en XML (`None` : absentes). Sans « RunAtLoad » vrai ni « KeepAlive » (vrai, ou des conditions), il ne part
/// qu'à la demande ou à heure fixe, comme une tâche planifiée : il n'est pas dans la liste.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn agent_au_demarrage(run_at_load: Option<&str>, keep_alive: Option<&str>) -> bool {
    run_at_load.and_then(valeur_plist) == Some("<true/>")
        || keep_alive.and_then(valeur_plist).is_some_and(|v| v != "<false/>")
}

/// L'agent est-il actif ? Le réglage de launchd (`surcharge`, désactivé ou non) l'emporte sur la clé « Disabled » du
/// plist (`disabled`, extraite en XML). Sans ce calcul, un agent que son plist désactive paraissait actif : le retirer
/// puis le remettre l'aurait activé (« launchctl enable » l'emporte sur le plist), ce qu'il n'était pas avant.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn agent_actif(surcharge: Option<bool>, disabled: Option<&str>) -> bool {
    match surcharge {
        Some(desactive) => !desactive,
        None => disabled.and_then(valeur_plist) != Some("<true/>"),
    }
}

/// Un programme de la liste : ce qui l'affiche et le réglage qui le retire.
struct Ligne {
    nom: String,
    commande: String,
    actif: bool,
    machine: bool,
    garde: Garde,
    par_vanguard: bool,
    reglage: Reglage,
}

impl Ligne {
    /// Pourquoi il reste, s'il le doit.
    fn garder(&self) -> Option<&'static str> {
        match self.garde {
            Garde::Garder(r) => Some(r),
            Garde::PareFeu | Garde::Ordinaire => None,
        }
    }

    /// Un pare-feu reconnu par son paquet : le retirer est une baisse.
    fn pare_feu(&self) -> bool {
        self.garde == Garde::PareFeu
    }
}

/// Ce qui se montre : les programmes qui se lancent, et ceux que Vanguard a retirés (pour pouvoir les remettre). Un
/// programme retiré ailleurs (Gestionnaire des tâches, Réglages) reste comme il est, sans être montré.
fn lignes(programmes: Vec<Programme>, h: &Historique) -> Vec<Ligne> {
    let mut l: Vec<Ligne> = Vec::new();
    for p in programmes {
        let garde = if p.actif { classer(&p) } else { Garde::Ordinaire };
        let Some(r) = reglage(&p.nom, p.changement) else {
            continue;
        };
        let par_vanguard = h.reglages.contains_key(r.id.as_ref());
        if p.actif || par_vanguard {
            l.push(Ligne {
                garde,
                nom: affichable(&p.nom),
                commande: affichable(&p.commande),
                actif: p.actif,
                machine: p.machine,
                par_vanguard,
                reglage: r,
            });
        }
    }
    // Retirés par Vanguard mais introuvables ici (un service désactivé ne se liste plus) : rebâtis d'après la note.
    for r in notes(h) {
        if !l.iter().any(|x| x.reglage.id == r.id) {
            let identite = r.id.strip_prefix(PREFIXE).unwrap_or_default();
            l.push(Ligne {
                nom: affichable(&systeme::Changement::nom_demarrage(identite)),
                commande: affichable(identite),
                actif: false,
                machine: false,
                garde: Garde::Ordinaire,
                par_vanguard: true,
                reglage: r,
            });
        }
    }
    l.sort_by_key(|x| x.nom.to_lowercase());
    l
}

/// Pour le blocage : un programme qui se lance à l'ouverture de session et que Vanguard saurait retirer.
pub struct AuDemarrage {
    /// Prêt à montrer.
    pub nom: String,
    /// Ce qui est lancé, tel quel : le blocage y cherche le fichier du programme.
    pub commande: String,
    /// Le réglage (« demarrage:… ») qui le retire, puis le remet exactement.
    pub id: String,
    /// De toute la machine : il faut les droits d'administrateur.
    pub machine: bool,
}

/// Les programmes qui se lancent à l'ouverture de session, sauf ceux à garder (sécurité, Vanguard, pilotes,
/// accessibilité, bureau) et les pare-feu : ceux-là ne sont jamais proposés au blocage.
pub fn retirables() -> Vec<AuDemarrage> {
    systeme::au_demarrage()
        .into_iter()
        .filter(|p| p.actif && classer(p) == Garde::Ordinaire)
        .filter_map(|p| {
            let (nom, commande, machine) = (affichable(&p.nom), p.commande.clone(), p.machine);
            let r = reglage(&p.nom, p.changement)?;
            Some(AuDemarrage {
                nom,
                commande,
                id: r.id.into_owned(),
                machine,
            })
        })
        .collect()
}

/// Retire du démarrage le programme de ce réglage, l'accord ayant été donné avant (blocage) : la valeur d'avant est
/// notée comme pour la liste à cocher. `None` : il ne se lance plus, ou n'est plus là.
pub fn retirer(id: &str) -> Option<bool> {
    let r = systeme::au_demarrage()
        .into_iter()
        .filter(|p| p.actif && classer(p) == Garde::Ordinaire)
        .filter_map(|p| reglage(&p.nom, p.changement))
        .find(|r| r.id == id)?;
    let mut h = charger();
    let (faits, _) = executer(&[&r], &[], &mut h);
    Some(faits == [true] && etat(&r) == Etat::Fait)
}

/// Remet au démarrage ce que Vanguard en a retiré, d'après sa note (l'annulation d'un blocage). `None` : aucune note
/// pour ce réglage.
pub fn remettre(id: &str) -> Option<bool> {
    let mut h = charger();
    let r = notes(&h).into_iter().find(|r| r.id == id)?;
    let (_, remis) = executer(&[], &[&r], &mut h);
    Some(remis == [true])
}

/// La liste à cocher : coché = se lance à l'ouverture de session. Décocher retire, recocher remet exactement comme
/// avant ce que Vanguard avait retiré.
pub fn menu() {
    let h = charger();
    let l = lignes(systeme::au_demarrage(), &h);
    if l.is_empty() {
        titre(tr!("Programmes au démarrage", "Startup programs"));
        trp!(
            "  {VERT}✔{RESET} Aucun programme du compte ne se lance à l'ouverture de session.",
            "  {VERT}✔{RESET} No program of this account starts at login."
        );
        afficher_aligne("  ", ailleurs(), 2, "");
        return;
    }
    let cases: Vec<Case> = l
        .iter()
        .map(|x| {
            let precision = match (x.garder(), x.actif) {
                (Some(raison), _) => raison,
                (None, true) if x.pare_feu() => tr!("pare-feu : retrait = baisse", "firewall: removing = lowering"),
                (None, true) => tr!("se lance", "starts"),
                (None, false) => tr!("retiré par Vanguard", "removed by Vanguard"),
            };
            let mut detail = x.commande.chars().take(200).collect::<String>();
            if x.machine {
                detail.push_str(tr!(
                    " · tout l'ordinateur : la fenêtre administrateur s'ouvrira",
                    " · whole machine: the administrator window will open"
                ));
            }
            Case {
                texte: x.nom.clone(),
                precision: precision.to_string(),
                detail,
                cochee: x.actif,
                recommandee: false,
                // À garder : montré, jamais proposé.
                fixe: x.garder().is_some() && x.actif,
            }
        })
        .collect();
    let entete = vec![
        String::new(),
        ligne_titre(tr!("Programmes au démarrage", "Startup programs")),
        trf!(
            "  {GRIS}Coché = se lance à l'ouverture de session. Décochez pour le retirer :{RESET}",
            "  {GRIS}Checked = starts at login. Uncheck to remove it: it stays{RESET}"
        ),
        trf!(
            "  {GRIS}il reste installé. Recocher le remet exactement comme avant.{RESET}",
            "  {GRIS}installed. Checking it again puts it back exactly as before.{RESET}"
        ),
        String::new(),
    ];
    let Some(voulu) = cocher(&entete, &cases) else {
        return;
    };
    let choisis = |garde: fn(&Ligne, bool) -> bool| -> Vec<&Reglage> {
        l.iter()
            .zip(&voulu)
            .filter(|(x, v)| garde(x, **v))
            .map(|(x, _)| &x.reglage)
            .collect()
    };
    let a_retirer = choisis(|x, v| x.actif && !v && x.garder().is_none());
    let a_remettre = choisis(|x, v| !x.actif && v && x.par_vanguard);
    let baisses: Vec<&str> = l
        .iter()
        .zip(&voulu)
        .filter(|(x, v)| x.actif && !**v && x.garder().is_none() && x.pare_feu())
        .map(|(x, _)| x.nom.as_str())
        .collect();
    if a_retirer.is_empty() && a_remettre.is_empty() {
        trp!("  {GRIS}Rien à changer.{RESET}", "  {GRIS}Nothing to change.{RESET}");
    } else if !liste_admise(baisses.len(), a_retirer.len() + a_remettre.len()) {
        afficher_aligne(
            "  ✖ ",
            tr!(
                "Liste refusée : elle mêle le retrait d'un pare-feu, qui baisse votre protection, à d'autres changements. Retirez-le seul.",
                "List refused: it mixes removing a firewall, which lowers your protection, with other changes. Remove it alone."
            ),
            4,
            "",
        );
    } else if baisses.is_empty() || baisse_ok(&baisses) {
        confirmer_et_executer(&a_retirer, &a_remettre);
    } else {
        trp!("  Annulé : rien n'a changé.", "  Cancelled: nothing changed.");
    }
    println!();
    afficher_aligne("  ", ailleurs(), 2, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmes_a_garder() {
        assert!(
            a_garder(
                "SecurityHealth",
                r"C:\Windows\system32\SecurityHealthSystray.exe",
                false
            )
            .is_some()
        );
        assert!(a_garder("AVG UI", "avgui.exe", false).is_some());
        // « avg » est un mot entier : un jeu qui le contient au milieu d'un mot n'est pas un antivirus.
        assert_eq!(a_garder("Savgame Sync", "savgame.exe", false), None);
        assert!(a_garder("RtkAudUService", r"C:\Windows\System32\RtkAudUService64.exe", false).is_some());
        assert!(a_garder("Clavier visuel", "osk.exe", false).is_some());
        assert!(a_garder("vanguard-surveillance", "vanguard surveiller", false).is_some());
        assert!(a_garder("PipeWire", "/usr/bin/pipewire", false).is_some());
        assert!(a_garder("Panneau", "panneau", true).is_some());
        assert_eq!(
            a_garder("Discord", r"C:\Users\alice\AppData\Local\Discord\Update.exe", false),
            None
        );
        assert_eq!(a_garder("Steam", "/usr/bin/steam -silent", false), None);
        // Outils de sécurité ajoutés : notifications d'AppArmor, protections d'entreprise, VPN, outils du Mac.
        assert!(a_garder("AppArmor Notify", "aa-notify -p -s 1 -w 60 -f /var/log/kern.log", false).is_some());
        assert!(
            a_garder("SentinelOne", r"C:\Program Files\SentinelOne\SentinelUI.exe", false)
                .is_some_and(|r| r.contains("sécurité") || r.contains("security"))
        );
        assert!(
            a_garder(
                "blockblock",
                "/Applications/BlockBlock Helper.app/Contents/MacOS/BlockBlock",
                false
            )
            .is_some()
        );
        assert!(a_garder("NordVPN", r"C:\Program Files\NordVPN\NordVPN.exe", false).is_some());
        assert!(a_garder("mullvad-vpn", "/opt/Mullvad VPN/mullvad-gui", false).is_some());
        assert!(
            a_garder(
                "AVKTray",
                r"C:\Program Files (x86)\G DATA\AntiVirus\AVK\AVKTray.exe",
                false
            )
            .is_some()
        );
        // Et pas les programmes ordinaires.
        for (nom, commande) in [
            ("Spotify", "spotify --minimized"),
            ("Slack", "slack -u"),
            ("Pandoc", "pandoc"),
            ("Telegram", "telegram-desktop"),
            ("Big Data Studio", "bigdata --tray"),
        ] {
            assert_eq!(a_garder(nom, commande, false), None, "{nom}");
        }
    }

    #[test]
    fn valeurs_de_startup_approved() {
        assert_eq!(octets(&hex(&[3, 0, 0x10, 0xff])), Some(vec![3, 0, 0x10, 0xff]));
        assert_eq!(octets("0"), None);
        assert_eq!(octets("zz"), None);
        assert!(desactive_windows("030000000011223344556677"));
        assert!(desactive_windows("07000000"));
        assert!(!desactive_windows("020000000000000000000000"));
        assert!(!desactive_windows(""));
        // 1970 : la première date des FILETIME de 1601 décalée, en petit-boutiste après 03 00 00 00.
        let v = valeur_desactivee(std::time::UNIX_EPOCH);
        assert_eq!(v, format!("03000000{}", hex(&116_444_736_000_000_000u64.to_le_bytes())));
        assert_eq!(v.len(), 24);
        assert!(desactive_windows(&valeur_desactivee(std::time::SystemTime::now())));
        assert_eq!(liste_approuvee("Run32"), Some("Run32"));
        assert_eq!(liste_approuvee(r"Run\..\Autre"), None);
    }

    /// Sous Linux, un pare-feu n'est reconnu que par le paquet qui fournit son programme, jamais par son nom ; un
    /// paquet illisible (ou un programme qu'on ne peut pas suivre) avec un nom de pare-feu le fait garder ; ClamAV et
    /// AppArmor restent gardés quoi qu'il arrive.
    #[cfg(target_os = "linux")]
    #[test]
    fn pare_feu_reconnu_par_son_paquet() {
        use crate::machine::linux::EtatPaquet;
        use std::path::{Path, PathBuf};
        let classe = |nom: &str, commande: &str, paquet: EtatPaquet| {
            classer_linux(
                nom,
                commande,
                false,
                |p: &str| Some(PathBuf::from(p)),
                |_: &Path| paquet.clone(),
            )
        };
        let intact = |n: &str| EtatPaquet::Intact(n.to_string());
        assert_eq!(
            classe("OpenSnitch", "/usr/bin/opensnitch-ui", intact("opensnitch-ui")),
            Garde::PareFeu
        );
        // Un nom quelconque, mais le paquet d'un pare-feu : reconnu.
        assert_eq!(
            classe("Applet réseau", "/usr/bin/applet", intact("firewall-applet")),
            Garde::PareFeu
        );
        // Un nom de pare-feu sur un faux programme : un programme comme un autre.
        assert_eq!(
            classe("ufw", "/home/alice/.local/bin/ufw", EtatPaquet::Aucun),
            Garde::Ordinaire
        );
        assert_eq!(classe("Firewall", "/usr/bin/steam", intact("steam")), Garde::Ordinaire);
        // Paquet illisible : traité comme le vrai pare-feu (gardé), et dit ; sans nom de pare-feu, rien à protéger.
        assert!(matches!(
            classe("gufw", "/usr/bin/gufw", EtatPaquet::Illisible),
            Garde::Garder(r) if r.contains("illisible") || r.contains("unreadable")
        ));
        assert_eq!(
            classe("Syncthing", "/usr/bin/syncthing", EtatPaquet::Illisible),
            Garde::Ordinaire
        );
        // Le fichier du pare-feu modifié depuis son installation : gardé.
        assert!(matches!(
            classe(
                "firewall-applet",
                "/usr/bin/firewall-applet",
                EtatPaquet::Modifie("firewall-applet".into())
            ),
            Garde::Garder(_)
        ));
        // Une enveloppe ou un programme introuvable cache le vrai : gardé s'il porte un nom de pare-feu.
        for c in ["env QT_SCALE=2 opensnitch-ui", "sh -c 'gufw'", "QT_X=1 gufw"] {
            assert!(
                matches!(classe("opensnitch-ui", c, intact("opensnitch-ui")), Garde::Garder(_)),
                "{c}"
            );
        }
        assert!(matches!(
            classer_linux("ufw-tray", "ufw-tray", false, |_: &str| None, |_: &Path| intact("ufw")),
            Garde::Garder(_)
        ));
        // ClamAV et AppArmor : toujours gardés, quel que soit le paquet.
        for (nom, commande) in [
            ("ClamTk", "/usr/bin/clamtk"),
            ("AppArmor Notify", "/usr/bin/aa-notify -p -s 1"),
        ] {
            assert!(
                matches!(classe(nom, commande, EtatPaquet::Aucun), Garde::Garder(_)),
                "{nom}"
            );
            assert!(
                matches!(classe(nom, commande, intact("ufw")), Garde::Garder(_)),
                "{nom}"
            );
        }
        // Le premier mot, préfixes de systemd et guillemets ôtés.
        assert_eq!(executable("-/usr/bin/gufw --tray"), Some("/usr/bin/gufw"));
        assert_eq!(executable("\"/usr/bin/gufw\" %u"), Some("/usr/bin/gufw"));
        assert_eq!(executable("/usr/bin/env gufw"), None);
        assert_eq!(executable(""), None);
    }

    /// Le retrait d'un pare-feu part seul (liste pure) ; sinon la liste entière est refusée.
    #[test]
    fn retrait_du_pare_feu_seul() {
        assert!(liste_admise(0, 3));
        assert!(liste_admise(1, 1));
        assert!(!liste_admise(1, 2));
        assert!(!liste_admise(2, 2));
        #[cfg(not(target_os = "linux"))]
        assert!(!baisse_ok(&["gufw"]));
    }

    /// Hors de Linux, les noms de pare-feu gardent l'élément, comme avant ; sous Linux, le nom seul ne garde rien.
    #[test]
    fn nom_de_pare_feu_selon_le_systeme() {
        for (nom, commande) in [
            ("GUFW", "gufw"),
            ("Firewall", "fw.exe"),
            ("LuLu", "/Applications/LuLu.app"),
        ] {
            assert_eq!(
                a_garder(nom, commande, false).is_some(),
                !cfg!(target_os = "linux"),
                "{nom}"
            );
        }
        assert!(a_garder("ClamTk", "clamtk", false).is_some());
    }

    /// Montrés : ceux qui se lancent, et ceux que Vanguard a retirés, même introuvables (un service désactivé ne se
    /// liste plus) ; pas ceux retirés ailleurs.
    #[cfg(target_os = "linux")]
    #[test]
    fn programmes_montres() {
        use super::super::Avant;
        use super::systeme::{Changement, Entree};
        let service = |nom: &str, actif: bool| Programme {
            nom: nom.to_string(),
            commande: format!("/usr/bin/{nom}"),
            actif,
            machine: false,
            bureau: false,
            changement: Changement::Demarrage {
                entree: Entree::Service(format!("{nom}.service")),
                cible: Some("disabled".to_string()),
            },
        };
        let mut h = Historique::default();
        h.reglages.insert(
            format!("{PREFIXE}systemd|retire.service"),
            Avant {
                date: String::new(),
                valeurs: vec![Some("enabled".to_string())],
                ..Avant::default()
            },
        );
        let l = lignes(
            vec![
                service("syncthing", true),
                service("ailleurs", false),
                service("vanguard-essai", true),
            ],
            &h,
        );
        let vus: Vec<(&str, bool, bool, bool)> = l
            .iter()
            .map(|x| (x.nom.as_str(), x.actif, x.par_vanguard, x.garder().is_some()))
            .collect();
        assert_eq!(
            vus,
            [
                ("retire", false, true, false),
                ("syncthing", true, false, false),
                ("vanguard-essai", true, false, true)
            ]
        );
        // « Tout remettre comme avant » le retrouve aussi.
        let n = notes(&h);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].id, "demarrage:systemd|retire.service");
    }

    /// Le nom d'un programme au démarrage, et ce qu'il lance, sont écrits par qui a posé l'entrée : piégés, ils
    /// arrivent inoffensifs dans la liste à cocher et dans la confirmation.
    #[cfg(target_os = "linux")]
    #[test]
    fn noms_pieges_au_demarrage() {
        use super::systeme::{Changement, Entree};
        let piege = Programme {
            nom: "x\x1b]52;c;eA==\x07\x1b[2K\rfaux\u{202e}".into(),
            commande: "/tmp/x\x1b[8m --cache".into(),
            actif: true,
            machine: false,
            bureau: false,
            changement: Changement::Demarrage {
                entree: Entree::Service("x.service".into()),
                cible: Some("disabled".into()),
            },
        };
        let l = lignes(vec![piege], &Historique::default());
        assert_eq!(l[0].nom, "x�]52;c;eA==��[2K�faux�");
        assert_eq!(l[0].commande, "/tmp/x�[8m --cache");
        assert!(
            !crate::ui::contient_un_piege(&l[0].reglage.titre),
            "{}",
            l[0].reglage.titre
        );
    }

    #[test]
    fn agents_desactives_de_launchd() {
        let texte = "disabled services = {\n\t\"com.exemple.agent\" => disabled\n\t\"com.exemple.autre\" => enabled\n\t\"org.ancien.mac\" => true\n\t\"org.ancien.actif\" => false\n}\n";
        let e = etats_launchd(texte);
        assert_eq!(e.get("com.exemple.agent"), Some(&true));
        assert_eq!(e.get("org.ancien.mac"), Some(&true));
        assert_eq!(e.get("com.exemple.autre"), Some(&false));
        assert_eq!(e.get("org.ancien.actif"), Some(&false));
        assert_eq!(e.get("com.absent"), None);
        // Valeurs extraites par plutil en XML.
        let xml = |v: &str| {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n{v}\n</plist>\n"
            )
        };
        let (vrai, faux) = (xml("<true/>"), xml("<false/>"));
        let conditions = xml("<dict>\n\t<key>SuccessfulExit</key>\n\t<false/>\n</dict>");
        assert_eq!(valeur_plist(&vrai), Some("<true/>"));
        assert_eq!(valeur_plist(&conditions), Some("<dict>"));
        // Au démarrage : RunAtLoad vrai, ou KeepAlive vrai ou à conditions ; pas un agent à la demande.
        assert!(agent_au_demarrage(Some(&vrai), None));
        assert!(agent_au_demarrage(None, Some(&vrai)));
        assert!(agent_au_demarrage(Some(&faux), Some(&conditions)));
        assert!(!agent_au_demarrage(Some(&faux), Some(&faux)));
        assert!(!agent_au_demarrage(None, None));
        // Actif : le réglage de launchd d'abord, sinon la clé Disabled du plist.
        assert!(agent_actif(None, None));
        assert!(!agent_actif(None, Some(&vrai)));
        assert!(agent_actif(None, Some(&faux)));
        assert!(agent_actif(Some(false), Some(&vrai)));
        assert!(!agent_actif(Some(true), None));
        assert!(label_valide("com.exemple.agent-2_b"));
        assert!(!label_valide("com.exemple;rm"));
        assert!(!label_valide(""));
    }
}
