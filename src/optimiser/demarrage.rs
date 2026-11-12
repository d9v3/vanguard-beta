//! Programmes au démarrage : ceux qui se lancent à l'ouverture de session, retirés ou remis après accord. Chacun est
//! un réglage hors catalogue (« demarrage:<identité> ») : la valeur d'avant est notée, il s'annule exactement, un par
//! un dans cette liste ou tous par « Tout remettre comme avant ». Le programme reste installé et se lance à la main.
//! Ce qui protège ou fait marcher l'ordinateur (Vanguard, antivirus, pare-feu, pilotes, accessibilité, composants du
//! bureau) est montré sans être proposé.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

mod resultat;

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

/// Des motifs de pare-feu (ou d'interfaces de pare-feu) dans le nom ou la commande. Sous Windows, ils gardent
/// l'élément (« sécurité ») ; sous Linux, le nom seul ne prouve rien : seul le paquet qui fournit le programme le
/// reconnaît (`classer`), et ces motifs ne servent qu'à refuser quand ce paquet ne se lit pas.
#[rustfmt::skip]
const PARE_FEU: &[&str] = &[
    "firewall", "firewalld", "gufw", "ufw", "opensnitch", "little snitch", "lulu", "nftables", "tinywall", "glasswire",
    "simplewall", "portmaster",
];

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
        // Un VPN qui démarre avec la session protège la connexion (souvent avec un coupe-circuit).
        "wireguard", "openvpn", "protonvpn", "mullvad", "nordvpn", "expressvpn", "surfshark", "tailscale",
        "cloudflare warp", "warp-svc", "warp-taskbar", "zerotier",
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

/// Sous Linux : le programme lancé (premier mot de la commande) et le paquet qui le fournit. Sous Windows :
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

/// Pure : `chemin` trouve le programme, `paquet` dit qui le fournit. Le nom seul ne fait jamais un pare-feu qu'on
/// retire avec la question de baisse : seul son paquet le prouve. Mais un nom de pare-feu sans paquet qui le prouve
/// (paquet illisible, fichier du paquet modifié, hors de tout paquet, ou programme qu'on ne peut pas suivre :
/// enveloppe, introuvable) est gardé par prudence (R15), et c'est dit : un pare-feu installé à la main (dans
/// /opt, ou le dossier du compte) se retirait sinon d'un clic, comme un programme ordinaire.
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
        EtatPaquet::Aucun if nom_de_pare_feu(nom, commande) => {
            Garde::Garder(tr!("pare-feu ? hors paquet", "firewall? not from a package"))
        }
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

/// Ce qui n'a pas pu être lu (`releve_demarrage`), tel que la liste du terminal le dit : chaque manque nettoyé pour
/// l'écran, coupé à la largeur, « ! » devant (un signe que toute console dessine).
fn lignes_des_manques(manques: &[String]) -> Vec<String> {
    let largeur = LARGEUR.saturating_sub(4);
    let mut v = Vec::new();
    for m in manques {
        for (i, l) in envelopper(&affichable(m), largeur).iter().enumerate() {
            v.push(if i == 0 {
                format!("  {GRAS}!{RESET} {GRIS}{l}{RESET}")
            } else {
                format!("    {GRIS}{l}{RESET}")
            });
        }
    }
    v
}

/// Ce que Vanguard ne retire pas d'ici, et où le faire.
fn ailleurs() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Les tâches planifiées et les services ne sont pas dans cette liste : Gestionnaire des tâches, ou Virus et logiciels espions › Analyse antivirus › Analyse rapide (revue du démarrage).",
            "Scheduled tasks and services are not in this list: Task Manager, or Viruses and spyware › Antivirus scan › Quick scan (startup review)."
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
    octets
        .iter()
        .fold(String::with_capacity(octets.len().saturating_mul(2)), |mut s, o| {
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
        .map(|i| {
            i.checked_add(2)
                .and_then(|f| hex.get(i..f))
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        })
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
    let temps = u64::try_from(depuis_1970.as_nanos() / 100)
        .unwrap_or(0)
        .saturating_add(DE_1601_A_1970);
    let mut o = vec![3, 0, 0, 0];
    o.extend_from_slice(&temps.to_le_bytes());
    hex(&o)
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
        let garde = match p.actif {
            false => Garde::Ordinaire,
            // Masquée, elle ne se relirait plus (D-2) : montrée, jamais proposée.
            true if !p.changement.cible_relisible() => Garde::Garder(tr!(
                "à garder : trop grosse pour être masquée sans perte",
                "keep: too large to be hidden safely"
            )),
            true => classer(&p),
        };
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
    // Pas celui dont l'entrée ne se lit pas (la liste la dit pas lue) : recocher l'écraserait (D-1).
    for r in notes(h) {
        if !l.iter().any(|x| x.reglage.id == r.id) && r.changements.iter().all(systeme::Changement::entree_lisible) {
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
    let Some(_notes) = super::tenir_les_notes(&crate::reseau::dossier_local()) else {
        return Some(false);
    };
    let r = systeme::au_demarrage()
        .into_iter()
        .filter(|p| p.actif && classer(p) == Garde::Ordinaire)
        .filter_map(|p| reglage(&p.nom, p.changement))
        .find(|r| r.id == id)?;
    Some(retirer_le(&r))
}

/// Retire ce programme, qui se lance, valeur d'avant notée d'abord (`executer`) ; vrai s'il ne se lance plus. Une
/// vieille note du même programme (retiré par Vanguard, puis remis ailleurs, ou réécrit par une mise à jour) ne vaut
/// plus : elle ferait remettre un fichier d'avant ; c'est la valeur de maintenant qui est notée. Seulement ici :
/// ailleurs, la plus ancienne note reste (`executer`). Le verrou des notes est tenu (déjà tenu : rien de plus).
fn retirer_le(r: &Reglage) -> bool {
    let Some(_notes) = super::tenir_les_notes(&crate::reseau::dossier_local()) else {
        return false;
    };
    let mut h = charger();
    h.reglages.remove(r.id.as_ref());
    let (faits, _) = executer(&[r], &[], &mut h);
    faits == [true] && etat(r) == Etat::Fait
}

/// Ce que la fenêtre demande pour un seul programme, désigné par son empreinte (`vanguard demarrage --retirer` ou
/// `--remettre`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SorteDeChangement {
    /// Le retirer du démarrage : seulement un programme ordinaire qui se lance.
    Retirer,
    /// Remettre exactement comme avant ce que Vanguard en a retiré, d'après sa note.
    Remettre,
}

impl SorteDeChangement {
    fn code(self) -> &'static str {
        match self {
            SorteDeChangement::Retirer => "retirer",
            SorteDeChangement::Remettre => "remettre",
        }
    }
}

/// Pourquoi rien n'est changé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refus {
    /// Pas 32 chiffres hexadécimaux minuscules.
    MalFormee,
    /// Aucun programme (ou aucune note de Vanguard) n'a cette empreinte.
    Inconnue,
    /// Plusieurs y répondent : aucun n'est choisi au hasard.
    Ambigue,
    /// Il ne se lance plus : rien à retirer.
    NeSeLancePas,
    /// Il se lance déjà (remis ou réécrit hors de Vanguard) : la vieille note n'écrase pas l'entrée d'aujourd'hui.
    SeLanceDeja,
    /// Masquée, son entrée dépasserait la borne de lecture : ni le retrait ne se constaterait, ni elle ne se remettrait.
    TropGrosse,
    /// Son entrée d'aujourd'hui ne se lit pas (trop grosse, pas en UTF-8, un lien) : elle se lance peut-être, la note
    /// ne passe pas par-dessus.
    PasLue,
    /// Il protège ou fait marcher l'ordinateur.
    AGarder(&'static str),
    /// Un pare-feu : le retirer serait une baisse, qui ne se choisit que dans la liste à cocher, avec sa question.
    PareFeu,
    /// Les notes de Vanguard sont illisibles ou changées hors de lui : rien ne s'en remet, et rien n'est retiré (la
    /// première écriture les remplacerait par des neuves, et ce qu'elles gardaient ne se remettrait plus).
    NotesDouteuses,
    /// Un autre Vanguard tient les notes (il change des réglages) : rien n'est changé, à refaire à sa fin.
    NotesOccupees,
}

impl Refus {
    fn raison(self) -> String {
        match self {
            Refus::MalFormee => tr!(
                "empreinte mal formée (32 chiffres hexadécimaux minuscules attendus)",
                "malformed fingerprint (32 lowercase hexadecimal digits expected)"
            )
            .to_string(),
            Refus::Inconnue => tr!(
                "aucun programme au démarrage n'a cette empreinte (la liste a peut-être changé)",
                "no startup program has this fingerprint (the list may have changed)"
            )
            .to_string(),
            Refus::Ambigue => tr!(
                "plusieurs programmes répondent à cette empreinte : aucun n'est choisi",
                "several programs match this fingerprint: none is chosen"
            )
            .to_string(),
            Refus::NeSeLancePas => tr!(
                "ce programme ne se lance plus à l'ouverture de session",
                "this program no longer starts at login"
            )
            .to_string(),
            Refus::SeLanceDeja => tr!(
                "ce programme se lance déjà à l'ouverture de session : rien n'est remis par-dessus",
                "this program already starts at login: nothing is put back over it"
            )
            .to_string(),
            Refus::TropGrosse => tr!(
                "l'entrée masquée dépasserait 64 Kio et ne se relirait plus : rien n'est retiré",
                "the hidden entry would exceed 64 KiB and could no longer be read back: nothing is removed"
            )
            .to_string(),
            Refus::PasLue => tr!(
                "entrée pas lue (trop grosse, pas en UTF-8 ou un lien) : rien n'est remis par-dessus",
                "entry not read (too large, not UTF-8 or a link): nothing is put back over it"
            )
            .to_string(),
            Refus::AGarder(raison) => trf!("à garder ({})", "to keep ({})", raison),
            Refus::PareFeu => tr!(
                "pare-feu : le retirer baisserait la protection (seulement par la liste « vanguard demarrage », avec sa question)",
                "firewall: removing it would lower protection (only through the “vanguard startup” list, with its question)"
            )
            .to_string(),
            Refus::NotesDouteuses => tr!(
                "notes de Vanguard illisibles ou changées hors de Vanguard : rien n'est retiré ni remis tant qu'elles le sont",
                "Vanguard's notes unreadable or changed outside Vanguard: nothing is removed or put back while they are"
            )
            .to_string(),
            Refus::NotesOccupees => tr!(
                "un autre Vanguard change des réglages en ce moment : réessayez à sa fin",
                "another Vanguard is changing settings right now: try again when it ends"
            )
            .to_string(),
        }
    }
}

/// 32 chiffres hexadécimaux minuscules, rien d'autre (ni espace, ni majuscule, ni préfixe).
fn empreinte_bien_formee(e: &str) -> bool {
    e.len() == 32 && e.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Le seul réglage dont l'identité a cette empreinte, parmi `reglages` ; refusé s'il n'y en a aucun ou plusieurs.
fn le_seul<T>(trouves: Vec<T>) -> Result<T, Refus> {
    let mut i = trouves.into_iter();
    match (i.next(), i.next()) {
        (Some(t), None) => Ok(t),
        (None, _) => Err(Refus::Inconnue),
        (Some(_), Some(_)) => Err(Refus::Ambigue),
    }
}

/// L'empreinte de l'identité de ce réglage (« demarrage:… » sans le préfixe), comme la liste l'écrit.
fn empreinte_du(r: &Reglage) -> Option<String> {
    resultat::empreinte(r.id.strip_prefix(PREFIXE)?)
}

/// Le programme à retirer qui a cette empreinte, parmi ceux du système : il doit se lancer et être ordinaire. Tous
/// les programmes comptent pour reconnaître une empreinte en double ; seul le programme trouvé est classé (son
/// paquet lu), `classer` passé pour les essais. Rend aussi son nom, rendu inoffensif, s'il est seul à l'avoir.
fn a_retirer_nomme(
    programmes: Vec<Programme>,
    empreinte: &str,
    classer: impl Fn(&Programme) -> Garde,
) -> (Option<String>, Result<Reglage, Refus>) {
    if !empreinte_bien_formee(empreinte) {
        return (None, Err(Refus::MalFormee));
    }
    // Comme `empreinte_du` sur son réglage, sans le bâtir.
    let trouves: Vec<Programme> = programmes
        .into_iter()
        .filter(|p| {
            p.changement
                .identite_demarrage()
                .and_then(|i| resultat::empreinte(&i))
                .as_deref()
                == Some(empreinte)
        })
        .collect();
    let p = match le_seul(trouves) {
        Ok(p) => p,
        Err(refus) => return (None, Err(refus)),
    };
    let nom = Some(affichable(&p.nom));
    let garde = if p.actif { classer(&p) } else { Garde::Ordinaire };
    let issue = match (p.actif, garde) {
        (false, _) => Err(Refus::NeSeLancePas),
        (true, Garde::Garder(raison)) => Err(Refus::AGarder(raison)),
        (true, Garde::PareFeu) => Err(Refus::PareFeu),
        (true, Garde::Ordinaire) if !p.changement.cible_relisible() => Err(Refus::TropGrosse),
        (true, Garde::Ordinaire) => reglage(&p.nom, p.changement).ok_or(Refus::Inconnue),
    };
    (nom, issue)
}

#[cfg(test)]
fn a_retirer(
    programmes: Vec<Programme>,
    empreinte: &str,
    classer: impl Fn(&Programme) -> Garde,
) -> Result<Reglage, Refus> {
    a_retirer_nomme(programmes, empreinte, classer).1
}

/// Le programme retiré par Vanguard qui a cette empreinte, d'après ses notes.
fn a_remettre(h: &Historique, empreinte: &str) -> Result<Reglage, Refus> {
    if !empreinte_bien_formee(empreinte) {
        return Err(Refus::MalFormee);
    }
    le_seul(
        notes(h)
            .into_iter()
            .filter(|r| empreinte_du(r).as_deref() == Some(empreinte))
            .collect(),
    )
}

/// Ce qu'est devenue la demande.
enum Issue {
    Fait,
    Refuse(Refus),
    /// Tenté sans succès : fenêtre administrateur refusée, système qui refuse, note impossible à écrire.
    Echec,
}

/// `vanguard demarrage --retirer|--remettre <empreinte>` : un seul programme, sans question (l'accord a été donné
/// dans la fenêtre, après la confirmation qui montre le nom et la commande). L'empreinte est vérifiée avant toute
/// lecture du système ; rien n'est changé pour une empreinte inconnue, en double, d'un programme à garder ou d'un
/// pare-feu. Le verrou des notes est tenu de leur lecture à leur dernière écriture (un autre Vanguard qui le tient :
/// refusé). Chaque demande, faite, refusée ou en échec, va au journal des événements. Avec `json`, l'issue est la
/// dernière ligne. Rend le code de sortie : 0 fait, 1 refusé ou non fait, 2 empreinte mal formée.
pub fn changer(sorte: SorteDeChangement, empreinte: &str, json: bool) -> i32 {
    // Vérifiée avant toute lecture du système.
    let (nom, issue) = if empreinte_bien_formee(empreinte) {
        match super::tenir_les_notes(&crate::reseau::dossier_local()) {
            Some(_notes) => changer_tenu(sorte, empreinte),
            None => (None, Issue::Refuse(Refus::NotesOccupees)),
        }
    } else {
        (None, Issue::Refuse(Refus::MalFormee))
    };
    let (code, mot, raison) = match &issue {
        Issue::Fait => (0, "fait", String::new()),
        Issue::Refuse(Refus::MalFormee) => (2, "refuse", Refus::MalFormee.raison()),
        Issue::Refuse(r) => (1, "refuse", r.raison()),
        Issue::Echec => (
            1,
            "echec",
            tr!(
                "non fait : fenêtre administrateur refusée, ou le système l'a refusé (détail plus haut)",
                "not done: administrator window declined, or the system refused it (details above)"
            )
            .to_string(),
        ),
    };
    noter_au_journal(sorte, empreinte, nom.as_deref(), &issue, &raison);
    if json {
        println!(
            "{}",
            serde_json::json!({ "geste": sorte.code(), "issue": mot, "raison": raison })
        );
    } else {
        match (&issue, sorte) {
            (Issue::Fait, SorteDeChangement::Retirer) => trp!(
                "  {VERT}✔{RESET} Retiré du démarrage ; il reste installé.",
                "  {VERT}✔{RESET} Removed from startup; it stays installed."
            ),
            (Issue::Fait, SorteDeChangement::Remettre) => trp!(
                "  {VERT}✔{RESET} Remis au démarrage, exactement comme avant.",
                "  {VERT}✔{RESET} Put back at startup, exactly as before."
            ),
            (Issue::Refuse(_), _) => trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}"),
            (Issue::Echec, _) => trp!("  ✖ {raison}", "  ✖ {raison}"),
        }
    }
    code
}

/// `changer`, le verrou des notes tenu : le nom du programme visé (s'il est connu) et l'issue.
fn changer_tenu(sorte: SorteDeChangement, empreinte: &str) -> (Option<String>, Issue) {
    match sorte {
        // Des notes douteuses seraient remplacées par des neuves à la première écriture : ce que Vanguard avait
        // retiré ne se remettrait plus, et l'avertissement de la liste disparaîtrait. Rien n'est donc retiré.
        SorteDeChangement::Retirer if super::historique_sans_ecrire(&crate::reseau::dossier_local()).is_none() => {
            (None, Issue::Refuse(Refus::NotesDouteuses))
        }
        SorteDeChangement::Retirer => match a_retirer_nomme(systeme::au_demarrage(), empreinte, classer) {
            (nom, Ok(r)) if retirer_le(&r) => (nom, Issue::Fait),
            (nom, Ok(_)) => (nom, Issue::Echec),
            (nom, Err(refus)) => (nom, Issue::Refuse(refus)),
        },
        SorteDeChangement::Remettre => {
            // Choisi d'après les notes lues sans rien écrire : un refus ne laisse aucune trace.
            let dossier = crate::reseau::dossier_local();
            let choisi = super::historique_sans_ecrire(&dossier)
                .ok_or(Refus::NotesDouteuses)
                .and_then(|h1| a_remettre(&h1, empreinte).map(|r| (h1, r)));
            let (h1, r) = match choisi {
                Ok(t) => t,
                Err(refus) => return (None, Issue::Refuse(refus)),
            };
            let nom =
                r.id.strip_prefix(PREFIXE)
                    .map(|i| affichable(&systeme::Changement::nom_demarrage(i)));
            // La liste n'offre « remettre » que pour un programme qui ne se lance plus : une entrée qui se lance
            // (remise ou réécrite hors de Vanguard, peut-être devenue un programme à garder), ou qui ne se lit pas
            // (D-1), n'est jamais écrasée.
            if let Some(refus) = remise_refusee(&r, &systeme::au_demarrage()) {
                return (nom, Issue::Refuse(refus));
            }
            // Les notes relues pour de bon (`charger`) doivent dire la même chose que celles qui ont choisi : sinon,
            // rien n'est remis (ni écrit) d'après des notes qui ont changé entre les deux lectures.
            let mut h = charger();
            let r2 = match relu_pareil(&h1, &r, &h, empreinte) {
                Ok(r2) => r2,
                Err(refus) => return (nom, Issue::Refuse(refus)),
            };
            let (_, remis) = executer(&[], &[&r2], &mut h);
            (nom, if remis == [true] { Issue::Fait } else { Issue::Echec })
        }
    }
}

/// Pourquoi ce réglage de démarrage, rebâti d'une note, ne se remet pas aujourd'hui (lu sur le système), s'il ne le
/// doit pas : `remise_refusee`, dite.
pub(super) fn raison_de_ne_pas_remettre(r: &Reglage) -> Option<String> {
    remise_refusee(r, &systeme::au_demarrage()).map(Refus::raison)
}

/// Pourquoi ce réglage, rebâti d'une note, ne se remet pas par-dessus l'entrée d'aujourd'hui, s'il ne le doit pas :
/// un programme de `programmes` (ceux qui se lisent) se lance avec son identité, ou son entrée ne se lit pas. Une
/// entrée pas lue n'est pas dans `programmes` (`au_demarrage` ne la propose pas) : sans ce second regard, elle
/// passerait pour absente et serait écrasée (correction n° 2 de la 0.94, D-1).
fn remise_refusee(r: &Reglage, programmes: &[Programme]) -> Option<Refus> {
    if se_lance(programmes, r) {
        Some(Refus::SeLanceDeja)
    } else if !r.changements.iter().all(systeme::Changement::entree_lisible) {
        Some(Refus::PasLue)
    } else {
        None
    }
}

/// Parmi `programmes`, un qui se lance a l'identité de ce réglage.
fn se_lance(programmes: &[Programme], r: &Reglage) -> bool {
    let Some(identite) = r.id.strip_prefix(PREFIXE) else {
        return false;
    };
    programmes
        .iter()
        .any(|p| p.actif && p.changement.identite_demarrage().as_deref() == Some(identite))
}

/// Le réglage à remettre d'après les notes relues pour de bon (`h`), seulement s'il est celui choisi d'après la
/// première lecture (`h1`, `r`) avec la même note : sinon `NotesDouteuses`, et rien n'est remis.
fn relu_pareil(h1: &Historique, r: &Reglage, h: &Historique, empreinte: &str) -> Result<Reglage, Refus> {
    a_remettre(h, empreinte)
        .ok()
        .filter(|r2| r2.id == r.id && h.reglages.get(r.id.as_ref()) == h1.reglages.get(r.id.as_ref()))
        .ok_or(Refus::NotesDouteuses)
}

/// La demande au journal des événements, faite ou pas : un changement demandé par la fenêtre se voit ensuite à côté
/// des alertes, même si personne ne regardait. Le nom est déjà rendu inoffensif ; l'empreinte seulement bien formée.
fn noter_au_journal(sorte: SorteDeChangement, empreinte: &str, nom: Option<&str>, issue: &Issue, raison: &str) {
    use crate::modele::evenement::{Evenement, Source};
    let bien_formee = empreinte_bien_formee(empreinte);
    let qui = match nom {
        Some(n) => n.to_string(),
        None if bien_formee => trf!("empreinte {}", "fingerprint {}", empreinte),
        None => tr!("empreinte mal formée", "malformed fingerprint").to_string(),
    };
    let geste = match sorte {
        SorteDeChangement::Retirer => tr!("retirer du démarrage", "remove from startup"),
        SorteDeChangement::Remettre => tr!("remettre au démarrage", "put back at startup"),
    };
    let texte = match issue {
        Issue::Fait => trf!("Démarrage : {} « {} » : fait", "Startup: {} “{}”: done", geste, qui),
        Issue::Refuse(_) => trf!(
            "Démarrage : {} « {} » : refusé ({})",
            "Startup: {} “{}”: refused ({})",
            geste,
            qui,
            raison
        ),
        Issue::Echec => trf!("Démarrage : {} « {} » : {}", "Startup: {} “{}”: {}", geste, qui, raison),
    };
    let cle = format!("demarrage|{}", if bien_formee { empreinte } else { "mal-formee" });
    let ev = Evenement::action(Source::Correction, &texte, matches!(issue, Issue::Fait), &[]).cle(Some(&cle));
    // Un refus identique au dernier mot noté pour cette empreinte, il y a moins de 10 minutes, ne se réécrit pas : une
    // fenêtre détournée qui redemande sans fin ne noie pas les alertes sous le même refus. Un changement fait, un
    // échec ou un refus qui dit autre chose s'écrivent toujours.
    if matches!(issue, Issue::Refuse(_))
        && crate::modele::journal::dernier_evenement(
            |e| e.cle.as_deref() == Some(cle.as_str()),
            chrono::Duration::minutes(REFUS_REPETE_MINUTES),
        )
        .is_some_and(|d| d.source == ev.source && d.quoi == ev.quoi)
    {
        return;
    }
    crate::modele::journal::noter(ev);
}

/// Pendant combien de minutes un refus identique pour la même empreinte ne se réécrit pas au journal.
const REFUS_REPETE_MINUTES: i64 = 10;

/// Remet au démarrage ce que Vanguard en a retiré, d'après sa note (l'annulation d'un blocage). `None` : aucune note
/// pour ce réglage.
pub fn remettre(id: &str) -> Option<bool> {
    let Some(_notes) = super::tenir_les_notes(&crate::reseau::dossier_local()) else {
        return Some(false);
    };
    let mut h = charger();
    let r = notes(&h).into_iter().find(|r| r.id == id)?;
    // Comme la fenêtre : une entrée qui se lance déjà, ou qui ne se lit pas, n'est pas réécrite d'après une vieille
    // note (dit ici, puisque l'appelant renvoie au message ci-dessus).
    if let Some(refus) = remise_refusee(&r, &systeme::au_demarrage()) {
        let raison = refus.raison();
        trp!("  ✖ Rien n'a changé : {raison}", "  ✖ Nothing changed: {raison}");
        return Some(false);
    }

    let (_, remis) = executer(&[], &[&r], &mut h);
    Some(remis == [true])
}

/// `vanguard demarrage --json` : la liste de l'écran à cocher, jugée sans rien retirer ni rien écrire (pas même
/// l'historique, lu par `historique_sans_ecrire`), versée au rapport et au journal, puis imprimée.
pub fn json() {
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let (programmes, mut manques) = systeme::releve_demarrage();
    let h = super::historique_sans_ecrire(&crate::reseau::dossier_local()).unwrap_or_else(|| {
        manques.push(
            tr!(
                "notes de Vanguard illisibles ou changées hors de Vanguard : les programmes qu'il a retirés ne sont pas listés",
                "Vanguard's notes unreadable or changed outside Vanguard: the programs it removed are not listed"
            )
            .to_string(),
        );
        Historique::default()
    });
    let l = lignes(programmes, &h);
    let entrees: Vec<resultat::Entree> = l
        .iter()
        .map(|x| resultat::Entree {
            nom: &x.nom,
            commande: &x.commande,
            identite: x.reglage.id.strip_prefix(PREFIXE).unwrap_or(&x.reglage.id),
            machine: x.machine,
            statut: match (x.garder(), x.actif) {
                (Some(raison), true) => resultat::Statut::Garder(raison),
                (None, true) if x.pare_feu() => resultat::Statut::PareFeu,
                (_, true) => resultat::Statut::SeLance,
                (_, false) => resultat::Statut::Retire,
            },
        })
        .collect();
    let r = resultat::resultat(&entrees, manques, debut);
    crate::modele::resultat::verser(&r);
    println!("{}", crate::modele::resultat::json(&r));
}

/// La liste à cocher : coché = se lance à l'ouverture de session. Décocher retire, recocher remet exactement comme
/// avant ce que Vanguard avait retiré.
pub fn menu() {
    let h = charger();
    let (programmes, manques) = systeme::releve_demarrage();
    let l = lignes(programmes, &h);
    let pas_lus = lignes_des_manques(&manques);
    if l.is_empty() {
        titre(tr!("Programmes au démarrage", "Startup programs"));
        // Quelque chose n'a pas pu être lu : jamais « aucun programme » (T-1).
        if pas_lus.is_empty() {
            trp!(
                "  {VERT}✔{RESET} Aucun programme du compte ne se lance à l'ouverture de session.",
                "  {VERT}✔{RESET} No program of this account starts at login."
            );
        }
        for ligne in &pas_lus {
            println!("{ligne}");
        }
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
    let entete = if pas_lus.is_empty() {
        entete
    } else {
        entete.into_iter().chain(pas_lus).chain([String::new()]).collect()
    };
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
    } else if !liste_admise(baisses.len(), a_retirer.len().saturating_add(a_remettre.len())) {
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// T-1, de bout en bout : un dossier d'autostart du compte qui est un lien (dotfiles) ne fait jamais dire
    /// « aucun programme » ; le résultat de `demarrage --json` est « non vérifié », une vérification faite et le
    /// manque dit. Le même dossier, vrai et vide : sain, « aucun programme ».
    #[cfg(target_os = "linux")]
    #[test]
    fn dossier_autostart_lien_dit_non_verifie_de_bout_en_bout() {
        let base = crate::essais::temporaire().join(format!("vanguard-demarrage-t1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (config, ailleurs) = (base.join("config"), base.join("dotfiles"));
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&ailleurs).unwrap();
        std::fs::write(
            ailleurs.join("synchro.desktop"),
            "[Desktop Entry]\nType=Application\nName=Synchro\nExec=synchro\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&ailleurs, config.join("autostart")).unwrap();
        let debut = (chrono::Utc::now(), std::time::Instant::now());
        let (programmes, manques) = systeme::releve_dans(&config, &[], "Hyprland", Some(String::new()));
        assert!(lignes(programmes, &Historique::default()).is_empty());
        let r = resultat::resultat(&[], manques, debut);
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 1);
        assert_eq!(r.couverture.non_verifies.len(), 1, "{:?}", r.couverture.non_verifies);
        assert!(r.couverture.non_verifies[0].contains("autostart"));
        assert!(
            !r.constats.iter().any(|c| c.message.contains("Aucun programme")),
            "{:?}",
            r.constats.iter().map(|c| &c.message).collect::<Vec<_>>()
        );
        assert!(lignes_des_manques(&r.couverture.non_verifies)[0].contains("non vérifié"));
        // Le même dossier, vrai et vide.
        std::fs::remove_file(config.join("autostart")).unwrap();
        std::fs::create_dir_all(config.join("autostart")).unwrap();
        let (programmes, manques) = systeme::releve_dans(&config, &[], "Hyprland", Some(String::new()));
        assert!(programmes.is_empty() && manques.is_empty(), "{manques:?}");
        let r = resultat::resultat(&[], manques, debut);
        assert_eq!(r.verdict(), "sain");
        assert!(r.constats.iter().any(|c| c.message.contains("Aucun programme")));
        std::fs::remove_dir_all(&base).unwrap();
    }

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
        // Outils de sécurité ajoutés : notifications d'AppArmor, protections d'entreprise, VPN.
        assert!(a_garder("AppArmor Notify", "aa-notify -p -s 1 -w 60 -f /var/log/kern.log", false).is_some());
        assert!(
            a_garder("SentinelOne", r"C:\Program Files\SentinelOne\SentinelUI.exe", false)
                .is_some_and(|r| r.contains("sécurité") || r.contains("security"))
        );
        assert!(a_garder("NordVPN", r"C:\Program Files\NordVPN\NordVPN.exe", false).is_some());
        assert!(a_garder("mullvad-vpn", "/opt/Mullvad VPN/mullvad-gui", false).is_some());
        for (nom, commande) in [
            ("Tailscale", r"C:\Program Files\Tailscale\tailscale-ipn.exe"),
            (
                "Cloudflare WARP",
                r"C:\Program Files\Cloudflare\Cloudflare WARP\Cloudflare WARP.exe",
            ),
            (
                "ZeroTier One",
                r"C:\Program Files (x86)\ZeroTier\One\zerotier_desktop_ui.exe",
            ),
        ] {
            assert!(a_garder(nom, commande, false).is_some(), "{nom}");
        }
        // Pare-feu tiers de Windows : à garder (sous Linux, `classer` lit d'abord le paquet).
        #[cfg(not(target_os = "linux"))]
        for (nom, commande) in [
            ("TinyWall", r"C:\Program Files (x86)\TinyWall\TinyWall.exe"),
            ("GlassWire", r"C:\Program Files (x86)\GlassWire\glasswire.exe"),
            ("simplewall", r"C:\Program Files\simplewall\simplewall.exe"),
            ("Portmaster", r"C:\Program Files\Safing\Portmaster\portmaster-start.exe"),
        ] {
            assert!(a_garder(nom, commande, false).is_some(), "{nom}");
        }
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
        // Un nom de pare-feu hors de tout paquet (un faux, ou un pare-feu posé à la main) : jamais retiré d'un clic,
        // ni proposé comme pare-feu ; gardé, et dit.
        for (nom, commande) in [
            ("ufw", "/home/alice/.local/bin/ufw"),
            ("Portmaster", "/opt/safing/portmaster/portmaster-start"),
            ("simplewall", "/home/alice/bin/simplewall"),
        ] {
            assert!(
                matches!(
                    classe(nom, commande, EtatPaquet::Aucun),
                    Garde::Garder(r) if r.contains("hors paquet") || r.contains("not from a package")
                ),
                "{nom}"
            );
        }
        // Hors paquet sans nom de pare-feu : un programme comme un autre.
        assert_eq!(
            classe("Lecteur", "/home/alice/bin/lecteur", EtatPaquet::Aucun),
            Garde::Ordinaire
        );
        // Les VPN connus restent gardés (sécurité), quel que soit le paquet.
        for (nom, commande) in [
            ("Tailscale", "/usr/bin/tailscale systray"),
            ("Cloudflare WARP", "/usr/bin/warp-taskbar"),
            ("ZeroTier", "/usr/sbin/zerotier-one"),
        ] {
            assert!(
                matches!(classe(nom, commande, EtatPaquet::Aucun), Garde::Garder(_)),
                "{nom}"
            );
        }
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
        for (nom, commande) in [("GUFW", "gufw"), ("Firewall", "fw.exe")] {
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
                vu: None,
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
                vu: None,
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
}

#[cfg(test)]
mod essais_changer {
    use super::*;

    /// Seuls 32 chiffres hexadécimaux minuscules passent : ni majuscule, ni espace, ni longueur voisine, ni chemin.
    #[test]
    fn empreinte_mal_formee_refusee() {
        assert!(empreinte_bien_formee(&"0a".repeat(16)));
        for e in [
            String::new(),
            "0".repeat(31),
            "0".repeat(33),
            "0A".repeat(16),
            format!(" {}", "0".repeat(31)),
            format!("{}\n", "0".repeat(31)),
            "../../../../../../etc/passwd.....".to_string(),
            "g".repeat(32),
            "\u{ff10}".repeat(32),
        ] {
            assert!(!empreinte_bien_formee(&e), "{e:?}");
            assert_eq!(
                a_retirer(Vec::new(), &e, |_| Garde::Ordinaire).err(),
                Some(Refus::MalFormee)
            );
            assert_eq!(a_remettre(&Historique::default(), &e).err(), Some(Refus::MalFormee));
        }
        // Mal formée : refusée avant toute lecture du système, code 2.
        assert_eq!(changer(SorteDeChangement::Retirer, "NOPE", true), 2);
        assert_eq!(changer(SorteDeChangement::Remettre, &"0".repeat(31), false), 2);
    }

    /// Remettre une empreinte sans note (le dossier de Vanguard des essais est jetable et vide) : refusé, code 1,
    /// rien de lu sur le système.
    #[test]
    fn remettre_sans_note_refuse() {
        assert_eq!(changer(SorteDeChangement::Remettre, &"0".repeat(32), true), 1);
    }

    #[cfg(target_os = "linux")]
    fn service(nom: &str, actif: bool) -> Programme {
        use super::systeme::{Changement, Entree};
        Programme {
            nom: nom.to_string(),
            commande: format!("/usr/bin/{}", nom.to_lowercase()),
            actif,
            machine: false,
            bureau: false,
            changement: Changement::Demarrage {
                entree: Entree::Service(format!("{nom}.service")),
                cible: Some("disabled".to_string()),
                vu: None,
            },
        }
    }

    #[cfg(target_os = "linux")]
    fn empreinte_de(nom: &str) -> String {
        resultat::empreinte(&format!("systemd|{nom}.service")).unwrap_or_default()
    }

    /// Une liste inventée, classée sans lire le système : seul le programme ordinaire qui se lance est retiré ; un
    /// programme à garder ou un pare-feu ne l'est jamais, même désigné par sa vraie empreinte.
    #[cfg(target_os = "linux")]
    #[test]
    fn seul_un_programme_ordinaire_se_retire() {
        let liste = || {
            vec![
                service("Lecteur", true),
                service("Pilote", true),
                service("Murdefeu", true),
                service("Ancien", false),
            ]
        };
        let classe = |p: &Programme| match p.nom.as_str() {
            "Pilote" => Garde::Garder("pilote"),
            "Murdefeu" => Garde::PareFeu,
            _ => Garde::Ordinaire,
        };
        let r = a_retirer(liste(), &empreinte_de("Lecteur"), classe);
        assert_eq!(
            r.map(|r| r.id.into_owned()),
            Ok("demarrage:systemd|Lecteur.service".to_string())
        );
        for (nom, refus) in [
            ("Pilote", Refus::AGarder("pilote")),
            ("Murdefeu", Refus::PareFeu),
            ("Ancien", Refus::NeSeLancePas),
        ] {
            assert_eq!(
                a_retirer(liste(), &empreinte_de(nom), classe).err(),
                Some(refus),
                "{nom}"
            );
        }
        assert_eq!(a_retirer(liste(), &"0".repeat(32), classe).err(), Some(Refus::Inconnue));
        // Une empreinte en double : aucun des deux n'est choisi.
        let double = vec![service("Lecteur", true), service("Lecteur", true)];
        assert_eq!(
            a_retirer(double, &empreinte_de("Lecteur"), classe).err(),
            Some(Refus::Ambigue)
        );
        // L'empreinte d'un programme ne désigne pas un autre.
        assert_eq!(
            a_retirer(vec![service("Pilote", true)], &empreinte_de("Lecteur"), |_| {
                Garde::Ordinaire
            })
            .err(),
            Some(Refus::Inconnue)
        );
    }

    /// Correction n° 2 de la 0.94, D-1 : Vanguard a noté une entrée d'autostart ; elle se lance de nouveau, réécrite
    /// hors de lui en plus de 64 Kio (ou pas en UTF-8). Le relevé ne la lit pas (il la dit pas lue) : elle n'est ni
    /// offerte à remettre, ni remise par-dessus (`--remettre`, la liste, « Tout remettre comme avant »).
    #[cfg(target_os = "linux")]
    #[test]
    fn note_sur_une_entree_pas_lue_ni_offerte_ni_remise() {
        use super::super::Avant;
        let base = crate::essais::temporaire().join(format!("vanguard-demarrage-d1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let autostart = base.join("config/autostart");
        std::fs::create_dir_all(&autostart).unwrap();
        let gros = format!("[Desktop Entry]\nName=Gros\nExec=gros\n#{}\n", "x".repeat(76 << 10)).into_bytes();
        let latin1 = b"[Desktop Entry]\nName=Caf\xe9\nExec=cafe\n".to_vec();
        for (fichier, contenu) in [("gros.desktop", gros), ("latin1.desktop", latin1)] {
            let p = autostart.join(fichier);
            std::fs::write(&p, &contenu).unwrap();
            let identite = format!("autostart|{}", p.display());
            let mut h = Historique::default();
            h.reglages.insert(
                format!("{PREFIXE}{identite}"),
                Avant {
                    date: String::new(),
                    valeurs: vec![Some("+[Desktop Entry]\nName=Ancien\nExec=ancien\n".to_string())],
                    ..Avant::default()
                },
            );
            let (programmes, manques) =
                systeme::releve_dans(&base.join("config"), &[], "Hyprland", Some(String::new()));
            assert!(programmes.is_empty(), "{fichier} lue");
            assert_eq!(manques.len(), 1, "{fichier} : {manques:?}");
            // La note existe, l'empreinte la désigne ; mais rien ne s'offre ni ne se remet.
            let r = a_remettre(&h, &resultat::empreinte(&identite).unwrap()).unwrap();
            assert_eq!(remise_refusee(&r, &programmes), Some(Refus::PasLue), "{fichier}");
            assert!(lignes(programmes, &h).is_empty(), "{fichier} offerte à remettre");
            assert!(Refus::PasLue.raison().contains("rien n"));
            assert_eq!(std::fs::read(&p).unwrap(), contenu, "{fichier}");
            std::fs::remove_file(&p).unwrap();
            // Absente : offerte et remise, comme avant.
            let (programmes, manques) =
                systeme::releve_dans(&base.join("config"), &[], "Hyprland", Some(String::new()));
            assert!(manques.is_empty(), "{manques:?}");
            assert_eq!(remise_refusee(&r, &programmes), None);
            assert_eq!(lignes(programmes, &h).len(), 1);
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Correction n° 2 de la 0.94, D-2 : une entrée qui, masquée, dépasserait la borne de lecture est montrée à
    /// garder dans la liste et refusée par `--retirer` (rien d'écrit) ; un octet de moins, elle se retire.
    #[cfg(target_os = "linux")]
    #[test]
    fn entree_trop_grosse_une_fois_masquee_ni_proposee_ni_retiree() {
        let base = crate::essais::temporaire().join(format!("vanguard-demarrage-d2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let autostart = base.join("config/autostart");
        std::fs::create_dir_all(&autostart).unwrap();
        let p = autostart.join("bord.desktop");
        let entete = "[Desktop Entry]\nName=Bord\nExec=bord\n#";
        let releve = || systeme::releve_dans(&base.join("config"), &[], "", Some(String::new())).0;
        for (n, refus) in [(65_523, None), (65_524, Some(Refus::TropGrosse))] {
            std::fs::write(&p, format!("{entete}{}\n", "x".repeat(n - entete.len() - 1))).unwrap();
            let empreinte = resultat::empreinte(&format!("autostart|{}", p.display())).unwrap();
            let issue = a_retirer(releve(), &empreinte, |_| Garde::Ordinaire);
            assert_eq!(issue.err(), refus, "{n}");
            let l = lignes(releve(), &Historique::default());
            assert_eq!(l.len(), 1, "{n}");
            assert_eq!(l[0].garder().is_some(), refus.is_some(), "{n}");
            assert!(Refus::TropGrosse.raison().contains("rien n"));
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Remettre ne vise que ce que Vanguard a noté.
    #[cfg(target_os = "linux")]
    #[test]
    fn seul_un_programme_note_se_remet() {
        use super::super::Avant;
        let mut h = Historique::default();
        h.reglages.insert(
            format!("{PREFIXE}systemd|Lecteur.service"),
            Avant {
                date: String::new(),
                valeurs: vec![Some("enabled".to_string())],
                ..Avant::default()
            },
        );
        assert_eq!(
            a_remettre(&h, &empreinte_de("Lecteur")).map(|r| r.id.into_owned()),
            Ok("demarrage:systemd|Lecteur.service".to_string())
        );
        assert_eq!(a_remettre(&h, &empreinte_de("Autre")).err(), Some(Refus::Inconnue));
        assert_eq!(
            a_remettre(&Historique::default(), &empreinte_de("Lecteur")).err(),
            Some(Refus::Inconnue)
        );
        // Relues pour de bon avant de remettre : la même note, ou rien.
        let r = a_remettre(&h, &empreinte_de("Lecteur")).unwrap();
        let note = |valeur: &str| {
            let mut n = Historique::default();
            n.reglages.insert(
                format!("{PREFIXE}systemd|Lecteur.service"),
                Avant {
                    date: String::new(),
                    valeurs: vec![Some(valeur.to_string())],
                    ..Avant::default()
                },
            );
            n
        };
        assert!(relu_pareil(&h, &r, &note("enabled"), &empreinte_de("Lecteur")).is_ok());
        let autre = note("disabled");
        assert_eq!(
            relu_pareil(&h, &r, &autre, &empreinte_de("Lecteur")).err(),
            Some(Refus::NotesDouteuses)
        );
        assert_eq!(
            relu_pareil(&h, &r, &Historique::default(), &empreinte_de("Lecteur")).err(),
            Some(Refus::NotesDouteuses)
        );
    }

    /// Chaque refus se dit.
    #[test]
    fn chaque_refus_a_sa_raison() {
        for r in [
            Refus::MalFormee,
            Refus::Inconnue,
            Refus::Ambigue,
            Refus::NeSeLancePas,
            Refus::SeLanceDeja,
            Refus::AGarder("pilote"),
            Refus::PareFeu,
            Refus::NotesDouteuses,
            Refus::NotesOccupees,
        ] {
            assert_ne!(r.raison(), "");
        }
    }
}
