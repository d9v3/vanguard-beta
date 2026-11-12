//! Réglages de Linux : services de systemd, fichiers de réglage posés par Vanguard, préférences de GNOME, options des
//! distributions (Ubuntu, Debian). Chacun n'est proposé que si cette machine en a l'usage : un SSD pour l'entretien
//! des SSD, GNOME pour ses préférences, le paquet concerné pour les options des distributions.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::path::{Path, PathBuf};

use super::demarrage::{Ecriture, Programme};
use super::{Categorie, Reglage, Valeur};
use crate::commande::sh_chaine;
use crate::machine::defense_eleve::DOSSIER_NOTES;
use crate::machine::gestes_unix::{Defense, GesteUnix, IdNote};
use crate::machine::linux::natif;
use crate::ui::*;

mod sous_maison;

/// La présence de la note d'un geste de défense (`Changement::Defense`), seule valeur relevée : son contenu n'est lu
/// que par root.
const NOTE_PRESENTE: &str = "note";
/// La plus longue note admise d'un fichier d'autostart (« + » et contenu) : ce qu'en lit `lire` et ce qu'en admet la
/// relecture des notes, une seule borne.
const AUTOSTART_MAX: usize = 64 << 10;
/// Le plus long fichier d'unité de systemd lu par le démarrage (une unité ordinaire fait quelques centaines
/// d'octets) : au-delà, il n'est pas lu, et c'est dit (relecture 0.94, R-7).
const UNITE_MAX: usize = 64 << 10;

/// Ce que retire un réglage de démarrage.
pub enum Entree {
    /// Fichier .desktop d'autostart du compte (chemin complet). Une entrée du système s'y masque par une copie qui
    /// porte « Hidden=true » ; la retirer fait revenir celle du système.
    Autostart(PathBuf),
    /// Service de systemd --user installé par la personne (~/.config/systemd/user).
    Service(String),
}

pub enum Changement {
    /// Minuterie ou service de systemd : « enabled » ou « disabled ». `defaut` : son état sur un système neuf.
    Unite {
        nom: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// Fichier posé par Vanguard (présent = fait), retiré pour annuler ; `apres`, la commande qui le fait prendre.
    Fichier {
        chemin: &'static str,
        contenu: &'static str,
        apres: &'static str,
    },
    /// Préférence de GNOME (gsettings), avec sa valeur d'origine.
    Gnome {
        schema: &'static str,
        cle: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// Ligne « CLE=valeur » d'un fichier de configuration du système.
    Option {
        fichier: &'static str,
        cle: &'static str,
        cible: &'static str,
        defaut: &'static str,
    },
    /// DNS d'une connexion de NetworkManager (outil « DNS le plus rapide »). Valeur : « uuid\ndns4|ignore4|dns6|ignore6 »,
    /// les serveurs séparés par des virgules ; « ignore » (yes, no) dit si ceux de la box sont écartés. `cible` :
    /// `None` quand le réglage n'est rebâti que pour être annulé.
    Dns { connexion: String, cible: Option<String> },
    /// Programme lancé à l'ouverture de session (outil « Programmes au démarrage »). Valeur : « +contenu » du fichier
    /// d'autostart du compte (« - » : absent), ou l'état du service pour systemd (enabled, disabled). `cible` :
    /// `None` quand le réglage n'est rebâti que pour être annulé. `vu` : la valeur lue quand l'entrée a été listée,
    /// celle d'où viennent ce qui est montré et `cible` ; la note la garde (`lire_pour_noter`), et rien ne s'écrit si
    /// le fichier n'est plus celui-là (`ecrire_ici`). `None` : un service, ou rebâti d'après une note.
    Demarrage {
        entree: Entree,
        cible: Option<String>,
        vu: Option<String>,
    },
    /// Réglage du noyau (/proc/sys) qu'une correction du bilan ou un réglage pour jouer change, remis par
    /// `sysctl -w`. La clé s'écrit en chemin (« kernel/kptr_restrict ») : un nom d'interface peut contenir un point.
    Sysctl { cle: String },
    /// Fichier que Vanguard pose dans /etc (liste fermée `POSES`), noté en entier : remis tel quel, ou retiré s'il
    /// n'existait pas, puis sa commande `apres` le fait prendre. `chemin` : son nom d'aujourd'hui ou d'avant le
    /// changement de nom (`passage`), celui que la note désigne.
    Pose {
        chemin: String,
        fichier: &'static FichierPose,
    },
    /// Module du noyau (liste fermée `MODULES`) : « charge », ou absent.
    Module { nom: &'static str },
    /// Droits d'un fichier du dossier personnel (« 0644 »), remis par chmod, sans sudo.
    Droits { chemin: PathBuf },
    /// Heure réglée par le réseau (`timedatectl`) : « yes » ou « no ».
    Ntp,
    /// Un geste de défense, fait par l'enfant root (`machine::defense_eleve`), qui a noté avant lui l'état d'avant dans
    /// `/var/lib/vanguard/avant/<id>`, que seul root lit. Ici, seule la présence de cette note se relève (le dossier se
    /// traverse sans se lister) : absente avant le geste, elle se remet en faisant défaire le geste par l'enfant
    /// (`Defense::Remettre`), qui rejuge la note, redemande à la personne et la retire.
    Defense { id: IdNote },
}

/// Ce qu'un fichier posé par Vanguard peut contenir pour qu'une valeur notée y soit remise avec sudo.
#[derive(Clone, Copy)]
pub enum Forme {
    /// Lignes « clé = nombre » de sysctl.d (ou commentaires) : jamais un texte, que le noyau lirait comme une
    /// commande (kernel.core_pattern).
    Sysctl,
    /// Lignes « Directive valeur » de sshd, parmi les directives que Vanguard écrit (`DIRECTIVES_SSHD`).
    Sshd,
    /// Exactement ce que Vanguard y écrit.
    Exact(&'static str),
}

/// Un fichier que Vanguard pose dans /etc : ce qu'il peut contenir, et ce qui le fait prendre une fois remis.
pub struct FichierPose {
    pub chemin: &'static str,
    pub forme: Forme,
    pub apres: &'static str,
}

/// Le contenu que la correction d'Ollama pose (écoute en local seulement).
pub(crate) const OLLAMA_CONTENU: &str = "[Service]\nEnvironment=OLLAMA_HOST=127.0.0.1\n";
pub(crate) const OLLAMA_VANGUARD: &str = "/etc/systemd/system/ollama.service.d/vanguard.conf";

/// La liste fermée des fichiers que Vanguard pose et sait remettre : une note ne peut en désigner aucun autre.
/// Le fichier du durcissement du noyau (`SYSCTL_VANGUARD`) n'y est pas : c'est une protection, que Vanguard ne défait
/// pas ; une note qui le retirerait ou le viderait affaiblirait le noyau au prochain démarrage.
static POSES: [FichierPose; 4] = [
    FichierPose {
        chemin: crate::machine::linux::SSHD_VANGUARD,
        forme: Forme::Sshd,
        apres: crate::machine::linux::RECHARGER_SSHD,
    },
    FichierPose {
        chemin: OLLAMA_VANGUARD,
        forme: Forme::Exact(OLLAMA_CONTENU),
        // Lot U3 : reste une commande, après le fichier posé ; geste avec lui (U4).
        apres: "sudo systemctl daemon-reload && sudo systemctl try-restart ollama",
    },
    FichierPose {
        chemin: crate::gaming::linux::SYSCTL_JEUX,
        forme: Forme::Sysctl,
        apres: "",
    },
    FichierPose {
        chemin: crate::gaming::linux::NTSYNC_CONF,
        forme: Forme::Exact("ntsync\n"),
        apres: "",
    },
];

/// Les services que les corrections du bilan arrêtent ou lancent, et qu'une note peut faire remettre.
const UNITES: [&str; 2] = ["cups-browsed", "auditd"];

/// Les modules du noyau qu'un réglage pour jouer charge.
const MODULES: [&str; 1] = ["ntsync"];

/// Les directives que Vanguard écrit dans son fichier de sshd : une note n'y remet que celles-là.
const DIRECTIVES_SSHD: [&str; 16] = [
    "PermitEmptyPasswords",
    "PermitRootLogin",
    "PasswordAuthentication",
    "KbdInteractiveAuthentication",
    "ChallengeResponseAuthentication",
    "GatewayPorts",
    "X11Forwarding",
    "MaxAuthTries",
    "Ciphers",
    "MACs",
    "KexAlgorithms",
    "HostKeyAlgorithms",
    "PubkeyAcceptedAlgorithms",
    "PubkeyAcceptedKeyTypes",
    "CASignatureAlgorithms",
    "HostbasedAcceptedAlgorithms",
];

/// Un contenu noté pour un fichier posé : une forme que ce fichier peut avoir, sans rien que sudo écrirait d'autre.
fn contenu_admis(forme: Forme, t: &str) -> bool {
    let lignes_admises = |ligne: &dyn Fn(&str) -> bool| {
        t.len() <= 8 << 10
            && !t.contains('\0')
            && t.lines()
                .map(str::trim)
                .all(|l| l.is_empty() || l.starts_with('#') || ligne(l))
    };
    match forme {
        Forme::Exact(c) => t == c,
        Forme::Sysctl => lignes_admises(&|l| {
            l.split_once('=').is_some_and(|(k, v)| {
                let (k, v) = (k.trim(), v.trim());
                !k.is_empty()
                    && k.chars().all(|c| c.is_ascii_alphanumeric() || "._-/*".contains(c))
                    && !v.is_empty()
                    && v.chars().all(|c| c.is_ascii_digit() || " \t-".contains(c))
                    && ligne_sysctl_posee(&k.replace('.', "/"), v)
            })
        }),
        Forme::Sshd => lignes_admises(&|l| {
            l.split_once(' ').is_some_and(|(d, v)| {
                !v.is_empty()
                    && v.len() <= 2048
                    && v.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-=/*?,".contains(c))
                    && directive_sshd_posee(d, v.trim())
            })
        }),
    }
}

/// La plus petite limite de mémoire des jeux remise : celle du noyau par défaut.
const MAX_MAP_COUNT_MIN: u64 = 65_530;

/// Une ligne de sysctl que Vanguard écrit dans ses fichiers, ou remet par `sysctl -w` : la limite de mémoire des
/// jeux, ou une clé du durcissement à sa valeur sûre. Ces fichiers sont lus en root à chaque démarrage, et la remise
/// se fait en root : une clé libre ou une valeur affaiblie viendrait d'ailleurs que de Vanguard.
fn ligne_sysctl_posee(cle: &str, v: &str) -> bool {
    match cle {
        // Un plancher : la valeur par défaut du noyau (65 530). Plus bas, plus aucun programme ne démarre.
        "vm/max_map_count" => v
            .parse::<u64>()
            .is_ok_and(|n| (MAX_MAP_COUNT_MIN..=u64::from(i32::MAX.unsigned_abs())).contains(&n)),
        _ => v
            .parse::<i64>()
            .is_ok_and(|n| crate::machine::linux::valeur_durcie(cle, n)),
    }
}

/// Une directive de sshd à une valeur que Vanguard écrit : celles qui ferment (« no »), la connexion root sans mot
/// de passe au plus, peu d'essais, des algorithmes sans faible. sshd relit ce fichier en premier : « yes » ouvrirait
/// ce que les corrections ont fermé.
fn directive_sshd_posee(d: &str, v: &str) -> bool {
    match d {
        "PermitRootLogin" => matches!(v, "no" | "prohibit-password"),
        "MaxAuthTries" => v.parse::<u8>().is_ok_and(|n| (1..=6).contains(&n)),
        "Ciphers"
        | "MACs"
        | "KexAlgorithms"
        | "HostKeyAlgorithms"
        | "PubkeyAcceptedAlgorithms"
        | "PubkeyAcceptedKeyTypes"
        | "CASignatureAlgorithms"
        | "HostbasedAcceptedAlgorithms" => crate::machine::linux::liste_sure(v),
        _ => DIRECTIVES_SSHD.contains(&d) && v == "no",
    }
}

/// La seule clé de sysctl qu'une note peut faire remettre par `sysctl -w` : la limite de mémoire des jeux. Celles du
/// durcissement n'y sont plus : c'est une protection, que Vanguard ne défait pas, et une note forgée ne doit pas
/// pouvoir y poser une valeur, même plus sûre (« ptrace_scope = 3 » en root bloquerait tout débogueur jusqu'au
/// redémarrage).
fn cle_sysctl_connue(cle: &str) -> bool {
    cle == "vm/max_map_count"
}

/// Un geste du durcissement du noyau tel que la 0.86 et la 0.87 le notaient (son fichier, sous son nom d'aujourd'hui
/// ou d'avant, une clé du durcissement, la redirection IPv6 d'une interface) : c'est une protection désormais, et
/// sa note d'annulation est retirée au chargement (`annulables::retirer_protections`).
pub fn geste_de_protection(geste: &str) -> bool {
    if let Some(chemin) = geste.strip_prefix("fichier|") {
        return crate::passage::les_deux(crate::machine::linux::SYSCTL_VANGUARD)
            .iter()
            .any(|n| n == chemin);
    }
    geste.strip_prefix("sysctl|").is_some_and(|cle| {
        crate::machine::linux::cle_durcie(cle)
            || cle
                .strip_prefix("net/ipv6/conf/")
                .and_then(|r| r.strip_suffix("/accept_redirects"))
                .is_some_and(|i| !i.is_empty() && !i.contains('/'))
    })
}

/// Aucun réglage du catalogue n'est une protection ici.
pub fn reglage_protege(_id: &str) -> bool {
    false
}

/// La valeur d'une clé de sysctl, espaces normalisés (« 4096 87380 6291456 ») ; `None` : illisible.
fn sysctl_lu(cle: &str) -> Option<String> {
    let t = std::fs::read_to_string(Path::new("/proc/sys").join(cle)).ok()?;
    Some(t.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// L'heure réglée par le réseau, d'après timedatectl : « yes » ou « no ».
fn ntp_lu() -> Option<String> {
    let v = sortie("timedatectl", &["show", "-p", "NTP", "--value"])?;
    matches!(v.as_str(), "yes" | "no").then_some(v)
}

/// Un nom de service de systemd : il entre tel quel dans la commande.
fn unite_valide(t: &str) -> bool {
    t.len() <= 255
        && t.strip_suffix(".service")
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || "@._:-".contains(c)))
}

/// Le nom et la commande d'une entrée .desktop, prêts à montrer (bornés, caractères de contrôle neutralisés).
fn resume_entree(texte: &str) -> String {
    let borne = |v: &str| montrer_borne(v, 80);
    let nom = champ(texte, "Name").map_or_else(|| "?".to_string(), borne);
    let exec = champ(texte, "Exec").map_or_else(|| "?".to_string(), borne);
    format!("{nom} · {exec}")
}

/// La valeur d'une clé du groupe [Desktop Entry] d'un fichier .desktop.
fn champ<'a>(texte: &'a str, cle: &str) -> Option<&'a str> {
    let mut dans_entree = false;
    for l in texte.lines() {
        let l = l.trim();
        if l.starts_with('[') {
            dans_entree = l == "[Desktop Entry]";
        } else if dans_entree
            && let Some((k, v)) = l.split_once('=')
            && k.trim() == cle
        {
            return Some(v.trim());
        }
    }
    None
}

/// Une valeur d'entrée d'autostart (« +contenu », « - », absente) dont l'écriture se relirait : le contenu tient
/// dans la borne de `lire` (`AUTOSTART_MAX` avec le « + »).
fn relisible(v: Option<&str>) -> bool {
    v.and_then(|v| v.strip_prefix('+'))
        .is_none_or(|contenu| contenu.len() < AUTOSTART_MAX)
}

/// Le fichier d'autostart masqué : « Hidden=true » juste sous [Desktop Entry], à la place de toute autre valeur
/// « Hidden » de ce groupe ; le reste est gardé à l'octet près. Masquer deux fois ne change plus rien.
fn masquer(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len().saturating_add(16));
    let mut dans_entree = false;
    let mut pose = false;
    for l in texte.split_inclusive('\n') {
        let t = l.trim();
        if t.starts_with('[') {
            dans_entree = t == "[Desktop Entry]";
            sortie.push_str(l);
            if dans_entree && !pose {
                if !l.ends_with('\n') {
                    sortie.push('\n');
                }
                sortie.push_str("Hidden=true\n");
                pose = true;
            }
            continue;
        }
        if dans_entree && t.split_once('=').is_some_and(|(k, _)| k.trim() == "Hidden") {
            continue;
        }
        sortie.push_str(l);
    }
    if !pose {
        if !sortie.is_empty() && !sortie.ends_with('\n') {
            sortie.push('\n');
        }
        sortie.push_str("[Desktop Entry]\nHidden=true\n");
    }
    sortie
}

/// Le fichier d'autostart sans ses lignes « Hidden » : la forme où l'entrée se lance.
fn demasquer(texte: &str) -> String {
    let mut dans_entree = false;
    texte
        .split_inclusive('\n')
        .filter(|l| {
            let t = l.trim();
            if t.starts_with('[') {
                dans_entree = t == "[Desktop Entry]";
                return true;
            }
            !(dans_entree && t.split_once('=').is_some_and(|(k, _)| k.trim() == "Hidden"))
        })
        .collect()
}

/// Les dossiers d'autostart du système (`dossiers_autostart_selon`, d'après XDG_CONFIG_DIRS).
fn dossiers_systeme() -> Vec<PathBuf> {
    dossiers_autostart_du_systeme().0
}

/// Le dossier de configuration du système que la norme XDG donne par défaut, /etc/xdg. Essais seulement (binaire de
/// débogage) : `VANGUARD_ESSAI_XDG_DEFAUT` le remplace par un dossier jetable, pour qu'un essai ne lise pas les
/// entrées de la machine qui le lance. Rien dans un binaire livré.
fn xdg_par_defaut() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(d) = std::env::var_os("VANGUARD_ESSAI_XDG_DEFAUT") {
        return PathBuf::from(d);
    }
    PathBuf::from("/etc/xdg")
}

/// `dossiers_autostart_selon` sur XDG_CONFIG_DIRS de l'environnement de Vanguard et /etc/xdg (`lenteur` et
/// `demarrage` lisent les mêmes dossiers).
pub(crate) fn dossiers_autostart_du_systeme() -> (Vec<PathBuf>, Option<String>) {
    dossiers_autostart_selon(std::env::var("XDG_CONFIG_DIRS").ok().as_deref(), &xdg_par_defaut())
}

/// Les dossiers d'autostart du système : ceux de XDG_CONFIG_DIRS (`variable`), chemins absolus seulement (la norme XDG
/// ignore les autres : un chemin relatif se lirait depuis le dossier courant), puis toujours celui de `defaut`
/// (/etc/xdg). Avec la phrase à dire quand la variable ne nomme pas `defaut` ou nomme un chemin relatif : la variable
/// se règle dans un fichier du compte (démarrage du shell), et la régler ainsi cachait sans un mot les entrées que
/// la session lance depuis /etc/xdg/autostart (relecture 0.95, G-3). Une variable qui ajoute des dossiers devant
/// /etc/xdg (Ubuntu, flatpak) ne cache rien : pas de phrase.
fn dossiers_autostart_selon(variable: Option<&str>, defaut: &Path) -> (Vec<PathBuf>, Option<String>) {
    let variable = variable.unwrap_or_default();
    let noms: Vec<&Path> = variable.split(':').filter(|d| !d.is_empty()).map(Path::new).collect();
    let absolus: Vec<&Path> = noms.iter().copied().filter(|d| d.is_absolute()).collect();
    let mut dossiers: Vec<PathBuf> = Vec::new();
    for d in absolus.iter().copied().chain(std::iter::once(defaut)) {
        let a = d.join("autostart");
        if !dossiers.contains(&a) {
            dossiers.push(a);
        }
    }
    let cache = !noms.is_empty() && (absolus.len() != noms.len() || !absolus.contains(&defaut));
    let phrase = cache.then(|| {
        trf!(
            "XDG_CONFIG_DIRS ({}) ne nomme pas {} ou nomme un chemin relatif : la session lit peut-être d'autres entrées ; {} est lu quand même, les chemins relatifs ne le sont pas",
            "XDG_CONFIG_DIRS ({}) does not name {} or names a relative path: the session may read other entries; {} is read anyway, relative paths are not",
            montrer_borne(&sans_maison_xdg(variable), 200),
            court(defaut),
            court(&defaut.join("autostart"))
        )
    });
    (dossiers, phrase)
}

/// La valeur de XDG_CONFIG_DIRS, chaque dossier sous le dossier personnel montré « ~/… » (`court`) : la phrase part
/// dans `--json`, au rapport et au journal, sans le nom du compte (relecture 0.95, H-3, comme R-4 pour la commande).
fn sans_maison_xdg(variable: &str) -> String {
    let maison = crate::socle::personnel::dossier_personnel();
    variable
        .split(':')
        .map(|d| match maison.as_deref() {
            Some(m) if Path::new(d) == m => "~".to_string(),
            _ => court(Path::new(d)),
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// Un texte venu de l'extérieur prêt à montrer (`ui::affichable`), coupé à `max` caractères.
fn montrer_borne(texte: &str, max: usize) -> String {
    let v = crate::ui::affichable(texte);
    if v.chars().count() > max {
        format!("{}…", v.chars().take(max).collect::<String>())
    } else {
        v
    }
}

thread_local! {
    /// La raison du dernier refus d'écrire, dite sur sa ligne ✖ : `demarrage --retirer|--remettre --json` la reprend
    /// dans son issue, au lieu d'une phrase générale (relecture 0.94, m-4).
    static DERNIER_REFUS: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Dit à l'écran pourquoi rien n'est écrit (ligne ✖), et le retient pour `dernier_refus`.
fn refuser_ici(raison: &str) {
    println!("    ✖ {raison}");
    DERNIER_REFUS.with_borrow_mut(|d| *d = Some(raison.to_string()));
}

/// La raison du dernier refus d'écrire de ce fil, s'il y en a eu un depuis la dernière demande ; la vide.
pub fn dernier_refus() -> Option<String> {
    DERNIER_REFUS.with_borrow_mut(Option::take)
}

/// Un chemin du dossier personnel, écrit court (« ~/.config/autostart/… »).
fn court(p: &Path) -> String {
    let maison = crate::socle::personnel::dossier_personnel();
    match maison.as_deref().and_then(|m| p.strip_prefix(m).ok()) {
        Some(reste) if !reste.as_os_str().is_empty() => format!("~/{}", reste.display()),
        _ => p.display().to_string(),
    }
}

/// Une propriété d'une connexion de NetworkManager, sans échappement (les « : » des adresses IPv6 restent) : par
/// D-Bus (GetSettings), au format de `nmcli -g` ; nmcli en secours si le bus ne répond pas.
fn nm_valeur(connexion: &str, propriete: &str) -> Option<String> {
    match crate::machine::linux::networkmanager::profil(connexion) {
        Ok(Some(p)) => return p.propriete(propriete),
        // Profil inconnu de NetworkManager : rien à lire, comme nmcli qui répond par une erreur.
        Ok(None) => return None,
        Err(_) => {}
    }
    let r = crate::commande::lancer(
        crate::commande::par_le_systeme("nmcli").args([
            "-t",
            "-e",
            "no",
            "-g",
            propriete,
            "connection",
            "show",
            connexion,
        ]),
        10,
    )?;
    (r.code == Some(0)).then(|| r.sortie.trim().to_string())
}

/// Liste de serveurs normalisée : « 1.1.1.1,1.0.0.1 », quel que soit le séparateur lu.
fn liste_dns(t: &str) -> String {
    t.split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// Un identifiant de connexion de NetworkManager (UUID) : il entre tel quel dans les commandes.
fn uuid_valide(t: &str) -> bool {
    t.len() == 36 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Ce que dit une valeur de DNS : les serveurs listés, et si ceux de la box servent encore.
fn decrire_dns(v: Option<&str>) -> String {
    let reste = v.and_then(|v| v.split_once('\n')).map_or("", |(_, r)| r);
    let c: Vec<&str> = reste.split('|').collect();
    let serveurs: Vec<&str> = [0, 2]
        .iter()
        .filter_map(|&i| c.get(i))
        .flat_map(|l| l.split(','))
        .filter(|s| !s.is_empty())
        .collect();
    super::texte_dns(&serveurs, c.get(1) != Some(&"yes"))
}

/// Carte réseau de la route par défaut dans /proc/net/route (la plus petite métrique, via une passerelle).
fn carte_par_defaut(table: &str) -> Option<String> {
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let drapeaux = u32::from_str_radix(c.get(3)?, 16).ok()?;
            // Route vers tout (destination 0), par une passerelle, active (drapeaux UP et GATEWAY).
            if c.get(1) != Some(&"00000000") || c.get(2) == Some(&"00000000") || drapeaux & 0x3 != 0x3 {
                return None;
            }
            Some((c.get(6)?.parse::<u32>().ok()?, (*c.first()?).to_string()))
        })
        .min()
        .map(|(_, carte)| carte)
}

/// Le DNS de la connexion principale (celle de la route par défaut), à régler sur ces serveurs ; ceux en IPv6
/// seulement si la connexion se sert de l'IPv6. Erreur : pourquoi il faut le faire à la main.
pub fn dns_principal(v4: &[&str], v6: &[&str]) -> Result<Changement, String> {
    let a_la_main = tr!(
        "NetworkManager ne gère pas cette connexion : le DNS se règle à la main (paramètres réseau, ou dans le routeur).",
        "NetworkManager does not manage this connection: set the DNS by hand (network settings, or in the router)."
    );
    let carte = std::fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|t| carte_par_defaut(&t))
        .ok_or_else(|| tr!("Pas de connexion à Internet.", "No Internet connection.").to_string())?;
    // Les connexions actives par D-Bus ; nmcli en secours.
    let actives = crate::machine::linux::networkmanager::actives().unwrap_or_else(|_| {
        sortie(
            "nmcli",
            &["-t", "-e", "no", "-f", "UUID,DEVICE", "connection", "show", "--active"],
        )
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let (uuid, appareil) = l.split_once(':')?;
            Some((uuid.to_string(), vec![appareil.to_string()]))
        })
        .collect()
    });
    let connexion = actives
        .into_iter()
        .find(|(uuid, cartes)| cartes.contains(&carte) && uuid_valide(uuid))
        .map(|(uuid, _)| uuid)
        .ok_or_else(|| a_la_main.to_string())?;
    let actuel = Changement::Dns {
        connexion: connexion.clone(),
        cible: None,
    }
    .lire()
    .ok_or_else(|| a_la_main.to_string())?;
    let c: Vec<&str> = actuel.split_once('\n').map_or("", |(_, r)| r).split('|').collect();
    let ipv6 = !matches!(
        nm_valeur(&connexion, "ipv6.method").as_deref(),
        None | Some("disabled" | "ignore")
    );
    let (dns6, ignore6) = if ipv6 && !v6.is_empty() {
        (v6.join(","), "yes".to_string())
    } else {
        (
            c.get(2).copied().unwrap_or_default().to_string(),
            c.get(3).copied().unwrap_or("no").to_string(),
        )
    };
    Ok(Changement::Dns {
        connexion,
        cible: Some(format!("{}|yes|{dns6}|{ignore6}", v4.join(","))),
    })
}

/// Le mode de démarrage d'un service s'accorde-t-il avec sa marche ? Seulement alors « enable/disable --now »
/// ramène l'état d'avant tout entier.
fn releve_fidele(etat: &str, actif: bool) -> bool {
    match etat {
        "enabled" => actif,
        "disabled" | "masked" => !actif,
        _ => true,
    }
}

fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    // Par son chemin dans les dossiers du système, jamais par le PATH du compte : un faux « systemctl » posé dans
    // ~/.local/bin rendrait une liste choisie (relecture 0.95, G-3).
    let r = crate::commande::lancer(crate::commande::par_le_systeme(cmd).args(args), 10)?;
    Some(r.sortie.trim().to_string())
}

impl Changement {
    /// La valeur d'avant que note une correction : pour une entrée d'autostart listée, celle lue alors (`vu`), d'où
    /// vient ce qui a été montré et ce qui sera écrit, jamais une seconde lecture qui verrait peut-être un autre
    /// contenu (campagne B, M-1) ; sinon `lire`.
    pub fn lire_pour_noter(&self) -> Valeur {
        if let Changement::Demarrage { vu: Some(v), .. } = self {
            return Some(v.clone());
        }
        self.lire()
    }

    pub fn lire(&self) -> Valeur {
        match self {
            // « is-enabled » répond aussi par son code de retour : seul le texte compte ici.
            Changement::Unite { nom, .. } => etat_unite_lu(nom, false),
            Changement::Fichier { chemin, contenu, .. } => {
                let t = std::fs::read_to_string(chemin).ok()?;
                Some(if t == *contenu { "present" } else { "autre" }.to_string())
            }
            // Lue dans dconf et les schémas compilés, au format de gsettings ; lui en secours.
            Changement::Gnome { schema, cle, .. } => crate::machine::linux::dconf::gsettings_get(schema, cle)
                .or_else(|| sortie("gsettings", &["get", schema, cle])),
            Changement::Option { fichier, cle, .. } => std::fs::read_to_string(fichier).ok()?.lines().find_map(|l| {
                l.trim()
                    .strip_prefix(cle)
                    .and_then(|r| r.strip_prefix('='))
                    .map(|v| v.trim().to_string())
            }),
            Changement::Dns { connexion, .. } => {
                let champ = |p| nm_valeur(connexion, p);
                Some(format!(
                    "{connexion}\n{}|{}|{}|{}",
                    liste_dns(&champ("ipv4.dns")?),
                    champ("ipv4.ignore-auto-dns")?,
                    liste_dns(&champ("ipv6.dns")?),
                    champ("ipv6.ignore-auto-dns")?
                ))
            }
            Changement::Demarrage { entree, .. } => match entree {
                // Une seule ouverture, sans suivre de lien ni attendre, jugée sur ce qui a été ouvert et bornée : un
                // tube nommé, /dev/zero ou un lien échangé entre le regard et la lecture ne figent ni ne gonflent la
                // note. Ses dossiers aussi s'ouvrent sans suivre de lien, depuis le dossier personnel
                // (`sous_maison`) : un ~/.config/autostart lien n'est pas lu. Le « + » de la note compte dans la
                // borne de son admission (`valeur_admise`).
                Entree::Autostart(p) => {
                    match sous_maison::lire(p, u64::try_from(AUTOSTART_MAX - 1).unwrap_or(0)) {
                        Ok(t) => Some(format!("+{t}")),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("-".to_string()),
                        // Illisible, pas un simple fichier, trop gros : ni présent ni absent, rien ne s'écrit d'après ça.
                        Err(_) => None,
                    }
                }
                Entree::Service(u) => etat_unite_lu(u, true),
            },
            Changement::Sysctl { .. }
            | Changement::Pose { .. }
            | Changement::Module { .. }
            | Changement::Droits { .. }
            | Changement::Ntp
            | Changement::Defense { .. } => self.relever().flatten(),
        }
    }

    /// La valeur d'avant, relevée avant une correction : `None` si elle ne se lit pas (droits, outil absent), ce
    /// qui n'est pas la même chose qu'une valeur absente (`Some(None)` : fichier, ligne, module qui n'existe pas).
    pub fn relever(&self) -> Option<Valeur> {
        match self {
            Changement::Sysctl { cle } => sysctl_lu(cle).map(Some),
            Changement::Pose { chemin, .. } => match std::fs::read_to_string(chemin) {
                Ok(t) => Some(Some(t)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
                Err(_) => None,
            },
            Changement::Module { nom } => Some(
                Path::new("/sys/module")
                    .join(nom)
                    .exists()
                    .then(|| "charge".to_string()),
            ),
            Changement::Droits { chemin } => super::annulables::droits_lus(chemin).map(Some),
            Changement::Ntp => ntp_lu().map(Some),
            // Illisible (le dossier d'une autre forme, fermé) : ni présente ni absente, rien n'est noté.
            Changement::Defense { id } => match std::fs::symlink_metadata(Path::new(DOSSIER_NOTES).join(id.as_str())) {
                Ok(_) => Some(Some(NOTE_PRESENTE.to_string())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(None),
                Err(_) => None,
            },
            // Remis par « enable/disable --now », qui lance ou arrête aussi le service ; relu, seul le mode de
            // démarrage compte. Activé mais arrêté (ou l'inverse), l'état d'avant ne reviendrait pas et la relecture
            // le dirait revenu : non noté, la correction est dite non annulable avant d'être appliquée.
            Changement::Unite { nom, .. } => etat_unite_lu(nom, false)
                .filter(|e| releve_fidele(e, sortie("systemctl", &["is-active", nom]).as_deref() == Some("active")))
                .map(Some),
            _ => Some(self.lire()),
        }
    }

    /// Le changement que désigne un geste noté (`annulables::Geste`), s'il vise une cible de la liste fermée :
    /// une note ne fait jamais écrire ailleurs.
    pub fn depuis_geste(geste: &str) -> Option<Changement> {
        let (genre, cible) = geste.split_once('|').unwrap_or((geste, ""));
        match genre {
            "unite" => UNITES.iter().find(|u| **u == cible).map(|nom| Changement::Unite {
                nom,
                cible: "?",
                defaut: "?",
            }),
            "sysctl" => cle_sysctl_connue(cible).then(|| Changement::Sysctl { cle: cible.to_string() }),
            "fichier" => POSES
                .iter()
                .find(|f| crate::passage::les_deux(f.chemin).iter().any(|n| n == cible))
                .map(|fichier| Changement::Pose {
                    chemin: cible.to_string(),
                    fichier,
                }),
            "module" => MODULES
                .iter()
                .find(|m| **m == cible)
                .map(|nom| Changement::Module { nom }),
            "droits" => super::annulables::dans_la_maison(Path::new(cible)).then(|| Changement::Droits {
                chemin: PathBuf::from(cible),
            }),
            "ntp" if cible.is_empty() => Some(Changement::Ntp),
            "defense" => IdNote::nouveau(cible).map(|id| Changement::Defense { id }),
            _ => None,
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Unite { cible, .. } | Changement::Gnome { cible, .. } | Changement::Option { cible, .. } => {
                (*cible).to_string()
            }
            Changement::Fichier { .. } => "present".to_string(),
            // Rebâti pour être annulé : une cible qu'aucune lecture ne donne.
            Changement::Dns { connexion, cible } => format!("{connexion}\n{}", cible.as_deref().unwrap_or("?")),
            Changement::Demarrage { cible, .. } => cible.clone().unwrap_or_else(|| "?".to_string()),
            // Rebâtis pour être annulés seulement : une cible qu'aucune lecture ne donne.
            Changement::Sysctl { .. }
            | Changement::Pose { .. }
            | Changement::Module { .. }
            | Changement::Droits { .. }
            | Changement::Ntp
            | Changement::Defense { .. } => "?".to_string(),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Unite { defaut, .. } | Changement::Gnome { defaut, .. } | Changement::Option { defaut, .. } => {
                Some((*defaut).to_string())
            }
            Changement::Fichier { .. } => None,
            // Les DNS donnés par la box, en IPv4 comme en IPv6.
            Changement::Dns { connexion, .. } => Some(format!("{connexion}\n|no||no")),
            // La forme où le programme se lance, sans rien effacer : le fichier sans sa ligne Hidden (absent reste
            // absent) ; « ? » si on ne sait pas le relire, qu'aucune écriture n'accepte.
            Changement::Demarrage { entree, .. } => Some(match entree {
                Entree::Autostart(_) => match self.lire() {
                    Some(v) => v.strip_prefix('+').map_or(v.clone(), |t| format!("+{}", demasquer(t))),
                    None => "?".to_string(),
                },
                Entree::Service(_) => "enabled".to_string(),
            }),
            // Pas de « système neuf » pour une correction : sans note admise, rien ne se remet (« ? » ne s'écrit pas).
            Changement::Sysctl { .. }
            | Changement::Pose { .. }
            | Changement::Module { .. }
            | Changement::Droits { .. }
            | Changement::Ntp
            | Changement::Defense { .. } => Some("?".to_string()),
        }
    }

    /// L'identité stable d'un réglage de démarrage (« autostart|chemin », « systemd|service »), notée dans
    /// l'historique.
    pub fn identite_demarrage(&self) -> Option<String> {
        let Changement::Demarrage { entree, .. } = self else {
            return None;
        };
        Some(match entree {
            Entree::Autostart(p) => format!("autostart|{}", p.display()),
            Entree::Service(u) => format!("systemd|{u}"),
        })
    }

    /// Le réglage de démarrage rebâti d'après son identité notée, pour l'annuler. La note ne doit viser qu'un fichier
    /// .desktop du dossier d'autostart du compte (celui que lit la liste), ou un service au nom valide.
    pub fn demarrage_depuis(identite: &str) -> Option<Changement> {
        // Les essais : un dossier « autostart » sous leur dossier jetable tient lieu de celui du compte, comme leur
        // dossier jetable tient lieu de dossier personnel (`sous_maison::depart`).
        #[cfg(test)]
        if let Some(c) = identite
            .strip_prefix("autostart|")
            .and_then(|r| Path::new(r).parent())
            .filter(|d| d.starts_with(crate::essais::temporaire()) && d.file_name() == Some("autostart".as_ref()))
            .and_then(|d| Self::demarrage_depuis_dans(identite, d))
        {
            return Some(c);
        }
        Self::demarrage_depuis_dans(identite, &config_du_compte().join("autostart"))
    }

    /// `demarrage_depuis`, `autostart` étant le dossier d'autostart du compte. L'identité doit être, au texte près,
    /// celle qu'aurait notée la liste pour ce nom (`autostart` suivi du nom du fichier) : un autre dossier nommé
    /// autostart sous le dossier personnel, un sous-dossier, « . » ou « .. » ne se rebâtissent pas (relecture 0.94,
    /// R-8 : une note ne vise que l'entrée qu'elle déclare).
    fn demarrage_depuis_dans(identite: &str, autostart: &Path) -> Option<Changement> {
        let (sorte, reste) = identite.split_once('|')?;
        let entree = match sorte {
            "autostart" => {
                let p = PathBuf::from(reste);
                let valide = p.is_absolute()
                    && p.extension().is_some_and(|e| e == "desktop")
                    && p.file_name()
                        .is_some_and(|n| autostart.join(n).as_os_str() == std::ffi::OsStr::new(reste));
                valide.then_some(Entree::Autostart(p))?
            }
            "systemd" => unite_valide(reste).then(|| Entree::Service(reste.to_string()))?,
            _ => return None,
        };
        Some(Changement::Demarrage {
            entree,
            cible: None,
            vu: None,
        })
    }

    /// L'entrée de démarrage visée se lit-elle aujourd'hui (présente et bornée, ou absente) ? Une entrée d'autostart
    /// trop grosse, pas en UTF-8, lien ou tube, non : rien ne se remet par-dessus, ni ne se propose de l'être
    /// (correction n° 2 de la 0.94, D-1). Un service, ou tout autre réglage : oui (rien n'y est écrasé).
    pub fn entree_lisible(&self) -> bool {
        match self {
            Changement::Demarrage {
                entree: Entree::Autostart(_),
                ..
            } => self.lire().is_some(),
            _ => true,
        }
    }

    /// Vanguard peut-il écrire l'entrée visée ? Une entrée d'autostart : jugée comme celles de la liste
    /// (`ecriture_refusee`), le dossier et le remède dans la raison. Un service : oui (systemctl l'écrit). Sert aux
    /// lignes rebâties d'après une note (relecture 0.95, J-3).
    pub fn ecriture(&self) -> Ecriture {
        match self {
            Changement::Demarrage {
                entree: Entree::Autostart(chemin),
                ..
            } => ecriture_refusee(chemin),
            _ => Ecriture::Permise,
        }
    }

    /// Ce que le retrait écrirait se relira-t-il, borné comme la note ? Faux seulement pour une entrée d'autostart
    /// dont la copie masquée dépasserait la borne (D-2) : rien n'est alors retiré.
    pub fn cible_relisible(&self) -> bool {
        match self {
            Changement::Demarrage {
                entree: Entree::Autostart(_),
                cible,
                ..
            } => relisible(cible.as_deref()),
            _ => true,
        }
    }

    /// Le nom d'un programme d'après l'identité notée : le fichier ou le service, sans extension.
    pub fn nom_demarrage(identite: &str) -> String {
        let reste = identite.split_once('|').map_or(identite, |(_, r)| r);
        let p = Path::new(reste);
        // Une entrée d'autostart : le nom qu'affiche son fichier, celui du compte ou celui du système au même nom. Lus
        // bornés, sans attendre un tube, et celui du compte sans suivre de lien (campagne 0.94, C-1) : un fichier
        // échangé après le retrait ne fige ni ne gonfle la liste.
        if identite.starts_with("autostart|")
            && let Some(fichier) = p.file_name()
        {
            let max = u64::try_from(AUTOSTART_MAX - 1).unwrap_or(0);
            let nom = sous_maison::lire(p, max)
                .ok()
                .and_then(|t| champ(&t, "Name").map(str::to_string))
                .or_else(|| {
                    dossiers_systeme()
                        .into_iter()
                        .find_map(|d| champ(&lire_du_systeme(&d.join(fichier), max).ok()?, "Name").map(str::to_string))
                });
            if let Some(nom) = nom {
                return nom;
            }
        }
        p.file_stem()
            .map_or_else(|| reste.to_string(), |n| n.to_string_lossy().into_owned())
    }

    /// Remettre la valeur notée `v` sur l'entrée d'autostart d'aujourd'hui ne perd rien : elle est absente, déjà `v`,
    /// ou encore exactement ce que le retrait a écrit (la copie masquée de `v`). Pour une entrée du système notée
    /// absente du compte (`v` = « - »), le retrait a écrit la copie masquée de celle du système, qui a pu changer
    /// depuis (mise à jour) : il suffit que l'entrée du compte soit encore masquée. Faux pour tout autre contenu, et
    /// pour une entrée qui ne se lit pas.
    fn remise_sans_perte(&self, v: Option<&str>) -> bool {
        let Changement::Demarrage {
            entree: Entree::Autostart(_),
            ..
        } = self
        else {
            return true;
        };
        let Some(aujourd_hui) = self.lire() else {
            return false;
        };
        if aujourd_hui == "-" || Some(aujourd_hui.as_str()) == v {
            return true;
        }
        let Some(ecrit) = aujourd_hui.strip_prefix('+') else {
            return false;
        };
        match v.map(|v| (v, v.strip_prefix('+'))) {
            Some((_, Some(avant))) => ecrit == masquer(avant),
            Some(("-", None)) => masquer(ecrit) == ecrit,
            _ => false,
        }
    }

    /// Écrit ce qui est propre au compte sans passer par une commande : le fichier d'autostart, son contenu entier
    /// remis à l'octet près, ou retiré ; les droits d'un fichier du compte, posés par fchmod sur le fichier ouvert
    /// sans suivre de lien (`droits::poser`), jamais par `chmod` du shell. `None` : ce changement passe par une
    /// commande.
    pub(crate) fn ecrire_ici(&self, v: Option<&str>) -> Option<bool> {
        if let Changement::Droits { chemin } = self {
            let mode = v
                .filter(|v| super::annulables::droits_admis(v))
                .and_then(|v| u32::from_str_radix(v, 8).ok());
            return Some(match mode {
                Some(m) => match super::droits::poser(chemin, m) {
                    Ok(_) => true,
                    Err(e) => {
                        println!("    ✖ {e}");
                        false
                    }
                },
                None => false,
            });
        }
        let Changement::Demarrage {
            entree: Entree::Autostart(p),
            cible,
            vu,
        } = self
        else {
            return None;
        };
        // Un retrait sans valeur d'avant lue : la note serait vide, rien ne le défairait (campagne 0.94, C-3). Seule
        // une annulation (rebâtie d'une note, sans cible) écrit sans valeur vue.
        if cible.is_some() && vu.is_none() {
            refuser_ici(tr!(
                "valeur d'avant pas lue : rien n'est écrit",
                "previous value not read: nothing is written"
            ));
            return Some(false);
        }
        // Remise d'après une note (sans cible ni valeur vue) : l'entrée d'aujourd'hui doit se lire bornée, présente
        // ou absente. Trop grosse, pas en UTF-8, un lien ou un tube, elle se lance peut-être (la liste ne la montre
        // pas) : ni le contenu noté ni un retrait ne passent par-dessus (correction n° 2 de la 0.94, D-1).
        if cible.is_none() && vu.is_none() && self.lire().is_none() {
            refuser_ici(tr!(
                "entrée pas lue : rien n'est remis par-dessus",
                "entry not read: nothing is put back over it"
            ));
            return Some(false);
        }
        // Une remise (ce qui s'écrit n'est pas la cible du changement), qu'elle vienne d'une note (`--remettre`, « Tout
        // remettre ») ou de la liste à cocher refaite (cible et valeur vue posées) : l'entrée d'aujourd'hui doit être
        // absente, déjà remise, ou encore celle que le retrait a écrite. Réécrite depuis (même masquée, donc pas
        // lancée), son contenu serait écrasé et gardé nulle part (relecture 0.94, m-1 ; relecture 0.95, G-2).
        if cible.as_deref() != v && !self.remise_sans_perte(v) {
            refuser_ici(tr!(
                "l'entrée a été réécrite depuis que Vanguard l'a retirée : rien n'est remis par-dessus",
                "the entry was rewritten since Vanguard removed it: nothing is put back over it"
            ));
            return Some(false);
        }
        // Listée, l'entrée doit être encore celle lue alors : échangée depuis, ce qui s'écrirait viendrait de l'ancien
        // contenu et la note ne dirait pas ce qui a été montré (campagne B, M-1).
        if let Some(vu) = vu
            && self.lire().as_deref() != Some(vu.as_str())
        {
            refuser_ici(tr!(
                "l'entrée a changé depuis qu'elle a été montrée : rien n'est écrit",
                "the entry changed since it was shown: nothing is written"
            ));
            return Some(false);
        }
        // Ce qui s'écrit doit se relire, borné comme la note : sinon ni le retrait ne se constaterait, ni l'entrée ne
        // se remettrait (D-1 la dirait pas lue). Masquer ajoute « Hidden=true » : une entrée lue de justesse peut
        // dépasser la borne une fois masquée (correction n° 2 de la 0.94, D-2).
        if !relisible(v) {
            refuser_ici(tr!(
                "l'entrée masquée dépasserait 64 Kio et ne se relirait plus : rien n'est écrit",
                "the hidden entry would exceed 64 KiB and could no longer be read back: nothing is written"
            ));
            return Some(false);
        }
        // Sous le dossier personnel, sans suivre de lien à aucun élément du chemin (`sous_maison`) : un dossier
        // d'autostart lien vers ailleurs n'est ni suivi ni écrit, comme les droits (`droits::poser`).
        let r = match v.map(|t| (t, t.strip_prefix('+'))) {
            Some((_, Some(contenu))) => sous_maison::ecrire(p, contenu.as_bytes()),
            Some(("-", None)) => sous_maison::retirer(p),
            _ => {
                refuser_ici(tr!(
                    "valeur notée pas reconnue : rien n'est écrit",
                    "noted value not recognized: nothing is written"
                ));
                return Some(false);
            }
        };
        Some(match r {
            Ok(()) => true,
            Err(e) => {
                refuser_ici(&e.to_string());
                false
            }
        })
    }

    /// La valeur notée `v` a-t-elle une forme que ce changement peut écrire ? Elle est remise avec sudo (ou dans le
    /// compte) : un ensemble fermé, ou une forme stricte, jamais un texte libre venu d'un fichier que tout programme
    /// du compte peut réécrire.
    pub fn valeur_admise(&self, v: Option<&str>) -> bool {
        let Some(v) = v else {
            // Absente (ligne, préférence, fichier, module) : se remet en retirant, rien d'autre. Une entrée
            // d'autostart absente se note « - » : une note vide ne vient pas de Vanguard (campagne 0.94, C-3).
            return !matches!(
                self,
                Changement::Dns { .. }
                    | Changement::Sysctl { .. }
                    | Changement::Droits { .. }
                    | Changement::Ntp
                    | Changement::Demarrage {
                        entree: Entree::Autostart(_),
                        ..
                    }
            );
        };
        match self {
            // Ni un état que l'assistant refuse (un pare-feu ou une protection masqués, que rien ne pourrait plus
            // lancer ; un pare-feu désactivé) : la note est refusée entière.
            Changement::Unite { nom, .. } => {
                ETATS_UNITE.contains(&v) && crate::machine::gestes_unix::geste_d_unite(nom, v).is_ok()
            }
            Changement::Fichier { .. } => matches!(v, "present" | "autre"),
            Changement::Gnome { cible, defaut, .. } => v == *cible || v == *defaut || super::gvariant_simple(v),
            Changement::Option { cible, defaut, .. } => v == *cible || v == *defaut || super::jeton_simple(v),
            Changement::Dns { connexion, .. } => dns_admis(connexion, v),
            Changement::Demarrage { entree, .. } => match entree {
                // Le fichier d'autostart du compte, remis à l'octet près : il s'écrit sans droits, dans le compte.
                Entree::Autostart(_) => {
                    v == "-" || (v.starts_with('+') && v.len() <= AUTOSTART_MAX && !v.contains('\0'))
                }

                Entree::Service(_) => ETATS_UNITE.contains(&v),
            },
            // Remise en root par `sysctl -w` : le même plancher que dans les fichiers posés (`contenu_admis`). Une
            // clé du durcissement ne revient jamais sous sa valeur sûre : « ptrace_scope = 0 » ou l'ASLR coupée
            // viendraient d'une note forgée, jamais de Vanguard, qui ne défait pas cette protection.
            Changement::Sysctl { cle } => {
                v.len() <= 64
                    && !v.is_empty()
                    && v.chars().all(|c| c.is_ascii_digit() || " -".contains(c))
                    && ligne_sysctl_posee(cle, v.trim())
            }
            Changement::Pose { fichier, .. } => contenu_admis(fichier.forme, v),
            Changement::Module { .. } => v == "charge",
            Changement::Droits { .. } => super::annulables::droits_admis(v),
            Changement::Ntp => matches!(v, "yes" | "no"),
            // Une note déjà là avant le geste : l'enfant refuse alors de le faire, rien ne se note.
            Changement::Defense { .. } => false,
        }
    }

    /// La commande qui pose la valeur `v` d'un réglage de DNS (mode Wi-Fi public).
    pub fn commande_dns(&self, v: &str) -> Option<String> {
        matches!(self, Changement::Dns { .. })
            .then(|| self.commande(Some(v)))
            .flatten()
    }

    /// Pourquoi la valeur `v` n'est jamais écrite : un geste que l'assistant refuse (`gestes_unix::geste_d_unite`).
    /// Dit à la personne, et le réglage compte comme pas fait, plutôt que de passer en silence.
    pub(super) fn refus(&self, v: Option<&str>) -> Option<(&'static str, &'static str)> {
        match (self, v) {
            (Changement::Unite { nom, .. }, Some(v)) => crate::machine::gestes_unix::geste_d_unite(nom, v).err(),
            _ => None,
        }
    }

    /// La connexion d'un réglage de DNS.
    pub fn identite_dns(&self) -> Option<&str> {
        match self {
            Changement::Dns { connexion, .. } => Some(connexion),
            _ => None,
        }
    }

    /// Le réglage de DNS rebâti d'après sa valeur d'avant notée, pour l'annuler.
    pub fn dns_note(avant: &str) -> Option<Changement> {
        let (connexion, _) = avant.split_once('\n')?;
        uuid_valide(connexion).then(|| Changement::Dns {
            connexion: connexion.to_string(),
            cible: None,
        })
    }

    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Unite { nom, .. } => format!("systemctl {} {nom}", v.map_or("?", etat_unite)),
            Changement::Fichier { chemin, .. } => match v {
                Some(_) => trf!("{chemin} : posé", "{chemin}: written"),
                None => trf!("{chemin} : retiré", "{chemin}: removed"),
            },
            Changement::Gnome { schema, cle, .. } => match v {
                Some(v) => format!("gsettings set {schema} {cle} {v}"),
                None => format!("gsettings reset {schema} {cle}"),
            },
            Changement::Option { fichier, cle, .. } => match v {
                Some(v) => format!("{fichier} : {cle}={v}"),
                None => trf!("{fichier} : ligne {cle} retirée", "{fichier}: line {cle} removed"),
            },
            Changement::Dns { .. } => decrire_dns(v),
            Changement::Demarrage { entree, .. } => match entree {
                Entree::Autostart(p) => {
                    let f = court(p);
                    match v.and_then(|v| v.strip_prefix('+')) {
                        Some(t) if champ(t, "Hidden").is_some_and(|h| h.eq_ignore_ascii_case("true")) => {
                            trf!(
                                "{f} : Hidden=true, ne se lance plus",
                                "{f}: Hidden=true, no longer starts"
                            )
                        }
                        // Relecture 0.95, G-2 : ce qui revient est le contenu noté, pas l'entrée d'aujourd'hui ; son
                        // nom et sa commande sont montrés avant d'être écrits.
                        Some(t) => trf!(
                            "{f} : remis comme avant ({})",
                            "{f}: put back as before ({})",
                            resume_entree(t)
                        ),
                        None => trf!(
                            "{f} : retiré, l'entrée du système revient",
                            "{f}: removed, the system entry comes back"
                        ),
                    }
                }
                Entree::Service(u) => format!(
                    "systemctl --user {} {u}",
                    match v {
                        Some("disabled") => "disable",
                        Some("enabled") => "enable",
                        _ => "?",
                    }
                ),
            },
            Changement::Sysctl { cle } => format!("sysctl {} = {}", cle.replace('/', "."), v.unwrap_or("?")),
            // Le contenu est montré avant d'être écrit en root : « remis comme avant » seul cacherait ce qui revient.
            Changement::Pose { chemin, .. } => match v {
                Some(t) => {
                    let lignes: Vec<&str> = t
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect();
                    if lignes.is_empty() {
                        trf!(
                            "{chemin} : remis comme avant (vide)",
                            "{chemin}: put back as before (empty)"
                        )
                    } else {
                        trf!(
                            "{chemin} : remis comme avant ({})",
                            "{chemin}: put back as before ({})",
                            lignes.join(" ; ")
                        )
                    }
                }
                None => trf!("{chemin} : retiré", "{chemin}: removed"),
            },
            Changement::Module { nom } => match v {
                Some(_) => format!("modprobe {nom}"),
                None => format!("modprobe -r {nom}"),
            },
            Changement::Droits { chemin } => format!("chmod {} {}", v.unwrap_or("?"), court(chemin)),
            Changement::Ntp => format!(
                "timedatectl set-ntp {}",
                if v == Some("yes") { "true" } else { "false" }
            ),
            Changement::Defense { id } => {
                let id = id.as_str();
                match v {
                    None => trf!(
                        "geste de défense {id} défait par Vanguard (administrateur), sa note retirée",
                        "defense step {id} undone by Vanguard (administrator), its note removed"
                    ),
                    Some(_) => trf!(
                        "geste de défense {id} fait, sa note gardée par root",
                        "defense step {id} done, its note kept by root"
                    ),
                }
            }
        }
    }

    /// La commande qui met la valeur `v`.
    pub(super) fn commande(&self, v: Option<&str>) -> Option<String> {
        Some(match self {
            Changement::Unite { nom, .. } => match v? {
                // Une unité de la table de l'assistant (fstrim, cups-browsed, auditd), activée ou désactivée : son
                // geste, par le bus système, rejugé par l'assistant élevé (lot U3). Un geste refusé (`refus`) reste
                // refusé : jamais de commande sudo à sa place. Les autres (apport, avec son fichier, et « masked »
                // d'une unité ordinaire) restent des commandes jusqu'à U4.
                e @ ("enabled" | "disabled" | "masked") => match crate::machine::gestes_unix::geste_d_unite(nom, e) {
                    Ok(Some(g)) => g.ligne(),
                    Ok(None) => format!("sudo systemctl {} --now {nom}", etat_unite(e)),
                    Err(_) => return None,
                },
                // « static », « indirect » : pas un état qu'on choisit, rien à remettre.
                _ => return None,
            },
            Changement::Fichier { chemin, contenu, apres } => match v {
                Some(_) => {
                    let dossier = Path::new(chemin).parent()?.display().to_string();
                    format!(
                        "sudo mkdir -p {} && printf '%s' {} | sudo tee {} >/dev/null && {apres}",
                        sh_chaine(&dossier),
                        sh_chaine(contenu),
                        sh_chaine(chemin)
                    )
                }
                None => format!("sudo rm -f {} && {apres}", sh_chaine(chemin)),
            },
            Changement::Gnome { schema, cle, .. } => match v {
                Some(v) => format!("gsettings set {schema} {cle} {}", sh_chaine(v)),
                None => format!("gsettings reset {schema} {cle}"),
            },
            Changement::Option { fichier, cle, .. } => {
                let f = sh_chaine(fichier);
                match v {
                    // La ligne est remplacée si elle existe, ajoutée sinon. Dans le remplacement de sed, « \ », « | »
                    // et « & » sont protégés : une valeur d'avant remise doit l'être telle quelle.
                    // Ce remplacement est déjà entre apostrophes dans le script de sed : sh_chaine ne s'y applique
                    // pas, l'apostrophe y est échappée à la main.
                    Some(v) => format!(
                        "if grep -q '^{cle}=' {f}; then sudo sed -i 's|^{cle}=.*|{cle}={}|' {f}; else echo {} | sudo tee -a {f} >/dev/null; fi",
                        v.replace('\\', r"\\")
                            .replace('|', r"\|")
                            .replace('&', r"\&")
                            .replace('\'', r"'\''"),
                        sh_chaine(&format!("{cle}={v}")),
                    ),
                    // Absente avant le changement : la ligne est retirée.
                    None => format!("sudo sed -i '/^{cle}=/d' {f}"),
                }
            }
            Changement::Dns { connexion, .. } => {
                let (id, reste) = v?.split_once('\n')?;
                if id != connexion || !uuid_valide(connexion) {
                    return None;
                }
                let [dns4, ignore4, dns6, ignore6] = reste.split('|').collect::<Vec<_>>()[..] else {
                    return None;
                };
                let oui_non = |t: &str| if t == "yes" { "yes" } else { "no" };
                // Appliqué tout de suite à la carte active (reapply ne coupe pas la connexion) ; une connexion inactive
                // le prendra à son prochain branchement.
                format!(
                    "sudo nmcli connection modify {connexion} ipv4.dns {} ipv4.ignore-auto-dns {} ipv6.dns {} \
                     ipv6.ignore-auto-dns {} && carte=$(nmcli -t -f UUID,DEVICE connection show --active | grep -m1 \
                     '^{connexion}:' | cut -d: -f2) && {{ [ -z \"$carte\" ] || sudo nmcli device reapply \"$carte\"; }}",
                    sh_chaine(&dns4.replace(',', " ")),
                    oui_non(ignore4),
                    sh_chaine(&dns6.replace(',', " ")),
                    oui_non(ignore6)
                )
            }
            Changement::Demarrage { entree, .. } => match entree {
                // Écrit par Vanguard lui-même (`ecrire_ici`).
                Entree::Autostart(_) => return None,
                // Sans « --now » : le service tourne jusqu'à la fin de la session, il ne repart simplement plus.
                Entree::Service(u) => match v? {
                    "enabled" if unite_valide(u) => format!("systemctl --user enable {}", sh_chaine(u)),
                    "disabled" if unite_valide(u) => format!("systemctl --user disable {}", sh_chaine(u)),
                    _ => return None,
                },
            },
            // Chaque valeur repasse par `valeur_admise` avant d'entrer dans une commande : « ? » (aucune note) n'en
            // donne aucune.
            Changement::Sysctl { cle } => {
                let v = v.filter(|v| self.valeur_admise(Some(v)))?;
                format!("sudo sysctl -w {} >/dev/null", sh_chaine(&format!("{cle}={v}")))
            }
            Changement::Pose { chemin, fichier } => {
                if !self.valeur_admise(v) {
                    return None;
                }
                let suite = if fichier.apres.is_empty() {
                    String::new()
                } else {
                    format!(" && {}", fichier.apres)
                };
                match v {
                    Some(t) => format!(
                        "printf '%s' {} | sudo tee {} >/dev/null{suite}",
                        sh_chaine(t),
                        sh_chaine(chemin)
                    ),
                    None => format!("sudo rm -f {}{suite}", sh_chaine(chemin)),
                }
            }
            Changement::Module { nom } => match v {
                Some("charge") => format!("sudo modprobe {nom}"),
                None => format!("sudo modprobe -r {nom}"),
                Some(_) => return None,
            },
            // Posés par Vanguard lui-même (`ecrire_ici`), sans shell : `chmod` suivrait un lien posé sur le chemin.
            Changement::Droits { .. } => return None,
            Changement::Ntp => match v? {
                "yes" => "sudo timedatectl set-ntp true".to_string(),
                "no" => "sudo timedatectl set-ntp false".to_string(),
                _ => return None,
            },
            // Le geste de l'assistant, par sa ligne : jamais une commande sudo, qui écrirait sans rejuger.
            Changement::Defense { id } => match v {
                None => GesteUnix::Defense(Defense::Remettre, *id).ligne(),
                Some(_) => return None,
            },
        })
    }

    /// Demande sudo, et un point de restauration avant (tout sauf ce qui est propre au compte).
    fn admin(&self) -> bool {
        !matches!(
            self,
            Changement::Gnome { .. } | Changement::Demarrage { .. } | Changement::Droits { .. }
        )
    }
}

/// Ce que `systemctl is-enabled` peut répondre : rien d'autre ne se note pour une unité.
const ETATS_UNITE: [&str; 14] = [
    "enabled",
    "enabled-runtime",
    "linked",
    "linked-runtime",
    "alias",
    "masked",
    "masked-runtime",
    "static",
    "indirect",
    "disabled",
    "generated",
    "transient",
    "bad",
    "not-found",
];

/// Une valeur de DNS notée : « uuid\ndns4|oui-non|dns6|oui-non », pour cette connexion, des adresses IP seulement.
fn dns_admis(connexion: &str, v: &str) -> bool {
    let Some((id, reste)) = v.split_once('\n') else {
        return false;
    };
    let [dns4, ignore4, dns6, ignore6] = reste.split('|').collect::<Vec<_>>()[..] else {
        return false;
    };
    id == connexion
        && uuid_valide(id)
        && super::adresses_ip(dns4)
        && super::adresses_ip(dns6)
        && [ignore4, ignore6].iter().all(|o| matches!(*o, "yes" | "no" | ""))
}

fn etat_unite(v: &str) -> &str {
    match v {
        "enabled" => "enable",
        "disabled" => "disable",
        "masked" => "mask",
        autre => autre,
    }
}

/// Applique des lots de changements (un lot par réglage), point de restauration d'abord si le système est touché ;
/// `en_plus`, des commandes d'autres annulations lancées dans le même passage. Rend la réussite de chaque lot, puis
/// de chaque groupe en plus.
pub fn ecrire_avec(lots: &[Vec<(&Changement, Valeur)>], en_plus: &[Vec<String>]) -> (Vec<bool>, Vec<bool>) {
    if (!en_plus.is_empty() || lots.iter().flatten().any(|(c, _)| c.admin()))
        && let Some((outil, point)) = crate::reparer::point_restauration(tr!("réglages", "settings"))
    {
        trp!(
            "    {GRIS}Point de restauration d'abord ({outil}).{RESET}",
            "    {GRIS}Restore point first ({outil}).{RESET}"
        );
        if !crate::machine::appliquer(&[point])
            && !demander(tr!(
                "    ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
                "    ✖ Restore point not possible. Continue anyway? [y/N]: "
            ))
            .oui()
        {
            return (vec![false; lots.len()], vec![false; en_plus.len()]);
        }
    }
    // Un réglage dont un changement est refusé n'est pas fait du tout, et le refus est dit : jamais à moitié, jamais
    // en silence.
    let refuses: Vec<bool> = lots
        .iter()
        .map(|lot| {
            let mut refuse = false;
            for (c, v) in lot {
                if let Some((fr, en)) = c.refus(v.as_deref()) {
                    let raison = if crate::langue::anglais() { en } else { fr };
                    trp!("    ✖ {} : {raison}", "    ✖ {}: {raison}", c.decrire(v.as_deref()));
                    DERNIER_REFUS.with_borrow_mut(|d| *d = Some(raison.to_string()));
                    refuse = true;
                }
            }
            refuse
        })
        .collect();
    let mut commandes: Vec<Vec<String>> = lots
        .iter()
        .zip(&refuses)
        .map(|(lot, refuse)| {
            if *refuse {
                return Vec::new();
            }
            lot.iter().filter_map(|(c, v)| c.commande(v.as_deref())).collect()
        })
        .collect();
    commandes.extend(en_plus.iter().cloned());
    // Une note qui remet une unité (un geste de l'assistant) et autre chose (des commandes) : chaque moitié par son
    // chemin, jamais mêlées dans une liste, que l'assistant refuserait.
    // Une moitié faite seulement compte comme un échec : la note n'est pas défaite, elle reste à refaire.
    let mut resultats: Vec<bool> = crate::machine::appliquer_gestes_puis_commandes(&commandes)
        .into_iter()
        .map(|i| i == crate::machine::IssueMelee::Fait)
        .collect();
    let plus = resultats.split_off(lots.len().min(resultats.len()));
    for (ok, refuse) in resultats.iter_mut().zip(&refuses) {
        *ok &= !refuse;
    }
    // Ce qui est propre au compte et s'écrit sans commande (fichiers d'autostart), montré comme une commande.
    for ((lot, ok), refuse) in lots.iter().zip(resultats.iter_mut()).zip(&refuses) {
        if *refuse {
            continue;
        }
        for (c, v) in lot {
            if let Some(ecrit) = c.ecrire_ici(v.as_deref()) {
                // Refusé ou en échec (la raison est déjà dite sur sa ligne ✖), rien n'est écrit : jamais « remis comme
                // avant » sous un refus (relecture 0.95, G-4).
                if ecrit {
                    println!("    {GRIS}{}{RESET}", c.decrire(v.as_deref()));
                } else if let Changement::Demarrage {
                    entree: Entree::Autostart(p),
                    ..
                } = c
                {
                    let f = court(p);
                    trp!(
                        "    {GRIS}{f} : rien n'est écrit{RESET}",
                        "    {GRIS}{f}: nothing is written{RESET}"
                    );
                }
                *ok &= ecrit;
            }
        }
    }
    (resultats, plus)
}

/// Les programmes lancés à l'ouverture de session de ce compte : entrées d'autostart (celles du compte, et celles
/// du système qu'il ne remplace pas et qui se lancent sur ce bureau) et services de systemd --user installés par la
/// personne.
pub fn au_demarrage() -> Vec<Programme> {
    releve_demarrage().0
}

/// `au_demarrage`, avec ce qui n'a pas pu être lu : un dossier d'autostart qui existe mais ne se liste pas ou que la
/// garde refuse, une entrée lien, tube ou trop grosse, les services du compte quand systemctl --user ne répond pas
/// (pas de session systemd). La liste à cocher du terminal les dit sous son titre, jamais « aucun programme » ;
/// `demarrage --json` ne compte pas une liste incomplète comme lue. Le troisième membre : au moins une source
/// (dossier d'autostart du compte ou du système, services du compte) a été lue, même vide ; faux, rien ne l'a été, et
/// `demarrage --json` ne compte aucune vérification (relecture 0.94, R-9).
pub fn releve_demarrage() -> (Vec<Programme>, Vec<String>, bool) {
    let maison = crate::socle::maison();
    let config = config_du_compte();
    let bureau = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    // systemctl par son chemin dans les dossiers du système, jamais par le PATH du compte (relecture 0.95, G-3) :
    // introuvable là, il ne se lance pas, les services ne sont pas lus, et c'est dit.
    let activees = crate::commande::lancer(
        crate::commande::par_le_systeme("systemctl").args([
            "--user",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ]),
        10,
    );
    // L'ordre où systemd lit les unités du compte, celui du bilan des persistances : une unité d'un dossier du
    // compte qui passe avant le système (~/.local/share/systemd/user, /run/user/…) remplace celle du système.
    let ordre = crate::machine::linux::dossiers_d_unites_du_compte(&maison, |v| std::env::var_os(v));
    let unites: Vec<PathBuf> = UNITES_DU_SYSTEME.iter().map(PathBuf::from).collect();
    let (systeme, phrase) = dossiers_autostart_du_systeme();
    let (programmes, mut manques, lu) = releve_selon(
        &config,
        &systeme,
        &bureau,
        activees.as_ref().and_then(services_actives),
        ordre,
        &unites,
    );
    manques.extend(phrase);
    (programmes, manques, lu)
}

/// Le dossier de configuration du compte (`XDG_CONFIG_HOME`, sinon ~/.config) : celui où `vanguard demarrage` lit
/// les entrées d'autostart du compte, le seul où une note en remet une.
fn config_du_compte() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| crate::socle::maison().join(".config"), PathBuf::from)
}

/// Les dossiers de compléments de l'unité `nom` (`complements_d_unite`), dans l'ordre où systemd les prend pour un
/// même dossier d'unités : le sien (« nom.service.d ») d'abord, puis du plus long au plus court (préfixes
/// « a-b-.service.d », « a-.service.d », gabarit, enfin « service.d ») : à nom de fichier égal, le plus précis passe.
fn dossiers_de_complements(nom: &str) -> Vec<String> {
    let mut l = crate::machine::linux::complements_d_unite(nom);
    let propre = format!("{nom}.d");
    l.sort_by_key(|c| (*c != propre, std::cmp::Reverse(c.len())));
    l
}

/// Au plus tant de compléments lus pour une unité : au-delà, rien n'est conclu.
const COMPLEMENTS_MAX: usize = 256;

/// Les compléments (« *.conf ») que systemd applique à l'unité connue sous `noms` (son nom et ses alias,
/// `noms_d_unite`), cherchés dans `dossiers` du plus prioritaire au moins : un même nom de fichier ne se prend qu'une
/// fois, au dossier qui passe devant (il masque les autres) ; puis rangés par nom de fichier, l'ordre où systemd les
/// applique, chacun avec son texte (un lien vers /dev/null masque : vide). `Err` : le premier dossier de compléments
/// ou complément qui ne se lit pas borné (`lire_du_systeme` : 64 Kio, UTF-8, sans attendre un tube), ou plus de
/// `COMPLEMENTS_MAX` ; rien n'est conclu, jamais « aucun complément ».
fn complements_lus(dossiers: &[PathBuf], noms: &[String]) -> Result<Vec<(PathBuf, String)>, PathBuf> {
    let mut pris: Vec<(std::ffi::OsString, PathBuf)> = Vec::new();
    for d in dossiers {
        for nom in noms {
            for c in dossiers_de_complements(nom) {
                let c = d.join(c);
                let entrees = match std::fs::read_dir(&c) {
                    Ok(e) => e,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(_) => return Err(c),
                };
                for e in entrees {
                    let e = e.map_err(|_| c.clone())?;
                    let f = e.file_name();
                    if Path::new(&f).extension().is_none_or(|x| x != "conf") || pris.iter().any(|(n, _)| *n == f) {
                        continue;
                    }
                    if pris.len() >= COMPLEMENTS_MAX {
                        return Err(c);
                    }
                    pris.push((f, e.path()));
                }
            }
        }
    }
    pris.sort_by(|a, b| a.0.cmp(&b.0));
    let max = u64::try_from(AUTOSTART_MAX - 1).unwrap_or(0);
    pris.into_iter()
        .map(|(_, p)| {
            if std::fs::read_link(&p).is_ok_and(|v| v == Path::new("/dev/null")) {
                return Ok((p, String::new()));
            }
            match lire_du_systeme(&p, max) {
                Ok(t) => Ok((p, t)),
                Err(_) => Err(p),
            }
        })
        .collect()
}

/// La liste des services du compte activés que rend `systemctl --user list-unit-files`, ou `None` s'il n'a pas
/// répondu (pas de session systemd, bus fermé) : un manque, jamais une liste vide (T-5). systemctl sort en 1 sur une
/// liste vide ; seulement alors, sans rien écrire ni sur sa sortie ni sur ses erreurs, la liste est vide.
fn services_actives(r: &crate::commande::Resultat) -> Option<String> {
    match r.code {
        Some(0) => Some(r.sortie.trim().to_string()),
        Some(1) if r.sortie.trim().is_empty() && r.erreurs.trim().is_empty() => Some(String::new()),
        _ => None,
    }
}

/// Les dossiers d'unités du compte que fournit le système (paquets, administrateur), sous leurs chemins fixes. Pas
/// ceux de `XDG_CONFIG_DIRS` ni `XDG_DATA_DIRS` : ces variables peuvent pointer dans le dossier personnel (flatpak,
/// home-manager), et une unité qui s'y trouve est de la personne.
const UNITES_DU_SYSTEME: [&str; 8] = [
    "/etc/systemd/user",
    "/etc/xdg/systemd/user",
    "/run/systemd/user",
    "/usr/local/lib/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
    "/usr/local/share/systemd/user",
    "/usr/share/systemd/user",
];

/// `releve_demarrage` sur ces dossiers (essais) : `config`, le dossier de configuration du compte ; `activees`, la
/// réponse de systemctl (`services_actives`) ; les unités lues dans `config`/systemd/user puis les dossiers fixes du
/// système. Ce qui ne se lit pas, ou que la garde refuse (`sous_maison::juger` : lien, tube, autre compte, hors du
/// dossier personnel), est un manque dit, jamais une entrée tue (T-1, T-3).
#[cfg(test)]
pub(super) fn releve_dans(
    config: &Path,
    systeme: &[PathBuf],
    bureau: &str,
    activees: Option<String>,
) -> (Vec<Programme>, Vec<String>, bool) {
    let unites: Vec<PathBuf> = UNITES_DU_SYSTEME.iter().map(PathBuf::from).collect();
    let ordre = std::iter::once(config.join("systemd/user"))
        .chain(unites.iter().cloned())
        .collect();
    releve_selon(config, systeme, bureau, activees, Ok(ordre), &unites)
}

/// `releve_demarrage` : `ordre`, les dossiers d'unités du compte dans l'ordre où systemd les lit
/// (`dossiers_d_unites_du_compte`, ou pourquoi il ne se fait pas) ; `unites_systeme`, ceux que fournit le système
/// (`UNITES_DU_SYSTEME`). Systemd lance l'unité du premier dossier qui porte son nom : celle de
/// `config`/systemd/user se lit ; celle d'un dossier du système se tait, sauf si un dossier du compte la complète
/// (« nom.service.d ») ; toute autre (~/.local/share/systemd/user, /run/user/…, même devant une unité du système
/// au même nom), un nom introuvable ou un dossier qui ne se traverse pas : un manque dit, jamais un silence
/// (relecture 0.94, R-2, C-1).
fn releve_selon(
    config: &Path,
    systeme: &[PathBuf],
    bureau: &str,
    activees: Option<String>,
    ordre: Result<Vec<PathBuf>, crate::machine::temoins::Refus>,
    unites_systeme: &[PathBuf],
) -> (Vec<Programme>, Vec<String>, bool) {
    let mut manques = Vec::new();
    let compte = config.join("autostart");
    // Une source lue, même vide : quelque chose a été vérifié (relecture 0.94, R-9). Le dossier du compte que la garde
    // refuse (lien, autre compte, hors du dossier personnel) n'a rien donné à lire. Le dossier du compte absent est
    // vérifié (la garde a jugé ceux au-dessus : aucune entrée) ; un dossier du système absent n'a rien donné à lire
    // (XDG_CONFIG_DIRS peut nommer un dossier qui n'existe pas : relecture 0.95, G-3).
    let mut lu = false;
    for d in std::iter::once(compte.clone()).chain(systeme.iter().cloned()) {
        match std::fs::read_dir(&d) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => manques.push(trf!(
                "dossier de démarrage illisible ({}) : {}",
                "startup folder unreadable ({}): {}",
                e,
                court(&d)
            )),
            _ if d == compte => lu |= sous_maison::juger_le_dossier(&compte).is_ok(),
            Err(_) => {}
            Ok(_) => lu = true,
        }
    }
    let (mut l, pas_lues) = autostart(&compte, systeme, bureau);
    manques.extend(pas_lues);
    let dossier = config.join("systemd/user");
    let Some(activees) = activees else {
        manques.push(
            tr!(
                "services du compte (systemctl --user) pas lus",
                "account services (systemctl --user) not read"
            )
            .to_string(),
        );
        return (l, manques, lu);
    };
    // Sans la liste de systemd (dossier de la session inconnu), seul le dossier du compte se lit : tout autre service
    // est dit, et le manque aussi. Le dossier du compte y est toujours, à sa place ou devant.
    let mut ordre = ordre.unwrap_or_else(|raison| {
        manques.push(trf!(
            "services du compte pas tous vérifiés : {}",
            "account services not all checked: {}",
            raison.0
        ));
        Vec::new()
    });
    if !ordre.contains(&dossier) {
        ordre.insert(0, dossier.clone());
    }
    for unite in activees.lines().filter_map(|l| l.split_whitespace().next()) {
        let chemin = dossier.join(unite);
        // Le nom ne sort pas du dossier : systemd n'y met jamais de « / ».
        let porte = if unite.contains('/') {
            None
        } else {
            ordre
                .iter()
                .find_map(|d| match std::fs::symlink_metadata(d.join(unite)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                    lu => Some((d, lu.map(|_| ()))),
                })
        };
        match porte {
            Some((d, Ok(()))) if *d == dossier => {}
            // Porté d'abord par le système : un service activé pour chacun, que la personne n'a pas installé, sauf
            // si un dossier du compte le complète (ExecStart changé par « nom.service.d/x.conf »).
            // Ses compléments du compte se lisent et se jugent comme au bilan : dits seulement s'ils changent ce qu'il
            // lance (Exec…, variables, unités qu'il démarre) ou si l'un ne se lit pas (relecture 0.94, D).
            Some((d, Ok(()))) if unites_systeme.contains(d) => {
                let du_compte: Vec<PathBuf> = ordre.iter().filter(|d| !unites_systeme.contains(d)).cloned().collect();
                let lus = crate::machine::linux::noms_d_unite(&ordre, unite)
                    .map_or_else(|| Err(d.join(unite)), |noms| complements_lus(&du_compte, &noms));
                match lus {
                    Ok(lus) => {
                        let maison = crate::socle::maison();
                        for (c, texte) in &lus {
                            let cles = crate::machine::linux::complement_change_le_lancement(texte, &maison);
                            if !cles.is_empty() {
                                manques.push(trf!(
                                    "service du système {} changé par le compte ({} : {}) ; ce qu'il lance n'est ni montré ni proposé ici",
                                    "system service {} changed by the account ({}: {}); what it starts is neither shown nor offered here",
                                    crate::ui::affichable(unite),
                                    court(c),
                                    crate::ui::affichable(&cles.join(", "))
                                ));
                            }
                        }
                    }
                    Err(c) => manques.push(trf!(
                        "non vérifié : service du système complété par le compte ({}) ; ni lu ni proposé",
                        "not verified: system service completed by the account ({}); neither read nor offered",
                        court(&c)
                    )),
                }
                continue;
            }
            Some((d, Ok(()))) => {
                manques.push(trf!(
                    "non vérifié : service activé que systemd lit hors de {} ({}) ; ni lu ni proposé",
                    "not verified: enabled service that systemd reads outside {} ({}); neither read nor offered",
                    court(&dossier),
                    court(&d.join(unite))
                ));
                continue;
            }
            Some((_, Err(e))) => {
                manques.push(trf!(
                    "non vérifié : service du compte illisible ({}, {}) ; ni lu ni proposé",
                    "not verified: account service unreadable ({}, {}); neither read nor offered",
                    crate::ui::affichable(unite),
                    e
                ));
                continue;
            }
            None => {
                manques.push(trf!(
                    "non vérifié : service activé hors de {} ({}) ; ni lu ni proposé",
                    "not verified: enabled service outside {} ({}); neither read nor offered",
                    court(&dossier),
                    crate::ui::affichable(unite)
                ));
                continue;
            }
        }
        if !unite_valide(unite) {
            manques.push(trf!(
                "non vérifié : service du compte au nom que Vanguard ne lit pas ({}) ; pas proposé",
                "not verified: account service with a name Vanguard does not read ({}); not offered",
                crate::ui::affichable(unite)
            ));
            continue;
        }
        if let Err(e) = sous_maison::juger_lecture(&chemin) {
            manques.push(trf!(
                "non vérifié : {} ; ce service n'est ni lu ni proposé",
                "not verified: {}; this service is neither read nor offered",
                e
            ));
            continue;
        }
        // Relu d'une seule ouverture, sans suivre de lien ni attendre un tube, et borné (relecture 0.94, R-7) : une
        // unité qui ne se lit pas ainsi n'est pas proposée avec son nom pour commande, elle est dite. Une unité lien
        // vient d'un gestionnaire de configuration (dotfiles, `systemctl link`) : `systemctl disable` retirerait le
        // lien lui-même, rien ne s'annulerait exactement.
        let Ok(texte) = sous_maison::lire(&chemin, u64::try_from(UNITE_MAX).unwrap_or(0)) else {
            manques.push(trf!(
                "non vérifié : service du compte {} pas lu (plus de 64 Kio, pas en UTF-8, pas un simple fichier ou \
                 illisible) ; ni lu ni proposé",
                "not verified: account service {} not read (over 64 KiB, not UTF-8, not a plain file or \
                 unreadable); neither read nor offered",
                crate::ui::affichable(unite)
            ));
            continue;
        };
        // La commande que systemd lance : celle du fichier, changée par ses compléments (« nom.service.d/x.conf »,
        // ceux de ses alias, de tous les dossiers d'unités). Un complément qui ne se lit pas : la commande du fichier,
        // et le manque dit (relecture 0.94, D-4).
        let lus = crate::machine::linux::noms_d_unite(&ordre, unite)
            .map_or_else(|| Err(chemin.clone()), |noms| complements_lus(&ordre, &noms));
        let commandes = match &lus {
            Ok(lus) => {
                // Ce qu'un complément change d'autre que la commande (ExecStartPre=, conditions, variables) n'est pas
                // montré : le dire (relecture 0.95, V-8). Un complément masqué (/dev/null, vide) ne compte pas.
                let changent: Vec<String> = lus
                    .iter()
                    .filter(|(_, t)| !t.is_empty())
                    .map(|(c, _)| court(c))
                    .collect();
                if !changent.is_empty() {
                    manques.push(trf!(
                        "{} : commande montrée avec ses seules lignes ExecStart=, complétée par {} fichier(s) ({}) dont le reste (ExecStartPre=, conditions, variables) n'est pas montré",
                        "{}: command shown with its ExecStart= lines only, completed by {} file(s) ({}) whose other settings (ExecStartPre=, conditions, variables) are not shown",
                        crate::ui::affichable(unite),
                        changent.len(),
                        crate::ui::affichable(&changent.join(", "))
                    ));
                }
                crate::machine::linux::exec_start_effectif(
                    std::iter::once(texte.as_str()).chain(lus.iter().map(|(_, t)| t.as_str())),
                )
            }
            Err(c) => {
                manques.push(trf!(
                    "commande de {} peut-être autre que celle montrée : complément pas lu ({})",
                    "command of {} may differ from the one shown: drop-in not read ({})",
                    crate::ui::affichable(unite),
                    court(c)
                ));
                crate::machine::linux::exec_start_effectif([texte.as_str()])
            }
        };
        l.push(Programme {
            nom: unite.trim_end_matches(".service").to_string(),
            commande: if commandes.is_empty() {
                unite.to_string()
            } else {
                commandes.join(" ; ")
            },
            actif: true,
            machine: false,
            bureau: false,
            changement: Changement::Demarrage {
                entree: Entree::Service(unite.to_string()),
                cible: Some("disabled".to_string()),
                vu: None,
            },
            ecriture: ecriture_refusee(&chemin),
        });
    }
    (l, manques, true)
}

/// Les entrées d'autostart : chaque fichier .desktop du compte, puis celles du système au nom qu'il n'a pas et qui se
/// lancent sur ce bureau (une entrée pour un autre bureau, ou déjà masquée, n'a rien à retirer). Une entrée du compte
/// qui est un lien n'est pas proposée, ni celle du système qu'elle remplace ; ni aucune dont un dossier du chemin
/// est un lien ou sort du dossier personnel (`sous_maison::juger_lecture`) : la retirer écrirait à travers lui. Chacune est
/// dite non vérifiée (T-1, T-3), le dossier refusé une fois pour toutes ses entrées ; celles du système y restent
/// montrées sans être proposées, une entrée du dossier refusé pouvant les masquer (relecture 0.95, H-2). Rend aussi
/// les entrées du compte qui ne se lisent pas bornées (plus de 64 Kio, pas en UTF-8) : pas proposées, faute de valeur
/// d'avant à noter, mais dites (campagne 0.94, C-3).
fn autostart(compte: &Path, systeme: &[PathBuf], bureau: &str) -> (Vec<Programme>, Vec<String>) {
    // Les noms seulement : chaque entrée se lit ensuite une fois, bornée, sans attendre un tube (campagne 0.94, C-2).
    // Gardés tels quels (`OsString`) : un nom de fichier n'est pas du texte. Converti avec pertes, un nom qui n'est
    // pas en UTF-8 désignait un autre fichier, « introuvable », et l'entrée était tue (relecture 0.94, R-1).
    let noms = |d: &Path| -> Vec<std::ffi::OsString> {
        let mut l: Vec<std::ffi::OsString> = std::fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| e == "desktop"))
            .map(|f| f.file_name())
            .collect();
        l.sort();
        l
    };
    // Une entrée au nom qui n'est pas en UTF-8 ne se note pas (la note et l'identité sont du texte) : elle n'est ni
    // lue ni proposée, mais dite, et elle masque l'entrée du système au même nom exact.
    let nom_pas_en_utf8 = |chemin: &Path| {
        trf!(
            "non vérifié : entrée de démarrage au nom qui n'est pas en UTF-8 ({}) ; ni lue ni proposée",
            "not verified: startup entry whose name is not UTF-8 ({}); neither read nor offered",
            affichable(&court(chemin))
        )
    };
    let max = u64::try_from(AUTOSTART_MAX - 1).unwrap_or(0);
    let mut vus: std::collections::HashSet<std::ffi::OsString> = std::collections::HashSet::new();
    let mut l = Vec::new();
    let mut manques = Vec::new();
    // Le dossier du compte lui-même refusé (un lien vers des dotfiles, hors du dossier personnel, à un autre compte) :
    // aucune de ses entrées ne se lit ni ne se propose, et la liste le dit une fois (T-1), jamais « aucun programme ».
    let dossier_refuse = match sous_maison::juger_le_dossier(compte) {
        Ok(()) => false,
        Err(e) => {
            manques.push(trf!(
                "non vérifié : {} ; ses entrées de démarrage ne sont ni lues ni proposées",
                "not verified: {}; its startup entries are neither read nor offered",
                e
            ));
            true
        }
    };
    for nom in noms(compte) {
        let chemin = compte.join(&nom);
        if nom.to_str().is_none() {
            if !dossier_refuse {
                manques.push(nom_pas_en_utf8(&chemin));
            }
            vus.insert(nom);
            continue;
        }
        // Un lien, un tube ou un dossier, à un autre compte : ni lu ni proposé, mais dit (T-1, T-3) ; il masque
        // l'entrée du système au même nom.
        match sous_maison::juger_lecture(&chemin) {
            Ok(()) => {
                // Relu d'une seule ouverture, sans suivre de lien et borné, comme la note : ce qui est montré, la
                // cible et la note viennent tous de cette lecture-là. Pas lu ainsi : rien à noter, donc rien de
                // proposé (écrite, l'entrée ne se remettrait plus).
                match sous_maison::lire(&chemin, max) {
                    Ok(t) => l.push(programme_autostart(chemin, &t, bureau, Some(format!("+{t}")))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => manques.push(pas_lue(&chemin)),
                }
            }
            Err(_) if dossier_refuse => {}
            Err(e) => manques.push(trf!(
                "non vérifié : {} ; l'entrée n'est ni lue ni proposée",
                "not verified: {}; the entry is neither read nor offered",
                e
            )),
        }
        vus.insert(nom);
    }
    for d in systeme {
        for nom in noms(d) {
            if vus.contains(&nom) {
                continue;
            }
            if nom.to_str().is_none() {
                manques.push(nom_pas_en_utf8(&d.join(&nom)));
                vus.insert(nom);
                continue;
            }
            let texte = match lire_du_systeme(&d.join(&nom), max) {
                Ok(t) => t,
                // Absente depuis, ou lien pendant : rien à masquer.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    manques.push(pas_lue(&d.join(&nom)));
                    vus.insert(nom);
                    continue;
                }
            };
            if vus.insert(nom.clone()) && crate::lenteur::entree_autostart(&texte, bureau).is_some() {
                // La copie du compte n'existait pas : elle ne s'écrit que si c'est encore vrai.
                let mut p = programme_autostart(compte.join(&nom), &texte, bureau, Some("-".to_string()));
                // Le dossier du compte ne se lit pas (un lien vers des dotfiles, refusé) : une entrée à ce nom peut
                // la masquer sans que Vanguard le voie. Montrée comme `lenteur` la compte, jamais proposée (H-2) ;
                // le dossier est déjà dit, une fois, dans ce qui n'a pas été vérifié.
                if sous_maison::juger_lecture(&compte.join(&nom)).is_err() {
                    p.ecriture = Ecriture::MasquageInconnu;
                }
                l.push(p);
            }
        }
    }
    (l, manques)
}

/// Le texte d'une entrée d'autostart lu comme `vanguard demarrage` le lit, pour qui ne fait que la regarder
/// (`vanguard lenteur`) : borné, sans attendre un tube ; celle du compte (`du_compte`) sans suivre de lien ni sortir du
/// dossier personnel. `NotFound` : absente ; une autre erreur : pas lue ainsi (correction n° 2 de la 0.94, D-4), à
/// dire (relecture 0.94, R-5).
pub(crate) fn texte_autostart(chemin: &Path, du_compte: bool) -> std::io::Result<String> {
    let max = u64::try_from(AUTOSTART_MAX - 1).unwrap_or(0);
    if du_compte {
        sous_maison::lire(chemin, max)
    } else {
        lire_du_systeme(chemin, max)
    }
}

/// Le texte d'une entrée d'autostart du système, d'au plus `max` octets. Les liens sont suivis (les paquets en posent,
/// et rien ne s'écrit d'après eux ailleurs que dans le compte), mais l'ouverture n'attend pas un tube, et seul un
/// simple fichier se lit, borné (campagne 0.94, C-1, C-2). `NotFound` : absente, ou lien pendant.
fn lire_du_systeme(p: &Path, max: u64) -> std::io::Result<String> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let invalide = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    // Regardé avant d'être ouvert (lien suivi, comme le bureau le suit) : un tube, un périphérique ou un dossier
    // qu'XDG_CONFIG_DIRS nomme ne s'ouvre pas, même pour être refusé (relecture 0.94, m-a). Le second regard, sur le
    // fichier ouvert, tient si le nom change entre les deux.
    if !std::fs::metadata(p)?.is_file() {
        return Err(invalide());
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(p)?;
    if !f.metadata()?.is_file() {
        return Err(invalide());
    }
    let mut octets = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut octets)?;
    if u64::try_from(octets.len()).map_or(true, |n| n > max) {
        return Err(invalide());
    }
    String::from_utf8(octets).map_err(|_| invalide())
}

/// Ce que dit la liste d'une entrée d'autostart qui ne se lit pas bornée : pas proposée.
fn pas_lue(chemin: &Path) -> String {
    let ou = court(chemin);
    trf!(
        "entrée de démarrage {ou} pas lue (plus de 64 Kio, pas en UTF-8, pas un simple fichier ou illisible) : pas \
         proposée",
        "startup entry {ou} not read (over 64 KiB, not UTF-8, not a plain file or unreadable): not offered"
    )
}

/// Une entrée d'autostart : `chemin`, le fichier du compte où elle se masque (sa copie, pour une entrée du système).
fn programme_autostart(chemin: PathBuf, texte: &str, bureau: &str, vu: Option<String>) -> Programme {
    let actif = crate::lenteur::entree_autostart(texte, bureau);
    let nom = actif
        .as_ref()
        .map(|(n, _)| n.clone())
        .or_else(|| champ(texte, "Name").map(str::to_string))
        .unwrap_or_else(|| Changement::nom_demarrage(&chemin.display().to_string()));
    let ecriture = ecriture_refusee(&chemin);
    Programme {
        nom,
        commande: champ(texte, "Exec").unwrap_or_default().to_string(),
        actif: actif.is_some(),
        machine: false,
        // Une étape de la session de GNOME ou de KDE : le bureau en a besoin.
        bureau: champ(texte, "X-GNOME-Autostart-Phase").is_some() || champ(texte, "X-KDE-autostart-phase").is_some(),
        changement: Changement::Demarrage {
            entree: Entree::Autostart(chemin),
            cible: Some(format!("+{}", masquer(texte))),
            vu,
        },
        ecriture,
    }
}

/// La raison d'une entrée lue où Vanguard n'écrit pas : la garde d'écriture (`sous_maison::juger`) la refuse alors que
/// celle de lecture l'a laissée passer, donc pour les droits d'un dossier du chemin, que le groupe ou les autres
/// peuvent modifier ou qui porte un bit spécial (relecture 0.95, G-1). Sa phrase entière : le dossier, ses droits et
/// le remède (H-1 suite).
fn ecriture_refusee(chemin: &Path) -> Ecriture {
    sous_maison::juger(chemin).map_or_else(|e| Ecriture::Refusee(e.to_string()), |()| Ecriture::Permise)
}

pub fn apres(_touches: &[&Reglage]) {}

/// Le fichier de l'unité existe (ce que vérifiait `systemctl cat`), lu dans les dossiers de systemd.
fn unite_existe(nom: &str) -> bool {
    natif::unite_existe(nom)
}

/// Au moins un disque sans pièce mobile (SSD, NVMe), que sysfs marque non rotatif.
fn ssd() -> bool {
    a_un_ssd(&natif::disques())
}

/// Ce que `lsblk` dit « disk » : la mémoire compressée (zram) s'y dit aussi disque sans pièce mobile, mais TRIM n'y
/// a pas de sens ; loop non plus.
fn a_un_ssd(disques: &[natif::Disque]) -> bool {
    disques.iter().any(|d| {
        crate::fiche::disque_entier(d) && !d.rotatif && !d.nom.starts_with("zram") && !d.nom.starts_with("loop")
    })
}

/// GNOME est le bureau, et ses réglages de vie privée sont installés : le schéma se lit dans sa description XML,
/// gsettings en secours quand elle manque.
fn gnome() -> bool {
    std::env::var("XDG_CURRENT_DESKTOP").is_ok_and(|d| d.to_uppercase().contains("GNOME"))
        && crate::sauvegarde::schema_gsettings("org.gnome.desktop.privacy", None).unwrap_or_else(|| {
            sortie("gsettings", &["list-keys", "org.gnome.desktop.privacy"]).is_some_and(|t| !t.is_empty())
        })
}

/// L'état d'une unité comme `systemctl [--user] is-enabled` le dit (la valeur notée avant un changement, remise
/// pour l'annuler) : lu dans les dossiers de systemd quand c'est un état qu'un réglage sait remettre, sinon
/// demandé à systemctl, qui sait nommer les autres.
fn etat_unite_lu(nom: &str, utilisateur: bool) -> Valeur {
    let maison = crate::socle::maison();
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let donnees = std::env::var_os("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
    let uid = crate::socle::uid();
    let dossiers = DossiersUnites::du_systeme(Path::new("/"), &config, &donnees, uid, utilisateur);
    etat_unite_selon(&dossiers, nom, natif::unite_activee(nom, utilisateur))
        .map(str::to_string)
        .or_else(|| {
            let mut args = vec!["is-enabled", nom];
            if utilisateur {
                args.insert(0, "--user");
            }
            // « is-enabled » répond aussi par son code de retour : seul le texte compte ici.
            sortie("systemctl", &args).filter(|t| !t.is_empty())
        })
}

/// Où systemd range les unités : (dossier de configuration, valable pour ce démarrage seulement), du plus
/// prioritaire au moins prioritaire, puis les dossiers des paquets.
struct DossiersUnites {
    configuration: Vec<(PathBuf, bool)>,
    paquets: Vec<PathBuf>,
}

impl DossiersUnites {
    fn du_systeme(racine: &Path, config: &Path, donnees: &Path, uid: u32, utilisateur: bool) -> Self {
        let sous = |d: &str| racine.join(d.trim_start_matches('/'));
        if utilisateur {
            DossiersUnites {
                configuration: vec![
                    (sous(&config.join("systemd/user").to_string_lossy()), false),
                    (sous("/etc/systemd/user"), false),
                    (sous(&format!("/run/user/{uid}/systemd/user")), true),
                    (sous("/run/systemd/user"), true),
                ],
                paquets: vec![
                    sous(&donnees.join("systemd/user").to_string_lossy()),
                    sous("/usr/local/lib/systemd/user"),
                    sous("/usr/lib/systemd/user"),
                    sous("/lib/systemd/user"),
                ],
            }
        } else {
            DossiersUnites {
                configuration: vec![
                    (sous("/etc/systemd/system"), false),
                    (sous("/run/systemd/system"), true),
                ],
                paquets: vec![
                    sous("/usr/local/lib/systemd/system"),
                    sous("/usr/lib/systemd/system"),
                    sous("/lib/systemd/system"),
                ],
            }
        }
    }
}

/// « masked », « enabled » ou « disabled », les seuls états qu'un réglage remet ; `activee` est la lecture de
/// natif (un lien d'activation). `None` pour le reste, que systemctl nomme : un masque de ce démarrage seulement
/// (« masked-runtime »), un fichier d'unité introuvable, un lien (« linked », « alias »), une unité sans
/// `[Install]` (« static ») ou qui n'y cite que d'autres unités (« indirect »).
fn etat_unite_selon(dossiers: &DossiersUnites, nom: &str, activee: Option<bool>) -> Option<&'static str> {
    for (d, ce_demarrage) in &dossiers.configuration {
        if std::fs::read_link(d.join(nom)).is_ok_and(|c| c == Path::new("/dev/null")) {
            return (!ce_demarrage).then_some("masked");
        }
    }
    if activee? {
        // Activée pour ce démarrage seulement (« enabled-runtime », un lien sous /run), ou par un alias ou une
        // instance : seul un lien à son nom dans un dossier durable se remet à coup sûr.
        let lien_durable = dossiers
            .configuration
            .iter()
            .filter(|(_, ce_demarrage)| !ce_demarrage)
            .any(|(d, _)| {
                std::fs::read_dir(d).into_iter().flatten().flatten().any(|w| {
                    let n = w.file_name();
                    let n = n.to_string_lossy();
                    (n.ends_with(".wants") || n.ends_with(".requires")) && w.path().join(nom).symlink_metadata().is_ok()
                })
            });
        return lien_durable.then_some("enabled");
    }
    let fichier = dossiers
        .configuration
        .iter()
        .map(|(d, _)| d)
        .chain(&dossiers.paquets)
        .map(|d| d.join(nom))
        .find(|f| f.symlink_metadata().is_ok())?;
    // Sans suivre de lien, sans attendre un tube, borné (relecture 0.94, R-7) : ce qui ne se lit pas ainsi est laissé
    // à systemctl, qui nomme l'état.
    let texte = crate::socle::lire_texte_ordinaire(&fichier, u64::try_from(UNITE_MAX).unwrap_or(0)).ok()?;
    installable(&texte).then_some("disabled")
}

/// La section `[Install]` dit à `systemctl enable` quoi poser : une cible qui la veut, ou un autre nom.
fn installable(unite: &str) -> bool {
    let mut dans_install = false;
    unite.lines().map(str::trim).any(|l| {
        if l.starts_with('[') {
            dans_install = l == "[Install]";
            return false;
        }
        dans_install
            && l.split_once('=').is_some_and(|(cle, valeur)| {
                matches!(cle.trim(), "WantedBy" | "RequiredBy" | "UpheldBy" | "Alias") && !valeur.trim().is_empty()
            })
    })
}

pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort, Performance};
    let systemd = Path::new("/run/systemd/system").is_dir();
    let mut l = Vec::new();
    if systemd && unite_existe("fstrim.timer") && ssd() {
        l.push(Reglage {
            id: "fstrim".into(),
            categorie: Performance,
            titre: tr!("Entretien du SSD chaque semaine", "Weekly SSD maintenance").into(),
            effet: tr!(
                "Une fois par semaine, le système dit au SSD quelles zones sont libres (TRIM) : les écritures restent rapides et le disque s'use moins.",
                "Once a week, the system tells the SSD which areas are free (TRIM): writes stay fast and the drive wears less."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Unite {
                nom: "fstrim.timer",
                cible: "enabled",
                defaut: "disabled",
            }],
        });
    }
    if systemd {
        l.push(Reglage {
            id: "journal_taille".into(),
            categorie: Performance,
            titre: tr!("Journal du système limité à 500 Mo", "System journal capped at 500 MB").into(),
            effet: tr!(
                "Les journaux du système ne prennent plus jusqu'à 4 Go : les plus anciens s'effacent au-delà de 500 Mo.",
                "System logs no longer take up to 4 GB: the oldest are removed beyond 500 MB."
            ),
            prudence: Some(tr!(
                "L'historique des journaux remonte moins loin dans le temps.",
                "The log history goes back less far in time."
            )),
            recommande: false,
            changements: vec![Changement::Fichier {
                chemin: "/etc/systemd/journald.conf.d/50-vanguard-taille.conf",
                contenu: "[Journal]\nSystemMaxUse=500M\n",
                // Lot U3 : reste une commande, après le fichier posé ; geste avec lui (U4).
                apres: "sudo systemctl restart systemd-journald",
            }],
        });
    }
    if gnome() {
        l.push(Reglage {
            id: "gnome_rapports".into(),
            categorie: Confidentialite,
            titre: tr!("GNOME : pas de rapports envoyés", "GNOME: no reports sent").into(),
            effet: tr!(
                "GNOME n'envoie plus de rapports de problèmes techniques.",
                "GNOME no longer sends technical problem reports."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Gnome {
                schema: "org.gnome.desktop.privacy",
                cle: "report-technical-problems",
                cible: "false",
                defaut: "true",
            }],
        });
    }
    if systemd && unite_existe("apport.service") {
        l.push(Reglage {
            id: "apport".into(),
            categorie: Confidentialite,
            titre: tr!("Ubuntu : rapports de plantage coupés", "Ubuntu: crash reports off").into(),
            effet: tr!(
                "Ubuntu ne propose plus d'envoyer les plantages à ses serveurs, et n'en garde plus de copie.",
                "Ubuntu no longer offers to send crashes to its servers, and keeps no copy of them."
            ),
            prudence: None,
            recommande: true,
            changements: vec![
                Changement::Option {
                    fichier: "/etc/default/apport",
                    cle: "enabled",
                    cible: "0",
                    defaut: "1",
                },
                Changement::Unite {
                    nom: "apport.service",
                    cible: "disabled",
                    defaut: "enabled",
                },
            ],
        });
    }
    if Path::new("/etc/popularity-contest.conf").is_file() {
        l.push(Reglage {
            id: "popcon".into(),
            categorie: Confidentialite,
            titre: tr!("Statistiques de paquets coupées", "Package statistics off").into(),
            effet: tr!(
                "La liste des programmes installés n'est plus envoyée chaque semaine à Debian ou Ubuntu.",
                "The list of installed programs is no longer sent to Debian or Ubuntu every week."
            ),
            prudence: None,
            recommande: true,
            changements: vec![Changement::Option {
                fichier: "/etc/popularity-contest.conf",
                cle: "PARTICIPATE",
                cible: "\"no\"",
                defaut: "\"yes\"",
            }],
        });
    }
    if Path::new("/etc/default/motd-news").is_file() {
        l.push(Reglage {
            id: "motd_news".into(),
            categorie: Confort,
            titre: tr!("Ubuntu : pas d'annonces au terminal", "Ubuntu: no terminal ads").into(),
            effet: tr!(
                "Les annonces d'Ubuntu affichées à l'ouverture d'une session en terminal disparaissent.",
                "The Ubuntu announcements shown when opening a terminal session go away."
            ),
            prudence: None,
            recommande: false,
            changements: vec![Changement::Option {
                fichier: "/etc/default/motd-news",
                cle: "ENABLED",
                cible: "0",
                defaut: "1",
            }],
        });
    }
    l
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Un service activé mais arrêté (ou désactivé mais en marche) ne se note pas : « enable/disable --now » ne
    /// ramènerait pas son état d'avant, et la relecture le dirait revenu.
    #[test]
    fn service_releve_seulement_si_mode_et_marche_s_accordent() {
        assert!(releve_fidele("enabled", true));
        assert!(releve_fidele("disabled", false));
        assert!(!releve_fidele("enabled", false));
        assert!(!releve_fidele("disabled", true));
        assert!(!releve_fidele("masked", true));
        assert!(releve_fidele("static", false));
    }

    #[test]
    fn commandes_du_shell() {
        let o = Changement::Option {
            fichier: "/etc/popularity-contest.conf",
            cle: "PARTICIPATE",
            cible: "\"no\"",
            defaut: "\"yes\"",
        };
        let c = o.commande(Some("\"no\"")).unwrap();
        assert!(c.contains("s|^PARTICIPATE=.*|PARTICIPATE=\"no\"|"), "{c}");
        let f = Changement::Fichier {
            chemin: "/etc/systemd/journald.conf.d/50-vanguard-taille.conf",
            contenu: "[Journal]\nSystemMaxUse=500M\n",
            apres: "sudo systemctl restart systemd-journald",
        };
        // Chaque commande est du shell valide (une apostrophe de trop ne se verrait qu'au lancement).
        for c in [
            o.commande(Some("\"no\"")),
            f.commande(Some("present")),
            f.commande(None),
        ]
        .into_iter()
        .flatten()
        {
            assert!(
                Command::new("bash").args(["-n", "-c", &c]).status().unwrap().success(),
                "{c}"
            );
        }
        let u = Changement::Unite {
            nom: "fstrim.timer",
            cible: "enabled",
            defaut: "disabled",
        };
        assert_eq!(
            u.commande(Some("enabled")).as_deref(),
            Some("vanguard:geste unite activer fstrim.timer")
        );
        assert_eq!(
            u.commande(Some("disabled")).as_deref(),
            Some("vanguard:geste unite desactiver fstrim.timer")
        );
        // « masked », et une unité hors de la table de l'assistant (apport, réglée avec son fichier) : des commandes
        // jusqu'à U4.
        assert_eq!(
            u.commande(Some("masked")).as_deref(),
            Some("sudo systemctl mask --now fstrim.timer")
        );
        let apport = Changement::Unite {
            nom: "apport.service",
            cible: "disabled",
            defaut: "enabled",
        };
        assert_eq!(
            apport.commande(Some("disabled")).as_deref(),
            Some("sudo systemctl disable --now apport.service")
        );
        assert_eq!(u.commande(Some("static")), None);
        // Un geste refusé par l'assistant reste refusé : aucune commande sudo à sa place, et le refus est dit.
        for (nom, v) in [
            ("ufw.service", "disabled"),
            ("ufw.service", "masked"),
            ("firewalld.service", "disabled"),
            ("auditd", "masked"),
        ] {
            let c = Changement::Unite {
                nom,
                cible: "enabled",
                defaut: "enabled",
            };
            assert_eq!(c.commande(Some(v)), None, "{nom} {v}");
            assert!(c.refus(Some(v)).is_some(), "{nom} {v}");
        }
        assert_eq!(u.refus(Some("masked")), None);
    }

    /// Les commandes d'une option, lancées pour de vrai sur un fichier jetable (sans sudo) : une valeur aux caractères
    /// spéciaux revient telle quelle, et « absente » retire la ligne.
    #[test]
    fn option_posee_remise_puis_retiree() {
        let f = crate::essais::temporaire().join(format!("vanguard-test-option-sed-{}", std::process::id()));
        std::fs::write(&f, "# réglage\nPARTICIPATE=\"yes\"\nAUTRE=1\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let o = Changement::Option {
            fichier: chemin,
            cle: "PARTICIPATE",
            cible: "\"no\"",
            defaut: "\"yes\"",
        };
        let lancer = |v: Option<&str>| {
            let c = o.commande(v).unwrap().replace("sudo ", "");
            assert!(Command::new("bash").args(["-c", &c]).status().unwrap().success(), "{c}");
        };
        let etrange = r"a&b|c\d'e";
        lancer(Some(etrange));
        assert_eq!(o.lire().as_deref(), Some(etrange));
        lancer(None);
        assert_eq!(o.lire(), None);
        lancer(Some("\"no\""));
        assert_eq!(o.lire().as_deref(), Some("\"no\""));
        let texte = std::fs::read_to_string(&f).unwrap();
        assert!(
            texte.contains("AUTRE=1\n") && texte.starts_with("# réglage\n"),
            "{texte}"
        );
        let _ = std::fs::remove_file(&f);
    }

    /// Les valeurs notées remises avec sudo : seulement des formes fermées ou strictes. Une note réécrite par un
    /// programme du compte (une commande glissée dans une ligne, un DNS qui n'est pas une adresse, un état inventé)
    /// est refusée.
    #[test]
    fn valeurs_notees_validees() {
        let option = Changement::Option {
            fichier: "/etc/default/apport",
            cle: "enabled",
            cible: "0",
            defaut: "1",
        };
        for bonne in [None, Some("0"), Some("1"), Some("\"no\""), Some("auto")] {
            assert!(option.valeur_admise(bonne), "{bonne:?}");
        }
        for mauvaise in ["1\nLD_PRELOAD=/tmp/x.so", "$(id)", "1; rm -rf ~", "a b", "\"no"] {
            assert!(!option.valeur_admise(Some(mauvaise)), "{mauvaise:?}");
        }
        let unite = Changement::Unite {
            nom: "fstrim.timer",
            cible: "enabled",
            defaut: "disabled",
        };
        assert!(unite.valeur_admise(Some("static")) && unite.valeur_admise(Some("masked")));
        // Une protection n'est jamais remise masquée par une note (lot U3, P7).
        let auditd = Changement::depuis_geste("unite|auditd").unwrap();
        assert!(auditd.valeur_admise(Some("disabled")) && !auditd.valeur_admise(Some("masked")));
        // Ni un pare-feu masqué ou désactivé.
        for v in ["masked", "disabled"] {
            let ufw = Changement::Unite {
                nom: "ufw.service",
                cible: "enabled",
                defaut: "enabled",
            };
            assert!(!ufw.valeur_admise(Some(v)), "{v}");
        }
        assert!(!unite.valeur_admise(Some("enabled --now evil.service")));
        let gnome = Changement::Gnome {
            schema: "org.gnome.desktop.privacy",
            cle: "report-technical-problems",
            cible: "false",
            defaut: "true",
        };
        for bonne in ["true", "uint32 5", "-3", "'default'"] {
            assert!(gnome.valeur_admise(Some(bonne)), "{bonne}");
        }
        assert!(!gnome.valeur_admise(Some("'a' && touch /tmp/x")));
        let connexion = "6b9a0f0e-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
        let dns = Changement::Dns {
            connexion: connexion.into(),
            cible: None,
        };
        assert!(dns.valeur_admise(Some(&format!(
            "{connexion}\n1.1.1.1,9.9.9.9|yes|2606:4700:4700::1111|yes"
        ))));
        assert!(dns.valeur_admise(Some(&format!("{connexion}\n|no||no"))));
        assert!(!dns.valeur_admise(Some(&format!("{connexion}\nevil.example.com|yes||no"))));
        assert!(!dns.valeur_admise(Some(&format!("{connexion}\n1.1.1.1|peut-être||no"))));
        assert!(!dns.valeur_admise(Some("0b8c2f4e-1a2b-4c3d-9e8f-001122334455\n1.1.1.1|yes||no")));
        assert!(!dns.valeur_admise(None));
        let service = Changement::Demarrage {
            entree: Entree::Service("discord.service".into()),
            cible: None,
            vu: None,
        };
        assert!(service.valeur_admise(Some("disabled")) && !service.valeur_admise(Some("on")));
    }

    /// Un geste de défense noté ne se remet que par la ligne `remettre` de l'assistant, avec le même identifiant :
    /// jamais une commande sudo, ni un identifiant forgé (majuscules, trop court, chemin), ni une note déjà là avant.
    #[test]
    fn geste_de_defense_note() {
        let id = "0123456789abcdef";
        let c = Changement::depuis_geste(&format!("defense|{id}")).unwrap();
        assert!(matches!(c, Changement::Defense { id: i } if i.as_str() == id));
        assert!(c.valeur_admise(None));
        assert!(!c.valeur_admise(Some(NOTE_PRESENTE)) && !c.valeur_admise(Some("autre")));
        assert_eq!(
            c.commande(None).as_deref(),
            Some("vanguard:geste defense remettre 0123456789abcdef")
        );
        assert_eq!(c.commande(Some(NOTE_PRESENTE)), None);
        assert!(c.admin() && c.refus(None).is_none());
        assert_eq!((c.cible(), c.defaut()), (Some("?".into()), Some("?".into())));
        for forge in [
            "defense|0123456789ABCDEF",
            "defense|0123456789abcde",
            "defense|0123456789abcdef0",
            "defense|../../etc/passwd",
            "defense|0123456789abcdef|x",
            "defense",
        ] {
            assert!(Changement::depuis_geste(forge).is_none(), "{forge}");
        }
        assert_eq!(
            super::super::Geste::defense(IdNote::nouveau(id).unwrap()).0,
            format!("defense|{id}")
        );
    }

    #[test]
    fn dns_de_networkmanager() {
        let connexion = "6b9a0f0e-1c2d-4e5f-8a9b-0c1d2e3f4a5b";
        let c = Changement::Dns {
            connexion: connexion.into(),
            cible: Some("1.1.1.1,1.0.0.1|yes|2606:4700:4700::1111|yes".into()),
        };
        let cible = c.cible().unwrap();
        assert_eq!(
            cible,
            format!("{connexion}\n1.1.1.1,1.0.0.1|yes|2606:4700:4700::1111|yes")
        );
        let commande = c.commande(Some(&cible)).unwrap();
        assert!(
            commande.contains("ipv4.dns '1.1.1.1 1.0.0.1' ipv4.ignore-auto-dns yes"),
            "{commande}"
        );
        let remise = c.commande(c.defaut().as_deref()).unwrap();
        assert!(
            remise.contains("ipv4.dns '' ipv4.ignore-auto-dns no ipv6.dns '' ipv6.ignore-auto-dns no"),
            "{remise}"
        );
        for ligne in [&commande, &remise] {
            assert!(
                Command::new("bash")
                    .args(["-n", "-c", ligne])
                    .status()
                    .unwrap()
                    .success(),
                "{ligne}"
            );
        }
        // Une valeur d'une autre connexion, ou un identifiant qui n'en est pas un : aucune commande.
        assert_eq!(c.commande(Some("autre\n|no||no")), None);
        assert!(Changement::dns_note("pas un uuid\n|no||no").is_none());
        let rebati = Changement::dns_note(&format!("{connexion}\n|no||no")).unwrap();
        assert_eq!(rebati.identite_dns(), Some(connexion));
        assert_ne!(
            rebati.cible(),
            rebati.defaut(),
            "une cible inconnue ne doit jamais passer pour atteinte"
        );
        assert_eq!(
            decrire_dns(Some(&cible)),
            super::super::texte_dns(&["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"], false)
        );
        assert_eq!(decrire_dns(c.defaut().as_deref()), super::super::texte_dns(&[], true));
        assert_eq!(liste_dns("1.1.1.1 1.0.0.1,"), "1.1.1.1,1.0.0.1");
    }

    #[test]
    fn carte_de_la_route_par_defaut() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                     tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
                     wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                     eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(carte_par_defaut(table).as_deref(), Some("eth0"));
        assert_eq!(carte_par_defaut("Iface\tDestination\n"), None);
    }

    fn disque(nom: &str, rotatif: bool, genre: &str) -> natif::Disque {
        natif::Disque {
            nom: nom.into(),
            octets: 1 << 30,
            rotatif,
            amovible: false,
            modele: String::new(),
            serie: String::new(),
            bus: String::new(),
            genre: genre.into(),
        }
    }

    /// Ni la mémoire compressée, ni loop, ni device-mapper, ni une grappe RAID (non rotatifs pour sysfs) ne sont un
    /// SSD.
    #[test]
    fn la_memoire_compressee_n_est_pas_un_ssd() {
        let sans = [
            disque("zram0", false, "disk"),
            disque("sda", true, "disk"),
            disque("loop0", false, "loop"),
            disque("dm-0", false, "dm"),
            disque("md0", false, "disk"),
        ];
        assert!(!a_un_ssd(&sans));
        assert!(a_un_ssd(&[
            disque("zram0", false, "disk"),
            disque("nvme0n1", false, "disk")
        ]));
        assert!(!a_un_ssd(&[]));
    }

    /// Sur cet ordinateur, « un SSD » se lit comme `lsblk -dno NAME,ROTA,TYPE` le disait, quand il est là.
    #[test]
    fn ssd_comme_lsblk() {
        let Some(r) = crate::commande::lancer(Command::new("lsblk").args(["-dno", "NAME,ROTA,TYPE"]), 10)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("lsblk absent");
        };
        let attendu = r.sortie.lines().any(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            matches!(c[..], [nom, "0", "disk"] if !nom.starts_with("zram") && !nom.starts_with("loop"))
        });
        assert_eq!(ssd(), attendu, "{}", r.sortie);
    }

    /// Une arborescence de systemd inventée, pour le système ou le compte.
    fn dossiers_inventes(nom: &str, utilisateur: bool) -> (PathBuf, DossiersUnites) {
        let d = crate::essais::temporaire().join(format!("vanguard-optimiser-unites-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let dossiers = DossiersUnites::du_systeme(
            &d,
            Path::new("/home/alice/.config"),
            Path::new("/home/alice/.local/share"),
            1000,
            utilisateur,
        );
        for c in dossiers.configuration.iter().map(|(c, _)| c).chain(&dossiers.paquets) {
            std::fs::create_dir_all(c).unwrap();
        }
        (d, dossiers)
    }

    /// L'état noté avant un changement : masquée (par l'administrateur seulement), activée, désactivée ; le reste
    /// (statique, indirecte, liée, introuvable, masque de ce démarrage) est laissé à systemctl.
    #[test]
    fn etat_d_une_unite_lu_dans_les_dossiers() {
        use std::os::unix::fs::symlink;
        let (d, dossiers) = dossiers_inventes("systeme", false);
        let paquet = &dossiers.paquets[1];
        let etc = &dossiers.configuration[0].0;
        let run = &dossiers.configuration[1].0;
        std::fs::write(
            paquet.join("fstrim.timer"),
            "[Timer]\nOnCalendar=weekly\n[Install]\nWantedBy=timers.target\n",
        )
        .unwrap();
        std::fs::write(paquet.join("statique.service"), "[Service]\nExecStart=/bin/true\n").unwrap();
        std::fs::write(
            paquet.join("indirecte.service"),
            "[Install]\nAlso=autre.socket\nWantedBy=\n",
        )
        .unwrap();
        symlink(paquet.join("fstrim.timer"), etc.join("liee.timer")).unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "fstrim.timer", Some(false)),
            Some("disabled")
        );
        // Activée : un lien à son nom dans un « *.wants » durable ; sous /run seulement, c'est « enabled-runtime ».
        std::fs::create_dir_all(run.join("timers.target.wants")).unwrap();
        symlink(
            paquet.join("fstrim.timer"),
            run.join("timers.target.wants/fstrim.timer"),
        )
        .unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "fstrim.timer", Some(true)),
            None,
            "enabled-runtime"
        );
        std::fs::create_dir_all(etc.join("timers.target.wants")).unwrap();
        symlink(
            paquet.join("fstrim.timer"),
            etc.join("timers.target.wants/fstrim.timer"),
        )
        .unwrap();
        assert_eq!(etat_unite_selon(&dossiers, "fstrim.timer", Some(true)), Some("enabled"));
        assert_eq!(etat_unite_selon(&dossiers, "fstrim.timer", None), None, "sans systemd");
        assert_eq!(etat_unite_selon(&dossiers, "statique.service", Some(false)), None);
        assert_eq!(etat_unite_selon(&dossiers, "indirecte.service", Some(false)), None);
        assert_eq!(etat_unite_selon(&dossiers, "liee.timer", Some(false)), None);
        assert_eq!(etat_unite_selon(&dossiers, "absente.service", Some(false)), None);
        symlink("/dev/null", run.join("fstrim.timer")).unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "fstrim.timer", Some(false)),
            None,
            "masked-runtime"
        );
        symlink("/dev/null", etc.join("fstrim.timer")).unwrap();
        assert_eq!(etat_unite_selon(&dossiers, "fstrim.timer", Some(false)), Some("masked"));
        let _ = std::fs::remove_dir_all(&d);

        // Un service du compte, ajouté dans ~/.config/systemd/user.
        let (d, dossiers) = dossiers_inventes("compte", true);
        let config = &dossiers.configuration[0].0;
        assert!(
            config.ends_with("home/alice/.config/systemd/user"),
            "{}",
            config.display()
        );
        std::fs::write(config.join("synchro.service"), "[Install]\nWantedBy=default.target\n").unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "synchro.service", Some(false)),
            Some("disabled")
        );
        std::fs::create_dir_all(config.join("default.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            config.join("synchro.service"),
            config.join("default.target.wants/synchro.service"),
        )
        .unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "synchro.service", Some(true)),
            Some("enabled")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, chaque état que la lecture native conclut est celui que dit `systemctl is-enabled`, pour
    /// toutes les unités des dossiers du système et du compte, quand il répond.
    #[test]
    fn etats_comme_systemctl_is_enabled() {
        let maison = crate::socle::maison();
        let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
        let donnees = std::env::var_os("XDG_DATA_HOME").map_or_else(|| maison.join(".local/share"), PathBuf::from);
        let uid = crate::socle::uid();
        for utilisateur in [false, true] {
            let dossiers = DossiersUnites::du_systeme(Path::new("/"), &config, &donnees, uid, utilisateur);
            let mut noms: Vec<String> = dossiers
                .configuration
                .iter()
                .map(|(d, _)| d)
                .chain(&dossiers.paquets)
                .flat_map(|d| std::fs::read_dir(d).into_iter().flatten().flatten())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.contains('@') && [".service", ".timer", ".socket"].iter().any(|s| n.ends_with(s)))
                .collect();
            noms.sort();
            noms.dedup();
            if noms.is_empty() {
                continue;
            }
            let mut args = vec!["is-enabled"];
            if utilisateur {
                args.insert(0, "--user");
            }
            args.extend(noms.iter().map(String::as_str));
            let Some(r) = crate::commande::lancer(Command::new("systemctl").args(&args), 30) else {
                continue;
            };
            let etats: Vec<&str> = r.sortie.lines().map(str::trim).collect();
            if etats.len() != noms.len() {
                continue;
            }
            for (nom, etat) in noms.iter().zip(etats) {
                if let Some(natif) = etat_unite_selon(&dossiers, nom, natif::unite_activee(nom, utilisateur)) {
                    assert_eq!(natif, etat, "{nom} (utilisateur : {utilisateur})");
                }
            }
        }
    }

    #[test]
    fn lit_une_option_d_un_fichier() {
        let f = crate::essais::temporaire().join(format!("vanguard-test-option-{}", std::process::id()));
        std::fs::write(&f, "# commentaire\nENABLED=1\n").unwrap();
        let chemin: &'static str = Box::leak(f.display().to_string().into_boxed_str());
        let o = Changement::Option {
            fichier: chemin,
            cle: "ENABLED",
            cible: "0",
            defaut: "1",
        };
        assert_eq!(o.lire().as_deref(), Some("1"));
        let _ = std::fs::remove_file(&f);
    }

    /// Un dossier jetable par essai : les essais tournent en même temps.
    fn dossier_jetable(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-test-demarrage-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn autostart_masque_puis_demasque() {
        let t = "[Desktop Entry]\nType=Application\nName=Discord\nExec=/usr/bin/discord --start-minimized\nHidden=false\n\n[Desktop Action Nouveau]\nHidden=autre\n";
        let m = masquer(t);
        assert_eq!(
            m,
            "[Desktop Entry]\nHidden=true\nType=Application\nName=Discord\nExec=/usr/bin/discord --start-minimized\n\n[Desktop Action Nouveau]\nHidden=autre\n"
        );
        assert_eq!(masquer(&m), m, "masquer deux fois ne change plus rien");
        assert!(crate::lenteur::entree_autostart(&m, "Hyprland").is_none());
        assert_eq!(
            demasquer(&m),
            "[Desktop Entry]\nType=Application\nName=Discord\nExec=/usr/bin/discord --start-minimized\n\n[Desktop Action Nouveau]\nHidden=autre\n"
        );
        // Sans saut de ligne après l'en-tête, ou sans en-tête du tout.
        assert_eq!(masquer("[Desktop Entry]"), "[Desktop Entry]\nHidden=true\n");
        assert_eq!(masquer("Name=x"), "Name=x\n[Desktop Entry]\nHidden=true\n");
        assert_eq!(champ(t, "Exec"), Some("/usr/bin/discord --start-minimized"));
        assert_eq!(champ(t, "Absent"), None);
    }

    #[test]
    fn entrees_d_autostart_du_compte_et_du_systeme() {
        let base = dossier_jetable("liste");
        let (compte, systeme) = (base.join("compte/autostart"), base.join("systeme/autostart"));
        std::fs::create_dir_all(&compte).unwrap();
        std::fs::create_dir_all(&systeme).unwrap();
        let entree =
            |nom: &str, suite: &str| format!("[Desktop Entry]\nType=Application\nName={nom}\nExec={nom}\n{suite}");
        std::fs::write(compte.join("discord.desktop"), entree("Discord", "")).unwrap();
        std::fs::write(compte.join("vieux.desktop"), entree("Vieux", "Hidden=true\n")).unwrap();
        std::fs::write(systeme.join("discord.desktop"), entree("Discord du système", "")).unwrap();
        std::fs::write(systeme.join("syncthing.desktop"), entree("Syncthing", "")).unwrap();
        std::fs::write(
            systeme.join("gnome.desktop"),
            entree("Seulement GNOME", "OnlyShowIn=GNOME;\n"),
        )
        .unwrap();
        std::fs::write(
            systeme.join("session.desktop"),
            entree("Session", "X-GNOME-Autostart-Phase=Initialization\n"),
        )
        .unwrap();
        let (l, manques) = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland");
        assert!(manques.is_empty(), "{manques:?}");
        let vus: Vec<(&str, bool, bool)> = l.iter().map(|p| (p.nom.as_str(), p.actif, p.bureau)).collect();
        // Celui du compte l'emporte sur l'entrée du système au même nom ; celle d'un autre bureau n'a rien à retirer.
        assert_eq!(
            vus,
            [
                ("Discord", true, false),
                ("Vieux", false, false),
                ("Session", true, true),
                ("Syncthing", true, false)
            ]
        );
        // Une entrée du système se masque par une copie dans le dossier du compte.
        let syncthing = l.iter().find(|p| p.nom == "Syncthing").unwrap();
        assert_eq!(
            syncthing.changement.identite_demarrage(),
            Some(format!("autostart|{}", compte.join("syncthing.desktop").display()))
        );
        assert!(
            syncthing
                .changement
                .cible()
                .unwrap()
                .starts_with("+[Desktop Entry]\nHidden=true\n")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Retirer puis remettre redonne le fichier d'avant à l'octet près ; pour une entrée du système, la copie masquée
    /// du compte disparaît.
    #[test]
    fn retrait_d_autostart_annule_exactement() {
        let base = dossier_jetable("annuler");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("discord.desktop");
        let original = "[Desktop Entry]\r\nName=Discord\nExec=discord\n# commentaire gardé  \n";
        std::fs::write(&p, original).unwrap();
        let c = Changement::Demarrage {
            entree: Entree::Autostart(p.clone()),
            cible: Some(format!("+{}", masquer(original))),
            vu: Some(format!("+{original}")),
        };
        // L'annulation est rebâtie de la note, comme `--remettre` : sans cible ni valeur vue.
        let annuler = |c: &Changement| Changement::demarrage_depuis(&c.identite_demarrage().unwrap()).unwrap();
        let avant = c.lire();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        assert_eq!(c.lire(), c.cible());
        assert_eq!(annuler(&c).ecrire_ici(avant.as_deref()), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);

        let q = compte.join("syncthing.desktop");
        let s = Changement::Demarrage {
            entree: Entree::Autostart(q.clone()),
            cible: Some("+[Desktop Entry]\nHidden=true\nName=Syncthing\n".to_string()),
            vu: Some("-".to_string()),
        };
        let avant = s.lire();
        assert_eq!(avant.as_deref(), Some("-"));
        assert_eq!(s.ecrire_ici(s.cible().as_deref()), Some(true));
        assert!(q.is_file());
        assert_eq!(annuler(&s).ecrire_ici(avant.as_deref()), Some(true));
        assert!(!q.exists());
        // Une valeur qu'on n'a pas su lire ne s'écrit jamais.
        assert_eq!(annuler(&s).ecrire_ici(Some("?")), Some(false));
        assert!(s.decrire(Some("-")).contains("syncthing.desktop"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Relecture 0.94, m-1 : une entrée retirée puis réécrite à la main, encore masquée (pas lancée, donc offerte à
    /// « remettre »), n'est pas écrasée par le contenu noté : refusé, et la raison dite. Remise telle que le retrait
    /// l'a laissée, ou absente, elle se remet. Une copie d'une entrée du système démasquée à la main ne s'efface pas.
    #[test]
    fn une_entree_reecrite_apres_le_retrait_n_est_pas_ecrasee() {
        let base = dossier_jetable("reecrite");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("lecteur.desktop");
        let original = "[Desktop Entry]\nName=Lecteur\nExec=lecteur\n";
        std::fs::write(&p, original).unwrap();
        let c = Changement::Demarrage {
            entree: Entree::Autostart(p.clone()),
            cible: Some(format!("+{}", masquer(original))),
            vu: Some(format!("+{original}")),
        };
        let remettre = Changement::demarrage_depuis(&c.identite_demarrage().unwrap()).unwrap();
        let avant = c.lire();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        let a_la_main = "[Desktop Entry]\nHidden=true\nName=Autre\nExec=/usr/bin/false\n";
        std::fs::write(&p, a_la_main).unwrap();
        let _ = dernier_refus();
        assert_eq!(remettre.ecrire_ici(avant.as_deref()), Some(false));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), a_la_main);
        assert!(dernier_refus().is_some_and(|r| r.contains("réécrite")));
        // Telle que le retrait l'a laissée : remise.
        std::fs::write(&p, masquer(original)).unwrap();
        assert_eq!(remettre.ecrire_ici(avant.as_deref()), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
        // Effacée à la main : remise aussi (rien à perdre).
        std::fs::remove_file(&p).unwrap();
        assert_eq!(remettre.ecrire_ici(avant.as_deref()), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
        // Une copie d'une entrée du système (notée absente du compte), démasquée à la main : pas effacée.
        let q = compte.join("panneau.desktop");
        std::fs::write(&q, "[Desktop Entry]\nName=Panneau\nExec=panneau\nOnlyShowIn=Autre;\n").unwrap();
        let copie = Changement::demarrage_depuis(&format!("autostart|{}", q.display())).unwrap();
        assert_eq!(copie.ecrire_ici(Some("-")), Some(false));
        assert!(q.is_file());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Relecture 0.95, G-2 : la liste à cocher remet par le changement de la liste refaite (cible et valeur vue
    /// posées), pas par celui rebâti de la note. Réécrite à la main depuis le retrait (encore masquée), l'entrée n'est
    /// pas écrasée par ce chemin-là non plus ; telle que le retrait l'a laissée, elle se remet.
    #[test]
    fn la_liste_a_cocher_n_ecrase_pas_une_entree_reecrite() {
        let base = dossier_jetable("reecrite-liste");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("lecteur.desktop");
        let original = "[Desktop Entry]\nName=Lecteur\nExec=lecteur\n";
        std::fs::write(&p, original).unwrap();
        let listee = |nom: &str| {
            let (liste, _) = autostart(&compte, &[], "");
            liste.into_iter().find(|x| x.nom == nom).expect("listée").changement
        };
        let c = listee("Lecteur");
        let note = c.lire();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        let a_la_main = "[Desktop Entry]\nHidden=true\nName=Autre\nExec=/usr/bin/false\n";
        std::fs::write(&p, a_la_main).unwrap();
        let relistee = listee("Autre");
        let _ = dernier_refus();
        assert_eq!(relistee.ecrire_ici(note.as_deref()), Some(false));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), a_la_main);
        assert!(dernier_refus().is_some_and(|r| r.contains("réécrite")));
        // Telle que le retrait l'a laissée : la liste à cocher la remet.
        std::fs::write(&p, masquer(original)).unwrap();
        let relistee = listee("Lecteur");
        // La confirmation montre ce qui sera écrit (le nom et la commande notés), pas seulement le nom du fichier.
        assert!(relistee.decrire(note.as_deref()).contains("(Lecteur · lecteur)"));
        let piege = "+[Desktop Entry]\nName=A\u{1b}[2Kb\nExec=x\n";
        assert!(relistee.decrire(Some(piege)).contains("(A�[2Kb · x)"));
        assert_eq!(relistee.ecrire_ici(note.as_deref()), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Relecture 0.95, G-3 : /etc/xdg/autostart est toujours lu ; les chemins relatifs de XDG_CONFIG_DIRS sont
    /// ignorés ; la phrase n'est dite que si la variable cache /etc/xdg (absent de la liste, ou chemin relatif).
    #[test]
    fn xdg_config_dirs_ne_cache_jamais_etc_xdg() {
        let defaut = Path::new("/etc/xdg");
        let dossiers = |v: Option<&str>| dossiers_autostart_selon(v, defaut);
        let chemins = |v: &[&str]| v.iter().map(PathBuf::from).collect::<Vec<_>>();
        for v in [
            None,
            Some(""),
            Some("/etc/xdg"),
            Some("/etc/xdg/"),
            Some(":"),
            Some("::/etc/xdg"),
        ] {
            assert_eq!(dossiers(v), (chemins(&["/etc/xdg/autostart"]), None), "{v:?}");
        }
        assert_eq!(
            dossiers(Some("/etc/xdg/xdg-ubuntu:/etc/xdg")),
            (chemins(&["/etc/xdg/xdg-ubuntu/autostart", "/etc/xdg/autostart"]), None)
        );
        let (d, phrase) = dossiers(Some("/nulle-part"));
        assert_eq!(d, chemins(&["/nulle-part/autostart", "/etc/xdg/autostart"]));
        assert!(phrase.is_some_and(|p| p.contains("/nulle-part")));
        let (d, phrase) = dossiers(Some("relatif:/etc/xdg"));
        assert_eq!(d, chemins(&["/etc/xdg/autostart"]));
        assert!(phrase.is_some());
        // Un nom piégé est montré neutralisé.
        let (_, phrase) = dossiers(Some("/a\u{1b}[2Kb"));
        assert!(phrase.is_some_and(|p| !p.contains('\u{1b}')));
        // Relecture 0.95, H-3 : un dossier sous le dossier personnel est montré « ~/… », jamais avec le nom du
        // compte (la phrase part dans --json, au rapport et au journal).
        let maison = crate::socle::personnel::dossier_personnel().expect("HOME");
        let variable = format!("/opt/xdg:{m}/xdg-perso:{m}:{m}/", m = maison.display());
        let (_, phrase) = dossiers(Some(&variable));
        let phrase = phrase.expect("la variable cache /etc/xdg");
        assert!(
            !phrase.contains(&*maison.to_string_lossy()) && phrase.contains("/opt/xdg:~/xdg-perso:~:~"),
            "{phrase}"
        );
    }

    /// Relecture 0.94, m-4 : un refus d'écrire une entrée du compte retient sa raison (celle de la ligne ✖), une
    /// seule fois, pour l'issue de `demarrage --json` ; un geste fait n'en laisse aucune.
    #[test]
    fn un_refus_d_ecrire_retient_sa_raison() {
        let base = dossier_jetable("raison");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("cible.desktop");
        let montre = "[Desktop Entry]\nName=Cible\nExec=cible\n";
        std::fs::write(&p, montre).unwrap();
        let (liste, _) = autostart(&compte, &[], "");
        let c = &liste.iter().find(|x| x.nom == "Cible").expect("listée").changement;
        let _ = dernier_refus();
        std::fs::write(&p, "[Desktop Entry]\nName=Autre\nExec=autre\n").unwrap();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(false));
        assert_eq!(
            dernier_refus().as_deref(),
            Some("l'entrée a changé depuis qu'elle a été montrée : rien n'est écrit")
        );
        assert_eq!(dernier_refus(), None);
        std::fs::write(&p, montre).unwrap();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        assert_eq!(dernier_refus(), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Campagne B, M-1 : une entrée listée garde ce qui a été lu alors. Son contenu échangé avant le geste, rien n'est
    /// écrit (ni l'ancien contenu masqué, ni rien d'autre) ; la note est la valeur lue à la liste, jamais une seconde
    /// lecture ; échangée contre un lien, le lien reste. Une copie du système, prévue absente du compte, ne s'écrit
    /// pas sur un fichier apparu entre-temps.
    #[test]
    fn une_entree_echangee_apres_la_liste_n_est_pas_ecrite() {
        let base = dossier_jetable("echangee");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("cible.desktop");
        let montre = "[Desktop Entry]\nName=Cible\nExec=cible\n";
        std::fs::write(&p, montre).unwrap();
        let (liste, _) = autostart(&compte, &[], "");
        let c = &liste.iter().find(|x| x.nom == "Cible").expect("listée").changement;
        assert_eq!(c.lire_pour_noter().as_deref(), Some(format!("+{montre}").as_str()));
        let autre = "[Desktop Entry]\nName=Autre\nExec=autre\n";
        std::fs::write(&p, autre).unwrap();
        assert_eq!(c.lire_pour_noter().as_deref(), Some(format!("+{montre}").as_str()));
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(false));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), autre);
        // Échangée contre un lien : il reste, rien n'est écrit à sa place.
        std::fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(base.join("ailleurs.desktop"), &p).unwrap();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(false));
        assert!(std::fs::symlink_metadata(&p).unwrap().file_type().is_symlink());
        // Remise comme listée : le geste passe.
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, montre).unwrap();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        assert_eq!(c.lire(), c.cible());
        // Une copie d'une entrée du système, absente du compte à la liste.
        let systeme = base.join("xdg");
        std::fs::create_dir_all(&systeme).unwrap();
        std::fs::write(
            systeme.join("copie.desktop"),
            "[Desktop Entry]\nName=Copie\nExec=copie\n",
        )
        .unwrap();
        let (liste, _) = autostart(&compte, std::slice::from_ref(&systeme), "");
        let c = &liste.iter().find(|x| x.nom == "Copie").expect("listée").changement;
        assert_eq!(c.lire_pour_noter().as_deref(), Some("-"));
        std::fs::write(compte.join("copie.desktop"), "[Desktop Entry]\nName=Mien\n").unwrap();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(false));
        assert_eq!(
            std::fs::read_to_string(compte.join("copie.desktop")).unwrap(),
            "[Desktop Entry]\nName=Mien\n"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// La valeur d'avant d'une entrée d'autostart se lit en une ouverture, sans suivre de lien ni attendre un tube,
    /// bornée : un lien, un tube nommé ou un fichier trop gros ne se lisent pas (`None` : rien ne s'écrit d'après
    /// eux) ; la plus longue note lue est encore admise à la relecture.
    #[test]
    fn valeur_d_avant_d_autostart_ni_lien_ni_tube_ni_trop_gros() {
        let base = dossier_jetable("lecture-bornee");
        std::fs::create_dir_all(&base).unwrap();
        let entree = |nom: &str| Changement::Demarrage {
            entree: Entree::Autostart(base.join(nom)),
            cible: None,
            vu: None,
        };
        std::fs::write(base.join("vrai.desktop"), "[Desktop Entry]\nName=Lecteur\n").unwrap();
        assert_eq!(
            entree("vrai.desktop").lire().as_deref(),
            Some("+[Desktop Entry]\nName=Lecteur\n")
        );
        assert_eq!(entree("absent.desktop").lire().as_deref(), Some("-"));
        std::os::unix::fs::symlink(base.join("vrai.desktop"), base.join("lien.desktop")).unwrap();
        assert_eq!(entree("lien.desktop").lire(), None);
        crate::essais::tube_nomme(&base.join("tube.desktop")).unwrap();
        assert_eq!(entree("tube.desktop").lire(), None);
        std::fs::write(base.join("gros.desktop"), "x".repeat(AUTOSTART_MAX)).unwrap();
        assert_eq!(entree("gros.desktop").lire(), None);
        std::fs::write(base.join("juste.desktop"), "x".repeat(AUTOSTART_MAX - 1)).unwrap();
        let juste = entree("juste.desktop");
        let v = juste.lire().unwrap();
        assert_eq!(v.len(), AUTOSTART_MAX);
        assert!(juste.valeur_admise(Some(&v)));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Campagne 0.94, C-3 : une entrée du compte de plus de 64 Kio ne se lit pas bornée. Elle n'est pas proposée,
    /// la liste dit qu'elle n'a pas été lue ; un changement d'autostart sans valeur vue n'écrit rien ; une note absente
    /// (`null`) ne se remet jamais.
    #[test]
    fn entree_trop_grosse_ni_proposee_ni_ecrite() {
        let base = dossier_jetable("trop-grosse");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let p = compte.join("gros.desktop");
        let texte = format!("[Desktop Entry]\nName=Gros\nExec=gros\n#{}\n", "x".repeat(76 << 10));
        std::fs::write(&p, &texte).unwrap();
        let (l, manques) = autostart(&compte, &[], "");
        assert!(l.is_empty(), "proposée sans valeur d'avant lisible");
        assert_eq!(manques.len(), 1, "{manques:?}");
        assert!(manques[0].contains("gros.desktop"), "{manques:?}");
        let c = Changement::Demarrage {
            entree: Entree::Autostart(p.clone()),
            cible: Some(format!("+{}", masquer(&texte))),
            vu: None,
        };
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(false));
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            texte,
            "écrite sans valeur d'avant"
        );
        assert!(!c.valeur_admise(None), "une note absente se remettrait");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Correction n° 2 de la 0.94, D-1 : une note de Vanguard pour une entrée d'autostart qui se lance aujourd'hui
    /// mais ne se lit pas bornée (76 Kio, ou pas en UTF-8) : la remettre (une annulation, rebâtie de la note, sans
    /// cible ni valeur vue) n'écrit rien par-dessus, ni le contenu noté ni un retrait ; l'entrée reste à l'octet près.
    #[test]
    fn remise_sur_une_entree_pas_lue_n_ecrit_rien() {
        let base = dossier_jetable("remise-pas-lue");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let gros = format!("[Desktop Entry]\nName=Gros\nExec=gros\n#{}\n", "x".repeat(76 << 10)).into_bytes();
        let latin1 = b"[Desktop Entry]\nName=Caf\xe9\nExec=cafe\n".to_vec();
        for (nom, contenu) in [("gros.desktop", gros), ("latin1.desktop", latin1)] {
            let p = compte.join(nom);
            std::fs::write(&p, &contenu).unwrap();
            let c = Changement::demarrage_depuis(&format!("autostart|{}", p.display())).unwrap();
            assert_eq!(c.lire(), None, "{nom}");
            assert!(!c.entree_lisible(), "{nom}");
            for note in ["+[Desktop Entry]\nName=Ancien\nExec=ancien\n", "-"] {
                assert_eq!(c.ecrire_ici(Some(note)), Some(false), "{nom} {note:?}");
                assert_eq!(std::fs::read(&p).unwrap(), contenu, "{nom} écrasée par {note:?}");
            }
        }
        // Lisible, ou absente : la remise s'écrit comme avant.
        let p = compte.join("lisible.desktop");
        let c = Changement::demarrage_depuis(&format!("autostart|{}", p.display())).unwrap();
        assert!(c.entree_lisible());
        assert_eq!(c.ecrire_ici(Some("+[Desktop Entry]\nName=Remis\n")), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "[Desktop Entry]\nName=Remis\n");
        assert!(
            Changement::demarrage_depuis("systemd|x.service")
                .unwrap()
                .entree_lisible()
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Correction n° 2 de la 0.94, D-2 : masquer ajoute « Hidden=true\n » (12 octets). Une entrée de 65 523 octets
    /// masquée en fait 65 535 et se relit : retirée puis remise à l'octet près. Une de 65 524 octets se lit et se
    /// liste, mais masquée elle ne se relirait plus (ni retrait constaté, ni remise) : refusée avant d'écrire.
    #[test]
    fn entree_trop_grosse_une_fois_masquee_refusee_avant_d_ecrire() {
        let base = dossier_jetable("bord-masque");
        let compte = base.join("autostart");
        std::fs::create_dir_all(&compte).unwrap();
        let entete = "[Desktop Entry]\nName=Bord\nExec=bord\n#";
        let de_taille = |n: usize| format!("{entete}{}\n", "x".repeat(n - entete.len() - 1));
        for (n, permis) in [(65_523, true), (65_524, false), (AUTOSTART_MAX - 1, false)] {
            let texte = de_taille(n);
            assert_eq!(texte.len(), n);
            std::fs::write(compte.join("bord.desktop"), &texte).unwrap();
            let (l, manques) = autostart(&compte, &[], "");
            assert!(manques.is_empty(), "{n} : {manques:?}");
            let [p] = &l[..] else { panic!("{n} : pas listée") };
            let c = &p.changement;
            assert_eq!(c.cible_relisible(), permis, "{n}");
            assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(permis), "{n}");
            let lu = std::fs::read_to_string(compte.join("bord.desktop")).unwrap();
            if permis {
                assert_eq!(c.lire(), c.cible(), "{n} : masquée, pas relue");
                let annuler = Changement::demarrage_depuis(&c.identite_demarrage().unwrap()).unwrap();
                assert_eq!(annuler.ecrire_ici(Some(&format!("+{texte}"))), Some(true), "{n}");
                assert_eq!(std::fs::read_to_string(compte.join("bord.desktop")).unwrap(), texte);
            } else {
                assert_eq!(lu, texte, "{n} : écrite alors qu'elle ne se relirait plus");
            }
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Campagne 0.94, C-1 et C-2 : la liste et le nom d'une entrée se lisent bornés, sans attendre un tube ni suivre
    /// un lien du compte. Une entrée du système trop grosse ou tube, une du compte creuse et géante ou pas en UTF-8
    /// sont dites non lues ; le nom d'une entrée retirée devenue un tube se rend sans attendre, celui d'un lien ne se lit pas à
    /// travers lui.
    #[test]
    fn liste_et_noms_lus_bornes() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let base = dossier_jetable("bornes");
        let (compte, systeme, dehors) = (base.join("compte/autostart"), base.join("systeme"), base.join("dehors"));
        for d in [&compte, &systeme, &dehors] {
            std::fs::create_dir_all(d).unwrap();
        }
        let gros = format!("[Desktop Entry]\nName=Gros\nExec=gros\n#{}\n", "x".repeat(76 << 10));
        std::fs::write(systeme.join("gros-systeme.desktop"), &gros).unwrap();
        std::fs::write(
            compte.join("latin.desktop"),
            b"[Desktop Entry]\nName=Caf\xe9\nExec=cafe\n",
        )
        .unwrap();
        std::fs::File::create(compte.join("creux.desktop"))
            .unwrap()
            .set_len(256 << 20)
            .unwrap();
        crate::essais::tube_nomme(&systeme.join("tube-systeme.desktop")).unwrap();
        let (l, manques) = autostart(&compte, std::slice::from_ref(&systeme), "");
        let noms: Vec<&str> = l.iter().map(|p| p.nom.as_str()).collect();
        assert!(noms.is_empty(), "{noms:?}");
        for nom in [
            "gros-systeme.desktop",
            "tube-systeme.desktop",
            "latin.desktop",
            "creux.desktop",
        ] {
            assert!(manques.iter().any(|m| m.contains(nom)), "{nom} : {manques:?}");
        }
        // Le nom d'une entrée retirée, d'après sa note : un tube à sa place ne fait pas attendre.
        let tube = compte.join("essai-vanguard-tube.desktop");
        crate::essais::tube_nomme(&tube).unwrap();
        let id = format!("autostart|{}", tube.display());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(Changement::nom_demarrage(&id));
        });
        let nom = rx.recv_timeout(std::time::Duration::from_secs(10));
        if nom.is_err() {
            // Débloque la lecture restée en attente d'un écrivain.
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&tube);
        }
        assert_eq!(nom.as_deref().ok(), Some("essai-vanguard-tube"), "figé sur un tube");
        // Un lien vers dehors : son contenu n'est pas lu.
        std::fs::write(dehors.join("cible.desktop"), "[Desktop Entry]\nName=Dehors\n").unwrap();
        let lien = compte.join("essai-vanguard-lien.desktop");
        std::os::unix::fs::symlink(dehors.join("cible.desktop"), &lien).unwrap();
        assert_eq!(
            Changement::nom_demarrage(&format!("autostart|{}", lien.display())),
            "essai-vanguard-lien"
        );
        // Un simple fichier du compte donne son nom.
        let simple = compte.join("essai-vanguard-nom.desktop");
        std::fs::write(&simple, "[Desktop Entry]\nName=Mon lecteur\n").unwrap();
        assert_eq!(
            Changement::nom_demarrage(&format!("autostart|{}", simple.display())),
            "Mon lecteur"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn identite_des_reglages_de_demarrage() {
        let c = Changement::Demarrage {
            entree: Entree::Autostart(PathBuf::from("/home/alice/.config/autostart/essai-vanguard-x.desktop")),
            cible: None,
            vu: None,
        };
        let id = c.identite_demarrage().unwrap();
        assert_eq!(id, "autostart|/home/alice/.config/autostart/essai-vanguard-x.desktop");
        let autostart = Path::new("/home/alice/.config/autostart");
        assert!(matches!(
            Changement::demarrage_depuis_dans(&id, autostart),
            Some(Changement::Demarrage {
                entree: Entree::Autostart(_),
                cible: None,
                vu: None
            })
        ));
        assert_eq!(Changement::nom_demarrage(&id), "essai-vanguard-x");
        // Une note qui viserait autre chose qu'un .desktop d'un dossier autostart, ou un service douteux : refusée.
        for mauvaise in [
            "autostart|/etc/passwd",
            "autostart|relatif/autostart/x.desktop",
            "autostart|/home/alice/.bashrc.desktop",
            "systemd|x;rm -rf ~.service",
            "systemd|.service",
            "systemd|x",
            "inconnu|x",
            // Relecture 0.94, R-8 : un autre dossier nommé autostart que celui du compte, ou plus bas que lui.
            "autostart|/home/alice/projets/autostart/x.desktop",
            "autostart|/home/alice/.config/autostart/autostart/x.desktop",
            "autostart|/home/alice/.config/autostart/../autostart/x.desktop",
            "autostart|/home/alice/.config/autostart/./x.desktop",
            "autostart|/home/bob/.config/autostart/x.desktop",
            "autostart|/etc/xdg/autostart/x.desktop",
        ] {
            assert!(
                Changement::demarrage_depuis_dans(mauvaise, autostart).is_none(),
                "{mauvaise}"
            );
        }
        let s = Changement::demarrage_depuis("systemd|syncthing.service").unwrap();
        assert_eq!(
            s.commande(Some("disabled")).as_deref(),
            Some("systemctl --user disable 'syncthing.service'")
        );
        assert_eq!(
            s.commande(Some("enabled")).as_deref(),
            Some("systemctl --user enable 'syncthing.service'")
        );
        assert_eq!(s.commande(Some("static")), None);
        assert_eq!(Changement::nom_demarrage("systemd|syncthing.service"), "syncthing");
        assert!(!s.admin() && !c.admin());
    }

    #[test]
    fn liens_d_autostart_laisses_tels_quels() {
        // Sous le dossier des essais : la garde (`sous_maison`) n'accepte rien hors de lui ou du dossier personnel.
        let base = dossier_jetable("liens");
        let (compte, systeme, ailleurs) = (base.join("compte"), base.join("systeme"), base.join("dotfiles"));
        for d in [&compte, &systeme, &ailleurs] {
            std::fs::create_dir_all(d).unwrap();
        }
        let entree = |nom: &str| format!("[Desktop Entry]\nType=Application\nName={nom}\nExec={nom}\n");
        std::fs::write(compte.join("note.desktop"), entree("Note")).unwrap();
        // Géré par des dotfiles : un lien vers leur dossier.
        std::fs::write(ailleurs.join("synchro.desktop"), entree("Synchro")).unwrap();
        std::os::unix::fs::symlink(ailleurs.join("synchro.desktop"), compte.join("synchro.desktop")).unwrap();
        // Le système a une entrée du même nom que le lien, et une autre.
        std::fs::write(systeme.join("synchro.desktop"), entree("Synchro du système")).unwrap();
        std::fs::write(systeme.join("horloge.desktop"), entree("Horloge")).unwrap();
        let noms: Vec<String> = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland")
            .0
            .into_iter()
            .map(|p| p.nom)
            .collect();
        assert_eq!(noms, ["Note", "Horloge"]);
        // Le dossier d'autostart du compte lui-même est un lien (vers des dotfiles, ou hors du dossier personnel) :
        // ni ses entrées ni les copies des entrées du système ne sont proposées, rien ne s'écrirait à travers lui.
        // Celles du système restent montrées, chacune « masquage inconnu » (relecture 0.95, H-2) : jamais proposées.
        let lien = base.join("compte-lien");
        std::os::unix::fs::symlink(&ailleurs, &lien).unwrap();
        let (l, manques) = autostart(&lien, std::slice::from_ref(&systeme), "Hyprland");
        let vus: Vec<(&str, &Ecriture)> = l.iter().map(|p| (p.nom.as_str(), &p.ecriture)).collect();
        // Synchro a une entrée à son nom dans le dossier lié : masquée, pas montrée.
        assert_eq!(vus, [("Horloge", &Ecriture::MasquageInconnu)]);
        // T-1 : le dossier refusé est dit une fois, comme non vérifié, et pas chacune de ses entrées.
        assert_eq!(manques.len(), 1, "{manques:?}");
        assert!(
            manques[0].contains("compte-lien") && manques[0].contains("non vérifié"),
            "{manques:?}"
        );
        // T-3 : l'entrée elle-même lien, ou un tube à sa place, est dite non vérifiée, avec son nom.
        crate::essais::tube_nomme(&compte.join("tube.desktop")).unwrap();
        let (_, manques) = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland");
        assert_eq!(manques.len(), 2, "{manques:?}");
        for nom in ["synchro.desktop", "tube.desktop"] {
            assert!(
                manques.iter().any(|m| m.contains(nom) && m.contains("non vérifié")),
                "{nom} : {manques:?}"
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// R-1 (relecture de la correction n° 2 de la 0.94) : un nom de fichier n'est pas du texte. Une entrée au nom
    /// qui n'est pas en UTF-8, du compte ou du système, était convertie avec pertes, relue sous un autre nom,
    /// « introuvable », donc tue : « aucun programme ». Elle est dite non vérifiée, jamais tue, et masque toujours
    /// l'entrée du système au même nom exact.
    #[test]
    fn entree_au_nom_pas_en_utf8_est_dite() {
        use std::os::unix::ffi::OsStrExt as _;
        let base = dossier_jetable("nom-pas-utf8");
        let (compte, systeme) = (base.join("autostart"), base.join("systeme"));
        for d in [&compte, &systeme] {
            std::fs::create_dir_all(d).unwrap();
        }
        let entree = "[Desktop Entry]\nType=Application\nName=Charge\nExec=/usr/bin/charge\n";
        let nom = |octets: &[u8]| std::ffi::OsStr::from_bytes(octets).to_owned();
        std::fs::write(compte.join(nom(b"charge\xff.desktop")), entree).unwrap();
        std::fs::write(systeme.join(nom(b"autre\xfe.desktop")), entree).unwrap();
        // Le même nom exact dans le compte et dans le système : celle du système reste masquée, pas dite deux fois.
        std::fs::write(systeme.join(nom(b"charge\xff.desktop")), entree).unwrap();
        let (l, manques) = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland");
        assert!(l.is_empty(), "{:?}", l.iter().map(|p| &p.nom).collect::<Vec<_>>());
        assert_eq!(manques.len(), 2, "{manques:?}");
        for m in &manques {
            assert!(m.contains("non vérifié") && m.contains("UTF-8"), "{manques:?}");
        }
        assert!(manques.iter().any(|m| m.contains("charge")), "{manques:?}");
        assert!(manques.iter().any(|m| m.contains("autre")), "{manques:?}");
        // Tout le relevé : jamais « aucun programme » sans rien dire.
        let (l, manques, _) = releve_dans(&base, std::slice::from_ref(&systeme), "Hyprland", Some(String::new()));
        assert!(l.is_empty() && manques.len() == 2, "{manques:?}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Relecture 0.94, m-a et m-b. Côté système (XDG_CONFIG_DIRS, une variable que le compte peut changer), un nom
    /// en « .desktop » qui n'est pas un simple fichier (tube, lien vers un tube, dossier) n'est jamais ouvert : il est
    /// dit, avec la bonne raison (« pas un simple fichier », pas « plus de 64 Kio »). Le témoin : un écrivain attend
    /// sur le tube ; une ouverture en lecture le débloquerait.
    #[test]
    fn systeme_pas_un_simple_fichier_ni_ouvert_ni_mal_dit() {
        use std::os::unix::fs::OpenOptionsExt as _;
        let base = dossier_jetable("systeme-pas-fichier");
        let (compte, systeme) = (base.join("autostart"), base.join("systeme"));
        std::fs::create_dir_all(&compte).unwrap();
        std::fs::create_dir_all(systeme.join("dossier.desktop")).unwrap();
        let tube = base.join("tube");
        crate::essais::tube_nomme(&tube).unwrap();
        std::os::unix::fs::symlink(&tube, systeme.join("lien.desktop")).unwrap();
        let (vu, ouvert) = std::sync::mpsc::channel();
        let ecrivain = {
            let tube = tube.clone();
            std::thread::spawn(move || {
                let _f = std::fs::OpenOptions::new().write(true).open(&tube);
                let _ = vu.send(());
            })
        };
        // L'écrivain attend bien sur le tube avant la liste : sinon une ouverture de la liste passerait inaperçue.
        let attente = std::time::Duration::from_millis(200);
        assert!(ouvert.recv_timeout(attente).is_err(), "tube ouvert avant la liste");
        let (l, manques) = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland");
        let ouvert_par_la_liste = ouvert.recv_timeout(std::time::Duration::from_millis(300)).is_ok();
        // L'écrivain libéré dans tous les cas : une lecture qui ne bloque pas l'ouvre.
        let _lecteur = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&tube)
            .unwrap();
        ecrivain.join().unwrap();
        assert!(!ouvert_par_la_liste, "le tube a été ouvert par la liste");
        assert!(l.is_empty());
        assert_eq!(manques.len(), 2, "{manques:?}");
        for nom in ["dossier.desktop", "lien.desktop"] {
            assert!(
                manques
                    .iter()
                    .any(|m| m.contains(nom) && m.contains("pas un simple fichier")),
                "{nom} : {manques:?}"
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// T-5 : systemctl --user qui ne répond pas est un manque ; seule sa sortie en 1 sans rien écrire (aucun service
    /// activé) est une liste vide.
    #[test]
    fn systemctl_du_compte_qui_echoue_est_un_manque() {
        let r = |code: Option<i32>, sortie: &str, erreurs: &str| crate::commande::Resultat {
            code,
            sortie: sortie.to_string(),
            erreurs: erreurs.to_string(),
        };
        assert_eq!(
            services_actives(&r(Some(0), "syncthing.service enabled enabled\n", "")).as_deref(),
            Some("syncthing.service enabled enabled")
        );
        assert_eq!(services_actives(&r(Some(1), "", "")).as_deref(), Some(""));
        assert_eq!(
            services_actives(&r(
                Some(1),
                "",
                "Failed to connect to user scope bus via local transport"
            )),
            None
        );
        assert_eq!(services_actives(&r(Some(1), "x.service enabled enabled", "")), None);
        assert_eq!(services_actives(&r(None, "", "")), None);
        let base = dossier_jetable("systemctl");
        let (l, manques, _) = releve_dans(&base, &[], "Hyprland", None);
        assert!(l.is_empty());
        assert!(manques.iter().any(|m| m.contains("systemctl")), "{manques:?}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// T-3 : un service du compte activé dont le fichier est un lien (« systemctl --user link ») n'est pas proposé,
    /// mais dit non vérifié ; un service du système activé (absent du dossier du compte) n'est pas un manque.
    #[test]
    fn service_du_compte_en_lien_dit_non_verifie() {
        let base = dossier_jetable("service-lien");
        let (unites, ailleurs) = (base.join("systemd/user"), base.join("dotfiles"));
        std::fs::create_dir_all(&unites).unwrap();
        std::fs::create_dir_all(&ailleurs).unwrap();
        std::fs::write(
            ailleurs.join("synchro.service"),
            "[Service]\nExecStart=/usr/bin/synchro\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(ailleurs.join("synchro.service"), unites.join("synchro.service")).unwrap();
        std::fs::write(unites.join("note.service"), "[Service]\nExecStart=/usr/bin/note\n").unwrap();
        let du_systeme = base.join("usr-lib-systemd-user");
        std::fs::create_dir_all(&du_systeme).unwrap();
        std::fs::write(
            du_systeme.join("pipewire.service"),
            "[Service]\nExecStart=/usr/bin/pipewire\n",
        )
        .unwrap();
        let activees =
            "synchro.service enabled enabled\nnote.service enabled enabled\npipewire.service enabled enabled";
        let (l, manques, _) = releve_selon(
            &base,
            &[],
            "Hyprland",
            Some(activees.to_string()),
            Ok(ordre_essai(&base, std::slice::from_ref(&du_systeme))),
            &[du_systeme],
        );
        let noms: Vec<&str> = l.iter().map(|p| p.nom.as_str()).collect();
        assert_eq!(noms, ["note"]);
        assert_eq!(manques.len(), 1, "{manques:?}");
        assert!(
            manques[0].contains("synchro.service") && manques[0].contains("non vérifié"),
            "{manques:?}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// Relecture 0.94, R-7 : le fichier d'une unité du compte se lit borné, sans suivre de lien ni attendre. Trop
    /// gros ou pas en UTF-8 : ni lu ni proposé, mais dit ; jamais proposé avec son nom pour commande. Une unité saine
    /// à côté reste proposée.
    #[test]
    fn unite_du_compte_lue_bornee() {
        let base = dossier_jetable("unite-bornee");
        let unites = base.join("systemd/user");
        std::fs::create_dir_all(&unites).unwrap();
        let mut gros = String::from("[Service]\nExecStart=/usr/bin/gros\n");
        gros.push_str(&"#".repeat(UNITE_MAX));
        std::fs::write(unites.join("gros.service"), gros).unwrap();
        std::fs::write(unites.join("latin.service"), b"[Service]\nExecStart=/usr/bin/caf\xe9\n").unwrap();
        std::fs::write(unites.join("sain.service"), "[Service]\nExecStart=/usr/bin/sain\n").unwrap();
        let activees = "gros.service enabled enabled\nlatin.service enabled enabled\nsain.service enabled enabled";
        let (l, manques, _) = releve_dans(&base, &[], "Hyprland", Some(activees.to_string()));
        let noms: Vec<&str> = l.iter().map(|p| p.nom.as_str()).collect();
        assert_eq!(noms, ["sain"], "{manques:?}");
        for u in ["gros.service", "latin.service"] {
            assert!(
                manques.iter().any(|m| m.contains(u) && m.contains("non vérifié")),
                "{u} : {manques:?}"
            );
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// R-7, par le nom : l'état d'une unité (`etat_unite_selon`) ne se juge pas sur un fichier plus gros que la
    /// borne ; il est laissé à systemctl (`None`), comme un fichier qui ne se lit pas.
    #[test]
    fn etat_d_une_unite_trop_grosse_laisse_a_systemctl() {
        let (d, dossiers) = dossiers_inventes("unite-grosse", true);
        let paquet = &dossiers.paquets[1];
        let mut gros = String::from("[Install]\nWantedBy=default.target\n");
        gros.push_str(&"#".repeat(UNITE_MAX));
        std::fs::write(paquet.join("gros.service"), gros).unwrap();
        std::fs::write(paquet.join("sain.service"), "[Install]\nWantedBy=default.target\n").unwrap();
        assert_eq!(
            etat_unite_selon(&dossiers, "sain.service", Some(false)),
            Some("disabled")
        );
        assert_eq!(etat_unite_selon(&dossiers, "gros.service", Some(false)), None);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// L'ordre de systemd dans un essai : le dossier d'unités de `config`, puis les dossiers du système donnés.
    fn ordre_essai(config: &Path, systeme: &[PathBuf]) -> Vec<PathBuf> {
        std::iter::once(config.join("systemd/user"))
            .chain(systeme.iter().cloned())
            .collect()
    }

    /// C-1 (relecture 0.94) : systemd lance l'unité du premier dossier qui porte son nom. Une unité d'un dossier du
    /// compte qui passe avant le système (~/.local/share/systemd/user, /run/user/…/systemd/user.control) remplace
    /// celle du système au même nom : elle est dite, jamais tue ; un complément du compte (« nom.service.d ») sur une
    /// unité du système aussi. L'unité du système seule, ou devant une copie plus loin, reste tue.
    #[test]
    fn unite_du_compte_qui_masque_le_systeme_est_dite() {
        let base = dossier_jetable("unite-masque");
        let config = base.join("config");
        let (controle, unites, donnees, du_systeme, apres) = (
            base.join("run/systemd/user.control"),
            config.join("systemd/user"),
            base.join("donnees/systemd/user"),
            base.join("usr-lib-systemd-user"),
            base.join("flatpak/systemd/user"),
        );
        for d in [&controle, &unites, &donnees, &du_systeme, &apres] {
            std::fs::create_dir_all(d).unwrap();
        }
        let unite = |d: &Path, nom: &str| {
            std::fs::write(d.join(nom), "[Service]\nExecStart=/usr/bin/x\n").unwrap();
        };
        let ordre = || {
            Ok(vec![
                controle.clone(),
                unites.clone(),
                du_systeme.clone(),
                donnees.clone(),
                apres.clone(),
            ])
        };
        let systeme = std::slice::from_ref(&du_systeme);
        let releve = |activees: &str, ordre: Result<Vec<PathBuf>, crate::machine::temoins::Refus>| {
            releve_selon(&config, &[], "Hyprland", Some(activees.to_string()), ordre, systeme)
        };
        // Témoin : l'unité du système seule, ou devant une copie du compte plus loin dans l'ordre, se tait.
        unite(&du_systeme, "pipewire.service");
        unite(&du_systeme, "wireplumber.service");
        unite(&apres, "wireplumber.service");
        let (l, manques, _) = releve(
            "pipewire.service enabled enabled\nwireplumber.service enabled enabled",
            ordre(),
        );
        assert!(l.is_empty() && manques.is_empty(), "{manques:?}");
        // Le dossier de données du compte passe avant le système dans la vraie liste : la sienne tourne.
        let (l, manques, _) = releve(
            "pipewire.service enabled enabled",
            Ok(vec![unites.clone(), donnees.clone(), du_systeme.clone()]),
        );
        assert!(
            l.is_empty() && manques.is_empty(),
            "rien encore dans les données : {manques:?}"
        );
        unite(&donnees, "pipewire.service");
        let (l, manques, _) = releve(
            "pipewire.service enabled enabled",
            Ok(vec![unites.clone(), donnees.clone(), du_systeme.clone()]),
        );
        assert!(l.is_empty(), "{:?}", l.iter().map(|p| &p.nom).collect::<Vec<_>>());
        assert_eq!(manques.len(), 1, "{manques:?}");
        assert!(
            manques[0].contains("non vérifié") && manques[0].contains("pipewire.service"),
            "{manques:?}"
        );
        // user.control, devant même ~/.config/systemd/user : l'unité lue du compte n'est pas celle qui tourne.
        unite(&unites, "note.service");
        let (l, manques, _) = releve("note.service enabled enabled", ordre());
        assert_eq!(l.len(), 1, "témoin : l'unité du compte se lit");
        assert!(manques.is_empty(), "{manques:?}");
        unite(&controle, "note.service");
        let (l, manques, _) = releve("note.service enabled enabled", ordre());
        assert!(l.is_empty(), "{:?}", l.iter().map(|p| &p.nom).collect::<Vec<_>>());
        assert!(
            manques.len() == 1 && manques[0].contains("non vérifié") && manques[0].contains("note.service"),
            "{manques:?}"
        );
        // Un complément du compte sur l'unité du système (ExecStart changé) : dit, même plus loin dans l'ordre.
        for complement in ["wireplumber.service.d", "service.d"] {
            let c = apres.join(complement);
            std::fs::create_dir_all(&c).unwrap();
            std::fs::write(c.join("x.conf"), "[Service]\nExecStart=\nExecStart=/usr/bin/charge\n").unwrap();
            let (l, manques, _) = releve("wireplumber.service enabled enabled", ordre());
            assert!(l.is_empty());
            assert!(
                manques.len() == 1 && manques[0].contains("changé par le compte") && manques[0].contains(complement),
                "{complement} : {manques:?}"
            );
            std::fs::remove_dir_all(&c).unwrap();
        }
        // Sans la liste de systemd : le manque est dit, et une unité du système ne passe plus pour sûre.
        let (l, manques, _) = releve(
            "pipewire.service enabled enabled",
            Err(crate::machine::temoins::Refus("session inconnue".to_string())),
        );
        assert!(l.is_empty());
        assert_eq!(manques.len(), 2, "{manques:?}");
        assert!(manques.iter().any(|m| m.contains("session inconnue")), "{manques:?}");
        assert!(manques.iter().any(|m| m.contains("pipewire.service")), "{manques:?}");
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// D (relecture 0.94) : les compléments du compte posés sur une unité du système (bt-agent.service.d,
    /// hyprland-focused-booster.service.d) se lisent et se jugent : tus s'ils ne changent rien de ce qui se lance,
    /// dits (avec la clé) sinon, et « non vérifié » s'ils ne se lisent pas. Les alias comptent (F-3).
    #[test]
    fn complement_du_compte_sur_le_systeme_dit_seulement_s_il_change_le_lancement() {
        let base = dossier_jetable("complement-systeme");
        let config = base.join("config");
        let (unites, du_systeme) = (config.join("systemd/user"), base.join("usr-lib-systemd-user"));
        for d in [&unites, &du_systeme] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(du_systeme.join("bt.service"), "[Service]\nExecStart=/usr/bin/bt\n").unwrap();
        let systeme = std::slice::from_ref(&du_systeme);
        let releve = || {
            releve_selon(
                &config,
                &[],
                "Hyprland",
                Some("bt.service enabled enabled".to_string()),
                Ok(ordre_essai(&config, systeme)),
                systeme,
            )
        };
        let c = unites.join("bt.service.d");
        std::fs::create_dir_all(&c).unwrap();
        // Rien qui lance : délais, redémarrage, ordre, description, commentaires, section « X- ».
        std::fs::write(
            c.join("10-calme.conf"),
            "[Unit]\nDescription=calme\nAfter=graphical-session.target\n[Service]\n# ExecStart=/x\nRestart=on-failure\nTimeoutStopSec=5\n[X-Note]\nExecStart=/x\n",
        )
        .unwrap();
        let (l, manques, _) = releve();
        assert!(l.is_empty() && manques.is_empty(), "{manques:?}");
        // Chaque façon de changer ce qui se lance est dite, la clé nommée ; une ligne continuée aussi.
        for (ligne, cle) in [
            ("[Service]\nExecStartPost=/usr/bin/sleep 2\n", "ExecStartPost"),
            ("[Service]\nExecStartPre=/x \\\n  --opt\n", "ExecStartPre"),
            ("[Unit]\nWants=autre.service\n", "Wants"),
            ("[Service]\nEnvironment=LD_PRELOAD=/home/a/x.so\n", "Environment"),
            ("[Service]\nRootDirectory=/home/a/r\n", "RootDirectory"),
            ("Restart=always\n", "Restart"),
            ("[Service]\nn'importe quoi\n", "?"),
        ] {
            std::fs::write(c.join("20-change.conf"), ligne).unwrap();
            let (l, manques, _) = releve();
            assert!(l.is_empty());
            assert!(
                manques.len() == 1
                    && manques[0].contains("changé par le compte")
                    && manques[0].contains("20-change.conf")
                    && manques[0].contains(cle),
                "{ligne:?} : {manques:?}"
            );
        }
        std::fs::remove_file(c.join("20-change.conf")).unwrap();
        // Un alias posé par le compte : ses compléments s'appliquent aussi (F-3).
        std::os::unix::fs::symlink(du_systeme.join("bt.service"), unites.join("copie.service")).unwrap();
        let a = unites.join("copie.service.d");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("x.conf"), "[Service]\nExecStartPre=/home/a/x\n").unwrap();
        let (_, manques, _) = releve();
        assert!(
            manques.len() == 1 && manques[0].contains("copie.service.d") && manques[0].contains("ExecStartPre"),
            "{manques:?}"
        );
        std::fs::remove_dir_all(&a).unwrap();
        // Un complément qui ne se lit pas (tube) ou un dossier de compléments qui ne se liste pas (boucle de liens) :
        // non vérifié, jamais tu.
        let tube = c.join("30-tube.conf");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&tube)
                .status()
                .is_ok_and(|s| s.success())
        );
        let (_, manques, _) = releve();
        assert!(
            manques.len() == 1 && manques[0].contains("non vérifié") && manques[0].contains("30-tube.conf"),
            "{manques:?}"
        );
        std::fs::remove_file(&tube).unwrap();
        let boucle = unites.join("service.d");
        std::os::unix::fs::symlink(&boucle, &boucle).unwrap();
        let (_, manques, _) = releve();
        assert!(
            manques.len() == 1 && manques[0].contains("non vérifié") && manques[0].contains("service.d"),
            "{manques:?}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// D-4 (relecture 0.94) : la commande montrée d'un service du compte est celle que systemd lance, ses
    /// compléments appliqués (« ExecStart= » vide efface, ordre des noms de fichiers, le dossier qui passe devant
    /// masque un même nom, ceux du système aussi) ; un complément qui ne se lit pas est dit.
    #[test]
    fn commande_d_un_service_du_compte_avec_ses_complements() {
        let base = dossier_jetable("commande-complements");
        let config = base.join("config");
        let (unites, du_systeme) = (config.join("systemd/user"), base.join("usr-lib-systemd-user"));
        for d in [&unites, &du_systeme] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(
            unites.join("note.service"),
            "[Unit]\nDescription=ExecStart=/faux\n[Service]\nExecStart=/usr/bin/note\n",
        )
        .unwrap();
        let systeme = std::slice::from_ref(&du_systeme);
        let releve = || {
            releve_selon(
                &config,
                &[],
                "Hyprland",
                Some("note.service enabled enabled".to_string()),
                Ok(ordre_essai(&config, systeme)),
                systeme,
            )
        };
        let commande = || {
            let (l, manques, _) = releve();
            assert_eq!(l.len(), 1, "{manques:?}");
            (l[0].commande.clone(), manques)
        };
        assert_eq!(commande(), ("/usr/bin/note".to_string(), vec![]));
        let c = unites.join("note.service.d");
        std::fs::create_dir_all(&c).unwrap();
        std::fs::write(
            c.join("b.conf"),
            "[Service]\nExecStart=\nExecStart=/home/a/charge \\\n  --vite\n",
        )
        .unwrap();
        assert_eq!(commande().0, "/home/a/charge    --vite");
        // a.conf passe avant b.conf : b efface ce que a pose.
        // V-8 (relecture 0.95) : ce que le complément change d'autre que la commande n'est pas montré ; le dire.
        let (_, manques) = commande();
        assert!(
            manques.len() == 1 && manques[0].contains("complétée par 1 fichier") && manques[0].contains("note.service"),
            "{manques:?}"
        );
        std::fs::write(c.join("a.conf"), "[Service]\nExecStart=/home/a/autre\n").unwrap();
        assert_eq!(commande().0, "/home/a/charge    --vite");
        // c.conf, après : s'ajoute (Type=oneshot).
        std::fs::write(c.join("c.conf"), "[Service]\nExecStart=/home/a/encore\n").unwrap();
        assert_eq!(commande().0, "/home/a/charge    --vite ; /home/a/encore");
        std::fs::remove_file(c.join("c.conf")).unwrap();
        // Le même nom dans un dossier du système, plus loin : masqué par celui du compte.
        let s = du_systeme.join("note.service.d");
        std::fs::create_dir_all(&s).unwrap();
        std::fs::write(s.join("b.conf"), "[Service]\nExecStart=\nExecStart=/usr/bin/masque\n").unwrap();
        assert_eq!(commande().0, "/home/a/charge    --vite");
        // Un autre nom au système, et « service.d » : appliqués aussi, dans l'ordre des noms.
        std::fs::write(s.join("z.conf"), "[Service]\nExecStart=\nExecStart=/usr/bin/systeme\n").unwrap();
        assert_eq!(commande().0, "/usr/bin/systeme");
        let general = unites.join("service.d");
        std::fs::create_dir_all(&general).unwrap();
        std::fs::write(
            general.join("zz.conf"),
            "[Service]\nExecStart=\nExecStart=/home/a/tous\n",
        )
        .unwrap();
        assert_eq!(commande().0, "/home/a/tous");
        std::fs::remove_dir_all(&general).unwrap();
        // Masqué par un lien vers /dev/null : vide.
        std::os::unix::fs::symlink("/dev/null", c.join("z.conf")).unwrap();
        assert_eq!(commande().0, "/home/a/charge    --vite");
        // Un complément qui ne se lit pas : la commande du fichier, et le manque dit.
        let tube = c.join("t.conf");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&tube)
                .status()
                .is_ok_and(|s| s.success())
        );
        let (montree, manques) = commande();
        assert_eq!(montree, "/usr/bin/note");
        assert!(
            manques.len() == 1 && manques[0].contains("peut-être autre") && manques[0].contains("t.conf"),
            "{manques:?}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// V-8 (relecture 0.95) : une unité du compte qui ne se lit pas (ici, pas en UTF-8) ne montre pas son seul nom
    /// en silence : le manque est dit, et elle n'est pas proposée (relecture 0.94, R-7 : pas de valeur d'avant lue).
    #[test]
    fn service_du_compte_illisible_est_dit() {
        let base = dossier_jetable("service-illisible");
        let config = base.join("config");
        let unites = config.join("systemd/user");
        std::fs::create_dir_all(&unites).unwrap();
        std::fs::write(
            unites.join("note.service"),
            b"[Service]\nExecStart=/usr/bin/note \xff\n",
        )
        .unwrap();
        let (l, manques, _) = releve_selon(
            &config,
            &[],
            "Hyprland",
            Some("note.service enabled enabled".to_string()),
            Ok(ordre_essai(&config, &[])),
            &[],
        );
        assert!(
            l.is_empty()
                && manques
                    .iter()
                    .any(|m| m.contains("note.service") && m.contains("pas lu")),
            "{} {manques:?}",
            l.len()
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    /// R-2 (relecture 0.94) : un service activé dont l'unité n'est pas dans ~/.config/systemd/user, ni dans un
    /// dossier d'unités du système, est un manque dit, jamais un silence.
    #[test]
    fn service_du_compte_introuvable_est_dit() {
        use std::os::unix::fs::PermissionsExt;
        let base = dossier_jetable("service-introuvable");
        let (config, donnees, du_systeme) = (base.join("config"), base.join("donnees"), base.join("systeme"));
        for d in [
            config.join("systemd/user"),
            donnees.join("systemd/user"),
            du_systeme.clone(),
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Dans ~/.local/share/systemd/user : de la personne, pas du système ; Vanguard ne l'y lit pas.
        std::fs::write(
            donnees.join("systemd/user/synchro.service"),
            "[Service]\nExecStart=/usr/bin/synchro\n",
        )
        .unwrap();
        std::fs::write(
            du_systeme.join("pipewire.service"),
            "[Service]\nExecStart=/usr/bin/pipewire\n",
        )
        .unwrap();
        let activees = "synchro.service enabled enabled\npipewire.service enabled enabled";
        let systeme = std::slice::from_ref(&du_systeme);
        let (l, manques, _) = releve_selon(
            &config,
            &[],
            "Hyprland",
            Some(activees.to_string()),
            Ok(ordre_essai(&config, systeme)),
            systeme,
        );
        assert!(l.is_empty());
        assert_eq!(manques.len(), 1, "le service du système reste tu : {manques:?}");
        assert!(
            manques[0].contains("synchro.service") && manques[0].contains("non vérifié"),
            "{manques:?}"
        );
        // Le dossier du compte ne se traverse pas : rien n'est pris pour un service du système, même pipewire.
        std::fs::write(
            config.join("systemd/user/note.service"),
            "[Service]\nExecStart=/usr/bin/note\n",
        )
        .unwrap();
        std::fs::set_permissions(config.join("systemd/user"), std::fs::Permissions::from_mode(0o600)).unwrap();
        // En root (verifier.sh, sa passe sous unshare), les droits ne ferment rien : ce cas-là est sauté, et dit.
        if std::fs::metadata(config.join("systemd/user/note.service")).is_ok() {
            crate::essais::saute("dossier fermé traversable quand même ici, root ou espace de noms");
        } else {
            let activees = "note.service enabled enabled\npipewire.service enabled enabled";
            let (l, manques, _) = releve_selon(
                &config,
                &[],
                "Hyprland",
                Some(activees.to_string()),
                Ok(ordre_essai(&config, systeme)),
                systeme,
            );
            assert!(l.is_empty());
            assert_eq!(manques.len(), 2, "{manques:?}");
            assert!(manques.iter().all(|m| m.contains("non vérifié")), "{manques:?}");
        }
        std::fs::set_permissions(config.join("systemd/user"), std::fs::Permissions::from_mode(0o700)).unwrap();
        // Le chemin fixe du système : une unité au nom inventé n'y est pas, elle est dite.
        let (_, manques, _) = releve_dans(
            &config,
            &[],
            "Hyprland",
            Some("vanguard-essai-r2-ailleurs.service enabled enabled".to_string()),
        );
        assert!(
            manques.iter().any(|m| m.contains("vanguard-essai-r2-ailleurs.service")),
            "{manques:?}"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn retirer_n_ecrit_jamais_a_travers_un_dossier_lien() {
        let base = dossier_jetable("dossier-lien");
        let ailleurs = dossier_jetable("dossier-lien-ailleurs");
        std::fs::write(ailleurs.join("note.desktop"), "[Desktop Entry]\nExec=note\n").unwrap();
        std::os::unix::fs::symlink(&ailleurs, base.join("autostart")).unwrap();
        let c = Changement::Demarrage {
            entree: Entree::Autostart(base.join("autostart/note.desktop")),
            cible: None,
            vu: None,
        };
        assert_eq!(c.lire(), None, "pas lu à travers le lien");
        assert_eq!(c.ecrire_ici(Some("+Hidden=true\n")), Some(false));
        assert_eq!(c.ecrire_ici(Some("-")), Some(false));
        assert_eq!(
            std::fs::read_to_string(ailleurs.join("note.desktop")).unwrap(),
            "[Desktop Entry]\nExec=note\n"
        );
        std::fs::remove_dir_all(&base).unwrap();
        std::fs::remove_dir_all(&ailleurs).unwrap();
    }
}
