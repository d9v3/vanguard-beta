//! Réglages de Linux : services de systemd, fichiers de réglage posés par Vanguard, préférences de GNOME, options des
//! distributions (Ubuntu, Debian). Chacun n'est proposé que si cette machine en a l'usage : un SSD pour l'entretien
//! des SSD, GNOME pour ses préférences, le paquet concerné pour les options des distributions.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::demarrage::Programme;
use super::{Categorie, Reglage, Valeur};
use crate::commande::sh_chaine;
use crate::machine::linux::natif;
use crate::ui::*;

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
    /// `None` quand le réglage n'est rebâti que pour être annulé.
    Demarrage { entree: Entree, cible: Option<String> },
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
            .is_ok_and(|n| (MAX_MAP_COUNT_MIN..=i32::MAX as u64).contains(&n)),
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

/// Le fichier d'autostart masqué : « Hidden=true » juste sous [Desktop Entry], à la place de toute autre valeur
/// « Hidden » de ce groupe ; le reste est gardé à l'octet près. Masquer deux fois ne change plus rien.
fn masquer(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len() + 16);
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

/// Les dossiers d'autostart du système (XDG_CONFIG_DIRS, sinon /etc/xdg).
fn dossiers_systeme() -> Vec<PathBuf> {
    std::env::var("XDG_CONFIG_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/etc/xdg".into())
        .split(':')
        .map(|d| Path::new(d).join("autostart"))
        .collect()
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
        Command::new("nmcli").args(["-t", "-e", "no", "-g", propriete, "connection", "show", connexion]),
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
    let r = crate::commande::lancer(Command::new(cmd).args(args), 10)?;
    Some(r.sortie.trim().to_string())
}

impl Changement {
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
                Entree::Autostart(p) => match std::fs::read_to_string(p) {
                    Ok(t) => Some(format!("+{t}")),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("-".to_string()),
                    // Illisible : ni présent ni absent, rien ne doit s'écrire d'après cette lecture.
                    Err(_) => None,
                },
                Entree::Service(u) => etat_unite_lu(u, true),
            },
            Changement::Sysctl { .. }
            | Changement::Pose { .. }
            | Changement::Module { .. }
            | Changement::Droits { .. }
            | Changement::Ntp => self.relever().flatten(),
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
            | Changement::Ntp => "?".to_string(),
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
            | Changement::Ntp => Some("?".to_string()),
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
    /// .desktop d'un dossier autostart, ou un service au nom valide.
    pub fn demarrage_depuis(identite: &str) -> Option<Changement> {
        let (sorte, reste) = identite.split_once('|')?;
        let entree = match sorte {
            "autostart" => {
                let p = PathBuf::from(reste);
                let valide = p.is_absolute()
                    && p.extension().is_some_and(|e| e == "desktop")
                    && p.parent().is_some_and(|d| d.ends_with("autostart"));
                valide.then_some(Entree::Autostart(p))?
            }
            "systemd" => unite_valide(reste).then(|| Entree::Service(reste.to_string()))?,
            _ => return None,
        };
        Some(Changement::Demarrage { entree, cible: None })
    }

    /// Le nom d'un programme d'après l'identité notée : le fichier ou le service, sans extension.
    pub fn nom_demarrage(identite: &str) -> String {
        let reste = identite.split_once('|').map_or(identite, |(_, r)| r);
        let p = Path::new(reste);
        // Une entrée d'autostart : le nom qu'affiche son fichier, celui du compte ou celui du système au même nom.
        if identite.starts_with("autostart|")
            && let Some(fichier) = p.file_name()
        {
            let nom = std::iter::once(p.to_path_buf())
                .chain(dossiers_systeme().into_iter().map(|d| d.join(fichier)))
                .find_map(|f| champ(&std::fs::read_to_string(f).ok()?, "Name").map(str::to_string));
            if let Some(nom) = nom {
                return nom;
            }
        }
        p.file_stem()
            .map_or_else(|| reste.to_string(), |n| n.to_string_lossy().into_owned())
    }

    /// Écrit ce qui est propre au compte sans passer par une commande : le fichier d'autostart, son contenu entier
    /// remis à l'octet près, ou retiré. `None` : ce changement passe par une commande.
    fn ecrire_ici(&self, v: Option<&str>) -> Option<bool> {
        let Changement::Demarrage {
            entree: Entree::Autostart(p),
            ..
        } = self
        else {
            return None;
        };
        Some(match v {
            Some(t) if t.starts_with('+') => {
                p.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok())
                    && crate::socle::ecrire_atomique(p, &t[1..]).is_ok()
            }
            Some("-") => match std::fs::remove_file(p) {
                Ok(()) => true,
                Err(e) => e.kind() == std::io::ErrorKind::NotFound,
            },
            _ => false,
        })
    }

    /// La valeur notée `v` a-t-elle une forme que ce changement peut écrire ? Elle est remise avec sudo (ou dans le
    /// compte) : un ensemble fermé, ou une forme stricte, jamais un texte libre venu d'un fichier que tout programme
    /// du compte peut réécrire.
    pub fn valeur_admise(&self, v: Option<&str>) -> bool {
        let Some(v) = v else {
            // Absente (ligne, préférence, fichier, module) : se remet en retirant, rien d'autre.
            return !matches!(
                self,
                Changement::Dns { .. } | Changement::Sysctl { .. } | Changement::Droits { .. } | Changement::Ntp
            );
        };
        match self {
            Changement::Unite { .. } => ETATS_UNITE.contains(&v),
            Changement::Fichier { .. } => matches!(v, "present" | "autre"),
            Changement::Gnome { cible, defaut, .. } => v == *cible || v == *defaut || super::gvariant_simple(v),
            Changement::Option { cible, defaut, .. } => v == *cible || v == *defaut || super::jeton_simple(v),
            Changement::Dns { connexion, .. } => dns_admis(connexion, v),
            Changement::Demarrage { entree, .. } => match entree {
                // Le fichier d'autostart du compte, remis à l'octet près : il s'écrit sans droits, dans le compte.
                Entree::Autostart(_) => v == "-" || (v.starts_with('+') && v.len() <= 64 << 10 && !v.contains('\0')),
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
        }
    }

    /// La commande qui pose la valeur `v` d'un réglage de DNS (mode Wi-Fi public).
    pub fn commande_dns(&self, v: &str) -> Option<String> {
        matches!(self, Changement::Dns { .. })
            .then(|| self.commande(Some(v)))
            .flatten()
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
                        Some(_) => trf!("{f} : remis comme avant", "{f}: put back as before"),
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
        }
    }

    /// La commande qui met la valeur `v`.
    pub(super) fn commande(&self, v: Option<&str>) -> Option<String> {
        Some(match self {
            Changement::Unite { nom, .. } => match v? {
                e @ ("enabled" | "disabled" | "masked") => format!("sudo systemctl {} --now {nom}", etat_unite(e)),
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
            Changement::Droits { chemin } => {
                let v = v.filter(|v| super::annulables::droits_admis(v))?;
                format!("chmod {v} {}", sh_chaine(&chemin.display().to_string()))
            }
            Changement::Ntp => match v? {
                "yes" => "sudo timedatectl set-ntp true".to_string(),
                "no" => "sudo timedatectl set-ntp false".to_string(),
                _ => return None,
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
    let mut commandes: Vec<Vec<String>> = lots
        .iter()
        .map(|lot| lot.iter().filter_map(|(c, v)| c.commande(v.as_deref())).collect())
        .collect();
    commandes.extend(en_plus.iter().cloned());
    let mut resultats = crate::machine::appliquer_chacune(&commandes);
    let plus = resultats.split_off(lots.len().min(resultats.len()));
    // Ce qui est propre au compte et s'écrit sans commande (fichiers d'autostart), montré comme une commande.
    for (lot, ok) in lots.iter().zip(resultats.iter_mut()) {
        for (c, v) in lot {
            if let Some(ecrit) = c.ecrire_ici(v.as_deref()) {
                println!("    {GRIS}{}{RESET}", c.decrire(v.as_deref()));
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
    let maison = crate::socle::maison();
    let config = std::env::var_os("XDG_CONFIG_HOME").map_or_else(|| maison.join(".config"), PathBuf::from);
    let systeme = dossiers_systeme();
    let bureau = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let mut l = autostart(&config.join("autostart"), &systeme, &bureau);
    let dossier = config.join("systemd/user");
    let activees = sortie(
        "systemctl",
        &[
            "--user",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    for unite in activees.lines().filter_map(|l| l.split_whitespace().next()) {
        if unite_valide(unite) && fichier_ordinaire(&dossier.join(unite)) {
            let texte = std::fs::read_to_string(dossier.join(unite)).unwrap_or_default();
            l.push(Programme {
                nom: unite.trim_end_matches(".service").to_string(),
                commande: texte
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("ExecStart="))
                    .unwrap_or(unite)
                    .to_string(),
                actif: true,
                machine: false,
                bureau: false,
                changement: Changement::Demarrage {
                    entree: Entree::Service(unite.to_string()),
                    cible: Some("disabled".to_string()),
                },
            });
        }
    }
    l
}

/// Un vrai fichier, pas un lien. Une entrée d'autostart ou une unité de systemd du compte qui est un lien vient d'un
/// gestionnaire de configuration (dotfiles, stow, home-manager) : l'écrire remplacerait le lien par un fichier, et
/// `systemctl disable` retire aussi le lien d'une unité ajoutée par `systemctl link`. Rien ne s'annulerait exactement :
/// Vanguard n'y touche pas.
fn fichier_ordinaire(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_file())
}

/// Les entrées d'autostart : chaque fichier .desktop du compte, puis celles du système au nom qu'il n'a pas et qui se
/// lancent sur ce bureau (une entrée pour un autre bureau, ou déjà masquée, n'a rien à retirer). Une entrée du compte
/// qui est un lien n'est pas proposée, ni celle du système qu'elle remplace.
fn autostart(compte: &Path, systeme: &[PathBuf], bureau: &str) -> Vec<Programme> {
    let fichiers = |d: &Path| -> Vec<(String, String)> {
        let mut l: Vec<(String, String)> = std::fs::read_dir(d)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|f| f.path().extension().is_some_and(|e| e == "desktop") && f.path().is_file())
            .filter_map(|f| {
                let texte = std::fs::read_to_string(f.path()).ok()?;
                Some((f.file_name().to_string_lossy().into_owned(), texte))
            })
            .collect();
        l.sort();
        l
    };
    let mut vus: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut l = Vec::new();
    for (nom, texte) in fichiers(compte) {
        if fichier_ordinaire(&compte.join(&nom)) {
            l.push(programme_autostart(compte.join(&nom), &texte, bureau));
        }
        vus.insert(nom);
    }
    for d in systeme {
        for (nom, texte) in fichiers(d) {
            if vus.insert(nom.clone()) && crate::lenteur::entree_autostart(&texte, bureau).is_some() {
                l.push(programme_autostart(compte.join(&nom), &texte, bureau));
            }
        }
    }
    l
}

/// Une entrée d'autostart : `chemin`, le fichier du compte où elle se masque (sa copie, pour une entrée du système).
fn programme_autostart(chemin: PathBuf, texte: &str, bureau: &str) -> Programme {
    let actif = crate::lenteur::entree_autostart(texte, bureau);
    let nom = actif
        .as_ref()
        .map(|(n, _)| n.clone())
        .or_else(|| champ(texte, "Name").map(str::to_string))
        .unwrap_or_else(|| Changement::nom_demarrage(&chemin.display().to_string()));
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
        },
    }
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
    // SAFETY: getuid ne peut pas échouer et ne touche à aucune mémoire du programme.
    let uid = unsafe { libc::getuid() };
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
    if !fichier_ordinaire(&fichier) {
        return None;
    }
    installable(&std::fs::read_to_string(&fichier).ok()?).then_some("disabled")
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

#[cfg(test)]
mod tests {
    use super::*;

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
            Some("sudo systemctl enable --now fstrim.timer")
        );
        assert_eq!(u.commande(Some("static")), None);
    }

    /// Les commandes d'une option, lancées pour de vrai sur un fichier jetable (sans sudo) : une valeur aux caractères
    /// spéciaux revient telle quelle, et « absente » retire la ligne.
    #[test]
    fn option_posee_remise_puis_retiree() {
        let f = std::env::temp_dir().join(format!("vanguard-test-option-sed-{}", std::process::id()));
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
        };
        assert!(service.valeur_admise(Some("disabled")) && !service.valeur_admise(Some("on")));
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
        let d = std::env::temp_dir().join(format!("vanguard-optimiser-unites-{nom}-{}", std::process::id()));
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
        // SAFETY: getuid ne peut pas échouer et ne touche à aucune mémoire du programme.
        let uid = unsafe { libc::getuid() };
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
        let f = std::env::temp_dir().join(format!("vanguard-test-option-{}", std::process::id()));
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
        let d = std::env::temp_dir().join(format!("vanguard-test-demarrage-{nom}-{}", std::process::id()));
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
        let l = autostart(&compte, std::slice::from_ref(&systeme), "Hyprland");
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
        };
        let avant = c.lire();
        assert_eq!(c.ecrire_ici(c.cible().as_deref()), Some(true));
        assert_eq!(c.lire(), c.cible());
        assert_eq!(c.ecrire_ici(avant.as_deref()), Some(true));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), original);

        let q = compte.join("syncthing.desktop");
        let s = Changement::Demarrage {
            entree: Entree::Autostart(q.clone()),
            cible: Some("+[Desktop Entry]\nHidden=true\nName=Syncthing\n".to_string()),
        };
        let avant = s.lire();
        assert_eq!(avant.as_deref(), Some("-"));
        assert_eq!(s.ecrire_ici(s.cible().as_deref()), Some(true));
        assert!(q.is_file());
        assert_eq!(s.ecrire_ici(avant.as_deref()), Some(true));
        assert!(!q.exists());
        // Une valeur qu'on n'a pas su lire ne s'écrit jamais.
        assert_eq!(s.ecrire_ici(Some("?")), Some(false));
        assert!(s.decrire(Some("-")).contains("syncthing.desktop"));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn identite_des_reglages_de_demarrage() {
        let c = Changement::Demarrage {
            entree: Entree::Autostart(PathBuf::from("/home/alice/.config/autostart/essai-vanguard-x.desktop")),
            cible: None,
        };
        let id = c.identite_demarrage().unwrap();
        assert_eq!(id, "autostart|/home/alice/.config/autostart/essai-vanguard-x.desktop");
        assert!(matches!(
            Changement::demarrage_depuis(&id),
            Some(Changement::Demarrage {
                entree: Entree::Autostart(_),
                cible: None
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
        ] {
            assert!(Changement::demarrage_depuis(mauvaise).is_none(), "{mauvaise}");
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
        let base = crate::protection::isoler::dossier_jetable().unwrap();
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
            .into_iter()
            .map(|p| p.nom)
            .collect();
        assert_eq!(noms, ["Note", "Horloge"]);
        assert!(fichier_ordinaire(&compte.join("note.desktop")));
        assert!(!fichier_ordinaire(&compte.join("synchro.desktop")));
        assert!(!fichier_ordinaire(&compte.join("absent.desktop")));
        std::fs::remove_dir_all(&base).unwrap();
    }
}
