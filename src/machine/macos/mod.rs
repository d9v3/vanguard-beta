//! Audit de sécurité macOS (12 Monterey et plus récents), sans droits administrateur. Les corrections passent par
//! `sudo` dans le Terminal, après accord, comme sous Linux.
//!
//! Écrit sans Mac sous la main : les lectures sont vérifiées par les tests automatiques sur les Mac de GitHub
//! (.github/workflows/macos.yml), et une vérification qui échoue le dit (« Impossible de vérifier ») plutôt que de conclure.

use std::path::PathBuf;

use super::{Audit, Constat, alerte, cles_ssh, impossible, ok, sortie};
use crate::plist::Valeur;
use crate::risk::{Niveau, info_port};
use crate::{tr, trf};

pub(crate) mod config_reseau;
#[cfg(test)]
pub(crate) mod corpus;
mod durcissement;
mod maj;
pub(crate) mod noyau;
mod parite;
mod persistance;
mod privileges;
mod protection;
mod regles;

pub use maj::mises_a_jour_completes;
use persistance::persistance;

pub const NOM: &str = "macOS";

/// Famille de processeur, comme Apple la nomme.
pub fn architecture() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "Apple Silicon"
    } else {
        "Intel"
    }
}

/// socketfilterfw fait foi (outil gardé, §4) : com.apple.alf.plist n'est plus une source sûre depuis macOS 15, qui a
/// déplacé ces réglages. Lancé sans shell pour la lecture ; ses corrections, montrées, passent par sudo.
const PARE_FEU: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";

/// Commande d'installation d'un outil (Homebrew, le gestionnaire de paquets des Mac).
pub fn commande_installation(paquet: &str) -> String {
    if homebrew().is_some() {
        format!("brew install {paquet}")
    } else {
        trf!(
            "installer Homebrew (https://brew.sh), puis : brew install {paquet}",
            "install Homebrew (https://brew.sh), then: brew install {paquet}"
        )
    }
}

/// Programme brew, s'il est installé (Apple Silicon : /opt/homebrew, Intel : /usr/local).
pub fn homebrew() -> Option<&'static str> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())
}

/// Installation officielle de Homebrew : le script demande le mot de passe et explique ce qu'il fait.
pub const INSTALLER_HOMEBREW: &str =
    "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"";

/// Le programme brew : celui qui est installé, sinon l'endroit où l'installation officielle le mettra.
pub fn brew() -> &'static str {
    homebrew().unwrap_or(if cfg!(target_arch = "aarch64") {
        "/opt/homebrew/bin/brew"
    } else {
        "/usr/local/bin/brew"
    })
}

/// Commandes qui installent une application avec Homebrew (« cask »). Sans Homebrew, on l'installe d'abord.
pub fn installer_cask(cask: &str) -> Vec<String> {
    let installer = format!("{} install --cask {cask}", brew());
    if homebrew().is_some() {
        vec![installer]
    } else {
        vec![INSTALLER_HOMEBREW.into(), installer]
    }
}

/// Application présente dans /Applications ou ~/Applications (installée par Homebrew ou à la main).
pub fn app_installee(nom: &str) -> bool {
    [PathBuf::from("/Applications"), maison().join("Applications")]
        .iter()
        .any(|d| d.join(format!("{nom}.app")).is_dir())
}

use crate::socle::maison;

/// Les réglages d'un domaine de préférences, lus dans leur fichier.
enum Reglages {
    Lus(Valeur),
    Absents,
    /// Fichier interdit ou d'un format inconnu : à demander à `defaults`.
    Illisibles,
}

/// Le fichier d'un domaine, comme `defaults` le comprend : un chemin sans « .plist », le domaine global (« -g »), ou
/// un domaine du compte.
fn fichier_preferences(domaine: &str) -> PathBuf {
    if domaine.starts_with('/') {
        PathBuf::from(format!("{domaine}.plist"))
    } else if domaine == "-g" || domaine == "NSGlobalDomain" {
        maison().join("Library/Preferences/.GlobalPreferences.plist")
    } else {
        maison().join("Library/Preferences").join(format!("{domaine}.plist"))
    }
}

fn reglages(domaine: &str) -> Reglages {
    match crate::plist::lire_fichier(&fichier_preferences(domaine)) {
        Ok(crate::plist::Lu::Plist(r @ Valeur::Dico(_))) => Reglages::Lus(r),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Reglages::Absents,
        _ => Reglages::Illisibles,
    }
}

/// Lit une préférence système, ce que donne `defaults read <domaine> <clé>` ; `None` si elle n'existe pas. Le fichier
/// est lu directement ; `defaults` ne sert plus qu'en secours, quand il est illisible. Une clé absente du fichier
/// n'est pas redemandée à `defaults` : c'est voulu, un programme de moins par lecture. Le prix : `defaults` passe par
/// cfprefsd, qui peut tenir une valeur changée dans Réglages Système il y a quelques secondes et pas encore écrite
/// sur le disque ; pour `-g` ou com.apple.sharingd, ce changement tout récent est manqué jusqu'au prochain vidage.
/// Pour les domaines de /Library/Preferences lus en tant qu'utilisateur, sans effet (pas de cache utilisateur).
pub(crate) fn preference(domaine: &str, cle: &str) -> Option<String> {
    let defaults = || sortie("defaults", &["read", domaine, cle]).map(|s| s.trim().to_string());
    match reglages(domaine) {
        Reglages::Lus(r) => r
            .cle(cle)
            .and_then(|v| v.comme_defaults().map(|s| s.trim().to_string()).or_else(defaults)),
        Reglages::Absents => None,
        Reglages::Illisibles => defaults(),
    }
}

/// Une valeur de SystemVersion.plist (« ProductName », « ProductVersion », « ProductBuildVersion »), ce qu'affiche
/// `sw_vers` ; lui en secours.
pub fn version_systeme(cle: &str) -> Option<String> {
    let lue = crate::plist::lire_fichier(std::path::Path::new("/System/Library/CoreServices/SystemVersion.plist"))
        .ok()
        .and_then(crate::plist::Lu::valeur)
        .and_then(|v| v.cle(cle)?.texte().map(str::to_string));
    if lue.is_some() {
        return lue;
    }
    let option = match cle {
        "ProductName" => "-productName",
        "ProductVersion" => "-productVersion",
        "ProductBuildVersion" => "-buildVersion",
        _ => return None,
    };
    sortie("sw_vers", &[option]).map(|s| s.trim().to_string())
}

/// « Firewall is enabled. (State = 1) » ; « State = 2 » : tout bloquer sauf l'essentiel.
fn lire_pare_feu(sortie: &str) -> Option<bool> {
    if sortie.contains("disabled") || sortie.contains("State = 0") {
        Some(false)
    } else if sortie.contains("enabled") || sortie.contains("State = 1") || sortie.contains("State = 2") {
        Some(true)
    } else {
        None
    }
}

fn pare_feu() -> Constat {
    match sortie(PARE_FEU, &["--getglobalstate"]).as_deref().and_then(lire_pare_feu) {
        Some(true) => ok("Pare-feu", tr!("Le pare-feu de macOS est actif.", "The macOS firewall is on.")),
        Some(false) => alerte(
            "Pare-feu",
            Niveau::Eleve,
            tr!(
                "Le pare-feu de macOS est désactivé : les programmes de ce Mac peuvent recevoir des connexions de tout le réseau.",
                "The macOS firewall is off: the programs on this Mac can receive connections from the whole network."
            ),
        )
        .corriger(
            tr!("Activer le pare-feu de macOS", "Turn on the macOS firewall"),
            &[format!("sudo {PARE_FEU} --setglobalstate on")],
        )
        .protection(),
        None => impossible("Pare-feu", tr!("socketfilterfw illisible", "socketfilterfw unreadable")),
    }
}

/// Mode furtif : le Mac ne répond pas aux sondes (ping…) du réseau. Utile sur les Wi-Fi publics.
fn mode_furtif() -> Constat {
    let Some(texte) = sortie(PARE_FEU, &["--getstealthmode"]) else {
        return impossible(
            "Pare-feu",
            tr!(
                "mode furtif illisible (socketfilterfw)",
                "stealth mode unreadable (socketfilterfw)"
            ),
        );
    };
    if texte.contains("enabled") || texte.contains("is on") {
        return ok("Pare-feu", tr!("Mode furtif actif.", "Stealth mode on."));
    }
    alerte(
        "Pare-feu",
        Niveau::Info,
        tr!(
            "Mode furtif désactivé : ce Mac répond aux sondes du réseau, ce qui le rend visible sur un Wi-Fi public.",
            "Stealth mode off: this Mac answers network probes, which makes it visible on public Wi-Fi."
        ),
    )
    .corriger(
        tr!("Activer le mode furtif", "Turn on stealth mode"),
        &[format!("sudo {PARE_FEU} --setstealthmode on")],
    )
    .protection()
}

/// Service de partage de macOS derrière un port, et où le couper.
fn partage(port: u16) -> Option<&'static str> {
    Some(match port {
        22 => tr!("Session à distance (Remote Login, SSH)", "Remote Login (SSH)"),
        445 | 139 | 548 => tr!("Partage de fichiers", "File Sharing"),
        5900 => tr!("Partage d'écran", "Screen Sharing"),
        3283 => tr!("Gestion à distance", "Remote Management"),
        3031 => tr!("Événements Apple à distance", "Remote Apple Events"),
        5000 | 7000 => tr!("Récepteur AirPlay", "AirPlay Receiver"),
        3689 => tr!("Partage de médias", "Media Sharing"),
        631 => tr!("Partage d'imprimantes", "Printer Sharing"),
        _ => return None,
    })
}

/// Serveur SSH (Remote Login) : jugé seulement s'il écoute le réseau sur le port 22. netstat fait foi pour les prises
/// de tous les comptes (sshd tourne en root) : leurs structures dans le noyau (xinpcb_n) sont privées.
fn ssh_serveur() -> Constat {
    let Some(netstat) = sortie("netstat", &["-an", "-p", "tcp"]) else {
        return impossible("SSH", tr!("netstat indisponible", "netstat unavailable"));
    };
    let ecoute = super::unix::lire_netstat(&netstat, true)
        .iter()
        .any(|(adresse, port)| *port == 22 && !(adresse.starts_with("127.") || adresse == "::1"));
    if !ecoute {
        return super::sans_objet(
            "SSH",
            crate::modele::Absence::Inactif,
            tr!(
                "Session à distance (SSH) fermée au réseau : rien à juger.",
                "Remote Login (SSH) closed to the network: nothing to judge."
            ),
        );
    }
    let Some(conf) = super::unix::configuration_sshd() else {
        return impossible(
            "SSH",
            tr!("configuration de sshd illisible", "sshd configuration unreadable"),
        );
    };
    super::unix::juger_sshd_mac(&conf).unwrap_or_else(|| {
        ok(
            "SSH",
            tr!(
                "Session à distance ouverte au réseau, sans compte sans mot de passe ni connexion en root.",
                "Remote Login open to the network, without passwordless accounts or root logins."
            ),
        )
    })
}

/// Les ports ouverts au réseau : netstat pour ceux de tous les comptes (il fait foi : xinpcb_n est privé), les noms
/// des programmes du compte lus au noyau (lsof en secours).
fn ports_ecoute(pare_feu_actif: bool) -> Vec<Constat> {
    let programmes = super::programmes_en_ecoute();
    let mut constats = Vec::new();
    let mut vus = Vec::new();
    for (proto, tcp) in [("tcp", true), ("udp", false)] {
        let Some(netstat) = sortie("netstat", &["-an", "-p", proto]) else {
            return vec![impossible(
                "Ports en écoute",
                tr!("netstat indisponible", "netstat unavailable"),
            )];
        };
        for (adresse, port) in super::unix::lire_netstat(&netstat, tcp) {
            let local = adresse.starts_with("127.") || adresse == "::1" || adresse.starts_with("fe80:");
            let i = info_port(port);
            // UDP : Bonjour (5353) et le service de noms NetBIOS (137, 138, netbiosd) font partie de macOS ; ports
            // éphémères anonymes = sockets clientes.
            let bruit = !tcp
                && (matches!(port, 5353 | 137 | 138 | 68) || (port >= 49152 && i.service == crate::risk::inconnu()));
            if local || bruit || vus.contains(&(proto, port)) {
                continue;
            }
            vus.push((proto, port));
            let programme = programmes
                .get(&port)
                .map_or(tr!("programme du système", "system program"), String::as_str);
            let (_, constat) = super::port_expose(port, proto, &i, programme, pare_feu_actif);
            // Le nom lu (noyau ou lsof), jamais « programme du système » traduit : la clé ne dépend pas de la langue.
            let constat = constat.avec_objet(crate::modele::Objet::port(
                port,
                proto,
                programmes.get(&port).map(String::as_str),
            ));
            constats.push(match partage(port) {
                Some(service) => constat.manuel(
                    trf!(
                        "Si vous ne vous en servez pas : Réglages Système > Général > Partage > désactiver « {service} »",
                        "If you do not use it: System Settings > General > Sharing > turn off “{service}”"
                    ),
                    &[],
                ),
                None => constat,
            });
        }
    }
    if constats.is_empty() {
        constats.push(super::aucun_port_expose());
    }
    constats
}

fn chiffrement_disque() -> Constat {
    let Some(etat) = sortie("fdesetup", &["status"]) else {
        return impossible("Chiffrement", tr!("fdesetup illisible", "fdesetup unreadable"));
    };
    if etat.contains("FileVault is On") || etat.contains("Encryption in progress") {
        ok(
            "Chiffrement",
            tr!("Disque chiffré (FileVault).", "Disk encrypted (FileVault)."),
        )
    } else {
        alerte(
            "Chiffrement",
            Niveau::Eleve,
            tr!(
                "FileVault est désactivé : un Mac perdu ou volé livre tous ses fichiers à qui le démarre sur un autre système.",
                "FileVault is off: a lost or stolen Mac hands over all its files to anyone who boots it on another system."
            ),
        )
        .manuel(
            tr!(
                "Réglages Système > Confidentialité et sécurité > FileVault > Activer (garder la clé de secours en lieu sûr)",
                "System Settings > Privacy & Security > FileVault > Turn On (keep the recovery key somewhere safe)"
            ),
            &[],
        )
    }
}

/// Gatekeeper (seuls les programmes signés et vérifiés par Apple s'ouvrent sans avertissement) et SIP (les
/// fichiers du système sont protégés, même contre l'administrateur).
fn protection_systeme() -> Vec<Constat> {
    let mut constats = Vec::new();
    match sortie("spctl", &["--status"]) {
        Some(s) if s.contains("enabled") => constats.push(ok(
            "Protection système",
            tr!("Gatekeeper actif.", "Gatekeeper on."),
        )),
        Some(_) => constats.push(
            alerte(
                "Protection système",
                Niveau::Eleve,
                tr!(
                    "Gatekeeper est désactivé : n'importe quel programme téléchargé s'ouvre sans la moindre vérification.",
                    "Gatekeeper is off: any downloaded program opens without any check."
                ),
            )
            .corriger(
                tr!("Réactiver Gatekeeper", "Turn Gatekeeper back on"),
                &["sudo spctl --global-enable 2>/dev/null || sudo spctl --master-enable"],
            )
            .protection(),
        ),
        None => constats.push(impossible("Protection système", tr!("spctl illisible", "spctl unreadable"))),
    }
    constats.push(sip());
    constats
}

/// SIP : demandé au noyau (csr_get_active_config, cherché par dlsym), `csrutil status` en secours et comme oracle
/// (noyau.rs). Entier quand aucun drapeau n'est posé ; « enabled (Custom Configuration) » de csrutil, une exception
/// faite par `csrutil enable --without …`, est un SIP réduit.
fn sip() -> Constat {
    let sain = || {
        ok(
            "Protection système",
            tr!(
                "Protection de l'intégrité du système (SIP) active.",
                "System Integrity Protection (SIP) on."
            ),
        )
    };
    let reduit = |drapeaux: &str| {
        alerte(
            "Protection système",
            Niveau::Eleve,
            if drapeaux.is_empty() {
                tr!(
                    "La protection de l'intégrité du système (SIP) est désactivée ou réduite : un programme administrateur peut modifier macOS lui-même.",
                    "System Integrity Protection (SIP) is off or reduced: an administrator program can modify macOS itself."
                )
                .to_string()
            } else {
                trf!(
                    "La protection de l'intégrité du système (SIP) est désactivée ou réduite ({drapeaux}) : un programme administrateur peut modifier macOS lui-même.",
                    "System Integrity Protection (SIP) is off or reduced ({drapeaux}): an administrator program can modify macOS itself."
                )
            },
        )
        .manuel(
            tr!(
                "Redémarrer en mode de secours (bouton d'alimentation maintenu sur Apple Silicon, Cmd-R sur Intel), Utilitaires > Terminal : csrutil enable, puis redémarrer",
                "Restart in Recovery (hold the power button on Apple Silicon, Cmd-R on Intel), Utilities > Terminal: csrutil enable, then restart"
            ),
            &[],
        )
    };
    if let Some(config) = noyau::sip() {
        let drapeaux = crate::machine::darwin::drapeaux_sip(config);
        return if drapeaux.is_empty() {
            sain()
        } else {
            reduit(&drapeaux.join(", "))
        };
    }
    match sortie("csrutil", &["status"]) {
        Some(s) if s.contains("status: enabled.") => sain(),
        Some(_) => reduit(""),
        None => impossible("Protection système", tr!("csrutil illisible", "csrutil unreadable")),
    }
}

/// Mot de passe à la sortie de veille.
#[derive(Debug, PartialEq)]
enum Verrouillage {
    Coupe,
    /// Délai avant que le mot de passe soit demandé, en secondes.
    Delai(u64),
}

/// « screenLock delay is immediate » / « screenLock delay is 300 seconds » / « screenLock is off » (sur la sortie
/// d'erreur).
fn lire_verrouillage(texte: &str) -> Option<Verrouillage> {
    if texte.contains("screenLock is off") {
        return Some(Verrouillage::Coupe);
    }
    let delai = texte.split_once("screenLock delay is ")?.1;
    if delai.starts_with("immediate") {
        return Some(Verrouillage::Delai(0));
    }
    delai.split_whitespace().next()?.parse().ok().map(Verrouillage::Delai)
}

fn verrouillage_ecran() -> Option<Constat> {
    let r = crate::commande::lancer(
        std::process::Command::new("sysadminctl").args(["-screenLock", "status"]),
        15,
    )?;
    let etat = lire_verrouillage(&format!("{}\n{}", r.sortie, r.erreurs))?;
    let reglage = tr!(
        "Réglages Système > Écran de verrouillage > « Exiger le mot de passe après le début de l'économiseur ou la suspension de l'écran » : immédiatement",
        "System Settings > Lock Screen > “Require password after screen saver begins or display is turned off”: immediately"
    );
    Some(match etat {
        Verrouillage::Coupe => alerte(
            "Verrouillage",
            Niveau::Moyen,
            tr!(
                "Aucun mot de passe n'est demandé à la sortie de veille : quiconque passe devant le Mac y a accès.",
                "No password is asked when waking up: anyone walking by the Mac gets in."
            ),
        )
        .manuel(reglage, &[]),
        Verrouillage::Delai(s) if s > 300 => alerte(
            "Verrouillage",
            Niveau::Info,
            trf!(
                "Le mot de passe n'est demandé que {} min après la mise en veille de l'écran.",
                "The password is only asked {} min after the display sleeps.",
                s / 60
            ),
        )
        .manuel(reglage, &[]),
        Verrouillage::Delai(_) => ok(
            "Verrouillage",
            tr!(
                "Mot de passe demandé à la sortie de veille.",
                "Password asked when waking up."
            ),
        ),
    })
}

/// Session ouverte automatiquement au démarrage, et compte invité.
fn ouverture_de_session() -> Vec<Constat> {
    let mut constats = Vec::new();
    if let Some(compte) = preference("/Library/Preferences/com.apple.loginwindow", "autoLoginUser") {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Moyen,
                trf!(
                    "La session de « {compte} » s'ouvre toute seule au démarrage : un Mac volé s'allume directement sur vos fichiers (et FileVault ne peut pas protéger le disque).",
                    "“{compte}”'s session opens by itself at startup: a stolen Mac boots straight into your files (and FileVault cannot protect the disk)."
                ),
            )
            .corriger(
                tr!(
                    "Désactiver l'ouverture de session automatique",
                    "Turn off automatic login"
                ),
                &[
                    "sudo defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser",
                    "sudo rm -f /etc/kcpassword",
                ],
            ),
        );
    }
    if preference("/Library/Preferences/com.apple.loginwindow", "GuestEnabled").as_deref() == Some("1") {
        constats.push(
            alerte(
                "Comptes",
                Niveau::Info,
                tr!(
                    "Le compte invité est activé : n'importe qui peut ouvrir une session sans mot de passe.",
                    "The guest account is on: anyone can log in without a password."
                ),
            )
            .corriger(
                tr!("Désactiver le compte invité", "Turn off the guest account"),
                &["sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"],
            ),
        );
    }
    constats
}

/// Une valeur de sysctl en octets, par sysctlbyname : le même appel au noyau que la commande `sysctl`, sans la lancer.
fn sysctl(nom: &str) -> Option<Vec<u8>> {
    sysctl_ou_vide(nom).filter(|o| !o.is_empty())
}

/// Comme `sysctl`, mais une valeur vide (kern.bootargs sans option) est une réponse : `Some` d'un tableau vide.
// FFI de libc : sysctlbyname, gethostname, getgrnam_r.
#[allow(unsafe_code)]
fn sysctl_ou_vide(nom: &str) -> Option<Vec<u8>> {
    let nom = std::ffi::CString::new(nom).ok()?;
    let mut taille: libc::size_t = 0;
    // SAFETY: nom est une chaîne C terminée par un nul ; sans tampon (pointeur nul), sysctlbyname n'écrit que la
    // taille voulue dans `taille`.
    let code = unsafe {
        libc::sysctlbyname(
            nom.as_ptr(),
            std::ptr::null_mut(),
            &raw mut taille,
            std::ptr::null_mut(),
            0,
        )
    };
    if code != 0 || taille > 1024 * 1024 {
        return None;
    }
    if taille == 0 {
        return Some(Vec::new());
    }
    let mut tampon = vec![0u8; taille];
    // SAFETY: tampon de `taille` octets, vivant pendant l'appel ; le noyau n'écrit pas au-delà et redit dans
    // `taille` ce qu'il a écrit.
    let code = unsafe {
        libc::sysctlbyname(
            nom.as_ptr(),
            tampon.as_mut_ptr().cast(),
            &raw mut taille,
            std::ptr::null_mut(),
            0,
        )
    };
    if code != 0 {
        return None;
    }
    tampon.truncate(taille);
    Some(tampon)
}

/// Texte de sysctl (« machdep.cpu.brand_string », « hw.model ») : une chaîne C.
pub fn sysctl_texte(nom: &str) -> Option<String> {
    let octets = sysctl(nom)?;
    // Jusqu'au premier nul, s'il y en a un.
    let octets: Vec<u8> = octets.into_iter().take_while(|&o| o != 0).collect();
    let texte = String::from_utf8_lossy(&octets).trim().to_string();
    (!texte.is_empty()).then_some(texte)
}

/// Nombre de sysctl (« hw.memsize ») : un entier de 4 ou 8 octets, dans l'ordre de la machine.
pub fn sysctl_nombre(nom: &str) -> Option<u64> {
    let octets = sysctl(nom)?;
    match octets.len() {
        4 => Some(u64::from(u32::from_ne_bytes(octets.try_into().ok()?))),
        8 => Some(u64::from_ne_bytes(octets.try_into().ok()?)),
        _ => None,
    }
}

/// Heure du démarrage en secondes depuis 1970 : « kern.boottime », une struct timeval dont les secondes viennent en
/// premier, sur 8 octets.
pub fn demarrage() -> Option<u64> {
    let octets = sysctl("kern.boottime")?;
    u64::try_from(i64::from_ne_bytes(octets.get(..8)?.try_into().ok()?)).ok()
}

/// Un nom de ce Mac dans ses réglages réseau, ce que donne `scutil --get` : « ComputerName » (le nom affiché) ou
/// « LocalHostName » (le nom sur le réseau local, sans « .local ») ; scutil en secours.
pub fn nom_machine(cle: &str) -> Option<String> {
    let reglages = crate::plist::lire_fichier(std::path::Path::new(
        "/Library/Preferences/SystemConfiguration/preferences.plist",
    ))
    .ok()
    .and_then(crate::plist::Lu::valeur);
    let lu = reglages.as_ref().and_then(|r| {
        let systeme = r.cle("System")?;
        let valeur = match cle {
            "ComputerName" => systeme.cle("System")?.cle("ComputerName")?,
            "LocalHostName" => systeme.cle("Network")?.cle("HostNames")?.cle("LocalHostName")?,
            _ => return None,
        };
        valeur.texte().map(|t| t.trim().to_string())
    });
    lu.or_else(|| sortie("scutil", &["--get", cle]).map(|s| s.trim().to_string()))
}

/// Nom d'hôte, ce qu'affiche `hostname` (gethostname).
// FFI de libc : sysctlbyname, gethostname, getgrnam_r.
#[allow(unsafe_code)]
pub fn nom_hote() -> Option<String> {
    let mut tampon = [0u8; 256];
    // SAFETY: tampon de 256 octets vivant pendant l'appel ; gethostname n'écrit pas au-delà de la taille donnée.
    if unsafe { libc::gethostname(tampon.as_mut_ptr().cast(), tampon.len()) } != 0 {
        return None;
    }
    let fin = tampon.iter().position(|&o| o == 0)?;
    let nom = String::from_utf8_lossy(tampon.get(..fin)?).trim().to_string();
    (!nom.is_empty()).then_some(nom)
}

/// Membres du groupe admin, ceux du « GroupMembership » de dscl, demandés à la bibliothèque du système. `None` :
/// groupe introuvable ou illisible. Aussi lu par `administrateurs` (nouveaux administrateurs).
// FFI de libc : sysctlbyname, gethostname, getgrnam_r.
#[allow(unsafe_code)]
pub(super) fn membres_admin() -> Option<Vec<String>> {
    let mut taille = 16 * 1024;
    loop {
        let mut tampon: Vec<libc::c_char> = vec![0; taille];
        // SAFETY: une struct group faite de nombres et de pointeurs, que getgrnam_r remplit avant toute lecture.
        let mut groupe: libc::group = unsafe { std::mem::zeroed() };
        let mut trouve: *mut libc::group = std::ptr::null_mut();
        // SAFETY: le nom est une chaîne C terminée par un nul ; tampon, groupe et trouve vivent pendant l'appel, et
        // getgrnam_r n'écrit que dans les tailles données.
        let code = unsafe {
            libc::getgrnam_r(
                c"admin".as_ptr(),
                &raw mut groupe,
                tampon.as_mut_ptr(),
                tampon.len(),
                &raw mut trouve,
            )
        };
        if code == libc::ERANGE && taille < 1024 * 1024 {
            taille *= 4;
            continue;
        }
        if code != 0 || trouve.is_null() || groupe.gr_mem.is_null() {
            return None;
        }
        let mut membres = Vec::new();
        // SAFETY: gr_mem est un tableau de chaînes C terminé par un pointeur nul, rangé dans tampon, encore vivant ;
        // la borne du nombre de membres arrête un tableau sans fin.
        unsafe {
            let mut p = groupe.gr_mem;
            while membres.len() < 10_000 && !(*p).is_null() {
                membres.push(std::ffi::CStr::from_ptr(*p).to_string_lossy().into_owned());
                p = p.add(1);
            }
        }
        return Some(membres);
    }
}

/// Comptes administrateurs : par la bibliothèque du système, dscl en secours (« GroupMembership: root alice »).
fn comptes() -> Constat {
    // Un Mac a toujours un administrateur : une liste vide (groupe dont Open Directory ne remplit pas
    // les noms, adhésion par identifiant seulement) est une lecture manquée, qui passe à dscl.
    let membres = membres_admin().filter(|m| !m.is_empty()).or_else(|| {
        let texte = sortie("dscl", &[".", "-read", "/Groups/admin", "GroupMembership"])?;
        let m: Vec<String> = texte.split_whitespace().skip(1).map(str::to_string).collect();
        (!m.is_empty()).then_some(m)
    });
    let Some(membres) = membres else {
        return impossible("Comptes", tr!("dscl illisible", "dscl unreadable"));
    };
    let admins = personnes(&membres);
    if admins.is_empty() {
        // Seulement root ou des comptes internes : la vraie liste n'a pas été lue.
        return impossible(
            "Comptes",
            tr!("aucune personne dans le groupe admin", "no person in the admin group"),
        );
    }
    if admins.len() > 2 {
        alerte(
            "Comptes",
            Niveau::Info,
            trf!(
                "{} comptes administrateurs : {}. Chacun peut tout modifier ; vérifiez qu'ils sont tous connus.",
                "{} administrator accounts: {}. Each can change everything; check they are all known.",
                admins.len(),
                admins.join(", ")
            ),
        )
    } else {
        ok(
            "Comptes",
            trf!("Administrateurs : {}.", "Administrators: {}.", admins.join(", ")),
        )
    }
}

/// Les membres qui sont des personnes : root et les comptes internes de macOS (« _mbsetupuser ») n'en
/// sont pas.
fn personnes(membres: &[String]) -> Vec<&str> {
    membres
        .iter()
        .map(String::as_str)
        .filter(|n| *n != "root" && !n.starts_with('_'))
        .collect()
}

/// Gestion à distance (MDM) : une organisation qui gère ce Mac peut y installer des programmes et des profils.
/// Normal sur un Mac de travail ; sur un Mac personnel, c'est à comprendre.
fn gestion_a_distance() -> Option<Constat> {
    let texte = sortie("profiles", &["status", "-type", "enrollment"])?;
    let inscrit = texte
        .lines()
        .any(|l| l.contains("MDM enrollment:") && l.contains("Yes"));
    Some(if inscrit {
        alerte(
            "Gestion à distance",
            Niveau::Moyen,
            tr!(
                "Ce Mac est géré à distance (MDM) : l'organisation peut y installer des programmes, des certificats et des réglages. Normal sur un Mac de travail, à vérifier sur un Mac personnel.",
                "This Mac is remotely managed (MDM): the organization can install programs, certificates and settings on it. Normal on a work Mac, worth checking on a personal Mac."
            ),
        )
        .manuel(
            tr!(
                "Voir qui le gère : Réglages Système > Général > Gestion des appareils",
                "See who manages it: System Settings > General > Device Management"
            ),
            &[],
        )
    } else {
        ok(
            "Gestion à distance",
            tr!(
                "Ce Mac n'est géré par aucune organisation (MDM).",
                "This Mac is not managed by any organization (MDM)."
            ),
        )
    })
}

/// Réglages des mises à jour automatiques. Une clé absente = réglage par défaut (activé).
fn mises_a_jour_automatiques() -> Constat {
    const DOMAINE: &str = "/Library/Preferences/com.apple.SoftwareUpdate";
    let coupe = |cle: &str| preference(DOMAINE, cle).as_deref() == Some("0");
    let mut coupes = Vec::new();
    let mut commandes = Vec::new();
    for (cle, nom) in [
        ("AutomaticCheckEnabled", tr!("recherche", "check")),
        (
            "CriticalUpdateInstall",
            tr!("réponses de sécurité", "security responses"),
        ),
        (
            "ConfigDataInstall",
            tr!("données de sécurité (XProtect)", "security data (XProtect)"),
        ),
    ] {
        if coupe(cle) {
            coupes.push(nom);
            commandes.push(format!("sudo defaults write {DOMAINE} {cle} -bool true"));
        }
    }
    if coupes.is_empty() {
        return ok(
            "Mises à jour",
            tr!(
                "Mises à jour de sécurité automatiques actives.",
                "Automatic security updates on."
            ),
        );
    }
    alerte(
        "Mises à jour",
        Niveau::Moyen,
        trf!(
            "Mises à jour automatiques coupées : {}. Les failles corrigées par Apple restent ouvertes sur ce Mac.",
            "Automatic updates turned off: {}. The flaws Apple fixes stay open on this Mac.",
            coupes.join(", ")
        ),
    )
    .corriger(
        tr!(
            "Réactiver les mises à jour de sécurité automatiques",
            "Turn automatic security updates back on"
        ),
        &commandes,
    )
}

/// Date de la dernière sauvegarde dans un chemin Time Machine (« …/2024-05-01-123456 »).
fn date_sauvegarde(chemin: &str) -> Option<chrono::NaiveDate> {
    let nom = chemin.trim().rsplit('/').next()?;
    chrono::NaiveDate::parse_from_str(nom.get(..10)?, "%Y-%m-%d").ok()
}

/// Destinations Time Machine dont la sauvegarde n'est pas chiffrée, d'après les réglages de Time Machine
/// (« LastKnownEncryptionState = NotEncrypted; », une fois par destination).
fn destinations_non_chiffrees(reglages: &str) -> usize {
    reglages
        .lines()
        .filter(|l| {
            l.split_once('=').is_some_and(|(k, v)| {
                k.trim() == "LastKnownEncryptionState" && v.trim().trim_end_matches(';').trim() == "NotEncrypted"
            })
        })
        .count()
}

/// Sauvegarde Time Machine non chiffrée : le disque de sauvegarde volé donne tous les fichiers, même avec FileVault.
fn sauvegarde_chiffree() -> Option<Constat> {
    const TIME_MACHINE: &str = "/Library/Preferences/com.apple.TimeMachine";
    let n = match reglages(TIME_MACHINE) {
        Reglages::Lus(r) => r
            .cle("Destinations")?
            .tableau()?
            .iter()
            .filter(|d| d.cle("LastKnownEncryptionState").and_then(Valeur::texte) == Some("NotEncrypted"))
            .count(),
        Reglages::Absents => return None,
        Reglages::Illisibles => {
            destinations_non_chiffrees(&sortie("defaults", &["read", TIME_MACHINE, "Destinations"])?)
        }
    };
    (n > 0).then(|| {
        alerte(
            "Sauvegardes",
            Niveau::Moyen,
            if n == 1 {
                tr!(
                    "La sauvegarde Time Machine n'est pas chiffrée : le disque de sauvegarde volé donne tous vos fichiers, même avec FileVault.",
                    "The Time Machine backup is not encrypted: a stolen backup disk gives away all your files, even with FileVault."
                )
                .to_string()
            } else {
                trf!(
                    "{n} sauvegardes Time Machine ne sont pas chiffrées : un disque de sauvegarde volé donne tous vos fichiers, même avec FileVault.",
                    "{n} Time Machine backups are not encrypted: a stolen backup disk gives away all your files, even with FileVault."
                )
            },
        )
        .manuel(
            tr!(
                "Réglages Système > Général > Time Machine : retirer le disque puis l'ajouter de nouveau en cochant « Chiffrer la sauvegarde » (une nouvelle sauvegarde complète repart)",
                "System Settings > General > Time Machine: remove the disk, then add it again with “Encrypt Backup” checked (a new full backup starts)"
            ),
            &[],
        )
    })
}

/// La plus récente des sauvegardes notées dans les réglages de Time Machine (« SnapshotDates » de chaque destination),
/// en date locale. `None` : aucune date notée (la clé manque selon les versions de macOS).
fn derniere_sauvegarde(destinations: &[Valeur]) -> Option<chrono::NaiveDate> {
    let secondes = destinations
        .iter()
        .filter_map(|d| d.cle("SnapshotDates")?.tableau())
        .flatten()
        .filter_map(|v| match v {
            Valeur::Date(s) => Some(*s),
            _ => None,
        })
        .fold(None, |max: Option<f64>, s| Some(max.map_or(s, |m| m.max(s))))?;
    let d = chrono::DateTime::from_timestamp(crate::plist::date_unix(secondes)?, 0)?;
    Some(d.with_timezone(&chrono::Local).date_naive())
}

/// Le constat d'une sauvegarde réglée, d'après la date de la dernière (`None` : inconnue).
fn sauvegarde_datee(date: Option<chrono::NaiveDate>) -> Constat {
    match date {
        Some(date) => {
            let jours = (chrono::Local::now().date_naive() - date).num_days();
            if jours > 14 {
                alerte(
                    "Sauvegardes",
                    Niveau::Moyen,
                    trf!(
                        "Dernière sauvegarde Time Machine il y a {jours} jours : rebranchez le disque de sauvegarde.",
                        "Last Time Machine backup {jours} days ago: plug the backup disk back in."
                    ),
                )
            } else {
                ok(
                    "Sauvegardes",
                    trf!(
                        "Time Machine : dernière sauvegarde il y a {jours} jour(s).",
                        "Time Machine: last backup {jours} day(s) ago."
                    ),
                )
            }
        }
        None => ok(
            "Sauvegardes",
            tr!("Time Machine est configuré.", "Time Machine is set up."),
        ),
    }
}

/// Time Machine : une destination notée dans ses réglages (com.apple.TimeMachine.plist) suffit à la dire réglée, avec
/// la date de sa dernière sauvegarde ; tmutil dit le reste (aucune destination, date absente), tant que l'oracle de
/// macos.yml n'a pas prouvé la lecture native : un réglage que macOS aurait déplacé ne doit pas passer pour « aucune
/// sauvegarde ». Le Mac de GitHub n'a pas de Time Machine : cette lecture n'y est pas prouvée.
fn sauvegardes() -> Constat {
    const TIME_MACHINE: &str = "/Library/Preferences/com.apple.TimeMachine";
    if let Reglages::Lus(r) = reglages(TIME_MACHINE)
        && let Some(destinations) = r
            .cle("Destinations")
            .and_then(Valeur::tableau)
            .filter(|d| !d.is_empty())
    {
        let date = derniere_sauvegarde(destinations)
            .or_else(|| sortie("tmutil", &["latestbackup"]).as_deref().and_then(date_sauvegarde));
        return sauvegarde_datee(date);
    }
    let Some(destinations) = sortie("tmutil", &["destinationinfo"]) else {
        return impossible("Sauvegardes", tr!("tmutil illisible", "tmutil unreadable"));
    };
    if destinations.contains("No destinations configured") || !destinations.contains("Name") {
        return alerte(
            "Sauvegardes",
            Niveau::Moyen,
            tr!(
                "Aucune sauvegarde Time Machine configurée : un disque qui lâche, un vol ou un rançongiciel emportent tout.",
                "No Time Machine backup set up: a failing disk, a theft or ransomware takes everything."
            ),
        )
        .manuel(
            tr!(
                "Brancher un disque externe, puis Réglages Système > Général > Time Machine > Ajouter un disque de sauvegarde",
                "Plug in an external disk, then System Settings > General > Time Machine > Add Backup Disk"
            ),
            &[],
        );
    }
    // La date demande l'accès complet au disque ; sans lui, on sait seulement que Time Machine est réglé.
    sauvegarde_datee(sortie("tmutil", &["latestbackup"]).as_deref().and_then(date_sauvegarde))
}

/// Wi-Fi : protection du réseau connecté, et un éventuel jumeau maléfique parmi les réseaux visibles.
/// system_profiler met quelques secondes : il tourne en même temps que les autres vérifications.
fn wifi() -> Vec<Constat> {
    let Some(r) = crate::commande::lancer(
        std::process::Command::new("system_profiler").arg("SPAirPortDataType"),
        40,
    ) else {
        return vec![super::impossible_par(
            "Wi-Fi",
            crate::modele::Raison::Absente("system_profiler".into()),
            tr!(
                "Impossible de vérifier le Wi-Fi (system_profiler n'a pas répondu).",
                "Could not check Wi-Fi (system_profiler did not answer)."
            ),
        )];
    };
    let visibles = super::wifi::lire_system_profiler(&r.sortie);
    let Some(actif) = visibles.iter().find(|v| v.actif) else {
        return vec![wifi_sans_connexion(&r.sortie)];
    };
    let nom = if actif.ssid == super::wifi::CACHE {
        tr!("nom caché par macOS", "name hidden by macOS")
    } else {
        actif.ssid.as_str()
    };
    let admin = crate::reseau::scan::passerelle().map(|g| format!("open http://{g}"));
    let admin: Vec<&str> = admin.iter().map(String::as_str).collect();
    let mut constats = vec![super::wifi::securite(nom, &actif.securite, &admin)];
    constats.extend(super::wifi::jumeau(&visibles));
    constats
}

/// Aucun réseau connecté dans `system_profiler SPAirPortDataType` : sans objet seulement quand il le dit (aucune
/// carte listée, ou Wi-Fi éteint), non vérifié sinon. Ses mots sont en anglais quelle que soit la langue du Mac.
fn wifi_sans_connexion(sortie: &str) -> Constat {
    use crate::modele::{Absence, Raison};
    if !sortie.trim().is_empty() && !sortie.contains("Interfaces:") {
        return super::sans_objet(
            "Wi-Fi",
            Absence::Materiel,
            tr!("Pas de carte Wi-Fi sur ce Mac.", "No Wi-Fi card on this Mac."),
        );
    }
    if sortie.lines().any(|l| l.trim() == "Status: Off") {
        return super::sans_objet(
            "Wi-Fi",
            Absence::Inactif,
            tr!("Wi-Fi éteint : rien à juger.", "Wi-Fi off: nothing to judge."),
        );
    }
    super::impossible_par(
        "Wi-Fi",
        Raison::Illisible("system_profiler".into()),
        tr!(
            "Impossible de vérifier le Wi-Fi : system_profiler ne nomme aucun réseau connecté.",
            "Could not check Wi-Fi: system_profiler names no connected network."
        ),
    )
}

pub fn auditer() -> Audit {
    // Les vérifications sont les règles du registre (regles.rs), le pare-feu en tête.
    super::audit(NOM)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// root et les comptes internes ne comptent pas : une liste sans personne n'est pas un bilan.
    #[test]
    fn administrateurs_personnes() {
        let m: Vec<String> = ["root", "alice", "_mbsetupuser"].map(String::from).into();
        assert_eq!(personnes(&m), ["alice"]);
        assert_eq!(personnes(&["root".to_string()]), [] as [&str; 0]);
        assert_eq!(personnes(&[]), [] as [&str; 0]);
    }

    #[test]
    fn lecture_du_pare_feu() {
        assert_eq!(lire_pare_feu("Firewall is enabled. (State = 1)"), Some(true));
        assert_eq!(
            lire_pare_feu("Firewall is blocking all non-essential incoming connections. (State = 2)"),
            Some(true)
        );
        assert_eq!(lire_pare_feu("Firewall is disabled. (State = 0)"), Some(false));
        assert_eq!(lire_pare_feu(""), None);
    }

    #[test]
    fn lecture_du_verrouillage() {
        assert_eq!(
            lire_verrouillage("screenLock delay is immediate"),
            Some(Verrouillage::Delai(0))
        );
        assert_eq!(
            lire_verrouillage("2024-05-01 sysadminctl[1:2] screenLock delay is 300 seconds"),
            Some(Verrouillage::Delai(300))
        );
        assert_eq!(lire_verrouillage("screenLock is off"), Some(Verrouillage::Coupe));
        assert_eq!(lire_verrouillage("autre chose"), None);
    }

    #[test]
    fn time_machine_non_chiffree() {
        let reglages = "(\n        {\n        DestinationID = \"1\";\n        LastKnownEncryptionState = NotEncrypted;\n    },\n        {\n        LastKnownEncryptionState = Encrypted;\n    }\n)\n";
        assert_eq!(destinations_non_chiffrees(reglages), 1);
        assert_eq!(destinations_non_chiffrees("LastKnownEncryptionState = Encrypted;"), 0);
        assert_eq!(destinations_non_chiffrees(""), 0);
    }

    #[test]
    fn derniere_sauvegarde_notee() {
        let d = |s: f64| Valeur::Dico(vec![("SnapshotDates".into(), Valeur::Tableau(vec![Valeur::Date(s)]))]);
        // 800 000 000 s après 2001 : 8 mai 2026 ; la plus récente des deux destinations l'emporte.
        let lue = derniere_sauvegarde(&[d(700_000_000.0), d(800_000_000.0)]).unwrap();
        assert_eq!(lue.format("%Y").to_string(), "2026");
        assert_eq!(derniere_sauvegarde(&[Valeur::Dico(Vec::new())]), None);
    }

    #[test]
    fn date_time_machine() {
        assert_eq!(
            date_sauvegarde("/Volumes/Sauvegarde/Backups.backupdb/Mac/2024-05-01-123456\n"),
            chrono::NaiveDate::from_ymd_opt(2024, 5, 1)
        );
        assert_eq!(
            date_sauvegarde("2024-05-01-123456.backup"),
            chrono::NaiveDate::from_ymd_opt(2024, 5, 1)
        );
        assert_eq!(date_sauvegarde("Failed to mount backup destination"), None);
    }
}
