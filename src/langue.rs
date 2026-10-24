//! Langue de l'interface : français ou anglais, choisie d'après le système (pour forcer : variable VANGUARD_LANG, ou
//! menu Paramètres).
//! Chaque texte est écrit dans les deux langues à l'endroit où il sert : `tr!("Pare-feu actif", "Firewall on")`.
//! Les noms internes (catégories des constats, clés JSON) restent en français : le code s'en sert pour décider.

use std::sync::OnceLock;

static ANGLAIS: OnceLock<bool> = OnceLock::new();

/// Code de langue d'une variable d'environnement : « fr_CA.UTF-8 » → « fr », « C » ou vide → `None`.
fn code(valeur: &str) -> Option<String> {
    let c = valeur.split(['_', '.', '@', '-']).next()?.trim().to_ascii_lowercase();
    (c.len() == 2 || c.len() == 3).then_some(c)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où la langue peut être inconnue
fn langue_systeme() -> Option<String> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY : fonction sans argument de l'API Windows, toujours disponible.
    let id = unsafe { GetUserDefaultUILanguage() };
    // 10 bits bas = langue principale ; 0x0C = français (France, Canada, Belgique, Suisse…).
    Some(if id & 0x3ff == 0x0c { "fr" } else { "en" }.to_string())
}

#[cfg(not(windows))]
fn langue_systeme() -> Option<String> {
    // Même ordre de priorité que gettext : LC_ALL, puis LC_MESSAGES, puis LANG.
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
        .and_then(|v| code(&v))
}

/// Français si le système est en français, anglais sinon. Les tests, eux, sont toujours en français.
fn detecter() -> bool {
    if cfg!(test) {
        return false;
    }
    // VANGUARD_LANG, sinon le menu Paramètres (parametres.json).
    let forcee = crate::parametres::langue().and_then(|v| code(&v));
    forcee.or_else(langue_systeme).is_none_or(|c| c != "fr")
}

pub fn anglais() -> bool {
    #[cfg(test)]
    if let Some(forcee) = FORCEE.with(std::cell::Cell::get) {
        return forcee;
    }
    *ANGLAIS.get_or_init(detecter)
}

// La langue forcée pour ce fil seulement, le temps d'un test (`en_anglais`) : les autres tests, qui tournent en
// même temps sur d'autres fils, restent en français.
#[cfg(test)]
thread_local! {
    static FORCEE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Lance `f` en anglais sur ce fil, puis revient au français : pour vérifier qu'un jugement ne dépend pas de la
/// langue (les clés des constats).
#[cfg(test)]
pub(crate) fn en_anglais<R>(f: impl FnOnce() -> R) -> R {
    FORCEE.with(|l| l.set(Some(true)));
    let r = f();
    FORCEE.with(|l| l.set(None));
    r
}

/// Le texte dans la langue de l'interface (deux littéraux) : `tr!("Annulé.", "Cancelled.")`.
#[macro_export]
macro_rules! tr {
    ($fr:literal, $en:literal $(,)?) => {
        if $crate::langue::anglais() { $en } else { $fr }
    };
}

/// `format!` dans la langue de l'interface : `trf!("{n} appareil(s)", "{n} device(s)")`.
#[macro_export]
macro_rules! trf {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { format!($en $(, $arg)*) } else { format!($fr $(, $arg)*) }
    };
}

/// `println!` dans la langue de l'interface, chaque ligne trop longue coupée entre deux mots (`ui::mettre_en_lignes`).
#[macro_export]
macro_rules! trp {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        $crate::ui::imprimer(&if $crate::langue::anglais() { format!($en $(, $arg)*) } else { format!($fr $(, $arg)*) })
    };
}

/// `eprintln!` dans la langue de l'interface.
#[macro_export]
macro_rules! tre {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { eprintln!($en $(, $arg)*) } else { eprintln!($fr $(, $arg)*) }
    };
}

/// `print!` dans la langue de l'interface.
#[macro_export]
macro_rules! trpr {
    ($fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { print!($en $(, $arg)*) } else { print!($fr $(, $arg)*) }
    };
}

/// `write!` dans la langue de l'interface.
#[macro_export]
macro_rules! trw {
    ($dest:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { write!($dest, $en $(, $arg)*) } else { write!($dest, $fr $(, $arg)*) }
    };
}

/// `writeln!` dans la langue de l'interface.
#[macro_export]
macro_rules! trwln {
    ($dest:expr, $fr:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        if $crate::langue::anglais() { writeln!($dest, $en $(, $arg)*) } else { writeln!($dest, $fr $(, $arg)*) }
    };
}

/// Réponse « oui » à une question [o/N] : o, oui, y, yes, quelle que soit la langue.
pub fn oui(reponse: &str) -> bool {
    matches!(reponse.trim().to_lowercase().as_str(), "o" | "oui" | "y" | "yes")
}

/// `demander(…).oui()` : la réponse à une question [o/N] / [y/N], dans les deux langues.
pub trait Reponse {
    fn oui(&self) -> bool;
}

impl Reponse for String {
    fn oui(&self) -> bool {
        oui(self)
    }
}

/// Réponse « tout » : t (tout) ou a (all).
pub fn tout(reponse: &str) -> bool {
    matches!(reponse.trim().to_lowercase().as_str(), "t" | "tout" | "a" | "all")
}

/// Nom affiché du rôle d'un appareil du réseau (son nom interne est français).
pub fn role(nom: &str) -> &str {
    match (anglais(), nom) {
        (true, "passerelle") => "gateway",
        (true, "cette machine") => "this computer",
        (false, "cette machine") => "cet ordinateur",
        _ => nom,
    }
}

/// Un nombre à virgule, avec `chiffres` décimales, écrit à la française (« 14,5 ») ou à l'anglaise (« 14.5 »).
pub fn decimal(x: f64, chiffres: usize) -> String {
    let texte = format!("{x:.chiffres$}");
    if anglais() { texte } else { texte.replace('.', ",") }
}

/// Nom affiché d'une catégorie de constat (son nom interne est français).
pub fn categorie(nom: &str) -> &str {
    if !anglais() {
        return nom;
    }
    categorie_en(nom).unwrap_or(nom)
}

/// Le nom anglais d'une catégorie, s'il diffère du français.
fn categorie_en(nom: &str) -> Option<&'static str> {
    Some(match nom {
        "Pare-feu" => "Firewall",
        "Réseau local" => "Local network",
        "Accès à distance" => "Remote access",
        "Logiciels espions" => "Spyware",
        "Logiciels pas à jour" => "Outdated software",
        "Courriel suspect" => "Suspicious email",
        "Lien suspect" => "Suspicious link",
        "Confidentialité" => "Privacy",
        "Connexion" => "Connection",
        "Connexions sortantes" => "Outbound connections",
        "Listes noires" => "Blocklists",
        "Agents d'IA" => "AI agents",
        "Bureau à distance" => "Remote Desktop",
        "Carte graphique" => "Graphics card",
        "Certificats" => "Certificates",
        "Clé VANGUARD" => "VANGUARD key",
        "Chiffrement" => "Encryption",
        "Clé USB" => "USB key",
        "Clés SSH" => "SSH keys",
        "Durcissement" => "Hardening",
        "Autodiagnostic" => "Self-test",
        "Comptes" => "Accounts",
        "Extensions" => "Browser extensions",
        "Failles connues" => "Known flaws",
        "Fichiers secrets" => "Secret files",
        "Fin de support" => "End of support",
        "Fichiers suspects" => "Suspicious files",
        "Gestion à distance" => "Remote management",
        "Groupes" => "Groups",
        "Heure" => "Time",
        "Historique" => "History",
        "Intégrité" => "Integrity",
        "État de Vanguard" => "Vanguard's state",
        "Journaux" => "Logs",
        "Navigateur" => "Browser",
        "Mises à jour" => "Updates",
        "Noyau" => "Kernel",
        "Noyau durci" => "Kernel hardening",
        "Écoute du réseau" => "Network sniffing",
        "Plateforme" => "Platform",
        "Journal d'audit" => "Audit log",
        "Paquets AUR" => "AUR packages",
        "Partages de fichiers" => "File shares",
        "Persistance" => "Persistence",
        "Pilotes" => "Drivers",
        "Pilotes DKMS" => "DKMS drivers",
        "Privilèges" => "Privileges",
        "Ports en écoute" => "Listening ports",
        "Post-quantique" => "Post-quantum",
        "Processeur" => "Processor",
        "Programmes" => "Programs",
        "Protection système" => "System protection",
        "Périphériques" => "Devices",
        "Rançongiciels" => "Ransomware",
        "Redémarrage" => "Restart",
        "Santé" => "Health",
        "Sauvegardes" => "Backups",
        "Surveillance" => "Monitoring",
        "Verrouillage" => "Screen lock",
        "Affichage X11" => "X11 display",
        "Erreurs" => "Errors",
        "Erreurs du journal" => "Log errors",
        // Les domaines de l'audit du réseau (audit/).
        "Exposition" => "Exposure",
        "Appareils" => "Connected devices",
        "Postes" => "Computers",
        _ => return None,
    })
}

/// Catégories qui s'écrivent pareil dans les deux langues (pour le test qui relit le code, hors Windows).
#[cfg(all(test, unix))]
const MEMES_EN: &[&str] = &[
    "AUR",
    "AirDrop",
    "Antivirus",
    "AppArmor/SELinux",
    "Audit",
    "Bluetooth",
    "DNS",
    "Docker",
    "Firmware",
    "Flatpak",
    "Homebrew",
    "SMBv1",
    "SSH",
    "Secure Boot",
    "Segmentation",
    "Services",
    "Signatures",
    "Snap",
    "Sudo",
    "UAC",
    "Wi-Fi",
    "Windows Update",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nombres_a_virgule() {
        // Le texte anglais garde le point ; le format ne dépend que de la langue de l'interface.
        let attendu = if anglais() { "14.5" } else { "14,5" };
        assert_eq!(decimal(14.49, 1), attendu);
        assert_eq!(decimal(3.0, 0), "3");
        assert_eq!(decimal(1234.5678, 2), if anglais() { "1234.57" } else { "1234,57" });
    }

    /// Chaque catégorie écrite dans le code (alerte, ok, impossible…) a son nom anglais, ou s'écrit pareil : sans
    /// cela, l'interface anglaise montrait « Affichage X11 ». Le code est relu sur le disque (pas sous Wine).
    #[cfg(unix)]
    #[test]
    fn chaque_categorie_a_son_nom_anglais() {
        fn fichiers(dossier: &std::path::Path, tous: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dossier).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    fichiers(&p, tous);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    tous.push(p);
                }
            }
        }
        let mut tous = Vec::new();
        fichiers(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut tous);
        let mut manquantes = std::collections::BTreeSet::new();
        for f in tous {
            let texte = std::fs::read_to_string(&f).unwrap();
            for appel in ["alerte(", "ok(", "impossible(", "illisible(", "registre_illisible("] {
                for (i, _) in texte.match_indices(appel) {
                    // Un appel de fonction, pas la fin d'un autre nom (« pas_ok(… »).
                    let avant = texte[..i].chars().last();
                    // Ni dans une chaîne (« "ok(" », la liste de ce test).
                    if avant.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '"') {
                        continue;
                    }
                    let reste = texte[i + appel.len()..].trim_start();
                    let Some(dedans) = reste.strip_prefix('"') else {
                        continue;
                    };
                    let Some((nom, _)) = dedans.split_once('"') else {
                        continue;
                    };
                    if categorie_en(nom).is_none() && !MEMES_EN.contains(&nom) {
                        manquantes.insert(nom.to_string());
                    }
                }
            }
        }
        assert_eq!(manquantes, std::collections::BTreeSet::new());
    }

    #[test]
    fn codes_de_langue() {
        assert_eq!(code("fr_CA.UTF-8").as_deref(), Some("fr"));
        assert_eq!(code("en_US").as_deref(), Some("en"));
        assert_eq!(code("fr").as_deref(), Some("fr"));
        assert_eq!(code("C"), None);
        assert_eq!(code(""), None);
        assert!(oui("Yes") && oui("o") && !oui("n") && !oui(""));
        assert!(tout("a") && tout("T") && !tout("o"));
    }
}
