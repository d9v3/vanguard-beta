//! La chronologie de l'incident : ce que la collecte a lu de daté (journaux, ce qui se lance tout seul, comptes,
//! fichiers récents), remis dans l'ordre du temps sur les 7 derniers jours, du plus ancien au plus récent : « qu'est-ce
//! qui s'est passé, et quand ». Une ligne par événement : l'heure locale, d'où il vient, ce qui s'est passé, et la
//! technique MITRE ATT&CK quand elle est évidente.
//!
//! Rien n'est relu sur l'ordinateur : chaque partie note ses dates en lisant, les journaux texte (Linux, macOS) sont
//! repris dans les fichiers que la collecte vient d'écrire, et sous Windows les événements voulus sont lus une fois,
//! par les fonctions de Windows (wevtapi), sans PowerShell.

use std::fmt::Write as _;
use std::path::Path;
use std::time::SystemTime;

use chrono::TimeZone;

use super::{Bi, Manque, Partie, Raison, bi, champ, entete};

/// La fenêtre de la chronologie : celle des journaux.
pub(crate) const JOURS: i64 = 7;
/// Les lignes gardées au plus : une semaine se lit encore à la main, et une rafale (des milliers d'échecs de
/// connexion) ne fait pas un fichier de centaines de Mo.
pub(crate) const MAX_LIGNES: usize = 5000;
/// Le détail d'une ligne, en caractères au plus : un bloc de script ou une ligne de commande peut faire des pages.
const MAX_DETAIL: usize = 300;
/// Le fichier écrit.
const NOM: &str = "CHRONOLOGIE.txt";

/// D'où vient un événement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Source {
    /// Un journal du système : journal de systemd, syslog, journal unifié, journaux d'événements de Windows.
    Journal,
    /// Les comptes : démarrages et sessions (last), fichiers des comptes, dernière connexion.
    Compte,
    /// Ce qui se lance tout seul : la date d'un fichier ou d'une clé du registre.
    Demarrage,
    /// Un fichier récent d'un endroit à risque : sa date de modification.
    Fichier,
    /// Ce que Vanguard a vu et fait : ses alertes, ses blocages, ses quarantaines (07-vanguard.txt).
    Vanguard,
}

impl Source {
    fn texte(self) -> &'static str {
        match self {
            Source::Journal => "journal/log",
            Source::Compte => "compte/account",
            Source::Demarrage => "démarrage/startup",
            Source::Fichier => "fichier/file",
            Source::Vanguard => "vanguard",
        }
    }
}

/// Ce qui s'est passé.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Genre {
    // Journaux de Linux et macOS.
    #[cfg_attr(windows, allow(dead_code))]
    SshAccepte,
    #[cfg_attr(windows, allow(dead_code))]
    SshRefuse,
    #[cfg_attr(windows, allow(dead_code))]
    Sudo,
    #[cfg_attr(windows, allow(dead_code))]
    SudoRefuse,
    CompteCree,
    AjoutAuGroupe,
    #[cfg_attr(windows, allow(dead_code))]
    ModuleDuNoyau,
    // Journaux de Windows.
    #[cfg_attr(not(windows), allow(dead_code))]
    Session,
    #[cfg_attr(not(windows), allow(dead_code))]
    SessionBureauADistance,
    #[cfg_attr(not(windows), allow(dead_code))]
    EchecDeSession,
    #[cfg_attr(not(windows), allow(dead_code))]
    ServiceInstalle,
    #[cfg_attr(not(windows), allow(dead_code))]
    TacheCreee,
    #[cfg_attr(not(windows), allow(dead_code))]
    JournalEfface,
    #[cfg_attr(not(windows), allow(dead_code))]
    ScriptPowerShell,
    #[cfg_attr(not(windows), allow(dead_code))]
    MenaceDetectee,
    #[cfg_attr(not(windows), allow(dead_code))]
    MenaceTraitee,
    #[cfg_attr(not(windows), allow(dead_code))]
    ProtectionCoupee,
    /// Une alerte d'une règle `EVT-` (`journaux_windows`), à la date de son premier événement.
    AlerteDesJournaux,
    // Comptes.
    #[cfg_attr(windows, allow(dead_code))]
    DemarrageOrdinateur,
    #[cfg_attr(windows, allow(dead_code))]
    SessionReseau,
    #[cfg_attr(not(windows), allow(dead_code))]
    DerniereConnexion,
    #[cfg_attr(not(windows), allow(dead_code))]
    MotDePasseDefini,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    FichierDesComptes,
    // Ce qui se lance tout seul, fichiers récents.
    ServiceSystemd,
    Lancement,
    Fichier,
    FichiersGroupes,
    ProgrammesGroupes,
    // Vanguard lui-même.
    AlerteDeVanguard,
    GesteDeVanguard,
}

impl Genre {
    /// Ce qui s'est passé, en français puis en anglais.
    fn texte(self) -> (&'static str, &'static str) {
        match self {
            Genre::SshAccepte => ("Connexion SSH acceptée", "SSH login accepted"),
            Genre::SshRefuse => ("Connexion SSH refusée", "SSH login failed"),
            Genre::Sudo => ("Commande sudo", "sudo command"),
            Genre::SudoRefuse => ("sudo refusé", "sudo denied"),
            Genre::CompteCree => ("Compte créé", "Account created"),
            Genre::AjoutAuGroupe => ("Compte ajouté à un groupe", "Account added to a group"),
            Genre::ModuleDuNoyau => ("Module du noyau chargé", "Kernel module loaded"),
            Genre::Session => ("Ouverture de session", "Logon"),
            Genre::SessionBureauADistance => ("Session par le Bureau à distance", "Remote Desktop logon"),
            Genre::EchecDeSession => ("Échec d'ouverture de session", "Failed logon"),
            Genre::ServiceInstalle => ("Service installé", "Service installed"),
            Genre::TacheCreee => ("Tâche planifiée créée", "Scheduled task created"),
            Genre::JournalEfface => ("Journal effacé", "Log cleared"),
            Genre::ScriptPowerShell => ("Bloc de script PowerShell", "PowerShell script block"),
            Genre::MenaceDetectee => ("Menace détectée par Defender", "Threat detected by Defender"),
            Genre::MenaceTraitee => ("Menace traitée par Defender", "Threat handled by Defender"),
            Genre::ProtectionCoupee => (
                "Protection en temps réel de Defender coupée",
                "Defender real-time protection turned off",
            ),
            Genre::DemarrageOrdinateur => ("Démarrage de l'ordinateur", "Computer started"),
            Genre::SessionReseau => ("Session depuis le réseau", "Session from the network"),
            Genre::DerniereConnexion => ("Dernière connexion du compte", "Account's last logon"),
            Genre::MotDePasseDefini => ("Mot de passe défini", "Password set"),
            Genre::FichierDesComptes => ("Fichier des comptes modifié", "Account file modified"),
            Genre::ServiceSystemd => ("Service systemd ajouté ou activé", "systemd service added or enabled"),
            Genre::Lancement => ("Lancement automatique modifié", "Autostart entry modified"),
            Genre::Fichier => ("Fichier modifié", "File modified"),
            Genre::FichiersGroupes => (
                "Fichiers modifiés (dossier et sous-dossiers)",
                "Files modified (folder and subfolders)",
            ),
            Genre::ProgrammesGroupes => (
                "Programmes, scripts ou fichiers cachés modifiés en nombre (dossier et sous-dossiers)",
                "Many programs, scripts or hidden files modified (folder and subfolders)",
            ),
            Genre::AlerteDeVanguard => ("Alerte de Vanguard", "Vanguard alert"),
            Genre::AlerteDesJournaux => (
                "ALERTE des journaux de Windows (règle EVT-)",
                "ALERT from the Windows logs (EVT- rule)",
            ),
            Genre::GesteDeVanguard => (
                "Geste de Vanguard (blocage, quarantaine)",
                "Vanguard action (block, quarantine)",
            ),
        }
    }

    /// La technique MITRE ATT&CK quand l'événement la montre à lui seul ; celle d'un lancement automatique ou d'un
    /// fichier dépend de l'endroit (`mitre_du_chemin`). Une détection de Defender, un démarrage, une dernière
    /// connexion n'en ont pas : ils disent un moment, pas une technique.
    fn mitre(self) -> Option<&'static str> {
        Some(match self {
            Genre::SshAccepte => "T1021.004",
            Genre::SshRefuse | Genre::EchecDeSession => "T1110",
            Genre::Sudo | Genre::SudoRefuse => "T1548.003",
            Genre::CompteCree => "T1136.001",
            Genre::AjoutAuGroupe => "T1098",
            Genre::ModuleDuNoyau => "T1547.006",
            Genre::Session => "T1078",
            Genre::SessionBureauADistance => "T1021.001",
            Genre::SessionReseau => "T1021",
            Genre::ServiceInstalle => "T1543.003",
            Genre::TacheCreee => "T1053.005",
            Genre::JournalEfface => "T1070.001",
            Genre::ScriptPowerShell => "T1059.001",
            Genre::ProtectionCoupee => "T1562.001",
            Genre::ServiceSystemd => "T1543.002",
            Genre::MenaceDetectee
            | Genre::MenaceTraitee
            | Genre::DemarrageOrdinateur
            | Genre::DerniereConnexion
            | Genre::MotDePasseDefini
            | Genre::FichierDesComptes
            | Genre::Lancement
            | Genre::Fichier
            | Genre::FichiersGroupes
            | Genre::ProgrammesGroupes
            | Genre::AlerteDeVanguard
            | Genre::AlerteDesJournaux
            | Genre::GesteDeVanguard => return None,
        })
    }
}

/// Un événement de la chronologie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Evenement {
    /// Secondes depuis 1970, en UTC.
    pub quand: i64,
    pub source: Source,
    pub genre: Genre,
    /// Ce qui le précise : compte, adresse, commande, chemin. Il vient de n'importe qui (un nom de compte essayé par
    /// un robot) : écrit sans ce qui casserait la ligne (`champ`).
    pub detail: String,
    pub mitre: Option<&'static str>,
}

impl Evenement {
    pub(crate) fn new(quand: i64, source: Source, genre: Genre, detail: impl Into<String>) -> Evenement {
        Evenement {
            quand,
            source,
            genre,
            detail: detail.into(),
            mitre: genre.mitre(),
        }
    }

    /// Un fichier ou une clé de ce qui se lance tout seul, écrit à cette date : sa technique dépend de l'endroit.
    pub(crate) fn lancement(quand: i64, chemin: &str) -> Evenement {
        let genre = if est_systemd(chemin) {
            Genre::ServiceSystemd
        } else {
            Genre::Lancement
        };
        Evenement {
            mitre: genre.mitre().or_else(|| mitre_du_chemin(chemin)),
            ..Evenement::new(quand, Source::Demarrage, genre, chemin)
        }
    }

    /// Un fichier récent d'un endroit à risque, modifié à cette date ; son empreinte, si elle a été calculée, pour la
    /// chercher sur VirusTotal sans ouvrir un autre fichier.
    pub(crate) fn fichier(quand: i64, chemin: &str, taille: u64, empreinte: Option<&str>) -> Evenement {
        let mut detail = format!("{chemin} ({taille} octets/bytes)");
        if let Some(h) = empreinte {
            let _ = write!(detail, " SHA-256 {h}");
        }
        Evenement {
            mitre: mitre_du_chemin(chemin),
            ..Evenement::new(quand, Source::Fichier, Genre::Fichier, detail)
        }
    }
}

/// Les extensions d'un fichier qui se lance ou se charge : il a sa ligne dans la chronologie.
const EXTENSIONS_PARLANTES: &[&str] = &[
    "exe", "dll", "sys", "scr", "ps1", "bat", "cmd", "vbs", "js", "hta", "lnk", "msi", "jar", "sh", "py", "so",
];

/// Un fichier récent, tel que la chronologie le reprend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FichierRecent {
    pub chemin: String,
    /// Le dossier où il est compté s'il n'est pas parlant : celui juste sous l'endroit à risque, ou l'endroit.
    pub dossier: String,
    /// Sa date de modification, en secondes depuis 1970.
    pub quand: i64,
    pub taille: u64,
    pub empreinte: Option<String>,
    pub parlant: bool,
}

/// Un fichier « parlant » a sa propre ligne : un programme ou un script (droit d'exécution, extension qui se lance
/// ou se charge), un fichier caché (son nom ou un dossier sous l'endroit à risque commence par « . », ou l'attribut
/// de Windows), ou rangé dans un dossier de démarrage. Les autres (caches, compilations, documents) se comptent par
/// dossier et par heure : sur un ordinateur de développeur, /tmp en change des milliers par jour, et ils noyaient le
/// reste. `relatif` : le chemin sous l'endroit à risque.
pub(crate) fn parlant(chemin: &str, relatif: &Path, executable: bool, cache: bool) -> bool {
    let extension = Path::new(chemin)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let cache = cache
        || relatif
            .components()
            .any(|c| matches!(c, std::path::Component::Normal(n) if n.to_string_lossy().starts_with('.')));
    executable || cache || EXTENSIONS_PARLANTES.contains(&extension.as_str()) || mitre_du_chemin(chemin).is_some()
}

/// Au-delà de tant de fichiers parlants dans le même dossier et la même heure, c'est une installation ou une archive
/// dépliée (un préfixe de Wine, des centaines de DLL) : une ligne qui les compte par extension en dit plus que des
/// centaines. La liste entière, avec les empreintes, reste dans 06-fichiers-recents.txt.
const MAX_PARLANTS_PAR_HEURE: usize = 20;

/// L'heure locale d'une date (« 2026-10-20 14 ») : la clé des regroupements.
fn heure_locale<Tz: TimeZone>(quand: i64, fuseau: &Tz) -> Option<String> {
    let d = chrono::DateTime::from_timestamp(quand, 0)?;
    Some(d.with_timezone(fuseau).naive_local().format("%Y-%m-%d %H").to_string())
}

/// « 3 dans/in /tmp/a, entre/between 14:00 et/and 15:00 », daté du premier fichier modifié.
fn ligne_de_groupe(genre: Genre, dossier: &str, heure: &str, membres: &[&FichierRecent], suite: &str) -> Evenement {
    let premier = membres.iter().map(|f| f.quand).min().unwrap_or_default();
    let h: u32 = heure.get(11..).and_then(|h| h.parse().ok()).unwrap_or_default();
    Evenement::new(
        premier,
        Source::Fichier,
        genre,
        format!(
            "{} dans/in {dossier}, entre/between {h:02}:00 et/and {:02}:00{suite}",
            membres.len(),
            (h + 1) % 24
        ),
    )
}

/// Les extensions les plus nombreuses d'un groupe : « (dll 3999, exe 698, py 18) ».
fn extensions(membres: &[&FichierRecent]) -> String {
    let mut par: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in membres {
        let e = Path::new(&f.chemin)
            .extension()
            .map_or_else(|| "-".to_string(), |e| e.to_string_lossy().to_lowercase());
        *par.entry(e).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = par.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let liste: Vec<String> = v.iter().take(5).map(|(e, n)| format!("{e} {n}")).collect();
    format!(" ({}{})", liste.join(", "), if v.len() > 5 { ", …" } else { "" })
}

/// Les événements des fichiers récents : une ligne par fichier parlant, les autres comptés en une ligne par dossier
/// et par heure (à l'heure locale), datée du premier modifié. Seul dans son heure, un fichier garde sa ligne : elle
/// en dit plus que « 1 fichier ». Plus de `MAX_PARLANTS_PAR_HEURE` fichiers parlants dans le même dossier et la même
/// heure sont comptés aussi, par extension ; jamais ceux d'un dossier de démarrage, qui ont toujours leur ligne.
pub(crate) fn evenements_des_fichiers<Tz: TimeZone>(fichiers: &[FichierRecent], fuseau: &Tz) -> Vec<Evenement> {
    type Groupes<'a> = std::collections::BTreeMap<(&'a str, String), Vec<&'a FichierRecent>>;
    let fichier = |f: &FichierRecent| Evenement::fichier(f.quand, &f.chemin, f.taille, f.empreinte.as_deref());
    let mut v = Vec::new();
    let (mut parlants, mut autres) = (Groupes::new(), Groupes::new());
    for f in fichiers {
        if f.parlant && mitre_du_chemin(&f.chemin).is_some() {
            v.push(fichier(f));
            continue;
        }
        let Some(heure) = heure_locale(f.quand, fuseau) else {
            continue;
        };
        let groupes = if f.parlant { &mut parlants } else { &mut autres };
        groupes.entry((f.dossier.as_str(), heure)).or_default().push(f);
    }
    for ((dossier, heure), membres) in parlants {
        if membres.len() > MAX_PARLANTS_PAR_HEURE {
            v.push(ligne_de_groupe(
                Genre::ProgrammesGroupes,
                dossier,
                &heure,
                &membres,
                &extensions(&membres),
            ));
        } else {
            v.extend(membres.into_iter().map(fichier));
        }
    }
    for ((dossier, heure), membres) in autres {
        if let [seul] = membres[..] {
            v.push(fichier(seul));
        } else {
            v.push(ligne_de_groupe(Genre::FichiersGroupes, dossier, &heure, &membres, ""));
        }
    }
    v
}

/// Ce que les journaux donnent à la chronologie, et ce qui n'a pas pu en être lu.
#[derive(Debug, Default)]
pub(crate) struct Apport {
    pub evenements: Vec<Evenement>,
    pub manques: Vec<Manque>,
}

/// Les alertes `EVT-` d'une analyse des journaux de Windows, pour la chronologie : chacune à la date de son premier
/// événement, avec sa règle, sa gravité, ce qu'elle dit et où la retrouver, et sa technique ATT&CK ; celles que les
/// normales taisent restent tues (`journaux_windows::chronologie`). Une règle qui n'a pas tout lu est dite parmi ce
/// qui manque, comme les alertes sans date, qu'aucune ligne ne peut placer.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn alertes_des_journaux(
    a: &crate::journaux_windows::regles::resultat::Analyse,
    est_normale: &dyn Fn(&str) -> bool,
) -> Apport {
    use crate::journaux_windows::chronologie as jc;
    let c = jc::chronologie(a, est_normale);
    let mut apport = Apport::default();
    let mut sans_date = 0usize;
    for x in &c.alertes {
        let Some(quand) = x.date.map(|d| d.timestamp()) else {
            sans_date += 1;
            continue;
        };
        let mut detail = format!("{} [{}] {}", x.regle, jc::gravite(x.gravite), x.texte);
        if !x.contexte.is_empty() {
            let _ = write!(detail, " ({})", x.contexte);
        }
        apport.evenements.push(Evenement {
            mitre: x.technique,
            ..Evenement::new(quand, Source::Journal, Genre::AlerteDesJournaux, detail)
        });
    }
    if sans_date > 0 {
        apport.manques.push(Manque {
            quoi: bi!(
                "Chronologie : {sans_date} alertes des journaux (EVT-) sans date, pas placées",
                "Timeline: {sans_date} log alerts (EVT-) without a date, not placed"
            ),
            raison: Raison::Introuvable,
        });
    }
    for b in &c.au_dela {
        apport.manques.push(Manque {
            quoi: bi!(
                "Chronologie : {} événements de plus au-delà des bornes ({})",
                "Timeline: {} more events beyond the limits ({})",
                b.evenements,
                b.regle
            ),
            raison: Raison::Borne(b.evenements),
        });
    }
    let (_, couverture) = crate::journaux_windows::regles::resultat::constats(a, est_normale);
    for n in couverture.non_verifies {
        apport.manques.push(Manque {
            quoi: Bi::new(
                "Chronologie : alertes des journaux de Windows (EVT-), non vérifié",
                "Timeline: Windows log alerts (EVT-), not verified",
            ),
            raison: Raison::Erreur(n),
        });
    }
    apport
}

/// Une date du système en secondes depuis 1970 ; `None` avant 1970.
pub(crate) fn secondes(t: SystemTime) -> Option<i64> {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).ok()?;
    i64::try_from(d.as_secs()).ok()
}

/// Une heure locale (sans fuseau) en secondes depuis 1970 ; à l'heure qui se répète au passage à l'heure d'hiver,
/// la première des deux.
fn locale_vers_secondes<Tz: TimeZone>(d: chrono::NaiveDateTime, fuseau: &Tz) -> Option<i64> {
    fuseau.from_local_datetime(&d).earliest().map(|d| d.timestamp())
}

/// Le dossier d'une unité de systemd, du système ou du compte (ses dossiers .wants compris).
fn est_systemd(chemin: &str) -> bool {
    chemin.contains("/systemd/system/") || chemin.contains("/systemd/user/")
}

/// Les fichiers du shell lus à chaque ouverture : ce qu'on y ajoute se lance avec lui.
const FICHIERS_DU_SHELL: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    "config.fish",
];

/// La technique MITRE ATT&CK que désigne l'endroit d'un lancement automatique ou d'un fichier : unité de systemd,
/// démarrage de session, agent ou démon de launchd, dossier Démarrage ou clé Run de Windows, tâche planifiée, cron,
/// clés SSH autorisées, bibliothèque préchargée, fichiers du shell. Ailleurs (un téléchargement, /tmp) : aucune.
pub(crate) fn mitre_du_chemin(chemin: &str) -> Option<&'static str> {
    let c = chemin.replace('\\', "/").to_lowercase();
    let nom = c.rsplit('/').next().unwrap_or(&c);
    let dans = |d: &str| c.contains(d);
    let sous = |d: &[&str]| d.iter().any(|d| c.starts_with(d));
    Some(if est_systemd(&c) {
        "T1543.002"
    } else if dans("/autostart/") {
        "T1547.013"
    } else if dans("/launchagents/") {
        "T1543.001"
    } else if dans("/launchdaemons/") {
        "T1543.004"
    } else if dans("/startupitems/") {
        "T1037.005"
    } else if dans("/start menu/programs/startup/") || dans("/currentversion/run") || dans("/startupapproved/run") {
        "T1547.001"
    } else if dans("/system32/tasks/") {
        "T1053.005"
    } else if sous(&[
        "/etc/cron",
        "/etc/anacrontab",
        "/etc/periodic/",
        "/var/spool/cron",
        "/var/at/tabs",
        "/usr/lib/cron/tabs",
    ]) {
        "T1053.003"
    } else if nom == "authorized_keys" || nom == "authorized_keys2" {
        "T1098.004"
    } else if c == "/etc/ld.so.preload" {
        "T1574.006"
    } else if c == "/etc/rc.local" {
        "T1037.004"
    } else if FICHIERS_DU_SHELL.contains(&nom)
        || sous(&["/etc/profile", "/etc/bash.bashrc", "/etc/zshrc", "/etc/zprofile"])
    {
        "T1546.004"
    } else {
        return None;
    })
}

/// Les fichiers et dossiers de ce qui se lance tout seul, avec la date que leur lecture a notée (`Feuille::dates`).
/// Ceux de /proc et /sys n'ont pas de vraie date.
pub(crate) fn lancements(dates: &[(String, SystemTime)]) -> Vec<Evenement> {
    dates
        .iter()
        .filter(|(c, _)| !c.starts_with("/proc/") && !c.starts_with("/sys/"))
        .filter_map(|(c, t)| Some(Evenement::lancement(secondes(*t)?, c)))
        .collect()
}

/// Les événements de la fenêtre [`debut`, `fin`], du plus ancien au plus récent ; à la même seconde, dans un ordre
/// fixe (source, genre, détail). Le même événement noté deux fois (un fichier listé puis lu) ne fait qu'une ligne.
pub(crate) fn garder(evenements: impl IntoIterator<Item = Evenement>, debut: i64, fin: i64) -> Vec<Evenement> {
    let mut v: Vec<Evenement> = evenements
        .into_iter()
        .filter(|e| (debut..=fin).contains(&e.quand))
        .collect();
    v.sort_by(|a, b| (a.quand, a.source, a.genre, &a.detail).cmp(&(b.quand, b.source, b.genre, &b.detail)));
    v.dedup();
    v
}

/// Garde `max` lignes au plus, dans l'ordre, et rend combien sont coupées. Partent d'abord les fichiers sans
/// technique, les plus anciens (un dossier temporaire en change des milliers par jour sur un ordinateur de
/// développeur), puis les lignes les plus anciennes : ce qui vient de se passer compte le plus.
pub(crate) fn borner(evenements: Vec<Evenement>, max: usize) -> (Vec<Evenement>, usize) {
    let n = evenements.len();
    if n <= max {
        return (evenements, 0);
    }
    let secondaire = |e: &Evenement| e.source == Source::Fichier && e.mitre.is_none();
    let secondaires = evenements.iter().filter(|e| secondaire(e)).count();
    let importants = n - secondaires;
    let mut a_couper_importants = importants.saturating_sub(max);
    let mut a_couper_secondaires = secondaires - max.saturating_sub(importants).min(secondaires);
    let gardes = evenements
        .into_iter()
        .filter(|e| {
            let reste = if secondaire(e) {
                &mut a_couper_secondaires
            } else {
                &mut a_couper_importants
            };
            if *reste > 0 {
                *reste -= 1;
                false
            } else {
                true
            }
        })
        .collect();
    (gardes, n - max)
}

/// « 2026-10-20 14:03:22 -04:00 » : l'heure locale, avec son décalage (un passage à l'heure d'hiver dans la semaine
/// ne rend aucune ligne ambiguë).
pub(crate) fn date_locale<Tz: TimeZone>(quand: i64, fuseau: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    chrono::DateTime::from_timestamp(quand, 0).map_or_else(String::new, |d| {
        d.with_timezone(fuseau).format("%Y-%m-%d %H:%M:%S %:z").to_string()
    })
}

/// Une ligne de la chronologie, ses champs séparés par des tabulations : date, source, ce qui s'est passé, technique
/// (« - » sans technique évidente).
pub(crate) fn ligne<Tz: TimeZone>(e: &Evenement, fuseau: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let (fr, en) = e.genre.texte();
    let mut quoi = format!("{fr}/{en}");
    let detail = champ(&e.detail);
    if !detail.is_empty() {
        quoi.push_str(" : ");
        let mut caracteres = detail.chars();
        quoi.extend(caracteres.by_ref().take(MAX_DETAIL));
        if caracteres.next().is_some() {
            quoi.push('…');
        }
    }
    format!(
        "{}\t{}\t{quoi}\t{}",
        date_locale(e.quand, fuseau),
        e.source.texte(),
        e.mitre.unwrap_or("-")
    )
}

fn titre() -> Bi {
    Bi::new("Chronologie de l'incident", "Incident timeline")
}

/// Le fichier entier : l'en-tête (fenêtre, nombre de lignes par source, lignes coupées, sources illisibles), puis une
/// ligne par événement.
pub(crate) fn texte<Tz: TimeZone>(
    evenements: &[Evenement],
    coupees: usize,
    debut: i64,
    fuseau: &Tz,
    manques: &[Manque],
) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let mut t = entete(&titre());
    let depuis = date_locale(debut, fuseau);
    let _ = writeln!(
        t,
        "# Du plus ancien au plus récent, depuis {depuis} ({JOURS} jours), heures locales / oldest first, since {depuis} ({JOURS} days), local times"
    );
    let par = |s: Source| evenements.iter().filter(|e| e.source == s).count();
    let _ = writeln!(
        t,
        "# Lignes / lines : {} (journal/log {}, compte/account {}, démarrage/startup {}, fichier/file {})",
        evenements.len(),
        par(Source::Journal),
        par(Source::Compte),
        par(Source::Demarrage),
        par(Source::Fichier)
    );
    let alertes = evenements
        .iter()
        .filter(|e| e.genre == Genre::AlerteDesJournaux)
        .count();
    if alertes > 0 {
        let _ = writeln!(
            t,
            "# Alertes des journaux de Windows (règles EVT-, vanguard journaux-windows) / Windows log alerts (EVT- rules, vanguard windows-logs) : {alertes}, marquées « ALERTE » / marked “ALERT”"
        );
    }
    if coupees > 0 {
        let _ = writeln!(
            t,
            "# Coupées / cut : {coupees} lignes de plus, au-delà de {MAX_LIGNES} : les fichiers sans technique les plus anciens, puis les lignes les plus anciennes / {coupees} more lines beyond {MAX_LIGNES}: the oldest files without a technique, then the oldest lines"
        );
    }
    for m in manques {
        let quoi = if m.quoi.fr == m.quoi.en {
            m.quoi.fr.clone()
        } else {
            format!("{} / {}", m.quoi.fr, m.quoi.en)
        };
        let _ = writeln!(
            t,
            "# Incomplet ou illisible / incomplete or unreadable : {} {}",
            champ(&quoi),
            m.raison.note()
        );
    }
    t.push_str(
        "# MITRE ATT&CK : la technique quand l'événement la montre à lui seul, « - » sinon / the technique when the event shows it by itself, “-” otherwise\n",
    );
    t.push_str("DATE\tSOURCE\tQUOI/WHAT\tMITRE ATT&CK\n");
    if evenements.is_empty() {
        t.push_str("(aucun événement / no event)\n");
    }
    for e in evenements {
        t.push_str(&ligne(e, fuseau));
        t.push('\n');
    }
    t
}

/// La partie de la chronologie, écrite dans CHRONOLOGIE.txt : les événements des autres parties et ceux des
/// journaux (`apport`), sur les `JOURS` jours avant `maintenant` (secondes depuis 1970).
pub(crate) fn partie(dossier: &Path, parties: &[Partie], apport: Apport, maintenant: i64) -> Partie {
    let mut p = Partie::new(titre());
    let debut = maintenant - JOURS * 86_400;
    let tous = parties
        .iter()
        .flat_map(|x| x.evenements.iter().cloned())
        .chain(apport.evenements);
    let (lignes, coupees) = borner(garder(tous, debut, maintenant), MAX_LIGNES);
    let contenu = texte(&lignes, coupees, debut, &chrono::Local, &apport.manques);
    p.manques = apport.manques;
    let n = lignes.len();
    let techniques = lignes.iter().filter(|e| e.mitre.is_some()).count();
    if p.ecrire(
        dossier,
        NOM,
        &contenu,
        bi!(
            "la chronologie de l'incident : ce que les autres fichiers ont de daté (journaux : connexions, sudo ou ouvertures de session, comptes créés, services, tâches, journaux effacés, modules du noyau, Defender ; ce que Vanguard a vu et fait : alertes, blocages, quarantaines ; ce qui se lance tout seul ; comptes ; fichiers récents, un par ligne s'il est exécutable, caché ou dans un dossier de démarrage, les autres comptés par dossier et par heure, comme les programmes dépliés par centaines), remis dans l'ordre du temps, du plus ancien au plus récent, sur les {JOURS} derniers jours, {MAX_LIGNES} lignes au plus ; une ligne par événement : heure locale, source, ce qui s'est passé, technique MITRE ATT&CK quand elle est évidente",
            "the incident timeline: what the other files hold with a date (logs: logins, sudo or logons, accounts created, services, tasks, logs cleared, kernel modules, Defender; what Vanguard saw and did: alerts, blocks, quarantines; what starts by itself; accounts; recent files, one per line if executable, hidden or in a startup folder, the others counted per folder and per hour, like programs unpacked by the hundred), put back in time order, oldest first, over the last {JOURS} days, {MAX_LIGNES} lines at most; one line per event: local time, source, what happened, MITRE ATT&CK technique when obvious"
        ),
    ) {
        p.compte = Some(bi!(
            "{n} événements ({techniques} avec une technique MITRE ATT&CK)",
            "{n} events ({techniques} with a MITRE ATT&CK technique)"
        ));
    }
    if coupees > 0 {
        p.manque(
            Bi::new(
                "Chronologie, les lignes les plus anciennes",
                "Timeline, the oldest lines",
            ),
            Raison::Lignes(coupees),
        );
    }
    p
}

// ───────────────────────────── Journaux texte (Linux, macOS) ─────────────────────────────

/// Le numéro d'un mois en anglais (« Oct »), comme l'écrivent syslog et last.
#[cfg(any(unix, test))]
fn mois(t: &str) -> Option<u32> {
    const MOIS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    MOIS.iter()
        .position(|m| *m == t)
        .and_then(|i| u32::try_from(i + 1).ok())
}

/// Une date sans année (syslog classique, last de macOS) : celle de cette année, ou de l'an dernier si elle tomberait
/// plus d'un jour dans le futur (un journal de décembre lu en janvier). `heure` : « 14:03:22 » ou « 14:03 ».
#[cfg(any(unix, test))]
fn date_sans_annee(
    mois: u32,
    jour: u32,
    heure: &str,
    maintenant: chrono::NaiveDateTime,
) -> Option<chrono::NaiveDateTime> {
    use chrono::Datelike;
    let h = chrono::NaiveTime::parse_from_str(heure, "%H:%M:%S")
        .or_else(|_| chrono::NaiveTime::parse_from_str(heure, "%H:%M"))
        .ok()?;
    let annee = maintenant.year();
    let d = chrono::NaiveDate::from_ymd_opt(annee, mois, jour)?.and_time(h);
    if d > maintenant + chrono::TimeDelta::days(1) {
        Some(chrono::NaiveDate::from_ymd_opt(annee - 1, mois, jour)?.and_time(h))
    } else {
        Some(d)
    }
}

/// La date au début d'une ligne de journal, et le reste de la ligne : « 2026-10-20T14:03:22-04:00 » (journalctl -o
/// short-iso, rsyslog d'aujourd'hui), « 2026-10-20 14:03:22.123456-0400 » (log show --style syslog de macOS) ou
/// « Oct 20 14:03:22 » (syslog classique, à l'heure de l'ordinateur et sans année).
#[cfg(any(unix, test))]
fn date_de_ligne<'a, Tz: TimeZone>(
    ligne: &'a str,
    maintenant: chrono::NaiveDateTime,
    fuseau: &Tz,
) -> Option<(i64, &'a str)> {
    let (premier, reste) = ligne.split_once(char::is_whitespace)?;
    if premier.len() > 10 && premier.as_bytes().get(10) == Some(&b'T') {
        let d = chrono::DateTime::parse_from_rfc3339(premier)
            .or_else(|_| chrono::DateTime::parse_from_str(premier, "%Y-%m-%dT%H:%M:%S%.f%z"))
            .ok()?;
        return Some((d.timestamp(), reste));
    }
    if premier.len() == 10 && premier.as_bytes().get(4) == Some(&b'-') {
        let (heure, reste) = reste.trim_start().split_once(char::is_whitespace)?;
        let d = chrono::DateTime::parse_from_str(&format!("{premier} {heure}"), "%Y-%m-%d %H:%M:%S%.f%z").ok()?;
        return Some((d.timestamp(), reste));
    }
    let mois = mois(premier)?;
    let (jour, reste) = reste.trim_start().split_once(char::is_whitespace)?;
    let (heure, reste) = reste.trim_start().split_once(char::is_whitespace)?;
    let d = date_sans_annee(mois, jour.parse().ok()?, heure, maintenant)?;
    Some((locale_vers_secondes(d, fuseau)?, reste))
}

/// La date d'une ligne de journal texte, en secondes depuis 1970 : jusqu'où un journal remonte.
#[cfg(any(unix, test))]
pub(crate) fn quand_de_ligne<Tz: TimeZone>(ligne: &str, maintenant: chrono::NaiveDateTime, fuseau: &Tz) -> Option<i64> {
    date_de_ligne(ligne, maintenant, fuseau).map(|(q, _)| q)
}

/// Une ligne d'un journal texte : l'événement de la chronologie qu'elle raconte, s'il en est un. Après la date,
/// « hôte programme[pid]: message ». `maintenant` (heure locale) : l'année des dates qui n'en ont pas.
#[cfg(any(unix, test))]
pub(crate) fn lire_ligne_journal<Tz: TimeZone>(
    ligne: &str,
    maintenant: chrono::NaiveDateTime,
    fuseau: &Tz,
) -> Option<Evenement> {
    let (quand, reste) = date_de_ligne(ligne, maintenant, fuseau)?;
    let (_hote, reste) = reste.trim_start().split_once(char::is_whitespace)?;
    let (ident, message) = reste.trim_start().split_once(": ")?;
    if ident.contains(char::is_whitespace) {
        return None;
    }
    let programme = ident.split('[').next().unwrap_or(ident);
    let (genre, detail) = classer(programme, message.trim())?;
    Some(Evenement::new(quand, Source::Journal, genre, detail))
}

/// Ce que raconte le message d'un programme, s'il intéresse la chronologie : connexions SSH (sshd, sshd-session),
/// sudo, comptes créés (useradd) ou ajoutés à un groupe (usermod, gpasswd), module du noyau hors arbre ou non signé.
#[cfg(any(unix, test))]
fn classer(programme: &str, message: &str) -> Option<(Genre, String)> {
    if programme.starts_with("sshd") {
        if let Some(r) = message.strip_prefix("Accepted ") {
            return Some((Genre::SshAccepte, connexion_ssh(r)?));
        }
        return Some((Genre::SshRefuse, connexion_ssh(message.strip_prefix("Failed ")?)?));
    }
    match programme {
        "sudo" => sudo(message),
        "useradd" => Some((Genre::CompteCree, nouveau_compte(message.strip_prefix("new user: ")?)?)),
        "usermod" => {
            // « add 'bob' to group 'wheel' » ; la même ligne pour « shadow group » serait un doublon.
            let r = message.strip_prefix("add '")?;
            let (compte, groupe) = r.split_once("' to group '")?;
            Some((
                Genre::AjoutAuGroupe,
                format!("{compte} → {}", groupe.strip_suffix('\'')?),
            ))
        }
        "gpasswd" => {
            // « user bob added by root to group wheel »
            let r = message.strip_prefix("user ")?;
            let (compte, r) = r.split_once(" added by ")?;
            let (auteur, groupe) = r.rsplit_once(" to group ")?;
            Some((Genre::AjoutAuGroupe, format!("{compte} → {groupe} (par/by {auteur})")))
        }
        "kernel" => module_du_noyau(message),
        _ => None,
    }
}

/// « publickey for alice from 192.0.2.10 port 52222 ssh2: … » → « alice ← 192.0.2.10 (publickey) ». Un compte qui
/// n'existe pas (« invalid user ») est dit : c'est un robot qui essaie des noms.
#[cfg(any(unix, test))]
fn connexion_ssh(r: &str) -> Option<String> {
    let (methode, r) = r.split_once(" for ")?;
    let (compte, inconnu) = match r.strip_prefix("invalid user ") {
        Some(r) => (r, " (compte inconnu/unknown account)"),
        None => (r, ""),
    };
    let (compte, apres) = compte.rsplit_once(" from ")?;
    let adresse = apres.split_whitespace().next()?;
    Some(format!("{compte} ← {adresse} ({methode}){inconnu}"))
}

/// « alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id » → « alice → root : /usr/bin/id ». Un
/// refus a sa raison avant TTY (« 3 incorrect password attempts », « user NOT in sudoers »). Sans COMMAND (sudo qui ne
/// lit pas sa configuration) : rien.
#[cfg(any(unix, test))]
fn sudo(message: &str) -> Option<(Genre, String)> {
    let (compte, r) = message.split_once(" : ")?;
    let commande = &r[r.find("COMMAND=")? + "COMMAND=".len()..];
    let cible = r.split(" ; ").find_map(|c| c.strip_prefix("USER=")).unwrap_or("root");
    let premier = r.split(" ; ").next().unwrap_or_default();
    let ordinaire = ["TTY=", "PWD=", "USER=", "COMMAND=", "HOST="]
        .iter()
        .any(|c| premier.starts_with(c));
    let detail = format!("{} → {cible} : {}", compte.trim(), commande.trim());
    Some(if ordinaire {
        (Genre::Sudo, detail)
    } else {
        (Genre::SudoRefuse, format!("{detail} ({})", premier.trim()))
    })
}

/// « name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/1 » → « bob (UID 1001, /bin/bash) ».
#[cfg(any(unix, test))]
fn nouveau_compte(r: &str) -> Option<String> {
    let valeur = |cle: &str| r.split(", ").find_map(|c| c.strip_prefix(cle));
    let nom = valeur("name=")?;
    Some(match (valeur("UID="), valeur("shell=")) {
        (Some(uid), Some(shell)) => format!("{nom} (UID {uid}, {shell})"),
        (Some(uid), None) => format!("{nom} (UID {uid})"),
        _ => nom.to_string(),
    })
}

/// « nvidia: loading out-of-tree module taints kernel. » → « nvidia (hors arbre/out-of-tree) » ; « x: module
/// verification failed: … » → « x (non signé/unsigned) ». Les modules ordinaires ne laissent pas de trace au
/// chargement ; un module hors arbre ou non signé, si : c'est la marque d'un rootkit (ou d'un pilote comme celui de
/// NVIDIA). Le temps du noyau en tête (« [   12.345678] », kern.log) est passé.
#[cfg(any(unix, test))]
fn module_du_noyau(message: &str) -> Option<(Genre, String)> {
    let message = match message.strip_prefix('[') {
        Some(r) => r.split_once("] ")?.1,
        None => message,
    };
    let (nom, r) = message.split_once(": ")?;
    if nom.contains(char::is_whitespace) {
        return None;
    }
    let genre = if r.starts_with("loading out-of-tree module taints kernel") {
        "hors arbre/out-of-tree"
    } else if r.starts_with("module verification failed") {
        "non signé/unsigned"
    } else {
        return None;
    };
    Some((Genre::ModuleDuNoyau, format!("{nom} ({genre})")))
}

/// L'hôte d'une session vient du réseau : une adresse, ou un nom avec un point (pas un affichage local « :0 », ni
/// « (tmux…) »).
#[cfg(any(unix, test))]
pub(crate) fn hote_distant(hote: &str) -> bool {
    hote.parse::<std::net::IpAddr>().is_ok() || (hote.contains('.') && !hote.starts_with(':') && !hote.contains('('))
}

/// Les démarrages et les sessions depuis le réseau d'après « last » : « -F » de Linux (« Tue Oct 20 23:09:30 2026 »),
/// ou sans année ni secondes (last de macOS, wtmpdb). Les sessions locales (terminaux, écran) ne sont pas gardées :
/// chaque terminal ouvert en fait une.
#[cfg(any(unix, test))]
pub(crate) fn lire_last<Tz: TimeZone>(sortie: &str, maintenant: chrono::NaiveDateTime, fuseau: &Tz) -> Vec<Evenement> {
    const JOURS_SEMAINE: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let mut v = Vec::new();
    for l in sortie.lines() {
        let mots: Vec<&str> = l.split_whitespace().collect();
        if mots.len() < 5 || mots[1] == "begins" {
            continue;
        }
        let Some(i) = (1..mots.len() - 3).find(|&i| {
            JOURS_SEMAINE.contains(&mots[i])
                && mois(mots[i + 1]).is_some()
                && mots[i + 2].parse::<u32>().is_ok()
                && mots[i + 3].contains(':')
        }) else {
            continue;
        };
        let (Some(m), Ok(jour)) = (mois(mots[i + 1]), mots[i + 2].parse::<u32>()) else {
            continue;
        };
        let annee = mots
            .get(i + 4)
            .filter(|a| a.len() == 4)
            .and_then(|a| a.parse::<i32>().ok());
        let date = match annee {
            Some(a) => chrono::NaiveDate::from_ymd_opt(a, m, jour).and_then(|d| {
                chrono::NaiveTime::parse_from_str(mots[i + 3], "%H:%M:%S")
                    .ok()
                    .map(|h| d.and_time(h))
            }),
            None => date_sans_annee(m, jour, mots[i + 3], maintenant),
        };
        let Some(quand) = date.and_then(|d| locale_vers_secondes(d, fuseau)) else {
            continue;
        };
        let compte = mots[0];
        match compte {
            "reboot" => {
                // Linux : « reboot system boot 6.17.1-arch1-1 » (la version du noyau) ; macOS : « reboot ~ ».
                let noyau = mots[1..i]
                    .iter()
                    .filter(|m| !["system", "boot", "~"].contains(m))
                    .copied()
                    .collect::<Vec<_>>()
                    .join(" ");
                v.push(Evenement::new(quand, Source::Compte, Genre::DemarrageOrdinateur, noyau));
            }
            "shutdown" | "runlevel" => {}
            _ => {
                let hote = mots.get(2..i).map(|h| h.join(" ")).unwrap_or_default();
                if hote_distant(&hote) {
                    v.push(Evenement::new(
                        quand,
                        Source::Compte,
                        Genre::SessionReseau,
                        format!("{compte} ← {hote} ({})", mots[1]),
                    ));
                }
            }
        }
    }
    v
}

// ───────────────────────────── Windows ─────────────────────────────

/// Un compte du système, pas une personne : ses ouvertures de session (services, gestionnaire de fenêtres) se
/// comptent par centaines et ne disent rien.
#[cfg(any(windows, test))]
fn compte_du_systeme(compte: &str) -> bool {
    let c = compte.to_uppercase();
    c.is_empty()
        || c == "-"
        || c.ends_with('$')
        || c.starts_with("DWM-")
        || c.starts_with("UMFD-")
        || [
            "SYSTEM",
            "SYSTÈME",
            "LOCAL SERVICE",
            "SERVICE LOCAL",
            "NETWORK SERVICE",
            "SERVICE RÉSEAU",
            "ANONYMOUS LOGON",
            "ANONYME",
        ]
        .contains(&c.as_str())
}

/// Une adresse d'origine qui ne vient pas du réseau : vide, « - », la boucle locale.
#[cfg(any(windows, test))]
fn adresse_locale(ip: &str) -> bool {
    ["", "-", "127.0.0.1", "::1"].contains(&ip)
}

/// Un événement d'un journal de Windows, d'après son numéro, sa date (UTC, ISO 8601) et ses valeurs nommées
/// (EventData, UserData), telles que `parcourir_nommes` les donne. Ouvertures de session d'une personne (4624 :
/// au clavier, Bureau à distance, en cache, ou par le réseau depuis une autre machine), échecs (4625), compte créé
/// (4720) ou ajouté à un groupe (4732), service installé (7045, 4697), tâche planifiée créée (4698), journal effacé
/// (1102, 104), bloc de script PowerShell (4104, sa première partie), Defender : menace détectée (1116), traitée
/// (1117), protection coupée (5001). `None` : un autre événement, ou un qui ne dit rien (session d'un service).
#[cfg(any(windows, test))]
pub(crate) fn evenement_windows(id: u32, date: &str, valeurs: &[(String, String)]) -> Option<Evenement> {
    let quand = chrono::DateTime::parse_from_rfc3339(date).ok()?.timestamp();
    let v = |nom: &str| valeurs.iter().find(|(n, _)| n == nom).map_or("", |(_, x)| x.trim());
    let par = |qui: &str| {
        if qui.is_empty() || qui == "-" {
            String::new()
        } else {
            format!(" (par/by {qui})")
        }
    };
    let depuis = |ip: &str| {
        if adresse_locale(ip) {
            String::new()
        } else {
            format!(" ← {ip}")
        }
    };
    let qui = || {
        let (domaine, compte) = (v("TargetDomainName"), v("TargetUserName"));
        if domaine.is_empty() || domaine == "-" {
            compte.to_string()
        } else {
            format!("{domaine}\\{compte}")
        }
    };
    let (genre, detail) = match id {
        4624 => {
            let type_ = v("LogonType");
            if compte_du_systeme(v("TargetUserName")) {
                return None;
            }
            let genre = match type_ {
                "10" => Genre::SessionBureauADistance,
                "2" | "11" => Genre::Session,
                "3" if !adresse_locale(v("IpAddress")) => Genre::Session,
                _ => return None,
            };
            (genre, format!("{}, type {type_}{}", qui(), depuis(v("IpAddress"))))
        }
        4625 => (
            Genre::EchecDeSession,
            format!("{}, type {}{}", qui(), v("LogonType"), depuis(v("IpAddress"))),
        ),
        4720 => (
            Genre::CompteCree,
            format!("{}{}", v("TargetUserName"), par(v("SubjectUserName"))),
        ),
        4732 => {
            // Un compte local est souvent nommé « - » : son SID le désigne.
            let membre = match v("MemberName") {
                "" | "-" => v("MemberSid"),
                nom => nom,
            };
            (
                Genre::AjoutAuGroupe,
                format!("{membre} → {}{}", v("TargetUserName"), par(v("SubjectUserName"))),
            )
        }
        4697 | 7045 => {
            let nom = v("ServiceName");
            if nom.is_empty() {
                return None;
            }
            let programme = if id == 4697 {
                v("ServiceFileName")
            } else {
                v("ImagePath")
            };
            (
                Genre::ServiceInstalle,
                format!("{nom} : {programme}{}", par(v("SubjectUserName"))),
            )
        }
        4698 => (
            Genre::TacheCreee,
            format!(
                "{}{}{}",
                v("TaskName"),
                commande_de_tache(v("TaskContent")),
                par(v("SubjectUserName"))
            ),
        ),
        1102 => (Genre::JournalEfface, format!("Security{}", par(v("SubjectUserName")))),
        104 => {
            let journal = v("Channel");
            if journal.is_empty() {
                return None;
            }
            (Genre::JournalEfface, format!("{journal}{}", par(v("SubjectUserName"))))
        }
        4104 => {
            // Un long script est découpé en plusieurs événements : le premier suffit à le reconnaître.
            if !matches!(v("MessageNumber"), "" | "1") {
                return None;
            }
            let script = v("ScriptBlockText").split_whitespace().collect::<Vec<_>>().join(" ");
            let detail = match v("Path") {
                "" => script,
                chemin => format!("{chemin} : {script}"),
            };
            (Genre::ScriptPowerShell, detail)
        }
        1116 => (Genre::MenaceDetectee, format!("{} : {}", v("Threat Name"), v("Path"))),
        1117 => (
            Genre::MenaceTraitee,
            format!("{} : {} ({})", v("Threat Name"), v("Action Name"), v("Path")),
        ),
        5001 => (Genre::ProtectionCoupee, String::new()),
        _ => return None,
    };
    Some(Evenement::new(quand, Source::Journal, genre, detail))
}

/// Ce que lance une tâche planifiée, d'après son XML (TaskContent du 4698) : « : programme arguments ».
#[cfg(any(windows, test))]
fn commande_de_tache(xml: &str) -> String {
    let entre = |balise: &str| {
        let debut = xml.find(&format!("<{balise}>"))? + balise.len() + 2;
        let fin = xml[debut..].find(&format!("</{balise}>"))?;
        Some(xml[debut..debut + fin].trim().to_string())
    };
    match (entre("Command"), entre("Arguments")) {
        (Some(c), Some(a)) => format!(" : {c} {a}"),
        (Some(c), None) => format!(" : {c}"),
        _ => String::new(),
    }
}

/// Les comptes locaux de Windows (lignes « nom␟activé␟dernière connexion␟mot de passe défini␟… », dates
/// « yyyy-MM-dd HH:mm » à l'heure de l'ordinateur) : dernière connexion et mot de passe défini de chacun.
#[cfg(any(windows, test))]
pub(crate) fn comptes_windows<Tz: TimeZone>(lignes: &[&str], separateur: char, fuseau: &Tz) -> Vec<Evenement> {
    let mut v = Vec::new();
    for l in lignes {
        let c: Vec<&str> = l.split(separateur).collect();
        let (Some(nom), Some(derniere), Some(mot_de_passe)) = (c.first(), c.get(2), c.get(3)) else {
            continue;
        };
        for (date, genre) in [
            (derniere, Genre::DerniereConnexion),
            (mot_de_passe, Genre::MotDePasseDefini),
        ] {
            if let Some(quand) = chrono::NaiveDateTime::parse_from_str(date.trim(), "%Y-%m-%d %H:%M")
                .ok()
                .and_then(|d| locale_vers_secondes(d, fuseau))
            {
                v.push(Evenement::new(quand, Source::Compte, genre, nom.trim()));
            }
        }
    }
    v
}

/// Une date FILETIME (intervalles de 100 ns depuis le 1er janvier 1601, celle d'une clé du registre) en secondes
/// depuis 1970 ; `None` pour une date nulle (jamais écrite).
#[cfg(any(windows, test))]
pub(crate) fn filetime_vers_unix(ft: u64) -> Option<i64> {
    if ft == 0 {
        return None;
    }
    i64::try_from(ft / 10_000_000).ok().map(|s| s - 11_644_473_600)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L'heure de l'est de l'Amérique du Nord en été (−4 h) : les tests ne dépendent pas du fuseau de l'ordinateur.
    fn fuseau() -> chrono::FixedOffset {
        chrono::FixedOffset::west_opt(4 * 3600).unwrap()
    }

    /// 2026-10-20 14:03:22 à −4 h.
    const T: i64 = 1_792_519_402;

    fn maintenant() -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 21)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
    }

    #[test]
    fn date_et_ligne() {
        assert_eq!(date_locale(T, &fuseau()), "2026-10-20 14:03:22 -04:00");
        let e = Evenement::new(
            T,
            Source::Journal,
            Genre::SshAccepte,
            "alice\t← 192.0.2.10\n(publickey)",
        );
        let l = ligne(&e, &fuseau());
        let champs: Vec<&str> = l.split('\t').collect();
        assert_eq!(champs.len(), 4, "{l}");
        assert_eq!(champs[0], "2026-10-20 14:03:22 -04:00");
        assert_eq!(champs[1], "journal/log");
        // Le détail vient de n'importe qui : ni tabulation ni saut de ligne n'y passent.
        assert_eq!(
            champs[2],
            "Connexion SSH acceptée/SSH login accepted : alice\\t← 192.0.2.10\\n(publickey)"
        );
        assert_eq!(champs[3], "T1021.004");
        let sans = Evenement::new(T, Source::Compte, Genre::DemarrageOrdinateur, "");
        assert!(ligne(&sans, &fuseau()).ends_with("Démarrage de l'ordinateur/Computer started\t-"));
        // Un détail trop long est coupé, la fin marquée.
        let long = Evenement::new(T, Source::Journal, Genre::ScriptPowerShell, "x".repeat(1000));
        let l = ligne(&long, &fuseau());
        assert!(l.contains(&format!("{}…\t", "x".repeat(MAX_DETAIL))), "{l}");
    }

    #[test]
    fn etiquettes_mitre() {
        let tag = |g: Genre| Evenement::new(T, Source::Journal, g, "").mitre;
        assert_eq!(tag(Genre::SshRefuse), Some("T1110"));
        assert_eq!(tag(Genre::EchecDeSession), Some("T1110"));
        assert_eq!(tag(Genre::Sudo), Some("T1548.003"));
        assert_eq!(tag(Genre::CompteCree), Some("T1136.001"));
        assert_eq!(tag(Genre::ServiceInstalle), Some("T1543.003"));
        assert_eq!(tag(Genre::TacheCreee), Some("T1053.005"));
        assert_eq!(tag(Genre::JournalEfface), Some("T1070.001"));
        assert_eq!(tag(Genre::ScriptPowerShell), Some("T1059.001"));
        assert_eq!(tag(Genre::ProtectionCoupee), Some("T1562.001"));
        assert_eq!(tag(Genre::SessionBureauADistance), Some("T1021.001"));
        assert_eq!(tag(Genre::MenaceDetectee), None);
        assert_eq!(tag(Genre::DemarrageOrdinateur), None);
        // D'après l'endroit.
        for (chemin, attendu) in [
            (
                "/etc/systemd/system/multi-user.target.wants/x.service",
                Some("T1543.002"),
            ),
            ("/home/alice/.config/systemd/user/x.service", Some("T1543.002")),
            ("/home/alice/.config/autostart/x.desktop", Some("T1547.013")),
            ("/etc/cron.d/x", Some("T1053.003")),
            ("/var/spool/cron/alice", Some("T1053.003")),
            ("/home/alice/.ssh/authorized_keys", Some("T1098.004")),
            ("/etc/ld.so.preload", Some("T1574.006")),
            ("/etc/rc.local", Some("T1037.004")),
            ("/home/alice/.bashrc", Some("T1546.004")),
            ("/etc/profile.d/x.sh", Some("T1546.004")),
            (
                "/Users/alice/Library/LaunchAgents/com.exemple.x.plist",
                Some("T1543.001"),
            ),
            ("/Library/LaunchDaemons/com.exemple.x.plist", Some("T1543.004")),
            (
                r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
                Some("T1547.001"),
            ),
            (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                Some("T1547.001"),
            ),
            (r"C:\Windows\System32\Tasks\Mise a jour", Some("T1053.005")),
            (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", None),
            ("/tmp/cron-x.sh", None),
            ("/home/alice/Téléchargements/facture.pdf.exe", None),
        ] {
            assert_eq!(mitre_du_chemin(chemin), attendu, "{chemin}");
        }
        let e = Evenement::lancement(T, "/etc/systemd/system/x.service");
        assert_eq!((e.genre, e.mitre), (Genre::ServiceSystemd, Some("T1543.002")));
        let e = Evenement::lancement(T, "/home/alice/.zshrc");
        assert_eq!((e.genre, e.mitre), (Genre::Lancement, Some("T1546.004")));
        let e = Evenement::fichier(T, "/tmp/x", 12, Some("ab"));
        assert_eq!((e.source, e.mitre), (Source::Fichier, None));
        assert_eq!(e.detail, "/tmp/x (12 octets/bytes) SHA-256 ab");
        // /proc n'a pas de vraie date.
        let t = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1000);
        let l = lancements(&[("/proc/modules".into(), t), ("/etc/rc.local".into(), t)]);
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].quand, 1000);
    }

    #[test]
    fn fichiers_parlants_et_regroupes() {
        let p = |chemin: &str, relatif: &str, x: bool| parlant(chemin, Path::new(relatif), x, false);
        assert!(p("/tmp/x/outil", "x/outil", true));
        assert!(p("/tmp/x/a.SH", "x/a.SH", false));
        assert!(p(r"C:\Users\alice\Downloads\facture.pdf.exe", "facture.pdf.exe", false));
        assert!(p("/tmp/.x/donnees", ".x/donnees", false));
        assert!(p("/dev/shm/.cache", ".cache", false));
        assert!(p("/home/alice/.config/autostart/x.desktop", "x.desktop", false));
        assert!(parlant(r"C:\Users\Public\note.txt", Path::new("note.txt"), false, true));
        assert!(!p("/tmp/cargo/build/lib.rlib", "cargo/build/lib.rlib", false));
        assert!(!p("/home/alice/Téléchargements/photo.jpg", "photo.jpg", false));
        let f = |chemin: &str, dossier: &str, quand: i64, parlant: bool| FichierRecent {
            chemin: chemin.into(),
            dossier: dossier.into(),
            quand,
            taille: 10,
            empreinte: None,
            parlant,
        };
        // T est 14:03:22 à −4 h : trois fichiers de /tmp/a dans l'heure de 14 h, un à 15 h, un seul dans /tmp/b, un
        // programme.
        let v = evenements_des_fichiers(
            &[
                f("/tmp/a/1", "/tmp/a", T + 100, false),
                f("/tmp/a/x/2", "/tmp/a", T, false),
                f("/tmp/a/3", "/tmp/a", T + 1000, false),
                f("/tmp/a/4", "/tmp/a", T + 3600, false),
                f("/tmp/b/seul.txt", "/tmp/b", T, false),
                f("/tmp/a/mineur", "/tmp/a", T + 5, true),
            ],
            &fuseau(),
        );
        let vus: Vec<(i64, Genre, &str)> = v.iter().map(|e| (e.quand, e.genre, e.detail.as_str())).collect();
        assert_eq!(
            vus,
            [
                (T + 5, Genre::Fichier, "/tmp/a/mineur (10 octets/bytes)"),
                (
                    T,
                    Genre::FichiersGroupes,
                    "3 dans/in /tmp/a, entre/between 14:00 et/and 15:00"
                ),
                (T + 3600, Genre::Fichier, "/tmp/a/4 (10 octets/bytes)"),
                (T, Genre::Fichier, "/tmp/b/seul.txt (10 octets/bytes)"),
            ]
        );
        assert!(v.iter().all(|e| e.source == Source::Fichier && e.mitre.is_none()));
        // Des centaines de DLL dépliées dans la même heure : comptées par extension ; un raccourci du dossier
        // Démarrage garde sa ligne.
        let mut dlls: Vec<FichierRecent> = (0..30)
            .map(|i| f(&format!("/tmp/w/sys/{i}.dll"), "/tmp/w", T + i, true))
            .collect();
        dlls.push(f("/tmp/w/sys/a.exe", "/tmp/w", T + 40, true));
        dlls.push(f(
            "/home/alice/.config/autostart/x.desktop",
            "/home/alice/.config/autostart",
            T,
            true,
        ));
        let v = evenements_des_fichiers(&dlls, &fuseau());
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v[0].mitre, Some("T1547.013"));
        assert_eq!(v[1].genre, Genre::ProgrammesGroupes);
        assert_eq!(
            v[1].detail,
            "31 dans/in /tmp/w, entre/between 14:00 et/and 15:00 (dll 30, exe 1)"
        );
        // Le passage de 23 h à minuit.
        let tard = T + 9 * 3600 + 1800;
        let v = evenements_des_fichiers(
            &[
                f("/tmp/a/1", "/tmp/a", tard, false),
                f("/tmp/a/2", "/tmp/a", tard, false),
            ],
            &fuseau(),
        );
        assert_eq!(v[0].detail, "2 dans/in /tmp/a, entre/between 23:00 et/and 00:00");
    }

    /// Les alertes EVT- d'une analyse, à leur heure dans la chronologie, marquées ; ce qui n'a pas été vérifié est
    /// dit en tête du fichier.
    #[test]
    fn alertes_des_journaux_de_windows() {
        use crate::journaux_windows::regles::resultat;
        let d = std::env::temp_dir().join(format!("vanguard-chrono-evt-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        // Un dossier vide : toutes les règles non vérifiées, aucune alerte.
        let a = resultat::analyser_dossier(&d, &crate::journaux_windows::regles::moteur::Options::default()).unwrap();
        let apport = alertes_des_journaux(&a, &|_| false);
        assert_eq!(apport.evenements, Vec::<Evenement>::new());
        assert!(
            apport
                .manques
                .iter()
                .any(|m| m.quoi.fr.contains("EVT-") || matches!(&m.raison, Raison::Erreur(e) if e.starts_with("EVT-")))
        );
        let _ = std::fs::remove_dir_all(&d);
        let e = Evenement {
            mitre: Some("T1543.003"),
            ..Evenement::new(
                1_760_000_000,
                Source::Journal,
                Genre::AlerteDesJournaux,
                "EVT-SRV-001 [alerte] x\u{1b}[2J",
            )
        };
        let t = texte(&[e], 0, 1_759_000_000, &fuseau(), &[]);
        assert!(
            t.contains("ALERTE des journaux de Windows") && t.contains("T1543.003"),
            "{t}"
        );
        assert!(t.contains("Alertes des journaux de Windows (règles EVT-"), "{t}");
        assert!(!t.contains('\u{1b}'), "{t}");
    }

    #[test]
    fn fusion_tri_et_fenetre() {
        let e = |q: i64, d: &str| Evenement::new(q, Source::Journal, Genre::Sudo, d);
        let a = vec![e(T + 10, "b"), e(T - 8 * 86_400, "trop vieux"), e(T + 5, "a")];
        let b = vec![
            e(T + 10, "a"),
            e(T + 5, "a"),
            e(T + 99_999, "futur"),
            Evenement::lancement(T + 10, "/etc/rc.local"),
        ];
        let v = garder(a.into_iter().chain(b), T - JOURS * 86_400, T + 60);
        let vus: Vec<(i64, &str)> = v.iter().map(|e| (e.quand, e.detail.as_str())).collect();
        // Le doublon ne fait qu'une ligne ; à la même seconde, le journal avant le démarrage, puis le détail.
        assert_eq!(
            vus,
            [(T + 5, "a"), (T + 10, "a"), (T + 10, "b"), (T + 10, "/etc/rc.local")]
        );
    }

    #[test]
    fn bornes() {
        let f = |q: i64| Evenement::fichier(q, "/tmp/x", 1, None);
        let j = |q: i64| Evenement::new(q, Source::Journal, Genre::SshRefuse, "root ← 192.0.2.7");
        // 4 fichiers sans technique et 3 événements du journal, 5 lignes au plus : les 2 fichiers les plus anciens
        // partent, l'ordre reste.
        let v = vec![f(1), j(2), f(3), j(4), f(5), j(6), f(7)];
        let (gardes, coupees) = borner(v.clone(), 5);
        assert_eq!(coupees, 2);
        assert_eq!(gardes.iter().map(|e| e.quand).collect::<Vec<_>>(), [2, 4, 5, 6, 7]);
        // Plus d'événements importants que de place : plus aucun fichier, puis les plus anciens partent.
        let (gardes, coupees) = borner(v.clone(), 2);
        assert_eq!(coupees, 5);
        assert_eq!(gardes.iter().map(|e| e.quand).collect::<Vec<_>>(), [4, 6]);
        // Assez de place : rien ne bouge.
        assert_eq!(borner(v.clone(), 7), (v, 0));
        // Un fichier d'un endroit de démarrage garde sa place comme un événement du journal.
        let demarrage = Evenement::fichier(1, "/home/alice/.config/autostart/x.desktop", 1, None);
        let (gardes, _) = borner(vec![demarrage.clone(), f(2), j(3)], 2);
        assert_eq!(gardes, [demarrage, j(3)]);
    }

    #[test]
    fn journaux_texte() {
        let lire = |l: &str| lire_ligne_journal(l, maintenant(), &fuseau());
        let e = lire("2026-10-20T14:03:22-04:00 portable sshd-session[4242]: Accepted publickey for alice from 192.0.2.10 port 52222 ssh2: ED25519 SHA256:abc").unwrap();
        assert_eq!((e.quand, e.genre), (T, Genre::SshAccepte));
        assert_eq!(e.detail, "alice ← 192.0.2.10 (publickey)");
        let e = lire("2026-10-20T14:03:22-0400 portable sshd[4242]: Failed password for invalid user admin from 192.0.2.7 port 4444 ssh2").unwrap();
        assert_eq!((e.quand, e.genre), (T, Genre::SshRefuse));
        assert_eq!(
            e.detail,
            "admin ← 192.0.2.7 (password) (compte inconnu/unknown account)"
        );
        assert!(lire("2026-10-20T14:03:22-04:00 portable sshd[1]: Server listening on 0.0.0.0 port 22.").is_none());
        let e = lire("2026-10-20T14:03:22-04:00 portable sudo[77]:     alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id -u").unwrap();
        assert_eq!(e.genre, Genre::Sudo);
        assert_eq!(e.detail, "alice → root : /usr/bin/id -u");
        let e = lire("2026-10-20T14:03:22-04:00 portable sudo[77]:     alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/su").unwrap();
        assert_eq!(e.genre, Genre::SudoRefuse);
        assert_eq!(e.detail, "alice → root : /usr/bin/su (3 incorrect password attempts)");
        // sudo qui ne lit pas sa configuration n'a pas lancé de commande.
        assert!(lire("2026-10-20T14:03:22-04:00 portable sudo[77]:     root : unable to open /etc/sudoers : Invalid argument ; PWD=/ ; USER=root ;").is_none());
        let e = lire("2026-10-20T14:03:22-04:00 portable useradd[90]: new user: name=bob, UID=1001, GID=1001, home=/home/bob, shell=/bin/bash, from=/dev/pts/1").unwrap();
        assert_eq!(
            (e.genre, e.detail.as_str()),
            (Genre::CompteCree, "bob (UID 1001, /bin/bash)")
        );
        assert_eq!(e.mitre, Some("T1136.001"));
        let e = lire("2026-10-20T14:03:22-04:00 portable usermod[91]: add 'bob' to group 'wheel'").unwrap();
        assert_eq!((e.genre, e.detail.as_str()), (Genre::AjoutAuGroupe, "bob → wheel"));
        assert!(lire("2026-10-20T14:03:22-04:00 portable usermod[91]: add 'bob' to shadow group 'wheel'").is_none());
        let e = lire("2026-10-20T14:03:22-04:00 portable gpasswd[92]: user bob added by root to group wheel").unwrap();
        assert_eq!(e.detail, "bob → wheel (par/by root)");
        let e =
            lire("2026-10-20T14:03:22-04:00 portable kernel: rk: loading out-of-tree module taints kernel.").unwrap();
        assert_eq!(
            (e.genre, e.detail.as_str()),
            (Genre::ModuleDuNoyau, "rk (hors arbre/out-of-tree)")
        );
        assert_eq!(e.mitre, Some("T1547.006"));
        // syslog classique (kern.log, auth.log) : à l'heure de l'ordinateur, sans année.
        let e = lire("Oct 20 14:03:22 portable kernel: [   12.345678] rk: module verification failed: signature and/or required key missing - tainting kernel").unwrap();
        assert_eq!((e.quand, e.detail.as_str()), (T, "rk (non signé/unsigned)"));
        // Une ligne de décembre lue en janvier est de l'an dernier.
        let janvier = chrono::NaiveDate::from_ymd_opt(2027, 1, 2)
            .unwrap()
            .and_hms_opt(8, 0, 0)
            .unwrap();
        let e = lire_ligne_journal(
            "Dec 31 23:00:00 portable sshd[1]: Accepted password for alice from 192.0.2.10 port 1 ssh2",
            janvier,
            &fuseau(),
        )
        .unwrap();
        assert_eq!(date_locale(e.quand, &fuseau()), "2026-12-31 23:00:00 -04:00");
        // log show --style syslog de macOS.
        let e = lire("2026-10-20 14:03:22.123456-0400  localhost sshd[4242]: Accepted keyboard-interactive/pam for alice from 192.0.2.10 port 50000 ssh2").unwrap();
        assert_eq!((e.quand, e.genre), (T, Genre::SshAccepte));
        assert_eq!(
            quand_de_ligne(
                "2026-10-20T14:03:22-04:00 portable systemd[1]: Started x.service.",
                maintenant(),
                &fuseau()
            ),
            Some(T)
        );
        // En-têtes, suites de lignes, rien de daté : rien.
        for l in [
            "# Vanguard 0.82.0 — Journal",
            "-- No entries --",
            "    suite d'un message",
            "",
            "2026-10-20T14:03:22-04:00",
            "2026-10-20T14:03:22-04:00 portable un message sans programme",
        ] {
            assert!(lire(l).is_none(), "{l}");
        }
    }

    #[test]
    fn sessions_de_last() {
        let sortie = "alice    pts/3        192.0.2.10       Tue Oct 20 14:03:22 2026 - Tue Oct 20 15:00:00 2026  (00:56)\n\
                      alice    pts/0        wayland-1        Tue Oct 20 16:50:24 2026   still logged in\n\
                      alice    tty2         :0               Tue Oct 20 08:01:02 2026 - down  (08:00)\n\
                      reboot   system boot  6.17.1-arch1-1   Tue Oct 20 08:00:00 2026   still running\n\
                      bob      ttys001      192.0.2.11       Tue Oct 20 14:03   still logged in\n\
                      reboot   ~                             Tue Oct 20 07:00\n\
                      \n\
                      wtmp begins Thu Oct  1 13:50:52 2026\n";
        let v = lire_last(sortie, maintenant(), &fuseau());
        let vus: Vec<(Genre, &str)> = v.iter().map(|e| (e.genre, e.detail.as_str())).collect();
        assert_eq!(
            vus,
            [
                (Genre::SessionReseau, "alice ← 192.0.2.10 (pts/3)"),
                (Genre::DemarrageOrdinateur, "6.17.1-arch1-1"),
                (Genre::SessionReseau, "bob ← 192.0.2.11 (ttys001)"),
                (Genre::DemarrageOrdinateur, ""),
            ]
        );
        assert_eq!(v[0].quand, T);
        assert_eq!(v[2].quand, T - 22);
        assert!(v.iter().all(|e| e.source == Source::Compte));
    }

    fn valeurs(paires: &[(&str, &str)]) -> Vec<(String, String)> {
        paires
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn evenements_de_windows() {
        let date = "2026-10-20T18:03:22.1234567Z";
        let lire = |id: u32, p: &[(&str, &str)]| evenement_windows(id, date, &valeurs(p));
        let e = lire(
            4624,
            &[
                ("TargetUserName", "alice"),
                ("TargetDomainName", "PORTABLE"),
                ("LogonType", "10"),
                ("IpAddress", "192.0.2.10"),
            ],
        )
        .unwrap();
        assert_eq!(e.quand, T);
        assert_eq!((e.genre, e.mitre), (Genre::SessionBureauADistance, Some("T1021.001")));
        assert_eq!(e.detail, "PORTABLE\\alice, type 10 ← 192.0.2.10");
        // Les sessions des services et du système ne disent rien ; celles du réseau, seulement d'une autre machine.
        assert!(lire(4624, &[("TargetUserName", "alice"), ("LogonType", "5")]).is_none());
        assert!(lire(4624, &[("TargetUserName", "SYSTEM"), ("LogonType", "2")]).is_none());
        assert!(lire(4624, &[("TargetUserName", "PORTABLE$"), ("LogonType", "3")]).is_none());
        assert!(
            lire(
                4624,
                &[("TargetUserName", "alice"), ("LogonType", "3"), ("IpAddress", "::1")]
            )
            .is_none()
        );
        let e = lire(
            4624,
            &[
                ("TargetUserName", "alice"),
                ("LogonType", "3"),
                ("IpAddress", "192.0.2.12"),
            ],
        )
        .unwrap();
        assert_eq!(
            (e.genre, e.detail.as_str()),
            (Genre::Session, "alice, type 3 ← 192.0.2.12")
        );
        let e = lire(
            4625,
            &[
                ("TargetUserName", "admin"),
                ("LogonType", "3"),
                ("IpAddress", "192.0.2.7"),
            ],
        )
        .unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::EchecDeSession, Some("T1110")));
        let e = lire(4720, &[("TargetUserName", "bob"), ("SubjectUserName", "alice")]).unwrap();
        assert_eq!((e.genre, e.detail.as_str()), (Genre::CompteCree, "bob (par/by alice)"));
        let e = lire(
            4732,
            &[
                ("MemberName", "-"),
                ("MemberSid", "S-1-5-21-1-2-3-1001"),
                ("TargetUserName", "Administrateurs"),
                ("SubjectUserName", "alice"),
            ],
        )
        .unwrap();
        assert_eq!(e.detail, "S-1-5-21-1-2-3-1001 → Administrateurs (par/by alice)");
        let e = lire(
            7045,
            &[
                ("ServiceName", "Mise a jour"),
                ("ImagePath", r"C:\Users\alice\AppData\x.exe"),
            ],
        )
        .unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::ServiceInstalle, Some("T1543.003")));
        assert_eq!(e.detail, r"Mise a jour : C:\Users\alice\AppData\x.exe");
        assert!(lire(7045, &[("ImagePath", "x")]).is_none());
        let e = lire(
            4697,
            &[
                ("ServiceName", "x"),
                ("ServiceFileName", "x.exe"),
                ("SubjectUserName", "alice"),
            ],
        )
        .unwrap();
        assert_eq!(e.detail, "x : x.exe (par/by alice)");
        let e = lire(
            4698,
            &[
                ("TaskName", r"\Mise a jour"),
                (
                    "TaskContent",
                    "<Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-enc AAAA</Arguments></Exec></Actions></Task>",
                ),
                ("SubjectUserName", "alice"),
            ],
        )
        .unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::TacheCreee, Some("T1053.005")));
        assert_eq!(e.detail, r"\Mise a jour : powershell.exe -enc AAAA (par/by alice)");
        let e = lire(1102, &[("SubjectUserName", "alice")]).unwrap();
        assert_eq!(
            (e.genre, e.detail.as_str()),
            (Genre::JournalEfface, "Security (par/by alice)")
        );
        let e = lire(104, &[("SubjectUserName", "alice"), ("Channel", "System")]).unwrap();
        assert_eq!(
            (e.detail.as_str(), e.mitre),
            ("System (par/by alice)", Some("T1070.001"))
        );
        assert!(lire(104, &[("autre", "x")]).is_none());
        let e = lire(
            4104,
            &[
                ("MessageNumber", "1"),
                (
                    "ScriptBlockText",
                    "IEX (New-Object Net.WebClient)\r\n  .DownloadString('x')",
                ),
                ("Path", ""),
            ],
        )
        .unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::ScriptPowerShell, Some("T1059.001")));
        assert_eq!(e.detail, "IEX (New-Object Net.WebClient) .DownloadString('x')");
        assert!(lire(4104, &[("MessageNumber", "2"), ("ScriptBlockText", "suite")]).is_none());
        let e = lire(
            1116,
            &[
                ("Threat Name", "Virus:DOS/EICAR_Test_File"),
                ("Path", r"file:_C:\x.com"),
            ],
        )
        .unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::MenaceDetectee, None));
        assert_eq!(e.detail, r"Virus:DOS/EICAR_Test_File : file:_C:\x.com");
        let e = lire(
            1117,
            &[("Threat Name", "x"), ("Action Name", "Quarantaine"), ("Path", "y")],
        )
        .unwrap();
        assert_eq!(
            (e.genre, e.detail.as_str()),
            (Genre::MenaceTraitee, "x : Quarantaine (y)")
        );
        let e = lire(5001, &[]).unwrap();
        assert_eq!((e.genre, e.mitre), (Genre::ProtectionCoupee, Some("T1562.001")));
        assert!(lire(4634, &[]).is_none());
        assert!(evenement_windows(4625, "pas une date", &[]).is_none());
    }

    #[test]
    fn comptes_et_registre_de_windows() {
        let s = '\u{1f}';
        let lignes = [
            format!("alice{s}True{s}2026-10-20 14:03{s}2026-10-01 09:00{s}S-1-5-21-1-2-3-1001{s}"),
            format!("Invité{s}False{s}{s}{s}S-1-5-21-1-2-3-501{s}Compte invité"),
        ];
        let lignes: Vec<&str> = lignes.iter().map(String::as_str).collect();
        let v = comptes_windows(&lignes, s, &fuseau());
        assert_eq!(v.len(), 2);
        assert_eq!(
            (v[0].genre, v[0].quand, v[0].detail.as_str()),
            (Genre::DerniereConnexion, T - 22, "alice")
        );
        assert_eq!(v[1].genre, Genre::MotDePasseDefini);
        assert!(v.iter().all(|e| e.source == Source::Compte));
        // 1er janvier 1970 en FILETIME ; zéro : jamais écrite.
        assert_eq!(filetime_vers_unix(116_444_736_000_000_000), Some(0));
        assert_eq!(
            filetime_vers_unix(116_444_736_000_000_000 + 10_000_000 * 1_792_519_402),
            Some(T)
        );
        assert_eq!(filetime_vers_unix(0), None);
    }

    #[test]
    fn fichier_de_la_chronologie() {
        let dossier = crate::socle::dossier_local().join("chronologie");
        std::fs::create_dir_all(&dossier).unwrap();
        let _ = std::fs::remove_file(dossier.join(NOM));
        let maintenant = secondes(SystemTime::now()).unwrap();
        let mut demarrage = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
        demarrage.evenements = vec![
            Evenement::lancement(maintenant - 3600, "/etc/systemd/system/x.service"),
            Evenement::lancement(maintenant - 30 * 86_400, "/etc/rc.local"),
        ];
        let mut fichiers = Partie::new(Bi::new("Fichiers récents", "Recent files"));
        fichiers.evenements = (0..i64::try_from(MAX_LIGNES).unwrap())
            .map(|i| Evenement::fichier(maintenant - 7200 - i, &format!("/tmp/f{i}"), 1, None))
            .collect();
        let apport = Apport {
            evenements: vec![Evenement::new(
                maintenant - 60,
                Source::Journal,
                Genre::SshAccepte,
                "alice ← 192.0.2.10 (publickey)",
            )],
            manques: vec![Manque {
                quoi: Bi::new("Journal de sécurité", "Security log"),
                raison: Raison::Droits,
            }],
        };
        let p = partie(&dossier, &[demarrage, fichiers], apport, maintenant);
        assert_eq!(p.fichiers.len(), 1);
        assert_eq!(p.fichiers[0].nom, NOM);
        // La source illisible et les lignes coupées sont dites dans le LISEZMOI.
        assert!(p.manques.iter().any(|m| m.raison == Raison::Droits));
        assert!(p.manques.iter().any(|m| m.raison == Raison::Lignes(2)));
        let contenu = std::fs::read_to_string(dossier.join(NOM)).unwrap();
        assert!(
            contenu.starts_with("# Vanguard ") && contenu.contains("Chronologie de l'incident / Incident timeline")
        );
        assert!(contenu.contains(
            "# Incomplet ou illisible / incomplete or unreadable : Journal de sécurité / Security log (réservé à"
        ));
        assert!(contenu.contains("# Coupées / cut : 2 lignes de plus"));
        let lignes: Vec<&str> = contenu
            .lines()
            .skip_while(|l| !l.starts_with("DATE\t"))
            .skip(1)
            .collect();
        assert_eq!(lignes.len(), MAX_LIGNES);
        // Du plus ancien au plus récent ; le démarrage d'il y a 30 jours est hors de la fenêtre.
        assert!(lignes[lignes.len() - 2].contains("systemd"));
        assert!(lignes[lignes.len() - 1].contains("Connexion SSH acceptée"));
        assert!(!contenu.contains("rc.local"));
        let dates: Vec<i64> = lignes
            .iter()
            .map(|l| {
                let d = l.split('\t').next().unwrap();
                chrono::DateTime::parse_from_str(d, "%Y-%m-%d %H:%M:%S %:z")
                    .unwrap()
                    .timestamp()
            })
            .collect();
        assert!(dates.windows(2).all(|d| d[0] <= d[1]));
        // Rien : dit aussi.
        assert!(texte(&[], 0, T, &fuseau(), &[]).contains("(aucun événement / no event)"));
    }
}

/// Les journaux racontent ce que d'autres ont tapé : un nom de compte essayé par un robot, une commande, un script
/// PowerShell, un nom de service. Jamais de panique, et chaque ligne de la chronologie reste une seule ligne de quatre
/// champs, au détail borné.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    fn maintenant() -> chrono::NaiveDateTime {
        chrono::NaiveDate::from_ymd_opt(2026, 10, 21)
            .unwrap()
            .and_hms_opt(10, 0, 0)
            .unwrap()
    }

    /// Un fuseau quelconque, de −23 h 59 à +23 h 59.
    fn fuseau() -> impl Strategy<Value = chrono::FixedOffset> {
        (-86_399i32..86_400).prop_map(|s| chrono::FixedOffset::east_opt(s).unwrap())
    }

    /// Du texte d'attaquant : quelconque, ou fait des séparateurs que les lecteurs cherchent (« from », « port »,
    /// « : », « ; », « ' to group ' ») et de caractères qui casseraient une ligne ou l'affichage.
    fn texte() -> impl Strategy<Value = String> {
        let mot = prop_oneof![
            any::<String>(),
            prop::sample::select(vec![
                " from ",
                " port ",
                " for ",
                "invalid user ",
                ": ",
                " : ",
                " ; ",
                "COMMAND=",
                "USER=",
                "TTY=",
                "name=",
                ", UID=",
                ", shell=",
                "' to group '",
                "'",
                " added by ",
                " to group ",
                "] ",
                "[",
                "\t",
                "\n",
                "\r",
                "|",
                "\\",
                "\u{202e}",
                "\u{1b}[2J",
                "é",
                "😀",
                "192.0.2.10",
                "::1",
                "-",
            ])
            .prop_map(str::to_string),
        ];
        prop::collection::vec(mot, 0..10).prop_map(|m| m.concat())
    }

    /// Un mot d'attaquant (sans blanc, comme un nom de compte ou d'hôte), ou un texte d'attaquant.
    fn mot() -> impl Strategy<Value = String> {
        prop_oneof![3 => "[a-zA-Z0-9_.$é😀\u{202e}-]{1,12}", 1 => texte()]
    }

    /// Une ligne de journal texte : une date à l'un des trois formats (valide ou non), l'hôte, le programme et un
    /// message construit comme ceux que la chronologie lit, aux valeurs d'attaquant.
    fn ligne_de_journal() -> impl Strategy<Value = String> {
        let date = prop_oneof![
            3 => prop::sample::select(vec![
                "2026-10-20T14:03:22-04:00",
                "2026-10-20T14:03:22.5+0200",
                "2026-10-20 14:03:22.123456-0400",
                "Oct 20 14:03:22",
                "Dec 31 23:59",
                "Feb 29 12:00:00",
            ])
            .prop_map(str::to_string),
            1 => "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.+-]{0,20}",
            1 => "(Jan|Feb|Dec|Oct) +[0-9]{1,3} [0-9:]{0,9}",
            1 => any::<String>(),
        ];
        let adresse = prop_oneof![
            any::<[u8; 4]>().prop_map(|o| std::net::IpAddr::from(o).to_string()),
            mot()
        ];
        let message = prop_oneof![
            (
                prop::sample::select(vec![
                    "Accepted publickey for ",
                    "Failed password for ",
                    "Failed password for invalid user "
                ]),
                texte(),
                adresse,
                mot(),
                texte()
            )
                .prop_map(|(d, compte, a, port, reste)| format!(
                    "sshd[1]: {d}{compte} from {a} port {port} ssh2{reste}"
                )),
            (mot(), texte(), mot(), texte()).prop_map(|(compte, raison, cible, commande)| format!(
                "sudo[77]:     {compte} : {raison}TTY=pts/0 ; PWD=/home/x ; USER={cible} ; COMMAND={commande}"
            )),
            (texte(), mot(), texte()).prop_map(|(nom, uid, shell)| format!(
                "useradd[9]: new user: name={nom}, UID={uid}, GID=1001, home=/home/x, shell={shell}, from=/dev/pts/1"
            )),
            (texte(), texte()).prop_map(|(c, g)| format!("usermod[9]: add '{c}' to group '{g}'")),
            (texte(), texte(), texte()).prop_map(|(c, a, g)| format!("gpasswd[9]: user {c} added by {a} to group {g}")),
            (mot(), texte(), any::<bool>()).prop_map(|(nom, reste, signe)| if signe {
                format!("kernel: [   12.345678] {nom}: module verification failed: {reste}")
            } else {
                format!("kernel: {nom}: loading out-of-tree module taints kernel{reste}")
            }),
            texte().prop_map(|m| format!("cron[1]: {m}")),
        ];
        (date, mot(), message).prop_map(|(d, hote, m)| format!("{d} {hote} {m}"))
    }

    /// Une sortie de « last » : compte, terminal, hôte, puis une date (jour, mois, quantième, heure, année) vraie ou
    /// fausse, et la suite.
    fn sortie_de_last() -> impl Strategy<Value = String> {
        let choix =
            |v: Vec<&'static str>| prop_oneof![3 => prop::sample::select(v).prop_map(str::to_string), 1 => mot()];
        let ligne = (
            choix(vec!["reboot", "shutdown", "runlevel", "alice", "wtmp"]),
            choix(vec!["system boot", "pts/3", "~", "ttys001", "begins"]),
            choix(vec![
                "6.17.1-arch1-1",
                "192.0.2.10",
                ":0",
                "wayland-1",
                "box.example",
                "(:0)",
                "",
            ]),
            choix(vec!["Tue", "Mon", "Sun"]),
            choix(vec!["Oct", "Feb", "Dec"]),
            choix(vec!["20", "29", "31", "0", "99999999999"]),
            choix(vec!["14:03:22", "14:03", "25:61", ":"]),
            choix(vec!["2026", "2025", "0000", "99999", ""]),
            texte(),
        )
            .prop_map(|(c, t, h, j, m, q, heure, a, suite)| format!("{c} {t} {h} {j} {m} {q} {heure} {a} {suite}"));
        prop::collection::vec(prop_oneof![3 => ligne, 1 => texte()], 0..8).prop_map(|l| l.join("\n"))
    }

    /// Les valeurs nommées d'un événement de Windows : les noms lus, des valeurs d'attaquant.
    fn valeurs() -> impl Strategy<Value = Vec<(String, String)>> {
        let nom = prop::sample::select(vec![
            "TargetUserName",
            "TargetDomainName",
            "LogonType",
            "IpAddress",
            "SubjectUserName",
            "MemberName",
            "MemberSid",
            "ServiceName",
            "ServiceFileName",
            "ImagePath",
            "TaskName",
            "TaskContent",
            "Channel",
            "MessageNumber",
            "ScriptBlockText",
            "Path",
            "Threat Name",
            "Action Name",
        ]);
        let valeur = prop_oneof![
            texte(),
            prop::sample::select(vec!["2", "3", "10", "11", "1", "-", "", "SYSTEM", "PC$", "127.0.0.1"])
                .prop_map(str::to_string),
            (texte(), texte()).prop_map(|(c, a)| format!("<Task><Command>{c}</Command><Arguments>{a}</Arguments>")),
        ];
        prop::collection::vec((nom.prop_map(str::to_string), valeur), 0..12)
    }

    /// Une ligne de la chronologie : une seule ligne, quatre champs, un détail borné.
    fn ligne_sure(e: &Evenement, fuseau: chrono::FixedOffset) -> Result<(), TestCaseError> {
        let l = ligne(e, &fuseau);
        prop_assert!(!l.contains(['\n', '\r']), "{l:?}");
        prop_assert_eq!(l.split('\t').count(), 4, "{:?}", l);
        prop_assert!(
            l.split('\t').nth(2).unwrap().chars().count() <= 200 + MAX_DETAIL,
            "{l:?}"
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn journaux_texte(l in prop_oneof![ligne_de_journal(), any::<String>()], f in fuseau()) {
            let _ = quand_de_ligne(&l, maintenant(), &f);
            if let Some(e) = lire_ligne_journal(&l, maintenant(), &f) {
                ligne_sure(&e, f)?;
            }
        }

        #[test]
        fn sorties_de_last(s in prop_oneof![sortie_de_last(), any::<String>()], f in fuseau()) {
            let evenements = lire_last(&s, maintenant(), &f);
            prop_assert!(evenements.len() <= s.lines().count());
            for e in &evenements {
                ligne_sure(e, f)?;
            }
        }

        #[test]
        fn evenements_de_windows(
            id in prop::sample::select(vec![4624u32, 4625, 4720, 4732, 4697, 7045, 4698, 1102, 104, 4104, 1116, 1117, 5001, 0]),
            date in prop_oneof![Just("2026-10-20T18:03:22.1234567Z".to_string()), "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.Z+-]{0,24}", any::<String>()],
            v in valeurs(),
            f in fuseau(),
        ) {
            if let Some(e) = evenement_windows(id, &date, &v) {
                ligne_sure(&e, f)?;
            }
        }

        #[test]
        fn comptes_et_dates_de_windows(lignes in prop::collection::vec(texte(), 0..6), sep in prop_oneof![Just('\u{241f}'), Just('|'), any::<char>()], f in fuseau(), ft: u64, quand: i64) {
            let lignes: Vec<&str> = lignes.iter().map(String::as_str).collect();
            for e in comptes_windows(&lignes, sep, &f) {
                ligne_sure(&e, f)?;
            }
            let _ = filetime_vers_unix(ft);
            let _ = date_locale(quand, &f);
        }
    }
}
