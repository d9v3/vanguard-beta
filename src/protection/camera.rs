//! Caméra et micro : qui s'en sert ? En lecture seule. Sous Windows, le système note pour chaque programme la
//! dernière fois qu'il a utilisé la caméra ou le micro (et s'il s'en sert en ce moment) : Vanguard le lit et le date,
//! en signalant un programme lancé depuis un dossier temporaire ou Téléchargements. Sous Linux, aucun historique
//! n'existe : Vanguard dit ce qui tient la caméra (/dev/video*) et ce qui enregistre le micro (flux de PipeWire ou
//! PulseAudio) en ce moment, pour les programmes de ce compte. Sous macOS, la liste est protégée par le système :
//! Vanguard dit où la voir.

// macOS n'a ni historique ni liste lisible : seule l'explication sert.
#![cfg_attr(target_os = "macos", allow(dead_code))]

use crate::ui::*;

/// Un programme vu avec la caméra ou le micro.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Usage {
    /// Nom montré (application du Store) ou chemin du programme.
    programme: String,
    /// Dernier usage, « AAAA-MM-JJ HH:MM » ; `None` : jamais daté (Linux : en ce moment).
    dernier: Option<String>,
    en_cours: bool,
}

/// Un programme qui n'a rien à faire avec la caméra ou le micro, d'après l'endroit d'où il se lance.
pub(crate) fn lieu_suspect(programme: &str) -> bool {
    let bas = programme.to_lowercase().replace('/', "\\");
    [
        "\\appdata\\local\\temp\\",
        "\\windows\\temp\\",
        "\\downloads\\",
        "\\téléchargements\\",
        "\\users\\public\\",
    ]
    .iter()
    .any(|d| bas.contains(d))
}

fn afficher(titre_appareil: &str, usages: &[Usage]) {
    section(titre_appareil);
    if usages.is_empty() {
        trp!("  {GRIS}Aucun programme.{RESET}", "  {GRIS}No program.{RESET}");
        return;
    }
    for u in usages.iter().take(15) {
        let marque = if lieu_suspect(&u.programme) {
            format!("{}⚠{RESET}", couleur(crate::risk::Niveau::Eleve))
        } else if u.en_cours {
            format!("{}●{RESET}", couleur(crate::risk::Niveau::Moyen))
        } else {
            format!("{GRIS}·{RESET}")
        };
        let quand = match (&u.dernier, u.en_cours) {
            (_, true) => tr!("en ce moment", "right now").to_string(),
            (Some(d), false) => d.clone(),
            (None, false) => String::new(),
        };
        afficher_aligne(
            &format!("  {marque} {GRIS}{quand:<16}{RESET} "),
            &affichable(&u.programme),
            21,
            "",
        );
    }
    if usages.len() > 15 {
        trp!(
            "  {GRIS}… et {} autre(s), plus anciens.{RESET}",
            "  {GRIS}… and {} more, older.{RESET}",
            usages.len() - 15
        );
    }
}

/// `vanguard camera-micro` et le menu Antivirus et protection.
pub fn afficher_tout() {
    titre(tr!(
        "Caméra et micro : qui s'en sert ?",
        "Camera and microphone: who uses them?"
    ));
    #[cfg(windows)]
    {
        let (camera, micro) = (windows::lire("webcam"), windows::lire("microphone"));
        afficher(tr!("CAMÉRA", "CAMERA"), &camera);
        afficher(tr!("MICRO", "MICROPHONE"), &micro);
        conclure(camera.iter().chain(&micro));
    }
    #[cfg(target_os = "linux")]
    {
        let camera = linux::camera();
        let micro = linux::micro();
        if let Some(c) = &camera {
            afficher(tr!("CAMÉRA, EN CE MOMENT", "CAMERA, RIGHT NOW"), c);
        } else {
            section(tr!("CAMÉRA, EN CE MOMENT", "CAMERA, RIGHT NOW"));
            trp!(
                "  {GRIS}Impossible de lire les processus (/proc) : rien n'est conclu.{RESET}",
                "  {GRIS}Could not read the processes (/proc): nothing is concluded.{RESET}"
            );
        }
        if let Some(m) = &micro {
            afficher(tr!("MICRO, EN CE MOMENT", "MICROPHONE, RIGHT NOW"), m);
        } else {
            section(tr!("MICRO, EN CE MOMENT", "MICROPHONE, RIGHT NOW"));
            trp!(
                "  {GRIS}Impossible de lire les flux du micro (pactl absent ou serveur de son muet) : rien n'est conclu.{RESET}",
                "  {GRIS}Could not read the microphone streams (pactl missing or sound server silent): nothing is concluded.{RESET}"
            );
        }
        println!();
        for l in envelopper(
            tr!(
                "Linux ne garde pas d'historique : seul ce qui s'en sert maintenant se voit, pour les programmes de ce compte. Relancez l'outil quand le voyant de la caméra s'allume sans raison.",
                "Linux keeps no history: only what uses them now is visible, for this account's programs. Run the tool again when the camera light turns on for no reason."
            ),
            LARGEUR - 2,
        ) {
            println!("  {GRIS}{l}{RESET}");
        }
        // Rien vu, alors qu'une des deux lectures a manqué : non vérifié, jamais « aucun programme ».
        if camera.iter().chain(&micro).all(Vec::is_empty) && (camera.is_none() || micro.is_none()) {
            println!();
            trp!(
                "  {GRIS}Rien vu, mais tout n'a pas pu être lu : non vérifié. Rien n'a été changé.{RESET}",
                "  {GRIS}Nothing seen, but not everything could be read: not verified. Nothing was changed.{RESET}"
            );
        } else {
            conclure(camera.iter().flatten().chain(micro.iter().flatten()));
        }
    }
    #[cfg(target_os = "macos")]
    {
        for l in envelopper(
            tr!(
                "macOS protège cette liste : un point vert (caméra) ou orange (micro) s'allume en haut de l'écran quand un programme s'en sert, et le Centre de contrôle dit lequel. Les programmes autorisés : Réglages Système › Confidentialité et sécurité › Caméra, et › Micro ; retirez ceux que vous ne reconnaissez pas.",
                "macOS protects this list: a green (camera) or orange (microphone) dot lights up at the top of the screen when a program uses them, and Control Center says which one. The allowed programs: System Settings › Privacy & Security › Camera, and › Microphone; remove those you do not recognize."
            ),
            LARGEUR - 2,
        ) {
            println!("  {l}");
        }
    }
}

#[cfg(any(windows, target_os = "linux"))]
fn conclure<'a>(usages: impl Iterator<Item = &'a Usage>) {
    let usages: Vec<&Usage> = usages.collect();
    let suspects = usages.iter().filter(|u| lieu_suspect(&u.programme)).count();
    println!();
    if usages.is_empty() {
        trp!(
            "  {VERT}✔{RESET} Aucun programme ne s'en sert. Rien n'a été changé.",
            "  {VERT}✔{RESET} No program uses them. Nothing was changed."
        );
    } else if suspects == 0 {
        for l in envelopper(
            tr!(
                "Un programme que vous ne reconnaissez pas : cherchez son nom, puis retirez-le (Logiciels, ou « Mon ordinateur est-il contrôlé ? » pour un logiciel de prise de contrôle). Rien n'a été changé.",
                "A program you do not recognize: look up its name, then remove it (Software, or “Is my computer being controlled?” for a remote access tool). Nothing was changed."
            ),
            LARGEUR - 2,
        ) {
            println!("  {l}");
        }
    } else {
        for l in envelopper(
            tr!(
                "⚠ Un programme lancé depuis un dossier temporaire ou Téléchargements s'est servi de la caméra ou du micro : un logiciel espion se cache souvent là. Faites vérifier le fichier (Vérifier un fichier téléchargé, Analyse YARA) avant tout. Rien n'a été changé.",
                "⚠ A program started from a temporary folder or Downloads used the camera or microphone: spyware often hides there. Have the file checked (Check a downloaded file, YARA scan) first. Nothing was changed."
            ),
            LARGEUR - 2,
        ) {
            println!("  {l}");
        }
    }
}

/// « 2026-10-18 21:04 » d'un FILETIME de Windows (centaines de nanosecondes depuis 1601), en heure locale.
#[cfg(any(windows, test))]
pub(crate) fn date_filetime(ft: u64) -> Option<String> {
    if ft == 0 {
        return None;
    }
    let secondes = i64::try_from(ft / 10_000_000).ok()? - 11_644_473_600;
    let utc = chrono::DateTime::from_timestamp(secondes, 0)?;
    Some(utc.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
}

/// Les usages d'après le registre : (nom de la sous-clé, début, fin) ; un programme hors du Store a pour nom son
/// chemin, « \ » écrit « # ». Fin à zéro et début non nul : en cours. Les plus récents en tête.
#[cfg(any(windows, test))]
fn juger_windows(entrees: &[(String, u64, u64)]) -> Vec<Usage> {
    let mut usages: Vec<(u64, Usage)> = entrees
        .iter()
        .filter(|(_, debut, _)| *debut != 0)
        .map(|(nom, debut, fin)| {
            let programme = nom_programme(nom);
            let en_cours = *fin == 0;
            (
                (*debut).max(*fin),
                Usage {
                    programme,
                    dernier: date_filetime((*debut).max(*fin)),
                    en_cours,
                },
            )
        })
        .collect();
    usages.sort_by_key(|(t, u)| (!u.en_cours, std::cmp::Reverse(*t)));
    usages.into_iter().map(|(_, u)| u).collect()
}

/// Le nom montré d'une sous-clé du registre : un programme hors du Store a pour nom son chemin, « \ » écrit « # ».
#[cfg(any(windows, test))]
pub(crate) fn nom_programme(nom: &str) -> String {
    if nom.contains('#') {
        nom.replace('#', "\\")
    } else {
        nom.to_string()
    }
}

/// Ce que le registre (ConsentStore de CapabilityAccessManager) dit d'une capacité : `webcam`, `microphone`,
/// `location` ou `contacts`. Partagé avec le bilan de confidentialité (`acces`), qui lit aussi l'autorisation.
#[cfg(any(windows, test))]
#[derive(Debug, Default, Clone)]
pub(crate) struct Consentement {
    /// « Allow » ou « Deny » de la clé de la capacité : l'interrupteur de tout le compte (HKCU) ou de l'appareil
    /// (HKLM).
    pub(crate) global: Option<String>,
    /// La même chose pour les programmes classiques (sous-clé « NonPackaged »).
    pub(crate) hors_store: Option<String>,
    pub(crate) entrees: Vec<Entree>,
}

/// Une application notée sous la capacité.
#[cfg(any(windows, test))]
#[derive(Debug, Clone)]
pub(crate) struct Entree {
    /// Nom de la sous-clé : famille du paquet (Store) ou chemin, « \ » écrit « # » (programme classique).
    pub(crate) nom: String,
    /// « Allow » ou « Deny » ; les programmes classiques n'en ont souvent pas.
    pub(crate) valeur: Option<String>,
    /// FILETIME du dernier début et de la dernière fin d'usage (0 : jamais).
    pub(crate) debut: u64,
    pub(crate) fin: u64,
    pub(crate) hors_store: bool,
}

#[cfg(windows)]
pub(crate) mod windows {
    use super::{Consentement, Entree};
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    /// La capacité dans le registre de ce compte (`machine` faux) ou de tout l'ordinateur ; `None` : clé absente ou
    /// illisible. Les applications du Store, puis les autres (« NonPackaged »).
    pub(crate) fn consentement(machine: bool, capacite: &str) -> Option<Consentement> {
        let ruche = RegKey::predef(if machine { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
        let racine = ruche
            .open_subkey(format!(
                r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capacite}"
            ))
            .ok()?;
        let mut c = Consentement {
            global: racine.get_value("Value").ok(),
            ..Consentement::default()
        };
        let mut lire_cle = |cle: &RegKey, hors_store: bool| {
            for nom in cle.enum_keys().flatten() {
                if nom == "NonPackaged" {
                    continue;
                }
                if let Ok(k) = cle.open_subkey(&nom) {
                    c.entrees.push(Entree {
                        valeur: k.get_value("Value").ok(),
                        debut: k.get_value("LastUsedTimeStart").unwrap_or(0),
                        fin: k.get_value("LastUsedTimeStop").unwrap_or(0),
                        nom,
                        hors_store,
                    });
                }
            }
        };
        lire_cle(&racine, false);
        let hors_store = racine.open_subkey("NonPackaged").ok();
        if let Some(h) = &hors_store {
            lire_cle(h, true);
        }
        c.hors_store = hors_store.and_then(|h| h.get_value("Value").ok());
        Some(c)
    }

    /// `webcam` ou `microphone`, pour ce compte.
    pub(super) fn lire(appareil: &str) -> Vec<super::Usage> {
        let entrees: Vec<(String, u64, u64)> = consentement(false, appareil)
            .map(|c| c.entrees.into_iter().map(|e| (e.nom, e.debut, e.fin)).collect())
            .unwrap_or_default();
        super::juger_windows(&entrees)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Usage;

    /// Les programmes de ce compte qui tiennent un /dev/video* ouvert ; `None` : /proc illisible (la liste vide
    /// d'avant passait pour « personne »).
    pub(super) fn camera() -> Option<Vec<Usage>> {
        let mut noms: Vec<String> = Vec::new();
        for pid in crate::socle::processus::pids()? {
            let tient = std::fs::read_dir(format!("/proc/{pid}/fd"))
                .into_iter()
                .flatten()
                .flatten()
                .any(|fd| std::fs::read_link(fd.path()).is_ok_and(|l| l.to_string_lossy().starts_with("/dev/video")));
            if tient {
                let nom = crate::socle::processus::nom_court(pid).unwrap_or_default();
                let nom = format!("{} ({pid})", nom.trim());
                if !noms.contains(&nom) {
                    noms.push(nom);
                }
            }
        }
        Some(
            noms.into_iter()
                .map(|programme| Usage {
                    programme,
                    dernier: None,
                    en_cours: true,
                })
                .collect(),
        )
    }

    /// Les flux d'enregistrement en cours (pactl, que PipeWire comprend aussi) ; `None` : illisible.
    pub(super) fn micro() -> Option<Vec<Usage>> {
        let r = crate::commande::lancer_en_anglais(
            std::process::Command::new("pactl").args(["list", "source-outputs"]),
            5,
        )?;
        (r.code == Some(0)).then(|| super::lire_pactl(&r.sortie))
    }
}

/// `pactl list source-outputs` : un bloc « Source Output #N » par flux, avec application.name et
/// application.process.binary.
#[cfg(any(target_os = "linux", test))]
fn lire_pactl(texte: &str) -> Vec<Usage> {
    let valeur = |bloc: &str, cle: &str| {
        bloc.lines().find_map(|l| {
            let (k, v) = l.trim().split_once(" = ")?;
            (k == cle).then(|| v.trim().trim_matches('"').to_string())
        })
    };
    let mut usages: Vec<Usage> = Vec::new();
    for bloc in texte.split("Source Output #").skip(1) {
        let nom = valeur(bloc, "application.process.binary")
            .or_else(|| valeur(bloc, "application.name"))
            .unwrap_or_else(|| tr!("programme inconnu", "unknown program").to_string());
        if !usages.iter().any(|u| u.programme == nom) {
            usages.push(Usage {
                programme: nom,
                dernier: None,
                en_cours: true,
            });
        }
    }
    usages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn historique_de_windows() {
        // 2026-10-18 01:00:00 UTC en FILETIME, et une heure plus tard.
        let t = (1_792_285_200 + 11_644_473_600) * 10_000_000_u64;
        let h = 3600 * 10_000_000_u64;
        let usages = juger_windows(&[
            ("Microsoft.WindowsCamera_8wekyb3d8bbwe".into(), t, t + h),
            ("C:#Users#alice#AppData#Local#Temp#svc.exe".into(), t + 2 * h, 0),
            ("C:#Program Files#Zoom#bin#Zoom.exe".into(), t + 3 * h, t + 4 * h),
            ("Jamais.Utilisee_123".into(), 0, 0),
        ]);
        assert_eq!(usages.len(), 3);
        // En cours d'abord, puis du plus récent au plus ancien.
        assert!(usages[0].en_cours && usages[0].programme == r"C:\Users\alice\AppData\Local\Temp\svc.exe");
        assert!(lieu_suspect(&usages[0].programme));
        assert_eq!(usages[1].programme, r"C:\Program Files\Zoom\bin\Zoom.exe");
        assert!(!lieu_suspect(&usages[1].programme));
        assert_eq!(usages[2].programme, "Microsoft.WindowsCamera_8wekyb3d8bbwe");
        assert!(usages[2].dernier.as_deref().is_some_and(|d| d.starts_with("2026-10-1")));
        assert_eq!(date_filetime(0), None);
    }

    #[test]
    fn flux_du_micro() {
        let sortie = "Source Output #42\n\tDriver: PipeWire\n\tProperties:\n\t\tapplication.name = \"Firefox\"\n\
                      \t\tapplication.process.binary = \"firefox\"\nSource Output #43\n\tProperties:\n\
                      \t\tapplication.name = \"Discord\"\nSource Output #44\n\tProperties:\n\
                      \t\tapplication.process.binary = \"firefox\"\n";
        let u = lire_pactl(sortie);
        assert_eq!(
            u.iter().map(|x| x.programme.as_str()).collect::<Vec<_>>(),
            ["firefox", "Discord"]
        );
        assert!(u.iter().all(|x| x.en_cours));
        assert_eq!(lire_pactl(""), Vec::<Usage>::new());
        assert!(lieu_suspect(
            "/home/alice/Téléchargements/x".replace('/', "\\").as_str()
        ));
    }
}
