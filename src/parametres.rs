//! Paramètres : tous les réglages de Vanguard au même endroit (Cette machine › Paramètres, ou « s » au menu
//! principal ; `vanguard parametres`, alias `settings`). Ceux du lancement (langue, emojis, travail sans Internet) sont gardés dans
//! parametres.json, sur cet ordinateur, et lus au lancement, avant tout affichage ; une variable d'environnement
//! (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) l'emporte toujours sur le fichier. Les autres gardent leur
//! place et leur code, que ce menu appelle : la surveillance horaire et l'entretien du mois (leurs minuteries), les
//! alertes apprises (appris.json), le blocage (blocage.json), les restrictions des extensions (plugins/reglages.json,
//! par leur interrupteur et son accord), la clé abuse.ch (`protection::abuse_ch`, jamais montrée en entier), la
//! protection en temps réel (`protection::temps_reel` : coupée d'un coup pour un temps ou jusqu'à reprise, après
//! accord, sans toucher aux réglages de chacun). Chaque changement est montré avec sa valeur d'avant, et s'annule en
//! la remettant. Le téléchargement des versions des logiciels (`protection::perimes`) est gardé dans parametres.json
//! aussi, mais lu à chaque usage : ce n'est pas un réglage du lancement. parametres.json est scellé (`sceau`) : changé
//! hors de Vanguard, ce qu'il coupait (travail sans Internet, autodiagnostic, versions des logiciels) reste en marche,
//! et c'est dit.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::langue::Reponse;
use crate::selection::{Ligne, choisir};
use crate::ui::*;

/// Ce que garde parametres.json : les réglages du lancement, lus une fois, et celui du téléchargement des versions
/// des logiciels, lu à chaque usage (`versions_logiciels`).
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, Debug)]
#[allow(clippy::struct_excessive_bools)] // des réglages, chacun pour lui-même
struct Fichier {
    /// « fr » ou « en » ; absente : la langue du système.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    langue: Option<String>,
    /// Absente : d'après la console (l'ancienne console de Windows les dessine mal).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    emojis: Option<bool>,
    /// Travailler sans Internet, comme VANGUARD_HORS_LIGNE.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    hors_ligne: bool,
    /// Ne plus télécharger les fichiers des dernières versions des logiciels (oui par défaut).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sans_versions: bool,
    /// Ne plus faire l'autodiagnostic de la semaine avec la surveillance (fait par défaut).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sans_autotest: bool,
    /// Envoyer à aur.archlinux.org le nom des paquets installés hors des dépôts (non par défaut : sans cet accord, la
    /// règle LNX-MAJ-006 n'est pas vérifiée).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    paquets_aur: bool,
}

/// Au-delà, ce n'est pas le fichier de Vanguard : il n'est pas lu (le processus élevé de Windows le lit aussi).
const TAILLE_MAX: u64 = 64 << 10;

/// Le nom du fichier, scellé (`sceau`) : trois de ses réglages coupent une défense.
pub(crate) const PARAMETRES: &str = "parametres.json";

fn fichier() -> PathBuf {
    crate::socle::dossier_local().join(PARAMETRES)
}

/// Le fichier ; absent : les défauts ; `Err` (la raison) s'il est là mais ne se lit pas.
fn charger_de(chemin: &Path) -> Result<Fichier, crate::modele::Echec> {
    charger_juge(chemin).map(|(f, _)| f)
}

/// Le fichier relu sous son sceau, et s'il n'est pas tel que Vanguard l'a écrit : la raison, quand des réglages qui
/// coupent une défense (travail sans Internet, autodiagnostic de la semaine, versions des logiciels) ou donnent un
/// accord (paquets de l'AUR : leurs noms sortent de l'ordinateur) y étaient et ont été ignorés. Un programme du compte qui écrivait `{"hors_ligne":true}` coupait les mises à jour, les listes
/// de menaces et l'épreuve du DNS, sous un simple « pas d'Internet ». Changé hors de Vanguard, ou accepté tel quel
/// après des sceaux refaits (rien ne prouve qui l'a écrit ; repris d'une version d'avant à la mise à jour, il vaut,
/// lui) : ces réglages valent leur défaut, le plus protecteur,
/// jusqu'à ce que la personne les règle de nouveau ici ; la langue et les emojis, eux, restent. Lu sans rien écrire
/// (`sceau::lire_sans_ecrire`) : il l'est au lancement, avant la reprise des données d'une version d'avant.
///
/// La langue se lit dans ce fichier : pendant sa lecture au lancement, `tr!` répond en français sans la demander
/// (`en_lecture`) ; les raisons gardées se traduisent à l'affichage (`Douteux::texte`).
fn charger_juge(chemin: &Path) -> Result<(Fichier, Option<Douteux>), crate::modele::Echec> {
    use crate::modele::{Echec, Raison};
    use crate::sceau::Lecture;
    const OU: &str = "parametres/lire";
    let illisible = |e: String| Echec::new(OU, Raison::Illisible(e));
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or(PARAMETRES);
    let (octets, douteux) = match crate::sceau::lire_sans_ecrire(dossier, nom) {
        Lecture::Absent | Lecture::Inconnu | Lecture::Falsifie(None) => return Ok((Fichier::default(), None)),
        Lecture::Illisible(e) => return Err(illisible(e)),
        Lecture::Intact(o) => (o, None),
        // Accepté tel quel lors de la mise à jour d'une version d'avant le sceau : les réglages de la personne,
        // gardés. Accepté parce que les sceaux ont été refaits : rien ne prouve qui l'a écrit.
        Lecture::Adopte(o) if !crate::sceau::refaits_dans(dossier) => (o, None),
        Lecture::Adopte(o) => (o, Some(Douteux::Adopte)),
        Lecture::Falsifie(Some(o)) => (o, Some(Douteux::HorsVanguard)),
    };
    if octets.len() as u64 > TAILLE_MAX {
        return Err(illisible(trf!("plus de {} Kio", "over {} KiB", TAILLE_MAX >> 10)));
    }
    let texte = String::from_utf8(octets).map_err(|e| illisible(e.to_string()))?;
    let mut f: Fichier =
        serde_json::from_str(texte.trim_start_matches('\u{feff}')).map_err(|e| illisible(e.to_string()))?;
    let Some(raison) = douteux else {
        return Ok((f, None));
    };
    let coupait = f.hors_ligne || f.sans_autotest || f.sans_versions || f.paquets_aur;
    f.hors_ligne = false;
    f.sans_autotest = false;
    f.sans_versions = false;
    // Un accord ne se donne pas à la place de la personne : écrit hors de Vanguard, il ne vaut pas.
    f.paquets_aur = false;
    Ok((f, coupait.then_some(raison)))
}

/// parametres.json d'une version d'avant, accepté tel quel à la mise à jour : rescellé (`sceau::resceller_si`).
pub(crate) fn resceller_d_avant() {
    crate::sceau::resceller_si(PARAMETRES, |o| serde_json::from_slice::<Fichier>(o).is_ok());
}

/// Pourquoi des réglages qui coupaient une défense ont été ignorés.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Douteux {
    /// Accepté tel quel au premier usage des sceaux.
    Adopte,
    /// Changé hors de Vanguard.
    HorsVanguard,
}

impl Douteux {
    fn texte(self) -> &'static str {
        match self {
            Douteux::Adopte => tr!(
                "accepté tel quel après des sceaux refaits",
                "accepted as it was after seals were remade"
            ),
            Douteux::HorsVanguard => tr!("changé hors de Vanguard", "changed outside Vanguard"),
        }
    }
}

fn enregistrer_dans(f: &Fichier, chemin: &Path) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(f).map_err(std::io::Error::other)?;
    let dossier = chemin.parent().unwrap_or_else(|| Path::new("."));
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or(PARAMETRES);
    crate::sceau::ecrire_dans(dossier, nom, texte.as_bytes())
}

/// Les réglages du lancement, lus une fois : un fichier abîmé vaut les défauts (le menu le dit).
fn au_demarrage() -> &'static Fichier {
    static LUS: OnceLock<Fichier> = OnceLock::new();
    LUS.get_or_init(|| {
        EN_LECTURE.with(|l| l.set(true));
        let lus = charger_de(&fichier()).unwrap_or_default();
        EN_LECTURE.with(|l| l.set(false));
        lus
    })
}

// Les réglages du lancement se lisent sur ce fil : la langue (`langue::anglais`), qui les attend, ne les redemande
// pas pendant ce temps (elle attendrait sa propre réponse pour toujours, au premier `tr!` d'une lecture refusée).
thread_local! {
    static EN_LECTURE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Les réglages du lancement sont-ils en cours de lecture sur ce fil ?
pub(crate) fn en_lecture() -> bool {
    EN_LECTURE.with(std::cell::Cell::get)
}

/// Pourquoi Vanguard ne va pas sur Internet, à dire là où il ne vérifie rien en ligne : un réglage (variable, fichier,
/// ou la commande elle-même), jamais un simple « pas d'Internet », qui cacherait qu'il a été demandé.
pub(crate) fn raison_hors_ligne() -> &'static str {
    if HORS_LIGNE_FORCE.load(std::sync::atomic::Ordering::SeqCst) {
        return tr!(
            "travail sans Internet demandé pour cette commande",
            "offline work requested for this command"
        );
    }
    let variable = std::env::var_os("VANGUARD_HORS_LIGNE").map(|v| v.to_string_lossy().into_owned());
    if hors_ligne_voulu(variable.as_deref(), false) {
        return tr!(
            "travail sans Internet demandé par VANGUARD_HORS_LIGNE",
            "offline work requested by VANGUARD_HORS_LIGNE"
        );
    }
    tr!(
        "travail sans Internet réglé dans les Paramètres (« vanguard parametres sans-internet non » pour le couper)",
        "offline work set in Settings (“vanguard settings offline no” to turn it off)"
    )
}

/// À appeler au début du programme, avant tout affichage : les réglages du lancement sont lus là.
pub fn au_lancement() {
    let _ = au_demarrage();
}

/// La langue voulue : VANGUARD_LANG, sinon le fichier ; `None` : celle du système.
pub(crate) fn langue() -> Option<String> {
    priorite(crate::passage::variable("VANGUARD_LANG"), au_demarrage().langue.clone())
}

/// Les emojis voulus, tels que `ui` les lit (« 1 », « 0 ») : VANGUARD_EMOJI, sinon le fichier ; `None` : d'après
/// la console.
pub(crate) fn emojis() -> Option<String> {
    priorite(
        crate::passage::variable("VANGUARD_EMOJI"),
        au_demarrage().emojis.map(|e| if e { "1" } else { "0" }.to_string()),
    )
}

/// Travailler sans Internet : VANGUARD_HORS_LIGNE posée (sauf à « 0 », « non »…), sinon le fichier.
pub(crate) fn hors_ligne() -> bool {
    if HORS_LIGNE_FORCE.load(std::sync::atomic::Ordering::SeqCst) {
        return true;
    }
    let variable = std::env::var_os("VANGUARD_HORS_LIGNE").map(|v| v.to_string_lossy().into_owned());
    hors_ligne_voulu(variable.as_deref(), au_demarrage().hors_ligne)
}

/// Télécharger les fichiers des dernières versions des logiciels ? Oui par défaut ; lu dans le fichier à chaque
/// usage, pour qu'un changement vaille aussitôt. Un fichier illisible vaut les défauts, comme au lancement. Le travail
/// sans Internet (`hors_ligne`) coupe aussi ce téléchargement, à part.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) fn versions_logiciels() -> bool {
    !charger_de(&fichier()).unwrap_or_default().sans_versions
}

/// Envoyer à l'AUR le nom des paquets installés hors des dépôts ? Non par défaut : c'est une partie de la liste des
/// logiciels qui sort de l'ordinateur. Lu à chaque usage, comme les versions.
#[cfg(target_os = "linux")]
pub(crate) fn paquets_aur() -> bool {
    charger_de(&fichier()).unwrap_or_default().paquets_aur
}

/// L'autodiagnostic de la semaine, avec la surveillance ? Oui par défaut ; lu à chaque usage, comme les versions.
pub(crate) fn autotest_hebdomadaire() -> bool {
    !charger_de(&fichier()).unwrap_or_default().sans_autotest
}

/// Hors ligne forcé pour ce processus (`vanguard autotest` sans `--internet`) : poser `VANGUARD_HORS_LIGNE` par
/// `set_var` n'est pas sûr dès qu'un fil existe (`unsafe` en Rust 2024), ce drapeau, si.
static HORS_LIGNE_FORCE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Travailler sans Internet jusqu'à la fin du processus, quoi que disent la variable et le fichier.
pub(crate) fn forcer_hors_ligne() {
    HORS_LIGNE_FORCE.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// La variable d'environnement l'emporte sur le fichier.
fn priorite(variable: Option<String>, fichier: Option<String>) -> Option<String> {
    variable.or(fichier)
}

fn hors_ligne_voulu(variable: Option<&str>, fichier: bool) -> bool {
    match variable.map(|v| v.trim().to_lowercase()) {
        Some(v) => !matches!(v.as_str(), "0" | "non" | "no" | "off" | "false"),
        None => fichier,
    }
}

/// Les réglages de ce menu. Chacun garde sa place et son code ; ce menu ne fait que les montrer et les changer. Les
/// restrictions des extensions passent par leur propre interrupteur (`plugins::reglages::regler`) : le même accord,
/// le même avertissement, le même fichier que le menu Extensions, rien de copié.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reglage {
    Langue,
    Emojis,
    HorsLigne,
    TempsReel,
    Surveillance,
    Entretien,
    Appris,
    Blocage,
    Restrictions,
    CleAbuseCh,
    VersionsLogiciels,
    Autotest,
    PaquetsAur,
}

impl Reglage {
    const TOUS: [Reglage; 13] = [
        Reglage::Langue,
        Reglage::Emojis,
        Reglage::HorsLigne,
        Reglage::TempsReel,
        Reglage::Surveillance,
        Reglage::Entretien,
        Reglage::Appris,
        Reglage::Blocage,
        Reglage::Restrictions,
        Reglage::CleAbuseCh,
        Reglage::VersionsLogiciels,
        Reglage::Autotest,
        Reglage::PaquetsAur,
    ];

    /// Le mot de la ligne de commande.
    fn mot(self) -> &'static str {
        match self {
            Reglage::Langue => tr!("langue", "language"),
            Reglage::Emojis => "emojis",
            Reglage::HorsLigne => tr!("sans-internet", "offline"),
            Reglage::TempsReel => tr!("temps-reel", "real-time"),
            Reglage::Surveillance => tr!("surveillance", "monitoring"),
            Reglage::Entretien => tr!("entretien", "maintenance"),
            Reglage::Appris => tr!("appris", "learned"),
            Reglage::Blocage => tr!("blocage", "blocking"),
            Reglage::Restrictions => "restrictions",
            Reglage::CleAbuseCh => "abuse.ch",
            Reglage::VersionsLogiciels => tr!("versions-logiciels", "software-versions"),
            Reglage::Autotest => "autotest",
            Reglage::PaquetsAur => tr!("paquets-aur", "aur-packages"),
        }
    }

    fn depuis_mot(mot: &str) -> Option<Reglage> {
        match mot.trim().to_lowercase().as_str() {
            "langue" | "language" | "lang" => Some(Reglage::Langue),
            "emojis" | "emoji" => Some(Reglage::Emojis),
            "sans-internet" | "hors-ligne" | "horsligne" | "offline" | "internet" => Some(Reglage::HorsLigne),
            "temps-reel"
            | "temps-réel"
            | "tempsreel"
            | "temps_reel"
            | "temps-reel-vanguard"
            | "real-time"
            | "realtime"
            | "real_time" => Some(Reglage::TempsReel),
            "surveillance" | "monitoring" | "monitor" => Some(Reglage::Surveillance),
            "entretien" | "maintenance" => Some(Reglage::Entretien),
            "appris" | "learned" | "apprentissage" | "learning" => Some(Reglage::Appris),
            "blocage" | "blocking" => Some(Reglage::Blocage),
            "restrictions" | "restriction" => Some(Reglage::Restrictions),
            "abuse.ch" | "abuse-ch" | "abusech" | "cle-abuse.ch" | "cle-abuse-ch" | "clé-abuse.ch" | "abuse.ch-key" => {
                Some(Reglage::CleAbuseCh)
            }
            "versions-logiciels" | "software-versions" | "versions" | "perimes" | "périmés" | "outdated" => {
                Some(Reglage::VersionsLogiciels)
            }
            "autotest" | "self-test" | "autodiagnostic" | "selftest" => Some(Reglage::Autotest),
            "paquets-aur" | "aur-packages" | "aur" | "paquets_aur" => Some(Reglage::PaquetsAur),
            _ => None,
        }
    }

    fn titre(self) -> &'static str {
        match self {
            Reglage::Langue => tr!("Langue", "Language"),
            Reglage::Emojis => tr!("Emojis", "Emojis"),
            Reglage::HorsLigne => tr!("Travailler sans Internet", "Work without the Internet"),
            Reglage::TempsReel => tr!("Protection en temps réel", "Real-time protection"),
            Reglage::Surveillance => tr!("Surveillance horaire du réseau", "Hourly network monitoring"),
            Reglage::Entretien => tr!("Entretien du mois", "Monthly check-up"),
            Reglage::Appris => tr!("Alertes apprises", "Learned alerts"),
            Reglage::Blocage => tr!("Blocage des menaces", "Threat blocking"),
            Reglage::Restrictions => tr!("Restrictions des extensions", "Extension restrictions"),
            Reglage::CleAbuseCh => tr!("Clé abuse.ch", "abuse.ch key"),
            Reglage::VersionsLogiciels => tr!("Versions des logiciels", "Software versions"),
            Reglage::Autotest => tr!("Autodiagnostic de la semaine", "Weekly self-test"),
            Reglage::PaquetsAur => tr!("Paquets de l'AUR", "AUR packages"),
        }
    }

    /// La variable d'environnement qui l'emporte sur le fichier, pour un réglage du lancement.
    fn variable(self) -> Option<&'static str> {
        match self {
            Reglage::Langue => Some("VANGUARD_LANG"),
            Reglage::Emojis => Some("VANGUARD_EMOJI"),
            Reglage::HorsLigne => Some("VANGUARD_HORS_LIGNE"),
            _ => None,
        }
    }

    /// Les valeurs qu'il accepte, telles qu'on les tape dans la langue de l'interface (l'autre marche aussi) ; vide :
    /// il ouvre son propre écran.
    fn valeurs(self) -> &'static [&'static str] {
        let anglais = crate::langue::anglais();
        match self {
            Reglage::Langue => &["auto", "fr", "en"],
            Reglage::Emojis if anglais => &["auto", "yes", "no"],
            Reglage::Emojis => &["auto", "oui", "non"],
            Reglage::HorsLigne
            | Reglage::TempsReel
            | Reglage::Surveillance
            | Reglage::Entretien
            | Reglage::Restrictions
            | Reglage::VersionsLogiciels
            | Reglage::Autotest
            | Reglage::PaquetsAur
                if anglais =>
            {
                &["yes", "no"]
            }
            Reglage::HorsLigne
            | Reglage::TempsReel
            | Reglage::Surveillance
            | Reglage::Entretien
            | Reglage::Restrictions
            | Reglage::VersionsLogiciels
            | Reglage::Autotest
            | Reglage::PaquetsAur => &["oui", "non"],
            Reglage::Appris | Reglage::Blocage | Reglage::CleAbuseCh => &[],
        }
    }
}

/// Une valeur tapée pour la langue : `Ok(None)` = auto, `Ok(Some("fr"))`… ; `Err` : inconnue.
fn langue_de(mot: &str) -> Result<Option<String>, ()> {
    match mot.trim().to_lowercase().as_str() {
        "auto" | "systeme" | "système" | "system" => Ok(None),
        "fr" | "francais" | "français" | "french" => Ok(Some("fr".into())),
        "en" | "anglais" | "english" => Ok(Some("en".into())),
        _ => Err(()),
    }
}

/// Oui ou non, dans les deux langues ; `None` : inconnu.
fn oui_non(mot: &str) -> Option<bool> {
    match mot.trim().to_lowercase().as_str() {
        "oui" | "o" | "yes" | "y" | "on" | "1" | "true" | "active" | "activee" | "activée" | "activé" => Some(true),
        "non" | "n" | "no" | "off" | "0" | "false" | "desactive" | "désactivé" | "désactivée" | "desactivee" => {
            Some(false)
        }
        _ => None,
    }
}

/// Auto (`Ok(None)`), oui ou non ; `Err` : inconnu.
fn auto_oui_non(mot: &str) -> Result<Option<bool>, ()> {
    if mot.trim().eq_ignore_ascii_case("auto") {
        Ok(None)
    } else {
        oui_non(mot).map(Some).ok_or(())
    }
}

fn mot_oui_non(oui: bool) -> &'static str {
    if oui { tr!("oui", "yes") } else { tr!("non", "no") }
}

/// Un réglage du lancement changé dans le fichier : `Err` si la valeur est inconnue. Rend (avant, après), tels
/// qu'on les tape.
fn changer_dans(f: &mut Fichier, r: Reglage, valeur: &str) -> Result<(String, String), ()> {
    let auto = |v: Option<String>| v.unwrap_or_else(|| "auto".into());
    let oui_non_auto = |v: Option<bool>| v.map_or_else(|| "auto".to_string(), |o| mot_oui_non(o).to_string());
    match r {
        Reglage::Langue => {
            let nouvelle = langue_de(valeur)?;
            let avant = auto(f.langue.clone());
            f.langue = nouvelle;
            Ok((avant, auto(f.langue.clone())))
        }
        Reglage::Emojis => {
            let nouveau = auto_oui_non(valeur)?;
            let avant = oui_non_auto(f.emojis);
            f.emojis = nouveau;
            Ok((avant, oui_non_auto(f.emojis)))
        }
        Reglage::HorsLigne => {
            let nouveau = oui_non(valeur).ok_or(())?;
            let avant = mot_oui_non(f.hors_ligne).to_string();
            f.hors_ligne = nouveau;
            Ok((avant, mot_oui_non(f.hors_ligne).to_string()))
        }
        Reglage::VersionsLogiciels => {
            let nouveau = oui_non(valeur).ok_or(())?;
            let avant = mot_oui_non(!f.sans_versions).to_string();
            f.sans_versions = !nouveau;
            Ok((avant, mot_oui_non(!f.sans_versions).to_string()))
        }
        Reglage::Autotest => {
            let nouveau = oui_non(valeur).ok_or(())?;
            let avant = mot_oui_non(!f.sans_autotest).to_string();
            f.sans_autotest = !nouveau;
            Ok((avant, mot_oui_non(!f.sans_autotest).to_string()))
        }
        Reglage::PaquetsAur => {
            let nouveau = oui_non(valeur).ok_or(())?;
            let avant = mot_oui_non(f.paquets_aur).to_string();
            f.paquets_aur = nouveau;
            Ok((avant, mot_oui_non(f.paquets_aur).to_string()))
        }
        _ => Err(()),
    }
}

/// La valeur d'un réglage, telle qu'elle se montre.
fn valeur(r: Reglage) -> String {
    let fichier = charger_de(&fichier()).unwrap_or_default();
    let mut texte = match r {
        Reglage::Langue => match &fichier.langue {
            Some(l) => l.clone(),
            None => trf!(
                "auto ({})",
                "auto ({})",
                if crate::langue::anglais() { "en" } else { "fr" }
            ),
        },
        Reglage::Emojis => fichier
            .emojis
            .map_or_else(|| tr!("auto", "auto").to_string(), |e| mot_oui_non(e).to_string()),
        Reglage::HorsLigne => mot_oui_non(fichier.hors_ligne).to_string(),
        Reglage::VersionsLogiciels => mot_oui_non(!fichier.sans_versions).to_string(),
        Reglage::Autotest => mot_oui_non(!fichier.sans_autotest).to_string(),
        Reglage::PaquetsAur => mot_oui_non(fichier.paquets_aur).to_string(),
        Reglage::TempsReel => crate::protection::temps_reel::valeur(),
        Reglage::Surveillance => mot_oui_non(crate::reseau::surveillance::active()).to_string(),
        Reglage::Entretien => mot_oui_non(crate::entretien::active()).to_string(),
        Reglage::Appris => match crate::apprentissage::nombre() {
            Some(n) => trf!("{n} alerte(s) normale(s)", "{n} normal alert(s)"),
            None => tr!("liste illisible", "list unreadable").to_string(),
        },
        Reglage::Blocage => crate::protection::blocage::etat_court().to_string(),
        Reglage::Restrictions => {
            texte_restrictions(&restrictions_actives(crate::plugins::reglages_lisibles().as_deref()))
        }
        // Masquée : seuls ses quatre derniers caractères, jamais la clé entière.
        Reglage::CleAbuseCh => crate::protection::abuse_ch::etat_court(),
    };
    if let Some(v) = r.variable().filter(|v| std::env::var_os(v).is_some()) {
        texte += &trf!(" ({v} l'emporte)", " ({v} wins)");
    }
    texte
}

/// Les restrictions des extensions, lues de leur interrupteur : actives ? Sans dossier à lire (administrateur), oui :
/// l'interrupteur n'y vaut rien. `Err` (la raison) : son fichier ne se lit plus, et elles restent actives.
fn restrictions_actives(racine: Option<&Path>) -> Result<bool, String> {
    racine.map_or(Ok(true), |r| {
        crate::plugins::reglages::lire(r).map(|g| !g.sans_restrictions)
    })
}

/// Leur valeur montrée : oui (actives), ou non et ce que cela veut dire. Un fichier illisible est dit : il ne vaut
/// pas un « oui » tranquille (ses confiances « à moi » ne servent plus, et le prochain changement le met de côté).
fn texte_restrictions(actives: &Result<bool, String>) -> String {
    match actives {
        Ok(true) => mot_oui_non(true).to_string(),
        Ok(false) => trf!("{} (sans contrôle)", "{} (no checks)", mot_oui_non(false)),
        Err(_) => trf!(
            "{} (réglages illisibles)",
            "{} (settings unreadable)",
            mot_oui_non(true)
        ),
    }
}

/// Les restrictions mises à `actives` par leur interrupteur (`plugins::reglages::regler` : l'accord demandé une seule
/// fois, comme au menu Extensions) ; refusé, rien ne change. Rend (avant, après) : actives ?
fn restrictions_dans(racine: &Path, actives: bool, accord: impl FnOnce(&str) -> bool) -> Result<(bool, bool), String> {
    let (avant, apres) = crate::plugins::reglages::regler(racine, !actives, accord)?;
    Ok((!avant, !apres))
}

/// `vanguard parametres` : l'état ; avec un réglage et une valeur, le change ; « appris » et « blocage » ouvrent leur
/// outil (« blocage » prend aussi ses propres mots : `vanguard parametres blocage connexions auto`) ; « abuse.ch »
/// demande la clé, ou la retire (« retirer »), mais ne la prend jamais en argument ; « temps-reel non » prend aussi
/// « --pendant 1h|4h ».
pub fn commande(mots: &[String]) {
    let Some((premier, reste)) = mots.split_first() else {
        afficher();
        return;
    };
    let Some(r) = Reglage::depuis_mot(premier) else {
        trp!(
            "  ✖ Réglage inconnu : « {} ». Réglages : {}.",
            "  ✖ Unknown setting: “{}”. Settings: {}.",
            affichable(premier),
            Reglage::TOUS.map(Reglage::mot).join(", ")
        );
        return;
    };
    match (r, reste) {
        (Reglage::Appris, _) => crate::apprentissage::menu(),
        (Reglage::Blocage, _) => crate::protection::blocage::commande(reste),
        (Reglage::CleAbuseCh, []) => crate::protection::abuse_ch::menu(),
        (Reglage::CleAbuseCh, [mot]) if est_retirer(mot) => crate::protection::abuse_ch::retirer(),
        // L'historique du terminal et la liste des processus garderaient une clé donnée en argument.
        (Reglage::CleAbuseCh, _) => trp!(
            "  ✖ La clé ne se donne pas sur la ligne de commande : l'historique du terminal la garderait. « vanguard parametres abuse.ch » la demande ; « vanguard parametres abuse.ch retirer » la retire.",
            "  ✖ The key is not given on the command line: the terminal history would keep it. “vanguard settings abuse.ch” asks for it; “vanguard settings abuse.ch remove” removes it."
        ),
        (Reglage::TempsReel, [valeur, options @ ..]) => {
            changer_temps_reel(valeur, options);
        }
        (_, [valeur]) => {
            changer(r, valeur);
        }
        _ => trp!(
            "  {} : {}. Valeurs : {}.",
            "  {}: {}. Values: {}.",
            r.mot(),
            valeur(r),
            valeurs_dites(r)
        ),
    }
}

/// Les valeurs, telles que l'aide les dit : la protection en temps réel coupée prend aussi sa durée.
fn valeurs_dites(r: Reglage) -> String {
    let valeurs = r.valeurs().join(", ");
    if r == Reglage::TempsReel {
        trf!(
            "{valeurs} [--pendant 1h|4h] (sans --pendant : jusqu'à ce que vous la remettiez)",
            "{valeurs} [--for 1h|4h] (without --for: until you turn it back on)"
        )
    } else {
        valeurs
    }
}

/// « --pendant 1h », « --pendant=4h » (et « --for », « --duree ») : `Ok(None)` sans option, `Err` sinon.
fn duree_saisie(options: &[String]) -> Result<Option<crate::protection::temps_reel::Duree>, ()> {
    use crate::protection::temps_reel::Duree;
    let est_option = |o: &str| matches!(o, "--pendant" | "--for" | "--duree" | "--durée" | "--duration");
    let valeur = match options {
        [] => return Ok(None),
        [o, v] if est_option(o) => v.as_str(),
        [o] => match o.split_once('=') {
            Some((o, v)) if est_option(o) => v,
            _ => return Err(()),
        },
        _ => return Err(()),
    };
    Duree::depuis_mot(valeur).map(Some).ok_or(())
}

/// `vanguard parametres temps-reel oui|non [--pendant 1h|4h]`. `false` : rien changé.
fn changer_temps_reel(saisie: &str, options: &[String]) -> bool {
    use crate::protection::temps_reel::Duree;
    let r = Reglage::TempsReel;
    let (Some(en_marche), Ok(duree)) = (oui_non(saisie), duree_saisie(options)) else {
        trp!(
            "  ✖ Valeur inconnue pour {} : « {} ». Valeurs : {}.",
            "  ✖ Unknown value for {}: “{}”. Values: {}.",
            r.mot(),
            affichable(
                &std::iter::once(saisie)
                    .chain(options.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            valeurs_dites(r)
        );
        return false;
    };
    match (en_marche, duree) {
        (true, None) => regler_temps_reel(None),
        (true, Some(_)) => {
            trp!(
                "  ✖ --pendant va avec « non » : la protection remise l'est jusqu'à la prochaine coupure.",
                "  ✖ --for goes with “no”: protection turned back on stays on until the next pause."
            );
            false
        }
        (false, d) => regler_temps_reel(Some(d.unwrap_or(Duree::JusquaReprise))),
    }
}

/// Coupe (`Some(durée)`, après la liste de ce qui s'arrête et un accord) ou remet (`None`, sans rien demander) la
/// protection en temps réel. `false` : rien changé.
fn regler_temps_reel(voulu: Option<crate::protection::temps_reel::Duree>) -> bool {
    use crate::protection::temps_reel;
    let r = Reglage::TempsReel;
    let mut accepte = false;
    let fait = temps_reel::regler(voulu, |d| {
        println!();
        afficher_aligne(
            "  ",
            &trf!(
                "Couper la protection en temps réel {} arrête :",
                "Turning real-time protection off {} stops:",
                d.libelle()
            ),
            2,
            GRAS,
        );
        let lignes = temps_reel::ce_qui_s_arrete(
            crate::reseau::surveillance::active(),
            crate::protection::blocage::protection_active(),
        );
        for l in &lignes {
            afficher_aligne("  ", l, 4, "");
        }
        accepte = demander(&trf!(
            "\n  Couper la protection en temps réel {} ? [o/N] : ",
            "\n  Turn real-time protection off {}? [y/N]: ",
            d.libelle()
        ))
        .oui();
        accepte
    });
    let (avant, apres) = match fait {
        Err(e) => {
            afficher_aligne(
                &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                &e,
                4,
                "",
            );
            return false;
        }
        Ok(_) if voulu.is_some() && !accepte => {
            trp!("  Rien n'a changé.", "  Nothing changed.");
            return false;
        }
        Ok(etats) => etats,
    };
    trp!(
        "  {VERT}✔{RESET} {} : {} → {}",
        "  {VERT}✔{RESET} {}: {} → {}",
        r.titre(),
        temps_reel::montrer(&avant),
        temps_reel::montrer(&apres)
    );
    match apres.coupure() {
        Some(c) => {
            if let Some(h) = temps_reel::heure_de_reprise(&c) {
                trp!(
                    "  {GRIS}Elle reprend toute seule à {h}, chacun comme il était réglé.{RESET}",
                    "  {GRIS}It comes back by itself at {h}, each part as it was set.{RESET}"
                );
            }
            trp!(
                "  {GRIS}Pour la remettre tout de suite : vanguard parametres {} {}{RESET}",
                "  {GRIS}To turn it back on right now: vanguard settings {} {}{RESET}",
                r.mot(),
                mot_oui_non(true)
            );
        }
        None if avant.coupure().is_some() => trp!(
            "  {GRIS}Pour la couper de nouveau : vanguard parametres {} {} [--pendant 1h|4h]{RESET}",
            "  {GRIS}To turn it off again: vanguard settings {} {} [--for 1h|4h]{RESET}",
            r.mot(),
            mot_oui_non(false)
        ),
        None => {}
    }
    true
}

/// « retirer », dans les deux langues.
fn est_retirer(mot: &str) -> bool {
    matches!(
        mot.trim().to_lowercase().as_str(),
        "retirer" | "oublier" | "supprimer" | "aucune" | "remove" | "delete" | "forget" | "none"
    )
}

/// Change un réglage : la valeur d'avant et la nouvelle sont montrées, avec de quoi revenir. `false` : rien changé.
fn changer(r: Reglage, saisie: &str) -> bool {
    let inconnue = || {
        trp!(
            "  ✖ Valeur inconnue pour {} : « {} ». Valeurs : {}.",
            "  ✖ Unknown value for {}: “{}”. Values: {}.",
            r.mot(),
            affichable(saisie),
            r.valeurs().join(", ")
        );
        false
    };
    let (avant, apres) = match r {
        Reglage::Langue
        | Reglage::Emojis
        | Reglage::HorsLigne
        | Reglage::VersionsLogiciels
        | Reglage::Autotest
        | Reglage::PaquetsAur => {
            let chemin = fichier();
            let lu = charger_de(&chemin);
            let mut f = lu.clone().unwrap_or_default();
            let Ok((avant, apres)) = changer_dans(&mut f, r, saisie) else {
                return inconnue();
            };
            if lu.is_err() {
                // Jamais écraser en silence un fichier qu'on ne sait plus lire : il est gardé à côté.
                let copie = chemin.with_extension(format!(
                    "illisible-{}.json",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ));
                // Seulement un simple fichier, borné : un tube ou un lien vers /dev/zero à sa place ne se recopie pas.
                if let Ok(o) = crate::socle::lire_ordinaire(&chemin, TAILLE_MAX)
                    && chemin.parent().is_some_and(crate::socle::ecriture_sure)
                {
                    let _ = crate::socle::ecrire_atomique(&copie, o);
                }
            }
            if let Err(e) = enregistrer_dans(&f, &chemin) {
                trp!("  ✖ Non enregistré ({e}).", "  ✖ Not saved ({e}).");
                return false;
            }
            (avant, apres)
        }
        Reglage::Surveillance | Reglage::Entretien => {
            let Some(voulu) = oui_non(saisie) else {
                return inconnue();
            };
            let actif = if r == Reglage::Surveillance {
                crate::reseau::surveillance::active()
            } else {
                crate::entretien::active()
            };
            if actif != voulu {
                if r == Reglage::Surveillance {
                    crate::reseau::surveillance::activer(voulu);
                } else {
                    crate::entretien::activer(voulu);
                }
            }
            (mot_oui_non(actif).to_string(), mot_oui_non(voulu).to_string())
        }
        Reglage::Restrictions => {
            let Some(actives) = oui_non(saisie) else {
                return inconnue();
            };
            let fait = crate::plugins::dossier_des_reglages()
                .and_then(|racine| restrictions_dans(&racine, actives, |q| demander(q).oui()));
            match fait {
                Err(e) => {
                    afficher_aligne(
                        &format!("  {}✖{RESET} ", couleur(crate::risk::Niveau::Eleve)),
                        &e,
                        4,
                        "",
                    );
                    return false;
                }
                Ok((_, apres)) if apres != actives => {
                    trp!("  Rien n'a changé.", "  Nothing changed.");
                    return false;
                }
                Ok((avant, apres)) => (mot_oui_non(avant).to_string(), mot_oui_non(apres).to_string()),
            }
        }
        Reglage::TempsReel => return changer_temps_reel(saisie, &[]),
        Reglage::Appris | Reglage::Blocage | Reglage::CleAbuseCh => return false,
    };
    trp!(
        "  {VERT}✔{RESET} {} : {avant} → {apres}",
        "  {VERT}✔{RESET} {}: {avant} → {apres}",
        r.titre()
    );
    if r == Reglage::Restrictions && apres == mot_oui_non(false) {
        // Le même avertissement qu'au menu Extensions, et ce qui reste même coupées.
        crate::plugins::dire_restrictions(true);
        afficher_aligne("  ", crate::plugins::reglages::ce_qui_reste(), 2, GRIS);
    }
    if r.variable().is_some() {
        trp!(
            "  {GRIS}Effectif au prochain lancement de Vanguard.{RESET}",
            "  {GRIS}Effective the next time Vanguard starts.{RESET}"
        );
    }
    if let Some(v) = r.variable().filter(|v| std::env::var_os(v).is_some()) {
        trp!(
            "  {GRIS}{v} est posée : elle l'emporte sur ce réglage tant qu'elle l'est.{RESET}",
            "  {GRIS}{v} is set: it wins over this setting as long as it is.{RESET}"
        );
    }
    if avant != apres {
        trp!(
            "  {GRIS}Pour revenir en arrière : vanguard parametres {} {avant}{RESET}",
            "  {GRIS}To go back: vanguard settings {} {avant}{RESET}",
            r.mot()
        );
    }
    true
}

/// L'état de tous les réglages.
fn afficher() {
    titre(tr!("Paramètres", "Settings"));
    match charger_juge(&fichier()) {
        Err(e) => trp!(
            "  {}⚠{RESET} parametres.json illisible ({e}) : les valeurs par défaut servent.",
            "  {}⚠{RESET} parametres.json unreadable ({e}): the defaults are used.",
            couleur(crate::risk::Niveau::Moyen)
        ),
        Ok((_, Some(douteux))) => afficher_aligne(
            &format!("  {}⚠{RESET} ", couleur(crate::risk::Niveau::Eleve)),
            &trf!(
                "parametres.json {} : le travail sans Internet, l'autodiagnostic et les versions des logiciels qu'il coupait restent en marche. Réglez-les de nouveau ici s'ils sont bien de vous.",
                "parametres.json {}: offline work, the self-test and software versions it turned off stay on. Set them again here if they really are yours.",
                douteux.texte()
            ),
            4,
            "",
        ),
        Ok(_) => {}
    }
    for r in Reglage::TOUS {
        afficher_aligne(&format!("  {GRAS}{:<16}{RESET} ", r.mot()), &valeur(r), 19, "");
    }
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Changer : vanguard parametres <réglage> <valeur> (sans valeur : celles qu'il accepte). Pour annuler, remettre la valeur d'avant. Une variable d'environnement (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) l'emporte sur ces réglages.",
            "Change: vanguard settings <setting> <value> (no value: the ones it accepts). To undo, put the previous value back. An environment variable (VANGUARD_LANG, VANGUARD_EMOJI, VANGUARD_HORS_LIGNE) wins over these settings."
        ),
        2,
        GRIS,
    );
}

/// Ce que fait un réglage, en une phrase, sous son choix de valeur.
fn explication(r: Reglage) -> &'static str {
    match r {
        Reglage::Langue => tr!(
            "La langue de l'interface ; auto : celle du système.",
            "The interface language; auto: the system's."
        ),
        Reglage::Emojis => tr!(
            "L'ampoule et la clé à molette devant les conseils ; auto : sauf dans l'ancienne console de Windows, qui les dessine mal.",
            "The light bulb and the wrench in front of tips; auto: except in the old Windows console, which draws them badly."
        ),
        Reglage::HorsLigne => tr!(
            "Ce que Vanguard demande à Internet de lui-même est sauté : adresse vue d'Internet, DNS de l'audit, nouvelle version, empreintes de MalwareBazaar, versions des logiciels.",
            "What Vanguard asks the Internet by itself is skipped: address seen from the Internet, the audit's DNS, new version, MalwareBazaar fingerprints, software versions."
        ),
        Reglage::VersionsLogiciels => tr!(
            "Oui : Vanguard télécharge une fois par jour, en entier, les fichiers publics des dernières versions (sites des éditeurs, endoflife.date, Homebrew, avis de Mozilla) et le catalogue des failles exploitées de la CISA, les mêmes pour tous : la liste de vos logiciels ne sort jamais. Non : rien n'est téléchargé ; les copies déjà gardées servent encore 30 jours au plus (3 jours pour dire « à jour »), puis les logiciels pas à jour ne sont plus vérifiés, ce qui est dit.",
            "Yes: once a day, Vanguard downloads the public files of the latest versions in full (publishers' sites, endoflife.date, Homebrew, Mozilla advisories) and CISA's exploited flaws catalog, the same for everyone: the list of your software never leaves. No: nothing is downloaded; the copies already kept still serve for 30 days at most (3 days to say “up to date”), then outdated software is no longer checked, which is said."
        ),
        Reglage::Autotest => tr!(
            "Oui : une fois par semaine, avec la surveillance, Vanguard compare ses propres lectures (logiciels installés, services, ports, comptes, pare-feu) à ce qu'en disent les outils du système, et note ce qui ralentit. Rien n'est changé, rien n'est envoyé, aucune notification ; reporté pendant un jeu. « vanguard autotest » le fait à la main.",
            "Yes: once a week, with the monitoring, Vanguard compares its own readings (installed software, services, ports, accounts, firewall) with what the system's tools say, and notes what slows down. Nothing is changed, nothing is sent, no notification; postponed during a game. “vanguard autotest” does it by hand."
        ),
        Reglage::PaquetsAur => tr!(
            "Arch Linux : oui, le bilan envoie à aur.archlinux.org le nom des paquets installés hors des dépôts officiels, pour dire ceux qui ne sont plus mis à jour (règle LNX-MAJ-006). Non : rien n'est envoyé, et ces paquets ne sont pas vérifiés, ce qui est dit.",
            "Arch Linux: yes, the check sends aur.archlinux.org the names of the packages installed outside the official repositories, to tell which ones no longer get updates (rule LNX-MAJ-006). No: nothing is sent, and these packages are not checked, which is said."
        ),
        Reglage::TempsReel => tr!(
            "Coupe d'un coup ce que Vanguard fait tout seul en continu : la surveillance horaire et la protection active du blocage, pendant 1 heure, 4 heures ou jusqu'à ce que vous la remettiez. Les réglages de chacun ne changent pas : à la reprise, chacun retrouve son état d'avant. Jamais Defender, le pare-feu ni l'UAC.",
            "Turns off at once what Vanguard does by itself all the time: the hourly monitoring and the active protection of blocking, for 1 hour, 4 hours or until you turn it back on. Each part's settings do not change: when it comes back, each one is as it was. Never Defender, the firewall or UAC."
        ),
        Reglage::Surveillance => tr!(
            "Un scan du réseau toutes les heures, notification si un appareil inconnu arrive.",
            "A network scan every hour, notification if an unknown device shows up."
        ),
        Reglage::Entretien => tr!(
            "Une notification par mois : note, mises à jour, place, problèmes nouveaux.",
            "One notification a month: grade, updates, space, new problems."
        ),
        Reglage::Restrictions => tr!(
            "Oui : une extension demande votre accord, son empreinte est vérifiée, elle est analysée et bornée, jamais en administrateur. Non : elle tourne comme un de vos programmes, sans contrôle ; couper demande votre accord une fois.",
            "Yes: an extension asks for your consent, its fingerprint is checked, it is scanned and limited, never as administrator. No: it runs like one of your programs, without checks; turning them off asks for your consent once."
        ),
        Reglage::Appris | Reglage::Blocage | Reglage::CleAbuseCh => "",
    }
}

/// Le menu Paramètres : chaque réglage et sa valeur ; choisi, ses valeurs (ou son outil).
/// Les réglages, pour la recherche du menu principal : chacun ouvre Paramètres (`cle`, « 13.1 »).
pub fn lignes_de_recherche(cle: &str) -> Vec<crate::selection::Ligne> {
    let chemin = format!("Vanguard › {} ›", tr!("Paramètres", "Settings"));
    Reglage::TOUS
        .into_iter()
        .map(|r| crate::selection::Ligne::cachee(cle, &chemin, r.titre(), "").avec_mots(r.mot()))
        .collect()
}

pub fn menu() {
    let mut dernier = String::from("1");
    loop {
        let mut lignes = vec![
            Ligne::Texte(String::new()),
            Ligne::Texte(ligne_titre(tr!("Paramètres", "Settings"))),
            Ligne::Texte(String::new()),
        ];
        for (i, r) in Reglage::TOUS.iter().enumerate() {
            lignes.push(Ligne::choix(&(i + 1).to_string(), r.titre(), &couper(&valeur(*r), 33)));
        }
        lignes.push(Ligne::Texte(String::new()));
        lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
        let Some(choix) = choisir(
            &lignes,
            tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
            &dernier,
            tr!("revenir", "back"),
        ) else {
            return;
        };
        let choix = choix.trim().to_string();
        let Some(&r) = choix
            .parse::<usize>()
            .ok()
            .and_then(|i| Reglage::TOUS.get(i.checked_sub(1)?))
        else {
            return;
        };
        dernier = choix;
        match r {
            Reglage::Appris => crate::apprentissage::menu(),
            Reglage::Blocage => crate::protection::blocage::menu(),
            Reglage::CleAbuseCh => crate::protection::abuse_ch::menu(),
            Reglage::TempsReel => choisir_temps_reel(),
            _ => choisir_valeur(r),
        }
    }
}

/// Le choix de la protection en temps réel : en marche, ou coupée pour une des trois durées ; la valeur actuelle
/// marquée.
fn choisir_temps_reel() {
    use crate::protection::temps_reel::{self as temps_reel, Duree};
    let r = Reglage::TempsReel;
    let coupure = temps_reel::coupure();
    let mut lignes = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(r.titre()))];
    // Ce qui ne change jamais est dit en entier avec la question, juste après le choix d'une durée.
    lignes.extend(
        envelopper(explication(r), LARGEUR - 4)
            .into_iter()
            .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
    );
    lignes.push(Ligne::Texte(String::new()));
    let en_ce_moment = tr!("← en ce moment", "← now");
    lignes.push(Ligne::choix(
        "1",
        &trf!("{}, en marche", "{}, on", mot_oui_non(true)),
        if coupure.is_none() { en_ce_moment } else { "" },
    ));
    for (i, d) in Duree::TOUTES.iter().enumerate() {
        let precision = coupure
            .filter(|c| c.duree() == *d)
            .map(|c| format!("← {}", temps_reel::echeance(&c)))
            .unwrap_or_default();
        lignes.push(Ligne::choix(
            &(i + 2).to_string(),
            &format!("{}, {}", mot_oui_non(false), d.libelle()),
            &couper(&precision, 33),
        ));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let Some(choix) = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    ) else {
        return;
    };
    match choix.trim().parse::<usize>() {
        Ok(1) => {
            regler_temps_reel(None);
        }
        Ok(n) => {
            if let Some(&d) = n.checked_sub(2).and_then(|i| Duree::TOUTES.get(i)) {
                regler_temps_reel(Some(d));
            }
        }
        Err(_) => {}
    }
}

/// Le choix d'une valeur, la valeur actuelle marquée.
fn choisir_valeur(r: Reglage) {
    let actuelle = valeur(r);
    let mut lignes = vec![Ligne::Texte(String::new()), Ligne::Texte(ligne_titre(r.titre()))];
    lignes.extend(
        envelopper(explication(r), LARGEUR - 4)
            .into_iter()
            .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
    );
    if r == Reglage::Restrictions {
        lignes.extend(
            envelopper(crate::plugins::reglages::ce_qui_reste(), LARGEUR - 4)
                .into_iter()
                .map(|l| Ligne::Texte(format!("  {GRIS}{l}{RESET}"))),
        );
    }
    lignes.push(Ligne::Texte(String::new()));
    for (i, v) in r.valeurs().iter().enumerate() {
        let en_cours = actuelle == *v || actuelle.starts_with(&format!("{v} ("));
        let precision = if en_cours {
            tr!("← en ce moment", "← now")
        } else {
            ""
        };
        lignes.push(Ligne::choix(&(i + 1).to_string(), v, precision));
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    let Some(choix) = choisir(
        &lignes,
        tr!("\n  Choix (Entrée pour revenir) : ", "\n  Choice (Enter to go back): "),
        "1",
        tr!("revenir", "back"),
    ) else {
        return;
    };
    if let Some(v) = choix
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|i| r.valeurs().get(i.checked_sub(1)?))
    {
        changer(r, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-parametres-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("parametres.json")
    }

    #[test]
    fn fichier_ecrit_relu_ou_refuse() {
        let f = jetable("fichier");
        // Absent : les défauts, rien d'écrit.
        assert_eq!(charger_de(&f).unwrap(), Fichier::default());
        let voulu = Fichier {
            langue: Some("en".into()),
            emojis: Some(false),
            hors_ligne: true,
            sans_versions: true,
            sans_autotest: true,
            paquets_aur: true,
        };
        enregistrer_dans(&voulu, &f).unwrap();
        assert_eq!(charger_de(&f).unwrap(), voulu);
        // Les défauts ne s'écrivent pas : un fichier vide d'un réglage le laisse à « auto ».
        enregistrer_dans(&Fichier::default(), &f).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap().trim(), "{}");
        // Abîmé ou démesuré : refusé.
        std::fs::write(&f, "{pas du json").unwrap();
        assert!(charger_de(&f).is_err());
        std::fs::write(&f, " ".repeat(usize::try_from(TAILLE_MAX).unwrap() + 1)).unwrap();
        assert!(charger_de(&f).is_err());
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// Un programme du compte écrit `{"hors_ligne":true}` (ou coupe l'autodiagnostic) dans parametres.json : le
    /// fichier n'est plus scellé, ces réglages valent leur défaut (en marche), la langue reste, et la raison est
    /// rendue pour être dite. Réglés de nouveau par Vanguard, ils valent.
    #[test]
    fn reglages_qui_coupent_une_defense_changes_hors_de_vanguard_ignores() {
        let f = jetable("forge");
        // Posé sans sceau à côté de sceaux existants : falsifié.
        crate::sceau::ecrire_dans(f.parent().unwrap(), crate::sceau::APPRIS, b"{}").unwrap();
        std::fs::write(
            &f,
            r#"{"langue":"en","hors_ligne":true,"sans_autotest":true,"sans_versions":true}"#,
        )
        .unwrap();
        let (lu, raison) = charger_juge(&f).unwrap();
        assert_eq!(raison, Some(Douteux::HorsVanguard));
        assert!(!lu.hors_ligne && !lu.sans_autotest && !lu.sans_versions, "{lu:?}");
        assert_eq!(lu.langue.as_deref(), Some("en"));
        // La personne le règle elle-même : écrit et scellé par Vanguard, il vaut.
        let voulu = Fichier { hors_ligne: true, ..lu };
        enregistrer_dans(&voulu, &f).unwrap();
        assert_eq!(charger_juge(&f).unwrap(), (voulu, None));
        // Le message de mise à jour dit que c'est un réglage, jamais « pas d'Internet ».
        let r = raison_hors_ligne();
        assert!(!r.contains("pas d'Internet") && !r.contains("no Internet"), "{r}");
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// Un programme du compte écrit `{"paquets_aur":true}` : l'accord n'est pas donné, la raison est rendue ; donné
    /// par Vanguard lui-même, il vaut.
    #[test]
    fn accord_aur_ecrit_hors_de_vanguard_ignore() {
        let f = jetable("accord-aur");
        crate::sceau::ecrire_dans(f.parent().unwrap(), crate::sceau::APPRIS, b"{}").unwrap();
        std::fs::write(&f, r#"{"paquets_aur":true}"#).unwrap();
        let (lu, raison) = charger_juge(&f).unwrap();
        assert_eq!(raison, Some(Douteux::HorsVanguard));
        assert!(!lu.paquets_aur, "{lu:?}");
        let voulu = Fichier {
            paquets_aur: true,
            ..lu
        };
        enregistrer_dans(&voulu, &f).unwrap();
        assert_eq!(charger_juge(&f).unwrap(), (voulu, None));
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// Repris d'une version d'avant le sceau à la mise à jour, parametres.json vaut tel quel (le choix de la
    /// personne) ; accepté tel quel après des sceaux effacés (leur verrou resté), il ne coupe rien.
    #[test]
    fn mise_a_jour_gardee_sceaux_refaits_ignores() {
        let f = jetable("adopte");
        std::fs::write(&f, r#"{"hors_ligne":true}"#).unwrap();
        let (lu, raison) = charger_juge(&f).unwrap();
        assert!(lu.hors_ligne && raison.is_none(), "{lu:?} {raison:?}");
        let d = f.parent().unwrap();
        crate::sceau::ecrire_dans(d, crate::sceau::APPRIS, b"{}").unwrap();
        enregistrer_dans(&lu, &f).unwrap();
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        let (lu, raison) = charger_juge(&f).unwrap();
        assert_eq!(raison, Some(Douteux::Adopte));
        assert!(!lu.hors_ligne);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Un tube nommé ou un lien vers /dev/zero à la place de parametres.json : refusé tout de suite, jamais une
    /// lecture qui fige le lancement ni qui charge sans fin.
    #[cfg(unix)]
    #[test]
    fn parametres_tube_ou_lien_ne_fige_rien() {
        let f = jetable("tube");
        let c = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY : mkfifo reçoit un chemin terminé par zéro, qui vit le temps de l'appel.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let debut = std::time::Instant::now();
        assert!(charger_de(&f).is_err());
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink("/dev/zero", &f).unwrap();
        assert!(charger_de(&f).is_err());
        assert!(debut.elapsed() < std::time::Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// La variable d'environnement l'emporte toujours sur le fichier.
    #[test]
    fn la_variable_l_emporte() {
        assert_eq!(priorite(Some("en".into()), Some("fr".into())).as_deref(), Some("en"));
        assert_eq!(priorite(None, Some("fr".into())).as_deref(), Some("fr"));
        assert_eq!(priorite(None, None), None);
        assert!(hors_ligne_voulu(Some("1"), false));
        assert!(hors_ligne_voulu(Some(""), false), "posée, même vide : comme avant");
        assert!(
            !hors_ligne_voulu(Some("0"), true),
            "la variable dit non : elle l'emporte"
        );
        assert!(!hors_ligne_voulu(Some("non"), true));
        assert!(hors_ligne_voulu(None, true));
        assert!(!hors_ligne_voulu(None, false));
    }

    /// Une valeur inconnue est refusée, et rien ne change ; une connue rend la valeur d'avant, pour revenir.
    #[test]
    fn valeurs_connues_ou_refusees() {
        let mut f = Fichier::default();
        assert_eq!(
            changer_dans(&mut f, Reglage::Langue, "en"),
            Ok(("auto".to_string(), "en".to_string()))
        );
        assert_eq!(f.langue.as_deref(), Some("en"));
        assert_eq!(changer_dans(&mut f, Reglage::Langue, "klingon"), Err(()));
        assert_eq!(f.langue.as_deref(), Some("en"));
        assert_eq!(
            changer_dans(&mut f, Reglage::Langue, "auto"),
            Ok(("en".to_string(), "auto".to_string()))
        );
        assert_eq!(f.langue, None);
        assert!(changer_dans(&mut f, Reglage::Emojis, "non").is_ok());
        assert_eq!(f.emojis, Some(false));
        assert_eq!(changer_dans(&mut f, Reglage::Emojis, "parfois"), Err(()));
        assert!(changer_dans(&mut f, Reglage::HorsLigne, "oui").is_ok());
        assert!(f.hors_ligne);
        assert_eq!(changer_dans(&mut f, Reglage::HorsLigne, "auto"), Err(()));
        // Les versions des logiciels : oui par défaut, la valeur d'avant rendue pour revenir.
        assert!(!f.sans_versions);
        assert_eq!(
            changer_dans(&mut f, Reglage::VersionsLogiciels, "non"),
            Ok((mot_oui_non(true).to_string(), mot_oui_non(false).to_string()))
        );
        assert!(f.sans_versions);
        assert_eq!(changer_dans(&mut f, Reglage::VersionsLogiciels, "auto"), Err(()));
        assert!(f.sans_versions);
        assert!(changer_dans(&mut f, Reglage::VersionsLogiciels, "yes").is_ok());
        assert!(!f.sans_versions);
        // Les réglages qui ont leur propre place ne passent pas par le fichier.
        assert_eq!(changer_dans(&mut f, Reglage::Surveillance, "oui"), Err(()));
        assert_eq!(oui_non("Activée"), Some(true));
        assert_eq!(oui_non("off"), Some(false));
        assert_eq!(oui_non("peut-être"), None);
    }

    /// Les restrictions des extensions : lues de leur interrupteur et changées par lui seul, dans le même fichier que
    /// le menu Extensions ; couper passe par son accord (refusé : rien ne change), remettre ne demande rien.
    #[test]
    fn restrictions_par_leur_interrupteur() {
        use crate::plugins::reglages;
        let d = jetable("restrictions").with_file_name("plugins");
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(
            restrictions_actives(None),
            Ok(true),
            "sans dossier à lire (administrateur) : actives"
        );
        assert_eq!(restrictions_actives(Some(&d)), Ok(true), "sans fichier : actives");
        assert_eq!(texte_restrictions(&Ok(true)), mot_oui_non(true));
        // Coupées, la valeur montrée garde le mot tapé devant : le choix au menu reste marqué.
        assert!(texte_restrictions(&Ok(false)).starts_with(&format!("{} (", mot_oui_non(false))));
        // Refusé : rien ne change, rien n'est écrit.
        assert_eq!(restrictions_dans(&d, false, |_| false), Ok((true, true)));
        assert_eq!(reglages::charger(&d), reglages::Reglages::default());
        assert_eq!(restrictions_actives(Some(&d)), Ok(true));
        // Accepté : la question est celle de l'interrupteur, et sa réponse est gardée dans son fichier.
        let mut question = String::new();
        let fait = restrictions_dans(&d, false, |q| {
            question = q.to_string();
            true
        });
        assert_eq!(fait, Ok((true, false)));
        assert!(question.contains("/N]"), "{question}");
        assert_eq!(restrictions_actives(Some(&d)), Ok(false));
        assert!(reglages::charger(&d).sans_restrictions && reglages::charger(&d).coupure_confirmee);
        // Déjà coupées : rien n'est demandé ni changé.
        assert_eq!(
            restrictions_dans(&d, false, |_| panic!("rien à demander")),
            Ok((false, false))
        );
        // Remettre ne demande rien ; le menu Extensions voit la même chose, et sa bascule est lue ici.
        assert_eq!(
            restrictions_dans(&d, true, |_| panic!("remettre ne demande rien")),
            Ok((false, true))
        );
        assert!(!reglages::charger(&d).sans_restrictions);
        assert!(reglages::basculer(&d, |_| panic!("déjà confirmé une fois")).unwrap());
        assert_eq!(restrictions_actives(Some(&d)), Ok(false));
        assert_eq!(restrictions_dans(&d, true, |_| panic!("remettre")), Ok((false, true)));
        assert_eq!(restrictions_actives(Some(&d)), Ok(true));
        // Un fichier qui ne se lit plus : actives, et c'est dit ; le mot tapé reste devant, marqué au menu.
        std::fs::write(d.join("reglages.json"), "{pas du json").unwrap();
        let illisible = restrictions_actives(Some(&d));
        assert!(illisible.is_err());
        let montre = texte_restrictions(&illisible);
        assert!(montre.starts_with(&format!("{} (", mot_oui_non(true))), "{montre}");
        assert_ne!(montre, texte_restrictions(&Ok(true)));
        let _ = std::fs::remove_dir_all(d.parent().unwrap());
    }

    /// Le guide (« vanguard parametres ») nomme chaque réglage, dans les deux langues, comme l'aide et le README : les
    /// restrictions des extensions y avaient été oubliées. Un réglage ajouté doit trouver son nom ici.
    #[test]
    fn le_guide_nomme_chaque_reglage() {
        let (fr, en) = crate::guide::explication_vanguard("vanguard parametres").expect("vanguard parametres au guide");
        for r in Reglage::TOUS {
            if r == Reglage::PaquetsAur {
                // La ligne est pleine : celui-ci a sa propre ligne au guide, qui dit ce qu'il envoie et où.
                let (fr, en) = crate::guide::explication_vanguard("vanguard parametres paquets-aur oui")
                    .expect("paquets-aur au guide");
                assert!(fr.contains("AUR") && en.contains("AUR"), "{r:?} : {fr} / {en}");
                continue;
            }
            let (nom_fr, nom_en) = match r {
                Reglage::Langue => ("langue", "language"),
                Reglage::Emojis => ("emojis", "emojis"),
                Reglage::HorsLigne => ("sans Internet", "offline"),
                Reglage::TempsReel => ("temps réel", "real-time"),
                Reglage::Surveillance => ("surveillance", "monitoring"),
                Reglage::Entretien => ("entretien", "check-up"),
                Reglage::Appris => ("alertes apprises", "learned alerts"),
                Reglage::Blocage => ("blocage", "blocking"),
                // Douze réglages sur deux lignes de 70 colonnes : les plus longs y sont dits en un mot.
                Reglage::Restrictions => ("extensions", "extensions"),
                Reglage::CleAbuseCh => ("clé abuse.ch", "abuse.ch key"),
                Reglage::VersionsLogiciels => ("versions", "software versions"),
                Reglage::Autotest => ("autotest", "self-test"),
                Reglage::PaquetsAur => unreachable!("vérifié plus haut"),
            };
            // Sans tenir compte des majuscules : la phrase du guide commence par l'un d'eux.
            assert!(
                fr.to_lowercase().contains(&nom_fr.to_lowercase()),
                "{r:?} absent du guide : {fr}"
            );
            assert!(
                en.to_lowercase().contains(&nom_en.to_lowercase()),
                "{r:?} missing from the guide: {en}"
            );
        }
    }

    /// « temps-reel non » et sa durée : « --pendant 1h », « --pendant=4h », « --for 1h » ; une autre durée ou une
    /// option inconnue est refusée (rien ne change).
    #[test]
    fn duree_de_la_coupure() {
        use crate::protection::temps_reel::Duree;
        let mots = |t: &str| t.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(duree_saisie(&[]), Ok(None));
        assert_eq!(duree_saisie(&mots("--pendant 1h")), Ok(Some(Duree::UneHeure)));
        assert_eq!(duree_saisie(&mots("--pendant=4h")), Ok(Some(Duree::QuatreHeures)));
        assert_eq!(duree_saisie(&mots("--for 4h")), Ok(Some(Duree::QuatreHeures)));
        assert_eq!(duree_saisie(&mots("--pendant 2h")), Err(()));
        assert_eq!(duree_saisie(&mots("--pendant")), Err(()));
        assert_eq!(duree_saisie(&mots("--toujours 1h")), Err(()));
        assert_eq!(duree_saisie(&mots("--pendant 1h encore")), Err(()));
        assert!(valeurs_dites(Reglage::TempsReel).contains("1h|4h"));
    }

    #[test]
    fn mots_des_reglages() {
        for r in Reglage::TOUS {
            assert_eq!(Reglage::depuis_mot(r.mot()), Some(r));
            // Chaque valeur proposée au menu est acceptée par la ligne de commande.
            for v in r.valeurs() {
                let mut f = Fichier::default();
                let ok = match r {
                    Reglage::TempsReel | Reglage::Surveillance | Reglage::Entretien | Reglage::Restrictions => {
                        oui_non(v).is_some()
                    }
                    _ => changer_dans(&mut f, r, v).is_ok(),
                };
                assert!(ok, "{r:?} {v}");
            }
        }
        assert_eq!(Reglage::depuis_mot("settings"), None);
        assert_eq!(Reglage::depuis_mot("Language"), Some(Reglage::Langue));
        assert_eq!(Reglage::depuis_mot("offline"), Some(Reglage::HorsLigne));
        assert_eq!(Reglage::depuis_mot("abuse-ch"), Some(Reglage::CleAbuseCh));
        assert_eq!(Reglage::depuis_mot("Temps-Réel"), Some(Reglage::TempsReel));
        assert_eq!(Reglage::depuis_mot("realtime"), Some(Reglage::TempsReel));
        for mot in [
            "versions-logiciels",
            "software-versions",
            "versions",
            "perimes",
            "outdated",
        ] {
            assert_eq!(Reglage::depuis_mot(mot), Some(Reglage::VersionsLogiciels), "{mot}");
        }
        assert!(est_retirer("Retirer") && est_retirer("remove") && !est_retirer("a1B2c3D4e5F6g7H8i9J0k1L2"));
    }
}
