//! Protection en temps réel de Vanguard : un interrupteur qui coupe d'un coup ce qui veille et agit en continu (la
//! surveillance horaire et tout ce qu'elle regarde, la protection active du blocage), pendant une heure, quatre heures
//! ou jusqu'à ce que la personne la remette. Les réglages de chacun ne sont pas touchés : la minuterie de la
//! surveillance reste en place, blocage.json reste tel quel ; chacun les relit à la reprise, et retrouve donc son état
//! d'avant. La coupure tient dans temps-reel.json (son début, son échéance) ; à l'échéance, elle ne vaut plus, et la
//! surveillance, qui passe toutes les heures, le constate elle-même, retire le fichier et le notifie.
//!
//! Jamais Defender, le pare-feu ni l'UAC : ce réglage ne concerne que Vanguard. Ce qu'un blocage a déjà posé (règle du
//! pare-feu, quarantaine) reste en place : couper le temps réel ne défait rien. Un fichier abîmé ne coupe rien : la
//! protection reste en marche, et c'est dit. En administrateur, il ne se règle pas (comme les restrictions des
//! extensions) : le fichier est celui du compte, que la surveillance lit sans droits ; lu (sous sudo ou pkexec, celui
//! du compte qui l'a lancé, pas celui de root), il ne change rien à ce qu'y fait Vanguard, qui n'y bloque déjà rien
//! tout seul (`blocage::pour_agir`).
//!
//! Un autre programme du compte peut écrire ce fichier : couper d'abord ce qui surveille est un geste de logiciel
//! malveillant. Le réglage et le moment du dernier rappel sont donc scellés (`sceau`) : un réglage écrit hors de
//! Vanguard ne coupe rien (il se lit « illisible », la protection reste en marche), et un rappel posé d'avance ne
//! tait plus la notification. Une coupure ne reste jamais muette : la surveillance la notifie à sa première passe,
//! puis une fois par jour tant qu'elle dure, et l'entretien du mois la redit.

#[cfg(unix)]
use crate::socle::personnel::dossier_personnel_de;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::machine::Constat;
use crate::risk::Niveau;
use crate::ui::*;

/// Au-delà, ce n'est pas le fichier de Vanguard : il n'est pas lu.
const TAILLE_MAX: u64 = 4 << 10;

/// Une horloge retardée de plus que cela depuis la coupure (changement d'heure à la main, pile de la carte mère) : une
/// coupure à durée ne se croit plus sur parole, et la protection reprend.
const RETARD_TOLERE: i64 = 5 * 60;

/// Avant le 1er janvier 2026, Vanguard n'avait pas ce réglage : une coupure plus ancienne n'est pas la sienne (un
/// « coupee_le » à 0 ou à i64::MIN ne coupe rien).
const PLUS_ANCIENNE: i64 = 1_767_225_600;

/// Une coupure qui dure se redit par une notification à peu près une fois par jour (la surveillance passe toutes les
/// heures, un peu plus tard chaque fois : 23 heures font un rappel quotidien).
const RAPPEL: i64 = 23 * 3600;

/// Combien de temps la coupure dure.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Duree {
    UneHeure,
    QuatreHeures,
    JusquaReprise,
}

impl Duree {
    pub(crate) const TOUTES: [Duree; 3] = [Duree::UneHeure, Duree::QuatreHeures, Duree::JusquaReprise];

    fn secondes(self) -> Option<i64> {
        match self {
            Duree::UneHeure => Some(3600),
            Duree::QuatreHeures => Some(4 * 3600),
            Duree::JusquaReprise => None,
        }
    }

    /// Ce qui suit « --pendant » ; `None` : inconnu.
    pub(crate) fn depuis_mot(mot: &str) -> Option<Duree> {
        match mot.trim().to_lowercase().replace(' ', "").as_str() {
            "1h" | "1" | "1heure" | "1hour" | "60min" | "60m" => Some(Duree::UneHeure),
            "4h" | "4" | "4heures" | "4hours" | "240min" | "240m" => Some(Duree::QuatreHeures),
            _ => None,
        }
    }

    /// Telle qu'elle se lit dans une phrase (« couper … ? »).
    pub(crate) fn libelle(self) -> &'static str {
        match self {
            Duree::UneHeure => tr!("pendant 1 heure", "for 1 hour"),
            Duree::QuatreHeures => tr!("pendant 4 heures", "for 4 hours"),
            Duree::JusquaReprise => tr!("jusqu'à ce que vous la remettiez", "until you turn it back on"),
        }
    }

    /// Les plus longues durées données par Vanguard : une échéance plus lointaine n'est pas la sienne.
    const PLUS_LONGUE: i64 = 4 * 3600;
}

/// Ce que garde temps-reel.json : des secondes depuis 1970, comme l'horloge du système.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct Fichier {
    coupee_le: i64,
    /// Absente : jusqu'à ce que la personne la remette.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    jusqu_a: Option<i64>,
}

/// Une coupure : son début et son échéance (`None` : jusqu'à reprise).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Coupure {
    pub depuis: i64,
    pub jusqu_a: Option<i64>,
}

impl Coupure {
    /// La durée choisie, retrouvée de son échéance.
    pub(crate) fn duree(&self) -> Duree {
        match self.jusqu_a {
            None => Duree::JusquaReprise,
            Some(fin) if fin.saturating_sub(self.depuis) <= 3600 => Duree::UneHeure,
            Some(_) => Duree::QuatreHeures,
        }
    }
}

/// L'état lu.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) enum Etat {
    /// Pas de coupure : chacun fait ce qui est réglé.
    EnMarche,
    Coupee(Coupure),
    /// L'échéance est passée : la protection a repris, et le fichier attend d'être retiré (surveillance, changement).
    Echue(Coupure),
    /// Le fichier ne se lit plus : rien n'est coupé sur la foi d'un fichier abîmé.
    Illisible(String),
}

impl Etat {
    pub(crate) fn coupure(&self) -> Option<Coupure> {
        match self {
            Etat::Coupee(c) => Some(*c),
            _ => None,
        }
    }
}

fn fichier() -> PathBuf {
    dossier_local_appelant().0.join("temps-reel.json")
}

/// Le dossier de données du compte qui a lancé Vanguard : sous sudo ou pkexec, celui du compte d'avant (`true`),
/// sinon `reseau::dossier_local` (`false`). Les traces d'incident, que le LISEZMOI conseille de relancer avec sudo,
/// lisaient sinon les données de root : aucun geste, aucune alerte, alors qu'un blocage avait eu lieu la nuit.
pub(crate) fn dossier_local_appelant() -> (PathBuf, bool) {
    #[cfg(unix)]
    if !cfg!(test)
        && let Some(d) = dossier_appelant(
            // SAFETY: geteuid ne prend aucun argument et ne touche aucune mémoire.
            unsafe { libc::geteuid() },
            std::env::var("SUDO_UID")
                .or_else(|_| std::env::var("PKEXEC_UID"))
                .ok()
                .as_deref(),
            dossier_personnel_de,
        )
    {
        return (d, true);
    }
    (crate::reseau::dossier_local(), false)
}

/// Le fichier du rappel : quand la coupure a été notifiée pour la dernière fois.
fn dossier_rappel() -> PathBuf {
    crate::socle::dossier_local()
}

/// Sous sudo ou pkexec (root, avec le numéro du compte qui l'a lancé) : le dossier de données de ce compte. Sous
/// « sudo -i » ou « sudo -H », HOME est celui de root, et le réglage lu aurait été celui de root : « pas coupée »
/// alors que celle du compte l'est. `None` : pas en root, root lui-même, ou un compte inconnu.
#[cfg(unix)]
fn dossier_appelant(
    euid: libc::uid_t,
    appelant: Option<&str>,
    dossier_de: impl Fn(libc::uid_t) -> Option<PathBuf>,
) -> Option<PathBuf> {
    if euid != 0 {
        return None;
    }
    let uid: libc::uid_t = appelant?.trim().parse().ok().filter(|&u| u != 0)?;
    let maison = dossier_de(uid).filter(|d| d.is_absolute())?;
    // Le dossier par défaut de `crate::socle::dossier_local` (le XDG_DATA_HOME du compte ne se lit pas d'ici).
    let sous = if cfg!(target_os = "macos") {
        "Library/Application Support/vanguard"
    } else {
        ".local/share/vanguard"
    };
    Some(maison.join(sous))
}

fn maintenant() -> i64 {
    chrono::Local::now().timestamp()
}

/// L'état de `chemin` à l'instant `maintenant`.
/// Le dossier et le nom d'un fichier d'état (`chemin` : `<dossier>/temps-reel.json`).
fn dossier_et_nom(chemin: &Path) -> (&Path, &str) {
    (
        chemin.parent().unwrap_or(Path::new(".")),
        chemin
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(crate::sceau::TEMPS_REEL),
    )
}

fn lire_de(chemin: &Path, maintenant: i64) -> Etat {
    use crate::sceau::{Doute, Juge};
    // Lu par les sceaux : un simple fichier (ni lien, ni tube, ni périphérique, qu'un Vanguard en administrateur
    // lirait sinon sans fin, ou avec ses droits), tel que Vanguard l'a écrit. Écrit hors de Vanguard, il ne coupe
    // rien : un programme du compte ne coupe pas la surveillance en posant ce fichier. Sous sudo, le dossier du
    // compte n'est que lu (`socle::ecriture_sure`).
    // Accepté tel quel après des sceaux refaits (`sceau::juge`), il ne coupe rien non plus : rien ne prouve qui l'a
    // écrit.
    let (dossier, nom) = dossier_et_nom(chemin);
    let lu = crate::sceau::lire_dans(dossier, nom);
    let octets = match crate::sceau::juger_lecture(lu, || crate::sceau::repris_dans(dossier, nom)) {
        Juge::Absent | Juge::Douteux(Doute::Inconnu | Doute::HorsVanguard, None) => return Etat::EnMarche,
        Juge::Cru(o) => o,
        Juge::Douteux(d, _) => return Etat::Illisible(d.texte().to_string()),
        Juge::Illisible(e) => return Etat::Illisible(e),
    };
    if octets.len() as u64 > TAILLE_MAX {
        return Etat::Illisible(trf!("plus de {} Kio", "over {} KiB", TAILLE_MAX >> 10));
    }
    let texte = String::from_utf8_lossy(&octets);
    let lu = serde_json::from_str::<Fichier>(texte.trim_start_matches('\u{feff}')).map_err(|e| e.to_string());
    let f = match lu {
        Ok(f) => f,
        Err(e) => return Etat::Illisible(e),
    };
    let c = Coupure {
        depuis: f.coupee_le,
        jusqu_a: f.jusqu_a,
    };
    match c.jusqu_a {
        // Une date ou une durée que Vanguard ne donne jamais : ce n'est pas lui qui a écrit ce fichier.
        _ if c.depuis < PLUS_ANCIENNE => Etat::Illisible(tr!("date inconnue", "unknown date").to_string()),
        Some(fin) if fin <= c.depuis || fin.saturating_sub(c.depuis) > Duree::PLUS_LONGUE => {
            Etat::Illisible(tr!("durée inconnue", "unknown duration").to_string())
        }
        // Une horloge retardée bien avant la coupure : elle ne se croit plus sur parole, à durée comme jusqu'à
        // reprise, et la protection reprend.
        _ if maintenant < c.depuis.saturating_sub(RETARD_TOLERE) => Etat::Echue(c),
        Some(fin) if maintenant >= fin => Etat::Echue(c),
        _ => Etat::Coupee(c),
    }
}

/// L'état de la protection en temps réel, maintenant.
pub(crate) fn etat() -> Etat {
    lire_de(&fichier(), maintenant())
}

/// La coupure en cours, s'il y en a une : ce que la surveillance et le blocage consultent.
pub(crate) fn coupure() -> Option<Coupure> {
    etat().coupure()
}

/// Un fichier qu'on ne sait plus lire n'est jamais écrasé ni effacé en silence : il est gardé à côté, tel quel, sous
/// un nom libre (deux mis de côté dans la même seconde ne s'écrasent pas l'un l'autre).
fn mettre_de_cote(chemin: &Path) -> std::io::Result<PathBuf> {
    let date = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string();
    let copie = (0..100)
        .map(|n| {
            let suite = if n == 0 { String::new() } else { format!("-{n}") };
            chemin.with_extension(format!("illisible-{date}{suite}.json"))
        })
        .find(|c| !c.exists())
        .ok_or_else(|| std::io::Error::other(tr!("trop de fichiers mis de côté", "too many files set aside")))?;
    std::fs::rename(chemin, &copie)?;
    // Mis de côté par Vanguard lui-même : son sceau part avec lui, sinon le bilan le dirait supprimé hors de Vanguard.
    let (dossier, nom) = dossier_et_nom(chemin);
    let _ = crate::sceau::effacer_dans(dossier, nom);
    Ok(copie)
}

/// Coupe pour `duree` à partir de `maintenant`.
fn couper_dans(chemin: &Path, duree: Duree, maintenant: i64) -> Result<Coupure, String> {
    if matches!(lire_de(chemin, maintenant), Etat::Illisible(_)) {
        mettre_de_cote(chemin).map_err(|e| e.to_string())?;
    }
    let f = Fichier {
        coupee_le: maintenant,
        jusqu_a: duree.secondes().map(|s| maintenant.saturating_add(s)),
    };
    let texte = serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?;
    let (dossier, nom) = dossier_et_nom(chemin);
    crate::sceau::ecrire_dans(dossier, nom, texte.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Coupure {
        depuis: f.coupee_le,
        jusqu_a: f.jusqu_a,
    })
}

/// Remet la protection : le fichier retiré (illisible : gardé à côté).
fn reprendre_dans(chemin: &Path, maintenant: i64) -> Result<(), String> {
    match lire_de(chemin, maintenant) {
        Etat::EnMarche => Ok(()),
        Etat::Illisible(_) => mettre_de_cote(chemin).map(|_| ()).map_err(|e| e.to_string()),
        Etat::Coupee(_) | Etat::Echue(_) => {
            let (dossier, nom) = dossier_et_nom(chemin);
            crate::sceau::effacer_dans(dossier, nom).map_err(|e| e.to_string())
        }
    }
}

/// Le changement voulu : `None` remet la protection, `Some(durée)` la coupe, après `accord` (refusé : rien ne
/// change). Rend (avant, après).
fn regler_dans(
    chemin: &Path,
    voulu: Option<Duree>,
    maintenant: i64,
    accord: impl FnOnce(Duree) -> bool,
) -> Result<(Etat, Etat), String> {
    let avant = lire_de(chemin, maintenant);
    match voulu {
        None => reprendre_dans(chemin, maintenant)?,
        Some(d) => {
            if !accord(d) {
                return Ok((avant.clone(), avant));
            }
            couper_dans(chemin, d, maintenant)?;
        }
    }
    Ok((avant, lire_de(chemin, maintenant)))
}

/// Vanguard tourne-t-il en administrateur (ou ne peut-il pas le savoir) ?
fn administrateur() -> bool {
    crate::protection::blocage::administrateur_ou_inconnu()
}

fn refus_administrateur() -> String {
    tr!(
        "Vanguard tourne en administrateur : la protection en temps réel ne se règle pas d'ici. Son réglage est celui de votre compte, lu par la surveillance sans droits ; relancez Vanguard sans droits d'administrateur (sans sudo, ou pas « en tant qu'administrateur ») pour la couper ou la remettre.",
        "Vanguard is running as administrator: real-time protection is not set from here. Its setting belongs to your account and is read by the monitoring without rights; start Vanguard again without administrator rights (no sudo, or not “as administrator”) to turn it off or back on."
    )
    .to_string()
}

/// Le réglage changé pour de vrai, dans le fichier de ce compte. `Err` : refusé en administrateur, ou non écrit.
pub(crate) fn regler(voulu: Option<Duree>, accord: impl FnOnce(Duree) -> bool) -> Result<(Etat, Etat), String> {
    if administrateur() {
        return Err(refus_administrateur());
    }
    regler_dans(&fichier(), voulu, maintenant(), accord)
}

/// Une heure montrée : « 17:30 » le jour même, avec la date sinon.
fn heure(ts: i64, maintenant: i64) -> String {
    use chrono::TimeZone;
    let local = |t: i64| chrono::Local.timestamp_opt(t, 0).single();
    match (local(ts), local(maintenant)) {
        (Some(t), Some(m)) if t.date_naive() == m.date_naive() => t.format("%H:%M").to_string(),
        (Some(t), _) => t.format(tr!("%d/%m %H:%M", "%m-%d %H:%M")).to_string(),
        (None, _) => "?".into(),
    }
}

/// « jusqu'à 17:30 » ou « jusqu'à reprise ».
fn jusqu_a(c: &Coupure, maintenant: i64) -> String {
    match c.jusqu_a {
        Some(fin) => trf!("jusqu'à {}", "until {}", heure(fin, maintenant)),
        None => tr!("jusqu'à reprise", "until turned back on").to_string(),
    }
}

/// La valeur montrée dans Paramètres : le mot tapé devant (« oui », « non »), puis ce qu'il veut dire.
pub(crate) fn valeur_de(e: &Etat, maintenant: i64) -> String {
    let (oui, non) = (tr!("oui", "yes"), tr!("non", "no"));
    match e {
        Etat::EnMarche | Etat::Echue(_) => oui.to_string(),
        Etat::Coupee(c) => format!("{non} ({})", jusqu_a(c, maintenant)),
        Etat::Illisible(_) => trf!("{oui} (fichier illisible)", "{oui} (file unreadable)"),
    }
}

pub(crate) fn valeur() -> String {
    valeur_de(&etat(), maintenant())
}

/// Un état tel qu'il se montre maintenant (avant et après un changement).
pub(crate) fn montrer(e: &Etat) -> String {
    valeur_de(e, maintenant())
}

/// L'échéance d'une coupure, telle qu'elle se montre (« jusqu'à 17:30 »).
pub(crate) fn echeance(c: &Coupure) -> String {
    jusqu_a(c, maintenant())
}

/// L'heure de la reprise (« 17:30 ») ; `None` : jusqu'à reprise.
pub(crate) fn heure_de_reprise(c: &Coupure) -> Option<String> {
    c.jusqu_a.map(|fin| heure(fin, maintenant()))
}

/// Pour l'en-tête du menu principal, en couleur : avec l'échéance, puis sans (quand la ligne serait trop longue).
pub(crate) fn en_tete() -> Option<(String, String)> {
    let c = coupure()?;
    let teinte = couleur(Niveau::Moyen);
    let court = trf!("{teinte}temps réel coupé{RESET}", "{teinte}real-time off{RESET}");
    let long = match c.jusqu_a {
        Some(fin) => trf!(
            "{teinte}temps réel coupé → {}{RESET}",
            "{teinte}real-time off → {}{RESET}",
            heure(fin, maintenant())
        ),
        None => court.clone(),
    };
    Some((long, court))
}

/// La phrase qui dit la coupure au bilan : tout ce qu'elle arrête, ce qui reste, et comment la remettre.
fn phrase(c: &Coupure, maintenant: i64) -> String {
    let reprise = match c.jusqu_a {
        Some(_) => tr!(
            "Elle reprend toute seule à l'échéance ; tout de suite : vanguard parametres temps-reel oui.",
            "It comes back by itself when the time is up; right now: vanguard settings real-time yes."
        ),
        None => tr!(
            "Pour la remettre : vanguard parametres temps-reel oui.",
            "To turn it back on: vanguard settings real-time yes."
        ),
    };
    trf!(
        "Protection en temps réel de Vanguard coupée depuis {} ({}) : la surveillance horaire ne passe plus et rien n'est bloqué tout seul. Defender, le pare-feu, l'UAC et les blocages déjà faits restent en place. {reprise}",
        "Vanguard's real-time protection off since {} ({}): the hourly monitoring no longer runs and nothing is blocked by itself. Defender, the firewall, UAC and the blocks already made stay in place. {reprise}",
        heure(c.depuis, maintenant),
        jusqu_a(c, maintenant)
    )
}

/// Là où la coupure se dit, chacun avec ce qu'elle y change.
#[derive(Clone, Copy)]
pub(crate) enum Ou {
    Blocage,
    Sortantes,
    /// La surveillance qu'on vient d'activer : sa minuterie est posée, mais aucune passe ne se fera avant la reprise.
    Surveillance,
}

/// Ce que la coupure change à l'écran `ou`.
fn phrase_pour(ou: Ou, c: &Coupure, maintenant: i64) -> String {
    let quand = jusqu_a(c, maintenant);
    match ou {
        Ou::Blocage => trf!(
            "Protection en temps réel coupée ({quand}) : rien n'est bloqué tout seul, le certain se propose d'un clic. Les blocages déjà faits restent en place ; vos réglages reviennent tels quels à la reprise.",
            "Real-time protection off ({quand}): nothing is blocked by itself, what is certain is offered with one click. The blocks already made stay in place; your settings come back as they were when it resumes."
        ),
        Ou::Sortantes => trf!(
            "Protection en temps réel coupée ({quand}) : la surveillance ne notifie ni ne bloque plus une connexion vers un serveur de commande ; cet écran, lui, la montre. Les blocages déjà faits restent en place.",
            "Real-time protection off ({quand}): the monitoring no longer notifies or blocks a connection to a command server; this screen still shows it. The blocks already made stay in place."
        ),
        Ou::Surveillance => trf!(
            "Protection en temps réel coupée ({quand}) : aucune passe ne se fera avant qu'elle reprenne, rien ne sera regardé ni notifié d'ici là. La remettre : vanguard parametres temps-reel oui.",
            "Real-time protection off ({quand}): no run will happen until it comes back, nothing will be looked at or notified until then. Turn it back on: vanguard settings real-time yes."
        ),
    }
}

/// Dit la coupure en une ligne d'information, s'il y en a une. Rend `true` si elle l'a dite.
pub(crate) fn dire_si_coupee(ou: Ou) -> bool {
    let Some(c) = coupure() else {
        return false;
    };
    afficher_aligne(
        &format!("  {}ℹ{RESET} ", couleur(Niveau::Moyen)),
        &phrase_pour(ou, &c, maintenant()),
        4,
        "",
    );
    true
}

/// Le constat du bilan : toujours un, en marche ou coupée, pour que la coupure ne change jamais la note ni ce qui
/// la rend possible (le nombre de vérifications) ; coupée, une information, jamais une alerte.
pub(crate) fn constat() -> Constat {
    constat_de(&etat(), maintenant())
}

fn constat_de(e: &Etat, maintenant: i64) -> Constat {
    const CAT: &str = "Surveillance";
    match e {
        Etat::Coupee(c) => crate::machine::alerte(CAT, Niveau::Info, phrase(c, maintenant)),
        Etat::Illisible(raison) => crate::machine::alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Le réglage de la protection en temps réel ne se lit plus ({raison}) : elle reste en marche. « vanguard parametres temps-reel oui » le met de côté.",
                "The real-time protection setting can no longer be read ({raison}): it stays on. “vanguard settings real-time yes” sets it aside."
            ),
        ),
        Etat::EnMarche | Etat::Echue(_) => crate::machine::ok(
            CAT,
            tr!(
                "Protection en temps réel de Vanguard : pas coupée.",
                "Vanguard's real-time protection: not turned off."
            ),
        ),
    }
}

/// Faut-il redire la coupure `c` par une notification, le dernier rappel datant de `dernier` ? À la première passe
/// d'une coupure, puis une fois par jour tant qu'elle dure (et si l'horloge a reculé depuis le dernier).
fn rappel_du(c: &Coupure, dernier: Option<i64>, maintenant: i64) -> bool {
    dernier.is_none_or(|d| d < c.depuis || maintenant < d || maintenant.saturating_sub(d) >= RAPPEL)
}

/// La notification d'une coupure qui dure : (titre, texte).
fn texte_du_rappel(c: &Coupure, maintenant: i64) -> (&'static str, String) {
    (
        tr!(
            "Vanguard : protection en temps réel coupée",
            "Vanguard: real-time protection is off"
        ),
        trf!(
            "Coupée depuis {} ({}) : la surveillance horaire ne regarde plus rien et rien n'est bloqué tout seul. Si ce n'est pas vous, un programme l'a peut-être coupée exprès. La remettre : vanguard parametres temps-reel oui.",
            "Off since {} ({}): the hourly monitoring no longer looks at anything and nothing is blocked by itself. If it was not you, a program may have turned it off on purpose. Turn it back on: vanguard settings real-time yes.",
            heure(c.depuis, maintenant),
            jusqu_a(c, maintenant)
        ),
    )
}

/// Redit la coupure par une notification, si c'est le moment ; le moment du rappel est noté.
fn rappeler(c: &Coupure) {
    let maintenant = maintenant();
    let dossier = dossier_rappel();
    if !rappel_du(c, dernier_rappel(&dossier), maintenant) {
        return;
    }
    let (titre, texte) = texte_du_rappel(c, maintenant);
    crate::reseau::surveillance::alerter(crate::reseau::tableau::Genre::Autre, titre, &texte);
    // Non noté (disque plein, dossier refusé) : la passe suivante la redit, plutôt que de se taire.
    let _ = crate::sceau::ecrire_dans(
        &dossier,
        crate::sceau::TEMPS_REEL_RAPPEL,
        maintenant.to_string().as_bytes(),
    );
}

/// Le moment du dernier rappel, seulement tel que Vanguard l'a noté : posé, adopté, changé ou illisible, il ne
/// vaut rien, et la coupure se redit tout de suite.
fn dernier_rappel(dossier: &Path) -> Option<i64> {
    match crate::sceau::lire_dans(dossier, crate::sceau::TEMPS_REEL_RAPPEL) {
        crate::sceau::Lecture::Intact(o) => std::str::from_utf8(&o).ok()?.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Au début de chaque passe de la surveillance : `true` si la passe s'arrête là (coupée ; c'est notifié à la première
/// passe, puis une fois par jour). Une échéance passée remet la protection (le fichier retiré, la reprise notifiée),
/// puis la passe se fait comme d'habitude. Un fichier illisible ne coupe rien.
pub(crate) fn a_la_passe() -> bool {
    match etat() {
        Etat::Coupee(c) => {
            rappeler(&c);
            true
        }
        Etat::Echue(_) => {
            if reprendre_dans(&fichier(), maintenant()).is_ok() {
                crate::reseau::surveillance::notifier(
                    tr!(
                        "Vanguard : protection en temps réel reprise",
                        "Vanguard: real-time protection back on"
                    ),
                    tr!(
                        "La coupure est finie : la surveillance et la protection active reprennent comme vous les aviez réglées.",
                        "The pause is over: monitoring and active protection resume as you had set them."
                    ),
                );
            }
            false
        }
        Etat::EnMarche | Etat::Illisible(_) => false,
    }
}

/// La ligne de l'entretien du mois, s'il y a une coupure : au bilan, elle n'est qu'une information, que l'entretien
/// ne retient pas avec les problèmes.
pub(crate) fn pour_entretien() -> Option<String> {
    let c = coupure()?;
    let maintenant = maintenant();
    Some(trf!(
        "Protection en temps réel de Vanguard coupée depuis {} ({}) : vanguard parametres temps-reel oui la remet.",
        "Vanguard's real-time protection off since {} ({}): vanguard settings real-time yes turns it back on.",
        heure(c.depuis, maintenant),
        jusqu_a(&c, maintenant)
    ))
}

/// Ce que la coupure arrête, avec l'état de chacun (rien n'est arrêté qui ne tournait déjà), puis ce qui reste.
pub(crate) fn ce_qui_s_arrete(surveillance: bool, protection_active: bool) -> Vec<String> {
    let etat = |oui: bool| {
        if oui {
            tr!("en marche", "running")
        } else {
            tr!("déjà coupée", "already off")
        }
    };
    let mut lignes = vec![
        trf!(
            "• La surveillance horaire ({}) : plus de scan du réseau ni d'audit de l'ordinateur, plus aucune notification (appareil nouveau, port ouvert, routeur, DNS, Wi-Fi, fichiers critiques, téléchargements, serveurs de botnet, extensions qui veillent), sauf celle qui redit la coupure, une fois par jour.",
            "• Hourly monitoring ({}): no more network scan or machine audit, no notification at all (new device, open port, router, DNS, Wi-Fi, critical files, downloads, botnet servers, extensions that watch), except the one that recalls the pause, once a day.",
            etat(surveillance)
        ),
        trf!(
            "• La protection active du blocage ({}) : plus rien n'est bloqué tout seul, ni au bilan ni dans la surveillance ; au bilan, le certain se propose d'un clic.",
            "• Active protection of blocking ({}): nothing is blocked by itself any more, neither at the check-up nor in the monitoring; at the check-up, what is certain is offered with one click.",
            if protection_active {
                tr!("en marche", "running")
            } else {
                tr!("pas activée", "not turned on")
            }
        ),
    ];
    // Le veilleur lit cette coupure toutes les minutes : il continue de tourner, mais ne note ni ne notifie plus rien.
    #[cfg(target_os = "linux")]
    if crate::machine::linux::veilleur::voulu() {
        lignes.push(
            tr!(
                "• Le veilleur des lancements et des connexions (allumé) : il reste en marche, mais ne note ni ne notifie plus rien jusqu'à la reprise.",
                "• The watcher of launches and connections (on): it keeps running, but notes and notifies nothing until it comes back."
            )
            .to_string(),
        );
    }
    lignes.push(ce_qui_reste().to_string());
    lignes
}

/// Ce que la coupure ne touche jamais.
pub(crate) fn ce_qui_reste() -> &'static str {
    tr!(
        "Ce qui ne change pas : Defender, le pare-feu et l'UAC, que ce réglage ne touche jamais ; les blocages déjà faits, qui restent en place (règles du pare-feu, quarantaine ; « vanguard blocage annuler » en défait un) ; vos réglages de surveillance et de blocage, retrouvés tels quels à la reprise ; le bilan, l'antivirus et les outils que vous lancez ; l'entretien du mois.",
        "What does not change: Defender, the firewall and UAC, which this setting never touches; the blocks already made, which stay in place (firewall rules, quarantine; “vanguard blocking undo” undoes one); your monitoring and blocking settings, found as they were when it comes back; the check-up, the antivirus and the tools you start; the monthly check-up notification."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jetable(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-temps-reel-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("temps-reel.json")
    }

    const MIDI: i64 = 1_792_000_000;

    /// Un réglage tel que Vanguard l'écrit (scellé).
    fn poser(f: &Path, texte: &str) {
        let (dossier, nom) = dossier_et_nom(f);
        crate::sceau::ecrire_dans(dossier, nom, texte.as_bytes()).unwrap();
    }

    /// Un programme du compte coupe la protection en posant le réglage, puis un rappel tout frais pour taire la
    /// notification : le réglage posé ne coupe rien, et le rappel posé ne vaut rien (la coupure se redit).
    #[test]
    fn reglage_et_rappel_poses_a_cote_ne_coupent_ni_ne_taisent_rien() {
        let f = jetable("pose");
        let d = f.parent().unwrap().to_path_buf();
        // Les sceaux existent déjà (Vanguard a servi ici).
        crate::sceau::ecrire_dans(&d, crate::sceau::APPRIS, b"{}").unwrap();
        std::fs::write(&f, format!("{{\"coupee_le\": {}}}", MIDI - 60)).unwrap();
        assert!(
            matches!(lire_de(&f, MIDI), Etat::Illisible(_)),
            "{:?}",
            lire_de(&f, MIDI)
        );
        std::fs::write(d.join(crate::sceau::TEMPS_REEL_RAPPEL), (MIDI - 30).to_string()).unwrap();
        assert_eq!(dernier_rappel(&d), None);
        // Noté par Vanguard : cru.
        crate::sceau::ecrire_dans(&d, crate::sceau::TEMPS_REEL_RAPPEL, (MIDI - 30).to_string().as_bytes()).unwrap();
        assert_eq!(dernier_rappel(&d), Some(MIDI - 30));
        // S2c : les sceaux effacés avec le réglage posé (accepté tel quel) : rien n'est coupé non plus.
        std::fs::write(&f, format!("{{\"coupee_le\": {}}}", MIDI - 60)).unwrap();
        std::fs::remove_file(d.join("sceaux.json")).unwrap();
        assert!(matches!(
            crate::sceau::lire_dans(&d, crate::sceau::TEMPS_REEL),
            crate::sceau::Lecture::Adopte(_)
        ));
        assert!(lire_de(&f, MIDI).coupure().is_none(), "{:?}", lire_de(&f, MIDI));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sans fichier : en marche. Coupée pour une heure : coupée, puis échue passé l'heure ; jusqu'à reprise : coupée
    /// même un an après. La reprise retire le fichier.
    #[test]
    fn coupure_puis_reprise() {
        let f = jetable("coupure");
        assert_eq!(lire_de(&f, MIDI), Etat::EnMarche);
        let c = couper_dans(&f, Duree::UneHeure, MIDI).unwrap();
        assert_eq!(c.jusqu_a, Some(MIDI + 3600));
        assert_eq!(lire_de(&f, MIDI + 60), Etat::Coupee(c));
        assert_eq!(lire_de(&f, MIDI + 3599).coupure(), Some(c));
        // L'échéance passée : elle a repris, même si personne n'a encore retiré le fichier.
        assert_eq!(lire_de(&f, MIDI + 3600), Etat::Echue(c));
        assert_eq!(lire_de(&f, MIDI + 3600).coupure(), None);
        // Une horloge retardée bien avant la coupure : une coupure à durée ne se croit plus.
        assert_eq!(lire_de(&f, MIDI - 3600), Etat::Echue(c));
        assert_eq!(lire_de(&f, MIDI - 60).coupure(), Some(c), "un petit écart est toléré");
        reprendre_dans(&f, MIDI + 3600).unwrap();
        assert!(!f.exists());
        assert_eq!(lire_de(&f, MIDI), Etat::EnMarche);
        let c = couper_dans(&f, Duree::QuatreHeures, MIDI).unwrap();
        assert_eq!(c.jusqu_a, Some(MIDI + 4 * 3600));
        let c = couper_dans(&f, Duree::JusquaReprise, MIDI).unwrap();
        assert_eq!(c.jusqu_a, None);
        assert_eq!(lire_de(&f, MIDI + 365 * 86_400).coupure(), Some(c));
        reprendre_dans(&f, MIDI).unwrap();
        assert_eq!(lire_de(&f, MIDI), Etat::EnMarche);
        // Déjà en marche : remettre ne fait rien, sans erreur.
        reprendre_dans(&f, MIDI).unwrap();
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// Couper passe par l'accord : refusé, rien ne change ni ne s'écrit ; remettre ne demande rien.
    #[test]
    fn refus_qui_ne_change_rien() {
        let f = jetable("refus");
        let (avant, apres) = regler_dans(&f, Some(Duree::UneHeure), MIDI, |_| false).unwrap();
        assert_eq!((avant, apres), (Etat::EnMarche, Etat::EnMarche));
        assert!(!f.exists());
        let mut demandee = None;
        let (_, apres) = regler_dans(&f, Some(Duree::QuatreHeures), MIDI, |d| {
            demandee = Some(d);
            true
        })
        .unwrap();
        assert_eq!(demandee, Some(Duree::QuatreHeures));
        assert!(apres.coupure().is_some());
        // Déjà coupée, un refus garde la coupure telle quelle.
        let (avant, apres) = regler_dans(&f, Some(Duree::UneHeure), MIDI + 10, |_| false).unwrap();
        assert_eq!(avant, apres);
        assert_eq!(apres.coupure().unwrap().jusqu_a, Some(MIDI + 4 * 3600));
        let (avant, apres) = regler_dans(&f, None, MIDI, |_| panic!("remettre ne demande rien")).unwrap();
        assert!(avant.coupure().is_some());
        assert_eq!(apres, Etat::EnMarche);
        let _ = std::fs::remove_dir_all(f.parent().unwrap());
    }

    /// Un fichier abîmé, démesuré ou d'une durée que Vanguard ne donne pas : rien n'est coupé, et c'est dit. Il n'est
    /// jamais écrasé ni effacé en silence : remettre ou couper le met d'abord de côté.
    #[test]
    fn fichier_abime() {
        let f = jetable("abime");
        let d = f.parent().unwrap().to_path_buf();
        let de_cote = || {
            std::fs::read_dir(&d)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().contains("illisible-"))
                .count()
        };
        std::fs::write(&f, "{pas du json").unwrap();
        let e = lire_de(&f, MIDI);
        assert!(matches!(e, Etat::Illisible(_)), "{e:?}");
        assert_eq!(e.coupure(), None);
        assert!(valeur_de(&e, MIDI).starts_with(&format!("{} (", tr!("oui", "yes"))));
        reprendre_dans(&f, MIDI).unwrap();
        assert!(!f.exists());
        assert_eq!(de_cote(), 1);
        std::fs::write(&f, " ".repeat(usize::try_from(TAILLE_MAX).unwrap() + 1)).unwrap();
        assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)));
        // Une échéance plus lointaine que quatre heures, ou d'avant la coupure : pas la sienne.
        for fin in [MIDI + 4 * 3600 + 1, MIDI, MIDI - 1] {
            poser(&f, &format!("{{\"coupee_le\": {MIDI}, \"jusqu_a\": {fin}}}"));
            assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)), "{fin}");
        }
        // Des nombres extrêmes ne font pas planter la lecture.
        poser(
            &f,
            &format!("{{\"coupee_le\": {}, \"jusqu_a\": {}}}", i64::MIN, i64::MAX),
        );
        assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)));
        // Jusqu'à reprise, une date de début que Vanguard ne donne jamais (0, i64::MIN, d'avant le réglage) ne coupe
        // rien : un autre programme ne coupe pas la surveillance pour toujours avec « coupee_le: 0 ».
        for debut in [i64::MIN, 0, PLUS_ANCIENNE - 1] {
            poser(&f, &format!("{{\"coupee_le\": {debut}}}"));
            assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)), "{debut}");
        }
        // Écrite hors de Vanguard, une coupure valable ne coupe rien.
        std::fs::write(&f, format!("{{\"coupee_le\": {MIDI}}}")).unwrap();
        assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)));
        poser(&f, &format!("{{\"coupee_le\": {MIDI}}}"));
        assert!(lire_de(&f, MIDI + 365 * 86_400).coupure().is_some());
        // Jusqu'à reprise, une coupure datée de bien après maintenant (horloge retardée) ne se croit plus.
        assert!(matches!(lire_de(&f, MIDI - 3600), Etat::Echue(_)));
        assert!(lire_de(&f, MIDI - 60).coupure().is_some(), "un petit écart est toléré");
        // Un lien (vers un tube, un périphérique, un fichier de root) n'est pas lu : rien n'est coupé.
        #[cfg(unix)]
        {
            let cible = d.join("ailleurs.json");
            std::fs::write(&cible, format!("{{\"coupee_le\": {MIDI}}}")).unwrap();
            std::fs::remove_file(&f).unwrap();
            std::os::unix::fs::symlink(&cible, &f).unwrap();
            assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)));
            std::fs::remove_file(&f).unwrap();
            std::fs::create_dir(&f).unwrap();
            assert!(matches!(lire_de(&f, MIDI), Etat::Illisible(_)));
            std::fs::remove_dir(&f).unwrap();
        }
        // Couper par-dessus un fichier abîmé : l'ancien est gardé à côté, la nouvelle coupure se lit.
        std::fs::write(&f, "{abîmé").unwrap();
        let c = couper_dans(&f, Duree::UneHeure, MIDI).unwrap();
        assert_eq!(lire_de(&f, MIDI), Etat::Coupee(c));
        assert_eq!(de_cote(), 2);
        // Mis de côté puis retiré par Vanguard : rien n'est dit « supprimé hors de Vanguard ».
        reprendre_dans(&f, MIDI).unwrap();
        std::fs::write(&f, "{abîmé").unwrap();
        reprendre_dans(&f, MIDI).unwrap();
        assert_eq!(
            crate::sceau::lire_dans(&d, crate::sceau::TEMPS_REEL),
            crate::sceau::Lecture::Absent
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une coupure ne reste jamais muette : notifiée à la première passe, puis une fois par jour tant qu'elle dure ;
    /// une nouvelle coupure, ou une horloge qui a reculé, se notifie aussitôt.
    #[test]
    fn coupure_redite_chaque_jour() {
        let c = Coupure {
            depuis: MIDI,
            jusqu_a: None,
        };
        assert!(rappel_du(&c, None, MIDI + 60));
        assert!(!rappel_du(&c, Some(MIDI + 60), MIDI + 3700));
        assert!(!rappel_du(&c, Some(MIDI + 60), MIDI + 60 + RAPPEL - 1));
        assert!(rappel_du(&c, Some(MIDI + 60), MIDI + 60 + RAPPEL));
        // Le rappel d'une coupure d'avant : celle-ci n'a pas encore été dite.
        assert!(rappel_du(&c, Some(MIDI - 10), MIDI + 60));
        assert!(rappel_du(&c, Some(MIDI + 7200), MIDI + 3600), "horloge reculée");
        // Une coupure de quatre heures se dit donc une fois.
        let courte = Coupure {
            depuis: MIDI,
            jusqu_a: Some(MIDI + 4 * 3600),
        };
        assert!((1..4).all(|h| !rappel_du(&courte, Some(MIDI + 60), MIDI + h * 3600)));
        let (titre, texte) = texte_du_rappel(&c, MIDI + 60);
        assert_ne!(titre, "");
        assert!(
            texte.contains("temps-reel oui") || texte.contains("real-time yes"),
            "{texte}"
        );
        assert!(
            texte.contains(tr!("jusqu'à reprise", "until turned back on")),
            "{texte}"
        );
    }

    /// Sous sudo ou pkexec, le réglage lu est celui du compte qui a lancé Vanguard, pas celui de root ; sans droits,
    /// ou root lui-même, celui du dossier habituel.
    #[cfg(unix)]
    #[test]
    fn sous_sudo_le_reglage_du_compte() {
        let maison = |uid| (uid == 1000).then(|| PathBuf::from("/home/alice"));
        let d = dossier_appelant(0, Some("1000"), maison).unwrap();
        assert!(
            d.starts_with("/home/alice") && d.ends_with("vanguard"),
            "{}",
            d.display()
        );
        assert_eq!(dossier_appelant(1000, Some("1000"), maison), None, "pas en root");
        assert_eq!(dossier_appelant(0, None, maison), None, "root lui-même");
        assert_eq!(dossier_appelant(0, Some("0"), maison), None);
        assert_eq!(dossier_appelant(0, Some("alice"), maison), None);
        assert_eq!(dossier_appelant(0, Some("1001"), maison), None, "compte inconnu");
        assert_eq!(
            dossier_appelant(0, Some("1000"), |_| Some(PathBuf::from("relatif"))),
            None
        );
        // La vraie base des comptes : le compte qui lance les tests y est (root dans « unshare -rn »).
        // SAFETY: getuid ne prend aucun argument et ne touche aucune mémoire.
        let moi = unsafe { libc::getuid() };
        assert!(dossier_personnel_de(moi).is_some_and(|d| d.is_absolute()));
    }

    /// Le bilan : toujours un constat, d'information quand elle est coupée, jamais une alerte ; la note reste la même.
    #[test]
    fn au_bilan_une_information_sans_effet_sur_la_note() {
        let c = Coupure {
            depuis: MIDI,
            jusqu_a: Some(MIDI + 3600),
        };
        let coupee = constat_de(&Etat::Coupee(c), MIDI);
        let en_marche = constat_de(&Etat::EnMarche, MIDI);
        let illisible = constat_de(&Etat::Illisible("x".into()), MIDI);
        for k in [&coupee, &en_marche, &illisible] {
            assert!(k.verifie);
            assert!(k.probleme.is_none_or(|n| n == Niveau::Info), "{}", k.message);
            assert_eq!(k.probleme.map_or(0, Niveau::penalite), 0);
            assert!(k.correctif.is_none());
        }
        assert_eq!(coupee.probleme, Some(Niveau::Info));
        assert!(coupee.message.contains("temps-reel oui") || coupee.message.contains("real-time yes"));
        assert!(en_marche.probleme.is_none());
        assert_eq!(constat_de(&Etat::Echue(c), MIDI + 3600).probleme, None);
    }

    /// Chaque écran qui dit la coupure dit son échéance ; la surveillance qu'on active dit qu'aucune passe ne se fera.
    #[test]
    fn phrases_de_chaque_ecran() {
        let c = Coupure {
            depuis: MIDI,
            jusqu_a: None,
        };
        for ou in [Ou::Blocage, Ou::Sortantes, Ou::Surveillance] {
            assert!(phrase_pour(ou, &c, MIDI).contains(tr!("jusqu'à reprise", "until turned back on")));
        }
        let s = phrase_pour(Ou::Surveillance, &c, MIDI);
        assert!(
            s.contains(tr!("aucune passe", "no run")) && s.contains(tr!("temps-reel oui", "real-time yes")),
            "{s}"
        );
    }

    /// Les mots de « --pendant », et ce que montre Paramètres.
    #[test]
    fn durees_et_valeurs() {
        assert_eq!(Duree::depuis_mot("1h"), Some(Duree::UneHeure));
        assert_eq!(Duree::depuis_mot("4 H"), Some(Duree::QuatreHeures));
        assert_eq!(Duree::depuis_mot("4"), Some(Duree::QuatreHeures));
        assert_eq!(Duree::depuis_mot("2h"), None);
        assert_eq!(Duree::depuis_mot("toujours"), None);
        for d in Duree::TOUTES {
            assert_ne!(d.libelle(), "");
            assert!(d.secondes().is_none_or(|s| s <= Duree::PLUS_LONGUE));
        }
        let c = Coupure {
            depuis: MIDI,
            jusqu_a: None,
        };
        let v = valeur_de(&Etat::Coupee(c), MIDI);
        assert!(v.starts_with(&format!("{} (", tr!("non", "no"))), "{v}");
        assert!(largeur_affichee(&v) <= 33, "{v}");
        let c = Coupure {
            depuis: MIDI,
            jusqu_a: Some(MIDI + 4 * 3600),
        };
        assert!(largeur_affichee(&valeur_de(&Etat::Coupee(c), MIDI)) <= 33);
        assert_eq!(valeur_de(&Etat::EnMarche, MIDI), tr!("oui", "yes"));
        assert_eq!(valeur_de(&Etat::Echue(c), MIDI + 4 * 3600), tr!("oui", "yes"));
    }

    /// La liste de ce qui s'arrête dit l'état de chacun, et ce qui ne change pas : Defender, le pare-feu, l'UAC et les
    /// blocages déjà faits.
    #[test]
    fn liste_de_ce_qui_s_arrete() {
        let l = ce_qui_s_arrete(true, false).join(" ");
        assert!(l.contains("Defender") && l.contains("UAC"), "{l}");
        assert!(
            l.contains(tr!("vanguard blocage annuler", "vanguard blocking undo")),
            "{l}"
        );
        assert_ne!(ce_qui_s_arrete(true, true), ce_qui_s_arrete(false, false));
    }
}
