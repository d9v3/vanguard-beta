//! Historique des bilans complets : ce qui a changé depuis le dernier (notes, problèmes nouveaux ou réglés) et la
//! courbe des notes dans le rapport HTML. Gardé sur cet ordinateur : ce détail ne voyage pas avec la clé, seul un
//! résumé y va (« Mes ordinateurs », `ordinateurs`).
//!
//! Chaque bilan porte son empreinte BLAKE3 et celle du précédent : une chaîne. Un historique réécrit après coup (un
//! problème effacé, une note gonflée, un bilan retiré du milieu) ne colle plus, et le bilan le dit. La chaîne commence
//! au premier bilan qui a une empreinte (les anciens n'en ont pas) ; le premier bilan gardé peut pointer vers un bilan
//! que la rotation a retiré, ce n'est pas une falsification. Barrière, pas coffre : qui réécrit tout le fichier peut
//! aussi retirer toutes les empreintes.
//!
//! Deux empreintes par bilan depuis les clés des problèmes (`Constat::cle`) : la première, calculée exactement comme
//! avant, qu'une version plus ancienne de Vanguard sait encore vérifier ; la seconde (`empreinte_v2`) couvre en plus
//! les clés et les notes de l'audit du réseau, et se chaîne à part. Une clé hors de toute empreinte permettrait de
//! masquer un problème en réécrivant historique.json sans rompre la chaîne : une clé n'est donc crue que si la
//! seconde empreinte de son bilan colle ; sinon la comparaison retombe sur le texte.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::audit::AuditReseau;
use crate::machine::Audit;
use crate::reseau::Rapport;
use crate::risk::Niveau;
use crate::ui::*;

/// Nombre de bilans gardés.
const GARDES: usize = 200;
/// Au-delà, ce n'est pas l'historique de Vanguard (200 bilans font quelques Mio) : il n'est pas chargé.
const HISTORIQUE_MAX: u64 = 64 << 20;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct Bilan {
    /// « AAAA-MM-JJ HH:MM ».
    pub date: String,
    /// Note de la machine, quand l'audit était fiable.
    pub machine: Option<u32>,
    pub reseau: Option<u32>,
    /// Réseau noté (adresse du réseau) : deux réseaux différents ne se comparent pas.
    #[serde(default)]
    pub nom_reseau: Option<String>,
    /// Problèmes moyens ou plus graves, « catégorie : message ».
    #[serde(default)]
    pub problemes: Vec<String>,
    /// Les notes de l'audit du réseau par domaine (nom interne → note), hors de l'empreinte : les bilans d'avant
    /// n'en ont pas et ne doivent pas devenir « rompus ».
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<BTreeMap<String, u32>>,
    /// Empreinte BLAKE3 de ce bilan (`empreinte_de`), et celle du bilan précédent : la chaîne.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empreinte: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedent: Option<String>,
    /// La clé de chaque problème (`Constat::cle`), dans l'ordre de `problemes` ; `None` pour une règle qui ne pose
    /// pas encore d'objet. Vide pour les bilans d'avant les clés. Couvertes par `empreinte_v2`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cles: Vec<Option<String>>,
    /// La seconde empreinte (`empreinte_v2_de`), et celle du bilan précédent : la seconde chaîne. Une version plus
    /// ancienne, qui réécrit tout le fichier, les retire de tous les bilans d'un coup : la chaîne repart alors au
    /// bilan suivant, et les clés retirées avec elles ne servent plus.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub empreinte_v2: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precedent_v2: Option<String>,
}

impl Bilan {
    /// La note de l'audit du réseau : la plus basse des six domaines, seulement quand les six en ont une.
    pub fn note_audit(&self) -> Option<u32> {
        let notes = self.audit.as_ref()?;
        (notes.len() == crate::audit::Domaine::TOUS.len())
            .then(|| notes.values().copied().min())
            .flatten()
    }
}

/// L'empreinte d'un bilan : ses champs dans un ordre fixe, y compris l'empreinte du précédent (jamais les notes de
/// l'audit du réseau, un champ arrivé après les premiers bilans chaînés).
fn empreinte_de(b: &Bilan) -> String {
    let canon = serde_json::to_string(&(&b.date, b.machine, b.reseau, &b.nom_reseau, &b.problemes, &b.precedent))
        .unwrap_or_default();
    blake3::hash(canon.as_bytes()).to_hex().to_string()
}

/// La seconde empreinte d'un bilan : tout ce que couvre la première, plus les clés des problèmes, les notes de
/// l'audit du réseau et la seconde empreinte du précédent. Une autre clé de dérivation que les sceaux : une empreinte
/// ne vaut jamais pour un autre usage.
fn empreinte_v2_de(b: &Bilan) -> String {
    let canon = serde_json::to_string(&(
        &b.date,
        b.machine,
        b.reseau,
        &b.nom_reseau,
        &b.problemes,
        &b.precedent,
        &b.cles,
        &b.audit,
        &b.precedent_v2,
    ))
    .unwrap_or_default();
    let mut h = blake3::Hasher::new_derive_key("vanguard bilan 2");
    h.update(canon.as_bytes());
    h.finalize().to_hex().to_string()
}

impl Bilan {
    /// La clé du problème `i`, seulement si la seconde empreinte du bilan la couvre : une clé ajoutée ou changée à
    /// la main ne fait jamais taire un problème.
    fn cle_crue(&self, i: usize) -> Option<&str> {
        if self.empreinte_v2.as_deref() != Some(empreinte_v2_de(self).as_str()) {
            return None;
        }
        self.cles.get(i)?.as_deref()
    }
}

/// L'état de la chaîne des bilans.
#[derive(Debug, PartialEq, Eq)]
pub enum Chaine {
    /// `chaines` bilans se suivent sans trou (0 : aucun bilan n'a encore d'empreinte).
    Intacte { chaines: usize },
    /// Le bilan `indice` ne colle pas : son contenu ne correspond plus à son empreinte, ou il ne suit plus le précédent.
    Rompue { indice: usize, date: String, contenu: bool },
    /// La première chaîne tient, mais le bilan `indice` n'a pas la seconde empreinte alors qu'un bilan d'avant
    /// l'avait (ou porte des clés sans elle) : écrit par une version plus ancienne, ou à la main. Ni sain ni
    /// falsifié : non vérifié, et ses clés ne servent pas.
    NonVerifiee { indice: usize, date: String },
}

pub fn verifier_chaine(tous: &[Bilan]) -> Chaine {
    let mut chaines = 0usize;
    let mut precedent: Option<&Bilan> = None;
    for (indice, b) in tous.iter().enumerate() {
        let rompue = |contenu| Chaine::Rompue {
            indice,
            date: b.date.clone(),
            contenu,
        };
        match &b.empreinte {
            Some(e) => {
                if *e != empreinte_de(b) {
                    return rompue(true);
                }
                // Un maillon suit le précédent quand celui-ci est chaîné ; le premier bilan gardé peut pointer vers un
                // bilan retiré par la rotation.
                if let Some(pe) = precedent.and_then(|p| p.empreinte.as_deref())
                    && b.precedent.as_deref() != Some(pe)
                {
                    return rompue(false);
                }
                chaines = chaines.saturating_add(1);
            }
            // Un bilan sans empreinte après des bilans chaînés : ajouté à la main.
            None if precedent.is_some_and(|p| p.empreinte.is_some()) => return rompue(true),
            None => {}
        }
        precedent = Some(b);
    }
    verifier_v2(tous).unwrap_or(Chaine::Intacte { chaines })
}

/// La seconde chaîne, une fois la première tenue : `None` si elle tient aussi.
fn verifier_v2(tous: &[Bilan]) -> Option<Chaine> {
    let mut non_verifiee = None;
    let mut deja_v2 = false;
    for (indice, b) in tous.iter().enumerate() {
        let date = || b.date.clone();
        let Some(e) = &b.empreinte_v2 else {
            if (deja_v2 || !b.cles.is_empty()) && non_verifiee.is_none() {
                non_verifiee = Some(Chaine::NonVerifiee { indice, date: date() });
            }
            continue;
        };
        if *e != empreinte_v2_de(b) {
            return Some(Chaine::Rompue {
                indice,
                date: date(),
                contenu: true,
            });
        }
        // Le premier bilan gardé peut pointer vers un bilan retiré par la rotation ; après lui, la seconde chaîne
        // suit celle du précédent, ou repart (aucune) si le précédent n'en avait pas.
        if indice
            .checked_sub(1)
            .and_then(|k| tous.get(k))
            .is_some_and(|precedent| b.precedent_v2 != precedent.empreinte_v2)
        {
            return Some(Chaine::Rompue {
                indice,
                date: date(),
                contenu: false,
            });
        }
        deja_v2 = true;
    }
    non_verifiee
}

/// Au bilan : rien tant que la chaîne tient.
pub fn constat() -> Option<crate::machine::Constat> {
    constat_dans(&fichier())
}

/// `constat` de l'historique `chemin` : illisible ou rompu d'abord ; sinon son verrou gardé en ce moment par un autre
/// (`verrou_tenu_maintenant` : ce bilan-ci, qui s'enregistre après l'affichage, le dit lui-même ; passe 4, P4-H1) ;
/// sinon un refus d'avant, dit au passé avec sa raison (P4-H2), retenu par ce processus.
fn constat_dans(chemin: &std::path::Path) -> Option<crate::machine::Constat> {
    let dossier = chemin.parent();
    let avant = dossier.and_then(refus_retenu);
    constat_de(lire_de(chemin)).or_else(|| {
        if dossier.is_some_and(verrou_tenu_maintenant) {
            Some(constat_verrou_tenu())
        } else {
            avant.map(|r| constat_bilan_perdu(&r))
        }
    })
}

/// Les dossiers dont le verrou de l'historique a été refusé à ce processus, avec la raison du refus, et pas rendu
/// depuis : le dernier bilan n'y a pas été enregistré (passe 4, H1). Un verrou gardé au-delà de l'attente, ou
/// inutilisable pour une autre raison que son remplacement (que le constat des verrous du sceau dit déjà ; P4-H4).
static TENUS: std::sync::Mutex<BTreeMap<PathBuf, String>> = std::sync::Mutex::new(BTreeMap::new());

fn tenus() -> std::sync::MutexGuard<'static, BTreeMap<PathBuf, String>> {
    TENUS.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn refus_retenu(dossier: &std::path::Path) -> Option<String> {
    tenus().get(dossier).cloned()
}

/// L'attente de la sonde du verrou au bilan : un enregistrement ordinaire le garde bien moins longtemps ; au-delà,
/// celui qui le garde est figé ou n'est pas un Vanguard.
const SONDE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_millis(100)
} else {
    std::time::Duration::from_secs(2)
};

/// Le verrou de l'historique est-il gardé en ce moment par un autre, au-delà de `SONDE` ? Pris partagé (rien ne s'écrit
/// pendant la sonde, aucun verrou n'est créé là où il n'existe pas). Pas sondé pour l'aperçu d'une correction (sans
/// attente, et rien n'y est enregistré) : seul le refus retenu s'y dit.
fn verrou_tenu_maintenant(dossier: &std::path::Path) -> bool {
    if crate::autotest::lecture_seule::sans_attente()
        || !std::fs::symlink_metadata(dossier.join(VERROU)).is_ok_and(|m| m.file_type().is_file())
    {
        return false;
    }
    matches!(
        crate::socle::Verrou::prendre(dossier, VERROU, true, SONDE),
        Err(crate::socle::SansVerrou::Occupe)
    )
}

/// Passe 4, H1 et P4-H1 : le verrou de l'historique gardé en ce moment, vu au bilan même. Sans ce constat, l'historique
/// cessait de s'écrire sans rien dire ailleurs que sur la sortie d'erreur, et le bilan qui échouait ne le disait pas.
/// Un verrou remplacé (dossier, lien, tube, droits retirés) se dit, lui, au constat des verrous de l'état (`sceau`).
fn constat_verrou_tenu() -> crate::machine::Constat {
    crate::machine::alerte(
        "Historique",
        Niveau::Moyen,
        tr!(
            "Ce bilan risque de ne pas être enregistré dans l'historique : son verrou (historique.verrou) est gardé en ce moment par un autre programme (un Vanguard figé, ou un autre programme du compte) ; le bilan ne s'enregistre que si le verrou est rendu dans les 30 secondes.",
            "This check may not be saved to the history: its lock (historique.verrou) is being kept right now by another program (a frozen Vanguard, or another program of the account); the check is saved only if the lock is released within 30 seconds."
        ),
    )
    .manuel(
        tr!(
            "Fermez les autres Vanguard ouverts, puis relancez le bilan ; si cela reste, regardez ce qui tourne sous votre compte",
            "Close the other open Vanguard windows, then run the check-up again; if it stays, look at what runs under your account"
        ),
        &[],
    )
}

/// Passe 4, P4-H2 : un bilan d'avant non enregistré, dit au passé avec la raison du refus (le verrou a pu être rendu
/// depuis : rien n'est dit au présent sans être revu).
fn constat_bilan_perdu(raison: &str) -> crate::machine::Constat {
    crate::machine::alerte(
        "Historique",
        Niveau::Moyen,
        trf!(
            "Un bilan précédent n'a pas été enregistré dans l'historique : {raison}.",
            "An earlier check was not saved to the history: {raison}."
        ),
    )
    .manuel(
        tr!(
            "Fermez les autres Vanguard ouverts, puis relancez le bilan ; si cela reste, regardez ce qui tourne sous votre compte",
            "Close the other open Vanguard windows, then run the check-up again; if it stays, look at what runs under your account"
        ),
        &[],
    )
}

/// `constat` d'un historique lu `lu`. Un historique qui ne se lit pas (lien, tube ou dossier à sa place, droit refusé,
/// contenu abîmé) est dit « non vérifié », jamais pris pour un historique vide qui tient.
fn constat_de(lu: Result<Vec<Bilan>, String>) -> Option<crate::machine::Constat> {
    let tous = match lu {
        Ok(tous) => tous,
        Err(e) => {
            return Some(crate::machine::impossible_par(
                "Historique",
                crate::modele::Raison::Illisible(e),
                tr!(
                    "L'historique des bilans ne se lit pas : sa chaîne n'est pas vérifiée. Un fichier abîmé est mis de côté au prochain bilan ; autre chose à sa place (un lien, un dossier, un fichier qu'on ne peut pas lire) est laissé tel quel, et aucun bilan n'y est enregistré tant qu'il y est.",
                    "The check history cannot be read: its chain is not checked. A damaged file is set aside at the next check; anything else in its place (a link, a folder, a file that cannot be read) is left as is, and no check is saved to it while it is there."
                ),
            ));
        }
    };
    match verifier_chaine(&tous) {
        Chaine::Intacte { .. } => None,
        Chaine::NonVerifiee { date, .. } => Some(crate::machine::impossible_par(
            "Historique",
            crate::modele::Raison::VersionAncienne,
            trf!(
                "Le bilan du {date} n'a pas la seconde empreinte de l'historique : écrit par une version plus ancienne de Vanguard, ou à la main. Ses clés ne sont pas crues ; il est comparé sur son texte.",
                "The check of {date} lacks the history's second checksum: written by an older version of Vanguard, or by hand. Its keys are not trusted; it is compared on its text."
            ),
        )),
        Chaine::Rompue { date, contenu, .. } => Some(
            crate::machine::alerte(
                "Historique",
                Niveau::Eleve,
                if contenu {
                    trf!(
                        "L'historique des bilans a été modifié après coup : le bilan du {date} ne correspond plus à son empreinte. Quelqu'un, ou un programme, a réécrit historique.json dans le dossier de Vanguard.",
                        "The check history was modified afterwards: the check of {date} no longer matches its checksum. Someone, or a program, rewrote historique.json in Vanguard's folder."
                    )
                } else {
                    trf!(
                        "L'historique des bilans a été modifié après coup : le bilan du {date} ne suit plus le précédent (un bilan a été retiré ou inséré au milieu).",
                        "The check history was modified afterwards: the check of {date} no longer follows the previous one (a check was removed or inserted in the middle)."
                    )
                },
            )
            .manuel(
                tr!(
                    "Regardez ce qui a accès au dossier de Vanguard (menu Protection › Intégrité, Qui parle à Internet ?) ; la chaîne repart au prochain bilan",
                    "Look at what has access to Vanguard's folder (Protection menu › Integrity, Who talks to the Internet?); the chain restarts at the next check"
                ),
                &[],
            ),
        ),
    }
}

/// Une ligne pour le rapport : la chaîne et sa longueur, ou la rupture.
pub fn etat_chaine() -> Option<String> {
    etat_chaine_de(lire())
}

/// `etat_chaine` d'un historique lu `lu` : s'il ne se lit pas, la ligne le dit (`constat_de`).
fn etat_chaine_de(lu: Result<Vec<Bilan>, String>) -> Option<String> {
    let tous = match lu {
        Ok(tous) => tous,
        Err(e) => {
            return Some(trf!(
                "⚠ Historique non vérifié : il ne se lit pas ({e}) ; aucun bilan n'y est enregistré tant qu'il en est ainsi.",
                "⚠ History not checked: it cannot be read ({e}); no check is saved to it while this lasts."
            ));
        }
    };
    match verifier_chaine(&tous) {
        Chaine::Intacte { chaines: 0 } => None,
        Chaine::Intacte { chaines } => Some(trf!(
            "Historique intact : {chaines} bilans chaînés par leur empreinte.",
            "History intact: {chaines} checks chained by their checksum."
        )),
        Chaine::Rompue { date, .. } => Some(trf!(
            "⚠ Historique modifié après coup : le bilan du {date} ne colle plus à la chaîne.",
            "⚠ History modified afterwards: the check of {date} no longer fits the chain."
        )),
        Chaine::NonVerifiee { date, .. } => Some(trf!(
            "Historique non vérifié : le bilan du {date} n'a pas la seconde empreinte (version plus ancienne, ou à la main).",
            "History not checked: the check of {date} lacks the second checksum (older version, or by hand)."
        )),
    }
}

fn fichier() -> PathBuf {
    crate::socle::dossier_local().join("historique.json")
}

/// L'historique, vide s'il ne se lit pas : seulement là où « non lu » et « aucun bilan » mènent au même geste (la
/// courbe du rapport, que suit la ligne de `etat_chaine`). Un écran qui dit « aucun bilan » lit `charger_lu`.
pub fn charger() -> Vec<Bilan> {
    lire().unwrap_or_default()
}

/// L'historique ; `None` s'il existe mais ne se lit pas (passe 3, historique N4 : jamais montré comme vide). La
/// raison n'est pas rendue : le prochain bilan la dit, par la ligne ⚠ de `etat_chaine`.
pub fn charger_lu() -> Option<Vec<Bilan>> {
    lire().ok()
}

/// L'historique tel qu'il est écrit, lu sans rien écrire (ni copie mise de côté) : pour la porte de lecture des
/// assistants d'IA (`porte_mcp`). `None` s'il existe mais ne se lit pas : la porte le dit « illisible », sans en
/// montrer la raison, qui peut porter un chemin.
pub(crate) fn lire_sans_ecrire_dans(dossier: &std::path::Path) -> Option<Vec<Bilan>> {
    lire_de(&dossier.join("historique.json")).ok()
}

/// L'historique tel qu'il est écrit ; `Err` s'il existe mais ne se lit pas.
fn lire() -> Result<Vec<Bilan>, String> {
    lire_de(&fichier())
}

/// Celui d'un fichier donné : les tests ont chacun le leur, sans quoi l'un réécrirait celui qu'un autre lit (le menu,
/// le rapport ; sous Windows, un fichier ouvert ne se remplace pas).
fn lire_de(chemin: &std::path::Path) -> Result<Vec<Bilan>, String> {
    lire_de_borne(chemin, HISTORIQUE_MAX).map_err(|e| e.to_string())
}

/// `lire_de`, borné à `max` octets (`HISTORIQUE_MAX` hors des essais).
fn lire_de_borne(chemin: &std::path::Path, max: u64) -> std::io::Result<Vec<Bilan>> {
    lire_de_borne_vu(chemin, max).1
}

/// `lire_de_borne`, avec ce que le système dit du fichier ouvert et lu (fstat), quand il s'est ouvert : c'est lui,
/// pas ce qui porte son nom plus tard, que `mettre_de_cote` met de côté s'il est abîmé (passe 3, historique N1).
fn lire_de_borne_vu(chemin: &std::path::Path, max: u64) -> (Option<std::fs::Metadata>, std::io::Result<Vec<Bilan>>) {
    use std::io::Read as _;
    // Un simple fichier, borné : un tube ou un lien vers /dev/zero à sa place ne fige ni ne remplit rien. Ouvert par
    // `ouvrir_ordinaire`, qui garde le genre de l'erreur (`lire_texte_ordinaire` les ferait tous « InvalidData ») :
    // un droit refusé ne se confond pas avec un historique abîmé (`a_mettre_de_cote`). Sans borne à l'ouverture,
    // pour garder ce qu'il est même trop gros : la borne se juge juste après.
    let (f, vu) = match crate::socle::ouvrir_ordinaire(chemin, u64::MAX) {
        Ok(ouvert) => ouvert,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (None, Ok(Vec::new())),
        Err(e) => return (None, Err(e)),
    };
    let trop_gros = || {
        std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            trf!("plus de {} Kio", "over {} KiB", max >> 10),
        )
    };
    if vu.len() > max {
        return (Some(vu), Err(trop_gros()));
    }
    let mut octets = Vec::new();
    if let Err(e) = f.take(max.saturating_add(1)).read_to_end(&mut octets) {
        return (Some(vu), Err(e));
    }
    if u64::try_from(octets.len()).unwrap_or(u64::MAX) > max {
        return (Some(vu), Err(trop_gros()));
    }
    let lu = String::from_utf8(octets)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        .and_then(|texte| {
            serde_json::from_str(texte.trim_start_matches('\u{feff}'))
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        });
    (Some(vu), lu)
}

fn bilan(audit: Option<&Audit>, reseau: Option<&Rapport>, audit_reseau: Option<&AuditReseau>) -> Bilan {
    let graves: Vec<&crate::machine::Constat> = audit.map_or_default(|a| {
        a.constats
            .iter()
            .filter(|c| c.probleme.is_some_and(|n| n >= Niveau::Moyen))
            .collect()
    });
    let cles: Vec<Option<String>> = graves.iter().map(|c| c.cle().map(|k| k.to_string())).collect();
    Bilan {
        date: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
        machine: audit.filter(|a| a.fiable()).map(|a| a.score),
        reseau: reseau.map(|r| r.score_global),
        nom_reseau: reseau.map(|r| r.reseau.clone()),
        problemes: graves
            .iter()
            .map(|c| format!("{} : {}", c.categorie, c.message))
            .collect(),
        audit: audit_reseau.map(AuditReseau::notes),
        // Aucune clé : rien à écrire, le bilan garde la forme d'avant.
        cles: if cles.iter().all(Option::is_none) {
            Vec::new()
        } else {
            cles
        },
        ..Bilan::default()
    }
}

/// Ajoute ce bilan à l'historique ; rend le précédent, s'il y en a un.
pub fn enregistrer(audit: Option<&Audit>, reseau: Option<&Rapport>) -> (Option<Bilan>, Bilan) {
    enregistrer_complet(audit, reseau, None)
}

/// Comme `enregistrer`, avec l'audit du réseau par domaine du bilan complet.
pub fn enregistrer_complet(
    audit: Option<&Audit>,
    reseau: Option<&Rapport>,
    audit_reseau: Option<&AuditReseau>,
) -> (Option<Bilan>, Bilan) {
    enregistrer_dans(&fichier(), bilan(audit, reseau, audit_reseau))
}

pub(crate) fn enregistrer_dans(chemin: &std::path::Path, nouveau: Bilan) -> (Option<Bilan>, Bilan) {
    enregistrer_dans_borne(chemin, nouveau, HISTORIQUE_MAX)
}

fn enregistrer_dans_borne(chemin: &std::path::Path, nouveau: Bilan, max: u64) -> (Option<Bilan>, Bilan) {
    enregistrer_en_attendant(chemin, nouveau, max, crate::socle::ATTENTE_ECRITURE)
}

/// `enregistrer_dans`, l'historique borné à `max` octets : la borne même du lecteur (`lire_de_borne`), pour que
/// l'écrivain ne pose jamais un fichier que le lecteur refuse. Les essais la prennent petite. Le verrou s'attend au plus
/// `attente` (bornée : `socle::ATTENTE_ECRITURE` hors essais).
fn enregistrer_en_attendant(
    chemin: &std::path::Path,
    nouveau: Bilan,
    max: u64,
    attente: std::time::Duration,
) -> (Option<Bilan>, Bilan) {
    let dossier = chemin.parent().unwrap_or(std::path::Path::new("."));
    enregistrer_selon(chemin, nouveau, max, attente, crate::socle::ecriture_sure(dossier))
}

/// `enregistrer_en_attendant`, `sure` disant si Vanguard peut écrire dans le dossier (`socle::ecriture_sure`), à part
/// pour les essais (sous `cfg(test)`, il l'est toujours).
fn enregistrer_selon(
    chemin: &std::path::Path,
    nouveau: Bilan,
    max: u64,
    attente: std::time::Duration,
    sure: bool,
) -> (Option<Bilan>, Bilan) {
    // Passe 3, historique N2 : lire, mettre de côté et écrire sous un verrou. Sans lui, deux Vanguard (la minuterie
    // et la fenêtre) qui trouvent le même historique abîmé pouvaient mettre de côté, puis retirer par son nom,
    // l'historique neuf que l'autre venait d'écrire ; ou perdre un bilan en écrivant en même temps. En administrateur
    // dans le dossier d'un compte, aucun verrou n'y est créé (il bloquerait ensuite chaque bilan du compte), et rien
    // n'y est écrit, comme le journal et les sceaux (H2) : sans verrou, l'écriture pouvait croiser celle du compte et
    // perdre un bilan, et un historique posé par root ne se relisait plus sous le compte.
    let dossier = chemin.parent().unwrap_or(std::path::Path::new("."));
    if !sure {
        let e = crate::sceau::dossier_d_un_autre();
        tre!(
            "Attention : bilan non enregistré dans l'historique ({e}).",
            "Warning: check not saved to the history ({e})."
        );
        return rendu_seul(nouveau);
    }
    let _verrou = {
        match crate::socle::Verrou::prendre(dossier, VERROU, false, attente) {
            Ok(v) => {
                tenus().remove(dossier);
                v
            }
            Err(e) => {
                let retenu =
                    matches!(e, crate::socle::SansVerrou::Occupe) || !crate::socle::verrou_remplace(dossier, VERROU);
                let e = e.erreur(VERROU);
                if retenu {
                    tenus().insert(dossier.to_path_buf(), e.to_string());
                }
                tre!(
                    "Attention : bilan non enregistré dans l'historique ({e}).",
                    "Warning: check not saved to the history ({e})."
                );
                return rendu_seul(nouveau);
            }
        }
    };
    enregistrer_sous_verrou(chemin, nouveau, max)
}

/// Le verrou de l'historique (`enregistrer_dans_borne`), à côté de lui.
pub(crate) const VERROU: &str = "historique.verrou";

/// `enregistrer_dans_borne`, le verrou tenu.
fn enregistrer_sous_verrou(chemin: &std::path::Path, mut nouveau: Bilan, max: u64) -> (Option<Bilan>, Bilan) {
    let (vu, lu) = lire_de_borne_vu(chemin, max);
    let mut tous = match lu {
        Ok(tous) => tous,
        // Un historique qu'on ne peut pas lire (droit refusé, erreur passagère) n'est pas abîmé : rien n'y est touché.
        Err(e) if !a_mettre_de_cote(&e) => {
            tre!(
                "Attention : historique des bilans illisible ({e}) : il est laissé tel quel et ce bilan n'y est pas enregistré.",
                "Warning: check history unreadable ({e}): it is left as is and this check is not saved to it."
            );
            return rendu_seul(nouveau);
        }
        Err(e) => match mettre_de_cote(chemin, vu.as_ref()) {
            // Jamais écraser un historique qu'on ne sait pas relire : il est mis de côté, intact et sans être relu
            // (il peut être trop gros pour l'être), avant le nouveau. « Copie gardée » seulement quand c'est fait.
            Ok(copie) => {
                tre!(
                    "Attention : historique des bilans illisible ({e}). Copie gardée : {}",
                    "Warning: check history unreadable ({e}). Copy kept: {}",
                    crate::ui::chemin_affichable(&copie)
                );
                Vec::new()
            }
            // Pas mis de côté : l'historique reste tel quel, ce bilan n'y est pas ajouté ; il est rendu quand même.
            Err(PasMisDeCote::Laisse(raison)) => {
                tre!(
                    "Attention : historique des bilans illisible ({e}), et il n'a pas pu être mis de côté ({raison}) : il est laissé tel quel et ce bilan n'y est pas enregistré.",
                    "Warning: check history unreadable ({e}), and it could not be set aside ({raison}): it is left as is and this check is not saved to it."
                );
                return rendu_seul(nouveau);
            }
            // Déplacé, mais le nom neuf n'a pas pu être vérifié : il est nommé, rien n'est écrit à la place.
            Err(PasMisDeCote::Deplace { copie, raison }) => {
                tre!(
                    "Attention : historique des bilans illisible ({e}) : déplacé sous {}, mais ce nom n'a pas pu être vérifié ({raison}) ; ce bilan n'est pas enregistré.",
                    "Warning: check history unreadable ({e}): moved to {}, but that name could not be checked ({raison}); this check is not saved.",
                    crate::ui::chemin_affichable(&copie)
                );
                return rendu_seul(nouveau);
            }
        },
    };
    let precedent = tous.last().cloned();
    nouveau.precedent = precedent.as_ref().and_then(|p| p.empreinte.clone());
    nouveau.empreinte = Some(empreinte_de(&nouveau));
    nouveau.precedent_v2 = precedent.as_ref().and_then(|p| p.empreinte_v2.clone());
    nouveau.empreinte_v2 = Some(empreinte_v2_de(&nouveau));
    tous.push(nouveau.clone());
    let surplus = tous.len().saturating_sub(GARDES);
    tous.drain(..surplus);
    match texte_borne(&mut tous, max) {
        Ok((texte, retires)) => {
            if avertir_du_retrait(retires) {
                tre!(
                    "Attention : historique des bilans plus gros que {} Mio : {retires} bilan(s) parmi les plus anciens retiré(s) pour qu'il reste lisible.",
                    "Warning: check history larger than {} MiB: {retires} of the oldest check(s) removed so that it stays readable.",
                    max >> 20
                );
            }
            // D'un bloc : une coupure pendant l'écriture laisse l'ancien historique ou le nouveau, jamais un fichier
            // tronqué.
            if let Err(e) = crate::socle::ecrire_atomique(chemin, &texte) {
                tre!(
                    "Attention : bilan non enregistré dans l'historique ({e}).",
                    "Warning: check not saved to the history ({e})."
                );
            }
        }
        Err(()) => {
            tre!(
                "Attention : ce bilan seul dépasse {} Mio, la taille que l'historique peut relire : il n'y est pas enregistré, l'historique reste tel quel.",
                "Warning: this check alone exceeds {} MiB, the size the history can read back: it is not saved to it, the history is left as is.",
                max >> 20
            );
        }
    }
    (precedent, nouveau)
}

/// Un bilan qui n'entre pas dans l'historique, rendu quand même, avec ses empreintes.
fn rendu_seul(mut nouveau: Bilan) -> (Option<Bilan>, Bilan) {
    nouveau.empreinte = Some(empreinte_de(&nouveau));
    nouveau.empreinte_v2 = Some(empreinte_v2_de(&nouveau));
    (None, nouveau)
}

/// Une erreur de lecture qui dit l'historique abîmé (contenu invalide, trop gros, pas un simple fichier), seule à le
/// faire mettre de côté. Un droit refusé ou une erreur passagère ne dit rien du contenu : l'historique reste à sa
/// place.
fn a_mettre_de_cote(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::FileTooLarge
    )
}

/// Dire les bilans retirés pour la borne : seulement quand plus d'un part d'un coup. À la borne, chaque bilan en
/// fait partir un, le plus ancien, comme la rotation (`GARDES`) : le redire à chaque bilan n'apprend rien.
fn avertir_du_retrait(retires: usize) -> bool {
    retires > 1
}

/// Le texte de l'historique `tous`, au plus `max` octets : les plus vieux bilans retirés jusqu'à passer, comme la
/// rotation (`GARDES`) : le premier bilan gardé peut pointer vers un bilan retiré, la chaîne tient
/// (`verifier_chaine`). Rend le texte et le nombre de bilans retirés ; `Err` si le dernier seul dépasse, ou si un
/// bilan ne s'écrit pas : rien à écrire.
fn texte_borne(tous: &mut Vec<Bilan>, max: u64) -> Result<(String, usize), ()> {
    // Chaque bilan écrit une seule fois : « [a,b,c] » fait 2 octets, plus chaque bilan, plus une virgule entre deux.
    let textes: Vec<String> = tous
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<_, _>>()
        .map_err(|_| ())?;
    let tailles: Vec<u64> = textes
        .iter()
        .map(|t| u64::try_from(t.len()).unwrap_or(u64::MAX))
        .collect();
    let mut total = tailles
        .iter()
        .fold(2u64, |t, n| t.saturating_add(*n).saturating_add(1))
        .saturating_sub(1);
    let mut retires = 0usize;
    for n in &tailles {
        if total <= max || retires.saturating_add(1) >= tailles.len() {
            break;
        }
        total = total.saturating_sub(n.saturating_add(1));
        retires = retires.saturating_add(1);
    }
    tous.drain(..retires);
    let texte = format!("[{}]", textes.get(retires..).unwrap_or_default().join(","));
    if u64::try_from(texte.len()).unwrap_or(u64::MAX) > max {
        return Err(());
    }
    Ok((texte, retires))
}

/// Pourquoi un historique n'a pas été mis de côté : laissé à sa place (`Laisse`), ou déplacé sous `copie` sans que ce
/// nom ait pu être vérifié (`Deplace`, à nommer : jamais « laissé tel quel » pour un fichier qui n'y est plus).
#[derive(Debug)]
enum PasMisDeCote {
    Laisse(std::io::Error),
    Deplace { copie: PathBuf, raison: std::io::Error },
}

/// Met de côté l'historique illisible `chemin` sans le relire : renommé sous un nom neuf
/// (« `historique.illisible-<date>-<hasard>.json` »), jamais par-dessus un fichier déjà là. Seulement le simple fichier
/// lu et jugé abîmé (`vu`, ce que fstat en a dit) : un historique sain posé à sa place depuis n'est pas touché ; un
/// lien n'est jamais suivi, un tube ou un dossier (qui ne s'ouvre pas : rien de `vu`) n'est pas déplacé. Rend le nom
/// de la copie, qui existe et est le fichier d'avant (même appareil, même numéro) ; sinon pourquoi, prêt à montrer
/// (`PasMisDeCote`).
fn mettre_de_cote(chemin: &std::path::Path, vu: Option<&std::fs::Metadata>) -> Result<PathBuf, PasMisDeCote> {
    let Some(avant) = vu else {
        return Err(PasMisDeCote::Laisse(std::io::Error::other(tr!(
            "ce n'est pas un simple fichier",
            "it is not a plain file"
        ))));
    };
    mettre_de_cote_comme(chemin, avant, true)
}

/// `mettre_de_cote`, le fichier regardé `avant` donné ; `lien` faux prend le renommage simple (des systèmes sans liens
/// durs) : les essais y passent.
fn mettre_de_cote_comme(
    chemin: &std::path::Path,
    avant: &std::fs::Metadata,
    lien: bool,
) -> Result<PathBuf, PasMisDeCote> {
    use PasMisDeCote::Laisse;
    if !avant.file_type().is_file() {
        return Err(Laisse(std::io::Error::other(tr!(
            "ce n'est pas un simple fichier",
            "it is not a plain file"
        ))));
    }
    let mut sel = [0u8; 8];
    getrandom::fill(&mut sel).map_err(|e| Laisse(std::io::Error::other(e.to_string())))?;
    let copie = chemin.with_extension(format!(
        "illisible-{}-{:016x}.json",
        chrono::Local::now().format("%Y%m%d-%H%M%S"),
        u64::from_le_bytes(sel)
    ));
    // Un second nom d'abord (link ne suit pas de lien et ne remplace rien), puis l'ancien nom retiré : un renommage
    // qui ne remplace jamais. Sans liens durs (FAT, certains partages), un renommage simple, le nom neuf vérifié
    // libre juste avant.
    let lie = if lien {
        std::fs::hard_link(chemin, &copie)
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    };
    match lie {
        Ok(()) => {
            if let Err(raison) = meme_fichier(avant, &copie) {
                // Lié à autre chose que le fichier regardé (remplacé entre-temps) : le second nom est retiré s'il
                // nomme encore ce qui est à `chemin` (rien ne se perd), sinon il est nommé.
                return Err(retirer_le_second_nom(chemin, &copie, raison));
            }
            if let Err(e) = std::fs::remove_file(chemin) {
                // Le second nom est le nôtre (vérifié) : retiré, l'historique reste seul à sa place.
                let _ = std::fs::remove_file(&copie);
                return Err(Laisse(e));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(Laisse(e)),
        Err(_) => {
            match std::fs::symlink_metadata(&copie) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => {
                    return Err(Laisse(std::io::Error::other(tr!(
                        "nom de copie déjà pris",
                        "copy name already taken"
                    ))));
                }
                Err(e) => return Err(Laisse(e)),
            }
            std::fs::rename(chemin, &copie).map_err(Laisse)?;
            // Renommé : l'historique n'est plus à sa place, quoi que dise la vérification.
            meme_fichier(avant, &copie).map_err(|raison| PasMisDeCote::Deplace {
                copie: copie.clone(),
                raison,
            })?;
        }
    }
    Ok(copie)
}

/// Le second nom `copie` d'un lien dur qui ne vise pas le fichier regardé : retiré seulement s'il nomme encore le même
/// fichier que `chemin` (qui le garde) ; sinon laissé et nommé.
fn retirer_le_second_nom(chemin: &std::path::Path, copie: &std::path::Path, raison: std::io::Error) -> PasMisDeCote {
    // Même entrée, quelle qu'elle soit (passe 3, historique N3) : un lien symbolique posé à la place reçoit lui-même
    // le second nom (link ne le suit pas) ; ce n'est pas un simple fichier, mais c'est bien lui, et il est retiré.
    let encore = match (std::fs::symlink_metadata(chemin), std::fs::symlink_metadata(copie)) {
        (Ok(a), Ok(b)) => meme_entree(&a, &b),
        _ => false,
    };
    if encore && std::fs::remove_file(copie).is_ok() {
        PasMisDeCote::Laisse(raison)
    } else {
        PasMisDeCote::Deplace {
            copie: copie.to_path_buf(),
            raison,
        }
    }
}

/// La copie `copie` est un simple fichier, et le fichier regardé `avant` : sous Unix même appareil et même numéro,
/// ailleurs même taille et même date de changement. Jamais « Copie gardée » pour un nom qui ne la porte pas.
fn meme_fichier(avant: &std::fs::Metadata, copie: &std::path::Path) -> std::io::Result<()> {
    let apres = std::fs::symlink_metadata(copie)?;
    if apres.file_type().is_file() && meme_entree(avant, &apres) {
        Ok(())
    } else {
        Err(std::io::Error::other(tr!(
            "la copie n'est pas le fichier d'avant",
            "the copy is not the previous file"
        )))
    }
}

/// `a` et `b` sont la même entrée : sous Unix même appareil et même numéro, ailleurs même genre, même taille et même
/// date de changement.
fn meme_entree(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        a.dev() == b.dev() && a.ino() == b.ino()
    }
    #[cfg(not(unix))]
    {
        a.file_type() == b.file_type() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
    }
}

/// Un problème sans ses nombres (« 3 mises à jour » et « 4 mises à jour » sont le même problème).
fn cle(probleme: &str) -> String {
    probleme
        .chars()
        .map(|c| if c.is_ascii_digit() { '#' } else { c })
        .collect()
}

/// Deux problèmes sont-ils le même ? Par leur clé quand les deux en ont une crue (changer de langue ou de tournure ne
/// fait rien), sinon par leur texte, l'une comme l'autre sans ses nombres : un bilan d'avant les clés se compare
/// encore au suivant, sans faire de tout un « nouveau » ; un logiciel dont la version change sans être à jour
/// (« perimes:chrome@150.0.1.2 » puis « @150.0.1.9 ») reste le même problème, pas un « réglé » suivi d'un
/// « nouveau ». L'apprentissage, lui, garde la clé exacte : déclarer normale une version ne tait pas la suivante.
fn meme_probleme(a: (&str, Option<&str>), b: (&str, Option<&str>)) -> bool {
    match (a.1, b.1) {
        (Some(x), Some(y)) => cle(x) == cle(y),
        _ => cle(a.0) == cle(b.0),
    }
}

/// (nouveaux, réglés) entre deux bilans.
fn differences<'a>(avant: &'a Bilan, apres: &'a Bilan) -> (Vec<&'a str>, Vec<&'a str>) {
    let lus = |b: &'a Bilan| -> Vec<(&'a str, Option<&'a str>)> {
        b.problemes
            .iter()
            .enumerate()
            .map(|(i, p)| (p.as_str(), b.cle_crue(i)))
            .collect()
    };
    let (av, ap) = (lus(avant), lus(apres));
    let absents = |de: &[(&'a str, Option<&'a str>)], dans: &[(&'a str, Option<&'a str>)]| -> Vec<&'a str> {
        de.iter()
            .filter(|p| !dans.iter().any(|q| meme_probleme(**p, *q)))
            .map(|p| p.0)
            .collect()
    };
    (absents(&ap, &av), absents(&av, &ap))
}

fn evolution(nom: &str, avant: Option<u32>, apres: Option<u32>) {
    let (Some(a), Some(b)) = (avant, apres) else { return };
    // Deux u32 en i64 : l'écart tient toujours.
    let ecart = i64::from(b).saturating_sub(i64::from(a));
    let signe = match ecart {
        e if e > 0 => format!("{VERT}+{e}{RESET}"),
        e if e < 0 => format!("{}{e}{RESET}", couleur(Niveau::Eleve)),
        _ => tr!("sans changement", "unchanged").to_string(),
    };
    println!("  {nom:<14} {a} → {b} ({signe})");
}

pub fn afficher_changements(avant: &Bilan, apres: &Bilan) {
    titre(&trf!(
        "Depuis le dernier bilan ({})",
        "Since the last check ({})",
        avant.date
    ));
    evolution(tr!("Cet ordinateur", "This computer"), avant.machine, apres.machine);
    if avant.nom_reseau == apres.nom_reseau {
        evolution(tr!("Réseau", "Network"), avant.reseau, apres.reseau);
        evolution(
            tr!("Audit du réseau", "Network audit"),
            avant.note_audit(),
            apres.note_audit(),
        );
    }
    let (nouveaux, regles) = differences(avant, apres);
    let traduire = |p: &str| match p.split_once(" : ") {
        Some((cat, msg)) => format!("{} : {msg}", crate::langue::categorie(cat)),
        None => p.to_string(),
    };
    for p in regles.iter().take(8) {
        trp!(
            "  {VERT}✔ réglé{RESET}   {}",
            "  {VERT}✔ fixed{RESET}   {}",
            traduire(p)
        );
    }
    for p in nouveaux.iter().take(8) {
        trp!(
            "  {}✖ nouveau{RESET} {}",
            "  {}✖ new{RESET}     {}",
            couleur(Niveau::Moyen),
            traduire(p)
        );
    }
    if nouveaux.is_empty() && regles.is_empty() {
        trp!(
            "  {GRIS}Aucun problème nouveau ni réglé.{RESET}",
            "  {GRIS}No new or fixed problem.{RESET}"
        );
    }
}

/// Courbe des notes (SVG intégré, couleurs du thème clair ou sombre) ; `None` s'il y a moins de deux bilans.
/// Le réseau et son audit ne sont tracés que pour le réseau du dernier bilan.
pub fn courbe(historique: &[Bilan]) -> Option<String> {
    let derniers = historique.get(historique.len().saturating_sub(30)..)?;
    if derniers.len() < 2 {
        return None;
    }
    let reseau_actuel = derniers.last()?.nom_reseau.clone();
    let (largeur, hauteur, marge) = (640.0, 200.0, 28.0);
    // Au plus 30 relevés : le compte tient dans un u32, puis f64 sans perte.
    let pas = (largeur - 2.0 * marge) / f64::from(u32::try_from(derniers.len().saturating_sub(1)).unwrap_or(u32::MAX));
    // Échelle à partir de la dizaine sous la note la plus basse (au plus 40) : le haut de l'échelle reste lisible.
    let plus_basse = derniers
        .iter()
        .flat_map(|b| [b.machine, b.reseau, b.note_audit()])
        .flatten()
        .min()
        .unwrap_or(40);
    let bas = (plus_basse.min(40) / 10).saturating_mul(10);
    let y = |note: u32| {
        hauteur
            - marge
            - f64::from(note.saturating_sub(bas)) / f64::from(100u32.saturating_sub(bas)) * (hauteur - 2.0 * marge)
    };
    let mut svg = format!(
        "<svg viewBox=\"0 0 {largeur} {hauteur}\" role=img aria-label=\"{}\" style=\"width:100%;height:auto\">",
        tr!("Évolution des notes", "Grade history")
    );
    // Seuils des lettres : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40.
    for (seuil, lettre) in [(90, "A"), (75, "B"), (60, "C"), (40, "D")]
        .into_iter()
        .filter(|(s, _)| *s >= bas)
    {
        let y0 = y(seuil);
        let _ = write!(
            svg,
            "<line x1={marge} x2={} y1={y0:.1} y2={y0:.1} style=\"stroke:var(--bord)\"/><text x=4 y={:.1} style=\"fill:var(--doux);font-size:11px\">{lettre}</text>",
            largeur - marge,
            y0 + 4.0
        );
    }
    let mut serie = |valeurs: Vec<Option<u32>>, couleur: &str, nom: &str| {
        let points: Vec<String> = valeurs
            .iter()
            .enumerate()
            .filter_map(|(i, v)| {
                let x = marge + f64::from(u32::try_from(i).unwrap_or(u32::MAX)) * pas;
                v.map(|n| format!("{x:.1},{:.1}", y(n)))
            })
            .collect();
        if points.is_empty() {
            return;
        }
        let _ = write!(
            svg,
            "<polyline points=\"{}\" style=\"fill:none;stroke:var({couleur});stroke-width:2.5\"><title>{nom}</title></polyline>",
            points.join(" ")
        );
        for p in &points {
            let (x, yy) = p.split_once(',').unwrap_or(("0", "0"));
            let _ = write!(svg, "<circle cx={x} cy={yy} r=3 style=\"fill:var({couleur})\"/>");
        }
    };
    serie(
        derniers.iter().map(|b| b.machine).collect(),
        "--info",
        tr!("Cet ordinateur", "This computer"),
    );
    serie(
        derniers
            .iter()
            .map(|b| if b.nom_reseau == reseau_actuel { b.reseau } else { None })
            .collect(),
        "--ok",
        tr!("Réseau", "Network"),
    );
    serie(
        derniers
            .iter()
            .map(|b| {
                if b.nom_reseau == reseau_actuel {
                    b.note_audit()
                } else {
                    None
                }
            })
            .collect(),
        "--moyen",
        tr!("Audit du réseau", "Network audit"),
    );
    let jour = |b: &Bilan| esc_court(&b.date);
    let _ = write!(
        svg,
        "<text x={marge} y={} style=\"fill:var(--doux);font-size:11px\">{}</text><text x={} y={} text-anchor=end style=\"fill:var(--doux);font-size:11px\">{}</text></svg>",
        hauteur - 6.0,
        jour(derniers.first()?),
        largeur - marge,
        hauteur - 6.0,
        jour(derniers.last()?)
    );
    Some(svg)
}

/// Date du bilan sans l'heure, prête pour le HTML (les dates écrites par Vanguard ne contiennent rien à échapper).
fn esc_court(date: &str) -> String {
    date.split(' ').next().unwrap_or(date).replace(['<', '>', '&'], "")
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn b(machine: u32, problemes: &[&str]) -> Bilan {
        Bilan {
            date: "2026-10-17 12:00".into(),
            machine: Some(machine),
            reseau: Some(80),
            nom_reseau: Some("10.0.0.0/24".into()),
            problemes: problemes.iter().map(ToString::to_string).collect(),
            ..Bilan::default()
        }
    }

    #[test]
    fn problemes_nouveaux_et_regles() {
        let avant = b(
            80,
            &["Mises à jour : 3 mises à jour en attente.", "Pare-feu : inactif."],
        );
        let apres = b(
            90,
            &["Mises à jour : 5 mises à jour en attente.", "DNS : réponses inventées."],
        );
        let (nouveaux, regles) = differences(&avant, &apres);
        assert_eq!(nouveaux, ["DNS : réponses inventées."]);
        assert_eq!(regles, ["Pare-feu : inactif."]);
    }

    /// Un historique tronqué n'est pas remplacé en silence par le seul nouveau bilan : il est mis de côté.
    #[test]
    fn historique_illisible_mis_de_cote() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-historique-illisible-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        std::fs::write(&chemin, "[{\"date\":\"2026-10-17 12:00\",\"machine\":8").unwrap();
        assert!(lire_de(&chemin).is_err());
        let (precedent, _) = enregistrer_dans(&chemin, bilan(None, None, None));
        assert!(precedent.is_none());
        let copies = std::fs::read_dir(&dossier)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("historique.illisible-"))
            .count();
        assert!(copies >= 1, "l'historique illisible n'a pas été gardé");
        assert_eq!(
            std::fs::read_to_string(super::tests::copies(&dossier)[0].as_path()).unwrap(),
            "[{\"date\":\"2026-10-17 12:00\",\"machine\":8"
        );
        assert_eq!(lire_de(&chemin).map(|t| t.len()), Ok(1));
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un dossier d'essai neuf.
    fn dossier_d_essai(nom: &str) -> PathBuf {
        let dossier = crate::essais::temporaire().join(format!("vanguard-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        dossier
    }

    /// Les copies mises de côté du dossier.
    fn copies(dossier: &std::path::Path) -> Vec<PathBuf> {
        std::fs::read_dir(dossier)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("historique.illisible-"))
            .map(|e| e.path())
            .collect()
    }

    /// Lot des écritures (point B) : l'écrivain ne pose jamais un fichier que le lecteur refuse. Des bilans gros
    /// dépassaient HISTORIQUE_MAX vers le 156e : chaque bilan suivant trouvait l'historique illisible. Les plus vieux
    /// partent, le dernier reste, la chaîne tient.
    #[test]
    fn historique_jamais_plus_gros_que_ce_qui_se_relit() {
        let dossier = dossier_d_essai("historique-borne");
        let chemin = dossier.join("historique.json");
        let max = 8 * 1024;
        let gros = "x".repeat(900);
        for i in 0..40u32 {
            let mut nouveau = b(i, &[]);
            nouveau.problemes = vec![format!("Persistance : {i} {gros}")];
            let (_, rendu) = enregistrer_dans_borne(&chemin, nouveau, max);
            let tous = lire_de_borne(&chemin, max).expect("l'historique écrit se relit");
            assert!(std::fs::metadata(&chemin).unwrap().len() <= max);
            assert_eq!(tous.last().map(|b| b.empreinte.clone()), Some(rendu.empreinte.clone()));
            assert!(matches!(verifier_chaine(&tous), Chaine::Intacte { .. }), "{i}");
        }
        let tous = lire_de_borne(&chemin, max).unwrap();
        assert!(tous.len() > 1 && tous.len() < 40, "{}", tous.len());
        assert_eq!(tous.last().unwrap().machine, Some(39));
        assert!(copies(&dossier).is_empty(), "aucun historique n'a été jugé illisible");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Point B : un bilan seul plus gros que la borne n'est pas écrit (le fichier serait illisible) ; l'historique
    /// reste tel quel, le bilan est rendu.
    #[test]
    fn bilan_seul_trop_gros_pas_ecrit() {
        let dossier = dossier_d_essai("historique-seul-trop-gros");
        let chemin = dossier.join("historique.json");
        let max = 4 * 1024;
        enregistrer_dans_borne(&chemin, b(70, &["Pare-feu : inactif."]), max);
        let avant = std::fs::read(&chemin).unwrap();
        let mut gros = b(71, &[]);
        gros.problemes = vec!["y".repeat(5000)];
        let (precedent, rendu) = enregistrer_dans_borne(&chemin, gros, max);
        assert_eq!(precedent.map(|p| p.machine), Some(Some(70)));
        assert_eq!(rendu.machine, Some(71));
        assert_eq!(std::fs::read(&chemin).unwrap(), avant);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Point C : un historique trop gros pour être relu est mis de côté sans être relu (avant, la copie le relisait
    /// sous la même borne, n'écrivait rien, disait « Copie gardée », puis l'historique était remplacé : perdu).
    #[test]
    fn historique_trop_gros_mis_de_cote_sans_perte() {
        let dossier = dossier_d_essai("historique-trop-gros");
        let chemin = dossier.join("historique.json");
        let max = 2 * 1024;
        let ancien = format!(
            "[{{\"date\":\"2026-10-17 12:00\",\"problemes\":[\"{}\"]}}]",
            "z".repeat(3000)
        );
        std::fs::write(&chemin, &ancien).unwrap();
        assert!(lire_de_borne(&chemin, max).is_err());
        let (precedent, _) = enregistrer_dans_borne(&chemin, b(80, &[]), max);
        assert!(precedent.is_none());
        let copies = copies(&dossier);
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!(
            std::fs::read_to_string(&copies[0]).unwrap(),
            ancien,
            "la copie est l'historique entier"
        );
        assert_eq!(lire_de_borne(&chemin, max).expect("relu").len(), 1);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Point C : un historique qui ne se met pas de côté (un lien à sa place, jamais suivi) n'est pas remplacé ; le
    /// bilan est rendu quand même.
    #[cfg(unix)]
    #[test]
    fn historique_pas_mis_de_cote_pas_remplace() {
        let dossier = dossier_d_essai("historique-lien");
        let chemin = dossier.join("historique.json");
        let cible = dossier.join("ailleurs.json");
        std::fs::write(&cible, "[").unwrap();
        std::os::unix::fs::symlink(&cible, &chemin).unwrap();
        let (precedent, rendu) = enregistrer_dans_borne(&chemin, b(80, &[]), HISTORIQUE_MAX);
        assert!(precedent.is_none());
        assert_eq!(rendu.machine, Some(80));
        assert!(rendu.empreinte.is_some());
        assert!(std::fs::symlink_metadata(&chemin).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&cible).unwrap(), "[");
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        // Un dossier à sa place non plus.
        std::fs::remove_file(&chemin).unwrap();
        std::fs::create_dir(&chemin).unwrap();
        let _ = enregistrer_dans_borne(&chemin, b(81, &[]), HISTORIQUE_MAX);
        assert!(std::fs::metadata(&chemin).unwrap().is_dir());
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 2, HIS3 : un historique sain qu'on ne peut pas lire (droit refusé) n'est pas abîmé : jamais mis de côté,
    /// laissé tel quel, ce bilan pas enregistré. Seuls un contenu invalide, trop gros ou pas un simple fichier le font.
    #[cfg(unix)]
    #[test]
    fn historique_refuse_laisse_en_place() {
        use std::os::unix::fs::PermissionsExt as _;
        for (genre, oui) in [
            (std::io::ErrorKind::InvalidData, true),
            (std::io::ErrorKind::FileTooLarge, true),
            (std::io::ErrorKind::PermissionDenied, false),
            (std::io::ErrorKind::Interrupted, false),
            (std::io::ErrorKind::Other, false),
        ] {
            assert_eq!(a_mettre_de_cote(&std::io::Error::from(genre)), oui, "{genre:?}");
        }
        let dossier = dossier_d_essai("historique-refuse");
        let chemin = dossier.join("historique.json");
        enregistrer_dans_borne(&chemin, b(70, &[]), HISTORIQUE_MAX);
        enregistrer_dans_borne(&chemin, b(71, &[]), HISTORIQUE_MAX);
        let avant = std::fs::read(&chemin).unwrap();
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&chemin).is_ok() {
            // Lu malgré les droits (root) : rien à essayer.
            std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
            let _ = std::fs::remove_dir_all(&dossier);
            return;
        }
        let (precedent, rendu) = enregistrer_dans_borne(&chemin, b(72, &[]), HISTORIQUE_MAX);
        std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(precedent.is_none());
        assert!(rendu.empreinte.is_some());
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        assert_eq!(std::fs::read(&chemin).unwrap(), avant);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 2, HIS2 : un historique qui ne se lit pas n'est jamais pris pour un historique vide qui tient : le
    /// constat le dit « non vérifié », le rapport aussi.
    #[test]
    fn historique_illisible_dit() {
        let c = constat_de(Err("pas un simple fichier".into())).expect("constat");
        assert!(!c.verifie);
        assert!(
            matches!(&c.precision, crate::modele::Precision::NonVerifie(crate::modele::Raison::Illisible(e)) if e == "pas un simple fichier"),
            "{:?}",
            c.precision
        );
        let ligne = etat_chaine_de(Err("pas un simple fichier".into())).expect("ligne");
        assert!(ligne.contains("pas un simple fichier"), "{ligne}");
        assert!(constat_de(Ok(Vec::new())).is_none());
        assert!(etat_chaine_de(Ok(Vec::new())).is_none());
    }

    /// Passe 2, HIS1 : un lien dur fait sur autre chose que le fichier regardé (remplacé entre-temps) ne laisse pas de
    /// second nom : retiré, l'historique reste seul à sa place, et c'est « laissé ».
    #[test]
    fn second_nom_retire_si_pas_le_fichier() {
        let dossier = dossier_d_essai("historique-second-nom");
        let chemin = dossier.join("historique.json");
        let autre = dossier.join("autre.json");
        std::fs::write(&chemin, "[").unwrap();
        std::fs::write(&autre, "[]").unwrap();
        let regarde = std::fs::symlink_metadata(&autre).unwrap();
        let r = mettre_de_cote_comme(&chemin, &regarde, true);
        assert!(matches!(r, Err(PasMisDeCote::Laisse(_))), "{r:?}");
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        assert_eq!(std::fs::read_to_string(&chemin).unwrap(), "[");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 4, H1, P4-H1 et P4-H2 : un verrou de l'historique gardé par un autre se dit au bilan même, avant tout
    /// enregistrement (au présent) ; rendu, le refus d'avant se dit au passé, avec sa raison ; le bilan suivant
    /// s'enregistre et le constat se tait.
    #[test]
    fn verrou_tenu_dit_au_constat() {
        let dossier = dossier_d_essai("historique-verrou-tenu");
        let chemin = dossier.join("historique.json");
        let tenu = crate::socle::Verrou::prendre(&dossier, VERROU, false, crate::socle::ATTENTE_ECRITURE).unwrap();
        // Le bilan qui va échouer le dit lui-même : rien n'a encore été refusé à ce processus.
        assert!(refus_retenu(&dossier).is_none());
        let c = constat_dans(&chemin).expect("constat du verrou tenu, au bilan même");
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("en ce moment"), "{}", c.message);
        let debut = std::time::Instant::now();
        let _ = enregistrer_en_attendant(&chemin, b(7, &[]), HISTORIQUE_MAX, std::time::Duration::from_millis(50));
        assert!(debut.elapsed() < std::time::Duration::from_secs(10));
        assert!(!chemin.exists());
        assert!(refus_retenu(&dossier).is_some());
        drop(tenu);
        // Rendu : plus rien au présent, le bilan perdu se dit au passé.
        let c = constat_dans(&chemin).expect("constat du bilan perdu");
        assert!(!c.message.contains("en ce moment"), "{}", c.message);
        assert!(c.message.contains("Un bilan précédent"), "{}", c.message);
        assert!(c.message.contains("historique.verrou"), "{}", c.message);
        let _ = enregistrer_dans(&chemin, b(8, &[]));
        assert!(refus_retenu(&dossier).is_none());
        assert_eq!(lire_de(&chemin).unwrap().len(), 1);
        assert!(constat_dans(&chemin).is_none());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// H2 : en administrateur dans le dossier d'un compte, l'historique ne s'écrit pas (ni verrou, ni fichier), comme
    /// le journal et les sceaux ; le bilan est rendu seul.
    #[test]
    fn dossier_d_un_autre_compte_pas_ecrit() {
        let dossier = dossier_d_essai("historique-autre-compte");
        let chemin = dossier.join("historique.json");
        let (avant, rendu) = enregistrer_selon(
            &chemin,
            b(7, &[]),
            HISTORIQUE_MAX,
            crate::socle::ATTENTE_ECRITURE,
            false,
        );
        assert!(avant.is_none());
        assert!(rendu.empreinte.is_some());
        assert!(!chemin.exists());
        assert!(!dossier.join(VERROU).exists());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 4, P4-H4 : un verrou inutilisable sans avoir été remplacé (ici, son dossier ne peut pas exister : un
    /// fichier est à la place d'un de ses parents) est retenu comme un verrou gardé ; le constat du sceau ne le
    /// dirait pas.
    #[test]
    fn verrou_inutilisable_retenu() {
        let base = dossier_d_essai("historique-verrou-inutilisable");
        std::fs::write(base.join("pas-un-dossier"), "x").unwrap();
        let dossier = base.join("pas-un-dossier/sous");
        let _ = enregistrer_en_attendant(
            &dossier.join("historique.json"),
            b(7, &[]),
            HISTORIQUE_MAX,
            std::time::Duration::from_millis(50),
        );
        assert!(!crate::socle::verrou_remplace(&dossier, VERROU));
        let r = refus_retenu(&dossier).expect("refus retenu");
        assert!(r.contains("historique.verrou"), "{r}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Passe 3, historique N1 : seul le fichier lu et jugé abîmé se met de côté. Un historique sain posé à sa place
    /// depuis la lecture reste là, sans copie.
    #[test]
    fn historique_sain_pose_apres_la_lecture_laisse() {
        let dossier = dossier_d_essai("historique-pose-apres");
        let chemin = dossier.join("historique.json");
        std::fs::write(&chemin, "[{").unwrap();
        let (vu, lu) = lire_de_borne_vu(&chemin, HISTORIQUE_MAX);
        assert!(lu.is_err());
        let sain = serde_json::to_string(&vec![b(8, &[]), b(9, &[])]).unwrap();
        let provisoire = dossier.join("neuf.json");
        std::fs::write(&provisoire, &sain).unwrap();
        std::fs::rename(&provisoire, &chemin).unwrap();
        let r = mettre_de_cote(&chemin, vu.as_ref());
        assert!(matches!(r, Err(PasMisDeCote::Laisse(_))), "{r:?}");
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        assert_eq!(lire_de(&chemin).unwrap().len(), 2);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 3, historique N2 : lire, mettre de côté et écrire se font sous le verrou de l'historique ; un autre
    /// Vanguard qui le tient fait attendre, et le bilan s'ajoute ensuite.
    #[test]
    fn enregistrer_attend_le_verrou() {
        let dossier = dossier_d_essai("historique-verrou");
        let chemin = dossier.join("historique.json");
        let tenu = crate::socle::Verrou::prendre(&dossier, VERROU, false, crate::socle::ATTENTE_ECRITURE).unwrap();
        let (dit, attendu) = std::sync::mpsc::channel();
        let fil = std::thread::spawn(move || {
            dit.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(400));
            drop(tenu);
        });
        attendu.recv().unwrap();
        let debut = std::time::Instant::now();
        let _ = enregistrer_dans(&chemin, b(7, &[]));
        assert!(
            debut.elapsed() >= std::time::Duration::from_millis(300),
            "écrit sans attendre le verrou : {:?}",
            debut.elapsed()
        );
        fil.join().unwrap();
        assert_eq!(lire_de(&chemin).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 3, historique N3 : un lien symbolique posé à la place reçoit lui-même le second nom (link ne le suit
    /// pas) : ce second nom est retiré, et c'est « laissé », pas « déplacé ».
    #[cfg(unix)]
    #[test]
    fn lien_echange_second_nom_retire() {
        let dossier = dossier_d_essai("historique-lien-echange");
        let chemin = dossier.join("historique.json");
        let autre = dossier.join("autre.json");
        std::fs::write(&autre, "[").unwrap();
        let regarde = std::fs::symlink_metadata(&autre).unwrap();
        std::os::unix::fs::symlink("ailleurs.json", &chemin).unwrap();
        let r = mettre_de_cote_comme(&chemin, &regarde, true);
        assert!(matches!(r, Err(PasMisDeCote::Laisse(_))), "{r:?}");
        assert_eq!(copies(&dossier), Vec::<PathBuf>::new());
        assert!(std::fs::symlink_metadata(&chemin).unwrap().file_type().is_symlink());
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 2, ROB8 : sans liens durs, un renommage fait puis non vérifié rend « déplacé sous `<copie>` », jamais
    /// « laissé tel quel » ; vérifié, la copie.
    #[test]
    fn renommage_simple_nomme_la_copie() {
        let dossier = dossier_d_essai("historique-renommage");
        let chemin = dossier.join("historique.json");
        let autre = dossier.join("autre.json");
        std::fs::write(&chemin, "[").unwrap();
        std::fs::write(&autre, "[]").unwrap();
        let regarde = std::fs::symlink_metadata(&autre).unwrap();
        match mettre_de_cote_comme(&chemin, &regarde, false) {
            Err(PasMisDeCote::Deplace { copie, .. }) => {
                assert_eq!(std::fs::read_to_string(&copie).unwrap(), "[");
                assert_eq!(copies(&dossier), vec![copie]);
            }
            r => panic!("{r:?}"),
        }
        assert!(std::fs::symlink_metadata(&chemin).is_err());
        std::fs::write(&chemin, "{").unwrap();
        let regarde = std::fs::symlink_metadata(&chemin).unwrap();
        let copie = mettre_de_cote_comme(&chemin, &regarde, false).expect("mis de côté");
        assert_eq!(std::fs::read_to_string(&copie).unwrap(), "{");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Passe 2, ROB6 : le texte de la borne, fait des bilans écrits une seule fois, est celui de serde ; le retrait
    /// ne se dit que quand plus d'un bilan part d'un coup.
    #[test]
    fn texte_borne_comme_serde() {
        let tous: Vec<Bilan> = (0..12u32)
            .map(|i| {
                let mut x = b(i, &["Pare-feu : inactif."]);
                x.empreinte = Some(format!("e{i}"));
                x
            })
            .collect();
        for max in [u64::MAX, 1500, 600] {
            let mut v = tous.clone();
            let (texte, retires) = texte_borne(&mut v, max).expect("texte");
            assert_eq!(texte, serde_json::to_string(&v).unwrap(), "{max}");
            assert_eq!(v.len().saturating_add(retires), tous.len());
            assert!(u64::try_from(texte.len()).unwrap() <= max);
        }
        assert!(!avertir_du_retrait(0));
        assert!(!avertir_du_retrait(1));
        assert!(avertir_du_retrait(2));
    }

    #[test]
    fn courbe_des_notes() {
        assert!(courbe(&[b(80, &[])]).is_none());
        let svg = courbe(&[b(70, &[]), b(85, &[]), b(95, &[])]).unwrap();
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<polyline").count(), 2);
        // L'audit du réseau n'est tracé que quand ses six domaines ont une note : la plus basse.
        let notes = |valeurs: &[u32]| {
            crate::audit::Domaine::TOUS
                .iter()
                .zip(valeurs)
                .map(|(d, n)| (d.nom().to_string(), *n))
                .collect::<BTreeMap<_, _>>()
        };
        let mut complet = b(80, &[]);
        complet.audit = Some(notes(&[90, 85, 100, 70, 95, 88]));
        let mut partiel = b(82, &[]);
        partiel.audit = Some(notes(&[90, 85]));
        assert_eq!(complet.note_audit(), Some(70));
        assert_eq!(partiel.note_audit(), None);
        assert_eq!(b(80, &[]).note_audit(), None);
        let svg = courbe(&[partiel, complet]).unwrap();
        assert_eq!(svg.matches("<polyline").count(), 3);
    }
    #[test]
    fn chaine_des_bilans() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-chaine-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        // Deux anciens bilans, sans empreinte, déjà là.
        let ancien = |date: &str| Bilan {
            date: date.into(),
            machine: Some(80),
            problemes: vec!["Pare-feu : coupé".into()],
            ..Bilan::default()
        };
        std::fs::write(
            &chemin,
            serde_json::to_string(&[ancien("2026-01-01 10:00"), ancien("2026-02-01 10:00")]).unwrap(),
        )
        .unwrap();
        for (i, date) in ["2026-03-01 10:00", "2026-04-01 10:00", "2026-05-01 10:00"]
            .iter()
            .enumerate()
        {
            let mut b = ancien(date);
            b.machine = Some(80 + u32::try_from(i).unwrap());
            // Les notes de l'audit du réseau, hors de l'empreinte : un bilan qui en porte se chaîne comme les autres.
            if i == 1 {
                b.audit = Some(BTreeMap::from([("Appareils".to_string(), 95)]));
            }
            enregistrer_dans(&chemin, b);
        }
        let tous = lire_de(&chemin).unwrap();
        assert_eq!(tous.len(), 5);
        assert_eq!(tous[3].audit.as_ref().map(BTreeMap::len), Some(1));
        assert!(tous[1].empreinte.is_none() && tous[2].empreinte.is_some() && tous[2].precedent.is_none());
        assert_eq!(tous[3].precedent, tous[2].empreinte);
        assert_eq!(verifier_chaine(&tous), Chaine::Intacte { chaines: 3 });
        // Un problème effacé après coup.
        let mut falsifie = tous.clone();
        falsifie[3].problemes.clear();
        assert_eq!(
            verifier_chaine(&falsifie),
            Chaine::Rompue {
                indice: 3,
                date: "2026-04-01 10:00".into(),
                contenu: true
            }
        );
        // Un bilan retiré du milieu.
        let mut troue = tous.clone();
        troue.remove(3);
        assert_eq!(
            verifier_chaine(&troue),
            Chaine::Rompue {
                indice: 3,
                date: "2026-05-01 10:00".into(),
                contenu: false
            }
        );
        // Un bilan sans empreinte glissé après la chaîne.
        let mut glisse = tous.clone();
        glisse.push(ancien("2026-06-01 10:00"));
        assert!(matches!(
            verifier_chaine(&glisse),
            Chaine::Rompue {
                indice: 5,
                contenu: true,
                ..
            }
        ));
        // La rotation retire les premiers bilans : le premier gardé pointe vers un bilan absent, ce n'est pas une
        // falsification.
        let roule: Vec<Bilan> = tous[3..].to_vec();
        assert_eq!(verifier_chaine(&roule), Chaine::Intacte { chaines: 2 });
        assert_eq!(verifier_chaine(&tous[..2]), Chaine::Intacte { chaines: 0 });
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Un historique écrit par la 0.85 (une chaîne d'empreintes v1, sans clés) : relu intact, puis prolongé par un
    /// bilan à clés sans que rien ne devienne « nouveau » ni « rompu ».
    #[test]
    fn historique_de_la_085_relu_puis_prolonge() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-historique-085-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        std::fs::write(&chemin, include_str!("../tests/donnees/historique-0.85.json")).unwrap();
        let anciens = lire_de(&chemin).unwrap();
        assert_eq!(anciens.len(), 4);
        assert!(anciens.iter().all(|b| b.empreinte_v2.is_none() && b.cles.is_empty()));
        assert_eq!(verifier_chaine(&anciens), Chaine::Intacte { chaines: 3 });
        let mut nouveau = b(91, &[]);
        nouveau.problemes = vec![
            "Ports en écoute : 8080/tcp (HTTP) ouvert sur le réseau par « python3 ». Un service web de développement."
                .into(),
        ];
        nouveau.cles = vec![Some("LNX-RES-001|port:8080/tcp:python3".into())];
        let (precedent, nouveau) = enregistrer_dans(&chemin, nouveau);
        let precedent = precedent.unwrap();
        assert!(nouveau.empreinte_v2.is_some() && nouveau.precedent_v2.is_none());
        let tous = lire_de(&chemin).unwrap();
        assert_eq!(verifier_chaine(&tous), Chaine::Intacte { chaines: 4 });
        // Le bilan d'avant n'a pas de clé : on retombe sur le texte, le port n'est pas « nouveau ».
        assert_eq!(differences(&tous[2], &tous[4]), (vec![], vec![]));
        assert_eq!(precedent.date, "2026-10-22 09:05");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// Deux bilans à clés, chaînés par leurs deux empreintes.
    fn deux_bilans_a_cles() -> Vec<Bilan> {
        let dossier = crate::essais::temporaire().join(format!(
            "vanguard-historique-cles-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("historique.json");
        let _ = std::fs::remove_file(&chemin);
        for (date, texte) in [
            ("2026-10-22 10:00", "Ports en écoute : 8080/tcp ouvert par « python3 »."),
            ("2026-10-23 10:00", "Listening ports: 8080/tcp open by “python3”."),
        ] {
            let mut x = b(90, &[texte]);
            x.date = date.into();
            x.cles = vec![Some("LNX-RES-001|port:8080/tcp:python3".into())];
            x.audit = Some(BTreeMap::from([("Appareils".to_string(), 95)]));
            enregistrer_dans(&chemin, x);
        }
        let tous = lire_de(&chemin).unwrap();
        let _ = std::fs::remove_dir_all(&dossier);
        tous
    }

    /// Les clés et les notes de l'audit d'un bilan ne sont jamais hors d'une empreinte : changées à la main, la
    /// seconde chaîne rompt ; retirées avec la seconde empreinte, le bilan est « non vérifié » et ses clés ne
    /// servent plus ; retirées partout (une version plus ancienne réécrit le fichier), la première chaîne tient.
    #[test]
    fn cles_jamais_hors_empreinte() {
        let tous = deux_bilans_a_cles();
        assert_eq!(verifier_chaine(&tous), Chaine::Intacte { chaines: 2 });
        assert_eq!(tous[1].precedent_v2, tous[0].empreinte_v2);
        assert!(tous[1].cle_crue(0).is_some());

        let mut cle_changee = tous.clone();
        cle_changee[1].cles = vec![Some("LNX-RES-001|port:9999/tcp:autre".into())];
        assert!(matches!(
            verifier_chaine(&cle_changee),
            Chaine::Rompue {
                indice: 1,
                contenu: true,
                ..
            }
        ));
        assert_eq!(cle_changee[1].cle_crue(0), None);

        let mut audit_change = tous.clone();
        audit_change[0].audit = Some(BTreeMap::from([("Appareils".to_string(), 100)]));
        assert!(matches!(
            verifier_chaine(&audit_change),
            Chaine::Rompue {
                indice: 0,
                contenu: true,
                ..
            }
        ));

        let mut seconde_retiree = tous.clone();
        seconde_retiree[1].empreinte_v2 = None;
        seconde_retiree[1].precedent_v2 = None;
        assert!(matches!(
            verifier_chaine(&seconde_retiree),
            Chaine::NonVerifiee { indice: 1, .. }
        ));
        assert_eq!(seconde_retiree[1].cle_crue(0), None);

        let mut suite_coupee = tous.clone();
        suite_coupee[1].precedent_v2 = None;
        suite_coupee[1].empreinte_v2 = Some(empreinte_v2_de(&suite_coupee[1]));
        assert!(matches!(
            verifier_chaine(&suite_coupee),
            Chaine::Rompue {
                indice: 1,
                contenu: false,
                ..
            }
        ));

        // Une version plus ancienne relit et réécrit tout : ce qu'elle ne connaît pas disparaît partout.
        let reecrit: Vec<Bilan> = tous
            .iter()
            .map(|x| Bilan {
                cles: Vec::new(),
                empreinte_v2: None,
                precedent_v2: None,
                ..x.clone()
            })
            .collect();
        assert_eq!(verifier_chaine(&reecrit), Chaine::Intacte { chaines: 2 });
    }

    /// Changer de langue ne fait apparaître aucun « nouveau » problème quand les clés sont là ; un autre objet, si.
    #[test]
    fn comparaison_par_cle_puis_par_texte() {
        let tous = deux_bilans_a_cles();
        assert_eq!(differences(&tous[0], &tous[1]), (vec![], vec![]));
        assert!(meme_probleme(
            ("a : 3 x", None),
            ("a : 4 x", Some("LNX-RES-001|port:22/tcp"))
        ));
        assert!(!meme_probleme(
            ("Ports en écoute : 22/tcp", Some("LNX-RES-001|port:22/tcp")),
            ("Ports en écoute : 22/tcp", Some("LNX-RES-001|port:22/tcp:sshd"))
        ));
        // Une version qui change sans être à jour : le même problème, ni « réglé » ni « nouveau ». Un autre
        // logiciel reste un autre problème.
        let perime = |cle| ("Logiciels : 1 logiciel(s) pas à jour.", Some(cle));
        assert!(meme_probleme(
            perime("WIN-MAJ-002|perimes:chrome@150.0.1.2"),
            perime("WIN-MAJ-002|perimes:chrome@150.0.1.9")
        ));
        assert!(!meme_probleme(
            perime("WIN-MAJ-002|perimes:chrome@150.0.1.2"),
            perime("WIN-MAJ-002|perimes:firefox@150.0.1.2")
        ));
    }
}
