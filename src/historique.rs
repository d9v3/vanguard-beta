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
    let mut chaines = 0;
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
                chaines += 1;
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
        if indice > 0 && b.precedent_v2 != tous[indice - 1].empreinte_v2 {
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
    match verifier_chaine(&charger()) {
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
    match verifier_chaine(&charger()) {
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

pub fn charger() -> Vec<Bilan> {
    lire().unwrap_or_default()
}

/// L'historique tel qu'il est écrit ; `Err` s'il existe mais ne se lit pas.
fn lire() -> Result<Vec<Bilan>, String> {
    lire_de(&fichier())
}

/// Celui d'un fichier donné : les tests ont chacun le leur, sans quoi l'un réécrirait celui qu'un autre lit (le menu,
/// le rapport ; sous Windows, un fichier ouvert ne se remplace pas).
fn lire_de(chemin: &std::path::Path) -> Result<Vec<Bilan>, String> {
    match std::fs::read_to_string(chemin) {
        Ok(t) => serde_json::from_str(t.trim_start_matches('\u{feff}')).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e.to_string()),
    }
}

fn bilan(audit: Option<&Audit>, reseau: Option<&Rapport>, audit_reseau: Option<&AuditReseau>) -> Bilan {
    let graves: Vec<&crate::machine::Constat> = audit
        .map(|a| {
            a.constats
                .iter()
                .filter(|c| c.probleme.is_some_and(|n| n >= Niveau::Moyen))
                .collect()
        })
        .unwrap_or_default();
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

fn enregistrer_dans(chemin: &std::path::Path, mut nouveau: Bilan) -> (Option<Bilan>, Bilan) {
    let mut tous = match lire_de(chemin) {
        Ok(tous) => tous,
        Err(e) => {
            // Jamais écraser un historique qu'on ne sait pas relire : il est mis de côté, intact, avant le nouveau.
            let copie = chemin.with_extension(format!(
                "illisible-{}.json",
                chrono::Local::now().format("%Y%m%d-%H%M%S")
            ));
            let _ = std::fs::copy(chemin, &copie);
            tre!(
                "Attention : historique des bilans illisible ({e}). Copie gardée : {}",
                "Warning: check history unreadable ({e}). Copy kept: {}",
                copie.display()
            );
            Vec::new()
        }
    };
    let precedent = tous.last().cloned();
    nouveau.precedent = precedent.as_ref().and_then(|p| p.empreinte.clone());
    nouveau.empreinte = Some(empreinte_de(&nouveau));
    nouveau.precedent_v2 = precedent.as_ref().and_then(|p| p.empreinte_v2.clone());
    nouveau.empreinte_v2 = Some(empreinte_v2_de(&nouveau));
    tous.push(nouveau.clone());
    let surplus = tous.len().saturating_sub(GARDES);
    tous.drain(..surplus);
    // D'un bloc : une coupure pendant l'écriture laisse l'ancien historique ou le nouveau, jamais un fichier tronqué.
    if let Ok(texte) = serde_json::to_string(&tous)
        && let Err(e) = crate::socle::ecrire_atomique(chemin, &texte)
    {
        tre!(
            "Attention : bilan non enregistré dans l'historique ({e}).",
            "Warning: check not saved to the history ({e})."
        );
    }
    (precedent, nouveau)
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
    let ecart = i64::from(b) - i64::from(a);
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
    let derniers = &historique[historique.len().saturating_sub(30)..];
    if derniers.len() < 2 {
        return None;
    }
    let reseau_actuel = derniers.last()?.nom_reseau.clone();
    let (largeur, hauteur, marge) = (640.0, 200.0, 28.0);
    #[allow(clippy::cast_precision_loss)]
    let pas = (largeur - 2.0 * marge) / (derniers.len() - 1) as f64;
    // Échelle à partir de la dizaine sous la note la plus basse (au plus 40) : le haut de l'échelle reste lisible.
    let plus_basse = derniers
        .iter()
        .flat_map(|b| [b.machine, b.reseau, b.note_audit()])
        .flatten()
        .min()
        .unwrap_or(40);
    let bas = plus_basse.min(40) / 10 * 10;
    let y = |note: u32| {
        hauteur - marge - f64::from(note.saturating_sub(bas)) / f64::from(100 - bas) * (hauteur - 2.0 * marge)
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
                #[allow(clippy::cast_precision_loss)]
                let x = marge + i as f64 * pas;
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
        jour(&derniers[0]),
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
        let dossier = std::env::temp_dir().join(format!("vanguard-historique-illisible-{}", std::process::id()));
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
        assert_eq!(lire_de(&chemin).map(|t| t.len()), Ok(1));
        let _ = std::fs::remove_dir_all(&dossier);
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
        let dossier = std::env::temp_dir().join(format!("vanguard-chaine-{}", std::process::id()));
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
        let dossier = std::env::temp_dir().join(format!("vanguard-historique-085-{}", std::process::id()));
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
        let dossier = std::env::temp_dir().join(format!(
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
