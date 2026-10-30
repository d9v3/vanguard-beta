//! `vanguard evenements` : le journal commun des événements (`modele::journal`) montré, ou rendu en JSON pour un
//! script. L'état de sa chaîne vient d'abord : un journal falsifié se lit quand même (on ne cache pas une alerte),
//! mais il est dit non vérifié, jamais sain. Le jugement vit dans `modele` ; seul l'affichage est ici.

use crate::modele::evenement::Evenement;
use crate::modele::journal::{self, Lecture};
use crate::ui::*;
use crate::{tr, trf, trp};

/// Événements montrés au plus, les plus récents : le JSON, lui, les rend tous.
const MONTRES: usize = 40;

/// Ce que dit l'état du journal, en une phrase.
fn etat(l: &Lecture) -> (String, &'static str) {
    match l {
        Lecture::Vide => (
            tr!("journal vide : rien de noté encore", "empty log: nothing recorded yet").into(),
            GRIS,
        ),
        Lecture::Intact => (
            tr!(
                "journal intact : chaîne et tête scellée d'accord",
                "log intact: chain and sealed head agree"
            )
            .into(),
            VERT,
        ),
        Lecture::Adopte => (
            tr!(
                "journal accepté tel quel au premier usage des sceaux : rien ne prouve qu'il n'a pas changé avant",
                "log accepted as it was when the seals were first used: nothing proves it did not change before"
            )
            .into(),
            couleur(crate::risk::Niveau::Moyen),
        ),
        Lecture::Incomplet(r) => (
            trf!(
                "journal incomplet, non vérifié : {}",
                "incomplete log, not verified: {}",
                affichable(r)
            ),
            couleur(crate::risk::Niveau::Moyen),
        ),
        Lecture::Falsifie(r) => (
            trf!(
                "journal changé hors de Vanguard, non vérifié : {}",
                "log changed outside Vanguard, not verified: {}",
                affichable(r)
            ),
            couleur(crate::risk::Niveau::Eleve),
        ),
    }
}

/// Le JSON rendu : l'état de la chaîne et les événements, tels qu'ils sont écrits.
fn en_json(lu: &journal::Lu, montres: &[&Evenement]) -> serde_json::Value {
    let raison = match &lu.lecture {
        Lecture::Incomplet(r) | Lecture::Falsifie(r) => Some(r.clone()),
        _ => None,
    };
    serde_json::json!({
        "etat": lu.lecture.code(),
        "raison": raison,
        "illisibles": lu.illisibles,
        "evenements": montres,
    })
}

/// Ce qu'on montre d'un événement : la date, la ligne, l'identifiant. Chaque champ passe par `affichable` : un
/// journal falsifié (justement celui qu'on doit signaler) peut porter dans `id` ou dans un `quand` qui n'est pas une
/// date des séquences qui effaceraient, plus haut, la phrase qui le dit changé.
fn montre(e: &Evenement) -> (String, String, String) {
    let quand = affichable(&e.date_locale().unwrap_or_else(|| e.quand.clone()));
    let lie = if e.cause.is_some() { "↳ " } else { "" };
    (
        quand.get(..16).unwrap_or(&quand).to_string(),
        format!("{lie}{} : {}", e.quoi.sorte(), affichable(&e.resume())),
        format!("id {}", affichable(&e.id)),
    )
}

/// `vanguard evenements [--json] [--incident ID]`.
pub fn afficher(json: bool, incident: Option<&str>) {
    let lu = journal::lire();
    let montres: Vec<&Evenement> = match incident {
        Some(id) if lu.evenements.iter().any(|e| e.id == id) => journal::incident(&lu.evenements, id),
        Some(_) => Vec::new(),
        None => lu.evenements.iter().collect(),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&en_json(&lu, &montres)).unwrap_or_default()
        );
        return;
    }
    titre(tr!("JOURNAL DES ÉVÉNEMENTS", "EVENT LOG"));
    let (phrase, style) = etat(&lu.lecture);
    afficher_aligne("  ", &phrase, 2, style);
    if let Some(id) = incident
        && montres.is_empty()
    {
        afficher_aligne(
            "  ",
            &trf!("Aucun événement « {} ».", "No event “{}”.", affichable(id)),
            2,
            GRIS,
        );
        return;
    }
    if montres.is_empty() {
        return;
    }
    if incident.is_none() && montres.len() > MONTRES {
        trp!(
            "\n  {GRIS}Les {MONTRES} plus récents ; tous : vanguard evenements --json{RESET}",
            "\n  {GRIS}The {MONTRES} most recent; all of them: vanguard events --json{RESET}"
        );
    }
    println!();
    let a_sauter = montres
        .len()
        .saturating_sub(if incident.is_some() { usize::MAX } else { MONTRES });
    for e in montres.iter().skip(a_sauter) {
        let (quand, corps, id) = montre(e);
        afficher_aligne(&format!("  {GRIS}{quand}{RESET} "), &corps, 19, "");
        afficher_aligne("                   ", &id, 19, GRIS);
    }
    if incident.is_none() {
        trp!(
            "\n  {GRIS}Le fil d'un incident : vanguard evenements --incident <id>{RESET}",
            "\n  {GRIS}One incident's thread: vanguard events --incident <id>{RESET}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_dit_l_etat_et_la_raison() {
        let lu = journal::Lu {
            lecture: Lecture::Falsifie("2026-10 ligne/line 3".into()),
            evenements: Vec::new(),
            illisibles: 1,
            verifies_des: 0,
        };
        let v = en_json(&lu, &[]);
        assert_eq!(v["etat"], "falsifie");
        assert_eq!(v["raison"], "2026-10 ligne/line 3");
        assert_eq!(v["illisibles"], 1);
        assert_eq!(v["evenements"], serde_json::json!([]));
        // Jamais « intact » ni vert pour un journal qui ne l'est pas.
        for l in [
            Lecture::Falsifie("x".into()),
            Lecture::Incomplet("x".into()),
            Lecture::Adopte,
        ] {
            assert_ne!(etat(&l).1, VERT);
        }
    }

    /// Un `id` et un `quand` piégés (lignes écrites hors de Vanguard) ne pilotent pas le terminal.
    #[test]
    fn id_et_date_pieges_inoffensifs() {
        use crate::modele::evenement::{Genre, Source};
        let mut e = Evenement::nouveau(
            Source::Surveillance,
            Genre::Alerte {
                famille: "port".into(),
                titre: "alerte".into(),
                texte: "x".into(),
            },
        );
        e.id = "a\u{1b}[2A\u{1b}[2K".into();
        e.quand = "\u{1b}[2K\u{1b}]52;c;eA==\u{7}".into();
        let (quand, corps, id) = montre(&e);
        for champ in [&quand, &corps, &id] {
            assert!(!champ.contains('\u{1b}') && !champ.contains('\u{7}'), "{champ:?}");
        }
    }
}
