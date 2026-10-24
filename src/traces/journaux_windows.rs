//! Les alertes des règles `EVT-` (`journaux_windows`) pour la chronologie de l'incident : à part de `chronologie`,
//! que le banc de fuzzing inclut seul, sans le moteur des règles.

use std::fmt::Write as _;

use super::chronologie::{Apport, Evenement, Genre, Source};
use super::{Bi, Manque, Raison, bi};

/// Les alertes `EVT-` d'une analyse des journaux de Windows, pour la chronologie : chacune à la date de son premier
/// événement, avec sa règle, sa gravité, ce qu'elle dit et où la retrouver, et sa technique ATT&CK ; celles que les
/// normales taisent restent tues (`journaux_windows::chronologie`). Une règle qui n'a pas tout lu est dite parmi ce
/// qui manque, comme les alertes sans date, qu'aucune ligne ne peut placer.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traces::chronologie;

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
        let t = chronologie::texte(
            &[e],
            0,
            1_759_000_000,
            &chrono::FixedOffset::east_opt(-4 * 3600).unwrap(),
            &[],
        );
        assert!(
            t.contains("ALERTE des journaux de Windows") && t.contains("T1543.003"),
            "{t}"
        );
        assert!(t.contains("Alertes des journaux de Windows (règles EVT-"), "{t}");
        assert!(!t.contains('\u{1b}'), "{t}");
    }
}
