//! L'état de l'antivirus en résultat commun (`modele::resultat`, PRO-ANV-001), pour `vanguard antivirus --etat
//! --json` : chaque base avec son jugement, et ce que l'écran dit du moteur, de ce qu'il ne lit pas, des choix et du
//! temps réel. Une base absente, illisible, ancienne ou en partie refusée est non vérifiée : le moteur analyse sans
//! elle (ou sans sa part récente), ce n'est jamais « sain ».

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::{Constat, ok};
use crate::modele::resultat::{Couverture, Resultat, sans_piege};
use crate::protection::yara::resultat::Debut;

const CAT: &str = "Antivirus";

/// Ce que l'écran a relevé, en phrases prêtes à montrer.
#[derive(Default, Debug)]
pub(super) struct Etat {
    /// Chaque base (MalwareBazaar, ClamAV, YARA) : `true` quand elle est là, lisible, entière et à jour.
    pub bases: Vec<(bool, String)>,
    /// Le moteur, ce qu'il ne lit pas, les choix, le temps réel : dits, sans changer le verdict.
    pub notes: Vec<String>,
    /// Ce qui manque hors des bases (Windows : Defender coupé sans choix noté, ou illisible).
    pub manques: Vec<String>,
}

/// Le résultat : une base à jour est vérifiée, une autre non vérifiée ; les notes suivent.
pub(super) fn resultat(e: &Etat, debut: Debut) -> Resultat {
    let constats: Vec<Constat> = e
        .bases
        .iter()
        .filter(|(a_jour, _)| *a_jour)
        .map(|(_, l)| l)
        .chain(&e.notes)
        .map(|t| ok(CAT, sans_piege(t, false)))
        .collect();
    let verifies = e.bases.iter().filter(|(a_jour, _)| *a_jour).count();
    Resultat::nouveau(
        crate::protection::antivirus::resultat::ID,
        debut,
        &constats,
        Couverture {
            verifies: u32::try_from(verifies).unwrap_or(u32::MAX),
            non_verifies: e
                .bases
                .iter()
                .filter(|(a_jour, _)| !*a_jour)
                .map(|(_, l)| l)
                .chain(&e.manques)
                .cloned()
                .collect(),
        },
    )
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Toutes les bases à jour : sain ; une base ancienne ou absente, ou Defender non vérifié : jamais sain ; aucune
    /// base : rien de vérifié.
    #[test]
    fn bases_a_jour_ou_non() {
        let mut e = Etat {
            bases: vec![
                (true, "MalwareBazaar : liste complète du 08/11/2026".into()),
                (true, "Base ClamAV : main.cvd version 62".into()),
                (true, "Règles YARA : 308".into()),
            ],
            notes: vec!["Temps réel des fichiers : en marche.".into()],
            ..Etat::default()
        };
        let r = resultat(&e, debut());
        assert_eq!(r.verdict(), "sain");
        assert_eq!(r.couverture.verifies, 3);
        assert_eq!(r.outil, "PRO-ANV-001");
        e.bases[0].0 = false;
        let r = resultat(&e, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(
            r.couverture.non_verifies,
            ["MalwareBazaar : liste complète du 08/11/2026"]
        );
        assert!(r.constats.iter().all(|c| !c.message.contains("MalwareBazaar")));
        e.bases[0].0 = true;
        e.manques.push("Defender coupé sans choix noté".into());
        assert_eq!(resultat(&e, debut()).verdict(), "non-verifie");
        e.bases.clear();
        e.manques.clear();
        assert_eq!(resultat(&e, debut()).verdict(), "non-verifie");
    }
}
