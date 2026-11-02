//! La mission du réglage des délais (lots L6 et A6) : une règle qui frôle son délai deux semaines de suite, ou en
//! sort deux fois en 7 jours (R1), voit le sien monter de `DELAI` à `DELAI_LONG`, une fois. Elle lit ce que
//! l'auto-réglage prévoit (`autotest::reglage`) sans rien écrire. Elle suit aussi, dans son état, les « non vérifié »
//! passagers de chaque règle d'un bilan à l'autre : ceux qui se résolvent d'ordinaire au bilan suivant valent à la
//! règle un second essai à la fin du bilan (R4). Le tour vérifie le sens sûr, puis applique.
//!
//! R5 (la réserve de fils du bilan) n'est pas ici : elle attend une semaine de mesures de l'ordre de départ (avis du
//! coordinateur sur L6a), et une réserve mal bornée ralentirait un bilan sous Windows.

use std::collections::BTreeSet;
use std::time::Duration;

use super::super::decision::{Ajustement, Levier};
use super::super::etat::EtatReglage;
use super::super::forme::{RegleId, ResumeBilan};
use super::super::{Arret, Budget, Decision, Genre, Lecture, Mission, MissionId, Moment};
use super::{Prevus, de_montee, juger_prevus};

pub(crate) struct Reglage;

/// Ce que voit la mission : les montées prévues, le bilan qui vient de finir, et les règles dont le second essai est
/// déjà donné ou annulé.
pub(crate) struct ObsReglage {
    pub prevus: Prevus,
    pub bilan: Option<ResumeBilan>,
    pub deja: BTreeSet<RegleId>,
}

impl Mission for Reglage {
    type Obs = ObsReglage;
    type Etat = EtatReglage;

    fn id(&self) -> MissionId {
        MissionId::Reglage
    }
    fn genre(&self) -> Genre {
        Genre::Reglage
    }
    fn moments(&self) -> &'static [Moment] {
        &[Moment::FinDeBilan]
    }
    fn budget(&self) -> Budget {
        Budget::new(2, 8, Duration::from_secs(10))
    }
    fn observer(&self, lu: &Lecture<'_>, b: &mut Budget) -> Result<ObsReglage, Arret> {
        b.lire()?;
        let prevu = crate::autotest::reglage::prevoir_dans(lu.dossier, lu.aujourd_hui, lu.mesures, lu.delai_du_code)
            .ok_or(Arret::Coupe)?;
        b.lire()?;
        let deja = crate::autotest::reglage::relances_connues_dans(lu.dossier).ok_or(Arret::Coupe)?;
        Ok(ObsReglage {
            prevus: Prevus {
                jour: lu.jour(),
                ajustements: prevu.montees.iter().filter_map(de_montee).collect(),
            },
            bilan: lu.bilan.cloned(),
            deja: deja.iter().filter_map(|r| RegleId::depuis(r)).collect(),
        })
    }
    fn juger(&self, obs: &ObsReglage, etat: &EtatReglage) -> (Vec<Decision>, EtatReglage) {
        let jour = obs.prevus.jour;
        let suivi = match &obs.bilan {
            Some(b) => etat.clone().suivre(jour, b),
            None => etat.clone(),
        };
        let mut ajustements = obs.prevus.ajustements.clone();
        for (regle, n, repris) in suivi.a_relancer(jour) {
            if obs.deja.contains(&regle) {
                continue;
            }
            let (Ok(passageres), Ok(reprises)) = (u16::try_from(n), u16::try_from(repris)) else {
                continue;
            };
            ajustements.push(Ajustement {
                levier: Levier::SecondEssai {
                    regle,
                    passageres,
                    reprises,
                },
                mesure: u64::from(n),
            });
        }
        let (decisions, c) = juger_prevus(&Prevus { jour, ajustements }, &suivi.compteurs());
        (decisions, suivi.avec_compteurs(c))
    }
}
