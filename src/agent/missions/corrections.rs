//! La mission des corrections (R6) : de l'information seulement. Elle lit les corrections appliquées depuis le tour
//! d'avant (notées par Vanguard, des règles et des empreintes, jamais un message) et le bilan qui vient de finir ;
//! elle garde dans son état les échecs de suite de chaque correction et les problèmes corrigés qui reviennent au
//! bilan suivant. Ce qu'elle décide se montre (une proposition) ; rien n'est retiré ni masqué : une correction
//! fragile reste proposée, une à une, avec son avis (`super::super::avis_corrections`). Elle n'ajuste rien.

use std::time::Duration;

use super::super::etat::EtatCorrections;
use super::super::forme::{NoteCorrection, ResumeBilan};
use super::super::{Arret, Budget, Decision, Genre, Lecture, Mission, MissionId, Moment};

pub(crate) struct Corrections;

/// Ce que voit la mission : le jour, les corrections notées, le bilan qui vient de finir.
pub(crate) struct ObsCorrections {
    pub jour: i32,
    pub notes: Vec<NoteCorrection>,
    pub bilan: Option<ResumeBilan>,
}

impl Mission for Corrections {
    type Obs = ObsCorrections;
    type Etat = EtatCorrections;

    fn id(&self) -> MissionId {
        MissionId::Corrections
    }
    fn genre(&self) -> Genre {
        Genre::Reglage
    }
    fn moments(&self) -> &'static [Moment] {
        &[Moment::FinDeBilan, Moment::Sortie]
    }
    fn budget(&self) -> Budget {
        Budget::new(1, 8, Duration::from_secs(10))
    }
    fn observer(&self, lu: &Lecture<'_>, b: &mut Budget) -> Result<ObsCorrections, Arret> {
        b.lire()?;
        Ok(ObsCorrections {
            jour: lu.jour(),
            notes: lu.corrections.to_vec(),
            bilan: lu.bilan.cloned(),
        })
    }
    fn juger(&self, obs: &ObsCorrections, etat: &EtatCorrections) -> (Vec<Decision>, EtatCorrections) {
        // Rien de neuf : l'état ne change pas (aucune écriture à chaque sortie).
        if obs.notes.is_empty() && obs.bilan.is_none() {
            return (Vec::new(), etat.clone());
        }
        let (apres, montrer) = etat.clone().apres(obs.jour, &obs.notes, obs.bilan.as_ref());
        // Le journal en garde au plus le compte du jour ; l'état, lui, garde tout (c'est lui qui se montre).
        let decisions: Vec<Decision> = montrer
            .into_iter()
            .take(usize::from(etat.compteurs().restants(obs.jour)))
            .map(Decision::Proposer)
            .collect();
        let n = u16::try_from(decisions.len()).unwrap_or(u16::MAX);
        let c = apres.compteurs().apres(obs.jour, n);
        (decisions, apres.avec_compteurs(c))
    }
}
