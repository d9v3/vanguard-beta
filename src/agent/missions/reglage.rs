//! La mission du réglage des délais (lot L6) : une règle qui frôle son délai deux semaines de suite voit le sien
//! monter de `DELAI` à `DELAI_LONG`, une fois. Elle lit ce que l'auto-réglage prévoit (`autotest::reglage`) sans rien
//! écrire ; le tour vérifie le sens sûr, puis applique.

use std::time::Duration;

use super::super::{Arret, Budget, Compteurs, Decision, Genre, Lecture, Mission, MissionId, Moment};
use super::{Prevus, de_montee, juger_prevus};

pub(crate) struct Reglage;

impl Mission for Reglage {
    type Obs = Prevus;
    type Etat = Compteurs;

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
        Budget::new(1, 8, Duration::from_secs(10))
    }
    fn observer(&self, lu: &Lecture<'_>, b: &mut Budget) -> Result<Prevus, Arret> {
        b.lire()?;
        let prevu = crate::autotest::reglage::prevoir_dans(lu.dossier, lu.aujourd_hui, lu.mesures, lu.delai_du_code)
            .ok_or(Arret::Coupe)?;
        Ok(Prevus {
            jour: lu.jour(),
            ajustements: prevu.montees.iter().filter_map(de_montee).collect(),
        })
    }
    fn juger(&self, obs: &Prevus, etat: &Compteurs) -> (Vec<Decision>, Compteurs) {
        juger_prevus(obs, etat)
    }
}
