//! La mission de la cache du passage horaire (lot L6c) : une règle de la table de la cache que les vérifications à
//! neuf contredisent trop souvent voit sa durée raccourcir d'un pas, jamais sous le plancher. Elle lit ce que
//! l'auto-réglage prévoit (`autotest::reglage`) sans rien écrire ; le tour vérifie le sens sûr, puis applique.

use std::time::Duration;

use super::super::{Arret, Budget, Compteurs, Decision, Genre, Lecture, Mission, MissionId, Moment};
use super::{Prevus, de_raccourcie, juger_prevus};

pub(crate) struct Cache;

impl Mission for Cache {
    type Obs = Prevus;
    type Etat = Compteurs;

    fn id(&self) -> MissionId {
        MissionId::Cache
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
            ajustements: prevu.raccourcies.iter().filter_map(de_raccourcie).collect(),
        })
    }
    fn juger(&self, obs: &Prevus, etat: &Compteurs) -> (Vec<Decision>, Compteurs) {
        juger_prevus(obs, etat)
    }
}
