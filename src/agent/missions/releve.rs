//! La mission du relevé local (A2) : elle ne décide rien. Le tour l'appelle en fin de bilan, à la passe horaire et à
//! la sortie ; quand elle a tourné (ni coupée, ni sautée), le tour passe la main au relevé (`Contexte::relever`), qui
//! vit dans `amelioration` et ne lit ni n'écrit rien de l'agent. Son état ne change pas : aucune écriture de plus.

use std::time::Duration;

use super::super::{Arret, Budget, Compteurs, Decision, Genre, Lecture, Mission, MissionId, Moment};

pub(crate) struct Releve;

impl Mission for Releve {
    type Obs = i32;
    type Etat = Compteurs;

    fn id(&self) -> MissionId {
        MissionId::Releve
    }
    fn genre(&self) -> Genre {
        Genre::Releve
    }
    fn moments(&self) -> &'static [Moment] {
        &[Moment::FinDeBilan, Moment::PasseHoraire, Moment::Sortie]
    }
    fn budget(&self) -> Budget {
        Budget::new(1, 0, Duration::from_secs(10))
    }
    fn observer(&self, lu: &Lecture<'_>, b: &mut Budget) -> Result<i32, Arret> {
        b.lire()?;
        Ok(lu.jour())
    }
    fn juger(&self, _jour: &i32, etat: &Compteurs) -> (Vec<Decision>, Compteurs) {
        (Vec::new(), *etat)
    }
}
