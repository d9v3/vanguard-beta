//! Le contrat d'une mission : observer (lire seulement, dans son budget), puis juger (une fonction pure, qui ne voit
//! que des types fermés et son état). Elle n'écrit rien et n'applique rien : c'est le tour (`super::tic`) qui vérifie
//! chaque décision (genre, levier, sens sûr), l'applique, la note au journal et écrit l'état.

use serde::Serialize;
use serde::de::DeserializeOwned;

use super::budget::{Arret, Budget};
use super::decision::Decision;
use super::etat::Borne;
use super::forme::{Genre, MissionId, Moment};

/// Ce qu'une mission peut lire : le dossier de données (lecture seulement, garde `missions_ne_font_que_lire`), le
/// jour, les mesures du bilan, et le délai de chaque règle dans le code.
pub(crate) struct Lecture<'a> {
    pub dossier: &'a std::path::Path,
    pub aujourd_hui: chrono::NaiveDate,
    pub mesures: &'a crate::autotest::mesures::Mesures,
    pub delai_du_code: &'a dyn Fn(&str) -> Option<std::time::Duration>,
    /// Le bilan qui vient de finir (à la fin d'un bilan seulement) : des règles et des issues, aucun texte.
    pub bilan: Option<&'a super::forme::ResumeBilan>,
    /// Les corrections appliquées depuis le tour d'avant (R6).
    pub corrections: &'a [super::forme::NoteCorrection],
}

impl Lecture<'_> {
    /// Le jour, compté depuis 1970 (les états ne gardent que des nombres).
    pub(crate) fn jour(&self) -> i32 {
        i32::try_from(
            self.aujourd_hui
                .signed_duration_since(chrono::NaiveDate::default())
                .num_days(),
        )
        .unwrap_or(0)
    }
}

pub(crate) trait Mission: Send + Sync {
    /// Ce qu'elle observe : des types fermés, aucun texte.
    type Obs;
    /// Ce qu'elle garde d'un tour à l'autre (scellé, borné, aucun texte).
    type Etat: Serialize + DeserializeOwned + Default + Borne + Clone + PartialEq;
    fn id(&self) -> MissionId;
    fn genre(&self) -> Genre;
    fn moments(&self) -> &'static [Moment];
    fn budget(&self) -> Budget;
    fn observer(&self, lu: &Lecture<'_>, b: &mut Budget) -> Result<Self::Obs, Arret>;
    /// Pure : mêmes observations et même état, mêmes décisions.
    fn juger(&self, obs: &Self::Obs, etat: &Self::Etat) -> (Vec<Decision>, Self::Etat);
}
