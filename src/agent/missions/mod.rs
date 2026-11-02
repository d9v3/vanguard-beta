//! Les missions de l'agent, une par fichier. Chacune ne fait que lire (`Lecture`) et juger ; seul le tour applique
//! (`super::appliquer`), après vérification. Les deux premières sont des adaptateurs vers l'auto-réglage de
//! l'autotest (`autotest::reglage`, lots L6 et L6c), dont le code reste à sa place : elles en reprennent les montées
//! de délai et les pas de raccourci prévus, convertis en `Ajustement`.

mod cache;
mod reglage;

pub(crate) use cache::Cache;
pub(crate) use reglage::Reglage;

use super::decision::{Ajustement, Levier};
use super::forme::RegleId;
use crate::autotest::reglage::{Montee, Raccourcie};

/// Une montée de délai de l'auto-réglage, en ajustement ; `None` si la règle n'a pas la forme du registre.
pub(crate) fn de_montee(m: &Montee) -> Option<Ajustement> {
    Some(Ajustement {
        levier: Levier::Delai {
            regle: RegleId::depuis(&m.regle)?,
            avant_s: m.avant_s,
            apres_s: m.apres_s,
        },
        mesure: m.mesure_ms,
    })
}

/// Un pas de raccourci de la durée de la cache, en ajustement (la mesure : les écarts comptés).
pub(crate) fn de_raccourcie(r: &Raccourcie) -> Option<Ajustement> {
    Some(Ajustement {
        levier: Levier::Cache {
            regle: RegleId::depuis(&r.regle)?,
            avant_min: r.avant_min,
            apres_min: r.apres_min,
        },
        mesure: u64::from(r.ecarts),
    })
}

/// Ce qu'une mission de réglage voit : le jour, et les ajustements que l'auto-réglage prévoit.
pub(crate) struct Prevus {
    pub jour: i32,
    pub ajustements: Vec<Ajustement>,
}

/// Le jugement commun aux deux missions de réglage : au plus ce que le plafond du jour laisse, dans l'ordre prévu ;
/// l'état compte le tour et ce qui a été décidé.
pub(crate) fn juger_prevus(obs: &Prevus, etat: &super::Compteurs) -> (Vec<super::Decision>, super::Compteurs) {
    let decisions: Vec<super::Decision> = obs
        .ajustements
        .iter()
        .take(usize::from(etat.restants(obs.jour)))
        .map(|a| super::Decision::Ajuster(*a))
        .collect();
    let n = u16::try_from(decisions.len()).unwrap_or(u16::MAX);
    (decisions, etat.apres(obs.jour, n))
}
