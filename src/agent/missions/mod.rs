//! Les missions de l'agent, une par fichier. Chacune ne fait que lire (`Lecture`) et juger ; seul le tour applique
//! (`super::appliquer`), après vérification. Les deux premières sont des adaptateurs vers l'auto-réglage de
//! l'autotest (`autotest::reglage`, lots L6, L6c et A6), dont le code reste à sa place : elles en reprennent les
//! changements prévus (montées de délai, pas de la cache, coupures), convertis en `Ajustement` ; celle du réglage y
//! ajoute le second essai (R4), jugé sur son propre état. Celle des corrections (R6) ne fait que dire.

mod cache;
mod corrections;
mod reglage;
mod releve;

pub(crate) use cache::Cache;
pub(crate) use corrections::Corrections;
pub(crate) use reglage::Reglage;
pub(crate) use releve::Releve;

use super::decision::{Ajustement, Levier};
use super::forme::RegleId;
use crate::autotest::reglage::{Coupure, Montee, Raccourcie, Rallongee, Relance};

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

/// Un pas de raccourci défait, en ajustement (la mesure : les vérifications justes de suite).
pub(crate) fn de_rallongee(r: &Rallongee) -> Option<Ajustement> {
    Some(Ajustement {
        levier: Levier::CacheRallonge {
            regle: RegleId::depuis(&r.regle)?,
            avant_min: r.avant_min,
            apres_min: r.apres_min,
        },
        mesure: u64::from(r.comparees),
    })
}

/// Une coupure de la cache, en ajustement (la mesure : les écarts des 14 jours).
pub(crate) fn de_coupure(c: &Coupure) -> Option<Ajustement> {
    Some(Ajustement {
        levier: Levier::CacheCoupee {
            regle: RegleId::depuis(&c.regle)?,
        },
        mesure: u64::from(c.ecarts),
    })
}

/// Un second essai, en ajustement (la mesure : les « non vérifiée » passagers de la semaine).
pub(crate) fn de_relance(r: &Relance) -> Option<Ajustement> {
    Some(Ajustement {
        levier: Levier::SecondEssai {
            regle: RegleId::depuis(&r.regle)?,
            passageres: u16::try_from(r.passageres).ok()?,
            reprises: u16::try_from(r.reprises).ok()?,
        },
        mesure: u64::from(r.passageres),
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
