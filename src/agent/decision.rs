//! Ce qu'une mission peut décider, en trois sortes et rien d'autre :
//! - un **ajustement** : un levier de Vanguard lui-même, sur cet ordinateur, poussé dans le sens sûr (un délai de
//!   règle qui monte, une durée de cache qui raccourcit). Seule sorte qui change quelque chose, seulement par les
//!   fonctions de l'agent qui la bornent (`super::sens_sur`), et chacune s'annule dans Paramètres ;
//! - une **proposition** : rien n'est fait ; elle se montre, la personne décide ;
//! - un **signal** : une observation à faire voir.
//!
//! Aucune ne porte de texte libre (`super::forme`) ; aucune ne touche au système, au réseau ni aux corrections.
//!
//! Module pur : le banc de fuzzing l'inclut (`agent_journal`).
// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use super::forme::{Genre, MissionId, RegleId};

/// Un levier que l'agent peut pousser : chacun a son sens sûr, et lui seul.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Levier {
    /// Le délai d'une règle du bilan, en secondes : il ne fait que monter (une règle lente a plus de temps, jamais
    /// moins).
    Delai { regle: RegleId, avant_s: u64, apres_s: u64 },
    /// La durée d'une règle de la cache du passage horaire, en minutes : elle ne fait que descendre (un résultat repris
    /// moins longtemps, donc vérifié à neuf plus souvent).
    Cache {
        regle: RegleId,
        avant_min: u16,
        apres_min: u16,
    },
}

impl Levier {
    pub(crate) fn regle(&self) -> RegleId {
        match self {
            Levier::Delai { regle, .. } | Levier::Cache { regle, .. } => *regle,
        }
    }
}

/// Un ajustement : le levier, et la mesure qui l'a décidé (la plus longue durée de la semaine en ms pour un délai,
/// les écarts sur les vérifications à neuf pour une durée de cache).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ajustement {
    pub levier: Levier,
    pub mesure: u64,
}

/// Une proposition : montrée, jamais exécutée par l'agent. Les missions suivantes en ajouteront les sortes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[cfg_attr(not(test), allow(dead_code))] // les missions de G4 (corrections) et G7 (agents voyous)
pub(crate) enum Proposition {
    /// Revoir une règle (son délai, sa durée) : la personne regarde dans Paramètres.
    RevoirRegle { regle: RegleId },
}

/// Un signal : une observation à faire voir. Les missions de détection en ajouteront les sortes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
#[cfg_attr(not(test), allow(dead_code))] // la mission des agents voyous (G7)
pub(crate) enum Signal {
    /// Une règle a vu quelque chose de nouveau depuis la référence approuvée.
    Nouveaute { regle: RegleId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Decision {
    Ajuster(Ajustement),
    Proposer(Proposition),
    Signaler(Signal),
}

/// Ce que le genre permet : un réglage ajuste ou propose, une détection signale ou propose, un relevé ne décide rien.
pub(crate) fn permise(genre: Genre, d: &Decision) -> bool {
    matches!(
        (genre, d),
        (Genre::Reglage, Decision::Ajuster(_) | Decision::Proposer(_))
            | (Genre::Detection, Decision::Signaler(_) | Decision::Proposer(_))
    )
}

/// Ce que chaque mission peut ajuster : la mission du réglage les délais, celle de la cache les durées de la cache.
pub(crate) fn levier_de(mission: MissionId, l: &Levier) -> bool {
    matches!(
        (mission, l),
        (MissionId::Reglage, Levier::Delai { .. }) | (MissionId::Cache, Levier::Cache { .. })
    )
}
