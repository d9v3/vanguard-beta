//! Ce que l'agent garde d'un tour à l'autre, sous le dossier de données : l'état de chaque mission
//! (`agent/etat/<mission>.json`) et ses interrupteurs (`agent/agent.json`). Scellés (`sceau`), 1 Mio au plus chacun,
//! sans un seul texte libre : des nombres et des noms de mission de la liste fermée. Un fichier trop gros, illisible
//! ou hors de ses bornes rend l'état d'origine, serré dans ses bornes ; un fichier douteux (sceau) fait sauter la
//! mission, et rien n'y est réécrit tout seul.
//!
//! La partie pure (types, bornes, lecture des octets) est incluse par le banc de fuzzing (`agent_etat`).
// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::forme::MissionId;

/// Au-delà, ce n'est pas un fichier de l'agent (quelques dizaines d'octets d'ordinaire).
pub(crate) const TAILLE_MAX: usize = 1 << 20;
/// Les interrupteurs des missions. Scellé.
pub(crate) const AGENT: &str = "agent/agent.json";
/// L'état de chaque mission. Scellés.
pub(crate) const ETAT_REGLAGE: &str = "agent/etat/reglage.json";
pub(crate) const ETAT_CACHE: &str = "agent/etat/cache.json";
pub(crate) const ETAT_RELEVE: &str = "agent/etat/releve.json";

/// Ajustements au plus par mission et par jour : même si une mesure s'emballe, l'agent n'enchaîne pas les changements.
pub(crate) const PAR_JOUR_MAX: u16 = 20;
/// Les jours (depuis 1970) qu'un état peut porter : du 1er janvier 2020 à l'an 2200. Hors de là, l'horloge ou le
/// fichier ment, et le compte du jour repart de zéro.
pub(crate) const JOUR_MIN: i32 = 18_262;
pub(crate) const JOUR_MAX: i32 = 84_000;

/// Un état qui sait se serrer dans ses bornes, et dire s'il y est.
pub(crate) trait Borne: Sized {
    fn borne(self) -> Self;
    #[cfg_attr(not(any(test, fuzzing)), allow(dead_code))] // les essais et le banc de fuzzing
    fn dans_ses_bornes(&self) -> bool;
}

/// Le contenu d'un fichier de l'agent, serré dans ses bornes ; trop gros ou illisible : l'état d'origine.
pub(crate) fn lire_de<E: DeserializeOwned + Default + Borne>(octets: &[u8]) -> E {
    if octets.len() > TAILLE_MAX {
        return E::default().borne();
    }
    serde_json::from_slice::<E>(octets).unwrap_or_default().borne()
}

/// L'état d'une mission de réglage : ce qu'elle a décidé, et combien aujourd'hui.
#[derive(Serialize, Deserialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Compteurs {
    #[serde(default)]
    pub v: u16,
    /// Le jour (depuis 1970) des ajustements comptés dans `du_jour` ; 0 : aucun encore.
    #[serde(default)]
    pub jour: i32,
    #[serde(default)]
    pub du_jour: u16,
    /// Les tours faits et les ajustements décidés, depuis toujours (saturés).
    #[serde(default)]
    pub tours: u32,
    #[serde(default)]
    pub total: u32,
}

impl Compteurs {
    /// Ajustements encore permis le jour `jour`.
    pub(crate) fn restants(&self, jour: i32) -> u16 {
        if self.jour == jour {
            PAR_JOUR_MAX.saturating_sub(self.du_jour)
        } else {
            PAR_JOUR_MAX
        }
    }

    /// Après un tour du jour `jour` qui a décidé `n` ajustements.
    pub(crate) fn apres(self, jour: i32, n: u16) -> Compteurs {
        let deja = if self.jour == jour { self.du_jour } else { 0 };
        Compteurs {
            v: 1,
            jour: if n > 0 || self.jour == jour { jour } else { self.jour },
            du_jour: if n > 0 || self.jour == jour {
                deja.saturating_add(n)
            } else {
                self.du_jour
            },
            tours: self.tours.saturating_add(1),
            total: self.total.saturating_add(u32::from(n)),
        }
        .borne()
    }
}

impl Borne for Compteurs {
    fn borne(mut self) -> Compteurs {
        self.v = 1;
        if !(JOUR_MIN..=JOUR_MAX).contains(&self.jour) {
            self.jour = 0;
            self.du_jour = 0;
        }
        self.du_jour = self.du_jour.min(PAR_JOUR_MAX);
        self
    }

    fn dans_ses_bornes(&self) -> bool {
        self.v == 1
            && self.du_jour <= PAR_JOUR_MAX
            && ((JOUR_MIN..=JOUR_MAX).contains(&self.jour) || (self.jour == 0 && self.du_jour == 0))
    }
}

/// Les interrupteurs : les missions coupées dans Paramètres. Absent : toutes en marche. L'interrupteur de l'agent
/// entier est celui de l'auto-réglage (`autotest::reglage`, « oui » par défaut).
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Interrupteurs {
    #[serde(default)]
    pub v: u16,
    #[serde(default)]
    pub coupees: BTreeSet<MissionId>,
}

impl Borne for Interrupteurs {
    fn borne(mut self) -> Interrupteurs {
        self.v = 1;
        self
    }

    fn dans_ses_bornes(&self) -> bool {
        self.v == 1 && self.coupees.len() <= MissionId::TOUTES.len()
    }
}

/// Ce qu'un fichier de l'agent donne.
#[cfg(not(fuzzing))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Lu<E> {
    Absent,
    Cru(E),
    /// Falsifié, adopté, illisible (`sceau`) : rien n'en est cru, et rien n'y est réécrit tout seul.
    Douteux,
}

#[cfg(not(fuzzing))]
impl<E: Default> Lu<E> {
    /// L'état, s'il peut servir : celui d'origine quand le fichier est absent.
    pub(crate) fn utilisable(self) -> Option<E> {
        match self {
            Lu::Absent => Some(E::default()),
            Lu::Cru(e) => Some(e),
            Lu::Douteux => None,
        }
    }
}

/// Le fichier d'état de la mission.
#[cfg(not(fuzzing))]
pub(crate) fn nom_etat(id: MissionId) -> &'static str {
    match id {
        MissionId::Reglage => ETAT_REGLAGE,
        MissionId::Cache => ETAT_CACHE,
        MissionId::Releve => ETAT_RELEVE,
    }
}

#[cfg(not(fuzzing))]
pub(crate) fn lire_dans<E: DeserializeOwned + Default + Borne>(dossier: &std::path::Path, nom: &str) -> Lu<E> {
    match crate::sceau::juge_dans(dossier, nom) {
        crate::sceau::Juge::Absent => Lu::Absent,
        crate::sceau::Juge::Cru(o) => Lu::Cru(lire_de(&o)),
        _ => Lu::Douteux,
    }
}

#[cfg(not(fuzzing))]
pub(crate) fn ecrire_dans<E: Serialize + Borne + Clone>(
    dossier: &std::path::Path,
    nom: &str,
    e: &E,
) -> std::io::Result<()> {
    let o = serde_json::to_vec(&e.clone().borne()).map_err(std::io::Error::other)?;
    if o.len() > TAILLE_MAX {
        return Err(std::io::ErrorKind::FileTooLarge.into());
    }
    crate::sceau::ecrire_dans(dossier, nom, &o)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Tout état lu, quels que soient les octets, reste dans ses bornes.
        #[test]
        fn tout_etat_lu_reste_dans_ses_bornes(octets in proptest::collection::vec(any::<u8>(), 0..200),
            jour in any::<i32>(), du_jour in any::<u16>(), tours in any::<u32>(), n in 0u16..100) {
            prop_assert!(lire_de::<Compteurs>(&octets).dans_ses_bornes());
            prop_assert!(lire_de::<Interrupteurs>(&octets).dans_ses_bornes());
            let json = format!(r#"{{"v":7,"jour":{jour},"du_jour":{du_jour},"tours":{tours},"total":3}}"#);
            let c = lire_de::<Compteurs>(json.as_bytes());
            prop_assert!(c.dans_ses_bornes());
            // Un tour de plus reste dans les bornes, et n'ouvre jamais plus que le plafond du jour.
            let j = JOUR_MIN + 100;
            let apres = c.apres(j, n);
            prop_assert!(apres.dans_ses_bornes());
            prop_assert!(apres.restants(j) <= PAR_JOUR_MAX);
        }
    }

    #[test]
    fn plafond_du_jour() {
        let j = JOUR_MIN + 5;
        let c = Compteurs::default().borne().apres(j, PAR_JOUR_MAX);
        assert_eq!(c.restants(j), 0);
        assert_eq!(c.restants(j + 1), PAR_JOUR_MAX);
        // Trop gros : l'état d'origine, sans être lu.
        let mut gros = br#"{"v":1,"jour":18300,"du_jour":20}"#.to_vec();
        gros.resize(TAILLE_MAX + 1, b' ');
        assert_eq!(lire_de::<Compteurs>(&gros), Compteurs::default().borne());
        // Une mission inconnue dans les interrupteurs : rien n'en est cru, toutes en marche.
        assert!(
            lire_de::<Interrupteurs>(br#"{"v":1,"coupees":["rogue-x"]}"#)
                .coupees
                .is_empty()
        );
    }
}
