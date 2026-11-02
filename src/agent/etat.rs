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

use super::decision::Proposition;
use super::forme::{CodeEchec, Issue, IssueCorrection, MissionId, NoteCorrection, RegleId, ResumeBilan};

/// Au-delà, ce n'est pas un fichier de l'agent (quelques dizaines d'octets d'ordinaire).
pub(crate) const TAILLE_MAX: usize = 1 << 20;
/// Les interrupteurs des missions. Scellé.
pub(crate) const AGENT: &str = "agent/agent.json";
/// L'état de chaque mission. Scellés.
pub(crate) const ETAT_REGLAGE: &str = "agent/etat/reglage.json";
pub(crate) const ETAT_CACHE: &str = "agent/etat/cache.json";
pub(crate) const ETAT_RELEVE: &str = "agent/etat/releve.json";
pub(crate) const ETAT_CORRECTIONS: &str = "agent/etat/corrections.json";

/// Ajustements au plus par mission et par jour : même si une mesure s'emballe, l'agent n'enchaîne pas les changements.
pub(crate) const PAR_JOUR_MAX: u16 = 20;
/// Les jours (depuis 1970) qu'un état peut porter : du 1er janvier 2020 à l'an 2200. Hors de là, l'horloge ou le
/// fichier ment, et le compte du jour repart de zéro.
pub(crate) const JOUR_MIN: i32 = 18_262;
pub(crate) const JOUR_MAX: i32 = 84_000;

/// Un état qui sait se serrer dans ses bornes, et dire s'il y est.
pub(crate) trait Borne: Sized {
    /// Un fichier scellé qui ne se lit pas (trop gros, d'une autre version) : douteux plutôt que l'état d'origine.
    /// Pour les interrupteurs, l'état d'origine remettrait en marche ce qui avait été coupé.
    const ILLISIBLE_DOUTEUX: bool = false;
    fn borne(self) -> Self;
    #[cfg_attr(not(any(test, fuzzing)), allow(dead_code))] // les essais et le banc de fuzzing
    fn dans_ses_bornes(&self) -> bool;
}

/// Le contenu d'un fichier de l'agent, serré dans ses bornes ; trop gros ou illisible : l'état d'origine.
#[cfg_attr(not(any(test, fuzzing)), allow(dead_code))] // les essais et le banc de fuzzing
pub(crate) fn lire_de<E: DeserializeOwned + Default + Borne>(octets: &[u8]) -> E {
    lisible(octets).unwrap_or_else(|| E::default().borne())
}

/// Le contenu d'un fichier de l'agent, serré dans ses bornes ; `None` : trop gros ou illisible.
fn lisible<E: DeserializeOwned + Borne>(octets: &[u8]) -> Option<E> {
    if octets.len() > TAILLE_MAX {
        return None;
    }
    serde_json::from_slice::<E>(octets).ok().map(Borne::borne)
}

/// Un fichier scellé et cru : son contenu, ou l'état d'origine s'il ne se lit pas (`Borne::ILLISIBLE_DOUTEUX` :
/// douteux).
#[cfg(not(fuzzing))]
fn cru<E: DeserializeOwned + Default + Borne>(octets: &[u8]) -> Lu<E> {
    match lisible(octets) {
        Some(e) => Lu::Cru(e),
        None if E::ILLISIBLE_DOUTEUX => Lu::Douteux,
        None => Lu::Cru(E::default().borne()),
    }
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
    /// Le jour (depuis 1970) du dernier tour de la mission ; 0 : aucun encore. Il ne change qu'une fois par jour :
    /// une mission qui n'a rien à garder n'écrit pas son état à chaque tour.
    #[serde(default, skip_serializing_if = "nul")]
    pub dernier: i32,
}

/// Rien d'écrit pour un champ à zéro : un état d'avant ce champ se réécrit à l'identique.
#[allow(clippy::trivially_copy_pass_by_ref)] // la forme que demande serde
fn nul(j: &i32) -> bool {
    *j == 0
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
            dernier: jour,
        }
        .borne()
    }

    /// Un tour du jour `jour` qui n'a rien jugé : seul le jour du dernier tour change.
    pub(crate) fn vu(self, jour: i32) -> Compteurs {
        Compteurs { dernier: jour, ..self }.borne()
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
        if !jour_valable(self.dernier) {
            self.dernier = 0;
        }
        self
    }

    fn dans_ses_bornes(&self) -> bool {
        self.v == 1
            && self.du_jour <= PAR_JOUR_MAX
            && ((JOUR_MIN..=JOUR_MAX).contains(&self.jour) || (self.jour == 0 && self.du_jour == 0))
            && (self.dernier == 0 || jour_valable(self.dernier))
    }
}

/// Les interrupteurs : les missions coupées dans Paramètres. Absent : toutes en marche ; scellé mais illisible (d'une
/// autre version) : douteux, toutes coupées sauf une détection. L'interrupteur de l'agent
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
    const ILLISIBLE_DOUTEUX: bool = true;
    fn borne(mut self) -> Interrupteurs {
        self.v = 1;
        self
    }

    fn dans_ses_bornes(&self) -> bool {
        self.v == 1 && self.coupees.len() <= MissionId::TOUTES.len()
    }
}

/// Règles suivies au plus par la mission du réglage pour le second essai (R4), et passages gardés par règle.
pub(crate) const SUIVIS_MAX: usize = 200;
pub(crate) const PASSAGES_MAX: usize = 16;
/// La semaine que juge le second essai : aujourd'hui et les 6 jours d'avant.
pub(crate) const SEMAINE: i32 = 7;

/// Un « non vérifié » passager d'une règle, et ce qu'elle a rendu au bilan suivant.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Passage {
    /// Le jour (depuis 1970) du bilan où elle n'a pas pu conclure.
    pub jour: i32,
    /// Vrai si elle a conclu au bilan suivant.
    pub repris: bool,
}

/// Le suivi d'une règle pour le second essai.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Suivi {
    pub regle: RegleId,
    /// Le jour d'un « non vérifié » passager dont on attend le bilan suivant.
    #[serde(default)]
    pub attente: Option<i32>,
    #[serde(default)]
    pub passages: Vec<Passage>,
}

/// L'état de la mission du réglage : ses compteurs (la forme de `Compteurs`, qu'un fichier d'avant garde) et le suivi
/// des « non vérifié » passagers de chaque règle.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EtatReglage {
    #[serde(default)]
    pub v: u16,
    #[serde(default)]
    pub jour: i32,
    #[serde(default)]
    pub du_jour: u16,
    #[serde(default)]
    pub tours: u32,
    #[serde(default)]
    pub total: u32,
    #[serde(default, skip_serializing_if = "nul")]
    pub dernier: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suivis: Vec<Suivi>,
}

fn jour_valable(j: i32) -> bool {
    (JOUR_MIN..=JOUR_MAX).contains(&j)
}

/// Garde les `n` derniers d'une liste.
fn derniers<T>(v: &mut Vec<T>, n: usize) {
    let trop = v.len().saturating_sub(n);
    v.drain(..trop);
}

impl EtatReglage {
    pub(crate) fn compteurs(&self) -> Compteurs {
        Compteurs {
            v: self.v,
            jour: self.jour,
            du_jour: self.du_jour,
            tours: self.tours,
            total: self.total,
            dernier: self.dernier,
        }
    }

    pub(crate) fn avec_compteurs(mut self, c: Compteurs) -> EtatReglage {
        self.v = c.v;
        self.jour = c.jour;
        self.du_jour = c.du_jour;
        self.tours = c.tours;
        self.total = c.total;
        self.dernier = c.dernier;
        self.borne()
    }

    /// Après le bilan `bilan`, le jour `jour` : une règle en attente note si elle a conclu ; une règle passagère se
    /// met en attente. Les passages de plus d'une semaine s'oublient.
    pub(crate) fn suivre(mut self, jour: i32, bilan: &ResumeBilan) -> EtatReglage {
        for (regle, issue) in &bilan.regles {
            let i = match self.suivis.iter().position(|s| s.regle == *regle) {
                Some(i) => i,
                None if *issue == Issue::Passagere && self.suivis.len() < SUIVIS_MAX => {
                    self.suivis.push(Suivi {
                        regle: *regle,
                        attente: None,
                        passages: Vec::new(),
                    });
                    self.suivis.len().saturating_sub(1)
                }
                None => continue,
            };
            let Some(s) = self.suivis.get_mut(i) else {
                continue;
            };
            if let Some(j) = s.attente.take() {
                s.passages.push(Passage {
                    jour: j,
                    repris: *issue == Issue::Concluse,
                });
            }
            if *issue == Issue::Passagere {
                s.attente = Some(jour);
            }
        }
        let debut = jour.saturating_sub(SEMAINE.saturating_sub(1));
        for s in &mut self.suivis {
            s.passages.retain(|p| p.jour >= debut && p.jour <= jour);
            s.attente = s.attente.filter(|a| *a >= debut && *a <= jour);
        }
        self.suivis.retain(|s| s.attente.is_some() || !s.passages.is_empty());
        self.borne()
    }

    /// Les règles dont les « non vérifié » passagers de la semaine se sont le plus souvent résolus au bilan suivant
    /// (deux au moins, plus de la moitié) : la règle, les passagers, les résolus.
    pub(crate) fn a_relancer(&self, jour: i32) -> Vec<(RegleId, u32, u32)> {
        let debut = jour.saturating_sub(SEMAINE.saturating_sub(1));
        self.suivis
            .iter()
            .filter_map(|s| {
                let semaine = s.passages.iter().filter(|p| p.jour >= debut && p.jour <= jour);
                let n = u32::try_from(semaine.clone().count()).unwrap_or(u32::MAX);
                let repris = u32::try_from(semaine.filter(|p| p.repris).count()).unwrap_or(u32::MAX);
                (n >= 2 && repris.saturating_mul(2) > n).then_some((s.regle, n, repris))
            })
            .collect()
    }
}

impl Borne for EtatReglage {
    fn borne(self) -> EtatReglage {
        let c = self.compteurs().borne();
        let mut vues = BTreeSet::new();
        let mut suivis: Vec<Suivi> = self
            .suivis
            .into_iter()
            .filter(|s| vues.insert(s.regle))
            .map(|mut s| {
                s.attente = s.attente.filter(|j| jour_valable(*j));
                s.passages.retain(|p| jour_valable(p.jour));
                derniers(&mut s.passages, PASSAGES_MAX);
                s
            })
            .filter(|s| s.attente.is_some() || !s.passages.is_empty())
            .collect();
        derniers(&mut suivis, SUIVIS_MAX);
        EtatReglage {
            v: c.v,
            jour: c.jour,
            du_jour: c.du_jour,
            tours: c.tours,
            total: c.total,
            dernier: c.dernier,
            suivis,
        }
    }

    fn dans_ses_bornes(&self) -> bool {
        let mut vues = BTreeSet::new();
        self.compteurs().dans_ses_bornes()
            && self.suivis.len() <= SUIVIS_MAX
            && self.suivis.iter().all(|s| {
                vues.insert(s.regle)
                    && s.passages.len() <= PASSAGES_MAX
                    && s.passages.iter().all(|p| jour_valable(p.jour))
                    && s.attente.is_none_or(jour_valable)
                    && (s.attente.is_some() || !s.passages.is_empty())
            })
    }
}

/// Ce que la mission des corrections garde au plus de chaque sorte, et combien de jours.
pub(crate) const CORRECTIONS_MAX: usize = 64;
pub(crate) const ECHECS_JOURS: i32 = 90;
pub(crate) const SUIVIE_JOURS: i32 = 7;
pub(crate) const REVENUE_JOURS: i32 = 30;
/// Échecs de suite à partir desquels une correction se dit fragile.
pub(crate) const FRAGILE_DES: u16 = 2;
const ECHECS_PLAFOND: u16 = 999;

/// Les échecs de suite de la correction d'une règle (remis à zéro par une réussite).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Echec {
    pub regle: RegleId,
    pub n: u16,
    pub code: CodeEchec,
    /// Le jour du dernier.
    pub jour: i32,
}

/// Une correction réussie, suivie `SUIVIE_JOURS` jours : le problème corrigé revient-il à un bilan ?
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Suivie {
    pub regle: RegleId,
    pub empreinte: u64,
    pub quand_ms: i64,
    pub jour: i32,
}

/// Une correction qui n'a pas tenu : le problème est revenu à un bilan d'après.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revenue {
    pub regle: RegleId,
    pub jour: i32,
}

/// L'état de la mission des corrections (R6) : des règles, des nombres, des jours ; jamais un message ni une commande.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct EtatCorrections {
    #[serde(default)]
    pub v: u16,
    #[serde(default)]
    pub jour: i32,
    #[serde(default)]
    pub du_jour: u16,
    #[serde(default)]
    pub tours: u32,
    #[serde(default)]
    pub total: u32,
    #[serde(default, skip_serializing_if = "nul")]
    pub dernier: i32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub echecs: Vec<Echec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suivies: Vec<Suivie>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revenues: Vec<Revenue>,
}

/// Une seule entrée par règle (la dernière), dans l'ordre, `CORRECTIONS_MAX` au plus.
fn une_par_regle<T: Copy>(v: &mut Vec<T>, regle: impl Fn(&T) -> RegleId) {
    let mut vues = BTreeSet::new();
    let mut gardes: Vec<T> = v.iter().rev().copied().filter(|x| vues.insert(regle(x))).collect();
    gardes.reverse();
    derniers(&mut gardes, CORRECTIONS_MAX);
    *v = gardes;
}

impl EtatCorrections {
    /// Après les corrections `notes` et le bilan `bilan` (s'il y en a un), le jour `jour` : l'état d'après, et ce
    /// qu'il faut montrer (une correction devenue fragile, une correction qui n'a pas tenu). Pure.
    pub(crate) fn apres(
        mut self,
        jour: i32,
        notes: &[NoteCorrection],
        bilan: Option<&ResumeBilan>,
    ) -> (EtatCorrections, Vec<Proposition>) {
        let mut montrer = Vec::new();
        self = self.au_jour(jour);
        for n in notes {
            match n.issue {
                IssueCorrection::Echouee(code) => {
                    let avant = self.echecs.iter().find(|e| e.regle == n.regle).map_or(0, |e| e.n);
                    let e = Echec {
                        regle: n.regle,
                        n: avant.saturating_add(1).min(ECHECS_PLAFOND),
                        code,
                        jour,
                    };
                    self.echecs.retain(|x| x.regle != n.regle);
                    self.echecs.push(e);
                    if e.n >= FRAGILE_DES {
                        montrer.push(Proposition::CorrectionFragile {
                            regle: n.regle,
                            echecs: e.n,
                            code,
                        });
                    }
                }
                IssueCorrection::Reussie { empreinte } => {
                    self.echecs.retain(|x| x.regle != n.regle);
                    self.suivies.retain(|x| x.regle != n.regle);
                    if let Some(empreinte) = empreinte {
                        self.suivies.push(Suivie {
                            regle: n.regle,
                            empreinte,
                            quand_ms: n.quand_ms,
                            jour,
                        });
                    }
                }
            }
        }
        if let Some(b) = bilan {
            let mut encore = Vec::new();
            for s in std::mem::take(&mut self.suivies) {
                let issue = b.regles.iter().find(|(r, _)| *r == s.regle).map(|(_, i)| *i);
                let revenu = b.problemes.contains(&(s.regle, s.empreinte));
                if b.debut_ms <= s.quand_ms || issue.is_none() {
                    encore.push(s);
                } else if revenu {
                    self.revenues.retain(|r| r.regle != s.regle);
                    self.revenues.push(Revenue { regle: s.regle, jour });
                    montrer.push(Proposition::NeTientPas { regle: s.regle });
                } else {
                    // Tenue à ce bilan (le premier suit souvent la correction de près) : elle reste suivie jusqu'à
                    // `SUIVIE_JOURS`, car un réglage remis plus tard par un autre programme ne tient pas non plus.
                    if issue == Some(Issue::Concluse) {
                        self.revenues.retain(|r| r.regle != s.regle);
                    }
                    encore.push(s);
                }
            }
            self.suivies = encore;
        }
        (self.borne(), montrer)
    }

    /// L'état le jour `jour` : ce qui a passé sa durée (`ECHECS_JOURS`, `SUIVIE_JOURS`, `REVENUE_JOURS`) s'oublie,
    /// même sans tour depuis. Pure.
    pub(crate) fn au_jour(mut self, jour: i32) -> EtatCorrections {
        self.echecs.retain(|e| e.jour >= jour.saturating_sub(ECHECS_JOURS));
        self.suivies.retain(|s| s.jour >= jour.saturating_sub(SUIVIE_JOURS));
        self.revenues.retain(|r| r.jour >= jour.saturating_sub(REVENUE_JOURS));
        self.borne()
    }

    /// Ce qui se dit d'une correction de `regle` : ses échecs de suite (s'ils la disent fragile) et son code, et si
    /// elle n'a pas tenu.
    pub(crate) fn avis(&self, regle: RegleId) -> (Option<(u16, CodeEchec)>, bool) {
        (
            self.echecs
                .iter()
                .find(|e| e.regle == regle && e.n >= FRAGILE_DES)
                .map(|e| (e.n, e.code)),
            self.revenues.iter().any(|r| r.regle == regle),
        )
    }

    pub(crate) fn compteurs(&self) -> Compteurs {
        Compteurs {
            v: self.v,
            jour: self.jour,
            du_jour: self.du_jour,
            tours: self.tours,
            total: self.total,
            dernier: self.dernier,
        }
    }

    pub(crate) fn avec_compteurs(mut self, c: Compteurs) -> EtatCorrections {
        self.v = c.v;
        self.jour = c.jour;
        self.du_jour = c.du_jour;
        self.tours = c.tours;
        self.total = c.total;
        self.dernier = c.dernier;
        self.borne()
    }
}

impl Borne for EtatCorrections {
    fn borne(mut self) -> EtatCorrections {
        let c = self.compteurs().borne();
        self.echecs.retain(|e| jour_valable(e.jour) && e.n >= 1);
        for e in &mut self.echecs {
            e.n = e.n.min(ECHECS_PLAFOND);
        }
        self.suivies.retain(|s| jour_valable(s.jour));
        self.revenues.retain(|r| jour_valable(r.jour));
        une_par_regle(&mut self.echecs, |e| e.regle);
        une_par_regle(&mut self.suivies, |s| s.regle);
        une_par_regle(&mut self.revenues, |r| r.regle);
        EtatCorrections {
            v: c.v,
            jour: c.jour,
            du_jour: c.du_jour,
            tours: c.tours,
            total: c.total,
            dernier: c.dernier,
            ..self
        }
    }

    fn dans_ses_bornes(&self) -> bool {
        fn unique<T>(v: &[T], regle: impl Fn(&T) -> RegleId) -> bool {
            let mut vues = BTreeSet::new();
            v.len() <= CORRECTIONS_MAX && v.iter().all(|x| vues.insert(regle(x)))
        }
        self.compteurs().dans_ses_bornes()
            && unique(&self.echecs, |e| e.regle)
            && unique(&self.suivies, |s| s.regle)
            && unique(&self.revenues, |r| r.regle)
            && self
                .echecs
                .iter()
                .all(|e| jour_valable(e.jour) && (1..=ECHECS_PLAFOND).contains(&e.n))
            && self.suivies.iter().all(|s| jour_valable(s.jour))
            && self.revenues.iter().all(|r| jour_valable(r.jour))
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
        MissionId::Corrections => ETAT_CORRECTIONS,
    }
}

#[cfg(not(fuzzing))]
pub(crate) fn lire_dans<E: DeserializeOwned + Default + Borne>(dossier: &std::path::Path, nom: &str) -> Lu<E> {
    match crate::sceau::juge_dans(dossier, nom) {
        crate::sceau::Juge::Absent => Lu::Absent,
        crate::sceau::Juge::Cru(o) => cru(&o),
        _ => Lu::Douteux,
    }
}

/// `lire_dans` sans rien écrire ni créer (`sceau::juge_sans_ecrire_dans`) : ce que lit `vanguard agent --json`.
#[cfg(not(fuzzing))]
pub(crate) fn lire_sans_ecrire_dans<E: DeserializeOwned + Default + Borne>(
    dossier: &std::path::Path,
    nom: &str,
) -> Lu<E> {
    match crate::sceau::juge_sans_ecrire_dans(dossier, nom) {
        crate::sceau::Juge::Absent => Lu::Absent,
        crate::sceau::Juge::Cru(o) => cru(&o),
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

    fn r(id: &str) -> RegleId {
        RegleId::depuis(id).unwrap()
    }

    fn bilan(debut_ms: i64, regles: &[(&str, Issue)], problemes: &[(&str, u64)]) -> ResumeBilan {
        ResumeBilan {
            debut_ms,
            regles: regles.iter().map(|(x, i)| (r(x), *i)).collect(),
            problemes: problemes.iter().map(|(x, e)| (r(x), *e)).collect(),
        }
    }

    fn note(regle: &str, issue: IssueCorrection, quand_ms: i64) -> NoteCorrection {
        NoteCorrection {
            regle: r(regle),
            issue,
            quand_ms,
        }
    }

    proptest! {
        /// Les états du réglage et des corrections, lus de n'importe quels octets ou d'un fichier aux listes et aux
        /// jours hostiles, restent dans leurs bornes ; un tour de plus aussi.
        #[test]
        fn les_etats_d_a6_restent_dans_leurs_bornes(
            octets in proptest::collection::vec(any::<u8>(), 0..200),
            jours in proptest::collection::vec(any::<i32>(), 0..80),
            n in any::<u16>(),
            issues in proptest::collection::vec(0u8..3, 0..20),
        ) {
            prop_assert!(lire_de::<EtatReglage>(&octets).dans_ses_bornes());
            prop_assert!(lire_de::<EtatCorrections>(&octets).dans_ses_bornes());
            let regle = |i: usize| format!("LNX-TST-{:03}", i % 3);
            let suivis: Vec<String> = jours
                .iter()
                .enumerate()
                .map(|(i, j)| format!(r#"{{"regle":"{}","attente":{j},"passages":[{{"jour":{j},"repris":true}}]}}"#, regle(i)))
                .collect();
            let json = format!(r#"{{"v":1,"jour":{},"suivis":[{}]}}"#, jours.first().unwrap_or(&0), suivis.join(","));
            let e = lire_de::<EtatReglage>(json.as_bytes());
            prop_assert!(e.dans_ses_bornes());
            let echecs: Vec<String> = jours
                .iter()
                .enumerate()
                .map(|(i, j)| format!(r#"{{"regle":"{}","n":{n},"code":"echoue","jour":{j}}}"#, regle(i)))
                .collect();
            let json = format!(r#"{{"v":1,"echecs":[{}]}}"#, echecs.join(","));
            let c = lire_de::<EtatCorrections>(json.as_bytes());
            prop_assert!(c.dans_ses_bornes());
            let j = JOUR_MIN + 100;
            let b = bilan(5, &[("LNX-TST-000", Issue::Passagere), ("LNX-TST-001", Issue::Concluse)], &[("LNX-TST-001", 9)]);
            prop_assert!(e.suivre(j, &b).dans_ses_bornes());
            let notes: Vec<NoteCorrection> = issues
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    let issue = match k {
                        0 => IssueCorrection::Echouee(CodeEchec::Echoue),
                        1 => IssueCorrection::Reussie { empreinte: Some(9) },
                        _ => IssueCorrection::Reussie { empreinte: None },
                    };
                    note(&regle(i), issue, 1)
                })
                .collect();
            let (apres, montrer) = c.apres(j, &notes, Some(&b));
            prop_assert!(apres.dans_ses_bornes());
            prop_assert!(montrer.len() <= notes.len().saturating_add(CORRECTIONS_MAX));
        }
    }

    /// R4 : un passager se suit jusqu'au bilan suivant ; deux sur trois résolus dans la semaine valent un second
    /// essai, la moitié non ; une semaine plus tard, tout s'oublie.
    #[test]
    fn un_passager_resolu_au_bilan_suivant_se_compte() {
        let j = JOUR_MIN + 50;
        let p = |x| bilan(1, &[("LNX-TST-010", x)], &[]);
        let mut e = EtatReglage::default().borne();
        for (d, issue) in [
            (0, Issue::Passagere),
            (1, Issue::Concluse),
            (2, Issue::Passagere),
            (3, Issue::Autre),
            (4, Issue::Passagere),
        ] {
            e = e.suivre(j + d, &p(issue));
        }
        // Deux passages, un résolu : la moitié, pas plus.
        assert_eq!(e.a_relancer(j + 4), []);
        e = e.suivre(j + 5, &p(Issue::Concluse));
        assert_eq!(e.a_relancer(j + 5), [(r("LNX-TST-010"), 3, 2)]);
        // Une règle jamais passagère n'est pas suivie.
        let autre = EtatReglage::default()
            .borne()
            .suivre(j, &bilan(1, &[("LNX-TST-011", Issue::Concluse)], &[]));
        assert_eq!(autre.suivis, []);
        // Huit jours plus tard, la semaine est passée.
        assert_eq!(e.clone().suivre(j + 13, &bilan(1, &[], &[])).a_relancer(j + 13), []);
        assert_eq!(e.suivre(j + 13, &bilan(1, &[], &[])).suivis, []);
    }

    /// R6 : deux échecs de suite disent une correction fragile (une réussite remet à zéro) ; un problème corrigé
    /// qui revient à un bilan de la semaine, de la même empreinte, dit qu'elle ne tient pas ; un bilan commencé avant la
    /// correction, ou qui n'a pas relancé sa règle, ne juge rien.
    #[test]
    fn echecs_de_suite_et_correction_revenue() {
        let j = JOUR_MIN + 50;
        let echec = note("LNX-TST-010", IssueCorrection::Echouee(CodeEchec::Echoue), 10);
        let (e, m) = EtatCorrections::default().apres(j, &[echec], None);
        assert_eq!(m, []);
        assert_eq!(e.avis(r("LNX-TST-010")), (None, false));
        let (e, m) = e.apres(j + 1, &[echec], None);
        assert_eq!(
            m,
            [Proposition::CorrectionFragile {
                regle: r("LNX-TST-010"),
                echecs: 2,
                code: CodeEchec::Echoue
            }]
        );
        assert_eq!(e.avis(r("LNX-TST-010")), (Some((2, CodeEchec::Echoue)), false));
        // Réussie : plus fragile, et suivie.
        let reussie = note("LNX-TST-010", IssueCorrection::Reussie { empreinte: Some(7) }, 1_000);
        let (e, m) = e.apres(j + 2, &[reussie], None);
        assert_eq!(m, []);
        assert_eq!(e.avis(r("LNX-TST-010")), (None, false));
        // Un bilan d'avant la correction, puis un qui n'a pas lancé la règle, puis un passager : rien n'est jugé.
        let (e, m) = e.apres(
            j + 2,
            &[],
            Some(&bilan(900, &[("LNX-TST-010", Issue::Concluse)], &[("LNX-TST-010", 7)])),
        );
        assert_eq!(m, []);
        let (e, m) = e.apres(
            j + 2,
            &[],
            Some(&bilan(2_000, &[("LNX-TST-011", Issue::Concluse)], &[])),
        );
        assert_eq!(m, []);
        let (e, m) = e.apres(
            j + 2,
            &[],
            Some(&bilan(2_000, &[("LNX-TST-010", Issue::Passagere)], &[])),
        );
        assert_eq!(m, []);
        assert_eq!(e.suivies.len(), 1);
        // Le problème d'une autre empreinte n'est pas le même.
        let (autre, m) = e.clone().apres(
            j + 3,
            &[],
            Some(&bilan(
                2_000,
                &[("LNX-TST-010", Issue::Concluse)],
                &[("LNX-TST-010", 8)],
            )),
        );
        assert_eq!(m, []);
        assert_eq!(autre.revenues, []);
        // Tenue au bilan qui suit la correction, elle reste suivie : revenue trois jours plus tard, elle ne tient pas.
        assert_eq!(autre.suivies.len(), 1);
        let (plus_tard, m) = autre.apres(
            j + 6,
            &[],
            Some(&bilan(
                9_000,
                &[("LNX-TST-010", Issue::Concluse)],
                &[("LNX-TST-010", 7)],
            )),
        );
        assert_eq!(
            m,
            [Proposition::NeTientPas {
                regle: r("LNX-TST-010")
            }]
        );
        assert_eq!(plus_tard.suivies, []);
        // Au-delà de `SUIVIE_JOURS`, plus rien n'est suivi.
        let (vieille, _) = e.clone().apres(j + 3 + SUIVIE_JOURS, &[], None);
        assert_eq!(vieille.suivies, []);
        // Revenu : ne tient pas, dit une fois.
        let (e, m) = e.apres(
            j + 3,
            &[],
            Some(&bilan(
                2_000,
                &[("LNX-TST-010", Issue::Concluse)],
                &[("LNX-TST-010", 7)],
            )),
        );
        assert_eq!(
            m,
            [Proposition::NeTientPas {
                regle: r("LNX-TST-010")
            }]
        );
        assert_eq!(e.avis(r("LNX-TST-010")), (None, true));
        let (e, m) = e.apres(
            j + 4,
            &[],
            Some(&bilan(
                3_000,
                &[("LNX-TST-010", Issue::Concluse)],
                &[("LNX-TST-010", 7)],
            )),
        );
        assert_eq!(m, []);
        // L'avis tient trente jours.
        assert!(
            e.clone()
                .apres(j + 3 + REVENUE_JOURS, &[], None)
                .0
                .avis(r("LNX-TST-010"))
                .1
        );
        assert!(!e.apres(j + 4 + REVENUE_JOURS, &[], None).0.avis(r("LNX-TST-010")).1);
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
        // Une mission inconnue dans les interrupteurs : rien n'en est cru ; scellé, le fichier est douteux (toutes
        // coupées, `lire_dans`), pas l'état d'origine qui les remettrait en marche.
        assert!(
            lire_de::<Interrupteurs>(br#"{"v":1,"coupees":["rogue-x"]}"#)
                .coupees
                .is_empty()
        );
        assert!(matches!(
            cru::<Interrupteurs>(br#"{"v":1,"coupees":["rogue-x","cache"]}"#),
            Lu::Douteux
        ));
        assert!(matches!(cru::<Compteurs>(br#"{"v":1,"neuf":1}"#), Lu::Cru(c) if c == Compteurs::default().borne()));
    }
}
