//! Ce que l'agent dit de lui-même, lu de ses seuls fichiers et sans rien écrire : `vanguard agent --json` et l'écran
//! de Paramètres (`parametres::agent`) lisent la même vue.
//!
//! La sortie JSON, schéma 1 (`SCHEMA`). Un champ ne change de sens qu'avec un schéma neuf ; un champ de plus peut
//! s'ajouter sans changer de schéma. Aucun chemin, aucun nom d'ordinateur ou de compte, aucun texte venu de
//! l'ordinateur : des noms de la liste fermée, des identifiants de règle (« LNX-NOY-001 »), des nombres et des dates.
//! Rien de l'heure de la demande : deux demandes sans tour entre elles rendent les mêmes octets.
//!
//! - `schema` : 1 ;
//! - `agent` : « en-marche », « coupe » (Paramètres, « non ») ou « douteux » (son fichier a changé hors de Vanguard :
//!   rien n'est réglé) ;
//! - `interrupteurs` : « absent » (toutes les missions en marche), « intact » ou « douteux » (seule une détection
//!   tourne) ;
//! - `journal` : « absent », « intact », « douteux » (son sceau) ou « rompu » (sa chaîne) ; douteux ou rompu, aucune
//!   de ses lignes n'est montrée et l'agent ne prend plus de tour jusqu'à « tout remettre » ;
//! - `tout_remis` : la date de « tout remettre » (secondes depuis 1970, UTC), ou `null` ;
//! - `missions` : dans l'ordre des tours, chacune avec
//!   - `nom` : « reglage », « cache », « releve » ou « corrections » ; `genre` : « reglage », « releve » ou
//!     « detection » ;
//!   - `etat` : « en-marche », « coupee » (elle ne prend aucun tour) ou « sautee » (elle prendrait son tour, mais
//!     un fichier douteux l'arrête) ; `pourquoi` : `null` en marche, sinon « agent-coupe », « agent-douteux »,
//!     « coupee-ici » (son interrupteur dans Paramètres), « interrupteurs-douteux », « etat-douteux » ou
//!     « journal-douteux » ;
//!   - `dernier_tour` : le jour de son dernier tour (« AAAA-MM-JJ », jour de l'ordinateur), ou `null` ;
//!   - `tours`, `decisions_total` : ce qu'elle a jugé depuis le début (`null` pour le relevé, qui ne décide rien) ;
//!   - `decisions` : ses `DECISIONS_MAX` dernières au journal, la plus récente d'abord : `quand` (secondes depuis
//!     1970, UTC), `sorte` (« appliquee », « montree » ou « refusee »), `decision` (telle qu'au journal : un
//!     ajustement, son levier et sa mesure ; une proposition ; un signal) et `raison`, en mot fermé
//!     (« frole-son-delai », « contredite-a-neuf », « juste-de-suite », « trop-d-ecarts », « reprise-au-bilan-suivant »,
//!     « a-revoir », « echecs-de-suite », « probleme-revenu », « nouveaute », « non-permise »).

use std::path::Path;

use serde::Serialize;

use super::decision::{Decision, Levier, Proposition, Signal};
use super::etat::{self, Compteurs, EtatCorrections, EtatReglage, Interrupteurs, Lu};
use super::forme::{Genre, MissionId};
use super::journal::{self, Entree, Fait};

pub(crate) const SCHEMA: u16 = 1;
/// Les décisions montrées au plus par mission.
pub(crate) const DECISIONS_MAX: usize = 16;

/// L'interrupteur de l'agent entier (celui de l'auto-réglage).
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EtatAgent {
    EnMarche,
    Coupe,
    Douteux,
}

/// Ce qu'un fichier de l'agent vaut à la lecture.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Fichier {
    Absent,
    Intact,
    Douteux,
    /// Le journal seulement : scellé, mais sa chaîne ne tient pas.
    Rompu,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum EtatMission {
    EnMarche,
    Coupee,
    Sautee,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Pourquoi {
    AgentCoupe,
    AgentDouteux,
    CoupeeIci,
    InterrupteursDouteux,
    EtatDouteux,
    JournalDouteux,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum GenreVu {
    Reglage,
    Releve,
    Detection,
}

impl From<Genre> for GenreVu {
    fn from(g: Genre) -> GenreVu {
        match g {
            Genre::Reglage => GenreVu::Reglage,
            Genre::Releve => GenreVu::Releve,
            Genre::Detection => GenreVu::Detection,
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Sorte {
    /// Un ajustement appliqué.
    Appliquee,
    /// Une proposition ou un signal, à montrer.
    Montree,
    /// Refusée par le tour : hors du genre de la mission, d'un levier qui n'est pas le sien, ou hors du sens sûr.
    Refusee,
}

/// Pourquoi la mission a décidé, d'après la sorte de la décision : un mot fermé, jamais un texte.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Raison {
    /// Un délai monté : la règle frôle son délai (la mesure : sa plus longue durée de la semaine, en ms).
    FroleSonDelai,
    /// Une durée de cache raccourcie : une vérification à neuf a contredit le résultat repris (la mesure : les écarts).
    ContrediteANeuf,
    /// Un pas de raccourci défait : des vérifications à neuf justes de suite (la mesure : leur nombre).
    JusteDeSuite,
    /// Une cache coupée : trop d'écarts en 14 jours (la mesure : les écarts).
    TropDEcarts,
    /// Un second essai : ses « non vérifiée » passagers ont surtout conclu au bilan suivant.
    RepriseAuBilanSuivant,
    ARevoir,
    EchecsDeSuite,
    ProblemeRevenu,
    Nouveaute,
    /// Une décision refusée.
    NonPermise,
}

pub(crate) fn raison(sorte: Sorte, d: &Decision) -> Raison {
    if sorte == Sorte::Refusee {
        return Raison::NonPermise;
    }
    match d {
        Decision::Ajuster(a) => match a.levier {
            Levier::Delai { .. } => Raison::FroleSonDelai,
            Levier::Cache { .. } => Raison::ContrediteANeuf,
            Levier::CacheRallonge { .. } => Raison::JusteDeSuite,
            Levier::CacheCoupee { .. } => Raison::TropDEcarts,
            Levier::SecondEssai { .. } => Raison::RepriseAuBilanSuivant,
        },
        Decision::Proposer(Proposition::RevoirRegle { .. }) => Raison::ARevoir,
        Decision::Proposer(Proposition::CorrectionFragile { .. }) => Raison::EchecsDeSuite,
        Decision::Proposer(Proposition::NeTientPas { .. }) => Raison::ProblemeRevenu,
        Decision::Signaler(Signal::Nouveaute { .. }) => Raison::Nouveaute,
    }
}

/// Un jour compté depuis 1970, écrit « AAAA-MM-JJ ».
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Jour(pub i32);

impl Jour {
    pub(crate) fn date(self) -> Option<chrono::NaiveDate> {
        chrono::NaiveDate::default().checked_add_signed(chrono::Duration::days(i64::from(self.0)))
    }
}

impl Serialize for Jour {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.date() {
            Some(d) => s.collect_str(&d.format("%Y-%m-%d")),
            None => s.serialize_none(),
        }
    }
}

/// Une décision du journal, telle qu'elle se montre.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DecisionVue {
    pub quand: i64,
    pub sorte: Sorte,
    pub decision: Decision,
    pub raison: Raison,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct MissionVue {
    pub nom: MissionId,
    pub genre: GenreVu,
    pub etat: EtatMission,
    pub pourquoi: Option<Pourquoi>,
    pub dernier_tour: Option<Jour>,
    pub tours: Option<u32>,
    pub decisions_total: Option<u32>,
    pub decisions: Vec<DecisionVue>,
}

/// La vue entière : voir le commentaire du module.
#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Vue {
    pub schema: u16,
    pub agent: EtatAgent,
    pub interrupteurs: Fichier,
    pub journal: Fichier,
    pub tout_remis: Option<i64>,
    pub missions: Vec<MissionVue>,
}

/// Une ligne du journal, en sorte et décision ; « tout remettre » n'en est pas une.
pub(crate) fn de_fait(f: &Fait) -> Option<(MissionId, Sorte, Decision)> {
    match *f {
        Fait::Decision {
            mission,
            decision: d @ Decision::Ajuster(_),
        } => Some((mission, Sorte::Appliquee, d)),
        Fait::Decision { mission, decision } => Some((mission, Sorte::Montree, decision)),
        Fait::Refus { mission, decision } => Some((mission, Sorte::Refusee, decision)),
        Fait::ToutRemis => None,
    }
}

/// Le journal lu sans rien écrire : ce qu'il vaut, et ses lignes, la plus récente d'abord (aucune s'il est douteux
/// ou rompu : ce qu'il dit n'est pas cru).
pub(crate) fn journal_dans(dossier: &Path) -> (Fichier, Vec<Entree>) {
    match crate::sceau::juge_sans_ecrire_dans(dossier, journal::JOURNAL) {
        crate::sceau::Juge::Absent => (Fichier::Absent, Vec::new()),
        crate::sceau::Juge::Cru(o) => {
            let j = journal::lire_de(&o, super::empreinte);
            if j.intact() {
                (Fichier::Intact, j.entrees.into_iter().rev().collect())
            } else {
                (Fichier::Rompu, Vec::new())
            }
        }
        _ => (Fichier::Douteux, Vec::new()),
    }
}

/// Les compteurs de la mission `id` (son état, lu à sa forme) ; `None` : son fichier est douteux.
fn compteurs_dans(dossier: &Path, id: MissionId) -> Option<Compteurs> {
    let nom = etat::nom_etat(id);
    match id {
        MissionId::Reglage => etat::lire_sans_ecrire_dans::<EtatReglage>(dossier, nom)
            .utilisable()
            .map(|e| e.compteurs()),
        MissionId::Corrections => etat::lire_sans_ecrire_dans::<EtatCorrections>(dossier, nom)
            .utilisable()
            .map(|e| e.compteurs()),
        MissionId::Cache | MissionId::Releve => etat::lire_sans_ecrire_dans::<Compteurs>(dossier, nom).utilisable(),
    }
}

/// L'état d'une mission comme le tour le jugerait (`super::tic_dans`), dans le même ordre : l'agent coupé, le
/// journal, les interrupteurs, l'interrupteur de l'agent pour un réglage, l'état de la mission.
fn etat_de(
    genre: Genre,
    id: MissionId,
    agent: Option<bool>,
    journal: Fichier,
    interrupteurs: Option<&Interrupteurs>,
    etat_lisible: bool,
) -> (EtatMission, Option<Pourquoi>) {
    let coupee = |p| (EtatMission::Coupee, Some(p));
    if agent == Some(false) {
        return coupee(Pourquoi::AgentCoupe);
    }
    if matches!(journal, Fichier::Douteux | Fichier::Rompu) {
        return (EtatMission::Sautee, Some(Pourquoi::JournalDouteux));
    }
    match interrupteurs {
        None if genre != Genre::Detection => return coupee(Pourquoi::InterrupteursDouteux),
        Some(i) if i.coupees.contains(&id) => return coupee(Pourquoi::CoupeeIci),
        _ => {}
    }
    if genre == Genre::Reglage && agent != Some(true) {
        return coupee(Pourquoi::AgentDouteux);
    }
    if !etat_lisible {
        return (EtatMission::Sautee, Some(Pourquoi::EtatDouteux));
    }
    (EtatMission::EnMarche, None)
}

/// La mission prendrait-elle son tour, comme `super::tic_dans` en juge (l'agent, le journal, les interrupteurs, son
/// état) : la cache du passage horaire ne sert que si sa mission tourne, elle qui la corrige.
pub(crate) fn en_marche_dans(dossier: &Path, id: MissionId) -> bool {
    vue_dans(dossier)
        .missions
        .iter()
        .any(|m| m.nom == id && m.etat == EtatMission::EnMarche)
}

/// La vue de l'agent dans `dossier`, sans rien écrire.
pub(crate) fn vue_dans(dossier: &Path) -> Vue {
    let agent = crate::autotest::reglage::en_marche_sans_ecrire_dans(dossier);
    let lu = etat::lire_sans_ecrire_dans::<Interrupteurs>(dossier, etat::AGENT);
    let fichier_interrupteurs = match lu {
        Lu::Absent => Fichier::Absent,
        Lu::Cru(_) => Fichier::Intact,
        Lu::Douteux => Fichier::Douteux,
    };
    let interrupteurs = lu.utilisable();
    let (fichier_journal, entrees) = journal_dans(dossier);
    let tout_remis = entrees.iter().find(|e| e.fait == Fait::ToutRemis).map(|e| e.quand);
    let missions = super::missions()
        .iter()
        .map(|m| {
            let id = m.id();
            let c = compteurs_dans(dossier, id);
            let (etat, pourquoi) = etat_de(
                m.genre(),
                id,
                agent,
                fichier_journal,
                interrupteurs.as_ref(),
                c.is_some(),
            );
            let c = c.unwrap_or_default();
            let decide = id != MissionId::Releve;
            MissionVue {
                nom: id,
                genre: m.genre().into(),
                etat,
                pourquoi,
                dernier_tour: (c.dernier != 0).then_some(Jour(c.dernier)),
                tours: decide.then_some(c.tours),
                decisions_total: decide.then_some(c.total),
                decisions: entrees
                    .iter()
                    .filter_map(|e| {
                        let (mission, sorte, decision) = de_fait(&e.fait)?;
                        (mission == id).then(|| DecisionVue {
                            quand: e.quand,
                            sorte,
                            decision,
                            raison: raison(sorte, &decision),
                        })
                    })
                    .take(DECISIONS_MAX)
                    .collect(),
            }
        })
        .collect();
    Vue {
        schema: SCHEMA,
        agent: match agent {
            Some(true) => EtatAgent::EnMarche,
            Some(false) => EtatAgent::Coupe,
            None => EtatAgent::Douteux,
        },
        interrupteurs: fichier_interrupteurs,
        journal: fichier_journal,
        tout_remis,
        missions,
    }
}

/// `vanguard agent --json` : la vue, en JSON indenté, suivie d'un saut de ligne.
pub(crate) fn json_dans(dossier: &Path) -> Vec<u8> {
    let mut o = serde_json::to_vec_pretty(&vue_dans(dossier)).unwrap_or_default();
    o.push(b'\n');
    o
}
