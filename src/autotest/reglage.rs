//! L'auto-réglage local du bilan : ce que Vanguard ajuste de lui-même, sur cet ordinateur, d'après les durées
//! mesurées de ses règles (`super::mesures`). Rien ne sort de l'ordinateur, rien ne passe par une IA.
//!
//! Ce qui peut bouger, et seulement entre des bornes écrites ici :
//! - l'**ordre de départ** des règles, la plus longue d'abord (médiane de la semaine), pour que le bilan ne finisse
//!   pas sur elle. Les règles tournent toutes en même temps, chacune dans son fil ; l'ordre ne change ni ce qu'elles
//!   rendent ni l'ordre affiché (celui des rangs) ;
//! - le **délai** d'une règle qui frôle le sien (sa plus longue durée de la semaine au-delà de la moitié) deux
//!   semaines de suite, ou qui en sort deux fois en 7 jours (R1) : il monte de `DELAI` à `DELAI_LONG`, jamais plus
//!   haut, jamais sous la valeur du code. Chaque montée est notée (date, règle, avant, après, mesure), 50 au plus,
//!   dans `autotest/reglage.json`, scellé ;
//! - un **second essai** (R4) pour une règle dont les « non vérifiée » passagers de la semaine se résolvent d'ordinaire
//!   au bilan suivant : une fois, à la fin du bilan, jamais au-delà de `DELAI_LONG` depuis son début ; le second
//!   résultat ne remplace le premier que s'il conclut (`machine::regles_lancees`) ;
//! - la **durée de la cache** du passage horaire (`super::cache`) d'une règle dont le résultat repris s'est révélé
//!   dépassé (R2, un écart parmi les vérifications à neuf qui suivent une reprise) : elle descend de 15 minutes,
//!   jamais sous le plancher de `cache::TABLE` ; après 20 vérifications justes de suite, le dernier pas se défait,
//!   jamais au-dessus de la durée du code. Plus de 2 % d'écarts sur 14 jours (R3) : la règle n'est plus reprise du
//!   tout. Seules les règles de la table, qui ne peuvent pas trahir une attaque en cours (`cache::EXCLUES`). La
//!   cache elle-même suit l'interrupteur : coupé ou fichier douteux, rien n'est repris.
//!
//! Chaque montée, durée raccourcie ou coupée et second essai s'annule seul dans Paramètres (la règle n'est plus
//! jamais changée),
//! « tout remettre » vide le fichier et coupe le réglage, l'interrupteur à « non » rend les valeurs du code sans rien
//! oublier ; chacun de ces gestes vide aussi la cache. Fichier douteux (sceau) : les valeurs du code, et rien n'y est
//! réécrit tout seul.
//!
//! Ce qui ne bouge **jamais** ici : un seuil, un niveau, une règle ou une liste de détection, le blocage, la fraîcheur
//! des sources de menaces ; un bilan lance toujours toutes ses règles. Ce module n'importe ni `risk` ni un module de
//! détection (garde : `reglage_ne_touche_pas_la_detection`).
//!
//! Deux processus (surveillance et Paramètres) peuvent écrire en même temps : la surveillance relit le fichier juste
//! avant d'écrire et n'écrit pas s'il a changé depuis sa lecture, donc un changement voulu n'est pas écrasé. Reste
//! l'instant entre cette relecture et l'écriture (une passe par heure) ; au pire une montée se perd et revient.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::machine::regles::{DELAI, DELAI_LONG};
use crate::ui::*;
use crate::{tr, trf, trp};

/// Le fichier, sous le dossier de données. Scellé : il décide du délai de règles du bilan.
pub(crate) const REGLAGE: &str = "autotest/reglage.json";
/// Au-delà, ce n'est pas le fichier de Vanguard (50 montées font quelques Kio).
const TAILLE_MAX: usize = 256 << 10;
/// Montées gardées au plus : autant de règles au délai monté.
const MONTEES_MAX: usize = 50;
/// Règles suivies (qui frôlent) ou refusées (montée annulée), au plus chacune.
const SUIVIES_MAX: usize = 200;
/// Une règle qui frôle encore son délai 7 jours après la première fois (deux semaines de mesures qui ne se recouvrent
/// pas) voit le sien monter.
const JOURS_DE_SUITE: i64 = 7;

/// Une montée de délai.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Montee {
    /// Le jour (« AAAA-MM-JJ »).
    pub quand: String,
    pub regle: String,
    /// Les délais d'avant et d'après, en secondes.
    pub avant_s: u64,
    pub apres_s: u64,
    /// La mesure qui l'a décidée : sa plus longue durée de la semaine (ms).
    pub mesure_ms: u64,
}

/// Un pas de raccourci d'une durée de la cache (`super::cache::TABLE`) : chaque pas part de la durée laissée par le
/// précédent, si bien qu'on les défait un par un, exactement.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Raccourcie {
    /// Le jour (« AAAA-MM-JJ ») de ce pas.
    pub quand: String,
    pub regle: String,
    /// La durée d'avant ce pas (celle du code, ou celle du pas précédent) et d'après, en minutes.
    pub avant_min: u16,
    pub apres_min: u16,
    /// Ce qui l'a décidée : les vérifications à neuf jugées, et celles qui contredisaient le résultat repris.
    pub comparees: u32,
    pub ecarts: u32,
    /// La date (secondes depuis 1970) de la dernière vérification jugée : un nouveau raccourci ne juge que les
    /// suivantes.
    pub depuis_s: i64,
}

/// Vérifications à neuf de suite sans un écart, après un pas de raccourci, avant que la durée remonte d'un pas
/// (jamais au-dessus de celle du code : seul un pas de l'agent se défait ainsi).
const RALLONGE_SANS_ECART: usize = 20;
/// La coupure de la cache d'une règle : plus de 2 % d'écarts (un sur cinquante) sur les 14 derniers jours, jugés sur
/// 50 vérifications à neuf au moins.
const COUPE_JOURS: i64 = 14;
const COUPE_COMPAREES_MIN: usize = 50;
const COUPE_UNE_SUR: usize = 50;

/// Une coupure de la cache d'une règle de `cache::TABLE` : son résultat n'est plus jamais repris, chaque passage la
/// vérifie à neuf (le sens sûr : plus de vérifications, jamais moins).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Coupure {
    /// Le jour (« AAAA-MM-JJ »).
    pub quand: String,
    pub regle: String,
    /// Ce qui l'a décidée : les vérifications à neuf des 14 jours, et celles qui contredisaient le résultat repris.
    pub comparees: u32,
    pub ecarts: u32,
}

/// Un pas de raccourci défait par l'agent : 20 vérifications à neuf de suite l'ont donné juste. Pas gardé dans le
/// fichier (le pas disparaît, la durée revient à celle d'avant lui) ; noté au journal de l'agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Rallongee {
    pub regle: String,
    /// La durée d'avant (celle du pas défait) et d'après (celle d'avant ce pas), en minutes.
    pub avant_min: u16,
    pub apres_min: u16,
    pub comparees: u32,
    /// La dernière vérification jugée : un nouveau jugement ne voit que les suivantes.
    pub depuis_s: i64,
}

/// Un second essai permis à une règle du bilan (R4) : une règle dont les « non vérifiée » passagers (délai,
/// illisible) de la semaine se sont le plus souvent résolus au bilan suivant est relancée une fois, à la fin du bilan,
/// dans le temps qui reste avant `DELAI_LONG`. Son second résultat ne remplace le premier que s'il conclut : un essai
/// de plus ne retire jamais un constat.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Relance {
    /// Le jour (« AAAA-MM-JJ »).
    pub quand: String,
    pub regle: String,
    /// Ce qui l'a décidée : les « non vérifiée » passagers de la semaine, et ceux résolus au bilan suivant.
    pub passageres: u32,
    pub reprises: u32,
}

/// L'état de l'auto-réglage.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Etat {
    #[serde(default)]
    pub v: u16,
    /// Coupé (« non » dans Paramètres, ou « tout remettre ») : les délais du code, rien n'est ajusté.
    #[serde(default)]
    pub coupe: bool,
    /// Les montées en vigueur, dans l'ordre où elles sont venues.
    #[serde(default)]
    pub montees: Vec<Montee>,
    /// Les règles qui frôlent leur délai, et depuis quel jour.
    #[serde(default)]
    pub frolent_depuis: BTreeMap<String, String>,
    /// Les règles dont la montée a été annulée : jamais remontées.
    #[serde(default)]
    pub refusees: BTreeSet<String>,
    /// Les pas de raccourci des durées de la cache, dans l'ordre où ils sont venus : pour chaque règle de
    /// `cache::TABLE`, une chaîne qui part de la durée du code et descend de 15 minutes à chaque pas.
    #[serde(default)]
    pub raccourcies: Vec<Raccourcie>,
    /// Les règles dont un raccourci ou une coupure a été annulé : l'agent ne touche plus à leur durée.
    #[serde(default)]
    pub gardees: BTreeSet<String>,
    /// Les règles de la table dont un pas a été défait (R2), et la date de la dernière vérification jugée alors.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rallongees: BTreeMap<String, i64>,
    /// Les règles dont la cache est coupée (R3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coupures: Vec<Coupure>,
    /// Les règles qui ont droit à un second essai (R4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relances: Vec<Relance>,
    /// Les règles dont le second essai a été annulé : jamais redonné.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub sans_relance: BTreeSet<String>,
}

/// Ce que le fichier donne.
#[derive(Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // lu une fois par bilan ou par geste, jamais gardé en nombre
pub(crate) enum Lu {
    /// Pas encore de fichier : le réglage est en marche, rien n'est monté.
    Absent,
    Cru(Etat),
    /// Falsifié, adopté, illisible (`sceau`) : les délais du code, et rien n'y est réécrit tout seul.
    Douteux,
}

/// « AAA-AAA-000 », comme chaque règle du registre : rien d'autre ne se garde ni ne se montre.
fn id_valide(id: &str) -> bool {
    let o = id.as_bytes();
    o.len() == 11
        && o.iter().enumerate().all(|(i, c)| match i {
            0..=2 | 4..=6 => c.is_ascii_uppercase(),
            3 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

fn date(texte: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(texte, "%Y-%m-%d").ok()
}

fn jour(d: chrono::NaiveDate) -> String {
    d.format("%Y-%m-%d").to_string()
}

fn secondes(d: Duration) -> u64 {
    d.as_secs()
}

impl Etat {
    /// Serré dans ses bornes : identifiants de règle et dates bien formés, délais exactement `DELAI` → `DELAI_LONG`,
    /// une montée par règle, aucune pour une règle refusée, 50 montées et 200 règles suivies au plus.
    fn borne(mut self) -> Etat {
        let mut vues = BTreeSet::new();
        self.refusees.retain(|r| id_valide(r));
        while self.refusees.len() > SUIVIES_MAX {
            self.refusees.pop_last();
        }
        let refusees = &self.refusees;
        self.montees.retain(|m| {
            id_valide(&m.regle)
                && date(&m.quand).is_some()
                && m.avant_s == secondes(DELAI)
                && m.apres_s == secondes(DELAI_LONG)
                && !refusees.contains(&m.regle)
                && vues.insert(m.regle.clone())
        });
        self.montees.truncate(MONTEES_MAX);
        self.frolent_depuis
            .retain(|r, d| id_valide(r) && date(d).is_some() && !vues.contains(r) && !refusees.contains(r));
        while self.frolent_depuis.len() > SUIVIES_MAX {
            self.frolent_depuis.pop_last();
        }
        self.gardees.retain(|r| super::cache::en_cache(r).is_some());
        // Chaque pas part exactement d'où le précédent de la même règle s'est arrêté (la durée du code pour le
        // premier), descend d'un pas, jamais sous le plancher ; une chaîne rompue s'arrête au dernier pas valable.
        let mut laissees: BTreeMap<String, Option<u16>> = BTreeMap::new();
        self.raccourcies.retain(|r| {
            let Some(t) = super::cache::en_cache(&r.regle) else {
                return false;
            };
            let laissee = laissees.entry(r.regle.clone()).or_insert(Some(t.duree_min));
            let bon = laissee.is_some_and(|l| r.avant_min == l)
                && r.avant_min.checked_sub(r.apres_min) == Some(super::cache::PAS_MIN)
                && r.apres_min >= t.plancher_min
                && date(&r.quand).is_some();
            *laissee = if bon { Some(r.apres_min) } else { None };
            bon
        });
        self.rallongees.retain(|r, _| super::cache::en_cache(r).is_some());
        let gardees = &self.gardees;
        let mut coupees = BTreeSet::new();
        self.coupures.retain(|c| {
            super::cache::en_cache(&c.regle).is_some()
                && date(&c.quand).is_some()
                && !gardees.contains(&c.regle)
                && coupees.insert(c.regle.clone())
        });
        self.sans_relance.retain(|r| id_valide(r));
        while self.sans_relance.len() > SUIVIES_MAX {
            self.sans_relance.pop_last();
        }
        let sans = &self.sans_relance;
        let mut relancees = BTreeSet::new();
        self.relances.retain(|r| {
            id_valide(&r.regle)
                && date(&r.quand).is_some()
                && !sans.contains(&r.regle)
                && relancees.insert(r.regle.clone())
        });
        self.relances.truncate(MONTEES_MAX);
        self.v = 1;
        self
    }

    /// Dans ses bornes : `borne` n'y change rien que le numéro de version (les essais et la preuve par proptest).
    #[cfg(test)]
    fn dans_ses_bornes(&self) -> bool {
        self.clone().borne() == Etat { v: 1, ..self.clone() }
    }

    /// La durée de chaque règle raccourcie de la cache (son dernier pas), telle que le passage horaire l'applique, et
    /// 0 pour une règle coupée (jamais reprise : `cache::duree_appliquee`) ; `None` quand le réglage est coupé : pas
    /// de cache.
    fn pour_le_cache(&self) -> Option<BTreeMap<String, u16>> {
        (!self.coupe).then(|| {
            self.raccourcies
                .iter()
                .map(|r| (r.regle.clone(), r.apres_min))
                .chain(self.coupures.iter().map(|c| (c.regle.clone(), 0)))
                .collect()
        })
    }

    /// Les règles qui ont droit à un second essai, telles que le bilan les applique : aucune quand le réglage est
    /// coupé.
    fn relancees(&self) -> BTreeSet<String> {
        if self.coupe {
            BTreeSet::new()
        } else {
            self.relances.iter().map(|r| r.regle.clone()).collect()
        }
    }

    /// Les règles au délai monté, telles que le bilan les applique : aucune quand le réglage est coupé.
    pub(crate) fn delais_longs(&self) -> BTreeSet<String> {
        if self.coupe {
            BTreeSet::new()
        } else {
            self.montees.iter().map(|m| m.regle.clone()).collect()
        }
    }
}

/// Le contenu du fichier, serré dans ses bornes ; illisible ou trop gros : l'état d'origine.
pub(crate) fn lire_de(octets: &[u8]) -> Etat {
    if octets.len() > TAILLE_MAX {
        return Etat::default();
    }
    serde_json::from_slice::<Etat>(octets).map_or_else(|_| Etat::default(), Etat::borne)
}

pub(crate) fn lire_dans(dossier: &Path) -> Lu {
    match crate::sceau::juge_dans(dossier, REGLAGE) {
        crate::sceau::Juge::Absent => Lu::Absent,
        crate::sceau::Juge::Cru(o) => Lu::Cru(lire_de(&o)),
        _ => Lu::Douteux,
    }
}

/// L'interrupteur de l'auto-réglage, qui est aussi celui de l'Agent Vanguard (`agent`) : « oui » tant que rien n'est
/// écrit ; `None` quand le fichier est douteux (rien n'en est cru, l'agent ne règle rien).
pub(crate) fn en_marche_dans(dossier: &Path) -> Option<bool> {
    match lire_dans(dossier) {
        Lu::Absent => Some(true),
        Lu::Cru(e) => Some(!e.coupe),
        Lu::Douteux => None,
    }
}

/// `en_marche_dans` sans rien écrire ni créer (`sceau::juge_sans_ecrire_dans`) : ce que lit `vanguard agent --json`.
pub(crate) fn en_marche_sans_ecrire_dans(dossier: &Path) -> Option<bool> {
    match crate::sceau::juge_sans_ecrire_dans(dossier, REGLAGE) {
        crate::sceau::Juge::Absent => Some(true),
        crate::sceau::Juge::Cru(o) => Some(!lire_de(&o).coupe),
        _ => None,
    }
}

impl Lu {
    pub(crate) fn delais_longs(&self) -> BTreeSet<String> {
        match self {
            Lu::Cru(e) => e.delais_longs(),
            Lu::Absent | Lu::Douteux => BTreeSet::new(),
        }
    }

    /// Ce que la cache du passage horaire peut faire : rien (`None`) si le réglage est coupé ou son fichier douteux.
    fn pour_le_cache(&self) -> Option<BTreeMap<String, u16>> {
        match self {
            Lu::Absent => Some(BTreeMap::new()),
            Lu::Cru(e) => e.pour_le_cache(),
            Lu::Douteux => None,
        }
    }
}

/// Les durées raccourcies de la cache sur cet ordinateur ; `None` : coupé ou douteux, ou la mission de la cache de
/// l'agent pas en marche (coupée, ses interrupteurs, le journal de l'agent ou son état douteux), la cache ne sert
/// pas : tout se vérifie à neuf. Une cache sans la mission qui la corrige reprendrait un résultat qu'une vérification
/// à neuf contredit.
pub(crate) fn pour_le_cache() -> Option<BTreeMap<String, u16>> {
    pour_le_cache_dans(&crate::socle::dossier_local())
}

pub(crate) fn pour_le_cache_dans(dossier: &Path) -> Option<BTreeMap<String, u16>> {
    if !crate::agent::sortie::en_marche_dans(dossier, crate::agent::MissionId::Cache) {
        return None;
    }
    lire_dans(dossier).pour_le_cache()
}

/// Les règles au délai monté sur cet ordinateur (le bilan les lit une fois).
pub(crate) fn delais_longs() -> BTreeSet<String> {
    lire_dans(&crate::socle::dossier_local()).delais_longs()
}

/// Les règles qui ont droit à un second essai sur cet ordinateur (le bilan les lit une fois) : aucune si le réglage
/// est coupé ou son fichier douteux.
pub(crate) fn relances() -> BTreeSet<String> {
    match lire_dans(&crate::socle::dossier_local()) {
        Lu::Cru(e) => e.relancees(),
        Lu::Absent | Lu::Douteux => BTreeSet::new(),
    }
}

/// Les règles dont le second essai est déjà donné ou a été annulé : ce que la mission du réglage de l'agent ne
/// redemande pas. `None` : réglage coupé, fichier douteux, ou lecture seule.
pub(crate) fn relances_connues_dans(dossier: &Path) -> Option<BTreeSet<String>> {
    if super::lecture_seule::active() {
        return None;
    }
    let e = match lire_dans(dossier) {
        Lu::Absent => Etat::default(),
        Lu::Cru(e) => e,
        Lu::Douteux => return None,
    };
    (!e.coupe).then(|| {
        e.relances
            .iter()
            .map(|r| r.regle.clone())
            .chain(e.sans_relance.iter().cloned())
            .collect()
    })
}

/// Donne un second essai aux règles `demandes` (identifiant, « non vérifiée » passagers, résolus au bilan suivant),
/// par l'Agent Vanguard seulement, après vérification : jamais à une règle annulée, une fois par règle, 50 au plus.
/// Relu juste avant d'écrire, comme `ajuster_retenus_dans`. Rend ce qui a été écrit.
pub(crate) fn relancer_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    demandes: &[(String, u32, u32)],
) -> Vec<Relance> {
    if super::lecture_seule::active() || demandes.is_empty() {
        return Vec::new();
    }
    let avant = match lire_dans(dossier) {
        Lu::Absent => None,
        Lu::Cru(e) => Some(e),
        Lu::Douteux => return Vec::new(),
    };
    let mut e = avant.clone().unwrap_or_default();
    if e.coupe {
        return Vec::new();
    }
    let mut nouvelles = Vec::new();
    for (regle, passageres, reprises) in demandes {
        if !id_valide(regle)
            || crate::machine::regles::SANS_SECOND_ESSAI.contains(&regle.as_str())
            || e.sans_relance.contains(regle)
            || e.relances.iter().any(|r| &r.regle == regle)
            || e.relances.len() >= MONTEES_MAX
        {
            continue;
        }
        let r = Relance {
            quand: jour(aujourd_hui),
            regle: regle.clone(),
            passageres: *passageres,
            reprises: *reprises,
        };
        e.relances.push(r.clone());
        nouvelles.push(r);
    }
    let inchange = match lire_dans(dossier) {
        Lu::Absent => avant.is_none(),
        Lu::Cru(x) => avant.as_ref() == Some(&x),
        Lu::Douteux => false,
    };
    if !nouvelles.is_empty() && inchange && ecrire_dans(dossier, &e.borne()).is_ok() {
        nouvelles
    } else {
        Vec::new()
    }
}

fn ecrire_dans(dossier: &Path, e: &Etat) -> std::io::Result<()> {
    let o = serde_json::to_vec(e).map_err(std::io::Error::other)?;
    crate::sceau::ecrire_dans(dossier, REGLAGE, &o)
}

/// Ajuste l'état d'après les règles qui frôlent leur délai (`frolent` : identifiant et plus longue durée de la
/// semaine, en ms, jugées contre le délai du code). `delai_du_code` : celui de chaque règle de ce système, `None`
/// pour une règle inconnue. Seule une règle au délai `DELAI` peut monter, une fois, à `DELAI_LONG`. Rend vrai si
/// l'état a changé.
fn ajuster_etat(
    e: &mut Etat,
    aujourd_hui: chrono::NaiveDate,
    frolent: &[(String, u64)],
    hors_delai: &[(String, u64)],
    delai_du_code: impl Fn(&str) -> Option<Duration>,
) -> bool {
    let avant = e.clone();
    let montees: BTreeSet<String> = e.montees.iter().map(|m| m.regle.clone()).collect();
    let permise =
        |r: &str| id_valide(r) && !montees.contains(r) && !e.refusees.contains(r) && delai_du_code(r) == Some(DELAI);
    // R1 : sortie de son délai deux fois en 7 jours, la règle n'attend pas deux semaines (même montée, mêmes bornes).
    let sorties: BTreeMap<&str, u64> = hors_delai
        .iter()
        .filter(|(r, _)| permise(r))
        .map(|(r, ms)| (r.as_str(), *ms))
        .collect();
    let candidates: BTreeMap<&str, u64> = frolent
        .iter()
        .filter(|(r, _)| permise(r) && !sorties.contains_key(r.as_str()))
        .map(|(r, ms)| (r.as_str(), *ms))
        .collect();
    for (regle, mesure_ms) in &sorties {
        if e.montees.len() < MONTEES_MAX {
            e.frolent_depuis.remove(*regle);
            e.montees.push(Montee {
                quand: jour(aujourd_hui),
                regle: (*regle).to_string(),
                avant_s: secondes(DELAI),
                apres_s: secondes(DELAI_LONG),
                mesure_ms: *mesure_ms,
            });
        }
    }
    e.frolent_depuis.retain(|r, _| candidates.contains_key(r.as_str()));
    for (regle, mesure_ms) in candidates {
        let depuis = match e.frolent_depuis.get(regle).and_then(|d| date(d)) {
            // Une date à venir (horloge reculée) repart d'aujourd'hui.
            Some(d) if d <= aujourd_hui => d,
            _ if e.frolent_depuis.len() >= SUIVIES_MAX && !e.frolent_depuis.contains_key(regle) => continue,
            _ => {
                e.frolent_depuis.insert(regle.to_string(), jour(aujourd_hui));
                aujourd_hui
            }
        };
        if aujourd_hui.signed_duration_since(depuis).num_days() >= JOURS_DE_SUITE && e.montees.len() < MONTEES_MAX {
            e.frolent_depuis.remove(regle);
            e.montees.push(Montee {
                quand: jour(aujourd_hui),
                regle: regle.to_string(),
                avant_s: secondes(DELAI),
                apres_s: secondes(DELAI_LONG),
                mesure_ms,
            });
        }
    }
    *e != avant
}

/// Ce qu'une passe propose à la cache, à part des pas de raccourci (qui vont dans l'état) : les pas à défaire et les
/// coupures, appliqués seulement s'ils sont retenus (`ajuster_retenus_dans`).
#[derive(Debug, Default, PartialEq, Eq)]
struct PourLaCache {
    rallongees: Vec<Rallongee>,
    coupures: Vec<Coupure>,
}

/// Règle la durée de la cache de chaque règle de `cache::TABLE` d'après les vérifications à neuf qui suivent une
/// reprise (`super::mesures::Cache::recentes`), jamais pour une règle gardée (un raccourci ou une coupure annulé) :
/// - **coupure** (R3) : plus de 2 % d'écarts sur 14 jours (50 vérifications au moins) : la règle n'est plus reprise ;
/// - **raccourci** (R2) : un écart parmi les vérifications jugées depuis le dernier changement, et la durée descend
///   d'un pas de 15 minutes, jamais sous le plancher (poussé dans `e`) ;
/// - **pas défait** (R2) : 20 vérifications de suite sans écart depuis le dernier changement, et le dernier pas de
///   l'agent se défait : la durée revient à celle d'avant lui, jamais au-dessus de celle du code (sans pas, rien).
fn regler_cache(
    e: &mut Etat,
    aujourd_hui: chrono::NaiveDate,
    mesures: &BTreeMap<String, super::mesures::Cache>,
) -> PourLaCache {
    let mut pour = PourLaCache::default();
    let debut_coupe = aujourd_hui
        .checked_sub_signed(chrono::Duration::days(COUPE_JOURS.saturating_sub(1)))
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map_or(i64::MIN, |d| d.and_utc().timestamp());
    for t in super::cache::TABLE {
        if e.gardees.contains(t.regle) || e.coupures.iter().any(|c| c.regle == t.regle) {
            continue;
        }
        let Some(m) = mesures.get(t.regle) else {
            continue;
        };
        let quinzaine: Vec<bool> = m
            .recentes
            .iter()
            .filter(|(q, _)| *q >= debut_coupe)
            .map(|(_, x)| *x)
            .collect();
        let ecarts_quinzaine = quinzaine.iter().filter(|x| **x).count();
        if quinzaine.len() >= COUPE_COMPAREES_MIN && ecarts_quinzaine.saturating_mul(COUPE_UNE_SUR) > quinzaine.len() {
            pour.coupures.push(Coupure {
                quand: jour(aujourd_hui),
                regle: t.regle.to_string(),
                comparees: u32::try_from(quinzaine.len()).unwrap_or(u32::MAX),
                ecarts: u32::try_from(ecarts_quinzaine).unwrap_or(u32::MAX),
            });
            continue;
        }
        let deja = e.raccourcies.iter().rev().find(|r| r.regle == t.regle).cloned();
        let depuis = deja
            .as_ref()
            .map_or(i64::MIN, |r| r.depuis_s)
            .max(e.rallongees.get(t.regle).copied().unwrap_or(i64::MIN));
        let jugees: Vec<(i64, bool)> = m.recentes.iter().copied().filter(|(q, _)| *q > depuis).collect();
        let ecarts = jugees.iter().filter(|(_, x)| *x).count();
        let dernier = jugees.iter().map(|(q, _)| *q).max().unwrap_or(depuis);
        let actuelle = deja.as_ref().map_or(t.duree_min, |r| r.apres_min);
        if ecarts == 0 {
            if let Some(pas) = deja.filter(|_| jugees.len() >= RALLONGE_SANS_ECART) {
                pour.rallongees.push(Rallongee {
                    regle: t.regle.to_string(),
                    avant_min: pas.apres_min,
                    apres_min: pas.avant_min,
                    comparees: u32::try_from(jugees.len()).unwrap_or(u32::MAX),
                    depuis_s: dernier,
                });
            }
            continue;
        }
        let apres = actuelle.saturating_sub(super::cache::PAS_MIN).max(t.plancher_min);
        if apres >= actuelle {
            continue;
        }
        e.raccourcies.push(Raccourcie {
            quand: jour(aujourd_hui),
            regle: t.regle.to_string(),
            avant_min: actuelle,
            apres_min: apres,
            comparees: u32::try_from(jugees.len()).unwrap_or(u32::MAX),
            ecarts: u32::try_from(ecarts).unwrap_or(u32::MAX),
            depuis_s: dernier,
        });
    }
    pour
}

/// Défait le pas `r` s'il est encore le dernier de sa règle, exactement celui-là ; rend vrai si c'est fait.
fn defaire_pas(e: &mut Etat, r: &Rallongee) -> bool {
    let Some(i) = e.raccourcies.iter().rposition(|x| x.regle == r.regle) else {
        return false;
    };
    let bon = e
        .raccourcies
        .get(i)
        .is_some_and(|x| x.apres_min == r.avant_min && x.avant_min == r.apres_min);
    if bon {
        e.raccourcies.remove(i);
        e.rallongees.insert(r.regle.clone(), r.depuis_s);
    }
    bon
}

/// Ce qu'une passe de l'auto-réglage ajoute : les montées de délai, les pas de raccourci nouveaux, les pas défaits
/// et les coupures de la cache.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Prevu {
    pub montees: Vec<Montee>,
    pub raccourcies: Vec<Raccourcie>,
    pub rallongees: Vec<Rallongee>,
    pub coupures: Vec<Coupure>,
}

/// Ce que l'Agent Vanguard retient d'une passe, après vérification : une fonction par sorte.
pub(crate) struct Retenus<'a> {
    pub montee: &'a dyn Fn(&Montee) -> bool,
    pub pas: &'a dyn Fn(&Raccourcie) -> bool,
    pub rallongee: &'a dyn Fn(&Rallongee) -> bool,
    pub coupure: &'a dyn Fn(&Coupure) -> bool,
}

/// Le jugement d'une passe d'après les mesures de cet ordinateur : l'état lu (`None` : pas de fichier), celui
/// d'après (montées et pas de raccourci), et ce qui reste à retenir pour la cache. Rien (`None`) en lecture seule
/// (l'autotest), réglage coupé ou fichier douteux.
fn juger_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
) -> Option<(Option<Etat>, Etat, PourLaCache)> {
    if super::lecture_seule::active() {
        return None;
    }
    let avant = match lire_dans(dossier) {
        Lu::Absent => None,
        Lu::Cru(e) => Some(e),
        Lu::Douteux => return None,
    };
    let mut e = avant.clone().unwrap_or_default();
    if e.coupe {
        return None;
    }
    let delai = |id: &str| delai_du_code(id).unwrap_or(DELAI);
    let verdict = super::mesures::juger(mesures, aujourd_hui, delai);
    let frolent: Vec<(String, u64)> = verdict
        .frolent_le_delai
        .into_iter()
        .map(|f| (f.regle, f.max_ms))
        .collect();
    let hors_delai = super::mesures::hors_delai(mesures, aujourd_hui, delai);
    ajuster_etat(&mut e, aujourd_hui, &frolent, &hors_delai, delai_du_code);
    let pour = regler_cache(&mut e, aujourd_hui, &mesures.cache);
    Some((avant, e, pour))
}

/// Ce que la passe ajouterait, sans rien écrire : ce que lisent les missions de l'agent (`agent::missions`).
pub(crate) fn prevoir_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
) -> Option<Prevu> {
    let (avant, mut e, pour) = juger_dans(dossier, aujourd_hui, mesures, delai_du_code)?;
    let avant = avant.unwrap_or_default();
    Some(Prevu {
        montees: e.montees.split_off(avant.montees.len().min(e.montees.len())),
        raccourcies: e
            .raccourcies
            .split_off(avant.raccourcies.len().min(e.raccourcies.len())),
        rallongees: pour.rallongees,
        coupures: pour.coupures,
    })
}

/// Après un bilan noté, par l'Agent Vanguard (`agent`) seulement : la même passe, mais seuls les changements retenus
/// (vérifiés par l'agent) s'appliquent ; une montée écartée garde son suivi, elle se reprendra. Le suivi des règles
/// qui frôlent leur délai s'écrit aussi. Rend ce qui a été écrit.
pub(crate) fn ajuster_retenus_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
    retenus: &Retenus<'_>,
) -> Prevu {
    let Some((avant, mut e, pour)) = juger_dans(dossier, aujourd_hui, mesures, delai_du_code) else {
        return Prevu::default();
    };
    let base = avant.clone().unwrap_or_default();
    let nouvelles = e.montees.split_off(base.montees.len().min(e.montees.len()));
    let mut montees = Vec::new();
    for m in nouvelles {
        if (retenus.montee)(&m) {
            montees.push(m);
        } else if let Some(depuis) = base.frolent_depuis.get(&m.regle) {
            e.frolent_depuis.insert(m.regle.clone(), depuis.clone());
        }
    }
    e.montees.extend(montees.iter().cloned());
    let pas = e.raccourcies.split_off(base.raccourcies.len().min(e.raccourcies.len()));
    let raccourcies: Vec<Raccourcie> = pas.into_iter().filter(|r| (retenus.pas)(r)).collect();
    e.raccourcies.extend(raccourcies.iter().cloned());
    let rallongees: Vec<Rallongee> = pour
        .rallongees
        .into_iter()
        .filter(|r| (retenus.rallongee)(r) && defaire_pas(&mut e, r))
        .collect();
    let coupures: Vec<Coupure> = pour.coupures.into_iter().filter(|c| (retenus.coupure)(c)).collect();
    e.coupures.extend(coupures.iter().cloned());
    // Relu juste avant d'écrire : un changement voulu (annuler, tout remettre, couper) écrit depuis la première
    // lecture n'est jamais écrasé ; la montée attend la prochaine passe.
    let inchange = match lire_dans(dossier) {
        Lu::Absent => avant.is_none(),
        Lu::Cru(x) => avant.as_ref() == Some(&x),
        Lu::Douteux => false,
    };
    if e != base && inchange && ecrire_dans(dossier, &e.borne()).is_ok() {
        Prevu {
            montees,
            raccourcies,
            rallongees,
            coupures,
        }
    } else {
        Prevu::default()
    }
}

/// La passe entière, tout retenu : les essais de l'auto-réglage seul.
#[cfg(test)]
fn ajuster_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: impl Fn(&str) -> Option<Duration>,
) {
    let _ = ajuster_retenus_dans(
        dossier,
        aujourd_hui,
        mesures,
        &delai_du_code,
        &Retenus {
            montee: &|_| true,
            pas: &|_| true,
            rallongee: &|_| true,
            coupure: &|_| true,
        },
    );
}

/// L'état de départ d'un changement voulu : celui du fichier, ou celui d'origine s'il est absent ou douteux (le
/// changement le réécrit, scellé).
fn pour_changer(dossier: &Path) -> Etat {
    match lire_dans(dossier) {
        Lu::Cru(e) => e,
        Lu::Absent | Lu::Douteux => Etat::default(),
    }
}

/// Met le réglage en marche ou le coupe ; les changements restent, appliqués seulement en marche. La cache est vidée
/// d'abord : rien de ce qu'elle gardait ne revient après le geste (et s'il échoue, rien n'a changé).
fn mettre_en_marche_dans(dossier: &Path, en_marche: bool) -> std::io::Result<()> {
    let _geste = crate::agent::geste_dans(dossier)?;
    let mut e = pour_changer(dossier);
    e.coupe = !en_marche;
    super::cache::oublier_dans(dossier, true)?;
    ecrire_dans(dossier, &e.borne())
}

/// Annule la montée de `regle` : son délai redevient celui du code, et elle ne remontera plus. Rend vrai si elle
/// était montée.
fn annuler_dans(dossier: &Path, regle: &str) -> std::io::Result<bool> {
    let _geste = crate::agent::geste_dans(dossier)?;
    let mut e = pour_changer(dossier);
    let avant = e.montees.len();
    e.montees.retain(|m| m.regle != regle);
    if e.montees.len() == avant {
        return Ok(false);
    }
    e.refusees.insert(regle.to_string());
    super::cache::oublier_dans(dossier, true)?;
    ecrire_dans(dossier, &e.borne())?;
    Ok(true)
}

/// Annule des pas de raccourci de la durée de la cache de `regle` : `depuis_min`, le pas qui partait de cette durée et
/// ceux d'après (le menu, un par un) ; `None`, le dernier pas seulement. La durée revient exactement à celle d'avant le
/// pas annulé, et elle ne descendra plus. Rend la durée remise, ou `None` si rien n'était à annuler.
fn annuler_duree_dans(dossier: &Path, regle: &str, depuis_min: Option<u16>) -> std::io::Result<Option<u16>> {
    let _geste = crate::agent::geste_dans(dossier)?;
    let mut e = pour_changer(dossier);
    let Some(remise) = depuis_min.or_else(|| {
        e.raccourcies
            .iter()
            .rev()
            .find(|r| r.regle == regle)
            .map(|r| r.avant_min)
    }) else {
        return Ok(None);
    };
    let avant = e.raccourcies.len();
    e.raccourcies.retain(|r| r.regle != regle || r.avant_min > remise);
    if e.raccourcies.len() == avant {
        return Ok(None);
    }
    e.gardees.insert(regle.to_string());
    super::cache::oublier_dans(dossier, true)?;
    ecrire_dans(dossier, &e.borne())?;
    Ok(Some(remise))
}

/// Annule la coupure de la cache de `regle` : son résultat se reprend de nouveau comme avant, et l'agent ne touche
/// plus à sa durée. Rend vrai si elle était coupée.
fn annuler_coupure_dans(dossier: &Path, regle: &str) -> std::io::Result<bool> {
    let _geste = crate::agent::geste_dans(dossier)?;
    let mut e = pour_changer(dossier);
    let avant = e.coupures.len();
    e.coupures.retain(|c| c.regle != regle);
    if e.coupures.len() == avant {
        return Ok(false);
    }
    e.gardees.insert(regle.to_string());
    super::cache::oublier_dans(dossier, true)?;
    ecrire_dans(dossier, &e.borne())?;
    Ok(true)
}

/// Annule le second essai de `regle` : elle n'est plus relancée, et ne le sera plus. Rend vrai s'il était donné.
fn annuler_relance_dans(dossier: &Path, regle: &str) -> std::io::Result<bool> {
    let _geste = crate::agent::geste_dans(dossier)?;
    let mut e = pour_changer(dossier);
    let avant = e.relances.len();
    e.relances.retain(|r| r.regle != regle);
    if e.relances.len() == avant {
        return Ok(false);
    }
    e.sans_relance.insert(regle.to_string());
    ecrire_dans(dossier, &e.borne())?;
    Ok(true)
}

/// Tout remettre comme à l'origine : plus rien de monté, suivi ni refusé, la cache vidée, les états de l'Agent
/// Vanguard (`agent`) remis à zéro, et le réglage coupé jusqu'à ce qu'on le remette en marche.
fn tout_remettre_dans(dossier: &Path) -> std::io::Result<()> {
    let geste = crate::agent::geste_dans(dossier)?;
    super::cache::oublier_dans(dossier, true)?;
    crate::agent::tout_remettre_dans(dossier, chrono::Utc::now().timestamp(), &geste)?;
    ecrire_dans(
        dossier,
        &Etat {
            coupe: true,
            ..Etat::default()
        }
        .borne(),
    )
}

/// L'ordre de départ : les positions de `ids` (une par vérification, `None` pour une vérification sans règle du
/// registre), la plus longue médiane d'abord. Une règle jamais mesurée part après les mesurées, dans l'ordre des
/// rangs, comme deux règles de même médiane. Toujours une permutation de `0..ids.len()` : aucune règle perdue ni
/// lancée deux fois.
pub(crate) fn ordre_de_depart(ids: &[Option<&str>], medianes: &BTreeMap<String, u64>) -> Vec<usize> {
    let mut ordre: Vec<usize> = (0..ids.len()).collect();
    let duree = |i: &usize| ids.get(*i).copied().flatten().and_then(|id| medianes.get(id)).copied();
    // Tri stable : à égalité (ou sans mesure), l'ordre des rangs reste.
    ordre.sort_by_key(|i| std::cmp::Reverse(duree(i)));
    ordre
}

/// `depart` s'il est une permutation de `0..n`, sinon l'ordre des rangs : un ordre faux ne fait jamais sauter ni
/// doubler une règle.
pub(crate) fn permutation_ou_rangs(depart: Vec<usize>, n: usize) -> Vec<usize> {
    let mut vus = vec![false; n];
    let juste = depart.len() == n
        && depart.iter().all(|&i| match vus.get_mut(i) {
            Some(v) if !*v => {
                *v = true;
                true
            }
            _ => false,
        });
    if juste { depart } else { (0..n).collect() }
}

/// La valeur montrée dans Paramètres.
pub(crate) fn etat_court() -> String {
    match lire_dans(&crate::socle::dossier_local()) {
        Lu::Absent => tr!("oui", "yes").to_string(),
        Lu::Cru(e) if e.coupe => tr!("non", "no").to_string(),
        Lu::Cru(e) if nombre_de_changements(&e) == 0 => tr!("oui", "yes").to_string(),
        Lu::Cru(e) => trf!(
            "oui ({} changement(s))",
            "yes ({} change(s))",
            nombre_de_changements(&e)
        ),
        Lu::Douteux => tr!(
            "oui (fichier douteux : délais d'origine)",
            "yes (doubtful file: original time limits)"
        )
        .to_string(),
    }
}

fn nombre_de_changements(e: &Etat) -> usize {
    [e.montees.len(), e.raccourcies.len(), e.coupures.len(), e.relances.len()]
        .into_iter()
        .fold(0, usize::saturating_add)
}

/// Une montée, telle qu'elle se montre : « LNX-NOY-001 : délai 10 → 30 min, le 2026-11-02 (mesure 6 min 12 s) ».
fn montree(m: &Montee) -> String {
    let mesure = m.mesure_ms / 1000;
    trf!(
        "{} : délai {} → {} min, le {} (mesuré : {} min {:02} s)",
        "{}: time limit {} → {} min, on {} (measured: {} min {:02} s)",
        m.regle,
        m.avant_s / 60,
        m.apres_s / 60,
        m.quand,
        mesure / 60,
        mesure % 60
    )
}

/// Un raccourci, tel qu'il se montre : « LNX-MAJ-001 : résultat repris jusqu'à 90 → 75 min, le 2026-11-02 (2
/// écart(s) sur 5) ».
fn raccourcie_montree(r: &Raccourcie) -> String {
    trf!(
        "{} : résultat repris jusqu'à {} → {} min, le {} ({} écart(s) sur {} vérification(s))",
        "{}: result reused for up to {} → {} min, on {} ({} mismatch(es) in {} check(s))",
        r.regle,
        r.avant_min,
        r.apres_min,
        r.quand,
        r.ecarts,
        r.comparees
    )
}

/// Une coupure, telle qu'elle se montre.
fn coupure_montree(c: &Coupure) -> String {
    trf!(
        "{} : résultat jamais repris, vérifié à neuf à chaque passage, depuis le {} ({} écart(s) sur {} vérification(s) en 14 jours)",
        "{}: result never reused, checked afresh at every pass, since {} ({} mismatch(es) in {} check(s) over 14 days)",
        c.regle,
        c.quand,
        c.ecarts,
        c.comparees
    )
}

/// Un second essai, tel qu'il se montre.
fn relance_montree(r: &Relance) -> String {
    trf!(
        "{} : un second essai à la fin du bilan s'il n'a pas pu conclure, depuis le {} ({} sur {} « non vérifiée » de la semaine résolus au bilan suivant)",
        "{}: a second attempt at the end of the check if it could not conclude, since {} ({} of {} “not checked” of the week resolved at the next check)",
        r.regle,
        r.quand,
        r.reprises,
        r.passageres
    )
}

/// Un changement en vigueur, comme le menu les numérote.
enum Changement {
    Montee(Montee),
    Raccourcie(Raccourcie),
    Coupure(Coupure),
    Relance(Relance),
}

fn dire_echec(e: &std::io::Error) {
    trp!(
        "  ✖ Rien n'a changé : {} ne s'écrit pas ({e}).",
        "  ✖ Nothing changed: {} cannot be written ({e}).",
        REGLAGE
    );
}

fn dire_en_marche(en_marche: bool) {
    match mettre_en_marche_dans(&crate::socle::dossier_local(), en_marche) {
        Ok(()) if en_marche => trp!(
            "  {VERT}✔{RESET} Agent Vanguard (sans IA) : en marche.",
            "  {VERT}✔{RESET} Vanguard Agent (no AI): on."
        ),
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Agent Vanguard (sans IA) : coupé. Les délais du code servent ; les changements restent notés, et reviennent s'il est remis en marche.",
            "  {VERT}✔{RESET} Vanguard Agent (no AI): off. The code's time limits are used; the changes stay noted, and come back if it is turned on again."
        ),
        Err(e) => dire_echec(&e),
    }
}

/// Ce qu'un geste « annuler » défait pour une règle.
#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)] // ce que défait le geste, chaque levier pour lui-même
struct Annuler {
    montee: bool,
    duree: bool,
    coupure: bool,
    relance: bool,
}

impl Annuler {
    const TOUT: Annuler = Annuler {
        montee: true,
        duree: true,
        coupure: true,
        relance: true,
    };
    const RIEN: Annuler = Annuler {
        montee: false,
        duree: false,
        coupure: false,
        relance: false,
    };
}

/// Annule ce que `quoi` désigne pour `regle` : la montée, un pas de raccourci (à partir de `depuis_min`, sinon le
/// dernier), la coupure, le second essai ; rend vrai si quelque chose a été annulé.
fn dire_annule(regle: &str, quoi: Annuler, depuis_min: Option<u16>) -> bool {
    let dossier = crate::socle::dossier_local();
    let mut fait = false;
    if quoi.coupure {
        match annuler_coupure_dans(&dossier, regle) {
            Ok(true) => {
                fait = true;
                trp!(
                    "  {VERT}✔{RESET} {regle} : son résultat se reprend de nouveau, comme avant la coupure, et l'agent ne touchera plus à sa durée.",
                    "  {VERT}✔{RESET} {regle}: its result is reused again, as before the cut, and the agent will not touch its duration again."
                );
            }
            Ok(false) => {}
            Err(e) => {
                dire_echec(&e);
                return true;
            }
        }
    }
    if quoi.relance {
        match annuler_relance_dans(&dossier, regle) {
            Ok(true) => {
                fait = true;
                trp!(
                    "  {VERT}✔{RESET} {regle} : plus de second essai, et il ne sera plus donné.",
                    "  {VERT}✔{RESET} {regle}: no more second attempt, and it will not be given again."
                );
            }
            Ok(false) => {}
            Err(e) => {
                dire_echec(&e);
                return true;
            }
        }
    }
    let (montee, duree) = (quoi.montee, quoi.duree);
    if montee {
        match annuler_dans(&dossier, regle) {
            Ok(true) => {
                fait = true;
                trp!(
                    "  {VERT}✔{RESET} {regle} : délai remis à {} min, et il ne montera plus.",
                    "  {VERT}✔{RESET} {regle}: time limit back to {} min, and it will not go up again.",
                    secondes(DELAI) / 60
                );
            }
            Ok(false) => {}
            Err(e) => {
                dire_echec(&e);
                return true;
            }
        }
    }
    if duree {
        match annuler_duree_dans(&dossier, regle, depuis_min) {
            Ok(Some(remise)) => {
                fait = true;
                trp!(
                    "  {VERT}✔{RESET} {regle} : résultat repris de nouveau jusqu'à {remise} min, comme avant ce raccourci, et ce ne sera plus raccourci.",
                    "  {VERT}✔{RESET} {regle}: result reused again for up to {remise} min, as before this shortening, and it will not be shortened again."
                );
            }
            Ok(None) => {}
            Err(e) => {
                dire_echec(&e);
                return true;
            }
        }
    }
    fait
}

fn dire_tout_remis() {
    match tout_remettre_dans(&crate::socle::dossier_local()) {
        Ok(()) => trp!(
            "  {VERT}✔{RESET} Tout est remis comme à l'origine, et le réglage est coupé. « vanguard parametres auto-reglage oui » le remet en marche.",
            "  {VERT}✔{RESET} Everything is back to the original, and tuning is off. “vanguard settings auto-tuning yes” turns it back on."
        ),
        Err(e) => dire_echec(&e),
    }
}

/// `vanguard parametres auto-reglage [oui|non|tout-remettre|annuler <règle>|missions|mission <nom> <oui|non>|journal]` :
/// sans mot, l'état et les changements.
pub(crate) fn commande(mots: &[String]) {
    let mots: Vec<String> = mots.iter().map(|m| m.trim().to_lowercase()).collect();
    match mots.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => {
            afficher();
        }
        ["oui" | "o" | "yes" | "y" | "on"] => dire_en_marche(true),
        ["non" | "n" | "no" | "off"] => dire_en_marche(false),
        ["tout-remettre" | "reset" | "origine" | "original"] => dire_tout_remis(),
        ["missions"] => {
            crate::parametres::agent::afficher_missions(
                &crate::agent::sortie::vue_dans(&crate::socle::dossier_local()),
            );
        }
        ["journal" | "log"] => crate::parametres::agent::afficher_journal(),
        ["mission", mission, etat] if crate::parametres::agent::commande_mission(mission, etat) => {}
        ["annuler" | "undo", regle] => {
            if !dire_annule(&regle.to_uppercase(), Annuler::TOUT, None) {
                trp!(
                    "  Rien n'a changé : cette règle n'a ni délai monté, ni durée raccourcie ou coupée, ni second essai.",
                    "  Nothing changed: this rule has no raised time limit, no shortened or cut duration, no second attempt."
                );
            }
        }
        _ => trp!(
            "  Valeurs : oui, non, tout-remettre, annuler <règle> (par exemple « annuler LNX-NOY-001 »), missions, mission <reglage|cache|releve|corrections> <oui|non>, journal.",
            "  Values: yes, no, reset, undo <rule> (for example “undo LNX-NOY-001”), missions, mission <tuning|cache|record|fixes> <yes|no>, journal."
        ),
    }
}

/// L'état, les changements en vigueur et ce que garde la cache ; rend les changements montrés, numérotés à partir
/// de 1.
fn afficher() -> Vec<Changement> {
    titre(tr!("Agent Vanguard (sans IA)", "Vanguard Agent (no AI)"));
    afficher_aligne("  ", explication(), 2, GRIS);
    println!();
    let lu = lire_dans(&crate::socle::dossier_local());
    trp!("  En marche : {}", "  On: {}", etat_court());
    let changements: Vec<Changement> = match lu {
        Lu::Cru(e) => e
            .montees
            .into_iter()
            .map(Changement::Montee)
            .chain(e.raccourcies.into_iter().map(Changement::Raccourcie))
            .chain(e.coupures.into_iter().map(Changement::Coupure))
            .chain(e.relances.into_iter().map(Changement::Relance))
            .collect(),
        Lu::Absent | Lu::Douteux => Vec::new(),
    };
    if changements.is_empty() {
        trp!(
            "  Aucun changement : chaque règle a les valeurs du code.",
            "  No change: every rule has the code's values."
        );
    }
    for (i, c) in changements.iter().enumerate() {
        let texte = match c {
            Changement::Montee(m) => montree(m),
            Changement::Raccourcie(r) => raccourcie_montree(r),
            Changement::Coupure(c) => coupure_montree(c),
            Changement::Relance(r) => relance_montree(r),
        };
        afficher_aligne(&format!("  {TOUCHE}{:>2}{RESET} ", i.saturating_add(1)), &texte, 5, "");
    }
    let vue = crate::agent::sortie::vue_dans(&crate::socle::dossier_local());
    let en_marche = vue
        .missions
        .iter()
        .filter(|m| m.etat == crate::agent::sortie::EtatMission::EnMarche)
        .count();
    trp!(
        "  Missions en marche : {en_marche} sur {} (« m » pour les voir, ou en couper une).",
        "  Missions on: {en_marche} of {} (“m” to see them, or turn one off).",
        vue.missions.len()
    );
    println!();
    trp!("  Cache du passage horaire :", "  Hourly pass cache:");
    for l in super::cache::lignes() {
        afficher_aligne("    ", &l, 4, GRIS);
    }
    changements
}

/// Ce que fait le réglage, en une phrase.
pub(crate) fn explication() -> &'static str {
    tr!(
        "Oui : un petit agent intégré, sans IA, règle Vanguard sur cet ordinateur, entre des bornes fixes. Le bilan lance d'abord ses règles les plus longues, et le délai d'une règle qui le frôle deux semaines de suite, ou le dépasse deux fois en une semaine, monte de 10 à 30 minutes, jamais plus. Une règle qui n'a pas pu conclure (délai, lecture) et y arrive d'ordinaire au bilan suivant a droit à un second essai à la fin du bilan, une fois, dans les 30 minutes du bilan ; son second résultat ne remplace le premier que s'il conclut. Le passage horaire reprend aussi, une fois sur deux au plus, le résultat récent de quelques vérifications lentes (mises à jour, fichiers sensibles), avec son âge ; un bilan que vous lancez vérifie tout à neuf. Une durée raccourcit dès qu'elle se trompe, reprend un cran après 20 vérifications justes (jamais plus que celle du code), et une règle qui se trompe trop souvent n'est plus reprise du tout. Les règles et ce qu'elles jugent ne changent jamais. Chaque changement est noté avec sa valeur d'avant et s'annule ici. Rien n'est envoyé.",
        "Yes: a small built-in agent, with no AI, tunes Vanguard on this computer, within fixed bounds. The check starts its longest rules first, and the time limit of a rule that comes close to it two weeks in a row, or exceeds it twice in a week, goes up from 10 to 30 minutes, never more. A rule that could not conclude (time limit, reading) and usually does at the next check gets a second attempt at the end of the check, once, within the check's 30 minutes; its second result replaces the first only if it concludes. The hourly pass also reuses, every other time at most, the recent result of a few slow checks (updates, sensitive files), with its age; a check you start checks everything afresh. A duration gets shorter as soon as it is wrong, goes back up one step after 20 right checks (never more than the code's), and a rule that is too often wrong is no longer reused at all. The rules and how they judge never change. Each change is noted with its previous value and can be undone here. Nothing is sent."
    )
}

/// L'écran de Paramètres : l'état, les changements, et de quoi les défaire.
pub(crate) fn menu() {
    let changements = afficher();
    let reponse = demander(tr!(
        "\n  Numéro : annuler celui-ci ; « oui » ou « non » : mettre en marche ou couper ; « m » : ses missions, une à une ; « j » : son journal ; « t » : tout remettre comme à l'origine ; Entrée pour revenir : ",
        "\n  Number: undo this one; “yes” or “no”: turn on or off; “m”: its missions, one by one; “j”: its journal; “a”: put everything back to the original; Enter to go back: "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    if reponse.eq_ignore_ascii_case("m") {
        crate::parametres::agent::menu();
    } else if reponse.eq_ignore_ascii_case("j") {
        crate::parametres::agent::journal_et_revenir();
    } else if crate::langue::tout(reponse) {
        dire_tout_remis();
    } else if crate::langue::oui(reponse) {
        dire_en_marche(true);
    } else if matches!(reponse.to_lowercase().as_str(), "n" | "non" | "no") {
        dire_en_marche(false);
    } else if let Some(c) = reponse
        .parse::<usize>()
        .ok()
        .and_then(|i| changements.get(i.checked_sub(1)?))
    {
        let fait = match c {
            Changement::Montee(m) => dire_annule(
                &m.regle,
                Annuler {
                    montee: true,
                    ..Annuler::RIEN
                },
                None,
            ),
            Changement::Raccourcie(r) => dire_annule(
                &r.regle,
                Annuler {
                    duree: true,
                    ..Annuler::RIEN
                },
                Some(r.avant_min),
            ),
            Changement::Coupure(c) => dire_annule(
                &c.regle,
                Annuler {
                    coupure: true,
                    ..Annuler::RIEN
                },
                None,
            ),
            Changement::Relance(r) => dire_annule(
                &r.regle,
                Annuler {
                    relance: true,
                    ..Annuler::RIEN
                },
                None,
            ),
        };
        if !fait {
            trp!("  Rien n'a changé.", "  Nothing changed.");
        }
    } else {
        trp!("  Rien n'a changé.", "  Nothing changed.");
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn medianes(paires: &[(&str, u64)]) -> BTreeMap<String, u64> {
        paires.iter().map(|(k, v)| ((*k).to_string(), *v)).collect()
    }

    #[test]
    fn la_plus_longue_d_abord_puis_les_rangs() {
        let ids = [Some("A"), None, Some("B"), Some("C"), Some("D")];
        let m = medianes(&[("B", 9_000), ("D", 9_000), ("A", 100)]);
        // B et D ex aequo : dans l'ordre des rangs ; A mesurée avant la vérification sans règle et C jamais mesurée.
        assert_eq!(ordre_de_depart(&ids, &m), vec![2, 4, 0, 1, 3]);
        assert_eq!(ordre_de_depart(&ids, &BTreeMap::new()), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn un_ordre_faux_rend_les_rangs() {
        assert_eq!(permutation_ou_rangs(vec![2, 0, 1], 3), vec![2, 0, 1]);
        assert_eq!(permutation_ou_rangs(vec![0, 0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1], 3), vec![0, 1, 2]);
        assert_eq!(permutation_ou_rangs(vec![0, 1, 3], 3), vec![0, 1, 2]);
    }

    /// Le module ne nomme rien de la détection : ni niveau de risque, ni module de règles ou de protection.
    #[test]
    fn reglage_ne_touche_pas_la_detection() {
        let source = include_str!("reglage.rs");
        let code: String = source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or(source)
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect();
        for interdit in [
            "risk",
            "Niveau",
            "protection",
            "regles_communes",
            "seuil",
            "SEUIL",
            "blocage",
        ] {
            assert!(!code.contains(interdit), "reglage.rs nomme « {interdit} »");
        }
    }

    fn j(t: &str) -> chrono::NaiveDate {
        date(t).unwrap()
    }

    /// Le délai du code des règles de l'essai : LNX-TST-010 ordinaire, LNX-MAJ-010 déjà long, le reste inconnu.
    fn du_code(id: &str) -> Option<Duration> {
        match id {
            "LNX-TST-010" | "LNX-TST-011" => Some(DELAI),
            "LNX-MAJ-010" => Some(DELAI_LONG),
            _ => None,
        }
    }

    fn frole(ids: &[&str]) -> Vec<(String, u64)> {
        ids.iter().map(|r| ((*r).to_string(), 400_000)).collect()
    }

    /// Frôler une fois ne suffit pas ; 7 jours plus tard, toujours : le délai monte, une fois, noté avec sa valeur
    /// d'avant. Une règle qui cesse de frôler repart de zéro ; une règle déjà longue ou inconnue ne monte jamais.
    #[test]
    fn deux_semaines_de_suite_puis_monte_une_fois() {
        let mut e = Etat::default();
        let tous = [
            "LNX-TST-010",
            "LNX-TST-011",
            "LNX-MAJ-010",
            "LNX-ABC-999",
            "pas une règle",
        ];
        assert!(ajuster_etat(&mut e, j("2026-11-01"), &frole(&tous), &[], du_code));
        assert_eq!(e.montees.len(), 0);
        assert_eq!(
            e.frolent_depuis.keys().map(String::as_str).collect::<Vec<_>>(),
            ["LNX-TST-010", "LNX-TST-011"]
        );
        // LNX-TST-011 cesse de frôler : oubliée.
        assert!(ajuster_etat(
            &mut e,
            j("2026-11-05"),
            &frole(&["LNX-TST-010"]),
            &[],
            du_code
        ));
        assert!(!e.frolent_depuis.contains_key("LNX-TST-011"));
        assert!(!ajuster_etat(
            &mut e,
            j("2026-11-07"),
            &frole(&["LNX-TST-010"]),
            &[],
            du_code
        ));
        assert!(ajuster_etat(&mut e, j("2026-11-08"), &frole(&tous), &[], du_code));
        assert_eq!(
            e.montees,
            vec![Montee {
                quand: "2026-11-08".into(),
                regle: "LNX-TST-010".into(),
                avant_s: 600,
                apres_s: 1800,
                mesure_ms: 400_000,
            }]
        );
        assert_eq!(e.delais_longs(), BTreeSet::from(["LNX-TST-010".to_string()]));
        // Déjà montée : plus rien pour elle ; LNX-TST-011, qui frôle de nouveau depuis le 8, attend ses 7 jours.
        let deux = frole(&["LNX-TST-010", "LNX-TST-011"]);
        assert!(!ajuster_etat(&mut e, j("2026-11-14"), &deux, &[], du_code));
        assert_eq!(e.montees.len(), 1);
        assert!(ajuster_etat(&mut e, j("2026-11-15"), &deux, &[], du_code));
        assert_eq!(
            e.montees.iter().map(|m| m.regle.as_str()).collect::<Vec<_>>(),
            ["LNX-TST-010", "LNX-TST-011"]
        );
        assert_eq!(e.frolent_depuis.len(), 0);
    }

    fn dossier_d_essai(nom: &str) -> std::path::PathBuf {
        let d = crate::socle::dossier_local().join(format!("essai-reglage-{nom}"));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Annuler une montée rend le délai du code et ne la refait jamais ; couper rend les délais du code sans rien
    /// oublier ; « tout remettre » vide tout et coupe.
    #[test]
    fn chaque_changement_s_annule_exactement() {
        let d = dossier_d_essai("annuler");
        let mut e = Etat::default();
        e.frolent_depuis.insert("LNX-TST-010".into(), "2026-11-01".into());
        e.frolent_depuis.insert("LNX-TST-011".into(), "2026-11-01".into());
        assert!(ajuster_etat(
            &mut e,
            j("2026-11-08"),
            &frole(&["LNX-TST-010", "LNX-TST-011"]),
            &[],
            du_code
        ));
        ecrire_dans(&d, &e).unwrap();
        assert_eq!(lire_dans(&d).delais_longs().len(), 2);

        mettre_en_marche_dans(&d, false).unwrap();
        assert_eq!(lire_dans(&d).delais_longs(), BTreeSet::new());
        mettre_en_marche_dans(&d, true).unwrap();
        assert_eq!(lire_dans(&d).delais_longs().len(), 2);

        assert!(annuler_dans(&d, "LNX-TST-010").unwrap());
        assert!(!annuler_dans(&d, "LNX-TST-010").unwrap());
        let Lu::Cru(mut apres) = lire_dans(&d) else {
            panic!("illisible")
        };
        assert_eq!(apres.delais_longs(), BTreeSet::from(["LNX-TST-011".to_string()]));
        // Elle frôle encore deux semaines : jamais remontée.
        apres.frolent_depuis.insert("LNX-TST-010".into(), "2026-11-08".into());
        ajuster_etat(&mut apres, j("2026-11-30"), &frole(&["LNX-TST-010"]), &[], du_code);
        assert!(!apres.delais_longs().contains("LNX-TST-010"));

        tout_remettre_dans(&d).unwrap();
        assert_eq!(
            lire_dans(&d),
            Lu::Cru(Etat {
                v: 1,
                coupe: true,
                ..Etat::default()
            })
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un fichier posé hors de Vanguard (sans sceau) : les délais du code, et l'ajustement ne le réécrit pas.
    #[test]
    fn fichier_douteux_delais_du_code_et_rien_ecrit() {
        let d = dossier_d_essai("douteux");
        ecrire_dans(&d, &Etat::default()).unwrap();
        let force = br#"{"v":1,"montees":[{"quand":"2026-11-01","regle":"LNX-TST-010","avant_s":600,"apres_s":1800,"mesure_ms":1}]}"#;
        std::fs::write(d.join(REGLAGE), force).unwrap();
        assert_eq!(lire_dans(&d), Lu::Douteux);
        assert_eq!(lire_dans(&d).delais_longs(), BTreeSet::new());
        ajuster_dans(&d, j("2026-11-08"), &super::super::mesures::Mesures::default(), du_code);
        assert_eq!(std::fs::read(d.join(REGLAGE)).unwrap(), force);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Coupé, rien n'est ajusté.
    #[test]
    fn coupe_rien_n_est_ajuste() {
        let d = dossier_d_essai("coupe");
        tout_remettre_dans(&d).unwrap();
        let avant = std::fs::read(d.join(REGLAGE)).unwrap();
        let mut m = super::super::mesures::Mesures::default();
        m.ajouter(&[("LNX-TST-010", Duration::from_mins(9))], j("2026-11-08"));
        ajuster_dans(&d, j("2026-11-08"), &m, du_code);
        assert_eq!(std::fs::read(d.join(REGLAGE)).unwrap(), avant);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Une passe de la cache sur `e` (pas de raccourci seulement) ; vrai si `e` a changé.
    fn raccourcir_etat(
        e: &mut Etat,
        aujourd_hui: chrono::NaiveDate,
        mesures: &BTreeMap<String, super::super::mesures::Cache>,
    ) -> bool {
        let avant = e.clone();
        let _ = regler_cache(e, aujourd_hui, mesures);
        *e != avant
    }

    fn comparaisons(paires: &[(i64, bool)]) -> BTreeMap<String, super::super::mesures::Cache> {
        BTreeMap::from([(
            "LNX-MAJ-001".to_string(),
            super::super::mesures::Cache {
                recentes: paires.to_vec(),
                ..Default::default()
            },
        )])
    }

    /// Dès un écart parmi les vérifications à neuf (R2) : la durée de la cache descend d'un pas de 15 minutes, jamais
    /// sous son plancher ; les comparaisons déjà jugées ne comptent plus ; chaque pas part du précédent, et une chaîne
    /// rompue s'arrête au dernier pas valable.
    #[test]
    fn la_duree_de_la_cache_raccourcit_dans_ses_bornes() {
        let t = super::super::cache::en_cache("LNX-MAJ-001").unwrap();
        let mut e = Etat::default();
        // Aucun écart, et aucun pas à défaire : rien.
        assert!(!raccourcir_etat(
            &mut e,
            j("2026-11-02"),
            &comparaisons(&[(1, false), (2, false), (3, false)])
        ));
        // Un seul écart suffit.
        let mut paires = vec![(1, false), (2, false), (3, false), (4, true)];
        assert!(raccourcir_etat(&mut e, j("2026-11-02"), &comparaisons(&paires)));
        assert_eq!(
            e.raccourcies,
            vec![Raccourcie {
                quand: "2026-11-02".into(),
                regle: "LNX-MAJ-001".into(),
                avant_min: t.duree_min,
                apres_min: t.duree_min - 15,
                comparees: 4,
                ecarts: 1,
                depuis_s: 4,
            }]
        );
        assert_eq!(e.pour_le_cache().unwrap()["LNX-MAJ-001"], t.duree_min - 15);
        // Les mêmes comparaisons ne le refont pas.
        assert!(!raccourcir_etat(&mut e, j("2026-11-03"), &comparaisons(&paires)));
        // De nouvelles, encore et encore : jamais sous le plancher.
        for k in 0..20 {
            paires.extend((0..4).map(|i| (10 + k * 4 + i, true)));
            raccourcir_etat(
                &mut e,
                j("2026-11-04"),
                &comparaisons(&paires[paires.len().saturating_sub(16)..]),
            );
        }
        let pas = usize::from((t.duree_min - t.plancher_min) / 15);
        assert_eq!(e.raccourcies.len(), pas);
        assert_eq!(e.raccourcies.last().unwrap().apres_min, t.plancher_min);
        for (i, r) in e.raccourcies.iter().enumerate() {
            let i = u16::try_from(i).unwrap();
            assert_eq!(
                (r.avant_min, r.apres_min),
                (t.duree_min - 15 * i, t.duree_min - 15 * (i + 1))
            );
        }
        assert_eq!(e.pour_le_cache().unwrap()["LNX-MAJ-001"], t.plancher_min);
        assert_eq!(e.clone().borne().raccourcies, e.raccourcies);
        // Hors des bornes (au-dessus de la durée du code, sous le plancher, deux pas d'un coup, autre règle) : retiré à
        // la lecture, avec les pas d'après.
        let mut faux = e.clone();
        faux.raccourcies[0].apres_min = t.duree_min + 15;
        assert_eq!(faux.borne().raccourcies.len(), 0);
        let mut faux = e.clone();
        faux.raccourcies[pas - 1].apres_min = t.plancher_min - 15;
        faux.raccourcies[pas - 1].avant_min = t.plancher_min;
        assert_eq!(faux.borne().raccourcies.len(), pas - 1);
        let mut faux = e.clone();
        faux.raccourcies[0].apres_min = t.duree_min - 30;
        assert_eq!(faux.borne().raccourcies.len(), 0);
        let mut faux = e.clone();
        faux.raccourcies.remove(1);
        assert_eq!(faux.borne().raccourcies.len(), 1);
        let mut faux = e.clone();
        faux.raccourcies[0].regle = "LNX-PFE-001".into();
        assert_eq!(faux.borne().raccourcies.len(), 0);
        // Coupé : pas de cache du tout.
        e.coupe = true;
        assert_eq!(e.pour_le_cache(), None);
    }

    /// Annuler un pas de raccourci, couper, tout remettre : la durée d'avant ce pas revient exactement, la règle n'est
    /// plus raccourcie, et chaque geste vide la cache (même un fichier douteux).
    #[test]
    fn chaque_geste_vide_la_cache_et_annule_exactement() {
        let d = dossier_d_essai("cache");
        let cache = d.join(super::super::cache::CACHE);
        let poser = || crate::sceau::ecrire_dans(&d, super::super::cache::CACHE, b"{}").unwrap();
        let t = super::super::cache::en_cache("LNX-MAJ-001").unwrap();
        let mut e = Etat::default();
        assert!(raccourcir_etat(
            &mut e,
            j("2026-11-02"),
            &comparaisons(&[(1, true), (2, true), (3, true), (4, true)])
        ));
        ecrire_dans(&d, &e).unwrap();
        assert_eq!(lire_dans(&d).pour_le_cache().unwrap().len(), 1);
        // Deux pas de plus : chacun s'annule exactement, un par un.
        let mut trois = e.clone();
        for k in 0..2 {
            assert!(raccourcir_etat(
                &mut trois,
                j("2026-11-03"),
                &comparaisons(&(0..4).map(|i| (10 + k * 4 + i, true)).collect::<Vec<_>>())
            ));
        }
        assert_eq!(trois.raccourcies.len(), 3);
        ecrire_dans(&d, &trois).unwrap();
        poser();
        assert_eq!(
            annuler_duree_dans(&d, "LNX-MAJ-001", Some(t.duree_min - 30)).unwrap(),
            Some(t.duree_min - 30)
        );
        assert!(super::super::cache::oubliee_dans(&d));
        assert_eq!(lire_dans(&d).pour_le_cache().unwrap()["LNX-MAJ-001"], t.duree_min - 30);
        assert_eq!(
            annuler_duree_dans(&d, "LNX-MAJ-001", None).unwrap(),
            Some(t.duree_min - 15)
        );
        let Lu::Cru(un) = lire_dans(&d) else {
            panic!("illisible")
        };
        assert_eq!(un.raccourcies, e.raccourcies);
        assert!(un.gardees.contains("LNX-MAJ-001"));
        ecrire_dans(&d, &e).unwrap();

        poser();
        mettre_en_marche_dans(&d, false).unwrap();
        assert!(super::super::cache::oubliee_dans(&d));
        assert_eq!(lire_dans(&d).pour_le_cache(), None);
        poser();
        mettre_en_marche_dans(&d, true).unwrap();
        assert!(super::super::cache::oubliee_dans(&d));
        assert_eq!(lire_dans(&d).pour_le_cache().unwrap().len(), 1);

        poser();
        assert_eq!(annuler_duree_dans(&d, "LNX-MAJ-001", None).unwrap(), Some(t.duree_min));
        assert!(super::super::cache::oubliee_dans(&d));
        assert_eq!(annuler_duree_dans(&d, "LNX-MAJ-001", None).unwrap(), None);
        let Lu::Cru(mut apres) = lire_dans(&d) else {
            panic!("illisible")
        };
        assert_eq!(apres.pour_le_cache(), Some(BTreeMap::new()));
        assert!(!raccourcir_etat(
            &mut apres,
            j("2026-11-09"),
            &comparaisons(&[(5, true), (6, true), (7, true), (8, true)])
        ));

        // Un fichier de cache douteux : « tout remettre » le vide aussi.
        poser();
        std::fs::write(&cache, b"{\"v\":1}").unwrap();
        tout_remettre_dans(&d).unwrap();
        assert!(super::super::cache::oubliee_dans(&d));
        assert_eq!(lire_dans(&d).pour_le_cache(), None);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R2, dans l'autre sens : 20 vérifications à neuf justes de suite défont le dernier pas de l'agent, exactement,
    /// et jamais plus haut que la durée du code ; sans pas de l'agent, rien ne s'allonge.
    #[test]
    fn un_pas_se_defait_apres_vingt_verifications_justes() {
        let t = super::super::cache::en_cache("LNX-MAJ-001").unwrap();
        let mut e = Etat::default();
        assert!(raccourcir_etat(&mut e, j("2026-11-02"), &comparaisons(&[(1, true)])));
        let mut paires = vec![(1, true)];
        paires.extend((2..21).map(|q| (q, false)));
        let pour = regler_cache(&mut e.clone(), j("2026-11-03"), &comparaisons(&paires));
        assert!(pour.rallongees.is_empty(), "19 de suite ne suffisent pas");
        paires.push((21, false));
        let pour = regler_cache(&mut e.clone(), j("2026-11-03"), &comparaisons(&paires));
        let r = &pour.rallongees[0];
        assert_eq!(
            (r.avant_min, r.apres_min, r.comparees),
            (t.duree_min - 15, t.duree_min, 20)
        );
        assert!(r.apres_min <= t.duree_min);
        assert!(defaire_pas(&mut e, r));
        assert_eq!(e.raccourcies, []);
        assert_eq!(e.pour_le_cache().unwrap().get("LNX-MAJ-001"), None);
        assert!(e.dans_ses_bornes());
        // Le même pas ne se défait pas deux fois, et les mêmes vérifications ne comptent plus.
        assert!(!defaire_pas(&mut e, r));
        assert_eq!(
            regler_cache(&mut e, j("2026-11-04"), &comparaisons(&paires)).rallongees,
            []
        );
        // Sans pas de l'agent : la durée du code, jamais plus.
        let longues: Vec<(i64, bool)> = (100..200).map(|q| (q, false)).collect();
        let mut vierge = Etat::default();
        assert_eq!(
            regler_cache(&mut vierge, j("2026-11-04"), &comparaisons(&longues)).rallongees,
            []
        );
        assert_eq!(vierge, Etat::default());
    }

    /// R3 : plus de 2 % d'écarts sur les 14 derniers jours (50 vérifications au moins) coupent la cache de la règle
    /// (jamais reprise ensuite) ; 2 % tout juste, non. « Annuler » la rend, gardée (l'agent ne la recoupe pas), et
    /// vide la cache.
    #[test]
    fn plus_de_deux_pour_cent_d_ecarts_coupent_la_cache() {
        let d = dossier_d_essai("coupure");
        let jour_s = |t: &str| j(t).and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp();
        let quinzaine = |ecarts: usize| -> Vec<(i64, bool)> {
            (0..50)
                .map(|i| (jour_s("2026-11-10") + i64::try_from(i).unwrap(), i < ecarts))
                .collect()
        };
        let pour = regler_cache(&mut Etat::default(), j("2026-11-14"), &comparaisons(&quinzaine(1)));
        assert_eq!(pour.coupures, []);
        // Trop vieux (au-delà de 14 jours) : rien non plus.
        let pour = regler_cache(&mut Etat::default(), j("2026-11-30"), &comparaisons(&quinzaine(2)));
        assert_eq!(pour.coupures, []);
        let m = super::super::mesures::Mesures {
            cache: comparaisons(&quinzaine(2)),
            ..Default::default()
        };
        ajuster_dans(&d, j("2026-11-14"), &m, du_code);
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert_eq!(e.coupures.len(), 1);
        assert_eq!(e.raccourcies, []);
        let cache = lire_dans(&d).pour_le_cache().unwrap();
        assert_eq!(super::super::cache::duree_appliquee("LNX-MAJ-001", &cache), None);
        // La passe suivante ne la recoupe pas, ne la raccourcit pas.
        ajuster_dans(&d, j("2026-11-15"), &m, du_code);
        assert_eq!(lire_dans(&d), Lu::Cru(e));
        crate::sceau::ecrire_dans(&d, super::super::cache::CACHE, b"{}").unwrap();
        assert!(annuler_coupure_dans(&d, "LNX-MAJ-001").unwrap());
        assert!(super::super::cache::oubliee_dans(&d));
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert!(e.coupures.is_empty() && e.gardees.contains("LNX-MAJ-001"));
        ajuster_dans(&d, j("2026-11-16"), &m, du_code);
        assert_eq!(lire_dans(&d), Lu::Cru(e));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R4, côté réglage : un second essai se note une fois par règle, se lit pour le bilan, s'annule et n'est
    /// jamais redonné ; coupé, aucun ne vaut.
    #[test]
    fn un_second_essai_se_donne_une_fois_et_s_annule() {
        let d = dossier_d_essai("relance");
        let demande = [("LNX-TST-010".to_string(), 4, 3)];
        let faites = relancer_dans(&d, j("2026-11-02"), &demande);
        assert_eq!(faites.len(), 1);
        assert_eq!((faites[0].passageres, faites[0].reprises), (4, 3));
        assert_eq!(relancer_dans(&d, j("2026-11-03"), &demande), []);
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert_eq!(e.relancees(), BTreeSet::from(["LNX-TST-010".to_string()]));
        assert!(relances_connues_dans(&d).unwrap().contains("LNX-TST-010"));
        assert!(annuler_relance_dans(&d, "LNX-TST-010").unwrap());
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert!(e.relancees().is_empty());
        assert!(relances_connues_dans(&d).unwrap().contains("LNX-TST-010"));
        assert_eq!(relancer_dans(&d, j("2026-11-04"), &demande), []);
        // Un identifiant hors des règles gardées n'est jamais noté, ni une règle des journaux effacés.
        assert_eq!(
            relancer_dans(&d, j("2026-11-04"), &[("pas une règle".to_string(), 4, 3)]),
            []
        );
        for id in crate::machine::regles::SANS_SECOND_ESSAI {
            assert_eq!(relancer_dans(&d, j("2026-11-04"), &[(id.to_string(), 4, 3)]), []);
        }
        mettre_en_marche_dans(&d, false).unwrap();
        assert_eq!(relances_connues_dans(&d), None);
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert!(e.relancees().is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// R1 : une règle sortie de son délai deux jours de la même semaine voit le sien monter tout de suite, sans
    /// attendre deux semaines ; une seule sortie, non ; une règle déjà longue, jamais.
    #[test]
    fn deux_sorties_de_delai_en_sept_jours_montent() {
        let d = dossier_d_essai("hors-delai");
        let mut m = super::super::mesures::Mesures::default();
        m.ajouter(&[("LNX-TST-010", DELAI), ("LNX-MAJ-010", DELAI_LONG)], j("2026-11-02"));
        ajuster_dans(&d, j("2026-11-02"), &m, du_code);
        assert!(lire_dans(&d).delais_longs().is_empty(), "une sortie ne suffit pas");
        m.ajouter(&[("LNX-TST-010", DELAI), ("LNX-MAJ-010", DELAI_LONG)], j("2026-11-04"));
        ajuster_dans(&d, j("2026-11-04"), &m, du_code);
        assert_eq!(
            lire_dans(&d).delais_longs(),
            BTreeSet::from(["LNX-TST-010".to_string()])
        );
        let Lu::Cru(e) = lire_dans(&d) else { panic!("illisible") };
        assert_eq!(e.montees.len(), 1);
        assert_eq!(
            (e.montees[0].avant_s, e.montees[0].apres_s),
            (DELAI.as_secs(), DELAI_LONG.as_secs())
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Chaque règle du registre, sur chaque système, a un identifiant que l'auto-réglage garde.
    #[test]
    fn chaque_regle_a_un_identifiant_garde() {
        use crate::machine::regles::{Os, regles};
        for os in [Os::Linux, Os::Windows, Os::Tous] {
            for r in regles(os) {
                assert!(id_valide(r.id), "{}", r.id);
            }
        }
        assert!(!id_valide("LNX-TST-01") && !id_valide("lnx-TST-010") && !id_valide("LNX_TST_010"));
    }

    proptest! {
        /// Quel que soit le contenu du fichier, chaque règle garde un délai entre celui du code et `DELAI_LONG`, et
        /// « tout remettre » rend exactement ceux du code.
        #[test]
        fn tout_fichier_reste_dans_les_bornes(
            octets in proptest::collection::vec(any::<u8>(), 0..400),
            ids in proptest::collection::vec("[A-Z]{3}-[A-Z]{3}-[0-9]{3}|LNX-[A-Z]{3}-0[0-9]{2}", 0..80),
            coupe in any::<bool>(),
            secs in any::<u64>(),
            minutes in proptest::collection::vec((any::<u16>(), any::<u16>()), 80),
        ) {
            use crate::machine::regles::{Os, regles};
            let montees: Vec<serde_json::Value> = ids
                .iter()
                .map(|r| serde_json::json!({"quand": "2026-11-01", "regle": r, "avant_s": 600, "apres_s": secs % 3 * 1200 + 600, "mesure_ms": 1}))
                .collect();
            let raccourcies: Vec<serde_json::Value> = ids
                .iter()
                .zip(&minutes)
                .map(|(r, (a, b))| serde_json::json!({"quand": "2026-11-01", "regle": r, "avant_min": a, "apres_min": b, "comparees": 4, "ecarts": 1, "depuis_s": 1}))
                .collect();
            let coupures: Vec<serde_json::Value> = ids
                .iter()
                .map(|r| serde_json::json!({"quand": "2026-11-01", "regle": r, "comparees": 50, "ecarts": 2}))
                .collect();
            let relances: Vec<serde_json::Value> = ids
                .iter()
                .map(|r| serde_json::json!({"quand": "2026-11-01", "regle": r, "passageres": 4, "reprises": 3}))
                .collect();
            let json = serde_json::to_vec(&serde_json::json!({
                "v": 1, "coupe": coupe, "montees": montees, "raccourcies": raccourcies,
                "coupures": coupures, "relances": relances,
            }))
            .unwrap();
            let toutes: Vec<_> = [Os::Linux, Os::Windows, Os::Tous].into_iter().flat_map(regles).collect();
            for contenu in [octets, json] {
                let e = lire_de(&contenu);
                prop_assert!(e.montees.len() <= MONTEES_MAX);
                prop_assert!(e.frolent_depuis.len() <= SUIVIES_MAX && e.refusees.len() <= SUIVIES_MAX);
                prop_assert!(e.dans_ses_bornes());
                prop_assert!(e.relances.len() <= MONTEES_MAX && e.coupures.len() <= super::super::cache::TABLE.len());
                prop_assert!(e.relancees().iter().all(|r| id_valide(r)));
                // La cache : jamais au-delà de la durée du code, jamais sous le plancher, pour ses seules règles ;
                // une règle coupée n'est jamais reprise.
                if let Some(c) = e.pour_le_cache() {
                    for (regle, min) in &c {
                        let t = super::super::cache::en_cache(regle);
                        prop_assert!(t.is_some(), "{}", regle);
                        if let Some(d) = super::super::cache::duree_appliquee(regle, &c) {
                            let t = t.unwrap();
                            prop_assert!(*min != 0 && d >= t.plancher_min && d <= t.duree_min);
                        }
                    }
                }
                let longs = Lu::Cru(e).delais_longs();
                for r in &toutes {
                    let d = r.delai_avec(&longs);
                    prop_assert!(d >= r.delai() && d >= DELAI && d <= DELAI_LONG, "{} {:?}", r.id, d);
                }
            }
            let d = crate::socle::dossier_local().join("essai-reglage-bornes");
            let _ = std::fs::remove_dir_all(&d);
            tout_remettre_dans(&d).unwrap();
            let longs = lire_dans(&d).delais_longs();
            for r in &toutes {
                prop_assert_eq!(r.delai_avec(&longs), r.delai());
            }
            let _ = std::fs::remove_dir_all(&d);
        }

        /// Quelles que soient les vérifications à neuf, jour après jour, et ce que l'agent retient : la durée de la cache
        /// reste entre le plancher et celle du code, chaque pas est d'un cran, l'état reste dans ses bornes, et une
        /// règle coupée n'est plus jamais reprise.
        #[test]
        fn la_cache_reste_dans_ses_bornes_jour_apres_jour(
            jours in proptest::collection::vec(proptest::collection::vec(any::<bool>(), 0..30), 1..20),
            garder in proptest::collection::vec(any::<bool>(), 20),
        ) {
            let t = super::super::cache::en_cache("LNX-MAJ-001").unwrap();
            let mut e = Etat::default();
            let mut paires = Vec::new();
            let mut coupee = false;
            for (n, verifs) in jours.iter().enumerate() {
                let jour = j("2026-11-01") + chrono::Duration::days(i64::try_from(n).unwrap());
                let base = jour.and_hms_opt(1, 0, 0).unwrap().and_utc().timestamp();
                for (i, x) in verifs.iter().enumerate() {
                    paires.push((base + i64::try_from(i).unwrap(), *x));
                }
                let pour = regler_cache(&mut e, jour, &comparaisons(&paires));
                if garder[n] {
                    for r in &pour.rallongees {
                        prop_assert!(r.apres_min <= t.duree_min && r.avant_min >= t.plancher_min);
                        prop_assert_eq!(r.apres_min - r.avant_min, super::super::cache::PAS_MIN);
                        defaire_pas(&mut e, r);
                    }
                    e.coupures.extend(pour.coupures);
                }
                prop_assert!(e.dans_ses_bornes());
                let c = e.pour_le_cache().unwrap();
                match super::super::cache::duree_appliquee("LNX-MAJ-001", &c) {
                    Some(d) => {
                        prop_assert!(!coupee);
                        prop_assert!(d >= t.plancher_min && d <= t.duree_min);
                    }
                    None => coupee = true,
                }
            }
        }

        /// Quelles que soient les mesures, l'ordre de départ lance chaque vérification une fois et une seule.
        #[test]
        fn toujours_une_permutation(
            n in 0usize..80,
            mesures in proptest::collection::btree_map("[A-C]{1,2}", any::<u64>(), 0..12),
            noms in proptest::collection::vec(proptest::option::of("[A-C]{1,2}"), 80),
        ) {
            let ids: Vec<Option<&str>> = noms.iter().take(n).map(Option::as_deref).collect();
            let mut ordre = ordre_de_depart(&ids, &mesures);
            prop_assert_eq!(permutation_ou_rangs(ordre.clone(), ids.len()), ordre.clone());
            ordre.sort_unstable();
            prop_assert_eq!(ordre, (0..ids.len()).collect::<Vec<_>>());
        }
    }
}
