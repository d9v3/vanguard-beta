//! L'auto-réglage local du bilan : ce que Vanguard ajuste de lui-même, sur cet ordinateur, d'après les durées
//! mesurées de ses règles (`super::mesures`). Rien ne sort de l'ordinateur, rien ne passe par une IA.
//!
//! Ce qui peut bouger, et seulement entre des bornes écrites ici :
//! - l'**ordre de départ** des règles, la plus longue d'abord (médiane de la semaine), pour que le bilan ne finisse
//!   pas sur elle. Les règles tournent toutes en même temps, chacune dans son fil ; l'ordre ne change ni ce qu'elles
//!   rendent ni l'ordre affiché (celui des rangs) ;
//! - le **délai** d'une règle qui frôle le sien (sa plus longue durée de la semaine au-delà de la moitié) deux
//!   semaines de suite : il monte de `DELAI` à `DELAI_LONG`, jamais plus haut, jamais sous la valeur du code. Chaque
//!   montée est notée (date, règle, avant, après, mesure), 50 au plus, dans `autotest/reglage.json`, scellé.
//!
//! - la **durée de la cache** du passage horaire (`super::cache`) d'une règle dont le résultat repris s'est trop
//!   souvent révélé dépassé (un écart sur trois vérifications à neuf qui suivent une reprise, quatre au moins) : elle
//!   descend de 15 minutes, jamais sous le plancher de `cache::TABLE`, jamais au-dessus de la durée du code. La cache
//!   elle-même suit l'interrupteur : coupé ou fichier douteux, rien n'est repris.
//!
//! Chaque montée et chaque durée raccourcie s'annule seule dans Paramètres (la règle n'est plus jamais changée),
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

/// Vérifications à neuf jugées au moins avant de raccourcir une durée de la cache, et part d'écarts (un sur trois).
const COMPAREES_MIN: usize = 4;
const ECARTS_SUR: usize = 3;

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
    /// Les règles dont un raccourci a été annulé : leur durée ne descend plus.
    #[serde(default)]
    pub gardees: BTreeSet<String>,
}

/// Ce que le fichier donne.
#[derive(Debug, PartialEq, Eq)]
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
        self.v = 1;
        self
    }

    /// La durée de chaque règle raccourcie de la cache (son dernier pas), telle que le passage horaire l'applique ;
    /// `None` quand le réglage est coupé : pas de cache.
    fn pour_le_cache(&self) -> Option<BTreeMap<String, u16>> {
        (!self.coupe).then(|| {
            self.raccourcies
                .iter()
                .map(|r| (r.regle.clone(), r.apres_min))
                .collect()
        })
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

/// Les durées raccourcies de la cache sur cet ordinateur ; `None` : coupé ou douteux, la cache ne sert pas.
pub(crate) fn pour_le_cache() -> Option<BTreeMap<String, u16>> {
    lire_dans(&crate::socle::dossier_local()).pour_le_cache()
}

/// Les règles au délai monté sur cet ordinateur (le bilan les lit une fois).
pub(crate) fn delais_longs() -> BTreeSet<String> {
    lire_dans(&crate::socle::dossier_local()).delais_longs()
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
    delai_du_code: impl Fn(&str) -> Option<Duration>,
) -> bool {
    let avant = e.clone();
    let montees: BTreeSet<String> = e.montees.iter().map(|m| m.regle.clone()).collect();
    let candidates: BTreeMap<&str, u64> = frolent
        .iter()
        .filter(|(r, _)| {
            id_valide(r) && !montees.contains(r) && !e.refusees.contains(r) && delai_du_code(r) == Some(DELAI)
        })
        .map(|(r, ms)| (r.as_str(), *ms))
        .collect();
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

/// Raccourcit la durée de la cache d'une règle dont les vérifications à neuf contredisent trop souvent le résultat
/// repris juste avant (`super::mesures::Cache::recentes`, comparaisons d'après le dernier pas) : un pas de plus, 15
/// minutes de moins, jamais sous le plancher de `cache::TABLE`. Une règle gardée (raccourci annulé) ne change plus.
/// Rend vrai si l'état a changé.
fn raccourcir_etat(
    e: &mut Etat,
    aujourd_hui: chrono::NaiveDate,
    mesures: &BTreeMap<String, super::mesures::Cache>,
) -> bool {
    let avant = e.clone();
    for t in super::cache::TABLE {
        if e.gardees.contains(t.regle) {
            continue;
        }
        let Some(m) = mesures.get(t.regle) else {
            continue;
        };
        let deja = e.raccourcies.iter().rev().find(|r| r.regle == t.regle).cloned();
        let depuis = deja.as_ref().map_or(i64::MIN, |r| r.depuis_s);
        let jugees: Vec<(i64, bool)> = m.recentes.iter().copied().filter(|(q, _)| *q > depuis).collect();
        let ecarts = jugees.iter().filter(|(_, x)| *x).count();
        if jugees.len() < COMPAREES_MIN || ecarts.saturating_mul(ECARTS_SUR) < jugees.len() {
            continue;
        }
        let actuelle = deja.as_ref().map_or(t.duree_min, |r| r.apres_min);
        let apres = actuelle.saturating_sub(super::cache::PAS_MIN).max(t.plancher_min);
        if apres >= actuelle {
            continue;
        }
        let r = Raccourcie {
            quand: jour(aujourd_hui),
            regle: t.regle.to_string(),
            avant_min: actuelle,
            apres_min: apres,
            comparees: u32::try_from(jugees.len()).unwrap_or(u32::MAX),
            ecarts: u32::try_from(ecarts).unwrap_or(u32::MAX),
            depuis_s: jugees.iter().map(|(q, _)| *q).max().unwrap_or(depuis),
        };
        e.raccourcies.push(r);
    }
    *e != avant
}

/// Ce qu'une passe de l'auto-réglage ajoute : les montées de délai et les pas de raccourci nouveaux.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Prevu {
    pub montees: Vec<Montee>,
    pub raccourcies: Vec<Raccourcie>,
}

/// Le jugement d'une passe d'après les mesures de cet ordinateur : l'état lu (`None` : pas de fichier) et celui
/// d'après. Rien (`None`) en lecture seule (l'autotest), réglage coupé ou fichier douteux.
fn juger_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
) -> Option<(Option<Etat>, Etat)> {
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
    let verdict = super::mesures::juger(mesures, aujourd_hui, |id| delai_du_code(id).unwrap_or(DELAI));
    let frolent: Vec<(String, u64)> = verdict
        .frolent_le_delai
        .into_iter()
        .map(|f| (f.regle, f.max_ms))
        .collect();
    ajuster_etat(&mut e, aujourd_hui, &frolent, delai_du_code);
    raccourcir_etat(&mut e, aujourd_hui, &mesures.cache);
    Some((avant, e))
}

/// Ce que la passe ajouterait, sans rien écrire : ce que lit la mission de l'agent (`agent::missions`).
pub(crate) fn prevoir_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
) -> Option<Prevu> {
    let (avant, mut e) = juger_dans(dossier, aujourd_hui, mesures, delai_du_code)?;
    let avant = avant.unwrap_or_default();
    Some(Prevu {
        montees: e.montees.split_off(avant.montees.len().min(e.montees.len())),
        raccourcies: e
            .raccourcies
            .split_off(avant.raccourcies.len().min(e.raccourcies.len())),
    })
}

/// Après un bilan noté, par l'Agent Vanguard (`agent`) seulement : la même passe, mais seules les montées et les pas
/// retenus (vérifiés par l'agent) s'appliquent ; une montée écartée garde son suivi, elle se reprendra. Le suivi des
/// règles qui frôlent leur délai s'écrit aussi. Rend ce qui a été écrit.
pub(crate) fn ajuster_retenus_dans(
    dossier: &Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &super::mesures::Mesures,
    delai_du_code: &dyn Fn(&str) -> Option<Duration>,
    retenir_montee: &dyn Fn(&Montee) -> bool,
    retenir_pas: &dyn Fn(&Raccourcie) -> bool,
) -> Prevu {
    let Some((avant, mut e)) = juger_dans(dossier, aujourd_hui, mesures, delai_du_code) else {
        return Prevu::default();
    };
    let base = avant.clone().unwrap_or_default();
    let nouvelles = e.montees.split_off(base.montees.len().min(e.montees.len()));
    let mut montees = Vec::new();
    for m in nouvelles {
        if retenir_montee(&m) {
            montees.push(m);
        } else if let Some(depuis) = base.frolent_depuis.get(&m.regle) {
            e.frolent_depuis.insert(m.regle.clone(), depuis.clone());
        }
    }
    e.montees.extend(montees.iter().cloned());
    let pas = e.raccourcies.split_off(base.raccourcies.len().min(e.raccourcies.len()));
    let raccourcies: Vec<Raccourcie> = pas.into_iter().filter(|r| retenir_pas(r)).collect();
    e.raccourcies.extend(raccourcies.iter().cloned());
    // Relu juste avant d'écrire : un changement voulu (annuler, tout remettre, couper) écrit depuis la première
    // lecture n'est jamais écrasé ; la montée attend la prochaine passe.
    let inchange = match lire_dans(dossier) {
        Lu::Absent => avant.is_none(),
        Lu::Cru(x) => avant.as_ref() == Some(&x),
        Lu::Douteux => false,
    };
    if e != base && inchange && ecrire_dans(dossier, &e.borne()).is_ok() {
        Prevu { montees, raccourcies }
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
    let _ = ajuster_retenus_dans(dossier, aujourd_hui, mesures, &delai_du_code, &|_| true, &|_| true);
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
    let mut e = pour_changer(dossier);
    e.coupe = !en_marche;
    super::cache::oublier_dans(dossier, true)?;
    ecrire_dans(dossier, &e.borne())
}

/// Annule la montée de `regle` : son délai redevient celui du code, et elle ne remontera plus. Rend vrai si elle
/// était montée.
fn annuler_dans(dossier: &Path, regle: &str) -> std::io::Result<bool> {
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

/// Tout remettre comme à l'origine : plus rien de monté, suivi ni refusé, la cache vidée, les états de l'Agent
/// Vanguard (`agent`) remis à zéro, et le réglage coupé jusqu'à ce qu'on le remette en marche.
fn tout_remettre_dans(dossier: &Path) -> std::io::Result<()> {
    super::cache::oublier_dans(dossier, true)?;
    crate::agent::tout_remettre_dans(dossier, chrono::Utc::now().timestamp())?;
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
        Lu::Cru(e) if e.montees.is_empty() && e.raccourcies.is_empty() => tr!("oui", "yes").to_string(),
        Lu::Cru(e) => trf!(
            "oui ({} changement(s))",
            "yes ({} change(s))",
            e.montees.len() + e.raccourcies.len()
        ),
        Lu::Douteux => tr!(
            "oui (fichier douteux : délais d'origine)",
            "yes (doubtful file: original time limits)"
        )
        .to_string(),
    }
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

/// Un changement en vigueur, comme le menu les numérote.
enum Changement {
    Montee(Montee),
    Raccourcie(Raccourcie),
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

/// Annule la montée (`montee`) ou un pas de raccourci (`duree`, à partir de `depuis_min`, sinon le dernier) de
/// `regle` ; rend vrai si quelque chose a été annulé.
fn dire_annule(regle: &str, montee: bool, duree: bool, depuis_min: Option<u16>) -> bool {
    let dossier = crate::socle::dossier_local();
    let mut fait = false;
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

/// `vanguard parametres auto-reglage [oui|non|tout-remettre|annuler <règle>]` : sans mot, l'état et les changements.
pub(crate) fn commande(mots: &[String]) {
    let mots: Vec<String> = mots.iter().map(|m| m.trim().to_lowercase()).collect();
    match mots.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => {
            afficher();
        }
        ["oui" | "o" | "yes" | "y" | "on"] => dire_en_marche(true),
        ["non" | "n" | "no" | "off"] => dire_en_marche(false),
        ["tout-remettre" | "reset" | "origine" | "original"] => dire_tout_remis(),
        ["annuler" | "undo", regle] => {
            if !dire_annule(&regle.to_uppercase(), true, true, None) {
                trp!(
                    "  Rien n'a changé : cette règle n'a ni délai monté ni durée raccourcie.",
                    "  Nothing changed: this rule has neither a raised time limit nor a shortened duration."
                );
            }
        }
        _ => trp!(
            "  Valeurs : oui, non, tout-remettre, annuler <règle> (par exemple « annuler LNX-NOY-001 »).",
            "  Values: yes, no, reset, undo <rule> (for example “undo LNX-NOY-001”)."
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
        };
        afficher_aligne(&format!("  {TOUCHE}{:>2}{RESET} ", i + 1), &texte, 5, "");
    }
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
        "Oui : un petit agent intégré, sans IA, règle Vanguard sur cet ordinateur, entre des bornes fixes. Le bilan lance d'abord ses règles les plus longues, et le délai d'une règle qui le frôle deux semaines de suite monte de 10 à 30 minutes, jamais plus. Le passage horaire reprend aussi, une fois sur deux au plus, le résultat récent de quelques vérifications lentes (mises à jour, fichiers sensibles), avec son âge ; un bilan que vous lancez vérifie tout à neuf, et une durée qui se trompe trop souvent raccourcit. Les règles et ce qu'elles jugent ne changent jamais. Chaque changement est noté avec sa valeur d'avant et s'annule ici. Rien n'est envoyé.",
        "Yes: a small built-in agent, with no AI, tunes Vanguard on this computer, within fixed bounds. The check starts its longest rules first, and the time limit of a rule that comes close to it two weeks in a row goes up from 10 to 30 minutes, never more. The hourly pass also reuses, every other time at most, the recent result of a few slow checks (updates, sensitive files), with its age; a check you start checks everything afresh, and a duration that is too often wrong gets shorter. The rules and how they judge never change. Each change is noted with its previous value and can be undone here. Nothing is sent."
    )
}

/// L'écran de Paramètres : l'état, les changements, et de quoi les défaire.
pub(crate) fn menu() {
    let changements = afficher();
    let reponse = demander(tr!(
        "\n  Numéro : annuler celui-ci ; « oui » ou « non » : mettre en marche ou couper ; « t » : tout remettre comme à l'origine ; Entrée pour revenir : ",
        "\n  Number: undo this one; “yes” or “no”: turn on or off; “a”: put everything back to the original; Enter to go back: "
    ));
    let reponse = reponse.trim();
    if reponse.is_empty() {
        return;
    }
    if crate::langue::tout(reponse) {
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
            Changement::Montee(m) => dire_annule(&m.regle, true, false, None),
            Changement::Raccourcie(r) => dire_annule(&r.regle, false, true, Some(r.avant_min)),
        };
        if !fait {
            trp!("  Rien n'a changé.", "  Nothing changed.");
        }
    } else {
        trp!("  Rien n'a changé.", "  Nothing changed.");
    }
}

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
        assert!(ajuster_etat(&mut e, j("2026-11-01"), &frole(&tous), du_code));
        assert_eq!(e.montees.len(), 0);
        assert_eq!(
            e.frolent_depuis.keys().map(String::as_str).collect::<Vec<_>>(),
            ["LNX-TST-010", "LNX-TST-011"]
        );
        // LNX-TST-011 cesse de frôler : oubliée.
        assert!(ajuster_etat(&mut e, j("2026-11-05"), &frole(&["LNX-TST-010"]), du_code));
        assert!(!e.frolent_depuis.contains_key("LNX-TST-011"));
        assert!(!ajuster_etat(
            &mut e,
            j("2026-11-07"),
            &frole(&["LNX-TST-010"]),
            du_code
        ));
        assert!(ajuster_etat(&mut e, j("2026-11-08"), &frole(&tous), du_code));
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
        assert!(!ajuster_etat(&mut e, j("2026-11-14"), &deux, du_code));
        assert_eq!(e.montees.len(), 1);
        assert!(ajuster_etat(&mut e, j("2026-11-15"), &deux, du_code));
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
        ajuster_etat(&mut apres, j("2026-11-30"), &frole(&["LNX-TST-010"]), du_code);
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

    fn comparaisons(paires: &[(i64, bool)]) -> BTreeMap<String, super::super::mesures::Cache> {
        BTreeMap::from([(
            "LNX-MAJ-001".to_string(),
            super::super::mesures::Cache {
                recentes: paires.to_vec(),
                ..Default::default()
            },
        )])
    }

    /// Un écart sur trois vérifications à neuf (quatre au moins) : la durée de la cache descend d'un pas de 15 minutes,
    /// jamais sous son plancher ; les comparaisons déjà jugées ne comptent plus ; chaque pas part du précédent, et une
    /// chaîne rompue s'arrête au dernier pas valable.
    #[test]
    fn la_duree_de_la_cache_raccourcit_dans_ses_bornes() {
        let t = super::super::cache::en_cache("LNX-MAJ-001").unwrap();
        let mut e = Etat::default();
        // Trois comparaisons, ou un écart sur quatre : rien.
        assert!(!raccourcir_etat(
            &mut e,
            j("2026-11-02"),
            &comparaisons(&[(1, true), (2, true), (3, true)])
        ));
        assert!(!raccourcir_etat(
            &mut e,
            j("2026-11-02"),
            &comparaisons(&[(1, true), (2, false), (3, false), (4, false)])
        ));
        let mut paires = vec![(1, true), (2, false), (3, true), (4, false)];
        assert!(raccourcir_etat(&mut e, j("2026-11-02"), &comparaisons(&paires)));
        assert_eq!(
            e.raccourcies,
            vec![Raccourcie {
                quand: "2026-11-02".into(),
                regle: "LNX-MAJ-001".into(),
                avant_min: t.duree_min,
                apres_min: t.duree_min - 15,
                comparees: 4,
                ecarts: 2,
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

    /// Chaque règle du registre, sur chaque système, a un identifiant que l'auto-réglage garde.
    #[test]
    fn chaque_regle_a_un_identifiant_garde() {
        use crate::machine::regles::{Os, regles};
        for os in [Os::Linux, Os::Windows, Os::MacOs, Os::Tous] {
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
        ) {
            use crate::machine::regles::{Os, regles};
            let montees: Vec<serde_json::Value> = ids
                .iter()
                .map(|r| serde_json::json!({"quand": "2026-11-01", "regle": r, "avant_s": 600, "apres_s": secs % 3 * 1200 + 600, "mesure_ms": 1}))
                .collect();
            let json = serde_json::to_vec(&serde_json::json!({"v": 1, "coupe": coupe, "montees": montees})).unwrap();
            let toutes: Vec<_> = [Os::Linux, Os::Windows, Os::MacOs, Os::Tous].into_iter().flat_map(regles).collect();
            for contenu in [octets, json] {
                let e = lire_de(&contenu);
                prop_assert!(e.montees.len() <= MONTEES_MAX);
                prop_assert!(e.frolent_depuis.len() <= SUIVIES_MAX && e.refusees.len() <= SUIVIES_MAX);
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
