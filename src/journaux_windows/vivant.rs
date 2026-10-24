//! La source « vivante » des événements de Windows : les journaux de cet ordinateur, lus par le service des journaux
//! (EvtQuery, EvtNext, EvtRender de `machine::windows::evenements`, sans PowerShell), chaque événement rendu en XML
//! puis changé en la forme commune par la même extraction que celle des fichiers.
//!
//! Ce qui ne se lit pas est rendu distinctement, pour qu'une règle dise « non vérifié » avec sa raison : journal
//! réservé aux administrateurs (Security), absent de cet ordinateur, ou illisible pour une autre raison ; un journal
//! désactivé (il n'écrit plus rien) est dit à part, sa lecture pouvant réussir sur ses anciens événements.

use std::time::Instant;

use chrono::{DateTime, Utc};

use super::evenement::{Ecart, EvenementWindows, Filtre, Origine};
use super::evtx::Bornes;
use super::trous::{self, Contexte, Nature, Numerotation, Present, Suite};
use super::xml;
use crate::machine::windows::evenements::{FinLecture, lire_rendus};

/// Les numéros d'événements mis au plus dans la requête XPath : Windows en refuse une de plus de vingt expressions
/// (« Consuming Events », <https://learn.microsoft.com/en-us/windows/win32/wes/consuming-events>), et la fenêtre de
/// dates en prend deux. Au-delà, le tri se fait ici.
const IDS_DANS_LA_REQUETE: usize = 16;

/// Les bornes d'une lecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BornesVivant {
    /// Événements lus au plus (les plus récents d'abord) : au-delà, les plus anciens ne le sont pas, et c'est dit.
    pub evenements: usize,
    /// Les bornes du XML de chaque événement, celles du lecteur .evtx.
    pub xml: Bornes,
    /// Trous gardés au plus.
    pub trous: usize,
    /// Trous revérifiés au plus par une requête sur leurs numéros (voir `lire_journal`).
    pub confirmations: usize,
    /// Événements lus au plus par revérification.
    pub par_confirmation: usize,
}

impl Default for BornesVivant {
    fn default() -> Self {
        Self {
            evenements: 200_000,
            xml: Bornes::default(),
            trous: 1000,
            confirmations: 32,
            par_confirmation: 4096,
        }
    }
}

/// Pourquoi un journal ne se lit pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusVivant {
    /// Accès refusé (ERROR_ACCESS_DENIED) : le journal de sécurité, sans droits d'administrateur, ou des droits
    /// changés sur le journal.
    Droits,
    /// Le journal n'existe pas sur cet ordinateur (ERROR_EVT_CHANNEL_NOT_FOUND, ERROR_FILE_NOT_FOUND) : Defender
    /// retiré, rôle ou programme absent.
    Absent,
    /// Une autre raison, avec le code d'erreur de Windows s'il y en a un (requête refusée, service arrêté…).
    Illisible(Option<i32>),
}

/// Ce qu'une lecture a donné.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BilanVivant {
    pub journal: String,
    /// Le journal est-il activé (Enabled de HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<journal>,
    /// ce que règle `wevtutil sl /e`) ; rien si le registre ne le dit pas. Désactivé, il n'écrit plus rien : ce qui
    /// est lu est ancien.
    pub active: Option<bool>,
    /// Événements donnés à l'appelant.
    pub donnes: u64,
    /// Événements écartés par le filtre.
    pub filtres: u64,
    /// Événements sans date lisible quand le filtre a une fenêtre de dates.
    pub sans_date: u64,
    /// Événements sans numéro d'événement lisible.
    pub sans_identifiant: u64,
    /// Événements que Windows n'a pas pu rendre, ou au XML illisible ou démesuré.
    pub illisibles: u64,
    /// Textes coupés à `Bornes::texte` caractères.
    pub chaines_tronquees: u64,
    /// `BornesVivant::evenements` atteinte : les plus anciens ne sont pas lus.
    pub borne_atteinte: bool,
    /// Le délai est tombé : les plus anciens ne sont pas lus.
    pub delai: bool,
    /// Le journal a refusé en cours de route, et pourquoi : les plus anciens ne sont pas lus.
    pub interrompu: Option<RefusVivant>,
    /// La suite des EventRecordID lus, quand la requête les a tous pris (pas de numéro d'événement dans la
    /// requête) : rien sinon, un trou n'y voudrait rien dire.
    pub suite: Option<Suite>,
    /// Trous qui n'ont pas pu être revérifiés (borne des revérifications, délai) : ils restent, sans certitude
    /// que leurs numéros ne soient pas hors de la fenêtre de dates.
    pub trous_non_confirmes: u64,
}

impl BilanVivant {
    /// Tout ce que la requête demandait a été lu et jugé.
    pub(crate) fn complet(&self) -> bool {
        !self.borne_atteinte
            && !self.delai
            && self.interrompu.is_none()
            && self.illisibles == 0
            && self.chaines_tronquees == 0
            && self.sans_date == 0
            && self.sans_identifiant == 0
            && self.trous_non_confirmes == 0
    }
}

/// Une date dans la forme que comparent les requêtes du journal (celle que pose l'Observateur d'événements pour
/// une plage personnalisée) : « 2026-10-17T04:00:00.000Z ».
fn date_xpath(d: DateTime<Utc>) -> String {
    d.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// La requête XPath du filtre : les numéros d'événements (s'il y en a au plus `IDS_DANS_LA_REQUETE`) et la fenêtre
/// de dates. Ne contient que des nombres et des dates mis en forme ici : rien d'autre ne peut sortir de la chaîne.
/// Avec, vrai si les numéros d'événements y sont (la suite des EventRecordID n'est alors pas jugée).
pub(crate) fn requete(filtre: &Filtre) -> (String, bool) {
    let mut conditions = Vec::new();
    let ids = !filtre.ids.is_empty() && filtre.ids.len() <= IDS_DANS_LA_REQUETE;
    if ids {
        let liste: Vec<String> = filtre.ids.iter().map(|i| format!("EventID={i}")).collect();
        conditions.push(format!("({})", liste.join(" or ")));
    }
    let mut dates = Vec::new();
    if let Some(d) = filtre.depuis {
        dates.push(format!("@SystemTime>='{}'", date_xpath(d)));
    }
    if let Some(j) = filtre.jusqua {
        dates.push(format!("@SystemTime<='{}'", date_xpath(j)));
    }
    if !dates.is_empty() {
        conditions.push(format!("TimeCreated[{}]", dates.join(" and ")));
    }
    if conditions.is_empty() {
        ("*".to_string(), ids)
    } else {
        (format!("*[System[{}]]", conditions.join(" and ")), ids)
    }
}

/// Le refus d'après le code d'erreur de Windows.
pub(crate) fn refus(code: Option<i32>) -> RefusVivant {
    match code {
        Some(5) => RefusVivant::Droits,
        Some(2 | 15007) => RefusVivant::Absent,
        // 0 : refusé sans code (Wine, qui n'a pas de journaux).
        Some(0) | None => RefusVivant::Illisible(None),
        c => RefusVivant::Illisible(c),
    }
}

/// Le journal est-il activé ? D'après le registre ; rien s'il ne le dit pas, ou que le nom ne peut pas être une clé
/// (une barre oblique inverse y descendrait dans une autre).
fn active(journal: &str) -> Option<bool> {
    if journal.is_empty() || journal.contains(['\\', '\0']) {
        return None;
    }
    let cle = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\{journal}"
        ))
        .ok()?;
    let v: u32 = cle.get_value("Enabled").ok()?;
    Some(v != 0)
}

/// Ce que le XML d'un événement donne à la lecture.
#[derive(Default)]
struct Compte {
    donnes: u64,
    filtres: u64,
    sans_date: u64,
    sans_identifiant: u64,
    illisibles: u64,
    chaines_tronquees: u64,
    vus: u64,
    /// Événements dont l'EventRecordID n'a pas pu être lu : un trou peut être l'un d'eux.
    sans_numero: u64,
}

/// Lit le journal nommé `journal` de cet ordinateur (« Security », « Microsoft-Windows-PowerShell/Operational »…),
/// les plus récents d'abord, jusqu'à `fin`, et donne à `recevoir` chaque événement que `filtre` veut (les numéros
/// d'événements et la fenêtre de dates vont dans la requête, et sont revérifiés ici).
///
/// Sans numéro d'événement dans la requête, la suite des EventRecordID lus est jugée. Avec une fenêtre de dates,
/// un trou peut venir d'une horloge qui a reculé (des événements de ces numéros, datés hors de la fenêtre) : chaque
/// trou est revérifié par une requête sur ses seuls numéros, et ce qu'elle trouve le comble.
///
/// `Err` : le journal refuse avant le premier événement. Un refus plus tard, le délai ou la borne laissent ce qui a
/// été lu et le disent (`BilanVivant::complet`).
pub(crate) fn lire_journal(
    journal: &str,
    filtre: &Filtre,
    bornes: &BornesVivant,
    fin: Instant,
    mut recevoir: impl FnMut(EvenementWindows),
) -> Result<BilanVivant, RefusVivant> {
    let (requete, ids_dans_la_requete) = requete(filtre);
    let mut compte = Compte::default();
    let mut presents: Vec<Present> = Vec::new();
    let max = bornes.evenements;
    let lecture = lire_rendus(journal, &requete, fin, max == 0, |xml| {
        compte.vus += 1;
        let Some(x) = xml else {
            // Windows n'a pas pu le rendre : ni l'événement ni son numéro.
            compte.illisibles += 1;
            compte.sans_numero += 1;
            return compte.vus < max as u64;
        };
        let Ok((e, tronquees)) = xml::enregistrement(x, &bornes.xml) else {
            // Illisible ou démesuré : son numéro est quand même pris dans System, pour que la suite ne s'y troue
            // pas.
            compte.illisibles += 1;
            match xml::numero_de_secours(x) {
                Some(numero) => presents.push(Present { numero, date: None }),
                None => compte.sans_numero += 1,
            }
            return compte.vus < max as u64;
        };
        compte.chaines_tronquees += tronquees;
        match e.numero_systeme {
            Some(numero) => presents.push(Present { numero, date: e.cree }),
            None => compte.sans_numero += 1,
        }
        match EvenementWindows::depuis(e, Origine::Vivant) {
            None => compte.sans_identifiant += 1,
            Some(evenement) => match filtre.juger(&evenement) {
                Ok(()) => {
                    compte.donnes += 1;
                    recevoir(evenement);
                }
                Err(Ecart::Filtre) => compte.filtres += 1,
                Err(Ecart::SansDate) => compte.sans_date += 1,
            },
        }
        compte.vus < max as u64
    });
    let (delai, interrompu) = match lecture {
        FinLecture::Complete => (false, None),
        FinLecture::Delai => (true, None),
        FinLecture::Refus(code) if compte.vus == 0 => return Err(refus(code)),
        FinLecture::Refus(code) => (false, Some(refus(code))),
    };
    let mut bilan = BilanVivant {
        journal: journal.to_string(),
        active: active(journal),
        donnes: compte.donnes,
        filtres: compte.filtres,
        sans_date: compte.sans_date,
        sans_identifiant: compte.sans_identifiant,
        illisibles: compte.illisibles,
        chaines_tronquees: compte.chaines_tronquees,
        borne_atteinte: max > 0 && compte.vus >= max as u64 && lecture == FinLecture::Complete,
        delai,
        interrompu,
        suite: None,
        trous_non_confirmes: 0,
    };
    if !ids_dans_la_requete {
        let fenetre = filtre.depuis.is_some() || filtre.jusqua.is_some();
        // Un événement lu sans son numéro peut être n'importe quel trou : ils sont alors tous non vérifiés.
        let entre = if compte.sans_numero > 0 {
            Nature::Illisible
        } else {
            Nature::Absents
        };
        let (suite, non_confirmes) = juger_suite(journal, presents, entre, fenetre, bornes, fin);
        bilan.suite = Some(suite);
        bilan.trous_non_confirmes = non_confirmes;
    }
    Ok(bilan)
}

/// La suite des EventRecordID lus et ses trous ; avec une fenêtre de dates, chaque trou revérifié par une requête
/// sur ses seuls numéros (sans fenêtre), au plus `BornesVivant::confirmations`. Avec le nombre de trous qui n'ont pas
/// pu l'être.
fn juger_suite(
    journal: &str,
    mut presents: Vec<Present>,
    entre: Nature,
    fenetre: bool,
    bornes: &BornesVivant,
    fin: Instant,
) -> (Suite, u64) {
    let contexte = Contexte {
        morceaux: &[],
        entre_morceaux: entre,
    };
    let suite = trous::juger(Numerotation::Journal, presents.clone(), &contexte, bornes.trous);
    if !fenetre || suite.trous.is_empty() {
        return (suite, 0);
    }
    let mut non_confirmes = suite.trous_au_dela;
    for (i, t) in suite.trous.iter().enumerate() {
        if i >= bornes.confirmations {
            non_confirmes += 1;
            continue;
        }
        let requete = format!("*[System[EventRecordID>={} and EventRecordID<={}]]", t.de, t.a);
        let mut vus = 0usize;
        let lecture = lire_rendus(journal, &requete, fin, false, |xml| {
            vus += 1;
            if let Some(Ok((e, _))) = xml.map(|x| xml::enregistrement(x, &bornes.xml))
                && let Some(n) = e.numero_systeme
            {
                presents.push(Present {
                    numero: n,
                    date: e.cree,
                });
            }
            vus < bornes.par_confirmation
        });
        // Une revérification bornée, coupée ou refusée laisse le trou sans certitude.
        if lecture != FinLecture::Complete || vus >= bornes.par_confirmation {
            non_confirmes += 1;
        }
    }
    (
        trous::juger(Numerotation::Journal, presents, &contexte, bornes.trous),
        non_confirmes,
    )
}

#[cfg(test)]
mod tests;
