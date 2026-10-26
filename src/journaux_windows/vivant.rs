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
    /// `BornesVivant::evenements` atteinte (ou nulle) : les plus anciens ne sont pas lus.
    pub borne_atteinte: bool,
    /// Le délai est tombé : les plus anciens ne sont pas lus.
    pub delai: bool,
    /// Le journal a refusé en cours de route, et pourquoi : les plus anciens ne sont pas lus.
    pub interrompu: Option<RefusVivant>,
    /// Les suites des EventRecordID lus, quand la requête les a tous pris (pas de numéro d'événement dans la
    /// requête ; vide sinon, un trou n'y voudrait rien dire) : celle du journal ; pour un journal de collecte
    /// (ForwardedEvents, ou des numéros d'ordinateurs qui se chevauchent : ils gardent leurs numéros d'origine), une
    /// par ordinateur et par journal d'origine, en `Numerotation::Origine`.
    pub suites: Vec<Suite>,
    /// Événements dont l'ordinateur et le journal d'origine n'ont pas eu leur suite (au-delà de `MAX_ORDINATEURS`).
    pub hors_suites: u64,
    /// Trous qui n'ont pas pu être revérifiés (borne des revérifications, délai, lecture coupée) : rendus
    /// `Illisible`, faute de savoir si leurs numéros sont hors de la fenêtre de dates.
    pub trous_non_confirmes: u64,
}

impl BilanVivant {
    // Pour les tests.
    /// Tout ce que la requête demandait a été lu et jugé.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn complet(&self) -> bool {
        !self.borne_atteinte
            && !self.delai
            && self.interrompu.is_none()
            && self.illisibles == 0
            && self.chaines_tronquees == 0
            && self.sans_date == 0
            && self.sans_identifiant == 0
            && self.hors_suites == 0
            && self.trous_non_confirmes == 0
    }
}

/// Les ordinateurs (et journaux d'origine) suivis au plus dans un journal de collecte.
const MAX_ORDINATEURS: usize = 64;

/// Une date dans la forme que comparent les requêtes du journal (celle que pose l'Observateur d'événements pour
/// une plage personnalisée) : « 2026-10-17T04:00:00.000Z ». `haut` : arrondie à la milliseconde au-dessus (la fin
/// d'une fenêtre ne doit écarter aucun événement qu'elle contient).
fn date_xpath(d: DateTime<Utc>, haut: bool) -> String {
    let d = if haut && !d.timestamp_subsec_nanos().is_multiple_of(1_000_000) {
        DateTime::from_timestamp_millis(d.timestamp_millis().saturating_add(1)).unwrap_or(d)
    } else {
        d
    };
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
        dates.push(format!("@SystemTime>='{}'", date_xpath(d, false)));
    }
    if let Some(j) = filtre.jusqua {
        dates.push(format!("@SystemTime<='{}'", date_xpath(j, true)));
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
    /// Événements dont l'EventRecordID n'a pas pu être lu : chacun peut être un numéro manquant.
    sans_numero: u64,
    hors_suites: u64,
}

/// Les numéros lus, par ordinateur et par journal d'origine (System/Computer, System/Channel, coupés à
/// `trous::CLE_MAX` caractères) : un journal de collecte mêle les suites de plusieurs.
#[derive(Default)]
struct Numeros {
    cles: Vec<(String, String)>,
    presents: Vec<(usize, Present)>,
    /// Numéros d'événements au XML illisible, pris sans leur ordinateur.
    orphelins: Vec<Present>,
}

impl Numeros {
    /// Note un numéro ; faux si sa clé n'a pas pu avoir sa suite (au-delà de `MAX_ORDINATEURS`).
    fn noter(&mut self, ordinateur: &str, canal: &str, present: Present) -> bool {
        let cle = (
            ordinateur.chars().take(trous::CLE_MAX).collect::<String>(),
            canal.chars().take(trous::CLE_MAX).collect::<String>(),
        );
        let i = match self.cles.iter().position(|c| *c == cle) {
            Some(i) => i,
            None if self.cles.len() < MAX_ORDINATEURS => {
                self.cles.push(cle);
                self.cles.len() - 1
            }
            None => return false,
        };
        self.presents.push((i, present));
        true
    }

    /// Le plus petit et le plus grand numéro de chaque clé.
    fn plages(&self) -> Vec<(u64, u64)> {
        let mut plages: Vec<Option<(u64, u64)>> = vec![None; self.cles.len()];
        for (i, p) in &self.presents {
            plages[*i] = Some(match plages[*i] {
                Some((a, b)) => (a.min(p.numero), b.max(p.numero)),
                None => (p.numero, p.numero),
            });
        }
        plages.into_iter().flatten().collect()
    }
}

/// Le journal est-il un journal de collecte (des événements d'autres ordinateurs, avec leurs numéros d'origine) ?
/// ForwardedEvents, ou des numéros de plusieurs ordinateurs ou journaux d'origine qui se chevauchent. Un nom
/// d'ordinateur qui change dans un journal local (poste renommé, joint à un domaine, « PC » puis « PC.maison.lan »)
/// ne suffit pas : ses numéros se suivent d'un nom à l'autre, une seule suite. Ni le nom de cet ordinateur, que
/// n'importe quel compte change dans son environnement.
fn collecte(journal: &str, mut plages: Vec<(u64, u64)>) -> bool {
    plages.sort_unstable();
    journal.eq_ignore_ascii_case("ForwardedEvents") || plages.windows(2).any(|p| p[1].0 <= p[0].1)
}

/// L'événement d'un XML rendu, et son numéro même quand le XML ne se lit pas (`numero_de_secours`).
enum Rendu {
    Lu(Box<super::evtx::Enregistrement>, u64),
    Illisible(Option<u64>),
}

fn rendu(xml: Option<&str>, bornes: &Bornes) -> Rendu {
    let Some(x) = xml else {
        // Windows n'a pas pu le rendre : ni l'événement ni son numéro.
        return Rendu::Illisible(None);
    };
    match xml::enregistrement(x, bornes) {
        Ok((e, tronquees)) => Rendu::Lu(Box::new(e), tronquees),
        // Illisible ou démesuré : son numéro est quand même pris dans System, pour que la suite ne s'y troue pas.
        Err(_) => Rendu::Illisible(xml::numero_de_secours(x)),
    }
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
    let mut numeros = Numeros::default();
    let max = bornes.evenements;
    let lecture = lire_rendus(journal, &requete, fin, max == 0, |xml| {
        compte.vus += 1;
        let e = match rendu(xml, &bornes.xml) {
            Rendu::Lu(e, tronquees) => {
                compte.chaines_tronquees += tronquees;
                *e
            }
            Rendu::Illisible(numero) => {
                compte.illisibles += 1;
                match numero {
                    Some(numero) => numeros.orphelins.push(Present {
                        numero,
                        date: None,
                        morceau: None,
                        verifie: true,
                    }),
                    None => compte.sans_numero += 1,
                }
                return compte.vus < max as u64;
            }
        };
        match e.numero_systeme {
            Some(numero) => {
                let present = Present {
                    numero,
                    date: e.cree,
                    morceau: None,
                    verifie: true,
                };
                if !numeros.noter(&e.ordinateur, &e.canal, present) {
                    compte.hors_suites += 1;
                }
            }
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
        borne_atteinte: max == 0 || (compte.vus >= max as u64 && lecture == FinLecture::Complete),
        delai,
        interrompu,
        suites: Vec::new(),
        hors_suites: compte.hors_suites,
        trous_non_confirmes: 0,
    };
    if !ids_dans_la_requete {
        if collecte(journal, numeros.plages()) {
            // Un numéro sans son ordinateur ne se range dans aucune suite d'origine.
            bilan.hors_suites += numeros.orphelins.len() as u64;
            bilan.suites = suites_de_collecte(numeros, bornes.trous);
        } else {
            let mut presents: Vec<Present> = numeros.presents.into_iter().map(|(_, p)| p).collect();
            presents.append(&mut numeros.orphelins);
            let fenetre = filtre.depuis.is_some() || filtre.jusqua.is_some();
            let pertes = vec![1u64; usize::try_from(compte.sans_numero).unwrap_or(usize::MAX)];
            let (suite, non_confirmes) = juger_suite(journal, presents, &pertes, fenetre, bornes, fin);
            bilan.suites = vec![suite];
            bilan.trous_non_confirmes = non_confirmes;
        }
    }
    Ok(bilan)
}

/// Les suites d'un journal de collecte : une par ordinateur et par journal d'origine, en numéros d'origine, que le
/// filtre de l'abonnement peut trouer (`AvantExport`).
fn suites_de_collecte(numeros: Numeros, max_trous: usize) -> Vec<Suite> {
    let mut par_cle: Vec<Vec<Present>> = vec![Vec::new(); numeros.cles.len()];
    for (i, p) in numeros.presents {
        par_cle[i].push(p);
    }
    let mut restant = max_trous;
    numeros
        .cles
        .into_iter()
        .zip(par_cle)
        .map(|((ordinateur, journal), presents)| {
            let s = trous::juger(
                Numerotation::Origine { ordinateur, journal },
                presents,
                &Contexte::nu(Nature::AvantExport),
                restant,
            );
            restant = restant.saturating_sub(s.trous.len());
            s
        })
        .collect()
}

/// La suite des EventRecordID lus et ses trous (`pertes` : un numéro par événement lu sans le sien) ; avec une
/// fenêtre de dates, chaque trou revérifié par une requête sur ses seuls numéros (sans fenêtre), au plus
/// `BornesVivant::confirmations`. Un trou qui n'a pas pu l'être est rendu `Illisible`. Avec leur nombre.
fn juger_suite(
    journal: &str,
    mut presents: Vec<Present>,
    pertes: &[u64],
    fenetre: bool,
    bornes: &BornesVivant,
    fin: Instant,
) -> (Suite, u64) {
    let contexte = Contexte {
        pertes,
        ..Contexte::nu(Nature::Absents)
    };
    let suite = trous::juger(Numerotation::Journal, presents.clone(), &contexte, bornes.trous);
    if !fenetre || (suite.trous.is_empty() && suite.trous_au_dela == 0) {
        return (suite, 0);
    }
    // Les plages qui n'ont pas pu être revérifiées.
    let mut plages_douteuses: Vec<(u64, u64)> = Vec::new();
    for (i, t) in suite.trous.iter().enumerate() {
        if t.nature != Nature::Absents {
            continue;
        }
        if i >= bornes.confirmations {
            plages_douteuses.push((t.de, t.a));
            continue;
        }
        let requete = format!("*[System[EventRecordID>={} and EventRecordID<={}]]", t.de, t.a);
        let mut vus = 0usize;
        let mut sans_numero = false;
        let lecture = lire_rendus(journal, &requete, fin, false, |xml| {
            vus += 1;
            let numero = match rendu(xml, &bornes.xml) {
                Rendu::Lu(e, _) => e.numero_systeme.map(|n| (n, e.cree)),
                Rendu::Illisible(n) => n.map(|n| (n, None)),
            };
            match numero {
                Some((numero, date)) => presents.push(Present {
                    numero,
                    date,
                    morceau: None,
                    verifie: true,
                }),
                None => sans_numero = true,
            }
            vus < bornes.par_confirmation
        });
        // Une revérification bornée, coupée, refusée, ou qui a lu un événement sans son numéro laisse le trou
        // sans certitude.
        if lecture != FinLecture::Complete || vus >= bornes.par_confirmation || sans_numero {
            plages_douteuses.push((t.de, t.a));
        }
    }
    let mut suite = trous::juger(Numerotation::Journal, presents, &contexte, bornes.trous);
    // Les trous au-delà de la borne n'ont pas été revérifiés non plus.
    let mut non_confirmes = suite.trous_au_dela;
    for t in &mut suite.trous {
        if t.nature == Nature::Absents && plages_douteuses.iter().any(|&(de, a)| t.de <= a && de <= t.a) {
            t.nature = Nature::Illisible;
            non_confirmes += 1;
        }
    }
    // Deux trous voisins devenus de même nature n'en font qu'un.
    let mut fusionnes: Vec<trous::Trou> = Vec::new();
    for t in suite.trous {
        match fusionnes.last_mut() {
            Some(d) if d.nature == t.nature && d.a.checked_add(1) == Some(t.de) => {
                d.a = t.a;
                d.apres = t.apres;
            }
            _ => fusionnes.push(t),
        }
    }
    suite.trous = fusionnes;
    (suite, non_confirmes)
}

#[cfg(test)]
mod tests;
