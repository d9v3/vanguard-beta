//! Les trous dans la suite des numéros d'enregistrement (EventRecordID) d'un journal : des enregistrements retirés
//! un à un (effacement partiel, T1070.001), que l'effacement entier (1102, 104) ne dit pas.
//!
//! Ce que dit Microsoft du numéro : le premier enregistrement d'un journal porte le numéro 1, les suivants se
//! suivent ; un journal qui écrase ses plus anciens n'a plus le numéro 1, le plus ancien est ailleurs (« Event Log
//! Records », <https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-records>). Après un effacement,
//! la suite continue : le 1102 qui ouvre le journal vidé porte un grand numéro (exemple de la page de l'événement
//! 1102, EventRecordID 1087729 ;
//! <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102>),
//! vu aussi dans un échantillon public (security_big_sample.evtx de la crate evtx : un 1102 au numéro 227126, en
//! tête d'un fichier dont les morceaux recomptent depuis 1). Ni l'effacement ni la rotation ne font donc de trou :
//! ils font commencer la suite plus loin. Ce qui précède le plus petit numéro n'est jamais un trou.
//!
//! Ce qui fait un trou sans effacement, et que ce module dit autrement :
//! - un morceau écarté par le lecteur (CRC faux), des enregistrements illisibles ou laissés au-delà des bornes :
//!   la lecture, pas le journal (`Nature::Illisible`) ;
//! - un fichier « sale », copié pendant que Windows l'écrivait : les morceaux qu'il gardait en mémoire ne sont pas
//!   encore sur le disque, ou y portent d'anciens enregistrements. Vu dans les échantillons publics copiés depuis
//!   un cliché de volume (2-vss_0-…RemoteConnectionManager…evtx : des morceaux d'août 3 à 7 mêlés, des centaines de
//!   milliers de numéros entre eux ; 2-vss_7-System.evtx : deux morceaux à zéro au milieu) ; (`Nature::CopieAChaud`) ;
//! - un fichier exporté (wevtutil epl avec une requête, « Enregistrer les événements sélectionnés ») ou une archive
//!   d'événements transférés : les enregistrements y sont renumérotés depuis 1, les EventRecordID d'origine gardés ;
//!   un trou dans ceux-ci peut venir du filtre de l'export (`Nature::AvantExport`).
//!
//! Ce qui reste un constat : un trou dans la plage qu'annonce l'en-tête d'un morceau lu en entier (`Retires` :
//! Windows n'y laisse jamais de trou, le morceau a été réécrit et ses CRC recalculés), ou entre deux morceaux d'un
//! fichier fermé proprement, ou dans ce que rend le service des journaux (`Absents`). Jugé par E3, jamais ici.
//!
//! Module autonome (aucun `crate::`) : pur, sans entrée ni sortie, essayé par proptest contre un modèle naïf.

use chrono::{DateTime, Utc};

use super::evtx::RecapMorceau;

/// Ce qu'un trou veut dire, d'après l'endroit où il tombe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Nature {
    /// Dans la plage qu'annonce l'en-tête d'un morceau lu en entier (deux CRC justes, tous ses enregistrements
    /// rendus) : le morceau dit que ces enregistrements y étaient, ils n'y sont plus.
    Retires,
    /// Entre deux morceaux d'un fichier fermé proprement (ni sale ni abîmé) dont la lecture n'a rien perdu, ou dans
    /// ce que rend le service des journaux de l'ordinateur : des enregistrements manquent. Retirés (morceaux remis à
    /// zéro ou ôtés, fichier remplacé), ou fichier copié incomplet.
    Absents,
    /// Entre deux morceaux d'un fichier « sale » ou à l'en-tête abîmé : copié pendant que Windows l'écrivait, ou
    /// pas fermé proprement. Pas une preuve d'effacement.
    CopieAChaud,
    /// Là où la lecture a perdu quelque chose (morceau écarté, enregistrement illisible ou au-delà des bornes), ou
    /// dans un fichier où elle a perdu des morceaux sans savoir quels numéros ils portaient : non vérifié.
    Illisible,
    /// Entre deux EventRecordID d'origine d'un fichier exporté ou d'une archive d'événements transférés : effacés
    /// du journal d'origine avant l'export, ou laissés de côté par le filtre de l'export ou de l'abonnement.
    AvantExport,
}

/// Quels numéros forment la suite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Numerotation {
    /// Ceux du journal lu : les en-têtes des enregistrements d'un fichier, ou les EventRecordID que rend le service
    /// des journaux.
    Journal,
    /// Les EventRecordID d'origine d'un fichier exporté, pour un ordinateur et un journal (System/Computer,
    /// System/Channel) : une archive d'événements transférés en mêle plusieurs, chacun avec sa propre suite.
    Origine { ordinateur: String, journal: String },
}

/// Des numéros qui manquent, de `de` à `a` compris.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Trou {
    pub de: u64,
    pub a: u64,
    pub nature: Nature,
    /// La date de l'enregistrement présent juste avant (le plus grand numéro sous `de`), s'il y en a un et qu'elle
    /// est lisible.
    pub avant: Option<DateTime<Utc>>,
    /// La date de l'enregistrement présent juste après (le plus petit numéro au-dessus de `a`).
    pub apres: Option<DateTime<Utc>>,
}

impl Trou {
    /// Le nombre de numéros qui manquent.
    pub(crate) fn nombre(&self) -> u64 {
        (self.a - self.de).saturating_add(1)
    }
}

/// La suite des numéros d'un journal et ses trous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Suite {
    pub numerotation: Numerotation,
    /// Le plus petit et le plus grand numéro présents ou annoncés par un morceau lu ; rien pour une suite vide.
    pub premier: Option<u64>,
    pub dernier: Option<u64>,
    /// Numéros distincts présents.
    pub presents: u64,
    /// Numéros vus plus d'une fois (au-delà de la première) : jamais écrits ainsi par Windows dans un même journal.
    pub doublons: u64,
    /// Les trous, dans l'ordre des numéros, au plus `max_trous`.
    pub trous: Vec<Trou>,
    /// Trous au-delà de `max_trous`, comptés sans être gardés.
    pub trous_au_dela: u64,
}

/// Un numéro présent et sa date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Present {
    pub numero: u64,
    pub date: Option<DateTime<Utc>>,
}

/// Ce que l'on sait du journal autour de ses numéros.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Contexte<'a> {
    /// Les morceaux lus ou écartés (vide pour la source vivante et pour les EventRecordID d'origine).
    pub morceaux: &'a [RecapMorceau],
    /// La nature d'un trou qu'aucun morceau ne réclame : `Absents` pour un fichier propre ou l'ordinateur vivant,
    /// `CopieAChaud` pour un fichier sale, `Illisible` quand la lecture a perdu des morceaux sans place connue,
    /// `AvantExport` pour les EventRecordID d'origine.
    pub entre_morceaux: Nature,
}

/// Ce qui couvre un numéro : combien de morceaux lus en entier l'annoncent, combien de morceaux où la lecture a
/// perdu quelque chose.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Couverture {
    reclame: u32,
    perdu: u32,
}

/// La couverture des numéros, par paliers : chaque palier vaut de son début jusqu'au début du suivant ; avant le
/// premier, rien ne couvre.
fn paliers(morceaux: &[RecapMorceau]) -> Vec<(u64, Couverture)> {
    // (numéro, réclamé +1/-1, perdu +1/-1)
    let mut bords: Vec<(u64, i64, i64)> = Vec::new();
    for m in morceaux {
        let Some((p, d)) = m.annonce else { continue };
        let (r, l) = if m.lu && m.non_rendus == 0 { (1, 0) } else { (0, 1) };
        bords.push((p, r, l));
        // Une annonce qui finit au dernier numéro possible n'a pas de fin à poser.
        if let Some(fin) = d.checked_add(1) {
            bords.push((fin, -r, -l));
        }
    }
    bords.sort_unstable_by_key(|b| b.0);
    let mut sortie: Vec<(u64, Couverture)> = Vec::new();
    let (mut r, mut l) = (0i64, 0i64);
    let mut i = 0;
    while i < bords.len() {
        let pos = bords[i].0;
        while i < bords.len() && bords[i].0 == pos {
            r += bords[i].1;
            l += bords[i].2;
            i += 1;
        }
        let c = Couverture {
            reclame: u32::try_from(r.max(0)).unwrap_or(u32::MAX),
            perdu: u32::try_from(l.max(0)).unwrap_or(u32::MAX),
        };
        sortie.push((pos, c));
    }
    sortie
}

fn nature(c: Couverture, entre: Nature) -> Nature {
    if c.perdu > 0 {
        Nature::Illisible
    } else if c.reclame > 0 {
        Nature::Retires
    } else {
        entre
    }
}

/// La suite des numéros `presents` (dans n'importe quel ordre, doublons compris) et ses trous, d'après le
/// `contexte`. Les numéros manquants sont ceux qui tombent entre le plus petit et le plus grand numéro présents ou
/// annoncés par un morceau lu : ce qui précède le plus petit (journal tournant, effacé) n'en est pas un, ce qui suit
/// le plus grand non plus, sauf si un morceau lu l'annonce (des derniers enregistrements ôtés, la place libre
/// reculée).
pub(crate) fn juger(
    numerotation: Numerotation,
    mut presents: Vec<Present>,
    contexte: &Contexte,
    max_trous: usize,
) -> Suite {
    presents.sort_unstable_by_key(|p| p.numero);
    let avant_dedoublonnage = presents.len();
    presents.dedup_by_key(|p| p.numero);
    let doublons = (avant_dedoublonnage - presents.len()) as u64;
    let annonces_lues = contexte.morceaux.iter().filter(|m| m.lu).filter_map(|m| m.annonce);
    let premier = presents
        .first()
        .map(|p| p.numero)
        .into_iter()
        .chain(annonces_lues.clone().map(|a| a.0))
        .min();
    let dernier = presents
        .last()
        .map(|p| p.numero)
        .into_iter()
        .chain(annonces_lues.map(|a| a.1))
        .max();
    let mut suite = Suite {
        numerotation,
        premier,
        dernier,
        presents: presents.len() as u64,
        doublons,
        trous: Vec::new(),
        trous_au_dela: 0,
    };
    let (Some(lo), Some(hi)) = (premier, dernier) else {
        return suite;
    };
    let paliers = paliers(contexte.morceaux);
    // Le palier en cours : les trous viennent dans l'ordre, l'indice ne recule jamais.
    let mut k = 0usize;
    let ranger = |de: u64, a: u64, suite: &mut Suite, k: &mut usize| {
        let mut x = de;
        loop {
            while *k < paliers.len() && paliers[*k].0 <= x {
                *k += 1;
            }
            let couverture = if *k == 0 {
                Couverture::default()
            } else {
                paliers[*k - 1].1
            };
            let n = nature(couverture, contexte.entre_morceaux);
            // Jusqu'au palier suivant, ou la fin du trou.
            let mut fin = match paliers.get(*k) {
                Some(&(debut, _)) if debut <= a => debut - 1,
                _ => a,
            };
            // Les paliers suivants de même nature prolongent le même trou.
            while fin < a {
                let suivant = fin + 1;
                while *k < paliers.len() && paliers[*k].0 <= suivant {
                    *k += 1;
                }
                let c = if *k == 0 {
                    Couverture::default()
                } else {
                    paliers[*k - 1].1
                };
                if nature(c, contexte.entre_morceaux) != n {
                    break;
                }
                fin = match paliers.get(*k) {
                    Some(&(debut, _)) if debut <= a => debut - 1,
                    _ => a,
                };
            }
            if suite.trous.len() < max_trous {
                suite.trous.push(Trou {
                    de: x,
                    a: fin,
                    nature: n,
                    avant: None,
                    apres: None,
                });
            } else {
                suite.trous_au_dela += 1;
            }
            if fin >= a {
                break;
            }
            x = fin + 1;
        }
    };
    // Le prochain numéro attendu ; rien quand le dernier possible est passé.
    let mut attendu = Some(lo);
    for p in &presents {
        if let Some(x) = attendu
            && p.numero > x
        {
            ranger(x, p.numero - 1, &mut suite, &mut k);
        }
        attendu = p.numero.checked_add(1);
    }
    if let Some(x) = attendu
        && x <= hi
    {
        ranger(x, hi, &mut suite, &mut k);
    }
    // Les dates autour de chaque trou : celles des présents voisins.
    for t in &mut suite.trous {
        let i = presents.partition_point(|p| p.numero < t.de);
        t.avant = i.checked_sub(1).and_then(|j| presents.get(j)).and_then(|p| p.date);
        t.apres = presents.get(i).and_then(|p| p.date);
    }
    suite
}

#[cfg(test)]
mod tests;
