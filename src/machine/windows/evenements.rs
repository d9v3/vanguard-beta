//! Journaux d'événements de Windows : WIN-JRN-003, les 7 derniers jours jugés par le moteur des règles `EVT-`
//! (`journaux_windows::regles`, un seul juge), et ce que d'autres outils lisent eux-mêmes par les fonctions de Windows
//! (wevtapi) : les échecs et réussites de connexion de la chasse (mot de passe deviné), le 104 de la règle commune des
//! journaux, les événements du diagnostic et des traces.

use std::collections::HashMap;

use chrono::NaiveDateTime;

use super::*;
use crate::machine::regles::{Os, regle};

const JOURS: u32 = 7;
/// Les échecs lus au plus : assez pour voir une rafale, sans faire durer le bilan quand un robot en envoie des
/// milliers par jour.
const MAX_ECHECS: usize = 2000;

/// Une lecture d'un journal : sa section, le journal, les événements voulus, combien au plus.
struct Lecture {
    section: &'static str,
    journal: &'static str,
    evenements: &'static str,
    max: usize,
}

/// ECH (4625, échecs de connexion) : journal Security, lisible seulement en administrateur ; la chasse les lit (mot
/// de passe deviné).
const ECHECS: Lecture = Lecture {
    section: "ECH",
    journal: "Security",
    evenements: "EventID=4625",
    max: MAX_ECHECS,
};

/// Un événement lu dans son XML (celui que montre l'Observateur d'événements) : son numéro, sa date (UTC, ISO 8601) et
/// ses valeurs dans l'ordre (EventData/Data, ou les champs sous UserData pour le 1102) : les « Properties » que
/// Get-WinEvent donnait. `None` : XML illisible.
fn lire_xml(xml: &str) -> Option<(u32, String, Vec<String>)> {
    lire_xml_nomme(xml).map(|(id, date, valeurs, _)| (id, date, valeurs))
}

/// Comme `lire_xml`, avec le nom de chaque valeur (l'attribut Name d'un Data, ou le nom du champ sous UserData) :
/// des événements dont les champs changent de place d'un numéro à l'autre (Diagnostics-Performance).
fn lire_xml_nomme(xml: &str) -> Option<(u32, String, Vec<String>, Vec<String>)> {
    use quick_xml::events::Event;
    let mut lecteur = quick_xml::Reader::from_str(xml);
    let mut chemin: Vec<Vec<u8>> = Vec::new();
    let (mut id, mut date, mut valeurs, mut noms) = (String::new(), String::new(), Vec::new(), Vec::new());
    // La valeur en cours de lecture, et la profondeur de son élément.
    let mut valeur: Option<(usize, String)> = None;
    loop {
        let evenement = lecteur.read_event().ok()?;
        let (ouvert, vide) = match &evenement {
            Event::Start(e) => (Some(e), false),
            Event::Empty(e) => (Some(e), true),
            _ => (None, false),
        };
        if let Some(e) = ouvert {
            let nom = e.local_name().as_ref().as_bytes().to_vec();
            if nom == b"TimeCreated"
                && let Some(a) = e.try_get_attribute("SystemTime").ok().flatten()
            {
                date = a
                    .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    .ok()?
                    .into_owned();
            }
            let dans = |n: &[u8]| chemin.last().is_some_and(|p| p == n);
            // Une valeur : un Data sous EventData, ou un champ sous l'élément unique de UserData.
            let est_valeur =
                (dans(b"EventData") && nom == b"Data") || chemin.len() >= 2 && chemin[chemin.len() - 2] == b"UserData";
            if est_valeur && valeur.is_none() {
                let attribut = e.try_get_attribute("Name").ok().flatten();
                noms.push(match attribut {
                    Some(a) => a
                        .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        .ok()?
                        .into_owned(),
                    None => String::from_utf8_lossy(&nom).into_owned(),
                });
                if vide {
                    valeurs.push(String::new());
                } else {
                    valeur = Some((chemin.len(), String::new()));
                }
            }
            if !vide {
                chemin.push(nom);
            }
            continue;
        }
        match evenement {
            Event::Text(t) => {
                let texte = t.xml10_content();
                if let Some((_, v)) = &mut valeur {
                    v.push_str(&texte);
                } else if chemin.last().is_some_and(|n| n == b"EventID") {
                    id.push_str(&texte);
                }
            }
            Event::GeneralRef(r) => {
                let c = match r.as_ref() {
                    "amp" => Some('&'),
                    "lt" => Some('<'),
                    "gt" => Some('>'),
                    "quot" => Some('"'),
                    "apos" => Some('\''),
                    _ => r.resolve_char_ref().ok().flatten(),
                };
                if let (Some((_, v)), Some(c)) = (&mut valeur, c) {
                    v.push(c);
                }
            }
            Event::End(_) => {
                chemin.pop();
                if valeur
                    .as_ref()
                    .is_some_and(|(profondeur, _)| *profondeur == chemin.len())
                {
                    valeurs.extend(valeur.take().map(|(_, v)| v));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Some((id.trim().parse().ok()?, date, valeurs, noms))
}

/// Une valeur sur une ligne, sans le séparateur des champs.
fn champ(v: Option<&String>) -> String {
    let v = v.map_or("", String::as_str);
    v.split(['\r', '\n', '|'])
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// La ligne d'une section pour un événement, telle que les jugements la lisent. `date` : déjà à l'heure locale.
fn ligne(section: &str, id: u32, date: &str, p: &[String]) -> Option<String> {
    Some(match (section, id) {
        // Type de connexion, adresse d'origine, compte visé.
        ("ECH", 4625) => format!("{date}|{}|{}|{}", champ(p.get(10)), champ(p.get(19)), champ(p.get(5))),
        _ => return None,
    })
}

/// « 2026-10-20T13:46:40.1234567Z » → « 2026-10-20 09:46 » à l'heure de l'ordinateur, comme l'Observateur
/// d'événements la montre.
pub(crate) fn date_locale(systeme: &str) -> Option<String> {
    let utc = chrono::DateTime::parse_from_rfc3339(systeme).ok()?;
    Some(utc.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M").to_string())
}

#[link(name = "wevtapi")]
unsafe extern "system" {
    fn EvtQuery(session: *mut c_void, chemin: *const u16, requete: *const u16, drapeaux: u32) -> *mut c_void;
    fn EvtNext(
        resultats: *mut c_void,
        taille: u32,
        evenements: *mut *mut c_void,
        delai: u32,
        drapeaux: u32,
        rendus: *mut u32,
    ) -> i32;
    fn EvtRender(
        contexte: *mut c_void,
        fragment: *mut c_void,
        drapeaux: u32,
        taille: u32,
        tampon: *mut c_void,
        utilise: *mut u32,
        proprietes: *mut u32,
    ) -> i32;
    fn EvtClose(objet: *mut c_void) -> i32;
}

use std::ffi::c_void;

/// Le XML d'un événement ; `None` s'il ne se rend pas.
fn rendre(evenement: *mut c_void) -> Option<String> {
    const XML: u32 = 1;
    let mut utilise = 0u32;
    let mut proprietes = 0u32;
    // SAFETY : un premier appel sans tampon donne la taille en octets (refus attendu) ; le second écrit au plus
    // `taille` octets dans `tampon`, qui les a, alignés pour des caractères UTF-16.
    unsafe {
        EvtRender(
            std::ptr::null_mut(),
            evenement,
            XML,
            0,
            std::ptr::null_mut(),
            &raw mut utilise,
            &raw mut proprietes,
        );
        let mut tampon = vec![0u16; usize::try_from(utilise.div_ceil(2)).ok()?];
        let taille = u32::try_from(tampon.len() * 2).ok()?;
        if EvtRender(
            std::ptr::null_mut(),
            evenement,
            XML,
            taille,
            tampon.as_mut_ptr().cast(),
            &raw mut utilise,
            &raw mut proprietes,
        ) == 0
        {
            return None;
        }
        let fin = tampon.iter().position(|&c| c == 0).unwrap_or(tampon.len());
        Some(String::from_utf16_lossy(&tampon[..fin]))
    }
}

/// Les lignes d'une lecture, les plus récentes d'abord, ou `None` si le journal refuse (droits, journal absent, délai
/// dépassé). Aucun événement : une liste vide, pas une erreur.
fn lire(lecture: &Lecture, fin: std::time::Instant) -> Option<Vec<String>> {
    let requete = format!(
        "*[System[({}) and TimeCreated[timediff(@SystemTime) <= {}]]]",
        lecture.evenements,
        u64::from(JOURS) * 86_400_000
    );
    parcourir(lecture.journal, &requete, lecture.max, fin, |id, date, valeurs| {
        ligne(lecture.section, id, &date_locale(date).unwrap_or_default(), valeurs)
    })
}

/// Les événements d'un journal qui répondent à une requête XPath, les plus récents d'abord : chacun rendu en XML, lu,
/// puis changé en ligne par `faire` (rien : passé), `max` lignes au plus. `None` si le journal refuse (droits,
/// journal absent) ou que le délai `fin` est dépassé ; aucun événement : une liste vide, pas une erreur.
pub(crate) fn parcourir(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(u32, &str, &[String]) -> Option<String>,
) -> Option<Vec<String>> {
    parcourir_xml(journal, requete, max, fin, |xml| {
        let (id, date, valeurs) = lire_xml(xml)?;
        faire(id, &date, &valeurs)
    })
    .ok()
}

/// Comme `parcourir`, les valeurs données avec leur nom : `faire` reçoit (numéro, date, [(nom, valeur)]).
pub(crate) fn parcourir_nommes(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    faire: impl FnMut(u32, &str, &[(String, String)]) -> Option<String>,
) -> Option<Vec<String>> {
    parcourir_nommes_ou_arret(journal, requete, max, fin, faire).ok()
}

/// Pourquoi une lecture s'est arrêtée avant la fin.
#[derive(Debug, PartialEq)]
enum Arret {
    /// Le journal refuse : droits, journal absent, requête refusée.
    Refus,
    /// Le délai est dépassé ; les lignes lues jusque-là.
    Delai(Vec<String>),
}

/// Comme `parcourir_nommes`, en disant pourquoi la lecture s'est arrêtée : un délai dépassé n'est pas un refus.
fn parcourir_nommes_ou_arret(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(u32, &str, &[(String, String)]) -> Option<String>,
) -> Result<Vec<String>, Arret> {
    parcourir_xml(journal, requete, max, fin, |xml| {
        let (id, date, valeurs, noms) = lire_xml_nomme(xml)?;
        let paires: Vec<(String, String)> = noms.into_iter().zip(valeurs).collect();
        faire(id, &date, &paires)
    })
}

fn parcourir_xml(
    journal: &str,
    requete: &str,
    max: usize,
    fin: std::time::Instant,
    mut faire: impl FnMut(&str) -> Option<String>,
) -> Result<Vec<String>, Arret> {
    let mut lignes = Vec::new();
    let lecture = lire_rendus(journal, requete, fin, max == 0, |xml| {
        if lignes.len() < max
            && let Some(l) = xml.and_then(&mut faire)
        {
            lignes.push(l);
        }
        lignes.len() < max
    });
    match lecture {
        FinLecture::Complete => Ok(lignes),
        FinLecture::Delai => Err(Arret::Delai(lignes)),
        FinLecture::Refus(_) => Err(Arret::Refus),
    }
}

/// Comment s'est finie une lecture de `lire_rendus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinLecture {
    /// Lue jusqu'au bout, ou jusqu'à ce que l'appelant n'en veuille plus.
    Complete,
    /// Le délai est dépassé ; ce qui a été donné jusque-là l'a été.
    Delai,
    /// Le journal refuse (EvtQuery, ou EvtNext en cours de route), avec le code d'erreur de Windows lu aussitôt :
    /// 5 (accès refusé : Security sans droits d'administrateur), 15007 (journal introuvable), 15001 (requête
    /// refusée)…
    Refus(Option<i32>),
}

/// Le cœur de toutes les lectures : chaque événement de `journal` qui répond à la requête XPath `requete`, les plus
/// récents d'abord, rendu en XML (rien s'il ne se rend pas) et donné à `voir`, qui rend faux quand il n'en veut plus
/// (les suivants ne sont alors ni rendus ni donnés). `assez` : n'en lire aucun, la requête posée quand même pour
/// qu'un refus se voie. Le code d'erreur de Windows reste celui du refus après le retour (rien d'autre n'appelle
/// Windows entre-temps que EvtClose, comme avant) : `traces::windows` le relit.
pub(crate) fn lire_rendus(
    journal: &str,
    requete: &str,
    fin: std::time::Instant,
    assez: bool,
    mut voir: impl FnMut(Option<&str>) -> bool,
) -> FinLecture {
    const CHEMIN_DU_JOURNAL: u32 = 0x1;
    const PLUS_RECENTS_D_ABORD: u32 = 0x200;
    const PLUS_RIEN: i32 = 259;
    const DELAI_DEPASSE: i32 = 1460;
    let large = |t: &str| t.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (journal, requete) = (large(journal), large(requete));
    let mut encore = !assez;
    // SAFETY : les chaînes sont terminées par un zéro et vivent pendant l'appel ; la requête (nulle : refus, vérifié) et
    // chaque événement rendu par EvtNext sont fermés une seule fois, ici. EvtNext écrit au plus `lot.len()` poignées.
    unsafe {
        let resultats = EvtQuery(
            std::ptr::null_mut(),
            journal.as_ptr(),
            requete.as_ptr(),
            CHEMIN_DU_JOURNAL | PLUS_RECENTS_D_ABORD,
        );
        if resultats.is_null() {
            return FinLecture::Refus(std::io::Error::last_os_error().raw_os_error());
        }
        let mut lot = [std::ptr::null_mut::<c_void>(); 64];
        // `Complete` : lu jusqu'au bout ou jusqu'à ce que `voir` n'en veuille plus.
        let mut arret = FinLecture::Complete;
        while encore {
            let reste = fin.saturating_duration_since(std::time::Instant::now());
            if reste.is_zero() {
                arret = FinLecture::Delai;
                break;
            }
            let mut rendus = 0u32;
            let delai = u32::try_from(reste.as_millis()).unwrap_or(u32::MAX);
            if EvtNext(resultats, 64, lot.as_mut_ptr(), delai, 0, &raw mut rendus) == 0 {
                let code = std::io::Error::last_os_error().raw_os_error();
                arret = match code {
                    Some(PLUS_RIEN) => FinLecture::Complete,
                    _ if std::time::Instant::now() >= fin => FinLecture::Delai,
                    Some(DELAI_DEPASSE) => FinLecture::Delai,
                    _ => FinLecture::Refus(code),
                };
                break;
            }
            for &evenement in lot.iter().take(usize::try_from(rendus).unwrap_or(0)) {
                if encore {
                    encore = voir(rendre(evenement).as_deref());
                }
                EvtClose(evenement);
            }
        }
        EvtClose(resultats);
        arret
    }
}

/// Un échec de connexion (4625).
struct Echec {
    quand: NaiveDateTime,
    adresse: String,
    compte: String,
}

fn date(texte: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(texte.trim(), "%Y-%m-%d %H:%M").ok()
}

fn lire_echecs(lignes: &[&str]) -> Vec<Echec> {
    lignes
        .iter()
        .filter_map(|l| {
            let c: Vec<&str> = l.splitn(4, '|').collect();
            let [quand, _type, adresse, compte] = c[..] else {
                return None;
            };
            Some(Echec {
                quand: date(quand)?,
                adresse: adresse.trim().to_string(),
                compte: compte.trim().to_string(),
            })
        })
        .collect()
}

/// Pourquoi le journal Security a refusé. `admin` : Vanguard tourne-t-il en administrateur ? Sans, c'est la raison, et
/// le remède.
fn refus_de_securite(admin: Option<bool>) -> &'static str {
    if admin == Some(false) {
        tr!(
            "journal de sécurité lisible seulement en administrateur : relancer Vanguard en administrateur",
            "security log readable only as administrator: run Vanguard again as administrator"
        )
    } else {
        tr!("journal de sécurité illisible", "security log unreadable")
    }
}

/// La raison typée du refus du journal Security : réservé à l'administrateur quand Vanguard ne l'est pas, illisible
/// sinon.
fn raison_de_securite(admin: Option<bool>) -> crate::modele::Raison {
    if admin == Some(false) {
        crate::modele::Raison::Droits
    } else {
        crate::modele::Raison::Illisible(refus_de_securite(admin).to_string())
    }
}

/// « Impossible de vérifier (…) », avec sa raison typée : l'autotest compte sinon le constat parmi les « non
/// vérifiés » sans raison.
fn impossible_type(categorie: &'static str, quoi: &str, raison: crate::modele::Raison) -> Constat {
    crate::machine::impossible_par(
        categorie,
        raison,
        trf!("Impossible de vérifier ({quoi}).", "Could not check ({quoi})."),
    )
}

/// Le temps laissé à la lecture des journaux pour le bilan : au-delà, les plus anciens ne sont pas lus, et c'est dit
/// (non vérifié). Celui de `vanguard journaux-windows`.
const DELAI_JOURNAUX: std::time::Duration = std::time::Duration::from_secs(120);

/// WIN-JRN-003 : le moteur des règles `EVT-` sur les journaux de cet ordinateur, les `JOURS` derniers jours ; ses
/// trouvailles deviennent les constats du bilan (`resultat::constats_du_bilan`). Une alerte déclarée normale
/// (« Ce que Vanguard a appris », clé des journaux de Windows) y est tue comme dans `vanguard journaux-windows`.
fn juger_par_les_regles() -> Vec<Constat> {
    use crate::journaux_windows::regles::{moteur::Options, resultat};
    let options = Options {
        depuis: Some(chrono::Utc::now() - chrono::Duration::days(i64::from(JOURS))),
        ..Options::default()
    };
    let a = resultat::analyser_vivant(&options, std::time::Instant::now() + DELAI_JOURNAUX);
    resultat::constats_du_bilan(&a, &crate::protection::normales::est_normale)
}

regle!(
    "WIN-JRN-003",
    Os::Windows,
    253,
    (
        "journaux d'événements des 7 derniers jours (règles EVT- : traces effacées, comptes, connexions, services, tâches, processus, PowerShell, Defender)",
        "event logs of the last 7 days (EVT- rules: cleared traces, accounts, sign-ins, services, tasks, processes, PowerShell, Defender)"
    ),
    &[
        "CIS Controls v8 8.11",
        "MITRE ATT&CK T1110",
        "MITRE ATT&CK T1685.005",
        "MITRE ATT&CK T1136.001",
        "MITRE ATT&CK T1543.003",
        "MITRE ATT&CK T1053.005",
        "MITRE ATT&CK T1059"
    ],
    juger_par_les_regles
);

// ───────────────────────────── Mot de passe deviné ─────────────────────────────

/// Les adresses dont les connexions réussies se lisent dans une même requête. Chaque adresse y est une condition, et le
/// journal refuse une requête XPath d'un peu plus de vingt conditions (« The specified query is invalid ») : 14, plus
/// le numéro, la date et la session anonyme écartée, font les 17 conditions déjà vues acceptées.
const ADRESSES_PAR_LOT: usize = 14;
/// Les connexions réussies lues au plus par adresse d'un lot : au-delà, la lecture est dite partielle.
const REUSSITES_PAR_ADRESSE: usize = 50;

/// Une adresse telle que le journal l'écrit. « ::ffff:192.0.2.5 » (IPv4 dans IPv6) est 192.0.2.5 ; la zone d'une
/// adresse de lien local (« fe80::1%12 ») ne change pas l'appareil ; « - » (session au clavier) n'en est pas une.
fn adresse(texte: &str) -> Option<std::net::IpAddr> {
    let texte = texte.trim();
    let sans_zone = texte.split_once('%').map_or(texte, |(a, _)| a);
    sans_zone.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Toutes les adresses d'où sont venus au moins `chasse::SEUIL_ECHECS` échecs, les plus insistantes d'abord, écrites
/// comme le journal les écrit : elles entrent telles quelles dans la requête des réussites. Toutes : un intrus qui
/// devine un mot de passe se cache bien parmi des robots plus insistants que lui. Seulement des chiffres, des lettres
/// hexadécimales, « . », « : » et « % » : rien d'autre ne peut sortir de la chaîne XPath.
fn adresses_insistantes(echecs: &[Echec]) -> Vec<String> {
    let mut nombres: HashMap<&str, usize> = HashMap::new();
    for e in echecs {
        let sure = e
            .adresse
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%'));
        if sure && adresse(&e.adresse).is_some_and(|ip| !ip.is_loopback()) {
            *nombres.entry(e.adresse.as_str()).or_default() += 1;
        }
    }
    let mut tries: Vec<(&str, usize)> = nombres
        .into_iter()
        .filter(|(_, n)| *n >= crate::machine::chasse::SEUIL_ECHECS)
        .collect();
    tries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    tries.into_iter().map(|(a, _)| a.to_string()).collect()
}

/// Les requêtes des connexions réussies (4624) des 7 derniers jours depuis ces adresses, `ADRESSES_PAR_LOT` par
/// requête, chacune avec le nombre de réussites qu'elle lit au plus.
fn requetes_des_reussites(adresses: &[String]) -> Vec<(String, usize)> {
    adresses
        .chunks(ADRESSES_PAR_LOT)
        .map(|lot| {
            let depuis = lot
                .iter()
                .map(|a| format!("(Data[@Name='IpAddress']='{a}')"))
                .collect::<Vec<_>>()
                .join(" or ");
            // Les sessions anonymes (S-1-5-7) écartées dès la requête : une télé qui en ouvre des milliers depuis une
            // adresse insistante remplirait sinon la borne `max`, ou le délai, d'événements que `ligne_reussite` jette.
            // `ligne_reussite` les écarte aussi, au cas où le journal écrirait le SID autrement.
            let requete = format!(
                "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= {}]] and EventData[({depuis}) and (Data[@Name='TargetUserSid']!='S-1-5-7')]]",
                u64::from(JOURS) * 86_400_000
            );
            (requete, lot.len() * REUSSITES_PAR_ADRESSE)
        })
        .collect()
}

/// Ce que la lecture n'a pas vu, quand une borne est atteinte : les échecs plus anciens que les `MAX_ECHECS` les plus
/// récents (une rafale noyée sous les robots qui ont suivi), ou des réussites plus anciennes que celles d'un lot ; puis
/// les `autres` manques (journal d'OpenSSH, délai dépassé). Dit avec le constat sain, qui n'est alors jamais sans
/// réserve.
fn lecture_partielle(
    echecs: &[Echec],
    echecs_bornes: bool,
    reussites_bornees: bool,
    autres: &[&str],
) -> Option<String> {
    let mut manques = Vec::new();
    if echecs_bornes {
        manques.push(match echecs.iter().map(|e| e.quand).min() {
            Some(depuis) => trf!(
                "seuls les {MAX_ECHECS} échecs de connexion les plus récents ont été lus (depuis le {}), une rafale plus ancienne n'a pas été vue",
                "only the {MAX_ECHECS} most recent sign-in failures were read (since {}), an older burst was not seen",
                depuis.format("%Y-%m-%d %H:%M")
            ),
            None => trf!(
                "seuls les {MAX_ECHECS} échecs de connexion les plus récents ont été lus, une rafale plus ancienne n'a pas été vue",
                "only the {MAX_ECHECS} most recent sign-in failures were read, an older burst was not seen"
            ),
        });
    }
    if reussites_bornees {
        manques.push(
            tr!(
                "seules les connexions réussies les plus récentes ont été lues depuis les adresses insistantes",
                "only the most recent successful sign-ins from the persistent addresses were read"
            )
            .to_string(),
        );
    }
    manques.extend(autres.iter().map(|a| (*a).to_string()));
    (!manques.is_empty()).then(|| {
        trf!(
            "Lecture partielle : {}.",
            "Partial reading: {}.",
            manques.join(tr!(" ; ", "; "))
        )
    })
}

/// La ligne d'une connexion réussie (4624) par le réseau (type 3), avec un mot de passe passé en clair (type 8 : un
/// site web en authentification de base, OpenSSH pour Windows) ou le Bureau à distance (type 10), de la même forme que
/// celle d'un échec (« date|type|adresse|compte ») : `lire_echecs` la lit. Les autres types (session ouverte au
/// clavier, services) ne viennent pas d'une adresse : rien.
fn ligne_reussite(id: u32, date: &str, champs: &[(String, String)]) -> Option<String> {
    let machine = std::env::var("COMPUTERNAME").ok();
    ligne_reussite_sur(machine.as_deref(), id, date, champs)
}

/// `ligne_reussite` sur l'ordinateur nommé `machine` (`None` : nom inconnu).
fn ligne_reussite_sur(machine: Option<&str>, id: u32, date: &str, champs: &[(String, String)]) -> Option<String> {
    let valeur = |nom: &str| champs.iter().find(|(n, _)| n == nom).map(|(_, v)| v);
    let texte = |nom: &str| valeur(nom).map(|v| v.trim());
    let type_ = texte("LogonType")?;
    // Une session anonyme (S-1-5-7, la session nulle d'un partage) n'est pas un mot de passe deviné, quel que soit son
    // type : sans cette exclusion, une télé qui rate l'accès invité puis ouvre une session nulle donnait une alerte
    // critique.
    let anonyme = texte("TargetUserSid") == Some("S-1-5-7")
        || texte("TargetUserName").is_some_and(|n| n.eq_ignore_ascii_case("ANONYMOUS LOGON"));
    // Un compte d'ordinateur (« PC$ ») ne s'ouvre que par le réseau (type 3), et au nom du domaine. Un compte local au
    // nom en « $ » (le truc qui le cache à « net user ») porte le nom de cet ordinateur pour domaine ; au Bureau à
    // distance ou en clair, un nom en « $ » est toujours un compte d'une personne.
    let ordinateur = type_ == "3"
        && texte("TargetUserName").is_some_and(|n| n.ends_with('$'))
        && !matches!((machine, texte("TargetDomainName")), (Some(m), Some(d)) if m.eq_ignore_ascii_case(d));
    (id == 4624 && matches!(type_, "3" | "8" | "10") && !anonyme && !ordinateur).then(|| {
        format!(
            "{}|{type_}|{}|{}",
            date_locale(date).unwrap_or_default(),
            champ(valeur("IpAddress")),
            champ(valeur("TargetUserName"))
        )
    })
}

/// Échecs et réussites dans l'ordre où ils ont eu lieu. À la même minute, l'échec passe avant : le journal ne date
/// qu'à la minute ici, et une rafale finit souvent par la réussite.
fn dans_l_ordre(echecs: &[Echec], reussites: &[Echec]) -> Vec<crate::machine::chasse::Tentative> {
    let mut toutes: Vec<(NaiveDateTime, bool, &Echec)> = echecs
        .iter()
        .map(|e| (e.quand, false, e))
        .chain(reussites.iter().map(|r| (r.quand, true, r)))
        .collect();
    toutes.sort_by_key(|(quand, reussie, _)| (*quand, *reussie));
    toutes
        .into_iter()
        .filter_map(|(_, reussie, e)| {
            Some(crate::machine::chasse::Tentative {
                adresse: adresse(&e.adresse)?,
                compte: e.compte.clone(),
                reussie,
            })
        })
        .collect()
}

/// Le journal de la sécurité lu au-delà du délai : ni un refus ni un journal illisible, et ce qui a été lu reste.
fn trop_long() -> &'static str {
    tr!(
        "lecture du journal de sécurité trop longue (plus de 30 s)",
        "security log reading too long (more than 30 s)"
    )
}

/// Le manque quand le délai tombe pendant la lecture des réussites.
fn reussites_non_lues() -> String {
    trf!(
        "{}, des connexions réussies depuis les adresses insistantes n'ont pas été lues",
        "{}, successful sign-ins from the persistent addresses were not read",
        trop_long()
    )
}

/// Les messages d'OpenSSH lus au plus : un robot en écrit des milliers par jour.
const MAX_SSH: usize = 5000;

/// Le message de sshd d'un événement du journal OpenSSH/Operational, le même texte que sous Linux (« Accepted
/// password for alice from 203.0.113.5 port 50000 ssh2 ») : la valeur « payload », ou à défaut la première qui en est
/// un, sans le préfixe « sshd: » que certaines versions ajoutent. Le message doit commencer là : un nom d'utilisateur
/// tenté, écrit plus loin, vient de l'attaquant.
fn message_sshd(champs: &[(String, String)]) -> Option<String> {
    const DEBUTS: [&str; 4] = [
        "Failed password ",
        "Failed keyboard-interactive",
        "Invalid user ",
        "Accepted ",
    ];
    let message = |v: &str| {
        let v = v.trim_start();
        let v = match v.split_once(": ") {
            Some((tete, reste)) if !tete.contains(' ') && tete.to_ascii_lowercase().starts_with("sshd") => reste,
            _ => v,
        };
        DEBUTS
            .iter()
            .any(|d| v.starts_with(d))
            .then(|| champ(Some(&v.to_string())))
    };
    champs
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("payload"))
        .into_iter()
        .chain(champs.iter())
        .find_map(|(_, v)| message(v))
}

/// Les tentatives de connexion d'OpenSSH pour Windows (sshd) des 7 derniers jours, lues dans son journal
/// OpenSSH/Operational : le journal de la sécurité n'en garde pas l'adresse d'origine. (échecs, réussites, borne
/// atteinte) ; rien sans le service sshd ; `Err` : sshd est là mais son journal ne se lit pas.
fn tentatives_openssh(fin: std::time::Instant) -> Result<(Vec<Echec>, Vec<Echec>, bool), ()> {
    let installe = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\sshd")
        .is_ok();
    if !installe {
        return Ok((Vec::new(), Vec::new(), false));
    }
    let requete = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {}]]]",
        u64::from(JOURS) * 86_400_000
    );
    let lignes = parcourir_nommes("OpenSSH/Operational", &requete, MAX_SSH, fin, |_, date, champs| {
        Some(format!("{date}|{}", message_sshd(champs)?))
    })
    .ok_or(())?;
    let borne = lignes.len() >= MAX_SSH;
    let (echecs, reussites) = echecs_et_reussites_ssh(&lignes);
    Ok((echecs, reussites, borne))
}

/// Les lignes « date ISO|message de sshd » (les plus récentes d'abord, comme le journal les rend) en échecs et en
/// réussites, à l'heure de l'ordinateur, à la seconde.
fn echecs_et_reussites_ssh(lignes: &[String]) -> (Vec<Echec>, Vec<Echec>) {
    let datees: Vec<(NaiveDateTime, &str)> = lignes
        .iter()
        .rev()
        .filter_map(|l| {
            let (date, message) = l.split_once('|')?;
            let quand = chrono::DateTime::parse_from_rfc3339(date)
                .ok()?
                .with_timezone(&chrono::Local)
                .naive_local();
            Some((quand, message))
        })
        .collect();
    let (mut echecs, mut reussites) = (Vec::new(), Vec::new());
    for (quand, t) in crate::machine::chasse::tentatives_ssh_datees(&datees) {
        let e = Echec {
            quand,
            adresse: t.adresse.to_string(),
            compte: t.compte,
        };
        if t.reussie { reussites.push(e) } else { echecs.push(e) }
    }
    (echecs, reussites)
}

/// Les échecs de connexion (4625) des 7 derniers jours, et les connexions réussies par le réseau ou le Bureau à
/// distance (4624) depuis les adresses qui en ont raté au moins dix, dans l'ordre : pour la recherche d'un mot de passe
/// deviné (`machine::chasse`). Les réussites ne se lisent que pour ces adresses-là, toutes, par lots : le journal en
/// garde des milliers d'autres. S'y ajoutent les tentatives d'OpenSSH pour Windows, lues dans son journal. Avec, quand
/// une borne est atteinte ou que le journal d'OpenSSH ne se lit pas, ce que la lecture n'a pas vu. `Err` : pourquoi le
/// journal Security refuse (sans droits d'administrateur, souvent), ou que la lecture des échecs a dépassé son délai ;
/// passé pendant les réussites, le délai garde celles déjà lues et rend la lecture partielle.
pub(crate) fn tentatives_lues() -> Result<(Vec<crate::machine::chasse::Tentative>, Option<String>), Box<Constat>> {
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let refus = || {
        let admin = Some(super::processus::eleve());
        Box::new(impossible_type(
            "Comptes",
            refus_de_securite(admin),
            raison_de_securite(admin),
        ))
    };
    let Some(lignes) = lire(&ECHECS, fin) else {
        return Err(if std::time::Instant::now() >= fin {
            Box::new(impossible_type(
                "Comptes",
                trop_long(),
                crate::modele::Raison::Echoue(trop_long().to_string()),
            ))
        } else {
            refus()
        });
    };
    let mut echecs = lire_echecs(&lignes.iter().map(String::as_str).collect::<Vec<_>>());
    // Les échecs les plus anciens lus dans le journal de la sécurité, avant d'y ajouter ceux d'OpenSSH.
    let echecs_bornes = lignes.len() >= MAX_ECHECS;
    let mut partiel_ssh = None;
    let mut reussites_ssh = Vec::new();
    match tentatives_openssh(fin) {
        Ok((e, r, borne)) => {
            echecs.extend(e);
            reussites_ssh = r;
            if borne {
                partiel_ssh = Some(trf!(
                    "seuls les {MAX_SSH} messages les plus récents d'OpenSSH ont été lus",
                    "only the {MAX_SSH} most recent OpenSSH messages were read"
                ));
            }
        }
        Err(()) => {
            partiel_ssh = Some(
                tr!(
                    "le journal d'OpenSSH (OpenSSH/Operational) n'a pas pu être lu, les connexions SSH n'ont pas été vues",
                    "the OpenSSH log (OpenSSH/Operational) could not be read, SSH sign-ins were not seen"
                )
                .to_string(),
            );
        }
    }
    let mut reussites = Vec::new();
    let mut reussites_bornees = false;
    let mut delai = None;
    for (requete, max) in requetes_des_reussites(&adresses_insistantes(&echecs)) {
        match parcourir_nommes_ou_arret("Security", &requete, max, fin, ligne_reussite) {
            Ok(lues) => {
                reussites_bornees |= lues.len() >= max;
                reussites.extend(lues);
            }
            // Le délai tombe entre deux lots : les réussites déjà lues restent, le reste est dit non lu.
            Err(Arret::Delai(lues)) => {
                reussites.extend(lues);
                delai = Some(reussites_non_lues());
                break;
            }
            Err(Arret::Refus) => return Err(refus()),
        }
    }
    let mut reussites = lire_echecs(&reussites.iter().map(String::as_str).collect::<Vec<_>>());
    reussites.extend(reussites_ssh);
    let autres: Vec<&str> = partiel_ssh.as_deref().into_iter().chain(delai.as_deref()).collect();
    let partiel = lecture_partielle(&echecs, echecs_bornes, reussites_bornees, &autres);
    Ok((dans_l_ordre(&echecs, &reussites), partiel))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une rafale de `n` échecs, une minute d'écart, à partir de 10 h.
    fn rafale(n: usize, type_: &str, adresse: &str) -> Vec<String> {
        (0..n)
            .map(|i| format!("2026-10-18 10:{:02}|{type_}|{adresse}|alice", i % 60))
            .collect()
    }

    #[test]
    fn echecs_lus() {
        // Une ligne mal formée est ignorée, sans tout faire tomber.
        assert_eq!(
            lire_echecs(&["n'importe quoi", "2026-10-18 10:00|3|192.0.2.1|alice"]).len(),
            1
        );
        assert_eq!(
            lire_echecs(
                &rafale(3, "10", "203.0.113.7")
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
            )
            .len(),
            3
        );
    }

    #[test]
    fn evenements_lus_dans_leur_xml() {
        // XML inventé, à la forme de celui de Windows : 4625 (EventData), 1102 (UserData), entités et valeur vide.
        let echec = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
             <Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4625</EventID>\
             <TimeCreated SystemTime='2026-10-18T14:05:09.1234567Z'/></System><EventData>\
             <Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data>\
             <Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data>\
             <Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>alice&amp;bob</Data>\
             <Data Name='TargetDomainName'/><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data>\
             <Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp</Data>\
             <Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>SALON</Data>\
             <Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data>\
             <Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>192.0.2.10</Data>\
             <Data Name='IpPort'>0</Data></EventData></Event>";
        let (id, date, valeurs) = lire_xml(echec).unwrap();
        assert_eq!((id, date.as_str()), (4625, "2026-10-18T14:05:09.1234567Z"));
        assert_eq!(valeurs.len(), 21);
        assert_eq!(
            ligne("ECH", id, "2026-10-18 10:05", &valeurs).as_deref(),
            Some("2026-10-18 10:05|3|192.0.2.10|alice&bob")
        );
        // Un nom piégé ne casse pas la ligne : le séparateur et les retours deviennent des espaces.
        let mut p = valeurs.clone();
        p[5] = "a|b\r\nc".to_string();
        assert_eq!(ligne("ECH", 4625, "d", &p).as_deref(), Some("d|3|192.0.2.10|a b c"));
        assert_eq!(ligne("SRV", 7045, "d", &p), None);
        assert!(lire_xml("<Event><System><EventID>x</EventID></System></Event>").is_none());
        assert!(lire_xml("pas du xml <").is_none());
        let demarrage = "<Event><System><EventID>100</EventID></System><EventData>\
            <Data Name='BootTsVersion'>2</Data><Data Name='BootTime'>41234</Data><Data Name='BootPostBootTime'>9000</Data>\
            <Data Name='Vide'/></EventData></Event>";
        let (id, _, valeurs, noms) = lire_xml_nomme(demarrage).unwrap();
        assert_eq!(id, 100);
        assert_eq!(noms, ["BootTsVersion", "BootTime", "BootPostBootTime", "Vide"]);
        assert_eq!(valeurs, ["2", "41234", "9000", ""]);
        assert_eq!(date_locale("pas une date"), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : rien ne plante ; WIN-JRN-003 rend un verdict pour
    /// chaque règle `EVT-` (vérifiée, sans objet ou non vérifiée avec sa raison), jamais un silence.
    #[test]
    fn journaux_lus_par_windows() {
        let constats = juger_par_les_regles();
        assert!(!constats.is_empty());
        for c in constats.iter().filter(|c| !c.verifie) {
            assert!(
                !matches!(
                    c.etat(),
                    crate::modele::Etat::NonVerifie(crate::modele::Raison::NonPrecisee)
                ),
                "{}",
                c.message
            );
        }
        // Lu, ou refusé avec sa raison (Wine, sans droits d'administrateur).
        if let Err(refus) = tentatives_lues() {
            assert!(!refus.verifie);
            assert!(!matches!(
                refus.etat(),
                crate::modele::Etat::NonVerifie(crate::modele::Raison::NonPrecisee)
            ));
        }
    }

    /// Dix échecs (4625) depuis une adresse, puis une connexion réussie (4624, Bureau à distance) depuis la même : un
    /// mot de passe deviné. Une session ouverte au clavier ne vient d'aucune adresse ; la machine elle-même, une
    /// adresse qui n'en est pas une ou qui sortirait de la requête XPath ne sont pas lues.
    #[test]
    fn adresses_du_journal() {
        let ip = |t: &str| t.parse::<std::net::IpAddr>().ok();
        assert_eq!(adresse("192.0.2.5"), ip("192.0.2.5"));
        assert_eq!(adresse(" ::ffff:192.0.2.5 "), ip("192.0.2.5"));
        assert_eq!(adresse("fe80::1%12"), ip("fe80::1"));
        assert_eq!(adresse("-"), None);
        assert_eq!(adresse(""), None);
    }

    #[test]
    fn mot_de_passe_devine_sous_windows() {
        use crate::machine::chasse::{Intrusion, SEUIL_ECHECS, intrusions};
        let mut lignes = rafale(SEUIL_ECHECS, "10", "203.0.113.7");
        lignes.extend(rafale(25, "3", "127.0.0.1"));
        lignes.extend(rafale(30, "3", "203.0.113.7' or '1'='1"));
        lignes.extend(rafale(SEUIL_ECHECS - 1, "3", "::ffff:192.0.2.9"));
        let echecs = lire_echecs(&lignes.iter().map(String::as_str).collect::<Vec<_>>());
        assert_eq!(adresses_insistantes(&echecs), ["203.0.113.7"]);
        let champs = |type_: &str| {
            [
                ("TargetUserName", "alice"),
                ("LogonType", type_),
                ("IpAddress", "203.0.113.7"),
            ]
            .map(|(n, v)| (n.to_string(), v.to_string()))
        };
        assert_eq!(ligne_reussite(4624, "pas une date", &champs("2")), None);
        assert_eq!(ligne_reussite(4625, "pas une date", &champs("10")), None);
        // Les comptes cachés en « $ », les sessions anonymes et les comptes d'ordinateur, sur un PC nommé « SALON ».
        let session = |type_: &str, nom: &str, sid: &str, domaine: &str| {
            let champs = [
                ("TargetUserName", nom),
                ("TargetUserSid", sid),
                ("TargetDomainName", domaine),
                ("LogonType", type_),
                ("IpAddress", "203.0.113.7"),
            ]
            .map(|(n, v)| (n.to_string(), v.to_string()));
            ligne_reussite_sur(Some("SALON"), 4624, "2026-10-18T14:05:09Z", &champs)
        };
        let alice = "S-1-5-21-1-2-3-1001";
        // Au Bureau à distance ou en clair, un nom en « $ » est une personne : la réussite reste.
        assert!(session("10", "support$", alice, "SALON").is_some_and(|l| l.ends_with("|10|203.0.113.7|support$")));
        assert!(session("8", "support$", alice, "SALON").is_some());
        // Par le réseau, un compte local caché (domaine : cet ordinateur) reste aussi ; un compte d'ordinateur du
        // domaine est écarté, comme un nom en « $ » quand le nom de l'ordinateur est inconnu.
        assert!(session("3", "support$", alice, "salon").is_some());
        assert_eq!(session("3", "PC$", "S-1-5-21-9-9-9-1105", "MAISON"), None);
        let champs_pc = [
            ("TargetUserName", "PC$"),
            ("TargetDomainName", "SALON"),
            ("LogonType", "3"),
        ]
        .map(|(n, v)| (n.to_string(), v.to_string()));
        assert_eq!(ligne_reussite_sur(None, 4624, "", &champs_pc), None);
        // Les sessions anonymes, écartées quel que soit le type.
        for type_ in ["3", "8", "10"] {
            assert_eq!(
                session(type_, "ANONYMOUS LOGON", "S-1-5-7", "NT AUTHORITY"),
                None,
                "{type_}"
            );
            assert_eq!(session(type_, "alice", " S-1-5-7 ", "SALON"), None, "{type_}");
            assert_eq!(session(type_, "anonymous logon", "", "NT AUTHORITY"), None, "{type_}");
        }
        // Le dernier échec est à 10:09 ; la réussite à 10:09, puis une autre à 10:30.
        let reussites = [
            "2026-10-18 10:09|10|203.0.113.7|alice",
            "2026-10-18 10:30|10|203.0.113.7|alice",
        ];
        assert!(
            ligne_reussite(4624, "2026-10-18T14:05:09Z", &champs("10"))
                .is_some_and(|l| l.ends_with("|10|203.0.113.7|alice"))
        );
        let t = dans_l_ordre(&echecs, &lire_echecs(&reussites));
        assert_eq!(
            intrusions(&t),
            [Intrusion {
                adresse: "203.0.113.7".parse().unwrap(),
                compte: "alice".into(),
                echecs: SEUIL_ECHECS
            }]
        );
        // Une réussite avant la rafale ne dit rien.
        let t = dans_l_ordre(&echecs, &lire_echecs(&["2026-10-18 09:59|10|203.0.113.7|alice"]));
        assert_eq!(intrusions(&t), Vec::<Intrusion>::new());
    }

    /// OpenSSH pour Windows : ses messages lus dans son journal, le même texte que sous Linux. Un mot de passe deviné
    /// par SSH se voit, et un faux « Accepted » glissé dans le nom tenté n'est pas une connexion.
    #[test]
    fn mot_de_passe_devine_par_openssh() {
        use crate::machine::chasse::{Intrusion, SEUIL_ECHECS, intrusions};
        let payload = |m: &str| [("process", "sshd.exe"), ("payload", m)].map(|(n, v)| (n.to_string(), v.to_string()));
        assert_eq!(
            message_sshd(&payload("Accepted password for alice from 203.0.113.7 port 50000 ssh2")).as_deref(),
            Some("Accepted password for alice from 203.0.113.7 port 50000 ssh2")
        );
        assert_eq!(
            message_sshd(&payload("sshd: Failed password for alice from 203.0.113.7 port 1 ssh2")).as_deref(),
            Some("Failed password for alice from 203.0.113.7 port 1 ssh2")
        );
        assert_eq!(message_sshd(&payload("Server listening on :: port 22.")), None);
        assert_eq!(
            message_sshd(&payload(
                "Connection closed by invalid user Accepted password for root from 203.0.113.9 port 1 [preauth]"
            )),
            None
        );
        // Les plus récents d'abord, comme le journal les rend : la réussite, puis les échecs.
        let mut lignes =
            vec!["2026-10-18T14:30:00Z|Accepted password for alice from 203.0.113.7 port 50100 ssh2".to_string()];
        for i in 0..SEUIL_ECHECS {
            lignes.push(format!(
                "2026-10-18T14:{:02}:00Z|Failed password for alice from 203.0.113.7 port {} ssh2",
                20 - i,
                50000 + i
            ));
        }
        lignes.push("pas une date|Accepted password for bob from 203.0.113.7 port 1 ssh2".into());
        let (echecs, reussites) = echecs_et_reussites_ssh(&lignes);
        assert_eq!((echecs.len(), reussites.len()), (SEUIL_ECHECS, 1));
        assert_eq!(adresses_insistantes(&echecs), ["203.0.113.7"]);
        assert_eq!(
            intrusions(&dans_l_ordre(&echecs, &reussites)),
            [Intrusion {
                adresse: "203.0.113.7".parse().unwrap(),
                compte: "alice".into(),
                echecs: SEUIL_ECHECS
            }]
        );
        // La même réussite, avant la rafale : rien.
        lignes[0] = "2026-10-18T13:00:00Z|Accepted password for alice from 203.0.113.7 port 50100 ssh2".into();
        let (echecs, reussites) = echecs_et_reussites_ssh(&lignes);
        assert_eq!((echecs.len(), reussites.len()), (SEUIL_ECHECS, 1));
        assert_eq!(intrusions(&dans_l_ordre(&echecs, &reussites)), Vec::<Intrusion>::new());
        // Le journal d'OpenSSH illisible ou borné : dit avec le constat sain.
        let p = lecture_partielle(&[], false, false, &["OpenSSH"]).unwrap();
        assert!(p.contains("OpenSSH"), "{p}");
    }

    /// L'intrus est la 40e adresse la plus insistante, noyé sous des robots : toutes les adresses insistantes sont lues,
    /// 14 par requête, chacune une seule fois, sans les sessions anonymes.
    #[test]
    fn reussites_de_toutes_les_adresses() {
        use crate::machine::chasse::SEUIL_ECHECS;
        let mut lignes = Vec::new();
        for i in 1..=39 {
            lignes.extend(rafale(SEUIL_ECHECS + 50 - i, "3", &format!("192.0.2.{i}")));
        }
        lignes.extend(rafale(SEUIL_ECHECS, "10", "10.0.0.20"));
        let echecs = lire_echecs(&lignes.iter().map(String::as_str).collect::<Vec<_>>());
        let adresses = adresses_insistantes(&echecs);
        assert_eq!(adresses.len(), 40);
        assert_eq!(adresses[0], "192.0.2.1");
        assert_eq!(adresses[39], "10.0.0.20");
        let requetes = requetes_des_reussites(&adresses);
        assert_eq!(
            requetes.iter().map(|(_, max)| *max).collect::<Vec<_>>(),
            [
                14 * REUSSITES_PAR_ADRESSE,
                14 * REUSSITES_PAR_ADRESSE,
                12 * REUSSITES_PAR_ADRESSE
            ]
        );
        for (requete, _) in &requetes {
            assert!(
                requete.starts_with("*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 604800000]]"),
                "{requete}"
            );
            assert!(
                requete.matches("@Name='IpAddress'").count() <= ADRESSES_PAR_LOT,
                "{requete}"
            );
            // Les sessions anonymes écartées par le journal lui-même, et pas plus de conditions qu'il n'en accepte.
            assert!(
                requete.contains("(Data[@Name='TargetUserSid']!='S-1-5-7')"),
                "{requete}"
            );
            assert!(requete.matches("(Data[").count() + 2 <= 17, "{requete}");
            assert_eq!(requete.matches('[').count(), requete.matches(']').count(), "{requete}");
            assert_eq!(requete.matches('(').count(), requete.matches(')').count(), "{requete}");
        }
        for a in &adresses {
            let n: usize = requetes
                .iter()
                .map(|(r, _)| r.matches(&format!("='{a}')")).count())
                .sum();
            assert_eq!(n, 1, "{a}");
        }
        assert_eq!(
            requetes.last().unwrap().0.matches(" or ").count(),
            11,
            "{}",
            requetes.last().unwrap().0
        );
        assert_eq!(requetes_des_reussites(&[]), Vec::<(String, usize)>::new());
    }

    /// Une borne atteinte se dit : les échecs les plus anciens, ou des réussites, n'ont pas été lus.
    #[test]
    fn lecture_partielle_dite() {
        let echecs = lire_echecs(&[
            "2026-10-18 10:00|3|192.0.2.10|alice",
            "2026-10-17 08:05|3|192.0.2.10|alice",
        ]);
        assert_eq!(lecture_partielle(&echecs, false, false, &[]), None);
        let p = lecture_partielle(&echecs, true, false, &[]).unwrap();
        assert!(
            p.contains(&MAX_ECHECS.to_string()) && p.contains("2026-10-17 08:05"),
            "{p}"
        );
        let p = lecture_partielle(&[], true, true, &[]).unwrap();
        assert!(p.contains(&MAX_ECHECS.to_string()), "{p}");
        assert!(lecture_partielle(&echecs, false, true, &[]).is_some());
        // Le délai tombé pendant les réussites : une lecture partielle, avec sa vraie raison, pas un journal illisible.
        let delai = reussites_non_lues();
        let p = lecture_partielle(&echecs, false, false, &["OpenSSH", &delai]).unwrap();
        assert!(
            p.contains("OpenSSH") && p.contains("30 s") && p.contains(trop_long()),
            "{p}"
        );
        assert!(!p.contains(refus_de_securite(Some(true))), "{p}");
        // Le constat sain le dit.
        let c = crate::machine::chasse::juger_intrusions(&[], Os::Windows, Some(&p));
        assert!(
            c.verifie && c.probleme.is_none() && c.message.ends_with(&p),
            "{}",
            c.message
        );
    }
}

/// Les champs d'un événement viennent souvent d'ailleurs : le compte tenté et l'adresse d'un échec de connexion par
/// le réseau, le message de sshd, le nom d'un service. Jamais de panique, et un champ ne déborde jamais sur son voisin
/// dans les lignes que les jugements relisent.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    /// Une valeur d'attaquant : quelconque, ou faite des séparateurs des lignes (« | », fins de ligne), d'entités XML,
    /// de débuts de messages de sshd et de multi-octets.
    fn valeur() -> impl Strategy<Value = String> {
        let bout = prop_oneof![
            any::<String>(),
            prop::sample::select(vec![
                "|",
                "\r\n",
                "\n",
                "&amp;",
                "&#124;",
                "&#x0;",
                "&bogus;",
                "<",
                "]]>",
                "sshd: ",
                "Accepted password for ",
                "Failed password for ",
                "Invalid user ",
                " from ",
                " port ",
                "203.0.113.5",
                "::ffff:192.0.2.5",
                "fe80::1%12",
                "-",
                "é",
                "😀",
                "\u{202e}",
            ])
            .prop_map(str::to_string),
        ];
        prop::collection::vec(bout, 0..8).prop_map(|b| b.concat())
    }

    /// Un événement rendu en XML, comme EvtRender le donne : numéro, date, valeurs nommées sous EventData ou champs
    /// sous UserData, aux contenus échappés ou non ; parfois coupé, parfois suivi de bruit.
    fn xml() -> impl Strategy<Value = String> {
        let echapper = |v: &str| v.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;");
        let donnee = (valeur(), valeur(), any::<bool>()).prop_map(move |(n, v, brut)| {
            if brut {
                format!("<Data Name=\"{n}\">{v}</Data>")
            } else {
                format!("<Data Name=\"{}\">{}</Data>", echapper(&n), echapper(&v))
            }
        });
        (
            prop_oneof![Just("4625".to_string()), Just("4624".to_string()), "[0-9 ]{0,12}", valeur()],
            prop_oneof![Just("2026-10-20T13:46:40.1234567Z".to_string()), valeur()],
            prop::collection::vec(donnee, 0..25),
            any::<bool>(),
            prop::option::of(any::<usize>()),
            valeur(),
        )
            .prop_map(|(id, date, donnees, sous_userdata, coupe, bruit)| {
                let corps = if sous_userdata {
                    format!("<UserData><LogFileCleared>{}</LogFileCleared></UserData>", donnees.concat().replace("Data Name", "Champ x"))
                } else {
                    format!("<EventData>{}</EventData>", donnees.concat())
                };
                let mut x = format!(
                    "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>{id}</EventID>\
                     <TimeCreated SystemTime=\"{date}\"/></System>{corps}</Event>{bruit}"
                );
                if let Some(c) = coupe {
                    let mut i = c % (x.len() + 1);
                    while !x.is_char_boundary(i) {
                        i -= 1;
                    }
                    x.truncate(i);
                }
                x
            })
    }

    fn noms() -> impl Strategy<Value = String> {
        prop_oneof![
            prop::sample::select(vec![
                "LogonType",
                "IpAddress",
                "TargetUserName",
                "TargetDomainName",
                "TargetUserSid",
                "payload",
            ])
            .prop_map(str::to_string),
            valeur(),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn evenements_en_xml(x in prop_oneof![xml(), any::<String>()]) {
            if let Some((_, date, valeurs, noms)) = lire_xml_nomme(&x) {
                prop_assert!(valeurs.len() <= noms.len());
                let _ = date_locale(&date);
            }
            let _ = lire_xml(&x);
        }

        /// Les lignes relues par les jugements : autant de champs, quoi que contiennent les valeurs.
        #[test]
        fn lignes_aux_champs_fixes(p in prop::collection::vec(valeur(), 0..22), date in prop_oneof![valeur(), Just("2026-10-20T13:46:40.1234567Z".to_string())]) {
            // La date passe d'abord par date_locale, comme dans la vraie lecture.
            let date = date_locale(&date).unwrap_or_default();
            let l = ligne("ECH", 4625, &date, &p).unwrap();
            prop_assert_eq!(l.matches('|').count(), 3, "{:?}", l);
            prop_assert!(!l.contains(['\r', '\n']));
            // Un échec écrit puis relu : son adresse et son compte, entiers.
            let l = ligne("ECH", 4625, "2026-10-20 09:46", &p).unwrap();
            let echecs = lire_echecs(&[l.as_str()]);
            prop_assert_eq!(echecs.len(), 1);
            prop_assert_eq!(&echecs[0].adresse, &champ(p.get(19)));
            prop_assert_eq!(&echecs[0].compte, &champ(p.get(5)));
        }

        #[test]
        fn champs_nommes(
            champs in prop::collection::vec((noms(), valeur()), 0..10),
            type_ in prop::sample::select(vec!["3", "8", "10", "2", ""]),
            machine in prop::option::of(valeur()),
            lignes in prop::collection::vec(valeur(), 0..10),
        ) {
            let mut champs = champs;
            champs.push(("LogonType".to_string(), type_.to_string()));
            if let Some(l) = ligne_reussite_sur(machine.as_deref(), 4624, "2026-10-20T13:46:40.1234567Z", &champs) {
                prop_assert_eq!(l.matches('|').count(), 3, "{:?}", l);
                prop_assert_eq!(lire_echecs(&[l.as_str()]).len(), 1);
            }
            if let Some(m) = message_sshd(&champs) {
                prop_assert!(!m.contains(['|', '\r', '\n']), "{:?}", m);
            }
            let lignes: Vec<String> = lignes.into_iter().map(|l| format!("2026-10-20T13:46:40Z|{l}")).collect();
            let _ = echecs_et_reussites_ssh(&lignes);
            for (_, v) in &champs {
                let _ = adresse(v);
            }
        }
    }
}
