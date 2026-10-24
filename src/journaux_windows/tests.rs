//! Une seule forme, deux sources : le XML rendu par le service des journaux (source vivante) et le BinXml d'un fichier
//! (source fichiers) donnent le même événement. Essayé sur du XML écrit à la main (la forme de celui de Windows),
//! sur l'arbre d'un fichier réécrit en XML puis relu, sur le XML de la crate evtx (un autre lecteur), et sur les
//! échantillons publics (`VANGUARD_EVTX_ECHANTILLONS`, jamais dans le dépôt), dont les bilans sont vérifiés.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use proptest::prelude::*;

use super::evenement::{EvenementWindows, Filtre, Origine};
use super::evtx::{self, Bornes, Noeud};
use super::fichiers::{self, BornesFichiers};
use super::trous::{Nature, Numerotation};
use super::xml::{self, ErreurXml};

/// La forme commune d'un XML rendu, comme la source vivante la tire.
fn du_xml(x: &str) -> Option<EvenementWindows> {
    let (e, _) = xml::enregistrement(x, &Bornes::default()).ok()?;
    EvenementWindows::depuis(e, Origine::Vivant)
}

#[test]
fn le_xml_de_windows_donne_la_forme_commune() {
    // XML inventé, à la forme de celui que rend EvtRender : 4625 (EventData), entités, valeur vide, SID d'auteur.
    let echec = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
         <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/>\
         <EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task>\
         <TimeCreated SystemTime='2026-10-18T14:05:09.1234567Z'/><EventRecordID>81234</EventRecordID>\
         <Correlation/><Execution ProcessID='812' ThreadID='9000'/><Channel>Security</Channel>\
         <Computer>poste-alice</Computer><Security UserID='S-1-5-18'/></System><EventData>\
         <Data Name='TargetUserName'>alice&amp;bob &lt;x&gt; &#x263A;</Data><Data Name='TargetDomainName'/>\
         <Data Name='LogonType'>3</Data><Data Name='IpAddress'>192.0.2.10</Data></EventData></Event>";
    let e = du_xml(echec).unwrap();
    assert_eq!(
        (e.journal.as_str(), e.id, e.niveau, e.numero),
        ("Security", 4625, Some(0), Some(81234))
    );
    assert_eq!(e.fournisseur, "Microsoft-Windows-Security-Auditing");
    assert_eq!(e.ordinateur, "poste-alice");
    assert_eq!(e.utilisateur.as_deref(), Some("S-1-5-18"));
    let attendue = chrono::DateTime::parse_from_rfc3339("2026-10-18T14:05:09.1234567Z").unwrap();
    assert_eq!(e.date, Some(attendue.to_utc()));
    assert_eq!(
        e.champs,
        [
            ("TargetUserName", "alice&bob <x> ☺"),
            ("TargetDomainName", ""),
            ("LogonType", "3"),
            ("IpAddress", "192.0.2.10")
        ]
        .map(|(n, v)| (n.to_string(), v.to_string()))
    );
    assert_eq!(e.origine, Origine::Vivant);
    // 1102 : les champs sous UserData, nommés par leur chemin sous son premier élément.
    let efface = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>\
         <Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><Level>4</Level>\
         <TimeCreated SystemTime='2026-10-18T14:05:09Z'/><EventRecordID>1087729</EventRecordID>\
         <Channel>Security</Channel><Computer>poste-alice</Computer></System><UserData>\
         <LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
         <SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>bob</SubjectUserName></LogFileCleared>\
         </UserData></Event>";
    let e = du_xml(efface).unwrap();
    assert_eq!(
        (e.id, e.numero, e.utilisateur.as_deref()),
        (1102, Some(1_087_729), None)
    );
    assert_eq!(e.champ("SubjectUserName"), Some("bob"));
    assert_eq!(e.champ("SubjectUserSid"), Some("S-1-5-21-1"));
}

/// Les fins de ligne et les tabulations d'une valeur (un bloc de script, une ligne de commande) restent telles
/// quelles, dans le texte comme dans un attribut, brutes ou en références : le même texte que le lecteur .evtx.
#[test]
fn les_fins_de_ligne_ne_sont_pas_normalisees() {
    let x = "<Event a='p\tq\r\nr&#13;'><Data>x\r\ny\rz&#xD;&#10;</Data></Event>";
    let a = xml::arbre(x, &Bornes::default()).unwrap();
    assert_eq!(a.racine.attribut("a"), Some("p\tq\r\nr\r"));
    assert_eq!(a.racine.enfants[0].texte, "x\r\ny\rz\r\n");
    // Un « & » sans « ; » reste tel quel dans un attribut ; une référence inconnue y devient U+FFFD.
    let a = xml::arbre("<Event a='x &amp; y' b='&inconnue;' c='&#0;'/>", &Bornes::default()).unwrap();
    assert_eq!(
        (a.racine.attribut("a"), a.racine.attribut("b"), a.racine.attribut("c")),
        (Some("x & y"), Some("\u{FFFD}"), Some("\u{FFFD}"))
    );
}

#[test]
fn un_xml_mal_forme_ou_demesure_est_illisible() {
    let b = Bornes::default();
    for x in ["", "pas du xml", "<Event><System>", "<Event></System></Event>", "<a/>"] {
        assert!(xml::enregistrement(x, &b).is_err(), "{x}");
    }
    // Sans numéro d'événement : lu, mais pas dans la forme commune (la source le compte à part).
    let (e, _) = xml::enregistrement("<Event><System><EventRecordID>7</EventRecordID></System></Event>", &b).unwrap();
    assert_eq!(e.numero_systeme, Some(7));
    assert!(EvenementWindows::depuis(e, Origine::Vivant).is_none());
    // Trop profond, trop d'éléments, trop de texte : démesuré, sans déborder la pile.
    let profond = format!("{}{}", "<a>".repeat(100_000), "</a>".repeat(100_000));
    assert_eq!(xml::arbre(&profond, &b), Err(ErreurXml::Demesure));
    let large = format!("<Event>{}</Event>", "<Data/>".repeat(10_000));
    assert_eq!(xml::arbre(&large, &b), Err(ErreurXml::Demesure));
    let attributs = format!(
        "<Event {}/>",
        (0..5000).fold(String::new(), |mut s, i| {
            let _ = write!(s, "a{i}='x' ");
            s
        })
    );
    assert_eq!(xml::arbre(&attributs, &b), Err(ErreurXml::Demesure));
    let texte = format!("<Event>{}</Event>", "<Data>&amp;</Data>".repeat(3000));
    let petites = Bornes {
        texte_enregistrement: 1000,
        ..Bornes::default()
    };
    assert_eq!(xml::arbre(&texte, &petites), Err(ErreurXml::Demesure));
    assert!(xml::arbre(&"x".repeat(xml::XML_MAX + 1), &b).is_err());
    // Une valeur trop longue est coupée et comptée, une seule fois, même faite de mille références.
    let longue = format!(
        "<Event><Data>{}</Data><Data>court</Data></Event>",
        "&#x41;".repeat(40_000)
    );
    let a = xml::arbre(&longue, &b).unwrap();
    assert_eq!(a.chaines_tronquees, 1);
    assert_eq!(a.racine.enfants[0].texte.chars().count(), b.texte);
    assert_eq!(a.racine.enfants[1].texte, "court");
    // Une entité inconnue ne fait pas tomber l'événement : marquée U+FFFD. Aucune DTD n'est dépliée.
    let a = xml::arbre("<!DOCTYPE e [<!ENTITY x 'yyyy'>]><Event>&x;&#0;</Event>", &b).unwrap();
    assert_eq!(a.racine.texte, "\u{FFFD}\u{FFFD}");
    // Le numéro de secours : la première balise littérale, jamais une valeur échappée.
    assert_eq!(
        xml::numero_de_secours(
            "<Event><System><Provider Name='&lt;EventRecordID&gt;9'/><EventRecordID>42</EventRecordID>"
        ),
        Some(42)
    );
    assert_eq!(xml::numero_de_secours("<Event><EventRecordID>x</EventRecordID>"), None);
}

// ---- L'arbre d'un fichier réécrit en XML ----

/// Une valeur écrite comme Windows l'échappe, fins de ligne et tabulations telles quelles : la source vivante ne
/// les normalise pas (XML § 2.11 et 3.3.3), l'arbre doit revenir à l'identique.
fn echapper(v: &str, sortie: &mut String) {
    for c in v.chars() {
        match c {
            '&' => sortie.push_str("&amp;"),
            '<' => sortie.push_str("&lt;"),
            '>' => sortie.push_str("&gt;"),
            '\'' => sortie.push_str("&apos;"),
            '"' => sortie.push_str("&quot;"),
            c => sortie.push(c),
        }
    }
}

fn en_xml(n: &Noeud, sortie: &mut String) {
    let _ = write!(sortie, "<{}", n.nom);
    for (nom, v) in &n.attributs {
        let _ = write!(sortie, " {nom}=\"");
        echapper(v, sortie);
        sortie.push('"');
    }
    sortie.push('>');
    echapper(&n.texte, sortie);
    for e in &n.enfants {
        en_xml(e, sortie);
    }
    let _ = write!(sortie, "</{}>", n.nom);
}

/// Un caractère que XML 1.0 ne peut pas porter, même en référence : Windows ne le rend pas tel quel non plus.
fn hors_xml(n: &Noeud) -> bool {
    let mauvais = |t: &str| {
        t.chars()
            .any(|c| (c < ' ' && !matches!(c, '\t' | '\n' | '\r')) || c == '\u{FFFE}' || c == '\u{FFFF}')
    };
    mauvais(&n.texte) || n.attributs.iter().any(|(_, v)| mauvais(v)) || n.enfants.iter().any(hors_xml)
}

/// L'événement d'un fichier, et le même réécrit en XML puis relu par la source vivante : la même forme (hors son
/// origine). `None` : l'arbre porte un caractère que XML ne peut pas porter.
fn aller_retour(e: &evtx::Enregistrement) -> Option<(Option<EvenementWindows>, Option<EvenementWindows>)> {
    if hors_xml(&e.evenement) {
        return None;
    }
    let mut x = String::new();
    en_xml(&e.evenement, &mut x);
    let attendu = EvenementWindows::depuis(e.clone(), Origine::Vivant).map(|mut v| {
        // La source vivante ne connaît que l'EventRecordID de System, et la date de TimeCreated.
        v.numero = e.numero_systeme;
        v.date = e.cree;
        v.verifie = true;
        v
    });
    Some((attendu, du_xml(&x)))
}

#[test]
fn un_evenement_de_fichier_et_son_xml_donnent_la_meme_forme() {
    let f = evtx::tests::fichier(&[evtx::tests::morceau_type(1)]);
    let lu = evtx::lire_octets(&f, &Bornes::default()).unwrap();
    assert_eq!(lu.enregistrements.len(), 3);
    for e in &lu.enregistrements {
        let (a, b) = aller_retour(e).unwrap();
        assert!(a.is_some());
        assert_eq!(a, b);
    }
}

// ---- Les échantillons ----

/// Le XML de la crate evtx (un autre lecteur du même fichier) passé par notre source vivante : comparé à ce que
/// notre source fichiers tire du même enregistrement, sur ce que les deux rendent de la même façon (voir la lecture
/// croisée d'evtx::tests : champs vides ôtés, GUID, dates à la microseconde).
fn comparer_a_la_crate(
    octets: &[u8],
    nous: &BTreeMap<u64, EvenementWindows>,
    ecarts: &mut BTreeMap<&'static str, (usize, String)>,
) -> usize {
    let reglages = ::evtx::ParserSettings::new()
        .validate_checksums(true)
        .num_threads(1)
        .indent(false);
    let mut lecteur = ::evtx::EvtxParser::from_buffer(octets.to_vec())
        .unwrap()
        .with_configuration(reglages);
    let mut compares = 0;
    for r in lecteur.records().flatten() {
        let Some(a) = nous.get(&r.event_record_id) else {
            continue;
        };
        let Some(b) = du_xml(&r.data) else {
            ecarts.entry("illisible").or_insert((0, r.data.clone())).0 += 1;
            continue;
        };
        compares += 1;
        let mut ecart = |sorte: &'static str, d: String| ecarts.entry(sorte).or_insert((0, d)).0 += 1;
        if (a.id, &a.journal, &a.fournisseur, &a.ordinateur, a.niveau)
            != (b.id, &b.journal, &b.fournisseur, &b.ordinateur, b.niveau)
        {
            ecart("System", format!("{a:?} / {b:?}"));
        }
        if a.date.map(|d| d.timestamp_micros()) != b.date.map(|d| d.timestamp_micros()) {
            ecart("TimeCreated", format!("{:?} / {:?}", a.date, b.date));
        }
        if a.utilisateur != b.utilisateur {
            ecart("UserID", format!("{:?} / {:?}", a.utilisateur, b.utilisateur));
        }
        let pleins = |e: &EvenementWindows| -> Vec<(String, String)> {
            e.champs
                .iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(n, v)| (n.clone(), evtx::tests::forme_commune(v)))
                .collect()
        };
        // Seulement EventData : la crate rend UserData autrement (comme dans la lecture croisée du lecteur).
        if r.data.contains("<EventData") && pleins(a) != pleins(&b) {
            ecart("EventData", format!("{:?} / {:?}", pleins(a), pleins(&b)));
        }
    }
    compares
}

#[test]
fn les_echantillons_passent_par_la_forme_commune() {
    let Some(dossier) = std::env::var_os("VANGUARD_EVTX_ECHANTILLONS") else {
        return crate::essais::saute("VANGUARD_EVTX_ECHANTILLONS absente : pas d'échantillons .evtx");
    };
    let dossier = std::path::PathBuf::from(dossier);
    let mut evenements: BTreeMap<std::sync::Arc<std::path::Path>, BTreeMap<u64, EvenementWindows>> = BTreeMap::new();
    let bilan = fichiers::lire_dossier(&dossier, &Filtre::default(), &BornesFichiers::default(), |e| {
        if let Origine::Fichier { chemin, numero_fichier } = &e.origine {
            evenements.entry(chemin.clone()).or_default().insert(*numero_fichier, e);
        }
    })
    .unwrap();
    assert_ne!(bilan.fichiers.len(), 0);
    let (mut allers, mut sautes, mut compares) = (0usize, 0usize, 0usize);
    let mut ecarts = BTreeMap::new();
    let mut natures: BTreeMap<Nature, u64> = BTreeMap::new();
    for f in &bilan.fichiers {
        // Le bilan rendu est celui du lecteur, tel quel, et chaque enregistrement lu est donné ou compté.
        let lu = evtx::lire_fichier(&f.chemin, &Bornes::default()).unwrap();
        assert_eq!(f.lecture.as_ref().unwrap(), &lu.bilan, "{:?}", f.chemin);
        assert_eq!(
            f.donnes + f.sans_identifiant,
            lu.bilan.enregistrements_lus,
            "{:?}",
            f.chemin
        );
        assert_eq!(
            f.complet(),
            lu.bilan.complet() && f.sans_identifiant == 0,
            "{:?}",
            f.chemin
        );
        let nous = evenements.remove(&f.chemin).unwrap_or_default();
        assert_eq!(nous.len() as u64, f.donnes, "{:?}", f.chemin);
        // Chaque événement réécrit en XML puis relu : la même forme.
        for e in &lu.enregistrements {
            match aller_retour(e) {
                Some((a, b)) => {
                    assert_eq!(a, b, "{:?} n° {}", f.chemin, e.numero);
                    allers += 1;
                }
                None => sautes += 1,
            }
        }
        let par_numero_systeme: BTreeMap<u64, EvenementWindows> =
            nous.into_values().filter_map(|e| Some((e.numero?, e))).collect();
        compares += comparer_a_la_crate(&std::fs::read(&f.chemin).unwrap(), &par_numero_systeme, &mut ecarts);
        let nom = f.chemin.file_name().unwrap().to_string_lossy().into_owned();
        for s in &f.suites {
            for t in &s.trous {
                *natures.entry(t.nature).or_default() += 1;
            }
            eprintln!(
                "{nom} : {:?}, {}..{:?}, {} présents, {} doublons, trous {:?}",
                s.numerotation,
                s.premier.unwrap_or(0),
                s.dernier,
                s.presents,
                s.doublons,
                s.trous
                    .iter()
                    .take(4)
                    .map(|t| (t.de, t.a, t.nature))
                    .collect::<Vec<_>>()
            );
            // Windows écrit des en-têtes de morceaux qui se tiennent, et un prochain numéro qui suit le dernier.
            assert_eq!(s.incoherences, 0, "{nom}");
            // Les EventRecordID d'origine ne viennent que des fichiers exportés.
            assert!(matches!(s.numerotation, Numerotation::Journal) || f.exporte, "{nom}");
            // Aucun trou d'un fichier propre : ces échantillons publics ne sont pas trafiqués ; ceux des copies à
            // chaud et des morceaux écartés sont dits comme tels.
            assert!(
                s.trous
                    .iter()
                    .all(|t| !matches!(t.nature, Nature::Retires | Nature::Absents)),
                "{nom} : {:?}",
                s.trous
            );
        }
    }
    eprintln!(
        "aller-retour XML : {allers} (sautés, caractère hors XML : {sautes}) ; comparés à la crate : {compares} ; écarts {ecarts:?} ; trous par nature {natures:?}"
    );
    assert!(allers > 10_000 && compares > 10_000);
    assert!(ecarts.is_empty(), "{ecarts:?}");
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    /// Du XML au hasard ou presque : jamais de panique, les bornes tenues.
    #[test]
    fn un_xml_au_hasard_ne_fait_jamais_paniquer(
        morceaux in prop::collection::vec(prop_oneof![
            Just("<Event>".to_string()), Just("</Event>".to_string()), Just("<System>".to_string()),
            Just("</System>".to_string()), Just("<EventID>4625</EventID>".to_string()),
            Just("<EventRecordID>12</EventRecordID>".to_string()), Just("<Data Name='a'>".to_string()),
            Just("</Data>".to_string()), Just("<EventData>".to_string()), Just("</EventData>".to_string()),
            Just("&amp;".to_string()), Just("&#x0;".to_string()), Just("&bogus;".to_string()),
            Just("<![CDATA[x]]>".to_string()), Just("<?xml version='1.0'?>".to_string()),
            any::<String>(),
        ], 0..40),
    ) {
        let x = morceaux.concat();
        let petites = Bornes { noeuds: 16, profondeur: 4, texte: 8, texte_enregistrement: 64, ..Bornes::default() };
        if let Ok(a) = xml::arbre(&x, &petites) {
            let (mut noeuds, mut texte) = (0, 0);
            let mut pile = vec![&a.racine];
            let mut profondeur = vec![1usize];
            while let Some(n) = pile.pop() {
                let p = profondeur.pop().unwrap();
                prop_assert!(p <= petites.profondeur);
                noeuds += 1 + n.attributs.len();
                texte += n.texte.len() + n.attributs.iter().map(|(_, v)| v.len()).sum::<usize>();
                prop_assert!(n.texte.chars().count() <= petites.texte);
                for e in &n.enfants {
                    pile.push(e);
                    profondeur.push(p + 1);
                }
            }
            prop_assert!(noeuds <= petites.noeuds);
            prop_assert!(texte <= petites.texte_enregistrement);
        }
        let _ = du_xml(&x);
        let _ = xml::numero_de_secours(&x);
    }
}
