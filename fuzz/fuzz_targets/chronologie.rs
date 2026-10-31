//! Les lecteurs de journaux texte de la chronologie (syslog, journal de systemd, « last ») : un nom de compte essayé
//! par un robot, une commande passée à sudo y sont écrits tels quels. Ceux de Windows ne se compilent que pour
//! Windows : leurs tests de propriétés (proptest) les couvrent, sous Wine.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/traces.rs"]
mod traces;

use traces::{Bi, Manque, Partie, Raison, bi, champ, entete};

#[allow(dead_code)]
#[path = "../../src/traces/chronologie.rs"]
mod chronologie;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    let maintenant = chrono::NaiveDate::from_ymd_opt(2026, 10, 21)
        .unwrap()
        .and_hms_opt(10, 0, 0)
        .unwrap();
    let fuseau = chrono::FixedOffset::west_opt(4 * 3600).unwrap();
    let mut evenements = Vec::new();
    for l in texte.lines() {
        let _ = chronologie::quand_de_ligne(l, maintenant, &fuseau);
        evenements.extend(chronologie::lire_ligne_journal(l, maintenant, &fuseau));
    }
    let sessions = chronologie::lire_last(texte, maintenant, &fuseau);
    assert!(sessions.len() <= texte.lines().count());
    evenements.extend(sessions);
    let (gardes, _) = chronologie::borner(chronologie::garder(evenements, i64::MIN, i64::MAX), 100);
    for e in &gardes {
        let ligne = chronologie::ligne(e, &fuseau);
        assert!(!ligne.contains('\n') && ligne.split('\t').count() == 4, "{ligne:?}");
    }
});
