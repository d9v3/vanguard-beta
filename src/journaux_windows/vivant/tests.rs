//! La source vivante : la requête bâtie depuis le filtre, les refus de Windows rendus distinctement, et la vraie
//! lecture (Wine ici, qui n'a pas de vrais journaux : un refus rendu proprement ; la VM ensuite).

use super::*;

/// Wine se reconnaît à sa clé de registre.
fn sous_wine() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"Software\Wine")
        .is_ok()
}

#[test]
fn la_requete_ne_porte_que_des_nombres_et_des_dates() {
    assert_eq!(requete(&Filtre::default()), ("*".to_string(), false));
    let depuis = DateTime::parse_from_rfc3339("2026-10-17T04:00:00Z").unwrap().to_utc();
    let jusqua = DateTime::parse_from_rfc3339("2026-10-24T03:59:59.5Z").unwrap().to_utc();
    let f = Filtre {
        journaux: vec!["Security".into()],
        ids: vec![4624, 4625],
        depuis: Some(depuis),
        jusqua: Some(jusqua),
    };
    assert_eq!(
        requete(&f),
        (
            "*[System[(EventID=4624 or EventID=4625) and TimeCreated[@SystemTime>='2026-10-17T04:00:00.000Z' and \
             @SystemTime<='2026-10-24T03:59:59.500Z']]]"
                .to_string(),
            true
        )
    );
    // Au-delà de seize numéros, le tri se fait ici : la requête reste sous les vingt expressions de Windows, et la
    // suite des numéros peut être jugée.
    let beaucoup = Filtre {
        ids: (1..=17).collect(),
        depuis: Some(depuis),
        ..Filtre::default()
    };
    let (r, ids) = requete(&beaucoup);
    assert!(!ids && !r.contains("EventID"), "{r}");
    let seize = Filtre {
        ids: (1..=16).collect(),
        depuis: Some(depuis),
        jusqua: Some(jusqua),
        ..Filtre::default()
    };
    let (r, ids) = requete(&seize);
    assert!(ids);
    assert!(
        r.matches("EventID=").count() + r.matches("@SystemTime").count() <= 20,
        "{r}"
    );
}

#[test]
fn les_refus_de_windows_sont_distincts() {
    assert_eq!(refus(Some(5)), RefusVivant::Droits);
    assert_eq!(refus(Some(15007)), RefusVivant::Absent);
    assert_eq!(refus(Some(2)), RefusVivant::Absent);
    assert_eq!(refus(Some(15001)), RefusVivant::Illisible(Some(15001)));
    assert_eq!(refus(None), RefusVivant::Illisible(None));
    // Un nom qui descendrait dans une autre clé du registre n'y est pas lu.
    assert_eq!(active(r"Security\..\..\Run"), None);
    assert_eq!(active(""), None);
}

/// Les vraies fonctions de Windows : rien ne plante ; un journal qui n'existe pas est refusé (absent sur un vrai
/// Windows), et le journal de sécurité lu ou refusé avec sa raison.
#[test]
fn les_journaux_de_cet_ordinateur_se_lisent_ou_se_refusent_proprement() {
    let fin = Instant::now() + std::time::Duration::from_secs(20);
    let bornes = BornesVivant {
        evenements: 500,
        ..BornesVivant::default()
    };
    let absent = lire_journal("Vanguard-Essai/Inexistant", &Filtre::default(), &bornes, fin, |_| {});
    match absent {
        Err(r) if !sous_wine() => assert_eq!(r, RefusVivant::Absent),
        Err(_) => {}
        Ok(b) => panic!("un journal inexistant a été lu : {b:?}"),
    }
    for journal in ["System", "Security"] {
        let mut vus = Vec::new();
        match lire_journal(journal, &Filtre::default(), &bornes, fin, |e| vus.push(e)) {
            Ok(b) => {
                assert_eq!(b.donnes, vus.len() as u64);
                assert!(vus.len() <= bornes.evenements);
                assert!(
                    vus.iter()
                        .all(|e| e.origine == Origine::Vivant && e.journal.eq_ignore_ascii_case(journal))
                );
                // Toute la requête lue sans numéro d'événement : la suite est jugée.
                assert!(b.suite.is_some());
                // La borne atteinte n'est jamais une lecture complète.
                assert!(!(b.borne_atteinte && b.complet()), "{b:?}");
            }
            Err(r) => {
                assert_eq!(vus.len(), 0);
                if sous_wine() {
                    return crate::essais::saute(&format!(
                        "Wine n'a pas de journaux d'événements : seul le refus de {journal} est vérifié ({r:?})"
                    ));
                }
                // Sur un vrai Windows, System se lit toujours ; Security, seulement en administrateur.
                assert_eq!((journal, r), ("Security", RefusVivant::Droits));
            }
        }
    }
}
