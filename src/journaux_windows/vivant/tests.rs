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

/// La fin d'une fenêtre arrondie à la milliseconde au-dessus : aucun événement qu'elle contient n'est écarté par
/// Windows sans être compté.
#[test]
fn la_fin_de_la_fenetre_n_ecarte_rien() {
    let d = DateTime::parse_from_rfc3339("2026-10-24T12:00:00.000900Z")
        .unwrap()
        .to_utc();
    assert_eq!(date_xpath(d, true), "2026-10-24T12:00:00.001Z");
    assert_eq!(date_xpath(d, false), "2026-10-24T12:00:00.000Z");
    let rond = DateTime::parse_from_rfc3339("2026-10-24T12:00:00.250Z")
        .unwrap()
        .to_utc();
    assert_eq!(date_xpath(rond, true), "2026-10-24T12:00:00.250Z");
}

/// Un journal de collecte garde les EventRecordID des ordinateurs d'origine : sa suite se juge par ordinateur. Un
/// poste renommé ou joint à un domaine change de nom dans son propre journal, sans que ses numéros se chevauchent.
#[test]
fn un_journal_de_collecte_se_reconnait() {
    assert!(!collecte("Security", vec![(1, 500)]));
    // « DESKTOP-ALICE » puis « DESKTOP-ALICE.salon.local » : une seule suite qui continue.
    assert!(!collecte("Security", vec![(501, 900), (1, 500)]));
    assert!(collecte("ForwardedEvents", vec![(1, 500)]));
    // Deux ordinateurs (ou deux journaux d'origine) dont les numéros se mêlent.
    assert!(collecte("Security", vec![(1, 500), (300, 800)]));
    assert!(collecte("Security", vec![(25_416, 25_416), (25_416, 40_825)]));
    let mut n = Numeros::default();
    for (o, c, x) in [
        ("pc", "System", 5),
        ("pc", "Application", 7),
        ("PC.maison.lan", "System", 6),
    ] {
        assert!(n.noter(
            o,
            c,
            Present {
                numero: x,
                date: None,
                morceau: None,
                verifie: true,
            }
        ));
    }
    assert_eq!(n.plages(), [(5, 5), (7, 7), (6, 6)]);
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
                assert_ne!(b.suites.len(), 0);
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

/// Un trou qui n'a pas pu être revérifié (ici, le journal refuse la revérification : il n'existe pas) n'est pas
/// rendu comme un constat : `Illisible`, et compté. Sans fenêtre de dates, il n'y a rien à revérifier.
#[test]
fn un_trou_non_reverifie_est_illisible() {
    let presents: Vec<Present> = (1..=5)
        .chain(10..=12)
        .chain(20..=22)
        .map(|numero| Present {
            numero,
            date: None,
            morceau: None,
            verifie: true,
        })
        .collect();
    let fin = Instant::now() + std::time::Duration::from_secs(10);
    let bornes = BornesVivant::default();
    let journal = "Vanguard-Essai/Inexistant";
    let (s, n) = juger_suite(journal, presents.clone(), &[], false, &bornes, fin);
    let plages = |s: &Suite| s.trous.iter().map(|t| (t.de, t.a, t.nature)).collect::<Vec<_>>();
    assert_eq!(
        (plages(&s), n),
        (vec![(6, 9, Nature::Absents), (13, 19, Nature::Absents)], 0)
    );
    let (s, n) = juger_suite(journal, presents.clone(), &[], true, &bornes, fin);
    assert_eq!(
        (plages(&s), n),
        (vec![(6, 9, Nature::Illisible), (13, 19, Nature::Illisible)], 2)
    );
    // Un événement lu sans son numéro peut être un numéro manquant, pas plus.
    let (s, _) = juger_suite(journal, presents, &[4], false, &bornes, fin);
    assert_eq!(plages(&s), [(6, 9, Nature::Illisible), (13, 19, Nature::Absents)]);
}
