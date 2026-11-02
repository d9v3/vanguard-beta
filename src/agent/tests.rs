//! Les essais du socle de l'agent : gardes sur le source, tour (verrou, jeu, lecture seule, interrupteurs), genre de
//! chaque décision, sens sûr, journal.

use std::time::Duration;

use proptest::prelude::*;

use super::decision::{Proposition, Signal};
use super::forme::RegleId;
use super::journal::Fait;
use super::*;
use crate::essais::Jetable;

/// Le code d'un fichier sans ses essais ni ses commentaires.
fn code_sans_essais(source: &str) -> String {
    source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source)
        .lines()
        .map(|l| l.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Chaque fichier de `src/agent/` (sauf ces essais) : chemin relatif et code sans essais ni commentaires.
fn sources_de_l_agent() -> Vec<(String, String)> {
    let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/agent");
    let mut tous = Vec::new();
    let mut a_voir = vec![racine.clone()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                a_voir.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") && p.file_name().is_some_and(|n| n != "tests.rs") {
                let rel = p.strip_prefix(&racine).unwrap().to_string_lossy().replace('\\', "/");
                tous.push((rel, code_sans_essais(&std::fs::read_to_string(&p).unwrap())));
            }
        }
    }
    assert!(tous.len() >= 7, "{tous:?}");
    tous
}

fn mot(code: &str, m: &str) -> bool {
    code.match_indices(m).any(|(i, _)| {
        let avant = code[..i].chars().next_back();
        let apres = code[i + m.len()..].chars().next();
        !avant.is_some_and(|c| c.is_alphanumeric() || c == '_')
            && !apres.is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// L'agent ne nomme ni commande, ni réseau, ni élévation, ni correction, ni blocage, ni envoi ; aucun texte libre
/// (`String`) dans ses types ; ses missions de réglage ne nomment rien de la détection ; ses missions ne font que
/// lire.
#[test]
fn gardes_sur_le_source() {
    for (fichier, code) in sources_de_l_agent() {
        // Le seul `unsafe` permis : celui qui le refuse.
        let code = code.replace("#![forbid(unsafe_code)]", "");
        for interdit in [
            "std::process",
            "process::",
            "Command",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "crate::http",
            "crate::commande",
            "crate::corriger",
            "machine::appliquer",
            "blocage",
            "envoi",
            "sudo",
            "pkexec",
            "runas",
            "unsafe",
        ] {
            assert!(!code.contains(interdit), "agent/{fichier} nomme « {interdit} »");
        }
        assert!(!mot(&code, "String"), "agent/{fichier} : un texte libre (String)");
        if fichier.starts_with("missions/") {
            for interdit in [
                "ecrire",
                "write",
                "remove",
                "rename",
                "OpenOptions",
                "create_dir",
                "oublier",
                "ajuster",
                "set_permissions",
            ] {
                assert!(!code.contains(interdit), "agent/{fichier} écrit (« {interdit} »)");
            }
        }
        if fichier == "missions/reglage.rs" || fichier == "missions/cache.rs" {
            for interdit in ["risk", "Niveau"] {
                assert!(!code.contains(interdit), "agent/{fichier} nomme « {interdit} »");
            }
        }
    }
}

#[test]
fn la_garde_voit_un_mot() {
    assert!(mot("type Obs = String;", "String"));
    assert!(!mot("type Obs = Chaine; // StringX", "String"));
    assert!(!mot("MaString", "String"));
}

/// Une mission d'essai : son genre, son id, ses moments, et les décisions qu'elle rend telles quelles.
struct Essai {
    id: MissionId,
    genre: Genre,
    moments: &'static [Moment],
    decisions: Vec<Decision>,
}

impl Mission for Essai {
    type Obs = ();
    type Etat = Compteurs;
    fn id(&self) -> MissionId {
        self.id
    }
    fn genre(&self) -> Genre {
        self.genre
    }
    fn moments(&self) -> &'static [Moment] {
        self.moments
    }
    fn budget(&self) -> Budget {
        Budget::new(4, 8, Duration::from_secs(60))
    }
    fn observer(&self, _lu: &Lecture<'_>, b: &mut Budget) -> Result<(), Arret> {
        b.lire()
    }
    fn juger(&self, _obs: &(), etat: &Compteurs) -> (Vec<Decision>, Compteurs) {
        (self.decisions.clone(), etat.apres(super::etat::JOUR_MIN + 10, 0))
    }
}

const FIN: &[Moment] = &[Moment::FinDeBilan];

fn r(id: &str) -> RegleId {
    RegleId::depuis(id).unwrap()
}

fn du_code(id: &str) -> Option<Duration> {
    (id == "LNX-TST-010").then_some(DELAI)
}

/// Un délai dans le sens sûr pour LNX-TST-010.
fn monte() -> Decision {
    Decision::Ajuster(Ajustement {
        levier: Levier::Delai {
            regle: r("LNX-TST-010"),
            avant_s: DELAI.as_secs(),
            apres_s: DELAI_LONG.as_secs(),
        },
        mesure: 400_000,
    })
}

fn mesures() -> &'static crate::autotest::mesures::Mesures {
    Box::leak(Box::default())
}

fn contexte(dossier: &Path) -> Contexte<'_> {
    Contexte {
        lecture: Lecture {
            dossier,
            aujourd_hui: chrono::NaiveDate::from_ymd_opt(2026, 11, 2).unwrap(),
            mesures: mesures(),
            delai_du_code: &du_code,
        },
        quand: 1_793_577_600,
        en_jeu: false,
        en_marche: Some(true),
    }
}

/// Le faux applicateur : applique tout ce qu'on lui donne, et le garde pour l'essai.
fn tout_appliquer(_lu: &Lecture<'_>, a: &[(MissionId, Ajustement)]) -> Vec<(MissionId, Ajustement)> {
    a.to_vec()
}

fn journal_de(d: &Path) -> Vec<Fait> {
    match crate::sceau::juge_dans(d, journal::JOURNAL) {
        crate::sceau::Juge::Cru(o) => {
            let j = journal::lire_de(&o, empreinte);
            assert!(j.intact());
            j.entrees.into_iter().map(|e| e.fait).collect()
        }
        crate::sceau::Juge::Absent => Vec::new(),
        autre => panic!("{autre:?}"),
    }
}

/// Une décision hors du genre, d'un levier qui n'est pas celui de la mission ou hors du sens sûr : refusée, notée
/// comme refus, jamais appliquée. Le reste passe et se note.
#[test]
fn chaque_decision_verifiee() {
    let d = Jetable::nouveau("agent-verifiee");
    let baisse = Decision::Ajuster(Ajustement {
        levier: Levier::Delai {
            regle: r("LNX-TST-010"),
            avant_s: DELAI_LONG.as_secs(),
            apres_s: DELAI.as_secs(),
        },
        mesure: 1,
    });
    let reglage = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![
            monte(),
            baisse,
            Decision::Signaler(Signal::Nouveaute {
                regle: r("LNX-TST-010"),
            }),
            Decision::Proposer(Proposition::RevoirRegle {
                regle: r("LNX-TST-010"),
            }),
        ],
    };
    // La mission de la cache n'a pas le levier des délais.
    let cache = Essai {
        id: MissionId::Cache,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&reglage, &cache], &tout_appliquer);
    assert_eq!(
        t,
        Tour::Fait {
            appliquees: 1,
            montrees: 1,
            refusees: 3
        }
    );
    let faits = journal_de(&d);
    assert_eq!(faits.iter().filter(|f| matches!(f, Fait::Refus { .. })).count(), 3);
    assert!(faits.contains(&Fait::Decision {
        mission: MissionId::Reglage,
        decision: monte()
    }));
    // L'état de la mission est écrit, scellé, dans ses bornes.
    assert!(matches!(
        etat::lire_dans::<Compteurs>(&d, etat::ETAT_REGLAGE),
        etat::Lu::Cru(c) if c.tours == 1
    ));
}

/// Jamais d'attente : le verrou tenu, un jeu, la lecture seule sautent le tour ; l'interrupteur à « non » le coupe ;
/// un moment que personne n'écoute ne fait rien.
#[test]
fn tour_saute_sans_attendre() {
    let d = Jetable::nouveau("agent-saute");
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    let tourner = |ctx: &Contexte<'_>, moment| tic_dans(ctx, moment, &[&m], &tout_appliquer);
    assert_eq!(
        tourner(&contexte(&d), Moment::PasseHoraire),
        Tour::Saute(Saut::PersonneNEcoute)
    );
    let verrou = crate::socle::Verrou::prendre(&d, "agent.lock", false, Duration::ZERO).unwrap();
    let debut = std::time::Instant::now();
    assert_eq!(tourner(&contexte(&d), Moment::FinDeBilan), Tour::Saute(Saut::Occupe));
    assert!(debut.elapsed() < Duration::from_secs(5));
    drop(verrou);
    let en_jeu = Contexte {
        en_jeu: true,
        ..contexte(&d)
    };
    assert_eq!(tourner(&en_jeu, Moment::FinDeBilan), Tour::Saute(Saut::EnJeu));
    let coupe = Contexte {
        en_marche: Some(false),
        ..contexte(&d)
    };
    assert_eq!(tourner(&coupe, Moment::FinDeBilan), Tour::Coupe);
    // Interrupteur douteux : un réglage ne tourne pas.
    let douteux = Contexte {
        en_marche: None,
        ..contexte(&d)
    };
    assert_eq!(
        tourner(&douteux, Moment::FinDeBilan),
        Tour::Fait {
            appliquees: 0,
            montrees: 0,
            refusees: 0
        }
    );
    crate::autotest::lecture_seule::poser();
    let lecture_seule = tourner(&contexte(&d), Moment::FinDeBilan);
    crate::autotest::lecture_seule::relever_pour_le_test();
    assert_eq!(lecture_seule, Tour::Saute(Saut::LectureSeule));
    // Rien n'a été écrit par tous ces tours sautés.
    assert_eq!(journal_de(&d), Vec::new());
}

/// Une mission coupée dans `agent/agent.json` ne tourne pas ; un journal douteux fait sauter le tour.
#[test]
fn interrupteur_de_mission_et_journal_douteux() {
    let d = Jetable::nouveau("agent-interrupteurs");
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    let i = etat::Interrupteurs {
        v: 1,
        coupees: [MissionId::Reglage].into(),
    };
    etat::ecrire_dans(&d, etat::AGENT, &i).unwrap();
    let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    assert_eq!(
        t,
        Tour::Fait {
            appliquees: 0,
            montrees: 0,
            refusees: 0
        }
    );
    etat::ecrire_dans(&d, etat::AGENT, &etat::Interrupteurs::default()).unwrap();
    // Le journal changé hors de Vanguard : douteux, tour sauté, rien n'est appliqué.
    std::fs::create_dir_all(d.join("agent")).unwrap();
    std::fs::write(d.join(journal::JOURNAL), b"{}\n").unwrap();
    let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    assert_eq!(t, Tour::Saute(Saut::JournalDouteux));
}

/// « Tout remettre » : états et interrupteurs d'origine, noté au journal.
#[test]
fn tout_remettre_note() {
    let d = Jetable::nouveau("agent-remettre");
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    tout_remettre_dans(&d, 1_793_577_700).unwrap();
    assert_eq!(
        etat::lire_dans::<Compteurs>(&d, etat::ETAT_REGLAGE),
        etat::Lu::Cru(etat::Borne::borne(Compteurs::default()))
    );
    assert_eq!(journal_de(&d).last(), Some(&Fait::ToutRemis));
}

fn levier() -> impl Strategy<Value = Levier> {
    let regle = prop_oneof![
        Just("LNX-TST-010"),
        Just("LNX-MAJ-010"),
        Just("WIN-MAJ-004"),
        Just("LNX-SEC-002")
    ]
    .prop_map(r);
    prop_oneof![
        (regle.clone(), any::<u64>(), any::<u64>()).prop_map(|(regle, avant_s, apres_s)| Levier::Delai {
            regle,
            avant_s,
            apres_s
        }),
        (regle, any::<u16>(), any::<u16>()).prop_map(|(regle, avant_min, apres_min)| Levier::Cache {
            regle,
            avant_min,
            apres_min
        }),
    ]
}

fn decision() -> impl Strategy<Value = Decision> {
    let regle = Just(r("LNX-TST-010"));
    prop_oneof![
        (levier(), any::<u64>()).prop_map(|(levier, mesure)| Decision::Ajuster(Ajustement { levier, mesure })),
        regle.prop_map(|regle| Decision::Proposer(Proposition::RevoirRegle { regle })),
        regle.prop_map(|regle| Decision::Signaler(Signal::Nouveaute { regle })),
    ]
}

fn genre() -> impl Strategy<Value = Genre> {
    prop_oneof![Just(Genre::Reglage), Just(Genre::Releve), Just(Genre::Detection)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Toute décision appliquée ou montrée appartient au genre de sa mission, est d'un levier à elle et dans le sens
    /// sûr ; le reste est refusé, et le compte tombe juste.
    #[test]
    fn toute_decision_appartient_au_genre(
        g1 in genre(), g2 in genre(),
        d1 in proptest::collection::vec(decision(), 0..6),
        d2 in proptest::collection::vec(decision(), 0..6),
    ) {
        let d = Jetable::nouveau("agent-genre");
        let a = Essai { id: MissionId::Reglage, genre: g1, moments: FIN, decisions: d1.clone() };
        let b = Essai { id: MissionId::Cache, genre: g2, moments: FIN, decisions: d2.clone() };
        let recus = std::cell::RefCell::new(Vec::new());
        let appliquer = |lu: &Lecture<'_>, x: &[(MissionId, Ajustement)]| {
            for (id, a) in x {
                assert!(decision::levier_de(*id, &a.levier) && sens_sur(lu, &a.levier));
            }
            recus.borrow_mut().extend_from_slice(x);
            x.to_vec()
        };
        let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&a, &b], &appliquer);
        let ctx = contexte(&d);
        let mut attendu = (0, 0, 0);
        for (m, ds) in [(&a as &dyn Tourne, &d1), (&b, &d2)] {
            // Un réglage à l'interrupteur « oui » tourne ; un relevé ou une détection aussi (interrupteurs absents).
            for x in ds {
                match (verifiee(&ctx.lecture, m, x), x) {
                    (false, _) => attendu.2 += 1,
                    (true, Decision::Ajuster(_)) => {
                        prop_assert_eq!(m.genre(), Genre::Reglage);
                        attendu.0 += 1;
                    }
                    (true, _) => {
                        prop_assert!(m.genre() != Genre::Releve);
                        attendu.1 += 1;
                    }
                }
            }
        }
        prop_assert_eq!(t, Tour::Fait { appliquees: attendu.0, montrees: attendu.1, refusees: attendu.2 });
        prop_assert_eq!(recus.borrow().len(), attendu.0);
        for f in journal_de(&d) {
            if let Fait::Decision { mission, decision } = f {
                let g = if mission == MissionId::Reglage { g1 } else { g2 };
                prop_assert!(decision::permise(g, &decision));
            }
        }
    }
}

// Lot G2 : les missions de l'auto-réglage (L6, L6c) branchées sur le tour.

/// Les missions : celles de `MissionId::TOUTES`, dans cet ordre ; deux réglages de fin de bilan.
#[test]
fn les_missions_dans_l_ordre() {
    let ids: Vec<MissionId> = missions().iter().map(|m| m.id()).collect();
    assert_eq!(ids, MissionId::TOUTES);
    for m in missions() {
        assert_eq!(m.genre(), Genre::Reglage);
        assert_eq!(m.moments(), FIN);
    }
}

fn jour(j: u32) -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(2026, 11, j).unwrap()
}

/// LNX-TST-010 a pris 9 minutes (plus de la moitié de `DELAI`) chacun de ces jours.
fn frole_le(jours: &[chrono::NaiveDate]) -> crate::autotest::mesures::Mesures {
    let mut m = crate::autotest::mesures::Mesures::default();
    for j in jours {
        m.ajouter(&[("LNX-TST-010", Duration::from_mins(9))], *j);
    }
    m
}

fn contexte_au<'a>(
    dossier: &'a Path,
    aujourd_hui: chrono::NaiveDate,
    mesures: &'a crate::autotest::mesures::Mesures,
    en_marche: Option<bool>,
) -> Contexte<'a> {
    Contexte {
        lecture: Lecture {
            dossier,
            aujourd_hui,
            mesures,
            delai_du_code: &du_code,
        },
        quand: aujourd_hui.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp(),
        en_jeu: false,
        en_marche,
    }
}

fn reglage_de(d: &Path) -> crate::autotest::reglage::Etat {
    match crate::autotest::reglage::lire_dans(d) {
        crate::autotest::reglage::Lu::Cru(e) => e,
        autre => panic!("réglage {autre:?}"),
    }
}

/// De bout en bout, avec les vraies missions et le vrai applicateur : le suivi s'écrit sans ajustement ; mission
/// coupée, la montée attend et son suivi reste ; remise en marche, le délai monte, une fois, noté au journal. Agent
/// coupé : rien.
#[test]
fn l_agent_monte_un_delai_de_bout_en_bout() {
    let d = Jetable::nouveau("agent-g2-monte");
    let m0 = frole_le(&[jour(2)]);
    let t = tic_dans(
        &contexte_au(&d, jour(2), &m0, Some(true)),
        Moment::FinDeBilan,
        &missions(),
        &appliquer,
    );
    assert_eq!(
        t,
        Tour::Fait {
            appliquees: 0,
            montrees: 0,
            refusees: 0
        }
    );
    let e = reglage_de(&d);
    assert_eq!(
        e.frolent_depuis.get("LNX-TST-010").map(String::as_str),
        Some("2026-11-02")
    );
    assert_eq!(e.montees, []);

    let coupee = etat::Interrupteurs {
        v: 1,
        coupees: [MissionId::Reglage].into(),
    };
    etat::ecrire_dans(&d, etat::AGENT, &coupee).unwrap();
    let m9 = frole_le(&[jour(2), jour(9)]);
    let ctx = contexte_au(&d, jour(9), &m9, Some(true));
    assert_eq!(
        tic_dans(&ctx, Moment::FinDeBilan, &missions(), &appliquer),
        Tour::Fait {
            appliquees: 0,
            montrees: 0,
            refusees: 0
        }
    );
    let e = reglage_de(&d);
    assert_eq!(e.montees, []);
    assert_eq!(
        e.frolent_depuis.get("LNX-TST-010").map(String::as_str),
        Some("2026-11-02")
    );

    etat::ecrire_dans(&d, etat::AGENT, &etat::Interrupteurs::default()).unwrap();
    assert_eq!(
        tic_dans(&ctx, Moment::FinDeBilan, &missions(), &appliquer),
        Tour::Fait {
            appliquees: 1,
            montrees: 0,
            refusees: 0
        }
    );
    assert_eq!(
        crate::autotest::reglage::lire_dans(&d).delais_longs(),
        std::collections::BTreeSet::from(["LNX-TST-010".to_string()])
    );
    assert_eq!(
        journal_de(&d).last(),
        Some(&Fait::Decision {
            mission: MissionId::Reglage,
            decision: monte_de(540_000),
        })
    );
    // Une fois : la passe suivante n'ajoute rien.
    assert!(matches!(
        tic_dans(&ctx, Moment::FinDeBilan, &missions(), &appliquer),
        Tour::Fait { appliquees: 0, .. }
    ));

    // L'agent coupé (l'interrupteur de l'auto-réglage à « non ») : rien ne s'écrit.
    let sans = Jetable::nouveau("agent-g2-coupe");
    for (j, m) in [(jour(2), &m0), (jour(9), &m9)] {
        let t = tic_dans(
            &contexte_au(&sans, j, m, Some(false)),
            Moment::FinDeBilan,
            &missions(),
            &appliquer,
        );
        assert_eq!(t, Tour::Coupe);
    }
    assert_eq!(
        crate::autotest::reglage::lire_dans(&sans),
        crate::autotest::reglage::Lu::Absent
    );
}

/// `monte()`, avec cette mesure.
fn monte_de(mesure: u64) -> Decision {
    match monte() {
        Decision::Ajuster(a) => Decision::Ajuster(Ajustement { mesure, ..a }),
        autre => autre,
    }
}

/// Trois règles d'essai, rapides : une grave, une saine, une moyenne (deux constats).
fn regles_d_essai() -> &'static [&'static crate::machine::regles::Regle] {
    use crate::machine::regles::{Os, Regle};
    use crate::risk::Niveau;
    static REGLES: std::sync::OnceLock<Vec<&'static Regle>> = std::sync::OnceLock::new();
    REGLES.get_or_init(|| {
        let regle = |id: &'static str, verifier: fn() -> Vec<crate::machine::Constat>| -> &'static Regle {
            Box::leak(Box::new(Regle {
                id,
                systeme: Os::actuel(),
                rang: 1,
                sujet: ("essai", "test"),
                references: &[],
                verifier,
            }))
        };
        vec![
            regle("LNX-TST-010", || {
                vec![crate::machine::alerte("Audit", Niveau::Eleve, "grave")]
            }),
            regle("LNX-TST-011", || vec![crate::machine::ok("Audit", "sain")]),
            regle("LNX-TST-012", || {
                vec![
                    crate::machine::alerte("Audit", Niveau::Moyen, "moyen"),
                    crate::machine::ok("Audit", "sain"),
                ]
            }),
        ]
    })
}

/// Un bilan demandé par la personne (aucune reprise de la cache), avec ce départ et ces délais montés.
fn bilan_d_essai(
    depart: Vec<usize>,
    longs: &std::collections::BTreeSet<String>,
) -> Vec<(&'static str, Option<crate::risk::Niveau>, String)> {
    let (constats, _) = crate::machine::regles_lancees(regles_d_essai().to_vec(), &|_| None, depart, longs);
    constats.into_iter().map(|c| (c.regle, c.probleme, c.message)).collect()
}

fn problemes(
    b: &[(&'static str, Option<crate::risk::Niveau>, String)],
) -> Vec<(&'static str, crate::risk::Niveau, String)> {
    b.iter().filter_map(|(r, n, m)| n.map(|n| (*r, n, m.clone()))).collect()
}

/// Différentiel : le même bilan fabriqué, avec ce que l'agent en marche a changé (le délai monté de LNX-TST-010)
/// puis agent coupé (rien de changé) : chaque problème de l'un est dans l'autre, au même niveau.
#[test]
fn bilan_avec_l_agent_contient_celui_sans() {
    let avec = Jetable::nouveau("agent-g2-avec");
    let sans = Jetable::nouveau("agent-g2-sans");
    let m0 = frole_le(&[jour(2)]);
    let m9 = frole_le(&[jour(2), jour(9)]);
    for (d, en_marche) in [(&avec, true), (&sans, false)] {
        for (j, m) in [(jour(2), &m0), (jour(9), &m9)] {
            tic_dans(
                &contexte_au(d, j, m, Some(en_marche)),
                Moment::FinDeBilan,
                &missions(),
                &appliquer,
            );
        }
    }
    let longs_avec = crate::autotest::reglage::lire_dans(&avec).delais_longs();
    let longs_sans = crate::autotest::reglage::lire_dans(&sans).delais_longs();
    assert_eq!(longs_avec.len(), 1);
    assert!(longs_sans.is_empty());
    let b_avec = problemes(&bilan_d_essai(vec![0, 1, 2], &longs_avec));
    let b_sans = problemes(&bilan_d_essai(vec![0, 1, 2], &longs_sans));
    assert_eq!(b_sans.len(), 2);
    for p in &b_sans {
        assert!(b_avec.contains(p), "{p:?} perdu avec l'agent");
    }
    assert_eq!(b_avec, b_sans);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, failure_persistence: None, ..ProptestConfig::default() })]

    /// Un bilan lancé par la personne lance toutes les règles, chacune une fois, rendues dans l'ordre des rangs,
    /// quels que soient l'ordre de départ et les délais montés ; ses problèmes restent ceux des délais du code.
    #[test]
    fn bilan_manuel_lance_toutes_les_regles(
        depart in prop::collection::vec(0usize..6, 0..6),
        montes in prop::collection::vec(any::<bool>(), 3),
    ) {
        let longs: std::collections::BTreeSet<String> = regles_d_essai()
            .iter()
            .zip(&montes)
            .filter(|(_, m)| **m)
            .map(|(r, _)| r.id.to_string())
            .collect();
        let b = bilan_d_essai(depart, &longs);
        let regles: Vec<&str> = b.iter().map(|(r, _, _)| *r).collect();
        prop_assert_eq!(regles, ["LNX-TST-010", "LNX-TST-011", "LNX-TST-012", "LNX-TST-012"]);
        prop_assert_eq!(problemes(&b), problemes(&bilan_d_essai(vec![], &std::collections::BTreeSet::new())));
    }
}
