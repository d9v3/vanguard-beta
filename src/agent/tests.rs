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
        if ["missions/reglage.rs", "missions/cache.rs", "missions/corrections.rs"].contains(&fichier.as_str()) {
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
            bilan: None,
            corrections: &[],
        },
        quand: 1_793_577_600,
        en_jeu: false,
        en_marche: Some(true),
        relever: &|_, _| {},
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
    tout_remettre_dans(&d, 1_793_577_700, &geste_dans(&d).unwrap()).unwrap();
    assert_eq!(
        etat::lire_dans::<Compteurs>(&d, etat::ETAT_REGLAGE),
        etat::Lu::Cru(etat::Borne::borne(Compteurs::default()))
    );
    // Un journal neuf, dont « tout remettre » est la première ligne.
    assert_eq!(journal_de(&d), [Fait::ToutRemis]);
}

/// Un journal douteux (changé hors de Vanguard) ou scellé mais rompu (une ligne retirée au milieu) fait sauter le
/// tour ; « tout remettre » repart d'un journal neuf, et l'agent tourne de nouveau.
#[test]
fn journal_douteux_ou_rompu_puis_tout_remettre() {
    let d = Jetable::nouveau("agent-journal-rompu");
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    let o = journal::ajouter(Vec::new(), &[Fait::ToutRemis; 3], 1_793_577_600, empreinte);
    let lignes: Vec<&[u8]> = o.split(|&c| c == b'\n').filter(|l| !l.is_empty()).collect();
    let rompu = [lignes[0], lignes[2], b""].join(&b'\n');
    assert!(journal::lire_de(&rompu, empreinte).rompue.is_some());
    crate::sceau::ecrire_dans(&d, journal::JOURNAL, &rompu).unwrap();
    let tourner = || tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    assert_eq!(tourner(), Tour::Saute(Saut::JournalDouteux));
    tout_remettre_dans(&d, 1_793_577_700, &geste_dans(&d).unwrap()).unwrap();
    assert_eq!(journal_de(&d), [Fait::ToutRemis]);
    // Un octet ajouté hors de Vanguard : douteux pour le sceau, même issue.
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(d.join(journal::JOURNAL))
        .unwrap();
    std::io::Write::write_all(&mut f, b" ").unwrap();
    drop(f);
    assert_eq!(tourner(), Tour::Saute(Saut::JournalDouteux));
    tout_remettre_dans(&d, 1_793_577_800, &geste_dans(&d).unwrap()).unwrap();
    assert_eq!(journal_de(&d), [Fait::ToutRemis]);
    assert!(matches!(tourner(), Tour::Fait { appliquees: 1, .. }));
}

/// Un geste de Paramètres pendant un tour (ici, depuis l'application même) attend le verrou de l'agent, puis échoue
/// et le dit : rien ne se perd au milieu d'un tour. Hors d'un tour, il passe.
#[test]
fn un_geste_attend_la_fin_du_tour() {
    let d = Jetable::nouveau("agent-geste");
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![monte()],
    };
    let geste_pendant = std::cell::Cell::new(true);
    let appliquer_pendant_un_geste = |lu: &Lecture<'_>, a: &[(MissionId, Ajustement)]| {
        geste_pendant.set(geste_dans(lu.dossier).is_ok());
        a.to_vec()
    };
    let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &appliquer_pendant_un_geste);
    assert_eq!(
        t,
        Tour::Fait {
            appliquees: 1,
            montrees: 0,
            refusees: 0
        }
    );
    assert!(!geste_pendant.get());
    tout_remettre_dans(&d, 1_793_577_700, &geste_dans(&d).unwrap()).unwrap();
    assert_eq!(journal_de(&d), [Fait::ToutRemis]);
    assert_eq!(
        etat::lire_dans::<Compteurs>(&d, etat::ETAT_REGLAGE),
        etat::Lu::Cru(etat::Borne::borne(Compteurs::default()))
    );
}

/// Une mission qui respecte le compte du jour, comme les vraies (`missions::juger_prevus`).
struct Plafonnee(Vec<Decision>);

impl Mission for Plafonnee {
    type Obs = ();
    type Etat = Compteurs;
    fn id(&self) -> MissionId {
        MissionId::Reglage
    }
    fn genre(&self) -> Genre {
        Genre::Reglage
    }
    fn moments(&self) -> &'static [Moment] {
        FIN
    }
    fn budget(&self) -> Budget {
        Budget::new(4, 8, Duration::from_secs(60))
    }
    fn observer(&self, _lu: &Lecture<'_>, b: &mut Budget) -> Result<(), Arret> {
        b.lire()
    }
    fn juger(&self, _obs: &(), etat: &Compteurs) -> (Vec<Decision>, Compteurs) {
        let j = etat::JOUR_MIN + 10;
        let d: Vec<Decision> = self.0.iter().copied().take(usize::from(etat.restants(j))).collect();
        let n = u16::try_from(d.len()).unwrap();
        (d, etat.apres(j, n))
    }
}

/// Le plafond du jour tient sur des tours répétés ; l'état de la mission qui ne s'écrit plus (dossier en lecture
/// seule), elle n'agit plus du tout, au lieu de repartir de zéro à chaque tour.
#[test]
fn le_plafond_du_jour_tient_meme_sans_etat_ecrit() {
    let d = Jetable::nouveau("agent-plafond");
    let m = Plafonnee(vec![monte(); 8]);
    let tourner = || match tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer) {
        Tour::Fait { appliquees, .. } => appliquees,
        autre => panic!("{autre:?}"),
    };
    assert_eq!(
        (0..5).map(|_| tourner()).sum::<usize>(),
        usize::from(etat::PAR_JOUR_MAX)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let e = Jetable::nouveau("agent-plafond-lecture-seule");
        let m = Plafonnee(vec![monte(); 8]);
        let tourner = || tic_dans(&contexte(&e), Moment::FinDeBilan, &[&m], &tout_appliquer);
        assert!(matches!(tourner(), Tour::Fait { appliquees: 8, .. }));
        let etats = e.join("agent/etat");
        std::fs::set_permissions(&etats, std::fs::Permissions::from_mode(0o500)).unwrap();
        let ecrivable = std::fs::write(etats.join("essai"), b"").is_ok();
        let apres: Vec<Tour> = (0..3).map(|_| tourner()).collect();
        std::fs::set_permissions(&etats, std::fs::Permissions::from_mode(0o700)).unwrap();
        if ecrivable {
            return crate::essais::saute("administrateur : un dossier en lecture seule s'écrit quand même");
        }
        let rien = Tour::Fait {
            appliquees: 0,
            montrees: 0,
            refusees: 0,
        };
        assert_eq!(apres, [rien; 3]);
    }
}

/// Au plus 8 décisions par tour et par mission (son budget), même si elle en rend davantage.
#[test]
fn au_plus_huit_decisions_par_tour() {
    let d = Jetable::nouveau("agent-huit");
    let signal = Decision::Signaler(Signal::Nouveaute {
        regle: r("LNX-TST-010"),
    });
    let m = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: [vec![monte(); 12], vec![signal; 12]].concat(),
    };
    let t = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    assert_eq!(
        t,
        Tour::Fait {
            appliquees: 8,
            montrees: 0,
            refusees: 0
        }
    );
    assert_eq!(journal_de(&d).len(), 8);
}

/// Au niveau du tour, une durée de cache hors du sens sûr est refusée : règle hors de `cache::TABLE`, sous le
/// plancher, d'un pas qui n'est pas `PAS_MIN`, au-dessus de la durée du code ou qui monte. Seul le pas sûr passe.
#[test]
fn une_cache_hors_du_sens_sur_est_refusee() {
    use crate::autotest::cache::{PAS_MIN, TABLE};
    let d = Jetable::nouveau("agent-cache-bornes");
    let t = &TABLE[0];
    let cache = |regle: &str, avant_min: u16, apres_min: u16| {
        Decision::Ajuster(Ajustement {
            levier: Levier::Cache {
                regle: r(regle),
                avant_min,
                apres_min,
            },
            mesure: 1,
        })
    };
    let sure = cache(t.regle, t.duree_min, t.duree_min - PAS_MIN);
    let m = Essai {
        id: MissionId::Cache,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![
            cache("LNX-TST-010", 90, 90 - PAS_MIN),
            cache(t.regle, t.plancher_min, t.plancher_min - PAS_MIN),
            cache(t.regle, t.duree_min, t.duree_min - 2 * PAS_MIN),
            cache(t.regle, t.duree_min + PAS_MIN, t.duree_min),
            cache(t.regle, t.duree_min - PAS_MIN, t.duree_min),
            sure,
        ],
    };
    let tour = tic_dans(&contexte(&d), Moment::FinDeBilan, &[&m], &tout_appliquer);
    assert_eq!(
        tour,
        Tour::Fait {
            appliquees: 1,
            montrees: 0,
            refusees: 5
        }
    );
    assert!(journal_de(&d).contains(&Fait::Decision {
        mission: MissionId::Cache,
        decision: sure
    }));
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
        (regle.clone(), any::<u16>(), any::<u16>()).prop_map(|(regle, avant_min, apres_min)| Levier::Cache {
            regle,
            avant_min,
            apres_min
        }),
        (regle.clone(), any::<u16>(), any::<u16>()).prop_map(|(regle, avant_min, apres_min)| {
            Levier::CacheRallonge {
                regle,
                avant_min,
                apres_min,
            }
        }),
        regle.clone().prop_map(|regle| Levier::CacheCoupee { regle }),
        (regle, any::<u16>(), any::<u16>()).prop_map(|(regle, passageres, reprises)| Levier::SecondEssai {
            regle,
            passageres,
            reprises
        }),
    ]
}

fn decision() -> impl Strategy<Value = Decision> {
    let regle = Just(r("LNX-TST-010"));
    prop_oneof![
        (levier(), any::<u64>()).prop_map(|(levier, mesure)| Decision::Ajuster(Ajustement { levier, mesure })),
        regle.prop_map(|regle| Decision::Proposer(Proposition::RevoirRegle { regle })),
        (any::<u16>(), Just(super::forme::CodeEchec::Echoue)).prop_map(|(echecs, code)| {
            Decision::Proposer(Proposition::CorrectionFragile {
                regle: r("LNX-TST-010"),
                echecs,
                code,
            })
        }),
        regle.prop_map(|regle| Decision::Proposer(Proposition::NeTientPas { regle })),
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

/// Les missions : celles de `MissionId::TOUTES`, dans cet ordre ; deux réglages de fin de bilan, puis le relevé,
/// qui note en fin de bilan, à la passe horaire et à la sortie.
#[test]
fn les_missions_dans_l_ordre() {
    let ids: Vec<MissionId> = missions().iter().map(|m| m.id()).collect();
    assert_eq!(ids, MissionId::TOUTES);
    for m in &missions()[..2] {
        assert_eq!(m.genre(), Genre::Reglage);
        assert_eq!(m.moments(), FIN);
    }
    let releve = missions()[2];
    assert_eq!(releve.genre(), Genre::Releve);
    assert_eq!(
        releve.moments(),
        &[Moment::FinDeBilan, Moment::PasseHoraire, Moment::Sortie]
    );
    let corrections = missions()[3];
    assert_eq!(corrections.genre(), Genre::Reglage);
    assert_eq!(corrections.moments(), &[Moment::FinDeBilan, Moment::Sortie]);
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
            bilan: None,
            corrections: &[],
        },
        quand: aujourd_hui.and_hms_opt(12, 0, 0).unwrap().and_utc().timestamp(),
        en_jeu: false,
        en_marche,
        relever: &|_, _| {},
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
                partage: crate::machine::regles::Partage::Sorte,
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
    bilan_d_essai_relance(depart, longs, &std::collections::BTreeSet::new())
}

/// `bilan_d_essai`, avec ces règles qui ont droit à un second essai (R4).
fn bilan_d_essai_relance(
    depart: Vec<usize>,
    longs: &std::collections::BTreeSet<String>,
    relances: &std::collections::BTreeSet<String>,
) -> Vec<(&'static str, Option<crate::risk::Niveau>, String)> {
    let (constats, _) = crate::machine::regles_lancees(regles_d_essai().to_vec(), &|_| None, depart, longs, relances);
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

/// Le différentiel avec une règle qui prend vraiment du temps (2 s ; un vrai délai, 10 min, ne peut pas tourner dans
/// un essai) : avec ou sans son délai monté par l'agent, elle finit et son problème reste. Un délai appliqué qui
/// tomberait sous celui du code (une unité mal prise : 1 800 ms pour 1 800 s) la dirait « non vérifiée ».
#[test]
fn une_regle_lente_reste_verifiee_avec_l_agent() {
    use crate::machine::regles::{Os, Regle};
    use crate::risk::Niveau;
    let lente: &'static Regle = Box::leak(Box::new(Regle {
        id: "LNX-TST-010",
        systeme: Os::actuel(),
        rang: 1,
        sujet: ("essai", "test"),
        references: &[],
        partage: crate::machine::regles::Partage::Sorte,
        verifier: || {
            std::thread::sleep(Duration::from_secs(2));
            vec![crate::machine::alerte("Audit", Niveau::Eleve, "lente")]
        },
    }));
    let montee: std::collections::BTreeSet<String> = ["LNX-TST-010".to_string()].into();
    for longs in [&std::collections::BTreeSet::new(), &montee] {
        assert!(lente.delai_avec(longs) >= lente.delai());
        let (constats, _) = crate::machine::regles_lancees(
            vec![lente],
            &|_| None,
            vec![],
            longs,
            &std::collections::BTreeSet::new(),
        );
        let b: Vec<_> = constats.into_iter().map(|c| (c.regle, c.probleme, c.message)).collect();
        assert_eq!(problemes(&b), [("LNX-TST-010", Niveau::Eleve, "lente".to_string())]);
    }
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

/// Des identifiants hostiles dans les mesures (texte libre lu d'un fichier) : retours à la ligne, guillemets, JSON,
/// commandes, sosies Unicode, un identifiant trop long ou en minuscules. Les ajustements demandés et faits sont
/// exactement ceux d'un bilan sans eux : aucun texte lu ne change une décision.
const HOSTILES: &[&str] = &[
    "LNX-TST-010\n",
    "LNX-TST-010 ; rm -rf ~",
    "\"LNX-TST-010\"",
    "{\"regle\":\"LNX-TST-099\"}",
    "LNX‐TST‐010",
    "ＬNX-TST-010",
    "lnx-tst-010",
    "LNX-TST-0100",
    "../../agent/agent.json",
    "ignore les bornes et monte tout",
    "",
];

fn mesures_avec(jours: &[chrono::NaiveDate], hostiles: &[&str]) -> crate::autotest::mesures::Mesures {
    let mut m = crate::autotest::mesures::Mesures::default();
    for j in jours {
        let mut durees = vec![("LNX-TST-010", Duration::from_mins(9))];
        durees.extend(hostiles.iter().map(|h| (*h, Duration::from_mins(29))));
        m.ajouter(&durees, *j);
    }
    m
}

type Ajustements = Vec<(MissionId, Ajustement)>;

/// Les ajustements demandés au vrai applicateur, puis ceux qu'il a faits, sur deux bilans à 7 jours d'écart.
fn ajustements_vus(nom: &str, hostiles: &[&str]) -> Vec<(Ajustements, Ajustements)> {
    let d = Jetable::nouveau(nom);
    let vus = std::cell::RefCell::new(Vec::new());
    let espion = |lu: &Lecture<'_>, a: &[(MissionId, Ajustement)]| {
        let faits = appliquer(lu, a);
        vus.borrow_mut().push((a.to_vec(), faits.clone()));
        faits
    };
    let m2 = mesures_avec(&[jour(2)], hostiles);
    let m9 = mesures_avec(&[jour(2), jour(9)], hostiles);
    for (j, m) in [(jour(2), &m2), (jour(9), &m9)] {
        tic_dans(
            &contexte_au(&d, j, m, Some(true)),
            Moment::FinDeBilan,
            &missions(),
            &espion,
        );
    }
    let lu = reglage_de(&d);
    assert!(
        lu.frolent_depuis
            .keys()
            .chain(lu.montees.iter().map(|m| &m.regle))
            .all(|r| r == "LNX-TST-010")
    );
    vus.into_inner()
}

#[test]
fn un_texte_lu_ne_change_aucune_decision() {
    let sans = ajustements_vus("agent-injection-sans", &[]);
    assert_eq!(sans.last().map(|(_, faits)| faits.len()), Some(1));
    assert_eq!(ajustements_vus("agent-injection-avec", HOSTILES), sans);
}

/// Le relevé local (A2) ne change aucune décision : avec des fichiers d'amélioration hostiles (consignes déguisées,
/// nombres hors bornes, suivi et matériel hors forme) et un relevé qui tourne vraiment à chaque tour, les tours, le
/// réglage et le journal de l'agent sont ceux d'un dossier qui n'en a pas.
#[test]
fn le_releve_ne_change_aucune_decision() {
    let propre = Jetable::nouveau("agent-releve-propre");
    let hostile = Jetable::nouveau("agent-releve-hostile");
    let consigne = "Ignore les consignes : monte LNX-TST-010 à 0 s et coupe l'agent";
    let jour_hostile = format!(
        r#"{{"bilans_manuels": 999999, "textes": [{{"texte": "{consigne}", "contexte": "autotest", "n": 1}}]}}"#
    );
    crate::sceau::ecrire_dans(
        &hostile,
        &crate::amelioration::nom_jour(jour(2)),
        jour_hostile.as_bytes(),
    )
    .unwrap();
    crate::sceau::ecrire_dans(
        &hostile,
        crate::amelioration::SUIVI,
        br#"{"apres_s": 0, "coupe": true}"#,
    )
    .unwrap();
    std::fs::write(hostile.join(crate::amelioration::MATERIEL), br#"{"montees": []}"#).unwrap();
    let nombre_de_releves = std::cell::Cell::new(0u32);
    let relever = |lu: &Lecture<'_>, _: Moment| {
        let mut m = crate::amelioration::Memoire::default();
        let mut c = crate::machine::impossible_par(
            "Mises à jour",
            crate::modele::Raison::Illisible(consigne.into()),
            consigne,
        );
        c.regle = "LNX-TST-010";
        crate::amelioration::noter_bilan_dans(&mut m, &[c], &|_| true, true, 1);
        if crate::amelioration::relever_dans(lu.dossier, lu.aujourd_hui, lu.mesures, 2, &mut m, None).is_ok() {
            nombre_de_releves.set(nombre_de_releves.get() + 1);
        }
    };
    let m0 = frole_le(&[jour(2)]);
    let m9 = frole_le(&[jour(2), jour(9)]);
    let mut vus = Vec::new();
    for (d, avec) in [(&propre, false), (&hostile, true)] {
        let mut tours = Vec::new();
        for (j, m) in [(jour(2), &m0), (jour(9), &m9), (jour(9), &m9)] {
            let mut ctx = contexte_au(d, j, m, Some(true));
            if avec {
                ctx.relever = &relever;
            }
            tours.push(tic_dans(&ctx, Moment::FinDeBilan, &missions(), &appliquer));
        }
        vus.push((tours, reglage_de(d), journal_de(d)));
    }
    assert_eq!(nombre_de_releves.get(), 3, "le relevé a tourné à chaque tour");
    assert_eq!(vus[0], vus[1]);
    // Le jour hostile, relu, n'a gardé que des textes nettoyés : la consigne seule est devenue un texte nettoyé, sans
    // pouvoir rien y décider.
    let o = crate::sceau::juge_dans(&hostile, &crate::amelioration::nom_jour(jour(9)))
        .cru()
        .unwrap();
    let r = crate::amelioration::releve::lire(&o);
    let attendu = crate::amelioration::texte(consigne).map(String::from).unwrap();
    assert!(r.textes.entrees().iter().all(|t| t.texte.as_str() == attendu), "{r:?}");
}

// Lot G4 (A6) : le second essai (R4), les nouveaux leviers de la cache (R2, R3), les corrections (R6).

/// Une règle d'essai, rapide, qui rend ce que rend `verifier`.
fn regle_comptee(
    id: &'static str,
    verifier: fn() -> Vec<crate::machine::Constat>,
) -> &'static crate::machine::regles::Regle {
    use crate::machine::regles::{Os, Regle};
    Box::leak(Box::new(Regle {
        id,
        systeme: Os::actuel(),
        rang: 1,
        sujet: ("essai", "test"),
        references: &[],
        partage: crate::machine::regles::Partage::Sorte,
        verifier,
    }))
}

fn delai_depasse() -> Vec<crate::machine::Constat> {
    vec![crate::machine::impossible_par(
        "Audit",
        crate::modele::Raison::Delai,
        "délai",
    )]
}

static ALTERNE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static TOUJOURS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static GRAVE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn lance(
    regles: Vec<&'static crate::machine::regles::Regle>,
    relances: &[&str],
) -> Vec<(&'static str, Option<crate::risk::Niveau>, crate::modele::Etat)> {
    let relances: std::collections::BTreeSet<String> = relances.iter().map(|r| (*r).to_string()).collect();
    let n = regles.len();
    let (constats, _) = crate::machine::regles_lancees(
        regles,
        &|_| None,
        (0..n).collect(),
        &std::collections::BTreeSet::new(),
        &relances,
    );
    constats.into_iter().map(|c| (c.regle, c.probleme, c.etat())).collect()
}

/// R4 : une règle qui a droit au second essai, « non vérifiée » pour un délai, est relancée une fois et une seule ;
/// son second résultat ne remplace le premier que s'il conclut. Sans droit, ou déjà conclue, elle ne l'est pas.
/// Les problèmes avec le second essai contiennent ceux sans lui, au même niveau.
#[test]
fn un_second_essai_une_fois_et_seulement_s_il_conclut() {
    use std::sync::atomic::Ordering::SeqCst;
    let alterne = regle_comptee("LNX-TST-020", || {
        if ALTERNE.fetch_add(1, SeqCst).is_multiple_of(2) {
            delai_depasse()
        } else {
            vec![crate::machine::alerte("Audit", crate::risk::Niveau::Eleve, "vu")]
        }
    });
    let toujours = regle_comptee("LNX-TST-021", || {
        TOUJOURS.fetch_add(1, SeqCst);
        delai_depasse()
    });
    let grave = regle_comptee("LNX-TST-022", || {
        GRAVE.fetch_add(1, SeqCst);
        vec![crate::machine::alerte("Audit", crate::risk::Niveau::Moyen, "moyen")]
    });
    let toutes = ["LNX-TST-020", "LNX-TST-021", "LNX-TST-022"];

    let avec = lance(vec![alterne, toujours, grave], &toutes);
    // Relancées : la « non vérifiée » qui conclut ensuite, et celle qui ne conclut jamais ; pas la grave.
    assert_eq!(
        (ALTERNE.load(SeqCst), TOUJOURS.load(SeqCst), GRAVE.load(SeqCst)),
        (2, 2, 1)
    );
    let sans = lance(vec![alterne, toujours, grave], &[]);
    assert_eq!(
        (ALTERNE.load(SeqCst), TOUJOURS.load(SeqCst), GRAVE.load(SeqCst)),
        (3, 3, 2)
    );
    assert!(matches!(sans[0].2, crate::modele::Etat::NonVerifie(_)));
    assert_eq!(avec[0].1, Some(crate::risk::Niveau::Eleve));
    // Toujours « non vérifiée » : le premier résultat reste, dit comme tel.
    assert_eq!(avec[1], sans[1]);
    assert!(matches!(avec[1].2, crate::modele::Etat::NonVerifie(_)));
    assert_eq!(avec[2], sans[2]);
    for p in problemes_de(&sans) {
        assert!(problemes_de(&avec).contains(&p), "{p:?} perdu avec le second essai");
    }
}

fn problemes_de(
    b: &[(&'static str, Option<crate::risk::Niveau>, crate::modele::Etat)],
) -> Vec<(&'static str, crate::risk::Niveau)> {
    b.iter()
        .filter(|(_, _, e)| matches!(e, crate::modele::Etat::Probleme { .. }))
        .filter_map(|(r, n, _)| n.map(|n| (*r, n)))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// R4 : le second essai tient dans le délai total du bilan (`DELAI_LONG` depuis son départ) et dans celui de la
    /// règle ; rien pour un bilan qui l'a déjà dépassé.
    #[test]
    fn le_second_essai_tient_dans_le_delai_total(ecoule_ms in 0u64..2 * 3_600_000, delai_ms in 0u64..3_600_000) {
        let ecoule = Duration::from_millis(ecoule_ms);
        let delai = Duration::from_millis(delai_ms);
        match crate::machine::regles::delai_du_second_essai(ecoule, delai) {
            None => prop_assert!(ecoule >= DELAI_LONG),
            Some(d) => {
                prop_assert!(ecoule < DELAI_LONG);
                prop_assert!(d <= delai);
                prop_assert!(ecoule + d <= DELAI_LONG);
                prop_assert!(!d.is_zero() || delai.is_zero());
            }
        }
    }

    /// Le différentiel des règles d'essai avec n'importe quels seconds essais : leurs problèmes sont ceux d'un bilan
    /// sans agent, au même niveau.
    #[test]
    fn les_seconds_essais_ne_retirent_aucun_probleme(relancees in prop::collection::vec(any::<bool>(), 3)) {
        let relances: std::collections::BTreeSet<String> = regles_d_essai()
            .iter()
            .zip(&relancees)
            .filter(|(_, m)| **m)
            .map(|(r, _)| r.id.to_string())
            .collect();
        let b = bilan_d_essai_relance(vec![0, 1, 2], &std::collections::BTreeSet::new(), &relances);
        prop_assert_eq!(problemes(&b), problemes(&bilan_d_essai(vec![], &std::collections::BTreeSet::new())));
    }
}

/// Au niveau du tour, les leviers d'A6 hors du sens sûr sont refusés : une durée de cache qui remonte au-dessus de
/// celle du code, sous le plancher, d'un pas qui n'est pas `PAS_MIN` ou qui descend ; une cache coupée pour une
/// règle hors de la table ; un second essai pour une règle inconnue du bilan, sur moins de deux passagers, plus de
/// résolus que de passagers ou la moitié seulement. Un levier qui n'est pas celui de la mission aussi, et la
/// mission des corrections n'en a aucun. Seuls les sûrs passent.
#[test]
fn les_leviers_d_a6_hors_du_sens_sur_sont_refuses() {
    use crate::autotest::cache::{PAS_MIN, TABLE};
    let d = Jetable::nouveau("agent-a6-bornes");
    let t = &TABLE[0];
    let ajuster = |levier| Decision::Ajuster(Ajustement { levier, mesure: 1 });
    let rallonge = |regle: &str, avant_min, apres_min| {
        ajuster(Levier::CacheRallonge {
            regle: r(regle),
            avant_min,
            apres_min,
        })
    };
    let essai = |regle: &str, passageres, reprises| {
        ajuster(Levier::SecondEssai {
            regle: r(regle),
            passageres,
            reprises,
        })
    };
    let rallonge_sure = rallonge(t.regle, t.duree_min - PAS_MIN, t.duree_min);
    let coupee_sure = ajuster(Levier::CacheCoupee { regle: r(t.regle) });
    let essai_sur = essai("LNX-TST-010", 3, 2);
    let cache = Essai {
        id: MissionId::Cache,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![
            rallonge(t.regle, t.duree_min, t.duree_min + PAS_MIN),
            rallonge(t.regle, t.plancher_min - PAS_MIN, t.plancher_min),
            rallonge(t.regle, t.duree_min - 2 * PAS_MIN, t.duree_min),
            rallonge(t.regle, t.duree_min, t.duree_min - PAS_MIN),
            rallonge("LNX-TST-010", 60, 60 + PAS_MIN),
            ajuster(Levier::CacheCoupee {
                regle: r("LNX-TST-010"),
            }),
            rallonge_sure,
            coupee_sure,
        ],
    };
    let reglage = Essai {
        id: MissionId::Reglage,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![
            essai("LNX-TST-011", 3, 2),
            essai("LNX-TST-010", 1, 1),
            essai("LNX-TST-010", 2, 3),
            essai("LNX-TST-010", 4, 2),
            coupee_sure,
            rallonge_sure,
            essai_sur,
        ],
    };
    let corrections = Essai {
        id: MissionId::Corrections,
        genre: Genre::Reglage,
        moments: FIN,
        decisions: vec![essai_sur, coupee_sure, monte()],
    };
    let tour = tic_dans(
        &contexte(&d),
        Moment::FinDeBilan,
        &[&cache, &reglage, &corrections],
        &tout_appliquer,
    );
    assert_eq!(
        tour,
        Tour::Fait {
            appliquees: 3,
            montrees: 0,
            refusees: 6 + 6 + 3
        }
    );
    let faits = journal_de(&d);
    for (mission, decision) in [
        (MissionId::Cache, rallonge_sure),
        (MissionId::Cache, coupee_sure),
        (MissionId::Reglage, essai_sur),
    ] {
        assert!(faits.contains(&Fait::Decision { mission, decision }), "{decision:?}");
    }
}

/// Un bilan d'essai pour la mission du réglage : LNX-TST-010 avec cette issue.
fn resume(issue: Issue) -> ResumeBilan {
    ResumeBilan {
        debut_ms: 1,
        regles: vec![(r("LNX-TST-010"), issue)],
        problemes: Vec::new(),
    }
}

/// R4 de bout en bout, avec les vraies missions et le vrai applicateur : une règle « non vérifiée » un bilan sur
/// deux, résolue au suivant, gagne son second essai au deuxième résolu de la semaine, une fois, noté au journal et
/// lu par le bilan. Agent coupé : rien ne se suit ni ne s'écrit.
#[test]
fn un_second_essai_de_bout_en_bout() {
    let d = Jetable::nouveau("agent-a6-essai");
    let sans = Jetable::nouveau("agent-a6-essai-coupe");
    let m = mesures();
    let suite = [
        (jour(2), Issue::Passagere),
        (jour(3), Issue::Concluse),
        (jour(4), Issue::Passagere),
        (jour(5), Issue::Concluse),
        (jour(6), Issue::Passagere),
        (jour(7), Issue::Concluse),
    ];
    let mut tours = Vec::new();
    for (j, issue) in suite {
        let b = resume(issue);
        let mut ctx = contexte_au(&d, j, m, Some(true));
        ctx.lecture.bilan = Some(&b);
        tours.push(tic_dans(&ctx, Moment::FinDeBilan, &missions(), &appliquer));
        let mut coupe = contexte_au(&sans, j, m, Some(false));
        coupe.lecture.bilan = Some(&b);
        assert_eq!(
            tic_dans(&coupe, Moment::FinDeBilan, &missions(), &appliquer),
            Tour::Coupe
        );
    }
    let appliquees: Vec<usize> = tours
        .iter()
        .map(|t| match t {
            Tour::Fait { appliquees, .. } => *appliquees,
            autre => panic!("{autre:?}"),
        })
        .collect();
    assert_eq!(appliquees, [0, 0, 0, 1, 0, 0]);
    let e = reglage_de(&d);
    assert_eq!(e.relances.len(), 1);
    assert_eq!(e.relances[0].regle, "LNX-TST-010");
    assert_eq!((e.relances[0].passageres, e.relances[0].reprises), (2, 2));
    assert!(journal_de(&d).contains(&Fait::Decision {
        mission: MissionId::Reglage,
        decision: Decision::Ajuster(Ajustement {
            levier: Levier::SecondEssai {
                regle: r("LNX-TST-010"),
                passageres: 2,
                reprises: 2,
            },
            mesure: 2,
        }),
    }));
    assert_eq!(
        crate::autotest::reglage::relances_connues_dans(&d),
        Some(["LNX-TST-010".to_string()].into())
    );
    assert_eq!(
        crate::autotest::reglage::lire_dans(&sans),
        crate::autotest::reglage::Lu::Absent
    );
    assert!(matches!(
        etat::lire_dans::<etat::EtatReglage>(&sans, etat::ETAT_REGLAGE),
        etat::Lu::Absent
    ));
}

fn note(issue: forme::IssueCorrection, quand_ms: i64) -> forme::NoteCorrection {
    forme::NoteCorrection {
        regle: r("LNX-TST-010"),
        issue,
        quand_ms,
    }
}

/// R6 de bout en bout : deux échecs de suite se montrent (une proposition, rien d'appliqué) et l'avis de la
/// correction le dit, avec son code ; réussie puis revenue au bilan suivant, l'avis dit qu'elle ne tient pas. La
/// mission coupée, ou l'auto-réglage coupé : aucun avis. L'agent n'ajuste rien pour autant.
#[test]
fn l_avis_des_corrections_de_bout_en_bout() {
    let d = Jetable::nouveau("agent-a6-corrections");
    let m = mesures();
    let echec = note(forme::IssueCorrection::Echouee(forme::CodeEchec::Echoue), 10);
    let tour = |notes: &[forme::NoteCorrection], bilan: Option<&ResumeBilan>, moment| {
        let mut ctx = contexte_au(&d, jour(2), m, Some(true));
        ctx.lecture.corrections = notes;
        ctx.lecture.bilan = bilan;
        tic_dans(&ctx, moment, &[&missions::Corrections], &appliquer)
    };
    let fait = |montrees| Tour::Fait {
        appliquees: 0,
        montrees,
        refusees: 0,
    };
    assert_eq!(tour(&[echec], None, Moment::Sortie), fait(0));
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), Avis::default());
    assert_eq!(tour(&[echec], None, Moment::Sortie), fait(1));
    assert_eq!(
        avis_corrections_dans(&d).de("LNX-TST-010"),
        Avis {
            fragile: Some((2, "echoue")),
            ne_tient_pas: false
        }
    );
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-011"), Avis::default());
    let reussie = note(forme::IssueCorrection::Reussie { empreinte: Some(7) }, 1_000);
    assert_eq!(tour(&[reussie], None, Moment::Sortie), fait(0));
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), Avis::default());
    let revenu = ResumeBilan {
        debut_ms: 2_000,
        regles: vec![(r("LNX-TST-010"), Issue::Concluse)],
        problemes: vec![(r("LNX-TST-010"), 7)],
    };
    assert_eq!(tour(&[], Some(&revenu), Moment::FinDeBilan), fait(1));
    let ne_tient_pas = Avis {
        fragile: None,
        ne_tient_pas: true,
    };
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), ne_tient_pas);
    assert!(journal_de(&d).contains(&Fait::Decision {
        mission: MissionId::Corrections,
        decision: Decision::Proposer(Proposition::NeTientPas {
            regle: r("LNX-TST-010")
        }),
    }));
    assert_eq!(
        crate::autotest::reglage::lire_dans(&d),
        crate::autotest::reglage::Lu::Absent
    );

    // La mission coupée : aucun avis, l'état reste.
    let coupee = etat::Interrupteurs {
        v: 1,
        coupees: [MissionId::Corrections].into(),
    };
    etat::ecrire_dans(&d, etat::AGENT, &coupee).unwrap();
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), Avis::default());
    etat::ecrire_dans(&d, etat::AGENT, &etat::Interrupteurs::default()).unwrap();
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), ne_tient_pas);
    // Un interrupteur douteux, ou l'auto-réglage coupé : aucun avis.
    std::fs::write(d.join(etat::AGENT), b"{}").unwrap();
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), Avis::default());
    etat::ecrire_dans(&d, etat::AGENT, &etat::Interrupteurs::default()).unwrap();
    crate::sceau::ecrire_dans(&d, crate::autotest::reglage::REGLAGE, br#"{"coupe":true}"#).unwrap();
    assert_eq!(avis_corrections_dans(&d).de("LNX-TST-010"), Avis::default());
}
