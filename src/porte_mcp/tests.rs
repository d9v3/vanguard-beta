//! La porte entière. Le transport face à un client hostile (`servir` : trame géante, flot sans fin, débit, délais,
//! sortie fermée) ; puis les vrais outils sur un dossier planté de valeurs inventées : rien d'écrit pendant une
//! session, rien d'exclu dans les réponses, la teinte en tête de chacune.

use super::*;
use serde_json::{Map, json};
use std::io::Cursor;

use crate::modele::evenement::{Evenement, Genre, Source};
use crate::risk::Niveau;

const INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"essai","version":"1"}}}"#;
const PING: &str = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;

/// Des outils qui ne servent rien : seul le transport est jugé.
struct Aucun;

impl Outils for Aucun {
    fn liste(&self) -> Value {
        json!([])
    }

    fn nom_ferme(&self, _nom: &str) -> Option<&'static str> {
        None
    }

    fn appeler(&mut self, _nom: &'static str, _arguments: Option<&RawValue>) -> Result<Map<String, Value>, Code> {
        Err(Code::Arguments)
    }
}

use serde_json::value::RawValue;

fn courtes() -> Bornes {
    Bornes {
        message_max: 64 * 1024,
        delai_message: Duration::from_millis(300),
        inactivite: Duration::from_millis(400),
        duree_max: Duration::from_secs(30),
        demandes_max: 1000,
        delai_ecriture: Duration::from_millis(500),
    }
}

/// Un noteur qui ne note rien : le transport seul.
struct Muet;

impl Noteur for Muet {
    fn ouvrir(&mut self, _: &BilanSession) {}
    fn alerter(&mut self) {}
    fn fermer(&mut self, _: &BilanSession) {}
}

fn servir_muet<R: Read + Send + 'static>(
    entree: R,
    sortie: &mut impl Write,
    outils: &mut dyn Outils,
    bornes: Bornes,
) -> BilanSession {
    let arret = AtomicBool::new(false);
    let mut b = Branchements {
        outils,
        noteur: &mut Muet,
        arret: &arret,
    };
    servir(entree, sortie, &mut b, bornes)
}

/// Sert `entree` jusqu'au bout ; rend le bilan et chaque ligne écrite, relue en JSON.
fn session<R: Read + Send + 'static>(entree: R, bornes: Bornes) -> (BilanSession, Vec<Value>) {
    let mut sortie = Vec::new();
    let bilan = servir_muet(entree, &mut sortie, &mut Aucun, bornes);
    let lignes = String::from_utf8(sortie)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (bilan, lignes)
}

fn code_d_erreur(v: &Value) -> &str {
    v.pointer("/error/data/code").and_then(Value::as_str).unwrap_or("")
}

#[test]
fn une_trame_geante_est_refusee_et_ferme_la_session() {
    let geante = format!("{INIT}\n{{\"x\":\"{}\"}}\n{PING}\n", "a".repeat(70_000));
    let (bilan, lignes) = session(Cursor::new(geante.into_bytes()), courtes());
    assert_eq!(bilan.fin, Fin::Hostile);
    assert!(bilan.hostile);
    assert_eq!(
        lignes.len(),
        2,
        "le ping d'après la trame géante n'a pas de réponse : {lignes:?}"
    );
    assert_eq!(lignes.get(1).map(code_d_erreur), Some("trame-trop-grande"));
    assert_eq!(lignes.get(1).and_then(|l| l.get("id")), Some(&Value::Null));
}

#[test]
fn un_flot_sans_fin_de_ligne_est_coupe_vite() {
    let depart = Instant::now();
    let (bilan, lignes) = session(std::io::repeat(b'a'), courtes());
    assert_eq!(bilan.fin, Fin::Hostile);
    assert_eq!(lignes.first().map(code_d_erreur), Some("trame-trop-grande"));
    assert!(depart.elapsed() < Duration::from_secs(5), "{:?}", depart.elapsed());
}

#[test]
fn trop_de_demandes_par_seconde_ferme_la_session() {
    let rafale = format!("{INIT}\n{}", format!("{PING}\n").repeat(40));
    let (bilan, lignes) = session(Cursor::new(rafale.into_bytes()), courtes());
    assert_eq!(bilan.fin, Fin::Hostile);
    assert_eq!(lignes.last().map(code_d_erreur), Some("rythme"));
    assert!(lignes.len() < 41, "la rafale entière a été servie");
}

#[test]
fn le_nombre_de_demandes_est_borne() {
    let bornes = Bornes {
        demandes_max: 5,
        ..courtes()
    };
    let suite = format!("{INIT}\n{}", format!("{PING}\n").repeat(10));
    let (bilan, lignes) = session(Cursor::new(suite.into_bytes()), bornes);
    assert_eq!(bilan.fin, Fin::Demandes);
    assert_eq!(lignes.last().map(code_d_erreur), Some("trop-de-demandes"));
    assert!(!bilan.hostile);
}

#[test]
fn un_message_commence_doit_finir_a_temps() {
    let (lecture, mut ecriture) = std::io::pipe().unwrap();
    ecriture.write_all(b"{\"jsonrpc\":").unwrap();
    let depart = Instant::now();
    let (bilan, lignes) = session(lecture, courtes());
    assert_eq!(bilan.fin, Fin::Delai);
    assert_eq!(lignes, Vec::<Value>::new());
    assert!(depart.elapsed() < Duration::from_secs(5));
    drop(ecriture);
}

#[test]
fn le_silence_finit_la_session() {
    let (lecture, ecriture) = std::io::pipe().unwrap();
    let (bilan, _) = session(lecture, courtes());
    assert_eq!(bilan.fin, Fin::Inactivite);
    drop(ecriture);
}

#[test]
fn la_duree_d_une_session_est_bornee() {
    let (lecture, ecriture) = std::io::pipe().unwrap();
    let bornes = Bornes {
        inactivite: Duration::from_secs(60),
        duree_max: Duration::from_millis(300),
        ..courtes()
    };
    let depart = Instant::now();
    let (bilan, _) = session(lecture, bornes);
    assert_eq!(bilan.fin, Fin::Duree);
    assert!(depart.elapsed() < Duration::from_secs(5));
    drop(ecriture);
}

struct Fermee;

impl Write for Fermee {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }
}

#[test]
fn une_sortie_fermee_finit_la_session() {
    let bilan = servir_muet(
        Cursor::new(format!("{INIT}\n{PING}\n").into_bytes()),
        &mut Fermee,
        &mut Aucun,
        courtes(),
    );
    assert_eq!(bilan.fin, Fin::SortieFermee);
}

#[test]
fn la_fin_du_flot_et_la_ligne_coupee() {
    let (bilan, lignes) = session(Cursor::new(format!("{INIT}\n").into_bytes()), courtes());
    assert_eq!(bilan.fin, Fin::FlotFini);
    assert_eq!(lignes.len(), 1);
    let (bilan, lignes) = session(Cursor::new(INIT.as_bytes().to_vec()), courtes());
    assert_eq!(bilan.fin, Fin::Coupee);
    assert_eq!(lignes, Vec::<Value>::new(), "une ligne sans fin n'est pas servie");
}

/// Des outils qui servent `etat` (un objet vide), pour juger quand la note s'écrit.
struct UnOutil;

impl Outils for UnOutil {
    fn liste(&self) -> Value {
        json!([])
    }

    fn nom_ferme(&self, nom: &str) -> Option<&'static str> {
        (nom == "etat").then_some("etat")
    }

    fn appeler(&mut self, _nom: &'static str, _arguments: Option<&RawValue>) -> Result<Map<String, Value>, Code> {
        Ok(Map::new())
    }
}

type Trace = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

/// Note dans la même trace que la sortie : l'ordre des notes et des réponses se lit.
struct Temoin(Trace);

impl Noteur for Temoin {
    fn ouvrir(&mut self, ouverture: &BilanSession) {
        self.0.borrow_mut().push(format!("ouvrir:{}", ouverture.fin.nom()));
    }
    fn alerter(&mut self) {
        self.0.borrow_mut().push("alerter".into());
    }
    fn fermer(&mut self, bilan: &BilanSession) {
        self.0.borrow_mut().push(format!("fermer:{}", bilan.fin.nom()));
    }
}

struct SortieTemoin(Trace);

impl Write for SortieTemoin {
    fn write(&mut self, octets: &[u8]) -> std::io::Result<usize> {
        Ok(octets.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().push("reponse".into());
        Ok(())
    }
}

fn trace_de(entree: String) -> Vec<String> {
    let trace = Trace::default();
    let arret = AtomicBool::new(false);
    let mut b = Branchements {
        outils: &mut UnOutil,
        noteur: &mut Temoin(trace.clone()),
        arret: &arret,
    };
    servir(
        Cursor::new(entree.into_bytes()),
        &mut SortieTemoin(trace.clone()),
        &mut b,
        courtes(),
    );
    trace.take()
}

/// CLIENT-1, CLIENT-2 : la note s'ouvre au premier appel servi, avant sa réponse (un client qui tue la porte en
/// lisant cette réponse ne l'efface pas) ; l'alerte d'un client hostile s'écrit avant la réponse qui ferme ; une
/// session sans appel servi n'ouvre rien.
#[test]
fn la_note_passe_avant_la_reponse() {
    let appel = |id: u32| json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": "etat", "arguments": {} } });
    let geante = format!("{{\"x\":\"{}\"}}", "a".repeat(70_000));
    let trace = trace_de(format!("{INIT}\n{PING}\n{}\n{}\n{geante}\n", appel(2), appel(3)));
    assert_eq!(
        trace,
        [
            "reponse",
            "reponse",
            "ouvrir:ouverte",
            "reponse",
            "reponse",
            "alerter",
            "reponse",
            "fermer:hostile"
        ]
    );
    let trace = trace_de(format!("{INIT}\n{PING}\n"));
    assert_eq!(trace, ["reponse", "reponse", "fermer:fin-du-flot"]);
    let trace = trace_de(format!("{INIT}\n{geante}\n"));
    assert_eq!(trace, ["reponse", "alerter", "reponse", "fermer:hostile"]);
}

/// CLIENT-1 : un signal d'arrêt (le drapeau levé par le fil des signaux) finit la session vite, et proprement :
/// la note de fin passe.
#[test]
fn un_signal_finit_la_session_et_la_note() {
    let (lecture, ecriture) = std::io::pipe().unwrap();
    let arret = std::sync::Arc::new(AtomicBool::new(false));
    let leve = arret.clone();
    let fil = crate::socle::fil::lancer("essai-signal", move || {
        std::thread::sleep(Duration::from_millis(300));
        leve.store(true, Ordering::SeqCst);
    })
    .unwrap();
    let trace = Trace::default();
    let mut b = Branchements {
        outils: &mut UnOutil,
        noteur: &mut Temoin(trace.clone()),
        arret: &arret,
    };
    let depart = Instant::now();
    let bornes = Bornes {
        inactivite: Duration::from_secs(60),
        ..courtes()
    };
    let bilan = servir(lecture, &mut Vec::new(), &mut b, bornes);
    assert_eq!(bilan.fin, Fin::Signal);
    assert!(depart.elapsed() < Duration::from_secs(5), "{:?}", depart.elapsed());
    assert_eq!(trace.take(), ["fermer:signal"]);
    fil.join().unwrap();
    drop(ecriture);
}

/// Une sortie qui ne rend jamais la main (un client qui ne lit plus ses réponses) ; relâchée à la fin de l'essai.
struct Coincee(std::sync::mpsc::Receiver<()>);

impl Write for Coincee {
    fn write(&mut self, octets: &[u8]) -> std::io::Result<usize> {
        let _ = self.0.recv();
        Ok(octets.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// CLIENT-3 : une réponse que le client ne prend pas ne retient pas la porte au-delà du délai d'écriture ; la
/// session finit, comptée hostile.
#[test]
fn une_sortie_qui_ne_lit_plus_finit_la_session_a_temps() {
    let (relache, attente) = std::sync::mpsc::channel();
    let bornes = courtes();
    let mut sortie = SortieBornee::new(Coincee(attente), bornes.delai_ecriture).unwrap();
    let (lecture, ecriture) = std::io::pipe().unwrap();
    let mut envoi = ecriture;
    writeln!(envoi, "{INIT}\n{PING}").unwrap();
    let depart = Instant::now();
    let bilan = servir_muet(lecture, &mut sortie, &mut Aucun, bornes);
    assert_eq!(bilan.fin, Fin::SortieBloquee);
    assert!(bilan.hostile);
    assert!(depart.elapsed() < Duration::from_secs(5), "{:?}", depart.elapsed());
    // Bloquée, elle le reste : plus rien ne s'écrit.
    assert_eq!(
        sortie
            .write_all(b"x")
            .and_then(|()| sortie.flush())
            .map_err(|e| e.kind()),
        Err(std::io::ErrorKind::TimedOut)
    );
    drop(relache);
    drop(envoi);
}

/// Une sortie bornée qui marche rend chaque réponse, entière et dans l'ordre.
#[test]
fn une_sortie_bornee_rend_les_reponses() {
    let (lecture, ecriture) = std::io::pipe().unwrap();
    let mut sortie = SortieBornee::new(ecriture, Duration::from_secs(5)).unwrap();
    let bilan = servir_muet(
        Cursor::new(format!("{INIT}\n{PING}\n").into_bytes()),
        &mut sortie,
        &mut Aucun,
        courtes(),
    );
    assert_eq!(bilan.fin, Fin::FlotFini);
    drop(sortie);
    let mut texte = String::new();
    BufReader::new(lecture).read_to_string(&mut texte).unwrap();
    let lignes: Vec<Value> = texte.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lignes.len(), 2, "{texte}");
    assert_eq!(lignes.get(1).and_then(|l| l.get("id")), Some(&json!(1)));
}

/// DROITS-4 : root, setuid, setgid, une capacité effective, ou un champ qui manque : refusée.
#[test]
fn les_droits_eleves_se_lisent_dans_le_status() {
    let status =
        |uid: &str, gid: &str, cap: &str| format!("Name:\tvanguard\nUid:\t{uid}\nGid:\t{gid}\nCapEff:\t{cap}\n");
    let ordinaire = status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000", "0000000000000000");
    assert!(!eleve_d_apres(&ordinaire));
    for eleve in [
        status("0\t0\t0\t0", "0\t0\t0\t0", "0000000000000000"),
        status("1000\t0\t1000\t1000", "1000\t1000\t1000\t1000", "0000000000000000"),
        status("1000\t1000\t0\t1000", "1000\t1000\t1000\t1000", "0000000000000000"),
        status("1000\t1000\t1000\t1000", "1000\t5\t1000\t1000", "0000000000000000"),
        status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000", "0000000000001000"),
        status("1000\t1000\t1000", "1000\t1000\t1000\t1000", "0000000000000000"),
        status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000", "zz"),
        "Name:\tvanguard\nUid:\t1000\t1000\t1000\t1000\n".to_string(),
        String::new(),
    ] {
        assert!(eleve_d_apres(&eleve), "{eleve}");
    }
}

/// A-FREIN-1 : sous un plafond de taille de fichier, la porte refuse de démarrer ; un plafond illisible aussi. Le
/// plafond est lu pour de vrai dans un processus lancé sous `prlimit --fsize`.
#[cfg(target_os = "linux")]
#[test]
fn la_porte_refuse_un_plafond_de_taille_de_fichier() {
    assert!(!plafond_refuse(&Ok(u64::MAX)));
    assert!(plafond_refuse(&Ok(1 << 40)));
    assert!(plafond_refuse(&Err(io::Error::other("illisible"))));
    let Ok(sortie) = std::process::Command::new("prlimit")
        .args(["--fsize=4096", "--", "cat", "/proc/self/limits"])
        .output()
    else {
        return crate::essais::saute("prlimit absent");
    };
    if !sortie.status.success() {
        return crate::essais::saute("prlimit n'a pas pu poser le plafond");
    }
    let lu = crate::socle::processus::plafond_lu(&String::from_utf8_lossy(&sortie.stdout));
    assert_eq!(lu, Some(4096));
    assert!(plafond_refuse(&lu.ok_or_else(|| io::Error::other("illisible"))));
}

/// CONTRAT-7 : sous Windows, refusée tant qu'elle n'y est pas essayée.
#[cfg(windows)]
#[test]
fn la_porte_est_refusee_sous_windows() {
    assert!(refus_de_demarrer().is_some());
}

/// CLIENT-1, CLIENT-2 : avec le vrai journal, une session qui sert un appel laisse sa note d'ouverture puis sa note
/// de fin ; une session sans appel ne laisse rien ; un client hostile laisse son alerte, même sans appel.
#[test]
fn le_vrai_journal_ne_note_que_les_sessions_servies() {
    use crate::modele::journal::lire_dans;
    let dossier = planter("porte-mcp-notes");
    let porte_mcp = |dossier: &std::path::Path| {
        lire_dans(dossier)
            .evenements
            .into_iter()
            .filter(|e| e.source == Source::PorteMcp)
            .map(|e| match e.quoi {
                Genre::SessionPorte { fin, .. } => fin,
                Genre::Alerte { famille, .. } => format!("alerte:{famille}"),
                autre => format!("{autre:?}"),
            })
            .collect::<Vec<_>>()
    };
    let servir_journal = |entree: String| {
        let arret = AtomicBool::new(false);
        let mut noteur = NoteurJournal::new(dossier.to_path_buf());
        let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
        let mut b = Branchements {
            outils: &mut porte,
            noteur: &mut noteur,
            arret: &arret,
        };
        servir(Cursor::new(entree.into_bytes()), &mut Vec::new(), &mut b, courtes());
    };
    servir_journal(format!("{INIT}\n{PING}\n"));
    assert_eq!(porte_mcp(&dossier), Vec::<String>::new());
    let appel = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "etat" } });
    servir_journal(format!("{INIT}\n{appel}\n"));
    assert_eq!(porte_mcp(&dossier), ["ouverte", "fin-du-flot"]);
    servir_journal(format!("{INIT}\n{{\"x\":\"{}\"}}\n", "a".repeat(70_000)));
    assert_eq!(porte_mcp(&dossier), ["ouverte", "fin-du-flot", "alerte:porte-mcp"]);
}

// --- Les vrais outils sur un dossier planté ---------------------------------------------------------------------

/// Ce qui ne doit jamais sortir de la porte : chemins, compte, ligne de commande, pid, adresse, objet, geste.
const EXCLUS: &[&str] = &[
    "/home/",
    "alice",
    "Alice",
    "Hunter2Invente",
    "--password",
    "987654",
    "876543",
    "203.0.113.77",
    "facture-piegee",
    "projets-secrets",
    "rm -rf",
    "regle-de-blocage-xyz",
    "Salon-Invente",
    "accord-invente",
];

fn preuve() -> crate::protection::preuve::Preuve {
    use crate::protection::preuve::{Fichier, Preuve, Processus};
    Preuve {
        date: "2026-11-16 10:00:00".into(),
        processus: Some(Processus {
            pid: 987_654,
            parent: Some(876_543),
            programme: Some("/home/alice/projets-secrets/minerai-xmr".into()),
            ligne: Some("/home/alice/projets-secrets/minerai-xmr --password=Hunter2Invente".into()),
            compte: Some("alice".into()),
        }),
        fichier: Some(Fichier {
            chemin: "/home/alice/projets-secrets/minerai-xmr".into(),
            sha256: Some("ab".repeat(32)),
            taille: Some(4096),
        }),
        connexions: vec!["203.0.113.77:4444".into()],
        impossible: vec!["/home/alice/projets-secrets/illisible".into()],
    }
}

fn resultat(outil: &str) -> Vec<u8> {
    let r = json!({
        "outil": outil,
        "dossier": "/home/alice/projets-secrets",
        "schema": 1,
        "debut": "2026-11-16T10:00:00Z",
        "duree_ms": 1200,
        "couverture": { "verifies": 12, "non_verifies": ["/home/alice/projets-secrets/illisible"] },
        "constats": [{
            "regle": "ESP-1",
            "objet": "/home/alice/Documents/facture-piegee.pdf.exe",
            "categorie": "Espions",
            "etat": "probleme",
            "niveau": "Eleve",
            "raison": "signature-inconnue",
            "message": "Programme espion trouvé",
            "corrigeable": true,
            "date": "2026-11-16T09:59:00Z",
            "geste": {
                "sorte": "retirer",
                "empreinte": "cd".repeat(32),
                "nom": "facture-piegee",
                "commande": "rm -rf /home/alice/Documents",
                "accord": "accord-invente",
            },
        }],
    });
    // Relu en `Resultat` d'abord : un nom de champ faux ferait un essai qui ne plante rien.
    let r: crate::modele::resultat::Resultat = serde_json::from_value(r).unwrap();
    serde_json::to_vec(&r).unwrap()
}

/// Un dossier de Vanguard comme après quelques jours : journal, examens scellés, un examen sans sceau (qu'une lecture
/// ordinaire adopterait en écrivant), l'historique des bilans.
fn planter(nom: &str) -> crate::essais::Jetable {
    use crate::modele::journal::noter_dans;
    let dossier = crate::essais::Jetable::nouveau(nom);
    std::fs::create_dir_all(&*dossier).unwrap();
    let maintenant = chrono::Utc::now();
    let evs = [
        Evenement::alerte(
            Source::Surveillance,
            "botnet",
            "Connexion vers un serveur de commande",
            "Le programme minerai-xmr parle à un serveur connu.",
        )
        .gravite(Niveau::Eleve)
        .cle(Some("alerte-botnet|203.0.113.77")),
        Evenement::nouveau(Source::Blocage, Genre::Preuve { releve: preuve() })
            .gravite(Niveau::Eleve)
            .cause(Some("e-1-987654")),
        Evenement::nouveau(
            Source::Blocage,
            Genre::Action {
                quoi: "Arrêté /home/alice/projets-secrets/minerai-xmr (pid 987654)".into(),
                reussi: true,
                automatique: true,
                blocage: Some("regle-de-blocage-xyz".into()),
                annulable: Some("/home/alice/.local/share/vanguard/quarantaine/minerai-xmr".into()),
                commandes: vec!["rm -rf /home/alice/projets-secrets".into()],
            },
        )
        .gravite(Niveau::Moyen),
        Evenement::nouveau(
            Source::Utilisateur,
            Genre::Annulation {
                objet: "/home/alice/projets-secrets/minerai-xmr".into(),
                supprime: false,
            },
        ),
        Evenement::nouveau(
            Source::Outil,
            Genre::Examen {
                outil: "PRO-ESP-001".into(),
                verdict: "probleme".into(),
                problemes: 1,
                non_verifies: 1,
            },
        )
        .gravite(Niveau::Eleve),
    ];
    for ev in evs {
        noter_dans(&dossier, ev, maintenant).unwrap();
    }
    for outil in ["PRO-ESP-001", "PRO-PER-001"] {
        let nom = crate::modele::resultat::fichier(outil).unwrap();
        crate::sceau::ecrire_dans(&dossier, nom, &resultat(outil)).unwrap();
    }
    // Sans sceau : écrit hors de Vanguard.
    let nom = crate::modele::resultat::fichier("PRO-COU-001").unwrap();
    std::fs::write(dossier.join(nom), resultat("PRO-COU-001")).unwrap();
    let historique = json!([
        { "date": "2026-11-10 12:00", "machine": 80, "reseau": 70, "nom_reseau": "Salon-Invente",
          "problemes": ["Pare-feu : /home/alice/projets-secrets"] },
        { "date": "2026-11-15 12:00", "machine": 85, "reseau": 75, "nom_reseau": "Salon-Invente", "problemes": [] },
    ]);
    std::fs::write(dossier.join("historique.json"), historique.to_string()).unwrap();
    dossier
}

/// Chaque outil, avec des arguments qui touchent chaque branche, puis une page suivante des événements.
fn appels() -> Vec<(&'static str, Value)> {
    let depuis = (chrono::Utc::now() - chrono::Duration::days(10))
        .format("%Y-%m-%d")
        .to_string();
    vec![
        ("etat", json!({})),
        ("evenements", json!({})),
        ("evenements", json!({ "limite": 2 })),
        ("evenements", json!({ "genre": "preuve" })),
        ("evenements", json!({ "genre": "action" })),
        ("evenements", json!({ "genre": "annulation" })),
        ("evenements", json!({ "gravite_min": "moyen", "depuis": depuis })),
        ("constats", json!({})),
        ("constats", json!({ "outil": "PRO-ESP-001", "niveau_min": "moyen" })),
        ("bilans", json!({ "limite": 30 })),
        ("identite", json!({})),
        ("inexistant", json!({})),
        ("evenements", json!({ "limite": 0 })),
    ]
}

/// Une session entière sur les vrais outils ; rend chaque réponse relue.
fn session_reelle(dossier: &std::path::Path) -> Vec<Value> {
    lues(&session_brute(dossier))
}

fn lues(lignes: &[String]) -> Vec<Value> {
    lignes.iter().map(|l| serde_json::from_str(l).unwrap()).collect()
}

/// La session de `session_brute` sans la page suivante, que seul un dossier à trois événements ou plus donne ; et
/// le lien `suivant` de sa première page de deux, s'il y en a un.
fn premiere_page(dossier: &std::path::Path) -> (Vec<String>, Option<String>, Bornes) {
    let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
    let mut lignes = vec![
        INIT.to_string(),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.into(),
    ];
    lignes.push(r#"{"jsonrpc":"2.0","id":"l","method":"tools/list"}"#.into());
    for (i, (nom, args)) in appels().into_iter().enumerate() {
        let demande = json!({ "jsonrpc": "2.0", "id": i, "method": "tools/call",
                              "params": { "name": nom, "arguments": args } });
        lignes.push(demande.to_string());
    }
    let mut sortie = Vec::new();
    let entree = Cursor::new(lignes.iter().fold(String::new(), |t, l| t + l + "\n").into_bytes());
    // Sous le rythme : quinze lignes, moins de vingt. Le temps de traitement compte dans le silence du client : sous
    // Wine chargé (verifier.sh), une réponse passait 400 ms et la session finissait par « inactivité ». Cet essai juge
    // les réponses, pas le rythme (essayé par ses propres essais, avec les bornes courtes).
    let bornes = Bornes {
        inactivite: Duration::from_secs(10),
        ..courtes()
    };
    let bilan = servir_muet(entree, &mut sortie, &mut porte, bornes);
    assert_eq!(bilan.fin, Fin::FlotFini, "{bilan:?}");
    let reponses: Vec<String> = String::from_utf8(sortie).unwrap().lines().map(str::to_string).collect();
    // Le lien de la première page de deux, vers la page suivante des événements.
    let suivant = reponses
        .iter()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find_map(|r| {
            r.pointer("/result/structuredContent/suivant")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    (reponses, suivant, bornes)
}

/// La même session, chaque réponse telle qu'écrite (l'ordre des clés compte), page suivante des événements comprise.
fn session_brute(dossier: &std::path::Path) -> Vec<String> {
    let (mut reponses, suivant, bornes) = premiere_page(dossier);
    // Exigée (3e re-contrôle) : une page 2 manquante, faute de lien `suivant`, ferait passer les essais de contenu sans
    // l'avoir lue. Mêmes bornes et même bilan exigé, et une vraie page d'événements, pas une erreur d'outil.
    let avant = suivant.expect("la première page de deux doit donner un lien suivant");
    let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
    let demande = json!({ "jsonrpc": "2.0", "id": 99, "method": "tools/call",
                          "params": { "name": "evenements", "arguments": { "limite": 2, "avant": avant } } });
    let mut sortie = Vec::new();
    let entree = Cursor::new(format!("{INIT}\n{demande}\n").into_bytes());
    let bilan = servir_muet(entree, &mut sortie, &mut porte, bornes);
    assert_eq!(bilan.fin, Fin::FlotFini, "page suivante : {bilan:?}");
    let page: Vec<String> = String::from_utf8(sortie).unwrap().lines().map(str::to_string).collect();
    assert!(
        page.iter()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .any(|r| r["id"] == 99
                && r.pointer("/result/isError").is_none_or(|e| e == false)
                && r.pointer("/result/structuredContent/evenements")
                    .and_then(Value::as_array)
                    .is_some_and(|e| !e.is_empty())),
        "pas de page d'événements non vide d'id 99 à la page suivante : {page:?}"
    );
    reponses.extend(page);
    reponses
}

#[test]
fn une_session_entiere_n_ecrit_rien() {
    use crate::autotest::lecture_seule::{ecarts, empreinte_dossier};
    let dossier = planter("porte-mcp-rien-ecrit");
    let avant = empreinte_dossier(&dossier);
    let reponses = session_reelle(&dossier);
    assert!(reponses.len() > 10, "{reponses:?}");
    let apres = empreinte_dossier(&dossier);
    assert_eq!(
        ecarts(&avant, &apres),
        Vec::new(),
        "la porte a écrit dans le dossier de Vanguard"
    );
}

#[test]
fn un_premier_usage_n_est_pas_adopte_en_ecrivant() {
    use crate::autotest::lecture_seule::{ecarts, empreinte_dossier};
    // Un dossier sans aucun sceau : la lecture ordinaire adopterait l'examen et écrirait les sceaux.
    let dossier = crate::essais::Jetable::nouveau("porte-mcp-premier-usage");
    std::fs::create_dir_all(&*dossier).unwrap();
    let nom = crate::modele::resultat::fichier("PRO-ESP-001").unwrap();
    std::fs::create_dir_all(dossier.join(nom).parent().unwrap()).unwrap();
    std::fs::write(dossier.join(nom), resultat("PRO-ESP-001")).unwrap();
    let avant = empreinte_dossier(&dossier);
    // Sans événement, pas de page suivante.
    let reponses = lues(&premiere_page(&dossier).0);
    assert_eq!(ecarts(&avant, &empreinte_dossier(&dossier)), Vec::new());
    // Adopté sans être cru : jamais « sain ».
    let etat = reponses
        .iter()
        .find_map(|r| r.pointer("/result/structuredContent/examens"))
        .unwrap();
    assert!(!etat.to_string().contains("\"sain\""), "{etat}");
}

#[test]
fn rien_d_exclu_ne_sort_de_la_porte() {
    let dossier = planter("porte-mcp-exclus");
    let reponses = session_reelle(&dossier);
    let tout: String = reponses.iter().map(Value::to_string).collect();
    for exclu in EXCLUS {
        assert!(!tout.contains(exclu), "« {exclu} » est sorti de la porte");
    }
    // Ce qui doit sortir sort : sinon l'essai ne prouverait rien.
    // Le nom court du programme d'une preuve garde son propre champ ; « minerai-xmr » n'est pas un mot du vocabulaire
    // de Vanguard : il sort « … », dans ce champ comme dans le texte de l'alerte, dont les mots de Vanguard sortent.
    assert!(
        !tout.contains("minerai"),
        "un nom hors vocabulaire est sorti de la porte"
    );
    for attendu in [
        "\"programme\":{\"texte_externe\":\"…\"",
        "Le programme … parle à un serveur connu.",
        "botnet",
        "alerte-botnet",
        "\"preuve\"",
        "\"action\"",
        "\"annulation\"",
    ] {
        assert!(tout.contains(attendu), "« {attendu} » manque : {tout}");
    }
    let examens = reponses
        .iter()
        .find_map(|r| r.pointer("/result/structuredContent/examens"))
        .unwrap()
        .to_string();
    assert!(examens.contains("PRO-COU-001"), "{examens}");
}

#[test]
fn la_teinte_est_en_tete_de_chaque_reponse() {
    let dossier = planter("porte-mcp-teinte");
    let mut structures = 0;
    for brute in session_brute(&dossier) {
        let r: Value = serde_json::from_str(&brute).unwrap();
        if let Some(e) = r.get("error") {
            assert_eq!(
                e.pointer("/data/teinte").and_then(Value::as_str),
                Some(rpc::TEINTE),
                "{r}"
            );
            continue;
        }
        let resultat = r.get("result").unwrap();
        assert_eq!(
            resultat.pointer("/_meta/vanguard~1teinte").and_then(Value::as_str),
            Some(rpc::TEINTE),
            "{r}"
        );
        if let Some(contenu) = resultat.get("structuredContent") {
            assert_eq!(contenu.get("teinte").and_then(Value::as_str), Some(rpc::TEINTE), "{r}");
            let texte = resultat.pointer("/content/0/text").and_then(Value::as_str).unwrap();
            assert!(texte.starts_with(r#"{"teinte":"non-fiable""#), "{texte}");
            // Dans la ligne même : `structuredContent` commence par la teinte, avant tout contenu.
            assert!(
                brute.contains(r#""structuredContent":{"teinte":"non-fiable","origine":"vanguard","schema":"#),
                "{}",
                brute.chars().take(300).collect::<String>()
            );
            structures += 1;
        }
    }
    assert!(structures >= 5, "des réponses d'outil attendues : {structures}");
}

/// Les arguments d'un outil sont un objet : un tableau, que serde lirait par position, est refusé.
#[test]
fn des_arguments_en_tableau_sont_refuses() {
    let mut porte = outils::Porte::new(crate::essais::temporaire(), vues::Liens::fixes());
    for (nom, brut) in [("etat", "[]"), ("bilans", "[3]"), ("evenements", " [null,null,null,2]")] {
        let brut = RawValue::from_string(brut.to_string()).unwrap();
        assert_eq!(
            porte.appeler(nom, Some(&brut)).err(),
            Some(rpc::Code::Arguments),
            "{nom}"
        );
    }
    let objet = RawValue::from_string(r#" {"limite":3}"#.to_string()).unwrap();
    assert!(porte.appeler("bilans", Some(&objet)).is_ok());
}

#[test]
fn la_liste_des_outils_est_fermee() {
    let porte = outils::Porte::new(crate::essais::temporaire(), vues::Liens::fixes());
    let noms: Vec<String> = porte
        .liste()
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|o| o.get("name").and_then(Value::as_str).map(str::to_string))
        .collect();
    assert_eq!(noms, ["etat", "evenements", "constats", "bilans", "identite"]);
    for nom in &noms {
        assert_eq!(porte.nom_ferme(nom), Some(nom.as_str()));
    }
    for autre in [
        "Etat",
        "etat ",
        "etat\0",
        "corriger",
        "examiner",
        "",
        "../etat",
        "evenements/ecrire",
    ] {
        assert_eq!(porte.nom_ferme(autre), None, "{autre:?}");
    }
    for outil in porte.liste().as_array().unwrap() {
        assert_eq!(
            outil.pointer("/annotations/readOnlyHint"),
            Some(&json!(true)),
            "{outil}"
        );
        assert_eq!(
            outil.pointer("/inputSchema/additionalProperties"),
            Some(&json!(false)),
            "{outil}"
        );
    }
}

proptest::proptest! {
    /// Un texte venu de l'ordinateur, quel qu'il soit, sort borné, sans caractère de contrôle ni chevron.
    #[test]
    fn un_texte_externe_sort_toujours_borne(brut in "\\PC{0,600}|[\\x00-\\x7f]{0,600}") {
        let v = vues::texte_externe(&brut);
        let t = v.get("texte_externe").and_then(Value::as_str).unwrap_or("");
        proptest::prop_assert!(t.len() <= 1200, "{}", t.len());
        proptest::prop_assert!(!t.chars().any(|c| c.is_control() && c != '\n' && c != '\t'), "{t:?}");
        proptest::prop_assert_eq!(v.get("non_fiable"), Some(&json!(true)));
    }

    /// Un nom fermé n'accepte que `[a-z0-9-]`.
    #[test]
    fn un_nom_ferme_n_accepte_que_sa_forme(brut in "\\PC{0,50}") {
        if let Some(n) = vues::ferme(&brut, 40) {
            proptest::prop_assert!(n.bytes().all(|o| o.is_ascii_lowercase() || o.is_ascii_digit() || o == b'-'));
        }
    }
}

/// A-PROTOCOLE-1 : des événements qui portent le même id (un journal changé hors de Vanguard), en un bloc plus grand
/// qu'une page : la pagination par `suivant` finit, et rend chaque ligne une fois.
#[test]
fn la_pagination_finit_meme_avec_des_ids_en_double() {
    use crate::modele::journal::noter_dans;
    let dossier = crate::essais::Jetable::nouveau("porte-mcp-ids-en-double");
    std::fs::create_dir_all(&*dossier).unwrap();
    let maintenant = chrono::Utc::now();
    for i in 0..60 {
        let mut ev = Evenement::alerte(Source::Surveillance, "port", "Port ouvert", "Un port est ouvert.");
        if (10..50).contains(&i) {
            ev.id = "e-1-meme".into();
        }
        noter_dans(&dossier, ev, maintenant).unwrap();
    }
    let total = crate::modele::journal::lire_dans(&dossier).evenements.len();
    let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
    let (mut vus, mut avant, mut pages) = (0, None::<String>, 0);
    loop {
        let args = match &avant {
            Some(a) => json!({ "limite": 7, "avant": a }),
            None => json!({ "limite": 7 }),
        };
        let brut = RawValue::from_string(args.to_string()).unwrap();
        let page = porte.appeler("evenements", Some(&brut)).unwrap();
        vus += page["evenements"].as_array().unwrap().len();
        pages += 1;
        assert!(pages <= total, "la pagination ne finit pas");
        match page["suivant"].as_str() {
            Some(s) => avant = Some(s.to_string()),
            None => break,
        }
    }
    assert_eq!(vus, total);
}

/// A-PROTOCOLE-2 : la note d'ouverture que la porte écrit elle-même ne rend pas son journal « pas à jour » : deux
/// appels de suite sur un journal sain le disent à jour et vérifié, et le second voit la note.
#[test]
fn la_note_de_la_porte_ne_rend_pas_son_journal_perime() {
    let dossier = planter("porte-mcp-a-jour");
    let arret = AtomicBool::new(false);
    let mut noteur = NoteurJournal::new(dossier.to_path_buf());
    let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
    let mut b = Branchements {
        outils: &mut porte,
        noteur: &mut noteur,
        arret: &arret,
    };
    let appel =
        |id: u8| json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": "evenements" } });
    let mut sortie = Vec::new();
    let entree = format!("{INIT}\n{}\n{}\n", appel(1), appel(2));
    servir(Cursor::new(entree.into_bytes()), &mut sortie, &mut b, courtes());
    let pages: Vec<Value> = String::from_utf8(sortie)
        .unwrap()
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<Value>(l)
                .unwrap()
                .pointer("/result/structuredContent")
                .cloned()
        })
        .collect();
    assert_eq!(pages.len(), 2);
    for page in &pages {
        assert_eq!(page.pointer("/journal/a_jour"), Some(&json!(true)), "{page}");
        assert_eq!(page.pointer("/journal/lecture"), Some(&json!("intact")), "{page}");
    }
    let sources = |p: &Value| -> Vec<Value> {
        p["evenements"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["source"].clone())
            .collect()
    };
    assert!(!sources(&pages[0]).contains(&json!("porte-mcp")));
    assert!(
        sources(&pages[1]).contains(&json!("porte-mcp")),
        "la note de la porte n'est pas vue"
    );
}

/// A-PROTOCOLE-3 : des lignes vides envoyées de temps en temps ne tiennent pas la session ouverte : le silence court.
#[test]
fn les_lignes_vides_ne_rompent_pas_le_silence() {
    let (lecture, mut ecriture) = std::io::pipe().unwrap();
    let envoi = std::thread::spawn(move || {
        for _ in 0..30 {
            if ecriture.write_all(b"\n").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let depart = Instant::now();
    let (bilan, lignes) = session(lecture, courtes());
    assert_eq!(bilan.fin, Fin::Inactivite, "{bilan:?}");
    assert_eq!(lignes, Vec::<Value>::new());
    assert!(depart.elapsed() < Duration::from_secs(2), "{:?}", depart.elapsed());
    envoi.join().unwrap();
}

/// A-FUITE-6 : un historique sans empreinte (écrit à la main) n'est pas dit « intacte » ni ses bilans vérifiés ; dans
/// une chaîne, seul un bilan qui porte son empreinte est dit vérifié ; une date d'une autre forme ne sort pas.
#[test]
fn un_bilan_sans_empreinte_n_est_pas_dit_verifie() {
    let bilans = |dossier: &std::path::Path| {
        let mut porte = outils::Porte::new(dossier.to_path_buf(), vues::Liens::fixes());
        let brut = RawValue::from_string(json!({ "limite": 30 }).to_string()).unwrap();
        porte.appeler("bilans", Some(&brut)).unwrap()
    };
    let verifies = |m: &Map<String, Value>| -> Vec<Value> {
        m["bilans"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["verifie"].clone())
            .collect()
    };
    let plante = planter("porte-mcp-bilans-a-la-main");
    let m = bilans(&plante);
    assert_eq!(m["chaine"], "non-verifiee");
    assert_eq!(verifies(&m), [json!(false), json!(false)]);
    let dossier = crate::essais::Jetable::nouveau("porte-mcp-bilans-chaines");
    std::fs::create_dir_all(&*dossier).unwrap();
    let chemin = dossier.join("historique.json");
    std::fs::write(
        &chemin,
        json!([{ "date": "203-0-113-7:4242", "machine": 80, "problemes": [] }]).to_string(),
    )
    .unwrap();
    for date in ["2026-11-16 09:00", "2026-11-17 10:00"] {
        let b = crate::historique::Bilan {
            date: date.into(),
            machine: Some(90),
            ..Default::default()
        };
        crate::historique::enregistrer_dans(&chemin, b);
    }
    let m = bilans(&dossier);
    assert_eq!(m["chaine"], "intacte");
    assert_eq!(verifies(&m), [json!(true), json!(true), json!(false)]);
    let dates: Vec<Value> = m["bilans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["date"].clone())
        .collect();
    assert_eq!(
        dates,
        [json!("2026-11-17 10:00"), json!("2026-11-16 09:00"), Value::Null]
    );
}
