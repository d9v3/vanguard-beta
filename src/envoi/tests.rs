//! Les essais de l'envoi : d, s, c, b, e (dossier, serveur, cadre, bilan, état) reviennent dans chacun.
#![allow(clippy::many_single_char_names)]

use super::*;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Instant;

use crate::compte_rendu::champs::Jour;
use crate::compte_rendu::envoi::{self, Arch, Compte, Edition, FamilleFine, Langue, SystemeVersion};
use crate::essais::Jetable;

// --- Le petit serveur local, qui compte les connexions -----------------------------------------------------------

/// Ce que fait le serveur de chaque connexion, une fois la demande lue.
#[derive(Clone, Copy)]
enum Mode {
    /// Répond ce code, sans corps.
    Code(u16),
    /// Ne répond jamais, garde la connexion ouverte.
    Muet,
    /// Ferme sans rien répondre.
    Coupe,
    /// Répond 200 puis un corps sans fin (il ne doit jamais être lu).
    SansFin,
    /// Renvoie ailleurs (302) : la redirection ne doit pas être suivie.
    Ailleurs(u16),
}

struct Serveur {
    port: u16,
    connexions: Arc<AtomicUsize>,
    demandes: Arc<Mutex<Vec<Vec<u8>>>>,
    fin: Arc<AtomicBool>,
}

impl Serveur {
    /// Sur 127.0.0.1, au port que choisit le système.
    fn lancer(mode: Mode) -> Serveur {
        let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
        ecoute.set_nonblocking(true).unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let connexions = Arc::new(AtomicUsize::new(0));
        let demandes = Arc::new(Mutex::new(Vec::new()));
        let fin = Arc::new(AtomicBool::new(false));
        let (n, d, f) = (connexions.clone(), demandes.clone(), fin.clone());
        std::thread::spawn(move || {
            while !f.load(Ordering::SeqCst) {
                match ecoute.accept() {
                    Ok((flux, _)) => {
                        n.fetch_add(1, Ordering::SeqCst);
                        // Sous Windows, la connexion acceptée hérite du mode non bloquant de l'écoute : la demande
                        // ne serait pas lue.
                        let _ = flux.set_nonblocking(false);
                        let (d, f) = (d.clone(), f.clone());
                        std::thread::spawn(move || servir(flux, mode, &d, &f));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Serveur {
            port,
            connexions,
            demandes,
            fin,
        }
    }

    fn adresse(&self) -> String {
        format!("http://127.0.0.1:{}/v1/lot", self.port)
    }

    fn connexions(&self) -> usize {
        self.connexions.load(Ordering::SeqCst)
    }
}

impl Drop for Serveur {
    fn drop(&mut self) {
        self.fin.store(true, Ordering::SeqCst);
    }
}

/// La demande entière : en-têtes, puis le corps annoncé.
fn lire_demande(flux: &mut TcpStream) -> Vec<u8> {
    let _ = flux.set_read_timeout(Some(Duration::from_secs(5)));
    let mut recu = Vec::new();
    let mut morceau = [0u8; 4096];
    loop {
        if let Some(fin) = recu.windows(4).position(|w| w == b"\r\n\r\n") {
            let entetes = String::from_utf8_lossy(&recu[..fin]).to_ascii_lowercase();
            let longueur = entetes
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if recu.len() >= fin + 4 + longueur {
                return recu;
            }
        }
        match flux.read(&mut morceau) {
            Ok(0) | Err(_) => return recu,
            Ok(n) => recu.extend_from_slice(&morceau[..n]),
        }
    }
}

fn servir(mut flux: TcpStream, mode: Mode, demandes: &Mutex<Vec<Vec<u8>>>, fin: &AtomicBool) {
    let demande = lire_demande(&mut flux);
    demandes.lock().unwrap().push(demande);
    match mode {
        Mode::Code(c) => {
            let _ = write!(flux, "HTTP/1.1 {c} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        }
        Mode::Muet => {
            while !fin.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        Mode::Coupe => {}
        Mode::SansFin => {
            let _ = write!(flux, "HTTP/1.1 200 OK\r\ncontent-length: 1000000000000\r\n\r\n");
            let bloc = [b'x'; 16 << 10];
            while !fin.load(Ordering::SeqCst) && flux.write_all(&bloc).is_ok() {}
        }
        Mode::Ailleurs(port) => {
            let _ = write!(
                flux,
                "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:{port}/v1/lot\r\ncontent-length: 0\r\n\r\n"
            );
        }
    }
}

// --- Le cadre des essais -----------------------------------------------------------------------------------------

/// Ferme un garde-fou, un seul à la fois.
type Fermer = fn(&mut Garde);

fn jour(j: u32) -> NaiveDate {
    NaiveDate::from_ymd_opt(2026, 11, j).unwrap()
}

/// Le 10 novembre 2026 à midi (UTC), en secondes.
const MIDI: i64 = 1_794_312_000;

fn ouverte() -> Garde {
    Garde {
        releve: true,
        developpement: false,
        hors_ligne: false,
        accord: true,
        arrete: false,
    }
}

fn cadre<'a>(dossier: &'a Path, relais: Option<&'a str>) -> Cadre<'a> {
    Cadre {
        dossier,
        aujourd_hui: jour(10),
        maintenant: MIDI,
        garde: ouverte(),
        relais,
        version: Version::new("0.89.1").unwrap(),
    }
}

fn plateforme_essai() -> (Plateforme, Activite) {
    (
        Plateforme {
            famille: FamilleFine::Arch,
            systeme_version: SystemeVersion::new("6.17").unwrap(),
            arch: Arch::X86_64,
            langue: Langue::Fr,
            edition: None,
            administrateur: false,
        },
        Activite {
            bilans_manuels: Compte::default(),
            passes_horaires: Compte::default(),
            surveillance: true,
            veilleur: false,
            cle: false,
        },
    )
}

/// Le POST des essais : le vrai, avec des délais courts (un serveur muet ne retient pas l'essai 10 s).
fn poster(adresse: &str, corps: Vec<u8>) -> Option<u16> {
    crate::http::poster_sans_lire(adresse, corps, Duration::from_millis(500), Duration::from_secs(1))
}

/// Une passe où chaque jour de `avec_releve` a un relevé (le lot est sa base, telle quelle).
fn passer(c: &Cadre, avec_releve: &[u32]) -> Bilan {
    passe_dans(
        c,
        Sources {
            plateforme: || Some(plateforme_essai()),
            du_jour: |d: NaiveDate, base: Lot| avec_releve.iter().any(|&j| jour(j) == d).then_some(base),
            poster,
            encore: || true,
        },
    )
}

fn en_file(dossier: &Path) -> Vec<NaiveDate> {
    file::jours_en_file(dossier)
}

fn etat(dossier: &Path) -> Etat {
    file::lire_etat(dossier)
}

// --- Sans relais, rien ---------------------------------------------------------------------------------------------

/// Le relais n'est pas déployé : l'adresse reste à `None` jusqu'au jour où son hôte entre dans `HOTES`.
#[test]
fn le_relais_n_a_pas_d_adresse() {
    assert!(RELAIS.is_none());
}

/// Tant que `RELAIS` vaut `None`, aucune connexion, même tous les autres garde-fous ouverts et un relevé chaque
/// jour : le serveur ne compte rien, le POST n'est jamais appelé, rien n'est écrit.
#[test]
fn sans_relais_aucune_connexion() {
    let s = Serveur::lancer(Mode::Code(200));
    let d = Jetable::nouveau("envoi-sans-relais");
    let adresse = s.adresse();
    let appels = AtomicUsize::new(0);
    let c = cadre(&d, RELAIS);
    let b = passe_dans(
        &c,
        Sources {
            plateforme: || Some(plateforme_essai()),
            du_jour: |_, base| Some(base),
            poster: |_: &str, corps| {
                appels.fetch_add(1, Ordering::SeqCst);
                poster(&adresse, corps)
            },
            encore: || true,
        },
    );
    // Le point d'entrée du programme non plus : sous les essais, il ne lance même pas de fil.
    en_fond(true);
    attendre();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(b, Bilan::default());
    assert_eq!(appels.load(Ordering::SeqCst), 0);
    assert_eq!(s.connexions(), 0);
    assert!(!d.join("envoi").exists());
    assert!(!d.join("envoi.lock").exists());
}

/// Sous les essais, ce processus ne prépare rien (`amelioration::actif`, et l'accord d'A5 encore fermé).
#[test]
fn ce_processus_ne_prepare_rien_sous_les_essais() {
    let g = Garde::de_ce_processus();
    assert!(!g.releve);
    assert!(!g.accord);
    assert!(!g.peut_preparer());
    assert!(!g.peut_envoyer());
}

/// Chaque garde-fou, seul, arrête tout : rien de mis en file, aucune connexion. Sans Internet, la file se remplit
/// mais rien ne part.
#[test]
fn chaque_garde_fou_arrete() {
    let s = Serveur::lancer(Mode::Code(200));
    let adresse = s.adresse();
    let fermees: [(&str, Fermer); 4] = [
        ("relevé", |g| g.releve = false),
        ("développement", |g| g.developpement = true),
        ("accord", |g| g.accord = false),
        ("arrêté", |g| g.arrete = true),
    ];
    for (nom, fermer) in fermees {
        let d = Jetable::nouveau("envoi-garde");
        let mut c = cadre(&d, Some(&adresse));
        fermer(&mut c.garde);
        assert_eq!(passer(&c, &[8, 9]), Bilan::default(), "{nom}");
        assert!(!d.join("envoi").exists(), "{nom}");
    }
    let d = Jetable::nouveau("envoi-hors-ligne");
    let mut c = cadre(&d, Some(&adresse));
    c.garde.hors_ligne = true;
    let b = passer(&c, &[8, 9]);
    assert_eq!((b.mis, b.postes), (2, 0));
    assert_eq!(en_file(&d), [jour(8), jour(9)]);
    assert_eq!(s.connexions(), 0);
}

// --- Les réponses du relais ----------------------------------------------------------------------------------------

/// 200 : le lot part, tel que la lecture stricte le relit, en JSON ; la file se vide.
#[test]
fn un_200_vide_la_file() {
    let s = Serveur::lancer(Mode::Code(200));
    let d = Jetable::nouveau("envoi-200");
    let adresse = s.adresse();
    let b = passer(&cadre(&d, Some(&adresse)), &[8, 9]);
    assert_eq!(
        b,
        Bilan {
            mis: 2,
            postes: 2,
            recus: 2,
            jetes: 0
        }
    );
    assert_eq!(s.connexions(), 2);
    assert_eq!(en_file(&d), Vec::<NaiveDate>::new());
    let e = etat(&d);
    assert_eq!(e.dernier_succes, Some(Jour::new("2026-11-10").unwrap()));
    assert_eq!(e.dernier_mis, Some(Jour::new("2026-11-09").unwrap()));
    for demande in s.demandes.lock().unwrap().iter() {
        let fin = demande.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let entetes = String::from_utf8_lossy(&demande[..fin]).to_ascii_lowercase();
        assert!(entetes.starts_with("post /v1/lot "), "{entetes}");
        assert!(entetes.contains("content-type: application/json"), "{entetes}");
        let lot = envoi::lire(&demande[fin + 4..]).unwrap();
        assert!(lot.installation.is_some());
        assert_eq!(lot.version.as_str(), "0.89.1");
    }
    // Le même jour, rien de plus : les jours envoyés ne se refont pas.
    let b = passer(&cadre(&d, Some(&adresse)), &[8, 9]);
    assert_eq!(b, Bilan::default());
    assert_eq!(s.connexions(), 2);
}

/// 429 et 503 : le lot reste, et rien ne part avant 24 h, ni le même jour ni le lendemain matin.
#[test]
fn un_429_ou_un_503_attend_24_h() {
    for (code, raison) in [(429, Raison::Limite), (503, Raison::Indisponible)] {
        let s = Serveur::lancer(Mode::Code(code));
        let d = Jetable::nouveau("envoi-attente");
        let adresse = s.adresse();
        let mut c = cadre(&d, Some(&adresse));
        let b = passer(&c, &[8, 9]);
        assert_eq!((b.mis, b.postes, b.recus), (2, 1, 0), "{code}");
        assert_eq!(en_file(&d), [jour(8), jour(9)]);
        let e = etat(&d);
        assert_eq!(e.attendre_jusqu_a, Some(MIDI + 86_400));
        assert_eq!(e.dernier_echec.map(|e| (e.raison, e.code)), Some((raison, Some(code))));
        passer(&c, &[]);
        c.aujourd_hui = jour(11);
        c.maintenant = MIDI + 86_399;
        passer(&c, &[]);
        assert_eq!(s.connexions(), 1, "{code}");
        c.maintenant = MIDI + 86_400;
        passer(&c, &[]);
        assert_eq!(s.connexions(), 2, "{code}");
    }
}

/// Un refus du contrat (413, 422, 400) : le lot est refusé pour de bon, il est jeté et la raison notée ; le suivant part.
#[test]
fn un_lot_refuse_est_jete() {
    for code in [413, 422, 400] {
        let s = Serveur::lancer(Mode::Code(code));
        let d = Jetable::nouveau("envoi-refuse");
        let adresse = s.adresse();
        let b = passer(&cadre(&d, Some(&adresse)), &[8, 9]);
        assert_eq!(
            b,
            Bilan {
                mis: 2,
                postes: 2,
                recus: 0,
                jetes: 2
            },
            "{code}"
        );
        assert_eq!(en_file(&d), Vec::<NaiveDate>::new());
        let e = etat(&d).dernier_echec.unwrap();
        assert_eq!((e.raison, e.code), (Raison::Refuse, Some(code)));
    }
}

/// Un serveur muet ne retient pas l'envoi au-delà de son délai ; une coupure non plus. Le lot attend, la passe
/// s'arrête au premier échec (un seul essai).
/// Un autre 4xx (403 d'un pare-feu, 404 d'un chemin pas encore déployé, 408) ne dit rien du lot : il attend, et
/// rien d'autre ne part ce jour-là.
#[test]
fn un_autre_4xx_garde_le_lot() {
    for code in [403, 404, 408] {
        let s = Serveur::lancer(Mode::Code(code));
        let d = Jetable::nouveau("envoi-autre-4xx");
        let adresse = s.adresse();
        let b = passer(&cadre(&d, Some(&adresse)), &[8, 9]);
        assert_eq!((b.mis, b.postes, b.recus, b.jetes), (2, 1, 0, 0), "{code}");
        assert_eq!(en_file(&d), [jour(8), jour(9)], "{code}");
        let e = etat(&d).dernier_echec.unwrap();
        assert_eq!((e.raison, e.code), (Raison::Autre, Some(code)));
    }
}

/// Les garde-fous relus avant chaque POST : fermés pendant la passe, plus rien ne part, ni essai compté.
#[test]
fn les_garde_fous_sont_relus_avant_chaque_post() {
    let s = Serveur::lancer(Mode::Code(200));
    let d = Jetable::nouveau("envoi-relus");
    let adresse = s.adresse();
    let b = passe_dans(
        &cadre(&d, Some(&adresse)),
        Sources {
            plateforme: || Some(plateforme_essai()),
            du_jour: |_, base| Some(base),
            poster,
            encore: || false,
        },
    );
    assert_eq!((b.mis, b.postes), (7, 0));
    assert_eq!(s.connexions(), 0);
    assert_eq!(etat(&d).essais, None);
}

/// Le relevé d'hier est là mais ne se croit pas encore : le jour n'est pas tenu pour passé, la passe suivante le
/// met en file. Un relevé plus vieux qui ne se croit pas, lui, est passé (il ne bloque pas la file).
#[test]
fn un_releve_d_hier_pas_encore_croyable_est_repris() {
    let d = Jetable::nouveau("envoi-hier");
    let c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    let c = Cadre {
        garde: Garde {
            hors_ligne: true,
            ..ouverte()
        },
        ..c
    };
    for j in [8, 9] {
        let nom = d.join(crate::amelioration::nom_jour(jour(j)));
        std::fs::create_dir_all(nom.parent().unwrap()).unwrap();
        std::fs::write(nom, b"en cours").unwrap();
    }
    assert_eq!(passer(&c, &[]).mis, 0);
    assert_eq!(etat(&d).dernier_mis, Some(Jour::new("2026-11-08").unwrap()));
    assert_eq!(passer(&c, &[9]).mis, 1);
    assert_eq!(en_file(&d), [jour(9)]);
    assert_eq!(etat(&d).dernier_mis, Some(Jour::new("2026-11-09").unwrap()));
}

/// Les restes d'une écriture de l'état coupée sont balayés, et « Ne pas partager » retire alors `envoi/`.
#[test]
fn les_restes_de_l_etat_sont_balayes() {
    let d = Jetable::nouveau("envoi-restes");
    file::ecrire_etat(&d, &Etat::default()).unwrap();
    std::fs::write(d.join("envoi").join("etat.tmp-1-2-0000000000000003"), b"{}").unwrap();
    file::purger(&d, |_| true);
    assert!(!d.join("envoi").join("etat.tmp-1-2-0000000000000003").exists());
    assert!(d.join(ETAT).exists());
    file::vider(&d).unwrap();
    assert!(!d.join("envoi").exists());
}

#[test]
fn serveur_muet_ou_coupure() {
    for mode in [Mode::Muet, Mode::Coupe] {
        let s = Serveur::lancer(mode);
        let d = Jetable::nouveau("envoi-muet");
        let adresse = s.adresse();
        let debut = Instant::now();
        let b = passer(&cadre(&d, Some(&adresse)), &[8, 9]);
        assert!(debut.elapsed() < Duration::from_secs(5), "{:?}", debut.elapsed());
        assert_eq!((b.postes, b.recus), (1, 0));
        assert_eq!(s.connexions(), 1);
        assert_eq!(en_file(&d), [jour(8), jour(9)]);
        assert_eq!(etat(&d).dernier_echec.map(|e| e.raison), Some(Raison::SansReponse));
    }
}

/// Le corps de la réponse n'est jamais lu : un corps sans fin ne retient rien, le code suffit.
#[test]
fn le_corps_de_la_reponse_n_est_jamais_lu() {
    let s = Serveur::lancer(Mode::SansFin);
    let d = Jetable::nouveau("envoi-sans-fin");
    let adresse = s.adresse();
    let debut = Instant::now();
    let b = passer(&cadre(&d, Some(&adresse)), &[9]);
    assert!(debut.elapsed() < Duration::from_secs(2), "{:?}", debut.elapsed());
    assert_eq!((b.postes, b.recus), (1, 1));
}

/// Une redirection n'est pas suivie : rien n'arrive à l'adresse donnée, le lot attend.
#[test]
fn une_redirection_n_est_pas_suivie() {
    let ailleurs = Serveur::lancer(Mode::Code(200));
    let s = Serveur::lancer(Mode::Ailleurs(ailleurs.port));
    let d = Jetable::nouveau("envoi-redirection");
    let adresse = s.adresse();
    let b = passer(&cadre(&d, Some(&adresse)), &[9]);
    assert_eq!((b.postes, b.recus), (1, 0));
    assert_eq!(ailleurs.connexions(), 0);
    assert_eq!(en_file(&d), [jour(9)]);
    let e = etat(&d).dernier_echec.unwrap();
    assert_eq!((e.raison, e.code), (Raison::Autre, Some(302)));
}

/// Trois essais par jour au plus, d'une passe à l'autre ; le lendemain, trois de plus.
#[test]
fn trois_essais_par_jour() {
    let s = Serveur::lancer(Mode::Coupe);
    let d = Jetable::nouveau("envoi-essais");
    let adresse = s.adresse();
    let mut c = cadre(&d, Some(&adresse));
    for _ in 0..5 {
        passer(&c, &[5, 6, 7, 8, 9]);
    }
    assert_eq!(s.connexions(), 3);
    assert_eq!(etat(&d).essais.map(|e| e.n), Some(3));
    c.aujourd_hui = jour(11);
    for _ in 0..5 {
        passer(&c, &[]);
    }
    assert_eq!(s.connexions(), 6);
}

// --- La file -------------------------------------------------------------------------------------------------------

/// La file ne garde que les 7 jours clos de la fenêtre : un jour plus vieux, un jour du futur, les restes d'une
/// écriture coupée et ce qu'un autre y a posé partent ; un sous-dossier reste, jamais lu.
#[test]
fn la_file_garde_sept_jours_au_plus() {
    let d = Jetable::nouveau("envoi-fenetre");
    let base = |j| {
        let (p, a) = plateforme_essai();
        Lot::new(
            Version::new("0.89.1").unwrap(),
            file::jour(jour(j)),
            Anciennete::Moins7,
            p,
            a,
        )
    };
    for j in 1..=12 {
        file::mettre(&d, jour(j), base(j)).unwrap();
    }
    let f = d.join(FILE);
    std::fs::write(f.join("notes.txt"), b"x").unwrap();
    std::fs::write(f.join("2026-11-09.json.tmp-1-0-00"), b"x").unwrap();
    std::fs::create_dir(f.join("dossier")).unwrap();
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    let b = passer(&c, &[]);
    assert_eq!(b.mis, 0);
    assert_eq!(en_file(&d), (3..=9).map(jour).collect::<Vec<_>>());
    let mut noms: Vec<String> = std::fs::read_dir(&f)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    noms.sort();
    assert_eq!(noms.len(), 8);
    assert!(noms.contains(&"dossier".to_string()));
}

/// Un lot de la file qui ne se relit pas strictement (pas du JSON, un champ de trop, un autre jour que son nom,
/// trop gros) est jeté sans partir ; le bon, lui, part.
#[test]
fn un_lot_forge_est_jete_sans_partir() {
    let s = Serveur::lancer(Mode::Code(200));
    let d = Jetable::nouveau("envoi-forge");
    let adresse = s.adresse();
    let (p, a) = plateforme_essai();
    let bon = Lot::new(
        Version::new("0.89.1").unwrap(),
        file::jour(jour(9)),
        Anciennete::Moins7,
        p,
        a,
    );
    file::mettre(&d, jour(9), bon.clone()).unwrap();
    let f = d.join(FILE);
    std::fs::write(f.join("2026-11-05.json"), b"pas du json").unwrap();
    let mut texte = String::from_utf8(bon.ecrire()).unwrap();
    texte.insert_str(1, "\"chemin\":\"/home/alice\",");
    std::fs::write(f.join("2026-11-06.json"), texte).unwrap();
    std::fs::write(f.join("2026-11-07.json"), bon.ecrire()).unwrap();
    std::fs::write(f.join("2026-11-08.json"), vec![b' '; envoi::LOT_MAX + 1]).unwrap();
    let e = Etat {
        dernier_mis: Some(Jour::new("2026-11-09").unwrap()),
        ..Etat::default()
    };
    file::ecrire_etat(&d, &e).unwrap();
    let b = passer(&cadre(&d, Some(&adresse)), &[]);
    assert_eq!(
        b,
        Bilan {
            mis: 0,
            postes: 1,
            recus: 1,
            jetes: 4
        }
    );
    assert_eq!(s.connexions(), 1);
    assert_eq!(en_file(&d), Vec::<NaiveDate>::new());
    let demandes = s.demandes.lock().unwrap();
    let corps = &demandes[0];
    assert!(!String::from_utf8_lossy(corps).contains("alice"));
}

/// Un lien posé à la place d'un dossier ou d'un lot n'est jamais suivi : rien ne s'écrit ni ne s'efface à travers.
#[cfg(unix)]
#[test]
fn un_lien_n_est_jamais_suivi() {
    let s = Serveur::lancer(Mode::Code(200));
    let adresse = s.adresse();
    let ailleurs = Jetable::nouveau("envoi-ailleurs");
    // `envoi/file` est un lien : rien n'est préparé.
    let d = Jetable::nouveau("envoi-lien-dossier");
    std::fs::create_dir_all(d.join("envoi")).unwrap();
    std::os::unix::fs::symlink(&*ailleurs, d.join(FILE)).unwrap();
    std::fs::write(ailleurs.join("2026-11-01.json"), b"x").unwrap();
    assert_eq!(passer(&cadre(&d, Some(&adresse)), &[8, 9]), Bilan::default());
    assert!(ailleurs.join("2026-11-01.json").exists());
    assert_eq!(std::fs::read_dir(&*ailleurs).unwrap().count(), 1);
    // Un lot qui est un lien vers un vrai lot : jeté (le lien seul), sans partir.
    let d = Jetable::nouveau("envoi-lien-lot");
    let (p, a) = plateforme_essai();
    let lot = Lot::new(
        Version::new("0.89.1").unwrap(),
        file::jour(jour(9)),
        Anciennete::Moins7,
        p,
        a,
    );
    std::fs::write(ailleurs.join("lot.json"), lot.ecrire()).unwrap();
    std::fs::create_dir_all(d.join(FILE)).unwrap();
    std::os::unix::fs::symlink(ailleurs.join("lot.json"), d.join(FILE).join("2026-11-09.json")).unwrap();
    let b = passer(&cadre(&d, Some(&adresse)), &[]);
    assert_eq!((b.postes, b.jetes), (0, 1));
    assert_eq!(s.connexions(), 0);
    assert!(ailleurs.join("lot.json").exists());
}

// --- L'état --------------------------------------------------------------------------------------------------------

/// L'état reste sous 2 Kio ; un état plus gros, ou forgé, repart de zéro ; une attente forgée très loin est ramenée
/// à 24 h, une date du futur à aujourd'hui.
#[test]
fn l_etat_reste_borne() {
    let s = Serveur::lancer(Mode::Code(503));
    let d = Jetable::nouveau("envoi-etat");
    let adresse = s.adresse();
    passer(&cadre(&d, Some(&adresse)), &[3, 4, 5, 6, 7, 8, 9]);
    let taille = std::fs::metadata(d.join(ETAT)).unwrap().len();
    assert!(taille < 1024, "{taille}");
    std::fs::write(d.join(ETAT), vec![b' '; 4096]).unwrap();
    assert_eq!(etat(&d), Etat::default());
    std::fs::write(d.join(ETAT), br#"{"inconnu":1}"#).unwrap();
    assert_eq!(etat(&d), Etat::default());
    let futur = Jour::new("2027-01-01").unwrap();
    let e = Etat {
        attendre_jusqu_a: Some(i64::MAX),
        premier_jour: Some(futur.clone()),
        dernier_mis: Some(futur.clone()),
        essais: Some(Essais { jour: futur, n: 99 }),
        ..Etat::default()
    };
    file::ecrire_etat(&d, &e).unwrap();
    let mut c = cadre(&d, Some(&adresse));
    passer(&c, &[]);
    let e = etat(&d);
    assert_eq!(e.attendre_jusqu_a, Some(MIDI + 86_400));
    assert_eq!(e.premier_jour, Some(Jour::new("2026-11-10").unwrap()));
    assert_eq!(e.dernier_mis, Some(Jour::new("2026-11-09").unwrap()));
    let avant = s.connexions();
    c.maintenant = MIDI + 86_400;
    c.aujourd_hui = jour(11);
    passer(&c, &[10]);
    assert_eq!(s.connexions(), avant + 1);
}

/// L'identifiant d'installation : 16 chiffres hexadécimaux tirés au hasard, gardé 90 jours, puis retiré.
#[test]
fn l_identifiant_tourne_tous_les_90_jours() {
    let d = Jetable::nouveau("envoi-id");
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    passer(&c, &[]);
    let premier = etat(&d).installation.unwrap();
    assert_eq!(premier.id.as_str().len(), 16);
    c.aujourd_hui = jour(10) + chrono::Duration::days(89);
    passer(&c, &[]);
    assert_eq!(etat(&d).installation.unwrap(), premier);
    c.aujourd_hui = jour(10) + chrono::Duration::days(90);
    passer(&c, &[]);
    let second = etat(&d).installation.unwrap();
    assert_ne!(second.id, premier.id);
    assert_eq!(second.depuis.as_str(), "2027-02-08");
}

/// Après une mise à jour, les lots des 7 jours suivants portent la version d'avant ; puis plus.
#[test]
fn la_version_d_avant_suit_sept_jours() {
    let d = Jetable::nouveau("envoi-version");
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    c.version = Version::new("0.89.0").unwrap();
    passer(&c, &[]);
    c.version = Version::new("0.89.1").unwrap();
    c.aujourd_hui = jour(11);
    passer(&c, &[10]);
    let avant = |j| file::relire(&d, jour(j)).unwrap().unwrap().version_avant;
    // Le 10 a tourné en 0.89.0 jusqu'à la mise à jour du 11 : pas de version d'avant.
    assert_eq!(avant(10), None);
    // Les jours du 11 au 17, les 7 qui suivent la mise à jour, portent 0.89.0 ; le 18, plus.
    for j in 12..=19 {
        c.aujourd_hui = jour(j);
        passer(&c, &[j - 1]);
        let attendue = (j <= 18).then(|| "0.89.0".to_string());
        assert_eq!(avant(j - 1).map(|v| v.as_str().to_string()), attendue, "{j}");
    }
}

/// L'ancienneté se compte depuis le premier jour vu, en quatre classes.
#[test]
fn l_anciennete_vient_du_premier_jour() {
    let d = Jetable::nouveau("envoi-anciennete");
    let e = Etat {
        premier_jour: Some(Jour::new("2026-10-01").unwrap()),
        ..Etat::default()
    };
    file::ecrire_etat(&d, &e).unwrap();
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    passer(&c, &[9]);
    let lot = file::relire(&d, jour(9)).unwrap().unwrap();
    assert_eq!(lot.anciennete, Anciennete::Moins90);
}

/// « Ne pas partager » vide la file et l'état (l'identifiant part avec), et laisse ce qui n'est pas à l'envoi.
#[test]
fn vider_efface_la_file_et_l_identifiant() {
    let d = Jetable::nouveau("envoi-vider");
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    passer(&c, &[8, 9]);
    assert!(etat(&d).installation.is_some());
    std::fs::create_dir(d.join(FILE).join("autre")).unwrap();
    file::vider(&d).unwrap();
    assert_eq!(en_file(&d), Vec::<NaiveDate>::new());
    assert!(!d.join(ETAT).exists());
    assert!(d.join(FILE).join("autre").is_dir());
}

/// Le lot vient vraiment du relevé du jour (`amelioration::lot_du_jour`), et la lecture stricte l'accepte.
#[test]
fn le_lot_vient_du_releve_du_jour() {
    let d = Jetable::nouveau("envoi-releve");
    let mesures = crate::autotest::mesures::Mesures::default();
    let mut m = crate::amelioration::Memoire::default();
    crate::amelioration::outil_dans(&mut m, "bilan", envoi::Origine::Menu, None);
    crate::amelioration::relever_dans(&d, jour(9), &mesures, 1, &mut m, None).unwrap();
    let mut c = cadre(&d, Some("http://127.0.0.1:9/v1/lot"));
    c.garde.hors_ligne = true;
    let b = passe_dans(
        &c,
        Sources {
            plateforme: || Some(plateforme_essai()),
            du_jour: |j, base| crate::amelioration::lot_du_jour(&d, j, base, &mesures, |_| Some(60)),
            poster,
            encore: || true,
        },
    );
    assert_eq!(b.mis, 1);
    let lot = file::relire(&d, jour(9)).unwrap().unwrap();
    assert_eq!(lot.jour.as_str(), "2026-11-09");
    assert!(!lot.outils.est_vide());
}

// --- La plateforme -------------------------------------------------------------------------------------------------

#[test]
fn la_famille_vient_d_id_puis_d_id_like() {
    let f = plateforme::famille_linux;
    assert_eq!(f("ID=arch\n"), FamilleFine::Arch);
    assert_eq!(f("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n"), FamilleFine::Ubuntu);
    assert_eq!(f("ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n"), FamilleFine::Mint);
    assert_eq!(f("ID=\"opensuse-tumbleweed\"\n"), FamilleFine::Opensuse);
    assert_eq!(f("ID=endeavouros\nID_LIKE=arch\n"), FamilleFine::Arch);
    assert_eq!(f("ID=pop\nID_LIKE=\"ubuntu debian\"\n"), FamilleFine::Ubuntu);
    // Le nom écrit ne compte jamais : seul l'identifiant, et un inconnu n'est que « linux-autre ».
    assert_eq!(f("NAME=Fedora\nID=salon-os\n"), FamilleFine::LinuxAutre);
    assert_eq!(f(""), FamilleFine::LinuxAutre);
}

#[test]
fn le_noyau_garde_son_majeur_mineur() {
    let n = |s| plateforme::noyau_reduit(s).map(|v| v.as_str().to_string());
    assert_eq!(n("6.17.2-arch1-1\n").as_deref(), Some("6.17"));
    assert_eq!(n("6.1.0-maison").as_deref(), Some("6.1"));
    assert_eq!(n("7").as_deref(), Some("7"));
    assert_eq!(n("maison-6.1"), None);
    assert_eq!(n(""), None);
}

#[test]
fn windows_et_macos_se_reduisent() {
    let w = |b| plateforme::windows(b).map(|(f, v)| (f, v.as_str().to_string()));
    assert_eq!(w("19045"), Some((FamilleFine::Windows10, "19045".into())));
    assert_eq!(w("26100"), Some((FamilleFine::Windows11, "26100".into())));
    assert_eq!(w("26100.1"), None);
    let e = plateforme::edition_windows;
    assert_eq!(e("Core"), Some(Edition::Home));
    assert_eq!(e("CoreSingleLanguage"), Some(Edition::Home));
    assert_eq!(e("Professional"), Some(Edition::Pro));
    assert_eq!(e("Enterprise"), Some(Edition::Entreprise));
    assert_eq!(e("Education"), Some(Edition::Entreprise));
    assert_eq!(e("ServerStandard"), Some(Edition::Serveur));
    assert_eq!(e("Salon"), None);
    let m = |v| plateforme::macos(v).map(|v| v.as_str().to_string());
    assert_eq!(m("15.1.1").as_deref(), Some("15"));
    assert_eq!(m("x"), None);
}
