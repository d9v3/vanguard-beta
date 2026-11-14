//! Tests du programme lui-même, vu de l'extérieur : Vanguard est lancé comme le ferait quelqu'un (arguments, réponses
//! envoyées par un tube), avec un dossier personnel jetable pour ne rien écrire dans le vrai (journal des erreurs,
//! base des appareils, historique). Les fonctions internes (lecture des sorties des outils, notes, fabricants…) se
//! testent dans leur propre module : un programme n'a pas de bibliothèque que ce dossier pourrait appeler.
//! Rien ici ne change le système : listes, menus quittés, refus aux questions, scan de 127.0.0.1 seulement.

// Les aides de ce fichier ne sont pas dans un #[test] : l'exemption des tests de clippy.toml ne les couvre pas, et y
// planter reste la façon d'échouer (voir les règles anti-panique de Cargo.toml).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Les essais sautés, comptés par outils/verifier.sh comme ceux des tests unitaires.
#[path = "../src/essais.rs"]
mod essais;

struct Sortie {
    code: Option<i32>,
    texte: String,
    erreurs: String,
}

/// Un dossier personnel neuf pour chaque lancement, retiré à la fin de l'essai même s'il échoue ou se dit sauté.
fn maison_jetable() -> essais::Jetable {
    essais::Jetable::nouveau("essai")
}

/// Wine (tests Windows faits depuis Linux) n'a pas de PowerShell : les lectures du système y échouent, et c'est dit.
fn sous_wine() -> bool {
    cfg!(windows) && Path::new(r"C:\windows\system32\wineboot.exe").is_file()
}

fn lire_en_fond(mut flux: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut octets = Vec::new();
        let _ = flux.read_to_end(&mut octets);
        String::from_utf8_lossy(&octets).into_owned()
    })
}

/// Lance Vanguard en `langue` avec `entree` tapée d'avance, et l'attend au plus `secondes` (tué au-delà : un menu
/// qui ne rend pas la main est un défaut).
fn vanguard(langue: &str, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    let maison = maison_jetable();
    let sortie = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        langue,
        args,
        entree,
        secondes,
    );
    let _ = std::fs::remove_dir_all(&maison);
    sortie
}

/// Comme `vanguard`, avec un programme et un dossier personnel donnés (gardé après le lancement).
fn vanguard_dans(programme: &Path, maison: &Path, langue: &str, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    vanguard_dans_env(programme, maison, langue, args, entree, secondes, &[])
}

/// Comme `vanguard_dans`, avec des variables d'environnement en plus.
fn vanguard_dans_env(
    programme: &Path,
    maison: &Path,
    langue: &str,
    args: &[&str],
    entree: &str,
    secondes: u64,
    env: &[(&str, &str)],
) -> Sortie {
    let mut commande = Command::new(programme);
    commande.envs(env.iter().copied());
    commande
        .args(args)
        .env("VANGUARD_LANG", langue)
        // La vraie clé (cherchée dans /run/media/$USER, journal compris) et la vraie session (systemctl --user) restent
        // hors de portée : sinon le programme écrirait sur la clé, et la surveillance installée sous un ancien nom
        // serait reprise au nom de ce programme d'essai.
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("LOCALAPPDATA", maison.join("local"))
        .env("APPDATA", maison.join("roaming"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    attendre(commande, args, entree, secondes)
}

/// Lance `commande` (ses sorties en tubes), lui tape `entree`, et l'attend au plus `secondes`.
fn attendre(mut commande: Command, args: &[&str], entree: &str, secondes: u64) -> Sortie {
    // Un programme copié à l'instant (mise_a_jour_depuis_la_cle) peut être refusé « Text file busy » : un autre test
    // qui lance un processus au même moment a hérité, le temps de son exec, du fichier encore ouvert en écriture.
    // Quelques essais espacés suffisent ; toute autre erreur arrête le test.
    let mut essais = 0;
    let mut enfant = loop {
        match commande.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && essais < 20 => {
                essais += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.expect("vanguard ne démarre pas"),
        }
    };
    // Les sorties sont lues pendant que le programme tourne : un tube plein le bloquerait.
    let texte = lire_en_fond(enfant.stdout.take().unwrap());
    let erreurs = lire_en_fond(enfant.stderr.take().unwrap());
    {
        let mut stdin = enfant.stdin.take().unwrap();
        let _ = stdin.write_all(entree.as_bytes());
    }
    let fin = Instant::now() + Duration::from_secs(secondes);
    let code = loop {
        if let Some(statut) = enfant.try_wait().unwrap() {
            break statut.code();
        }
        if Instant::now() > fin {
            let _ = enfant.kill();
            panic!("vanguard {args:?} n'a pas rendu la main en {secondes} s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Sortie {
        code,
        texte: texte.join().unwrap_or_default(),
        erreurs: erreurs.join().unwrap_or_default(),
    }
}

/// Le texte sans les codes de couleur.
fn sans_couleurs(t: &str) -> String {
    let mut propre = String::with_capacity(t.len());
    let mut dans_code = false;
    for c in t.chars() {
        match (dans_code, c) {
            (false, '\x1b') => dans_code = true,
            (true, c) if c.is_ascii_alphabetic() => dans_code = false,
            (true, _) => {}
            (false, c) => propre.push(c),
        }
    }
    propre
}

#[test]
fn version() {
    let s = vanguard("fr", &["--version"], "", 30);
    assert_eq!(s.code, Some(0));
    assert_eq!(s.texte.trim(), format!("vanguard {}", env!("CARGO_PKG_VERSION")));
}

/// Un tube nommé ou un lien vers /dev/zero posé à la place d'un fichier d'état (par n'importe quel programme du
/// compte) ne fige jamais Vanguard ni ne lui fait charger sans fin : ni au lancement (`--version` lit les réglages et
/// les clés connues), ni pour « Ce que Vanguard a changé », ni pour les Paramètres, qui lisent la plupart d'entre eux.
#[cfg(unix)]
#[test]
fn fichiers_d_etat_piegees_ne_figent_rien() {
    const ETAT: &[&str] = &[
        "parametres.json",
        "cles-connues.json",
        "changements.jsonl",
        "blocage.json",
        "sceaux.json",
        "sceaux.verrou",
        "sceaux.temoin",
        "historique.json",
        "reglages.json",
        "appris.json",
        "normales.json",
        "temps-reel.json",
        "administrateurs.json",
        "bluetooth.json",
        "ports-bloques.txt",
        "entretien.json",
        "connexion.json",
        "surveillance-alertes.jsonl",
        "surveillance-passe.txt",
        "appareils.json",
        "evenements.tete",
        "jeux.json",
        "sauvegarde.json",
        "pieges.json",
        "evenements.verrou",
        "appareils.verrou",
        "alertes.verrou",
        "journal-erreurs.txt",
    ];
    for piege in ["tube", "zero"] {
        let maison = maison_jetable();
        let donnees = dossier_vanguard(&maison);
        std::fs::create_dir_all(&donnees).unwrap();
        for nom in ETAT {
            let chemin = donnees.join(nom);
            if piege == "tube" {
                essais::tube_nomme(&chemin).unwrap_or_else(|e| panic!("{nom} : {e}"));
            } else {
                std::os::unix::fs::symlink("/dev/zero", &chemin).unwrap();
            }
        }
        let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
        for args in [&["--version"][..], &["changements"], &["parametres"]] {
            let s = vanguard_dans_env(programme, &maison, "fr", args, "", 60, &[("VANGUARD_HORS_LIGNE", "1")]);
            assert_eq!(s.code, Some(0), "{piege} {args:?} : {}", s.erreurs);
        }
        let _ = std::fs::remove_dir_all(&maison);
    }
}

/// parametres.json changé hors de Vanguard (sans son sceau) : le lancement ne fige pas (la langue se lit dans ce
/// fichier, et la raison n'est traduite qu'à l'affichage), la langue reste, le travail sans Internet qu'il demandait
/// ne coupe rien, et les Paramètres le disent.
#[cfg(unix)]
#[test]
fn parametres_changes_hors_de_vanguard_dits_sans_rien_couper() {
    let maison = maison_jetable();
    let donnees = dossier_vanguard(&maison);
    std::fs::create_dir_all(&donnees).unwrap();
    std::fs::write(
        donnees.join("sceaux.json"),
        r#"{"depuis":"2026-10-01","fichiers":{},"vus":["parametres.json"]}"#,
    )
    .unwrap();
    std::fs::write(donnees.join("parametres.json"), r#"{"langue":"en","hors_ligne":true}"#).unwrap();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let s = vanguard_dans_env(programme, &maison, "en", &["--version"], "", 30, &[]);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let s = vanguard_dans_env(programme, &maison, "en", &["parametres"], "", 30, &[]);
    let texte = sans_couleurs(&s.texte);
    assert!(texte.contains("changed outside Vanguard"), "{texte}");
    let _ = std::fs::remove_dir_all(&maison);
}

/// Les animations de la fenêtre, gardées par le vrai programme : `couleurs --animations reduites` les écrit (journal
/// noté), un lancement suivant les relit dans `couleurs --json` ; parametres.json changé hors de Vanguard ensuite :
/// rien d'écrit par-dessus (code 1, la raison dite), et les animations relues sont « toutes ».
#[cfg(unix)]
#[test]
fn les_animations_de_la_fenetre_se_gardent_d_une_ouverture_a_l_autre() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let derniere = |s: &Sortie| -> serde_json::Value {
        serde_json::from_str(s.texte.lines().last().unwrap_or_default()).unwrap_or_default()
    };
    let lu = vanguard_dans(programme, &maison, "fr", &["couleurs", "--json"], "", 30);
    assert_eq!(
        (lu.code, derniere(&lu)["animations"].as_str()),
        (Some(0), Some("toutes")),
        "{}",
        lu.erreurs
    );
    let fait = vanguard_dans(
        programme,
        &maison,
        "fr",
        &["couleurs", "--animations", "reduites", "--json"],
        "",
        30,
    );
    let j = derniere(&fait);
    assert_eq!(fait.code, Some(0), "{} {}", fait.texte, fait.erreurs);
    assert_eq!(
        (j["geste"].as_str(), j["issue"].as_str()),
        (Some("animations"), Some("fait"))
    );
    assert_eq!(
        (j["avant"].as_str(), j["apres"].as_str()),
        (Some("toutes"), Some("reduites"))
    );
    let relu = vanguard_dans(programme, &maison, "fr", &["couleurs", "--json"], "", 30);
    assert_eq!(
        derniere(&relu)["animations"].as_str(),
        Some("reduites"),
        "{}",
        relu.texte
    );
    // Mal formé : code 2, rien d'écrit.
    let fichier = dossier_vanguard(&maison).join("parametres.json");
    let avant = std::fs::read(&fichier).unwrap();
    let mal = vanguard_dans(
        programme,
        &maison,
        "fr",
        &["couleurs", "--animations", "aucune"],
        "",
        30,
    );
    assert_eq!(mal.code, Some(2), "{}", mal.texte);
    assert_eq!(std::fs::read(&fichier).unwrap(), avant);
    // Un programme du compte réécrit le fichier : il n'est pas écrasé, et ses « réduites » ne valent pas.
    std::fs::write(&fichier, r#"{"couleurs":{"animations_reduites":true},"langue":"fr"}"#).unwrap();
    let refus = vanguard_dans(
        programme,
        &maison,
        "fr",
        &["couleurs", "--animations", "toutes"],
        "",
        30,
    );
    assert_eq!(refus.code, Some(1), "{}", refus.texte);
    assert!(
        sans_couleurs(&refus.texte)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .contains("rien n'est enregistré par-dessus"),
        "{}",
        refus.texte
    );
    assert_eq!(
        std::fs::read(&fichier).unwrap(),
        br#"{"couleurs":{"animations_reduites":true},"langue":"fr"}"#
    );
    let douteux = derniere(&vanguard_dans(
        programme,
        &maison,
        "fr",
        &["couleurs", "--json"],
        "",
        30,
    ));
    assert_eq!(
        (douteux["animations"].as_str(), douteux["douteux"].as_str()),
        (Some("toutes"), Some("hors_vanguard"))
    );
    let _ = std::fs::remove_dir_all(&maison);
}

/// F4 (E-M1) : sceaux.json ramené à une forme d'avant (`format` absent) et parametres.json retiré de ses `vus`, sans
/// la tête du journal qui prouverait une vraie mise à jour : rien n'est repris d'une « mise à jour », le
/// parametres.json forgé est dit accepté tel quel après des sceaux refaits, et rien de ce qu'il dit n'est appliqué.
#[cfg(unix)]
#[test]
fn sceaux_ramenes_a_une_forme_d_avant_ne_font_rien_croire() {
    let maison = maison_jetable();
    let donnees = dossier_vanguard(&maison);
    std::fs::create_dir_all(&donnees).unwrap();
    std::fs::write(
        donnees.join("sceaux.json"),
        r#"{"depuis":"2026-10-01","fichiers":{},"vus":["pieges.json"]}"#,
    )
    .unwrap();
    std::fs::write(
        donnees.join("parametres.json"),
        r#"{"langue":"en","hors_ligne":true,"sans_autotest":true}"#,
    )
    .unwrap();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let s = vanguard_dans_env(programme, &maison, "en", &["parametres"], "", 30, &[]);
    let texte = sans_couleurs(&s.texte);
    assert!(texte.contains("accepted as it was after seals were remade"), "{texte}");
    let _ = std::fs::remove_dir_all(&maison);
}

/// F4 (relecture du delta, bloquante) : une 0.86 ou une 0.87 qui n'avait rien noté au journal, mise à jour, puis le
/// menu ouvert et quitté. Le journal prenait son verrou et créait son dossier avant que les sceaux d'avant soient
/// jugés : ses propres traces les faisaient dire refaits (élevé). Jugés d'abord : « sans journal », rien de refait.
#[cfg(unix)]
#[test]
fn une_version_d_avant_sans_journal_ne_se_dit_pas_refaite_au_menu() {
    let maison = maison_jetable();
    let donnees = dossier_vanguard(&maison);
    std::fs::create_dir_all(&donnees).unwrap();
    std::fs::write(donnees.join("sceaux.json"), r#"{"depuis":"2026-10-01","fichiers":{}}"#).unwrap();
    std::fs::write(donnees.join("parametres.json"), r#"{"langue":"en"}"#).unwrap();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let s = vanguard_dans_env(
        programme,
        &maison,
        "en",
        &[],
        "q\n",
        60,
        &[("VANGUARD_HORS_LIGNE", "1")],
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let sceaux: serde_json::Value =
        serde_json::from_slice(&std::fs::read(donnees.join("sceaux.json")).unwrap()).unwrap();
    assert_ne!(sceaux["refaits"], serde_json::Value::Bool(true), "{sceaux}");
    assert!(sceaux["sans_journal"].is_string(), "{sceaux}");
    let _ = std::fs::remove_dir_all(&maison);
}

/// F4 (E-M2) : sceaux.verrou gardé par un autre programme du compte : la commande n'attend plus chaque prise du verrou
/// (il en fallait des minutes), mais une seule fois, puis une seconde en tout ; `--version` ne l'attend pas. Ce qui
/// devait se noter et ne l'a pas pu n'est pas perdu en silence : le verrou rendu, le journal se lit « incomplet ».
#[cfg(unix)]
#[test]
fn verrou_des_sceaux_garde_ailleurs_court_et_dit() {
    let maison = maison_jetable();
    let donnees = dossier_vanguard(&maison);
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let hors_ligne = [("VANGUARD_HORS_LIGNE", "1")];
    let lien = ["lien", "https://example.com", "--json"];
    let s = vanguard_dans_env(programme, &maison, "en", &lien, "", 60, &hors_ligne);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let verrou = std::fs::File::open(donnees.join("sceaux.verrou")).unwrap();
    verrou.lock().unwrap();
    let debut = std::time::Instant::now();
    let s = vanguard_dans_env(programme, &maison, "en", &["--version"], "", 30, &[]);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(
        debut.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        debut.elapsed()
    );
    let debut = std::time::Instant::now();
    let s = vanguard_dans_env(programme, &maison, "en", &lien, "", 120, &hors_ligne);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    // Avant : 140 s pour ce seul `lien` ; une attente, puis une seconde en tout.
    assert!(
        debut.elapsed() < std::time::Duration::from_secs(45),
        "{:?}",
        debut.elapsed()
    );
    verrou.unlock().unwrap();
    let s = vanguard_dans_env(programme, &maison, "en", &["evenements", "--json"], "", 60, &hors_ligne);
    assert!(s.texte.contains(r#""etat": "incomplet""#), "{}", s.texte);
    assert!(s.texte.contains("not noted"), "{}", s.texte);
    let _ = std::fs::remove_dir_all(&maison);
}

#[test]
fn aide_dans_les_deux_langues() {
    let fr = vanguard("fr", &["--help"], "", 30);
    assert_eq!(fr.code, Some(0));
    for commande in ["bilan", "audit", "logiciels", "nettoyer", "reparer", "mises-a-jour"] {
        assert!(fr.texte.contains(commande), "aide sans « {commande} »");
    }
    let en = vanguard("en", &["nettoyer", "--help"], "", 30);
    assert!(en.texte.contains("Clean up the system"), "{}", en.texte);
    assert!(en.texte.contains("--liste") && en.texte.contains("deleting nothing"));
}

// « defender », l'ancienne commande des blocages, mène aux Options de défense (alias) ; ailleurs que sous Windows,
// rien à proposer et rien changé.
#[test]
fn defender_mene_aux_options_de_defense() {
    let aide = vanguard("en", &["defender", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("Windows defense options"),
        "{}",
        aide.texte
    );
    if !cfg!(windows) {
        let r = vanguard("en", &["defender"], "", 30);
        assert_eq!(r.code, Some(0));
        // Sous Linux, l'écran du pare-feu de Linux (D7c) ; ailleurs, « Windows seulement ».
        let attendu = if cfg!(target_os = "linux") {
            "Linux firewall"
        } else {
            "Windows only"
        };
        assert!(sans_couleurs(&r.texte).contains(attendu), "{}", r.texte);
    }
}

/// Options de défense, sans rien choisir (l'entrée se ferme tout de suite). Sous Linux, l'état du pare-feu de Linux est
/// lu sans droits (rien demandé, rien de fait, aucune règle dans le JSON) ; sous Windows (Wine compris), il ne plante
/// pas, ne demande rien à l'administrateur et ne porte aucun texte du système dans le JSON.
#[test]
fn options_defense_sans_choix() {
    let aide = vanguard("en", &["options-defense", "--help"], "", 30);
    let t = sans_couleurs(&aide.texte);
    assert!(t.contains("Windows defense options"), "{t}");
    // Chaque entrée qui change quelque chose est dans l'aide, avec ce qui la confirme.
    for o in ["--choisir", "--rallumer", "--exclure", "--permettre", "--noter"] {
        assert!(t.contains(o), "{o} : {t}");
    }
    let linux = cfg!(target_os = "linux");
    for (langue, titre, seulement) in [
        (
            "fr",
            "Options de défense",
            if linux {
                "Pare-feu de Linux"
            } else {
                "Windows seulement"
            },
        ),
        (
            "en",
            "Defense options",
            if linux { "Linux firewall" } else { "Windows only" },
        ),
    ] {
        let r = vanguard(langue, &["options-defense"], "", 60);
        assert_eq!(r.code, Some(0), "{}", r.erreurs);
        assert!(!r.erreurs.contains("panicked"), "{}", r.erreurs);
        let t = sans_couleurs(&r.texte);
        assert!(t.contains(titre), "{t}");
        // Rien choisi : aucune demande d'administrateur, rien de fait.
        assert!(!t.contains("administrateur") && !t.contains("administrator"), "{t}");
        if !cfg!(windows) {
            assert!(t.contains(seulement), "{t}");
        }
    }
    let r = vanguard("fr", &["options-defense", "--json"], "", 60);
    assert_eq!(r.code, Some(0), "{}", r.erreurs);
    let v: serde_json::Value = serde_json::from_str(&r.texte).expect("JSON");
    assert_eq!(v["version"], 1);
    assert_eq!(v["lecture_seule"], true);
    assert_eq!(v["disponible"], cfg!(windows) || linux);
    if linux {
        assert_eq!(v["systeme"], "linux");
        let pf = v["pare_feu"].as_array().expect("pare_feu");
        let ids: Vec<&str> = pf.iter().filter_map(|x| x["id"].as_str()).collect();
        assert_eq!(ids, ["pare-feu-ufw", "pare-feu-firewalld", "pare-feu-nftables"]);
        // Des identifiants et des états seulement : aucune règle n'est lue sans droits.
        assert!(pf.iter().all(|x| x["regles_lues"] == false), "{v}");
    } else if !cfg!(windows) {
        assert_eq!(v["raison"], "windows-seulement");
    }
}

#[test]
fn commande_inconnue_refusee() {
    let s = vanguard("fr", &["nimportequoi"], "", 30);
    assert_eq!(s.code, Some(2), "clap refuse une commande inconnue avec le code 2");
    assert!(s.erreurs.contains("nimportequoi"));
}

#[test]
fn menu_quitte_par_q_et_par_la_fin_de_l_entree() {
    let s = vanguard("fr", &[], "q\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("BILAN DE SÉCURITÉ") && t.contains("CYBERDÉFENSE") && t.contains("EN PLUS"),
        "{t}"
    );
    // Entrée fermée sans réponse (script, tâche planifiée) : le menu s'en va au lieu d'attendre.
    let ferme = vanguard("fr", &[], "", 60);
    assert_eq!(ferme.code, Some(0));
}

/// RELRO appliqué par le programme lui-même (src/socle/relro.rs) : le démarrage de musl laisse PT_GNU_RELRO
/// écrivable. Le programme est lancé sur son menu, qui attend une réponse ; sa plage RELRO, lue dans ses propres
/// en-têtes, doit être en lecture seule dans /proc/<pid>/maps pendant qu'il tourne.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
#[test]
fn relro_applique_par_le_programme() {
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let octets = std::fs::read(programme).unwrap();
    let u16_ = |o: usize| usize::from(u16::from_le_bytes(octets[o..o + 2].try_into().unwrap()));
    let u64_ = |o: usize| usize::try_from(u64::from_le_bytes(octets[o..o + 8].try_into().unwrap())).unwrap();
    assert_eq!(&octets[..6], b"\x7fELF\x02\x01", "ELF 64 bits petit-boutiste attendu");
    let (position, taille, nombre) = (u64_(0x20), u16_(0x36), u16_(0x38));
    let entetes: Vec<(u32, usize, usize, usize)> = (0..nombre)
        .map(|i| {
            let e = position + i * taille;
            let type_ = u32::from_le_bytes(octets[e..e + 4].try_into().unwrap());
            (type_, u64_(e + 8), u64_(e + 16), u64_(e + 40))
        })
        .collect();
    let Some(&(_, _, adresse, memoire)) = entetes.iter().find(|e| e.0 == 0x6474_e552) else {
        return essais::saute("programme sans PT_GNU_RELRO");
    };
    let premier = entetes
        .iter()
        .find(|e| e.0 == 1 && e.1 == 0)
        .expect("PT_LOAD à la position 0")
        .2;
    let chemin = std::fs::canonicalize(programme).unwrap();
    let maison = maison_jetable();
    let mut enfant = Command::new(programme)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("VANGUARD_LANG", "fr")
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("HOME", &*maison)
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("XDG_STATE_HOME", maison.join("etat"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let maps = format!("/proc/{}/maps", enfant.id());
    let masque = !0xFFF_usize;
    // Comme glibc : début et fin arrondis à la page inférieure (4 Kio sur x86-64).
    let plage = |base: usize| ((base + adresse) & masque, (base + adresse + memoire) & masque);
    let fin_attente = Instant::now() + Duration::from_secs(30);
    let mut vu = String::new();
    let protege = loop {
        let lu = std::fs::read_to_string(&maps).unwrap_or_default();
        let lignes: Vec<(usize, usize, String, usize, String)> = lu
            .lines()
            .filter_map(|l| {
                let mut champs = l.split_whitespace();
                let (a, b) = champs.next()?.split_once('-')?;
                let droits = champs.next()?.to_owned();
                let decalage = usize::from_str_radix(champs.next()?, 16).ok()?;
                let nom = champs.nth(2).unwrap_or("").to_owned();
                Some((
                    usize::from_str_radix(a, 16).ok()?,
                    usize::from_str_radix(b, 16).ok()?,
                    droits,
                    decalage,
                    nom,
                ))
            })
            .collect();
        let base = lignes
            .iter()
            .find(|l| l.3 == 0 && Path::new(&l.4) == chemin)
            .map(|l| l.0 - premier);
        if let Some(base) = base {
            let (debut, fin) = plage(base);
            let couvrants: Vec<&String> = lignes
                .iter()
                .filter(|l| l.0 < fin && l.1 > debut)
                .map(|l| &l.2)
                .collect();
            vu = format!("{debut:#x}-{fin:#x} : {couvrants:?}");
            if !couvrants.is_empty() && couvrants.iter().all(|d| d.starts_with("r-")) {
                break true;
            }
        }
        if Instant::now() > fin_attente || enfant.try_wait().unwrap().is_some() {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    if let Some(mut stdin) = enfant.stdin.take() {
        let _ = stdin.write_all(b"q\n");
    }
    let fin = Instant::now() + Duration::from_secs(30);
    while enfant.try_wait().unwrap().is_none() && Instant::now() < fin {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
    let _ = std::fs::remove_dir_all(&maison);
    assert!(protege, "plage RELRO écrivable ou introuvable dans {maps} : {vu}");
}

/// F4 (relecture du delta) : ouvrir le menu, sans rien d'autre, note la tête du journal ; c'est la preuve d'une vraie
/// mise à jour que lira la version suivante (sans elle, ce qu'elle reprendrait ne serait pas cru).
#[test]
fn le_menu_note_la_tete_du_journal() {
    let maison = maison_jetable();
    let s = vanguard_dans(Path::new(env!("CARGO_BIN_EXE_vanguard")), &maison, "fr", &[], "q\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let tete = dossier_vanguard(&maison).join("evenements.tete");
    let lu = std::fs::read_to_string(&tete).unwrap_or_default();
    assert!(lu.contains(env!("CARGO_PKG_VERSION")), "{tete:?} : {lu}");
    let _ = std::fs::remove_dir_all(&maison);
}

/// Le bilan aussi note la tête du journal, dès son début (même raison que le menu).
#[test]
fn le_bilan_note_la_tete_du_journal() {
    let maison = maison_jetable();
    let s = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["audit", "--json"],
        "",
        300,
    );
    assert!(s.code.is_some(), "{}", s.erreurs);
    let tete = dossier_vanguard(&maison).join("evenements.tete");
    let lu = std::fs::read_to_string(&tete).unwrap_or_default();
    assert!(lu.contains(env!("CARGO_PKG_VERSION")), "{tete:?} : {lu}");
    let _ = std::fs::remove_dir_all(&maison);
}

#[test]
fn sous_menu_optimiser() {
    // 12 : le groupe Optimiser et installer ; Entrée : revenir ; q : quitter.
    let s = vanguard("fr", &[], "12\n\nq\n", 60);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Logiciels recommandés") && t.contains("Nettoyer le système") && t.contains("Réglages recommandés"),
        "{t}"
    );
    assert_eq!(s.code, Some(0));
}

#[test]
fn logiciels_listes_sans_rien_installer() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let s = vanguard("fr", &["logiciels", "--liste"], "", 120);
    let t = sans_couleurs(&s.texte);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(
        t.contains("Navigateurs et courriel") && t.contains("logiciels proposés ici"),
        "{t}"
    );
    // Le menu, quitté tout de suite.
    let menu = vanguard("fr", &["logiciels"], "\n", 120);
    assert!(sans_couleurs(&menu.texte).contains("Pack de départ"));
}

#[test]
fn nettoyer_mesure_puis_refus() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let liste = vanguard("fr", &["nettoyer", "--liste"], "", 120);
    assert_eq!(liste.code, Some(0), "{}", liste.erreurs);
    assert!(sans_couleurs(&liste.texte).contains("Rien n'a été effacé"));
    // Entrée garde les cases cochées d'office ; « n » à la question : rien n'est fait.
    let refus = vanguard("fr", &["nettoyer"], "\nn\n", 120);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("Annulé") || t.contains("Rien à nettoyer"), "{t}");
}

/// Une entrée d'un instantané : sorte et droits (le mode entier), taille, date, date du dernier changement d'inode
/// (ctime, en secondes et nanosecondes : un chmod ou un chown au même mode s'y voit), puis le contenu d'un fichier
/// (BLAKE3) ou la cible d'un lien.
#[cfg(unix)]
type Entree = (u32, u64, Option<std::time::SystemTime>, (i64, i64), String);

/// Ce qu'il y a dans un dossier, lui compris, entrée par entrée (chemin relatif), sans suivre les liens. Assez pour
/// voir une entrée créée, effacée, réécrite ou seulement retouchée, un droit changé ou un lien redirigé.
#[cfg(unix)]
fn instantane(racine: &Path) -> std::collections::BTreeMap<String, Entree> {
    use std::os::unix::fs::MetadataExt;
    let mut vus = std::collections::BTreeMap::new();
    let mut a_voir = vec![racine.to_path_buf()];
    while let Some(p) = a_voir.pop() {
        let Ok(m) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        let contenu = if m.is_file() {
            blake3::hash(&std::fs::read(&p).unwrap_or_default())
                .to_hex()
                .to_string()
        } else if m.file_type().is_symlink() {
            format!(
                "-> {}",
                std::fs::read_link(&p)
                    .map(|c| c.display().to_string())
                    .unwrap_or_default()
            )
        } else {
            String::new()
        };
        let nom = p.strip_prefix(racine).unwrap().to_string_lossy().into_owned();
        vus.insert(
            nom,
            (
                m.mode(),
                m.len(),
                m.modified().ok(),
                (m.ctime(), m.ctime_nsec()),
                contenu,
            ),
        );
        if m.is_dir() {
            a_voir.extend(std::fs::read_dir(&p).into_iter().flatten().flatten().map(|e| e.path()));
        }
    }
    vus
}

/// Ce qui diffère d'un instantané à l'autre : entrées effacées, changées, créées.
#[cfg(unix)]
fn ecarts(
    avant: &std::collections::BTreeMap<String, Entree>,
    apres: &std::collections::BTreeMap<String, Entree>,
) -> Vec<String> {
    let mut ecarts = Vec::new();
    for (nom, a) in avant {
        match apres.get(nom) {
            None => ecarts.push(format!("effacé « {nom} »")),
            Some(b) if b != a => ecarts.push(format!("changé « {nom} » : {a:?} -> {b:?}")),
            Some(_) => {}
        }
    }
    ecarts.extend(
        apres
            .keys()
            .filter(|n| !avant.contains_key(*n))
            .map(|n| format!("créé « {n} »")),
    );
    ecarts
}

/// `vanguard <args>` sous un environnement VIDÉ (`env_clear`), comme le lancerait un autre programme : le dossier
/// personnel `maison`, et les dossiers XDG et temporaire HORS de lui, dans `dehors` (vérification de Fable n° 2, L5).
#[cfg(unix)]
fn vanguard_a_vide(programme: &Path, maison: &Path, dehors: &Path, args: &[&str]) -> Sortie {
    let mut commande = Command::new(programme);
    commande
        .env_clear()
        .args(args)
        .env("PATH", "/usr/bin:/bin")
        .env("VANGUARD_LANG", "fr")
        .env("USER", "essai")
        .env("HOME", maison)
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", dehors.join("run"))
        .env("XDG_DATA_HOME", dehors.join("donnees"))
        .env("XDG_CONFIG_HOME", dehors.join("config"))
        .env("XDG_CACHE_HOME", dehors.join("cache"))
        .env("XDG_STATE_HOME", dehors.join("etat"))
        .env("TMPDIR", dehors.join("tmp"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    attendre(commande, args, "", 300)
}

/// Les règles que l'aperçu relance (`RELUES_SANS_PROGRAMME` de `machine::apercu`), recopiées : une règle ajoutée là
/// sans l'être ici fait échouer `voir_une_correction_n_ecrit_rien`, qui la relance alors dans un dossier vide.
#[cfg(unix)]
const RELANCEES: &[&str] = &[
    "LNX-SSH-003",
    "LNX-PRV-001",
    "LNX-NOY-003",
    "LNX-NOY-007",
    "LNX-RES-003",
    "LNX-NOY-004",
    "LNX-MAT-001",
    "LNX-PRV-004",
];

/// `correction --voir` ne change rien, quelle que soit la règle que désigne le jeton : chaque règle du bilan relancée
/// par un jeton à son nom (les 4 premiers octets ; la clé, inventée, ne répond à aucun constat), chacune dans un
/// dossier personnel VIDE, sans premier lancement ni sceaux (vérification de Fable, R1 et E1 : un premier lancement
/// cachait les sceaux écrits avant l'interrupteur de lecture seule), comparé entrée par entrée, droits et liens
/// compris. Une règle de la liste permise est relancée, puis dite disparue ; les autres sont refusées sans être
/// lancées (elles lancent d'autres programmes, qui écrivent leurs propres fichiers).
#[cfg(unix)]
#[test]
fn voir_une_correction_n_ecrit_rien() {
    let ids: Vec<String> = {
        let s = vanguard("fr", &["regles", "--json"], "", 60);
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        let v: serde_json::Value = serde_json::from_str(&s.texte).expect("regles --json : JSON illisible");
        v["bilan"]
            .as_array()
            .expect("pas de règles")
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert!(ids.len() > 30, "{} règles seulement", ids.len());
    for r in RELANCEES {
        assert!(ids.iter().any(|i| i == r), "{r} n'est plus une règle du bilan");
    }
    let jeton = |id: &str| {
        let r = blake3::derive_key("vanguard jeton v1 regle", id.as_bytes());
        format!("{}{}", &blake3::Hash::from(r).to_hex()[..8], "5a".repeat(12))
    };
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let fautes = std::sync::Mutex::new(Vec::new());
    let suivant = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..8 {
            s.spawn(|| {
                loop {
                    let i = suivant.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let Some(id) = ids.get(i) else { break };
                    let j = jeton(id);
                    let args = ["correction", "--voir", &j, "--json"];
                    // Chaque règle sous un environnement vidé, XDG et dossier temporaire hors du dossier personnel,
                    // les deux arbres comparés ; les règles relancées aussi avec XDG et dossier temporaire dedans.
                    let relancee = RELANCEES.contains(&id.as_str());
                    for dedans in [false, true] {
                        if dedans && !relancee {
                            continue;
                        }
                        let maison = maison_jetable();
                        let dehors = maison_jetable();
                        let tmp = if dedans { maison.join("tmp") } else { dehors.join("tmp") };
                        std::fs::create_dir_all(&tmp).unwrap();
                        let avant = (instantane(&maison), instantane(&dehors));
                        let sortie = if dedans {
                            let env = &[("TMPDIR", tmp.to_str().unwrap())];
                            vanguard_dans_env(programme, &maison, "fr", &args, "", 300, env)
                        } else {
                            vanguard_a_vide(programme, &maison, &dehors, &args)
                        };
                        let mut changes = ecarts(&avant.0, &instantane(&maison));
                        changes.extend(ecarts(&avant.1, &instantane(&dehors)));
                        let derniere: serde_json::Value =
                            serde_json::from_str(sortie.texte.lines().last().unwrap_or_default()).unwrap_or_default();
                        let ou = if dedans { "XDG dedans" } else { "env vidé, XDG dehors" };
                        let mut f = fautes.lock().unwrap();
                        if sortie.code != Some(1)
                            || derniere["geste"] != "voir-correction"
                            || derniere["issue"] != "refuse"
                        {
                            f.push(format!(
                                "{id} ({ou}) : code {:?}, {} {}",
                                sortie.code, sortie.texte, sortie.erreurs
                            ));
                        }
                        let raison = derniere["raison"].as_str().unwrap_or_default();
                        let attendue = if relancee {
                            raison.starts_with("ce problème a disparu")
                        } else {
                            raison.contains("lance d'autres programmes")
                        };
                        if !attendue {
                            f.push(format!("{id} ({ou}) : raison inattendue « {raison} »"));
                        }
                        if !changes.is_empty() {
                            f.push(format!("{id} ({ou}) : {changes:?}"));
                        }
                    }
                }
            });
        }
    });
    let fautes = fautes.into_inner().unwrap();
    assert!(fautes.is_empty(), "correction --voir :\n{}", fautes.join("\n"));
}

/// Les corrections du compte (droits de ~/.ssh, d'une clé, du dossier personnel, des fichiers secrets) offrent
/// « Voir la correction » dans le bilan, et leur aperçu se fait sans mot de passe d'administrateur. Rien n'est changé
/// par les vrais jetons du bilan (vérification de Fable, E1) : le dossier personnel, comparé entrée par entrée après
/// le bilan puis après les aperçus, droits et liens compris ; puis de même, les fichiers JSON de Vanguard abîmés
/// (R2 : une erreur de lecture notée au journal l'écrivait).
#[cfg(unix)]
#[test]
fn les_corrections_du_compte_offrent_l_apercu() {
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let maison = maison_jetable();
    let ssh = maison.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::write(ssh.join("id_essai"), "clé inventée\n").unwrap();
    std::fs::write(maison.join(".netrc"), "machine exemple.invalid login alice\n").unwrap();
    let modes = [
        (maison.to_path_buf(), 0o755),
        (ssh.clone(), 0o755),
        (ssh.join("id_essai"), 0o644),
        (maison.join(".netrc"), 0o644),
    ];
    for (chemin, mode) in &modes {
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
    let bilan = vanguard_dans(programme, &maison, "fr", &["audit", "--json"], "", 300);
    assert!(matches!(bilan.code, Some(0 | 1)), "{}", bilan.erreurs);
    let v: serde_json::Value = serde_json::from_str(&bilan.texte).expect("audit --json : JSON illisible");
    let jetons: Vec<String> = v["constats"]
        .as_array()
        .expect("pas de constats")
        .iter()
        .filter_map(|c| c["geste"]["jeton"].as_str().map(str::to_string))
        .collect();
    let attendus = [
        "chmod 700 ~/.ssh",
        "chmod 600 ~/.ssh/",
        "chmod 750 ~",
        "chmod 600 ~/.netrc",
    ];
    let voir_tout = || {
        let mut vus = Vec::new();
        for j in &jetons {
            let s = vanguard_dans(
                programme,
                &maison,
                "fr",
                &["correction", "--voir", j, "--json"],
                "",
                300,
            );
            let r: serde_json::Value =
                serde_json::from_str(s.texte.lines().last().unwrap_or_default()).unwrap_or_default();
            assert!(
                matches!(s.code, Some(0 | 1)) && r["geste"] == "voir-correction",
                "{j} : code {:?}, {} {}",
                s.code,
                s.texte,
                s.erreurs
            );
            if r["issue"] != "fait" || r["apercu"]["droits"] != "compte" {
                continue;
            }
            vus.extend(
                r["apercu"]["commandes"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str())
                    .map(str::to_string),
            );
        }
        vus
    };
    let avant = instantane(&maison);
    let vus = voir_tout();
    let changes = ecarts(&avant, &instantane(&maison));
    assert!(changes.is_empty(), "les aperçus ont écrit : {changes:?}");
    for a in attendus {
        assert!(
            vus.iter().any(|x| x.starts_with(a)),
            "{a} sans aperçu du compte : {vus:?}"
        );
    }
    // Vérification de Fable n° 2, L1 : des sceaux présents, leur verrou retiré. La ligne de commande, lue avant
    // l'interrupteur, le recréait (ses textes traduits lisent les réglages scellés).
    let verrous: Vec<&String> = avant.keys().filter(|n| n.ends_with("sceaux.verrou")).collect();
    assert!(!verrous.is_empty(), "pas de verrou des sceaux dans {:?}", avant.keys());
    assert!(avant.keys().any(|n| n.ends_with("sceaux.json")), "pas de sceaux");
    for v in verrous {
        std::fs::remove_file(maison.join(v)).unwrap();
    }
    let avant = instantane(&maison);
    let _ = voir_tout();
    let changes = ecarts(&avant, &instantane(&maison));
    assert!(changes.is_empty(), "les aperçus ont écrit, verrou absent : {changes:?}");
    // Les fichiers JSON de Vanguard abîmés : les aperçus ne les réparent pas, n'en notent rien, et répondent.
    let mut abimes = 0;
    for (nom, entree) in &avant {
        let chemin = maison.join(nom);
        if std::path::Path::new(nom).extension().is_some_and(|e| e == "json")
            && std::fs::symlink_metadata(&chemin).is_ok_and(|m| m.is_file())
            && entree.1 > 0
        {
            std::fs::write(&chemin, "{abîmé").unwrap();
            abimes += 1;
        }
    }
    assert!(abimes > 0, "aucun fichier JSON de Vanguard dans {:?}", avant.keys());
    let avant = instantane(&maison);
    let _ = voir_tout();
    let changes = ecarts(&avant, &instantane(&maison));
    assert!(
        changes.is_empty(),
        "les aperçus ont écrit, fichiers abîmés : {changes:?}"
    );
    for (chemin, mode) in &modes {
        let m = std::fs::metadata(chemin).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, *mode, "{} changé", chemin.display());
    }
}

/// Vérification de Fable n° 2, L6 : l'aperçu écrit dans une sortie fermée (tube sans lecteur) ou pleine (/dev/full)
/// sort proprement, code 141 comme les autres commandes, sans panique (code 101) ; rien n'est écrit.
#[cfg(unix)]
#[test]
fn l_apercu_dans_une_sortie_coupee_rend_141() {
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let jeton = format!("{}{}", "00".repeat(4), "5a".repeat(12));
    for pleine in [false, true] {
        let maison = maison_jetable();
        let dehors = maison_jetable();
        let avant = (instantane(&maison), instantane(&dehors));
        let mut c = Command::new(programme);
        c.env_clear()
            .args(["correction", "--voir", &jeton, "--json"])
            .env("PATH", "/usr/bin:/bin")
            .env("VANGUARD_LANG", "fr")
            .env("HOME", &*maison)
            .env("XDG_DATA_HOME", dehors.join("donnees"))
            .env("XDG_CONFIG_HOME", dehors.join("config"))
            .env("XDG_CACHE_HOME", dehors.join("cache"))
            .env("TMPDIR", &*dehors)
            .stdin(Stdio::null())
            .stderr(Stdio::piped());
        if pleine {
            c.stdout(std::fs::OpenOptions::new().write(true).open("/dev/full").unwrap());
        } else {
            let (lecteur, ecrivain) = std::io::pipe().unwrap();
            drop(lecteur);
            c.stdout(ecrivain);
        }
        let s = c.output().unwrap();
        let erreurs = String::from_utf8_lossy(&s.stderr);
        assert_eq!(s.status.code(), Some(141), "pleine {pleine} : {erreurs}");
        assert!(!erreurs.contains("panicked"), "{erreurs}");
        let mut changes = ecarts(&avant.0, &instantane(&maison));
        changes.extend(ecarts(&avant.1, &instantane(&dehors)));
        assert!(changes.is_empty(), "pleine {pleine} : {changes:?}");
    }
}

/// Vérification de Fable, V1 : une clé, ~/.ssh ou un fichier secret qui sont des liens symboliques ne donnent ni
/// correction ni jeton (un chmod changerait la cible, pas ce qui est montré) ; l'alerte reste, et nomme la cible.
#[cfg(unix)]
#[test]
fn un_lien_n_offre_pas_de_correction() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    for ssh_lie in [false, true] {
        let maison = maison_jetable();
        let ailleurs = maison_jetable();
        mode(&maison, 0o700);
        let cible_ssh = ailleurs.join("ssh");
        std::fs::create_dir_all(&cible_ssh).unwrap();
        std::fs::write(cible_ssh.join("id_cible"), "clé inventée\n").unwrap();
        std::fs::write(ailleurs.join("netrc"), "machine exemple.invalid login alice\n").unwrap();
        mode(&cible_ssh, 0o755);
        mode(&cible_ssh.join("id_cible"), 0o644);
        mode(&ailleurs.join("netrc"), 0o644);
        let ssh = maison.join(".ssh");
        let cle = if ssh_lie {
            symlink(&cible_ssh, &ssh).unwrap();
            "id_cible"
        } else {
            std::fs::create_dir_all(&ssh).unwrap();
            mode(&ssh, 0o700);
            symlink(cible_ssh.join("id_cible"), ssh.join("id_lien")).unwrap();
            "id_lien"
        };
        symlink(ailleurs.join("netrc"), maison.join(".netrc")).unwrap();
        let bilan = vanguard_dans(programme, &maison, "fr", &["audit", "--json"], "", 300);
        assert!(matches!(bilan.code, Some(0 | 1)), "{}", bilan.erreurs);
        let v: serde_json::Value = serde_json::from_str(&bilan.texte).expect("audit --json : JSON illisible");
        let mut attendus = vec![format!("~/.ssh/{cle}"), "~/.netrc".to_string()];
        if ssh_lie {
            attendus.push("~/.ssh est lisible".to_string());
        }
        for a in &attendus {
            let lies: Vec<&serde_json::Value> = v["constats"]
                .as_array()
                .expect("pas de constats")
                .iter()
                .filter(|c| c["message"].as_str().is_some_and(|m| m.contains(a.as_str())))
                .collect();
            assert!(!lies.is_empty(), "{a} n'est pas dit (lien de ~/.ssh : {ssh_lie})");
            for c in lies {
                let m = c["message"].as_str().unwrap_or_default();
                assert!(
                    c["geste"].is_null() && c["correctif"].is_null(),
                    "{a} corrigeable à travers un lien : {c}"
                );
                assert!(m.contains("est un lien vers"), "{m}");
            }
        }
    }
}

/// Les constats des catégories `categories` d'un `audit --json` lancé avec ce HOME : il doit rendre la main (un tube
/// nommé dans ~/.ssh le figeait).
#[cfg(unix)]
fn constats_du_bilan(programme: &Path, maison: &Path, categories: &[&str]) -> Vec<serde_json::Value> {
    let debut = std::time::Instant::now();
    let bilan = vanguard_dans(programme, maison, "fr", &["audit", "--json"], "", 120);
    assert!(
        matches!(bilan.code, Some(0 | 1)),
        "{:?} : {}",
        bilan.code,
        bilan.erreurs
    );
    assert!(debut.elapsed() < std::time::Duration::from_secs(100), "bilan trop long");
    let v: serde_json::Value = serde_json::from_str(&bilan.texte).expect("audit --json : JSON illisible");
    v["constats"]
        .as_array()
        .expect("pas de constats")
        .iter()
        .filter(|c| categories.iter().any(|k| c["categorie"] == *k))
        .cloned()
        .collect()
}

/// Les constats « Clés SSH » d'un `audit --json` lancé avec ce HOME (`constats_du_bilan`) ; aucun ne porte de
/// correction ni de geste.
#[cfg(unix)]
fn constats_ssh_sans_correction(programme: &Path, maison: &Path) -> Vec<serde_json::Value> {
    let ssh = constats_du_bilan(programme, maison, &["Clés SSH"]);
    for c in &ssh {
        assert!(c["geste"].is_null() && c["correctif"].is_null(), "corrigeable : {c}");
    }
    ssh
}

/// Vérification de Fable n° 2, liens L1, L2, L3, L4, L6 : dans ~/.ssh, un nom qui n'est pas UTF-8 (et son sosie au
/// caractère de remplacement, un lien), un dossier nommé comme une clé, une clé à deux noms, un tube nommé (à la place
/// d'une clé et de la configuration), un lien vers un périphérique sans fin ; puis un HOME lien écrit avec « / » ou
/// « /. » à la fin. Le bilan rend la main, chaque cas est dit, aucun ne reçoit de correction ni de jeton.
#[cfg(unix)]
#[test]
fn les_cas_limites_de_ssh_ne_donnent_ni_correction_ni_blocage() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let tube = |c: &Path| {
        let s = Command::new("mkfifo").arg(c).status().unwrap();
        assert!(s.success(), "mkfifo {}", c.display());
    };
    let maison = maison_jetable();
    let ailleurs = maison_jetable();
    mode(&maison, 0o700);
    let ssh = maison.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    mode(&ssh, 0o700);
    // L1 : le nom invalide, et le sosie que la commande écrite avec perte viserait (un lien vers un dossier 0700).
    let invalide = ssh.join(std::ffi::OsStr::from_bytes(b"id_\xff"));
    std::fs::write(&invalide, "clé inventée\n").unwrap();
    mode(&invalide, 0o644);
    std::fs::create_dir_all(ailleurs.join("cible")).unwrap();
    mode(&ailleurs.join("cible"), 0o700);
    symlink(ailleurs.join("cible"), ssh.join("id_\u{FFFD}")).unwrap();
    // L2 : un dossier nommé comme une clé.
    std::fs::create_dir_all(ssh.join("id_dossier")).unwrap();
    mode(&ssh.join("id_dossier"), 0o755);
    // L6 : une clé à deux noms.
    std::fs::write(ssh.join("id_double"), "clé inventée\n").unwrap();
    mode(&ssh.join("id_double"), 0o644);
    std::fs::hard_link(ssh.join("id_double"), ailleurs.join("double")).unwrap();
    // L3 : des tubes nommés et un lien vers un périphérique sans fin.
    tube(&ssh.join("id_tube"));
    mode(&ssh.join("id_tube"), 0o644);
    tube(&ssh.join("config"));
    symlink("/dev/zero", ssh.join("id_zero")).unwrap();
    let ssh_constats = constats_ssh_sans_correction(programme, &maison);
    let dit = |bout: &str, raison: &str| {
        assert!(
            ssh_constats.iter().any(|c| {
                let m = c["message"].as_str().unwrap_or_default();
                m.contains(bout) && m.contains(raison)
            }),
            "{bout} ({raison}) n'est pas dit : {ssh_constats:?}"
        );
    };
    dit("lisible par d'autres", "UTF-8");
    dit("~/.ssh/id_dossier", "n'est pas un simple fichier");
    dit("~/.ssh/id_double", "lien physique");
    dit("~/.ssh/id_tube", "n'est pas un simple fichier");
    dit("~/.ssh/id_zero", "est un lien vers /dev/zero");
    dit("~/.ssh/config non lu", "Impossible de vérifier");
    // L4 : le dossier personnel est un lien ; écrit avec « / » ou « /. » à la fin, il reste vu comme tel.
    let vrai = maison_jetable();
    mode(&vrai, 0o755);
    std::fs::create_dir_all(vrai.join(".ssh")).unwrap();
    mode(&vrai.join(".ssh"), 0o755);
    std::fs::write(vrai.join(".ssh/id_cle"), "clé inventée\n").unwrap();
    mode(&vrai.join(".ssh/id_cle"), 0o644);
    let parent = maison_jetable();
    let lien = parent.join("maison");
    symlink(&*vrai, &lien).unwrap();
    for fin in ["/", "/."] {
        let home = std::path::PathBuf::from(format!("{}{fin}", lien.display()));
        let c = constats_ssh_sans_correction(programme, &home);
        assert!(
            c.iter()
                .any(|c| c["message"].as_str().is_some_and(|m| m.contains("~ est un lien vers"))),
            "HOME {fin} : {c:?}"
        );
    }
}

/// Vérification de Fable n° 3 (M1, M2, M3) : ce que Vanguard n'a pas lu dans ~/.ssh n'est jamais compté sain. Un
/// fichier inclus par la configuration, plus gros que la borne de lecture : dit « non lu » (au bilan des clés et à
/// celui du client SSH). Un fichier inclus avec un octet hors UTF-8 dans un commentaire : lu quand même, son réglage
/// relâché signalé. Une clé sans phrase de passe, nommée autrement que id_*, en 0644, avec un octet hors UTF-8 après sa
/// fin : ses deux alertes. Un tube nommé, un tube id_* en 0600 et un lien vers un périphérique : dits « non lu », et
/// le bilan ne dit plus « Permissions de ~/.ssh correctes ». Une socket (ControlMaster) et un dossier : rien à dire.
#[cfg(unix)]
#[test]
fn ce_qui_n_est_pas_lu_dans_ssh_n_est_jamais_sain() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let tube = |c: &Path| {
        let s = Command::new("mkfifo").arg(c).status().unwrap();
        assert!(s.success(), "mkfifo {}", c.display());
    };
    let maison = maison_jetable();
    mode(&maison, 0o700);
    let ssh = maison.join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    mode(&ssh, 0o700);
    std::fs::write(ssh.join("config"), "Include inclus\nInclude gros\nInclude absent\n").unwrap();
    // M1 (a) : un octet hors UTF-8 dans un commentaire ; SSH applique le reste.
    std::fs::write(
        ssh.join("inclus"),
        b"# r\xe9glages du labo\nHost *\n    StrictHostKeyChecking no\n",
    )
    .unwrap();
    // M1 (b) : plus d'un Mio de lignes courtes, que SSH lit en entier.
    let mut gros = "# commentaire\n".repeat(80_000);
    gros.push_str("Host *\n    ForwardAgent yes\n");
    std::fs::write(ssh.join("gros"), gros).unwrap();
    // M2 : en-tête de clé inventé (chiffrement « none »), un octet de trop après la ligne de fin.
    let mut cle = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n\
                   -----END OPENSSH PRIVATE KEY-----\n"
        .to_vec();
    cle.push(0xff);
    std::fs::write(ssh.join("serveur"), cle).unwrap();
    mode(&ssh.join("serveur"), 0o644);
    // M3 : ce qui n'est pas un simple fichier, sous un nom quelconque ou id_* bien protégé.
    tube(&ssh.join("controle"));
    mode(&ssh.join("controle"), 0o600);
    tube(&ssh.join("id_tube"));
    mode(&ssh.join("id_tube"), 0o600);
    symlink("/dev/null", ssh.join("nul")).unwrap();
    // Jamais une clé : rien à dire.
    // Par le dossier ouvert (/proc/self/fd/N) : le chemin d'une prise est borné à 108 octets, et le dossier jetable
    // peut être plus long.
    let dossier_ssh = std::fs::File::open(&ssh).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(format!(
        "/proc/self/fd/{}/cm-alice@labo:22",
        std::os::fd::AsRawFd::as_raw_fd(&dossier_ssh)
    ))
    .unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(
        &std::fs::metadata(ssh.join("cm-alice@labo:22")).unwrap().file_type()
    ));
    std::fs::create_dir_all(ssh.join("sockets")).unwrap();
    mode(&ssh.join("sockets"), 0o755);
    let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Post-quantique"]);
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    let dit = |bouts: &[&str]| {
        assert!(
            constats.iter().any(|c| bouts.iter().all(|b| message(c).contains(b))),
            "{bouts:?} n'est pas dit : {constats:#?}"
        );
    };
    dit(&["~/.ssh/inclus, ligne 3", "sans vérifier qu'il est le bon"]);
    dit(&["Impossible de vérifier", "~/.ssh/gros non lu", "plus de 1024 Kio"]);
    dit(&["Clé privée ~/.ssh/serveur sans phrase de passe"]);
    dit(&["Clé privée ~/.ssh/serveur lisible par d'autres"]);
    for nom in ["controle", "id_tube", "nul"] {
        dit(&[
            "Impossible de vérifier",
            &format!("~/.ssh/{nom} non lu"),
            "pas un simple fichier",
        ]);
    }
    // Chaque fichier non lu est dit une fois, même quand la revue des clés et la configuration le croisent toutes deux.
    let mut vus = std::collections::BTreeSet::new();
    for c in &constats {
        let m = message(c);
        assert!(vus.insert(m.clone()), "dit deux fois : {m}");
        assert!(
            !m.contains("~/.ssh correctes"),
            "sain alors que tout n'est pas lu : {m}"
        );
        for rien in ["cm-alice", "~/.ssh/sockets", "~/.ssh/absent"] {
            assert!(!m.contains(rien), "{rien} : {m}");
        }
        if m.starts_with("Impossible de vérifier") {
            assert_eq!(c["verifie"], false, "{c}");
        }
    }
    // Le client SSH ne se juge pas sans le fichier inclus non lu (il peut porter les algorithmes d'échange).
    let client = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .iter()
        .any(|p| Path::new(p).exists());
    let attendu = if client {
        "Client SSH : échange de clés post-quantique non vérifié (illisible : ~/.ssh/gros non lu : plus de 1024 Kio)"
    } else {
        "Pas de client OpenSSH"
    };
    assert!(
        constats.iter().any(|c| message(c).contains(attendu)),
        "{attendu} : {constats:#?}"
    );
}

/// Vérification de Fable n° 4 (N1, N2, N3). Un motif d'Include que Vanguard ne résout pas comme SSH (joker dans un
/// dossier, crochets, variable, jeton, « ~nom », guillemets avec une espace, apostrophes, barre oblique inverse, mot-clé
/// entre guillemets) : le fichier que SSH lit relâche la vérification des serveurs, et le bilan dit le motif non lu,
/// jamais « ~/.ssh correctes ». Les formes simples restent lues et signalées à leur ligne. Un éventail d'inclusions
/// s'arrête au plafond, dit une fois. ~/.ssh et ~/.netrc en boucle de liens : non vérifiés, ni absents ni protégés.
#[cfg(unix)]
#[test]
fn un_include_que_vanguard_ne_resout_pas_est_dit_non_lu() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let relache = "Host *\n    StrictHostKeyChecking no\n";
    let client = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .iter()
        .any(|p| Path::new(p).exists());
    // Une maison jetable : ~/.ssh/config, et le fichier relâché à chaque endroit qu'un des motifs vise chez SSH.
    let preparer = |config: &str| {
        let maison = maison_jetable();
        mode(&maison, 0o700);
        let ssh = maison.join(".ssh");
        std::fs::create_dir_all(ssh.join("d1")).unwrap();
        mode(&ssh, 0o700);
        std::fs::write(ssh.join("config"), config).unwrap();
        for nom in ["inclus", "d1/inclus", "mon inclus"] {
            std::fs::write(ssh.join(nom), relache).unwrap();
        }
        maison
    };
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    let formes = [
        "Include d*/inclus",
        "Include incl[u]s",
        "Include ${HOME}/.ssh/inclus",
        "Include %d/.ssh/inclus",
        "Include ~alice/.ssh/inclus",
        "Include \"mon inclus\"",
        "Include 'inclus'",
        "Include incl\\us",
        "\"Include\" inclus",
    ];
    std::thread::scope(|fils| {
        let mut attentes = Vec::new();
        for forme in formes {
            attentes.push(fils.spawn(move || {
                let maison = preparer(&format!("{forme}\n"));
                let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Post-quantique"]);
                assert!(
                    constats.iter().any(|c| {
                        let m = message(c);
                        m.starts_with("Impossible de vérifier")
                            && (m.contains(" non lu : motif d'inclusion non interprété (~/.ssh/config, ligne 1)")
                                || m.contains(" non lu : forme non interprétée (~/.ssh/config, ligne 1)"))
                            && c["verifie"] == false
                    }),
                    "{forme} : {constats:#?}"
                );
                for c in &constats {
                    let m = message(c);
                    assert!(
                        !m.contains("~/.ssh correctes"),
                        "{forme} : sain sans avoir tout lu : {m}"
                    );
                }
                if client {
                    assert!(
                        constats.iter().any(|c| {
                            let m = message(c);
                            m.contains("Client SSH : échange de clés post-quantique non vérifié")
                                && m.contains(" non interprét")
                        }),
                        "{forme} : client jugé sans le motif : {constats:#?}"
                    );
                }
            }));
        }
        // Témoins : les formes simples sont lues, le réglage relâché signalé à sa ligne.
        for forme in [
            "Include inclus",
            "Include ~/.ssh/inclus",
            "Include=\"inclus\" # commentaire",
        ] {
            attentes.push(fils.spawn(move || {
                let maison = preparer(&format!("{forme}\n"));
                let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
                assert!(
                    constats.iter().any(|c| {
                        let m = message(c);
                        m.contains("~/.ssh/inclus, ligne 2") && m.contains("sans vérifier qu'il est le bon")
                    }),
                    "{forme} : {constats:#?}"
                );
                assert!(
                    constats.iter().all(|c| !message(c).contains("non lu")),
                    "{forme} : {constats:#?}"
                );
            }));
        }
        // N3 : sept motifs qui se réincluent (7^8 lectures avant) : plafond dit une fois, bilan rendu.
        attentes.push(fils.spawn(move || {
            let eventail = "Include a b c d e f g\n";
            let maison = preparer(eventail);
            for nom in ["a", "b", "c", "d", "e", "f", "g"] {
                std::fs::write(maison.join(".ssh").join(nom), eventail).unwrap();
            }
            let debut = Instant::now();
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
            eprintln!("éventail de 7 motifs : bilan en {:?}", debut.elapsed());
            let plafond = constats
                .iter()
                .filter(|c| message(c).contains("plus de 128 fichiers inclus en tout"))
                .count();
            assert_eq!(plafond, 1, "{constats:#?}");
            assert!(constats.iter().all(|c| !message(c).contains("~/.ssh correctes")));
        }));
        // Plus de seize motifs non interprétés : les seize premiers dits, les autres comptés, jamais tus.
        attentes.push(fils.spawn(move || {
            let config = (0..20)
                .map(|i| format!("Include \"x{i}\n"))
                .collect::<Vec<_>>()
                .concat();
            let maison = preparer(&config);
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
            let non_interpretes = constats
                .iter()
                .filter(|c| message(c).contains("motif d'inclusion non interprété"))
                .count();
            assert_eq!(non_interpretes, 16, "{constats:#?}");
            assert!(
                constats.iter().any(
                    |c| message(c).contains("4 autre(s) inclusion(s) de ~/.ssh/config non lue(s)")
                        && c["verifie"] == false
                ),
                "{constats:#?}"
            );
        }));
        // N2 : ~/.ssh et ~/.netrc en boucle de liens.
        attentes.push(fils.spawn(move || {
            let maison = maison_jetable();
            mode(&maison, 0o700);
            symlink(".ssh", maison.join(".ssh")).unwrap();
            symlink(".netrc", maison.join(".netrc")).unwrap();
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Fichiers secrets"]);
            for (categorie, bout) in [("Clés SSH", "~/.ssh non lu"), ("Fichiers secrets", "~/.netrc non lu")] {
                assert!(
                    constats.iter().any(|c| c["categorie"] == categorie
                        && message(c).starts_with("Impossible de vérifier")
                        && message(c).contains(bout)
                        && c["verifie"] == false),
                    "{bout} : {constats:#?}"
                );
            }
            for c in &constats {
                let m = message(c);
                assert!(
                    !m.contains("Pas de dossier ~/.ssh") && !m.contains("protégés"),
                    "boucle prise pour absent ou sain : {m}"
                );
            }
        }));
        for a in attentes {
            if let Err(e) = a.join() {
                std::panic::resume_unwind(e);
            }
        }
    });
}

/// Une configuration de ~/.ssh/config, ses fichiers (nom, texte), le réglage que `ssh -G` doit appliquer, et ce
/// que Vanguard en dit (`la_configuration_ssh_est_lue_comme_ssh`).
#[cfg(unix)]
type Cas = (String, Vec<(&'static str, &'static str)>, &'static str, Attendu);

/// Ce que Vanguard attend d'une configuration du client SSH (`la_configuration_ssh_est_lue_comme_ssh`).
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Attendu {
    /// Le réglage relâché signalé, à ce fichier et cette ligne, sans rien de non lu.
    Alerte(&'static str),
    /// Une ligne dite non lue (le bilan ne dit pas « correctes »).
    NonLu,
    /// Le client post-quantique n'est pas dit « proposé » (échange affaibli par la configuration, ou non vérifié).
    PasPropose,
}

/// Vérification avant 0.94 (S1, S2, S3, S5). Chaque configuration ci-dessous relâche un réglage pour tout serveur :
/// `ssh -G` (OpenSSH local, dans la maison jetable) le confirme, et Vanguard le signale à sa ligne ou dit la ligne non
/// lue, jamais « Permissions de ~/.ssh correctes » ni « post-quantique proposé ». S1 : le mot-clé « Include » écrit
/// autrement. S2 : après un fichier inclus qui finit sous un Host précis, SSH remet la portée d'avant. S3 : réglages
/// écrits autrement (« = » devant, guillemets, synonymes, octet nul, hôtes larges, Match). S5 : un fichier qui se
/// réinclut ne donne qu'une alerte, et un chemin long est abrégé.
#[cfg(unix)]
#[test]
fn la_configuration_ssh_est_lue_comme_ssh() {
    use Attendu::{Alerte, NonLu, PasPropose};
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let ssh = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let relache = "Host *\n    StrictHostKeyChecking no\n";
    let hotes = "Host routeur\n    User alice\n";
    let kex = "KexAlgorithms curve25519-sha256";
    #[rustfmt::skip]
    let cas: Vec<Cas> = vec![
        // S1 : le mot-clé « Include » ; le fichier inclus relâche la vérification des serveurs.
        ("=Include inclus".into(), vec![("inclus", relache)], "stricthostkeychecking", Alerte("~/.ssh/inclus, ligne 2")),
        (" = Include inclus".into(), vec![("inclus", relache)], "stricthostkeychecking", Alerte("~/.ssh/inclus, ligne 2")),
        (" =Include inclus".into(), vec![("inclus", relache)], "stricthostkeychecking", Alerte("~/.ssh/inclus, ligne 2")),
        ("\"Include\"inclus".into(), vec![("inclus", relache)], "stricthostkeychecking", NonLu),
        ("Inc\"lude\"inclus".into(), vec![("inclus", relache)], "stricthostkeychecking", NonLu),
        ("=Include inclus".into(), vec![("inclus", "Host *\nKexAlgorithms curve25519-sha256\n")], "kexalgorithms", PasPropose),
        // S2 : « Include » en tête (fichiers d'hôtes), puis réglages généraux.
        ("Include hotes\nStrictHostKeyChecking no".into(), vec![("hotes", hotes)], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 2")),
        ("Include hotes\nForwardAgent yes".into(), vec![("hotes", hotes)], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Include config.d/*\nForwardAgent yes".into(), vec![("config.d/routeur", hotes)], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Host *\nInclude hotes\nStrictHostKeyChecking no".into(), vec![("hotes", hotes)], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 3")),
        (format!("Include hotes\n{kex}"), vec![("hotes", hotes)], "kexalgorithms", PasPropose),
        // S3 : écrits autrement dans le fichier principal.
        ("=ForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 1")),
        ("ForwardAgent true".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 1")),
        ("ForwardAgent ~/.ssh/agent.sock".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 1")),
        ("ForwardAgent yes\0 no".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 1")),
        ("StrictHostKeyChecking false".into(), vec![], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 1")),
        ("Host *\0routeur\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Host **\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Host ?*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Host * !routeur\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match final all\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match host *\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("\"ForwardAgent\" yes".into(), vec![], "forwardagent", NonLu),
        ("ForwardAgent 'yes'".into(), vec![], "forwardagent", NonLu),
        ("ForwardAgent \"ye\"s".into(), vec![], "forwardagent", NonLu),
        // Vérification de Fable n° 2, P6 : apostrophes lues comme `argv_split`.
        ("Host '*'\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        // P2 : sous une négation, un motif fait de jokers et d'un signe ne couvre pas un hôte ordinaire.
        ("Match !host *_*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match !host *.*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match !host *€*\nStrictHostKeyChecking no".into(), vec![], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 2")),
        ("Match !originalhost *_*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match !host routeur,*_*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match !host *,!*-*\nStrictHostKeyChecking no".into(), vec![], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 2")),
        // Vérification de Fable n° 3, N5 : « critère=valeur », lu comme OpenSSH 10.0 et plus.
        ("Match host=*\nForwardAgent yes".into(), vec![], "forwardagent", Alerte("~/.ssh/config, ligne 2")),
        ("Match !host=routeur\nStrictHostKeyChecking no".into(), vec![], "stricthostkeychecking", Alerte("~/.ssh/config, ligne 2")),
        (format!("Match originalhost=*\n{kex}"), vec![], "kexalgorithms", PasPropose),
        (format!("={kex}"), vec![], "kexalgorithms", PasPropose),
        (format!("Host ?*\n{kex}"), vec![], "kexalgorithms", PasPropose),
        ("\"KexAlgorithms\" curve25519-sha256".into(), vec![], "kexalgorithms", PasPropose),
    ];
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    let preparer = |config: &str, fichiers: &[(&str, &str)]| {
        let maison = maison_jetable();
        mode(&maison, 0o700);
        let dossier = maison.join(".ssh");
        std::fs::create_dir_all(dossier.join("config.d")).unwrap();
        mode(&dossier, 0o700);
        std::fs::write(dossier.join("config"), format!("{config}\n")).unwrap();
        for (nom, texte) in fichiers {
            std::fs::write(dossier.join(nom), texte).unwrap();
        }
        maison
    };
    // Le juge : la valeur que SSH applique à un serveur quelconque.
    let juge = |maison: &Path, cle: &str| -> Option<String> {
        let sortie = Command::new(ssh?)
            .env_clear()
            .env("HOME", maison)
            .args(["-G", "-F"])
            .arg(maison.join(".ssh/config"))
            .arg("serveur-quelconque")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            sortie.status.success(),
            "ssh -G : {}",
            String::from_utf8_lossy(&sortie.stderr)
        );
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
        texte
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{cle} ")).map(str::to_string))
    };
    std::thread::scope(|fils| {
        let mut attentes = Vec::new();
        for (config, fichiers, cle, attendu) in &cas {
            attentes.push(fils.spawn(move || {
                let maison = preparer(config, fichiers);
                if let Some(valeur) = juge(&maison, cle) {
                    let applique = match *cle {
                        "forwardagent" => valeur != "no",
                        "stricthostkeychecking" => valeur == "false",
                        _ => !valeur.contains("mlkem") && !valeur.contains("sntrup"),
                    };
                    assert!(applique, "{config:?} : SSH n'applique pas le réglage ({cle} {valeur})");
                }
                let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Post-quantique"]);
                let non_lu = |c: &serde_json::Value| {
                    let m = message(c);
                    m.starts_with("Impossible de vérifier") && m.contains(" non lu") && c["verifie"] == false
                };
                // Un réglage relâché ou une ligne non lue : jamais « correctes » ; un échange affaibli ou une ligne
                // non lue : jamais « proposé ».
                let kex = *cle == "kexalgorithms";
                for c in &constats {
                    let m = message(c);
                    assert!(kex || !m.contains("~/.ssh correctes"), "{config:?} : sain : {m}");
                    assert!(
                        !(kex || matches!(attendu, NonLu)) || !m.contains("est proposé aux serveurs"),
                        "{config:?} : proposé : {m}"
                    );
                }
                match attendu {
                    Alerte(ou) => {
                        assert!(
                            constats.iter().any(|c| {
                                let m = message(c);
                                m.contains(ou)
                                    && (m.contains("est prêté à tous") || m.contains("sans vérifier qu'il est le bon"))
                            }),
                            "{config:?} : pas d'alerte à {ou} : {constats:#?}"
                        );
                        assert!(!constats.iter().any(non_lu), "{config:?} : {constats:#?}");
                    }
                    NonLu => assert!(constats.iter().any(non_lu), "{config:?} : {constats:#?}"),
                    PasPropose => {}
                }
            }));
        }
        // S5 : un fichier qui se réinclut (« Include * » dans ~/.ssh) : une seule alerte pour sa ligne.
        attentes.push(fils.spawn(move || {
            let maison = preparer("ForwardAgent yes\nInclude *", &[]);
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
            let alertes = constats
                .iter()
                .filter(|c| message(c).contains("est prêté à tous"))
                .count();
            assert_eq!(alertes, 1, "{constats:#?}");
        }));
        // Vérification de Fable n° 2, P5 : 40 fichiers inclus de 600 lignes relâchées chacun : 16 alertes, puis une qui
        // dit le plafond et compte le reste (64 sur 80), au lieu d'une alerte par ligne.
        attentes.push(fils.spawn(move || {
            let corps = "ForwardAgent yes\nStrictHostKeyChecking no\n".repeat(300);
            let fichiers: Vec<(String, &str)> =
                (0..40).map(|i| (format!("config.d/f{i:02}"), corps.as_str())).collect();
            let maison = preparer("Include config.d/*", &[]);
            for (nom, texte) in &fichiers {
                std::fs::write(maison.join(".ssh").join(nom), texte).unwrap();
            }
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
            let alertes: Vec<String> = constats
                .iter()
                .map(message)
                .filter(|m| {
                    m.contains("est prêté à tous") || m.contains("sans vérifier") || m.contains("du même genre")
                })
                .collect();
            assert_eq!(alertes.len(), 17, "{alertes:#?}");
            assert!(alertes[0].contains("ligne 1 (et 299 autre(s) ligne(s)"), "{alertes:#?}");
            assert!(
                alertes[16].starts_with("64 autre(s) alerte(s) du même genre"),
                "{alertes:#?}"
            );
        }));
        // S5 : un chemin d'inclusion long est abrégé (début…fin) dans le non lu.
        attentes.push(fils.spawn(move || {
            let long = vec!["d".repeat(200); 12].join("/");
            let maison = preparer(&format!("Include {long}/gros"), &[]);
            let dossier = maison.join(".ssh").join(&long);
            std::fs::create_dir_all(&dossier).unwrap();
            std::fs::write(dossier.join("gros"), "# x\n".repeat(300_000)).unwrap();
            let constats = constats_du_bilan(programme, &maison, &["Clés SSH"]);
            assert!(
                constats.iter().any(|c| {
                    let m = message(c);
                    m.contains("…") && m.contains("/gros non lu") && m.chars().count() < 600
                }),
                "{constats:#?}"
            );
        }));
        for a in attentes {
            if let Err(e) = a.join() {
                std::panic::resume_unwind(e);
            }
        }
    });
    if ssh.is_none() {
        essais::saute("ssh absent : Vanguard essayé, juge non consulté");
    }
}

/// Vérification de Fable n° 2, P1 : sous un en-tête que SSH n'applique peut-être pas à tout serveur (« Match final
/// all », joker avec exclusion, « *.* », critères qui ne regardent pas l'hôte…), une liste post-quantique ne cache pas
/// la liste classique écrite plus bas sous « Host * », ni « WarnWeakCrypto no ». `ssh -G` (maison jetable) confirme
/// que SSH applique la liste classique et coupe l'avertissement ; Vanguard ne dit jamais « proposé » et signale les deux.
#[cfg(unix)]
#[test]
fn un_en_tete_douteux_ne_cache_pas_la_valeur_globale() {
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let ssh = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let en_tetes = [
        "Host * !serveur",
        "Match final all",
        "Match canonical all",
        "Match localuser bob",
        "Host *.*",
        "Match host *,!serveur",
        "Match user bob",
        "Match tagged essai",
        "Match exec \"false\"",
        "Match localnetwork 192.0.2.0/24",
        "Match command uptime",
        "Match version OpenSSH_1.*",
        "Match sessiontype subsystem",
    ];
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    std::thread::scope(|fils| {
        let mut attentes = Vec::new();
        for en_tete in en_tetes {
            attentes.push(fils.spawn(move || {
                let maison = maison_jetable();
                mode(&maison, 0o700);
                let dossier = maison.join(".ssh");
                std::fs::create_dir_all(&dossier).unwrap();
                mode(&dossier, 0o700);
                let config = format!(
                    "{en_tete}\n    KexAlgorithms mlkem768x25519-sha256\n    WarnWeakCrypto yes\nHost *\n    KexAlgorithms curve25519-sha256\n    WarnWeakCrypto no\n"
                );
                std::fs::write(dossier.join("config"), &config).unwrap();
                if let Some(ssh) = ssh {
                    let sortie = Command::new(ssh)
                        .env_clear()
                        .env("HOME", &*maison)
                        .args(["-G", "-F"])
                        .arg(dossier.join("config"))
                        .arg("serveur")
                        .stdin(Stdio::null())
                        .output()
                        .unwrap();
                    let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
                    assert!(sortie.status.success(), "{en_tete:?} : ssh -G : {}", String::from_utf8_lossy(&sortie.stderr));
                    assert!(texte.lines().any(|l| l == "kexalgorithms curve25519-sha256"), "{en_tete:?} : {texte}");
                    assert!(texte.lines().any(|l| l == "warnweakcrypto no"), "{en_tete:?} : {texte}");
                }
                let constats = constats_du_bilan(programme, &maison, &["Post-quantique"]);
                let messages: Vec<String> = constats.iter().map(message).collect();
                assert!(
                    !messages.iter().any(|m| m.starts_with("Client SSH") && m.contains("est proposé aux serveurs")),
                    "{en_tete:?} : proposé : {messages:#?}"
                );
                assert!(
                    // Vérification de Fable n° 3, N4 : la bonne valeur, placée avant sous l'en-tête douteux, vaut
                    // peut-être pour certains serveurs : un doute, pas « écarte pour tous ».
                    messages.iter().any(|m| m.contains("~/.ssh/config peut écarter l'échange post-quantique")),
                    "{en_tete:?} : pas d'alerte : {messages:#?}"
                );
                assert!(
                    messages.iter().any(|m| m.contains("WarnWeakCrypto no") && m.contains("~/.ssh/config")),
                    "{en_tete:?} : avertissement tu : {messages:#?}"
                );
            }));
        }
        for a in attentes {
            if let Err(e) = a.join() {
                std::panic::resume_unwind(e);
            }
        }
    });
    if ssh.is_none() {
        essais::saute("ssh absent : Vanguard essayé, juge non consulté");
    }
}

/// Vérification de Fable n° 3, N1 : SSH ne compare aucun motif d'une liste « Match host » ou « originalhost » qui
/// atteint 1023 octets (`match_pattern_list`), même à côté d'un « * ». Pour 1022 et 1023 octets, dans chaque sens et
/// pour chaque critère, `ssh -G` (maison jetable) dit si le bloc s'applique à un serveur quelconque, et Vanguard doit
/// suivre : sous la négation, l'agent prêté et la vérification coupée sont signalés quand SSH les applique ; sous le
/// sens positif, « post-quantique proposé » n'est dit que si SSH garde la liste post-quantique du bloc.
#[cfg(unix)]
#[test]
fn un_motif_trop_long_ne_rend_pas_la_portee_sure() {
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let ssh = ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
        .into_iter()
        .find(|p| Path::new(p).exists());
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    let mut cas = Vec::new();
    for critere in ["host ", "originalhost ", "host="] {
        for n in [1022, 1023] {
            let long = "a".repeat(n);
            // (configuration, le bloc s'applique-t-il, d'après la borne de SSH ; sens nié ?)
            cas.push((
                format!("Match !{critere}*,{long}\n    ForwardAgent yes\n    StrictHostKeyChecking no\n"),
                n == 1023,
                true,
            ));
            cas.push((
                format!(
                    "Match {critere}*,{long}\n    KexAlgorithms mlkem768x25519-sha256\n    WarnWeakCrypto yes\nHost *\n    KexAlgorithms curve25519-sha256\n    WarnWeakCrypto no\n"
                ),
                n == 1022,
                false,
            ));
        }
    }
    std::thread::scope(|fils| {
        let mut attentes = Vec::new();
        for (config, applique, nie) in &cas {
            attentes.push(fils.spawn(move || {
                let court = abreger_essai(config);
                let maison = maison_jetable();
                mode(&maison, 0o700);
                let dossier = maison.join(".ssh");
                std::fs::create_dir_all(&dossier).unwrap();
                mode(&dossier, 0o700);
                std::fs::write(dossier.join("config"), config).unwrap();
                if let Some(ssh) = ssh {
                    let sortie = Command::new(ssh)
                        .env_clear()
                        .env("HOME", &*maison)
                        .args(["-G", "-F"])
                        .arg(dossier.join("config"))
                        .arg("serveur-quelconque")
                        .stdin(Stdio::null())
                        .output()
                        .unwrap();
                    let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
                    assert!(
                        sortie.status.success(),
                        "{court} : ssh -G : {}",
                        String::from_utf8_lossy(&sortie.stderr)
                    );
                    let attendu = if *nie {
                        "forwardagent yes"
                    } else {
                        "kexalgorithms mlkem768x25519-sha256"
                    };
                    assert_eq!(
                        texte.lines().any(|l| l == attendu),
                        *applique,
                        "{court} : borne de SSH : {texte}"
                    );
                }
                let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Post-quantique"]);
                let messages: Vec<String> = constats.iter().map(message).collect();
                if *nie {
                    let alertes = messages
                        .iter()
                        .filter(|m| m.contains("est prêté à tous") || m.contains("sans vérifier qu'il est le bon"))
                        .count();
                    assert_eq!(alertes, if *applique { 2 } else { 0 }, "{court} : {messages:#?}");
                    assert_eq!(
                        messages.iter().any(|m| m.contains("~/.ssh correctes")),
                        !*applique,
                        "{court} : {messages:#?}"
                    );
                } else {
                    let propose = messages
                        .iter()
                        .any(|m| m.starts_with("Client SSH") && m.contains("est proposé aux serveurs"));
                    assert_eq!(propose, *applique, "{court} : {messages:#?}");
                    if !*applique {
                        assert!(
                            messages
                                .iter()
                                .any(|m| m.contains("WarnWeakCrypto no") && m.contains("~/.ssh/config")),
                            "{court} : avertissement tu : {messages:#?}"
                        );
                    }
                }
            }));
        }
        for a in attentes {
            if let Err(e) = a.join() {
                std::panic::resume_unwind(e);
            }
        }
    });
    if ssh.is_none() {
        essais::saute("ssh absent : Vanguard essayé, juge non consulté");
    }
}

/// Vérification de Fable n° 3, N2 : une ligne KexAlgorithms de 500 000 « * » faisait planter Vanguard (pile débordée,
/// plus aucun bilan) et des « *? » alternés le figeaient (temps exponentiel). Le bilan rend la main vite : la liste
/// trop longue est dite non lue, la liste sous la borne est jugée comme SSH la lit.
#[cfg(unix)]
#[test]
fn une_liste_kex_piegee_ne_plante_ni_ne_fige_le_bilan() {
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    let cas = [
        (format!("KexAlgorithms -{}\n", "*".repeat(500_000)), true),
        // Les deux premiers noms post-quantiques retirés tels quels : seul le troisième (34 octets) passe par le
        // motif, qui échoue à la fin après avoir essayé chaque placement des jokers.
        (
            format!(
                "KexAlgorithms -mlkem768x25519-sha256,sntrup761x25519-sha512,{}x\n",
                "*?".repeat(20)
            ),
            false,
        ),
        (
            format!(
                "KexAlgorithms -mlkem768x25519-sha256,sntrup761x25519-sha512,{}x\n",
                "*?".repeat(500)
            ),
            false,
        ),
    ];
    std::thread::scope(|fils| {
        let mut attentes = Vec::new();
        for (config, non_lu) in &cas {
            attentes.push(fils.spawn(move || {
                let court = abreger_essai(config);
                let maison = maison_jetable();
                mode(&maison, 0o700);
                let dossier = maison.join(".ssh");
                std::fs::create_dir_all(&dossier).unwrap();
                mode(&dossier, 0o700);
                std::fs::write(dossier.join("config"), config).unwrap();
                let debut = std::time::Instant::now();
                let constats = constats_du_bilan(programme, &maison, &["Post-quantique"]);
                assert!(
                    debut.elapsed() < std::time::Duration::from_secs(60),
                    "{court} : bilan trop long"
                );
                let client: Vec<String> = constats
                    .iter()
                    .map(message)
                    .filter(|m| m.contains("Client SSH"))
                    .collect();
                assert!(!client.is_empty(), "{court} : {constats:#?}");
                let dit_non_lu = client
                    .iter()
                    .any(|m| m.contains("non vérifié") && m.contains("KexAlgorithms non lu"));
                assert_eq!(dit_non_lu, *non_lu, "{court} : {client:#?}");
                // Non lue : jamais « proposé » ; jugée : `ssh -G` (OpenSSH 10.6) garde
                // sntrup761x25519-sha512@openssh.com, que le motif ne retire pas.
                let propose = client.iter().any(|m| m.contains("est proposé aux serveurs"));
                assert_eq!(propose, !*non_lu, "{court} : {client:#?}");
            }));
        }
        for a in attentes {
            if let Err(e) = a.join() {
                std::panic::resume_unwind(e);
            }
        }
    });
}

/// Une configuration d'essai montrée par son début, pour les messages d'échec (un motif de 1 Kio les noierait).
#[cfg(unix)]
fn abreger_essai(texte: &str) -> String {
    let debut: String = texte.chars().take(60).collect();
    format!("{debut:?}… ({} octets)", texte.len())
}

/// Vérification avant 0.94 (bruit) : des configurations ordinaires (un Host par serveur, IdentityFile, Include
/// config.d/*, ProxyJump, ProxyCommand avec guillemets, Match host … exec "…", gabarits courants) ne donnent aucun
/// « non lu » ni aucune alerte, et le client post-quantique y est jugé.
#[cfg(unix)]
#[test]
fn une_configuration_ssh_ordinaire_ne_donne_aucun_non_lu() {
    use std::os::unix::fs::PermissionsExt;
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let mode = |c: &Path, m: u32| std::fs::set_permissions(c, std::fs::Permissions::from_mode(m)).unwrap();
    let maison = maison_jetable();
    mode(&maison, 0o700);
    let dossier = maison.join(".ssh");
    std::fs::create_dir_all(dossier.join("config.d")).unwrap();
    mode(&dossier, 0o700);
    let config = "\
# Mes serveurs
Include config.d/*

Host depot.exemple.org
    HostName depot.exemple.org
    User git
    IdentityFile ~/.ssh/id_ed25519
    IdentitiesOnly yes

Host bastion
\tHostName 192.0.2.10
\tUser alice
\tPort 2222

Host interne-* !interne-test
    ProxyJump bastion
    ForwardAgent no

Host vieux vieux.exemple.org
    ProxyCommand ssh -W \"%h:%p\" bastion
    KexAlgorithms +diffie-hellman-group14-sha1
    HostKeyAlgorithms +ssh-rsa
    StrictHostKeyChecking=accept-new

Match host labo exec \"test -f ~/.ssh/labo.actif\"
    StrictHostKeyChecking no

Match originalhost bastion user alice
    Port 22

Match host labo2 exec 'test -f ~/.ssh/labo2.actif'
    User alice

Match host labo3 exec \"test -f \\\"$HOME/.ssh/labo3.actif\\\"\"
    User alice

Match host labo4 exec test\\ -f\\ /etc/labo4
    User alice

Host 'nas'
    HostName 192.0.2.20

Host *
    ServerAliveInterval 30
    AddKeysToAgent yes
    IdentityFile ~/.ssh/id_ed25519
    UserKnownHostsFile ~/.ssh/known_hosts ~/.ssh/known_hosts2
    SetEnv LANG=C
    SendEnv LANG LC_*
    LocalForward 8080 localhost:80
    ControlPath ~/.ssh/cm-%r@%h:%p
    ForwardAgent no
    StrictHostKeyChecking ask
";
    std::fs::write(dossier.join("config"), config).unwrap();
    std::fs::write(
        dossier.join("config.d/travail"),
        "Host travail\n  HostName travail.exemple.org\n  User alice\n  Port=22\n  ForwardAgent yes # confiance\n",
    )
    .unwrap();
    let constats = constats_du_bilan(programme, &maison, &["Clés SSH", "Post-quantique"]);
    let message = |c: &serde_json::Value| c["message"].as_str().unwrap_or_default().to_string();
    for c in &constats {
        let m = message(c);
        assert!(
            !m.contains("non lu")
                && !m.contains("non interprét")
                && !m.contains("est prêté")
                && !m.contains("sans vérifier"),
            "{m}"
        );
    }
}

#[test]
fn audit_en_json() {
    let s = vanguard("fr", &["audit", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let audit: serde_json::Value = serde_json::from_str(&s.texte).expect("machine --json : JSON illisible");
    let score = audit["score"].as_u64().expect("pas de note");
    assert!(score <= 100);
    // La fenêtre de Vanguard ne montre la note que si elle est dite fiable.
    assert!(audit["fiable"].is_boolean(), "fiable absent");
    let constats = audit["constats"].as_array().expect("pas de constats");
    assert!(constats.len() >= 5, "{} constats seulement", constats.len());
    for c in constats {
        assert!(c["categorie"].is_string() && c["message"].is_string() && c["verifie"].is_boolean());
    }
}

/// `protection --json` : chaque interrupteur avec son identifiant stable, rien de changé ; « --json on » est refusé.
#[test]
fn protection_en_json() {
    let s = vanguard("fr", &["protection", "--json"], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).expect("protection --json : JSON illisible");
    let liste = v["interrupteurs"].as_array().expect("pas d'interrupteurs");
    let ids: Vec<&str> = liste.iter().filter_map(|i| i["interrupteur"].as_str()).collect();
    for id in ["temps-reel", "surveillance", "blocage", "sites-dangereux", "raccourci"] {
        assert!(ids.contains(&id), "{id} absent : {ids:?}");
    }
    assert!(liste.iter().all(|i| i["nom"].is_string() && i["etat"].is_string()));
    let refus = vanguard("fr", &["protection", "--json", "non"], "", 60);
    assert_eq!(refus.code, Some(2), "{}", refus.texte);
    // --json après un mot vaut pour la commande : « etat --json » rend le même JSON ; « oui --json » et
    // « non --json » sont refusés comme « --json non », sans rien changer (aucune coupure posée).
    for args in [&["protection", "etat", "--json"][..], &["protection", "--json", "etat"]] {
        let s = vanguard("fr", args, "", 60);
        assert_eq!(s.code, Some(0), "{args:?} : {}", s.erreurs);
        let v: serde_json::Value =
            serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{args:?} : JSON illisible ({e}) : {}", s.texte));
        assert!(v["interrupteurs"].is_array(), "{args:?} : {v}");
    }
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let avant = vanguard_dans(programme, &maison, "fr", &["protection", "--json"], "", 60);
    for args in [
        &["protection", "oui", "--json"][..],
        &["protection", "non", "--json"],
        &["protection", "non", "--pendant", "1h", "--json"],
    ] {
        let s = vanguard_dans(programme, &maison, "fr", args, "o\n", 60);
        assert_eq!(s.code, Some(2), "{args:?} : {}", s.texte);
        assert!(!s.texte.trim_start().starts_with('{'), "{args:?} : {}", s.texte);
    }
    let apres = vanguard_dans(programme, &maison, "fr", &["protection", "--json"], "", 60);
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(avant.texte, apres.texte, "un refus a changé un interrupteur");
}

#[test]
fn scan_de_cette_machine_en_json() {
    // Sous Wine, ce scan ne finit pas (sa pile réseau n'imite pas celle de Windows) ; le vrai Windows de la CI le fait.
    if sous_wine() {
        return essais::saute("sous Wine, le scan ne finit pas");
    }
    // 127.0.0.1 seulement : aucun paquet ne part sur le réseau.
    let s = vanguard("fr", &["appareils", "127.0.0.1", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let scan: serde_json::Value = serde_json::from_str(&s.texte).expect("reseau --json : JSON illisible");
    let hotes = scan["hotes"].as_array().expect("pas d'appareils");
    assert!(hotes.iter().all(|h| h["ip"] == "127.0.0.1"), "{hotes:?}");
}

#[test]
fn sauvegarde_puis_restauration() {
    // Hors du dossier personnel jetable : le fichier doit passer d'un lancement à l'autre.
    let fichier = essais::temporaire().join(format!("vanguard-sauvegarde-essai-{}.json", std::process::id()));
    let chemin = fichier.to_str().unwrap();
    let s = vanguard("fr", &["exporter", chemin], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("Sauvegarde écrite"), "{}", s.texte);
    let texte = std::fs::read_to_string(&fichier).unwrap();
    assert!(texte.contains("\"format\": \"vanguard-sauvegarde\""), "{texte}");
    let r = vanguard("fr", &["importer", chemin], "", 60);
    assert_eq!(r.code, Some(0), "{}", r.erreurs);
    assert!(
        sans_couleurs(&r.texte).contains("Ajouté à la base actuelle"),
        "{}",
        r.texte
    );
    // Un fichier qui n'est pas une sauvegarde : rien n'est restauré.
    std::fs::write(&fichier, "{\"autre\":1}").unwrap();
    let refus = vanguard("fr", &["importer", chemin], "", 60);
    assert!(
        sans_couleurs(&refus.texte).contains("Rien de restauré"),
        "{}",
        refus.texte
    );
    let _ = std::fs::remove_file(&fichier);
}

/// Ordinateur d'un proche, tout refusé : les trois questions, le bilan et son résumé, aucune correction, aucun scan du
/// réseau, aucune page posée.
#[test]
fn ordinateur_d_un_proche_tout_refuse() {
    let maison = maison_jetable();
    // Un Bureau, pour qu'une page posée par erreur s'y voie.
    std::fs::create_dir_all(maison.join("Desktop")).unwrap();
    let entree = format!("1\n2\n1\n{}", "n\n".repeat(80));
    let sortie = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "en",
        &["troubleshoot", "relative"],
        &entree,
        180,
    );
    let texte = sans_couleurs(&sortie.texte);
    let bureau: Vec<_> = std::fs::read_dir(maison.join("Desktop")).unwrap().flatten().collect();
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(sortie.code, Some(0), "{}", sortie.erreurs);
    assert!(
        texte.contains("A relative's computer") && texte.contains("IN SHORT") && texte.contains("What is left to do"),
        "{texte}"
    );
    // Réseau refusé : pas de scan ; page refusée : rien sur le Bureau.
    assert!(!texte.contains("Network scan"), "{texte}");
    assert!(texte.contains("The page is still possible later"), "{texte}");
    assert!(bureau.is_empty(), "{bureau:?}");
}

#[test]
fn lenteur_fiche_depanner_et_copie_sans_rien_changer() {
    // Fiche en JSON : lisible, et sans les numéros de série (ils ne s'affichent qu'à l'écran).
    let sortie_fiche = vanguard("fr", &["fiche-ordinateur", "--json"], "", 120);
    assert_eq!(sortie_fiche.code, Some(0), "{}", sortie_fiche.erreurs);
    let fiche: serde_json::Value = serde_json::from_str(&sortie_fiche.texte).expect("fiche --json : JSON illisible");
    assert!(
        fiche.get("processeur").is_some() && fiche.get("series").is_none(),
        "{fiche}"
    );
    // Pourquoi c'est lent : la mesure et ses sections, en lecture seule (refusé, voulu, sur un Windows élevé avec l'UAC).
    if !optimiser_refuse_ici() {
        let lenteur = vanguard("fr", &["lenteur"], "", 120);
        assert_eq!(lenteur.code, Some(0), "{}", lenteur.erreurs);
        let texte = sans_couleurs(&lenteur.texte);
        assert!(texte.contains("EN CE MOMENT") && texte.contains("DÉMARRAGE"), "{texte}");
    }
    // Un sujet de dépannage inconnu : la liste des sujets, dans la langue de l'interface.
    let depanner = vanguard("en", &["troubleshoot", "nimportequoi"], "", 30);
    assert_eq!(depanner.code, Some(0), "{}", depanner.erreurs);
    let texte = sans_couleurs(&depanner.texte);
    assert!(texte.contains("printer") && texte.contains("Disk full"), "{texte}");
    assert!(
        texte.contains("leaving") && texte.contains("After an infection"),
        "{texte}"
    );
    // Ordinateur qui part, quitté à la première question : rien n'est effacé ni lancé.
    let depart = vanguard("en", &["troubleshoot", "leaving"], "", 30);
    assert_eq!(depart.code, Some(0), "{}", depart.erreurs);
    assert!(
        sans_couleurs(&depart.texte).contains("Computer leaving"),
        "{}",
        depart.texte
    );
    // Copier vers un dossier qui n'existe pas : rien n'est copié.
    let copie = vanguard("fr", &["copier-fichiers", "/chemin/qui/n-existe/pas"], "", 30);
    assert_eq!(copie.code, Some(0), "{}", copie.erreurs);
    let texte = sans_couleurs(&copie.texte);
    assert!(
        texte.contains("Aucun dossier personnel") || texte.contains("n-existe"),
        "{texte}"
    );
}

#[test]
fn gaming_quitte_sans_rien_installer() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let s = vanguard("fr", &["jeux"], "\n", 120);
    let t = sans_couleurs(&s.texte);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(t.contains("Gaming") && !t.contains("Terminé"), "{t}");
}

#[test]
fn entretien_du_mois_sans_rien_installer() {
    let coupe = vanguard("fr", &["entretien", "off"], "", 60);
    assert_eq!(coupe.code, Some(0), "{}", coupe.erreurs);
    assert!(
        sans_couleurs(&coupe.texte).contains("Entretien du mois coupé"),
        "{}",
        coupe.texte
    );
    // Sans argument : ce qu'il dirait maintenant, dans le terminal ; rien n'est gardé ni planifié.
    let s = vanguard("fr", &["entretien"], "", 300);
    let t = sans_couleurs(&s.texte);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(
        t.contains("Note de cet ordinateur") && t.contains("Entretien coupé"),
        "{t}"
    );
}

#[test]
fn sous_menu_protection() {
    // 6 : Virus et logiciels espions, puis 7 : Arnaques et vie privée ; Entrée : revenir ; q : quitter.
    let s = vanguard("fr", &[], "6\n\n7\n\nq\n", 60);
    let t = sans_couleurs(&s.texte);
    let arnaques = t
        .find("VANGUARD › Arnaques et vie privée")
        .expect("groupe 7 pas ouvert");
    let (virus, arnaques) = t.split_at(arnaques);
    for outil in [
        "Analyse antivirus",
        "Logiciels espions : en ai-je un ?",
        "Qui parle à Internet ?",
        "Vérifier un fichier téléchargé",
    ] {
        assert!(virus.contains(outil), "{outil} absent du groupe 6 : {t}");
    }
    for outil in [
        "Ce lien est-il dangereux ?",
        "Ce courriel est-il une arnaque ?",
        "Mon ordinateur est-il contrôlé ?",
    ] {
        assert!(arnaques.contains(outil), "{outil} absent du groupe 7 : {t}");
    }
    // Les variantes de l'analyse sont dans son écran à choix, pas dans le groupe.
    assert!(!virus.contains("Analyse complète"), "{t}");
    let antivirus = virus.find("Analyse antivirus").unwrap();
    let espions = virus.find("Logiciels espions : en ai-je un ?").unwrap();
    assert!(antivirus < espions, "{t}");
    // Chaque ligne du sous-menu tient dans 76 colonnes (sans terminal, l'écran suivant suit la question « Choix » sur
    // la même ligne : celles-là ne comptent pas).
    let longues: Vec<&str> = t
        .lines()
        .filter(|l| !l.contains("Choix :") && l.chars().count() > 76)
        .collect();
    assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues");
    assert_eq!(s.code, Some(0));
}

#[test]
fn lien_examine_sans_rien_envoyer() {
    // Refus de la vérification en ligne : rien ne sort de l'ordinateur, le verdict vient du lien lui-même. Des noms
    // réservés aux exemples (.example) : outils/liens.py ne cherche pas à les ouvrir.
    let s = vanguard(
        "fr",
        &["lien", "https://paypal.com.compte-secure.example/login"],
        "n\n",
        60,
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Sous-domaine trompeur") && t.contains("compte-secure.example"),
        "{t}"
    );
    assert!(t.contains("Rien n'a été envoyé") && t.contains("Dangereux"), "{t}");
    let en = vanguard("en", &["link", "https://paypa1.example/"], "n\n", 60);
    let t = sans_couleurs(&en.texte);
    assert!(t.contains("Looks like PayPal") && t.contains("Nothing was sent"), "{t}");
    let aide = vanguard("en", &["lien", "--help"], "", 30);
    assert!(aide.texte.contains("The link you received"), "{}", aide.texte);
}

/// Un hameçonnage inventé (domaines réservés aux exemples) : nom affiché d'une marque, réponses vers une messagerie
/// gratuite, lien qui montre une adresse et mène à une autre, objet démesuré et nom piégé pour la largeur de l'écran.
fn courriel_piege(dossier: &Path) -> PathBuf {
    let objet = "Votre compte est suspendu ".repeat(20);
    let texte = format!(
        "Received: from envoi.paypa1-secure.example by mx.example.net\r\n\
Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=paypa1-secure.example; dkim=none; dmarc=none\r\n\
From: \"PayPal Service =?utf-8?B?4oCu?=\" <service@paypa1-secure.example>\r\n\
Reply-To: noreply@gmail.com\r\nTo: alice@example.com\r\nSubject: {objet}\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\n\
Confirmez sur https://paypa1-secure.example/login\r\n--b\r\nContent-Type: text/html\r\n\r\n\
<a href=\"https://paypa1-secure.example/login\">https://www.paypal.com/{}</a>\r\n--b--\r\n",
        "x".repeat(300)
    );
    let chemin = dossier.join("hamecon.eml");
    std::fs::write(&chemin, texte).unwrap();
    chemin
}

/// Ce courriel est-il une arnaque ? : refus de la vérification en ligne, rien ne sort ; le verdict vient de l'examen
/// sur l'ordinateur. Chaque ligne tient dans 76 colonnes, même avec un objet démesuré.
#[test]
fn courriel_suspect_sans_rien_envoyer() {
    let dossier = maison_jetable();
    let eml = courriel_piege(&dossier);
    let s = vanguard("fr", &["courriel-suspect", eml.to_str().unwrap()], "n\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Arnaque probable") && t.contains("messagerie gratuite") && t.contains("Le lien affiche"),
        "{t}"
    );
    // Sans Internet (passe hors ligne de verifier.sh), la question n'est pas posée et c'est dit.
    assert!(
        t.contains("Rien n'a été envoyé") || (hors_ligne() && t.contains("Mode hors ligne")),
        "{t}"
    );
    assert!(!t.contains('\u{202e}'), "caractère piège montré tel quel");
    let longues: Vec<&str> = t.lines().filter(|l| l.chars().count() > 76).collect();
    assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues");
    let en = vanguard("en", &["suspicious-email", eml.to_str().unwrap()], "n\n", 60);
    let t = sans_couleurs(&en.texte);
    assert!(t.contains("Probably a scam"), "{t}");
    assert!(
        t.contains("Nothing was sent") || (hors_ligne() && t.contains("Offline mode")),
        "{t}"
    );
    // Pas un courriel, ou un message Outlook : dit, rien d'analysé.
    let png = dossier.join("image.eml");
    std::fs::write(&png, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").unwrap();
    let s = vanguard("fr", &["courriel-suspect", png.to_str().unwrap()], "", 30);
    assert!(
        sans_couleurs(&s.texte).contains("pas un courriel reconnu"),
        "{}",
        s.texte
    );
    let msg = dossier.join("message.msg");
    std::fs::write(&msg, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1rien").unwrap();
    let s = vanguard("fr", &["courriel-suspect", msg.to_str().unwrap()], "", 30);
    assert!(
        sans_couleurs(&s.texte).contains("message Outlook (.msg)"),
        "{}",
        s.texte
    );
    let aide = vanguard("en", &["courriel-suspect", "--help"], "", 30);
    assert!(aide.texte.contains("The saved email (.eml)"), "{}", aide.texte);
    let _ = std::fs::remove_dir_all(&dossier);
}

#[test]
fn verifier_fichier_absent_ou_dossier() {
    let s = vanguard("fr", &["verifier-fichier", "/nexiste/pas/outil.zip"], "", 30);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("Introuvable"), "{}", s.texte);
    let dossier = std::env::temp_dir();
    let d = vanguard("fr", &["verifier-fichier", dossier.to_str().unwrap()], "", 30);
    assert!(
        sans_couleurs(&d.texte).contains("Ce n'est pas un fichier"),
        "{}",
        d.texte
    );
    let aide = vanguard("en", &["check-file", "--help"], "", 30);
    assert!(
        aide.texte.contains("The checksum published by the site"),
        "{}",
        aide.texte
    );
}

#[test]
fn verifier_fichier_verdicts() {
    // Wine calcule les empreintes par Windows, qu'il n'a pas : sous Wine, tout serait « impossible à calculer ».
    if sous_wine() {
        return;
    }
    let dossier = maison_jetable();
    let notes = dossier.join("notes.txt");
    std::fs::write(&notes, "bonjour\n").unwrap();
    let sha256 = "9cec0af545144159bac85c7b908d5e0b9b0ef961497401c5ad8da26f065ad926";
    let verifier = |langue: &str, fichier: &Path, empreinte: Option<&str>| {
        let mut args = vec!["verifier-fichier", fichier.to_str().unwrap()];
        args.extend(empreinte);
        // Sans ClamAV (CI), Vanguard propose de l'installer : la fin de l'entrée vaut « non », et le
        // verdict suit (`verifier_fichier_sans_clamav_ni_reponse`).
        let s = vanguard(langue, &args, "", 120);
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        // Les phrases longues sont coupées en lignes à l'écran : remises bout à bout.
        sans_couleurs(&s.texte).split_whitespace().collect::<Vec<_>>().join(" ")
    };
    // La bonne empreinte SHA-256, collée : c'est le fichier publié.
    let t = verifier("fr", &notes, Some(sha256));
    assert!(
        t.contains("L'empreinte SHA-256 (collée) correspond : c'est bien le fichier publié"),
        "{t}"
    );
    assert!(!t.contains("Ne l'ouvrez pas"), "{t}");
    let t = verifier("en", &notes, Some(sha256));
    assert!(
        t.contains("The SHA-256 checksum (pasted) matches: it is the published file"),
        "{t}"
    );
    // Une autre : le fichier a été abîmé ou remplacé, et le verdict le dit.
    let t = verifier("fr", &notes, Some(&"0".repeat(64)));
    assert!(
        t.contains("ne correspond pas : le fichier a été abîmé ou remplacé"),
        "{t}"
    );
    assert!(
        t.contains("Ne l'ouvrez pas : ce fichier n'est pas ce qu'il prétend être"),
        "{t}"
    );
    // MD5 : il prouve que le fichier n'est pas abîmé, pas que personne ne l'a remplacé ; le verdict n'est pas « conforme ».
    let t = verifier("fr", &notes, Some("94baaad4d1347ec6e15ae35c88ee8bc8"));
    assert!(t.contains("MD5 se falsifie"), "{t}");
    assert!(
        t.contains("l'empreinte n'a pas prouvé que c'est le fichier publié"),
        "{t}"
    );
    // Un texte qui n'est pas une empreinte est dit, et rien n'est conclu de lui.
    let t = verifier("fr", &notes, Some("voir le site"));
    assert!(t.contains("« voir le site » n'est pas une empreinte reconnue"), "{t}");
    assert!(t.contains("Pas d'empreinte à comparer"), "{t}");
    // Sans empreinte donnée, celle d'un SHA256SUMS posé à côté.
    std::fs::write(dossier.join("SHA256SUMS"), format!("{sha256}  notes.txt\n")).unwrap();
    let t = verifier("fr", &notes, None);
    assert!(t.contains("(lue dans SHA256SUMS) correspond"), "{t}");
    // Un programme Windows déguisé en document, sous une double extension.
    let piege = dossier.join("facture.pdf.exe");
    std::fs::write(&piege, b"MZ\x90\x00").unwrap();
    let t = verifier("fr", &piege, None);
    assert!(t.contains("Double extension « .pdf.exe »"), "{t}");
    assert!(
        t.contains("Ne l'ouvrez pas : ce fichier n'est pas ce qu'il prétend être"),
        "{t}"
    );
    let _ = std::fs::remove_dir_all(&dossier);
}

/// `verifier-fichier --json` : rien n'est demandé ni affiché hors du JSON ; l'antivirus du système, pas lancé, est dit
/// non vérifié, donc le verdict n'est jamais « sain » ; le moteur de Vanguard rend le sien à part, et une source qui
/// lui manquait (empreintes de MalwareBazaar dans un dossier personnel neuf) figure dans ce qui n'a pas été vérifié.
/// Le résultat est versé (`examens/PRO-TEL-001.json`) ; un fichier introuvable rend un résultat non vérifié.
#[test]
fn verifier_fichier_en_json() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let notes = maison.join("notes.txt");
    std::fs::write(&notes, "bonjour\n").unwrap();
    let lire = |args: &[&str]| -> serde_json::Value {
        // Hors ligne : MalwareBazaar n'est pas demandé par Internet (lent, sensible au réseau) ; ses empreintes
        // absentes deviennent la réserve que l'essai attend plus bas. 120 s : le moteur lit les vraies bases de
        // ClamAV de l'ordinateur (pas de dossier de bases au choix, exprès), ce qui dépasse 60 s en debug quand les
        // autres essais tournent en même temps.
        let s = vanguard_dans_env(programme, &maison, "fr", args, "", 120, &[("VANGUARD_HORS_LIGNE", "1")]);
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{args:?} : JSON illisible ({e}) : {}", s.texte))
    };
    let v = lire(&["verifier-fichier", notes.to_str().unwrap(), "--json"]);
    assert_eq!(v["outil"], "PRO-TEL-001", "{v}");
    let constats = v["constats"].as_array().expect("pas de constats");
    assert!(constats.iter().all(|c| c["etat"] != "probleme"), "{v}");
    let manques: Vec<&str> = v["couverture"]["non_verifies"]
        .as_array()
        .expect("pas de non_verifies")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    let antivirus = if cfg!(windows) { "Defender" } else { "ClamAV" };
    assert!(
        manques.contains(&format!("{antivirus} : pas lancé avec --json").as_str()),
        "{manques:?}"
    );
    let moteur = &v["moteur"];
    assert!(moteur.is_object(), "{v}");
    let verdict = moteur["verdict"].as_str().expect("moteur sans verdict");
    assert!(["sain", "non-verifie"].contains(&verdict), "{verdict}");
    // Une source facultative absente n'est pas tue : chaque réserve du moteur est un manque du résultat. Hors ligne,
    // dans un dossier personnel neuf, les empreintes de MalwareBazaar manquent toujours : la boucle a de quoi juger.
    let reserves: Vec<&str> = moteur["reserves"]
        .as_array()
        .expect("pas de réserves")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(reserves.iter().any(|r| r.contains("MalwareBazaar")), "{reserves:?}");
    for r in reserves {
        assert!(
            manques.contains(&format!("Vanguard : {r}").as_str()),
            "{r} : {manques:?}"
        );
    }
    assert!(
        dossier_vanguard(&maison)
            .join("examens")
            .join("PRO-TEL-001.json")
            .is_file(),
        "résultat pas versé"
    );
    // Un programme Windows déguisé en document : un problème, que l'antivirus manque ou non.
    let piege = maison.join("facture.pdf.exe");
    std::fs::write(&piege, b"MZ\x90\x00").unwrap();
    let v = lire(&["verifier-fichier", piege.to_str().unwrap(), "--json"]);
    let constats = v["constats"].as_array().expect("pas de constats");
    assert!(constats.iter().any(|c| c["etat"] == "probleme"), "{v}");
    // Introuvable : rien de vérifié, et le moteur n'a rien rendu.
    let v = lire(&["verifier-fichier", "/nexiste/pas/outil.zip", "--json"]);
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert!(
        v["constats"]
            .as_array()
            .is_some_and(|c| c.iter().all(|c| c["etat"] == "non-verifie")),
        "{v}"
    );
    assert!(v["moteur"].is_null(), "{v}");
}

/// ClamAV absent (un PATH vide) et aucune réponse : depuis AV5 (P16), Vanguard ne propose plus de l'installer, ni
/// commande ni question ; clamscan n'est qu'un second avis facultatif. Son absence reste dite, et la vérification
/// incomplète : ce qui n'a pas pu être vérifié n'est jamais compté sain.
#[cfg(unix)]
#[test]
fn verifier_fichier_sans_clamav_ni_reponse() {
    let maison = maison_jetable();
    let vide = maison.join("bin-vide");
    std::fs::create_dir_all(&vide).unwrap();
    let notes = maison.join("notes.txt");
    std::fs::write(&notes, "bonjour\n").unwrap();
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["verifier-fichier", notes.to_str().unwrap()],
        "",
        120,
        &[("PATH", vide.to_str().unwrap())],
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte).split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(!t.contains("L'installer maintenant ?"), "{t}");
    for proposition in [
        "sudo ",
        "pacman -S",
        "pkg add",
        "apt install",
        "dnf install",
        " install clamav",
    ] {
        assert!(!t.contains(proposition), "installation proposée ({proposition}) : {t}");
    }
    assert!(t.contains("second avis facultatif"), "{t}");
    assert!(t.contains("ClamAV : impossible à vérifier"), "{t}");
    assert!(t.contains("Vérification incomplète (ClamAV)"), "{t}");
    let _ = std::fs::remove_dir_all(&maison);
}

#[test]
fn sortantes_en_lecture_seule() {
    let s = vanguard("fr", &["connexions-sortantes"], "", 90);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Qui parle à Internet ?") && t.contains("Rien n'est coupé ni bloqué"),
        "{t}"
    );
    // Sous Wine, pas de PowerShell : c'est dit, rien n'est inventé.
    assert!(
        t.contains("vers Internet") || t.contains("Impossible de lire les connexions"),
        "{t}"
    );
}

/// Mon ordinateur est-il contrôlé ? : l'arnaque est expliquée, la recherche se fait, et « n » ne retire rien.
#[test]
fn distance_sans_rien_retirer() {
    let s = vanguard("fr", &["acces-a-distance"], "n\nn\n", 120);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Mon ordinateur est-il contrôlé ?") && t.contains("faux technicien"),
        "{t}"
    );
    // Rien trouvé, quelque chose trouvé mais gardé, ou PowerShell absent (Wine) : jamais un retrait.
    assert!(
        t.contains("Aucun logiciel de prise de contrôle")
            || t.contains("Rien n'a été retiré")
            || t.contains("Impossible de vérifier"),
        "{t}"
    );
    assert!(!t.contains("retiré."), "{t}");
}

/// Logiciels espions, sans Internet : vite, en lecture seule, la liste d'Échap dite non vérifiée, et jamais « aucun
/// signe » sans le nombre de points non vérifiés ; l'alias anglais et l'aide anglaise.
#[test]
fn logiciels_espions_hors_ligne() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    for (langue, commande) in [("fr", "logiciels-espions"), ("en", "spyware")] {
        let debut = Instant::now();
        let s = vanguard_dans_env(
            programme,
            &maison,
            langue,
            &[commande],
            "",
            60,
            &[("VANGUARD_HORS_LIGNE", "1")],
        );
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        assert!(debut.elapsed() < Duration::from_secs(60), "{:?}", debut.elapsed());
        let t = sans_couleurs(&s.texte);
        if langue == "fr" {
            assert!(t.contains("Logiciels espions : en ai-je un ?"), "{t}");
            assert!(t.contains("liste d'Échap non vérifiée : hors ligne demandé"), "{t}");
            assert!(t.contains("Indicateurs : Échap (CC-BY 4.0)"), "{t}");
            assert!(!t.to_lowercase().contains("aucun logiciel espion"), "{t}");
            if t.contains("Aucun signe") {
                assert!(t.contains("point(s) non vérifié(s)"), "{t}");
            }
        } else {
            assert!(t.contains("Spyware: is someone watching me?"), "{t}");
            assert!(t.contains("Échap list not checked: offline mode requested"), "{t}");
        }
    }
    let _ = std::fs::remove_dir_all(&maison);
    let aide = vanguard("en", &["spyware", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("known stalkerware servers"),
        "{}",
        aide.texte
    );
}

/// Les logiciels pas à jour, sans Internet : rien ne part, la commande rend la main vite et sans planter. Sous
/// Linux, elle renvoie au gestionnaire de paquets ; sous Windows (Wine), elle dit d'où viennent les versions et que
/// rien de l'ordinateur n'est envoyé.
#[test]
fn logiciels_perimes_hors_ligne() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    for (langue, commande) in [("fr", "logiciels-perimes"), ("en", "outdated-software")] {
        let debut = Instant::now();
        let s = vanguard_dans_env(
            programme,
            &maison,
            langue,
            &[commande],
            "",
            90,
            &[("VANGUARD_HORS_LIGNE", "1")],
        );
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        assert!(!s.erreurs.contains("panicked"), "{}", s.erreurs);
        assert!(debut.elapsed() < Duration::from_secs(60), "{:?}", debut.elapsed());
        // Les lignes coupées à 76 colonnes, remises bout à bout.
        let t = sans_couleurs(&s.texte).split_whitespace().collect::<Vec<_>>().join(" ");
        let (titre, linux, mention) = if langue == "fr" {
            (
                "Logiciels pas à jour",
                "Sous Linux, le gestionnaire de paquets tient les versions",
                "rien de cet ordinateur n'est envoyé",
            )
        } else {
            (
                "Outdated software",
                "On Linux, the package manager keeps the versions",
                "nothing about this computer is sent",
            )
        };
        assert!(t.contains(titre), "{t}");
        if cfg!(target_os = "linux") {
            assert!(t.contains(linux), "{t}");
        } else {
            assert!(t.contains(mention), "{t}");
        }
    }
    let _ = std::fs::remove_dir_all(&maison);
    let aide = vanguard("en", &["outdated-software", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("Firefox and Edge checked flaw by flaw"),
        "{}",
        aide.texte
    );
    let aide = vanguard("fr", &["logiciels-perimes", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("Logiciels pas à jour"),
        "{}",
        aide.texte
    );
}

/// Vérifier Vanguard lui-même : version, date et empreinte, sans rien changer.
#[test]
fn verifier_moi_en_lecture_seule() {
    let s = vanguard("fr", &["verifier-moi"], "", 120);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Vérifier Vanguard lui-même") && t.contains(env!("CARGO_PKG_VERSION")),
        "{t}"
    );
    // Sous Wine, pas de PowerShell : l'empreinte est dite impossible, jamais inventée.
    assert!(t.contains("SHA-256") || t.contains("Empreinte impossible"), "{t}");
    assert!(t.contains("Compilé le"), "{t}");
    // Sans terminal, la question de l'historique signé n'est pas posée : elle aurait lu la fin de l'entrée et quitté
    // avant l'avertissement final. Ses lignes sont recollées : le paragraphe est coupé à la largeur.
    let mots = t.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(mots.contains("Si elles diffèrent, ne l'utilisez pas."), "{t}");
}

/// Programmes au démarrage : la liste se montre, et Entrée sans rien décocher ne change rien.
#[test]
fn demarrage_sans_rien_changer() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let s = vanguard("fr", &["demarrage"], "\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(!t.contains("À appliquer") && !t.contains("À annuler"), "{t}");
    assert!(t.contains("Rien à changer") || t.contains("Aucun programme"), "{t}");
    let aide = vanguard("en", &["startup", "--help"], "", 30);
    assert!(
        sans_couleurs(&aide.texte).contains("Startup programs"),
        "{}",
        aide.texte
    );
}

/// Retirer ou remettre au démarrage d'après une empreinte inventée ou mal formée : refusé, dit en une ligne JSON (la
/// dernière), code non nul, rien de changé. Une empreinte inventée ne répond à aucun programme réel.
#[test]
fn demarrage_refuse_une_empreinte_inconnue_ou_mal_formee() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let inventee = "0123456789abcdef0123456789abcdef";
    let cas: [(&[&str], &str, i32); 5] = [
        (&["demarrage", "--retirer", inventee, "--json"], "retirer", 1),
        (&["demarrage", "--remettre", inventee, "--json"], "remettre", 1),
        (
            &["demarrage", "--retirer", "0123456789ABCDEF0123456789ABCDEF", "--json"],
            "retirer",
            2,
        ),
        (
            &["demarrage", "--remettre", "../../etc/passwd", "--json"],
            "remettre",
            2,
        ),
        (&["startup", "--remove", "Lecteur", "--json"], "retirer", 2),
    ];
    for (args, geste, code) in cas {
        let s = vanguard("fr", args, "", 60);
        assert_eq!(s.code, Some(code), "{args:?} : {} {}", s.texte, s.erreurs);
        let derniere = s.texte.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(derniere).unwrap_or_else(|e| panic!("{e} : {derniere}"));
        assert_eq!(
            (v["geste"].as_str(), v["issue"].as_str()),
            (Some(geste), Some("refuse")),
            "{v}"
        );
        assert!(v["raison"].as_str().is_some_and(|r| !r.is_empty()), "{v}");
    }
    // Sans --json : le refus se dit en clair, en anglais aussi.
    let s = vanguard("en", &["startup", "--put-back", inventee], "", 60);
    assert_eq!(s.code, Some(1), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("Nothing changed"), "{}", s.texte);
    // Les deux à la fois : refusé par les arguments.
    let s = vanguard(
        "fr",
        &["demarrage", "--retirer", inventee, "--remettre", inventee],
        "",
        30,
    );
    assert_eq!(s.code, Some(2), "{}", s.erreurs);
}

/// Retirer puis remettre de bout en bout, comme le fait la fenêtre (par le relais) : un programme inventé du dossier
/// d'autostart jetable, son empreinte lue dans `demarrage --json`, retiré (« Hidden=true »), puis remis : le fichier
/// revient à l'octet près, et chaque geste est au journal des événements. Puis la vieille note (F2) : le programme
/// retiré est réactivé autrement à la main, retiré de nouveau, remis : c'est la valeur d'avant ce second retrait qui
/// revient, pas celle du premier. Sans bus de session (systemctl --user ne répond pas) ; les dossiers du système
/// (XDG_CONFIG_DIRS) sont un dossier jetable vide.
#[test]
fn demarrage_retire_puis_remet_a_l_octet_pres() {
    if !cfg!(target_os = "linux") {
        return essais::saute("Linux seulement");
    }
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let maison = maison_jetable();
    let systeme = maison.join("xdg");
    let autostart = maison.join("config/autostart");
    std::fs::create_dir_all(&systeme).unwrap();
    std::fs::create_dir_all(&autostart).unwrap();
    let fichier = autostart.join("lecteur.desktop");
    let v1 = "[Desktop Entry]\nType=Application\nName=Lecteur\nExec=/home/alice/bin/lecteur\n# garde ce commentaire\n";
    std::fs::write(&fichier, v1).unwrap();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let systeme_txt = systeme.to_string_lossy().into_owned();
    let lancer = |args: &[&str]| {
        vanguard_dans_env(
            programme,
            &maison,
            "fr",
            args,
            "",
            60,
            &[("XDG_CONFIG_DIRS", systeme_txt.as_str())],
        )
    };
    // L'empreinte que `demarrage --json` donne au geste attendu (« retirer » ou « remettre ») du Lecteur.
    let empreinte = |sorte: &str| {
        let s = lancer(&["demarrage", "--json"]);
        assert_eq!(s.code, Some(0), "{} {}", s.texte, s.erreurs);
        let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{e} : {}", s.texte));
        let gestes: Vec<&serde_json::Value> = v["constats"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("geste"))
            .filter(|g| g["nom"] == "Lecteur")
            .collect();
        assert_eq!(gestes.len(), 1, "{v}");
        assert_eq!(gestes[0]["sorte"].as_str(), Some(sorte), "{v}");
        gestes[0]["empreinte"].as_str().unwrap().to_string()
    };
    let changer = |option: &str, e: &str, geste: &str| {
        let s = lancer(&["demarrage", option, e, "--json"]);
        let derniere = s.texte.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(derniere).unwrap_or_else(|e| panic!("{e} : {}", s.texte));
        assert_eq!(
            (s.code, v["geste"].as_str(), v["issue"].as_str()),
            (Some(0), Some(geste), Some("fait")),
            "{option} : {} {}",
            s.texte,
            s.erreurs
        );
    };
    let lu = || std::fs::read_to_string(&fichier).unwrap();

    let e = empreinte("retirer");
    changer("--retirer", &e, "retirer");
    assert!(lu().lines().any(|l| l == "Hidden=true"), "{}", lu());
    assert!(lu().contains("# garde ce commentaire"), "{}", lu());
    assert_eq!(empreinte("remettre"), e, "même programme, même empreinte");
    changer("--remettre", &e, "remettre");
    assert_eq!(lu(), v1, "remis à l'octet près");
    assert_eq!(empreinte("retirer"), e);

    // F2 : une note restée d'un retrait d'avant ne prend pas la place de la valeur lue maintenant.
    changer("--retirer", &e, "retirer");
    let v2 = "[Desktop Entry]\nType=Application\nName=Lecteur\nExec=/home/alice/bin/lecteur --discret\n";
    std::fs::write(&fichier, v2).unwrap();
    changer("--retirer", &e, "retirer");
    assert!(lu().lines().any(|l| l == "Hidden=true"), "{}", lu());
    changer("--remettre", &e, "remettre");
    assert_eq!(lu(), v2, "la valeur d'avant le dernier retrait");

    // Chaque geste est au journal des événements, avec son empreinte et le nom du programme.
    let mut journal = String::new();
    for f in std::fs::read_dir(maison.join("donnees/vanguard/evenements"))
        .unwrap()
        .flatten()
    {
        journal.push_str(&std::fs::read_to_string(f.path()).unwrap_or_default());
    }
    let cle = format!("demarrage|{e}");
    let notes: Vec<&str> = journal.lines().filter(|l| l.contains(&cle)).collect();
    assert_eq!(notes.len(), 5, "{journal}");
    assert!(notes.iter().all(|l| l.contains("Lecteur")), "{journal}");
}

/// Le démarrage changé comme une fenêtre prise en main (ou un autre programme du compte) le demanderait, après la
/// campagne d'attaque du lot 2a : chaque essai dit le comportement sûr attendu. Tout se passe dans un dossier
/// personnel jetable, sans bus de session, avec des programmes inventés ; seules des entrées d'autostart du dossier
/// jetable sont visées (jamais un service, jamais un réglage du système).
#[cfg(target_os = "linux")]
mod demarrage_sous_attaque {
    use super::*;
    use std::collections::BTreeSet;

    struct Banc {
        maison: essais::Jetable,
        systeme: String,
        autostart: PathBuf,
    }

    impl Banc {
        fn nouveau(nom: &str) -> Banc {
            let maison = essais::Jetable::nouveau(nom);
            let systeme = maison.join("xdg");
            let autostart = maison.join("config/autostart");
            std::fs::create_dir_all(&systeme).unwrap();
            std::fs::create_dir_all(&autostart).unwrap();
            Banc {
                systeme: systeme.to_string_lossy().into_owned(),
                autostart,
                maison,
            }
        }

        fn lancer(&self, args: &[&str]) -> Sortie {
            vanguard_dans_env(
                Path::new(env!("CARGO_BIN_EXE_vanguard")),
                &self.maison,
                "fr",
                args,
                "",
                180,
                &[("XDG_CONFIG_DIRS", self.systeme.as_str())],
            )
        }

        /// Pose une entrée d'autostart inventée ; rend son chemin et son contenu.
        fn poser(&self, fichier: &str, nom: &str, exec: &str) -> (PathBuf, String) {
            let texte = format!("[Desktop Entry]\nType=Application\nName={nom}\nExec={exec}\n");
            let chemin = self.autostart.join(fichier);
            std::fs::write(&chemin, &texte).unwrap();
            (chemin, texte)
        }

        /// `demarrage --json` : le résultat lu, et sa sortie brute (ce que le relais lit).
        fn liste(&self) -> (serde_json::Value, String) {
            let s = self.lancer(&["demarrage", "--json"]);
            assert_eq!(s.code, Some(0), "{} {}", s.texte, s.erreurs);
            let v = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{e} : {}", s.texte));
            (v, s.texte)
        }

        /// Le bouton que l'écran donne au programme `nom` : (sorte, empreinte) ; `None` : aucun bouton.
        fn geste(&self, nom: &str) -> Option<(String, String)> {
            gestes(&self.liste().0)
                .into_iter()
                .find(|g| g.0 == nom)
                .map(|(_, sorte, e)| (sorte, e))
        }

        /// Ce qui n'a pas pu être lu, d'après la liste.
        fn manques(&self) -> String {
            self.liste().0["couverture"].to_string()
        }

        /// `demarrage <option> <empreinte> --json` : (code, issue, raison).
        fn changer(&self, option: &str, e: &str) -> (Option<i32>, String, String) {
            let s = self.lancer(&["demarrage", option, e, "--json"]);
            let derniere = s.texte.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or_default();
            let v: serde_json::Value =
                serde_json::from_str(derniere).unwrap_or_else(|e| panic!("{e} : {} {}", s.texte, s.erreurs));
            (
                s.code,
                v["issue"].as_str().unwrap_or_default().to_string(),
                v["raison"].as_str().unwrap_or_default().to_string(),
            )
        }

        /// `vanguard <args>` lancé avec l'arrêt d'essai `etape` (`VANGUARD_ESSAI_ARRET`, binaire de débogage
        /// seulement), tué net une fois figé là.
        fn tuer_a(&self, args: &[&str], etape: &str) {
            use std::io::BufRead as _;
            let mut enfant = Command::new(env!("CARGO_BIN_EXE_vanguard"))
                .args(args)
                .env("VANGUARD_ESSAI_ARRET", etape)
                .env("XDG_CONFIG_DIRS", &self.systeme)
                .env("VANGUARD_LANG", "fr")
                .env("USER", "essai")
                .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
                .env("XDG_RUNTIME_DIR", self.maison.join("run"))
                .env("HOME", &*self.maison)
                .env("XDG_DATA_HOME", self.maison.join("donnees"))
                .env("XDG_CONFIG_HOME", self.maison.join("config"))
                .env("XDG_CACHE_HOME", self.maison.join("cache"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let sortie = lire_en_fond(enfant.stdout.take().unwrap());
            let mut erreurs = std::io::BufReader::new(enfant.stderr.take().unwrap());
            let mut ligne = String::new();
            loop {
                ligne.clear();
                if erreurs.read_line(&mut ligne).unwrap_or(0) == 0 {
                    let _ = enfant.kill();
                    let _ = enfant.wait();
                    panic!("jamais arrêté à « {etape} » : {}", sortie.join().unwrap_or_default());
                }
                if ligne.trim_end() == format!("essai : arrêt {etape}") {
                    break;
                }
            }
            let _ = enfant.kill();
            let _ = enfant.wait();
        }

        /// Le dossier des notes de Vanguard, celui de `reglages.json`.
        fn donnees(&self) -> PathBuf {
            let d = self.maison.join("donnees/vanguard");
            assert!(
                d.join("reglages.json").is_file(),
                "reglages.json absent de {}",
                d.display()
            );
            d
        }

        /// Les lignes du journal des événements qui parlent de cette empreinte.
        fn au_journal(&self, e: &str) -> Vec<String> {
            let cle = format!("demarrage|{e}");
            let mut lignes = Vec::new();
            for f in std::fs::read_dir(self.maison.join("donnees/vanguard/evenements"))
                .into_iter()
                .flatten()
                .flatten()
            {
                let t = std::fs::read_to_string(f.path()).unwrap_or_default();
                lignes.extend(t.lines().filter(|l| l.contains(&cle)).map(str::to_string));
            }
            lignes
        }
    }

    /// Les gestes de la liste : (nom, sorte, empreinte).
    fn gestes(v: &serde_json::Value) -> Vec<(String, String, String)> {
        let mot = |g: &serde_json::Value, cle: &str| g[cle].as_str().unwrap_or_default().to_string();
        v["constats"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("geste"))
            .map(|g| (mot(g, "nom"), mot(g, "sorte"), mot(g, "empreinte")))
            .collect()
    }

    fn lu(f: &Path) -> String {
        std::fs::read_to_string(f).unwrap_or_else(|e| format!("<illisible : {e}>"))
    }

    fn copier(de: &Path, vers: &Path) {
        std::fs::create_dir_all(vers).unwrap();
        for f in std::fs::read_dir(de).unwrap().flatten() {
            let (a, b) = (f.path(), vers.join(f.file_name()));
            if f.file_type().unwrap().is_dir() {
                copier(&a, &b);
            } else if f.file_type().unwrap().is_file() {
                std::fs::copy(&a, &b).unwrap();
            }
        }
    }

    /// L'empreinte d'une entrée d'autostart, comme `vanguard` la calcule (BLAKE3 de « demarrage:autostart|chemin »,
    /// 16 octets) : pour viser une entrée que la liste ne montre pas, comme un programme du compte le pourrait.
    fn empreinte_de(chemin: &Path) -> String {
        let h = blake3::hash(format!("demarrage:autostart|{}", chemin.display()).as_bytes());
        h.to_hex()[..32].to_string()
    }

    /// A1. Vanguard a retiré le Lecteur (note gardée), puis le Lecteur a été réécrit hors de Vanguard et se lance de
    /// nouveau : l'écran n'offre que « Retirer ». « Remettre » avec la même empreinte est refusé, le fichier de
    /// maintenant reste.
    #[test]
    fn remettre_refuse_quand_le_programme_se_lance() {
        let b = Banc::nouveau("remettre-actif");
        let (f, _) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --ancien");
        let (sorte, e) = b.geste("Lecteur").unwrap();
        assert_eq!(sorte, "retirer");
        assert_eq!(e, empreinte_de(&f), "l'empreinte se calcule hors de Vanguard");
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        let (_, v2) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --nouveau");
        assert_eq!(b.geste("Lecteur").map(|g| g.0).as_deref(), Some("retirer"));
        let (code, issue, raison) = b.changer("--remettre", &e);
        assert_eq!((code, issue.as_str()), (Some(1), "refuse"), "{raison}");
        assert!(raison.contains("se lance déjà"), "{raison}");
        assert_eq!(lu(&f), v2);
        // La note reste : retiré de nouveau, il se remet comme il était juste avant (v2).
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        assert_eq!(b.changer("--remettre", &e).1, "fait");
        assert_eq!(lu(&f), v2);
    }

    /// A2. La note d'un vieux retrait vise un fichier où se trouve maintenant un programme à garder (aucun bouton à
    /// l'écran) : « Remettre » est refusé, rien n'est réécrit.
    #[test]
    fn remettre_n_ecrase_pas_un_programme_a_garder() {
        let b = Banc::nouveau("remettre-garder");
        let (f, _) = b.poser("agent.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let (_, e) = b.geste("Lecteur").unwrap();
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        let (_, v2) = b.poser("agent.desktop", "ClamTk", "/opt/clamtk/clamtk --veille");
        let (v, _) = b.liste();
        assert!(v.to_string().contains("à garder"), "{v}");
        assert_eq!(b.geste("ClamTk"), None, "un programme à garder n'a aucun bouton");
        let (code, issue, raison) = b.changer("--remettre", &e);
        assert_eq!((code, issue.as_str()), (Some(1), "refuse"), "{raison}");
        assert_eq!(lu(&f), v2);
    }

    /// « Tout remettre comme avant » (`optimiser annuler`) ne réécrit pas non plus, d'après une vieille note, une
    /// entrée qui se lance de nouveau : la note est refusée, dite, et gardée.
    #[test]
    fn tout_remettre_n_ecrase_pas_une_entree_qui_se_lance() {
        let b = Banc::nouveau("tout-remettre-actif");
        let (f, _) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --ancien");
        let e = empreinte_de(&f);
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        let (_, v2) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --nouveau");
        let s = vanguard_dans_env(
            Path::new(env!("CARGO_BIN_EXE_vanguard")),
            &b.maison,
            "fr",
            &["optimiser", "annuler"],
            "o\n",
            180,
            &[("XDG_CONFIG_DIRS", b.systeme.as_str())],
        );
        let tout = espaces_unis(&format!("{}{}", s.texte, s.erreurs));
        assert_eq!(lu(&f), v2, "{tout}");
        assert!(tout.contains("se lance déjà"), "{tout}");
        // La note est gardée : la liste n'offre pas « Remettre » (il se lance), mais un nouveau retrait se remet.
        assert_eq!(b.geste("Lecteur").map(|g| g.0).as_deref(), Some("retirer"));
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        assert_eq!(b.changer("--remettre", &e).1, "fait");
        assert_eq!(lu(&f), v2);
    }

    /// A3. Le Lecteur est retiré (note), puis les notes sont changées hors de Vanguard (douteuses : l'écran le dit).
    /// Retirer la Musique est alors refusé comme « Remettre » : une première écriture remplacerait les notes par des
    /// neuves, et le Lecteur ne se remettrait plus. Les notes remises comme elles étaient, il se remet.
    #[test]
    fn retirer_refuse_sur_des_notes_douteuses() {
        let b = Banc::nouveau("notes-douteuses");
        let (fa, va) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let (fb, vb) = b.poser("musique.desktop", "Musique", "/home/alice/bin/musique");
        let (_, ea) = b.geste("Lecteur").unwrap();
        let (_, eb) = b.geste("Musique").unwrap();
        assert_eq!(b.changer("--retirer", &ea).1, "fait");
        let notes = b.donnees().join("reglages.json");
        let original = lu(&notes);
        std::fs::write(&notes, format!("{original} ")).unwrap();
        assert!(b.manques().contains("notes de Vanguard"), "le doute est dit");
        assert_eq!(b.changer("--remettre", &ea).1, "refuse");
        let (code, issue, raison) = b.changer("--retirer", &eb);
        assert_eq!((code, issue.as_str()), (Some(1), "refuse"), "{raison}");
        assert!(raison.contains("notes de Vanguard"), "{raison}");
        assert_eq!(lu(&fb), vb, "rien n'est retiré");
        assert_eq!(lu(&notes), format!("{original} "), "les notes ne sont pas réécrites");
        assert!(b.manques().contains("notes de Vanguard"), "l'avertissement reste");
        std::fs::write(&notes, &original).unwrap();
        assert_eq!(b.changer("--remettre", &ea).1, "fait");
        assert_eq!(lu(&fa), va);
    }

    /// A4. Deux changements à la fois, hors du relais (un autre programme du compte lance `vanguard` en même temps) :
    /// six retraits ensemble, puis six remises ensemble, trois tours. Chaque « fait » a sa note (il se remet à l'octet
    /// près), chaque refus n'a rien changé, aucun fichier temporaire ne traîne.
    #[test]
    fn changements_simultanes_sans_note_perdue() {
        let b = Banc::nouveau("simultanes");
        let programmes: Vec<(PathBuf, String, String)> = (0..6)
            .map(|i| {
                let nom = format!("Programme{i}");
                let (f, v) = b.poser(&format!("p{i}.desktop"), &nom, &format!("/home/alice/bin/p{i}"));
                (f, v, nom)
            })
            .collect();
        let empreintes: Vec<String> = programmes.iter().map(|(f, _, _)| empreinte_de(f)).collect();
        let ensemble = |option: &'static str| -> Vec<(Option<i32>, String, String)> {
            std::thread::scope(|s| {
                let fils: Vec<_> = empreintes.iter().map(|e| s.spawn(|| b.changer(option, e))).collect();
                fils.into_iter().map(|f| f.join().unwrap()).collect()
            })
        };
        for tour in 0..3 {
            let retraits = ensemble("--retirer");
            for ((f, v, nom), r) in programmes.iter().zip(&retraits) {
                let cache = lu(f).lines().any(|l| l == "Hidden=true");
                if r.1 == "fait" {
                    assert!(cache, "tour {tour} {nom} : dit fait, pas retiré");
                } else {
                    assert_eq!(&lu(f), v, "tour {tour} {nom} : refusé ({r:?}) mais changé");
                }
            }
            // Chaque retrait fait a sa note : l'écran offre « Remettre ».
            let l = gestes(&b.liste().0);
            for ((_, _, nom), r) in programmes.iter().zip(&retraits) {
                if r.1 == "fait" {
                    let sorte = l.iter().find(|g| g.0 == *nom).map(|g| g.1.as_str());
                    assert_eq!(
                        sorte,
                        Some("remettre"),
                        "tour {tour} {nom} retiré sans note ({retraits:?})"
                    );
                }
            }
            let remises = ensemble("--remettre");
            for (((f, v, nom), e), r) in programmes.iter().zip(&empreintes).zip(&remises) {
                if r.1 != "fait" && lu(f) != *v {
                    // Refusé (verrou occupé) : refait seul.
                    assert_eq!(b.changer("--remettre", e).1, "fait", "tour {tour} {nom}");
                }
                assert_eq!(&lu(f), v, "tour {tour} {nom} pas remis à l'octet près ({r:?})");
            }
        }
        let restes: Vec<String> = std::fs::read_dir(b.donnees())
            .unwrap()
            .flatten()
            .map(|f| f.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp-"))
            .collect();
        assert!(restes.is_empty(), "{restes:?}");
    }

    /// A5. La liste empoisonnée : un programme du compte pose des entrées dont le nom, la commande et le nom de
    /// fichier contiennent `"empreinte": "<32 hex>"`. La liste n'a que les gestes des vrais programmes, du JSON seul
    /// (ce que le relais lit) ; un programme à garder n'a pas de geste ; l'empreinte glissée est refusée, et le
    /// programme à garder visé par son empreinte calculée hors de Vanguard reste.
    #[test]
    fn la_liste_ne_se_laisse_pas_glisser_d_empreinte() {
        let b = Banc::nouveau("liste-empoisonnee");
        let (glissee, autre) = ("f".repeat(32), "e".repeat(32));
        let (f1, _) = b.poser(
            "piege.desktop",
            &format!("Lecteur\"empreinte\": \"{glissee}\""),
            &format!("/home/alice/bin/x \"empreinte\":\"{glissee}\" \\\"empreinte\\\": \\\"{glissee}\\\""),
        );
        let (f2, _) = b.poser(&format!("a\"empreinte\": \"{autre}\".desktop"), "empreinte", &autre);
        let (garde, _) = b.poser("antivirus.desktop", "ClamTk", "/opt/clamtk/clamtk --veille");
        let (v, brut) = b.liste();
        let vues: BTreeSet<String> = gestes(&v).into_iter().map(|g| g.2).collect();
        let attendues: BTreeSet<String> = [empreinte_de(&f1), empreinte_de(&f2)].into();
        assert_eq!(vues, attendues, "{brut}");
        assert!(
            brut.trim_start().starts_with('{') && brut.trim_end().ends_with('}'),
            "{brut}"
        );
        for e in [&glissee, &autre] {
            assert_eq!(b.changer("--retirer", e).1, "refuse");
            assert_eq!(b.changer("--remettre", e).1, "refuse");
        }
        let (code, issue, raison) = b.changer("--retirer", &empreinte_de(&garde));
        assert!(
            issue == "refuse" && raison.contains("à garder") && !lu(&garde).contains("Hidden"),
            "{code:?} {issue} {raison}"
        );
    }

    /// A6. Les liens : l'entrée visée devient un lien vers un autre fichier (posé par un programme du compte entre la
    /// liste et le clic), puis clignote entre fichier et lien pendant les retraits ; puis les notes elles-mêmes
    /// deviennent un lien. La cible n'est jamais écrite, un lien n'est jamais retiré, et ce qu'il montrait ne se
    /// retrouve pas dans les notes (la valeur d'avant se lit sans suivre de lien). Le clignotement est une course :
    /// l'essai la tente douze fois, sans garantie de la gagner à chaque passage.
    #[test]
    fn un_lien_ne_fait_ecrire_nulle_part_ailleurs() {
        let b = Banc::nouveau("liens");
        let (f, v1) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let (fm, _) = b.poser("musique.desktop", "Musique", "/home/alice/bin/musique");
        let e = empreinte_de(&f);
        let ailleurs = b.maison.join("ailleurs");
        std::fs::create_dir_all(&ailleurs).unwrap();
        let cible = ailleurs.join("cible.desktop");
        let secret = "[Desktop Entry]\nType=Application\nName=Cible\nExec=/home/alice/bin/cible --cle-inventee\n";
        std::fs::write(&cible, secret).unwrap();
        std::fs::remove_file(&f).unwrap();
        std::os::unix::fs::symlink(&cible, &f).unwrap();
        let (code, issue, raison) = b.changer("--retirer", &e);
        assert!(
            issue == "refuse" && lu(&cible) == secret && f.symlink_metadata().unwrap().file_type().is_symlink(),
            "un lien a été retiré ({code:?} {issue} {raison}) : {}",
            lu(&cible)
        );
        let fin = std::sync::atomic::AtomicBool::new(false);
        let issues = std::thread::scope(|s| {
            s.spawn(|| {
                let mut lien = false;
                while !fin.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = std::fs::remove_file(&f);
                    if lien {
                        let _ = std::os::unix::fs::symlink(&cible, &f);
                    } else {
                        let _ = std::fs::write(&f, &v1);
                    }
                    lien = !lien;
                    std::thread::sleep(Duration::from_micros(300));
                }
            });
            let issues: Vec<String> = (0..12).map(|_| b.changer("--retirer", &e).1).collect();
            fin.store(true, std::sync::atomic::Ordering::Relaxed);
            issues
        });
        assert_eq!(lu(&cible), secret, "la cible du lien a été écrite ({issues:?})");
        let notes = b.maison.join("donnees/vanguard/reglages.json");
        assert!(
            !lu(&notes).contains("--cle-inventee"),
            "ce que montrait le lien est dans les notes ({issues:?})"
        );
        // Les notes deviennent un lien vers la cible : un retrait n'écrit pas à travers.
        let _ = std::fs::remove_file(&notes);
        std::os::unix::fs::symlink(&cible, &notes).unwrap();
        let r = b.changer("--retirer", &empreinte_de(&fm));
        assert_eq!(lu(&cible), secret, "écrit à travers le lien des notes ({r:?})");
    }

    /// Campagne 0.94, C-3. Une entrée de plus de 64 Kio ne se lit pas bornée : `--retirer` la visant n'écrit rien et
    /// ne laisse aucune note vide (avant : écrite, dite « échec », note `null`, jamais remise) ; la liste ne la
    /// propose pas et dit qu'elle n'a pas été lue.
    #[test]
    fn entree_trop_grosse_ni_ecrite_ni_notee() {
        let b = Banc::nouveau("trop-grosse");
        let f = b.autostart.join("gros.desktop");
        let texte = format!(
            "[Desktop Entry]\nType=Application\nName=Gros\nExec=/home/alice/bin/gros\n#{}\n",
            "x".repeat(76 << 10)
        );
        std::fs::write(&f, &texte).unwrap();
        let (code, issue, raison) = b.changer("--retirer", &empreinte_de(&f));
        assert!(lu(&f) == texte, "l'entrée a été écrite ({code:?} {issue} {raison})");
        assert_ne!(issue, "fait", "{raison}");
        let notes = lu(&b.maison.join("donnees/vanguard/reglages.json"));
        assert!(!notes.contains("gros.desktop"), "une note reste : {notes}");
        assert_eq!(b.geste("Gros"), None, "proposée");
        let m = b.manques();
        assert!(m.contains("gros.desktop"), "pas dite non lue : {m}");
    }

    /// Campagne 0.94, C-1. Après un retrait, le fichier de l'entrée devient un tube nommé : la liste et `--remettre`
    /// rendent la main (avant : figés à la lecture du nom, verrou des notes tenu) ; le tube reste, la note aussi.
    #[test]
    fn un_tube_a_la_place_d_une_entree_retiree_ne_fige_rien() {
        let b = Banc::nouveau("tube");
        let (f, _) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let e = empreinte_de(&f);
        let (_, issue, raison) = b.changer("--retirer", &e);
        assert_eq!(issue, "fait", "{raison}");
        std::fs::remove_file(&f).unwrap();
        essais::tube_nomme(&f).unwrap();
        let lancer = |args: &[&str]| {
            vanguard_dans_env(
                Path::new(env!("CARGO_BIN_EXE_vanguard")),
                &b.maison,
                "fr",
                args,
                "",
                30,
                &[("XDG_CONFIG_DIRS", b.systeme.as_str())],
            )
        };
        let s = lancer(&["demarrage", "--json"]);
        assert_eq!(s.code, Some(0), "{} {}", s.texte, s.erreurs);
        let s = lancer(&["demarrage", "--remettre", &e, "--json"]);
        assert_ne!(s.code, Some(0), "remis sur un tube : {}", s.texte);
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(&f.symlink_metadata().unwrap().file_type()),
            "le tube a été remplacé"
        );
        assert!(
            lu(&b.donnees().join("reglages.json")).contains("lecteur.desktop"),
            "la note est perdue"
        );
    }

    /// Campagne 0.94, C-5. Une entrée en 0600 retirée puis remise garde ses droits, pas seulement son contenu.
    #[test]
    fn retirer_puis_remettre_garde_les_droits() {
        use std::os::unix::fs::PermissionsExt as _;
        let b = Banc::nouveau("droits");
        let (f, texte) = b.poser("prive.desktop", "Privé", "/home/alice/bin/prive");
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let droits = || std::fs::metadata(&f).unwrap().permissions().mode() & 0o7777;
        let e = empreinte_de(&f);
        let (_, issue, raison) = b.changer("--retirer", &e);
        assert_eq!(issue, "fait", "{raison}");
        assert_eq!(droits(), 0o600, "retirée : {:o}", droits());
        let (_, issue, raison) = b.changer("--remettre", &e);
        assert_eq!(issue, "fait", "{raison}");
        assert_eq!(lu(&f), texte);
        assert_eq!(droits(), 0o600, "remise : {:o}", droits());
    }

    /// Campagne B, P-1. Vanguard tué entre le carnet des notes (`reglages.json`) et son sceau, pendant un second
    /// retrait : rien n'est dit changé hors de Vanguard, le carnet n'est pas mis de côté, et le premier retrait, fini,
    /// se remet encore à l'octet près.
    #[test]
    fn tue_entre_le_carnet_et_son_sceau_l_annulation_reste() {
        if !cfg!(debug_assertions) {
            return essais::saute("arrêt d'essai : binaire de débogage seulement");
        }
        let b = Banc::nouveau("sceau-tue");
        let (fl, v1) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        b.poser("musique.desktop", "Musique", "/home/alice/bin/musique");
        let (sorte, e) = b.geste("Lecteur").unwrap();
        assert_eq!(sorte, "retirer");
        let r = b.changer("--retirer", &e);
        assert_eq!(r.1, "fait", "{r:?}");
        let (_, em) = b.geste("Musique").unwrap();
        b.tuer_a(&["demarrage", "--retirer", &em, "--json"], "sceau:reglages.json");
        let (_, brut) = b.liste();
        let mis_de_cote: Vec<String> = std::fs::read_dir(b.donnees())
            .unwrap()
            .flatten()
            .map(|f| f.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("falsifie"))
            .collect();
        assert!(mis_de_cote.is_empty(), "carnet mis de côté : {mis_de_cote:?} ; {brut}");
        assert_eq!(b.geste("Lecteur").map(|g| g.0).as_deref(), Some("remettre"), "{brut}");
        let r = b.changer("--remettre", &e);
        assert_eq!(r.1, "fait", "{r:?}");
        assert_eq!(lu(&fl), v1, "remis à l'octet près");
    }

    /// Campagne B, P-3. Le dossier d'autostart du compte (`config/autostart`), puis `config` lui-même, sont des liens
    /// vers un dossier hors du dossier personnel : aucune de ses entrées n'est proposée, ni la copie d'une entrée du
    /// système qui s'y écrirait ; un retrait demandé quand même (empreinte calculée) n'écrit rien hors de la maison.
    #[test]
    fn un_dossier_d_autostart_lien_n_est_ni_propose_ni_ecrit() {
        // Ce que contient le dossier du dehors : chaque nom et son contenu (une écriture, une création se voient).
        fn releve(d: &Path, l: &mut Vec<(PathBuf, String)>) {
            for f in std::fs::read_dir(d).unwrap().flatten() {
                if f.file_type().unwrap().is_dir() {
                    releve(&f.path(), l);
                } else {
                    l.push((f.path(), lu(&f.path())));
                }
            }
            l.sort();
        }
        let instantane = |d: &Path| {
            let mut l = Vec::new();
            releve(d, &mut l);
            l
        };
        for lien in ["config/autostart", "config"] {
            let b = Banc::nouveau("dossier-lien");
            let dehors = essais::Jetable::nouveau("dossier-lien-dehors");
            let (_, v1) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
            std::fs::write(
                Path::new(&b.systeme).join("horloge.desktop"),
                "[Desktop Entry]\nType=Application\nName=Horloge\nExec=/usr/bin/horloge-inventee\n",
            )
            .unwrap();
            // Le même contenu, mais hors de la maison, derrière le lien.
            let autostart_dehors = if lien == "config" {
                dehors.join("autostart")
            } else {
                dehors.to_path_buf()
            };
            copier(&b.autostart, &autostart_dehors);
            std::fs::remove_dir_all(b.maison.join(lien)).unwrap();
            let pointe = if lien == "config" {
                &*dehors
            } else {
                autostart_dehors.as_path()
            };
            std::os::unix::fs::symlink(pointe, b.maison.join(lien)).unwrap();
            let avant = instantane(&dehors);
            assert_eq!(b.geste("Lecteur"), None, "{lien} : entrée proposée à travers le lien");
            assert_eq!(
                b.geste("Horloge"),
                None,
                "{lien} : copie du système proposée à travers le lien"
            );
            for nom in ["lecteur.desktop", "horloge.desktop"] {
                let (_, issue, raison) = b.changer("--retirer", &empreinte_de(&b.autostart.join(nom)));
                assert_ne!(issue, "fait", "{lien} {nom} : {raison}");
            }
            assert_eq!(instantane(&dehors), avant, "{lien} : écrit hors de la maison");
            assert_eq!(lu(&autostart_dehors.join("lecteur.desktop")), v1);
        }
    }

    /// A7. Le verrou des notes tenu par un autre programme du compte (`flock`) : tout changement est refusé sans rien
    /// changer, en un temps borné.
    #[test]
    fn verrou_tenu_par_un_autre_rien_ne_change() {
        if Command::new("flock").arg("--version").output().is_err() {
            return essais::saute("flock (util-linux) absent");
        }
        let b = Banc::nouveau("verrou-tenu");
        let (f, v1) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let (fm, _) = b.poser("musique.desktop", "Musique", "/home/alice/bin/musique");
        // Un premier changement crée le dossier et le fichier du verrou.
        assert_eq!(b.changer("--retirer", &empreinte_de(&fm)).1, "fait");
        let verrou = b.donnees().join("reglages.lock");
        assert!(
            verrou.is_file(),
            "aucun fichier de verrou dans {}",
            b.donnees().display()
        );
        // « -o » : seul flock tient le verrou ; il le rend quand `cat` finit (son entrée fermée plus bas).
        let mut tenu = Command::new("flock")
            .args(["-x", "-o"])
            .arg(&verrou)
            .arg("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let debut = Instant::now();
        let (code, issue, raison) = b.changer("--retirer", &empreinte_de(&f));
        let duree = debut.elapsed();
        drop(tenu.stdin.take());
        let _ = tenu.wait();
        assert!(
            issue == "refuse" && code == Some(1) && lu(&f) == v1 && duree < Duration::from_secs(90),
            "{code:?} {issue} {raison} en {duree:?}"
        );
    }

    /// A8. Des notes forgées, puis rejouées. (a) Une note réécrite sans son sceau ne fait rien remettre. (b) Les notes
    /// et les sceaux d'avant, recopiés par un programme du compte après une remise, ne font pas remettre un vieux
    /// contenu par-dessus une entrée qui se lance (refus « se lance déjà »). Le rejeu sur une entrée qui ne se lance
    /// plus reste une limite dite (MODELE-DE-MENACE.md, « barrière, pas coffre ») : il n'est pas essayé ici.
    #[test]
    fn notes_forgees_ou_rejouees() {
        let b = Banc::nouveau("notes-forgees");
        let (f, v1) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --ancien");
        let e = empreinte_de(&f);
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        let donnees = b.donnees();
        let copie = b.maison.join("copie-des-notes");
        copier(&donnees, &copie);
        assert_eq!(b.changer("--remettre", &e).1, "fait");
        assert_eq!(lu(&f), v1);
        // (a) La note d'avant, réécrite vers un autre programme, sans toucher aux sceaux.
        let forgee = lu(&copie.join("reglages.json")).replace("lecteur --ancien", "pirate --forge");
        assert!(forgee.contains("pirate --forge"), "{forgee}");
        std::fs::write(donnees.join("reglages.json"), &forgee).unwrap();
        let (code, issue, raison) = b.changer("--remettre", &e);
        assert!(
            issue == "refuse" && lu(&f) == v1,
            "{code:?} {issue} {raison} : {}",
            lu(&f)
        );
        // (b) Le fichier a changé depuis (v2) ; notes et sceaux d'avant sont recopiés tels quels.
        let (_, v2) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur --nouveau");
        copier(&copie, &donnees);
        let (code, issue, raison) = b.changer("--remettre", &e);
        assert!(
            issue == "refuse" && lu(&f) == v2,
            "{code:?} {issue} {raison} : {}",
            lu(&f)
        );
        assert!(raison.contains("se lance déjà"), "{raison}");
    }

    /// A9. Une fenêtre prise en main (ou un autre programme du compte) répète une demande refusée : le même refus
    /// pour la même empreinte ne s'écrit qu'une fois au journal des événements en 10 minutes, et ne noie pas les
    /// alertes. Un changement fait s'écrit toujours, un refus qui dit autre chose aussi.
    #[test]
    fn des_refus_repetes_ne_noient_pas_le_journal() {
        let b = Banc::nouveau("refus-repetes");
        let (f, _) = b.poser("lecteur.desktop", "Lecteur", "/home/alice/bin/lecteur");
        let e = empreinte_de(&f);
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        assert_eq!(b.au_journal(&e).len(), 1);
        // Le Lecteur ne se lance plus : « retirer » est refusé à chaque fois.
        for _ in 0..40 {
            assert_eq!(b.changer("--retirer", &e).1, "refuse");
        }
        let lignes = b.au_journal(&e);
        assert_eq!(lignes.len(), 2, "{lignes:#?}");
        assert!(lignes[1].contains("refusé"), "{lignes:#?}");
        // Un changement fait s'écrit, puis un refus d'une autre raison aussi (une fois).
        assert_eq!(b.changer("--remettre", &e).1, "fait");
        for _ in 0..3 {
            assert_eq!(b.changer("--remettre", &e).1, "refuse");
        }
        let lignes = b.au_journal(&e);
        assert_eq!(lignes.len(), 4, "{lignes:#?}");
        assert!(
            lignes[2].contains(": fait") && lignes[3].contains("refusé"),
            "{lignes:#?}"
        );

        // Après un fait, le même refus qu'avant s'écrit de nouveau : seul le dernier mot noté compte.
        assert_eq!(b.changer("--retirer", &e).1, "fait");
        assert_eq!(b.changer("--retirer", &e).1, "refuse");
        assert_eq!(b.au_journal(&e).len(), 6);
    }
}

/// Lancés sans Internet : outils/verifier.sh refait toute la suite dans un espace réseau vide (unshare -rn, la boucle
/// locale seule) et pose VANGUARD_HORS_LIGNE. Ailleurs, ce test ne fait rien : Internet y répondrait.
fn hors_ligne() -> bool {
    std::env::var_os("VANGUARD_HORS_LIGNE").is_some()
}

/// Sans Internet, chaque outil qui en dépend s'arrête de lui-même, vite, sans planter, et dit pourquoi : jamais une
/// attente sans fin, jamais un « tout va bien » qu'il n'a pas pu vérifier.
#[test]
fn sans_internet_chaque_outil_le_dit() {
    if !hors_ligne() || cfg!(not(target_os = "linux")) {
        return essais::saute("seulement sans Internet (verifier.sh, unshare -rn)");
    }
    let dossier = maison_jetable();
    let eml = courriel_piege(&dossier);
    let cas: [(&[&str], &str, &str); 8] = [
        (
            &["listes-noires"],
            "o\n",
            "Travail sans Internet demandé : rien n'a été envoyé",
        ),
        (&["nat"], "", "Aucun serveur n'a répondu"),
        (&["dns-rapide"], "", "ne répond pas"),
        (&["connexions-sortantes"], "", "Aucune connexion vers Internet"),
        (&["logiciels-espions"], "", "liste d'Échap non vérifiée"),
        (&["test-connexion"], "", "Internet ne répond pas : test arrêté"),
        (
            &["lien", "https://exemple.com/a"],
            "n\n",
            "listes et âge du domaine non vérifiés",
        ),
        (
            &["courriel-suspect", eml.to_str().unwrap()],
            "o\n",
            "listes publiques non vérifiés",
        ),
    ];
    for (args, entree, attendu) in cas {
        let debut = Instant::now();
        let s = vanguard("fr", args, entree, 90);
        let texte = sans_couleurs(&s.texte);
        assert_eq!(s.code, Some(0), "{args:?} : {}", s.erreurs);
        assert!(!s.erreurs.contains("panicked"), "{args:?} : {}", s.erreurs);
        assert!(texte.contains(attendu), "{args:?} : « {attendu} » absent de\n{texte}");
        assert!(
            debut.elapsed() < Duration::from_secs(60),
            "{args:?} : {:?}",
            debut.elapsed()
        );
    }
    let _ = std::fs::remove_dir_all(&dossier);
    // Le scan sans réseau local : une erreur claire, pas une attente.
    let s = vanguard("fr", &["appareils"], "", 60);
    assert_eq!(s.code, Some(1), "{}", s.texte);
    assert!(
        sans_couleurs(&s.erreurs).contains("impossible de détecter le réseau local"),
        "{}",
        s.erreurs
    );
    // L'audit du réseau sans réseau local : en moins d'une minute, six domaines tous « non vérifié », aucune note,
    // un JSON qui se relit ; à l'écran, le pourquoi.
    let debut = Instant::now();
    let s = vanguard("fr", &["audit-reseau", "--json"], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(debut.elapsed() < Duration::from_secs(60), "{:?}", debut.elapsed());
    let audit: serde_json::Value = serde_json::from_str(&s.texte).expect("audit-reseau --json : JSON illisible");
    assert!(audit["score"].is_null() && audit["appareils"].is_null(), "{audit}");
    let domaines = audit["domaines"].as_array().expect("pas de domaines");
    assert_eq!(domaines.len(), 6);
    for d in domaines {
        assert!(d["score"].is_null(), "{d}");
        let constats = d["constats"].as_array().expect("pas de constats");
        assert!(
            !constats.is_empty() && constats.iter().all(|c| c["verifie"] == false),
            "{d}"
        );
    }
    let ecran = vanguard("fr", &["audit-reseau"], "", 60);
    assert_eq!(ecran.code, Some(0), "{}", ecran.erreurs);
    let texte = sans_couleurs(&ecran.texte);
    assert!(
        texte.contains("Pas de réseau local à auditer") && texte.contains("Note de l'audit : aucune"),
        "{texte}"
    );
}

/// L'audit du réseau : dans l'aide des deux langues, avec son alias et ses options ; au sous-menu « Réseau et
/// Internet », juste après « Scanner le réseau », chaque ligne dans 76 colonnes. Rien n'est lancé.
#[test]
fn audit_du_reseau_au_menu_et_dans_l_aide() {
    // L'aide générée montre les noms de la langue de l'interface, rangés comme le menu.
    let aide = vanguard("en", &["--help"], "", 30);
    assert!(
        aide.texte.contains("5 Network and Internet") && aide.texte.contains("network-audit"),
        "{}",
        aide.texte
    );
    let aide_fr = vanguard("fr", &["--help"], "", 30);
    assert!(aide_fr.texte.contains("audit-reseau"), "{}", aide_fr.texte);
    let commande = vanguard("en", &["network-audit", "--help"], "", 30);
    assert_eq!(commande.code, Some(0), "{}", commande.erreurs);
    assert!(
        commande.texte.contains("Network audit by domain")
            && commande.texte.contains("--invite")
            && commande.texte.contains("guest network"),
        "{}",
        commande.texte
    );
    let fr = vanguard("fr", &["audit-reseau", "--help"], "", 30);
    assert!(
        fr.texte.contains("six notes") && fr.texte.contains("réseau invité"),
        "{}",
        fr.texte
    );
    // 5 : le groupe Réseau et Internet ; Entrée : revenir ; q : quitter.
    let s = vanguard("fr", &[], "5\n\nq\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    let appareils = t.find("Appareils du réseau").expect("« Appareils du réseau » absent");
    let audit = t.find("Audit du réseau").expect("« Audit du réseau » absent");
    let nommer = t.find("Nommer un appareil").expect("« Nommer un appareil » absent");
    assert!(appareils < audit && audit < nommer, "{t}");
    assert!(t.contains("six notes : routeur, Wi-Fi, DNS…"), "{t}");
    let longues: Vec<&str> = t
        .lines()
        .filter(|l| !l.contains("Choix :") && l.chars().count() > 76)
        .collect();
    assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues");
}

/// Les outils de la 0.61 et de la 0.62, en lecture seule ou refusés : ils s'ouvrent, disent ce qu'ils voient et ne
/// changent rien. (Le rapport à laisser n'est pas lancé ici : il ouvre le navigateur.)
#[test]
fn outils_recents_sans_rien_changer() {
    let camera = vanguard("fr", &["camera-micro"], "", 60);
    assert_eq!(camera.code, Some(0), "{}", camera.erreurs);
    assert!(
        sans_couleurs(&camera.texte).contains("Caméra et micro : qui s'en sert ?"),
        "{}",
        camera.texte
    );
    let changements = vanguard("fr", &["changements"], "", 30);
    assert_eq!(changements.code, Some(0), "{}", changements.erreurs);
    assert!(
        sans_couleurs(&changements.texte).contains("aucune correction n'a été lancée"),
        "{}",
        changements.texte
    );
    let quarantaine = vanguard("fr", &["quarantaine"], "", 30);
    assert_eq!(quarantaine.code, Some(0), "{}", quarantaine.erreurs);
    assert!(
        sans_couleurs(&quarantaine.texte).contains("La quarantaine est vide."),
        "{}",
        quarantaine.texte
    );
    let copie = vanguard("fr", &["verifier-copie", "/chemin/qui/n-existe/pas"], "", 30);
    assert_eq!(copie.code, Some(0), "{}", copie.erreurs);
    assert!(
        sans_couleurs(&copie.texte).contains("Aucune copie de Vanguard ici"),
        "{}",
        copie.texte
    );
    // Parcours « Mon compte a été piraté », quitté à la première question.
    let compte = vanguard("en", &["troubleshoot", "account"], "", 30);
    assert_eq!(compte.code, Some(0), "{}", compte.erreurs);
    assert!(
        sans_couleurs(&compte.texte).contains("My account was hacked"),
        "{}",
        compte.texte
    );
    let aide = vanguard("fr", &["--help"], "", 30);
    for commande in [
        "camera-micro",
        "quarantaine",
        "verifier-copie",
        "verifier-cle",
        "sauvegarde-auto",
        "raccourci",
        "rapport-a-laisser",
    ] {
        assert!(aide.texte.contains(commande), "aide sans « {commande} »");
    }
}

/// Bilan de confidentialité, sans terminal et dans les deux langues : il s'ouvre, passe les quatre permissions, ne
/// change rien et tient dans 76 colonnes. Sans D-Bus (les essais le coupent) ou sous Wine, une lecture échoue : elle
/// doit se dire « non vérifiée », jamais disparaître.
#[test]
fn bilan_de_confidentialite_en_lecture_seule() {
    for (langue, titre, permissions, fin) in [
        (
            "fr",
            "Bilan de confidentialité",
            ["POSITION", "CONTACTS", "CAMÉRA", "MICRO"],
            "Rien n'a été changé.",
        ),
        (
            "en",
            "Privacy check",
            ["LOCATION", "CONTACTS", "CAMERA", "MICROPHONE"],
            "Nothing was changed.",
        ),
    ] {
        let s = vanguard(langue, &["bilan-confidentialite"], "", 120);
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        let t = sans_couleurs(&s.texte);
        assert!(t.contains(titre), "{t}");
        for p in permissions {
            assert!(t.contains(&format!("── {p}")), "{p} absent : {t}");
        }
        assert!(t.contains(fin), "{t}");
        let longues: Vec<&str> = t.lines().filter(|l| l.chars().count() > 76).collect();
        assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues");
    }
    // L'alias anglais mène au même écran.
    let alias = vanguard("en", &["privacy-review"], "", 120);
    assert!(sans_couleurs(&alias.texte).contains("Privacy check"));
}

/// Raccourci sur cet ordinateur, dans un dossier personnel jetable : refusé, rien n'est posé ; posé puis retiré, il
/// apparaît puis disparaît. Linux seulement : sous Windows, il va sur le Bureau.
#[test]
fn raccourci_pose_puis_retire() {
    if !cfg!(target_os = "linux") {
        return essais::saute("Linux seulement");
    }
    let refus = vanguard("fr", &["raccourci"], "n\n", 30);
    assert_eq!(refus.code, Some(0), "{}", refus.erreurs);
    assert!(
        !sans_couleurs(&refus.texte).contains("Raccourci posé"),
        "{}",
        refus.texte
    );
    // Une même maison pour les deux lancements : le dossier personnel jetable est refait à chaque fois, donc chacun
    // se vérifie seul.
    let pose = vanguard("fr", &["raccourci", "on"], "", 30);
    assert_eq!(pose.code, Some(0), "{}", pose.erreurs);
    assert!(sans_couleurs(&pose.texte).contains("Raccourci posé"), "{}", pose.texte);
    let retire = vanguard("fr", &["raccourci", "off"], "", 30);
    assert_eq!(retire.code, Some(0), "{}", retire.erreurs);
}

/// Retirer Vanguard, dans une maison jetable où il a posé une surveillance, un raccourci et sa copie : la liste
/// montre tout sans rien retirer ; une ligne vide ne retire rien ; les numéros cochés puis « o » retirent ce qui est
/// coché, et le dossier de données reste. Sans bus de session, systemctl --user échoue : c'est dit dans « Échoué »,
/// jamais compté comme fait. Tout tient dans 76 colonnes, en français et en anglais (alias « uninstall »).
#[test]
fn desinstaller_montre_puis_retire_dans_une_maison_jetable() {
    if !cfg!(target_os = "linux") {
        return essais::saute("Linux seulement");
    }
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let lancer = |langue: &str, args: &[&str], entree: &str| {
        let s = vanguard_dans(programme, &maison, langue, args, entree, 60);
        assert_eq!(s.code, Some(0), "{}\n{}", s.texte, s.erreurs);
        let t = sans_couleurs(&s.texte);
        // Un chemin plus long que la ligne (ceux de la maison jetable et du programme d'essai le sont) a sa ligne à
        // lui, entier : seul un texte qu'on aurait pu couper compte.
        let longues: Vec<&str> = t
            .lines()
            .filter(|l| l.chars().count() > 76 && l.trim().contains(' '))
            .collect();
        assert_eq!(longues, Vec::<&str>::new(), "lignes trop longues : {t}");
        t
    };
    lancer("fr", &["raccourci", "on"], "");
    let donnees = maison.join("donnees/vanguard");
    let copie = donnees.join("bin/vanguard");
    std::fs::create_dir_all(copie.parent().unwrap()).unwrap();
    std::fs::write(&copie, "copie").unwrap();
    std::fs::write(donnees.join("appareils.json"), "{}").unwrap();
    let unites = maison.join(".config/systemd/user");
    std::fs::create_dir_all(&unites).unwrap();
    std::fs::write(
        unites.join("vanguard-surveillance.service"),
        format!("[Service]\nExecStart=\"{}\" surveiller\n", copie.display()),
    )
    .unwrap();
    std::fs::write(
        unites.join("vanguard-surveillance.timer"),
        "[Timer]\nOnUnitActiveSec=1h\n",
    )
    .unwrap();
    std::fs::write(unites.join("autre.timer"), "[Timer]\n").unwrap();
    let raccourci = maison.join("donnees/applications/Vanguard.desktop");
    let icone = maison.join("donnees/icons/hicolor/128x128/apps/vanguard.png");
    assert!(raccourci.is_file() && icone.is_file());
    let intact = || {
        raccourci.is_file()
            && icone.is_file()
            && copie.is_file()
            && unites.join("vanguard-surveillance.timer").is_file()
            && donnees.join("appareils.json").is_file()
    };

    let liste = lancer("fr", &["desinstaller", "--liste"], "");
    for attendu in [
        "Surveillance horaire",
        "Raccourci : menu des applications",
        "Copie du programme (bin/)",
        "Dossier de données",
        "Rien n'a été retiré",
    ] {
        assert!(liste.contains(attendu), "{attendu} absent : {liste}");
    }
    assert!(!liste.contains("autre.timer"), "{liste}");
    assert!(intact(), "--liste a retiré quelque chose");

    let vide = lancer("fr", &["desinstaller"], "\n");
    assert!(vide.contains("Rien n'a été retiré"), "{vide}");
    assert!(intact(), "une ligne vide a retiré quelque chose");
    // Les numéros des cases, tels que la liste à cocher les montre.
    let numero = |texte: &str| {
        vide.lines()
            .find(|l| l.contains(&format!("[ ] {texte}")))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or_else(|| panic!("{texte} absent : {vide}"))
            .to_string()
    };
    let choix = format!(
        "{} {} {}\no\n",
        numero("Surveillance horaire"),
        numero("Raccourci : menu"),
        numero("Copie du programme")
    );
    let fait = lancer("fr", &["desinstaller"], &choix);
    assert!(!raccourci.exists() && !icone.exists(), "{fait}");
    assert!(!copie.exists(), "{fait}");
    assert!(!unites.join("vanguard-surveillance.timer").exists(), "{fait}");
    assert!(unites.join("autre.timer").is_file(), "{fait}");
    assert!(
        donnees.join("appareils.json").is_file(),
        "le dossier de données est parti : {fait}"
    );
    // systemctl --user sans bus : la surveillance est dite « Échoué », jamais comptée comme retirée.
    if fait.contains("── Échoué") {
        let echoue = fait.split("── Échoué").nth(1).unwrap();
        assert!(echoue.contains("Surveillance horaire"), "{fait}");
        assert!(fait.contains("non retiré(s)") && !fait.contains("Fait :"), "{fait}");
        let retire = fait.split("── Retiré").nth(1).unwrap_or_default();
        let retire = retire.split("── ").next().unwrap_or_default();
        assert!(!retire.contains("Surveillance horaire"), "{fait}");
    } else {
        assert!(fait.contains("Fait :"), "{fait}");
    }

    // En anglais, par son alias : la liste, sans rien retirer.
    let anglais = lancer("en", &["uninstall", "--list"], "");
    assert!(anglais.contains("Remove Vanguard from this computer"), "{anglais}");
    assert!(
        anglais.contains("Data folder") && anglais.contains("Nothing was removed"),
        "{anglais}"
    );
    let _ = std::fs::remove_dir_all(&maison);
}

/// Les outils qui écrivent sur un disque s'ouvrent et rendent la main quand on revient sans rien choisir (Entrée) ;
/// la clé VANGUARD, et chacune de ses partitions, n'est jamais proposée.
#[test]
fn outils_de_disque_quittes_sans_rien_ecrire() {
    if !cfg!(target_os = "linux") {
        return essais::saute("Linux seulement");
    }
    let cle = vanguard("fr", &["verifier-cle"], "\n", 30);
    assert_eq!(cle.code, Some(0), "{}", cle.erreurs);
    let t = sans_couleurs(&cle.texte);
    assert!(t.contains("VÉRIFIER MA CLÉ"), "{t}");
    for partition in ["VANGUARD ", "VANGUARDLOG", "VTOYEFI", "WIN11"] {
        assert!(!t.contains(&format!("  {partition}")), "{partition} proposée : {t}");
    }
    assert!(!t.contains("Commencer ?"), "{t}");
    let sauvegarde = vanguard("fr", &["sauvegarde-auto"], "\n\n", 60);
    assert_eq!(sauvegarde.code, Some(0), "{}", sauvegarde.erreurs);
    let t = sans_couleurs(&sauvegarde.texte);
    assert!(t.contains("SAUVEGARDE AUTOMATIQUE"), "{t}");
}

/// Lancé depuis une clé (le programme copié dans <clé>/Linux, témoin vide : jamais la remontée en lecture seule), Vanguard
/// remplace sur accord la copie plus ancienne de cet ordinateur par lui-même ; lancé depuis cette copie, il se tourne
/// vers GitHub. Dans le dossier temporaire de cargo, pas dans /tmp : deux programmes de debug y pèsent 250 Mo.
/// Aucune requête vers GitHub pendant les tests : la mise à jour depuis GitHub, proposée en fin d'écran, s'arrête là.
#[cfg(target_os = "linux")]
const HORS_LIGNE: &[(&str, &str)] = &[("VANGUARD_HORS_LIGNE", "1")];

#[cfg(target_os = "linux")]
#[test]
fn mise_a_jour_depuis_la_cle() {
    let racine = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mise-a-jour-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&racine);
    let (cle, maison) = (racine.join("cle"), racine.join("maison"));
    std::fs::create_dir_all(cle.join("Linux")).unwrap();
    std::fs::write(cle.join("vanguard.cle"), "").unwrap();
    let sur_la_cle = cle.join("Linux").join("vanguard");
    std::fs::copy(env!("CARGO_BIN_EXE_vanguard"), &sur_la_cle).unwrap();
    // Le dossier de XDG_RUNTIME_DIR : le programme s'y recopie avant de tourner (protection::cle), pas dans /tmp.
    std::fs::create_dir_all(maison.join("run")).unwrap();
    let copie = maison.join("donnees").join("vanguard").join("bin").join("vanguard");
    std::fs::create_dir_all(copie.parent().unwrap()).unwrap();
    std::fs::write(&copie, "vieille copie, sans version gravée").unwrap();

    // Refusée (Entrée) : rien ne change.
    let refus = vanguard_dans_env(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "\n", 60, HORS_LIGNE);
    assert_eq!(refus.code, Some(0), "{}", refus.erreurs);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("d'avant la 0.78") && t.contains("La remplacer"), "{t}");
    assert_eq!(
        std::fs::read(&copie).unwrap(),
        b"vieille copie, sans version grav\xc3\xa9e"
    );
    // Acceptée : la copie devient le programme de la clé, octet pour octet.
    let accord = vanguard_dans_env(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "o\n", 60, HORS_LIGNE);
    assert!(
        sans_couleurs(&accord.texte).contains("Copie de cet ordinateur mise à jour"),
        "{}",
        accord.texte
    );
    // Comparés sans assert_eq! : en cas d'échec, il imprimerait deux programmes de 113 Mo.
    let identique = std::fs::read(&copie).unwrap() == std::fs::read(&sur_la_cle).unwrap();
    assert!(identique, "la copie n'est pas le programme de la clé");
    // Ensuite : à jour depuis la clé ; depuis la copie, renvoi vers la clé (jamais une clé seulement branchée).
    let ensuite = vanguard_dans_env(&sur_la_cle, &maison, "fr", &["se-mettre-a-jour"], "", 60, HORS_LIGNE);
    assert!(
        sans_couleurs(&ensuite.texte).contains("est à jour"),
        "{}",
        ensuite.texte
    );
    let depuis_la_copie = vanguard_dans_env(&copie, &maison, "en", &["se-mettre-a-jour"], "", 60, HORS_LIGNE);
    assert!(
        sans_couleurs(&depuis_la_copie.texte).contains("the update comes from"),
        "{}",
        depuis_la_copie.texte
    );
    let _ = std::fs::remove_dir_all(&racine);
}

/// Lancé depuis une clé (témoin `vanguard.cle`, programme dans Linux/), même chez son propriétaire, Vanguard tourne
/// depuis une copie hors de la clé : clé retirée ou port USB coupé, rien de ce qu'il relit n'y est plus. Le processus
/// qui tourne (/proc/<pid>/exe) n'est plus le fichier de la clé, sa copie est déjà effacée, et son dossier aussi.
#[cfg(target_os = "linux")]
#[test]
fn lance_depuis_la_cle_tourne_depuis_une_copie() {
    let racine = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cle-independante-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&racine);
    let (cle, maison) = (racine.join("cle"), racine.join("maison"));
    std::fs::create_dir_all(cle.join("Linux")).unwrap();
    std::fs::create_dir_all(maison.join("run")).unwrap();
    std::fs::write(cle.join("vanguard.cle"), "").unwrap();
    let sur_la_cle = cle.join("Linux").join("vanguard");
    std::fs::copy(env!("CARGO_BIN_EXE_vanguard"), &sur_la_cle).unwrap();
    let mut commande = Command::new(&sur_la_cle);
    commande
        .env("VANGUARD_LANG", "fr")
        .env("VANGUARD_HORS_LIGNE", "1")
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", &maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env_remove("VANGUARD_ORIGINE")
        // Le menu attend sa ligne : l'entrée reste ouverte le temps de regarder le processus.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut essais = 0;
    let mut enfant = loop {
        match commande.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && essais < 20 => {
                essais += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.expect("vanguard ne démarre pas"),
        }
    };
    let texte = lire_en_fond(enfant.stdout.take().unwrap());
    let erreurs = lire_en_fond(enfant.stderr.take().unwrap());
    let lien = PathBuf::from(format!("/proc/{}/exe", enfant.id()));
    let fin = Instant::now() + Duration::from_secs(60);
    let image = loop {
        let image = std::fs::read_link(&lien).unwrap_or_default();
        // La copie s'efface au démarrage : Linux la montre alors « (deleted) ».
        if image.to_string_lossy().ends_with(" (deleted)") || Instant::now() > fin {
            break image;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    {
        let mut entree = enfant.stdin.take().unwrap();
        let _ = entree.write_all(b"q\n");
    }
    let fin = Instant::now() + Duration::from_secs(60);
    while enfant.try_wait().unwrap().is_none() && Instant::now() < fin {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = enfant.kill();
    let _ = enfant.wait();
    let (texte, erreurs) = (texte.join().unwrap_or_default(), erreurs.join().unwrap_or_default());
    let image = image.to_string_lossy().into_owned();
    let copie = PathBuf::from(image.trim_end_matches(" (deleted)"));
    assert!(
        copie.starts_with(maison.join("run")) && copie.ends_with("vanguard"),
        "image {image}\n{texte}\n{erreurs}"
    );
    assert!(!copie.starts_with(&cle), "{image}");
    assert!(!copie.exists(), "copie laissée : {image}");
    assert!(
        !copie.parent().unwrap().exists(),
        "dossier de la copie laissé : {image}"
    );
    assert!(!texte.contains("tourne depuis la clé"), "{texte}");
    let _ = std::fs::remove_dir_all(&racine);
}

/// BASSE (campagne d'attaque, DONNEES-3) : une copie temporaire lancée avec VANGUARD_ORIGINE vers un autre fichier
/// dit l'écart et continue. L'alerte notée au journal se demandait où est la clé, donc rappelait la décision de
/// l'origine pendant sa propre initialisation : Vanguard restait figé (ou paniquait) au lieu de continuer.
#[cfg(target_os = "linux")]
#[test]
fn origine_ecartee_dans_une_copie_ne_fige_pas() {
    let racine = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("origine-ecartee-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&racine);
    let maison = racine.join("maison");
    // Une copie à sa place (`<XDG_RUNTIME_DIR>/vanguard-<…>/vanguard`), d'un autre processus que le sien : elle ne
    // s'efface pas, et l'origine désignée n'a pas ses octets.
    let dossier = maison.join("run").join("vanguard-1-1");
    std::fs::create_dir_all(&dossier).unwrap();
    let copie = dossier.join("vanguard");
    std::fs::copy(env!("CARGO_BIN_EXE_vanguard"), &copie).unwrap();
    let autre = racine.join("autre");
    std::fs::write(&autre, b"programme d'un autre").unwrap();
    let mut commande = Command::new(&copie);
    commande
        .arg("--help")
        .env("VANGUARD_LANG", "fr")
        .env("VANGUARD_HORS_LIGNE", "1")
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", &maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("VANGUARD_ORIGINE", &autre)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut essais = 0;
    let mut enfant = loop {
        match commande.spawn() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy && essais < 20 => {
                essais += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            r => break r.expect("vanguard ne démarre pas"),
        }
    };
    let texte = lire_en_fond(enfant.stdout.take().unwrap());
    let erreurs = lire_en_fond(enfant.stderr.take().unwrap());
    let fin = Instant::now() + Duration::from_secs(30);
    let statut = loop {
        if let Some(s) = enfant.try_wait().unwrap() {
            break Some(s);
        }
        if Instant::now() > fin {
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let _ = enfant.kill();
    let _ = enfant.wait();
    let (texte, erreurs) = (texte.join().unwrap_or_default(), erreurs.join().unwrap_or_default());
    assert!(statut.is_some(), "figé après l'alerte\n{texte}\n{erreurs}");
    assert!(statut.unwrap().success(), "{texte}\n{erreurs}");
    assert!(erreurs.contains("VANGUARD_ORIGINE"), "alerte absente : {erreurs}");
    let _ = std::fs::remove_dir_all(&racine);
}

/// BASSE (relecture adverse, R2W-N2) : une copie temporaire déjà effacée (elle s'efface au démarrage) et relancée
/// par son image (l'autotest relance `/proc/self/exe`) se sait encore une copie : le noyau ajoute « (deleted) » à son
/// chemin, qui ne ressemblait plus à une copie, et VANGUARD_ORIGINE (sa clé) était oubliée sans rien dire. Ici
/// l'origine désignée n'a pas ses octets : l'écart doit être dit, preuve que la variable a bien été examinée.
#[cfg(target_os = "linux")]
#[test]
fn copie_effacee_relancee_par_son_image_reste_une_copie() {
    use std::os::fd::AsRawFd;
    let racine = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("copie-effacee-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&racine);
    let maison = racine.join("maison");
    let dossier = maison.join("run").join("vanguard-1-1");
    std::fs::create_dir_all(&dossier).unwrap();
    let copie = dossier.join("vanguard");
    std::fs::copy(env!("CARGO_BIN_EXE_vanguard"), &copie).unwrap();
    let image = std::fs::File::open(&copie).unwrap();
    std::fs::remove_file(&copie).unwrap();
    std::fs::remove_dir(&dossier).unwrap();
    let autre = racine.join("autre");
    std::fs::write(&autre, b"programme d'un autre").unwrap();
    let par_l_image = format!("/proc/{}/fd/{}", std::process::id(), image.as_raw_fd());
    let sortie = Command::new(&par_l_image)
        .arg("--help")
        .env("VANGUARD_LANG", "fr")
        .env("VANGUARD_HORS_LIGNE", "1")
        .env("USER", "essai")
        .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
        .env("XDG_RUNTIME_DIR", maison.join("run"))
        .env("HOME", &maison)
        .env("XDG_DATA_HOME", maison.join("donnees"))
        .env("XDG_CONFIG_HOME", maison.join("config"))
        .env("XDG_CACHE_HOME", maison.join("cache"))
        .env("VANGUARD_ORIGINE", &autre)
        .stdin(Stdio::null())
        .output()
        .expect("vanguard ne démarre pas par son image");
    drop(image);
    let erreurs = String::from_utf8_lossy(&sortie.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&racine);
    assert!(sortie.status.success(), "{erreurs}");
    assert!(
        erreurs.contains("VANGUARD_ORIGINE"),
        "copie effacée plus reconnue : {erreurs}"
    );
}

/// Les traces collectées dans un dossier jetable : un seul dossier daté, réservé au compte, avec LISEZMOI (en
/// français puis en anglais), MANIFESTE et les processus ; chaque empreinte du manifeste est juste et chaque fichier y
/// est. Sous Wine, sans PowerShell, une partie manque et c'est dit ; LISEZMOI et MANIFESTE, eux, sont là.
#[test]
fn traces_collectees_et_manifeste_juste() {
    use sha2::Digest;
    let maison = maison_jetable();
    let dossier = maison.join("enquete");
    let s = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["depanner", "traces", dossier.to_str().unwrap()],
        "",
        300,
    );
    assert_eq!(s.code, Some(0), "{}\n{}", s.texte, s.erreurs);
    assert!(!s.erreurs.contains("panicked"), "{}", s.erreurs);
    let texte = sans_couleurs(&s.texte);
    assert!(
        texte.contains("Collecter les traces") && texte.contains("Traces : "),
        "{texte}"
    );
    let traces: Vec<PathBuf> = std::fs::read_dir(&dossier)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    assert_eq!(traces.len(), 1, "{traces:?}");
    let d = &traces[0];
    let nom = d.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        nom.starts_with("traces-") && nom.len() == "traces-20261020-140322".len(),
        "{nom}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(d).unwrap().permissions().mode() & 0o777, 0o700);
    }
    let lisezmoi = std::fs::read_to_string(d.join("LISEZMOI.txt")).unwrap();
    assert!(
        lisezmoi.contains("TRACES COLLECTÉES PAR VANGUARD") && lisezmoi.contains("TRACES COLLECTED BY VANGUARD"),
        "{lisezmoi}"
    );
    assert!(lisezmoi.contains("données personnelles") && lisezmoi.contains(env!("CARGO_PKG_VERSION")));
    // La chronologie : toujours écrite (vide au besoin), une ligne de quatre champs par événement, dite au LISEZMOI.
    let chronologie = std::fs::read_to_string(d.join("CHRONOLOGIE.txt")).unwrap();
    assert!(
        chronologie.starts_with("# Vanguard ") && chronologie.contains("\nDATE\tSOURCE\tQUOI/WHAT\tMITRE ATT&CK\n"),
        "{chronologie}"
    );
    assert!(
        chronologie
            .lines()
            .skip_while(|l| !l.starts_with("DATE\t"))
            .skip(1)
            .all(|l| l.split('\t').count() == 4 || l.starts_with("(aucun")),
        "{chronologie}"
    );
    assert!(lisezmoi.contains("CHRONOLOGIE.txt"));
    if !sous_wine() {
        let processus = std::fs::read_to_string(d.join("01-processus.txt")).unwrap();
        assert!(processus.lines().count() > 3, "{processus}");
    }
    // Le manifeste : chaque fichier du dossier, sauf lui-même, avec son empreinte juste (format de sha256sum).
    let manifeste = std::fs::read_to_string(d.join("MANIFESTE.txt")).unwrap();
    let mut listes: Vec<String> = Vec::new();
    for ligne in manifeste.lines() {
        let (empreinte, nom) = ligne.split_once("  ").expect("ligne du manifeste mal formée");
        let calculee =
            sha2::Sha256::digest(std::fs::read(d.join(nom)).unwrap())
                .iter()
                .fold(String::new(), |mut s, o| {
                    use std::fmt::Write;
                    let _ = write!(s, "{o:02x}");
                    s
                });
        assert_eq!(empreinte, calculee, "{nom}");
        listes.push(nom.to_string());
    }
    let mut presents: Vec<String> = std::fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n != "MANIFESTE.txt")
        .collect();
    presents.sort();
    assert_eq!(listes, presents);
    assert!(listes.contains(&"LISEZMOI.txt".to_string()));
    let _ = std::fs::remove_dir_all(&maison);
}

/// Paramètres › Partage avec l'auteur, par un tube (sans terminal) : une ligne vide, la fin de la lecture, une
/// réponse inconnue, ou un chiffre ou une lettre (d'un script qui répondait à autre chose) ne donnent aucun accord ;
/// rien n'est écrit.
#[test]
fn partage_sans_terminal_rien_sans_reponse() {
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    for (entree, refus) in [
        ("13.1\n15\n\n", None),
        ("13.1\n15\n", None),
        ("13.1\n15\npeut-être\n", Some("réponse inconnue ; rien ne change")),
        ("13.1\n15\n1\n", Some("sans terminal, répondez par un mot")),
        ("13.1\n15\ny\n", Some("sans terminal, répondez par un mot")),
    ] {
        let maison = maison_jetable();
        let s = vanguard_dans(programme, &maison, "fr", &[], entree, 60);
        let texte = sans_couleurs(&s.texte);
        assert_eq!(s.code, Some(0), "{entree:?} : {texte}{}", s.erreurs);
        assert!(texte.contains("Partager avec l'auteur ?"), "{entree:?} : {texte}");
        assert!(texte.contains("3  Voir ce qui serait envoyé"), "{texte}");
        assert!(
            texte.contains("Réponse : oui, non ou voir (Entrée : plus tard)"),
            "{texte}"
        );
        assert_eq!(
            texte.contains("rien ne change."),
            refus.is_some(),
            "{entree:?} : {texte}"
        );
        assert!(refus.is_none_or(|r| texte.contains(r)), "{entree:?} : {texte}");
        let parametres = std::fs::read_to_string(dossier_vanguard(&maison).join("parametres.json")).unwrap_or_default();
        assert!(!parametres.contains("partage"), "{entree:?} : {parametres}");
        let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage"], "", 60);
        assert!(s.texte.contains("partage : pas répondu"), "{}", s.texte);
    }
}

/// « Non » efface le relevé, la file de l'envoi et l'identifiant (rien d'autre du dossier) ; « oui » note son jour ;
/// un fichier de paramètres réécrit hors de Vanguard ne donne pas l'accord.
#[test]
fn partage_non_efface_oui_date_falsifie_ignore() {
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let maison = maison_jetable();
    let dossier = dossier_vanguard(&maison);
    std::fs::create_dir_all(dossier.join("envoi/file")).unwrap();
    std::fs::create_dir_all(dossier.join("amelioration/jours")).unwrap();
    std::fs::write(dossier.join("envoi/etat.json"), "{}").unwrap();
    std::fs::write(dossier.join("envoi/file/2026-11-01.json"), "{}").unwrap();
    std::fs::write(dossier.join("amelioration/jours/2026-11-01.json"), "{}").unwrap();
    std::fs::write(dossier.join("a-moi.txt"), "à alice").unwrap();
    // CI vidé pour le programme : sur les machines de GitHub (CI=true), Vanguard n'efface pas, voulu ; l'essai veut
    // l'effacement lui-même, sur chaque système.
    let s = vanguard_dans_env(programme, &maison, "fr", &[], "13.1\n15\nnon\n", 60, &[("CI", "")]);
    assert_eq!(s.code, Some(0), "{}{}", s.texte, s.erreurs);
    assert!(s.texte.contains("Partage avec l'auteur : non"), "{}", s.texte);
    // En root (verifier.sh, sous unshare) ou sous Wine, le dossier n'est pas celui d'une personne : rien n'est
    // effacé, et c'est dit.
    let efface = !(en_root() || sous_wine());
    for parti in ["envoi", "amelioration"] {
        assert_eq!(dossier.join(parti).exists(), !efface, "{parti}/ : {}", s.texte);
    }
    assert_eq!(s.texte.contains("Rien d'effacé ici"), !efface, "{}", s.texte);
    assert_eq!(std::fs::read_to_string(dossier.join("a-moi.txt")).unwrap(), "à alice");
    let parametres = std::fs::read_to_string(dossier.join("parametres.json")).unwrap();
    assert!(parametres.contains("\"partage\": \"non\""), "{parametres}");
    // Noté aussi à part, pour qu'une version d'avant qui réécrit parametres.json ne l'efface pas.
    assert!(dossier.join("partage-non").is_file(), "{}", s.texte);
    // Coupé, rien ne se relève plus, même en lançant d'autres commandes.
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage", "voir"], "", 60);
    assert!(s.texte.contains("Partage coupé"), "{}", s.texte);
    if efface {
        assert!(
            !dossier.join("amelioration").exists(),
            "le relevé a repris malgré « non »"
        );
    }
    // Une valeur inconnue ne change rien.
    let s = vanguard_dans(
        programme,
        &maison,
        "fr",
        &["parametres", "partage", "peut-être"],
        "",
        60,
    );
    assert!(s.texte.contains("Valeur inconnue"), "{}", s.texte);
    assert_eq!(
        std::fs::read_to_string(dossier.join("parametres.json")).unwrap(),
        parametres
    );
    // « Oui » note le jour de l'accord.
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage", "oui"], "", 60);
    assert!(s.texte.contains("Partage avec l'auteur : oui"), "{}", s.texte);
    let parametres = std::fs::read_to_string(dossier.join("parametres.json")).unwrap();
    assert!(
        parametres.contains("\"partage\": \"oui\"") && parametres.contains("partage_le"),
        "{parametres}"
    );
    assert!(!dossier.join("partage-non").exists(), "{}", s.texte);
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage", "voir"], "", 60);
    assert!(
        s.texte
            .contains(if efface { "En attente : 0" } else { "En attente : " }),
        "{}",
        s.texte
    );
    // Le même accord, réécrit hors de Vanguard (le sceau ne correspond plus) : il ne vaut pas.
    std::fs::write(
        dossier.join("parametres.json"),
        "{\"partage\": \"oui\", \"partage_le\": \"2026-01-01\", \"partage_phase\": 1}",
    )
    .unwrap();
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage"], "", 60);
    assert!(s.texte.contains("partage : pas répondu"), "{}", s.texte);
    // Un « non » dont le fichier est effacé hors de Vanguard : sa marque le garde ; sans elle non plus, rien ne part.
    vanguard_dans(programme, &maison, "fr", &["parametres", "partage", "non"], "", 60);
    std::fs::remove_file(dossier.join("parametres.json")).unwrap();
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage"], "", 60);
    assert!(s.texte.contains("partage : non"), "{}", s.texte);
    std::fs::remove_file(dossier.join("partage-non")).unwrap();
    let s = vanguard_dans(programme, &maison, "fr", &["parametres", "partage"], "", 60);
    assert!(
        s.texte.contains("partage : fichier effacé : rien ne part"),
        "{}",
        s.texte
    );
}

/// Le dossier de Vanguard dans un dossier personnel jetable, selon le système (voir `socle::dossier_local`).
fn dossier_vanguard(maison: &Path) -> PathBuf {
    if cfg!(windows) {
        maison.join("local").join("vanguard")
    } else {
        maison.join("donnees").join("vanguard")
    }
}

#[test]
fn tableau_de_bord_sans_surveillance_explique() {
    // Ni surveillance, ni historique, ni appareil : la page le dit et explique comment l'activer, sans navigateur.
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    for (langue, args, attendu) in [
        ("fr", ["tableau-de-bord", "--sans-ouvrir"], "vanguard surveillance on"),
        ("en", ["dashboard", "--no-open"], "vanguard monitor on"),
    ] {
        let s = vanguard_dans(programme, &maison, langue, &args, "", 60);
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        let page = std::fs::read_to_string(dossier_vanguard(&maison).join("tableau.html")).unwrap();
        assert!(page.contains(attendu), "{page}");
        assert!(page.ends_with("</main></div></div></body></html>"));
        // Le menu du terminal y est repris, même sur une page vide.
        assert!(page.contains("<section id=fonctions>"), "{page}");
    }
    let _ = std::fs::remove_dir_all(&maison);
}

/// Le plugin d'exemple ajouté (accord tapé), lancé, puis refusé quand son script change ; un script posé dans le labo,
/// approuvé au premier lancement. Pour de vrai, dans un dossier personnel jetable.
#[cfg(unix)]
#[test]
fn plugin_d_exemple_et_labo() {
    // Dans `unshare -rn` (verifier.sh), le compte devient root : Vanguard y refuse à raison les extensions.
    if std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .ok()
        == Some(0)
    {
        return essais::saute("en root : extensions refusées");
    }
    let maison = maison_jetable();
    let source = maison.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let exemple = Path::new(env!("CARGO_MANIFEST_DIR")).join("extensions/exemples/exemple");
    for f in ["plugin.toml", "exemple.sh", "exemple.ps1"] {
        std::fs::copy(exemple.join(f), source.join(f)).unwrap();
    }
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let env = [("VANGUARD_HORS_LIGNE", "1")];
    let source_texte = source.to_string_lossy().into_owned();
    let s = vanguard_dans_env(
        programme,
        &maison,
        "fr",
        &["plugins", "ajouter", &source_texte],
        "o\n",
        120,
        &env,
    );
    assert_eq!(s.code, Some(0), "{}{}", s.texte, s.erreurs);
    assert!(
        s.texte.contains("Empreinte du dossier") && s.texte.contains("non vérifié par Vanguard"),
        "{}",
        s.texte
    );
    let s = vanguard_dans_env(programme, &maison, "fr", &["plugins", "exemple"], "", 60, &env);
    assert_eq!(s.code, Some(0), "{}{}", s.texte, s.erreurs);
    assert!(
        s.texte.contains("Bonjour depuis le plugin d'exemple (--salut)"),
        "{}",
        s.texte
    );
    assert!(
        s.texte.contains("Une prise connectée inventée") && s.texte.contains("plugin exemple"),
        "{}",
        s.texte
    );
    let plugins = dossier_vanguard(&maison).join("plugins");
    let mut script = std::fs::read_to_string(plugins.join("exemple/exemple.sh")).unwrap();
    script.push_str("echo de plus\n");
    std::fs::write(plugins.join("exemple/exemple.sh"), script).unwrap();
    let s = vanguard_dans_env(programme, &maison, "fr", &["plugins", "exemple"], "", 60, &env);
    assert_eq!(s.code, Some(1));
    assert!(s.texte.contains("a changé depuis son approbation"), "{}", s.texte);

    let s = vanguard_dans_env(programme, &maison, "fr", &["labo", "ouvrir"], "", 30, &env);
    assert!(s.texte.contains("plugins/labo"), "{}", s.texte);
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("extensions/exemples/labo-exemple.sh"),
        plugins.join("labo/labo-exemple.sh"),
    )
    .unwrap();
    let s = vanguard_dans_env(programme, &maison, "fr", &["labo", "labo-exemple.sh"], "o\n", 120, &env);
    assert_eq!(s.code, Some(0), "{}{}", s.texte, s.erreurs);
    assert!(
        s.texte.contains("EXPÉRIMENTAL") && s.texte.contains("labo labo-exemple.sh"),
        "{}",
        s.texte
    );
    let _ = std::fs::remove_dir_all(&maison);
}

/// La protection en temps réel : couper demande l'accord, avec la liste de ce qui s'arrête (refusé : rien d'écrit),
/// pour une durée choisie ; c'est redit en tête du menu principal, et la remettre ne demande rien. Par la ligne de
/// commande en français et en anglais, par le menu Paramètres, et dans l'aide des deux langues.
#[test]
fn protection_en_temps_reel_coupee_puis_remise() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let fichier = dossier_vanguard(&maison).join("temps-reel.json");
    let lancer = |langue: &str, args: &[&str], entree: &str| {
        let s = vanguard_dans(programme, &maison, langue, args, entree, 60);
        assert_eq!(s.code, Some(0), "{args:?} : {}{}", s.texte, s.erreurs);
        sans_couleurs(&s.texte)
    };
    // En administrateur (dans `unshare -rn`, verifier.sh, le compte devient root ; les Windows de la CI sont élevés) :
    // refusé sans question, rien d'écrit, comme les restrictions des extensions.
    if en_root() || windows_eleve() {
        let t = lancer("fr", &["parametres", "temps-reel", "non", "--pendant", "1h"], "o\n");
        assert!(t.contains("tourne en administrateur") && !t.contains("[o/N]"), "{t}");
        assert!(!fichier.exists());
        let _ = std::fs::remove_dir_all(&maison);
        return;
    }
    // Refusé : la liste a été montrée, rien n'est écrit.
    let t = lancer("fr", &["parametres", "temps-reel", "non", "--pendant", "1h"], "n\n");
    assert!(
        t.contains("La surveillance horaire") && t.contains("Defender, le pare-feu et l'UAC"),
        "{t}"
    );
    assert!(t.contains("[o/N]") && t.contains("Rien n'a changé"), "{t}");
    assert!(!fichier.exists());
    // Une durée inconnue, ou « --pendant » avec « oui » : refusés sans question.
    let t = lancer("fr", &["parametres", "temps-reel", "non", "--pendant", "2h"], "");
    assert!(t.contains("Valeur inconnue") && !t.contains("[o/N]"), "{t}");
    let t = lancer("fr", &["parametres", "temps-reel", "oui", "--pendant", "1h"], "");
    assert!(t.contains("--pendant va avec « non »"), "{t}");
    assert!(!fichier.exists());
    // Accepté : coupée pour une heure, dit dans Paramètres et en tête du menu principal.
    let t = lancer("fr", &["parametres", "temps-reel", "non", "--pendant", "1h"], "o\n");
    assert!(t.contains("oui → non (jusqu'à"), "{t}");
    assert!(fichier.is_file());
    let t = lancer("fr", &["parametres"], "");
    assert!(t.contains("temps-reel") && t.contains("non (jusqu'à"), "{t}");
    let t = lancer("fr", &[], "q\n");
    assert!(t.contains("temps réel coupé"), "{t}");
    // Remise : sans question, le fichier retiré, et le menu ne le dit plus.
    let t = lancer("fr", &["parametres", "temps-reel", "oui"], "");
    assert!(t.contains("→ oui") && !t.contains("[o/N]"), "{t}");
    assert!(!fichier.exists());
    assert!(!lancer("fr", &[], "q\n").contains("temps réel coupé"));
    // En anglais, jusqu'à reprise.
    let t = lancer("en", &["settings", "real-time", "no"], "y\n");
    assert!(
        t.contains("until you turn it back on") && t.contains("yes → no (until turned back on)"),
        "{t}"
    );
    assert!(lancer("en", &[], "q\n").contains("real-time off"));
    lancer("en", &["settings", "real-time", "yes"], "");
    assert!(!fichier.exists());
    // Par le menu : « s » (Paramètres), 4 (Protection en temps réel), 3 (4 heures), accord, puis revenir.
    let t = lancer("fr", &[], "s\n4\n3\no\n\n\nq\n");
    assert!(
        t.contains("PROTECTION EN TEMPS RÉEL") || t.contains("Protection en temps réel"),
        "{t}"
    );
    assert!(
        t.contains("non, pendant 4 heures") && t.contains("oui → non (jusqu'à"),
        "{t}"
    );
    assert!(fichier.is_file());
    lancer("fr", &["parametres", "temps-reel", "oui"], "");
    // L'aide, dans les deux langues.
    assert!(lancer("fr", &["parametres", "--help"], "").contains("temps-reel non"));
    assert!(lancer("en", &["settings", "--help"], "").contains("real-time no --for 1h|4h"));
    let _ = std::fs::remove_dir_all(&maison);
}

/// Mode Wi-Fi public, sans rien changer : sans argument, son état (éteint) et rien de lancé ; « off » sans état, rien
/// à éteindre ; un état posé par un autre programme (sans sceau) n'est jamais remis : extinction sûre proposée,
/// refusée, l'état reste.
#[test]
fn wifi_public_sans_rien_changer() {
    let s = vanguard("fr", &["wifi-public", "off"], "", 30);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(sans_couleurs(&s.texte).contains("rien à éteindre"), "{}", s.texte);
    let s = vanguard("en", &["public-wifi"], "\n", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(
        t.contains("Public Wi-Fi mode") && t.contains("Off.") && t.contains("Turn the mode on"),
        "{t}"
    );
    let s = vanguard("fr", &["wifi-public", "demain"], "", 30);
    assert_ne!(s.code, Some(0), "valeur hors de on, off, portail");
    if cfg!(target_os = "linux") {
        let maison = maison_jetable();
        let donnees = maison.join("donnees/vanguard");
        std::fs::create_dir_all(&donnees).unwrap();
        let pose = r#"{"version":1,"etape":"allume","depuis":"2026-10-23 10:00","demarrage":"x",
            "reseau":{"nom":"Café","interface":"wlan0","id":"0b8c2f4e-1a2b-4c3d-9e8f-001122334455"},
            "elements":[{"genre":"nm","uuid":"0b8c2f4e-1a2b-4c3d-9e8f-001122334455","propriete":"connection.mdns","avant":"no"}]}"#;
        std::fs::write(donnees.join("wifi-public.json"), pose).unwrap();
        let s = vanguard_dans(
            Path::new(env!("CARGO_BIN_EXE_vanguard")),
            &maison,
            "fr",
            &["wifi-public", "off"],
            "n\n",
            30,
        );
        let t = sans_couleurs(&s.texte);
        assert!(t.contains("Extinction sûre") && t.contains("Annulé"), "{t}");
        assert!(!t.contains("nmcli"), "aucune valeur notée n'est proposée : {t}");
        assert!(donnees.join("wifi-public.json").exists());
        let _ = std::fs::remove_dir_all(&maison);
    }
}

/// `vanguard signaler --incident <id> --programme msrc --json` sur un journal écrit à la main (sans sa tête, donc
/// « falsifie ») : un JSON aux clés stables, le brouillon dit les observations non vérifiées, rien de personnel n'y
/// reste (chemin d'un autre compte, nom de fichier, ligne de commande), et rien n'est écrit ni noté.
#[test]
fn signaler_en_json_sur_un_journal_d_essai() {
    let maison = maison_jetable();
    // Le dossier de données de chaque système (comme les essais plus haut).
    let donnees = if cfg!(windows) {
        maison.join("local")
    } else {
        maison.join("donnees")
    };
    let segment = donnees
        .join("vanguard/evenements")
        .join(format!("{}.jsonl", chrono::Utc::now().format("%Y-%m")));
    std::fs::create_dir_all(segment.parent().unwrap()).unwrap();
    let journal = concat!(
        r#"{"v":1,"id":"a1","quand":"2026-10-23T10:00:00Z","source":"surveillance","cle":"port|8080","quoi":{"sorte":"alerte","famille":"port","titre":"Port 8080 ouvert par /home/bob/bin/srv","texte":"x`@bob <img src=x>"},"precedent":""}"#,
        "\n",
        r#"{"v":1,"id":"a2","quand":"2026-10-23T10:00:01Z","source":"blocage","cause":"a1","quoi":{"sorte":"preuve","releve":{"date":"x","processus":{"pid":4,"programme":"/home/bob/bin/srv","ligne":"--token=SECRET","compte":"bob"},"fichier":{"chemin":"/home/bob/Documents/CV-Zoé-Martin.pdf","sha256":"abab"}}},"precedent":""}"#,
        "\n"
    );
    std::fs::write(&segment, journal).unwrap();
    let s = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["signaler", "--incident", "a1", "--programme", "msrc", "--json"],
        "",
        60,
    );
    assert_eq!(s.code, Some(0), "{}\n{}", s.texte, s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).expect("signaler --json : JSON illisible");
    assert_eq!(v["etat_journal"], "falsifie");
    assert_eq!(v["tri"]["sorte"], "a-ecrire");
    assert_eq!(v["programme"], "msrc");
    assert_eq!(v["langue"], "en");
    assert_eq!(v["ecrit"], false);
    assert_eq!(v["incomplet"], true);
    assert_eq!(
        v["manque"],
        serde_json::json!(["etapes", "observe", "preuve-de-concept"])
    );
    let brouillon = v["brouillon"].as_str().expect("brouillon absent");
    assert!(
        brouillon.starts_with("# INCOMPLETE") && brouillon.contains("not verified"),
        "{brouillon}"
    );
    for absent in ["SECRET", "/home/bob", "Zoé-Martin", "account: bob"] {
        assert!(!brouillon.contains(absent), "{absent} :\n{brouillon}");
    }
    assert!(!donnees.join("vanguard/signalements").exists());
    assert_eq!(
        std::fs::read_to_string(&segment).unwrap(),
        journal,
        "rien n'est noté au journal"
    );
    // Un identifiant inconnu est refusé, et c'est dit.
    let s = vanguard_dans(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["signaler", "--incident", "inconnu", "--json"],
        "",
        60,
    );
    assert!(s.texte.contains("aucun événement « inconnu »"), "{}", s.texte);
    let _ = std::fs::remove_dir_all(&maison);
}

/// Le menu, l'interface principale, parcouru pour de vrai dans un pseudo-terminal (comme une personne au clavier,
/// pas par un tube) : flèches, Entrée, Échap, puis « q » et Entrée. Les autres tests parlent au programme par un tube, où les
/// menus lisent des lignes ; ici, le mode brut du terminal, les touches une à une et le retour au menu principal se
/// vérifient. Linux seulement : un pseudo-terminal s'ouvre là sans outil (openpty), et c'est le système de l'auteur.
#[cfg(target_os = "linux")]
mod menus_dans_un_terminal {
    use super::{maison_jetable, sans_couleurs};
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    const BAS: &str = "\x1b[B";
    const ENTREE: &str = "\r";
    const ECHAP: &str = "\x1b";

    /// Un pseudo-terminal de `colonnes` × `rangees` : (côté programme de test, côté Vanguard).
    fn ouvrir(colonnes: u16, rangees: u16) -> (OwnedFd, OwnedFd) {
        let (mut maitre, mut esclave) = (-1, -1);
        let taille = libc::winsize {
            ws_row: rangees,
            ws_col: colonnes,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty écrit deux descripteurs dans les entiers donnés ; le nom (NULL) et les réglages (NULL)
        // ne sont pas demandés, la taille est lue dans une structure valide le temps de l'appel.
        let r = unsafe {
            libc::openpty(
                &raw mut maitre,
                &raw mut esclave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &raw const taille,
            )
        };
        assert_eq!(r, 0, "openpty : {}", std::io::Error::last_os_error());
        // SAFETY: les deux descripteurs viennent d'être ouverts par openpty et ne sont à personne d'autre.
        unsafe { (OwnedFd::from_raw_fd(maitre), OwnedFd::from_raw_fd(esclave)) }
    }

    /// Ce que Vanguard a écrit dans le terminal, lu en fond, et la suite de l'échange.
    struct Terminal {
        ecrit: Arc<Mutex<Vec<u8>>>,
        clavier: std::fs::File,
        vu: usize,
    }

    impl Terminal {
        /// Attend que l'écran, depuis la dernière attente, montre `texte` (couleurs retirées) ; rend ce qui a paru.
        fn attendre(&mut self, texte: &str, secondes: u64) -> String {
            let fin = Instant::now() + Duration::from_secs(secondes);
            loop {
                let tout = self.ecrit.lock().unwrap().clone();
                // Une demande de position du curseur reçoit une réponse, comme d'un vrai terminal : sans elle, une
                // bibliothèque qui la pose attendrait.
                let nouveau = String::from_utf8_lossy(&tout[self.vu.min(tout.len())..]).into_owned();
                if nouveau.contains("\x1b[6n") {
                    let _ = self.clavier.write_all(b"\x1b[1;1R");
                }
                let propre = sans_couleurs(&nouveau);
                if propre.contains(texte) {
                    self.vu = tout.len();
                    return propre;
                }
                assert!(
                    Instant::now() < fin,
                    "« {texte} » n'a pas paru en {secondes} s ; écran depuis la dernière touche :\n{propre}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        fn taper(&mut self, touches: &str) {
            self.clavier.write_all(touches.as_bytes()).unwrap();
            // Une touche à la fois, comme au clavier : Échap seul se distingue ainsi du début d'une flèche.
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    /// Vanguard lancé dans un pseudo-terminal de 80 × 40, avec `args` et le dossier personnel `maison` : le processus,
    /// le terminal, et le fil qui lit l'écran.
    fn lancer(maison: &std::path::Path, args: &[&str]) -> (std::process::Child, Terminal, std::thread::JoinHandle<()>) {
        lancer_en(maison, args, "fr")
    }

    /// `lancer`, dans la langue donnée (« fr », « en »).
    fn lancer_en(
        maison: &std::path::Path,
        args: &[&str],
        langue: &str,
    ) -> (std::process::Child, Terminal, std::thread::JoinHandle<()>) {
        let (maitre, esclave) = ouvrir(80, 40);
        let mut commande = Command::new(env!("CARGO_BIN_EXE_vanguard"));
        commande
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TERM", "xterm-256color")
            .env("VANGUARD_LANG", langue)
            .env("USER", "essai")
            .env("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent")
            .env("XDG_RUNTIME_DIR", maison.join("run"))
            .env("HOME", maison)
            .env("XDG_DATA_HOME", maison.join("donnees"))
            .env("XDG_CONFIG_HOME", maison.join("config"))
            .env("XDG_CACHE_HOME", maison.join("cache"))
            // Rien ne doit partir sur Internet pendant l'essai (l'annonce d'une version plus récente, par exemple).
            .env("VANGUARD_HORS_LIGNE", "1")
            .stdin(Stdio::from(esclave.try_clone().unwrap()))
            .stdout(Stdio::from(esclave.try_clone().unwrap()))
            .stderr(Stdio::from(esclave));
        // SAFETY: entre fork et exec, seuls setsid et ioctl sont appelés, tous deux sûrs à cet endroit (ni
        // allocation ni verrou) : Vanguard devient chef d'une session dont le pseudo-terminal est le terminal.
        unsafe {
            commande.pre_exec(|| {
                libc::setsid();
                if libc::ioctl(0, libc::TIOCSCTTY, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let enfant = commande.spawn().expect("vanguard ne démarre pas");
        // L'esclave n'est plus ouvert ici (il a été donné à Command) : à la sortie de Vanguard, la lecture finit.
        drop(commande);
        let ecrit = Arc::new(Mutex::new(Vec::new()));
        let mut lecture = std::fs::File::from(maitre.try_clone().unwrap());
        let copie = Arc::clone(&ecrit);
        let lecteur = std::thread::spawn(move || {
            let mut tampon = [0u8; 4096];
            while let Ok(n) = lecture.read(&mut tampon) {
                if n == 0 {
                    break;
                }
                copie.lock().unwrap().extend_from_slice(&tampon[..n]);
            }
        });
        let t = Terminal {
            ecrit,
            clavier: std::fs::File::from(maitre),
            vu: 0,
        };
        (enfant, t, lecteur)
    }

    #[test]
    fn petite_liste_en_ligne_sans_rien_effacer() {
        // 8.2 Bloquer les sites dangereux : l'état, puis une petite liste dessinée dessous (B, R, rien). La lettre
        // pose la marque sans rien lancer ; Échap revient sans rien changer.
        let maison = maison_jetable();
        let (mut enfant, mut t, lecteur) = lancer(&maison, &[]);
        t.attendre("q quitter", 60);
        t.taper("8.2");
        t.taper(ENTREE);
        let ecran = t.attendre("Retirer le blocage", 60);
        assert!(
            ecran.contains("dangereux"),
            "l'état reste au-dessus de la liste : {ecran}"
        );
        assert!(
            ecran.contains("Bloquer, ou rafraîchir la liste") && ecran.contains("Rien"),
            "{ecran}"
        );
        // La lettre redessine la liste, sans rien lancer (Retirer demanderait les droits d'administrateur).
        t.taper("r");
        t.attendre("Retirer le blocage", 30);
        t.taper(ECHAP);
        t.attendre("Entrée pour revenir au menu", 30);
        t.taper(ENTREE);
        t.attendre("q quitter", 30);
        t.taper("q");
        t.taper(ENTREE);
        let fin = Instant::now() + Duration::from_secs(30);
        while enfant.try_wait().unwrap().is_none() {
            assert!(Instant::now() < fin, "« q » n'a pas fermé Vanguard");
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(t);
        let _ = lecteur.join();
        let _ = std::fs::remove_dir_all(&maison);
    }

    #[test]
    fn fleches_entree_echap_puis_quitter() {
        let maison = maison_jetable();
        let (mut enfant, mut t, lecteur) = lancer(&maison, &[]);
        let menu = t.attendre("q quitter", 60);
        assert!(
            menu.contains("Bilan de sécurité complet") && menu.contains("Cet ordinateur"),
            "{menu}"
        );
        // Trois fois en bas depuis « Bilan de sécurité complet » : le premier groupe, « Cet ordinateur », ouvert par
        // Entrée.
        for _ in 0..3 {
            t.taper(BAS);
        }
        t.taper(ENTREE);
        let sous_menu = t.attendre("Revenir au menu principal", 30);
        assert!(sous_menu.contains("VANGUARD › Cet ordinateur"), "{sous_menu}");
        assert!(sous_menu.contains("Audit de sécurité"), "{sous_menu}");
        // Échap revient au menu principal, sans rien lancer.
        t.taper(ECHAP);
        let retour = t.attendre("q quitter", 30);
        assert!(retour.contains("Bilan de sécurité complet"), "{retour}");
        // « q », une seule lettre, n'est pas une recherche : Entrée le valide comme raccourci, et Vanguard s'arrête.
        t.taper("q");
        t.taper(ENTREE);
        let fin = Instant::now() + Duration::from_secs(30);
        let statut = loop {
            if let Some(s) = enfant.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > fin {
                let _ = enfant.kill();
                panic!("« q » n'a pas fermé Vanguard en 30 s :\n{}", t.attendre("", 0));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(statut.success(), "{statut:?}");
        // Le côté programme de test fermé, le lecteur en fond s'arrête de lui-même.
        drop(t);
        let _ = lecteur.join();
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Blocage › Suites de gestes au clavier, en français puis en anglais : « Outil d'attaque », un geste ajouté
    /// (Suspendre, le premier qui manque) et enregistré scellé dans blocage.json, puis la suite par défaut remise
    /// (rien n'y reste écrit) ; Entrée revient de chaque écran, jusqu'à la sortie.
    #[test]
    fn suites_de_gestes_au_clavier() {
        for (langue, entree, legende, defaut, ajout, enregistree, choisie) in [
            (
                "fr",
                "Suites de gestes",
                "* : suite choisie ici",
                "Suite par défaut.",
                "« reprendre » le lève",
                "suite enregistrée",
                "Remettre la suite par défaut",
            ),
            (
                "en",
                "Action suites",
                "* : suite chosen here",
                "Default suite.",
                "“resume” lifts it",
                "suite saved",
                "Restore the default suite",
            ),
        ] {
            let maison = maison_jetable();
            let fichier = maison.join("donnees/vanguard/blocage.json");
            let lu = || std::fs::read_to_string(&fichier).unwrap_or_default();
            let (mut enfant, mut t, lecteur) = lancer_en(&maison, &["blocage"], langue);
            t.attendre(entree, 60);
            t.taper("7");
            t.taper(ENTREE);
            t.attendre(legende, 30);
            t.taper("3");
            t.taper(ENTREE);
            t.attendre(defaut, 30);
            t.taper("a");
            t.taper(ENTREE);
            t.attendre(ajout, 30);
            t.taper("1");
            t.taper(ENTREE);
            let ecran = t.attendre(choisie, 30);
            assert!(ecran.contains(enregistree), "{langue} : {ecran}");
            let ecrit = lu();
            assert!(
                ecrit.contains("outil-d-attaque") && ecrit.contains("suspendre"),
                "{langue} : {ecrit}"
            );
            // Scellé par Vanguard : relu sans l'avertissement d'un fichier changé hors de lui.
            assert!(maison.join("donnees/vanguard/sceaux.json").exists(), "{langue}");
            t.taper("d");
            t.taper(ENTREE);
            let ecran = t.attendre(defaut, 30);
            assert!(ecran.contains(enregistree), "{langue} : {ecran}");
            assert!(!lu().contains("outil-d-attaque"), "{langue} : {}", lu());
            // « d » parti avec la suite choisie : Entrée revient (pas le premier geste rouvert).
            t.taper(ENTREE);
            t.attendre(legende, 30);
            t.taper(ECHAP);
            t.attendre(entree, 30);
            t.taper(ECHAP);
            let fin = Instant::now() + Duration::from_secs(30);
            let statut = loop {
                if let Some(s) = enfant.try_wait().unwrap() {
                    break s;
                }
                if Instant::now() > fin {
                    let _ = enfant.kill();
                    panic!(
                        "{langue} : Entrée n'a pas fermé le menu du blocage en 30 s :\n{}",
                        t.attendre("", 0)
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            };
            assert!(statut.success(), "{langue} : {statut:?}");
            drop(t);
            let _ = lecteur.join();
            let _ = std::fs::remove_dir_all(&maison);
        }
    }

    /// L'assistant de signalement au clavier : « Rien de ce que Vanguard a vu » choisi par Entrée, la question du tri
    /// montrée, puis Échap : on revient sans rien écrire.
    #[test]
    fn signaler_au_clavier_sans_rien_ecrire() {
        let maison = maison_jetable();
        let (mut enfant, mut t, lecteur) = lancer(&maison, &["signaler"]);
        let ecran = t.attendre("Rien de ce que Vanguard a vu", 60);
        assert!(ecran.contains("Il ne l'envoie jamais"), "{ecran}");
        t.taper(ENTREE);
        let tri = t.attendre("Un logiciel se comporte mal", 30);
        assert!(tri.contains("Un lien ou courriel d'hameçonnage"), "{tri}");
        t.taper(ECHAP);
        let fin = Instant::now() + Duration::from_secs(30);
        let statut = loop {
            if let Some(s) = enfant.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > fin {
                let _ = enfant.kill();
                panic!("Échap n'a pas fermé l'assistant en 30 s :\n{}", t.attendre("", 0));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(statut.success(), "{statut:?}");
        drop(t);
        let _ = lecteur.join();
        assert!(!maison.join("donnees/vanguard/signalements").exists());
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Paramètres › Partage avec l'auteur au clavier : les trois choix et « plus tard » ; Échap ne change rien,
    /// « Voir » revient à la question, « Non » efface le relevé et la file, « Oui » note l'accord.
    #[test]
    fn partage_trois_choix_echap_voir_non_oui() {
        let maison = maison_jetable();
        let dossier = maison.join("donnees/vanguard");
        std::fs::create_dir_all(dossier.join("envoi/file")).unwrap();
        std::fs::create_dir_all(dossier.join("amelioration/jours")).unwrap();
        std::fs::write(dossier.join("envoi/etat.json"), "{}").unwrap();
        std::fs::write(dossier.join("amelioration/jours/2026-11-01.json"), "{}").unwrap();
        std::fs::write(dossier.join("a-moi.txt"), "à alice").unwrap();
        let parametres = || std::fs::read_to_string(dossier.join("parametres.json")).unwrap_or_default();
        let (mut enfant, mut t, lecteur) = lancer(&maison, &[]);
        t.attendre("q quitter", 60);
        t.taper("13.1");
        t.taper(ENTREE);
        t.attendre("Échap/← revenir", 60);
        t.taper("15");
        t.taper(ENTREE);
        let question = t.attendre("Échap/← plus tard", 30);
        for attendu in [
            "Partager avec l'auteur ?",
            "En ce moment : pas répondu.",
            "Oui",
            "une fois par jour",
            "arrêter et effacer le relevé",
            "Voir ce qui serait envoyé",
            "Plus tard",
            "rien ne change",
        ] {
            assert!(question.contains(attendu), "« {attendu} » manque :\n{question}");
        }
        // Échap : plus tard, rien d'écrit, rien d'effacé.
        t.taper(ECHAP);
        t.attendre("Échap/← revenir", 30);
        assert!(!parametres().contains("partage"), "{}", parametres());
        assert!(dossier.join("amelioration").exists() && dossier.join("envoi").exists());
        // Entrée sur « Plus tard » (où la question s'ouvre) : pareil, sans rien dire d'autre.
        t.taper(ENTREE);
        t.attendre("Échap/← plus tard", 30);
        t.taper(ENTREE);
        let liste = t.attendre("Échap/← revenir", 30);
        assert!(!liste.contains("réponse inconnue"), "{liste}");
        assert!(!parametres().contains("partage"), "{}", parametres());
        // Voir, puis retour à la question.
        t.taper(ENTREE);
        t.attendre("Échap/← plus tard", 30);
        t.taper("3");
        t.taper(ENTREE);
        let vu = t.attendre("Entrée pour revenir à la question", 30);
        assert!(
            vu.contains("Ce qui serait envoyé") && vu.contains("En attente : 0"),
            "{vu}"
        );
        assert!(!parametres().contains("partage"), "« Voir » a écrit : {}", parametres());
        t.taper(ENTREE);
        t.attendre("Échap/← plus tard", 30);
        // Non : effacé, et noté.
        t.taper("2");
        t.taper(ENTREE);
        let liste = t.attendre("Échap/← revenir", 30);
        assert!(liste.contains("Partage avec l'auteur"), "{liste}");
        assert!(parametres().contains("\"partage\": \"non\""), "{}", parametres());
        // En root (verifier.sh, sous unshare), le dossier n'est pas celui d'une personne : rien d'effacé, et dit.
        let efface = !super::en_root();
        assert_eq!(liste.contains("Rien d'effacé ici"), !efface, "{liste}");
        for parti in ["envoi", "amelioration"] {
            assert_eq!(dossier.join(parti).exists(), !efface, "{parti}/ :\n{liste}");
        }
        assert_eq!(std::fs::read_to_string(dossier.join("a-moi.txt")).unwrap(), "à alice");
        // Oui, depuis « non ».
        t.taper(ENTREE);
        let question = t.attendre("Échap/← plus tard", 30);
        assert!(question.contains("En ce moment : non."), "{question}");
        t.taper("1");
        t.taper(ENTREE);
        t.attendre("Échap/← revenir", 30);
        assert!(parametres().contains("\"partage\": \"oui\""), "{}", parametres());
        t.taper(ECHAP);
        t.attendre("q quitter", 30);
        t.taper("q");
        t.taper(ENTREE);
        let fin = Instant::now() + Duration::from_secs(30);
        while enfant.try_wait().unwrap().is_none() {
            assert!(Instant::now() < fin, "« q » n'a pas fermé Vanguard");
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(t);
        let _ = lecteur.join();
        let _ = std::fs::remove_dir_all(&maison);
    }
}

/// Le compte est-il root (sous `unshare -rn`, verifier.sh le rend root) ?
#[cfg(unix)]
fn en_root() -> bool {
    std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .ok()
        == Some(0)
}
#[cfg(not(unix))]
fn en_root() -> bool {
    false
}

const REFUS_OPTIMISER: &str =
    "Windows élevé avec l'UAC : les outils d'Optimiser refusent, voulu (refus_d_optimiser_en_administrateur)";

/// Les outils d'Optimiser refusés ici ? Attendu d'après Windows lui-même, pas d'après Vanguard : élevé (`windows_eleve`)
/// avec un jeton ordinaire à côté (`jeton_ordinaire_a_cote`). `jeux` lancé une fois doit alors refuser (code 2 et
/// la raison), et sinon tourner : un refus à tort serait un échec, pas des essais sautés. Sous Linux, les essais ne
/// tournent jamais en root venu de sudo (`unshare -rn` n'est pas root de l'ordinateur).
fn optimiser_refuse_ici() -> bool {
    static REFUSE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *REFUSE.get_or_init(|| {
        if !windows_eleve() {
            return false;
        }
        let attendu = jeton_ordinaire_a_cote();
        let s = vanguard("fr", &["jeux"], "", 60);
        let refuse = s.code == Some(2)
            && espaces_unis(&s.erreurs).contains("les outils d'Optimiser refusent de tourner avec tous les droits");
        assert_eq!(
            refuse, attendu,
            "Windows élevé, jeton ordinaire à côté : {attendu} ; jeux : {:?} {}",
            s.code, s.erreurs
        );
        refuse
    })
}

/// Le texte sur une ligne : un avertissement enveloppé à la largeur de l'écran se relit comme une phrase.
fn espaces_unis(t: &str) -> String {
    t.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// L'élévation a-t-elle un jeton ordinaire à côté (TokenElevationType ≠ 1) ? Lu à Windows lui-même, sans Vanguard.
/// EnableLUA ne suffit pas : un processus lancé par un service (la CI de GitHub) est élevé sans jeton ordinaire, UAC
/// allumé ou pas, et rien ne refuse alors. Illisible : compté avec jeton ordinaire, comme le refus, qui échoue fermé.
#[cfg(windows)]
fn jeton_ordinaire_a_cote() -> bool {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION_TYPE, TOKEN_QUERY, TokenElevationType, TokenElevationTypeDefault,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut poignee = HANDLE::default();
    let mut genre = TOKEN_ELEVATION_TYPE::default();
    let mut taille = 0u32;
    // SAFETY: GetCurrentProcess rend une pseudo-poignée ; le jeton ouvert est fermé une seule fois. Windows écrit au
    // plus 4 octets, la taille exacte de TOKEN_ELEVATION_TYPE (il refuse un tampon plus grand), dans `genre`.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut poignee).is_err() {
            return true;
        }
        let lu = GetTokenInformation(
            poignee,
            TokenElevationType,
            Some((&raw mut genre).cast()),
            u32::try_from(size_of::<TOKEN_ELEVATION_TYPE>()).unwrap(),
            &raw mut taille,
        )
        .is_ok();
        let _ = CloseHandle(poignee);
        !lu || genre != TokenElevationTypeDefault
    }
}
#[cfg(not(windows))]
fn jeton_ordinaire_a_cote() -> bool {
    false
}

/// Élevé avec l'UAC, un outil d'Optimiser refuse avant tout geste : code 2, la raison sur la sortie d'erreur, rien à
/// l'écran ; « optimiser annuler » (Tout remettre comme avant) n'est pas refusé.
#[test]
fn refus_d_optimiser_en_administrateur() {
    if !optimiser_refuse_ici() {
        return essais::saute("pas un Windows élevé avec l'UAC : rien n'est refusé ici");
    }
    for args in [
        &["nettoyer", "--liste"][..],
        &["lenteur", "--json"],
        &["optimiser", "confort"],
    ] {
        let s = vanguard("en", args, "", 60);
        assert_eq!(s.code, Some(2), "{args:?}");
        assert!(
            espaces_unis(&s.erreurs).contains("Optimize tools refuse to run with full administrator rights"),
            "{args:?} : {}",
            s.erreurs
        );
        assert!(!s.texte.contains("Nothing was deleted"), "{args:?} : {}", s.texte);
    }
    let annuler = vanguard("fr", &["optimiser", "annuler"], "n\n", 60);
    assert!(
        !espaces_unis(&annuler.erreurs).contains("refusent de tourner"),
        "{}",
        annuler.erreurs
    );
}

/// Sous Windows, le programme tourne-t-il élevé (administrateur) ? Comme `processus::eleve` (TokenElevation) : un
/// jeton élevé porte le niveau d'intégrité haut, S-1-16-12288, que `whoami /groups` montre quelle que soit la langue
/// (`net session` répondait aussi sous Wine, où Vanguard ne se voit pas élevé). Pas dans `en_root` : l'autotest, lui,
/// ne refuse pas un Windows élevé.
#[cfg(windows)]
fn windows_eleve() -> bool {
    let systeme = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    std::process::Command::new(Path::new(&systeme).join("System32").join("whoami.exe"))
        .arg("/groups")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("S-1-16-12288"))
}
#[cfg(not(windows))]
fn windows_eleve() -> bool {
    false
}

/// Les fichiers d'un dossier, avec leur contenu (chemin relatif → octets), sauf ceux que l'autotest écrit lui-même
/// (son résultat scellé, sa date, l'événement d'essai et la tête du journal, les sceaux qui les scellent et leur
/// témoin) et le journal des erreurs.
fn contenus(dossier: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut tous = std::collections::BTreeMap::new();
    let mut a_voir = vec![dossier.to_path_buf()];
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            let relatif = p.strip_prefix(dossier).unwrap().to_string_lossy().replace('\\', "/");
            let propre = [
                "autotest",
                "examens/AUT-VAN-001.json",
                "evenements",
                "evenements.tete",
                "sceaux.json",
                "sceaux.temoin",
            ]
            .iter()
            .any(|x| relatif == *x || relatif.starts_with(&format!("{x}/")))
                || relatif == "journal-erreurs.txt"
                || relatif.ends_with(".verrou")
                || std::path::Path::new(&relatif).extension().is_some_and(|e| e == "lock");
            if propre {
                continue;
            }
            if p.is_dir() {
                a_voir.push(p);
            } else {
                tous.insert(relatif, std::fs::read(&p).unwrap_or_default());
            }
        }
    }
    tous
}

/// L'autotest pour de vrai, dans un dossier personnel jetable : en root (sous `unshare -rn`), refusé sans rien écrire ;
/// sinon, après un bilan qui pose l'état (administrateurs, logiciels vus), il rend un JSON relisible, son code de
/// sortie, une preuve « rien changé », et le dossier de Vanguard est le même au fichier près (hors ses propres
/// fichiers).
#[test]
fn autotest_ne_change_rien() {
    let maison = maison_jetable();
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let dossier = dossier_vanguard(&maison);
    if en_root() {
        let s = vanguard_dans(programme, &maison, "fr", &["autotest", "--json"], "", 60);
        assert_eq!(s.code, Some(2), "{}", s.erreurs);
        let r: serde_json::Value = serde_json::from_str(&s.texte).expect("JSON illisible");
        assert_eq!(r["verdict"], "refuse");
        assert!(contenus(&dossier).is_empty(), "rien ne s'écrit en root");
        let _ = std::fs::remove_dir_all(&maison);
        return essais::saute("en root (unshare) : seul le refus est essayé");
    }
    let bilan = vanguard_dans(programme, &maison, "fr", &["audit", "--json"], "", 300);
    assert_eq!(bilan.code, Some(0), "{}", bilan.erreurs);
    let avant = contenus(&dossier);
    let s = vanguard_dans(programme, &maison, "fr", &["autotest", "--json"], "", 600);
    let r: serde_json::Value = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{e} : {}", s.texte));
    assert_eq!(r["outil"], "AUT-VAN-001");
    assert_eq!(
        s.code,
        r["code"].as_i64().map(|c| i32::try_from(c).unwrap()),
        "{}",
        s.erreurs
    );
    assert!(r["regles"]["essayees"].as_u64().unwrap() >= 35);
    assert_eq!(r["hors_ligne"], true, "hors ligne par défaut");
    assert_eq!(r["preuve"]["verdict"], "rien-change", "{r}");
    assert_eq!(contenus(&dossier), avant, "l'autotest a changé le dossier de Vanguard");
    assert!(dossier.join("examens/AUT-VAN-001.json").is_file());
    assert!(dossier.join("autotest/dernier.json").is_file());
    // Le JSON ne porte aucune valeur : ni le compte, ni le dossier personnel.
    assert!(!s.texte.contains(&*maison.to_string_lossy()));
    // --detail avec --json est refusé : le JSON peut sortir de l'ordinateur.
    let refus = vanguard_dans(programme, &maison, "fr", &["autotest", "--json", "--detail"], "", 30);
    assert_ne!(refus.code, Some(0));
    let _ = std::fs::remove_dir_all(&maison);
}

/// journal-vers-github.py hors réseau, avec un faux gh qui note ses appels : cinq entrées de même signature font un
/// seul ticket ; deux lectures croisées différentes, deux tickets ; un corps de plus de 60 000 octets est coupé et le
/// dit.
#[cfg(unix)]
#[test]
fn tickets_du_journal_regroupes() {
    if Command::new("python3").arg("-V").output().is_err() {
        return essais::saute("python3 absent");
    }
    let d = maison_jetable();
    let faux = d.join("bin");
    std::fs::create_dir_all(&faux).unwrap();
    let appels = d.join("appels.txt");
    std::fs::write(
        faux.join("gh"),
        format!(
            "#!/bin/sh\nprintf '%s' \"$*\" | tr '\\n' ' ' >> '{0}'\necho >> '{0}'\ncase \"$1 $2\" in\n  'issue create') echo https://github.invalid/x/y/issues/$$ ;;\nesac\nexit 0\n",
            appels.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(faux.join("gh"), std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let entree = |contexte: &str, detail: &str| {
        format!(
            "== 2026-10-23 10:00 UTC · vanguard 0.86.0 · Arch Linux 7.2 · fr · autotest\n[{contexte}]\n  {detail}\n\n"
        )
    };
    let mut texte = String::new();
    for n in 1..=5 {
        texte += &entree(
            "autotest AUT-LNX-001",
            &format!("[absent-natif] {n} en plus, 0 en moins"),
        );
    }
    texte += &entree("autotest AUT-LNX-002", "[absent-natif] 1 en plus, 0 en moins");
    texte += &entree(
        "autotest AUT-LNX-003",
        &format!("[sortie-inattendue] {}", "é".repeat(40_000)),
    );
    let fichier = d.join("journal-a-envoyer.txt");
    std::fs::write(&fichier, &texte).unwrap();
    let chemin = format!("{}:{}", faux.display(), std::env::var("PATH").unwrap_or_default());
    let s = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("outils/journal-vers-github.py"))
        .arg(&fichier)
        .env("PATH", chemin)
        .env("HOME", &*d)
        .output()
        .unwrap();
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let journal = std::fs::read_to_string(&appels).unwrap();
    let crees: Vec<&str> = journal.lines().filter(|l| l.starts_with("issue create")).collect();
    assert_eq!(crees.len(), 3, "{journal}");
    assert!(!journal.lines().any(|l| l.starts_with("issue comment")), "{journal}");
    let groupe = crees.iter().find(|l| l.contains("AUT-LNX-001")).unwrap();
    assert!(
        groupe.contains("Vu 5 fois") && groupe.contains("--label autotest"),
        "{groupe}"
    );
    let gros = crees.iter().find(|l| l.contains("AUT-LNX-003")).unwrap();
    assert!(gros.contains("coupé") && gros.len() < 70_000, "{}", gros.len());
    // Tout est parti : le fichier est vidé.
    assert_eq!(std::fs::read_to_string(&fichier).unwrap().trim(), "");

    // Vérifications impossibles : l'état de l'ordinateur ne part pas (filet des 0.88 à 0.91, reconnu au texte, toutes
    // les raisons du message), le reste d'une même règle fait un seul ticket par code de raison.
    let impossible = |version: &str, detail: &str, champs: &str| {
        format!(
            "== 2026-10-27 17:27 UTC · vanguard {version} · Windows · fr · menu\n[vérification impossible]\n  {detail}\n{champs}\n"
        )
    };
    let jrn = "§ genre=impossible contexte=verification-impossible regle=WIN-JRN-003 code=- lieu=-";
    let mut texte = String::new();
    // Comme les tickets #8 à #16 : Security refusé hors administrateur, audit éteint, historique court, accord de
    // l'AUR, déploiement d'Edge.
    for detail in [
        "Journaux d'événements : Non vérifié — journal Security réservé à l'administrateur ; Security : rien ne prouve que Windows écrit ces événements (aucune ouverture de session journalisée : l'audit des ouvertures de session est peut-être coupé) : EVT-MDP-001 (mots de passe devinés).",
        "Journaux d'événements : Non vérifié — journal System lu seulement depuis le 2026-10-24 13:33 : plus ancien écrasé, effacé, ou rien écrit : EVT-SRV-001 (service d'attaque installé).",
        "Journaux d'événements : Non vérifié — journal PowerShellCore/Operational absent de cet ordinateur : EVT-PSH-001 (PowerShell malveillant).",
        "SSH : Impossible de vérifier les droits de %ProgramData%\\ssh\\administrators_authorized_keys (réservés à l'administrateur).",
        "Logiciels pas à jour : Impossible de vérifier (Microsoft Edge 156.0.4314.42 (déploiement de la 156.0.4314.50 en cours)).",
        "Paquets AUR : Could not check (the names of the packages outside the repositories are sent to aur.archlinux.org only with your consent (Settings › AUR packages)).",
    ] {
        texte += &impossible("0.88.0", detail, "");
        texte += &impossible("0.91.0", detail, jrn);
    }
    // Une raison non attendue dans le message : envoyée, et deux détails différents de WIN-JRN-003, un seul ticket.
    texte += &impossible(
        "0.91.0",
        "Journaux d'événements : Non vérifié — journal Security réservé à l'administrateur ; journal System illisible : accès refusé : EVT-EFF-001 (traces effacées).",
        jrn,
    );
    texte += &impossible(
        "0.91.0",
        "Journaux d'événements : Non vérifié — journal Application illisible : délai : EVT-SRV-001 (service).",
        jrn,
    );
    // Zen sans version (le ticket #5) : pas un état de l'ordinateur, envoyé.
    texte += &impossible(
        "0.88.0",
        "Post-quantique : Impossible de vérifier (Zen : version illisible, échange de clés post-quantique par défaut non vérifié).",
        "",
    );
    std::fs::write(&fichier, &texte).unwrap();
    std::fs::remove_file(&appels).unwrap();
    let chemin = format!("{}:{}", faux.display(), std::env::var("PATH").unwrap_or_default());
    let s = Command::new("python3")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("outils/journal-vers-github.py"))
        .arg(&fichier)
        .env("PATH", chemin)
        .env("HOME", &*d)
        .output()
        .unwrap();
    assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
    let sortie = String::from_utf8_lossy(&s.stdout);
    assert!(
        sortie.contains("12 vérification(s) impossible(s) attendue(s)"),
        "{sortie}"
    );
    let journal = std::fs::read_to_string(&appels).unwrap();
    let crees: Vec<&str> = journal.lines().filter(|l| l.starts_with("issue create")).collect();
    assert_eq!(crees.len(), 2, "{journal}");
    let regle = crees.iter().find(|l| l.contains("WIN-JRN-003")).unwrap();
    assert!(
        regle.contains("Vu 2 fois") && regle.contains("EVT-EFF-001") && regle.contains("journal Application illisible"),
        "{regle}"
    );
    assert!(crees.iter().any(|l| l.contains("Zen")), "{journal}");
    assert!(
        !journal.contains("EVT-PSH-001") && !journal.contains("aur.archlinux.org"),
        "{journal}"
    );
    assert_eq!(std::fs::read_to_string(&fichier).unwrap().trim(), "");
    let _ = std::fs::remove_dir_all(&d);
}

/// `vanguard chercher` : la recherche du menu en ligne de commande. « box » mène au routeur (synonyme), une faute
/// se corrige, rien de trouvé sort en 1.
#[test]
fn chercher_en_ligne_de_commande() {
    let s = vanguard("fr", &["chercher", "box", "--json"], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap();
    assert_eq!(v["resultats"][0]["touche"], "5.4", "{v}");
    let faute = vanguard("fr", &["chercher", "imprimnte", "--json"], "", 60);
    let v: serde_json::Value = serde_json::from_str(&faute.texte).unwrap();
    assert_eq!(v["corrections"][0]["corrige"], "imprimante", "{v}");
    let rien = vanguard("fr", &["chercher", "zzzqqq"], "", 60);
    assert_eq!(rien.code, Some(1));
    assert!(sans_couleurs(&rien.texte).contains("Aucun résultat"));
}

/// `--json` d'un outil qui rend un résultat (`modele::resultat`) : code 0, rien d'autre que le JSON sur la sortie
/// standard (toute la sortie se lit d'un bloc), son identifiant, son schéma et ses constats. Rien n'est demandé :
/// l'entrée reste vide. Rend le résultat lu.
fn examen_en_json(commande: &str, id: &str) -> serde_json::Value {
    let maison = maison_jetable();
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &[commande, "--json"],
        "",
        180,
        &[("VANGUARD_HORS_LIGNE", "1")],
    );
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(s.code, Some(0), "{commande} --json : {}", s.erreurs);
    assert!(s.texte.trim_start().starts_with('{'), "{commande} --json : {}", s.texte);
    let v: serde_json::Value = serde_json::from_str(&s.texte)
        .unwrap_or_else(|e| panic!("{commande} --json : JSON illisible ({e}) : {}", s.texte));
    assert_eq!(v["outil"], id, "{v}");
    assert_eq!(v["schema"], 1, "{v}");
    assert!(v["constats"].is_array(), "{v}");
    assert!(v["couverture"]["verifies"].is_u64(), "{v}");
    v
}

/// `diagnostic --json` : le relevé jugé, sans copie texte ni question.
#[test]
fn diagnostic_en_json() {
    examen_en_json("diagnostic", "PRO-DIA-001");
}

/// `integrite --json` : dans une maison jetable, pas de référence ; aucune n'est posée en silence, et le résultat
/// n'est jamais sain.
#[test]
fn integrite_en_json() {
    let v = examen_en_json("integrite", "PRO-INT-001");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert_eq!(v["constats"][0]["etat"], "non-verifie", "{v}");
    assert_eq!(v["constats"][0]["raison"], "introuvable", "{v}");
}

/// `dernieres-failles --json` sans Internet ni copie gardée : rien n'est conclu, et la raison est dite.
#[test]
fn dernieres_failles_en_json() {
    let v = examen_en_json("dernieres-failles", "PRO-KEV-001");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert!(v["couverture"]["non_verifies"][0].is_string(), "{v}");
    assert_eq!(v["constats"][0]["etat"], "non-verifie", "{v}");
}

/// `lenteur --json` : la mesure de deux secondes jugée, sans le menu des outils.
#[test]
fn lenteur_en_json() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    examen_en_json("lenteur", "PRO-LEN-001");
}

/// `objets-connectes --json` : dans une maison jetable, aucun scan gardé ; jamais sain, et la raison est dite.
#[test]
fn objets_connectes_en_json() {
    let v = examen_en_json("objets-connectes", "PRO-OBJ-001");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert!(v["couverture"]["non_verifies"][0].is_string(), "{v}");
    assert_eq!(v["constats"][0]["raison"], "introuvable", "{v}");
}

/// `secrets --json` sur un dépôt jetable dont l'historique garde un faux jeton (inventé, coupé en deux dans le
/// source pour ne jamais ressembler à un vrai) : la fuite est dite (genre, fichier, ligne, commit), et aucun morceau
/// utilisable du secret n'est dans la sortie, ni sur l'erreur standard.
#[test]
fn secrets_en_json_sans_le_secret() {
    let maison = maison_jetable();
    let depot = maison.join("projets").join("site");
    std::fs::create_dir_all(&depot).unwrap();
    let git = |args: &[&str]| {
        Command::new("git")
            .args([
                "-c",
                "user.name=alice",
                "-c",
                "user.email=alice@exemple.invalid",
                "-c",
                "commit.gpgsign=false",
                "-C",
            ])
            .arg(&depot)
            .args(args)
            .env("HOME", &*maison)
            .output()
            .is_ok_and(|s| s.status.success())
    };
    if !git(&["init", "-q"]) {
        return essais::saute("git absent");
    }
    let alea = "q8Zr2LmN4vB7xC1dF5gH9jK3pQ6sT0wY2eR4";
    std::fs::write(
        depot.join("config.env"),
        format!("TOKEN={}{alea}\n", concat!("ghp", "_")),
    )
    .unwrap();
    assert!(git(&["add", "."]) && git(&["commit", "-qm", "ajout"]));
    std::fs::write(depot.join("config.env"), "TOKEN=\n").unwrap();
    assert!(git(&["commit", "-qam", "efface"]));
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["secrets", "--json"],
        "",
        180,
        &[("VANGUARD_HORS_LIGNE", "1")],
    );
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("JSON illisible ({e})"));
    assert_eq!(v["outil"], "PRO-GIT-001", "{v}");
    assert!(
        v["constats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["etat"] == "probleme" && c["message"].as_str().is_some_and(|m| m.contains("config.env:1"))),
        "{v}"
    );
    // Aucune fenêtre de huit caractères du secret : ni entier, ni coupé, ni dans une erreur.
    let tout = format!("{}{}", s.texte, s.erreurs);
    let bouts: Vec<&str> = (0..=alea.len() - 8).map(|i| &alea[i..i + 8]).collect();
    assert!(
        bouts.iter().all(|b| !tout.contains(b)),
        "un morceau du secret est sorti"
    );
}

/// `secrets --json` dans une maison sans dépôt : sans objet (rien à relire), jamais compté sain.
#[test]
fn secrets_en_json_sans_depot() {
    let v = examen_en_json("secrets", "PRO-GIT-001");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert_eq!(v["constats"][0]["etat"], "sans-objet", "{v}");
}

/// `verifier-moi --json` : l'historique signé (qui demande un accord) n'est pas comparé, et c'est dit ; le résultat
/// n'est donc jamais sain, et rien ne se dit authentique.
#[test]
fn verifier_moi_en_json() {
    let v = examen_en_json("verifier-moi", "PRO-MOI-001");
    assert!(v["couverture"]["non_verifies"][0].is_string(), "{v}");
    assert!(!v.to_string().to_lowercase().contains("authenti"), "{v}");
}

/// `changements --json` dans une maison neuve : un relevé absent, rien à montrer, et aucun menu d'annulation.
#[test]
fn changements_en_json() {
    let s = vanguard("fr", &["changements", "--json"], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value =
        serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("JSON illisible ({e}) : {}", s.texte));
    assert_eq!(v["schema"], 1, "{v}");
    assert_eq!(v["releve"], "absent", "{v}");
    assert_eq!((v["total"].as_u64(), v["montres"].as_u64()), (Some(0), Some(0)), "{v}");
    assert!(v["changements"].as_array().is_some_and(Vec::is_empty), "{v}");
}

/// `regles --json` : le registre entier, sans question, avec ce programme-ci parmi les outils.
#[test]
fn regles_en_json() {
    let s = vanguard("fr", &["regles", "--json"], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("JSON illisible ({e})"));
    assert_eq!(v["schema"], 1, "{v}");
    assert!(v["bilan"].as_array().is_some_and(|b| !b.is_empty()), "{v}");
    let outils = v["outils"].as_array().unwrap();
    assert!(outils.iter().any(|o| o["id"] == "PRO-GIT-001"), "{v}");
    assert!(outils.iter().any(|o| o["id"] == "PRO-MOI-001"), "{v}");
}

/// Le JSON d'un outil lancé avec `--json` (dossier personnel jetable, `env` en plus) : code 0, la sortie standard
/// n'est que ce JSON (aucune question, aucun « Entrée pour continuer »), l'outil, le schéma et des constats.
fn resultat_json(args: &[&str], env: &[(&str, &str)], outil: &str, code: i32) -> serde_json::Value {
    let maison = maison_jetable();
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        args,
        "o\n",
        120,
        env,
    );
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(s.code, Some(code), "{args:?} : {}", s.erreurs);
    let t = s.texte.trim();
    assert!(
        t.starts_with('{') && t.ends_with('}'),
        "{args:?} : autre chose que le JSON :\n{}",
        s.texte
    );
    let v: serde_json::Value =
        serde_json::from_str(t).unwrap_or_else(|e| panic!("{args:?} : JSON illisible ({e}) :\n{t}"));
    assert_eq!(v["outil"], outil, "{v}");
    assert_eq!(v["schema"], 1, "{v}");
    assert!(v["constats"].is_array(), "{v}");
    assert!(v["couverture"]["verifies"].is_u64(), "{v}");
    v
}

/// `bilan-confidentialite --json` : lecture seule, rien demandé ; ce qui n'a pas pu être lu est dit.
#[test]
fn bilan_confidentialite_en_json() {
    let v = resultat_json(&["bilan-confidentialite", "--json"], &[], "PRO-ACC-001", 0);
    let constats = v["constats"].as_array().unwrap();
    assert!(!constats.is_empty(), "{v}");
    // Jamais « sain » sans rien de lu : quatre permissions au plus, et un manque dit quand il en manque une.
    let verifies = v["couverture"]["verifies"].as_u64().unwrap();
    assert!(verifies <= 4, "{v}");
    if verifies < 4 {
        assert!(
            v["couverture"]["non_verifies"]
                .as_array()
                .is_some_and(|n| !n.is_empty()),
            "{v}"
        );
    }
}

/// `test-connexion --json` hors ligne : rien ne part, tout est non vérifié, jamais un « bon » qu'il n'a pas mesuré.
#[test]
fn test_connexion_en_json() {
    if optimiser_refuse_ici() {
        return essais::saute(REFUS_OPTIMISER);
    }
    let v = resultat_json(
        &["test-connexion", "--json"],
        &[("VANGUARD_HORS_LIGNE", "1")],
        "PRO-CNX-001",
        0,
    );
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    let constats = v["constats"].as_array().unwrap();
    assert!(constats.iter().all(|c| c["etat"] != "sain"), "{v}");
}

/// `lien --json` : sans --internet, le lien piégé est jugé sur l'ordinateur seul, et l'âge du domaine et les listes
/// sont dits non vérifiés ; avec --internet en mode hors ligne, rien ne part non plus. Un texte qui n'est pas un lien :
/// code 2, un résultat non vérifié. Des noms réservés aux exemples (.example).
#[test]
fn lien_en_json() {
    let hors_ligne = [("VANGUARD_HORS_LIGNE", "1")];
    let piege = "https://paypal.com.compte-secure.example/login";
    for args in [&["lien", piege, "--json"][..], &["lien", piege, "--json", "--internet"]] {
        let v = resultat_json(args, &hors_ligne, "PRO-LIE-001", 0);
        let constats = v["constats"].as_array().unwrap();
        assert!(
            constats
                .iter()
                .any(|c| c["etat"] == "probleme" && c["objet"] == "site:compte-secure.example"),
            "{args:?} : {v}"
        );
        let manques = v["couverture"]["non_verifies"].as_array().expect("pas de non vérifié");
        assert!(
            manques
                .iter()
                .any(|m| m.as_str().is_some_and(|m| m.contains("listes publiques"))),
            "{args:?} : {v}"
        );
    }
    let v = resultat_json(&["lien", "bonjour", "--json"], &hors_ligne, "PRO-LIE-001", 2);
    assert_eq!(v["constats"][0]["etat"], "non-verifie", "{v}");
}

/// Un lien à identifiants (« alice:motdepasse@site ») : le signe reste, mais ni l'identifiant ni le mot de passe ne
/// s'écrivent, ni dans le JSON, ni sur le disque (examens/, journal des événements). Valeurs inventées.
#[test]
fn lien_a_identifiants_rien_sur_le_disque() {
    let maison = maison_jetable();
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        &["lien", "https://alice:Secr3t@paypal.com.compte.example/x", "--json"],
        "",
        60,
        &[("VANGUARD_HORS_LIGNE", "1")],
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(s.texte.contains("identifiants retirés"), "{}", s.texte);
    let mut a_voir = vec![maison.to_path_buf()];
    let mut lus = 0;
    while let Some(d) = a_voir.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                a_voir.push(p);
            } else if let Ok(octets) = std::fs::read(&p) {
                lus += 1;
                let t = String::from_utf8_lossy(&octets);
                assert!(!t.contains("Secr3t") && !t.contains("alice"), "{} : {t}", p.display());
            }
        }
    }
    let _ = std::fs::remove_dir_all(&maison);
    assert!(lus > 0, "rien n'a été versé");
    assert!(!s.texte.contains("Secr3t") && !s.texte.contains("alice"), "{}", s.texte);
}

/// `--json` d'un outil de protection, hors ligne : code 0, rien d'autre que le JSON sur la sortie standard (il se lit
/// en entier), l'identifiant de l'outil, le format 1 et des constats. Des réponses sont tapées d'avance : une question
/// posée les lirait (et, pour les listes noires, enverrait l'adresse).
fn resultat_json_hors_ligne(args: &[&str], outil: &str, secondes: u64) -> serde_json::Value {
    let maison = maison_jetable();
    let s = vanguard_dans_env(
        Path::new(env!("CARGO_BIN_EXE_vanguard")),
        &maison,
        "fr",
        args,
        "o\no\no\n",
        secondes,
        &[("VANGUARD_HORS_LIGNE", "1")],
    );
    let _ = std::fs::remove_dir_all(&maison);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    assert!(s.texte.trim_start().starts_with('{'), "{}", s.texte);
    let v: serde_json::Value =
        serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{args:?} : JSON illisible ({e}) : {}", s.texte));
    assert_eq!(v["outil"], outil, "{v}");
    assert_eq!(v["schema"], 1, "{v}");
    assert!(v["constats"].is_array(), "{v}");
    assert!(v["couverture"]["verifies"].is_u64(), "{v}");
    v
}

#[test]
fn connexions_sortantes_en_json() {
    let v = resultat_json_hors_ligne(&["connexions-sortantes", "--json"], "PRO-SOR-001", 120);
    // Lecture seule : aucune correction proposée.
    let constats = v["constats"].as_array().unwrap();
    assert!(constats.iter().all(|c| c.get("corrigeable").is_none()), "{v}");
}

#[test]
fn acces_a_distance_en_json() {
    let v = resultat_json_hors_ligne(&["acces-a-distance", "--json"], "PRO-DIS-001", 120);
    // Toujours au moins un constat : un logiciel trouvé, ou ce qui a été cherché.
    let constats = v["constats"].as_array().unwrap();
    assert!(!constats.is_empty(), "{v}");
    assert!(
        constats
            .iter()
            .all(|c| ["sain", "probleme", "non-verifie"].contains(&c["etat"].as_str().unwrap_or_default())),
        "{v}"
    );
}

/// `yara --json` dans un dossier personnel jetable : aucun endroit à risque → rien d'analysé, jamais « sain » ; un
/// téléchargement inventé → lu, le résultat versé ; rien trouvé n'est « sain » que sans aucun manque. Le « o » tapé
/// d'avance n'est jamais lu (aucune question). `antivirus --etat --json` : l'état des bases, sans rien verser.
#[cfg(unix)]
#[test]
fn analyses_de_fichiers_en_json() {
    let programme = Path::new(env!("CARGO_BIN_EXE_vanguard"));
    let hors_ligne = [("VANGUARD_HORS_LIGNE", "1")];
    let lire = |s: &Sortie| -> serde_json::Value {
        assert_eq!(s.code, Some(0), "{}", s.erreurs);
        serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("JSON illisible ({e}) : {}", s.texte))
    };
    let vide = maison_jetable();
    let v = lire(&vanguard_dans_env(
        programme,
        &vide,
        "fr",
        &["yara", "--json"],
        "o\no\n",
        300,
        &hors_ligne,
    ));
    assert_eq!(v["outil"], "PRO-YAR-001", "{v}");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert_eq!(v["constats"][0]["etat"], "sans-objet", "{v}");

    let maison = maison_jetable();
    std::fs::create_dir_all(maison.join("Downloads")).unwrap();
    std::fs::write(maison.join("Downloads/note-essai.txt"), "bonjour, ceci est un essai\n").unwrap();
    let v = lire(&vanguard_dans_env(
        programme,
        &maison,
        "fr",
        &["yara", "--json"],
        "o\no\n",
        300,
        &hors_ligne,
    ));
    assert_eq!(v["outil"], "PRO-YAR-001", "{v}");
    assert!(v["couverture"]["verifies"].as_u64().is_some_and(|n| n >= 1), "{v}");
    let manques = v["couverture"]["non_verifies"].as_array().map_or(0, Vec::len);
    let premier = v["constats"][0]["etat"].as_str().unwrap_or_default();
    assert!(
        (manques == 0 && premier == "sain") || (manques > 0 && premier == "non-verifie"),
        "{v}"
    );
    assert!(dossier_vanguard(&maison).join("examens/PRO-YAR-001.json").is_file());

    let s = vanguard_dans_env(
        programme,
        &maison,
        "fr",
        &["antivirus", "--etat", "--json"],
        "o\n",
        120,
        &hors_ligne,
    );
    let v = lire(&s);
    assert_eq!(v["outil"], "PRO-ANV-001", "{v}");
    assert!(!dossier_vanguard(&maison).join("examens/PRO-ANV-001.json").exists());
    let _ = std::fs::remove_dir_all(&vide);
    let _ = std::fs::remove_dir_all(&maison);
}

/// Sans --internet, rien ne part (ni la demande de l'adresse publique, ni les listes) malgré le « o » tapé d'avance :
/// non vérifié, la raison dite, sans l'attente d'une demande en ligne. Avec --internet mais hors ligne, rien non plus.
#[test]
fn listes_noires_en_json_sans_rien_envoyer() {
    let v = resultat_json_hors_ligne(&["listes-noires", "--json"], "PRO-LNO-001", 60);
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    let constats = v["constats"].as_array().unwrap();
    assert!(
        !constats.is_empty() && constats.iter().all(|c| c["etat"] == "non-verifie"),
        "{v}"
    );
    assert!(
        v["couverture"]["non_verifies"][0]
            .as_str()
            .unwrap_or_default()
            .contains("--internet"),
        "{v}"
    );
    assert!(v["duree_ms"].as_u64().is_some_and(|d| d < 2000), "{v}");
    let hors_ligne = resultat_json_hors_ligne(&["listes-noires", "--json", "--internet"], "PRO-LNO-001", 60);
    assert_eq!(hors_ligne["couverture"]["verifies"], 0, "{hors_ligne}");
    assert_eq!(hors_ligne["constats"][0]["raison"], "refuse", "{hors_ligne}");
}

/// `journaux-windows` sans `--dossier`, hors de Windows : rien à lire ici, dit sur la sortie d'erreur avec
/// l'exemple d'un dossier, code 2 ; rien sur la sortie, même sous `--json`.
#[test]
fn journaux_windows_sans_dossier() {
    if cfg!(windows) {
        return essais::saute("sous Windows, sans --dossier, ce sont les journaux de l'ordinateur");
    }
    for args in [&["journaux-windows"][..], &["journaux-windows", "--json"]] {
        let s = vanguard("fr", args, "", 30);
        assert_eq!(s.code, Some(2), "{args:?} : {}", s.erreurs);
        assert!(s.texte.trim().is_empty(), "{args:?} : {}", s.texte);
        let e = sans_couleurs(&s.erreurs);
        assert!(e.contains("--dossier") && e.contains("winevt"), "{e}");
    }
}

/// `--jours` : 0 et un nombre négatif refusés avant toute lecture ; un dossier qui n'existe pas, code 1.
#[test]
fn journaux_windows_options_refusees() {
    for jours in ["0", "-3", "abc"] {
        let s = vanguard("fr", &["journaux-windows", "--dossier", ".", "--jours", jours], "", 30);
        assert_eq!(s.code, Some(2), "--jours {jours} : {}", s.erreurs);
        assert!(s.texte.trim().is_empty(), "--jours {jours} : {}", s.texte);
    }
    let absent = maison_jetable().join("pas-la");
    let s = vanguard(
        "fr",
        &["journaux-windows", "--dossier", absent.to_str().unwrap()],
        "",
        30,
    );
    assert_eq!(s.code, Some(1), "{}", s.erreurs);
    // Le message est mis en lignes à la largeur : un chemin long peut couper la phrase.
    let erreurs = sans_couleurs(&s.erreurs)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(erreurs.contains("ne se lit pas"), "{}", s.erreurs);
}

/// Un dossier sans journal lisible (un faux .evtx) : jamais « rien trouvé » ; chaque règle non vérifiée, la période de
/// chaque journal dite, et en JSON le résultat commun, non vérifié. Rien n'est demandé (aucune entrée tapée).
#[test]
fn journaux_windows_dossier_sans_journal_lisible() {
    let d = maison_jetable();
    std::fs::write(d.join("System.evtx"), b"pas un journal").unwrap();
    let dossier = d.to_str().unwrap();
    let s = vanguard("fr", &["journaux-windows", "--dossier", dossier], "", 60);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(t.contains("QUE S'EST-IL PASSÉ ?") && t.contains("CHRONOLOGIE"), "{t}");
    assert!(t.contains("EVT-SRV-001") && t.contains("non vérifié"), "{t}");
    assert!(t.contains("Pas tout vérifié") && !t.contains("Rien trouvé"), "{t}");
    assert!(
        t.contains("PÉRIODE LUE PAR JOURNAL") && t.contains("absent du dossier"),
        "{t}"
    );
    for l in t.lines() {
        assert!(l.chars().count() <= 76, "{l}");
    }
    let s = vanguard(
        "en",
        &["windows-logs", "--folder", dossier, "--days", "30", "--json"],
        "",
        60,
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap_or_else(|e| panic!("{e} : {}", s.texte));
    assert_eq!(v["outil"], "PRO-EVT-001", "{v}");
    assert_eq!(v["schema"], 1, "{v}");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert!(!v["couverture"]["non_verifies"].as_array().unwrap().is_empty(), "{v}");
    assert!(
        v["constats"].as_array().unwrap().iter().all(|c| c["etat"] != "sain"),
        "{v}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// Sur les échantillons publics (journaux d'attaque publiés) : des alertes datées dans l'ordre du temps, avec leur
/// contexte ; en JSON, chaque alerte porte sa date en UTC. Tout tient dans 76 colonnes.
#[test]
fn journaux_windows_sur_les_echantillons() {
    let Some(dossier) = std::env::var_os("VANGUARD_EVTX_ECHANTILLONS") else {
        return essais::saute("VANGUARD_EVTX_ECHANTILLONS absente : pas d'échantillons .evtx");
    };
    let dossier = dossier.to_str().unwrap().to_string();
    let s = vanguard(
        "fr",
        &["journaux-windows", "--dossier", &dossier, "--jours", "3650"],
        "",
        300,
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let t = sans_couleurs(&s.texte);
    assert!(t.contains("EVT-ADM-001") && t.contains("événement 4720"), "{t}");
    assert!(t.contains("alerte(s) à regarder"), "{t}");
    for l in t.lines() {
        assert!(l.chars().count() <= 76, "{l}");
    }
    // Les dates de la chronologie, dans l'ordre.
    let dates: Vec<&str> = t
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("✖ "))
        .filter(|l| l.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .filter_map(|l| l.get(..16))
        .collect();
    assert!(dates.len() > 5, "{t}");
    assert!(dates.windows(2).all(|w| w[0] <= w[1]), "{dates:?}");
    let s = vanguard(
        "fr",
        &["journaux-windows", "--dossier", &dossier, "--jours", "3650", "--json"],
        "",
        300,
    );
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let v: serde_json::Value = serde_json::from_str(&s.texte).unwrap();
    let alertes: Vec<&serde_json::Value> = v["constats"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["etat"] == "probleme")
        .collect();
    assert!(
        alertes
            .iter()
            .filter(|c| c["date"].as_str().is_some_and(|d| d.ends_with('Z')))
            .count()
            > 5,
        "{v}"
    );
    assert_ne!(
        v["couverture"]["verifies"],
        serde_json::json!(11),
        "échantillons abîmés exprès : jamais tout vérifié"
    );
}

/// Campagne 3, la haute : au branchement, `manifeste --ecrire` réécrivait la référence d'après la clé telle qu'elle
/// revenait, et ce qui avait été planté en voyage devenait « la clé n'a pas changé ». Le déploiement compare d'abord
/// (`deploiement comparer-cle`) ; `--ecrire` refuse un écart hors de ce que le déploiement pose (code 2) ; seul
/// `--forcer` (l'accord de l'auteur) l'accepte.
#[test]
fn manifeste_de_la_cle_jamais_reecrit_sur_un_ecart() {
    let maison = maison_jetable();
    let cle = maison.join("cle");
    std::fs::create_dir_all(cle.join("Linux")).unwrap();
    std::fs::write(cle.join("vanguard.cle"), "temoin\n").unwrap();
    std::fs::write(cle.join("vanguard.jeton"), "0123456789abcdef0123456789abcdef\n").unwrap();
    std::fs::write(cle.join("Linux/vanguard"), "programme").unwrap();
    let cle_txt = cle.to_string_lossy().into_owned();
    let lancer = |args: &[&str]| vanguard_dans(Path::new(env!("CARGO_BIN_EXE_vanguard")), &maison, "fr", args, "", 120);
    let s = lancer(&["manifeste", "--ecrire", &cle_txt]);
    assert_eq!(s.code, Some(0), "{}{}", s.texte, s.erreurs);
    assert_eq!(lancer(&["deploiement", "comparer-cle", &cle_txt]).code, Some(0));
    // Le voyage : un raccourci planté à la racine.
    std::fs::write(cle.join("Photos.lnk"), "piege").unwrap();
    let s = lancer(&["deploiement", "comparer-cle", &cle_txt]);
    assert_eq!(s.code, Some(2), "{}{}", s.texte, s.erreurs);
    assert!(s.erreurs.contains("Photos.lnk"), "{}", s.erreurs);
    let s = lancer(&["manifeste", "--ecrire", &cle_txt]);
    assert_eq!(s.code, Some(2), "réécrite malgré l'écart : {}{}", s.texte, s.erreurs);
    assert_eq!(lancer(&["deploiement", "comparer-cle", &cle_txt]).code, Some(2));
    // Le programme réécrit par le déploiement entre seul, une fois le plantage retiré.
    std::fs::remove_file(cle.join("Photos.lnk")).unwrap();
    std::fs::write(cle.join("Linux/vanguard"), "programme 2").unwrap();
    assert_eq!(lancer(&["manifeste", "--ecrire", &cle_txt]).code, Some(0));
    // L'accord explicite.
    std::fs::write(cle.join("Photos.lnk"), "voulu").unwrap();
    assert_eq!(lancer(&["manifeste", "--ecrire", &cle_txt, "--forcer"]).code, Some(0));
    assert_eq!(lancer(&["deploiement", "comparer-cle", &cle_txt]).code, Some(0));
    // Aucune clé montée pour ce compte d'essai : rien, sans erreur.
    let s = lancer(&["deploiement", "cle"]);
    assert_eq!((s.code, s.texte.trim()), (Some(0), ""), "{}", s.erreurs);
    let _ = std::fs::remove_dir_all(&maison);
}

/// `deploiement cle` par le vrai programme, avec des volumes montés pour de faux : un espace de noms à soi
/// (`unshare -rm`, sans root) où /run est vide et /run/media/alice (compte inventé) ne montre que les volumes de
/// l'essai. Une copie de la clé (même jeton, autre dossier) : aucune n'est rendue, code 4 (`outils/cle-commun.sh`
/// n'écrit alors sur rien).
/// La même clé vue par deux chemins n'est pas une copie d'elle-même : elle est rendue.
#[test]
fn deploiement_cle_refuse_une_copie_pas_un_second_chemin() {
    if !cfg!(target_os = "linux") {
        return essais::saute("Linux seulement");
    }
    let maison = maison_jetable();
    let cle = maison.join("cle");
    std::fs::create_dir_all(&cle).unwrap();
    std::fs::write(cle.join("vanguard.cle"), "temoin\n").unwrap();
    std::fs::write(cle.join("vanguard.jeton"), "0123456789abcdef0123456789abcdef\n").unwrap();
    let cle_txt = cle.to_string_lossy().into_owned();
    let programme = env!("CARGO_BIN_EXE_vanguard");
    let s = vanguard_dans(
        Path::new(programme),
        &maison,
        "fr",
        &["manifeste", "--ecrire", &cle_txt],
        "",
        120,
    );
    assert_eq!(s.code, Some(0), "jeton pas noté : {}{}", s.texte, s.erreurs);
    let copie = maison.join("copie");
    std::fs::create_dir_all(&copie).unwrap();
    for f in ["vanguard.cle", "vanguard.jeton"] {
        std::fs::copy(cle.join(f), copie.join(f)).unwrap();
    }
    // Les volumes sont des liens vers les dossiers de l'essai : un montage lié de /tmp peut être refusé (quota). Le
    // programme est ouvert avant de cacher /run, où peuvent être ses dossiers de compilation (un disque monté là) ;
    // les dossiers de l'essai aussi, alors : celui de la maison, résolu, est gardé ouvert et remonté à sa place (sans
    // --no-canonicalize, mount lirait le lien de /proc en chemin, celui du dossier vide recréé).
    let script = r#"exec 3<"$1" && garde=$2 && shift 2 || exit 97
if [ -n "$garde" ]; then exec 4<"$garde" || exit 97; fi
mount -t tmpfs essai /run && mkdir -p /run/media/alice || exit 97
if [ -n "$garde" ]; then mkdir -p "$garde" && mount --no-canonicalize --bind /proc/self/fd/4 "$garde" && exec 4<&- || exit 97; fi
for v in "$@"; do
  case $v in --) shift; break ;; *) ln -s "${v#*=}" "/run/media/alice/${v%%=*}" || exit 97; shift ;; esac
done
export USER=alice
exec /proc/self/fd/3 "$@""#;
    let reelle = std::fs::canonicalize(&maison).unwrap();
    let garde = if reelle.starts_with("/run") {
        reelle.to_string_lossy().into_owned()
    } else {
        String::new()
    };
    let dans_l_espace = |volumes: &[(&str, &Path)]| {
        let mut args: Vec<String> = ["-rm", "sh", "-c", script, "sh", programme, &garde]
            .map(String::from)
            .to_vec();
        args.extend(volumes.iter().map(|(n, d)| format!("{n}={}", d.display())));
        args.extend(["--", "deploiement", "cle"].map(String::from));
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        vanguard_dans(Path::new("unshare"), &maison, "fr", &args, "", 60)
    };
    let seule = dans_l_espace(&[("VANGUARD", &cle)]);
    if seule.code == Some(97) || seule.erreurs.contains("unshare") {
        let _ = std::fs::remove_dir_all(&maison);
        return essais::saute("espace de noms refusé (unshare -rm)");
    }
    assert_eq!(
        (seule.code, seule.texte.trim()),
        (Some(0), "/run/media/alice/VANGUARD"),
        "{}",
        seule.erreurs
    );
    let deux = dans_l_espace(&[("VANGUARD", &cle), ("VANGUARD1", &copie)]);
    assert_eq!((deux.code, deux.texte.trim()), (Some(4), ""), "{}", deux.erreurs);
    assert!(deux.erreurs.contains("/run/media/alice/VANGUARD1"), "{}", deux.erreurs);
    assert!(deux.erreurs.contains("même jeton"), "{}", deux.erreurs);
    let meme = dans_l_espace(&[("VANGUARD", &cle), ("VANGUARD1", &cle)]);
    assert_eq!(
        (meme.code, meme.texte.trim()),
        (Some(0), "/run/media/alice/VANGUARD"),
        "{}",
        meme.erreurs
    );
    let _ = std::fs::remove_dir_all(&maison);
}

/// `nat --json` hors ligne : rien ne part vers les serveurs STUN, rien n'est conclu, et la raison est dite.
#[test]
fn nat_en_json_hors_ligne() {
    let v = examen_en_json("nat", "PRO-NAT-001");
    assert_eq!(v["couverture"]["verifies"], 0, "{v}");
    assert_eq!(v["constats"][0]["etat"], "non-verifie", "{v}");
    assert_eq!(v["constats"][0]["raison"], "refuse", "{v}");
}

/// `canaux-wifi --json` : la lecture du système seulement (aucune recherche lancée), sans question. Ce qu'elle
/// trouve dépend de la machine : seule la forme est vérifiée. `cameras-cachees` (qui sonderait le réseau local de la
/// machine d'essai) et `conteneurs` (qui lancerait trivy sur ses images) n'ont pas d'essai ici.
#[test]
fn canaux_wifi_en_json() {
    examen_en_json("canaux-wifi", "PRO-CAN-001");
}
