//! Tests du programme lui-même, vu de l'extérieur : Vanguard est lancé comme le ferait quelqu'un (arguments, réponses
//! envoyées par un tube), avec un dossier personnel jetable pour ne rien écrire dans le vrai (journal des erreurs,
//! base des appareils, historique). Les fonctions internes (lecture des sorties des outils, notes, fabricants…) se
//! testent dans leur propre module : un programme n'a pas de bibliothèque que ce dossier pourrait appeler.
//! Rien ici ne change le système : listes, menus quittés, refus aux questions, scan de 127.0.0.1 seulement.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// Les essais sautés, comptés par outils/verifier.sh comme ceux des tests unitaires.
#[path = "../src/essais.rs"]
mod essais;

struct Sortie {
    code: Option<i32>,
    texte: String,
    erreurs: String,
}

/// Un dossier personnel neuf pour chaque lancement.
fn maison_jetable() -> PathBuf {
    static NUMERO: AtomicUsize = AtomicUsize::new(0);
    let d = std::env::temp_dir().join(format!(
        "vanguard-essai-{}-{}",
        std::process::id(),
        NUMERO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
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

// Blocages de Windows Defender : en anglais dans l'aide ; ailleurs que sous Windows, rien à proposer et rien changé.
#[test]
fn durcir_hors_de_windows() {
    let aide = vanguard("en", &["defender", "--help"], "", 30);
    assert!(aide.texte.contains("Windows Defender blocking"), "{}", aide.texte);
    if !cfg!(windows) {
        let r = vanguard("en", &["defender"], "", 30);
        assert_eq!(r.code, Some(0));
        assert!(r.texte.contains("Nothing in this category"), "{}", r.texte);
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
    let liste = vanguard("fr", &["nettoyer", "--liste"], "", 120);
    assert_eq!(liste.code, Some(0), "{}", liste.erreurs);
    assert!(sans_couleurs(&liste.texte).contains("Rien n'a été effacé"));
    // Entrée garde les cases cochées d'office ; « n » à la question : rien n'est fait.
    let refus = vanguard("fr", &["nettoyer"], "\nn\n", 120);
    let t = sans_couleurs(&refus.texte);
    assert!(t.contains("Annulé") || t.contains("Rien à nettoyer"), "{t}");
}

#[test]
fn audit_en_json() {
    let s = vanguard("fr", &["audit", "--json"], "", 300);
    assert_eq!(s.code, Some(0), "{}", s.erreurs);
    let audit: serde_json::Value = serde_json::from_str(&s.texte).expect("machine --json : JSON illisible");
    let score = audit["score"].as_u64().expect("pas de note");
    assert!(score <= 100);
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
    let fichier = std::env::temp_dir().join(format!("vanguard-sauvegarde-essai-{}.json", std::process::id()));
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
    // Pourquoi c'est lent : la mesure et ses sections, en lecture seule.
    let lenteur = vanguard("fr", &["lenteur"], "", 120);
    assert_eq!(lenteur.code, Some(0), "{}", lenteur.erreurs);
    let texte = sans_couleurs(&lenteur.texte);
    assert!(texte.contains("EN CE MOMENT") && texte.contains("DÉMARRAGE"), "{texte}");
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
        (&["listes-noires"], "o\n", "Adresse publique introuvable"),
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
/// apparaît puis disparaît. Linux seulement : sous Windows et macOS, il va sur le Bureau.
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

/// Lancé depuis une clé (le programme copié dans <clé>/Linux, témoin vide : jamais la protection de la clé), Vanguard
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

/// Le dossier de Vanguard dans un dossier personnel jetable, selon le système (voir `socle::dossier_local`).
fn dossier_vanguard(maison: &Path) -> PathBuf {
    if cfg!(windows) {
        maison.join("local").join("vanguard")
    } else if cfg!(target_os = "macos") {
        maison.join("Library").join("Application Support").join("vanguard")
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
        assert!(page.ends_with("</main></body></html>"));
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
    // En administrateur (dans `unshare -rn`, verifier.sh, le compte devient root) : refusé sans question, rien
    // d'écrit, comme les restrictions des extensions.
    #[cfg(unix)]
    if std::fs::metadata("/proc/self")
        .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
        .ok()
        == Some(0)
    {
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
    // Le dossier de données de chaque système (comme les essais plus haut) : sous macOS, Library/Application Support.
    let donnees = if cfg!(windows) {
        maison.join("local")
    } else if cfg!(target_os = "macos") {
        maison.join("Library").join("Application Support")
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
        // SAFETY : openpty écrit deux descripteurs dans les entiers donnés ; le nom (NULL) et les réglages (NULL)
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
        // SAFETY : les deux descripteurs viennent d'être ouverts par openpty et ne sont à personne d'autre.
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
        let (maitre, esclave) = ouvrir(80, 40);
        let mut commande = Command::new(env!("CARGO_BIN_EXE_vanguard"));
        commande
            .args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TERM", "xterm-256color")
            .env("VANGUARD_LANG", "fr")
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
        // SAFETY : entre fork et exec, seuls setsid et ioctl sont appelés, tous deux sûrs à cet endroit (ni
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

/// Les fichiers d'un dossier, avec leur contenu (chemin relatif → octets), sauf ceux que l'autotest écrit lui-même
/// (son résultat scellé, sa date, l'événement d'essai et la tête du journal, les sceaux qui les scellent) et le
/// journal des erreurs.
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
            ]
            .iter()
            .any(|x| relatif == *x || relatif.starts_with(&format!("{x}/")))
                || relatif == "journal-erreurs.txt"
                || relatif.ends_with(".verrou");
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
        .env("HOME", &d)
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

/// `--json` d'un outil de protection : code 0, rien d'autre que le JSON sur la sortie standard (il se lit en entier),
/// l'identifiant de l'outil, le format 1 et des constats. Des réponses sont tapées d'avance : une question posée les
/// lirait (et, pour les listes noires, enverrait l'adresse).
fn resultat_json(args: &[&str], outil: &str, secondes: u64) -> serde_json::Value {
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
    let v = resultat_json(&["connexions-sortantes", "--json"], "PRO-SOR-001", 120);
    // Lecture seule : aucune correction proposée.
    let constats = v["constats"].as_array().unwrap();
    assert!(constats.iter().all(|c| c.get("corrigeable").is_none()), "{v}");
}

#[test]
fn acces_a_distance_en_json() {
    let v = resultat_json(&["acces-a-distance", "--json"], "PRO-DIS-001", 120);
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

/// Sans --internet, rien ne part (ni la demande de l'adresse publique, ni les listes) malgré le « o » tapé d'avance :
/// non vérifié, la raison dite, sans l'attente d'une demande en ligne. Avec --internet mais hors ligne, rien non plus.
#[test]
fn listes_noires_en_json_sans_rien_envoyer() {
    let v = resultat_json(&["listes-noires", "--json"], "PRO-LNO-001", 60);
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
    let hors_ligne = resultat_json(&["listes-noires", "--json", "--internet"], "PRO-LNO-001", 60);
    assert_eq!(hors_ligne["couverture"]["verifies"], 0, "{hors_ligne}");
    assert_eq!(hors_ligne["constats"][0]["raison"], "refuse", "{hors_ligne}");
}
