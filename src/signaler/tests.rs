//! Les tests de l'assistant de signalement : valeurs inventées (alice, Zoé, DESKTOP-AB12, préfixes MAC gardés) et
//! dossiers jetables.

use super::brouillon::{self, Kev, Masque, Reponses};
use super::garde::Sorte;
use super::programmes::{Langue, PROGRAMMES, Programme};
use super::tri::Sujet;
use super::*;
use crate::modele::evenement::{Evenement, Genre, Source};
use crate::modele::journal::Lecture;
use crate::modele::resultat::{ConstatEcrit, Couverture, Resultat};
use crate::protection::preuve::{Fichier, Preuve, Processus};
use proptest::prelude::*;
use std::fmt::Write as _;

/// Les sources du module, sans leurs tests (ce fichier) : le code qui tourne.
fn sources() -> Vec<(String, String)> {
    let dossier = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/signaler");
    let mut v = Vec::new();
    for e in std::fs::read_dir(&dossier).unwrap().flatten() {
        let p = e.path();
        let nom = p.file_name().unwrap().to_string_lossy().to_string();
        if nom == "tests.rs" || p.extension().is_none_or(|x| x != "rs") {
            continue;
        }
        let texte = std::fs::read_to_string(&p).unwrap();
        let code = texte.find("#[cfg(test)]\nmod ").map_or(texte.as_str(), |t| &texte[..t]);
        // Sans les commentaires : ils parlent des chemins interdits pour dire pourquoi.
        let code = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .fold(String::new(), |mut tout, l| {
                let _ = writeln!(tout, "{l}");
                tout
            });
        v.push((nom, code));
    }
    assert!(v.len() >= 6, "{} fichiers lus seulement", v.len());
    v
}

/// T5 (1) : aucun code réseau dans le module, ni courriel prêt à partir. Pas le mot « http » seul : les adresses
/// https:// de la liste des programmes le feraient échouer à tort.
#[test]
fn aucun_reseau_dans_le_module() {
    // Écrits en morceaux : ce fichier-ci n'est pas lu, mais un outil qui cherche ces mots dans le dépôt les verrait.
    let interdits = [
        concat!("crate::", "http"),
        concat!("req", "west"),
        concat!("std::", "net"),
        concat!("Tcp", "Stream"),
        concat!("Udp", "Socket"),
        concat!("mail", "to:"),
        concat!("arb", "oard"),
        "wl-copy",
        "pbcopy",
        "clip.exe",
    ];
    for (nom, code) in sources() {
        for i in interdits {
            assert!(!code.contains(i), "{nom} contient « {i} »");
        }
    }
}

/// T5 (2) : le catalogue KEV n'est lu que dans sa copie gardée (`catalogue_selon(Some(…))`) ; `catalogue()` et
/// `exploitees()` le téléchargent quand la copie a plus d'un jour.
#[test]
fn kev_lu_sans_telechargement() {
    let tout: String = sources().into_iter().map(|(_, c)| c).collect();
    assert!(!tout.contains(concat!("kev::catalogue", "(")));
    assert!(!tout.contains(concat!("exploitees", "(")));
    assert!(tout.contains(concat!("catalogue_selon(Some", "(")));
}

/// Les chemins `crate::…` d'un code, les groupes « crate::a::{b, c} » dépliés (un niveau).
fn chemins_crate(code: &str) -> Vec<String> {
    let mut v = Vec::new();
    for (i, _) in code.match_indices("crate::") {
        let reste = &code[i..];
        let chemin: String = reste
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':' || *c == '*')
            .collect();
        let chemin = chemin.trim_end_matches(':').to_string();
        let apres = &reste[chemin.len()..];
        if let Some(groupe) = apres.strip_prefix("::{") {
            let fin = groupe.find('}').expect("groupe non fermé");
            for membre in groupe[..fin].split(',') {
                let m = membre.trim();
                if !m.is_empty() {
                    v.push(format!("{chemin}::{}", m.split_whitespace().next().unwrap()));
                }
            }
        } else {
            v.push(chemin);
        }
    }
    v
}

/// T5 (3) : la liste fermée de ce que le module a le droit d'appeler. Un appel indirect au réseau ne contient pas le
/// mot « http » (le catalogue KEV se télécharge par `catalogue()`) : seule une liste blanche le voit. Un ajout ici se
/// décide en relisant ce que la fonction appelle.
#[test]
fn liste_fermee_des_appels() {
    const PERMIS: &[&str] = &[
        "crate::modele::Echec",
        "crate::modele::evenement::Evenement",
        "crate::modele::evenement::Genre",
        "crate::modele::evenement::Source",
        "crate::modele::evenement::Source::Analyse",
        "crate::modele::evenement::borne",
        "crate::modele::journal::Lecture",
        "crate::modele::journal::Lu",
        "crate::modele::journal::lire",
        "crate::modele::journal::incident",
        "crate::modele::journal::alertes",
        "crate::modele::journal::noter",
        "crate::modele::resultat::Resultat",
        "crate::modele::resultat::sans_piege",
        "crate::modele::resultat::nom_sans_piege",
        "crate::modele::resultat::derniers",
        "crate::modele::resultat::AVEC_RESULTAT",
        "crate::modele::registre::OUTILS",
        "crate::journal::anonymiser",
        "crate::journal::noms_a_retirer",
        "crate::journal::systeme",
        "crate::protection::kev::catalogue_selon",
        "crate::socle::dossier_local",
        "crate::socle::ecrire_atomique",
        "crate::socle::ecriture_sure",
        "crate::selection::Ligne",
        "crate::selection::choisir",
        "crate::ui::*",
        "crate::langue::anglais",
        "crate::langue::oui",
        "crate::machine::ouvrir",
        "crate::risk::Niveau::Moyen",
        "crate::risk::Niveau::Critique",
        "crate::risk::Niveau::Eleve",
        "crate::risk::Niveau",
        "crate::tr",
        "crate::trf",
        "crate::trp",
    ];
    let mut hors_liste = Vec::new();
    let mut vus = 0;
    for (nom, code) in sources() {
        for c in chemins_crate(&code) {
            vus += 1;
            if !PERMIS.contains(&c.as_str()) {
                hors_liste.push(format!("{nom} : {c}"));
            }
        }
    }
    assert!(vus > 20, "{vus} chemins seulement : la lecture ne trouve plus rien");
    assert_eq!(hors_liste, Vec::<String>::new());
}

#[test]
fn les_groupes_sont_deplies() {
    assert_eq!(
        chemins_crate("use crate::a::{b, c as d};\ncrate::e::f();"),
        ["crate::a::b", "crate::a::c", "crate::e::f"]
    );
}

fn quand(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

/// Un masquage d'essai : celui du journal des erreurs, plus des noms que cet ordinateur ne connaît pas (la machine
/// et le réseau inventés).
fn anonymiser_essai(t: &str) -> String {
    let noms = vec![
        ("DESKTOP-AB12".to_string(), "<machine>"),
        ("Salon-Zoé".to_string(), "<réseau>"),
    ];
    crate::journal::anonymiser(&crate::journal::sans_noms_avec(t, &noms))
}

fn masque_essai(maisons: &[String]) -> Masque<'_> {
    Masque {
        maisons,
        anonymiser: &anonymiser_essai,
    }
}

fn ctx(journal: Option<Lecture>) -> Contexte {
    Contexte {
        systeme: "Arch Linux 6.17.2".into(),
        journal,
        kev: None,
    }
}

fn reponses() -> Reponses {
    Reponses {
        produit: "Firefox 132.0".into(),
        fait: "Ouvrir la page".into(),
        vu: "Le processus plante".into(),
        attendu: "Rien".into(),
        impact: String::new(),
        preuve: "page jointe".into(),
        ..Reponses::default()
    }
}

fn une_alerte(titre: &str, texte: &str) -> Evenement {
    Evenement::le(
        Source::Surveillance,
        Genre::Alerte {
            famille: "machine".into(),
            titre: titre.into(),
            texte: texte.into(),
        },
        quand("2026-10-23T10:00:00Z"),
    )
}

fn preuve(chemin: &str, programme: &str, compte: &str, ligne: &str) -> Evenement {
    Evenement::le(
        Source::Blocage,
        Genre::Preuve {
            releve: Preuve {
                date: "2026-10-23 10:00:01".into(),
                processus: Some(Processus {
                    pid: 4242,
                    parent: Some(1),
                    programme: Some(programme.into()),
                    ligne: Some(ligne.into()),
                    compte: Some(compte.into()),
                }),
                fichier: Some(Fichier {
                    chemin: chemin.into(),
                    sha256: Some("ab".repeat(32)),
                    taille: Some(1234),
                }),
                connexions: vec![
                    "203.0.113.7:443 (PID 4242, x)".into(),
                    "203.0.113.8:443 (PID 4242, x)".into(),
                ],
                impossible: Vec::new(),
            },
        },
        quand("2026-10-23T10:00:01Z"),
    )
}

fn incident(fil: Vec<Evenement>) -> Sujet {
    Sujet::Incident {
        choisi: Box::new(fil[0].clone()),
        fil,
        omis: 0,
    }
}

fn markdown(sujet: &Sujet, r: &Reponses, journal: Option<Lecture>, p: Programme) -> String {
    let maisons = vec!["/home/alice".to_string()];
    let b = brouillon::assembler(p.fiche(), Langue::En, sujet, r, &ctx(journal), &masque_essai(&maisons));
    brouillon::en_markdown(&b)
}

/// Les valeurs personnelles inventées, et ce qui ne doit plus se lire après masquage.
const PERSONNELLES: &[(&str, &str)] = &[
    ("/home/alice/projet/notes.txt", "alice"),
    (r"C:\Users\Zoé\Desktop\x.txt", "Zoé"),
    ("DESKTOP-AB12", "desktop-ab12"),
    ("S-1-5-21-1004336348-1177238915-682003330-1001", "1004336348"),
    ("bob.martin@example.com", "bob.martin"),
    ("3c:22:fb:12:34:56", "12:34:56"),
    ("81.12.34.56", "81.12.34.56"),
    ("2a01:e0a:2b3:4c50:1234:5678:9abc:def0", "2a01:e0a"),
    ("Salon-Zoé", "salon-zoé"),
    ("https://exemple.example/compte?session=abc123", "session=abc123"),
];

proptest! {
    /// T2 : chaque valeur personnelle, glissée dans n'importe quel champ du fil (titre, texte, chemin de la preuve,
    /// programme) ou d'un examen, ne se retrouve pas dans le brouillon.
    #[test]
    fn rien_de_personnel_dans_le_brouillon(places in proptest::collection::vec(0usize..5, PERSONNELLES.len()),
                                          bruit in "[a-z ]{0,12}") {
        let mut champs = vec![String::new(); 5];
        for ((valeur, _), place) in PERSONNELLES.iter().zip(&places) {
            let _ = writeln!(champs[*place], " {bruit} {valeur} ");
        }
        let fil = vec![
            une_alerte(&champs[0], &champs[1]),
            preuve(&champs[2], &champs[3], "root", "x"),
        ];
        let examen = Sujet::Examen(Box::new(Resultat {
            outil: "PRO-ESP-001".into(),
            schema: 1,
            debut: "2026-10-23T10:00:00Z".into(),
            duree_ms: 1,
            couverture: Couverture { verifies: 3, non_verifies: Vec::new() },
            constats: vec![ConstatEcrit {
                regle: "PRO-ESP-001".into(),
                objet: None,
                categorie: "x".into(),
                etat: "probleme".into(),
                niveau: None,
                raison: None,
                message: champs[4].clone(),
                corrigeable: false,
            }],
        }));
        for sujet in [incident(fil), examen] {
            let md = markdown(&sujet, &reponses(), Some(Lecture::Intact), Programme::Msrc).to_lowercase();
            for (_, trace) in PERSONNELLES {
                prop_assert!(!md.contains(&trace.to_lowercase()), "{} dans :\n{}", trace, md);
            }
        }
    }
}

/// T16 : la preuve réduite. Ni la ligne de commande (un jeton), ni le compte d'un proche, ni le nom complet d'un nom
/// de fichier personnel ; une adresse web perd sa requête et son fragment.
#[test]
fn preuve_reduite() {
    let fil = vec![
        preuve(
            "/home/alice/Documents/CV-Zoé-Martin.pdf",
            "/usr/bin/curl",
            "bob",
            "curl --token=SECRET https://203.0.113.9/x?session=abc#k",
        ),
        une_alerte("Lien", "vu https://203.0.113.9/x?session=abc#k"),
    ];
    let md = markdown(&incident(fil), &reponses(), Some(Lecture::Intact), Programme::Mozilla);
    for absent in ["SECRET", "bob", "Zoé-Martin", "session=abc", "#k", "PID 4242"] {
        assert!(!md.contains(absent), "{absent} dans :\n{md}");
    }
    for present in [
        "<fichier>.pdf",
        "/usr/bin/curl",
        "<compte>",
        "2 connection(s) ; ports 443",
        "https://203.0.113.9/x",
    ] {
        assert!(md.contains(present), "{present} manque :\n{md}");
    }
}

/// T3 : un masquage raté (anonymiser court-circuité) est attrapé par le contrôle final : `Err`, aucun fichier écrit,
/// et le message nomme la sorte de donnée, jamais sa valeur.
#[test]
fn controle_final_attrape_un_masquage_rate() {
    let maisons: Vec<String> = Vec::new();
    let rien = |t: &str| t.to_string();
    let m = Masque {
        maisons: &maisons,
        anonymiser: &rien,
    };
    let sujet = incident(vec![une_alerte("Sur DESKTOP-AB12", "x")]);
    let b = brouillon::assembler(Programme::Msrc.fiche(), Langue::En, &sujet, &reponses(), &ctx(None), &m);
    let connues = vec![("DESKTOP-AB12".to_string(), Sorte::Machine)];
    let sortes = finaliser(&b, &connues).unwrap_err();
    assert_eq!(sortes, [Sorte::Machine]);
    let message = refus(&sortes).to_string();
    assert!(
        !message.contains("AB12") && message.contains(&Sorte::Machine.nom()),
        "{message}"
    );
    // Le même brouillon masqué passe.
    let maisons = vec!["/home/alice".to_string()];
    let b = brouillon::assembler(
        Programme::Msrc.fiche(),
        Langue::En,
        &sujet,
        &reponses(),
        &ctx(None),
        &masque_essai(&maisons),
    );
    assert!(finaliser(&b, &connues).is_ok());
}

/// T6 : un journal falsifié, incomplet ou adopté se dit non vérifié ou non prouvé, jamais intact ; un examen falsifié
/// (relu par `resultat::derniers` sans aucun constat) n'en fournit aucun.
#[test]
fn honnetete_sur_l_etat_du_journal() {
    let sujet = incident(vec![une_alerte("Port", "8080")]);
    for (l, attendu) in [
        (Lecture::Falsifie("ligne 3".into()), "not verified"),
        (Lecture::Incomplet("fin".into()), "not proven"),
        (Lecture::Adopte, "not proven"),
    ] {
        let md = markdown(&sujet, &reponses(), Some(l), Programme::Ghsa);
        assert!(md.contains(attendu) && !md.contains("intact"), "{md}");
    }
    assert!(markdown(&sujet, &reponses(), Some(Lecture::Intact), Programme::Ghsa).contains("Event log: intact"));
    let falsifie = Resultat {
        outil: "PRO-ESP-001".into(),
        schema: 1,
        debut: "2026-10-23T10:00:00Z".into(),
        duree_ms: 0,
        couverture: Couverture {
            verifies: 0,
            non_verifies: vec!["non vérifié : résultat changé hors de Vanguard".into()],
        },
        constats: Vec::new(),
    };
    let md = markdown(&Sujet::Examen(Box::new(falsifie)), &reponses(), None, Programme::Ghsa);
    assert!(
        md.contains("verdict: non-verifie") && md.contains("changé hors de Vanguard"),
        "{md}"
    );
    assert!(!md.contains("\n- probleme"), "{md}");
}

/// T7 : le brouillon de chaque programme contient chacune de ses rubriques, remplie ou « à compléter ».
#[test]
fn chaque_programme_a_toutes_ses_rubriques() {
    for f in PROGRAMMES {
        for l in [Langue::Fr, Langue::En] {
            let maisons: Vec<String> = Vec::new();
            let b = brouillon::assembler(
                f,
                l,
                &Sujet::Rien,
                &Reponses::default(),
                &ctx(None),
                &masque_essai(&maisons),
            );
            let md = brouillon::en_markdown(&b);
            for c in f.champs {
                assert!(md.contains(&format!("## {}\n", c.titre(l))), "{} : {:?}", f.id, c);
            }
            assert!(md.contains(f.adresse) && md.contains(l.t("Préparé avec Vanguard", "Prepared with Vanguard")));
            // Aucun score inventé.
            assert!(!md.contains("CVSS") && !md.contains("CWE-"), "{}", f.id);
        }
    }
}

/// T8 : sans « ce que tu as fait » ni « ce qui s'est passé », le titre porte INCOMPLET ; MSRC, Apple et Chrome
/// restent incomplets sans preuve de concept.
#[test]
fn incomplet_tant_qu_il_manque_l_essentiel() {
    let vide = markdown(&Sujet::Rien, &Reponses::default(), None, Programme::Ghsa);
    assert!(vide.starts_with("# INCOMPLETE — "), "{vide}");
    let complet = markdown(&Sujet::Rien, &reponses(), None, Programme::Ghsa);
    assert!(complet.starts_with("# Vulnerability report draft"), "{complet}");
    let sans_preuve = Reponses {
        preuve: String::new(),
        ..reponses()
    };
    for p in [Programme::Msrc, Programme::Apple, Programme::Chrome] {
        assert!(
            markdown(&Sujet::Rien, &sans_preuve, None, p).starts_with("# INCOMPLETE"),
            "{p:?}"
        );
    }
    assert!(markdown(&Sujet::Rien, &sans_preuve, None, Programme::Mozilla).starts_with("# Vulnerability"));
}

/// T9 : un fil de 500 événements est coupé à 50, et le brouillon dit combien sont omis ; un texte de 1 Mo est borné.
#[test]
fn bornes() {
    let fil: Vec<Evenement> = (0..500).map(|i| une_alerte(&format!("alerte {i}"), "x")).collect();
    let maisons: Vec<String> = Vec::new();
    let b = brouillon::assembler(
        Programme::Ghsa.fiche(),
        Langue::En,
        &incident(fil),
        &reponses(),
        &ctx(None),
        &masque_essai(&maisons),
    );
    assert_eq!(b.observations.len(), brouillon::FIL_MAX);
    assert_eq!(b.omis, 450);
    assert!(brouillon::en_markdown(&b).contains("450 event(s) of the thread left out"));
    let enorme = Reponses {
        fait: "a".repeat(1 << 20),
        ..reponses()
    };
    let md = markdown(&Sujet::Rien, &enorme, None, Programme::Ghsa);
    assert!(md.len() < 40_000, "{} octets", md.len());
}

/// T4 : un nom de fichier piégé ne notifie personne, ne charge aucune image et ne ferme pas son bloc de code ; une
/// réponse piégée est neutralisée ; les caractères de contrôle, bidi et OSC 52 deviennent « � ».
#[test]
fn injection_markdown() {
    let piege = "x```@bob <img src=x> [x](y) \u{202e}fdp.exe \u{1b}]52;c;eA==\u{7}";
    let fil = vec![une_alerte(piege, "# titre | a")];
    let r = Reponses {
        vu: "@bob <img src=x> ![i](y)\n# titre".into(),
        ..reponses()
    };
    let md = markdown(&incident(fil), &r, None, Programme::Ghsa);
    assert!(
        !md.contains('\u{202e}') && !md.contains('\u{1b}') && !md.contains('\u{7}'),
        "{md}"
    );
    // Hors des blocs de code, aucune mention, image, lien ni titre venus de l'extérieur.
    let mut dans_bloc: Option<String> = None;
    for ligne in md.lines() {
        if let Some(c) = &dans_bloc {
            if ligne == c {
                dans_bloc = None;
            }
            continue;
        }
        if ligne.starts_with("```") {
            dans_bloc = Some(ligne.to_string());
            continue;
        }
        let sans = ligne
            .replace("\\\\", "")
            .replace("\\@", "")
            .replace("\\<", "")
            .replace("\\[", "")
            .replace("\\!", "")
            .replace("\\#", "");
        assert!(
            !sans.contains("@bob") && !sans.contains("<img") && !sans.contains("[x]") && !sans.contains("!["),
            "{ligne}"
        );
        assert!(!ligne.starts_with("# titre"), "{ligne}");
    }
    assert!(dans_bloc.is_none(), "un bloc n'est pas fermé :\n{md}");
}

/// Un dossier jetable à soi, sous le dossier temporaire.
fn jetable(nom: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vanguard-signaler-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// T10 : refus quand l'écriture n'est pas sûre ; fichier en 0600 dans un dossier en 0700 ; nom sans rien venu de
/// l'extérieur ; rien n'est écrasé ; `--effacer` ne touche que les `.md` de `signalements`.
#[test]
fn ecriture_et_effacement() {
    let d = jetable("ecrire");
    assert!(ecrire_dans(&d, "a.md", "x", false).is_err());
    assert!(!d.join(DOSSIER).exists());
    let nom = nom_de_fichier(
        chrono::DateTime::parse_from_rfc3339("2026-10-23T14:05:09+02:00")
            .unwrap()
            .with_timezone(&chrono::Local),
        Programme::Msrc.fiche(),
    );
    assert!(
        nom.ends_with("-msrc.md") && nom.len() == "20261023-140509-msrc.md".len(),
        "{nom}"
    );
    let a = ecrire_dans(&d, &nom, "un", true).unwrap();
    let b = ecrire_dans(&d, &nom, "deux", true).unwrap();
    assert_ne!(a, b);
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "un");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(d.join(DOSSIER)).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    std::fs::write(d.join(DOSSIER).join("autre.txt"), "garde").unwrap();
    assert_eq!(nombre_dans(&d), 2);
    assert_eq!(effacer_liste(&brouillons_dans(&d)).unwrap(), 2);
    assert_eq!(nombre_dans(&d), 0);
    assert!(d.join(DOSSIER).join("autre.txt").exists());
    // `signalements` remplacé par un lien : rien n'est écrit à travers.
    #[cfg(unix)]
    {
        let l = jetable("lien");
        let cible = jetable("cible");
        std::os::unix::fs::symlink(&cible, l.join(DOSSIER)).unwrap();
        assert!(ecrire_dans(&l, "a.md", "x", true).is_err());
        assert_eq!(std::fs::read_dir(&cible).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&l);
        let _ = std::fs::remove_dir_all(&cible);
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// T11 : le geste noté au journal : source Utilisateur, la cause et la clé de l'incident, jamais le texte du rapport.
#[test]
fn geste_au_journal() {
    let d = jetable("journal");
    let a = une_alerte("Port", "8080").cle(Some("port|8080"));
    let sujet = incident(vec![a.clone()]);
    let e = geste(Programme::Msrc.fiche(), &sujet);
    crate::modele::journal::noter_dans(&d, e, chrono::Utc::now()).unwrap();
    let lu = crate::modele::journal::lire_dans(&d);
    let note = lu
        .evenements
        .iter()
        .find(|e| matches!(e.quoi, Genre::Action { .. }))
        .unwrap();
    assert_eq!(note.source, Source::Utilisateur);
    assert_eq!(note.cause.as_deref(), Some(a.id.as_str()));
    assert_eq!(note.cle.as_deref(), Some("port|8080"));
    let Genre::Action { quoi, commandes, .. } = &note.quoi else {
        panic!()
    };
    assert!(quoi.contains("Microsoft (MSRC)") && commandes.is_empty(), "{quoi}");
    let _ = std::fs::remove_dir_all(&d);
}

/// T12 : les chemins de Windows et de macOS sont masqués, comme ceux de Linux.
#[test]
fn chemins_windows_et_macos() {
    let fil = vec![preuve(
        r"C:\Users\Zoé\Downloads\facture.exe",
        "/Users/alice/Applications/x.app",
        "Zoé",
        "x",
    )];
    let md = markdown(&incident(fil), &reponses(), None, Programme::Apple);
    assert!(!md.contains("Zoé") && !md.contains("alice"), "{md}");
    assert!(
        md.contains(r"~\…\<fichier>.exe") && md.contains("~/…/<fichier>.app"),
        "{md}"
    );
}

/// Une faille connue signalée quand même : c'est dit, avec ce qu'en dit le catalogue de la CISA, ou « non vérifié ».
#[test]
fn faille_connue_signalee_quand_meme() {
    let r = Reponses {
        outre_connue: vec!["CVE-2026-0001".into()],
        ..reponses()
    };
    let maisons: Vec<String> = Vec::new();
    for (kev, attendu) in [
        (
            Some(Kev::Exploitees(vec!["CVE-2026-0001".into()])),
            "In CISA's KEV catalog (exploited): CVE-2026-0001",
        ),
        (
            Some(Kev::NonVerifie("absente".into())),
            "CISA's KEV catalog: not checked",
        ),
    ] {
        let c = Contexte { kev, ..ctx(None) };
        let b = brouillon::assembler(
            Programme::Mozilla.fiche(),
            Langue::En,
            &Sujet::Rien,
            &r,
            &c,
            &masque_essai(&maisons),
        );
        let md = brouillon::en_markdown(&b);
        assert!(
            md.contains("Already known flaw, reported anyway") && md.contains(attendu),
            "{md}"
        );
    }
}

/// Le JSON d'un sujet que le tri écarte n'a pas de brouillon ; celui d'un rapport à écrire en a un, incomplet.
#[test]
fn json_selon_le_tri() {
    let lu = Lu {
        lecture: Lecture::Falsifie("x".into()),
        evenements: Vec::new(),
        illisibles: 0,
    };
    let bot = Evenement::alerte(Source::Surveillance, "botnet", "Serveur", "203.0.113.7:443");
    let v = en_json(&lu, &incident(vec![bot]), Some(Programme::Msrc), None);
    assert_eq!(v["tri"]["sorte"], "malveillant");
    assert!(v["brouillon"].is_null());
    let v = en_json(
        &lu,
        &incident(vec![une_alerte("Port", "8080")]),
        Some(Programme::Msrc),
        None,
    );
    assert_eq!(v["etat_journal"], "falsifie");
    assert_eq!(v["programme"], "msrc");
    assert_eq!(v["langue"], "en");
    assert_eq!(v["incomplet"], true);
    assert_eq!(v["ecrit"], false);
    let texte = v["brouillon"].as_str().unwrap();
    assert!(
        texte.contains("not verified") && texte.starts_with("# INCOMPLETE"),
        "{texte}"
    );
}

/// Les textes du menu tiennent dans la largeur (précisions de 33 caractères au plus).
#[test]
fn textes_dans_la_largeur() {
    let source =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/signaler/mod.rs")).unwrap();
    assert_eq!(crate::ui::textes_trop_larges(&source), Vec::<String>::new());
}

fn constat(etat: &str, niveau: Option<crate::risk::Niveau>, message: &str) -> ConstatEcrit {
    ConstatEcrit {
        regle: "PRO-PER-001".into(),
        objet: None,
        categorie: "x".into(),
        etat: etat.into(),
        niveau,
        raison: None,
        message: message.into(),
        corrigeable: false,
    }
}

/// Un examen des logiciels périmés nomme chaque logiciel installé : le brouillon n'en garde que le produit touché
/// par la faille exploitée (constat critique) et le compte des points non vérifiés, jamais l'inventaire.
#[test]
fn examen_des_perimes_sans_inventaire() {
    use crate::risk::Niveau;
    let r = Resultat {
        outil: "PRO-PER-001".into(),
        schema: 1,
        debut: "2026-10-23T10:00:00Z".into(),
        duree_ms: 1,
        couverture: Couverture {
            verifies: 4,
            non_verifies: vec!["Slack — version illisible".into()],
        },
        constats: vec![
            constat(
                "probleme",
                Some(Niveau::Critique),
                "Microsoft Edge 120 : CVE-2026-0001 exploitée (KEV)",
            ),
            constat(
                "probleme",
                Some(Niveau::Moyen),
                "2 logiciel(s) pas à jour : PuTTY — dernière : 0.99 ; 7-Zip — dernière : 99.0.",
            ),
            constat("non-verifie", None, "Impossible de lire : Tor Browser"),
        ],
    };
    let md = markdown(&Sujet::Examen(Box::new(r)), &reponses(), None, Programme::Msrc);
    assert!(
        md.contains("Microsoft Edge") && md.contains("not checked: 1 item(s)"),
        "{md}"
    );
    for absent in ["PuTTY", "7-Zip", "Slack", "Tor Browser"] {
        assert!(!md.contains(absent), "{absent} dans :\n{md}");
    }
}

/// Le diagnostic et les connexions sortantes nomment aussi l'inventaire (programmes plantés, sources du journal,
/// programmes et leurs serveurs) : seuls les constats élevés ou plus partent, et le compte des points non vérifiés.
#[test]
fn diagnostic_et_sortantes_sans_inventaire() {
    use crate::risk::Niveau;
    let examen = |outil: &str, constats: Vec<ConstatEcrit>| Resultat {
        outil: outil.into(),
        schema: 1,
        debut: "2026-10-23T10:00:00Z".into(),
        duree_ms: 1,
        couverture: Couverture {
            verifies: 3,
            non_verifies: vec!["Services en échec : bus-maison illisible".into()],
        },
        constats,
    };
    let diagnostic = examen(
        "PRO-DIA-001",
        vec![
            constat("probleme", Some(Niveau::Eleve), "Écrans bleus : 2 en 30 jours"),
            constat(
                "probleme",
                Some(Niveau::Moyen),
                "Programmes plantés : 3 en 7 jours : outil-secret (2), Signal (1)",
            ),
            constat("non-verifie", None, "Erreurs du journal : nextdns illisible"),
        ],
    );
    let md = markdown(&Sujet::Examen(Box::new(diagnostic)), &reponses(), None, Programme::Msrc);
    assert!(
        md.contains("Écrans bleus") && md.contains("not checked: 1 item(s)"),
        "{md}"
    );
    for absent in ["outil-secret", "Signal", "nextdns", "bus-maison"] {
        assert!(!md.contains(absent), "{absent} dans :\n{md}");
    }
    let sortantes = examen(
        "PRO-SOR-001",
        vec![
            constat(
                "probleme",
                Some(Niveau::Eleve),
                "facture → 203.0.113.7:443 : serveur de commande de botnet connu",
            ),
            constat("probleme", Some(Niveau::Moyen), "Signal → 198.51.100.4:443 : non signé"),
        ],
    );
    let md = markdown(&Sujet::Examen(Box::new(sortantes)), &reponses(), None, Programme::Msrc);
    assert!(md.contains("203.0.113.7") && !md.contains("Signal"), "{md}");
}

/// Sans CVE citée, le catalogue KEV n'a rien cherché : jamais « absente du catalogue », même avec une copie gardée.
#[test]
fn kev_sans_cve_non_verifie() {
    let copie = || Ok(vec!["CVE-2026-0001".to_string()]);
    assert!(matches!(kev_selon(&[], copie()), Kev::NonVerifie(_)));
    assert_eq!(
        kev_selon(&["CVE-2026-0002".into()], copie()),
        Kev::Exploitees(Vec::new())
    );
    let r = Reponses {
        outre_connue: vec!["CVE ?".into()],
        ..reponses()
    };
    let c = Contexte {
        kev: Some(kev_selon(&[], copie())),
        ..ctx(None)
    };
    let maisons: Vec<String> = Vec::new();
    let b = brouillon::assembler(
        Programme::Mozilla.fiche(),
        Langue::En,
        &Sujet::Rien,
        &r,
        &c,
        &masque_essai(&maisons),
    );
    let md = brouillon::en_markdown(&b);
    assert!(
        !md.contains("Not in CISA's KEV") && md.contains("CISA's KEV catalog: not checked"),
        "{md}"
    );
}

/// Le tri d'un incident tiré d'un journal non vérifié le dit avant de trancher ; pas pour un journal intact ni pour
/// un examen.
#[test]
fn tri_d_un_journal_non_verifie_averti() {
    let sujet = incident(vec![une_alerte("Port", "8080")]);
    for l in [
        Lecture::Falsifie("x".into()),
        Lecture::Incomplet("x".into()),
        Lecture::Adopte,
    ] {
        let a = avertissement_journal(&l, &sujet).unwrap();
        assert!(a.contains(tr!("non vérifié", "not verified")), "{a}");
    }
    assert!(avertissement_journal(&Lecture::Intact, &sujet).is_none());
    assert!(avertissement_journal(&Lecture::Falsifie("x".into()), &Sujet::Rien).is_none());
}

/// Un fil plus long que 50 : l'événement choisi par la personne reste dans ce qui est gardé, même en dernier.
#[test]
fn le_choix_reste_dans_le_fil_coupe() {
    let fil: Vec<Evenement> = (0..61).map(|i| une_alerte(&format!("alerte {i}"), "x")).collect();
    let choisi = fil[60].clone();
    let sujet = Sujet::Incident {
        choisi: Box::new(choisi),
        fil,
        omis: 0,
    };
    let maisons: Vec<String> = Vec::new();
    let b = brouillon::assembler(
        Programme::Ghsa.fiche(),
        Langue::En,
        &sujet,
        &reponses(),
        &ctx(None),
        &masque_essai(&maisons),
    );
    assert_eq!(b.observations.len(), brouillon::FIL_MAX);
    assert_eq!(b.omis, 11);
    assert!(
        b.observations.last().unwrap().contenu.contains("alerte 60"),
        "{:?}",
        b.observations.last()
    );
}
