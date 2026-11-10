//! Les essais de la campagne d'attaque du lot 1, repris comme tests : les invariants qu'aucune saisie ni aucune
//! sortie de `vanguard` ne doit pouvoir casser. Des écarts faibles qu'elle a constatés, partagés avec le terminal, les
//! espaces Unicode d'une autre largeur (A4) sont maintenant montrées comme une espace ordinaire (`nettoyage`) ; les
//! homoglyphes gardés (A5) et les espaces de queue retirées avant de juger un état (A6b) sont assumés, dits dans
//! MODELE-DE-MENACE.md, et ne sont pas figés ici.
//!
//! Lot 2a (B1 à B3) : le premier geste qui change l'ordinateur, un programme retiré du démarrage ou remis. Une
//! fenêtre prise (par ce qu'elle dessine) ou une sortie piégée ne doit pouvoir en faire qu'un changement de forme
//! fermée, `demarrage --retirer|--remettre <32 chiffres> --json`, dont Vanguard seul juge l'empreinte.

use crate::commandes::{self, Commande, Empreinte, Lancement, Saisie};
use crate::donnees::{appareils, bilan, evenements, libre, protection};

/// Un générateur fixe (même suite à chaque passage) : un échec se rejoue tel quel.
struct Suite(u64);

impl Suite {
    fn suivant(&mut self) -> u64 {
        // xorshift64
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn parmi<'a, T>(&mut self, choix: &'a [T]) -> &'a T {
        let i = usize::try_from(self.suivant() % choix.len() as u64).unwrap();
        &choix[i]
    }
}

/// A1 : quoi qu'on tape, une saisie acceptée est une commande de la liste fermée, lancée avec exactement
/// [sous-commande, "--json"], et le mot tapé est exactement l'un de ses noms : aucun argument ne vient de la saisie.
#[test]
fn aucune_saisie_ne_fabrique_un_argument() {
    let mut essais: Vec<String> = [
        "bilan; rm -rf ~",
        "bilan && corriger",
        "bilan --html",
        "protection --json non",
        "options-defense --rallumer pare-feu",
        "$(corriger)",
        "`corriger`",
        "bilan\u{0}",
        "bilan\ncorriger",
        "bilan\r\ncorriger",
        "--json",
        "vanguard vanguard bilan",
        "-- bilan",
        "bilan --",
        "biIan",
        "\u{0431}ilan",
        "ｂｉｌａｎ",
        "ʙilan",
        "bılan",
        "\u{202e}bilan",
        "bilan\u{200b}",
        "\u{feff}bilan",
        "bi\u{200b}lan",
    ]
    .map(String::from)
    .to_vec();
    let noms: Vec<&str> = Commande::TOUTES
        .iter()
        .flat_map(|c| [c.nom(), c.nom_anglais()])
        .collect();
    let morceaux = [
        "",
        " ",
        "\t",
        "\u{a0}",
        "\u{2028}",
        "\u{3000}",
        "\u{200b}",
        "\u{202e}",
        ";",
        "&",
        "|",
        "$(",
        "`",
        "--json",
        "--",
        "-x",
        "\n",
        "\r",
        "\0",
        "vanguard",
        "VANGUARD",
        "corriger",
        "é",
        "\u{1b}[2K",
    ];
    let mut s = Suite(0x5eed_f0e7_0001);
    for _ in 0..20_000 {
        let mut e = String::new();
        for _ in 0..=s.suivant() % 4 {
            if s.suivant().is_multiple_of(2) {
                e.push_str(s.parmi(&noms));
            } else {
                e.push_str(s.parmi(&morceaux));
            }
        }
        essais.push(e);
    }
    for e in &essais {
        if let Saisie::Lancer(c) = commandes::comprendre(e) {
            assert!(Commande::TOUTES.contains(&c), "{e:?}");
            // Une commande d'un autre système (les journaux de Windows sous Linux) ne se comprend pas ici.
            assert!(c.sur_ce_systeme(), "{e:?} -> {c:?}");
            let a = c.arguments();
            // La sous-commande et --json, ou la seule option qui lit (antivirus --etat) : jamais un mot tapé.
            assert!(a.len() == 2 || a == ["antivirus", "--etat", "--json"], "{e:?} -> {a:?}");
            assert_eq!(a.last(), Some(&"--json"), "{e:?}");
            assert!(
                a.iter().all(|m| m.bytes().all(|o| o.is_ascii_lowercase() || o == b'-')),
                "{e:?} -> {a:?}"
            );
            // Le seul mot gardé (après un « vanguard » permis) est un nom de cette commande, à la casse ASCII près.
            let mots: Vec<&str> = e.split_whitespace().collect();
            let mot = mots.last().unwrap().to_ascii_lowercase();
            assert!(mot == c.nom() || mot == c.nom_anglais(), "{e:?} -> {c:?}");
            assert!(
                mots.len() == 1 || (mots.len() == 2 && mots[0].eq_ignore_ascii_case("vanguard")),
                "{e:?}"
            );
        }
    }
}

/// Les lettres d'une autre écriture qui ressemblent à un nom de la liste ne lancent rien.
#[test]
fn un_nom_qui_ressemble_n_est_pas_un_nom() {
    for faux in [
        "\u{0431}ilan",
        "ｂｉｌａｎ",
        "biIan",
        "ʙilan",
        "bılan",
        "bilan\u{200b}",
        "\u{feff}bilan",
    ] {
        assert!(
            matches!(commandes::comprendre(faux), Saisie::Refusee(_)),
            "{faux:?} accepté"
        );
    }
}

/// A7 : un état que la fenêtre ne connaît pas (version future, faute, espace, piège) n'est jamais compté sain, et la
/// note d'un bilan qui en a se dit incomplète.
#[test]
fn un_etat_inconnu_n_est_jamais_sain() {
    let v = bilan::lire(br#"{"score": 100, "fiable": true, "constats": [{"categorie": "X", "etat": "tout-va-bien"}]}"#)
        .unwrap();
    assert_eq!(v.compte(bilan::Rang::Sain), 0);
    assert_eq!(v.compte(bilan::Rang::NonVerifie), 1);
    assert!(v.note_incomplete().is_some());
    for faux_sain in [
        "sain ",
        " sain",
        "Sain",
        "SAIN",
        "sain\u{200b}",
        "sain\u{a0}",
        "\u{feff}sain",
        "ѕain",
        "sain.",
        "",
    ] {
        let j = serde_json::json!({"constats": [{"categorie": "X", "etat": faux_sain}]});
        let v = bilan::lire(j.to_string().as_bytes()).unwrap();
        assert_eq!(v.compte(bilan::Rang::Sain), 0, "{faux_sain:?} compté sain");
    }
    // Un état d'un autre type (nombre, liste, objet, vrai) non plus.
    for etat in ["1", "true", "[\"sain\"]", "{\"sain\": 1}", "null"] {
        let j = format!(r#"{{"constats": [{{"categorie": "X", "etat": {etat}}}]}}"#);
        let v = bilan::lire(j.as_bytes()).unwrap();
        assert_eq!(v.compte(bilan::Rang::Sain), 0, "{etat} compté sain");
    }
}

/// Un interrupteur n'est jamais dit allumé par un texte qui n'est pas exactement le mot.
#[test]
fn un_interrupteur_n_est_jamais_faussement_allume() {
    for etat in [
        "activé\u{200b}",
        "activé\u{202e}",
        "ACTIVÉ",
        "aĉtivé",
        "allumé.",
        "\u{feff}allumé",
        "activé, en pause",
        "en pause (temps réel coupé)",
        "désactivé",
    ] {
        let j = serde_json::json!({"interrupteurs": [{"interrupteur": "x", "nom": "x", "etat": etat}]});
        let v = protection::lire(j.to_string().as_bytes()).unwrap();
        assert_ne!(v.interrupteurs[0].allure, protection::Allure::Allume, "{etat:?}");
    }
}

/// Un lecteur de sortie, nommé.
type Lecteur = (&'static str, fn(&[u8]));

/// A9 : JSON profond, énorme, mal formé, nombres hors bornes : chaque lecteur rend une erreur ou une vue bornée,
/// jamais une panique (attrapée ici pour nommer le lecteur et l'entrée), ni un débordement de pile (qui arrêterait
/// tout le banc).
#[test]
fn aucun_lecteur_ne_panique_sur_un_json_hostile() {
    let el = format!("{}1{}", "{\"a\":".repeat(100), "}".repeat(100));
    let corpus: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"{".to_vec(),
        b"[".to_vec(),
        b"\xff\xfe\x00".to_vec(),
        b"null".to_vec(),
        b"-0".to_vec(),
        br#"{"score": 1e400}"#.to_vec(),
        br#"{"score": -1}"#.to_vec(),
        br#"{"score": 18446744073709551615}"#.to_vec(),
        br#"{"constats": [{"niveau": 1e400}]}"#.to_vec(),
        br#"{"interrupteurs": NaN}"#.to_vec(),
        br#"{"evenements": [{"quoi": {"problemes": 1e400}}]}"#.to_vec(),
        br#"{"constats": "\ud800"}"#.to_vec(),
        format!("{}1{}", "{\"a\":".repeat(100_000), "}".repeat(100_000)).into_bytes(),
        "[".repeat(200_000).into_bytes(),
        "[{\"constats\":".repeat(5000).into_bytes(),
        "{\"interrupteurs\":[{\"etat\":".repeat(5000).into_bytes(),
        format!("{{\"constats\": [{}]}}", "0,".repeat(2_000_000)).into_bytes(),
        format!("{{\"constats\": [{}]}}", vec![el.as_str(); 4000].join(",")).into_bytes(),
        format!("{{\"evenements\": [{}]}}", vec![el.as_str(); 4000].join(",")).into_bytes(),
        format!("{{\"x\": \"{}\"}}", "é".repeat(1_000_000)).into_bytes(),
        // Les formes du scan et de l'audit du réseau : variantes inconnues, imbriquées, hors bornes.
        br#"{"upnp": {"Actif": {"redirections": [{"port_public": 1e400}], "ailleurs": 5}}}"#.to_vec(),
        br#"{"upnp": {"Actif": 1, "Absent": 2}, "empoisonnement": {"Teste": {"x": 1}}}"#.to_vec(),
        br#"{"hotes": [{"alertes": [[1e400, {"a": 1}, 3]], "ports": [{"port": -1}]}]}"#.to_vec(),
        format!(
            "{{\"upnp\": {}1{}}}",
            "{\"Actif\":".repeat(100_000),
            "}".repeat(100_000)
        )
        .into_bytes(),
        format!("{{\"hotes\": [{}]}}", vec![el.as_str(); 4000].join(",")).into_bytes(),
        format!(
            "{{\"domaines\": [{}]}}",
            vec!["{\"constats\": [0,0,0]}"; 100_000].join(",")
        )
        .into_bytes(),
        "{\"domaines\":[{\"constats\":".repeat(5000).into_bytes(),
    ];
    for s in &corpus {
        let apercu = String::from_utf8_lossy(&s[..s.len().min(40)]).into_owned();
        let lecteurs: [Lecteur; 6] = [
            ("bilan", |s| drop(bilan::lire(s))),
            ("audit-reseau", |s| drop(bilan::lire_audit_reseau(s))),
            ("appareils", |s| drop(appareils::lire(s))),
            ("protection", |s| drop(protection::lire(s))),
            ("evenements", |s| drop(evenements::lire(s))),
            ("libre", |s| drop(libre::lire(s))),
        ];
        for (nom, lire) in lecteurs {
            let r = std::panic::catch_unwind(|| lire(s));
            assert!(r.is_ok(), "panique de {nom} sur {apercu:?}");
        }
    }
    // La vue libre reste bornée, en lignes comme en profondeur.
    let large: Vec<u32> = (0..1_000_000).collect();
    let v = libre::lire(serde_json::json!({ "x": large }).to_string().as_bytes()).unwrap();
    assert_eq!(v.lignes.len(), libre::LIGNES_MAX);
    assert!(v.coupe);
}

/// La forme fermée d'un changement : quatre arguments, une option connue, 32 chiffres minuscules, --json.
fn forme_fermee(a: &[String]) -> bool {
    a.len() == 4
        && a[0] == "demarrage"
        && (a[1] == "--retirer" || a[1] == "--remettre")
        && a[2].len() == 32
        && a[2].bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f'))
        && a[3] == "--json"
}

/// B1 : une fenêtre prise peut demander n'importe quelle empreinte (le relais la lit comme un inconnu) ; elle n'en
/// fait jamais autre chose que la forme fermée. C'est Vanguard qui refuse une empreinte inconnue, à garder ou d'un
/// pare-feu (essais de `optimiser::demarrage` et de tests/programme.rs).
#[test]
fn une_fenetre_prise_ne_forme_qu_un_changement_ferme() {
    let mut suite = Suite(0x5eed_2a2a_0001);
    for _ in 0..5000 {
        let mut o = [0u8; 16];
        for x in &mut o {
            *x = u8::try_from(suite.suivant() & 0xff).unwrap();
        }
        let sorte = *suite.parmi(&[commandes::Sorte::Retirer, commandes::Sorte::Remettre]);
        let l = Lancement::Changement(commandes::Changement {
            sorte,
            empreinte: Empreinte::depuis_octets(o),
        });
        assert!(forme_fermee(&l.arguments()), "{:?}", l.arguments());
        assert_eq!(l.commande(), Commande::Demarrage);
    }
}

/// B2 : un nom ou une commande piégés dans la liste (séquence de terminal, sens d'écriture, option, chemin, fin de
/// ligne) n'atteignent jamais les arguments : seule l'empreinte part ; montrés, ils arrivent propres. Une empreinte
/// piégée (option, chemin, majuscules, chiffres d'une autre écriture, longueur voisine) ne donne pas de bouton.
#[test]
fn un_nom_piege_n_atteint_jamais_les_arguments() {
    let e = "0123456789abcdef0123456789abcdef";
    let pieges = [
        "Lecteur\\u001b]0;titre\\u0007",
        "Lecteur\\u202egpj.exe",
        "--remettre ffffffffffffffffffffffffffffffff",
        "Lecteur\\n--json",
        "/home/alice/.config/autostart/Lecteur.desktop; rm -rf ~",
    ];
    for nom in pieges {
        let json = format!(
            r#"{{"constats": [{{"etat": "sain", "message": "{nom}", "geste": {{"sorte": "retirer", "empreinte": "{e}", "nom": "{nom}", "commande": "{nom}"}}}}]}}"#
        );
        let v = bilan::lire(json.as_bytes()).unwrap();
        let g = v.constats[0].geste.clone().unwrap();
        let a = Lancement::Changement(g.changement).arguments();
        assert!(forme_fermee(&a), "{a:?}");
        assert_eq!(a[2], e);
        // Le nom et la commande tiennent sur une ligne ; le message peut en avoir plusieurs, rien d'autre.
        for t in [&g.nom, &g.commande] {
            assert!(
                t.chars().all(|c| c != '\n' && crate::nettoyage::rendu(c) == Some(c)),
                "{t:?} piégé"
            );
        }
        let m = &v.constats[0].message;
        assert!(
            m.chars().all(|c| c == '\n' || crate::nettoyage::rendu(c) == Some(c)),
            "{m:?} piégé"
        );
    }
    for faux in [
        "--retirer",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdef0",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcde\u{0660}",
        "０123456789abcdef0123456789abcde",
        "0123456789abcdef 123456789abcdef",
        "../../../../../etc/autostart/x.d",
        "0123456789abcdef0123456789abcde\n",
        "",
    ] {
        assert_eq!(Empreinte::lire(faux), None, "{faux:?}");
    }
}

/// B3 : la console ne lance aucun changement, sous aucune forme tapée (le changement n'existe que par un clic,
/// confirmé dans la fenêtre).
#[test]
fn la_console_ne_lance_aucun_changement() {
    let e = "0123456789abcdef0123456789abcdef";
    let mut suite = Suite(0x5eed_2a2a_0003);
    let morceaux = [
        "demarrage",
        "startup",
        "--retirer",
        "--remove",
        "--remettre",
        "--put-back",
        e,
        "--json",
        "retirer",
        "remettre",
        ";",
        "&&",
        "\u{a0}",
        "=",
    ];
    for _ in 0..5000 {
        let n = 1 + usize::try_from(suite.suivant() % 4).unwrap();
        let mots: Vec<&str> = (0..n).map(|_| *suite.parmi(&morceaux)).collect();
        let saisie = mots.join(" ");
        match commandes::comprendre(&saisie) {
            Saisie::Lancer(c) => {
                // Une commande de la liste, jamais une option de changement ni une empreinte.
                assert!(
                    c.arguments()
                        .iter()
                        .all(|x| !matches!(*x, "--retirer" | "--remettre") && *x != e),
                    "{saisie:?}"
                );
            }
            Saisie::Refusee(_) | Saisie::Rien | Saisie::Aide | Saisie::AideSur(_) | Saisie::Effacer => {}
        }
    }
}
