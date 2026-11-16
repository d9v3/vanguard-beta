//! La console de la fenêtre (fenetre/src/commandes.rs) et son nettoyage (fenetre/src/nettoyage.rs) : quoi qu'on tape
//! ou colle, seule une commande de la liste fermée se lance, toujours avec ses propres arguments en JSON, jamais un
//! morceau du texte tapé ; un refus redit le texte nettoyé, sur une ligne, borné. Chaque nettoyage rend un texte
//! borné, sans caractère piégé, qu'un second passage ne change plus. Les suggestions restent dans la liste, bornées.
//! Le premier octet choisit la langue.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (fenetre/src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../fenetre/src/langue.rs"]
mod langue;

#[allow(dead_code)]
#[path = "../../fenetre/src/nettoyage.rs"]
mod nettoyage;

#[allow(dead_code)]
#[path = "../../fenetre/src/couleurs.rs"]
mod couleurs;

#[allow(dead_code)]
#[path = "../../src/socle/valeur_console.rs"]
mod valeur;

#[allow(dead_code)]
#[path = "../../fenetre/src/commandes.rs"]
mod commandes;

use commandes::{Commande, Saisie};
use nettoyage::{LIGNE_MAX, TEXTE_MAX, rendu};

fn sans_piege(s: &str, sauts: bool) {
    for c in s.chars() {
        assert!(
            (sauts && c == '\n') || rendu(c) == Some(c),
            "caractère piégé U+{:04X} dans {s:?}",
            u32::from(c)
        );
    }
}

fn nettoyer(brut: &str) {
    let l = nettoyage::ligne(brut);
    sans_piege(&l, false);
    assert!(l.chars().count() <= LIGNE_MAX);
    assert_eq!(nettoyage::ligne(&l), l);
    let t = nettoyage::texte(brut);
    sans_piege(&t, true);
    assert!(t.chars().count() <= TEXTE_MAX);
    assert_eq!(nettoyage::texte(&t), t);
    for max in [1, 20, 60, 200] {
        let n = nettoyage::nom(brut, max);
        sans_piege(&n, false);
        assert!(n.chars().count() <= max);
        assert_eq!(nettoyage::nom(&n, max), n);
    }
}

fn comprendre(brut: &str) {
    match commandes::comprendre(brut) {
        Saisie::Lancer(c) => {
            assert!(Commande::TOUTES.contains(&c));
            // Ses arguments viennent de la liste, jamais de la saisie : un nom, au plus une option ou une
            // sous-commande fixe de la liste (« antivirus --etat », « blocage etat »), puis --json.
            let a = c.arguments();
            assert!(a.len() == 2 || a.len() == 3, "{a:?}");
            assert_eq!(a.last().copied(), Some("--json"));
            assert!(a[0].bytes().all(|o| o.is_ascii_lowercase() || o == b'-'), "{a:?}");
            assert!(
                a[1..]
                    .iter()
                    .all(|x| x.strip_prefix("--").unwrap_or(x).bytes().all(|o| o.is_ascii_lowercase() || o == b'-')),
                "{a:?}"
            );
            // Et le texte tapé était bien son nom (« vanguard » devant permis), à la casse près.
            let mots: Vec<String> = brut.split_whitespace().map(str::to_ascii_lowercase).collect();
            let mot = mots.last().map(String::as_str).unwrap_or_default();
            assert!(mot == c.nom() || mot == c.nom_anglais(), "{brut:?} → {c:?}");
            assert!(mots.len() == 1 || (mots.len() == 2 && mots[0] == "vanguard"), "{brut:?}");
        }
        Saisie::Refusee(t) => {
            sans_piege(&t, false);
            assert!(t.chars().count() <= 60);
        }
        Saisie::Rien => assert!(brut.trim().is_empty()),
        Saisie::AideSur(c) => {
            // « aide <nom> » : une commande de la liste, décrite, jamais lancée ; le nom était bien le sien.
            assert!(Commande::TOUTES.contains(&c));
            let mots: Vec<String> = brut.split_whitespace().map(str::to_ascii_lowercase).collect();
            assert_eq!(mots.len(), 2, "{brut:?}");
            assert!(mots[1] == c.nom() || mots[1] == c.nom_anglais(), "{brut:?} → {c:?}");
        }
        // Une valeur : la commande de la liste qui en prend une, de sa sorte, jugée bonne, seule case libre de
        // `console <nom> -- <valeur>`.
        Saisie::LancerAvec(av) => {
            let c = av.commande();
            assert!(Commande::TOUTES.contains(&c));
            assert_eq!(c.argument(), Some(av.sorte()), "{brut:?}");
            assert!(valeur::valider(av.sorte(), av.valeur()).is_ok(), "{brut:?}");
            // Rien d'invisible (table `valeur::INVISIBLES`) ni aucun blanc autre que l'espace ordinaire : la valeur
            // lancée se lit telle qu'elle s'affiche.
            for ch in av.valeur().chars() {
                assert!(!valeur::invisible(ch), "U+{:04X} dans {brut:?}", u32::from(ch));
                assert!(!ch.is_whitespace() || ch == ' ', "U+{:04X} dans {brut:?}", u32::from(ch));
            }
            let l = commandes::Lancement::AvecValeur(av.clone());
            assert_eq!(l.arguments(), ["console", c.nom(), "--", av.valeur()], "{brut:?}");
            assert!(!l.change());
        }
        Saisie::ValeurManquante(c) => assert!(c.valeur_requise(), "{brut:?}"),
        Saisie::ValeurRefusee(c, _) => assert!(c.argument().is_some(), "{brut:?}"),
        Saisie::SansValeur(c) => assert!(c.argument().is_none(), "{brut:?}"),
        Saisie::Aide | Saisie::Effacer => {}
    }
    // Les suggestions : bornées, sans doublon, toutes de la liste fermée (elles ne se lancent jamais seules).
    let s = commandes::suggestions(brut);
    assert!(s.len() <= commandes::SUGGESTIONS_MAX);
    for (i, c) in s.iter().enumerate() {
        assert!(Commande::TOUTES.contains(c));
        assert!(!s[..i].contains(c), "{brut:?} → {s:?}");
    }
    if let Some(n) = commandes::completer(brut) {
        assert!(n.starts_with(&brut.trim().to_ascii_lowercase()), "{brut:?} → {n:?}");
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, reste)) = donnees.split_first() else { return };
    langue::choisir(Some(langue & 1 == 1));
    let brut = String::from_utf8_lossy(reste);
    nettoyer(&brut);
    comprendre(&brut);
});
