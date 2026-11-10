//! La console de la fenêtre (fenetre/src/commandes.rs) et son nettoyage (fenetre/src/nettoyage.rs) : quoi qu'on tape
//! ou colle, seule une commande de la liste fermée se lance, toujours avec ses propres arguments en JSON, jamais un
//! morceau du texte tapé ; un refus redit le texte nettoyé, sur une ligne, borné. Chaque nettoyage rend un texte
//! borné, sans caractère piégé, qu'un second passage ne change plus. Le premier octet choisit la langue.
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
#[path = "../../fenetre/src/commandes.rs"]
mod commandes;

use commandes::{Commande, Saisie};
use nettoyage::{LIGNE_MAX, TEXTE_MAX, piege};

fn sans_piege(s: &str, sauts: bool) {
    for c in s.chars() {
        assert!(
            (sauts && c == '\n') || !piege(c),
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
            // Ses arguments viennent de la liste, jamais de la saisie : un nom, puis --json.
            let a = c.arguments();
            assert_eq!(a.len(), 2, "{a:?}");
            assert_eq!(a[1], "--json");
            assert!(a[0].bytes().all(|o| o.is_ascii_lowercase() || o == b'-'), "{a:?}");
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
        Saisie::Aide | Saisie::Effacer => {}
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
