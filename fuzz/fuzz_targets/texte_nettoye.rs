//! La voie ouverte de l'auto-amélioration (src/amelioration/texte.rs) : quoi qu'on lui donne, un texte gardé est
//! borné, n'a que des caractères permis, ne fait plus sonner le détecteur de secrets et sort tel quel d'un second
//! nettoyage. Un jeton connu glissé n'importe où n'en ressort jamais. Module pur, inclus sans cale.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/amelioration/texte.rs"]
mod texte;

use texte::{Gabarit, NomLogiciel, TexteNettoye, VersionTierce};

fn verifier(s: &str, max: usize) {
    assert!(s.len() <= max, "{s:?} dépasse {max}");
    assert!(texte::sortie_permise(s), "caractère interdit dans {s:?}");
    assert!(!s.contains(['@', '`', '|', '"', '\\', '$', '{', '}']), "{s:?}");
    assert_eq!(texte::alertes(s), 0, "le détecteur sonne encore sur {s:?}");
    let c: Vec<char> = s.chars().collect();
    assert!(
        !c.windows(2).any(|w| matches!(w, ['#', x] if x.is_ascii_digit())),
        "renvoi de ticket dans {s:?}"
    );
}

fn essayer(brut: &str) {
    if let Ok(t) = TexteNettoye::nettoyer(brut) {
        verifier(t.as_str(), texte::TEXTE_MAX);
        assert_eq!(TexteNettoye::nettoyer(t.as_str()).as_ref(), Ok(&t));
        assert_eq!(TexteNettoye::lire(t.as_str()).as_ref(), Some(&t));
        let g = Gabarit::de(&t);
        assert!(Gabarit::lire(g.as_str()).is_some());
    }
    if let Ok(n) = NomLogiciel::nettoyer(brut) {
        verifier(n.as_str(), texte::NOM_MAX);
        assert_eq!(NomLogiciel::lire(n.as_str()).as_ref(), Some(&n));
    }
    if let Ok(v) = VersionTierce::nettoyer(brut) {
        verifier(v.as_str(), texte::VERSION_MAX);
        assert_eq!(VersionTierce::lire(v.as_str()).as_ref(), Some(&v));
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let brut = String::from_utf8_lossy(octets);
    essayer(&brut);
    // Un faux jeton (inventé ; préfixe recollé à l'exécution pour ne pas faire sonner les détecteurs de GitHub)
    // glissé à une position tirée de l'entrée : aucun de ses morceaux ne doit rester.
    let Some((&tirage, _)) = octets.split_first() else {
        return;
    };
    let corps = "FAUXjetonInventePourLeFuzz";
    let jeton = ["gh", "p_", corps].concat();
    let mut pos = usize::from(tirage).min(brut.len());
    while !brut.is_char_boundary(pos) {
        pos -= 1;
    }
    let avec = format!("{} {jeton} {}", &brut[..pos], &brut[pos..]);
    essayer(&avec);
    for sortie in [
        TexteNettoye::nettoyer(&avec).map(String::from).ok(),
        NomLogiciel::nettoyer(&avec).map(String::from).ok(),
    ]
    .into_iter()
    .flatten()
    {
        // Le corps du jeton ne figure pas dans l'entrée d'origine : s'il ressort, c'est qu'il a passé.
        if !brut.contains("InventePourLe") {
            assert!(!sortie.contains("InventePourLe"), "jeton passé : {sortie:?}");
        }
    }
});
