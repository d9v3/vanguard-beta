//! Les heuristiques du moteur d'analyse (src/protection/heuristiques.rs) sur chaque partie d'un fichier quelconque :
//! sections et segments qui mentent, signatures Authenticode tronquées, noms aux extensions empilées ou aux
//! caractères de contrôle, raccourcis aux arguments sans fin, scripts en UTF-16 coupé ou base64 piégée : jamais de
//! panique, au plus un signe par heuristique et par partie, un détail borné.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/archives/mod.rs"]
mod archives;

#[allow(dead_code)]
#[path = "../../src/pe.rs"]
mod pe;

#[allow(dead_code, unused_imports)]
#[path = "../../src/analyse/mod.rs"]
mod analyse;

#[allow(dead_code)]
#[path = "../../src/protection/heuristiques.rs"]
mod heuristiques;

use heuristiques::Lieu;

/// Petites : chaque exécution reste brève.
fn bornes() -> analyse::Bornes {
    analyse::Bornes {
        parties: 200,
        taille_partie: 1 << 20,
        produits: 2 << 20,
        seuil_taux: 1 << 20,
        entrees: 300,
        texte: 1 << 16,
        ..analyse::Bornes::default()
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // Le premier octet choisit le lieu, le reste est le fichier : le programme sans signature n'est jugé qu'hors du
    // lieu ordinaire.
    let Some((&choix, fichier)) = octets.split_first() else {
        return;
    };
    let lieu = match choix % 3 {
        0 => Lieu::Ordinaire,
        1 => Lieu::Temporaire,
        _ => Lieu::Telechargements,
    };
    let bornes = bornes();
    let _ = analyse::analyser(fichier, "f.pdf.exe", &bornes, &mut |p, o| {
        let signes = heuristiques::juger(p, o, lieu);
        assert!(signes.len() <= heuristiques::Heuristique::TOUTES.len());
        for (k, s) in signes.iter().enumerate() {
            assert!(signes[..k].iter().all(|t| t.heuristique != s.heuristique));
            assert!(s.detail.len() <= 4096);
            if lieu == Lieu::Ordinaire {
                assert_ne!(s.heuristique, heuristiques::Heuristique::PeNonSigne);
            }
        }
    });
});
