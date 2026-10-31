//! L'analyse d'un fichier entier en arbre de parties (src/analyse/) : n'importe quel fichier peut être piégé. PE, ELF
//! et Mach-O aux en-têtes qui mentent, zips aux entrées cachées ou imbriquées, fichiers composés aux chaînes qui
//! bouclent, macros VBA compressées abîmées, raccourcis coupés, scripts UTF-16 : jamais de panique, et les bornes
//! (parties, octets produits, profondeur) tiennent.
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

/// Petites : chaque exécution reste brève, et un dépassement se voit vite.
fn bornes() -> analyse::Bornes {
    analyse::Bornes {
        parties: 300,
        taille_partie: 1 << 20,
        produits: 4 << 20,
        seuil_taux: 1 << 20,
        entrees: 500,
        texte: 1 << 16,
        ..analyse::Bornes::default()
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let bornes = bornes();
    let mut visites = 0usize;
    let a = analyse::analyser(octets, "f", &bornes, &mut |p, o| {
        visites += 1;
        assert_eq!(p.taille, o.len() as u64);
    });
    assert!(a.parties.len() <= bornes.parties);
    assert!(a.produits <= bornes.produits + bornes.texte as u64);
    assert!(visites <= a.parties.len());
    for (k, p) in a.parties.iter().enumerate() {
        assert!(p.parent.is_none_or(|q| q < k));
        assert!(p.profondeur <= bornes.profondeur);
        // Ce qui n'est pas reconnu est toujours dit « non vérifié ».
        if p.type_ == analyse::Type::Inconnu && p.sha256.is_some() {
            assert!(!p.manques.is_empty());
        }
        if p.type_.non_lu() {
            assert!(!p.manques.is_empty());
        }
    }
});
