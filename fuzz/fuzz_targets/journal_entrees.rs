//! La lecture du journal des erreurs pour le compte rendu pour Claude (src/compte_rendu/journal.rs) : le journal
//! s'écrit sur la partition VANGUARDLOG de n'importe quel ordinateur, et dans un dossier que tout programme du compte
//! peut modifier. Jamais de panique, des bornes tenues, et une ligne de champs relue se réécrit à l'identique.
//! Modules purs (les champs et leur lecture), inclus sans cale.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/compte_rendu/champs.rs"]
mod champs;

#[allow(dead_code)]
#[path = "../../src/compte_rendu/journal.rs"]
mod journal;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let l = journal::lire(octets);
    let lus = octets.get(..journal::OCTETS_MAX).unwrap_or(octets);
    let debuts = lus.split(|&o| o == b'\n').filter(|x| x.starts_with(b"== ")).count();
    assert_eq!(l.entrees.len() + l.refusees + l.en_trop, debuts);
    assert_eq!(l.coupe, octets.len() > journal::OCTETS_MAX);
    assert!(l.entrees.len() <= journal::ENTREES_MAX);
    for e in &l.entrees {
        if e.ancienne {
            continue;
        }
        let c = journal::Champs {
            genre: e.genre,
            contexte: e.contexte.expect("une entrée à champs a son contexte"),
            regle: e.regle.clone(),
            code: e.code.clone(),
            lieu: e.lieu.clone(),
        };
        let ligne = c.ligne();
        assert!(
            ligne
                .strip_prefix(journal::MARQUE)
                .unwrap()
                .bytes()
                .all(|o| o.is_ascii_alphanumeric() || b"=:._/ -".contains(&o)),
            "{ligne:?}"
        );
        assert_eq!(journal::Champs::de_ligne(&ligne).as_ref(), Some(&c));
    }
});
