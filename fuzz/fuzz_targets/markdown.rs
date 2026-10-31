//! La neutralisation Markdown du brouillon de signalement (src/signaler/markdown.rs) : un texte quelconque (nom de
//! fichier, titre d'alerte, réponse de la personne) ne laisse aucun caractère spécial libre hors d'un bloc de code, et
//! ne ferme jamais le bloc qui le contient. Module pur, inclus sans cale.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/signaler/markdown.rs"]
mod markdown;

/// Les caractères que le Markdown de GitHub ou de Bugzilla interprète (la liste de markdown.rs).
const SPECIAUX: &[char] = &['\\', '`', '@', '<', '>', '[', ']', '!', '#', '|', '&'];

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    // Hors d'un bloc : chaque caractère spécial est échappé, et le texte montré est celui écrit.
    let n = markdown::neutraliser_markdown(texte);
    let mut vu = String::new();
    let mut car = n.chars();
    while let Some(c) = car.next() {
        if c == '\\' {
            vu.push(car.next().expect("barre oblique finale non suivie"));
        } else {
            assert!(!SPECIAUX.contains(&c), "{c:?} libre dans {n:?}");
            vu.push(c);
        }
    }
    assert_eq!(vu, texte);
    // Dans un bloc : la clôture est plus longue que toute suite d'accents graves du texte, qui reste tel quel.
    let b = markdown::bloc_de_code(texte);
    let cloture = b.split('\n').next().unwrap();
    assert!(cloture.len() >= 3 && cloture.chars().all(|c| c == '`'));
    assert!(!texte.contains(cloture));
    assert_eq!(&b[cloture.len() + 1..b.len() - cloture.len() - 1], texte);
});
