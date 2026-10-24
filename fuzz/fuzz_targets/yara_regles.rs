//! Le lecteur des règles YARA (src/protection/regles_yara.rs) et leur compilation (moteur_yara.rs, motifs.rs) : un
//! fichier de règles abîmé ou hostile (accolades qui ne ferment pas, chaînes hexadécimales démesurées, choix imbriqués,
//! conditions sans fin) ne doit jamais faire paniquer ; les règles comprises s'appliquent ensuite à quelques données.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/pe.rs"]
mod pe;

// Les trois modules du moteur, côte à côte comme dans src/protection/ (ils se citent par `super::`).
#[allow(dead_code)]
#[path = "../../src/protection/motifs.rs"]
mod motifs;
#[allow(dead_code)]
#[path = "../../src/protection/moteur_yara.rs"]
mod moteur_yara;
#[allow(dead_code)]
#[path = "../../src/protection/regles_yara.rs"]
mod regles_yara;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let texte = String::from_utf8_lossy(octets);
    let regles = moteur_yara::Regles::compiler(&texte);
    // Chaque règle est soit appliquée, soit refusée (dite) ; jamais perdue en silence.
    assert!(regles.nombre() <= regles_yara::REGLES_MAX);
    if regles.nombre() == 0 {
        return;
    }
    let echeance = Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
    for donnees in [&b"MZ\x90\x00 vanguard"[..], b"\x7fELF\x02\x01\x01", octets] {
        let _ = regles.analyser_tampon(donnees, echeance);
    }
});
