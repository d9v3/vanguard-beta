//! Les courriels enregistrés (.eml) : la personne donne un courriel reçu, écrit par n'importe qui pour gêner la lecture
//! (frontières en boucle, imbrications sans fin, encodages abîmés).
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/protection/courriel_suspect/mime.rs"]
mod mime;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // Bornes réduites : le fuzzer atteint chacune avec de petites entrées.
    let bornes = mime::Bornes {
        octets: 64 * 1024,
        profondeur: 4,
        parties: 20,
        entetes: 30,
        entete_octets: 512,
        bloc_entetes: 4096,
        mots_encodes: 8,
        parametres: 8,
        frontiere: 70,
    };
    let m = mime::lire_borne(octets, &bornes);
    assert!(m.parties.len() <= bornes.parties);
    assert!(m.entetes.len() <= bornes.entetes);
    assert!(m.parties.iter().all(|p| p.profondeur <= bornes.profondeur));
    for e in &m.entetes {
        let _ = mime::mots_encodes(&e.brut, &bornes);
        let _ = mime::parametres(&e.texte(), &bornes);
    }
    for p in &m.parties {
        let _ = mime::texte(&p.contenu, p.jeu.as_deref());
    }
});
