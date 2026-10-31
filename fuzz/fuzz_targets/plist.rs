//! Les plists d'Apple (XML et binaires) : un agent posé dans LaunchAgents peut être fabriqué pour gêner l'analyse.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/plist.rs"]
mod plist;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let _ = plist::lire(octets);
    // Le même contenu derrière l'en-tête binaire : le fuzzer n'a pas à le deviner.
    let mut binaire = b"bplist00".to_vec();
    binaire.extend_from_slice(octets);
    let _ = plist::lire(&binaire);
});
