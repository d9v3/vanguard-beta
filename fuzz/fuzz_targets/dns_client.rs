//! Les réponses DNS : n'importe quel serveur, ou un paquet forgé qui se fait passer pour sa réponse.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/reseau.rs"]
mod reseau;

#[allow(dead_code)]
#[path = "../../src/audit/dns_client.rs"]
mod dns_client;

use dns_client::Donnees;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    // L'identifiant attendu est celui du message : le fuzzer va tout de suite au-delà de cette porte.
    let Some(&[a, b]) = octets.first_chunk::<2>() else {
        return;
    };
    let Some(r) = dns_client::lire(octets, u16::from_be_bytes([a, b])) else {
        return;
    };
    assert!(r.enregistrements.len() <= 64);
    for e in &r.enregistrements {
        assert!(e.nom.len() <= 253);
        match &e.donnees {
            Donnees::Txt(t) => assert!(t.len() <= 32),
            Donnees::Svcb { cible, alpn, .. } => assert!(cible.len() <= 253 && alpn.len() <= 32),
            _ => {}
        }
    }
});
