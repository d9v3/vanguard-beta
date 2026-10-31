//! La réponse d'un serveur TLS à la sonde post-quantique (le site de référence, ou l'administration de la box) ; et
//! le ClientHello lui-même, quel que soit le nom donné.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/langue.rs"]
#[macro_use]
mod langue;

#[path = "../cale/reseau.rs"]
mod reseau;

#[path = "../cale/modele.rs"]
mod modele;

#[allow(dead_code)]
#[path = "../../src/audit/tls_pq.rs"]
mod tls_pq;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let _ = tls_pq::lire_reponse(octets);
    // Un nom quelconque : la sonde reste un enregistrement TLS bien formé, de la taille visée (un nom trop long
    // n'entre pas dans le SNI).
    if let Ok(hote) = std::str::from_utf8(octets) {
        let o = tls_pq::client_hello_avec(Some(hote), &[0; 64]);
        assert_eq!(usize::from(u16::from_be_bytes([o[3], o[4]])), o.len() - 5);
        assert_eq!(o.len(), tls_pq::TAILLE_SONDE);
    }
});
