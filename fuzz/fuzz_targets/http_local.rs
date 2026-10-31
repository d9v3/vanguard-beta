//! Les réponses HTTP d'un appareil du réseau local (une box) : en-têtes, longueurs, morceaux.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/, cales) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[path = "../cale/reseau.rs"]
mod reseau;

#[allow(dead_code)]
#[path = "../../src/audit/http_local.rs"]
mod http_local;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    if let Some(r) = http_local::lire_reponse(octets) {
        assert!(r.corps.len() <= octets.len());
        let _ = r.texte();
    }
    // Une adresse donnée par la box : jamais hors du réseau local, jamais un chemin qui casse la demande.
    if let Ok(texte) = std::str::from_utf8(octets)
        && let Some(a) = http_local::Adresse::lire(texte)
    {
        assert!(reseau::nmap::locale(a.ip));
        assert!(!a.chemin.chars().any(|c| c.is_ascii_control() || c == ' '));
        let _ = a.resoudre(texte);
    }
});
