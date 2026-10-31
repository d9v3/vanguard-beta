//! Le paquet KEXINIT d'un serveur SSH (la box, ou un appareil qui se fait passer pour elle) : lignes de bannière,
//! identification, longueurs, liste des échanges de clés.
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
#[path = "../../src/audit/ssh_kex.rs"]
mod ssh_kex;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    if let Ok(ssh_kex::Lu::Kex(noms)) = ssh_kex::lire(octets) {
        assert!(!noms.is_empty());
        for n in &noms {
            assert!(!n.is_empty() && n.len() <= 64);
            assert!(n.bytes().all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c)));
        }
    }
});
