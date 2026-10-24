//! La ressource de version d'un exécutable Windows (PE, RT_VERSION), et ses gardes (Load Config, manifeste) : un .exe
//! peut être fabriqué pour gêner l'analyse (en-têtes qui débordent, arbre des ressources qui boucle, tailles
//! démesurées).
#![no_main]

#[allow(dead_code)]
#[path = "../../src/pe.rs"]
mod pe;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let _ = pe::lire(&mut std::io::Cursor::new(octets), octets.len() as u64);
    let _ = pe::lire_gardes(&mut std::io::Cursor::new(octets), octets.len() as u64);
    // La même chose derrière un en-tête DOS valide : le fuzzer n'a pas à deviner « MZ » ni e_lfanew.
    let mut mz = vec![0u8; 0x40];
    mz[..2].copy_from_slice(b"MZ");
    mz[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    mz.extend_from_slice(octets);
    let _ = pe::lire(&mut std::io::Cursor::new(&mz), mz.len() as u64);
    let _ = pe::lire_gardes(&mut std::io::Cursor::new(&mz), mz.len() as u64);
});
