//! Le moteur YARA (src/protection/moteur_yara.rs, motifs.rs, champs pe de src/pe.rs) sur des données hostiles, avec
//! les 308 règles d'origine : fichiers et mémoire de processus piégés, en-têtes PE et ELF qui mentent. Jamais de
//! panique, et le flux lu par petits blocs trouve exactement ce que trouve le tampon.
#![no_main]

use std::sync::OnceLock;

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

use moteur_yara::Regles;

const REGLES: &str = include_str!("../../assets/yara/reversinglabs.yara");

fn regles() -> &'static (Regles, Regles) {
    static R: OnceLock<(Regles, Regles)> = OnceLock::new();
    R.get_or_init(|| (Regles::compiler(REGLES), Regles::compiler(REGLES).avec_bloc(5)))
}

/// Les données, avec en tête de quoi passer le premier filtre des règles : « MZ » et un en-tête PE à 0x40 (le
/// fuzzer n'a pas à deviner e_lfanew), ou un en-tête ELF.
fn variantes(octets: &[u8]) -> [Vec<u8>; 3] {
    let mut mz = vec![0u8; 0x40];
    mz[..2].copy_from_slice(b"MZ");
    mz[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    mz.extend_from_slice(b"PE\0\0");
    mz.extend_from_slice(octets);
    let mut elf = b"\x7fELF".to_vec();
    elf.extend_from_slice(octets);
    [octets.to_vec(), mz, elf]
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let (tampon, flux) = regles();
    assert_eq!(tampon.refus().len(), 0);
    for d in variantes(octets) {
        let a = tampon.analyser_tampon(&d, None).expect("tampon");
        let b = flux
            .analyser_flux(&mut std::io::Cursor::new(&d[..]), d.len() as u64, None)
            .expect("flux");
        assert_eq!(a, b);
    }
});
