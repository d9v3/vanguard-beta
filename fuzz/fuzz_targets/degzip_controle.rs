//! Les fichiers gzip téléchargés (endoflife.date, formula.json et cask.json de Homebrew, archive des avis de
//! Mozilla) : en-têtes aux champs facultatifs démesurés, flux deflate abîmés, CRC et taille faux, membres bout à bout,
//! bombes de décompression. La lecture des fichiers de cet ordinateur (`degzip`) passe aussi.
#![no_main]

#[path = "../../src/archives/crc32.rs"]
mod crc32;

#[allow(dead_code)]
#[path = "../../src/archives/gzip.rs"]
mod gzip;

/// Petite, pour que le fuzzer atteigne souvent la limite (une bombe s'y arrête).
const LIMITE: usize = 1 << 16;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let _ = gzip::degzip_controle(octets, LIMITE);
    let _ = gzip::degzip(octets, LIMITE);
    // Derrière un en-tête valide : le fuzzer n'a pas à deviner les trois premiers octets.
    let mut gz = vec![0x1f, 0x8b, 8];
    gz.extend_from_slice(octets);
    if let Some(contenu) = gzip::degzip_controle(&gz, LIMITE) {
        assert!(contenu.len() <= LIMITE);
    }
    let _ = gzip::degzip_controle(&gz, 0);
});
