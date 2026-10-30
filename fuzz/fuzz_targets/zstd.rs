//! Le décodeur zstd fait maison (src/machine/linux/zstd.rs) : les champs compressés du journal de systemd, qu'un
//! programme de n'importe quel compte peut remplir. Tables FSE et Huffman forgées, décalages qui remontent avant le
//! début, blocs qui mentent sur leur taille, trames à sauter démesurées, bombes de décompression.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/machine/linux/zstd.rs"]
mod zstd;

/// Petite, pour que le fuzzer atteigne souvent la limite (une bombe s'y arrête).
const LIMITE: usize = 1 << 16;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    if let Some(contenu) = zstd::decompresser(octets, LIMITE) {
        assert!(contenu.len() <= LIMITE);
    }
    // Derrière la signature d'une trame : le fuzzer n'a pas à deviner ses quatre octets.
    let mut trame = vec![0x28, 0xb5, 0x2f, 0xfd];
    trame.extend_from_slice(octets);
    if let Some(contenu) = zstd::decompresser(&trame, LIMITE) {
        assert!(contenu.len() <= LIMITE);
    }
    if let Some(contenu) = zstd::decompresser(&trame, 0) {
        assert!(contenu.is_empty());
    }
});
