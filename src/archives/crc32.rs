//! Le CRC-32 de gzip et de zip (IEEE 802.3, polynôme réfléchi 0xEDB88320) : une seule table, pour les deux lecteurs
//! qui vérifient ce qu'ils décompressent (`gzip::degzip_controle`, `zip::controler`).
//!
//! Sans `crate::` : le banc de fuzzing l'inclut par son chemin, avec les lecteurs.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// La table, calculée à la compilation.
const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    // L'indice et sa valeur à part : pas de conversion (`From` n'est pas utilisable dans un `const`).
    let (mut i, mut valeur) = (0usize, 0u32);
    while i < 256 {
        let mut c = valeur;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        #[expect(clippy::indexing_slicing, reason = "i < 256 par la boucle, la table en a 256")]
        {
            table[i] = c;
        }
        i += 1;
        valeur += 1;
    }
    table
};

pub(crate) fn crc32(octets: &[u8]) -> u32 {
    !octets.iter().fold(!0u32, |c, &o| {
        // L'octet de poids faible de c, mêlé à o : (c ^ o) & 0xff.
        let [bas, ..] = c.to_le_bytes();
        #[expect(clippy::indexing_slicing, reason = "un octet indexe une table de 256 entrées")]
        let t = TABLE[usize::from(bas ^ o)];
        t ^ (c >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La valeur de contrôle de la norme (« 123456789 »), et le vide.
    #[test]
    fn valeurs_de_reference() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }
}
