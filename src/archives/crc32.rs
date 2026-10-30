//! Le CRC-32 de gzip et de zip (IEEE 802.3, polynôme réfléchi 0xEDB88320) : une seule table, pour les deux lecteurs
//! qui vérifient ce qu'ils décompressent (`gzip::degzip_controle`, `zip::controler`).
//!
//! Sans `crate::` : le banc de fuzzing l'inclut par son chemin, avec les lecteurs.

/// La table, calculée à la compilation.
const TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        #[expect(clippy::indexing_slicing, reason = "i < 256 par la boucle, la table en a 256")]
        {
            table[i as usize] = c;
        }
        i += 1;
    }
    table
};

pub(crate) fn crc32(octets: &[u8]) -> u32 {
    !octets.iter().fold(!0u32, |c, &o| {
        #[expect(clippy::indexing_slicing, reason = "indice masqué à 0xff, la table en a 256")]
        let t = TABLE[((c ^ u32::from(o)) & 0xff) as usize];
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
