//! Les empreintes écrites en hexadécimal, par les fonctions de hachage de RustCrypto (sha1, sha2, md-5).

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use sha2::Digest;

/// Des octets en hexadécimal minuscule.
pub(crate) fn hexa(octets: &[u8]) -> String {
    use std::fmt::Write;
    octets
        .iter()
        .fold(String::with_capacity(octets.len().saturating_mul(2)), |mut t, o| {
            let _ = write!(t, "{o:02x}");
            t
        })
}

/// L'empreinte SHA-1 de `octets`, en hexadécimal minuscule (40 caractères).
pub(crate) fn sha1_hexa(octets: &[u8]) -> String {
    hexa(&sha1::Sha1::digest(octets))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Les vecteurs de la FIPS 180 : la même écriture que la crate d'avant (sha1_smol), au caractère près, sans quoi
    /// l'empreinte de la machine (`machine::empreinte_machine`) changerait.
    #[test]
    fn sha1_des_vecteurs() {
        assert_eq!(sha1_hexa(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(sha1_hexa(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            sha1_hexa(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(hexa(&[0, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
