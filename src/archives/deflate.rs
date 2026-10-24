//! Un flux deflate (RFC 1951) décompressé par miniz_oxide, borné, qui dit comment il s'est arrêté : fini, à la
//! limite, coupé ou abîmé, avec ce qui a été produit jusque-là. L'analyse des fichiers (`analyse/`) en a besoin pour
//! ne jamais confondre « tout lu » et « lu jusqu'à la borne » : `decompress_to_vec_with_limit` rend une erreur dans
//! les deux derniers cas, avec un tampon dont la longueur n'est pas celle des octets produits.
//!
//! Lecteur pur (miniz_oxide seul, sans `crate::`) : le banc de fuzzing l'inclut par son chemin.

/// Comment le flux s'est arrêté.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fin {
    /// Le bloc final a été lu : le contenu est entier.
    Complet,
    /// `limite` octets produits et le flux continuait (ou finissait pile là : on ne peut pas le savoir sans lire
    /// plus) : le reste n'est pas lu.
    Limite,
    /// Les octets compressés s'arrêtent avant le bloc final.
    Coupe,
    /// Un code deflate invalide.
    Abime,
}

/// Ce qu'a donné le flux : le contenu produit (entier ou non, voir `fin`) et le nombre d'octets compressés lus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inflate {
    pub contenu: Vec<u8>,
    pub lus: usize,
    pub fin: Fin,
}

/// Le flux deflate brut `flux`, au plus `limite` octets produits. Le tampon grandit par doublement depuis une taille
/// tirée de l'entrée (jamais de la taille annoncée par un en-tête), plafonnée à `limite`.
pub(crate) fn inflater(flux: &[u8], limite: usize) -> Inflate {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    let drapeaux = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let mut sortie = vec![0u8; flux.len().saturating_mul(2).clamp(64, 1 << 20).min(limite)];
    let mut decodeur = Box::<DecompressorOxide>::default();
    let (mut lus, mut ecrits) = (0usize, 0usize);
    loop {
        let entree = flux.get(lus..).unwrap_or(&[]);
        let (etat, consommes, produits) = decompress(&mut decodeur, entree, &mut sortie, ecrits, drapeaux);
        lus = lus.saturating_add(consommes).min(flux.len());
        ecrits = ecrits.saturating_add(produits).min(sortie.len());
        let fin = match etat {
            TINFLStatus::Done => Fin::Complet,
            TINFLStatus::HasMoreOutput if sortie.len() < limite => {
                let nouvelle = sortie.len().saturating_mul(2).min(limite);
                sortie.resize(nouvelle, 0);
                continue;
            }
            TINFLStatus::HasMoreOutput => Fin::Limite,
            // Sans TINFL_FLAG_HAS_MORE_INPUT, une entrée épuisée avant le bloc final se dit ainsi.
            TINFLStatus::FailedCannotMakeProgress | TINFLStatus::NeedsMoreInput => Fin::Coupe,
            _ => Fin::Abime,
        };
        sortie.truncate(ecrits);
        return Inflate {
            contenu: sortie,
            lus,
            fin,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fini_limite_coupe_abime() {
        let texte = b"Sub AutoOpen()\n  MsgBox 1\nEnd Sub\n".repeat(200);
        let flux = miniz_oxide::deflate::compress_to_vec(&texte, 6);
        let lu = inflater(&flux, 1 << 20);
        assert_eq!(
            (lu.fin, lu.lus, lu.contenu.as_slice()),
            (Fin::Complet, flux.len(), &texte[..])
        );
        // Des octets après la fin du flux ne sont pas lus : `lus` dit où il finit.
        let mut suivi = flux.clone();
        suivi.extend(b"PK\x03\x04");
        assert_eq!(inflater(&suivi, 1 << 20).lus, flux.len());
        // La limite : le début seulement, et dit.
        let borne = inflater(&flux, 100);
        assert_eq!((borne.fin, borne.contenu.as_slice()), (Fin::Limite, &texte[..100]));
        // Coupé : ce qui a pu être produit, et dit.
        let coupe = inflater(&flux[..flux.len() / 2], 1 << 20);
        assert_eq!(coupe.fin, Fin::Coupe);
        assert!(texte.starts_with(&coupe.contenu));
        // Type de bloc réservé (11) : abîmé.
        assert_eq!(inflater(&[0b0000_0111], 1 << 20).fin, Fin::Abime);
        assert_eq!(inflater(&[], 1 << 20).fin, Fin::Coupe);
    }

    /// Une bombe : 16 Mio de zéros en quelques Kio, arrêtée à la limite sans tout produire.
    #[test]
    fn bombe() {
        let flux = miniz_oxide::deflate::compress_to_vec(&vec![0u8; 16 << 20], 9);
        assert!(flux.len() < 64 << 10);
        let lu = inflater(&flux, 1 << 20);
        assert_eq!((lu.fin, lu.contenu.len()), (Fin::Limite, 1 << 20));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..2000), limite in 0usize..5000) {
            let lu = inflater(&octets, limite);
            proptest::prop_assert!(lu.contenu.len() <= limite);
            proptest::prop_assert!(lu.lus <= octets.len());
        }
    }
}
