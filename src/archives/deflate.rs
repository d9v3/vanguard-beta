//! Un flux deflate (RFC 1951) décompressé par miniz_oxide, borné, qui dit comment il s'est arrêté : fini, à la
//! limite, coupé ou abîmé, avec ce qui a été produit jusque-là. L'analyse des fichiers (`analyse/`) en a besoin pour
//! ne jamais confondre « tout lu » et « lu jusqu'à la borne » : `decompress_to_vec_with_limit` rend une erreur dans
//! les deux derniers cas, avec un tampon dont la longueur n'est pas celle des octets produits.
//!
//! Lecteur pur (miniz_oxide seul, sans `crate::`) : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

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
    /// L'échéance est passée avant la fin : des blocs vides ne produisent rien mais coûtent chacun une table à
    /// reconstruire (≈ 1,2 s de processeur par Mio compressé), et la seule borne de la sortie ne les arrête pas.
    Delai,
}

/// Les octets compressés donnés au décodeur d'un coup : l'échéance se regarde entre deux tranches, soit au pire
/// ≈ 80 ms de blocs vides sans la regarder.
const TRANCHE: usize = 64 << 10;

/// Ce qu'a donné le flux : le contenu produit (entier ou non, voir `fin`) et le nombre d'octets compressés lus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inflate {
    pub contenu: Vec<u8>,
    pub lus: usize,
    pub fin: Fin,
}

/// Le flux deflate brut `flux`, au plus `limite` octets produits. Le tampon grandit par doublement depuis une taille
/// tirée de l'entrée (jamais de la taille annoncée par un en-tête), plafonnée à `limite`.
#[cfg(test)] // toute lecture du programme a son échéance (`inflater_avant`)
pub(crate) fn inflater(flux: &[u8], limite: usize) -> Inflate {
    inflater_avant(flux, limite, None)
}

/// `inflater`, arrêté à `echeance` (`Fin::Delai`) : les octets compressés sont donnés par tranches, et l'échéance
/// regardée avant chacune sauf la première. Une échéance déjà passée laisse donc lire la première tranche : un flux
/// court se lit toujours.
pub(crate) fn inflater_avant(flux: &[u8], limite: usize, echeance: Option<std::time::Instant>) -> Inflate {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    let mut sortie = vec![0u8; flux.len().saturating_mul(2).clamp(64, 64 << 10).min(limite)];
    let mut decodeur = Box::<DecompressorOxide>::default();
    let (mut lus, mut ecrits) = (0usize, 0usize);
    loop {
        let bout = lus.saturating_add(TRANCHE).min(flux.len());
        let entree = flux.get(lus..bout).unwrap_or(&[]);
        // Une tranche qui n'est pas la dernière : le décodeur attend la suite au lieu de conclure à un flux coupé.
        let drapeaux = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
            | if bout < flux.len() {
                inflate_flags::TINFL_FLAG_HAS_MORE_INPUT
            } else {
                0
            };
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
            TINFLStatus::NeedsMoreInput if lus < flux.len() && consommes > 0 => {
                if echeance.is_some_and(|e| std::time::Instant::now() >= e) {
                    Fin::Delai
                } else {
                    continue;
                }
            }
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

/// Les octets compressés qu'un contenu de `taille` octets peut plausiblement occuper. Deflate n'agrandit jamais
/// beaucoup : au pire des symboles de 9 bits pour 8 (bloc fixe), plus les en-têtes de blocs. Des octets compressés
/// bien plus nombreux que leur contenu ne sont que des blocs vides, coûteux à décoder et qui ne produisent rien.
pub(crate) fn compresse_plausible(taille: usize) -> usize {
    taille.saturating_add(taille / 8).saturating_add(4096)
}

/// Le contenu d'une entrée d'archive dont la taille est annoncée : entier et exactement de `taille` octets, ou rien.
/// Le flux doit être plausible pour cette taille (`compresse_plausible`) et lu avant `echeance` : une entrée de blocs
/// vides ne tient pas le processeur, que sa taille annoncée soit vraie ou non.
pub(crate) fn entier_avant(flux: &[u8], taille: usize, echeance: std::time::Instant) -> Option<Vec<u8>> {
    if flux.len() > compresse_plausible(taille) {
        return None;
    }
    // Une place de plus que la taille : un flux qui la dépasse se voit (`Complet` d'une autre longueur, ou `Limite`).
    let lu = inflater_avant(flux, taille.saturating_add(1), Some(echeance));
    (lu.fin == Fin::Complet && lu.contenu.len() == taille).then_some(lu.contenu)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
pub(crate) mod tests {
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

    /// Des blocs deflate vides (bloc fixe sans symbole, 10 bits), puis un bloc final stocké d'un octet.
    pub(crate) fn blocs_vides(octets: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(octets + 8);
        while v.len() + 5 <= octets {
            v.extend_from_slice(&[0x02, 0x08, 0x20, 0x80, 0x00]);
        }
        v.extend_from_slice(&[0x01, 0x01, 0x00, 0xFE, 0xFF, b'x']);
        v
    }

    /// Un flux plus long qu'une tranche, suivi d'autre chose : lu entier, sa fin trouvée à l'octet près, comme d'un
    /// seul coup.
    #[test]
    fn par_tranches_comme_d_un_coup() {
        let mut graine = 0x1234_5678u32;
        let texte: Vec<u8> = (0..300_000)
            .map(|_| {
                graine ^= graine << 13;
                graine ^= graine >> 17;
                graine ^= graine << 5;
                graine.to_le_bytes()[0]
            })
            .collect();
        let flux = miniz_oxide::deflate::compress_to_vec(&texte, 6);
        assert!(flux.len() > 3 * TRANCHE);
        let mut suivi = flux.clone();
        suivi.extend(b"PK\x03\x04");
        let lu = inflater_avant(&suivi, 1 << 20, None);
        assert_eq!((lu.fin, lu.lus), (Fin::Complet, flux.len()));
        assert_eq!(lu.contenu, texte);
        let coupe = inflater(&flux[..flux.len() - 100], 1 << 20);
        assert_eq!(coupe.fin, Fin::Coupe);
    }

    /// Des Mio de blocs vides : sans échéance, lus jusqu'au bout (lentement) ; avec une échéance passée, arrêtés
    /// après la première tranche, et dit.
    #[test]
    fn blocs_vides_arretes_a_l_echeance() {
        let petit = blocs_vides(TRANCHE / 2);
        let lu = inflater_avant(&petit, 10, None);
        assert_eq!((lu.fin, lu.contenu.as_slice()), (Fin::Complet, &b"x"[..]));
        // Une échéance déjà passée : la première tranche se lit quand même (un flux court passe toujours).
        assert_eq!(
            inflater_avant(&petit, 10, Some(std::time::Instant::now())).fin,
            Fin::Complet
        );
        let gros = blocs_vides(4 << 20);
        let debut = std::time::Instant::now();
        let lu = inflater_avant(&gros, 10, Some(debut));
        assert_eq!(lu.fin, Fin::Delai);
        assert!(lu.lus <= TRANCHE && lu.contenu.is_empty());
    }

    /// Des blocs vides (non finaux, alignés sur l'octet) puis `contenu` compressé : un flux valide, lent à lire.
    pub(crate) fn vides_puis(vides: usize, contenu: &[u8]) -> Vec<u8> {
        let mut flux = blocs_vides(vides);
        flux.truncate(flux.len() - 6);
        flux.extend(miniz_oxide::deflate::compress_to_vec(contenu, 6));
        flux
    }

    /// Une entrée d'archive : lue entière à sa taille ; refusée si ses octets compressés ne sont pas plausibles pour
    /// elle, ou si l'échéance passe avant la fin.
    #[test]
    fn entree_entiere_plausible_et_a_l_heure() {
        let loin = std::time::Instant::now() + std::time::Duration::from_secs(600);
        let contenu = vec![7u8; 64 << 10];
        let flux = vides_puis(16 << 10, &contenu);
        assert_eq!(entier_avant(&flux, contenu.len(), loin), Some(contenu.clone()));
        assert_eq!(entier_avant(&flux, contenu.len() - 1, loin), None);
        assert_eq!(entier_avant(&flux, contenu.len() + 1, loin), None);
        // Plus de blocs vides que la taille ne le permet : refusé sans décoder.
        let trop = vides_puis(128 << 10, &contenu);
        assert_eq!(entier_avant(&trop, contenu.len(), loin), None);
        // Plausible pour sa taille (1 Mio), mais l'échéance passe : arrêté après la première tranche.
        let gros = vec![7u8; 1 << 20];
        let lent = vides_puis(4 * TRANCHE, &gros);
        assert!(lent.len() <= compresse_plausible(gros.len()));
        assert_eq!(entier_avant(&lent, gros.len(), loin).map(|c| c.len()), Some(gros.len()));
        assert_eq!(entier_avant(&lent, gros.len(), std::time::Instant::now()), None);
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
