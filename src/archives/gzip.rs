//! gzip (RFC 1952), lu par miniz_oxide : l'en-tête sauté (nom, commentaire, champ libre et son contrôle), puis le
//! flux deflate. Deux lectures : `degzip`, celle des fichiers de cet ordinateur (bases de pacman, mtree), qui ne
//! regarde pas la fin du membre ; `degzip_controle`, celle des fichiers téléchargés, qui vérifie en plus le CRC-32 et
//! la taille écrits à la fin de chaque membre : un téléchargement coupé ou abîmé ne passe pas pour un fichier entier.
//!
//! Lecteur pur (miniz_oxide seul, sans `crate::`) : le banc de fuzzing l'inclut par son chemin. Les deux lectures
//! sont donc compilées partout, sans servir partout.

/// Les trois premiers octets d'un gzip (deflate, la seule méthode définie).
pub(crate) fn est_gzip(octets: &[u8]) -> bool {
    octets.starts_with(&[0x1f, 0x8b, 8])
}

/// Où commence le flux deflate d'un membre qui commence en `debut`. `None` : pas du gzip, ou en-tête coupé.
fn debut_du_flux(octets: &[u8], debut: usize) -> Option<usize> {
    const FHCRC: u8 = 2;
    const FEXTRA: u8 = 4;
    const FNAME: u8 = 8;
    const FCOMMENT: u8 = 16;
    let membre = octets.get(debut..)?;
    if !est_gzip(membre) {
        return None;
    }
    let drapeaux = *membre.get(3)?;
    let mut pos = 10usize;
    if drapeaux & FEXTRA != 0 {
        let n = u16::from_le_bytes([*membre.get(pos)?, *membre.get(pos + 1)?]);
        pos += 2 + usize::from(n);
    }
    for champ in [FNAME, FCOMMENT] {
        if drapeaux & champ != 0 {
            pos += membre.get(pos..)?.iter().position(|&o| o == 0)? + 1;
        }
    }
    if drapeaux & FHCRC != 0 {
        pos += 2;
    }
    // L'en-tête entier doit être là : sinon le flux commencerait hors du fichier.
    (pos <= membre.len()).then_some(debut + pos)
}

#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))] // bases de pacman, mtree
/// Le contenu d'un gzip : le premier membre, au plus `limite` octets. `None` si ce n'est pas du gzip, s'il est abîmé
/// ou s'il dépasse la limite. La fin du membre (CRC, taille) n'est pas lue : un fichier de cet ordinateur, que le
/// système de fichiers garde entier.
pub(crate) fn degzip(octets: &[u8], limite: usize) -> Option<Vec<u8>> {
    let pos = debut_du_flux(octets, 0)?;
    miniz_oxide::inflate::decompress_to_vec_with_limit(octets.get(pos..)?, limite).ok()
}

#[cfg_attr(not(any(windows, target_os = "macos", test)), allow(dead_code))] // logiciels pas à jour
/// Le contenu d'un gzip téléchargé, au plus `limite` octets en tout : chaque membre (un serveur peut en mettre
/// plusieurs bout à bout) est décompressé, puis son CRC-32 et sa taille, écrits à sa fin, sont vérifiés. `None` : pas
/// du gzip, coupé, abîmé, plus grand que la limite (une « bombe » de quelques Kio qui en donnerait des Go s'arrête à
/// la limite), ou suivi d'autre chose qu'un membre.
pub(crate) fn degzip_controle(octets: &[u8], limite: usize) -> Option<Vec<u8>> {
    let mut contenu = Vec::new();
    let mut debut = 0usize;
    loop {
        let flux = debut_du_flux(octets, debut)?;
        let (membre, lus) = inflater(octets.get(flux..)?, limite - contenu.len())?;
        let fin = flux.checked_add(lus)?;
        let crc = u32::from_le_bytes(octets.get(fin..fin + 4)?.try_into().ok()?);
        let taille = u32::from_le_bytes(octets.get(fin + 4..fin + 8)?.try_into().ok()?);
        // La taille est écrite modulo 2³² (RFC 1952, ISIZE).
        #[allow(clippy::cast_possible_truncation)]
        if crc != super::crc32::crc32(&membre) || taille != membre.len() as u32 {
            return None;
        }
        contenu.extend_from_slice(&membre);
        debut = fin + 8;
        if debut == octets.len() {
            return Some(contenu);
        }
    }
}

#[cfg_attr(not(any(windows, target_os = "macos", test)), allow(dead_code))] // logiciels pas à jour
/// Le flux deflate de `flux`, au plus `limite` octets, et le nombre d'octets qu'il occupe (pour trouver la fin du
/// membre, qui le suit). Le même travail que `decompress_to_vec_with_limit`, qui ne dit pas où le flux finit.
fn inflater(flux: &[u8], limite: usize) -> Option<(Vec<u8>, usize)> {
    use miniz_oxide::inflate::TINFLStatus;
    use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
    let drapeaux = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let mut sortie = vec![0u8; flux.len().saturating_mul(2).clamp(64, 1 << 20).min(limite)];
    let mut decodeur = Box::<DecompressorOxide>::default();
    let (mut lus, mut ecrits) = (0usize, 0usize);
    loop {
        let (etat, consommes, produits) = decompress(&mut decodeur, flux.get(lus..)?, &mut sortie, ecrits, drapeaux);
        lus = lus.checked_add(consommes)?;
        ecrits = ecrits.checked_add(produits)?;
        match etat {
            TINFLStatus::Done => {
                sortie.truncate(ecrits);
                return Some((sortie, lus));
            }
            TINFLStatus::HasMoreOutput if sortie.len() < limite => {
                let nouvelle = sortie.len().saturating_mul(2).min(limite);
                sortie.resize(nouvelle, 0);
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::crc32::crc32;
    use super::*;

    /// Un membre gzip fait à la main : en-tête de 10 octets (et ses champs facultatifs), flux deflate, CRC et taille.
    fn membre(contenu: &[u8], entete: &[u8]) -> Vec<u8> {
        let mut gz = entete.to_vec();
        gz.extend(miniz_oxide::deflate::compress_to_vec(contenu, 6));
        gz.extend(crc32(contenu).to_le_bytes());
        gz.extend(u32::try_from(contenu.len()).unwrap().to_le_bytes());
        gz
    }

    const SIMPLE: [u8; 10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];

    #[test]
    fn gzip_lu_sans_zcat() {
        let texte = b"#mtree\n./usr/bin/sudo time=1 sha256digest=00ff\n";
        let flux = miniz_oxide::deflate::compress_to_vec(texte, 6);
        // En-tête avec un nom de fichier (FNAME), comme gzip l'écrit ; la fin (CRC, taille) est ignorée.
        let mut gz = vec![0x1f, 0x8b, 8, 8, 0, 0, 0, 0, 0, 3];
        gz.extend_from_slice(b".MTREE\0");
        gz.extend_from_slice(&flux);
        gz.extend_from_slice(&[0; 8]);
        assert_eq!(degzip(&gz, 1 << 20).as_deref(), Some(&texte[..]));
        // Champ libre (FEXTRA) et contrôle d'en-tête (FHCRC).
        let mut gz = vec![0x1f, 0x8b, 8, 4 | 2, 0, 0, 0, 0, 0, 3, 3, 0, 1, 2, 3, 0xaa, 0xbb];
        gz.extend_from_slice(&flux);
        assert_eq!(degzip(&gz, 1 << 20).as_deref(), Some(&texte[..]));
        assert!(degzip("#mtree pas compressé".as_bytes(), 1 << 20).is_none());
        assert!(degzip(&[0x1f, 0x8b, 8, 8, 0], 1 << 20).is_none());
        assert!(est_gzip(&gz) && !est_gzip(b"{\"total\": 1}"));
    }

    #[test]
    fn controle_du_crc_et_de_la_taille() {
        let texte = "{\"total\": 485, \"result\": []}\n".repeat(50);
        let bon = membre(texte.as_bytes(), &SIMPLE);
        assert_eq!(degzip_controle(&bon, 1 << 20).as_deref(), Some(texte.as_bytes()));
        // Tous les champs facultatifs de l'en-tête : nom, commentaire, champ libre, contrôle de l'en-tête.
        let mut entete = vec![0x1f, 0x8b, 8, 2 | 4 | 8 | 16, 0, 0, 0, 0, 0, 3, 2, 0, 0xab, 0xcd];
        entete.extend(b"full.json\0commentaire\0");
        entete.extend([0x12, 0x34]);
        assert_eq!(
            degzip_controle(&membre(texte.as_bytes(), &entete), 1 << 20).as_deref(),
            Some(texte.as_bytes())
        );
        // CRC faux, taille fausse : refusés.
        let mut crc_faux = bon.clone();
        let n = crc_faux.len();
        crc_faux[n - 8] ^= 1;
        assert_eq!(degzip_controle(&crc_faux, 1 << 20), None);
        let mut taille_fausse = bon.clone();
        taille_fausse[n - 1] ^= 1;
        assert_eq!(degzip_controle(&taille_fausse, 1 << 20), None);
        // Coupé, n'importe où : jamais lu comme entier.
        for coupe in [n - 1, n - 4, n - 8, n / 2, 11, 3] {
            assert_eq!(degzip_controle(&bon[..coupe], 1 << 20), None, "coupé à {coupe}");
        }
        // Deux membres bout à bout : les deux contenus, dans l'ordre.
        let mut deux = bon.clone();
        deux.extend(membre(b"suite\n", &SIMPLE));
        let attendu = [texte.as_bytes(), b"suite\n"].concat();
        assert_eq!(degzip_controle(&deux, 1 << 20), Some(attendu));
        // Autre chose qu'un membre après le premier : refusé (le reste ne serait pas lu).
        let mut suivi = bon.clone();
        suivi.extend(b"<html>");
        assert_eq!(degzip_controle(&suivi, 1 << 20), None);
        // Une page de portail Wi-Fi, du vide.
        assert_eq!(degzip_controle(b"<html>Connexion requise</html>", 1 << 20), None);
        assert_eq!(degzip_controle(&[], 1 << 20), None);
    }

    /// Une bombe : quelques Kio de gzip qui en donneraient 16 Mio. La limite l'arrête, sans tout décompresser.
    #[test]
    fn bombe_arretee_a_la_limite() {
        let gros = vec![0u8; 16 << 20];
        let bombe = membre(&gros, &SIMPLE);
        assert!(bombe.len() < 64 << 10, "{}", bombe.len());
        assert_eq!(degzip_controle(&bombe, 4 << 20), None);
        assert_eq!(degzip(&bombe, 4 << 20), None);
        assert_eq!(degzip_controle(&bombe, 16 << 20).map(|v| v.len()), Some(16 << 20));
        // Deux membres dont la somme dépasse la limite.
        let mut deux = membre(&gros[..1 << 20], &SIMPLE);
        deux.extend(membre(&gros[..1 << 20], &SIMPLE));
        assert_eq!(degzip_controle(&deux, (2 << 20) - 1), None);
        assert_eq!(degzip_controle(&deux, 2 << 20).map(|v| v.len()), Some(2 << 20));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..400)) {
            let _ = degzip(&octets, 1 << 16);
            let _ = degzip_controle(&octets, 1 << 16);
            let mut gz = SIMPLE.to_vec();
            gz.extend(&octets);
            let _ = degzip(&gz, 1 << 16);
            let _ = degzip_controle(&gz, 1 << 16);
        }

        /// Un gzip valide se relit tel quel ; abîmé d'un octet, il est refusé ou relu à l'identique, jamais faux.
        #[test]
        fn relu_ou_refuse(contenu in proptest::collection::vec(proptest::num::u8::ANY, 0..2000), i in 0usize..4000, x in 1u8..=255) {
            let gz = membre(&contenu, &SIMPLE);
            let lu = degzip_controle(&gz, 1 << 16);
            proptest::prop_assert_eq!(lu.as_deref(), Some(&contenu[..]));
            let mut abime = gz.clone();
            let i = i % abime.len();
            abime[i] ^= x;
            if let Some(lu) = degzip_controle(&abime, 1 << 16) {
                proptest::prop_assert_eq!(lu, contenu);
            }
        }
    }
}
