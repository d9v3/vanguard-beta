//! Les fichiers d'une archive zip : seulement des fichiers stockés tels quels ou compressés (deflate), sans zip64 ni
//! chiffrement, comme tldr-pages en publie. Le répertoire central est cherché depuis la fin, puis chaque entrée lue à
//! la position que donne son en-tête local.

use super::Bornes;

/// Les fichiers (nom, contenu). Une entrée illisible, hors des bornes ou dont le contenu n'a pas la taille annoncée
/// est sautée ; une archive illisible donne une liste vide. Au plus `entrees` entrées parcourues, `fichier` octets
/// par fichier, `total` en tout.
pub(crate) fn lire(octets: &[u8], bornes: &Bornes) -> Vec<(String, Vec<u8>)> {
    // La fin du répertoire central, cherchée depuis la fin (un commentaire peut la suivre).
    let Some(fin) = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
    else {
        return Vec::new();
    };
    let (Some(nombre), Some(debut)) = (u16_a(octets, fin + 10), u32_a(octets, fin + 16)) else {
        return Vec::new();
    };
    let mut fichiers = Vec::new();
    let mut total = 0;
    let mut i = debut as usize;
    for _ in 0..usize::from(nombre).min(bornes.entrees) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            break;
        }
        let Some((methode, compresse, taille, longueur_nom, autres, local)) = entree_centrale(octets, i) else {
            break;
        };
        let nom = octets
            .get(i + 46..i + 46 + longueur_nom)
            .map(|n| String::from_utf8_lossy(n).into_owned());
        i += 46 + longueur_nom + autres;
        let Some(nom) = nom else { break };
        if taille > bornes.fichier || total + taille > bornes.total {
            continue;
        }
        let donnees = donnees_locales(octets, local, compresse);
        // La taille rendue doit être celle annoncée, qui a passé les bornes : une entrée qui ment (annoncée minuscule,
        // décompressée bien plus grande) ferait sinon dépasser la borne du total.
        let contenu = match (methode, donnees) {
            (0, Some(d)) if d.len() == taille => Some(d.to_vec()),
            (8, Some(d)) => miniz_oxide::inflate::decompress_to_vec_with_limit(d, taille)
                .ok()
                .filter(|c| c.len() == taille),
            _ => None,
        };
        if let Some(contenu) = contenu {
            total += contenu.len();
            fichiers.push((nom, contenu));
        }
    }
    fichiers
}

/// Pourquoi une archive n'est pas intacte (`controler`) ; le numéro est celui de l'entrée dans le répertoire central.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaut {
    /// Pas de fin de répertoire central : pas un zip, ou coupé.
    PasUnZip,
    /// Zip64, ou une archive sur plusieurs disques : ces champs ne disent alors plus rien, tldr-pages n'en fait pas.
    NonPrise,
    /// Trop d'entrées, ou une entrée (ou leur somme) annoncée plus grande que les bornes : refusée sans décompresser.
    Demesuree,
    /// Une entrée illisible : en-tête coupé, nom différent dans l'en-tête local, contenu de la mauvaise taille.
    Illisible(usize),
    /// Chiffrée, ou ni stockée ni compressée par deflate.
    Methode(usize),
    /// Lue, mais son CRC-32 n'est pas celui annoncé.
    Crc(usize),
}

/// Le contrôle entier d'une archive, comme `zipfile.testzip()` de Python : chaque entrée du répertoire central relue
/// à son en-tête local (même nom), décompressée, à sa taille et à son CRC-32 annoncés. Une seule qui ne va pas, et
/// l'archive entière est refusée (`lire`, lui, la saute). Au plus `entrees` entrées, `fichier` octets annoncés par
/// entrée et `total` en tout, jugés avant de décompresser. Rend les noms des entrées, dans l'ordre.
pub(crate) fn controler(octets: &[u8], bornes: &Bornes) -> Result<Vec<String>, Defaut> {
    let fin = (0..octets.len().saturating_sub(21))
        .rev()
        .take(65_557)
        .find(|&i| u32_a(octets, i) == Some(0x0605_4b50))
        .ok_or(Defaut::PasUnZip)?;
    let champ16 = |d: usize| u16_a(octets, fin + d).ok_or(Defaut::PasUnZip);
    let (disque, disque_central, ici, nombre) = (champ16(4)?, champ16(6)?, champ16(8)?, champ16(10)?);
    let (taille_centrale, debut) = (
        u32_a(octets, fin + 12).ok_or(Defaut::PasUnZip)?,
        u32_a(octets, fin + 16).ok_or(Defaut::PasUnZip)?,
    );
    if disque != 0 || disque_central != 0 || ici != nombre || nombre == 0xFFFF {
        return Err(Defaut::NonPrise);
    }
    if taille_centrale == 0xFFFF_FFFF || debut == 0xFFFF_FFFF {
        return Err(Defaut::NonPrise);
    }
    if usize::from(nombre) > bornes.entrees {
        return Err(Defaut::Demesuree);
    }
    let mut noms = Vec::with_capacity(usize::from(nombre));
    let mut total: usize = 0;
    let mut i = debut as usize;
    for n in 0..usize::from(nombre) {
        if u32_a(octets, i) != Some(0x0201_4b50) {
            return Err(Defaut::Illisible(n));
        }
        let (Some(drapeaux), Some(crc), Some((methode, compresse, taille, longueur_nom, autres, local))) =
            (u16_a(octets, i + 8), u32_a(octets, i + 16), entree_centrale(octets, i))
        else {
            return Err(Defaut::Illisible(n));
        };
        let nom = octets.get(i + 46..i + 46 + longueur_nom).ok_or(Defaut::Illisible(n))?;
        i += 46 + longueur_nom + autres;
        // Bit 0 : chiffrée ; bit 6 : chiffrement « fort ». Ni l'un ni l'autre ne se relit sans mot de passe.
        if drapeaux & 0x41 != 0 || !matches!(methode, 0 | 8) {
            return Err(Defaut::Methode(n));
        }
        total = total.saturating_add(taille);
        if taille > bornes.fichier || total > bornes.total {
            return Err(Defaut::Demesuree);
        }
        // Le nom de l'en-tête local doit être celui du répertoire central, comme le veut zipfile.
        let longueur_locale = u16_a(octets, local + 26).map(usize::from);
        if longueur_locale != Some(longueur_nom) || octets.get(local + 30..local + 30 + longueur_nom) != Some(nom) {
            return Err(Defaut::Illisible(n));
        }
        let donnees = donnees_locales(octets, local, compresse).ok_or(Defaut::Illisible(n))?;
        let contenu = match methode {
            0 => (donnees.len() == taille).then(|| donnees.to_vec()),
            // Un octet de marge : un contenu plus long que la taille annoncée se voit à sa longueur.
            _ => miniz_oxide::inflate::decompress_to_vec_with_limit(donnees, taille.saturating_add(1))
                .ok()
                .filter(|c| c.len() == taille),
        }
        .ok_or(Defaut::Illisible(n))?;
        if super::crc32::crc32(&contenu) != crc {
            return Err(Defaut::Crc(n));
        }
        noms.push(String::from_utf8_lossy(nom).into_owned());
    }
    Ok(noms)
}

fn u16_a(octets: &[u8], i: usize) -> Option<u16> {
    octets.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_a(octets: &[u8], i: usize) -> Option<u32> {
    octets
        .get(i..i + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Une entrée du répertoire central : (méthode, taille compressée, taille, longueur du nom, longueur des champs qui
/// suivent le nom, position de l'en-tête local).
fn entree_centrale(octets: &[u8], i: usize) -> Option<(u16, usize, usize, usize, usize, usize)> {
    Some((
        u16_a(octets, i + 10)?,
        u32_a(octets, i + 20)? as usize,
        u32_a(octets, i + 24)? as usize,
        usize::from(u16_a(octets, i + 28)?),
        usize::from(u16_a(octets, i + 30)?) + usize::from(u16_a(octets, i + 32)?),
        u32_a(octets, i + 42)? as usize,
    ))
}

/// Les données d'un fichier, après son en-tête local.
fn donnees_locales(octets: &[u8], local: usize, compresse: usize) -> Option<&[u8]> {
    (u32_a(octets, local)? == 0x0403_4b50).then_some(())?;
    let depart = local + 30 + usize::from(u16_a(octets, local + 26)?) + usize::from(u16_a(octets, local + 28)?);
    octets.get(depart..depart.checked_add(compresse)?)
}

#[cfg(test)]
pub(crate) mod essais {
    //! Des archives zip fabriquées pour les tests d'ici et de la clé (`guide::tldr::cle`) : aucun zip tiers.

    /// Un zip fabriqué ici : (nom, méthode, contenu), le CRC calculé par `crc32`, les tailles justes.
    pub(crate) fn archive_controlee(entrees: &[(&str, u16, &[u8])]) -> Vec<u8> {
        let mut zip = Vec::new();
        let mut central = Vec::new();
        for (nom, methode, contenu) in entrees {
            let donnees = if *methode == 8 {
                miniz_oxide::deflate::compress_to_vec(contenu, 6)
            } else {
                contenu.to_vec()
            };
            let local = u32::try_from(zip.len()).unwrap();
            let (crc, compresse, taille) = (
                super::super::crc32::crc32(contenu),
                u32::try_from(donnees.len()).unwrap(),
                u32::try_from(contenu.len()).unwrap(),
            );
            let longueur = u16::try_from(nom.len()).unwrap();
            zip.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            zip.extend_from_slice(&[20, 0, 0, 0]);
            zip.extend_from_slice(&methode.to_le_bytes());
            zip.extend_from_slice(&[0; 4]);
            for v in [crc, compresse, taille] {
                zip.extend_from_slice(&v.to_le_bytes());
            }
            zip.extend_from_slice(&longueur.to_le_bytes());
            zip.extend_from_slice(&[0, 0]);
            zip.extend_from_slice(nom.as_bytes());
            zip.extend_from_slice(&donnees);
            central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            central.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            central.extend_from_slice(&methode.to_le_bytes());
            central.extend_from_slice(&[0; 4]);
            for v in [crc, compresse, taille] {
                central.extend_from_slice(&v.to_le_bytes());
            }
            central.extend_from_slice(&longueur.to_le_bytes());
            central.extend_from_slice(&[0; 12]);
            central.extend_from_slice(&local.to_le_bytes());
            central.extend_from_slice(nom.as_bytes());
        }
        let debut = u32::try_from(zip.len()).unwrap();
        let nombre = u16::try_from(entrees.len()).unwrap();
        let taille = u32::try_from(central.len()).unwrap();
        zip.extend_from_slice(&central);
        zip.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        zip.extend_from_slice(&[0; 4]);
        zip.extend_from_slice(&nombre.to_le_bytes());
        zip.extend_from_slice(&nombre.to_le_bytes());
        zip.extend_from_slice(&taille.to_le_bytes());
        zip.extend_from_slice(&debut.to_le_bytes());
        zip.extend_from_slice(&[0, 0]);
        zip
    }
}

#[cfg(test)]
mod tests {
    use super::essais::archive_controlee;
    use super::*;

    /// Une archive zip faite à la main : (nom, données telles qu'écrites, méthode, taille annoncée) par entrée.
    fn archive(entrees: &[(&str, Vec<u8>, u16, u32)]) -> Vec<u8> {
        let (mut zip, mut central) = (Vec::new(), Vec::new());
        for (nom, donnees, methode, taille) in entrees {
            let local = u32::try_from(zip.len()).unwrap();
            let compresse = u32::try_from(donnees.len()).unwrap();
            let longueur = u16::try_from(nom.len()).unwrap();
            zip.extend(0x0403_4b50u32.to_le_bytes());
            zip.extend([20, 0, 0, 0]);
            zip.extend(methode.to_le_bytes());
            zip.extend([0u8; 8]);
            zip.extend(compresse.to_le_bytes());
            zip.extend(taille.to_le_bytes());
            zip.extend(longueur.to_le_bytes());
            zip.extend([0, 0]);
            zip.extend(nom.as_bytes());
            zip.extend(donnees);
            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend([20, 0, 20, 0, 0, 0]);
            central.extend(methode.to_le_bytes());
            central.extend([0u8; 8]);
            central.extend(compresse.to_le_bytes());
            central.extend(taille.to_le_bytes());
            central.extend(longueur.to_le_bytes());
            central.extend([0u8; 12]);
            central.extend(local.to_le_bytes());
            central.extend(nom.as_bytes());
        }
        let debut = u32::try_from(zip.len()).unwrap();
        let n = u16::try_from(entrees.len()).unwrap();
        let taille_centrale = u32::try_from(central.len()).unwrap();
        zip.extend(central);
        zip.extend(0x0605_4b50u32.to_le_bytes());
        zip.extend([0, 0, 0, 0]);
        zip.extend(n.to_le_bytes());
        zip.extend(n.to_le_bytes());
        zip.extend(taille_centrale.to_le_bytes());
        zip.extend(debut.to_le_bytes());
        zip.extend([0, 0]);
        zip
    }

    #[test]
    fn stockees_et_compressees() {
        let texte = b"# exemple\n\n> Une page inventee.\n".repeat(20);
        let deflate = miniz_oxide::deflate::compress_to_vec(&texte, 6);
        let taille = u32::try_from(texte.len()).unwrap();
        let zip = archive(&[
            ("pages/common/a.md", b"stockee".to_vec(), 0, 7),
            ("pages/common/b.md", deflate, 8, taille),
            ("pages/common/c.md", b"xx".to_vec(), 0, 3),
        ]);
        let bornes = Bornes {
            entrees: 10,
            fichier: 1 << 16,
            total: 1 << 16,
        };
        let lus = lire(&zip, &bornes);
        assert_eq!(lus.len(), 2, "la taille fausse de c.md l'écarte");
        assert_eq!(lus[0], ("pages/common/a.md".to_string(), b"stockee".to_vec()));
        assert_eq!(lus[1].1, texte);
    }

    /// Une entrée compressée qui ment sur sa taille (annoncée minuscule, décompressée bien plus grande) : écartée, et
    /// les bornes tiennent sur ce qui est rendu, pas sur ce qui est annoncé.
    #[test]
    fn taille_annoncee_fausse() {
        let gros = vec![b'a'; 60_000];
        let deflate = miniz_oxide::deflate::compress_to_vec(&gros, 6);
        let entrees: Vec<(String, Vec<u8>, u16, u32)> = (0..20)
            .map(|i| (format!("pages/common/{i}.md"), deflate.clone(), 8, 1))
            .collect();
        let entrees: Vec<(&str, Vec<u8>, u16, u32)> = entrees
            .iter()
            .map(|(n, d, m, t)| (n.as_str(), d.clone(), *m, *t))
            .collect();
        let bornes = Bornes {
            entrees: 100,
            fichier: 1 << 16,
            total: 1 << 17,
        };
        let lus = lire(&archive(&entrees), &bornes);
        assert!(lus.iter().map(|(_, c)| c.len()).sum::<usize>() <= bornes.total);
        assert!(lus.is_empty(), "{} entrées rendues", lus.len());
    }

    const BORNES_CONTROLE: Bornes = Bornes {
        entrees: 100,
        fichier: 1 << 16,
        total: 1 << 17,
    };

    /// Ce que `zipfile.testzip()` refusait, et un peu plus : l'archive entière est refusée pour une seule entrée.
    #[test]
    fn controle_entier() {
        let texte: &[u8] = b"# tar\n\n> Archiver.\n\n- Creer :\n\n`tar cf a.tar b`\n";
        let bonne = archive_controlee(&[
            ("pages/", 0, b""),
            ("pages/common/tar.md", 8, texte),
            ("pages/linux/ls.md", 0, b"# ls\n"),
        ]);
        assert_eq!(
            controler(&bonne, &BORNES_CONTROLE),
            Ok(vec![
                "pages/".to_string(),
                "pages/common/tar.md".to_string(),
                "pages/linux/ls.md".to_string()
            ])
        );
        // Un octet de données inversé dans la page stockée : elle se lit encore (`lire` la rend), seul le CRC le voit.
        let position = bonne.windows(5).position(|f| f == b"# ls\n").unwrap();
        let mut inversee = bonne.clone();
        inversee[position + 2] ^= 0x20;
        assert_eq!(lire(&inversee, &BORNES_CONTROLE).len(), 3);
        assert_eq!(controler(&inversee, &BORNES_CONTROLE), Err(Defaut::Crc(2)));
        // Le CRC changé dans le répertoire central.
        let central = bonne
            .windows(4)
            .position(|f| f == 0x0201_4b50u32.to_le_bytes())
            .unwrap();
        let mut crc = bonne.clone();
        crc[central + 16] ^= 1;
        assert_eq!(controler(&crc, &BORNES_CONTROLE), Err(Defaut::Crc(0)));
        // Chiffrée (bit 0), ou chiffrement fort (bit 6), dans le répertoire central.
        for bit in [1u8, 0x40] {
            let mut chiffree = bonne.clone();
            chiffree[central + 8] |= bit;
            assert_eq!(controler(&chiffree, &BORNES_CONTROLE), Err(Defaut::Methode(0)));
        }
        // Méthode 12 (bzip2) : inconnue, refusée.
        let bzip = archive_controlee(&[("pages/linux/ls.md", 12, b"# ls\n")]);
        assert_eq!(controler(&bzip, &BORNES_CONTROLE), Err(Defaut::Methode(0)));
        // Un autre nom dans l'en-tête local que dans le répertoire central.
        let mut nom = bonne.clone();
        let local = nom.windows(19).position(|f| f == b"pages/common/tar.md").unwrap();
        nom[local] = b'P';
        assert_eq!(controler(&nom, &BORNES_CONTROLE), Err(Defaut::Illisible(1)));
        // Tronquée, ou sans fin de répertoire central.
        assert!(controler(&bonne[..bonne.len() / 2], &BORNES_CONTROLE).is_err());
        assert_eq!(controler(b"pas un zip", &BORNES_CONTROLE), Err(Defaut::PasUnZip));
        assert_eq!(controler(&[], &BORNES_CONTROLE), Err(Defaut::PasUnZip));
    }

    /// Les formes que le lecteur ne sait pas lire, et les bornes, jugées avant de décompresser.
    #[test]
    fn controle_formes_et_bornes() {
        let bonne = archive_controlee(&[("pages/linux/ls.md", 0, b"# ls\n")]);
        let fin = bonne.len() - 22;
        // Une archive sur plusieurs disques, ou des entrées sur un autre disque.
        let mut disques = bonne.clone();
        disques[fin + 4] = 1;
        assert_eq!(controler(&disques, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        let mut ailleurs = bonne.clone();
        ailleurs[fin + 8] = 0;
        assert_eq!(controler(&ailleurs, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        // Les marques de zip64.
        let mut zip64 = bonne.clone();
        zip64[fin + 16..fin + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(controler(&zip64, &BORNES_CONTROLE), Err(Defaut::NonPrise));
        // Plus d'entrées que la borne.
        let noms: Vec<String> = (0..3).map(|n| format!("pages/common/{n}.md")).collect();
        let trois: Vec<(&str, u16, &[u8])> = noms.iter().map(|n| (n.as_str(), 0, &b"x"[..])).collect();
        let bornes = Bornes {
            entrees: 2,
            ..BORNES_CONTROLE
        };
        assert_eq!(controler(&archive_controlee(&trois), &bornes), Err(Defaut::Demesuree));
        // Une entrée annoncée trop grosse, ou leur somme : refusées sans être décompressées.
        let gros = vec![b'a'; 200_000];
        let bombe = archive_controlee(&[("pages/common/a.md", 8, &gros)]);
        assert_eq!(controler(&bombe, &BORNES_CONTROLE), Err(Defaut::Demesuree));
        let moyen = vec![b'a'; 50_000];
        let somme = archive_controlee(&[
            ("pages/common/a.md", 8, &moyen),
            ("pages/common/b.md", 8, &moyen),
            ("pages/common/c.md", 8, &moyen),
        ]);
        assert_eq!(controler(&somme, &BORNES_CONTROLE), Err(Defaut::Demesuree));
        // Une entrée qui ment sur sa taille (annoncée 1, décompressée en 50 000) : illisible.
        let mut ment = archive_controlee(&[("pages/common/a.md", 8, &moyen)]);
        let central = ment.windows(4).position(|f| f == 0x0201_4b50u32.to_le_bytes()).unwrap();
        ment[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(controler(&ment, &BORNES_CONTROLE), Err(Defaut::Illisible(0)));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 2000, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let bornes = Bornes { entrees: 100, fichier: 1 << 12, total: 1 << 14 };
            let _ = lire(&octets, &bornes);
            let _ = controler(&octets, &bornes);
            // Une fin de répertoire central en queue : le parcours des entrées est essayé, pas seulement la recherche.
            let mut avec_fin = octets.clone();
            avec_fin.extend(0x0605_4b50u32.to_le_bytes());
            avec_fin.extend([0, 0, 0, 0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            let _ = lire(&avec_fin, &bornes);
            let _ = controler(&avec_fin, &bornes);
        }
    }
}
