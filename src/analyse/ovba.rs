//! La compression des projets VBA ([MS-OVBA] 2.4.1) : un octet de signature 0x01, puis des morceaux d'au plus
//! 4 098 octets qui donnent chacun au plus 4 096 octets. En-tête de morceau (16 bits, petit-boutiste) : taille du
//! morceau moins 3 (12 bits), signature 0b011 (3 bits), drapeau (1 bit : compressé, sinon 4 096 octets bruts). Un
//! morceau compressé est une suite de séquences : un octet de drapeaux (bit de poids faible d'abord), puis huit
//! jetons, littéral (un octet) ou copie (16 bits : longueur et distance, dont le partage dépend de la position dans
//! le morceau, au moins 4 bits de distance, « CopyToken Help » 2.4.1.3.19.1).
//!
//! Une copie hostile peut désigner avant le début du morceau (hors du tampon) : refusée. La sortie est bornée par
//! l'appelant et par morceau (4 096). Ce qui a pu être décompressé avant un défaut est rendu avec lui : la source
//! d'une macro coupée reste cherchable, et le défaut est dit.
//!
//! Lecteur pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

/// Pourquoi la décompression s'est arrêtée avant la fin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Defaut {
    /// Pas l'octet 0x01 au début.
    Signature,
    /// Un en-tête de morceau dont la signature n'est pas 0b011, ou coupé.
    EnTete,
    /// Une copie qui désigne avant le début du morceau, ou un morceau qui donnerait plus de 4 096 octets.
    Copie,
    /// Un jeton ou un morceau brut coupé par la fin des données.
    Tronque,
    /// La borne de l'appelant atteinte.
    Limite,
}

/// Le résultat : ce qui a été décompressé, et le défaut qui a arrêté la lecture (`None` : tout est lu).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decompresse {
    pub contenu: Vec<u8>,
    pub defaut: Option<Defaut>,
}

const MORCEAU: usize = 4096;

/// Le conteneur compressé `conteneur` (qui va jusqu'à la fin des octets donnés), au plus `limite` octets.
pub(crate) fn decompresser(conteneur: &[u8], limite: usize) -> Decompresse {
    let mut sortie = Vec::new();
    let defaut = boucle(conteneur, limite, &mut sortie).err();
    Decompresse {
        contenu: sortie,
        defaut,
    }
}

fn boucle(c: &[u8], limite: usize, sortie: &mut Vec<u8>) -> Result<(), Defaut> {
    if c.first() != Some(&0x01) {
        return Err(Defaut::Signature);
    }
    let mut pos = 1usize;
    while pos < c.len() {
        let debut_morceau = pos;
        let en_tete = match c.get(pos..).and_then(<[u8]>::first_chunk::<2>) {
            Some(b) => u16::from_le_bytes(*b),
            None => return Err(Defaut::EnTete),
        };
        let taille = usize::from(en_tete & 0x0FFF) + 3;
        if (en_tete >> 12) & 0b111 != 0b011 {
            return Err(Defaut::EnTete);
        }
        let compresse = en_tete & 0x8000 != 0;
        let debut_sortie = sortie.len();
        let fin = c.len().min(debut_morceau + taille);
        pos = debut_morceau + 2;
        if !compresse {
            // Un morceau brut : 4 096 octets tels quels.
            let reste = c.get(pos..).ok_or(Defaut::Tronque)?;
            let brut = reste.get(..MORCEAU).unwrap_or(reste);
            let place = limite.saturating_sub(sortie.len());
            sortie.extend_from_slice(brut.get(..place).unwrap_or(brut));
            if brut.len() > place {
                return Err(Defaut::Limite);
            }
            if brut.len() < MORCEAU {
                return Err(Defaut::Tronque);
            }
            pos += MORCEAU;
            continue;
        }
        while pos < fin {
            let &drapeaux = c.get(pos).ok_or(Defaut::Tronque)?;
            pos += 1;
            for indice in 0..8 {
                if pos >= fin {
                    break;
                }
                if drapeaux >> indice & 1 == 0 {
                    if sortie.len() >= limite {
                        return Err(Defaut::Limite);
                    }
                    sortie.push(*c.get(pos).ok_or(Defaut::Tronque)?);
                    pos += 1;
                } else {
                    let Some(b) = c
                        .get(pos..)
                        .and_then(<[u8]>::first_chunk::<2>)
                        .filter(|_| pos + 2 <= fin)
                    else {
                        return Err(Defaut::Tronque);
                    };
                    let jeton = u16::from_le_bytes(*b);
                    let ecart = sortie.len() - debut_sortie;
                    if ecart == 0 {
                        // Rien avant dans ce morceau : une copie n'a rien à copier.
                        return Err(Defaut::Copie);
                    }
                    // Le plus petit entier ≥ log2(écart), au moins 4 (et au plus 12 : un morceau fait 4 096 octets).
                    let bits = (ecart - 1).bit_width().max(4);
                    if bits > 12 {
                        return Err(Defaut::Copie);
                    }
                    let masque_longueur = 0xFFFFu16 >> bits;
                    let longueur = usize::from(jeton & masque_longueur) + 3;
                    let distance = usize::from(jeton >> (16 - bits)) + 1;
                    if distance > ecart {
                        return Err(Defaut::Copie);
                    }
                    if ecart + longueur > MORCEAU {
                        return Err(Defaut::Copie);
                    }
                    if sortie.len() + longueur > limite {
                        return Err(Defaut::Limite);
                    }
                    // Octet par octet : la source peut chevaucher ce qui s'écrit (une répétition).
                    let source = sortie.len() - distance;
                    for k in 0..longueur {
                        let &o = sortie.get(source + k).ok_or(Defaut::Copie)?;
                        sortie.push(o);
                    }
                    pos += 2;
                }
            }
            if sortie.len() - debut_sortie > MORCEAU {
                return Err(Defaut::Copie);
            }
        }
        pos = pos.max(fin);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod essais {
    //! Une compression simple, écrite d'après la même section (2.4.1.3.6 à 2.4.1.3.19.4) : de quoi fabriquer des
    //! modules VBA compressés pour les tests, sans document tiers.

    /// `donnees` compressées : par morceaux de 4 096, chaque morceau en séquences de jetons ; les copies cherchent
    /// la plus longue répétition dans le morceau (recherche directe, lente mais juste).
    pub(crate) fn compresser(donnees: &[u8]) -> Vec<u8> {
        let mut sortie = vec![0x01u8];
        for morceau in donnees.chunks(super::MORCEAU) {
            let mut corps = Vec::new();
            let mut i = 0usize;
            while i < morceau.len() {
                let mut drapeaux = 0u8;
                let mut jetons = Vec::new();
                for indice in 0..8 {
                    if i >= morceau.len() {
                        break;
                    }
                    let bits = i.saturating_sub(1).bit_width().max(4) as usize;
                    let longueur_max = (0xFFFFusize >> bits) + 3;
                    let (mut meilleure, mut distance) = (0usize, 0usize);
                    // Les 512 positions précédentes seulement : plus court, toujours juste.
                    for debut in i.saturating_sub(512)..i {
                        let mut n = 0;
                        while n < longueur_max && i + n < morceau.len() && morceau[debut + n] == morceau[i + n] {
                            n += 1;
                        }
                        if n > meilleure {
                            meilleure = n;
                            distance = i - debut;
                        }
                    }
                    if meilleure >= 3 {
                        let jeton = u16::try_from(((distance - 1) << (16 - bits)) | (meilleure - 3)).unwrap();
                        jetons.extend(jeton.to_le_bytes());
                        drapeaux |= 1 << indice;
                        i += meilleure;
                    } else {
                        jetons.push(morceau[i]);
                        i += 1;
                    }
                }
                corps.push(drapeaux);
                corps.extend(jetons);
            }
            let en_tete = 0xB000u16 | u16::try_from(corps.len() + 2 - 3).unwrap();
            sortie.extend(en_tete.to_le_bytes());
            sortie.extend(corps);
        }
        sortie
    }
}

#[cfg(test)]
mod tests {
    use super::essais::compresser;
    use super::*;

    /// Les exemples de [MS-OVBA] 3.2.1 (sans copie) et 3.2.2 (« Normal Compression Example »), octet pour octet.
    #[test]
    fn exemples_de_la_specification() {
        let sans_copie = [
            0x01, 0x19, 0xB0, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x00, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
            0x6E, 0x6F, 0x70, 0x00, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x2E,
        ];
        let lu = decompresser(&sans_copie, 1 << 16);
        assert_eq!(
            (lu.defaut, lu.contenu.as_slice()),
            (None, &b"abcdefghijklmnopqrstuv."[..])
        );
        let normal = [
            0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70, 0x61, 0x67,
            0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x20, 0x6D, 0x6E, 0x6F, 0x70, 0x06, 0x71, 0x02,
            0x70, 0x04, 0x00, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x2C,
        ];
        let lu = decompresser(&normal, 1 << 16);
        assert_eq!(
            (lu.defaut, lu.contenu.as_slice()),
            (None, &b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa"[..])
        );
        // Notre compression donne ce que la décompression relit (pas forcément les mêmes octets que l'exemple).
        assert_eq!(decompresser(&compresser(&lu.contenu), 1 << 16).contenu, lu.contenu);
    }

    #[test]
    fn aller_retour_et_bornes() {
        let source =
            "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  MsgBox \"bonjour\"\r\nEnd Sub\r\n".repeat(150);
        let c = compresser(source.as_bytes());
        let lu = decompresser(&c, 1 << 20);
        assert_eq!((lu.defaut, lu.contenu.as_slice()), (None, source.as_bytes()));
        // La borne : le début, et dit.
        let lu = decompresser(&c, 100);
        assert_eq!(lu.defaut, Some(Defaut::Limite));
        assert!(lu.contenu.len() <= 100 && source.as_bytes().starts_with(&lu.contenu));
        // Coupé : ce qui précède, et dit.
        let lu = decompresser(&c[..c.len() / 2], 1 << 20);
        assert!(lu.defaut.is_some());
        assert!(source.as_bytes().starts_with(&lu.contenu));
        assert_eq!(decompresser(b"\x02", 10).defaut, Some(Defaut::Signature));
        assert_eq!(decompresser(b"", 10).defaut, Some(Defaut::Signature));
        assert_eq!(decompresser(b"\x01", 10).defaut, None);
    }

    /// Une copie qui désigne avant le début du morceau (hors du tampon), une copie en tête de morceau.
    #[test]
    fn copies_hors_du_tampon() {
        // Drapeaux 0b10 : un littéral « a », puis une copie de distance 16 (jeton 0xF000 : 4 bits de distance à 15,
        // longueur 3) alors qu'un seul octet précède.
        let c = [0x01, 0x05, 0xB0, 0b10, b'a', 0x00, 0xF0];
        assert_eq!(decompresser(&c, 100).defaut, Some(Defaut::Copie));
        let c = [0x01, 0x03, 0xB0, 0b1, 0x00, 0x00];
        assert_eq!(decompresser(&c, 100).defaut, Some(Defaut::Copie));
        // Un morceau brut annoncé, coupé.
        let mut brut = vec![0x01, 0xFF, 0x3F];
        brut.extend([b'x'; 100]);
        let lu = decompresser(&brut, 1 << 16);
        assert_eq!((lu.defaut, lu.contenu.len()), (Some(Defaut::Tronque), 100));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 600, failure_persistence: None, ..proptest::prelude::ProptestConfig::default() })]
        #[test]
        fn jamais_de_plantage(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..3000), limite in 0usize..20_000) {
            let mut c = vec![0x01];
            c.extend(&octets);
            let lu = decompresser(&c, limite);
            proptest::prop_assert!(lu.contenu.len() <= limite);
        }

        #[test]
        fn aller_retour(donnees in proptest::collection::vec(0u8..4, 0..9000)) {
            let lu = decompresser(&compresser(&donnees), 1 << 20);
            proptest::prop_assert_eq!(lu.defaut, None);
            proptest::prop_assert_eq!(lu.contenu, donnees);
        }
    }
}
