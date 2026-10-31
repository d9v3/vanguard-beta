//! Les entiers de SQLite (src/sqlite.rs) : un fichier fabriqué choisit chaque octet. Kani prouve, pour toutes les
//! entrées dans la borne, l'absence de panique et de débordement, et l'aller-retour avec l'encodage de SQLite.

use super::{entier, taille_colonne, varint};

/// L'encodage de SQLite (sqlite3PutVarint), écrit à part : 1 à 8 octets de 7 bits, de poids fort en tête, le bit
/// haut à 1 sauf sur le dernier ; au-delà de 56 bits, 8 octets de 7 bits puis un dernier octet entier.
fn encoder(v: u64) -> ([u8; 9], usize) {
    let septet = |x: u64| (x & 0x7f).to_le_bytes()[0];
    let mut sortie = [0u8; 9];
    if v >> 56 != 0 {
        sortie[8] = v.to_le_bytes()[0];
        let mut reste = v >> 8;
        for i in (0..8).rev() {
            sortie[i] = septet(reste) | 0x80;
            reste >>= 7;
        }
        return (sortie, 9);
    }
    let mut n = 1;
    while n < 8 && v >> (7 * n) != 0 {
        n += 1;
    }
    for i in 0..n {
        let groupe = septet(v >> (7 * (n - 1 - i)));
        sortie[i] = if i + 1 < n { groupe | 0x80 } else { groupe };
    }
    (sortie, n)
}

/// Tout tampon de 0 à 10 octets : jamais de panique ; la longueur lue est dans le tampon et entre 1 et 9 ; sur
/// moins de 9 octets, la valeur tient dans 7 bits par octet lu. `None` seulement sur un tampon trop court.
#[kani::proof]
#[kani::unwind(11)]
fn varint_borne() {
    let octets: [u8; 10] = kani::any();
    let n = kani::any_where(|n: &usize| *n <= 10);
    match varint(&octets[..n]) {
        Some((v, lus)) => {
            assert!((1..=9).contains(&lus) && lus <= n);
            if lus < 9 {
                assert_eq!(v >> (7 * lus), 0);
            }
        }
        None => {
            assert!(n < 9 && octets[..n].iter().all(|o| o & 0x80 != 0));
        }
    }
}

/// Toute valeur de 64 bits, encodée comme SQLite, se relit à l'identique et sur la même longueur.
#[kani::proof]
#[kani::unwind(10)]
fn varint_aller_retour() {
    let v: u64 = kani::any();
    let (octets, n) = encoder(v);
    assert_eq!(varint(&octets[..n]), Some((v, n)));
}

/// Tout type de série et tout tampon de 0 à 8 octets : ni panique ni débordement ; un entier des types 1 à 6 (1, 2,
/// 3, 4, 6 ou 8 octets) tient dans ses octets, et il n'est lu que si le tampon les contient.
#[kani::proof]
#[kani::unwind(9)]
fn entier_borne() {
    let type_serie: u64 = kani::any();
    let octets: [u8; 8] = kani::any();
    let n = kani::any_where(|n: &usize| *n <= 8);
    let taille = taille_colonne(type_serie);
    let lu = entier(type_serie, &octets[..n]);
    if (1..=6).contains(&type_serie) {
        let t = taille.unwrap();
        assert_eq!(lu.is_some(), t <= n);
        if let Some(v) = lu
            && t < 8
        {
            assert_eq!(v >> (8 * t), 0);
        }
    }
}
