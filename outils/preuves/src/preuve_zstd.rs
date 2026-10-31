//! La lecture des bits du décodeur zstd (src/machine/linux/zstd.rs) : les champs compressés du journal de systemd
//! viennent de n'importe quel compte. Kani prouve, pour tout tampon et toute position dans la borne, que `bits` rend
//! exactement les bits demandés (et zéro pour une largeur nulle ou au-delà de 57 bits), et que le flux à l'envers
//! (`Arriere`) ne panique ni ne déborde jamais, quelle que soit la largeur demandée.

use super::{Arriere, bits};

/// Le bit `i` (petit-boutiste) du tampon, zéro au-delà de la fin : la définition, un bit à la fois.
fn bit(octets: &[u8], i: usize) -> u64 {
    octets.get(i / 8).map_or(0, |o| u64::from((o >> (i % 8)) & 1))
}

/// Pour tout tampon de 0 à 9 octets, toute position jusqu'à 80 bits et toute largeur (le contrat de `bits`) : jusqu'à
/// 57 bits, la valeur rendue est celle que donne la lecture bit à bit, zéros au-delà de la fin compris ; au-delà de
/// 57 bits, zéro, gardé dans `bits` et non chez les appelants.
#[kani::proof]
#[kani::unwind(58)]
fn bits_comme_bit_a_bit() {
    let octets: [u8; 9] = kani::any();
    let longueur = kani::any_where(|l: &usize| *l <= 9);
    let debut = kani::any_where(|d: &usize| *d <= 80);
    let n: u32 = kani::any();
    let tampon = &octets[..longueur];
    if n > 57 {
        assert_eq!(bits(tampon, debut, n), 0);
        return;
    }
    let mut attendu = 0u64;
    for i in 0..n as usize {
        attendu |= bit(tampon, debut + i) << i;
    }
    assert_eq!(bits(tampon, debut, n), attendu);
}

/// Pour tout tampon de 0 à 8 octets et trois lectures de n'importe quelle largeur : jamais de panique ni de
/// débordement ; chaque valeur tient sur la largeur demandée (zéro au-delà de 57 bits) ; ce qui reste à lire ne fait
/// que baisser, de la largeur lue, et une lecture au-delà du début ou de plus de 57 bits est notée (débordement), une
/// fois pour toutes, et vide le flux.
#[kani::proof]
#[kani::unwind(10)]
fn arriere_borne() {
    let octets: [u8; 8] = kani::any();
    let longueur = kani::any_where(|l: &usize| *l <= 8);
    let tampon = &octets[..longueur];
    let Some(mut flux) = Arriere::new(tampon) else {
        assert!(longueur == 0 || octets[longueur - 1] == 0);
        return;
    };
    assert!(flux.restant < longueur * 8 && !flux.deborde);
    for _ in 0..3 {
        let n: u32 = kani::any();
        let (avant, deborde_avant) = (flux.restant, flux.deborde);
        let v = flux.lire(n);
        assert_eq!(v.checked_shr(n).unwrap_or(0), 0);
        assert!(n <= 57 || v == 0);
        let depasse = n as usize > avant || n > 57;
        assert_eq!(flux.restant, if depasse { 0 } else { avant - n as usize });
        assert_eq!(flux.deborde, deborde_avant || depasse);
    }
}
