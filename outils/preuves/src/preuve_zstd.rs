//! La lecture des bits du décodeur zstd (src/machine/linux/zstd.rs) : les champs compressés du journal de systemd
//! viennent de n'importe quel compte. Kani prouve, pour tout tampon et toute position dans la borne, que `bits` rend
//! exactement les bits demandés, et que le flux à l'envers (`Arriere`) ne panique ni ne déborde jamais.

use super::{Arriere, bits};

/// Le bit `i` (petit-boutiste) du tampon, zéro au-delà de la fin : la définition, un bit à la fois.
fn bit(octets: &[u8], i: usize) -> u64 {
    octets.get(i / 8).map_or(0, |o| u64::from((o >> (i % 8)) & 1))
}

/// Pour tout tampon de 0 à 9 octets, toute position jusqu'à 80 bits et toute largeur jusqu'à 57 bits (le contrat de
/// `bits`) : la valeur rendue est celle que donne la lecture bit à bit, zéros au-delà de la fin compris.
#[kani::proof]
#[kani::unwind(58)]
fn bits_comme_bit_a_bit() {
    let octets: [u8; 9] = kani::any();
    let longueur = kani::any_where(|l: &usize| *l <= 9);
    let debut = kani::any_where(|d: &usize| *d <= 80);
    let n = kani::any_where(|n: &u32| *n <= 57);
    let tampon = &octets[..longueur];
    let mut attendu = 0u64;
    for i in 0..n as usize {
        attendu |= bit(tampon, debut + i) << i;
    }
    assert_eq!(bits(tampon, debut, n), attendu);
}

/// Pour tout tampon de 0 à 8 octets et trois lectures de 0 à 57 bits chacune : jamais de panique ni de débordement ;
/// chaque valeur tient sur la largeur demandée ; ce qui reste à lire ne fait que baisser, de la largeur lue, et la
/// lecture au-delà du début est notée (débordement), une fois pour toutes.
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
        let n = kani::any_where(|n: &u32| *n <= 57);
        let (avant, deborde_avant) = (flux.restant, flux.deborde);
        let v = flux.lire(n);
        assert_eq!(v >> n, 0);
        let depasse = n as usize > avant;
        assert_eq!(flux.restant, if depasse { 0 } else { avant - n as usize });
        assert_eq!(flux.deborde, deborde_avant || depasse);
    }
}
