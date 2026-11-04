//! Conversions entre entiers et flottants. Rust n'a que `as` pour elles : elles vivent ici, une fois, chacune sous sa
//! levée et sa raison (LANG-ARITH, CONFORMITE-ANSSI.md), au lieu d'un `as` caché dans chaque calcul. Les flottants
//! servent à montrer (débits, pourcentages, tailles, positions d'une fenêtre), jamais à compter.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Un entier positif en flottant. Un nombre qui ne tient pas dans un u64 vaut u64::MAX ; au-delà de 2^53, arrondi.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[allow(clippy::cast_precision_loss)]
#[expect(
    clippy::as_conversions,
    reason = "entier vers f64 : seul `as` existe ; une valeur à montrer, arrondie"
)]
pub(crate) fn flottant<T: TryInto<u64>>(n: T) -> f64 {
    n.try_into().unwrap_or(u64::MAX) as f64
}

/// Un flottant ramené à un entier positif : `as` sature (négatif ou NaN : 0, trop grand : u64::MAX), tronque la
/// partie décimale.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
#[expect(
    clippy::as_conversions,
    reason = "f64 vers u64 : seul `as` existe, et il sature au lieu de déborder"
)]
pub(crate) fn entier(x: f64) -> u64 {
    x as u64
}

/// Un flottant ramené à un entier signé : `as` sature (NaN : 0), tronque la partie décimale.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[allow(clippy::cast_possible_truncation)]
#[expect(
    clippy::as_conversions,
    reason = "f64 vers i64 : seul `as` existe, et il sature au lieu de déborder"
)]
pub(crate) fn entier_signe(x: f64) -> i64 {
    x as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les bornes : rien ne déborde ni ne panique, les valeurs ordinaires sont exactes.
    #[test]
    fn conversions_bornees() {
        assert!((flottant(1_048_576u64) - 1_048_576.0).abs() < f64::EPSILON);
        assert!((flottant(usize::MAX) - 18_446_744_073_709_551_615.0).abs() < 1.0e4);
        assert_eq!(entier(-1.0), 0);
        assert_eq!(entier(f64::NAN), 0);
        assert_eq!(entier(1.0e30), u64::MAX);
        assert_eq!(entier(41.9), 41);
        assert_eq!(entier_signe(-41.9), -41);
        assert_eq!(entier_signe(f64::NAN), 0);
        assert_eq!(entier_signe(-1.0e30), i64::MIN);
    }
}
