//! La progression d'une commande, telle que `vanguard` l'écrit sur sa sortie des erreurs quand la fenêtre la demande
//! (variable `VANGUARD_PROGRESSION=1`, posée par `lanceur`) : une ligne de forme fixe, `@etape 3/9 Comptes`. Jamais
//! sur la sortie : le JSON reste intact. La ligne vient d'un programme qui pourrait être remplacé : elle est lue
//! strictement (deux nombres bornés, le premier au plus le second, un libellé nettoyé et court) ; toute autre forme
//! n'est pas une étape et reste une ligne ordinaire de la console.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// La variable que la fenêtre pose pour demander la progression.
pub const VARIABLE: &str = "VANGUARD_PROGRESSION";
/// Le début de chaque ligne de progression.
pub const PREFIXE: &str = "@etape ";
/// Le plus grand nombre d'étapes lu.
pub const NOMBRE_MAX: u32 = 9999;
/// Le libellé, en caractères au plus.
pub const LIBELLE_MAX: usize = 60;
/// Une ligne plus longue (en octets) n'est pas lue : le préfixe, deux nombres de quatre chiffres, le libellé.
const LIGNE_MAX: usize = 7 + 4 + 1 + 4 + 1 + LIBELLE_MAX * 4;

/// Une étape lue : `fait` sur `total` (1 ≤ total ≤ NOMBRE_MAX, fait ≤ total), et ce qui vient de finir.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Etape {
    pub fait: u32,
    pub total: u32,
    pub libelle: String,
}

impl Etape {
    /// La part faite, entre 0 et 1.
    pub fn part(&self) -> f32 {
        // Deux nombres d'au plus quatre chiffres : exacts en f32.
        f32::from(u16::try_from(self.fait).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(self.total).unwrap_or(u16::MAX).max(1))
    }
}

/// Un nombre décimal de 1 à 4 chiffres, sans signe ni zéro en tête (sauf « 0 » seul).
fn nombre(s: &str) -> Option<u32> {
    let ok =
        !s.is_empty() && s.len() <= 4 && s.bytes().all(|o| o.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

/// Lit une ligne de la sortie des erreurs : `Some` seulement pour une étape de la forme exacte.
pub fn lire(ligne: &str) -> Option<Etape> {
    if ligne.len() > LIGNE_MAX {
        return None;
    }
    let reste = ligne.strip_prefix(PREFIXE)?;
    let (compte, libelle) = reste.split_once(' ').unwrap_or((reste, ""));
    let (fait, total) = compte.split_once('/')?;
    let (fait, total) = (nombre(fait)?, nombre(total)?);
    if total == 0 || total > NOMBRE_MAX || fait > total {
        return None;
    }
    let libelle = crate::nettoyage::nom(libelle.trim(), LIBELLE_MAX);
    Some(Etape { fait, total, libelle })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seule_la_forme_exacte_est_une_etape() {
        assert_eq!(
            lire("@etape 3/9 Comptes"),
            Some(Etape {
                fait: 3,
                total: 9,
                libelle: "Comptes".into()
            })
        );
        assert_eq!(lire("@etape 0/1").map(|e| e.libelle), Some(String::new()));
        assert!(lire("@etape 9999/9999 x").is_some());
        for faux in [
            "@etape",
            "@etape ",
            "@etape 3",
            "@etape 3/",
            "@etape /9",
            "@etape 10/9 trop",
            "@etape 1/0",
            "@etape 1/10000",
            "@etape 01/9",
            "@etape +1/9",
            "@etape -1/9",
            "@etape 1/9x",
            "@etape  1/9",
            "@ETAPE 1/9",
            " @etape 1/9",
            "étape 1/9",
            "@etape ١/٩",
        ] {
            assert_eq!(lire(faux), None, "{faux:?}");
        }
        // Le libellé est nettoyé et borné ; une ligne immense n'est pas lue.
        let e = lire("@etape 1/2 a\u{202e}b\u{1b}[31mc").unwrap();
        assert!(!e.libelle.contains('\u{202e}') && !e.libelle.contains('\u{1b}'));
        let long = format!("@etape 1/2 {}", "é".repeat(50));
        assert!(lire(&long).unwrap().libelle.chars().count() <= LIBELLE_MAX);
        assert_eq!(lire(&format!("@etape 1/2 {}", "x".repeat(LIGNE_MAX))), None);
        assert!((lire("@etape 1/4").unwrap().part() - 0.25).abs() < 1e-6);
    }
}
