//! La progression d'une commande pour la fenêtre : quand elle la demande (variable `VANGUARD_PROGRESSION=1`, posée par
//! son lanceur), chaque étape finie s'écrit sur la sortie des erreurs en une ligne de forme fixe, `@etape 3/9 Comptes`.
//! Jamais sur la sortie : le JSON reste identique, avec ou sans. La fenêtre la relit strictement
//! (`fenetre/src/progression.rs`) ; ici, la ligne est bornée de la même façon (nombres de 1 à 9999, libellé court,
//! sans caractère de contrôle), pour qu'aucune étape écrite ne soit refusée là-bas.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::sync::OnceLock;

/// La variable que la fenêtre pose.
pub const VARIABLE: &str = "VANGUARD_PROGRESSION";
/// Le plus grand nombre d'étapes écrit (celui que la fenêtre accepte).
const NOMBRE_MAX: usize = 9999;
/// Le libellé, en caractères au plus.
const LIBELLE_MAX: usize = 60;

/// La fenêtre a demandé la progression (lu une fois).
pub fn active() -> bool {
    static ACTIVE: OnceLock<bool> = OnceLock::new();
    *ACTIVE.get_or_init(|| std::env::var_os(VARIABLE).is_some_and(|v| v == "1"))
}

/// La ligne d'une étape : `fait` sur `total` (bornés, `fait` au plus `total`), puis le libellé sur une ligne, sans
/// caractère de contrôle ni de mise en forme, coupé à `LIBELLE_MAX` caractères. `None` quand `total` est nul.
pub fn ligne(fait: usize, total: usize, libelle: &str) -> Option<String> {
    if total == 0 {
        return None;
    }
    let total = total.min(NOMBRE_MAX);
    let fait = fait.min(total);
    let libelle: String = libelle
        .chars()
        .map(|c| if c.is_control() || est_format(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(LIBELLE_MAX)
        .collect();
    Some(format!("@etape {fait}/{total} {libelle}").trim_end().to_owned())
}

/// Les caractères invisibles qui changent l'affichage (sens d'écriture, jointures).
fn est_format(c: char) -> bool {
    matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{2069}' | '\u{feff}')
}

/// Écrit l'étape sur la sortie des erreurs, seulement quand la fenêtre l'a demandé. Une ligne entière par appel
/// (`eprintln!` tient la sortie le temps de la ligne) : des fils qui finissent ensemble ne s'entremêlent pas.
pub fn etape(fait: usize, total: usize, libelle: &str) {
    if active()
        && let Some(l) = ligne(fait, total, libelle)
    {
        eprintln!("{l}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_ligne_a_la_forme_que_la_fenetre_lit() {
        assert_eq!(ligne(3, 9, "Comptes").as_deref(), Some("@etape 3/9 Comptes"));
        assert_eq!(ligne(0, 1, "").as_deref(), Some("@etape 0/1"));
        assert_eq!(ligne(5, 0, "x"), None);
        // Bornée : jamais plus que le total, jamais plus de 9999.
        assert_eq!(ligne(12, 9, "x").as_deref(), Some("@etape 9/9 x"));
        assert_eq!(ligne(20_000, 20_000, "x").as_deref(), Some("@etape 9999/9999 x"));
        // Une seule ligne, sans contrôle ni inversion du sens, courte.
        let l = ligne(1, 2, "a\nb\u{1b}[31m\u{202e}c\t d").unwrap_or_default();
        assert_eq!(l, "@etape 1/2 a b [31m c d");
        let long = ligne(1, 2, &"é".repeat(200)).unwrap_or_default();
        assert_eq!(long.chars().count(), "@etape 1/2 ".chars().count() + LIBELLE_MAX);
    }
}
