//! La neutralisation Markdown du brouillon : il sera collé dans GitHub ou Bugzilla, qui interprètent le Markdown. Un
//! nom de fichier choisi par n'importe qui (« x`@bob <img src=…> ») ne doit ni notifier quelqu'un, ni charger une
//! image, ni ajouter un lien ou un titre au rapport de la personne.
//!
//! Pourquoi un fichier à part, pur et sans aucun `crate::` : le masquage (`garde`) lit la base des appareils et ne peut
//! pas entrer dans le banc de fuzzing (fuzz/) ; la neutralisation, elle, y entre telle quelle.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Les caractères que GitHub ou Bugzilla interprètent hors d'un bloc de code : la barre oblique inverse d'abord (sinon
/// « \@ » écrit par quelqu'un redeviendrait « \\@ », une barre échappée suivie d'une mention), l'accent grave (code en
/// ligne), « @ » (mention qui notifie), « < » et « > » (HTML, citation), « [ » « ] » « ! » (lien, image), « # » (titre,
/// renvoi vers un ticket), « | » (tableau), « & » (entité HTML qui écrirait « @ » autrement).
const SPECIAUX: &[char] = &['\\', '`', '@', '<', '>', '[', ']', '!', '#', '|', '&'];

/// Un texte écrit par la personne (ses réponses), prêt à entrer tel quel dans le Markdown, hors d'un bloc de code :
/// chaque caractère spécial est précédé d'une barre oblique inverse. Les sauts de ligne restent.
pub(crate) fn neutraliser_markdown(texte: &str) -> String {
    // Une réserve, pas une borne : saturer ne changerait que la place demandée d'avance.
    let mut sortie = String::with_capacity(texte.len().saturating_add(texte.len() / 8));
    for c in texte.chars() {
        if SPECIAUX.contains(&c) {
            sortie.push('\\');
        }
        sortie.push(c);
    }
    sortie
}

/// La plus longue suite d'accents graves du texte.
fn plus_longue_suite(texte: &str) -> usize {
    // L'accent grave tient sur un octet : la longueur d'une suite est son nombre d'accents.
    texte.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// Un texte venu de l'extérieur (nom de fichier, de programme, titre d'une alerte), dans un bloc de code délimité par
/// une clôture plus longue que sa plus longue suite d'accents graves : rien de ce qu'il contient ne la ferme, et
/// rien n'y est interprété (ni mention, ni image, ni lien).
pub(crate) fn bloc_de_code(texte: &str) -> String {
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "la suite tient dans le texte : au plus isize::MAX octets, + 1 ne déborde pas"
    )]
    let cloture = "`".repeat(plus_longue_suite(texte).max(2) + 1);
    format!("{cloture}\n{texte}\n{cloture}")
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// Le texte sans ses échappements : ce que le Markdown montre.
    fn sans_echappements(t: &str) -> (String, bool) {
        let mut vu = String::new();
        let mut libre_special = false;
        let mut car = t.chars();
        while let Some(c) = car.next() {
            if c == '\\' {
                if let Some(suivant) = car.next() {
                    vu.push(suivant);
                }
                continue;
            }
            libre_special |= SPECIAUX.contains(&c);
            vu.push(c);
        }
        (vu, libre_special)
    }

    #[test]
    fn cas_fixes() {
        let piege = "x`@bob <img src=x onerror=alert(1)> [x](y) ![i](y) # titre | a | &#64;bob \\@bob";
        let n = neutraliser_markdown(piege);
        let (vu, libre) = sans_echappements(&n);
        assert_eq!(vu, piege);
        assert!(!libre, "{n}");
        assert!(n.contains("\\@bob") && n.contains("\\<img") && n.contains("\\[x\\]") && n.contains("\\!\\["));
        assert!(n.contains("\\# titre") && n.contains("\\|") && n.contains("\\&\\#64;"));
        // Une barre oblique écrite par la personne est échappée elle aussi : « \@ » ne redevient pas une mention.
        assert!(n.ends_with("\\\\\\@bob"), "{n}");
    }

    #[test]
    fn la_cloture_est_plus_longue_que_le_texte() {
        assert_eq!(bloc_de_code("a"), "```\na\n```");
        assert_eq!(bloc_de_code("a ``` b"), "````\na ``` b\n````");
        assert_eq!(bloc_de_code("``````"), "```````\n``````\n```````");
        assert_eq!(bloc_de_code(""), "```\n\n```");
    }

    proptest! {
        /// Hors d'un bloc, aucun caractère spécial ne reste libre, et le texte montré est celui écrit.
        #[test]
        fn rien_ne_reste_libre(t in "[a-z@<>\\[\\]!#|&`\\\\ \n()é]{0,60}") {
            let n = neutraliser_markdown(&t);
            let (vu, libre) = sans_echappements(&n);
            prop_assert_eq!(vu, t);
            prop_assert!(!libre);
        }

        /// Dans un bloc, aucune ligne du texte ne ferme la clôture, et le texte est gardé tel quel.
        #[test]
        fn le_texte_ne_ferme_jamais_le_bloc(t in "[a-z`@<>\n ]{0,80}") {
            let b = bloc_de_code(&t);
            let cloture = b.lines().next().unwrap().to_string();
            prop_assert!(cloture.len() >= 3 && cloture.chars().all(|c| c == '`'));
            let dedans = &b[cloture.len() + 1..b.len() - cloture.len() - 1];
            prop_assert_eq!(dedans, t.as_str());
            for l in dedans.lines() {
                prop_assert!(!l.trim().starts_with(cloture.as_str()), "{}", l);
            }
        }
    }
}
