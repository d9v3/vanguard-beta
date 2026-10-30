//! Prédiction du mot en cours de frappe, la même dans tous les menus : en tapant « wi », la fin du mot le plus
//! probable (« fi » de « wifi ») s'affiche en gris après le curseur, et Tab ou → la complète. Les mots viennent de ce
//! que le menu sait trouver (textes, précisions, mots cachés des outils et des commandes du guide), et une prédiction
//! mène toujours à au moins une ligne : elle n'invente rien.

use std::collections::{HashMap, HashSet};

use crate::selection::simplifier;

/// Les mots trop courants pour aider (sous leur forme simplifiée) : jamais prédits.
const MOTS_VIDES: &[&str] = &[
    "aux", "avec", "ces", "cette", "dans", "des", "elle", "est", "les", "leur", "lui", "mais", "par", "pas", "plus",
    "pour", "que", "qui", "sans", "ses", "son", "sont", "sur", "tous", "tout", "toute", "une", "all", "and", "any",
    "are", "but", "can", "for", "from", "has", "its", "not", "one", "that", "the", "this", "with", "you", "your",
];

/// Un mot du menu.
struct Mot {
    /// Sa forme simplifiée (`selection::simplifier`) : celle que compare la recherche.
    simple: String,
    /// Sa forme montrée, en minuscules, accents gardés : la plus courante dans le menu.
    montre: String,
    /// Le nombre de lignes du menu qui le contiennent.
    lignes: usize,
}

/// Les mots d'un menu, triés par forme simplifiée.
pub struct Vocabulaire {
    mots: Vec<Mot>,
}

/// Les mots d'un texte : lettres et chiffres, tirets intérieurs compris (« wi-fi », « list-units »).
fn decouper(texte: &str) -> impl Iterator<Item = &str> {
    texte
        .split(|c: char| !c.is_alphanumeric() && c != '-')
        .map(|m| m.trim_matches('-'))
        .filter(|m| !m.is_empty())
}

/// La suite de `montre` après ce qui, une fois simplifié, donne `voulu` : « eau » pour « réseau » et « res ».
fn suite_de(montre: &str, voulu: &str) -> Option<String> {
    let mut lu = String::new();
    for (i, c) in montre.char_indices() {
        if lu == voulu {
            return Some(montre[i..].to_string());
        }
        lu.push_str(&simplifier(&c.to_string()));
        if !voulu.starts_with(lu.as_str()) {
            return None;
        }
    }
    None
}

impl Vocabulaire {
    /// Les mots de `textes` : tout ce que la recherche lit de chaque ligne, un texte par ligne, sans codes de couleur.
    pub fn nouveau<S: AsRef<str>>(textes: &[S]) -> Self {
        // Pour chaque forme simplifiée : ses formes montrées et leur nombre, et le nombre de lignes où elle paraît.
        let mut formes: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut lignes: HashMap<String, usize> = HashMap::new();
        for texte in textes {
            let mut vus = HashSet::new();
            for mot in decouper(texte.as_ref()) {
                let montre = mot.to_lowercase();
                let simple = simplifier(&montre);
                if simple.chars().count() < 3
                    || simple.chars().all(|c| c.is_ascii_digit())
                    || MOTS_VIDES.contains(&simple.as_str())
                {
                    continue;
                }
                *formes.entry(simple.clone()).or_default().entry(montre).or_default() += 1;
                if vus.insert(simple.clone()) {
                    *lignes.entry(simple).or_default() += 1;
                }
            }
        }
        // À égalité, la forme accentuée l'emporte : « réseau » plutôt que « reseau ».
        let accents = |m: &str| m.chars().filter(|c| !c.is_ascii()).count();
        let mut mots: Vec<Mot> = formes
            .into_iter()
            .filter_map(|(simple, f)| {
                let montre = f
                    .into_iter()
                    .max_by(|(a, na), (b, nb)| na.cmp(nb).then(accents(a).cmp(&accents(b))).then(b.cmp(a)))?
                    .0;
                Some(Mot {
                    lignes: lignes.get(&simple).copied().unwrap_or(0),
                    simple,
                    montre,
                })
            })
            .collect();
        mots.sort_by(|a, b| a.simple.cmp(&b.simple));
        Vocabulaire { mots }
    }

    /// La suite du dernier mot de `tape`, à montrer en gris après le curseur : celle du mot le plus courant du menu
    /// qui commence ainsi et, une fois complété, trouve encore au moins une ligne avec les autres mots tapés.
    /// `trouve` dit si une recherche trouve au moins une ligne du menu (la première suffit : des milliers de lignes
    /// se parcourent à chaque touche). `None` : rien à prédire (mot de moins de deux lettres, espace à la fin, touche
    /// comme « 4.2 », aucun mot qui mène à une ligne).
    pub fn suite(&self, tape: &str, trouve: impl Fn(&str) -> bool) -> Option<String> {
        if tape.ends_with(char::is_whitespace) {
            return None;
        }
        let dernier = tape.split_whitespace().last()?;
        let voulu = simplifier(dernier);
        if voulu.chars().count() < 2 || !dernier.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return None;
        }
        let debut = self.mots.partition_point(|m| m.simple < voulu);
        // Un mot déjà entier (« disque », « tar ») ne se fait rien proposer : on a sans doute tapé ce qu'on voulait,
        // pas « disques » ni « target ».
        if self.mots.get(debut).is_some_and(|m| m.simple == voulu) {
            return None;
        }
        let mut candidats: Vec<&Mot> = self
            .mots
            .iter()
            .skip(debut)
            .take_while(|m| m.simple.starts_with(voulu.as_str()))
            .filter(|m| m.simple.len() > voulu.len())
            .collect();
        // Le plus courant dans les textes du menu (pas dans les chemins : « Windows 11 › » sur chaque ligne d'un
        // système ne doit pas faire prédire « windows » à qui tape « wi » pour « wifi »), puis le plus court.
        candidats.sort_by(|a, b| {
            b.lignes
                .cmp(&a.lignes)
                .then(a.simple.len().cmp(&b.simple.len()))
                .then(a.simple.cmp(&b.simple))
        });
        candidats.into_iter().take(20).find_map(|m| {
            let suite = suite_de(&m.montre, &voulu)?;
            trouve(&format!("{tape}{suite}")).then_some(suite)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::correspond;

    /// La prédiction sur ces lignes, avec la vraie recherche des menus.
    fn predire(lignes: &[&str], tape: &str) -> Option<String> {
        let cherche: Vec<String> = lignes.iter().map(|l| simplifier(l)).collect();
        Vocabulaire::nouveau(lignes).suite(tape, |q| cherche.iter().any(|c| correspond(q, c)))
    }

    #[test]
    fn le_mot_le_plus_courant_du_menu() {
        let menu = [
            "Scanner le réseau Wi-Fi",
            "Réseaux wifi enregistrés",
            "Windows Update",
            "Mot de passe du wifi",
        ];
        assert_eq!(predire(&menu, "wi").as_deref(), Some("fi"));
        assert_eq!(predire(&menu, "win").as_deref(), Some("dows"));
        // Accents gardés dans la suite, qu'on tape l'accent ou non.
        assert_eq!(predire(&menu, "res").as_deref(), Some("eau"));
        assert_eq!(predire(&menu, "rés").as_deref(), Some("eau"));
        // Majuscules : la suite reste en minuscules, la recherche n'en tient pas compte.
        assert_eq!(predire(&menu, "WI").as_deref(), Some("fi"));
        // Un tiret intérieur suit le mot.
        assert_eq!(predire(&["Wi-Fi seulement"], "wi").as_deref(), Some("-fi"));
        assert_eq!(predire(&["Wi-Fi seulement"], "wif").as_deref(), Some("i"));
    }

    #[test]
    fn rien_a_predire() {
        let menu = ["Scanner le réseau", "Pour tout le monde", "Disque et disques externes"];
        // Une lettre seule, une espace à la fin, une touche, un mot inconnu.
        for tape in ["r", "reseau ", "4.2", "4.", "zzz", ""] {
            assert_eq!(predire(&menu, tape), None, "{tape}");
        }
        // Les mots vides ne se prédisent pas ; un mot déjà entier ne se fait pas proposer son pluriel.
        assert_eq!(predire(&menu, "po"), None);
        assert_eq!(predire(&menu, "disque"), None);
        assert_eq!(predire(&menu, "disq").as_deref(), Some("ue"));
    }

    #[test]
    fn les_autres_mots_tapes_comptent() {
        // « sa » seul : « sauvegarde », plus courant ; après « disque » : « santé », qui garde une ligne.
        let menu = ["Sauvegarde automatique", "Sauvegarde vers une clé", "Santé du disque"];
        assert_eq!(predire(&menu, "sa").as_deref(), Some("uvegarde"));
        assert_eq!(predire(&menu, "disque sa").as_deref(), Some("nté"));
        // Aucun mot ne mène à une ligne avec « clé » : rien.
        assert_eq!(predire(&menu, "clé san"), None);
    }
}

/// Menus et saisies au hasard : jamais de plantage, et une suite prédite mène toujours à au moins une ligne.
#[cfg(test)]
mod tests_au_hasard {
    use super::*;
    use crate::selection::correspond;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn une_prediction_trouve_toujours_quelque_chose(
            lignes in prop::collection::vec("[a-zéèçœ\\- ]{0,40}|\\PC{0,30}", 0..12),
            tape in "[a-zéœ\\- .4]{0,12}|\\PC{0,8}",
        ) {
            let cherche: Vec<String> = lignes.iter().map(|l| simplifier(l)).collect();
            let trouve = |q: &str| cherche.iter().any(|c| correspond(q, c));
            if let Some(suite) = Vocabulaire::nouveau(&lignes).suite(&tape, trouve) {
                prop_assert!(!suite.is_empty());
                let complet = format!("{tape}{suite}");
                prop_assert!(trouve(&complet));
            }
        }
    }
}
