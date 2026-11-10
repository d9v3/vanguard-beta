//! Ce que les commandes de `vanguard` écrivent en JSON, relu pour l'affichage. Jamais de panique : un JSON abîmé
//! rend une erreur dite à l'écran, un champ inconnu est ignoré, un champ absent prend sa valeur par défaut, et un
//! élément illisible d'une liste est compté à part (« pas pu lire »), jamais pris pour sain. Chaque texte passe par
//! `nettoyage` dès la lecture : les écrans ne voient que du texte propre et borné.
//!
//! Rien n'est d'abord relu en arbre (`serde_json::Value`) : un arbre coûte bien plus de mémoire que le JSON lu (une
//! valeur fait 32 octets, `[0,0,…]` deux octets par valeur), et une sortie de 16 Mio en ferait des centaines. Un
//! texte est lu au fil de l'eau, ce qu'il ne prend pas est sauté sans être gardé (`IgnoredAny`) ; un élément de liste
//! est gardé tel qu'écrit (`RawValue`, au plus sa taille dans la sortie) le temps d'être lu à part.

pub mod bilan;
pub mod evenements;
pub mod libre;
pub mod protection;

use std::fmt;
use std::marker::PhantomData;

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;

/// Le nombre maximal d'éléments relus dans une liste (constats, événements, interrupteurs) : au-delà, comptés comme
/// non lus. Les sorties sont déjà bornées en octets (`lanceur::SORTIE_MAX`) ; ceci borne le travail de l'affichage.
pub const ELEMENTS_MAX: usize = 5000;

/// Un texte lu dans un JSON, déjà nettoyé et borné. Une chaîne est prise telle quelle (nettoyée), un nombre ou un
/// booléen écrit en texte, le reste (absent, null, liste, objet) devient vide.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Texte(pub String);

impl Texte {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for Texte {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Texte, D::Error> {
        d.deserialize_any(VersTexte)
    }
}

/// Un nombre écrit comme serde_json l'écrit (1.0 reste « 1.0 »).
pub(super) fn nombre(n: f64) -> String {
    serde_json::Number::from_f64(n)
        .map(|n| n.to_string())
        .unwrap_or_default()
}

struct VersTexte;

impl<'de> Visitor<'de> for VersTexte {
    type Value = Texte;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("un texte")
    }

    fn visit_str<E>(self, s: &str) -> Result<Texte, E> {
        Ok(Texte(crate::nettoyage::texte(s)))
    }

    fn visit_bool<E>(self, b: bool) -> Result<Texte, E> {
        Ok(Texte(b.to_string()))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Texte, E> {
        Ok(Texte(n.to_string()))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Texte, E> {
        Ok(Texte(n.to_string()))
    }

    fn visit_f64<E>(self, n: f64) -> Result<Texte, E> {
        Ok(Texte(nombre(n)))
    }

    fn visit_unit<E>(self) -> Result<Texte, E> {
        Ok(Texte::default())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Texte, A::Error> {
        while s.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Texte::default())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Texte, A::Error> {
        while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Texte::default())
    }
}

/// Une liste lue élément par élément : ceux qui ne se lisent pas sont comptés, pas perdus en silence.
#[derive(Clone, Debug, PartialEq)]
pub struct Liste<T> {
    pub elements: Vec<T>,
    pub illisibles: usize,
}

impl<T> Default for Liste<T> {
    fn default() -> Self {
        Liste {
            elements: Vec::new(),
            illisibles: 0,
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Liste<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Liste<T>, D::Error> {
        d.deserialize_any(VersListe(PhantomData))
    }
}

struct VersListe<T>(PhantomData<T>);

impl<T> VersListe<T> {
    /// Pas une liste : rien de lu, et c'est dit (un élément illisible).
    fn pas_une_liste() -> Liste<T> {
        Liste {
            elements: Vec::new(),
            illisibles: 1,
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Visitor<'de> for VersListe<T> {
    type Value = Liste<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("une liste")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Liste<T>, A::Error> {
        let mut l = Liste::default();
        loop {
            // Au-delà de la borne : sauté sans être gardé, compté.
            if l.elements.len().saturating_add(l.illisibles) >= ELEMENTS_MAX {
                if s.next_element::<IgnoredAny>()?.is_none() {
                    break;
                }
                l.illisibles = l.illisibles.saturating_add(1);
                continue;
            }
            // Chaque élément lu à part : un élément d'une forme inattendue est compté sans faire tomber la liste.
            let Some(brut) = s.next_element::<Box<RawValue>>()? else {
                break;
            };
            match serde_json::from_str::<T>(brut.get()) {
                Ok(x) => l.elements.push(x),
                Err(_) => l.illisibles = l.illisibles.saturating_add(1),
            }
        }
        Ok(l)
    }

    fn visit_unit<E>(self) -> Result<Liste<T>, E> {
        Ok(Liste::default())
    }

    fn visit_bool<E>(self, _: bool) -> Result<Liste<T>, E> {
        Ok(Self::pas_une_liste())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Liste<T>, E> {
        Ok(Self::pas_une_liste())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Liste<T>, E> {
        Ok(Self::pas_une_liste())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Liste<T>, E> {
        Ok(Self::pas_une_liste())
    }

    fn visit_str<E>(self, _: &str) -> Result<Liste<T>, E> {
        Ok(Self::pas_une_liste())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Liste<T>, A::Error> {
        while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(Self::pas_une_liste())
    }
}

/// Lit une sortie de `vanguard` : du JSON en UTF-8, sinon une erreur courte à montrer.
pub fn lire<T: serde::de::DeserializeOwned>(sortie: &[u8]) -> Result<T, String> {
    if sortie.iter().all(u8::is_ascii_whitespace) {
        return Err(crate::tr!("la commande n'a rien écrit", "the command wrote nothing").to_string());
    }
    // Chaque réponse de Vanguard est un objet : une liste, un nombre ou un texte seul n'en est pas une.
    if sortie.iter().find(|o| !o.is_ascii_whitespace()) != Some(&b'{') {
        return Err(crate::tr!(
            "réponse illisible (pas un objet JSON)",
            "unreadable answer (not a JSON object)"
        )
        .to_string());
    }
    serde_json::from_slice(sortie).map_err(|e| {
        crate::trf!(
            "réponse illisible ({})",
            "unreadable answer ({})",
            crate::nettoyage::nom(&e.to_string(), 120)
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, Default, Debug, PartialEq)]
    #[serde(default)]
    struct Essai {
        nom: Texte,
        n: Option<u32>,
    }

    #[derive(Deserialize, Default, Debug)]
    #[serde(default)]
    struct Groupe {
        membres: Liste<Essai>,
    }

    #[test]
    fn un_texte_tolere_tout() {
        let t: Vec<Texte> = serde_json::from_str(r#"["a\u001b[2Kb", 3, true, null, [1], {"x": 1}]"#).unwrap();
        let t: Vec<&str> = t.iter().map(Texte::as_str).collect();
        assert_eq!(t, ["ab", "3", "true", "", "", ""]);
        let t: Vec<Texte> = serde_json::from_str("[1.0, -2, 1e300, 18446744073709551615]").unwrap();
        let t: Vec<&str> = t.iter().map(Texte::as_str).collect();
        assert_eq!(t, ["1.0", "-2", "1e+300", "18446744073709551615"]);
    }

    #[test]
    fn une_liste_compte_ce_qu_elle_ne_lit_pas() {
        let l: Liste<Essai> = serde_json::from_str(r#"[{"nom": "alice"}, {"n": "pas un nombre"}, 7, {}]"#).unwrap();
        assert_eq!(l.elements.len(), 2);
        assert_eq!(l.illisibles, 2);
        let pas_liste: Liste<Essai> = serde_json::from_str(r#"{"nom": "x"}"#).unwrap();
        assert_eq!((pas_liste.elements.len(), pas_liste.illisibles), (0, 1));
        let nulle: Liste<Essai> = serde_json::from_str("null").unwrap();
        assert_eq!((nulle.elements.len(), nulle.illisibles), (0, 0));
        for autre in ["3", "\"x\"", "true", "-1.5"] {
            let l: Liste<Essai> = serde_json::from_str(autre).unwrap();
            assert_eq!((l.elements.len(), l.illisibles), (0, 1), "{autre}");
        }
        // Une liste dans un élément, lue elle aussi élément par élément.
        let g: Liste<Groupe> = serde_json::from_str(r#"[{"membres": [{"nom": "a"}, 5]}, "x"]"#).unwrap();
        assert_eq!((g.elements.len(), g.illisibles), (1, 1));
        assert_eq!(
            (g.elements[0].membres.elements.len(), g.elements[0].membres.illisibles),
            (1, 1)
        );
    }

    #[test]
    fn une_liste_est_bornee() {
        let json = format!("[{}{{}}]", "{},".repeat(ELEMENTS_MAX + 9));
        let l: Liste<Essai> = serde_json::from_str(&json).unwrap();
        assert_eq!(l.elements.len(), ELEMENTS_MAX);
        assert_eq!(l.illisibles, 10);
    }

    #[test]
    fn lire_ne_panique_jamais() {
        assert!(lire::<Essai>(b"").is_err());
        assert!(lire::<Essai>(b"  \n").is_err());
        assert!(lire::<Essai>(b"{").is_err());
        assert!(lire::<Essai>(b"\xff\xfe").is_err());
        // Imbrication profonde : serde_json s'arrête à 128 niveaux, sans déborder la pile.
        assert!(lire::<Essai>("[".repeat(100_000).as_bytes()).is_err());
        let e: Essai = lire(br#"{"nom": "Salon", "inconnu": [1, 2], "n": 4}"#).unwrap();
        assert_eq!(
            e,
            Essai {
                nom: Texte("Salon".into()),
                n: Some(4)
            }
        );
    }
}
