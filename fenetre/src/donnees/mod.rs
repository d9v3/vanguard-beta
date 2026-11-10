//! Ce que les commandes de `vanguard` écrivent en JSON, relu pour l'affichage. Jamais de panique : un JSON abîmé
//! rend une erreur dite à l'écran, un champ inconnu est ignoré, un champ absent prend sa valeur par défaut, et un
//! élément illisible d'une liste est compté à part (« pas pu lire »), jamais pris pour sain. Chaque texte passe par
//! `nettoyage` dès la lecture : les écrans ne voient que du texte propre et borné.

pub mod bilan;
pub mod evenements;
pub mod libre;
pub mod protection;

use serde::{Deserialize, Deserializer};

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
        let v = serde_json::Value::deserialize(d)?;
        Ok(Texte(match v {
            serde_json::Value::String(s) => crate::nettoyage::texte(&s),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => String::new(),
        }))
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
        let v = serde_json::Value::deserialize(d)?;
        let serde_json::Value::Array(brut) = v else {
            // Pas une liste : rien de lu, et c'est dit (un élément illisible).
            return Ok(Liste {
                elements: Vec::new(),
                illisibles: usize::from(!v.is_null()),
            });
        };
        let mut l = Liste {
            elements: Vec::new(),
            illisibles: 0,
        };
        for (i, e) in brut.into_iter().enumerate() {
            if i >= ELEMENTS_MAX {
                l.illisibles = l.illisibles.saturating_add(1);
                continue;
            }
            match serde_json::from_value::<T>(e) {
                Ok(x) => l.elements.push(x),
                Err(_) => l.illisibles = l.illisibles.saturating_add(1),
            }
        }
        Ok(l)
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

    #[test]
    fn un_texte_tolere_tout() {
        let t: Vec<Texte> = serde_json::from_str(r#"["a\u001b[2Kb", 3, true, null, [1], {"x": 1}]"#).unwrap();
        let t: Vec<&str> = t.iter().map(Texte::as_str).collect();
        assert_eq!(t, ["ab", "3", "true", "", "", ""]);
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
