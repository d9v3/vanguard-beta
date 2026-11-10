//! Un JSON sans lecteur à lui (`fiche-ordinateur`, `options-defense`), montré tel quel : une ligne par valeur, son
//! chemin de clés en retrait. Borné en profondeur et en lignes : au-delà, une ligne le dit.

use std::fmt;

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Profondeur montrée au plus.
const PROFONDEUR_MAX: usize = 6;
/// Lignes montrées au plus.
pub const LIGNES_MAX: usize = 200;

/// Une ligne : son retrait, sa clé (vide pour un élément de liste), sa valeur (vide pour un titre de groupe).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ligne {
    pub retrait: usize,
    pub cle: String,
    pub valeur: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vue {
    pub lignes: Vec<Ligne>,
    /// Des valeurs n'ont pas été montrées (trop profond ou trop de lignes).
    pub coupe: bool,
}

pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let Racine(vue) = super::lire(sortie)?;
    Ok(vue)
}

/// Le document lu au fil de l'eau, sans arbre en mémoire (voir `donnees`) : chaque valeur devient sa ligne dès qu'elle
/// est lue ; au-delà des bornes, le reste est sauté sans être gardé.
struct Racine(Vue);

impl<'de> Deserialize<'de> for Racine {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Racine, D::Error> {
        let mut vue = Vue::default();
        Noeud {
            vue: &mut vue,
            profondeur: 0,
            cle: None,
        }
        .deserialize(d)?;
        Ok(Racine(vue))
    }
}

/// Une valeur et sa place : sa clé (`None` pour la racine, dont les enfants sont au retrait 0 sans ligne de titre),
/// son retrait.
struct Noeud<'a> {
    vue: &'a mut Vue,
    profondeur: usize,
    cle: Option<String>,
}

impl Noeud<'_> {
    fn feuille(self, valeur: String) {
        pousser(self.vue, self.profondeur, self.cle.unwrap_or_default(), valeur);
    }

    /// La ligne de titre d'un groupe ; le retrait de ses enfants, ou `None` s'ils ne seront pas montrés.
    fn groupe(&mut self) -> Option<usize> {
        let Some(cle) = self.cle.take() else {
            return (self.vue.lignes.len() < LIGNES_MAX).then_some(0);
        };
        if self.profondeur + 1 >= PROFONDEUR_MAX {
            self.vue.coupe = true;
            pousser(self.vue, self.profondeur, cle, "…".into());
            return None;
        }
        pousser(self.vue, self.profondeur, cle, String::new()).then_some(self.profondeur + 1)
    }
}

impl<'de> DeserializeSeed<'de> for Noeud<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Noeud<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("une valeur JSON")
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        self.feuille("—".into());
        Ok(())
    }

    fn visit_bool<E>(self, b: bool) -> Result<(), E> {
        self.feuille(
            if b {
                crate::tr!("oui", "yes")
            } else {
                crate::tr!("non", "no")
            }
            .into(),
        );
        Ok(())
    }

    fn visit_i64<E>(self, n: i64) -> Result<(), E> {
        self.feuille(n.to_string());
        Ok(())
    }

    fn visit_u64<E>(self, n: u64) -> Result<(), E> {
        self.feuille(n.to_string());
        Ok(())
    }

    fn visit_f64<E>(self, n: f64) -> Result<(), E> {
        self.feuille(super::nombre(n));
        Ok(())
    }

    fn visit_str<E>(self, s: &str) -> Result<(), E> {
        self.feuille(crate::nettoyage::nom(s, 200));
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut s: A) -> Result<(), A::Error> {
        let Some(retrait) = self.groupe() else {
            while s.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(());
        };
        loop {
            if self.vue.lignes.len() >= LIGNES_MAX {
                if s.next_element::<IgnoredAny>()?.is_none() {
                    return Ok(());
                }
                self.vue.coupe = true;
                continue;
            }
            let enfant = Noeud {
                vue: &mut *self.vue,
                profondeur: retrait,
                cle: Some(String::new()),
            };
            if s.next_element_seed(enfant)?.is_none() {
                return Ok(());
            }
        }
    }

    fn visit_map<A: MapAccess<'de>>(mut self, mut m: A) -> Result<(), A::Error> {
        let Some(retrait) = self.groupe() else {
            while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(());
        };
        loop {
            if self.vue.lignes.len() >= LIGNES_MAX {
                if m.next_entry::<IgnoredAny, IgnoredAny>()?.is_none() {
                    return Ok(());
                }
                self.vue.coupe = true;
                continue;
            }
            let Some(cle) = m.next_key::<Cle>()? else {
                return Ok(());
            };
            m.next_value_seed(Noeud {
                vue: &mut *self.vue,
                profondeur: retrait,
                cle: Some(cle.0),
            })?;
        }
    }
}

/// Une ligne de plus, ou rien (et `coupe`) quand il y en a déjà `LIGNES_MAX`.
fn pousser(vue: &mut Vue, retrait: usize, cle: String, valeur: String) -> bool {
    if vue.lignes.len() >= LIGNES_MAX {
        vue.coupe = true;
        return false;
    }
    vue.lignes.push(Ligne { retrait, cle, valeur });
    true
}

/// Une clé, nettoyée et bornée dès la lecture.
struct Cle(String);

impl<'de> Deserialize<'de> for Cle {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Cle, D::Error> {
        let t = String::deserialize(d)?;
        Ok(Cle(crate::nettoyage::nom(&t, 60)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn met_un_json_a_plat() {
        let v = lire(br#"{"modele": "Essai 3000", "memoire": {"total_gio": 16, "libre": null}, "disques": [{"nom": "a"}], "ok": true}"#).unwrap();
        let l: Vec<(usize, &str, &str)> = v
            .lignes
            .iter()
            .map(|l| (l.retrait, l.cle.as_str(), l.valeur.as_str()))
            .collect();
        assert_eq!(
            l,
            [
                (0, "modele", "Essai 3000"),
                (0, "memoire", ""),
                (1, "total_gio", "16"),
                (1, "libre", "—"),
                (0, "disques", ""),
                (1, "", ""),
                (2, "nom", "a"),
                (0, "ok", "oui"),
            ]
        );
        assert!(!v.coupe);
    }

    #[test]
    fn est_borne() {
        let large: Vec<u32> = (0..1000).collect();
        let v = lire(serde_json::json!({ "x": large }).to_string().as_bytes()).unwrap();
        assert_eq!(v.lignes.len(), LIGNES_MAX);
        assert!(v.coupe);
        let profond = format!("{{\"a\": {}1{}}}", "[".repeat(100), "]".repeat(100));
        let v = lire(profond.as_bytes()).unwrap();
        assert!(v.coupe);
        assert!(v.lignes.len() <= PROFONDEUR_MAX);
        let v = lire(br#"{"k": "seul\u001b[2K"}"#).unwrap();
        assert_eq!(v.lignes.first().map(|l| l.valeur.as_str()), Some("seul"));
        // Une réponse qui n'est pas un objet n'est pas une réponse de Vanguard.
        assert!(lire(b"[1, 2]").is_err());
        assert!(lire(b"\"seul\"").is_err());
    }
}
