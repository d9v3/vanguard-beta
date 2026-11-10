//! Un JSON sans lecteur à lui (`fiche-ordinateur`, `options-defense`), montré tel quel : une ligne par valeur, son
//! chemin de clés en retrait. Borné en profondeur et en lignes : au-delà, une ligne le dit.

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
    let v: serde_json::Value = super::lire(sortie)?;
    let mut vue = Vue::default();
    parcourir(&v, 0, &mut vue);
    Ok(vue)
}

fn valeur(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => Some("—".into()),
        serde_json::Value::Bool(b) => Some(
            if *b {
                crate::tr!("oui", "yes")
            } else {
                crate::tr!("non", "no")
            }
            .into(),
        ),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::String(s) => Some(crate::nettoyage::nom(s, 200)),
        _ => None,
    }
}

fn pousser(vue: &mut Vue, retrait: usize, cle: String, valeur: String) -> bool {
    if vue.lignes.len() >= LIGNES_MAX {
        vue.coupe = true;
        return false;
    }
    vue.lignes.push(Ligne { retrait, cle, valeur });
    true
}

fn parcourir(v: &serde_json::Value, profondeur: usize, vue: &mut Vue) {
    let enfants: Vec<(String, &serde_json::Value)> = match v {
        serde_json::Value::Object(o) => o.iter().map(|(k, x)| (crate::nettoyage::nom(k, 60), x)).collect(),
        serde_json::Value::Array(a) => a.iter().map(|x| (String::new(), x)).collect(),
        _ => {
            if let Some(t) = valeur(v) {
                pousser(vue, profondeur, String::new(), t);
            }
            return;
        }
    };
    for (cle, x) in enfants {
        if let Some(t) = valeur(x) {
            if !pousser(vue, profondeur, cle, t) {
                return;
            }
        } else if profondeur + 1 >= PROFONDEUR_MAX {
            vue.coupe = true;
            if !pousser(vue, profondeur, cle, "…".into()) {
                return;
            }
        } else {
            if !pousser(vue, profondeur, cle, String::new()) {
                return;
            }
            parcourir(x, profondeur + 1, vue);
            if vue.coupe && vue.lignes.len() >= LIGNES_MAX {
                return;
            }
        }
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
