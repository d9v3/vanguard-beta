//! `protection --json` : les interrupteurs de la protection. Leur état est un texte dans la langue de Vanguard
//! (« activé », « en pause (temps réel coupé) »…), montré tel quel ; seuls les mots exacts « allumé » et « éteint »
//! prennent une couleur. Tout autre texte reste neutre : la fenêtre ne devine pas qu'un état est bon.

use serde::Deserialize;

use super::{Liste, Texte};

/// Ce que dit l'état, quand il le dit sans détour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Allure {
    Allume,
    Eteint,
    /// Un autre texte (une pause, un état à finir, des réglages illisibles) : montré sans jugement.
    Nuance,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct InterrupteurBrut {
    interrupteur: Texte,
    nom: Texte,
    etat: Texte,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Brut {
    interrupteurs: Liste<InterrupteurBrut>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interrupteur {
    pub id: String,
    pub nom: String,
    pub etat: String,
    pub allure: Allure,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Vue {
    pub interrupteurs: Vec<Interrupteur>,
    pub illisibles: usize,
}

impl Vue {
    pub fn compte(&self, allure: Allure) -> usize {
        self.interrupteurs.iter().filter(|i| i.allure == allure).count()
    }
}

fn allure(etat: &str) -> Allure {
    match etat {
        "activé" | "activée" | "allumé" | "protection active" | "oui" | "on" | "active protection" | "yes" => {
            Allure::Allume
        }
        "désactivé" | "désactivée" | "éteint" | "non" | "off" | "no" => Allure::Eteint,
        _ => Allure::Nuance,
    }
}

pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let b: Brut = super::lire(sortie)?;
    Ok(Vue {
        illisibles: b.interrupteurs.illisibles,
        interrupteurs: b
            .interrupteurs
            .elements
            .into_iter()
            .map(|i| {
                let etat = crate::nettoyage::nom(i.etat.as_str(), 80);
                Interrupteur {
                    id: crate::nettoyage::nom(i.interrupteur.as_str(), 40),
                    nom: crate::nettoyage::nom(i.nom.as_str(), 80),
                    allure: allure(&etat),
                    etat: if etat.is_empty() {
                        crate::tr!("état inconnu", "unknown state").into()
                    } else {
                        etat
                    },
                }
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lit_les_interrupteurs() {
        let v = lire(
            r#"{"interrupteurs": [
                {"interrupteur": "temps-reel", "nom": "Protection en temps réel", "etat": "activé"},
                {"interrupteur": "blocage", "nom": "Blocage des menaces", "etat": "en pause (temps réel coupé)"},
                {"interrupteur": "entretien", "nom": "Entretien du mois", "etat": "désactivé"},
                {"interrupteur": "futur", "nom": "Nouveau"},
                42
            ]}"#
            .as_bytes(),
        )
        .unwrap();
        let allures: Vec<Allure> = v.interrupteurs.iter().map(|i| i.allure).collect();
        assert_eq!(
            allures,
            [Allure::Allume, Allure::Nuance, Allure::Eteint, Allure::Nuance]
        );
        assert_eq!(v.interrupteurs.get(3).map(|i| i.etat.as_str()), Some("état inconnu"));
        assert_eq!(v.illisibles, 1);
        assert_eq!(v.compte(Allure::Allume), 1);
    }

    #[test]
    fn un_etat_qui_ressemble_n_est_pas_allume() {
        // « activé » suivi d'autre chose, ou piégé, n'est pas « activé ».
        for etat in ["activé, en pause", "activé\u{202e}", "ACTIVÉ", " activé"] {
            let json = serde_json::json!({"interrupteurs": [{"interrupteur": "x", "nom": "x", "etat": etat}]});
            let v = lire(json.to_string().as_bytes()).unwrap();
            assert_ne!(
                v.interrupteurs.first().map(|i| i.allure),
                Some(Allure::Allume),
                "{etat:?}"
            );
        }
    }
}
