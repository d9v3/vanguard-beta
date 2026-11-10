//! `evenements --json` : le journal de Vanguard. Son état vient d'abord : un journal falsifié ou incomplet se lit
//! quand même (on ne cache pas une alerte), mais il est dit non vérifié, jamais intact. Les événements d'essai
//! (autotest) ne sont ni des alertes ni de l'historique.

use serde::Deserialize;

use super::bilan::Gravite;
use super::{Liste, Texte};

/// L'état de la chaîne du journal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Etat {
    Vide,
    Intact,
    /// Accepté tel quel au premier usage des sceaux : rien ne prouve qu'il n'a pas changé avant.
    Adopte,
    Incomplet,
    Falsifie,
    /// Un mot écrit par une version plus récente : non vérifié.
    Inconnu,
}

impl Etat {
    fn lire(mot: &str) -> Etat {
        match mot {
            "vide" => Etat::Vide,
            "intact" => Etat::Intact,
            "adopte" => Etat::Adopte,
            "incomplet" => Etat::Incomplet,
            "falsifie" => Etat::Falsifie,
            _ => Etat::Inconnu,
        }
    }

    /// La phrase de l'état, comme `vanguard evenements` la dit.
    pub fn phrase(self) -> &'static str {
        match self {
            Etat::Vide => crate::tr!("journal vide : rien de noté encore", "empty log: nothing recorded yet"),
            Etat::Intact => crate::tr!(
                "journal intact : chaîne et tête scellée d'accord",
                "log intact: chain and sealed head agree"
            ),
            Etat::Adopte => crate::tr!(
                "journal accepté tel quel au premier usage des sceaux : rien ne prouve qu'il n'a pas changé avant",
                "log accepted as it was when the seals were first used: nothing proves it did not change before"
            ),
            Etat::Incomplet => crate::tr!("journal incomplet, non vérifié", "incomplete log, not verified"),
            Etat::Falsifie => crate::tr!(
                "journal changé hors de Vanguard, non vérifié",
                "log changed outside Vanguard, not verified"
            ),
            Etat::Inconnu => crate::tr!(
                "état du journal inconnu de cette fenêtre : non vérifié",
                "log state unknown to this window: not verified"
            ),
        }
    }

    /// Faut-il le dire en rouge ou en orange ?
    pub fn gravite(self) -> Option<Gravite> {
        match self {
            Etat::Vide | Etat::Intact => None,
            Etat::Adopte | Etat::Incomplet | Etat::Inconnu => Some(Gravite::Moyenne),
            Etat::Falsifie => Some(Gravite::Elevee),
        }
    }
}

/// `quoi` d'un événement : tous les champs des sortes connues, facultatifs.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct QuoiBrut {
    sorte: Texte,
    famille: Texte,
    titre: Texte,
    texte: Texte,
    quoi: Texte,
    reussi: Option<bool>,
    automatique: Option<bool>,
    objet: Texte,
    de: Texte,
    vers: Texte,
    outil: Texte,
    verdict: Texte,
    problemes: Option<u64>,
    non_verifies: Option<u64>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct EvenementBrut {
    id: Texte,
    quand: Texte,
    source: Texte,
    gravite: Texte,
    cause: Texte,
    essai: Option<bool>,
    quoi: QuoiBrut,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Brut {
    etat: Texte,
    raison: Texte,
    illisibles: Option<u64>,
    evenements: Liste<EvenementBrut>,
}

/// Un événement prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evenement {
    pub id: String,
    pub quand: String,
    pub source: String,
    pub sorte: String,
    pub alerte: bool,
    pub titre: String,
    pub detail: String,
    pub gravite: Option<Gravite>,
    pub lie: bool,
}

impl From<EvenementBrut> for Evenement {
    fn from(b: EvenementBrut) -> Evenement {
        let q = b.quoi;
        let nom = |t: &Texte, n: usize| crate::nettoyage::nom(t.as_str(), n);
        let (titre, detail) = match q.sorte.as_str() {
            "alerte" => (nom(&q.titre, 120), q.texte.0.clone()),
            "action" => (
                nom(&q.quoi, 160),
                match (q.reussi, q.automatique) {
                    (Some(true), Some(true)) => crate::tr!("réussi, automatique", "succeeded, automatic").into(),
                    (Some(true), _) => crate::tr!("réussi", "succeeded").into(),
                    (Some(false), _) => crate::tr!("échoué", "failed").into(),
                    (None, _) => String::new(),
                },
            ),
            "annulation" => (crate::tr!("Geste défait", "Action undone").into(), nom(&q.objet, 80)),
            "normale" => (
                crate::tr!("Déclarée normale", "Marked as normal").into(),
                nom(&q.titre, 120),
            ),
            "normale-oubliee" => (
                crate::tr!("Alerte normale oubliée", "Normal alert forgotten").into(),
                String::new(),
            ),
            "version" => (
                crate::tr!("Nouvelle version de Vanguard", "New Vanguard version").into(),
                if q.de.is_empty() {
                    nom(&q.vers, 40)
                } else {
                    format!("{} → {}", nom(&q.de, 40), nom(&q.vers, 40))
                },
            ),
            "rupture" => (
                crate::tr!("Rupture du journal", "Log break").into(),
                crate::tr!(
                    "la fin du journal n'était pas celle attendue",
                    "the end of the log was not the expected one"
                )
                .into(),
            ),
            "examen" => (
                crate::trf!("Examen : {}", "Check: {}", nom(&q.outil, 40)),
                crate::trf!(
                    "{} · {} problème(s), {} pas pu vérifier",
                    "{} · {} problem(s), {} could not check",
                    nom(&q.verdict, 20),
                    q.problemes.unwrap_or(0),
                    q.non_verifies.unwrap_or(0)
                ),
            ),
            "preuve" => (crate::tr!("Preuve relevée", "Evidence recorded").into(), String::new()),
            _ => (
                crate::tr!("Événement d'une version plus récente", "Event from a newer version").into(),
                nom(&q.sorte, 40),
            ),
        };
        let gravite = match b.gravite.as_str() {
            "" => None,
            "Info" => Some(Gravite::Info),
            "Eleve" => Some(Gravite::Elevee),
            "Critique" => Some(Gravite::Critique),
            _ => Some(Gravite::Moyenne),
        };
        Evenement {
            id: nom(&b.id, 80),
            quand: nom(&b.quand, 32),
            source: nom(&b.source, 20),
            alerte: q.sorte.as_str() == "alerte",
            sorte: nom(&q.sorte, 20),
            titre: if titre.is_empty() { nom(&q.famille, 60) } else { titre },
            detail,
            gravite,
            lie: !b.cause.is_empty(),
        }
    }
}

/// Le journal relu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vue {
    pub etat: Etat,
    pub raison: String,
    /// Lignes illisibles du journal (dites par Vanguard) et événements illisibles ici.
    pub illisibles: u64,
    /// Du plus récent au plus ancien, sans les essais.
    pub evenements: Vec<Evenement>,
}

pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let b: Brut = super::lire(sortie)?;
    let illisibles = b
        .illisibles
        .unwrap_or(0)
        .saturating_add(u64::try_from(b.evenements.illisibles).unwrap_or(u64::MAX));
    let mut evenements: Vec<Evenement> = b
        .evenements
        .elements
        .into_iter()
        .filter(|e| e.essai != Some(true))
        .map(Evenement::from)
        .collect();
    evenements.reverse();
    Ok(Vue {
        etat: Etat::lire(b.etat.as_str()),
        raison: crate::nettoyage::nom(b.raison.as_str(), 200),
        illisibles,
        evenements,
    })
}

impl Vue {
    pub fn alertes(&self) -> impl Iterator<Item = &Evenement> {
        self.evenements.iter().filter(|e| e.alerte)
    }

    /// Les alertes de `self` absentes de `avant` (par identifiant), à dire dans la console.
    pub fn nouvelles_alertes<'a>(&'a self, avant: &Vue) -> Vec<&'a Evenement> {
        self.alertes()
            .filter(|e| !e.id.is_empty() && !avant.evenements.iter().any(|a| a.id == e.id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOURNAL: &str = r#"{
        "etat": "intact", "raison": null, "illisibles": 0,
        "evenements": [
            {"v": 1, "id": "a1", "quand": "2026-11-09T13:00:00Z", "source": "vanguard",
             "quoi": {"sorte": "version", "vers": "0.90.0"}, "precedent": ""},
            {"v": 1, "id": "a2", "quand": "2026-11-09T13:10:00Z", "source": "surveillance", "gravite": "Eleve",
             "cle": "botnet|x", "quoi": {"sorte": "alerte", "famille": "botnet", "titre": "Connexion suspecte",
             "texte": "Un programme parle à 203.0.113.7."}, "precedent": "x"},
            {"v": 1, "id": "a3", "quand": "2026-11-09T13:11:00Z", "source": "blocage", "cause": "a2",
             "quoi": {"sorte": "action", "quoi": "Bloquer 203.0.113.7", "reussi": true, "automatique": true}},
            {"v": 1, "id": "a4", "quand": "2026-11-09T13:12:00Z", "source": "surveillance", "essai": true,
             "quoi": {"sorte": "alerte", "famille": "essai", "titre": "Essai", "texte": "autotest"}},
            {"v": 1, "id": "a5", "quand": "2026-11-09T13:20:00Z", "source": "outil",
             "quoi": {"sorte": "examen", "outil": "PRO-LEN-001", "verdict": "probleme", "problemes": 2,
             "non_verifies": 1}},
            {"v": 2, "id": "a6", "quand": "2026-11-09T13:30:00Z", "source": "futur", "quoi": {"sorte": "hologramme"}},
            "abîmé"
        ]
    }"#;

    #[test]
    fn lit_le_journal() {
        let v = lire(JOURNAL.as_bytes()).unwrap();
        assert_eq!(v.etat, Etat::Intact);
        assert_eq!(v.illisibles, 1);
        let ids: Vec<&str> = v.evenements.iter().map(|e| e.id.as_str()).collect();
        // Du plus récent au plus ancien, sans l'essai.
        assert_eq!(ids, ["a6", "a5", "a3", "a2", "a1"]);
        let alertes: Vec<&str> = v.alertes().map(|e| e.titre.as_str()).collect();
        assert_eq!(alertes, ["Connexion suspecte"]);
        let a3 = v.evenements.get(2).unwrap();
        assert!(a3.lie);
        assert_eq!(a3.detail, "réussi, automatique");
        assert_eq!(v.evenements.first().map(|e| e.sorte.as_str()), Some("hologramme"));
        assert_eq!(v.evenements.get(3).and_then(|e| e.gravite), Some(Gravite::Elevee));
    }

    #[test]
    fn un_journal_falsifie_garde_ses_alertes() {
        let v = lire(
            JOURNAL
                .replace(
                    r#""etat": "intact", "raison": null"#,
                    r#""etat": "falsifie", "raison": "tête""#,
                )
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(v.etat, Etat::Falsifie);
        assert_eq!(v.etat.gravite(), Some(Gravite::Elevee));
        assert_eq!(v.raison, "tête");
        assert_eq!(v.alertes().count(), 1);
        // Un état inconnu n'est jamais intact.
        let v = lire(
            JOURNAL
                .replace(r#""etat": "intact""#, r#""etat": "scelle-v9""#)
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(v.etat, Etat::Inconnu);
        assert!(v.etat.gravite().is_some());
    }

    #[test]
    fn trouve_les_nouvelles_alertes() {
        let avant = lire(br#"{"etat": "vide", "evenements": []}"#).unwrap();
        let apres = lire(JOURNAL.as_bytes()).unwrap();
        assert_eq!(apres.nouvelles_alertes(&avant).len(), 1);
        assert_eq!(apres.nouvelles_alertes(&apres), Vec::<&Evenement>::new());
    }
}
