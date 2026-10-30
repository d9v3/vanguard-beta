//! Cale : le canal d'erreur commun (`modele::Echec`, `modele::Raison`) réduit à ce que les lecteurs du réseau
//! demandent. Le fuzzing cherche les plantages des lecteurs, pas le texte de leurs erreurs.

#![allow(dead_code)]

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Raison {
    Droits,
    Introuvable,
    Delai,
    Panique,
    Illisible(String),
    Refuse(String),
    Echoue(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Echec {
    pub raison: Raison,
    pub contexte: &'static str,
    pub detail: String,
}

impl Echec {
    pub fn new(contexte: &'static str, raison: Raison) -> Echec {
        Echec {
            raison,
            contexte,
            detail: String::new(),
        }
    }

    pub fn refuse(contexte: &'static str, phrase: impl Into<String>) -> Echec {
        Echec::new(contexte, Raison::Refuse(phrase.into()))
    }

    pub fn echoue(contexte: &'static str, phrase: impl Into<String>) -> Echec {
        Echec::new(contexte, Raison::Echoue(phrase.into()))
    }

    pub fn io(contexte: &'static str, e: &std::io::Error) -> Echec {
        Echec::new(contexte, Raison::Illisible(e.to_string()))
    }
}

/// `modele::raison::Echec`, le chemin que prennent certains modules.
pub mod raison {
    #[allow(unused_imports)]
    pub use super::Echec;
}
