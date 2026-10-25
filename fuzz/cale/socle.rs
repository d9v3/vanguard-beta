//! Cale : ce que les modules inclus demandent à `crate::socle`. `adresses` est le vrai module (il décide quelles
//! adresses de la liste d'Échap sont gardées) ; le cache ne sert qu'à télécharger, ce que le fuzzing ne fait jamais :
//! il reprend la cale d'`abuse_ch`, qui répond « pas de réponse ».

#![allow(dead_code)]

#[path = "../../src/socle/adresses.rs"]
pub mod adresses;

pub mod cache {
    pub(crate) use crate::protection::abuse_ch::{Echec, Liste, liste};
    pub(crate) const LISTE_MAX: u64 = 1 << 30;

    /// Pourquoi une copie gardée est refusée : le fuzzing n'en garde aucune.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Refus {}

    impl Refus {
        pub(crate) fn texte(self) -> String {
            match self {}
        }
    }

    /// Aucune copie gardée : « absente ».
    pub(crate) fn gardee(_lieu: (&str, &str), _max: u64) -> Result<Option<(Vec<u8>, std::time::Duration)>, Refus> {
        Ok(None)
    }
}

/// Le fuzzing ne lit aucun fichier d'état : « absent ».
pub(crate) fn lire_ordinaire(_chemin: &std::path::Path, _max: u64) -> std::io::Result<Vec<u8>> {
    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
}

pub fn dossier_local() -> std::path::PathBuf {
    crate::reseau::dossier_local()
}
