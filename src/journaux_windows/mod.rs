//! Les journaux d'événements de Windows, lus par Vanguard lui-même (sans Hayabusa ni autre programme) :
//!
//! - `evtx` : le lecteur de fichiers .evtx, qui sert aussi sous Linux et macOS (journaux rapportés, disque monté
//!   depuis la clé de secours) ;
//! - `evenement` : la forme commune d'un événement (`EvenementWindows`) et le filtre, quelle que soit la source ;
//! - `fichiers` : la source « fichiers », un dossier de .evtx lu par `evtx`, en flux ;
//! - `vivant` (Windows) : la source « vivante », les journaux de cet ordinateur rendus par son service des journaux ;
//! - `xml` : le XML que rend ce service, changé en l'arbre de `evtx`, pour une seule extraction des champs ;
//! - `trous` : les trous dans la suite des numéros d'enregistrement (effacement partiel), et ce qui les explique
//!   sans effacement.
//!
//! - `regles` : les règles `EVT-` et leur moteur, sur l'une ou l'autre source.
//!
//! La chronologie et la commande suivent (lot E4).

// Appelé par E4 (la commande et la chronologie) : rien ne s'en sert encore hors des tests.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod evenement;
pub(crate) mod evtx;
pub(crate) mod fichiers;
pub(crate) mod regles;
pub(crate) mod trous;
#[cfg(windows)]
pub(crate) mod vivant;
pub(crate) mod xml;

#[cfg(test)]
mod tests;
