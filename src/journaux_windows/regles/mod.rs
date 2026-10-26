//! Les règles des journaux d'événements de Windows (identifiants `EVT-`), et leur moteur : ce que cherchent les
//! règles, écrit d'après la documentation de Microsoft de chaque événement et la technique d'ATT&CK qu'il trahit,
//! jamais recopié d'un autre jeu de règles (Sigma porte la licence DRL, et chaque alerte devrait citer son auteur).
//!
//! - `moteur` : les formes de règles (un événement à la fois, rafale dans une fenêtre de temps, rafale puis réussite),
//!   les conditions sur les champs, et ce que vaut la lecture de chaque journal (lu, partiel, absent, refusé,
//!   désactivé, non audité d'origine) : une règle qui n'a pas pu tout lire est « non vérifiée », jamais « rien vu » ;
//! - `jeu` : les règles, des données ;
//! - `resultat` : le jugement changé en constats et en couverture (`modele::resultat::Resultat`), et les deux points
//!   d'entrée, un dossier de .evtx ou l'ordinateur vivant.
//!
//! `moteur` et `jeu` sont autonomes (aucun `crate::`, aucun texte traduit : leurs textes sont des paires français,
//! anglais) : le banc de fuzzing les inclut par leur chemin, avec le lecteur.

#[cfg(test)]
pub(crate) mod corpus;
pub(crate) mod jeu;
pub(crate) mod moteur;
pub(crate) mod resultat;

// Les modules voisins, sous le même nom que dans le banc de fuzzing (qui inclut tout à la racine) : `moteur` et `jeu`
// les nomment `super::evenement`, `super::trous` et `super::xml` dans les deux cas.
use super::evenement;
use super::trous;
use super::xml;

#[cfg(test)]
mod tests;
