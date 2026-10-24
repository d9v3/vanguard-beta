//! Les journaux d'événements de Windows, lus par Vanguard lui-même (sans Hayabusa ni autre programme) : le lecteur
//! de fichiers .evtx (`evtx`), qui sert aussi sous Linux et macOS (journaux rapportés, disque monté depuis la clé de
//! secours). La forme commune des événements, les règles et la chronologie suivent (lots E2 à E4).

// Appelé par E2 (la source « fichiers » des événements) : rien ne s'en sert encore hors des tests.
#![cfg_attr(not(test), allow(dead_code))]

pub(crate) mod evtx;
