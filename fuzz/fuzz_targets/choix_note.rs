//! Les notes « avant » des choix de la personne (src/machine/windows/choix_note.rs), lues dans le registre HKLM, que
//! tout programme administrateur peut avoir écrit : n'importe quels octets, puis les mêmes clos de leur vraie
//! empreinte (pour passer le contrôle et atteindre la lecture des champs). Une note lue porte le nom demandé et se
//! réécrit octet pour octet à l'identique ; une note écrite se relit telle quelle.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/windows/choix_note.rs"]
mod choix_note;

use choix_note::{NOTE_MAX, Note};
use sha2::{Digest, Sha256};

/// Une note lue : sous le nom demandé, bornée, et identique à ses octets réécrits (aucune autre forme n'est admise).
fn verifier(nom: &str, octets: &[u8]) {
    if let Some(n) = Note::lire(nom, octets) {
        assert_eq!(n.id, nom);
        assert!(octets.len() <= NOTE_MAX);
        assert_eq!(n.octets(), octets, "{n:?}");
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    // Le premier octet : la longueur du nom de la valeur ; puis le nom ; puis la note.
    let Some((&k, reste)) = donnees.split_first() else { return };
    let k = usize::from(k).min(reste.len());
    let (nom, octets) = reste.split_at(k);
    let nom = String::from_utf8_lossy(nom);
    verifier(&nom, octets);
    let mut close = octets.to_vec();
    close.extend_from_slice(&Sha256::digest(octets));
    verifier(&nom, &close);
    // Écrite puis relue : la même note, pour un nom ASCII visible et des nombres pris dans les octets.
    if !nom.is_empty() && nom.bytes().all(|o| o.is_ascii_graphic()) {
        let nombre = |i: usize| {
            octets
                .get(i..i.saturating_add(8))
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(i64::from_le_bytes)
        };
        let note = Note {
            id: nom.to_string(),
            avant: nombre(0),
            posee: nombre(8).unwrap_or(1),
            date: nombre(16).map_or(0, i64::unsigned_abs),
        };
        let ecrite = note.octets();
        if ecrite.len() <= NOTE_MAX {
            assert_eq!(Note::lire(&nom, &ecrite), Some(note));
        }
    }
});
