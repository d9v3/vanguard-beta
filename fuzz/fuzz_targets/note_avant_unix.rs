//! Les notes d'« avant » des gestes de défense de Linux (src/machine/note_avant_unix.rs), lues par l'assistant élevé
//! dans /var/lib/vanguard/avant : n'importe quels octets, puis les mêmes clos de leur vraie empreinte (pour passer le
//! contrôle et atteindre la lecture des champs). Une note lue porte l'identifiant demandé, est bornée et se réécrit
//! octet pour octet à l'identique.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/note_avant_unix.rs"]
mod note_avant_unix;

use note_avant_unix::{CHAMPS_MAX, NOTE_MAX, Note, VALEUR_MAX};
use sha2::{Digest, Sha256};

fn verifier(id: &str, octets: &[u8]) {
    if let Some(n) = Note::lire(id, octets) {
        assert!(octets.len() <= NOTE_MAX);
        assert!(n.champs.len() <= CHAMPS_MAX && n.geste.is_ascii());
        assert!(n.champs.iter().all(|(_, v)| v.len() <= VALEUR_MAX));
        assert_eq!(n.octets(id).as_deref(), Some(octets), "{n:?}");
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    // Le premier octet : la longueur de l'identifiant ; puis l'identifiant ; puis la note.
    let Some((&k, reste)) = donnees.split_first() else { return };
    let k = usize::from(k).min(reste.len());
    let (id, octets) = reste.split_at(k);
    let id = String::from_utf8_lossy(id);
    verifier(&id, octets);
    let mut close = octets.to_vec();
    close.extend_from_slice(&Sha256::digest(octets));
    verifier(&id, &close);
});
