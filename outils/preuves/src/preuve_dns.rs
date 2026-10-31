//! Les noms des réponses DNS (src/audit/dns_client.rs) : n'importe quel serveur, ou un paquet forgé, choisit chaque
//! octet, pointeurs de compression compris. Kani prouve, pour tout message de 3 octets au plus et toute position,
//! l'absence de panique, de débordement et de boucle sans fin (pointeurs qui tournent en rond : la lecture s'arrête au
//! 17e saut), un nom de 253 caractères au plus et une position de suite qui reste dans le message.
//!
//! `String::from_utf8_lossy` est remplacé par un modèle qui rend autant de caractères que l'étiquette a d'octets : Kani
//! déplie la boucle 20 fois, chaque tour avec son décodage UTF-8 d'octets quelconques, ce qui demande plus de 10 Go
//! et d'un quart d'heure ; l'absence de panique de ce décodage relève de la bibliothèque standard, et la borne de 253
//! est vérifiée par `nom` après chaque ajout, quelle que soit la longueur décodée. Pourquoi 3 octets : à 4, une
//! étiquette suivie d'un pointeur vers elle fait grandir le nom 17 fois, ce qui dépasse aussi les 10 Go ; la boucle de
//! pointeurs, elle, tient en 2 octets. Le fuzzing (cible `dns_client`) couvre les noms longs.

use super::nom;
use std::borrow::Cow;

/// Le modèle du décodage : autant de caractères que d'octets (une étiquette en a 63 au plus).
fn decodage_modele(octets: &[u8]) -> Cow<'_, str> {
    const TEXTE: &str = "???????????????????????????????????????????????????????????????";
    Cow::Borrowed(TEXTE.get(..octets.len()).unwrap_or(TEXTE))
}

#[kani::proof]
#[kani::unwind(20)]
#[kani::stub(std::string::String::from_utf8_lossy, decodage_modele)]
fn nom_borne() {
    let message: [u8; 3] = kani::any();
    let longueur = kani::any_where(|l: &usize| *l <= 3);
    let pos: usize = kani::any();
    if let Some((texte, suite)) = nom(&message[..longueur], pos) {
        assert!(texte.len() <= 253);
        assert!(pos < longueur && suite <= longueur);
    }
}
