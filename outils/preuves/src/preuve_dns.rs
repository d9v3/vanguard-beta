//! Les noms des réponses DNS (src/audit/dns_client.rs) : n'importe quel serveur, ou un paquet forgé, choisit chaque
//! octet, pointeurs de compression compris. Kani prouve le parcours d'un nom (`etiquettes`, que `nom` appelle), pour
//! tout message de TAILLE octets au plus et toute position : pas de panique ni de débordement, pas de boucle sans fin
//! (des pointeurs qui tournent en rond arrêtent la lecture au 17e saut), chaque étiquette prise dans le message, une
//! position de suite qui reste dans le message.
//!
//! La garde de longueur de `nom` (253 caractères) est remplacée par un choix quelconque, continuer ou s'arrêter à
//! chaque étiquette : la preuve vaut quelle que soit la longueur décodée, mais elle ne prouve pas la borne elle-même,
//! qui est un garde-fou (inatteignable dans un si petit message ; le fuzzing, cible `dns_client`, couvre les noms
//! longs). L'assemblage du texte (`String::push_str`, `from_utf8_lossy`) reste hors de la preuve : avec lui, Kani
//! dépasse 9 Go de mémoire dès 3 octets ; sans lui, 4 octets prennent environ 5 min et 6 Go
//! (outils/veille/LISEZMOI.md).

use super::etiquettes;

/// La taille du message : à 4 octets, une étiquette suivie d'un pointeur vers elle passe 17 fois par `ajout` ; d'où
/// un dépliage de 35 tours (17 étiquettes, 17 sauts dont le dernier refusé), dont Kani vérifie qu'il suffit.
const TAILLE: usize = 4;

#[kani::proof]
#[kani::unwind(35)]
fn nom_borne() {
    let message: [u8; TAILLE] = kani::any();
    let longueur = kani::any_where(|l: &usize| *l <= TAILLE);
    let pos: usize = kani::any();
    let mut appels: u8 = 0;
    let suite = etiquettes(&message[..longueur], pos, |etiquette| {
        assert!(etiquette.len() < longueur);
        appels += 1;
        kani::any()
    });
    assert!(appels <= 17);
    if let Some(suite) = suite {
        assert!(pos < longueur && suite <= longueur);
    }
}
