//! Les fichiers d'état de l'Agent Vanguard (src/agent/etat.rs) : compteurs d'une mission et interrupteurs, lus depuis
//! n'importe quels octets (JSON tronqué, nombres hors bornes, mission inconnue, champ en trop, fichier démesuré).
//! Tout état lu reste dans ses bornes, s'écrit et se relit à l'identique, et un tour de plus n'ouvre jamais plus que
//! le plafond du jour.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

// Chaque module y lit ses voisins par `super::`, ici la racine de la cible.
#[allow(dead_code)]
#[path = "../../src/agent/forme.rs"]
mod forme;
#[allow(dead_code)]
#[path = "../../src/agent/etat.rs"]
mod etat;

use etat::{Borne, Compteurs, Interrupteurs};

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let c: Compteurs = etat::lire_de(octets);
    assert!(c.dans_ses_bornes(), "{c:?}");
    let i: Interrupteurs = etat::lire_de(octets);
    assert!(i.dans_ses_bornes(), "{i:?}");
    // Écrit puis relu : le même état.
    let relu: Compteurs = etat::lire_de(&serde_json::to_vec(&c).unwrap());
    assert_eq!(relu, c);
    let relu: Interrupteurs = etat::lire_de(&serde_json::to_vec(&i).unwrap());
    assert_eq!(relu, i);
    // Un tour de plus, n'importe quel jour et n'importe quel nombre d'ajustements : toujours dans les bornes, et
    // jamais plus d'ajustements permis ce jour-là que le plafond.
    let jour = octets.first().map_or(0, |&o| i32::from(o)) * 400 + etat::JOUR_MIN - 2_000;
    let n = octets.get(1).map_or(0, |&o| u16::from(o));
    let apres = c.apres(jour, n);
    assert!(apres.dans_ses_bornes(), "{apres:?}");
    assert!(apres.restants(jour) <= etat::PAR_JOUR_MAX);
    assert!(apres.tours >= c.tours && apres.total >= c.total);
    assert_eq!(apres.borne(), apres);
});
