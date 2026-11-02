//! Les fichiers d'état de l'Agent Vanguard (src/agent/etat.rs) : compteurs d'une mission, interrupteurs, et les
//! états du réglage (suivi des « non vérifié » passagers, R4) et des corrections (échecs, corrections revenues, R6),
//! lus depuis n'importe quels octets (JSON tronqué, nombres hors bornes, mission inconnue, champ en trop, fichier
//! démesuré, règle répétée). Tout état lu reste dans ses bornes, s'écrit et se relit à l'identique, et un tour de plus
//! n'ouvre jamais plus que le plafond du jour.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

// Chaque module y lit ses voisins par `super::`, ici la racine de la cible.
#[allow(dead_code)]
#[path = "../../src/agent/forme.rs"]
mod forme;
#[allow(dead_code)]
#[path = "../../src/agent/decision.rs"]
mod decision;
#[allow(dead_code)]
#[path = "../../src/agent/etat.rs"]
mod etat;

use etat::{Borne, Compteurs, EtatCorrections, EtatReglage, Interrupteurs};

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
    // Les états d'A6 : dans leurs bornes, relus à l'identique, et encore après un bilan ou des corrections.
    let r: EtatReglage = etat::lire_de(octets);
    assert!(r.dans_ses_bornes(), "{r:?}");
    let relu: EtatReglage = etat::lire_de(&serde_json::to_vec(&r).unwrap());
    assert_eq!(relu, r);
    let k: EtatCorrections = etat::lire_de(octets);
    assert!(k.dans_ses_bornes(), "{k:?}");
    let relu: EtatCorrections = etat::lire_de(&serde_json::to_vec(&k).unwrap());
    assert_eq!(relu, k);
    let regle = forme::RegleId::depuis("LNX-TST-010").unwrap();
    let issue = match octets.get(2).map_or(0, |o| o % 3) {
        0 => forme::Issue::Passagere,
        1 => forme::Issue::Concluse,
        _ => forme::Issue::Autre,
    };
    let bilan = forme::ResumeBilan {
        debut_ms: 1,
        regles: vec![(regle, issue)],
        problemes: vec![(regle, u64::from(octets.get(3).copied().unwrap_or(0)))],
    };
    let suivi = r.suivre(jour, &bilan);
    assert!(suivi.dans_ses_bornes(), "{suivi:?}");
    assert!(suivi.a_relancer(jour).iter().all(|(_, n, repris)| *n >= 2 && repris <= n));
    let note = forme::NoteCorrection {
        regle,
        issue: if octets.get(4).is_some_and(|o| o % 2 == 0) {
            forme::IssueCorrection::Echouee(forme::CodeEchec::Echoue)
        } else {
            forme::IssueCorrection::Reussie {
                empreinte: Some(u64::from(octets.get(3).copied().unwrap_or(0))),
            }
        },
        quand_ms: 0,
    };
    let (apres, _) = k.apres(jour, &[note], Some(&bilan));
    assert!(apres.dans_ses_bornes(), "{apres:?}");
});
