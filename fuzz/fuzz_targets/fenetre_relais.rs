//! Le protocole entre la fenêtre et son relais (fenetre/src/protocole.rs), la frontière des droits sous Linux : le
//! relais, qui a les droits du compte, lit les demandes d'une fenêtre peut-être prise par ce qu'elle dessine ; la
//! fenêtre lit les réponses du relais. Quoi qu'on envoie : aucune trame plus longue que la borne n'est acceptée (ni
//! réservée), une demande comprise est une commande de la liste fermée qui se recode octet pour octet à l'identique,
//! et une réponse comprise a une ligne d'erreur propre et bornée. Le premier octet choisit la langue.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (fenetre/src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../fenetre/src/langue.rs"]
mod langue;

#[allow(dead_code)]
#[path = "../../fenetre/src/nettoyage.rs"]
mod nettoyage;

#[allow(dead_code)]
#[path = "../../fenetre/src/commandes.rs"]
mod commandes;

#[allow(dead_code)]
#[path = "../../fenetre/src/protocole.rs"]
mod protocole;

use commandes::{Commande, Fin, Issue};
use nettoyage::{LIGNE_MAX, piege};
use protocole::{DEMANDE_MAX, Demande, Reponse};

fn sans_piege(s: &str) {
    assert!(!s.chars().any(piege), "caractère piégé dans {s:?}");
}

/// Les demandes, comme le relais les lit : trame après trame, jusqu'à la première hors protocole.
fn relais(mut flux: &[u8]) {
    let avant = flux.len();
    while let Ok(Some(t)) = protocole::lire_trame(&mut flux, DEMANDE_MAX) {
        assert!(t.len() <= DEMANDE_MAX && t.len() <= avant);
        let Some(d) = Demande::lire(&t) else { break };
        if let Demande::Lancer { commande, .. } = d {
            assert!(Commande::TOUTES.contains(&commande));
        }
        assert_eq!(d.coder(), t, "{d:?}");
    }
}

/// Une réponse, comme la fenêtre la lit ; comprise, elle se recode à l'identique (sauf le texte, nettoyé).
fn fenetre(t: &[u8]) {
    match protocole::lire_reponse(t) {
        Some(Reponse::Ligne(id, l)) => {
            sans_piege(&l);
            assert!(l.chars().count() <= LIGNE_MAX);
            assert_eq!(protocole::lire_reponse(&protocole::coder_ligne(id, &l)), Some(Reponse::Ligne(id, l)));
        }
        Some(Reponse::Fin { id, code, issue, duree, sortie }) => {
            if let Issue::Impossible(e) = &issue {
                sans_piege(e);
                assert!(e.chars().count() <= 300);
            }
            assert!(sortie.len() <= t.len());
            let f = Fin { commande: Commande::Bilan, code, sortie, issue, duree };
            let recodee = protocole::coder_fin(id, &f);
            let Fin { code, sortie, issue, duree, .. } = f;
            assert_eq!(protocole::lire_reponse(&recodee), Some(Reponse::Fin { id, code, issue, duree, sortie }));
        }
        None => {}
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, reste)) = donnees.split_first() else { return };
    langue::choisir(Some(langue & 1 == 1));
    relais(reste);
    fenetre(reste);
    // Les mêmes octets en trames d'une réponse, bornées comme la fenêtre les borne (petite borne ici).
    let mut flux = reste;
    while let Ok(Some(t)) = protocole::lire_trame(&mut flux, 4096) {
        assert!(t.len() <= 4096);
        fenetre(&t);
    }
});
