//! La forme des ordres du blocage que l'assistant élevé de Linux et macOS et le processus élevé de Windows lisent du
//! Vanguard non élevé (src/protection/blocage/ordres_ligne.rs) : verbes hors de la liste, pare-feu inconnus,
//! adresses écrites autrement (IPv4 en IPv6, zéros de tête), ports nuls ou démesurés, chemins en hexadécimal piégés
//! (majuscules, longueur impaire, relatif, NUL, saut de ligne), lignes démesurées ; et le non-recouvrement avec les
//! gestes de Linux (src/machine/gestes_unix.rs), qui passent par le même canal.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/protection/blocage/ordres_ligne.rs"]
mod ordres_ligne;

#[allow(dead_code)]
#[path = "../../src/machine/gestes_unix.rs"]
mod gestes_unix;

/// Ce qu'ordres_ligne.rs demande à `super::pare_feu` : les quatre pare-feu de
/// src/protection/blocage/pare_feu.rs, sans le reste du module (qui lance des commandes).
mod pare_feu {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum PareFeu {
        Ufw,
        Nftables,
        Windows,
        Pf,
    }
}

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    for l in texte.split('\n') {
        let Some(o) = ordres_ligne::analyser(l) else {
            continue;
        };
        // Une ligne relue se réécrit à l'identique : rien d'autre que sa forme exacte n'est accepté.
        assert_eq!(o.ligne(), l);
        assert_eq!(ordres_ligne::analyser(&o.ligne()), Some(o.clone()));
        assert!(l.len() <= ordres_ligne::LIGNE_MAX && l.is_ascii());
        assert!(l.starts_with(ordres_ligne::PREFIXE));
        assert!(!l.contains(['\0', '\r', '\t']));
        // Un ordre n'est jamais un geste de Linux, ni l'inverse : chacun a son verbe.
        assert!(!gestes_unix::a_le_prefixe(l));
        assert_eq!(gestes_unix::analyser(l), None);
        match o {
            ordres_ligne::Ordre::FermerPort { port, .. } | ordres_ligne::Ordre::RouvrirPort { port, .. } => {
                assert_ne!(port, 0);
            }
            ordres_ligne::Ordre::ArreterProcessus { pid, chemin } => {
                assert_ne!(pid, 0);
                assert!(!chemin.is_empty() && chemin.len() <= ordres_ligne::CHEMIN_MAX);
                assert!(!chemin.contains(['\0', '\n', '\r']));
            }
            _ => {}
        }
    }
    // Un geste de Linux relu n'est jamais lu comme un ordre.
    for l in texte.split('\n') {
        if gestes_unix::analyser(l).is_some() {
            assert_eq!(ordres_ligne::analyser(l), None);
        }
    }
});
