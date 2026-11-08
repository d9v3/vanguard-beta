//! La forme des ordres du blocage que l'assistant élevé de Linux et le processus élevé de Windows lisent du
//! Vanguard non élevé (src/protection/blocage/ordres_ligne.rs) : verbes hors de la liste, pare-feu inconnus,
//! adresses écrites autrement (IPv4 en IPv6, zéros de tête), ports nuls ou démesurés, chemins en hexadécimal piégés
//! (majuscules, longueur impaire, relatif, NUL, saut de ligne), départs absents ou nuls de la coupure du réseau d'un
//! programme, comptes root ou pauses démesurées du garde, adresses gardées par l'isolement en double, en désordre,
//! IPv4 écrites en IPv6 ou trop nombreuses, lignes démesurées ; et le non-recouvrement avec les
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

/// Ce qu'ordres_ligne.rs demande à `super::pare_feu` : les trois pare-feu de
/// src/protection/blocage/pare_feu.rs, sans le reste du module (qui lance des commandes).
mod pare_feu {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum PareFeu {
        Ufw,
        Nftables,
        Windows,
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
            ordres_ligne::Ordre::ArreterProcessus { pid, chemin, .. }
            | ordres_ligne::Ordre::SuspendreProcessus { pid, chemin, .. }
            | ordres_ligne::Ordre::ReprendreProcessus { pid, chemin, .. } => {
                assert_ne!(pid, 0);
                assert!(!chemin.is_empty() && chemin.len() <= ordres_ligne::CHEMIN_MAX);
                assert!(!chemin.contains(['\0', '\n', '\r']));
            }
            // La coupure du réseau d'un programme : le départ est toujours là, jamais nul (anti-course).
            ordres_ligne::Ordre::CouperReseauProgramme { pid, chemin, depart }
            | ordres_ligne::Ordre::RendreReseauProgramme { pid, chemin, depart } => {
                assert_ne!(pid, 0);
                assert_ne!(depart, 0);
                assert!(!chemin.is_empty() && chemin.len() <= ordres_ligne::CHEMIN_MAX);
                assert!(!chemin.contains(['\0', '\n', '\r']));
            }
            ordres_ligne::Ordre::RendreReseauFichier { chemin } => {
                assert!(!chemin.is_empty() && chemin.len() <= ordres_ligne::CHEMIN_MAX);
                assert!(!chemin.contains(['\0', '\n', '\r']));
            }
            // Le garde : jamais posé pour root, ses listes sous un chemin absolu ; une pause bornée.
            ordres_ligne::Ordre::GardePoser { compte, dossier } => {
                assert_ne!(compte, 0);
                assert!(dossier.starts_with('/') && dossier.len() <= ordres_ligne::CHEMIN_MAX);
                assert!(!dossier.contains(['\0', '\n', '\r']));
            }
            ordres_ligne::Ordre::GardePause { secondes } => assert!(secondes <= ordres_ligne::PAUSE_MAX),
            // L'isolement : des sessions exactes (adresse d'hôte, deux ports non nuls), triées sans double, bornées ;
            // jamais une forme IPv4 écrite en IPv6.
            ordres_ligne::Ordre::Isoler { garder } => {
                assert!(garder.len() <= ordres_ligne::GARDER_MAX);
                assert!(garder.windows(2).all(|p| p[0] < p[1]));
                for s in &garder {
                    let ip = s.distante;
                    assert!(!ip.is_unspecified() && !ip.is_multicast() && ip.to_canonical() == ip);
                    assert!(s.port_distant != 0 && s.port_local != 0);
                    assert_eq!(ordres_ligne::SessionGardee::lire(&s.texte()), Some(*s));
                }
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
