//! Le lecteur des événements de fanotify et de /proc/self/mountinfo que le garde (root) et le veilleur (temps réel
//! des fichiers, sans droits) lisent (src/machine/linux/fanotify/lecture.rs) : versions de métadonnées inconnues,
//! longueurs nulles, coupées, démesurées ou qui sortent du tampon, enregistrements d'information mal formés (longueur
//! nulle, PIDFD en double ou de mauvaise taille, DFID_NAME en double, à la poignée démesurée ou au nom sans fin),
//! tampons pleins d'événements ; lignes de mountinfo hostiles (échappements faux, champs manquants, types inconnus).
//! Les octets vont aux deux lecteurs d'événements, tout le texte au lecteur de montages.
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

#[allow(dead_code)]
#[path = "../../src/machine/linux/fanotify/lecture.rs"]
mod lecture;

libfuzzer_sys::fuzz_target!(|octets: &[u8]| {
    let l = lecture::evenements(octets);
    assert!(l.evenements.len() <= lecture::EVENEMENTS_MAX);
    // Chaque événement lu tient dans le tampon ; un PIDFD rendu est un descripteur (jamais FAN_NOPIDFD ni FAN_EPIDFD).
    assert!(l.evenements.len().saturating_mul(lecture::TAILLE_METADONNEES) <= octets.len());
    for e in &l.evenements {
        assert!(e.pidfd.is_none_or(|p| p >= 0));
        // Réécrit comme le noyau l'écrit, il se relit tel quel.
        let t = lecture::ecrire(e, e.pidfd);
        assert_eq!(lecture::evenements(&t).evenements, vec![*e]);
    }
    // Le groupe de notification du veilleur : chaque nom rendu est borné, non vide, sans NUL, et se relit tel quel.
    let n = lecture::evenements_nommes(octets);
    assert!(n.evenements.len() <= lecture::EVENEMENTS_MAX);
    for e in &n.evenements {
        if let Some(nom) = &e.nom {
            assert!(!nom.is_empty() && nom.len() <= lecture::NOM_MAX && !nom.contains(&0));
        }
        let t = lecture::ecrire_nomme(e);
        assert_eq!(lecture::evenements_nommes(&t).evenements, vec![e.clone()]);
    }
    // Sans défaut, tout le tampon a été lu ; vide, rien.
    if octets.is_empty() {
        assert_eq!(l, lecture::Lecture::default());
    }
    if let Ok(texte) = std::str::from_utf8(octets) {
        let m = lecture::locaux(texte);
        assert!(m.len() <= lecture::MONTAGES_MAX);
        for (i, x) in m.iter().enumerate() {
            assert!(lecture::local(&x.genre));
            assert!(x.point.starts_with('/'));
            // Un système de fichiers n'est marqué qu'une fois.
            assert!(m.iter().skip(i + 1).all(|y| y.dev != x.dev));
        }
    }
});
