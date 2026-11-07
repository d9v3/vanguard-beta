//! Le lecteur des événements de fanotify et de /proc/self/mountinfo que le garde (root) lit
//! (src/machine/linux/fanotify/lecture.rs) : versions de métadonnées inconnues, longueurs nulles, coupées,
//! démesurées ou qui sortent du tampon, enregistrements d'information mal formés (longueur nulle, PIDFD en double ou
//! de mauvaise taille), tampons pleins d'événements ; lignes de mountinfo hostiles (échappements faux, champs
//! manquants, types inconnus). La première moitié des octets va au lecteur d'événements, tout le texte au lecteur de
//! montages.
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
