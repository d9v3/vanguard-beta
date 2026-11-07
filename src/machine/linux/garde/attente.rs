//! Les demandes lues et pas encore répondues, pur : chacune n'est répondue qu'une fois, par celui qui la retire d'ici
//! (le fil de décision, le fil du délai qui la permet après 250 ms, ou l'arrêt qui permet tout). Le descripteur reste
//! ouvert tant que quelqu'un le tient (`Arc`) : son numéro ne peut pas être repris par une autre demande entre-temps,
//! et la comparaison des pointeurs en est la ceinture.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Le délai au-delà duquel une demande est permise sans verdict (P9).
pub(crate) const DELAI: Duration = Duration::from_millis(250);

/// Les demandes en attente, par numéro de descripteur.
#[derive(Debug)]
pub(crate) struct Attentes<T> {
    demandes: HashMap<i32, (Arc<T>, Instant)>,
}

impl<T> Default for Attentes<T> {
    fn default() -> Self {
        Attentes {
            demandes: HashMap::new(),
        }
    }
}

impl<T> Attentes<T> {
    pub(crate) fn ajouter(&mut self, fd: i32, porteur: Arc<T>, recue: Instant) {
        self.demandes.insert(fd, (porteur, recue));
    }

    /// Retire la demande pour y répondre : faux si quelqu'un d'autre l'a déjà fait.
    pub(crate) fn prendre(&mut self, fd: i32, porteur: &Arc<T>) -> bool {
        match self.demandes.get(&fd) {
            Some((p, _)) if Arc::ptr_eq(p, porteur) => {
                self.demandes.remove(&fd);
                true
            }
            _ => false,
        }
    }

    /// La demande attend-elle encore sa réponse ?
    pub(crate) fn contient(&self, fd: i32, porteur: &Arc<T>) -> bool {
        self.demandes.get(&fd).is_some_and(|(p, _)| Arc::ptr_eq(p, porteur))
    }

    /// Retire les demandes reçues il y a `delai` ou plus.
    pub(crate) fn en_retard(&mut self, maintenant: Instant, delai: Duration) -> Vec<(i32, Arc<T>)> {
        let vieilles: Vec<i32> = self
            .demandes
            .iter()
            .filter(|(_, (_, recue))| maintenant.saturating_duration_since(*recue) >= delai)
            .map(|(fd, _)| *fd)
            .collect();
        vieilles
            .into_iter()
            .filter_map(|fd| self.demandes.remove(&fd).map(|(p, _)| (fd, p)))
            .collect()
    }

    /// Retire toutes les demandes (l'arrêt).
    pub(crate) fn toutes(&mut self) -> Vec<(i32, Arc<T>)> {
        self.demandes.drain().map(|(fd, (p, _))| (fd, p)).collect()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.demandes.len()
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_demande_repondue_une_fois() {
        let mut a = Attentes::default();
        let t0 = Instant::now();
        let p = Arc::new(5u8);
        a.ajouter(5, Arc::clone(&p), t0);
        // Un autre porteur au même numéro (une demande plus ancienne déjà fermée) ne la prend pas.
        assert!(!a.prendre(5, &Arc::new(5u8)));
        assert!(a.contient(5, &p) && !a.contient(5, &Arc::new(5u8)));
        assert!(a.prendre(5, &p));
        assert!(!a.contient(5, &p));
        assert!(!a.prendre(5, &p), "déjà répondue");
        assert_eq!(a.len(), 0);
    }

    #[test]
    fn permises_apres_le_delai_et_toutes_a_l_arret() {
        let mut a = Attentes::default();
        let t0 = Instant::now();
        let (vieille, jeune) = (Arc::new(1u8), Arc::new(2u8));
        a.ajouter(1, Arc::clone(&vieille), t0);
        a.ajouter(2, Arc::clone(&jeune), t0 + Duration::from_millis(200));
        assert_eq!(a.en_retard(t0 + Duration::from_millis(249), DELAI).len(), 0);
        let retard = a.en_retard(t0 + DELAI, DELAI);
        assert_eq!(retard.len(), 1);
        assert_eq!(retard[0].0, 1);
        // Le fil de décision arrive trop tard : il ne répond pas une seconde fois.
        assert!(!a.prendre(1, &vieille));
        // Une horloge qui recule ne fait rien déborder.
        assert_eq!(a.en_retard(t0, DELAI).len(), 0);
        let restes = a.toutes();
        assert_eq!(restes.len(), 1);
        assert_eq!(restes[0].0, 2);
        assert_eq!(a.len(), 0);
    }
}
