//! Le budget d'un tour de mission : ce qu'elle peut lire, combien de décisions elle peut rendre, et en combien de
//! temps. Un budget épuisé arrête la mission (`Arret`) : rien n'est décidé sur une observation à moitié faite.

use std::time::{Duration, Instant};

/// Pourquoi une mission s'arrête avant de juger. Fermé : rien qu'un fichier lu ne puisse ajouter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Arret {
    /// Plus de lectures permises.
    Lectures,
    /// Le temps du tour est passé.
    Temps,
    /// Rien à observer : le levier est coupé, ou son fichier douteux (les valeurs du code s'appliquent).
    Coupe,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Budget {
    lectures: u16,
    decisions: u16,
    fin: Instant,
}

impl Budget {
    pub(crate) fn new(lectures: u16, decisions: u16, duree: Duration) -> Budget {
        Budget {
            lectures,
            decisions,
            fin: Instant::now() + duree,
        }
    }

    /// Une lecture de plus : refusée quand il n'en reste plus, ou que le temps est passé.
    pub(crate) fn lire(&mut self) -> Result<(), Arret> {
        self.temps()?;
        self.lectures = self.lectures.checked_sub(1).ok_or(Arret::Lectures)?;
        Ok(())
    }

    pub(crate) fn temps(&self) -> Result<(), Arret> {
        if Instant::now() > self.fin {
            Err(Arret::Temps)
        } else {
            Ok(())
        }
    }

    /// Décisions au plus que le tour garde (les suivantes sont laissées, jamais appliquées).
    pub(crate) fn decisions(&self) -> u16 {
        self.decisions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lectures_et_temps_comptes() {
        let mut b = Budget::new(2, 3, Duration::from_secs(60));
        assert_eq!(b.lire(), Ok(()));
        assert_eq!(b.lire(), Ok(()));
        assert_eq!(b.lire(), Err(Arret::Lectures));
        let mut b = Budget::new(5, 3, Duration::ZERO);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(b.lire(), Err(Arret::Temps));
        assert_eq!(b.decisions(), 3);
    }
}
