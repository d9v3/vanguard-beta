//! La fenêtre glissante des changements de fichiers, bornée : ce que le veilleur accumule avant de juger une rafale.
//! Un `Changement` est un fait vu par `notify` (contenu réécrit, renommage, création, suppression), horodaté. La
//! `Fenetre` garde les changements des dernières secondes, au plus 4 096 (au-delà, comptés « perdus » : un
//! débordement est lui-même un signal de rafale, jamais un calme).

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// La durée de la fenêtre courte, qui sert au quasi-certain : 10 secondes (un disque lent et un rançongiciel qui
/// temporise un peu tiennent dedans).
pub(crate) const FENETRE: Duration = Duration::from_secs(10);
/// Au plus tant de changements gardés : au-delà, les plus vieux partent et le compteur « perdus » monte.
pub(crate) const CHANGEMENTS_MAX: usize = 4_096;

/// La sorte d'un changement vu sur un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Sorte {
    /// Contenu réécrit puis refermé (`Close(Write)`) : le cas le plus courant d'un chiffrement en place.
    Ecrit,
    /// Renommé : l'ancien nom (dans le même dossier ou un autre). Sert à retrouver l'extension d'origine.
    Renomme { ancien: PathBuf },
    /// Créé.
    Cree,
    /// Supprimé.
    Supprime,
}

/// Un changement vu, horodaté. `quand` est un `Instant` : des durées, jamais une heure murale, pour la fenêtre.
#[derive(Debug, Clone)]
pub(crate) struct Changement {
    pub quand: Instant,
    pub chemin: PathBuf,
    pub sorte: Sorte,
}

impl Changement {
    pub(crate) fn nouveau(chemin: PathBuf, sorte: Sorte) -> Changement {
        Changement {
            quand: Instant::now(),
            chemin,
            sorte,
        }
    }
}

/// La fenêtre glissante, bornée.
#[derive(Debug, Default)]
pub(crate) struct Fenetre {
    changements: VecDeque<Changement>,
    /// Combien ont été jetés faute de place : dits, jamais oubliés.
    perdus: u64,
}

impl Fenetre {
    pub(crate) fn nouvelle() -> Fenetre {
        Fenetre::default()
    }

    /// Ajoute un changement, enlève ceux qui sortent de la fenêtre, et borne la taille (au-delà, le plus vieux part et
    /// « perdus » monte). Rend vrai si la fenêtre a débordé.
    pub(crate) fn ajouter(&mut self, c: Changement) -> bool {
        let limite = c.quand.checked_sub(FENETRE);
        self.changements.push_back(c);
        if let Some(limite) = limite {
            while self.changements.front().is_some_and(|c| c.quand < limite) {
                self.changements.pop_front();
            }
        }
        let mut deborde = false;
        while self.changements.len() > CHANGEMENTS_MAX {
            self.changements.pop_front();
            self.perdus = self.perdus.saturating_add(1);
            deborde = true;
        }
        deborde
    }

    /// Les changements encore dans la fenêtre à l'instant `maintenant` (les plus vieux sont écartés sans être
    /// comptés perdus : ils ont seulement vieilli).
    pub(crate) fn actuels(&self, maintenant: Instant) -> impl Iterator<Item = &Changement> {
        let limite = maintenant.checked_sub(FENETRE);
        self.changements
            .iter()
            .filter(move |c| limite.is_none_or(|l| c.quand >= l))
    }

    /// Ajoute des changements jetés avant d'arriver ici (canal de la veille plein) : un débordement en amont compte
    /// comme celui de la fenêtre, dit et jamais pris pour un calme.
    pub(crate) fn noter_perdus(&mut self, n: u64) {
        self.perdus = self.perdus.saturating_add(n);
    }

    /// Les débordements accumulés, remis à zéro (dits, jamais oubliés).
    pub(crate) fn prendre_perdus(&mut self) -> u64 {
        std::mem::take(&mut self.perdus)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.changements.len()
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
    fn bornee_et_perdus_comptes() {
        let mut f = Fenetre::nouvelle();
        let t = Instant::now();
        for i in 0..(CHANGEMENTS_MAX + 100) {
            f.changements.push_back(Changement {
                quand: t,
                chemin: PathBuf::from(format!("/tmp/f{i}")),
                sorte: Sorte::Ecrit,
            });
            while f.changements.len() > CHANGEMENTS_MAX {
                f.changements.pop_front();
                f.perdus += 1;
            }
        }
        assert_eq!(f.len(), CHANGEMENTS_MAX);
        assert_eq!(f.prendre_perdus(), 100);
    }

    #[test]
    fn vieux_changements_ecartes_sans_etre_perdus() {
        let mut f = Fenetre::nouvelle();
        let maintenant = Instant::now();
        f.changements.push_back(Changement {
            quand: maintenant.checked_sub(Duration::from_secs(20)).unwrap(),
            chemin: PathBuf::from("/tmp/vieux"),
            sorte: Sorte::Ecrit,
        });
        f.changements.push_back(Changement {
            quand: maintenant,
            chemin: PathBuf::from("/tmp/neuf"),
            sorte: Sorte::Ecrit,
        });
        assert_eq!(f.actuels(maintenant).count(), 1);
        assert_eq!(f.prendre_perdus(), 0);
    }
}
