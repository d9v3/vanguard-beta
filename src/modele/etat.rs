//! L'état d'un constat, en quatre cas qui ne se confondent jamais : sain, sans objet (absence prouvée), non vérifié
//! (avec sa raison), problème (avec son niveau). C'est une vue calculée sur `probleme` et `verifie`, que les 500 et
//! quelques lectures du code gardent telles quelles ; seule la précision (l'absence, la raison) s'ajoute.

use super::Raison;
use crate::risk::Niveau;

/// Pourquoi une règle n'a rien à juger : une absence PROUVÉE, jamais une lecture qui a échoué.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Absence {
    /// Le matériel n'existe pas ici (pas de carte Wi-Fi).
    Materiel,
    /// Le logiciel jugé n'est pas installé.
    Logiciel,
    /// Le système ne l'a pas (version, édition).
    Plateforme,
    /// Il existe mais ne sert pas en ce moment (Wi-Fi présent, aucun réseau connecté).
    Inactif,
}

impl Absence {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Absence::Materiel => "materiel",
            Absence::Logiciel => "logiciel",
            Absence::Plateforme => "plateforme",
            Absence::Inactif => "inactif",
        }
    }
}

/// Ce que `probleme` et `verifie` ne disent pas d'un constat.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) enum Precision {
    #[default]
    Aucune,
    /// Rien à juger ici (`verifie` vrai, sans problème).
    SansObjet(Absence),
    /// La raison d'un « non vérifié » (`verifie` faux).
    NonVerifie(Raison),
}

/// L'état d'un constat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Etat {
    Sain,
    SansObjet(Absence),
    NonVerifie(Raison),
    Probleme { niveau: Niveau },
}

impl Etat {
    /// La vue sur les champs d'un constat. Non vérifié l'emporte sur tout : un niveau posé sur un constat non
    /// vérifié baisse la note, mais ne le fait jamais passer pour vérifié.
    pub(crate) fn de(probleme: Option<Niveau>, verifie: bool, precision: &Precision) -> Etat {
        match (verifie, probleme, precision) {
            (false, _, Precision::NonVerifie(r)) => Etat::NonVerifie(r.clone()),
            (false, _, _) => Etat::NonVerifie(Raison::NonPrecisee),
            (true, Some(niveau), _) => Etat::Probleme { niveau },
            (true, None, Precision::SansObjet(a)) => Etat::SansObjet(*a),
            (true, None, _) => Etat::Sain,
        }
    }

    /// Le code stable, pour le JSON et les fichiers.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Etat::Sain => "sain",
            Etat::SansObjet(_) => "sans-objet",
            Etat::NonVerifie(_) => "non-verifie",
            Etat::Probleme { .. } => "probleme",
        }
    }
}

/// Une combinaison que les constructeurs ne font jamais : non vérifié avec un niveau élevé ou critique (une alerte
/// qu'on ne peut pas prouver ne crie pas plus fort qu'un « moyen »), sain avec une correction, une précision qui
/// contredit `verifie`.
pub(crate) fn coherent(probleme: Option<Niveau>, verifie: bool, correctif: bool, precision: &Precision) -> bool {
    let trop_fort = !verifie && probleme.is_some_and(|n| n >= Niveau::Eleve);
    let sain_corrige = verifie && probleme.is_none() && correctif;
    let contredit = match precision {
        Precision::Aucune => false,
        Precision::SansObjet(_) => !verifie || probleme.is_some(),
        Precision::NonVerifie(_) => verifie,
    };
    !(trop_fort || sain_corrige || contredit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quatre_cas_sans_confusion() {
        let p = Precision::Aucune;
        assert_eq!(Etat::de(None, true, &p), Etat::Sain);
        assert_eq!(
            Etat::de(Some(Niveau::Moyen), true, &p),
            Etat::Probleme { niveau: Niveau::Moyen }
        );
        // L'« impossible » d'avant : Info, non vérifié.
        assert_eq!(
            Etat::de(Some(Niveau::Info), false, &p),
            Etat::NonVerifie(Raison::NonPrecisee)
        );
        let muette = Precision::NonVerifie(Raison::Muette);
        assert_eq!(
            Etat::de(Some(Niveau::Info), false, &muette),
            Etat::NonVerifie(Raison::Muette)
        );
        // Un non vérifié qui porte un niveau reste non vérifié.
        assert_eq!(
            Etat::de(Some(Niveau::Moyen), false, &p),
            Etat::NonVerifie(Raison::NonPrecisee)
        );
        let codes: Vec<&str> = [
            Absence::Materiel,
            Absence::Logiciel,
            Absence::Plateforme,
            Absence::Inactif,
        ]
        .into_iter()
        .map(Absence::code)
        .collect();
        assert_eq!(codes, ["materiel", "logiciel", "plateforme", "inactif"]);
        let sans = Precision::SansObjet(Absence::Materiel);
        assert_eq!(Etat::de(None, true, &sans), Etat::SansObjet(Absence::Materiel));
        // Une absence posée sur un constat non vérifié ne le rend jamais « sans objet ».
        assert!(matches!(Etat::de(None, false, &sans), Etat::NonVerifie(_)));
    }

    #[test]
    fn combinaisons_refusees() {
        let p = Precision::Aucune;
        assert!(coherent(None, true, false, &p));
        assert!(coherent(Some(Niveau::Moyen), false, false, &p));
        assert!(!coherent(Some(Niveau::Critique), false, false, &p));
        assert!(!coherent(None, true, true, &p));
        assert!(!coherent(
            Some(Niveau::Info),
            true,
            false,
            &Precision::SansObjet(Absence::Inactif)
        ));
        assert!(!coherent(None, true, false, &Precision::NonVerifie(Raison::Muette)));
        assert!(coherent(
            Some(Niveau::Info),
            false,
            false,
            &Precision::NonVerifie(Raison::Muette)
        ));
    }
}
