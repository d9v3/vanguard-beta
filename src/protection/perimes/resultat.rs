//! Le résultat de l'examen des logiciels pas à jour (`modele::resultat`) : le jugement du bilan, sans l'écran. Versé
//! au rapport (`examens/PRO-PER-001.json`), au journal des événements, et rendu par `--json`.

use crate::modele::resultat::{Couverture, Resultat};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-PER-001";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'un bilan : un constat par logiciel ou groupe jugé, les logiciels dont la version n'a pas pu être
/// comparée comptés non vérifiés.
#[cfg(any(windows, test))]
#[cfg_attr(not(windows), allow(dead_code))] // l'écran ne tourne que sous Windows
pub(super) fn resultat(b: &super::rapport::Bilan, debut: Debut) -> Resultat {
    let mut non_verifies = super::rapport::non_verifies(b);
    // Rien de suivi trouvé : le verdict reste « non vérifié » (un logiciel installé ailleurs n'est pas vu), mais il
    // dit pourquoi, comme l'écran ; sans cela le rapport disait « pas tout vérifié » sans aucune ligne « ? ».
    if b.juges.is_empty() && non_verifies.is_empty() {
        non_verifies.push(super::rapport::aucun().to_string());
    }
    // Les logiciels jugés dont la version a pu être comparée : les comptes et dossiers non lus ne s'en retirent pas.
    let verifies = b.juges.iter().filter(|j| !j.non_verifie()).count();
    Resultat::nouveau(
        ID,
        debut,
        &super::rapport::constats_de(b),
        Couverture {
            verifies: u32::try_from(verifies).unwrap_or(u32::MAX),
            non_verifies,
        },
    )
}

/// Hors de Windows, l'outil ne juge rien : le gestionnaire de paquets tient les versions. Un résultat
/// sans objet, jamais sain (rien n'a été vérifié).
#[cfg(any(not(windows), test))]
pub(crate) fn hors_portee(debut: Debut) -> Resultat {
    use crate::modele::Absence;
    Resultat::nouveau(
        ID,
        debut,
        &[crate::machine::sans_objet(
            "Logiciels pas à jour",
            Absence::Plateforme,
            crate::tr!(
                "Ce contrôle vise Windows ; sous Linux, le gestionnaire de paquets tient les versions.",
                "This check is for Windows; on Linux, the package manager keeps the versions."
            ),
        )],
        Couverture::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Aucun logiciel suivi trouvé : jamais sain, et la raison est dite (comme à l'écran).
    #[test]
    fn aucun_logiciel_suivi_dit_pourquoi() {
        let b = super::super::rapport::Bilan {
            juges: Vec::new(),
            non_lus: Vec::new(),
            kev: Ok(Vec::new()),
            age: None,
            manques: Vec::new(),
        };
        let r = resultat(&b, (chrono::Utc::now(), std::time::Instant::now()));
        assert_eq!(r.verdict(), "non-verifie");
        assert_ne!(r.couverture.non_verifies, Vec::<String>::new());
        assert_eq!(r.couverture.verifies, 0);
    }

    #[test]
    fn hors_portee_jamais_sain() {
        let r = hors_portee((chrono::Utc::now(), std::time::Instant::now()));
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.constats[0].etat, "sans-objet");
    }
}
