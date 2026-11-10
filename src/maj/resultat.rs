//! Le résultat des mises à jour (`modele::resultat`), pour `vanguard mises-a-jour --json` : ce que la recherche de
//! l'écran a trouvé (paquets, Flatpak, Snap, AUR, firmware, pilotes, noyau chargé ; sous Windows, Windows Update,
//! winget, signatures de Defender, périphériques), sans l'écran ni l'installation, versé au rapport
//! (`examens/PRO-MAJ-001.json`) et au journal.
//!
//! Une catégorie par constat (la recherche résume déjà chaque liste en un nombre) : la taille reste bornée. Une
//! recherche qui n'a pas pu se faire (hors ligne, outil absent, service muet), une source pas interrogée sans
//! Internet, l'AUR sans l'accord d'y envoyer des noms : non vérifié, jamais « tout est à jour ».

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::Constat;
use crate::modele::resultat::{Couverture, Resultat, nom_sans_piege};
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-MAJ-001";

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'une recherche : ses constats tels quels, chaque recherche faite comptée vérifiée, chaque recherche
/// impossible dite. `hors_ligne` : pourquoi les sources en ligne n'ont pas été interrogées.
pub(super) fn resultat(
    constats: &[Constat],
    hors_ligne: Option<&str>,
    aur_sans_accord: bool,
    debut: Debut,
) -> Resultat {
    let verifies = u32::try_from(constats.iter().filter(|c| c.verifie).count()).unwrap_or(u32::MAX);
    let mut non_verifies: Vec<String> = constats
        .iter()
        .filter(|c| !c.verifie)
        .map(|c| {
            format!(
                "{} : {}",
                crate::langue::categorie(c.categorie),
                nom_sans_piege(&c.message, 200)
            )
        })
        .collect();
    if let Some(raison) = hors_ligne {
        non_verifies.push(trf!(
            "dépôts, programmes et firmware pas interrogés : {}",
            "repositories, programs and firmware not queried: {}",
            raison
        ));
    }
    if aur_sans_accord {
        non_verifies.push(
            tr!(
                "paquets AUR pas vérifiés : leurs noms ne partent vers l'AUR qu'avec l'accord donné dans Paramètres",
                "AUR packages not checked: their names go to the AUR only with the consent given in Settings"
            )
            .to_string(),
        );
    }
    Resultat::nouveau(ID, debut, constats, Couverture { verifies, non_verifies })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{alerte, impossible, ok};
    use crate::risk::Niveau;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Des mises à jour en attente : un problème, corrigeable, sans que rien soit installé ici.
    #[test]
    fn mises_a_jour_trouvees() {
        let constats = [
            alerte("Mises à jour", Niveau::Moyen, "3 paquet(s) à mettre à jour.")
                .corriger("Mettre le système à jour", &["pacman -Syu"]),
            ok("Flatpak", "Flatpak à jour."),
        ];
        let r = resultat(&constats, None, false, debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (2, "probleme"));
        assert!(r.constats[0].corrigeable);
    }

    /// Tout cherché, rien en attente : sain.
    #[test]
    fn rien_en_attente_sain() {
        let r = resultat(&[ok("Mises à jour", "Système à jour.")], None, false, debut());
        assert_eq!(r.verdict(), "sain");
    }

    /// Une recherche impossible, les sources en ligne sautées ou l'AUR sans accord : partiel, jamais sain, même
    /// quand tout ce qui a été lu est à jour.
    #[test]
    fn partiel_jamais_sain() {
        let a_jour = || ok("Mises à jour", "Système à jour.");
        let r = resultat(&[a_jour(), impossible("Firmware", "fwupd muet")], None, false, debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (1, "non-verifie"));
        assert!(r.couverture.non_verifies[0].contains("fwupd muet"));
        let r = resultat(&[a_jour()], Some("travail sans Internet demandé"), false, debut());
        assert_eq!(r.verdict(), "non-verifie");
        let r = resultat(&[a_jour()], None, true, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(resultat(&[], None, false, debut()).verdict(), "non-verifie");
    }
}
