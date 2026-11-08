//! Le résultat de « Vérifier un fichier téléchargé » (`modele::resultat`) : chaque signe vu (empreinte qui ne
//! correspond pas, nom ou contenu trompeur, détection d'un moteur), sa gravité, et ce qui n'a pas pu être vérifié,
//! sans l'écran. Versé au rapport (`examens/PRO-TEL-001.json`), au journal des événements, et rendu par `--json`.
//! Une source facultative absente du moteur (base ClamAV, empreintes de MalwareBazaar) est un manque ici : le
//! résultat n'est jamais « sain » sans réserve quand une source manquait.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use crate::machine::{Constat, alerte, impossible, ok};
use crate::modele::resultat::{Couverture, Resultat, sans_piege};
use crate::risk::Niveau;

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-TEL-001";

const CAT: &str = "Fichiers suspects";

/// Les étapes de la vérification : empreinte, nom et contenu, moteur de Vanguard, antivirus du système.
const ETAPES: u32 = 4;

pub(super) type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce qu'une vérification a relevé, sans l'écran.
#[derive(Default, Debug)]
pub(super) struct Releve {
    /// Les signes plus graves qu'une information, tels qu'écrits à l'écran.
    pub signes: Vec<(Niveau, String)>,
    /// Ce qui n'a pas pu être vérifié, une phrase par manque.
    pub manques: Vec<String>,
    /// L'empreinte publiée (d'un algorithme solide) correspond.
    pub conforme: bool,
}

/// Le résultat d'une vérification : un constat par signe, sinon « rien de suspect » (jamais une garantie).
pub(super) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    let mut constats: Vec<Constat> = r
        .signes
        .iter()
        .filter(|(n, _)| *n > Niveau::Info)
        // Les textes reprennent des noms venus du fichier ou du site (fichier d'empreintes, règle) : sans piège.
        .map(|(n, t)| alerte(CAT, *n, sans_piege(t, false)))
        .collect();
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            if r.conforme {
                crate::tr!(
                    "Empreinte conforme et rien de suspect dans ce qui a été vérifié (ce n'est pas une garantie).",
                    "Matching checksum and nothing suspicious in what was checked (that is not a guarantee)."
                )
            } else {
                crate::tr!(
                    "Rien de suspect dans ce qui a été vérifié ; l'empreinte n'a pas prouvé que c'est le fichier publié.",
                    "Nothing suspicious in what was checked; the checksum did not prove it is the published file."
                )
            },
        ));
    }
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: ETAPES,
            non_verifies: r.manques.iter().map(|m| sans_piege(m, false)).collect(),
        },
    )
}

/// Le résultat d'un fichier qui n'a pas pu être vérifié : rien de vérifié.
pub(super) fn refuse(raison: &str, debut: Debut) -> Resultat {
    Resultat::nouveau(ID, debut, &[impossible(CAT, raison)], Couverture::default())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    /// Sans signe ni manque : « sain » ; un manque (antivirus pas lancé, base ClamAV absente) : jamais « sain » ;
    /// une information ne compte pas ; un signe : « probleme » ; un refus : « non-verifie ».
    #[test]
    fn signes_et_manques() {
        let mut r = Releve::default();
        assert_eq!(resultat(&r, debut()).verdict(), "sain");
        r.manques.push("ClamAV : base absente".into());
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.signes.push((Niveau::Info, "nom ordinaire".into()));
        assert_eq!(resultat(&r, debut()).pire(), None);
        r.signes
            .push((Niveau::Moyen, "Vanguard : section écrivable et exécutable".into()));
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "probleme");
        assert_eq!(res.pire(), Some(Niveau::Moyen));
        assert_eq!(res.constats.len(), 1);
        assert_eq!(refuse("fichier introuvable", debut()).verdict(), "non-verifie");
    }

    /// Un nom piégé (U+202E, saut de ligne) repris dans un signe ou un manque n'arrive jamais tel quel au résultat.
    #[test]
    fn textes_sans_piege() {
        let r = Releve {
            signes: vec![(Niveau::Eleve, "facture\u{202e}fdp.exe\nsuite".into())],
            manques: vec!["lue dans x\u{1b}]52;c;y\u{7}".into()],
            conforme: false,
        };
        let json = crate::modele::resultat::json(&resultat(&r, debut()));
        assert!(
            !json.contains('\u{202e}') && !json.contains("\\u001b") && !json.contains("\\n"),
            "{json}"
        );
    }
}
