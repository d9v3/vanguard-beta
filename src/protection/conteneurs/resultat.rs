//! Le résultat des failles des images de conteneurs (`modele::resultat`) : une ligne par image analysée par trivy,
//! sans l'écran. Versé au rapport (`examens/PRO-CTN-001.json`), au journal des événements, et rendu par `--json`.
//!
//! Le mode `--json` ne télécharge rien et n'installe rien : sans trivy, ou sans sa base des failles, les images sont
//! dites non analysées, jamais saines. Une base de plus d'une semaine est dite aussi : les failles plus récentes n'y
//! sont pas.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use chrono::{DateTime, Utc};

use super::Faille;
use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Absence, Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-CTN-001";

const CAT: &str = "Conteneurs";

/// Au-delà, la base des failles ne connaît pas les plus récentes : c'est dit.
const BASE_JOURS_MAX: i64 = 7;

/// Les identifiants de failles critiques nommés par image ; les autres sont comptés.
const IDS_MAX: usize = 5;

type Debut = (DateTime<Utc>, std::time::Instant);

/// Ce que `super::relever` a pu voir, étape par étape.
#[derive(Debug)]
pub(super) enum Releve {
    SansMoteur,
    ListeIllisible,
    SansImage,
    SansTrivy {
        images: usize,
    },
    SansBase {
        images: usize,
    },
    Analyse {
        images: usize,
        /// La date de la base des failles de trivy.
        base: DateTime<Utc>,
        /// Les images analysées, dans l'ordre (nom affichable ; `None` : trivy a échoué ou n'a pas eu le temps).
        analysees: Vec<(String, Option<Vec<Faille>>)>,
    },
}

/// La date de la base des failles, d'après `trivy version --format json` ; `None` : pas de base, ou illisible.
pub(super) fn date_de_la_base(json: &str) -> Option<DateTime<Utc>> {
    let valeur: serde_json::Value = serde_json::from_str(json).ok()?;
    let date = valeur.get("VulnerabilityDB")?.get("UpdatedAt")?.as_str()?;
    DateTime::parse_from_rfc3339(date).ok().map(|d| d.with_timezone(&Utc))
}

pub(super) fn resultat(r: &Releve, debut: Debut) -> Resultat {
    let (constats, couverture) = juger(r, debut.0);
    Resultat::nouveau(ID, debut, &constats, couverture)
}

fn non_analysees(n: usize) -> String {
    match n {
        1 => tr!("1 image non analysée", "1 image not scanned").to_string(),
        n => trf!("{n} images non analysées", "{n} images not scanned"),
    }
}

fn juger(r: &Releve, maintenant: DateTime<Utc>) -> (Vec<Constat>, Couverture) {
    let mut constats = Vec::new();
    let mut non_verifies = Vec::new();
    let mut verifies = 0u32;
    // Un constat non vérifié, et sa raison dans la couverture.
    let manque = |c: Constat, pourquoi: String, constats: &mut Vec<Constat>, non_verifies: &mut Vec<String>| {
        constats.push(c);
        non_verifies.push(pourquoi);
    };
    match r {
        // Rien de vérifié : un autre moteur (containerd, nerdctl) n'est pas regardé.
        Releve::SansMoteur => constats.push(sans_objet(
            CAT,
            Absence::Logiciel,
            tr!(
                "Ni Docker ni Podman sur cet ordinateur : rien à analyser.",
                "Neither Docker nor Podman on this computer: nothing to scan."
            ),
        )),
        Releve::ListeIllisible => {
            let raison = tr!(
                "liste des images illisible : Docker est peut-être réservé à root et au groupe docker, ou arrêté",
                "image list unreadable: Docker may be reserved to root and the docker group, or stopped"
            );
            let c = impossible_par(
                CAT,
                Raison::Echoue(raison.into()),
                trf!("Non vérifié : {raison}.", "Not checked: {raison}."),
            );
            manque(c, raison.into(), &mut constats, &mut non_verifies);
        }
        Releve::SansImage => {
            constats.push(sans_objet(
                CAT,
                Absence::Inactif,
                tr!("Aucune image sur cet ordinateur.", "No image on this computer."),
            ));
            verifies = 1;
        }
        Releve::SansTrivy { images } => {
            let pourquoi = trf!(
                "{} : trivy (libre, licence Apache 2.0) n'est pas installé ; « vanguard conteneurs » propose de l'installer",
                "{}: trivy (open source, Apache 2.0 license) is not installed; “vanguard containers” offers to install it",
                non_analysees(*images)
            );
            let c = impossible_par(CAT, Raison::Absente("trivy".into()), format!("{pourquoi}."));
            manque(c, pourquoi, &mut constats, &mut non_verifies);
        }
        Releve::SansBase { images } => {
            let pourquoi = trf!(
                "{} : la base des failles de trivy est absente ou illisible ; « vanguard conteneurs » la télécharge",
                "{}: trivy's flaw database is missing or unreadable; “vanguard containers” downloads it",
                non_analysees(*images)
            );
            let c = impossible_par(CAT, Raison::Echoue(pourquoi.clone()), format!("{pourquoi}."));
            manque(c, pourquoi, &mut constats, &mut non_verifies);
        }
        Releve::Analyse {
            images,
            base,
            analysees,
        } => {
            let jours = maintenant.signed_duration_since(*base).num_days();
            if jours > BASE_JOURS_MAX {
                non_verifies.push(trf!(
                    "les failles des {jours} derniers jours : la base de trivy n'est pas à jour (« vanguard conteneurs » la met à jour)",
                    "flaws of the last {jours} days: trivy's database is not up to date (“vanguard containers” updates it)"
                ));
            }
            for (nom, failles) in analysees {
                let objet = Objet::de("image", nom);
                let Some(failles) = failles else {
                    let pourquoi = trf!(
                        "{nom} : pas pu être analysée, rien n'est conclu pour elle",
                        "{nom}: could not be scanned, nothing is concluded for it"
                    );
                    let c = impossible_par(CAT, Raison::Echoue(pourquoi.clone()), format!("{pourquoi}."));
                    manque(c.avec_objet(objet), pourquoi, &mut constats, &mut non_verifies);
                    continue;
                };
                verifies = verifies.saturating_add(1);
                constats.push(image(nom, failles).avec_objet(objet));
            }
            let restantes = images.saturating_sub(analysees.len());
            if restantes > 0 {
                non_verifies.push(trf!(
                    "{} : au plus {} images et {} minutes par examen",
                    "{}: at most {} images and {} minutes per scan",
                    non_analysees(restantes),
                    super::IMAGES_MAX,
                    super::BUDGET_S / 60
                ));
            }
        }
    }
    (constats, Couverture { verifies, non_verifies })
}

/// Le constat d'une image analysée : élevé s'il y a une faille critique, moyen si elles sont graves seulement.
fn image(nom: &str, failles: &[Faille]) -> Constat {
    if failles.is_empty() {
        return ok(
            CAT,
            trf!("{nom} : aucune faille grave connue.", "{nom}: no known serious flaw."),
        );
    }
    let critiques: Vec<&Faille> = failles.iter().filter(|f| f.critique).collect();
    let corrigees = failles.iter().filter(|f| f.corrigee).count();
    let mut message = trf!(
        "{nom} : {} critique(s), {} grave(s) ; {corrigees} corrigée(s) par une version plus récente : récupérez sa dernière version, puis recréez les conteneurs qui s'en servent.",
        "{nom}: {} critical, {} serious; {corrigees} fixed by a newer version: fetch its latest version, then recreate the containers that use it.",
        critiques.len(),
        failles.len().saturating_sub(critiques.len())
    );
    if !critiques.is_empty() {
        let ids: Vec<String> = critiques
            .iter()
            .take(IDS_MAX)
            .map(|f| format!("{} ({})", f.id, f.paquet))
            .collect();
        message.push_str(&trf!(" Critiques : {}", " Critical: {}", ids.join(", ")));
        let reste = critiques.len().saturating_sub(IDS_MAX);
        if reste > 0 {
            message.push_str(&trf!(", et {reste} autre(s)", ", and {reste} more"));
        }
        message.push('.');
    }
    let niveau = if critiques.is_empty() {
        Niveau::Moyen
    } else {
        Niveau::Eleve
    };
    alerte(CAT, niveau, message)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn maintenant() -> DateTime<Utc> {
        date_de_la_base(r#"{"VulnerabilityDB":{"UpdatedAt":"2030-01-10T06:00:00.123456789Z"}}"#).unwrap()
    }

    fn faille(n: usize, critique: bool) -> Faille {
        Faille {
            id: format!("CVE-2030-{n:04}"),
            paquet: "paquet-essai".into(),
            critique,
            corrigee: n.is_multiple_of(2),
        }
    }

    fn ecrit(r: &Releve) -> Resultat {
        resultat(r, (maintenant(), std::time::Instant::now()))
    }

    fn verdict(r: &Releve) -> &'static str {
        ecrit(r).verdict()
    }

    #[test]
    fn base_de_trivy() {
        assert_eq!(maintenant().timestamp(), 1_894_255_200);
        assert_eq!(date_de_la_base(r#"{"Version":"0.0.1"}"#), None);
        assert_eq!(date_de_la_base("pas du json"), None);
    }

    /// Ce qui n'a pas été analysé n'est jamais sain ; aucune image : sain.
    #[test]
    fn etapes_non_verifiees() {
        for r in [
            Releve::SansMoteur,
            Releve::ListeIllisible,
            Releve::SansTrivy { images: 3 },
            Releve::SansBase { images: 1 },
        ] {
            assert_eq!(verdict(&r), "non-verifie", "{r:?}");
        }
        assert_eq!(verdict(&Releve::SansImage), "sain");
        let c = ecrit(&Releve::SansTrivy { images: 2 }).constats;
        assert_eq!(c[0].raison.as_deref(), Some("absente"));
    }

    /// Une image critique, une grave, une saine, une en échec, et deux au-delà des bornes.
    #[test]
    fn images_jugees() {
        let critiques: Vec<Faille> = (0..8).map(|n| faille(n, true)).chain([faille(9, false)]).collect();
        let r = Releve::Analyse {
            images: 6,
            base: maintenant(),
            analysees: vec![
                ("a:1".into(), Some(critiques)),
                ("b:1".into(), Some(vec![faille(1, false)])),
                ("c:1".into(), Some(Vec::new())),
                ("d:1".into(), None),
            ],
        };
        let Resultat {
            constats: c,
            couverture,
            ..
        } = ecrit(&r);
        assert_eq!(couverture.verifies, 3);
        assert_eq!(couverture.non_verifies.len(), 2);
        assert_eq!(c[0].niveau, Some(Niveau::Eleve));
        assert!(c[0].message.contains("CVE-2030-0004") && !c[0].message.contains("CVE-2030-0005"));
        assert!(c[0].message.contains(", et 3") || c[0].message.contains(", and 3"));
        assert_eq!(c[1].niveau, Some(Niveau::Moyen));
        assert_eq!(c[2].niveau, None);
        assert_eq!(c[3].raison.as_deref(), Some("echoue"));
        assert_eq!(verdict(&r), "probleme");
    }

    /// Une base de plus d'une semaine : ce qui est sain y est dit non vérifié.
    #[test]
    fn base_trop_vieille() {
        let base = maintenant() - chrono::Duration::days(BASE_JOURS_MAX + 1);
        let r = Releve::Analyse {
            images: 1,
            base,
            analysees: vec![("a:1".into(), Some(Vec::new()))],
        };
        assert_eq!(verdict(&r), "non-verifie");
        let r = Releve::Analyse {
            images: 1,
            base: maintenant(),
            analysees: vec![("a:1".into(), Some(Vec::new()))],
        };
        assert_eq!(verdict(&r), "sain");
    }
}
