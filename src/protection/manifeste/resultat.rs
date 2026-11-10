//! Le résultat de « Vérifier Vanguard lui-même » (`modele::resultat`, PRO-MOI-001), sans l'écran : version et date de
//! compilation, empreinte SHA-256 du programme, comparaison au manifeste de la clé du propriétaire, et l'historique
//! signé des versions publiées. Rendu par `vanguard verifier-moi --json`. Rien n'y est demandé : l'historique signé,
//! qui demande un accord avant d'aller sur GitHub, n'est pas comparé, et c'est dit ; le résultat n'est donc jamais
//! « sain ». Une empreinte calculée n'est pas une preuve (qui remplace le programme peut mentir) : elle est dite, à
//! comparer, jamais comptée vérifiée ; seule une comparaison faite (manifeste identique) l'est.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::Comparaison;
use crate::machine::{Constat, alerte, impossible, impossible_par, ok};
use crate::modele::Raison;
use crate::modele::resultat::{Couverture, Resultat};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-MOI-001";

const CAT: &str = "Intégrité";

pub(crate) type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Pourquoi l'historique signé des versions n'a pas été comparé.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Historique {
    /// Travail sans Internet.
    HorsLigne,
    /// La comparaison demande un accord, et `--json` ne pose pas de question.
    SansAccord,
}

/// Ce que la vérification a relevé.
#[derive(Debug)]
pub(crate) struct Moi {
    /// La version de ce programme ; `None` pour une autre copie (sa version ne se lit pas sans la lancer).
    pub version: Option<&'static str>,
    /// La date du dernier commit compilé, et son âge en jours.
    pub compile: Option<(chrono::NaiveDate, i64)>,
    /// La ligne d'avertissement d'une copie trop vieille (`avertissement`).
    pub perime: Option<String>,
    /// Le programme vérifié, prêt à montrer ; `None` : impossible de savoir quel fichier tourne.
    pub programme: Option<String>,
    /// Son empreinte SHA-256, ou pourquoi elle n'a pas pu être calculée.
    pub sha256: Option<Result<String, String>>,
    /// Le manifeste de la clé ; `None` : pas lancé depuis la clé (ou une autre copie, qu'il ne nomme pas).
    pub manifeste: Option<Comparaison>,
    pub historique: Historique,
}

/// Le résultat : ce qui a été vérifié (manifeste identique), ce qui est seulement dit (version, empreinte), et ce qui
/// ne l'a pas été.
pub(crate) fn resultat(m: &Moi, debut: Debut) -> Resultat {
    let mut constats: Vec<Constat> = Vec::new();
    let mut manques: Vec<String> = Vec::new();
    let mut verifies = 0u32;
    if let Some(v) = m.version {
        constats.push(ok(
            CAT,
            match m.compile {
                Some((date, jours)) => trf!(
                    "Version {v}, compilée le {date} (il y a {jours} jour(s)).",
                    "Version {v}, built on {date} ({jours} day(s) ago)."
                ),
                None => trf!(
                    "Version {v}, date de compilation inconnue (compilée hors d'un dépôt git).",
                    "Version {v}, unknown build date (built outside a git repository)."
                ),
            },
        ));
    }
    if let Some(p) = &m.perime {
        constats.push(alerte(CAT, Niveau::Moyen, p.clone()));
    }
    match &m.programme {
        Some(p) => constats.push(ok(CAT, trf!("Programme : {p}", "Program: {p}"))),
        None => constats.push(impossible(
            CAT,
            tr!(
                "Impossible de savoir quel fichier est en train de tourner : rien n'a pu être vérifié.",
                "Could not tell which file is running: nothing could be checked."
            ),
        )),
    }
    match &m.sha256 {
        Some(Ok(h)) => constats.push(ok(
            CAT,
            trf!(
                "Empreinte SHA-256 : {h}. À comparer à celle de la page de la version, ou à celle que vous a donnée la personne qui vous a remis le programme ; si elles diffèrent, ne l'utilisez pas.",
                "SHA-256 checksum: {h}. Compare it with the one on the release page, or the one given by the person who handed you the program; if they differ, do not use it."
            ),
        )),
        Some(Err(e)) => constats.push(impossible_par(
            CAT,
            Raison::Echoue(e.clone()),
            trf!("Empreinte impossible ({e}).", "Checksum impossible ({e})."),
        )),
        None => {}
    }
    match &m.manifeste {
        None if m.version.is_some() && m.programme.is_some() => manques.push(
            tr!(
                "Manifeste de la clé : non comparé, ce programme n'est pas lancé depuis une clé VANGUARD.",
                "Key manifest: not compared, this program is not started from a VANGUARD key."
            )
            .to_string(),
        ),
        None => {}
        Some(Comparaison::Identique(date)) => {
            verifies = verifies.saturating_add(1);
            constats.push(ok(
                CAT,
                trf!(
                    "Identique au manifeste de la clé écrit le {date}.",
                    "Identical to the key manifest written on {date}."
                ),
            ));
        }
        Some(Comparaison::Differe(date)) => constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "DIFFÈRE du manifeste écrit le {date} : ce n'est pas le programme posé sur la clé. Réécrivez la clé (outils/deployer.sh) avant de vous en servir.",
                "DIFFERS from the manifest written on {date}: this is not the program put on the key. Rewrite the key (outils/deployer.sh) before using it."
            ),
        )),
        Some(Comparaison::Absent) => constats.push(alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Absent du manifeste de la clé : ce fichier n'y était pas quand elle a été écrite.",
                "Missing from the key manifest: this file was not there when it was written."
            ),
        )),
        Some(Comparaison::Douteuse(raison)) => constats.push(alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "Le manifeste de cette clé sur cet ordinateur ne peut pas être cru ({raison}) : rien n'a pu être comparé. Ne lancez rien depuis elle.",
                "This key's manifest on this computer cannot be trusted ({raison}): nothing could be compared. Do not run anything from it."
            ),
        )),
        Some(Comparaison::IdentifiantChange) => constats.push(alerte(
            CAT,
            Niveau::Eleve,
            tr!(
                "Jeton d'une clé déployée ici, mais son identifiant de volume ne correspond plus à son manifeste : rien n'a pu être comparé. Possible piège : ne lancez rien depuis elle, réécrivez-la (outils/deployer.sh).",
                "Token of a key deployed here, but its volume identifier no longer matches its manifest: nothing could be compared. Possible trap: do not run anything from it, rewrite it (outils/deployer.sh)."
            ),
        )),
        Some(Comparaison::SansSaReference) => constats.push(alerte(
            CAT,
            Niveau::Moyen,
            tr!(
                "Pas de manifeste ici pour cette clé, alors que d'autres clés y ont le leur : autre clé, ou jeton et identifiant changés. Rien n'a été comparé : ne lancez rien depuis elle avant de l'avoir redéployée.",
                "No manifest here for this key, while other keys have theirs: another key, or token and identifier changed. Nothing was compared: do not run anything from it before redeploying it."
            ),
        )),
        Some(Comparaison::HorsDeChezLeProprietaire) => manques.push(
            tr!(
                "Manifeste de la clé : non comparé, lancé depuis la clé hors de l'ordinateur du propriétaire (le manifeste reste chez lui).",
                "Key manifest: not compared, started from the key away from the owner's computer (the manifest stays there)."
            )
            .to_string(),
        ),
    }
    // L'historique ne se compare qu'à une empreinte calculée.
    if matches!(m.sha256, Some(Ok(_))) {
        manques.push(
            match m.historique {
                Historique::HorsLigne => tr!(
                    "Historique signé des versions : non comparé (travail sans Internet).",
                    "Signed version history: not compared (offline mode)."
                ),
                Historique::SansAccord => tr!(
                    "Historique signé des versions : non comparé, la comparaison demande un accord et --json ne pose pas de question (au terminal : vanguard verifier-moi).",
                    "Signed version history: not compared, the comparison asks for consent and --json asks no question (in a terminal: vanguard verifier-moi)."
                ),
            }
            .to_string(),
        );
    }
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies,
            non_verifies: manques,
        },
    )
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

    fn moi() -> Moi {
        Moi {
            version: Some("0.0.1"),
            compile: None,
            perime: None,
            programme: Some("/maison/alice/vanguard".into()),
            sha256: Some(Ok("ab".repeat(32))),
            manifeste: None,
            historique: Historique::SansAccord,
        }
    }

    /// Jamais « sain » sans l'historique signé : même identique au manifeste, le tout reste non vérifié ; hors de la
    /// clé, rien n'est vérifié ; un programme qui diffère du manifeste est un problème élevé ; le mot « authentique »
    /// n'est jamais écrit.
    #[test]
    fn jamais_sain_sans_historique() {
        let mut m = moi();
        let r = resultat(&m, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(r.couverture.non_verifies.len(), 2, "{:?}", r.couverture);
        m.manifeste = Some(Comparaison::Identique("2026-01-02".into()));
        let r = resultat(&m, debut());
        assert_eq!((r.verdict(), r.couverture.verifies), ("non-verifie", 1));
        m.historique = Historique::HorsLigne;
        let sans_internet = resultat(&m, debut()).couverture.non_verifies.join(" ");
        assert!(
            sans_internet.contains("sans Internet") || sans_internet.contains("offline"),
            "{sans_internet}"
        );
        m.manifeste = Some(Comparaison::Differe("2026-01-02".into()));
        let r = resultat(&m, debut());
        assert_eq!((r.verdict(), r.pire()), ("probleme", Some(Niveau::Eleve)));
        m.manifeste = Some(Comparaison::HorsDeChezLeProprietaire);
        assert_eq!(resultat(&m, debut()).couverture.verifies, 0);
        let json = crate::modele::resultat::json(&resultat(&m, debut())).to_lowercase();
        assert!(!json.contains("authenti"), "{json}");
    }

    /// Une autre copie : son empreinte, sans version ni manifeste ; une empreinte impossible ou un programme inconnu
    /// sont non vérifiés, sans historique à comparer.
    #[test]
    fn copie_et_empreinte_impossible() {
        let copie = Moi { version: None, ..moi() };
        let r = resultat(&copie, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(
            r.couverture.non_verifies.len(),
            1,
            "seulement l'historique : {:?}",
            r.couverture
        );
        let rate = Moi {
            sha256: Some(Err("illisible".into())),
            programme: None,
            ..copie
        };
        let r = resultat(&rate, debut());
        assert_eq!(r.verdict(), "non-verifie");
        assert_eq!(r.couverture.non_verifies, Vec::<String>::new());
        assert!(
            r.constats
                .iter()
                .all(|c| c.etat != "sain" || c.message.starts_with("Version"))
        );
    }
}
