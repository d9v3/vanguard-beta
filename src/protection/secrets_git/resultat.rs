//! Le résultat de la recherche de secrets dans les projets git (`modele::resultat`, PRO-GIT-001), sans l'écran : une
//! alerte par secret trouvé (le genre, le fichier, la ligne et le commit, jamais le secret), et ce qui n'a pas pu être
//! relu (dépôt illisible, commits au-delà de la borne, dépôts au-delà de la borne). Rendu par `vanguard secrets --json`
//! et versé au rapport. Rien trouvé dans une lecture incomplète n'est jamais « sain ». gitleaks absent n'est pas un
//! manque : il ne fait qu'ajouter ses règles à celles de Vanguard, qui ont relu l'historique ; c'est dit.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::{PAR_DEPOT, Recherche, bornes};
use crate::machine::{Constat, alerte, impossible_par, ok, sans_objet};
use crate::modele::resultat::{Couverture, Resultat};
use crate::modele::{Absence, Raison};
use crate::protection::yara::resultat::{Debut, MANQUES_MAX, TROUVES_MAX, bornees};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-GIT-001";

// La catégorie des fichiers sensibles du bilan, déjà traduite : un secret resté dans l'historique en est un.
const CAT: &str = "Fichiers secrets";

/// Le résultat d'une recherche faite.
pub(crate) fn resultat(r: &Recherche, debut: Debut) -> Resultat {
    // Les secrets, `PAR_DEPOT` au plus par dépôt comme à l'écran, `TROUVES_MAX` en tout ; le reste compté.
    let mut trouves: Vec<String> = Vec::new();
    for (depot, fuites) in &r.avec {
        trouves.extend(
            fuites
                .iter()
                .take(PAR_DEPOT)
                .map(|f| format!("{depot} : {}", f.resume())),
        );
        let reste = fuites.len().saturating_sub(PAR_DEPOT);
        if reste > 0 {
            trouves.push(trf!(
                "{depot} : {reste} autre(s) secret(s), non détaillé(s) ici.",
                "{depot}: {reste} other secret(s), not detailed here."
            ));
        }
    }
    let mut constats: Vec<Constat> = bornees(&trouves, TROUVES_MAX, |n| {
        trf!(
            "{n} autre(s) secret(s), non détaillé(s) ici.",
            "{n} other secret(s), not detailed here."
        )
    })
    .into_iter()
    .map(|t| alerte(CAT, Niveau::Eleve, t))
    .collect();
    let mut manques: Vec<String> = r
        .illisibles
        .iter()
        .map(|d| {
            trf!(
                "{d} : pas pu être relu, rien n'est conclu pour lui.",
                "{d}: could not be read, nothing is concluded for it."
            )
        })
        .collect();
    manques.extend(bornes(r));
    let lus = r.sains.saturating_add(r.avec.len());
    if constats.is_empty() {
        constats.push(if r.depots == 0 {
            sans_objet(
                CAT,
                Absence::Inactif,
                tr!(
                    "Aucun projet git dans le dossier personnel : rien n'a été relu.",
                    "No git project in the home folder: nothing was read."
                ),
            )
        } else if manques.is_empty() {
            ok(
                CAT,
                trf!(
                    "Aucun secret dans l'historique des {lus} projet(s) git relus (une règle ne voit pas tout).",
                    "No secret in the history of the {lus} git project(s) read (a rule does not see everything)."
                ),
            )
        } else {
            impossible_par(
                CAT,
                Raison::Illisible(tr!("lecture incomplète", "incomplete read").to_string()),
                trf!(
                    "Rien trouvé dans les {lus} projet(s) git relus, mais la lecture est incomplète : rien n'est conclu pour le reste, non vérifié.",
                    "Nothing found in the {lus} git project(s) read, but the read is incomplete: nothing is concluded for the rest, not verified."
                ),
            )
        });
    }
    if r.depots > 0 {
        constats.push(if r.gitleaks {
            ok(
                CAT,
                tr!(
                    "gitleaks est installé : ses règles se sont ajoutées à celles de Vanguard.",
                    "gitleaks is installed: its rules were added to Vanguard's."
                ),
            )
        } else {
            sans_objet(
                CAT,
                Absence::Logiciel,
                tr!(
                    "gitleaks n'est pas installé : seules les règles de Vanguard ont relu l'historique.",
                    "gitleaks is not installed: only Vanguard's rules read the history."
                ),
            )
        });
    }
    Resultat::nouveau(
        ID,
        debut,
        &constats,
        Couverture {
            verifies: u32::try_from(lus).unwrap_or(u32::MAX),
            non_verifies: bornees(&manques, MANQUES_MAX, |n| {
                trf!(
                    "{n} autre(s) élément(s) non vérifié(s), non détaillé(s) ici.",
                    "{n} other item(s) not checked, not detailed here."
                )
            }),
        },
    )
}

/// git absent : rien ne peut être relu. Des dépôts trouvés restent non vérifiés ; sans dépôt, rien à relire.
pub(crate) fn sans_git(depots: usize, debut: Debut) -> Resultat {
    let constat = if depots == 0 {
        sans_objet(
            CAT,
            Absence::Logiciel,
            tr!(
                "git n'est pas installé, et aucun projet git dans le dossier personnel : rien à relire.",
                "git is not installed, and no git project in the home folder: nothing to read."
            ),
        )
    } else {
        impossible_par(
            CAT,
            Raison::Absente("git".into()),
            trf!(
                "git n'est pas installé : {depots} projet(s) git trouvé(s), non relu(s), non vérifié(s).",
                "git is not installed: {depots} git project(s) found, not read, not verified."
            ),
        )
    };
    Resultat::nouveau(ID, debut, &[constat], Couverture::default())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::super::{COMMITS_MAX, Fuite};
    use super::*;

    fn debut() -> Debut {
        (chrono::Utc::now(), std::time::Instant::now())
    }

    fn fuite(n: u64) -> Fuite {
        Fuite {
            regle: "clé d'accès AWS".into(),
            fichier: "config.env".into(),
            ligne: n,
            commit: "70d57ee".into(),
        }
    }

    /// Tout relu, rien trouvé : sain ; un dépôt illisible, des commits ou des dépôts au-delà de la borne : non
    /// vérifié ; aucun dépôt ou git absent : non vérifié, jamais sain ; un secret : problème élevé.
    #[test]
    fn sain_seulement_si_tout_est_relu() {
        let mut r = Recherche {
            depots: 2,
            sains: 2,
            ..Recherche::default()
        };
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "sain");
        assert_eq!(res.outil, ID);
        assert!(res.constats.iter().any(|c| c.message.contains("gitleaks")));
        r.tronques.push("~/projet".into());
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "non-verifie");
        assert!(res.couverture.non_verifies[0].contains(&COMMITS_MAX.to_string()));
        r.tronques.clear();
        r.plafond = true;
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.plafond = false;
        r.sans_vanguard.push("~/projet".into());
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.sans_vanguard.clear();
        r.sans_gitleaks.push("~/projet".into());
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.sans_gitleaks.clear();
        r.hors_temps = 4;
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        r.hors_temps = 0;
        r.illisibles.push("~/autre".into());
        assert_eq!(resultat(&r, debut()).verdict(), "non-verifie");
        assert_eq!(resultat(&Recherche::default(), debut()).verdict(), "non-verifie");
        assert_eq!(sans_git(0, debut()).verdict(), "non-verifie");
        assert_eq!(sans_git(3, debut()).verdict(), "non-verifie");
        r.avec.push(("~/projet".into(), vec![fuite(3)]));
        let res = resultat(&r, debut());
        assert_eq!(res.verdict(), "probleme");
        assert!(
            res.constats
                .iter()
                .any(|c| c.message.contains("config.env:3 — ") && c.message.contains("(70d57ee)"))
        );
    }

    /// Dix secrets au plus par dépôt, comme à l'écran ; le reste est compté, et le tout reste borné.
    #[test]
    fn secrets_bornes() {
        let r = Recherche {
            depots: 30,
            avec: (0..30)
                .map(|d| (format!("~/projet{d}"), (0..15).map(fuite).collect()))
                .collect(),
            ..Recherche::default()
        };
        let res = resultat(&r, debut());
        let alertes = res.constats.iter().filter(|c| c.etat == "probleme").count();
        assert_eq!(alertes, TROUVES_MAX + 1);
        assert!(
            res.constats
                .iter()
                .any(|c| c.message.contains("5 autre(s)") || c.message.contains("5 other"))
        );
    }
}
