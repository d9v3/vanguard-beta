//! Le résultat des dernières failles exploitées (`modele::resultat`), pour `vanguard dernieres-failles --json` : les
//! failles que la CISA a ajoutées à son catalogue ces derniers jours, sans l'écran, versées au rapport
//! (`examens/PRO-KEV-001.json`) et au journal.
//!
//! Deux lectures font la couverture : le catalogue, et les CVE des paquets de cet ordinateur. Sans catalogue, rien
//! n'est conclu (couverture nulle). Une copie de plus d'un jour peut manquer les derniers ajouts ; sans les CVE d'ici,
//! une faille listée n'est jamais dite « ne touche pas cet ordinateur » : non vérifié, jamais compté sain.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::collections::HashSet;
use std::time::Duration;

use chrono::NaiveDate;

use super::{Exploitee, depuis, recentes};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::raison::Echec;
use crate::modele::resultat::{Couverture, Resultat, nom_sans_piege};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`).
pub(crate) const ID: &str = "PRO-KEV-001";

const CAT: &str = "Failles connues";

/// Au-delà, les failles se résument en une ligne : la CISA en ajoute parfois des dizaines d'un coup (`--jours 365`).
const FAILLES_MONTREES: usize = 30;

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Le résultat d'après le catalogue lu (avec l'âge de sa copie) ; les CVE d'ici ne sont lues (`ici`) que s'il y a un
/// catalogue à rapprocher.
pub(super) fn resultat(
    catalogue: Result<(Vec<Exploitee>, Duration), Echec>,
    jours: u32,
    aujourd_hui: NaiveDate,
    ici: impl FnOnce() -> Result<HashSet<String>, Echec>,
    debut: Debut,
) -> Resultat {
    let (constats, couverture) = juger(catalogue, jours, aujourd_hui, ici);
    Resultat::nouveau(ID, debut, &constats, couverture)
}

/// Le jugement seul, sans l'heure : ce que le corpus de détection exerce (`corpus`).
fn juger(
    catalogue: Result<(Vec<Exploitee>, Duration), Echec>,
    jours: u32,
    aujourd_hui: NaiveDate,
    ici: impl FnOnce() -> Result<HashSet<String>, Echec>,
) -> (Vec<Constat>, Couverture) {
    let (catalogue, age) = match catalogue {
        Ok(c) => c,
        Err(e) => {
            let raison = e.to_string();
            let c = impossible_par(
                CAT,
                Raison::Illisible(raison.clone()),
                trf!(
                    "Catalogue des failles exploitées (CISA) pas lu : {}. Rien n'est conclu : non vérifié.",
                    "Exploited flaws catalog (CISA) not read: {}. Nothing concluded: not verified.",
                    raison
                ),
            );
            return (
                vec![c],
                Couverture {
                    verifies: 0,
                    non_verifies: vec![trf!(
                        "catalogue de la CISA pas lu : {}",
                        "CISA catalog not read: {}",
                        raison
                    )],
                },
            );
        }
    };
    let mut verifies = 1u32;
    let mut non_verifies = Vec::new();
    if age > super::FRAICHE {
        non_verifies.push(trf!(
            "copie du catalogue vieille de {} h (pas rafraîchie) : les derniers ajouts peuvent manquer",
            "catalog copy {} h old (not refreshed): the latest additions may be missing",
            age.as_secs() / 3600
        ));
    }
    let ici = match ici() {
        Ok(cves) => {
            verifies = verifies.saturating_add(1);
            Some(cves)
        }
        Err(raison) => {
            non_verifies.push(trf!(
                "failles pas rapprochées des paquets de cet ordinateur : {}",
                "flaws not matched against this computer's packages: {}",
                raison
            ));
            None
        }
    };
    let vide = HashSet::new();
    let liste = recentes(&catalogue, depuis(aujourd_hui, jours), ici.as_ref().unwrap_or(&vide));
    let touche = |e: &Exploitee| ici.as_ref().is_some_and(|i| i.contains(&e.cve));
    let mut constats: Vec<Constat> = liste
        .iter()
        .take(FAILLES_MONTREES)
        .map(|e| constat(e, touche(e), ici.is_some()))
        .collect();
    let reste: Vec<&Exploitee> = liste.iter().skip(FAILLES_MONTREES).copied().collect();
    if !reste.is_empty() {
        let touchent = reste.iter().filter(|e| touche(e)).count();
        let texte = trf!(
            "… et {} autre(s) faille(s) ajoutée(s) ces {} derniers jours : la liste entière dans « vanguard dernieres-failles ».",
            "… and {} other flaw(s) added in the last {} days: the whole list in “vanguard latest-flaws”.",
            reste.len(),
            jours
        );
        // Celles d'ici passent en tête (`recentes`) : il n'en reste que si plus de 30 touchent cet ordinateur.
        constats.push(if touchent > 0 {
            alerte(CAT, Niveau::Critique, texte)
        } else {
            ok(CAT, texte)
        });
    }
    if liste.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Aucune faille ajoutée au catalogue de la CISA ces {} derniers jours.",
                "No flaw added to CISA's catalog in the last {} days.",
                jours
            ),
        ));
    }
    (constats, Couverture { verifies, non_verifies })
}

/// PRO-KEV-001 au corpus de détection : `catalogue|CVE|AAAA-MM-JJ|éditeur|produit|nom` (une faille du catalogue de la
/// CISA, inventée) et `ici|CVE` (une CVE des paquets de cet ordinateur), jugés au 10 novembre 2026, sur 7 jours.
#[cfg(test)]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let catalogue = e
        .de("catalogue")
        .iter()
        .filter_map(|c| match c.as_slice() {
            [cve, date, editeur, produit, nom] => Some(Exploitee {
                cve: (*cve).to_string(),
                ajoutee: NaiveDate::parse_from_str(date, "%Y-%m-%d").ok(),
                editeur: (*editeur).to_string(),
                produit: (*produit).to_string(),
                nom: (*nom).to_string(),
                rancongiciel: false,
            }),
            _ => None,
        })
        .collect();
    let ici: HashSet<String> = e
        .de("ici")
        .iter()
        .filter_map(|c| c.first().map(|v| (*v).to_string()))
        .collect();
    let jour = NaiveDate::from_ymd_opt(2026, 11, 10).unwrap_or_default();
    juger(Ok((catalogue, Duration::from_hours(1))), 7, jour, || Ok(ici)).0
}

/// Le constat d'une faille listée : un problème critique si elle touche un paquet d'ici (exploitée pour de vrai) ;
/// sinon sain seulement si les CVE d'ici sont connues.
fn constat(e: &Exploitee, touche: bool, ici_connu: bool) -> Constat {
    let date = e.ajoutee.map_or_else(String::new, |d| format!("{d} · "));
    let mut texte = format!(
        "{date}{} · {} {} : {}",
        e.cve,
        nom_sans_piege(&e.editeur, 60),
        nom_sans_piege(&e.produit, 60),
        nom_sans_piege(&e.nom, 160)
    );
    if e.rancongiciel {
        texte.push_str(tr!(" — utilisée par des rançongiciels", " — used by ransomware"));
    }
    let c = if touche {
        texte.push_str(tr!(
            " — touche un paquet de cet ordinateur : le bilan (Failles connues) dit quoi mettre à jour.",
            " — affects a package on this computer: the check-up (Known flaws) says what to update."
        ));
        alerte(CAT, Niveau::Critique, texte)
    } else if ici_connu {
        texte.push_str(tr!(
            " — ne touche aucun paquet suivi de cet ordinateur.",
            " — affects no tracked package on this computer."
        ));
        ok(CAT, texte)
    } else {
        texte.push_str(tr!(
            " — pas pu dire si elle touche cet ordinateur.",
            " — could not tell whether it affects this computer."
        ));
        impossible_par(
            CAT,
            Raison::Illisible(
                tr!(
                    "CVE des paquets de cet ordinateur inconnues",
                    "CVEs of this computer's packages unknown"
                )
                .to_string(),
            ),
            texte,
        )
    };
    c.avec_objet(Objet::de("cve", &e.cve))
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

    fn jour(d: &str) -> NaiveDate {
        NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap()
    }

    /// Une faille inventée.
    fn faille(cve: &str, d: &str) -> Exploitee {
        Exploitee {
            cve: cve.into(),
            ajoutee: Some(jour(d)),
            editeur: "Exemple".into(),
            produit: "Lecteur".into(),
            nom: "Exemple Lecteur Remote Code Execution".into(),
            rancongiciel: false,
        }
    }

    fn ici(cves: &[&str]) -> HashSet<String> {
        cves.iter().map(|c| (*c).to_string()).collect()
    }

    const UNE_HEURE: Duration = Duration::from_hours(1);

    /// Sans catalogue (pas d'Internet, sans copie) : couverture nulle, la raison dite, les CVE d'ici jamais lues.
    #[test]
    fn sans_catalogue_couverture_nulle() {
        let r = resultat(
            Err(Echec::echoue("essai", "pas d'Internet ?")),
            7,
            jour("2026-11-10"),
            || panic!("rien à rapprocher"),
            debut(),
        );
        assert_eq!((r.couverture.verifies, r.verdict()), (0, "non-verifie"));
        assert!(r.couverture.non_verifies[0].contains("Internet"));
        assert_eq!(r.constats.len(), 1);
    }

    /// Une faille qui touche un paquet d'ici : critique, objet « cve:… », en tête ; les autres saines.
    #[test]
    fn faille_d_ici_trouvee() {
        let cat = vec![
            faille("CVE-2026-0001", "2026-11-08"),
            faille("CVE-2026-0002", "2026-11-09"),
        ];
        let r = resultat(
            Ok((cat, UNE_HEURE)),
            7,
            jour("2026-11-10"),
            || Ok(ici(&["CVE-2026-0001"])),
            debut(),
        );
        assert_eq!((r.couverture.verifies, r.verdict()), (2, "probleme"));
        assert_eq!(r.pire(), Some(Niveau::Critique));
        assert_eq!(r.constats[0].objet.as_deref(), Some("cve:CVE-2026-0001"));
        assert_eq!(r.constats[1].etat, "sain");
    }

    /// Rien d'ajouté dans la période, tout lu : sain ; une faille trop vieille n'est pas listée.
    #[test]
    fn rien_de_recent_sain() {
        let r = resultat(
            Ok((vec![faille("CVE-2025-0001", "2025-01-01")], UNE_HEURE)),
            7,
            jour("2026-11-10"),
            || Ok(ici(&[])),
            debut(),
        );
        assert_eq!(r.verdict(), "sain");
        assert_eq!(r.constats.len(), 1);
    }

    /// Les CVE d'ici inconnues (Windows, pas Arch, hors ligne) ou une copie de plus d'un jour : partiel, jamais
    /// sain, même sans aucune faille d'ici.
    #[test]
    fn partiel_jamais_sain() {
        let cat = || vec![faille("CVE-2026-0002", "2026-11-09")];
        let r = resultat(
            Ok((cat(), UNE_HEURE)),
            7,
            jour("2026-11-10"),
            || Err(Echec::echoue("essai", "hors ligne")),
            debut(),
        );
        assert_eq!((r.couverture.verifies, r.verdict()), (1, "non-verifie"));
        assert_eq!(r.constats[0].etat, "non-verifie");
        let r = resultat(
            Ok((cat(), Duration::from_hours(50))),
            7,
            jour("2026-11-10"),
            || Ok(ici(&[])),
            debut(),
        );
        assert_eq!(r.verdict(), "non-verifie");
        assert!(r.couverture.non_verifies[0].contains("50"));
    }

    /// Plafonné : 30 failles montrées, le reste résumé ; un nom piégé venu du catalogue sort inoffensif.
    #[test]
    fn liste_plafonnee() {
        let mut cat: Vec<Exploitee> = (0..45)
            .map(|i| faille(&format!("CVE-2026-{i:04}"), "2026-11-09"))
            .collect();
        cat[3].nom = "x\u{1b}[2Ky\u{202e}".into();
        let r = resultat(Ok((cat, UNE_HEURE)), 7, jour("2026-11-10"), || Ok(ici(&[])), debut());
        assert_eq!(r.constats.len(), FAILLES_MONTREES + 1);
        assert!(r.constats.last().unwrap().message.contains(" 15 "));
        assert!(
            r.constats
                .iter()
                .all(|c| !c.message.contains('\u{1b}') && !c.message.contains('\u{202e}'))
        );
        assert_eq!(r.verdict(), "sain");
    }
}
