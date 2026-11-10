//! Le résultat de l'intégrité des fichiers critiques (`modele::resultat`), pour `vanguard integrite --json` : la
//! comparaison avec la référence, sans l'écran, versée au rapport (`examens/PRO-INT-001.json`) et au journal.
//!
//! Lecture seule : sans référence, aucune n'est posée ici. Une référence prise en silence par un script figerait
//! comme « normal » un fichier déjà changé ; elle se pose depuis le menu (ou « vanguard integrite »), où c'est montré.
//! Ce qui n'a pas pu être comparé par son contenu (fichier illisible sans droits root, suivi par sa taille et sa
//! date ; dossier qui ne se liste pas) est dit non vérifié : jamais compté sain.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::{CAT, Etat, Reference, comparer, douteuse};
use crate::machine::{Constat, alerte, impossible_par, ok};
use crate::modele::resultat::{Couverture, Resultat, nom_pour_cle, nom_sans_piege};
use crate::modele::{Objet, Raison};
use crate::risk::Niveau;
use crate::{tr, trf};

/// L'identifiant de l'outil (`modele::registre::OUTILS`). Pas SUR-FIC-001 : celui-là nomme l'alerte de la
/// surveillance horaire (un fichier changé, notifié), et un résultat d'outil se range sous un identifiant d'outil.
pub(crate) const ID: &str = "PRO-INT-001";

/// Au-delà, les fichiers changés se résument en une ligne : après une mise à jour du système, des dizaines changent
/// d'un coup, et la fenêtre n'a pas à en lister des centaines.
const FICHIERS_MONTRES: usize = 20;

type Debut = (chrono::DateTime<chrono::Utc>, std::time::Instant);

/// Ce qu'on lit de l'ordinateur, seulement s'il y a une référence à quoi comparer : les empreintes actuelles, et les
/// dossiers suivis qui existent mais ne se listent pas.
pub(super) type Lecture = (Etat, Vec<String>);

/// Le résultat d'après la référence retrouvée et l'état actuel (lu par `lire`, seulement s'il y a de quoi comparer).
pub(super) fn resultat(reference: Reference, lire: impl FnOnce() -> Lecture, debut: Debut) -> Resultat {
    let (constats, couverture) = juger(reference, lire);
    Resultat::nouveau(ID, debut, &constats, couverture)
}

/// Le jugement seul, sans l'heure : ce que le corpus de détection exerce (`corpus`).
fn juger(reference: Reference, lire: impl FnOnce() -> Lecture) -> (Vec<Constat>, Couverture) {
    let (reference, adoptee) = match reference {
        Reference::Valable(r) => (r, false),
        Reference::Adoptee(r) => (r, true),
        Reference::Douteuse(pourquoi) => {
            let manque = trf!(
                "la référence ne peut pas servir : {}",
                "the reference cannot be used: {}",
                pourquoi
            );
            return (
                vec![douteuse(&pourquoi)],
                Couverture {
                    verifies: 0,
                    non_verifies: vec![manque],
                },
            );
        }
        Reference::Absente => {
            let c = impossible_par(
                CAT,
                Raison::Introuvable,
                tr!(
                    "Pas encore de référence pour les fichiers critiques : à poser depuis le menu (ou « vanguard integrite »). Rien n'est comparé : non vérifié.",
                    "No reference yet for critical files: set it from the menu (or “vanguard integrity”). Nothing is compared: not verified."
                ),
            );
            return (
                vec![c],
                Couverture {
                    verifies: 0,
                    non_verifies: vec![
                        tr!(
                            "pas de référence, à poser depuis le menu",
                            "no reference, to be set from the menu"
                        )
                        .to_string(),
                    ],
                },
            );
        }
    };
    let (actuel, dossiers_illisibles) = lire();
    let mut non_verifies = Vec::new();
    // Comparés par leur contenu : les seuls qui comptent comme vérifiés.
    let lus = actuel.values().filter(|h| h.starts_with("b3:")).count();
    let par_date = actuel.len().saturating_sub(lus);
    if par_date > 0 {
        non_verifies.push(trf!(
            "{} fichier(s) illisible(s) sans droits root : seules leur taille et leur date sont comparées",
            "{} file(s) unreadable without root rights: only their size and date are compared",
            par_date
        ));
    }
    for d in &dossiers_illisibles {
        non_verifies.push(trf!(
            "dossier illisible sans droits root, ses fichiers ne sont pas comparés : {}",
            "folder unreadable without root rights, its files are not compared: {}",
            nom_sans_piege(d, 120)
        ));
    }
    if adoptee {
        non_verifies.push(
            tr!(
                "référence acceptée telle quelle, sans sceau d'avant : rien ne prouve qu'elle n'a pas été réécrite",
                "reference accepted as it was, without an earlier seal: nothing proves it was not rewritten"
            )
            .to_string(),
        );
    }
    let e = comparer(&reference, &actuel);
    let mut constats: Vec<Constat> = Vec::new();
    let changes = e
        .modifies
        .iter()
        .map(|f| (f, tr!("modifié depuis la référence", "modified since the reference")))
        .chain(
            e.ajoutes
                .iter()
                .map(|f| (f, tr!("ajouté depuis la référence", "added since the reference"))),
        )
        .chain(
            e.supprimes
                .iter()
                .map(|f| (f, tr!("supprimé depuis la référence", "removed since the reference"))),
        );
    for (f, quoi) in changes.take(FICHIERS_MONTRES) {
        constats.push(
            alerte(CAT, Niveau::Moyen, format!("{} : {quoi}", nom_sans_piege(f, 200)))
                .avec_objet(Objet::de("fichier", &nom_pour_cle(f))),
        );
    }
    let reste = e.total().saturating_sub(FICHIERS_MONTRES);
    if reste > 0 {
        constats.push(alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "… et {} autre(s) fichier(s) critique(s) changé(s) : la liste entière dans « vanguard integrite ».",
                "… and {} other critical file(s) changed: the whole list in “vanguard integrity”.",
                reste
            ),
        ));
    }
    if !e.vide() {
        constats.push(alerte(
            CAT,
            Niveau::Info,
            tr!(
                "Normal après une mise à jour du système ; sinon, à examiner. Après examen, la référence se refait depuis le menu.",
                "Normal after a system update; otherwise, worth a look. After a look, the reference is remade from the menu."
            ),
        ));
    } else if lus > 0 {
        constats.push(ok(
            CAT,
            trf!(
                "{} fichiers critiques identiques à la référence.",
                "{} critical files identical to the reference.",
                actuel.len()
            ),
        ));
    }
    let verifies = u32::try_from(lus).unwrap_or(u32::MAX);
    (constats, Couverture { verifies, non_verifies })
}

/// PRO-INT-001 au corpus de détection : `reference|fichier|empreinte` (la référence) et `actuel|fichier|empreinte` (ce
/// qui se lit maintenant), comme COM-INT-001.
#[cfg(test)]
pub(crate) fn corpus(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let etat = |genre: &str| -> Etat {
        e.de(genre)
            .iter()
            .map(|c| (c[0].to_string(), c[1].to_string()))
            .collect()
    };
    juger(Reference::Valable(etat("reference")), || (etat("actuel"), Vec::new())).0
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

    /// Des empreintes inventées.
    fn etat(paires: &[(&str, &str)]) -> Etat {
        paires.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    /// Sans référence : rien n'est lu ni comparé, couverture nulle, jamais sain.
    #[test]
    fn sans_reference_couverture_nulle() {
        let r = resultat(Reference::Absente, || panic!("rien à lire sans référence"), debut());
        assert_eq!(r.outil, ID);
        assert_eq!(r.couverture.verifies, 0);
        assert_eq!(r.verdict(), "non-verifie");
        assert!(r.constats.iter().all(|c| c.etat == "non-verifie"));
        assert!(r.couverture.non_verifies[0].contains("menu"), "{:?}", r.couverture);
    }

    /// Une référence changée hors de Vanguard : rien n'est comparé, non vérifié, la raison dite.
    #[test]
    fn reference_douteuse_non_verifiee() {
        let r = resultat(
            Reference::Douteuse("abîmée".into()),
            || panic!("rien à comparer"),
            debut(),
        );
        assert_eq!((r.couverture.verifies, r.verdict()), (0, "non-verifie"));
        assert!(r.couverture.non_verifies[0].contains("abîmée"));
    }

    /// Tout identique et tout lu : le seul cas sain.
    #[test]
    fn tout_identique_sain() {
        let e = etat(&[("/etc/hosts", "b3:aa"), ("/etc/passwd", "b3:bb")]);
        let r = resultat(Reference::Valable(e.clone()), || (e, vec![]), debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (2, "sain"));
    }

    /// Un fichier lu par sa seule date, un dossier qui ne se liste pas, une référence adoptée : couverture partielle,
    /// jamais sain, même sans aucun changement.
    #[test]
    fn partiel_jamais_sain() {
        let e = etat(&[("/etc/hosts", "b3:aa"), ("/etc/shadow", "meta:10:1")]);
        let r = resultat(Reference::Valable(e.clone()), || (e.clone(), vec![]), debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (1, "non-verifie"));
        let r = resultat(
            Reference::Valable(etat(&[("/etc/hosts", "b3:aa")])),
            || (etat(&[("/etc/hosts", "b3:aa")]), vec!["/etc/sudoers.d".into()]),
            debut(),
        );
        assert_eq!(r.verdict(), "non-verifie");
        assert!(r.couverture.non_verifies[0].contains("/etc/sudoers.d"));
        let r = resultat(
            Reference::Adoptee(etat(&[("/etc/hosts", "b3:aa")])),
            || (etat(&[("/etc/hosts", "b3:aa")]), vec![]),
            debut(),
        );
        assert_eq!(r.verdict(), "non-verifie");
    }

    /// Des changements : un constat par fichier (objet « fichier:… »), plafonné, le reste résumé ; un nom piégé posé
    /// dans un dossier suivi sort inoffensif.
    #[test]
    fn changements_plafonnes() {
        let reference = etat(&[("/etc/passwd", "b3:aa"), ("/etc/shadow", "b3:bb")]);
        let mut actuel = etat(&[("/etc/passwd", "b3:cc")]);
        for i in 0..30 {
            actuel.insert(format!("/etc/cron.d/essai{i}\u{202e}"), "b3:dd".into());
        }
        let r = resultat(Reference::Valable(reference), || (actuel, vec![]), debut());
        assert_eq!(r.verdict(), "probleme");
        let fichiers: Vec<_> = r
            .constats
            .iter()
            .filter(|c| c.objet.as_deref().is_some_and(|o| o.starts_with("fichier:")))
            .collect();
        assert_eq!(fichiers.len(), FICHIERS_MONTRES);
        assert_eq!(fichiers[0].objet.as_deref(), Some("fichier:/etc/passwd"));
        assert!(
            r.constats.iter().any(|c| c.message.contains(" 12 ")),
            "32 changés, 20 montrés"
        );
        assert!(r.constats.iter().all(|c| !c.message.contains('\u{202e}')));
        assert!(r.constats.len() <= FICHIERS_MONTRES + 2);
    }

    /// Le fil entier, comme `vanguard integrite --json` : dans un dossier sans référence, rien n'est écrit ; une
    /// référence posée avant se compare sans être refaite.
    #[test]
    fn sans_reference_rien_n_est_ecrit() {
        let dossier = crate::essais::Jetable::nouveau("integrite-json");
        let r = super::super::examiner_dans(&dossier, || panic!("rien à lire sans référence"), debut());
        assert_eq!((r.couverture.verifies, r.verdict()), (0, "non-verifie"));
        assert!(!dossier.join(crate::sceau::INTEGRITE).exists());
        assert!(matches!(
            crate::sceau::lire_dans(&dossier, crate::sceau::INTEGRITE),
            crate::sceau::Lecture::Absent
        ));
        let e = etat(&[("/etc/hosts", "b3:aa")]);
        crate::sceau::ecrire_dans(
            &dossier,
            crate::sceau::INTEGRITE,
            serde_json::to_string(&e).unwrap().as_bytes(),
        )
        .unwrap();
        let avant = std::fs::read(dossier.join(crate::sceau::INTEGRITE)).unwrap();
        let r = super::super::examiner_dans(&dossier, || (etat(&[("/etc/hosts", "b3:ff")]), vec![]), debut());
        assert_eq!(r.verdict(), "probleme");
        assert_eq!(std::fs::read(dossier.join(crate::sceau::INTEGRITE)).unwrap(), avant);
    }
}
