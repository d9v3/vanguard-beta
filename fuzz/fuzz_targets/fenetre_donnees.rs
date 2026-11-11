//! Les lecteurs des sorties de `vanguard` dans la fenêtre (fenetre/src/donnees/) : un `vanguard` remplacé, ou des noms
//! venus de l'extérieur qu'il reprend (réseau, programme, appareil), peuvent écrire n'importe quoi. Quoi qu'on leur
//! donne, ils ne plantent pas, restent bornés (éléments, lignes, longueur des textes) et ne rendent aucun caractère
//! piégé (séquence d'échappement, sens d'écriture, invisible) ; seuls les textes longs de Vanguard gardent leurs sauts
//! de ligne. Le contrôle juge chaque caractère d'après sa catégorie Unicode, pas d'après les listes du nettoyage :
//! une liste qui laisserait passer un caractère de format, non attribué ou privé se verrait ici. Le premier octet choisit la langue des textes de la fenêtre (et le code de sortie de l'aperçu d'une
//! correction).
#![no_main]
// Aucun unsafe ici ni dans ce que la cible inclut (fenetre/src/) : refusé sans recours, un allow ne compile pas.
#![forbid(unsafe_code)]

// `tr!` et `trf!` de la fenêtre elle-même (pas la cale de src/) : les deux langues sont essayées.
#[allow(dead_code)]
#[path = "../../fenetre/src/langue.rs"]
mod langue;

#[allow(dead_code)]
#[path = "../../fenetre/src/nettoyage.rs"]
mod nettoyage;

// Le geste d'un programme du démarrage (lot 2a) se lit avec la sorte et l'empreinte de la fenêtre.
#[allow(dead_code)]
#[path = "../../fenetre/src/couleurs.rs"]
mod couleurs;

#[allow(dead_code)]
#[path = "../../fenetre/src/commandes.rs"]
mod commandes;

/// Ce que `donnees` prend du lanceur : ses deux types de fin, qui viennent de `commandes`.
mod lanceur {
    pub use crate::commandes::{Fin, Issue};
}

#[allow(dead_code)]
#[path = "../../fenetre/src/donnees/mod.rs"]
mod donnees;

use donnees::{ELEMENTS_MAX, bilan, correction, evenements, libre, protection};
use nettoyage::{MARQUES_MAX, TEXTE_MAX, rendu};
use unicode_general_category::{GeneralCategory as G, get_general_category};

/// Un texte prêt à montrer : borné, chaque caractère montré tel quel par le nettoyage (`rendu`) ; un saut de ligne
/// seulement s'il est permis. Et, jugé d'après la catégorie Unicode : ni contrôle, ni caractère de format, non
/// attribué, privé ou séparateur de ligne ; une seule espace, l'ordinaire ; une marque combinante seulement sur un
/// signe (pas au début, ni après une espace ou un saut de ligne), `MARQUES_MAX` au plus sur le même.
fn propre(s: &str, sauts: bool) {
    assert!(s.chars().count() <= TEXTE_MAX, "{} caractères", s.chars().count());
    // Les marques posées sur le dernier signe ; `None` : rien où en poser.
    let mut marques: Option<usize> = None;
    for c in s.chars() {
        if c == '\n' {
            assert!(sauts, "saut de ligne dans {s:?}");
            marques = None;
            continue;
        }
        assert_eq!(rendu(c), Some(c), "caractère piégé U+{:04X} dans {s:?}", u32::from(c));
        match get_general_category(c) {
            G::Control
            | G::Format
            | G::Unassigned
            | G::PrivateUse
            | G::Surrogate
            | G::LineSeparator
            | G::ParagraphSeparator => panic!("caractère invisible U+{:04X} dans {s:?}", u32::from(c)),
            G::SpaceSeparator => {
                assert_eq!(c, ' ', "espace U+{:04X} dans {s:?}", u32::from(c));
                marques = None;
            }
            G::NonspacingMark | G::SpacingMark | G::EnclosingMark => {
                let n = marques.unwrap_or_else(|| panic!("marque sans signe U+{:04X} dans {s:?}", u32::from(c)));
                assert!(n < MARQUES_MAX, "trop de marques dans {s:?}");
                marques = Some(n + 1);
            }
            _ => marques = Some(0),
        }
    }
}

/// Un texte qui se voit : au moins un caractère qui n'est ni une espace ni une marque.
fn visible(s: &str) -> bool {
    s.chars().any(|c| {
        !matches!(
            get_general_category(c),
            G::SpaceSeparator | G::NonspacingMark | G::SpacingMark | G::EnclosingMark
        )
    })
}

/// Une erreur à montrer : une ligne courte, propre.
fn erreur(e: &str) {
    propre(e, false);
    assert!(e.chars().count() <= 200, "{e:?}");
}

fn essayer(sortie: &[u8]) {
    match bilan::lire(sortie) {
        Ok(v) => {
            for s in [&v.systeme, &v.outil] {
                propre(s, false);
            }
            assert!(v.note.is_none_or(|n| n <= 100), "{:?}", v.note);
            assert!(v.constats.len() <= ELEMENTS_MAX && v.manques.len() <= ELEMENTS_MAX);
            for c in &v.constats {
                for s in [&c.categorie, &c.regle, &c.objet] {
                    propre(s, false);
                }
                propre(&c.message, true);
                propre(&c.action, true);
                // Un geste lu ne garde qu'une empreinte de 32 chiffres minuscules, un nom et une commande d'une ligne.
                if let Some(g) = &c.geste {
                    propre(&g.nom, false);
                    propre(&g.commande, false);
                    let a = commandes::Lancement::Changement(g.changement).arguments();
                    assert!(
                        a.len() == 4
                            && a[2].len() == 32
                            && a[2].bytes().all(|o| matches!(o, b'0'..=b'9' | b'a'..=b'f')),
                        "{a:?}"
                    );
                }
            }
            for m in &v.manques {
                propre(m, true);
            }
        }
        Err(e) => erreur(&e),
    }
    match protection::lire(sortie) {
        Ok(v) => {
            assert!(v.interrupteurs.len() <= ELEMENTS_MAX);
            for i in &v.interrupteurs {
                for s in [&i.id, &i.nom, &i.etat] {
                    propre(s, false);
                }
            }
        }
        Err(e) => erreur(&e),
    }
    match evenements::lire(sortie) {
        Ok(v) => {
            propre(&v.raison, false);
            assert!(v.evenements.len() <= ELEMENTS_MAX);
            for e in &v.evenements {
                for s in [&e.id, &e.quand, &e.source, &e.sorte, &e.titre] {
                    propre(s, false);
                }
                // Le texte d'une alerte garde ses lignes ; les autres détails viennent de noms.
                propre(&e.detail, e.alerte);
            }
        }
        Err(e) => erreur(&e),
    }
    match libre::lire(sortie) {
        Ok(v) => {
            assert!(v.lignes.len() <= libre::LIGNES_MAX);
            for l in &v.lignes {
                // Six niveaux au plus (PROFONDEUR_MAX de libre.rs) : le dernier montré est au retrait 5.
                assert!(l.retrait < 6, "retrait {}", l.retrait);
                propre(&l.cle, false);
                propre(&l.valeur, false);
            }
        }
        Err(e) => erreur(&e),
    }
}

/// L'aperçu d'une correction (`correction --voir`) : lu pour un jeton fixe et le code choisi par le premier octet.
/// Lu, il est borné et propre : chaque texte tient sur une ligne, sans longue suite d'espaces qui pousserait la fin
/// d'une commande hors de la vue, et chaque texte de Vanguard (commandes comprises) se voit ; refusé ou illisible, sa
/// raison est une ligne propre qui se voit.
fn apercu(code: Option<i32>, sortie: &[u8]) {
    let jeton = commandes::Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
    match correction::lire(jeton, code, sortie) {
        correction::Lecture::Lue(a) => {
            assert_eq!(code, Some(0));
            let espaces = " ".repeat(correction::ESPACES_MAX + 1);
            let ligne = |s: &str| {
                propre(s, false);
                assert!(!s.contains(&espaces), "{s:?}");
            };
            for s in [&a.version, &a.regle, &a.categorie] {
                ligne(s);
                assert!(s.chars().count() <= 80 && visible(s), "{s:?}");
            }
            for s in [&a.message, &a.action, &a.pourquoi_pas] {
                ligne(s);
            }
            assert!(visible(&a.message) && visible(&a.action), "{a:?}");
            // Une correction qui s'annule n'a pas de « pourquoi pas », mais ses valeurs d'avant ; l'inverse sinon.
            assert_eq!(a.annulable, a.pourquoi_pas.is_empty(), "{a:?}");
            assert_eq!(a.annulable, !a.avant.is_empty(), "{a:?}");
            assert!(a.automatique || a.droits != correction::Droits::Compte, "{a:?}");
            assert!(!a.automatique || !a.commandes.is_empty(), "{a:?}");
            assert!(a.commandes.len() <= correction::COMMANDES_MAX && a.avant.len() <= correction::AVANT_MAX);
            for c in &a.commandes {
                ligne(c);
                assert!(visible(c), "{c:?}");
            }
            for v in &a.avant {
                ligne(&v.geste);
                if let Some(x) = &v.valeur {
                    ligne(x);
                }
            }
        }
        correction::Lecture::Refusee(r) => {
            assert!(code.is_some_and(|c| c != 0));
            erreur(&r);
            assert!(visible(&r) && !r.contains("    "), "{r:?}");
        }
        correction::Lecture::Illisible(r) => erreur(&r),
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, sortie)) = donnees.split_first() else { return };
    langue::choisir(Some(langue & 1 == 1));
    essayer(sortie);
    // Le code de sortie de l'aperçu : 0, 1, 2 ou aucun (arrêté), choisi par deux bits du même octet.
    let code = match (langue >> 1) & 3 {
        0 => Some(0),
        1 => Some(1),
        2 => Some(2),
        _ => None,
    };
    apercu(code, sortie);
});
