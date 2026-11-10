//! Les lecteurs des sorties de `vanguard` dans la fenêtre (fenetre/src/donnees/) : un `vanguard` remplacé, ou des noms
//! venus de l'extérieur qu'il reprend (réseau, programme, appareil), peuvent écrire n'importe quoi. Quoi qu'on leur
//! donne, ils ne plantent pas, restent bornés (éléments, lignes, longueur des textes) et ne rendent aucun caractère
//! piégé (séquence d'échappement, sens d'écriture, invisible) ; seuls les textes longs de Vanguard gardent leurs sauts
//! de ligne. Le premier octet choisit la langue des textes de la fenêtre.
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

#[allow(dead_code)]
#[path = "../../fenetre/src/donnees/mod.rs"]
mod donnees;

use donnees::{ELEMENTS_MAX, bilan, evenements, libre, protection};
use nettoyage::{TEXTE_MAX, rendu};

/// Un texte prêt à montrer : borné, chaque caractère montré tel quel (aucun piège, espace trompeuse, sélecteur de
/// variante ni invisible rare) ; un saut de ligne seulement s'il est permis.
fn propre(s: &str, sauts: bool) {
    assert!(s.chars().count() <= TEXTE_MAX, "{} caractères", s.chars().count());
    for c in s.chars() {
        if c == '\n' {
            assert!(sauts, "saut de ligne dans {s:?}");
        } else {
            assert_eq!(rendu(c), Some(c), "caractère piégé U+{:04X} dans {s:?}", u32::from(c));
        }
    }
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

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, sortie)) = donnees.split_first() else { return };
    langue::choisir(Some(langue & 1 == 1));
    essayer(sortie);
});
