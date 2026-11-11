//! Les lecteurs des sorties de `vanguard` dans la fenêtre (fenetre/src/donnees/) : un `vanguard` remplacé, ou des noms
//! venus de l'extérieur qu'il reprend (réseau, programme, appareil), peuvent écrire n'importe quoi. Quoi qu'on leur
//! donne, ils ne plantent pas, restent bornés (éléments, lignes, longueur des textes) et ne rendent aucun caractère
//! piégé (séquence d'échappement, sens d'écriture, invisible) ; seuls les textes longs de Vanguard gardent leurs sauts
//! de ligne. Le contrôle juge chaque caractère d'après sa catégorie Unicode, pas d'après les listes du nettoyage :
//! une liste qui laisserait passer un caractère de format, non attribué ou privé se verrait ici. Le premier octet choisit la langue des textes de la fenêtre (et le code de sortie de l'aperçu d'une
//! correction, de l'aperçu d'une annulation et de l'issue d'un geste qui change).
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

use donnees::{ELEMENTS_MAX, bilan, changements, correction, evenements, libre, protection};
use nettoyage::{MARQUES_MAX, TEXTE_MAX, rendu};
use unicode_general_category::{GeneralCategory as G, get_general_category};

/// Un texte prêt à montrer : borné, chaque caractère montré tel quel par le nettoyage (`rendu`) ; un saut de ligne
/// seulement s'il est permis. Et, jugé d'après la catégorie Unicode : ni contrôle, ni caractère de format, non
/// attribué, privé ou séparateur de ligne ; une seule espace, l'ordinaire ; une marque combinante seulement sur une
/// lettre (pas au début, ni après une espace, un saut de ligne, un chiffre, une ponctuation, un symbole ou une lettre
/// modificative : vérification de Fable n° 4, N2, Inter y dessine la marque comme son signe espacé), `MARQUES_MAX` au
/// plus sur la même.
fn propre(s: &str, sauts: bool) {
    assert!(s.chars().count() <= TEXTE_MAX, "{} caractères", s.chars().count());
    // Les marques posées sur la dernière lettre ; `None` : rien où en poser.
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
            G::UppercaseLetter | G::LowercaseLetter | G::TitlecaseLetter | G::OtherLetter => marques = Some(0),
            _ => marques = None,
        }
    }
}

/// Un texte de Vanguard qui se lit : au moins une lettre ou un chiffre qui n'est ni une marque (posée sur un autre
/// signe) ni une lettre modificative (« ʰ », « ˀ » : 3 à 5 pixels d'encre, vérification de Fable n° 4, N5). Fait
/// seulement d'espaces, de marques, de « � », de « ␠ » ou de « ˙ », il se montrerait vide ou comme une suite de
/// remplacements (vérification de Fable n° 3, A6).
fn visible(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_alphanumeric()
            && !matches!(
                get_general_category(c),
                G::NonspacingMark | G::SpacingMark | G::EnclosingMark | G::ModifierLetter
            )
    })
}

/// Le signe « − » (U+2212) : JetBrains Mono le dessine comme « - ». Nommé ici, pas pris de la liste du nettoyage
/// (`JUMEAUX_GARDES`) : s'il en sortait, ce contrôle le verrait.
const MOINS: char = '\u{2212}';
/// Le tiret « – » (U+2013) : doublé, Inter le dessine comme « — » (vérification de Fable n° 4, N4). Nommé ici pour la
/// même raison que `MOINS`.
const DEMI: char = '\u{2013}';

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
/// Lu, il est borné et propre : chaque texte tient sur une ligne, sans espace en tête ni en bout (une espace de tête
/// décalerait une commande sans rien dire), sans longue suite d'espaces qui pousserait la fin d'une commande hors de
/// la vue, sans « − » (qui se dessine comme « - »), et chaque texte de Vanguard (commandes comprises) a une lettre ou
/// un chiffre ; refusé, sa raison est une ligne propre de 200 signes au plus, sans espace en tête, qui se lit ;
/// illisible, sa raison est une ligne propre.
fn apercu(code: Option<i32>, sortie: &[u8]) {
    let jeton = commandes::Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
    match correction::lire(jeton, code, sortie) {
        correction::Lecture::Lue(a) => {
            assert_eq!(code, Some(0));
            let espaces = " ".repeat(correction::ESPACES_MAX + 1);
            let ligne = |s: &str| {
                propre(s, false);
                assert!(!s.contains(&espaces), "{s:?}");
                assert!(
                    !s.starts_with(' ') && !s.ends_with(' ') && !s.contains([MOINS, DEMI]),
                    "{s:?}"
                );
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
            assert!(
                r.chars().count() <= 200 && !r.starts_with(' ') && !r.contains([MOINS, DEMI]),
                "{r:?}"
            );
        }
        correction::Lecture::Illisible(r) => erreur(&r),
    }
}

/// « Ce que Vanguard a changé » (étape 5) : la liste, bornée, chaque texte propre ; un jeton offert l'est par une
/// seule ligne. L'aperçu d'une annulation lu : seulement avec le code 0, des droits en quatre chiffres octaux, un
/// chemin du compte ou absolu, un accord non nul, des textes propres ; un refus ou une illisibilité : une raison
/// propre. L'issue d'un geste qui change : un « fait » n'a jamais de raison ; un refus, un échec ou une issue
/// inconnue ont une raison propre et bornée.
fn changements_(code: Option<i32>, sortie: &[u8]) {
    if let Ok(v) = changements::lire(sortie) {
        assert!(v.lignes.len() <= ELEMENTS_MAX);
        propre(&v.releve, false);
        let mut offerts = std::collections::HashSet::new();
        for l in &v.lignes {
            propre(&l.date, false);
            propre(&l.texte, false);
            if let Some(j) = l.annulation {
                assert!(offerts.insert(j), "jeton offert deux fois");
            }
        }
    }
    let jeton = commandes::Empreinte::lire("0123456789abcdef0123456789abcdef").unwrap();
    let octal = |t: &str| matches!(t.len(), 3 | 4) && t.bytes().all(|o| (b'0'..=b'7').contains(&o));
    match changements::lire_apercu(jeton, code, sortie) {
        correction::Lecture::Lue(a) => {
            assert_eq!(code, Some(0));
            assert_ne!(a.accord, commandes::Accord::NUL);
            propre(&a.titre, false);
            propre(&a.date, false);
            assert!(!a.valeurs.is_empty() && a.valeurs.len() <= changements::VALEURS_MAX);
            for v in &a.valeurs {
                propre(&v.chemin, false);
                assert!(v.chemin.chars().count() <= changements::CHEMIN_MAX);
                assert!(v.chemin.starts_with('/') || v.chemin == "~" || v.chemin.starts_with("~/"), "{v:?}");
                assert!(octal(&v.actuel) && octal(&v.avant), "{v:?}");
                assert!(v.pose.is_empty() || octal(&v.pose), "{v:?}");
            }
        }
        correction::Lecture::Refusee(r) => {
            assert!(code.is_some_and(|c| c != 0));
            propre(&r, false);
            assert!(visible(&r) && r.chars().count() <= changements::RAISON_MAX, "{r:?}");
        }
        correction::Lecture::Illisible(r) => erreur(&r),
    }
    for famille in [commandes::Famille::Correction, commandes::Famille::Annulation] {
        match changements::lire_issue(famille, code, sortie) {
            changements::IssueChange::Fait { annulation, .. } => {
                assert!(matches!(code, Some(0 | 1)));
                assert_eq!(annulation.is_some(), famille == commandes::Famille::Correction);
            }
            changements::IssueChange::Refuse(r) | changements::IssueChange::Echec(r) => {
                assert!(code.is_some_and(|c| c != 0));
                propre(&r, false);
                assert!(visible(&r) && r.chars().count() <= changements::RAISON_MAX, "{r:?}");
            }
            changements::IssueChange::Illisible(r) => erreur(&r),
        }
    }
}

libfuzzer_sys::fuzz_target!(|donnees: &[u8]| {
    let Some((&langue, sortie)) = donnees.split_first() else {
        return;
    };
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
    changements_(code, sortie);
});
