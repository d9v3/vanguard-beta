//! Les signatures de contenu de ClamAV (.ndb : `nom:cible:décalage:hexadécimal[:min[:max]]`), et ce que les
//! sous-signatures des logiques (.ldb) partagent avec elles : l'hexadécimal changé en éléments du moteur de motifs
//! (`protection::motifs`) et le décalage qui dit où la signature commence.
//!
//! Hexadécimal : octets (`4d5a`), demi-octets et jokers (`?a`, `a?`, `??`), sauts (`{n}`, `{-n}`, `{n-}`, `{n-m}`,
//! `[n-m]`, `*`), choix (`(aa|bbcc|d?)`). Un saut sans fin (`*`, `{n-}`) est borné à `ouvert` octets : la signature
//! est alors « approchée » (un écart plus grand échappe ; jamais l'inverse). Les formes que Vanguard ne lit pas
//! (`(B)`, `(L)`, `!(…)`) sont refusées et comptées.
//!
//! Décalages : `*`, `n`, `EOF-n`, `EP+n`, `EP-n`, `Sx+n`, `SL+n` (chacun avec `,m` : début dans les `m` octets
//! suivants) et `SEx` (dans la section `x`).
//!
//! Module pur, sans données de la machine : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use super::commun::{Cible, NonLu, chiffre_hex, niveau_permis};
use crate::protection::motifs::{Element, PROFONDEUR_MAX};

/// D'où une signature commence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ancre {
    /// N'importe où.
    Partout,
    /// À `n` octets du début.
    Debut(u64),
    /// À `n` octets avant la fin.
    Fin(u64),
    /// Au point d'entrée du programme, plus (ou moins) `n`.
    PointEntree(i64),
    /// Au début de la section `x` (comptée de 0), plus `n`.
    Section(u32, u64),
    /// Au début de la dernière section, plus `n`.
    DerniereSection(u64),
    /// N'importe où dans la section `x`.
    DansSection(u32),
}

/// Le décalage : l'ancre, et l'étendue (`,m`) où le début peut se trouver après elle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Decalage {
    pub ancre: Ancre,
    pub etendue: u64,
}

/// Un nombre décimal, chiffres seuls (ni signe ni espace).
fn nombre(t: &str) -> Option<u64> {
    if t.is_empty() || !t.bytes().all(|o| o.is_ascii_digit()) {
        return None;
    }
    t.parse().ok()
}

/// Lit un décalage. `Err(Forme)` : une forme que Vanguard ne lit pas (`VI`, macros `$n$`…).
pub(crate) fn lire_decalage(texte: &str) -> Result<Decalage, NonLu> {
    if texte == "*" {
        return Ok(Decalage {
            ancre: Ancre::Partout,
            etendue: 0,
        });
    }
    let (ancre, etendue) = match texte.split_once(',') {
        Some((a, e)) => (a, nombre(e).ok_or(NonLu::Illisible)?),
        None => (texte, 0),
    };
    let ancre = if let Some(n) = ancre.strip_prefix("EOF-") {
        Ancre::Fin(nombre(n).ok_or(NonLu::Illisible)?)
    } else if let Some(n) = ancre.strip_prefix("EP+") {
        Ancre::PointEntree(i64::try_from(nombre(n).ok_or(NonLu::Illisible)?).map_err(|_| NonLu::Illisible)?)
    } else if let Some(n) = ancre.strip_prefix("EP-") {
        let n = i64::try_from(nombre(n).ok_or(NonLu::Illisible)?).map_err(|_| NonLu::Illisible)?;
        Ancre::PointEntree(n.checked_neg().ok_or(NonLu::Illisible)?)
    } else if let Some(n) = ancre.strip_prefix("SL+") {
        Ancre::DerniereSection(nombre(n).ok_or(NonLu::Illisible)?)
    } else if let Some(x) = ancre.strip_prefix("SE") {
        if etendue != 0 {
            return Err(NonLu::Illisible);
        }
        Ancre::DansSection(u32::try_from(nombre(x).ok_or(NonLu::Illisible)?).map_err(|_| NonLu::Illisible)?)
    } else if let Some(reste) = ancre.strip_prefix('S') {
        let (x, n) = reste.split_once('+').ok_or(NonLu::Forme)?;
        let x = u32::try_from(nombre(x).ok_or(NonLu::Illisible)?).map_err(|_| NonLu::Illisible)?;
        Ancre::Section(x, nombre(n).ok_or(NonLu::Illisible)?)
    } else if ancre.bytes().all(|o| o.is_ascii_digit()) {
        Ancre::Debut(nombre(ancre).ok_or(NonLu::Illisible)?)
    } else {
        return Err(NonLu::Forme);
    };
    Ok(Decalage { ancre, etendue })
}

/// L'hexadécimal changé en éléments, et le nombre de sauts sans fin bornés à `ouvert`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lu {
    pub elements: Vec<Element>,
    pub ouverts: usize,
}

/// Lit l'hexadécimal d'une signature ; les sauts sans fin (`*`, `{n-}`) vont jusqu'à `ouvert` octets de plus que leur
/// minimum.
pub(crate) fn lire_hex(texte: &str, ouvert: u32) -> Result<Lu, NonLu> {
    let mut l = Lecteur {
        t: texte.as_bytes(),
        i: 0,
        ouvert,
        ouverts: 0,
    };
    let elements = l.suite(0)?;
    if l.i != l.t.len() || elements.is_empty() {
        return Err(NonLu::Illisible);
    }
    Ok(Lu {
        elements,
        ouverts: l.ouverts,
    })
}

struct Lecteur<'a> {
    t: &'a [u8],
    i: usize,
    ouvert: u32,
    ouverts: usize,
}

impl Lecteur<'_> {
    fn octet(&self) -> Option<u8> {
        self.t.get(self.i).copied()
    }

    fn avancer(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    /// Une suite d'éléments, jusqu'à la fin du texte, ou jusqu'à `|` ou `)` dans un choix (`profondeur` > 0).
    fn suite(&mut self, profondeur: usize) -> Result<Vec<Element>, NonLu> {
        let mut elements = Vec::new();
        while let Some(o) = self.octet() {
            match o {
                b'|' | b')' if profondeur > 0 => break,
                b'*' => {
                    self.avancer();
                    self.ouverts = self.ouverts.saturating_add(1);
                    elements.push(Element::Saut {
                        min: 0,
                        max: self.ouvert,
                    });
                }
                b'{' | b'[' => elements.push(self.saut(o)?),
                b'(' => {
                    self.avancer();
                    if matches!(self.octet(), Some(b'B' | b'L')) {
                        return Err(NonLu::Forme);
                    }
                    if profondeur >= PROFONDEUR_MAX {
                        return Err(NonLu::Bornes);
                    }
                    let mut suites = Vec::new();
                    loop {
                        suites.push(self.suite(profondeur.saturating_add(1))?);
                        match self.octet() {
                            Some(b'|') => self.avancer(),
                            Some(b')') => {
                                self.avancer();
                                break;
                            }
                            _ => return Err(NonLu::Illisible),
                        }
                    }
                    elements.push(Element::Choix(suites));
                }
                b'!' => return Err(NonLu::Forme),
                _ => {
                    let h = self.octet().ok_or(NonLu::Illisible)?;
                    self.avancer();
                    let b = self.octet().ok_or(NonLu::Illisible)?;
                    self.avancer();
                    elements.push(demi_octets(h, b).ok_or(NonLu::Illisible)?);
                }
            }
        }
        Ok(elements)
    }

    /// `{n}`, `{-n}`, `{n-}`, `{n-m}` ou `[n-m]`.
    fn saut(&mut self, ouvrant: u8) -> Result<Element, NonLu> {
        let fermant = if ouvrant == b'{' { b'}' } else { b']' };
        self.avancer();
        let debut = self.i;
        while self.octet().is_some_and(|o| o != fermant) {
            self.avancer();
        }
        let dedans = self.t.get(debut..self.i).ok_or(NonLu::Illisible)?;
        if self.octet() != Some(fermant) {
            return Err(NonLu::Illisible);
        }
        self.avancer();
        let dedans = std::str::from_utf8(dedans).map_err(|_| NonLu::Illisible)?;
        let borne = |t: &str| -> Result<u32, NonLu> {
            u32::try_from(nombre(t).ok_or(NonLu::Illisible)?).map_err(|_| NonLu::Bornes)
        };
        let (min, max) = match dedans.split_once('-') {
            None if ouvrant == b'{' => {
                let n = borne(dedans)?;
                (n, n)
            }
            None => return Err(NonLu::Illisible),
            Some(("", m)) if ouvrant == b'{' => (0, borne(m)?),
            Some((n, "")) if ouvrant == b'{' => {
                let n = borne(n)?;
                self.ouverts = self.ouverts.saturating_add(1);
                (n, n.checked_add(self.ouvert).ok_or(NonLu::Bornes)?)
            }
            Some((n, m)) => (borne(n)?, borne(m)?),
        };
        if min > max {
            return Err(NonLu::Illisible);
        }
        Ok(Element::Saut { min, max })
    }
}

/// Deux chiffres (ou `?`) : un octet, un demi-octet connu ou un joker.
fn demi_octets(h: u8, b: u8) -> Option<Element> {
    let demi = |c: u8| -> Option<(u8, u8)> {
        if c == b'?' {
            Some((0, 0))
        } else {
            chiffre_hex(c).map(|v| (v, 0xF))
        }
    };
    let ((vh, mh), (vb, mb)) = (demi(h)?, demi(b)?);
    Some(Element::Octet {
        valeur: vh.checked_shl(4)? | vb,
        masque: mh.checked_shl(4)? | mb,
    })
}

/// Les éléments pour un texte sans casse (`::i`) : chaque lettre ASCII en minuscule, à chercher dans une vue en
/// minuscules des données. Un demi-octet ou un joker n'a pas de casse sûre : refusé.
pub(crate) fn sans_casse(elements: &[Element]) -> Result<Vec<Element>, NonLu> {
    elements
        .iter()
        .map(|e| match e {
            Element::Octet { valeur, masque: 0xFF } => Ok(Element::Octet {
                valeur: valeur.to_ascii_lowercase(),
                masque: 0xFF,
            }),
            Element::Octet { .. } => Err(NonLu::Forme),
            Element::Saut { .. } => Ok(e.clone()),
            Element::Choix(suites) => Ok(Element::Choix(
                suites.iter().map(|s| sans_casse(s)).collect::<Result<_, _>>()?,
            )),
        })
        .collect()
}

/// Les éléments en texte large (`::w`, UTF-16 petit-boutiste) : un zéro après chaque octet, les sauts doublés.
pub(crate) fn large(elements: &[Element]) -> Result<Vec<Element>, NonLu> {
    let mut sortie = Vec::with_capacity(elements.len().saturating_mul(2));
    for e in elements {
        match e {
            Element::Octet { .. } => {
                sortie.push(e.clone());
                sortie.push(Element::Octet {
                    valeur: 0,
                    masque: 0xFF,
                });
            }
            Element::Saut { min, max } => sortie.push(Element::Saut {
                min: min.checked_mul(2).ok_or(NonLu::Bornes)?,
                max: max.checked_mul(2).ok_or(NonLu::Bornes)?,
            }),
            Element::Choix(suites) => sortie.push(Element::Choix(
                suites.iter().map(|s| large(s)).collect::<Result<_, _>>()?,
            )),
        }
    }
    Ok(sortie)
}

/// Une ligne de .ndb lue.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ndb<'a> {
    pub nom: &'a str,
    pub cible: Cible,
    pub decalage: Decalage,
    pub hex: &'a str,
}

/// Lit une ligne de .ndb (l'hexadécimal n'est que découpé : `lire_hex` le lit).
pub(crate) fn lire_ligne(ligne: &str) -> Result<Ndb<'_>, NonLu> {
    let mut champs = ligne.split(':');
    let (Some(nom), Some(cible), Some(decalage), Some(hex)) =
        (champs.next(), champs.next(), champs.next(), champs.next())
    else {
        return Err(NonLu::Illisible);
    };
    let (min, max) = (champs.next(), champs.next());
    if champs.next().is_some() || nom.is_empty() || hex.is_empty() {
        return Err(NonLu::Illisible);
    }
    if !niveau_permis(min, max).ok_or(NonLu::Illisible)? {
        return Err(NonLu::Niveau);
    }
    let cible = nombre(cible).ok_or(NonLu::Illisible)?;
    let cible = u32::try_from(cible)
        .ok()
        .and_then(Cible::du_numero)
        .ok_or(NonLu::Cible)?;
    Ok(Ndb {
        nom,
        cible,
        decalage: lire_decalage(decalage)?,
        hex,
    })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    fn o(valeur: u8) -> Element {
        Element::Octet { valeur, masque: 0xFF }
    }

    #[test]
    fn hexadecimal_et_jokers() {
        let l = lire_hex("4d5a??a??b{2}{-3}{4-5}[6-7]*(aa|bbcc)", 100).unwrap();
        assert_eq!(l.ouverts, 1);
        assert_eq!(
            l.elements,
            vec![
                o(0x4d),
                o(0x5a),
                Element::Octet { valeur: 0, masque: 0 },
                Element::Octet {
                    valeur: 0xa0,
                    masque: 0xF0
                },
                Element::Octet {
                    valeur: 0x0b,
                    masque: 0x0F
                },
                Element::Saut { min: 2, max: 2 },
                Element::Saut { min: 0, max: 3 },
                Element::Saut { min: 4, max: 5 },
                Element::Saut { min: 6, max: 7 },
                Element::Saut { min: 0, max: 100 },
                Element::Choix(vec![vec![o(0xaa)], vec![o(0xbb), o(0xcc)]]),
            ]
        );
        assert_eq!(
            lire_hex("aa{5-}bb", 10).unwrap(),
            Lu {
                elements: vec![o(0xaa), Element::Saut { min: 5, max: 15 }, o(0xbb)],
                ouverts: 1
            }
        );
    }

    #[test]
    fn hexadecimal_refuse() {
        for (t, raison) in [
            ("", NonLu::Illisible),
            ("4", NonLu::Illisible),
            ("4g", NonLu::Illisible),
            ("+1", NonLu::Illisible),
            ("aa{3-2}bb", NonLu::Illisible),
            ("aa{x}bb", NonLu::Illisible),
            ("aa{3", NonLu::Illisible),
            ("aa[3]bb", NonLu::Illisible),
            ("aa(bb|cc", NonLu::Illisible),
            ("aa)bb", NonLu::Illisible),
            ("aa(B)bb", NonLu::Forme),
            ("aa(L)bb", NonLu::Forme),
            ("aa!(bb|cc)", NonLu::Forme),
            ("aa{99999999999}bb", NonLu::Bornes),
            ("((((((((((aa))))))))))", NonLu::Bornes),
        ] {
            assert_eq!(lire_hex(t, 10).map(|_| ()), Err(raison), "{t}");
        }
        // Très profond : refusé sans épuiser la pile.
        let profond = format!("{}aa{}", "(".repeat(100_000), ")".repeat(100_000));
        assert_eq!(lire_hex(&profond, 10).map(|_| ()), Err(NonLu::Bornes));
    }

    #[test]
    fn decalages() {
        let d = |a, e| Ok(Decalage { ancre: a, etendue: e });
        assert_eq!(lire_decalage("*"), d(Ancre::Partout, 0));
        assert_eq!(lire_decalage("12"), d(Ancre::Debut(12), 0));
        assert_eq!(lire_decalage("12,4"), d(Ancre::Debut(12), 4));
        assert_eq!(lire_decalage("EOF-9"), d(Ancre::Fin(9), 0));
        assert_eq!(lire_decalage("EP+3,2"), d(Ancre::PointEntree(3), 2));
        assert_eq!(lire_decalage("EP-3"), d(Ancre::PointEntree(-3), 0));
        assert_eq!(lire_decalage("S2+5"), d(Ancre::Section(2, 5), 0));
        assert_eq!(lire_decalage("SL+5"), d(Ancre::DerniereSection(5), 0));
        assert_eq!(lire_decalage("SE1"), d(Ancre::DansSection(1), 0));
        for (t, raison) in [
            ("VI", NonLu::Forme),
            ("$1$", NonLu::Forme),
            ("EP+", NonLu::Illisible),
            ("EP+-1", NonLu::Illisible),
            ("12,", NonLu::Illisible),
            ("SE1,4", NonLu::Illisible),
            ("S1-4", NonLu::Forme),
            ("99999999999999999999", NonLu::Illisible),
        ] {
            assert_eq!(lire_decalage(t), Err(raison), "{t}");
        }
    }

    #[test]
    fn casse_et_texte_large() {
        let l = lire_hex("41(42|43)??", 0).unwrap().elements;
        assert_eq!(sans_casse(&l), Err(NonLu::Forme));
        let l = lire_hex("41(42|2e){1}61", 0).unwrap().elements;
        assert_eq!(
            sans_casse(&l).unwrap(),
            vec![
                o(0x61),
                Element::Choix(vec![vec![o(0x62)], vec![o(0x2e)]]),
                Element::Saut { min: 1, max: 1 },
                o(0x61)
            ]
        );
        assert_eq!(
            large(&lire_hex("41{1}42", 0).unwrap().elements).unwrap(),
            vec![o(0x41), o(0), Element::Saut { min: 2, max: 2 }, o(0x42), o(0)]
        );
    }

    #[test]
    fn lignes_ndb() {
        assert_eq!(
            lire_ligne("Essai.Ndb-1:1:EP+0:6a40:51:255"),
            Ok(Ndb {
                nom: "Essai.Ndb-1",
                cible: Cible::Pe,
                decalage: Decalage {
                    ancre: Ancre::PointEntree(0),
                    etendue: 0
                },
                hex: "6a40"
            })
        );
        for (l, raison) in [
            ("Essai:0:*", NonLu::Illisible),
            ("Essai:0:*:", NonLu::Illisible),
            (":0:*:aa", NonLu::Illisible),
            ("Essai:x:*:aa", NonLu::Illisible),
            ("Essai:3:*:aa", NonLu::Cible),
            ("Essai:0:*:aa:999", NonLu::Niveau),
            ("Essai:0:*:aa:1:2:3", NonLu::Illisible),
            ("Essai:0:VI:aa", NonLu::Forme),
        ] {
            assert_eq!(lire_ligne(l), Err(raison), "{l}");
        }
    }
}
