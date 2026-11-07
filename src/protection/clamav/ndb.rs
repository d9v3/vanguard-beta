//! Les signatures de contenu de ClamAV (.ndb : `nom:cible:décalage:hexadécimal[:min[:max]]`), et ce que les
//! sous-signatures des logiques (.ldb) partagent avec elles : l'hexadécimal changé en éléments du moteur de motifs
//! (`protection::motifs`) et le décalage qui dit où la signature commence.
//!
//! Hexadécimal : octets (`4d5a`), demi-octets et jokers (`?a`, `a?`, `??`), sauts (`{n}`, `{-n}`, `{n-}`, `{n-m}`,
//! `*`), choix (`(aa|bbcc|d?)`). Un saut sans fin (`*`, `{n-}`) est borné à `ouvert` octets : la signature est alors
//! « approchée » (un écart plus grand échappe ; jamais l'inverse). Les formes que Vanguard ne lit pas (`(B)`, `(L)`,
//! `!(…)`) sont refusées et comptées.
//!
//! `[n]` et `[n-m]` comme ClamAV (`cli_ac_addsig`) : un seul octet (non joker) au bout d'une partie (les parties
//! sont coupées aux sauts `{…}` et `*`), à `n` à `m` octets (`m` ≤ 32) du reste de la partie, `HEX`. Vanguard les
//! lit, suivis (ou précédés) d'au moins deux octets, comme `aa{n-m}HEX` : aux deux bouts de la signature entière,
//! où c'est exact ; au bout d'une partie intérieure, seulement contre un saut sans fin (`*`, `{n-}`) : ClamAV
//! mesure ce saut depuis `HEX`, donc ce que Vanguard trouve, ClamAV le trouve aussi (l'inverse peut échapper).
//! Ailleurs (contre un saut borné, dans un choix) : refusé. Devant la signature, avec un décalage autre que `*` :
//! refusé aussi (ClamAV mesure le décalage depuis `HEX`, pas depuis l'octet). En texte large (`::w`), ClamAV les
//! change en `{n-m}`, sans contrainte.
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

/// L'hexadécimal changé en éléments, le nombre de sauts sans fin bornés à `ouvert`, et la place (dans `elements`) des
/// sauts écrits `[n-m]`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Lu {
    pub elements: Vec<Element>,
    pub ouverts: usize,
    pub crochets: Vec<usize>,
    /// Les sauts sans fin (`*`, `{n-}`) hors des choix, par leur place dans `elements`.
    pub sans_fin: Vec<usize>,
}

/// La plus grande distance d'un `[n-m]` (`AC_CH_MAXDIST` de ClamAV).
const CROCHET_MAX: u32 = 32;

/// Les `[n-m]` de `lu` lus en texte étroit, comme ClamAV (voir l'en-tête du module) ; `partout` : la signature n'a
/// pas d'autre décalage que `*`. `Err(Illisible)` : ce que ClamAV refuse aussi ; `Err(Forme)` : ce que Vanguard ne
/// lit pas.
pub(crate) fn crochets_etroits(lu: &Lu, partout: bool) -> Result<(), NonLu> {
    let octet = |i: usize| matches!(lu.elements.get(i), Some(Element::Octet { .. }));
    let seul = |i: usize| match lu.elements.get(i) {
        Some(Element::Octet { masque, .. }) => *masque != 0,
        _ => false,
    };
    // Les parties de ClamAV : coupées aux sauts `{…}` et `*` (pas aux crochets).
    let coupe = |i: usize| matches!(lu.elements.get(i), Some(Element::Saut { .. })) && !lu.crochets.contains(&i);
    let fin = lu.elements.len();
    for &k in &lu.crochets {
        match lu.elements.get(k) {
            Some(Element::Saut { max, .. }) if *max <= CROCHET_MAX => {}
            _ => return Err(NonLu::Illisible),
        }
        let (Some(k1), Some(k2)) = (k.checked_add(1), k.checked_add(2)) else {
            return Err(NonLu::Illisible);
        };
        // La partie de `k` : de `a` (compris) à `b` (exclu).
        let a = (0..k).rev().find(|&i| coupe(i)).map_or(Some(0), |i| i.checked_add(1));
        let b = (k1..fin).find(|&i| coupe(i)).unwrap_or(fin);
        let Some(a) = a else {
            return Err(NonLu::Illisible);
        };
        let devant = a.checked_add(1) == Some(k) && seul(a) && k2 < b && octet(k1) && octet(k2);
        let derriere = b.checked_sub(1) == Some(k1)
            && seul(k1)
            && k.checked_sub(2).is_some_and(|i| i >= a && octet(i))
            && k.checked_sub(1).is_some_and(octet);
        // Au bout d'une partie intérieure, ClamAV mesure le saut voisin depuis `HEX`, pas depuis l'octet : Vanguard
        // ne le lit que si ce saut est sans fin (`*`, `{n-}`), où ce qu'il trouve, ClamAV le trouve aussi.
        let devant = devant && (a == 0 || a.checked_sub(1).is_some_and(|i| lu.sans_fin.contains(&i)));
        let derriere = derriere && (b == fin || lu.sans_fin.contains(&b));
        if devant && a == 0 && !partout {
            return Err(NonLu::Forme);
        }
        if !devant && !derriere {
            return Err(NonLu::Forme);
        }
    }
    Ok(())
}

/// Lit l'hexadécimal d'une signature ; les sauts sans fin (`*`, `{n-}`) vont jusqu'à `ouvert` octets de plus que leur
/// minimum.
pub(crate) fn lire_hex(texte: &str, ouvert: u32) -> Result<Lu, NonLu> {
    let mut l = Lecteur {
        t: texte.as_bytes(),
        i: 0,
        ouvert,
        ouverts: 0,
        crochets: Vec::new(),
        sans_fin: Vec::new(),
    };
    let elements = l.suite(0)?;
    if l.i != l.t.len() || elements.is_empty() {
        return Err(NonLu::Illisible);
    }
    Ok(Lu {
        elements,
        ouverts: l.ouverts,
        crochets: l.crochets,
        sans_fin: l.sans_fin,
    })
}

struct Lecteur<'a> {
    t: &'a [u8],
    i: usize,
    ouvert: u32,
    ouverts: usize,
    crochets: Vec<usize>,
    sans_fin: Vec<usize>,
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
                    if profondeur == 0 {
                        self.sans_fin.push(elements.len());
                    }
                    elements.push(Element::Saut {
                        min: 0,
                        max: self.ouvert,
                    });
                }
                // Dans un choix, ClamAV le lirait comme un saut au bout d'une partie : refusé (voir l'en-tête).
                b'[' if profondeur > 0 => return Err(NonLu::Forme),
                b'[' => {
                    self.crochets.push(elements.len());
                    elements.push(self.saut(o)?);
                }
                b'{' => {
                    let avant = self.ouverts;
                    let saut = self.saut(o)?;
                    if profondeur == 0 && self.ouverts != avant {
                        self.sans_fin.push(elements.len());
                    }
                    elements.push(saut);
                }
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

    /// `{n}`, `{-n}`, `{n-}`, `{n-m}`, `[n]` ou `[n-m]`.
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
            None => {
                let n = borne(dedans)?;
                (n, n)
            }
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

/// Les éléments en texte large (`::w`, UTF-16 petit-boutiste) : un zéro après chaque octet. Les sauts restent en
/// octets, comme ClamAV (`cli_sigopts_handler` recopie `{n-m}` tel quel, et change `[n-m]` en `{n-m}`).
pub(crate) fn large(elements: &[Element]) -> Vec<Element> {
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
            Element::Saut { .. } => sortie.push(e.clone()),
            Element::Choix(suites) => sortie.push(Element::Choix(suites.iter().map(|s| large(s)).collect())),
        }
    }
    sortie
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
        assert_eq!((l.ouverts, &l.crochets[..], &l.sans_fin[..]), (1, &[8][..], &[9][..]));
        // Un saut sans fin dans un choix n'est pas à la racine : pas dans `sans_fin`.
        let choix = lire_hex("aa(bb*cc|dd)ee{2-}ff", 10).unwrap();
        assert_eq!((choix.ouverts, &choix.sans_fin[..]), (2, &[3][..]));
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
                ouverts: 1,
                crochets: vec![],
                sans_fin: vec![1],
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
            ("aa[3-]bb", NonLu::Illisible),
            ("aa[-3]bb", NonLu::Illisible),
            ("aa(bb|cc[1]dd)", NonLu::Forme),
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

    /// `[n-m]` comme `cli_ac_addsig` de ClamAV : un octet à un bout de la signature, au plus 32 octets d'écart.
    #[test]
    fn crochets_comme_clamav() {
        let lire = |t: &str, partout: bool| lire_hex(t, 10).and_then(|l| crochets_etroits(&l, partout).map(|()| l));
        // Devant, derrière, les deux ; `[n]` est `[n-n]`.
        let l = lire("aa[2-4]bbcc", true).unwrap();
        assert_eq!(
            l.elements,
            [o(0xaa), Element::Saut { min: 2, max: 4 }, o(0xbb), o(0xcc)]
        );
        let l = lire("bb??[3]cc", false).unwrap();
        assert_eq!(l.elements[2], Element::Saut { min: 3, max: 3 });
        assert!(lire("aa[0-32]bb?c{5}ddee[1]f?", true).is_ok());
        assert!(lire("aa[1-2]bbcc*dd", true).is_ok());
        // Derrière, un décalage reste juste : ClamAV le mesure depuis le début, qui ne change pas.
        assert!(lire("bbcc[1-2]dd", false).is_ok());
        // Au bout d'une partie intérieure, contre un saut sans fin : ce que Vanguard trouve, ClamAV le trouve aussi
        // (comme dans main.ndb : `…68[4-4]e8*83????…`). Le décalage ne vaut que pour la première partie.
        assert!(lire("aabb*cc[1-2]ddee", false).is_ok());
        assert!(lire("aabbcc[4]dd*eeff", false).is_ok());
        assert!(lire("aabb{3-}cc[1-2]ddee{-4}ff", false).is_ok());
        assert!(lire("aa*bb[4]ccdd[1]ee*ff", true).is_ok());
        for (t, partout, raison) in [
            // Plus de 32 : ClamAV refuse la signature.
            ("aa[1-33]bbcc", true, NonLu::Illisible),
            // Ni au bout ni seul : ClamAV refuse, ou mesure autrement (au bout d'une partie entre deux sauts).
            ("aabb[1-2]ccdd", true, NonLu::Forme),
            ("aa{2}bb[1-2]ccdd{2}ee", true, NonLu::Forme),
            ("aa[1-2]bb", true, NonLu::Forme),
            ("aa[1-2]bb{2}cc", true, NonLu::Forme),
            // Contre un saut borné : ClamAV mesure ce saut depuis `HEX`, à jusqu'à 33 octets de l'octet.
            ("aabb{3}cc[1-2]ddee", true, NonLu::Forme),
            ("aabbcc[4]dd{2-5}eeff", true, NonLu::Forme),
            ("aabb{-3}cc[1-2]ddee", true, NonLu::Forme),
            // Devant la première partie, avec un décalage.
            ("aa[1-2]bbcc*dd", false, NonLu::Forme),
            ("aa[1-2]bb[1-2]cc", true, NonLu::Forme),
            // Un joker entier n'est rien vérifier (ClamAV l'ignore) : refusé.
            ("??[1-2]bbcc", true, NonLu::Forme),
            ("bbcc[1-2]??", true, NonLu::Forme),
            // Devant, avec un décalage : ClamAV le mesure depuis `bbcc`.
            ("aa[1-2]bbcc", false, NonLu::Forme),
        ] {
            assert_eq!(lire(t, partout).map(|_| ()), Err(raison), "{t}");
        }
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
            large(&lire_hex("41{1}42", 0).unwrap().elements),
            vec![o(0x41), o(0), Element::Saut { min: 1, max: 1 }, o(0x42), o(0)]
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
