//! Les signatures logiques de ClamAV (.ldb : `nom;bloc cible;expression;sous-signature0;sous-signature1;…`), dans le
//! sous-ensemble que Vanguard sait appliquer exactement :
//! - bloc cible : `Target`, `Engine` (niveau du moteur), `FileSize`, `EntryPoint`, `NumberOfSections` ; tout autre
//!   (`Container`, `Icon…`, `HandlerType`, `Intermediates`) est compté, jamais deviné ;
//! - expression : `&`, `|`, parenthèses, et les comptes que « présente » ou « absente » suffisent à juger (`>0`, `=0`,
//!   `<1`, `>0,M` : au moins M sous-signatures différentes) ; `&` et `|` mêlés sans parenthèses sont refusés plutôt
//!   que lus dans un sens qui ne serait peut-être pas celui de ClamAV ;
//! - sous-signature : `[décalage:]hexadécimal[::i|w|a]` ; PCRE, comparaison d'octets, macros, images floues et mot
//!   entier (`::f`) sont comptés.
//!
//! L'expression devient une suite à pile (notation polonaise inverse) jugée en trois valeurs : présente, absente,
//! inconnue (premier passage, où seuls les atomes sont cherchés).
//!
//! Module pur, sans données de la machine : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use super::commun::{Cible, NIVEAU, NonLu};
use super::ndb::{Decalage, lire_decalage};

/// Les sous-signatures d'une logique, au plus (la limite de ClamAV).
pub(crate) const SOUS_MAX: usize = 64;
/// Les opérations d'une expression, et sa profondeur, au plus.
const OPERATIONS_MAX: usize = 512;
const PROFONDEUR_MAX: usize = 32;

/// Une opération de l'expression, sur une pile de valeurs à trois états.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// Empile l'état de la sous-signature `i`.
    Sous(u8),
    /// Remplace les `n` dernières valeurs par leur « et », ou leur « ou ».
    Et(u8),
    Ou(u8),
    /// Remplace la dernière valeur par son contraire.
    Non,
    /// Remplace les `n` dernières valeurs par « au moins `m` sont présentes ».
    AuMoins {
        m: u8,
        n: u8,
    },
}

/// Une valeur à trois états.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Etat {
    Absente,
    Inconnue,
    Presente,
}

/// Juge l'expression `ops` ; `etat(i)` donne celui de la sous-signature `i`. `None` : une expression mal formée (ne
/// devrait pas arriver : `lire_expression` les refuse).
pub(crate) fn juger(ops: &[Op], etat: impl Fn(u8) -> Etat) -> Option<Etat> {
    let mut pile: Vec<Etat> = Vec::with_capacity(ops.len());
    for op in ops {
        let v = match *op {
            Op::Sous(i) => etat(i),
            Op::Non => match pile.pop()? {
                Etat::Absente => Etat::Presente,
                Etat::Inconnue => Etat::Inconnue,
                Etat::Presente => Etat::Absente,
            },
            Op::Et(n) | Op::Ou(n) | Op::AuMoins { n, .. } => {
                let debut = pile.len().checked_sub(usize::from(n))?;
                let valeurs = pile.get(debut..)?;
                let presentes = valeurs.iter().filter(|v| **v == Etat::Presente).count();
                let possibles = valeurs.iter().filter(|v| **v != Etat::Absente).count();
                let au_moins = match *op {
                    Op::Et(_) => usize::from(n),
                    Op::Ou(_) => 1,
                    Op::AuMoins { m, .. } => usize::from(m),
                    _ => return None,
                };
                pile.truncate(debut);
                if presentes >= au_moins {
                    Etat::Presente
                } else if possibles < au_moins {
                    Etat::Absente
                } else {
                    Etat::Inconnue
                }
            }
        };
        pile.push(v);
    }
    match pile.as_slice() {
        [v] => Some(*v),
        _ => None,
    }
}

/// Un nœud d'expression lu, avant d'être aplati.
enum Noeud {
    Sous(u8),
    Et(Vec<Noeud>),
    Ou(Vec<Noeud>),
    Non(Box<Noeud>),
    AuMoins(u8, Vec<u8>),
}

struct Expression<'a> {
    t: &'a [u8],
    i: usize,
    sous: usize,
}

impl Expression<'_> {
    fn octet(&self) -> Option<u8> {
        self.t.get(self.i).copied()
    }

    fn avancer(&mut self) {
        self.i = self.i.saturating_add(1);
    }

    fn nombre(&mut self) -> Result<u32, NonLu> {
        let debut = self.i;
        while self.octet().is_some_and(|o| o.is_ascii_digit()) {
            self.avancer();
        }
        let t = self.t.get(debut..self.i).ok_or(NonLu::Illisible)?;
        let t = std::str::from_utf8(t).map_err(|_| NonLu::Illisible)?;
        if t.is_empty() {
            return Err(NonLu::Illisible);
        }
        t.parse().map_err(|_| NonLu::Illisible)
    }

    /// termes séparés par un seul sorte d'opérateur.
    fn liste(&mut self, profondeur: usize) -> Result<Noeud, NonLu> {
        if profondeur > PROFONDEUR_MAX {
            return Err(NonLu::Bornes);
        }
        let mut termes = vec![self.terme(profondeur)?];
        let mut sorte: Option<u8> = None;
        while let Some(o @ (b'&' | b'|')) = self.octet() {
            if sorte.is_some_and(|s| s != o) {
                return Err(NonLu::Forme);
            }
            sorte = Some(o);
            self.avancer();
            termes.push(self.terme(profondeur)?);
        }
        Ok(match (sorte, termes.len()) {
            (None, 1) => termes.pop().ok_or(NonLu::Illisible)?,
            (Some(b'&'), _) => Noeud::Et(termes),
            _ => Noeud::Ou(termes),
        })
    }

    fn terme(&mut self, profondeur: usize) -> Result<Noeud, NonLu> {
        let noeud = match self.octet() {
            Some(b'(') => {
                self.avancer();
                let n = self.liste(profondeur.saturating_add(1))?;
                if self.octet() != Some(b')') {
                    return Err(NonLu::Illisible);
                }
                self.avancer();
                n
            }
            Some(b'0'..=b'9') => {
                let i = self.nombre()?;
                let i = u8::try_from(i).map_err(|_| NonLu::Illisible)?;
                if usize::from(i) >= self.sous {
                    return Err(NonLu::Illisible);
                }
                Noeud::Sous(i)
            }
            _ => return Err(NonLu::Illisible),
        };
        let Some(comparaison @ (b'=' | b'>' | b'<')) = self.octet() else {
            return Ok(noeud);
        };
        self.avancer();
        let n = self.nombre()?;
        let m = if self.octet() == Some(b',') {
            self.avancer();
            Some(self.nombre()?)
        } else {
            None
        };
        // Seuls les comptes que « présente » ou « absente » jugent : une somme d'occurrences ne se connaît pas.
        let membres = || -> Result<Vec<u8>, NonLu> {
            let mut v = Vec::new();
            membres(&noeud, &mut v)?;
            Ok(v)
        };
        match (comparaison, n, m) {
            (b'>', 0, None) => {
                membres()?;
                Ok(noeud)
            }
            (b'=', 0, None) | (b'<', 1, None) => {
                membres()?;
                Ok(Noeud::Non(Box::new(noeud)))
            }
            (b'>', 0, Some(m)) => {
                let m = u8::try_from(m).map_err(|_| NonLu::Comptage)?;
                Ok(Noeud::AuMoins(m.max(1), membres()?))
            }
            _ => Err(NonLu::Comptage),
        }
    }
}

/// Les sous-signatures d'un « ou » (ou d'une seule) : ce qu'un compte peut viser. Un « et » ou un contraire compté
/// n'a pas de sens sûr : refusé.
fn membres(n: &Noeud, v: &mut Vec<u8>) -> Result<(), NonLu> {
    match n {
        Noeud::Sous(i) => {
            if !v.contains(i) {
                v.push(*i);
            }
            Ok(())
        }
        Noeud::Ou(termes) => termes.iter().try_for_each(|t| membres(t, v)),
        _ => Err(NonLu::Comptage),
    }
}

fn aplatir(n: Noeud, ops: &mut Vec<Op>) -> Result<(), NonLu> {
    if ops.len() >= OPERATIONS_MAX {
        return Err(NonLu::Bornes);
    }
    let compte = |l: usize| u8::try_from(l).map_err(|_| NonLu::Bornes);
    match n {
        Noeud::Sous(i) => ops.push(Op::Sous(i)),
        Noeud::Et(termes) | Noeud::Ou(termes) if termes.is_empty() => return Err(NonLu::Illisible),
        Noeud::Et(termes) => {
            let n = compte(termes.len())?;
            termes.into_iter().try_for_each(|t| aplatir(t, ops))?;
            ops.push(Op::Et(n));
        }
        Noeud::Ou(termes) => {
            let n = compte(termes.len())?;
            termes.into_iter().try_for_each(|t| aplatir(t, ops))?;
            ops.push(Op::Ou(n));
        }
        Noeud::Non(t) => {
            aplatir(*t, ops)?;
            ops.push(Op::Non);
        }
        Noeud::AuMoins(m, membres) => {
            let n = compte(membres.len())?;
            ops.extend(membres.into_iter().map(Op::Sous));
            ops.push(Op::AuMoins { m, n });
        }
    }
    Ok(())
}

/// Lit une expression logique sur `sous` sous-signatures.
pub(crate) fn lire_expression(texte: &str, sous: usize) -> Result<Vec<Op>, NonLu> {
    let mut e = Expression {
        t: texte.as_bytes(),
        i: 0,
        sous,
    };
    let n = e.liste(0)?;
    if e.i != e.t.len() {
        return Err(NonLu::Illisible);
    }
    let mut ops = Vec::new();
    aplatir(n, &mut ops)?;
    Ok(ops)
}

/// Une borne `min-max` (ou un nombre seul) du bloc cible.
fn intervalle(t: &str) -> Option<(u64, u64)> {
    let lire = |t: &str| -> Option<u64> {
        if t.is_empty() || !t.bytes().all(|o| o.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    match t.split_once('-') {
        Some((a, "")) => Some((lire(a)?, u64::MAX)),
        Some((a, b)) => Some((lire(a)?, lire(b)?)),
        None => lire(t).map(|n| (n, n)),
    }
}

/// Le bloc cible lu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Conditions {
    pub cible: Cible,
    pub taille: Option<(u64, u64)>,
    pub point_entree: Option<(u64, u64)>,
    pub sections: Option<(u64, u64)>,
}

/// Lit le bloc cible : `Err(Niveau)` pour un autre niveau du moteur, `Err(Condition)` pour une condition que Vanguard
/// ne juge pas.
pub(crate) fn lire_conditions(texte: &str) -> Result<Conditions, NonLu> {
    let mut cible = None;
    let mut c = Conditions {
        cible: Cible::Tout,
        taille: None,
        point_entree: None,
        sections: None,
    };
    let mut autre = false;
    for champ in texte.split(',') {
        let (cle, valeur) = champ.split_once(':').ok_or(NonLu::Illisible)?;
        match cle {
            "Target" => {
                let n: u32 = valeur.parse().map_err(|_| NonLu::Illisible)?;
                cible = Some(Cible::du_numero(n));
            }
            "Engine" => {
                let (min, max) = intervalle(valeur).ok_or(NonLu::Illisible)?;
                if u64::from(NIVEAU) < min || u64::from(NIVEAU) > max {
                    return Err(NonLu::Niveau);
                }
            }
            "FileSize" => c.taille = Some(intervalle(valeur).ok_or(NonLu::Illisible)?),
            "EntryPoint" => c.point_entree = Some(intervalle(valeur).ok_or(NonLu::Illisible)?),
            "NumberOfSections" => c.sections = Some(intervalle(valeur).ok_or(NonLu::Illisible)?),
            _ => autre = true,
        }
    }
    // Le niveau d'abord : une signature d'un autre moteur n'est pas « non comprise ».
    if autre {
        return Err(NonLu::Condition);
    }
    c.cible = cible.ok_or(NonLu::Illisible)?.ok_or(NonLu::Cible)?;
    Ok(c)
}

/// Les modificateurs d'une sous-signature.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Modificateurs {
    pub sans_casse: bool,
    pub large: bool,
    /// `::a` avec `::w` : les deux formes.
    pub etroit_aussi: bool,
}

/// Une sous-signature lue (l'hexadécimal n'est que découpé).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sous<'a> {
    pub decalage: Decalage,
    pub hex: &'a str,
    pub modificateurs: Modificateurs,
}

pub(crate) fn lire_sous(texte: &str) -> Result<Sous<'_>, NonLu> {
    // Une expression rationnelle : `[décalage:]déclencheur/motif/[options]`.
    if texte.contains('/') {
        return Err(NonLu::Pcre);
    }
    // Comparaison d'octets, image floue (`#`), macro (`${…}…$`).
    if texte.contains('#') || texte.contains('$') {
        return Err(NonLu::Forme);
    }
    let (corps, mods) = match texte.split_once("::") {
        Some((c, m)) => (c, Some(m)),
        None => (texte, None),
    };
    let mut modificateurs = Modificateurs::default();
    let mut ascii = false;
    for m in mods.unwrap_or("").bytes() {
        match m {
            b'i' => modificateurs.sans_casse = true,
            b'w' => modificateurs.large = true,
            b'a' => ascii = true,
            b'f' => return Err(NonLu::Forme),
            _ => return Err(NonLu::Illisible),
        }
    }
    if mods == Some("") {
        return Err(NonLu::Illisible);
    }
    modificateurs.etroit_aussi = ascii && modificateurs.large;
    let (decalage, hex) = match corps.split_once(':') {
        Some((d, h)) => (lire_decalage(d)?, h),
        None => (lire_decalage("*")?, corps),
    };
    if hex.is_empty() || hex.contains(':') {
        return Err(NonLu::Illisible);
    }
    Ok(Sous {
        decalage,
        hex,
        modificateurs,
    })
}

/// Une ligne de .ldb lue.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Ldb<'a> {
    pub nom: &'a str,
    pub conditions: Conditions,
    pub expression: Vec<Op>,
    pub sous: Vec<Sous<'a>>,
}

/// Lit une ligne de .ldb. La première raison trouvée compte la ligne entière : une logique dont une partie manque
/// n'est jamais appliquée à moitié.
pub(crate) fn lire_ligne(ligne: &str) -> Result<Ldb<'_>, NonLu> {
    let mut champs = ligne.split(';');
    let (Some(nom), Some(bloc), Some(expression)) = (champs.next(), champs.next(), champs.next()) else {
        return Err(NonLu::Illisible);
    };
    if nom.is_empty() {
        return Err(NonLu::Illisible);
    }
    let conditions = lire_conditions(bloc)?;
    let textes: Vec<&str> = champs.by_ref().take(SOUS_MAX.saturating_add(1)).collect();
    if textes.is_empty() || textes.len() > SOUS_MAX {
        return Err(NonLu::Illisible);
    }
    let sous = textes.into_iter().map(lire_sous).collect::<Result<Vec<_>, _>>()?;
    let expression = lire_expression(expression, sous.len())?;
    Ok(Ldb {
        nom,
        conditions,
        expression,
        sous,
    })
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::super::ndb::Ancre;
    use super::*;

    fn juge(expr: &str, n: usize, etats: &[Etat]) -> Etat {
        let ops = lire_expression(expr, n).unwrap();
        juger(&ops, |i| etats[usize::from(i)]).unwrap()
    }

    #[test]
    fn expressions() {
        use Etat::{Absente as A, Inconnue as I, Presente as P};
        assert_eq!(juge("0", 1, &[P]), P);
        assert_eq!(juge("0&1", 2, &[P, A]), A);
        assert_eq!(juge("0&1", 2, &[P, I]), I);
        assert_eq!(juge("0|1", 2, &[A, I]), I);
        assert_eq!(juge("0|1", 2, &[A, P]), P);
        assert_eq!(juge("(0|1)&2", 3, &[A, P, P]), P);
        assert_eq!(juge("0&1=0", 2, &[P, A]), P);
        assert_eq!(juge("0&1<1", 2, &[P, P]), A);
        assert_eq!(juge("(0|1)>0", 2, &[A, P]), P);
        assert_eq!(juge("(0|1|2)>0,2", 3, &[P, A, P]), P);
        assert_eq!(juge("(0|1|2)>0,2", 3, &[P, A, A]), A);
        assert_eq!(juge("(0|1|2)>0,2", 3, &[P, A, I]), I);
        assert_eq!(juge("((0|1)|2)>0,3", 3, &[P, P, P]), P);
        assert_eq!(juge("0=0", 1, &[I]), I);
    }

    #[test]
    fn expressions_refusees() {
        for (e, raison) in [
            ("0&1|2", NonLu::Forme),
            ("0>1", NonLu::Comptage),
            ("0=2", NonLu::Comptage),
            ("0<2", NonLu::Comptage),
            ("(0&1)>0", NonLu::Comptage),
            ("(0|1)>0,999", NonLu::Comptage),
            ("3", NonLu::Illisible),
            ("0&", NonLu::Illisible),
            ("(0", NonLu::Illisible),
            ("0)", NonLu::Illisible),
            ("", NonLu::Illisible),
            ("0 & 1", NonLu::Illisible),
            ("99999999999", NonLu::Illisible),
        ] {
            assert_eq!(lire_expression(e, 3), Err(raison), "{e}");
        }
        let profond = format!("{}0{}", "(".repeat(10_000), ")".repeat(10_000));
        assert_eq!(lire_expression(&profond, 1), Err(NonLu::Bornes));
        let long = (0..64).map(|i| i.to_string()).collect::<Vec<_>>().join("&");
        assert_eq!(lire_expression(&long, 64).unwrap().len(), 65);
    }

    #[test]
    fn blocs_cibles() {
        assert_eq!(
            lire_conditions("Engine:51-255,Target:1,FileSize:10-20,EntryPoint:0-,NumberOfSections:3"),
            Ok(Conditions {
                cible: Cible::Pe,
                taille: Some((10, 20)),
                point_entree: Some((0, u64::MAX)),
                sections: Some((3, 3)),
            })
        );
        for (b, raison) in [
            ("Target:1,Engine:300-400", NonLu::Niveau),
            ("Target:1,Engine:1-50", NonLu::Niveau),
            ("Target:1,Container:CL_TYPE_ZIP", NonLu::Condition),
            ("Engine:300-400,IconGroup1:x", NonLu::Niveau),
            ("Target:3", NonLu::Cible),
            ("Engine:51-255", NonLu::Illisible),
            ("Target", NonLu::Illisible),
            ("Target:x", NonLu::Illisible),
            ("Target:1,FileSize:a-b", NonLu::Illisible),
        ] {
            assert_eq!(lire_conditions(b), Err(raison), "{b}");
        }
    }

    #[test]
    fn sous_signatures() {
        let s = lire_sous("EP+2,4:6a40::wa").unwrap();
        assert_eq!(s.decalage.ancre, Ancre::PointEntree(2));
        assert_eq!(s.decalage.etendue, 4);
        assert_eq!(s.hex, "6a40");
        assert!(s.modificateurs.large && s.modificateurs.etroit_aussi && !s.modificateurs.sans_casse);
        assert!(lire_sous("6a40::i").unwrap().modificateurs.sans_casse);
        assert_eq!(lire_sous("6a40").unwrap().decalage.ancre, Ancre::Partout);
        for (t, raison) in [
            ("0/abc/i", NonLu::Pcre),
            ("0(>>2#hb2#=0)", NonLu::Forme),
            ("${6-7}0$", NonLu::Forme),
            ("fuzzy_img#af2ad01ed42993c7", NonLu::Forme),
            ("6a40::f", NonLu::Forme),
            ("6a40::z", NonLu::Illisible),
            ("6a40::", NonLu::Illisible),
            ("EP+0:", NonLu::Illisible),
            ("VI:6a40", NonLu::Forme),
        ] {
            assert_eq!(lire_sous(t), Err(raison), "{t}");
        }
    }

    #[test]
    fn lignes_ldb() {
        let l = lire_ligne("Essai.Ldb-1;Engine:81-255,Target:0;0&1;6a40;EOF-4:41424344::i").unwrap();
        assert_eq!(l.nom, "Essai.Ldb-1");
        assert_eq!(l.sous.len(), 2);
        assert_eq!(l.expression, vec![Op::Sous(0), Op::Sous(1), Op::Et(2)]);
        assert_eq!(lire_ligne("Essai;Target:0;0&1;6a40"), Err(NonLu::Illisible));
        assert_eq!(lire_ligne("Essai;Target:0;0;0/a/"), Err(NonLu::Pcre));
        assert_eq!(lire_ligne("Essai;Target:0"), Err(NonLu::Illisible));
        let trop = format!("Essai;Target:0;0;{}", vec!["aa"; 65].join(";"));
        assert_eq!(lire_ligne(&trop), Err(NonLu::Illisible));
    }
}
