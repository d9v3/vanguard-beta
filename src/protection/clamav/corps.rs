//! Les signatures de contenu (.ndb et logiques .ldb) gardées et cherchées en deux temps, pour tenir des centaines de
//! milliers de signatures sans les compiler toutes :
//! 1. au chargement, chaque sous-signature est lue une fois par le moteur de motifs (`protection::motifs`), qui la
//!    valide et en tire son atome (quelques octets fixes) ; seuls son texte, son décalage et le numéro de son atome
//!    sont gardés. Les atomes, sans doublon, forment une seule recherche ;
//! 2. sur une partie, cette recherche dit quels atomes s'y trouvent ; l'expression de chaque signature, jugée en
//!    trois valeurs (un atome absent : sous-signature absente ; présent : inconnue), écarte presque tout ; les
//!    sous-signatures des signatures qui restent sont alors compilées et cherchées pour de bon, à leur décalage.
//!
//! Module pur, sans données de la machine : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::time::Instant;

use super::commun::{Cible, NonLu};
use super::ldb::{self, Conditions, Etat, Modificateurs, Op};
use super::ndb::{self, Ancre, Decalage};
use crate::protection::motifs::{Echec, Element, Motif, Recherche, Refus};

/// Les bornes essayées pour un saut sans fin (`*`, `{n-}`), de la plus large à la plus étroite : la première que le
/// moteur de motifs accepte (longueur et coût bornés) est gardée.
const OUVERTS: [u32; 3] = [32 << 10, 4 << 10, 512];
/// Les positions essayées entre deux lectures de l'horloge, pour un décalage à étendue.
const POSITIONS_ENTRE_DELAIS: usize = 1 << 12;

/// Ce qu'on sait d'une partie hors de ses octets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Cadre {
    pub cible: Cible,
    /// La place du point d'entrée dans les octets (programmes seulement).
    pub point_entree: Option<u64>,
    /// La place et la taille de chaque section dans les octets (programmes seulement).
    pub sections: Vec<(u64, u64)>,
}

impl Cadre {
    pub(crate) fn simple(cible: Cible) -> Cadre {
        Cadre {
            cible,
            point_entree: None,
            sections: Vec::new(),
        }
    }
}

/// Le numéro d'un atome : sa place dans la recherche des octets tels quels, ou dans celle en minuscules (`::i`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Atome {
    minuscule: bool,
    numero: u32,
}

/// Une sous-signature gardée.
#[derive(Clone, Debug)]
struct Sous {
    /// La place de son hexadécimal dans `Corps::textes`.
    debut: u32,
    longueur: u32,
    decalage: Decalage,
    /// La borne de ses sauts sans fin (voir `OUVERTS`).
    ouvert: u32,
    modificateurs: Modificateurs,
    /// L'atome de la forme étroite, puis de la forme large (`::w`).
    atomes: [Option<Atome>; 2],
}

/// Une signature gardée.
#[derive(Clone, Debug)]
struct Sig {
    nom: u32,
    conditions: Conditions,
    /// Ses sous-signatures : `Corps::sous[sous..sous + n]`.
    sous: u32,
    n: u8,
    /// Son expression : `Corps::ops[ops..ops + n_ops]`.
    ops: u32,
    n_ops: u16,
}

/// Les signatures de contenu.
#[derive(Default)]
pub(crate) struct Corps {
    textes: String,
    noms: String,
    sous: Vec<Sous>,
    sigs: Vec<Sig>,
    ops: Vec<Op>,
    /// Pendant le chargement : chaque atome et son numéro.
    index: HashMap<(bool, Vec<u8>), u32>,
    atomes: [Vec<Vec<u8>>; 2],
    /// Après `finir` : la recherche des atomes tels quels, puis en minuscules.
    recherches: [Option<Recherche>; 2],
    /// `true` autant que d'atomes : « tous utiles » pour `Recherche::dans_tampon`.
    utiles: Vec<bool>,
}

/// La forme étroite et la forme large d'une sous-signature, en éléments.
type Formes = [Option<Vec<Element>>; 2];

/// Les formes d'une sous-signature, ses sauts sans fin bornés à `ouvert` ; et s'il y en a.
fn formes(hex: &str, ouvert: u32, m: Modificateurs) -> Result<(Formes, bool), NonLu> {
    let lu = ndb::lire_hex(hex, ouvert)?;
    let etroite = if m.sans_casse {
        ndb::sans_casse(&lu.elements)?
    } else {
        lu.elements
    };
    let formes = if m.large {
        let large = ndb::large(&etroite)?;
        [m.etroit_aussi.then_some(etroite), Some(large)]
    } else {
        [Some(etroite), None]
    };
    Ok((formes, lu.ouverts > 0))
}

fn raison(r: Refus) -> NonLu {
    match r {
        Refus::TropLong => NonLu::Bornes,
        Refus::SansAtome => NonLu::Forme,
        Refus::Vide | Refus::Saut | Refus::Choix => NonLu::Illisible,
    }
}

/// Les motifs d'une sous-signature, avec la borne de ses sauts sans fin, et si elle est approchée.
fn motifs(hex: &str, m: Modificateurs) -> Result<([Option<Motif>; 2], u32, bool), NonLu> {
    let mut derniere = NonLu::Illisible;
    for ouvert in OUVERTS {
        let (formes, approchee) = formes(hex, ouvert, m)?;
        let [etroite, large] = formes;
        let compiler = |f: Option<Vec<Element>>| f.map(Motif::nouveau).transpose();
        match (compiler(etroite), compiler(large)) {
            (Ok(e), Ok(l)) => return Ok(([e, l], ouvert, approchee)),
            (Err(r), _) | (_, Err(r)) => {
                derniere = raison(r);
                // Une borne plus étroite n'aide que les sauts sans fin.
                if !approchee || r != Refus::TropLong {
                    return Err(derniere);
                }
            }
        }
    }
    Err(derniere)
}

/// Le motif de la forme `f` d'une sous-signature déjà acceptée au chargement.
fn motif(hex: &str, s: &Sous, f: usize) -> Option<Motif> {
    let (formes, _) = formes(hex, s.ouvert, s.modificateurs).ok()?;
    let [etroite, large] = formes;
    let forme = if f == 0 { etroite } else { large };
    Motif::nouveau(forme?).ok()
}

/// La première place de début permise et l'étendue, pour un décalage ancré ; `None` : hors des données.
fn place(d: &Decalage, cadre: &Cadre, longueur: u64) -> Option<(u64, u64)> {
    let (debut, etendue) = match d.ancre {
        Ancre::Partout => return None,
        Ancre::Debut(n) => (n, d.etendue),
        Ancre::Fin(n) => (longueur.checked_sub(n)?, d.etendue),
        Ancre::PointEntree(n) => (cadre.point_entree?.checked_add_signed(n)?, d.etendue),
        Ancre::Section(x, n) => {
            let (pos, _) = *cadre.sections.get(usize::try_from(x).ok()?)?;
            (pos.checked_add(n)?, d.etendue)
        }
        Ancre::DerniereSection(n) => (cadre.sections.last()?.0.checked_add(n)?, d.etendue),
        Ancre::DansSection(x) => {
            let (pos, taille) = *cadre.sections.get(usize::try_from(x).ok()?)?;
            (pos, taille.checked_sub(1)?)
        }
    };
    (debut < longueur).then_some((debut, etendue))
}

/// Le motif commence-t-il à l'une des places permises par `d` ?
fn ancre_ici(m: &Motif, donnees: &[u8], d: &Decalage, cadre: &Cadre, echeance: Option<Instant>) -> Result<bool, Echec> {
    let longueur = u64::try_from(donnees.len()).map_err(|_| Echec::Lecture)?;
    let Some((debut, etendue)) = place(d, cadre, longueur) else {
        return Ok(false);
    };
    let fin = debut.saturating_add(etendue).min(longueur.saturating_sub(1));
    let fenetre = usize::try_from(m.longueur_max()).map_err(|_| Echec::Lecture)?;
    let (debut, fin) = (
        usize::try_from(debut).map_err(|_| Echec::Lecture)?,
        usize::try_from(fin).map_err(|_| Echec::Lecture)?,
    );
    for (k, p) in (debut..=fin).enumerate() {
        if k % POSITIONS_ENTRE_DELAIS == 0 && echeance.is_some_and(|e| Instant::now() >= e) {
            return Err(Echec::Delai);
        }
        let Some(ici) = donnees.get(p..p.saturating_add(fenetre).min(donnees.len())) else {
            break;
        };
        if m.commence_ici(ici) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn conditions_remplies(c: &Conditions, cadre: &Cadre, longueur: u64) -> bool {
    let dans =
        |b: Option<(u64, u64)>, v: Option<u64>| b.is_none_or(|(min, max)| v.is_some_and(|v| min <= v && v <= max));
    c.cible.vise(cadre.cible)
        && dans(c.taille, Some(longueur))
        && dans(c.point_entree, cadre.point_entree)
        && dans(c.sections, u64::try_from(cadre.sections.len()).ok())
}

impl Corps {
    pub(crate) fn nombre(&self) -> usize {
        self.sigs.len()
    }

    /// Le numéro de l'atome `a` (vue en minuscules ou non), ajouté s'il est neuf.
    fn atome(&mut self, minuscule: bool, a: &[u8]) -> Result<Atome, NonLu> {
        let cle = (minuscule, a.to_vec());
        if let Some(&numero) = self.index.get(&cle) {
            return Ok(Atome { minuscule, numero });
        }
        let liste = self.atomes.get_mut(usize::from(minuscule)).ok_or(NonLu::Bornes)?;
        let numero = u32::try_from(liste.len()).map_err(|_| NonLu::Bornes)?;
        liste.push(a.to_vec());
        self.index.insert(cle, numero);
        Ok(Atome { minuscule, numero })
    }

    /// Garde une signature : `Ok(true)` si l'un de ses sauts sans fin a été borné (approchée).
    fn garder(&mut self, nom: &str, conditions: Conditions, sous: &[ldb::Sous<'_>], ops: &[Op]) -> Result<bool, NonLu> {
        // Tout est contrôlé avant d'ajouter quoi que ce soit : une signature refusée ne laisse rien.
        let mut preparees = Vec::with_capacity(sous.len());
        let mut approchee = false;
        for s in sous {
            let (motifs, ouvert, a) = motifs(s.hex, s.modificateurs)?;
            approchee |= a;
            preparees.push((s, motifs, ouvert));
        }
        let place = |t: usize| u32::try_from(t).map_err(|_| NonLu::Bornes);
        let premiere = place(self.sous.len())?;
        let premiere_op = place(self.ops.len())?;
        let nom_debut = place(self.noms.len())?;
        place(self.noms.len().saturating_add(nom.len()).saturating_add(1))?;
        let mut textes = self.textes.len();
        for (s, _, _) in &preparees {
            textes = textes.saturating_add(s.hex.len());
        }
        place(textes)?;
        let n = u8::try_from(sous.len()).map_err(|_| NonLu::Bornes)?;
        let n_ops = u16::try_from(ops.len()).map_err(|_| NonLu::Bornes)?;
        for (s, motifs, ouvert) in preparees {
            let mut atomes = [None, None];
            for (atome, m) in atomes.iter_mut().zip(motifs) {
                if let Some(m) = m {
                    *atome = Some(self.atome(s.modificateurs.sans_casse, m.atome())?);
                }
            }
            let debut = place(self.textes.len())?;
            self.textes.push_str(s.hex);
            self.sous.push(Sous {
                debut,
                longueur: place(s.hex.len())?,
                decalage: s.decalage,
                ouvert,
                modificateurs: s.modificateurs,
                atomes,
            });
        }
        self.noms.push_str(nom);
        self.noms.push('\n');
        self.ops.extend_from_slice(ops);
        self.sigs.push(Sig {
            nom: nom_debut,
            conditions,
            sous: premiere,
            n,
            ops: premiere_op,
            n_ops,
        });
        Ok(approchee)
    }

    /// Ajoute une signature .ndb ; `Ok(true)` : approchée.
    pub(crate) fn ajouter_ndb(&mut self, l: &ndb::Ndb<'_>) -> Result<bool, NonLu> {
        let sous = ldb::Sous {
            decalage: l.decalage,
            hex: l.hex,
            modificateurs: Modificateurs::default(),
        };
        let conditions = Conditions {
            cible: l.cible,
            taille: None,
            point_entree: None,
            sections: None,
        };
        self.garder(l.nom, conditions, &[sous], &[Op::Sous(0)])
    }

    /// Ajoute une signature logique ; `Ok(true)` : approchée.
    pub(crate) fn ajouter_ldb(&mut self, l: &ldb::Ldb<'_>) -> Result<bool, NonLu> {
        self.garder(l.nom, l.conditions, &l.sous, &l.expression)
    }

    /// Prépare la recherche des atomes, une fois tout ajouté. `Err` : trop d'atomes pour l'automate (les signatures de
    /// contenu sont alors toutes inutilisables, ce que l'appelant compte).
    pub(crate) fn finir(&mut self) -> Result<(), NonLu> {
        self.index = HashMap::new();
        let mut plus_grand = 0usize;
        for (k, liste) in self.atomes.iter_mut().enumerate() {
            let liste = std::mem::take(liste);
            plus_grand = plus_grand.max(liste.len());
            let motifs = liste
                .into_iter()
                .map(|a| {
                    Motif::nouveau(
                        a.into_iter()
                            .map(|valeur| Element::Octet { valeur, masque: 0xFF })
                            .collect(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(raison)?;
            let r = if motifs.is_empty() {
                None
            } else {
                Some(Recherche::nouvelle(motifs).ok_or(NonLu::Bornes)?)
            };
            if let Some(place) = self.recherches.get_mut(k) {
                *place = r;
            }
        }
        self.utiles = vec![true; plus_grand];
        self.textes.shrink_to_fit();
        self.noms.shrink_to_fit();
        self.sous.shrink_to_fit();
        self.sigs.shrink_to_fit();
        self.ops.shrink_to_fit();
        Ok(())
    }

    /// Retire tout : ce qui reste après un `finir` refusé ne doit pas être cherché à moitié.
    pub(crate) fn vider(&mut self) {
        *self = Corps::default();
    }

    pub(crate) fn nom(&self, sig: u32) -> Option<&str> {
        let s = self.sigs.get(usize::try_from(sig).ok()?)?;
        self.noms.get(usize::try_from(s.nom).ok()?..)?.split('\n').next()
    }

    fn texte(&self, s: &Sous) -> Option<&str> {
        let debut = usize::try_from(s.debut).ok()?;
        self.textes
            .get(debut..debut.checked_add(usize::try_from(s.longueur).ok()?)?)
    }

    /// Les atomes présents dans `vues` (telles quelles, en minuscules).
    fn atomes_vus(&self, vues: [&[u8]; 2], echeance: Option<Instant>) -> Result<[Vec<bool>; 2], Echec> {
        let mut presents = [Vec::new(), Vec::new()];
        for ((presents, recherche), vue) in presents.iter_mut().zip(&self.recherches).zip(vues) {
            if let Some(r) = recherche {
                *presents = vec![false; r.motifs().len()];
                let utiles = self.utiles.get(..r.motifs().len()).ok_or(Echec::Lecture)?;
                r.dans_tampon(vue, presents, utiles, echeance)?;
            }
        }
        Ok(presents)
    }

    /// Les signatures (leur numéro, pour `nom`) présentes dans `donnees`, une partie de sorte et de structure `cadre`.
    pub(crate) fn examiner(&self, donnees: &[u8], cadre: &Cadre, echeance: Option<Instant>) -> Result<Vec<u32>, Echec> {
        if self.sigs.is_empty() {
            return Ok(Vec::new());
        }
        let longueur = u64::try_from(donnees.len()).map_err(|_| Echec::Lecture)?;
        let minuscules: Vec<u8> = if self.recherches[1].is_some() {
            donnees.to_ascii_lowercase()
        } else {
            Vec::new()
        };
        let vues: [&[u8]; 2] = [donnees, &minuscules];
        let atomes = self.atomes_vus(vues, echeance)?;
        let vu = |a: &Option<Atome>| {
            a.is_some_and(|a| {
                atomes
                    .get(usize::from(a.minuscule))
                    .and_then(|v| v.get(usize::try_from(a.numero).ok()?))
                    .copied()
                    .unwrap_or(false)
            })
        };
        // Premier temps : les signatures que les atomes n'écartent pas.
        let mut candidates: Vec<(u32, &Sig)> = Vec::new();
        for (k, sig) in self.sigs.iter().enumerate() {
            if !conditions_remplies(&sig.conditions, cadre, longueur) {
                continue;
            }
            let (sous, ops) = self.parts(sig).ok_or(Echec::Lecture)?;
            let etat = |i: u8| {
                if sous.get(usize::from(i)).is_some_and(|s| s.atomes.iter().any(vu)) {
                    Etat::Inconnue
                } else {
                    Etat::Absente
                }
            };
            if ldb::juger(ops, etat).ok_or(Echec::Lecture)? != Etat::Absente {
                candidates.push((u32::try_from(k).map_err(|_| Echec::Lecture)?, sig));
            }
        }
        // Second temps : les sous-signatures de ces signatures, cherchées pour de bon. Celles qui flottent (`*`) le
        // sont toutes ensemble, une recherche par vue ; les ancrées, chacune à sa place.
        let mut presentes: HashMap<u32, bool> = HashMap::new();
        let mut flottants: [Vec<(u32, Motif)>; 2] = [Vec::new(), Vec::new()];
        for (_, sig) in &candidates {
            let (sous, _) = self.parts(sig).ok_or(Echec::Lecture)?;
            for (i, s) in (sig.sous..).zip(sous) {
                if presentes.contains_key(&i) {
                    continue;
                }
                presentes.insert(i, false);
                let hex = self.texte(s).ok_or(Echec::Lecture)?;
                for (f, atome) in s.atomes.iter().enumerate() {
                    if !vu(atome) {
                        continue;
                    }
                    let m = motif(hex, s, f).ok_or(Echec::Lecture)?;
                    let vue = usize::from(s.modificateurs.sans_casse);
                    if s.decalage.ancre == Ancre::Partout {
                        if let Some(liste) = flottants.get_mut(vue) {
                            liste.push((i, m));
                        }
                    } else if ancre_ici(&m, vues.get(vue).ok_or(Echec::Lecture)?, &s.decalage, cadre, echeance)? {
                        presentes.insert(i, true);
                    }
                }
            }
        }
        for (liste, vue) in flottants.into_iter().zip(vues) {
            if liste.is_empty() {
                continue;
            }
            let (proprietaires, motifs): (Vec<u32>, Vec<Motif>) = liste.into_iter().unzip();
            let r = Recherche::nouvelle(motifs).ok_or(Echec::Lecture)?;
            let mut trouves = vec![false; proprietaires.len()];
            let utiles = vec![true; proprietaires.len()];
            r.dans_tampon(vue, &mut trouves, &utiles, echeance)?;
            for (i, v) in proprietaires.into_iter().zip(trouves) {
                if v {
                    presentes.insert(i, true);
                }
            }
        }
        let mut trouvees = Vec::new();
        for (k, sig) in candidates {
            let (_, ops) = self.parts(sig).ok_or(Echec::Lecture)?;
            let etat = |i: u8| match sig.sous.checked_add(u32::from(i)).and_then(|g| presentes.get(&g)) {
                Some(true) => Etat::Presente,
                _ => Etat::Absente,
            };
            if ldb::juger(ops, etat).ok_or(Echec::Lecture)? == Etat::Presente {
                trouvees.push(k);
            }
        }
        Ok(trouvees)
    }

    fn parts(&self, sig: &Sig) -> Option<(&[Sous], &[Op])> {
        let s = usize::try_from(sig.sous).ok()?;
        let o = usize::try_from(sig.ops).ok()?;
        Some((
            self.sous.get(s..s.checked_add(usize::from(sig.n))?)?,
            self.ops.get(o..o.checked_add(usize::from(sig.n_ops))?)?,
        ))
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protection::clamav::commun::hex;

    fn corps(ndb: &[&str], ldb: &[&str]) -> Corps {
        let mut c = Corps::default();
        for l in ndb {
            c.ajouter_ndb(&ndb::lire_ligne(l).unwrap()).unwrap();
        }
        for l in ldb {
            c.ajouter_ldb(&ldb::lire_ligne(l).unwrap()).unwrap();
        }
        c.finir().unwrap();
        c
    }

    fn noms(c: &Corps, donnees: &[u8], cadre: &Cadre) -> Vec<String> {
        c.examiner(donnees, cadre, None)
            .unwrap()
            .into_iter()
            .map(|k| c.nom(k).unwrap().to_string())
            .collect()
    }

    #[test]
    fn signatures_ndb() {
        let c = corps(
            &[
                &format!("Essai.Flottante:0:*:{}", hex(b"vanguard-essai")),
                &format!("Essai.Joker:0:*:{}??{}", hex(b"debut"), hex(b"fin")),
                &format!("Essai.Etoile:0:*:{}*{}", hex(b"alpha"), hex(b"omega")),
                &format!("Essai.Debut:0:0:{}", hex(b"#!")),
                &format!("Essai.Fin:0:EOF-3:{}", hex(b"END")),
                &format!("Essai.Pe:1:*:{}", hex(b"vanguard-essai")),
            ],
            &[],
        );
        let tout = Cadre::simple(Cible::Tout);
        assert_eq!(noms(&c, b"xx vanguard-essai yy", &tout), ["Essai.Flottante"]);
        assert_eq!(
            noms(&c, b"xx vanguard-essai yy", &Cadre::simple(Cible::Pe)),
            ["Essai.Flottante", "Essai.Pe"]
        );
        assert_eq!(noms(&c, b"debut-fin", &tout), ["Essai.Joker"]);
        assert_eq!(noms(&c, b"debutfin", &tout), [] as [String; 0]);
        let mut loin = b"alpha".to_vec();
        loin.extend(vec![b'.'; 10_000]);
        loin.extend(b"omega");
        assert_eq!(noms(&c, &loin, &tout), ["Essai.Etoile"]);
        assert_eq!(noms(&c, b"#!/bin/sh END", &tout), ["Essai.Debut", "Essai.Fin"]);
        assert_eq!(noms(&c, b" #!/bin/sh END ", &tout), [] as [String; 0]);
        assert_eq!(noms(&c, b"", &tout), [] as [String; 0]);
    }

    #[test]
    fn decalages_de_programme() {
        let c = corps(
            &[
                &format!("Essai.Ep:1:EP+2:{}", hex(b"code")),
                &format!("Essai.EpEtendue:1:EP-4,8:{}", hex(b"autre")),
                &format!("Essai.Section:1:S1+0:{}", hex(b"sect")),
                &format!("Essai.Derniere:1:SL+1:{}", hex(b"last")),
                &format!("Essai.Dans:1:SE0:{}", hex(b"dans")),
            ],
            &[],
        );
        let mut d = vec![b'.'; 100];
        d[12..16].copy_from_slice(b"code");
        d[6..11].copy_from_slice(b"autre");
        d[40..44].copy_from_slice(b"sect");
        d[61..65].copy_from_slice(b"last");
        d[25..29].copy_from_slice(b"dans");
        let cadre = Cadre {
            cible: Cible::Pe,
            point_entree: Some(10),
            sections: vec![(20, 20), (40, 20), (60, 40)],
        };
        assert_eq!(
            noms(&c, &d, &cadre),
            [
                "Essai.Ep",
                "Essai.EpEtendue",
                "Essai.Section",
                "Essai.Derniere",
                "Essai.Dans"
            ]
        );
        // Sans structure de programme, les ancres de programme ne trouvent rien.
        assert_eq!(noms(&c, &d, &Cadre::simple(Cible::Pe)), [] as [String; 0]);
        // Le point d'entrée à 2 : « code » n'est pas à 4, et EP-4 tomberait avant le début.
        let ailleurs = Cadre {
            point_entree: Some(2),
            ..cadre.clone()
        };
        assert_eq!(
            noms(&c, &d, &ailleurs),
            ["Essai.Section", "Essai.Derniere", "Essai.Dans"]
        );
    }

    #[test]
    fn signatures_logiques() {
        let c = corps(
            &[],
            &[
                &format!(
                    "Essai.Et;Engine:51-255,Target:0;0&1;{};{}",
                    hex(b"premier"),
                    hex(b"second")
                ),
                &format!("Essai.Sans;Target:0;0&1=0;{};{}", hex(b"premier"), hex(b"interdit")),
                &format!("Essai.Casse;Target:0;0;{}::i", hex(b"majuscule")),
                &format!("Essai.Large;Target:0;0;{}::w", hex(b"large")),
                &format!(
                    "Essai.Deux;Target:0;(0|1|2)>0,2;{};{};{}",
                    hex(b"un"),
                    hex(b"deux"),
                    hex(b"trois")
                ),
                &format!("Essai.Taille;Target:0,FileSize:0-10;0;{}", hex(b"petit")),
            ],
        );
        let tout = Cadre::simple(Cible::Tout);
        assert_eq!(noms(&c, b"premier ... second", &tout), ["Essai.Et", "Essai.Sans"]);
        assert_eq!(noms(&c, b"premier", &tout), ["Essai.Sans"]);
        assert_eq!(noms(&c, b"premier interdit", &tout), [] as [String; 0]);
        assert_eq!(noms(&c, b"une MaJuScUlE ici", &tout), ["Essai.Casse"]);
        assert_eq!(noms(&c, b"l\0a\0r\0g\0e\0", &tout), ["Essai.Large"]);
        assert_eq!(noms(&c, b"large", &tout), [] as [String; 0]);
        assert_eq!(noms(&c, b"un trois", &tout), ["Essai.Deux"]);
        assert_eq!(noms(&c, b"un un", &tout), [] as [String; 0]);
        assert_eq!(noms(&c, b"petit", &tout), ["Essai.Taille"]);
        assert_eq!(noms(&c, b"petit et long", &tout), [] as [String; 0]);
    }

    #[test]
    fn refus_sans_trace() {
        let mut c = Corps::default();
        // La deuxième sous-signature est refusée : la première ne doit rien laisser.
        let l = ldb::lire_ligne("Essai;Target:0;0&1;61626364;??").unwrap();
        assert_eq!(c.ajouter_ldb(&l), Err(NonLu::Forme));
        assert!(c.sous.is_empty() && c.textes.is_empty() && c.index.is_empty());
        let l = ndb::lire_ligne("Essai:0:*:aa{70000}bb").unwrap();
        assert_eq!(c.ajouter_ndb(&l), Err(NonLu::Bornes));
        // Un saut sans fin trop large pour le coût : borné plus court, la signature est gardée et dite approchée.
        let long = "61".repeat(2000);
        let ligne = format!("Essai.Long:0:*:{long}*{long}");
        let l = ndb::lire_ligne(&ligne).unwrap();
        assert_eq!(c.ajouter_ndb(&l), Ok(true));
        c.finir().unwrap();
        assert_eq!(c.nombre(), 1);
    }

    #[test]
    fn delai_passe() {
        let c = corps(&[&format!("Essai:0:*:{}", hex(b"abc"))], &[]);
        let passe = Instant::now();
        assert_eq!(
            c.examiner(&vec![b'a'; 4 << 20], &Cadre::simple(Cible::Tout), Some(passe)),
            Err(Echec::Delai)
        );
    }
}
