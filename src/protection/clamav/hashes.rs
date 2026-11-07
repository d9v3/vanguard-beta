//! Les signatures d'empreinte de ClamAV : fichier entier (.hdb en MD5, .hsb en SHA-1 ou SHA-256 : `empreinte:taille:nom`)
//! et sections de programme Windows (.mdb en MD5, .msb : `taille:empreinte:nom`), avec le niveau de moteur facultatif
//! en fin de ligne (`:min[:max]`). La sorte d'empreinte se lit à sa longueur (32, 40 ou 64 chiffres), comme ClamAV ;
//! une taille `*` (n'importe laquelle) n'est permise qu'avec un niveau minimum d'au moins 73 (règle de `cli_loadhash`).
//! Les listes blanches (.fp, .sfp) ont la forme des .hdb : la même table les garde.
//!
//! La table est faite pour des millions de lignes (main.mdb en a 2,7 millions) : des tableaux triés d'entrées de
//! taille fixe, recherche dichotomique, et les noms dans un seul texte.
//!
//! Module pur, sans `crate::` : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use super::commun::{NonLu, hex_fixe, niveau_permis};

/// Une taille quelconque (`*`).
const TOUTE_TAILLE: u32 = u32::MAX;
/// Le niveau minimum exigé d'une signature à taille `*`.
const NIVEAU_TOUTE_TAILLE: u32 = 73;

/// Une empreinte lue dans la base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Empreinte {
    Md5([u8; 16]),
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}

impl Empreinte {
    fn lire(texte: &str) -> Option<Empreinte> {
        match texte.len() {
            32 => hex_fixe(texte).map(Empreinte::Md5),
            40 => hex_fixe(texte).map(Empreinte::Sha1),
            64 => hex_fixe(texte).map(Empreinte::Sha256),
            _ => None,
        }
    }
}

/// Une ligne lue : l'empreinte, la taille (`None` : `*`) et le nom de la signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ligne<'a> {
    pub empreinte: Empreinte,
    pub taille: Option<u32>,
    pub nom: &'a str,
}

/// Lit une ligne de fichier entier (`section` faux : `empreinte:taille:nom…`) ou de section (`taille:empreinte:nom…`).
/// `Err` : la raison de ne pas l'appliquer (illisible, ou prévue pour un autre niveau du moteur).
pub(crate) fn lire_ligne(ligne: &str, section: bool) -> Result<Ligne<'_>, NonLu> {
    let mut champs = ligne.split(':');
    let (Some(a), Some(b), Some(nom)) = (champs.next(), champs.next(), champs.next()) else {
        return Err(NonLu::Illisible);
    };
    let (min, max) = (champs.next(), champs.next());
    if champs.next().is_some() || nom.is_empty() {
        return Err(NonLu::Illisible);
    }
    let (empreinte, taille) = if section { (b, a) } else { (a, b) };
    let empreinte = Empreinte::lire(empreinte).ok_or(NonLu::Illisible)?;
    let taille = match taille {
        "*" => {
            let min: u32 = min.and_then(|m| m.parse().ok()).ok_or(NonLu::Illisible)?;
            if min < NIVEAU_TOUTE_TAILLE {
                return Err(NonLu::Illisible);
            }
            None
        }
        t => {
            // Que des chiffres : ni signe ni espace.
            if t.is_empty() || !t.bytes().all(|o| o.is_ascii_digit()) {
                return Err(NonLu::Illisible);
            }
            let t: u32 = t.parse().map_err(|_| NonLu::Illisible)?;
            if t == TOUTE_TAILLE {
                return Err(NonLu::Illisible);
            }
            Some(t)
        }
    };
    if !niveau_permis(min, max).ok_or(NonLu::Illisible)? {
        return Err(NonLu::Niveau);
    }
    Ok(Ligne { empreinte, taille, nom })
}

/// Une entrée de table : l'empreinte, la taille (`TOUTE_TAILLE` : `*`) et la place du nom dans `Table::noms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Entree<const N: usize> {
    empreinte: [u8; N],
    taille: u32,
    nom: u32,
}

/// Les empreintes d'un contenu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Empreintes {
    pub md5: [u8; 16],
    pub sha1: [u8; 20],
    pub sha256: [u8; 32],
}

impl Empreintes {
    pub(crate) fn de(octets: &[u8]) -> Empreintes {
        use sha2::Digest;
        Empreintes {
            md5: md5::Md5::digest(octets).into(),
            sha1: sha1::Sha1::digest(octets).into(),
            sha256: sha2::Sha256::digest(octets).into(),
        }
    }
}

/// Une table d'empreintes : à remplir (`ajouter`), puis à trier une fois (`finir`) avant de chercher.
#[derive(Debug, Default)]
pub(crate) struct Table {
    md5: Vec<Entree<16>>,
    sha1: Vec<Entree<20>>,
    sha256: Vec<Entree<32>>,
    /// Les noms, chacun suivi d'un saut de ligne (un nom n'en contient jamais : il vient d'une ligne).
    noms: String,
}

/// Les entrées d'empreinte `e` et de taille `taille` ou `*`, dans `t` triée.
fn trouver<const N: usize>(t: &[Entree<N>], e: &[u8; N], taille: u64) -> Option<u32> {
    let debut = t.partition_point(|x| x.empreinte < *e);
    t.get(debut..)?
        .iter()
        .take_while(|x| x.empreinte == *e)
        .find(|x| x.taille == TOUTE_TAILLE || u64::from(x.taille) == taille)
        .map(|x| x.nom)
}

impl Table {
    /// Ajoute une ligne lue. `Err(Bornes)` : les noms ne tiennent plus en 4 Gio.
    pub(crate) fn ajouter(&mut self, l: &Ligne<'_>) -> Result<(), NonLu> {
        let nom = u32::try_from(self.noms.len()).map_err(|_| NonLu::Bornes)?;
        if u32::try_from(self.noms.len().saturating_add(l.nom.len()).saturating_add(1)).is_err() {
            return Err(NonLu::Bornes);
        }
        // Un nom n'a pas de saut de ligne (il vient d'une ligne) : le séparateur reste sûr.
        self.noms.push_str(l.nom);
        self.noms.push('\n');
        let taille = l.taille.unwrap_or(TOUTE_TAILLE);
        match l.empreinte {
            Empreinte::Md5(empreinte) => self.md5.push(Entree { empreinte, taille, nom }),
            Empreinte::Sha1(empreinte) => self.sha1.push(Entree { empreinte, taille, nom }),
            Empreinte::Sha256(empreinte) => self.sha256.push(Entree { empreinte, taille, nom }),
        }
        Ok(())
    }

    /// Trie les tables : à faire une fois tout ajouté, avant de chercher.
    pub(crate) fn finir(&mut self) {
        self.md5.sort_unstable();
        self.sha1.sort_unstable();
        self.sha256.sort_unstable();
        self.md5.shrink_to_fit();
        self.sha1.shrink_to_fit();
        self.sha256.shrink_to_fit();
        self.noms.shrink_to_fit();
    }

    pub(crate) fn nombre(&self) -> usize {
        self.md5
            .len()
            .saturating_add(self.sha1.len())
            .saturating_add(self.sha256.len())
    }

    pub(crate) fn est_vide(&self) -> bool {
        self.nombre() == 0
    }

    fn nom(&self, debut: u32) -> Option<&str> {
        self.noms.get(usize::try_from(debut).ok()?..)?.split('\n').next()
    }

    /// Le nom de la signature d'un contenu de `taille` octets et d'empreintes `e`, s'il y en a une.
    pub(crate) fn chercher(&self, e: &Empreintes, taille: u64) -> Option<&str> {
        let nom = trouver(&self.md5, &e.md5, taille)
            .or_else(|| trouver(&self.sha1, &e.sha1, taille))
            .or_else(|| trouver(&self.sha256, &e.sha256, taille))?;
        self.nom(nom)
    }

    /// Le nom de la signature SHA-256 `e`, quelle que soit la taille (une collision de SHA-256 n'existe pas en
    /// pratique : la taille ne départage rien).
    pub(crate) fn chercher_sha256(&self, e: &[u8; 32]) -> Option<&str> {
        let debut = self.sha256.partition_point(|x| x.empreinte < *e);
        let x = self.sha256.get(debut)?;
        (x.empreinte == *e).then(|| self.nom(x.nom)).flatten()
    }

    /// Les SHA-256, triés, sans doublon.
    pub(crate) fn sha256_tries(&self) -> Vec<[u8; 32]> {
        let mut v: Vec<[u8; 32]> = self.sha256.iter().map(|x| x.empreinte).collect();
        v.dedup();
        v
    }

    /// Les MD5 et leur taille (`None` : `*`), triés, sans doublon.
    pub(crate) fn md5_et_tailles(&self) -> Vec<([u8; 16], Option<u32>)> {
        let mut v: Vec<([u8; 16], Option<u32>)> = self
            .md5
            .iter()
            .map(|x| (x.empreinte, (x.taille != TOUTE_TAILLE).then_some(x.taille)))
            .collect();
        v.dedup();
        v
    }
}

/// Une liste binaire de SHA-256 (32 octets chacun, triés, sans doublon), produite par le compte de la personne depuis
/// la base (`Signatures::liste_sha256`) : ce qu'un programme en administrateur peut lire sans analyser aucun format
/// (P22, remarque 16 de l'étude). Une liste mal formée (longueur, ordre) est refusée entière.
#[derive(Debug)]
pub(crate) struct ListeSha256(Vec<u8>);

impl ListeSha256 {
    pub(crate) fn lire(octets: Vec<u8>) -> Option<ListeSha256> {
        let (empreintes, reste) = octets.as_chunks::<32>();
        if !reste.is_empty() || !empreintes.is_sorted_by(|a, b| a < b) {
            return None;
        }
        Some(ListeSha256(octets))
    }

    pub(crate) fn nombre(&self) -> usize {
        self.0.as_chunks::<32>().0.len()
    }

    pub(crate) fn contient(&self, e: &[u8; 32]) -> bool {
        self.0.as_chunks::<32>().0.binary_search(e).is_ok()
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

    #[test]
    fn lignes_de_fichier_et_de_section() {
        let e = Empreintes::de(b"contenu invente");
        let l = format!("{}:15:Essai.Md5-1", hex(&e.md5));
        assert_eq!(
            lire_ligne(&l, false),
            Ok(Ligne {
                empreinte: Empreinte::Md5(e.md5),
                taille: Some(15),
                nom: "Essai.Md5-1"
            })
        );
        let l = format!("15:{}:Essai.Section-1:73", hex(&e.sha256));
        assert_eq!(lire_ligne(&l, true).unwrap().empreinte, Empreinte::Sha256(e.sha256));
        let l = format!("{}:*:Essai.Toute-1:73", hex(&e.sha1));
        assert_eq!(lire_ligne(&l, false).unwrap().taille, None);
    }

    #[test]
    fn lignes_refusees() {
        let m = "0123456789abcdef0123456789abcdef";
        for (l, raison) in [
            (format!("{m}:*:Sans.Niveau"), NonLu::Illisible),
            (format!("{m}:*:Niveau.Bas:72"), NonLu::Illisible),
            (format!("{m}:+15:Signe"), NonLu::Illisible),
            (format!("{m}: 15:Espace"), NonLu::Illisible),
            (format!("{m}:4294967295:Taille.Reservee"), NonLu::Illisible),
            (format!("{m}:99999999999:Trop.Grande"), NonLu::Illisible),
            (format!("{m}:15:"), NonLu::Illisible),
            (format!("{m}:15"), NonLu::Illisible),
            (format!("{m}:15:Nom:1:2:3"), NonLu::Illisible),
            (format!("{m}0:15:Longueur"), NonLu::Illisible),
            (format!("{m}:15:Futur:235"), NonLu::Niveau),
            (format!("{m}:15:Ancien:1:100"), NonLu::Niveau),
            (format!("{m}:15:Niveau.Faux:x"), NonLu::Illisible),
        ] {
            assert_eq!(lire_ligne(&l, false), Err(raison), "{l}");
        }
    }

    #[test]
    fn recherche_par_empreinte_et_taille() {
        let a = Empreintes::de(b"premier contenu");
        let b = Empreintes::de(b"second contenu");
        let c = Empreintes::de(b"troisieme");
        let mut t = Table::default();
        for l in [
            format!("{}:15:Essai.A-1", hex(&a.md5)),
            format!("{}:99:Essai.A-Autre-Taille", hex(&a.md5)),
            format!("{}:*:Essai.B-1:73", hex(&b.sha1)),
            format!("{}:9:Essai.C-1", hex(&c.sha256)),
        ] {
            t.ajouter(&lire_ligne(&l, false).unwrap()).unwrap();
        }
        t.finir();
        assert_eq!(t.nombre(), 4);
        assert_eq!(t.chercher(&a, 15), Some("Essai.A-1"));
        assert_eq!(t.chercher(&a, 99), Some("Essai.A-Autre-Taille"));
        assert_eq!(t.chercher(&a, 16), None);
        assert_eq!(t.chercher(&b, 123_456), Some("Essai.B-1"));
        assert_eq!(t.chercher(&c, 9), Some("Essai.C-1"));
        assert_eq!(t.chercher(&c, 10), None);
        assert_eq!(t.chercher_sha256(&c.sha256), Some("Essai.C-1"));
        assert_eq!(t.chercher_sha256(&a.sha256), None);
        assert_eq!(t.sha256_tries(), vec![c.sha256]);
        let mut md5 = vec![(a.md5, Some(15)), (a.md5, Some(99))];
        md5.sort_unstable();
        assert_eq!(t.md5_et_tailles(), md5);
        assert!(Table::default().est_vide());
    }

    #[test]
    fn liste_binaire() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let l = ListeSha256::lire([a, b].concat()).unwrap();
        assert_eq!(l.nombre(), 2);
        assert!(l.contient(&a) && l.contient(&b) && !l.contient(&[3; 32]));
        assert!(ListeSha256::lire([b, a].concat()).is_none());
        assert!(ListeSha256::lire([a, a].concat()).is_none());
        assert!(ListeSha256::lire(vec![0; 33]).is_none());
        assert_eq!(ListeSha256::lire(Vec::new()).unwrap().nombre(), 0);
    }
}
