//! Les signatures d'une base ClamAV assemblées depuis ses fichiers (membres des .cvd/.cld ou fichiers à part), et le
//! jugement d'un contenu : liste blanche d'abord, puis empreintes du contenu entier, des sections de programme
//! Windows, et signatures de contenu. Chaque ligne non appliquée est comptée par raison (`commun::Comptes`).
//!
//! Deux modes (P21) : la base complète, chargée à la demande ; les empreintes seules (fichiers entiers, listes
//! blanches, ignorées), assez légères pour une veille continue.
//!
//! Module pur, sans données de la machine : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::time::Instant;

use super::commun::{Cible, Comptes, NonLu, lignes};
use super::corps::{Cadre, Corps};
use super::fp::Ignorees;
use super::hashes::{self, Empreintes, Table};
use super::{ldb, ndb};
use crate::protection::motifs::Echec;

/// Les noms rendus pour une partie, au plus.
const NOMS_MAX: usize = 8;

/// Ce qui est chargé.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    /// Tout ce que Vanguard sait appliquer : à la demande.
    Complete,
    /// Les empreintes de fichiers entiers seules : en continu.
    Empreintes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Options {
    pub mode: Mode,
    /// Les programmes potentiellement indésirables (PUA) aussi : non par défaut, comme clamscan.
    pub pua: bool,
}

/// La sorte d'un fichier de signatures, d'après son extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sorte {
    /// .hdb, .hsb (fichiers entiers).
    Fichier,
    /// .mdb, .msb (sections de programme Windows).
    Section,
    /// .ndb.
    Ndb,
    /// .ldb.
    Ldb,
    /// .fp, .sfp (listes blanches).
    Blanche,
    /// .ign, .ign2.
    Ignoree,
    /// Une sorte que Vanguard ne lit pas, comptée.
    NonLue(NonLu),
    /// Pas des signatures (licence, liste .info, différences .cdiff, signatures .sign…).
    Autre,
}

/// La sorte d'un fichier, et s'il porte des PUA (.hdu, .ndu…).
fn sorte(nom: &str) -> (Sorte, bool) {
    let Some((_, extension)) = nom.rsplit_once('.') else {
        return (Sorte::Autre, false);
    };
    match extension {
        "hdb" | "hsb" => (Sorte::Fichier, false),
        "hdu" | "hsu" => (Sorte::Fichier, true),
        "mdb" | "msb" => (Sorte::Section, false),
        "mdu" | "msu" => (Sorte::Section, true),
        "ndb" => (Sorte::Ndb, false),
        "ndu" => (Sorte::Ndb, true),
        "ldb" => (Sorte::Ldb, false),
        "ldu" => (Sorte::Ldb, true),
        "fp" | "sfp" => (Sorte::Blanche, false),
        "ign" | "ign2" => (Sorte::Ignoree, false),
        "cbc" => (Sorte::NonLue(NonLu::Bytecode), false),
        "cdb" | "zmd" | "rmd" => (Sorte::NonLue(NonLu::Conteneurs), false),
        "pdb" | "gdb" | "wdb" => (Sorte::NonLue(NonLu::Hameconnage), false),
        "yar" | "yara" => (Sorte::NonLue(NonLu::Yara), false),
        "idb" | "crb" | "cat" | "imp" | "ftm" | "cfg" | "ndbx" | "ldbx" => (Sorte::NonLue(NonLu::AutreFormat), false),
        _ => (Sorte::Autre, false),
    }
}

/// Un fichier que le chargement lit (signatures, listes, ou sorte non appliquée mais comptée) ; les autres (licence,
/// liste .info, différences .cdiff, signatures .sign, état de freshclam) ne sont pas ouverts.
pub(crate) fn a_lire(nom: &str) -> bool {
    sorte(nom).0 != Sorte::Autre
}

/// Un fichier qui n'apporte que des signatures (ni liste blanche ni signatures ignorées) : sans lui, la base trouve
/// moins, jamais plus.
pub(crate) fn sans_exception(nom: &str) -> bool {
    matches!(
        sorte(nom).0,
        Sorte::Fichier | Sorte::Section | Sorte::Ndb | Sorte::Ldb | Sorte::NonLue(_)
    )
}

/// Le nom de signature d'une ligne, sans la lire toute : pour juger tôt une signature ignorée ou PUA.
fn nom_de(sorte: Sorte, ligne: &str) -> Option<&str> {
    match sorte {
        Sorte::Fichier | Sorte::Section => ligne.split(':').nth(2),
        Sorte::Ndb => ligne.split(':').next(),
        Sorte::Ldb => ligne.split(';').next(),
        _ => None,
    }
}

/// Ce qu'un contenu a donné.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Dans une liste blanche de la base : rien n'y est cherché.
    Blanche,
    /// Les signatures trouvées (vide : aucune).
    Trouvees(Vec<String>),
}

/// Les signatures chargées.
#[derive(Default)]
pub(crate) struct Signatures {
    fichiers: Table,
    sections: Table,
    blanches: Table,
    corps: Corps,
    ignorees: Ignorees,
    pub comptes: Comptes,
}

/// Une base en cours de chargement : les listes d'ignorées d'abord (`ignorer`, sur tous les fichiers), puis les
/// signatures (`ajouter`), puis `finir`.
pub(crate) struct Chargement {
    s: Signatures,
    options: Options,
}

impl Chargement {
    pub(crate) fn nouveau(options: Options) -> Chargement {
        Chargement {
            s: Signatures::default(),
            options,
        }
    }

    /// Lit `contenu` s'il est une liste d'ignorées (.ign, .ign2).
    pub(crate) fn ignorer(&mut self, nom: &str, contenu: &[u8]) {
        if sorte(nom).0 == Sorte::Ignoree {
            let illisibles = self.s.ignorees.lire(contenu);
            self.s.comptes.ajouter(NonLu::Illisible, illisibles);
        }
    }

    /// Lit les signatures du fichier `nom`.
    pub(crate) fn ajouter(&mut self, nom: &str, contenu: &[u8]) {
        let (sorte, pua) = sorte(nom);
        let compter = |c: &mut Comptes, raison| c.ajouter(raison, lignes(contenu).count());
        match sorte {
            Sorte::Autre | Sorte::Ignoree => return,
            Sorte::NonLue(raison) => return compter(&mut self.s.comptes, raison),
            _ if pua && !self.options.pua => return compter(&mut self.s.comptes, NonLu::Pua),
            Sorte::Section | Sorte::Ndb | Sorte::Ldb if self.options.mode == Mode::Empreintes => {
                return compter(&mut self.s.comptes, NonLu::Mode);
            }
            _ => {}
        }
        for ligne in lignes(contenu) {
            if let Err(raison) = self.ligne(sorte, ligne) {
                self.s.comptes.un(raison);
            }
        }
    }

    fn ligne(&mut self, sorte: Sorte, ligne: Result<&str, ()>) -> Result<(), NonLu> {
        let ligne = ligne.map_err(|()| NonLu::Illisible)?;
        if let Some(nom) = nom_de(sorte, ligne) {
            if !self.options.pua && nom.starts_with("PUA.") {
                return Err(NonLu::Pua);
            }
            if self.s.ignorees.ignore(nom, ligne) {
                return Err(NonLu::Ignoree);
            }
        }
        let s = &mut self.s;
        match sorte {
            Sorte::Fichier => s.fichiers.ajouter(&hashes::lire_ligne(ligne, false)?),
            Sorte::Section => s.sections.ajouter(&hashes::lire_ligne(ligne, true)?),
            Sorte::Blanche => s.blanches.ajouter(&hashes::lire_ligne(ligne, false)?),
            Sorte::Ndb => {
                if s.corps.ajouter_ndb(&ndb::lire_ligne(ligne)?)? {
                    s.comptes.approchees = s.comptes.approchees.saturating_add(1);
                }
                Ok(())
            }
            Sorte::Ldb => {
                if s.corps.ajouter_ldb(&ldb::lire_ligne(ligne)?)? {
                    s.comptes.approchees = s.comptes.approchees.saturating_add(1);
                }
                Ok(())
            }
            Sorte::Ignoree | Sorte::NonLue(_) | Sorte::Autre => Ok(()),
        }
    }

    pub(crate) fn finir(self) -> Signatures {
        let mut s = self.s;
        s.fichiers.finir();
        s.sections.finir();
        s.blanches.finir();
        if let Err(raison) = s.corps.finir() {
            s.comptes.ajouter(raison, s.corps.nombre());
            s.corps.vider();
        }
        s
    }
}

impl Signatures {
    /// Les signatures appliquées.
    pub(crate) fn nombre(&self) -> usize {
        self.fichiers
            .nombre()
            .saturating_add(self.sections.nombre())
            .saturating_add(self.corps.nombre())
    }

    /// Les signatures de fichier entier, et les entrées de liste blanche.
    pub(crate) fn empreintes(&self) -> (usize, usize) {
        (self.fichiers.nombre(), self.blanches.nombre())
    }

    /// Juge un contenu : `cadre` dit sa sorte et, pour un programme, son point d'entrée et ses sections (place et
    /// taille dans `octets`). `Err` : pas fini avant `echeance`, rien n'est conclu.
    pub(crate) fn juger(&self, octets: &[u8], cadre: &Cadre, echeance: Option<Instant>) -> Result<Verdict, Echec> {
        let taille = u64::try_from(octets.len()).map_err(|_| Echec::Lecture)?;
        let e = Empreintes::de(octets);
        if self.blanches.chercher(&e, taille).is_some() {
            return Ok(Verdict::Blanche);
        }
        let mut noms: Vec<String> = Vec::new();
        if let Some(n) = self.fichiers.chercher(&e, taille) {
            noms.push(n.to_string());
        }
        if cadre.cible == Cible::Pe && !self.sections.est_vide() {
            for &(position, longueur) in &cadre.sections {
                if echeance.is_some_and(|e| Instant::now() >= e) {
                    return Err(Echec::Delai);
                }
                let debut = usize::try_from(position).map_err(|_| Echec::Lecture)?;
                let fin = debut.saturating_add(usize::try_from(longueur).map_err(|_| Echec::Lecture)?);
                // Une section qui sort du fichier n'a pas d'empreinte sûre : sautée, comme ClamAV.
                let Some(section) = octets.get(debut..fin) else {
                    continue;
                };
                if let Some(n) = self.sections.chercher(&Empreintes::de(section), longueur) {
                    noms.push(n.to_string());
                }
            }
        }
        for k in self.corps.examiner(octets, cadre, echeance)? {
            if let Some(n) = self.corps.nom(k) {
                noms.push(n.to_string());
            }
        }
        noms.retain(|n| !self.ignorees.ignore_le_nom(n));
        noms.dedup();
        noms.truncate(NOMS_MAX);
        Ok(Verdict::Trouvees(noms))
    }

    /// Le nom de la signature d'un fichier entier par son seul SHA-256 (ce que le garde et le veilleur connaissent
    /// d'un fichier), sauf s'il est dans une liste blanche. Les signatures en MD5 ou SHA-1 (les .hdb, la plupart de
    /// celles de ClamAV) n'y sont pas : `par_empreintes` les voit.
    pub(crate) fn par_sha256(&self, sha256: &[u8; 32]) -> Option<&str> {
        if self.blanches.chercher_sha256(sha256).is_some() {
            return None;
        }
        self.fichiers
            .chercher_sha256(sha256)
            .filter(|n| !self.ignorees.ignore_le_nom(n))
    }

    /// Le nom de la signature d'un fichier entier de `taille` octets par ses trois empreintes, sauf s'il est dans une
    /// liste blanche : ce que le garde demande d'un fichier qu'il a lu en entier, sans analyser son format.
    pub(crate) fn par_empreintes(&self, e: &Empreintes, taille: u64) -> Option<&str> {
        if self.blanches.chercher(e, taille).is_some() {
            return None;
        }
        self.fichiers
            .chercher(e, taille)
            .filter(|n| !self.ignorees.ignore_le_nom(n))
    }

    /// Les SHA-256 des fichiers entiers, triés, sans doublon ni ceux des listes blanches, mis bout à bout : la liste
    /// binaire qu'un programme en administrateur lit sans rien analyser (`hashes::ListeSha256`).
    pub(crate) fn liste_sha256(&self) -> Vec<u8> {
        let blanches = self.blanches.sha256_tries();
        self.fichiers
            .sha256_tries()
            .into_iter()
            .filter(|e| blanches.binary_search(e).is_err())
            .flatten()
            .collect()
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

    fn charger(options: Options, fichiers: &[(&str, String)]) -> Signatures {
        let mut c = Chargement::nouveau(options);
        for (nom, contenu) in fichiers {
            c.ignorer(nom, contenu.as_bytes());
        }
        for (nom, contenu) in fichiers {
            c.ajouter(nom, contenu.as_bytes());
        }
        c.finir()
    }

    const COMPLETE: Options = Options {
        mode: Mode::Complete,
        pua: false,
    };

    fn trouvees(s: &Signatures, octets: &[u8], cible: Cible) -> Vec<String> {
        match s.juger(octets, &Cadre::simple(cible), None).unwrap() {
            Verdict::Trouvees(n) => n,
            Verdict::Blanche => vec!["(blanche)".to_string()],
        }
    }

    fn base_essai() -> Vec<(&'static str, String)> {
        let a = Empreintes::de(b"contenu a");
        let b = Empreintes::de(b"contenu b");
        let pua = Empreintes::de(b"contenu pua");
        vec![
            (
                "essai.hdb",
                format!(
                    "{}:9:Essai.Fichier-1\n{}:9:Essai.Ignoree-1\n{}:9:PUA.Essai-1\n",
                    hex(&a.md5),
                    hex(&b.md5),
                    hex(&pua.md5)
                ),
            ),
            ("essai.hsb", format!("{}:9:Essai.Sha-1:73\n", hex(&b.sha256))),
            ("essai.hdu", format!("{}:11:Essai.Pua-1\n", hex(&pua.md5))),
            ("essai.ndb", format!("Essai.Corps-1:0:*:{}\n", hex(b"marque-essai"))),
            ("essai.ldb", "Essai.Pcre-1;Target:0;0;0/abc/\n".to_string()),
            ("essai.cbc", "ClamBC\nsuite\n".to_string()),
            ("essai.ign2", "Essai.Ignoree-1\n".to_string()),
            ("COPYING", "licence\n".to_string()),
            ("essai.info", "essai.hdb:1:x\n".to_string()),
        ]
    }

    #[test]
    fn base_complete() {
        let s = charger(COMPLETE, &base_essai());
        assert_eq!(s.nombre(), 3);
        assert_eq!(trouvees(&s, b"contenu a", Cible::Tout), ["Essai.Fichier-1"]);
        assert_eq!(trouvees(&s, b"contenu b", Cible::Tout), ["Essai.Sha-1"]);
        assert_eq!(trouvees(&s, b"contenu pua", Cible::Tout), [] as [String; 0]);
        assert_eq!(trouvees(&s, b"x marque-essai x", Cible::Pe), ["Essai.Corps-1"]);
        let c = &s.comptes.non_lues;
        assert_eq!(c.get(&NonLu::Pua), Some(&2));
        assert_eq!(c.get(&NonLu::Ignoree), Some(&1));
        assert_eq!(c.get(&NonLu::Pcre), Some(&1));
        assert_eq!(c.get(&NonLu::Bytecode), Some(&2));
        assert_eq!(s.comptes.manquees(), 3);
        // Avec les PUA.
        let s = charger(
            Options {
                mode: Mode::Complete,
                pua: true,
            },
            &base_essai(),
        );
        // La taille de la ligne PUA du .hdb (9) n'est pas celle du contenu (11) : seule celle du .hdu le trouve.
        assert_eq!(trouvees(&s, b"contenu pua", Cible::Tout), ["Essai.Pua-1"]);
    }

    #[test]
    fn empreintes_seules_et_liste() {
        let s = charger(
            Options {
                mode: Mode::Empreintes,
                pua: false,
            },
            &base_essai(),
        );
        assert_eq!(s.nombre(), 2);
        assert_eq!(s.comptes.non_lues.get(&NonLu::Mode), Some(&2));
        assert_eq!(trouvees(&s, b"x marque-essai x", Cible::Tout), [] as [String; 0]);
        let b = Empreintes::de(b"contenu b");
        assert_eq!(s.par_sha256(&b.sha256), Some("Essai.Sha-1"));
        assert_eq!(s.liste_sha256(), b.sha256.to_vec());
        let liste = hashes::ListeSha256::lire(s.liste_sha256()).unwrap();
        assert!(liste.contient(&b.sha256));
    }

    #[test]
    fn liste_blanche() {
        let a = Empreintes::de(b"contenu a");
        let mut fichiers = base_essai();
        fichiers.push(("essai.fp", format!("{}:9:Blanche-1\n", hex(&a.md5))));
        fichiers.push((
            "essai.sfp",
            format!("{}:9:Blanche-2\n", hex(&Empreintes::de(b"contenu b").sha256)),
        ));
        let s = charger(COMPLETE, &fichiers);
        assert_eq!(trouvees(&s, b"contenu a", Cible::Tout), ["(blanche)"]);
        assert_eq!(s.liste_sha256(), [] as [u8; 0]);
        assert_eq!(s.par_sha256(&Empreintes::de(b"contenu b").sha256), None);
    }

    #[test]
    fn sections_de_programme() {
        let section = b"section de code";
        let e = Empreintes::de(section);
        let s = charger(
            COMPLETE,
            &[(
                "essai.mdb",
                format!("{}:{}:Essai.Section-1\n", section.len(), hex(&e.md5)),
            )],
        );
        let mut octets = vec![0u8; 64];
        octets[16..16 + section.len()].copy_from_slice(section);
        let cadre = Cadre {
            cible: Cible::Pe,
            point_entree: None,
            sections: vec![(0, 16), (16, section.len() as u64), (60, 100)],
        };
        assert_eq!(
            s.juger(&octets, &cadre, None).unwrap(),
            Verdict::Trouvees(vec!["Essai.Section-1".to_string()])
        );
        assert_eq!(
            s.juger(&octets, &Cadre::simple(Cible::Elf), None).unwrap(),
            Verdict::Trouvees(Vec::new())
        );
    }
}
