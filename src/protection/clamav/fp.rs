//! Ce que la base retire d'elle-même : les signatures ignorées (.ign, .ign2) par leur nom seul (`nom`), par leur nom et
//! l'empreinte MD5 de leur ligne (`nom:md5`, pour n'en retirer qu'une version), ou dans l'ancienne forme
//! `base:ligne:nom` (le nom seul compte, comme pour ClamAV aujourd'hui). Les listes blanches de fichiers (.fp en MD5,
//! .sfp en SHA-1 ou SHA-256, forme des .hdb) vont dans une table d'empreintes (`hashes::Table`).
//!
//! Module pur, sans données de la machine : le banc de fuzzing l'inclut par son chemin.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

use md5::Digest;

use super::commun::{hex_fixe, lignes};

/// Les signatures que la base ignore.
#[derive(Debug, Default)]
pub(crate) struct Ignorees {
    noms: HashSet<String>,
    /// Nom → empreintes MD5 des lignes ignorées de ce nom.
    lignes: HashMap<String, Vec<[u8; 16]>>,
}

impl Ignorees {
    /// Lit un .ign ou .ign2 ; rend le nombre de lignes illisibles.
    pub(crate) fn lire(&mut self, contenu: &[u8]) -> usize {
        let mut illisibles = 0usize;
        for l in lignes(contenu) {
            let Ok(l) = l else {
                illisibles = illisibles.saturating_add(1);
                continue;
            };
            let champs: Vec<&str> = l.splitn(4, ':').collect();
            match champs.as_slice() {
                [nom] | [_, _, nom] if !nom.is_empty() => {
                    self.noms.insert((*nom).to_string());
                }
                [nom, md5] if !nom.is_empty() => match hex_fixe::<16>(md5) {
                    Some(e) => self.lignes.entry((*nom).to_string()).or_default().push(e),
                    None => illisibles = illisibles.saturating_add(1),
                },
                _ => illisibles = illisibles.saturating_add(1),
            }
        }
        illisibles
    }

    pub(crate) fn est_vide(&self) -> bool {
        self.noms.is_empty() && self.lignes.is_empty()
    }

    /// La signature `nom`, lue de la ligne `ligne`, est-elle ignorée ?
    pub(crate) fn ignore(&self, nom: &str, ligne: &str) -> bool {
        self.noms.contains(nom)
            || self
                .lignes
                .get(nom)
                .is_some_and(|v| v.contains(&md5::Md5::digest(ligne.as_bytes()).into()))
    }

    /// La signature `nom` est-elle ignorée quelle que soit sa ligne (ce que juge une trouvaille, après coup) ?
    pub(crate) fn ignore_le_nom(&self, nom: &str) -> bool {
        self.noms.contains(nom)
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
    fn listes_ignorees() {
        let ligne = "Essai.Version-2:0:*:6162";
        let md5 = hex(&md5::Md5::digest(ligne.as_bytes()));
        let mut i = Ignorees::default();
        assert!(i.est_vide());
        let texte = format!(
            "# commentaire\nEssai.Nom-1\r\ndaily.ndb:12:Essai.Ancienne-1\nEssai.Version-2:{md5}\nEssai:pas-du-md5\na:b:c:d\n\n"
        );
        assert_eq!(i.lire(texte.as_bytes()), 2);
        assert!(i.ignore("Essai.Nom-1", "n'importe quoi"));
        assert!(i.ignore_le_nom("Essai.Ancienne-1"));
        assert!(i.ignore("Essai.Version-2", ligne));
        assert!(!i.ignore("Essai.Version-2", "Essai.Version-2:0:*:6163"));
        assert!(!i.ignore_le_nom("Essai.Version-2"));
        assert!(!i.ignore("Essai.Autre", ligne));
        assert_eq!(Ignorees::default().lire(b"\xff\xfe\n:\n"), 2);
    }
}
