//! La note « avant » d'un choix de la personne, telle que le registre la garde (`choix_avant`) : ses octets et leur
//! lecture stricte. À part pour le banc de fuzzing (`fuzz/fuzz_targets/choix_note.rs`) : une note se lit dans le
//! registre, que d'autres programmes administrateurs peuvent avoir écrit.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// L'en-tête d'une note, version comprise : une autre version n'est jamais lue.
pub(crate) const ENTETE: &[u8] = b"VGCHX\x01";
/// La plus longue note admise : une valeur simple et son identifiant n'en prennent que quelques dizaines d'octets.
pub(crate) const NOTE_MAX: usize = 4096;
/// L'empreinte qui clôt une note.
pub(crate) const EMPREINTE: usize = 32;
/// La plus courte note possible : l'en-tête, trois longueurs, la date, l'empreinte.
const NOTE_MIN: usize = ENTETE.len() + 6 + 8 + EMPREINTE;

/// Une note « avant » : ce qu'un choix a trouvé, ce qu'il a demandé, et quand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Note {
    /// L'identifiant du réglage (`IdChoix::texte`), le nom de la valeur.
    pub(crate) id: String,
    /// La valeur trouvée avant la première baisse (`None` : règle ASR absente de la liste).
    pub(crate) avant: Option<i64>,
    /// La valeur demandée par la baisse : écrite avant la relecture, elle peut ne pas avoir pris (valeur changée
    /// pendant le geste, note gardée pour « Rallumer »). Elle sert à lire la note, jamais de cible.
    pub(crate) posee: i64,
    /// Secondes depuis 1970 (UTC).
    pub(crate) date: u64,
}

pub(crate) fn texte_valeur(v: Option<i64>) -> String {
    v.map_or_else(|| "absente".to_string(), |n| n.to_string())
}

/// Un entier décimal écrit par `texte_valeur`, et seulement lui : pas de « + », de zéro de tête ni d'espace.
#[allow(clippy::option_option)] // None : illisible ; Some(None) : valeur absente
pub(crate) fn lire_valeur(t: &str) -> Option<Option<i64>> {
    if t == "absente" {
        return Some(None);
    }
    let n: i64 = t.parse().ok()?;
    (n.to_string() == t).then_some(Some(n))
}

impl Note {
    /// Les octets de la note : en-tête, trois champs (longueur sur 2 octets petit-boutiste, puis le texte ASCII),
    /// la date sur 8 octets, puis le SHA-256 de tout ce qui précède.
    pub(crate) fn octets(&self) -> Vec<u8> {
        let mut o = ENTETE.to_vec();
        for champ in [self.id.clone(), texte_valeur(self.avant), self.posee.to_string()] {
            let n = u16::try_from(champ.len()).unwrap_or(u16::MAX);
            o.extend_from_slice(&n.to_le_bytes());
            o.extend_from_slice(champ.as_bytes());
        }
        o.extend_from_slice(&self.date.to_le_bytes());
        let empreinte = Sha256::digest(&o);
        o.extend_from_slice(&empreinte);
        o
    }

    /// La note de la valeur `nom`, si et seulement si ses octets en ont la forme exacte : bornée, empreinte juste,
    /// bonne version, identifiant égal au nom de la valeur (une note copiée sous un autre nom est refusée), texte
    /// ASCII visible, nombres réécrits à l'identique, rien après. `None` sinon : « Rallumer » vise alors la valeur
    /// sûre.
    pub(crate) fn lire(nom: &str, octets: &[u8]) -> Option<Note> {
        if octets.len() > NOTE_MAX || octets.len() < NOTE_MIN {
            return None;
        }
        let (corps, empreinte) = octets.split_at(octets.len().checked_sub(EMPREINTE)?);
        if Sha256::digest(corps).as_slice() != empreinte {
            return None;
        }
        let mut reste = corps.strip_prefix(ENTETE)?;
        let mut champs = Vec::with_capacity(3);
        for _ in 0..3 {
            let (n, suite) = reste.split_first_chunk::<2>()?;
            let n = usize::from(u16::from_le_bytes(*n));
            let (texte, suite) = (suite.get(..n)?, suite.get(n..)?);
            if texte.is_empty() || !texte.iter().all(u8::is_ascii_graphic) {
                return None;
            }
            champs.push(std::str::from_utf8(texte).ok()?);
            reste = suite;
        }
        let date: [u8; 8] = reste.try_into().ok()?;
        let [id, avant, posee] = champs.as_slice() else {
            return None;
        };
        if *id != nom {
            return None;
        }
        Some(Note {
            id: (*id).to_string(),
            avant: lire_valeur(avant)?,
            posee: lire_valeur(posee)??,
            date: u64::from_le_bytes(date),
        })
    }
}
