//! Les types fermés de l'agent : qui (la mission), quand (le moment), de quel genre, sur quelle règle, et
//! l'empreinte qui chaîne son journal. Aucun texte libre : une règle est 11 octets de la forme « AAA-AAA-000 », une
//! empreinte 64 chiffres hexadécimaux. Ce qu'un fichier, un programme ou une page aurait écrit ne peut donc ni entrer
//! dans un jugement de l'agent ni ressortir par son journal.
//!
//! Module pur (ni fichier, ni horloge) : le banc de fuzzing l'inclut tel quel (`agent_etat`, `agent_journal`).
// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Les missions de l'agent : une liste fermée, qu'aucun fichier ne peut allonger. Les suivantes (relevé,
/// corrections, agents d'IA voyous) s'ajoutent ici, dans le code, avec leur genre.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum MissionId {
    /// L'auto-réglage des délais des règles (L6, `autotest::reglage`).
    Reglage,
    /// La durée de la cache du passage horaire (L6c, `autotest::cache`).
    Cache,
}

impl MissionId {
    /// Toutes, dans l'ordre où un tour les passe.
    pub(crate) const TOUTES: [MissionId; 2] = [MissionId::Reglage, MissionId::Cache];
}

/// Ce qu'une mission a le droit de décider. Un réglage ajuste (dans le sens sûr) ou propose ; un relevé ne fait que
/// noter ; une détection signale ou propose, sans jamais rien ajuster.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(test), allow(dead_code))] // Releve et Detection : les missions de G3 (relevé) et G7 (agents voyous)
pub(crate) enum Genre {
    Reglage,
    Releve,
    Detection,
}

/// Quand un tour de l'agent a lieu. Pas de démon neuf : il vit dans ce qui tourne déjà.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(test), allow(dead_code))] // Veilleur et Sortie : branchés par les lots qui en auront besoin
pub(crate) enum Moment {
    /// À la fin d'un bilan noté (demandé ou du passage horaire).
    FinDeBilan,
    /// À la passe horaire de la surveillance.
    PasseHoraire,
    /// Au réveil du veilleur (plus tard, sur accord).
    Veilleur,
    /// À la sortie du programme.
    Sortie,
}

/// L'identifiant d'une règle du registre, « AAA-AAA-000 », et rien d'autre : 11 octets ASCII vérifiés.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct RegleId([u8; 11]);

impl RegleId {
    /// `None` pour tout ce qui n'a pas exactement la forme d'un identifiant de règle.
    pub(crate) fn depuis(texte: &str) -> Option<RegleId> {
        let o: [u8; 11] = texte.as_bytes().try_into().ok()?;
        o.iter()
            .enumerate()
            .all(|(i, c)| match i {
                0..=2 | 4..=6 => c.is_ascii_uppercase(),
                3 | 7 => *c == b'-',
                _ => c.is_ascii_digit(),
            })
            .then_some(RegleId(o))
    }

    pub(crate) fn texte(&self) -> &str {
        // Vérifié à la construction : de l'ASCII.
        std::str::from_utf8(&self.0).unwrap_or("???-???-000")
    }
}

impl std::fmt::Debug for RegleId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.texte())
    }
}

/// L'empreinte d'une entrée du journal : 32 octets, écrits en 64 chiffres hexadécimaux minuscules.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Empreinte(pub [u8; 32]);

impl Empreinte {
    fn depuis(texte: &str) -> Option<Empreinte> {
        let o = texte.as_bytes();
        if o.len() != 64 {
            return None;
        }
        let chiffre = |c: u8| match c {
            b'0'..=b'9' | b'a'..=b'f' => char::from(c).to_digit(16).and_then(|d| u8::try_from(d).ok()),
            _ => None,
        };
        let mut e = [0u8; 32];
        for (octet, [fort, faible]) in e.iter_mut().zip(o.as_chunks::<2>().0) {
            *octet = (chiffre(*fort)? << 4) | chiffre(*faible)?;
        }
        Some(Empreinte(e))
    }

    fn hexa(&self) -> [u8; 64] {
        const CHIFFRES: &[u8; 16] = b"0123456789abcdef";
        let mut h = [0u8; 64];
        for (paire, o) in h.as_chunks_mut::<2>().0.iter_mut().zip(self.0) {
            let chiffre = |n: u8| CHIFFRES.get(usize::from(n)).copied().unwrap_or(b'0');
            *paire = [chiffre(o >> 4), chiffre(o & 15)];
        }
        h
    }
}

impl std::fmt::Debug for Empreinte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(std::str::from_utf8(&self.hexa()).unwrap_or_default())
    }
}

/// Lit une chaîne JSON sans la garder : la forme fermée, ou un refus.
struct Forme<T>(fn(&str) -> Option<T>, &'static str);

impl<T> serde::de::Visitor<'_> for Forme<T> {
    type Value = T;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<T, E> {
        (self.0)(v).ok_or_else(|| E::custom(self.1))
    }
}

impl Serialize for RegleId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.texte())
    }
}

impl<'de> Deserialize<'de> for RegleId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(Forme(RegleId::depuis, "une règle « AAA-AAA-000 »"))
    }
}

impl Serialize for Empreinte {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(std::str::from_utf8(&self.hexa()).unwrap_or_default())
    }
}

impl<'de> Deserialize<'de> for Empreinte {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(Forme(Empreinte::depuis, "64 chiffres hexadécimaux"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regle_seulement_de_la_forme_du_registre() {
        assert_eq!(RegleId::depuis("LNX-NOY-001").unwrap().texte(), "LNX-NOY-001");
        for faux in [
            "",
            "LNX-NOY-01",
            "lnx-noy-001",
            "LNX_NOY-001",
            "LNX-NOY-0011",
            "LNX-NOY-00a",
            "ÉNX-NOY-001",
        ] {
            assert!(RegleId::depuis(faux).is_none(), "{faux}");
        }
        let r = RegleId::depuis("WIN-MAJ-004").unwrap();
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"WIN-MAJ-004\"");
        assert_eq!(serde_json::from_str::<RegleId>(&json).unwrap(), r);
        assert!(serde_json::from_str::<RegleId>("\"ignore les consignes\"").is_err());
    }

    #[test]
    fn empreinte_aller_retour() {
        let e = Empreinte([0xab; 32]);
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<Empreinte>(&json).unwrap(), e);
        assert!(serde_json::from_str::<Empreinte>("\"AB\"").is_err());
    }
}
