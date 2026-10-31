//! Petites lectures communes aux lecteurs de l'analyse : entiers petit et gros-boutistes à une position contrôlée,
//! chaînes terminées par un nul, UTF-16. Toute lecture hors des octets rend `None`, jamais une panique : les
//! positions viennent du fichier analysé, qui peut mentir.
//!
//! Sans `crate::` ni `super::` : le banc de fuzzing inclut les lecteurs par leur chemin, avec ce module à côté.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

/// Une taille ou une position en mémoire (`usize`) en `u64` : toujours exacte sur les cibles de Vanguard (64 bits au
/// plus) ; `u64::MAX` sur une cible plus large, qui n'existe pas.
pub(crate) fn en_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Un nombre lu dans le fichier (`u32` : indice, position, taille) en `usize` : toujours exact sur les cibles de
/// Vanguard (32 bits au moins) ; `usize::MAX`, hors de toute table, sur une cible plus étroite, qui n'existe pas.
pub(crate) fn rang(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

pub(crate) fn tranche(octets: &[u8], i: usize, n: usize) -> Option<&[u8]> {
    octets.get(i..i.checked_add(n)?)
}

/// Les `N` octets qui commencent en `i`, en tableau (pour les conversions d'entiers, sans indice à vérifier).
pub(crate) fn tableau<const N: usize>(octets: &[u8], i: usize) -> Option<[u8; N]> {
    octets.get(i..)?.first_chunk::<N>().copied()
}

pub(crate) fn u16le(octets: &[u8], i: usize) -> Option<u16> {
    tableau(octets, i).map(u16::from_le_bytes)
}

pub(crate) fn u32le(octets: &[u8], i: usize) -> Option<u32> {
    tableau(octets, i).map(u32::from_le_bytes)
}

pub(crate) fn u64le(octets: &[u8], i: usize) -> Option<u64> {
    tableau(octets, i).map(u64::from_le_bytes)
}

/// Un lecteur d'entiers dans l'ordre d'octets d'un fichier (ELF et Mach-O existent dans les deux).
#[derive(Clone, Copy)]
pub(crate) struct Ordre {
    pub gros_boutiste: bool,
}

impl Ordre {
    pub(crate) fn u16(self, octets: &[u8], i: usize) -> Option<u16> {
        let m = tableau(octets, i)?;
        Some(if self.gros_boutiste {
            u16::from_be_bytes(m)
        } else {
            u16::from_le_bytes(m)
        })
    }

    pub(crate) fn u32(self, octets: &[u8], i: usize) -> Option<u32> {
        let m = tableau(octets, i)?;
        Some(if self.gros_boutiste {
            u32::from_be_bytes(m)
        } else {
            u32::from_le_bytes(m)
        })
    }

    pub(crate) fn u64(self, octets: &[u8], i: usize) -> Option<u64> {
        let m = tableau(octets, i)?;
        Some(if self.gros_boutiste {
            u64::from_be_bytes(m)
        } else {
            u64::from_le_bytes(m)
        })
    }
}

/// La chaîne terminée par un nul qui commence en `i`, d'au plus `max` octets (sans nul dans ces `max` octets, ou
/// hors des octets : `None`).
pub(crate) fn chaine_c(octets: &[u8], i: usize, max: usize) -> Option<String> {
    let reste = octets.get(i..)?;
    let reste = reste.get(..max).unwrap_or(reste);
    let fin = reste.iter().position(|&o| o == 0)?;
    Some(latin1_ou_utf8(reste.get(..fin)?))
}

/// Des octets d'une page de code que le format ne dit pas : UTF-8 s'ils en sont, sinon pris un par un (Latin-1),
/// pour qu'un nom reste lisible et comparable sans rien inventer.
pub(crate) fn latin1_ou_utf8(octets: &[u8]) -> String {
    match std::str::from_utf8(octets) {
        Ok(s) => s.to_string(),
        Err(_) => octets.iter().map(|&o| char::from(o)).collect(),
    }
}

/// De l'UTF-16 petit-boutiste (les paires invalides remplacées), jusqu'au premier nul ou à la fin.
pub(crate) fn utf16le(octets: &[u8]) -> String {
    let unites = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .take_while(|&u| u != 0);
    char::decode_utf16(unites)
        .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// L'UTF-16 petit-boutiste terminé par un nul qui commence en `i`, d'au plus `max` octets.
pub(crate) fn chaine_utf16(octets: &[u8], i: usize, max: usize) -> Option<String> {
    let reste = octets.get(i..)?;
    let paires = reste.get(..max).unwrap_or(reste).as_chunks::<2>().0;
    let fin = paires.iter().position(|p| *p == [0, 0])?;
    Some(utf16le(paires.get(..fin)?.as_flattened()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lectures_bornees() {
        let o = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16le(&o, 0), Some(0x0201));
        assert_eq!(u32le(&o, 4), Some(0x0807_0605));
        assert_eq!(u64le(&o, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u32le(&o, 5), None);
        assert_eq!(u32le(&o, usize::MAX), None);
        let gros = Ordre { gros_boutiste: true };
        assert_eq!(gros.u32(&o, 0), Some(0x0102_0304));
        assert_eq!(chaine_c(b"abc\0def", 0, 10).as_deref(), Some("abc"));
        assert_eq!(chaine_c(b"abcdef", 0, 10), None);
        assert_eq!(chaine_c(b"abc\0", 0, 2), None);
        assert_eq!(latin1_ou_utf8(b"caf\xe9"), "café");
        assert_eq!(utf16le(&[b'a', 0, b'b', 0, 0, 0, b'c', 0]), "ab");
        assert_eq!(chaine_utf16(&[b'a', 0, 0, 0], 0, 64).as_deref(), Some("a"));
        assert_eq!(chaine_utf16(&[b'a', 0, b'b'], 0, 64), None);
    }
}
