//! Petites lectures communes aux lecteurs de l'analyse : entiers petit et gros-boutistes à une position contrôlée,
//! chaînes terminées par un nul, UTF-16. Toute lecture hors des octets rend `None`, jamais une panique : les
//! positions viennent du fichier analysé, qui peut mentir.
//!
//! Sans `crate::` ni `super::` : le banc de fuzzing inclut les lecteurs par leur chemin, avec ce module à côté.

pub(crate) fn tranche(octets: &[u8], i: usize, n: usize) -> Option<&[u8]> {
    octets.get(i..i.checked_add(n)?)
}

pub(crate) fn u16le(octets: &[u8], i: usize) -> Option<u16> {
    tranche(octets, i, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn u32le(octets: &[u8], i: usize) -> Option<u32> {
    tranche(octets, i, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn u64le(octets: &[u8], i: usize) -> Option<u64> {
    let b = tranche(octets, i, 8)?;
    let mut m = [0u8; 8];
    m.copy_from_slice(b);
    Some(u64::from_le_bytes(m))
}

/// Un lecteur d'entiers dans l'ordre d'octets d'un fichier (ELF et Mach-O existent dans les deux).
#[derive(Clone, Copy)]
pub(crate) struct Ordre {
    pub gros_boutiste: bool,
}

impl Ordre {
    pub(crate) fn u16(self, octets: &[u8], i: usize) -> Option<u16> {
        let b = tranche(octets, i, 2)?;
        let m = [b[0], b[1]];
        Some(if self.gros_boutiste {
            u16::from_be_bytes(m)
        } else {
            u16::from_le_bytes(m)
        })
    }

    pub(crate) fn u32(self, octets: &[u8], i: usize) -> Option<u32> {
        let b = tranche(octets, i, 4)?;
        let m = [b[0], b[1], b[2], b[3]];
        Some(if self.gros_boutiste {
            u32::from_be_bytes(m)
        } else {
            u32::from_le_bytes(m)
        })
    }

    pub(crate) fn u64(self, octets: &[u8], i: usize) -> Option<u64> {
        let b = tranche(octets, i, 8)?;
        let mut m = [0u8; 8];
        m.copy_from_slice(b);
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
    let reste = &reste[..reste.len().min(max)];
    let fin = reste.iter().position(|&o| o == 0)?;
    Some(latin1_ou_utf8(&reste[..fin]))
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
    let reste = &reste[..reste.len().min(max)];
    let fin = reste.as_chunks::<2>().0.iter().position(|p| *p == [0, 0])?;
    Some(utf16le(&reste[..fin * 2]))
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
