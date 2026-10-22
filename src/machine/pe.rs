//! Lecture d'un programme Windows (format PE) sur n'importe quel système : un seul champ, DependentLoadFlags du
//! répertoire « Load Config ». Le programme Windows le grave (`windows/chargement.rs`) pour que ses DLL importées ne
//! viennent que de System32 ; le déploiement, qui tourne sous Linux, le relit dans le vanguard.exe compilé avant de
//! le livrer (`vanguard deploiement verifier-pe`), comme le fait la compilation reproductible de la CI. Ici, et pas
//! sous cfg(windows) : sinon le programme Linux ne pourrait pas le vérifier, et une seconde lecture (en Python)
//! pourrait diverger de celle-ci.

/// LOAD_LIBRARY_SEARCH_SYSTEM32.
pub(crate) const SYSTEM32_SEULEMENT: u16 = 0x800;

/// DependentLoadFlags est au décalage 78 (2 octets) : Windows ne le lit que si la taille annoncée du répertoire le
/// couvre. Une taille plus courte laisserait le champ ignoré, quelle que soit sa valeur.
pub(crate) const TAILLE_MIN_DRAPEAUX: u32 = 80;

/// La taille annoncée et DependentLoadFlags du répertoire « Load Config » d'un PE 64 bits ; `None` s'il n'en a pas.
pub(crate) fn lire_load_config(pe: &[u8]) -> Option<(u32, u16)> {
    let u16_a = |i: usize| pe.get(i..i + 2).map(|o| u16::from_le_bytes([o[0], o[1]]));
    let u32_a = |i: usize| pe.get(i..i + 4).map(|o| u32::from_le_bytes([o[0], o[1], o[2], o[3]]));
    let entete = usize::try_from(u32_a(0x3C)?).ok()?;
    if pe.get(entete..entete + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = usize::from(u16_a(entete + 6)?);
    let facultatif = entete + 24;
    if u16_a(facultatif)? != 0x20B {
        return None;
    }
    // Répertoire n° 10 (Load Config), après les 112 premiers octets de l'en-tête facultatif PE32+.
    let rva = u32_a(facultatif + 112 + 10 * 8)?;
    if rva == 0 {
        return None;
    }
    let premiere = facultatif + usize::from(u16_a(entete + 20)?);
    (0..sections).find_map(|n| {
        let s = premiere + n * 40;
        let (taille, debut, brut) = (u32_a(s + 8)?, u32_a(s + 12)?, u32_a(s + 20)?);
        let dedans = rva.checked_sub(debut).filter(|d| *d < taille)?;
        let position = usize::try_from(brut.checked_add(dedans)?).ok()?;
        Some((u32_a(position)?, u16_a(position + 78)?))
    })
}

/// Le programme ne charge-t-il ses DLL que depuis System32 ? Seulement si le champ y est, et lu par Windows.
pub(crate) fn system32_seulement(lu: Option<(u32, u16)>) -> bool {
    matches!(lu, Some((taille, drapeaux)) if taille >= TAILLE_MIN_DRAPEAUX && drapeaux == SYSTEM32_SEULEMENT)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Un PE32+ minimal, fait à la main : en-tête MZ (e_lfanew = 0x40), signature, en-tête de fichier (une section),
    /// en-tête facultatif PE32+ de 240 octets dont le répertoire n° 10 vise RVA 0x1000, une section « .rdata »
    /// (RVA 0x1000, 0x200 octets, données brutes à 0x200), et le Load Config qui y commence.
    pub(crate) fn pe_d_essai(taille: u32, drapeaux: u16) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        let fichier = 0x44;
        pe[fichier..fichier + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[fichier + 2..fichier + 4].copy_from_slice(&1u16.to_le_bytes());
        pe[fichier + 16..fichier + 18].copy_from_slice(&240u16.to_le_bytes());
        let facultatif = 0x58;
        pe[facultatif..facultatif + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        let repertoire = facultatif + 112 + 10 * 8;
        pe[repertoire..repertoire + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[repertoire + 4..repertoire + 8].copy_from_slice(&taille.to_le_bytes());
        let section = facultatif + 240;
        pe[section..section + 6].copy_from_slice(b".rdata");
        pe[section + 8..section + 12].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[section + 16..section + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x200..0x204].copy_from_slice(&taille.to_le_bytes());
        pe[0x200 + 78..0x200 + 80].copy_from_slice(&drapeaux.to_le_bytes());
        pe
    }

    #[test]
    fn un_pe_fait_a_la_main_se_lit() {
        let pe = pe_d_essai(148, SYSTEM32_SEULEMENT);
        assert_eq!(lire_load_config(&pe), Some((148, 0x800)));
        assert!(system32_seulement(lire_load_config(&pe)));
        assert!(!system32_seulement(lire_load_config(&pe_d_essai(148, 0))));
        assert!(!system32_seulement(None));
    }

    /// Une taille annoncée qui ne couvre pas le champ : Windows ne le lit pas, le programme n'est pas protégé.
    #[test]
    fn taille_trop_courte_refusee() {
        let pe = pe_d_essai(79, SYSTEM32_SEULEMENT);
        assert_eq!(lire_load_config(&pe), Some((79, 0x800)));
        assert!(!system32_seulement(lire_load_config(&pe)));
        assert!(system32_seulement(lire_load_config(&pe_d_essai(
            80,
            SYSTEM32_SEULEMENT
        ))));
    }

    #[test]
    fn formes_refusees() {
        // PE32 (32 bits).
        let mut pe32 = pe_d_essai(148, SYSTEM32_SEULEMENT);
        pe32[0x58..0x5A].copy_from_slice(&0x10Bu16.to_le_bytes());
        assert_eq!(lire_load_config(&pe32), None);
        // Pas de répertoire Load Config.
        let mut sans = pe_d_essai(148, SYSTEM32_SEULEMENT);
        let repertoire = 0x58 + 112 + 80;
        sans[repertoire..repertoire + 4].fill(0);
        assert_eq!(lire_load_config(&sans), None);
        // Un RVA hors de toute section.
        let mut hors = pe_d_essai(148, SYSTEM32_SEULEMENT);
        hors[repertoire..repertoire + 4].copy_from_slice(&0x9000u32.to_le_bytes());
        assert_eq!(lire_load_config(&hors), None);
        // Tronqué au milieu du Load Config, ou avant les en-têtes.
        let entier = pe_d_essai(148, SYSTEM32_SEULEMENT);
        assert_eq!(lire_load_config(&entier[..0x200 + 40]), None);
        assert_eq!(lire_load_config(&entier[..0x60]), None);
        assert_eq!(lire_load_config(b"MZ"), None);
        // e_lfanew démesuré.
        let mut loin = pe_d_essai(148, SYSTEM32_SEULEMENT);
        loin[0x3C..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(lire_load_config(&loin), None);
    }

    proptest::proptest! {
        /// Des octets au hasard (overflow-checks est actif, même en version publiée) : jamais de panique.
        #[test]
        fn octets_au_hasard_sans_panique(octets in proptest::collection::vec(proptest::num::u8::ANY, 0..2048)) {
            let _ = lire_load_config(&octets);
        }

        /// Un PE valide dont des octets sont changés au hasard : jamais de panique non plus.
        #[test]
        fn pe_abime_sans_panique(changes in proptest::collection::vec((0usize..0x400, proptest::num::u8::ANY), 1..16)) {
            let mut pe = pe_d_essai(148, SYSTEM32_SEULEMENT);
            for (i, o) in changes {
                pe[i] = o;
            }
            let _ = lire_load_config(&pe);
        }
    }
}
