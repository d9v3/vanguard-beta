//! Descripteurs de sécurité de Windows (droits d'un partage, d'un dossier) : copiés depuis Windows, puis relus en code
//! sûr, chaque décalage vérifié dans la copie avant d'être lu.

use std::ffi::c_void;
use std::path::Path;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn IsValidSecurityDescriptor(descripteur: *const c_void) -> i32;
    fn GetSecurityDescriptorLength(descripteur: *const c_void) -> u32;
    fn GetNamedSecurityInfoW(
        nom: *const u16,
        sorte: u32,
        quoi: u32,
        proprietaire: *mut *mut c_void,
        groupe: *mut *mut c_void,
        liste: *mut *mut c_void,
        audit: *mut *mut c_void,
        descripteur: *mut *mut c_void,
    ) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memoire: *mut c_void) -> *mut c_void;
}

/// Une règle (ACE) de la liste des droits.
#[derive(Debug, PartialEq)]
pub(crate) struct Ace {
    /// 0 : autoriser, 1 : refuser ; les autres sortes (objets, rappels) sont gardées pour être sautées.
    pub sorte: u8,
    /// Héritage (0x8 : « héritée seulement », vaut pour le contenu, pas pour l'objet).
    pub drapeaux: u8,
    pub masque: u32,
    pub sid: Vec<u8>,
}

/// Copie un descripteur de sécurité rendu par Windows ; `None` s'il n'est pas valide (ou fait plus de 64 Kio).
///
/// # Safety
/// `descripteur` est nul, ou désigne un descripteur de sécurité qui vit pendant l'appel.
pub(crate) unsafe fn copier(descripteur: *const c_void) -> Option<Vec<u8>> {
    if descripteur.is_null() {
        return None;
    }
    // SAFETY : le descripteur est vérifié avant que sa longueur soit demandée, et copié sur cette longueur seulement.
    unsafe {
        if IsValidSecurityDescriptor(descripteur) == 0 {
            return None;
        }
        let n = usize::try_from(GetSecurityDescriptorLength(descripteur)).ok()?;
        if n == 0 || n > 64 * 1024 {
            return None;
        }
        Some(std::slice::from_raw_parts(descripteur.cast::<u8>(), n).to_vec())
    }
}

/// Le descripteur (liste des droits seulement) d'un fichier ou d'un dossier, comme Get-Acl le lit ; `None` s'il ne se
/// lit pas.
pub(crate) fn du_fichier(chemin: &Path) -> Option<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    const FICHIER: u32 = 1;
    const LISTE_DES_DROITS: u32 = 0x4;
    let nom: Vec<u16> = chemin.as_os_str().encode_wide().chain([0]).collect();
    let mut descripteur = std::ptr::null_mut();
    let mut liste = std::ptr::null_mut();
    // SAFETY : le nom est terminé par un zéro et vit pendant l'appel ; le descripteur alloué par Windows (code non nul :
    // rien n'est alloué) est copié puis rendu une seule fois par LocalFree.
    unsafe {
        if GetNamedSecurityInfoW(
            nom.as_ptr(),
            FICHIER,
            LISTE_DES_DROITS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut liste,
            std::ptr::null_mut(),
            &raw mut descripteur,
        ) != 0
        {
            return None;
        }
        let copie = copier(descripteur);
        LocalFree(descripteur);
        copie
    }
}

/// Les règles d'un descripteur autonome (SECURITY_DESCRIPTOR_RELATIVE) ; `None` sans liste des droits (tout le monde a
/// tout). Une règle qui déborde de la liste arrête la lecture.
pub(crate) fn aces(octets: &[u8]) -> Option<Vec<Ace>> {
    const AUTONOME: u16 = 0x8000;
    const LISTE_PRESENTE: u16 = 0x4;
    let u16_a = |d: usize| Some(u16::from_le_bytes(octets.get(d..d + 2)?.try_into().ok()?));
    let u32_a = |d: usize| Some(u32::from_le_bytes(octets.get(d..d + 4)?.try_into().ok()?));
    let controle = u16_a(2)?;
    let liste = usize::try_from(u32_a(16)?).ok()?;
    if controle & AUTONOME == 0 || controle & LISTE_PRESENTE == 0 || liste == 0 {
        return None;
    }
    let taille = usize::from(u16_a(liste + 2)?);
    let nombre = u16_a(liste + 4)?;
    let fin = liste.checked_add(taille).filter(|&f| f <= octets.len())?;
    let mut regles = Vec::new();
    let mut d = liste + 8;
    for _ in 0..nombre {
        let (Some(&sorte), Some(&drapeaux), Some(taille_regle)) =
            (octets.get(d), octets.get(d + 1), u16_a(d + 2).map(usize::from))
        else {
            break;
        };
        if taille_regle < 8 || d + taille_regle > fin {
            break;
        }
        regles.push(Ace {
            sorte,
            drapeaux,
            masque: u32_a(d + 4)?,
            sid: octets.get(d + 8..d + taille_regle)?.to_vec(),
        });
        d += taille_regle;
    }
    Some(regles)
}

/// « S-1-5-21-… » d'un SID binaire : révision, nombre de sous-autorités, autorité sur six octets (gros-boutiste), puis
/// les sous-autorités (petit-boutistes).
pub(crate) fn sid_en_texte(sid: &[u8]) -> Option<String> {
    use std::fmt::Write as _;
    let (revision, n) = (*sid.first()?, usize::from(*sid.get(1)?));
    if revision != 1 || n > 15 || sid.len() < 8 + 4 * n {
        return None;
    }
    let autorite = sid.get(2..8)?.iter().fold(0u64, |a, &o| (a << 8) | u64::from(o));
    let mut t = format!("S-1-{autorite}");
    let (sous_autorites, _) = sid.get(8..8 + 4 * n)?.as_chunks::<4>();
    for s in sous_autorites {
        let _ = write!(t, "-{}", u32::from_le_bytes(*s));
    }

    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_en_texte() {
        assert_eq!(
            sid_en_texte(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]).as_deref(),
            Some("S-1-1-0")
        );
        let mut invite = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for s in [21u32, 111, 222, 333, 501] {
            invite.extend_from_slice(&s.to_le_bytes());
        }
        assert_eq!(sid_en_texte(&invite).as_deref(), Some("S-1-5-21-111-222-333-501"));
        assert_eq!(sid_en_texte(&invite[..20]), None);
        assert_eq!(sid_en_texte(&[2, 0, 0, 0, 0, 0, 0, 1]), None);
    }

    /// Le vrai Windows (Wine ici, la VM ensuite) : la liste des droits du dossier de Windows se lit et se relit.
    #[test]
    fn droits_d_un_dossier() {
        let windows = std::env::var_os("SystemRoot").map_or_else(|| r"C:\Windows".into(), std::path::PathBuf::from);
        if let Some(d) = du_fichier(&windows) {
            let _ = aces(&d);
        }
        assert_eq!(du_fichier(Path::new(r"C:\vanguard-dossier-inexistant")), None);
    }
}
