//! L'empreinte d'un fichier (MD5, SHA-1, SHA-256, SHA-512) calculée par BCrypt, le chiffrement de Windows, sans
//! PowerShell : Get-FileHash passait par le délai de 60 s de `ps`, trop court pour une image disque.

use std::ffi::c_void;
use std::fmt::Write as _;
use std::io::Read;
use std::path::Path;

#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptOpenAlgorithmProvider(
        algo: *mut *mut c_void,
        nom: *const u16,
        fournisseur: *const u16,
        drapeaux: u32,
    ) -> i32;
    fn BCryptCreateHash(
        algo: *mut c_void,
        calcul: *mut *mut c_void,
        objet: *mut u8,
        taille_objet: u32,
        secret: *mut u8,
        taille_secret: u32,
        drapeaux: u32,
    ) -> i32;
    fn BCryptHashData(calcul: *mut c_void, donnees: *const u8, taille: u32, drapeaux: u32) -> i32;
    fn BCryptFinishHash(calcul: *mut c_void, sortie: *mut u8, taille: u32, drapeaux: u32) -> i32;
    fn BCryptDestroyHash(calcul: *mut c_void) -> i32;
    fn BCryptCloseAlgorithmProvider(algo: *mut c_void, drapeaux: u32) -> i32;
}

/// L'empreinte en hexadécimal minuscule ; `algo` est le nom de BCrypt (« MD5 », « SHA1 », « SHA256 », « SHA512 »)
/// et `taille` la longueur de l'empreinte en octets. `None` si le fichier ne se lit pas ou que BCrypt refuse.
pub(crate) fn empreinte(fichier: &Path, algo: &str, taille: usize) -> Option<String> {
    let mut f = std::fs::File::open(fichier).ok()?;
    let nom: Vec<u16> = algo.encode_utf16().chain([0]).collect();
    let (mut fournisseur, mut calcul) = (std::ptr::null_mut(), std::ptr::null_mut());
    let mut resultat = vec![0u8; taille];
    let mut morceau = vec![0u8; 1 << 20];
    // SAFETY: le nom est terminé par un zéro et vit pendant l'appel ; le fournisseur et le calcul (refus : code non
    // nul, vérifié avant tout usage) sont rendus une seule fois, à la fin. BCrypt lit au plus `n` octets du morceau,
    // qui les a, et écrit `taille` octets dans `resultat`, qui les a (BCrypt refuse une taille qui n'est pas celle
    // de l'algorithme).
    unsafe {
        if BCryptOpenAlgorithmProvider(&raw mut fournisseur, nom.as_ptr(), std::ptr::null(), 0) != 0 {
            return None;
        }
        let mut lu = BCryptCreateHash(
            fournisseur,
            &raw mut calcul,
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            0,
            0,
        ) == 0;
        while lu {
            match f.read(&mut morceau) {
                Ok(0) => break,
                Ok(n) => lu = BCryptHashData(calcul, morceau.as_ptr(), u32::try_from(n).unwrap_or(0), 0) == 0,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => lu = false,
            }
        }
        // Pas de `?` ici : le fournisseur et le calcul doivent encore être rendus.
        lu = lu && u32::try_from(taille).is_ok_and(|t| BCryptFinishHash(calcul, resultat.as_mut_ptr(), t, 0) == 0);
        if !calcul.is_null() {
            BCryptDestroyHash(calcul);
        }
        BCryptCloseAlgorithmProvider(fournisseur, 0);
        lu.then(|| {
            resultat.iter().fold(String::new(), |mut t, o| {
                let _ = write!(t, "{o:02x}");
                t
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La vraie BCrypt (Wine ici, la VM ensuite) sur « abc », aux empreintes connues.
    #[test]
    fn empreintes_de_bcrypt() {
        let f = std::env::temp_dir().join(format!("vanguard-hachage-{}.txt", std::process::id()));
        std::fs::write(&f, b"abc").unwrap();
        assert_eq!(
            empreinte(&f, "MD5", 16).as_deref(),
            Some("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            empreinte(&f, "SHA1", 20).as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            empreinte(&f, "SHA256", 32).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(empreinte(&f, "SHA512", 64).map(|e| e.len()), Some(128));
        assert_eq!(empreinte(&f, "SHA256", 20), None);
        let _ = std::fs::remove_file(&f);
        assert_eq!(empreinte(&f, "SHA256", 32), None);
    }
}
