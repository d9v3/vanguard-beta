//! Sous Windows, la fenêtre n'a pas de console (`windows_subsystem`) : une erreur de démarrage écrite sur la sortie
//! d'erreur ne se voit nulle part. Lancée seule (raccourci, double-clic), elle le dit donc dans une boîte de message.
//! Lancée par `vanguard` (`--depuis-vanguard`), rien : `vanguard` voit qu'elle ne s'est pas ouverte et prend le menu.

use crate::{tr, trf};

/// Le texte de la boîte : ce qui n'a pas marché, puis quoi faire. Sans OpenGL 2.0 (une machine virtuelle, un PC sans
/// pilote graphique), Windows n'offre que son OpenGL 1.1, trop vieux pour la fenêtre : c'est dit en clair.
pub(crate) fn texte(erreur: &str) -> String {
    let cause = if erreur.to_ascii_lowercase().contains("opengl") {
        tr!(
            "Cet ordinateur n'a pas de pilote graphique assez récent (OpenGL 2.0 ou plus) : c'est souvent le cas d'une \
             machine virtuelle ou d'un Windows sans le pilote de sa carte graphique.",
            "This computer has no recent enough graphics driver (OpenGL 2.0 or later): this is often the case in a \
             virtual machine or on a Windows without its graphics card driver."
        )
    } else {
        ""
    };
    let sep = if cause.is_empty() { "" } else { "\n\n" };
    trf!(
        "La fenêtre de Vanguard n'a pas pu s'ouvrir.\n\n{cause}{sep}Vanguard marche quand même : lance vanguard.exe, \
         il ouvre le menu du terminal.\n\nDétail : {erreur}",
        "The Vanguard window could not open.\n\n{cause}{sep}Vanguard still works: run vanguard.exe, it opens the \
         terminal menu.\n\nDetail: {erreur}"
    )
}

/// Montre la boîte d'erreur et attend « OK ». user32.dll est déjà chargée par la fenêtre (table d'importation).
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) fn montrer(erreur: &str) {
    // FFI de user32 : MessageBoxW, une boîte modale sans propriétaire.
    #[link(name = "user32")]
    unsafe extern "system" {
        fn MessageBoxW(fenetre: *mut core::ffi::c_void, texte: *const u16, titre: *const u16, genre: u32) -> i32;
    }
    const MB_ICONERROR: u32 = 0x10;
    // Un NUL au milieu couperait le texte : il est retiré, puis le NUL final ajouté.
    let large = |s: &str| -> Vec<u16> { s.encode_utf16().filter(|&c| c != 0).chain([0]).collect() };
    let texte = large(&texte(erreur));
    let titre = large("Vanguard");
    // SAFETY: deux chaînes UTF-16 terminées par NUL, vivantes jusqu'au retour ; aucune fenêtre propriétaire.
    unsafe {
        MessageBoxW(core::ptr::null_mut(), texte.as_ptr(), titre.as_ptr(), MB_ICONERROR);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opengl_trop_vieux_est_dit_en_clair() {
        let t = texte("OpenGL: requires opengl 2.0+.");
        assert!(t.contains("OpenGL 2.0"), "{t}");
        assert!(t.contains("vanguard.exe"), "{t}");
        assert!(t.ends_with("requires opengl 2.0+."), "{t}");
    }

    #[test]
    fn une_autre_erreur_garde_son_detail_sans_cause_inventee() {
        let t = texte("autre panne");
        assert!(!t.contains("pilote") && !t.contains("driver"), "{t}");
        assert!(t.contains("autre panne"), "{t}");
        assert!(!t.contains("\n\n\n"), "{t}");
    }
}
