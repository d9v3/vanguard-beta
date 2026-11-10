//! La sortie de la fenêtre après « ouverte ». Lancée par `vanguard`, elle a pour sortie un tuyau que `vanguard` lit
//! jusqu'à cette ligne, puis ferme en s'arrêtant. Une écriture de plus dans ce tuyau sans lecteur (un `println!`
//! d'une bibliothèque, un jour) échouerait, et `println!` panique sur une écriture échouée : la fenêtre se fermerait.
//! La sortie est donc remplacée par le néant (/dev/null, NUL) juste après la ligne. La sortie d'erreur l'est déjà :
//! `vanguard` la donne vide (`Stdio::null`).

use std::fs::OpenOptions;

/// Remplace la sortie (descripteur 1) par /dev/null ; faux si ce n'a pas pu se faire (la sortie reste le tuyau).
#[cfg(unix)]
// raison : FFI de dup2 (libc), que std ne sait pas faire sur la sortie du processus.
#[allow(unsafe_code)]
pub fn vers_le_neant() -> bool {
    use std::os::fd::AsRawFd;
    let Ok(rien) = OpenOptions::new().write(true).open("/dev/null") else {
        return false;
    };
    // SAFETY: dup2 ne reçoit que deux numéros de descripteurs, tous deux ouverts (`rien`, gardé jusqu'après l'appel,
    // et la sortie) ; il fait du 1 une copie de /dev/null et ferme le tuyau, sans toucher à la mémoire du programme.
    unsafe { libc::dup2(rien.as_raw_fd(), libc::STDOUT_FILENO) >= 0 }
}

// FFI de kernel32 : SetStdHandle.
#[cfg(windows)]
#[allow(unsafe_code)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetStdHandle(quelle: u32, poignee: *mut std::ffi::c_void) -> i32;
}

/// Remplace la sortie du processus par NUL (std la redemande à Windows à chaque écriture) ; faux si ce n'a pas pu
/// se faire. La poignée de NUL reste ouverte jusqu'à la fin du processus : c'est désormais sa sortie.
#[cfg(windows)]
// raison : FFI de kernel32, un simple réglage du processus.
#[allow(unsafe_code)]
pub fn vers_le_neant() -> bool {
    use std::os::windows::io::IntoRawHandle;
    /// STD_OUTPUT_HANDLE, (DWORD)-11.
    const SORTIE: u32 = 0xFFFF_FFF5;
    let Ok(rien) = OpenOptions::new().write(true).open(r"\\.\NUL") else {
        return false;
    };
    // SAFETY: la poignée vient d'être ouverte et n'est plus à personne d'autre (into_raw_handle) ; SetStdHandle ne
    // fait que la noter comme sortie du processus.
    unsafe { SetStdHandle(SORTIE, rien.into_raw_handle()) != 0 }
}

#[cfg(all(test, unix))]
mod tests {
    use std::io::Write;

    /// Rejoué dans un processus à part (ce même programme d'essais, ce seul essai) : remplacer la sortie ici
    /// couperait celle du lanceur d'essais.
    #[test]
    fn apres_la_ligne_la_sortie_ne_va_plus_nulle_part() {
        if std::env::var_os("VANGUARD_FENETRE_ESSAI_SORTIE").is_some() {
            let mut s = std::io::stdout();
            let _ = s.write_all(b"TEMOIN-AVANT\n");
            let _ = s.flush();
            assert!(super::vers_le_neant());
            let _ = s.write_all(b"TEMOIN-APRES\n");
            let _ = s.flush();
            return;
        }
        let o = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sortie::tests::apres_la_ligne_la_sortie_ne_va_plus_nulle_part",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("VANGUARD_FENETRE_ESSAI_SORTIE", "1")
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&o.stdout);
        assert!(
            o.status.success(),
            "{:?} {texte} {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            texte.contains("TEMOIN-AVANT") && !texte.contains("TEMOIN-APRES"),
            "{texte}"
        );
    }
}
