//! La sortie standard réservée à un protocole (la porte de lecture des assistants d'IA, `porte_mcp`) : une copie à
//! soi du descripteur, puis la vraie sortie standard tournée vers le néant. Un `println!` égaré, d'un module qui ne
//! sait pas qu'il parle dans un protocole, ne glisse plus une ligne au milieu des réponses. Et le processus hors des
//! vidages et des lectures de mémoire par un autre programme du compte (`PR_SET_DUMPABLE`), sous Linux.

// FFI : dup2 et prctl sous Linux, SetStdHandle sous Windows, sans équivalent sûr dans std.
#![allow(unsafe_code)]

use std::fs::File;
use std::io;

/// Rend une copie de la sortie standard, à soi, et tourne la vraie vers le néant (/dev/null, NUL).
#[cfg(unix)]
pub(crate) fn garder_stdout() -> io::Result<File> {
    use std::os::fd::{AsFd as _, AsRawFd as _};
    let copie = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let neant = File::options().write(true).open("/dev/null")?;
    // SAFETY: deux descripteurs ouverts, tenus le temps de l'appel ; dup2 ne touche aucune mémoire de Vanguard.
    if unsafe { libc::dup2(neant.as_raw_fd(), libc::STDOUT_FILENO) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(copie)
}

/// Rend une copie de la sortie standard, à soi, et tourne la vraie vers NUL : std relit `GetStdHandle` à chaque
/// écriture, un `println!` égaré y part donc.
#[cfg(windows)]
pub(crate) fn garder_stdout() -> io::Result<File> {
    use std::os::windows::io::{AsHandle as _, IntoRawHandle as _};
    let copie = File::from(io::stdout().as_handle().try_clone_to_owned()?);
    let neant = File::options().write(true).open("NUL")?;
    // La poignée sort du `File` sans être fermée : elle reste ouverte pour toute la vie du processus.
    let poignee = windows::Win32::Foundation::HANDLE(neant.into_raw_handle());
    // SAFETY: une poignée ouverte, à soi, jamais fermée ; SetStdHandle ne fait que la retenir.
    unsafe {
        windows::Win32::System::Console::SetStdHandle(windows::Win32::System::Console::STD_OUTPUT_HANDLE, poignee)
    }
    .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(copie)
}

/// Le processus hors des vidages, et sa mémoire hors de portée de ptrace par un autre programme du compte (Linux).
/// Sous Windows, rien : un programme du même compte y lit la mémoire d'un autre ; le modèle de menace le dit.
pub(crate) fn hors_des_vidages() {
    #[cfg(target_os = "linux")]
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) ne prend aucun pointeur ; un échec laisse le processus tel quel.
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}
