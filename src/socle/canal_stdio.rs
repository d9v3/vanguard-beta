//! La sortie standard réservée à un protocole (la porte de lecture des assistants d'IA, `porte_mcp`) : une copie à
//! soi du descripteur, puis la vraie sortie standard tournée vers le néant. Un `println!` égaré, d'un module qui ne
//! sait pas qu'il parle dans un protocole, ne glisse plus une ligne au milieu des réponses. Et le processus hors des
//! vidages et des lectures de mémoire par un autre programme du compte (`PR_SET_DUMPABLE`), sous Linux.

// FFI : dup2 et prctl sous Linux, SetStdHandle sous Windows, sans équivalent sûr dans std.
#![allow(unsafe_code)]

use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};

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

/// Levé par un signal d'arrêt, une fois `fin_sur_signal` posé.
#[cfg(target_os = "linux")]
static ARRET: AtomicBool = AtomicBool::new(false);

// Le gestionnaire ne fait qu'une écriture atomique sans verrou : sûre dans un signal.
#[cfg(target_os = "linux")]
extern "C" fn sur_signal(_signal: libc::c_int) {
    ARRET.store(true, Ordering::SeqCst);
}

/// Les signaux d'arrêt (SIGTERM, SIGINT, SIGHUP) ne tuent plus le processus : ils lèvent le drapeau rendu, que la
/// session lit à chaque pas et qui la finit proprement, notée. Un gestionnaire plutôt qu'un masque : les fils de
/// tokio, nés avant, ne l'auraient pas. SIGKILL ne s'attrape pas : la note d'ouverture, écrite avant la première
/// réponse, reste alors seule.
#[cfg(target_os = "linux")]
pub(crate) fn fin_sur_signal() -> io::Result<&'static AtomicBool> {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: sigaction n'a que des entiers et des pointeurs, valide à zéro ; son masque est vidé juste après.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        // sigaction prend le gestionnaire comme un entier (sighandler_t) : seul `as` convertit un pointeur de fonction.
        #[expect(
            clippy::as_conversions,
            reason = "pointeur de fonction vers sighandler_t, la forme de l'ABI de sigaction"
        )]
        {
            action.sa_sigaction = sur_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        }
        action.sa_flags = libc::SA_RESTART;
        // SAFETY: `action` est à nous, vivant pendant les appels ; le gestionnaire ne fait qu'une écriture atomique ;
        // l'ancienne action n'est pas demandée (null).
        let r = unsafe {
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaction(signal, &raw const action, std::ptr::null_mut())
        };
        if r != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(&ARRET)
}

/// Un plafond de taille de fichier abaissé pendant la session (`prlimit --pid`) envoie SIGXFSZ, qui tuerait le
/// processus au milieu d'une écriture du journal, sans la défaire. Ignoré, il fait rendre à l'écriture l'erreur
/// EFBIG : la porte remet alors le segment à sa taille d'avant et sa tête sans annonce.
#[cfg(target_os = "linux")]
pub(crate) fn depassement_de_taille_ignore() -> io::Result<()> {
    // SAFETY: sigaction est une structure C sans invariant : tout à zéro est valide (masque vide, aucun drapeau).
    let mut ignore: libc::sigaction = unsafe { std::mem::zeroed() };
    ignore.sa_sigaction = libc::SIG_IGN;
    // SAFETY: un pointeur vers une structure vivante de la pile, le temps de l'appel ; l'ancienne action n'est pas
    // demandée (null) ; SIG_IGN ne fait tourner aucun code dans un gestionnaire.
    if unsafe { libc::sigaction(libc::SIGXFSZ, &raw const ignore, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    /// A-FREIN-1 : SIGXFSZ ignoré, une écriture au-delà du plafond rend une erreur au lieu de tuer le processus.
    #[test]
    fn le_depassement_de_taille_ne_tue_plus() {
        assert!(super::depassement_de_taille_ignore().is_ok());
        // SAFETY: tout à zéro est valide pour sigaction (voir plus haut).
        let mut vue: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: lecture seule (aucune nouvelle disposition) dans une structure vivante de la pile.
        let lu = unsafe { libc::sigaction(libc::SIGXFSZ, std::ptr::null(), &raw mut vue) };
        assert_eq!(lu, 0);
        assert_eq!(vue.sa_sigaction, libc::SIG_IGN);
    }
}
