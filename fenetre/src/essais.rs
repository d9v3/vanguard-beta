//! Ce que partagent les essais de la fenêtre.

/// Un essai qui n'a rien vérifié le dit, et verifier.sh le compte (`VANGUARD_TESTS_SAUTES`, comme `essais::saute`
/// du programme).
#[track_caller]
pub fn sauter(raison: &str) {
    let ou = std::panic::Location::caller();
    let nom = std::thread::current().name().unwrap_or("?").to_string();
    eprintln!("essai SAUTÉ ({nom}) : {raison}");
    if let Some(fichier) = std::env::var_os("VANGUARD_TESTS_SAUTES")
        && let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(fichier)
    {
        use std::io::Write;
        let _ = writeln!(f, "{nom}\t{raison}\t{}:{}", ou.file(), ou.line());
    }
}
