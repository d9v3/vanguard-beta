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

/// Le dossier jetable d'un essai qui lance un faux `vanguard` : `essais-fenetre/<nom>-<pid>`, à côté du programme
/// d'essai, donc dans le vrai dossier de compilation. Le chemin est résolu (ni lien ni « .. ») : le garde du lanceur
/// refuse, à raison, un chemin dont un dossier est un lien, et `target` en est un quand la compilation se fait sur un
/// autre disque. Le garde n'est pas assoupli pour les essais : ce sont eux qui lui donnent un vrai chemin. Le dossier
/// n'est pas créé ici.
#[cfg(unix)]
// Un module d'essais : y planter est la façon d'échouer (la règle anti-panique vise le programme).
#[allow(clippy::expect_used)]
pub fn banc(nom: &str) -> std::path::PathBuf {
    let programme = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .expect("le chemin du programme d'essai");
    // …/debug/deps/vanguard_fenetre-… : le dossier du profil (debug), sinon celui du programme.
    let deps = programme.parent().expect("le dossier du programme d'essai");
    let profil = deps.parent().unwrap_or(deps);
    profil
        .join("essais-fenetre")
        .join(format!("{nom}-{}", std::process::id()))
}
