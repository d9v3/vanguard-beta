//! Pour les tests seulement : un essai qui ne peut pas tourner ici (outil du système absent, registre inaccessible,
//! root d'un espace de noms, copie d'un vrai fichier non donnée…) le dit au lieu de passer pour réussi sans rien
//! avoir vérifié. cargo test n'a pas d'état « sauté » : un test qui rend la main tôt compte comme réussi, et les
//! comparaisons « lecteur en Rust contre outil du système » ne tournent pour de vrai que sur l'ordinateur de
//! l'auteur. Chaque saut est donc écrit, s'il est demandé, dans le fichier de `VANGUARD_TESTS_SAUTES`, que
//! `outils/verifier.sh` compte et montre à côté du nombre de tests passés : « non vérifié n'est jamais compté sain »,
//! appliqué à la suite de tests. Aussi inclus par `tests/programme.rs`, par son chemin.

use std::io::Write;

/// L'essai en cours s'arrête sans rien vérifier, pour `raison` : à appeler juste avant de rendre la main
/// (`return essais::saute("pacman absent");`). Le nom du test est celui de son fil, que cargo test lui donne.
#[track_caller]
pub fn saute(raison: &str) {
    let ou = std::panic::Location::caller();
    let nom = std::thread::current().name().unwrap_or("?").to_string();
    eprintln!("essai SAUTÉ ({nom}) : {raison}");
    if let Some(fichier) = std::env::var_os("VANGUARD_TESTS_SAUTES") {
        noter(std::path::Path::new(&fichier), &nom, raison, ou);
    }
}

/// Un tube nommé (FIFO) à `chemin`, pour les essais qui vérifient qu'un lecteur ne s'y bloque pas : un seul appel à
/// mkfifo pour tous, au lieu d'un bloc `unsafe` dans chaque module essayé (dont des lecteurs fuzzés, qui n'en ont pas
/// le droit). Rend l'erreur du système si le tube n'a pas pu être créé.
#[cfg(unix)]
// FFI de libc : mkfifo n'a pas d'équivalent dans std.
#[allow(unsafe_code)]
pub fn tube_nomme(chemin: &std::path::Path) -> std::io::Result<()> {
    let c = std::ffi::CString::new(chemin.as_os_str().as_encoded_bytes())?;
    // SAFETY: mkfifo reçoit un chemin terminé par zéro, qui vit le temps de l'appel, et n'en garde rien.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Le dossier des fichiers jetables des essais, à la place du dossier temporaire du système (`temp_dir`) : `target/essais-tmp/` du dépôt,
/// que `cargo clean` vide. Le dossier temporaire du système peut avoir un quota (celui de l'ordinateur de l'auteur en
/// a un) : un essai qui y écrivait pouvait échouer pour une raison sans rapport. Un sous-dossier par système : un essai
/// sous Wine et un autre sous Linux, du même numéro de processus, ne s'y croisent pas. Sous Wine, le chemin du dépôt,
/// connu à la compilation sous Linux, passe par le lecteur Z: qui montre la racine de Linux.
pub fn temporaire() -> std::path::PathBuf {
    let depot = env!("CARGO_MANIFEST_DIR");
    #[cfg(windows)]
    let depot = match depot.strip_prefix('/') {
        Some(reste) => format!("Z:\\{}", reste.replace('/', "\\")),
        None => depot.to_string(),
    };
    let dossier = std::path::Path::new(&depot)
        .join("target")
        .join("essais-tmp")
        .join(std::env::consts::OS);
    // Un dossier qui ne peut pas être créé fait échouer l'essai à sa première écriture, avec le chemin dans l'erreur.
    let _ = std::fs::create_dir_all(&dossier);
    dossier
}

/// Une ligne par saut (nom, raison, endroit), écrite d'un seul appel en ajout : les tests tournent en parallèle, et
/// une écriture en mode ajout de cette taille ne se mélange pas avec celle d'un autre fil.
fn noter(fichier: &std::path::Path, nom: &str, raison: &str, ou: &std::panic::Location) {
    let ligne = format!("{nom}\t{raison}\t{}:{}\n", ou.file(), ou.line());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(fichier) {
        let _ = f.write_all(ligne.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    /// Le saut est écrit dans le fichier donné, à la suite des autres, avec le nom du test, la raison et l'endroit.
    /// (Sans passer par la variable, que verifier.sh pose pour tout le processus : la changer ici perdrait les sauts
    /// des tests qui tournent en même temps.)
    #[test]
    fn un_saut_est_note_avec_son_nom_et_sa_raison() {
        // Pas `reseau::dossier_local` : ce module est aussi inclus par tests/programme.rs, qui ne l'a pas.
        let dossier = super::temporaire().join(format!("vanguard-essais-sautes-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let fichier = dossier.join("sautes.txt");
        let _ = std::fs::remove_file(&fichier);
        super::noter(&fichier, "a::b", "outil d'essai absent", std::panic::Location::caller());
        super::noter(&fichier, "a::c", "pas en root", std::panic::Location::caller());
        let lu = std::fs::read_to_string(&fichier).unwrap();
        let lignes: Vec<&str> = lu.lines().collect();
        assert_eq!(lignes.len(), 2, "{lu}");
        assert!(lignes[0].starts_with("a::b\toutil d'essai absent\t"), "{lu}");
        // Le chemin du fichier tel que le compilateur l'a reçu : « src/essais.rs », ou avec \ sous Windows.
        assert!(lignes[0].contains("essais.rs:"), "{lu}");
        assert!(lignes[1].starts_with("a::c\tpas en root\t"), "{lu}");
        let _ = std::fs::remove_dir_all(&dossier);
    }

    /// B-6 de la relecture des correctifs c6 : les fichiers jetables des essais vont sous `target/` du dépôt, jamais
    /// dans le dossier temporaire du système ; ils s'y écrivent.
    #[test]
    fn les_fichiers_jetables_restent_dans_le_depot() {
        let d = super::temporaire();
        let fin = std::path::Path::new("target/essais-tmp").join(std::env::consts::OS);
        assert!(d.is_absolute() && d.ends_with(&fin), "{}", d.display());
        // Sous Wine, le dépôt est vu par Z: : la fin du chemin suffit.
        #[cfg(not(windows))]
        assert_eq!(d, std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(&fin));
        assert!(!d.starts_with(std::env::temp_dir()), "{}", d.display());
        let f = d.join(format!("essai-{}", std::process::id()));
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"x");
        let _ = std::fs::remove_file(&f);
    }
}
