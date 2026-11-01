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

/// Le dossier des fichiers jetables des essais, à la place du dossier temporaire du système (`temp_dir`) :
/// `essais-tmp/` dans le dossier de compilation de cargo, celui de `CARGO_TARGET_DIR` s'il était donné à la compilation
/// (`livrer-branche.sh`, `/verifier`), sinon `target/` du dépôt ; `cargo clean` le vide. Le dossier temporaire du
/// système peut avoir un quota (celui de l'ordinateur de l'auteur en a un) : un essai qui y écrivait pouvait échouer
/// pour une raison sans rapport. Un sous-dossier par système : un essai sous Wine et un autre sous Linux, du même
/// numéro de processus, ne s'y croisent pas. Sous Wine, le chemin, connu à la compilation sous Linux, passe par le
/// lecteur Z: qui montre la racine de Linux. Au premier appel, les restes de plus d'un jour (essai interrompu ou qui
/// a paniqué avant de nettoyer) en sont retirés : une série qui tourne en même temps, elle, n'y perd rien.
/// Chaque lancement y a son sous-dossier (`lancement`).
pub fn temporaire() -> std::path::PathBuf {
    static PURGE: std::sync::Once = std::sync::Once::new();
    let depot = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // Relatif, cargo le lit depuis le dossier où il est lancé : celui du dépôt, en pratique.
    let cible = option_env!("CARGO_TARGET_DIR").map_or_else(|| depot.join("target"), |c| depot.join(c));
    #[cfg(windows)]
    let cible = match cible.to_str().and_then(|c| c.strip_prefix('/')) {
        Some(reste) => std::path::PathBuf::from(format!("Z:\\{}", reste.replace('/', "\\"))),
        None => cible,
    };
    let systeme = cible.join("essais-tmp").join(std::env::consts::OS);
    let dossier = systeme.join(lancement());
    // Un dossier qui ne peut pas être créé fait échouer l'essai à sa première écriture, avec le chemin dans l'erreur.
    let _ = std::fs::create_dir_all(&dossier);
    PURGE.call_once(|| purger_vieux(&systeme, std::time::Duration::from_hours(24)));
    dossier
}

/// Ce lancement-ci, une fois pour tout le processus : son numéro et l'heure de son premier appel. Le numéro seul ne
/// suffit pas : sous Wine, chaque série reçoit le même (un préfixe neuf numérote toujours pareil), et le retrait à la
/// sortie (`atexit`) n'y a pas lieu ; la série suivante reprenait alors les fichiers de la précédente (un journal
/// d'événements déjà écrit, des alertes en double ; verifier.sh n°7 du lot T10).
fn lancement() -> &'static str {
    static LANCEMENT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    LANCEMENT.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("lancement-{:x}-{nanos:x}", std::process::id())
    })
}

/// Un nom de dossier ou de fichier jetable qu'aucun autre essai ne prend : `vanguard-<nom>-<processus>-<n>`. Deux
/// essais du même processus (les tests tournent en parallèle) qui donnaient le même nom se partageaient le dossier,
/// et l'un pouvait effacer ou rendre illisible celui de l'autre.
pub fn nom_unique(nom: &str) -> String {
    static COMPTE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COMPTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("vanguard-{nom}-{}-{n}", std::process::id())
}

/// Un dossier jetable d'essai, neuf, sous `temporaire()`, retiré avec tout son contenu quand l'essai le lâche, même
/// sur une assertion qui échoue (la panique déroule la pile), et même si l'essai a retiré ses droits à un dossier
/// qu'il contient.
pub struct Jetable(std::path::PathBuf);

impl Jetable {
    /// Un dossier neuf, au nom unique (`nom_unique`).
    pub fn nouveau(nom: &str) -> Jetable {
        Jetable::garder(temporaire().join(nom_unique(nom)))
    }

    /// Prend en charge un dossier déjà nommé par l'essai : vidé s'il existait, créé, retiré à la fin.
    pub fn garder(chemin: std::path::PathBuf) -> Jetable {
        retirer(&chemin);
        // Comme `temporaire` : l'erreur se verra à la première écriture, avec le chemin.
        let _ = std::fs::create_dir_all(&chemin);
        Jetable(chemin)
    }
}

impl std::ops::Deref for Jetable {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl AsRef<std::path::Path> for Jetable {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Jetable {
    fn drop(&mut self) {
        retirer(&self.0);
    }
}

/// Retire un fichier ou un dossier jetable et tout ce qu'il contient, après avoir rendu leurs droits aux dossiers
/// qu'un essai a fermés (mode 000) : sans cela, `remove_dir_all` s'y arrêtait et le reste durait. Un lien symbolique
/// est retiré, jamais suivi.
pub fn retirer(chemin: &std::path::Path) {
    rouvrir(chemin, 0);
    match std::fs::symlink_metadata(chemin) {
        Ok(m) if m.is_dir() => {
            let _ = std::fs::remove_dir_all(chemin);
        }
        Ok(_) => {
            let _ = std::fs::remove_file(chemin);
        }
        Err(_) => {}
    }
}

/// Rend lecture, écriture et parcours au propriétaire, sur chaque dossier de l'arbre (pas sur les liens, ni à travers
/// eux), à 64 niveaux au plus : les essais n'en font jamais autant.
fn rouvrir(chemin: &std::path::Path, profondeur: usize) {
    let Ok(m) = std::fs::symlink_metadata(chemin) else {
        return;
    };
    if !m.is_dir() || profondeur > 64 {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o700 != 0o700 {
            let _ = std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o700));
        }
    }
    if let Ok(entrees) = std::fs::read_dir(chemin) {
        for e in entrees.flatten() {
            rouvrir(&e.path(), profondeur.saturating_add(1));
        }
    }
}

/// Retire de `dossier` ce qui n'a pas changé depuis `age` : les restes d'une série d'essais d'avant. Le dossier est
/// partagé par les séries qui tournent en même temps (Linux, Wine, la suite refaite sans Internet, `tests/programme.rs`) :
/// le vider en entier au premier appel effacerait leurs fichiers en cours.
fn purger_vieux(dossier: &std::path::Path, age: std::time::Duration) {
    let Some(limite) = std::time::SystemTime::now().checked_sub(age) else {
        return;
    };
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for e in entrees.flatten() {
        let vieux = e.metadata().and_then(|m| m.modified()).is_ok_and(|t| t < limite);
        if vieux {
            retirer(&e.path());
        }
    }
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

    /// B-6 de la relecture des correctifs c6 : les fichiers jetables des essais vont sous le dossier de compilation
    /// de cargo, jamais dans le dossier temporaire du système ; ils s'y écrivent. M-1 de la relecture des restes c6 :
    /// celui de `CARGO_TARGET_DIR` quand il est donné (`livrer-branche.sh`), plus `target/` du dépôt à côté.
    #[test]
    fn les_fichiers_jetables_restent_dans_le_dossier_de_compilation() {
        let d = super::temporaire();
        let fin = std::path::Path::new("essais-tmp").join(std::env::consts::OS);
        // Un sous-dossier par lancement (T10, verifier.sh n°7) : jamais celui d'une série précédente.
        assert!(
            d.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("lancement-"))
        );
        assert_eq!(super::temporaire(), d, "le même pour tout le processus");
        let d = d.parent().unwrap().to_path_buf();
        assert!(d.is_absolute() && d.ends_with(&fin), "{}", d.display());
        // Sous Wine, le dépôt est vu par Z: : la fin du chemin suffit.
        #[cfg(not(windows))]
        {
            let depot = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
            let cible = option_env!("CARGO_TARGET_DIR").map_or_else(|| depot.join("target"), |c| depot.join(c));
            assert_eq!(d, cible.join(&fin));
        }
        assert!(!d.starts_with(std::env::temp_dir()), "{}", d.display());
        let f = super::temporaire().join(super::nom_unique("ecrit"));
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"x");
        let _ = std::fs::remove_file(&f);
    }

    /// M-1 : un dossier jetable disparaît à la fin de l'essai, même quand l'essai a fermé (mode 000) un dossier
    /// qu'il contient, même sur une panique, et sans suivre un lien vers un dossier qui doit rester.
    #[test]
    fn un_jetable_est_retire_avec_ce_qu_il_contient() {
        let garde = super::Jetable::nouveau("garde-temoin");
        std::fs::write(garde.join("temoin"), b"reste").unwrap();
        let chemin = {
            let d = super::Jetable::nouveau("jetable-ferme");
            let ferme = d.join("ferme");
            std::fs::create_dir_all(ferme.join("sous")).unwrap();
            std::fs::write(ferme.join("sous").join("f"), b"x").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::os::unix::fs::symlink(&*garde, d.join("lien")).unwrap();
                std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o000)).unwrap();
            }
            d.to_path_buf()
        };
        assert!(
            std::fs::symlink_metadata(&chemin).is_err(),
            "{} reste",
            chemin.display()
        );
        assert_eq!(std::fs::read(garde.join("temoin")).unwrap(), b"reste");
        let paniquee = std::panic::catch_unwind(|| {
            let d = super::Jetable::nouveau("jetable-panique");
            std::fs::write(d.join("f"), b"x").unwrap();
            std::panic::panic_any(d.to_path_buf());
        });
        let chemin = paniquee.unwrap_err().downcast::<std::path::PathBuf>().unwrap();
        assert!(
            std::fs::symlink_metadata(&*chemin).is_err(),
            "{} reste",
            chemin.display()
        );
    }

    /// M-2 : deux noms jetables demandés pareils, dans le même processus, ne donnent jamais le même dossier.
    #[test]
    fn deux_noms_jetables_ne_se_croisent_pas() {
        let a = super::nom_unique("illisible");
        let b = super::nom_unique("illisible");
        assert_ne!(a, b);
        assert!(
            a.starts_with(&format!("vanguard-illisible-{}-", std::process::id())),
            "{a}"
        );
    }

    /// M-1 : les restes d'une série d'avant (plus vieux que l'âge donné), même fermés en mode 000, sont retirés ;
    /// un dossier récent, qui peut être celui d'une série en cours, reste.
    #[cfg(unix)]
    #[test]
    fn les_vieux_restes_sont_purges() {
        use std::os::unix::fs::PermissionsExt;
        let racine = super::Jetable::nouveau("purge");
        let vieux = racine.join("vieux");
        std::fs::create_dir_all(vieux.join("ferme")).unwrap();
        std::fs::write(vieux.join("ferme").join("f"), b"x").unwrap();
        std::fs::set_permissions(vieux.join("ferme"), std::fs::Permissions::from_mode(0o000)).unwrap();
        let il_y_a_deux_jours = std::time::SystemTime::now() - std::time::Duration::from_hours(48);
        std::fs::File::open(&vieux)
            .unwrap()
            .set_modified(il_y_a_deux_jours)
            .unwrap();
        let recent = racine.join("recent");
        std::fs::create_dir_all(&recent).unwrap();
        super::purger_vieux(&racine, std::time::Duration::from_hours(24));
        assert!(std::fs::symlink_metadata(&vieux).is_err(), "le vieux reste reste");
        assert!(recent.is_dir(), "le dossier récent a été retiré");
    }
}
