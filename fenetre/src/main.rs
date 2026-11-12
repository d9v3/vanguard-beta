//! vanguard-fenetre : la fenêtre de Vanguard. Elle lance `vanguard` (le programme posé à côté d'elle) avec une
//! commande d'une liste fermée et montre ce qu'il répond ; elle ne change rien elle-même, n'ouvre aucune connexion et
//! n'écrit aucun fichier. Le seul changement qu'elle peut demander, un programme retiré du démarrage ou remis, passe
//! par une confirmation dans la fenêtre puis par `vanguard`, qui le rejuge (`appli.rs`). Options : `--langue fr|en`,
//! `--depuis-vanguard` (dire à `vanguard` qu'elle s'est ouverte), `--vanguard <chemin absolu>` (le programme à lancer,
//! donné par `vanguard` qui la lance d'une copie en mémoire : elle n'a alors plus de dossier), `--version`.

// Sous Windows, pas de console noire derrière la fenêtre.
#![cfg_attr(not(test), windows_subsystem = "windows")]
// Un fil se crée par std::thread::Builder, son refus rendu (clippy.toml, `disallowed-methods`) ; dans les essais,
// un fil refusé fait échouer l'essai.
#![cfg_attr(test, allow(clippy::disallowed_methods))]

mod appli;
#[cfg(test)]
mod attaques;
#[cfg(any(windows, test))]
mod avis;
#[cfg(target_os = "linux")]
mod bac_a_sable;
#[cfg(windows)]
mod chargement;
mod commandes;
mod console;
mod couleurs;
mod coulisses;
mod dessin;
mod donnees;
#[cfg(all(test, target_os = "linux"))]
mod essais;
mod lanceur;
mod langue;
mod nettoyage;
mod progression;
#[cfg(target_os = "linux")]
mod protocole;
#[cfg(target_os = "linux")]
mod relais;
mod sortie;
mod temps;
#[cfg(windows)]
mod travail;

use std::process::ExitCode;

/// Les options lues. Une option inconnue est refusée : rien d'autre n'entre par la ligne de commande.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    langue: Option<bool>,
    depuis_vanguard: bool,
    vanguard: Option<std::path::PathBuf>,
    version: bool,
}

/// Les arguments en `OsString` : un chemin d'installation aux octets non UTF-8 (`--vanguard`) passe tel quel, et
/// une option illisible est refusée comme inconnue, jamais une panique (`std::env::args` en ferait une).
fn options(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Options, String> {
    let mut o = Options {
        langue: None,
        depuis_vanguard: false,
        vanguard: None,
        version: false,
    };
    let mut args = args;
    while let Some(a) = args.next() {
        let Some(a) = a.to_str() else {
            let lu = a.to_string_lossy();
            return Err(format!("option inconnue : {}", nettoyage::nom(&lu, 40)));
        };
        match a {
            "--langue" | "--lang" => match args.next().as_deref().and_then(std::ffi::OsStr::to_str) {
                Some("fr") => o.langue = Some(false),
                Some("en") => o.langue = Some(true),
                _ => return Err("--langue : fr ou en".into()),
            },
            "--depuis-vanguard" => o.depuis_vanguard = true,
            // Un chemin absolu, une fois : il remplace « à côté de la fenêtre », avec la même garde (`lanceur`).
            "--vanguard" => match args.next().map(std::path::PathBuf::from) {
                Some(c) if c.is_absolute() && o.vanguard.is_none() => o.vanguard = Some(c),
                _ => return Err("--vanguard : un chemin absolu, une fois".into()),
            },
            "--version" | "-V" => o.version = true,
            autre => return Err(format!("option inconnue : {}", nettoyage::nom(autre, 40))),
        }
    }
    Ok(o)
}

fn main() -> ExitCode {
    // Avant tout le reste : une DLL posée à côté du programme (clé USB, Téléchargements) n'est jamais chargée.
    #[cfg(windows)]
    if !chargement::system32_seulement() {
        let e = "SetDefaultDllDirectories refusé";
        eprintln!("vanguard-fenetre : {e}, la fenêtre ne s'ouvre pas");
        if !std::env::args_os().any(|a| a == "--depuis-vanguard") {
            avis::montrer(e);
        }
        return ExitCode::FAILURE;
    }
    let o = match options(std::env::args_os().skip(1)) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("vanguard-fenetre : {e}");
            return ExitCode::from(2);
        }
    };
    if o.version {
        println!("vanguard-fenetre {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    langue::choisir(o.langue);
    if let Some(c) = o.vanguard {
        lanceur::designer(c);
    }
    // Avant le premier fil et la première bibliothèque d'affichage : le relais part à côté avec les droits du compte,
    // la fenêtre entre dans son bac à sable (`relais`, `bac_a_sable`).
    #[cfg(target_os = "linux")]
    relais::separer();
    match dessin::ouvrir(lanceur::Programme::voisin(), o.depuis_vanguard) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vanguard-fenetre : {e}");
            #[cfg(windows)]
            if !o.depuis_vanguard {
                avis::montrer(&e);
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lire(a: &[&str]) -> Result<Options, String> {
        options(a.iter().map(std::ffi::OsString::from))
    }

    #[test]
    fn les_options_connues_seulement() {
        assert_eq!(
            lire(&[]).unwrap(),
            Options {
                langue: None,
                depuis_vanguard: false,
                vanguard: None,
                version: false
            }
        );
        assert_eq!(
            lire(&["--langue", "en", "--depuis-vanguard"]).unwrap().langue,
            Some(true)
        );
        assert!(lire(&["--depuis-vanguard"]).unwrap().depuis_vanguard);
        assert!(lire(&["--langue"]).is_err());
        assert!(lire(&["--langue", "de"]).is_err());
        assert!(lire(&["audit"]).is_err());
        assert!(lire(&["--commande", "x"]).is_err());
        // Le programme à lancer : un chemin absolu, une seule fois.
        assert_eq!(
            lire(&["--vanguard", "/opt/v/vanguard"]).unwrap().vanguard.as_deref(),
            Some(std::path::Path::new("/opt/v/vanguard"))
        );
        assert!(lire(&["--vanguard"]).is_err());
        assert!(lire(&["--vanguard", "vanguard"]).is_err());
        assert!(lire(&["--vanguard", "/a/vanguard", "--vanguard", "/b/vanguard"]).is_err());
    }

    /// L4 (relecture 0.96) : un dossier d'installation au nom non UTF-8 arrive en octets bruts dans `--vanguard` ;
    /// la fenêtre paniquait en lisant ses arguments. Le chemin passe tel quel, une option illisible est refusée.
    #[test]
    fn un_argument_non_utf8_n_arrete_pas_la_fenetre() {
        #[cfg(unix)]
        let (chemin, illisible) = {
            use std::os::unix::ffi::OsStrExt;
            (
                std::ffi::OsStr::from_bytes(b"/opt/v\xff/vanguard").to_os_string(),
                std::ffi::OsStr::from_bytes(b"--\xff").to_os_string(),
            )
        };
        #[cfg(windows)]
        let (chemin, illisible) = {
            use std::os::windows::ffi::OsStringExt;
            let mut c: Vec<u16> = "C:\\v".encode_utf16().collect();
            c.push(0xD800);
            c.extend("\\vanguard.exe".encode_utf16());
            (
                std::ffi::OsString::from_wide(&c),
                std::ffi::OsString::from_wide(&[0x2D, 0x2D, 0xD800]),
            )
        };
        let o = options(["--vanguard".into(), chemin.clone()].into_iter()).unwrap();
        assert_eq!(o.vanguard.as_deref(), Some(std::path::Path::new(&chemin)));
        assert!(options([illisible].into_iter()).is_err());
        assert!(options(["--langue".into(), chemin].into_iter()).is_err());
    }
}
