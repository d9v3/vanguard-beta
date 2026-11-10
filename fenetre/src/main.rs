//! vanguard-fenetre : la fenêtre de Vanguard. Elle lance `vanguard` (le programme posé à côté d'elle) avec une
//! commande d'une liste fermée et montre ce qu'il répond ; elle ne change rien elle-même, n'ouvre aucune connexion et
//! n'écrit aucun fichier. Options : `--langue fr|en`, `--depuis-vanguard` (dire à `vanguard` qu'elle s'est ouverte),
//! `--version`.

// Sous Windows, pas de console noire derrière la fenêtre.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod appli;
mod commandes;
mod dessin;
mod donnees;
mod lanceur;
mod langue;
mod nettoyage;
mod temps;

use std::process::ExitCode;

/// Les options lues. Une option inconnue est refusée : rien d'autre n'entre par la ligne de commande.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    langue: Option<bool>,
    depuis_vanguard: bool,
    version: bool,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut o = Options {
        langue: None,
        depuis_vanguard: false,
        version: false,
    };
    let mut args = args;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--langue" | "--lang" => match args.next().as_deref() {
                Some("fr") => o.langue = Some(false),
                Some("en") => o.langue = Some(true),
                _ => return Err("--langue : fr ou en".into()),
            },
            "--depuis-vanguard" => o.depuis_vanguard = true,
            "--version" | "-V" => o.version = true,
            autre => return Err(format!("option inconnue : {}", nettoyage::nom(autre, 40))),
        }
    }
    Ok(o)
}

fn main() -> ExitCode {
    let o = match options(std::env::args().skip(1)) {
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
    match dessin::ouvrir(lanceur::Programme::voisin(), o.depuis_vanguard) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("vanguard-fenetre : {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lire(a: &[&str]) -> Result<Options, String> {
        options(a.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn les_options_connues_seulement() {
        assert_eq!(
            lire(&[]).unwrap(),
            Options {
                langue: None,
                depuis_vanguard: false,
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
    }
}
