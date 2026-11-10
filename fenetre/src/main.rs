//! vanguard-fenetre : la fenêtre de Vanguard. Elle lance `vanguard` (le programme posé à côté d'elle) avec une
//! commande d'une liste fermée et montre ce qu'il répond ; elle ne change rien elle-même, n'ouvre aucune connexion et
//! n'écrit aucun fichier. Le seul changement qu'elle peut demander, un programme retiré du démarrage ou remis, passe
//! par une confirmation dans la fenêtre puis par `vanguard`, qui le rejuge (`appli.rs`). Options : `--langue fr|en`,
//! `--depuis-vanguard` (dire à `vanguard` qu'elle s'est ouverte), `--version`.

// Sous Windows, pas de console noire derrière la fenêtre.
#![cfg_attr(not(test), windows_subsystem = "windows")]

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
mod coulisses;
mod dessin;
mod donnees;
#[cfg(all(test, target_os = "linux"))]
mod essais;
mod lanceur;
mod langue;
mod nettoyage;
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
    // Avant tout le reste : une DLL posée à côté du programme (clé USB, Téléchargements) n'est jamais chargée.
    #[cfg(windows)]
    if !chargement::system32_seulement() {
        let e = "SetDefaultDllDirectories refusé";
        eprintln!("vanguard-fenetre : {e}, la fenêtre ne s'ouvre pas");
        if !std::env::args().any(|a| a == "--depuis-vanguard") {
            avis::montrer(e);
        }
        return ExitCode::FAILURE;
    }
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
