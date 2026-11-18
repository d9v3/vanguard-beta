//! vanguard-fenetre : la fenêtre de Vanguard. Elle lance `vanguard` (le programme posé à côté d'elle) avec une
//! commande d'une liste fermée et montre ce qu'il répond ; elle ne change rien elle-même, n'ouvre aucune connexion et
//! n'écrit aucun fichier. Le seul changement qu'elle peut demander, un programme retiré du démarrage ou remis, passe
//! par une confirmation dans la fenêtre puis par `vanguard`, qui le rejuge (`appli.rs`). Options : `--langue fr|en`,
//! `--depuis-vanguard` (dire à `vanguard` qu'elle s'est ouverte), `--vanguard <chemin absolu>` (le programme à lancer,
//! donné par `vanguard` qui la lance d'une copie en mémoire : elle n'a alors plus de dossier) avec
//! `--empreinte-vanguard <SHA-256>` (l'empreinte que ses octets doivent avoir à chaque lancement), `--version`.

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
#[cfg(target_os = "linux")]
mod memfd;
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
// La valeur tapée après le nom d'une commande de la console : le fichier de `vanguard console`, compilé ici à
// l'identique (une seule règle des deux côtés). Le jugement des chemins réels n'y sert qu'au relais (Linux).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[path = "../../src/socle/valeur_console.rs"]
mod valeur;

use std::process::ExitCode;

/// Les options lues. Une option inconnue est refusée : rien d'autre n'entre par la ligne de commande.
#[derive(Debug, PartialEq, Eq)]
struct Options {
    langue: Option<bool>,
    depuis_vanguard: bool,
    vanguard: Option<std::path::PathBuf>,
    empreinte: Option<[u8; 32]>,
    version: bool,
}

/// Les arguments en `OsString` : un chemin d'installation aux octets non UTF-8 (`--vanguard`) passe tel quel, et
/// une option illisible est refusée comme inconnue, jamais une panique (`std::env::args` en ferait une).
fn options(args: impl Iterator<Item = std::ffi::OsString>) -> Result<Options, String> {
    let mut o = Options {
        langue: None,
        depuis_vanguard: false,
        vanguard: None,
        empreinte: None,
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
            // 64 chiffres hexadécimaux minuscules, une fois, ce que `vanguard` écrit (src/demarrage/lancer_fenetre.rs) :
            // rien d'autre n'est lu comme une empreinte.
            "--empreinte-vanguard" => match args.next().as_deref().and_then(std::ffi::OsStr::to_str).and_then(hex) {
                Some(e) if o.empreinte.is_none() => o.empreinte = Some(e),
                _ => return Err("--empreinte-vanguard : 64 chiffres hexadécimaux minuscules, une fois".into()),
            },
            "--version" | "-V" => o.version = true,
            autre => return Err(format!("option inconnue : {}", nettoyage::nom(autre, 40))),
        }
    }
    // L'un ne va pas sans l'autre : un `vanguard` désigné sans empreinte serait relancé sur la foi de son chemin
    // (L2 de la relecture 0.96), et une empreinte seule ne désigne rien.
    if o.vanguard.is_some() != o.empreinte.is_some() {
        return Err("--vanguard et --empreinte-vanguard vont ensemble".into());
    }
    Ok(o)
}

/// Une empreinte SHA-256 écrite en 64 chiffres hexadécimaux minuscules, sinon rien.
fn hex(texte: &str) -> Option<[u8; 32]> {
    let chiffre = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let octets = texte.as_bytes();
    if octets.len() != 64 {
        return None;
    }
    let (paires, reste) = octets.as_chunks::<2>();
    if !reste.is_empty() {
        return None;
    }
    let mut e = [0u8; 32];
    for (sortie, [fort, faible]) in e.iter_mut().zip(paires) {
        *sortie = (chiffre(*fort)? << 4) | chiffre(*faible)?;
    }
    Some(e)
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
    // Le `vanguard` à relancer et l'empreinte qu'il doit avoir, retenus avant le relais (qui en hérite) : donnés par
    // `vanguard`, sinon le voisin lu maintenant.
    match (o.vanguard, o.empreinte) {
        (Some(c), Some(e)) => lanceur::designer(c, e),
        _ => lanceur::epingler_voisin(),
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
                empreinte: None,
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
        // Le programme à lancer : un chemin absolu, une seule fois, avec son empreinte.
        assert_eq!(
            lire(&["--vanguard", "/opt/v/vanguard", "--empreinte-vanguard", EMPREINTE])
                .unwrap()
                .vanguard
                .as_deref(),
            Some(std::path::Path::new("/opt/v/vanguard"))
        );
        assert!(lire(&["--vanguard", "--empreinte-vanguard", EMPREINTE]).is_err());
        assert!(lire(&["--vanguard", "vanguard", "--empreinte-vanguard", EMPREINTE]).is_err());
        assert!(
            lire(&[
                "--vanguard",
                "/a/vanguard",
                "--vanguard",
                "/b/vanguard",
                "--empreinte-vanguard",
                EMPREINTE
            ])
            .is_err()
        );
    }

    /// Une empreinte faite pour l'essai : 0x01, 0x23, …, 0xef, quatre fois.
    const EMPREINTE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// L2 (relecture 0.96) : `--vanguard` sans `--empreinte-vanguard`, ou une empreinte absente, mal formée, en
    /// double ou sans `--vanguard`, est refusé net : la fenêtre ne s'ouvre pas, elle ne relance jamais un chemin sur
    /// sa seule foi.
    #[test]
    fn l_empreinte_de_vanguard_va_avec_son_chemin() {
        let o = lire(&["--vanguard", "/opt/v/vanguard", "--empreinte-vanguard", EMPREINTE]).unwrap();
        let mut attendue = [0u8; 32];
        for (i, o) in attendue.iter_mut().enumerate() {
            *o = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef][i % 8];
        }
        assert_eq!(o.empreinte, Some(attendue));
        // Absente.
        assert!(lire(&["--vanguard", "/opt/v/vanguard"]).is_err(), "sans empreinte");
        assert!(lire(&["--vanguard", "/opt/v/vanguard", "--empreinte-vanguard"]).is_err());
        // Seule.
        assert!(lire(&["--empreinte-vanguard", EMPREINTE]).is_err(), "sans --vanguard");
        // Mal formée : trop courte, trop longue, en majuscules, un signe qui n'est pas un chiffre, vide.
        let v = |e: &str| lire(&["--vanguard", "/opt/v/vanguard", "--empreinte-vanguard", e]);
        assert!(v(&EMPREINTE[..62]).is_err());
        assert!(v(&format!("{EMPREINTE}00")).is_err());
        assert!(v(&EMPREINTE.to_uppercase()).is_err());
        assert!(v(&format!("{}g", &EMPREINTE[..63])).is_err());
        assert!(v(&format!("{}é", &EMPREINTE[..62])).is_err());
        assert!(v("").is_err());
        // Deux fois, même égales.
        assert!(
            lire(&[
                "--vanguard",
                "/opt/v/vanguard",
                "--empreinte-vanguard",
                EMPREINTE,
                "--empreinte-vanguard",
                EMPREINTE
            ])
            .is_err()
        );
        // Ce que `vanguard` écrit (hexadécimal minuscule) est relu à l'identique.
        let ecrite = attendue.iter().fold(String::new(), |mut t, o| {
            use std::fmt::Write;
            let _ = write!(t, "{o:02x}");
            t
        });
        assert_eq!(hex(&ecrite), Some(attendue));
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
        let o = options(
            [
                "--vanguard".into(),
                chemin.clone(),
                "--empreinte-vanguard".into(),
                EMPREINTE.into(),
            ]
            .into_iter(),
        )
        .unwrap();
        assert_eq!(o.vanguard.as_deref(), Some(std::path::Path::new(&chemin)));
        assert!(options([illisible].into_iter()).is_err());
        assert!(options(["--langue".into(), chemin].into_iter()).is_err());
    }
}
