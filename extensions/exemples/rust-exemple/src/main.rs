//! Exemple de plugin en Rust : deux constats inventés, puis la version du système lue par un programme lancé
//! proprement (sans shell, délai et sortie bornés).

// Un plugin n'a aucune raison d'écrire de l'`unsafe` : le compilateur le refuse.
#![forbid(unsafe_code)]

use std::time::Duration;

use vanguard_extension::{Constat, arguments, lancer, message, tr};

fn main() {
    message(tr(
        "Bonjour depuis un plugin écrit en Rust.",
        "Hello from a plugin written in Rust.",
    ));
    let args = arguments();
    if !args.is_empty() {
        message(&format!("{} {}", tr("Arguments :", "Arguments:"), args.join(" ")));
    }
    Constat::moyen(
        "Salon",
        tr(
            "Une prise connectée inventée a son port 23 ouvert.",
            "A made-up smart plug has port 23 open.",
        ),
    )
    .envoyer();
    Constat::ok(
        "Salon",
        tr("Le reste du salon va bien.", "The rest of the living room is fine."),
    )
    .envoyer();

    // Un programme du système, lancé sans shell : chaque argument arrive tel quel.
    #[cfg(windows)]
    let systeme = lancer("cmd", &["/d", "/c", "ver"], Duration::from_secs(10));
    #[cfg(not(windows))]
    let systeme = lancer("uname", &["-a"], Duration::from_secs(10));
    match systeme {
        Ok(s) if s.code == Some(0) => {
            Constat::info(tr("Système", "System"), s.sortie.trim()).envoyer();
        }
        Ok(s) => message(&format!(
            "{} {:?}",
            tr("Le programme a échoué :", "The program failed:"),
            s.code
        )),
        Err(e) => message(&format!("{} {e}", tr("Lancement impossible :", "Could not start:"))),
    }
}
