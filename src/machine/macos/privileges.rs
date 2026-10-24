//! Privilèges sous macOS : fichiers de mots de passe et de jetons lisibles par d'autres comptes, sudo sans mot de
//! passe, dossiers de commandes ouverts à tous (vérifiés comme sous Linux : machine/unix.rs), compte root activé.

use std::process::Command;

use super::{Constat, alerte, maison, ok};
#[cfg(test)]
use crate::machine::unix::secret_expose;
use crate::risk::Niveau;
use crate::tr;

pub(super) fn fichiers_secrets() -> Vec<Constat> {
    crate::machine::unix::fichiers_secrets(
        &maison(),
        tr!(
            "Votre dossier personnel est lisible par les autres comptes du Mac.",
            "Your home folder is readable by the Mac's other accounts."
        ),
    )
}

pub(super) fn sudo_sans_mot_de_passe() -> Vec<Constat> {
    crate::machine::unix::sudo_sans_mot_de_passe(tr!(
        "sudo sans mot de passe pour TOUTES les commandes : n'importe quel programme lancé par vous peut prendre la main sur le Mac.",
        "sudo without a password for ALL commands: any program you run can take over the Mac."
    ))
}

/// Règles « sudo sans mot de passe » qui donnent tout, et nombre de celles limitées à des commandes précises : la forme
/// que lisent les tests de ce fichier.
#[cfg(test)]
fn regles_nopasswd(liste: &str) -> (usize, usize) {
    let (totales, limitees) = crate::machine::unix::regles_nopasswd(liste);
    (totales.len(), limitees)
}

/// Le compte root a-t-il un mot de passe (activé) ? macOS le laisse désactivé d'origine. `None` : illisible.
fn lire_root(sortie: &str, erreurs: &str) -> Option<bool> {
    if erreurs.contains("No such key") || sortie.contains("DisabledUser") {
        Some(false)
    } else if sortie.contains("ShadowHash") || sortie.contains("Kerberosv5") {
        Some(true)
    } else {
        None
    }
}

/// dscl fait foi (outil gardé, §4) : getpwnam rend « ******** » pour le mot de passe, la fiche de root dans
/// /var/db/dslocal ne se lit qu'en root, et OpenDirectory ne s'appelle qu'en Objective-C. Lancé sans shell.
pub(super) fn compte_root() -> Option<Constat> {
    let r = crate::commande::lancer(
        Command::new("dscl").args([".", "-read", "/Users/root", "AuthenticationAuthority"]),
        10,
    )?;
    Some(if lire_root(&r.sortie, &r.erreurs)? {
        alerte(
            "Comptes",
            Niveau::Moyen,
            tr!(
                "Le compte root est activé : un seul mot de passe ouvre tout le Mac, sans aucune limite.",
                "The root account is on: a single password opens the whole Mac, with no limit."
            ),
        )
        .manuel(
            tr!(
                "Désactiver root (le mot de passe d'un administrateur est demandé)",
                "Turn root off (an administrator's password is asked)"
            ),
            &["dsenableroot -d"],
        )
    } else {
        ok("Comptes", tr!("Compte root désactivé.", "Root account off."))
    })
}

/// Les dossiers de commandes du système. Seulement ceux ouverts à tous : Homebrew prend /usr/local/bin à son compte
/// sur les Mac Intel, et sudo garde le PATH de la personne (machine/unix.rs).
const DOSSIERS_DU_SYSTEME: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"];

pub(super) fn dossiers_de_commandes() -> Option<Constat> {
    crate::machine::unix::dossiers_de_commandes(DOSSIERS_DU_SYSTEME, &maison(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn droits_et_regles() {
        assert!(!secret_expose(0o100_600) && !secret_expose(0o40700));
        assert!(secret_expose(0o100_644));
        assert_eq!(regles_nopasswd("    (ALL) NOPASSWD: ALL\n"), (1, 0));
        assert_eq!(
            regles_nopasswd("    (root) NOPASSWD: /usr/bin/pmset\n    (ALL) ALL\n"),
            (0, 1)
        );
    }

    #[test]
    fn compte_root_lu() {
        assert_eq!(lire_root("", "No such key: AuthenticationAuthority"), Some(false));
        assert_eq!(
            lire_root("AuthenticationAuthority: ;DisabledUser;;ShadowHash;", ""),
            Some(false)
        );
        assert_eq!(
            lire_root(
                "AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>",
                ""
            ),
            Some(true)
        );
        assert_eq!(lire_root("", ""), None);
    }
}
