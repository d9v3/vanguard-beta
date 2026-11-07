//! La minuterie du compte qui relance « vanguard garde maj » une fois par jour tant que le garde est posé : les listes
//! CERTAIN (MalwareBazaar, base de ClamAV) se rafraîchissent sans y penser. Posée avec le garde, retirée avec lui ; le
//! service ne part que si l'unité du garde est là (ConditionPathExists), et sous le compte seulement (P22) : il ne
//! touche jamais au garde lui-même, qui relit les listes de lui-même.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::path::PathBuf;

use crate::machine::linux::dbus::actions::{Geste, utilisateur};
use crate::trf;

/// Le nom des deux unités (.service, .timer).
pub(crate) const NOM: &str = "vanguard-garde-maj";

/// Les textes des deux unités : le service, puis la minuterie.
pub(crate) fn unites(exe: &str) -> (String, String) {
    // Chemin entre guillemets (un dossier personnel peut contenir une espace), « % » doublé (spécificateurs systemd).
    let exe = format!("\"{}\"", exe.replace('%', "%%").replace('"', "\\\""));
    let garde = super::FICHIER_UNITE;
    (
        trf!(
            "[Unit]\nDescription=Vanguard : listes du garde des lancements\nConditionPathExists={garde}\n\n[Service]\nType=oneshot\nExecStart={exe} garde maj\nNice=10\n",
            "[Unit]\nDescription=Vanguard: launch guard lists\nConditionPathExists={garde}\n\n[Service]\nType=oneshot\nExecStart={exe} garde maj\nNice=10\n"
        ),
        trf!(
            "[Unit]\nDescription=Vanguard : listes du garde, une fois par jour\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
            "[Unit]\nDescription=Vanguard: guard lists, once a day\n\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n"
        ),
    )
}

fn fichiers() -> [PathBuf; 2] {
    let d = crate::reseau::surveillance::dossier_unites_maison();
    [d.join(format!("{NOM}.service")), d.join(format!("{NOM}.timer"))]
}

/// Une des deux unités est-elle là ?
pub(crate) fn posee() -> bool {
    fichiers().iter().any(|f| std::fs::symlink_metadata(f).is_ok())
}

/// Écrit les deux unités et active la minuterie. Faux si quelque chose a manqué.
pub(crate) fn poser() -> bool {
    let Some(exe) = crate::reseau::surveillance::executable() else {
        return false;
    };
    let [service, minuterie] = fichiers();
    let Some(dossier) = service.parent() else {
        return false;
    };
    let (texte_service, texte_minuterie) = unites(&exe);
    std::fs::create_dir_all(dossier).is_ok()
        && crate::socle::ecrire_atomique(&service, texte_service.as_bytes()).is_ok()
        && crate::socle::ecrire_atomique(&minuterie, texte_minuterie.as_bytes()).is_ok()
        && utilisateur(Geste::Recharger, "")
        && utilisateur(Geste::Activer { maintenant: true }, &format!("{NOM}.timer"))
}

/// Arrête la minuterie et efface les deux unités. Vrai si plus rien n'est là.
pub(crate) fn retirer() -> bool {
    if !posee() {
        return true;
    }
    let _ = utilisateur(Geste::Desactiver { maintenant: true }, &format!("{NOM}.timer"));
    let _ = crate::reseau::surveillance::retirer_fichiers(&fichiers());
    let _ = utilisateur(Geste::Recharger, "");
    !posee()
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_jour_sous_le_compte_seulement_si_le_garde_est_pose() {
        let (service, minuterie) = unites("/home/alice/.local/share/vanguard/bin/van%guard \"x\"");
        assert!(service.contains("ExecStart=\"/home/alice/.local/share/vanguard/bin/van%%guard \\\"x\\\"\" garde maj"));
        assert!(service.contains(&format!("ConditionPathExists={}", super::super::FICHIER_UNITE)));
        assert!(service.contains("Type=oneshot"));
        // Sous le compte : ni User=, ni le service du garde.
        for interdit in ["User=", "garde-servir"] {
            assert!(!service.contains(interdit), "{interdit}");
        }
        assert!(minuterie.contains("OnCalendar=daily") && minuterie.contains("Persistent=true"));
        assert!(minuterie.contains("WantedBy=timers.target"));
    }
}
