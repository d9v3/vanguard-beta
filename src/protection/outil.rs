//! Outils externes que Vanguard lance quand ils sont installés (trivy ; gitleaks en complément) : trouvés dans le PATH, ou là où
//! winget les pose sous Windows, et proposés à l'installation après accord, par l'outil du système. Vanguard ne
//! télécharge jamais un programme lui-même : la distribution, Homebrew ou winget en répondent.

use std::path::PathBuf;

use crate::ui::*;

/// Où un outil se trouve dans les dépôts des distributions Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Linux {
    /// Seulement dans ceux d'Arch : ailleurs, il faut le dépôt de son auteur, que Vanguard n'ajoute pas tout seul.
    Arch,
}

/// Un outil externe : son nom de programme (et de paquet), sa présentation, et où l'obtenir.
pub(crate) struct Externe {
    pub nom: &'static str,
    pub presentation: (&'static str, &'static str),
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub linux: Linux,
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub brew: &'static str,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub winget: &'static str,
    pub site: &'static str,
}

/// Le programme, dans le PATH ou, sous Windows, dans le dossier de liens de winget : juste après une installation, le
/// PATH de ce programme ne le connaît pas encore.
pub(crate) fn trouver(nom: &str) -> Option<PathBuf> {
    let fichier = if cfg!(windows) {
        format!("{nom}.exe")
    } else {
        nom.to_string()
    };
    let mut dossiers: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    if cfg!(windows) {
        for (variable, sous) in [
            ("LOCALAPPDATA", r"Microsoft\WinGet\Links"),
            ("ProgramFiles", r"WinGet\Links"),
        ] {
            dossiers.extend(std::env::var_os(variable).map(|d| PathBuf::from(d).join(sous)));
        }
    }
    dossiers.into_iter().map(|d| d.join(&fichier)).find(|f| f.is_file())
}

/// La commande qui installe l'outil sur ce système ; `None` s'il n'y en a pas d'officielle ici.
#[cfg_attr(windows, allow(clippy::unnecessary_wraps))] // winget toujours là ; ailleurs, parfois aucune commande
fn commande_d_installation(e: &Externe) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        use crate::machine::linux::Paquets;
        let gestionnaire = Paquets::detecter()?;
        match (&e.linux, gestionnaire) {
            (Linux::Arch, g @ Paquets::Pacman) => Some(g.installer(e.nom)),
            (Linux::Arch, _) => None,
        }
    }
    #[cfg(target_os = "macos")]
    {
        crate::machine::macos::homebrew().map(|brew| format!("{brew} install {}", e.brew))
    }
    #[cfg(windows)]
    {
        Some(format!(
            "winget install --id {} -e --source winget --accept-source-agreements --accept-package-agreements",
            e.winget
        ))
    }
}

/// Propose d'installer l'outil, montre la commande, et ne fait rien sans accord. Le programme s'il est là ensuite.
pub(crate) fn proposer(e: &Externe) -> Option<PathBuf> {
    println!(
        "  {}",
        if crate::langue::anglais() {
            e.presentation.1
        } else {
            e.presentation.0
        }
    );
    let Some(commande) = commande_d_installation(e) else {
        println!(
            "  {}",
            trf!(
                "Installez-le comme l'explique son site ({}), puis relancez.",
                "Install it as its site explains ({}), then run again.",
                e.site
            )
        );
        return None;
    };
    println!("  {GRIS}{commande}{RESET}");
    if !demander_ou_defaut(tr!("  L'installer maintenant ? [o/N] : ", "  Install it now? [y/N]: ")).oui() {
        return None;
    }
    // Au premier plan : sudo ou winget peuvent poser une question. Par le lanceur des corrections sous Linux et
    // macOS, noté dans « Ce que Vanguard a changé » ; winget reste hors de la fenêtre administrateur, et se note à part.
    #[cfg(unix)]
    let fait = crate::machine::appliquer(std::slice::from_ref(&commande));
    #[cfg(windows)]
    let fait = {
        let ok = crate::machine::windows::winget()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            .and_then(|w| {
                std::process::Command::new(w)
                    .args(commande.split_whitespace().skip(1))
                    .status()
            })
            .is_ok_and(|s| s.success());
        crate::changements::noter(&[vec![commande.clone()]], &[ok]);
        ok
    };
    if !fait {
        println!(
            "  {}",
            trf!(
                "✖ Installation impossible : voir son site ({}).",
                "✖ Installation failed: see its site ({}).",
                e.site
            )
        );
        return None;
    }
    let trouve = trouver(e.nom);
    if trouve.is_none() {
        trp!(
            "  ✖ Installé, mais pas encore trouvé : relancez Vanguard.",
            "  ✖ Installed, but not found yet: restart Vanguard."
        );
    }
    trouve
}

/// Un chemin à montrer : le dossier personnel abrégé en « ~ », et rien qui puisse piloter le terminal.
pub(crate) fn chemin_affiche(chemin: &std::path::Path, maison: &std::path::Path) -> String {
    let texte = match chemin.strip_prefix(maison) {
        Ok(reste) if !reste.as_os_str().is_empty() => format!("~/{}", reste.display()),
        Ok(_) => "~".to_string(),
        Err(_) => chemin.display().to_string(),
    };
    affichable(&texte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemins_abreges() {
        let maison = std::path::Path::new("/home/alice");
        assert_eq!(
            chemin_affiche(std::path::Path::new("/home/alice/projets/site"), maison),
            "~/projets/site"
        );
        assert_eq!(chemin_affiche(maison, maison), "~");
        assert_eq!(chemin_affiche(std::path::Path::new("/srv/depot"), maison), "/srv/depot");
        // Un nom de dossier piégé ne pilote pas le terminal.
        assert!(!chemin_affiche(std::path::Path::new("/home/alice/\x1b[2Jx"), maison).contains('\x1b'));
    }
}
