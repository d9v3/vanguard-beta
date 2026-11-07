//! R7 : l'effacement des copies de secours, l'étape qui rend le chiffrement irréversible (MITRE T1490). Fonction
//! pure : elle lit le nom et la ligne de commande d'un programme et dit, en une phrase bilingue, quelle copie il
//! efface — ou `None`. Rien n'est lancé ici.

use crate::machine::chasse::EnMarche;
use crate::machine::regles::Os;

/// Ce que l'effacement des copies touche, en français et en anglais ; `None` si le programme n'en efface pas.
/// `os` : sous Windows, un processus non élevé peut ne voir que le NOM de l'outil (vssadmin.exe…), pas sa ligne de
/// commande ; le nom seul suffit alors, car ces outils ont peu d'usages hors d'une suppression (score.rs décide de
/// la gravité selon la rafale). Sous Linux, on exige le verbe de suppression dans la ligne.
pub(crate) fn effacement(p: &EnMarche, os: Os) -> Option<(&'static str, &'static str)> {
    let nom = crate::machine::chasse::nom_de_fichier(&p.nom).to_ascii_lowercase();
    let nom = nom.strip_suffix(".exe").unwrap_or(&nom);
    let ligne = p.ligne.as_deref().unwrap_or("").to_ascii_lowercase();
    match os {
        Os::Windows => effacement_windows(nom, &ligne),
        Os::Linux => effacement_linux(nom, &ligne),
        Os::Tous => effacement_windows(nom, &ligne).or_else(|| effacement_linux(nom, &ligne)),
    }
}

fn effacement_windows(nom: &str, ligne: &str) -> Option<(&'static str, &'static str)> {
    // Le nom seul des outils typiques, même sans ligne de commande lisible.
    let outils = [
        (
            "vssadmin",
            "efface les copies cachées de Windows (vssadmin)",
            "is deleting Windows shadow copies (vssadmin)",
        ),
        (
            "wbadmin",
            "efface le catalogue de sauvegarde de Windows (wbadmin)",
            "is deleting the Windows backup catalog (wbadmin)",
        ),
        (
            "bcdedit",
            "coupe la réparation au démarrage de Windows (bcdedit)",
            "is disabling Windows startup recovery (bcdedit)",
        ),
        (
            "diskshadow",
            "efface les copies cachées de Windows (diskshadow)",
            "is deleting Windows shadow copies (diskshadow)",
        ),
    ];
    for (outil, fr, en) in outils {
        if nom == outil {
            return Some((fr, en));
        }
    }
    // wmic shadowcopy delete, ou PowerShell Win32_ShadowCopy …Delete() : par la ligne de commande.
    if (nom == "wmic" && ligne.contains("shadowcopy") && ligne.contains("delete"))
        || (ligne.contains("win32_shadowcopy") && ligne.contains("delete"))
    {
        return Some((
            "efface les copies cachées de Windows (wmic)",
            "is deleting Windows shadow copies (wmic)",
        ));
    }
    None
}

fn effacement_linux(nom: &str, ligne: &str) -> Option<(&'static str, &'static str)> {
    if nom == "snapper" && ligne.contains("delete") {
        return Some(("efface un instantané snapper", "is deleting a snapper snapshot"));
    }
    if nom == "btrfs" && ligne.contains("subvolume") && ligne.contains("delete") {
        return Some(("efface un sous-volume btrfs", "is deleting a btrfs subvolume"));
    }
    if nom == "timeshift" && (ligne.contains("--delete") || ligne.contains("--delete-all")) {
        return Some(("efface une sauvegarde Timeshift", "is deleting a Timeshift snapshot"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog(nom: &str, ligne: &str) -> EnMarche {
        EnMarche {
            nom: nom.to_string(),
            ligne: (!ligne.is_empty()).then(|| ligne.to_string()),
            ..EnMarche::default()
        }
    }

    #[test]
    fn t1490_windows() {
        assert!(effacement(&prog("vssadmin.exe", ""), Os::Windows).is_some());
        assert!(effacement(&prog("VSSADMIN.EXE", "delete shadows /all /quiet"), Os::Windows).is_some());
        assert!(effacement(&prog("wbadmin.exe", "delete catalog -quiet"), Os::Windows).is_some());
        assert!(
            effacement(
                &prog(r"C:\Windows\System32\bcdedit.exe", "/set recoveryenabled no"),
                Os::Windows
            )
            .is_some()
        );
        assert!(effacement(&prog("wmic.exe", "shadowcopy delete"), Os::Windows).is_some());
        assert!(
            effacement(
                &prog("powershell.exe", "Get-WmiObject Win32_ShadowCopy | % { $_.Delete() }"),
                Os::Windows
            )
            .is_some()
        );
        assert!(effacement(&prog("notepad.exe", "fichier.txt"), Os::Windows).is_none());
        // wmic sans suppression : pas R7.
        assert!(effacement(&prog("wmic.exe", "shadowcopy list"), Os::Windows).is_none());
    }

    #[test]
    fn t1490_linux() {
        assert!(effacement(&prog("snapper", "delete 42"), Os::Linux).is_some());
        assert!(effacement(&prog("btrfs", "subvolume delete /.snapshots/1"), Os::Linux).is_some());
        assert!(effacement(&prog("timeshift", "--delete --snapshot 2024"), Os::Linux).is_some());
        assert!(effacement(&prog("snapper", "list"), Os::Linux).is_none());
        assert!(effacement(&prog("rm", "-rf /tmp/x"), Os::Linux).is_none());
    }
}
