//! Lent depuis une mise à jour : les dernières mises à jour installées, datées, et comment revenir en arrière avec
//! l'outil du système (point de restauration ou désinstallation d'une mise à jour sous Windows, instantané btrfs
//! sous Linux avec snapper ou Timeshift). Vanguard ne revient en arrière sur rien lui-même :
//! il montre, puis ouvre l'outil si on le veut.

use super::{Etat, conseil};
use crate::ui::*;

/// Une mise à jour installée : « AAAA-MM-JJ », et ce qu'elle a changé.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Maj {
    pub date: String,
    pub quoi: String,
}

/// pacman.log : « [2026-10-18T21:40:23-0400] `[ALPM]` upgraded mise-bin (2026.10.12-1 -> 2026.10.13-1) », les plus
/// récentes en tête, au plus `n`.
#[cfg(any(target_os = "linux", test))]
fn lire_pacman(journal: &str, n: usize) -> Vec<Maj> {
    journal
        .lines()
        .rev()
        .filter_map(|l| {
            let (date, reste) = l.strip_prefix('[')?.split_once(']')?;
            let paquet = reste.trim().strip_prefix("[ALPM] upgraded ")?;
            Some(Maj {
                date: date.get(..10)?.to_string(),
                quoi: affichable(paquet.trim()),
            })
        })
        .take(n)
        .collect()
}

/// apt history.log : des blocs « Start-Date: 2026-10-18  21:40:23 » puis « Upgrade: a (1 -> 2), b (…) ».
#[cfg(any(target_os = "linux", test))]
fn lire_apt(journal: &str, n: usize) -> Vec<Maj> {
    let mut majs = Vec::new();
    let mut date = String::new();
    for l in journal.lines() {
        if let Some(d) = l.strip_prefix("Start-Date:") {
            date = d.trim().get(..10).unwrap_or_default().to_string();
        } else if let Some(liste) = l.strip_prefix("Upgrade:") {
            for paquet in liste.split("), ") {
                let paquet = paquet.trim().trim_end_matches(')');
                if !paquet.is_empty() {
                    majs.push(Maj {
                        date: date.clone(),
                        quoi: affichable(&format!("{paquet})")),
                    });
                }
            }
        }
    }
    majs.into_iter().rev().take(n).collect()
}

#[cfg(target_os = "linux")]
fn recentes() -> Vec<Maj> {
    if let Ok(t) = std::fs::read_to_string("/var/log/pacman.log") {
        return lire_pacman(&t, 12);
    }
    std::fs::read_to_string("/var/log/apt/history.log")
        .map(|t| lire_apt(&t, 12))
        .unwrap_or_default()
}

/// Windows : les mises à jour de Windows (KB) les plus récentes.
#[cfg(windows)]
fn recentes() -> Vec<Maj> {
    // WMI d'abord (la classe que lit Get-HotFix), PowerShell en secours.
    if let Some(c) = crate::machine::windows::correctifs::installes() {
        return c
            .iter()
            .take(8)
            .map(|c| Maj {
                date: c.date.format("%Y-%m-%d").to_string(),
                quoi: affichable(format!("{} {}", c.numero, c.description).trim()),
            })
            .collect();
    }
    crate::machine::windows::ps(
        "Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 8 | \
         ForEach-Object { \"MAJ|$($_.InstalledOn.ToString('yyyy-MM-dd'))|$($_.HotFixID) $($_.Description)\" }; 'MAJ_FIN'",
    )
    .and_then(|s| {
        crate::commande::section(Some(&s), "MAJ").map(|l| {
            l.iter()
                .filter_map(|l| {
                    let (date, quoi) = l.split_once('|')?;
                    Some(Maj {
                        date: date.trim().to_string(),
                        quoi: affichable(quoi.trim()),
                    })
                })
                .collect()
        })
    })
    .unwrap_or_default()
}

/// Comment revenir en arrière sur ce système.
fn retour_arriere() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Revenir en arrière : Paramètres › Windows Update › Historique › Désinstaller des mises à jour (la plus récente d'abord), ou un point de restauration d'avant la mise à jour (Vanguard peut ouvrir l'outil).",
            "Go back: Settings › Windows Update › History › Uninstall updates (the latest first), or a restore point from before the update (Vanguard can open the tool)."
        )
    } else if std::path::Path::new("/usr/bin/snapper").exists() {
        tr!(
            "Revenir en arrière : un instantané d'avant la mise à jour (snapper) se choisit au démarrage, dans le menu du chargeur ; « snapper list » les montre. Sinon, l'ancienne version d'un paquet se réinstalle depuis le cache du gestionnaire.",
            "Go back: a snapshot from before the update (snapper) is chosen at boot, in the boot loader menu; “snapper list” shows them. Otherwise the previous version of a package is reinstalled from the package manager's cache."
        )
    } else {
        tr!(
            "Revenir en arrière : un instantané Timeshift d'avant la mise à jour, s'il y en a ; sinon l'ancienne version d'un paquet se réinstalle depuis le cache du gestionnaire. Le noyau précédent reste souvent au menu de démarrage.",
            "Go back: a Timeshift snapshot from before the update, if there is one; otherwise the previous version of a package is reinstalled from the package manager's cache. The previous kernel often stays in the boot menu."
        )
    }
}

/// Dans « L'ordinateur est lent » › « Depuis peu » : les dernières mises à jour et le retour en arrière.
pub(super) fn apres_mise_a_jour() {
    section(tr!("DERNIÈRES MISES À JOUR", "LATEST UPDATES"));
    let majs = recentes();
    if majs.is_empty() {
        Etat::Info.dire(tr!(
            "Les dernières mises à jour ne se lisent pas ici.",
            "The latest updates cannot be read here."
        ));
    }
    for m in &majs {
        afficher_aligne(&format!("  {GRIS}{}{RESET}  ", m.date), &m.quoi, 14, "");
    }
    conseil(retour_arriere());
    #[cfg(windows)]
    super::proposer_outil(
        tr!(
            "\n  Ouvrir les points de restauration de Windows ? [o/N] : ",
            "\n  Open Windows restore points? [y/N]: "
        ),
        || {
            let _ = crate::commande::systeme("rstrui.exe").spawn();
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journaux_des_mises_a_jour() {
        let pacman = "[2026-10-17T22:48:30-0400] [ALPM] upgraded zed (1.18.1-1 -> 1.24.3-1)\n\
                      [2026-10-17T22:49:00-0400] [ALPM] installed foo (1.0-1)\n\
                      [2026-10-18T21:40:23-0400] [ALPM] upgraded mise-bin (2026.10.12-1 -> 2026.10.13-1)\n\
                      [2026-10-18T21:42:30-0400] [ALPM] running 'x.hook'...\n";
        let m = lire_pacman(pacman, 5);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].date, "2026-10-18");
        assert!(m[0].quoi.starts_with("mise-bin"));
        assert_eq!(lire_pacman(pacman, 1).len(), 1);
        let apt = "Start-Date: 2026-10-10  09:00:01\nCommandline: apt upgrade\n\
                   Upgrade: firefox:amd64 (130.0, 131.0), libc6:amd64 (2.39-1, 2.39-2)\nEnd-Date: 2026-10-10  09:01:00\n";
        let m = lire_apt(apt, 5);
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].date, "2026-10-10");
        assert_eq!(m[0].quoi, "libc6:amd64 (2.39-1, 2.39-2)");
        assert_eq!(m[1].quoi, "firefox:amd64 (130.0, 131.0)");
    }
}
