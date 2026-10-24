//! Mises à jour sous macOS : le système (softwareupdate), les programmes Homebrew et ceux de l'App Store (mas).

use super::super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Une mise à jour proposée par `softwareupdate -l` : son étiquette et sa version.
#[derive(Debug, PartialEq)]
struct MiseAJour {
    etiquette: String,
    version: Option<String>,
}

/// Mises à jour de `softwareupdate -l` : « * Label: macOS Tahoe 26.7.1-25G241 », suivie de « Title: …, Version:
/// 26.7.1, … ». La réponse « No new software available. » arrive sur la sortie d'erreur.
fn lire_softwareupdate(texte: &str) -> Option<Vec<MiseAJour>> {
    if texte.contains("No new software available") {
        return Some(Vec::new());
    }
    let mut liste: Vec<MiseAJour> = Vec::new();
    for l in texte.lines().map(str::trim) {
        if let Some(etiquette) = l.strip_prefix("* Label:") {
            liste.push(MiseAJour {
                etiquette: etiquette.trim().to_string(),
                version: None,
            });
        } else if let (Some(derniere), Some((_, reste))) = (liste.last_mut(), l.split_once("Version:")) {
            derniere.version = reste.split(',').next().map(|v| v.trim().to_string());
        }
    }
    (!liste.is_empty() || texte.contains("Software Update found")).then_some(liste)
}

/// Passage à une nouvelle version majeure de macOS (26 → 27) : ce n'est pas une mise à jour de sécurité, c'est un
/// nouveau système, à installer quand on veut, après une sauvegarde.
fn mise_a_niveau(m: &MiseAJour, majeure_actuelle: u32) -> bool {
    m.etiquette.starts_with("macOS")
        && m.version
            .as_deref()
            .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
            .is_some_and(|majeure| majeure > majeure_actuelle)
}

pub fn mises_a_jour() -> Vec<Constat> {
    // La recherche interroge les serveurs d'Apple : jusqu'à une ou deux minutes.
    let Some(r) = crate::commande::lancer(std::process::Command::new("softwareupdate").arg("-l"), 180) else {
        return vec![impossible(
            "Mises à jour",
            tr!("softwareupdate sans réponse", "softwareupdate did not answer"),
        )];
    };
    let Some(liste) = lire_softwareupdate(&format!("{}\n{}", r.sortie, r.erreurs)) else {
        return vec![impossible(
            "Mises à jour",
            tr!("hors ligne ou réponse illisible", "offline or unreadable answer"),
        )];
    };
    let majeure_actuelle = super::version_systeme("ProductVersion")
        .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
        .unwrap_or(u32::MAX);
    let (niveaux, mises): (Vec<MiseAJour>, Vec<MiseAJour>) =
        liste.into_iter().partition(|m| mise_a_niveau(m, majeure_actuelle));
    let mut constats = Vec::new();
    if mises.is_empty() {
        constats.push(ok("Mises à jour", tr!("macOS est à jour.", "macOS is up to date.")));
    } else {
        let noms: Vec<&str> = mises.iter().map(|m| m.etiquette.as_str()).collect();
        // Par leur étiquette : « --all » installerait aussi une nouvelle version majeure de macOS.
        let commande = format!(
            "sudo softwareupdate --install {}",
            noms.iter()
                .map(|n| crate::commande::sh_chaine(n))
                .collect::<Vec<_>>()
                .join(" ")
        );
        constats.push(
            alerte(
                "Mises à jour",
                Niveau::Eleve,
                trf!(
                    "{} mise(s) à jour d'Apple en attente : {}. Elles corrigent souvent des failles déjà exploitées.",
                    "{} Apple update(s) waiting: {}. They often fix flaws already being exploited.",
                    noms.len(),
                    noms.join(", ")
                ),
            )
            .corriger(
                tr!(
                    "Installer ces mises à jour d'Apple (un redémarrage peut être demandé)",
                    "Install these Apple updates (a restart may be needed)"
                ),
                &[commande],
            ),
        );
    }
    for n in niveaux {
        let version = n.version.unwrap_or_default();
        constats.push(
            alerte(
                "Mises à jour",
                Niveau::Info,
                trf!(
                    "macOS {version} est disponible : une nouvelle version du système, pas une simple mise à jour. À installer quand vous voulez, après une sauvegarde.",
                    "macOS {version} is available: a new version of the system, not just an update. Install it when you like, after a backup."
                ),
            )
            .manuel(
                tr!(
                    "Réglages Système > Général > Mise à jour de logiciels > Mettre à niveau",
                    "System Settings > General > Software Update > Upgrade Now"
                ),
                &[],
            ),
        );
    }
    constats
}

/// Programmes Homebrew et App Store en retard. `None` sans Homebrew ni mas.
pub fn homebrew_a_jour() -> Vec<Constat> {
    let mut constats = Vec::new();
    if let Some(brew) = super::homebrew() {
        let r = crate::commande::lancer(std::process::Command::new(brew).args(["outdated", "--quiet"]), 120);
        match r {
            Some(r) if r.code == Some(0) => {
                let paquets: Vec<&str> = r.sortie.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
                constats.push(if paquets.is_empty() {
                    ok(
                        "Homebrew",
                        tr!("Programmes Homebrew à jour.", "Homebrew programs up to date."),
                    )
                } else {
                    alerte(
                        "Homebrew",
                        Niveau::Moyen,
                        trf!(
                            "{} programme(s) Homebrew à mettre à jour : {}.",
                            "{} Homebrew program(s) to update: {}.",
                            paquets.len(),
                            paquets.join(", ")
                        ),
                    )
                    .corriger(
                        tr!("Mettre à jour les programmes Homebrew", "Update the Homebrew programs"),
                        &[format!("{brew} update && {brew} upgrade")],
                    )
                });
            }
            _ => constats.push(impossible(
                "Homebrew",
                tr!("brew outdated a échoué", "brew outdated failed"),
            )),
        }
    }
    // mas : l'App Store en ligne de commande, s'il est installé (brew install mas).
    if let Some(r) = crate::commande::lancer(std::process::Command::new("mas").arg("outdated"), 60)
        && r.code == Some(0)
    {
        let apps: Vec<String> = r
            .sortie
            .lines()
            .filter_map(|l| {
                // « 497799835 Xcode (15.3 -> 15.4) » : le nom est entre l'identifiant et la parenthèse.
                let (_, reste) = l.trim().split_once(' ')?;
                Some(reste.rsplit_once(" (").map_or(reste, |(n, _)| n).trim().to_string())
            })
            .collect();
        if !apps.is_empty() {
            constats.push(
                alerte(
                    "Programmes",
                    Niveau::Moyen,
                    trf!(
                        "{} app(s) de l'App Store à mettre à jour : {}.",
                        "{} App Store app(s) to update: {}.",
                        apps.len(),
                        apps.join(", ")
                    ),
                )
                .corriger(
                    tr!("Mettre à jour les apps de l'App Store", "Update the App Store apps"),
                    &["mas upgrade"],
                ),
            );
        }
    }
    constats
}

/// `vanguard mises-a-jour` : système, Homebrew, App Store. `seulement` limite aux catégories qu'on vient d'installer.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let systeme = voulu(&["Mises à jour"]).then(|| portee.spawn(mises_a_jour));
        let programmes = voulu(&["Homebrew", "Programmes"]).then(|| portee.spawn(homebrew_a_jour));
        let mut constats: Vec<Constat> = systeme
            .map(|t| {
                t.join().unwrap_or_else(|_| {
                    vec![impossible(
                        "Mises à jour",
                        tr!("vérification interrompue", "check interrupted"),
                    )]
                })
            })
            .unwrap_or_default();
        constats.extend(programmes.map(|t| t.join().unwrap_or_default()).unwrap_or_default());
        constats
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_de_softwareupdate() {
        let attente = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n\
                       * Label: macOS Tahoe 26.7.1-25G241\n\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 1234567KiB, Recommended: YES, Action: restart,\n\
                       * Label: macOS 27.0.1-26A434\n\tTitle: macOS 27.0.1, Version: 27.0.1, Size: 9999999KiB, Recommended: YES, Action: restart,\n\
                       * Label: Safari27.0TahoeAuto-27.0\n";
        let liste = lire_softwareupdate(attente).unwrap();
        assert_eq!(liste.len(), 3);
        assert_eq!(liste[0].version.as_deref(), Some("26.7.1"));
        assert_eq!(liste[2].version, None);
        assert!(!mise_a_niveau(&liste[0], 26));
        assert!(mise_a_niveau(&liste[1], 26));
        assert!(!mise_a_niveau(&liste[2], 26));
        assert_eq!(
            lire_softwareupdate("Software Update Tool\n\nFinding available software\nNo new software available.\n"),
            Some(Vec::new())
        );
        assert_eq!(
            lire_softwareupdate("Software Update Tool\n\nFinding available software\n"),
            None
        );
    }
}
