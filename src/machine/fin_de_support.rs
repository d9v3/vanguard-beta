//! Fin de support : ce qui ne reçoit plus de corrections de sécurité. Le système lui-même (Windows 10 depuis le
//! 14 octobre 2025, les premières versions de Windows 11, les macOS de plus de trois ans) et les programmes que leur
//! éditeur a abandonnés (Flash, Silverlight, QuickTime pour Windows, Java 6 et 7, Office 2016 et plus anciens…) : leurs
//! failles ne seront jamais corrigées. Les navigateurs installés à part (Windows, macOS) sont jugés par les logiciels
//! pas à jour (`protection::perimes`), qui comparent leur version à la dernière publiée ; quand elle ne se compare
//! pas, ils reprennent d'ici l'âge du fichier (`age_jours`, `constat_navigateur`) : un seul constat par navigateur.
//! Sous Linux, le gestionnaire de paquets tient tout cela : seuls Python 2 et le greffon Flash sont cherchés.

use super::{Constat, alerte};
use crate::risk::Niveau;
use crate::{tr, trf};

const CAT: &str = "Fin de support";
/// Au-delà, un navigateur qui se met à jour toutes les quatre semaines a cessé de le faire.
#[cfg(any(windows, target_os = "macos", test))]
pub(crate) const NAVIGATEUR_JOURS: u64 = 60;

/// Un programme abandonné : un morceau de son nom (en minuscules, tel que l'affiche la liste des programmes), le nom
/// montré, et l'année de sa dernière correction.
const ABANDONNES: &[(&str, &str, u16)] = &[
    ("adobe flash player", "Adobe Flash Player", 2020),
    ("adobe shockwave player", "Adobe Shockwave Player", 2019),
    ("microsoft silverlight", "Microsoft Silverlight", 2021),
    ("quicktime", "QuickTime pour Windows", 2016),
    ("java(tm) 6", "Java 6", 2018),
    ("java 6 update", "Java 6", 2018),
    ("java(tm) 7", "Java 7", 2022),
    ("java 7 update", "Java 7", 2022),
    ("adobe reader 9", "Adobe Reader 9", 2013),
    ("adobe reader x ", "Adobe Reader X", 2015),
    ("adobe reader xi", "Adobe Reader XI", 2017),
    ("adobe acrobat xi", "Adobe Acrobat XI", 2017),
    ("microsoft office 2007", "Microsoft Office 2007", 2017),
    ("microsoft office 2010", "Microsoft Office 2010", 2020),
    ("microsoft office 2013", "Microsoft Office 2013", 2023),
    ("microsoft office 2016", "Microsoft Office 2016", 2025),
    ("microsoft office 2019", "Microsoft Office 2019", 2025),
    ("python 2.", "Python 2", 2020),
    ("windows live essentials", "Windows Essentials", 2017),
];

/// Les programmes abandonnés parmi ces noms (liste des programmes installés), chacun une fois.
fn abandonnes(noms: &[String]) -> Vec<(&'static str, u16)> {
    let mut trouves: Vec<(&'static str, u16)> = Vec::new();
    for nom in noms {
        let bas = format!("{} ", nom.to_lowercase());
        for &(motif, montre, annee) in ABANDONNES {
            if bas.contains(motif) && !trouves.iter().any(|(m, _)| *m == montre) {
                trouves.push((montre, annee));
            }
        }
    }
    trouves
}

fn constat_abandonne(nom: &str, annee: u16) -> Constat {
    alerte(
        CAT,
        Niveau::Moyen,
        trf!(
            "« {nom} » n'est plus corrigé par son éditeur depuis {annee} : ses failles connues ne le seront jamais.",
            "“{nom}” has not been fixed by its publisher since {annee}: its known flaws never will be."
        ),
    )
    .manuel(
        if cfg!(windows) {
            tr!(
                "Le désinstaller (Paramètres › Applications), ou le remplacer par sa version actuelle",
                "Uninstall it (Settings › Apps), or replace it with its current version"
            )
        } else {
            tr!(
                "Le désinstaller, ou le remplacer par sa version actuelle",
                "Uninstall it, or replace it with its current version"
            )
        },
        &[],
    )
}

/// Un navigateur installé à part, pas mis à jour depuis `jours`.
#[cfg_attr(target_os = "linux", allow(dead_code))] // sous Linux, le gestionnaire de paquets s'en charge
pub(crate) fn constat_navigateur(nom: &str, jours: u64) -> Constat {
    alerte(
        "Navigateur",
        Niveau::Moyen,
        trf!(
            "{nom} n'a pas été mis à jour depuis {jours} jours, alors qu'il l'est toutes les quatre semaines : sa mise à jour automatique ne se fait plus, et chaque faille corrigée depuis reste ouverte chez vous.",
            "{nom} has not been updated for {jours} days, though it is every four weeks: its automatic update no longer happens, and every flaw fixed since stays open here."
        ),
    )
    .manuel(
        tr!(
            "L'ouvrir, puis Menu › Aide › À propos : la mise à jour se lance ; sinon le réinstaller depuis son site",
            "Open it, then Menu › Help › About: the update starts; otherwise reinstall it from its site"
        ),
        &[],
    )
}

/// Âge en jours d'un fichier (sa date de modification : celle de la version installée).
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn age_jours(chemin: &std::path::Path) -> Option<u64> {
    let m = std::fs::metadata(chemin).ok()?.modified().ok()?;
    Some(std::time::SystemTime::now().duration_since(m).ok()?.as_secs() / 86_400)
}

// ───────────────────────────── Le système ─────────────────────────────

/// Windows : la fin du support d'après le numéro de build et l'édition. Windows 10 (build < 22000) : plus rien depuis
/// le 14 octobre 2025 (seules les entreprises inscrites aux mises à jour étendues en reçoivent encore). Windows 11 :
/// chaque version est corrigée 24 mois (Famille, Professionnel) ou 36 mois (Entreprise, Éducation).
#[cfg(any(windows, test))]
fn systeme_windows(build: u32, edition: &str) -> Option<Constat> {
    let longue = ["enterprise", "education", "iot"]
        .iter()
        .any(|e| edition.to_lowercase().contains(e));
    // (build, nom, fin pour Famille et Professionnel, fin pour Entreprise et Éducation)
    let fins: &[(u32, &str, &str, &str)] = &[
        (22000, "Windows 11 21H2", "2023-10-10", "2024-10-08"),
        (22621, "Windows 11 22H2", "2024-10-08", "2025-10-14"),
        (22631, "Windows 11 23H2", "2025-11-11", "2026-11-10"),
    ];
    if build < 22000 {
        return Some(
            alerte(
                CAT,
                Niveau::Eleve,
                tr!(
                    "Windows 10 ne reçoit plus de corrections de sécurité depuis le 14 octobre 2025 (sauf entreprise inscrite aux mises à jour étendues) : chaque faille découverte depuis reste ouverte.",
                    "Windows 10 has received no security fixes since October 14, 2025 (except businesses enrolled in Extended Security Updates): every flaw found since stays open."
                ),
            )
            .manuel(
                tr!(
                    "Passer à Windows 11 (gratuit si l'ordinateur le permet : Paramètres › Windows Update) ; sinon, un Linux comme Mint ou Ubuntu garde un ordinateur ancien à jour",
                    "Move to Windows 11 (free if the computer allows it: Settings › Windows Update); otherwise a Linux like Mint or Ubuntu keeps an old computer up to date"
                ),
                &["Start-Process ms-settings:windowsupdate"],
            ),
        );
    }
    let aujourd_hui = chrono::Local::now().format("%Y-%m-%d").to_string();
    let &(_, nom, fin_courte, fin_longue) = fins.iter().find(|(b, ..)| *b == build)?;
    let fin = if longue { fin_longue } else { fin_courte };
    (aujourd_hui.as_str() > fin).then(|| {
        alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "{nom} ne reçoit plus de corrections de sécurité depuis le {fin}.",
                "{nom} has received no security fixes since {fin}."
            ),
        )
        .manuel(
            tr!(
                "Installer la version suivante de Windows 11, gratuite : Paramètres › Windows Update",
                "Install the next Windows 11 version, free: Settings › Windows Update"
            ),
            &["Start-Process ms-settings:windowsupdate"],
        )
    })
}

/// macOS : Apple corrige les trois dernières versions. Depuis macOS 26, la numérotation suit l'année : 26, 15 et 14
/// sont corrigées en 2026 ; 13 Ventura et plus anciens ne le sont plus.
#[cfg(any(target_os = "macos", test))]
fn systeme_macos(version: &str) -> Option<Constat> {
    let majeure: u32 = version.trim().split('.').next()?.parse().ok()?;
    let nom = match majeure {
        10 => "macOS 10",
        11 => "macOS 11 Big Sur",
        12 => "macOS 12 Monterey",
        13 => "macOS 13 Ventura",
        _ => return None,
    };
    Some(
        alerte(
            CAT,
            Niveau::Eleve,
            trf!(
                "{nom} ne reçoit plus de corrections de sécurité : Apple ne corrige que les trois dernières versions de macOS.",
                "{nom} receives no more security fixes: Apple only fixes the last three versions of macOS."
            ),
        )
        .manuel(
            tr!(
                "Réglages Système › Général › Mise à jour de logiciels : installer la dernière version que ce Mac accepte",
                "System Settings › General › Software Update: install the latest version this Mac accepts"
            ),
            &[],
        ),
    )
}

// ───────────────────────────── Lectures ─────────────────────────────

#[cfg(windows)]
pub fn constats() -> Vec<Constat> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut constats = Vec::new();
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(v) = hklm.open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") {
        let build: String = v.get_value("CurrentBuildNumber").unwrap_or_default();
        let edition: String = v.get_value("EditionID").unwrap_or_default();
        if let Some(c) = build.trim().parse().ok().and_then(|b| systeme_windows(b, &edition)) {
            constats.push(c);
        }
    }
    // Les mêmes clés Uninstall que les autres lectures (machine 64 et 32 bits, ce compte).
    let noms: Vec<String> = super::windows::installes::noms()
        .unwrap_or_default()
        .iter()
        .map(|n| crate::ui::affichable(n))
        .collect();
    constats.extend(abandonnes(&noms).into_iter().map(|(n, a)| constat_abandonne(n, a)));
    constats
}

#[cfg(target_os = "macos")]
pub fn constats() -> Vec<Constat> {
    let mut constats = Vec::new();
    if let Some(version) = super::macos::version_systeme("ProductVersion")
        && let Some(c) = systeme_macos(&version)
    {
        constats.push(c);
    }
    let maison = crate::socle::maison();
    let present = |p: &str| std::path::Path::new(p).exists() || maison.join(p.trim_start_matches('/')).exists();
    let mut noms = Vec::new();
    for (chemin, nom) in [
        ("/Library/Internet Plug-Ins/Flash Player.plugin", "Adobe Flash Player"),
        ("/Library/PreferencePanes/Flash Player.prefPane", "Adobe Flash Player"),
        ("/Library/Internet Plug-Ins/Silverlight.plugin", "Microsoft Silverlight"),
        ("/Applications/Microsoft Office 2011", "Microsoft Office 2010"),
    ] {
        if present(chemin) {
            noms.push(nom.to_string());
        }
    }
    constats.extend(abandonnes(&noms).into_iter().map(|(n, a)| constat_abandonne(n, a)));
    constats
}

#[cfg(target_os = "linux")]
pub fn constats() -> Vec<Constat> {
    let mut noms = Vec::new();
    if ["/usr/bin/python2", "/usr/local/bin/python2"]
        .iter()
        .any(|p| std::path::Path::new(p).exists())
    {
        noms.push("Python 2.7".to_string());
    }
    let maison = crate::socle::maison();
    let flash = [
        std::path::PathBuf::from("/usr/lib/mozilla/plugins/libflashplayer.so"),
        std::path::PathBuf::from("/usr/lib64/mozilla/plugins/libflashplayer.so"),
        maison.join(".mozilla/plugins/libflashplayer.so"),
    ];
    if flash.iter().any(|p| p.exists()) {
        noms.push("Adobe Flash Player".to_string());
    }
    abandonnes(&noms)
        .into_iter()
        .map(|(n, a)| constat_abandonne(n, a))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn programmes_abandonnes() {
        let noms: Vec<String> = [
            "Adobe Flash Player 32 NPAPI",
            "Adobe Flash Player 32 PPAPI",
            "Java(TM) 7 Update 80",
            "Microsoft Office Professionnel Plus 2016",
            "Microsoft Office 2016",
            "Python 2.7.18",
            "Python 3.13.1 (64-bit)",
            "Mozilla Firefox (x64 fr)",
            "Adobe Reader X (10.1.16)",
            "Adobe Acrobat Reader DC",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let t = abandonnes(&noms);
        let montres: Vec<&str> = t.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            montres,
            [
                "Adobe Flash Player",
                "Java 7",
                "Microsoft Office 2016",
                "Python 2",
                "Adobe Reader X"
            ]
        );
        let c = constat_abandonne("Java 7", 2022);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("2022"));
    }

    #[test]
    fn fin_de_windows() {
        assert_eq!(
            systeme_windows(19045, "Professional").unwrap().probleme,
            Some(Niveau::Eleve)
        );
        assert!(systeme_windows(22621, "Core").is_some());
        assert!(systeme_windows(22631, "Professional").is_some());
        // 25H2 et les builds inconnus : rien à dire.
        assert!(systeme_windows(26200, "Professional").is_none());
        assert!(systeme_windows(99999, "Core").is_none());
    }

    #[test]
    fn fin_de_macos() {
        assert!(systeme_macos("12.7.6\n").unwrap().message.contains("Monterey"));
        assert!(systeme_macos("13.7").is_some());
        assert!(systeme_macos("14.8").is_none());
        assert!(systeme_macos("26.1").is_none());
        assert!(systeme_macos("").is_none());
    }

    #[test]
    fn navigateur_pas_a_jour() {
        let c = constat_navigateur("Google Chrome", 95);
        assert_eq!(c.probleme, Some(Niveau::Moyen));
        assert!(c.message.contains("95"));
    }
}
