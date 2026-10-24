//! Nettoyer sous Windows : fichiers temporaires (les tiens et ceux de Windows), cache de Windows Update et de
//! l'optimisation de distribution, anciennes versions des composants (DISM), rapports de plantage, corbeille. Ce qui
//! est à toi se nettoie dans ton compte ; ce qui est à Windows passe par une seule fenêtre administrateur.

use std::path::{Path, PathBuf};

use super::{Age, Element, taille_dossier};
use crate::commande::ps_chaine;
use crate::ui::*;

/// Un dossier lu dans l'environnement, s'il est absolu. Vide ou relatif, une commande de suppression viserait le
/// dossier courant (« Get-ChildItem '' » le lit) ou la racine du disque (« \Temp ») : l'élément n'est pas proposé.
fn dossier(env: &dyn Fn(&str) -> Option<PathBuf>, nom: &str) -> Option<PathBuf> {
    env(nom).filter(|p| p.is_absolute())
}

fn dossier_windows(env: &dyn Fn(&str) -> Option<PathBuf>) -> PathBuf {
    dossier(env, "SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Vide les dossiers nommés, sans toucher aux dossiers eux-mêmes ; un fichier encore ouvert reste. Les chemins sont
/// écrits en toutes lettres (la personne voit lesquels avant d'accepter) et lus tels quels (-LiteralPath).
fn vider(dossiers: &[&Path]) -> String {
    let liste: Vec<String> = dossiers.iter().map(|d| ps_chaine(&d.to_string_lossy())).collect();
    format!(
        "Get-ChildItem -LiteralPath {} -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue",
        liste.join(", ")
    )
}

/// La corbeille du disque système : un dossier par compte dans `$Recycle.Bin`, seul le sien est lisible.
fn taille_corbeille() -> Option<u64> {
    let lecteur = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let racine = PathBuf::from(format!(r"{lecteur}\$Recycle.Bin"));
    std::fs::read_dir(racine)
        .ok()?
        .flatten()
        .filter_map(|e| taille_dossier(&e.path(), Age::Tout, &[]))
        .reduce(u64::saturating_add)
}

pub fn elements() -> Vec<Element> {
    elements_selon(&|nom| std::env::var_os(nom).map(PathBuf::from))
}

/// Les éléments, avec les dossiers de `env` : les tests y mettent une variable vide ou relative.
fn elements_selon(env: &dyn Fn(&str) -> Option<PathBuf>) -> Vec<Element> {
    let windows = dossier_windows(env);
    let temp_windows = windows.join("Temp");
    let telechargements = windows.join(r"SoftwareDistribution\Download");
    let mut rapports = vec![windows.join("Minidump")];
    rapports.extend(dossier(env, "ProgramData").map(|d| d.join(r"Microsoft\Windows\WER\ReportArchive")));
    let rapports: Vec<&Path> = rapports.iter().map(PathBuf::as_path).collect();
    [
        dossier(env, "TEMP").map(|temp| Element {
            titre: tr!("Vos fichiers temporaires", "Your temporary files"),
            effet: tr!(
                "Ce que les programmes laissent dans votre dossier temporaire ; un fichier encore ouvert reste.",
                "What programs leave in your temporary folder; a file still open stays."
            )
            .into(),
            prudence: None,
            taille: taille_dossier(&temp, Age::Tout, &[]),
            commandes: vec![vider(&[&temp])],
            recommande: true,
            admin: false,
        }),
        Some(Element {
            titre: tr!("Fichiers temporaires de Windows", "Windows temporary files"),
            effet: tr!(
                "Le dossier temporaire de Windows lui-même (installations, mises à jour).",
                "Windows' own temporary folder (installs, updates)."
            )
            .into(),
            prudence: None,
            taille: taille_dossier(&temp_windows, Age::Tout, &[]),
            commandes: vec![vider(&[&temp_windows])],
            recommande: true,
            admin: true,
        }),
        Some(Element {
            titre: tr!("Cache de Windows Update", "Windows Update cache"),
            effet: tr!(
                "Les mises à jour déjà téléchargées et installées.",
                "Updates already downloaded and installed."
            )
            .into(),
            prudence: Some(tr!(
                "Une mise à jour en cours de téléchargement recommencera.",
                "An update being downloaded will start over."
            )),
            taille: taille_dossier(&telechargements, Age::Tout, &[]),
            commandes: vec![format!(
                "Stop-Service wuauserv -Force; {}; Start-Service wuauserv",
                vider(&[&telechargements])
            )],
            recommande: true,
            admin: true,
        }),
        Some(Element {
            titre: tr!("Optimisation de distribution", "Delivery Optimization"),
            effet: tr!(
                "Le cache des mises à jour partagées avec les autres PC (réseau local ou Internet).",
                "The cache of updates shared with other PCs (local network or Internet)."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec!["Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue".into()],
            recommande: true,
            admin: true,
        }),
        Some(Element {
            titre: tr!("Anciens composants de Windows", "Old Windows components"),
            effet: tr!(
                "Les versions remplacées des composants de Windows (DISM), gardées après chaque mise à jour ; quelques minutes.",
                "Replaced versions of Windows components (DISM), kept after each update; a few minutes."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec!["Dism /Online /Cleanup-Image /StartComponentCleanup".into()],
            recommande: true,
            admin: true,
        }),
        dossier(env, "LOCALAPPDATA").map(|local| {
            let plantages = local.join("CrashDumps");
            Element {
                titre: tr!("Vos rapports de plantage", "Your crash reports"),
                effet: tr!(
                    "Copies de la mémoire des programmes qui ont planté.",
                    "Memory copies of programs that crashed."
                )
                .into(),
                prudence: None,
                taille: Some(taille_dossier(&plantages, Age::Tout, &[]).unwrap_or(0)),
                commandes: vec![vider(&[&plantages])],
                recommande: true,
                admin: false,
            }
        }),
        Some(Element {
            titre: tr!("Rapports d'erreurs de Windows", "Windows error reports"),
            effet: tr!(
                "Rapports d'erreurs déjà traités et copies de la mémoire après un écran bleu.",
                "Error reports already processed and memory copies after a blue screen."
            )
            .into(),
            prudence: None,
            taille: None,
            commandes: vec![vider(&rapports)],
            recommande: true,
            admin: true,
        }),
        Some(Element {
            titre: tr!("Corbeille", "Recycle Bin"),
            effet: tr!("Les fichiers mis à la corbeille.", "Files moved to the Recycle Bin.").into(),
            prudence: Some(tr!(
                "Ce qui est dans la corbeille ne pourra plus être récupéré.",
                "What is in the Recycle Bin can no longer be recovered."
            )),
            taille: taille_corbeille(),
            commandes: vec!["Clear-RecycleBin -Force -ErrorAction SilentlyContinue".into()],
            recommande: false,
            admin: false,
        }),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Place libre du disque du système (le seul disque que le nettoyage touche), lue par kernel32 ; .NET en secours.
pub fn place() -> Option<(u64, u64, u64)> {
    let systeme = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    if let Some(l) = crate::machine::windows::lecteurs::lecteur(std::path::Path::new(&systeme)) {
        return Some((l.libre, l.total, l.libre));
    }
    let s = crate::machine::windows::ps(
        "$d = [IO.DriveInfo]::new($env:SystemDrive); \"$($d.AvailableFreeSpace) $($d.TotalSize)\"",
    )?;
    let mut n = s.split_whitespace().filter_map(|x| x.parse::<u64>().ok());
    let (libre, total) = (n.next()?, n.next()?);
    Some((libre, total, libre))
}

/// Ce qui est à Windows dans une seule fenêtre administrateur ; ce qui est à la personne dans son propre compte (la
/// fenêtre administrateur peut être celle d'un autre compte, avec une autre corbeille et un autre dossier temporaire).
pub fn executer(choisis: &[&Element]) -> Vec<bool> {
    let systeme: Vec<Vec<String>> = choisis
        .iter()
        .filter(|e| e.admin)
        .map(|e| e.commandes.clone())
        .collect();
    let mut resultats = if systeme.is_empty() {
        Vec::new()
    } else {
        crate::machine::appliquer_chacune(&systeme)
    }
    .into_iter();
    choisis
        .iter()
        .map(|e| {
            if e.admin {
                resultats.next().unwrap_or(false)
            } else {
                e.commandes.iter().all(|c| {
                    println!("    {GRIS}PS> {}{RESET}", crate::ui::commande_affichable(c));
                    crate::machine::windows::ps(c).is_some()
                })
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_de(paires: &[(&str, &str)]) -> impl Fn(&str) -> Option<PathBuf> + use<> {
        let paires: Vec<(String, String)> = paires.iter().map(|(n, v)| ((*n).into(), (*v).into())).collect();
        move |nom| paires.iter().find(|(n, _)| n == nom).map(|(_, v)| PathBuf::from(v))
    }

    fn commandes(env: &dyn Fn(&str) -> Option<PathBuf>) -> Vec<String> {
        elements_selon(env).into_iter().flat_map(|e| e.commandes).collect()
    }

    /// Variables vides ou relatives : rien ne vise le dossier courant ni la racine du disque, et ce qui en dépend
    /// n'est pas proposé.
    #[test]
    fn variables_vides_rien_vers_le_dossier_courant() {
        let env = env_de(&[
            ("TEMP", ""),
            ("LOCALAPPDATA", "AppData"),
            ("SystemRoot", ""),
            ("ProgramData", r"\ProgramData"),
        ]);
        let tout = commandes(&env);
        assert_eq!(elements_selon(&env).len(), 6);
        for c in &tout {
            assert!(!c.contains("$env:"), "{c}");
            assert!(!c.contains("''"), "{c}");
            assert!(!c.contains(r"'\"), "{c}");
        }
        assert!(tout.iter().any(|c| c.contains(r"-LiteralPath 'C:\Windows\Temp'")));
        assert!(
            tout.iter()
                .any(|c| c.contains(r"-LiteralPath 'C:\Windows\Minidump' -Force"))
        );
    }

    #[test]
    fn chemins_ecrits_en_toutes_lettres() {
        let env = env_de(&[
            ("TEMP", r"C:\Users\alice\AppData\Local\Temp"),
            ("LOCALAPPDATA", r"C:\Users\alice\AppData\Local"),
            ("SystemRoot", r"D:\Windows"),
            ("ProgramData", r"C:\ProgramData"),
        ]);
        let tout = commandes(&env);
        assert_eq!(elements_selon(&env).len(), 8);
        assert!(tout.contains(
            &r"Get-ChildItem -LiteralPath 'C:\Users\alice\AppData\Local\Temp' -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue".to_string()
        ));
        assert!(
            tout.iter()
                .any(|c| c.contains(r"-LiteralPath 'C:\Users\alice\AppData\Local\CrashDumps'"))
        );
        assert!(tout.iter().any(|c| {
            c.contains(r"-LiteralPath 'D:\Windows\Minidump', 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive'")
        }));
        assert!(tout.iter().any(|c| c.starts_with(
            "Stop-Service wuauserv -Force; Get-ChildItem -LiteralPath 'D:\\Windows\\SoftwareDistribution\\Download'"
        )));
    }

    /// Une apostrophe dans le chemin ne ferme pas la chaîne : la suite du chemin n'est pas une commande.
    #[test]
    fn apostrophe_dans_le_chemin_citee() {
        let env = env_de(&[("TEMP", r"D:\l'atelier\Temp")]);
        assert!(
            commandes(&env)
                .iter()
                .any(|c| c.contains(r"-LiteralPath 'D:\l''atelier\Temp'"))
        );
    }
}
