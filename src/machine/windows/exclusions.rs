//! Exclusions de Microsoft Defender : un dossier, un programme ou un type de fichier que Defender ne regarde plus. Un
//! programme malveillant en ajoute pour se cacher (le disque entier, les Téléchargements, PowerShell, les « .exe ») ;
//! seules les exclusions aussi larges sont signalées, celles d'un jeu ou d'un outil de développement restent.

use super::super::{Constat, alerte};
use super::ps;
use crate::commande::ps_chaine;
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf};

/// Les exclusions de Defender. Sans droits administrateur, Windows les cache (« N/A: Must be an administrator… ») :
/// rien à conclure. Avec un autre antivirus, Get-MpPreference échoue : rien non plus.
pub(super) fn exclusions() -> Option<Constat> {
    // WMI d'abord (la classe que lit Get-MpPreference), PowerShell en secours.
    if let Some(l) = super::wmi::requete(
        r"root\Microsoft\Windows\Defender",
        "MSFT_MpPreference",
        "",
        &["ExclusionPath", "ExclusionProcess", "ExclusionExtension"],
    )
    .and_then(|l| l.into_iter().next())
    {
        // Une liste absente de la réponse compte pour vide : à elle seule, elle ne signale rien, et les deux autres
        // sont jugées quand même (un `None` pour toutes les trois tairait leurs exclusions).
        let liste = |cle: &str| -> Vec<String> {
            l.get(cle)
                .map(|v| v.liste().iter().filter_map(|x| x.texte().map(str::to_string)).collect())
                .unwrap_or_default()
        };
        return juger(
            &liste("ExclusionPath"),
            &liste("ExclusionProcess"),
            &liste("ExclusionExtension"),
        );
    }
    let json = ps(
        "$p = Get-MpPreference; @{c=@($p.ExclusionPath); p=@($p.ExclusionProcess); e=@($p.ExclusionExtension)} | ConvertTo-Json -Compress",
    )?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    // Le script rend toujours trois tableaux (@(…)) ; un autre compte pour vide, comme plus haut : les deux autres
    // sont jugées quand même.
    let liste = |cle: &str| -> Vec<String> {
        v.get(cle)
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    juger(&liste("c"), &liste("p"), &liste("e"))
}

/// Exclusions trop larges, avec la commande qui retire chacune. `None` si aucune, ou si la liste est cachée.
pub(super) fn juger(chemins: &[String], processus: &[String], extensions: &[String]) -> Option<Constat> {
    if chemins
        .iter()
        .chain(processus)
        .chain(extensions)
        .any(|x| x.starts_with("N/A"))
    {
        return None;
    }
    let mut montrees = Vec::new();
    let mut commandes = Vec::new();
    for c in chemins.iter().filter(|c| chemin_large(c)) {
        montrees.push(affichable(c));
        commandes.push(format!("Remove-MpPreference -ExclusionPath {}", ps_chaine(c)));
    }
    for p in processus.iter().filter(|p| programme_sensible(p)) {
        montrees.push(affichable(p));
        commandes.push(format!("Remove-MpPreference -ExclusionProcess {}", ps_chaine(p)));
    }
    for e in extensions.iter().filter(|e| extension_sensible(e)) {
        montrees.push(format!("*.{}", affichable(e.trim().trim_start_matches(['*', '.']))));
        commandes.push(format!("Remove-MpPreference -ExclusionExtension {}", ps_chaine(e)));
    }
    if montrees.is_empty() {
        return None;
    }
    let liste = resume(&montrees, 4, ", ");
    let commandes: Vec<&str> = commandes.iter().map(String::as_str).collect();
    Some(
        alerte(
            "Antivirus",
            Niveau::Eleve,
            trf!(
                "Defender ne regarde pas : {liste}. Un programme malveillant qui passe par là n'est pas contrôlé.",
                "Defender does not look at: {liste}. Malware going through there is not checked.",
            ),
        )
        .manuel(
            tr!(
                "Si vous n'avez pas ajouté ces exclusions vous-même, les retirer (commandes ci-dessous, en administrateur), puis lancer une analyse complète",
                "If you did not add these exclusions yourself, remove them (commands below, as administrator), then run a full scan"
            ),
            &commandes,
        ),
    )
}

/// Un dossier trop large pour être exclu : un disque entier, le système, les comptes, ou un dossier où tombe ce qui
/// vient de l'extérieur (Téléchargements, Temp, AppData, Bureau, Documents, démarrage).
fn chemin_large(chemin: &str) -> bool {
    let c = chemin.trim().replace('/', "\\").to_lowercase();
    let c = c.trim_end_matches(['*', '\\', '.']);
    let parties: Vec<&str> = c.split('\\').filter(|p| !p.is_empty()).collect();
    let Some(&dernier) = parties.last() else {
        return true; // « * » ou « \ » : tout
    };
    if parties.len() == 1 && (dernier.ends_with(':') || dernier.starts_with('%')) {
        // Un disque (« C: »), ou une variable seule : %TEMP%, %USERPROFILE%, %APPDATA%, %SystemRoot%…
        return dernier.ends_with(':')
            || matches!(
                dernier.trim_matches('%'),
                "temp"
                    | "tmp"
                    | "appdata"
                    | "localappdata"
                    | "userprofile"
                    | "public"
                    | "programdata"
                    | "allusersprofile"
                    | "windir"
                    | "systemroot"
                    | "systemdrive"
            );
    }
    let parent = parties.len().checked_sub(2).and_then(|i| parties.get(i)).copied();
    // Un compte entier : C:\Users\nom.
    if matches!(parties.as_slice(), [_, "users", _]) {
        return true;
    }
    match dernier {
        "users" | "windows" | "system32" | "syswow64" | "programdata" | "appdata" | "temp" | "tmp" | "downloads"
        | "téléchargements" | "desktop" | "bureau" | "documents" | "public" | "startup" | "démarrage" => true,
        "local" | "roaming" | "locallow" => parent == Some("appdata"),
        _ => false,
    }
}

/// Un programme qui lance d'autres programmes ou des scripts : l'exclure laisse passer tout ce qu'il exécute.
fn programme_sensible(programme: &str) -> bool {
    let nom = programme
        .trim()
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_lowercase();
    matches!(
        nom.as_str(),
        "powershell.exe"
            | "pwsh.exe"
            | "powershell_ise.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "msiexec.exe"
            | "explorer.exe"
            | "svchost.exe"
            | "conhost.exe"
            | "dllhost.exe"
            | "wmic.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
            | "*"
            | "*.exe"
    )
}

/// Un type de fichier qui s'exécute ou en contient : l'exclure laisse passer tous les fichiers de ce type.
fn extension_sensible(extension: &str) -> bool {
    let e = extension.trim().trim_start_matches(['*', '.']).to_lowercase();
    matches!(
        e.as_str(),
        "" | "exe"
            | "dll"
            | "sys"
            | "scr"
            | "com"
            | "pif"
            | "cpl"
            | "msi"
            | "msix"
            | "appx"
            | "ps1"
            | "psm1"
            | "bat"
            | "cmd"
            | "vbs"
            | "vbe"
            | "js"
            | "jse"
            | "wsf"
            | "hta"
            | "lnk"
            | "iso"
            | "img"
            | "vhd"
            | "vhdx"
            | "zip"
            | "rar"
            | "7z"
            | "docm"
            | "xlsm"
            | "pptm"
            | "jar"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(l: &[&str]) -> Vec<String> {
        l.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn dossiers_trop_larges() {
        for c in [
            "C:\\",
            "C:",
            "c:\\*",
            "*",
            "%TEMP%",
            "%UserProfile%\\",
            "C:\\Users",
            "C:\\Users\\alice",
            "C:\\Users\\alice\\Downloads",
            "C:\\Users\\alice\\AppData\\Roaming",
            "C:\\Users\\alice\\AppData\\Local\\Temp\\",
            "C:\\Windows\\System32",
            "C:\\ProgramData",
            "D:/",
        ] {
            assert!(chemin_large(c), "{c}");
        }
        for c in [
            "C:\\Users\\alice\\source\\repos",
            "D:\\SteamLibrary",
            "C:\\Program Files\\Jeu\\local",
            "C:\\Users\\alice\\AppData\\Local\\Programs\\Outil",
            "%TEMP%\\outil",
        ] {
            assert!(!chemin_large(c), "{c}");
        }
    }

    #[test]
    fn programmes_et_types_sensibles() {
        assert!(programme_sensible(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe"
        ));
        assert!(programme_sensible("rundll32.exe") && programme_sensible(" *.exe"));
        assert!(!programme_sensible("C:\\Jeux\\jeu.exe") && !programme_sensible("code.exe"));
        assert!(extension_sensible(".exe") && extension_sensible("*.PS1") && extension_sensible("lnk"));
        assert!(!extension_sensible(".vmdk") && !extension_sensible("log") && !extension_sensible("pst"));
    }

    #[test]
    fn constat_et_commandes() {
        // Liste cachée sans droits administrateur : rien à conclure.
        let cache = v(&["N/A: Must be an administrator to view exclusions"]);
        assert!(juger(&cache, &cache, &cache).is_none());
        // Exclusions ordinaires : rien.
        assert!(juger(&v(&["D:\\SteamLibrary"]), &v(&["jeu.exe"]), &v(&["vmdk"])).is_none());
        assert!(juger(&[], &[], &[]).is_none());
        // Trop larges : une commande par exclusion, la valeur entre apostrophes doublées.
        let c = juger(
            &v(&["C:\\", "D:\\SteamLibrary", "C:\\Users\\bob\\Downloads"]),
            &v(&["C:\\Outils d'été\\powershell.exe"]),
            &v(&[".exe"]),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        let k = c.correctif.unwrap();
        assert!(!k.automatique);
        assert_eq!(
            k.commandes,
            [
                "Remove-MpPreference -ExclusionPath 'C:\\'",
                "Remove-MpPreference -ExclusionPath 'C:\\Users\\bob\\Downloads'",
                "Remove-MpPreference -ExclusionProcess 'C:\\Outils d''été\\powershell.exe'",
                "Remove-MpPreference -ExclusionExtension '.exe'",
            ]
        );
        assert!(c.message.contains("*.exe") && !c.message.contains("SteamLibrary"));
        // Un nom piégé : rendu inoffensif dans le message.
        let c = juger(&v(&["C:\\Users\\x\x1b]52;c;eA==\x07\\Downloads"]), &[], &[]).unwrap();
        assert!(!c.message.contains('\x1b'));
    }
}
