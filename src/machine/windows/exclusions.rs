//! Exclusions de Microsoft Defender : un dossier, un programme ou un type de fichier que Defender ne regarde plus. Un
//! programme malveillant en ajoute pour se cacher (le disque entier, les Téléchargements, PowerShell, les « .exe ») ;
//! seules les exclusions aussi larges sont signalées, celles d'un jeu ou d'un outil de développement restent.

use super::super::{Constat, alerte};
use super::ps;
use super::wmi::Valeur;
use crate::commande::ps_chaine;
use crate::protection::antivirus::Politiques;
use crate::risk::Niveau;
use crate::ui::{affichable, resume, tr, trf};

/// Les exclusions de Defender. Sans droits administrateur, Windows les cache (« N/A: Must be an administrator… ») :
/// rien à conclure. Avec un autre antivirus, Get-MpPreference échoue : rien non plus.
pub(super) fn exclusions() -> Option<Constat> {
    let [chemins, processus, extensions] = listes()?;
    juger(&chemins, &processus, &extensions)
}

/// Les trois listes d'exclusions de Defender, telles que lues : chemins, processus, extensions. Cachées sans droits
/// administrateur, elles contiennent « N/A: Must be an administrator… » ; `None` si ni WMI ni PowerShell ne
/// répondent (autre antivirus).
pub(crate) fn listes() -> Option<[Vec<String>; 3]> {
    lecture().map(|(listes, _)| listes)
}

/// Les trois listes de `listes`, et les politiques qui les cachent, lues ensemble (une seule requête, un seul
/// instant). Pour l'antivirus : un « found no threats » sur un dossier exclu ne prouve rien, et une politique peut
/// cacher les exclusions même à l'administrateur, peut-être sous la forme de listes vides plutôt que de « N/A ».
/// Fonction voisine plutôt que trois valeurs de plus dans `listes` : le constat de l'audit (`exclusions`) n'en a pas
/// l'usage et garde sa forme.
pub(crate) fn lecture() -> Option<([Vec<String>; 3], Politiques)> {
    // WMI d'abord (la classe que lit Get-MpPreference), PowerShell en secours.
    if let Some(l) = super::wmi::requete(
        r"root\Microsoft\Windows\Defender",
        "MSFT_MpPreference",
        "",
        &[
            "ExclusionPath",
            "ExclusionProcess",
            "ExclusionExtension",
            "HideExclusionsFromLocalAdmins",
            "HideExclusionsFromLocalUsers",
        ],
    )
    .and_then(|l| l.into_iter().next())
    {
        // Une liste absente de la réponse compte pour vide : à elle seule, elle ne signale rien, et les deux autres
        // sont jugées quand même (un `None` pour toutes les trois tairait leurs exclusions). Un texte seul compte
        // pour une liste d'un élément : un « N/A… » rendu ainsi garde la liste cachée, au lieu de la faire passer
        // pour lue et vide.
        let liste = |cle: &str| -> Vec<String> { l.get(cle).map(Valeur::textes).unwrap_or_default() };
        // Une politique que ce Windows n'a pas (plateforme plus ancienne) arrive nulle (`requete` lit `*` puis
        // chaque champ) : elle ne cache rien.
        let vraie = |cle: &str| l.get(cle).is_some_and(politique_vraie);
        return Some((
            [
                liste("ExclusionPath"),
                liste("ExclusionProcess"),
                liste("ExclusionExtension"),
            ],
            Politiques {
                aux_admins: vraie("HideExclusionsFromLocalAdmins"),
                aux_utilisateurs: vraie("HideExclusionsFromLocalUsers"),
            },
        ));
    }
    let json = ps(
        "$p = Get-MpPreference; @{c=@($p.ExclusionPath); p=@($p.ExclusionProcess); e=@($p.ExclusionExtension); ha=$p.HideExclusionsFromLocalAdmins; hu=$p.HideExclusionsFromLocalUsers} | ConvertTo-Json -Compress",
    )?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    Some(lire_json(&v))
}

/// La réponse du secours PowerShell. Le script rend toujours trois tableaux (@(…)) ; un autre compte pour vide,
/// comme pour WMI : les deux autres sont jugées quand même. Une politique absente de cette plateforme vaut `null` :
/// elle ne cache rien.
fn lire_json(v: &serde_json::Value) -> ([Vec<String>; 3], Politiques) {
    let liste = |cle: &str| -> Vec<String> {
        v.get(cle)
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    };
    let vraie = |cle: &str| match v.get(cle) {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::Number(n)) => n.as_i64().is_some_and(|n| n != 0),
        Some(serde_json::Value::String(t)) => texte_vrai(t),
        _ => false,
    };
    (
        [liste("c"), liste("p"), liste("e")],
        Politiques {
            aux_admins: vraie("ha"),
            aux_utilisateurs: vraie("hu"),
        },
    )
}

/// Une politique booléenne lue par WMI : un entier (0 ou 1, la valeur du registre) compte aussi, et un texte
/// (`texte_vrai`).
fn politique_vraie(v: &Valeur) -> bool {
    match v {
        Valeur::Booleen(b) => *b,
        Valeur::Texte(t) => texte_vrai(t),
        x => x.entier().is_some_and(|n| n != 0),
    }
}

/// Une politique rendue en texte : « True » (la forme d'un booléen converti en chaîne, toute casse) ou un entier non
/// nul. Microsoft ne documente pas la forme de la propriété ; la lire fausse rendrait lisibles des listes que la
/// politique a vidées (relecture des correctifs T10, 4e passe, BAS-1).
fn texte_vrai(t: &str) -> bool {
    let t = t.trim();
    t.eq_ignore_ascii_case("true") || t.parse::<i64>().is_ok_and(|n| n != 0)
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
    fn politiques_qui_cachent_les_exclusions() {
        // Relecture des correctifs T10, 3e passe, MOYEN-1 : absentes (Windows plus ancien), nulles ou fausses, elles
        // ne cachent rien ; vraies, en booléen ou en entier (la valeur du registre).
        let lire = |texte: &str| lire_json(&serde_json::from_str(texte).unwrap());
        let (listes, p) = lire(r#"{"c":["D:\\Jeux"],"p":[],"e":["vmdk"]}"#);
        assert_eq!(listes, [v(&["D:\\Jeux"]), vec![], v(&["vmdk"])]);
        assert!(!p.aux_admins && !p.aux_utilisateurs);
        let (_, p) = lire(r#"{"c":[],"p":[],"e":[],"ha":null,"hu":false}"#);
        assert!(!p.aux_admins && !p.aux_utilisateurs);
        let (listes, p) = lire(r#"{"c":[],"p":[],"e":[],"ha":true,"hu":1}"#);
        assert_eq!(listes, [Vec::<String>::new(), vec![], vec![]]);
        assert!(p.aux_admins && p.aux_utilisateurs);
        assert!(politique_vraie(&Valeur::Booleen(true)) && politique_vraie(&Valeur::Entier(1)));
        assert!(!politique_vraie(&Valeur::Nul) && !politique_vraie(&Valeur::Booleen(false)));
        assert!(!politique_vraie(&Valeur::Entier(0)) && !politique_vraie(&Valeur::Texte("oui".into())));
        // 4e passe, BAS-1 : un booléen rendu en texte, toute casse, espaces autour ; « 1 » aussi.
        for t in ["True", "true", " TRUE ", "1", " 1"] {
            assert!(politique_vraie(&Valeur::Texte(t.into())), "{t}");
        }
        for t in ["False", "0", "", " ", "truE!", "vrai"] {
            assert!(!politique_vraie(&Valeur::Texte(t.into())), "{t}");
        }
        let (_, p) = lire(r#"{"c":[],"p":[],"e":[],"ha":" True ","hu":"1"}"#);
        assert!(p.aux_admins && p.aux_utilisateurs);
        let (_, p) = lire(r#"{"c":[],"p":[],"e":[],"ha":"False","hu":"0"}"#);
        assert!(!p.aux_admins && !p.aux_utilisateurs);
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
