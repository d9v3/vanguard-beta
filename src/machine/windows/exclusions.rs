//! Exclusions de Microsoft Defender : un dossier, un programme ou un type de fichier que Defender ne regarde plus. Un
//! programme malveillant en ajoute pour se cacher (le disque entier, les Téléchargements, PowerShell, les « .exe ») ;
//! seules les exclusions aussi larges sont signalées, celles d'un jeu ou d'un outil de développement restent.

use super::super::{Constat, alerte};
use super::ps;
use super::wmi::Valeur;
use crate::machine::gestes::{self, GenreExclusion};
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
    if let Some(l) = lecture_wmi() {
        return Some(l);
    }
    let json = ps(
        "$p = Get-MpPreference; @{c=@($p.ExclusionPath); p=@($p.ExclusionProcess); e=@($p.ExclusionExtension); ha=$p.HideExclusionsFromLocalAdmins; hu=$p.HideExclusionsFromLocalUsers} | ConvertTo-Json -Compress",
    )?;
    let v: serde_json::Value = serde_json::from_str(&json).ok()?;
    Some(lire_json(&v))
}

/// La lecture de `lecture` par WMI seul (MSFT_MpPreference) : celle du processus élevé, qui rejuge une exclusion
/// juste avant de la retirer, sans PowerShell. `None` si Defender ne répond pas.
pub(crate) fn lecture_wmi() -> Option<([Vec<String>; 3], Politiques)> {
    let l = super::wmi::requete(
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
    .and_then(|l| l.into_iter().next())?;
    // Une liste absente de la réponse compte pour vide : à elle seule, elle ne signale rien, et les deux autres
    // sont jugées quand même (un `None` pour toutes les trois tairait leurs exclusions). Un texte seul compte
    // pour une liste d'un élément : un « N/A… » rendu ainsi garde la liste cachée, au lieu de la faire passer
    // pour lue et vide.
    let liste = |cle: &str| -> Vec<String> { l.get(cle).map(Valeur::textes).unwrap_or_default() };
    // Une politique que ce Windows n'a pas (plateforme plus ancienne) arrive nulle (`requete` lit `*` puis
    // chaque champ) : elle ne cache rien.
    let vraie = |cle: &str| l.get(cle).is_some_and(politique_vraie);
    Some((
        [
            liste("ExclusionPath"),
            liste("ExclusionProcess"),
            liste("ExclusionExtension"),
        ],
        Politiques {
            aux_admins: vraie("HideExclusionsFromLocalAdmins"),
            aux_utilisateurs: vraie("HideExclusionsFromLocalUsers"),
        },
    ))
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

/// Une liste lue est-elle cachée (« N/A: Must be an administrator… ») ? Rien n'y est alors à conclure.
pub(crate) fn cachee(listes: &[Vec<String>; 3]) -> bool {
    listes.iter().flatten().any(|x| x.starts_with("N/A"))
}

/// Le bilan signale-t-il cette exclusion ? La même règle que `juger`, pour le processus élevé qui la rejuge avant de
/// la retirer : une ligne forgée qui désigne une exclusion ordinaire (un jeu, un outil) ne la retire pas.
pub(crate) fn signalee(genre: GenreExclusion, valeur: &str) -> bool {
    match genre {
        GenreExclusion::Chemin => chemin_large(valeur),
        GenreExclusion::Processus => programme_sensible(valeur),
        GenreExclusion::Extension => extension_sensible(valeur),
    }
}

/// Exclusions trop larges, avec la ligne du processus élevé qui retire chacune (par WMI, rejugée là-bas). `None` si
/// aucune, ou si la liste est cachée.
pub(super) fn juger(chemins: &[String], processus: &[String], extensions: &[String]) -> Option<Constat> {
    let listes = [chemins.to_vec(), processus.to_vec(), extensions.to_vec()];
    if cachee(&listes) {
        return None;
    }
    let mut montrees = Vec::new();
    // `None` dès qu'une exclusion n'a pas la forme d'une ligne (trop longue, caractère de contrôle) : elle se retire
    // alors à la main, et les autres avec elle, pour ne pas en laisser une derrière un « fait ».
    let mut lignes = Some(Vec::new());
    for (genre, liste) in GenreExclusion::TOUS.into_iter().zip(&listes) {
        for x in liste.iter().filter(|x| signalee(genre, x)) {
            montrees.push(match genre {
                GenreExclusion::Extension => format!("*.{}", affichable(x.trim().trim_start_matches(['*', '.']))),
                GenreExclusion::Chemin | GenreExclusion::Processus => affichable(x),
            });
            lignes = lignes.and_then(|mut l: Vec<String>| {
                l.push(gestes::ligne_defender_exclusion_retirer(genre, x)?);
                Some(l)
            });
        }
    }
    if montrees.is_empty() {
        return None;
    }
    let liste = resume(&montrees, 4, ", ");
    let c = alerte(
        "Antivirus",
        Niveau::Eleve,
        trf!(
            "Defender ne regarde pas : {liste}. Un programme malveillant qui passe par là n'est pas contrôlé.",
            "Defender does not look at: {liste}. Malware going through there is not checked.",
        ),
    );
    Some(match lignes {
        Some(lignes) => c
            .corriger(
                tr!(
                    "Si vous n'avez pas ajouté ces exclusions vous-même, les retirer, puis lancer une analyse complète",
                    "If you did not add these exclusions yourself, remove them, then run a full scan"
                ),
                &lignes,
            )
            .protection(),
        None => c.manuel(
            tr!(
                "Si vous n'avez pas ajouté ces exclusions vous-même, les retirer dans Sécurité Windows (Protection contre les virus et menaces > Gérer les paramètres > Exclusions), puis lancer une analyse complète",
                "If you did not add these exclusions yourself, remove them in Windows Security (Virus & threat protection > Manage settings > Exclusions), then run a full scan"
            ),
            &[],
        ),
    })
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
        // Trop larges : une ligne du processus élevé par exclusion, la valeur en hexadécimal UTF-16.
        let c = juger(
            &v(&["C:\\", "D:\\SteamLibrary", "C:\\Users\\bob\\Downloads"]),
            &v(&["C:\\Outils d'été\\powershell.exe"]),
            &v(&[".exe"]),
        )
        .unwrap();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        let k = c.correctif.unwrap();
        assert!(k.automatique && k.defaire == crate::machine::Defaire::Protection);
        let attendues = [
            (GenreExclusion::Chemin, "C:\\"),
            (GenreExclusion::Chemin, "C:\\Users\\bob\\Downloads"),
            (GenreExclusion::Processus, "C:\\Outils d'été\\powershell.exe"),
            (GenreExclusion::Extension, ".exe"),
        ];
        assert_eq!(k.commandes.len(), attendues.len());
        for (ligne, (genre, valeur)) in k.commandes.iter().zip(attendues) {
            assert_eq!(
                Some(ligne.clone()),
                gestes::ligne_defender_exclusion_retirer(genre, valeur)
            );
            match gestes::analyser_acte(ligne) {
                Some(gestes::Acte::DefenderExclusionRetirer(g, e)) => {
                    assert!(g == genre && e.texte() == valeur && signalee(g, e.texte()));
                }
                autre => panic!("{ligne} : {autre:?}"),
            }
        }
        assert_eq!(
            k.commandes[0],
            "vanguard:defender-exclusion-retirer chemin 43003a005c00"
        );
        assert!(c.message.contains("*.exe") && !c.message.contains("SteamLibrary"));
        // Une exclusion qui n'a pas la forme d'une ligne (caractère de contrôle) : toutes se retirent à la main.
        let c = juger(&v(&["C:\\", "C:\\Users\\x\x01\\Downloads"]), &[], &[]).unwrap();
        let k = c.correctif.unwrap();
        assert!(!k.automatique && k.commandes.is_empty());
        // Une exclusion ordinaire n'est pas signalée : le processus élevé refusera de la retirer.
        assert!(!signalee(GenreExclusion::Chemin, "D:\\SteamLibrary"));
        assert!(!signalee(GenreExclusion::Processus, "jeu.exe"));
        assert!(!signalee(GenreExclusion::Extension, "vmdk"));
        assert!(signalee(GenreExclusion::Extension, "*.PS1"));
        // Un nom piégé : rendu inoffensif dans le message.
        let c = juger(&v(&["C:\\Users\\x\x1b]52;c;eA==\x07\\Downloads"]), &[], &[]).unwrap();
        assert!(!c.message.contains('\x1b'));
    }
}
