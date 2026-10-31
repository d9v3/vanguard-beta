//! L'environnement d'un programme lancé avec les droits d'administrateur : PowerShell, DISM, sfc, chkdsk… Tout ce
//! que le compte peut écrire (HKCU\Environment, `set` avant de lancer Vanguard) en est retiré : COR_PROFILER et
//! COMPlus_* chargeraient une DLL dans PowerShell, PSModulePath ferait charger un module des Documents, PATH ferait
//! trouver un faux programme. Seule une liste fixe de variables passe, chacune calculée par Windows.

// FFI de kernel32 (GetSystemWindowsDirectoryW, GetComputerNameW) et de shell32 (SHGetKnownFolderPath) : les dossiers
// du système demandés à Windows plutôt qu'à l'environnement.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::core::{GUID, PWSTR};

/// Les extensions de programme de Windows, telles qu'à l'installation.
const PATHEXT: &str = ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC";

/// Les dossiers qui composent l'environnement, demandés à Windows.
#[derive(Clone, Debug, Default)]
pub(crate) struct Dossiers {
    /// System32 (GetSystemDirectoryW).
    pub systeme: PathBuf,
    /// Le dossier de Windows (GetSystemWindowsDirectoryW).
    pub windows: PathBuf,
    pub program_files: Option<PathBuf>,
    pub program_files_x86: Option<PathBuf>,
    pub fichiers_communs: Option<PathBuf>,
    pub program_data: Option<PathBuf>,
    pub profil: Option<PathBuf>,
    pub appdata: Option<PathBuf>,
    pub appdata_local: Option<PathBuf>,
    pub ordinateur: Option<String>,
}

/// Les noms des variables qui passent, et rien d'autre (la garde des tests).
#[cfg(test)]
const PERMISES: &[&str] = &[
    "SystemRoot",
    "windir",
    "SystemDrive",
    "ComSpec",
    "PATHEXT",
    "PATH",
    "TEMP",
    "TMP",
    "PSModulePath",
    "PSModuleAnalysisCachePath",
    "OS",
    "PROCESSOR_ARCHITECTURE",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "CommonProgramFiles",
    "ProgramData",
    "ALLUSERSPROFILE",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "COMPUTERNAME",
];

/// Les variables d'un programme lancé en administrateur, à partir des dossiers de Windows. Un dossier que Windows n'a
/// pas donné laisse sa variable absente : jamais de valeur reprise de l'environnement du compte.
pub(crate) fn variables(d: &Dossiers) -> Vec<(&'static str, OsString)> {
    let s = &d.systeme;
    let w = &d.windows;
    let chemins = |liste: &[PathBuf]| std::env::join_paths(liste).unwrap_or_default();
    let temp = w.join("Temp");
    let mut v: Vec<(&'static str, OsString)> = vec![
        ("SystemRoot", w.clone().into_os_string()),
        ("windir", w.clone().into_os_string()),
        ("ComSpec", s.join("cmd.exe").into_os_string()),
        ("PATHEXT", PATHEXT.into()),
        (
            "PATH",
            chemins(&[s.clone(), w.clone(), s.join("Wbem"), s.join(r"WindowsPowerShell\v1.0")]),
        ),
        // Le dossier temporaire de Windows, pas celui du compte, qu'il peut remplir d'avance.
        ("TEMP", temp.clone().into_os_string()),
        ("TMP", temp.into_os_string()),
        // Les modules de Windows ($PSHOME\Modules), puis ceux installés pour tous (Program Files), que seul un
        // administrateur écrit ; jamais les Documents. PowerShell 5.1 prend une variable posée telle quelle, et n'y
        // ajoute le dossier du compte que si elle vaut HKCU puis HKLM, ce que cette valeur ne peut pas être.
        (
            "PSModulePath",
            chemins(
                &std::iter::once(s.join(r"WindowsPowerShell\v1.0\Modules"))
                    .chain(d.program_files.iter().map(|p| p.join(r"WindowsPowerShell\Modules")))
                    .collect::<Vec<_>>(),
            ),
        ),
        // Le cache d'analyse des modules vit dans le dossier du compte (LOCALAPPDATA, qu'il peut écrire) : NUL le
        // coupe (moyen documenté par Microsoft), PowerShell relit les modules eux-mêmes.
        ("PSModuleAnalysisCachePath", "NUL".into()),
        ("OS", "Windows_NT".into()),
        (
            "PROCESSOR_ARCHITECTURE",
            if cfg!(target_arch = "aarch64") {
                "ARM64"
            } else {
                "AMD64"
            }
            .into(),
        ),
    ];
    if let Some(l) = w.to_str().and_then(|t| t.get(..2)).filter(|l| l.ends_with(':')) {
        v.push(("SystemDrive", l.into()));
    }
    let dossiers = [
        ("ProgramFiles", &d.program_files),
        ("ProgramFiles(x86)", &d.program_files_x86),
        ("CommonProgramFiles", &d.fichiers_communs),
        ("ProgramData", &d.program_data),
        ("ALLUSERSPROFILE", &d.program_data),
        ("USERPROFILE", &d.profil),
        ("APPDATA", &d.appdata),
        ("LOCALAPPDATA", &d.appdata_local),
    ];
    for (nom, p) in dossiers {
        if let Some(p) = p {
            v.push((nom, p.clone().into_os_string()));
        }
    }
    if let Some(n) = &d.ordinateur {
        v.push(("COMPUTERNAME", n.into()));
    }
    v
}

/// Vide l'environnement hérité de `c` et n'y met que les variables de `variables`, avec les dossiers de ce Windows.
pub(crate) fn reduire(c: &mut Command) -> &mut Command {
    c.env_clear();
    for (nom, valeur) in variables(dossiers()) {
        c.env(nom, valeur);
    }
    c
}

/// Les dossiers de ce Windows, lus une fois.
pub(crate) fn dossiers() -> &'static Dossiers {
    static D: std::sync::OnceLock<Dossiers> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let systeme = crate::commande::dossier_systeme().to_path_buf();
        // Repli jamais vu : le parent de System32 plutôt que la variable SystemRoot.
        let windows =
            dossier_windows().unwrap_or_else(|| systeme.parent().map_or_else(|| systeme.clone(), Path::to_path_buf));
        Dossiers {
            program_files: dossier_connu(&PROGRAM_FILES),
            program_files_x86: dossier_connu(&PROGRAM_FILES_X86),
            fichiers_communs: dossier_connu(&FICHIERS_COMMUNS),
            program_data: dossier_connu(&PROGRAM_DATA),
            profil: dossier_connu(&PROFIL),
            appdata: dossier_connu(&APPDATA),
            appdata_local: dossier_connu(&APPDATA_LOCAL),
            ordinateur: nom_ordinateur(),
            systeme,
            windows,
        }
    })
}

// Les KNOWNFOLDERID de Microsoft (learn.microsoft.com, « KNOWNFOLDERID »).
static PROGRAM_FILES: GUID = GUID::from_u128(0x905e63b6_c1bf_494e_b29c_65b732d3d21a);
static PROGRAM_FILES_X86: GUID = GUID::from_u128(0x7c5a40ef_a0fb_4bfc_874a_c0f2e0b9fa8e);
static FICHIERS_COMMUNS: GUID = GUID::from_u128(0xf7f1ed05_9f6d_47a2_aaae_29d317c6f066);
static PROGRAM_DATA: GUID = GUID::from_u128(0x62ab5d82_fdc1_4dc3_a9dd_070d1d495d97);
static PROFIL: GUID = GUID::from_u128(0x5e6c858f_0e22_4760_9afe_ea3317b67173);
static APPDATA: GUID = GUID::from_u128(0x3eb685db_65f9_4cf6_a03a_e3ef65729f3d);
static APPDATA_LOCAL: GUID = GUID::from_u128(0xf1b32785_6fba_4fcf_9d55_7b8e7f157091);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemWindowsDirectoryW(tampon: *mut u16, taille: u32) -> u32;
    fn GetComputerNameW(tampon: *mut u16, taille: *mut u32) -> i32;
}

#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(id: *const GUID, drapeaux: u32, jeton: *mut std::ffi::c_void, chemin: *mut PWSTR) -> i32;
}

fn dossier_windows() -> Option<PathBuf> {
    let mut tampon = [0u16; 1024];
    // SAFETY: la taille passée est celle du tampon ; Windows y écrit au plus autant de caractères et rend leur nombre,
    // ou la taille qu'il faudrait (plus grande que le tampon), ou 0.
    let n = unsafe { GetSystemWindowsDirectoryW(tampon.as_mut_ptr(), 1024) } as usize;
    tampon
        .get(..n)
        .filter(|t| !t.is_empty())
        .map(|t| PathBuf::from(OsString::from_wide(t)))
}

fn nom_ordinateur() -> Option<String> {
    let mut tampon = [0u16; 64];
    let mut n = 64u32;
    // SAFETY: `n` dit la taille du tampon ; en cas de succès, Windows y écrit le nom et met dans `n` sa longueur sans
    // le zéro final (au plus 15 caractères NetBIOS).
    let ok = unsafe { GetComputerNameW(tampon.as_mut_ptr(), &raw mut n) } != 0;
    let nom = String::from_utf16(tampon.get(..n as usize)?).ok()?;
    (ok && !nom.is_empty()).then_some(nom)
}

/// KF_FLAG_DEFAULT_PATH | KF_FLAG_NOT_PARENT_RELATIVE (learn.microsoft.com, « KNOWN_FOLDER_FLAG ») : le chemin par
/// défaut du dossier, indépendant de l'endroit où se trouve son parent, et non le chemin « actuel, peut-être
/// redirigé » que Windows lit dans HKCU\…\User Shell Folders, que le compte peut réécrire. Sans effet sur les
/// dossiers fixes (Program Files, ProgramData) ni sur le profil, que Windows ne redirige pas.
const PAR_DEFAUT: u32 = 0x0000_0400 | 0x0000_0200;

/// Un dossier connu du compte qui fait tourner ce processus (jeton nul), à son emplacement par défaut, ou `None` si
/// Windows n'en donne pas.
fn dossier_connu(id: &GUID) -> Option<PathBuf> {
    let mut chemin = PWSTR::null();
    // SAFETY: `id` est un GUID valide pour l'appel ; drapeaux documentés et jeton nul (le compte de ce processus) ;
    // Windows écrit dans `chemin` une chaîne allouée par CoTaskMemAlloc, à libérer même en cas d'échec.
    let r = unsafe { SHGetKnownFolderPath(id, PAR_DEFAUT, std::ptr::null_mut(), &raw mut chemin) };
    // SAFETY: en cas de succès, `chemin` est une chaîne terminée par un zéro, lue avant d'être libérée.
    let lu = (r >= 0 && !chemin.is_null()).then(|| PathBuf::from(OsString::from_wide(unsafe { chemin.as_wide() })));
    // SAFETY: CoTaskMemFree accepte un pointeur nul ; sinon c'est la chaîne rendue par SHGetKnownFolderPath, libérée
    // une seule fois, après sa dernière lecture.
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(chemin.0.cast_const().cast())) };
    lu.filter(|p| p.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exemple() -> Dossiers {
        Dossiers {
            systeme: PathBuf::from(r"C:\Windows\System32"),
            windows: PathBuf::from(r"C:\Windows"),
            program_files: Some(PathBuf::from(r"C:\Program Files")),
            program_files_x86: Some(PathBuf::from(r"C:\Program Files (x86)")),
            fichiers_communs: Some(PathBuf::from(r"C:\Program Files\Common Files")),
            program_data: Some(PathBuf::from(r"C:\ProgramData")),
            profil: Some(PathBuf::from(r"C:\Users\alice")),
            appdata: Some(PathBuf::from(r"C:\Users\alice\AppData\Roaming")),
            appdata_local: Some(PathBuf::from(r"C:\Users\alice\AppData\Local")),
            ordinateur: Some("SALON".to_string()),
        }
    }

    /// Chaque variable passée est de la liste permise, une seule fois ; PSModulePath ne contient que les modules de
    /// Windows et de Program Files, jamais les Documents ; PATH, que des dossiers du système.
    #[test]
    fn seules_les_variables_permises_passent() {
        let v = variables(&exemple());
        let noms: Vec<_> = v.iter().map(|(n, _)| *n).collect();
        let mut tries = noms.clone();
        tries.sort_unstable();
        let mut permises = PERMISES.to_vec();
        permises.sort_unstable();
        assert_eq!(tries, permises);
        let valeur = |n: &str| {
            v.iter()
                .find(|(m, _)| *m == n)
                .map(|(_, x)| x.to_string_lossy().into_owned())
        };
        assert_eq!(
            valeur("PSModulePath").as_deref(),
            Some(r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules;C:\Program Files\WindowsPowerShell\Modules")
        );
        assert_eq!(
            valeur("PATH").as_deref(),
            Some(r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0")
        );
        assert_eq!(valeur("TEMP").as_deref(), Some(r"C:\Windows\Temp"));
        assert_eq!(valeur("SystemDrive").as_deref(), Some("C:"));
        // Un dossier que Windows n'a pas donné : sa variable manque, rien n'est repris d'ailleurs.
        let v = variables(&Dossiers {
            program_files: None,
            profil: None,
            ..exemple()
        });
        assert!(v.iter().all(|(n, _)| *n != "ProgramFiles" && *n != "USERPROFILE"));
        let modules = v.iter().find(|(n, _)| *n == "PSModulePath").unwrap();
        assert_eq!(modules.1, r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules");
    }

    /// Le compte peut déplacer ses dossiers (HKCU\…\User Shell Folders) : le fils élevé n'en tient pas compte et prend
    /// le dossier par défaut. Sous Wine seulement : sur un vrai Windows, le test changerait le dossier de la personne.
    #[test]
    fn les_dossiers_du_profil_ne_suivent_pas_le_registre_du_compte() {
        use winreg::RegKey;
        use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
        if !crate::commande::sous_wine() {
            return crate::essais::saute("change HKCU : sous Wine seulement");
        }
        let Ok(cle) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            KEY_READ | KEY_WRITE,
        ) else {
            return crate::essais::saute("User Shell Folders absent");
        };
        let piege = std::env::temp_dir().join(format!("vanguard-piege-{}", std::process::id()));
        std::fs::create_dir_all(&piege).unwrap();
        let avant = cle.get_raw_value("Local AppData").ok();
        cle.set_value("Local AppData", &piege.as_os_str()).unwrap();
        let lu = dossier_connu(&APPDATA_LOCAL);
        match avant {
            Some(v) => cle.set_raw_value("Local AppData", &v).unwrap(),
            None => cle.delete_value("Local AppData").unwrap(),
        }
        let _ = std::fs::remove_dir(&piege);
        let lu = lu.expect("LOCALAPPDATA par défaut");
        assert_ne!(lu, piege);
        assert!(lu.ends_with(r"AppData\Local"), "{}", lu.display());
        // Les drapeaux valent pour chaque dossier demandé : Windows les donne tous.
        let d = dossiers();
        let tous = [
            &d.program_files,
            &d.program_files_x86,
            &d.fichiers_communs,
            &d.program_data,
            &d.profil,
            &d.appdata,
            &d.appdata_local,
        ];
        assert!(tous.iter().all(|p| p.is_some()), "{d:?}");
    }

    /// La commande réduite ne garde rien de l'environnement de Vanguard : un vrai programme lancé ainsi (cmd.exe,
    /// `set`) ne voit que les variables permises.
    #[test]
    fn la_commande_reduite_ne_voit_que_la_liste() {
        let mut c = Command::new(crate::commande::systeme32("cmd.exe"));
        reduire(&mut c);
        let posees: Vec<_> = c
            .get_envs()
            .map(|(n, v)| (n.to_string_lossy().into_owned(), v.is_some()))
            .collect();
        assert!(
            posees.iter().all(|(n, posee)| *posee && PERMISES.contains(&n.as_str())),
            "{posees:?}"
        );
        // Le test tourne avec les variables de cargo (CARGO_PKG_NAME…) : aucune ne doit arriver au programme.
        let Ok(sortie) = c.args(["/d", "/c", "set"]).output() else {
            return crate::essais::saute("cmd.exe ne se lance pas");
        };
        let texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
        let vues: Vec<&str> = texte
            .lines()
            .filter_map(|l| l.split_once('=').map(|(n, _)| n))
            .collect();
        assert!(vues.iter().any(|n| n.eq_ignore_ascii_case("PSModulePath")), "{texte}");
        let etrangeres: Vec<_> = vues
            .iter()
            // PROMPT : posée par cmd.exe lui-même ; WINE… : par Wine à chaque processus qu'il crée.
            .filter(|n| {
                **n != "PROMPT" && !n.starts_with("WINE") && !PERMISES.iter().any(|p| p.eq_ignore_ascii_case(n))
            })
            .collect();
        assert!(etrangeres.is_empty(), "{etrangeres:?}");
    }
}
