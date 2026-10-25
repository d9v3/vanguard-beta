//! Portes dérobées classiques de Windows, à côté des lancements automatiques (persistance.rs) : un débogueur posé sur
//! un programme (Image File Execution Options), qui se lance à sa place ; un programme d'accessibilité de l'écran de
//! connexion remplacé par une invite de commandes ; un bureau ou un Userinit détourné dans Winlogon ; une DLL imposée à
//! chaque programme qui ouvre une fenêtre (AppInit_DLLs) ; un abonnement WMI permanent qui lance une commande. Tout se
//! lit dans le registre et les fichiers, sans PowerShell ; les abonnements, par WMI (PowerShell en secours).

use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use super::persistance::lancement_suspect;
use super::*;
use crate::commande::{decouper_commande, ps_texte};
use crate::machine::regles::{Os, regle};
use crate::ui::{affichable, couper};

const CAT: &str = "Persistance";

/// Ce que l'écran de connexion lance avant toute ouverture de session, avec les droits du système : touches
/// rémanentes (Maj cinq fois), options d'ergonomie, clavier visuel, Narrateur, Loupe, choix de l'écran et leur lanceur.
/// Un débogueur posé sur l'un d'eux, ou une copie de cmd.exe à sa place, ouvre une invite système sans mot de passe.
const ACCESSIBILITE: [&str; 7] = [
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "narrator.exe",
    "magnify.exe",
    "displayswitch.exe",
    "atbroker.exe",
];

const IFEO: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];

const SORTIE_SILENCIEUSE: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
];

/// Les interpréteurs de commandes et de scripts (nom sans « .exe ») : un débogueur ou un service qui lance l'un d'eux
/// sert à exécuter n'importe quoi, ce qu'aucun logiciel installé normalement ne fait.
pub(super) const INTERPRETES: [&str; 9] = [
    "cmd",
    "powershell",
    "powershell_ise",
    "pwsh",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
];

/// FLG_MONITOR_SILENT_PROCESS_EXIT : sans ce drapeau dans GlobalFlag, Windows ne lance pas MonitorProcess.
const SURVEILLER_LA_SORTIE: u32 = 0x200;

/// Ce qu'une entrée d'Image File Execution Options règle pour un programme.
struct Reglage {
    /// La clé telle que PowerShell l'écrit (« HKLM:\SOFTWARE\…\sethc.exe »), pour la correction.
    cle: String,
    programme: String,
    debogueur: Option<String>,
    drapeaux: Option<u32>,
}

/// Un programme lancé quand un autre se ferme (SilentProcessExit).
struct Moniteur {
    cle: String,
    programme: String,
    processus: String,
}

/// GlobalFlag s'écrit en DWORD, mais gflags et certains outils le posent en texte (« 0x200 », « 512 »).
fn lire_drapeaux(texte: &str) -> Option<u32> {
    let t = texte.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hexa) => u32::from_str_radix(hexa, 16).ok(),
        None => t.parse().ok(),
    }
}

/// Les entrées d'Image File Execution Options qui posent un débogueur ou des drapeaux, et le nombre de programmes
/// lus. `None` si aucune des deux clés ne s'ouvre.
fn lire_ifeo() -> Option<(usize, Vec<Reglage>)> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut lus: Option<(usize, Vec<Reglage>)> = None;
    for racine in IFEO {
        let Ok(cle) = hklm.open_subkey(racine) else {
            continue;
        };
        let (total, reglages) = lus.get_or_insert_with(|| (0, Vec::new()));
        for programme in cle.enum_keys().flatten() {
            let Ok(sous) = cle.open_subkey(&programme) else {
                continue;
            };
            *total += 1;
            let debogueur = sous
                .get_value::<String, _>("Debugger")
                .ok()
                .filter(|d| !d.trim().is_empty());
            let drapeaux = sous.get_value::<u32, _>("GlobalFlag").ok().or_else(|| {
                sous.get_value::<String, _>("GlobalFlag")
                    .ok()
                    .and_then(|t| lire_drapeaux(&t))
            });
            if debogueur.is_some() || drapeaux.is_some() {
                reglages.push(Reglage {
                    cle: format!(r"HKLM:\{racine}\{programme}"),
                    programme,
                    debogueur,
                    drapeaux,
                });
            }
        }
    }
    lus
}

fn lire_moniteurs() -> Vec<Moniteur> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut moniteurs = Vec::new();
    for racine in SORTIE_SILENCIEUSE {
        // Absente sur un Windows où personne ne s'en est servi : rien à lire.
        let Ok(cle) = hklm.open_subkey(racine) else {
            continue;
        };
        for programme in cle.enum_keys().flatten() {
            let processus = cle
                .open_subkey(&programme)
                .and_then(|k| k.get_value::<String, _>("MonitorProcess"))
                .unwrap_or_default();
            if !processus.trim().is_empty() {
                moniteurs.push(Moniteur {
                    cle: format!(r"HKLM:\{racine}\{programme}"),
                    programme,
                    processus,
                });
            }
        }
    }
    moniteurs
}

/// Pourquoi ce débogueur ressemble à une porte dérobée, ou `None`. Un débogueur ordinaire (Process Explorer à la place
/// du Gestionnaire des tâches, celui de Visual Studio) n'y tombe pas : seuls un interpréteur de commandes ou de scripts
/// et les formes de malware de `lancement_suspect` (dossier temporaire ou public, PowerShell encodé…) sont retenus.
fn debogueur_suspect(valeur: &str) -> Option<&'static str> {
    let (exe, args) = decouper_commande(valeur);
    if let Some(raison) = lancement_suspect(&exe, &args) {
        return Some(raison);
    }
    let exe = exe.trim().trim_matches('"').to_lowercase().replace('/', "\\");
    let programme = exe.rsplit('\\').next().unwrap_or(&exe).trim_end_matches(".exe");
    INTERPRETES.contains(&programme).then_some(tr!(
        "un interpréteur de commandes ou de scripts se lance à sa place",
        "a command or script interpreter starts in its place"
    ))
}

fn est_accessibilite(programme: &str) -> bool {
    ACCESSIBILITE.iter().any(|a| a.eq_ignore_ascii_case(programme.trim()))
}

fn juger_ifeo(total: usize, reglages: &[Reglage], moniteurs: &[Moniteur]) -> Vec<Constat> {
    // Le nom du programme et la commande viennent de qui a posé la clé : montrés inoffensifs, la correction vise la
    // vraie clé.
    let mut constats = Vec::new();
    for r in reglages {
        let Some(debogueur) = &r.debogueur else {
            continue;
        };
        let (programme, valeur) = (affichable(&r.programme), couper(&affichable(debogueur), 160));
        let message = if est_accessibilite(&r.programme) {
            trf!(
                "Porte dérobée sur « {programme} » : un débogueur le remplace ({valeur}). À l'écran de connexion, ce raccourci d'accessibilité ouvre alors ce programme avec les droits du système, sans mot de passe.",
                "Backdoor on “{programme}”: a debugger replaces it ({valeur}). At the sign-in screen, this accessibility shortcut then opens that program with system rights, without a password."
            )
        } else if let Some(raison) = debogueur_suspect(debogueur) {
            trf!(
                "Programme détourné « {programme} » : à chaque lancement, Windows lance à sa place {valeur} ({raison}).",
                "Hijacked program “{programme}”: each time it starts, Windows runs {valeur} instead ({raison})."
            )
        } else {
            continue;
        };
        constats.push(alerte(CAT, Niveau::Eleve, message).corriger(
            trf!(
                "Retirer le débogueur de « {programme} » (Image File Execution Options)",
                "Remove the debugger from “{programme}” (Image File Execution Options)"
            ),
            &[format!(
                "Remove-ItemProperty -LiteralPath '{}' -Name Debugger",
                ps_texte(&r.cle)
            )],
        ));
    }
    for m in moniteurs {
        // Sans le drapeau sur le programme surveillé, Windows ne lance rien : un reste inoffensif.
        let actif = reglages.iter().any(|r| {
            r.programme.eq_ignore_ascii_case(&m.programme) && r.drapeaux.is_some_and(|d| d & SURVEILLER_LA_SORTIE != 0)
        });
        if !actif {
            continue;
        }
        let niveau = if est_accessibilite(&m.programme) || debogueur_suspect(&m.processus).is_some() {
            Niveau::Eleve
        } else {
            Niveau::Moyen
        };
        let (programme, processus) = (affichable(&m.programme), couper(&affichable(&m.processus), 160));
        constats.push(
            alerte(
                CAT,
                niveau,
                trf!(
                    "{processus} se lance chaque fois que « {programme} » se ferme (SilentProcessExit) : un moyen discret de se faire relancer, rarement utilisé hors des tests de logiciels.",
                    "{processus} starts each time “{programme}” closes (SilentProcessExit): a discreet way to get started again, rarely used outside software testing."
                ),
            )
            .corriger(
                trf!(
                    "Ne plus rien lancer à la fermeture de « {programme} »",
                    "Stop starting anything when “{programme}” closes"
                ),
                &[format!(
                    "Remove-ItemProperty -LiteralPath '{}' -Name MonitorProcess",
                    ps_texte(&m.cle)
                )],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Aucun programme détourné par un débogueur (Image File Execution Options, {total} entrées lues).",
                "No program hijacked by a debugger (Image File Execution Options, {total} entries read)."
            ),
        ));
    }
    constats
}

fn ifeo() -> Vec<Constat> {
    let Some((total, reglages)) = lire_ifeo() else {
        return vec![registre_illisible(CAT)];
    };
    juger_ifeo(total, &reglages, &lire_moniteurs())
}

/// Le dossier de Windows (« C:\Windows »).
fn racine_windows() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

/// Deux fichiers au même contenu ? La taille d'abord : le contenu n'est lu que pour deux fichiers de même taille, ce
/// qui n'arrive pas sur un Windows sain. `None` si l'un des deux ne se lit pas.
fn identiques(a: &Path, b: &Path) -> Option<bool> {
    let (ta, tb) = (std::fs::metadata(a).ok()?.len(), std::fs::metadata(b).ok()?.len());
    if ta != tb {
        return Some(false);
    }
    Some(std::fs::read(a).ok()? == std::fs::read(b).ok()?)
}

/// `verifies` : les programmes d'accessibilité comparés jusqu'au bout ; `remplaces` : (programme, ce qu'il copie) ;
/// `illisibles` : ceux qui existent mais n'ont pas pu être comparés.
fn juger_remplaces(verifies: usize, remplaces: &[(&str, &str)], illisibles: &[&str]) -> Vec<Constat> {
    let mut constats: Vec<Constat> = remplaces
        .iter()
        .map(|&(programme, copie)| {
            alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "« {programme} » est une copie de {copie} : à l'écran de connexion, son raccourci d'accessibilité ouvre {copie} avec les droits du système, sans mot de passe (porte dérobée classique).",
                    "“{programme}” is a copy of {copie}: at the sign-in screen, its accessibility shortcut opens {copie} with system rights, without a password (a classic backdoor)."
                ),
            )
            .manuel(
                tr!(
                    "Remettre le vrai programme : vérifier les fichiers de Windows (commande ci-dessous, en administrateur), puis lancer une analyse antivirus complète",
                    "Put the real program back: check Windows' files (command below, as administrator), then run a full antivirus scan"
                ),
                &["sfc /scannow"],
            )
        })
        .collect();
    if !illisibles.is_empty() {
        constats.push(impossible(
            CAT,
            &trf!(
                "programmes d'accessibilité illisibles : {}",
                "unreadable accessibility programs: {}",
                illisibles.join(", ")
            ),
        ));
    }
    if constats.is_empty() {
        constats.push(if verifies == 0 {
            impossible(
                CAT,
                tr!(
                    "aucun programme d'accessibilité trouvé",
                    "no accessibility program found"
                ),
            )
        } else {
            ok(
                CAT,
                trf!(
                    "Programmes d'accessibilité de l'écran de connexion intacts ({verifies} comparés à cmd, PowerShell et l'Explorateur).",
                    "Sign-in screen accessibility programs intact ({verifies} compared with cmd, PowerShell and Explorer)."
                ),
            )
        });
    }
    constats
}

fn programmes_remplaces() -> Vec<Constat> {
    let racine = PathBuf::from(racine_windows());
    let system32 = racine.join("System32");
    let modeles: Vec<(&str, PathBuf)> = [
        ("cmd.exe", system32.join("cmd.exe")),
        (
            "powershell.exe",
            system32.join(r"WindowsPowerShell\v1.0\powershell.exe"),
        ),
        ("explorer.exe", racine.join("explorer.exe")),
    ]
    .into_iter()
    .filter(|(_, chemin)| chemin.is_file())
    .collect();
    if modeles.is_empty() {
        return vec![impossible(
            CAT,
            tr!(
                "cmd.exe, PowerShell et l'Explorateur introuvables",
                "cmd.exe, PowerShell and Explorer not found"
            ),
        )];
    }
    let (mut verifies, mut remplaces, mut illisibles) = (0, Vec::new(), Vec::new());
    for programme in ACCESSIBILITE {
        let chemin = system32.join(programme);
        // Absent de cette édition de Windows : rien à comparer.
        if !chemin.is_file() {
            continue;
        }
        let comparaisons: Vec<(&str, Option<bool>)> = modeles
            .iter()
            .map(|(nom, modele)| (*nom, identiques(&chemin, modele)))
            .collect();
        if let Some((copie, _)) = comparaisons.iter().find(|(_, c)| *c == Some(true)) {
            remplaces.push((programme, *copie));
        } else if comparaisons.iter().any(|(_, c)| c.is_none()) {
            illisibles.push(programme);
        } else {
            verifies += 1;
        }
    }
    juger_remplaces(verifies, &remplaces, &illisibles)
}

const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Le bureau d'origine : « explorer.exe », parfois écrit avec son dossier.
fn bureau_d_origine(valeur: &str, racine: &str) -> bool {
    let v = valeur.trim().trim_matches('"').to_lowercase();
    v == "explorer.exe" || v == format!(r"{}\explorer.exe", racine.to_lowercase())
}

/// Userinit d'origine : « C:\Windows\system32\userinit.exe, », virgule finale comprise ; une entrée de plus après la
/// virgule est un programme ajouté à chaque ouverture de session.
fn userinit_d_origine(valeur: &str, racine: &str) -> bool {
    let attendus = [
        format!(r"{}\system32\userinit.exe", racine.to_lowercase()),
        r"%systemroot%\system32\userinit.exe".to_string(),
        "userinit.exe".to_string(),
    ];
    let entrees: Vec<String> = valeur
        .split(',')
        .map(|e| e.trim().trim_matches('"').to_lowercase())
        .filter(|e| !e.is_empty())
        .collect();
    matches!(&entrees[..], [seule] if attendus.contains(seule))
}

/// `shell`, `userinit` : les valeurs de Winlogon pour l'ordinateur ; `shell_du_compte` : celle du compte (absente
/// d'ordinaire) ; `cle_du_compte` : sa clé, pour la fenêtre administrateur (le HKCU de la personne).
fn juger_winlogon(
    shell: Option<&str>,
    userinit: Option<&str>,
    shell_du_compte: Option<&str>,
    racine: &str,
    cle_du_compte: &str,
) -> Vec<Constat> {
    let cle = format!(r"HKLM:\{WINLOGON}");
    let mut constats = Vec::new();
    if let Some(v) = shell.filter(|v| !v.trim().is_empty() && !bureau_d_origine(v, racine)) {
        let valeur = couper(&affichable(v), 160);
        constats.push(
            alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "Winlogon lance « {valeur} » comme bureau à l'ouverture de session, au lieu de l'Explorateur seul (explorer.exe) : ce programme démarre avec chaque session.",
                    "Winlogon starts “{valeur}” as the desktop at sign-in, instead of Explorer alone (explorer.exe): this program starts with every session."
                ),
            )
            .corriger(
                tr!(
                    "Remettre le bureau de Windows seul (Shell = explorer.exe, la valeur d'origine)",
                    "Put Windows' desktop back alone (Shell = explorer.exe, the original value)"
                ),
                &[format!(
                    "Set-ItemProperty -LiteralPath '{}' -Name Shell -Value 'explorer.exe' -Type String",
                    ps_texte(&cle)
                )],
            ),
        );
    }
    if let Some(v) = userinit.filter(|v| !v.trim().is_empty() && !userinit_d_origine(v, racine)) {
        let valeur = couper(&affichable(v), 160);
        let origine = format!(r"{racine}\system32\userinit.exe,");
        constats.push(
            alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "Winlogon lance « {valeur} » à l'ouverture de session, au lieu de userinit.exe seul : un programme ajouté là démarre avec chaque session.",
                    "Winlogon starts “{valeur}” at sign-in, instead of userinit.exe alone: a program added there starts with every session."
                ),
            )
            .corriger(
                trf!(
                    "Remettre Userinit d'origine ({origine})",
                    "Put the original Userinit back ({origine})"
                ),
                &[format!(
                    "Set-ItemProperty -LiteralPath '{}' -Name Userinit -Value '{}' -Type String",
                    ps_texte(&cle),
                    ps_texte(&origine)
                )],
            ),
        );
    }
    if let Some(v) = shell_du_compte.filter(|v| !v.trim().is_empty()) {
        let valeur = couper(&affichable(v), 160);
        constats.push(
            alerte(
                CAT,
                Niveau::Eleve,
                trf!(
                    "Votre compte remplace le bureau de Windows par « {valeur} » (Shell dans Winlogon) : ce programme démarre à chaque ouverture de votre session.",
                    "Your account replaces Windows' desktop with “{valeur}” (Shell in Winlogon): this program starts every time you sign in."
                ),
            )
            .corriger(
                tr!(
                    "Retirer ce remplacement : votre compte reprend le bureau de Windows",
                    "Remove this replacement: your account goes back to Windows' desktop"
                ),
                &[format!(
                    "Remove-ItemProperty -LiteralPath '{}' -Name Shell",
                    ps_texte(cle_du_compte)
                )],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Winlogon lance le bureau et l'ouverture de session de Windows, sans ajout.",
                "Winlogon starts Windows' desktop and sign-in program, with nothing added."
            ),
        ));
    }
    constats
}

fn winlogon() -> Vec<Constat> {
    let Ok(cle) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(WINLOGON) else {
        return vec![registre_illisible(CAT)];
    };
    let shell = cle.get_value::<String, _>("Shell").ok();
    let userinit = cle.get_value::<String, _>("Userinit").ok();
    let du_compte = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(WINLOGON)
        .and_then(|k| k.get_value::<String, _>("Shell"))
        .ok()
        .filter(|v| !v.trim().is_empty());
    // Le SID (whoami) seulement s'il y a quelque chose à corriger dans le compte.
    let cle_du_compte = if du_compte.is_some() {
        crate::reparer::hkcu_de_la_personne(crate::reparer::sid_de_la_personne().as_deref(), WINLOGON)
    } else {
        String::new()
    };
    juger_winlogon(
        shell.as_deref(),
        userinit.as_deref(),
        du_compte.as_deref(),
        &racine_windows(),
        &cle_du_compte,
    )
}

const APPINIT: [&str; 2] = [
    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
];

/// Chaque clé lue : (clé, LoadAppInit_DLLs, AppInit_DLLs). Les DLL ne sont chargées que si les deux y sont.
fn juger_appinit(lues: &[(&str, Option<u32>, Option<String>)]) -> Vec<Constat> {
    let mut constats = Vec::new();
    for (cle, charger, dlls) in lues {
        let Some(dlls) = dlls.as_deref().map(str::trim).filter(|d| !d.is_empty()) else {
            continue;
        };
        if *charger != Some(1) {
            continue;
        }
        let liste = couper(&affichable(dlls), 160);
        // Une DLL rangée dans un dossier temporaire, public ou de données d'application : rien d'installé normalement.
        let bas = dlls.to_lowercase();
        let cachee = lancement_suspect(dlls, "").is_some() || bas.contains("\\appdata\\");
        constats.push(
            alerte(
                CAT,
                if cachee { Niveau::Eleve } else { Niveau::Moyen },
                trf!(
                    "Une DLL est chargée dans chaque programme qui ouvre une fenêtre (AppInit_DLLs) : {liste}. De vieux logiciels le faisaient ; c'est surtout une façon pour un malware d'entrer dans tous les programmes.",
                    "A DLL is loaded into every program that opens a window (AppInit_DLLs): {liste}. Old software did this; it is mostly a way for malware to get into every program."
                ),
            )
            .corriger(
                tr!(
                    "Ne plus charger ces DLL (LoadAppInit_DLLs = 0, le réglage d'origine de Windows ; la liste reste notée)",
                    "Stop loading these DLLs (LoadAppInit_DLLs = 0, Windows' original setting; the list stays written down)"
                ),
                &[super::corrections::id(if *cle == APPINIT[1] { "appinit-coupe-32" } else { "appinit-coupe" })],
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucune DLL imposée à tous les programmes (AppInit_DLLs).",
                "No DLL forced into every program (AppInit_DLLs)."
            ),
        ));
    }
    constats
}

fn appinit() -> Vec<Constat> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let lues: Vec<(&str, Option<u32>, Option<String>)> = APPINIT
        .iter()
        .filter_map(|cle| {
            let k = hklm.open_subkey(cle).ok()?;
            Some((
                *cle,
                k.get_value::<u32, _>("LoadAppInit_DLLs").ok(),
                k.get_value::<String, _>("AppInit_DLLs").ok(),
            ))
        })
        .collect();
    if lues.is_empty() {
        return vec![registre_illisible(CAT)];
    }
    juger_appinit(&lues)
}

/// Les abonnements WMI permanents, en sections : ADM (droits administrateur), FLT (filtres : nom, requête), CMD
/// (consommateurs de commandes : nom, programme, ligne de commande), SCR (de scripts : nom, langage, fichier, texte),
/// LIE (liaisons : filtre, classe du consommateur, consommateur). Retours à la ligne et « | » remplacés, pour une
/// ligne par objet. Une classe absente de cette édition se lit comme vide ; un refus d'accès laisse la section sans
/// fin, donc non vérifiée.
const SCRIPT_WMI: &str = "function N($v) { (\"$v\" -replace '[\\r\\n]+', ' ' -replace '\\|', [string][char]0xA6).Trim() }; \
     try { 'ADM|' + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); 'ADM_FIN' } catch {}; \
     try { Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | ForEach-Object { 'FLT|' + (N $_.Name) + '|' + (N $_.Query) }; 'FLT_FIN' } catch {}; \
     try { try { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object { 'CMD|' + (N $_.Name) + '|' + (N $_.ExecutablePath) + '|' + (N $_.CommandLineTemplate) } } catch { if (\"$($_.Exception.NativeErrorCode)\" -ne 'InvalidClass') { throw } }; 'CMD_FIN' } catch {}; \
     try { try { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { 'SCR|' + (N $_.Name) + '|' + (N $_.ScriptingEngine) + '|' + (N $_.ScriptFileName) + '|' + (N $_.ScriptText) } } catch { if (\"$($_.Exception.NativeErrorCode)\" -ne 'InvalidClass') { throw } }; 'SCR_FIN' } catch {}; \
     try { Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object { 'LIE|' + (N $_.Filter.Name) + '|' + (N $_.Consumer.CimSystemProperties.ClassName) + '|' + (N $_.Consumer.Name) }; 'LIE_FIN' } catch {}";

/// Un texte sur une ligne de section, comme la fonction N du script : sauts de ligne en espaces, « | » en « ¦ ».
fn sur_une_ligne(v: &str) -> String {
    let mut sortie = String::with_capacity(v.len());
    let mut saut = false;
    for c in v.chars() {
        if matches!(c, '\r' | '\n') {
            if !saut {
                sortie.push(' ');
            }
            saut = true;
            continue;
        }
        saut = false;
        sortie.push(if c == '|' { '¦' } else { c });
    }
    sortie.trim().to_string()
}

/// Classe et nom d'une référence WMI (`\\.\root\subscription:CommandLineEventConsumer.Name="x"`), ce que
/// PowerShell résolvait en objet ($_.Consumer.Name) ; « \" » et « \\ » y sont échappés.
fn reference(chemin: &str) -> Option<(String, String)> {
    let sans_espace = if chemin.starts_with("\\\\") {
        chemin.split_once(':')?.1
    } else {
        chemin
    };
    let (classe, cle) = sans_espace.split_once('.')?;
    let valeur = cle.strip_prefix("Name=")?.strip_prefix('"')?.strip_suffix('"')?;
    let mut nom = String::new();
    let mut lettres = valeur.chars();
    while let Some(c) = lettres.next() {
        nom.push(if c == '\\' { lettres.next()? } else { c });
    }
    Some((classe.to_string(), nom))
}

/// Les sections de SCRIPT_WMI lues par WMI, et si toutes ont pu l'être (la section ADM l'est toujours) : sinon,
/// PowerShell est essayé, et faute de mieux cette lecture partielle dit « non vérifié ».
fn sortie_wmi() -> (bool, String) {
    use super::wmi::{Reponse, interroger, requete};
    use std::fmt::Write;
    const ABONNEMENTS: &str = r"root\subscription";
    let mut sortie = format!(
        "ADM|{}\nADM_FIN\n",
        if super::processus::eleve() { "True" } else { "False" }
    );
    let mut complet = true;
    let champ = |l: &super::wmi::Ligne, c: &str| sur_une_ligne(l[c].texte().unwrap_or_default());
    let mut section = |nom: &str, lignes: Option<Vec<String>>| match lignes {
        Some(lignes) => {
            for l in lignes {
                let _ = writeln!(sortie, "{nom}|{l}");
            }
            let _ = writeln!(sortie, "{nom}_FIN");
        }
        None => complet = false,
    };
    section(
        "FLT",
        requete(ABONNEMENTS, "__EventFilter", "", &["Name", "Query"]).map(|l| {
            l.iter()
                .map(|f| format!("{}|{}", champ(f, "Name"), champ(f, "Query")))
                .collect()
        }),
    );
    // Une classe de consommateur que ce Windows n'inscrit pas : aucun consommateur, pas un échec.
    let consommateurs = |classe: &str, champs: &[&str]| match interroger(ABONNEMENTS, classe, "", champs) {
        Some(Reponse::Lignes(l)) => Some(
            l.iter()
                .map(|c| champs.iter().map(|n| champ(c, n)).collect::<Vec<_>>().join("|"))
                .collect(),
        ),
        Some(Reponse::ClasseAbsente) => Some(Vec::new()),
        None => None,
    };
    section(
        "CMD",
        consommateurs(
            "CommandLineEventConsumer",
            &["Name", "ExecutablePath", "CommandLineTemplate"],
        ),
    );
    section(
        "SCR",
        consommateurs(
            "ActiveScriptEventConsumer",
            &["Name", "ScriptingEngine", "ScriptFileName", "ScriptText"],
        ),
    );
    section(
        "LIE",
        requete(ABONNEMENTS, "__FilterToConsumerBinding", "", &["Filter", "Consumer"]).map(|l| {
            l.iter()
                .map(|b| {
                    let filtre = b["Filter"]
                        .texte()
                        .and_then(reference)
                        .map(|(_, n)| n)
                        .unwrap_or_default();
                    let (classe, nom) = b["Consumer"].texte().and_then(reference).unwrap_or_default();
                    format!(
                        "{}|{}|{}",
                        sur_une_ligne(&filtre),
                        sur_une_ligne(&classe),
                        sur_une_ligne(&nom)
                    )
                })
                .collect()
        }),
    );
    (complet, sortie)
}

/// Les abonnements par WMI ; PowerShell s'il a manqué une section, et sinon la lecture partielle (« non vérifié »).
fn abonnements() -> String {
    let (complet, sortie) = sortie_wmi();
    if complet {
        return sortie;
    }
    ps(SCRIPT_WMI).unwrap_or(sortie)
}

/// Un consommateur qui lance quelque chose : sa classe, son nom, ce qu'il lance.
struct Consommateur<'a> {
    classe: &'static str,
    nom: &'a str,
    lance: String,
}

/// Windows ne pose lui-même que des consommateurs qui écrivent au journal (NTEventLogEventConsumer : « SCM Event Log
/// Consumer », « BVTConsumer » sur les anciennes versions) : ils ne lancent rien et ne sont pas lus ici. Un
/// consommateur de commandes ou de scripts qui reprendrait leur nom n'est pas excusé : un nom se choisit.
fn juger_wmi(sortie: Option<&str>) -> Vec<Constat> {
    let Some(sortie) = sortie else {
        return vec![illisible(CAT)];
    };
    let s = |nom: &str| section(Some(sortie), nom);
    let (Some(commandes), Some(scripts), Some(liens)) = (s("CMD"), s("SCR"), s("LIE")) else {
        let admin = s("ADM").and_then(|l| l.first().map(|v| v.trim().eq_ignore_ascii_case("true")));
        return vec![impossible(
            CAT,
            if admin == Some(false) {
                tr!(
                    "abonnements WMI lisibles seulement en administrateur : relancer Vanguard en administrateur",
                    "WMI subscriptions readable only as administrator: run Vanguard again as administrator"
                )
            } else {
                tr!("abonnements WMI illisibles", "WMI subscriptions unreadable")
            },
        )];
    };
    let filtres: Vec<(&str, &str)> = s("FLT")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|l| l.split_once('|'))
        .collect();
    let liens: Vec<(&str, &str, &str)> = liens
        .iter()
        .filter_map(|l| {
            let mut c = l.splitn(3, '|');
            Some((c.next()?, c.next()?, c.next()?))
        })
        .collect();
    let mut consommateurs = Vec::new();
    for l in &commandes {
        let c: Vec<&str> = l.splitn(3, '|').collect();
        let [nom, exe, modele] = c[..] else {
            continue;
        };
        let lance = [exe.trim(), modele.trim()]
            .iter()
            .filter(|t| !t.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        consommateurs.push(Consommateur {
            classe: "CommandLineEventConsumer",
            nom,
            lance,
        });
    }
    for l in &scripts {
        let c: Vec<&str> = l.splitn(4, '|').collect();
        let [nom, langage, fichier, texte] = c[..] else {
            continue;
        };
        let script = if fichier.trim().is_empty() { texte } else { fichier };
        consommateurs.push(Consommateur {
            classe: "ActiveScriptEventConsumer",
            nom,
            lance: format!("{} : {}", langage.trim(), script.trim()),
        });
    }
    let mut constats = Vec::new();
    for c in &consommateurs {
        let filtres_lies: Vec<&str> = liens
            .iter()
            .filter(|(_, classe, nom)| classe.eq_ignore_ascii_case(c.classe) && *nom == c.nom)
            .map(|(filtre, _, _)| *filtre)
            .collect();
        let (nom, lance) = (affichable(c.nom), couper(&affichable(&c.lance), 160));
        let message = if let Some(filtre) = filtres_lies.first() {
            let quand = filtres
                .iter()
                .find(|(f, _)| f == filtre)
                .map_or_else(|| affichable(filtre), |(_, requete)| couper(&affichable(requete), 120));
            trf!(
                "Abonnement WMI permanent « {nom} » : à l'événement « {quand} », Windows lance {lance} avec les droits du système, même sans session ouverte.",
                "Permanent WMI subscription “{nom}”: on the event “{quand}”, Windows runs {lance} with system rights, even with nobody signed in."
            )
        } else {
            trf!(
                "Consommateur WMI permanent « {nom} » qui lance {lance}, relié à aucun événement pour l'instant : un reste, ou une porte qui attend d'être rebranchée.",
                "Permanent WMI consumer “{nom}” that runs {lance}, tied to no event for now: a leftover, or a door waiting to be plugged back in."
            )
        };
        // Les commandes visent les vrais noms ; un filtre n'est retiré que s'il ne sert à aucun autre consommateur.
        let espace = "Get-CimInstance -Namespace root/subscription -ClassName";
        let mut retirer = Vec::new();
        if !filtres_lies.is_empty() {
            retirer.push(format!(
                "{espace} __FilterToConsumerBinding | Where-Object {{ $_.Consumer.Name -eq '{}' }} | Remove-CimInstance",
                ps_texte(c.nom)
            ));
        }
        retirer.push(format!(
            "{espace} {} | Where-Object {{ $_.Name -eq '{}' }} | Remove-CimInstance",
            c.classe,
            ps_texte(c.nom)
        ));
        for filtre in &filtres_lies {
            let partage = liens.iter().any(|(f, _, n)| f == filtre && *n != c.nom);
            if !partage {
                retirer.push(format!(
                    "{espace} __EventFilter | Where-Object {{ $_.Name -eq '{}' }} | Remove-CimInstance",
                    ps_texte(filtre)
                ));
            }
        }
        let retirer: Vec<&str> = retirer.iter().map(String::as_str).collect();
        constats.push(
            alerte(
                CAT,
                if filtres_lies.is_empty() { Niveau::Moyen } else { Niveau::Eleve },
                message,
            )
            .manuel(
                tr!(
                    "Si vous ne l'avez pas posé vous-même : le retirer (commandes ci-dessous, en administrateur), puis lancer une analyse antivirus complète",
                    "If you did not set it up yourself: remove it (commands below, as administrator), then run a full antivirus scan"
                ),
                &retirer,
            ),
        );
    }
    if constats.is_empty() {
        constats.push(ok(
            CAT,
            trf!(
                "Aucun abonnement WMI permanent ne lance de commande ni de script ({} filtre(s) d'événements lus).",
                "No permanent WMI subscription runs a command or script ({} event filter(s) read).",
                filtres.len()
            ),
        ));
    }
    constats
}

regle!(
    "WIN-PRS-002",
    Os::Windows,
    221,
    (
        "programmes détournés par un débogueur (Image File Execution Options)",
        "programs hijacked by a debugger (Image File Execution Options)"
    ),
    &[
        "CIS Controls v8 13.2",
        "MITRE ATT&CK T1546.012",
        "MITRE ATT&CK T1546.008"
    ],
    ifeo
);

regle!(
    "WIN-PRS-003",
    Os::Windows,
    222,
    (
        "programmes d'accessibilité de l'écran de connexion remplacés",
        "sign-in screen accessibility programs replaced"
    ),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1546.008"],
    programmes_remplaces
);

regle!(
    "WIN-PRS-004",
    Os::Windows,
    223,
    ("bureau et Userinit de Winlogon", "Winlogon desktop and Userinit"),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1547.004"],
    winlogon
);

regle!(
    "WIN-PRS-005",
    Os::Windows,
    224,
    (
        "DLL imposées à tous les programmes (AppInit_DLLs)",
        "DLLs forced into every program (AppInit_DLLs)"
    ),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1546.010"],
    appinit
);

regle!(
    "WIN-PRS-006",
    Os::Windows,
    225,
    ("abonnements WMI permanents", "permanent WMI subscriptions"),
    &["CIS Controls v8 13.2", "MITRE ATT&CK T1546.003"],
    || juger_wmi(Some(&abonnements()))
);

/// WIN-PRS-002 au corpus de détection : `ifeo|programme|débogueur|GlobalFlag` (vides : absents) et
/// `moniteur|programme|processus` (SilentProcessExit).
#[cfg(test)]
pub(super) fn corpus_ifeo(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let rien = |v: &str| (!v.is_empty()).then(|| v.to_string());
    let reglages: Vec<Reglage> = e
        .de("ifeo")
        .iter()
        .map(|c| Reglage {
            cle: format!(r"HKLM:\{}\{}", IFEO[0], c[0]),
            programme: c[0].to_string(),
            debogueur: rien(c[1]),
            drapeaux: rien(c[2]).and_then(|d| lire_drapeaux(&d)),
        })
        .collect();
    let moniteurs: Vec<Moniteur> = e
        .de("moniteur")
        .iter()
        .map(|c| Moniteur {
            cle: format!(r"HKLM:\corpus\{}", c[0]),
            programme: c[0].to_string(),
            processus: c[1].to_string(),
        })
        .collect();
    juger_ifeo(reglages.len(), &reglages, &moniteurs)
}

/// WIN-PRS-003 : `verifies|nombre`, `remplace|programme|ce qu'il copie`, `illisible|programme`.
#[cfg(test)]
pub(super) fn corpus_remplaces(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let verifies = e.de("verifies").first().map_or(0, |c| c[0].parse().unwrap());
    let remplaces: Vec<(&str, &str)> = e.de("remplace").iter().map(|c| (c[0], c[1])).collect();
    let illisibles: Vec<&str> = e.de("illisible").iter().map(|c| c[0]).collect();
    juger_remplaces(verifies, &remplaces, &illisibles)
}

/// WIN-PRS-004 : `shell|…`, `userinit|…`, `shell_du_compte|…` (absents : pas de valeur), dossier de Windows C:\Windows.
#[cfg(test)]
pub(super) fn corpus_winlogon(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let valeur = |nom: &str| e.de(nom).first().map(|c| c.join("|"));
    juger_winlogon(
        valeur("shell").as_deref(),
        valeur("userinit").as_deref(),
        valeur("shell_du_compte").as_deref(),
        r"C:\Windows",
        r"HKCU:\corpus",
    )
}

/// WIN-PRS-005 : `appinit|LoadAppInit_DLLs|AppInit_DLLs`, pour la clé 64 bits.
#[cfg(test)]
pub(super) fn corpus_appinit(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    let lues: Vec<(&str, Option<u32>, Option<String>)> = e
        .de("appinit")
        .iter()
        .map(|c| (APPINIT[0], c[0].parse().ok(), Some(c[1].to_string())))
        .collect();
    juger_appinit(&lues)
}

/// WIN-PRS-006 : la sortie du script WMI telle quelle (sections ADM, FLT, CMD, SCR, LIE).
#[cfg(test)]
pub(super) fn corpus_wmi(e: &crate::modele::corpus::Entree) -> Vec<Constat> {
    juger_wmi(Some(&e.texte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reglage(programme: &str, debogueur: Option<&str>, drapeaux: Option<u32>) -> Reglage {
        Reglage {
            cle: format!(r"HKLM:\{}\{programme}", IFEO[0]),
            programme: programme.to_string(),
            debogueur: debogueur.map(str::to_string),
            drapeaux,
        }
    }

    #[test]
    fn references_et_lignes() {
        assert_eq!(
            reference(r#"\\.\root\subscription:CommandLineEventConsumer.Name="Mise à jour""#),
            Some(("CommandLineEventConsumer".into(), "Mise à jour".into()))
        );
        assert_eq!(
            reference(r#"__EventFilter.Name="a\"b\\c""#),
            Some(("__EventFilter".into(), r#"a"b\c"#.into()))
        );
        assert_eq!(reference("pas une référence"), None);
        assert_eq!(
            sur_une_ligne(" powershell -c a|b\r\n\r\nsuite "),
            "powershell -c a¦b suite"
        );
    }

    /// Sous Wine, sans root\subscription : jamais « aucun abonnement », toujours « non vérifié ».
    #[test]
    fn abonnements_sous_wine() {
        if std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file() {
            assert!(juger_wmi(Some(&abonnements())).iter().all(|c| !c.verifie));
        }
    }

    #[test]
    fn debogueurs_detournes() {
        // Usages légitimes : Process Explorer à la place du Gestionnaire des tâches, débogueur de Visual Studio,
        // drapeaux de diagnostic sans débogueur.
        let sains = [
            reglage(
                "taskmgr.exe",
                Some(r#""C:\Users\alice\Downloads\ProcessExplorer\PROCEXP64.EXE""#),
                None,
            ),
            reglage("devenv.exe", Some(r#""C:\Windows\system32\vsjitdebugger.exe""#), None),
            reglage("jeu.exe", None, Some(0x0200_0000)),
        ];
        let c = juger_ifeo(120, &sains, &[]);
        assert!(c.len() == 1 && c[0].probleme.is_none(), "{}", c[0].message);
        // Sur un programme d'accessibilité, tout débogueur est une porte dérobée ; ailleurs, un interpréteur.
        let portes = [
            reglage("sethc.exe", Some(r"C:\Windows\System32\cmd.exe"), None),
            reglage("Utilman.exe", Some("notepad.exe"), None),
            reglage("msedge.exe", Some("powershell -w hidden -enc SQBFAFgA"), None),
            reglage("notepad.exe", Some(r"C:\Users\alice\AppData\Local\Temp\x.exe"), None),
            reglage("calc.exe", Some(r"C:\Windows\System32\cmd.exe /c start"), None),
        ];
        let c = juger_ifeo(120, &portes, &[]);
        assert_eq!(c.len(), 5);
        assert!(c.iter().all(|c| c.probleme == Some(Niveau::Eleve)));
        assert_eq!(
            c[0].correctif.as_ref().unwrap().commandes[0],
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger"
        );
        assert!(c[1].message.contains("Utilman.exe"));
    }

    #[test]
    fn programme_lance_a_la_fermeture() {
        let moniteur = |programme: &str, processus: &str| Moniteur {
            cle: format!(r"HKLM:\{}\{programme}", SORTIE_SILENCIEUSE[0]),
            programme: programme.to_string(),
            processus: processus.to_string(),
        };
        // Sans le drapeau 0x200 sur le programme, Windows ne lance rien.
        let c = juger_ifeo(10, &[], &[moniteur("notepad.exe", r"C:\Users\Public\a.exe")]);
        assert!(c[0].probleme.is_none());
        let drapeau = [reglage("notepad.exe", None, Some(SURVEILLER_LA_SORTIE))];
        let c = juger_ifeo(10, &drapeau, &[moniteur("notepad.exe", r"C:\Users\Public\a.exe")]);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].correctif.as_ref().unwrap().commandes[0].ends_with("-Name MonitorProcess"));
        let c = juger_ifeo(10, &drapeau, &[moniteur("notepad.exe", r"C:\Outils\journal.exe")]);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert_eq!(lire_drapeaux("0x200"), Some(0x200));
        assert_eq!(lire_drapeaux(" 512 "), Some(512));
        assert_eq!(lire_drapeaux("rien"), None);
    }

    /// Le nom de la clé et la commande viennent de qui les a posés : montrés inoffensifs, la correction vise la vraie
    /// clé, entre apostrophes doublées.
    #[test]
    fn noms_pieges_inoffensifs() {
        let piege = "x'\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}.exe";
        let r = [reglage(piege, Some("cmd.exe"), None)];
        let c = juger_ifeo(1, &r, &[]);
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!crate::ui::contient_un_piege(&c[0].message));
        assert!(!crate::ui::contient_un_piege(&k.action));
        assert!(k.commandes[0].contains("x''\x1b]52"), "{}", k.commandes[0]);
        let c = juger_winlogon(Some(piege), None, Some(piege), r"C:\Windows", r"HKCU:\x");
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|c| !crate::ui::contient_un_piege(&c.message)));
    }

    #[test]
    fn copies_de_cmd() {
        let dossier = crate::socle::dossier_local().join("accessibilite");
        std::fs::create_dir_all(&dossier).unwrap();
        let (cmd, sethc, osk) = (
            dossier.join("cmd.exe"),
            dossier.join("sethc.exe"),
            dossier.join("osk.exe"),
        );
        std::fs::write(&cmd, b"MZ invite de commandes").unwrap();
        std::fs::write(&sethc, b"MZ invite de commandes").unwrap();
        std::fs::write(&osk, b"MZ clavier visuel, autre").unwrap();
        assert_eq!(identiques(&sethc, &cmd), Some(true));
        assert_eq!(identiques(&osk, &cmd), Some(false));
        assert_eq!(identiques(&dossier.join("absent.exe"), &cmd), None);
        let c = juger_remplaces(4, &[("sethc.exe", "cmd.exe")], &[]);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(!c[0].correctif.as_ref().unwrap().automatique);
        assert!(juger_remplaces(5, &[], &[])[0].probleme.is_none());
        // Rien de comparé, ou un fichier illisible : dit, jamais compté comme sain.
        assert!(!juger_remplaces(0, &[], &[])[0].verifie);
        assert!(!juger_remplaces(4, &[], &["osk.exe"])[0].verifie);
    }

    #[test]
    fn winlogon_d_origine_ou_detourne() {
        let r = r"C:\WINDOWS";
        let sain = juger_winlogon(
            Some("explorer.exe"),
            Some(r"C:\Windows\system32\userinit.exe,"),
            None,
            r,
            "",
        );
        assert!(sain.len() == 1 && sain[0].probleme.is_none());
        assert!(bureau_d_origine(r"C:\Windows\Explorer.exe", r));
        assert!(userinit_d_origine(r"C:\Windows\system32\userinit.exe", r));
        assert!(!userinit_d_origine(
            r"C:\Windows\system32\userinit.exe,C:\Users\Public\a.exe,",
            r
        ));
        let c = juger_winlogon(
            Some("explorer.exe, C:\\Users\\alice\\AppData\\Roaming\\b.exe"),
            Some(r"C:\Windows\system32\userinit.exe,C:\Users\Public\a.exe,"),
            Some(r"C:\Users\alice\AppData\Roaming\c.exe"),
            r,
            r"Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        );
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|c| c.probleme == Some(Niveau::Eleve)));
        let commandes: Vec<&str> = c
            .iter()
            .map(|c| c.correctif.as_ref().unwrap().commandes[0].as_str())
            .collect();
        assert!(commandes[0].ends_with("-Name Shell -Value 'explorer.exe' -Type String"));
        assert!(commandes[1].contains(r"-Name Userinit -Value 'C:\WINDOWS\system32\userinit.exe,' -Type String"));
        assert!(
            commandes[2].starts_with(r"Remove-ItemProperty -LiteralPath 'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001")
        );
    }

    #[test]
    fn appinit_charge_ou_non() {
        let rien = juger_appinit(&[
            (APPINIT[0], Some(0), Some(r"C:\Outils\x.dll".into())),
            (APPINIT[1], Some(1), Some(String::new())),
        ]);
        assert!(rien.len() == 1 && rien[0].probleme.is_none());
        let c = juger_appinit(&[
            (APPINIT[0], Some(1), Some(r"C:\Program Files\Vieux\hook.dll".into())),
            (
                APPINIT[1],
                Some(1),
                Some(r"C:\Users\alice\AppData\Roaming\x.dll".into()),
            ),
        ]);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert_eq!(c[1].probleme, Some(Niveau::Eleve));
        assert_eq!(
            c[1].correctif.as_ref().unwrap().commandes[0],
            "vanguard:appinit-coupe-32"
        );
    }

    #[test]
    fn abonnements_wmi() {
        // Ceux de Windows (des consommateurs qui écrivent au journal) ne sont pas lus : rien à dire.
        let sain = "ADM|True\nADM_FIN\nFLT|SCM Event Log Filter|select * from MSFT_SCMEventLogEvent\nFLT_FIN\nCMD_FIN\nSCR_FIN\n\
                    LIE|SCM Event Log Filter|NTEventLogEventConsumer|SCM Event Log Consumer\nLIE_FIN";
        let c = juger_wmi(Some(sain));
        assert!(c.len() == 1 && c[0].probleme.is_none() && c[0].verifie);
        let porte = "ADM|True\nADM_FIN\nFLT|Demarrage|SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\nFLT_FIN\n\
                     CMD|Mise a jour|C:\\Windows\\System32\\cmd.exe|cmd.exe /c powershell -enc SQBFAFgA ¦ out-null\nCMD_FIN\n\
                     SCR|Reste|VBScript||CreateObject(\"WScript.Shell\").Run \"calc.exe\"\nSCR_FIN\n\
                     LIE|Demarrage|CommandLineEventConsumer|Mise a jour\nLIE_FIN";
        let c = juger_wmi(Some(porte));
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("powershell -enc"), "{}", c[0].message);
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!k.automatique);
        assert_eq!(k.commandes.len(), 3);
        assert!(k.commandes[1].contains("CommandLineEventConsumer | Where-Object { $_.Name -eq 'Mise a jour' }"));
        assert!(k.commandes[2].contains("__EventFilter | Where-Object { $_.Name -eq 'Demarrage' }"));
        // Un consommateur relié à rien : un reste, moins grave.
        assert_eq!(c[1].probleme, Some(Niveau::Moyen));
        assert_eq!(c[1].correctif.as_ref().unwrap().commandes.len(), 1);
        // Lecture refusée sans droits : non vérifié, avec la marche à suivre ; PowerShell absent : non vérifié.
        let refus = juger_wmi(Some("ADM|False\nADM_FIN\nFLT_FIN"));
        assert!(!refus[0].verifie && refus[0].message.contains(tr!("administrateur", "administrator")));
        assert!(!juger_wmi(None)[0].verifie);
    }
}
