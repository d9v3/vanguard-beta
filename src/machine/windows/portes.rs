//! Portes dérobées classiques de Windows, à côté des lancements automatiques (persistance.rs) : un débogueur posé sur
//! un programme (Image File Execution Options), qui se lance à sa place ; un programme d'accessibilité de l'écran de
//! connexion remplacé par une invite de commandes ; un bureau ou un Userinit détourné dans Winlogon ; une DLL imposée à
//! chaque programme qui ouvre une fenêtre (AppInit_DLLs) ; un abonnement WMI permanent qui lance une commande. Tout se
//! lit dans le registre et les fichiers, sans PowerShell ; les abonnements, par WMI (PowerShell en secours).

use std::path::{Path, PathBuf};

use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

use super::corrections::Resultat;
use super::persistance::lancement_suspect;
use super::*;
use crate::commande::{decouper_commande, ps_texte};
use crate::machine::gestes::{self, Acte, NomFichier, Vue};
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
    /// La racine où il a été lu (`gestes::Vue::ifeo`) ; la sous-clé est `programme`.
    vue: Vue,
    programme: String,
    debogueur: Option<String>,
    drapeaux: Option<u32>,
}

/// Un programme lancé quand un autre se ferme (SilentProcessExit).
struct Moniteur {
    /// La racine où il a été lu (`gestes::Vue::silencieuse`) ; la sous-clé est `programme`.
    vue: Vue,
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

/// La lecture d'IFEO et de SilentProcessExit dans la vue 64 bits, avec les drapeaux de `retirer_valeur_relue` : le
/// bilan et le processus élevé voient la même clé, quelle que soit la largeur du programme.
const LECTURE_64: u32 = winreg::enums::KEY_READ | winreg::enums::KEY_WOW64_64KEY;

/// Les entrées d'Image File Execution Options qui posent un débogueur ou des drapeaux, et le nombre de programmes
/// lus. `None` si aucune des deux clés ne s'ouvre.
fn lire_ifeo() -> Option<(usize, Vec<Reglage>)> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut lus: Option<(usize, Vec<Reglage>)> = None;
    for vue in Vue::TOUTES {
        let Ok(cle) = hklm.open_subkey_with_flags(vue.ifeo(), LECTURE_64) else {
            continue;
        };
        let (total, reglages) = lus.get_or_insert_with(|| (0, Vec::new()));
        for programme in cle.enum_keys().flatten() {
            let Ok(sous) = cle.open_subkey_with_flags(&programme, LECTURE_64) else {
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
                    vue,
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
    for vue in Vue::TOUTES {
        // Absente sur un Windows où personne ne s'en est servi : rien à lire.
        let Ok(cle) = hklm.open_subkey_with_flags(vue.silencieuse(), LECTURE_64) else {
            continue;
        };
        for programme in cle.enum_keys().flatten() {
            let processus = cle
                .open_subkey_with_flags(&programme, LECTURE_64)
                .and_then(|k| k.get_value::<String, _>("MonitorProcess"))
                .unwrap_or_default();
            if !processus.trim().is_empty() {
                moniteurs.push(Moniteur {
                    vue,
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

/// Le jugement d'Image File Execution Options et de SilentProcessExit, celui du bilan ET celui du processus élevé
/// avant d'écrire (`retirer_debogueur`, `retirer_moniteur`) : une seule fonction, sur les mêmes lectures.
fn juger_ifeo(total: usize, reglages: &[Reglage], moniteurs: &[Moniteur]) -> Vec<Constat> {
    // Le nom du programme et la commande viennent de qui a posé la clé : montrés inoffensifs, la correction désigne la
    // vraie clé par son nom en hexadécimal (`gestes::NomFichier`). Un nom que la grammaire refuse (séparateur, « .. »,
    // caractère de contrôle, trop long) est signalé, à retirer à la main : jamais de ligne qui viserait une autre clé.
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
        let constat = alerte(CAT, Niveau::Eleve, message);
        constats.push(match gestes::ligne_ifeo_debugger(r.vue, &r.programme) {
            Some(ligne) => constat.corriger(
                trf!(
                    "Retirer le débogueur de « {programme} » (Image File Execution Options)",
                    "Remove the debugger from “{programme}” (Image File Execution Options)"
                ),
                &[ligne],
            ),
            None => constat.manuel(
                trf!(
                    "Nom de clé piégé : retirer à la main dans regedit la valeur Debugger de HKLM\\{}\\{programme}",
                    "Booby-trapped key name: remove the Debugger value of HKLM\\{}\\{programme} by hand in regedit",
                    r.vue.ifeo()
                ),
                &[],
            ),
        });
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
        let constat = alerte(
            CAT,
            niveau,
            trf!(
                "{processus} se lance chaque fois que « {programme} » se ferme (SilentProcessExit) : un moyen discret de se faire relancer, rarement utilisé hors des tests de logiciels.",
                "{processus} starts each time “{programme}” closes (SilentProcessExit): a discreet way to get started again, rarely used outside software testing."
            ),
        );
        constats.push(match gestes::ligne_ifeo_silencieux(m.vue, &m.programme) {
            Some(ligne) => constat.corriger(
                trf!(
                    "Ne plus rien lancer à la fermeture de « {programme} »",
                    "Stop starting anything when “{programme}” closes"
                ),
                &[ligne],
            ),
            None => constat.manuel(
                trf!(
                    "Nom de clé piégé : retirer à la main dans regedit la valeur MonitorProcess de HKLM\\{}\\{programme}",
                    "Booby-trapped key name: remove the MonitorProcess value of HKLM\\{}\\{programme} by hand in regedit",
                    m.vue.silencieuse()
                ),
                &[],
            ),
        });
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

/// Un des constats propose-t-il exactement cette ligne ?
fn propose(constats: &[Constat], ligne: &str) -> bool {
    constats
        .iter()
        .filter_map(|c| c.correctif.as_ref())
        .any(|k| k.commandes.iter().any(|l| l == ligne))
}

/// Ce que le processus élevé doit retirer, relu et rejugé : `Ok(Some(valeur))` si le bilan, refait ici sur les
/// lectures de cet instant, propose encore la ligne ; `Ok(None)` s'il n'y a plus rien (rien à corriger) ; `Err` sinon.
fn rejuger(ligne: &str, valeur: Option<String>, constats: &[Constat]) -> Result<Option<String>, Resultat> {
    let Some(valeur) = valeur else {
        return Ok(None);
    };
    if propose(constats, ligne) {
        Ok(Some(valeur))
    } else {
        Err(Resultat::echec(
            None,
            tr!(
                "refusé : le bilan refait ici ne juge pas cette valeur dangereuse ; rien d'écrit",
                "refused: the check redone here does not find this value dangerous; nothing written"
            )
            .to_string(),
        ))
    }
}

/// Retire la valeur `nom_valeur` de `HKLM\<racine>\<programme>` si elle vaut encore `attendue` (relue juste avant),
/// puis relit son absence. Ouverte dans la vue 64 bits, celle que le bilan lit (`LECTURE_64`).
fn retirer_valeur_relue(racine: &str, programme: &NomFichier, nom_valeur: &str, attendue: &str) -> Resultat {
    use std::io::ErrorKind::NotFound;
    use winreg::enums::{KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};
    let avant = super::corrections::avant_notable(attendue);
    let chemin = format!(r"{racine}\{}", programme.texte());
    let cle = match RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(&chemin, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
    {
        Ok(k) => k,
        Err(e) => {
            let chemin = crate::ui::affichable(&chemin);
            return Resultat::echec(None, trf!("HKLM\\{chemin} : {e}", "HKLM\\{chemin}: {e}"));
        }
    };
    match cle.get_value::<String, _>(nom_valeur) {
        Ok(v) if v == attendue => {}
        Ok(_) => {
            return Resultat::echec(
                None,
                tr!(
                    "la valeur a changé entre la lecture et l'écriture ; rien d'écrit",
                    "the value changed between reading and writing; nothing written"
                )
                .to_string(),
            );
        }
        Err(e) => return Resultat::echec(None, e.to_string()),
    }
    match cle.delete_value(nom_valeur) {
        Ok(()) => {}
        Err(e) if e.kind() == NotFound => {}
        Err(e) => return Resultat::echec(Some(avant), e.to_string()),
    }
    match cle.get_raw_value(nom_valeur) {
        Err(e) if e.kind() == NotFound => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "la valeur est toujours là après son retrait",
                "the value is still there after its removal"
            )
            .to_string(),
        ),
    }
}

/// Dans le processus élevé : retire le débogueur de `programme` (Image File Execution Options de `vue`) si et
/// seulement si le bilan, refait ici par `juger_ifeo` sur les lectures de cet instant, propose cette même ligne. Plus
/// de débogueur : rien à corriger, rien d'écrit.
pub(super) fn retirer_debogueur(vue: Vue, programme: &NomFichier) -> Resultat {
    let Some((total, reglages)) = lire_ifeo() else {
        return Resultat::echec(
            None,
            tr!(
                "Image File Execution Options illisible, rien d'écrit",
                "Image File Execution Options unreadable, nothing written"
            )
            .to_string(),
        );
    };
    match debogueur_a_retirer(vue, programme, total, &reglages, &lire_moniteurs()) {
        Ok(Some(d)) => retirer_valeur_relue(vue.ifeo(), programme, "Debugger", &d),
        Ok(None) => Resultat::rien(rien_a_corriger()),
        Err(refus) => refus,
    }
}

/// Dans le processus élevé : ne lance plus rien à la fermeture de `programme` (SilentProcessExit de `vue`), si et
/// seulement si `juger_ifeo`, refait ici, propose cette même ligne (le drapeau du programme surveillé compris).
pub(super) fn retirer_moniteur(vue: Vue, programme: &NomFichier) -> Resultat {
    let Some((total, reglages)) = lire_ifeo() else {
        return Resultat::echec(
            None,
            tr!(
                "Image File Execution Options illisible, rien d'écrit",
                "Image File Execution Options unreadable, nothing written"
            )
            .to_string(),
        );
    };
    match moniteur_a_retirer(vue, programme, total, &reglages, &lire_moniteurs()) {
        Ok(Some(p)) => retirer_valeur_relue(vue.silencieuse(), programme, "MonitorProcess", &p),
        Ok(None) => Resultat::rien(rien_a_corriger()),
        Err(refus) => refus,
    }
}

/// Le débogueur de `programme` à retirer, jugé par `juger_ifeo` (la fonction du constat) sur ces lectures-là.
fn debogueur_a_retirer(
    vue: Vue,
    programme: &NomFichier,
    total: usize,
    reglages: &[Reglage],
    moniteurs: &[Moniteur],
) -> Result<Option<String>, Resultat> {
    let ligne = Acte::IfeoDebugger(vue, programme.clone()).ligne();
    let debogueur = reglages
        .iter()
        .find(|r| r.vue == vue && r.programme == programme.texte())
        .and_then(|r| r.debogueur.clone());
    rejuger(&ligne, debogueur, &juger_ifeo(total, reglages, moniteurs))
}

/// Le programme lancé à la fermeture de `programme` à retirer, jugé par `juger_ifeo` sur ces lectures-là.
fn moniteur_a_retirer(
    vue: Vue,
    programme: &NomFichier,
    total: usize,
    reglages: &[Reglage],
    moniteurs: &[Moniteur],
) -> Result<Option<String>, Resultat> {
    let ligne = Acte::IfeoSilencieux(vue, programme.clone()).ligne();
    let processus = moniteurs
        .iter()
        .find(|m| m.vue == vue && m.programme == programme.texte())
        .map(|m| m.processus.clone());
    rejuger(&ligne, processus, &juger_ifeo(total, reglages, moniteurs))
}

fn rien_a_corriger() -> String {
    tr!(
        "rien à corriger ici, rien d'écrit",
        "nothing to fix here, nothing written"
    )
    .to_string()
}

/// Le dossier de Windows (« C:\Windows »), lu par Windows (GetSystemWindowsDirectoryW), comme le processus élevé le
/// lit pour remettre Userinit : jamais la variable SystemRoot, qu'un programme du compte peut poser dans
/// HKCU\Environment. Illisible, celui d'un Windows ordinaire.
pub(super) fn racine_windows() -> String {
    super::environnement::dossier_windows().map_or_else(
        || r"C:\Windows".to_string(),
        |d| d.to_string_lossy().trim_end_matches('\\').to_string(),
    )
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

pub(super) const WINLOGON: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

/// Le bureau d'origine : « explorer.exe », parfois écrit avec son dossier.
pub(super) fn bureau_d_origine(valeur: &str, racine: &str) -> bool {
    let v = valeur.trim().trim_matches('"').to_lowercase();
    v == "explorer.exe" || v == format!(r"{}\explorer.exe", racine.to_lowercase())
}

/// Userinit d'origine : « C:\Windows\system32\userinit.exe, », virgule finale comprise ; une entrée de plus après la
/// virgule est un programme ajouté à chaque ouverture de session.
pub(super) fn userinit_d_origine(valeur: &str, racine: &str) -> bool {
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
/// d'ordinaire), retirée par un geste du compte (`winlogon-shell-compte`, fait par Vanguard non élevé dans le HKCU
/// de la personne, même quand la fenêtre administrateur s'ouvre sous un autre compte).
pub(super) fn juger_winlogon(
    shell: Option<&str>,
    userinit: Option<&str>,
    shell_du_compte: Option<&str>,
    racine: &str,
) -> Vec<Constat> {
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
                &[super::corrections::id("winlogon-shell")],
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
                // La racine n'est pas dans la ligne : le processus élevé la lit lui-même.
                &[super::corrections::id("winlogon-userinit")],
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
                &super::gestes::ligne_compte("winlogon-shell-compte").into_iter().collect::<Vec<_>>(),
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

/// Le constat de Winlogon pour l'ordinateur seul (Shell, Userinit), refait par le processus élevé avant de remettre
/// Shell (`corrections`, juge de `winlogon-shell`) : la même fonction que le bilan (`juger_winlogon`), sans la valeur
/// du compte. `None` si la clé ne se lit pas.
pub(super) fn winlogon_de_l_ordinateur() -> Option<Vec<Constat>> {
    let cle = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(WINLOGON).ok()?;
    let shell = cle.get_value::<String, _>("Shell").ok();
    let userinit = cle.get_value::<String, _>("Userinit").ok();
    Some(juger_winlogon(
        shell.as_deref(),
        userinit.as_deref(),
        None,
        &racine_windows(),
    ))
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
    juger_winlogon(
        shell.as_deref(),
        userinit.as_deref(),
        du_compte.as_deref(),
        &racine_windows(),
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
            vue: Vue::Windows,
            programme: c[0].to_string(),
            debogueur: rien(c[1]),
            drapeaux: rien(c[2]).and_then(|d| lire_drapeaux(&d)),
        })
        .collect();
    let moniteurs: Vec<Moniteur> = e
        .de("moniteur")
        .iter()
        .map(|c| Moniteur {
            vue: Vue::Windows,
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
            vue: Vue::Windows,
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
        // La correction désigne la clé par son nom en hexadécimal ; le chemin par script reprend la commande d'avant.
        let ligne = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert_eq!(ligne, "vanguard:ifeo-debugger 730065007400680063002e00650078006500");
        assert_eq!(
            super::super::corrections::en_powershell(&[vec![ligne.clone()]])[0][0],
            r"Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe' -Name Debugger"
        );
        assert!(c.iter().all(|c| c.correctif.as_ref().is_some_and(|k| k.automatique)));
        assert!(c[1].message.contains("Utilman.exe"));
    }

    #[test]
    fn programme_lance_a_la_fermeture() {
        let moniteur = |programme: &str, processus: &str| Moniteur {
            vue: Vue::Windows,
            programme: programme.to_string(),
            processus: processus.to_string(),
        };
        // Sans le drapeau 0x200 sur le programme, Windows ne lance rien.
        let c = juger_ifeo(10, &[], &[moniteur("notepad.exe", r"C:\Users\Public\a.exe")]);
        assert!(c[0].probleme.is_none());
        let drapeau = [reglage("notepad.exe", None, Some(SURVEILLER_LA_SORTIE))];
        let c = juger_ifeo(10, &drapeau, &[moniteur("notepad.exe", r"C:\Users\Public\a.exe")]);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        let ligne = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert_eq!(
            ligne,
            &gestes::ligne_ifeo_silencieux(Vue::Windows, "notepad.exe").unwrap()
        );
        assert!(
            super::super::corrections::en_powershell(&[vec![ligne.clone()]])[0][0]
                .ends_with(r"CurrentVersion\SilentProcessExit\notepad.exe' -Name MonitorProcess")
        );
        let c = juger_ifeo(10, &drapeau, &[moniteur("notepad.exe", r"C:\Outils\journal.exe")]);
        assert_eq!(c[0].probleme, Some(Niveau::Moyen));
        assert_eq!(lire_drapeaux("0x200"), Some(0x200));
        assert_eq!(lire_drapeaux(" 512 "), Some(512));
        assert_eq!(lire_drapeaux("rien"), None);
    }

    /// Le nom de la clé et la commande viennent de qui les a posés : montrés inoffensifs. Un nom que la grammaire des
    /// lignes refuse (ici des caractères de contrôle) n'a pas de ligne : à retirer à la main, jamais une ligne qui
    /// viserait une autre clé ; une apostrophe seule passe, en hexadécimal, et doublée dans la commande d'avant.
    #[test]
    fn noms_pieges_inoffensifs() {
        let piege = "x'\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}.exe";
        let r = [reglage(piege, Some("cmd.exe"), None)];
        let c = juger_ifeo(1, &r, &[]);
        let k = c[0].correctif.as_ref().unwrap();
        assert!(!crate::ui::contient_un_piege(&c[0].message));
        assert!(!crate::ui::contient_un_piege(&k.action));
        assert!(
            k.commandes.is_empty() && !k.automatique && k.action.contains("regedit"),
            "{}",
            k.action
        );
        for nom in [r"..\sethc.exe", r"a\b", "a\0b", &"a".repeat(261)] {
            let c = juger_ifeo(1, &[reglage(nom, Some("cmd.exe"), None)], &[]);
            assert!(c[0].correctif.as_ref().unwrap().commandes.is_empty(), "{nom:?}");
        }
        let c = juger_ifeo(1, &[reglage("x'y.exe", Some("cmd.exe"), None)], &[]);
        let ligne = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert!(
            super::super::corrections::en_powershell(&[vec![ligne.clone()]])[0][0]
                .contains(r"\x''y.exe' -Name Debugger")
        );
        let c = juger_winlogon(Some(piege), None, Some(piege), r"C:\Windows");
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
        );
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|c| c.probleme == Some(Niveau::Eleve)));
        let commandes: Vec<&str> = c
            .iter()
            .map(|c| c.correctif.as_ref().unwrap().commandes[0].as_str())
            .collect();
        // Des identifiants de la table, sans paramètre : la racine de Userinit est lue par le processus élevé.
        assert_eq!(commandes[0], "vanguard:winlogon-shell");
        assert_eq!(commandes[1], "vanguard:winlogon-userinit");
        // Celle du compte : un geste du compte, fait par Vanguard non élevé dans le HKCU de la personne.
        assert_eq!(commandes[2], "vanguard:compte winlogon-shell-compte");
    }

    /// Le processus élevé rejuge par LA fonction du bilan (`juger_ifeo`), sur les mêmes lectures : il retire ce que le
    /// bilan propose, refuse ce qu'il ne juge pas dangereux (une ligne forgée sur un débogueur ordinaire), et ne fait
    /// rien quand la valeur n'est plus là.
    #[test]
    fn le_processus_eleve_rejuge_comme_le_bilan() {
        let reglages = [
            reglage("sethc.exe", Some(r"C:\Windows\System32\cmd.exe"), None),
            reglage("taskmgr.exe", Some(r#""C:\Outils\PROCEXP64.EXE""#), None),
            reglage("notepad.exe", None, Some(SURVEILLER_LA_SORTIE)),
        ];
        let moniteurs = [
            Moniteur {
                vue: Vue::Windows,
                programme: "notepad.exe".to_string(),
                processus: r"C:\Users\Public\a.exe".to_string(),
            },
            Moniteur {
                vue: Vue::Windows,
                programme: "calc.exe".to_string(),
                processus: r"C:\Users\Public\b.exe".to_string(),
            },
        ];
        let bilan = juger_ifeo(3, &reglages, &moniteurs);
        let ligne = |r: &Reglage| gestes::ligne_ifeo_debugger(r.vue, &r.programme).unwrap();
        // Ce que le bilan propose, le processus élevé le retire.
        let sethc = ligne(&reglages[0]);
        assert!(propose(&bilan, &sethc));
        assert_eq!(
            rejuger(&sethc, reglages[0].debogueur.clone(), &bilan).ok(),
            Some(Some(r"C:\Windows\System32\cmd.exe".to_string()))
        );
        // Une ligne forgée sur un débogueur ordinaire : refusée, rien d'écrit.
        let taskmgr = ligne(&reglages[1]);
        assert!(!propose(&bilan, &taskmgr));
        let refus = rejuger(&taskmgr, reglages[1].debogueur.clone(), &bilan).unwrap_err();
        assert!(!refus.reussi && refus.avant.is_none(), "{}", refus.raison);
        // Plus de débogueur : rien à corriger.
        let notepad = gestes::ligne_ifeo_debugger(Vue::Windows, "notepad.exe").unwrap();
        assert_eq!(rejuger(&notepad, None, &bilan).ok(), Some(None));
        // SilentProcessExit : actif (drapeau posé) proposé ; sans drapeau (calc.exe), refusé.
        let actif = gestes::ligne_ifeo_silencieux(Vue::Windows, "notepad.exe").unwrap();
        assert!(propose(&bilan, &actif));
        let inactif = gestes::ligne_ifeo_silencieux(Vue::Windows, "calc.exe").unwrap();
        assert!(rejuger(&inactif, Some(r"C:\Users\Public\b.exe".to_string()), &bilan).is_err());
        // La vue compte : la même clé sous WOW6432Node est une autre ligne.
        let sethc_32 = gestes::ligne_ifeo_debugger(Vue::Wow32, "sethc.exe").unwrap();
        assert!(!propose(&bilan, &sethc_32));
        // Les juges de retirer_debogueur et retirer_moniteur, sur ces mêmes lectures : ce que le constat propose, et
        // seulement cela, est retiré ; le reste est refusé ou n'a plus rien à retirer.
        let nom = |n: &str| gestes::NomFichier::nouveau(n).unwrap();
        let deb = |vue, n: &str| debogueur_a_retirer(vue, &nom(n), 3, &reglages, &moniteurs);
        let mon = |vue, n: &str| moniteur_a_retirer(vue, &nom(n), 3, &reglages, &moniteurs);
        assert_eq!(
            deb(Vue::Windows, "sethc.exe").ok(),
            Some(Some(r"C:\Windows\System32\cmd.exe".to_string()))
        );
        assert!(deb(Vue::Windows, "taskmgr.exe").is_err_and(|r| !r.reussi));
        assert_eq!(deb(Vue::Windows, "notepad.exe").ok(), Some(None));
        assert_eq!(deb(Vue::Wow32, "sethc.exe").ok(), Some(None));
        assert_eq!(
            mon(Vue::Windows, "notepad.exe").ok(),
            Some(Some(r"C:\Users\Public\a.exe".to_string()))
        );
        assert!(mon(Vue::Windows, "calc.exe").is_err_and(|r| !r.reussi));
        assert_eq!(mon(Vue::Windows, "sethc.exe").ok(), Some(None));
        // Chaque ligne proposée par le constat, et elle seule, passe le juge du processus élevé.
        for r in &reglages {
            let l = ligne(r);
            assert_eq!(
                propose(&bilan, &l),
                matches!(deb(r.vue, &r.programme), Ok(Some(_))),
                "{l}"
            );
        }
        for m in &moniteurs {
            let l = gestes::ligne_ifeo_silencieux(m.vue, &m.programme).unwrap();
            assert_eq!(
                propose(&bilan, &l),
                matches!(mon(m.vue, &m.programme), Ok(Some(_))),
                "{l}"
            );
        }
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
