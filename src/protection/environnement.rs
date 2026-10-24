//! L'environnement dans lequel Vanguard démarre. Une bibliothèque injectée dans tous les programmes de la session
//! (LD_PRELOAD, LD_AUDIT, /etc/ld.so.preload sous Linux ; DYLD_INSERT_LIBRARIES sous macOS ; AppInit_DLLs sous
//! Windows) tourne aussi dans Vanguard et peut lui mentir : ce qu'il lit du système passe par elle. On le dit avant
//! tout bilan, sur la sortie d'erreur (une sortie JSON reste propre). LD_PRELOAD a des usages légitimes (GameMode,
//! l'overlay Steam, libgtk3-nocsd, fakeroot) : une bibliothèque d'un paquet du système, hors d'un dossier que
//! l'utilisateur peut écrire, est une information ; le reste, une alerte. Même jugement que la persistance pour
//! /etc/ld.so.preload.

use crate::risk::Niveau;
use crate::ui::*;

pub struct Avis {
    pub niveau: Niveau,
    pub texte: String,
}

/// Dossiers qu'un simple utilisateur, ou un programme lancé par lui, peut écrire : une bibliothèque qui en vient
/// n'offre aucune garantie. Un chemin relatif non plus.
#[cfg(any(target_os = "linux", test))]
fn dossier_modifiable(chemin: &str) -> bool {
    !chemin.starts_with('/')
        || [
            "/home/",
            "/root/",
            "/tmp/",
            "/var/tmp/",
            "/dev/shm/",
            "/run/user/",
            "/mnt/",
            "/media/",
            "/run/media/",
        ]
        .iter()
        .any(|d| chemin.starts_with(d))
}

/// Dossiers où le système range ses bibliothèques : un nom nu (« libgamemodeauto.so.0 », ou « $LIB/… » comme
/// l'écrit GameMode) s'y résout.
#[cfg(any(target_os = "linux", test))]
const DOSSIERS_LIB: [&str; 7] = [
    "/usr/lib",
    "/usr/lib64",
    "/usr/lib32",
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib",
    "/lib64",
];

/// Juge une bibliothèque préchargée ; `du_systeme(chemin)` : le fichier existe et vient d'un paquet du système.
#[cfg(any(target_os = "linux", test))]
fn juger_lib(lib: &str, du_systeme: &dyn Fn(&str) -> bool) -> Niveau {
    let lib = lib.trim();
    let nom = lib.rsplit('/').next().unwrap_or(lib);
    let nu = !lib.contains('/') || lib.starts_with("$LIB/") || lib.starts_with("${LIB}/");
    let chemin = if nu {
        match DOSSIERS_LIB
            .iter()
            .map(|d| format!("{d}/{nom}"))
            .find(|p| du_systeme(p))
        {
            Some(p) => p,
            None => return Niveau::Eleve,
        }
    } else {
        lib.to_string()
    };
    if !dossier_modifiable(&chemin) && du_systeme(&chemin) {
        Niveau::Info
    } else {
        Niveau::Eleve
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn avis_variable(source: &str, valeur: &str, niveau: Niveau) -> Avis {
    let valeur = affichable(valeur);
    let texte = if niveau == Niveau::Info {
        trf!(
            "{source} = {valeur} : une bibliothèque du système est chargée dans tous les programmes de cette session (GameMode, overlay Steam…). Rien d'anormal, mais Vanguard tourne avec elle.",
            "{source} = {valeur}: a system library is loaded into every program of this session (GameMode, Steam overlay…). Nothing abnormal, but Vanguard runs with it."
        )
    } else {
        trf!(
            "{source} = {valeur} : une bibliothèque qui ne vient pas d'un paquet du système est injectée dans tous les programmes de cette session, Vanguard compris. Mes résultats peuvent être faussés. Cherchez qui pose cela (.bashrc, .profile, /etc/environment, /etc/ld.so.preload), ou relancez depuis une session propre.",
            "{source} = {valeur}: a library that does not come from a system package is injected into every program of this session, Vanguard included. My results may be tampered with. Find what sets it (.bashrc, .profile, /etc/environment, /etc/ld.so.preload), or restart from a clean session."
        )
    };
    Avis { niveau, texte }
}

#[cfg(target_os = "linux")]
fn avis() -> Vec<Avis> {
    use std::path::Path;
    let gestion = crate::machine::linux::Paquets::detecter();
    let du_systeme = |p: &str| Path::new(p).is_file() && gestion.is_some_and(|g| g.possede(Path::new(p)));
    let mut liste = Vec::new();
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) else {
            continue;
        };
        let v = v.to_string_lossy().into_owned();
        let niveau = v
            .split([':', ' '])
            .filter(|l| !l.is_empty())
            .map(|l| juger_lib(l, &du_systeme))
            .max()
            .unwrap_or(Niveau::Info);
        liste.push(avis_variable(var, &v, niveau));
    }
    if let Ok(texte) = std::fs::read_to_string("/etc/ld.so.preload") {
        let libs: Vec<&str> = texte
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .flat_map(str::split_whitespace)
            .collect();
        if let Some(niveau) = libs.iter().map(|l| juger_lib(l, &du_systeme)).max() {
            liste.push(avis_variable("/etc/ld.so.preload", &libs.join(" "), niveau));
        }
    }
    liste
}

/// macOS : DYLD_INSERT_LIBRARIES n'a presque jamais de raison d'être posée pour toute une session.
#[cfg(target_os = "macos")]
fn avis() -> Vec<Avis> {
    std::env::var_os("DYLD_INSERT_LIBRARIES")
        .filter(|v| !v.is_empty())
        .map(|v| avis_variable("DYLD_INSERT_LIBRARIES", &v.to_string_lossy(), Niveau::Eleve))
        .into_iter()
        .collect()
}

/// Windows : AppInit_DLLs, chargées par le système dans chaque programme qui affiche une fenêtre (Vanguard, lancé dans
/// une console, en est). Vide sur un Windows normal ; les antivirus sérieux n'en ont plus besoin.
#[cfg(windows)]
fn avis() -> Vec<Avis> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let mut liste = Vec::new();
    for cle in [
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
    ] {
        let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(cle) else {
            continue;
        };
        let charge: u32 = k.get_value("LoadAppInit_DLLs").unwrap_or(0);
        let dlls: String = k.get_value("AppInit_DLLs").unwrap_or_default();
        if charge == 1 && !dlls.trim().is_empty() {
            liste.push(Avis {
                niveau: Niveau::Eleve,
                texte: trf!(
                    "AppInit_DLLs = {} : Windows charge ces DLL dans chaque programme, Vanguard compris. Mes résultats peuvent être faussés. Un Windows sain n'en a aucune : regardez quel programme les a posées (clé {cle}).",
                    "AppInit_DLLs = {}: Windows loads these DLLs into every program, Vanguard included. My results may be tampered with. A healthy Windows has none: look at which program set them (key {cle}).",
                    affichable(dlls.trim())
                ),
            });
        }
    }
    liste
}

/// Au démarrage : chaque avis sur la sortie d'erreur, une information en gris, une alerte en couleur.
pub fn afficher() {
    for a in avis() {
        let (marque, couleur) = if a.niveau == Niveau::Info {
            ("ℹ", GRIS)
        } else {
            ("⚠", couleur(a.niveau))
        };
        for (i, ligne) in envelopper(&a.texte, LARGEUR - 4).into_iter().enumerate() {
            if i == 0 {
                eprintln!("  {couleur}{marque}{RESET} {ligne}");
            } else {
                eprintln!("    {ligne}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bibliotheque_du_systeme_ou_pas() {
        let systeme = |p: &str| {
            p == "/usr/lib/libgamemodeauto.so.0"
                || p == "/usr/lib/libgtk3-nocsd.so.0"
                || p == "/home/alice/.steam/ubuntu12_32/gameoverlayrenderer.so"
        };
        // GameMode, écrit comme son lanceur le fait, et un chemin complet d'un paquet : information.
        assert_eq!(juger_lib("$LIB/libgamemodeauto.so.0", &systeme), Niveau::Info);
        assert_eq!(juger_lib("libgamemodeauto.so.0", &systeme), Niveau::Info);
        assert_eq!(juger_lib("/usr/lib/libgtk3-nocsd.so.0", &systeme), Niveau::Info);
        // Un fichier du dossier personnel, même connu : l'utilisateur (ou un programme à lui) peut le remplacer.
        assert_eq!(
            juger_lib("/home/alice/.steam/ubuntu12_32/gameoverlayrenderer.so", &systeme),
            Niveau::Eleve
        );
        // Hors paquet, dans /tmp, ou un nom nu que le système n'a pas : alerte.
        assert_eq!(juger_lib("/usr/lib/libinconnue.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("/tmp/libz.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("libz.so", &systeme), Niveau::Eleve);
        assert_eq!(juger_lib("./lib.so", &systeme), Niveau::Eleve);
        assert!(dossier_modifiable("/run/user/1000/x.so") && !dossier_modifiable("/usr/lib/x.so"));
        let a = avis_variable("LD_PRELOAD", "/tmp/libz.so", Niveau::Eleve);
        assert!(a.texte.contains("faussés"), "{}", a.texte);
    }
}
