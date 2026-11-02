//! Gaming sous Windows : composants dont les jeux ont besoin (Visual C++, .NET, DirectX, XNA, PhysX, pilote
//! graphique) et réglages de Windows utiles en jeu.
//! Tout est lu d'abord (registre, SetupAPI, fichiers ; PowerShell en secours), montré avec son état, puis appliqué
//! seulement après accord.
//! Les réglages qui retirent une protection (intégrité de la mémoire, Defender, pare-feu…) ne sont jamais proposés.

use std::fmt::Write;

use serde::Deserialize;

use super::{Element, element, proposer};
use crate::machine;
use crate::optimiser::Geste;
use crate::trw;
use crate::ui::*;

/// Ce que Vanguard lit avant d'afficher le menu : une photo de l'état (la forme du JSON du script de secours).
#[allow(clippy::struct_excessive_bools)]
#[derive(Default, Deserialize)]
#[serde(default)]
struct Etat {
    winget: bool,
    /// Noms des programmes installés (panneau « Applications installées »).
    programmes: Vec<String>,
    vc14_x64: bool,
    vc14_x86: bool,
    directx9: bool,
    netfx3: bool,
    gpu: Vec<Carte>,
    portable: bool,
    windows11: bool,
    mode_jeu: Option<u32>,
    hags: Option<u32>,
    dvr: Option<u32>,
    capture: Option<u32>,
    /// Valeurs de « Améliorer la précision du pointeur » ; `None` : absente.
    souris: Option<String>,
    seuil1: Option<String>,
    seuil2: Option<String>,
    fenetres: Option<String>,
    alimentation: String,
}

#[derive(Default, Deserialize)]
#[serde(default)]
struct Carte {
    nom: String,
    version: String,
    date: String,
}

/// L'état lu dans le registre, SetupAPI et le système de fichiers, sans PowerShell ; PowerShell seulement si la clé
/// des programmes de la machine ne s'ouvre pas.
fn lire_etat() -> Option<Etat> {
    use machine::windows::{installes, peripheriques};
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let Some(programmes) = installes::noms() else {
        return lire_par_powershell();
    };
    let (machine, compte) = (RegKey::predef(HKEY_LOCAL_MACHINE), RegKey::predef(HKEY_CURRENT_USER));
    let dword = |racine: &RegKey, cle: &str, nom: &str| racine.open_subkey(cle).ok()?.get_value::<u32, _>(nom).ok();
    let texte = |racine: &RegKey, cle: &str, nom: &str| racine.open_subkey(cle).ok()?.get_value::<String, _>(nom).ok();
    let vc = r"SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes";
    let systeme = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()));
    let gpu = peripheriques::presents(&peripheriques::AFFICHAGE)
        .unwrap_or_default()
        .iter()
        .filter(|p| !carte_ignoree(&p.nom))
        .map(|p| {
            let cle = peripheriques::cle_du_pilote(p);
            let valeur = |nom: &str| cle.as_ref().and_then(|c| c.get_value::<String, _>(nom).ok());
            Carte {
                nom: valeur("DriverDesc").unwrap_or_else(|| p.nom.clone()),
                version: valeur("DriverVersion").unwrap_or_default(),
                date: valeur("DriverDate")
                    .and_then(|d| peripheriques::date_du_pilote(&d))
                    .unwrap_or_default(),
            }
        })
        .collect();
    let build: u32 = texte(
        &machine,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    )
    .and_then(|b| b.trim().parse().ok())
    .unwrap_or(0);
    Some(Etat {
        // Un indice pour le choix 1 (installer ou ouvrir le Store), pas le winget lancé : la fenêtre administrateur
        // cherche le sien dans App Installer (`winget_eleve`) et, s'il manque ou est ailleurs, dit quoi faire.
        winget: installes::winget_present(),
        programmes,
        vc14_x64: dword(&machine, &format!(r"{vc}\x64"), "Installed") == Some(1),
        vc14_x86: dword(&machine, &format!(r"{vc}\x86"), "Installed") == Some(1),
        directx9: systeme.join(r"System32\d3dx9_43.dll").is_file() && systeme.join(r"SysWOW64\d3dx9_43.dll").is_file(),
        netfx3: dword(&machine, r"SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5", "Install") == Some(1),
        gpu,
        portable: batterie(),
        windows11: build >= 22000,
        mode_jeu: dword(&compte, r"Software\Microsoft\GameBar", "AutoGameModeEnabled"),
        hags: dword(
            &machine,
            r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "HwSchMode",
        ),
        dvr: dword(&compte, r"System\GameConfigStore", "GameDVR_Enabled"),
        capture: dword(
            &compte,
            r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "AppCaptureEnabled",
        ),
        souris: texte(&compte, r"Control Panel\Mouse", "MouseSpeed"),
        seuil1: texte(&compte, r"Control Panel\Mouse", "MouseThreshold1"),
        seuil2: texte(&compte, r"Control Panel\Mouse", "MouseThreshold2"),
        fenetres: texte(
            &compte,
            r"Software\Microsoft\DirectX\UserGpuPreferences",
            "DirectXUserGlobalSettings",
        ),
        alimentation: crate::commande::lancer(crate::commande::systeme("powercfg").arg("/getactivescheme"), 15)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie.trim().to_string())
            .unwrap_or_default(),
    })
}

/// Les cartes que Win32_VideoController filtré ignorait : affichage de base, bureau à distance, écrans virtuels.
fn carte_ignoree(nom: &str) -> bool {
    let nom = nom.to_lowercase();
    ["basic", "remote", "virtual", "parsec", "meta"]
        .iter()
        .any(|m| nom.contains(m))
}

/// Une batterie dans la machine (Win32_Battery) : GetSystemPowerStatus dit « aucune batterie » (128) ou « inconnu »
/// (255) sinon.
// FFI de kernel32 : GetSystemPowerStatus.
#[allow(unsafe_code)]
fn batterie() -> bool {
    #[repr(C)]
    #[derive(Default)]
    struct Alimentation {
        secteur: u8,
        drapeaux: u8,
        pourcentage: u8,
        economie: u8,
        restant: u32,
        complet: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemPowerStatus(etat: *mut Alimentation) -> i32;
    }
    let mut etat = Alimentation::default();
    // SAFETY: la structure a la forme de SYSTEM_POWER_STATUS (4 octets puis deux u32) et vit pendant l'appel.
    (unsafe { GetSystemPowerStatus(&raw mut etat) }) != 0 && !matches!(etat.drapeaux, 128 | 255)
}

/// `winget` : même indice que `installes::winget_present` (le PATH), pas le winget lancé en administrateur.
fn lire_par_powershell() -> Option<Etat> {
    let json = machine::windows::ps(
        r#"$noms = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.DisplayName } | Where-Object { $_ })
          function Lire($cle, $nom) { $v = Get-ItemProperty $cle -Name $nom -ErrorAction SilentlyContinue; if ($v) { $v.$nom } else { $null } }
          $vc = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes'
          [pscustomobject]@{
            winget = [bool](Get-Command winget -ErrorAction SilentlyContinue)
            programmes = $noms
            vc14_x64 = (Lire "$vc\x64" Installed) -eq 1
            vc14_x86 = (Lire "$vc\x86" Installed) -eq 1
            directx9 = (Test-Path "$env:SystemRoot\System32\d3dx9_43.dll") -and (Test-Path "$env:SystemRoot\SysWOW64\d3dx9_43.dll")
            netfx3 = (Lire 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v3.5' Install) -eq 1
            gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch 'Basic|Remote|Virtual|Parsec|Meta' } | ForEach-Object { [pscustomobject]@{ nom = [string]$_.Name; version = [string]$_.DriverVersion; date = if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' } } })
            portable = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
            windows11 = [Environment]::OSVersion.Version.Build -ge 22000
            mode_jeu = Lire 'HKCU:\Software\Microsoft\GameBar' AutoGameModeEnabled
            hags = Lire 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' HwSchMode
            fenetres = Lire 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' DirectXUserGlobalSettings
            dvr = Lire 'HKCU:\System\GameConfigStore' GameDVR_Enabled
            capture = Lire 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' AppCaptureEnabled
            souris = Lire 'HKCU:\Control Panel\Mouse' MouseSpeed
            seuil1 = Lire 'HKCU:\Control Panel\Mouse' MouseThreshold1
            seuil2 = Lire 'HKCU:\Control Panel\Mouse' MouseThreshold2
            alimentation = [string](powercfg /getactivescheme)
          } | ConvertTo-Json -Compress -Depth 4"#,
    )?;
    serde_json::from_str(&json).ok()
}

fn winget(id: &str) -> String {
    machine::windows::winget_installer(id)
}

/// Où vit une valeur notée : dans le compte de la personne (sa ruche, même depuis la fenêtre d'un autre
/// administrateur), ou dans la machine.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Ruche {
    Compte,
    Machine,
}

/// Les valeurs du registre que chaque réglage change : (réglage, ruche, clé, nom, DWORD plutôt que texte).
pub(crate) const VALEURS: &[(&str, Ruche, &str, &str, bool)] = &[
    (
        "mode_jeu",
        Ruche::Compte,
        r"Software\Microsoft\GameBar",
        "AutoGameModeEnabled",
        true,
    ),
    (
        "hags",
        Ruche::Machine,
        r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
        "HwSchMode",
        true,
    ),
    (
        "capture",
        Ruche::Compte,
        r"System\GameConfigStore",
        "GameDVR_Enabled",
        true,
    ),
    (
        "capture",
        Ruche::Compte,
        r"Software\Microsoft\Windows\CurrentVersion\GameDVR",
        "AppCaptureEnabled",
        true,
    ),
    ("souris", Ruche::Compte, r"Control Panel\Mouse", "MouseSpeed", false),
    (
        "souris",
        Ruche::Compte,
        r"Control Panel\Mouse",
        "MouseThreshold1",
        false,
    ),
    (
        "souris",
        Ruche::Compte,
        r"Control Panel\Mouse",
        "MouseThreshold2",
        false,
    ),
    (
        "fenetres",
        Ruche::Compte,
        r"Software\Microsoft\DirectX\UserGpuPreferences",
        "DirectXUserGlobalSettings",
        false,
    ),
];

/// Le mode d'alimentation actif, dans la sortie de « powercfg /getactivescheme » (son GUID, dans toutes les langues).
pub(crate) fn guid_alimentation(sortie: &str) -> Option<String> {
    sortie
        .split(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
        .find_map(|m| {
            let parties: Vec<usize> = m.split('-').map(str::len).collect();
            (parties == [8, 4, 4, 4, 12]).then(|| m.to_ascii_lowercase())
        })
}

/// Ce que change un réglage, en gestes d'Optimiser : ses valeurs du registre (`VALEURS`), ou le mode
/// d'alimentation. Leurs valeurs d'avant sont relevées et notées avant de l'appliquer.
fn gestes(id: &str) -> Vec<Geste> {
    if id == "alimentation" {
        return vec![Geste::alimentation()];
    }
    VALEURS
        .iter()
        .filter(|v| v.0 == id)
        .map(|&(_, ruche, cle, nom, _)| Geste::registre(ruche == Ruche::Machine, cle, nom))
        .collect()
}

/// Une valeur notée par jeux.json (« clé\nom », ou « powercfg »), dans la forme d'Optimiser : son geste et sa
/// valeur (« dword:1 », « sz:texte », un GUID). `None` : un nom ou une valeur que Vanguard n'a jamais notés.
pub(super) fn convertir(id: &str, nom_note: &str, v: Option<&str>) -> Option<(Geste, Option<String>)> {
    if nom_note == "powercfg" {
        let guid = match v {
            Some(t) => Some(guid_alimentation(t)?),
            None => None,
        };
        return Some((Geste::alimentation(), guid));
    }
    let &(_, ruche, cle, nom, dw) = VALEURS
        .iter()
        .find(|x| x.0 == id && format!(r"{}\{}", x.2, x.3) == nom_note)?;
    let valeur = match v {
        None => None,
        Some(n) if dw => Some(format!("dword:{}", n.trim().parse::<u32>().ok()?)),
        Some(t) => Some(format!("sz:{t}")),
    };
    Some((Geste::registre(ruche == Ruche::Machine, cle, nom), valeur))
}

fn a_programme(e: &Etat, motif: &str) -> bool {
    e.programmes.iter().any(|p| p.contains(motif))
}

fn composants(e: &Etat) -> Vec<Element> {
    let mut l = vec![
        element(
            tr!(
                "Visual C++ 2015-2022 (64 et 32 bits)",
                "Visual C++ 2015-2022 (64 and 32 bit)"
            ),
            tr!(
                "Bibliothèques demandées par presque tous les jeux récents (erreur « VCRUNTIME140.dll introuvable »).",
                "Libraries needed by almost every recent game (“VCRUNTIME140.dll not found” error)."
            ),
            Some(e.vc14_x64 && e.vc14_x86),
            vec![
                winget("Microsoft.VCRedist.2015+.x64"),
                winget("Microsoft.VCRedist.2015+.x86"),
            ],
        ),
        {
            let annees = ["2005", "2008", "2010", "2012", "2013"];
            let presentes = annees
                .iter()
                .filter(|a| a_programme(e, &format!("Visual C++ {a}")))
                .count();
            element(
                trf!(
                    "Visual C++ 2005 à 2013 ({presentes}/5 présents)",
                    "Visual C++ 2005 to 2013 ({presentes}/5 present)"
                ),
                tr!(
                    "Anciennes versions, pour les jeux d'avant 2015 (erreurs MSVCR100.dll, MSVCP120.dll…).",
                    "Old versions, for games from before 2015 (MSVCR100.dll, MSVCP120.dll… errors)."
                ),
                Some(presentes == annees.len()),
                annees
                    .iter()
                    .flat_map(|a| ["x64", "x86"].map(|arch| winget(&format!("Microsoft.VCRedist.{a}.{arch}"))))
                    .collect(),
            )
        },
        element(
            tr!(
                "DirectX 9 à 11 (bibliothèques de 2010)",
                "DirectX 9 to 11 (2010 libraries)"
            ),
            tr!(
                "d3dx9, d3dx10, d3dx11, XAudio2 et XInput anciens : Windows ne les fournit pas, beaucoup de jeux d'avant 2016 en ont besoin.",
                "Old d3dx9, d3dx10, d3dx11, XAudio2 and XInput: Windows does not include them, and many games from before 2016 need them."
            ),
            Some(e.directx9),
            vec![winget("Microsoft.DirectX")],
        ),
        element(
            tr!(".NET Desktop Runtime 8 et 10", ".NET Desktop Runtime 8 and 10"),
            tr!(
                "Lanceurs, mods et outils de jeu écrits en .NET (les versions encore suivies par Microsoft).",
                "Launchers, mods and game tools written in .NET (the versions still supported by Microsoft)."
            ),
            Some(a_programme(e, "Windows Desktop Runtime - 8.") && a_programme(e, "Windows Desktop Runtime - 10.")),
            vec![
                winget("Microsoft.DotNet.DesktopRuntime.8"),
                winget("Microsoft.DotNet.DesktopRuntime.10"),
            ],
        ),
        element(
            ".NET Framework 3.5",
            tr!(
                "Demandé par des jeux et lanceurs anciens ; c'est une fonctionnalité de Windows (téléchargée par Windows Update).",
                "Needed by older games and launchers; it is a Windows feature (downloaded by Windows Update)."
            ),
            Some(e.netfx3),
            // Par Vanguard administrateur : dism.exe de System32, arguments figés (`gestes::PROGRAMMES`).
            vec![crate::machine::gestes::ligne_programme("dism-ajouter-netfx3", None)],
        ),
        element(
            "XNA Framework 4.0",
            tr!(
                "Jeux indépendants des années 2010 (Terraria ancien, Stardew Valley ancien, Fez…).",
                "Indie games from the 2010s (old Terraria, old Stardew Valley, Fez…)."
            ),
            Some(a_programme(e, "XNA Framework Redistributable 4.0")),
            vec![winget("Microsoft.XNARedist")],
        ),
        element(
            tr!("PhysX ancien (Legacy)", "Old PhysX (Legacy)"),
            tr!(
                "Physique des jeux NVIDIA PhysX d'avant 2010 (Mirror's Edge, Mafia II…) ; utile même sans carte NVIDIA.",
                "Physics of NVIDIA PhysX games from before 2010 (Mirror's Edge, Mafia II…); useful even without an NVIDIA card."
            ),
            Some(e.programmes.iter().any(|p| p.contains("PhysX") && p.contains("Legacy"))),
            vec![winget("Nvidia.PhysXLegacy")],
        ),
    ];

    // Pilote graphique : celui du fabricant, plus récent que celui de Windows Update.
    for carte in &e.gpu {
        let nom = carte.nom.to_lowercase();
        // Nom, version et date viennent du pilote (registre, SetupAPI ou Win32_VideoController) :
        // montrés rendus inoffensifs, comme dans maj.rs ; le nom brut sert seulement à reconnaître
        // le fabricant.
        let affichable = crate::ui::affichable;
        let (vu, version, date) = (
            affichable(&carte.nom),
            affichable(&carte.version),
            affichable(&carte.date),
        );
        let pilote = trf!("pilote {} du {}", "driver {} from {}", version, date);
        let mut el = element(
            trf!("Pilote graphique : {}", "Graphics driver: {}", vu),
            trf!(
                "Installé : {pilote}. Le pilote du fabricant est plus récent et mieux optimisé que celui de Windows Update.",
                "Installed: {pilote}. The manufacturer's driver is newer and better optimized than the Windows Update one."
            ),
            None,
            vec![],
        );
        let Some((outil, lien)) = machine::windows::pilote_fabricant(&carte.nom) else {
            continue;
        };
        // Intel : son assistant s'installe par winget ; NVIDIA et AMD, seulement depuis leur page officielle.
        if nom.contains("intel") {
            let _ = trw!(
                el.pourquoi,
                " {outil} trouve le bon pilote.",
                " {outil} finds the right driver."
            );
            el.commandes = vec![winget("Intel.IntelDriverAndSupportAssistant")];
        } else {
            let _ = trw!(
                el.pourquoi,
                " {outil} installe et tient à jour le pilote (page officielle).",
                " {outil} installs the driver and keeps it up to date (official page)."
            );
            el.lien = Some(lien);
        }
        l.push(el);
    }
    l
}

/// Les lignes des gestes du compte (`gestes::VALEURS_COMPTE`) : faits par Vanguard non élevé, sous le compte de la
/// personne, jamais derrière l'UAC (`machine::windows::compte`). Un identifiant hors table ne donne aucune ligne (le
/// test `chaque_valeur_a_son_geste` le verrait).
fn compte(ids: &[&str]) -> Vec<String> {
    ids.iter().filter_map(|id| machine::gestes::ligne_compte(id)).collect()
}

/// Réglages de Windows pour jouer. Ceux du compte sont des gestes du compte, faits par Vanguard non élevé dans le
/// HKCU de la personne (la fenêtre administrateur peut s'ouvrir sous un autre compte) ; HAGS, sous HKLM, est une
/// correction de la table (`gaming-hags`), faite par le processus élevé.
fn reglages(e: &Etat) -> Vec<Element> {
    let perf = machine::windows::compte::PERFORMANCES;
    let mut l = vec![
        element(
            tr!("Mode Jeu activé", "Game Mode on"),
            tr!(
                "Windows donne la priorité au jeu et repousse les mises à jour et notifications pendant la partie.",
                "Windows gives priority to the game and holds back updates and notifications while you play."
            ),
            Some(e.mode_jeu != Some(0)),
            compte(&["jeux-mode"]),
        )
        .annulable("mode_jeu", gestes("mode_jeu")),
        element(
            tr!(
                "Planification GPU matérielle (HAGS)",
                "Hardware-accelerated GPU scheduling"
            ),
            tr!(
                "La carte graphique gère sa propre mémoire : un peu moins de latence, et obligatoire pour la génération d'images DLSS 3/4. Cartes GTX 1000 / RX 5000 et plus récentes. Prend effet au redémarrage.",
                "The graphics card manages its own memory: slightly lower latency, and required for DLSS 3/4 frame generation. GTX 1000 / RX 5000 cards and newer. Takes effect after a restart."
            ),
            Some(e.hags == Some(2)),
            vec![machine::windows::corrections::id("gaming-hags")],
        )
        .annulable("hags", gestes("hags")),
        element(
            tr!("Capture Xbox en arrière-plan coupée", "Xbox background recording off"),
            tr!(
                "La capture de jeu de la Xbox Game Bar consomme un peu de carte graphique et de disque. La Game Bar (Win+G) reste disponible.",
                "Xbox Game Bar game capture uses a bit of graphics card and disk. The Game Bar (Win+G) stays available."
            ),
            Some(e.dvr == Some(0) && e.capture != Some(1)),
            compte(&["jeux-dvr", "jeux-capture"]),
        )
        .annulable("capture", gestes("capture")),
        element(
            tr!("Accélération de la souris coupée", "Mouse acceleration off"),
            tr!(
                "« Améliorer la précision du pointeur » change la distance parcourue selon la vitesse du geste : la visée devient imprévisible. Prend effet à la prochaine ouverture de session.",
                "“Enhance pointer precision” changes the distance traveled depending on how fast you move: aiming becomes unpredictable. Takes effect at the next sign-in."
            ),
            e.souris.as_ref().map(|s| s == "0"),
            compte(&["souris-vitesse", "souris-seuil1", "souris-seuil2"]),
        )
        .annulable("souris", gestes("souris")),
    ];
    if e.windows11 {
        // La valeur regroupe plusieurs réglages (« VRROptimizeEnable=0;SwapEffectUpgradeEnable=1; ») : seul le
        // nôtre change (`gestes::avec_swap_effect`).
        l.push(element(
            tr!("Optimisations pour les jeux en fenêtre", "Optimizations for windowed games"),
            tr!("Les jeux DirectX 10/11 en fenêtre ou fenêtre sans bordure passent au mode d'affichage moderne : moins de latence, VRR et HDR automatique possibles.", "DirectX 10/11 games in windowed or borderless mode switch to the modern presentation model: lower latency, VRR and Auto HDR possible."),
            Some(e.fenetres.as_deref().is_some_and(|f| f.contains("SwapEffectUpgradeEnable=1"))),
            compte(&["jeux-fenetres"]),
        )
        .annulable("fenetres", gestes("fenetres")));
    }
    let mut alimentation = element(
        tr!("Alimentation « Performances élevées »", "“High performance” power plan"),
        tr!(
            "Le processeur reste à pleine fréquence : moins de saccades quand le jeu varie beaucoup. Consomme plus au repos.",
            "The processor stays at full speed: fewer stutters when the game load changes a lot. Uses more power at idle."
        ),
        (!e.alimentation.is_empty()).then(|| e.alimentation.contains(perf)),
        // powercfg par son chemin dans System32, sans droits : un geste du compte.
        vec![machine::gestes::ligne_alimentation()],
    )
    .annulable("alimentation", gestes("alimentation"));
    if e.portable {
        alimentation.deconseille = Some(tr!(
            "PC portable : la batterie fondrait et il chaufferait",
            "Laptop: the battery would drain and it would heat up"
        ));
    }
    l.push(alimentation);
    l
}

pub(super) fn menu() {
    trp!("  Lecture de l'état de Windows…", "  Reading the state of Windows…");
    let Some(etat) = lire_etat() else {
        trp!(
            "  ✖ Impossible de lire l'état de Windows (PowerShell ne répond pas).",
            "  ✖ Could not read the state of Windows (PowerShell is not responding)."
        );
        return;
    };
    let note = (!etat.winget).then(|| {
        trf!(
            "  {GRIS}winget manque : le choix 1 ouvre sa page dans le Microsoft Store.{RESET}",
            "  {GRIS}winget is missing: choice 1 opens its page in the Microsoft Store.{RESET}"
        )
    });
    match super::choisir_liste(
        (
            tr!("Composants pour les jeux", "Components for games"),
            tr!("Visual C++, DirectX, .NET…", "Visual C++, DirectX, .NET…"),
        ),
        (
            tr!("Réglages de Windows pour jouer", "Windows settings for gaming"),
            tr!("Mode Jeu, carte graphique, souris…", "Game Mode, graphics card, mouse…"),
        ),
        note,
    )
    .as_deref()
    {
        Some("1") if !etat.winget => machine::ouvrir("ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"),
        Some("1") => proposer(
            tr!("Composants pour les jeux", "Components for games"),
            &composants(&etat),
            false,
        ),
        Some("2") => proposer(
            tr!("Réglages de Windows pour jouer", "Windows settings for gaming"),
            &reglages(&etat),
            true,
        ),
        Some("3") => super::remettre(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn etat_vide() -> Etat {
        Etat {
            programmes: vec![
                "Microsoft Visual C++ 2010  x64 Redistributable - 10.0.40219".into(),
                "Microsoft Visual C++ 2013 Redistributable (x86) - 12.0.40664".into(),
                "Microsoft Windows Desktop Runtime - 8.0.11 (x64)".into(),
            ],
            souris: Some("1".into()),
            portable: true,
            windows11: true,
            ..Etat::default()
        }
    }

    /// Le vrai registre et SetupAPI (Wine ici, la VM ensuite), sans PowerShell : l'état se lit.
    #[test]
    fn etat_lu_sans_powershell() {
        assert!(lire_etat().is_some_and(|e| !e.programmes.iter().any(String::is_empty)));
        assert!(carte_ignoree("Microsoft Basic Display Adapter") && carte_ignoree("Parsec Virtual Display"));
        assert!(!carte_ignoree("NVIDIA GeForce RTX 4070"));
    }

    #[test]
    fn composants_et_etat() {
        let e = etat_vide();
        let l = composants(&e);
        assert!(l[1].titre.contains("2/5"));
        // .NET 8 présent mais pas 10 : à faire.
        assert_eq!(l[3].fait, Some(false));
        assert_eq!(l[1].commandes.len(), 10);
        assert!(l[0].commandes[0].contains("--id Microsoft.VCRedist.2015+.x64 --exact"));
        assert!(l.iter().all(|el| !el.commandes.is_empty()));
    }

    /// Une carte au nom, à la version ou à la date piégés arrive inoffensive dans la liste.
    #[test]
    fn carte_au_nom_piege() {
        let mut e = etat_vide();
        e.gpu = vec![Carte {
            nom: "NVIDIA GeForce\x1b]52;c;eA==\x07\u{202e}".into(),
            version: "32.0\x1b[2K".into(),
            date: "2026-01-01\x1b[8m".into(),
        }];
        let l = composants(&e);
        let el = l.iter().find(|el| el.titre.contains("NVIDIA GeForce")).unwrap();
        assert!(!crate::ui::contient_un_piege(&el.titre), "{}", el.titre);
        assert!(!crate::ui::contient_un_piege(&el.pourquoi), "{}", el.pourquoi);
        // Le fabricant reste reconnu : le lien de son pilote est donné.
        assert!(el.lien.is_some());
    }

    /// Ce qui est au compte de la personne est un geste du compte (fait par Vanguard non élevé, dans son HKCU, même
    /// quand la fenêtre administrateur s'ouvre sous un autre compte) ; ce qui est à la machine, une correction de la
    /// table faite par le processus élevé. Aucune commande PowerShell ne reste.
    #[test]
    fn reglages_du_compte_dans_sa_ruche() {
        use crate::machine::gestes::{analyser_compte, ligne_alimentation, ligne_compte};
        let e = etat_vide();
        let l = reglages(&e);
        // Mode Jeu absent du registre = activé par défaut.
        assert_eq!(l[0].fait, Some(true));
        assert_eq!(l[3].fait, Some(false));
        assert!(l.last().unwrap().deconseille.is_some());
        assert_eq!(l[0].commandes, [ligne_compte("jeux-mode").unwrap()]);
        assert_eq!(
            l[1].commandes,
            [crate::machine::windows::corrections::id("gaming-hags")]
        );
        assert_eq!(l[2].commandes.len(), 2);
        assert_eq!(l[3].commandes.len(), 3);
        assert_eq!(l.last().unwrap().commandes, [ligne_alimentation()]);
        for el in &l {
            for c in &el.commandes {
                assert!(
                    analyser_compte(c).is_some() || crate::machine::windows::corrections::native(c),
                    "{c}"
                );
                assert!(
                    !c.contains("HKCU:") && !c.contains("HKEY_USERS") && !c.contains("powercfg"),
                    "{c}"
                );
            }
        }
        super::super::tests::tient_dans_la_liste(&l);
        super::super::tests::tient_dans_la_liste(&composants(&e));
    }

    /// Chaque valeur notée d'un réglage est bien celle qu'écrit son geste : au compte, une valeur de
    /// `gestes::VALEURS_COMPTE` (même clé, même nom, même type) ; à la machine, la correction `gaming-hags` de la
    /// table. Ainsi Défaire remet exactement ce que l'application a changé, à la bonne ruche.
    #[test]
    fn chaque_valeur_a_son_geste() {
        use crate::machine::gestes::{Donnee, VALEURS_COMPTE};
        for &(reglage, ruche, cle, nom, dw) in VALEURS {
            match ruche {
                Ruche::Compte => {
                    let v = VALEURS_COMPTE
                        .iter()
                        .find(|v| v.cle == cle && v.nom == nom)
                        .unwrap_or_else(|| panic!("{reglage} {cle} {nom}"));
                    assert_eq!(matches!(v.donnee, Donnee::Dword(_)), dw, "{reglage} {nom}");
                    assert!(!v.durcit && v.id.starts_with(if reglage == "souris" { "souris-" } else { "jeux-" }));
                    assert!(reglages(&etat_vide()).iter().any(|el| {
                        el.commandes
                            .iter()
                            .any(|c| *c == format!("{}{}", crate::machine::gestes::COMPTE, v.id))
                    }));
                }
                Ruche::Machine => {
                    let c = crate::machine::windows::corrections::analyser(&crate::machine::windows::corrections::id(
                        "gaming-hags",
                    ))
                    .unwrap();
                    assert!(
                        matches!(c.geste, crate::machine::windows::corrections::Geste::Dword { cle: k, valeur: n, donnee: 2 } if k == cle && n == nom),
                        "{reglage}"
                    );
                    assert!(dw);
                }
            }
        }
    }

    /// Les vraies listes, telles que `proposer` les envoie (point de restauration en tête pour les réglages) : chaque
    /// choix seul, puis tout coché d'un coup, passe la validation du processus élevé. Sinon la personne ne lirait
    /// qu'une liste refusée, après avoir tout accepté.
    #[test]
    fn les_listes_reelles_passent_la_validation_du_processus_eleve() {
        let mut e = etat_vide();
        e.winget = true;
        let point = crate::reparer::point_restauration("essai").unwrap().1;
        for (liste, restauration) in [(composants(&e), false), (reglages(&e), true)] {
            let tete: Vec<String> = if restauration { vec![point.clone()] } else { Vec::new() };
            let mut tout = tete.clone();
            for el in liste.iter().filter(|el| !el.commandes.is_empty()) {
                let seul: Vec<String> = tete.iter().chain(&el.commandes).cloned().collect();
                assert!(
                    crate::machine::windows::accepte_par_le_processus_eleve(&[seul]),
                    "{}",
                    el.titre
                );
                tout.extend(el.commandes.iter().cloned());
            }
            assert!(tout.len() > tete.len());
            assert!(crate::machine::windows::accepte_par_le_processus_eleve(&[tout]));
        }
    }

    /// Chaque réglage désigne ses valeurs par des gestes d'Optimiser (relevées et notées avant de l'appliquer), et
    /// une note de jeux.json d'avant se convertit dans cette forme : DWORD et texte du registre, GUID du mode
    /// d'alimentation ; un nom ou une valeur que Vanguard n'a jamais notés ne se convertit pas.
    #[test]
    fn gestes_et_notes_d_avant() {
        assert_eq!(
            gestes("hags"),
            [Geste::registre(
                true,
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
                "HwSchMode"
            )]
        );
        assert_eq!(gestes("souris").len(), 3);
        assert_eq!(gestes("alimentation"), [Geste::alimentation()]);
        for el in reglages(&etat_vide()) {
            assert!(
                el.annulable.as_ref().is_some_and(|(_, g)| !g.is_empty()),
                "{}",
                el.titre
            );
        }
        assert_eq!(
            convertir(
                "hags",
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\HwSchMode",
                Some("1")
            ),
            Some((
                Geste::registre(true, r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers", "HwSchMode"),
                Some("dword:1".into())
            ))
        );
        assert_eq!(
            convertir("souris", r"Control Panel\Mouse\MouseThreshold1", Some("6")),
            Some((
                Geste::registre(false, r"Control Panel\Mouse", "MouseThreshold1"),
                Some("sz:6".into())
            ))
        );
        assert_eq!(
            convertir("mode_jeu", r"Software\Microsoft\GameBar\AutoGameModeEnabled", None),
            Some((
                Geste::registre(false, r"Software\Microsoft\GameBar", "AutoGameModeEnabled"),
                None
            ))
        );
        assert_eq!(
            convertir(
                "alimentation",
                "powercfg",
                Some("Power Scheme GUID: 381B4222-F694-41F0-9685-FF5BB260DF2E  (Balanced)")
            ),
            Some((
                Geste::alimentation(),
                Some("381b4222-f694-41f0-9685-ff5bb260df2e".into())
            ))
        );
        assert_eq!(convertir("alimentation", "powercfg", Some("pas un mode")), None);
        assert_eq!(
            convertir(
                "hags",
                r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers\HwSchMode",
                Some("x")
            ),
            None
        );
        assert_eq!(convertir("hags", r"SYSTEM\Ailleurs\Valeur", Some("1")), None);
    }

    #[test]
    fn mode_d_alimentation_lu_dans_toutes_les_langues() {
        assert_eq!(
            guid_alimentation(
                "GUID du mode de gestion de l'alimentation : 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (Performances élevées)"
            ),
            Some("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c".into())
        );
        assert_eq!(guid_alimentation("pas de mode"), None);
        assert_eq!(guid_alimentation(""), None);
    }
}
