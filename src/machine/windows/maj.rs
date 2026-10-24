//! Mises à jour Windows : Windows Update et ses pilotes, winget, périphériques, cartes graphiques, Defender.

use super::*;

/// Une mise à jour proposée par Windows Update.
#[derive(Debug, PartialEq)]
struct MiseAJour {
    pilote: bool,
    /// Correctif de sécurité classé « Critique » ou « Important » par Microsoft.
    importante: bool,
    titre: String,
}

/// Lignes « type|gravité|titre » écrites par la recherche Windows Update (type 2 = pilote). Le titre d'un pilote est
/// écrit par son fabricant : prêt à montrer, comme les noms de programmes et de périphériques de ce fichier.
fn lire_windows_update(sortie: &str) -> Vec<MiseAJour> {
    sortie
        .lines()
        .filter_map(|l| {
            let mut champs = l.trim().splitn(3, '|');
            let (genre, gravite, titre) = (champs.next()?, champs.next()?, champs.next()?.trim());
            (!titre.is_empty()).then(|| MiseAJour {
                pilote: genre == "2",
                importante: matches!(gravite, "Critical" | "Important"),
                titre: crate::ui::affichable(titre),
            })
        })
        .collect()
}

/// Commandes de la fenêtre administrateur qui téléchargent et installent les mises à jour Windows (`pilotes` =
/// false) ou les pilotes, par l'API de Windows Update, comme le bouton « Tout installer ». La recherche (jusqu'à
/// deux minutes) est gardée dans la fenêtre : installer les deux en une fois ne la refait pas.
fn installer_windows_update(pilotes: bool) -> Vec<String> {
    let genre = if pilotes { 2 } else { 1 };
    vec![
        format!(
            "$maj = New-Object -ComObject Microsoft.Update.Session; \
             if ($null -eq $trouvees) {{ $trouvees = $maj.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates }}; \
             $liste = New-Object -ComObject Microsoft.Update.UpdateColl; \
             foreach ($u in $trouvees) {{ if ([int]$u.Type -eq {genre}) {{ if (-not $u.EulaAccepted) {{ $u.AcceptEula() }}; \
             [void]$liste.Add($u); Write-Host \"  - $($u.Title)\" }} }}"
        ),
        // Une mise à jour non téléchargée (vu dans la VM : Windows Update bloqué sur « En attente de
        // téléchargement ») ne doit pas passer pour installée : chacune est vérifiée et nommée.
        tr!("if ($liste.Count) { $t = $maj.CreateUpdateDownloader(); $t.Updates = $liste; \
         try { [void]$t.Download() } catch { Write-Host \"  Téléchargement interrompu : $($_.Exception.Message)\" -ForegroundColor Red } }; \
         $pret = New-Object -ComObject Microsoft.Update.UpdateColl; $ko = 0; \
         foreach ($u in $liste) { if ($u.IsDownloaded) { [void]$pret.Add($u) } \
         else { $ko++; Write-Host \"  Pas téléchargée : $($u.Title)\" -ForegroundColor Red } }", "if ($liste.Count) { $t = $maj.CreateUpdateDownloader(); $t.Updates = $liste; \
         try { [void]$t.Download() } catch { Write-Host \"  Download interrupted: $($_.Exception.Message)\" -ForegroundColor Red } }; \
         $pret = New-Object -ComObject Microsoft.Update.UpdateColl; $ko = 0; \
         foreach ($u in $liste) { if ($u.IsDownloaded) { [void]$pret.Add($u) } \
         else { $ko++; Write-Host \"  Not downloaded: $($u.Title)\" -ForegroundColor Red } }")
            .into(),
        // L'API installe sans prévenir le service du panneau Paramètres (UsoSvc) : sans StartScan, il garde sa
        // liste d'avant, « En attente de téléchargement », même après un redémarrage (vu dans la VM).
        tr!("$r = $null; if ($pret.Count) { $i = $maj.CreateUpdateInstaller(); $i.Updates = $pret; $r = $i.Install(); \
         try { UsoClient StartScan } catch {}; $global:LASTEXITCODE = 0 }; \
         if ($r) { for ($n = 0; $n -lt $pret.Count; $n++) { $code = $r.GetUpdateResult($n).ResultCode; \
         if ($code -eq 2) { Write-Host \"  Installée : $($pret.Item($n).Title)\" -ForegroundColor Green } \
         else { $ko++; Write-Host \"  Pas installée (code $code) : $($pret.Item($n).Title)\" -ForegroundColor Red } } }; \
         if ($r -and $r.RebootRequired) { Write-Host '  Redémarrage nécessaire pour finir.' -ForegroundColor Yellow }; \
         if ($ko) { throw \"$ko mise(s) à jour à refaire plus tard (ou Paramètres > Windows Update)\" }", "$r = $null; if ($pret.Count) { $i = $maj.CreateUpdateInstaller(); $i.Updates = $pret; $r = $i.Install(); \
         try { UsoClient StartScan } catch {}; $global:LASTEXITCODE = 0 }; \
         if ($r) { for ($n = 0; $n -lt $pret.Count; $n++) { $code = $r.GetUpdateResult($n).ResultCode; \
         if ($code -eq 2) { Write-Host \"  Installed: $($pret.Item($n).Title)\" -ForegroundColor Green } \
         else { $ko++; Write-Host \"  Not installed (code $code): $($pret.Item($n).Title)\" -ForegroundColor Red } } }; \
         if ($r -and $r.RebootRequired) { Write-Host '  Restart needed to finish.' -ForegroundColor Yellow }; \
         if ($ko) { throw \"$ko update(s) to retry later (or Settings > Windows Update)\" }")
            .into(),
    ]
}

/// La catégorie « Mises à jour de sécurité » de Windows Update : son identifiant est le même dans toutes les langues.
const CATEGORIE_SECURITE: &str = "0fa1201d-4330-4fa8-8ae9-b877473b6441";

/// Ce que l'API de Windows Update a répondu.
enum Recherche {
    /// Lignes « type|gravité|titre », comme le script PowerShell.
    Faite(String),
    /// La recherche a échoué (hors ligne, service bloqué) : inutile de la refaire par PowerShell.
    Echouee,
}

/// La recherche de Windows Update par son API (COM). `None` : l'API ne répond pas du tout, PowerShell prend le
/// relais.
fn windows_update_com() -> Option<Recherche> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::System::UpdateAgent::{IUpdateSession, UpdateSession, orcSucceeded, orcSucceededWithErrors};
    use windows::core::BSTR;
    wmi::com_delai(
        "Windows Update",
        "IUpdateSearcher::Search",
        std::time::Duration::from_secs(180),
        || {
            // SAFETY : COM est initialisé dans ce fil (par `wmi::com_delai`) ; les collections de Windows Update
            // s'indexent de 0 à Count - 1, bornes lues avant chaque accès.
            unsafe {
                let session: IUpdateSession = CoCreateInstance(&UpdateSession, None, CLSCTX_INPROC_SERVER)?;
                let chercheur = session.CreateUpdateSearcher()?;
                let Ok(resultat) = chercheur.Search(&BSTR::from("IsInstalled=0 and IsHidden=0")) else {
                    return Ok(Recherche::Echouee);
                };
                // Une recherche qui n'a pas abouti ne dit pas « à jour », même avec une liste vide.
                let code = resultat.ResultCode()?;
                if code != orcSucceeded && code != orcSucceededWithErrors {
                    return Ok(Recherche::Echouee);
                }
                let trouvees = resultat.Updates()?;
                let mut lignes = Vec::new();
                for i in 0..trouvees.Count()? {
                    let maj = trouvees.get_Item(i)?;
                    let mut gravite = maj.MsrcSeverity().map(|g| g.to_string()).unwrap_or_default();
                    // La mise à jour cumulative de sécurité arrive souvent sans gravité (vu dans la VM) : sa catégorie
                    // la classe alors « Important », comme dans le script.
                    if gravite.is_empty() {
                        let categories = maj.Categories()?;
                        for j in 0..categories.Count()? {
                            if categories
                                .get_Item(j)?
                                .CategoryID()?
                                .to_string()
                                .eq_ignore_ascii_case(CATEGORIE_SECURITE)
                            {
                                gravite = "Important".into();
                            }
                        }
                    }
                    lignes.push(format!("{}|{gravite}|{}", maj.Type()?.0, maj.Title()?));
                }
                Ok(Recherche::Faite(lignes.join("\n")))
            }
        },
    )
}

/// Ce que Windows Update propose et qui n'est pas installé : correctifs (Windows, .NET, Defender) et pilotes.
fn windows_update() -> Vec<Constat> {
    let sortie = match windows_update_com() {
        Some(Recherche::Faite(lignes)) => Some(lignes),
        Some(Recherche::Echouee) => None,
        None => windows_update_powershell(),
    };
    windows_update_juge(sortie)
}

fn windows_update_powershell() -> Option<String> {
    ps_delai(
        // La mise à jour cumulative de sécurité arrive souvent sans gravité (vu dans la VM) : sa catégorie
        // « Mises à jour de sécurité » (identifiant fixe, quelle que soit la langue) la classe alors « Important ».
        "foreach ($u in (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0').Updates) \
         { $g = $u.MsrcSeverity; foreach ($c in $u.Categories) { if (-not $g -and $c.CategoryID -eq '0fa1201d-4330-4fa8-8ae9-b877473b6441') { $g = 'Important' } }; \
         \"$([int]$u.Type)|$g|$($u.Title)\" }",
        180,
    )
}

fn windows_update_juge(sortie: Option<String>) -> Vec<Constat> {
    let Some(sortie) = sortie else {
        return vec![
            impossible(
                "Windows Update",
                tr!("recherche impossible, hors ligne ?", "search failed, offline?"),
            ),
            impossible(
                "Pilotes",
                tr!("recherche Windows Update impossible", "Windows Update search failed"),
            ),
        ];
    };
    let (pilotes, logiciels): (Vec<_>, Vec<_>) = lire_windows_update(&sortie).into_iter().partition(|m| m.pilote);
    vec![
        constat_windows_update(
            "Windows Update",
            tr!(
                "Windows à jour (correctifs, .NET, Defender).",
                "Windows up to date (fixes, .NET, Defender)."
            ),
            tr!("mise(s) à jour en attente", "update(s) pending"),
            tr!(
                "Télécharger et installer les mises à jour de Windows",
                "Download and install the Windows updates"
            ),
            false,
            &logiciels,
        ),
        constat_windows_update(
            "Pilotes",
            tr!(
                "Aucun pilote à mettre à jour dans Windows Update.",
                "No driver to update in Windows Update."
            ),
            tr!("pilote(s) à mettre à jour", "driver(s) to update"),
            tr!(
                "Installer les pilotes proposés par Windows Update",
                "Install the drivers offered by Windows Update"
            ),
            true,
            &pilotes,
        ),
    ]
}

/// « À jour », ou la liste des mises à jour (ou des pilotes) avec leur installation.
fn constat_windows_update(
    categorie: &'static str,
    a_jour: &str,
    quoi: &str,
    action: &str,
    pilotes: bool,
    liste: &[MiseAJour],
) -> Constat {
    if liste.is_empty() {
        return ok(categorie, a_jour);
    }
    let niveau = if liste.iter().any(|m| m.importante) {
        Niveau::Eleve
    } else {
        Niveau::Moyen
    };
    let titres: Vec<&str> = liste.iter().map(|m| m.titre.as_str()).collect();
    alerte(
        categorie,
        niveau,
        trf!(
            "{} {quoi} : {}.",
            "{} {quoi}: {}.",
            liste.len(),
            resume(&titres, 3, tr!(" ; ", "; "))
        ),
    )
    .corriger(action, &installer_windows_update(pilotes))
}

/// Les quatre petites lectures de `vanguard mises-a-jour` (redémarrage, signatures, périphériques, cartes graphiques), chacune
/// avec son script de secours. Chaque section a son try et se termine par « NOM_FIN » : une lecture qui échoue
/// (Defender remplacé par un antivirus tiers…) ne prive pas les autres.
const LECTURES_RAPIDES: [(&str, &str); 4] = [
    (
        "REB",
        "try { 'REB|' + [bool]((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired -or \
         (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending')); 'REB_FIN' } catch {}",
    ),
    (
        "SIG",
        "try { 'SIG|' + (Get-MpComputerStatus).AntivirusSignatureAge; 'SIG_FIN' } catch {}",
    ),
    (
        "PNP",
        "try { Get-CimInstance Win32_PnPEntity -Filter 'ConfigManagerErrorCode <> 0 AND ConfigManagerErrorCode <> 22' | \
         ForEach-Object { \"PNP|$($_.ConfigManagerErrorCode)|$(if ($_.Name) { $_.Name } else { $_.PNPDeviceID })\" }; 'PNP_FIN' } catch {}",
    ),
    (
        "GPU",
        "try { Get-CimInstance Win32_VideoController | ForEach-Object { \
         \"GPU|$($_.Name)|$($_.DriverVersion)|$(if ($_.DriverDate) { ((Get-Date) - $_.DriverDate).Days })\" }; 'GPU_FIN' } catch {}",
    ),
];

/// Un redémarrage attendu : par Windows Update (son API) ou par la maintenance des composants (la clé du registre que
/// le script testait). Sous Wine, RebootRequired n'est qu'une ébauche (toujours faux) : aucun test ne s'appuie dessus.
fn redemarrage_com() -> Option<Vec<String>> {
    use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
    use windows::Win32::System::UpdateAgent::{ISystemInformation, SystemInformation};
    let windows_update = wmi::com("Windows Update", "ISystemInformation::RebootRequired", || {
        // SAFETY : COM est initialisé dans ce fil (par `wmi::com`) ; SystemInformation est la classe de l'API.
        unsafe {
            let info: ISystemInformation = CoCreateInstance(&SystemInformation, None, CLSCTX_INPROC_SERVER)?;
            Ok(info.RebootRequired()?.as_bool())
        }
    })?;
    let composants = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")
        .is_ok();
    // Écrit comme le [bool] de PowerShell.
    Some(vec![format!(
        "REB|{}",
        if windows_update || composants { "True" } else { "False" }
    )])
}

fn signatures_wmi() -> Option<Vec<String>> {
    let lignes = wmi::requete(
        r"root\Microsoft\Windows\Defender",
        "MSFT_MpComputerStatus",
        "",
        &["AntivirusSignatureAge"],
    )?;
    let age = lignes.first()?["AntivirusSignatureAge"].entier()?;
    Some(vec![format!("SIG|{age}")])
}

fn peripheriques_wmi() -> Option<Vec<String>> {
    let lignes = wmi::requete(
        r"root\cimv2",
        "Win32_PnPEntity",
        "ConfigManagerErrorCode <> 0 AND ConfigManagerErrorCode <> 22",
        &["ConfigManagerErrorCode", "Name", "PNPDeviceID"],
    )?;
    Some(
        lignes
            .iter()
            .map(|l| {
                let code = l["ConfigManagerErrorCode"]
                    .entier()
                    .map(|c| c.to_string())
                    .unwrap_or_default();
                let nom = l["Name"]
                    .texte()
                    .filter(|n| !n.is_empty())
                    .or_else(|| l["PNPDeviceID"].texte())
                    .unwrap_or_default();
                format!("PNP|{code}|{nom}")
            })
            .collect(),
    )
}

/// Jours écoulés depuis une date CIM (« 20240115000000.000000-000 »), comme `((Get-Date) - $_.DriverDate).Days` ;
/// `None` sans date lisible.
fn jours_depuis(date_cim: &str, aujourd_hui: chrono::NaiveDate) -> Option<i64> {
    let date = chrono::NaiveDate::parse_from_str(date_cim.get(..8)?, "%Y%m%d").ok()?;
    Some((aujourd_hui - date).num_days())
}

fn cartes_graphiques_wmi() -> Option<Vec<String>> {
    let lignes = wmi::requete(
        r"root\cimv2",
        "Win32_VideoController",
        "",
        &["Name", "DriverVersion", "DriverDate"],
    )?;
    let aujourd_hui = chrono::Local::now().date_naive();
    Some(
        lignes
            .iter()
            .map(|l| {
                let jours = l["DriverDate"]
                    .texte()
                    .and_then(|d| jours_depuis(d, aujourd_hui))
                    .map(|j| j.to_string())
                    .unwrap_or_default();
                format!(
                    "GPU|{}|{}|{jours}",
                    l["Name"].texte().unwrap_or_default(),
                    l["DriverVersion"].texte().unwrap_or_default()
                )
            })
            .collect(),
    )
}

/// Les sections « NOM|… » puis « NOM_FIN » des quatre lectures : sans PowerShell (COM, WMI, registre), et un seul
/// PowerShell pour celles qui n'ont pas répondu.
fn lectures_rapides() -> Option<String> {
    let lues = [
        redemarrage_com(),
        signatures_wmi(),
        peripheriques_wmi(),
        cartes_graphiques_wmi(),
    ];
    let mut sortie = String::new();
    let mut secours = Vec::new();
    for ((nom, script), lu) in LECTURES_RAPIDES.iter().zip(lues) {
        match lu {
            Some(lignes) => {
                for l in lignes {
                    sortie.push_str(&l);
                    sortie.push('\n');
                }
                sortie.push_str(nom);
                sortie.push_str("_FIN\n");
            }
            None => secours.push(*script),
        }
    }
    if !secours.is_empty()
        && let Some(ps) = ps(&secours.join("; "))
    {
        sortie.push_str(&ps);
    }
    (!sortie.is_empty()).then_some(sortie)
}

fn redemarrage_en_attente(lectures: Option<&str>) -> Constat {
    match section(lectures, "REB").as_deref() {
        Some([a]) if a.eq_ignore_ascii_case("true") => alerte(
            "Redémarrage",
            Niveau::Moyen,
            tr!(
                "Des mises à jour attendent un redémarrage pour être actives.",
                "Updates are waiting for a restart to take effect."
            ),
        )
        .manuel(
            tr!("Redémarrer quand c'est pratique", "Restart when convenient"),
            &["Restart-Computer"],
        ),
        Some([a]) if a.eq_ignore_ascii_case("false") => ok(
            "Redémarrage",
            tr!("Aucun redémarrage en attente.", "No restart pending."),
        ),
        _ => illisible("Redémarrage"),
    }
}

/// (nom, identifiant) des programmes du tableau de « winget upgrade ». Les colonnes sont alignées sur l'en-tête (traduit selon
/// la langue de Windows), juste au-dessus de la ligne de tirets. Le tableau s'arrête à la première ligne qui n'a
/// pas d'identifiant ni de source (« 3 mises à niveau disponibles. », ou le second tableau des programmes épinglés).
fn lire_winget(sortie: &str) -> Option<Vec<(String, String)>> {
    // La barre de progression de winget se réécrit avec des retours chariot : seul le dernier état compte.
    // winget aligne ses colonnes sur la largeur affichée : un idéogramme y prend deux colonnes. Chaque caractère
    // large est suivi d'un bouche-trou, pour que l'index d'une case soit sa colonne à l'écran.
    const BOUCHE_TROU: char = '\u{0}';
    let lignes: Vec<Vec<char>> = sortie
        .lines()
        .map(|l| {
            l.rsplit('\r')
                .next()
                .unwrap_or("")
                .trim_end()
                .chars()
                // Un caractère sans largeur (accent combiné) n'occupe aucune colonne : écarté de la grille.
                .filter(|&c| crate::ui::largeur_car(c) > 0)
                .flat_map(|c| {
                    let large = crate::ui::largeur_car(c) > 1;
                    std::iter::once(c).chain(large.then_some(BOUCHE_TROU))
                })
                .collect()
        })
        .collect();
    let tirets = lignes
        .iter()
        .position(|l| l.len() >= 10 && l.iter().all(|&c| c == '-' || c == '─'))?;
    let entete = lignes.get(tirets.checked_sub(1)?)?;
    let debuts: Vec<usize> = (0..entete.len())
        .filter(|&i| entete[i] != ' ' && (i == 0 || entete[i - 1] == ' '))
        .collect();
    if debuts.len() < 4 {
        return None;
    }
    let champ = |l: &[char], n: usize| -> String {
        let debut = debuts[n].min(l.len());
        let fin = debuts.get(n + 1).map_or(l.len(), |&f| f.min(l.len()));
        l[debut..fin]
            .iter()
            .filter(|&&c| c != BOUCHE_TROU)
            .collect::<String>()
            .trim()
            .to_string()
    };
    let mut noms = Vec::new();
    for l in &lignes[tirets + 1..] {
        let (id, source) = (champ(l, 1), champ(l, debuts.len() - 1));
        if id.is_empty() || id.contains(' ') || source.is_empty() || source.contains(' ') {
            break;
        }
        // Le nom, choisi par l'éditeur du programme, est seulement montré ; l'identifiant sert à la mise à jour.
        noms.push((crate::ui::affichable(&champ(l, 0)), id));
    }
    Some(noms)
}

/// Une commande par programme : chacun réussit ou échoue à part dans la fenêtre administrateur. App Installer, qui
/// est winget lui-même, passe en dernier : sa mise à jour coupe winget (vu dans la VM, la suite n'était pas faite).
fn commandes_winget(programmes: &[(String, String)]) -> Vec<String> {
    let mut ids: Vec<&str> = programmes.iter().map(|(_, id)| id.as_str()).collect();
    ids.sort_by_key(|id| id.eq_ignore_ascii_case("Microsoft.AppInstaller"));
    ids.iter()
        .map(|id| {
            format!(
                "winget upgrade --id '{}' --exact --accept-source-agreements --accept-package-agreements --disable-interactivity",
                crate::commande::ps_texte(id)
            )
        })
        .collect()
}

/// Le winget du Store, par son chemin complet. Par son seul nom, Windows chercherait d'abord dans le dossier de
/// Vanguard (Téléchargements, une clé passée sur une autre machine) : un winget.exe posé là serait lancé à la place
/// du vrai, et son tableau vide ferait dire « Programmes à jour ». C'est un alias d'exécution (point d'analyse) :
/// son entrée se lit sans le suivre. `LOCALAPPDATA` absent ou relatif : pas de chemin sûr, `None`.
pub(super) fn winget_du_store(local: Option<&std::ffi::OsStr>) -> Option<std::path::PathBuf> {
    let chemin = std::path::Path::new(local?).join(r"Microsoft\WindowsApps\winget.exe");
    (chemin.is_absolute() && std::fs::symlink_metadata(&chemin).is_ok()).then_some(chemin)
}

/// Programmes installés que winget sait mettre à jour (navigateurs, 7-Zip, Discord, Steam…).
fn programmes() -> Constat {
    // winget lancé directement, sans PowerShell autour ; PowerShell seulement s'il ne démarre pas, ou s'il n'est
    // pas à la place de celui du Store (installé autrement : PowerShell le trouve par le PATH, comme avant).
    let debut = std::time::Instant::now();
    let mut lance = false;
    let direct = if let Some(winget) = winget_du_store(std::env::var_os("LOCALAPPDATA").as_deref()) {
        lance = true;
        crate::commande::lancer(
            std::process::Command::new(winget).args([
                "upgrade",
                "--accept-source-agreements",
                "--disable-interactivity",
            ]),
            150,
        )
        .map(|r| {
            format!(
                "{}\nCODE={}",
                r.sortie,
                r.code.map_or_else(String::new, |c| c.to_string())
            )
        })
    } else if super::installes::winget_present() {
        None
    } else {
        Some("WINGET_ABSENT".to_string())
    };
    // winget a démarré mais n'a pas répondu à temps (réseau lent, source muette) : le relancer par PowerShell
    // doublerait l'attente pour le même résultat. Un démarrage raté, lui, est immédiat.
    if direct.is_none() && lance && debut.elapsed() >= std::time::Duration::from_secs(140) {
        return impossible("Programmes", tr!("winget ne répond pas", "winget is not responding"));
    }
    // Démarré mais en erreur sans tableau lisible (vu dans une machine virtuelle : -2147024809, « paramètre
    // incorrect », lancé hors de PowerShell) : PowerShell le relance par son nom, comme avant ; il ne cherche pas
    // dans le dossier courant, un winget.exe posé à côté de Vanguard n'y est donc pas pris.
    let direct = direct.filter(|s| {
        let code = s.rsplit_once("CODE=").and_then(|(_, c)| c.trim().parse::<i64>().ok());
        s.contains("WINGET_ABSENT") || lire_winget(s).is_some() || matches!(code, Some(0 | -1_978_335_212))
    });
    let Some(sortie) = direct.or_else(|| {
        ps_delai(
            "if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { 'WINGET_ABSENT' } \
             else { winget upgrade --accept-source-agreements --disable-interactivity | Out-String; \"CODE=$LASTEXITCODE\" }",
            150,
        )
    }) else {
        return illisible("Programmes");
    };
    if sortie.contains("WINGET_ABSENT") {
        return impossible("Programmes", "winget absent").manuel(
            tr!(
                "Installer « Programme d'installation d'application » depuis le Microsoft Store",
                "Install “App Installer” from the Microsoft Store"
            ),
            &["Start-Process ms-windows-store://pdp/?ProductId=9NBLGGH4NNS1"],
        );
    }
    // 0x8A150014 : aucun programme trouvé, pas une erreur.
    let code = sortie
        .rsplit_once("CODE=")
        .and_then(|(_, c)| c.trim().parse::<i64>().ok());
    let programmes = match lire_winget(&sortie) {
        Some(n) => n,
        None if matches!(code, Some(0 | -1_978_335_212)) => Vec::new(),
        None => {
            return impossible(
                "Programmes",
                &trf!(
                    "winget en erreur (code {})",
                    "winget failed (code {})",
                    code.map_or("?".into(), |c| c.to_string())
                ),
            );
        }
    };
    if programmes.is_empty() {
        return ok(
            "Programmes",
            tr!("Programmes à jour (winget).", "Programs up to date (winget)."),
        );
    }
    let noms: Vec<&str> = programmes.iter().map(|(n, _)| n.as_str()).collect();
    alerte(
        "Programmes",
        Niveau::Moyen,
        trf!(
            "{} programme(s) à mettre à jour : {}.",
            "{} program(s) to update: {}.",
            noms.len(),
            resume(&noms, 3, ", ")
        ),
    )
    .corriger(
        tr!(
            "Mettre à jour ces programmes avec winget",
            "Update these programs with winget"
        ),
        &commandes_winget(&programmes),
    )
}

/// Périphériques en erreur dans le Gestionnaire de périphériques (pilote absent, qui ne démarre pas…).
/// Code 22 (désactivé à la main) écarté : un choix, pas une panne. Sans nom, l'identifiant matériel
/// (PCI\VEN_1AF4&DEV_1045…) le remplace : c'est lui qu'on cherche sur Internet pour trouver le pilote.
fn peripheriques(lectures: Option<&str>) -> Constat {
    let Some(lignes) = section(lectures, "PNP") else {
        return illisible("Périphériques");
    };
    let en_panne: Vec<String> = lignes
        .iter()
        .filter_map(|l| l.split_once('|'))
        // Le périphérique fw_cfg des VM QEMU n'a jamais de pilote, et n'en a pas besoin (vu dans la VM de test).
        .filter(|(_, nom)| !nom.contains("QEMU0002"))
        .map(|(code, nom)| {
            // Le nom vient du pilote, ou de l'appareil branché lui-même : montré rendu inoffensif.
            let nom = if nom.trim().is_empty() {
                tr!("Périphérique inconnu", "Unknown device").to_string()
            } else {
                crate::ui::affichable(nom.trim())
            };
            match code {
                "28" | "1" => trf!("{nom} (pas de pilote)", "{nom} (no driver)"),
                _ => trf!("{nom} (erreur {code})", "{nom} (error {code})"),
            }
        })
        .collect();
    if en_panne.is_empty() {
        return ok(
            "Périphériques",
            tr!(
                "Tous les périphériques ont un pilote qui fonctionne.",
                "Every device has a working driver."
            ),
        );
    }
    alerte(
        "Périphériques",
        Niveau::Moyen,
        trf!(
            "{} périphérique(s) sans pilote ou en erreur : {}.", "{} device(s) without a driver or in error: {}.",
            en_panne.len(),
            resume(&en_panne, 3, ", ")
        ),
    )
    .manuel(
        tr!("Chercher le pilote dans Windows Update > Options avancées > Mises à jour facultatives, sinon sur le site du fabricant", "Look for the driver in Windows Update > Advanced options > Optional updates, otherwise on the manufacturer's website"),
        &["Start-Process ms-settings:windowsupdate-optionalupdates", "Start-Process devmgmt.msc"],
    )
}

/// Outil du fabricant qui installe et tient à jour le pilote de cette carte graphique, et sa page officielle.
/// `None` pour une carte virtuelle ou de base (VM, Bureau à distance) : pas de pilote de fabricant à chercher.
pub fn pilote_fabricant(carte: &str) -> Option<(&'static str, &'static str)> {
    let nom = carte.to_lowercase();
    // Pages dans la langue de l'interface.
    if nom.contains("nvidia") {
        Some((
            "NVIDIA App",
            tr!(
                "https://www.nvidia.com/fr-fr/software/nvidia-app/",
                "https://www.nvidia.com/en-us/software/nvidia-app/"
            ),
        ))
    } else if nom.contains("amd") || nom.contains("radeon") {
        Some((
            "AMD Software Adrenalin",
            tr!(
                "https://www.amd.com/fr/support/download/drivers.html",
                "https://www.amd.com/en/support/download/drivers.html"
            ),
        ))
    } else if nom.contains("intel") {
        Some((
            "Intel Driver & Support Assistant",
            tr!(
                "https://www.intel.com/content/www/fr/fr/support/detect.html",
                "https://www.intel.com/content/www/us/en/support/detect.html"
            ),
        ))
    } else {
        None
    }
}

/// Âge du pilote de chaque carte graphique NVIDIA, AMD ou Intel. Son fabricant le publie souvent bien avant
/// Windows Update, et un pilote vieux d'un an rate des correctifs de sécurité et des optimisations des jeux.
fn cartes_graphiques(lectures: Option<&str>) -> Vec<Constat> {
    let Some(lignes) = section(lectures, "GPU") else {
        return vec![illisible("Carte graphique")];
    };
    lignes
        .iter()
        .filter_map(|l| {
            let mut c = l.splitn(3, '|');
            let (nom, version, jours) = (c.next()?.trim(), c.next()?.trim(), c.next()?.trim().parse::<u32>().ok());
            let (outil, lien) = pilote_fabricant(nom)?;
            let (nom, version) = (crate::ui::affichable(nom), crate::ui::affichable(version));
            let manuel = trf!("Mettre le pilote à jour avec {outil}", "Update the driver with {outil}");
            let ouvrir = format!("Start-Process {lien}");
            Some(match jours {
                Some(j) if j > 180 => alerte(
                    "Carte graphique",
                    Niveau::Moyen,
                    trf!(
                        "{nom} : pilote {version} vieux de {j} jours.",
                        "{nom}: driver {version}, {j} days old."
                    ),
                )
                .manuel(manuel, &[&ouvrir]),
                Some(j) => ok(
                    "Carte graphique",
                    trf!(
                        "{nom} : pilote {version} de {j} jours.",
                        "{nom}: driver {version}, {j} days old."
                    ),
                ),
                None => ok(
                    "Carte graphique",
                    trf!("{nom} : pilote {version}.", "{nom}: driver {version}."),
                ),
            })
        })
        .collect()
}

/// Signatures de Defender : la même règle pour l'audit et pour `vanguard mises-a-jour`.
pub(super) fn signatures(age: u64) -> Constat {
    if age > 3 {
        alerte(
            "Signatures",
            Niveau::Moyen,
            trf!(
                "Signatures antivirus vieilles de {age} jours.",
                "Antivirus signatures {age} days old."
            ),
        )
        .corriger(
            tr!("Mettre à jour les signatures", "Update the signatures"),
            &["Update-MpSignature"],
        )
    } else {
        ok(
            "Signatures",
            tr!("Signatures de Defender à jour.", "Defender signatures up to date."),
        )
    }
}

/// `None` avec un antivirus tiers : Defender n'a alors pas de signatures à tenir à jour.
fn signatures_defender(lectures: Option<&str>) -> Option<Constat> {
    let age = section(lectures, "SIG")?.first()?.trim().parse().ok()?;
    Some(signatures(age))
}

/// Tout ce qui doit être à jour : Windows, ses pilotes, les programmes, Defender. Windows Update et winget (jusqu'à
/// deux minutes chacun) tournent en parallèle pendant les lectures rapides.
/// `seulement` : les catégories à revérifier (après une installation) ; les lectures rapides sont toujours faites.
pub fn mises_a_jour_completes(seulement: Option<&[&str]>) -> Vec<Constat> {
    let voulu = |categories: &[&str]| seulement.is_none_or(|s| categories.iter().any(|c| s.contains(c)));
    std::thread::scope(|portee| {
        let wu = voulu(&["Windows Update", "Pilotes"]).then(|| portee.spawn(windows_update));
        let winget = voulu(&["Programmes"]).then(|| portee.spawn(programmes));
        let lectures = lectures_rapides();
        let l = lectures.as_deref();
        let mut constats = wu.map(|t| t.join().unwrap_or_default()).unwrap_or_default();
        constats.push(redemarrage_en_attente(l));
        constats.extend(signatures_defender(l));
        constats.extend(winget.map(|t| t.join().unwrap_or_else(|_| illisible("Programmes"))));
        constats.push(peripheriques(l));
        constats.extend(cartes_graphiques(l));
        constats
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sous Wine, l'API de Windows Update n'est qu'une ébauche : jamais une recherche « faite » qui dirait Windows
    /// à jour.
    #[test]
    fn jours_d_un_pilote() {
        let jour = chrono::NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        assert_eq!(jours_depuis("20260101000000.000000-000", jour), Some(292));
        assert_eq!(jours_depuis("20261020000000.000000-000", jour), Some(0));
        assert_eq!(jours_depuis("", jour), None);
        assert_eq!(jours_depuis("pas une date", jour), None);
    }

    /// Chaque section rendue est complète (son marqueur de fin), lue par les fonctions de toujours.
    #[test]
    fn lectures_rapides_completes() {
        if let Some(l) = lectures_rapides().as_deref() {
            for nom in ["REB", "SIG", "PNP", "GPU"] {
                let lignes = l.lines().filter(|x| x.starts_with(&format!("{nom}|"))).count();
                assert!(lignes == 0 || l.lines().any(|x| x == format!("{nom}_FIN")), "{nom}");
            }
            let _ = (
                redemarrage_en_attente(Some(l)),
                peripheriques(Some(l)),
                cartes_graphiques(Some(l)),
            );
        }
    }

    /// winget n'est lancé que par le chemin du Store, jamais par son nom ; sans `LOCALAPPDATA` sûr, pas de lancement
    /// direct (PowerShell reprend, par le PATH).
    #[test]
    fn winget_par_son_chemin_complet() {
        let local = std::env::temp_dir().join(format!("vanguard-winget-{}", std::process::id()));
        let apps = local.join(r"Microsoft\WindowsApps");
        std::fs::create_dir_all(&apps).unwrap();
        assert_eq!(winget_du_store(Some(local.as_os_str())), None);
        std::fs::write(apps.join("winget.exe"), b"").unwrap();
        assert_eq!(winget_du_store(Some(local.as_os_str())), Some(apps.join("winget.exe")));
        assert_eq!(winget_du_store(Some(std::ffi::OsStr::new(r"Microsoft"))), None);
        assert_eq!(winget_du_store(None), None);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn windows_update_sous_wine() {
        let r = windows_update_com();
        if std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file() {
            assert!(!matches!(r, Some(Recherche::Faite(_))));
        }
    }

    /// Des noms en idéogrammes : winget leur donne deux colonnes chacun, les colonnes suivantes restent lues.
    #[test]
    fn tableau_de_winget_en_ideogrammes() {
        let sortie = "名称         ID               版本    可用    源\r\n\
-------------------------------------------------------\r\n\
腾讯QQ       Tencent.QQ       9.7     9.8     winget\r\n\
微软 Edge    Microsoft.Edge   130.0   131.0   winget\r\n\
7-Zip        7zip.7zip        24.07   24.08   winget\r\n";
        let ids: Vec<String> = lire_winget(sortie).unwrap().into_iter().map(|(_, id)| id).collect();
        assert_eq!(ids, ["Tencent.QQ", "Microsoft.Edge", "7zip.7zip"]);
        let noms: Vec<String> = lire_winget(sortie).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(noms[0], "腾讯QQ");
    }

    #[test]
    fn tableau_de_winget() {
        // Forme de la sortie de winget en français, barre de progression comprise (à confirmer dans la VM).
        let sortie = "   - \r   \\ \r\r\n\
Nom                         ID                       Version      Disponible   Source\r\n\
-------------------------------------------------------------------------------------\r\n\
Mozilla Firefox (x64 fr)    Mozilla.Firefox.fr       130.0        131.0.2      winget\r\n\
7-Zip 24.07 (x64)           7zip.7zip                24.07        24.08        winget\r\n\
Discord                     Discord.Discord          1.0.9163     1.0.9170     winget\r\n\
3 mises à niveau disponibles.\r\n\
\r\n\
Le package suivant a une mise à niveau, mais il nécessite un ciblage explicite :\r\n\
Nom    ID        Version Disponible Source\r\n\
------------------------------------------\r\n\
Steam  Valve.Steam 2.10  2.11       winget\r\n\
CODE=0";
        let noms: Vec<String> = lire_winget(sortie).unwrap().into_iter().map(|(n, _)| n).collect();
        assert_eq!(noms, ["Mozilla Firefox (x64 fr)", "7-Zip 24.07 (x64)", "Discord"]);
        // Sortie réelle de la VM Windows 11 (winget 1.29, anglais) : App Installer passe en dernier.
        let vm = "Name             Id                        Version       Available     Source\r\n\
-----------------------------------------------------------------------------\r\n\
App Installer    Microsoft.AppInstaller    1.29.379.0    1.29.380      winget\r\n\
Microsoft Edge   Microsoft.Edge            155.0.4283.45 155.0.4283.62 winget\r\n\
Windows Terminal Microsoft.WindowsTerminal 1.24.12741.0  1.25.2733.0   winget\r\n\
3 upgrades available.\r\nCODE=0";
        let programmes = lire_winget(vm).unwrap();
        assert_eq!(programmes.len(), 3);
        let c = commandes_winget(&programmes);
        assert!(c[0].contains("--id 'Microsoft.Edge'") && c[2].contains("--id 'Microsoft.AppInstaller'"));
        assert_eq!(
            lire_winget("Aucun package installé ne correspond aux critères d’entrée.\nCODE=0"),
            None
        );
        let resume_noms: Vec<String> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(crate::ui::resume(&resume_noms, 3, ", "), "a, b, c (et 2 autre(s))");
    }

    #[test]
    fn liste_de_windows_update() {
        let l = lire_windows_update(
            "1|Critical|2026-10 Mise à jour de sécurité (KB5127648) (26200.9711)\n\
             1||Mise à jour de la plateforme Microsoft Defender | KB4052623\n\
             2||NVIDIA - Display - 32.0.15.6094\n\n",
        );
        assert_eq!(l.len(), 3);
        assert!(l[0].importante && !l[0].pilote);
        // Un « | » dans le titre n'est pas un séparateur.
        assert_eq!(
            l[1].titre,
            "Mise à jour de la plateforme Microsoft Defender | KB4052623"
        );
        assert!(l[2].pilote && !l[2].importante);
        // Le titre d'un pilote, écrit par son fabricant, et le nom d'un programme : rendus inoffensifs.
        let l = lire_windows_update("2||Pilote\x1b]52;c;eA==\x07\x1b[2K\u{202e}\n");
        assert_eq!(l[0].titre, "Pilote�]52;c;eA==��[2K�");
        let tableau = "Name             Id         Version Available Source\r\n\
                       -----------------------------------------------------\r\n\
                       Outil\x1b[8m\u{2066}       Essai.Outil 1.0     1.1       winget\r\n";
        let p = lire_winget(tableau).unwrap();
        assert_eq!(p[0].1, "Essai.Outil");
        assert!(!crate::ui::contient_un_piege(&p[0].0), "{}", p[0].0);
    }

    #[test]
    fn sections_des_lectures_rapides() {
        // Defender absent (antivirus tiers) : sa section manque, les autres restent lisibles.
        let l = "REB|False\r\nREB_FIN\r\nPNP|28|PCI\\VEN_1AF4&DEV_1045\r\nPNP_FIN\r\nGPU_FIN\r\n";
        assert_eq!(section(Some(l), "REB"), Some(vec!["False"]));
        assert_eq!(section(Some(l), "SIG"), None);
        assert_eq!(section(Some(l), "PNP"), Some(vec!["28|PCI\\VEN_1AF4&DEV_1045"]));
        assert_eq!(section(Some(l), "GPU"), Some(vec![]));
        assert_eq!(section(None, "REB"), None);
    }

    /// Le nom d'un périphérique (donné par l'appareil branché ou par son pilote) et ceux d'une carte graphique :
    /// piégés, ils arrivent inoffensifs dans les constats.
    #[test]
    fn noms_de_materiel_pieges() {
        let l = "PNP|28|Clavier\x1b]0;x\x07\u{202e}\r\nPNP_FIN\r\n\
                 GPU|NVIDIA GeForce\x1b[8m|32.0\x1b[2K|400\r\nGPU_FIN\r\n";
        let p = peripheriques(Some(l));
        assert!(p.message.contains("Clavier�]0;x��"), "{}", p.message);
        let g = cartes_graphiques(Some(l));
        assert_eq!(g.len(), 1);
        assert!(g[0].message.starts_with("NVIDIA GeForce�[8m"), "{}", g[0].message);
        for c in std::iter::once(&p).chain(&g) {
            assert!(!crate::ui::contient_un_piege(&c.message), "{}", c.message);
        }
    }
}
