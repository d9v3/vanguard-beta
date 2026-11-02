//! Audit de sécurité Windows 10/11 via PowerShell (sans droits administrateur pour l'audit).

use std::fmt::Write;
use std::process::Command;

use super::{Audit, Constat, alerte, impossible, ok};
use crate::commande::section;
use crate::machine::gestes;
use crate::risk::{Niveau, info_port};
use crate::trw;
use crate::ui::{resume, tr, trf, trp};

mod ancrages;
pub(crate) mod cartes;
mod chargement;
pub(crate) mod compte;
pub(crate) mod comptes;
pub(crate) mod connexions;
#[cfg(test)]
pub(crate) mod corpus;
pub(crate) mod correctifs;
pub(crate) mod corrections;
mod croisees;
mod defender;
mod defender_ecriture;
mod durcissement;
pub(crate) mod ecoute;
pub(crate) mod eleve;
pub(crate) mod environnement;
pub(crate) mod evenements;
pub(crate) mod exclusions;
pub(crate) mod export_journaux;
pub(crate) mod gestionnaire;
pub(crate) mod hachage;
pub(crate) mod impression;
pub(crate) mod installes;
pub(crate) mod lecteurs;
pub(crate) mod magasins;
mod maj;
pub(crate) mod memoire;
pub(crate) mod ouvrir;
pub(crate) mod pare_feu;
pub(crate) mod partages;
pub(crate) mod peripheriques;
pub(crate) mod persistance;
mod pilotes;
pub(crate) mod planificateur;
mod portes;
pub(crate) mod processus;
mod regles;
pub(crate) mod routes;
pub(crate) mod securite;
mod services;
mod services_ecriture;
mod ssh;
mod verrouillage;
pub(crate) mod wmi;

use comptes::{comptes, politique};
use maj::signatures;
pub use maj::{mises_a_jour_completes, pilote_fabricant};
use persistance::persistance;

/// La clé des services et des pilotes : une seule écriture pour tous les lecteurs (bilan, gestionnaire, pilotes,
/// accès à distance, logiciels espions).
pub(crate) const CLE_SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";

pub const NOM: &str = "Windows";

const FIN: &str = "__VANGUARD_FIN__";

/// winget sort ces codes quand le paquet est déjà là (« aucune mise à jour applicable », « déjà installé ») :
/// ce n'est pas un échec.
const DEJA_INSTALLE: &str = "-1978335189, -1978335135";

/// winget dans la fenêtre administrateur, par son chemin complet. Par son seul nom, PowerShell le chercherait dans le
/// PATH du compte, que tout programme de ce compte peut changer : un winget.exe posé plus tôt dans ce PATH serait lancé
/// en administrateur. Le chemin vient du paquet App Installer de Microsoft (éditeur 8wekyb3d8bbwe), installé sous
/// Program Files\WindowsApps, dossier que seul le système écrit ; la plus récente version si plusieurs comptes en ont
/// une. Le module Appx est chargé par son chemin dans le dossier de PowerShell : un module « Appx » du compte (premier
/// dans PSModulePath) ne répond pas à sa place. Introuvable : la commande échoue, rien n'est lancé.
const RECHERCHE_DE_WINGET: &str = "$vanguardWinget = $null; Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules\\Appx')) -ErrorAction Stop; \
     $vanguardRacine = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'WindowsApps') + '\\'; $vanguardVersion = $null; \
     foreach ($vanguardPaquet in @(Appx\\Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller')) { \
     $vanguardDossier = [string]$vanguardPaquet.InstallLocation; $vanguardExe = [IO.Path]::Combine($vanguardDossier, 'winget.exe'); \
     if ($vanguardPaquet.PublisherId -eq '8wekyb3d8bbwe' -and $vanguardDossier.StartsWith($vanguardRacine, [StringComparison]::OrdinalIgnoreCase) -and -not $vanguardDossier.Contains('..') \
     -and [IO.File]::Exists($vanguardExe) -and (-not $vanguardVersion -or ([version]$vanguardPaquet.Version) -gt $vanguardVersion)) \
     { $vanguardVersion = [version]$vanguardPaquet.Version; $vanguardWinget = $vanguardExe } }; ";
/// La suite : introuvable, la commande échoue sans rien lancer ; trouvé, winget par ce chemin (les arguments suivent).
/// Un App Installer hors de Program Files\WindowsApps reste refusé (un dossier d'un autre disque peut être inscriptible
/// par le compte) : le message le dit, avec quoi faire.
const WINGET_TROUVE_FR: &str = "if (-not $vanguardWinget) { throw 'winget introuvable : App Installer de Microsoft manque, ou il n''est pas installé dans Program Files\\WindowsApps (ailleurs, Vanguard ne le lance pas en administrateur). Installez ou mettez à jour App Installer depuis le Microsoft Store ; rien n''a été lancé.' }; & $vanguardWinget";
const WINGET_TROUVE_EN: &str = "if (-not $vanguardWinget) { throw 'winget not found: Microsoft App Installer is missing, or it is not installed in Program Files\\WindowsApps (elsewhere, Vanguard does not run it as administrator). Install or update App Installer from the Microsoft Store; nothing was run.' }; & $vanguardWinget";

/// 0xC0000135 (STATUS_DLL_NOT_FOUND) en entier signé : winget lancé par son chemin, hors de l'alias du Store, n'a pas
/// trouvé une de ses bibliothèques (App Installer ancien ou abîmé). « code -1073741515 » ne dirait rien à personne.
const WINGET_NE_DEMARRE_PAS: i32 = -1_073_741_515;

/// À mettre juste après les arguments de `winget_eleve()` : un winget qui n'a pas pu démarrer devient une erreur
/// claire, dans la langue de l'interface, au lieu d'un code.
pub(crate) fn winget_demarre() -> String {
    format!(
        "; if ($LASTEXITCODE -eq {WINGET_NE_DEMARRE_PAS}) {{ throw '{}' }}",
        tr!(
            "winget n''a pas pu démarrer en administrateur (code 0xC0000135) : mettez App Installer à jour depuis le Microsoft Store, puis relancez.",
            "winget could not start as administrator (code 0xC0000135): update App Installer from the Microsoft Store, then try again."
        )
    )
}

/// Le début d'une commande winget de la fenêtre administrateur, dans la langue de l'interface (`& $vanguardWinget`
/// suit : les arguments viennent après).
pub(crate) fn winget_eleve() -> String {
    let suite = if crate::langue::anglais() {
        WINGET_TROUVE_EN
    } else {
        WINGET_TROUVE_FR
    };
    format!("{RECHERCHE_DE_WINGET}{suite}")
}

/// La commande sans la recherche de winget, telle qu'elle s'annonce : `winget install …`. `None` : pas une commande
/// winget de la fenêtre administrateur.
pub(crate) fn sans_recherche_de_winget(commande: &str) -> Option<&str> {
    let suite = commande.strip_prefix(RECHERCHE_DE_WINGET)?;
    [WINGET_TROUVE_FR, WINGET_TROUVE_EN]
        .iter()
        .find_map(|t| suite.strip_prefix(t))
}

/// Installation silencieuse par winget, sans erreur si le paquet est déjà là. La source est imposée : un
/// identifiant ne peut pas être pris pour une application du Microsoft Store au nom voisin.
pub fn winget_installer(id: &str) -> String {
    format!(
        "{} install --id {id} --exact --source winget --silent --accept-package-agreements --accept-source-agreements --disable-interactivity{}; \
         if ($LASTEXITCODE -in {DEJA_INSTALLE}) {{ $global:LASTEXITCODE = 0 }}",
        winget_eleve(),
        winget_demarre()
    )
}

/// Windows PowerShell 5.1, avec ses propres modules. Lancé depuis PowerShell 7 (Windows Terminal), il hériterait
/// de son PSModulePath et chargerait des modules de la version 7, incompatibles : le lecteur Cert: manquait ainsi
/// dans le test de la VM. Sans la variable, la 5.1 reprend ses chemins par défaut. Celui de System32 : par son seul nom,
/// Windows chercherait d'abord un powershell.exe posé à côté de Vanguard (dossier du programme lancé, peut-être en
/// administrateur). Absent (Wine) : il ne démarre pas, et ce qu'il devait lire reste non vérifié. Vanguard lancé en
/// administrateur : l'environnement réduit de `powershell_eleve`, le compte ne doit rien y glisser.
pub fn powershell() -> Command {
    let mut c = Command::new(crate::commande::systeme32(r"WindowsPowerShell\v1.0\powershell.exe"));
    if processus::eleve() {
        environnement::reduire(&mut c);
    } else {
        c.env_remove("PSModulePath");
    }
    c
}

/// PowerShell pour un geste de Vanguard administrateur : rien de l'environnement du compte (COR_PROFILER chargerait
/// une DLL, PSModulePath un module des Documents), seulement les variables calculées par Windows
/// (`environnement::reduire`) ; lancé depuis System32, pas depuis le dossier (Téléchargements, clé) d'où Vanguard est
/// parti.
pub(crate) fn powershell_eleve() -> Command {
    let mut c = Command::new(crate::commande::systeme32(r"WindowsPowerShell\v1.0\powershell.exe"));
    environnement::reduire(&mut c).current_dir(crate::commande::dossier_systeme());
    c
}

/// winget par son chemin : celui du Store, sinon celui du PATH ou des liens de winget. Jamais par son seul nom, que
/// Windows chercherait d'abord à côté de Vanguard.
pub(crate) fn winget() -> Option<std::path::PathBuf> {
    maj::winget_du_store(std::env::var_os("LOCALAPPDATA").as_deref())
        .or_else(|| crate::protection::outil::trouver("winget"))
}

/// Exécute un script PowerShell et retourne sa sortie (UTF-8), ou `None` en cas d'échec.
/// Le script doit aller jusqu'au marqueur de fin : une sortie vide sans marqueur (PowerShell bloqué,
/// absent, ou remplacé par un bouchon comme sous Wine) n'est jamais prise pour une réponse.
pub fn ps(script: &str) -> Option<String> {
    // 60 s : un cmdlet bloqué (service Defender suspendu…) ne doit pas figer l'audit.
    ps_delai(script, 60)
}

/// Comme `ps`, avec un délai choisi : la recherche Windows Update ou winget peuvent prendre une minute ou deux.
pub(crate) fn ps_delai(script: &str, secondes: u64) -> Option<String> {
    let complet =
        format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; {script}; '{FIN}'");
    // Début du script, pour retrouver lequel a échoué dans le journal.
    let debut: String = script.trim().chars().take(240).collect();
    let Some(r) = crate::commande::lancer(
        powershell().args(["-NoProfile", "-NonInteractive", "-Command", &complet]),
        secondes,
    ) else {
        crate::journal::erreur(
            "PowerShell",
            &format!("délai de {secondes} s dépassé, ou lancement impossible\n{debut}"),
        );
        return None;
    };
    match r.sortie.rsplit_once(FIN) {
        Some((avant, _)) if r.code == Some(0) => Some(avant.trim().to_string()),
        _ => {
            let etat = match r.code {
                Some(0) => "sortie incomplète (marqueur de fin absent)".to_string(),
                Some(c) => format!("code de retour {c}"),
                None => "arrêté par le système".to_string(),
            };
            crate::journal::erreur(
                "PowerShell",
                &format!("{etat}\n{debut}\n--- erreurs ---\n{}", r.erreurs.trim()),
            );
            None
        }
    }
}

/// Constat quand une vérification n'a pas pu se faire : on le dit, on ne conclut jamais « OK ».
/// Une valeur du registre, lue directement (winreg) : sans lancer PowerShell, dont chaque démarrage coûte près
/// d'une demi-seconde et charge .NET (une vingtaine à la fois au bilan se gênaient).
pub(super) fn registre<T: winreg::types::FromRegValue>(racine: winreg::HKEY, cle: &str, valeur: &str) -> Option<T> {
    winreg::RegKey::predef(racine)
        .open_subkey(cle)
        .ok()?
        .get_value(valeur)
        .ok()
}

/// Un réglage lu dans le registre qui manque ou ne se lit pas (sans PowerShell : ce n'est pas lui qui est en cause).
pub(super) fn registre_illisible(categorie: &'static str) -> Constat {
    impossible(
        categorie,
        tr!("réglage du registre illisible", "registry setting unreadable"),
    )
}

/// Comptes locaux, groupe des administrateurs et dernière connexion, lus en un seul lancement de PowerShell pour les
/// trois vérifications qui en ont besoin (comptes, comptes oubliés, nouveaux administrateurs). Sections : USR, MOI,
/// LBP (comptes), CPT (comptes oubliés), ADM (administrateurs, par le SID du groupe, dont le nom change avec la
/// langue).
const SCRIPT_COMPTES: &str = "try { Get-LocalUser | ForEach-Object { \"USR|$($_.Enabled)|$($_.PasswordRequired)|$($_.SID.Value)|$($_.Name)\" }; 'USR_FIN' } catch {}; \
     try { 'MOI|' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; 'MOI_FIN' } catch {}; \
     try { 'LBP|' + (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa').LimitBlankPasswordUse; 'LBP_FIN' } catch {}; \
     try { $moi = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; \
       Get-LocalUser | Where-Object { $_.Enabled -and $_.SID.Value -ne $moi -and $_.SID.Value -notmatch '-(500|501|503|504)$' } | \
       ForEach-Object { \"CPT|$(if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd') })|$($_.Name)\" }; 'CPT_FIN' } catch {}; \
     try { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { 'ADM|' + $_.Name }; 'ADM_FIN' } catch {}";

/// La dernière lecture des comptes et son heure. Vidée au début de chaque bilan ; plus d'une minute, relue.
static COMPTES: std::sync::Mutex<Option<(std::time::Instant, Option<String>)>> = std::sync::Mutex::new(None);

/// La sortie du script des comptes : la première vérification qui la demande la lit, les autres attendent et la
/// reprennent (chaque lancement de PowerShell coûte près d'une demi-seconde).
pub(crate) fn comptes_locaux() -> Option<String> {
    let mut garde = COMPTES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((quand, sortie)) = garde.as_ref()
        && quand.elapsed() < std::time::Duration::from_secs(60)
    {
        return sortie.clone();
    }
    // Par les fonctions de Windows d'abord (plus d'une demi-seconde de moins) ; le script en secours.
    let sortie = comptes::lecture_native().or_else(|| ps(SCRIPT_COMPTES));
    *garde = Some((std::time::Instant::now(), sortie.clone()));
    sortie
}

pub(super) fn illisible(categorie: &'static str) -> Constat {
    impossible(
        categorie,
        tr!("PowerShell indisponible ou bloqué", "PowerShell unavailable or blocked"),
    )
}

/// La variable d'environnement qui donne au script lancé par le processus élevé la poignée (héritée) du tube anonyme
/// où il écrit l'état de chaque correctif.
pub(super) const VARIABLE_RESULTATS: &str = "VANGUARD_RESULTATS";

/// Où le script écrit l'état de chaque correctif.
#[derive(Clone, Copy)]
enum Sortie<'a> {
    /// Dans ce fichier, ouvert seulement s'il n'existe pas encore, avec un journal à côté : la fenêtre PowerShell
    /// administrateur de Wine, un autre processus, qui ne peut répondre autrement.
    Fichier(&'a str),
    /// Dans le tube anonyme du processus élevé (`VARIABLE_RESULTATS`) : rien n'est écrit dans le dossier du compte, et
    /// la console du processus élevé, qui attend Entrée à la fin, garde ce qui s'est affiché.
    Tube,
}

/// Le script exécuté dans la fenêtre administrateur : chaque commande est annoncée, puis « OK » ou l'erreur.
/// Une fenêtre muette ne se distingue pas d'une fenêtre figée. Chaque étape a son try/catch : une erreur PowerShell
/// compte, comme un programme externe en échec, pour une étape ratée, et la fenêtre passe à la suivante. Après chaque
/// correctif, une ligne « ok » ou « echec » s'écrit dans la `sortie`, que Vanguard lit.
fn script_admin(correctifs: &[Vec<String>], sortie: Sortie) -> String {
    let texte = crate::commande::ps_texte;
    let mut script = String::from(tr!(
        "$Host.UI.RawUI.WindowTitle = 'Vanguard : correction en cours'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'Vanguard applique une correction.' -ForegroundColor Cyan\n\
         Write-Host 'Une étape longue (mise à jour, analyse, réparation de Windows) peut durer plusieurs minutes : son heure de début est affichée.'\n\
         $echecs = 0\n",
        "$Host.UI.RawUI.WindowTitle = 'Vanguard: applying a fix'\n\
         [Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         $ErrorActionPreference = 'Stop'\n\
         Write-Host 'Vanguard is applying a fix.' -ForegroundColor Cyan\n\
         Write-Host 'A long step (update, scan, Windows repair) can take several minutes: its start time is shown.'\n\
         $echecs = 0\n"
    ));
    // Ce que la fenêtre affiche reste écrit à côté du script (« .log ») : une fenêtre fermée ne laisserait aucune trace
    // de ce qui a réussi ou échoué. Ce dossier, tout programme du compte peut le modifier, et la fenêtre écrit avec les
    // droits d'administrateur : sous un nom connu d'avance, un lien posé là lui ferait écrire ailleurs (un fichier du
    // système). Le journal finit donc par un nombre qu'elle tire elle-même, sans rien écraser (-NoClobber), et le
    // fichier des résultats ne s'ouvre que s'il n'existe pas encore (CreateNew : ni fichier ni lien posé avant).
    // Dans le tube : sa poignée, héritée du processus élevé, et lue dans une variable que ce processus a lui-même fixée.
    match sortie {
        Sortie::Fichier(resultats) => {
            let journal = resultats.strip_suffix(".resultats").unwrap_or(resultats);
            let _ = writeln!(
                script,
                "try {{ Start-Transcript -LiteralPath ('{}-' + [guid]::NewGuid().ToString('N') + '.log') -NoClobber -ErrorAction Stop | Out-Null }} catch {{ }}\n\
                 try {{ $resultats = [IO.StreamWriter]::new([IO.File]::Open('{}', 'CreateNew', 'Write', 'Read')); $resultats.AutoFlush = $true }} catch {{ $resultats = $null }}",
                texte(journal),
                texte(resultats)
            );
        }
        Sortie::Tube => {
            let _ = writeln!(
                script,
                "try {{ Add-Type -AssemblyName System.Core; $resultats = [IO.StreamWriter]::new([IO.Pipes.AnonymousPipeClientStream]::new([IO.Pipes.PipeDirection]::Out, $env:{VARIABLE_RESULTATS})); $resultats.AutoFlush = $true }} catch {{ $resultats = $null }}"
            );
        }
    }
    for commandes in correctifs {
        script += "$avant = $echecs\n";
        for c in commandes {
            // Un programme externe (DISM, sfc, netsh…) en échec ne lève pas d'erreur PowerShell : seul son code de
            // retour le dit. On le lit après chaque commande (3010 = réussi, redémarrage demandé) et on continue :
            // dans « Internet ne marche plus », un netsh en échec ne doit pas empêcher de renouveler l'adresse.
            let _ = trw!(
                script,
                "Write-Host ''; Write-Host ('> ' + (Get-Date -Format 'HH:mm') + '  {}') -ForegroundColor Yellow\n$global:LASTEXITCODE = 0\ntry {{\n  {c}\n  \
                 if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (redémarrage nécessaire)' -ForegroundColor Green }}\n  \
                 elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Échec (code $LASTEXITCODE) : voir le message ci-dessus\" -ForegroundColor Red }}\n  \
                 else {{ Write-Host '  OK' -ForegroundColor Green }}\n\
                 }} catch {{ $echecs++; Write-Host ('  Échec : ' + $_.Exception.Message) -ForegroundColor Red }}\n",
                "Write-Host ''; Write-Host ('> ' + (Get-Date -Format 'HH:mm') + '  {}') -ForegroundColor Yellow\n$global:LASTEXITCODE = 0\ntry {{\n  {c}\n  \
                 if ($LASTEXITCODE -eq 3010) {{ Write-Host '  OK (restart needed)' -ForegroundColor Green }}\n  \
                 elseif ($LASTEXITCODE) {{ $echecs++; Write-Host \"  Failed (code $LASTEXITCODE): see the message above\" -ForegroundColor Red }}\n  \
                 else {{ Write-Host '  OK' -ForegroundColor Green }}\n\
                 }} catch {{ $echecs++; Write-Host ('  Failed: ' + $_.Exception.Message) -ForegroundColor Red }}\n",
                // Annoncée filtrée (un nom piégé ne réécrit pas la fenêtre), lancée telle quelle.
                texte(&crate::ui::commande_affichable(c))
            );
        }
        script += "if ($resultats) { $resultats.WriteLine($(if ($echecs -gt $avant) { 'echec' } else { 'ok' })) }\n";
    }
    if let Sortie::Tube = sortie {
        // Le processus élevé dit lui-même « Terminé » et attend Entrée avant de fermer sa console.
        script += "if ($resultats) { $resultats.Dispose() }\nif ($echecs) { exit 1 }\nexit 0";
        return script;
    }
    script += "if ($resultats) { $resultats.Dispose() }\ntry { Stop-Transcript | Out-Null } catch { }\n";
    script += tr!(
        "if ($echecs) { Write-Host ''; Write-Host \"Terminé, avec $echecs étape(s) en échec.\" -ForegroundColor Red; Read-Host 'Appuyez sur Entrée pour fermer'; exit 1 }\n\
               Write-Host ''; Write-Host 'Terminé.' -ForegroundColor Green; Read-Host 'Appuyez sur Entrée pour fermer'; exit 0",
        "if ($echecs) { Write-Host ''; Write-Host \"Finished, with $echecs failed step(s).\" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }\n\
               Write-Host ''; Write-Host 'Finished.' -ForegroundColor Green; Read-Host 'Press Enter to close'; exit 0"
    );
    script
}

/// Code de sortie de la fenêtre administrateur quand le script n'est plus celui que Vanguard a écrit.
pub(super) const SCRIPT_MODIFIE: i32 = 6;
/// Code de sortie quand PowerShell est en mode restreint (stratégie WDAC ou AppLocker) : sans .NET, l'empreinte ne se
/// vérifie pas, et un script modifié serait annoncé à tort.
pub(super) const LANGAGE_RESTREINT: i32 = 7;

/// L'empreinte SHA-256, en hexadécimal majuscule, comme la calcule PowerShell.
pub(super) fn sha256_hex(octets: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut s, o| {
            let _ = write!(s, "{o:02X}");
            s
        })
}

/// Ce que lance la demande d'administrateur, à la place du script lui-même : relire le script une seule fois, en
/// mémoire, vérifier son empreinte, puis exécuter ces octets-là. Le script est dans un dossier que tout programme de ce
/// compte peut modifier, et la demande d'administrateur reste ouverte le temps qu'on la lise : lancé par son chemin
/// (-File), un script remplacé entre-temps tournait avec les droits d'administrateur, derrière une demande qui ne
/// montre que « Windows PowerShell ». L'empreinte voyage dans la ligne de commande, fixée quand la demande est faite.
/// Une seule ligne, en clair et sans guillemet double : la demande d'administrateur la montre (« Plus de détails »),
/// elle passe telle quelle entre guillemets, et reste loin des quelque 2 048 caractères au-delà desquels ShellExecute
/// a été vu tronquer ses paramètres (encodée, elle en faisait 2 750).
pub(super) fn amorce_admin(chemin: &str, empreinte: &str) -> String {
    let chemin = crate::commande::ps_texte(chemin);
    trf!(
        "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {{ Write-Host 'PowerShell en mode restreint : script non vérifiable, rien n''est lancé.' -ForegroundColor Red; Read-Host 'Appuyez sur Entrée pour fermer'; exit {LANGAGE_RESTREINT} }}; \
         $o = $null; try {{ $o = [IO.File]::ReadAllBytes('{chemin}') }} catch {{ }}; \
         $h = if ($null -ne $o) {{ [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($o)).Replace('-', '') }} else {{ '' }}; \
         if ($h -ne '{empreinte}') {{ Write-Host 'Script modifié ou supprimé depuis son écriture : rien n''est lancé.' -ForegroundColor Red; Read-Host 'Appuyez sur Entrée pour fermer'; exit {SCRIPT_MODIFIE} }}; \
         $t = [Text.Encoding]::UTF8.GetString($o); if ($t.Length -and $t[0] -eq [char]0xFEFF) {{ $t = $t.Substring(1) }}; \
         & ([ScriptBlock]::Create($t))",
        "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {{ Write-Host 'PowerShell in restricted mode: script cannot be verified, nothing is run.' -ForegroundColor Red; Read-Host 'Press Enter to close'; exit {LANGAGE_RESTREINT} }}; \
         $o = $null; try {{ $o = [IO.File]::ReadAllBytes('{chemin}') }} catch {{ }}; \
         $h = if ($null -ne $o) {{ [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($o)).Replace('-', '') }} else {{ '' }}; \
         if ($h -ne '{empreinte}') {{ Write-Host 'Script modified or deleted since it was written: nothing is run.' -ForegroundColor Red; Read-Host 'Press Enter to close'; exit {SCRIPT_MODIFIE} }}; \
         $t = [Text.Encoding]::UTF8.GetString($o); if ($t.Length -and $t[0] -eq [char]0xFEFF) {{ $t = $t.Substring(1) }}; \
         & ([ScriptBlock]::Create($t))"
    )
}

/// Un script de correction écrit, prêt à lancer : son chemin, le fichier où il répond (fenêtre PowerShell de Wine
/// seulement), son empreinte.
struct Script {
    chemin: std::path::PathBuf,
    resultats: Option<std::path::PathBuf>,
    empreinte: String,
}

/// Écrit le script de ces correctifs (déjà en PowerShell) : en clair, dans un fichier .ps1 dont le chemin est
/// affiché, qu'on peut lire avant d'accepter la demande d'administrateur et qui reste comme trace. `None` : il ne
/// s'écrit pas (dit). `fichier` : il répond par un fichier `.resultats` (Wine) ; sinon par le tube du processus élevé.
fn ecrire_script(correctifs: &[Vec<String>], fichier: bool) -> Option<Script> {
    static SUITE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let dossier = crate::socle::dossier_local().join("corrections");
    // Deux scripts dans la même seconde (une liste mêlée en plusieurs morceaux) ne s'écrasent pas.
    let n = SUITE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nom = format!("correction-{}-{n}", chrono::Local::now().format("%Y%m%d-%H%M%S"));
    let chemin = dossier.join(format!("{nom}.ps1"));
    // La fenêtre PowerShell de Wine est un autre processus : elle répond par ce fichier, une ligne par correctif.
    let resultats = fichier.then(|| dossier.join(format!("{nom}.resultats")));
    // Le nom dans l'en-tête : deux scripts d'une même liste n'ont jamais la même empreinte (le processus élevé refuse
    // une empreinte qui revient).
    let entete = trf!(
        "# Correction proposée par Vanguard {} le {} ({}).\r\n# Ce script n'est lancé qu'après votre accord (demande d'administrateur).\r\n\r\n",
        "# Fix proposed by Vanguard {} on {} ({}).\r\n# This script only runs after your consent (administrator prompt).\r\n\r\n",
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format(tr!("%d/%m/%Y à %H:%M", "%Y-%m-%d %H:%M")),
        nom
    );
    // BOM : sans lui, Windows PowerShell 5.1 lit le fichier en ANSI et casse les accents.
    let resultats_texte = resultats.as_ref().map(|r| r.display().to_string());
    let sortie = resultats_texte.as_deref().map_or(Sortie::Tube, Sortie::Fichier);
    let script = script_admin(correctifs, sortie);
    let contenu = format!("\u{feff}{entete}{}\r\n", script.replace('\n', "\r\n"));
    let empreinte = sha256_hex(contenu.as_bytes());
    if std::fs::create_dir_all(&dossier)
        .and_then(|()| std::fs::write(&chemin, &contenu))
        .is_err()
    {
        trp!(
            "    Impossible d'écrire le script de correction dans {}",
            "    Could not write the fix script to {}",
            dossier.display()
        );
        return None;
    }
    if let Some(r) = &resultats {
        let _ = std::fs::remove_file(r);
    }
    trp!(
        "    Script de correction (lisible) : {}",
        "    Fix script (readable): {}",
        chemin.display()
    );
    Some(Script {
        chemin,
        resultats,
        empreinte,
    })
}

/// Ce que dit le code de sortie de la fenêtre qui a lancé le script, quand il dit quelque chose.
fn dire_code(code: Option<i32>) {
    if code == Some(crate::reparer::SANS_POINT_ARRETE) {
        trp!(
            "    Pas de point de restauration : arrêté à votre demande, rien n'a changé.",
            "    No restore point: stopped as you asked, nothing was changed."
        );
    }
    if code == Some(SCRIPT_MODIFIE) {
        trp!(
            "    ✖ Le script de correction a été modifié ou supprimé après son écriture : rien n'a été lancé avec les droits d'administrateur. Un autre programme y a touché : lancez une analyse antivirus.",
            "    ✖ The fix script was modified or deleted after being written: nothing was run with administrator rights. Another program touched it: run an antivirus scan."
        );
    }
    if code == Some(LANGAGE_RESTREINT) {
        trp!(
            "    PowerShell est en mode restreint sur ce PC (stratégie de sécurité) : Vanguard ne peut pas y vérifier son script, rien n'a été lancé.",
            "    PowerShell is in restricted mode on this PC (security policy): Vanguard cannot verify its script there, nothing was run."
        );
    }
}

/// La réussite de chaque correctif d'un script de la fenêtre PowerShell (Wine) : tous, s'il a fini sans échec ; sinon
/// ceux dont la ligne « ok » est dans son fichier de résultats (demande refusée, point de restauration refusé, fenêtre
/// fermée en route : un correctif sans sa ligne « ok » n'a pas été fait, ou pas en entier).
fn resultats_du_script(s: &Script, nombre: usize, reussi: bool) -> Vec<bool> {
    let lus = s
        .resultats
        .as_ref()
        .and_then(|r| {
            let lus = crate::socle::lire_texte_ordinaire(r, 1 << 20).ok();
            let _ = std::fs::remove_file(r);
            lus
        })
        .unwrap_or_default();
    if reussi {
        return vec![true; nombre];
    }
    let mut etats: Vec<bool> = lus.lines().map(|l| l.trim() == "ok").collect();
    etats.resize(nombre, false);
    etats
}

/// Lance des correctifs (chacun sa liste de commandes) dans une seule fenêtre PowerShell administrateur et dit
/// lesquels ont réussi. Sous Wine seulement, où l'élévation n'existe pas (aucune demande d'administrateur, un seul
/// compte) : partout ailleurs, tout passe par Vanguard administrateur (`admin_mele`), sans jamais revenir ici, même
/// quand il ne peut pas se lancer (un repli qu'on pourrait provoquer rouvrirait ce chemin, que le compte peut piéger).
pub fn powershell_admin_chacune(correctifs: &[Vec<String>]) -> Vec<bool> {
    let echec = vec![false; correctifs.len()];
    // Une correction native (« vanguard:… ») ou un ordre mêlé à du PowerShell passe par le script, sous sa forme
    // PowerShell.
    let correctifs = &corrections::en_powershell(correctifs);
    let Some(script) = ecrire_script(correctifs, true) else {
        return echec;
    };
    let amorce = crate::commande::ps_texte(&amorce_admin(&script.chemin.display().to_string(), &script.empreinte));
    // Demande d'administrateur refusée : Start-Process échoue et $p reste vide. Sans ce test, l'appel de méthode
    // sur $null était sauté et « exit $p.ExitCode » devenait « exit 0 » : la correction s'affichait « fait ».
    // Attente sans limite : la fenêtre est visible et attend Entrée, un délai compterait aussi le temps de lecture.
    let lanceur = trf!(
        "$q = [char]34; \
         $p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',($q + '{amorce}' + $q); \
         if (-not $p) {{ Write-Host 'Demande d''administrateur refusée : rien n''a été modifié.'; exit 3 }}; \
         $p.WaitForExit(); \
         if ($null -eq $p.ExitCode) {{ exit 4 }}; exit $p.ExitCode",
        "$q = [char]34; \
         $p = Start-Process powershell -Verb RunAs -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',($q + '{amorce}' + $q); \
         if (-not $p) {{ Write-Host 'Administrator prompt refused: nothing was changed.'; exit 3 }}; \
         $p.WaitForExit(); \
         if ($null -eq $p.ExitCode) {{ exit 4 }}; exit $p.ExitCode"
    );
    let statut = powershell().args(["-NoProfile", "-Command", &lanceur]).status();
    let reussi = statut.as_ref().is_ok_and(std::process::ExitStatus::success);
    let code = statut.as_ref().ok().and_then(std::process::ExitStatus::code);
    // 3 : demande d'administrateur refusée ; SANS_POINT_ARRETE : point refusé, le script s'arrête avant tout le reste.
    if matches!(code, Some(3 | crate::reparer::SANS_POINT_ARRETE)) {
        crate::machine::noter_inacheve(crate::machine::Inacheve::ArreteeADemande);
    }
    dire_code(code);
    resultats_du_script(&script, correctifs.len(), reussi)
}

/// Une liste de correctifs, en UNE seule demande UAC qui nomme Vanguard : les gestes natifs (corrections de la table,
/// ordres du blocage, programmes fixes) vont tels quels au processus élevé ; chaque suite de commandes PowerShell
/// devient un script (sous sa forme PowerShell), que le processus élevé lit en mémoire, vérifie par son empreinte et
/// lance lui-même. La découpe suit les lignes, pas les correctifs (`gestes::decouper`) : le point de restauration en
/// tête d'un correctif est toujours un geste à lui, que le processus élevé fait d'abord et dont l'échec arrête tout.
/// L'ordre de la liste est gardé. `None` : rien n'a été fait (script impossible à écrire, liste refusée, relance
/// impossible), et c'est dit ; aucune autre demande d'administrateur ne prend le relais.
pub(crate) fn admin_mele(correctifs: &[Vec<String>]) -> Option<(Vec<bool>, Vec<Vec<String>>)> {
    let morceaux = crate::machine::gestes::decouper(correctifs, corrections::native);
    let lignes = lignes_pour_eleve(correctifs, &morceaux)?;
    // Rien à envoyer : seulement quand chaque correctif est vide (`decouper` place toute ligne). Vrai pour un
    // correctif vide seulement, jamais d'office.
    if lignes.is_empty() {
        return Some(recomposer(correctifs, &morceaux, Vec::new()));
    }
    let reponses = eleve::appliquer(&lignes)?;
    // Tout arrêté à la demande de la personne (point refusé en tête, accord ou demande d'administrateur refusés) :
    // rien n'a été fait, et ce n'est pas un échec.
    crate::machine::noter_inacheve(inacheve(&reponses));
    Some(recomposer(correctifs, &morceaux, reponses))
}

/// Les lignes que reçoit le processus élevé pour ces morceaux : les gestes natifs tels quels, chaque suite PowerShell
/// écrite en script et remplacée par sa ligne `vanguard:script`. `None` : un script ne s'écrit pas, ou une ligne de
/// Vanguard mal formée irait dans un script (dit).
fn lignes_pour_eleve(correctifs: &[Vec<String>], morceaux: &[crate::machine::gestes::Morceau]) -> Option<Vec<String>> {
    use crate::machine::gestes::{self, Morceau};
    // Une place hors de `correctifs` ne peut pas venir de `decouper` (elle énumère cette liste) : sautée, elle laisse
    // le correctif en échec, jamais en réussite.
    let ligne = |i: usize, j: usize| correctifs.get(i).and_then(|c| c.get(j));
    // Une ligne de Vanguard que `native` n'a pas reconnue (forme fausse, identifiant inconnu) finirait dans un script,
    // où PowerShell la prendrait pour une commande inconnue, après la demande d'administrateur : toute la liste est
    // refusée avant, et avant d'écrire le moindre script.
    let egaree = morceaux.iter().any(|m| match m {
        Morceau::Script(suite) => suite
            .iter()
            .any(|(i, js)| js.iter().filter_map(|&j| ligne(*i, j)).any(|l| marque_de_vanguard(l))),
        Morceau::Natif(_) => false,
    });
    if egaree {
        trp!(
            "    Vanguard a refusé sa propre liste de corrections avant de demander les droits d'administrateur : rien n'a été fait. Mettez Vanguard à jour ; si cela revient, signalez-le (le journal des erreurs en garde une trace).",
            "    Vanguard refused its own list of fixes before asking for administrator rights: nothing was done. Update Vanguard; if it happens again, report it (the error log keeps a trace)."
        );
        crate::journal::erreur(
            "Vanguard administrateur",
            "liste refusée avant la demande (ligne vanguard: mal formée)",
        );
        return None;
    }
    let mut lignes = Vec::new();
    for m in morceaux {
        match m {
            Morceau::Natif(places) => {
                lignes.extend(places.iter().filter_map(|&(i, j)| ligne(i, j)).cloned());
            }
            Morceau::Script(suite) => {
                let commandes: Vec<Vec<String>> = suite
                    .iter()
                    .map(|(i, js)| js.iter().filter_map(|&j| ligne(*i, j)).cloned().collect())
                    .collect();
                let Some(script) = ecrire_script(&corrections::en_powershell(&commandes), false) else {
                    trp!("    Rien n'a été modifié.", "    Nothing was changed.");
                    return None;
                };
                lignes.push(gestes::ligne_script(
                    &script.empreinte,
                    &script.chemin.display().to_string(),
                ));
            }
        }
    }
    Some(lignes)
}

/// Une ligne qui se donne pour une ligne de Vanguard (`vanguard:…`, espaces en tête et casse comprises).
fn marque_de_vanguard(ligne: &str) -> bool {
    const MARQUE: &str = "vanguard:";
    ligne
        .trim_start()
        .get(..MARQUE.len())
        .is_some_and(|debut| debut.eq_ignore_ascii_case(MARQUE))
}

/// Pour les tests des listes réelles (réparations, jeux) : ces correctifs, séparés comme par `lancer_chacune` (les
/// gestes du compte restent dans Vanguard non élevé, `compte::lancer`), puis leur part élevée découpée et écrite comme
/// par `admin_mele`, sont acceptés tels quels par la validation du processus élevé, celle qui les refuserait avant la
/// demande d'administrateur (une ligne de Vanguard mal formée comprise : `lignes_pour_eleve` la refuse). Il faut au
/// moins une ligne, élevée ou du compte.
#[cfg(test)]
pub(crate) fn accepte_par_le_processus_eleve(correctifs: &[Vec<String>]) -> bool {
    use crate::machine::gestes::{FaitCompte, PassageEleve, lancer_separe};
    let mut accepte = true;
    let fait = lancer_separe(
        correctifs,
        |l| l == corrections::POINT,
        |envoyes| {
            let morceaux = crate::machine::gestes::decouper(envoyes, corrections::native);
            accepte =
                lignes_pour_eleve(envoyes, &morceaux).is_some_and(|l| !l.is_empty() && eleve::valider(&l).is_some());
            Some(PassageEleve {
                resultats: vec![true; envoyes.len()],
                notes: envoyes.to_vec(),
                arrete: false,
            })
        },
        |_| FaitCompte {
            reussi: true,
            rien: false,
            avant: None,
        },
    );
    fait.is_some() && accepte && correctifs.iter().any(|c| !c.is_empty())
}

/// Ce qui n'est pas fait l'est-il seulement par choix ou en attente d'un redémarrage ? Rien fait, et chaque réponse
/// dit « arrêté » (une liste vide, non) : arrêtée à la demande ; aucun vrai échec, et au moins une étape à finir au
/// redémarrage : à finir au redémarrage ; sinon rien de plus qu'un échec ordinaire.
fn inacheve(reponses: &[eleve::Reponse]) -> crate::machine::Inacheve {
    use crate::machine::Inacheve;
    if !reponses.is_empty() && reponses.iter().all(|r| r.arretee) {
        return Inacheve::ArreteeADemande;
    }
    let sans_vrai_echec = reponses.iter().all(|r| r.reussi || r.arretee || r.au_redemarrage);
    if sans_vrai_echec && reponses.iter().any(|r| r.au_redemarrage) {
        return Inacheve::AuRedemarrage;
    }
    Inacheve::Non
}

/// Les résultats de chaque correctif, et ses lignes annotées (valeur d'avant, précision), à partir des réponses du
/// processus élevé, dans l'ordre des morceaux. Un correctif réussit seulement si chacun de ses morceaux a réussi
/// (pour un script, son propre « ok » dans le tube), ou s'il est vide ; une réponse qui manque est un échec, comme
/// un correctif qu'aucun morceau ne couvre. Une ligne déjà bonne (« ok rien=… ») est retirée des lignes notées : rien
/// n'a changé ; un correctif dont il ne reste que le point de restauration n'a plus de ligne à noter.
fn recomposer(
    correctifs: &[Vec<String>],
    morceaux: &[crate::machine::gestes::Morceau],
    reponses: Vec<eleve::Reponse>,
) -> (Vec<bool>, Vec<Vec<String>>) {
    use crate::machine::gestes::Morceau;
    let mut reponses = reponses.into_iter();
    let mut resultats = vec![true; correctifs.len()];
    let mut couverts = vec![false; correctifs.len()];
    let mut notes = correctifs.to_vec();
    let mut deja_bons: Vec<Vec<usize>> = vec![Vec::new(); correctifs.len()];
    let mut echec = |i: usize| {
        if let Some(r) = resultats.get_mut(i) {
            *r = false;
        }
    };
    for m in morceaux {
        match m {
            Morceau::Natif(places) => {
                for &(i, j) in places {
                    if let Some(c) = couverts.get_mut(i) {
                        *c = true;
                    }
                    let r = reponses.next();
                    if !r.as_ref().is_some_and(|r| r.reussi) {
                        echec(i);
                    }
                    if r.as_ref().is_some_and(|r| r.reussi && r.rien) {
                        if let Some(d) = deja_bons.get_mut(i) {
                            d.push(j);
                        }
                        continue;
                    }
                    if let Some(note) = notes.get_mut(i).and_then(|n| n.get_mut(j)) {
                        match r.map(|r| (r.avant, r.note)) {
                            Some((Some(avant), _)) => *note = format!("{note} (avant : {avant})"),
                            Some((None, Some(n))) => *note = format!("{note} ({n})"),
                            _ => {}
                        }
                    }
                }
            }
            Morceau::Script(suite) => {
                for (i, _) in suite {
                    if let Some(c) = couverts.get_mut(*i) {
                        *c = true;
                    }
                }
                let r = reponses.next();
                dire_code(r.as_ref().and_then(|r| r.code));
                if r.as_ref().is_some_and(|r| r.reussi) {
                    continue;
                }
                // Un correctif sans son « ok » dans le tube n'a pas été fait, ou pas en entier.
                let mut etats = r.and_then(|r| r.etats).unwrap_or_default();
                etats.resize(suite.len(), false);
                for ((i, _), ok) in suite.iter().zip(etats) {
                    if !ok {
                        echec(*i);
                    }
                }
            }
        }
    }
    for (i, (c, couvert)) in correctifs.iter().zip(couverts).enumerate() {
        if !c.is_empty() && !couvert {
            echec(i);
        }
    }
    for (n, d) in notes.iter_mut().zip(deja_bons) {
        if d.is_empty() {
            continue;
        }
        let mut j = 0;
        n.retain(|_| {
            j += 1;
            !d.contains(&(j - 1))
        });
        if n.iter().all(|l| l.starts_with(corrections::POINT)) {
            n.clear();
        }
    }
    (resultats, notes)
}

/// État de chaque profil du pare-feu, lu dans le registre (les valeurs que rend Get-NetFirewallProfile, sans
/// lancer PowerShell : le pare-feu passe avant toutes les autres vérifications, son attente retardait tout le bilan).
/// Une stratégie de groupe passe avant le réglage local, comme pour Windows. Un profil illisible n'est pas listé.
pub(crate) fn profils_pare_feu() -> Vec<(&'static str, bool)> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    [
        ("Domain", "DomainProfile"),
        ("Private", "StandardProfile"),
        ("Public", "PublicProfile"),
    ]
    .into_iter()
    .filter_map(|(nom, cle)| {
        let strategie = registre::<u32>(
            HKEY_LOCAL_MACHINE,
            &format!(r"SOFTWARE\Policies\Microsoft\WindowsFirewall\{cle}"),
            "EnableFirewall",
        );
        let local = registre::<u32>(
            HKEY_LOCAL_MACHINE,
            &format!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{cle}"),
            "EnableFirewall",
        );
        strategie.or(local).map(|v| (nom, v != 0))
    })
    .collect()
}

fn pare_feu() -> Constat {
    let profils = profils_pare_feu();
    let off: Vec<&str> = profils.iter().filter(|(_, actif)| !actif).map(|(n, _)| *n).collect();
    match (profils.is_empty(), off.join(", ")) {
        // Rien de lu n'est rien de vérifié : sans constat vérifié du pare-feu, le bilan ne donne pas de note
        // (`Audit::fiable`), comme sous Linux et macOS.
        (true, _) => impossible(
            "Pare-feu",
            tr!(
                "aucun profil de pare-feu lu (pare-feu tiers ?)",
                "no firewall profile read (third-party firewall?)"
            ),
        ),
        (false, off) if off.is_empty() => ok(
            "Pare-feu",
            tr!(
                "Pare-feu Windows actif sur tous les profils.",
                "Windows firewall on for every profile."
            ),
        ),
        (false, off) => alerte(
            "Pare-feu",
            Niveau::Eleve,
            trf!("Pare-feu désactivé pour : {off}.", "Firewall off for: {off}."),
        )
        .corriger(
            tr!(
                "Réactiver le pare-feu Windows sur tous les profils",
                "Turn the Windows firewall back on for every profile"
            ),
            &[&crate::machine::gestes::ligne_pare_feu_actif()],
        )
        .protection(),
    }
}

/// L'état de Defender par WMI (les classes que lisent Get-MpComputerStatus et Get-MpPreference), dans le JSON que
/// rendait le script : `None` si Defender ne répond pas par WMI (absent, remplacé par un antivirus tiers, Wine).
fn defender_par_wmi() -> Option<serde_json::Value> {
    const DEFENDER: &str = r"root\Microsoft\Windows\Defender";
    let champs = [
        "AntivirusEnabled",
        "RealTimeProtectionEnabled",
        "AntivirusSignatureAge",
        "IsTamperProtected",
    ];
    let lignes = wmi::requete(DEFENDER, "MSFT_MpComputerStatus", "", &champs)?;
    let etat = lignes.first()?;
    let mut v = serde_json::Map::new();
    for champ in champs {
        v.insert(champ.to_string(), etat[champ].json());
    }
    // Comme le `try { … } catch { $null }` du script : la préférence peut manquer sans que l'état soit faux.
    let cloud = wmi::requete(DEFENDER, "MSFT_MpPreference", "", &["MAPSReporting"])
        .and_then(|l| l.first().and_then(|p| p["MAPSReporting"].entier()));
    v.insert("MAPSReporting".into(), cloud.into());
    Some(v.into())
}

/// Les antivirus inscrits au Centre de sécurité, par WMI : `None` sans Centre de sécurité (Windows Server, Wine).
fn antivirus_inscrits() -> Option<String> {
    let lignes = wmi::requete(r"root\SecurityCenter2", "AntivirusProduct", "", &["displayName"])?;
    Some(
        lignes
            .iter()
            .filter_map(|l| l["displayName"].texte())
            .collect::<Vec<_>>()
            .join(", "),
    )
}

/// Microsoft Defender est-il l'antivirus de cet ordinateur ? D'après les antivirus inscrits au Centre de sécurité ;
/// rien sans Centre de sécurité ou sans antivirus inscrit (Windows Server, Wine) : on ne le sait pas.
pub(crate) fn defender_est_l_antivirus() -> Option<bool> {
    let inscrits = antivirus_inscrits()?;
    if inscrits.trim().is_empty() {
        return None;
    }
    Some(inscrits.to_lowercase().contains("defender"))
}

fn antivirus() -> Vec<Constat> {
    // WMI d'abord (quelques millisecondes) ; sinon un seul PowerShell (près d'une demi-seconde par lancement) pour
    // l'état de Defender et sa protection dans le cloud ensemble. Get-MpPreference peut manquer sans que l'état
    // soit faux.
    let json = defender_par_wmi().map(|v| v.to_string()).or_else(|| {
        ps(
            "$s = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge,IsTamperProtected; \
             $s | Add-Member -NotePropertyName MAPSReporting -NotePropertyValue $(try { [int](Get-MpPreference).MAPSReporting } catch { $null }); \
             $s | ConvertTo-Json",
        )
    });
    let Some(json) = json else {
        // Defender ne répond pas : le Centre de sécurité connaît-il un autre antivirus ? Sinon, PowerShell
        // lui-même répond-il ? Demandé seulement maintenant.
        let tiers = if let Some(tiers) = antivirus_inscrits() {
            tiers
        } else {
            if ps("1").is_none() {
                return vec![illisible("Antivirus")];
            }
            ps("(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct).displayName -join ', '")
                .unwrap_or_default()
        };
        return vec![if tiers.is_empty() {
            alerte(
                "Antivirus",
                Niveau::Critique,
                tr!("Aucun antivirus détecté.", "No antivirus detected."),
            )
            .manuel(
                tr!(
                    "Ouvrir Sécurité Windows et réactiver Microsoft Defender",
                    "Open Windows Security and turn Microsoft Defender back on"
                ),
                &["Start-Process windowsdefender:"],
            )
        } else {
            ok(
                "Antivirus",
                trf!("Antivirus tiers : {tiers}.", "Third-party antivirus: {tiers}."),
            )
        }];
    };
    let v: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();
    let champ = |cle: &str| v.get(cle).unwrap_or(&serde_json::Value::Null);
    if !champ("RealTimeProtectionEnabled").is_boolean() {
        return vec![illisible("Antivirus")];
    }
    let mut c = Vec::new();
    if *champ("RealTimeProtectionEnabled") == false || *champ("AntivirusEnabled") == false {
        c.push(
            alerte(
                "Antivirus",
                Niveau::Critique,
                tr!(
                    "Protection en temps réel de Defender désactivée.",
                    "Defender real-time protection is off."
                ),
            )
            .corriger(
                tr!(
                    "Réactiver la protection en temps réel",
                    "Turn real-time protection back on"
                ),
                &[gestes::Acte::Defender(gestes::ReglageDefender::TempsReel, gestes::ValeurDefender::Actif).ligne()],
            )
            .protection(),
        );
    } else {
        c.push(ok(
            "Antivirus",
            tr!(
                "Microsoft Defender actif, protection en temps réel.",
                "Microsoft Defender on, real-time protection."
            ),
        ));
    }
    // Un âge absent ou illisible n'est pas « à jour » : la vérification est dite impossible.
    c.push(match champ("AntivirusSignatureAge").as_u64() {
        Some(age) => signatures(age),
        None => impossible(
            "Signatures",
            tr!("âge des signatures illisible", "signature age unreadable"),
        ),
    });
    c.extend(juger_cloud(
        champ("MAPSReporting").as_u64().map(|n| n.to_string()).as_deref(),
    ));
    if *champ("IsTamperProtected") == false {
        c.push(alerte("Antivirus", Niveau::Moyen, tr!("Protection contre les falsifications désactivée : un malware peut couper Defender.", "Tamper protection is off: malware can turn Defender off."))
            .manuel(tr!("Sécurité Windows > Protection contre les virus > Gérer les paramètres > Protection contre les falsifications", "Windows Security > Virus protection > Manage settings > Tamper protection"), &["Start-Process windowsdefender://threatsettings"]));
    }
    c
}

/// Protection dans le cloud de Defender (MAPSReporting : 0 coupée, 1 ou 2 active). Coupée, Defender ne reconnaît
/// que les menaces de ses signatures : un programme malveillant tout neuf passe, alors que le cloud le juge en
/// quelques secondes. Rien à dire si la valeur ne se lit pas.
fn juger_cloud(valeur: Option<&str>) -> Option<Constat> {
    (valeur.map(str::trim) == Some("0")).then(|| {
        alerte(
            "Antivirus",
            Niveau::Moyen,
            tr!(
                "La protection dans le cloud de Defender est coupée : un programme malveillant tout neuf, pas encore dans ses signatures, passe sans être reconnu.",
                "Defender's cloud protection is off: brand-new malware, not yet in its signatures, goes through unrecognized."
            ),
        )
        .corriger(
            tr!(
                "Rallumer la protection dans le cloud (le réglage de Windows)",
                "Turn cloud protection back on (Windows' setting)"
            ),
            &[gestes::Acte::Defender(gestes::ReglageDefender::Maps, gestes::ValeurDefender::Avance).ligne()],
        )
        .protection()
    })
}

/// Le serveur SMBv1 est-il actif ? Lu dans le registre, comme Get-SmbServerConfiguration le lit (près de 2 s de
/// PowerShell de moins) : sans son pilote (service « srv », absent quand la fonctionnalité n'est pas installée, le cas
/// de Windows 11), il ne peut pas l'être ; sinon, la valeur SMB1 des paramètres du serveur (absente : actif).
fn smb1_actif() -> Option<bool> {
    let services = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(CLE_SERVICES)
        .ok()?;
    if services.open_subkey("srv").is_err() {
        return Some(false);
    }
    let valeur: Option<u32> = services
        .open_subkey(r"LanmanServer\Parameters")
        .ok()
        .and_then(|p| p.get_value("SMB1").ok());
    Some(valeur != Some(0))
}

fn smb1() -> Constat {
    let Some(actif) = smb1_actif() else {
        return illisible("SMBv1");
    };
    if actif {
        alerte(
            "SMBv1",
            Niveau::Critique,
            tr!(
                "SMBv1 activé (exploité par WannaCry / NotPetya).",
                "SMBv1 on (exploited by WannaCry / NotPetya)."
            ),
        )
        .corriger(
            tr!("Désactiver SMBv1", "Turn SMBv1 off"),
            &[corrections::id("smb1-serveur-coupe")],
        )
    } else {
        ok("SMBv1", tr!("SMBv1 désactivé.", "SMBv1 off."))
    }
}

pub(super) fn bureau_distance() -> Constat {
    let terminal = r"System\CurrentControlSet\Control\Terminal Server";
    // La stratégie de groupe l'emporte sur le réglage local, comme pour le pare-feu : imposée, elle décide, et une
    // correction du réglage local ne servirait à rien.
    let strategie = registre::<u32>(
        winreg::enums::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "fDenyTSConnections",
    );
    let impose = strategie == Some(0);
    let local = registre::<u32>(winreg::enums::HKEY_LOCAL_MACHINE, terminal, "fDenyTSConnections");
    let actif = match strategie.or(local) {
        Some(0) => true,
        Some(1) => false,
        _ => return registre_illisible("Bureau à distance"),
    };
    if !actif {
        return ok(
            "Bureau à distance",
            tr!("Bureau à distance (RDP) désactivé.", "Remote Desktop (RDP) off."),
        );
    }
    let nla = registre::<u32>(
        winreg::enums::HKEY_LOCAL_MACHINE,
        &format!(r"{terminal}\WinStations\RDP-Tcp"),
        "UserAuthentication",
    ) == Some(1);
    // Session ouverte PAR le Bureau à distance (SESSIONNAME = RDP-Tcp#…) : le couper couperait l'utilisateur
    // lui-même. Jamais en correction automatique dans ce cas.
    if session_a_distance() {
        alerte("Bureau à distance", Niveau::Moyen, tr!("RDP activé ; vous êtes connecté par lui en ce moment.", "RDP on; you are connected through it right now.")).manuel(
            tr!("Ne pas le couper d'ici (vous perdriez la connexion). S'il n'est pas utile, le désactiver depuis l'écran de l'ordinateur : Paramètres > Système > Bureau à distance", "Do not turn it off from here (you would lose the connection). If it is not needed, turn it off from the computer's own screen: Settings > System > Remote Desktop"),
            &[],
        )
    } else if impose {
        alerte(
            "Bureau à distance",
            if nla { Niveau::Moyen } else { Niveau::Eleve },
            tr!(
                "RDP activé par une stratégie de groupe. Très attaqué s'il est exposé.",
                "RDP turned on by a group policy. Heavily attacked if exposed."
            ),
        )
        .manuel(
            tr!(
                "S'il n'est pas utile : gpedit.msc › Configuration ordinateur › Modèles d'administration › Composants Windows › Services Bureau à distance › Hôte de la session Bureau à distance › Connexions › « Autoriser les utilisateurs à se connecter à distance » (ou l'administrateur du domaine)",
                "If it is not needed: gpedit.msc › Computer Configuration › Administrative Templates › Windows Components › Remote Desktop Services › Remote Desktop Session Host › Connections › “Allow users to connect remotely” (or the domain administrator)"
            ),
            &[],
        )
    } else if nla {
        alerte(
            "Bureau à distance",
            Niveau::Moyen,
            tr!(
                "RDP activé (avec NLA). Très attaqué s'il est exposé.",
                "RDP on (with NLA). Heavily attacked if exposed."
            ),
        )
        .corriger(
            tr!(
                "Désactiver le Bureau à distance si vous ne l'utilisez pas",
                "Turn Remote Desktop off if you do not use it"
            ),
            &[corrections::id("rdp-coupe")],
        )
    } else {
        alerte(
            "Bureau à distance",
            Niveau::Eleve,
            tr!(
                "RDP activé SANS authentification au niveau réseau (NLA).",
                "RDP on WITHOUT Network Level Authentication (NLA)."
            ),
        )
        .corriger(
            tr!("Exiger NLA pour le Bureau à distance", "Require NLA for Remote Desktop"),
            &[&corrections::id("rdp-nla")],
        )
    }
}

// FFI de user32 : GetSystemMetrics.
#[allow(unsafe_code)]
#[link(name = "user32")]
unsafe extern "system" {
    fn GetSystemMetrics(index: i32) -> i32;
}

/// Cette session Windows est-elle affichée à travers le Bureau à distance, en ce moment ?
/// On interroge Windows directement : la variable SESSIONNAME est figée à l'ouverture de session et
/// reste « Console » quand le Bureau à distance reprend une session ouverte sur l'écran (vu en test réel).
// FFI de user32 : GetSystemMetrics.
#[allow(unsafe_code)]
pub fn session_a_distance() -> bool {
    const SM_REMOTESESSION: i32 = 0x1000;
    // SAFETY: GetSystemMetrics n'a ni pointeur ni effet de bord.
    let distante = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;
    // SESSIONNAME vient de l'environnement, que le compte peut poser (HKCU\Environment) : il ne fait qu'ajouter des
    // cas « à distance ». Forgé, il donne au pire un refus de plus (rdp-coupe refusé, dit), jamais une coupure.
    distante || std::env::var("SESSIONNAME").is_ok_and(|s| s.to_ascii_uppercase().starts_with("RDP-"))
}

fn uac() -> Constat {
    let cle = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    let lire = |v: &str| registre::<u32>(winreg::enums::HKEY_LOCAL_MACHINE, cle, v).map(|n| n.to_string());
    juger_uac(
        lire("EnableLUA").as_deref(),
        lire("ConsentPromptBehaviorAdmin").as_deref(),
    )
    .unwrap_or_else(|| registre_illisible("UAC"))
}

/// L'UAC, d'après EnableLUA et ConsentPromptBehaviorAdmin (vide quand absent : 5, la valeur de Windows). `None` si
/// EnableLUA ne se lit pas. À 0, ConsentPromptBehaviorAdmin élève sans rien demander : un programme lancé par un
/// administrateur prend les droits admin en silence, comme sans UAC.
fn juger_uac(lua: Option<&str>, consentement: Option<&str>) -> Option<Constat> {
    let lua = lua.map(str::trim).filter(|v| matches!(*v, "0" | "1"))?;
    if lua == "0" {
        return Some(
            alerte(
                "UAC",
                Niveau::Eleve,
                tr!(
                    "Contrôle de compte d'utilisateur (UAC) désactivé : tout programme a les droits admin.",
                    "User Account Control (UAC) is off: every program has admin rights."
                ),
            )
            .corriger(
                tr!(
                    "Réactiver l'UAC (effectif après redémarrage)",
                    "Turn UAC back on (effective after a restart)"
                ),
                &[&corrections::id("uac-active")],
            ),
        );
    }
    if consentement.map(str::trim) == Some("0") {
        return Some(
            alerte(
                "UAC",
                Niveau::Eleve,
                tr!(
                    "L'UAC ne demande plus rien aux administrateurs : un programme lancé depuis votre compte prend \
                     les droits admin en silence.",
                    "UAC no longer asks administrators anything: a program started from your account silently \
                     gets admin rights."
                ),
            )
            .corriger(
                tr!(
                    "Remettre la demande de l'UAC (le réglage de Windows)",
                    "Bring back the UAC prompt (the Windows setting)"
                ),
                &[&corrections::id("uac-demande")],
            ),
        );
    }
    Some(ok(
        "UAC",
        tr!("Contrôle de compte d'utilisateur actif.", "User Account Control on."),
    ))
}

fn mises_a_jour() -> Constat {
    // WMI d'abord (la classe que lit Get-HotFix), PowerShell en secours.
    let jours = correctifs::installes()
        .and_then(|c| c.first().map(|d| (chrono::Local::now().date_naive() - d.date).num_days()))
        .or_else(|| {
            ps("((Get-Date) - (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn).Days")
                .and_then(|j| j.parse::<i64>().ok())
        });
    match jours {
        Some(j) if j > 45 => alerte(
            "Mises à jour",
            Niveau::Eleve,
            trf!(
                "Dernière mise à jour Windows il y a {j} jours.",
                "Last Windows update {j} days ago."
            ),
        )
        .manuel(
            tr!(
                "Ouvrir Windows Update et installer les mises à jour",
                "Open Windows Update and install the updates"
            ),
            &["Start-Process ms-settings:windowsupdate"],
        ),
        Some(j) => ok(
            "Mises à jour",
            trf!(
                "Dernière mise à jour Windows il y a {j} jours.",
                "Last Windows update {j} days ago."
            ),
        ),
        None => impossible(
            "Mises à jour",
            tr!(
                "historique Windows Update illisible",
                "Windows Update history unreadable"
            ),
        ),
    }
}

/// System.Volume.BitLockerProtection de C:, la propriété que montre l'Explorateur, lue par son magasin de
/// propriétés : sans droits administrateur, contrairement à Get-BitLockerVolume et à Win32_EncryptableVolume. Vide
/// si le volume n'en a pas, comme ExtendedProperty dans PowerShell.
// FFI de COM (crate windows) : les propriétés du volume, pour BitLocker.
#[allow(unsafe_code)]
fn protection_bitlocker() -> Option<String> {
    use windows::Win32::Foundation::PROPERTYKEY;
    use windows::Win32::System::Com::StructuredStorage::{PropVariantClear, PropVariantToUInt32};
    use windows::Win32::System::Variant::VT_EMPTY;
    use windows::Win32::UI::Shell::PropertiesSystem::{
        GPS_DEFAULT, IPropertyStore, PSGetPropertyKeyFromName, SHGetPropertyStoreFromParsingName,
    };
    use windows::core::w;
    wmi::com_sta("BitLocker", "System.Volume.BitLockerProtection", || {
        // SAFETY: COM est initialisé dans ce fil (par `wmi::com_sta`) ; chaînes constantes terminées par un zéro ;
        // le PROPVARIANT rendu par GetValue est à nous et libéré par PropVariantClear.
        unsafe {
            let mut cle = PROPERTYKEY::default();
            PSGetPropertyKeyFromName(w!("System.Volume.BitLockerProtection"), &raw mut cle)?;
            let magasin: IPropertyStore = SHGetPropertyStoreFromParsingName(w!("C:\\"), None, GPS_DEFAULT)?;
            let mut valeur = magasin.GetValue(&raw const cle)?;
            let texte = if valeur.Anonymous.Anonymous.vt == VT_EMPTY {
                Ok(String::new())
            } else {
                PropVariantToUInt32(&raw const valeur).map(|n| n.to_string())
            };
            let _ = PropVariantClear(&raw mut valeur);
            texte
        }
    })
}

fn chiffrement() -> Constat {
    // Lisible sans droits admin, contrairement à Get-BitLockerVolume. PowerShell en secours de la lecture directe.
    juger_bitlocker(
        protection_bitlocker()
            .or_else(|| {
                ps(
                    "(New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')",
                )
            })
            .as_deref(),
    )
}

/// État BitLocker du disque C: (System.Volume.BitLockerProtection) : 1 actif, 3 chiffrement en cours, 6 actif et
/// verrouillé ; 5 suspendu (la clé est posée en clair sur le disque : un voleur lit tout) ; 8 en attente d'activation
/// (chiffrement de l'appareil pas fini : la clé reste en clair tant que sa clé de récupération n'est pas sauvegardée) ;
/// le reste, pas chiffré.
fn juger_bitlocker(etat: Option<&str>) -> Constat {
    match etat.map(str::trim) {
        Some("1" | "3" | "6") => ok(
            "Chiffrement",
            tr!("Disque C: chiffré (BitLocker).", "Disk C: encrypted (BitLocker)."),
        ),
        Some("5") => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!(
                "BitLocker est suspendu sur C: : la clé est posée en clair sur le disque, un voleur lit tout.",
                "BitLocker is suspended on C: the key sits in clear on the disk, a thief reads everything."
            ),
        )
        .corriger(
            tr!(
                "Reprendre BitLocker (une mise à jour du BIOS l'a souvent suspendu et ne l'a pas repris)",
                "Resume BitLocker (a BIOS update often suspended it and did not resume it)"
            ),
            &["Resume-BitLocker -MountPoint 'C:'"],
        )
        .protection(),
        Some("8") => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!(
                "Le chiffrement de C: attend d'être activé : tant que la clé de récupération n'est pas sauvegardée, la clé reste en clair sur le disque.",
                "Encryption of C: is waiting to be turned on: until the recovery key is backed up, the key stays in clear on the disk."
            ),
        )
        .manuel(
            tr!(
                "Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil : finir l'activation (la clé de récupération va dans le compte Microsoft, ou s'imprime)",
                "Settings > Privacy & security > Device encryption: finish turning it on (the recovery key goes to the Microsoft account, or gets printed)"
            ),
            &["Start-Process ms-settings:deviceencryption"],
        ),
        Some(_) => alerte(
            "Chiffrement",
            Niveau::Moyen,
            tr!(
                "Disque C: non chiffré : en cas de vol, les données sont lisibles.",
                "Disk C: not encrypted: if stolen, the data can be read."
            ),
        )
        .manuel(
            tr!(
                "Paramètres > Confidentialité et sécurité > Chiffrement de l'appareil (ou BitLocker sur Pro)",
                "Settings > Privacy & security > Device encryption (or BitLocker on Pro)"
            ),
            &["Start-Process ms-settings:deviceencryption"],
        ),
        None => impossible(
            "Chiffrement",
            tr!("état BitLocker illisible", "BitLocker state unreadable"),
        ),
    }
}

/// Ports TCP en écoute (« adresse|port|programme », une ligne chacun) et ports bloqués par une règle de Vanguard, lus
/// sans PowerShell (tables TCP de Windows, processus, registre). `None` si ni les tables ni netstat ne répondent.
fn ports_tcp_directs(pare_feu_actif: bool) -> Option<(String, Vec<u16>)> {
    let ecoutes = ecoute::ecoutes()?;
    let liste = ecoutes
        .iter()
        .filter(|e| e.tcp)
        .map(|e| format!("{}|{}|{}", e.adresse, e.port, e.nom))
        .collect::<Vec<_>>()
        .join("\n");
    let bloques = if pare_feu_actif {
        ecoute::ports_bloques().unwrap_or_else(ports_bloques_powershell)
    } else {
        Vec::new()
    };
    Some((liste, bloques))
}

/// Ports bloqués par une règle active de Vanguard, demandés à PowerShell quand le registre ne se lit pas.
fn ports_bloques_powershell() -> Vec<u16> {
    // Les règles posées sous l'ancien nom bloquent encore : elles comptent aussi (`passage`).
    ps(&format!(
        "@(Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue | \
        Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' }} | \
        Get-NetFirewallPortFilter | ForEach-Object {{ $_.LocalPort }}) -join ','",
        crate::passage::liste_ps("Vanguard : bloquer *")
    ))
    .unwrap_or_default()
    .split(',')
    .filter_map(|p| p.trim().parse().ok())
    .collect()
}

/// Les mêmes, par PowerShell, quand ni les tables ni netstat ne répondent : les noms des programmes lus une fois,
/// puis les ports en écoute, puis les règles de blocage dans leur section (leur échec ne fait pas perdre les ports).
fn ports_tcp_powershell(pare_feu_actif: bool) -> Option<(String, Vec<u16>)> {
    let regles = if pare_feu_actif {
        format!(
            "; try {{ 'BLQ|' + (@(Get-NetFirewallRule -DisplayName {} -ErrorAction SilentlyContinue | \
             Where-Object {{ $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and $_.Direction -eq 'Inbound' }} | \
             Get-NetFirewallPortFilter | ForEach-Object {{ $_.LocalPort }}) -join ','); 'BLQ_FIN' }} catch {{}}",
            crate::passage::liste_ps("Vanguard : bloquer *")
        )
    } else {
        String::new()
    };
    let sortie = ps(&format!(
        "$noms = @{{}}; Get-Process | ForEach-Object {{ $noms[$_.Id] = $_.ProcessName }}; \
         Get-NetTCPConnection -State Listen | ForEach-Object {{ \"ECO|$($_.LocalAddress)|$($_.LocalPort)|$($noms[[int]$_.OwningProcess])\" }}; 'ECO_FIN'{regles}"
    ));
    let liste = section(sortie.as_deref(), "ECO")?.join("\n");
    let bloques = section(sortie.as_deref(), "BLQ")
        .and_then(|l| l.first().copied())
        .unwrap_or_default()
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    Some((liste, bloques))
}

/// Les ports TCP en écoute et le nom de leur programme, pour nommer les services au scan du réseau ; `None` si ni les
/// tables de Windows ni netstat ne répondent.
pub(super) fn ports_tcp_et_noms() -> Option<Vec<(u16, String)>> {
    Some(
        ecoute::ecoutes()?
            .into_iter()
            .filter(|e| e.tcp)
            .map(|e| (e.port, e.nom))
            .collect(),
    )
}

/// La ligne qui ferme un port en entrée : l'ordre `fermer-port` du blocage, fait par COM dans le processus élevé.
fn port_ferme(port: u16) -> String {
    use crate::protection::blocage::ordres::Ordre;
    use crate::protection::blocage::pare_feu::PareFeu;
    Ordre::FermerPort {
        pare_feu: PareFeu::Windows,
        port,
    }
    .ligne()
}

fn ports_ecoute(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    // Le plus lent du bilan Windows par PowerShell (4 à 6 s dans la VM, une vingtaine de PowerShell démarrant
    // ensemble) : les tables de Windows et la liste des processus d'abord, PowerShell seulement s'ils ne répondent pas. Les ports bloqués par une
    // règle de Vanguard écoutent toujours mais ne sont plus joignables : sans cette lecture, l'alerte et la même
    // correction (une règle de plus à chaque fois) revenaient à chaque audit.
    let Some((liste, bloques)) = ports_tcp_directs(pare_feu_actif).or_else(|| ports_tcp_powershell(pare_feu_actif))
    else {
        return vec![illisible("Ports en écoute")];
    };
    // Les sessions à distance en cours, lues une fois : leur port n'est pas proposé à la fermeture (`port_a_garder`).
    let sessions = crate::protection::blocage::sessions_a_distance();
    // Ports RPC dynamiques ouverts par Windows lui-même : normaux et filtrés par le pare-feu.
    let systeme = ["svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle"];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    for l in liste.lines() {
        let mut c = l.splitn(3, '|');
        let (Some(adresse), Some(Ok(port)), programme) =
            (c.next(), c.next().map(str::parse::<u16>), c.next().unwrap_or("?"))
        else {
            continue;
        };
        let expose = matches!(adresse, "0.0.0.0" | "::") || ip_lan == Some(adresse);
        if !expose || vus.contains(&port) || (port >= 49152 && systeme.contains(&programme)) {
            continue;
        }
        vus.push(port);
        // La clé garde le nom tel que Windows le donne (sans casse), jamais « ? » traduit ni rendu affichable.
        let nom = programme.to_lowercase();
        let objet = crate::modele::Objet::port(port, "tcp", (nom != "?").then_some(nom.as_str()));
        // Chaque programme choisit son nom : montré, il est rendu inoffensif.
        let programme = crate::ui::affichable(programme);
        let i = info_port(port);
        if bloques.contains(&port) {
            constats.push(alerte(
                "Ports en écoute",
                Niveau::Info,
                trf!(
                    "{port}/tcp ({}) ouvert par « {programme} », bloqué en entrée par la règle « Vanguard : bloquer {port} » du pare-feu Windows.", "{port}/tcp ({}) opened by “{programme}”, blocked inbound by the “Vanguard : bloquer {port}” Windows firewall rule.",
                    i.service
                ),
            ).avec_objet(objet));
            continue;
        }
        let niveau = super::niveau_expose(pare_feu_actif, i.niveau);
        // SSH et RDP : pas de blocage aveugle, il coupe l'accès aux machines pilotées à distance (VM…) ; le processus
        // élevé le refuserait de toute façon (`ordres::juger`). Le constat « Bureau à distance » propose déjà NLA ou
        // la désactivation propre. Le port d'une session en cours (prise en main sur 5900…), ou tout port quand les
        // connexions ne se lisent pas : pas proposé non plus, et le constat dit pourquoi.
        let proposable = niveau >= Niveau::Moyen && crate::protection::blocage::port_intouchable(port).is_none();
        let garde = proposable
            .then(|| crate::protection::blocage::port_a_garder(port, sessions.as_ref()))
            .flatten();
        let texte = trf!(
            "{port}/tcp ({}) ouvert par « {programme} ». {}",
            "{port}/tcp ({}) opened by “{programme}”. {}",
            i.service,
            i.conseil
        );
        let texte = match garde {
            Some(raison) => trf!(
                "{texte} Blocage du port pas proposé : {raison}.",
                "{texte} Blocking the port not offered: {raison}."
            ),
            None => texte,
        };
        let constat = alerte("Ports en écoute", niveau, texte).avec_objet(objet);
        constats.push(if proposable && garde.is_none() {
            constat
                .corriger(
                    trf!(
                        "Bloquer le port {port} en entrée dans le pare-feu Windows",
                        "Block inbound port {port} in the Windows firewall"
                    ),
                    // L'ordre du blocage, fait par COM dans le processus élevé : la règle « Vanguard : bloquer {port} »
                    // (`nom_entrante`, celle que relit `regles_vanguard`), sans doublon si elle existe déjà.
                    &[&port_ferme(port)],
                )
                .bloquant(format!("{port}/tcp"))
        } else {
            constat
        });
    }
    if constats.is_empty() {
        constats.push(ok(
            "Ports en écoute",
            tr!(
                "Aucun service TCP sensible exposé au réseau.",
                "No sensitive TCP service exposed to the network."
            ),
        ));
    }
    constats
}

/// Wi-Fi : protection du réseau connecté, et un éventuel jumeau maléfique parmi les réseaux visibles, lus par l'API
/// WLAN, comme l'audit du réseau. Sans l'autorisation de localisation, la protection se lit encore sur la connexion,
/// et le jumeau est dit non cherché.
fn wifi() -> Vec<Constat> {
    match super::wifi::wlanapi::lire() {
        Ok(l) if l.connexion.is_some() => super::wifi::bilan(&l, &[]),
        _ => vec![wifi_sans_connexion()],
    }
}

/// Aucun réseau connecté lu : sans objet seulement si l'API Wi-Fi le confirme (pas de carte, ou aucune connectée).
/// Une carte connectée dont le réseau ne se lit pas, c'est Windows 11 24H2 sans l'autorisation de localisation : non
/// vérifié, jamais un silence.
fn wifi_sans_connexion() -> Constat {
    use crate::modele::{Absence, Raison};
    match super::wifi::wlanapi::cartes() {
        Ok(cartes) if cartes.is_empty() => super::sans_objet(
            "Wi-Fi",
            Absence::Materiel,
            tr!(
                "Pas de carte Wi-Fi sur cet ordinateur.",
                "No Wi-Fi card on this computer."
            ),
        ),
        Ok(cartes) if !cartes.contains(&true) => super::sans_objet(
            "Wi-Fi",
            Absence::Inactif,
            tr!(
                "Aucun réseau Wi-Fi connecté : rien à juger.",
                "No Wi-Fi network connected: nothing to judge."
            ),
        ),
        Ok(_) => super::impossible_par(
            "Wi-Fi",
            Raison::Illisible("wlanapi".into()),
            tr!(
                "Impossible de vérifier le Wi-Fi : connecté, mais Windows ne montre le réseau qu'avec la localisation (Paramètres > Confidentialité et sécurité > Localisation).",
                "Could not check Wi-Fi: connected, but Windows shows the network only with location access (Settings > Privacy & security > Location)."
            ),
        ),
        // Service WLAN arrêté ou API absente : sans aucune carte Wi-Fi parmi les cartes réseau, c'est simplement un
        // ordinateur sans Wi-Fi (bureau, machine virtuelle), pas un point non vérifié.
        Err(_) if cartes::cartes().is_some_and(|c| !c.is_empty() && !c.iter().any(cartes::Carte::sans_fil)) => {
            super::sans_objet(
                "Wi-Fi",
                Absence::Materiel,
                tr!(
                    "Pas de carte Wi-Fi sur cet ordinateur.",
                    "No Wi-Fi card on this computer."
                ),
            )
        }
        Err(e) => super::impossible_par(
            "Wi-Fi",
            Raison::Illisible(e.to_string()),
            trf!("Impossible de vérifier le Wi-Fi ({e}).", "Could not check Wi-Fi ({e})."),
        ),
    }
}

/// Ports UDP ouverts sur le réseau. Windows en ouvre beaucoup lui-même (découverte, heure, VPN) : on ne garde
/// que les services à risque et ceux des programmes installés, hors ports éphémères (réponses de clients).
fn ports_udp(pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    // Sans PowerShell d'abord : le réglage LLMNR dans le registre, les ports par les tables de Windows et la liste
    // des processus.
    if let Some(ecoutes) = ecoute::ecoutes() {
        let llmnr = registre::<u32>(
            winreg::enums::HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "EnableMulticast",
        )
        .map(|v| v.to_string())
        .unwrap_or_default();
        let mut liste = format!("LLMNR|{llmnr}\n{}\n", ligne_netbios());
        for e in ecoutes.iter().filter(|e| !e.tcp) {
            let _ = writeln!(liste, "{}|{}|{}", e.adresse, e.port, e.nom);
        }
        return lire_ports_udp(&liste, pare_feu_actif, ip_lan);
    }
    let Some(liste) = ps(
        // Première ligne : le réglage LLMNR (0 = coupé, effectif au prochain redémarrage seulement).
        "'LLMNR|' + (Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -ErrorAction SilentlyContinue).EnableMulticast; \
         Get-NetUDPEndpoint | ForEach-Object { \"$($_.LocalAddress)|$($_.LocalPort)|$((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName)\" }",
    ) else {
        return vec![illisible("Ports en écoute")];
    };
    lire_ports_udp(&format!("{}\n{liste}", ligne_netbios()), pare_feu_actif, ip_lan)
}

/// « NETBIOS|0 » quand NetbiosOptions vaut 2 sur chaque carte (coupé, effectif au prochain redémarrage seulement),
/// « NETBIOS|1 » sinon : lu dans le registre, pour les deux voies.
fn ligne_netbios() -> &'static str {
    if corrections::netbios_coupe() {
        "NETBIOS|0"
    } else {
        "NETBIOS|1"
    }
}

fn lire_ports_udp(liste: &str, pare_feu_actif: bool, ip_lan: Option<&str>) -> Vec<Constat> {
    let systeme = [
        "svchost", "lsass", "wininit", "services", "spoolsv", "System", "Idle", "",
    ];
    let mut vus = Vec::new();
    let mut constats = Vec::new();
    let llmnr_coupe = liste.lines().any(|l| l.trim() == "LLMNR|0");
    let netbios_coupe = liste.lines().any(|l| l.trim() == "NETBIOS|0");
    for l in liste
        .lines()
        .filter(|l| !l.starts_with("LLMNR|") && !l.starts_with("NETBIOS|"))
    {
        let mut c = l.trim().splitn(3, '|');
        let (Some(adresse), Some(Ok(port)), programme) =
            (c.next(), c.next().map(str::parse::<u16>), c.next().unwrap_or("").trim())
        else {
            continue;
        };
        let expose = matches!(adresse, "0.0.0.0" | "::") || ip_lan == Some(adresse);
        if !expose || port >= 49152 || vus.contains(&port) {
            continue;
        }
        let i = info_port(port);
        let du_systeme = systeme.contains(&programme);
        // 3389/udp : la moitié UDP du Bureau à distance, déjà jugé par son propre constat.
        if (du_systeme && i.niveau == Niveau::Info) || port == 3389 {
            continue;
        }
        vus.push(port);
        let nom = programme.to_lowercase();
        let objet = crate::modele::Objet::port(port, "udp", Some(nom.as_str()));
        // Chaque programme choisit son nom : montré, il est rendu inoffensif.
        let programme = if programme.is_empty() {
            tr!("programme inconnu", "unknown program").to_string()
        } else {
            crate::ui::affichable(programme)
        };
        let constat = alerte(
            "Ports en écoute",
            super::niveau_expose(pare_feu_actif, i.niveau),
            trf!(
                "{port}/udp ({}) ouvert par « {programme} ». {}",
                "{port}/udp ({}) opened by “{programme}”. {}",
                i.service,
                i.conseil
            ),
        );
        let constat = constat.avec_objet(objet.clone());
        // Services de découverte de Windows : une correction qui les coupe proprement (138 suit 137, une seule fois).
        constats.push(match port {
            5355 if llmnr_coupe => alerte(
                "Ports en écoute",
                Niveau::Info,
                tr!(
                    "5355/udp (LLMNR) encore ouvert, mais LLMNR est coupé : ce sera effectif au prochain redémarrage.",
                    "5355/udp (LLMNR) still open, but LLMNR is turned off: it takes effect at the next restart."
                ),
            )
            .avec_objet(objet),
            5355 => constat.corriger(
                tr!(
                    "Couper LLMNR (résolution de noms usurpable ; le DNS suffit)",
                    "Turn off LLMNR (spoofable name resolution; DNS is enough)"
                ),
                // Clé créée seulement si elle manque : « New-Item -Force » sur une clé existante l'écraserait, avec
                // les autres stratégies DNS qu'elle contient.
                &[&corrections::id("llmnr-coupe")],
            ),
            137 | 138 if netbios_coupe => alerte(
                "Ports en écoute",
                Niveau::Info,
                trf!(
                    "{port}/udp (NetBIOS) encore ouvert, mais NetBIOS est coupé : ce sera effectif au prochain redémarrage.",
                    "{port}/udp (NetBIOS) still open, but NetBIOS is turned off: it takes effect at the next restart."
                ),
            )
            .avec_objet(objet),
            137 | 138 if !vus.contains(&if port == 137 { 138 } else { 137 }) => constat.corriger(
                tr!(
                    "Couper NetBIOS sur TCP/IP (vieux partage ; le partage moderne passe par le port 445)",
                    "Turn off NetBIOS over TCP/IP (old sharing; modern sharing uses port 445)"
                ),
                &[corrections::id("netbios-coupe")],
            ),
            1900 => constat
                .corriger(
                    tr!(
                        "Couper la découverte UPnP (SSDP) ; à garder si vous diffusez vers une TV ou une console",
                        "Turn off UPnP discovery (SSDP); keep it if you cast to a TV or console"
                    ),
                    &[
                        gestes::ligne_service("SSDPSRV", gestes::Action::Arreter),
                        gestes::ligne_service("SSDPSRV", gestes::Action::Desactive),
                    ],
                )
                .annulable(vec![crate::optimiser::Geste::service("SSDPSRV")]),
            _ => constat,
        });
    }
    constats
}

pub fn auditer() -> Audit {
    // Un nouveau bilan relit les comptes : une correction a pu en désactiver un depuis le précédent.
    *COMPTES.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    // Les vérifications sont les règles du registre (regles.rs, durcissement.rs), le pare-feu en tête.
    super::audit(NOM)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::machine::gestes;

    /// La correction « Bloquer le port » est l'ordre du blocage : sa règle porte le nom que le bilan relit
    /// (`ecoute::port_bloque`), le même que l'ancienne ligne PowerShell, que garde le chemin de Wine.
    #[test]
    fn fermer_un_port_garde_le_nom_de_la_regle() {
        use crate::protection::blocage::ordres::{self, Ordre};
        use crate::protection::blocage::pare_feu::nom_entrante;
        let ligne = port_ferme(8080);
        assert_eq!(ligne, "vanguard:fermer-port windows 8080");
        let ordre = ordres::analyser(&ligne).unwrap();
        assert!(matches!(ordre, Ordre::FermerPort { port: 8080, .. }));
        assert!(corrections::native(&ligne));
        assert_eq!(nom_entrante(8080), "Vanguard : bloquer 8080");
        assert_eq!(
            ordres::powershell(&ordre).unwrap(),
            "if (-not (Get-NetFirewallRule -DisplayName 'Vanguard : bloquer 8080' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName 'Vanguard : bloquer 8080' -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Block | Out-Null }"
        );
        let regle = format!(
            "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8080|Name={}|",
            nom_entrante(8080)
        );
        assert_eq!(ecoute::port_bloque(&regle), Some(8080));
        // SSH et le Bureau à distance ne sont jamais proposés : le processus élevé les refuserait.
        for port in [22, 3389] {
            assert!(crate::protection::blocage::port_intouchable(port).is_some());
        }
        assert!(crate::protection::blocage::port_intouchable(8080).is_none());
    }

    /// Le pare-feu se rallume par l'acte natif, une protection (« Défaire » ne le propose pas).
    #[test]
    fn rallumer_le_pare_feu_est_un_acte() {
        let ligne = gestes::ligne_pare_feu_actif();
        assert_eq!(ligne, "vanguard:pare-feu-actif");
        assert!(corrections::native(&ligne));
        assert!(matches!(
            gestes::analyser_acte(&ligne),
            Some(gestes::Acte::PareFeuActif)
        ));
    }

    fn reponse(reussi: bool, note: Option<&str>, code: Option<i32>, etats: Option<Vec<bool>>) -> eleve::Reponse {
        eleve::Reponse {
            reussi,
            avant: None,
            note: note.map(str::to_string),
            code,
            etats,
            arretee: false,
            au_redemarrage: false,
            rien: false,
        }
    }

    /// Point de restauration refusé (« N ») ou demande refusée : chaque geste revient « arrêté », la liste est dite
    /// arrêtée à la demande de la personne, pas échouée ; un seul vrai échec, ou rien du tout, ne l'est pas.
    #[test]
    fn un_arret_demande_n_est_pas_un_echec() {
        use crate::machine::Inacheve;
        let arretee = || eleve::Reponse {
            arretee: true,
            ..reponse(false, None, None, None)
        };
        let a_finir = || eleve::Reponse {
            au_redemarrage: true,
            ..reponse(false, None, None, None)
        };
        let ok = || reponse(true, None, None, None);
        let echec = || reponse(false, None, Some(1), None);
        assert_eq!(inacheve(&[arretee(), arretee()]), Inacheve::ArreteeADemande);
        assert_eq!(inacheve(&[arretee(), echec()]), Inacheve::Non);
        assert_eq!(inacheve(&[]), Inacheve::Non);
        // chkdsk 3 : à finir au redémarrage, seulement sans autre vrai échec.
        assert_eq!(inacheve(&[ok(), a_finir()]), Inacheve::AuRedemarrage);
        assert_eq!(inacheve(&[a_finir(), echec()]), Inacheve::Non);
        crate::machine::noter_inacheve(inacheve(&[arretee()]));
        assert!(crate::machine::arretee_a_votre_demande() && !crate::machine::a_finir_au_redemarrage());
        crate::machine::noter_inacheve(inacheve(&[ok(), a_finir()]));
        assert!(crate::machine::a_finir_au_redemarrage() && !crate::machine::arretee_a_votre_demande());
        crate::machine::noter_inacheve(inacheve(&[echec()]));
        assert!(!crate::machine::arretee_a_votre_demande() && !crate::machine::a_finir_au_redemarrage());
    }

    /// Une liste mêlée se recompose correctif par correctif : le point (natif) puis un script qui couvre deux
    /// correctifs ; le script en échec partiel n'échoue que pour le correctif sans son « ok » ; une réponse qui
    /// manque est un échec ; un correctif vide réussit (rien à faire).
    #[test]
    fn admin_mele_recompose_par_correctif() {
        let correctifs = vec![
            vec![
                corrections::POINT.to_string(),
                "Set-Service a -StartupType Disabled".to_string(),
            ],
            vec!["Set-Service b -StartupType Disabled".to_string()],
            Vec::new(),
        ];
        let morceaux = gestes::decouper(&correctifs, corrections::native);
        assert_eq!(
            morceaux,
            [
                gestes::Morceau::Natif(vec![(0, 0)]),
                gestes::Morceau::Script(vec![(0, vec![1]), (1, vec![0])]),
            ]
        );
        // Tout réussi : tous vrais, la précision du point notée à sa ligne.
        let (r, notes) = recomposer(
            &correctifs,
            &morceaux,
            vec![
                reponse(true, Some("déjà fait"), None, None),
                reponse(true, None, None, None),
            ],
        );
        assert_eq!(r, [true, true, true]);
        assert_eq!(notes[0][0], format!("{} (déjà fait)", corrections::POINT));
        // Le script échoue après le premier correctif : seul le second est en échec.
        let (r, _) = recomposer(
            &correctifs,
            &morceaux,
            vec![
                reponse(true, None, None, None),
                reponse(false, None, Some(1), Some(vec![true])),
            ],
        );
        assert_eq!(r, [true, false, true]);
        // Le point refusé : le premier correctif échoue ; le script sans réponse (arrêt) : les deux.
        let (r, _) = recomposer(&correctifs, &morceaux, vec![reponse(false, None, None, None)]);
        assert_eq!(r, [false, false, true]);
        // Aucune réponse du tout : rien n'est compté fait, sauf le correctif vide.
        let (r, _) = recomposer(&correctifs, &morceaux, Vec::new());
        assert_eq!(r, [false, false, true]);
    }

    /// Une ligne déjà bonne (« ok rien=… ») réussit sans être notée : rien n'a changé. Un correctif dont il ne reste
    /// que le point de restauration n'a plus rien à noter ; les autres lignes gardent leur valeur d'avant.
    #[test]
    fn une_ligne_deja_bonne_n_est_pas_notee() {
        let correctifs = vec![
            vec![corrections::POINT.to_string(), corrections::id("wdigest-coupe")],
            vec![corrections::id("rdp-nla"), corrections::id("aie-machine")],
        ];
        let morceaux = gestes::decouper(&correctifs, corrections::native);
        let rien = || eleve::Reponse {
            rien: true,
            ..reponse(true, Some("déjà 1, rien d'écrit"), None, None)
        };
        let fait = eleve::Reponse {
            avant: Some("0".into()),
            ..reponse(true, None, None, None)
        };
        let (r, notes) = recomposer(
            &correctifs,
            &morceaux,
            vec![reponse(true, None, None, None), rien(), rien(), fait],
        );
        assert_eq!(r, [true, true]);
        assert_eq!(notes[0], [] as [String; 0]);
        assert_eq!(notes[1], [format!("{} (avant : 0)", corrections::id("aie-machine"))]);
        // Une ligne déjà bonne à côté d'un échec : l'échec reste noté, avec sa ligne.
        let (r, notes) = recomposer(
            &correctifs,
            &morceaux,
            vec![
                reponse(true, None, None, None),
                rien(),
                reponse(false, None, None, None),
                rien(),
            ],
        );
        assert_eq!(r, [true, false]);
        assert_eq!(notes[0], [] as [String; 0]);
        assert_eq!(notes[1], [corrections::id("rdp-nla")]);
    }

    /// Rien à envoyer au processus élevé : vrai seulement pour un correctif vide, jamais d'office (un correctif non
    /// vide qu'aucun morceau ne couvre est un échec).
    #[test]
    fn sans_rien_a_envoyer_seul_le_vide_reussit() {
        let vides = vec![Vec::new(), Vec::new()];
        assert_eq!(
            recomposer(&vides, &gestes::decouper(&vides, corrections::native), Vec::new()).0,
            [true, true]
        );
        let oublie = vec![Vec::new(), vec!["Set-Service a -StartupType Disabled".to_string()]];
        assert_eq!(recomposer(&oublie, &[], Vec::new()).0, [true, false]);
    }

    /// Une ligne de Vanguard (`vanguard:…`) mal formée n'est pas un geste natif : `decouper` la range dans un script,
    /// où PowerShell la prendrait pour une commande inconnue, après la demande d'administrateur. Elle fait refuser la
    /// liste entière avant, sans écrire de script.
    #[test]
    fn une_ligne_vanguard_egaree_fait_refuser_la_liste_avant_l_uac() {
        for egaree in [
            "vanguard:programme ipconfig /all",
            "vanguard:programme sfc-scannow ",
            "vanguard:inconnu x",
            "  Vanguard:programme sfc-scannow",
            // Un geste du compte hors de sa forme exacte n'est pas un geste du compte : il reste au travail élevé.
            "vanguard:compte proxy-coupe ",
            "vanguard:compte jeux-inconnu",
            "vanguard:compte run-retirer run 00",
        ] {
            let correctifs = vec![
                vec!["Set-Service a -StartupType Disabled".to_string()],
                vec![egaree.to_string()],
            ];
            let morceaux = gestes::decouper(&correctifs, corrections::native);
            assert!(lignes_pour_eleve(&correctifs, &morceaux).is_none(), "{egaree}");
            assert!(!accepte_par_le_processus_eleve(&correctifs), "{egaree}");
        }
        // Le mot ailleurs que tout au début n'est pas une ligne de Vanguard.
        let correctifs = vec![vec!["Write-Output 'vanguard:programme'".to_string()]];
        let morceaux = gestes::decouper(&correctifs, corrections::native);
        assert!(lignes_pour_eleve(&correctifs, &morceaux).is_some());
    }

    /// Un geste du compte n'est jamais un geste du processus élevé : ni natif, ni accepté par sa validation, ni écrit
    /// dans un script (refusé avant l'UAC). Séparé comme par `lancer_chacune`, il reste dans Vanguard non élevé.
    #[test]
    fn un_geste_du_compte_ne_passe_jamais_par_le_processus_eleve() {
        for l in [
            gestes::ligne_compte("proxy-coupe").unwrap(),
            gestes::ligne_macros("16.0", "word").unwrap(),
            gestes::ligne_run_retirer(false, &"Essai".encode_utf16().collect::<Vec<_>>()).unwrap(),
            gestes::ligne_alimentation(),
        ] {
            assert!(!corrections::native(&l), "{l}");
            assert!(eleve::valider(std::slice::from_ref(&l)).is_none(), "{l}");
            let seul = vec![vec![l.clone()]];
            assert!(
                lignes_pour_eleve(&seul, &gestes::decouper(&seul, corrections::native)).is_none(),
                "{l}"
            );
            // Séparé, il ne laisse rien au processus élevé, et passe.
            assert!(accepte_par_le_processus_eleve(&seul), "{l}");
            let avec_point = vec![vec![
                corrections::POINT.to_string(),
                l.clone(),
                corrections::id("rdp-nla"),
            ]];
            assert!(accepte_par_le_processus_eleve(&avec_point), "{l}");
        }
    }

    /// Sous Wine, ni Defender ni le Centre de sécurité ni PowerShell : « illisible », jamais « aucun antivirus » (une
    /// alerte critique fausse) ni « Defender actif ».
    /// La lecture directe rend un des états que juge `juger_bitlocker` (un nombre, ou vide sans BitLocker), ou rien.
    #[test]
    fn bitlocker_lu_directement() {
        if let Some(etat) = protection_bitlocker() {
            assert!(etat.is_empty() || etat.parse::<u32>().is_ok(), "{etat}");
        }
    }

    #[test]
    fn antivirus_illisible_sous_wine() {
        if std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file() {
            assert!(defender_par_wmi().is_none() && antivirus_inscrits().is_none());
            let c = antivirus();
            assert!(c.len() == 1 && !c[0].verifie, "{}", c[0].message);
        }
    }

    #[test]
    fn uac_qui_ne_demande_rien() {
        let probleme = |l, c| juger_uac(l, c).and_then(|c| c.probleme);
        assert_eq!(probleme(Some("1"), Some("5")), None);
        assert_eq!(probleme(Some("1"), Some("")), None); // absent : la valeur de Windows
        assert_eq!(probleme(Some("1"), Some("2")), None); // demande toujours, sur le bureau sécurisé
        assert_eq!(probleme(Some("1"), Some("0")), Some(Niveau::Eleve));
        assert_eq!(probleme(Some("0"), Some("5")), Some(Niveau::Eleve));
        assert!(juger_uac(None, None).is_none() && juger_uac(Some(""), Some("5")).is_none());
        let c = juger_uac(Some("1"), Some("0")).unwrap();
        assert_eq!(c.correctif.unwrap().commandes[0], "vanguard:uac-demande");
    }

    #[test]
    fn etats_de_bitlocker() {
        let probleme = |e: &str| juger_bitlocker(Some(e)).probleme;
        assert!(["1", "3", "6", "1\r\n"].iter().all(|e| probleme(e).is_none()));
        assert!(
            ["0", "2", "4", "5", "8"]
                .iter()
                .all(|e| probleme(e) == Some(Niveau::Moyen))
        );
        assert!(juger_bitlocker(Some("5")).correctif.unwrap().automatique);
        assert!(!juger_bitlocker(Some("8")).correctif.unwrap().automatique);
        assert_ne!(juger_bitlocker(None).probleme, Some(Niveau::Moyen));
    }

    #[test]
    fn protection_dans_le_cloud() {
        assert!(juger_cloud(None).is_none() && juger_cloud(Some("2")).is_none() && juger_cloud(Some("1")).is_none());
        let coupee = juger_cloud(Some("0\r\n")).unwrap();
        assert_eq!(coupee.probleme, Some(Niveau::Moyen));
        assert_eq!(coupee.correctif.unwrap().commandes, ["vanguard:defender maps avance"]);
    }

    /// T4 : un port UDP se reconnaît à son numéro et à son programme, sans casse ni langue.
    #[test]
    fn ports_udp_cles_sans_langue() {
        let liste = "0.0.0.0|161|snmp\n0.0.0.0|27036|Steam\n0.0.0.0|5355|svchost";
        let cles = crate::machine::controler_regle("WIN-RES-002", || lire_ports_udp(liste, true, None));
        assert_eq!(
            cles,
            [
                "WIN-RES-002|port:161/udp:snmp",
                "WIN-RES-002|port:27036/udp:steam",
                "WIN-RES-002|port:5355/udp:svchost"
            ]
        );
    }

    #[test]
    fn ports_udp_retenus() {
        let liste = "0.0.0.0|3389|svchost\n0.0.0.0|5353|svchost\n0.0.0.0|123|svchost\n0.0.0.0|161|snmp\n127.0.0.1|1900|svchost\n0.0.0.0|27036|steam\n0.0.0.0|60000|chrome\n0.0.0.0|161|snmp";
        let c = lire_ports_udp(liste, true, None);
        assert_eq!(c.len(), 2);
        assert!(c[0].message.starts_with("161/udp"));
        assert!(c[1].message.starts_with("27036/udp"));
        // Découverte de Windows : une correction chacune, une seule pour 137 et 138.
        let c = lire_ports_udp(
            "0.0.0.0|5355|svchost\n0.0.0.0|137|System\n0.0.0.0|138|System\n0.0.0.0|1900|svchost",
            false,
            None,
        );
        let corrigibles: Vec<bool> = c.iter().map(|c| c.correctif.is_some()).collect();
        assert_eq!(corrigibles, [true, true, false, true]);
        // LLMNR : la clé des stratégies DNS n'est créée que si elle manque, jamais écrasée.
        let llmnr = &c[0].correctif.as_ref().unwrap().commandes[0];
        assert_eq!(llmnr, "vanguard:llmnr-coupe");
        let c = lire_ports_udp("LLMNR|0\n0.0.0.0|5355|svchost", false, None);
        assert!(c.len() == 1 && c[0].correctif.is_none() && c[0].probleme == Some(Niveau::Info));
        // NetBIOS coupé dans le registre, 137 encore ouvert jusqu'au redémarrage : une information, pas de correction.
        let c = lire_ports_udp("NETBIOS|0\n0.0.0.0|137|System\n0.0.0.0|138|System", false, None);
        assert_eq!(c.len(), 2);
        assert!(
            c.iter()
                .all(|c| c.correctif.is_none() && c.probleme == Some(Niveau::Info))
        );
        assert!(c[0].message.starts_with("137/udp (NetBIOS)"), "{}", c[0].message);
        let c = lire_ports_udp("NETBIOS|1\n0.0.0.0|137|System", false, None);
        assert!(c.len() == 1 && c[0].correctif.is_some());
        // Un programme au nom piégé : rendu inoffensif dans le message.
        let c = lire_ports_udp("0.0.0.0|161|snmp\x1b]52;c;eA==\x07\u{202e}", true, None);
        assert!(c[0].message.contains("« snmp�]52;c;eA==�� »"), "{}", c[0].message);
    }

    // Sous Miri : session_a_distance appelle GetSystemMetrics, que Miri n'interprète pas.
    #[cfg_attr(miri, ignore)]
    #[test]
    // `std::env::set_var` est unsafe en édition 2024 : l'essai change SESSIONNAME.
    #[allow(unsafe_code)]
    fn jamais_couper_le_bureau_a_distance_qu_on_utilise() {
        // SAFETY: sous Windows, set_var est toujours sûr (documentation de std) : l'environnement du processus y est
        // protégé par un verrou ; `unsafe` ne sert qu'aux systèmes POSIX.
        unsafe { std::env::set_var("SESSIONNAME", "RDP-Tcp#3") };
        assert!(session_a_distance());
    }

    #[test]
    fn la_fenetre_admin_annonce_chaque_etape() {
        let s = script_admin(
            &[
                vec!["Update-MpSignature".to_string()],
                vec!["Disable-LocalUser -Name 'Invité'".to_string()],
            ],
            Sortie::Fichier(r"C:\Users\Zoé O'Brien\correction.resultats"),
        );
        assert!(s.contains("+ '  Update-MpSignature')"));
        assert!(s.contains("+ '  Disable-LocalUser -Name ''Invité'''"));
        assert!(s.contains("Read-Host"));
        // Un programme externe en échec est signalé, pas affiché « OK ».
        assert_eq!(s.matches("$global:LASTEXITCODE = 0").count(), 2);
        assert!(s.contains("$echecs++") && s.contains("exit 1 }"));
        // Chaque étape a son try/catch : une erreur PowerShell n'arrête pas les suivantes.
        assert_eq!(s.matches("} catch { $echecs++").count(), 2);
        // Une ligne de résultat par correctif, pour savoir lesquels ont réussi.
        assert_eq!(s.matches("$avant = $echecs").count(), 2);
        assert_eq!(s.matches("$resultats.WriteLine(").count(), 2);
        // Ouvert seulement s'il n'existe pas encore : un lien posé d'avance à ce nom ne détourne pas l'écriture.
        assert!(s.contains(r"[IO.File]::Open('C:\Users\Zoé O''Brien\correction.resultats', 'CreateNew'"));
    }

    /// Une commande qui reprend un nom piégé : la fenêtre administrateur l'annonce filtrée, rien ne s'efface à l'écran,
    /// et lance la vraie commande, inchangée.
    #[test]
    fn la_fenetre_admin_annonce_sans_piege() {
        let c = "Unregister-ScheduledTask -TaskName 'Maj\u{1b}[2K' -Confirm:$false".to_string();
        let s = script_admin(&[vec![c.clone()]], Sortie::Fichier(r"C:\x\correction-1.resultats"));
        assert!(
            s.contains("'  Unregister-ScheduledTask -TaskName ''Maj\u{fffd}[2K'' -Confirm:$false')"),
            "{s}"
        );
        assert!(s.contains(&format!("try {{\n  {c}\n")), "{s}");
    }

    #[test]
    fn la_fenetre_admin_garde_son_journal() {
        let s = script_admin(
            &[vec!["Update-MpSignature".to_string()]],
            Sortie::Fichier(r"C:\Users\Zoé O'Brien\correction-1.resultats"),
        );
        // Un nom que la fenêtre tire elle-même, sans rien écraser : pas de lien à poser d'avance sous ce nom.
        assert!(s.contains(
            r"Start-Transcript -LiteralPath ('C:\Users\Zoé O''Brien\correction-1-' + [guid]::NewGuid().ToString('N') + '.log') -NoClobber"
        ));
        let position = |mot: &str| s.find(mot).unwrap();
        assert!(position("Start-Transcript") < position("Update-MpSignature"));
        assert!(position("Stop-Transcript") < position("Read-Host"));
    }

    /// Par le processus élevé : l'état de chaque correctif part dans le tube hérité, sans journal ni fichier dans le
    /// dossier du compte, et sans attente d'Entrée (la console du processus élevé l'a déjà).
    #[test]
    fn la_fenetre_eleve_repond_par_le_tube() {
        let s = script_admin(
            &[vec!["Update-MpSignature".to_string()], vec!["Get-Date".to_string()]],
            Sortie::Tube,
        );
        assert!(s.contains(
            "[IO.Pipes.AnonymousPipeClientStream]::new([IO.Pipes.PipeDirection]::Out, $env:VANGUARD_RESULTATS)"
        ));
        assert_eq!(s.matches("$resultats.WriteLine(").count(), 2);
        for absent in [
            "Start-Transcript",
            "Stop-Transcript",
            "Read-Host",
            ".resultats",
            "CreateNew",
        ] {
            assert!(!s.contains(absent), "{absent}");
        }
        assert!(s.ends_with("if ($echecs) { exit 1 }\nexit 0"));
    }

    /// winget qui ne démarre pas (0xC0000135) : une erreur dite en mots, dans les deux langues, avant que le code ne
    /// soit lu comme « déjà installé » ou effacé ; App Installer introuvable ou hors de WindowsApps : refus dit, avec quoi
    /// faire. Les deux commandes winget de la fenêtre administrateur (installer, mettre à jour) portent le contrôle.
    #[test]
    fn winget_qui_ne_demarre_pas_se_dit_en_mots() {
        let verifier = |anglais: bool| {
            let controle = winget_demarre();
            assert!(
                controle.starts_with("; if ($LASTEXITCODE -eq -1073741515) { throw '"),
                "{controle}"
            );
            assert!(controle.contains("App Installer") && controle.contains("Microsoft Store"));
            assert!(controle.contains(if anglais {
                "could not start as administrator"
            } else {
                "n''a pas pu démarrer en administrateur"
            }));
            let installer = winget_installer("Microsoft.DirectX");
            let controle_a = installer.find(&controle).expect("contrôle absent de l'installation");
            assert!(controle_a < installer.find("-in -1978335189").expect("codes « déjà installé »"));
            assert!(installer.contains("--disable-interactivity; if ($LASTEXITCODE -eq -1073741515)"));
            let suite = if anglais { WINGET_TROUVE_EN } else { WINGET_TROUVE_FR };
            assert!(winget_eleve().ends_with(suite));
            assert!(suite.contains("Program Files\\WindowsApps") && suite.contains("Microsoft Store"));
        };
        verifier(false);
        crate::langue::en_anglais(|| verifier(true));
    }

    #[test]
    fn winget_en_administrateur_par_le_chemin_d_app_installer() {
        let c = winget_installer("Microsoft.DirectX");
        // Jamais par son seul nom : la commande commence par la recherche du paquet de Microsoft, et winget n'est
        // lancé que par le chemin trouvé.
        assert!(c.starts_with(
            "$vanguardWinget = $null; Import-Module -Name ([IO.Path]::Combine($PSHOME, 'Modules\\Appx'))"
        ));
        assert!(c.contains("Appx\\Get-AppxPackage -AllUsers -Name 'Microsoft.DesktopAppInstaller'"));
        assert!(c.contains("$vanguardPaquet.PublisherId -eq '8wekyb3d8bbwe'"));
        assert!(c.contains("[Environment]::GetFolderPath('ProgramFiles'), 'WindowsApps') + '\\'"));
        assert!(c.contains("& $vanguardWinget install --id Microsoft.DirectX --exact --source winget"));
        assert!(!c.contains("winget install") && !c.contains("; winget "));
        // Annoncée courte, dans les deux langues, le reste filtré comme toute commande.
        let attendu = "winget install --id Microsoft.DirectX --exact --source winget --silent";
        assert!(
            crate::ui::commande_affichable(&c).starts_with(attendu),
            "{}",
            crate::ui::commande_affichable(&c)
        );
        for suite in [WINGET_TROUVE_FR, WINGET_TROUVE_EN] {
            let autre = format!("{RECHERCHE_DE_WINGET}{suite} upgrade --id 'X\x1b[2K'");
            assert_eq!(
                crate::ui::commande_affichable(&autre),
                "winget upgrade --id 'X\u{fffd}[2K'"
            );
        }
        // Une recherche modifiée n'est pas raccourcie : on voit tout.
        let changee = c.replacen("8wekyb3d8bbwe", "0000000000000", 1);
        assert!(crate::ui::commande_affichable(&changee).starts_with("$vanguardWinget"));
    }

    #[test]
    fn empreinte_sha256_de_reference() {
        // Les valeurs de la norme (FIPS 180-2), en majuscules comme les rend PowerShell.
        assert_eq!(
            sha256_hex(b"abc"),
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert_eq!(
            sha256_hex(b""),
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        );
    }

    /// La fenêtre administrateur lit le script une seule fois et n'exécute que ces octets-là, après avoir vérifié leur
    /// empreinte.
    #[test]
    fn l_amorce_verifie_le_script_avant_de_le_lancer() {
        let a = amorce_admin(r"C:\Users\Zoé O'Brien\correction-1.ps1", "ABC123");
        assert_eq!(a.matches("ReadAllBytes(").count(), 1, "{a}");
        assert!(
            a.contains(r"ReadAllBytes('C:\Users\Zoé O''Brien\correction-1.ps1')"),
            "{a}"
        );
        assert!(a.contains("if ($h -ne 'ABC123')"), "{a}");
        let position = |mot: &str| a.find(mot).unwrap();
        assert!(position(&format!("exit {LANGAGE_RESTREINT} ")) < position("ReadAllBytes"));
        assert!(position(&format!("exit {SCRIPT_MODIFIE} ")) < position("[ScriptBlock]::Create"));
        assert!(!a.contains("-File"));
        // Une seule ligne sans guillemet double : elle passe entre guillemets dans la ligne de commande.
        assert!(!a.contains('\n') && !a.contains('"'), "{a}");
        assert!(a.len() < 1000, "{}", a.len());
    }
}
