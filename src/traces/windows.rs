//! Les traces sous Windows : processus par PowerShell (Win32_Process), connexions et ports par Get-NetTCPConnection,
//! tâches planifiées, services, clés Run et abonnements WMI, comptes locaux, journaux d'événements exportés en .evtx
//! par l'API des journaux (EvtExportLog, wevtutil en secours : le format que lisent l'Observateur d'événements et les
//! outils des spécialistes). Pour la chronologie,
//! les événements qui racontent une intrusion sont lus en plus par les fonctions de Windows (wevtapi).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::chronologie::{self, Apport};
use super::{Bi, Empreinte, Feuille, Manque, Partie, Processus, Produit, Raison, bi};
use crate::commande::section;
use crate::machine::windows::export_journaux;

/// Le séparateur des champs dans les sorties des scripts : une ligne de commande peut contenir « | » ou une
/// tabulation, jamais ce caractère (retiré par N).
const SEP: char = '\u{1f}';

/// Une commande de la console, lancée en UTF-8 : sans « chcp 65001 », ipconfig, schtasks ou netstat écrivent dans
/// l'ancienne page de code de la console, et les accents d'un Windows français deviennent illisibles. chcp et le
/// programme de la ligne sont écrits par leur chemin dans System32 : par leur seul nom, cmd les chercherait dans le
/// PATH, qui se change d'un `set` avant de lancer Vanguard (voir commande::cmd).
fn console(ligne: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut c = crate::commande::cmd();
    // Écrite telle quelle : Rust mettrait « \" » devant les guillemets des chemins, que cmd ne comprend pas.
    c.args(["/d", "/s", "/c"])
        .raw_arg(ligne_console(ligne, crate::commande::systeme32));
    c
}

/// La ligne passée à cmd, chcp et le premier mot de `ligne` remplacés par leur chemin (`chemin`) entre guillemets,
/// le tout entre guillemets : avec /s, cmd retire seulement le premier et le dernier.
fn ligne_console(ligne: &str, chemin: impl Fn(&str) -> PathBuf) -> String {
    let (programme, reste) = ligne.split_once(' ').unwrap_or((ligne, ""));
    let reste = if reste.is_empty() {
        String::new()
    } else {
        format!(" {reste}")
    };
    format!(
        "\"\"{}\" 65001 >nul & \"{}\"{reste}\"",
        chemin("chcp.com").display(),
        chemin(programme).display()
    )
}

/// Lancé en administrateur (fenêtre élevée) ? Lu sur le jeton du processus, sans whoami.
pub(super) fn administrateur() -> bool {
    static ADMIN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ADMIN.get_or_init(crate::machine::windows::processus::eleve)
}

/// Place libre pour ce compte sur le disque de `d`.
pub(super) fn place_libre(d: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(dossier: *const u16, libre: *mut u64, total: *mut u64, libre_total: *mut u64) -> i32;
    }
    let large: Vec<u16> = d.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut libre = 0u64;
    // SAFETY : `large` est une chaîne terminée par un zéro, vivante pendant l'appel ; `libre` est un entier de 64 bits
    // à nous ; les deux autres tailles, dont on n'a pas besoin, peuvent être nulles (documentation de l'API).
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            large.as_ptr(),
            &raw mut libre,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    (ok != 0).then_some(libre)
}

/// Fonction des scripts : une valeur sur une ligne, sans le séparateur des champs.
const N: &str = "$s = [char]31; function N($v) { (\"$v\" -replace '[\\r\\n\\x1f]+', ' ').Trim() }; ";

/// Les processus : numéro, parent, compte (Get-Process -IncludeUserName en administrateur, sinon GetOwner, qui ne
/// répond que pour les processus du compte), démarrage, programme et ligne de commande.
pub(crate) const SCRIPT_PROCESSUS: &str = "$u = @{}; \
     try { Get-Process -IncludeUserName -ErrorAction Stop | ForEach-Object { $u[$_.Id] = $_.UserName } } catch {}; \
     Get-CimInstance Win32_Process | ForEach-Object { \
       $c = $u[[int]$_.ProcessId]; \
       if (-not $c) { $c = try { $r = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop; if ($r.User) { $r.Domain + '\\' + $r.User } } catch { '' } }; \
       $d = if ($_.CreationDate) { $_.CreationDate.ToString('yyyy-MM-dd HH:mm:ss', [Globalization.CultureInfo]::InvariantCulture) } else { '' }; \
       'PRC|' + $_.ProcessId + $s + $_.ParentProcessId + $s + (N $c) + $s + $d + $s + (N $_.ExecutablePath) + $s + (N $_.CommandLine) }; \
     'PRC_FIN'";

/// Les lignes « PRC|… » du script des processus, sans PowerShell : Win32_Process par WMI, le compte de chaque processus
/// lu dans son jeton. `None` si WMI ne répond pas.
fn lignes_processus() -> Option<String> {
    let lignes = crate::machine::windows::wmi::requete(
        r"root\cimv2",
        "Win32_Process",
        "",
        &[
            "ProcessId",
            "ParentProcessId",
            "CreationDate",
            "ExecutablePath",
            "CommandLine",
        ],
    )?;
    let mut sortie: Vec<String> = lignes
        .iter()
        .filter_map(|p| {
            let texte = |c: &str| sur_une_ligne(p[c].texte().unwrap_or_default());
            let pid = u32::try_from(p["ProcessId"].entier()?).ok()?;
            let parent = p["ParentProcessId"].entier().map(|n| n.to_string()).unwrap_or_default();
            // La date CIM est à l'heure de l'ordinateur : « yyyy-MM-dd HH:mm:ss », comme le script.
            let debut = p["CreationDate"]
                .texte()
                .and_then(|d| chrono::NaiveDateTime::parse_from_str(d.get(..14)?, "%Y%m%d%H%M%S").ok())
                .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            let compte = sur_une_ligne(&crate::machine::windows::processus::compte_de(pid));
            Some(format!(
                "PRC|{pid}{SEP}{parent}{SEP}{compte}{SEP}{debut}{SEP}{}{SEP}{}",
                texte("ExecutablePath"),
                texte("CommandLine")
            ))
        })
        .collect();
    sortie.push("PRC_FIN".into());
    Some(sortie.join("\n"))
}

/// Les lignes « PRC|… » du script des processus : (pid, parent, compte, démarrage, programme, ligne de commande).
pub(crate) fn lire_processus(lignes: &[&str]) -> Vec<(u32, Option<u32>, String, String, String, String)> {
    lignes
        .iter()
        .filter_map(|l| {
            let c: Vec<&str> = l.split(SEP).collect();
            let [pid, parent, compte, debut, programme, ligne] = c[..] else {
                return None;
            };
            Some((
                pid.trim().parse().ok()?,
                parent.trim().parse().ok(),
                compte.to_string(),
                debut.to_string(),
                programme.to_string(),
                ligne.to_string(),
            ))
        })
        .collect()
}

pub(super) fn processus(dossier: &Path) -> Partie {
    let mut manques = Vec::new();
    let sortie =
        lignes_processus().or_else(|| crate::machine::windows::ps_delai(&format!("{N}{SCRIPT_PROCESSUS}"), 120));
    let Some(lignes) = section(sortie.as_deref(), "PRC") else {
        // Sans PowerShell : la liste de tasklist, sans programme ni ligne de commande.
        let mut p = Partie::new(Bi::new("Processus", "Processes"));
        let mut f = Feuille::new(&p.titre);
        let tasklist = f.commande(&mut console("tasklist /v /fo csv"), 60, true);
        p.manques.append(&mut f.manques);
        p.manque(
            Bi::new(
                "Programme, ligne de commande et empreinte des processus",
                "Program, command line and fingerprint of the processes",
            ),
            Raison::SansPowerShell,
        );
        if tasklist.is_some()
            && p.ecrire(
                dossier,
                "01-processus.txt",
                &f.texte,
                Bi::new(
                    "processus en marche, d'après tasklist (PowerShell n'a pas répondu)",
                    "running processes, from tasklist (PowerShell did not answer)",
                ),
            )
        {
            let n = tasklist.unwrap_or_default().lines().count().saturating_sub(1);
            p.compte = Some(bi!("{n} (sans empreintes)", "{n} (no fingerprints)"));
        }
        return p;
    };
    let admin = administrateur();
    let mut empreintes: HashMap<String, Empreinte> = HashMap::new();
    let fin = std::time::Instant::now() + super::DELAI_EMPREINTES;
    let mut sans_programme = 0;
    let liste: Vec<Processus> = lire_processus(&lignes)
        .into_iter()
        .map(|(pid, ppid, compte, debut, programme, ligne)| {
            let empreinte = if programme.is_empty() {
                // « System Idle Process » et « System » n'ont pas de programme ; les autres le cachent à qui n'est
                // pas administrateur.
                if pid <= 4 {
                    Empreinte::Aucune
                } else {
                    sans_programme += 1;
                    if admin { Empreinte::Illisible } else { Empreinte::Droits }
                }
            } else {
                empreintes
                    .entry(programme.to_lowercase())
                    .or_insert_with(|| {
                        if std::time::Instant::now() > fin {
                            Empreinte::Delai
                        } else {
                            super::empreinte(Path::new(&programme), super::TAILLE_PROGRAMME)
                        }
                    })
                    .clone()
            };
            Processus {
                pid,
                ppid,
                compte,
                debut,
                programme,
                etat: "",
                ligne,
                empreinte,
            }
        })
        .collect();
    if sans_programme > 0 && !admin {
        manques.push(Manque {
            quoi: bi!(
                "Programme et empreinte de {sans_programme} processus protégés ou d'autres comptes",
                "Program and fingerprint of {sans_programme} protected or other accounts' processes"
            ),
            raison: Raison::Droits,
        });
    }
    super::partie_processus(dossier, liste, manques)
}

/// Les connexions TCP et les ports UDP, avec le numéro et le nom du programme.
const SCRIPT_RESEAU: &str = "$p = @{}; Get-Process | ForEach-Object { $p[$_.Id] = $_.ProcessName }; \
     Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object { 'NET|TCP' + $s + $_.State + $s + $_.LocalAddress + ':' + $_.LocalPort + $s + $_.RemoteAddress + ':' + $_.RemotePort + $s + $_.OwningProcess + $s + (N $p[[int]$_.OwningProcess]) }; \
     Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { 'NET|UDP' + $s + '-' + $s + $_.LocalAddress + ':' + $_.LocalPort + $s + '-' + $s + $_.OwningProcess + $s + (N $p[[int]$_.OwningProcess]) }; \
     'NET_FIN'";

/// Une valeur sur une ligne, sans le séparateur des champs (la fonction N des scripts).
fn n(v: &str) -> String {
    v.split(['\r', '\n', SEP])
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// Les mêmes lignes « NET|… » que SCRIPT_RESEAU, lues dans les tables de Windows ; `None` si elles ne se lisent pas.
fn lignes_reseau() -> Option<String> {
    let noms: std::collections::HashMap<u32, String> = crate::machine::windows::processus::liste()
        .into_iter()
        .map(|p| (p.pid, p.nom))
        .collect();
    let mut lignes: Vec<String> = crate::machine::windows::connexions::sockets()?
        .into_iter()
        .map(|c| {
            let nom = n(noms.get(&c.pid).map_or("", String::as_str));
            let (proto, etat) = if c.tcp { ("TCP", c.etat) } else { ("UDP", "-") };
            let distante = c
                .distante
                .map_or_else(|| "-".to_string(), |(ip, port)| format!("{ip}:{port}"));
            let (ip, port) = c.locale;
            format!(
                "NET|{proto}{SEP}{etat}{SEP}{ip}:{port}{SEP}{distante}{SEP}{}{SEP}{nom}",
                c.pid
            )
        })
        .collect();
    lignes.push("NET_FIN".into());
    Some(lignes.join("\n"))
}

/// Les mêmes lignes « SRV|… » que la partie services de SCRIPT_DEMARRAGE, lues dans le registre et auprès du
/// gestionnaire de services ; `None` si la clé des services ne s'ouvre pas.
fn lignes_services() -> Option<String> {
    let mut lignes: Vec<String> = crate::machine::windows::gestionnaire::inscrits()?
        .into_iter()
        .map(|s| {
            format!(
                "SRV|{}{SEP}{}{SEP}{}{SEP}{}{SEP}{}",
                n(&s.nom),
                s.etat,
                s.demarrage,
                n(&s.compte),
                n(&s.programme)
            )
        })
        .collect();
    lignes.push("SRV_FIN".into());
    Some(lignes.join("\n"))
}

/// Les lignes « NET|… » mises en tableau, une connexion par ligne, champs séparés par des tabulations.
pub(crate) fn tableau_reseau(lignes: &[&str]) -> String {
    let mut t = String::from("PROTO\tÉTAT/STATE\tLOCALE/LOCAL\tDISTANTE/REMOTE\tPID\tPROGRAMME/PROGRAM\n");
    for l in lignes {
        let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
        let _ = writeln!(t, "{}", champs.join("\t"));
    }
    t
}

pub(super) fn reseau(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Réseau", "Network"));
    let mut f = Feuille::new(&p.titre);
    // Les tables de Windows (iphlpapi) ; PowerShell seulement si elles ne se lisent pas.
    let sortie = lignes_reseau().or_else(|| crate::machine::windows::ps(&format!("{N}{SCRIPT_RESEAU}")));
    let connexions = section(sortie.as_deref(), "NET");
    f.section("Get-NetTCPConnection, Get-NetUDPEndpoint");
    if let Some(lignes) = &connexions {
        f.lues += 1;
        f.ajouter(&tableau_reseau(lignes));
    } else {
        f.ajouter("(PowerShell)");
        f.commande(&mut console("netstat -ano"), 30, true);
    }
    f.commande(&mut console("arp -a"), 15, true);
    f.commande(&mut console("ipconfig /all"), 15, true);
    // Les noms demandés récemment : ils disparaissent au redémarrage ou après quelques heures.
    f.commande(&mut console("ipconfig /displaydns"), 30, false);
    f.commande(&mut console("route print"), 15, false);
    f.commande(&mut console("netsh winhttp show proxy"), 15, false);
    let racine = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    f.fichier(&racine.join(r"System32\drivers\etc\hosts"), true);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "02-reseau.txt",
        &f.texte,
        Bi::new(
            "connexions TCP et ports UDP avec leur programme (Get-NetTCPConnection, ou netstat -ano), voisins du réseau local (arp -a), cartes et DNS (ipconfig /all), noms demandés récemment (ipconfig /displaydns), routes, proxy et fichier hosts",
            "TCP connections and UDP ports with their program (Get-NetTCPConnection, or netstat -ano), local network neighbours (arp -a), adapters and DNS (ipconfig /all), recently resolved names (ipconfig /displaydns), routes, proxy and hosts file",
        ),
    ) {
        p.compte = Some(match connexions {
            Some(l) => bi!(
                "{} connexions et ports à l'écoute",
                "{} connections and listening ports",
                l.len()
            ),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Services (programme lancé et compte), abonnements WMI permanents (filtre, commande ou script lancés, et leurs
/// liens) : deux persistances que l'on ne voit dans aucune liste ordinaire.
const SCRIPT_DEMARRAGE: &str = "try { Get-CimInstance Win32_Service | ForEach-Object { 'SRV|' + (N $_.Name) + $s + $_.State + $s + $_.StartMode + $s + (N $_.StartName) + $s + (N $_.PathName) }; 'SRV_FIN' } catch {}; \
     try { \
       Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -ErrorAction Stop | ForEach-Object { 'WMI|filtre' + $s + (N $_.Name) + $s + (N $_.Query) }; \
       Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object { 'WMI|commande' + $s + (N $_.Name) + $s + (N ($_.ExecutablePath + ' ' + $_.CommandLineTemplate)) }; \
       Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object { 'WMI|script' + $s + (N $_.Name) + $s + (N $_.ScriptText) }; \
       Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -ErrorAction Stop | ForEach-Object { 'WMI|lien' + $s + (N $_.Filter) + $s + (N $_.Consumer) }; \
       'WMI_FIN' } catch {}";

/// Un texte sur une ligne de trace, comme la fonction N du script : sauts de ligne et séparateurs en espaces.
fn sur_une_ligne(v: &str) -> String {
    v.split(['\r', '\n', SEP])
        .filter(|m| !m.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_string()
}

/// La section WMI de SCRIPT_DEMARRAGE lue par WMI : filtres, consommateurs de commandes et de scripts, liens. Une
/// classe de consommateur que ce Windows n'inscrit pas n'en a aucun (le script, lui, perdait toute la section).
/// `None` si root/subscription refuse (droits) ou ne répond pas.
fn abonnements_wmi() -> Option<String> {
    use crate::machine::windows::wmi::{Ligne, Reponse, interroger};
    const ABONNEMENTS: &str = r"root\subscription";
    let lire = |classe: &str, champs: &[&str]| -> Option<Vec<Ligne>> {
        match interroger(ABONNEMENTS, classe, "", champs)? {
            Reponse::Lignes(l) => Some(l),
            Reponse::ClasseAbsente => Some(Vec::new()),
        }
    };
    let champ = |l: &Ligne, c: &str| sur_une_ligne(l[c].texte().unwrap_or_default());
    let mut lignes = Vec::new();
    for f in lire("__EventFilter", &["Name", "Query"])? {
        lignes.push(format!(
            "WMI|filtre{SEP}{}{SEP}{}",
            champ(&f, "Name"),
            champ(&f, "Query")
        ));
    }
    for c in lire(
        "CommandLineEventConsumer",
        &["Name", "ExecutablePath", "CommandLineTemplate"],
    )? {
        let lance = format!("{} {}", champ(&c, "ExecutablePath"), champ(&c, "CommandLineTemplate"));
        lignes.push(format!("WMI|commande{SEP}{}{SEP}{}", champ(&c, "Name"), lance.trim()));
    }
    for s in lire("ActiveScriptEventConsumer", &["Name", "ScriptText"])? {
        lignes.push(format!(
            "WMI|script{SEP}{}{SEP}{}",
            champ(&s, "Name"),
            champ(&s, "ScriptText")
        ));
    }
    for l in lire("__FilterToConsumerBinding", &["Filter", "Consumer"])? {
        lignes.push(format!(
            "WMI|lien{SEP}{}{SEP}{}",
            champ(&l, "Filter"),
            champ(&l, "Consumer")
        ));
    }
    lignes.push("WMI_FIN".into());
    Some(lignes.join("\n"))
}

/// Les clés du registre qui lancent un programme à l'ouverture de session ou au démarrage, ou s'immiscent dans
/// chaque lancement (Winlogon, AppInit_DLLs, AutoRun de l'invite de commandes, BootExecute).
const CLES_DEMARRAGE: [&str; 13] = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows",
    r"HKCU\Software\Microsoft\Command Processor",
    r"HKLM\Software\Microsoft\Command Processor",
    r"HKLM\System\CurrentControlSet\Control\Session Manager",
];

/// Le texte d'une valeur du registre, écrit comme « reg query » l'écrit : nombres en 0x…, chaînes multiples séparées
/// par « \\0 », le reste en hexadécimal. `genre` : son type (« REG_SZ »).
fn texte_registre(genre: &str, octets: &[u8]) -> String {
    let utf16 = |o: &[u8]| -> String {
        let mots: Vec<u16> = o.as_chunks::<2>().0.iter().map(|&m| u16::from_le_bytes(m)).collect();
        let fin = mots.len() - mots.iter().rev().take_while(|&&m| m == 0).count();
        String::from_utf16_lossy(&mots[..fin])
    };
    match genre {
        "REG_SZ" | "REG_EXPAND_SZ" | "REG_LINK" => utf16(octets),
        "REG_MULTI_SZ" => utf16(octets).replace('\0', "\\0"),
        "REG_DWORD" if octets.len() == 4 => format!(
            "0x{:x}",
            u32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]])
        ),
        "REG_QWORD" if octets.len() == 8 => {
            format!("0x{:x}", u64::from_le_bytes(octets.try_into().unwrap_or_default()))
        }
        _ => octets.iter().fold(String::new(), |mut t, o| {
            let _ = write!(t, "{o:02X}");
            t
        }),
    }
}

/// Une clé du registre lue directement, comme « reg query » la montrerait : ses valeurs (ou la seule demandée), puis
/// ses sous-clés ; et la date de sa dernière écriture (secondes depuis 1970), pour la chronologie. Sans cmd ni ligne
/// de commande à échapper : un nom à espaces (« Windows NT », « Command Processor ») se lit comme les autres. `Err` :
/// la note à sa place (clé absente ou refusée).
fn cle_registre(chemin: &str, seule: Option<&str>) -> Result<(String, Option<i64>), String> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    let (racine, reste) = match chemin.split_once('\\') {
        Some(("HKCU", reste)) => (RegKey::predef(HKEY_CURRENT_USER), reste),
        Some(("HKLM", reste)) => (RegKey::predef(HKEY_LOCAL_MACHINE), reste),
        _ => return Err(format!("(clé inconnue / unknown key : {chemin})")),
    };
    let cle = racine.open_subkey(reste).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => "(clé absente / key not found)".to_string(),
        std::io::ErrorKind::PermissionDenied => Raison::Droits.note(),
        _ => format!("(illisible / unreadable : {e})"),
    })?;
    let mut texte = String::new();
    let valeurs: Vec<(String, winreg::RegValue)> = match seule {
        Some(nom) => cle
            .get_raw_value(nom)
            .map(|v| vec![(nom.to_string(), v)])
            .unwrap_or_default(),
        None => cle.enum_values().flatten().collect(),
    };
    for (nom, valeur) in valeurs {
        let genre = format!("{:?}", valeur.vtype);
        let nom = if nom.is_empty() { "(Default)".to_string() } else { nom };
        let _ = writeln!(
            texte,
            "    {nom}    {genre}    {}",
            texte_registre(&genre, &valeur.bytes)
        );
    }
    if seule.is_none() {
        for sous_cle in cle.enum_keys().flatten() {
            let _ = writeln!(texte, "{chemin}\\{sous_cle}");
        }
    }
    if texte.is_empty() {
        texte.push_str("(vide / empty)\n");
    }
    let ecrite = cle.query_info().ok().and_then(|i| {
        let ft = &*i.last_write_time;
        chronologie::filetime_vers_unix((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime))
    });
    Ok((texte, ecrite))
}

pub(super) fn demarrage(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Ce qui se lance tout seul", "What starts by itself"));
    let mut f = Feuille::new(&p.titre);
    f.commande(&mut console("schtasks /query /fo LIST /v"), 90, true);
    let racine = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    // Les fichiers des tâches planifiées : la date de chacun dit quand la tâche a été posée ou changée, même sans
    // l'audit des tâches (4698), coupé d'ordinaire. La liste seulement ; leur contenu est dans schtasks.
    f.dossier(&racine.join(r"System32\Tasks"), 0, false);
    for cle in CLES_DEMARRAGE {
        // Session Manager : seulement BootExecute, le reste est long et sans rapport.
        let seule = cle.ends_with("Session Manager").then_some("BootExecute");
        f.section(cle);
        match cle_registre(cle, seule) {
            Ok((texte, ecrite)) => {
                f.lues += 1;
                f.ajouter(&texte);
                if let Some(quand) = ecrite {
                    p.evenements.push(chronologie::Evenement::lancement(quand, cle));
                }
            }
            Err(note) => f.ajouter(&note),
        }
    }
    for dossier_demarrage in [
        std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup")),
        std::env::var_os("ProgramData")
            .map(|a| PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\StartUp")),
    ]
    .into_iter()
    .flatten()
    {
        // Des raccourcis (.lnk) : la liste seulement ; leur empreinte est dans les fichiers récents.
        f.dossier(&dossier_demarrage, 0, false);
    }
    // Les services et les abonnements WMI sans PowerShell ; lui seulement si l'un des deux n'a pas répondu.
    let natifs = lignes_services();
    let abonnements_natifs = abonnements_wmi();
    let sortie = if natifs.is_some() && abonnements_natifs.is_some() {
        None
    } else {
        crate::machine::windows::ps(&format!("{N}{SCRIPT_DEMARRAGE}"))
    };
    f.section("Win32_Service");
    if let Some(services) = section(natifs.as_deref(), "SRV").or_else(|| section(sortie.as_deref(), "SRV")) {
        f.lues += 1;
        let mut t = String::from("NOM/NAME\tÉTAT/STATE\tDÉMARRAGE/START\tCOMPTE/ACCOUNT\tPROGRAMME/PROGRAM\n");
        for s in services {
            let champs: Vec<String> = s.split(SEP).map(super::champ).collect();
            let _ = writeln!(t, "{}", champs.join("\t"));
        }
        f.ajouter(&t);
    } else {
        f.ajouter("(PowerShell)");
        f.manques.push(Manque {
            quoi: Bi::new("Services", "Services"),
            raison: Raison::SansPowerShell,
        });
    }
    f.section("root/subscription (WMI)");
    if let Some(abonnements) =
        section(abonnements_natifs.as_deref(), "WMI").or_else(|| section(sortie.as_deref(), "WMI"))
    {
        f.lues += 1;
        if abonnements.is_empty() {
            f.ajouter("(aucun / none)");
        }
        for a in abonnements {
            let champs: Vec<String> = a.split(SEP).map(super::champ).collect();
            f.ajouter(&champs.join("\t"));
        }
    } else {
        // L'espace root/subscription ne se lit qu'en administrateur ; sans réponse du tout, PowerShell est en cause.
        // En administrateur, un PowerShell qui a répondu sans WMI_FIN dit que Get-CimInstance a échoué, pas lui.
        let raison = if sortie.is_none() {
            Raison::SansPowerShell
        } else if administrateur() {
            Raison::Erreur("Get-CimInstance root/subscription : échec / failed".into())
        } else {
            Raison::Droits
        };
        f.ajouter(&raison.note());
        f.manques.push(Manque {
            quoi: Bi::new("Abonnements WMI permanents", "Permanent WMI subscriptions"),
            raison,
        });
    }
    p.manques.append(&mut f.manques);
    p.evenements.extend(chronologie::lancements(&f.dates));
    if p.ecrire(
        dossier,
        "03-demarrage.txt",
        &f.texte,
        Bi::new(
            "ce qui se lance tout seul, tel quel : tâches planifiées (schtasks, et la liste datée de leurs fichiers), clés Run et RunOnce, Winlogon, AppInit_DLLs, AutoRun, BootExecute, dossiers Démarrage, services (programme et compte), abonnements WMI permanents",
            "what starts by itself, as is: scheduled tasks (schtasks, and the dated list of their files), Run and RunOnce keys, Winlogon, AppInit_DLLs, AutoRun, BootExecute, Startup folders, services (program and account), permanent WMI subscriptions",
        ),
    ) {
        p.compte = Some(bi!("{} source(s) lue(s)", "{} source(s) read", f.lues));
    }
    p
}

/// Les comptes locaux (activé, dernière connexion, mot de passe changé, SID) et les administrateurs, par le SID du
/// groupe (son nom change avec la langue).
const SCRIPT_COMPTES: &str = "function D($t) { if ($t) { $t.ToString('yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) } }; \
     try { Get-LocalUser | ForEach-Object { 'USR|' + (N $_.Name) + $s + $_.Enabled + $s + (D $_.LastLogon) + $s + (D $_.PasswordLastSet) + $s + $_.SID.Value + $s + (N $_.Description) }; 'USR_FIN' } catch {}; \
     try { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { 'ADM|' + (N $_.Name) + $s + $_.ObjectClass + $s + $_.PrincipalSource }; 'ADM_FIN' } catch {}";

pub(super) fn comptes(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Comptes", "Accounts"));
    let mut f = Feuille::new(&p.titre);
    // L'API réseau d'abord (NetUserEnum, NetLocalGroupGetMembers), sans PowerShell ; le script seulement pour ce
    // qu'elle n'a pas lu.
    let comptes_natifs = crate::machine::windows::comptes::comptes_des_traces(SEP);
    let admins_natifs = crate::machine::windows::comptes::administrateurs_des_traces(SEP);
    let sortie = (comptes_natifs.is_none() || admins_natifs.is_none())
        .then(|| crate::machine::windows::ps(&format!("{N}{SCRIPT_COMPTES}")))
        .flatten();
    let utilisateurs: Option<Vec<&str>> = match &comptes_natifs {
        Some(c) => Some(c.iter().map(String::as_str).collect()),
        None => section(sortie.as_deref(), "USR"),
    };
    f.section(if comptes_natifs.is_some() {
        "NetUserEnum + NetUserGetInfo (USER_INFO_4)"
    } else {
        "Get-LocalUser"
    });
    if let Some(u) = &utilisateurs {
        f.lues += 1;
        p.evenements = chronologie::comptes_windows(u, SEP, &chrono::Local);
        let mut t = String::from(
            "NOM/NAME\tACTIVÉ/ENABLED\tDERNIÈRE CONNEXION/LAST LOGON\tMOT DE PASSE/PASSWORD SET\tSID\tDESCRIPTION\n",
        );
        for l in u {
            let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
            let _ = writeln!(t, "{}", champs.join("\t"));
        }
        f.ajouter(&t);
    } else {
        f.ajouter("(PowerShell)");
        f.commande(&mut console("net user"), 15, true);
    }
    let administrateurs: Option<Vec<&str>> = match &admins_natifs {
        Some(a) => Some(a.iter().map(String::as_str).collect()),
        None => section(sortie.as_deref(), "ADM"),
    };
    f.section(if admins_natifs.is_some() {
        "NetLocalGroupGetMembers S-1-5-32-544"
    } else {
        "Get-LocalGroupMember -SID S-1-5-32-544"
    });
    if let Some(a) = administrateurs {
        f.lues += 1;
        for l in a {
            let champs: Vec<String> = l.split(SEP).map(super::champ).collect();
            f.ajouter(&champs.join("\t"));
        }
    } else {
        // PowerShell a pu répondre (USR lu) et seul Get-LocalGroupMember échouer : un membre orphelin
        // (compte de domaine ou Azure AD disparu) le fait lever ; chercher un PowerShell bloqué
        // serait une fausse piste.
        let raison = if sortie.is_none() {
            Raison::SansPowerShell
        } else {
            Raison::Erreur("Get-LocalGroupMember : échec / failed".into())
        };
        f.ajouter(&raison.note());
        f.manques.push(Manque {
            quoi: Bi::new("Administrateurs", "Administrators"),
            raison,
        });
    }
    f.commande(&mut console("query user"), 15, false);
    p.manques.append(&mut f.manques);
    if p.ecrire(
        dossier,
        "04-comptes.txt",
        &f.texte,
        Bi::new(
            "comptes locaux (activé, dernière connexion, mot de passe changé, SID), administrateurs, sessions ouvertes ; les connexions elles-mêmes (4624, 4625) sont dans le journal de sécurité",
            "local accounts (enabled, last logon, password set, SID), administrators, open sessions; the logons themselves (4624, 4625) are in the security log",
        ),
    ) {
        p.compte = Some(match utilisateurs {
            Some(u) => bi!("{} comptes", "{} accounts", u.len()),
            None => bi!("{} source(s) lue(s)", "{} source(s) read", f.lues),
        });
    }
    p
}

/// Les journaux exportés : (journal, fichier, titre, réservé à l'administrateur).
const JOURNAUX: [(&str, &str, (&str, &str), bool); 4] = [
    ("System", "05-System.evtx", ("Journal Système", "System log"), false),
    (
        "Security",
        "05-Security.evtx",
        ("Journal de sécurité", "Security log"),
        true,
    ),
    (
        "Microsoft-Windows-PowerShell/Operational",
        "05-PowerShell.evtx",
        ("Journal de PowerShell", "PowerShell log"),
        false,
    ),
    (
        "Microsoft-Windows-Windows Defender/Operational",
        "05-Defender.evtx",
        ("Journal de Windows Defender", "Windows Defender log"),
        false,
    ),
];

/// Les événements des 7 derniers jours (604 800 000 ms), dans la syntaxe XPath de wevtutil.
const SEPT_JOURS: &str = "/q:*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]";

/// La taille d'un journal d'après « wevtutil gli » (« fileSize: 1052672 »).
pub(crate) fn taille_gli(sortie: &str) -> Option<u64> {
    sortie
        .lines()
        .find_map(|l| l.trim().strip_prefix("fileSize:"))?
        .trim()
        .parse()
        .ok()
}

/// Pourquoi wevtutil a refusé, d'après son message (en anglais ou en français).
pub(crate) fn raison_wevtutil(erreurs: &str) -> Raison {
    let e = erreurs.to_lowercase();
    if e.contains("access is denied") || e.contains("accès refusé") || e.contains("acces refuse") {
        Raison::Droits
    } else if ["not found", "not be found", "introuvable", "n'existe pas"]
        .iter()
        .any(|m| e.contains(m))
    {
        Raison::Introuvable
    } else {
        Raison::Erreur(erreurs.lines().next().unwrap_or_default().trim().to_string())
    }
}

/// Le fichier .evtx d'un journal, tel que les traces le décrivent.
fn produit_du_journal(nom: &str, journal: &str, fr: &str, en: &str) -> Produit {
    Produit {
        nom: nom.into(),
        contenu: bi!(
            "{fr} ({journal}), les événements des 7 derniers jours, au format .evtx (Observateur d'événements)",
            "{en} ({journal}), the events of the last 7 days, as .evtx (Event Viewer)"
        ),
    }
}

pub(super) fn journaux(dossier: &Path) -> Partie {
    let mut p = Partie::new(Bi::new("Journaux", "Logs"));
    let admin = administrateur();
    let mut lus = Vec::new();
    let mut total = 0;
    // Les provisoires qu'un export d'avant, fini après son délai, aurait laissés dans le dossier temporaire : des
    // copies de journaux, à ne pas laisser traîner.
    for f in std::fs::read_dir(std::env::temp_dir()).into_iter().flatten().flatten() {
        let n = f.file_name().to_string_lossy().into_owned();
        if n.starts_with("vanguard-")
            && n.contains("-05-")
            && std::path::Path::new(&n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        {
            let _ = std::fs::remove_file(f.path());
        }
    }
    for (journal, nom, (fr, en), reserve) in JOURNAUX {
        let titre = Bi::new(fr, en);
        if reserve && !admin {
            p.manque(titre, Raison::Droits);
            continue;
        }
        let destination = dossier.join(nom);
        // L'API des journaux d'abord (EvtExportLog, le fichier que wevtutil epl écrit) ; wevtutil seulement si elle
        // échoue pour une autre raison qu'un refus ou un canal absent, qu'il dirait pareil.
        let requete = SEPT_JOURS.trim_start_matches("/q:");
        // Écrit d'abord dans le dossier temporaire, déplacé à sa place une fois fini : un export qui aboutirait après
        // le délai ne laisse rien dans le dossier des traces.
        let provisoire = std::env::temp_dir().join(format!("vanguard-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_file(&provisoire);
        let exporte = export_journaux::exporter(journal, requete, &provisoire, std::time::Duration::from_secs(120));
        let exporte = match exporte {
            Ok(()) if provisoire.is_file() => {
                let place = std::fs::rename(&provisoire, &destination)
                    .or_else(|_| std::fs::copy(&provisoire, &destination).map(|_| ()));
                let _ = std::fs::remove_file(&provisoire);
                if place.is_ok() {
                    Ok(())
                } else {
                    Err(export_journaux::Refus::Code(0))
                }
            }
            Ok(()) => Err(export_journaux::Refus::Code(0)),
            Err(export_journaux::Refus::Delai) => Err(export_journaux::Refus::Delai),
            Err(e) => {
                let _ = std::fs::remove_file(&provisoire);
                Err(e)
            }
        };
        match exporte {
            Ok(()) if destination.is_file() => {
                total += std::fs::metadata(&destination).map_or(0, |m| m.len());
                lus.push((fr, en));
                p.fichiers.push(produit_du_journal(nom, journal, fr, en));
                continue;
            }
            Err(export_journaux::Refus::Code(5)) => {
                p.manque(titre, Raison::Droits);
                continue;
            }
            Err(export_journaux::Refus::Code(15007)) => {
                p.manque(titre, Raison::Introuvable);
                continue;
            }
            Err(export_journaux::Refus::Delai) => {
                p.manque(titre, Raison::Delai(120));
                continue;
            }
            // Une réussite sans fichier, ou une autre erreur : wevtutil essaie à son tour (un fichier à moitié écrit
            // est d'abord retiré, wevtutil refusant d'écraser).
            _ => {
                let _ = std::fs::remove_file(&destination);
            }
        }
        let debut = std::time::Instant::now();
        let r = crate::commande::lancer(
            crate::commande::systeme("wevtutil")
                .args(["epl", journal])
                .arg(&destination)
                .arg(SEPT_JOURS),
            120,
        );
        match r {
            None if debut.elapsed().as_secs() >= 120 => p.manque(titre, Raison::Delai(120)),
            None => p.manque(titre, Raison::Absente("wevtutil".into())),
            // Codes de Windows : 5, accès refusé ; 15007, journal introuvable (Defender retiré, par exemple). Le
            // message, lui, est dans la langue et la page de code de la console.
            Some(r) if r.code == Some(5) => p.manque(titre, Raison::Droits),
            Some(r) if r.code == Some(15007) => p.manque(titre, Raison::Introuvable),
            Some(r) if r.code != Some(0) => p.manque(titre, raison_wevtutil(&format!("{}{}", r.erreurs, r.sortie))),
            // Une réussite sans fichier (wevtutil de Wine, qui ne fait rien) n'est pas une réussite.
            Some(_) if !destination.is_file() => {
                p.manque(
                    titre,
                    Raison::Erreur("wevtutil : aucun fichier écrit / no file written".into()),
                );
            }
            Some(_) => {
                total += std::fs::metadata(&destination).map_or(0, |m| m.len());
                lus.push((fr, en));
                p.fichiers.push(produit_du_journal(nom, journal, fr, en));
            }
        }
    }
    if !lus.is_empty() {
        #[allow(clippy::cast_precision_loss)]
        let mo = total as f64 / f64::from(1u32 << 20);
        let liste_fr = lus.iter().map(|(fr, _)| *fr).collect::<Vec<_>>().join(", ");
        let liste_en = lus.iter().map(|(_, en)| *en).collect::<Vec<_>>().join(", ");
        p.compte = Some(Bi::new(
            format!("{liste_fr} : {mo:.0} Mo (7 jours)"),
            format!("{liste_en}: {mo:.0} MB (7 days)"),
        ));
    }
    p
}

/// Une lecture d'un journal pour la chronologie.
struct LectureChronologie {
    journal: &'static str,
    /// Les numéros voulus, en XPath.
    numeros: &'static str,
    /// Un filtre sur les valeurs, en XPath, s'il en faut un.
    filtre: Option<&'static str>,
    max: usize,
    titre: (&'static str, &'static str),
}

/// Les lectures des journaux pour la chronologie, les plus récents d'abord, chacune bornée : une rafale d'échecs de
/// connexion n'éteint pas les autres. Les ouvertures de session sont filtrées dans la requête (au clavier, Bureau à
/// distance, en cache ; par le réseau depuis une autre machine) : celles des services se comptent par milliers.
const LECTURES_CHRONOLOGIE: [LectureChronologie; 7] = [
    LectureChronologie {
        journal: "Security",
        numeros: "EventID=4624",
        filtre: Some(
            "EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10' or Data[@Name='LogonType']='11']",
        ),
        max: 1000,
        titre: ("Ouvertures de session (4624)", "Logons (4624)"),
    },
    LectureChronologie {
        journal: "Security",
        numeros: "EventID=4624",
        filtre: Some(
            "EventData[Data[@Name='LogonType']='3' and Data[@Name='IpAddress']!='-' and Data[@Name='IpAddress']!='127.0.0.1' and Data[@Name='IpAddress']!='::1']",
        ),
        max: 500,
        titre: ("Ouvertures de session par le réseau (4624)", "Network logons (4624)"),
    },
    LectureChronologie {
        journal: "Security",
        numeros: "EventID=4625",
        filtre: None,
        max: 1000,
        titre: ("Échecs d'ouverture de session (4625)", "Failed logons (4625)"),
    },
    LectureChronologie {
        journal: "Security",
        numeros: "EventID=4720 or EventID=4732 or EventID=4697 or EventID=4698 or EventID=1102",
        filtre: None,
        max: 500,
        titre: (
            "Comptes, services, tâches, journal effacé (4720, 4732, 4697, 4698, 1102)",
            "Accounts, services, tasks, log cleared (4720, 4732, 4697, 4698, 1102)",
        ),
    },
    LectureChronologie {
        journal: "System",
        numeros: "EventID=7045 or EventID=104",
        filtre: None,
        max: 300,
        titre: (
            "Services installés, journaux effacés (7045, 104)",
            "Services installed, logs cleared (7045, 104)",
        ),
    },
    LectureChronologie {
        journal: "Microsoft-Windows-PowerShell/Operational",
        numeros: "EventID=4104",
        filtre: None,
        max: 300,
        titre: ("Blocs de script PowerShell (4104)", "PowerShell script blocks (4104)"),
    },
    LectureChronologie {
        journal: "Microsoft-Windows-Windows Defender/Operational",
        numeros: "EventID=1116 or EventID=1117 or EventID=5001",
        filtre: None,
        max: 300,
        titre: (
            "Détections et protection de Defender (1116, 1117, 5001)",
            "Defender detections and protection (1116, 1117, 5001)",
        ),
    },
];

/// La requête XPath d'une lecture : ses numéros, les 7 derniers jours, et son filtre s'il en a un.
fn requete_chronologie(numeros: &str, filtre: Option<&str>) -> String {
    let jours = u64::try_from(chronologie::JOURS).unwrap_or(7) * 86_400_000;
    let mut r = format!("*[System[({numeros}) and TimeCreated[timediff(@SystemTime) <= {jours}]]");
    if let Some(f) = filtre {
        r.push_str(" and ");
        r.push_str(f);
    }
    r.push(']');
    r
}

/// Ce que dit le code d'erreur laissé par EvtQuery quand un journal refuse.
fn raison_evtquery(code: Option<i32>, delai: bool) -> Raison {
    match code {
        _ if delai => Raison::Delai(30),
        Some(5) => Raison::Droits,
        // Journal introuvable (Defender retiré, PowerShell sans journal opérationnel).
        Some(2 | 15007) => Raison::Introuvable,
        Some(c) => Raison::Erreur(format!("EvtQuery : code {c}")),
        None => Raison::Erreur("EvtQuery".into()),
    }
}

/// Les événements des journaux de Windows pour la chronologie, lus par wevtapi sans PowerShell (30 s en tout), puis
/// les alertes des règles EVT- (une minute de plus au plus). Le
/// journal de sécurité ne se lit qu'en administrateur : sans, c'est dit une fois. Chaque journal qui refuse est dit.
pub(super) fn evenements_des_journaux(_dossier: &Path) -> Apport {
    let mut apport = lire_journaux_chronologie(administrateur());
    let alertes = alertes_des_journaux();
    apport.evenements.extend(alertes.evenements);
    apport.manques.extend(alertes.manques);
    apport
}

/// Les alertes des règles `EVT-` sur les journaux de cet ordinateur, des 7 jours de la chronologie, pour qu'elles y
/// soient à leur place dans le temps ; l'analyse est versée comme celle de `vanguard journaux-windows` (le rapport la
/// reprend). Une minute au plus : au-delà, les plus anciens ne sont pas lus, et c'est dit.
fn alertes_des_journaux() -> Apport {
    use crate::journaux_windows::regles::{moteur::Options, resultat};
    let debut = (chrono::Utc::now(), std::time::Instant::now());
    let options = Options {
        depuis: Some(debut.0 - chrono::Duration::days(chronologie::JOURS)),
        defender_antivirus: None,
        installation: None,
    };
    let a = resultat::analyser_vivant(&options, debut.1 + std::time::Duration::from_secs(60));
    let est_normale = |cle: &str| crate::protection::normales::est_normale(cle);
    crate::modele::resultat::verser(&resultat::resultat(&a, debut, &est_normale));
    super::journaux_windows::alertes_des_journaux(&a, &est_normale)
}

fn lire_journaux_chronologie(admin: bool) -> Apport {
    use crate::machine::windows::evenements::parcourir_nommes;
    const REQUETE_INVALIDE: i32 = 15001;
    let fin = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut apport = Apport::default();
    if !admin {
        apport.manques.push(Manque {
            quoi: Bi::new(
                "Chronologie : journal de sécurité (sessions, échecs, comptes, services, tâches, effacement)",
                "Timeline: security log (logons, failures, accounts, services, tasks, clearing)",
            ),
            raison: Raison::Droits,
        });
    }
    for &LectureChronologie {
        journal,
        numeros,
        filtre,
        max,
        titre: (fr, en),
    } in &LECTURES_CHRONOLOGIE
    {
        if journal == "Security" && !admin {
            continue;
        }
        let mut evenements = Vec::new();
        let mut lire = |filtre: Option<&str>| {
            evenements.clear();
            let lu = parcourir_nommes(
                journal,
                &requete_chronologie(numeros, filtre),
                max,
                fin,
                |id, date, v| {
                    let e = chronologie::evenement_windows(id, date, v)?;
                    evenements.push(e);
                    Some(String::new())
                },
            );
            // Le code d'EvtQuery, lu aussitôt : rien d'autre n'a appelé Windows entre-temps.
            (lu, std::io::Error::last_os_error().raw_os_error())
        };
        let (mut lu, mut code) = lire(filtre);
        // Un filtre sur les valeurs que ce Windows ne comprendrait pas : la même lecture sans lui, le tri se fait ici.
        if lu.is_none() && code == Some(REQUETE_INVALIDE) && filtre.is_some() {
            (lu, code) = lire(None);
        }
        let quoi = bi!("Chronologie : {fr}", "Timeline: {en}");
        if let Some(lignes) = lu {
            apport.manques.extend(lecture_coupee(quoi, lignes.len(), max));
            apport.evenements.append(&mut evenements);
        } else {
            apport.manques.push(Manque {
                quoi,
                raison: raison_evtquery(code, std::time::Instant::now() >= fin),
            });
        }
    }
    apport
}

/// Une lecture (`quoi`) qui atteint sa borne, `max` événements : les plus anciens de la semaine manquent, et c'est
/// dit, comme sous Linux. Une rafale d'échecs de connexion qui remplit la sienne ne passe plus pour toute la semaine.
fn lecture_coupee(quoi: Bi, lus: usize, max: usize) -> Option<Manque> {
    (lus >= max).then_some(Manque {
        quoi,
        raison: Raison::Entrees(max),
    })
}

/// Pas de montage à écarter sous Windows : un autre système de fichiers y est un autre lecteur.
pub(super) fn points_de_montage() -> Vec<PathBuf> {
    Vec::new()
}

/// La place que peuvent prendre les journaux : leur taille entière, au plus (l'export ne garde que 7 jours).
pub(super) fn place_des_journaux() -> u64 {
    JOURNAUX
        .iter()
        .map(|(journal, ..)| {
            // EvtGetLogInfo d'abord ; wevtutil gli s'il ne répond pas.
            export_journaux::taille(journal)
                .or_else(|| {
                    crate::commande::lancer(crate::commande::systeme("wevtutil").args(["gli", journal]), 15)
                        .and_then(|r| taille_gli(&r.sortie))
                })
                .unwrap_or(20 << 20)
        })
        .sum()
}

/// Les dossiers où un programme dépose ce qu'il lance, en plus de TEMP (déjà dans les endroits à risque) : le profil
/// Public, ouvert à tous les comptes, et le dossier Démarrage commun.
pub(super) fn endroits_temporaires() -> Vec<PathBuf> {
    [
        std::env::var_os("PUBLIC").map(PathBuf::from),
        std::env::var_os("ProgramData")
            .map(|d| PathBuf::from(d).join(r"Microsoft\Windows\Start Menu\Programs\StartUp")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_par_chemins_complets() {
        let chemin = |nom: &str| PathBuf::from(format!(r"C:\Windows\System32\{nom}"));
        assert_eq!(
            ligne_console("tasklist /v /fo csv", chemin),
            r#"""C:\Windows\System32\chcp.com" 65001 >nul & "C:\Windows\System32\tasklist" /v /fo csv""#
        );
        assert_eq!(
            ligne_console("arp", chemin),
            r#"""C:\Windows\System32\chcp.com" 65001 >nul & "C:\Windows\System32\arp"""#
        );
    }

    #[test]
    fn abonnement_sur_une_ligne() {
        assert_eq!(sur_une_ligne(" a\r\nb\u{1f}c  "), "a b c");
        // Sous Wine, root/subscription n'existe pas : pas de section, donc « non lu », jamais « aucun ».
        if std::path::Path::new(r"C:\windows\system32\wineboot.exe").is_file() {
            assert!(abonnements_wmi().is_none());
        }
    }

    #[test]
    fn valeurs_du_registre() {
        let utf16 = |t: &str| t.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
        assert_eq!(
            texte_registre("REG_SZ", &utf16("C:\\Windows\\explorer.exe\0")),
            "C:\\Windows\\explorer.exe"
        );
        assert_eq!(
            texte_registre("REG_MULTI_SZ", &utf16("autocheck autochk *\0autre\0\0")),
            "autocheck autochk *\\0autre"
        );
        assert_eq!(texte_registre("REG_DWORD", &1u32.to_le_bytes()), "0x1");
        assert_eq!(
            texte_registre("REG_QWORD", &0x1_0000_0000u64.to_le_bytes()),
            "0x100000000"
        );
        assert_eq!(texte_registre("REG_BINARY", &[0x01, 0xAB]), "01AB");
        // Une valeur mal formée ne plante pas : montrée en hexadécimal.
        assert_eq!(texte_registre("REG_DWORD", &[1, 2]), "0102");
        assert_eq!(texte_registre("REG_SZ", &[0x41]), "");
    }

    /// Le vrai registre (celui de Wine ici, puis de la VM) : une clé à espaces se lit, une clé absente le dit.
    #[test]
    fn cles_du_registre_lues() {
        let (texte, ecrite) = cle_registre(r"HKLM\Software\Microsoft\Windows NT\CurrentVersion", None).unwrap();
        assert!(texte.contains("REG_SZ"), "{texte}");
        // La date de la dernière écriture de la clé : après 2000, pas dans le futur.
        let maintenant = chronologie::secondes(std::time::SystemTime::now()).unwrap();
        assert!(
            ecrite.is_some_and(|t| (946_684_800..=maintenant + 86_400).contains(&t)),
            "{ecrite:?}"
        );
        assert_eq!(
            cle_registre(r"HKLM\Software\Vanguard\Cle qui n existe pas", None),
            Err("(clé absente / key not found)".to_string())
        );
        assert!(cle_registre(r"HKXX\Software", None).is_err());
    }

    #[test]
    fn lignes_des_scripts() {
        let s = SEP;
        let lignes = [
            format!("4242{s}1000{s}PC\\alice{s}2026-10-20 14:03:22{s}C:\\Users\\alice\\AppData\\x.exe{s}x.exe -a | b"),
            format!("4{s}0{s}{s}{s}{s}"),
            "illisible".to_string(),
        ];
        let lignes: Vec<&str> = lignes.iter().map(String::as_str).collect();
        let p = lire_processus(&lignes);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].0, 4242);
        assert_eq!(p[0].1, Some(1000));
        assert_eq!(p[0].2, "PC\\alice");
        assert_eq!(p[0].5, "x.exe -a | b");
        assert_eq!(p[1].4, "");
        let t = tableau_reseau(&[&format!(
            "TCP{s}Established{s}10.0.0.2:50000{s}203.0.113.5:4444{s}4242{s}x"
        )]);
        assert!(
            t.ends_with("TCP\tEstablished\t10.0.0.2:50000\t203.0.113.5:4444\t4242\tx\n"),
            "{t}"
        );
    }

    #[test]
    fn requetes_de_la_chronologie() {
        assert_eq!(
            requete_chronologie("EventID=4625", None),
            "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 604800000]]]"
        );
        let r = requete_chronologie("EventID=4624", Some("EventData[Data[@Name='LogonType']='10']"));
        assert!(r.ends_with("]] and EventData[Data[@Name='LogonType']='10']]"), "{r}");
        assert_eq!(r.matches('[').count(), r.matches(']').count());
        assert_eq!(raison_evtquery(Some(5), false), Raison::Droits);
        assert_eq!(raison_evtquery(Some(15007), false), Raison::Introuvable);
        assert_eq!(raison_evtquery(Some(5), true), Raison::Delai(30));
        assert!(matches!(raison_evtquery(Some(1), false), Raison::Erreur(_)));
    }

    /// Une lecture qui atteint sa borne (1000, 500 ou 300) est dite coupée, avec ce qu'elle lisait ; en deçà, rien.
    #[test]
    fn lecture_bornee_dite() {
        for l in &LECTURES_CHRONOLOGIE {
            let quoi = bi!("Chronologie : {}", "Timeline: {}", l.titre.0);
            let m = lecture_coupee(quoi.clone(), l.max, l.max).expect(l.titre.0);
            assert_eq!(
                m,
                Manque {
                    quoi,
                    raison: Raison::Entrees(l.max)
                }
            );
            assert!(lecture_coupee(Bi::meme("x"), l.max - 1, l.max).is_none());
        }
        assert_eq!(
            Raison::Entrees(1000).texte(),
            Bi::new(
                "coupé à 1000 entrées, les plus anciennes ne sont pas gardées",
                "cut at 1000 entries, the oldest are not kept"
            )
        );
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : chaque journal est lu ou dit, jamais passé sous
    /// silence ; sans droits, le journal de sécurité n'est pas demandé et c'est dit une fois.
    #[test]
    fn journaux_de_la_chronologie_lus_ou_dits() {
        for admin in [false, true] {
            let a = lire_journaux_chronologie(admin);
            let securite = LECTURES_CHRONOLOGIE.iter().filter(|l| l.journal == "Security").count();
            let autres = LECTURES_CHRONOLOGIE.len() - securite;
            let dits = a.manques.len();
            if admin {
                assert!(dits <= LECTURES_CHRONOLOGIE.len(), "{:?}", a.manques);
            } else {
                assert!(
                    a.manques[0].raison == Raison::Droits && dits <= 1 + autres,
                    "{:?}",
                    a.manques
                );
            }
            assert!(a.evenements.iter().all(|e| e.source == chronologie::Source::Journal));
        }
    }

    #[test]
    fn reponses_de_wevtutil() {
        assert_eq!(
            taille_gli("creationTime: 2026-01-01\nfileSize: 1052672\nattributes: 32"),
            Some(1_052_672)
        );
        assert_eq!(taille_gli("rien"), None);
        assert_eq!(
            raison_wevtutil("Failed to export log Security. Access is denied."),
            Raison::Droits
        );
        assert_eq!(raison_wevtutil("Échec de l'exportation. Accès refusé."), Raison::Droits);
        assert_eq!(
            raison_wevtutil("Failed to export log X. The specified channel could not be found."),
            Raison::Introuvable
        );
        assert!(matches!(raison_wevtutil("Autre chose"), Raison::Erreur(_)));
    }

    /// Les scripts envoyés à PowerShell, tels qu'ils partent : écrits dans le dossier des tests pour être analysés
    /// par pwsh (VANGUARD_SCRIPTS : le dossier où les copier).
    /// Les tables et le registre de Windows (Wine ici, la VM ensuite), sans PowerShell : lignes complètes, dans la
    /// forme des scripts.
    #[test]
    fn reseau_et_services_sans_powershell() {
        for (texte, section_, champs) in [(lignes_reseau(), "NET", 6), (lignes_services(), "SRV", 5)] {
            let texte = texte.expect(section_);
            let l = section(Some(&texte), section_).expect(section_);
            assert!(l.iter().all(|l| l.split(SEP).count() == champs), "{texte}");
        }
        assert_eq!(n(" a\r\nb\u{1f}c "), "a b c");
    }

    /// Win32_Process répond sous Wine : des lignes à six champs, ce processus parmi elles, avec son compte.
    #[test]
    fn processus_lus_directement() {
        let texte = lignes_processus().expect("Win32_Process répond");
        let lignes = section(Some(&texte), "PRC").expect("PRC_FIN");
        let p = lire_processus(&lignes);
        assert_eq!(p.len(), lignes.len());
        let moi = p.iter().find(|x| x.0 == std::process::id()).expect("ce processus");
        assert_ne!(moi.2, "");
    }

    #[test]
    fn scripts_complets() {
        let scripts = [
            ("processus", format!("{N}{SCRIPT_PROCESSUS}")),
            ("reseau", format!("{N}{SCRIPT_RESEAU}")),
            ("demarrage", format!("{N}{SCRIPT_DEMARRAGE}")),
            ("comptes", format!("{N}{SCRIPT_COMPTES}")),
        ];
        for (nom, s) in &scripts {
            for marque in ["PRC_FIN", "NET_FIN", "SRV_FIN", "WMI_FIN", "USR_FIN", "ADM_FIN"] {
                if s.contains(&marque[..3]) {
                    assert!(s.contains(marque), "{nom} : {marque}");
                }
            }
            if let Some(d) = std::env::var_os("VANGUARD_SCRIPTS") {
                let mut contenu = vec![0xef, 0xbb, 0xbf];
                contenu.extend_from_slice(s.as_bytes());
                std::fs::write(PathBuf::from(d).join(format!("traces-{nom}.ps1")), contenu).unwrap();
            }
        }
    }
}
