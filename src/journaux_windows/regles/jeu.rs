//! Les règles `EVT-`, écrites d'après la documentation de Microsoft de chaque événement (noms des
//! champs, sens des valeurs, politique d'audit d'origine d'un Windows 10 ou 11) et la technique d'ATT&CK qu'il
//! trahit ; vérifiées sur les échantillons publics (`VANGUARD_EVTX_ECHANTILLONS`). Rien n'est repris d'un autre jeu
//! de règles.
//!
//! D'origine sur un poste Windows 10 (depuis la 1809) ou 11 (colonne « Windows Default » de « Audit Policy
//! Recommendations », <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations>) :
//! Audit Logon en succès et en échec (4624, 4625, 4648), User Account Management et Security Group Management en
//! succès (4720, 4738, 4732) ; 1102 et 4719 s'écrivent quelle que soit la politique d'audit. Les journaux
//! « Operational » lus ici sont actifs d'origine ; un journal désactivé se voit (`EtatJournal::active`).
//!
//! Les valeurs des champs viennent de l'ordinateur jugé, parfois d'un attaquant qui connaît ces règles : les chemins
//! se comparent sans casse, barres obliques ramenées à « \ », guillemets ôtés ; les variables d'environnement et les
//! noms courts 8.3 qui pourraient cacher un dossier se voient eux-mêmes ; les groupes se reconnaissent à leur SID,
//! jamais à leur nom traduit.

use std::net::IpAddr;
use std::sync::LazyLock;

use crate::{liste_masquee, mot_masque};

use super::evenement::EvenementWindows;
use super::moteur::{Audit, Condition, Forme, Gravite, Indice, Libelle, Regle, Test, Texte, Volet, couper, nombre};

/// Le fournisseur des événements de sécurité.
const AUDIT: &[&str] = &["Microsoft-Windows-Security-Auditing"];
/// Celui du gestionnaire de services (7045, 7040).
const SCM: &[&str] = &["Service Control Manager"];
/// Celui du service des journaux (1102, 104).
const EVENTLOG: &[&str] = &["Microsoft-Windows-Eventlog"];

/// La valeur d'un champ, rognée ; vide s'il n'y est pas.
fn champ<'e>(e: &'e EvenementWindows, nom: &str) -> &'e str {
    e.champ(nom).map_or("", str::trim)
}

/// Un champ qui dit quelque chose : ni vide ni « - ».
fn rempli(v: &str) -> bool {
    !v.is_empty() && v != "-"
}

/// Un chemin ou une ligne de commande comparable : minuscules, « / » ramené à « \ ».
fn chemin_bas(t: &str) -> String {
    t.trim().to_lowercase().replace('/', "\\")
}

/// Une ligne de commande aux tirets ramenés à « - » : PowerShell prend aussi les tirets typographiques (U+2010 à
/// U+2015) et le signe moins (U+2212) pour annoncer une option, et « –enc » cachait ainsi la commande encodée aux
/// règles, qui ne cherchent que « -enc ».
fn tirets(t: &str) -> String {
    t.chars()
        .map(|c| {
            if matches!(c, '\u{2010}'..='\u{2015}' | '\u{2212}') {
                '-'
            } else {
                c
            }
        })
        .collect()
}

/// L'instant d'un événement, pour l'objet d'un événement ponctuel (un journal effacé, une protection coupée) :
/// déclarer normal celui-là ne fait pas taire les suivants.
fn instant(e: &EvenementWindows) -> String {
    match (e.date, e.numero) {
        (Some(d), _) => d.format("%Y-%m-%dT%H:%M:%S").to_string(),
        (None, Some(n)) => format!("n{n}"),
        (None, None) => "?".to_string(),
    }
}

// Rend une `Option` pour que chaque juge finisse sur une seule expression, comme ses refus (`return None`).
#[allow(clippy::unnecessary_wraps)]
fn indice(objet: String, gravite: Gravite, pourquoi: Texte, details: Vec<(Libelle, String)>) -> Option<Indice> {
    Some(Indice {
        objet,
        gravite,
        pourquoi,
        details: details.into_iter().filter(|(_, v)| rempli(v)).collect(),
        mise_en_route: None,
    })
}

/// Un indice que la mise en route de Windows donne aussi, avec le pourquoi à dire si c'est elle.
fn ou_mise_en_route(i: Option<Indice>, e: &EvenementWindows, pendant: Texte) -> Option<Indice> {
    i.map(|i| Indice {
        mise_en_route: par_l_ordinateur(e).then_some(pendant),
        ..i
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Programmes et chemins
// ---------------------------------------------------------------------------------------------------------------

/// Les interpréteurs et les programmes de Windows qui font exécuter autre chose (« vivre sur le terrain ») : un
/// service, un compte qui se connecte avec d'autres identifiants, qui passent par eux font ce que font les outils
/// d'attaque (PsExec et ses copies, Metasploit, Cobalt Strike installent un service qui lance cmd ou PowerShell).
const INTERPRETES: &[&str] = &[
    "cmd",
    "powershell",
    "powershell_ise",
    "pwsh",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "wmic",
    "msbuild",
    "installutil",
    "regasm",
    "regsvcs",
    "cmstp",
    "odbcconf",
    "forfiles",
];

/// Des interpréteurs de scripts que des programmes légitimes lancent aussi en service (un serveur Node.js, un
/// outil en Python) : moins sûrs qu'un cmd ou un PowerShell de service, qui ne sert qu'aux attaques.
const AUTRES_INTERPRETES: &[&str] = &["bash", "wsl", "python", "pythonw", "node"];

fn est_autre_interprete(nom: &str) -> bool {
    AUTRES_INTERPRETES.contains(&nom)
}

/// Ce qu'une ligne de commande contient quand elle lance un interpréteur ou du code encodé, où qu'il soit (après
/// « /c », dans un argument).
const LANCEMENTS: &[&str] = &[
    "cmd.exe",
    "cmd /c",
    "cmd /k",
    "%comspec%",
    "powershell",
    "pwsh",
    "mshta",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "frombase64string",
    "-encodedcommand",
    " -enc ",
    " -ec ",
    "downloadstring",
];

/// Des dossiers où un compte ordinaire écrit : un service ou un pilote qui s'y trouve peut être remplacé par
/// n'importe quel programme de ce compte, et rien ne s'installe normalement là.
/// Les dossiers temporaires, parmi les inscriptibles.
const TEMPORAIRES: &[&str] = &["\\temp\\", "\\tmp\\", "%temp%", "%tmp%"];

const INSCRIPTIBLES: &[&str] = &[
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\tmp\\",
    "%temp%",
    "%tmp%",
    "%appdata%",
    "%localappdata%",
    "%userprofile%",
    "%public%",
    "%homepath%",
    "\\perflogs\\",
    "\\$recycle.bin\\",
    "\\windows\\tasks\\",
    "\\windows\\tracing\\",
    "\\spool\\drivers\\color\\",
];

/// Le programme d'une ligne de commande (sans guillemets) et le reste. Sans guillemets, le programme s'arrête à la
/// première extension de programme suivie d'un blanc (« C:\Program Files\X\x.exe -a ») ; à défaut, au premier
/// blanc.
fn decouper(commande: &str) -> (String, String) {
    let c = commande.trim();
    if let Some(reste) = c.strip_prefix('"') {
        return match reste.find('"') {
            Some(i) => (reste[..i].to_string(), reste[i + 1..].to_string()),
            None => (reste.to_string(), String::new()),
        };
    }
    let bas = c.to_ascii_lowercase();
    for ext in [".exe", ".sys", ".com", ".bat", ".cmd", ".dll", ".scr"] {
        let mut depuis = 0;
        while let Some(i) = bas[depuis..].find(ext) {
            let fin = depuis + i + ext.len();
            if bas[fin..].chars().next().is_none_or(char::is_whitespace) {
                return (c[..fin].to_string(), c[fin..].to_string());
            }
            depuis = fin;
        }
    }
    match c.find(char::is_whitespace) {
        Some(i) => (c[..i].to_string(), c[i..].to_string()),
        None => (c.to_string(), String::new()),
    }
}

/// Le nom d'un programme sans dossier ni extension, en minuscules.
fn nom_programme(chemin: &str) -> String {
    let bas = chemin_bas(chemin);
    let nom = bas.rsplit('\\').next().unwrap_or(&bas);
    match nom.rsplit_once('.') {
        Some((n, x)) if ["exe", "com", "bat", "cmd", "sys", "dll", "scr"].contains(&x) => n.to_string(),
        _ => nom.to_string(),
    }
}

/// Un interpréteur, sous son nom ou sous son nom court 8.3 (« POWERS~1.EXE », « RUNDLL~1 ») : le nom court se
/// forme des six premiers caractères, un tilde et un chiffre.
fn est_interprete(nom: &str) -> bool {
    if INTERPRETES.contains(&nom) {
        return true;
    }
    match nom.split_once('~') {
        Some((debut, fin)) if !debut.is_empty() && fin.chars().next().is_some_and(|c| c.is_ascii_digit()) => {
            INTERPRETES
                .iter()
                .any(|i| i.starts_with(debut) && (debut.len() >= 6 || debut == *i))
        }
        _ => false,
    }
}

/// Un nom court 8.3 dans un dossier du chemin (« C:\PROGRA~3\ ») : il cache le nom du dossier.
fn nom_court(chemin_bas: &str) -> bool {
    chemin_bas.split('\\').any(|p| {
        p.split_once('~').is_some_and(|(debut, fin)| {
            (1..=6).contains(&debut.len()) && fin.chars().next().is_some_and(|c| c.is_ascii_digit())
        })
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Adresses
// ---------------------------------------------------------------------------------------------------------------

/// D'où vient une adresse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lieu {
    /// Cet ordinateur ou le réseau local : boucle, RFC 1918, lien local, IPv6 locale unique (fc00::/7), rien.
    Local,
    /// 100.64.0.0/10 (RFC 6598) : le partage d'adresses d'un opérateur, ou un réseau privé par-dessus Internet
    /// (Tailscale s'y range) : ni local, ni Internet à coup sûr.
    Partage,
    Internet,
    /// Pas une adresse lisible.
    Illisible,
}

/// Classe une adresse telle que Windows l'écrit (« 192.0.2.10 », « ::ffff:192.0.2.10 », « fe80::1%12 », « - »,
/// « LOCAL »).
pub(crate) fn lieu(adresse: &str) -> Lieu {
    let a = adresse.trim().trim_start_matches('[').trim_end_matches(']');
    if a.is_empty() || a == "-" || a.eq_ignore_ascii_case("local") || a.eq_ignore_ascii_case("localhost") {
        return Lieu::Local;
    }
    let sans_zone = a.split('%').next().unwrap_or(a);
    let Ok(ip) = sans_zone.parse::<IpAddr>() else {
        return Lieu::Illisible;
    };
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() {
                Lieu::Local
            } else if o[0] == 100 && (64..128).contains(&o[1]) {
                Lieu::Partage
            } else {
                Lieu::Internet
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() || v.is_unspecified() || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xfe00) == 0xfc00 {
                Lieu::Local
            } else {
                Lieu::Internet
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-EFF-001 : traces effacées
// ---------------------------------------------------------------------------------------------------------------

fn auteur(e: &EvenementWindows) -> String {
    let (d, n) = (champ(e, "SubjectDomainName"), champ(e, "SubjectUserName"));
    match (rempli(d), rempli(n)) {
        (true, true) => format!("{d}\\{n}"),
        (false, true) => n.to_string(),
        _ => champ(e, "SubjectUserSid").to_string(),
    }
}

fn securite_effacee(e: &EvenementWindows) -> Option<Indice> {
    indice(
        format!("security|{}", instant(e)),
        Gravite::Alerte,
        (
            "le journal de sécurité a été effacé (rien ne l'efface d'ordinaire : c'est ce que fait un attaquant qui cache ses traces)",
            "the security log was cleared (nothing normally clears it: this is what an attacker hiding their tracks does)",
        ),
        vec![(Libelle::Auteur, auteur(e))],
    )
}

fn journal_efface(e: &EvenementWindows) -> Option<Indice> {
    let journal = champ(e, "Channel");
    indice(
        format!("{}|{}", journal.to_lowercase(), instant(e)),
        Gravite::Alerte,
        (
            "un journal d'événements a été effacé (une désinstallation peut vider le sien ; sinon, des traces cachées)",
            "an event log was cleared (an uninstaller may empty its own; otherwise, hidden tracks)",
        ),
        vec![(Libelle::Journal, journal.to_string()), (Libelle::Auteur, auteur(e))],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-SRV-001 : service d'attaque installé
// ---------------------------------------------------------------------------------------------------------------

/// Les services des outils qui lancent des commandes à distance (PsExec, PAExec, RemCom, CSExec, winexe) et de
/// l'éditeur d'identifiants WCE : par le nom du service ou de son programme, en minuscules.
const OUTILS_DE_SERVICE: &[&str] = &[
    "psexesvc",
    "paexec",
    "remcomsvc",
    "csexecsvc",
    "winexesvc",
    "wceservice",
];

/// Les mises à jour des définitions de Defender installent un pilote « MpKsl » suivi de chiffres hexadécimaux
/// depuis leur dossier, à chaque mise à jour (noté par Microsoft) : ce dossier est protégé par Defender lui-même.
/// Le programme doit y être, pas seulement la ligne de commande le nommer.
fn pilote_de_defender(nom: &str, programme_bas: &str) -> bool {
    const DOSSIER: &str = "c:\\programdata\\microsoft\\windows defender\\definition updates\\";
    let nom = nom.to_ascii_lowercase();
    let hexa = nom
        .strip_prefix("mpksl")
        .is_some_and(|r| !r.is_empty() && r.chars().all(|c| c.is_ascii_hexdigit()));
    let chemin = programme_bas.strip_prefix("\\??\\").unwrap_or(programme_bas);
    hexa && chemin.starts_with(DOSSIER) && !chemin.contains("\\..\\")
}

/// Le chemin d'un programme sans ses préfixes de chemin long ou de l'espace de noms du noyau (« \\?\ »,
/// « \??\ ») ; un partage réseau sous ces formes (« \\?\UNC\hôte\ ») redevient « \\hôte\ ».
fn sans_prefixe(programme_bas: &str) -> String {
    for p in ["\\\\?\\unc\\", "\\??\\unc\\"] {
        if let Some(r) = programme_bas.strip_prefix(p) {
            return format!("\\\\{r}");
        }
    }
    for p in ["\\\\?\\", "\\??\\"] {
        if let Some(r) = programme_bas.strip_prefix(p) {
            return r.to_string();
        }
    }
    programme_bas.to_string()
}

/// Les programmes de Microsoft qui s'installent à la racine du dossier de Windows : Sysmon (Sysinternals) et son
/// pilote, vus dans un échantillon public.
const RACINE_CONNUS: &[&str] = &["sysmon", "sysmon64", "sysmondrv"];

/// Le dossier de Windows, sous ses noms.
fn dans_windows(chemin: &str) -> Option<&str> {
    ["c:\\windows\\", "%systemroot%\\", "%windir%\\", "\\systemroot\\"]
        .iter()
        .find_map(|p| chemin.strip_prefix(p))
}

/// Ce qu'un nouveau service a de suspect : sa gravité, pourquoi, et si son objet doit oublier les chiffres de son
/// chemin (un pilote d'outil de matériel posé dans un dossier temporaire numéroté à chaque version) ; rien pour un
/// service ordinaire.
pub(crate) fn service_suspect(nom: &str, image: &str) -> Option<(Gravite, Texte, bool)> {
    let (programme, arguments) = decouper(image);
    let programme_bas = sans_prefixe(&chemin_bas(&programme));
    let arguments_bas = tirets(&chemin_bas(&arguments));
    let nom_prog = nom_programme(&programme_bas);
    // Le programme lui-même, ou ce que ses arguments lancent : pas le nom d'un dossier (« PowerShell Universal »).
    if est_interprete(&nom_prog)
        || chemin_bas(image).contains("%comspec%")
        || LANCEMENTS
            .iter()
            .any(|l| arguments_bas.contains(l) || format!(" {arguments_bas} ").contains(l))
    {
        return Some((
            Gravite::Critique,
            (
                "le service lance un interpréteur de commandes ou du code encodé, comme les outils d'attaque qui s'installent à distance",
                "the service runs a command interpreter or encoded code, like attack tools that install themselves remotely",
            ),
            false,
        ));
    }
    if pilote_de_defender(nom, &chemin_bas(&programme)) {
        return None;
    }
    if est_autre_interprete(&nom_prog) {
        return Some((
            Gravite::Alerte,
            (
                "le service lance un interpréteur de scripts (Python, Node.js, Bash) : des programmes légitimes le font, des portes dérobées aussi",
                "the service runs a script interpreter (Python, Node.js, Bash): legitimate programs do, backdoors too",
            ),
            false,
        ));
    }
    if OUTILS_DE_SERVICE
        .iter()
        .any(|o| nom.to_lowercase().starts_with(o) || nom_prog.starts_with(o))
    {
        return Some((
            Gravite::Alerte,
            (
                "le service est celui d'un outil qui lance des commandes à distance (PsExec et ses semblables) : un administrateur s'en sert, et c'est l'outil le plus utilisé par les attaquants pour passer d'un ordinateur à l'autre",
                "the service belongs to a tool that runs commands remotely (PsExec and the like): administrators use it, and it is the tool attackers use most to move from one computer to another",
            ),
            false,
        ));
    }
    if !programme_bas.contains('\\') && !programme_bas.starts_with('%') && !programme_bas.is_empty() {
        return Some((
            Gravite::Alerte,
            (
                "le service n'a pas de dossier : son programme est cherché ailleurs, là où un autre du même nom peut l'attendre",
                "the service has no folder: its program is looked up elsewhere, where another one with the same name may wait",
            ),
            false,
        ));
    }
    if programme_bas.starts_with("\\\\") {
        return Some((
            Gravite::Alerte,
            (
                "le service est lancé depuis un partage réseau",
                "the service is run from a network share",
            ),
            false,
        ));
    }
    let pilote = nom_prog.len() < programme_bas.len()
        && std::path::Path::new(&programme_bas)
            .extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("sys"));
    if INSCRIPTIBLES.iter().any(|d| programme_bas.contains(d)) {
        if pilote && TEMPORAIRES.iter().any(|d| programme_bas.contains(d)) {
            return Some((
                Gravite::Info,
                (
                    "un pilote a été posé depuis un dossier temporaire : des outils de matériel le font (CPU-Z, HWiNFO, GPU-Z), et aussi les attaquants qui apportent un pilote vulnérable pour couper l'antivirus",
                    "a driver was loaded from a temporary folder: hardware tools do it (CPU-Z, HWiNFO, GPU-Z), and so do attackers bringing a vulnerable driver to kill the antivirus",
                ),
                true,
            ));
        }
        return Some((
            Gravite::Alerte,
            (
                "le service est rangé dans un dossier où un compte ordinaire écrit (profil, dossier temporaire), où rien ne s'installe normalement",
                "the service is stored in a folder an ordinary account can write to (profile, temporary folder), where nothing is normally installed",
            ),
            false,
        ));
    }
    // Un programme posé à la racine du dossier de Windows : l'endroit où psexec d'Impacket et Metasploit déposent
    // le leur sous un nom tiré au hasard (le partage ADMIN$).
    if dans_windows(&programme_bas).is_some_and(|r| !r.is_empty() && !r.contains('\\'))
        && !RACINE_CONNUS.contains(&nom_prog.as_str())
    {
        return Some((
            Gravite::Alerte,
            (
                "le programme du service est posé à la racine du dossier de Windows, où les outils d'attaque à distance déposent le leur",
                "the service program sits at the root of the Windows folder, where remote attack tools drop theirs",
            ),
            false,
        ));
    }
    if programme_bas.contains("\\programdata\\") {
        return Some((
            Gravite::Info,
            (
                "le service est rangé dans ProgramData, où tout compte peut créer des dossiers ; certains programmes y installent le leur",
                "the service is stored in ProgramData, where any account can create folders; some programs install theirs there",
            ),
            false,
        ));
    }
    if nom_court(&programme_bas) {
        return Some((
            Gravite::Info,
            (
                "le chemin du service passe par un nom court 8.3, qui cache le nom du dossier",
                "the service path goes through an 8.3 short name, which hides the folder name",
            ),
            false,
        ));
    }
    let dossier_des_pilotes = ["system32\\drivers\\", "system32\\driverstore\\", "syswow64\\drivers\\"]
        .iter()
        .any(|d| programme_bas.contains(d));
    let connu_a_la_racine =
        RACINE_CONNUS.contains(&nom_prog.as_str()) && dans_windows(&programme_bas).is_some_and(|r| !r.contains('\\'));
    if pilote && !dossier_des_pilotes && !connu_a_la_racine {
        return Some((
            Gravite::Info,
            (
                "un pilote du noyau est installé hors du dossier des pilotes de Windows (les anti-triche des jeux le font ; un pilote vulnérable apporté aussi)",
                "a kernel driver is installed outside the Windows driver folder (game anti-cheats do; a vulnerable driver brought along too)",
            ),
            false,
        ));
    }
    None
}

fn service_installe(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "ServiceName");
    let image = champ(e, "ImagePath");
    let (gravite, pourquoi, sans_chiffres) = service_suspect(nom, image)?;
    let mut objet = format!("{}|{}", nom.to_lowercase(), chemin_bas(image));
    if sans_chiffres {
        // « cpuz154\cpuz154_x64.sys » et « cpuz160\cpuz160_x64.sys » : le même outil, une seule normale.
        objet = objet
            .chars()
            .map(|c| if c.is_ascii_digit() { '#' } else { c })
            .collect();
    }
    indice(
        objet,
        gravite,
        pourquoi,
        vec![
            (Libelle::Service, nom.to_string()),
            (Libelle::Commande, image.to_string()),
            (Libelle::Demarrage, champ(e, "StartType").to_string()),
            (Libelle::Compte, champ(e, "AccountName").to_string()),
        ],
    )
}

/// Un service installé (7045 du gestionnaire de services, journal System) que rien ne rend suspect : son nom, que le
/// bilan liste en une information (WIN-JRN-003). Seulement d'un événement vérifié : un morceau abîmé n'ajoute rien.
pub(crate) fn service_ordinaire(e: &EvenementWindows) -> Option<String> {
    if e.id != 7045
        || !e.verifie
        || !e.journal.eq_ignore_ascii_case(SYSTEM)
        || !SCM.iter().any(|f| f.eq_ignore_ascii_case(e.fournisseur.trim()))
    {
        return None;
    }
    // Jugé exactement comme par `service_installe` (même champ, mêmes valeurs) : un service est soit une alerte,
    // soit listé, jamais ni l'un ni l'autre.
    let nom = champ(e, "ServiceName");
    (rempli(nom) && service_installe(e).is_none()).then(|| nom.to_string())
}

fn journal_des_evenements_change(e: &EvenementWindows) -> Option<Indice> {
    indice(
        format!("eventlog|{}", instant(e)),
        Gravite::Critique,
        (
            "le démarrage du service des journaux d'événements a été changé : coupé, Windows n'écrit plus aucun journal",
            "the start type of the event log service was changed: once off, Windows writes no log at all",
        ),
        vec![
            (Libelle::Service, champ(e, "param1").to_string()),
            (Libelle::AncienneValeur, champ(e, "param2").to_string()),
            (Libelle::NouvelleValeur, champ(e, "param3").to_string()),
        ],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-ADM-001 : un administrateur de plus
// ---------------------------------------------------------------------------------------------------------------

/// L'auteur est le compte de l'ordinateur lui-même (SYSTEM, S-1-5-18, que le journal écrit « DOMAINE\ORDINATEUR$ ») :
/// c'est lui qui, pendant la mise en route de Windows, crée le premier compte et le met administrateur. C'est aussi ce
/// qu'obtient un attaquant qui a pris la main : seulement pendant l'installation (`moteur::Options::installation`).
fn par_l_ordinateur(e: &EvenementWindows) -> bool {
    champ(e, "SubjectUserSid").eq_ignore_ascii_case("S-1-5-18")
}

fn compte_cree(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "TargetUserName");
    let details = vec![(Libelle::Compte, nom.to_string()), (Libelle::Auteur, auteur(e))];
    // Un compte d'ordinateur (nom en « $ ») se crée par 4741 sur un contrôleur de domaine, jamais par 4720 : un
    // compte d'utilisateur ainsi nommé se cache parmi eux (« net user » ne le montre pas).
    if nom.ends_with('$') {
        return indice(
            format!("cree:{}", nom.to_lowercase()),
            Gravite::Critique,
            (
                "un compte d'utilisateur au nom finissant par « $ » a été créé : il se cache parmi les comptes d'ordinateurs",
                "a user account whose name ends with “$” was created: it hides among computer accounts",
            ),
            details,
        );
    }
    ou_mise_en_route(
        indice(
            format!("cree:{}", nom.to_lowercase()),
            Gravite::Info,
            ("un compte a été créé", "an account was created"),
            details,
        ),
        e,
        (
            "un compte a été créé pendant l'installation de Windows, par le compte de l'ordinateur : la mise en route crée ainsi le premier compte",
            "an account was created during Windows setup, by the computer account: setup creates the first account this way",
        ),
    )
}

/// Les groupes locaux intégrés qui donnent la main sur l'ordinateur, par leur SID (le nom est traduit :
/// « Administrateurs », « Administrators »).
const GROUPES_LOCAUX: &[(&str, Gravite, Texte)] = &[
    (
        "S-1-5-32-544",
        Gravite::Alerte,
        (
            "un compte a été ajouté au groupe des Administrateurs",
            "an account was added to the Administrators group",
        ),
    ),
    (
        "S-1-5-32-555",
        Gravite::Alerte,
        (
            "un compte a été ajouté aux utilisateurs du Bureau à distance : il peut ouvrir une session à distance",
            "an account was added to Remote Desktop Users: it can log on remotely",
        ),
    ),
    (
        "S-1-5-32-551",
        Gravite::Alerte,
        (
            "un compte a été ajouté aux Opérateurs de sauvegarde, qui lisent tous les fichiers",
            "an account was added to Backup Operators, who can read every file",
        ),
    ),
    (
        "S-1-5-32-548",
        Gravite::Alerte,
        (
            "un compte a été ajouté aux Opérateurs de compte",
            "an account was added to Account Operators",
        ),
    ),
    (
        "S-1-5-32-549",
        Gravite::Alerte,
        (
            "un compte a été ajouté aux Opérateurs de serveur",
            "an account was added to Server Operators",
        ),
    ),
    (
        "S-1-5-32-580",
        Gravite::Alerte,
        (
            "un compte a été ajouté aux utilisateurs de la gestion à distance",
            "an account was added to Remote Management Users",
        ),
    ),
];

/// Les groupes de domaine privilégiés, par la fin de leur SID (RID) : Admins du domaine (512), Administrateurs du
/// schéma (518), de l'entreprise (519), Propriétaires créateurs de stratégie de groupe (520).
const RID_DOMAINE: &[&str] = &["-512", "-518", "-519", "-520"];

/// Le membre ajouté : son SID (MemberName vaut « - » pour un groupe local, dit Microsoft), à défaut son nom.
fn membre(e: &EvenementWindows) -> String {
    let sid = champ(e, "MemberSid");
    if rempli(sid) {
        sid.to_string()
    } else {
        champ(e, "MemberName").to_string()
    }
}

fn ajout_groupe_local(e: &EvenementWindows) -> Option<Indice> {
    let sid = champ(e, "TargetSid");
    let &(s, gravite, pourquoi) = GROUPES_LOCAUX.iter().find(|(s, _, _)| s.eq_ignore_ascii_case(sid))?;
    let i = indice(
        format!("groupe:{}:{}", s.to_lowercase(), membre(e).to_lowercase()),
        gravite,
        pourquoi,
        vec![
            (Libelle::Groupe, champ(e, "TargetUserName").to_string()),
            (Libelle::Membre, membre(e)),
            (Libelle::Auteur, auteur(e)),
        ],
    );
    // La mise en route ne met le premier compte que parmi les Administrateurs (et les Utilisateurs, que la règle ne
    // regarde pas) : un ajout au Bureau à distance ou aux Opérateurs de sauvegarde reste une alerte.
    if !s.eq_ignore_ascii_case(ADMINISTRATEURS) {
        return i;
    }
    ou_mise_en_route(
        i,
        e,
        (
            "un compte a été ajouté au groupe des Administrateurs pendant l'installation de Windows, par le compte de l'ordinateur : la mise en route y met ainsi le premier compte",
            "an account was added to the Administrators group during Windows setup, by the computer account: setup puts the first account there this way",
        ),
    )
}

/// Le groupe local des Administrateurs.
const ADMINISTRATEURS: &str = "S-1-5-32-544";

fn ajout_groupe_domaine(e: &EvenementWindows) -> Option<Indice> {
    let sid = champ(e, "TargetSid").to_ascii_uppercase();
    if !sid.starts_with("S-1-5-21-") || !RID_DOMAINE.iter().any(|r| sid.ends_with(r)) {
        return None;
    }
    indice(
        format!("groupe:{}:{}", sid.to_lowercase(), membre(e).to_lowercase()),
        Gravite::Alerte,
        (
            "un compte a été ajouté à un groupe privilégié du domaine",
            "an account was added to a privileged domain group",
        ),
        vec![
            (Libelle::Groupe, champ(e, "TargetUserName").to_string()),
            (Libelle::Membre, membre(e)),
            (Libelle::Auteur, auteur(e)),
        ],
    )
}

/// Les drapeaux du compte (OldUacValue, NewUacValue) : désactivé (0x1), sans mot de passe exigé (0x4), d'après la
/// table de l'événement 4720.
const DESACTIVE: u64 = 0x1;
const SANS_MOT_DE_PASSE: u64 = 0x4;

fn compte_change(e: &EvenementWindows) -> Option<Indice> {
    let (Some(avant), Some(apres)) = (
        e.champ("OldUacValue").and_then(nombre),
        e.champ("NewUacValue").and_then(nombre),
    ) else {
        return None;
    };
    let sid = champ(e, "TargetSid").to_ascii_uppercase();
    let integre = sid.starts_with("S-1-5-21-") && (sid.ends_with("-500") || sid.ends_with("-501"));
    let details = vec![
        (Libelle::Compte, champ(e, "TargetUserName").to_string()),
        (Libelle::Auteur, auteur(e)),
        (Libelle::Changement, format!("{avant:#x} → {apres:#x}")),
    ];
    if integre && avant & DESACTIVE != 0 && apres & DESACTIVE == 0 {
        return indice(
            format!("active:{}", sid.to_lowercase()),
            Gravite::Alerte,
            (
                "le compte Administrateur ou Invité intégré, désactivé d'origine, a été activé",
                "the built-in Administrator or Guest account, disabled by default, was enabled",
            ),
            details,
        );
    }
    if avant & SANS_MOT_DE_PASSE == 0 && apres & SANS_MOT_DE_PASSE != 0 {
        return indice(
            format!("sans-mot-de-passe:{}", sid.to_lowercase()),
            Gravite::Alerte,
            (
                "un compte a été réglé pour ne plus exiger de mot de passe",
                "an account was set to no longer require a password",
            ),
            details,
        );
    }
    None
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-MDP-001 : mot de passe deviné
// ---------------------------------------------------------------------------------------------------------------

/// Les types de connexion où quelqu'un tape ou envoie un mot de passe (table de l'événement 4624) : à l'écran (2),
/// par le réseau (3), au déverrouillage (7), en clair (8), au Bureau à distance (10), et leurs variantes
/// mises en cache (11, 12, 13). Les tâches (4) et services (5) en échec ont un mot de passe enregistré périmé.
const TYPES_DEVINABLES: &[u64] = &[2, 3, 7, 8, 10, 11, 12, 13];
const DEVINABLE: Condition = Condition::Champ("LogonType", Test::NombreDans(TYPES_DEVINABLES));

/// Dix échecs en dix minutes : le seuil de verrouillage de compte d'origine de Windows 11 (« Account lockout
/// threshold », 10 tentatives ; « Account lockout duration », 10 minutes).
const ECHECS: usize = 10;
const FENETRE_ECHECS: i64 = 600;
/// « Juste après » : une connexion réussie au plus cinq minutes après le dernier échec.
const DELAI_REUSSITE: i64 = 300;

const DEVINE: Texte = (
    "des échecs de connexion en rafale : quelqu'un essaie de deviner un mot de passe",
    "a burst of failed logons: someone is trying to guess a password",
);
/// Cinq échecs en dix secondes, tous comptes confondus : plus vite qu'une personne ne tape ; un programme essaie des
/// mots de passe (vu dans les échantillons publics : un outil local, seize essais en une seconde sur deux comptes ;
/// une attaque par SSH, cinq en deux secondes).
const ECHECS_RAPIDES: usize = 5;
const FENETRE_RAPIDE: i64 = 10;
const DEVINE_VITE: Texte = (
    "des échecs de connexion plus rapides qu'une personne ne tape : un programme essaie des mots de passe (ou un programme réglé avec un mot de passe périmé)",
    "failed logons faster than a person types: a program is trying passwords (or a program set with an outdated password)",
);

const DEVINE_ET_ENTRE: Texte = (
    "une connexion réussie juste après une rafale d'échecs : le mot de passe a peut-être été deviné",
    "a successful logon right after a burst of failures: the password may have been guessed",
);

// ---------------------------------------------------------------------------------------------------------------
// EVT-RDP-001 : Bureau à distance depuis l'extérieur
// ---------------------------------------------------------------------------------------------------------------

/// Une adresse de boucle (127.0.0.0/8, ::1, ::ffff:127.x) : cet ordinateur lui-même.
fn boucle(adresse: &str) -> bool {
    let a = adresse.trim().trim_start_matches('[').trim_end_matches(']');
    match a.split('%').next().unwrap_or(a).parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => v.is_loopback(),
        Ok(IpAddr::V6(v)) => v.is_loopback() || v.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
        Err(_) => false,
    }
}

/// Un compte sans son domaine, en minuscules (« POSTE\alice », « alice@domaine » : « alice »).
fn compte_seul(compte: &str) -> String {
    let bas = compte.trim().to_lowercase();
    let sans = bas.rsplit('\\').next().unwrap_or(&bas);
    sans.split('@').next().unwrap_or(sans).to_string()
}

fn distance(adresse: &str, compte: &str) -> Option<Indice> {
    // Une session de Bureau à distance qui arrive par la boucle locale est passée par un tunnel (ngrok, plink,
    // chisel : T1572) qui la fait entrer par cet ordinateur lui-même.
    let (lieu_dit, gravite, pourquoi) = match lieu(adresse) {
        Lieu::Local if boucle(adresse) => (
            "tunnel",
            Gravite::Alerte,
            (
                "une session de Bureau à distance est arrivée par la boucle locale : passée par un tunnel, qui cache d'où elle vient",
                "a Remote Desktop session came in through the loopback address: through a tunnel, which hides where it comes from",
            ),
        ),
        Lieu::Local => return None,
        Lieu::Internet => (
            "internet",
            Gravite::Alerte,
            (
                "une session de Bureau à distance a été ouverte depuis une adresse d'Internet : le Bureau à distance est exposé",
                "a Remote Desktop session was opened from an Internet address: Remote Desktop is exposed",
            ),
        ),
        Lieu::Partage => (
            "partage",
            Gravite::Info,
            (
                "une session de Bureau à distance depuis une adresse partagée (100.64.0.0/10 : opérateur, ou réseau privé comme Tailscale)",
                "a Remote Desktop session from a shared address (100.64.0.0/10: carrier, or a private network such as Tailscale)",
            ),
        ),
        Lieu::Illisible => (
            "illisible",
            Gravite::Info,
            (
                "une session de Bureau à distance depuis une adresse illisible",
                "a Remote Desktop session from an unreadable address",
            ),
        ),
    };
    // L'objet : le compte et d'où (Internet, tunnel…), pas l'adresse, qui change à chaque connexion depuis un
    // téléphone ; une même session (4624, puis 21 et 1149 qui nomment le compte avec son domaine) ne fait qu'un.
    indice(
        format!("{lieu_dit}|{}", compte_seul(compte)),
        gravite,
        pourquoi,
        vec![
            (Libelle::Adresse, adresse.to_string()),
            (Libelle::Compte, compte.to_string()),
        ],
    )
}

fn rdp_securite(e: &EvenementWindows) -> Option<Indice> {
    distance(champ(e, "IpAddress"), champ(e, "TargetUserName"))
}

fn rdp_session(e: &EvenementWindows) -> Option<Indice> {
    distance(champ(e, "Address"), champ(e, "User"))
}

fn rdp_authentifie(e: &EvenementWindows) -> Option<Indice> {
    let compte = match (champ(e, "Param2"), champ(e, "Param1")) {
        (d, n) if rempli(d) => format!("{d}\\{n}"),
        (_, n) => n.to_string(),
    };
    distance(champ(e, "Param3"), &compte)
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-IDE-001 : connexion avec d'autres identifiants
// ---------------------------------------------------------------------------------------------------------------

/// Les programmes de Windows qui se servent d'identifiants donnés exprès dans l'ordinaire (4648, « une activité
/// courante du système » selon Microsoft) : ouverture de session et services (winlogon, lsass, services, svchost),
/// élévation (consent), tâches planifiées (taskhostw), « Exécuter en tant que » (runas, cité par Microsoft),
/// l'Explorateur qui monte un lecteur réseau avec un autre compte, le client Bureau à distance (mstsc) et la
/// console d'administration (mmc) ; vus dans les échantillons publics sains : wininit (l'hôte des pilotes de
/// polices, compte UMFD-0, à chaque démarrage), taskeng (les tâches de Windows 7), et la première mise en route
/// (msoobe, CloudExperienceHostBroker), et le spouleur d'impression (une imprimante réseau) ; vus sur un Windows 11
/// installé le jour même : UserOOBEBroker (la mise en route, qui connecte le compte Microsoft) et le serveur OpenSSH
/// de Windows (System32\OpenSSH, une fonctionnalité facultative de Windows : chaque connexion SSH par mot de passe
/// passe par un 4648 de sshd, sous SYSTEM, pour le compte qui se connecte ou pour son compte virtuel « `sshd_<pid>` »).
/// Une connexion SSH elle-même se juge ailleurs (échecs en rafale : EVT-MDP-001). Ailleurs, rien de
/// Windows ne le fait : un programme inhabituel l'a fait. Ce que la règle ne voit pas : « Exécuter en tant que »
/// et ses semblables passent par le service d'ouverture de session secondaire (svchost), qu'elle ne peut pas
/// distinguer de l'ordinaire.
const IDENTIFIANTS_ATTENDUS: &[&str] = &[
    "c:\\windows\\system32\\winlogon.exe",
    "c:\\windows\\system32\\lsass.exe",
    "c:\\windows\\system32\\services.exe",
    "c:\\windows\\system32\\svchost.exe",
    "c:\\windows\\system32\\consent.exe",
    "c:\\windows\\system32\\taskhostw.exe",
    "c:\\windows\\system32\\runas.exe",
    "c:\\windows\\syswow64\\runas.exe",
    "c:\\windows\\explorer.exe",
    "c:\\windows\\system32\\mstsc.exe",
    "c:\\windows\\system32\\mmc.exe",
    "c:\\windows\\system32\\wininit.exe",
    "c:\\windows\\system32\\taskeng.exe",
    "c:\\windows\\system32\\oobe\\msoobe.exe",
    "c:\\windows\\system32\\oobe\\useroobebroker.exe",
    "c:\\windows\\system32\\openssh\\sshd.exe",
    "c:\\windows\\system32\\cloudexperiencehostbroker.exe",
    "c:\\windows\\system32\\spoolsv.exe",
];

/// Des noms de la liste qu'un programme légitime porte aussi ailleurs, et où : OpenSSH pour Windows publié par
/// Microsoft s'installe aussi dans Program Files (une version plus récente que celle de Windows), son sshd.exe n'y
/// est pas déguisé (seulement « à savoir », comme tout programme installé hors de la liste). Ailleurs, il l'est.
const NOMS_PARTAGES: &[(&str, &[&str])] = &[("sshd", &["c:\\program files\\", "c:\\program files (x86)\\"])];

/// Des dossiers d'où un programme qui se sert d'autres identifiants est douteux (avec les temporaires).
const DOUTEUX: &[&str] = &["\\downloads\\", "\\users\\public\\", "\\$recycle.bin\\", "\\perflogs\\"];

fn autres_identifiants(e: &EvenementWindows) -> Option<Indice> {
    let programme = champ(e, "ProcessName");
    if !rempli(programme) {
        // Sans programme (le noyau, System) : rien à juger.
        return None;
    }
    let bas = chemin_bas(programme);
    if IDENTIFIANTS_ATTENDUS.contains(&bas.as_str()) {
        return None;
    }
    let cible = champ(e, "TargetUserName");
    let serveur = champ(e, "TargetServerName");
    let details = vec![
        (Libelle::Programme, programme.to_string()),
        (Libelle::Compte, cible.to_string()),
        (Libelle::Serveur, serveur.to_string()),
        (Libelle::Auteur, auteur(e)),
    ];
    let objet = format!("{bas}|{}|{}", cible.to_lowercase(), serveur.to_lowercase());
    // Un programme installé pour un seul compte (Chrome, Teams, Zoom dans le profil) n'est qu'à savoir ; un
    // interpréteur, ou un programme d'un dossier temporaire, des téléchargements ou public, ce que font les outils.
    // Un programme qui porte le nom d'un des programmes de Windows de la liste, ailleurs que chez lui, se fait
    // passer pour lui.
    let nom = nom_programme(&bas);
    let partage = NOMS_PARTAGES
        .iter()
        .any(|(n, dossiers)| *n == nom && dossiers.iter().any(|d| bas.starts_with(d)));
    let deguise = !partage && IDENTIFIANTS_ATTENDUS.iter().any(|a| nom_programme(a) == nom);
    let douteux = deguise || TEMPORAIRES.iter().chain(DOUTEUX).any(|d| bas.contains(d));
    let (gravite, pourquoi) = if est_interprete(&nom_programme(&bas)) || douteux {
        (
            Gravite::Alerte,
            (
                "un interpréteur de commandes, ou un programme d'un dossier où un compte ordinaire écrit, s'est servi d'autres identifiants : ce que font les outils de vol d'identifiants et de déplacement d'un ordinateur à l'autre",
                "a command interpreter, or a program from a folder an ordinary account can write to, used other credentials: what credential theft and lateral movement tools do",
            ),
        )
    } else {
        (
            Gravite::Info,
            (
                "un programme s'est servi d'autres identifiants que ceux de sa session (des outils de sauvegarde ou d'administration le font aussi)",
                "a program used credentials other than those of its session (backup or administration tools do it too)",
            ),
        )
    };
    indice(objet, gravite, pourquoi, details)
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-PSH-001 : PowerShell malveillant
// ---------------------------------------------------------------------------------------------------------------

/// Un bloc de script comparable : minuscules, sans les accents graves (« Dow`nloadString ») ni les
/// concaténations de chaînes qui coupent un mot en deux (« 'Down'+'loadString' »). Le texte est déjà borné par la
/// lecture.
fn script_bas(texte: &str) -> String {
    let mut s: String = tirets(&texte.to_lowercase()).chars().filter(|&c| c != '`').collect();
    for coupure in ["'+'", "\"+\"", "' + '", "\" + \"", "'+\"", "\"+'", "')+('", "\")+(\""] {
        if s.contains(coupure) {
            s = s.replace(coupure, "");
        }
    }
    s
}

/// La forme ramassée d'un texte : sans blancs, guillemets, parenthèses, crochets, accolades, signes de
/// concaténation ni points. « ('Do'+'wn')+('loadStr'+'ing') », « [Net.WebClient] », « New-Object  Net . WebClient »
/// s'y lisent comme leur motif ramassé ; seuls les motifs d'au moins `RAMASSE_MIN` caractères y sont cherchés (un
/// motif court s'y trouverait à cheval sur deux mots).
fn ramasse(texte: &str) -> String {
    texte
        .chars()
        .filter(|c| !c.is_whitespace() && !"'\"`+()[]{}.,;&^$".contains(*c))
        .collect()
}

const RAMASSE_MIN: usize = 8;

/// Un bloc de script sous ses deux formes.
struct Script {
    bas: String,
    ramasse: String,
}

impl Script {
    fn de(texte: &str) -> Self {
        let bas = script_bas(texte);
        let ramasse = ramasse(&bas);
        Self { bas, ramasse }
    }

    fn contient(&self, motif: &str) -> bool {
        if contient_mot(&self.bas, motif) {
            return true;
        }
        // La forme ramassée seulement pour un motif de code (un point, un tiret, une parenthèse : « net.webclient »)
        // ou un nom qu'aucune phrase ne forme (« downloadstring ») : « # Download data » ramassé ferait
        // « downloaddata ».
        // Un motif à plusieurs mots (« -e powershell ») ne se ramasse pas : « the powershell » le formerait.
        let code = !motif.contains(' ') && motif.chars().any(|c| !c.is_ascii_alphanumeric());
        let m = ramasse(motif);
        (code || RAMASSABLES.iter().any(|r| r == motif))
            && m.chars().count() >= RAMASSE_MIN
            && self.ramasse.contains(&m)
    }
}

/// Des noms qui ne se forment pas par hasard en ramassant une phrase. La liste est masquée (`crate::masque`) parce
/// qu'elle contient des noms que reconnaîtrait un antivirus (les `amsi…`, `minidumpwritedump`) ; les autres entrées
/// (`downloadstring`, `virtualprotect`…) sont de simples noms d'API ou de cmdlets à double usage, présents en clair
/// dans d'innombrables programmes et ici même ailleurs (motifs plus bas, message montré) : les masquer ici ne les
/// cache nulle part, c'est seulement que la liste s'encode d'un bloc. On ne masque que ce qui *désigne un outil*.
static RAMASSABLES: LazyLock<Vec<String>> = liste_masquee![
    "downloadstring",
    "frombase64string",
    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "amsicontext",
    "amsiopensession",
    "minidumpwritedump",
    "virtualprotect",
    "getprocaddress",
];

/// `motif` dans `texte` ; un motif court qui commence par une lettre (« iex », « irm ») doit commencer un mot :
/// « -Confirm » ne contient pas « irm ».
fn contient_mot(texte: &str, motif: &str) -> bool {
    let court = motif.len() < RAMASSE_MIN && motif.starts_with(|c: char| c.is_ascii_alphabetic());
    if !court {
        return texte.contains(motif);
    }
    texte.match_indices(motif).any(|(i, _)| {
        texte[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric() && c != '-' && c != '_')
    })
}

/// Masqué (`crate::masque`) : les noms internes d'AMSI, qu'un antivirus reconnaîtrait en clair.
static AMSI: LazyLock<Vec<String>> = liste_masquee![
    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "amsicontext",
    "amsiopensession",
];

/// Des outils offensifs publiés, par les noms de leurs commandes : ils n'ont pas d'autre usage. Masqué
/// (`crate::masque`) : ces noms de commandes sont exactement ce qu'une signature d'antivirus cherche.
static OUTILS_OFFENSIFS: LazyLock<Vec<String>> = liste_masquee![
    "invoke-mimikatz",
    "sekurlsa::",
    "lsadump::",
    "kerberos::golden",
    "invoke-kerberoast",
    "invoke-shellcode",
    "invoke-reflectivepeinjection",
    "invoke-dllinjection",
    "powersploit",
    "invoke-bloodhound",
    "sharphound",
    "invoke-powershelltcp",
    "powercat",
    "invoke-dcsync",
    "invoke-tokenmanipulation",
    "get-gpppassword",
    "invoke-smbexec",
    "invoke-wmiexec",
    "invoke-thehash",
    "out-minidump",
    "get-keystrokes",
    "invoke-ninjacopy",
    "invoke-credentialinjection",
    "-e powershell",
    "-e cmd",
];

// Les listes qui suivent restent volontairement en clair : ce sont des noms d'API, de cmdlets et de techniques à
// double usage (télécharger, exécuter, écrire une clé, couper une protection), présents dans quantité de scripts
// d'administration légitimes et dans d'autres programmes. Elles ne *désignent pas un outil* précis, donc ne font pas
// qu'un antivirus prenne Vanguard pour tel outil ; le masquage (`crate::masque`) vise ce qui, seul, le trahirait.

/// Ce qui change le programme d'un service par le registre : la clé des services, la valeur, une écriture.
const SERVICES: &[&str] = &["currentcontrolset\\services\\"];
const VALEURS_DE_SERVICE: &[&str] = &["imagepath", "failurecommand"];
const ECRIRE_REGISTRE: &[&str] = &[
    "set-itemproperty",
    "new-itemproperty",
    "reg add",
    "reg.exe add",
    "setvalue(",
];

/// Des objets COM qui lancent des commandes, créés sur un autre ordinateur.
const DEPLACEMENT: &[&str] = &[
    "mmc20.application",
    "9ba05972-f6a8-11cf-a442-00a0c90a8f39",
    "c08afd90-f2a1-11d1-8455-00a0c91f3880",
];

/// Ce qui exécute un texte comme du code.
const EXECUTER: &[&str] = &[
    "iex(",
    "iex ",
    "|iex",
    "| iex",
    "invoke-expression",
    "[scriptblock]::create",
];

/// Ce qui télécharge.
const TELECHARGER: &[&str] = &[
    "net.webclient",
    "downloadfile",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "net.http.httpclient",
    "iwr ",
    "irm ",
    "curl ",
    "wget ",
];

/// Ce qui télécharge du texte en mémoire, presque toujours pour l'exécuter.
const TELECHARGER_EN_MEMOIRE: &[&str] = &["downloadstring", "downloaddata"];

/// Ce qui défait une valeur encodée en code.
const DECODER: &[&str] = &["frombase64string"];
const CHARGER: &[&str] = &["reflection.assembly]::load", "::load(", "-bxor"];

/// Ce qui réserve ou écrit de la mémoire, puis ce qui y lance un fil d'exécution : le chargeur de code en mémoire
/// (« shellcode ») de PowerShell le plus courant, sans fichier. PowerShell met ces noms parmi ceux qu'il juge
/// suspects (Avertissement) ; seuls, sans lancement, ils sont aussi ceux d'outils d'administration.
const ALLOUER: &[&str] = &["virtualalloc", "writeprocessmemory"];
const LANCER_FIL: &[&str] = &["createthread", "createremotethread", "getdelegateforfunctionpointer"];

/// Ce qui prend le jeton d'un autre programme pour agir sous son compte, puis ce qui s'en sert.
const COPIER_JETON: &[&str] = &["duplicatetokenex", "impersonateloggedonuser", "setthreadtoken"];
const SE_SERVIR_DU_JETON: &[&str] = &[
    "createprocesswithtoken",
    "openprocesstoken",
    "openthreadtoken",
    // Une ouverture de session avec un mot de passe, puis se faire passer pour ce compte dans le programme même.
    "logonuser",
];

/// Ce qui lit le clavier touche par touche, et ce qui traduit la touche : un enregistreur de frappe.
const LIRE_CLAVIER: &[&str] = &["getasynckeystate"];
const TRADUIRE_TOUCHE: &[&str] = &["getkeyboardstate", "mapvirtualkey", "tounicode"];

/// Ce qui demande des identifiants dans une fenêtre, les vérifie, puis en tire le mot de passe en clair : la fausse
/// fenêtre de connexion (ATT&CK T1056.002), qui redemande tant que le mot de passe est faux.
const DEMANDER: &[&str] = &["promptforcredential", "get-credential"];
const VERIFIER_MOT_DE_PASSE: &[&str] = &["validatecredentials"];
const EN_CLAIR: &[&str] = &["getnetworkcredential"];

/// Les réglages qui désarment Defender, par leur nom. Defender les déclare lui-même dans son module de PowerShell
/// (ConfigDefender : un module CDXML que Windows génère, que PowerShell journalise en Avertissement dès qu'on s'en
/// sert, Get-MpComputerStatus compris) : « ${DisableRealtimeMonitoring} », « ContainsKey('DisableRealtimeMonitoring') »,
/// « Name = 'DisableRealtimeMonitoring' ». Seul compte un nom employé pour régler (`reglage_employe`).
const REGLAGES_DE_DEFENDER: &[&str] = &[
    "disablerealtimemonitoring",
    "disableioavprotection",
    "disablebehaviormonitoring",
    "disablescriptscanning",
    "disablearchivescanning",
    "disableblockatfirstseen",
];

/// `reglage` employé pour régler, et pas seulement déclaré : passé en paramètre (« -DisableRealtimeMonitoring $true »,
/// « -DisableRealtimeMonitoring:1 »), nommé pour le registre (« -Name DisableRealtimeMonitoring », « -Name
/// 'DisableRealtimeMonitoring' », « reg add … /v DisableRealtimeMonitoring »), affecté (« $p.DisableRealtimeMonitoring =
/// $true », « @{DisableRealtimeMonitoring=1} », « 'DisableRealtimeMonitoring' = 1 ») ou passé à une méthode
/// (« SetValue('…', 'DisableRealtimeMonitoring', 1) »). `bas` : la forme comparable du script (`script_bas`).
fn reglage_employe(bas: &str, reglage: &str) -> bool {
    let guillemets: &[char] = &['\'', '"'];
    bas.match_indices(reglage).any(|(i, _)| {
        let avant = &bas[..i];
        let apres = bas[i + reglage.len()..].trim_start_matches(guillemets).trim_start();
        let nomme = avant
            .trim_end_matches(guillemets)
            .trim_end()
            .trim_end_matches('(')
            .trim_end();
        // Affecté par son index : « $h['DisableRealtimeMonitoring'] = $true », puis « Set-MpPreference @h ».
        let par_index = apres
            .strip_prefix(']')
            .map(str::trim_start)
            .is_some_and(|a| a.starts_with('=') && !a.starts_with("=="));
        // Donné par position, suivi de sa valeur : « Set-ItemProperty $k DisableRealtimeMonitoring 1 ».
        let valeur = apres.starts_with(|c: char| c.is_ascii_digit() || c == '$');
        // Le nom d'une table de paramètres (« @{Path=$k;Name='DisableRealtimeMonitoring';Value=1} », puis
        // « Set-ItemProperty @a ») ; celle du module CDXML porte aussi « ParameterType », qu'aucune commande de
        // réglage n'accepte.
        let table = (nomme.ends_with("name=") || nomme.ends_with("name =")) && {
            let suite: String = apres.chars().take_while(|&c| c != '}').collect();
            suite.contains("value") && !suite.contains("parametertype")
        };
        par_index
            || valeur
            || table
            || avant.ends_with('-')
            || nomme.ends_with("-name")
            || nomme.ends_with("-name:")
            || nomme.ends_with("/v")
            || (apres.starts_with('=') && !apres.starts_with("=="))
            || apres.starts_with(',')
    })
}

/// Ce qui coupe une défense de Defender (avec `REGLAGES_DE_DEFENDER`) ou efface un journal.
const DESARMER: &[&str] = &[
    "add-mppreference -exclusion",
    "clear-eventlog",
    "wevtutil cl",
    "wevtutil.exe cl",
    "remove-eventlog",
    "enablescriptblocklogging",
    "cachedgrouppolicysettings",
];

fn un<M: AsRef<str>>(s: &Script, motifs: &[M]) -> bool {
    motifs.iter().any(|m| s.contient(m.as_ref()))
}

/// Ce qu'un bloc de script a de malveillant : (catégorie, gravité, pourquoi).
pub(crate) fn script_suspect(texte: &str) -> Option<(&'static str, Gravite, Texte)> {
    let s = Script::de(texte);
    if un(&s, &AMSI[..]) {
        return Some((
            "amsi",
            Gravite::Critique,
            (
                "un script touche à AMSI, l'analyse des scripts par l'antivirus : la façon connue de l'aveugler",
                "a script tampers with AMSI, the antivirus script scanning: the known way to blind it",
            ),
        ));
    }
    // AMSI aveuglé sans le nommer (« '{1}{0}' -f », variables) : la même manœuvre, par sa forme. Masqué
    // (`crate::masque`) : c'est un contournement d'AMSI, qu'un antivirus reconnaîtrait en clair.
    if s.contient(mot_masque!("management.automation"))
        && s.contient(mot_masque!("getfield"))
        && s.contient(mot_masque!("nonpublic"))
        && s.contient(mot_masque!("setvalue($null,$true)"))
    {
        return Some((
            "amsi",
            Gravite::Critique,
            (
                "un script change un champ caché de PowerShell lui-même : la façon connue d'aveugler AMSI",
                "a script changes a hidden field of PowerShell itself: the known way to blind AMSI",
            ),
        ));
    }
    if s.contient("net.sockets.tcpclient") && s.contient("getstream") && un(&s, EXECUTER) {
        return Some((
            "outil",
            Gravite::Critique,
            (
                "un script ouvre une connexion et exécute ce qu'elle reçoit : un shell inversé",
                "a script opens a connection and runs what it receives: a reverse shell",
            ),
        ));
    }
    if un(&s, &OUTILS_OFFENSIFS[..]) {
        return Some((
            "outil",
            Gravite::Critique,
            (
                "un script nomme un outil d'attaque publié (vol de mots de passe, prise de contrôle)",
                "a script names a published attack tool (password theft, takeover)",
            ),
        ));
    }
    if s.contient(mot_masque!("minidumpwritedump")) && s.contient("lsass") {
        return Some((
            "lsass",
            Gravite::Alerte,
            (
                "un script vide la mémoire de LSASS, où Windows garde les identifiants des sessions",
                "a script dumps the memory of LSASS, where Windows keeps session credentials",
            ),
        ));
    }
    // Sans le nom de LSASS (visé par son numéro de processus) : le même vidage, que PowerShell ne fait que marquer
    // Avertissement ; aucun script ordinaire ne vide la mémoire d'un programme.
    if s.contient(mot_masque!("minidumpwritedump")) {
        return Some((
            "lsass",
            Gravite::Alerte,
            (
                "un script vide la mémoire d'un programme : la façon de prendre les identifiants de LSASS",
                "a script dumps a program's memory: how LSASS credentials get taken",
            ),
        ));
    }
    if s.contient("virtualprotect") && s.contient("getprocaddress") {
        return Some((
            "memoire",
            Gravite::Alerte,
            (
                "un script réécrit du code en mémoire (VirtualProtect, GetProcAddress) : la façon de patcher AMSI ou un antivirus",
                "a script rewrites code in memory (VirtualProtect, GetProcAddress): how AMSI or an antivirus gets patched",
            ),
        ));
    }
    if un(&s, ALLOUER) && un(&s, LANCER_FIL) {
        return Some((
            "memoire",
            Gravite::Alerte,
            (
                "un script réserve de la mémoire et y lance du code (VirtualAlloc, CreateThread) : la façon de charger un programme d'attaque sans fichier",
                "a script reserves memory and runs code in it (VirtualAlloc, CreateThread): how an attack program gets loaded without a file",
            ),
        ));
    }
    if un(&s, COPIER_JETON) && un(&s, SE_SERVIR_DU_JETON) {
        return Some((
            "jeton",
            Gravite::Alerte,
            (
                "un script prend le jeton d'un autre programme pour agir sous son compte (DuplicateTokenEx, ImpersonateLoggedOnUser) : une élévation ou un vol de session",
                "a script takes another program's token to act under its account (DuplicateTokenEx, ImpersonateLoggedOnUser): an elevation or a session theft",
            ),
        ));
    }
    if un(&s, LIRE_CLAVIER) && un(&s, TRADUIRE_TOUCHE) {
        return Some((
            "clavier",
            Gravite::Alerte,
            (
                "un script lit le clavier touche par touche (GetAsyncKeyState) : un enregistreur de frappe",
                "a script reads the keyboard key by key (GetAsyncKeyState): a keylogger",
            ),
        ));
    }
    if un(&s, DEMANDER) && un(&s, VERIFIER_MOT_DE_PASSE) && un(&s, EN_CLAIR) {
        return Some((
            "hameconnage",
            Gravite::Alerte,
            (
                "un script ouvre une fenêtre qui demande le mot de passe, le vérifie et le garde en clair : une fausse fenêtre de connexion",
                "a script opens a window asking for the password, checks it and keeps it in clear text: a fake sign-in window",
            ),
        ));
    }
    if un(&s, DESARMER) || REGLAGES_DE_DEFENDER.iter().any(|r| reglage_employe(&s.bas, r)) {
        return Some((
            "desarme",
            Gravite::Alerte,
            (
                "un script coupe une protection de Defender, lui ajoute une exclusion ou efface un journal",
                "a script turns off a Defender protection, adds an exclusion to it, or clears a log",
            ),
        ));
    }
    if un(&s, TELECHARGER_EN_MEMOIRE) || (un(&s, TELECHARGER) && un(&s, EXECUTER)) {
        return Some((
            "telecharge",
            Gravite::Alerte,
            (
                "un script télécharge du code et l'exécute aussitôt, sans fichier (les installateurs de Scoop ou de Chocolatey le font aussi)",
                "a script downloads code and runs it right away, without a file (the Scoop or Chocolatey installers do too)",
            ),
        ));
    }
    if un(&s, DECODER) && (un(&s, EXECUTER) || un(&s, CHARGER)) {
        return Some((
            "encode",
            Gravite::Alerte,
            (
                "un script décode du code caché en base64 et l'exécute ou le charge en mémoire",
                "a script decodes code hidden in base64 and runs it or loads it in memory",
            ),
        ));
    }
    if un(&s, SERVICES) && un(&s, VALEURS_DE_SERVICE) && un(&s, ECRIRE_REGISTRE) {
        return Some((
            "service",
            Gravite::Alerte,
            (
                "un script change le programme d'un service (ImagePath, FailureCommand) : une persistance ou une élévation",
                "a script changes the program of a service (ImagePath, FailureCommand): persistence or elevation",
            ),
        ));
    }
    if un(&s, DEPLACEMENT) && s.contient("gettypefrom") {
        return Some((
            "deplacement",
            Gravite::Alerte,
            (
                "un script crée un objet COM sur un autre ordinateur (MMC20, ShellWindows) : une façon connue d'y lancer des commandes",
                "a script creates a COM object on another computer (MMC20, ShellWindows): a known way to run commands there",
            ),
        ));
    }
    if s.bas.contains("-encodedcommand") || s.bas.contains(" -enc ") || s.bas.contains(" -ec ") {
        return Some((
            "encode",
            Gravite::Alerte,
            (
                "un script lance PowerShell avec une commande encodée, qui cache ce qu'elle fait",
                "a script starts PowerShell with an encoded command, which hides what it does",
            ),
        ));
    }
    None
}

/// Le niveau Avertissement (3) : PowerShell écrit lui-même d'origine, même sans la journalisation des blocs, ceux
/// qu'il juge suspects. Il en juge ainsi tout bloc qui contient l'un d'une centaine de mots (la liste est dans son
/// code, `CompiledScriptBlock.cs` : Add-Type, DllImport, Marshal, IntPtr, GetMethod, Methods, Properties, Bypass,
/// Cryptography, FromBase64String, VirtualAlloc…), ce que font aussi des modules de Windows lui-même (les modules
/// CDXML générés, la liste des méthodes de saisie) et des scripts d'installation (« -ExecutionPolicy Bypass »). Ce
/// niveau seul ne dit donc presque rien : sans motif reconnu (`script_suspect`), une information, regroupée par
/// fichier de script (ou tous les blocs sans fichier ensemble), qui dit combien.
const AVERTISSEMENT: u8 = 3;

/// FNV-1a sur 64 bits : une empreinte stable d'une version à l'autre du programme (celle de `std` ne l'est pas).
fn empreinte(texte: &str) -> u64 {
    texte.bytes().fold(0xcbf2_9ce4_8422_2325, |h, o| {
        (h ^ u64::from(o)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn bloc_de_script(e: &EvenementWindows) -> Option<Indice> {
    let texte = champ(e, "ScriptBlockText");
    let chemin = champ(e, "Path");
    let (categorie, gravite, pourquoi) = match script_suspect(texte) {
        Some(x) => x,
        None if e.niveau == Some(AVERTISSEMENT) => {
            // Regroupés : un Windows tout juste installé en écrit des centaines, chacun d'un texte différent (un
            // module généré par commande), ce qu'une empreinte par bloc ne réunirait pas.
            let quoi = if rempli(chemin) {
                chemin_bas(chemin)
            } else {
                "sans-fichier".to_string()
            };
            return indice(
                format!("avertissement|{quoi}"),
                Gravite::Info,
                (
                    "PowerShell a lui-même jugé suspects des blocs de script où aucun motif d'attaque n'est reconnu : il le fait pour une centaine de mots courants (Marshal, IntPtr, Bypass…), dans des modules de Windows aussi ; le premier",
                    "PowerShell itself judged script blocks suspicious where no attack pattern is recognized: it does so for about a hundred common words (Marshal, IntPtr, Bypass…), in Windows modules too; the first one",
                ),
                vec![
                    (Libelle::Script, texte.chars().take(300).collect()),
                    (Libelle::Programme, chemin.to_string()),
                ],
            );
        }
        None => return None,
    };
    // L'objet : la catégorie et le fichier du script (un même script relancé reste un seul objet, que l'on peut
    // déclarer normal), ou à défaut son numéro de bloc.
    let quoi = if rempli(chemin) {
        chemin_bas(chemin)
    } else {
        // Sans fichier : une empreinte du texte (le numéro de bloc change à chaque exécution, une tâche planifiée
        // qui relance la même commande ne ferait que des trouvailles nouvelles).
        format!("bloc:{:016x}", empreinte(&ramasse(&script_bas(texte))))
    };
    indice(
        format!("{categorie}|{quoi}"),
        gravite,
        pourquoi,
        vec![
            (Libelle::Script, texte.chars().take(300).collect()),
            (Libelle::Programme, chemin.to_string()),
        ],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-DEF-001 : Defender désarmé, ou qui a trouvé quelque chose
// ---------------------------------------------------------------------------------------------------------------

fn menace_trouvee(e: &EvenementWindows) -> Option<Indice> {
    let menace = champ(e, "Threat Name");
    let chemin = champ(e, "Path");
    indice(
        format!("menace:{}|{}", menace.to_lowercase(), chemin_bas(chemin)),
        Gravite::Alerte,
        (
            "Microsoft Defender a trouvé un logiciel malveillant",
            "Microsoft Defender found malware",
        ),
        vec![
            (Libelle::Menace, menace.to_string()),
            (Libelle::Commande, chemin.to_string()),
            (Libelle::Compte, champ(e, "Detection User").to_string()),
        ],
    )
}

fn action_prise(e: &EvenementWindows) -> Option<Indice> {
    let menace = champ(e, "Threat Name");
    let chemin = champ(e, "Path");
    indice(
        format!("action:{}|{}", menace.to_lowercase(), chemin_bas(chemin)),
        Gravite::Info,
        (
            "Microsoft Defender a agi contre une menace",
            "Microsoft Defender acted against a threat",
        ),
        vec![
            (Libelle::Menace, menace.to_string()),
            (Libelle::Action, champ(e, "Action Name").to_string()),
            (Libelle::Commande, chemin.to_string()),
        ],
    )
}

fn action_echouee(e: &EvenementWindows) -> Option<Indice> {
    let menace = champ(e, "Threat Name");
    let chemin = champ(e, "Path");
    indice(
        format!("echec:{}|{}", menace.to_lowercase(), chemin_bas(chemin)),
        Gravite::Critique,
        (
            "Microsoft Defender n'a pas pu agir contre une menace : elle est peut-être encore là",
            "Microsoft Defender could not act against a threat: it may still be there",
        ),
        vec![
            (Libelle::Menace, menace.to_string()),
            (Libelle::Action, champ(e, "Action Name").to_string()),
            (Libelle::Commande, chemin.to_string()),
        ],
    )
}

/// 5010 (analyse contre les logiciels espions coupée), 5012 (analyse antivirus coupée), 5013 (la protection
/// contre les falsifications a bloqué un changement : quelqu'un a essayé).
fn protection_touchee(e: &EvenementWindows) -> Option<Indice> {
    let pourquoi = match e.id {
        5013 => (
            "la protection contre les falsifications de Defender a bloqué une tentative de changer ses réglages",
            "Defender tamper protection blocked an attempt to change its settings",
        ),
        _ => (
            "une analyse de Microsoft Defender a été coupée",
            "a Microsoft Defender scan was turned off",
        ),
    };
    indice(
        format!("protection:{}|{}", e.id, instant(e)),
        Gravite::Alerte,
        pourquoi,
        vec![
            (Libelle::Reglage, champ(e, "Value").to_string()),
            (Libelle::NouvelleValeur, champ(e, "New Value").to_string()),
        ],
    )
}

fn temps_reel_coupe(e: &EvenementWindows) -> Option<Indice> {
    indice(
        format!("temps-reel|{}", instant(e)),
        Gravite::Alerte,
        (
            "la protection en temps réel de Microsoft Defender a été coupée",
            "Microsoft Defender real-time protection was turned off",
        ),
        Vec::new(),
    )
}

/// Les réglages de Defender qui, mis à 1, coupent une protection.
const COUPURES: &[&str] = &[
    "disablerealtimemonitoring",
    "disableantispyware",
    "disableantivirus",
    "disablebehaviormonitoring",
    "disableioavprotection",
    "disablescriptscanning",
    "disableonaccessprotection",
];

fn reglage_change(e: &EvenementWindows) -> Option<Indice> {
    let nouvelle = champ(e, "New Value");
    let ancienne = champ(e, "Old Value");
    let bas: String = nouvelle.to_lowercase().chars().filter(|c| !c.is_whitespace()).collect();
    let details = vec![
        (Libelle::AncienneValeur, ancienne.to_string()),
        (Libelle::NouvelleValeur, nouvelle.to_string()),
    ];
    // « HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0 » : une exclusion ajoutée (une
    // exclusion retirée laisse la nouvelle valeur vide).
    if bas.contains("\\exclusions\\") {
        return indice(
            format!("exclusion:{bas}"),
            Gravite::Alerte,
            (
                "une exclusion a été ajoutée à Microsoft Defender : ce qui y est rangé n'est plus analysé",
                "an exclusion was added to Microsoft Defender: what it covers is no longer scanned",
            ),
            details,
        );
    }
    // « …\DisableRealtimeMonitoring = 0x1 » : la valeur lue comme un nombre (« 1 », « 0x00000001 »), non nulle.
    let coupe = COUPURES.iter().find(|c| {
        let motif = format!("\\{c}=");
        bas.find(&motif).is_some_and(|i| {
            let valeur: String = bas[i + motif.len()..]
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect();
            nombre(&valeur).is_some_and(|n| n != 0)
        })
    })?;
    let objet = if *coupe == "disablerealtimemonitoring" {
        format!("temps-reel:reglage|{}", instant(e))
    } else {
        format!("reglage:{coupe}|{}", instant(e))
    };
    indice(
        objet,
        Gravite::Alerte,
        (
            "un réglage de Microsoft Defender a été changé pour couper une protection",
            "a Microsoft Defender setting was changed to turn off a protection",
        ),
        details,
    )
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-BIT-001 : téléchargement en douce par BITS
// ---------------------------------------------------------------------------------------------------------------

/// Les domaines d'où Windows et les programmes les plus courants téléchargent par BITS : Microsoft (Windows Update,
/// Office, Edge, Defender, Store ; OneDrive par sfx.ms et g.live.com, OneNote par onenote.net, vus dans un
/// échantillon public ;
/// aka.ms, son raccourcisseur ; le CDN d'Office chez Akamai), Google (mise à jour de Chrome : dl.google.com,
/// update.googleapis.com, gvt1.com), Mozilla (mise à jour de Firefox), Adobe. Seulement des noms où seul leur
/// éditeur publie : ni stockage ouvert à tous (blob.core.windows.net, storage.googleapis.com, github.com,
/// drive.google.com, onedrive.live.com : d'où google.com et live.com ne sont pas pris entiers), ni CDN loué
/// (azureedge.net, vo.msecnd.net, akamaized.net). Une redirection suivie par BITS ne se voit pas : le 59 ne garde
/// que l'adresse de départ.
const DOMAINES_ATTENDUS: &[&str] = &[
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "office.com",
    "office.net",
    "msedge.net",
    "g.live.com",
    "aka.ms",
    "officecdn.microsoft.com.edgesuite.net",
    "sfx.ms",
    "onenote.net",
    "xboxlive.com",
    "dl.google.com",
    "update.googleapis.com",
    "gvt1.com",
    "mozilla.org",
    "mozilla.net",
    "adobe.com",
];

/// Ce qu'une adresse web de BITS a d'inhabituel ; rien pour un domaine attendu.
pub(crate) fn adresse_inhabituelle(url: &str) -> Option<(String, Gravite, Texte)> {
    let u = url.trim();
    let bas = u.to_lowercase();
    let Some((schema, reste)) = bas.split_once("://") else {
        // Un chemin de fichier ou de partage (« \\serveur\partage », « file:… ») : la copie vient d'ailleurs que du
        // web.
        return Some((
            bas.chars().take(120).collect(),
            Gravite::Alerte,
            (
                "BITS a copié un fichier depuis un partage ou un chemin, pas depuis le web",
                "BITS copied a file from a share or a path, not from the web",
            ),
        ));
    };
    let fin = reste.find(['/', '?', '#']).unwrap_or(reste.len());
    let autorite = &reste[..fin];
    // Un « @ » (« http://microsoft.com@example.com/ ») ou une barre inverse dans l'autorité fait lire un autre
    // serveur que celui qu'on croit lire.
    if autorite.contains(['@', '\\']) || !(schema == "http" || schema == "https") {
        return Some((
            autorite.chars().take(120).collect(),
            Gravite::Alerte,
            (
                "BITS a téléchargé depuis une adresse web truquée, qui cache son vrai serveur",
                "BITS downloaded from a disguised URL, which hides its real server",
            ),
        ));
    }
    let hote = if let Some(v6) = autorite.strip_prefix('[') {
        v6.split(']').next().unwrap_or(v6)
    } else {
        autorite.rsplit_once(':').map_or(autorite, |(h, _)| h)
    };
    let hote = hote.trim_end_matches('.');
    if hote.parse::<IpAddr>().is_ok() {
        if lieu(hote) == Lieu::Local {
            return None;
        }
        return Some((
            hote.to_string(),
            Gravite::Alerte,
            (
                "BITS a téléchargé depuis une adresse IP nue, sans nom de domaine",
                "BITS downloaded from a bare IP address, without a domain name",
            ),
        ));
    }
    if hote == "localhost" {
        return None;
    }
    // Un nom du réseau local (une seule étiquette, ou .local, .lan, .home.arpa, .internal) : le serveur de mises à
    // jour d'une petite entreprise (WSUS), un NAS. À savoir, sans plus.
    if !hote.contains('.')
        || [".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".corp"]
            .iter()
            .any(|s| hote.ends_with(s))
    {
        return Some((
            hote.to_string(),
            Gravite::Info,
            (
                "BITS a téléchargé depuis un serveur du réseau local (un serveur de mises à jour, un NAS)",
                "BITS downloaded from a local network server (an update server, a NAS)",
            ),
        ));
    }
    if DOMAINES_ATTENDUS
        .iter()
        .any(|d| hote == *d || hote.strip_suffix(d).is_some_and(|p| p.ends_with('.')))
    {
        return None;
    }
    Some((
        hote.to_string(),
        Gravite::Alerte,
        (
            "BITS a téléchargé depuis un serveur hors des éditeurs courants (Microsoft, Google, Mozilla, Adobe) : la façon d'un programme malveillant de télécharger en douce",
            "BITS downloaded from a server outside the usual publishers (Microsoft, Google, Mozilla, Adobe): how malware downloads quietly",
        ),
    ))
}

fn bits(e: &EvenementWindows) -> Option<Indice> {
    let url = champ(e, "url");
    if url.is_empty() {
        return None;
    }
    let (hote, gravite, pourquoi) = adresse_inhabituelle(url)?;
    indice(
        hote,
        gravite,
        pourquoi,
        vec![
            (Libelle::AdresseWeb, url.to_string()),
            (Libelle::Commande, champ(e, "name").to_string()),
        ],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// EVT-WMI-001 : persistance par WMI ; EVT-AUD-001 : politique d'audit changée
// ---------------------------------------------------------------------------------------------------------------

/// L'abonnement que Windows pose lui-même (5861 à chaque démarrage du service WMI) : un consommateur qui écrit dans le
/// journal, sans commande possible, quel que soit son filtre. Un homonyme posé par un autre ne peut pas davantage.
const ABONNEMENT_DE_WINDOWS: &str = "nteventlogeventconsumer=\"scm event log consumer\"";

fn wmi(e: &EvenementWindows) -> Option<Indice> {
    let consommateur = champ(e, "CONSUMER");
    let bas = consommateur.to_lowercase();
    if bas == ABONNEMENT_DE_WINDOWS && champ(e, "Namespace").eq_ignore_ascii_case("//./root/subscription") {
        return None;
    }
    let (gravite, pourquoi) = if bas.contains("commandlineeventconsumer") || bas.contains("activescripteventconsumer") {
        (
            Gravite::Critique,
            (
                "un abonnement WMI permanent lance une commande ou un script à chaque déclenchement : une persistance cachée, sans fichier de démarrage",
                "a permanent WMI subscription runs a command or a script whenever it fires: hidden persistence, without a startup file",
            ),
        )
    } else {
        (
            Gravite::Info,
            (
                "un abonnement WMI permanent a été enregistré (journal, courriel ou fichier : pas de commande)",
                "a permanent WMI subscription was registered (log, email or file: no command)",
            ),
        )
    };
    indice(
        format!("{}|{}", champ(e, "Namespace").to_lowercase(), bas),
        gravite,
        pourquoi,
        vec![
            (Libelle::Consommateur, consommateur.to_string()),
            (Libelle::Commande, champ(e, "PossibleCause").to_string()),
        ],
    )
}

fn audit_change(e: &EvenementWindows) -> Option<Indice> {
    let changement = champ(e, "AuditPolicyChanges");
    let bas = changement.to_lowercase();
    // %%8448 : succès retiré, %%8450 : échec retiré (8449, 8451 : ajoutés).
    let retire = bas.contains("%%8448") || bas.contains("%%8450") || bas.contains("removed");
    let (gravite, pourquoi) = if retire {
        (
            Gravite::Alerte,
            (
                "la politique d'audit a été réduite : des événements de sécurité ne s'écrivent plus",
                "the audit policy was reduced: some security events are no longer written",
            ),
        )
    } else {
        (
            Gravite::Info,
            ("la politique d'audit a été changée", "the audit policy was changed"),
        )
    };
    indice(
        format!("{}|{}", champ(e, "SubcategoryGuid").to_lowercase(), bas),
        gravite,
        pourquoi,
        vec![
            (Libelle::Reglage, champ(e, "SubcategoryGuid").to_string()),
            (Libelle::Changement, couper(changement)),
            (Libelle::Auteur, auteur(e)),
        ],
    )
}

fn journal_plein(e: &EvenementWindows) -> Option<Indice> {
    indice(
        format!("plein|{}", instant(e)),
        Gravite::Alerte,
        (
            "le journal de sécurité est plein et réglé pour ne rien écraser : Windows n'y écrit plus (un attaquant peut le remplir exprès)",
            "the security log is full and set to overwrite nothing: Windows no longer writes to it (an attacker can fill it on purpose)",
        ),
        Vec::new(),
    )
}

fn compte_verrouille(e: &EvenementWindows) -> Option<Indice> {
    let compte = champ(e, "TargetUserName");
    indice(
        format!("verrouille:{}", compte_seul(compte)),
        Gravite::Alerte,
        (
            "un compte a été verrouillé après trop d'échecs de connexion",
            "an account was locked out after too many failed logons",
        ),
        vec![
            (Libelle::Compte, compte.to_string()),
            (Libelle::Serveur, champ(e, "TargetDomainName").to_string()),
        ],
    )
}

/// Windows PowerShell 400 (moteur démarré) : « EngineVersion=2.0 » dans ses données (des valeurs sans nom). La
/// version 2 n'écrit aucun bloc de script : la lancer exprès (« powershell -version 2 ») contourne la
/// journalisation et AMSI.
fn powershell_2(e: &EvenementWindows) -> Option<Indice> {
    let donnees = e
        .champs
        .iter()
        .map(|(_, v)| v.as_str())
        .find(|v| v.to_lowercase().contains("engineversion=2."))?;
    let ligne = donnees
        .lines()
        .find(|l| l.to_lowercase().contains("hostapplication="))
        .unwrap_or_default();
    indice(
        format!("v2|{}", instant(e)),
        Gravite::Alerte,
        (
            "PowerShell 2 a été lancé : il n'écrit aucun bloc de script et échappe à AMSI, la façon connue de contourner la journalisation",
            "PowerShell 2 was started: it writes no script block and escapes AMSI, the known way to bypass logging",
        ),
        vec![(Libelle::Commande, ligne.trim().to_string())],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Lignes de commande : EVT-PRC-001 (processus), EVT-TAC-001 (tâches planifiées)
// ---------------------------------------------------------------------------------------------------------------

/// Des programmes d'attaque publiés, par le nom de leur fichier (sans extension, en minuscules) : vol de mots de
/// passe et de tickets, reconnaissance d'un domaine, recherche d'une élévation. Ils n'ont pas d'autre usage. Masqué
/// (`crate::masque`) : ces noms sont exactement ce qu'une signature d'antivirus cherche.
static PROGRAMMES_OFFENSIFS: LazyLock<Vec<String>> = liste_masquee![
    "mimikatz",
    "safetykatz",
    "rubeus",
    "lazagne",
    "sharphound",
    "nanodump",
    "winpeas",
    "winpeasx64",
    "winpeasany",
    "kerbrute",
    "pypykatz",
];

/// Les programmes de PowerShell.
const POWERSHELLS: &[&str] = &["powershell", "pwsh", "powershell_ise"];

/// Les mots d'une ligne de commande (sans guillemets autour), au plus `MOTS_MAX` : une ligne hostile de 32 Kio
/// n'en fait pas des milliers.
const MOTS_MAX: usize = 64;

fn mots(ligne_bas: &str) -> Vec<&str> {
    ligne_bas
        .split_whitespace()
        .take(MOTS_MAX)
        .map(|m| m.trim_matches(['"', '\'']))
        .collect()
}

/// Un texte en base64 assez long pour cacher une commande.
fn base64_long(m: &str) -> bool {
    m.len() >= 16
        && m.bytes()
            .all(|o| o.is_ascii_alphanumeric() || o == b'+' || o == b'/' || o == b'=')
}

/// PowerShell lancé avec une commande encodée : « -EncodedCommand », ou l'une de ses abréviations que PowerShell
/// accepte (« -e », « -en », « -enc », « -ec »), suivie d'un texte en base64 ; ou un décodage de base64 dans la
/// commande même.
fn commande_encodee(nom: &str, ligne_bas: &str) -> bool {
    if !POWERSHELLS.contains(&nom) {
        return false;
    }
    if ligne_bas.contains("frombase64string") {
        return true;
    }
    let m = mots(ligne_bas);
    m.windows(2).any(|p| {
        let option = p[0]
            .strip_prefix('-')
            .or_else(|| p[0].strip_prefix('/'))
            .unwrap_or_default();
        !option.is_empty() && ("encodedcommand".starts_with(option) || option == "ec") && base64_long(p[1])
    })
}

/// Un programme d'attaque publié, par son nom ou celui d'un fichier de sa ligne, ou une commande d'un outil
/// d'attaque (`OUTILS_OFFENSIFS`) dans la ligne.
fn outil_offensif(nom: &str, ligne_bas: &str) -> bool {
    let nomme = |n: &str| PROGRAMMES_OFFENSIFS.iter().any(|o| o == n);
    nomme(nom)
        || mots(ligne_bas).iter().any(|m| nomme(&nom_programme(m)))
        || OUTILS_OFFENSIFS.iter().any(|o| ligne_bas.contains(o.as_str()))
}

/// La mémoire de LSASS vidée par un programme de Windows ou de Sysinternals : rundll32 et la fonction MiniDump de
/// comsvcs.dll, ou ProcDump visant lsass.
fn vidage_lsass(nom: &str, ligne_bas: &str) -> bool {
    (nom == "rundll32" && ligne_bas.contains("comsvcs") && ligne_bas.contains("minidump"))
        || (nom.starts_with("procdump") && ligne_bas.contains("lsass"))
}

/// Une adresse web dans une ligne de commande, ses « / » ramenés ou non à « \ » (`chemin_bas`).
fn adresse_web(ligne_bas: &str) -> bool {
    ["http://", "https://", "ftp://", "http:\\\\", "https:\\\\", "ftp:\\\\"]
        .iter()
        .any(|p| ligne_bas.contains(p))
}

/// Un programme de Windows détourné pour télécharger ou lancer du code d'ailleurs (ATT&CK T1105, T1218) : certutil
/// qui télécharge ou décode, bitsadmin qui transfère, mshta, regsvr32 ou rundll32 qui chargent une adresse web ou
/// un script.
fn telechargement_systeme(nom: &str, ligne_bas: &str) -> bool {
    match nom {
        "certutil" => {
            ((ligne_bas.contains("urlcache") || ligne_bas.contains("verifyctl")) && adresse_web(ligne_bas))
                || ligne_bas.contains("-decode")
                || ligne_bas.contains("/decode")
        }
        "bitsadmin" => ["/transfer", "/addfile", "/download"]
            .iter()
            .any(|o| ligne_bas.contains(o)),
        "mshta" => adresse_web(ligne_bas) || ligne_bas.contains("javascript:") || ligne_bas.contains("vbscript:"),
        "regsvr32" => ligne_bas.contains("scrobj") || (ligne_bas.contains(":http") && ligne_bas.contains("/i")),
        "rundll32" => ligne_bas.contains("javascript:") || adresse_web(ligne_bas),
        _ => false,
    }
}

/// Ce qu'une ligne de commande a de suspect, quel que soit ce qui la lance (un processus, une tâche) : (catégorie,
/// gravité, pourquoi). `programme` : le programme lancé ; `ligne` : la ligne entière (le programme compris, ou ses
/// seuls arguments). Rien pour une ligne ordinaire.
pub(crate) fn ligne_suspecte(programme: &str, ligne: &str) -> Option<(&'static str, Gravite, Texte)> {
    let nom = nom_programme(&decouper(programme).0);
    // Les « / » gardés : ce sont aussi ceux des options (« /transfer », « /i: »).
    let bas = tirets(&ligne.trim().to_lowercase());
    if outil_offensif(&nom, &bas) {
        return Some((
            "outil",
            Gravite::Critique,
            (
                "un programme d'attaque connu a été lancé (vol de mots de passe ou de tickets, reconnaissance du réseau)",
                "a known attack program was run (password or ticket theft, network reconnaissance)",
            ),
        ));
    }
    if vidage_lsass(&nom, &bas) {
        return Some((
            "lsass",
            Gravite::Critique,
            (
                "la mémoire de LSASS a été vidée par un programme de Windows : la façon de prendre les identifiants des sessions",
                "LSASS memory was dumped with a Windows program: how session credentials get taken",
            ),
        ));
    }
    if commande_encodee(&nom, &bas) {
        return Some((
            "encode",
            Gravite::Alerte,
            (
                "PowerShell a été lancé avec une commande encodée, qui cache ce qu'elle fait",
                "PowerShell was started with an encoded command, which hides what it does",
            ),
        ));
    }
    if telechargement_systeme(&nom, &bas) {
        return Some((
            "systeme",
            Gravite::Alerte,
            (
                "un programme de Windows a été détourné pour télécharger, décoder ou lancer du code d'ailleurs (certutil, bitsadmin, mshta, regsvr32, rundll32)",
                "a Windows program was misused to download, decode or run code from elsewhere (certutil, bitsadmin, mshta, regsvr32, rundll32)",
            ),
        ));
    }
    if POWERSHELLS.contains(&nom.as_str())
        && let Some((categorie, gravite, pourquoi)) = script_suspect(ligne)
    {
        return Some((categorie, gravite, pourquoi));
    }
    None
}

fn processus_cree(e: &EvenementWindows) -> Option<Indice> {
    let programme = champ(e, "NewProcessName");
    let ligne = champ(e, "CommandLine");
    // Sans la ligne de commande (stratégie coupée, la valeur d'origine), le nom du programme seul se juge encore.
    let ligne_jugee = if rempli(ligne) { ligne } else { programme };
    let (categorie, gravite, pourquoi) = ligne_suspecte(programme, ligne_jugee)?;
    indice(
        format!(
            "{categorie}|{}|{:016x}",
            nom_programme(programme),
            empreinte(&chemin_bas(ligne_jugee))
        ),
        gravite,
        pourquoi,
        vec![
            (Libelle::Programme, programme.to_string()),
            (Libelle::Commande, ligne.to_string()),
            (Libelle::Parent, champ(e, "ParentProcessName").to_string()),
            (Libelle::Auteur, auteur(e)),
        ],
    )
}

/// Les actions « Exec » d'une tâche (son XML, `TaskContent` du 4698, `TaskContentNew` du 4702) : (programme,
/// arguments), au plus `ACTIONS_MAX` (le Planificateur en admet 32). Les entités XML courantes sont défaites.
const ACTIONS_MAX: usize = 32;

/// Le XML d'une tâche lu au plus : une vraie tâche en fait quelques Kio ; un champ forgé peut en faire un Mio.
const XML_TACHE_MAX: usize = 64 * 1024;

/// Les actions de la tâche, et si son XML dépassait `XML_TACHE_MAX` (lu jusque-là seulement). Linéaire : chaque
/// recherche reste dans le bloc `<exec>…</exec>` qu'elle lit, et la suivante reprend après lui (un XML forgé fait de
/// milliers de `<exec>` sans fin ne fait plus relire tout le texte à chacun).
pub(crate) fn actions_de_tache(xml: &str) -> (Vec<(String, String)>, bool) {
    let tronque = xml.len() > XML_TACHE_MAX;
    let xml = if tronque {
        let mut fin = XML_TACHE_MAX;
        while !xml.is_char_boundary(fin) {
            fin -= 1;
        }
        &xml[..fin]
    } else {
        xml
    };
    // En minuscules ASCII seulement : les balises le sont, et les indices de `bas` restent ceux de `xml` (une lettre
    // dont la minuscule change de longueur, posée exprès dans la tâche, ne décale rien).
    let bas = xml.to_ascii_lowercase();
    // La valeur d'une balise dans le bloc `debut..fin`.
    let valeur = |debut: usize, fin: usize, balise: &str| -> Option<String> {
        let bloc = &bas[debut..fin];
        let (i, vide) = balise_ouvrante(bloc, 0, balise).map(|(_, i, vide)| (i, vide))?;
        if vide {
            return Some(String::new());
        }
        let (j, _) = balise_fermante(bloc, i, balise)?;
        Some(entites(&xml[debut + i..debut + j]))
    };
    let mut actions = Vec::new();
    let mut depuis = 0;
    while actions.len() < ACTIONS_MAX {
        let Some((_, i, vide)) = balise_ouvrante(&bas, depuis, "exec") else {
            break;
        };
        if vide {
            depuis = i;
            continue;
        }
        // Un bloc sans fin : rien d'autre à lire après lui.
        let Some((fin, apres)) = balise_fermante(&bas, i, "exec") else {
            break;
        };
        if let Some(commande) = valeur(i, fin, "command") {
            let arguments = valeur(i, fin, "arguments").unwrap_or_default();
            actions.push((commande, arguments));
        }
        depuis = apres;
    }
    (actions, tronque)
}

/// La prochaine balise ouvrante `<nom…>` de `bas` à partir de `depuis` : (son début, la fin de son « > », vide :
/// écrite `<nom/>`). Le schéma des tâches admet des attributs (`<Exec id="a">`) et XML des blancs avant « > » : les
/// chercher au seul littéral `<exec>` laissait une action ainsi écrite invisible. `<executable>` n'est pas `<exec>`.
fn balise_ouvrante(bas: &str, mut depuis: usize, nom: &str) -> Option<(usize, usize, bool)> {
    let ouvre = format!("<{nom}");
    loop {
        let i = bas[depuis..].find(&ouvre)? + depuis;
        let apres = i + ouvre.len();
        match bas.as_bytes().get(apres) {
            Some(b'>') => return Some((i, apres + 1, false)),
            Some(o) if o.is_ascii_whitespace() || *o == b'/' => {
                // Les attributs, jusqu'au « > » hors de leurs valeurs entre guillemets, où XML admet « > » et « / » :
                // `<Exec id="a/">` n'est pas une action vide.
                let mut guillemet = None;
                for (k, &c) in bas.as_bytes()[apres..].iter().enumerate() {
                    match (guillemet, c) {
                        (None, b'"' | b'\'') => guillemet = Some(c),
                        (Some(g), _) if c == g => guillemet = None,
                        (None, b'>') => {
                            let j = apres + k;
                            return Some((i, j + 1, bas[..j].trim_end().ends_with('/')));
                        }
                        _ => {}
                    }
                }
                return None;
            }
            _ => depuis = apres,
        }
    }
}

/// La prochaine balise fermante `</nom>` (des blancs admis avant « > ») à partir de `depuis` : (son début, la fin de
/// son « > »).
fn balise_fermante(bas: &str, mut depuis: usize, nom: &str) -> Option<(usize, usize)> {
    let ferme = format!("</{nom}");
    loop {
        let i = bas[depuis..].find(&ferme)? + depuis;
        let apres = i + ferme.len();
        let blancs = bas[apres..].len() - bas[apres..].trim_start_matches(|c: char| c.is_ascii_whitespace()).len();
        if bas.as_bytes().get(apres + blancs) == Some(&b'>') {
            return Some((i, apres + blancs + 1));
        }
        depuis = apres;
    }
}

/// Les entités XML d'une valeur (« &quot; », « &amp; »…), défaites une fois.
fn entites(t: &str) -> String {
    t.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .trim()
        .to_string()
}

/// Le dossier des versions de la plateforme de Defender, que Defender protège lui-même : ses tâches d'analyse y
/// lancent MpCmdRun, et chaque mise à jour de la plateforme les récrit.
fn plateforme_de_defender(programme_bas: &str) -> bool {
    ["c:\\programdata\\", "%programdata%\\"].iter().any(|p| {
        programme_bas
            .strip_prefix(p)
            .is_some_and(|r| r.starts_with("microsoft\\windows defender\\platform\\"))
    }) && !programme_bas.contains("\\..\\")
}

/// Ce que l'action d'une tâche a de suspect : (gravité, pourquoi) ; rien pour une action ordinaire.
pub(crate) fn tache_suspecte(commande: &str, arguments: &str) -> Option<(Gravite, Texte)> {
    let programme_bas = sans_prefixe(&chemin_bas(&decouper(commande).0));
    let nom = nom_programme(&programme_bas);
    let ligne = format!("{commande} {arguments}");
    if let Some((_, gravite, pourquoi)) = ligne_suspecte(commande, &ligne) {
        return Some((gravite, pourquoi));
    }
    if plateforme_de_defender(&programme_bas) {
        return None;
    }
    // rundll32 n'alerte que s'il va chercher ailleurs que dans Windows (des tâches de Windows le lancent sur une
    // bibliothèque du système : « rundll32.exe /d acproxy.dll,PerformAutochkOperations »).
    let ailleurs = |t: &str| INSCRIPTIBLES.iter().chain(DOUTEUX).any(|d| t.contains(d)) || adresse_web(t);
    let arguments_bas = chemin_bas(arguments);
    if (est_interprete(&nom) && nom != "rundll32")
        || (nom == "rundll32" && ailleurs(&arguments_bas))
        || est_autre_interprete(&nom)
        || chemin_bas(commande).contains("%comspec%")
    {
        return Some((
            Gravite::Alerte,
            (
                "la tâche lance un interpréteur de commandes ou de scripts, comme les programmes malveillants qui se relancent à chaque démarrage (des outils d'administration le font aussi)",
                "the task runs a command or script interpreter, like malware that restarts itself at every startup (administration tools do too)",
            ),
        ));
    }
    if TEMPORAIRES.iter().chain(DOUTEUX).any(|d| programme_bas.contains(d))
        || [
            "\\windows\\tasks\\",
            "\\windows\\tracing\\",
            "\\spool\\drivers\\color\\",
        ]
        .iter()
        .any(|d| programme_bas.contains(d))
    {
        return Some((
            Gravite::Alerte,
            (
                "la tâche lance un programme d'un dossier temporaire, des téléchargements ou public, où rien ne s'installe",
                "the task runs a program from a temporary, downloads or public folder, where nothing gets installed",
            ),
        ));
    }
    if INSCRIPTIBLES.iter().any(|d| programme_bas.contains(d)) {
        return Some((
            Gravite::Info,
            (
                "la tâche lance un programme rangé dans un profil, où le compte écrit lui-même (OneDrive, Teams ou Zoom s'y installent ; un programme malveillant aussi)",
                "the task runs a program stored in a profile, where the account itself writes (OneDrive, Teams or Zoom install there; malware too)",
            ),
        ));
    }
    if programme_bas.contains("\\programdata\\") || programme_bas.starts_with("%programdata%") {
        return Some((
            Gravite::Info,
            (
                "la tâche lance un programme rangé dans ProgramData, où tout compte peut créer des dossiers",
                "the task runs a program stored in ProgramData, where any account can create folders",
            ),
        ));
    }
    None
}

/// 4698 (tâche créée) et 4702 (tâche changée) : chaque action de la tâche jugée ; une tâche créée sans rien de
/// suspect reste une information, une tâche changée sans rien de suspect ne dit rien (Windows récrit les siennes à
/// chaque mise à jour).
fn tache_auditee(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "TaskName");
    let contenu = e
        .champ("TaskContent")
        .or_else(|| e.champ("TaskContentNew"))
        .unwrap_or_default();
    let (actions, tronque) = actions_de_tache(contenu);
    // Une action est là mais rien n'en a été lu (une commande écrite autrement que le lecteur ne l'attend) : la
    // tâche n'est pas jugée, elle ne passe pas pour une simple création.
    let non_lue = actions.is_empty() && balise_ouvrante(&contenu.to_ascii_lowercase(), 0, "exec").is_some();
    let pire = actions
        .iter()
        .filter_map(|(programme, arguments)| {
            tache_suspecte(programme, arguments).map(|(gravite, pourquoi)| (gravite, pourquoi, programme, arguments))
        })
        .max_by_key(|(gravite, ..)| *gravite);
    let (gravite, pourquoi, commande) = match pire {
        Some((gravite, pourquoi, programme, arguments)) => (gravite, pourquoi, format!("{programme} {arguments}")),
        None if e.id == 4698 || tronque || non_lue => (
            Gravite::Info,
            ("une tâche planifiée a été créée", "a scheduled task was created"),
            actions.first().map(|(c, a)| format!("{c} {a}")).unwrap_or_default(),
        ),
        None => return None,
    };
    // Une tâche démesurée n'a été lue qu'en partie : ce qui suit peut cacher une action.
    let (gravite, pourquoi) = if tronque && gravite < Gravite::Alerte {
        (
            Gravite::Alerte,
            (
                "le contenu de la tâche est démesuré (plus de 64 Kio, ce qu'aucune tâche ordinaire n'atteint) : il n'a été lu qu'en partie",
                "the task content is oversized (more than 64 KiB, which no ordinary task reaches): it was only partly read",
            ),
        )
    } else if non_lue && gravite < Gravite::Alerte {
        (
            Gravite::Alerte,
            (
                "la tâche a une action dont la commande n'a pas pu être lue : ce qu'elle lance n'est pas vérifié",
                "the task has an action whose command could not be read: what it runs is not verified",
            ),
        )
    } else {
        (gravite, pourquoi)
    };
    indice(
        format!("{}|{}", nom.to_lowercase(), chemin_bas(&commande)),
        gravite,
        pourquoi,
        vec![
            (Libelle::Tache, nom.to_string()),
            (Libelle::Commande, commande.trim().to_string()),
            (Libelle::Auteur, auteur(e)),
        ],
    )
}

/// TaskScheduler/Operational 106 (tâche inscrite) : ce journal ne dit pas ce qu'elle lance, une information.
fn tache_inscrite(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "TaskName");
    indice(
        format!("{}|inscrite|{}", nom.to_lowercase(), instant(e)),
        Gravite::Info,
        (
            "une tâche planifiée a été créée (ce journal ne dit pas ce qu'elle lance : son lancement le dira)",
            "a scheduled task was created (this log does not say what it runs: its launch will)",
        ),
        vec![
            (Libelle::Tache, nom.to_string()),
            (Libelle::Compte, champ(e, "UserContext").to_string()),
        ],
    )
}

/// TaskScheduler/Operational 140 (tâche mise à jour) : ce journal ne dit pas ce qu'elle lance désormais, une
/// information, jamais une alerte (Windows et les programmes récrivent leurs tâches à chaque mise à jour). Une tâche
/// mise à jour plusieurs fois fait une seule ligne, comptée.
fn tache_mise_a_jour(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "TaskName");
    indice(
        // « maj| » devant : aucun objet d'un 106, d'un 200 ou d'un 4698 (« nom|… ») ne peut lui ressembler.
        format!("maj|{}", nom.to_lowercase()),
        Gravite::Info,
        (
            "une tâche planifiée a été mise à jour (ce journal ne dit pas ce qu'elle lance : son lancement le dira)",
            "a scheduled task was updated (this log does not say what it runs: its launch will)",
        ),
        vec![
            (Libelle::Tache, nom.to_string()),
            (Libelle::Compte, champ(e, "UserName").to_string()),
        ],
    )
}

/// TaskScheduler/Operational 200 (action lancée) : le programme de l'action, sans ses arguments.
fn tache_lancee(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "TaskName");
    let programme = champ(e, "ActionName");
    let (gravite, pourquoi) = tache_suspecte(programme, "")?;
    indice(
        format!("{}|{}", nom.to_lowercase(), chemin_bas(programme)),
        gravite,
        pourquoi,
        vec![
            (Libelle::Tache, nom.to_string()),
            (Libelle::Programme, programme.to_string()),
        ],
    )
}

// ---------------------------------------------------------------------------------------------------------------
// Les règles
// ---------------------------------------------------------------------------------------------------------------

const fn chacun(
    journal: &'static str,
    fournisseurs: &'static [&'static str],
    ids: &'static [u32],
    quand: Condition,
    f: fn(&EvenementWindows) -> Option<Indice>,
) -> Volet {
    Volet {
        journal,
        fournisseurs,
        ids,
        quand,
        forme: Forme::Chacun(f),
        audit: Audit::DOrigine,
        sous_categorie: None,
    }
}

/// Un volet du journal de sécurité, sa sous-catégorie d'audit nommée (un 4719 qui la réduit le rend non vérifié).
const fn securite(
    ids: &'static [u32],
    quand: Condition,
    f: fn(&EvenementWindows) -> Option<Indice>,
    sc: &'static str,
) -> Volet {
    Volet {
        sous_categorie: Some(sc),
        ..chacun(SECURITY, AUDIT, ids, quand, f)
    }
}

/// Les GUID des sous-catégories d'audit (« auditpol /list /subcategory:* /v »), en minuscules comme le moteur les
/// compare.
const LOGON: &str = "{0cce9215-69ae-11d9-bed3-505054503030}";
const COMPTES: &str = "{0cce9235-69ae-11d9-bed3-505054503030}";
const GROUPES: &str = "{0cce9237-69ae-11d9-bed3-505054503030}";
const PROCESSUS: &str = "{0cce922b-69ae-11d9-bed3-505054503030}";
const AUTRES_OBJETS: &str = "{0cce9227-69ae-11d9-bed3-505054503030}";

/// L'audit des ouvertures de session : un poste allumé écrit sans cesse des 4624 ; sans un seul 4624, 4625 ou
/// 4648 vu, rien ne prouve que la sous-catégorie écrit encore.
const AUDIT_LOGON: Audit = Audit::Preuve {
    preuve: &[4624, 4625, 4648],
    quoi: (
        "aucune ouverture de session journalisée : l'audit des ouvertures de session est peut-être coupé",
        "no logon recorded: logon auditing may be turned off",
    ),
};

/// Un volet de rafale d'échecs de connexion.
const fn echecs(par: &'static [&'static str], nombre: usize, fenetre: i64, gravite: Gravite, pourquoi: Texte) -> Volet {
    Volet {
        journal: SECURITY,
        fournisseurs: AUDIT,
        ids: &[4625],
        quand: DEVINABLE,
        forme: Forme::Rafale {
            par,
            nombre,
            fenetre,
            gravite,
            pourquoi,
        },
        audit: AUDIT_LOGON,
        sous_categorie: Some(LOGON),
    }
}

/// Trente échecs en un jour, par compte ou par adresse : l'attaquant patient qui reste sous le seuil de
/// verrouillage (neuf essais toutes les dix minutes) ; le seuil d'origine de Windows 10 est zéro (jamais).
const ECHECS_LENTS: usize = 30;
const FENETRE_LENTE: i64 = 24 * 3600;
const DEVINE_LENTEMENT: Texte = (
    "des échecs de connexion répétés sur une journée : quelqu'un essaie des mots de passe sans se faire verrouiller (ou un programme garde un mot de passe périmé)",
    "repeated failed logons over a day: someone is trying passwords without getting locked out (or a program keeps an outdated password)",
);

const SECURITY: &str = "Security";
const SYSTEM: &str = "System";
const POWERSHELL: &str = "Microsoft-Windows-PowerShell/Operational";
const POWERSHELL_7: &str = "PowerShellCore/Operational";
const POWERSHELL_CLASSIQUE: &str = "Windows PowerShell";
const DEFENDER: &str = "Microsoft-Windows-Windows Defender/Operational";
const BITS: &str = "Microsoft-Windows-Bits-Client/Operational";
const WMI: &str = "Microsoft-Windows-WMI-Activity/Operational";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
const TACHES: &str = "Microsoft-Windows-TaskScheduler/Operational";
const DEFENDER_P: &[&str] = &["Microsoft-Windows-Windows Defender"];
const TACHES_P: &[&str] = &["Microsoft-Windows-TaskScheduler"];

/// L'audit des tâches planifiées (« Autres événements d'accès à l'objet », coupé d'origine) : sans un seul de ses
/// événements vu, rien ne prouve qu'il est allumé.
const AUDIT_TACHES: Audit = Audit::Preuve {
    preuve: &[4671, 4691, 4698, 4699, 4700, 4701, 4702, 5148, 5149, 5888, 5889, 5890],
    quoi: (
        "aucune tâche planifiée journalisée : allumer l'audit « Auditer d'autres événements d'accès à l'objet » (succès), ou l'historique du Planificateur de tâches (« Activer l'historique de toutes les tâches »)",
        "no scheduled task recorded: turn on the “Audit Other Object Access Events” auditing (success), or the Task Scheduler history (“Enable All Tasks History”)",
    ),
};

/// Un processus que le noyau crée sans programme sur le disque (Registry, MemCompression : un nom sans dossier) : sa
/// ligne de commande est vide même quand elle est journalisée.
fn processus_du_noyau(e: &EvenementWindows) -> bool {
    !champ(e, "NewProcessName").contains('\\')
}

/// L'audit de la création de processus et la ligne de commande dans ses événements, coupés d'origine.
const AUDIT_PROCESSUS: Audit = Audit::PreuveChamp {
    champ: "CommandLine",
    vide_permis: processus_du_noyau,
    quoi: (
        "aucune ligne de commande journalisée : allumer l'audit « Auditer la création du processus » (succès) et la stratégie « Inclure la ligne de commande dans les événements de création de processus »",
        "no command line recorded: turn on the “Audit Process Creation” auditing (success) and the “Include command line in process creation events” policy",
    ),
};

/// Les journaux que lisent les règles.
pub(crate) const JOURNAUX: &[&str] = &[
    SECURITY,
    SYSTEM,
    POWERSHELL,
    POWERSHELL_7,
    POWERSHELL_CLASSIQUE,
    DEFENDER,
    BITS,
    WMI,
    LSM,
    RCM,
    TACHES,
];

/// Les règles.
pub(crate) static REGLES: &[Regle] = &[
    Regle {
        id: "EVT-EFF-001",
        sujet: (
            "traces effacées : journaux vidés, enregistrements retirés",
            "cleared traces: emptied logs, removed records",
        ),
        techniques: &["T1685.005"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102",
            "https://learn.microsoft.com/en-us/windows/win32/eventlog/event-log-records",
            "https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/event-id-41-restart",
            "https://attack.mitre.org/techniques/T1685/005/",
        ],
        volets: &[
            chacun(SECURITY, EVENTLOG, &[1102], Condition::Toujours, securite_effacee),
            chacun(SYSTEM, EVENTLOG, &[104], Condition::Toujours, journal_efface),
            Volet {
                journal: "",
                fournisseurs: &[],
                ids: &[],
                quand: Condition::Toujours,
                forme: Forme::Trous,
                audit: Audit::DOrigine,
                sous_categorie: None,
            },
            chacun(SECURITY, EVENTLOG, &[1104], Condition::Toujours, journal_plein),
        ],
        limite: Some((
            "un enregistrement changé ou remplacé sans changer son numéro ne se voit pas, ni un journal qui cesse d'écrire (service coupé par le registre) sans laisser de trou",
            "a record changed or replaced without changing its number cannot be seen, nor a log that stops writing (service turned off in the registry) without leaving a gap",
        )),
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-SRV-001",
        sujet: (
            "service d'attaque installé, journal des événements coupé",
            "attack service installed, event log turned off",
        ),
        techniques: &["T1543.003", "T1685.001"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697",
            "https://attack.mitre.org/techniques/T1543/003/",
            "https://attack.mitre.org/techniques/T1685/001/",
        ],
        volets: &[
            chacun(SYSTEM, SCM, &[7045], Condition::Toujours, service_installe),
            // param4 : le nom court du service, qui ne se traduit pas (param1, son nom affiché, l'est).
            chacun(
                SYSTEM,
                SCM,
                &[7040],
                Condition::Champ("param4", Test::Egal("EventLog")),
                journal_des_evenements_change,
            ),
        ],
        limite: Some((
            "un service changé directement dans le registre (ImagePath, Start) n'écrit ni 7045 ni 7040",
            "a service changed directly in the registry (ImagePath, Start) writes neither 7045 nor 7040",
        )),
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-ADM-001",
        sujet: (
            "un administrateur de plus : compte créé, ajouté à un groupe privilégié",
            "one more administrator: account created, added to a privileged group",
        ),
        techniques: &["T1136.001", "T1098"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management",
            "https://attack.mitre.org/techniques/T1136/001/",
            "https://attack.mitre.org/techniques/T1098/",
        ],
        volets: &[
            securite(&[4720], Condition::Toujours, compte_cree, COMPTES),
            securite(&[4732], Condition::Toujours, ajout_groupe_local, GROUPES),
            securite(&[4728, 4756], Condition::Toujours, ajout_groupe_domaine, GROUPES),
            securite(&[4738], Condition::Toujours, compte_change, COMPTES),
        ],
        limite: None,
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-MDP-001",
        sujet: (
            "mot de passe deviné : échecs de connexion en rafale, puis réussite",
            "password guessed: burst of failed logons, then success",
        ),
        techniques: &["T1110.001"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740",
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
            "https://attack.mitre.org/techniques/T1110/001/",
        ],
        volets: &[
            echecs(&["TargetUserName"], ECHECS, FENETRE_ECHECS, Gravite::Alerte, DEVINE),
            echecs(&["IpAddress"], ECHECS, FENETRE_ECHECS, Gravite::Alerte, DEVINE),
            echecs(&[], ECHECS_RAPIDES, FENETRE_RAPIDE, Gravite::Alerte, DEVINE_VITE),
            // La réussite après une rafale, par compte seulement : par adresse, un appareil du réseau qui retente un
            // ancien mot de passe d'un compte ferait croire deviné le compte d'un autre qui se connecte de là.
            Volet {
                journal: SECURITY,
                fournisseurs: AUDIT,
                ids: &[4625],
                quand: DEVINABLE,
                forme: Forme::Apres {
                    par: &["TargetUserName"],
                    nombre: ECHECS,
                    fenetre: FENETRE_ECHECS,
                    delai: DELAI_REUSSITE,
                    b_ids: &[4624],
                    b_quand: DEVINABLE,
                    gravite: Gravite::Critique,
                    pourquoi: DEVINE_ET_ENTRE,
                },
                audit: AUDIT_LOGON,
                sous_categorie: Some(LOGON),
            },
            echecs(
                &["TargetUserName"],
                ECHECS_LENTS,
                FENETRE_LENTE,
                Gravite::Alerte,
                DEVINE_LENTEMENT,
            ),
            echecs(
                &["IpAddress"],
                ECHECS_LENTS,
                FENETRE_LENTE,
                Gravite::Alerte,
                DEVINE_LENTEMENT,
            ),
            securite(&[4740], Condition::Toujours, compte_verrouille, COMPTES),
        ],
        limite: None,
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-RDP-001",
        sujet: (
            "Bureau à distance ouvert depuis l'extérieur du réseau local",
            "Remote Desktop opened from outside the local network",
        ),
        techniques: &["T1021.001", "T1133"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624",
            "https://attack.mitre.org/techniques/T1021/001/",
            "https://attack.mitre.org/techniques/T1133/",
        ],
        volets: &[
            Volet {
                audit: AUDIT_LOGON,
                ..securite(
                    &[4624],
                    Condition::Champ("LogonType", Test::NombreDans(&[10, 12])),
                    rdp_securite,
                    LOGON,
                )
            },
            chacun(
                LSM,
                &["Microsoft-Windows-TerminalServices-LocalSessionManager"],
                &[21, 24, 25],
                Condition::Toujours,
                rdp_session,
            ),
            chacun(
                RCM,
                &["Microsoft-Windows-TerminalServices-RemoteConnectionManager"],
                &[1149],
                Condition::Toujours,
                rdp_authentifie,
            ),
        ],
        limite: None,
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-IDE-001",
        sujet: (
            "connexion avec d'autres identifiants par un programme inhabituel",
            "logon with other credentials by an unusual program",
        ),
        techniques: &["T1078"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648",
            "https://attack.mitre.org/techniques/T1078/",
        ],
        volets: &[Volet {
            audit: AUDIT_LOGON,
            ..securite(&[4648], Condition::Toujours, autres_identifiants, LOGON)
        }],
        limite: Some((
            "« Exécuter en tant que » et ses semblables passent par le service d'ouverture de session secondaire, indiscernable de l'ordinaire",
            "“Run as” and the like go through the Secondary Logon service, indistinguishable from the ordinary",
        )),
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-PSH-001",
        sujet: (
            "PowerShell malveillant : téléchargement, code encodé, AMSI aveuglé, outils d'attaque",
            "malicious PowerShell: download, encoded code, blinded AMSI, attack tools",
        ),
        techniques: &["T1059.001", "T1685"],
        references: &[
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1",
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
            "https://devblogs.microsoft.com/powershell/powershell-the-blue-team/",
            "https://attack.mitre.org/techniques/T1059/001/",
        ],
        volets: &[
            chacun(
                POWERSHELL,
                &["Microsoft-Windows-PowerShell"],
                &[4104],
                Condition::Toujours,
                bloc_de_script,
            ),
            chacun(
                POWERSHELL_7,
                &["PowerShellCore"],
                &[4104],
                Condition::Toujours,
                bloc_de_script,
            ),
            chacun(
                POWERSHELL_CLASSIQUE,
                &["PowerShell"],
                &[400],
                Condition::Toujours,
                powershell_2,
            ),
        ],
        limite: Some((
            "sans la stratégie « Activer la journalisation des blocs de script », PowerShell n'écrit d'origine que les blocs qu'il juge lui-même suspects ; PowerShell 7 n'écrit dans son journal qu'une fois inscrit ; un long script est jugé partie par partie",
            "without the “Turn on Script Block Logging” policy, PowerShell only writes by default the blocks it judges suspicious itself; PowerShell 7 only writes to its log once registered; a long script is judged part by part",
        )),
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-DEF-001",
        sujet: (
            "Microsoft Defender désarmé, ou qui a trouvé une menace",
            "Microsoft Defender disarmed, or that found a threat",
        ),
        techniques: &["T1685"],
        references: &[
            "https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus",
            "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility",
            "https://attack.mitre.org/techniques/T1685/",
        ],
        volets: &[
            chacun(DEFENDER, DEFENDER_P, &[1116], Condition::Toujours, menace_trouvee),
            chacun(DEFENDER, DEFENDER_P, &[1117], Condition::Toujours, action_prise),
            chacun(DEFENDER, DEFENDER_P, &[1118, 1119], Condition::Toujours, action_echouee),
            chacun(DEFENDER, DEFENDER_P, &[5001], Condition::Toujours, temps_reel_coupe),
            chacun(DEFENDER, DEFENDER_P, &[5007], Condition::Toujours, reglage_change),
            chacun(
                DEFENDER,
                DEFENDER_P,
                &[5010, 5012, 5013],
                Condition::Toujours,
                protection_touchee,
            ),
        ],
        limite: None,
        defender: true,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-BIT-001",
        sujet: (
            "téléchargement en douce par BITS depuis une adresse inhabituelle",
            "stealthy BITS download from an unusual address",
        ),
        techniques: &["T1197"],
        references: &[
            "https://learn.microsoft.com/en-us/windows/win32/bits/background-intelligent-transfer-service-portal",
            "https://attack.mitre.org/techniques/T1197/",
        ],
        volets: &[chacun(
            BITS,
            &["Microsoft-Windows-Bits-Client"],
            &[59],
            Condition::Toujours,
            bits,
        )],
        limite: Some((
            "une redirection suivie par BITS ne se voit pas : seule l'adresse de départ est écrite",
            "a redirect followed by BITS cannot be seen: only the starting address is written",
        )),
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-WMI-001",
        sujet: (
            "persistance par un abonnement WMI permanent",
            "persistence through a permanent WMI subscription",
        ),
        techniques: &["T1546.003"],
        references: &[
            "https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity",
            "https://attack.mitre.org/techniques/T1546/003/",
        ],
        volets: &[chacun(
            WMI,
            &["Microsoft-Windows-WMI-Activity"],
            &[5861],
            Condition::Toujours,
            wmi,
        )],
        limite: None,
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-AUD-001",
        sujet: ("politique d'audit changée", "audit policy changed"),
        techniques: &["T1685.001"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719",
            "https://attack.mitre.org/techniques/T1685/001/",
        ],
        // 4719 s'écrit quelle que soit la politique d'audit (Microsoft) : pas de sous-catégorie à prouver.
        volets: &[chacun(SECURITY, AUDIT, &[4719], Condition::Toujours, audit_change)],
        limite: None,
        defender: false,
        un_journal_suffit: false,
    },
    Regle {
        id: "EVT-TAC-001",
        sujet: (
            "tâche planifiée créée ou changée pour lancer un interpréteur ou un programme d'un dossier inscriptible",
            "scheduled task created or changed to run an interpreter or a program from a writable folder",
        ),
        techniques: &["T1053.005"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702",
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events",
            "https://attack.mitre.org/techniques/T1053/005/",
        ],
        // Deux sources de rechange : l'audit (4698, 4702, avec le contenu de la tâche), coupé d'origine, ou
        // l'historique du Planificateur (106, 140, 200 : le nom et le programme lancé), coupé d'origine lui aussi.
        volets: &[
            Volet {
                audit: AUDIT_TACHES,
                ..securite(&[4698, 4702], Condition::Toujours, tache_auditee, AUTRES_OBJETS)
            },
            chacun(TACHES, TACHES_P, &[106], Condition::Toujours, tache_inscrite),
            chacun(TACHES, TACHES_P, &[140], Condition::Toujours, tache_mise_a_jour),
            chacun(TACHES, TACHES_P, &[200], Condition::Toujours, tache_lancee),
        ],
        limite: Some((
            "une tâche écrite directement dans le registre ou dans System32\\Tasks n'écrit aucun de ces événements ; l'historique du Planificateur ne dit pas les arguments",
            "a task written directly into the registry or System32\\Tasks writes none of these events; the Task Scheduler history does not record the arguments",
        )),
        defender: false,
        un_journal_suffit: true,
    },
    Regle {
        id: "EVT-PRC-001",
        sujet: (
            "processus suspect : outil d'attaque, commande encodée, téléchargement par un programme de Windows",
            "suspicious process: attack tool, encoded command, download by a Windows program",
        ),
        techniques: &["T1059", "T1027.010", "T1105", "T1218"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688",
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing",
            "https://attack.mitre.org/techniques/T1059/",
            "https://attack.mitre.org/techniques/T1027/010/",
            "https://attack.mitre.org/techniques/T1105/",
            "https://attack.mitre.org/techniques/T1218/",
        ],
        volets: &[Volet {
            audit: AUDIT_PROCESSUS,
            ..securite(&[4688], Condition::Toujours, processus_cree, PROCESSUS)
        }],
        limite: Some((
            "un programme renommé, ou lancé autrement qu'en processus (une bibliothèque chargée, du code en mémoire), ne se voit pas à sa ligne de commande",
            "a renamed program, or one started other than as a process (a loaded library, code in memory), cannot be seen from its command line",
        )),
        defender: false,
        un_journal_suffit: false,
    },
];
