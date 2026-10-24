//! Les onze premières règles `EVT-`, écrites d'après la documentation de Microsoft de chaque événement (noms des
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

// Rend une `Option` pour que chaque juge finisse sur une seule expression, comme ses refus (`return None`).
#[allow(clippy::unnecessary_wraps)]
fn indice(objet: String, gravite: Gravite, pourquoi: Texte, details: Vec<(Libelle, String)>) -> Option<Indice> {
    Some(Indice {
        objet,
        gravite,
        pourquoi,
        details: details.into_iter().filter(|(_, v)| rempli(v)).collect(),
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
    "bash",
    "wsl",
    "python",
    "pythonw",
    "node",
];

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
        "security".into(),
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
        journal.to_lowercase(),
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

/// Les mises à jour des définitions de Defender installent un pilote « MpKsl… » depuis leur dossier, à chaque
/// mise à jour (noté par Microsoft) : protégé par Defender lui-même.
fn pilote_de_defender(nom: &str, chemin: &str) -> bool {
    nom.to_lowercase().starts_with("mpksl")
        && chemin.contains("\\programdata\\microsoft\\windows defender\\definition updates\\")
}

/// Ce qu'un nouveau service a de suspect : sa gravité et pourquoi ; rien pour un service ordinaire.
pub(crate) fn service_suspect(nom: &str, image: &str) -> Option<(Gravite, Texte)> {
    let bas = chemin_bas(image);
    let (programme, _) = decouper(image);
    let programme_bas = chemin_bas(&programme);
    let nom_prog = nom_programme(&programme);
    if est_interprete(&nom_prog) || LANCEMENTS.iter().any(|l| bas.contains(l)) {
        return Some((
            Gravite::Critique,
            (
                "le service lance un interpréteur de commandes ou du code encodé, comme les outils d'attaque qui s'installent à distance",
                "the service runs a command interpreter or encoded code, like attack tools that install themselves remotely",
            ),
        ));
    }
    if pilote_de_defender(nom, &bas) {
        return None;
    }
    if OUTILS_DE_SERVICE
        .iter()
        .any(|o| nom.to_lowercase().starts_with(o) || nom_prog.starts_with(o))
    {
        return Some((
            Gravite::Alerte,
            (
                "le service est celui d'un outil qui lance des commandes à distance (PsExec et ses semblables), l'outil le plus utilisé par les attaquants pour passer d'un ordinateur à l'autre",
                "the service belongs to a tool that runs commands remotely (PsExec and the like), the tool attackers use most to move from one computer to another",
            ),
        ));
    }
    if !programme_bas.contains('\\') && !programme_bas.starts_with('%') && !programme_bas.is_empty() {
        return Some((
            Gravite::Alerte,
            (
                "le service n'a pas de dossier : son programme est cherché ailleurs, là où un autre du même nom peut l'attendre",
                "the service has no folder: its program is looked up elsewhere, where another one with the same name may wait",
            ),
        ));
    }
    if INSCRIPTIBLES.iter().any(|d| programme_bas.contains(d)) {
        return Some((
            Gravite::Alerte,
            (
                "le service est rangé dans un dossier où un compte ordinaire écrit (profil, dossier temporaire), où rien ne s'installe normalement",
                "the service is stored in a folder an ordinary account can write to (profile, temporary folder), where nothing is normally installed",
            ),
        ));
    }
    if programme_bas.starts_with("\\\\")
        && !programme_bas.starts_with("\\\\?\\")
        && !programme_bas.starts_with("\\??\\")
    {
        return Some((
            Gravite::Alerte,
            (
                "le service est lancé depuis un partage réseau",
                "the service is run from a network share",
            ),
        ));
    }
    if programme_bas.contains("\\programdata\\") {
        return Some((
            Gravite::Info,
            (
                "le service est rangé dans ProgramData, où tout compte peut créer des dossiers ; certains programmes y installent le leur",
                "the service is stored in ProgramData, where any account can create folders; some programs install theirs there",
            ),
        ));
    }
    if nom_court(&programme_bas) {
        return Some((
            Gravite::Info,
            (
                "le chemin du service passe par un nom court 8.3, qui cache le nom du dossier",
                "the service path goes through an 8.3 short name, which hides the folder name",
            ),
        ));
    }
    None
}

fn service_installe(e: &EvenementWindows) -> Option<Indice> {
    let nom = champ(e, "ServiceName");
    let image = champ(e, "ImagePath");
    let (gravite, pourquoi) = service_suspect(nom, image)?;
    indice(
        format!("{}|{}", nom.to_lowercase(), chemin_bas(image)),
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

fn journal_des_evenements_change(e: &EvenementWindows) -> Option<Indice> {
    indice(
        "eventlog".into(),
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
    indice(
        format!("cree:{}", nom.to_lowercase()),
        Gravite::Info,
        ("un compte a été créé", "an account was created"),
        details,
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

fn membre(e: &EvenementWindows) -> String {
    let nom = champ(e, "MemberName");
    if rempli(nom) {
        nom.to_string()
    } else {
        champ(e, "MemberSid").to_string()
    }
}

fn ajout_groupe_local(e: &EvenementWindows) -> Option<Indice> {
    let sid = champ(e, "TargetSid");
    let &(s, gravite, pourquoi) = GROUPES_LOCAUX.iter().find(|(s, _, _)| s.eq_ignore_ascii_case(sid))?;
    indice(
        format!("groupe:{}:{}", s.to_lowercase(), champ(e, "MemberSid").to_lowercase()),
        gravite,
        pourquoi,
        vec![
            (Libelle::Groupe, champ(e, "TargetUserName").to_string()),
            (Libelle::Membre, membre(e)),
            (Libelle::Auteur, auteur(e)),
        ],
    )
}

fn ajout_groupe_domaine(e: &EvenementWindows) -> Option<Indice> {
    let sid = champ(e, "TargetSid").to_ascii_uppercase();
    if !sid.starts_with("S-1-5-21-") || !RID_DOMAINE.iter().any(|r| sid.ends_with(r)) {
        return None;
    }
    indice(
        format!("groupe:{}:{}", sid.to_lowercase(), champ(e, "MemberSid").to_lowercase()),
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

fn distance(adresse: &str, compte: &str) -> Option<Indice> {
    let (gravite, pourquoi) = match lieu(adresse) {
        Lieu::Local => return None,
        Lieu::Internet => (
            Gravite::Alerte,
            (
                "une session de Bureau à distance a été ouverte depuis une adresse d'Internet : le Bureau à distance est exposé",
                "a Remote Desktop session was opened from an Internet address: Remote Desktop is exposed",
            ),
        ),
        Lieu::Partage => (
            Gravite::Info,
            (
                "une session de Bureau à distance depuis une adresse partagée (100.64.0.0/10 : opérateur, ou réseau privé comme Tailscale)",
                "a Remote Desktop session from a shared address (100.64.0.0/10: carrier, or a private network such as Tailscale)",
            ),
        ),
        Lieu::Illisible => (
            Gravite::Info,
            (
                "une session de Bureau à distance depuis une adresse illisible",
                "a Remote Desktop session from an unreadable address",
            ),
        ),
    };
    indice(
        format!("{}|{}", adresse.trim().to_lowercase(), compte.trim().to_lowercase()),
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
/// (msoobe, CloudExperienceHostBroker). Ailleurs, rien de Windows ne le fait : un programme inhabituel l'a fait.
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
    "c:\\windows\\system32\\cloudexperiencehostbroker.exe",
];

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
    let (gravite, pourquoi) = if est_interprete(&nom_programme(&bas)) || INSCRIPTIBLES.iter().any(|d| bas.contains(d)) {
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
    let mut s: String = texte.to_lowercase().chars().filter(|&c| c != '`').collect();
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
        if self.bas.contains(motif) {
            return true;
        }
        let m = ramasse(motif);
        m.chars().count() >= RAMASSE_MIN && self.ramasse.contains(&m)
    }
}

const AMSI: &[&str] = &[
    "amsiutils",
    "amsiinitfailed",
    "amsiscanbuffer",
    "amsicontext",
    "amsiopensession",
];

/// Des outils offensifs publiés, par les noms de leurs commandes : ils n'ont pas d'autre usage.
const OUTILS_OFFENSIFS: &[&str] = &[
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
    "minidumpwritedump",
    "-e powershell",
    "-e cmd",
];

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
    "iwr ",
    "irm ",
];

/// Ce qui télécharge du texte en mémoire, presque toujours pour l'exécuter.
const TELECHARGER_EN_MEMOIRE: &[&str] = &["downloadstring", "downloaddata"];

/// Ce qui défait une valeur encodée en code.
const DECODER: &[&str] = &["frombase64string"];
const CHARGER: &[&str] = &[
    "reflection.assembly]::load",
    "::load(",
    "-bxor",
    "gzipstream",
    "deflatestream",
];

/// Ce qui coupe une défense de Defender ou efface un journal.
const DESARMER: &[&str] = &[
    "disablerealtimemonitoring",
    "disableioavprotection",
    "disablebehaviormonitoring",
    "disablescriptscanning",
    "add-mppreference -exclusion",
    "clear-eventlog",
    "wevtutil cl",
    "wevtutil.exe cl",
    "remove-eventlog",
];

fn un(s: &Script, motifs: &[&str]) -> bool {
    motifs.iter().any(|m| s.contient(m))
}

/// Ce qu'un bloc de script a de malveillant : (catégorie, gravité, pourquoi).
pub(crate) fn script_suspect(texte: &str) -> Option<(&'static str, Gravite, Texte)> {
    let s = Script::de(texte);
    if un(&s, AMSI) {
        return Some((
            "amsi",
            Gravite::Critique,
            (
                "un script touche à AMSI, l'analyse des scripts par l'antivirus : la façon connue de l'aveugler",
                "a script tampers with AMSI, the antivirus script scanning: the known way to blind it",
            ),
        ));
    }
    if un(&s, OUTILS_OFFENSIFS) {
        return Some((
            "outil",
            Gravite::Critique,
            (
                "un script nomme un outil d'attaque publié (vol de mots de passe, prise de contrôle)",
                "a script names a published attack tool (password theft, takeover)",
            ),
        ));
    }
    if un(&s, DESARMER) {
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
                "un script télécharge du code et l'exécute aussitôt, sans fichier",
                "a script downloads code and runs it right away, without a file",
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

/// Le niveau Avertissement (3) : PowerShell écrit lui-même d'origine les blocs qu'il juge suspects.
const AVERTISSEMENT: u8 = 3;

fn bloc_de_script(e: &EvenementWindows) -> Option<Indice> {
    let texte = champ(e, "ScriptBlockText");
    let chemin = champ(e, "Path");
    let (categorie, gravite, pourquoi) = match script_suspect(texte) {
        Some(x) => x,
        None if e.niveau == Some(AVERTISSEMENT) => (
            "avertissement",
            Gravite::Info,
            (
                "PowerShell a lui-même jugé ce bloc de script suspect (des scripts d'installation le sont aussi)",
                "PowerShell itself judged this script block suspicious (setup scripts can be too)",
            ),
        ),
        None => return None,
    };
    // L'objet : la catégorie et le fichier du script (un même script relancé reste un seul objet, que l'on peut
    // déclarer normal), ou à défaut son numéro de bloc.
    let quoi = if rempli(chemin) {
        chemin_bas(chemin)
    } else if rempli(champ(e, "ScriptBlockId")) {
        // Les parties d'un long script (MessageNumber, MessageTotal) portent le même numéro de bloc : une seule
        // trouvaille par script lancé.
        champ(e, "ScriptBlockId").to_lowercase()
    } else {
        ramasse(&script_bas(texte)).chars().take(120).collect()
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

fn temps_reel_coupe(_: &EvenementWindows) -> Option<Indice> {
    indice(
        "temps-reel".into(),
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
    let coupe = COUPURES.iter().find(|c| bas.contains(&format!("\\{c}=0x1")))?;
    let objet = if *coupe == "disablerealtimemonitoring" {
        "temps-reel:reglage".to_string()
    } else {
        format!("reglage:{coupe}")
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
/// Office, Edge, Defender, Store ; OneDrive par sfx.ms, OneNote par onenote.net, vus dans un échantillon public), Google (mise à jour de Chrome : dl.google.com, gvt1.com), Mozilla (mise à jour
/// de Firefox), Adobe. Seulement des domaines où seul leur éditeur publie : pas de stockage ouvert à tous
/// (blob.core.windows.net, storage.googleapis.com, github.com).
const DOMAINES_ATTENDUS: &[&str] = &[
    "microsoft.com",
    "windowsupdate.com",
    "windows.com",
    "office.com",
    "office.net",
    "live.com",
    "msedge.net",
    "sfx.ms",
    "onenote.net",
    "xboxlive.com",
    "google.com",
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

fn wmi(e: &EvenementWindows) -> Option<Indice> {
    let consommateur = champ(e, "CONSUMER");
    let bas = consommateur.to_lowercase();
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
    }
}

const SECURITY: &str = "Security";
const SYSTEM: &str = "System";
const POWERSHELL: &str = "Microsoft-Windows-PowerShell/Operational";
const POWERSHELL_7: &str = "PowerShellCore/Operational";
const DEFENDER: &str = "Microsoft-Windows-Windows Defender/Operational";
const BITS: &str = "Microsoft-Windows-Bits-Client/Operational";
const WMI: &str = "Microsoft-Windows-WMI-Activity/Operational";
const LSM: &str = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
const RCM: &str = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

/// Les journaux que lisent les règles.
pub(crate) const JOURNAUX: &[&str] = &[
    SECURITY,
    SYSTEM,
    POWERSHELL,
    POWERSHELL_7,
    DEFENDER,
    BITS,
    WMI,
    LSM,
    RCM,
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
            },
        ],
        limite: Some((
            "un enregistrement changé ou remplacé sans changer son numéro ne se voit pas",
            "a record changed or replaced without changing its number cannot be seen",
        )),
        defender: false,
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
        limite: None,
        defender: false,
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
            chacun(SECURITY, AUDIT, &[4720], Condition::Toujours, compte_cree),
            chacun(SECURITY, AUDIT, &[4732], Condition::Toujours, ajout_groupe_local),
            chacun(
                SECURITY,
                AUDIT,
                &[4728, 4756],
                Condition::Toujours,
                ajout_groupe_domaine,
            ),
            chacun(SECURITY, AUDIT, &[4738], Condition::Toujours, compte_change),
        ],
        limite: None,
        defender: false,
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
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
            "https://attack.mitre.org/techniques/T1110/001/",
        ],
        volets: &[
            Volet {
                journal: SECURITY,
                fournisseurs: AUDIT,
                ids: &[4625],
                quand: DEVINABLE,
                forme: Forme::Rafale {
                    par: &["TargetUserName"],
                    nombre: ECHECS,
                    fenetre: FENETRE_ECHECS,
                    gravite: Gravite::Alerte,
                    pourquoi: DEVINE,
                },
                audit: Audit::DOrigine,
            },
            Volet {
                journal: SECURITY,
                fournisseurs: AUDIT,
                ids: &[4625],
                quand: DEVINABLE,
                forme: Forme::Rafale {
                    par: &["IpAddress"],
                    nombre: ECHECS,
                    fenetre: FENETRE_ECHECS,
                    gravite: Gravite::Alerte,
                    pourquoi: DEVINE,
                },
                audit: Audit::DOrigine,
            },
            Volet {
                journal: SECURITY,
                fournisseurs: AUDIT,
                ids: &[4625],
                quand: DEVINABLE,
                forme: Forme::Rafale {
                    par: &[],
                    nombre: ECHECS_RAPIDES,
                    fenetre: FENETRE_RAPIDE,
                    gravite: Gravite::Alerte,
                    pourquoi: DEVINE_VITE,
                },
                audit: Audit::DOrigine,
            },
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
                audit: Audit::DOrigine,
            },
            Volet {
                journal: SECURITY,
                fournisseurs: AUDIT,
                ids: &[4625],
                quand: DEVINABLE,
                forme: Forme::Apres {
                    par: &["IpAddress"],
                    nombre: ECHECS,
                    fenetre: FENETRE_ECHECS,
                    delai: DELAI_REUSSITE,
                    b_ids: &[4624],
                    b_quand: DEVINABLE,
                    gravite: Gravite::Critique,
                    pourquoi: DEVINE_ET_ENTRE,
                },
                audit: Audit::DOrigine,
            },
        ],
        limite: None,
        defender: false,
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
            chacun(
                SECURITY,
                AUDIT,
                &[4624],
                Condition::Champ("LogonType", Test::NombreDans(&[10, 12])),
                rdp_securite,
            ),
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
        volets: &[chacun(
            SECURITY,
            AUDIT,
            &[4648],
            Condition::Toujours,
            autres_identifiants,
        )],
        limite: None,
        defender: false,
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
        ],
        limite: Some((
            "sans la stratégie « Activer la journalisation des blocs de script », PowerShell n'écrit d'origine que les blocs qu'il juge lui-même suspects ; PowerShell 7 n'écrit dans son journal qu'une fois inscrit",
            "without the “Turn on Script Block Logging” policy, PowerShell only writes by default the blocks it judges suspicious itself; PowerShell 7 only writes to its log once registered",
        )),
        defender: false,
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
            chacun(
                DEFENDER,
                &["Microsoft-Windows-Windows Defender"],
                &[1116],
                Condition::Toujours,
                menace_trouvee,
            ),
            chacun(
                DEFENDER,
                &["Microsoft-Windows-Windows Defender"],
                &[1117],
                Condition::Toujours,
                action_prise,
            ),
            chacun(
                DEFENDER,
                &["Microsoft-Windows-Windows Defender"],
                &[5001],
                Condition::Toujours,
                temps_reel_coupe,
            ),
            chacun(
                DEFENDER,
                &["Microsoft-Windows-Windows Defender"],
                &[5007],
                Condition::Toujours,
                reglage_change,
            ),
        ],
        limite: None,
        defender: true,
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
        limite: None,
        defender: false,
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
    },
    Regle {
        id: "EVT-AUD-001",
        sujet: ("politique d'audit changée", "audit policy changed"),
        techniques: &["T1685.001"],
        references: &[
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719",
            "https://attack.mitre.org/techniques/T1685/001/",
        ],
        volets: &[chacun(SECURITY, AUDIT, &[4719], Condition::Toujours, audit_change)],
        limite: None,
        defender: false,
    },
];
