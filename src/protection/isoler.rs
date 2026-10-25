//! Bac à sable : lancer un programme inconnu à l'écart du reste. Linux : bubblewrap (ou firejail), système en
//! lecture seule, dossier personnel et /tmp vides, pas de réseau, programme copié dans un dossier jetable.
//! Windows : Windows Sandbox, une machine jetable effacée à la fermeture, dossier du programme en lecture seule,
//! réseau coupé. macOS : sandbox-exec (le bac à sable intégré au système), pas de réseau, dossier personnel
//! illisible, écriture seulement dans le dossier jetable.

use std::path::{Path, PathBuf};

use crate::ui::*;

/// Dossier jetable qui reçoit une copie du programme (le bac à sable n'écrit jamais à côté de l'original). Créé de
/// façon exclusive, sous un nom imprévisible et réservé à l'utilisateur : dans un /tmp partagé, un dossier préparé
/// d'avance par un autre compte (avec un lien piégé au nom du programme) aurait fait écraser un de tes fichiers par
/// la copie.
pub(crate) fn dossier_jetable() -> std::io::Result<PathBuf> {
    static COMPTEUR: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COMPTEUR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dossier = std::env::temp_dir().join(format!("vanguard-bac-{}-{nanos}-{n}", std::process::id()));
    #[cfg_attr(windows, allow(unused_mut))]
    let mut createur = std::fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut createur, 0o700);
    createur.create(&dossier)?;
    Ok(dossier)
}

/// Arguments de bubblewrap. /run est masqué en entier : un système en lecture seule laisse quand même se connecter
/// aux sockets qu'il contient, et le réseau coupé ne touche pas aux sockets à chemin. Le bus du système s'y trouvait
/// (NetworkManager, logind, polkit : changer le réseau de l'ordinateur, ouvrir une vraie fenêtre de mot de passe),
/// comme les sockets de Docker, libvirt ou podman (root pour qui est dans leur groupe) et les disques montés sous
/// /run/media. Dans la session (/run/user/…), le bus de session permettrait de demander à systemd, hors du bac, de
/// lancer un programme : seul l'affichage Wayland en est rendu visible. `var_run` : /var/run est un vrai dossier
/// (vieux systèmes ; ailleurs, c'est un lien vers /run, masqué avec lui).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn arguments_bwrap(
    jetable: &Path,
    programme: &Path,
    session: Option<&str>,
    wayland: Option<&str>,
    var_run: bool,
) -> Vec<String> {
    let mut a: Vec<String> = [
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/root",
        "--tmpfs",
        "/run",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    if var_run {
        a.extend(["--tmpfs".into(), "/var/run".into()]);
    }
    if let Some(s) = session {
        a.extend(["--tmpfs".into(), s.into()]);
        if let Some(w) = wayland {
            let socket = format!("{s}/{w}");
            a.extend(["--ro-bind-try".into(), socket.clone(), socket]);
        }
    }
    let j = jetable.display().to_string();
    a.extend([
        "--bind".into(),
        j.clone(),
        j.clone(),
        "--chdir".into(),
        j.clone(),
        "--setenv".into(),
        "HOME".into(),
        j,
    ]);
    a.push(programme.display().to_string());
    a
}

/// Les arguments de bubblewrap pour une extension lancée avec `--isole` : la recette du bac à sable (système en
/// lecture seule, /home, /tmp et /run masqués, pas de réseau, aucune capacité), puis le dossier personnel masqué lui
/// aussi (où qu'il soit) : un montage en lecture seule n'empêcherait ni de joindre une socket (Bitwarden, Docker
/// Desktop, un agent SSH) ni d'écrire dans un tube (celui de Steam), et un programme hors du bac agirait pour
/// l'extension. Seuls restent le dossier jetable (la seule écriture permise, HOME) et le dossier de l'extension, en
/// lecture seule, comme dossier courant. Une socket posée dans le dossier de l'extension elle-même resterait
/// joignable : il est à la personne, et une copie (celle qui tourne) n'en a pas. `None` : bubblewrap n'est pas là.
#[cfg(target_os = "linux")]
pub(crate) fn arguments_extension(jetable: &Path, dossier: &Path, commande: &[String]) -> Option<Vec<String>> {
    let programme = commande.first()?;
    if !present("bwrap") {
        return None;
    }
    let session = std::env::var("XDG_RUNTIME_DIR").ok();
    let var_run = std::fs::symlink_metadata("/var/run").is_ok_and(|m| m.is_dir());
    let mut a = arguments_bwrap(jetable, Path::new(programme), session.as_deref(), None, var_run);
    // Le programme, le dossier courant et HOME de la recette sont remplacés : ceux de l'extension suivent.
    a.pop();
    if let Some(i) = a.iter().rposition(|x| x == "--chdir") {
        a.truncate(i);
    }
    let (j, d) = (jetable.display().to_string(), dossier.display().to_string());
    if let Some(maison) = crate::socle::personnel::dossier_personnel() {
        a.extend(["--tmpfs".into(), maison.display().to_string()]);
    }
    // Après le masquage (le jetable et le dossier sont souvent dans le dossier personnel) : d'abord le jetable en
    // écriture, puis le dossier de l'extension par-dessus, en lecture seule.
    a.extend([
        "--bind".into(),
        j.clone(),
        j.clone(),
        "--ro-bind".into(),
        d.clone(),
        d.clone(),
    ]);
    a.extend(["--chdir".into(), d, "--setenv".into(), "HOME".into(), j]);
    a.extend(commande.iter().cloned());
    Some(a)
}

/// Fichier de configuration de Windows Sandbox : dossier du programme en lecture seule, réseau coupé, programme
/// lancé à l'ouverture.
#[cfg_attr(not(windows), allow(dead_code))]
fn configuration_wsb(dossier: &str, nom: &str) -> String {
    let echapper = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!(
        "<Configuration>\r\n  <Networking>Disable</Networking>\r\n  <MappedFolders>\r\n    <MappedFolder>\r\n      \
         <HostFolder>{}</HostFolder>\r\n      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\Programme</SandboxFolder>\r\n      \
         <ReadOnly>true</ReadOnly>\r\n    </MappedFolder>\r\n  </MappedFolders>\r\n  <LogonCommand>\r\n    \
         <Command>explorer.exe C:\\Users\\WDAGUtilityAccount\\Desktop\\Programme\\{}</Command>\r\n  </LogonCommand>\r\n</Configuration>\r\n",
        echapper(dossier),
        echapper(nom)
    )
}

/// Le bac à sable (bwrap, firejail) est-il dans le PATH ? Lu sur le disque, sans lancer de shell.
#[cfg(target_os = "linux")]
fn present(cmd: &str) -> bool {
    crate::machine::linux::natif::present(cmd)
}

/// « vanguard isoler `<fichier>` » : lance le programme dans un bac à sable.
pub fn isoler(fichier: &Path) {
    titre(tr!("Bac à sable", "Sandbox"));
    // Le programme à isoler porte le nom que son auteur a choisi : montré, il est rendu inoffensif.
    let Ok(source) = fichier.canonicalize() else {
        trp!(
            "  ✖ Fichier introuvable : {}",
            "  ✖ File not found: {}",
            chemin_affichable(fichier)
        );
        return;
    };
    if !source.is_file() {
        trp!(
            "  ✖ Ce n'est pas un fichier : {}",
            "  ✖ Not a file: {}",
            chemin_affichable(&source)
        );
        return;
    }
    lancer(&source);
}

/// Le dossier jetable et, dedans, la copie exécutable du programme ; `None` (déjà dit) si l'un des deux manque.
/// `reel` : le chemin réel du dossier, sans lien.
#[cfg(unix)]
fn copie_jetable(source: &Path, reel: bool) -> Option<(PathBuf, PathBuf)> {
    use std::os::unix::fs::PermissionsExt;
    let Ok(jetable) = dossier_jetable() else {
        trp!(
            "  ✖ Dossier jetable impossible à créer.",
            "  ✖ Could not create the disposable folder."
        );
        return None;
    };
    let nom = source.file_name().unwrap_or_default();
    let jetable = if reel {
        jetable.canonicalize().unwrap_or(jetable)
    } else {
        jetable
    };
    let copie = jetable.join(nom);
    if std::fs::copy(source, &copie).is_err() {
        trp!(
            "  ✖ Copie impossible dans le dossier jetable.",
            "  ✖ Could not copy into the disposable folder."
        );
        let _ = std::fs::remove_dir_all(&jetable);
        return None;
    }
    let _ = std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o755));
    Some((jetable, copie))
}

/// Ce que dit la fin du programme isolé, une fois le dossier jetable effacé.
#[cfg(unix)]
fn dire_la_fin(statut: std::io::Result<std::process::ExitStatus>) {
    match statut {
        Ok(s) => trp!(
            "\n  {VERT}✔{RESET} Programme terminé (code {}). Le dossier jetable est effacé.",
            "\n  {VERT}✔{RESET} Program finished (code {}). The disposable folder is erased.",
            s.code().map_or_else(|| "?".to_string(), |c| c.to_string())
        ),
        Err(e) => trp!("  ✖ Lancement impossible : {e}", "  ✖ Could not start: {e}"),
    }
}

#[cfg(target_os = "linux")]
fn lancer(source: &Path) {
    let Some((jetable, copie)) = copie_jetable(source, false) else {
        return;
    };
    trp!(
        "  {GRIS}Isolé : système en lecture seule, dossier personnel invisible, pas de réseau. Copie jetable : {}{RESET}\n",
        "  {GRIS}Isolated: read-only system, home folder hidden, no network. Disposable copy: {}{RESET}\n",
        chemin_affichable(&copie)
    );
    let statut = if present("bwrap") {
        let session = std::env::var("XDG_RUNTIME_DIR").ok();
        let wayland = std::env::var("WAYLAND_DISPLAY").ok();
        // Un lien (le cas courant) n'est pas un dossier pour symlink_metadata : il suit /run, déjà masqué.
        let var_run = std::fs::symlink_metadata("/var/run").is_ok_and(|m| m.is_dir());
        std::process::Command::new("bwrap")
            .args(arguments_bwrap(
                &jetable,
                &copie,
                session.as_deref(),
                wayland.as_deref(),
                var_run,
            ))
            .status()
    } else if present("firejail") {
        std::process::Command::new("firejail")
            .args([
                "--noprofile",
                "--net=none",
                "--private-tmp",
                "--caps.drop=all",
                "--nonewprivs",
            ])
            .arg(format!("--private={}", jetable.display()))
            .arg(&copie)
            .status()
    } else {
        trp!(
            "  ✖ Ni bubblewrap ni firejail. Pour installer bubblewrap : {}",
            "  ✖ Neither bubblewrap nor firejail. To install bubblewrap: {}",
            crate::machine::linux::commande_installation("bubblewrap")
        );
        let _ = std::fs::remove_dir_all(&jetable);
        return;
    };
    let _ = std::fs::remove_dir_all(&jetable);
    dire_la_fin(statut);
}

/// Profil de sandbox-exec : tout est permis sauf le réseau, la lecture du dossier personnel et des disques branchés
/// (/Volumes), l'écriture hors du dossier jetable (et des terminaux, pour afficher), et les services qui lancent ou
/// pilotent une autre application. `open` passe par LaunchServices : l'application (un navigateur avec une adresse
/// qui porte des données) est lancée par launchd, hors du bac à sable et avec le réseau. Les Apple Events piloteraient
/// une application déjà ouverte, le presse-papiers ferait sortir ce qui y est copié. Profil non essayé sur un Mac.
#[cfg(any(target_os = "macos", test))]
fn profil_sandbox(jetable: &str, maison: &str) -> String {
    let echapper = |t: &str| t.replace('\\', "\\\\").replace('"', "\\\"");
    let (jetable, maison) = (echapper(jetable), echapper(maison));
    format!(
        "(version 1)\n(allow default)\n(deny network*)\n\
         (deny mach-lookup (global-name \"com.apple.coreservices.launchservicesd\") \
         (global-name-regex #\"^com\\.apple\\.lsd\\.\") \
         (global-name \"com.apple.coreservices.appleevents\") (global-name \"com.apple.pasteboard.1\"))\n\
         (deny file-read* (subpath \"{maison}\"))\n\
         (deny file-read* (subpath \"/Volumes\"))\n\
         (deny file-write*)\n\
         (allow file-read* file-write* (subpath \"{jetable}\"))\n\
         (allow file-write* (literal \"/dev/null\") (regex #\"^/dev/tty\") (regex #\"^/dev/fd/\"))\n"
    )
}

/// Les arguments de sandbox-exec pour une extension lancée avec `--isole` (macOS) : le profil du bac à sable (pas de
/// réseau, dossier personnel illisible, écriture seulement dans le dossier jetable), le dossier de l'extension relu
/// mais jamais écrit, puis la commande. Les chemins sont les chemins réels : sandbox-exec les compare ainsi (/var est
/// un lien vers /private/var). `None` : sandbox-exec n'est pas là.
#[cfg(target_os = "macos")]
pub(crate) fn arguments_extension(jetable: &Path, dossier: &Path, commande: &[String]) -> Option<Vec<String>> {
    if commande.is_empty() || !Path::new("/usr/bin/sandbox-exec").is_file() {
        return None;
    }
    let reel =
        |p: &Path| std::fs::canonicalize(p).map_or_else(|_| p.display().to_string(), |r| r.display().to_string());
    let maison = std::env::var("HOME").unwrap_or_default();
    let maison = reel(Path::new(&maison));
    let echapper = |t: &str| t.replace('\\', "\\\\").replace('"', "\\\"");
    let mut profil = profil_sandbox(&reel(jetable), &maison);
    // Après l'écriture permise dans le jetable (le dossier de l'extension y est souvent) : la relecture du dossier
    // de l'extension, jamais son écriture. Dans un profil, la dernière règle qui correspond l'emporte.
    let d = echapper(&reel(dossier));
    profil.push_str("(allow file-read* (subpath \"");
    profil.push_str(&d);
    profil.push_str("\"))\n(deny file-write* (subpath \"");
    profil.push_str(&d);
    profil.push_str("\"))\n");
    let mut a = vec!["-p".to_string(), profil];
    a.extend(commande.iter().cloned());
    Some(a)
}

#[cfg(target_os = "macos")]
fn lancer(source: &Path) {
    // sandbox-exec compare des chemins réels : /var est un lien vers /private/var.
    let Some((jetable, copie)) = copie_jetable(source, true) else {
        return;
    };
    let maison = crate::socle::maison();
    let maison = std::fs::canonicalize(&maison).unwrap_or(maison).display().to_string();
    trp!(
        "  {GRIS}Isolé : pas de réseau, dossier personnel illisible, écriture seulement dans la copie jetable : {}{RESET}\n",
        "  {GRIS}Isolated: no network, home folder unreadable, writing only in the disposable copy: {}{RESET}\n",
        chemin_affichable(&copie)
    );
    let statut = std::process::Command::new("sandbox-exec")
        .arg("-p")
        .arg(profil_sandbox(&jetable.display().to_string(), &maison))
        .arg(&copie)
        .current_dir(&jetable)
        .status();
    let _ = std::fs::remove_dir_all(&jetable);
    dire_la_fin(statut);
}

#[cfg(windows)]
fn lancer(source: &Path) {
    let sandbox = crate::commande::systeme32("WindowsSandbox.exe");
    if !sandbox.is_file() {
        trp!(
            "  ✖ Windows Sandbox n'est pas activé. Il existe sur Windows 10/11 Pro, Entreprise et Éducation :\n    Paramètres > Applications > Fonctionnalités facultatives > Plus de fonctionnalités Windows > « Bac à sable Windows ».",
            "  ✖ Windows Sandbox is not turned on. It exists on Windows 10/11 Pro, Enterprise and Education:\n    Settings > Apps > Optional features > More Windows features > “Windows Sandbox”."
        );
        return;
    }
    let dossier = source.parent().map(|d| d.display().to_string()).unwrap_or_default();
    let nom = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let Ok(jetable) = dossier_jetable() else {
        trp!(
            "  ✖ Configuration impossible à écrire.",
            "  ✖ Could not write the configuration."
        );
        return;
    };
    let wsb = jetable.join("vanguard.wsb");
    if std::fs::write(&wsb, configuration_wsb(&dossier, &nom)).is_err() {
        trp!(
            "  ✖ Configuration impossible à écrire.",
            "  ✖ Could not write the configuration."
        );
        return;
    }
    trp!(
        "  {GRIS}Windows Sandbox s'ouvre : machine jetable, réseau coupé, dossier du programme en lecture seule.\n  Tout est effacé à la fermeture de la fenêtre.{RESET}",
        "  {GRIS}Windows Sandbox opens: disposable machine, network off, program folder read-only.\n  Everything is erased when the window closes.{RESET}"
    );
    if let Err(e) = std::process::Command::new(&sandbox).arg(&wsb).spawn() {
        trp!("  ✖ Lancement impossible : {e}", "  ✖ Could not start: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sur cet ordinateur, le PATH lu trouve les mêmes bacs à sable que `command -v`.
    #[cfg(target_os = "linux")]
    #[test]
    fn present_comme_command_v() {
        for cmd in ["bwrap", "firejail", "sh", "vanguard-introuvable"] {
            let Some(r) = crate::commande::lancer(
                std::process::Command::new("sh").args(["-c", &format!("command -v {cmd}")]),
                5,
            ) else {
                return crate::essais::saute("sh absent");
            };
            assert_eq!(present(cmd), r.code == Some(0), "{cmd}");
        }
    }

    #[test]
    fn profil_de_sandbox_exec() {
        let p = profil_sandbox("/private/var/folders/x/T/vanguard-bac-1", "/Users/a \"b\"");
        assert!(p.contains("(deny network*)"));
        // Ni open (LaunchServices), ni Apple Events, ni presse-papiers : une application lancée par launchd sortirait
        // du bac à sable, avec le réseau.
        assert!(p.contains(
            "(deny mach-lookup (global-name \"com.apple.coreservices.launchservicesd\") \
             (global-name-regex #\"^com\\.apple\\.lsd\\.\") \
             (global-name \"com.apple.coreservices.appleevents\") (global-name \"com.apple.pasteboard.1\"))\n"
        ));
        assert!(p.contains("(deny file-read* (subpath \"/Volumes\"))"));
        assert!(p.contains("(deny file-read* (subpath \"/Users/a \\\"b\\\"\"))"));
        assert!(p.contains("(allow file-read* file-write* (subpath \"/private/var/folders/x/T/vanguard-bac-1\"))"));
    }

    #[test]
    fn dossier_jetable_exclusif() {
        let a = dossier_jetable().unwrap();
        let b = dossier_jetable().unwrap();
        // Deux dossiers distincts, chacun créé neuf (jamais un dossier préparé d'avance), réservés à l'utilisateur.
        assert_ne!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir(&a).unwrap();
        std::fs::remove_dir(&b).unwrap();
    }

    #[test]
    fn arguments_du_bac() {
        let a = arguments_bwrap(
            Path::new("/tmp/j"),
            Path::new("/tmp/j/p"),
            Some("/run/user/1000"),
            Some("wayland-1"),
            false,
        );
        let texte = a.join(" ");
        assert!(texte.contains("--unshare-all") && texte.contains("--new-session") && texte.contains("--cap-drop ALL"));
        // /run masqué (bus du système, socket de Docker), avant que l'affichage Wayland ne repasse : bubblewrap monte
        // dans l'ordre, un /run masqué après coup cacherait aussi l'affichage.
        let run = texte.find("--tmpfs /run ").expect("/run masqué");
        let session = texte
            .find("--tmpfs /run/user/1000 --ro-bind-try /run/user/1000/wayland-1 /run/user/1000/wayland-1")
            .expect("session masquée, seul l'affichage Wayland repasse");
        assert!(run < session);
        assert!(!texte.contains("/var/run"));
        assert!(
            arguments_bwrap(Path::new("/tmp/j"), Path::new("/tmp/j/p"), None, None, true)
                .join(" ")
                .contains("--tmpfs /run --unshare-all --die-with-parent --new-session --cap-drop ALL --tmpfs /var/run")
        );
        assert_eq!(a.last().map(String::as_str), Some("/tmp/j/p"));
        let wsb = configuration_wsb(r"C:\Users\x\Downloads", "setup.exe");
        assert!(wsb.contains("<Networking>Disable</Networking>") && wsb.contains("<ReadOnly>true</ReadOnly>"));
        assert!(wsb.contains(r"Programme\setup.exe"));
    }
}
