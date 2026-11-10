//! Le bac à sable de la fenêtre sous Linux : Landlock et no_new_privs, posés sur la fenêtre seule, au démarrage,
//! avant qu'elle ait un seul fil de plus que le sien (`relais::separer`, qui a déjà mis le relais à part).
//!
//! Restreinte, la fenêtre lit le système (bibliothèques, pilotes, réglages : `SYSTEME`, /run sauf /run/user et
//! /run/media) et, du compte, ses seuls thèmes de curseurs et son fichier de composition (`Milieu::curseurs`) ; elle
//! dessine (le pilote de la carte graphique, /dev/dri et /dev/nvidia*), parle à son bureau (la socket de Wayland, ou
//! celles d'X11, jamais les deux : `Bureau`) et au relais, et rien d'autre : elle ne lit ni le dossier personnel (ni
//! ~/.ssh, ni les navigateurs, ni les jetons), ni /tmp, ni les disques branchés ; elle n'écrit aucun fichier (sauf
//! /dev/null), ne lance aucun programme, n'ouvre aucune connexion réseau, ne joint aucune autre socket Unix (le bus
//! de session : `systemd-run --user` y lancerait n'importe quoi hors du bac), ne signale ni n'observe aucun processus
//! d'en dehors (Landlock y range aussi /proc des autres et ptrace), et ne peut plus gagner de droits (un programme
//! setuid). Un défaut de dessin, de police ou de JSON qui prendrait la main dans la fenêtre n'aurait que cela, et le
//! relais, qui ne lance que la liste fermée. Un fichier refusé que le dessin aurait voulu (un réglage de pilote du
//! compte, ~/.drirc ou ~/.nv) le laisse à ses valeurs par défaut ; si le bureau ou OpenGL ne s'ouvrait pas,
//! `vanguard` ne verrait pas « ouverte » et prendrait son menu du terminal, en le disant (src/demarrage).
//!
//! Pourquoi la fenêtre seule et pas `vanguard` : ce qu'elle lance hériterait du bac, et `vanguard` ne verrait plus ni
//! les programmes en cours, ni le bus système, ni sudo (no_new_privs) ; il le dirait (« non vérifié »), mais le bilan
//! d'un proche y perdrait (essai du lot 1b, dans un dossier jetable : 8 commandes de la liste sur 13 touchées).
//!
//! Selon le noyau, une partie seulement (`Bac::manques`) : le réseau depuis Landlock 4 (Linux 6.7), les signaux et
//! les sockets abstraites depuis 6 (6.12), les sockets Unix nommées depuis 9 ; sans Landlock (désactivé, ou noyau
//! d'avant 5.13), no_new_privs seul, et la fenêtre le dit dans sa console.
//!
//! Le bac ne retient pas ce que le bureau permet à toute fenêtre : sous X11, taper dans les autres fenêtres et lire
//! leur presse-papiers (et les sockets abstraites y restent joignables : X11 en a besoin) ; sous Wayland, cela dépend
//! du compositeur : Hyprland et ceux de wlroots offrent à toute fenêtre le clavier et le pointeur virtuels, le
//! presse-papiers des autres et la capture de l'écran, par la socket même où elle dessine (MODELE-DE-MENACE.md).

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

// Les actions de Landlock (linux/landlock.h).
const EXECUTE: u64 = 1;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;
const RESOLVE_UNIX: u64 = 1 << 16;
/// Celles qui s'appliquent à un fichier (une règle sur un fichier n'accepte qu'elles).
const SUR_UN_FICHIER: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV | RESOLVE_UNIX;
const NET_TCP: u64 = 0b11;
const NET_UDP: u64 = 0b1100;
const SCOPE_ABSTRAIT: u64 = 1;
const SCOPE_SIGNAL: u64 = 1 << 1;
const VERSION: u32 = 1;
const PATH_BENEATH: i32 = 1;

/// Ce que le bac à sable a pu faire.
#[derive(Debug, PartialEq, Eq)]
pub enum Bac {
    /// Landlock posé (sa version), avec ce que ce noyau ne sait pas encore restreindre. `maison` : le dossier
    /// personnel reste lisible (rangé sous un dossier du système, que la fenêtre lit).
    Actif {
        abi: u32,
        manques: Vec<&'static str>,
        maison: bool,
    },
    /// Pas de Landlock : pourquoi. `nnp` : no_new_privs posé quand même.
    Absent { raison: String, nnp: bool },
}

impl Bac {
    /// La phrase pour la console de la fenêtre, et si elle est à souligner.
    pub fn phrase(&self) -> (String, bool) {
        match self {
            Bac::Actif { abi, maison: true, .. } => (
                crate::trf!(
                    "Bac à sable actif (Landlock {}), mais votre dossier personnel reste lisible par la fenêtre : il est rangé sous un dossier du système.",
                    "Sandbox active (Landlock {}), but your home folder stays readable by the window: it sits under a system folder.",
                    abi
                ),
                true,
            ),
            Bac::Actif { abi, manques, .. } if manques.is_empty() => (
                crate::trf!(
                    "Bac à sable actif (Landlock {}) : la fenêtre ne peut ni lire vos fichiers, ni en écrire, ni lancer de programme, ni ouvrir de connexion ; `vanguard` est lancé à côté d'elle, avec tous ses droits de lecture.",
                    "Sandbox active (Landlock {}): the window can neither read your files, write any, start programs nor open connections; `vanguard` is started beside it, with all its read rights.",
                    abi
                ),
                false,
            ),
            Bac::Actif { abi, manques, .. } => (
                crate::trf!(
                    "Bac à sable actif (Landlock {}) : la fenêtre ne peut ni écrire de fichier ni lancer de programme ; ce noyau ne sait pas lui retirer {}.",
                    "Sandbox active (Landlock {}): the window can neither write files nor start programs; this kernel cannot take away {}.",
                    abi,
                    manques.join(", ")
                ),
                false,
            ),
            Bac::Absent { raison, nnp } => (
                if *nnp {
                    crate::trf!(
                        "Bac à sable absent ({}) : la fenêtre a les droits de votre compte, sauf d'en gagner d'autres (no_new_privs).",
                        "Sandbox missing ({}): the window has your account's rights, except gaining more (no_new_privs).",
                        raison
                    )
                } else {
                    crate::trf!(
                        "Bac à sable absent ({}) : la fenêtre a les droits de votre compte.",
                        "Sandbox missing ({}): the window has your account's rights.",
                        raison
                    )
                },
                true,
            ),
        }
    }
}

/// Ce que Landlock `abi` sait restreindre : (fichiers, réseau, portées), et ce qu'il ne sait pas encore.
fn gere(abi: u32, wayland: bool) -> (u64, u64, u64, Vec<&'static str>) {
    let mut fs = REFER - 1;
    let mut net = 0;
    let mut scope = 0;
    let mut manques = Vec::new();
    if abi >= 2 {
        fs |= REFER;
    }
    if abi >= 3 {
        fs |= TRUNCATE;
    }
    if abi >= 4 {
        net |= NET_TCP;
    } else {
        manques.push(crate::tr!("le réseau", "the network"));
    }
    if abi >= 5 {
        fs |= IOCTL_DEV;
    }
    if abi >= 6 {
        scope |= SCOPE_SIGNAL;
        // Les sockets abstraites, seulement sous Wayland : X11 en a une, que libxcb essaie d'abord, et dont le refus
        // ne le fait pas passer à la socket nommée (la fenêtre ne s'ouvrirait pas).
        if wayland {
            scope |= SCOPE_ABSTRAIT;
        }
    } else {
        manques.push(crate::tr!("les signaux", "signals"));
    }
    if abi >= 9 {
        fs |= RESOLVE_UNIX;
    } else {
        manques.push(crate::tr!(
            "les sockets Unix (le bus de session)",
            "Unix sockets (the session bus)"
        ));
    }
    if abi >= 10 {
        net |= NET_UDP;
    }
    (fs, net, scope, manques)
}

/// Le bureau que winit prendra, à la même règle que lui (winit 0.30, platform_impl/linux/mod.rs) : Wayland dès que
/// WAYLAND_DISPLAY ou WAYLAND_SOCKET n'est pas vide, sinon X11 si DISPLAY ne l'est pas. Il n'y revient pas ensuite :
/// si Wayland ne s'ouvre pas, la fenêtre ne s'ouvre pas (pas de repli sur X11), et le bac ne permet que ce bureau-là.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bureau {
    Wayland,
    X11,
    Aucun,
}

/// Ce que le bac lit du système et de l'environnement avant de se poser (à part, pour les essais). Une variable vide
/// compte comme absente, comme pour winit.
#[derive(Debug, Default)]
struct Milieu {
    wayland: Option<String>,
    wayland_socket: bool,
    display: bool,
    /// XDG_RUNTIME_DIR.
    execution: Option<PathBuf>,
    /// HOME.
    maison: Option<PathBuf>,
    xauthority: Option<PathBuf>,
    xcomposefile: Option<PathBuf>,
    xdg_config_home: Option<PathBuf>,
    xdg_data_home: Option<PathBuf>,
    xdg_data_dirs: Option<String>,
    xcursor_path: Option<String>,
    /// Les noms des dossiers /, /run et /dev.
    racine: Vec<String>,
    run: Vec<String>,
    dev: Vec<String>,
}

impl Milieu {
    fn lire() -> Milieu {
        let texte = |nom: &str| std::env::var(nom).ok().filter(|v| !v.is_empty());
        let chemin = |nom: &str| std::env::var_os(nom).filter(|v| !v.is_empty()).map(PathBuf::from);
        let noms = |d: &str| -> Vec<String> {
            std::fs::read_dir(d).map_or_else(
                |_| Vec::new(),
                |d| {
                    d.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                },
            )
        };
        Milieu {
            wayland: texte("WAYLAND_DISPLAY"),
            wayland_socket: texte("WAYLAND_SOCKET").is_some(),
            display: texte("DISPLAY").is_some(),
            execution: chemin("XDG_RUNTIME_DIR"),
            maison: chemin("HOME"),
            xauthority: chemin("XAUTHORITY"),
            xcomposefile: chemin("XCOMPOSEFILE"),
            xdg_config_home: chemin("XDG_CONFIG_HOME"),
            xdg_data_home: chemin("XDG_DATA_HOME"),
            xdg_data_dirs: texte("XDG_DATA_DIRS"),
            xcursor_path: texte("XCURSOR_PATH"),
            racine: noms("/"),
            run: noms("/run"),
            dev: noms("/dev"),
        }
    }

    fn bureau(&self) -> Bureau {
        if self.wayland.is_some() || self.wayland_socket {
            Bureau::Wayland
        } else if self.display {
            Bureau::X11
        } else {
            Bureau::Aucun
        }
    }

    /// Les dossiers de curseurs du compte, comme les cherchent libXcursor, libwayland-cursor et xcursor : XCURSOR_PATH
    /// s'il est là (« ~ » compris), sinon ~/.local/share/icons (ou XDG_DATA_HOME/icons), ~/.icons, les icons de
    /// XDG_DATA_DIRS et ~/.cursors. Seulement un dossier nommé icons ou cursors : jamais le dossier personnel, ni
    /// ~/.local/share entier (les trousseaux, les données des programmes y sont), même si une variable le nomme.
    fn curseurs(&self) -> Vec<PathBuf> {
        let deplier = |e: &str| -> Option<PathBuf> {
            match (e.strip_prefix("~/"), &self.maison) {
                (Some(reste), Some(m)) => Some(m.join(reste)),
                (Some(_), None) => None,
                (None, _) => Some(PathBuf::from(e)),
            }
        };
        let mut c: Vec<PathBuf> = Vec::new();
        if let Some(x) = &self.xcursor_path {
            c.extend(x.split(':').filter_map(deplier));
        } else {
            match (&self.xdg_data_home, &self.maison) {
                (Some(d), _) => c.push(d.join("icons")),
                (None, Some(m)) => c.push(m.join(".local/share/icons")),
                (None, None) => {}
            }
            if let Some(m) = &self.maison {
                c.push(m.join(".icons"));
                c.push(m.join(".cursors"));
            }
            if let Some(dirs) = &self.xdg_data_dirs {
                c.extend(dirs.split(':').filter_map(deplier).map(|d| d.join("icons")));
            }
        }
        c.retain(|d| {
            d.is_absolute()
                && !d.components().any(|p| matches!(p, std::path::Component::ParentDir))
                && d.file_name()
                    .is_some_and(|n| [".icons", "icons", ".cursors", "cursors"].iter().any(|v| n == *v))
        });
        c
    }

    /// Le fichier de composition du compte (les touches mortes, ~/.XCompose), comme le cherche xkbcommon.
    fn composition(&self) -> Vec<PathBuf> {
        let mut c: Vec<PathBuf> = self.xcomposefile.iter().cloned().collect();
        match (&self.xdg_config_home, &self.maison) {
            (Some(d), _) => c.push(d.join("XCompose")),
            (None, Some(m)) => c.push(m.join(".config/XCompose")),
            (None, None) => {}
        }
        c.extend(self.maison.iter().map(|m| m.join(".XCompose")));
        c
    }
}

/// Le bureau que la fenêtre prendra (`Bureau`).
#[cfg(test)]
pub fn bureau() -> Bureau {
    Milieu::lire().bureau()
}

/// Les dossiers du système que la fenêtre lit, à la racine : bibliothèques et pilotes (/usr, /lib*, /opt, et ceux de
/// NixOS, Guix, Snap et Flatpak), réglages (/etc : glvnd, fontconfig, ld.so), /proc et /sys (le pilote NVIDIA, Mesa et
/// libdrm y lisent la carte). Pas /home, /root, /tmp, /var, /mnt, /media, /srv ni ce qu'un disque y a monté.
const SYSTEME: [&str; 11] = [
    "usr", "etc", "opt", "bin", "sbin", "proc", "sys", "nix", "gnu", "snap", "app",
];

/// Les chemins permis et leurs actions.
fn regles(m: &Milieu) -> Vec<(PathBuf, u64)> {
    const LIRE: u64 = READ_FILE | READ_DIR;
    const CARTE: u64 = READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV;
    let mut r: Vec<(PathBuf, u64)> = Vec::new();
    for n in &m.racine {
        if SYSTEME.contains(&n.as_str()) || n.starts_with("lib") {
            r.push((Path::new("/").join(n), LIRE));
        }
    }
    // /run, sauf /run/user (le dossier du bureau de chaque compte : ses jetons, ses trousseaux) et /run/media (les
    // disques et les clés branchés).
    for n in m.run.iter().filter(|n| *n != "user" && *n != "media") {
        r.push((Path::new("/run").join(n), LIRE));
    }
    // /dev : le néant, où la sortie part après « ouverte » (`sortie`), le hasard, puis la carte graphique : Mesa
    // (Intel, AMD, logiciel) et NVIDIA. Pas le reste (micro, caméra, disques). Pas les caches de nuanceurs (~/.cache) :
    // les autres programmes les relisent, la fenêtre n'y écrit pas (elle les recompile, ils sont petits).
    r.push((PathBuf::from("/dev/null"), READ_FILE | WRITE_FILE));
    for n in ["zero", "full", "random", "urandom"] {
        r.push((Path::new("/dev").join(n), READ_FILE));
    }
    r.push((PathBuf::from("/dev/dri"), CARTE));
    for n in m.dev.iter().filter(|n| n.starts_with("nvidia")) {
        r.push((Path::new("/dev").join(n), CARTE));
    }
    // Du compte : les thèmes de curseurs, le fichier de composition. Rien d'autre (ni ~/.ssh, ni les navigateurs).
    for d in m.curseurs() {
        r.push((d, LIRE));
    }
    for f in m.composition() {
        r.push((f, READ_FILE));
    }
    match m.bureau() {
        // Wayland : sa socket seule (pas tout XDG_RUNTIME_DIR, où est le bus de session), et jamais celles d'X11 :
        // Xwayland y répond aussi, et ses programmes s'y tapent les uns dans les autres.
        Bureau::Wayland => {
            if let Some(w) = &m.wayland {
                let socket = if w.starts_with('/') {
                    Some(PathBuf::from(w))
                } else {
                    m.execution.as_ref().map(|d| d.join(w))
                };
                r.extend(socket.map(|s| (s, RESOLVE_UNIX)));
            }
        }
        // X11 : ses sockets nommées et le fichier de son autorisation (~/.Xauthority, ou XAUTHORITY).
        Bureau::X11 => {
            r.push((PathBuf::from("/tmp/.X11-unix"), RESOLVE_UNIX));
            let auth = m
                .xauthority
                .clone()
                .or_else(|| m.maison.as_ref().map(|d| d.join(".Xauthority")));
            r.extend(auth.map(|a| (a, READ_FILE)));
        }
        Bureau::Aucun => {}
    }
    r
}

/// Le nombre de fils du processus (1 attendu : Landlock et no_new_privs ne s'appliquent qu'au fil qui les pose et
/// à ce qu'il crée ensuite ; un fil déjà là resterait libre, et avec lui toute la mémoire de la fenêtre).
pub fn fils() -> usize {
    std::fs::read_dir("/proc/self/task").map_or(0, Iterator::count)
}

/// Pose le bac à sable sur la fenêtre : no_new_privs, puis Landlock. Appelé tant qu'elle n'a qu'un fil.
pub fn restreindre() -> Bac {
    let n = fils();
    if n != 1 {
        return Bac::Absent {
            raison: crate::trf!("{} fils déjà là", "{} threads already there", n),
            nnp: false,
        };
    }
    let nnp = sans_nouveaux_droits();
    match poser() {
        Ok((abi, manques, maison)) if nnp => Bac::Actif { abi, manques, maison },
        Ok(_) => Bac::Absent {
            raison: crate::tr!("no_new_privs refusé", "no_new_privs refused").into(),
            nnp: false,
        },
        Err(raison) => Bac::Absent { raison, nnp },
    }
}

/// Landlock sur le fil appelant (et ce qu'il crée ensuite) : la version, ce que ce noyau ne restreint pas, et si le
/// dossier personnel reste lisible.
pub fn poser() -> Result<(u32, Vec<&'static str>, bool), String> {
    let abi = version()?;
    let m = Milieu::lire();
    let (fs, net, scope, manques) = gere(abi, m.bureau() == Bureau::Wayland);
    let jeu = nouveau_jeu(fs, net, scope)?;
    let mut lus = Vec::new();
    for (chemin, droits) in regles(&m) {
        // Un chemin absent (pas de carte NVIDIA, pas d'X11, pas de ~/.icons) : pas de règle, rien de permis là.
        let Ok(f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&chemin)
        else {
            continue;
        };
        let dossier = f.metadata().is_ok_and(|m| m.is_dir());
        let droits = droits & fs & if dossier { u64::MAX } else { SUR_UN_FICHIER };
        if droits != 0 {
            ajouter(&jeu, &f, droits)?;
            if droits & READ_FILE != 0 {
                lus.push(chemin);
            }
        }
    }
    appliquer(&jeu)?;
    // Un dossier personnel rangé sous un dossier du système (/opt/alice) : lisible avec lui, et c'est dit.
    let maison = m.maison.as_deref().is_some_and(|d| maison_sous(d, &lus));
    Ok((abi, manques, maison))
}

/// Si `maison` est dans l'un des chemins lus (liens résolus : /home peut mener à /var/home), sans en être un des
/// sous-dossiers permis (les curseurs).
fn maison_sous(maison: &Path, lus: &[PathBuf]) -> bool {
    let reel = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let maison = reel(maison);
    lus.iter().map(|l| reel(l)).any(|l| maison.starts_with(&l))
}

#[repr(C)]
struct AttributsJeu {
    fs: u64,
    net: u64,
    scope: u64,
}

#[repr(C, packed)]
struct Dessous {
    droits: u64,
    parent: i32,
}

// raison : FFI de prctl (libc) : no_new_privs, que std ne sait pas poser.
#[allow(unsafe_code)]
pub fn sans_nouveaux_droits() -> bool {
    // SAFETY: prctl ne reçoit que des entiers (PR_SET_NO_NEW_PRIVS, 1, puis trois zéros exigés) et ne lit ni n'écrit
    // aucune mémoire du programme.
    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 }
}

/// La version de Landlock de ce noyau, ou pourquoi il n'y en a pas.
// raison : FFI de landlock_create_ruleset (appel système, sans enveloppe dans libc ni std).
#[allow(unsafe_code)]
fn version() -> Result<u32, String> {
    // SAFETY: avec LANDLOCK_CREATE_RULESET_VERSION, l'appel ne lit ni attributs (pointeur nul, taille 0) ni rien
    // d'autre : il rend la version, ou une erreur.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<AttributsJeu>(),
            0usize,
            VERSION,
        )
    };
    if r >= 1 {
        return u32::try_from(r).map_err(|e| e.to_string());
    }
    let e = std::io::Error::last_os_error();
    Err(match e.raw_os_error() {
        Some(libc::ENOSYS) => crate::tr!("noyau sans Landlock", "kernel without Landlock").into(),
        Some(libc::EOPNOTSUPP) => crate::tr!(
            "Landlock désactivé au démarrage du noyau",
            "Landlock disabled at kernel boot"
        )
        .into(),
        _ => crate::nettoyage::nom(&e.to_string(), 100),
    })
}

// raison : FFI de landlock_create_ruleset (appel système, sans enveloppe dans libc ni std).
#[allow(unsafe_code)]
fn nouveau_jeu(fs: u64, net: u64, scope: u64) -> Result<OwnedFd, String> {
    let attr = AttributsJeu { fs, net, scope };
    // SAFETY: le noyau lit `size_of::<AttributsJeu>()` octets à cette adresse, la structure vivante pendant l'appel
    // (trois u64, comme struct landlock_ruleset_attr jusqu'à `scoped` ; un noyau plus ancien exige les champs qu'il
    // ne connaît pas à zéro, ce que `gere` garantit). Il rend un descripteur neuf, à nous, ou -1.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attr,
            std::mem::size_of::<AttributsJeu>(),
            0u32,
        )
    };
    let fd = i32::try_from(r).map_err(|e| e.to_string())?;
    if fd < 0 {
        return Err(crate::nettoyage::nom(&std::io::Error::last_os_error().to_string(), 100));
    }
    // SAFETY: `fd` vient d'être ouvert par le noyau pour nous seuls ; OwnedFd le fermera une fois.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

// raison : FFI de landlock_add_rule (appel système, sans enveloppe dans libc ni std).
#[allow(unsafe_code)]
fn ajouter(jeu: &OwnedFd, chemin: &std::fs::File, droits: u64) -> Result<(), String> {
    let regle = Dessous {
        droits,
        parent: chemin.as_raw_fd(),
    };
    // SAFETY: le noyau lit la structure (packed, comme struct landlock_path_beneath_attr) le temps de l'appel ; les
    // deux descripteurs sont ouverts (empruntés ici).
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            jeu.as_raw_fd(),
            PATH_BENEATH,
            &raw const regle,
            0u32,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(crate::nettoyage::nom(&std::io::Error::last_os_error().to_string(), 100))
    }
}

// raison : FFI de landlock_restrict_self (appel système, sans enveloppe dans libc ni std).
#[allow(unsafe_code)]
fn appliquer(jeu: &OwnedFd) -> Result<(), String> {
    // SAFETY: l'appel ne reçoit qu'un descripteur ouvert et des drapeaux à zéro ; il ne touche aucune mémoire.
    let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, jeu.as_raw_fd(), 0u32) };
    if r == 0 {
        Ok(())
    } else {
        Err(crate::nettoyage::nom(&std::io::Error::last_os_error().to_string(), 100))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ce_que_chaque_version_sait_restreindre() {
        let (fs, net, scope, manques) = gere(1, true);
        assert_eq!((fs, net, scope, manques.len()), (REFER - 1, 0, 0, 3));
        assert_eq!(fs & (EXECUTE | WRITE_FILE), EXECUTE | WRITE_FILE);
        let (fs, net, scope, manques) = gere(4, true);
        assert_eq!((fs & TRUNCATE, net, scope, manques.len()), (TRUNCATE, NET_TCP, 0, 2));
        let (fs, _, scope, _) = gere(6, false);
        assert_eq!((fs & IOCTL_DEV, scope), (IOCTL_DEV, SCOPE_SIGNAL));
        let (fs, net, scope, manques) = gere(10, true);
        assert_eq!(fs, (RESOLVE_UNIX << 1) - 1);
        assert_eq!((net, scope), (NET_TCP | NET_UDP, SCOPE_SIGNAL | SCOPE_ABSTRAIT));
        assert_eq!(manques, [] as [&str; 0]);
    }

    fn milieu() -> Milieu {
        let noms = |n: &[&str]| n.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        Milieu {
            wayland: Some("wayland-1".into()),
            display: true,
            execution: Some("/run/user/1000".into()),
            maison: Some("/home/alice".into()),
            racine: noms(&[
                "bin", "etc", "home", "lib", "lib64", "mnt", "opt", "proc", "root", "run", "srv", "sys", "tmp", "usr",
                "var",
            ]),
            run: noms(&["dbus", "media", "systemd", "udev", "user"]),
            dev: noms(&["null", "nvidia0", "nvidiactl", "sda", "snd", "tty", "video0"]),
            ..Milieu::default()
        }
    }

    fn chemins(r: &[(PathBuf, u64)]) -> Vec<String> {
        r.iter().map(|(c, _)| c.to_string_lossy().into_owned()).collect()
    }

    /// Jamais un droit d'écrire ou de lancer hors de /dev/null et des cartes graphiques ; la socket de Wayland seule,
    /// jamais tout XDG_RUNTIME_DIR (le bus de session y est), ni celles d'X11 (Xwayland) même si DISPLAY est là ; rien
    /// à lire du dossier personnel que les curseurs, rien de /, /home, /tmp, /var, /mnt, /run/user ni /run/media.
    #[test]
    fn les_regles_ne_permettent_que_le_necessaire() {
        let m = milieu();
        assert_eq!(m.bureau(), Bureau::Wayland);
        let r = regles(&m);
        for (chemin, droits) in &r {
            assert_eq!(droits & EXECUTE, 0, "{chemin:?}");
            let c = chemin.to_string_lossy();
            if droits & WRITE_FILE != 0 {
                assert!(
                    c == "/dev/null" || c == "/dev/dri" || c.starts_with("/dev/nvidia"),
                    "{c}"
                );
            }
            if droits & RESOLVE_UNIX != 0 {
                assert_eq!(c, "/run/user/1000/wayland-1");
            }
            if c.starts_with("/home/alice") {
                assert_eq!(droits & !(READ_FILE | READ_DIR), 0, "{c}");
                assert!(
                    [
                        ".icons",
                        ".cursors",
                        ".local/share/icons",
                        ".config/XCompose",
                        ".XCompose"
                    ]
                    .iter()
                    .any(|f| c == format!("/home/alice/{f}")),
                    "{c}"
                );
            }
        }
        let c = chemins(&r);
        for permis in [
            "/usr",
            "/etc",
            "/lib",
            "/lib64",
            "/opt",
            "/proc",
            "/sys",
            "/bin",
            "/run/udev",
            "/dev/nvidia0",
        ] {
            assert!(c.contains(&permis.to_string()), "{permis}");
        }
        for refuse in [
            "/",
            "/home",
            "/home/alice",
            "/root",
            "/tmp",
            "/tmp/.X11-unix",
            "/var",
            "/mnt",
            "/srv",
            "/run",
            "/run/user",
            "/run/user/1000",
            "/run/media",
            "/dev",
            "/dev/sda",
            "/dev/snd",
            "/dev/video0",
            "/dev/tty",
        ] {
            assert!(!c.contains(&refuse.to_string()), "{refuse}");
        }
        assert!(!c.iter().any(|c| c.ends_with("/bus") || c.contains(".ssh")));
        let r = regles(&Milieu {
            wayland: Some("/tmp/w".into()),
            ..Milieu::default()
        });
        assert!(r.iter().any(|(c, d)| c == Path::new("/tmp/w") && *d == RESOLVE_UNIX));
    }

    /// Sous X11 : ses sockets nommées et son autorisation, rien de Wayland.
    #[test]
    fn sous_x11_ses_sockets_et_son_autorisation() {
        let m = Milieu {
            wayland: None,
            ..milieu()
        };
        assert_eq!(m.bureau(), Bureau::X11);
        let r = regles(&m);
        assert!(
            r.iter()
                .any(|(c, d)| c == Path::new("/tmp/.X11-unix") && *d == RESOLVE_UNIX)
        );
        assert!(
            r.iter()
                .any(|(c, d)| c == Path::new("/home/alice/.Xauthority") && *d == READ_FILE)
        );
        assert!(!chemins(&r).iter().any(|c| c.contains("wayland")));
        let r = regles(&Milieu {
            xauthority: Some("/run/user/1000/xauth_ABCDEF".into()),
            ..m
        });
        assert!(
            r.iter()
                .any(|(c, d)| c == Path::new("/run/user/1000/xauth_ABCDEF") && *d == READ_FILE)
        );
        assert!(!chemins(&r).contains(&"/home/alice/.Xauthority".to_string()));
    }

    /// Le bureau de winit : Wayland dès que WAYLAND_DISPLAY ou WAYLAND_SOCKET est là, puis X11, sinon aucun.
    #[test]
    fn le_bureau_est_celui_que_winit_prend() {
        let m = |wayland: Option<&str>, wayland_socket, display| Milieu {
            wayland: wayland.map(String::from),
            wayland_socket,
            display,
            ..Milieu::default()
        };
        assert_eq!(m(Some("wayland-0"), false, true).bureau(), Bureau::Wayland);
        assert_eq!(m(None, true, true).bureau(), Bureau::Wayland);
        assert_eq!(m(None, false, true).bureau(), Bureau::X11);
        assert_eq!(m(None, false, false).bureau(), Bureau::Aucun);
        assert!(
            regles(&m(None, false, false))
                .iter()
                .all(|(_, d)| d & RESOLVE_UNIX == 0)
        );
    }

    /// Les curseurs : XCURSOR_PATH (« ~ » déplié) l'emporte ; un dossier nommé icons ou cursors seulement, jamais le
    /// dossier personnel ni ~/.local/share entier, ni un chemin relatif ou avec « .. ».
    #[test]
    fn les_curseurs_seulement_dans_leurs_dossiers() {
        let m = Milieu {
            maison: Some("/home/alice".into()),
            xcursor_path: Some(
                "~/.local/share/icons:~/.icons:/usr/share/icons::~:~/.local/share:/:icons:/home/alice/x/../icons"
                    .into(),
            ),
            ..Milieu::default()
        };
        let c: Vec<String> = m.curseurs().iter().map(|c| c.to_string_lossy().into_owned()).collect();
        assert_eq!(
            c,
            [
                "/home/alice/.local/share/icons",
                "/home/alice/.icons",
                "/usr/share/icons"
            ]
        );
        let m = Milieu {
            maison: Some("/home/alice".into()),
            xdg_data_home: Some("/home/alice/.local/share".into()),
            xdg_data_dirs: Some("/usr/local/share:/var/lib/flatpak/exports/share".into()),
            ..Milieu::default()
        };
        let c: Vec<String> = m.curseurs().iter().map(|c| c.to_string_lossy().into_owned()).collect();
        assert_eq!(
            c,
            [
                "/home/alice/.local/share/icons",
                "/home/alice/.icons",
                "/home/alice/.cursors",
                "/usr/local/share/icons",
                "/var/lib/flatpak/exports/share/icons"
            ]
        );
    }

    /// Un dossier personnel sous un dossier lu (même par un lien) se voit ; pas sous ses propres curseurs.
    #[test]
    fn un_dossier_personnel_sous_le_systeme_se_voit() {
        let lus = [
            PathBuf::from("/usr"),
            PathBuf::from("/opt"),
            PathBuf::from("/home/alice/.icons"),
        ];
        assert!(maison_sous(Path::new("/opt/alice"), &lus));
        assert!(!maison_sous(Path::new("/home/alice"), &lus));
        assert!(!maison_sous(Path::new("/var/home/alice"), &lus));
    }
}
