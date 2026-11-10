//! Le bac à sable de la fenêtre sous Linux : Landlock et no_new_privs, posés sur la fenêtre seule, au démarrage,
//! avant qu'elle ait un seul fil de plus que le sien (`relais::separer`, qui a déjà mis le relais à part).
//!
//! Restreinte, la fenêtre lit les fichiers (bibliothèques, pilotes, thème), dessine (le pilote de la carte graphique,
//! /dev/dri et /dev/nvidia*), parle au bureau (la socket de Wayland, celles d'X11) et au relais, et rien d'autre :
//! elle n'écrit aucun fichier (sauf /dev/null), ne lance aucun programme, n'ouvre aucune connexion réseau, ne
//! joint aucune autre socket Unix (le bus de session : `systemd-run --user` y lancerait n'importe quoi hors du bac),
//! ne signale ni n'observe aucun processus d'en dehors (Landlock y range aussi /proc des autres et ptrace), et ne
//! peut plus gagner de droits (un programme setuid). Un défaut de dessin, de police ou de JSON qui prendrait la main
//! dans la fenêtre n'aurait que cela, et le relais, qui ne lance que la liste fermée.
//!
//! Pourquoi la fenêtre seule et pas `vanguard` : ce qu'elle lance hériterait du bac, et `vanguard` ne verrait plus ni
//! les programmes en cours, ni le bus système, ni sudo (no_new_privs) ; il le dirait (« non vérifié »), mais le bilan
//! d'un proche y perdrait (essai du lot 1b, dans un dossier jetable : 8 commandes de la liste sur 13 touchées).
//!
//! Selon le noyau, une partie seulement (`Bac::manques`) : le réseau depuis Landlock 4 (Linux 6.7), les signaux et
//! les sockets abstraites depuis 6 (6.12), les sockets Unix nommées depuis 9 ; sans Landlock (désactivé, ou noyau
//! d'avant 5.13), no_new_privs seul, et la fenêtre le dit dans sa console.
//!
//! Sous X11, le bac retient moins : tout programme d'un bureau X11 peut taper dans les autres fenêtres (un terminal),
//! et les sockets abstraites y restent joignables (X11 en a besoin). Sous Wayland, ni l'un ni l'autre.

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
    /// Landlock posé (sa version), avec ce que ce noyau ne sait pas encore restreindre.
    Actif { abi: u32, manques: Vec<&'static str> },
    /// Pas de Landlock : pourquoi. `nnp` : no_new_privs posé quand même.
    Absent { raison: String, nnp: bool },
}

impl Bac {
    /// La phrase pour la console de la fenêtre, et si elle est à souligner.
    pub fn phrase(&self) -> (String, bool) {
        match self {
            Bac::Actif { abi, manques } if manques.is_empty() => (
                crate::trf!(
                    "Bac à sable actif (Landlock {}) : la fenêtre ne peut ni écrire de fichier, ni lancer de programme, ni ouvrir de connexion ; `vanguard` est lancé à côté d'elle, avec tous ses droits de lecture.",
                    "Sandbox active (Landlock {}): the window can neither write files, start programs nor open connections; `vanguard` is started beside it, with all its read rights.",
                    abi
                ),
                false,
            ),
            Bac::Actif { abi, manques } => (
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

/// Les chemins permis et leurs actions. `wayland` : la valeur de WAYLAND_DISPLAY ; `execution` : XDG_RUNTIME_DIR ;
/// `dev` : les noms du dossier /dev.
fn regles(wayland: Option<&str>, execution: Option<&Path>, dev: &[String]) -> Vec<(PathBuf, u64)> {
    let mut r = vec![
        // Lire : bibliothèques, pilotes, thème, polices du système, /proc et /sys de la fenêtre elle-même.
        (PathBuf::from("/"), READ_FILE | READ_DIR),
        // Le néant, où la sortie part après « ouverte » (`sortie`).
        (PathBuf::from("/dev/null"), READ_FILE | WRITE_FILE),
        // La carte graphique : Mesa (Intel, AMD, logiciel) puis NVIDIA. Pas leurs caches de nuanceurs (~/.cache) :
        // les autres programmes les relisent, la fenêtre n'y écrit pas (elle les recompile, ils sont petits).
        (PathBuf::from("/dev/dri"), READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV),
        // X11 : ses sockets nommées.
        (PathBuf::from("/tmp/.X11-unix"), RESOLVE_UNIX),
    ];
    for n in dev.iter().filter(|n| n.starts_with("nvidia")) {
        r.push((Path::new("/dev").join(n), READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV));
    }
    // Wayland : sa socket seule (pas tout XDG_RUNTIME_DIR, où est le bus de session).
    if let Some(w) = wayland.filter(|w| !w.is_empty()) {
        let socket = if w.starts_with('/') {
            Some(PathBuf::from(w))
        } else {
            execution.map(|d| d.join(w))
        };
        if let Some(s) = socket {
            r.push((s, RESOLVE_UNIX));
        }
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
        Ok((abi, manques)) if nnp => Bac::Actif { abi, manques },
        Ok(_) => Bac::Absent {
            raison: crate::tr!("no_new_privs refusé", "no_new_privs refused").into(),
            nnp: false,
        },
        Err(raison) => Bac::Absent { raison, nnp },
    }
}

/// Landlock sur le fil appelant (et ce qu'il crée ensuite) : la version, et ce que ce noyau ne restreint pas.
pub fn poser() -> Result<(u32, Vec<&'static str>), String> {
    let abi = version()?;
    let wayland = std::env::var("WAYLAND_DISPLAY").ok();
    let (fs, net, scope, manques) = gere(abi, wayland.as_deref().is_some_and(|w| !w.is_empty()));
    let jeu = nouveau_jeu(fs, net, scope)?;
    let execution = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    let dev: Vec<String> = std::fs::read_dir("/dev").map_or_else(
        |_| Vec::new(),
        |d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        },
    );
    for (chemin, droits) in regles(wayland.as_deref(), execution.as_deref(), &dev) {
        // Un chemin absent (pas de carte NVIDIA, pas d'X11) : pas de règle, rien de permis là.
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
        }
    }
    appliquer(&jeu)?;
    Ok((abi, manques))
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

    /// Jamais un droit d'écrire ou de lancer hors de /dev/null et des cartes graphiques ; la socket de Wayland seule,
    /// jamais tout XDG_RUNTIME_DIR (le bus de session y est).
    #[test]
    fn les_regles_ne_permettent_que_le_necessaire() {
        let dev = ["null", "nvidia0", "nvidiactl", "sda", "tty"].map(String::from);
        let r = regles(Some("wayland-1"), Some(Path::new("/run/user/1000")), &dev);
        for (chemin, droits) in &r {
            assert_eq!(droits & EXECUTE, 0, "{chemin:?}");
            if droits & WRITE_FILE != 0 {
                let c = chemin.to_string_lossy();
                assert!(
                    c == "/dev/null" || c == "/dev/dri" || c.starts_with("/dev/nvidia"),
                    "{c}"
                );
            }
        }
        let chemins: Vec<String> = r.iter().map(|(c, _)| c.to_string_lossy().into_owned()).collect();
        assert!(chemins.contains(&"/run/user/1000/wayland-1".to_string()));
        assert!(
            !chemins
                .iter()
                .any(|c| c == "/run/user/1000" || c.ends_with("/bus") || c == "/dev/sda")
        );
        assert!(chemins.contains(&"/dev/nvidia0".to_string()));
        let r = regles(Some("/tmp/w"), None, &[]);
        assert!(r.iter().any(|(c, d)| c == Path::new("/tmp/w") && *d == RESOLVE_UNIX));
        assert!(
            !regles(None, Some(Path::new("/run/user/1")), &[])
                .iter()
                .any(|(c, _)| c.starts_with("/run"))
        );
    }
}
