//! Linux : qui lit le clavier ? Sous Wayland, un programme ordinaire ne voit pas les touches tapées ailleurs ; pour les
//! épier, un enregistreur de frappe ouvre directement le clavier, /dev/input/eventN (en root, ou depuis un compte du
//! groupe « input »). Les fichiers ouverts de chaque processus (`/proc/<pid>/fd`) le montrent, et /sys dit lesquels de
//! ces périphériques sont des claviers. Le compositeur, systemd-logind et les outils de remappage des touches en
//! tiennent aussi : reconnus et montrés, jamais cachés. Tout est lu dans /proc et /sys, sans lancer de commande.

use crate::risk::Niveau;

/// Les programmes qui lisent le clavier par nature : compositeurs Wayland et serveur X, gestion des sessions et des
/// touches spéciales (acpid), accessibilité (brltty), remappage et raccourcis, manettes et diffusion (Steam,
/// Sunshine, OBS). Comparés au nom de l'exécutable, sans égard à la casse ; au nom court du processus seulement quand
/// l'exécutable n'a pas pu être lu.
const LECTEURS_ATTENDUS: &[&str] = &[
    "hyprland",
    "sway",
    "kwin_wayland",
    "gnome-shell",
    "mutter",
    "xorg",
    "weston",
    "phoc",
    "river",
    "niri",
    "labwc",
    "wayfire",
    "cosmic-comp",
    "gamescope",
    "systemd-logind",
    "elogind",
    "seatd",
    "acpid",
    "brltty",
    "keyd",
    "kanata",
    "kmonad",
    "xremap",
    "udevmon",
    // interception-tools : udevmon lance « intercept -g », qui tient le clavier.
    "intercept",
    // libinput-gestures et fusuma passent par lui, sous le compte de la personne.
    "libinput-debug-events",
    // triggerhappy, installé d'office sur Raspberry Pi OS.
    "thd",
    "espanso",
    "logid",
    "ratbagd",
    "antimicrox",
    "steam",
    "sunshine",
    "obs",
];

/// Les lecteurs écrits en Python : leur exécutable est l'interpréteur, seul leur nom court (celui du script) les
/// reconnaît. Il se choisit aussi : ce n'est admis que pour un interpréteur, et pour ces noms seulement.
const SCRIPTS_ATTENDUS: &[&str] = &[
    "input-remapper",
    "input-remapper-service",
    "input-remapper-reader-service",
    "solaar",
    "sc-controller",
    "scc-daemon",
    "openrazer-daemon",
];

/// Un nom de la liste, sans égard à la casse ni au point de tête. Le noyau coupe le nom court à 15 octets
/// (« input-remapper- ») : un nom de 15 octets est aussi comparé au début des noms plus longs.
fn dans(liste: &[&str], nom: &str) -> bool {
    let n = nom.trim_start_matches('.');
    !n.is_empty()
        && liste.iter().any(|a| {
            a.eq_ignore_ascii_case(n)
                || (n.len() == 15 && a.len() > 15 && a.get(..15).is_some_and(|p| p.eq_ignore_ascii_case(n)))
        })
}

/// Un interpréteur (python3.14, perl…) : le programme qu'il fait tourner est un script.
fn interprete(exe: &str) -> bool {
    let bas = exe.to_ascii_lowercase();
    ["python", "perl", "ruby"].iter().any(|p| bas.starts_with(p)) || bas == "node"
}

/// Modules du noyau qui enregistrent les frappes : keysniffer (<https://github.com/jarun/keysniffer>).
const MODULES_ESPIONS: &[&str] = &["keysniffer"];

/// Un bit d'un masque de capacités de /sys (« 120013 », « 4057ff febeffdfffefffff fffffffffffffffe ») : des mots
/// hexadécimaux de 64 bits, le poids fort d'abord.
fn bits(masque: &str) -> impl Fn(usize) -> bool + '_ {
    let mots: Vec<u64> = masque
        .split_whitespace()
        .rev()
        .map(|m| u64::from_str_radix(m, 16).unwrap_or(0))
        .collect();
    move |n| mots.get(n / 64).is_some_and(|m| m >> (n % 64) & 1 == 1)
}

/// Un clavier, d'après ses capacités : des touches (EV_KEY), et toutes les lettres et l'espace. Une souris (boutons
/// seulement) ou un bouton d'alimentation n'en est pas un.
pub(super) fn est_clavier(ev: &str, key: &str) -> bool {
    const EV_KEY: usize = 1;
    // KEY_Q…KEY_P, KEY_A…KEY_L, KEY_Z…KEY_M, KEY_SPACE (linux/input-event-codes.h).
    let touches = (16..=25).chain(30..=38).chain(44..=50).chain([57]);
    let a = bits(key);
    bits(ev)(EV_KEY) && touches.into_iter().all(a)
}

/// « event12 » pour un lien vers /dev/input/event12 ; rien pour un autre fichier ou une prise (« `socket:[1]` »).
pub(super) fn evenement(lien: &str) -> Option<&str> {
    let nom = lien.strip_prefix("/dev/input/")?;
    (nom.starts_with("event") && nom[5..].bytes().all(|o| o.is_ascii_digit()) && nom.len() > 5).then_some(nom)
}

/// Un programme qui tient un clavier ouvert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Lecteur {
    pub pid: u32,
    pub programme: String,
    /// Le chemin de son exécutable ; « (deleted) » à la fin quand le fichier a été effacé après le lancement.
    pub chemin: Option<String>,
    pub claviers: Vec<String>,
}

/// Le jugement d'un lecteur : `None` s'il est attendu (montré comme reconnu), sinon (niveau, raison).
pub(super) fn juger(l: &Lecteur, montages: &str) -> Option<(Niveau, String)> {
    let exe = l
        .chemin
        .as_deref()
        .map(|c| c.trim_end_matches(" (deleted)"))
        .and_then(|c| c.rsplit('/').next())
        .unwrap_or_default();
    // NixOS : wrapProgram lance le vrai programme sous le nom « .Hyprland-wrapped », depuis /nix/store.
    let exe = if l.chemin.as_deref().is_some_and(|c| c.starts_with("/nix/store/")) {
        exe.trim_start_matches('.').strip_suffix("-wrapped").unwrap_or(exe)
    } else {
        exe
    };
    if let Some(s) = super::connus::reconnu(&l.programme).or_else(|| super::connus::reconnu(exe)) {
        // Un contrôle parental ou une surveillance d'employeur peut être voulu : à regarder, pas « signes sérieux ».
        let niveau = if s.genre == super::connus::Genre::Espion {
            Niveau::Eleve
        } else {
            Niveau::Moyen
        };
        return Some((niveau, super::texte_genre(s)));
    }
    if let Some(c) = l.chemin.as_deref() {
        if c.ends_with(" (deleted)") {
            return Some((
                Niveau::Eleve,
                crate::tr!(
                    "programme effacé après son lancement",
                    "program deleted after it started"
                )
                .to_string(),
            ));
        }
        if let Some(ou) = crate::protection::sortantes::dossier_risque(c, montages) {
            return Some((Niveau::Eleve, crate::trf!("lancé depuis {ou}", "started from {ou}")));
        }
    }
    // Avant les noms : un nom attendu ne rachète pas un exécutable rangé dans un dossier caché.
    if l.chemin
        .as_deref()
        .is_some_and(|c| dossier_cache(c) && !crate::protection::sortantes::appimage(c, montages))
    {
        return Some((
            Niveau::Eleve,
            crate::tr!("lancé depuis un dossier caché", "started from a hidden folder").to_string(),
        ));
    }
    // Le nom court se choisit (prctl(PR_SET_NAME)) : quand l'exécutable est connu, c'est lui qui compte ; le nom
    // court ne sert que pour un script (l'exécutable est alors l'interpréteur) ou sans exécutable lisible.
    let attendu = if exe.is_empty() {
        dans(LECTEURS_ATTENDUS, &l.programme) || dans(SCRIPTS_ATTENDUS, &l.programme)
    } else if interprete(exe) {
        dans(SCRIPTS_ATTENDUS, &l.programme)
    } else {
        dans(LECTEURS_ATTENDUS, exe)
    };
    if attendu {
        return None;
    }
    Some((
        Niveau::Moyen,
        crate::tr!(
            "programme inconnu qui lit le clavier",
            "unknown program reading the keyboard"
        )
        .to_string(),
    ))
}

/// Un exécutable rangé dans un dossier caché (« ~/.cache/x ») ou caché lui-même (« ~/bin/.x »), hors des dossiers où
/// les programmes du compte s'installent d'ordinaire (~/.local/bin, ~/.cargo/bin ; Steam dans ~/.local/share/Steam).
/// Seule exception pour le nom : les enveloppes de NixOS (« /nix/store/…/bin/.Hyprland-wrapped »).
fn dossier_cache(chemin: &str) -> bool {
    let ordinaires = ["/.local/bin/", "/.cargo/bin/", "/.local/share/Steam/", "/.steam/"];
    let cache = |p: &str| p.starts_with('.') && p.len() > 1;
    let (dossier, fichier) = chemin.rsplit_once('/').unwrap_or(("", chemin));
    let enveloppe_nix = chemin.starts_with("/nix/store/") && fichier.ends_with("-wrapped");
    (dossier.split('/').any(cache) || (cache(fichier) && !enveloppe_nix))
        && !ordinaires.iter().any(|o| chemin.contains(o))
}

/// Un module du noyau enregistreur de frappes, dans le contenu de /proc/modules.
pub(super) fn module_espion(modules: &str) -> Option<&'static str> {
    MODULES_ESPIONS
        .iter()
        .copied()
        .find(|m| modules.lines().any(|l| l.split_whitespace().next() == Some(*m)))
}

/// Le compte est dans le groupe `input` : le numéro du groupe (ligne « input:x:N: » de /etc/group) parmi ceux du
/// processus (ligne « Groups: » de /proc/self/status).
pub(super) fn dans_le_groupe_input(group: &str, status: &str) -> bool {
    let Some(gid) = group.lines().find_map(|l| {
        let mut champs = l.split(':');
        (champs.next() == Some("input")).then(|| champs.nth(1)).flatten()
    }) else {
        return false;
    };
    status
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .is_some_and(|g| g.split_whitespace().any(|n| n == gid))
}

/// Les programmes qui tiennent un clavier, et le nombre de processus dont les fichiers ouverts n'ont pas pu être lus
/// (ceux des autres comptes, sans root). Au plus 4 096 processus et 4 096 fichiers par processus : au-delà, ce qui
/// reste n'est pas lu et compte comme illisible.
#[cfg(target_os = "linux")]
pub(super) fn lecteurs() -> (Vec<Lecteur>, usize) {
    use std::collections::HashMap;
    const PROCESSUS_MAX: usize = 4096;
    const FICHIERS_MAX: usize = 4096;
    let soi = std::process::id();
    // Chaque périphérique n'est jugé qu'une fois : (clavier ?, nom).
    let mut vus: HashMap<String, Option<String>> = HashMap::new();
    let mut clavier = |ev: &str| -> Option<String> {
        vus.entry(ev.to_string())
            .or_insert_with(|| {
                let dossier = format!("/sys/class/input/{ev}/device");
                let lire = |f: &str| std::fs::read_to_string(format!("{dossier}/{f}")).unwrap_or_default();
                est_clavier(&lire("capabilities/ev"), &lire("capabilities/key"))
                    .then(|| crate::ui::affichable(lire("name").trim()))
            })
            .clone()
    };
    let (mut lecteurs, mut illisibles) = (Vec::new(), 0);
    // /proc illisible : aucun processus n'a pu être regardé, ce qui se dit (un illisible), au lieu d'une liste vide
    // qui passait pour « aucun lecteur du clavier ».
    let Some(pids) = crate::socle::processus::pids() else {
        return (lecteurs, 1);
    };
    for (i, pid) in pids.into_iter().enumerate() {
        if pid == soi {
            continue;
        }
        if i >= PROCESSUS_MAX {
            illisibles += 1;
            continue;
        }
        let fd = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
            Ok(fd) => fd,
            // Le processus a fini entre-temps : rien à dire.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                illisibles += 1;
                continue;
            }
        };
        let mut claviers: Vec<String> = fd
            .flatten()
            .take(FICHIERS_MAX)
            .filter_map(|e| std::fs::read_link(e.path()).ok())
            .filter_map(|l| clavier(evenement(&l.to_string_lossy())?))
            .collect();
        if claviers.is_empty() {
            continue;
        }
        claviers.sort();
        claviers.dedup();
        lecteurs.push(Lecteur {
            pid,
            programme: crate::socle::processus::nom_court(pid)
                .map(|n| crate::ui::affichable(&n))
                .unwrap_or_default(),
            chemin: crate::socle::processus::programme(pid).map(|c| c.to_string_lossy().into_owned()),
            claviers,
        });
    }
    (lecteurs, illisibles)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claviers_reconnus_par_leurs_capacites() {
        // Relevées sur un vrai ordinateur : un clavier, la souris G600 (boutons seulement), un bouton d'alimentation.
        assert!(est_clavier("120013", "4057ff febeffdfffefffff fffffffffffffffe"));
        assert!(!est_clavier("17", "ffff0000 0 0 0 0"));
        assert!(!est_clavier("3", ""));
        assert!(!est_clavier("120013", "1"));
        // Des touches sans EV_KEY : pas un clavier.
        assert!(!est_clavier("4", "4057ff febeffdfffefffff fffffffffffffffe"));
        assert_eq!(evenement("/dev/input/event12"), Some("event12"));
        assert_eq!(evenement("/dev/input/mice"), None);
        assert_eq!(evenement("/dev/input/event"), None);
        assert_eq!(evenement("socket:[1]"), None);
    }

    #[test]
    fn lecteurs_attendus_ou_suspects() {
        let lecteur = |programme: &str, chemin: &str| Lecteur {
            pid: 42,
            programme: programme.into(),
            chemin: Some(chemin.into()),
            claviers: vec!["Clavier".into()],
        };
        assert_eq!(juger(&lecteur("Hyprland", "/usr/bin/Hyprland"), ""), None);
        assert_eq!(
            juger(&lecteur("systemd-logind", "/usr/lib/systemd/systemd-logind"), ""),
            None
        );
        assert_eq!(
            juger(&lecteur("x", "/home/alice/Téléchargements/x"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger(&lecteur("outil", "/home/alice/.cache/outil"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger(&lecteur("outil", "/usr/bin/outil (deleted)"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger(&lecteur("logkeys", "/usr/bin/logkeys"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        assert_eq!(
            juger(&lecteur("outil", "/usr/bin/outil"), "").map(|j| j.0),
            Some(Niveau::Moyen)
        );
        // Un nom attendu lancé d'un endroit louche reste suspect.
        assert_eq!(
            juger(&lecteur("steam", "/tmp/steam"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        // Steam installé dans le dossier du compte, un outil dans ~/.local/bin : pas « caché ».
        assert_eq!(
            juger(
                &lecteur("steam", "/home/alice/.local/share/Steam/ubuntu12_32/steam"),
                ""
            ),
            None
        );
        assert_eq!(
            juger(&lecteur("outil", "/home/alice/.local/bin/outil"), "").map(|j| j.0),
            Some(Niveau::Moyen)
        );
        // Un nom attendu ne rachète pas un exécutable rangé dans un dossier caché.
        for (nom, chemin) in [
            ("steam", "/home/alice/.config/x/steam"),
            ("obs", "/home/alice/.cache/obs/obs"),
            ("Hyprland", "/home/alice/.cache/.k/kl"),
            ("Hyprland", "/home/alice/.cache/x"),
        ] {
            assert_eq!(
                juger(&lecteur(nom, chemin), "").map(|j| j.0),
                Some(Niveau::Eleve),
                "{nom} {chemin}"
            );
        }
        // Le nom court se choisit (prctl) : seul l'exécutable compte quand il est connu.
        assert_eq!(
            juger(&lecteur("systemd-logind", "/usr/local/sbin/kl"), "").map(|j| j.0),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            juger(&lecteur("x", "/usr/local/bin/x"), "").map(|j| j.0),
            Some(Niveau::Moyen)
        );
        // Les services écrits en Python : l'exécutable est l'interpréteur, le nom court (coupé à 15 octets par le
        // noyau) les reconnaît.
        assert_eq!(juger(&lecteur("input-remapper-", "/usr/bin/python3.14"), ""), None);
        assert_eq!(juger(&lecteur("solaar", "/usr/bin/python3"), ""), None);
        for (nom, chemin) in [
            ("elogind", "/usr/lib/elogind/elogind"),
            ("seatd", "/usr/bin/seatd"),
            ("brltty", "/usr/bin/brltty"),
        ] {
            assert_eq!(juger(&lecteur(nom, chemin), ""), None, "{nom}");
        }
        // NixOS : les compositeurs enveloppés par wrapProgram ne sont pas « cachés ».
        for chemin in [
            "/nix/store/abc123-hyprland-0.50/bin/.Hyprland-wrapped",
            "/nix/store/abc123-gnome-shell-48/bin/.gnome-shell-wrapped",
            "/nix/store/abc123-kwin-6.4/bin/.kwin_wayland-wrapped",
        ] {
            assert_eq!(juger(&lecteur("x", chemin), ""), None, "{chemin}");
        }
        // Une enveloppe ailleurs que dans /nix/store, ou un programme caché lui-même, reste suspect.
        for chemin in ["/home/alice/bin/.Hyprland-wrapped", "/home/alice/bin/.x"] {
            assert_eq!(
                juger(&lecteur("x", chemin), "").map(|j| j.0),
                Some(Niveau::Eleve),
                "{chemin}"
            );
        }
        // Remappage et gestes : interception-tools, libinput-gestures, triggerhappy, openrazer.
        for (nom, chemin) in [
            ("intercept", "/usr/bin/intercept"),
            ("libinput-debug-", "/usr/lib/libinput/libinput-debug-events"),
            ("thd", "/usr/sbin/thd"),
            ("openrazer-daemo", "/usr/bin/python3.12"),
        ] {
            assert_eq!(juger(&lecteur(nom, chemin), ""), None, "{nom}");
        }
        assert_eq!(
            juger(&lecteur("intercept", "/home/alice/.cache/intercept"), "").map(|j| j.0),
            Some(Niveau::Eleve)
        );
        // Sans exécutable lisible, le nom court seul.
        let sans_chemin = Lecteur {
            chemin: None,
            ..lecteur("Hyprland", "")
        };
        assert_eq!(juger(&sans_chemin, ""), None);
        // Une surveillance d'employeur ou un contrôle parental : à regarder, pas « signes sérieux ».
        assert_eq!(
            juger(&lecteur("teramind", "/opt/teramind/teramind"), "").map(|j| j.0),
            Some(Niveau::Moyen)
        );
        assert_eq!(
            module_espion("keysniffer 16384 0 - Live 0x0\nnvidia 1 0 - Live 0x0\n"),
            Some("keysniffer")
        );
        assert_eq!(module_espion("nvidia 1 0 - Live 0x0\n"), None);
        let group = "wheel:x:998:alice\ninput:x:994:alice\n";
        assert!(dans_le_groupe_input(group, "Name:\tx\nGroups:\t10 994 998 \n"));
        assert!(!dans_le_groupe_input(group, "Groups:\t10 998\n"));
        assert!(!dans_le_groupe_input("wheel:x:998:\n", "Groups:\t994\n"));
    }
}
