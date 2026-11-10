//! `vanguard` sans argument : la fenêtre de Vanguard (`vanguard-fenetre`, posée à côté du programme) quand la
//! personne est devant un écran graphique, sinon le menu du terminal, comme avant. La fenêtre ne fait rien d'elle-même :
//! elle relance ce programme-ci avec des commandes en lecture (voir `fenetre/` et MODELE-DE-MENACE.md, « La fenêtre »).
//!
//! Le menu reste le choix sûr : sans terminal des deux côtés (un script qui écrit les choix, une sortie redirigée),
//! en SSH ou au Bureau à distance, en administrateur, sans écran graphique, sans fenêtre posée à côté, avec une fenêtre que d'autres
//! comptes pourraient remplacer, ou si elle ne dit pas « ouverte » à temps. `vanguard --menu` le force.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::coulisses::Suivie;
use crate::{tr, trf};

/// La ligne que la fenêtre écrit sur sa sortie quand elle s'est ouverte (fenetre/src/dessin/mod.rs).
const OUVERTE: &str = "vanguard-fenetre:ouverte";

/// Le temps laissé à la fenêtre pour s'ouvrir (premier lancement sur un vieil ordinateur, pilote graphique lent).
const ATTENTE: Duration = Duration::from_secs(20);

/// Ce qui décide entre la fenêtre et le menu, lu une fois.
#[derive(Debug, Clone, Copy, Default)]
#[allow(clippy::struct_excessive_bools)] // des constats, chacun pour lui-même
pub(crate) struct Contexte {
    /// L'entrée et la sortie sont un terminal : quelqu'un est là, pas un script.
    pub(crate) terminal: bool,
    /// Un écran graphique est là (Linux : WAYLAND_DISPLAY ou DISPLAY).
    pub(crate) graphique: bool,
    /// Session à distance : SSH (Linux), Bureau à distance (Windows).
    pub(crate) a_distance: bool,
    /// Vanguard tourne en administrateur (root, sudo, console administrateur) : pas de fenêtre avec tous les droits.
    pub(crate) eleve: bool,
}

/// La fenêtre ou le menu ? La fenêtre seulement quand tout le dit ; dans le doute, le menu.
pub(crate) fn choisir(c: Contexte) -> bool {
    c.terminal && c.graphique && !c.a_distance && !c.eleve
}

fn contexte() -> Contexte {
    use std::io::IsTerminal;
    let present = |v: &str| std::env::var_os(v).is_some_and(|x| !x.is_empty());
    Contexte {
        terminal: std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        graphique: cfg!(windows) || present("WAYLAND_DISPLAY") || present("DISPLAY"),
        a_distance: a_distance(&present),
        eleve: super::droits::processus_eleve(),
    }
}

#[cfg(windows)]
fn a_distance(_present: &dyn Fn(&str) -> bool) -> bool {
    crate::machine::windows::session_a_distance()
}

#[cfg(not(windows))]
fn a_distance(present: &dyn Fn(&str) -> bool) -> bool {
    present("SSH_CONNECTION") || present("SSH_TTY") || present("SSH_CLIENT")
}

/// Le chemin de la fenêtre à côté de ce programme (jamais cherchée dans le PATH).
fn voisine(programme: &Path) -> Option<PathBuf> {
    let nom = format!("vanguard-fenetre{}", std::env::consts::EXE_SUFFIX);
    Some(programme.parent()?.join(nom))
}

/// Pourquoi la fenêtre posée à côté n'est pas lancée, s'il y a une raison. Sous Linux, elle doit être un vrai
/// fichier (pas un lien), à ce compte ou à root, et que ni le groupe ni les autres ne peuvent modifier : sinon un
/// autre compte pourrait y mettre une fausse fenêtre qui dirait « tout va bien ».
#[cfg(unix)]
fn refus(m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_file() {
        return Some(tr!("pas un fichier ordinaire", "not a regular file"));
    }
    if m.uid() != moi && m.uid() != 0 {
        return Some(tr!("à un autre compte", "owned by another account"));
    }
    if m.mode() & 0o022 != 0 {
        return Some(tr!("modifiable par d'autres comptes", "writable by other accounts"));
    }
    None
}

/// Un dossier du chemin de la fenêtre : un vrai dossier, à ce compte ou à root, que ni le groupe ni les autres ne
/// peuvent modifier, sauf s'il est « collant » (sticky, comme /tmp : les autres comptes n'y renomment ni n'y
/// effacent ce qui n'est pas à eux). Sinon un autre compte pourrait renommer la fenêtre ou son dossier et en poser
/// une fausse entre la vérification et le lancement.
#[cfg(unix)]
fn refus_dossier(m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    use std::os::unix::fs::MetadataExt;
    if !m.file_type().is_dir() {
        return Some(tr!(
            "un dossier du chemin est un lien",
            "a folder on the path is a link"
        ));
    }
    if m.uid() != moi && m.uid() != 0 {
        return Some(tr!(
            "un dossier du chemin est à un autre compte",
            "a folder on the path is owned by another account"
        ));
    }
    if m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0 {
        return Some(tr!(
            "un dossier du chemin est modifiable par d'autres comptes",
            "a folder on the path is writable by other accounts"
        ));
    }
    None
}

/// La fenêtre (`refus`), puis chacun des dossiers qui la contiennent jusqu'à la racine (`refus_dossier`), sans
/// suivre aucun lien. Le chemin vient de `current_exe`, déjà résolu sous Linux.
#[cfg(unix)]
fn refus_chemin(chemin: &Path, m: &std::fs::Metadata, moi: u32) -> Option<&'static str> {
    if let Some(r) = refus(m, moi) {
        return Some(r);
    }
    chemin
        .ancestors()
        .skip(1)
        .filter(|d| !d.as_os_str().is_empty())
        .find_map(|d| match std::fs::symlink_metadata(d) {
            Ok(m) => refus_dossier(&m, moi),
            Err(_) => Some(tr!("un dossier illisible", "an unreadable folder")),
        })
}

#[cfg(windows)]
fn refus(m: &std::fs::Metadata) -> Option<&'static str> {
    (!m.file_type().is_file()).then(|| tr!("pas un fichier ordinaire", "not a regular file"))
}

/// Ouvre la fenêtre si c'est le bon choix et qu'elle dit s'être ouverte ; `false` : le menu du terminal.
pub(crate) fn ouvrir() -> bool {
    if !choisir(contexte()) {
        return false;
    }
    let Some(chemin) = std::env::current_exe().ok().as_deref().and_then(voisine) else {
        return false;
    };
    // symlink_metadata : un lien n'est pas suivi, il est refusé (pas un fichier ordinaire).
    let Ok(m) = std::fs::symlink_metadata(&chemin) else {
        // Pas de fenêtre posée à côté (un Vanguard sans elle) : le menu, sans un mot.
        return false;
    };
    #[cfg(unix)]
    let raison = refus_chemin(&chemin, &m, crate::socle::uid());
    #[cfg(windows)]
    let raison = refus(&m);
    if let Some(r) = raison {
        eprintln!(
            "{}",
            trf!(
                "Fenêtre de Vanguard laissée de côté ({}) : le menu du terminal.",
                "Vanguard window left aside ({}): the terminal menu.",
                r
            )
        );
        return false;
    }
    if lancer(&chemin) {
        return true;
    }
    eprintln!(
        "{}",
        tr!(
            "La fenêtre de Vanguard ne s'est pas ouverte : le menu du terminal.",
            "The Vanguard window did not open: the terminal menu."
        )
    );
    false
}

/// Lance la fenêtre et attend qu'elle dise « ouverte ». Elle n'est pas attendue au-delà : ce programme s'arrête et
/// la fenêtre continue seule. Sa sortie d'erreur est jetée (un pilote graphique bavard ne salit pas le terminal).
/// Pas par `commande::lancer`, qui attend la fin du programme : la fenêtre vit après nous ; lancée par les coulisses
/// quand même (`spawn_suivi`), elle s'y voit.
fn lancer(chemin: &Path) -> bool {
    let mut c = Command::new(chemin);
    c.arg("--depuis-vanguard")
        .arg("--langue")
        .arg(if crate::langue::anglais() { "en" } else { "fr" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Son propre groupe de processus : la fermeture du terminal (SIGHUP au groupe de premier plan) ne la ferme pas,
    // ni un Ctrl+C tapé ensuite dans ce terminal.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut c, 0);
    let Ok(mut enfant) = c.spawn_suivi() else {
        return false;
    };
    let Some(sortie) = enfant.stdout.take() else {
        crate::commande::arreter(&mut enfant);
        return false;
    };
    let (envoi, reception) = mpsc::channel();
    std::thread::spawn(move || {
        // Une seule ligne, bornée : rien d'autre n'est attendu sur cette sortie.
        let mut ligne = String::new();
        let lu = BufReader::new(std::io::Read::take(sortie, 256))
            .read_line(&mut ligne)
            .is_ok();
        let _ = envoi.send(lu && ligne.trim_end() == OUVERTE);
    });
    if reception.recv_timeout(ATTENTE) == Ok(true) {
        return true;
    }
    crate::commande::arreter(&mut enfant);
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_fenetre_seulement_quand_tout_le_dit() {
        let devant = Contexte {
            terminal: true,
            graphique: true,
            a_distance: false,
            eleve: false,
        };
        assert!(choisir(devant));
        // Un script qui écrit les choix ou lit la sortie garde le menu.
        assert!(!choisir(Contexte {
            terminal: false,
            ..devant
        }));
        assert!(!choisir(Contexte {
            graphique: false,
            ..devant
        }));
        // SSH ou Bureau à distance : le menu, dans la session où l'on est.
        assert!(!choisir(Contexte {
            a_distance: true,
            ..devant
        }));
        // En administrateur : le menu, jamais une fenêtre avec tous les droits.
        assert!(!choisir(Contexte { eleve: true, ..devant }));
        assert!(!choisir(Contexte::default()));
    }

    #[test]
    fn la_fenetre_est_cherchee_a_cote_du_programme() {
        let p = Path::new("/opt/vanguard/vanguard");
        let v = voisine(p).unwrap();
        assert_eq!(v.parent(), Some(Path::new("/opt/vanguard")));
        assert!(
            v.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("vanguard-fenetre"))
        );
    }

    /// Une fenêtre que d'autres comptes pourraient remplacer n'est pas lancée ; un lien non plus.
    #[cfg(unix)]
    #[test]
    fn une_fenetre_modifiable_par_d_autres_est_refusee() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = crate::socle::dossier_local().join("essai-lancer-fenetre");
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let f = dossier.join("vanguard-fenetre");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        let moi = crate::socle::uid();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi), None);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi).is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o757)).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi).is_some());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Un autre propriétaire (ni ce compte ni root).
        if moi != 0 {
            assert!(refus(&std::fs::symlink_metadata(&f).unwrap(), moi.wrapping_add(1)).is_some());
        }
        // Le dossier : modifiable par d'autres, refusé ; collant (sticky, comme /tmp), permis.
        let meta = std::fs::symlink_metadata(&f).unwrap();
        assert_eq!(refus_chemin(&f, &meta, moi), None);
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(refus_chemin(&f, &meta, moi).is_some());
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert_eq!(refus_chemin(&f, &meta, moi), None);
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
        let lien = dossier.join("lien");
        std::os::unix::fs::symlink(&f, &lien).unwrap();
        assert!(refus(&std::fs::symlink_metadata(&lien).unwrap(), moi).is_some());
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
