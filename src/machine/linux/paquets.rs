//! Ce qui est installé sous Linux, lu dans les bases des gestionnaires (pacman, dpkg, Flatpak) plutôt qu'en lançant
//! leurs commandes. Écrit d'abord pour le menu Gaming, d'où sa place d'avant dans `gaming::linux` ; la protection
//! (accès à distance, accès aux appareils) et les logiciels en dépendaient sans rien avoir à faire des jeux.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use super::{Paquets, natif};

fn reussit(cmd: &str, args: &[&str]) -> bool {
    crate::commande::lancer(Command::new(cmd).args(args), 20).is_some_and(|r| r.code == Some(0))
}

/// Les noms de paquets installés, lus une fois dans la base : un menu qui teste des dizaines de logiciels la
/// relirait sinon à chaque test (des milliers de fichiers sous pacman, un status de plusieurs Mo sous dpkg).
/// Pas de cache pour tout le programme : le menu des jeux relit l'état après une installation. `None` : base
/// illisible, ou rpm (sa base est du SQLite).
pub(crate) fn noms_installes(gestion: Paquets) -> Option<HashSet<String>> {
    match gestion {
        Paquets::Pacman => noms_pacman(),
        Paquets::Apt => natif::paquets_dpkg_installes().map(|l| {
            l.into_iter()
                .flat_map(|(nom, arch)| [format!("{nom}:{arch}"), nom])
                .collect()
        }),
        Paquets::Dnf | Paquets::Zypper => None,
    }
}

/// Tous les paquets de la liste sont-ils installés ? Les bases de pacman et de dpkg se lisent directement
/// (`connus`, de `noms_installes`) ; leur commande ne sert qu'en secours, quand la base ne se lit pas. rpm garde
/// la sienne : sa base est du SQLite.
pub(crate) fn installes_parmi(connus: Option<&HashSet<String>>, gestion: Paquets, paquets: &[&str]) -> bool {
    if let Some(connus) = connus {
        return paquets.iter().all(|p| connus.contains(*p));
    }
    paquets.iter().all(|p| match gestion {
        Paquets::Pacman => reussit("pacman", &["-Q", p]),
        Paquets::Apt => crate::commande::lancer(Command::new("dpkg-query").args(["-W", "-f=${Status}", p]), 20)
            .is_some_and(|r| r.code == Some(0) && natif::installe_selon_dpkg(&r.sortie)),
        Paquets::Dnf | Paquets::Zypper => reussit("rpm", &["-q", p]),
    })
}

const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

/// Les noms que la base locale de pacman satisfait : ceux des paquets, et ce qu'ils fournissent (%PROVIDES%) :
/// `pacman -Q sh` répond « bash », qui fournit sh. La version (« sh=5.2 ») ne compte pas pour le nom. `None` si
/// la base ne se lit pas.
fn noms_pacman() -> Option<HashSet<String>> {
    noms_pacman_dans(Path::new(PACMAN_LOCAL))
}

fn noms_pacman_dans(base: &Path) -> Option<HashSet<String>> {
    let mut noms = HashSet::new();
    for e in std::fs::read_dir(base).ok()?.flatten() {
        let Ok(desc) = std::fs::read_to_string(e.path().join("desc")) else {
            continue;
        };
        let champs = natif::champs_pacman(&desc);
        for n in ["NAME", "PROVIDES"].iter().filter_map(|c| champs.get(*c)).flatten() {
            noms.insert(n.split(['=', '<', '>']).next().unwrap_or(n).to_string());
        }
    }
    Some(noms)
}

/// Les applications Flatpak installées (pour l'utilisateur et pour le système), lues dans leurs dossiers. La
/// commande `flatpak list` ne sert qu'en secours, quand Flatpak est réglé pour d'autres dossiers que ceux par
/// défaut (installations ajoutées dans /etc/flatpak/installations.d, variables FLATPAK_*_DIR) : leurs
/// applications ne se verraient pas. `None` : ni lecture ni commande n'ont abouti.
pub(crate) fn applications_flatpak() -> Option<Vec<String>> {
    applications_flatpak_si(natif::present("flatpak"))
}

fn applications_flatpak_si(flatpak_present: bool) -> Option<Vec<String>> {
    // Sans le programme flatpak, rien, comme la commande d'avant : les dossiers restés après sa
    // désinstallation (pacman ne retire que ses fichiers) ne sont plus des applications qui démarrent, et
    // `flatpak uninstall`, proposé pour les retirer, ne pourrait pas se lancer.
    if !flatpak_present {
        return None;
    }
    if flatpak_par_defaut() {
        return Some(natif::flatpak_apps());
    }
    crate::commande::lancer(
        Command::new("flatpak").args(["list", "--app", "--columns=application"]),
        30,
    )
    .filter(|r| r.code == Some(0))
    .map(|r| {
        r.sortie
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    })
}

/// Flatpak n'a-t-il que ses deux installations par défaut, celles que `natif` lit ?
pub(crate) fn flatpak_par_defaut() -> bool {
    let ajoutees = std::fs::read_dir("/etc/flatpak/installations.d")
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().extension().is_some_and(|x| x == "conf"));
    !ajoutees && std::env::var_os("FLATPAK_USER_DIR").is_none() && std::env::var_os("FLATPAK_SYSTEM_DIR").is_none()
}

/// Application Flatpak installée (pour l'utilisateur ou pour le système) ? Son fichier metadata en service le dit.
pub(crate) fn flatpak_installe(id: &str) -> bool {
    // Sans flatpak, ses dossiers restés sur le disque ne lancent rien (voir `applications_flatpak`).
    if !natif::present("flatpak") {
        return false;
    }
    if flatpak_par_defaut() {
        return natif::flatpak_metadata(id).is_some();
    }
    reussit("flatpak", &["info", id])
}

/// Installation Flatpak pour l'utilisateur seul : pas de mot de passe administrateur.
pub(crate) fn installer_flatpak(id: &str) -> Vec<String> {
    vec![
        "flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo".into(),
        format!("flatpak install --user -y --noninteractive flathub {id}"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use natif::present;

    fn jetable(nom: &str) -> std::path::PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-paquets-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// La commande, quand elle est là et réussit ; sinon le test s'arrête sans rien conclure.
    fn commande(programme: &str, args: &[&str]) -> Option<crate::commande::Resultat> {
        if !present(programme) {
            return None;
        }
        crate::commande::lancer_en_anglais(Command::new(programme).args(args), 30).filter(|r| r.code == Some(0))
    }

    #[test]
    fn noms_de_pacman_avec_ce_qui_est_fourni() {
        let d = jetable("pacman");
        for (dossier, desc) in [
            (
                "bash-5.3.1-1",
                "%NAME%\nbash\n\n%VERSION%\n5.3.1-1\n\n%PROVIDES%\nsh=5.3\n",
            ),
            ("python-3to2-1.1.1-1", "%NAME%\npython-3to2\n\n%VERSION%\n1.1.1-1\n"),
        ] {
            std::fs::create_dir_all(d.join(dossier)).unwrap();
            std::fs::write(d.join(dossier).join("desc"), desc).unwrap();
        }
        // Un dossier sans desc (installation interrompue) ne compte pas.
        std::fs::create_dir_all(d.join("casse-1-1")).unwrap();
        let noms = noms_pacman_dans(&d).unwrap();
        let mut tries: Vec<&String> = noms.iter().collect();
        tries.sort();
        assert_eq!(tries, ["bash", "python-3to2", "sh"]);
        assert!(noms_pacman_dans(&d.join("absente")).is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    /// Sur cet ordinateur, les bases lues donnent les mêmes réponses que pacman, dpkg et flatpak, quand ils sont là.
    #[test]
    fn comme_les_commandes() {
        if let (Some(r), Some(noms)) = (commande("pacman", &["-Qq"]), noms_pacman()) {
            for p in r.sortie.lines().filter(|l| !l.is_empty()) {
                assert!(noms.contains(p), "{p}");
            }
            // « sh » est fourni par bash : pacman -Q le trouve, la lecture aussi.
            assert_eq!(noms.contains("sh"), commande("pacman", &["-Q", "sh"]).is_some());
        }
        if let (Some(r), Some(l)) = (
            commande("dpkg-query", &["-W", "-f=${binary:Package} ${db:Status-Status}\n"]),
            natif::paquets_dpkg_installes(),
        ) {
            let installes = r.sortie.lines().filter(|l| l.ends_with(" installed")).count();
            assert_eq!(installes, l.len(), "{}", r.sortie);
        }
        if flatpak_par_defaut()
            && let Some(r) = commande("flatpak", &["list", "--app", "--columns=application"])
        {
            let mut l: Vec<&str> = r.sortie.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            l.sort_unstable();
            l.dedup();
            assert_eq!(
                Some(l.iter().map(|a| (*a).to_string()).collect()),
                applications_flatpak()
            );
        }
    }

    /// Sans le programme flatpak, aucune application : les dossiers restés après sa désinstallation ne se
    /// lisent même pas.
    #[test]
    fn sans_flatpak_aucune_application() {
        assert_eq!(applications_flatpak_si(false), None);
    }

    /// Les noms lus une fois servent à chaque test ; un nom avec son architecture vient de dpkg.
    #[test]
    fn installes_parmi_les_noms_lus() {
        let connus: HashSet<String> = ["steam", "mesa-vulkan-drivers", "mesa-vulkan-drivers:i386"]
            .iter()
            .map(|n| (*n).to_string())
            .collect();
        assert!(installes_parmi(Some(&connus), Paquets::Apt, &["steam"]));
        assert!(installes_parmi(
            Some(&connus),
            Paquets::Apt,
            &["mesa-vulkan-drivers", "mesa-vulkan-drivers:i386"]
        ));
        assert!(!installes_parmi(Some(&connus), Paquets::Apt, &["steam", "lutris"]));
        assert!(installes_parmi(Some(&connus), Paquets::Pacman, &[]));
        assert!(noms_installes(Paquets::Dnf).is_none());
    }
}
