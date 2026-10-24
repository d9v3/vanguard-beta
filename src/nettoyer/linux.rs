//! Nettoyer sous Linux : paquets téléchargés et devenus inutiles, anciennes versions des Snap, applications Flatpak
//! inutilisées, compilations AUR, caches des applications inutilisées, miniatures, vieux journaux, rapports de
//! plantage, corbeille.
//! La place à gagner est mesurée avant (simulations de paccache, tailles des dossiers) quand on peut le faire sans
//! droits d'administrateur.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;

use super::{Age, Element, caches_inutilises, lectures_datees, maison, somme, taille_dossier, volume};
use crate::machine::linux::natif::{self, Snap};
use crate::machine::linux::{Atomique, Paquets, atomique};
use crate::ui::*;

use crate::machine::linux::natif::present_systeme as present;

/// Sortie d'un outil lancé en anglais (ses messages se lisent alors à coup sûr).
fn sortie(cmd: &str, args: &[&str]) -> Option<String> {
    crate::commande::lancer(Command::new(cmd).args(args).env("LC_ALL", "C"), 30)
        .filter(|r| r.code == Some(0))
        .map(|r| r.sortie)
}

/// « 80.47 MiB », « 1.2 GiB », « 512 B » → octets.
fn octets(nombre: &str, unite: &str) -> Option<u64> {
    let n: f64 = nombre.parse().ok()?;
    let facteur = match unite.trim_end_matches(['.', ')']) {
        "B" => 1.0,
        "KiB" | "K" => 1024.0,
        "MiB" | "M" => 1024.0 * 1024.0,
        "GiB" | "G" => 1024.0 * 1024.0 * 1024.0,
        "TiB" | "T" => 1024.0_f64.powi(4),
        _ => return None,
    };
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // une taille positive, arrondie à l'octet
    Some((n * facteur) as u64)
}

/// Simulation de paccache : « ==> finished dry run: 2 candidates (disk space saved: 80.47 MiB) », ou rien à faire.
fn lire_paccache(sortie: &str) -> u64 {
    somme(sortie.lines().filter_map(|l| {
        let reste = l.split("disk space saved: ").nth(1)?;
        let mut mots = reste.split_whitespace();
        octets(mots.next()?, mots.next()?)
    }))
}

/// « Installed Size  : 1.23 MiB » dans `pacman -Qi`, pour chaque paquet.
fn lire_tailles_pacman(sortie: &str) -> u64 {
    somme(
        sortie
            .lines()
            .filter(|l| l.starts_with("Installed Size"))
            .filter_map(|l| {
                let mut mots = l.split(':').nth(1)?.split_whitespace();
                octets(mots.next()?, mots.next()?)
            }),
    )
}

/// `snap list --all` : les révisions désactivées (anciennes versions gardées), en (nom, révision).
fn revisions_desactivees(sortie: &str) -> Vec<(String, String)> {
    sortie
        .lines()
        .skip(1)
        .filter(|l| {
            l.split_whitespace()
                .last()
                .is_some_and(|n| n.split(',').any(|x| x == "disabled"))
        })
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            Some(((*c.first()?).to_string(), (*c.get(2)?).to_string()))
        })
        .collect()
}

/// Les révisions désactivées d'après les fichiers de snapd (`natif::snaps`) : toutes sauf celle en service. Un snap
/// désactivé n'en a plus : `snap list --all` les dit alors toutes « disabled ».
fn revisions_desactivees_de(snaps: &[Snap]) -> Vec<(String, String)> {
    snaps
        .iter()
        .flat_map(|s| {
            s.revisions
                .iter()
                .filter(|r| s.courante.as_ref() != Some(*r))
                .map(|r| (s.nom.clone(), r.clone()))
        })
        .collect()
}

const PACMAN_LOCAL: &str = "/var/lib/pacman/local";

/// Le nom d'une dépendance, sans sa contrainte de version (« glibc>=2.40 ») ni, pour une dépendance facultative,
/// sa raison (« python-pip: pour installer des modules »).
fn nom_de_dependance(d: &str) -> &str {
    d.split(':')
        .next()
        .unwrap_or(d)
        .split(['=', '<', '>'])
        .next()
        .unwrap_or(d)
        .trim()
}

/// Les paquets orphelins (`pacman -Qdtq`) et leur taille installée (%SIZE%, ce que `pacman -Qi` montre), lus dans
/// la base : installés comme dépendance (%REASON% 1) et que plus aucun paquet ne demande, ni dans %DEPENDS% ni
/// dans %OPTDEPENDS%, par son nom ou par ce qu'il fournit (%PROVIDES%). Les contraintes de version sont ignorées :
/// un paquet demandé dans une autre version que la sienne compte pour demandé, la place à gagner n'est donc
/// jamais surestimée. `None` si la base ne se lit pas.
fn orphelins_pacman_dans(base: &Path) -> Option<Vec<(String, u64)>> {
    let paquets: Vec<_> = std::fs::read_dir(base)
        .ok()?
        .flatten()
        .filter_map(|e| {
            Some(natif::champs_pacman(
                &std::fs::read_to_string(e.path().join("desc")).ok()?,
            ))
        })
        .collect();
    let demandes: HashSet<&str> = paquets
        .iter()
        .flat_map(|c| ["DEPENDS", "OPTDEPENDS"].into_iter().filter_map(|k| c.get(k)).flatten())
        .map(|d| nom_de_dependance(d))
        .collect();
    let mut orphelins: Vec<(String, u64)> = paquets
        .iter()
        .filter(|c| c.get("REASON").and_then(|r| r.first()).is_some_and(|r| r == "1"))
        .filter_map(|c| {
            let nom = c.get("NAME")?.first()?;
            let fournis = c.get("PROVIDES").into_iter().flatten().map(|p| nom_de_dependance(p));
            if std::iter::once(nom.as_str())
                .chain(fournis)
                .any(|n| demandes.contains(n))
            {
                return None;
            }
            let taille = c.get("SIZE").and_then(|t| t.first()?.parse().ok()).unwrap_or(0);
            Some((nom.clone(), taille))
        })
        .collect();
    orphelins.sort();
    Some(orphelins)
}

/// La place des journaux de systemd, comme `journalctl --disk-usage` : la somme des blocs occupés par les
/// fichiers « *.journal » et « *.journal~ » du dossier de cette machine (son identifiant, /etc/machine-id), dans
/// /var/log/journal et /run/log/journal. Leurs dossiers se lisent sans droits, et la taille d'un fichier sans
/// l'ouvrir. `None` si aucun des deux dossiers ne se lit.
fn taille_journaux(racines: &[&Path], machine: Option<&str>) -> Option<u64> {
    let mut lisible = false;
    let mut total = 0_u64;
    for r in racines {
        let Ok(dossiers) = std::fs::read_dir(r) else {
            continue;
        };
        lisible = true;
        for d in dossiers.flatten() {
            // journalctl ne compte que la machine en service ; sans son identifiant, tous les dossiers comptent.
            if machine.is_some_and(|m| d.file_name() != m) {
                continue;
            }
            for f in std::fs::read_dir(d.path()).into_iter().flatten().flatten() {
                let nom = f.file_name();
                let nom = nom.to_string_lossy();
                if (nom.ends_with(".journal") || nom.ends_with(".journal~"))
                    && let Ok(m) = f.metadata()
                {
                    total = total.saturating_add(m.blocks().saturating_mul(512));
                }
            }
        }
    }
    lisible.then_some(total)
}

fn paquets_telecharges(gestion: Paquets) -> Element {
    let (taille, commandes): (Option<u64>, Vec<&str>) = match gestion {
        // paccache garde les deux dernières versions de chaque paquet (de quoi revenir en arrière) ; sa simulation dit
        // exactement ce qu'il libère, sans droits.
        Paquets::Pacman if present("paccache") => (
            Some(
                lire_paccache(&sortie("paccache", &["-dk2"]).unwrap_or_default())
                    .saturating_add(lire_paccache(&sortie("paccache", &["-duk0"]).unwrap_or_default())),
            ),
            vec!["sudo paccache -rk2", "sudo paccache -ruk0"],
        ),
        Paquets::Pacman => (None, vec!["sudo pacman -Sc --noconfirm"]),
        Paquets::Apt => (
            taille_dossier(Path::new("/var/cache/apt/archives"), Age::Tout, &[]),
            vec!["sudo apt-get clean"],
        ),
        Paquets::Dnf if atomique() == Some(Atomique::RpmOstree) => (None, vec!["sudo rpm-ostree cleanup -bm"]),
        Paquets::Dnf => (
            ["/var/cache/libdnf5", "/var/cache/dnf"]
                .iter()
                .filter_map(|d| taille_dossier(Path::new(d), Age::Tout, &[]))
                .reduce(u64::saturating_add),
            vec!["sudo dnf clean all"],
        ),
        Paquets::Zypper => (
            taille_dossier(Path::new("/var/cache/zypp"), Age::Tout, &[]),
            vec!["sudo zypper clean --all"],
        ),
    };
    // Seul paccache garde de quoi revenir en arrière : pacman -Sc, apt-get clean, dnf clean all et zypper clean
    // effacent les anciennes versions, celles qu'on réinstalle après une mise à jour qui casse (depuis_maj.rs le
    // conseille). Recommandé seulement avec paccache, et la prudence dite sinon.
    let garde = commandes.first().is_some_and(|c| c.contains("paccache"));
    paquets_telecharges_element(taille, commandes.into_iter().map(String::from).collect(), garde)
}

fn paquets_telecharges_element(taille: Option<u64>, commandes: Vec<String>, garde: bool) -> Element {
    Element {
        titre: tr!("Paquets téléchargés", "Downloaded packages"),
        effet: if garde {
            tr!(
                "Les paquets gardés après chaque mise à jour. Les deux dernières versions de chacun restent, pour pouvoir revenir en arrière.",
                "Packages kept after each update. The last two versions of each stay, so you can roll back."
            )
        } else {
            tr!(
                "Les paquets gardés après chaque mise à jour.",
                "Packages kept after each update."
            )
        }
        .into(),
        prudence: (!garde).then(|| {
            tr!(
                "Efface aussi les anciennes versions, celles qui permettent de revenir en arrière après une mise à jour qui casse.",
                "Also erases the old versions, the ones that let you roll back after an update that breaks something."
            )
        }),
        taille,
        commandes,
        recommande: garde,
        admin: true,
    }
}

fn paquets_inutiles(gestion: Paquets) -> Option<Element> {
    let (taille, commande) = match gestion {
        Paquets::Pacman => {
            // pacman en secours seulement, quand sa base ne se lit pas.
            let taille = orphelins_pacman_dans(Path::new(PACMAN_LOCAL))
                .map(|o| somme(o.iter().map(|(_, t)| *t)))
                .or_else(|| {
                    let orphelins = sortie("pacman", &["-Qdtq"]).unwrap_or_default();
                    let noms: Vec<&str> = orphelins.split_whitespace().collect();
                    if noms.is_empty() {
                        Some(0)
                    } else {
                        let mut args = vec!["-Qi"];
                        args.extend(&noms);
                        sortie("pacman", &args).map(|s| lire_tailles_pacman(&s))
                    }
                });
            (
                taille,
                tr!(
                    "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'Aucun paquet orphelin.'; fi",
                    "orphelins=$(pacman -Qdtq); if [ -n \"$orphelins\" ]; then sudo pacman -Rns $orphelins; else echo 'No orphan packages.'; fi"
                ),
            )
        }
        // Sans -y : la liste s'affiche et se confirme (retirer un métapaquet peut emporter tout un bureau).
        Paquets::Apt => (None, "sudo apt-get autoremove --purge"),
        // Image en lecture seule (rpm-ostree) : rien à retirer à la main.
        Paquets::Dnf if atomique().is_some() => return None,
        Paquets::Dnf => (None, "sudo dnf autoremove"),
        Paquets::Zypper => return None,
    };
    Some(Element {
        titre: tr!("Paquets devenus inutiles", "Packages no longer needed"),
        effet: tr!(
            "Paquets installés pour un autre que plus rien n'utilise.",
            "Packages installed for another one that nothing uses any more."
        )
        .into(),
        prudence: Some(tr!(
            "La liste s'affiche et se confirme avant : vérifiez qu'elle ne contient rien que vous utilisez.",
            "The list is shown and confirmed first: check it holds nothing you use."
        )),
        taille,
        commandes: vec![commande.to_string()],
        recommande: false,
        admin: true,
    })
}

fn snap() -> Option<Element> {
    if !present("snap") {
        return None;
    }
    // Les fichiers de snapd disent les révisions gardées ; `snap list` en secours, quand ils ne se lisent pas.
    let anciennes = match natif::snaps() {
        Some(snaps) => revisions_desactivees_de(&snaps),
        None => revisions_desactivees(&sortie("snap", &["list", "--all"])?),
    };
    let taille = somme(
        anciennes
            .iter()
            .filter_map(|(nom, rev)| std::fs::metadata(format!("/var/lib/snapd/snaps/{nom}_{rev}.snap")).ok())
            .map(|m| m.len()),
    );
    Some(Element {
        titre: tr!("Anciennes versions des Snap", "Old Snap versions"),
        effet: tr!(
            "Snap garde les versions précédentes de chaque application ; la version en service reste.",
            "Snap keeps the previous versions of each app; the version in use stays."
        )
        .into(),
        prudence: None,
        taille: Some(taille),
        commandes: vec![
            "snap list --all | awk '/disabled/{print $1, $3}' | while read -r nom rev; do sudo snap remove \"$nom\" --revision=\"$rev\"; done"
                .into(),
        ],
        recommande: true,
        admin: true,
    })
}

fn flatpak() -> Option<Element> {
    present("flatpak").then(|| Element {
        titre: tr!("Flatpak inutilisés", "Unused Flatpak runtimes"),
        effet: tr!(
            "Bibliothèques Flatpak qu'aucune application installée n'utilise plus.",
            "Flatpak libraries that no installed app uses any more."
        )
        .into(),
        prudence: None,
        taille: None,
        commandes: vec!["flatpak uninstall --unused -y".into()],
        recommande: true,
        admin: false,
    })
}

/// Compilations gardées par les assistants AUR (yay, paru) : seulement reconstruire un paquet en a besoin.
fn compilations_aur(maison: &Path) -> Vec<Element> {
    [
        ("yay", ".cache/yay", "rm -rf ~/.cache/yay/*"),
        ("paru", ".cache/paru/clone", "rm -rf ~/.cache/paru/clone/*"),
    ]
    .into_iter()
    .filter_map(|(assistant, dossier, commande)| {
        let taille = taille_dossier(&maison.join(dossier), Age::Tout, &[])?;
        Some(Element {
            titre: if assistant == "yay" {
                tr!("Compilations AUR (yay)", "AUR builds (yay)")
            } else {
                tr!("Compilations AUR (paru)", "AUR builds (paru)")
            },
            effet: trf!(
                "Sources et compilations des paquets AUR, gardées par {assistant} ; il les retélécharge au besoin.",
                "Sources and builds of AUR packages, kept by {assistant}; it downloads them again when needed."
            ),
            prudence: None,
            taille: Some(taille),
            commandes: vec![commande.into()],
            recommande: true,
            admin: false,
        })
    })
    .collect()
}

/// Les caches d'applications de ~/.cache qui dorment ; ceux comptés à part (miniatures, AUR) n'y sont pas.
fn vieux_cache(maison: &Path) -> Option<Element> {
    let cache = maison.join(".cache");
    caches_inutilises(
        &cache,
        "~/.cache",
        &["thumbnails", "yay", "paru"],
        lectures_datees(&cache),
    )
}

fn miniatures(maison: &Path) -> Element {
    Element {
        titre: tr!("Miniatures des images", "Image thumbnails"),
        effet: tr!(
            "Aperçus des photos et vidéos ; le gestionnaire de fichiers les refait en les affichant.",
            "Previews of photos and videos; the file manager makes them again when showing them."
        )
        .into(),
        prudence: None,
        taille: Some(taille_dossier(&maison.join(".cache/thumbnails"), Age::Tout, &[]).unwrap_or(0)),
        commandes: vec!["rm -rf ~/.cache/thumbnails".into()],
        recommande: true,
        admin: false,
    }
}

/// « Archived and active journals take up 292.7M in the file system. » → octets.
fn lire_disk_usage(s: &str) -> Option<u64> {
    let reste = s.split("take up ").nth(1)?;
    let mot = reste.split_whitespace().next()?;
    let (nombre, unite) = mot.split_at(mot.find(|c: char| c.is_ascii_alphabetic())?);
    octets(nombre, unite)
}

fn journaux() -> Option<Element> {
    if !Path::new("/run/systemd/system").exists() {
        return None;
    }
    // La taille actuelle, pas ce qui partira. journalctl en secours, quand les dossiers ne se lisent pas.
    let machine = std::fs::read_to_string("/etc/machine-id").ok();
    let actuelle = taille_journaux(
        &[Path::new("/var/log/journal"), Path::new("/run/log/journal")],
        machine.as_deref().map(str::trim).filter(|m| !m.is_empty()),
    )
    .or_else(|| lire_disk_usage(&sortie("journalctl", &["--disk-usage"])?));
    Some(Element {
        titre: tr!("Vieux journaux du système", "Old system logs"),
        effet: match actuelle {
            Some(t) => trf!(
                "Les journaux font {} ; les deux dernières semaines restent.",
                "The logs take {}; the last two weeks stay.",
                super::taille_lisible(t)
            ),
            None => tr!(
                "Les deux dernières semaines de journaux restent.",
                "The last two weeks of logs stay."
            )
            .into(),
        },
        prudence: None,
        taille: None,
        commandes: vec!["sudo journalctl --vacuum-time=2weeks".into()],
        recommande: true,
        admin: true,
    })
}

fn plantages() -> Option<Element> {
    let dossier = Path::new("/var/lib/systemd/coredump");
    let taille = taille_dossier(dossier, Age::NonModifieDepuis(7), &[])?;
    Some(Element {
        titre: tr!("Rapports de plantage", "Crash reports"),
        effet: tr!(
            "Copies de la mémoire des programmes qui ont planté il y a plus d'une semaine.",
            "Memory copies of programs that crashed more than a week ago."
        )
        .into(),
        prudence: None,
        taille: Some(taille),
        commandes: vec!["sudo find /var/lib/systemd/coredump -type f -mtime +7 -delete".into()],
        recommande: true,
        admin: true,
    })
}

fn corbeille(maison: &Path) -> Element {
    Element {
        titre: tr!("Corbeille", "Trash"),
        effet: tr!("Les fichiers mis à la corbeille.", "Files moved to the trash.").into(),
        prudence: Some(tr!(
            "Ce qui est dans la corbeille ne pourra plus être récupéré.",
            "What is in the trash can no longer be recovered."
        )),
        taille: Some(taille_dossier(&maison.join(".local/share/Trash"), Age::Tout, &[]).unwrap_or(0)),
        commandes: vec![
            "rm -rf ~/.local/share/Trash/files ~/.local/share/Trash/info ~/.local/share/Trash/expunged".into(),
        ],
        recommande: false,
        admin: false,
    }
}

pub fn elements() -> Vec<Element> {
    let maison = maison();
    let gestion = Paquets::detecter();
    let mut l: Vec<Element> = Vec::new();
    l.extend(gestion.map(paquets_telecharges));
    l.extend(gestion.and_then(paquets_inutiles));
    l.extend(snap());
    l.extend(flatpak());
    l.extend(compilations_aur(&maison));
    l.extend(vieux_cache(&maison));
    l.push(miniatures(&maison));
    l.extend(journaux());
    l.extend(plantages());
    l.push(corbeille(&maison));
    l
}

/// Le volume racine, et celui du dossier personnel s'il est ailleurs. Deux sous-volumes btrfs (« @ » et « @home »)
/// partagent la même place : à la même taille, c'est le même disque, compté une fois.
pub fn place() -> Option<(u64, u64, u64)> {
    let (libre, total) = volume(Path::new("/"))?;
    let cumul = match volume(&maison()) {
        Some((l, t)) if t != total => libre.saturating_add(l),
        _ => libre,
    };
    Some((libre, total, cumul))
}

/// Les commandes de chaque élément, l'une après l'autre (sudo demande le mot de passe dans le terminal).
pub fn executer(choisis: &[&Element]) -> Vec<bool> {
    let groupes: Vec<Vec<String>> = choisis.iter().map(|e| e.commandes.clone()).collect();
    crate::machine::appliquer_chacune(&groupes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sans paccache, vider le cache efface de quoi revenir en arrière : pas recommandé, et la prudence le dit.
    #[test]
    fn paquets_telecharges_prudents_sans_paccache() {
        let sans = paquets_telecharges_element(Some(1 << 30), vec!["sudo apt-get clean".into()], false);
        assert!(!sans.recommande && sans.prudence.is_some());
        let avec = paquets_telecharges_element(Some(1 << 30), vec!["sudo paccache -rk2".into()], true);
        assert!(avec.recommande && avec.prudence.is_none());
        for p in [Paquets::Apt, Paquets::Zypper] {
            let e = paquets_telecharges(p);
            assert!(!e.recommande && e.prudence.is_some(), "{:?}", e.commandes);
        }
    }

    #[test]
    fn sorties_lues() {
        assert_eq!(
            lire_paccache("==> finished dry run: 2 candidates (disk space saved: 80.47 MiB)\n"),
            84_378_910
        );
        assert_eq!(lire_paccache("==> no candidate packages found for pruning\n"), 0);
        // Deux tailles démesurées : plafonnées, sans paniquer (la version publiée vérifie les dépassements).
        assert_eq!(
            lire_paccache("disk space saved: 1e19 B)\ndisk space saved: 1e19 B)\n"),
            u64::MAX
        );
        let qi = "Name            : a\nInstalled Size  : 1.50 MiB\nName            : b\nInstalled Size  : 512.00 KiB\n";
        assert_eq!(lire_tailles_pacman(qi), (3 << 19) + (512 << 10));
        let snaps = "Name    Version   Rev    Tracking       Publisher   Notes\n\
                     core20  20240416  2264   latest/stable  canonical✓  base,disabled\n\
                     core20  20240705  2318   latest/stable  canonical✓  base\n\
                     firefox 128.0     4451   latest/stable  mozilla✓    disabled\n";
        assert_eq!(
            revisions_desactivees(snaps),
            [
                ("core20".to_string(), "2264".to_string()),
                ("firefox".to_string(), "4451".to_string())
            ]
        );
    }

    fn jetable(nom: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("vanguard-nettoyer-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn orphelins_lus_dans_la_base() {
        let d = jetable("pacman");
        for (dossier, desc) in [
            // Demandé par « appli » sous un nom qu'il fournit : pas orphelin.
            (
                "libfoo-1-1",
                "%NAME%\nlibfoo\n\n%REASON%\n1\n\n%SIZE%\n100\n\n%PROVIDES%\nfoo.so=1-64\n",
            ),
            (
                "appli-2-1",
                "%NAME%\nappli\n\n%SIZE%\n5000\n\n%DEPENDS%\nfoo.so>=1\n\n%OPTDEPENDS%\nextra: aide\n",
            ),
            // Seulement facultatif pour « appli » : pas orphelin non plus (pacman -Qdt avec un seul t).
            ("extra-1-1", "%NAME%\nextra\n\n%REASON%\n1\n\n%SIZE%\n7\n"),
            ("vieux-3-1", "%NAME%\nvieux\n\n%REASON%\n1\n\n%SIZE%\n2048\n"),
            ("seul-1-1", "%NAME%\nseul\n\n%REASON%\n1\n\n%SIZE%\n10\n"),
            // Installé à la main (pas de %REASON%) : jamais orphelin.
            ("outil-1-1", "%NAME%\noutil\n\n%SIZE%\n99\n"),
        ] {
            std::fs::create_dir_all(d.join(dossier)).unwrap();
            std::fs::write(d.join(dossier).join("desc"), desc).unwrap();
        }
        assert_eq!(
            orphelins_pacman_dans(&d).unwrap(),
            [("seul".to_string(), 10), ("vieux".to_string(), 2048)]
        );
        assert!(orphelins_pacman_dans(&d.join("absente")).is_none());
        assert_eq!(nom_de_dependance("python-pip: pour pip"), "python-pip");
        assert_eq!(nom_de_dependance("glibc>=2.40"), "glibc");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn revisions_desactivees_des_fichiers() {
        let snaps = [
            Snap {
                nom: "core20".into(),
                courante: Some("2318".into()),
                revisions: vec!["2264".into(), "2318".into()],
            },
            Snap {
                nom: "firefox".into(),
                courante: None,
                revisions: vec!["4451".into()],
            },
        ];
        assert_eq!(
            revisions_desactivees_de(&snaps),
            [
                ("core20".to_string(), "2264".to_string()),
                ("firefox".to_string(), "4451".to_string())
            ]
        );
    }

    #[test]
    fn taille_des_journaux() {
        let d = jetable("journal");
        let ici = d.join("var").join("0123abcd");
        let autre = d.join("var").join("ffff0000");
        std::fs::create_dir_all(&ici).unwrap();
        std::fs::create_dir_all(&autre).unwrap();
        std::fs::write(ici.join("system.journal"), vec![1u8; 20_000]).unwrap();
        std::fs::write(ici.join("system-0001.journal~"), vec![1u8; 20_000]).unwrap();
        std::fs::write(ici.join("notes.txt"), vec![1u8; 20_000]).unwrap();
        std::fs::write(autre.join("system.journal"), vec![1u8; 20_000]).unwrap();
        let var = d.join("var");
        let absent = d.join("run");
        let ici_seul = taille_journaux(&[&var, &absent], Some("0123abcd")).unwrap();
        let tous = taille_journaux(&[&var, &absent], None).unwrap();
        // Des blocs occupés : au moins la taille écrite, les deux journaux de cette machine seulement.
        assert!(ici_seul >= 40_000, "{ici_seul}");
        assert!(tous > ici_seul, "{tous} {ici_seul}");
        assert_eq!(taille_journaux(&[&absent], None), None);
        let _ = std::fs::remove_dir_all(d);
    }

    /// Sur cet ordinateur, les lectures donnent ce que disent pacman, snap et journalctl, quand ils sont là.
    #[test]
    fn comme_les_commandes() {
        if present("pacman")
            && let Some(lus) = orphelins_pacman_dans(Path::new(PACMAN_LOCAL))
        {
            // pacman -Qdtq répond 1, sans rien écrire, quand il n'y a aucun orphelin.
            let liste = sortie("pacman", &["-Qdtq"]).unwrap_or_default();
            let attendus: Vec<&str> = liste.split_whitespace().collect();
            let noms: Vec<&str> = lus.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(noms, attendus);
        }
        if present("snap")
            && let (Some(s), Some(snaps)) = (sortie("snap", &["list", "--all"]), natif::snaps())
        {
            let mut a = revisions_desactivees(&s);
            let mut b = revisions_desactivees_de(&snaps);
            a.sort();
            b.sort();
            assert_eq!(a, b, "{s}");
        }
        let machine = std::fs::read_to_string("/etc/machine-id").unwrap_or_default();
        if let (Some(s), Some(lue)) = (
            sortie("journalctl", &["--disk-usage"]),
            taille_journaux(
                &[Path::new("/var/log/journal"), Path::new("/run/log/journal")],
                Some(machine.trim()).filter(|m| !m.is_empty()),
            ),
        ) && let Some(dite) = lire_disk_usage(&s)
        {
            // journalctl arrondit (« 4G ») et les journaux grandissent pendant le test : un dixième d'écart permis.
            assert!(lue.abs_diff(dite) <= dite / 10 + (1 << 20), "{s} : {lue}");
        }
    }

    #[test]
    fn commandes_shell_valides() {
        for e in elements() {
            for c in &e.commandes {
                let valide = Command::new("bash")
                    .args(["-n", "-c", c])
                    .status()
                    .is_ok_and(|s| s.success());
                assert!(valide, "« {} » : {c}", e.titre);
            }
        }
    }
}
