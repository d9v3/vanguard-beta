//! La place que `paccache -rk2` puis `paccache -ruk0` libéreraient dans le cache de pacman, calculée sans lancer
//! paccache : les fichiers du cache, groupés par paquet et architecture, triés par version (vercmp), les deux plus
//! récents gardés ; puis tous ceux des paquets désinstallés. Le découpage du nom suit celui de paccache
//! (paccache.sh.in : le nom est tout sauf les trois derniers morceaux séparés par « - »), et une signature `.sig`
//! compte avec son paquet.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Un paquet du cache : (nom, architecture, version « ver-rel »), découpé comme paccache le découpe. `None` : pas un
/// paquet (signature, téléchargement à moitié fait n'ayant pas la forme, autre fichier).
fn decouper(fichier: &str) -> Option<(String, String, String)> {
    // `*.pkg.tar!(*.sig)` : un paquet, compressé ou non, mais pas sa signature.
    // Le motif de paccache est sensible à la casse : « .SIG » n'est pas une signature pour lui.
    if !fichier.contains(".pkg.tar") || fichier.rsplit_once('.').is_some_and(|(_, e)| e == "sig") {
        return None;
    }
    let morceaux: Vec<&str> = fichier.split('-').collect();
    // Au moins quatre morceaux : un nom (lui-même peut contenir des « - »), la version, la révision, l'architecture.
    let [tete @ .., ver, rel, fin] = morceaux.as_slice() else {
        return None;
    };
    if tete.is_empty() {
        return None;
    }
    let nom = tete.join("-");
    let arch = fin.split('.').next().unwrap_or_default().to_string();
    let version = format!("{ver}-{rel}");
    Some((nom, arch, version))
}

/// Les dossiers du cache d'après pacman.conf (CacheDir, une ou plusieurs valeurs) ; /var/cache/pacman/pkg/ sinon.
/// `None` : pacman.conf illisible, ou un Include dans `[options]` que ce lecteur ne suit pas (paccache demande à
/// pacman-conf, qui le suit).
fn dossiers(conf: &str) -> Option<Vec<PathBuf>> {
    let mut dans_options = false;
    let mut dossiers = Vec::new();
    for l in conf.lines() {
        let l = l.split('#').next().unwrap_or_default().trim();
        if let Some(s) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            dans_options = s.trim() == "options";
            continue;
        }
        if !dans_options {
            continue;
        }
        let Some((cle, valeur)) = l.split_once('=') else {
            continue;
        };
        match cle.trim() {
            "CacheDir" => dossiers.extend(valeur.split_whitespace().map(PathBuf::from)),
            "Include" => return None,
            _ => {}
        }
    }
    if dossiers.is_empty() {
        dossiers.push(PathBuf::from("/var/cache/pacman/pkg/"));
    }
    Some(dossiers)
}

/// Les octets libérés : (`-rk2`, puis `-ruk0` sur ce qui reste). Pour chaque (nom, architecture), les versions au-delà
/// des deux plus récentes ; puis, des paquets que `installes` n'a pas, tout ce qui reste. Chaque fichier ne compte
/// qu'une fois, signature comprise. `taille` : la taille d'un fichier, `None` s'il n'existe pas.
fn calculer(
    fichiers: &[(PathBuf, String)],
    installes: &HashSet<String>,
    taille: impl Fn(&Path) -> Option<u64>,
) -> (u64, u64) {
    let mut groupes: HashMap<(String, String), Vec<(String, &PathBuf)>> = HashMap::new();
    for (chemin, nom) in fichiers {
        if let Some((paquet, arch, version)) = decouper(nom) {
            groupes.entry((paquet, arch)).or_default().push((version, chemin));
        }
    }
    let poids = |chemin: &Path| {
        let mut sig = chemin.as_os_str().to_owned();
        sig.push(".sig");
        taille(chemin).unwrap_or(0) + taille(Path::new(&sig)).unwrap_or(0)
    };
    let (mut anciennes, mut desinstalles) = (0u64, 0u64);
    for ((paquet, _), mut versions) in groupes {
        versions.sort_by(|a, b| super::maj::vercmp(&a.0, &b.0));
        let garder = versions.len().min(2);
        let (vieilles, recentes) = versions.split_at(versions.len() - garder);
        anciennes += vieilles.iter().map(|(_, c)| poids(c)).sum::<u64>();
        if !installes.contains(&paquet) {
            desinstalles += recentes.iter().map(|(_, c)| poids(c)).sum::<u64>();
        }
    }
    (anciennes, desinstalles)
}

/// La place récupérable dans le cache de pacman par `paccache -rk2` puis `paccache -ruk0`. `None` : le cache ou la
/// liste des paquets installés ne se lit pas ici ; paccache dira.
pub(crate) fn recuperable() -> Option<(u64, u64)> {
    let dossiers = dossiers(&std::fs::read_to_string("/etc/pacman.conf").ok()?)?;
    let installes: HashSet<String> = super::natif::paquets_pacman()?.into_iter().map(|(n, _)| n).collect();
    let mut fichiers = Vec::new();
    for d in dossiers {
        let lecture = match std::fs::read_dir(&d) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        for e in lecture.flatten() {
            // Un fichier ordinaire seulement, comme le motif de paccache sur un seul niveau.
            if e.file_type().is_ok_and(|t| t.is_file()) {
                fichiers.push((e.path(), e.file_name().to_string_lossy().into_owned()));
            }
        }
    }
    Some(calculer(&fichiers, &installes, |c| {
        std::fs::metadata(c).ok().map(|m| m.len())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_decoupes_comme_paccache() {
        assert_eq!(
            decouper("python-3to2-1.1.1-1-any.pkg.tar.zst"),
            Some(("python-3to2".into(), "any".into(), "1.1.1-1".into()))
        );
        assert_eq!(
            decouper("linux-6.17.1.arch1-1-x86_64.pkg.tar.zst"),
            Some(("linux".into(), "x86_64".into(), "6.17.1.arch1-1".into()))
        );
        assert_eq!(
            decouper("vim-2:9.1-2-x86_64.pkg.tar.xz"),
            Some(("vim".into(), "x86_64".into(), "2:9.1-2".into()))
        );
        assert_eq!(decouper("linux-6.17.1.arch1-1-x86_64.pkg.tar.zst.sig"), None);
        assert_eq!(decouper("a-1-x86_64.pkg.tar.zst"), None, "trop peu de morceaux");
        assert_eq!(decouper("notes.txt"), None);
    }

    #[test]
    fn cache_d_essai() {
        let f = |nom: &str| (PathBuf::from(format!("/cache/{nom}")), nom.to_string());
        let fichiers = [
            f("vim-9.1-1-x86_64.pkg.tar.zst"),
            f("vim-9.1-10-x86_64.pkg.tar.zst"),
            f("vim-9.1-2-x86_64.pkg.tar.zst"),
            f("vim-9.0-5-x86_64.pkg.tar.zst"),
            f("parti-1.0-1-any.pkg.tar.zst"),
            f("parti-0.9-1-any.pkg.tar.zst"),
            f("parti-0.8-1-any.pkg.tar.zst"),
            f("vim-9.1-10-x86_64.pkg.tar.zst.sig"),
            f("autre.txt"),
        ];
        let installes: HashSet<String> = ["vim".to_string()].into();
        // Chaque paquet pèse 100 octets, sa signature 1 (seule celle de vim 9.1-10 existe).
        let taille = |c: &Path| {
            let n = c.to_string_lossy();
            if n.ends_with(".sig") {
                n.contains("vim-9.1-10").then_some(1)
            } else {
                Some(100)
            }
        };
        // vim : 9.0-5 et 9.1-1 partent (9.1-2 et 9.1-10 restent : 10 > 2 par vercmp) ; parti : 0.8 part, puis 0.9 et
        // 1.0 avec -u.
        assert_eq!(calculer(&fichiers, &installes, taille), (300, 200));
        assert_eq!(calculer(&[], &installes, taille), (0, 0));
    }

    #[test]
    fn dossiers_du_cache() {
        assert_eq!(
            dossiers("[options]\n#CacheDir = /x\n"),
            Some(vec![PathBuf::from("/var/cache/pacman/pkg/")])
        );
        assert_eq!(
            dossiers("[options]\nCacheDir = /a/ /b/\n[core]\nCacheDir = /c/\n"),
            Some(vec![PathBuf::from("/a/"), PathBuf::from("/b/")])
        );
        assert_eq!(dossiers("[options]\nInclude = /etc/x.conf\n"), None);
    }

    /// L'oracle : la place récupérable calculée par Vanguard contre la simulation de paccache (-dk2, -duk0), sur cet
    /// ordinateur, à 0,01 Mio près (paccache arrondit).
    #[test]
    fn comme_paccache() {
        let Some((k2, u0)) = recuperable() else {
            return crate::essais::saute("cache de pacman illisible ici");
        };
        // La taille en Mio et ce que l'arrondi de paccache (deux décimales de son unité) peut en écarter.
        let simuler = |args: &[&str]| -> Option<(f64, f64)> {
            let r = crate::commande::lancer_en_anglais(std::process::Command::new("paccache").args(args), 60)?;
            if r.sortie.contains("no candidate packages found") {
                return Some((0.0, 0.01));
            }
            // En Mio : paccache choisit son unité selon la taille (« 121.03 KiB » passait pour 121 Mio, le 30 oct.).
            r.sortie.lines().find_map(|l| {
                let mut mots = l.split("disk space saved: ").nth(1)?.split_whitespace();
                let nombre: f64 = mots.next()?.parse().ok()?;
                let unite = match mots.next()?.trim_end_matches(')') {
                    "B" => 1.0 / 1024.0 / 1024.0,
                    "KiB" => 1.0 / 1024.0,
                    "MiB" => 1.0,
                    "GiB" => 1024.0,
                    "TiB" => 1024.0 * 1024.0,
                    _ => return None,
                };
                Some((nombre * unite, 0.005 * unite + 0.01))
            })
        };
        let (Some((a, marge_a)), Some((b, marge_b))) = (simuler(&["-dk2"]), simuler(&["-duk0"])) else {
            return crate::essais::saute("paccache absent");
        };
        #[allow(clippy::cast_precision_loss)]
        let mio = |o: u64| o as f64 / f64::from(1u32 << 20);
        assert!((mio(k2) - a).abs() < marge_a, "-dk2 : {} contre {a}", mio(k2));
        // -duk0 compte aussi les vieilles versions des paquets désinstallés, que -dk2 a déjà comptées.
        assert!(mio(u0) <= b + marge_b, "-duk0 : {} contre {b}", mio(u0));
        if k2 == 0 {
            assert!((mio(u0) - b).abs() < marge_b, "-duk0 : {} contre {b}", mio(u0));
        }
    }
}
