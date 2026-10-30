//! `dpkg --verify` sans dpkg : les empreintes MD5 que dpkg a gardées pour un paquet, lues dans sa base
//! (/var/lib/dpkg), et comparées au fichier sur le disque (MD5 de RustCrypto, crate md-5).
//!
//! Deux sources, comme dpkg (src/main/verify.c) : `info/<paquet>.md5sums` (ou `<paquet>:<arch>.md5sums` pour un
//! paquet Multi-Arch: same), une ligne « md5, deux espaces, chemin sans / initial » par fichier ; et le champ
//! Conffiles du paquet dans `status` (« /etc/x `<md5>` `[obsolete]` [remove-on-upgrade] »), les fichiers de
//! configuration, que md5sums ne couvre pas : les oublier ferait passer une configuration modifiée pour intacte.

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) const BASE: &str = "/var/lib/dpkg";

/// Un nom de paquet de dpkg, avec ou sans son architecture : il entre dans un chemin, rien d'autre n'y passe.
fn nom_valide(paquet: &str) -> bool {
    let (nom, arch) = paquet.split_once(':').unwrap_or((paquet, "a"));
    let bon = |t: &str, permis: &[u8]| {
        !t.is_empty() && t.len() <= 128 && t.bytes().all(|o| o.is_ascii_alphanumeric() || permis.contains(&o))
    };
    bon(nom, b"+-.") && bon(arch, b"-") && !nom.starts_with(['.', '-'])
}

/// Une empreinte MD5 en hexadécimal (32 chiffres) ; « newconffile », « nonexistent », « - » n'en sont pas.
fn empreinte_valide(t: &str) -> bool {
    t.len() == 32 && t.bytes().all(|o| o.is_ascii_hexdigit())
}

fn lire_md5sums(texte: &str) -> impl Iterator<Item = (PathBuf, String)> + '_ {
    texte.lines().filter_map(|l| {
        let (md5, chemin) = l.split_once("  ")?;
        empreinte_valide(md5).then(|| {
            (
                Path::new("/").join(chemin.trim_start_matches('/')),
                md5.to_ascii_lowercase(),
            )
        })
    })
}

/// Les conffiles du paquet `nom` (et de l'architecture `arch` si elle est donnée) dans le fichier status.
fn lire_conffiles(status: &str, nom: &str, arch: Option<&str>) -> Vec<(PathBuf, String)> {
    for bloc in status.split("\n\n") {
        let valeur = |cle: &str| {
            bloc.lines()
                .find_map(|l| l.strip_prefix(cle)?.strip_prefix(':').map(str::trim))
        };
        if valeur("Package") != Some(nom) || arch.is_some_and(|a| valeur("Architecture") != Some(a)) {
            continue;
        }
        let mut dans = false;
        let mut conffiles = Vec::new();
        for l in bloc.lines() {
            if l.starts_with("Conffiles:") {
                dans = true;
                continue;
            }
            if !dans {
                continue;
            }
            // Le champ continue sur les lignes qui commencent par une espace.
            if !l.starts_with(' ') {
                break;
            }
            let mots: Vec<&str> = l.split_whitespace().collect();
            // « /chemin md5 [obsolete] [remove-on-upgrade] » : le condensat est le deuxième mot.
            if let [chemin, md5, ..] = mots[..]
                && chemin.starts_with('/')
                && empreinte_valide(md5)
            {
                conffiles.push((PathBuf::from(chemin), md5.to_ascii_lowercase()));
            }
        }
        return conffiles;
    }
    Vec::new()
}

/// Les chemins détournés d'après /var/lib/dpkg/diversions : trois lignes par détournement (le chemin d'origine, sa
/// nouvelle place, le paquet qui détourne) ; les deux chemins comptent.
fn detournes(texte: &str) -> Vec<PathBuf> {
    let lignes: Vec<&str> = texte.lines().collect();
    lignes
        .as_chunks::<3>()
        .0
        .iter()
        .flat_map(|&[origine, nouvelle, _]| [PathBuf::from(origine), PathBuf::from(nouvelle)])
        .collect()
}

/// Les empreintes connues de dpkg pour `paquet` sous la base `base` : chemin → MD5. Celles de md5sums d'abord ; un
/// conffile sans ligne dans md5sums prend la sienne (comme verify.c). `None` : la base ne se lit pas, ou le paquet
/// n'y est pas (dpkg dira).
pub(crate) fn empreintes(base: &Path, paquet: &str) -> Option<HashMap<PathBuf, String>> {
    if !nom_valide(paquet) {
        return None;
    }
    let (nom, arch) = match paquet.split_once(':') {
        Some((n, a)) => (n, Some(a)),
        None => (paquet, None),
    };
    let info = base.join("info");
    let md5sums = [format!("{paquet}.md5sums"), format!("{nom}.md5sums")]
        .into_iter()
        .chain(
            arch.is_none()
                .then(|| {
                    // Un paquet Multi-Arch: same, nommé sans son architecture : son fichier la porte.
                    std::fs::read_dir(&info)
                        .into_iter()
                        .flatten()
                        .flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .find(|f| {
                            f.strip_prefix(nom)
                                .and_then(|r| r.strip_prefix(':'))
                                .is_some_and(|r| r.ends_with(".md5sums"))
                        })
                })
                .flatten(),
        )
        .find_map(|f| std::fs::read_to_string(info.join(f)).ok());
    let status = std::fs::read_to_string(base.join("status")).ok()?;
    let conffiles = lire_conffiles(&status, nom, arch);
    if md5sums.is_none() && conffiles.is_empty() {
        return None;
    }
    let mut empreintes: HashMap<PathBuf, String> = conffiles.into_iter().collect();
    empreintes.extend(lire_md5sums(md5sums.as_deref().unwrap_or_default()));
    // Un fichier détourné (dpkg-divert) : à son chemin se trouve le fichier d'un autre paquet, et dpkg vérifie
    // l'emplacement détourné. Sans suivre le détournement ici, il n'est pas comparé (non vérifiable), jamais dit
    // modifié à tort.
    if let Ok(d) = std::fs::read_to_string(base.join("diversions")) {
        for chemin in detournes(&d) {
            empreintes.remove(&chemin);
        }
    }
    Some(empreintes)
}

/// Le MD5 d'un fichier, en hexadécimal.
fn md5_de(chemin: &Path) -> Option<String> {
    use md5::Digest;
    use std::os::unix::fs::OpenOptionsExt;
    // Un fichier ordinaire seulement, ouvert sans attendre : une FIFO posée sur un chemin du paquet figerait la
    // lecture.
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(chemin)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut h = md5::Md5::new();
    let mut tampon = vec![0u8; 64 << 10];
    loop {
        let n = f.read(&mut tampon).ok()?;
        if n == 0 {
            break;
        }
        // `read` ne rend jamais plus que le tampon ; s'il le faisait, l'empreinte ne serait pas sûre : rien.
        h.update(tampon.get(..n)?);
    }
    Some(crate::socle::hachage::hexa(&h.finalize()))
}

/// Le fichier a-t-il changé depuis l'installation ? Son empreinte (ou celle de son chemin d'avant la fusion de
/// /usr) comparée à la sienne sur le disque. `None` : pas d'empreinte connue, ou fichier illisible.
pub(crate) fn modifie(empreintes: &HashMap<PathBuf, String>, fichier: &Path, ancien: Option<&Path>) -> Option<bool> {
    let attendue = empreintes.get(fichier).or_else(|| empreintes.get(ancien?))?;
    Some(md5_de(fichier)? != *attendue)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_de_dpkg_fabriquee() {
        let base = std::env::temp_dir().join(format!("vanguard-dpkg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("info")).unwrap();
        let fichiers = base.join("fichiers");
        std::fs::create_dir_all(&fichiers).unwrap();
        let bon = fichiers.join("bon");
        let change = fichiers.join("change");
        std::fs::write(&bon, b"salon").unwrap();
        std::fs::write(&change, b"piege").unwrap();
        // MD5 de « salon ».
        let md5_salon = md5_de(&bon).unwrap();
        assert_eq!(md5_salon, "0253c4a012e0d32bc73b0ad2a2832762");
        let rel = |p: &Path| p.to_string_lossy().trim_start_matches('/').to_string();
        std::fs::write(
            base.join("info/outil:amd64.md5sums"),
            format!(
                "{md5_salon}  {}\n{md5_salon}  {}\npas une ligne\n",
                rel(&bon),
                rel(&change)
            ),
        )
        .unwrap();
        let conf = fichiers.join("outil.conf");
        std::fs::write(&conf, b"modifie").unwrap();
        std::fs::write(
            base.join("status"),
            format!(
                "Package: autre\nStatus: install ok installed\n\nPackage: outil\nArchitecture: amd64\nConffiles:\n {} {md5_salon}\n /etc/vieux 0123456789abcdef0123456789abcdef obsolete\n /etc/neuf newconffile\nDescription: x\n",
                conf.display()
            ),
        )
        .unwrap();
        // Sans l'architecture : le fichier Multi-Arch est trouvé quand même.
        for nom in ["outil", "outil:amd64"] {
            let e = empreintes(&base, nom).unwrap();
            assert_eq!(modifie(&e, &bon, None), Some(false));
            assert_eq!(modifie(&e, &change, None), Some(true));
            assert_eq!(modifie(&e, &conf, None), Some(true), "conffile modifié vu");
            assert_eq!(modifie(&e, Path::new("/etc/neuf"), None), None, "pas d'empreinte");
            assert_eq!(
                modifie(&e, Path::new("/introuvable"), Some(&bon)),
                None,
                "fichier illisible"
            );
            assert!(e.contains_key(Path::new("/etc/vieux")));
        }
        // Un fichier détourné : plus comparé.
        std::fs::write(
            base.join("diversions"),
            format!("{}\n{}.distrib\nautre-paquet\n", change.display(), change.display()),
        )
        .unwrap();
        let e = empreintes(&base, "outil").unwrap();
        assert_eq!(modifie(&e, &change, None), None);
        std::fs::remove_file(base.join("diversions")).unwrap();
        // Le chemin d'avant /usr fusionné.
        let e = empreintes(&base, "outil").unwrap();
        assert_eq!(modifie(&e, &bon, Some(Path::new("/x"))), Some(false));
        // Paquet absent, nom piégé : rien.
        assert_eq!(empreintes(&base, "absent"), None);
        for piege in ["../etc/passwd", "a/b", "", ".cache", "a:b:c/"] {
            assert_eq!(empreintes(&base, piege), None, "{piege}");
        }
        let _ = std::fs::remove_dir_all(&base);
    }
}
