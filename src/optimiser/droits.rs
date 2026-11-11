//! Les droits d'un fichier ou d'un dossier du compte, lus et posés sans shell et sans suivre de lien : une seule
//! famille de fonctions pour le relevé d'avant, l'application d'une correction du compte et son annulation. Le
//! dossier personnel est ouvert sans suivre de lien sur son dernier élément (ses parents se résolvent comme pour le
//! système), puis chaque élément par openat relativement au précédent, avec O_NOFOLLOW (un lien au milieu n'est pas
//! un dossier, un lien au bout est refusé par ELOOP) ; chaque descripteur est jugé par fstat (propriétaire : le compte
//! qui agit ; sorte : dossier au milieu, simple fichier sans second nom ou dossier au bout) ; les droits se posent par
//! fchmod sur le descripteur même qui a été jugé. Entre la lecture et le geste, rien ne se résout plus par le nom :
//! un lien ou un autre fichier mis à sa place pendant ce temps ne change pas ce qui est visé.
//!
//! Une cible que son propriétaire ne peut pas lire (droits sans « r » pour lui) est refusée : l'ouvrir en lecture est
//! la seule façon, sans /proc, d'avoir un descripteur qu'accepte fchmod. Les corrections du compte ne font que
//! resserrer des droits lisibles par le compte : ce refus ne les touche pas.

// Ni débordement ni `as` : les modes passent par `try_from` et des masques.
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crate::trf;

/// Les drapeaux d'un dossier traversé : O_PATH (rien n'est demandé au système de fichiers pour l'ouvrir), un lien
/// n'est pas un dossier.
const TRAVERSE: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
/// Les drapeaux du bout : en lecture (fchmod refuse un descripteur O_PATH), sans attendre (un tube mis à sa place),
/// sans devenir le terminal du programme, sans suivre de lien.
const BOUT: i32 = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Les droits les plus larges qu'une correction ou son annulation pose : ni setuid ni setgid (le collant, oui :
/// un dossier partagé du compte peut l'avoir).
const MODE_MAX: u32 = 0o1777;

/// Les droits de `chemin` (fichier ou dossier du dossier personnel), lus sur le descripteur ouvert sans suivre de
/// lien, avec les mêmes gardes que pour les poser. L'erreur est une phrase dans la langue de l'interface.
pub(crate) fn lire(chemin: &Path) -> Result<u32, String> {
    let bout = ouvrir(chemin)?;
    Ok(bout.mode)
}

/// Pose `mode` sur `chemin` et rend les droits d'avant, lus sur le même descripteur juste avant. Rien n'est changé si
/// une garde refuse, ni si `mode` porte setuid, setgid ou plus que des droits.
pub(crate) fn poser(chemin: &Path, mode: u32) -> Result<u32, String> {
    if mode & !MODE_MAX != 0 {
        return Err(trf!(
            "droits refusés : {:04o} (ni setuid ni setgid)",
            "permissions refused: {:04o} (no setuid nor setgid)",
            mode
        ));
    }
    let bout = ouvrir(chemin)?;
    if bout.mode != mode {
        fchmod(bout.fichier.as_fd(), mode)
            .map_err(|e| trf!("{} : droits non posés ({e})", "{}: permissions not set ({e})", bout.ou))?;
        // Relu sur le descripteur : ce qui compte est ce que le noyau a gardé.
        let pose = mode_de(&bout.fichier)
            .map_err(|e| trf!("{} : relecture impossible ({e})", "{}: cannot read back ({e})", bout.ou))?;
        if pose != mode {
            return Err(trf!(
                "{} : {:04o} demandés, {:04o} relus",
                "{}: {:04o} requested, {:04o} read back",
                bout.ou,
                mode,
                pose
            ));
        }
    }
    Ok(bout.mode)
}

/// Le bout ouvert et jugé : son descripteur en lecture, ses droits lus dessus, et son nom pour les messages (« ~/… »).
struct Bout {
    fichier: File,
    mode: u32,
    ou: String,
}

/// Le dossier de départ de `chemin` et le chemin sous lui : le dossier personnel, ou, dans les essais, leur dossier
/// jetable (`essais::temporaire`), comme `annulables::dans_la_maison`.
fn depart(chemin: &Path) -> Result<(PathBuf, PathBuf), String> {
    let hors = || {
        trf!(
            "{} n'est pas dans le dossier personnel",
            "{} is not in the home folder",
            crate::modele::resultat::nom_sans_piege(&chemin.to_string_lossy(), 120)
        )
    };
    // Les essais d'abord : leur dossier jetable peut être sous le vrai dossier personnel, derrière un lien.
    #[cfg(test)]
    {
        let essais = crate::machine::unix::maison_simple(&crate::essais::temporaire()).map_err(String::from)?;
        if let Ok(r) = chemin.strip_prefix(&essais) {
            return Ok((essais, r.to_path_buf()));
        }
    }
    let maison = crate::machine::unix::maison_simple(&crate::socle::maison()).map_err(String::from)?;
    if let Ok(r) = chemin.strip_prefix(&maison) {
        return Ok((maison, r.to_path_buf()));
    }
    Err(hors())
}

/// Ouvre `chemin` élément par élément depuis son dossier de départ, sans suivre de lien, en jugeant chacun.
fn ouvrir(chemin: &Path) -> Result<Bout, String> {
    let (base, relatif) = depart(chemin)?;
    ouvrir_sous(&base, &relatif)
}

fn ouvrir_sous(base: &Path, relatif: &Path) -> Result<Bout, String> {
    let compte = crate::socle::euid();
    let mut ou = String::from("~");
    let noms: Vec<&OsStr> = relatif
        .components()
        .map(|c| match c {
            Component::Normal(n) => Ok(n),
            _ => Err(trf!("{ou} : chemin inattendu", "{ou}: unexpected path")),
        })
        .collect::<Result<_, _>>()?;
    let juger = |f: &File, ou: &str, dossier: bool| -> Result<std::fs::Metadata, String> {
        let m = f
            .metadata()
            .map_err(|e| trf!("{ou} : illisible ({e})", "{ou}: unreadable ({e})"))?;
        if m.uid() != compte {
            return Err(trf!(
                "{ou} appartient à un autre compte",
                "{ou} belongs to another account"
            ));
        }
        if dossier && !m.is_dir() {
            return Err(trf!("{ou} n'est pas un dossier", "{ou} is not a folder"));
        }
        Ok(m)
    };
    let lien = |e: &io::Error, ou: &str| -> String {
        match e.raw_os_error() {
            Some(libc::ELOOP | libc::ENOTDIR) => trf!(
                "{ou} est un lien ou n'est pas un dossier : rien n'est suivi",
                "{ou} is a link or not a folder: nothing is followed"
            ),
            Some(libc::ENOENT) => trf!("{ou} a disparu", "{ou} has disappeared"),
            Some(libc::EACCES) => trf!(
                "{ou} n'est pas lisible par le compte : ses droits ne sont pas touchés",
                "{ou} is not readable by the account: its permissions are not touched"
            ),
            _ => trf!("{ou} : ouverture impossible ({e})", "{ou}: cannot open ({e})"),
        }
    };
    let Some((dernier, milieu)) = noms.split_last() else {
        // Le dossier personnel lui-même.
        let f = ouvrir_chemin(base, BOUT | libc::O_DIRECTORY).map_err(|e| lien(&e, &ou))?;
        let m = juger(&f, &ou, true)?;
        return Ok(Bout {
            mode: m.mode() & 0o7777,
            fichier: f,
            ou,
        });
    };
    let mut courant = ouvrir_chemin(base, TRAVERSE).map_err(|e| lien(&e, &ou))?;
    juger(&courant, &ou, true)?;
    for nom in milieu {
        ou = suivant(&ou, nom)?;
        courant = un_element(courant.as_fd(), nom, TRAVERSE).map_err(|e| lien(&e, &ou))?;
        juger(&courant, &ou, true)?;
    }
    ou = suivant(&ou, dernier)?;
    let f = un_element(courant.as_fd(), dernier, BOUT).map_err(|e| lien(&e, &ou))?;
    let m = juger(&f, &ou, false)?;
    if m.is_file() {
        if m.nlink() > 1 {
            return Err(trf!(
                "{ou} a un autre nom ailleurs (lien physique), dont les droits changeraient aussi",
                "{ou} has another name elsewhere (hard link), whose permissions would change too"
            ));
        }
    } else if !m.is_dir() {
        return Err(trf!("{ou} n'est pas un simple fichier", "{ou} is not a plain file"));
    }
    Ok(Bout {
        mode: m.mode() & 0o7777,
        fichier: f,
        ou,
    })
}

/// « ~/a » suivi de `nom`, refusé s'il n'est pas lisible tel quel (UTF-8) : le geste l'écrit en texte.
fn suivant(ou: &str, nom: &OsStr) -> Result<String, String> {
    let montre = crate::ui::affichable(&nom.to_string_lossy());
    let ou = format!("{ou}/{montre}");
    if nom.to_str().is_none() {
        return Err(trf!(
            "le nom de {ou} n'est pas lisible tel quel (pas en UTF-8)",
            "the name of {ou} cannot be read as is (not UTF-8)"
        ));
    }
    Ok(ou)
}

/// Les droits lus sur un descripteur ouvert.
fn mode_de(f: &File) -> io::Result<u32> {
    Ok(f.metadata()?.mode() & 0o7777)
}

/// Le dossier de départ, par son chemin absolu (déjà simple : `maison_simple`), le dernier élément sans suivre de lien.
fn ouvrir_chemin(base: &Path, drapeaux: i32) -> io::Result<File> {
    let relatif = base
        .strip_prefix("/")
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if relatif.as_os_str().is_empty() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // Les parents du départ se résolvent comme pour le système (un /home lien vers un autre disque est permis) ;
    // seul son dernier élément ne doit pas être un lien.
    let (Some(parent), Some(nom)) = (relatif.parent(), relatif.file_name()) else {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    };
    // O_PATH : un parent qu'on traverse sans pouvoir le lister (/home en 711) s'ouvre aussi.
    let dossier = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(Path::new("/").join(parent))?
    };
    un_element(dossier.as_fd(), nom, drapeaux)
}

/// Un seul nom sous `dans`, par openat.
// FFI de libc : openat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel ; le descripteur rendu est
// pris par OwnedFd ici même.
#[allow(unsafe_code)]
fn un_element(dans: BorrowedFd<'_>, nom: &OsStr, drapeaux: i32) -> io::Result<File> {
    let nom = CString::new(nom.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `nom` est à nous, vivant pendant l'appel ; `dans` est un descripteur ouvert, emprunté pendant l'appel ;
    // aucun mode n'est passé (pas d'O_CREAT).
    let r = unsafe { libc::openat(dans.as_raw_fd(), nom.as_ptr(), drapeaux) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: un résultat ≥ 0 est un descripteur neuf, à nous seuls.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(r) }))
}

/// fchmod sur le descripteur jugé.
// FFI de libc : fchmod sur un descripteur ouvert, emprunté pendant l'appel.
#[allow(unsafe_code)]
fn fchmod(f: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    let mode = libc::mode_t::try_from(mode).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `f` est un descripteur ouvert, emprunté pendant l'appel ; fchmod ne touche aucune mémoire à nous.
    let r = unsafe { libc::fchmod(f.as_raw_fd(), mode) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dossier(nom: &str) -> PathBuf {
        let d = crate::essais::temporaire().join(format!("vanguard-droits-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("a")).unwrap();
        d
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn lit_et_pose_sur_le_descripteur() {
        let d = dossier("pose");
        let f = d.join("a/f");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(lire(&f), Ok(0o644));
        assert_eq!(poser(&f, 0o600), Ok(0o644));
        assert_eq!(mode(&f), 0o600);
        assert_eq!(poser(&f, 0o600), Ok(0o600));
        // Un dossier aussi.
        std::fs::set_permissions(d.join("a"), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(poser(&d.join("a"), 0o700), Ok(0o755));
        assert_eq!(mode(&d.join("a")), 0o700);
        // Ni setuid ni setgid, ni plus que des droits.
        assert!(poser(&f, 0o4600).is_err());
        assert!(poser(&f, 0o2600).is_err());
        assert!(poser(&f, 0o10600).is_err());
        assert_eq!(mode(&f), 0o600);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuse_un_lien_a_chaque_element() {
        let d = dossier("liens");
        std::fs::write(d.join("a/f"), b"x").unwrap();
        std::fs::set_permissions(d.join("a/f"), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(d.join("a"), d.join("lien")).unwrap();
        std::os::unix::fs::symlink(d.join("a/f"), d.join("a/lf")).unwrap();
        for refuse in ["lien/f", "a/lf", "lien"] {
            assert!(lire(&d.join(refuse)).is_err(), "{refuse}");
            assert!(poser(&d.join(refuse), 0o600).is_err(), "{refuse}");
        }
        assert_eq!(mode(&d.join("a/f")), 0o644);
        // Le départ lui-même par un lien.
        let ailleurs = crate::essais::temporaire().join(format!("vanguard-droits-ailleurs-{}", std::process::id()));
        let _ = std::fs::remove_file(&ailleurs);
        std::os::unix::fs::symlink(&d, &ailleurs).unwrap();
        assert!(ouvrir_sous(&ailleurs, Path::new("a/f")).is_err());
        assert!(ouvrir_sous(&ailleurs, Path::new("")).is_err());
        assert!(ouvrir_sous(&d, Path::new("a/f")).is_ok());
        let _ = std::fs::remove_file(&ailleurs);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuse_lien_physique_tube_remontee_et_hors_maison() {
        let d = dossier("sortes");
        std::fs::write(d.join("a/f"), b"x").unwrap();
        std::fs::hard_link(d.join("a/f"), d.join("a/g")).unwrap();
        let e = lire(&d.join("a/f")).unwrap_err();
        assert!(e.contains("lien physique") || e.contains("hard link"), "{e}");
        // Ni un tube au bout (ouvert sans attendre : O_NONBLOCK).
        crate::essais::tube_nomme(&d.join("a/t")).unwrap();
        assert!(lire(&d.join("a/t")).is_err());
        assert!(lire(&d.join("a/../a/f")).is_err());
        assert!(lire(&d.join("a/absent")).is_err());
        assert!(lire(Path::new("/etc/passwd")).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
