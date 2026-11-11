//! Les fichiers du démarrage du compte (entrées d'autostart, unités de systemd --user), lus, écrits et retirés sans
//! suivre de lien et sans sortir du dossier personnel : la même garde que pour les droits d'un fichier du compte.
//! Le dossier personnel est ouvert sans suivre de lien sur son dernier élément (ses parents se résolvent comme pour
//! le système), puis chaque dossier du chemin par openat relativement au précédent, avec O_NOFOLLOW : un
//! `~/.config` ou un `~/.config/autostart` qui est un lien (vers des dotfiles, ou hors du dossier personnel) n'est
//! pas suivi, et l'entrée n'est ni proposée ni écrite. Chaque dossier est jugé sur ce qui a été ouvert (fstat) :
//! un dossier du compte qui agit. Le fichier s'écrit dans un temporaire créé sous le dossier ouvert puis renommé à sa
//! place dans ce même dossier (renameat), et se retire par unlinkat : entre le jugement et le geste, rien ne se
//! résout plus par le nom.

#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use crate::trf;

/// Un dossier traversé : sans le lire, sans suivre de lien.
const TRAVERSE: i32 = libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
/// Le fichier visé, regardé sans l'ouvrir ni suivre de lien : un lien s'y voit comme lien.
const REGARD: i32 = libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC;
/// Le fichier visé, lu sans attendre (un tube mis à sa place), sans devenir le terminal du programme.
const LECTURE: i32 = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
/// Le temporaire : neuf, jamais par-dessus un nom déjà là, jamais à travers un lien.
const TEMPORAIRE: i32 = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;

/// Le dossier qui contient le fichier visé, ouvert et jugé, avec le nom du fichier et sa forme montrée (« ~/… »,
/// jamais le chemin du dossier personnel).
struct Dossier {
    fd: File,
    nom: CString,
    ou: String,
}

/// Le dossier de départ (le dossier personnel, ou dans les essais leur dossier jetable) et les noms sous lui.
fn depart(chemin: &Path) -> Result<(PathBuf, Vec<&OsStr>), String> {
    let hors = || {
        trf!(
            "{} n'est pas dans le dossier personnel : Vanguard n'y touche pas",
            "{} is not in the home folder: Vanguard does not touch it",
            crate::modele::resultat::nom_sans_piege(&chemin.to_string_lossy(), 120)
        )
    };
    // Les essais d'abord : leur dossier jetable peut être sous le vrai dossier personnel, derrière un lien.
    #[cfg(test)]
    let essais = Some(crate::essais::temporaire());
    #[cfg(not(test))]
    let essais: Option<PathBuf> = None;
    for base in essais.into_iter().chain(std::iter::once(crate::socle::maison())) {
        let Some(base) = simple(&base) else {
            continue;
        };
        if let Ok(reste) = chemin.strip_prefix(&base) {
            let noms = reste
                .components()
                .map(|c| match c {
                    Component::Normal(n) => Some(n),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(hors)?;
            return if noms.is_empty() { Err(hors()) } else { Ok((base, noms)) };
        }
    }
    Err(hors())
}

/// Le chemin absolu sans « . » ni « / » en trop (un « / » final ferait suivre le lien du dernier élément) ; `None`
/// pour un chemin relatif ou qui remonte.
fn simple(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut s = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::Normal(_) => s.push(c),
            _ => return None,
        }
    }
    Some(s)
}

/// « ~/a » suivi de `nom`, nettoyé pour l'écran.
fn suivant(ou: &str, nom: &OsStr) -> String {
    format!("{ou}/{}", crate::ui::affichable(&nom.to_string_lossy()))
}

/// La phrase d'un dossier ou d'un fichier qui ne s'ouvre pas sans suivre de lien.
fn phrase(e: &io::Error, ou: &str) -> String {
    match e.raw_os_error() {
        Some(libc::ELOOP | libc::ENOTDIR) => trf!(
            "{ou} est un lien ou n'est pas un dossier : Vanguard ne le suit pas (géré ailleurs, par des dotfiles par \
             exemple) et n'y touche pas",
            "{ou} is a link or not a folder: Vanguard does not follow it (managed elsewhere, by dotfiles for \
             instance) and does not touch it"
        ),
        _ => trf!("{ou} : ouverture impossible ({e})", "{ou}: cannot open ({e})"),
    }
}

/// Un dossier ouvert est-il un dossier du compte qui agit ?
fn juger_dossier(f: &File, ou: &str) -> Result<(), String> {
    let m = f
        .metadata()
        .map_err(|e| trf!("{ou} : illisible ({e})", "{ou}: unreadable ({e})"))?;
    if m.uid() != crate::socle::euid() {
        return Err(trf!(
            "{ou} appartient à un autre compte : Vanguard n'y touche pas",
            "{ou} belongs to another account: Vanguard does not touch it"
        ));
    }
    if !m.is_dir() {
        return Err(trf!("{ou} n'est pas un dossier", "{ou} is not a folder"));
    }
    Ok(())
}

/// Ouvre les dossiers du chemin, du dossier personnel jusqu'à celui du fichier. `creer` : un dossier manquant est
/// créé (droits par défaut du compte, comme `create_dir_all`) ; sinon, `None` dit qu'il manque (le fichier n'existe
/// donc pas).
fn parcourir(chemin: &Path, creer: bool) -> Result<Option<Dossier>, String> {
    let (base, noms) = depart(chemin)?;
    let Some((dernier, milieu)) = noms.split_last() else {
        return Err(trf!("chemin vide", "empty path"));
    };
    let mut ou = String::from("~");
    let mut courant = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(TRAVERSE)
            .open(&base)
            .map_err(|e| phrase(&e, &ou))?
    };
    juger_dossier(&courant, &ou)?;
    for nom in milieu {
        ou = suivant(&ou, nom);
        let c = c_nom(nom).map_err(|e| phrase(&e, &ou))?;
        courant = match ouvrir_a(courant.as_fd(), &c, TRAVERSE, 0) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound && !creer => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                match creer_dossier(courant.as_fd(), &c) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(e) => return Err(trf!("{ou} : création impossible ({e})", "{ou}: cannot create ({e})")),
                }
                ouvrir_a(courant.as_fd(), &c, TRAVERSE, 0).map_err(|e| phrase(&e, &ou))?
            }
            Err(e) => return Err(phrase(&e, &ou)),
        };
        juger_dossier(&courant, &ou)?;
    }
    ou = suivant(&ou, dernier);
    let nom = c_nom(dernier).map_err(|e| phrase(&e, &ou))?;
    Ok(Some(Dossier { fd: courant, nom, ou }))
}

/// Le fichier visé, regardé sans le suivre : `None` s'il n'existe pas ; refusé s'il est un lien, autre chose qu'un
/// simple fichier ou à un autre compte.
fn regarder(d: &Dossier) -> Result<Option<()>, String> {
    let ou = &d.ou;
    let f = match ouvrir_a(d.fd.as_fd(), &d.nom, REGARD, 0) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(phrase(&e, ou)),
    };
    let m = f
        .metadata()
        .map_err(|e| trf!("{ou} : illisible ({e})", "{ou}: unreadable ({e})"))?;
    if m.file_type().is_symlink() {
        return Err(trf!(
            "{ou} est un lien : Vanguard ne le suit pas (géré ailleurs, par des dotfiles par exemple) et n'y touche pas",
            "{ou} is a link: Vanguard does not follow it (managed elsewhere, by dotfiles for instance) and does not \
             touch it"
        ));
    }
    if !m.is_file() {
        return Err(trf!("{ou} n'est pas un simple fichier", "{ou} is not a plain file"));
    }
    if m.uid() != crate::socle::euid() {
        return Err(trf!(
            "{ou} appartient à un autre compte : Vanguard n'y touche pas",
            "{ou} belongs to another account: Vanguard does not touch it"
        ));
    }
    Ok(Some(()))
}

/// Vanguard peut-il écrire ou retirer `chemin` ? Chaque dossier qui existe est un vrai dossier du compte (pas un lien),
/// le fichier, s'il existe, un simple fichier du compte ; ce qui manque se créera. Une entrée qui ne passe pas n'est
/// pas proposée : rien ne s'écrirait ailleurs que dans le dossier personnel, ni à travers un lien.
pub(super) fn juger(chemin: &Path) -> Result<(), String> {
    if let Some(d) = parcourir(chemin, false)? {
        regarder(&d)?;
    }
    Ok(())
}

/// Le texte de `chemin`, d'au plus `max` octets, lu sur le fichier ouvert sans suivre de lien. `NotFound` s'il
/// n'existe pas (lui ou un de ses dossiers) ; `InvalidData` s'il n'est pas un simple fichier, trop gros ou pas en
/// UTF-8 ; une autre erreur si la garde le refuse.
pub(super) fn lire(chemin: &Path, max: u64) -> io::Result<String> {
    let d = parcourir(chemin, false)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let f = ouvrir_a(d.fd.as_fd(), &d.nom, LECTURE, 0)?;
    let m = f.metadata()?;
    if !m.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, d.ou));
    }
    if m.uid() != crate::socle::euid() {
        return Err(io::Error::other(d.ou));
    }
    let mut octets = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut octets)?;
    if u64::try_from(octets.len()).map_or(true, |n| n > max) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, d.ou));
    }
    String::from_utf8(octets).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Écrit `contenu` à la place de `chemin` : temporaire neuf dans le dossier ouvert, forcé sur le disque, puis
/// renommé à sa place dans ce même dossier. Les dossiers manquants sont créés sous le dossier personnel.
pub(super) fn ecrire(chemin: &Path, contenu: &[u8]) -> Result<(), String> {
    if crate::autotest::lecture_seule::refuse_fichier(chemin) {
        return Err(crate::autotest::lecture_seule::refus().to_string());
    }
    let d = parcourir(chemin, true)?.ok_or_else(|| trf!("chemin vide", "empty path"))?;
    regarder(&d)?;
    let ou = &d.ou;
    let mut sel = [0u8; 8];
    getrandom::fill(&mut sel).map_err(|e| trf!("{ou} : {e}", "{ou}: {e}"))?;
    let temporaire = CString::new(format!(
        ".vanguard-demarrage-{}-{:016x}.tmp",
        std::process::id(),
        u64::from_le_bytes(sel)
    ))
    .map_err(|e| trf!("{ou} : {e}", "{ou}: {e}"))?;
    let mut f = ouvrir_a(d.fd.as_fd(), &temporaire, TEMPORAIRE, 0o666)
        .map_err(|e| trf!("{ou} : écriture impossible ({e})", "{ou}: cannot write ({e})"))?;
    let r = f
        .write_all(contenu)
        .and_then(|()| f.sync_all())
        .and_then(|()| renommer(d.fd.as_fd(), &temporaire, &d.nom));
    if let Err(e) = r {
        let _ = effacer(d.fd.as_fd(), &temporaire);
        return Err(trf!("{ou} : écriture impossible ({e})", "{ou}: cannot write ({e})"));
    }
    Ok(())
}

/// Retire `chemin` s'il existe (un simple fichier du compte) ; absent, rien à faire.
pub(super) fn retirer(chemin: &Path) -> Result<(), String> {
    if crate::autotest::lecture_seule::refuse_fichier(chemin) {
        return Err(crate::autotest::lecture_seule::refus().to_string());
    }
    let Some(d) = parcourir(chemin, false)? else {
        return Ok(());
    };
    if regarder(&d)?.is_none() {
        return Ok(());
    }
    match effacer(d.fd.as_fd(), &d.nom) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => {
            let ou = &d.ou;
            Err(trf!("{ou} : retrait impossible ({e})", "{ou}: cannot remove ({e})"))
        }
    }
}

fn c_nom(nom: &OsStr) -> io::Result<CString> {
    CString::new(nom.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// Un seul nom sous `dans`, par openat ; `mode` ne sert qu'avec O_CREAT.
// FFI de libc : openat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel ; le descripteur rendu est
// pris par OwnedFd ici même.
#[allow(unsafe_code)]
fn ouvrir_a(dans: BorrowedFd<'_>, nom: &CStr, drapeaux: i32, mode: libc::c_uint) -> io::Result<File> {
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dans` est un descripteur ouvert,
    // emprunté pendant l'appel ; le mode, entier passé par valeur, n'est lu qu'avec O_CREAT.
    let r = unsafe { libc::openat(dans.as_raw_fd(), nom.as_ptr(), drapeaux, mode) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: un résultat ≥ 0 est un descripteur neuf, à nous seuls.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(r) }))
}

/// mkdirat sous `dans`, droits par défaut du compte (0777 moins son umask).
// FFI de libc : mkdirat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn creer_dossier(dans: BorrowedFd<'_>, nom: &CStr) -> io::Result<()> {
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dans` est un descripteur ouvert,
    // emprunté pendant l'appel.
    let r = unsafe { libc::mkdirat(dans.as_raw_fd(), nom.as_ptr(), 0o777) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// renameat de `de` vers `vers`, tous deux sous `dans` : le nom remplacé ne se suit pas, même s'il est un lien.
// FFI de libc : renameat sur un descripteur ouvert, avec deux noms en C vivants pendant l'appel.
#[allow(unsafe_code)]
fn renommer(dans: BorrowedFd<'_>, de: &CStr, vers: &CStr) -> io::Result<()> {
    let fd = dans.as_raw_fd();
    // SAFETY: `de` et `vers` sont des chaînes C à l'appelant, vivantes pendant l'appel ; `fd` est un descripteur
    // ouvert, emprunté pendant l'appel.
    let r = unsafe { libc::renameat(fd, de.as_ptr(), fd, vers.as_ptr()) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// unlinkat d'un fichier sous `dans` (jamais un dossier) : un lien s'y retire lui-même, sans être suivi.
// FFI de libc : unlinkat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn effacer(dans: BorrowedFd<'_>, nom: &CStr) -> io::Result<()> {
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dans` est un descripteur ouvert,
    // emprunté pendant l'appel.
    let r = unsafe { libc::unlinkat(dans.as_raw_fd(), nom.as_ptr(), 0) };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn dossier(nom: &str) -> crate::essais::Jetable {
        crate::essais::Jetable::nouveau(&format!("sous-maison-{nom}"))
    }

    #[test]
    fn ecrit_lit_et_retire_sous_la_maison() {
        let d = dossier("simple");
        let f = d.join(".config/autostart/note.desktop");
        assert!(juger(&f).is_ok(), "les dossiers manquants se créeront");
        assert_eq!(lire(&f, 100).unwrap_err().kind(), io::ErrorKind::NotFound);
        ecrire(&f, b"[Desktop Entry]\n").unwrap();
        assert_eq!(lire(&f, 100).unwrap(), "[Desktop Entry]\n");
        assert_eq!(lire(&f, 3).unwrap_err().kind(), io::ErrorKind::InvalidData);
        ecrire(&f, b"autre").unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "autre");
        retirer(&f).unwrap();
        assert!(!f.exists());
        retirer(&f).unwrap();
        // Aucun temporaire laissé.
        assert_eq!(std::fs::read_dir(d.join(".config/autostart")).unwrap().count(), 0);
    }

    #[test]
    fn un_dossier_lien_n_est_ni_suivi_ni_ecrit() {
        let d = dossier("lien");
        let ailleurs = dossier("ailleurs");
        std::fs::create_dir_all(d.join(".config")).unwrap();
        std::fs::write(ailleurs.join("note.desktop"), "dehors").unwrap();
        // ~/.config/autostart lien vers un autre dossier ; puis ~/.config lui-même.
        std::os::unix::fs::symlink(&*ailleurs, d.join(".config/autostart")).unwrap();
        let f = d.join(".config/autostart/note.desktop");
        let e = juger(&f).unwrap_err();
        assert!(
            e.starts_with("~/") && e.contains("/.config/autostart est un lien") && !e.contains(&*d.to_string_lossy()),
            "{e}"
        );
        assert!(lire(&f, 100).is_err());
        assert!(ecrire(&f, b"Hidden=true").is_err());
        assert!(retirer(&f).is_err());
        let d2 = dossier("lien-config");
        std::os::unix::fs::symlink(&*ailleurs, d2.join(".config")).unwrap();
        std::fs::create_dir_all(ailleurs.join("autostart")).unwrap();
        let f2 = d2.join(".config/autostart/note.desktop");
        assert!(juger(&f2).is_err());
        assert!(ecrire(&f2, b"Hidden=true").is_err());
        assert_eq!(
            std::fs::read_to_string(ailleurs.join("note.desktop")).unwrap(),
            "dehors"
        );
        assert!(!ailleurs.join("autostart/note.desktop").exists());
    }

    #[test]
    fn un_fichier_lien_tube_ou_hors_maison_refuse() {
        let d = dossier("bout");
        let ailleurs = dossier("bout-ailleurs");
        let a = d.join(".config/autostart");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(ailleurs.join("x.desktop"), "dehors").unwrap();
        std::os::unix::fs::symlink(ailleurs.join("x.desktop"), a.join("lien.desktop")).unwrap();
        assert!(juger(&a.join("lien.desktop")).is_err());
        assert!(ecrire(&a.join("lien.desktop"), b"Hidden=true").is_err());
        assert!(retirer(&a.join("lien.desktop")).is_err());
        assert!(
            a.join("lien.desktop")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(ailleurs.join("x.desktop")).unwrap(), "dehors");
        crate::essais::tube_nomme(&a.join("tube.desktop")).unwrap();
        assert!(juger(&a.join("tube.desktop")).is_err());
        assert!(lire(&a.join("tube.desktop"), 100).is_err());
        // Hors du dossier personnel et des essais, ou qui remonte : refusé avant toute ouverture.
        assert!(juger(Path::new("/etc/xdg/autostart/x.desktop")).is_err());
        assert!(juger(&a.join("../../../x.desktop")).is_err());
        assert!(ecrire(Path::new("/nulle-part/x.desktop"), b"x").is_err());
    }
}
