//! Le dossier personnel du compte, et la place sur les disques : lus par le nettoyage d'abord, d'où leur ancienne
//! place dans `nettoyer`, mais demandés partout (bilan, traces d'incident, protection, Gaming). Le dossier
//! personnel était relu dans une quarantaine d'endroits, chacun avec sa règle quand HOME manque.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]
// FFI de libc : getpwuid_r et statvfs.
#![allow(unsafe_code)]

use std::path::{Path, PathBuf};

use crate::{tr, trf};

/// Un mégaoctet : en dessous, « moins de 1 Mo ».
const MEGA: u64 = 1 << 20;

/// Le dossier personnel du compte : HOME quand c'est un chemin complet, sinon (HOME vide, relatif ou absent : un
/// service, un `env -i`) celui que la base des comptes donne au compte, sous Linux ; sous Windows,
/// USERPROFILE quand HOME manque. `None` : aucun des deux, jamais un chemin vide, qui se lirait depuis le dossier
/// courant. Écrit d'une seule façon (`normalise`).
pub(crate) fn dossier_personnel() -> Option<PathBuf> {
    #[cfg(unix)]
    let repli = || dossier_personnel_de(crate::socle::uid());
    #[cfg(windows)]
    let repli = || std::env::var_os("USERPROFILE").map(PathBuf::from);
    dossier_personnel_selon(std::env::var_os("HOME"), repli)
}

/// `dossier_personnel` d'après une valeur de HOME et un `repli` : HOME s'il est complet, sinon le `repli` ; écrit
/// d'une seule façon (`normalise`). R4-5, N5-8 (revérifications des rondes 4 et 5 du lot 0.95) : « /home/alice/ »,
/// « /home//alice », « /home/./alice » ou « /home/alice/. » (HOME de l'environnement ou de /etc/passwd) ne
/// ressemblaient plus à « /home/alice » pour les comparaisons de texte du bilan (« {maison}/ ») : un programme dans un
/// dossier caché du dossier personnel n'était plus dit caché. Un HOME complet avec « .. » : `None`, sans repli (ce
/// qu'il désigne dépend des liens du disque ; il n'est pas deviné, le bilan dit le dossier personnel inconnu).
fn dossier_personnel_selon(
    home: Option<std::ffi::OsString>,
    repli: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    match home.map(PathBuf::from) {
        Some(h) if h.is_absolute() => normalise(&h),
        _ => repli().filter(|d| d.is_absolute()).and_then(|d| normalise(&d)),
    }
}

/// Un chemin complet écrit d'une seule façon, sans toucher au disque : « / » doublés, « . » et « / » finaux retirés
/// (« /home//./alice/. » → « /home/alice ») ; la racine reste « / ». `None` : relatif, ou avec « .. », que seul le
/// disque résout (un lien peut mener ailleurs), jamais deviné. Sous Windows : le chemin tel quel s'il est complet
/// (pas relu ici).
fn normalise(d: &Path) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::path::Component;
        let mut sortie = PathBuf::new();
        for morceau in d.components() {
            match morceau {
                Component::RootDir => sortie.push("/"),
                Component::Normal(n) => sortie.push(n),
                Component::CurDir => {}
                Component::ParentDir | Component::Prefix(_) => return None,
            }
        }
        sortie.is_absolute().then_some(sortie)
    }
    #[cfg(not(unix))]
    {
        d.is_absolute().then(|| d.to_path_buf())
    }
}

/// `dossier_personnel`, pour qui y joint un sous-dossier et lit ce qui s'y trouve : un chemin vide quand il n'y en a
/// aucun (ce que faisaient toutes les copies), qui ne mène qu'à des lectures ratées, dites par chacun.
pub fn maison() -> PathBuf {
    dossier_personnel().unwrap_or_default()
}

/// Le dossier personnel du compte `uid`, d'après la base des comptes du système, écrit d'une seule façon
/// (`dossier_de_la_base`).
#[cfg(unix)]
pub(crate) fn dossier_personnel_de(uid: libc::uid_t) -> Option<PathBuf> {
    dossier_de_la_base(compte_de(uid))
}

/// Le dossier personnel d'une entrée de la base des comptes (`compte_de`) : complet, sans « .. », écrit d'une seule
/// façon (`normalise`, R4-5, N5-8) ; `None` sinon.
#[cfg(unix)]
fn dossier_de_la_base(compte: Option<(std::ffi::OsString, PathBuf)>) -> Option<PathBuf> {
    compte.and_then(|(_, dossier)| normalise(&dossier))
}

/// Le nom et le dossier personnel du compte `uid`, d'après la base des comptes du système (getpwuid_r) : ce que
/// `commande::environnement_propre` donne pour HOME, USER et LOGNAME, au lieu de les prendre d'un environnement qu'un
/// programme du compte a pu écrire.
#[cfg(unix)]
pub(crate) fn compte_de(uid: libc::uid_t) -> Option<(std::ffi::OsString, PathBuf)> {
    use std::os::unix::ffi::OsStrExt;
    let mut tampon: Vec<libc::c_char> = vec![0; 16 << 10];
    // SAFETY: passwd n'a que des entiers et des pointeurs, valides à zéro ; getpwuid_r les remplit.
    let mut compte: libc::passwd = unsafe { std::mem::zeroed() };
    let mut trouve: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: `compte`, `tampon` (avec sa vraie longueur) et `trouve` vivent jusqu'à la fin de la fonction ;
    // getpwuid_r n'écrit que dans eux.
    let r = unsafe { libc::getpwuid_r(uid, &raw mut compte, tampon.as_mut_ptr(), tampon.len(), &raw mut trouve) };
    if r != 0 || trouve.is_null() || compte.pw_dir.is_null() || compte.pw_name.is_null() {
        return None;
    }
    // SAFETY: pw_dir et pw_name pointent dans `tampon`, encore vivant, et getpwuid_r les a terminés par un zéro.
    let (dossier, nom) = unsafe {
        (
            std::ffi::CStr::from_ptr(compte.pw_dir),
            std::ffi::CStr::from_ptr(compte.pw_name),
        )
    };
    Some((
        std::ffi::OsStr::from_bytes(nom.to_bytes()).to_os_string(),
        PathBuf::from(std::ffi::OsStr::from_bytes(dossier.to_bytes())),
    ))
}

/// « 1.2 Go », « 340 Mo ».
pub fn taille_lisible(octets: u64) -> String {
    #[allow(clippy::cast_precision_loss)] // une taille affichée à un chiffre après la virgule
    let f = crate::socle::nombres::flottant(octets);
    if octets >= 1 << 30 {
        trf!("{} Go", "{} GB", crate::langue::decimal(f / f64::from(1u32 << 30), 1))
    } else if octets >= MEGA {
        trf!("{:.0} Mo", "{:.0} MB", f / f64::from(1u32 << 20))
    } else {
        tr!("moins de 1 Mo", "less than 1 MB").into()
    }
}

/// Le volume qui contient `chemin`, vu par statvfs.
#[cfg(unix)]
pub(crate) fn statvfs(chemin: &Path) -> Option<libc::statvfs> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(chemin.as_os_str().as_bytes()).ok()?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` est une chaîne C valide pendant tout l'appel ; statvfs remplit `s` en entier quand elle réussit
    // (retour 0), et `s` n'est lue qu'après.
    unsafe {
        if libc::statvfs(c.as_ptr(), s.as_mut_ptr()) != 0 {
            return None;
        }
        Some(s.assume_init())
    }
}

/// Place libre et taille du volume qui contient `chemin`, en octets.
#[cfg(unix)]
pub fn volume(chemin: &Path) -> Option<(u64, u64)> {
    let s = statvfs(chemin)?;
    #[allow(clippy::useless_conversion)] // les types de statvfs changent d'un système à l'autre
    let bloc = u64::from(s.f_frsize);
    // Plafonnés comme les tailles de fichiers : un volume réseau ou FUSE (sshfs) dit ce que son serveur veut.
    #[allow(clippy::useless_conversion)]
    Some((
        u64::from(s.f_bavail).saturating_mul(bloc),
        u64::from(s.f_blocks).saturating_mul(bloc),
    ))
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dossier_personnel_toujours_complet() {
        // Les tests tournent sous un vrai compte : HOME ou la base des comptes donne un chemin complet.
        assert!(dossier_personnel().is_some_and(|d| d.is_absolute()));
        assert_eq!(maison(), dossier_personnel().unwrap());
    }

    /// R4-5, N5-8 (revérifications des rondes 4 et 5 du lot 0.95) : un dossier personnel écrit autrement
    /// (« / » final ou doublé, « /./ », « /. » final), par HOME ou par la base des comptes, se lit d'une seule façon :
    /// les comparaisons de texte du bilan (« {maison}/ ») le reconnaissent. Avec « .. » : `None`, jamais deviné, même
    /// quand la base des comptes donnerait un chemin. Valeurs inventées.
    #[cfg(unix)]
    #[test]
    fn dossier_personnel_ecrit_d_une_seule_facon() {
        // Comparé en texte : deux PathBuf « /home/alice/ » et « /home/alice » sont égaux (par morceaux), alors que
        // le bilan compare leur texte.
        let os = |s: &str| Some(std::ffi::OsString::from(s));
        let texte = |d: Option<PathBuf>| d.map(PathBuf::into_os_string);
        let rien = || None;
        let alice = os("/home/alice");
        let formes = [
            "/home/alice",
            "/home/alice/",
            "/home/alice///",
            "/home//alice",
            "//home/alice",
            "/home/./alice",
            "/home/alice/.",
            "/home/alice/./",
            "/./home/alice",
        ];
        for forme in formes {
            // Source 1 : HOME de l'environnement.
            assert_eq!(texte(dossier_personnel_selon(os(forme), rien)), alice, "HOME={forme}");
            // Source 2 : la base des comptes (HOME absent, vide ou relatif).
            let compte = || Some((std::ffi::OsString::from("alice"), PathBuf::from(forme)));
            assert_eq!(texte(dossier_de_la_base(compte())), alice, "base des comptes : {forme}");
            let base = || dossier_de_la_base(compte());
            assert_eq!(texte(dossier_personnel_selon(None, base)), alice, "repli : {forme}");
            assert_eq!(
                texte(dossier_personnel_selon(os(""), base)),
                alice,
                "HOME vide : {forme}"
            );
            assert_eq!(
                texte(dossier_personnel_selon(os("alice/"), base)),
                alice,
                "HOME relatif : {forme}"
            );
        }
        assert_eq!(texte(dossier_personnel_selon(os("/"), rien)), os("/"));
        assert_eq!(texte(dossier_personnel_selon(os("//./"), rien)), os("/"));
        // « .. » : jamais deviné, ni par HOME (sans repli) ni par la base des comptes.
        let base_saine = || Some(PathBuf::from("/home/alice"));
        for forme in ["/home/x/../alice", "/home/alice/..", "/../home/alice"] {
            assert_eq!(dossier_personnel_selon(os(forme), base_saine), None, "HOME={forme}");
            let compte = Some((std::ffi::OsString::from("alice"), PathBuf::from(forme)));
            assert_eq!(dossier_de_la_base(compte), None, "base des comptes : {forme}");
        }
        assert_eq!(dossier_personnel_selon(None, || Some(PathBuf::from("rel/"))), None);
        assert_eq!(
            dossier_de_la_base(Some((std::ffi::OsString::from("alice"), PathBuf::from("rel")))),
            None
        );
        assert_eq!(dossier_de_la_base(None), None);
    }

    #[test]
    fn tailles_lisibles() {
        assert_eq!(taille_lisible(0), "moins de 1 Mo");
        assert_eq!(taille_lisible(340 << 20), "340 Mo");
        assert_eq!(taille_lisible(3 << 29), "1,5 Go");
    }
}
