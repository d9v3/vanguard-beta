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
/// dossier caché du dossier personnel n'était plus dit caché. N6-4 (revérification de la ronde 6) : un HOME complet
/// avec « .. » n'est pas deviné (ce qu'il désigne dépend des liens du disque) ; le `repli` le remplace, comme un HOME
/// relatif. Avant, `None` faisait de `maison` un chemin vide, lu depuis le dossier courant par qui y joint
/// « .config/… ». Le bilan dit encore un HOME de la session avec « .. » (persistance).
fn dossier_personnel_selon(
    home: Option<std::ffi::OsString>,
    repli: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    home.map(PathBuf::from)
        .filter(|h| h.is_absolute())
        .and_then(|h| normalise(&h))
        .or_else(|| repli().filter(|d| d.is_absolute()).and_then(|d| normalise(&d)))
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

/// `dossier_personnel`, pour qui y joint un sous-dossier et lit ce qui s'y trouve. Quand il n'y en a aucun (ni HOME
/// ni la base des comptes ne donnent un chemin complet sans « .. ») : `MAISON_INCONNUE`, jamais vide ni relatif.
pub fn maison() -> PathBuf {
    maison_selon(dossier_personnel())
}

/// Le dossier personnel que le système donne au compte (la base des comptes ; sous Windows, FOLDERID_Profile), sans
/// HOME, que tout programme du compte réécrit : pour les lieux de la protection (un fichier temporaire ou téléchargé),
/// qu'un HOME posé sur /tmp ou sur TEMP ne doit pas effacer. Repli : `maison`.
pub(crate) fn maison_du_compte() -> PathBuf {
    #[cfg(unix)]
    let compte = dossier_personnel_de(crate::socle::uid());
    #[cfg(windows)]
    let compte = crate::machine::windows::environnement::profil().filter(|p| p.is_absolute());
    compte.unwrap_or_else(maison)
}

/// N6-4 (revérification de la ronde 6 du lot 0.95) : le dossier personnel quand il n'y en a aucun. Un chemin vide
/// (l'ancien repli) devenait relatif une fois joint à « .config/… » : lu depuis le dossier courant, où l'absence de
/// tout passait pour « rien à signaler ». Ce chemin-ci est complet et contient un octet NUL : chaque lecture,
/// écriture ou commande qui s'en sert échoue (« InvalidInput », jamais « absent »), aucune comparaison de texte ne
/// le rencontre dans un vrai chemin. `maison` a plus de cent appelants : un type à traiter par chacun ne se
/// relisait pas en une ronde ; ceux qui disent déjà « dossier personnel inconnu » le reconnaissent (`maison_inconnue`).
#[cfg(unix)]
const MAISON_INCONNUE: &str = "/\0dossier-personnel-inconnu";
#[cfg(windows)]
const MAISON_INCONNUE: &str = "C:\\\0dossier-personnel-inconnu";

/// `maison` d'après `dossier_personnel` (essais).
fn maison_selon(dossier: Option<PathBuf>) -> PathBuf {
    dossier.unwrap_or_else(|| PathBuf::from(MAISON_INCONNUE))
}

/// Le dossier personnel `maison` est-il inconnu : vide, relatif, ou `MAISON_INCONNUE` (un octet NUL) ?
pub(crate) fn maison_inconnue(maison: &Path) -> bool {
    !maison.is_absolute() || maison.as_os_str().as_encoded_bytes().contains(&0)
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
        // « .. » : jamais deviné. N6-4 : un HOME avec « .. » cède à la base des comptes, comme un HOME relatif ; une
        // base avec « .. » ne donne rien.
        let base_saine = || Some(PathBuf::from("/home/alice"));
        for forme in ["/home/x/../alice", "/home/alice/..", "/../home/alice"] {
            assert_eq!(
                texte(dossier_personnel_selon(os(forme), base_saine)),
                alice,
                "HOME={forme}"
            );
            assert_eq!(
                dossier_personnel_selon(os(forme), rien),
                None,
                "HOME={forme}, sans base"
            );
            let compte = Some((std::ffi::OsString::from("alice"), PathBuf::from(forme)));
            assert_eq!(dossier_de_la_base(compte), None, "base des comptes : {forme}");
            let base = || Some(PathBuf::from(forme));
            assert_eq!(dossier_personnel_selon(os(forme), base), None, "HOME et base : {forme}");
        }
        assert_eq!(dossier_personnel_selon(None, || Some(PathBuf::from("rel/"))), None);
        assert_eq!(
            dossier_de_la_base(Some((std::ffi::OsString::from("alice"), PathBuf::from("rel")))),
            None
        );
        assert_eq!(dossier_de_la_base(None), None);
    }

    /// N6-4 (revérification de la ronde 6 du lot 0.95) : sans dossier personnel, `maison` n'est ni vide ni relatif ;
    /// joint à un sous-dossier, il ne se lit pas depuis le dossier courant, qui a pourtant ce sous-dossier.
    #[test]
    fn maison_inconnue_jamais_relative() {
        let m = maison_selon(None);
        assert!(m.is_absolute() && !m.as_os_str().is_empty(), "{m:?}");
        assert!(maison_inconnue(&m));
        assert!(maison_inconnue(Path::new("")) && maison_inconnue(Path::new("alice")));
        assert!(!maison_inconnue(Path::new(if cfg!(windows) {
            "C:\\Users\\alice"
        } else {
            "/home/alice"
        })));
        // Le dossier courant des essais a un « src » ; sous `maison` inconnu, il ne se lit pas, ni ne passe pour
        // absent : l'erreur dit une entrée refusée.
        assert!(Path::new("src").is_dir());
        for chemin in [m.clone(), m.join("src"), m.join(".config/uwsm/env")] {
            let e = std::fs::metadata(&chemin).expect_err("lu sous un dossier personnel inconnu");
            assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{chemin:?}");
        }
        let alice = PathBuf::from("/home/alice");
        assert_eq!(maison_selon(Some(alice.clone())), alice);
    }

    #[test]
    fn tailles_lisibles() {
        assert_eq!(taille_lisible(0), "moins de 1 Mo");
        assert_eq!(taille_lisible(340 << 20), "340 Mo");
        assert_eq!(taille_lisible(3 << 29), "1,5 Go");
    }
}
