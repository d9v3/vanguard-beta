//! Les fichiers de Vanguard : son dossier sur cet ordinateur, l'écriture qui ne laisse jamais un fichier à moitié
//! écrit, le verrou entre deux Vanguard lancés en même temps. Ils servaient d'abord à la base des appareils, d'où
//! leur ancienne place dans `reseau` ; le bilan, la protection et les traces s'en servent autant, sans rien avoir à
//! faire du réseau.

use std::path::PathBuf;

use crate::tre;
use crate::ui::*;

/// Écrit d'abord un fichier temporaire, le force sur le disque, puis le renomme à la place de l'ancien :
/// une coupure, un Ctrl-C ou une clé arrachée laissent soit l'ancienne base, soit la nouvelle, jamais une
/// base tronquée.
///
/// Le temporaire porte un nom tiré au hasard et se crée sans suivre de lien, jamais par-dessus un fichier déjà là :
/// lancé en root avec le dossier d'un compte (sudo -E), un nom déductible du numéro de processus laissait ce compte
/// poser d'avance un lien vers un fichier du système, que root aurait tronqué en écrivant à travers.
pub(crate) fn ecrire_atomique(chemin: &std::path::Path, contenu: impl AsRef<[u8]>) -> std::io::Result<()> {
    ecrire_atomique_date(chemin, contenu.as_ref(), None)
}

/// `ecrire_atomique`, avec la date de modification `date` donnée au fichier avant qu'il prenne sa place : une copie
/// garde ainsi l'âge de son original (archives de tldr-pages de la clé), sans instant où elle paraîtrait neuve.
pub(crate) fn ecrire_atomique_date(
    chemin: &std::path::Path,
    contenu: &[u8],
    date: Option<std::time::SystemTime>,
) -> std::io::Result<()> {
    use std::io::Write;
    // Un nom par écriture, pas seulement par processus : deux fils qui écrivent le même fichier en même temps se
    // volaient leur fichier temporaire, et le second renommage échouait (vu dans les tests sous Wine).
    static ECRITURES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    // Pendant un autotest, aucune écriture d'état ne passe (une règle y apprendrait son « déjà vu »).
    if crate::autotest::lecture_seule::refuse_fichier(chemin) {
        return Err(crate::autotest::lecture_seule::refus());
    }
    if let Some(d) = chemin.parent() {
        std::fs::create_dir_all(d)?;
    }
    let n = ECRITURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut sel = [0u8; 8];
    getrandom::fill(&mut sel).map_err(|e| std::io::Error::other(e.to_string()))?;
    let temporaire = chemin.with_extension(format!(
        "tmp-{}-{n}-{:016x}",
        std::process::id(),
        u64::from_le_bytes(sel)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW);
    // Pas créé (un lien ou un fichier déjà là sous ce nom) : rien à retirer, ce n'est pas le nôtre.
    let mut f = options.open(&temporaire)?;
    let resultat = (|| {
        f.write_all(contenu)?;
        if let Some(date) = date {
            f.set_modified(date)?;
        }
        f.sync_all()?;
        remplacer(&temporaire, chemin)
    })();
    if resultat.is_err() {
        let _ = std::fs::remove_file(&temporaire);
    }
    resultat
}

/// Lit un fichier d'état d'au plus `max` octets, seulement s'il est un simple fichier : ni lien, ni tube nommé, ni
/// périphérique. Un tube posé à la place d'un fichier d'état figeait la lecture dans open() pour toujours (la passe
/// horaire ne finissait plus, sans rien dire) ; un fichier creux de plusieurs Gio se chargeait en entier. Ouvert sans
/// suivre de lien et sans attendre, puis jugé sur ce qui a été ouvert (fstat), pas sur le chemin : un échange entre
/// le regard et l'ouverture ne passe pas. `NotFound` s'il n'existe pas ; `InvalidData` s'il n'est pas lu pour ça.
pub(crate) fn lire_ordinaire(chemin: &std::path::Path, max: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    {
        // FILE_FLAG_OPEN_REPARSE_POINT : un lien symbolique ou une jonction s'ouvre lui-même, sans être suivi.
        std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000);
    }
    let f = options.open(chemin).map_err(|e| {
        // O_NOFOLLOW sur un lien : ELOOP, qui n'est pas « absent ».
        if e.kind() == std::io::ErrorKind::NotFound {
            e
        } else {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        }
    })?;
    let m = f.metadata()?;
    if !m.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            tr!("pas un simple fichier", "not a plain file"),
        ));
    }
    if m.len() > max {
        return Err(trop_gros(max));
    }
    let mut octets = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut octets)?;
    if octets.len() as u64 > max {
        return Err(trop_gros(max));
    }
    Ok(octets)
}

fn trop_gros(max: u64) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        trf!("plus de {} Kio", "over {} KiB", max >> 10),
    )
}

/// Vanguard peut-il écrire ses fichiers d'état dans `dossier` ? Toujours, sauf en root (Unix) : le dossier, ou
/// son plus proche parent existant, doit alors être un vrai dossier qui appartient à root. Lancé par sudo -E (HOME ou
/// XDG_DATA_HOME du compte gardés), root écrivait sinon dans le dossier d'un compte, où un programme de ce compte
/// prépare d'avance liens et fichiers.
pub(crate) fn ecriture_sure(dossier: &std::path::Path) -> bool {
    // Pendant un autotest, rien ne s'écrit (sauf ses propres fichiers, dans le fil qui les écrit).
    if crate::autotest::lecture_seule::refuse_dossier() {
        return false;
    }
    // Les tests écrivent dans leurs dossiers jetables, même lancés en root dans `unshare -r` (verifier.sh), où /tmp
    // paraît à personne : la règle elle-même s'essaie par `ecriture_sure_pour`.
    if cfg!(test) {
        return true;
    }
    #[cfg(unix)]
    {
        // SAFETY : geteuid n'a ni pointeur ni effet de bord.
        ecriture_sure_pour(unsafe { libc::geteuid() }, dossier)
    }
    #[cfg(not(unix))]
    {
        let _ = dossier;
        true
    }
}

#[cfg(unix)]
pub(crate) fn ecriture_sure_pour(euid: libc::uid_t, dossier: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    if euid != 0 {
        return true;
    }
    dossier
        .ancestors()
        .find_map(|d| std::fs::symlink_metadata(d).ok())
        .is_some_and(|m| m.file_type().is_dir() && m.uid() == 0)
}

/// Renomme `de` à la place de `vers`. Sous Windows, le remplacement échoue tant qu'un autre programme tient `vers`
/// ouvert : Defender qui analyse le fichier qu'on vient d'écrire, un autre fil qui le lit. Quelques essais
/// rapprochés (une demi-seconde au plus) plutôt qu'une écriture perdue.
fn remplacer(de: &std::path::Path, vers: &std::path::Path) -> std::io::Result<()> {
    let mut essais = 0;
    loop {
        match std::fs::rename(de, vers) {
            Err(_) if cfg!(windows) && essais < 10 => {
                essais += 1;
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            r => return r,
        }
    }
}

/// Verrou entre processus Vanguard (fichier créé de façon exclusive, retiré à la fin).
pub(crate) struct Verrou(PathBuf);

impl Verrou {
    /// Le verrou `nom` dans `dossier` (un par fichier à protéger : le journal des alertes a le sien, pris pendant
    /// qu'un autre tient celui de la base). Attend au plus 10 s. Un verrou de plus de 2 minutes vient d'un Vanguard
    /// interrompu : on le reprend.
    pub(crate) fn prendre_nomme(dossier: &std::path::Path, nom: &str) -> Option<Verrou> {
        let _ = std::fs::create_dir_all(dossier);
        let chemin = dossier.join(nom);
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&chemin) {
                Ok(_) => return Some(Verrou(chemin)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let ancien = std::fs::metadata(&chemin)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|age| age > std::time::Duration::from_secs(120));
                    if ancien {
                        let _ = std::fs::remove_file(&chemin);
                    } else if std::time::Instant::now() > fin {
                        tre!(
                            "Attention : « {nom} » occupé par un autre Vanguard, écriture sans verrou.",
                            "Warning: “{nom}” locked by another Vanguard, writing without a lock."
                        );
                        return None;
                    } else {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

impl Drop for Verrou {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Données propres à cet ordinateur (quarantaine antivirus : on ne transporte pas de malware sur une clé).
pub fn dossier_local() -> PathBuf {
    // Tests automatiques : un dossier jetable. Ils tournent sur l'ordinateur de développement : ses vraies données ne
    // doivent être ni lues ni écrites.
    if cfg!(test) {
        return dossier_des_tests();
    }
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let base = super::personnel::dossier_personnel().map(|h| h.join("Library/Application Support"));
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| super::personnel::dossier_personnel().map(|h| h.join(".local/share")));
    base.unwrap_or_default().join("vanguard")
}

/// Le dossier local réservé à son compte (0700) : il garde les bilans (donc les failles trouvées sur cet ordinateur),
/// les appareils du réseau, la quarantaine et la référence des fichiers critiques. Créé avec les droits par défaut
/// (0755), il se lisait par les autres comptes de la machine dès que le dossier personnel leur était ouvert. Un dossier
/// déjà là n'est resserré que s'il est vraiment un dossier à soi : jamais un lien, ni le dossier d'un autre compte.
#[cfg(unix)]
pub fn proteger_dossier_local() {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let dossier = dossier_local();
    let _ = std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dossier);
    // SAFETY : getuid lit le compte du processus, sans argument ni échec possible.
    let moi = unsafe { libc::getuid() };
    if let Ok(m) = std::fs::symlink_metadata(&dossier)
        && m.is_dir()
        && m.uid() == moi
        && m.mode() & 0o077 != 0
    {
        let _ = std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o700));
    }
}

/// Le dossier jetable des tests de ce processus (un par `cargo test`, nommé par son numéro de processus), retiré
/// quand le processus se termine : chaque lancement en laissait un dans le dossier temporaire. Le crochet de sortie
/// est posé une fois, au premier appel ; les tests tournent tous avant que le processus ne sorte.
fn dossier_des_tests() -> PathBuf {
    let dossier = std::env::temp_dir().join(format!("vanguard-tests-{}", std::process::id()));
    #[cfg(test)]
    {
        static CROCHET: std::sync::Once = std::sync::Once::new();
        CROCHET.call_once(|| {
            unsafe extern "C" {
                fn atexit(f: extern "C" fn()) -> i32;
            }
            extern "C" fn retirer() {
                let _ = std::fs::remove_dir_all(
                    std::env::temp_dir().join(format!("vanguard-tests-{}", std::process::id())),
                );
            }
            // SAFETY : atexit de la bibliothèque C, présent sous Linux, Windows (msvcrt) et macOS ; il reçoit une
            // fonction sans argument qui vit tout le programme, appelée une fois à la sortie normale du processus.
            unsafe { atexit(retirer) };
        });
    }
    dossier
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn dossier_local_reserve_au_compte() {
        use std::os::unix::fs::PermissionsExt;
        let dossier = dossier_local();
        std::fs::create_dir_all(&dossier).unwrap();
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755)).unwrap();
        proteger_dossier_local();
        assert_eq!(std::fs::metadata(&dossier).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn ecriture_atomique_et_verrou() {
        let dossier = std::env::temp_dir().join(format!("vanguard-atomique-{}", std::process::id()));
        let fichier = dossier.join("appareils.json");
        ecrire_atomique(&fichier, "{\"reseaux\":{}}").unwrap();
        ecrire_atomique(&fichier, "{\"reseaux\":{\"box\":{}}}").unwrap();
        assert_eq!(std::fs::read_to_string(&fichier).unwrap(), "{\"reseaux\":{\"box\":{}}}");
        // Aucun fichier temporaire ne traîne.
        assert_eq!(std::fs::read_dir(&dossier).unwrap().count(), 1);
        // Le verrou est exclusif tant qu'il est gardé, et libéré à la fin.
        let v = Verrou::prendre_nomme(&dossier, "appareils.verrou").unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&v.0)
                .is_err()
        );
        let chemin = v.0.clone();
        drop(v);
        assert!(!chemin.exists());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Un lien posé d'avance sous un nom de temporaire n'est jamais suivi : la cible reste intacte, et le nom tiré
    /// au hasard ne se devine plus d'après le numéro du processus.
    #[cfg(unix)]
    #[test]
    fn ecriture_atomique_sans_suivre_de_lien() {
        let dossier = std::env::temp_dir().join(format!("vanguard-atomique-lien-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let cible = dossier.join("systeme.conf");
        std::fs::write(&cible, b"intact").unwrap();
        // Les noms d'avant le correctif, pour les écritures à venir de ce processus.
        let fichier = dossier.join("sceaux.json");
        for n in 0..20_000 {
            let piege = fichier.with_extension(format!("tmp-{}-{n}", std::process::id()));
            std::os::unix::fs::symlink(&cible, piege).unwrap();
        }
        ecrire_atomique(&fichier, b"{}").unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), b"intact");
        assert_eq!(std::fs::read(&fichier).unwrap(), b"{}");
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Un tube nommé, un lien ou un fichier trop gros à la place d'un fichier d'état : refusés tout de suite, sans
    /// rester bloqués dans open() ni tout charger.
    #[cfg(unix)]
    #[test]
    fn lecture_bornee_d_un_simple_fichier() {
        let dossier = std::env::temp_dir().join(format!("vanguard-ordinaire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let tube = dossier.join("appris.json");
        let c = std::ffi::CString::new(tube.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY : mkfifo reçoit un chemin terminé par zéro, qui vit le temps de l'appel.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let debut = std::time::Instant::now();
        let e = lire_ordinaire(&tube, 1024).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(debut.elapsed() < std::time::Duration::from_secs(2));
        let vrai = dossier.join("vrai.json");
        std::fs::write(&vrai, b"{}").unwrap();
        let lien = dossier.join("lien.json");
        std::os::unix::fs::symlink(&vrai, &lien).unwrap();
        assert_eq!(
            lire_ordinaire(&lien, 1024).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let gros = dossier.join("gros.json");
        std::fs::File::create(&gros).unwrap().set_len(1 << 30).unwrap();
        assert_eq!(
            lire_ordinaire(&gros, 1024).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(lire_ordinaire(&vrai, 1024).unwrap(), b"{}");
        assert_eq!(
            lire_ordinaire(&dossier.join("absent"), 1024).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// En root, le dossier d'un compte (le nôtre ici, qui n'est pas root) n'est pas sûr ; hors de root, tout l'est.
    #[cfg(unix)]
    #[test]
    fn en_root_seulement_un_dossier_de_root() {
        let d = std::env::temp_dir().join(format!("vanguard-sur-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        // SAFETY : getuid lit le compte du processus, sans argument.
        if unsafe { libc::getuid() } == 0 {
            return crate::essais::saute("lancé en root : un dossier à soi est à root");
        }
        assert!(ecriture_sure_pour(1000, &d));
        assert!(!ecriture_sure_pour(0, &d));
        assert!(!ecriture_sure_pour(0, &d.join("pas-encore/vanguard")));
        assert!(ecriture_sure_pour(0, std::path::Path::new("/")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Une écriture qui échoue (le dossier parent est un fichier) ne laisse aucun fichier provisoire derrière elle.
    #[test]
    fn ecriture_ratee_sans_reste() {
        let dossier = std::env::temp_dir().join(format!("vanguard-atomique-rate-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let bouchon = dossier.join("bouchon");
        std::fs::write(&bouchon, b"x").unwrap();
        assert!(ecrire_atomique(&bouchon.join("liste.json"), b"[]").is_err());
        assert_eq!(std::fs::read_dir(&dossier).unwrap().count(), 1);
        std::fs::remove_dir_all(&dossier).unwrap();
    }
}
