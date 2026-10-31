//! Les fichiers de Vanguard : son dossier sur cet ordinateur, l'écriture qui ne laisse jamais un fichier à moitié
//! écrit, le verrou entre deux Vanguard lancés en même temps. Ils servaient d'abord à la base des appareils, d'où
//! leur ancienne place dans `reseau` ; le bilan, la protection et les traces s'en servent autant, sans rien avoir à
//! faire du réseau.

use std::path::PathBuf;

use crate::{tr, trf};

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

/// `lire_ordinaire`, en texte UTF-8 (`InvalidData` sinon) : ce que lisent la plupart des fichiers d'état.
pub(crate) fn lire_texte_ordinaire(chemin: &std::path::Path, max: u64) -> std::io::Result<String> {
    String::from_utf8(lire_ordinaire(chemin, max)?).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
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
        ecriture_sure_pour(crate::socle::euid(), dossier)
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

/// Verrou entre processus (et entre fils) Vanguard : un verrou du système posé sur un fichier qui reste en place.
/// L'ancien verrou (un fichier créé de façon exclusive, retiré à la fin) laissait écrire sans lui après 10 s
/// d'attente : deux écrivains du journal scellé pouvaient alors écrire en même temps, la tête ne retrouvait plus la fin
/// annoncée et une rupture était notée, dite au bilan pendant un mois comme un journal changé hors de Vanguard. Il ne
/// savait pas non plus qui le tenait : celui d'un Vanguard tué bloquait deux minutes, puis tout verrou de plus de deux
/// minutes était repris, même à un Vanguard vivant mais lent. Le système, lui, libère le verrou d'un processus mort à
/// l'instant de sa fin (pas de numéro de processus réutilisé à deviner) et jamais celui d'un vivant.
pub(crate) struct Verrou {
    fichier: std::fs::File,
    /// Le fichier de l'ancien protocole, créé sous le verrou du système (`prendre_nomme`), retiré à la fin.
    ancien: Option<PathBuf>,
}

/// Pourquoi le verrou n'est pas tenu.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SansVerrou {
    /// Tenu par un autre Vanguard (ou un autre fil) au-delà du délai.
    Occupe,
    /// Le fichier du verrou ne s'ouvre pas, ou n'est pas un simple fichier (dossier, tube ou lien posé à sa place) :
    /// personne ne peut le tenir.
    Impossible(String),
}

impl SansVerrou {
    /// L'erreur que rend une écriture refusée faute de verrou.
    pub(crate) fn erreur(&self, nom: &str) -> std::io::Error {
        match self {
            SansVerrou::Occupe => std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                trf!(
                    "« {} » tenu par un autre Vanguard : rien n'est écrit sans lui",
                    "“{}” held by another Vanguard: nothing is written without it",
                    nom
                ),
            ),
            SansVerrou::Impossible(r) => std::io::Error::other(trf!(
                "« {} » inutilisable ({}) : rien n'est écrit sans lui",
                "“{}” unusable ({}): nothing is written without it",
                nom,
                r
            )),
        }
    }
}

/// L'attente d'un écrivain. Le verrou se tient le temps d'une écriture (relire le mois en cours, deux sceaux et un
/// ajout, chacun vidé sur le disque) : bien moins d'une seconde d'ordinaire, quelques secondes sur un Windows lent ou
/// dont l'antivirus analyse chaque fichier écrit. Trente secondes couvrent largement deux ou trois Vanguard qui se
/// suivent ; au-delà, mieux vaut ne pas écrire (et le dire) que figer qui note une alerte. Les essais mettent des
/// dizaines de fils sur un même verrou, sous Wine chargé : une minute.
pub(crate) const ATTENTE_ECRITURE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(60)
} else {
    std::time::Duration::from_secs(30)
};

/// L'attente d'un lecteur : moins, il ne fait qu'attendre la fin d'une écriture en cours.
pub(crate) const ATTENTE_LECTURE: std::time::Duration = if cfg!(test) {
    std::time::Duration::from_secs(60)
} else {
    std::time::Duration::from_secs(10)
};

/// Ce qu'écrit cette version dans le fichier de l'ancien protocole : trouvé là par qui tient le verrou du système, il
/// vient d'un Vanguard de cette version mort avant de le retirer (vivant, il tiendrait encore le verrou du système).
const MARQUE_ANCIEN: &[u8] = b"vanguard: verrou du systeme / system lock\n";

/// Au-delà, un fichier de l'ancien protocole sans marque est tenu pour abandonné : la règle des versions d'avant.
const ANCIEN_ABANDONNE: std::time::Duration = std::time::Duration::from_secs(120);

/// Le fichier sur lequel `Verrou::prendre_compatible` pose le verrou du système : `<nom sans .verrou>.lock`.
pub(crate) fn nom_systeme(nom: &str) -> String {
    format!("{}.lock", nom.strip_suffix(".verrou").unwrap_or(nom))
}

/// `nom` est-il dans `dossier` sous une autre forme qu'un simple fichier (un dossier, un lien, un tube), ou un fichier
/// qui ne s'ouvre plus en écriture (droits retirés, lecture seule) ? Un verrou ainsi remplacé ne se prend plus
/// (`SansVerrou::Impossible`), et rien ne s'écrit sous lui : aucune version de Vanguard ne le pose ainsi, c'est donc
/// un autre programme, à dire plutôt qu'à taire.
pub(crate) fn verrou_remplace(dossier: &std::path::Path, nom: &str) -> bool {
    let chemin = dossier.join(nom);
    let Ok(m) = std::fs::symlink_metadata(&chemin) else {
        return false;
    };
    if !m.file_type().is_file() {
        return true;
    }
    // Ouvert comme `Verrou::prendre` l'ouvre, sans créer ni tronquer ni verrouiller : rien ne change.
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
    #[cfg(windows)]
    std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000);
    options
        .open(&chemin)
        .is_err_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
}

impl Verrou {
    /// Le verrou exclusif `nom` (« evenements.verrou ») dans `dossier`, attendu au plus `ATTENTE_ECRITURE`. `None` :
    /// pas tenu, et l'appelant n'écrit pas. Voir `prendre_compatible`.
    pub(crate) fn prendre_nomme(dossier: &std::path::Path, nom: &str) -> Option<Verrou> {
        Self::prendre_compatible(dossier, nom, false, ATTENTE_ECRITURE).ok()
    }

    /// Le verrou `nom` des versions d'avant (0.86 et plus tôt : la clé portable peut en être une, à côté de la
    /// surveillance installée), tenu par les deux protocoles à la fois. Le verrou du système se pose sur un fichier à
    /// lui, `<nom sans .verrou>.lock`, qu'aucune version d'avant ne connaît ni n'efface : sur `nom` même, une version
    /// d'avant l'effaçait au bout de deux minutes et en créait un autre, que le Vanguard suivant verrouillait de son
    /// côté (deux tenants). Tenu exclusif, il crée aussi `nom` comme le faisaient les versions d'avant, qui attendent
    /// donc, et attend celui qu'une version d'avant tient. Un lecteur (`partage`) attend seulement qu'aucune version
    /// d'avant n'écrive.
    pub(crate) fn prendre_compatible(
        dossier: &std::path::Path,
        nom: &str,
        partage: bool,
        attente: std::time::Duration,
    ) -> Result<Verrou, SansVerrou> {
        let debut = std::time::Instant::now();
        let systeme = nom_systeme(nom);
        // Le fichier en cause est nommé : l'appelant ne connaît que `nom` (`SansVerrou::erreur`).
        let mut v = Self::prendre(dossier, &systeme, partage, attente).map_err(|e| match e {
            SansVerrou::Impossible(r) => SansVerrou::Impossible(format!("{systeme} : {r}")),
            occupe @ SansVerrou::Occupe => occupe,
        })?;
        let chemin = dossier.join(nom);
        let fin = debut + attente;
        loop {
            if !partage {
                match std::fs::OpenOptions::new().write(true).create_new(true).open(&chemin) {
                    Ok(mut f) => {
                        use std::io::Write as _;
                        let _ = f.write_all(MARQUE_ANCIEN);
                        v.ancien = Some(chemin);
                        return Ok(v);
                    }
                    Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
                        return Err(SansVerrou::Impossible(format!("{nom} : {e}")));
                    }
                    Err(_) => {}
                }
            }
            match std::fs::symlink_metadata(&chemin) {
                Err(_) if partage => return Ok(v),
                Err(_) => {}
                // Un dossier, un tube ou un lien posé à sa place ne se retire pas comme un verrou abandonné.
                Ok(m) if !m.file_type().is_file() => {
                    return Err(SansVerrou::Impossible(format!(
                        "{nom} : {}",
                        tr!("pas un simple fichier", "not a plain file")
                    )));
                }
                Ok(m) => {
                    let marque = lire_ordinaire(&chemin, 256).is_ok_and(|o| o == MARQUE_ANCIEN);
                    let abandonne = marque
                        || m.modified()
                            .ok()
                            .and_then(|t| t.elapsed().ok())
                            .is_some_and(|a| a > ANCIEN_ABANDONNE);
                    if abandonne {
                        if partage {
                            return Ok(v);
                        }
                        let _ = std::fs::remove_file(&chemin);
                        continue;
                    }
                }
            }
            if std::time::Instant::now() >= fin {
                return Err(SansVerrou::Occupe);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Le verrou du système sur le fichier `nom` de `dossier`, exclusif ou partagé (`partage` : des lecteurs
    /// ensemble, jamais pendant un écrivain), attendu au plus `attente`. Un lecteur ne crée le fichier que là où
    /// Vanguard peut écrire (`ecriture_sure`) : en administrateur dans le dossier d'un compte, il prend celui qui est
    /// déjà là, sinon rien.
    pub(crate) fn prendre(
        dossier: &std::path::Path,
        nom: &str,
        partage: bool,
        attente: std::time::Duration,
    ) -> Result<Verrou, SansVerrou> {
        let creer = !partage || ecriture_sure(dossier);
        if creer {
            let _ = std::fs::create_dir_all(dossier);
        }
        let chemin = dossier.join(nom);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(creer).create(creer).truncate(false);
        // Ni lien suivi, ni tube attendu : un tube posé à sa place figeait open() pour toujours.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        // FILE_FLAG_OPEN_REPARSE_POINT : un lien symbolique ou une jonction s'ouvre lui-même, sans être suivi.
        #[cfg(windows)]
        std::os::windows::fs::OpenOptionsExt::custom_flags(&mut options, 0x0020_0000);
        let f = options
            .open(&chemin)
            .map_err(|e| SansVerrou::Impossible(e.to_string()))?;
        if !f.metadata().is_ok_and(|m| m.file_type().is_file()) {
            return Err(SansVerrou::Impossible(
                tr!("pas un simple fichier", "not a plain file").to_string(),
            ));
        }
        let fin = std::time::Instant::now() + attente;
        loop {
            let essai = if partage { f.try_lock_shared() } else { f.try_lock() };
            match essai {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < fin => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::WouldBlock) => return Err(SansVerrou::Occupe),
                Err(std::fs::TryLockError::Error(e)) => return Err(SansVerrou::Impossible(e.to_string())),
            }
        }
        Ok(Verrou {
            fichier: f,
            ancien: None,
        })
    }
}

impl Drop for Verrou {
    fn drop(&mut self) {
        // L'ancien d'abord, encore sous le verrou du système : personne d'autre ne l'a créé entre-temps.
        if let Some(ancien) = &self.ancien {
            let _ = std::fs::remove_file(ancien);
        }
        // Rendu tout de suite, sans attendre que le système le fasse à la fermeture (sous Windows, « selon les
        // ressources disponibles »).
        let _ = self.fichier.unlock();
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
    let moi = crate::socle::uid();
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
                fn atexit(f: extern "C" fn()) -> std::ffi::c_int;
            }
            extern "C" fn retirer() {
                let _ = std::fs::remove_dir_all(
                    std::env::temp_dir().join(format!("vanguard-tests-{}", std::process::id())),
                );
            }
            // SAFETY: atexit de la bibliothèque C, présent sous Linux, Windows (msvcrt) et macOS ; il reçoit une
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
        // Le verrou est exclusif tant qu'il est gardé : ni un écrivain ni un lecteur ne le prennent ; il est rendu à
        // la fin, et son fichier reste.
        let court = std::time::Duration::from_millis(300);
        let v = Verrou::prendre(&dossier, "appareils.verrou", false, court).unwrap();
        assert_eq!(
            Verrou::prendre(&dossier, "appareils.verrou", false, court).err(),
            Some(SansVerrou::Occupe)
        );
        assert_eq!(
            Verrou::prendre(&dossier, "appareils.verrou", true, court).err(),
            Some(SansVerrou::Occupe)
        );
        drop(v);
        assert!(dossier.join("appareils.verrou").is_file());
        // Des lecteurs ensemble, jamais avec un écrivain.
        let l1 = Verrou::prendre(&dossier, "appareils.verrou", true, court).unwrap();
        let l2 = Verrou::prendre(&dossier, "appareils.verrou", true, court).unwrap();
        assert_eq!(
            Verrou::prendre(&dossier, "appareils.verrou", false, court).err(),
            Some(SansVerrou::Occupe)
        );
        drop((l1, l2));
        assert!(Verrou::prendre(&dossier, "appareils.verrou", false, court).is_ok());
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
        crate::essais::tube_nomme(&tube).unwrap();
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
        if crate::socle::uid() == 0 {
            return crate::essais::saute("lancé en root : un dossier à soi est à root");
        }
        assert!(ecriture_sure_pour(1000, &d));
        assert!(!ecriture_sure_pour(0, &d));
        assert!(!ecriture_sure_pour(0, &d.join("pas-encore/vanguard")));
        assert!(ecriture_sure_pour(0, std::path::Path::new("/")));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Un dossier (ancien) ou un tube posé à la place d'un verrou : jamais une boucle sans fin ni une attente à
    /// chaque écriture ; le verrou est dit impossible, et l'appelant n'écrit pas.
    #[cfg(unix)]
    #[test]
    fn verrou_qui_n_est_pas_un_fichier_ne_fige_rien() {
        let dossier = std::env::temp_dir().join(format!("vanguard-verrou-piege-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(dossier.join("evenements.verrou")).unwrap();
        let ancien = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::open(dossier.join("evenements.verrou"))
            .unwrap()
            .set_modified(ancien)
            .unwrap();
        let tube = dossier.join("alertes.verrou");
        crate::essais::tube_nomme(&tube).unwrap();
        let debut = std::time::Instant::now();
        for nom in ["evenements.verrou", "alertes.verrou"] {
            for partage in [false, true] {
                assert!(matches!(
                    Verrou::prendre(&dossier, nom, partage, ATTENTE_ECRITURE),
                    Err(SansVerrou::Impossible(_))
                ));
            }
        }
        assert!(
            debut.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            debut.elapsed()
        );
        // E5-M1 et E5-I2 (campagne 5) : le remplacement se voit sous ses trois formes, jamais un simple fichier ni un
        // nom absent ; l'échec nomme le fichier en cause, pas celui que l'appelant connaît.
        std::os::unix::fs::symlink(dossier.join("ailleurs"), dossier.join("sceaux.verrou")).unwrap();
        std::fs::write(dossier.join("appareils.verrou"), b"").unwrap();
        for nom in ["evenements.verrou", "alertes.verrou", "sceaux.verrou"] {
            assert!(verrou_remplace(&dossier, nom), "{nom}");
        }
        assert!(!verrou_remplace(&dossier, "appareils.verrou"));
        assert!(!verrou_remplace(&dossier, "absent.verrou"));
        // Un simple fichier aux droits retirés ne se prend pas davantage (relecture du lot campagne 5). Root ouvre
        // tout : rien à voir alors.
        std::fs::set_permissions(
            dossier.join("appareils.verrou"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o400),
        )
        .unwrap();
        if std::fs::OpenOptions::new()
            .write(true)
            .open(dossier.join("appareils.verrou"))
            .is_err()
        {
            assert!(verrou_remplace(&dossier, "appareils.verrou"));
            assert!(matches!(
                Verrou::prendre(&dossier, "appareils.verrou", false, ATTENTE_ECRITURE),
                Err(SansVerrou::Impossible(_))
            ));
        }
        std::fs::set_permissions(
            dossier.join("appareils.verrou"),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        assert!(!verrou_remplace(&dossier, "appareils.verrou"));
        std::fs::create_dir(dossier.join("journal.lock")).unwrap();
        let Err(SansVerrou::Impossible(r)) =
            Verrou::prendre_compatible(&dossier, "journal.verrou", false, ATTENTE_ECRITURE)
        else {
            panic!("pris malgré un dossier à la place de journal.lock");
        };
        assert!(r.starts_with("journal.lock"), "{r}");
        assert!(!dossier.join("ailleurs").exists());
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    /// Avec une version d'avant (0.86, fichier créé de façon exclusive, retiré à la fin) : son verrou en cours se
    /// respecte, dans les deux sens ; abandonné (plus de deux minutes) ou laissé par un Vanguard de cette version mort
    /// avant de le retirer (marqué), il se reprend ; jamais celui d'un vivant de cette version, tenu par le système.
    #[test]
    fn verrou_compatible_avec_une_version_d_avant() {
        let dossier = std::env::temp_dir().join(format!("vanguard-verrou-ancien-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let ancien = dossier.join("evenements.verrou");
        let court = std::time::Duration::from_millis(300);
        let prendre = |partage| Verrou::prendre_compatible(&dossier, "evenements.verrou", partage, court);
        // Une 0.86 écrit en ce moment : ni écrivain ni lecteur n'avancent.
        std::fs::write(&ancien, b"").unwrap();
        assert_eq!(prendre(false).err(), Some(SansVerrou::Occupe));
        assert_eq!(prendre(true).err(), Some(SansVerrou::Occupe));
        assert!(ancien.exists(), "le verrou d'une 0.86 vivante est retiré");
        // Abandonné : repris, et retiré à la fin.
        let vieux = std::time::SystemTime::now() - std::time::Duration::from_secs(600);
        std::fs::File::options()
            .write(true)
            .open(&ancien)
            .unwrap()
            .set_modified(vieux)
            .unwrap();
        let v = prendre(false).unwrap();
        // Tenu : une 0.86 le voit (création exclusive refusée), un autre de cette version attend.
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&ancien)
                .is_err()
        );
        assert_eq!(prendre(false).err(), Some(SansVerrou::Occupe));
        assert_eq!(prendre(true).err(), Some(SansVerrou::Occupe));
        drop(v);
        assert!(!ancien.exists());
        assert!(dossier.join("evenements.lock").is_file());
        // Laissé par un Vanguard de cette version tué avant de le retirer : repris tout de suite.
        std::fs::write(&ancien, MARQUE_ANCIEN).unwrap();
        assert!(prendre(true).is_ok());
        assert!(prendre(false).is_ok());
        std::fs::remove_dir_all(&dossier).unwrap();
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
