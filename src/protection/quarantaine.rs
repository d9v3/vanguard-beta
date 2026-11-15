//! Quarantaine réversible : un fichier jugé dangereux (antivirus, YARA) est déplacé dans le dossier de Vanguard sur cet
//! ordinateur (jamais sur la clé : on ne transporte pas de logiciel malveillant), rendu inutilisable (aucune
//! permission sous Linux ; sous Windows, une extension qui empêche de le lancer d'un double-clic, et lecture
//! seule), et noté : d'où il vient, ses permissions, la détection, la date. Une détection peut se tromper : « Remettre »
//! le replace exactement où il était, avec ses permissions d'avant, sans jamais écraser un fichier qui aurait pris sa
//! place. Les fichiers isolés avant la 0.61 (journal.txt seulement) se remettent aussi.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]

use std::path::{Path, PathBuf};

use crate::modele::{Echec, Raison};

use serde::{Deserialize, Serialize};

use crate::ui::*;

/// Ajouté au nom sous Windows : un fichier en « .exe.vanguard-quarantaine » ne se lance plus d'un double-clic.
const SUFFIXE_WINDOWS: &str = ".vanguard-quarantaine";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
struct Entree {
    /// Nom du fichier dans le dossier de la quarantaine.
    nom: String,
    /// Chemin d'origine, tel quel (pour le remettre) ; montré, il passe par `affichable`.
    origine: String,
    detection: String,
    /// « AAAA-MM-JJ HH:MM:SS ».
    date: String,
    /// Permissions d'origine (Linux), pour les remettre ; absentes pour un fichier isolé avant la 0.61.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
    /// Empreinte SHA-256 relevée avant l'isolement : pour le chercher (VirusTotal) et prouver que c'est le même
    /// fichier ; absente pour un fichier isolé avant la 0.86, ou trop gros pour être haché.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct Registre {
    fichiers: Vec<Entree>,
}

pub fn dossier() -> PathBuf {
    crate::socle::dossier_local().join("quarantaine")
}

fn registre_dans(dossier: &Path) -> PathBuf {
    dossier.join("quarantaine.json")
}

fn charger(dossier: &Path) -> Registre {
    crate::socle::lire_texte_ordinaire(&registre_dans(dossier), 16 << 20)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn enregistrer(dossier: &Path, r: &Registre) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(r).map_err(std::io::Error::other)?;
    crate::socle::ecrire_atomique(&registre_dans(dossier), texte)
}

/// L'identité d'un fichier (périphérique, inode, nombre de noms) prise à son examen, sur le descripteur même qui a été
/// lu. La quarantaine déplace ensuite un nom : sans cette identité, un programme du compte qui glisse sous ce nom un
/// lien dur vers ~/.bashrc entre l'examen et le déplacement ferait rendre ~/.bashrc illisible (permissions à zéro sur
/// l'inode partagé), au nom de la quarantaine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identite {
    pub dev: u64,
    pub ino: u64,
    pub liens: u64,
}

#[cfg(unix)]
impl Identite {
    pub(crate) fn de(m: &std::fs::Metadata) -> Identite {
        use std::os::unix::fs::MetadataExt;
        Identite {
            dev: m.dev(),
            ino: m.ino(),
            liens: m.nlink(),
        }
    }

    /// Le même inode (le nombre de noms à part).
    pub(crate) fn meme_fichier(&self, autre: &Identite) -> bool {
        (self.dev, self.ino) == (autre.dev, autre.ino)
    }
}

/// Qui demande la quarantaine, pour la noter dans « Ce que Vanguard a changé » (`changements`), avec de quoi
/// l'annuler (`vanguard blocage annuler`) : le blocage d'une menace, ou une analyse (antivirus, YARA) après accord.
pub(crate) struct Demande {
    /// La menace (« fichier:/chemin ») : relie l'alerte, le blocage et la quarantaine dans les traces d'incident.
    pub cle: String,
    /// Ce qui est fait, et pourquoi, prêt à montrer.
    pub quoi: String,
    pub automatique: bool,
    /// Ce qui a été fait juste avant (l'arrêt du processus), noté avec la quarantaine.
    pub lancees: Vec<String>,
    /// Le relevé d'avant le geste (`preuve::relever`) : sans lui, pas de quarantaine.
    pub preuve: crate::protection::preuve::PreuveFaite,
    /// L'identité du fichier à son examen (temps réel) : un autre fichier sous ce nom n'est pas isolé.
    pub identite: Option<Identite>,
}

/// La demande d'une analyse (antivirus, YARA) qui a trouvé `chemin` : son relevé est fait maintenant, avant
/// l'isolement.
pub(crate) fn demande_d_analyse(chemin: &Path, detection: &str) -> Demande {
    Demande {
        cle: format!("fichier:{}", chemin.display()),
        quoi: trf!(
            "Quarantaine de « {} » : {}",
            "Quarantine of “{}”: {}",
            chemin_affichable(chemin),
            affichable(detection)
        ),
        automatique: false,
        lancees: Vec::new(),
        preuve: crate::protection::preuve::relever(
            crate::protection::preuve::Releve::Fichier(chemin),
            &format!("fichier:{}", chemin.display()),
            crate::modele::evenement::Source::Analyse,
        ),
        identite: None,
    }
}

/// Le seul chemin vers la quarantaine, pour le blocage comme pour les analyses : isole `chemin` dans la quarantaine
/// de cet ordinateur, puis note le geste (réussi ou non) avec sa preuve et de quoi l'annuler. Rend son chemin en
/// quarantaine.
pub(crate) fn isoler(chemin: &Path, detection: &str, d: Demande) -> std::io::Result<PathBuf> {
    let mut lancees = d.lancees;
    lancees.push(format!("quarantaine : {}", chemin.display()));
    let sha256 = d
        .preuve
        .preuve()
        .and_then(|p| p.fichier.as_ref())
        .filter(|f| Path::new(&f.chemin) == chemin)
        .and_then(|f| f.sha256.clone());
    // Le seul chemin vers la quarantaine : un fichier signé par Microsoft n'y va jamais, d'où que vienne la demande
    // (défense D6a) ; une signature illisible s'y montre puis se confirme, seulement à la demande de la personne.
    let r = garde_de_signature(chemin, d.automatique, &mut lancees)
        .and_then(|()| isoler_dans(chemin, detection, &dossier(), sha256, d.identite));
    let annulation =
        r.as_ref()
            .ok()
            .and_then(|dest| dest.file_name())
            .map(|n| crate::changements::Annulation::Quarantaine {
                nom: n.to_string_lossy().into_owned(),
            });
    crate::changements::noter_blocage(
        lancees,
        r.is_ok(),
        crate::changements::Blocage {
            id: crate::changements::nouvel_id(),
            cle: d.cle,
            quoi: d.quoi,
            automatique: d.automatique,
            annulation,
            annule: None,
            supprime: false,
            preuve: None,
            evenement: None,
            origine: None,
        },
        d.preuve,
    );
    r
}

/// Supprime pour de bon un fichier trouvé par une analyse, après accord : relevé d'abord (son empreinte disparaît
/// avec lui), puis noté dans « Ce que Vanguard a changé », sans rien à annuler. Les traces d'incident le reprennent,
/// comme une quarantaine. ClamAV, seul à le proposer, n'est lancé d'ici que sous Linux.
///
/// Seulement s'il est encore le fichier examiné (`attendue`, PA-1, relecture du 12 nov.) : entre l'examen et la
/// réponse de la personne, un autre compte qui tient un dossier du chemin (dans /tmp) pouvait le changer en lien
/// vers le dossier d'un autre, et `remove_file` effaçait le fichier de même nom qui s'y trouve. Le dossier est donc
/// tenu ouvert, le nom y est relu sans suivre de lien, puis retiré de ce même dossier.
#[cfg(unix)]
pub(crate) fn supprimer_apres_analyse(chemin: &Path, detection: &str, attendue: &Identite) -> std::io::Result<()> {
    let cle = format!("fichier:{}", chemin.display());
    let tenu = tenir_le_meme(chemin, attendue);
    // Un autre fichier sous ce nom n'est même pas relevé : rien de lui n'entre dans les traces.
    let preuve = crate::protection::preuve::relever(
        if tenu.is_ok() {
            crate::protection::preuve::Releve::Fichier(chemin)
        } else {
            crate::protection::preuve::Releve::Rien
        },
        &cle,
        crate::modele::evenement::Source::Analyse,
    );
    #[cfg(test)]
    if let Some(autre_compte) = AVANT_LE_GESTE.with(|c| c.borrow_mut().take()) {
        autre_compte();
    }
    // Relu juste avant de retirer le nom : le relevé a pris un moment.
    let r = tenu.and_then(|(dossier, nom)| {
        le_meme_dans(&dossier, &nom, attendue)?;
        retirer_dans(&dossier, &nom)
    });
    crate::changements::noter_blocage(
        vec![format!("suppression : {}", chemin.display())],
        r.is_ok(),
        crate::changements::Blocage {
            id: crate::changements::nouvel_id(),
            cle,
            quoi: trf!(
                "Suppression de « {} » : {}",
                "Deletion of “{}”: {}",
                chemin_affichable(chemin),
                affichable(detection)
            ),
            automatique: false,
            annulation: None,
            annule: None,
            supprime: false,
            preuve: None,
            evenement: None,
            origine: None,
        },
        preuve,
    );
    r
}

#[cfg(all(test, unix))]
thread_local! {
    /// Joué juste avant le geste (le retrait d'un fichier analysé, le déplacement vers la quarantaine) : un essai y
    /// fait ce qu'un autre compte ferait de son dossier de /tmp pendant ce moment, que l'examen d'avant ne peut plus
    /// voir.
    static AVANT_LE_GESTE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Joué juste avant la sortie de la quarantaine, après l'empreinte : un essai y fait ce que ferait un programme du
    /// compte qui tient le dossier de la quarantaine (échanger le fichier isolé contre le sien).
    static AVANT_LA_SORTIE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
thread_local! {
    /// Joué dans la marche vers l'origine, juste avant de résoudre un « .. » : un essai y déplace un dossier déjà
    /// ouvert, ce qu'un compte ferait du sien pendant la remise.
    static AVANT_LA_REMONTEE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
thread_local! {
    /// Le lien (périphérique, inode) qu'un essai fait tenir pour posé par un autre compte : Vanguard lancé en root ne
    /// le suivrait pas, mais les essais tournent sous le compte même qui pose leurs liens.
    static LIEN_D_UN_AUTRE: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Le dossier de `chemin`, tenu ouvert, et son nom, si ce dossier est bien à sa place et que ce nom y désigne encore
/// le fichier `attendue`.
#[cfg(unix)]
fn tenir_le_meme(chemin: &Path, attendue: &Identite) -> std::io::Result<(std::fs::File, std::ffi::CString)> {
    let (dossier, nom) = tenir_le_dossier(chemin)?;
    // Le chemin vient de clamscan, sous des cibles canoniques : il y est écrit tel que lu, sans lien vers un dossier.
    // Un dossier de /tmp changé depuis en lien vers celui d'un autre y mène à un autre fichier, et un lien dur y
    // garde la même identité : seul le dossier même, à sa place, est accepté (PA-1, contrôle de la ronde 2).
    if !chemin.parent().is_some_and(|parent| a_sa_place(&dossier, parent)) {
        return Err(std::io::Error::other(tr!(
            "son chemin passe maintenant par un lien vers un dossier : rien n'est supprimé",
            "its path now goes through a link to a folder: nothing is deleted"
        )));
    }
    le_meme_dans(&dossier, &nom, attendue)?;
    Ok((dossier, nom))
}

/// Le dossier de `chemin`, tenu ouvert (il peut avoir été atteint par un lien), et le nom du fichier dans ce dossier :
/// tout geste qui suit (relecture, retrait, déplacement, remise) se fait dans ce dossier-là, jamais par le chemin, qu'un
/// autre compte qui tient un dossier du chemin peut faire mener ailleurs entre-temps.
#[cfg(unix)]
fn tenir_le_dossier(chemin: &Path) -> std::io::Result<(std::fs::File, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    let (Some(parent), Some(nom)) = (chemin.parent().filter(|p| p.is_absolute()), chemin.file_name()) else {
        return Err(std::io::Error::other(tr!(
            "ce n'est pas le chemin complet d'un fichier",
            "this is not the full path of a file"
        )));
    };
    let dossier = ouvrir_dossier(parent)?;
    let nom = std::ffi::CString::new(nom.as_bytes())
        .map_err(|_| std::io::Error::other(tr!("nom de fichier invalide", "invalid file name")))?;
    Ok((dossier, nom))
}

/// Un dossier ouvert pour y agir par son descripteur.
#[cfg(unix)]
fn ouvrir_dossier(dossier: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dossier)
}

/// Le dossier ouvert est-il à `parent` même ? Le noyau dit où il est (/proc/self/fd/N) : un chemin passé par un lien
/// vers un dossier y montre l'autre. Sans /proc, rien n'est su : refusé.
#[cfg(unix)]
fn a_sa_place(dossier: &std::fs::File, parent: &Path) -> bool {
    use std::os::fd::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", dossier.as_raw_fd())).is_ok_and(|lieu| lieu == parent)
}

/// `nom`, sous `dossier`, est-il encore le fichier ordinaire `attendue` ? Lu sans suivre de lien.
#[cfg(unix)]
fn le_meme_dans(dossier: &std::fs::File, nom: &std::ffi::CStr, attendue: &Identite) -> std::io::Result<()> {
    let m = std::fs::File::from(ouvrir_sans_suivre(dossier, nom)?).metadata()?;
    if !m.file_type().is_file() || !Identite::de(&m).meme_fichier(attendue) {
        return Err(std::io::Error::other(tr!(
            "le fichier a changé depuis son examen : rien n'est supprimé",
            "the file changed since it was scanned: nothing is deleted"
        )));
    }
    Ok(())
}

/// openat de `nom` sous `dossier`, en O_PATH sans suivre de lien : de quoi relire l'inode du nom lui-même.
#[cfg(unix)]
// FFI de libc : openat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn ouvrir_sans_suivre(dossier: &std::fs::File, nom: &std::ffi::CStr) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dossier` est un descripteur ouvert,
    // emprunté pendant l'appel.
    let fd = unsafe {
        libc::openat(
            dossier.as_raw_fd(),
            nom.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être rendu par openat, ouvert, et n'appartient à rien d'autre.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// unlinkat d'un fichier sous `dossier` (jamais un dossier) : le nom relu par `le_meme_dans`, dans le même dossier.
#[cfg(unix)]
// FFI de libc : unlinkat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn retirer_dans(dossier: &std::fs::File, nom: &std::ffi::CStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dossier` est un descripteur ouvert,
    // emprunté pendant l'appel.
    let r = unsafe { libc::unlinkat(dossier.as_raw_fd(), nom.as_ptr(), 0) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// La garde de signature de la quarantaine (défense D6a, choix 3.1) : Microsoft lisible refuse ; illisible refuse un
/// geste automatique ou sans vraie console, sinon montre pourquoi et ce qu'on sait du fichier, puis demande « Mettre
/// de côté quand même ? [o/N] ». Un fichier qu'une autre garde refuse (système, Vanguard) n'en reçoit jamais la
/// question. La signature est relue après la réponse : devenue Microsoft lisible, la réponse ne vaut plus.
fn garde_de_signature(chemin: &Path, automatique: bool, lancees: &mut Vec<String>) -> std::io::Result<()> {
    use crate::protection::blocage::gardes::{self, Decision};
    let texte = chemin.to_string_lossy();
    let sig = gardes::signature_lue(&texte);
    if matches!(sig, gardes::Signature::Autre) {
        // Lisible et pas Microsoft : rien de plus qu'avant (les autres gardes sont celles de l'appelant).
        return Ok(());
    }
    let mon_programme = std::env::current_exe().ok().map(|c| c.to_string_lossy().into_owned());
    let autre = gardes::fichier_intouchable(&texte, crate::machine::regles::Os::actuel(), mon_programme.as_deref());
    let raison = match gardes::decider_signature(sig, autre, !automatique, gardes::console_reelle()) {
        Decision::Permis => return Ok(()),
        Decision::Refuse(r) => return Err(std::io::Error::other(r)),
        Decision::Demander(r) => r,
    };
    if let Some(pourquoi) = gardes::mise_de_cote_bloquee(essai_de_deplacement(chemin)) {
        return Err(std::io::Error::other(pourquoi));
    }
    let portrait = gardes::portrait_de_fichier(chemin);
    let question = tr!(
        "\n  Mettre de côté quand même ? [o/N] : ",
        "\n  Set it aside anyway? [y/N]: "
    );
    if !gardes::montrer_et_confirmer(raison, &portrait, question) {
        return Err(std::io::Error::other(tr!(
            "vous avez répondu non : rien n'est mis de côté",
            "you answered no: nothing is set aside"
        )));
    }
    let relue = gardes::signature_lue(&texte);
    if matches!(relue, gardes::Signature::Microsoft) {
        return Err(std::io::Error::other(
            gardes::signature_intouchable(relue).unwrap_or_default(),
        ));
    }
    lancees.push(gardes::note_confirmee(true, raison, portrait.sha256.as_deref()));
    Ok(())
}

/// Le fichier s'ouvrirait-il pour être déplacé ? Ouvert avec le seul droit que demande un déplacement (DELETE), en
/// permettant tout partage pour ne gêner personne, et refermé aussitôt : l'erreur système, ou `None`.
#[cfg(windows)]
fn essai_de_deplacement(chemin: &Path) -> Option<u32> {
    use std::os::windows::fs::OpenOptionsExt as _;
    // DELETE ; FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
    let essai = std::fs::OpenOptions::new()
        .access_mode(0x0001_0000)
        .share_mode(7)
        .open(chemin);
    essai.err()?.raw_os_error().map(i32::cast_unsigned)
}

/// Hors de Windows, un fichier ouvert ne bloque pas son déplacement.
#[cfg(not(windows))]
fn essai_de_deplacement(_chemin: &Path) -> Option<u32> {
    None
}

fn isoler_dans(
    chemin: &Path,
    detection: &str,
    dossier: &Path,
    sha256: Option<String>,
    attendue: Option<Identite>,
) -> std::io::Result<PathBuf> {
    // Ce qui s'isole doit pouvoir se remettre : un chemin qui remonte (« .. ») ou incomplet serait refusé à la remise
    // (`origine_admise`), le fichier coincé en quarantaine (relecture de PA-4). Le blocage rend le chemin direct
    // (`chemin_direct`), comme la porte des analyses (`isoler_trouve`) ; ici, refusé, le fichier reste en place.
    if !origine_admise(&chemin.to_string_lossy(), false) {
        return Err(std::io::Error::other(trf!(
            "« {} » n'est pas un chemin complet et direct (sans « .. ») : rien n'est isolé, la remise ne saurait pas où le remettre",
            "“{}” is not a full, direct path (without “..”): nothing is isolated, restoring would not know where to put it back",
            chemin_affichable(chemin)
        )));
    }
    // Lancé par sudo -E, root écrirait dans le dossier d'un compte, où un programme de ce compte a pu changer
    // journal.txt en lien vers /etc/ld.so.preload : la ligne ajoutée (une origine choisie par lui) y serait lue. Le
    // fichier reste en place, et `isoler` note l'échec.
    if !crate::socle::ecriture_sure(dossier) {
        return Err(std::io::Error::other(refus_de_root()));
    }
    #[cfg(windows)]
    destination_sure(dossier, true)?;
    std::fs::create_dir_all(dossier)?;
    // Tenus jusqu'au retour : le déplacement, la note et le journal vont là où ils ont été relus.
    #[cfg(windows)]
    let _tenus = destination_tenue(dossier)?;
    // Unix : le dossier du fichier est tenu dès ici, et la relecture, le déplacement, la copie, le retrait et la
    // remise se font dans ce dossier-là. Par le chemin, un autre compte qui tient un dossier du chemin (dans /tmp)
    // pouvait le changer, juste après la relecture, en lien vers le dossier d'un autre : le fichier de même nom qui
    // s'y trouve partait en quarantaine, ou, d'un disque à l'autre, était copié puis effacé (PA-1, contrôle de la
    // ronde 2).
    #[cfg(unix)]
    let (tenu, nom_tenu) = tenir_le_dossier(chemin)?;
    #[cfg(unix)]
    let meta = std::fs::File::from(ouvrir_sans_suivre(&tenu, &nom_tenu)?).metadata()?;
    #[cfg(not(unix))]
    let meta = std::fs::symlink_metadata(chemin)?;
    if !meta.is_file() {
        return Err(std::io::Error::other(tr!(
            "ce n'est pas un fichier",
            "this is not a file"
        )));
    }
    #[cfg(unix)]
    let avant = {
        let avant = Identite::de(&meta);
        identite_permise(&avant, attendue.as_ref())?;
        avant
    };
    #[cfg(not(unix))]
    let _ = attendue;
    #[cfg(unix)]
    let mode = Some(std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777);
    #[cfg(windows)]
    let mode = None;
    let nom_origine = chemin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let horodatage = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let suffixe = if cfg!(windows) { SUFFIXE_WINDOWS } else { "" };
    let nom = format!("{horodatage}.{nom_origine}{suffixe}");
    let dest = dossier.join(&nom);
    #[cfg(all(test, unix))]
    if let Some(autre_compte) = AVANT_LE_GESTE.with(|c| c.borrow_mut().take()) {
        autre_compte();
    }
    #[cfg(unix)]
    let (quarantaine, nom_q) = (
        ouvrir_dossier(dossier)?,
        std::ffi::CString::new(nom.as_bytes())
            .map_err(|_| std::io::Error::other(tr!("nom de fichier invalide", "invalid file name")))?,
    );
    #[cfg(unix)]
    let renomme = deplacer_le_meme(&tenu, &nom_tenu, &quarantaine, &nom_q, &dest, &avant)?;
    // rename échoue d'un disque à l'autre (clé USB → disque) : copie, puis suppression de l'original.
    #[cfg(not(unix))]
    std::fs::rename(chemin, &dest).or_else(|_| {
        std::fs::copy(chemin, &dest)?;
        // Original impossible à supprimer : pas de seconde copie, encore utilisable, en quarantaine.
        std::fs::remove_file(chemin).inspect_err(|_| {
            let _ = std::fs::remove_file(&dest);
        })
    })?;
    // Le nom déplacé est relu avant de toucher aux permissions : un autre inode glissé sous ce nom entre la relecture
    // et le déplacement retourne à sa place, intact.
    #[cfg(unix)]
    if renomme {
        let apres = std::fs::symlink_metadata(&dest).map(|m| Identite::de(&m));
        if !apres.as_ref().is_ok_and(|a| a.meme_fichier(&avant) && a.liens == 1) {
            return Err(remettre_le_nom(&quarantaine, &nom_q, &dest, &tenu, &nom_tenu));
        }
    }
    // Décidé : le même contenu déjà en quarantaine n'y entre pas deux fois ; le fichier trouvé quitte quand même son
    // dossier.
    let lu = crate::protection::empreintes::sha256(&dest).map(|e| crate::protection::empreintes::hex(&e));
    // Sous Windows, chaque fichier garde sa copie : remis depuis celle d'un autre, il perdrait sa marque du web
    // (Zone.Identifier), qui fait avertir Windows à son ouverture.
    #[cfg(unix)]
    let joint = lu.as_deref().is_some_and(|h| rejoindre_un_jumeau(dossier, &dest, h));
    #[cfg(not(unix))]
    let joint = false;
    // Joint : l'empreinte relue des deux côtés, la même que celle du jumeau au registre ; sinon celle de la preuve.
    let sha256 = if joint { lu } else { sha256.or(lu) };
    fermer(&dest)?;
    let mut r = charger(dossier);
    let entree = Entree {
        nom,
        origine: chemin.to_string_lossy().into_owned(),
        detection: detection.to_string(),
        date: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        mode,
        sha256,
    };
    noter_journal(dossier, &entree);
    r.fichiers.push(entree);
    enregistrer(dossier, &r)?;
    Ok(dest)
}

/// Fermé : illisible pour tous (Unix), en lecture seule (Windows).
fn fermer(chemin: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    std::fs::set_permissions(chemin, std::os::unix::fs::PermissionsExt::from_mode(0o000))?;
    #[cfg(windows)]
    {
        let mut p = std::fs::metadata(chemin)?.permissions();
        p.set_readonly(true);
        std::fs::set_permissions(chemin, p)?;
    }
    Ok(())
}

/// Un contenu déjà isolé n'y entre pas deux fois : `dest` (le fichier trouvé, déjà déplacé et relu) devient un second
/// nom du fichier isolé qui a la même empreinte, relue des deux côtés (jamais celle du seul registre). Pas de seconde
/// copie ; chaque nom garde son origine et se remet ou se supprime à part. `lu` : l'empreinte de `dest`. `false` :
/// pas de jumeau, ou le lien impossible (le fichier reste une quarantaine ordinaire).
#[cfg(unix)]
fn rejoindre_un_jumeau(dossier: &Path, dest: &Path, lu: &str) -> bool {
    let Some(jumeau) = liste_dans(dossier)
        .into_iter()
        .filter(|x| x.sha256.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(lu)))
        .map(|x| dossier.join(&x.nom))
        .find(|c| c != dest && contenu_isole(c).is_some_and(|h| h.eq_ignore_ascii_case(lu)))
    else {
        return false;
    };
    let Some(mut nom) = dest.file_name().map(std::ffi::OsStr::to_os_string) else {
        return false;
    };
    nom.push(".lien");
    let lien = dest.with_file_name(nom);
    if std::fs::hard_link(&jumeau, &lien).is_err() {
        return false;
    }
    // Remplacé d'un coup : le nom n'est jamais vide, et seul l'inode du fichier trouvé s'en va.
    if std::fs::rename(&lien, dest).is_err() {
        let _ = std::fs::remove_file(&lien);
        return false;
    }
    true
}

/// L'empreinte d'un fichier isolé, ouvert le temps de la lire puis refermé (illisible sinon).
#[cfg(unix)]
fn contenu_isole(chemin: &Path) -> Option<String> {
    if !std::fs::symlink_metadata(chemin).ok()?.is_file() {
        return None;
    }
    std::fs::set_permissions(chemin, std::os::unix::fs::PermissionsExt::from_mode(0o400)).ok()?;
    let lu = crate::protection::empreintes::sha256(chemin);
    let _ = fermer(chemin);
    lu.map(|e| crate::protection::empreintes::hex(&e))
}

/// Les autres noms en quarantaine du même contenu que `e` (`rejoindre_un_jumeau`).
fn jumeaux(e: &Entree, dossier: &Path) -> Vec<PathBuf> {
    let Some(h) = e.sha256.as_deref() else {
        return Vec::new();
    };
    liste_dans(dossier)
        .into_iter()
        .filter(|x| x.nom != e.nom && x.sha256.as_deref().is_some_and(|y| y.eq_ignore_ascii_case(h)))
        .map(|x| dossier.join(&x.nom))
        .filter(|c| c.exists())
        .collect()
}

/// Le fichier relu juste avant le déplacement est-il celui qui a été examiné, et seul à porter son contenu ? Un fichier
/// à plusieurs noms (liens durs) n'est jamais isolé : ses permissions à zéro toucheraient aussi les autres noms, que
/// la personne n'a pas vus (un ~/.bashrc, une sauvegarde par liens durs).
#[cfg(unix)]
fn identite_permise(avant: &Identite, attendue: Option<&Identite>) -> std::io::Result<()> {
    if attendue.is_some_and(|a| !a.meme_fichier(avant)) {
        return Err(std::io::Error::other(tr!(
            "le fichier a changé depuis son examen : rien n'est isolé, il sera examiné de nouveau",
            "the file changed since it was scanned: nothing is isolated, it will be scanned again"
        )));
    }
    if avant.liens > 1 {
        return Err(std::io::Error::other(trf!(
            "ce fichier a {} noms (liens durs) : le rendre inutilisable toucherait aussi les autres ; rien n'est fait",
            "this file has {} names (hard links): making it unusable would also affect the others; nothing is done",
            avant.liens
        )));
    }
    Ok(())
}

/// `nom` du dossier tenu va en quarantaine sous `nom_q` (`dest`) : renameat2 d'un dossier ouvert à l'autre ; d'un
/// disque à l'autre (clé USB → disque, /tmp → home), copie depuis le dossier tenu, puis retrait du nom de ce même
/// dossier. Vrai si le nom a été déplacé (à relire), faux s'il a été copié.
#[cfg(unix)]
fn deplacer_le_meme(
    tenu: &std::fs::File,
    nom: &std::ffi::CStr,
    quarantaine: &std::fs::File,
    nom_q: &std::ffi::CStr,
    dest: &Path,
    avant: &Identite,
) -> std::io::Result<bool> {
    if renommer_sans_ecraser(tenu, nom, quarantaine, nom_q).is_ok() {
        return Ok(true);
    }
    copier_le_meme(tenu, nom, dest, avant)?;
    // Original impossible à supprimer : pas de seconde copie, encore utilisable, en quarantaine.
    retirer_dans(tenu, nom).inspect_err(|_| {
        let _ = std::fs::remove_file(dest);
    })?;
    Ok(false)
}

/// D'un disque à l'autre : la copie part du descripteur ouvert dans le dossier tenu sans suivre de lien, dont
/// l'identité est relue, puis l'original n'est supprimé que s'il porte encore cette identité.
#[cfg(unix)]
fn copier_le_meme(tenu: &std::fs::File, nom: &std::ffi::CStr, dest: &Path, avant: &Identite) -> std::io::Result<()> {
    let change = || {
        std::io::Error::other(tr!(
            "le fichier a changé pendant la quarantaine : rien n'est isolé",
            "the file changed during quarantine: nothing is isolated"
        ))
    };
    let mut source = std::fs::File::from(ouvrir_dans(
        tenu,
        nom,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?);
    if !Identite::de(&source.metadata()?).meme_fichier(avant) {
        return Err(change());
    }
    let mut copie = std::fs::OpenOptions::new().write(true).create_new(true).open(dest)?;
    let copiee = std::io::copy(&mut source, &mut copie).and_then(|_| copie.sync_all());
    let toujours = ouvrir_sans_suivre(tenu, nom)
        .and_then(|fd| std::fs::File::from(fd).metadata())
        .is_ok_and(|m| Identite::de(&m).meme_fichier(avant));
    if copiee.is_err() || !toujours {
        let _ = std::fs::remove_file(dest);
        return Err(copiee.err().unwrap_or_else(change));
    }
    Ok(())
}

/// Un autre inode est arrivé dans la quarantaine sous le nom examiné : il retourne à son nom, dans le dossier tenu
/// d'où il vient, sans rien écraser (renameat2 sans remplacement). Un nom repris entre-temps le laisse où il est, et
/// l'erreur le dit.
#[cfg(unix)]
fn remettre_le_nom(
    quarantaine: &std::fs::File,
    nom_q: &std::ffi::CStr,
    dest: &Path,
    tenu: &std::fs::File,
    nom: &std::ffi::CStr,
) -> std::io::Error {
    match renommer_sans_ecraser(quarantaine, nom_q, tenu, nom) {
        Ok(()) => std::io::Error::other(tr!(
            "un autre fichier a pris ce nom pendant la quarantaine : remis à sa place, rien n'est isolé",
            "another file took this name during quarantine: put back in place, nothing is isolated"
        )),
        Err(e) => std::io::Error::other(trf!(
            "un autre fichier a pris ce nom pendant la quarantaine, et ne se remet pas ({e}) : il est intact dans {}",
            "another file took this name during quarantine and cannot be put back ({e}): it is intact in {}",
            chemin_affichable(dest)
        )),
    }
}

/// Vanguard administrateur (Windows) écrit la quarantaine dans le profil du compte qui l'a ouvert ainsi, où un
/// programme de ce compte a pu poser une jonction vers un dossier de Windows : chaque dossier jusqu'à la racine du
/// profil est relu avant la création (défense D6a), puis tenu ouvert pendant le geste (`destination_tenue`). Les
/// essais écrivent dans leurs dossiers jetables, hors de tout profil : la règle s'y essaie par
/// `gardes::destination_de_quarantaine` et `tenir`.
#[cfg(windows)]
fn destination_sure(dossier: &Path, absents_permis: bool) -> std::io::Result<()> {
    if eleve_hors_essai() {
        let raison = match crate::machine::windows::environnement::profil() {
            Some(profil) => crate::protection::blocage::gardes::destination_de_quarantaine(
                dossier,
                &profil,
                |d| std::fs::symlink_metadata(d).map(|m| crate::machine::vidage::est_lien(&m)),
                absents_permis,
            ),
            None => Some(tr!(
                "le profil du compte ne se lit pas : Vanguard administrateur ne met rien en quarantaine",
                "the account profile cannot be read: Vanguard as administrator quarantines nothing"
            )),
        };
        if let Some(raison) = raison {
            return Err(std::io::Error::other(raison));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn eleve_hors_essai() -> bool {
    !cfg!(test) && crate::machine::windows::processus::eleve_ou_inconnu()
}

/// En administrateur : chaque dossier, du profil à la quarantaine, tenu ouvert (`tenir`). Ailleurs, rien à tenir.
#[cfg(windows)]
fn destination_tenue(dossier: &Path) -> std::io::Result<Vec<std::fs::File>> {
    if !eleve_hors_essai() {
        return Ok(Vec::new());
    }
    let Some(profil) = crate::machine::windows::environnement::profil() else {
        return Err(std::io::Error::other(tr!(
            "le profil du compte ne se lit pas : Vanguard administrateur ne met rien en quarantaine",
            "the account profile cannot be read: Vanguard as administrator quarantines nothing"
        )));
    };
    tenir(dossier, &profil)
}

/// Ouvre chaque dossier de `profil` jusqu'à `dossier`, de la racine vers le bas, sans suivre un lien
/// (FILE_FLAG_OPEN_REPARSE_POINT) et sans permettre à personne de le renommer ni de l'effacer (pas de
/// FILE_SHARE_DELETE) ; chacun est jugé par sa poignée (`gardes::destination_de_quarantaine`). Tant que les poignées
/// vivent, le chemin désigne ces dossiers-là : aucune jonction ne s'y glisse entre la relecture et l'écriture
/// (relecture de D6a, qui fermait la course par une seconde relecture seulement). Ouvert de haut en bas : chaque
/// dossier s'ouvre au travers de parents déjà tenus.
#[cfg(windows)]
fn tenir(dossier: &Path, profil: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::collections::HashMap;
    use std::io::ErrorKind;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    // FILE_LIST_DIRECTORY : sans droit sur les données, Windows ne retiendrait pas le partage refusé de la poignée.
    const LISTER: u32 = 0x0001;
    const LIRE_ATTRIBUTS: u32 = 0x0080;
    const SYNCHRONISER: u32 = 0x0010_0000;
    const PARTAGE_LIRE_ECRIRE: u32 = 0x1 | 0x2;
    const SANS_SUIVRE_DOSSIER: u32 = 0x0020_0000 | 0x0200_0000;
    const POINT_DE_REANALYSE: u32 = 0x400;
    let n = dossier.components().count().saturating_sub(profil.components().count()) + 1;
    let mut chemins: Vec<&Path> = dossier.ancestors().take(n).collect();
    chemins.reverse();
    let mut tenus = Vec::new();
    // Ce que chaque poignée dit : un lien, ou ce qui l'a empêchée ; tout ce qui est en dessous d'un refus en hérite.
    let mut lus: HashMap<&Path, Result<bool, ErrorKind>> = HashMap::new();
    let mut refus = None;
    for c in chemins {
        if let Some(r) = refus {
            lus.insert(c, r);
            continue;
        }
        let lu = std::fs::OpenOptions::new()
            .access_mode(LISTER | LIRE_ATTRIBUTS | SYNCHRONISER)
            .share_mode(PARTAGE_LIRE_ECRIRE)
            .custom_flags(SANS_SUIVRE_DOSSIER)
            .open(c)
            .and_then(|f| f.metadata().map(|m| (f, m)));
        let verdict = match lu {
            Ok((f, m)) => {
                let lien = m.file_attributes() & POINT_DE_REANALYSE != 0 || !m.is_dir();
                tenus.push(f);
                Ok(lien)
            }
            Err(e) => Err(e.kind()),
        };
        if verdict != Ok(false) {
            refus = Some(verdict);
        }
        lus.insert(c, verdict);
    }
    let raison = crate::protection::blocage::gardes::destination_de_quarantaine(
        dossier,
        profil,
        |a| match lus.get(a) {
            Some(Ok(lien)) => Ok(*lien),
            Some(Err(k)) => Err((*k).into()),
            None => Err(ErrorKind::NotFound.into()),
        },
        false,
    );
    match raison {
        Some(raison) => Err(std::io::Error::other(raison)),
        None => Ok(tenus),
    }
}

/// Le journal lisible par une personne (cat, éditeur), comme avant la 0.61 : noms rendus inoffensifs.
fn noter_journal(dossier: &Path, e: &Entree) {
    use std::io::Write;
    let ligne = format!(
        "{}\t{}\t{}\t{}\n",
        e.date,
        affichable(&e.detection),
        affichable(&e.origine),
        affichable(&e.nom)
    );
    let mut o = std::fs::OpenOptions::new();
    o.create(true).append(true);
    // Jamais au travers d'un lien : un journal.txt changé en lien ferait ajouter la ligne au fichier visé.
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut o, libc::O_NOFOLLOW);
    let _ = o
        .open(dossier.join("journal.txt"))
        .and_then(|mut j| j.write_all(ligne.as_bytes()));
}

/// Ce que le registre et le journal disent de la quarantaine : les entrées admises, et celles écartées parce que
/// leur nom n'est pas un simple nom de fichier du dossier.
struct Liste {
    admises: Vec<Entree>,
    ecartees: Vec<Entree>,
}

/// Un nom du dossier de quarantaine, et rien d'autre : une seule composante ordinaire (ni « .. », ni séparateur, ni
/// racine, ni lecteur ; sous Windows, ni « \\ » ni « : », qui désignerait un flux d'un autre fichier). Le registre et
/// le journal s'écrivent depuis le compte : « ../../etc/x » ferait supprimer, fermer ou sortir un fichier hors de la
/// quarantaine, avec les droits de ce Vanguard-ci (PA-4). Sous Linux, « \\ » est un caractère de nom comme un autre
/// (une archive faite sous Windows) : interdit, le fichier isolé ne se remettait plus.
fn nom_simple(nom: &str) -> bool {
    let interdits: &[char] = if cfg!(windows) {
        &['/', '\\', '\0', ':']
    } else {
        &['/', '\0']
    };
    // Sans séparateur, la seule composante doit être un nom : ni « . », ni « .. », ni un lecteur (« C:x »).
    !nom.contains(interdits)
        && matches!(
            Path::new(nom).components().next(),
            Some(std::path::Component::Normal(_))
        )
}

/// Une origine où remettre : un chemin absolu, jusqu'à un nom de fichier (pas un dossier), qui ne remonte jamais (« .. », même dans
/// un chemin \\?\ de Windows, qui ne les résout pas). `remontee_permise` : l'origine est mot pour mot celle du relevé
/// scellé, écrite par Vanguard d'avant la relecture de PA-4, qui isolait encore un chemin à « .. » (un script lancé
/// par « python3 ../outil.py ») ; la remise le suit dossier par dossier (`ouvrir_l_origine`), comme le noyau l'avait
/// suivi.
fn origine_admise(origine: &str, remontee_permise: bool) -> bool {
    let p = Path::new(origine);
    let separateurs: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    p.is_absolute()
        && p.file_name().is_some()
        && !origine.ends_with(separateurs)
        && !origine.contains('\0')
        && (remontee_permise
            || !p.components().any(|c| {
                matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir) || c.as_os_str() == ".."
            }))
}

/// Tout ce qui est en quarantaine : le registre, puis les fichiers isolés avant la 0.61 (journal.txt seulement),
/// quand leur ligne est fidèle (un nom réécrit pour l'affichage ne se remettrait pas au bon endroit) et le fichier
/// toujours là. Un nom qui n'est pas un simple nom du dossier est écarté (jamais suivi), et compté.
fn lire_liste(dossier: &Path) -> Liste {
    let (mut admises, ecartees): (Vec<Entree>, Vec<Entree>) =
        charger(dossier).fichiers.into_iter().partition(|e| nom_simple(&e.nom));
    let mut liste = Liste {
        admises: Vec::new(),
        ecartees,
    };
    admises.retain(|e| dossier.join(&e.nom).exists());
    // Les noms déjà vus, d'un coup d'œil : registre et journal s'écrivent depuis le compte, et 16 Mio de lignes
    // comparées chacune à toutes les entrées figeaient le menu (relecture de PA-4).
    let mut vus: std::collections::HashSet<String> =
        admises.iter().chain(&liste.ecartees).map(|e| e.nom.clone()).collect();
    let journal = crate::socle::lire_texte_ordinaire(&dossier.join("journal.txt"), 16 << 20).unwrap_or_default();
    for l in journal.lines() {
        let c: Vec<&str> = l.split('\t').collect();
        let [date, detection, origine, nom] = c[..] else {
            continue;
        };
        if vus.contains(nom) || origine.contains('\u{fffd}') || nom.contains('\u{fffd}') {
            continue;
        }
        vus.insert(nom.to_string());
        let entree = Entree {
            nom: nom.to_string(),
            origine: origine.to_string(),
            detection: detection.to_string(),
            date: date.to_string(),
            mode: None,
            sha256: None,
        };
        if !nom_simple(nom) {
            liste.ecartees.push(entree);
        } else if dossier.join(nom).exists() {
            admises.push(entree);
        }
    }
    liste.admises = admises;
    liste
}

/// Les entrées admises de la quarantaine (`lire_liste`).
fn liste_dans(dossier: &Path) -> Vec<Entree> {
    lire_liste(dossier).admises
}

/// Un fichier en quarantaine, pour les traces : (date, origine, détection, empreinte SHA-256).
pub(crate) type PourTraces = (String, String, String, Option<String>);

/// Ce qui est en quarantaine dans `dossier`, pour les traces d'incident : (date, origine, détection, empreinte
/// SHA-256). `Err` : un registre qui n'est pas un fichier ordinaire. La collecte peut tourner en administrateur dans
/// le dossier du compte : un tube nommé à sa place la bloquerait sans fin, un lien ferait lire un autre fichier.
pub(crate) fn pour_traces_dans(dossier: &Path) -> Result<Vec<PourTraces>, Echec> {
    for f in [registre_dans(dossier), dossier.join("journal.txt")] {
        if let Ok(m) = std::fs::symlink_metadata(&f)
            && !m.is_file()
        {
            return Err(Echec::refuse(
                "quarantaine/traces",
                format!("{} : pas un fichier ordinaire / not a regular file", f.display()),
            ));
        }
    }
    // Les entrées écartées aussi : un registre réécrit est une trace de l'incident, pas un bruit à taire. Marquées,
    // avec leur nom : sans marque, elles se liraient comme de vrais fichiers isolés, à l'origine choisie par qui a
    // réécrit le registre (relecture de PA-4).
    let liste = lire_liste(dossier);
    Ok(liste
        .admises
        .into_iter()
        .map(|e| (e.date, e.origine, e.detection, e.sha256))
        .chain(liste.ecartees.into_iter().map(|e| {
            let marquee = format!(
                "[écartée / set aside : « {} » hors du dossier de la quarantaine / outside the quarantine folder] {}",
                e.nom, e.detection
            );
            (e.date, e.origine, marquee, e.sha256)
        }))
        .collect())
}

/// Le registre de la quarantaine a-t-il pu être écrit par un compte qui a moins de droits que ce Vanguard-ci ? En
/// administrateur sous Windows, il vit dans le profil du compte (`destination_sure`) : tout programme de ce compte
/// peut le réécrire. Sous Linux, root n'écrit pas dans le dossier d'un compte (`ecriture_sure`) : la question ne se
/// pose pas.
fn registre_douteux() -> bool {
    #[cfg(windows)]
    {
        eleve_hors_essai()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Le refus de root dans le dossier d'un compte (lancé par sudo -E), dit en un seul endroit pour l'isolement, la remise
/// et la suppression : la garde `aucune_nouvelle_commande_sudo` compte chaque mot d'élévation, messages compris.
fn refus_de_root() -> &'static str {
    tr!(
        "root ne touche pas au dossier d'un compte (sudo -E) : relancez sans sudo",
        "root does not touch an account's folder (sudo -E): start again without sudo"
    )
}

/// Les gardes de l'entrée, avant de remettre ou de supprimer : root ne touche pas au dossier d'un compte (sudo -E),
/// et sous Windows en administrateur chaque dossier du profil à la quarantaine est relu puis tenu pendant le geste.
/// Rend ce qui est tenu (rien hors de Windows).
fn garde_du_dossier(dossier: &Path, ou: &'static str) -> Result<Vec<std::fs::File>, Echec> {
    if !crate::socle::ecriture_sure(dossier) {
        return Err(Echec::refuse(ou, refus_de_root()));
    }
    #[cfg(windows)]
    {
        destination_sure(dossier, false).map_err(|x| Echec::refuse(ou, x.to_string()))?;
        destination_tenue(dossier).map_err(|x| Echec::refuse(ou, x.to_string()))
    }
    #[cfg(not(windows))]
    Ok(Vec::new())
}

/// Ce que le relevé scellé de « Ce que Vanguard a changé » dit du fichier isolé sous `nom` : son chemin et son
/// empreinte relevés juste avant l'isolement (la preuve du blocage). Seule une ligne écrite par Vanguard sous son sceau
/// compte, et seul un blocage encore en place : un fichier en quarantaine n'a pas encore été remis.
fn scelle_de(nom: &str) -> Option<crate::protection::preuve::Fichier> {
    crate::changements::blocages_en_place()
        .into_iter()
        .rev()
        .map(|(_, b)| b)
        .filter(|b| b.origine.is_none())
        .filter(|b| matches!(&b.annulation, Some(crate::changements::Annulation::Quarantaine { nom: n }) if n == nom))
        .find_map(|b| b.preuve.and_then(|p| p.fichier))
}

/// Pourquoi l'entrée `e` ne sort pas de la quarantaine avant même d'y toucher, ou `None`. Le registre s'écrit depuis
/// le compte : le nom reste dans le dossier, l'origine est absolue et ne remonte pas (sauf mot pour mot celle du
/// relevé scellé, `origine_admise`), et elle est celle du relevé scellé quand il y en a un. `exige` (registre
/// douteux, Windows en administrateur) : rien ne sort, la personne reçoit de quoi le faire à la main.
fn refus_d_entree(
    e: &Entree,
    dossier: &Path,
    scelle: Option<&crate::protection::preuve::Fichier>,
    exige: bool,
) -> Option<String> {
    if !nom_simple(&e.nom) {
        return Some(trf!(
            "« {} » n'est pas un simple nom de fichier de la quarantaine (registre changé hors de Vanguard ?) : rien n'est fait",
            "“{}” is not a plain file name of the quarantine (registry changed outside Vanguard?): nothing is done",
            affichable(&e.nom)
        ));
    }
    let comme_scelle = scelle.is_some_and(|s| s.chemin == e.origine);
    if !origine_admise(&e.origine, comme_scelle) {
        return Some(trf!(
            "l'origine notée « {} » n'est pas un chemin complet qui ne remonte pas : rien n'est remis",
            "the noted origin “{}” is not a full path that never goes up: nothing is put back",
            affichable(&e.origine)
        ));
    }
    if let Some(s) = scelle
        && Path::new(&s.chemin) != Path::new(&e.origine)
    {
        return Some(trf!(
            "l'origine notée « {} » n'est pas celle du relevé scellé du blocage (« {} ») : rien n'est remis",
            "the noted origin “{}” is not the one in the block's sealed record (“{}”): nothing is put back",
            affichable(&e.origine),
            affichable(&s.chemin)
        ));
    }
    // Relecture de PA-4 : en administrateur, le registre, le fichier isolé et le relevé lui-même s'écrivent depuis
    // le compte (le sceau aussi) ; Vanguard n'a donc rien de sûr pour décider, et ne sort rien avec ses droits.
    if exige {
        return Some(trf!(
            "en administrateur, Vanguard ne sort rien de la quarantaine : elle vit dans le dossier du compte, que tout programme de ce compte peut réécrire. Relancez Vanguard sans les droits administrateur pour le remettre. {}",
            "as administrator, Vanguard takes nothing out of the quarantine: it lives in the account's folder, which any program of that account can rewrite. Start Vanguard again without administrator rights to put it back. {}",
            sortie_a_la_main(e, dossier)
        ));
    }
    None
}

/// De quoi sortir `e` à la main quand Vanguard refuse : où il est, et ce que le registre en dit. L'empreinte et la
/// destination viennent du registre, qu'un programme du compte peut réécrire : elles sont dites « notées, non
/// vérifiées », et c'est la personne qui juge (contrôle de PA-4, ronde 2 : « attendu » leur prêtait une confiance
/// qu'elles n'ont pas).
fn sortie_a_la_main(e: &Entree, dossier: &Path) -> String {
    let geste = if cfg!(windows) {
        tr!(
            "retirez-lui la lecture seule et le « .vanguard-quarantaine » de la fin de son nom",
            "remove its read-only flag and the “.vanguard-quarantaine” at the end of its name"
        )
    } else {
        tr!("rendez-le lisible (chmod 600)", "make it readable (chmod 600)")
    };
    trf!(
        "À la main : dans {}, le fichier « {} » (SHA-256 noté au registre, non vérifié : {}) ; s'il est bien celui que vous voulez reprendre, {geste}, puis déplacez-le vers « {} » (destination notée au registre : vérifiez que c'est bien là que vous le voulez).",
        "By hand: in {}, the file “{}” (SHA-256 noted in the registry, not verified: {}); if it is indeed the one you want back, {geste}, then move it to “{}” (destination noted in the registry: check that this is where you want it).",
        chemin_affichable(dossier),
        affichable(&e.nom),
        e.sha256
            .as_deref()
            .map_or_else(|| tr!("inconnu", "unknown").to_string(), affichable),
        affichable(&e.origine)
    )
}

/// Les droits spéciaux (setuid, setgid, sticky) notés au registre et jamais remis : de quoi les remettre soi-même,
/// s'ils étaient voulus, plutôt qu'un retrait silencieux. `None` : rien de retiré.
fn bits_retires(mode: Option<u32>, origine: &Path) -> Option<String> {
    let mode = mode?;
    (mode & 0o7000 != 0).then(|| {
        trf!(
            "  ⚠ Ses droits spéciaux notés (setuid, setgid ou sticky : {:o}) ne sont pas remis : le registre peut avoir été réécrit hors de Vanguard. S'ils étaient voulus : chmod {:o} « {} »",
            "  ⚠ Its noted special permissions (setuid, setgid or sticky: {:o}) are not restored: the registry may have been rewritten outside Vanguard. If they were intended: chmod {:o} “{}”",
            mode & 0o7777,
            mode & 0o7777,
            chemin_affichable(origine)
        )
    })
}

/// Remet un fichier à sa place d'origine, avec ses permissions d'avant (sans setuid, setgid ni sticky, dits par
/// `bits_retires`). Refuse d'écraser ce qui l'aurait remplacé, et de sortir un contenu qui n'est plus celui du relevé
/// scellé (`scelle`). `exige` : le registre a pu être écrit par un compte moins privilégié (`registre_douteux`) ; rien
/// ne sort alors.
///
/// Relecture de PA-4 : sous Linux, le dossier d'origine est ouvert dossier par dossier sans suivre un lien qu'un autre
/// compte aurait pu poser (`ouvrir_l_origine`), puis tenu ; le contenu qui sort est celui dont l'empreinte a été lue,
/// sur le même descripteur (`sortir`). Par le chemin, Vanguard en root écrivait au travers d'un lien posé dans
/// /home/alice après l'isolement, et un échange du fichier isolé après sa lecture faisait sortir un autre contenu.
fn remettre_dans(
    e: &Entree,
    dossier: &Path,
    scelle: Option<&crate::protection::preuve::Fichier>,
    exige: bool,
) -> Result<(), Echec> {
    const OU: &str = "quarantaine/remettre";
    let _tenus = garde_du_dossier(dossier, OU)?;
    if let Some(raison) = refus_d_entree(e, dossier, scelle, exige) {
        return Err(Echec::refuse(OU, raison));
    }
    let source = dossier.join(&e.nom);
    let origine = PathBuf::from(&e.origine);
    // Un lien posé dans la quarantaine sous ce nom ferait changer les permissions du fichier qu'il vise.
    if !std::fs::symlink_metadata(&source).is_ok_and(|m| m.is_file()) {
        return Err(Echec::refuse(
            OU,
            tr!(
                "ce nom de la quarantaine n'est pas un fichier ordinaire (un lien ?) : rien n'est remis",
                "this quarantine name is not a regular file (a link?): nothing is put back"
            ),
        ));
    }
    // Rien à sa place, même un lien cassé : la copie d'un disque à l'autre le suivrait jusqu'au fichier qu'il vise.
    if std::fs::symlink_metadata(&origine).is_ok() {
        return Err(Echec::refuse(
            OU,
            tr!(
                "un autre fichier est à sa place : rien n'est écrasé",
                "another file is in its place: nothing is overwritten"
            ),
        ));
    }
    // Le dossier d'origine refusé : rien ne sort, et la personne sait comment le sortir elle-même.
    let arrivee_refusee = |x: std::io::Error| {
        Echec::refuse(
            OU,
            trf!(
                "le dossier d'origine ne s'ouvre pas sans risque ({x}) : rien n'est remis, le fichier reste en quarantaine. {}",
                "the original folder cannot be opened safely ({x}): nothing is put back, the file stays in quarantine. {}",
                sortie_a_la_main(e, dossier)
            ),
        )
    };
    // Le dossier d'arrivée, ouvert et tenu avant de toucher au fichier isolé : refusé, il reste fermé.
    #[cfg(unix)]
    let arrivee = ouvrir_l_origine(&origine).map_err(arrivee_refusee)?;
    // Un contenu isolé sous plusieurs noms (`rejoindre_un_jumeau`) : ce nom-ci sort en copie, les autres restent
    // fermés en quarantaine. Cherchés avant l'empreinte : rien ne passe plus entre sa lecture et la sortie.
    let autres = jumeaux(e, dossier);
    // Il faut pouvoir le lire pour l'empreinte et pour le copier d'un disque à l'autre.
    #[cfg(unix)]
    let _ = std::fs::set_permissions(&source, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    #[cfg(windows)]
    if let Ok(m) = std::fs::symlink_metadata(&source) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // le fichier redevient celui d'avant
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&source, p);
    }
    #[cfg(unix)]
    let lu = match ouvrir_l_isole(dossier, &e.nom) {
        Ok(lu) => lu,
        Err(x) => {
            let _ = fermer(&source);
            return Err(Echec::ecriture(OU, &x));
        }
    };
    // L'empreinte de ce qui sort vraiment : c'est ce contenu-là que la personne reprend, et il doit être celui du
    // relevé scellé (le dossier est celui du compte : un programme a pu y remplacer le fichier isolé).
    #[cfg(unix)]
    let empreinte = crate::protection::empreintes::sha256_de(&lu.source);
    #[cfg(windows)]
    let empreinte = crate::protection::empreintes::sha256(&source);
    if let Some(attendue) = scelle.and_then(|s| s.sha256.as_deref())
        && !empreinte
            .as_ref()
            .is_some_and(|h| crate::protection::empreintes::hex(h).eq_ignore_ascii_case(attendue))
    {
        let _ = fermer(&source);
        // Les deux empreintes, celle lue et celle du relevé : elles diffèrent, et c'est la personne qui décide.
        let lue = empreinte.as_ref().map_or_else(
            || tr!("illisible", "unreadable").to_string(),
            crate::protection::empreintes::hex,
        );
        return Err(Echec::refuse(
            OU,
            trf!(
                "le fichier en quarantaine n'est plus celui relevé au blocage (SHA-256 lu : {lue} ; SHA-256 du relevé : {}) : rien n'est remis. {}",
                "the quarantined file is no longer the one recorded at the block (SHA-256 read: {lue}; SHA-256 of the record: {}): nothing is put back. {}",
                affichable(attendue),
                sortie_a_la_main(e, dossier)
            ),
        ));
    }
    // Sous Windows, chaque dossier de l'origine, de la racine vers le bas, ouvert sans suivre de lien ni de jonction
    // et tenu jusqu'à la sortie ; un dossier disparu est recréé dans son parent tenu (contrôle de PA-4, ronde 2).
    // Après l'empreinte : une remise refusée ne crée rien.
    #[cfg(windows)]
    let _arrivee = match tenir_l_origine(&origine) {
        Ok(tenus) => tenus,
        Err(x) => {
            let _ = fermer(&source);
            return Err(arrivee_refusee(x));
        }
    };
    #[cfg(test)]
    if let Some(f) = AVANT_LA_SORTIE.with(|c| c.borrow_mut().take()) {
        f();
    }
    // Sans mode noté (isolé avant la 0.61) : lecture et écriture pour soi, rien d'exécutable. Jamais setuid, setgid
    // ni sticky : le mode vient d'un registre que le compte peut réécrire.
    #[cfg(unix)]
    let sorti = sortir(&lu, &arrivee, e.mode.unwrap_or(0o600) & 0o777, !autres.is_empty());
    #[cfg(windows)]
    let sorti = sortir_par_le_chemin(&source, &origine, empreinte.as_ref(), !autres.is_empty());
    for autre in &autres {
        let _ = fermer(autre);
    }
    // Resté en quarantaine après un échec : fermé de nouveau, comme avant la tentative.
    if sorti.is_err() && source.exists() {
        let _ = fermer(&source);
    }
    sorti.map_err(|x| Echec::ecriture(OU, &x))?;
    if let Some(ligne) = bits_retires(e.mode, &origine) {
        crate::ui::imprimer(&ligne);
    }
    retirer_du_registre(dossier, &e.nom);
    declarer_remise(empreinte.as_ref(), &origine);
    // Le fichier est revenu : un résultat gardé d'avant (la cache du passage horaire) ne doit pas le cacher.
    crate::autotest::cache::oublier();
    Ok(())
}

/// Le fichier isolé, ouvert pour sa sortie : le dossier de la quarantaine tenu, son nom, et le descripteur lu (sans
/// suivre de lien, sans attendre un tube), d'où viennent l'empreinte et, d'un disque à l'autre, la copie.
#[cfg(unix)]
struct Isole {
    dossier: std::fs::File,
    nom: std::ffi::CString,
    source: std::fs::File,
    identite: Identite,
}

#[cfg(unix)]
fn ouvrir_l_isole(dossier: &Path, nom: &str) -> std::io::Result<Isole> {
    use std::os::unix::fs::OpenOptionsExt;
    let tenu = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dossier)?;
    let nom = std::ffi::CString::new(nom).map_err(|_| std::io::Error::other(tr!("nom invalide", "invalid name")))?;
    let source = std::fs::File::from(ouvrir_dans(
        &tenu,
        &nom,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?);
    let m = source.metadata()?;
    if !m.is_file() {
        return Err(std::io::Error::other(tr!(
            "ce nom de la quarantaine n'est pas un fichier ordinaire : rien n'est remis",
            "this quarantine name is not a regular file: nothing is put back"
        )));
    }
    Ok(Isole {
        dossier: tenu,
        nom,
        source,
        identite: Identite::de(&m),
    })
}

/// Sort le fichier lu (`lu`) vers `arrivee`, sans rien écraser : déplacé (renameat2 sans remplacement), puis relu à
/// l'arrivée ; un autre inode arrivé là (le nom de la quarantaine échangé après la lecture) y retourne, et rien n'est
/// remis. D'un disque à l'autre, ou partagé avec un jumeau : copié depuis le descripteur lu, puis le nom de la
/// quarantaine retiré s'il porte encore cet inode.
#[cfg(unix)]
fn sortir(lu: &Isole, arrivee: &(std::fs::File, std::ffi::CString), mode: u32, jumeaux: bool) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (dossier, nom) = arrivee;
    let partage = jumeaux || lu.identite.liens > 1;
    if !partage {
        lu.source.set_permissions(std::fs::Permissions::from_mode(mode))?;
        match renommer_sans_ecraser(&lu.dossier, &lu.nom, dossier, nom) {
            Ok(()) => {
                let arrive = std::fs::File::from(ouvrir_sans_suivre(dossier, nom)?).metadata();
                if arrive.is_ok_and(|m| Identite::de(&m).meme_fichier(&lu.identite)) {
                    return Ok(());
                }
                let retour = renommer_sans_ecraser(dossier, nom, &lu.dossier, &lu.nom);
                let _ = lu.source.set_permissions(std::fs::Permissions::from_mode(0o000));
                return Err(std::io::Error::other(match retour {
                    Ok(()) => tr!(
                        "le fichier isolé a été échangé pendant la remise : rien n'est remis, l'autre fichier est retourné dans la quarantaine",
                        "the isolated file was swapped during the restore: nothing is put back, the other file went back into the quarantine"
                    )
                    .to_string(),
                    Err(x) => trf!(
                        "le fichier isolé a été échangé pendant la remise, et l'autre fichier ne retourne pas dans la quarantaine ({x}) : supprimez-le de son emplacement d'origine",
                        "the isolated file was swapped during the restore, and the other file cannot go back into the quarantine ({x}): delete it from its original location"
                    ),
                }));
            }
            // Un autre disque, ou un système de fichiers sans « sans remplacement » : la copie, qui ne remplace rien
            // non plus.
            Err(x) if matches!(x.raw_os_error(), Some(libc::EXDEV | libc::EINVAL | libc::ENOSYS)) => {}
            Err(x) => return Err(x),
        }
    }
    copier_vers(&lu.source, dossier, nom, mode)?;
    let retire = le_meme_dans(&lu.dossier, &lu.nom, &lu.identite).and_then(|()| retirer_dans(&lu.dossier, &lu.nom));
    if let Err(x) = retire {
        // Pas de seconde copie, encore utilisable, hors de la quarantaine.
        let _ = retirer_dans(dossier, nom);
        return Err(x);
    }
    Ok(())
}

/// Copie `source` (relu depuis le début) vers un nom neuf de `dossier` : créé exclusivement (jamais au travers d'un
/// lien, jamais par-dessus un fichier), avec `mode`, écrit sur le disque. Retiré si la copie échoue.
#[cfg(unix)]
fn copier_vers(
    source: &std::fs::File,
    dossier: &std::fs::File,
    nom: &std::ffi::CStr,
    mode: u32,
) -> std::io::Result<()> {
    use std::io::Seek;
    use std::os::unix::fs::PermissionsExt;
    let mut lecture = source;
    lecture.seek(std::io::SeekFrom::Start(0))?;
    let mut copie = std::fs::File::from(ouvrir_dans(
        dossier,
        nom,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )?);
    let r = std::io::copy(&mut lecture, &mut copie)
        .and_then(|_| copie.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| copie.sync_all());
    if r.is_err() {
        let _ = retirer_dans(dossier, nom);
    }
    r
}

/// Sous Windows (sans les droits administrateur : en administrateur, `refus_d_entree` ne laisse rien sortir) : par le
/// chemin, dans les dossiers tenus par `tenir_l_origine`, puis l'empreinte relue à l'arrivée ; un autre contenu que
/// celui lu avant (échangé entre-temps), ou un contenu qui ne se relit pas, retourne dans la quarantaine sans rien y
/// écraser, et rien n'est remis. Le compte qui agit est le seul à pouvoir y écrire.
#[cfg(windows)]
fn sortir_par_le_chemin(
    source: &Path,
    origine: &Path,
    empreinte: Option<&[u8; 32]>,
    partage: bool,
) -> std::io::Result<()> {
    // Sans l'empreinte d'avant, rien ne dirait à l'arrivée si c'est le même contenu : rien ne bouge (contrôle de
    // PA-4, ronde 2 : le fichier ressortait puis revenait avec « échangé », ce qui était faux).
    let Some(avant) = empreinte else {
        return Err(std::io::Error::other(tr!(
            "le fichier isolé ne se lit pas (tenu par un autre programme ?) : rien n'est remis, réessayez plus tard",
            "the isolated file cannot be read (held by another program?): nothing is put back, try again later"
        )));
    };
    let sorti = if partage {
        std::fs::copy(source, origine).and_then(|_| std::fs::remove_file(source))
    } else {
        std::fs::rename(source, origine)
            .or_else(|_| std::fs::copy(source, origine).and_then(|_| std::fs::remove_file(source)))
    };
    sorti?;
    let ecart = match a_l_arrivee(avant, crate::protection::empreintes::sha256(origine).as_ref()) {
        Arrivee::Meme => return Ok(()),
        Arrivee::Illisible => tr!(
            "le fichier remis ne se relit pas à l'arrivée (tenu par un autre programme ?) : rien ne dit que c'est le même",
            "the restored file cannot be read again where it landed (held by another program?): nothing shows it is the same"
        ),
        Arrivee::Echange => tr!(
            "le fichier isolé a été échangé pendant la remise",
            "the isolated file was swapped during the restore"
        ),
    };
    // Un lien dur puis le retrait : retourne sans remplacer un nom repris entre-temps.
    let retour = std::fs::hard_link(origine, source).and_then(|()| std::fs::remove_file(origine));
    Err(std::io::Error::other(match retour {
        Ok(()) => trf!(
            "{ecart} : rien n'est remis, le fichier arrivé est retourné dans la quarantaine",
            "{ecart}: nothing is put back, the file that landed went back into the quarantine"
        ),
        Err(x) => trf!(
            "{ecart}, et le fichier arrivé ne retourne pas dans la quarantaine ({x}) : supprimez-le de son emplacement d'origine",
            "{ecart}, and the file that landed cannot go back into the quarantine ({x}): delete it from its original location"
        ),
    }))
}

/// Ce que dit l'empreinte relue à l'arrivée, comparée à celle lue avant la sortie.
#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
enum Arrivee {
    /// Le même contenu : la remise est faite.
    Meme,
    /// L'empreinte ne se relit pas : rien ne prouve que c'est le même contenu.
    Illisible,
    /// Un autre contenu que celui lu avant.
    Echange,
}

#[cfg(any(windows, test))]
fn a_l_arrivee(avant: &[u8; 32], apres: Option<&[u8; 32]>) -> Arrivee {
    match apres {
        Some(a) if a == avant => Arrivee::Meme,
        Some(_) => Arrivee::Echange,
        None => Arrivee::Illisible,
    }
}

/// Chaque dossier de l'origine sous Windows, de la racine du volume jusqu'à son dossier, ouvert sans suivre de lien
/// ni de jonction (FILE_FLAG_OPEN_REPARSE_POINT) et tenu sans permettre à personne de le renommer ni de l'effacer
/// (pas de FILE_SHARE_DELETE), comme `tenir` le fait pour la quarantaine. Un dossier disparu est recréé dans son
/// parent déjà tenu. Un lien ou une jonction (`lien_suivi` : les points d'analyse qui désignent un autre nom, pas les
/// fichiers de OneDrive) est refusé : un autre compte qui remplace un dossier partagé par une jonction vers le
/// dossier Démarrage de la personne y ferait atterrir le fichier remis (contrôle de PA-4, ronde 2).
#[cfg(windows)]
fn tenir_l_origine(origine: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const DOSSIER: u32 = 0x10;
    // Les mêmes drapeaux que `tenir` : lister (sans droit sur les données, Windows ne retiendrait pas le partage
    // refusé), lire les attributs, attendre ; partage en lecture et écriture seulement ; ne rien suivre.
    const LISTER: u32 = 0x0001;
    const LIRE_ATTRIBUTS: u32 = 0x0080;
    const SYNCHRONISER: u32 = 0x0010_0000;
    const PARTAGE_LIRE_ECRIRE: u32 = 0x1 | 0x2;
    const SANS_SUIVRE_DOSSIER: u32 = 0x0020_0000 | 0x0200_0000;
    let Some(parent) = origine.parent() else {
        return Err(std::io::Error::other(tr!("chemin invalide", "invalid path")));
    };
    let mut chemins: Vec<&Path> = parent.ancestors().collect();
    chemins.reverse();
    let mut tenus = Vec::with_capacity(chemins.len());
    for c in chemins {
        let ouvrir = || {
            std::fs::OpenOptions::new()
                .access_mode(LISTER | LIRE_ATTRIBUTS | SYNCHRONISER)
                .share_mode(PARTAGE_LIRE_ECRIRE)
                .custom_flags(SANS_SUIVRE_DOSSIER)
                .open(c)
        };
        let f = match ouvrir() {
            Err(x) if x.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(c)?;
                ouvrir()?
            }
            r => r?,
        };
        let m = f.metadata()?;
        if lien_suivi(c, &m) || m.file_attributes() & DOSSIER == 0 {
            return Err(std::io::Error::other(trf!(
                "« {} » est un lien, une jonction ou n'est pas un dossier : il n'est pas suivi",
                "“{}” is a link, a junction or not a folder: it is not followed",
                chemin_affichable(c)
            )));
        }
        tenus.push(f);
    }
    Ok(tenus)
}

/// `c` (tenu par `m`) mène-t-il ailleurs ? Un point d'analyse « substitut de nom » (lien, jonction, dossier monté)
/// dont la cible se lit, oui. Sans cible (ERROR_NOT_A_REPARSE_POINT) : un dossier ordinaire, celui que la poignée
/// tient (le point retiré entre-temps, ou un point de montage Unix que Wine montre ainsi). Toute autre erreur : oui,
/// on ne suit pas ce qu'on n'a pas pu lire.
#[cfg(windows)]
fn lien_suivi(c: &Path, m: &std::fs::Metadata) -> bool {
    const PAS_UN_POINT_D_ANALYSE: i32 = 4390;
    m.file_type().is_symlink()
        && !matches!(std::fs::read_link(c), Err(x) if x.raw_os_error() == Some(PAS_UN_POINT_D_ANALYSE))
}

/// Le nombre de liens suivis au plus pour atteindre un dossier d'origine, comme le noyau (ELOOP).
#[cfg(unix)]
const LIENS_SUIVIS_MAX: u32 = 40;

/// Le dossier de `origine`, ouvert de la racine vers le bas sans jamais suivre un lien d'un autre compte
/// (`lien_fiable`), les dossiers absents créés au passage, et son nom de fichier. Tenu ouvert, il désigne ce dossier-là
/// jusqu'à la sortie : un lien posé ensuite n'y change rien. « .. » revient au dossier tenu juste avant sur le chemin
/// parcouru (une pile de dossiers ouverts), jamais au parent du moment : un dossier qu'un autre compte déplace pendant
/// la marche ne fait plus remonter ailleurs (contrôle de PA-4, ronde 2). Après un lien, c'est le chemin du lien qui
/// compte, comme pour le noyau quand rien ne bouge.
#[cfg(unix)]
fn ouvrir_l_origine(origine: &Path) -> std::io::Result<(std::fs::File, std::ffi::CString)> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    let invalide = || std::io::Error::other(tr!("chemin invalide", "invalid path"));
    let (Some(parent), Some(nom)) = (origine.parent(), origine.file_name()) else {
        return Err(invalide());
    };
    let nom = std::ffi::CString::new(nom.as_bytes()).map_err(|_| invalide())?;
    let racine = || {
        std::os::unix::fs::OpenOptionsExt::custom_flags(
            std::fs::OpenOptions::new().read(true),
            libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
        .open("/")
    };
    let euid = crate::socle::euid();
    let mut a_faire = composantes(parent);
    // Les dossiers tenus, de la racine à celui atteint : le dernier est « ici », jamais vide.
    let mut pile = vec![racine()?];
    let mut suivis = 0u32;
    while let Some(c) = a_faire.pop_front() {
        let c = std::ffi::CString::new(c.as_bytes()).map_err(|_| invalide())?;
        if c.as_bytes() == b".." {
            #[cfg(test)]
            if let Some(f) = AVANT_LA_REMONTEE.with(|h| h.borrow_mut().take()) {
                f();
            }
            // La racine reste la racine, comme « /.. ».
            if pile.len() > 1 {
                pile.pop();
            }
            continue;
        }
        let ici = pile.last().ok_or_else(invalide)?;
        let fd = match ouvrir_sans_suivre(ici, &c) {
            Err(x) if x.kind() == std::io::ErrorKind::NotFound => {
                creer_dossier_dans(ici, &c)?;
                ouvrir_sans_suivre(ici, &c)?
            }
            r => r?,
        };
        let f = std::fs::File::from(fd);
        let m = f.metadata()?;
        if m.is_dir() {
            pile.push(f);
            continue;
        }
        if !m.file_type().is_symlink() {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR));
        }
        suivis = suivis.saturating_add(1);
        if suivis > LIENS_SUIVIS_MAX {
            return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
        }
        let d = ici.metadata()?;
        #[cfg(test)]
        let d_un_autre = LIEN_D_UN_AUTRE.with(std::cell::Cell::get) == Some((m.dev(), m.ino()));
        #[cfg(not(test))]
        let d_un_autre = false;
        if d_un_autre || !lien_fiable(euid, m.uid(), d.uid(), d.mode()) {
            return Err(std::io::Error::other(trf!(
                "« {} » est un lien qu'un autre compte a pu poser : il n'est pas suivi",
                "“{}” is a link another account could have placed: it is not followed",
                affichable(&c.to_string_lossy())
            )));
        }
        let cible = lire_lien(&f)?;
        let cible = Path::new(&cible);
        if cible.is_absolute() {
            pile.truncate(1);
        }
        for x in composantes(cible).into_iter().rev() {
            a_faire.push_front(x);
        }
    }
    Ok((pile.pop().ok_or_else(invalide)?, nom))
}

/// Les noms à ouvrir un à un pour atteindre `p` : « .. » en est un (un pas en arrière sur le chemin parcouru), la racine et
/// « . » n'en sont pas.
#[cfg(unix)]
fn composantes(p: &Path) -> std::collections::VecDeque<std::ffi::OsString> {
    p.components()
        .filter_map(|c| match c {
            std::path::Component::Normal(n) => Some(n.to_os_string()),
            std::path::Component::ParentDir => Some(std::ffi::OsString::from("..")),
            _ => None,
        })
        .collect()
}

/// Un lien se suit-il vers le dossier d'origine ? Seulement posé par root ou par le compte qui agit, dans un dossier
/// à root ou à ce compte, que personne d'autre ne peut réécrire (ou collant, où un autre ne retire pas le lien d'un
/// autre) : /home vers /var/home, oui ; un lien posé par un autre compte dans son dossier, jamais (Vanguard en root
/// écrirait au travers, dans /etc).
#[cfg(unix)]
fn lien_fiable(euid: u32, uid_lien: u32, uid_dossier: u32, mode_dossier: u32) -> bool {
    let sur = |uid: u32| uid == 0 || uid == euid;
    sur(uid_lien) && sur(uid_dossier) && (mode_dossier & 0o022 == 0 || mode_dossier & 0o1000 != 0)
}

/// openat de `nom` sous `dossier`, avec `drapeaux` et `mode` (à la création).
#[cfg(unix)]
// FFI de libc : openat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn ouvrir_dans(
    dossier: &std::fs::File,
    nom: &std::ffi::CStr,
    drapeaux: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dossier` est un descripteur ouvert,
    // emprunté pendant l'appel ; `mode` est passé par valeur (seulement lu avec O_CREAT).
    let fd = unsafe { libc::openat(dossier.as_raw_fd(), nom.as_ptr(), drapeaux, mode) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` vient d'être rendu par openat, ouvert, et n'appartient à rien d'autre.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// mkdirat d'un dossier absent sous `dossier` (droits par défaut, umask compris, comme `create_dir_all`).
#[cfg(unix)]
// FFI de libc : mkdirat sur un descripteur ouvert, avec un nom en C vivant pendant l'appel.
#[allow(unsafe_code)]
fn creer_dossier_dans(dossier: &std::fs::File, nom: &std::ffi::CStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `nom` est une chaîne C à l'appelant, vivante pendant l'appel ; `dossier` est un descripteur ouvert,
    // emprunté pendant l'appel.
    let r = unsafe { libc::mkdirat(dossier.as_raw_fd(), nom.as_ptr(), 0o777) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// La cible d'un lien ouvert en O_PATH sans le suivre (readlinkat sur le descripteur, nom vide) : celle du lien
/// examiné, pas d'un autre posé entre-temps sous son nom.
#[cfg(unix)]
// FFI de libc : readlinkat sur un descripteur ouvert, dans un tampon à nous dont la taille est passée.
#[allow(unsafe_code)]
fn lire_lien(lien: &std::fs::File) -> std::io::Result<std::ffi::OsString> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    let mut tampon = vec![0u8; 4096];
    // SAFETY: le nom vide est une chaîne C statique ; `tampon` nous appartient, vivant pendant l'appel, et sa taille
    // exacte est passée : readlinkat n'y écrit pas au-delà.
    let n = unsafe { libc::readlinkat(lien.as_raw_fd(), c"".as_ptr(), tampon.as_mut_ptr().cast(), tampon.len()) };
    let n = usize::try_from(n).map_err(|_| std::io::Error::last_os_error())?;
    if n >= tampon.len() {
        return Err(std::io::Error::from_raw_os_error(libc::ENAMETOOLONG));
    }
    tampon.truncate(n);
    Ok(std::ffi::OsString::from_vec(tampon))
}

/// renameat2 sans remplacement : `nom` de `de` devient `vers_nom` de `vers`, seulement si ce nom est libre (jamais
/// un fichier écrasé, ni un lien suivi). Par l'appel système : la musl livrée avec Rust n'a pas sa fonction.
#[cfg(unix)]
// Appel système brut : renameat2 sur deux descripteurs ouverts, avec des noms en C vivants pendant l'appel.
#[allow(unsafe_code)]
fn renommer_sans_ecraser(
    de: &std::fs::File,
    nom: &std::ffi::CStr,
    vers: &std::fs::File,
    vers_nom: &std::ffi::CStr,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `nom` et `vers_nom` sont des chaînes C à l'appelant, vivantes pendant l'appel ; `de` et `vers` sont
    // des descripteurs ouverts, empruntés pendant l'appel.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            de.as_raw_fd(),
            nom.as_ptr(),
            vers.as_raw_fd(),
            vers_nom.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Retient que la personne a sorti ce contenu exact de la quarantaine (`normales::cle_remise`, 90 jours) : ni la
/// passe horaire ni le temps réel ne l'y remettent tout seuls, sans quoi l'annulation serait défaite à leur passage ;
/// un autre contenu au même nom est examiné de nouveau. Sans empreinte lue ou sans liste écrite, c'est dit.
fn declarer_remise(empreinte: Option<&[u8; 32]>, origine: &Path) {
    let retenu = empreinte
        .ok_or_else(|| tr!("contenu illisible", "unreadable content").to_string())
        .and_then(|e| {
            crate::protection::normales::declarer(
                &crate::protection::normales::cle_remise(e, origine),
                crate::reseau::tableau::nom_genre(crate::reseau::tableau::Genre::Blocage),
                tr!("Sorti de la quarantaine", "Taken out of quarantine"),
                &affichable(&origine.to_string_lossy()),
            )
            .map_err(|x| x.to_string())
        });
    if let Err(x) = retenu {
        trp!(
            "  ⚠ Non retenu ({x}) : une prochaine analyse peut le remettre en quarantaine.",
            "  ⚠ Not remembered ({x}): a later scan may put it back in quarantine."
        );
    }
}

/// Remet à sa place le fichier isolé sous ce nom (l'annulation d'un blocage) ; mêmes gardes que le menu : rien n'est
/// écrasé, et le contenu qui sort est celui de `scelle`, la preuve du blocage relue sous son sceau.
pub(crate) fn remettre(nom: &str, scelle: Option<&crate::protection::preuve::Fichier>) -> Result<(), Echec> {
    let dossier = dossier();
    let e = liste_dans(&dossier).into_iter().find(|e| e.nom == nom).ok_or_else(|| {
        Echec::new("quarantaine/remettre", Raison::Introuvable)
            .detail(tr!("plus dans la quarantaine", "no longer in the quarantine"))
    })?;
    remettre_dans(&e, &dossier, scelle, registre_douteux())
}

/// Le nombre de fichiers en quarantaine sur cet ordinateur.
pub(crate) fn nombre() -> usize {
    nombre_dans(&dossier())
}

/// Le nombre de fichiers isolés dans le dossier de quarantaine `dossier`.
pub(crate) fn nombre_dans(dossier: &Path) -> usize {
    liste_dans(dossier).len()
}

/// Supprime pour de bon un fichier de la quarantaine, et seulement là : un nom du dossier, un fichier ordinaire.
fn supprimer_dans(e: &Entree, dossier: &Path) -> Result<(), Echec> {
    const OU: &str = "quarantaine/supprimer";
    let _tenus = garde_du_dossier(dossier, OU)?;
    if !nom_simple(&e.nom) {
        return Err(Echec::refuse(
            OU,
            trf!(
                "« {} » n'est pas un simple nom de fichier de la quarantaine (registre changé hors de Vanguard ?) : rien n'est supprimé",
                "“{}” is not a plain file name of the quarantine (registry changed outside Vanguard?): nothing is deleted",
                affichable(&e.nom)
            ),
        ));
    }
    let chemin = dossier.join(&e.nom);
    if !std::fs::symlink_metadata(&chemin).is_ok_and(|m| m.is_file()) {
        return Err(Echec::refuse(
            OU,
            tr!(
                "ce nom de la quarantaine n'est pas un fichier ordinaire (un lien ?) : rien n'est supprimé",
                "this quarantine name is not a regular file (a link?): nothing is deleted"
            ),
        ));
    }
    #[cfg(windows)]
    if let Ok(m) = std::fs::symlink_metadata(&chemin) {
        let mut p = m.permissions();
        #[allow(clippy::permissions_set_readonly_false)] // il va être supprimé
        p.set_readonly(false);
        let _ = std::fs::set_permissions(&chemin, p);
    }
    let r = std::fs::remove_file(&chemin);
    // Le même contenu sous un autre nom (`rejoindre_un_jumeau`) reste fermé.
    for autre in jumeaux(e, dossier) {
        let _ = fermer(&autre);
    }
    r.map_err(|x| Echec::ecriture(OU, &x))?;
    retirer_du_registre(dossier, &e.nom);
    Ok(())
}

fn retirer_du_registre(dossier: &Path, nom: &str) {
    let mut r = charger(dossier);
    let avant = r.fichiers.len();
    r.fichiers.retain(|x| x.nom != nom);
    if r.fichiers.len() != avant {
        let _ = enregistrer(dossier, &r);
    }
}

/// Après une analyse : propose d'isoler les fichiers trouvés, (chemin, détection). Rien sans accord.
pub fn proposer(trouves: &[(PathBuf, String)]) {
    if trouves.is_empty() {
        return;
    }
    let rep = demander(tr!(
        "\n  Les mettre en quarantaine (réversible : menu Virus et logiciels espions › Quarantaine) ? [o/N] : ",
        "\n  Quarantine them (reversible: menu Viruses and spyware › Quarantine)? [y/N]: "
    ));
    if !rep.oui() {
        trp!(
            "  Rien n'a été fait : les fichiers restent à leur place.",
            "  Nothing was done: the files stay where they are."
        );
        return;
    }
    for (chemin, detection) in trouves {
        let montre = chemin_affichable(chemin);
        match isoler_trouve(chemin, detection) {
            Ok(_) => println!("  {VERT}✔{RESET} {montre}"),
            Err(e) => {
                let conseil = conseil_d_echec(&e);
                trp!("  ✖ {montre} : {e}{conseil}", "  ✖ {montre}: {e}{conseil}");
            }
        }
    }
}

/// Un fichier trouvé par une analyse, mis en quarantaine. Son chemin est rendu complet et direct avant le relevé :
/// la quarantaine refuse un chemin relatif ou qui remonte (elle ne saurait pas où le remettre), et la remise compare
/// l'origine notée, mot pour mot, au chemin du relevé (contrôle de PA-4, ronde 2 : « vanguard yara . » laissait le
/// fichier détecté en place).
fn isoler_trouve(chemin: &Path, detection: &str) -> std::io::Result<PathBuf> {
    let chemin = chemin_direct(chemin.to_path_buf());
    isoler(&chemin, detection, demande_d_analyse(&chemin, detection))
}

/// Le conseil qui suit un échec de l'isolement : les droits administrateur seulement quand ce sont des droits qui ont
/// manqué ; pour un chemin refusé ou un fichier changé, le message dit déjà quoi faire.
fn conseil_d_echec(e: &std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        tr!(
            " (fichier du système ? relancer avec les droits administrateur)",
            " (system file? run again with administrator rights)"
        )
    } else {
        ""
    }
}

/// Le chemin complet et direct de `fichier` (sans « .. »), à prendre avant le relevé de la quarantaine : sous Linux,
/// son dossier résolu par le système (le même fichier, le même dossier ; relatif, depuis le dossier courant), son nom
/// gardé ; sous Windows, résolu sans toucher au disque, comme Windows le fait. Irrésoluble : tel quel, et
/// `isoler_dans` dira pourquoi il refuse.
pub(crate) fn chemin_direct(fichier: PathBuf) -> PathBuf {
    #[cfg(unix)]
    {
        let (Some(dossier), Some(nom)) = (fichier.parent(), fichier.file_name()) else {
            return fichier;
        };
        // « outil.bin » seul : son dossier est le dossier courant (`parent` le rend vide).
        let dossier = if dossier.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dossier
        };
        match std::fs::canonicalize(dossier) {
            Ok(d) => d.join(nom),
            Err(_) => fichier,
        }
    }
    #[cfg(windows)]
    {
        std::path::absolute(&fichier).unwrap_or(fichier)
    }
}

/// Menu Antivirus et protection › Quarantaine (`vanguard quarantaine`) : ce qui est isolé, à remettre ou à supprimer.
pub fn menu() {
    titre(tr!("Quarantaine", "Quarantine"));
    let dossier = dossier();
    loop {
        let Liste {
            admises: fichiers,
            ecartees,
        } = lire_liste(&dossier);
        // Écartées, jamais tues : un registre réécrit hors de Vanguard se dit, avec leurs noms et de quoi les retirer
        // (relecture de PA-4 : un compte seul ne disait pas lesquelles).
        if !ecartees.is_empty() {
            let n = ecartees.len();
            trp!(
                "  ⚠ {n} entrée(s) du registre écartée(s) : leur nom sort du dossier\n    de la quarantaine (registre changé hors de Vanguard ?).\n    Rien n'en est fait.",
                "  ⚠ {n} registry entry(ies) set aside: their name leaves the\n    quarantine folder (registry changed outside Vanguard?).\n    Nothing is done with them."
            );
            for e in ecartees.iter().take(5) {
                println!(
                    "      {GRIS}« {} » → {}{RESET}",
                    affichable(&e.nom),
                    affichable(&e.origine)
                );
            }
            if n > 5 {
                trp!(
                    "      {GRIS}… et {} autre(s){RESET}",
                    "      {GRIS}… and {} more{RESET}",
                    n.saturating_sub(5)
                );
            }
            trp!(
                "    Pour les retirer : dans {}, effacez leurs lignes de\n    quarantaine.json et de journal.txt.",
                "    To remove them: in {}, delete their lines from\n    quarantaine.json and journal.txt.",
                chemin_affichable(&dossier)
            );
        }
        if fichiers.is_empty() {
            trp!("  La quarantaine est vide.", "  The quarantine is empty.");
            return;
        }
        for (i, e) in fichiers.iter().enumerate() {
            println!(
                "  {TOUCHE}{:>2}{RESET}  {}",
                i.saturating_add(1),
                affichable(&e.origine)
            );
            println!(
                "      {GRIS}{} · {}{RESET}",
                affichable(&e.detection),
                e.date.get(..16).unwrap_or(&e.date)
            );
            if let Some(h) = &e.sha256 {
                println!("      {GRIS}SHA-256 {h}{RESET}");
            }
        }
        let choix = crate::selection::demander_ou_revenir(tr!(
            "\n  Numéro du fichier (Entrée pour revenir) : ",
            "\n  File number (Enter to go back): "
        ));
        let Some(e) = choix
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|n| n.checked_sub(1))
            .and_then(|i| fichiers.get(i))
        else {
            return;
        };
        let montre = affichable(&e.origine);
        println!("\n  « {montre} »");
        let supprimer = tr!("s", "d");
        let Some(action) = crate::selection::choisir_en_ligne(
            &[
                (
                    "r",
                    tr!(
                        "Remettre à sa place (faux positif)",
                        "Restore to its place (false positive)"
                    ),
                ),
                (supprimer, tr!("Supprimer pour de bon", "Delete for good")),
            ],
            &trf!(
                "  r : remettre à sa place · {supprimer} : supprimer pour de bon · Entrée : rien : ",
                "  r: restore to its place · {supprimer}: delete for good · Enter: nothing: "
            ),
        ) else {
            continue;
        };
        let resultat = if action == "r" {
            remettre_dans(e, &dossier, scelle_de(&e.nom).as_ref(), registre_douteux())
        } else {
            supprimer_dans(e, &dossier)
        };
        match resultat {
            Ok(()) => {
                // Sorti de la quarantaine : le blocage qui l'y avait mis n'est plus à annuler.
                crate::changements::marquer_annule_quarantaine(&e.nom, action.trim() != "r");
                trp!("  {VERT}✔{RESET} Fait.", "  {VERT}✔{RESET} Done.");
            }
            Err(x) => trp!("  ✖ {x}", "  ✖ {x}"),
        }
        println!();
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Retiré à la fin de l'essai, même fermé ou après une panique (M-1 de la relecture des restes c6).
    fn jetable(nom: &str) -> crate::essais::Jetable {
        crate::essais::Jetable::nouveau(&format!("quarantaine-{nom}"))
    }

    /// Relecture de D6a : chaque dossier du profil à la quarantaine est tenu pendant le geste ; ni lui ni un parent ne
    /// se renomme ni ne s'efface (une jonction ne peut donc pas prendre sa place), puis tout se libère. Hors du
    /// profil, ou un fichier à la place d'un dossier : refusé.
    #[cfg(windows)]
    #[test]
    fn quarantaine_tenue_pendant_le_geste() {
        let profil = jetable("tenue");
        let q = profil
            .join("AppData")
            .join("Local")
            .join("vanguard")
            .join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        let tenus = tenir(&q, &profil).unwrap();
        assert_eq!(tenus.len(), 5);
        let local = profil.join("AppData").join("Local");
        assert!(std::fs::rename(local.join("vanguard"), local.join("ailleurs")).is_err());
        assert!(std::fs::rename(&q, local.join("vanguard").join("autre")).is_err());
        assert!(std::fs::remove_dir(&q).is_err());
        drop(tenus);
        std::fs::rename(&q, local.join("vanguard").join("autre")).unwrap();
        std::fs::write(&q, b"pas un dossier").unwrap();
        assert!(tenir(&q, &profil).is_err());
        assert!(tenir(&q, &profil.join("autre-compte")).is_err());
    }

    #[test]
    fn isole_puis_remet_a_l_identique() {
        let maison = jetable("maison");
        let q = maison.join("quarantaine");
        let fichier = maison.join("Téléchargements").join("facture.pdf.exe");
        std::fs::create_dir_all(fichier.parent().unwrap()).unwrap();
        std::fs::write(&fichier, b"MZ contenu").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&fichier, std::os::unix::fs::PermissionsExt::from_mode(0o751)).unwrap();
        let dest = isoler_dans(&fichier, "Win32.Trojan.Exemple", &q, Some("ab".repeat(32)), None).unwrap();
        assert!(!fichier.exists() && dest.exists());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&dest).unwrap().permissions()) & 0o777,
            0
        );
        let liste = liste_dans(&q);
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, fichier.to_string_lossy());
        assert_eq!(liste[0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        // Un autre fichier a pris sa place : rien n'est écrasé.
        std::fs::write(&fichier, b"nouveau").unwrap();
        let oublis = crate::autotest::cache::OUBLIS.with(std::cell::Cell::get);
        assert!(remettre_dans(&liste[0], &q, None, false).is_err());
        assert_eq!(std::fs::read(&fichier).unwrap(), b"nouveau");
        assert_eq!(crate::autotest::cache::OUBLIS.with(std::cell::Cell::get), oublis);
        std::fs::remove_file(&fichier).unwrap();
        // Remis : même contenu, mêmes permissions, sorti du registre, et la cache vidée (reste du lot L6c).
        remettre_dans(&liste[0], &q, None, false).unwrap();
        assert_eq!(crate::autotest::cache::OUBLIS.with(std::cell::Cell::get), oublis + 1);
        assert_eq!(std::fs::read(&fichier).unwrap(), b"MZ contenu");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&fichier).unwrap().permissions()) & 0o777,
            0o751
        );
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        // Sorti par la personne : ce contenu exact à ce chemin est retenu (décidé : il n'y retourne pas tout seul) ;
        // un autre contenu au même nom, non.
        let normale = |contenu: &[u8]| {
            let e = crate::protection::empreintes::sha256_de(contenu).unwrap();
            crate::protection::normales::est_normale(&crate::protection::normales::cle_remise(&e, &fichier))
        };
        assert!(normale(b"MZ contenu"));
        assert!(!normale(b"MZ autre contenu"));
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Décidé : un contenu déjà en quarantaine n'y entre pas deux fois (un second nom du même fichier isolé, pas de
    /// seconde copie), mais le fichier trouvé quitte quand même son dossier ; chaque nom se remet à part, avec son
    /// origine et son mode, et l'autre reste fermé ; un autre contenu reste une copie à part. Sous Windows, chaque
    /// fichier garde sa copie (sa marque du web), et se remet de même.
    #[test]
    fn meme_contenu_isole_une_fois() {
        let maison = jetable("jumeaux");
        let q = maison.join("quarantaine");
        let telecharges = maison.join("Téléchargements");
        std::fs::create_dir_all(&telecharges).unwrap();
        let (a, b, autre) = (
            telecharges.join("a.exe"),
            telecharges.join("b.exe"),
            telecharges.join("c.exe"),
        );
        std::fs::write(&a, b"MZ jumeau").unwrap();
        std::fs::write(&b, b"MZ jumeau").unwrap();
        std::fs::write(&autre, b"MZ autre").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&b, std::os::unix::fs::PermissionsExt::from_mode(0o640)).unwrap();
        // La preuve de « a » n'avait pas d'empreinte : celle relue est notée, et sert au suivant.
        let da = isoler_dans(&a, "X", &q, None, None).unwrap();
        let db = isoler_dans(&b, "X", &q, Some("cd".repeat(32)), None).unwrap();
        let d_autre = isoler_dans(&autre, "X", &q, None, None).unwrap();
        assert!(
            !a.exists() && !b.exists() && !autre.exists(),
            "chaque fichier trouvé quitte son dossier"
        );
        assert!(da != db && d_autre.exists());
        let liste = liste_dans(&q);
        assert_eq!(liste.len(), 3);
        assert_ne!(liste[0].sha256, liste[2].sha256);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(liste[0].sha256, liste[1].sha256, "l'empreinte relue des deux côtés");
            let ma = std::fs::metadata(&da).unwrap();
            assert_eq!(ma.ino(), std::fs::metadata(&db).unwrap().ino(), "pas de seconde copie");
            assert_ne!(ma.ino(), std::fs::metadata(&d_autre).unwrap().ino());
            assert_eq!(ma.nlink(), 2);
            assert_eq!(ma.permissions().mode() & 0o777, 0);
        }
        // « b » sort : son origine, son contenu, son mode ; « a » reste en quarantaine, fermé et intact.
        remettre_dans(&liste[1], &q, None, false).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"MZ jumeau");
        assert!(da.exists() && !db.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            assert_eq!(std::fs::metadata(&b).unwrap().permissions().mode() & 0o777, 0o640);
            let ma = std::fs::metadata(&da).unwrap();
            assert_eq!(ma.permissions().mode() & 0o777, 0, "l'autre nom reste fermé");
            assert_eq!(ma.nlink(), 1);
        }
        #[cfg(unix)]
        assert_eq!(contenu_isole(&da), liste[0].sha256);
        // Isolé de nouveau, puis supprimé pour de bon sous ce nom : l'autre ne bouge pas.
        let db = isoler_dans(&b, "X", &q, None, None).unwrap();
        let liste = liste_dans(&q);
        let eb = liste.iter().find(|x| q.join(&x.nom) == db).unwrap();
        supprimer_dans(eb, &q).unwrap();
        assert!(da.exists() && !db.exists());
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&da).unwrap().permissions()) & 0o777,
            0
        );
        remettre_dans(&liste[0], &q, None, false).unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"MZ jumeau");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Un lien dur glissé sous le nom examiné (vers un fichier de la personne) n'est jamais isolé ni rendu illisible ;
    /// un fichier à plusieurs noms non plus ; le fichier examiné, lui, l'est.
    #[cfg(unix)]
    #[test]
    fn lien_dur_jamais_isole() {
        use std::os::unix::fs::PermissionsExt;
        let d = jetable("lien-dur");
        let q = d.join("quarantaine");
        let colis = d.join("colis.exe");
        let precieux = d.join("bashrc");
        std::fs::write(&colis, b"MZ examine").unwrap();
        std::fs::write(&precieux, b"export PS1=alice").unwrap();
        std::fs::set_permissions(&precieux, PermissionsExt::from_mode(0o644)).unwrap();
        let examine = Identite::de(&std::fs::symlink_metadata(&colis).unwrap());
        assert_eq!(examine.liens, 1);
        // Après l'examen, le nom devient un lien dur vers le fichier de la personne.
        std::fs::remove_file(&colis).unwrap();
        std::fs::hard_link(&precieux, &colis).unwrap();
        assert!(isoler_dans(&colis, "Test.Fichier", &q, None, Some(examine)).is_err());
        // Même sans identité attendue : deux noms, rien n'est fait.
        assert!(isoler_dans(&colis, "Test.Fichier", &q, None, None).is_err());
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&precieux), 0o644);
        assert_eq!(mode(&colis), 0o644);
        assert_eq!(std::fs::read(&precieux).unwrap(), b"export PS1=alice");
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        // La copie d'un disque à l'autre relit aussi l'identité : rien n'est copié.
        let ailleurs = d.join("copie");
        let (tenu, nom) = tenir_le_dossier(&colis).unwrap();
        assert!(copier_le_meme(&tenu, &nom, &ailleurs, &examine).is_err());
        assert!(!ailleurs.exists());
        // Le fichier examiné, à son nom, part en quarantaine.
        std::fs::remove_file(&colis).unwrap();
        std::fs::write(&colis, b"MZ examine").unwrap();
        let examine = Identite::de(&std::fs::symlink_metadata(&colis).unwrap());
        let dest = isoler_dans(&colis, "Test.Fichier", &q, None, Some(examine)).unwrap();
        assert!(!colis.exists());
        assert_eq!(mode(&dest), 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Un autre inode arrivé dans la quarantaine retourne à son nom sans rien écraser ; un nom repris le laisse où il
    /// est, intact.
    #[cfg(unix)]
    #[test]
    fn autre_inode_remis_a_son_nom() {
        let d = jetable("remis");
        let dest = d.join("123.colis.exe");
        let chemin = d.join("colis.exe");
        std::fs::write(&dest, b"fichier de la personne").unwrap();
        let (q, nom_q) = tenir_le_dossier(&dest).unwrap();
        let (tenu, nom) = tenir_le_dossier(&chemin).unwrap();
        let _ = remettre_le_nom(&q, &nom_q, &dest, &tenu, &nom);
        assert!(!dest.exists());
        assert_eq!(std::fs::read(&chemin).unwrap(), b"fichier de la personne");
        std::fs::write(&dest, b"second").unwrap();
        let e = remettre_le_nom(&q, &nom_q, &dest, &tenu, &nom);
        assert!(e.to_string().contains("123.colis.exe"), "{e}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"second");
        assert_eq!(std::fs::read(&chemin).unwrap(), b"fichier de la personne");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Le journal de la quarantaine se lit avec cat : un nom piégé n'y pilote pas le terminal, et ses tabulations ou
    /// sauts de ligne ne cassent pas les quatre colonnes.
    /// journal.txt changé en lien par un autre programme : la ligne n'est pas ajoutée au fichier visé. Et en root, le
    /// dossier de quarantaine d'un compte (le nôtre ici) est refusé par la règle que `isoler_dans` applique.
    #[cfg(unix)]
    #[test]
    fn journal_en_lien_jamais_suivi() {
        let d = jetable("lien");
        let q = d.join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        let cible = d.join("ld.so.preload");
        std::fs::write(&cible, b"").unwrap();
        std::os::unix::fs::symlink(&cible, q.join("journal.txt")).unwrap();
        let f = d.join("x.so");
        std::fs::write(&f, b"x").unwrap();
        isoler_dans(&f, "Test.Fichier", &q, None, None).unwrap();
        assert_eq!(std::fs::read(&cible).unwrap(), b"");
        if crate::socle::uid() == 0 {
            return crate::essais::saute("lancé en root : un dossier à soi est à root");
        }
        assert!(!crate::socle::ecriture_sure_pour(0, &q));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn journal_de_quarantaine_sans_piege() {
        let d = jetable("journal");
        noter_journal(
            &d,
            &Entree {
                nom: "x.q".into(),
                origine: "/home/alice/a\tb\x1b[2K\nc".into(),
                detection: "Eicar\x07".into(),
                date: "2026-10-18 23:00:00".into(),
                mode: None,
                sha256: None,
            },
        );
        let journal = std::fs::read_to_string(d.join("journal.txt")).unwrap();
        assert_eq!(journal.lines().count(), 1, "{journal:?}");
        let champs: Vec<&str> = journal.trim_end().split('\t').collect();
        assert_eq!(champs.len(), 4, "{journal:?}");
        assert_eq!(champs[1], "Eicar\u{fffd}");
        assert_eq!(champs[2], "/home/alice/a\u{fffd}b\u{fffd}[2K\u{fffd}c");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn anciennes_lignes_du_journal_et_suppression() {
        let q = jetable("ancien");
        // Isolé avant la 0.61 : journal.txt seulement.
        std::fs::write(q.join("123.outil.sh"), b"#!/bin/sh").unwrap();
        std::fs::write(
            q.join("journal.txt"),
            "2026-10-01 10:00:00\tEicar\t/home/alice/outil.sh\t123.outil.sh\n\
             2026-10-01 10:00:01\tEicar\t/home/alice/pi\u{fffd}ge.sh\t124.pi\u{fffd}ge.sh\n\
             2026-10-01 10:00:02\tEicar\t/home/alice/parti.sh\t125.parti.sh\n",
        )
        .unwrap();
        let liste = liste_dans(&q);
        // Le nom réécrit pour l'affichage et le fichier disparu ne sont pas proposés.
        assert_eq!(liste.len(), 1);
        assert_eq!(liste[0].origine, "/home/alice/outil.sh");
        assert_eq!(liste[0].mode, None);
        supprimer_dans(&liste[0], &q).unwrap();
        assert_eq!(liste_dans(&q), Vec::<Entree>::new());
        let _ = std::fs::remove_dir_all(&q);
    }
    /// Le registre s'écrit depuis le compte (PA-4) : un nom qui remonte (« .. ») n'est ni proposé, ni supprimé, ni
    /// traité en jumeau ; une origine qui remonte ne reçoit rien.
    #[test]
    fn registre_reecrit_rien_hors_de_la_quarantaine() {
        let maison = jetable("registre");
        let q = maison.join("quarantaine");
        let victime = maison.join("victime");
        std::fs::write(&victime, b"a moi").unwrap();
        let f = maison.join("x.exe");
        std::fs::write(&f, b"MZ x").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let legit = liste_dans(&q)[0].clone();
        // Forgée : un nom vers la victime, la même empreinte que l'entrée de Vanguard (un « jumeau »).
        let forgee = Entree {
            nom: "../victime".into(),
            origine: maison.join("ailleurs").to_string_lossy().into_owned(),
            ..legit.clone()
        };
        let mut r = charger(&q);
        r.fichiers.push(forgee.clone());
        enregistrer(&q, &r).unwrap();
        assert!(
            liste_dans(&q).iter().all(|e| e.nom != forgee.nom),
            "nom qui remonte proposé"
        );
        assert!(supprimer_dans(&forgee, &q).is_err());
        assert!(remettre_dans(&forgee, &q, None, false).is_err());
        assert_eq!(std::fs::read(&victime).unwrap(), b"a moi");
        assert!(!maison.join("ailleurs").exists());
        // Une origine qui remonte : refusée, rien n'est écrit là où elle mène.
        let remonte = Entree {
            origine: format!("{}/a/../b", maison.display()),
            ..legit.clone()
        };
        assert!(remettre_dans(&remonte, &q, None, false).is_err());
        assert!(!maison.join("b").exists() && !maison.join("a").exists());
        // L'entrée de Vanguard sort, et la victime (le « jumeau » forgé) n'est pas touchée.
        remettre_dans(&legit, &q, None, false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"MZ x");
        assert_eq!(std::fs::read(&victime).unwrap(), b"a moi");
        #[cfg(unix)]
        assert_ne!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&victime).unwrap().permissions()) & 0o777,
            0,
            "la victime a été fermée comme jumeau"
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Les noms et origines que le registre peut porter (PA-4) : un simple nom du dossier, une origine complète qui ne
    /// remonte pas ; les entrées écartées sont comptées, et les traces les gardent.
    #[test]
    fn noms_et_origines_du_registre() {
        for bon in ["1730000000.facture.pdf.exe", "123.outil.sh", ".cache"] {
            assert!(nom_simple(bon), "{bon}");
        }
        for mauvais in ["", ".", "..", "../x", "a/b", "/etc/x", "x\0y"] {
            assert!(!nom_simple(mauvais), "{mauvais:?}");
        }
        // « \ » sépare sous Windows ; ailleurs, c'est un caractère de nom (relecture de PA-4).
        assert_eq!(nom_simple("a\\b"), !cfg!(windows));
        assert_eq!(nom_simple(r"\\?\C:\x"), !cfg!(windows));
        // Sous Windows, « C:x » vise un lecteur et « a:b » un flux d'un autre fichier ; ailleurs, des noms ordinaires.
        assert_eq!(nom_simple("C:x"), !cfg!(windows));
        assert_eq!(nom_simple("a:b.exe"), !cfg!(windows));
        let maison = jetable("origines");
        let absolu = |reste: &str| format!("{}{reste}", maison.display());
        assert!(origine_admise(&absolu("/Téléchargements/a.exe"), false));
        // Mot pour mot l'origine du relevé scellé : « .. » permis, le reste non.
        assert!(origine_admise(&absolu("/a/../b"), true));
        assert!(!origine_admise("a/../b", true));
        for mauvais in [
            "a.exe".to_string(),
            absolu("/a/../b"),
            absolu("/.."),
            absolu("/"),
            String::new(),
        ] {
            assert!(!origine_admise(&mauvais, false), "{mauvais:?}");
        }
        #[cfg(windows)]
        assert!(!origine_admise(
            r"\\?\C:\Users\alice\..\..\Windows\System32\x.dll",
            false
        ));
        // Le registre et le journal d'avant la 0.61 : chacun une entrée qui sort du dossier, écartée et comptée.
        let q = maison.join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::write(maison.join("victime"), b"a moi").unwrap();
        std::fs::write(q.join("123.outil.sh"), b"#!/bin/sh").unwrap();
        let forgee = Entree {
            nom: "../victime".into(),
            origine: absolu("/ailleurs"),
            detection: "X".into(),
            date: "2026-11-12 10:00:00".into(),
            mode: None,
            sha256: None,
        };
        enregistrer(
            &q,
            &Registre {
                fichiers: vec![forgee.clone()],
            },
        )
        .unwrap();
        std::fs::write(
            q.join("journal.txt"),
            format!(
                "2026-10-01 10:00:00\tEicar\t{}\t123.outil.sh\n2026-10-01 10:00:01\tEicar\t{}\t../../victime\n",
                absolu("/outil.sh"),
                absolu("/x")
            ),
        )
        .unwrap();
        let liste = lire_liste(&q);
        assert_eq!(liste.admises.len(), 1);
        assert_eq!(liste.admises[0].nom, "123.outil.sh");
        assert_eq!(liste.ecartees.len(), 2);
        assert_eq!(nombre_dans(&q), 1);
        assert_eq!(
            pour_traces_dans(&q).unwrap().len(),
            3,
            "les écartées restent dans les traces"
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le relevé scellé du blocage décide de la sortie (PA-4) : une origine réécrite dans le registre, ou un contenu
    /// remplacé dans la quarantaine, ne sort pas ; en administrateur (registre douteux), rien ne sort sans relevé
    /// scellé qui porte une empreinte ; le bon relevé, lui, fait sortir le fichier.
    #[test]
    fn releve_scelle_decide_de_la_sortie() {
        let maison = jetable("scelle");
        let q = maison.join("quarantaine");
        let f = maison.join("Téléchargements").join("rapport.exe");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"MZ rapport").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let e = liste_dans(&q)[0].clone();
        let releve = crate::protection::preuve::Fichier {
            chemin: f.to_string_lossy().into_owned(),
            sha256: e.sha256.clone(),
            taille: None,
        };
        assert!(releve.sha256.is_some());
        // L'origine réécrite vers un autre fichier : refusée, rien n'y est écrit.
        let ailleurs = maison.join("autostart.desktop");
        let reecrite = Entree {
            origine: ailleurs.to_string_lossy().into_owned(),
            ..e.clone()
        };
        assert!(remettre_dans(&reecrite, &q, Some(&releve), false).is_err());
        assert!(!ailleurs.exists());
        // Registre douteux : sans relevé, ou un relevé sans empreinte, rien ne sort.
        assert!(remettre_dans(&e, &q, None, true).is_err());
        let sans_empreinte = crate::protection::preuve::Fichier {
            sha256: None,
            ..releve.clone()
        };
        assert!(remettre_dans(&e, &q, Some(&sans_empreinte), true).is_err());
        assert!(!f.exists());
        // Une empreinte scellée qui n'est pas celle du fichier relu : rien ne sort, et il reste fermé.
        let autre = crate::protection::preuve::Fichier {
            sha256: Some("00".repeat(32)),
            ..releve.clone()
        };
        assert!(remettre_dans(&e, &q, Some(&autre), true).is_err());
        assert!(!f.exists());
        // Le refus montre les deux empreintes, celle lue et celle du relevé, au lieu d'en donner une seule pour
        // « attendue » (contrôle de PA-4, ronde 2).
        let refus = remettre_dans(&e, &q, Some(&autre), false).unwrap_err().to_string();
        assert!(!f.exists());
        let lue = e.sha256.clone().unwrap();
        assert!(refus.contains(&"00".repeat(32)) && refus.contains(&lue), "{refus}");
        #[cfg(unix)]
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(q.join(&e.nom)).unwrap().permissions()) & 0o777,
            0,
            "refermé après le refus"
        );
        // En administrateur (registre douteux), même le bon relevé ne fait rien sortir : relevé, registre et fichier
        // isolé s'écrivent tous depuis le compte ; le refus dit où est le fichier, pour le sortir à la main.
        let refus = remettre_dans(&e, &q, Some(&releve), true).unwrap_err().to_string();
        assert!(!f.exists(), "sorti en administrateur");
        assert!(refus.contains(&e.nom), "{refus}");
        // Le bon relevé, sans écart de droits : il sort.
        remettre_dans(&e, &q, Some(&releve), false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"MZ rapport");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le dossier de l'origine changé en lien par un autre compte après l'isolement (relecture de PA-4) : rien n'est
    /// écrit au travers, le fichier reste en quarantaine. Un lien fiable (posé par root ou par le compte qui agit,
    /// comme /home vers /var/home), lui, se suit.
    #[cfg(unix)]
    #[test]
    fn origine_derriere_un_lien_pose_apres_l_isolement() {
        let maison = jetable("parent-lien");
        let q = maison.join("quarantaine");
        let systeme = maison.join("systeme");
        std::fs::create_dir_all(&systeme).unwrap();
        let outil = maison.join("Projets").join("outil");
        let f = outil.join("installer.sh");
        std::fs::create_dir_all(&outil).unwrap();
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let e = liste_dans(&q)[0].clone();
        std::fs::remove_dir(&outil).unwrap();
        std::os::unix::fs::symlink(&systeme, &outil).unwrap();
        let lien = std::fs::symlink_metadata(&outil).unwrap();
        let lien = (
            std::os::unix::fs::MetadataExt::dev(&lien),
            std::os::unix::fs::MetadataExt::ino(&lien),
        );
        LIEN_D_UN_AUTRE.with(|c| c.set(Some(lien)));
        let r = remettre_dans(&e, &q, None, false);
        LIEN_D_UN_AUTRE.with(|c| c.set(None));
        assert!(r.is_err());
        assert!(
            !systeme.join("installer.sh").exists(),
            "écrit au travers d'un lien posé à l'origine"
        );
        assert_eq!(liste_dans(&q).len(), 1, "le fichier reste en quarantaine");
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(q.join(&e.nom)).unwrap().permissions()) & 0o777,
            0,
            "refermé après le refus"
        );
        // Le même lien, fiable : suivi.
        remettre_dans(&e, &q, None, false).unwrap();
        assert_eq!(std::fs::read(systeme.join("installer.sh")).unwrap(), b"#!/bin/sh\n");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le fichier isolé échangé par un programme du compte entre l'empreinte et la sortie (relecture de PA-4) : le
    /// contenu qui sort est celui dont l'empreinte a été lue, ou rien.
    #[test]
    fn contenu_echange_apres_l_empreinte_jamais_sorti() {
        let maison = jetable("course");
        let q = maison.join("quarantaine");
        let f = maison.join("Outil").join("greffon.dll");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"MZ releve").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let e = liste_dans(&q)[0].clone();
        let releve = crate::protection::preuve::Fichier {
            chemin: f.to_string_lossy().into_owned(),
            sha256: e.sha256.clone(),
            taille: None,
        };
        let (isole, piege) = (q.join(&e.nom), q.join("piege"));
        std::fs::write(&piege, b"MZ echange").unwrap();
        AVANT_LA_SORTIE.with(|c| {
            *c.borrow_mut() = Some(Box::new(move || {
                let _ = std::fs::rename(&piege, &isole);
            }));
        });
        let _ = remettre_dans(&e, &q, Some(&releve), false);
        AVANT_LA_SORTIE.with(|c| *c.borrow_mut() = None);
        assert!(
            std::fs::read(&f).map_or(true, |o| o == b"MZ releve"),
            "un contenu échangé après le contrôle est sorti"
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Un registre et un journal remplis d'entrées par un programme du compte (relecture de PA-4) : la liste se lit
    /// d'un passage, sans parcourir toutes les entrées à chaque ligne du journal.
    #[test]
    fn registre_enorme_lu_sans_figer() {
        let maison = jetable("enorme");
        let q = maison.join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        let n = 60_000;
        let fichiers = (0..n)
            .map(|i| Entree {
                nom: format!("../x{i}"),
                origine: "/x".into(),
                detection: "X".into(),
                date: "2026-11-12 10:00:00".into(),
                mode: None,
                sha256: None,
            })
            .collect();
        enregistrer(&q, &Registre { fichiers }).unwrap();
        let journal = (0..n).fold(String::new(), |mut j, i| {
            use std::fmt::Write;
            let _ = writeln!(j, "d\tX\t/x\t{i}.absent");
            j
        });
        std::fs::write(q.join("journal.txt"), journal).unwrap();
        let debut = std::time::Instant::now();
        let liste = lire_liste(&q);
        let duree = debut.elapsed();
        assert_eq!(liste.ecartees.len(), n);
        assert_eq!(liste.admises.len(), 0);
        // Sous Linux, 0,5 s ; sous Wine, chaque accès passe par l'émulation : 4,3 s seul, plus sous charge (la borne
        // de 5 s y tombait). Un parcours de toutes les entrées à chaque ligne (60 000², 3,6 milliards de comparaisons) dépasse 5 s sous
        // Linux : c'est lui qui garde l'ordre de grandeur, Windows garde une borne contre le figé.
        let borne = std::time::Duration::from_secs(if cfg!(windows) { 60 } else { 5 });
        assert!(duree < borne, "{duree:?}");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Ce qui s'isole se remet (relecture de PA-4) : un chemin qui remonte (« .. ») n'est pas isolé, puisque la
    /// remise le refuserait ; une entrée déjà isolée ainsi sort quand son origine est celle du relevé scellé.
    #[test]
    fn ce_qui_s_isole_se_remet() {
        let maison = jetable("remonte");
        let q = maison.join("quarantaine");
        std::fs::create_dir_all(maison.join("x")).unwrap();
        std::fs::create_dir_all(maison.join("outils")).unwrap();
        let vrai = maison.join("outils").join("outil.py");
        std::fs::write(&vrai, b"print(1)").unwrap();
        // Tel que l'aurait rendu le blocage pour « python3 ../outils/outil.py » lancé depuis x.
        let remonte = maison.join("x").join("..").join("outils").join("outil.py");
        assert!(isoler_dans(&remonte, "X", &q, None, None).is_err());
        assert_eq!(std::fs::read(&vrai).unwrap(), b"print(1)", "laissé en place");
        // Isolé par une version d'avant, sous ce chemin : il sort avec son relevé scellé, jamais sans.
        isoler_dans(&vrai, "X", &q, None, None).unwrap();
        let e = Entree {
            origine: remonte.to_string_lossy().into_owned(),
            ..liste_dans(&q)[0].clone()
        };
        assert!(remettre_dans(&e, &q, None, false).is_err());
        let releve = crate::protection::preuve::Fichier {
            chemin: e.origine.clone(),
            sha256: e.sha256.clone(),
            taille: None,
        };
        remettre_dans(&e, &q, Some(&releve), false).unwrap();
        assert_eq!(std::fs::read(&vrai).unwrap(), b"print(1)");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Sous Linux, « \ » est un caractère de nom permis (une archive faite sous Windows) : le fichier isolé est
    /// listé, compté, et se remet (relecture de PA-4).
    #[cfg(unix)]
    #[test]
    fn nom_a_barre_inverse_se_remet() {
        let maison = jetable("barre");
        let q = maison.join("quarantaine");
        let f = maison.join(r"dossier\outil.exe");
        std::fs::write(&f, b"MZ").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let liste = lire_liste(&q);
        assert_eq!(liste.ecartees.len(), 0);
        assert_eq!(nombre_dans(&q), 1);
        remettre_dans(&liste.admises[0], &q, None, false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"MZ");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Une entrée écartée garde, dans les traces d'incident, une marque et son nom : jamais rendue comme un vrai
    /// fichier en quarantaine (relecture de PA-4).
    #[test]
    fn ecartee_marquee_dans_les_traces() {
        let maison = jetable("traces");
        let q = maison.join("quarantaine");
        std::fs::create_dir_all(&q).unwrap();
        std::fs::write(
            q.join("journal.txt"),
            "2026-01-01 00:00:00\tFaux.Virus\t/home/alice/faux\t../../x\n",
        )
        .unwrap();
        let t = pour_traces_dans(&q).unwrap();
        assert_eq!(t.len(), 1);
        let detection = &t[0].2;
        assert!(detection.contains("../../x"), "{detection}");
        assert!(
            detection.contains("écartée") && detection.contains("set aside"),
            "{detection}"
        );
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Le relevé scellé que le menu donne à la remise vient bien du blocage noté par `isoler` (relecture de PA-4).
    #[test]
    fn scelle_de_retrouve_le_releve_du_blocage() {
        let maison = jetable("scelle-de");
        let f = maison.join("outil.bin");
        std::fs::write(&f, b"contenu invente").unwrap();
        let dest = isoler(&f, "X", demande_d_analyse(&f, "X")).unwrap();
        let nom = dest.file_name().unwrap().to_string_lossy().into_owned();
        let s = scelle_de(&nom).expect("le relevé scellé du blocage");
        assert_eq!(s.chemin, f.to_string_lossy());
        let attendue = crate::protection::empreintes::hex(
            &crate::protection::empreintes::sha256_de(&b"contenu invente"[..]).unwrap(),
        );
        assert!(s.sha256.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(&attendue)));
        assert!(scelle_de("0.autre").is_none());
        remettre(&nom, Some(&s)).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"contenu invente");
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Un lien posé dans la quarantaine sous un nom du registre ne fait changer les permissions d'aucun autre fichier,
    /// et le mode remis n'a ni setuid, ni setgid, ni sticky (PA-4).
    #[cfg(unix)]
    #[test]
    fn sortie_sans_lien_ni_mode_special() {
        use std::os::unix::fs::PermissionsExt;
        let maison = jetable("sortie-lien");
        let q = maison.join("quarantaine");
        let victime = maison.join("victime");
        std::fs::write(&victime, b"a moi").unwrap();
        std::fs::set_permissions(&victime, PermissionsExt::from_mode(0o644)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o7777;
        let f = maison.join("outil");
        std::fs::write(&f, b"#!/bin/sh").unwrap();
        isoler_dans(&f, "X", &q, None, None).unwrap();
        let mut legit = liste_dans(&q)[0].clone();
        let lien = Entree {
            nom: "999.lien".into(),
            origine: maison.join("sortie").to_string_lossy().into_owned(),
            ..legit.clone()
        };
        std::os::unix::fs::symlink(&victime, q.join(&lien.nom)).unwrap();
        assert!(remettre_dans(&lien, &q, None, false).is_err());
        assert_eq!(mode(&victime), 0o644);
        // Un lien cassé à l'origine : rien n'est écrit au travers, et il reste tel quel.
        let cassé = maison.join("raccourci");
        std::os::unix::fs::symlink(maison.join("cible"), &cassé).unwrap();
        let vers_lien = Entree {
            origine: cassé.to_string_lossy().into_owned(),
            ..legit.clone()
        };
        assert!(remettre_dans(&vers_lien, &q, None, false).is_err());
        assert!(std::fs::symlink_metadata(&cassé).unwrap().file_type().is_symlink());
        assert!(!maison.join("cible").exists());
        assert!(std::fs::symlink_metadata(maison.join("sortie")).is_err());
        assert!(supprimer_dans(&lien, &q).is_err());
        assert!(std::fs::symlink_metadata(q.join(&lien.nom)).is_ok());
        // Un mode réécrit avec setuid, setgid et sticky : remis sans eux.
        legit.mode = Some(0o7755);
        remettre_dans(&legit, &q, None, false).unwrap();
        assert_eq!(mode(&f), 0o755);
        let _ = std::fs::remove_dir_all(&maison);
    }

    /// Supprimé après une analyse : le fichier n'est plus là, mais son empreinte est relevée et le geste noté pour
    /// les traces d'incident.
    #[cfg(unix)]
    #[test]
    fn suppression_apres_analyse_relevee_et_notee() {
        let j = jetable("suppression");
        // Canonique : `target` est un lien, et un dossier qui n'est pas à sa place n'est jamais touché (PA-1).
        let d = j.canonicalize().unwrap();
        let f = d.join("facture.pdf.exe");
        std::fs::write(&f, b"charge inventee").unwrap();
        let identite = Identite::de(&std::fs::symlink_metadata(&f).unwrap());
        supprimer_apres_analyse(&f, "Win.Test.EICAR", &identite).unwrap();
        assert!(!f.exists());
        let cle = format!("fichier:{}", f.display());
        let (_, reussi, b) = crate::changements::blocages()
            .into_iter()
            .find(|(_, _, b)| b.cle == cle)
            .expect("suppression notée");
        assert!(reussi && b.annulation.is_none());
        assert!(
            b.preuve
                .and_then(|p| p.fichier)
                .and_then(|x| x.sha256)
                .is_some_and(|h| h.len() == 64)
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 : pendant le relevé, l'autre compte déplace son dossier et met à sa place un lien vers le dossier d'un
    /// autre, où un fichier porte le même nom. Le retrait se fait dans le dossier tenu ouvert : le fichier examiné part,
    /// celui de l'autre reste. Par le chemin (`remove_file`), c'est lui qui partait.
    #[cfg(unix)]
    #[test]
    fn suppression_dans_le_dossier_tenu() {
        let j = jetable("suppression-tenue");
        let d = j.canonicalize().unwrap();
        std::fs::create_dir_all(d.join("tmp/e")).unwrap();
        std::fs::create_dir_all(d.join("victime")).unwrap();
        let f = d.join("tmp/e/bashrc");
        std::fs::write(&f, b"charge inventee").unwrap();
        std::fs::write(d.join("victime/bashrc"), b"export ESSAI=1\n").unwrap();
        let identite = Identite::de(&std::fs::symlink_metadata(&f).unwrap());
        let racine = d.clone();
        AVANT_LE_GESTE.with(|c| {
            *c.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(racine.join("tmp/e"), racine.join("tmp/e.cache")).unwrap();
                std::os::unix::fs::symlink(racine.join("victime"), racine.join("tmp/e")).unwrap();
            }));
        });
        supprimer_apres_analyse(&f, "Essai.Faux-1", &identite).unwrap();
        assert_eq!(std::fs::read(d.join("victime/bashrc")).unwrap(), b"export ESSAI=1\n");
        assert!(!d.join("tmp/e.cache/bashrc").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2) : le dossier tenu doit être à sa place, sans lien sur le chemin. Ici le nom y
    /// désigne bien l'inode examiné, mais par un second nom (lien dur) rangé ailleurs : rien n'est retiré de là.
    #[cfg(unix)]
    #[test]
    fn suppression_hors_de_sa_place() {
        let j = jetable("suppression-ailleurs");
        let d = j.canonicalize().unwrap();
        std::fs::create_dir_all(d.join("tmp/e")).unwrap();
        std::fs::create_dir_all(d.join("ailleurs")).unwrap();
        let f = d.join("tmp/e/x");
        std::fs::write(&f, b"charge inventee").unwrap();
        std::fs::hard_link(&f, d.join("ailleurs/x")).unwrap();
        let identite = Identite::de(&std::fs::symlink_metadata(&f).unwrap());
        std::fs::rename(d.join("tmp/e"), d.join("tmp/e.cache")).unwrap();
        std::os::unix::fs::symlink(d.join("ailleurs"), d.join("tmp/e")).unwrap();
        assert!(supprimer_apres_analyse(&f, "Essai.Faux-1", &identite).is_err());
        assert!(d.join("ailleurs/x").exists());
        assert!(d.join("tmp/e.cache/x").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// PA-1 (contrôle de la ronde 2) : juste avant le déplacement vers la quarantaine, l'autre compte met à la place
    /// de son dossier un lien vers celui d'un autre, où un fichier porte le même nom. Le déplacement se fait depuis le
    /// dossier tenu ouvert : le fichier examiné part, celui de l'autre n'est même pas touché (même ctime). Par le
    /// chemin, c'est lui qui partait (puis revenait, ou, d'un disque à l'autre, était copié puis effacé).
    #[cfg(unix)]
    #[test]
    fn isolement_dans_le_dossier_tenu() {
        use std::os::unix::fs::MetadataExt;
        let j = jetable("isolement-tenu");
        let d = j.canonicalize().unwrap();
        std::fs::create_dir_all(d.join("tmp/e")).unwrap();
        std::fs::create_dir_all(d.join("victime")).unwrap();
        let f = d.join("tmp/e/bashrc");
        std::fs::write(&f, b"charge inventee").unwrap();
        std::fs::write(d.join("victime/bashrc"), b"export ESSAI=1\n").unwrap();
        let date = |p: &Path| {
            std::fs::symlink_metadata(p)
                .map(|m| (m.ctime(), m.ctime_nsec(), m.nlink()))
                .unwrap()
        };
        let avant = date(&d.join("victime/bashrc"));
        let identite = Identite::de(&std::fs::symlink_metadata(&f).unwrap());
        let racine = d.clone();
        AVANT_LE_GESTE.with(|c| {
            *c.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(racine.join("tmp/e"), racine.join("tmp/e.cache")).unwrap();
                std::os::unix::fs::symlink(racine.join("victime"), racine.join("tmp/e")).unwrap();
            }));
        });
        let dest = isoler_dans(&f, "Essai.Faux-1", &d.join("quarantaine"), None, Some(identite));
        assert_eq!(std::fs::read(d.join("victime/bashrc")).unwrap(), b"export ESSAI=1\n");
        assert_eq!(date(&d.join("victime/bashrc")), avant);
        let dest = dest.unwrap();
        assert!(Identite::de(&std::fs::symlink_metadata(&dest).unwrap()).meme_fichier(&identite));
        assert!(!d.join("tmp/e.cache/bashrc").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Les liens suivis vers une origine (relecture de PA-4) : posés par root ou par le compte qui agit, dans un
    /// dossier à eux que personne d'autre ne réécrit (ou collant) ; jamais celui d'un autre compte.
    #[cfg(unix)]
    #[test]
    fn liens_suivis_vers_l_origine() {
        let (root, moi, autre) = (0, 1000, 1001);
        assert!(lien_fiable(root, root, root, 0o755), "/home vers /var/home");
        assert!(lien_fiable(moi, moi, moi, 0o700));
        assert!(lien_fiable(moi, root, root, 0o1777), "dans /tmp, posé par root");
        assert!(
            !lien_fiable(root, autre, autre, 0o755),
            "posé par un autre compte, chez lui"
        );
        assert!(
            !lien_fiable(root, root, autre, 0o755),
            "le dossier d'un autre : il remplace le lien"
        );
        assert!(!lien_fiable(root, root, root, 0o777), "un dossier que tous réécrivent");
        assert!(!lien_fiable(moi, autre, root, 0o1777), "dans /tmp, posé par un autre");
    }

    /// Les droits spéciaux notés ne sont jamais remis, mais se disent, avec la commande pour les remettre (relecture
    /// de PA-4).
    #[test]
    fn droits_speciaux_dits_a_la_remise() {
        let origine = Path::new("/opt/outil/lanceur");
        let dit = bits_retires(Some(0o4755), origine).expect("setuid dit");
        assert!(dit.contains("4755") && dit.contains("chmod"), "{dit}");
        assert!(bits_retires(Some(0o2750), origine).is_some());
        assert!(bits_retires(Some(0o1777), origine).is_some());
        assert_eq!(bits_retires(Some(0o755), origine), None);
        assert_eq!(bits_retires(None, origine), None);
    }

    /// `f` atteint depuis `ici` par un chemin relatif (« ../../… »), ou `None` sur un autre lecteur.
    fn relatif_depuis(ici: &Path, f: &Path) -> Option<PathBuf> {
        use std::path::Component;
        let racine = |p: &Path| -> PathBuf {
            p.components()
                .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
                .collect()
        };
        if racine(ici) != racine(f) {
            return None;
        }
        let montee = ici.components().filter(|c| matches!(c, Component::Normal(_))).count();
        let mut r: PathBuf = std::iter::repeat_n("..", montee).collect();
        r.extend(f.components().filter(|c| matches!(c, Component::Normal(_))));
        Some(r)
    }

    /// Un fichier trouvé par une analyse sous un chemin relatif (« vanguard yara . ») s'isole quand même, et se remet :
    /// son chemin devient complet avant le relevé, que la remise compare mot pour mot à l'origine notée (contrôle de
    /// PA-4, ronde 2 : la garde des chemins complets le laissait en place).
    #[test]
    fn trouve_par_un_chemin_relatif_s_isole_et_se_remet() {
        let maison = jetable("trouve-relatif");
        let f = maison.join("Telechargements").join("outil.bin");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"contenu invente").unwrap();
        let complet = std::path::absolute(&f).unwrap();
        let Some(relatif) = std::env::current_dir()
            .ok()
            .and_then(|ici| relatif_depuis(&ici, &complet))
        else {
            return crate::essais::saute("le dossier d'essai n'est pas sur le lecteur du dossier courant");
        };
        assert!(relatif.is_relative(), "{relatif:?}");
        let dest = isoler_trouve(&relatif, "Essai.Faux-1").unwrap();
        assert!(!f.exists(), "resté en place");
        let nom = dest.file_name().unwrap().to_string_lossy().into_owned();
        let s = scelle_de(&nom).expect("le relevé scellé de l'analyse");
        assert!(Path::new(&s.chemin).is_absolute(), "{}", s.chemin);
        remettre(&nom, Some(&s)).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"contenu invente");
    }

    /// Le conseil des droits administrateur ne suit qu'un refus de droits : un chemin refusé n'a rien à y voir
    /// (contrôle de PA-4, ronde 2).
    #[test]
    fn conseil_des_droits_seulement_pour_un_refus_de_droits() {
        assert_eq!(conseil_d_echec(&std::io::Error::other("chemin refusé")), "");
        assert_ne!(
            conseil_d_echec(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            ""
        );
    }

    /// Un dossier de l'origine disparu depuis l'isolement (une archive extraite puis effacée) est recréé à la remise,
    /// sous Linux comme sous Windows (contrôle de PA-4, ronde 2 : Windows ne le recréait plus).
    #[test]
    fn dossier_d_origine_disparu_se_recree() {
        let d = jetable("origine-disparue");
        let q = d.join("q");
        let f = d.join("maison").join("Telechargements").join("lot").join("outil.exe");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"contenu invente").unwrap();
        isoler_dans(&f, "Essai.Faux-1", &q, None, None).unwrap();
        std::fs::remove_dir_all(d.join("maison").join("Telechargements")).unwrap();
        let e = liste_dans(&q)[0].clone();
        remettre_dans(&e, &q, None, false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"contenu invente");
    }

    /// Sans crochet d'essai : un lien du compte même, dans un dossier que tous réécrivent (0o777, non collant), n'est
    /// pas suivi vers l'origine, et le refus dit comment sortir le fichier à la main ; le même dossier fermé aux
    /// autres (0o755), si (contrôle de PA-4, ronde 2).
    #[cfg(unix)]
    #[test]
    fn lien_dans_un_dossier_ouvert_a_tous_refuse() {
        use std::os::unix::fs::PermissionsExt;
        let d = jetable("lien-ouvert");
        let (q, ouvert, vrai) = (d.join("q"), d.join("ouvert"), d.join("vrai"));
        std::fs::create_dir_all(&ouvert).unwrap();
        std::fs::create_dir_all(&vrai).unwrap();
        let f = vrai.join("outil");
        std::fs::write(&f, b"contenu invente").unwrap();
        isoler_dans(&f, "Essai.Faux-1", &q, None, None).unwrap();
        std::os::unix::fs::symlink(&vrai, ouvert.join("lien")).unwrap();
        std::fs::set_permissions(&ouvert, std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut e = liste_dans(&q)[0].clone();
        e.origine = ouvert.join("lien").join("outil").to_string_lossy().into_owned();
        let refus = remettre_dans(&e, &q, None, false).unwrap_err().to_string();
        assert!(!f.exists(), "suivi au travers d'un dossier ouvert à tous");
        assert!(refus.contains(&e.nom), "sans la sortie à la main : {refus}");
        std::fs::set_permissions(&ouvert, std::fs::Permissions::from_mode(0o755)).unwrap();
        remettre_dans(&e, &q, None, false).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"contenu invente");
    }

    /// « .. » d'une ancienne origine se résout dans le chemin parcouru, pas par le dossier tenu : un compte qui
    /// déplace son dossier pendant la marche ne la fait pas monter ailleurs (contrôle de PA-4, ronde 2).
    #[cfg(unix)]
    #[test]
    fn remontee_dans_la_marche_reste_sur_le_chemin_parcouru() {
        use std::os::fd::AsRawFd;
        let d = jetable("remontee");
        let haut = d.join("haut");
        std::fs::create_dir_all(haut.join("a").join("b")).unwrap();
        std::fs::create_dir_all(haut.join("a").join("c")).unwrap();
        std::fs::create_dir_all(d.join("ailleurs").join("c")).unwrap();
        let (b, deplace) = (haut.join("a").join("b"), d.join("ailleurs").join("b"));
        AVANT_LA_REMONTEE.with(|h| {
            *h.borrow_mut() = Some(Box::new(move || std::fs::rename(&b, &deplace).unwrap()));
        });
        let ouvert = ouvrir_l_origine(&haut.join("a/b/../c/outil"));
        AVANT_LA_REMONTEE.with(|h| h.borrow_mut().take());
        let (tenu, nom) = ouvert.unwrap();
        assert_eq!(nom.to_bytes(), b"outil");
        let lieu = std::fs::read_link(format!("/proc/self/fd/{}", tenu.as_raw_fd())).unwrap();
        assert_eq!(lieu, haut.join("a").join("c").canonicalize().unwrap());
    }

    /// Windows sans droits administrateur : un dossier de l'origine changé en jonction (ou en lien) après l'isolement
    /// n'est pas suivi ; le fichier reste en quarantaine (contrôle de PA-4, ronde 2 : un autre compte qui tient un
    /// dossier partagé le faisait atterrir dans le dossier Démarrage de la personne).
    #[cfg(windows)]
    #[test]
    fn jonction_a_l_origine_jamais_suivie() {
        let d = jetable("jonction");
        let q = d.join("q");
        let partage = d.join("Public").join("lot");
        let demarrage = d.join("Demarrage");
        std::fs::create_dir_all(&partage).unwrap();
        std::fs::create_dir_all(&demarrage).unwrap();
        let f = partage.join("outil.exe");
        std::fs::write(&f, b"contenu invente").unwrap();
        isoler_dans(&f, "Essai.Faux-1", &q, None, None).unwrap();
        std::fs::remove_dir(&partage).unwrap();
        if std::os::windows::fs::symlink_dir(&demarrage, &partage).is_err()
            || !std::fs::symlink_metadata(&partage).is_ok_and(|m| m.file_type().is_symlink())
        {
            return crate::essais::saute("lien de dossier impossible à poser ici");
        }
        let e = liste_dans(&q)[0].clone();
        assert!(remettre_dans(&e, &q, None, false).is_err());
        assert!(!demarrage.join("outil.exe").exists(), "suivi au travers du lien");
        assert_eq!(liste_dans(&q).len(), 1, "le fichier reste en quarantaine");
    }

    /// Contrôle de PA-4, ronde 2 : une empreinte qui ne se relit pas à l'arrivée n'est pas un échange ; les deux
    /// refusent la remise, avec chacun son message (sous Windows, `sortir_par_le_chemin`).
    #[test]
    fn arrivee_illisible_n_est_pas_un_echange() {
        let avant = [7u8; 32];
        assert_eq!(a_l_arrivee(&avant, Some(&[7u8; 32])), Arrivee::Meme);
        assert_eq!(a_l_arrivee(&avant, Some(&[8u8; 32])), Arrivee::Echange);
        assert_eq!(a_l_arrivee(&avant, None), Arrivee::Illisible);
    }

    /// Un nom seul (« outil.bin », trouvé dans le dossier courant) a un parent vide : il devient lui aussi un chemin
    /// complet (l'ancien `menaces::sans_detour` le rendait tel quel, que la quarantaine refuse). Les essais tournent
    /// depuis le dossier du projet, où Cargo.toml existe.
    #[test]
    fn nom_seul_devient_complet() {
        let c = chemin_direct(PathBuf::from("Cargo.toml"));
        assert!(c.is_absolute(), "{c:?}");
        assert!(c.is_file(), "{c:?}");
        assert_eq!(c.file_name(), Some(std::ffi::OsStr::new("Cargo.toml")));
        assert!(origine_admise(&c.to_string_lossy(), false), "{c:?}");
    }
}
