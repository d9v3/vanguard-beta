//! La quarantaine d'un fichier du dossier Démarrage de toute la machine, par le processus élevé, sans PowerShell
//! (lot 3.5, passe b, R48). La ligne désigne, le processus élevé juge : le fichier est ouvert sans suivre de lien
//! (FILE_FLAG_OPEN_REPARSE_POINT), refusé s'il est un lien, une jonction, un dossier ou un fichier à plusieurs noms,
//! et son chemin final (GetFinalPathNameByHandleW) doit être celui de la ligne, directement dans le dossier Démarrage
//! commun que le processus élevé lit lui-même. Il est relu sur cette poignée (aucun autre programme ne peut l'écrire
//! tant qu'elle est ouverte), rejugé par la fonction du bilan (`persistance::demarrage_signale`), jamais une entrée de
//! Windows ou de Defender, copié dans la quarantaine (`quarantaine.rs`), la copie relue et comparée, noté (nom de la
//! copie et empreinte SHA-256) dans `gestes::DEMARRAGE_AVANT_CLE`, puis retiré par la même poignée et relu absent.
//! La remise ne prend que la copie notée, vérifiée par son empreinte, jamais par-dessus un fichier présent.
//!
//! Les fichiers du dossier Démarrage de la personne restent à retirer à la main (décision du lot 3.5).

use std::ffi::c_void;
use std::fs::File;
use std::io::ErrorKind::NotFound;
use std::io::{Read as _, Seek as _, Write as _};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use sha2::Digest as _;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::{Resultat, avant_notable};
use super::memoire::InformationFichier;
use crate::machine::gestes::{self, Acte, CheminFichier};
use crate::ui::{tr, trf};

/// Un fichier du dossier Démarrage est un raccourci ou un petit programme : au-delà, refusé plutôt que chargé.
const TAILLE_MAX: u64 = 64 << 20;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const DELETE: u32 = 0x0001_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_SHARE_READ: u32 = 0x0001;
const FILE_SHARE_WRITE: u32 = 0x0002;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const ATTRIBUT_DOSSIER: u32 = 0x10;
const ATTRIBUT_POINT_D_ANALYSE: u32 = 0x400;

// FFI de kernel32 : ce qu'une poignée ouverte désigne vraiment, et le retrait par cette même poignée.
#[allow(unsafe_code)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(fichier: *mut c_void, information: *mut InformationFichier) -> i32;
    fn GetFinalPathNameByHandleW(fichier: *mut c_void, tampon: *mut u16, taille: u32, drapeaux: u32) -> u32;
    fn SetFileInformationByHandle(fichier: *mut c_void, classe: i32, information: *const c_void, taille: u32) -> i32;
}

/// Les attributs et le nombre de noms (liens physiques) du fichier ouvert.
// FFI de kernel32 : GetFileInformationByHandle.
#[allow(unsafe_code)]
fn information(f: &File) -> Option<(u32, u32)> {
    let mut info = InformationFichier::default();
    // SAFETY: la poignée vient d'un fichier ouvert qui vit pendant l'appel ; `info` est une
    // BY_HANDLE_FILE_INFORMATION à nous, que l'appel remplit sans en sortir.
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle(), &raw mut info) } != 0;
    ok.then_some((info.attributs, info.liens))
}

/// Le chemin final du fichier ouvert (FILE_NAME_NORMALIZED, VOLUME_NAME_DOS), sans le « \\?\ » ; `None` pour un
/// partage (« \\?\UNC\… ») ou si Windows ne le donne pas.
// FFI de kernel32 : GetFinalPathNameByHandleW.
#[allow(unsafe_code)]
fn chemin_final(f: &File) -> Option<String> {
    let mut tampon = vec![0u16; 1024];
    for _ in 0..2 {
        let taille = u32::try_from(tampon.len()).ok()?;
        // SAFETY: la poignée vient d'un fichier ouvert qui vit pendant l'appel ; le tampon à nous fait `taille`
        // unités, l'appel n'écrit pas au-delà et rend le nombre d'unités écrites (sans le zéro) ou la taille voulue.
        let n = unsafe { GetFinalPathNameByHandleW(f.as_raw_handle(), tampon.as_mut_ptr(), taille, 0) };
        let n = usize::try_from(n).ok()?;
        if n == 0 {
            return None;
        }
        if n < tampon.len() {
            let texte = String::from_utf16(tampon.get(..n)?).ok()?;
            let sans = texte.strip_prefix(r"\\?\")?;
            return (!sans.starts_with(r"UNC\")).then(|| sans.to_string());
        }
        tampon = vec![0u16; n + 1];
    }
    None
}

/// Marque le fichier ouvert pour être retiré à la fermeture de sa poignée (FileDispositionInfo) : le fichier retiré
/// est celui qui a été relu et jugé, jamais un autre posé depuis au même chemin.
// FFI de kernel32 : SetFileInformationByHandle.
#[allow(unsafe_code)]
fn marquer_pour_retrait(f: &File) -> std::io::Result<()> {
    const FILE_DISPOSITION_INFO: i32 = 4;
    let retirer: u8 = 1;
    // SAFETY: la poignée vient d'un fichier ouvert avec le droit DELETE qui vit pendant l'appel ; FILE_DISPOSITION_INFO
    // est un seul BOOLEAN (un octet), à nous, lu par l'appel sans être gardé.
    let ok =
        unsafe { SetFileInformationByHandle(f.as_raw_handle(), FILE_DISPOSITION_INFO, (&raw const retirer).cast(), 1) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

fn meme_chemin(a: &str, b: &str) -> bool {
    a.trim_end_matches('\\').to_lowercase() == b.trim_end_matches('\\').to_lowercase()
}

fn sha256(octets: &[u8]) -> String {
    use std::fmt::Write as _;
    sha2::Sha256::digest(octets)
        .iter()
        .fold(String::with_capacity(64), |mut s, o| {
            let _ = write!(s, "{o:02x}");
            s
        })
}

/// Le nom de la note : la ligne sans son verbe (le chemin en hexadécimal), le même pour la quarantaine et la remise.
fn nom_note(f: &CheminFichier) -> String {
    Acte::DemarrageRemettre(f.clone())
        .ligne()
        .strip_prefix(gestes::DEMARRAGE_REMETTRE)
        .unwrap_or_default()
        .to_string()
}

/// La note : « empreinte|nom de la copie ».
fn note(empreinte: &str, copie: &str) -> String {
    format!("{empreinte}|{copie}")
}

fn lire_note(n: &str) -> Option<(String, String)> {
    let (empreinte, copie) = n.split_once('|')?;
    let bonne = empreinte.len() == 64
        && empreinte
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    (bonne && copie.starts_with("demarrage-")).then(|| (empreinte.to_string(), copie.to_string()))
}

/// Le dossier Démarrage commun, et le nom du fichier de la ligne s'il y est directement ; le refus sinon.
fn dans_le_dossier_commun(f: &CheminFichier) -> Result<(String, String), Resultat> {
    let Some(commun) = super::environnement::demarrage_commun() else {
        return Err(refus(
            tr!(
                "dossier Démarrage commun introuvable : rien d'écrit",
                "common Startup folder not found: nothing written"
            )
            .to_string(),
        ));
    };
    let commun = commun.to_string_lossy().into_owned();
    match f.texte().rsplit_once('\\') {
        Some((parent, nom)) if meme_chemin(parent, &commun) => Ok((commun, nom.to_string())),
        _ => Err(refus(
            tr!(
                "ce fichier n'est pas directement dans le dossier Démarrage de toute la machine : rien d'écrit",
                "this file is not directly in the all-users Startup folder: nothing written"
            )
            .to_string(),
        )),
    }
}

/// Dans le processus élevé : met en quarantaine le fichier `f` du dossier Démarrage commun si et seulement si le
/// bilan, refait ici sur ce fichier relu, le signale et propose cette même ligne.
pub(super) fn quarantaine(f: &CheminFichier) -> Resultat {
    let ligne = Acte::DemarrageQuarantaine(f.clone()).ligne();
    let (commun, nom) = match dans_le_dossier_commun(f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    // Ouvert sans suivre de lien, à lire et à retirer ; les autres programmes peuvent lire, pas écrire ni retirer.
    let fichier = match std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(f.texte())
    {
        Ok(o) => o,
        Err(e) if e.kind() == NotFound => {
            return Resultat::rien(
                tr!(
                    "le fichier n'est plus là : rien à mettre en quarantaine",
                    "the file is no longer there: nothing to quarantine"
                )
                .to_string(),
            );
        }
        Err(e) => {
            return refus(trf!(
                "le fichier ne s'ouvre pas ({e}) : rien d'écrit",
                "the file cannot be opened ({e}): nothing written"
            ));
        }
    };
    match information(&fichier) {
        Some((attributs, liens)) if attributs & (ATTRIBUT_POINT_D_ANALYSE | ATTRIBUT_DOSSIER) == 0 && liens == 1 => {}
        _ => {
            return refus(
                tr!(
                    "lien, jonction, dossier ou fichier à plusieurs noms : Vanguard n'y touche pas ; rien d'écrit",
                    "link, junction, folder or file with several names: Vanguard does not touch it; nothing written"
                )
                .to_string(),
            );
        }
    }
    // Le nom sur le disque, casse comprise, est celui de la ligne : la remise redonnera exactement ce nom.
    let meme_nom = |c: &str| c.rsplit_once('\\').is_some_and(|(_, n)| n == nom);
    if !chemin_final(&fichier).is_some_and(|c| meme_chemin(&c, f.texte()) && meme_nom(&c)) {
        return refus(
            tr!(
                "le fichier ouvert n'est pas celui de la ligne (chemin final différent) : rien d'écrit",
                "the opened file is not the one in the line (different final path): nothing written"
            )
            .to_string(),
        );
    }
    let mut octets = Vec::new();
    if let Err(e) = (&fichier).take(TAILLE_MAX + 1).read_to_end(&mut octets) {
        return refus(trf!(
            "le fichier ne se lit pas ({e}) : rien d'écrit",
            "the file cannot be read ({e}): nothing written"
        ));
    }
    if octets.len() as u64 > TAILLE_MAX {
        return refus(
            tr!(
                "fichier trop gros pour un fichier de démarrage : rien d'écrit",
                "file too large for a startup file: nothing written"
            )
            .to_string(),
        );
    }
    let Some(cible) = super::persistance::cible_demarrage(f.texte(), &octets) else {
        return refus(
            tr!(
                "raccourci illisible sans COM : rien d'écrit",
                "shortcut unreadable without COM: nothing written"
            )
            .to_string(),
        );
    };
    let (programme, _) = crate::commande::decouper_commande(&cible);
    if gestes::run_protege(&nom, &programme) {
        return refus(
            tr!(
                "entrée de Sécurité Windows ou de Defender : Vanguard n'y touche jamais ; rien d'écrit",
                "Windows Security or Defender entry: Vanguard never touches it; nothing written"
            )
            .to_string(),
        );
    }
    if !super::persistance::demarrage_signale(f.texte(), &cible, &commun, &ligne) {
        return refus(
            tr!(
                "le bilan refait ici ne signale pas ce fichier : rien d'écrit",
                "the check run again here does not report this file: nothing written"
            )
            .to_string(),
        );
    }
    // Une seule copie notée par fichier : une seconde quarantaine écraserait la note de la première, dont la copie
    // deviendrait introuvable pour la remise.
    let nom_note = nom_note(f);
    let deja = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(gestes::DEMARRAGE_AVANT_CLE, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        .is_ok_and(|k| k.get_raw_value(&nom_note).is_ok());
    if deja {
        return refus(
            tr!(
                "une copie de ce fichier attend déjà sa remise : la remettre d'abord ; rien d'écrit",
                "a copy of this file is already waiting to be put back: put it back first; nothing written"
            )
            .to_string(),
        );
    }
    let empreinte = sha256(&octets);
    let secondes = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let copie = format!("demarrage-{secondes}-{nom}");
    if let Err(e) = super::quarantaine::deposer(&copie, &octets) {
        return refus(trf!(
            "la copie en quarantaine n'a pas pu être faite ({e}) : rien d'écrit",
            "the quarantine copy could not be made ({e}): nothing written"
        ));
    }
    let retirer_copie = || {
        let _ = super::quarantaine::retirer(&copie);
    };
    if !super::quarantaine::lire(&copie, TAILLE_MAX).is_ok_and(|relue| relue == octets) {
        retirer_copie();
        return refus(
            tr!(
                "la copie en quarantaine relue n'est pas identique : rien d'écrit",
                "the quarantine copy read back is not identical: nothing written"
            )
            .to_string(),
        );
    }
    // Notée d'abord : sans note, pas de retrait (la remise serait perdue).
    let notes = RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey_with_flags(gestes::DEMARRAGE_AVANT_CLE, KEY_SET_VALUE | KEY_WOW64_64KEY)
        .map(|(k, _)| k);
    if let Err(e) = notes
        .as_ref()
        .map(|k| k.set_value(&nom_note, &note(&empreinte, &copie)))
    {
        retirer_copie();
        return refus(trf!(
            "la copie ne se note pas ({e}) : rien d'écrit",
            "the copy cannot be noted ({e}): nothing written"
        ));
    }
    let avant = avant_notable(&format!("{} → {cible}", f.texte()));
    if let Err(e) = marquer_pour_retrait(&fichier) {
        if let Ok(k) = &notes {
            let _ = k.delete_value(&nom_note);
        }
        retirer_copie();
        return refus(trf!(
            "le fichier ne se retire pas ({e}) : rien d'écrit",
            "the file cannot be removed ({e}): nothing written"
        ));
    }
    drop(fichier);
    match std::fs::symlink_metadata(f.texte()) {
        Err(e) if e.kind() == NotFound => Resultat::fait(avant),
        _ => Resultat::echec(
            Some(avant),
            tr!(
                "le fichier est toujours là (un autre programme le garde ouvert ?) ; il partira à sa fermeture, la copie est gardée",
                "the file is still there (another program keeps it open?); it goes when closed, the copy is kept"
            )
            .to_string(),
        ),
    }
}

/// Dans le processus élevé : remet le fichier `f` depuis la copie notée par `quarantaine`, vérifiée par son
/// empreinte, jamais par-dessus un fichier présent ; la note et la copie sont retirées après relecture.
pub(super) fn remettre(f: &CheminFichier) -> Resultat {
    let (commun, _) = match dans_le_dossier_commun(f) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let nom_note = nom_note(f);
    let notes = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
        gestes::DEMARRAGE_AVANT_CLE,
        KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
    );
    let lue = notes
        .as_ref()
        .ok()
        .and_then(|k| k.get_value::<String, _>(&nom_note).ok())
        .and_then(|n| lire_note(&n));
    let (Ok(notes), Some((empreinte, copie))) = (notes, lue) else {
        return refus(
            tr!(
                "aucune copie notée par Vanguard pour ce fichier : rien d'écrit",
                "no copy noted by Vanguard for this file: nothing written"
            )
            .to_string(),
        );
    };
    let octets = match super::quarantaine::lire(&copie, TAILLE_MAX) {
        Ok(o) if sha256(&o) == empreinte => o,
        Ok(_) => {
            return refus(
                tr!(
                    "la copie en quarantaine a changé (empreinte différente) : rien d'écrit",
                    "the quarantine copy changed (different fingerprint): nothing written"
                )
                .to_string(),
            );
        }
        Err(e) => {
            return refus(trf!(
                "la copie en quarantaine ne se lit pas ({e}) : rien d'écrit",
                "the quarantine copy cannot be read ({e}): nothing written"
            ));
        }
    };
    let terminer = || {
        let _ = notes.delete_value(&nom_note);
        let _ = super::quarantaine::retirer(&copie);
    };
    // Le dossier lui-même, ouvert sans suivre de lien : ni lien ni jonction, et bien celui que lit le processus élevé.
    // Sa poignée reste ouverte sans partage du retrait jusqu'à la fin : il ne peut être ni renommé ni remplacé par une
    // jonction entre ce contrôle et l'écriture.
    let dossier = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&commun)
        .ok()
        .filter(|d| {
            information(d).is_some_and(|(a, _)| a & ATTRIBUT_DOSSIER != 0 && a & ATTRIBUT_POINT_D_ANALYSE == 0)
                && chemin_final(d).is_some_and(|c| meme_chemin(&c, &commun))
        });
    if dossier.is_none() {
        return refus(
            tr!(
                "le dossier Démarrage commun est un lien, une jonction ou ne s'ouvre pas : rien d'écrit",
                "the common Startup folder is a link, a junction or cannot be opened: nothing written"
            )
            .to_string(),
        );
    }
    match std::fs::symlink_metadata(f.texte()) {
        Err(e) if e.kind() == NotFound => {}
        Ok(m)
            if m.is_file()
                && crate::socle::lire_ordinaire(std::path::Path::new(f.texte()), TAILLE_MAX)
                    .is_ok_and(|o| o == octets) =>
        {
            terminer();
            return Resultat::rien(
                tr!(
                    "le fichier est déjà là, identique : rien à remettre",
                    "the file is already there, identical: nothing to put back"
                )
                .to_string(),
            );
        }
        _ => {
            return refus(
                tr!(
                    "un autre fichier porte déjà ce nom : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
                    "another file already has this name: Vanguard never writes over it; nothing written"
                )
                .to_string(),
            );
        }
    }
    let absent = tr!("absent", "absent").to_string();
    // Créé seulement s'il n'existe pas (même un lien du même nom fait échouer), sans partage, avec le droit de le
    // retirer : le chemin final est vérifié avant d'écrire, et la relecture se fait par cette même poignée.
    let mut nouveau = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(f.texte())
    {
        Ok(n) => n,
        Err(e) => {
            return refus(trf!(
                "le fichier ne se crée pas ({e}) : rien d'écrit",
                "the file cannot be created ({e}): nothing written"
            ));
        }
    };
    let defaire = |n: File, raison: String| {
        let retire = marquer_pour_retrait(&n).is_ok();
        drop(n);
        if retire {
            refus(trf!(
                "{raison} ; le fichier créé est retiré, la note et la copie sont gardées",
                "{raison}; the created file is removed, the note and the copy are kept"
            ))
        } else {
            Resultat::echec(
                Some(absent.clone()),
                trf!(
                    "{raison} ; le fichier créé n'a pas pu être retiré, la note et la copie sont gardées",
                    "{raison}; the created file could not be removed, the note and the copy are kept"
                ),
            )
        }
    };
    let bon_nom = chemin_final(&nouveau).is_some_and(|c| meme_chemin(&c, f.texte()));
    if !bon_nom {
        return defaire(
            nouveau,
            tr!(
                "le fichier créé n'est pas au chemin de la ligne (chemin final différent)",
                "the created file is not at the line's path (different final path)"
            )
            .to_string(),
        );
    }
    let ecrit = nouveau
        .write_all(&octets)
        .and_then(|()| nouveau.sync_all())
        .and_then(|()| nouveau.seek(std::io::SeekFrom::Start(0)).map(|_| ()));
    if let Err(e) = ecrit {
        return defaire(nouveau, trf!("l'écriture a échoué ({e})", "writing failed ({e})"));
    }
    let mut relu = Vec::new();
    let lu = (&nouveau).take(TAILLE_MAX + 1).read_to_end(&mut relu);
    if lu.is_err() || relu != octets {
        return defaire(
            nouveau,
            tr!(
                "le fichier remis relu n'est pas la copie notée",
                "the file put back, read again, is not the noted copy"
            )
            .to_string(),
        );
    }
    drop(nouveau);
    drop(dossier);
    terminer();
    Resultat::fait(absent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_note_garde_empreinte_et_copie() {
        let e = "0".repeat(64);
        assert_eq!(
            lire_note(&note(&e, "demarrage-1-a.lnk")),
            Some((e.clone(), "demarrage-1-a.lnk".into()))
        );
        // Empreinte mal formée, copie hors de la quarantaine des fichiers de démarrage : refusées.
        assert_eq!(lire_note(&note(&"0".repeat(63), "demarrage-1-a.lnk")), None);
        assert_eq!(lire_note(&note(&"A".repeat(64), "demarrage-1-a.lnk")), None);
        assert_eq!(lire_note(&note(&e, "racine-1.cer")), None);
        assert_eq!(lire_note("sans barre"), None);
    }

    #[test]
    fn chemins_compares_sans_casse() {
        assert!(meme_chemin(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            r"c:\programdata\microsoft\windows\start menu\programs\Startup\"
        ));
        assert!(!meme_chemin(r"C:\ProgramData\a", r"C:\ProgramData\b"));
    }

    /// La poignée ouverte sans suivre de lien dit ce qu'elle désigne : un fichier ordinaire, un seul nom, son chemin
    /// final ; retiré par elle, il disparaît à sa fermeture.
    #[test]
    fn poignee_jugee_puis_retiree() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-demarrage-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dossier);
        let chemin = dossier.join("essai.txt");
        std::fs::write(&chemin, b"x").unwrap();
        let f = std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&chemin)
            .unwrap();
        let (attributs, liens) = information(&f).unwrap();
        assert_eq!(
            (attributs & (ATTRIBUT_DOSSIER | ATTRIBUT_POINT_D_ANALYSE), liens),
            (0, 1)
        );
        if let Some(c) = chemin_final(&f) {
            assert!(c.to_lowercase().ends_with(r"\essai.txt"), "{c}");
        }
        marquer_pour_retrait(&f).unwrap();
        drop(f);
        assert!(!chemin.exists());
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
