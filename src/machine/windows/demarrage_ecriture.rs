//! La quarantaine d'un fichier d'un dossier Démarrage, sans PowerShell (lot 3.5, passe b, R48 ; défense D6d). Le
//! dossier de toute la machine par le processus élevé (`Lieu::Commun`, notes sous HKLM, quarantaine de
//! `quarantaine.rs`), celui de la personne par Vanguard NON élevé, sous son propre compte, comme ses valeurs Run
//! (`Lieu::Personne`, geste du compte : notes sous son HKCU, quarantaine dans son dossier local).
//!
//! La ligne désigne, le geste juge : le fichier est ouvert sans suivre de lien (FILE_FLAG_OPEN_REPARSE_POINT), refusé
//! s'il est un lien, une jonction, un dossier ou un fichier à plusieurs noms, et son chemin final
//! (GetFinalPathNameByHandleW) doit être celui de la ligne, directement dans le dossier Démarrage que le geste lit
//! lui-même. Il est relu sur cette poignée (aucun autre programme ne peut l'écrire tant qu'elle est ouverte), rejugé par
//! la fonction du bilan (`persistance::demarrage_signale`), jamais le vrai programme de Windows ou de Defender
//! (`protege::protege` ; un nom seul se demande). Un raccourci que Vanguard ne lit pas sans COM est montré octet par
//! octet avant de demander ; un fichier plus gros qu'une copie (64 Mio) est déplacé tel quel, sur le même disque, après
//! une question.
//!
//! Chaque fichier garde jusqu'à huit copies (`demarrage_notes`) : un programme qui se redépose se remet en quarantaine,
//! la remise prend la plus récente ou celle qu'on choisit. Au-delà des bornes (8 par fichier, 64 Mio de copies en tout,
//! 8 fichiers déplacés), la plus vieille n'est effacée qu'après une question « non annulable », non par défaut. La copie
//! est faite, relue et comparée, notée (numéro, heure, taille, mode, empreinte SHA-256), puis l'original retiré par la
//! même poignée et relu absent. La remise ne prend que la copie notée, vérifiée par son empreinte, jamais par-dessus un
//! fichier présent.

use std::ffi::c_void;
use std::fs::File;
use std::io::ErrorKind::{AlreadyExists, NotFound};
use std::io::{Read as _, Seek as _, Write as _};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};

use sha2::Digest as _;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};

use super::corrections::{Resultat, avant_notable};
use super::demarrage_notes::{self as notes, Mode, Version};
use super::memoire::InformationFichier;
use super::protege::{self, Protege};
use crate::machine::gestes::{self, Acte, CheminFichier, GesteCompte};
use crate::ui::{tr, trf};

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
/// ERROR_NOT_SAME_DEVICE : un renommage ne passe pas d'un disque à l'autre.
const AUTRE_DISQUE: i32 = 17;
/// Le plus long chemin d'un renommage par la poignée, en unités UTF-16 (ceux de Vanguard sont bien plus courts).
const RENOMMAGE_MAX: usize = 1024;

// FFI de kernel32 : ce qu'une poignée ouverte désigne vraiment, et le retrait ou le renommage par cette même poignée.
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
pub(super) fn information(f: &File) -> Option<(u32, u32)> {
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
pub(super) fn chemin_final(f: &File) -> Option<String> {
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

/// FILE_RENAME_INFO (learn.microsoft.com) : l'union ReplaceIfExists/Flags, RootDirectory, FileNameLength en octets,
/// puis le nom ; un tableau fixe à nous plutôt qu'un tampon de taille variable.
#[repr(C)]
struct Renommage {
    remplacer: u32,
    racine: *mut c_void,
    longueur: u32,
    nom: [u16; RENOMMAGE_MAX],
}

/// Renomme le fichier ouvert (avec le droit DELETE) vers `vers`, chemin complet, jamais par-dessus un fichier qui
/// existe : le fichier déplacé est celui qui a été relu et jugé. Un autre disque refuse (`AUTRE_DISQUE`).
// FFI de kernel32 : SetFileInformationByHandle (FileRenameInfo).
#[allow(unsafe_code)]
fn renommer(f: &File, vers: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const FILE_RENAME_INFO: i32 = 3;
    let nom: Vec<u16> = vers.as_os_str().encode_wide().collect();
    if nom.len() >= RENOMMAGE_MAX || nom.contains(&0) || !vers.is_absolute() {
        return Err(std::io::Error::other(tr!("chemin refusé", "path refused")));
    }
    let mut info = Renommage {
        remplacer: 0,
        racine: std::ptr::null_mut(),
        longueur: u32::try_from(nom.len() * 2).map_err(std::io::Error::other)?,
        nom: [0; RENOMMAGE_MAX],
    };
    for (d, s) in info.nom.iter_mut().zip(&nom) {
        *d = *s;
    }
    let taille = u32::try_from(std::mem::size_of::<Renommage>()).map_err(std::io::Error::other)?;
    // SAFETY: la poignée vient d'un fichier ouvert avec le droit DELETE qui vit pendant l'appel ; `info` est une
    // FILE_RENAME_INFO à nous, de `taille` octets, dont le nom (terminé par un zéro, plus court que le tableau) fait
    // `longueur` octets ; l'appel la lit sans la garder.
    let ok =
        unsafe { SetFileInformationByHandle(f.as_raw_handle(), FILE_RENAME_INFO, (&raw const info).cast(), taille) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn refus(raison: String) -> Resultat {
    Resultat::echec(None, raison)
}

pub(super) fn meme_chemin(a: &str, b: &str) -> bool {
    a.trim_end_matches('\\').to_lowercase() == b.trim_end_matches('\\').to_lowercase()
}

/// L'empreinte du fichier ouvert, lu depuis son début par morceaux, et sa taille lue.
fn empreinte_flux(f: &File) -> std::io::Result<(String, u64)> {
    let mut lecteur = f;
    lecteur.seek(std::io::SeekFrom::Start(0))?;
    let mut h = sha2::Sha256::new();
    let mut tampon = vec![0u8; 1 << 20];
    let mut lu = 0u64;
    loop {
        let n = lecteur.read(&mut tampon)?;
        if n == 0 {
            break;
        }
        h.update(tampon.get(..n).unwrap_or_default());
        lu = lu.saturating_add(n as u64);
    }
    Ok((notes::hex(&h.finalize()), lu))
}

/// Le dossier Démarrage où le geste agit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Lieu {
    /// Celui de toute la machine, par le processus élevé.
    Commun,
    /// Celui de la personne, par Vanguard non élevé, sous son compte.
    Personne,
}

impl Lieu {
    fn dossier(self) -> Option<PathBuf> {
        match self {
            Lieu::Commun => super::environnement::demarrage_commun(),
            Lieu::Personne => super::environnement::demarrage_personne(),
        }
    }

    fn nom(self) -> &'static str {
        match self {
            Lieu::Commun => tr!("de toute la machine", "for all users"),
            Lieu::Personne => tr!("de votre compte", "of your account"),
        }
    }

    /// La ligne de la quarantaine de ce fichier, comme le bilan la propose.
    fn ligne(self, f: &CheminFichier) -> String {
        match self {
            Lieu::Commun => Acte::DemarrageQuarantaine(f.clone()).ligne(),
            Lieu::Personne => GesteCompte::DemarrageQuarantaine(f.clone()).ligne(),
        }
    }

    /// La clé des notes : sous HKLM (seul un administrateur y écrit) ou sous le HKCU de la personne (que ses
    /// programmes peuvent réécrire, comme ses fichiers : la remise n'écrit jamais que dans son propre dossier).
    fn notes(self) -> std::io::Result<RegKey> {
        let (racine, cle, vue) = match self {
            Lieu::Commun => (HKEY_LOCAL_MACHINE, gestes::DEMARRAGE_AVANT_CLE, KEY_WOW64_64KEY),
            Lieu::Personne => (HKEY_CURRENT_USER, gestes::DEMARRAGE_AVANT_COMPTE_CLE, 0),
        };
        RegKey::predef(racine)
            .create_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE | vue)
            .map(|(k, _)| k)
    }

    /// Le dossier de la quarantaine, vérifié : celui du processus élevé (réservé aux administrateurs), ou
    /// `<AppData\Local>\vanguard\quarantaine-demarrage`, atteint sans aucun lien ni jonction.
    fn quarantaine(self) -> Result<Quarantaine, Resultat> {
        let refuse = |raison: String| {
            refus(trf!(
                "la quarantaine ne s'ouvre pas ({raison}) : rien d'écrit",
                "the quarantine cannot be opened ({raison}): nothing written"
            ))
        };
        if self == Lieu::Commun {
            return super::quarantaine::dossier()
                .map(|dossier| Quarantaine { lieu: self, dossier })
                .map_err(|e| refuse(e.to_string()));
        }
        let base = if cfg!(test) {
            Some(crate::socle::dossier_local())
        } else {
            super::environnement::dossiers().appdata_local.clone()
        };
        let Some(base) = base.filter(|b| b.is_absolute()) else {
            return Err(refuse(
                tr!("dossier local introuvable", "local folder not found").to_string(),
            ));
        };
        let vanguard = base.join("vanguard");
        let q = vanguard.join("quarantaine-demarrage");
        for d in [&vanguard, &q] {
            match std::fs::create_dir(d) {
                Err(e) if e.kind() != AlreadyExists => return Err(refuse(e.to_string())),
                _ => {}
            }
        }
        let lien = |p: &Path| std::fs::symlink_metadata(p).map(|m| crate::machine::vidage::est_lien(&m) || !m.is_dir());
        if !notes::sans_lien(&q, &base, lien) {
            return Err(refuse(
                tr!(
                    "un de ses dossiers est un lien ou une jonction",
                    "one of its folders is a link or a junction"
                )
                .to_string(),
            ));
        }
        Ok(Quarantaine { lieu: self, dossier: q })
    }
}

/// Le dossier vérifié de la quarantaine d'un lieu. Celle de toute la machine passe par `quarantaine.rs`, qui revérifie
/// chaque niveau (lien, droits d'administrateur) à chaque appel ; celle de la personne a été vérifiée sans lien.
struct Quarantaine {
    lieu: Lieu,
    dossier: PathBuf,
}

/// Un nom de copie : un seul composant, jamais un chemin (il vient d'une note du registre).
fn nom_sur(nom: &str) -> bool {
    !nom.is_empty() && nom != "." && nom != ".." && !nom.contains(['\\', '/', ':', '\0'])
}

impl Quarantaine {
    fn chemin(&self, nom: &str) -> PathBuf {
        self.dossier.join(nom)
    }

    fn deposer(&self, nom: &str, octets: &[u8]) -> std::io::Result<()> {
        match self.lieu {
            Lieu::Commun => super::quarantaine::deposer(nom, octets)
                .map(drop)
                .map_err(|e| std::io::Error::other(e.to_string())),
            Lieu::Personne => deposer(&self.dossier, nom, octets),
        }
    }

    fn lire(&self, nom: &str) -> std::io::Result<Vec<u8>> {
        match self.lieu {
            Lieu::Commun => {
                super::quarantaine::lire(nom, notes::TAILLE_COPIE_MAX).map_err(|e| std::io::Error::other(e.to_string()))
            }
            Lieu::Personne if nom_sur(nom) => crate::socle::lire_ordinaire(&self.chemin(nom), notes::TAILLE_COPIE_MAX),
            Lieu::Personne => Err(std::io::Error::other(tr!("nom de fichier refusé", "file name refused"))),
        }
    }

    fn retirer(&self, nom: &str) -> std::io::Result<()> {
        match self.lieu {
            Lieu::Commun => super::quarantaine::retirer(nom).map_err(|e| std::io::Error::other(e.to_string())),
            Lieu::Personne if nom_sur(nom) => retirer_copie(&self.dossier, nom),
            Lieu::Personne => Err(std::io::Error::other(tr!("nom de fichier refusé", "file name refused"))),
        }
    }
}

/// Le nom de la note : le chemin en hexadécimal (la ligne de la remise sans son verbe), le même pour la quarantaine et
/// la remise.
fn nom_note(f: &CheminFichier) -> String {
    // En minuscules : Windows ne distingue pas « x.lnk » de « X.LNK », une seule série de copies pour les deux.
    let bas = CheminFichier::nouveau(&f.texte().to_lowercase()).unwrap_or_else(|| f.clone());
    Acte::DemarrageRemettre(bas, None)
        .ligne()
        .strip_prefix(gestes::DEMARRAGE_REMETTRE)
        .unwrap_or_default()
        .to_string()
}

/// Le fichier d'une note, d'après son nom ; `None` hors de la forme exacte.
fn fichier_de_note(nom: &str) -> Option<CheminFichier> {
    match gestes::analyser_acte(&format!("{}{nom}", gestes::DEMARRAGE_REMETTRE))? {
        Acte::DemarrageRemettre(f, None) => Some(f),
        _ => None,
    }
}

fn nom_de(f: &CheminFichier) -> &str {
    f.texte().rsplit_once('\\').map_or("", |(_, n)| n)
}

/// La note d'une version d'avant (une seule copie : « empreinte|nom de la copie »), sous HKLM seulement.
fn lire_note_ancienne(n: &str) -> Option<(String, String)> {
    let (empreinte, copie) = n.split_once('|')?;
    let bonne = empreinte.len() == 64
        && empreinte
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c));
    let sur = !copie.contains(['\\', '/', ':', '\0', '|', ';']) && copie != "." && copie != "..";
    (bonne && sur && copie.starts_with("demarrage-")).then(|| (empreinte.to_string(), copie.to_string()))
}

/// Toutes les notes lisibles de la quarantaine, par nom de note.
fn toutes_les_notes(k: &RegKey) -> Vec<(String, Vec<Version>)> {
    k.enum_values()
        .filter_map(Result::ok)
        .filter_map(|(nom, v)| {
            let t: String = winreg::types::FromRegValue::from_reg_value(&v).ok()?;
            Some((nom, notes::lire(&t)?))
        })
        .collect()
}

/// Les versions écrites sous ce nom de note ; aucune : la valeur est retirée.
fn noter(k: &RegKey, nom: &str, versions: &[Version]) -> std::io::Result<()> {
    if versions.is_empty() {
        match k.delete_value(nom) {
            Err(e) if e.kind() != NotFound => Err(e),
            _ => Ok(()),
        }
    } else {
        k.set_value(nom, &notes::ecrire(versions))
    }
}

/// Le fichier de la ligne, directement dans le dossier Démarrage du lieu (lu par le geste lui-même) : ce dossier et le
/// nom du fichier, ou le refus.
fn directement_dans(f: &CheminFichier, lieu: Lieu) -> Result<(String, String), Resultat> {
    let Some(dossier) = lieu.dossier() else {
        return Err(refus(trf!(
            "dossier Démarrage {} introuvable : rien d'écrit",
            "Startup folder {} not found: nothing written",
            lieu.nom()
        )));
    };
    let dossier = dossier.to_string_lossy().into_owned();
    match f.texte().rsplit_once('\\') {
        Some((parent, nom)) if meme_chemin(parent, &dossier) => Ok((dossier, nom.to_string())),
        _ => Err(refus(trf!(
            "ce fichier n'est pas directement dans le dossier Démarrage {} : rien d'écrit",
            "this file is not directly in the Startup folder {}: nothing written",
            lieu.nom()
        ))),
    }
}

/// Les dossiers Démarrage de la personne et de tous, tels que ce processus les lit, pour rejuger.
fn dossiers_lus() -> [Option<String>; 2] {
    [
        super::environnement::demarrage_personne(),
        super::environnement::demarrage_commun(),
    ]
    .map(|d| d.map(|d| d.to_string_lossy().into_owned()))
}

fn maintenant() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Une copie dite à la personne : son fichier, son numéro, sa taille.
fn decrire(nom_note: &str, v: &Version) -> String {
    let fichier = fichier_de_note(nom_note).map_or_else(|| "?".to_string(), |f| f.texte().to_string());
    let mode = match v.mode {
        Mode::Copie => tr!("copie", "copy"),
        Mode::Deplace => tr!("déplacé", "moved"),
    };
    trf!(
        "    {} : n° {} ({mode}, {} octets)",
        "    {}: no. {} ({mode}, {} bytes)",
        crate::ui::affichable(&fichier),
        v.n,
        v.taille
    )
}

/// Le geste : met en quarantaine le fichier `f` du dossier Démarrage du lieu si et seulement si le bilan, refait ici
/// sur ce fichier relu, le signale et propose cette même ligne (ou, pour un raccourci illisible sans COM, si la
/// personne le dit dans une vraie console après avoir vu ses octets).
pub(super) fn quarantaine(f: &CheminFichier, lieu: Lieu) -> Resultat {
    let ligne = lieu.ligne(f);
    let (_, nom) = match directement_dans(f, lieu) {
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
    let taille = match fichier.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            return refus(trf!(
                "le fichier ne se lit pas ({e}) : rien d'écrit",
                "the file cannot be read ({e}): nothing written"
            ));
        }
    };
    let mode = if taille <= notes::TAILLE_COPIE_MAX {
        Mode::Copie
    } else {
        Mode::Deplace
    };
    // Copié : lu en entier. Déplacé : son début seulement, pour le juger (un raccourci tient en un mégaoctet).
    let limite = if mode == Mode::Copie { taille } else { 1 << 20 };
    let mut octets = Vec::new();
    let lu = (&fichier).take(limite.saturating_add(1)).read_to_end(&mut octets);
    if let Err(e) = lu {
        return refus(trf!(
            "le fichier ne se lit pas ({e}) : rien d'écrit",
            "the file cannot be read ({e}): nothing written"
        ));
    }
    if mode == Mode::Copie && octets.len() as u64 != taille {
        return refus(
            tr!(
                "le fichier a changé pendant sa lecture : rien d'écrit",
                "the file changed while being read: nothing written"
            )
            .to_string(),
        );
    }
    let cible = super::persistance::cible_demarrage(f.texte(), &octets);
    let montre = protege::echappe_exact(&nom, 200);
    if let Some(cible) = &cible {
        let (programme, _) = crate::commande::decouper_commande(cible);
        let protege = protege::protege(&nom, &programme);
        if protege == Protege::Vrai {
            return refus(
                    tr!(
                        "entrée de Sécurité Windows ou de Defender (le vrai programme, signé par Microsoft) : Vanguard n'y touche jamais ; rien d'écrit",
                        "Windows Security or Defender entry (the real program, signed by Microsoft): Vanguard never touches it; nothing written"
                    )
                    .to_string(),
                );
        }
        let [personne, commun] = dossiers_lus();
        let dossiers = [personne.as_deref(), commun.as_deref()];
        if !super::persistance::demarrage_signale(f.texte(), cible, dossiers, &ligne) {
            return refus(
                tr!(
                    "le bilan refait ici ne signale pas ce fichier : rien d'écrit",
                    "the check run again here does not report this file: nothing written"
                )
                .to_string(),
            );
        }
        if protege == Protege::NomSeul
            && !protege::accord(
                &protege::texte_nom_seul(&nom, &programme),
                protege::question_quand_meme(),
            )
        {
            return refus(protege::non_confirme());
        }
    } else {
        let mut explication = trf!(
            "  Le raccourci {montre} ne se lit pas sans COM : Vanguard ne peut pas le rejuger ici. Ses premiers octets, tels quels, puis ses textes :\n{}",
            "  The shortcut {montre} cannot be read without COM: Vanguard cannot judge it again here. Its first bytes, as they are, then its texts:\n{}",
            notes::octets_montres(&octets)
        );
        if gestes::run_protege(&nom, "") {
            explication.push_str(tr!(
                    "  Il porte le nom de Defender ou de Sécurité Windows (ceux-ci ne passent pas par un raccourci du dossier Démarrage).",
                    "  It bears the name of Defender or Windows Security (those do not use a Startup folder shortcut)."
                ));
        }
        let question = tr!(
            "  Le mettre en quarantaine quand même ? [o/N] : ",
            "  Quarantine it anyway? [y/N]: "
        );
        if !protege::accord(&explication, question) {
            return refus(protege::non_confirme());
        }
    }
    if mode == Mode::Deplace {
        let explication = trf!(
            "  {montre} fait {} Mio, plus qu'une copie de quarantaine ({} Mio) : il sera déplacé tel quel dans la quarantaine, sur le même disque (rien de neuf n'est écrit), puis remis à sa place si vous le demandez.",
            "  {montre} is {} MiB, more than a quarantine copy ({} MiB): it will be moved as it is into the quarantine, on the same disk (nothing new is written), then put back if you ask.",
            taille >> 20,
            notes::TAILLE_COPIE_MAX >> 20
        );
        let question = tr!(
            "  Le déplacer en quarantaine ? [o/N] : ",
            "  Move it into the quarantine? [y/N]: "
        );
        if !protege::accord(&explication, question) {
            return refus(protege::non_confirme());
        }
    }
    let cle = match lieu.notes() {
        Ok(k) => k,
        Err(e) => {
            return refus(trf!(
                "les notes de la quarantaine ne s'ouvrent pas ({e}) : rien d'écrit",
                "the quarantine notes cannot be opened ({e}): nothing written"
            ));
        }
    };
    let nom_note = nom_note(f);
    let mut miennes = match cle.get_value::<String, _>(&nom_note) {
        Err(e) if e.kind() == NotFound => Vec::new(),
        Ok(t) => match notes::lire(&t) {
            Some(v) => v,
            // La note d'une version d'avant : sa copie attend toujours sa remise, que la nouvelle effacerait.
            None if lire_note_ancienne(&t).is_some() => {
                return refus(
                    tr!(
                        "une copie de ce fichier, d'une version d'avant de Vanguard, attend sa remise : la remettre d'abord ; rien d'écrit",
                        "a copy of this file, from an earlier Vanguard version, is waiting to be put back: put it back first; nothing written"
                    )
                    .to_string(),
                );
            }
            // Abîmée ou réécrite par un autre programme : la remplacer perd l'accès aux copies d'avant, d'où la
            // question ; un programme qui la brouille ne se met pas ainsi à l'abri.
            None => {
                let explication = tr!(
                    "  La note de Vanguard pour ce fichier est illisible (abîmée, ou réécrite par un autre programme) : la remplacer perd l'accès aux copies d'avant de ce fichier.",
                    "  Vanguard's note for this file is unreadable (damaged, or rewritten by another program): replacing it loses access to this file's earlier copies."
                );
                if !protege::accord(explication, protege::question_non_annulable()) {
                    return refus(protege::non_confirme());
                }
                Vec::new()
            }
        },
        Err(e) => {
            return refus(trf!(
                "la note de ce fichier ne se lit pas ({e}) : rien d'écrit",
                "this file's note cannot be read ({e}): nothing written"
            ));
        }
    };
    let mut toutes: Vec<(String, Vec<Version>)> = toutes_les_notes(&cle)
        .into_iter()
        .filter(|(k, _)| *k != nom_note)
        .collect();
    toutes.push((nom_note.clone(), miennes.clone()));
    let Some(ajout) = notes::placer(&nom_note, &toutes, taille, mode) else {
        return refus(
            tr!(
                "ce fichier ne tient pas dans la quarantaine : rien d'écrit",
                "this file does not fit in the quarantine: nothing written"
            )
            .to_string(),
        );
    };
    if !ajout.effacer.is_empty() {
        let mut explication = trf!(
            "  Pour garder cette copie, Vanguard doit effacer pour de bon les plus vieilles de sa quarantaine ({} copies par fichier, {} Mio de copies en tout, {} fichiers déplacés au plus) :",
            "  To keep this copy, Vanguard must permanently erase the oldest ones in its quarantine ({} copies per file, {} MiB of copies in all, {} moved files at most):",
            notes::COPIES_MAX,
            notes::TOTAL_MAX >> 20,
            notes::DEPLACES_MAX
        );
        for (k, n) in &ajout.effacer {
            if let Some(v) = toutes
                .iter()
                .find(|(c, _)| c == k)
                .and_then(|(_, vs)| vs.iter().find(|v| v.n == *n))
            {
                explication.push('\n');
                explication.push_str(&decrire(k, v));
            }
        }
        if !protege::accord(&explication, protege::question_non_annulable()) {
            return refus(protege::non_confirme());
        }
    }
    let q = match lieu.quarantaine() {
        Ok(q) => q,
        Err(r) => return r,
    };
    let (avant_le_depot, apres) = notes::avant_le_depot(&ajout, &nom_note);
    // Celle des siennes qui cède sa place sous le numéro de la nouvelle (le même nom) : la seule effacée avant le
    // dépôt, sa note réécrite d'abord (jamais une note qui désigne une copie effacée). Les autres attendent la
    // nouvelle, déposée et notée : un échec d'ici là n'a effacé qu'elle, et le dit.
    if avant_le_depot {
        let restent: Vec<Version> = miennes.iter().filter(|v| v.n != ajout.n).cloned().collect();
        if let Err(e) = noter(&cle, &nom_note, &restent) {
            return refus(trf!(
                "la note de ce fichier ne s'écrit pas ({e}) : rien d'écrit",
                "this file's note cannot be written ({e}): nothing written"
            ));
        }
        if let Err(e) = q.retirer(&notes::nom_copie(&nom, ajout.n)) {
            let _ = noter(&cle, &nom_note, &miennes);
            return refus(trf!(
                "une vieille copie ne s'efface pas ({e}) : rien d'écrit",
                "an old copy cannot be erased ({e}): nothing written"
            ));
        }
        miennes = restent;
    }
    let fin = deposer_et_retirer(Depot {
        f,
        fichier,
        q: &q,
        cle: &cle,
        nom_note: &nom_note,
        nom: &nom,
        cible: cible.as_deref(),
        octets: &octets,
        taille,
        mode,
        n: ajout.n,
        miennes,
        sans: &apres,
    });
    let fin = if avant_le_depot && !fin.reussi && fin.avant.is_none() {
        Resultat::echec(
            None,
            trf!(
                "{} (seule la copie n° {} de ce fichier, dont l'effacement a été accepté, est déjà effacée)",
                "{} (only this file's copy no. {}, whose erasure was accepted, is already erased)",
                fin.raison,
                ajout.n
            ),
        )
    } else {
        fin
    };
    // La nouvelle copie est déposée et notée (même si le fichier attend sa fermeture) : les vieilles copies cèdent
    // leur place maintenant, chaque note réécrite avant d'effacer sa copie ; une note qui ne s'écrit pas garde sa
    // copie.
    if fin.avant.is_some() {
        for (k, n) in &apres {
            let (Some(fk), Some((_, vs))) = (fichier_de_note(k), toutes.iter().find(|(c, _)| c == k)) else {
                continue;
            };
            if *k != nom_note {
                let restent: Vec<Version> = vs.iter().filter(|v| v.n != *n).cloned().collect();
                if noter(&cle, k, &restent).is_err() {
                    continue;
                }
                if let Some(t) = toutes.iter_mut().find(|(c, _)| c == k) {
                    t.1 = restent;
                }
            }
            let _ = q.retirer(&notes::nom_copie(nom_de(&fk), *n));
        }
    }
    fin
}

/// Ce que le dépôt de la nouvelle copie reprend de `quarantaine`.
struct Depot<'a> {
    f: &'a CheminFichier,
    /// Le fichier ouvert, fermé ici une fois marqué (il part à sa fermeture).
    fichier: File,
    q: &'a Quarantaine,
    cle: &'a RegKey,
    nom_note: &'a str,
    nom: &'a str,
    cible: Option<&'a str>,
    octets: &'a [u8],
    taille: u64,
    mode: Mode,
    n: u8,
    miennes: Vec<Version>,
    /// Les copies de ce fichier qui cèdent leur place après le dépôt : absentes de sa nouvelle note.
    sans: &'a [(String, u8)],
}

/// La nouvelle copie déposée, vérifiée et notée, puis le fichier retiré. `avant` : `Some` dès que la copie est notée.
fn deposer_et_retirer(d: Depot<'_>) -> Resultat {
    let Depot {
        f,
        fichier,
        q,
        cle,
        nom_note,
        nom,
        cible,
        octets,
        taille,
        mode,
        n,
        mut miennes,
        sans,
    } = d;
    let ancien = miennes.clone();
    miennes.retain(|v| !sans.iter().any(|(k, m)| k == nom_note && *m == v.n));
    let copie = notes::nom_copie(nom, n);
    let chemin_copie = q.chemin(&copie);
    let empreinte = match mode {
        Mode::Copie => {
            if let Err(e) = q.deposer(&copie, octets) {
                return refus(trf!(
                    "la copie en quarantaine n'a pas pu être faite ({e}) : rien d'écrit",
                    "the quarantine copy could not be made ({e}): nothing written"
                ));
            }
            if !q.lire(&copie).is_ok_and(|relue| relue == octets) {
                let _ = q.retirer(&copie);
                return refus(
                    tr!(
                        "la copie en quarantaine relue n'est pas identique : rien d'écrit",
                        "the quarantine copy read back is not identical: nothing written"
                    )
                    .to_string(),
                );
            }
            notes::sha256(octets)
        }
        Mode::Deplace => {
            let empreinte = match empreinte_flux(&fichier) {
                Ok((e, lu)) if lu == taille => e,
                Ok(_) => {
                    return refus(
                        tr!(
                            "le fichier a changé pendant sa lecture : rien d'écrit",
                            "the file changed while being read: nothing written"
                        )
                        .to_string(),
                    );
                }
                Err(e) => {
                    return refus(trf!(
                        "le fichier ne se lit pas ({e}) : rien d'écrit",
                        "the file cannot be read ({e}): nothing written"
                    ));
                }
            };
            match renommer(&fichier, &chemin_copie) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(AUTRE_DISQUE) => {
                    return refus(
                        tr!(
                            "la quarantaine est sur un autre disque : un fichier de cette taille ne s'y déplace pas ; rien d'écrit",
                            "the quarantine is on another disk: a file this size cannot be moved there; nothing written"
                        )
                        .to_string(),
                    );
                }
                Err(e) => {
                    return refus(trf!(
                        "le fichier ne se déplace pas ({e}) : rien d'écrit",
                        "the file cannot be moved ({e}): nothing written"
                    ));
                }
            }
            let q_texte = q.dossier.to_string_lossy();
            let arrive = chemin_final(&fichier)
                .is_some_and(|c| c.rsplit_once('\\').is_some_and(|(p, _)| meme_chemin(p, &q_texte)));
            if !arrive {
                let _ = renommer(&fichier, Path::new(f.texte()));
                return refus(
                    tr!(
                        "le fichier déplacé n'est pas arrivé dans la quarantaine : remis à sa place ; rien d'écrit",
                        "the moved file did not arrive in the quarantine: put back in place; nothing written"
                    )
                    .to_string(),
                );
            }
            empreinte
        }
    };
    let defaire_copie = || match mode {
        Mode::Copie => {
            let _ = q.retirer(&copie);
        }
        Mode::Deplace => {
            let _ = renommer(&fichier, Path::new(f.texte()));
        }
    };
    miennes.push(Version {
        n,
        secondes: maintenant(),
        taille,
        mode,
        empreinte,
    });
    // Notée d'abord : sans note, pas de retrait (la remise serait perdue).
    if let Err(e) = noter(cle, nom_note, &miennes) {
        defaire_copie();
        return refus(trf!(
            "la copie ne se note pas ({e}) : rien d'écrit",
            "the copy cannot be noted ({e}): nothing written"
        ));
    }
    let avant = avant_notable(&trf!(
        "{} → {} (copie n° {})",
        "{} → {} (copy no. {})",
        f.texte(),
        cible.unwrap_or("?"),
        n
    ));
    if mode == Mode::Copie
        && let Err(e) = marquer_pour_retrait(&fichier)
    {
        let _ = noter(cle, nom_note, &ancien);
        defaire_copie();
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

/// Dépose ces octets dans le dossier vérifié de la quarantaine, jamais par-dessus un fichier qui existe (ni un lien).
fn deposer(dossier: &Path, nom: &str, octets: &[u8]) -> std::io::Result<()> {
    let chemin = dossier.join(nom);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&chemin)?;
    if let Err(e) = f.write_all(octets).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(&chemin);
        return Err(e);
    }
    Ok(())
}

/// Retire une copie de la quarantaine (un lien serait retiré lui-même, jamais ce qu'il vise) ; déjà absente, rien.
fn retirer_copie(dossier: &Path, nom: &str) -> std::io::Result<()> {
    match std::fs::remove_file(dossier.join(nom)) {
        Err(e) if e.kind() != NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Ce que la remise reprend : la copie (son nom dans la quarantaine), son empreinte et son mode, puis les copies qui
/// restent notées (`None` : une note d'une version d'avant, retirée).
struct Source {
    copie: String,
    empreinte: String,
    mode: Mode,
    restent: Option<Vec<Version>>,
    n: Option<u8>,
}

/// La copie choisie (`n`, ou la plus récente) d'après la note du fichier ; le refus sinon.
fn source(cle: &RegKey, f: &CheminFichier, n: Option<u8>, lieu: Lieu) -> Result<Source, Resultat> {
    let aucune = || {
        refus(
            tr!(
                "aucune copie notée par Vanguard pour ce fichier : rien d'écrit",
                "no copy noted by Vanguard for this file: nothing written"
            )
            .to_string(),
        )
    };
    let Ok(texte) = cle.get_value::<String, _>(nom_note(f)) else {
        return Err(aucune());
    };
    if let Some(versions) = notes::lire(&texte) {
        let Some(v) = notes::choisir(&versions, n) else {
            let numeros: Vec<String> = versions.iter().map(|v| v.n.to_string()).collect();
            return Err(refus(trf!(
                "pas de copie n° {} ; copies gardées : {} ; rien d'écrit",
                "no copy no. {}; copies kept: {}; nothing written",
                n.unwrap_or_default(),
                numeros.join(", ")
            )));
        };
        return Ok(Source {
            copie: notes::nom_copie(nom_de(f), v.n),
            empreinte: v.empreinte.clone(),
            mode: v.mode,
            restent: Some(versions.iter().filter(|x| x.n != v.n).cloned().collect()),
            n: Some(v.n),
        });
    }
    match lire_note_ancienne(&texte) {
        Some((empreinte, copie)) if lieu == Lieu::Commun && n.is_none() => Ok(Source {
            copie,
            empreinte,
            mode: Mode::Copie,
            restent: None,
            n: None,
        }),
        _ => Err(aucune()),
    }
}

/// Le geste : remet le fichier `f` depuis la copie `n` (ou la plus récente) notée par `quarantaine`, vérifiée par son
/// empreinte, jamais par-dessus un fichier présent ; la copie est retirée de la quarantaine et de la note après
/// relecture.
pub(super) fn remettre(f: &CheminFichier, n: Option<u8>, lieu: Lieu) -> Resultat {
    let (dossier_demarrage, _) = match directement_dans(f, lieu) {
        Ok(c) => c,
        Err(r) => return r,
    };
    let cle = match lieu.notes() {
        Ok(k) => k,
        Err(e) => {
            return refus(trf!(
                "les notes de la quarantaine ne s'ouvrent pas ({e}) : rien d'écrit",
                "the quarantine notes cannot be opened ({e}): nothing written"
            ));
        }
    };
    let source = match source(&cle, f, n, lieu) {
        Ok(s) => s,
        Err(r) => return r,
    };
    let quarantaine = match lieu.quarantaine() {
        Ok(q) => q,
        Err(r) => return r,
    };
    let nom_note = nom_note(f);
    let terminer = || {
        let _ = match &source.restent {
            Some(restent) => noter(&cle, &nom_note, restent),
            None => noter(&cle, &nom_note, &[]),
        };
        if source.mode == Mode::Copie {
            let _ = quarantaine.retirer(&source.copie);
        }
    };
    // Le dossier lui-même, ouvert sans suivre de lien : ni lien ni jonction, et bien celui que lit le geste. Sa poignée
    // reste ouverte sans partage du retrait jusqu'à la fin : il ne peut être ni renommé ni remplacé par une jonction
    // entre ce contrôle et l'écriture.
    let dossier = std::fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(&dossier_demarrage)
        .ok()
        .filter(|d| {
            information(d).is_some_and(|(a, _)| a & ATTRIBUT_DOSSIER != 0 && a & ATTRIBUT_POINT_D_ANALYSE == 0)
                && chemin_final(d).is_some_and(|c| meme_chemin(&c, &dossier_demarrage))
        });
    if dossier.is_none() {
        return refus(
            tr!(
                "le dossier Démarrage est un lien, une jonction ou ne s'ouvre pas : rien d'écrit",
                "the Startup folder is a link, a junction or cannot be opened: nothing written"
            )
            .to_string(),
        );
    }
    let absent = match source.n {
        Some(n) => trf!("absent (copie n° {n} remise)", "absent (copy no. {n} put back)"),
        None => tr!("absent", "absent").to_string(),
    };
    let resultat = match source.mode {
        Mode::Copie => remettre_copie(f, quarantaine.lire(&source.copie), &source.empreinte, &absent),
        Mode::Deplace => remettre_deplace(f, &quarantaine.chemin(&source.copie), &source.empreinte, &absent),
    };
    drop(dossier);
    if remise_faite(&resultat) {
        terminer();
    }
    resultat
}

/// La copie et sa note ne partent qu'après une vraie remise : « déjà là, identique » (rien d'écrit) les garde, le
/// fichier redéposé tel quel pouvant repartir.
fn remise_faite(r: &Resultat) -> bool {
    r.reussi && !r.rien
}

/// La remise d'une copie : relue et vérifiée par son empreinte, écrite dans un fichier créé (jamais par-dessus un
/// autre), relue par la même poignée.
fn remettre_copie(f: &CheminFichier, copie: std::io::Result<Vec<u8>>, empreinte: &str, absent: &str) -> Resultat {
    let octets = match copie {
        Ok(o) if notes::sha256(&o) == empreinte => o,
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
    match std::fs::symlink_metadata(f.texte()) {
        Err(e) if e.kind() == NotFound => {}
        Ok(m)
            if m.is_file()
                && crate::socle::lire_ordinaire(Path::new(f.texte()), notes::TAILLE_COPIE_MAX)
                    .is_ok_and(|o| o == octets) =>
        {
            return Resultat::rien(
                tr!(
                    "le fichier est déjà là, identique : rien à remettre",
                    "the file is already there, identical: nothing to put back"
                )
                .to_string(),
            );
        }
        _ => return deja_un_autre(),
    }
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
                Some(absent.to_string()),
                trf!(
                    "{raison} ; le fichier créé n'a pas pu être retiré, la note et la copie sont gardées",
                    "{raison}; the created file could not be removed, the note and the copy are kept"
                ),
            )
        }
    };
    if !chemin_final(&nouveau).is_some_and(|c| meme_chemin(&c, f.texte())) {
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
    let lu = (&nouveau).take(notes::TAILLE_COPIE_MAX + 1).read_to_end(&mut relu);
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
    Resultat::fait(absent.to_string())
}

fn deja_un_autre() -> Resultat {
    refus(
        tr!(
            "un autre fichier porte déjà ce nom : Vanguard n'écrit jamais par-dessus ; rien d'écrit",
            "another file already has this name: Vanguard never writes over it; nothing written"
        )
        .to_string(),
    )
}

/// La remise d'un fichier déplacé : ouvert sans suivre de lien, un seul nom, vérifié par son empreinte sur sa poignée,
/// puis renommé par elle à sa place (jamais par-dessus un fichier présent).
fn remettre_deplace(f: &CheminFichier, copie: &Path, empreinte: &str, absent: &str) -> Resultat {
    let fichier = match std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(copie)
    {
        Ok(o) => o,
        Err(e) => {
            return refus(trf!(
                "le fichier en quarantaine ne s'ouvre pas ({e}) : rien d'écrit",
                "the quarantined file cannot be opened ({e}): nothing written"
            ));
        }
    };
    let ordinaire = information(&fichier)
        .is_some_and(|(a, liens)| a & (ATTRIBUT_POINT_D_ANALYSE | ATTRIBUT_DOSSIER) == 0 && liens == 1);
    if !ordinaire || !empreinte_flux(&fichier).is_ok_and(|(e, _)| e == empreinte) {
        return refus(
            tr!(
                "le fichier en quarantaine a changé (empreinte différente, lien ou plusieurs noms) : rien d'écrit",
                "the quarantined file changed (different fingerprint, link or several names): nothing written"
            )
            .to_string(),
        );
    }
    if std::fs::symlink_metadata(f.texte()).is_ok() {
        return deja_un_autre();
    }
    if let Err(e) = renommer(&fichier, Path::new(f.texte())) {
        return refus(trf!(
            "le fichier ne se remet pas à sa place ({e}) : rien d'écrit",
            "the file cannot be put back in place ({e}): nothing written"
        ));
    }
    if !chemin_final(&fichier).is_some_and(|c| meme_chemin(&c, f.texte())) {
        let _ = renommer(&fichier, copie);
        return refus(
            tr!(
                "le fichier remis n'est pas au chemin de la ligne : rendu à la quarantaine ; rien d'écrit",
                "the file put back is not at the line's path: returned to the quarantine; nothing written"
            )
            .to_string(),
        );
    }
    Resultat::fait(absent.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_note_garde_empreinte_et_copie() {
        let e = "0".repeat(64);
        let note = |e: &str, c: &str| format!("{e}|{c}");
        assert_eq!(
            lire_note_ancienne(&note(&e, "demarrage-1-a.lnk")),
            Some((e.clone(), "demarrage-1-a.lnk".into()))
        );
        // Empreinte mal formée, copie hors de la quarantaine des fichiers de démarrage, chemin : refusées.
        assert_eq!(lire_note_ancienne(&note(&"0".repeat(63), "demarrage-1-a.lnk")), None);
        assert_eq!(lire_note_ancienne(&note(&"A".repeat(64), "demarrage-1-a.lnk")), None);
        assert_eq!(lire_note_ancienne(&note(&e, "racine-1.cer")), None);
        assert_eq!(lire_note_ancienne(&note(&e, r"demarrage-..\..\x")), None);
        assert_eq!(lire_note_ancienne("sans barre"), None);
    }

    #[test]
    fn chemins_compares_sans_casse() {
        assert!(meme_chemin(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
            r"c:\programdata\microsoft\windows\start menu\programs\Startup\"
        ));
        assert!(!meme_chemin(r"C:\ProgramData\a", r"C:\ProgramData\b"));
    }

    /// « Déjà là, identique » garde la copie et sa note ; une vraie remise seulement les termine.
    #[test]
    fn deja_la_garde_la_copie() {
        assert!(!remise_faite(&Resultat::rien("déjà là, identique".into())));
        assert!(!remise_faite(&Resultat::echec(None, "x".into())));
        assert!(remise_faite(&Resultat::fait("absent".into())));
    }

    /// Le nom d'une note se relit en son fichier, et pas autrement.
    #[test]
    fn note_et_fichier() {
        let f = CheminFichier::nouveau(r"C:\Users\alice\Start\x.lnk").unwrap();
        assert_eq!(
            fichier_de_note(&nom_note(&f)),
            CheminFichier::nouveau(r"c:\users\alice\start\x.lnk")
        );
        // Une seule note pour les deux casses du même fichier.
        let haut = CheminFichier::nouveau(r"C:\USERS\Alice\START\X.LNK").unwrap();
        assert_eq!(nom_note(&haut), nom_note(&f));
        assert_eq!(nom_de(&f), "x.lnk");
        assert_eq!(fichier_de_note(&format!("{} 3", nom_note(&f))), None);
        assert_eq!(fichier_de_note("zz"), None);
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

    /// Le déplacement par la poignée : le fichier jugé arrive sous son nouveau nom, son empreinte suivie ; jamais par
    /// dessus un fichier présent. La copie déposée ne remplace pas non plus un fichier ni un nom pris.
    #[test]
    fn deplace_par_la_poignee_jamais_par_dessus() {
        let dossier = crate::essais::temporaire().join(format!("vanguard-deplace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).unwrap();
        let (a, b, c) = (dossier.join("a.bin"), dossier.join("b.bin"), dossier.join("c.bin"));
        std::fs::write(&a, b"contenu").unwrap();
        std::fs::write(&c, b"autre").unwrap();
        let f = std::fs::OpenOptions::new()
            .access_mode(GENERIC_READ | DELETE)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&a)
            .unwrap();
        let (empreinte, taille) = empreinte_flux(&f).unwrap();
        assert_eq!((empreinte, taille), (notes::sha256(b"contenu"), 7));
        assert!(renommer(&f, &c).is_err(), "jamais par-dessus un fichier présent");
        assert!(renommer(&f, Path::new("relatif.bin")).is_err());
        renommer(&f, &b).unwrap();
        drop(f);
        assert!(!a.exists());
        assert_eq!(std::fs::read(&b).unwrap(), b"contenu");
        assert_eq!(std::fs::read(&c).unwrap(), b"autre");
        assert!(deposer(&dossier, "c.bin", b"x").is_err());
        assert_eq!(std::fs::read(&c).unwrap(), b"autre");
        deposer(&dossier, "d.bin", b"y").unwrap();
        retirer_copie(&dossier, "d.bin").unwrap();
        retirer_copie(&dossier, "d.bin").unwrap();
        let _ = std::fs::remove_dir_all(&dossier);
    }
}
