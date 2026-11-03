//! La quarantaine du processus élevé : `%ProgramData%\Vanguard\quarantaine`, où il dépose ce qu'il retire (le
//! certificat d'une racine retirée), jamais dans le dossier du compte.
//!
//! Chaque niveau est créé par le processus élevé, avec une liste des droits réservée à SYSTEM et aux Administrateurs.
//! Déjà là, il n'est utilisé que s'il n'est ni un lien ni un point d'analyse, que son propriétaire est SYSTEM ou les
//! Administrateurs et qu'aucun autre compte ne peut y écrire : un compte ordinaire peut créer un dossier sous
//! ProgramData avant Vanguard, puis y poser une jonction vers un dossier de Windows.

// FFI de kernel32 : CreateDirectoryW avec un descripteur de sécurité.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use super::securite::{self, ConvertStringSecurityDescriptorToSecurityDescriptorW, Securite};
use crate::modele::Echec;
use crate::ui::{tr, trf};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateDirectoryW(chemin: *const u16, securite: *const Securite) -> i32;
}

/// Protégée (sans héritage de ProgramData, où les Utilisateurs créent des dossiers), héritée par le contenu.
/// Le propriétaire est posé (les Administrateurs), jamais laissé au réglage du compte.
const DROITS: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Crée le dossier avec la liste des droits réservée ; `Ok(())` aussi s'il existe déjà (vérifié ensuite).
fn creer(chemin: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const DEJA_LA: i32 = 183;
    let nom: Vec<u16> = chemin.as_os_str().encode_wide().chain([0]).collect();
    let sddl: Vec<u16> = DROITS.encode_utf16().chain([0]).collect();
    let taille = u32::try_from(std::mem::size_of::<Securite>()).map_err(std::io::Error::other)?;
    let mut descripteur: *mut c_void = std::ptr::null_mut();
    // SAFETY: le texte SDDL et le nom sont terminés par un zéro et vivent pendant les appels ; le descripteur alloué
    // par Windows (vérifié non nul) vit pendant CreateDirectoryW, puis est rendu une seule fois par LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &raw mut descripteur,
            std::ptr::null_mut(),
        ) == 0
            || descripteur.is_null()
        {
            return Err(std::io::Error::last_os_error());
        }
        let attributs = Securite {
            taille,
            descripteur,
            heritable: 0,
        };
        let cree = CreateDirectoryW(nom.as_ptr(), &raw const attributs) != 0;
        let erreur = std::io::Error::last_os_error();
        super::processus::LocalFree(descripteur);
        if cree || erreur.raw_os_error() == Some(DEJA_LA) {
            Ok(())
        } else {
            Err(erreur)
        }
    }
}

/// Le dossier, créé s'il manque, puis vérifié ; le refus dit pourquoi.
fn niveau(chemin: &Path) -> Result<(), Echec> {
    let montre = crate::ui::chemin_affichable(chemin);
    if std::fs::symlink_metadata(chemin).is_err() {
        creer(chemin).map_err(|e| {
            Echec::echoue(
                "quarantaine/creer",
                trf!(
                    "{montre} n'a pas pu être créé ({e})",
                    "{montre} could not be created ({e})"
                ),
            )
        })?;
    }
    let meta = std::fs::symlink_metadata(chemin).map_err(|e| Echec::io("quarantaine/lire", &e))?;
    if crate::machine::vidage::est_lien(&meta) || !meta.is_dir() {
        return Err(Echec::refuse(
            "quarantaine/dossier",
            trf!(
                "{montre} est un lien ou n'est pas un dossier : refusé",
                "{montre} is a link or not a folder: refused"
            ),
        ));
    }
    if !securite::proprietaire_et_droits(chemin).is_some_and(|d| securite::reserve_aux_administrateurs(&d)) {
        return Err(Echec::refuse(
            "quarantaine/droits",
            trf!(
                "{montre} appartient à un autre compte ou d'autres comptes peuvent y écrire : refusé",
                "{montre} belongs to another account or other accounts can write to it: refused"
            ),
        ));
    }
    Ok(())
}

/// Le dossier de la quarantaine, vérifié niveau par niveau.
fn dossier() -> Result<PathBuf, Echec> {
    let base = super::environnement::dossiers().program_data.clone().ok_or_else(|| {
        Echec::echoue(
            "quarantaine/dossier",
            tr!("dossier ProgramData introuvable", "ProgramData folder not found"),
        )
    })?;
    let vanguard = base.join("Vanguard");
    niveau(&vanguard)?;
    let quarantaine = vanguard.join("quarantaine");
    niveau(&quarantaine)?;
    Ok(quarantaine)
}

/// Dépose ces octets dans la quarantaine sous ce nom (jamais par-dessus un fichier qui existe) ; le chemin du fichier.
pub(super) fn deposer(nom: &str, octets: &[u8]) -> Result<PathBuf, Echec> {
    let chemin = dossier()?.join(nom);
    let montre = crate::ui::chemin_affichable(&chemin);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&chemin)
        .map_err(|e| {
            Echec::echoue(
                "quarantaine/deposer",
                trf!(
                    "{montre} n'a pas pu être créé ({e})",
                    "{montre} could not be created ({e})"
                ),
            )
        })?;
    if let Err(e) = f.write_all(octets).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(&chemin);
        return Err(Echec::echoue(
            "quarantaine/deposer",
            trf!(
                "{montre} n'a pas pu être écrit ({e})",
                "{montre} could not be written ({e})"
            ),
        ));
    }
    Ok(chemin)
}

/// Un nom de fichier de la quarantaine : un seul composant, jamais un chemin (il vient d'une note du registre).
fn nom_sur(nom: &str) -> bool {
    !nom.is_empty() && nom != "." && nom != ".." && !nom.contains(['\\', '/', ':', '\0'])
}

/// Relit un fichier de la quarantaine (un simple fichier, jamais un lien), au plus `max` octets.
pub(super) fn lire(nom: &str, max: u64) -> Result<Vec<u8>, Echec> {
    if !nom_sur(nom) {
        return Err(Echec::refuse(
            "quarantaine/lire",
            tr!("nom de fichier refusé", "file name refused"),
        ));
    }
    let chemin = dossier()?.join(nom);
    crate::socle::lire_ordinaire(&chemin, max).map_err(|e| Echec::io("quarantaine/lire", &e))
}

/// Retire un fichier de la quarantaine (une copie remise à sa place) ; un fichier déjà absent n'est pas une erreur.
pub(super) fn retirer(nom: &str) -> Result<(), Echec> {
    if !nom_sur(nom) {
        return Err(Echec::refuse(
            "quarantaine/retirer",
            tr!("nom de fichier refusé", "file name refused"),
        ));
    }
    let chemin = dossier()?.join(nom);
    match std::fs::remove_file(&chemin) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(Echec::io("quarantaine/retirer", &e)),
        _ => Ok(()),
    }
}
