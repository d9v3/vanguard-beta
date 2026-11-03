//! Retirer une racine signalée par le bilan (`vanguard:certificat-retirer <lm|cu> <empreinte>`, grammaire de
//! `gestes.rs`), dans le processus élevé, par crypt32, sans PowerShell.
//!
//! Le processus élevé relit les deux magasins « Root » et rejuge la racine par la fonction du bilan
//! (`certificats::retrait`) : même magasin, même empreinte exacte. Il exporte le certificat (sans clé privée) dans la
//! quarantaine, le retire, puis le cherche de nouveau : seule la relecture compte. Pour le magasin du compte, Windows
//! montre sa propre fenêtre de confirmation, et ce magasin doit être celui de la personne (le processus élevé peut
//! tourner sous un autre compte administrateur). Jamais un ajout : Vanguard ne remet pas une racine retirée ; la
//! copie de la quarantaine permet à la personne de la réimporter elle-même.

// FFI de crypt32 : CertOpenStore, CertFindCertificateInStore, CertDeleteCertificateFromStore.
#![allow(unsafe_code)]

use std::ffi::c_void;

use super::corrections::{Resultat, avant_notable};
use super::magasins::{
    CertCloseStore, CertDeleteCertificateFromStore, CertFindCertificateInStore, CertFreeCertificateContext,
    CertOpenStore,
};
use crate::machine::certificats;
use crate::machine::gestes::{Empreinte, MagasinRacine};
use crate::ui::{tr, trf};

/// CERT_CONTEXT de wincrypt.h : le certificat encodé (DER) et sa taille.
#[repr(C)]
struct ContexteCertificat {
    _encodage: u32,
    octets: *const u8,
    taille: u32,
    _infos: *const c_void,
    _magasin: *mut c_void,
}

/// CRYPT_HASH_BLOB.
#[repr(C)]
struct Empreinte20 {
    taille: u32,
    octets: *const u8,
}

/// Un magasin « Root » ouvert, fermé une seule fois.
struct Magasin(*mut c_void);

impl Magasin {
    fn ouvrir(m: MagasinRacine, lecture_seule: bool) -> Option<Magasin> {
        const SYSTEME: usize = 10;
        const EXISTANT: u32 = 0x4000;
        const LECTURE_SEULE: u32 = 0x8000;
        let emplacement: u32 = match m {
            MagasinRacine::Ordinateur => 2 << 16,
            MagasinRacine::Compte => 1 << 16,
        };
        let drapeaux = emplacement | EXISTANT | if lecture_seule { LECTURE_SEULE } else { 0 };
        let racine: Vec<u16> = "Root".encode_utf16().chain([0]).collect();
        // SAFETY: le nom du magasin est terminé par un zéro et vit pendant l'appel ; un magasin nul (refus) n'est
        // jamais gardé, un autre l'est par `Magasin`, qui le ferme une seule fois.
        let magasin = unsafe { CertOpenStore(SYSTEME as *const i8, 0, 0, drapeaux, racine.as_ptr().cast()) };
        (!magasin.is_null()).then_some(Magasin(magasin))
    }

    /// Le certificat de cette empreinte SHA-1, ou nul ; à rendre (CertFreeCertificateContext) ou à retirer.
    fn chercher(&self, empreinte: &[u8; 20]) -> *const c_void {
        const ENCODAGE: u32 = 0x1 | 0x1_0000;
        const PAR_SHA1: u32 = 1 << 16;
        let cherche = Empreinte20 {
            taille: 20,
            octets: empreinte.as_ptr(),
        };
        // SAFETY: le magasin est ouvert tant que `self` vit ; l'empreinte cherchée vit pendant l'appel.
        unsafe {
            CertFindCertificateInStore(
                self.0,
                ENCODAGE,
                0,
                PAR_SHA1,
                (&raw const cherche).cast(),
                std::ptr::null(),
            )
        }
    }
}

impl Drop for Magasin {
    fn drop(&mut self) {
        // SAFETY: le magasin vient de CertOpenStore (non nul) et n'est fermé qu'ici, une fois.
        unsafe {
            CertCloseStore(self.0, 0);
        }
    }
}

/// Retire la racine de ce magasin, signalée par le bilan relu ; `personne` : le SID de la personne.
pub(super) fn retirer(m: MagasinRacine, e: &Empreinte, personne: Option<&str>) -> Resultat {
    if m == MagasinRacine::Compte {
        let soi = super::processus::sid();
        if personne.is_none() || soi.as_deref() != personne {
            return Resultat::echec(
                None,
                tr!(
                    "Vanguard administrateur tourne sous un autre compte que le vôtre : votre magasin de certificats n'est pas le sien ; refusé, rien retiré",
                    "Vanguard as administrator runs under another account than yours: your certificate store is not its own; refused, nothing removed"
                )
                .to_string(),
            );
        }
    }
    let Some(sortie) = super::magasins::racines() else {
        return Resultat::echec(
            None,
            tr!(
                "magasins de certificats illisibles, rien retiré",
                "certificate stores unreadable, nothing removed"
            )
            .to_string(),
        );
    };
    let (racines, _) = certificats::racines_ajoutees(&sortie);
    let Some(nom) = racines
        .iter()
        .find(|r| r.magasin == m.nom() && Empreinte::nouvelle(r.empreinte).as_ref() == Some(e))
        .filter(|r| certificats::retrait(r.nom, r.cle_privee))
        .map(|r| r.nom.to_string())
    else {
        return Resultat::echec(
            None,
            tr!(
                "le bilan ne propose pas de retirer cette racine de ce magasin : refusée, rien retiré",
                "the scan does not offer to remove this root from this store: refused, nothing removed"
            )
            .to_string(),
        );
    };
    let Some(octets) = e.octets() else {
        return Resultat::echec(None, tr!("empreinte illisible", "unreadable thumbprint").to_string());
    };
    retirer_du_magasin(m, e, &octets, &nom)
}

fn retirer_du_magasin(m: MagasinRacine, e: &Empreinte, octets: &[u8; 20], nom: &str) -> Resultat {
    /// ERROR_CANCELLED : « Non » dans la fenêtre de confirmation de Windows.
    const ANNULE: i32 = 1223;
    let montre = crate::ui::affichable(nom);
    let Some(magasin) = Magasin::ouvrir(m, false) else {
        return Resultat::echec(
            None,
            trf!(
                "le magasin {} ne s'ouvre pas en écriture, rien retiré",
                "store {} cannot be opened for writing, nothing removed",
                m.nom()
            ),
        );
    };
    let certificat = magasin.chercher(octets);
    if certificat.is_null() {
        return Resultat::echec(
            None,
            tr!(
                "racine introuvable dans le magasin (posée par une stratégie de groupe ?), rien retiré",
                "root not found in the store (set by a group policy?), nothing removed"
            )
            .to_string(),
        );
    }
    // SAFETY: le contexte rendu par CertFindCertificateInStore (non nul) décrit son certificat encodé : `taille`
    // octets à `octets`, copiés tant qu'il vit.
    let der = unsafe {
        let c = certificat.cast::<ContexteCertificat>().read_unaligned();
        if c.octets.is_null() || c.taille == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(c.octets, c.taille as usize).to_vec()
        }
    };
    let secondes = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let copie = if der.is_empty() {
        Err(crate::modele::Echec::echoue(
            "certificats/retirer",
            tr!("certificat vide", "empty certificate"),
        ))
    } else {
        super::quarantaine::deposer(&format!("racine-{}-{secondes}.cer", e.texte()), &der)
    };
    // Sans copie, la racine est retirée quand même : un compte ordinaire peut poser d'avance un dossier Vanguard sous
    // ProgramData (refusé par `quarantaine`) ; s'il suffisait à garder sa racine, il la protégerait. La copie n'est
    // qu'une commodité pour la réimporter : l'empreinte et le nom restent notés.
    let copie = match copie {
        Ok(c) => trf!("copie : {}", "copy: {}", c.display()),
        Err(r) => trf!("sans copie ({r})", "no copy ({r})"),
    };
    let avant = avant_notable(&format!("{} {} « {montre} », {copie}", m.nom(), e.texte()));
    // SAFETY: CertDeleteCertificateFromStore rend le contexte dans tous les cas (réussite ou refus) : il n'est plus
    // touché ensuite.
    let retire = unsafe { CertDeleteCertificateFromStore(certificat) } != 0;
    if !retire {
        let erreur = std::io::Error::last_os_error();
        return Resultat::echec(
            Some(avant),
            if erreur.raw_os_error() == Some(ANNULE) {
                tr!(
                    "refusé dans la fenêtre de Windows : la racine est gardée",
                    "declined in the Windows window: the root is kept"
                )
                .to_string()
            } else {
                trf!(
                    "Windows refuse de retirer la racine ({erreur})",
                    "Windows refuses to remove the root ({erreur})"
                )
            },
        );
    }
    drop(magasin);
    match Magasin::ouvrir(m, true) {
        Some(relu) => {
            let encore = relu.chercher(octets);
            if encore.is_null() {
                encore_ailleurs(e, avant)
            } else {
                // SAFETY: le contexte trouvé (non nul) est rendu une seule fois.
                unsafe {
                    CertFreeCertificateContext(encore);
                }
                Resultat::echec(
                    Some(avant),
                    tr!(
                        "la racine est encore là à la relecture (stratégie de groupe, autre magasin) : rien n'est compté comme fait",
                        "the root is still there when read back (group policy, another store): nothing is counted as done"
                    )
                    .to_string(),
                )
            }
        }
        None => Resultat::echec(
            Some(avant),
            tr!(
                "magasin illisible après le retrait : rien n'est compté comme fait",
                "store unreadable after removal: nothing is counted as done"
            )
            .to_string(),
        ),
    }
}

/// Retirée de ce magasin : le bilan relu ne doit plus la montrer nulle part. Le magasin du compte montre aussi
/// l'ordinateur, et le bilan ne garde qu'une ligne par empreinte : une copie de la même racine dans l'autre magasin
/// n'apparaît qu'une fois la première retirée, et la racine resterait de confiance.
fn encore_ailleurs(e: &Empreinte, avant: String) -> Resultat {
    let Some(sortie) = super::magasins::racines() else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "retirée, mais les magasins ne se relisent pas : rien n'est compté comme fait",
                "removed, but the stores cannot be read back: nothing is counted as done"
            )
            .to_string(),
        );
    };
    let (racines, _) = certificats::racines_ajoutees(&sortie);
    if racines
        .iter()
        .any(|r| Empreinte::nouvelle(r.empreinte).as_ref() == Some(e))
    {
        Resultat::echec(
            Some(avant),
            tr!(
                "retirée de ce magasin, mais encore présente dans l'autre : refaire le bilan pour la retirer aussi",
                "removed from this store, but still present in the other one: run the scan again to remove it too"
            )
            .to_string(),
        )
    } else {
        Resultat::fait(avant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formes_de_windows() {
        assert_eq!(std::mem::size_of::<ContexteCertificat>(), 40);
        assert_eq!(std::mem::offset_of!(ContexteCertificat, octets), 8);
        assert_eq!(std::mem::offset_of!(ContexteCertificat, taille), 16);
        assert_eq!(std::mem::size_of::<Empreinte20>(), 16);
    }

    /// La vraie crypt32 (Wine ici) : une empreinte qui n'existe pas n'est jamais trouvée, rien n'est retiré.
    #[test]
    fn empreinte_absente_introuvable() {
        if let Some(m) = Magasin::ouvrir(MagasinRacine::Ordinateur, true) {
            assert!(m.chercher(&[0x5A; 20]).is_null());
        }
    }
}
