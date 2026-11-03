//! La signature d'un fichier, lue par Windows (wintrust) : dans un catalogue de Windows (CryptCATAdmin*), ou
//! intégrée à sa table des certificats, vérifiée par WinVerifyTrust, avec le sujet de son signataire. Elle ne sert
//! qu'à REFUSER un geste (défense D6a) : un fichier signé Microsoft est traité comme du système. Une signature qui ne
//! se vérifie pas (un certificat fait maison au nom de « Microsoft ») n'en est pas une : sinon n'importe quel
//! programme se rendrait intouchable en se signant lui-même. Une qui se vérifie ne suffit pas non plus : la racine
//! de sa chaîne doit être une des racines de Microsoft (CERT_CHAIN_POLICY_MICROSOFT_ROOT), car WinVerifyTrust admet
//! aussi les racines du magasin du compte, qu'un programme sans droits y ajoute par le registre, sans invite.

// FFI de wintrust et crypt32 : WinVerifyTrust, catalogues (CryptCATAdmin*), sujet du certificat (CertGetNameStringW),
// racine de la chaîne (CertVerifyCertificateChainPolicy).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io::{Seek, SeekFrom};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::GUID;

use crate::protection::blocage::gardes::{self, Illisibilite, Signature};

#[link(name = "wintrust")]
unsafe extern "system" {
    fn WinVerifyTrust(fenetre: *mut c_void, action: *const GUID, donnees: *mut c_void) -> i32;
    fn WTHelperProvDataFromStateData(etat: *mut c_void) -> *mut c_void;
    fn WTHelperGetProvSignerFromChain(
        donnees: *mut c_void,
        signataire: u32,
        contre: i32,
        indice: u32,
    ) -> *mut Signataire;
    fn CryptCATAdminAcquireContext2(
        admin: *mut *mut c_void,
        sous_systeme: *const GUID,
        algorithme: *const u16,
        politique: *const c_void,
        drapeaux: u32,
    ) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle2(
        admin: *mut c_void,
        fichier: *mut c_void,
        taille: *mut u32,
        empreinte: *mut u8,
        drapeaux: u32,
    ) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(
        admin: *mut c_void,
        empreinte: *const u8,
        taille: u32,
        drapeaux: u32,
        precedent: *mut *mut c_void,
    ) -> *mut c_void;
    fn CryptCATCatalogInfoFromContext(catalogue: *mut c_void, info: *mut InfoCatalogue, drapeaux: u32) -> i32;
    fn CryptCATAdminReleaseCatalogContext(admin: *mut c_void, catalogue: *mut c_void, drapeaux: u32) -> i32;
    fn CryptCATAdminReleaseContext(admin: *mut c_void, drapeaux: u32) -> i32;
}

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertVerifyCertificateChainPolicy(
        politique: *const u8,
        chaine: *const c_void,
        para: *const ParaPolitique,
        etat: *mut EtatPolitique,
    ) -> i32;
}

/// CERT_CHAIN_POLICY_MICROSOFT_ROOT : la chaîne finit-elle sur une racine de Microsoft (clé publique comparée à
/// celles que crypt32 porte en lui, quels que soient les magasins du compte) ? Sans drapeau : ni les racines d'essai
/// ni la racine « application ».
const POLITIQUE_RACINE_MICROSOFT: usize = 7;

/// WINTRUST_ACTION_GENERIC_VERIFY_V2 : la vérification Authenticode ordinaire.
const VERIFIER_V2: GUID = GUID::from_u128(0x00aa_c56b_cd44_11d0_8cc2_00c0_4fc2_95ee);
/// WTD_UI_NONE, WTD_REVOKE_NONE, WTD_CHOICE_FILE, WTD_STATEACTION_VERIFY puis CLOSE.
const SANS_FENETRE: u32 = 2;
const CHOIX_FICHIER: u32 = 1;
const ETAT_VERIFIER: u32 = 1;
const ETAT_FERMER: u32 = 2;
/// WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL : rien n'est demandé au réseau (une garde qui attendrait
/// Internet pour refuser ne refuserait pas hors ligne).
const SANS_RESEAU: u32 = 0x0000_0010 | 0x0000_1000;
/// CERT_NAME_RDN_TYPE avec CERT_X500_NAME_STR : le sujet entier (« C=US, …, O=Microsoft Corporation, CN=… »).
const NOM_RDN: u32 = 2;
static X500: u32 = 3;

/// WINTRUST_FILE_INFO.
#[repr(C)]
struct InfoFichier {
    taille: u32,
    chemin: *const u16,
    fichier: *mut c_void,
    sujet_connu: *const GUID,
}

/// WINTRUST_DATA (wintrust.h), sans les champs ajoutés après Windows 8 (la taille annoncée le dit).
#[repr(C)]
struct Confiance {
    taille: u32,
    politique: *mut c_void,
    sip: *mut c_void,
    interface: u32,
    revocation: u32,
    choix: u32,
    fichier: *mut InfoFichier,
    action: u32,
    etat: *mut c_void,
    url: *const u16,
    drapeaux: u32,
    contexte: u32,
    reglages: *mut c_void,
}

/// CRYPT_PROVIDER_SGNR, jusqu'à la chaîne construite par la vérification (pChainContext).
#[repr(C)]
struct Signataire {
    taille: u32,
    verifie_le: [u32; 2],
    certificats: u32,
    chaine: *const CertificatFournisseur,
    genre: u32,
    cms: *const c_void,
    erreur: u32,
    contre_signataires: u32,
    contre: *const c_void,
    contexte_chaine: *const c_void,
}

/// CERT_CHAIN_POLICY_PARA.
#[repr(C)]
struct ParaPolitique {
    taille: u32,
    drapeaux: u32,
    extra: *mut c_void,
}

/// CERT_CHAIN_POLICY_STATUS.
#[repr(C)]
struct EtatPolitique {
    taille: u32,
    erreur: u32,
    chaine: i32,
    element: i32,
    extra: *mut c_void,
}

/// Le début de CRYPT_PROVIDER_CERT : le certificat (PCCERT_CONTEXT).
#[repr(C)]
struct CertificatFournisseur {
    taille: u32,
    certificat: *const c_void,
}

/// CATALOG_INFO.
#[repr(C)]
struct InfoCatalogue {
    taille: u32,
    chemin: [u16; 260],
}

fn large(texte: &std::ffi::OsStr) -> Vec<u16> {
    texte.encode_wide().chain(std::iter::once(0)).collect()
}

fn taille_de<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(0)
}

/// La signature de `chemin` : Microsoft, autre (ou aucune), ou illisible (le fichier ne s'ouvre pas, un catalogue ou
/// sa signature ne se lit pas), avec la raison tirée du code de Windows.
pub(crate) fn lire(chemin: &Path) -> Signature {
    let mut fichier = match std::fs::File::open(chemin) {
        Ok(f) => f,
        Err(e) => return Signature::Illisible(raison_io(&e)),
    };
    let catalogue = catalogue_microsoft(&mut fichier);
    let integree = fichier
        .seek(SeekFrom::Start(0))
        .map_err(|e| raison_io(&e))
        .and_then(|_| verifier(chemin, Some(&fichier)));
    gardes::signature_de(catalogue, integree)
}

/// La raison d'une erreur de lecture du fichier.
fn raison_io(e: &std::io::Error) -> Illisibilite {
    let code = e.raw_os_error().map_or(0, i32::cast_unsigned);
    gardes::illisibilite_connue(code).unwrap_or(Illisibilite::Code(code))
}

/// La raison d'un échec d'une fonction des catalogues, d'après GetLastError : CryptSvc arrêté se dit tel ; un code
/// inconnu se rattache aux catalogues.
fn raison_catalogue() -> Illisibilite {
    let code = std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(0, i32::cast_unsigned);
    gardes::illisibilite_connue(code).unwrap_or(Illisibilite::Catalogues)
}

/// Le fichier est-il dans un catalogue de Windows signé par Microsoft ? Cherché par son empreinte SHA-256 puis
/// SHA-1 (les catalogues anciens n'ont que celle-là) ; chaque catalogue trouvé est vérifié comme un fichier signé.
fn catalogue_microsoft(fichier: &mut std::fs::File) -> Result<bool, Illisibilite> {
    for algorithme in ["SHA256", "SHA1"] {
        fichier.seek(SeekFrom::Start(0)).map_err(|e| raison_io(&e))?;
        let algorithme = large(std::ffi::OsStr::new(algorithme));
        let mut admin: *mut c_void = std::ptr::null_mut();
        // SAFETY: `admin` est à nous ; l'algorithme est une chaîne terminée par un zéro, vivante pendant l'appel ;
        // sous-système et politique nuls (ceux par défaut). Un contexte rendu est relâché une seule fois plus bas.
        if unsafe {
            CryptCATAdminAcquireContext2(
                &raw mut admin,
                std::ptr::null(),
                algorithme.as_ptr(),
                std::ptr::null(),
                0,
            )
        } == 0
        {
            return Err(raison_catalogue());
        }
        let trouve = dans_un_catalogue(admin, fichier);
        // SAFETY: le contexte acquis juste au-dessus, relâché une seule fois.
        unsafe { CryptCATAdminReleaseContext(admin, 0) };
        if trouve? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn dans_un_catalogue(admin: *mut c_void, fichier: &std::fs::File) -> Result<bool, Illisibilite> {
    let mut empreinte = [0u8; 64];
    let mut taille = u32::try_from(empreinte.len()).map_err(|_| Illisibilite::Catalogues)?;
    // SAFETY: le contexte est ouvert ; la poignée du fichier vit tant que `fichier` ; Windows écrit au plus `taille`
    // octets dans `empreinte`, puis leur nombre dans `taille`.
    let calcule = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            admin,
            fichier.as_raw_handle().cast(),
            &raw mut taille,
            empreinte.as_mut_ptr(),
            0,
        )
    } != 0;
    if !calcule {
        return Err(raison_catalogue());
    }
    if usize::try_from(taille).map_or(true, |t| t == 0 || t > empreinte.len()) {
        return Err(Illisibilite::Catalogues);
    }
    let mut catalogue: *mut c_void = std::ptr::null_mut();
    loop {
        // SAFETY: l'empreinte calculée, de `taille` octets ; `catalogue` est le précédent rendu (nul au départ), que
        // Windows relâche lui-même en rendant le suivant.
        let suivant =
            unsafe { CryptCATAdminEnumCatalogFromHash(admin, empreinte.as_ptr(), taille, 0, &raw mut catalogue) };
        if suivant.is_null() {
            // Plus aucun : le dernier a déjà été relâché par Windows.
            return Ok(false);
        }
        catalogue = suivant;
        let mut info = InfoCatalogue {
            taille: taille_de::<InfoCatalogue>(),
            chemin: [0; 260],
        };
        // SAFETY: `catalogue` vient d'être rendu ; `info` est à nous, sa taille annoncée.
        let lu = unsafe { CryptCATCatalogInfoFromContext(catalogue, &raw mut info, 0) } != 0;
        let microsoft = lu.then(|| {
            let fin = info.chemin.iter().position(|&c| c == 0).unwrap_or(info.chemin.len());
            let chemin = std::path::PathBuf::from(String::from_utf16_lossy(info.chemin.get(..fin).unwrap_or_default()));
            verifier(&chemin, None)
        });
        match microsoft {
            Some(Ok(true)) => {
                // SAFETY: le catalogue rendu par l'énumération, relâché une seule fois (on ne la poursuit pas).
                unsafe { CryptCATAdminReleaseCatalogContext(admin, catalogue, 0) };
                return Ok(true);
            }
            Some(Ok(false)) => {}
            // Le catalogue désigné ne se lit pas : illisible, jamais tenu pour « pas Microsoft ». CryptSvc arrêté se dit
            // tel ; le reste, « catalogues ».
            Some(Err(r)) => {
                // SAFETY: comme au-dessus.
                unsafe { CryptCATAdminReleaseCatalogContext(admin, catalogue, 0) };
                return Err(if r == Illisibilite::CryptSvc {
                    r
                } else {
                    Illisibilite::Catalogues
                });
            }
            None => {
                // SAFETY: comme au-dessus.
                unsafe { CryptCATAdminReleaseCatalogContext(admin, catalogue, 0) };
                return Err(Illisibilite::Catalogues);
            }
        }
    }
}

/// Vérifie la signature de `chemin` (par sa poignée ouverte quand elle est donnée) : `Ok(true)` si elle se vérifie,
/// jusqu'à une racine de Microsoft, au nom de Microsoft ; `Ok(false)` si elle est absente, ne se vérifie pas ou est
/// d'un autre ; `Err` si le fichier ou son signataire ne se lit pas, avec la raison.
fn verifier(chemin: &Path, fichier: Option<&std::fs::File>) -> Result<bool, Illisibilite> {
    let nom = large(chemin.as_os_str());
    let mut info = InfoFichier {
        taille: taille_de::<InfoFichier>(),
        chemin: nom.as_ptr(),
        fichier: fichier.map_or(std::ptr::null_mut(), |f| f.as_raw_handle().cast()),
        sujet_connu: std::ptr::null(),
    };
    let mut d = Confiance {
        taille: taille_de::<Confiance>(),
        politique: std::ptr::null_mut(),
        sip: std::ptr::null_mut(),
        interface: SANS_FENETRE,
        revocation: 0,
        choix: CHOIX_FICHIER,
        fichier: &raw mut info,
        action: ETAT_VERIFIER,
        etat: std::ptr::null_mut(),
        url: std::ptr::null(),
        drapeaux: SANS_RESEAU,
        contexte: 0,
        reglages: std::ptr::null_mut(),
    };
    // INVALID_HANDLE_VALUE : personne à qui montrer une fenêtre.
    let fenetre = usize::MAX as *mut c_void;
    // SAFETY: `d` et `info` sont à nous et vivent pendant les deux appels ; le chemin est terminé par un zéro ; la
    // poignée, s'il y en a une, vit tant que `fichier`. L'état ouvert par VERIFY est refermé par CLOSE juste après.
    let code = unsafe { WinVerifyTrust(fenetre, &VERIFIER_V2, (&raw mut d).cast()) };
    // Lu avant CLOSE : la chaîne et le signataire vivent dans l'état de la vérification.
    let signe = (code == 0).then(|| signataire_microsoft(d.etat));
    d.action = ETAT_FERMER;
    // SAFETY: comme au-dessus ; CLOSE libère l'état tenu dans `d.etat`.
    unsafe { WinVerifyTrust(fenetre, &VERIFIER_V2, (&raw mut d).cast()) };
    match signe {
        // Vérifiée, mais son signataire ou sa chaîne ne se lit pas : illisible.
        Some(signe) => signe.ok_or(Illisibilite::Signataire),
        None if gardes::verification_illisible(code) => {
            let code = code.cast_unsigned();
            Err(gardes::illisibilite_connue(code).unwrap_or(Illisibilite::Code(code)))
        }
        None => Ok(false),
    }
}

/// Le signataire d'une vérification réussie (avant sa fermeture) est-il Microsoft : sujet au nom de Microsoft ET
/// chaîne finie sur une racine de Microsoft ? `None` : le signataire, son sujet ou sa chaîne ne se lit pas.
fn signataire_microsoft(etat: *mut c_void) -> Option<bool> {
    if etat.is_null() {
        return None;
    }
    // SAFETY: `etat` est celui d'une vérification réussie, pas encore refermée : les données du fournisseur, le
    // signataire et sa chaîne vivent jusqu'à CLOSE. Chaque pointeur est vérifié non nul avant d'être lu, et seuls les
    // premiers champs (communs à toutes les versions) le sont.
    unsafe {
        let fournisseur = WTHelperProvDataFromStateData(etat);
        if fournisseur.is_null() {
            return None;
        }
        let signataire = WTHelperGetProvSignerFromChain(fournisseur, 0, 0, 0);
        if signataire.is_null() || (*signataire).certificats == 0 || (*signataire).chaine.is_null() {
            return None;
        }
        let certificat = (*(*signataire).chaine).certificat;
        if certificat.is_null() {
            return None;
        }
        // Une structure plus courte (Windows ancien) n'a pas la chaîne : illisible, jamais « Microsoft ».
        let jusqu_a_la_chaine =
            std::mem::offset_of!(Signataire, contexte_chaine) + std::mem::size_of::<*const c_void>();
        if usize::try_from((*signataire).taille).map_or(true, |t| t < jusqu_a_la_chaine) {
            return None;
        }
        let racine = racine_microsoft((*signataire).contexte_chaine)?;
        let mut tampon = vec![0u16; 2048];
        let n = super::magasins::CertGetNameStringW(
            certificat,
            NOM_RDN,
            0,
            (&raw const X500).cast(),
            tampon.as_mut_ptr(),
            u32::try_from(tampon.len()).ok()?,
        );
        let n = usize::try_from(n).ok()?.min(tampon.len());
        // Sans le zéro final que compte la longueur rendue ; 1 : un sujet vide.
        tampon.truncate(n.saturating_sub(1));
        let sujet = (!tampon.is_empty()).then(|| String::from_utf16_lossy(&tampon))?;
        Some(gardes::signe_par_microsoft(&sujet, racine))
    }
}

/// La chaîne construite par WinVerifyTrust finit-elle sur une racine de Microsoft ? `None` : chaîne absente, ou
/// politique qui ne se lit pas.
fn racine_microsoft(chaine: *const c_void) -> Option<bool> {
    if chaine.is_null() {
        return None;
    }
    let para = ParaPolitique {
        taille: taille_de::<ParaPolitique>(),
        drapeaux: 0,
        extra: std::ptr::null_mut(),
    };
    let mut etat = EtatPolitique {
        taille: taille_de::<EtatPolitique>(),
        erreur: 0,
        chaine: 0,
        element: 0,
        extra: std::ptr::null_mut(),
    };
    // SAFETY: la politique est un identifiant entier (macro MAKEINTRESOURCE de wincrypt.h), jamais lu comme une
    // chaîne ; `chaine` est le PCCERT_CHAIN_CONTEXT de la vérification encore ouverte, non nul ; `para` et `etat` sont à
    // nous, leur taille annoncée.
    let lu = unsafe {
        CertVerifyCertificateChainPolicy(
            std::ptr::without_provenance(POLITIQUE_RACINE_MICROSOFT),
            chaine,
            &raw const para,
            &raw mut etat,
        )
    } != 0;
    lu.then_some(etat.erreur == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lu pour de vrai (Windows ou Wine) : un fichier absent est illisible ; un fichier fait ici n'est pas signé
    /// Microsoft ; un programme de Windows l'est (sous Windows seulement : ceux de Wine ne sont pas signés).
    #[test]
    fn signature_lue_par_windows() {
        let dossier = crate::socle::dossier_local().join("essai-signature");
        std::fs::create_dir_all(&dossier).unwrap();
        assert_eq!(
            lire(&dossier.join("absent.exe")),
            Signature::Illisible(Illisibilite::Absent)
        );
        let fait_ici = dossier.join("fait-ici.exe");
        std::fs::write(&fait_ici, b"MZ pas un vrai programme").unwrap();
        let lu = lire(&fait_ici);
        let _ = std::fs::remove_file(&fait_ici);
        assert_ne!(lu, Signature::Microsoft);
        if crate::commande::sous_wine() {
            return crate::essais::saute("les programmes de Wine ne sont pas signés");
        }
        assert_eq!(lu, Signature::Autre);
        let systeme = crate::machine::windows::environnement::dossier_windows().unwrap();
        assert_eq!(lire(&systeme.join(r"System32\notepad.exe")), Signature::Microsoft);
        assert_eq!(lire(&systeme.join(r"System32\kernel32.dll")), Signature::Microsoft);
    }
}
