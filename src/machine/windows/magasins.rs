//! Les certificats racine des magasins de Windows (ordinateur et utilisateur), lus par crypt32 sans PowerShell :
//! les lignes « CERT|magasin|clé privée|empreinte|nom » que le lecteur Cert: de PowerShell donnait.

// FFI de crypt32 : magasins de certificats (CertOpenStore, CertEnumCertificatesInStore…).
#![allow(unsafe_code)]

use std::ffi::c_void;

#[link(name = "crypt32")]
unsafe extern "system" {
    /// Partagées avec `certificats_ecriture` : une seule déclaration de chaque import.
    pub(super) fn CertOpenStore(
        fournisseur: *const i8,
        encodage: u32,
        crypto: usize,
        drapeaux: u32,
        parametre: *const c_void,
    ) -> *mut c_void;
    fn CertEnumCertificatesInStore(magasin: *mut c_void, precedent: *const c_void) -> *const c_void;
    fn CertGetCertificateContextProperty(
        certificat: *const c_void,
        propriete: u32,
        donnees: *mut c_void,
        taille: *mut u32,
    ) -> i32;
    /// Partagée avec `signature` : une seule déclaration de chaque import.
    pub(super) fn CertGetNameStringW(
        certificat: *const c_void,
        sorte: u32,
        drapeaux: u32,
        parametre: *const c_void,
        nom: *mut u16,
        taille: u32,
    ) -> u32;
    pub(super) fn CertCloseStore(magasin: *mut c_void, drapeaux: u32) -> i32;
    pub(super) fn CertFindCertificateInStore(
        magasin: *mut c_void,
        encodage: u32,
        drapeaux: u32,
        sorte: u32,
        cherche: *const c_void,
        precedent: *const c_void,
    ) -> *const c_void;
    pub(super) fn CertDeleteCertificateFromStore(certificat: *const c_void) -> i32;
    pub(super) fn CertFreeCertificateContext(certificat: *const c_void) -> i32;
}

/// Les lignes des deux magasins « Root », ordinateur d'abord ; `None` si celui de l'ordinateur ne se lit pas jusqu'au
/// bout, ou se lit vide : un vrai Windows a toujours des racines dans ce magasin, et « 0 certificat, aucun ajouté »
/// serait une lecture ratée comptée saine. `None` aussi si celui du compte refuse de s'ouvrir : c'est là qu'un outil
/// d'interception installe sa racine sans droits administrateur. PowerShell reprend alors, comme le script qui
/// s'arrêtait sur l'un ou l'autre.
pub(crate) fn racines() -> Option<String> {
    let mut lignes = lire(SYSTEME, "LocalMachine", 2 << 16).filter(|l| !l.is_empty())?;
    lignes.extend(lire(SYSTEME, "CurrentUser", 1 << 16)?);
    Some(lignes.join("\n"))
}

/// Les racines du seul magasin physique du compte (registre HKCU\Software\Microsoft\SystemCertificates\Root), sans
/// celles de l'ordinateur que le magasin logique du compte montre aussi : ce qu'un programme lancé sous ce compte peut
/// y poser sans droits administrateur. `None` si ce magasin refuse de s'ouvrir ou se lit en partie.
pub(crate) fn racines_du_compte() -> Option<String> {
    Some(lire(REGISTRE, "CurrentUser", 1 << 16)?.join("\n"))
}

/// CERT_STORE_PROV_SYSTEM_W : le magasin logique, réunion de ses magasins physiques.
const SYSTEME: usize = 10;
/// CERT_STORE_PROV_SYSTEM_REGISTRY_W : le seul magasin du registre de l'emplacement.
const REGISTRE: usize = 13;

/// Les certificats du magasin « Root » d'un emplacement (CERT_SYSTEM_STORE_LOCAL_MACHINE ou CURRENT_USER), par le
/// fournisseur `fournisseur`, ouvert en lecture seule ; vide s'il n'existe pas, `None` s'il refuse de s'ouvrir ou si
/// l'énumération s'arrête sur une erreur. Un certificat dont l'empreinte n'est pas un SHA-1 lisible garde sa ligne
/// (`empreinte_lue`) : `certificats` la dit non vérifiée et lit le reste.
fn lire(fournisseur: usize, nom: &str, emplacement: u32) -> Option<Vec<String>> {
    const EXISTANT_LECTURE_SEULE: u32 = 0x4000 | 0x8000;
    const EMPREINTE_SHA1: u32 = 3;
    const INFOS_DE_LA_CLE: u32 = 2;
    const NOM_SIMPLE: u32 = 4;
    /// Ce que GetLastError rend quand CertEnumCertificatesInStore a passé le dernier certificat.
    #[allow(clippy::cast_possible_wrap)] // un HRESULT, signé pour Windows
    const FIN_DE_LISTE: i32 = 0x8009_2004_u32 as i32;
    let racine: Vec<u16> = "Root".encode_utf16().chain([0]).collect();
    let mut lignes = Vec::new();
    // SAFETY: le nom du magasin est terminé par un zéro et vit pendant l'appel ; le magasin (nul : refus, vérifié) est
    // fermé une seule fois. CertEnumCertificatesInStore libère le certificat précédent et rend le suivant, nul à la
    // fin ou en cas d'erreur (GetLastError les distingue), et la boucle n'en sort que sur ce nul : aucun certificat
    // n'est gardé ni rendu à la main ; chaque certificat n'est passé qu'aux fonctions de crypt32, qui écrivent au plus
    // la taille donnée dans les tampons, qui l'ont.
    unsafe {
        let magasin = CertOpenStore(
            fournisseur as *const i8,
            0,
            0,
            emplacement | EXISTANT_LECTURE_SEULE,
            racine.as_ptr().cast(),
        );
        if magasin.is_null() {
            // Magasin absent (sa clé du registre n'existe pas, ERROR_FILE_NOT_FOUND) : aucun certificat ne peut y
            // être, une vraie liste vide. Tout autre refus : non lu.
            const ABSENT: i32 = 2;
            return (std::io::Error::last_os_error().raw_os_error() == Some(ABSENT)).then(Vec::new);
        }
        let mut certificat = std::ptr::null();
        let complet = loop {
            certificat = CertEnumCertificatesInStore(magasin, certificat);
            if certificat.is_null() {
                // Nul aussi sur une erreur : une liste coupée en route cacherait les racines d'après (un proxy
                // d'interception ajouté en dernier), et elle ne doit pas passer pour la liste entière.
                break std::io::Error::last_os_error().raw_os_error() == Some(FIN_DE_LISTE);
            }
            // Plus grand qu'un SHA-1 : l'empreinte d'une entrée du registre du compte est celle qu'elle déclare (vu
            // sous Wine), de n'importe quelle taille. Ni sautée (sa ligne manquerait, « aucun ajouté »), ni fin de la
            // lecture (une seule entrée posée sans droits ferait refuser tout retrait au processus élevé) : écrite
            // telle quelle, vide si illisible.
            let mut empreinte = [0u8; 64];
            let mut taille = 64u32;
            let lue = CertGetCertificateContextProperty(
                certificat,
                EMPREINTE_SHA1,
                empreinte.as_mut_ptr().cast(),
                &raw mut taille,
            ) != 0;
            let mut taille_cle = 0u32;
            let cle = CertGetCertificateContextProperty(
                certificat,
                INFOS_DE_LA_CLE,
                std::ptr::null_mut(),
                &raw mut taille_cle,
            ) != 0;
            let mut tampon = vec![0u16; 512];
            let n = CertGetNameStringW(certificat, NOM_SIMPLE, 0, std::ptr::null(), tampon.as_mut_ptr(), 512);
            let n = usize::try_from(n).unwrap_or(0).min(tampon.len());
            // Sans le zéro final que compte la longueur rendue.
            tampon.truncate(n.saturating_sub(1));
            let nom_du_certificat = String::from_utf16_lossy(&tampon);

            lignes.push(ligne(
                nom,
                cle,
                empreinte_lue(lue, &empreinte, taille),
                &nom_du_certificat,
            ));
        };
        CertCloseStore(magasin, 0);
        complet.then_some(lignes)
    }
}

/// L'empreinte rendue par crypt32 : les `taille` premiers octets du tampon, rien si elle ne s'est pas lue (une taille
/// plus grande que le tampon est un refus, ERROR_MORE_DATA, sans rien d'écrit).
fn empreinte_lue(lue: bool, tampon: &[u8], taille: u32) -> &[u8] {
    let n = if lue {
        usize::try_from(taille).unwrap_or(usize::MAX).min(tampon.len())
    } else {
        0
    };
    tampon.get(..n).unwrap_or_default()
}

/// « CERT|LocalMachine|True|0123…ABCD|Nom » : l'empreinte en hexadécimal majuscule, comme Thumbprint.
fn ligne(magasin: &str, cle: bool, empreinte: &[u8], nom: &str) -> String {
    use std::fmt::Write as _;
    let hex = empreinte.iter().fold(String::new(), |mut t, o| {
        let _ = write!(t, "{o:02X}");
        t
    });
    let cle = if cle { "True" } else { "False" };
    format!("CERT|{magasin}|{cle}|{hex}|{}", nom.replace(['\r', '\n'], " "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lignes_des_certificats() {
        assert_eq!(
            ligne("CurrentUser", true, &[0xab, 0x01, 0xff], "mitm\nproxy"),
            "CERT|CurrentUser|True|AB01FF|mitm proxy"
        );
    }

    /// Contrôle de MC-4 : une empreinte d'une autre taille qu'un SHA-1 est écrite telle quelle, une empreinte illisible
    /// donne un champ vide ; la ligne reste dans les deux cas.
    #[test]
    fn empreinte_hors_de_sa_forme_gardee() {
        let tampon: Vec<u8> = (0u8..64).collect();
        assert_eq!(empreinte_lue(true, &tampon, 19), &tampon[..19]);
        assert_eq!(empreinte_lue(true, &tampon, 20).len(), 20);
        assert_eq!(empreinte_lue(true, &tampon, 500).len(), 64);
        assert_eq!(empreinte_lue(false, &tampon, 20), &[] as &[u8]);
        assert_eq!(ligne("CurrentUser", false, &[], "x"), "CERT|CurrentUser|False||x");
    }

    /// La vraie crypt32 (Wine ici, la VM ensuite) : le magasin de l'ordinateur s'ouvre et chaque ligne a la forme lue
    /// par `certificats`.
    #[test]
    fn racines_lues_par_windows() {
        let t = racines().expect("magasin Root de l'ordinateur");
        assert!(
            t.lines()
                .all(|l| l.splitn(5, '|').count() == 5 && l.split('|').nth(3).is_some_and(|e| e.len() == 40)),
            "{t}"
        );
    }
}
