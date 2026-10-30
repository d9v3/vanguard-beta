//! Les certificats racine des magasins de Windows (ordinateur et utilisateur), lus par crypt32 sans PowerShell :
//! les lignes « CERT|magasin|clé privée|empreinte|nom » que le lecteur Cert: de PowerShell donnait.

use std::ffi::c_void;

#[link(name = "crypt32")]
unsafe extern "system" {
    fn CertOpenStore(
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
    fn CertGetNameStringW(
        certificat: *const c_void,
        sorte: u32,
        drapeaux: u32,
        parametre: *const c_void,
        nom: *mut u16,
        taille: u32,
    ) -> u32;
    fn CertCloseStore(magasin: *mut c_void, drapeaux: u32) -> i32;
}

/// Les lignes des deux magasins « Root », ordinateur d'abord ; `None` si celui de l'ordinateur ne se lit pas jusqu'au
/// bout, ou se lit vide : un vrai Windows a toujours des racines dans ce magasin, et « 0 certificat, aucun ajouté »
/// serait une lecture ratée comptée saine. `None` aussi si celui du compte refuse de s'ouvrir : c'est là qu'un outil
/// d'interception installe sa racine sans droits administrateur. PowerShell reprend alors, comme le script qui
/// s'arrêtait sur l'un ou l'autre.
pub(crate) fn racines() -> Option<String> {
    let mut lignes = lire("LocalMachine", 2 << 16).filter(|l| !l.is_empty())?;
    lignes.extend(lire("CurrentUser", 1 << 16)?);
    Some(lignes.join("\n"))
}

/// Les certificats du magasin « Root » d'un emplacement (CERT_SYSTEM_STORE_LOCAL_MACHINE ou CURRENT_USER), ouvert en
/// lecture seule ; vide s'il n'existe pas, `None` s'il refuse de s'ouvrir ou si l'énumération s'arrête sur une erreur.
fn lire(nom: &str, emplacement: u32) -> Option<Vec<String>> {
    const SYSTEME: usize = 10;
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
    // fin ou en cas d'erreur (GetLastError les distingue) ; chaque certificat n'est passé qu'aux fonctions de crypt32, qui écrivent au plus la taille donnée dans
    // les tampons, qui l'ont.
    unsafe {
        let magasin = CertOpenStore(
            SYSTEME as *const i8,
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
            let mut empreinte = [0u8; 20];
            let mut taille = 20u32;
            if CertGetCertificateContextProperty(
                certificat,
                EMPREINTE_SHA1,
                empreinte.as_mut_ptr().cast(),
                &raw mut taille,
            ) == 0
                || taille != 20
            {
                continue;
            }
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

            lignes.push(ligne(nom, cle, &empreinte, &nom_du_certificat));
        };
        CertCloseStore(magasin, 0);
        complet.then_some(lignes)
    }
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
