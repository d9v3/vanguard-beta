//! Descripteurs de sécurité de Windows (droits d'un partage, d'un dossier) : copiés depuis Windows, puis relus en code
//! sûr, chaque décalage vérifié dans la copie avant d'être lu.

// FFI d'advapi32 : descripteurs de sécurité (GetNamedSecurityInfoW…).
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::path::Path;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn IsValidSecurityDescriptor(descripteur: *const c_void) -> i32;
    fn GetSecurityDescriptorLength(descripteur: *const c_void) -> u32;
    fn GetNamedSecurityInfoW(
        nom: *const u16,
        sorte: u32,
        quoi: u32,
        proprietaire: *mut *mut c_void,
        groupe: *mut *mut c_void,
        liste: *mut *mut c_void,
        audit: *mut *mut c_void,
        descripteur: *mut *mut c_void,
    ) -> u32;
    /// Partagé avec `eleve` (le tube) et `quarantaine` : une seule déclaration.
    pub(super) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        texte: *const u16,
        revision: u32,
        descripteur: *mut *mut c_void,
        taille: *mut u32,
    ) -> i32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descripteur: *const c_void,
        revision: u32,
        quoi: u32,
        texte: *mut *mut u16,
        taille: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(memoire: *mut c_void) -> *mut c_void;
}

/// SECURITY_ATTRIBUTES.
#[repr(C)]
pub(super) struct Securite {
    pub(super) taille: u32,
    pub(super) descripteur: *mut c_void,
    pub(super) heritable: i32,
}

/// Les SID qui peuvent écrire dans un dossier de Vanguard administrateur : SYSTEM, les Administrateurs, le
/// propriétaire créateur (les administrateurs, qui créent) et TrustedInstaller.
const ECRIVAINS_ADMIS: [&str; 4] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-3-0",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Les droits qui permettent d'écrire, de créer, d'effacer ou de changer les droits d'un dossier ou d'un fichier :
/// FILE_WRITE_DATA, FILE_APPEND_DATA, FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC,
/// WRITE_OWNER, GENERIC_ALL et GENERIC_WRITE.
const ECRITURE: u32 = 0x500D_0156;

/// Une règle (ACE) de la liste des droits.
#[derive(Debug, PartialEq)]
pub(crate) struct Ace {
    /// 0 : autoriser, 1 : refuser ; les autres sortes (objets, rappels) sont gardées pour être sautées.
    pub sorte: u8,
    /// Héritage (0x8 : « héritée seulement », vaut pour le contenu, pas pour l'objet).
    pub drapeaux: u8,
    pub masque: u32,
    pub sid: Vec<u8>,
}

/// Copie un descripteur de sécurité rendu par Windows ; `None` s'il n'est pas valide (ou fait plus de 64 Kio).
///
/// # Safety
/// `descripteur` est nul, ou désigne un descripteur de sécurité qui vit pendant l'appel.
pub(crate) unsafe fn copier(descripteur: *const c_void) -> Option<Vec<u8>> {
    if descripteur.is_null() {
        return None;
    }
    // SAFETY: le descripteur est vérifié avant que sa longueur soit demandée, et copié sur cette longueur seulement.
    unsafe {
        if IsValidSecurityDescriptor(descripteur) == 0 {
            return None;
        }
        let n = usize::try_from(GetSecurityDescriptorLength(descripteur)).ok()?;
        if n == 0 || n > 64 * 1024 {
            return None;
        }
        Some(std::slice::from_raw_parts(descripteur.cast::<u8>(), n).to_vec())
    }
}

/// Le descripteur (liste des droits seulement) d'un fichier ou d'un dossier, comme Get-Acl le lit ; `None` s'il ne se
/// lit pas.
pub(crate) fn du_fichier(chemin: &Path) -> Option<Vec<u8>> {
    const LISTE_DES_DROITS: u32 = 0x4;
    lire_fichier(chemin, LISTE_DES_DROITS)
}

/// Le descripteur d'un dossier avec son propriétaire et sa liste des droits ; `None` s'il ne se lit pas.
pub(crate) fn proprietaire_et_droits(chemin: &Path) -> Option<Vec<u8>> {
    const PROPRIETAIRE: u32 = 0x1;
    const LISTE_DES_DROITS: u32 = 0x4;
    lire_fichier(chemin, PROPRIETAIRE | LISTE_DES_DROITS)
}

fn lire_fichier(chemin: &Path, quoi: u32) -> Option<Vec<u8>> {
    use std::os::windows::ffi::OsStrExt;
    const FICHIER: u32 = 1;
    let nom: Vec<u16> = chemin.as_os_str().encode_wide().chain([0]).collect();
    let mut descripteur = std::ptr::null_mut();
    let mut liste = std::ptr::null_mut();
    // SAFETY: le nom est terminé par un zéro et vit pendant l'appel ; le descripteur alloué par Windows (code non nul :
    // rien n'est alloué) est copié puis rendu une seule fois par LocalFree.
    unsafe {
        let mut proprietaire = std::ptr::null_mut();
        if GetNamedSecurityInfoW(
            nom.as_ptr(),
            FICHIER,
            quoi,
            &raw mut proprietaire,
            std::ptr::null_mut(),
            &raw mut liste,
            std::ptr::null_mut(),
            &raw mut descripteur,
        ) != 0
        {
            return None;
        }
        let copie = copier(descripteur);
        LocalFree(descripteur);
        copie
    }
}

/// Les règles d'un descripteur autonome (SECURITY_DESCRIPTOR_RELATIVE) ; `None` sans liste des droits (tout le monde a
/// tout). Une règle qui déborde de la liste arrête la lecture.
pub(crate) fn aces(octets: &[u8]) -> Option<Vec<Ace>> {
    const AUTONOME: u16 = 0x8000;
    const LISTE_PRESENTE: u16 = 0x4;
    let u16_a = |d: usize| Some(u16::from_le_bytes(octets.get(d..d + 2)?.try_into().ok()?));
    let u32_a = |d: usize| Some(u32::from_le_bytes(octets.get(d..d + 4)?.try_into().ok()?));
    let controle = u16_a(2)?;
    let liste = usize::try_from(u32_a(16)?).ok()?;
    if controle & AUTONOME == 0 || controle & LISTE_PRESENTE == 0 || liste == 0 {
        return None;
    }
    let taille = usize::from(u16_a(liste + 2)?);
    let nombre = u16_a(liste + 4)?;
    let fin = liste.checked_add(taille).filter(|&f| f <= octets.len())?;
    let mut regles = Vec::new();
    let mut d = liste + 8;
    for _ in 0..nombre {
        let (Some(&sorte), Some(&drapeaux), Some(taille_regle)) =
            (octets.get(d), octets.get(d + 1), u16_a(d + 2).map(usize::from))
        else {
            break;
        };
        if taille_regle < 8 || d + taille_regle > fin {
            break;
        }
        regles.push(Ace {
            sorte,
            drapeaux,
            masque: u32_a(d + 4)?,
            sid: octets.get(d + 8..d + taille_regle)?.to_vec(),
        });
        d += taille_regle;
    }
    Some(regles)
}

/// Le propriétaire d'un descripteur autonome, en texte ; `None` s'il n'y en a pas ou qu'il déborde.
pub(crate) fn proprietaire(octets: &[u8]) -> Option<String> {
    let d = usize::try_from(u32::from_le_bytes(octets.get(4..8)?.try_into().ok()?)).ok()?;
    if d == 0 || u16::from_le_bytes(octets.get(2..4)?.try_into().ok()?) & 0x8000 == 0 {
        return None;
    }
    sid_en_texte(octets.get(d..)?)
}

/// Un dossier où Vanguard administrateur écrit est-il à l'abri des autres comptes ? Son propriétaire est SYSTEM ou les
/// Administrateurs, et aucune règle qui n'est pas un refus ne donne d'écrire à un autre SID (`ECRIVAINS_ADMIS`). Sans
/// liste des droits (tout le monde a tout) ou illisible : non.
pub(crate) fn reserve_aux_administrateurs(octets: &[u8]) -> bool {
    /// ACCESS_DENIED, ACCESS_DENIED_OBJECT, ACCESS_DENIED_CALLBACK, ACCESS_DENIED_CALLBACK_OBJECT : seuls ces refus
    /// sont sautés ; toute autre sorte compte comme une autorisation.
    const REFUS: [u8; 4] = [1, 6, 0xA, 0xC];
    let Some(p) = proprietaire(octets) else {
        return false;
    };
    if !matches!(p.as_str(), "S-1-5-18" | "S-1-5-32-544") {
        return false;
    }
    let Some(regles) = aces(octets) else {
        return false;
    };
    // `aces` s'arrête à une règle qui déborde : les suivantes ne seraient pas vues. Toutes lues, ou non.
    let annoncees = usize::try_from(u32::from_le_bytes(
        octets.get(16..20).and_then(|b| b.try_into().ok()).unwrap_or([0; 4]),
    ))
    .ok()
    .and_then(|d| octets.get(d.checked_add(4)?..d.checked_add(6)?))
    .and_then(|b| b.try_into().ok())
    .map(u16::from_le_bytes);
    if annoncees != u16::try_from(regles.len()).ok() {
        return false;
    }
    regles.iter().all(|r| {
        REFUS.contains(&r.sorte)
            || r.masque & ECRITURE == 0
            || r.sorte == 0 && sid_en_texte(&r.sid).is_some_and(|s| ECRIVAINS_ADMIS.contains(&s.as_str()))
    })
}

/// Le descripteur autonome sans les règles d'autorisation simples (ACCESS_ALLOWED) de ce SID, avec le nombre de règles
/// retirées. Le propriétaire, le groupe, la liste d'audit et les autres règles sont gardés tels quels, dans le même
/// ordre. `None` si le descripteur n'est pas autonome, n'a pas de liste des droits ou déborde.
pub(crate) fn sans_acces(octets: &[u8], sid: &str) -> Option<(Vec<u8>, usize)> {
    const AUTONOME: u16 = 0x8000;
    const LISTE_PRESENTE: u16 = 0x4;
    const AUDIT_PRESENT: u16 = 0x10;
    let u16_a = |o: &[u8], d: usize| Some(u16::from_le_bytes(o.get(d..d.checked_add(2)?)?.try_into().ok()?));
    let u32_a = |d: usize| usize::try_from(u32::from_le_bytes(octets.get(d..d.checked_add(4)?)?.try_into().ok()?)).ok();
    let controle = u16_a(octets, 2)?;
    if controle & AUTONOME == 0 || controle & LISTE_PRESENTE == 0 {
        return None;
    }
    // Un morceau désigné par son décalage (0 : absent), sur la longueur que donne son début.
    let morceau = |champ: usize, est_un_sid: bool| -> Option<Option<&[u8]>> {
        let d = u32_a(champ)?;
        if d == 0 {
            return Some(None);
        }
        let longueur = if est_un_sid {
            usize::from(*octets.get(d.checked_add(1)?)?)
                .checked_mul(4)?
                .checked_add(8)?
        } else {
            usize::from(u16_a(octets, d.checked_add(2)?)?)
        };
        Some(Some(octets.get(d..d.checked_add(longueur)?)?))
    };
    let proprietaire = morceau(4, true)?;
    let groupe = morceau(8, true)?;
    let audit = if controle & AUDIT_PRESENT == 0 {
        None
    } else {
        morceau(12, false)?
    };
    let liste = morceau(16, false)??;
    let nombre = u16_a(liste, 4)?;
    let mut regles = Vec::new();
    let (mut gardees, mut retirees) = (0u16, 0usize);
    let mut d = 8usize;
    for _ in 0..nombre {
        let sorte = *liste.get(d)?;
        let taille = usize::from(u16_a(liste, d.checked_add(2)?)?);
        if taille < 8 {
            return None;
        }
        let regle = liste.get(d..d.checked_add(taille)?)?;
        let visee = sorte == 0
            && regle
                .get(8..)
                .and_then(sid_en_texte)
                .is_some_and(|s| s.eq_ignore_ascii_case(sid));
        if visee {
            retirees = retirees.checked_add(1)?;
        } else {
            regles.extend_from_slice(regle);
            gardees = gardees.checked_add(1)?;
        }
        d = d.checked_add(taille)?;
    }
    let taille_liste = u16::try_from(regles.len().checked_add(8)?).ok()?;
    let mut nouvelle = Vec::with_capacity(usize::from(taille_liste));
    // Révision et Sbz1 de l'ACL, puis sa taille, le nombre de règles et Sbz2.
    nouvelle.extend_from_slice(liste.get(..2)?);
    nouvelle.extend_from_slice(&taille_liste.to_le_bytes());
    nouvelle.extend_from_slice(&gardees.to_le_bytes());
    nouvelle.extend_from_slice(&[0, 0]);
    nouvelle.extend_from_slice(&regles);
    // L'en-tête (révision, Sbz1, contrôle), puis les quatre décalages, remplis à mesure ; chaque morceau commence sur
    // quatre octets.
    let mut sortie = octets.get(..4)?.to_vec();
    sortie.extend_from_slice(&[0; 16]);
    for (champ, partie) in [
        (4usize, proprietaire),
        (8, groupe),
        (12, audit),
        (16, Some(nouvelle.as_slice())),
    ] {
        let Some(partie) = partie else { continue };
        while sortie.len() % 4 != 0 {
            sortie.push(0);
        }
        let decalage = u32::try_from(sortie.len()).ok()?.to_le_bytes();
        sortie.get_mut(champ..champ.checked_add(4)?)?.copy_from_slice(&decalage);
        sortie.extend_from_slice(partie);
    }
    Some((sortie, retirees))
}

/// Un descripteur en SDDL (propriétaire et liste des droits) ; `None` si Windows refuse.
///
/// # Safety
/// `descripteur` désigne un descripteur de sécurité valide qui vit pendant l'appel.
pub(crate) unsafe fn en_sddl(descripteur: *const c_void) -> Option<String> {
    const PROPRIETAIRE_ET_DROITS: u32 = 0x1 | 0x4;
    let mut texte: *mut u16 = std::ptr::null_mut();
    let mut taille = 0u32;
    // SAFETY: Windows alloue le texte (terminé par un zéro, `taille` caractères), lu puis rendu une seule fois.
    unsafe {
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descripteur,
            1,
            PROPRIETAIRE_ET_DROITS,
            &raw mut texte,
            &raw mut taille,
        ) == 0
            || texte.is_null()
        {
            return None;
        }
        let n = usize::try_from(taille).unwrap_or(0).min(64 * 1024);
        let t = String::from_utf16_lossy(std::slice::from_raw_parts(texte, n));
        LocalFree(texte.cast());
        Some(t.trim_end_matches('\0').to_string())
    }
}

/// « S-1-5-21-… » d'un SID binaire : révision, nombre de sous-autorités, autorité sur six octets (gros-boutiste), puis
/// les sous-autorités (petit-boutistes).
pub(crate) fn sid_en_texte(sid: &[u8]) -> Option<String> {
    use std::fmt::Write as _;
    let (revision, n) = (*sid.first()?, usize::from(*sid.get(1)?));
    if revision != 1 || n > 15 || sid.len() < 8 + 4 * n {
        return None;
    }
    let autorite = sid.get(2..8)?.iter().fold(0u64, |a, &o| (a << 8) | u64::from(o));
    let mut t = format!("S-1-{autorite}");
    let (sous_autorites, _) = sid.get(8..8 + 4 * n)?.as_chunks::<4>();
    for s in sous_autorites {
        let _ = write!(t, "-{}", u32::from_le_bytes(*s));
    }

    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sids_en_texte() {
        assert_eq!(
            sid_en_texte(&[1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]).as_deref(),
            Some("S-1-1-0")
        );
        let mut invite = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for s in [21u32, 111, 222, 333, 501] {
            invite.extend_from_slice(&s.to_le_bytes());
        }
        assert_eq!(sid_en_texte(&invite).as_deref(), Some("S-1-5-21-111-222-333-501"));
        assert_eq!(sid_en_texte(&invite[..20]), None);
        assert_eq!(sid_en_texte(&[2, 0, 0, 0, 0, 0, 0, 1]), None);
    }

    /// Un SID binaire depuis son texte, pour les essais : « S-1-a-b-… ».
    fn sid(texte: &str) -> Vec<u8> {
        let n: Vec<u64> = texte
            .trim_start_matches("S-1-")
            .split('-')
            .map(|x| x.parse().unwrap())
            .collect();
        let mut o = vec![1, u8::try_from(n.len() - 1).unwrap()];
        o.extend_from_slice(&n[0].to_be_bytes()[2..]);
        for s in &n[1..] {
            o.extend_from_slice(&u32::try_from(*s).unwrap().to_le_bytes());
        }
        o
    }

    fn regle(sorte: u8, masque: u32, s: &str) -> Vec<u8> {
        let s = sid(s);
        let mut r = vec![sorte, 0];
        r.extend_from_slice(&u16::try_from(8 + s.len()).unwrap().to_le_bytes());
        r.extend_from_slice(&masque.to_le_bytes());
        r.extend_from_slice(&s);
        r
    }

    /// Un descripteur autonome : propriétaire, puis la liste des droits (ou aucune).
    fn descripteur(proprietaire: &str, regles: Option<&[Vec<u8>]>) -> Vec<u8> {
        let p = sid(proprietaire);
        let mut controle: u16 = 0x8000;
        let mut o = vec![1, 0, 0, 0];
        o.extend_from_slice(&20u32.to_le_bytes());
        o.extend_from_slice(&[0; 8]);
        let liste = u32::try_from(20 + p.len()).unwrap();
        o.extend_from_slice(&if regles.is_some() { liste } else { 0 }.to_le_bytes());
        o.extend_from_slice(&p);
        if let Some(regles) = regles {
            controle |= 0x4;
            let corps: Vec<u8> = regles.concat();
            o.extend_from_slice(&[2, 0]);
            o.extend_from_slice(&u16::try_from(8 + corps.len()).unwrap().to_le_bytes());
            o.extend_from_slice(&u16::try_from(regles.len()).unwrap().to_le_bytes());
            o.extend_from_slice(&[0, 0]);
            o.extend_from_slice(&corps);
        }
        o[2..4].copy_from_slice(&controle.to_le_bytes());
        o
    }

    /// La quarantaine n'est utilisée que si les autres comptes ne peuvent pas y écrire, ni la remplacer.
    #[test]
    fn dossier_reserve_aux_administrateurs() {
        let admins = [regle(0, 0x1F_01FF, "S-1-5-18"), regle(0, 0x1F_01FF, "S-1-5-32-544")];
        assert!(reserve_aux_administrateurs(&descripteur("S-1-5-32-544", Some(&admins))));
        assert_eq!(
            proprietaire(&descripteur("S-1-5-32-544", Some(&admins))).as_deref(),
            Some("S-1-5-32-544")
        );
        // Un autre propriétaire (le compte qui l'a créé avant Vanguard) : il peut changer les droits.
        assert!(!reserve_aux_administrateurs(&descripteur(
            "S-1-5-21-1-2-3-1001",
            Some(&admins)
        )));
        // Sans liste des droits : tout le monde a tout.
        assert!(!reserve_aux_administrateurs(&descripteur("S-1-5-32-544", None)));
        // Les Utilisateurs peuvent y créer des fichiers ; ou Tout le monde a GENERIC_ALL.
        for (masque, s) in [(0x4, "S-1-5-32-545"), (0x1000_0000, "S-1-1-0"), (0x1_0000, "S-1-5-11")] {
            let mut r = admins.to_vec();
            r.push(regle(0, masque, s));
            assert!(!reserve_aux_administrateurs(&descripteur("S-1-5-18", Some(&r))), "{s}");
            // Une autorisation d'une autre sorte (objet, rappel) compte aussi.
            let mut r = admins.to_vec();
            r.push(regle(9, masque, s));
            assert!(!reserve_aux_administrateurs(&descripteur("S-1-5-18", Some(&r))), "{s}");
        }
        // Lire seulement, ou un refus d'écrire : admis.
        let mut r = admins.to_vec();
        r.push(regle(0, 0x12_00A9, "S-1-5-32-545"));
        r.push(regle(1, ECRITURE, "S-1-1-0"));
        assert!(reserve_aux_administrateurs(&descripteur("S-1-5-18", Some(&r))));
        // Une règle annoncée qui ne se lit pas (taille trop petite) : celles d'après ne seraient pas vues, refusé.
        let mut cassee = regle(0, 0x12_00A9, "S-1-5-32-545");
        cassee[2] = 4;
        let mut r = admins.to_vec();
        r.push(cassee);
        r.push(regle(0, 0x1F_01FF, "S-1-1-0"));
        assert!(!reserve_aux_administrateurs(&descripteur("S-1-5-18", Some(&r))));
    }

    /// Retirer d'un partage les autorisations d'un compte : seules les siennes partent, le reste est gardé tel quel.
    #[test]
    fn retirer_les_autorisations_d_un_compte() {
        let regles = [
            regle(0, 0x1F_01FF, "S-1-1-0"),
            regle(1, 0x1F_01FF, "S-1-1-0"),
            regle(0, 0x1F_01FF, "S-1-5-21-1-2-3-1001"),
            regle(0, 0x12_00A9, "S-1-1-0"),
        ];
        let d = descripteur("S-1-5-32-544", Some(&regles));
        let (nouveau, retirees) = sans_acces(&d, "S-1-1-0").unwrap();
        assert_eq!(retirees, 2);
        assert_eq!(proprietaire(&nouveau).as_deref(), Some("S-1-5-32-544"));
        let apres = aces(&nouveau).unwrap();
        assert_eq!(apres.len(), 2);
        assert_eq!(
            (apres[0].sorte, sid_en_texte(&apres[0].sid).as_deref()),
            (1, Some("S-1-1-0"))
        );
        assert_eq!(sid_en_texte(&apres[1].sid).as_deref(), Some("S-1-5-21-1-2-3-1001"));
        // Aucune règle de ce compte : rien retiré.
        assert_eq!(sans_acces(&d, "S-1-5-7").unwrap().1, 0);
        // Tout retiré : une liste vide, pas une liste absente (personne n'a accès, et non tout le monde).
        let seul = descripteur("S-1-5-32-544", Some(&[regle(0, 0x1F_01FF, "S-1-1-0")]));
        let (vide, n) = sans_acces(&seul, "S-1-1-0").unwrap();
        assert_eq!((n, aces(&vide).map(|a| a.len())), (1, Some(0)));
        // Sans liste des droits, pas autonome, ou une règle qui déborde : rien.
        assert_eq!(sans_acces(&descripteur("S-1-5-32-544", None), "S-1-1-0"), None);
        let mut absolu = d.clone();
        absolu[3] &= 0x7F;
        assert_eq!(sans_acces(&absolu, "S-1-1-0"), None);
        let mut deborde = d.clone();
        let n = deborde.len();
        deborde.truncate(n - 4);
        assert_eq!(sans_acces(&deborde, "S-1-1-0"), None);
    }

    /// Le vrai Windows (Wine ici, la VM ensuite) : la liste des droits du dossier de Windows se lit et se relit.
    #[test]
    fn droits_d_un_dossier() {
        let windows = std::env::var_os("SystemRoot").map_or_else(|| r"C:\Windows".into(), std::path::PathBuf::from);
        if let Some(d) = du_fichier(&windows) {
            let _ = aces(&d);
        }
        assert_eq!(du_fichier(Path::new(r"C:\vanguard-dossier-inexistant")), None);
    }
}
