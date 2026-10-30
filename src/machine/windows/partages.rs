//! Les partages de Windows lus sans PowerShell : NetShareEnum (les partages et leur descripteur de sécurité),
//! NetUserEnum (le compte Invité) et le gestionnaire de services (le service Serveur). Le texte rendu a la forme de
//! celui du script de secours (sections ACC, INV, SRV), lu par le même code. Le descripteur de sécurité est copié
//! puis relu en code sûr.

use std::ffi::c_void;

use super::securite::sid_en_texte;

/// SHARE_INFO_502 de lmshare.h.
#[repr(C)]
struct Partage502 {
    nom: *const u16,
    sorte: u32,
    remarque: *const u16,
    permissions: u32,
    max: u32,
    en_cours: u32,
    chemin: *const u16,
    mot_de_passe: *const u16,
    reserve: u32,
    securite: *const c_void,
}

/// SHARE_INFO_1 de lmshare.h : sans chemin ni droits, lisible sans être administrateur.
#[repr(C)]
struct Partage1 {
    nom: *const u16,
    sorte: u32,
    remarque: *const u16,
}

/// USER_INFO_20 de lmaccess.h : `rid` est le dernier nombre du SID du compte (501 : Invité).
#[repr(C)]
struct Compte20 {
    nom: *const u16,
    nom_complet: *const u16,
    commentaire: *const u16,
    drapeaux: u32,
    rid: u32,
}

#[link(name = "netapi32")]
unsafe extern "system" {
    fn NetShareEnum(
        serveur: *const u16,
        niveau: u32,
        tampon: *mut *mut c_void,
        maximum: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut u32,
    ) -> u32;
    fn NetUserEnum(
        serveur: *const u16,
        niveau: u32,
        filtre: u32,
        tampon: *mut *mut c_void,
        maximum: u32,
        lus: *mut u32,
        total: *mut u32,
        reprise: *mut u32,
    ) -> u32;
    fn NetApiBufferFree(tampon: *mut c_void) -> u32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn LookupAccountSidW(
        systeme: *const u16,
        sid: *mut c_void,
        nom: *mut u16,
        taille_nom: *mut u32,
        domaine: *mut u16,
        taille_domaine: *mut u32,
        usage: *mut u32,
    ) -> i32;
}

const TOUT: u32 = u32::MAX;
const SPECIAL: u32 = 0x8000_0000;

/// Un texte UTF-16 terminé par un zéro, rendu par Windows ; lu sur 32 767 caractères au plus (la plus grande longueur
/// d'un nom ou d'un chemin de Windows).
///
/// # Safety
/// `p` est nul, ou désigne un texte terminé par un zéro qui vit pendant l'appel.
unsafe fn texte(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    // SAFETY : la borne est testée avant chaque lecture ; le texte se termine par un zéro (contrat de l'appelant).
    unsafe {
        while n < 32_767 && *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

/// Les lignes « ACC|… » des partages non spéciaux, puis « ACC_FIN » ; `None` si Windows refuse même la liste simple.
/// Sans droits d'administrateur, les droits d'un partage ne se lisent pas : sa ligne le dit (« ? »), comme le script.
fn acces() -> Option<Vec<String>> {
    let mut tampon: *mut c_void = std::ptr::null_mut();
    let (mut lus, mut total) = (0u32, 0u32);
    let mut lignes = Vec::new();
    // SAFETY : NetShareEnum (serveur nul : cet ordinateur) écrit dans `tampon` `lus` structures du niveau demandé,
    // que les types repr(C) reproduisent ; elles sont lues tant que le tampon vit, puis rendu une seule fois. Code non
    // nul : rien n'a été alloué.
    unsafe {
        if NetShareEnum(
            std::ptr::null(),
            502,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            std::ptr::null_mut(),
        ) == 0
            && !tampon.is_null()
        {
            let liste = std::slice::from_raw_parts(tampon.cast::<Partage502>(), usize::try_from(lus).ok()?);
            for p in liste.iter().filter(|p| p.sorte & SPECIAL == 0) {
                let (nom, chemin) = (texte(p.nom), texte(p.chemin));
                match droits(p.securite) {
                    Some(regles) => lignes.extend(regles.into_iter().map(|r| format!("ACC|{nom}|{chemin}|{r}"))),
                    None => lignes.push(format!("ACC|{nom}|{chemin}|?|?|?|?")),
                }
            }
            NetApiBufferFree(tampon);
        // Un code d'erreur (ERROR_MORE_DATA…) peut venir avec un tampon alloué : rendu avant le second essai.
        } else if rendre(&mut tampon)
            && NetShareEnum(
                std::ptr::null(),
                1,
                &raw mut tampon,
                TOUT,
                &raw mut lus,
                &raw mut total,
                std::ptr::null_mut(),
            ) == 0
            && !tampon.is_null()
        {
            let liste = std::slice::from_raw_parts(tampon.cast::<Partage1>(), usize::try_from(lus).ok()?);
            for p in liste.iter().filter(|p| p.sorte & SPECIAL == 0) {
                lignes.push(format!("ACC|{}||?|?|?|?", texte(p.nom)));
            }
            NetApiBufferFree(tampon);
        } else {
            rendre(&mut tampon);
            return None;
        }
    }
    lignes.push("ACC_FIN".into());
    Some(lignes)
}

/// Les règles d'un partage, « compte|SID|Allow ou Deny|droit » ; `None` si son descripteur ne se lit pas. Sans
/// descripteur, ou sans liste de droits, Windows ouvre le partage à tout le monde.
fn droits(descripteur: *const c_void) -> Option<Vec<String>> {
    if descripteur.is_null() {
        return Some(vec!["Everyone|S-1-1-0|Allow|Full".into()]);
    }
    // SAFETY : le descripteur vient de NetShareEnum et vit avec son tampon.
    let octets = unsafe { super::securite::copier(descripteur) }?;
    let Some(regles) = regles_du_descripteur(&octets) else {
        return Some(vec!["Everyone|S-1-1-0|Allow|Full".into()]);
    };
    Some(
        regles
            .into_iter()
            .map(|r| format!("{}|{}|{}|{}", nom_du_compte(&r.sid), r.sid_texte, r.genre, r.droit))
            .collect(),
    )
}

/// Une règle lue dans la liste des droits d'un partage.
#[derive(Debug, PartialEq)]
struct Regle {
    sid: Vec<u8>,
    sid_texte: String,
    genre: &'static str,
    droit: &'static str,
}

/// Les règles « autoriser » et « refuser » simples d'un descripteur, les seules que Get-SmbShareAccess montre ; `None`
/// sans liste de droits (tout le monde a tout).
fn regles_du_descripteur(octets: &[u8]) -> Option<Vec<Regle>> {
    Some(
        super::securite::aces(octets)?
            .into_iter()
            .filter_map(|a| {
                let genre = match a.sorte {
                    0 => "Allow",
                    1 => "Deny",
                    _ => return None,
                };
                Some(Regle {
                    sid_texte: sid_en_texte(&a.sid)?,
                    droit: droit(a.masque),
                    sid: a.sid,
                    genre,
                })
            })
            .collect(),
    )
}

/// Le droit d'un masque, dans les mots de Get-SmbShareAccess : Full (contrôle total), Change (modifier), Read (lire),
/// sinon Custom.
fn droit(masque: u32) -> &'static str {
    const TOUS: u32 = 0x1000_0000;
    const LECTURE_GENERIQUE: u32 = 0x8000_0000;
    const CONTROLE_TOTAL: u32 = 0x001F_01FF;
    const MODIFIER: u32 = 0x0013_01BF;
    const LIRE: u32 = 0x0012_00A9;
    if masque & TOUS != 0 || masque & CONTROLE_TOTAL == CONTROLE_TOTAL {
        "Full"
    } else if masque & MODIFIER == MODIFIER {
        "Change"
    } else if masque & LIRE == LIRE || masque & LECTURE_GENERIQUE != 0 {
        "Read"
    } else {
        "Custom"
    }
}

/// Le nom d'un compte (« Everyone », « BUILTIN\Administrators ») ; son SID en texte s'il ne se traduit pas.
fn nom_du_compte(sid: &[u8]) -> String {
    let repli = || sid_en_texte(sid).unwrap_or_default();
    // Un SID est fait de mots de 32 bits : copié dans un tampon aligné pour Windows.
    // Petit-boutiste, le dernier mot complété de zéros.
    let mut aligne: Vec<u32> = sid
        .chunks(4)
        .map(|mot| {
            mot.iter()
                .enumerate()
                .fold(0, |a, (i, &o)| a | (u32::from(o) << (8 * i)))
        })
        .collect();
    let (mut nom, mut domaine) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut taille_nom, mut taille_domaine, mut usage) = (256u32, 256u32, 0u32);
    // SAFETY : le SID copié vit pendant l'appel ; Windows écrit au plus 256 caractères dans chaque tampon, qui les a.
    let lu = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            aligne.as_mut_ptr().cast(),
            nom.as_mut_ptr(),
            &raw mut taille_nom,
            domaine.as_mut_ptr(),
            &raw mut taille_domaine,
            &raw mut usage,
        )
    } != 0;
    if !lu {
        return repli();
    }
    // Jusqu'au premier zéro, ou tout le tampon s'il n'y en a pas.
    let lire = |t: &[u16]| String::from_utf16_lossy(t.split(|&c| c == 0).next().unwrap_or(t));

    match (lire(&domaine), lire(&nom)) {
        (_, n) if n.is_empty() => repli(),
        (d, n) if d.is_empty() => n,
        (d, n) => format!("{d}\\{n}"),
    }
}

/// ERROR_MORE_DATA : Windows a répondu en partie, d'autres entrées restent à lire.
const ERROR_MORE_DATA: u32 = 234;

/// Rend à Windows un tampon de NetShareEnum ou NetUserEnum s'il en a alloué un, même avec un code d'erreur, et le
/// remet à nul. Toujours vrai : il se place en tête d'une condition, avant un nouvel essai.
///
/// # Safety
/// `tampon` est nul, ou un tampon alloué par une fonction Net* et pas encore rendu.
unsafe fn rendre(tampon: &mut *mut c_void) -> bool {
    if !tampon.is_null() {
        // SAFETY : tampon alloué par Windows, rendu une seule fois (remis à nul aussitôt).
        unsafe { NetApiBufferFree(*tampon) };
        *tampon = std::ptr::null_mut();
    }
    true
}

/// « INV|True » si le compte Invité (RID 501) est activé, « INV|False » sinon, « INV| » s'il n'existe pas ; `None`
/// si la liste des comptes ne se lit pas.
fn invite() -> Option<String> {
    const COMPTES_NORMAUX: u32 = 0x2;
    const DESACTIVE: u32 = 0x2;
    let mut tampon: *mut c_void = std::ptr::null_mut();
    let (mut lus, mut total, mut reprise) = (0u32, 0u32, 0u32);
    // SAFETY : comme pour NetShareEnum : `lus` structures USER_INFO_20, lues tant que le tampon vit, rendu une fois.
    unsafe {
        let code = NetUserEnum(
            std::ptr::null(),
            20,
            COMPTES_NORMAUX,
            &raw mut tampon,
            TOUT,
            &raw mut lus,
            &raw mut total,
            &raw mut reprise,
        );
        if tampon.is_null() {
            return None;
        }
        // ERROR_MORE_DATA : un premier lot est lu (beaucoup de comptes). L'Invité y est presque toujours ; absent de
        // ce lot, il n'est pas pour autant absent de l'ordinateur : non lu.
        let etat = if code == 0 || code == ERROR_MORE_DATA {
            let liste = std::slice::from_raw_parts(tampon.cast::<Compte20>(), usize::try_from(lus).unwrap_or(0));
            match liste.iter().find(|c| c.rid == 501) {
                Some(c) => Some(if c.drapeaux & DESACTIVE == 0 { "True" } else { "False" }),
                None => (code == 0).then_some(""),
            }
        } else {
            None
        };
        // Rendu dans tous les cas où Windows l'a alloué, code d'erreur compris.
        NetApiBufferFree(tampon);
        etat.map(|e| format!("INV|{e}"))
    }
}

/// Le relevé des partages, dans la forme du script de secours ; `None` si Windows refuse la liste des partages.
pub(crate) fn releve() -> Option<String> {
    let mut lignes = acces()?;
    if let Some(i) = invite() {
        lignes.extend([i, "INV_FIN".into()]);
    }
    if let Some(super::gestionnaire::Service::Etat(e)) = super::gestionnaire::etat("LanmanServer") {
        lignes.extend([format!("SRV|{e}"), "SRV_FIN".into()]);
    }
    Some(lignes.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SID binaire de « Tout le monde » (S-1-1-0) et d'un compte inventé.
    const TOUT_LE_MONDE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];

    fn regle(sorte: u8, masque: u32, sid: &[u8]) -> Vec<u8> {
        let taille = u16::try_from(8 + sid.len()).unwrap();
        let mut r = vec![sorte, 0];
        r.extend_from_slice(&taille.to_le_bytes());
        r.extend_from_slice(&masque.to_le_bytes());
        r.extend_from_slice(sid);
        r
    }

    fn descripteur(regles: &[Vec<u8>], controle: u16) -> Vec<u8> {
        let corps: Vec<u8> = regles.concat();
        let mut d = vec![1, 0];
        d.extend_from_slice(&controle.to_le_bytes());
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&20u32.to_le_bytes());
        d.extend_from_slice(&[2, 0]);
        d.extend_from_slice(&u16::try_from(8 + corps.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&u16::try_from(regles.len()).unwrap().to_le_bytes());
        d.extend_from_slice(&[0, 0]);
        d.extend_from_slice(&corps);
        d
    }

    #[test]
    fn droits_des_masques() {
        assert_eq!(droit(0x001F_01FF), "Full");
        assert_eq!(droit(0x1000_0000), "Full");
        assert_eq!(droit(0x0013_01BF), "Change");
        assert_eq!(droit(0x0012_00A9), "Read");
        assert_eq!(droit(0x0000_0001), "Custom");
    }

    #[test]
    fn regles_relues_dans_le_descripteur() {
        let d = descripteur(
            &[
                regle(0, 0x0012_00A9, &TOUT_LE_MONDE),
                regle(5, 0x001F_01FF, &TOUT_LE_MONDE),
                regle(1, 0x001F_01FF, &TOUT_LE_MONDE),
            ],
            0x8004,
        );
        let r = regles_du_descripteur(&d).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            (r[0].sid_texte.as_str(), r[0].genre, r[0].droit),
            ("S-1-1-0", "Allow", "Read")
        );
        assert_eq!((r[1].genre, r[1].droit), ("Deny", "Full"));
        // Sans liste de droits : tout le monde a tout.
        assert_eq!(regles_du_descripteur(&descripteur(&[], 0x8000)), None);
        // Une règle qui déborde de la liste arrête la lecture ; un descripteur tronqué ne se lit pas.
        let mut tronque = d.clone();
        tronque[22] = 30;
        assert!(regles_du_descripteur(&tronque).is_some_and(|r| r.len() <= 1));
        assert_eq!(regles_du_descripteur(&d[..10]), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : le relevé se lit sans planter.
    #[test]
    fn partages_lus_par_windows() {
        if let Some(t) = releve() {
            assert!(t.lines().any(|l| l == "ACC_FIN"), "{t}");
        }
        assert_ne!(nom_du_compte(&TOUT_LE_MONDE), "");
    }
}
