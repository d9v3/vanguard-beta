//! Retirer l'accès d'un compte à un partage (`vanguard:partage-retirer-acces <nom> <SID>`, grammaire de `gestes.rs`),
//! dans le processus élevé, par netapi32, sans PowerShell.
//!
//! Le processus élevé relit les partages et rejuge par la fonction du bilan (`partages::acces_signale`) : ce partage,
//! ce compte (Tout le monde, Invités, Anonyme…). Il relit le descripteur du partage, n'en retire que les règles
//! « autoriser » de ce compte (les refus, le propriétaire et les autres comptes restent), l'écrit, puis le relit :
//! seule la relecture compte. Jamais un partage spécial (C$, ADMIN$, IPC$) : le Bureau à distance, SSH et
//! l'administration à distance en dépendent. Le descripteur d'avant est noté (SDDL) ; le geste ne s'annule pas tout
//! seul, car remettre l'accès de Tout le monde rouvrirait le partage.

// FFI de netapi32 : NetShareGetInfo, NetShareSetInfo.
#![allow(unsafe_code)]

use std::ffi::c_void;

use super::comptes::NetApiBufferFree;
use super::corrections::{Resultat, avant_notable};
use super::partages::{NetShareGetInfo, NetShareSetInfo, Partage502, SPECIAL};
use super::securite;
use crate::machine::gestes::AccesPartage;
use crate::modele::Echec;
use crate::ui::{tr, trf};

/// SHARE_INFO_1501 de lmshare.h.
#[repr(C)]
struct Partage1501 {
    reserve: u32,
    securite: *const c_void,
}

/// STYPE_IPC : le canal des appels à distance, jamais touché.
const IPC: u32 = 3;

/// Le descripteur d'un partage (copie autonome), ou pourquoi il ne se lit pas ou n'est pas touché.
fn descripteur(nom: &[u16]) -> Result<Vec<u8>, Echec> {
    let mut tampon: *mut c_void = std::ptr::null_mut();
    // SAFETY: le nom est terminé par un zéro et vit pendant l'appel ; NetShareGetInfo écrit dans `tampon` une
    // SHARE_INFO_502 (reproduite par Partage502), lue tant qu'il vit, puis rendu une seule fois. Code non nul : rien
    // n'a été alloué ou le tampon est rendu quand même s'il ne l'est pas.
    unsafe {
        let code = NetShareGetInfo(std::ptr::null(), nom.as_ptr(), 502, &raw mut tampon);
        if code != 0 || tampon.is_null() {
            if !tampon.is_null() {
                NetApiBufferFree(tampon);
            }
            return Err(Echec::echoue(
                "partages/retirer",
                trf!(
                    "partage illisible (erreur {code}), rien changé",
                    "share unreadable (error {code}), nothing changed"
                ),
            ));
        }
        let p = tampon.cast::<Partage502>().read_unaligned();
        let lu = if p.sorte & SPECIAL != 0 || p.sorte & 0xFF == IPC {
            Err(Echec::refuse(
                "partages/retirer",
                tr!(
                    "partage spécial de Windows (administration à distance) : jamais touché",
                    "special Windows share (remote administration): never touched"
                ),
            ))
        } else if p.securite.is_null() {
            Err(Echec::refuse(
                "partages/retirer",
                tr!(
                    "partage sans descripteur de sécurité (ouvert à tous par Windows) : rien à retirer règle par règle, à fermer dans Windows",
                    "share without a security descriptor (open to all by Windows): nothing to remove rule by rule, close it in Windows"
                ),
            ))
        } else {
            securite::copier(p.securite).ok_or_else(|| {
                Echec::echoue(
                    "partages/retirer",
                    tr!(
                        "descripteur du partage illisible, rien changé",
                        "share descriptor unreadable, nothing changed"
                    ),
                )
            })
        };
        NetApiBufferFree(tampon);
        lu
    }
}

/// Un descripteur autonome dans un tampon aligné (Windows le lit par mots), vérifié par Windows.
fn aligne(octets: &[u8]) -> Option<Vec<u64>> {
    // Octets natifs : la mémoire du tampon reprend les octets dans l'ordre, complétés de zéros.
    let tampon: Vec<u64> = octets
        .chunks(8)
        .map(|c| {
            let mut mot = [0u8; 8];
            mot.iter_mut().zip(c).for_each(|(m, o)| *m = *o);
            u64::from_ne_bytes(mot)
        })
        .collect();
    // SAFETY: le tampon vit pendant l'appel ; `copier` le vérifie (IsValidSecurityDescriptor) avant de le lire.
    let relu = unsafe { securite::copier(tampon.as_ptr().cast()) }?;
    (relu == octets).then_some(tampon)
}

/// Une règle « autoriser » de ce SID reste-t-elle dans ce descripteur ? Toutes les sortes d'autorisation comptent
/// (simple, objet, rappel, rappel objet : 0, 5, 9, 0xB), même si un partage n'a d'ordinaire que la première.
fn autorise_encore(octets: &[u8], sid: &str) -> bool {
    const AUTORISATIONS: [u8; 4] = [0, 5, 9, 0xB];
    securite::aces(octets).is_none_or(|regles| {
        regles.iter().any(|r| {
            AUTORISATIONS.contains(&r.sorte)
                && securite::sid_en_texte(&r.sid).is_some_and(|s| s.eq_ignore_ascii_case(sid))
        })
    })
}

/// Retire l'accès de ce compte à ce partage, signalé par le bilan relu.
pub(super) fn retirer_acces(a: &AccesPartage) -> Resultat {
    let (nom, sid) = (a.nom.texte(), a.sid.texte());
    let Some(sortie) = super::partages::releve() else {
        return Resultat::echec(
            None,
            tr!("partages illisibles, rien changé", "shares unreadable, nothing changed").to_string(),
        );
    };
    if !crate::machine::partages::acces_signale(&sortie, nom, sid) {
        return Resultat::echec(
            None,
            tr!(
                "le bilan ne propose pas de retirer cet accès à ce partage : refusé, rien changé",
                "the scan does not offer to remove this access from this share: refused, nothing changed"
            )
            .to_string(),
        );
    }
    let large: Vec<u16> = nom.encode_utf16().chain([0]).collect();
    let avant_octets = match descripteur(&large) {
        Ok(d) => d,
        Err(r) => return Resultat::echec(None, r.to_string()),
    };
    let Some(avant_aligne) = aligne(&avant_octets) else {
        return Resultat::echec(
            None,
            tr!(
                "descripteur du partage illisible, rien changé",
                "share descriptor unreadable, nothing changed"
            )
            .to_string(),
        );
    };
    // SAFETY: le descripteur aligné a été vérifié par Windows et vit pendant l'appel.
    let sddl = unsafe { securite::en_sddl(avant_aligne.as_ptr().cast()) }.unwrap_or_else(|| "?".into());
    let avant = avant_notable(&format!("{nom} : {sddl}"));
    let Some((apres, retirees)) = securite::sans_acces(&avant_octets, sid) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "partage sans liste des droits (ouvert à tous) ou descripteur illisible : rien changé, à fermer dans Windows",
                "share without an access list (open to all) or unreadable descriptor: nothing changed, close it in Windows"
            )
            .to_string(),
        );
    };
    if retirees == 0 {
        return Resultat::echec(
            Some(avant),
            tr!(
                "aucune règle de ce compte dans le descripteur relu : rien changé",
                "no rule for this account in the descriptor read back: nothing changed"
            )
            .to_string(),
        );
    }
    if autorise_encore(&apres, sid) {
        return Resultat::echec(
            Some(avant),
            tr!(
                "le partage donne aussi l'accès à ce compte par une règle d'une autre sorte : rien changé, à fermer dans Windows",
                "the share also grants this account access through another kind of rule: nothing changed, close it in Windows"
            )
            .to_string(),
        );
    }
    let Some(nouveau) = aligne(&apres) else {
        return Resultat::echec(
            Some(avant),
            tr!(
                "Windows refuse le descripteur recalculé : rien changé",
                "Windows refuses the recomputed descriptor: nothing changed"
            )
            .to_string(),
        );
    };
    let info = Partage1501 {
        reserve: 0,
        securite: nouveau.as_ptr().cast(),
    };
    let mut erreur = 0u32;
    // SAFETY: le nom est terminé par un zéro ; la structure et le descripteur qu'elle désigne vivent pendant l'appel.
    let code = unsafe {
        NetShareSetInfo(
            std::ptr::null(),
            large.as_ptr(),
            1501,
            (&raw const info).cast(),
            &raw mut erreur,
        )
    };
    if code != 0 {
        return Resultat::echec(
            Some(avant),
            trf!(
                "Windows refuse d'écrire les droits du partage (erreur {code}) : rien changé",
                "Windows refuses to write the share permissions (error {code}): nothing changed"
            ),
        );
    }
    match descripteur(&large) {
        Ok(relu) if !autorise_encore(&relu, sid) => Resultat::fait(avant),
        Ok(_) => Resultat::echec(
            Some(avant),
            tr!(
                "le compte a encore accès à la relecture : rien n'est compté comme fait",
                "the account still has access when read back: nothing is counted as done"
            )
            .to_string(),
        ),
        Err(r) => Resultat::echec(
            Some(avant),
            trf!(
                "relecture impossible ({r}) : rien n'est compté comme fait",
                "read-back failed ({r}): nothing is counted as done"
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formes_de_windows() {
        assert_eq!(std::mem::size_of::<Partage1501>(), 16);
        assert_eq!(std::mem::size_of::<Partage502>(), 72);
        assert_eq!(std::mem::offset_of!(Partage502, securite), 64);
    }

    /// Une règle « autoriser » restante se voit ; un refus du même compte n'en est pas une ; sans liste des droits,
    /// tout le monde a tout.
    #[test]
    fn acces_restant() {
        // O:BA D:(D;;FA;;;WD)(A;;FA;;;BA), écrit à la main : en-tête autonome, propriétaire, liste de deux règles.
        let ba = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        let wd = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let regle = |sorte: u8, sid: &[u8]| {
            let mut r = vec![sorte, 0];
            r.extend_from_slice(&u16::try_from(8 + sid.len()).unwrap().to_le_bytes());
            r.extend_from_slice(&0x001F_01FFu32.to_le_bytes());
            r.extend_from_slice(sid);
            r
        };
        let mut liste = Vec::new();
        liste.extend(regle(1, &wd));
        liste.extend(regle(0, &ba));
        let mut acl = vec![2u8, 0];
        acl.extend_from_slice(&u16::try_from(8 + liste.len()).unwrap().to_le_bytes());
        acl.extend_from_slice(&2u16.to_le_bytes());
        acl.extend_from_slice(&[0, 0]);
        acl.extend(liste);
        let mut sd = vec![1u8, 0];
        sd.extend_from_slice(&(0x8000u16 | 0x4).to_le_bytes());
        sd.extend_from_slice(&20u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&0u32.to_le_bytes());
        sd.extend_from_slice(&36u32.to_le_bytes());
        sd.extend_from_slice(&ba);
        sd.extend(acl);
        assert!(!autorise_encore(&sd, "S-1-1-0"));
        assert!(autorise_encore(&sd, "S-1-5-32-544"));
        // Le refus de Tout le monde devenu une autorisation à rappel (sorte 9) : elle compte.
        let mut rappel = sd.clone();
        assert_eq!(rappel[44], 1);
        rappel[44] = 9;
        assert!(autorise_encore(&rappel, "S-1-1-0"));
        let mut sans_liste = sd.clone();
        sans_liste[2] = 0;
        assert!(autorise_encore(&sans_liste, "S-1-1-0"));
    }
}
