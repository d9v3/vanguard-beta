//! Retirer une racine signalée par le bilan (`vanguard:certificat-retirer <lm|cu> <empreinte>`, grammaire de
//! `gestes.rs`), dans le processus élevé, par crypt32, sans PowerShell.
//!
//! Le processus élevé relit les deux magasins « Root » et rejuge la racine par la fonction du bilan
//! (`certificats::retrait`) : même magasin, même empreinte exacte. Il exporte le certificat (sans clé privée) dans la
//! quarantaine, le retire, puis le cherche de nouveau : seule la relecture compte. Pour le magasin du compte, Windows
//! montre sa propre fenêtre de confirmation, et ce magasin doit être celui de la personne (le processus élevé peut
//! tourner sous un autre compte administrateur). Jamais un ajout : Vanguard ne remet pas une racine retirée ; la
//! copie de la quarantaine permet à la personne de la réimporter elle-même. Sans copie possible, la console élevée
//! le dit et pose une question de plus (« sans copie, non annulable ») : seul un oui retire la racine, ses
//! empreintes (SHA-1, et SHA-256 quand le certificat se lit) et son nom notés.

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
    // Les deux empreintes et le nom, notés avant le nom (qui peut être long et coupé) : de quoi retrouver la racine
    // ailleurs, même sans sa copie.
    let empreintes = if der.is_empty() {
        format!("SHA-1 {}", e.texte())
    } else {
        format!("SHA-1 {}, SHA-256 {}", e.texte(), super::sha256_hex(&der))
    };
    let nom_note = crate::ui::couper(&montre, NOM_NOTE_MAX);
    // Sans copie, la racine peut quand même être retirée : un compte ordinaire peut poser d'avance un dossier Vanguard
    // sous ProgramData (refusé par `quarantaine`) ; s'il suffisait à garder sa racine, il la protégerait. Mais ce
    // retrait-là ne se rattrape pas : la personne le dit elle-même, par une question de plus dans cette console. La
    // fin de l'entrée (console fermée) vaut non : le processus va au bout de la liste et rend chaque ligne.
    let Some(copie) = decider_copie(copie, &nom_note, &empreintes, crate::ui::demander_ou_defaut) else {
        // SAFETY: le contexte trouvé (non nul) n'est ni retiré ni rendu ailleurs : rendu ici, une seule fois.
        unsafe {
            CertFreeCertificateContext(certificat);
        }
        return Resultat::echec(None, garde_sans_copie().to_string());
    };
    let avant = avant_notable(&format!("{} {empreintes} « {nom_note} », {copie}", m.nom()));
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

/// Au-delà, le nom de la racine est coupé dans la note : les empreintes passent avant lui (`AVANT_MAX`).
const NOM_NOTE_MAX: usize = 160;
/// Au-delà, la raison d'une copie manquée est coupée dans la note.
const RAISON_NOTE_MAX: usize = 160;

/// La raison d'une racine gardée parce que la personne n'a pas accepté de la retirer sans copie.
fn garde_sans_copie() -> &'static str {
    tr!(
        "racine gardée, encore de confiance : la copie .cer n'a pas pu être faite, et vous n'avez pas accepté de la retirer sans copie",
        "root kept, still trusted: the .cer copy could not be made, and you did not accept removing it without a copy"
    )
}

/// Ce que la note dit de la copie, ou `None` : la racine est gardée. Une copie faite : rien n'est demandé. Copie
/// impossible : la raison, puis une question de plus, posée ici, dans la console élevée, jamais par une ligne de la
/// liste (aucune ligne ne dit « sans copie » : une liste forgée ne peut pas sauter la question). Seul un oui retire ;
/// Entrée seule, la fin de l'entrée, une autre réponse ou une faute de frappe gardent la racine. `demander` pose la
/// question et rend la réponse (la console ; une réponse écrite dans les tests).
fn decider_copie(
    copie: Result<std::path::PathBuf, crate::modele::Echec>,
    nom: &str,
    empreintes: &str,
    demander: impl FnOnce(&str) -> String,
) -> Option<String> {
    let r = match copie {
        Ok(c) => return Some(trf!("copie : {}", "copy: {}", c.display())),
        Err(r) => r,
    };
    // Un dossier Vanguard que `quarantaine` refuse (lien, autre propriétaire, écrit par d'autres comptes) : un autre
    // compte l'a préparé, c'est suspect en soi.
    let prepare = matches!(r.raison, crate::modele::raison::Raison::Refuse(_))
        && matches!(r.contexte, "quarantaine/droits" | "quarantaine/dossier");
    // Entière à l'écran (la cause de Windows vient en dernier), coupée seulement dans la note.
    let raison = crate::ui::affichable(&r.to_string());
    crate::ui::imprimer(&texte_sans_copie(&raison, prepare, nom, empreintes));
    let reponse = demander(tr!(
        "  Retirer cette racine sans copie, non annulable ? [o/N] : ",
        "  Remove this root without a copy, not undoable? [y/N]: "
    ));
    if !crate::langue::oui(&reponse) {
        return None;
    }
    let raison = crate::ui::couper(&raison, RAISON_NOTE_MAX);
    Some(trf!(
        "sans copie, non annulable, accepté ({raison})",
        "no copy, not undoable, accepted ({raison})"
    ))
}

/// Ce que la console dit avant la question : la copie manquée, le risque de garder la racine, et ce que le retrait
/// sans copie coûte.
fn texte_sans_copie(raison: &str, prepare: bool, nom: &str, empreintes: &str) -> String {
    let mut t = trf!(
        "  Copie .cer impossible ({raison}).",
        "  .cer copy not possible ({raison})."
    );
    if prepare {
        t.push(' ');
        t.push_str(tr!(
            "Ce dossier a été préparé par un autre compte que l'administrateur : c'est suspect en soi.",
            "This folder was prepared by an account other than the administrator: that is suspicious in itself."
        ));
    }
    t.push(' ');
    t.push_str(&trf!(
        "Le bilan juge la racine « {nom} » ({empreintes}) dangereuse : gardée, elle reste de confiance pour tout ce qu'elle signe. Retirée SANS COPIE, ce retrait est NON ANNULABLE : ni Vanguard ni vous ne pourrez la réimporter depuis une copie ; si vous acceptez, ses empreintes et son nom seront notés dans « Ce que Vanguard a changé ».",
        "The scan finds root “{nom}” ({empreintes}) dangerous: if kept, it stays trusted for everything it signs. Removed WITHOUT A COPY, this removal is NOT UNDOABLE: neither Vanguard nor you can import it again from a copy; if you accept, its thumbprints and name will be noted in “What Vanguard changed”."
    ));
    t
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

    /// La décision du retrait, sans crypt32 : copie faite, rien n'est demandé ; copie impossible, la question de plus
    /// dit « sans copie » et « non annulable », et seul un oui retire ; Entrée seule (la réponse par défaut, aussi
    /// celle de la fin de l'entrée), un non ou une faute de frappe gardent la racine (`None`).
    #[test]
    fn sans_copie_seul_un_oui_retire() {
        use crate::modele::Echec;
        let empreintes = format!("SHA-1 {}, SHA-256 {}", "ab".repeat(20), "cd".repeat(32));
        let faite = decider_copie(
            Ok(r"C:\ProgramData\Vanguard\quarantaine\r.cer".into()),
            "R",
            &empreintes,
            |q| panic!("question posée alors que la copie est faite : {q}"),
        );
        assert!(faite.is_some_and(|n| n.contains("r.cer")));
        let manquee = || Echec::echoue("quarantaine/deposer", "disque plein");
        for (reponse, retire) in [
            ("o", true),
            ("oui", true),
            ("y", true),
            ("YES", true),
            ("", false),
            ("n", false),
            ("non", false),
            ("annuler", false),
            ("ouii", false),
        ] {
            let mut posee = String::new();
            let note = decider_copie(Err(manquee()), "Racine Piégée", &empreintes, |q| {
                posee = q.to_string();
                reponse.to_string()
            });
            assert_eq!(note.is_some(), retire, "{reponse:?}");
            if let Some(n) = note {
                assert!(n.contains("non annulable") || n.contains("not undoable"), "{n}");
                assert!(n.contains("disque plein"), "{n}");
            }
            assert!(
                posee.contains("sans copie") || posee.contains("without a copy"),
                "{posee}"
            );
            assert!(
                posee.contains("non annulable") || posee.contains("not undoable"),
                "{posee}"
            );
        }
        assert!(garde_sans_copie().contains(".cer"));
    }

    /// Le texte avant la question : la raison entière, le risque de garder la racine, le coût du retrait, au futur ; un
    /// dossier de quarantaine préparé par un autre compte est dit suspect, une autre raison non.
    #[test]
    fn le_texte_dit_le_risque_et_le_dossier_prepare() {
        let longue = format!("{} (cause de Windows à la fin)", "x".repeat(200));
        let t = texte_sans_copie(&longue, false, "Racine", "SHA-1 ab");
        // Entière : rien n'est coupé à l'écran, même au-delà de la coupe de la note.
        assert!(t.contains(&longue), "{t}");
        assert!(t.contains("NON ANNULABLE") || t.contains("NOT UNDOABLE"), "{t}");
        assert!(t.contains("seront notés") || t.contains("will be noted"), "{t}");
        assert!(t.contains("de confiance") || t.contains("trusted"), "{t}");
        assert!(!t.contains("suspect"), "{t}");
        assert!(texte_sans_copie("refusé", true, "Racine", "SHA-1 ab").contains("suspect"));
    }

    /// Aucune ligne de la liste ne peut sauter la question : la grammaire n'a pas de « sans copie », ni comme verbe ni
    /// comme champ de plus ; seule la ligne exacte se relit, et elle mène à la question.
    #[test]
    fn aucune_ligne_ne_retire_sans_la_question() {
        use crate::machine::gestes::{CERTIFICAT_RETIRER, analyser_acte};
        let e = "ab".repeat(20);
        assert!(analyser_acte(&format!("{CERTIFICAT_RETIRER}lm {e}")).is_some());
        for forgee in [
            format!("{CERTIFICAT_RETIRER}lm {e} sans-copie"),
            format!("{CERTIFICAT_RETIRER}lm {e} oui"),
            format!("{CERTIFICAT_RETIRER}lm {e} "),
            format!("{CERTIFICAT_RETIRER}sans-copie lm {e}"),
            format!("vanguard:certificat-retirer-sans-copie lm {e}"),
            format!("vanguard:certificat-retirer-force cu {e}"),
        ] {
            assert!(analyser_acte(&forgee).is_none(), "{forgee}");
        }
    }

    /// La vraie crypt32 (Wine ici) : une empreinte qui n'existe pas n'est jamais trouvée, rien n'est retiré.
    #[test]
    fn empreinte_absente_introuvable() {
        if let Some(m) = Magasin::ouvrir(MagasinRacine::Ordinateur, true) {
            assert!(m.chercher(&[0x5A; 20]).is_null());
        }
    }
}
