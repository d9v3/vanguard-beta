//! Les réglages du registre de la défense D6b dans le processus élevé : `vanguard:reglage <mot>` et
//! `vanguard:reglage-remettre <mot>` (grammaire fermée de `gestes.rs`, table de `reglages`).
//!
//! Avant d'écrire, tout est relu ici : le bilan refait sur la lecture d'à l'instant doit proposer la ligne (garde A),
//! une stratégie ne se retire que sur un PC hors domaine et hors gestion (§3.3), l'Assistance à distance ne se coupe
//! jamais pendant une aide en cours (msra.exe, garde B) ; un réglage risqué demande un oui tapé dans la console
//! élevée (défaut non). L'écriture passe par `reglages::poser` (valeur d'avant notée sous ChoixAvant, relue, retour
//! arrière à la moindre erreur) ; la remise, par `reglages::remettre`, une baisse montrée puis confirmée.

use std::io::ErrorKind::NotFound;

use winreg::RegKey;
use winreg::enums::{
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, RegType,
};

use super::corrections::{Resultat, avant_notable};
use crate::machine::gestes::{self, Acte, IdReglage, Montre, Sens};
use crate::machine::reglages::{self, Brute, Issue, Registre, Ruche};
use crate::modele::Echec;
use crate::ui::{tr, trf, trp};

const CONTEXTE: &str = "reglages/ecriture";

/// Le registre de Windows : HKLM en vue 64 bits, et la ruche du compte de la personne (HKU\<SID>), qui doit être
/// chargée (jamais créée). Les notes vont sous HKLM `SOFTWARE\Vanguard\ChoixAvant`.
pub(super) struct Winreg {
    sid: Option<String>,
}

/// La racine du registre d'un compte (HKU\<SID>) : lire, et créer dessous une clé qui manque (RegCreateKeyEx exige
/// KEY_CREATE_SUB_KEY sur la clé parente) ; rien de plus, chaque sous-clé s'ouvre avec ses propres droits.
const ACCES_RACINE_COMPTE: u32 = KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY;

impl Winreg {
    pub(super) fn nouveau(sid: Option<&str>) -> Winreg {
        Winreg {
            sid: sid.filter(|s| reglages::sid_valide(s)).map(str::to_string),
        }
    }

    fn racine(&self, ruche: Ruche) -> Result<RegKey, Echec> {
        match ruche {
            Ruche::Machine => Ok(RegKey::predef(HKEY_LOCAL_MACHINE)),
            Ruche::Compte => {
                let sid = self.sid.as_deref().ok_or_else(|| {
                    Echec::refuse(
                        CONTEXTE,
                        tr!(
                            "le compte de la personne ne se lit pas",
                            "the person's account cannot be read"
                        ),
                    )
                })?;
                RegKey::predef(HKEY_USERS)
                    .open_subkey_with_flags(sid, ACCES_RACINE_COMPTE)
                    .map_err(|e| {
                        Echec::echoue(
                            CONTEXTE,
                            trf!(
                                "le registre du compte n'est pas chargé ({e})",
                                "the account's registry is not loaded ({e})"
                            ),
                        )
                    })
            }
        }
    }
}

/// Le type de winreg d'un code de `reglages::CODES`.
fn type_reg(code: u32) -> Option<RegType> {
    Some(match code {
        1 => RegType::REG_SZ,
        2 => RegType::REG_EXPAND_SZ,
        3 => RegType::REG_BINARY,
        4 => RegType::REG_DWORD,
        7 => RegType::REG_MULTI_SZ,
        11 => RegType::REG_QWORD,
        _ => return None,
    })
}

impl Registre for Winreg {
    fn lire(&mut self, ruche: Ruche, cle: &str, valeur: &str) -> Result<Option<Brute>, Echec> {
        let k = match self
            .racine(ruche)?
            .open_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_WOW64_64KEY)
        {
            Ok(k) => k,
            Err(e) if e.kind() == NotFound => return Ok(None),
            Err(e) => return Err(Echec::io(CONTEXTE, &e)),
        };
        match k.get_raw_value(valeur) {
            Ok(mut v) => {
                let b = Brute {
                    code: v.vtype as u32,
                    octets: v.bytes.to_vec(),
                };
                // Le tampon de winreg aussi : un mot de passe en clair peut y passer.
                v.bytes.to_mut().fill(0);
                std::hint::black_box(&v.bytes);
                Ok(Some(b))
            }
            Err(e) if e.kind() == NotFound => Ok(None),
            Err(e) => Err(Echec::io(CONTEXTE, &e)),
        }
    }

    fn ecrire(&mut self, ruche: Ruche, cle: &str, valeur: &str, b: &Brute) -> Result<(), Echec> {
        let vtype = type_reg(b.code)
            .ok_or_else(|| Echec::refuse(CONTEXTE, tr!("type de valeur inconnu", "unknown value type")))?;
        let (k, _) = self
            .racine(ruche)?
            .create_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
            .map_err(|e| Echec::ecriture(CONTEXTE, &e))?;
        k.set_raw_value(
            valeur,
            &winreg::RegValue {
                bytes: std::borrow::Cow::Borrowed(&b.octets),
                vtype,
            },
        )
        .map_err(|e| Echec::ecriture(CONTEXTE, &e))
    }

    fn effacer(&mut self, ruche: Ruche, cle: &str, valeur: &str) -> Result<(), Echec> {
        let k = match self
            .racine(ruche)?
            .open_subkey_with_flags(cle, KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY)
        {
            Ok(k) => k,
            Err(e) if e.kind() == NotFound => return Ok(()),
            Err(e) => return Err(Echec::io(CONTEXTE, &e)),
        };
        match k.delete_value(valeur) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == NotFound => Ok(()),
            Err(e) => Err(Echec::ecriture(CONTEXTE, &e)),
        }
    }

    fn lire_note(&mut self, nom: &str) -> Option<Vec<u8>> {
        crate::machine::choix_avant::lire_brut(nom)
    }

    fn ecrire_note(&mut self, nom: &str, octets: &[u8]) -> Result<(), Echec> {
        crate::machine::choix_avant::ecrire_brut(nom, octets)
    }

    fn effacer_note(&mut self, nom: &str) {
        crate::machine::choix_avant::effacer_brut(nom);
    }
}

/// Ce qu'une remise va écrire, montré avant la question des baisses ; `None` pour ce qui n'est pas une remise de
/// réglage ou de chemin de service.
pub(super) fn juger(acte: &Acte, personne: Option<&str>) -> Option<(Montre, String)> {
    let texte = match acte {
        Acte::ReglageRemettre(id) => {
            let nom = super::corrections::nom_reglage(*id);
            let note = reglages::nom_note(*id, personne)
                .and_then(|n| reglages::texte_note(&mut Winreg::nouveau(personne), *id, &n));
            match note {
                Some(t) => trf!(
                    "{nom} : REMIS COMME AVANT ({})",
                    "{nom}: PUT BACK AS BEFORE ({})",
                    crate::ui::affichable(&t)
                ),
                None => trf!(
                    "{nom} : aucune valeur d'avant notée, rien ne sera écrit",
                    "{nom}: no previous value noted, nothing will be written"
                ),
            }
        }
        Acte::ServiceCheminRemettre(n) => super::services::texte_remise(n),
        // Les remises SSH (défense D6c), montrées comme une baisse : jamais déclenchées par une liste mêlée.
        _ => return super::ssh_ecriture::juger(acte, personne),
    };
    Some((
        Montre {
            sens: Sens::Baisse,
            lue: None,
        },
        texte,
    ))
}

/// Une session à distance est-elle ouverte (`None` : les connexions ne se lisent pas) ? Celle de ce processus
/// (Bureau à distance), puis toute connexion de session relue (Bureau à distance, SSH, WinRM).
pub(super) fn session_ouverte() -> Option<bool> {
    if super::session_a_distance() {
        return Some(true);
    }
    crate::protection::blocage::session_a_distance()
}

/// msra.exe tourne-t-il ? `None` : la liste des programmes ne se lit pas (jamais vide sur un Windows qui tourne).
fn msra_tourne() -> Option<bool> {
    let liste = super::processus::liste();
    (!liste.is_empty()).then(|| liste.iter().any(|p| p.nom.eq_ignore_ascii_case("msra")))
}

/// Pourquoi l'ouverture automatique de session reste (garde B, `gestes::refus_ouverture_auto`).
fn raison_ouverture_auto(r: &gestes::RefusOuvertureAuto) -> String {
    match r {
        gestes::RefusOuvertureAuto::Illisible => tr!(
            "les programmes ouverts ne se lisent pas : un outil d'accès à distance pourrait ne revenir qu'avec l'ouverture automatique de session ; rien d'écrit",
            "open programs cannot be read: a remote access tool might only come back with automatic sign-in; nothing written"
        )
        .to_string(),
        gestes::RefusOuvertureAuto::Outil(nom) => trf!(
            "« {} » (accès à distance, prise en main ou VPN) tourne dans une session ouverte et non en service : après un redémarrage, il ne reviendrait qu'avec l'ouverture automatique de session ; installez-le en service, ou coupez-la à la main (netplwiz) ; rien d'écrit",
            "“{}” (remote access, remote control or VPN) runs in a signed-in session, not as a service: after a restart it would only come back with automatic sign-in; install it as a service, or turn it off by hand (netplwiz); nothing written",
            crate::ui::affichable(nom)
        ),
    }
}

fn refus(fr: &str, en: &str) -> Resultat {
    Resultat::echec(None, if crate::langue::anglais() { en } else { fr }.to_string())
}

/// Met le réglage `id` à sa valeur sûre ; `personne` : le SID de la personne (réglages de son compte).
pub(super) fn poser(id: IdReglage, personne: Option<&str>) -> Resultat {
    let Some(nom) = reglages::nom_note(id, personne) else {
        return refus(
            "le compte de la personne ne se lit pas : rien d'écrit",
            "the person's account cannot be read: nothing written",
        );
    };
    let mut r = Winreg::nouveau(personne);
    if let Some(avant) = reglages::deja(&mut r, id) {
        return Resultat::rien(trf!(
            "déjà ainsi ({}), rien d'écrit",
            "already so ({}), nothing written",
            avant_notable(&avant)
        ));
    }
    if id.strategie() && !super::defense_etat::hors_gestion() {
        return refus(
            "PC dans un domaine, géré, ou dont la gestion ne se lit pas : la stratégie reste ; rien d'écrit",
            "PC in a domain, managed, or whose management cannot be read: the policy stays; nothing written",
        );
    }
    if !super::durcissement::rejuger_reglage(id, personne) {
        return refus(
            "le bilan refait ici ne propose pas ce réglage : rien d'écrit",
            "the check redone here does not offer this setting: nothing written",
        );
    }
    if id == IdReglage::AssistanceCoupe && gestes::refus_assistance(msra_tourne()) {
        return refus(
            "une assistance à distance est en cours (msra.exe), ou les programmes ne se lisent pas : Vanguard ne coupe jamais une session à distance ; rien d'écrit",
            "a remote assistance is in progress (msra.exe), or programs cannot be read: Vanguard never cuts a remote session; nothing written",
        );
    }
    if matches!(id, IdReglage::OuvertureAutoMdp | IdReglage::OuvertureAutoCoupe)
        && let Some(raison) = gestes::refus_ouverture_auto(
            super::comptes_ecriture::programmes_par_session().as_deref(),
            crate::protection::blocage::gardes::programme_de_session,
        )
    {
        return Resultat::echec(None, raison_ouverture_auto(&raison));
    }
    if let Some(q) = reglages::question(id)
        && !reglages::confirmer(super::eleve::console_reelle(), q, crate::ui::demander_ou_defaut)
    {
        return refus("non confirmé : rien d'écrit", "not confirmed: nothing written");
    }
    let issue = reglages::poser(&mut r, id, &nom);
    if matches!(issue, Issue::Fait { .. }) && id.redemarrage() {
        trp!(
            "  Effet au prochain redémarrage de Windows (Vanguard ne redémarre jamais l'ordinateur).",
            "  Takes effect at the next Windows restart (Vanguard never restarts the computer)."
        );
    }
    resultat(issue)
}

/// Remet ce qu'un réglage a noté (une baisse, déjà montrée et confirmée).
pub(super) fn remettre(id: IdReglage, personne: Option<&str>) -> Resultat {
    let Some(nom) = reglages::nom_note(id, personne) else {
        return refus(
            "le compte de la personne ne se lit pas : rien d'écrit",
            "the person's account cannot be read: nothing written",
        );
    };
    let issue = reglages::remettre(&mut Winreg::nouveau(personne), id, &nom);
    if matches!(issue, Issue::Fait { .. }) && id.redemarrage() {
        trp!(
            "  Effet au prochain redémarrage de Windows.",
            "  Takes effect at the next Windows restart."
        );
    }
    resultat(issue)
}

fn resultat(issue: Issue) -> Resultat {
    match issue {
        Issue::Fait { avant } => Resultat::fait(avant_notable(&avant)),
        Issue::Rien(avant) => Resultat::rien(trf!(
            "déjà ainsi ({}), rien d'écrit",
            "already so ({}), nothing written",
            avant_notable(&avant)
        )),
        Issue::Echec { avant, raison } => Resultat::echec(avant.as_deref().map(avant_notable), raison),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La racine du compte permet de créer une clé qui manque dessous, sans droit d'écrire ni d'effacer à la racine.
    #[test]
    fn acces_de_la_racine_du_compte() {
        use winreg::enums::KEY_ALL_ACCESS;
        /// DELETE et WRITE_DAC de winnt.h.
        const DELETE: u32 = 0x0001_0000;
        const WRITE_DAC: u32 = 0x0004_0000;
        assert_eq!(ACCES_RACINE_COMPTE & KEY_CREATE_SUB_KEY, KEY_CREATE_SUB_KEY);
        assert_eq!(ACCES_RACINE_COMPTE & KEY_QUERY_VALUE, KEY_QUERY_VALUE);
        assert_eq!(ACCES_RACINE_COMPTE & (KEY_SET_VALUE | DELETE | WRITE_DAC), 0);
        assert_ne!(ACCES_RACINE_COMPTE, KEY_ALL_ACCESS);
    }
}
