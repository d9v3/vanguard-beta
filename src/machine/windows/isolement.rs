//! L'isolement de Windows (Défense R4), dans le processus élevé, par le pare-feu natif de R3 (INetFwPolicy2) :
//!
//! - des règles Block au nom de Vanguard (`isolement::PREFIXE_WINDOWS`, puis la lettre de leur génération), en sortie
//!   et en entrée, écrites par `isolement::regles_windows` : une règle Block n'a pas d'exception et l'emporte sur toute
//!   règle Allow, donc chaque groupe d'adresses reçoit le bloc de ce qui ne lui est pas permis (rien vers le reste du
//!   monde ; vers une session, tout sauf sa connexion TCP exacte ; vers les serveurs de Vanguard, tout sauf TCP 443 ;
//!   vers le DNS et DHCP, tout sauf leurs ports) ;
//! - « bloquer toutes les connexions entrantes » sur chaque profil, seulement sans session à distance (il couperait le
//!   Bureau à distance) ; un profil coupé est rallumé (sinon les règles n'y feraient rien), sauf si c'est un profil
//!   courant pendant une session : refusé ;
//! - refaire l'isolement pose la génération suivante, puis retire l'autre : un échec ne retire que ce qu'il venait de
//!   poser et remet les profils tels qu'ils étaient juste avant, jamais une protection déjà en place ;
//! - les valeurs d'avant de chaque profil (en marche, toutes les entrées bloquées) notées dans la description des
//!   règles, et remises exactement à la levée ; une description illisible laisse les profils tels quels (plus fermés,
//!   jamais plus ouverts) et le dit.

// FFI de COM (crate windows) : les règles et les profils du Pare-feu Windows (INetFwPolicy2, INetFwRule).
#![allow(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::IpAddr;

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_PROFILE_TYPE2,
    NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::BSTR;

use super::pare_feu::{booleen, dans_com, lecture, regles_com, retirer_toutes, trouver, vrai_faux};
use crate::modele::Echec;
use crate::protection::blocage::ordres::Resultat;
use crate::protection::isolement::{
    Avant, PROFILS, Permis, RegleWindows, generation, generation_suivante, regles_windows,
};
use crate::{tr, trf};

/// Le contexte des échecs de l'isolement, celui du pare-feu du blocage (`compte_rendu::champs::CONTEXTES_ECHEC`).
const OU: &str = "blocage/pare-feu";

/// Les serveurs DHCP des cartes en service (registre : Tcpip\Parameters\Interfaces\{GUID}\DhcpServer).
fn serveurs_dhcp() -> Vec<IpAddr> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let mut v: Vec<IpAddr> = crate::machine::windows::cartes::cartes()
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.active && !c.cachee)
        .filter_map(|c| {
            let cle = hklm
                .open_subkey(format!(
                    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
                    c.guid
                ))
                .ok()?;
            cle.get_value::<String, _>("DhcpServer").ok()?.trim().parse().ok()
        })
        .filter(|ip: &IpAddr| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback())
        .collect();
    v.sort_unstable();
    v.dedup();
    v.truncate(8);
    v
}

/// Les valeurs de chaque profil, relues ; `None` si l'une ne se lit pas.
fn lire_profils(p: &INetFwPolicy2) -> Option<Avant> {
    let mut v = [(false, false); 3];
    for (case, (bit, _)) in v.iter_mut().zip(PROFILS) {
        let profil = NET_FW_PROFILE_TYPE2(bit);
        // SAFETY: objet COM valide ; chaque lecture rend une copie.
        let (marche, entrees) = unsafe {
            (
                p.get_FirewallEnabled(profil).ok()?,
                p.get_BlockAllInboundTraffic(profil).ok()?,
            )
        };
        *case = (vrai_faux(marche)?, vrai_faux(entrees)?);
    }
    Some(Avant(v))
}

/// Écrit les valeurs de chaque profil (toutes les entrées bloquées d'abord, puis en marche), puis les relit.
fn ecrire_profils(p: &INetFwPolicy2, voulu: Avant) -> Result<(), Echec> {
    for ((bit, _), (marche, entrees)) in PROFILS.into_iter().zip(voulu.0) {
        let profil = NET_FW_PROFILE_TYPE2(bit);
        // SAFETY: objet COM valide ; une écriture refusée revient en erreur.
        unsafe {
            p.put_BlockAllInboundTraffic(profil, booleen(entrees))
                .and_then(|()| p.put_FirewallEnabled(profil, booleen(marche)))
        }
        .map_err(|e| Echec::echoue(OU, e.message()))?;
    }
    match lire_profils(p) {
        Some(relu) if relu == voulu => Ok(()),
        _ => Err(Echec::echoue(
            OU,
            tr!(
                "les profils du pare-feu relus ne sont pas ceux écrits",
                "the firewall profiles read back are not those written"
            ),
        )),
    }
}

/// La description des règles : qui les a posées, comment les retirer, et les valeurs d'avant.
fn description(avant: Avant) -> String {
    format!(
        "{} {}",
        tr!(
            "Posée par l'isolement de Vanguard ; se lève par « vanguard blocage annuler ».",
            "Added by Vanguard's isolation; lifted with “vanguard blocking undo”."
        ),
        avant.texte()
    )
}

fn creer(r: &INetFwRules, v: &RegleWindows, avant: Avant) -> windows::core::Result<()> {
    // SAFETY: COM est initialisé dans ce fil ; NetFwRule est la classe d'une règle. Chaque réglage reçoit un BSTR
    // vivant pendant l'appel. Le protocole avant les ports (documentation de INetFwRule).
    unsafe {
        let regle: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        regle.SetName(&BSTR::from(v.nom.as_str()))?;
        regle.SetDescription(&BSTR::from(description(avant)))?;
        regle.SetProtocol(v.protocole.numero())?;
        if let Some(p) = &v.ports_locaux {
            regle.SetLocalPorts(&BSTR::from(p.as_str()))?;
        }
        if let Some(p) = &v.ports_distants {
            regle.SetRemotePorts(&BSTR::from(p.as_str()))?;
        }
        regle.SetRemoteAddresses(&BSTR::from(v.distantes.as_str()))?;
        regle.SetDirection(if v.entree {
            NET_FW_RULE_DIR_IN
        } else {
            NET_FW_RULE_DIR_OUT
        })?;
        regle.SetAction(NET_FW_ACTION_BLOCK)?;
        regle.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        regle.SetEnabled(windows::Win32::Foundation::VARIANT_TRUE)?;
        r.Add(&regle)
    }
}

/// Des ports relus égaux à ceux écrits, aux espaces près.
fn memes_ports(lus: windows::core::Result<BSTR>, voulus: &str) -> bool {
    let sans = |t: &str| t.chars().filter(|c| !c.is_whitespace()).collect::<String>();
    lus.is_ok_and(|l| sans(&l.to_string()) == sans(voulus))
}

/// La règle relue est-elle celle de l'isolement : bloquer, active, sur tous les profils, dans le bon sens, du bon
/// protocole, avec ses ports, et des adresses distantes (jamais « * », qui viserait aussi ce qui est gardé) ?
fn conforme(r: &INetFwRules, v: &RegleWindows) -> bool {
    let Some(regle) = trouver(r, &v.nom) else {
        return false;
    };
    let sens = if v.entree {
        NET_FW_RULE_DIR_IN
    } else {
        NET_FW_RULE_DIR_OUT
    };
    // SAFETY: objet COM valide ; chaque lecture rend une copie.
    unsafe {
        regle.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK)
            && regle.Enabled().is_ok_and(|e| vrai_faux(e) == Some(true))
            && regle.Direction().is_ok_and(|d| d == sens)
            && regle.Profiles().is_ok_and(|p| p == NET_FW_PROFILE2_ALL.0)
            && regle.Protocol().is_ok_and(|p| p == v.protocole.numero())
            && v.ports_locaux
                .as_deref()
                .is_none_or(|p| memes_ports(regle.LocalPorts(), p))
            && v.ports_distants
                .as_deref()
                .is_none_or(|p| memes_ports(regle.RemotePorts(), p))
            && regle
                .RemoteAddresses()
                .is_ok_and(|a| !a.is_empty() && a.to_string().trim() != "*")
    }
}

/// Les noms des règles de l'isolement en place (toutes générations, et la forme d'une version d'avant), relus.
fn noms_en_place(r: &INetFwRules) -> windows::core::Result<Vec<String>> {
    let (lues, _) = regles_com(r)?;
    let mut v: Vec<String> = lues
        .into_iter()
        .map(|(l, _)| l.nom)
        .filter(|n| generation(n).is_some())
        .collect();
    v.sort_unstable();
    v.dedup();
    Ok(v)
}

/// Les valeurs d'avant notées dans une des règles de l'isolement en place, si l'une se lit.
fn avant_note(r: &INetFwRules, noms: &[String]) -> Option<Avant> {
    noms.iter().find_map(|nom| {
        let regle = trouver(r, nom)?;
        // SAFETY: objet COM valide ; la lecture rend une copie.
        unsafe { regle.Description() }
            .ok()
            .and_then(|d| Avant::lire(&d.to_string()))
    })
}

/// Retire les règles de l'isolement de ces noms, et vérifie qu'elles sont parties.
fn retirer_regles<'a>(r: &INetFwRules, noms: impl IntoIterator<Item = &'a str>) -> Result<(), Echec> {
    for nom in noms {
        retirer_toutes(r, nom).map_err(|e| Echec::echoue(OU, e.message()))?;
        if trouver(r, nom).is_some() {
            return Err(Echec::echoue(
                OU,
                trf!(
                    "la règle « {nom} » est toujours là après son retrait",
                    "the rule “{nom}” is still there after its removal"
                ),
            ));
        }
    }
    Ok(())
}

/// Isole (processus élevé) : `sessions`, le nombre de sessions à distance gardées. Pose la génération suivante des
/// règles, puis retire l'autre ; un échec ne retire que ce qu'il venait de poser et remet les profils tels qu'ils
/// étaient juste avant (B6 : jamais une protection déjà en place).
pub(crate) fn isoler(permis: &Permis, sessions: usize) -> Resultat {
    let dhcp = serveurs_dhcp();
    let permis = permis.clone();
    let (n_serveurs, n_dns, n_dhcp) = (permis.serveurs.len(), permis.dns.len(), dhcp.len());
    dans_com(move |p, r| {
        // SAFETY: objet COM valide ; la lecture rend une copie.
        let etat = unsafe { p.LocalPolicyModifyState() };
        if etat.is_err() || etat.is_ok_and(|e| e == NET_FW_MODIFY_STATE_GP_OVERRIDE) {
            return Resultat::echec(tr!(
                "une stratégie de groupe commande le pare-feu : des règles locales n'y feraient rien, rien n'est isolé",
                "a group policy controls the firewall: local rules would do nothing there, nothing is isolated"
            ));
        }
        let Ok(en_place) = noms_en_place(r) else {
            return Resultat::echec(tr!(
                "les règles du pare-feu ne se lisent pas : rien n'est changé",
                "the firewall rules cannot be read: nothing is changed"
            ));
        };
        let nouvelle = generation_suivante(en_place.iter().map(String::as_str));
        let Some(regles) = regles_windows(&permis, &dhcp, nouvelle) else {
            return Resultat::echec(tr!(
                "les règles de l'isolement n'ont pas pu être écrites : rien n'est changé",
                "the isolation rules could not be written: nothing is changed"
            ));
        };
        // Les profils de maintenant : ceux que remet un échec (jamais un « avant » qui ne serait plus vrai).
        let Some(maintenant) = lire_profils(p) else {
            return Resultat::echec(tr!(
                "les profils du pare-feu ne se lisent pas : rien n'est changé",
                "the firewall profiles cannot be read: nothing is changed"
            ));
        };
        // Les valeurs d'avant : celles notées par un isolement déjà en place (le refaire ne les perd pas), sinon
        // celles de maintenant.
        let avant = if en_place.is_empty() {
            maintenant
        } else {
            match avant_note(r, &en_place) {
                Some(a) => a,
                None => {
                    return Resultat::echec(tr!(
                        "un isolement est déjà en place mais ses valeurs d'avant ne se lisent pas : levez-le d'abord",
                        "an isolation is already in place but its previous values cannot be read: lift it first"
                    ));
                }
            }
        };
        // SAFETY: objet COM valide ; la lecture rend une copie.
        let courants = unsafe { p.CurrentProfileTypes() }.unwrap_or(7);
        let mut voulu = maintenant;
        for (case, (bit, _)) in voulu.0.iter_mut().zip(PROFILS) {
            if !case.0 && sessions > 0 && courants & bit != 0 {
                return Resultat::echec(tr!(
                    "le pare-feu est coupé sur le réseau actif pendant une session à distance : le rallumer pourrait la couper, rien n'est isolé",
                    "the firewall is off on the active network during a remote session: turning it on could cut it, nothing is isolated"
                ));
            }
            case.0 = true;
            // Toutes les entrées bloquées couperait le Bureau à distance : seulement sans session.
            if sessions == 0 {
                case.1 = true;
            }
        }
        // Des restes de la génération à poser (un essai interrompu) : retirés d'abord ; l'autre génération reste.
        let de_la_nouvelle: Vec<String> = en_place
            .iter()
            .filter(|n| generation(n) == Some(nouvelle))
            .cloned()
            .collect();
        if let Err(e) = retirer_regles(r, de_la_nouvelle.iter().map(String::as_str)) {
            return Resultat::echec(trf!("{e} ; rien n'est changé", "{e}; nothing is changed"));
        }
        let noms: Vec<String> = regles.iter().map(|v| v.nom.clone()).collect();
        let defaire = |p: &INetFwPolicy2, r: &INetFwRules| {
            let _ = retirer_regles(r, noms.iter().map(String::as_str));
            let _ = ecrire_profils(p, maintenant);
        };
        let reste = if en_place.is_empty() {
            tr!("rien n'est isolé", "nothing is isolated")
        } else {
            tr!(
                "l'isolement déjà en place reste tel quel",
                "the isolation already in place stays as it is"
            )
        };
        for v in &regles {
            if let Err(e) = creer(r, v, avant) {
                defaire(p, r);
                return Resultat::echec(trf!(
                    "règle refusée par le Pare-feu Windows : {} ; {reste}",
                    "rule refused by the Windows Firewall: {}; {reste}",
                    e.message()
                ));
            }
        }
        if let Err(e) = ecrire_profils(p, voulu) {
            defaire(p, r);
            return Resultat::echec(trf!("{e} ; {reste}", "{e}; {reste}"));
        }
        if !regles.iter().all(|v| conforme(r, v)) {
            defaire(p, r);
            return Resultat::echec(trf!(
                "les règles de l'isolement relues ne sont pas celles posées ; {reste}",
                "the isolation rules read back are not those set; {reste}"
            ));
        }
        let mut note = trf!(
            "{sessions} session(s) à distance, {n_serveurs} adresse(s) des serveurs de Vanguard, {n_dns} DNS, {n_dhcp} DHCP gardés",
            "{sessions} remote session(s), {n_serveurs} Vanguard server address(es), {n_dns} DNS, {n_dhcp} DHCP kept"
        );
        if sessions > 0 {
            note.push_str(tr!(
                " ; « bloquer toutes les connexions entrantes » laissé tel quel (session à distance)",
                "; “block all incoming connections” left as is (remote session)"
            ));
        }
        // L'autre génération, maintenant que la nouvelle est en place : un échec laisse les deux (plus fermé).
        let anciennes: Vec<&str> = en_place
            .iter()
            .map(String::as_str)
            .filter(|n| generation(n) != Some(nouvelle))
            .collect();
        if let Err(e) = retirer_regles(r, anciennes) {
            note.push_str(&trf!(
                " ; des règles de l'isolement d'avant restent ({e}) : la levée les retirera",
                "; rules of the previous isolation remain ({e}): lifting will remove them"
            ));
        }
        Resultat::ok_note(note)
    })
}

/// Lève (processus élevé) : les règles par leur marque, puis les valeurs d'avant notées.
pub(crate) fn lever() -> Resultat {
    dans_com(|p, r| {
        let Ok(noms) = noms_en_place(r) else {
            return Resultat::echec(tr!(
                "les règles du pare-feu ne se lisent pas : rien n'est levé",
                "the firewall rules cannot be read: nothing is lifted"
            ));
        };
        if noms.is_empty() {
            return Resultat::ok_note(tr!("aucun isolement en place", "no isolation in place"));
        }
        let avant = avant_note(r, &noms);
        if let Err(e) = retirer_regles(r, noms.iter().map(String::as_str)) {
            return Resultat::echec(e);
        }
        match avant {
            Some(a) => match ecrire_profils(p, a) {
                Ok(()) => Resultat::ok(),
                Err(e) => Resultat::echec(trf!(
                    "règles retirées, mais les profils d'avant ne sont pas remis : {e}",
                    "rules removed, but the previous profiles are not restored: {e}"
                )),
            },
            None => Resultat::ok_note(tr!(
                "règles retirées ; les valeurs d'avant ne se lisaient pas : les profils du pare-feu sont laissés tels quels (en marche, entrées bloquées), à régler dans les Options de défense",
                "rules removed; the previous values could not be read: the firewall profiles are left as they are (on, incoming blocked), to adjust in the Defense options"
            )),
        }
    })
}

/// Une règle de l'isolement est-elle là ?
pub(crate) fn en_place() -> bool {
    lecture(|_, r| noms_en_place(r).map(|n| !n.is_empty())).unwrap_or(false)
}
