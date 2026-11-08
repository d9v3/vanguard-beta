//! L'isolement de Windows (Défense R4), dans le processus élevé, par le pare-feu natif de R3 (INetFwPolicy2) :
//!
//! - quatre règles Block au nom de Vanguard (`isolement::NOMS_WINDOWS`), en sortie et en entrée : tout sauf ce qui est
//!   gardé (sessions à distance, serveurs de Vanguard), le DNS, les serveurs DHCP et ce qui n'est jamais bloqué
//!   (`isolement::toujours_permises`), écrit en plages complémentaires (une règle Block n'a pas d'exception, et elle
//!   l'emporte sur toute règle Allow) ; puis TCP vers le lien local, le DNS et les serveurs DHCP, sauf le port 53 ;
//! - « bloquer toutes les connexions entrantes » sur chaque profil, seulement sans session à distance (il couperait le
//!   Bureau à distance) ; un profil coupé est rallumé (sinon les règles n'y feraient rien), sauf si c'est un profil
//!   courant pendant une session : refusé ;
//! - les valeurs d'avant de chaque profil (en marche, toutes les entrées bloquées) notées dans la description des
//!   règles, et remises exactement à la levée ; une description illisible laisse les profils tels quels (plus fermés,
//!   jamais plus ouverts) et le dit.

// FFI de COM (crate windows) : les règles et les profils du Pare-feu Windows (INetFwPolicy2, INetFwRule).
#![allow(unsafe_code)]
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::net::IpAddr;

use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP,
    NET_FW_MODIFY_STATE_GP_OVERRIDE, NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN,
    NET_FW_RULE_DIR_OUT, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::BSTR;

use super::pare_feu::{booleen, dans_com, lecture, retirer_toutes, trouver, vrai_faux};
use crate::modele::Echec;
use crate::protection::blocage::ordres::Resultat;
use crate::protection::isolement::{
    Avant, NOMS_WINDOWS, PROFILS, Permis, RegleWindows, TCP_LOCAL_PORTS, regles_windows,
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
        regle.SetName(&BSTR::from(v.nom))?;
        regle.SetDescription(&BSTR::from(description(avant)))?;
        if v.tcp {
            regle.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
            regle.SetRemotePorts(&BSTR::from(TCP_LOCAL_PORTS))?;
        } else {
            regle.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)?;
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

/// La règle relue est-elle celle de l'isolement : bloquer, active, sur tous les profils, dans le bon sens, avec des
/// adresses distantes (jamais « * », qui viserait aussi ce qui est gardé) ?
fn conforme(r: &INetFwRules, v: &RegleWindows) -> bool {
    let Some(regle) = trouver(r, v.nom) else {
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
            && regle
                .RemoteAddresses()
                .is_ok_and(|a| !a.is_empty() && a.to_string().trim() != "*")
    }
}

/// Les valeurs d'avant notées dans une des règles de l'isolement, si l'une est là et se lit.
fn avant_note(r: &INetFwRules) -> (bool, Option<Avant>) {
    let mut presente = false;
    for nom in NOMS_WINDOWS {
        if let Some(regle) = trouver(r, nom) {
            presente = true;
            // SAFETY: objet COM valide ; la lecture rend une copie.
            if let Some(a) = unsafe { regle.Description() }
                .ok()
                .and_then(|d| Avant::lire(&d.to_string()))
            {
                return (true, Some(a));
            }
        }
    }
    (presente, None)
}

fn retirer_regles(r: &INetFwRules) -> Result<(), Echec> {
    for nom in NOMS_WINDOWS {
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

/// Isole (processus élevé) : `sessions`, le nombre de sessions à distance en cours, relu par l'appelant.
pub(crate) fn isoler(permis: &Permis, sessions: usize) -> Resultat {
    let dhcp = serveurs_dhcp();
    let Some(regles) = regles_windows(permis, &dhcp) else {
        return Resultat::echec(tr!(
            "les règles de l'isolement n'ont pas pu être écrites : rien n'est isolé",
            "the isolation rules could not be written: nothing is isolated"
        ));
    };
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
        // Les valeurs d'avant : celles notées par un isolement déjà en place (le refaire ne les perd pas), sinon
        // celles de maintenant.
        let avant = match avant_note(r) {
            (_, Some(a)) => a,
            (true, None) => {
                return Resultat::echec(tr!(
                    "un isolement est déjà en place mais ses valeurs d'avant ne se lisent pas : levez-le d'abord",
                    "an isolation is already in place but its previous values cannot be read: lift it first"
                ));
            }
            (false, None) => match lire_profils(p) {
                Some(a) => a,
                None => {
                    return Resultat::echec(tr!(
                        "les profils du pare-feu ne se lisent pas : rien n'est isolé",
                        "the firewall profiles cannot be read: nothing is isolated"
                    ));
                }
            },
        };
        // SAFETY: objet COM valide ; la lecture rend une copie.
        let courants = unsafe { p.CurrentProfileTypes() }.unwrap_or(7);
        let maintenant = lire_profils(p).unwrap_or(avant);
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
        if let Err(e) = retirer_regles(r) {
            return Resultat::echec(e);
        }
        let annuler = |p: &INetFwPolicy2, r: &INetFwRules| {
            let _ = retirer_regles(r);
            let _ = ecrire_profils(p, avant);
        };
        for v in &regles {
            if let Err(e) = creer(r, v, avant) {
                annuler(p, r);
                return Resultat::echec(trf!(
                    "règle refusée par le Pare-feu Windows : {} ; rien n'est isolé",
                    "rule refused by the Windows Firewall: {}; nothing is isolated",
                    e.message()
                ));
            }
        }
        if let Err(e) = ecrire_profils(p, voulu) {
            annuler(p, r);
            return Resultat::echec(trf!("{e} ; rien n'est isolé", "{e}; nothing is isolated"));
        }
        if !regles.iter().all(|v| conforme(r, v)) {
            annuler(p, r);
            return Resultat::echec(tr!(
                "les règles de l'isolement relues ne sont pas celles posées : rien n'est compté comme isolé",
                "the isolation rules read back are not those set: nothing is counted as isolated"
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
        Resultat::ok_note(note)
    })
}

/// Lève (processus élevé) : les règles par leur nom, puis les valeurs d'avant notées.
pub(crate) fn lever() -> Resultat {
    dans_com(|p, r| {
        let (presente, avant) = avant_note(r);
        if !presente {
            return Resultat::ok_note(tr!("aucun isolement en place", "no isolation in place"));
        }
        if let Err(e) = retirer_regles(r) {
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
    lecture(|_, r| Ok(NOMS_WINDOWS.iter().any(|n| trouver(r, n).is_some()))).unwrap_or(false)
}
