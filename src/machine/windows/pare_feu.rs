//! Les règles de blocage dans le Pare-feu Windows, par son interface COM (INetFwPolicy2::Rules, INetFwRules::Add,
//! Remove, Item), dans le processus élevé : plus de New-NetFirewallRule ni de fenêtre PowerShell. Les noms sont ceux
//! que posaient les versions d'avant (Name de COM = DisplayName de NetSecurity), si bien qu'une règle posée par elles
//! se retire ici et que le bilan (« Vanguard : bloquer <port> ») la reconnaît toujours. Le nom d'une règle ne doit
//! contenir ni « | » ni être « all » (documentation de INetFwRule) : les nôtres sont faits d'une adresse ou d'un
//! port analysés. Après chaque geste, la règle est relue.

// FFI de COM (crate windows) : INetFwPolicy2, les règles du Pare-feu Windows.
#![allow(unsafe_code)]

use std::net::IpAddr;

use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION_BLOCK, NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP,
    NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_ALL, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION,
    NetFwPolicy2, NetFwRule,
};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::BSTR;

use crate::protection::blocage::ordres::Resultat;
use crate::{tr, trf};

/// Le nom de la règle sortante vers une adresse (celui des versions d'avant).
pub(crate) fn nom_sortante(ip: IpAddr) -> String {
    format!("Vanguard : bloquer vers {}", ip.to_canonical())
}

/// Le nom de la règle qui ferme un port (celui que le bilan reconnaît).
pub(crate) fn nom_entrante(port: u16) -> String {
    format!("Vanguard : bloquer {port}")
}

/// Une règle voulue : son nom, son sens, et ce qu'elle vise.
struct Voulue {
    nom: String,
    sens: NET_FW_RULE_DIRECTION,
    /// Une adresse distante (sortante), ou un port local TCP (entrante).
    adresse: Option<IpAddr>,
    port: Option<u16>,
}

fn politique() -> windows::core::Result<INetFwPolicy2> {
    // SAFETY: COM est initialisé dans ce fil (`wmi::com_delai`) ; NetFwPolicy2 est la classe de la politique.
    unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
}

/// Le Pare-feu Windows est-il en marche pour chaque profil actif (domaine, privé, public) ? Coupé, une règle posée
/// ne bloquerait rien : ce serait un faux « bloqué ».
fn en_marche(p: &INetFwPolicy2) -> bool {
    // SAFETY: objet COM valide ; chaque lecture rend une copie.
    unsafe {
        let Ok(actifs) = p.CurrentProfileTypes() else {
            return false;
        };
        [1, 2, 4].into_iter().filter(|bit| actifs & bit != 0).all(|bit| {
            p.get_FirewallEnabled(NET_FW_PROFILE_TYPE2(bit))
                .is_ok_and(|e| e == VARIANT_TRUE)
        }) && actifs & 7 != 0
    }
}

/// La règle de ce nom, si elle existe.
fn trouver(r: &INetFwRules, nom: &str) -> Option<INetFwRule> {
    // SAFETY: objet COM valide ; BSTR vivant pendant l'appel. Une erreur (règle absente) se défait dans ce fil.
    unsafe { r.Item(&BSTR::from(nom)) }.ok()
}

/// La règle existante est-elle exactement celle de Vanguard (bloquer, active, dans le bon sens, sur ce qu'elle vise) ?
/// Une règle du même nom qui autoriserait, ou serait coupée, n'en est pas une : elle est remplacée.
fn conforme(regle: &INetFwRule, v: &Voulue) -> bool {
    // SAFETY: objet COM valide ; chaque lecture rend une copie.
    unsafe {
        let bloque = regle.Action().is_ok_and(|a| a == NET_FW_ACTION_BLOCK);
        let active = regle.Enabled().is_ok_and(|e| e == VARIANT_TRUE);
        let sens = regle.Direction().is_ok_and(|d| d == v.sens);
        // Partout : tous les profils, aucune restriction d'adresse locale ni de port distant.
        let tout = |b: windows::core::Result<BSTR>| b.is_ok_and(|b| b == "*" || b.is_empty());
        let partout = regle.Profiles().is_ok_and(|p| p == NET_FW_PROFILE2_ALL.0)
            && tout(regle.LocalAddresses())
            && tout(regle.RemotePorts());
        let vise = partout
            && match (v.adresse, v.port) {
                (Some(ip), _) => {
                    regle.Protocol().is_ok_and(|x| x == NET_FW_IP_PROTOCOL_ANY.0)
                        && regle.RemoteAddresses().is_ok_and(|a| adresse_visee(&a.to_string(), ip))
                }
                (None, Some(p)) => {
                    regle.Protocol().is_ok_and(|x| x == NET_FW_IP_PROTOCOL_TCP.0)
                        && regle.LocalPorts().is_ok_and(|l| l == p.to_string().as_str())
                }
                (None, None) => false,
            };
        bloque && active && sens && vise
    }
}

/// RemoteAddresses relu (« 203.0.113.7/255.255.255.255 », ou l'adresse seule) désigne-t-il cette adresse, et elle
/// seule ?
fn adresse_visee(relu: &str, ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    let seule = match ip {
        IpAddr::V4(_) => "/255.255.255.255",
        IpAddr::V6(_) => "/128",
    };
    let a = relu.trim();
    a.strip_suffix(seule)
        .unwrap_or(a)
        .parse::<IpAddr>()
        .is_ok_and(|lu| lu.to_canonical() == ip)
}

fn creer(r: &INetFwRules, v: &Voulue) -> windows::core::Result<()> {
    // SAFETY: COM est initialisé dans ce fil ; NetFwRule est la classe d'une règle. Chaque réglage reçoit un BSTR
    // vivant pendant l'appel. L'ordre compte (documentation de INetFwRule) : le protocole avant le port.
    unsafe {
        let regle: INetFwRule = CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER)?;
        regle.SetName(&BSTR::from(v.nom.as_str()))?;
        regle.SetDescription(&BSTR::from(tr!(
            "Posée par le blocage de Vanguard ; se retire par « vanguard blocage annuler »",
            "Added by Vanguard's blocking; removed with “vanguard blocking undo”"
        )))?;
        match (v.adresse, v.port) {
            (Some(ip), _) => {
                regle.SetProtocol(NET_FW_IP_PROTOCOL_ANY.0)?;
                regle.SetRemoteAddresses(&BSTR::from(ip.to_canonical().to_string()))?;
            }
            (None, Some(p)) => {
                regle.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
                regle.SetLocalPorts(&BSTR::from(p.to_string()))?;
            }
            (None, None) => return Err(windows::core::Error::from(windows::Win32::Foundation::E_INVALIDARG)),
        }
        regle.SetDirection(v.sens)?;
        regle.SetAction(NET_FW_ACTION_BLOCK)?;
        regle.SetProfiles(NET_FW_PROFILE2_ALL.0)?;
        regle.SetEnabled(VARIANT_TRUE)?;
        r.Add(&regle)
    }
}

/// Retire toutes les règles de ce nom (des doublons laissés par une version d'avant : Remove n'en retire qu'une par
/// appel), 16 au plus ; `Ok(n)` : combien.
fn retirer_toutes(r: &INetFwRules, nom: &str) -> windows::core::Result<usize> {
    let mut n = 0;
    while trouver(r, nom).is_some() && n < 16 {
        // SAFETY: objet COM valide ; BSTR vivant pendant l'appel.
        unsafe { r.Remove(&BSTR::from(nom)) }?;
        n += 1;
    }
    Ok(n)
}

/// Dans un fil COM à part, avec un délai : le Pare-feu Windows qui ne répond pas ne fige pas le processus élevé.
fn dans_com(geste: impl FnOnce(&INetFwPolicy2, &INetFwRules) -> Resultat + Send + 'static) -> Resultat {
    let r = super::wmi::com_delai(
        "Pare-feu Windows",
        "INetFwPolicy2",
        std::time::Duration::from_secs(60),
        move || {
            // Une erreur de COM se dit en texte ici, dans son appartement (voir `wmi::dans_un_fil`).
            Ok(
                match politique().and_then(|p| {
                    // SAFETY: objet COM valide.
                    let r = unsafe { p.Rules() }?;
                    Ok((p, r))
                }) {
                    Ok((p, r)) => geste(&p, &r),
                    Err(e) => Resultat::echec(trf!(
                        "Pare-feu Windows injoignable : {}",
                        "Windows Firewall unreachable: {}",
                        e.message()
                    )),
                },
            )
        },
    );
    r.unwrap_or_else(|| {
        Resultat::echec(tr!(
            "le Pare-feu Windows n'a pas répondu dans la minute",
            "the Windows Firewall did not answer within a minute"
        ))
    })
}

fn poser(v: Voulue) -> Resultat {
    dans_com(move |p, r| {
        if !en_marche(p) {
            return Resultat::echec(tr!(
                "le Pare-feu Windows est coupé pour le réseau actif : une règle n'y bloquerait rien, aucune n'est posée",
                "the Windows Firewall is off for the active network: a rule would block nothing there, none is added"
            ));
        }
        if let Some(existante) = trouver(r, &v.nom) {
            if conforme(&existante, &v) {
                return Resultat::ok_note(tr!("règle déjà en place", "rule already in place"));
            }
            if let Err(e) = retirer_toutes(r, &v.nom) {
                return Resultat::echec(e.message());
            }
        }
        if let Err(e) = creer(r, &v) {
            return Resultat::echec(trf!(
                "règle refusée par le Pare-feu Windows : {}",
                "rule refused by the Windows Firewall: {}",
                e.message()
            ));
        }
        match trouver(r, &v.nom) {
            Some(relue) if conforme(&relue, &v) => Resultat::ok(),
            _ => {
                // Comptée en échec, donc sans note pour l'annuler : retirée aussitôt.
                let _ = retirer_toutes(r, &v.nom);
                Resultat::echec(tr!(
                    "la règle relue n'est pas celle posée : rien n'est compté comme bloqué",
                    "the rule read back is not the one added: nothing is counted as blocked"
                ))
            }
        }
    })
}

fn enlever(nom: String) -> Resultat {
    dans_com(move |_, r| match retirer_toutes(r, &nom) {
        Ok(_) if trouver(r, &nom).is_some() => Resultat::echec(tr!(
            "la règle est toujours là après son retrait",
            "the rule is still there after its removal"
        )),
        Ok(0) => Resultat::ok_note(tr!("déjà retirée", "already removed")),
        Ok(_) => Resultat::ok(),
        Err(e) => Resultat::echec(e.message()),
    })
}

pub(crate) fn bloquer_sortie(ip: IpAddr) -> Resultat {
    poser(Voulue {
        nom: nom_sortante(ip),
        sens: NET_FW_RULE_DIR_OUT,
        adresse: Some(ip.to_canonical()),
        port: None,
    })
}

pub(crate) fn debloquer_sortie(ip: IpAddr) -> Resultat {
    enlever(nom_sortante(ip))
}

pub(crate) fn fermer_port(port: u16) -> Resultat {
    poser(Voulue {
        nom: nom_entrante(port),
        sens: NET_FW_RULE_DIR_IN,
        adresse: None,
        port: Some(port),
    })
}

pub(crate) fn rouvrir_port(port: u16) -> Resultat {
    enlever(nom_entrante(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_et_adresses_relues() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(nom_sortante(ip), "Vanguard : bloquer vers 203.0.113.7");
        assert_eq!(nom_sortante("::ffff:203.0.113.7".parse().unwrap()), nom_sortante(ip));
        assert_eq!(nom_entrante(8188), "Vanguard : bloquer 8188");
        // Le nom de la règle de port est celui que lit le bilan.
        assert_eq!(
            crate::machine::windows::ecoute::port_bloque(&format!(
                "v2.32|Action=Block|Active=TRUE|Dir=In|Protocol=6|LPort=8188|Name={}|",
                nom_entrante(8188)
            )),
            Some(8188)
        );
        assert!(adresse_visee("203.0.113.7/255.255.255.255", ip));
        assert!(adresse_visee("203.0.113.7", ip));
        assert!(!adresse_visee("203.0.113.0/255.255.255.0", ip));
        assert!(!adresse_visee("*", ip));
        assert!(adresse_visee("2001:db8::7/128", "2001:db8::7".parse().unwrap()));
        assert!(!nom_sortante(ip).contains('|'));
    }
}
