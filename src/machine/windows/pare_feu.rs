//! Les règles de blocage dans le Pare-feu Windows, par son interface COM (INetFwPolicy2::Rules, INetFwRules::Add,
//! Remove, Item), dans le processus élevé : plus de New-NetFirewallRule ni de fenêtre PowerShell. Les noms sont ceux
//! que posaient les versions d'avant (Name de COM = DisplayName de NetSecurity), si bien qu'une règle posée par elles
//! se retire ici et que le bilan (« Vanguard : bloquer <port> ») la reconnaît toujours. Le nom d'une règle ne doit
//! contenir ni « | » ni être « all » (documentation de INetFwRule) : les nôtres sont faits d'une adresse ou d'un
//! port analysés. Après chaque geste, la règle est relue.
//!
//! Aussi les actes du pare-feu et des réseaux (`gestes::Acte`) : le pare-feu remis en marche sur ses trois profils,
//! le profil Public réglé (INetFwPolicy2 écrit le magasin local, celui que `-PolicyStore PersistentStore` lit et
//! écrit), et la catégorie d'un réseau (INetworkListManager, comme Set-NetConnectionProfile ; le registre en repli,
//! comme avant). Chaque valeur est relue après avoir été écrite.

// FFI de COM (crate windows) : INetFwPolicy2, les règles et les profils du Pare-feu Windows ; INetworkListManager,
// la catégorie des réseaux.
#![allow(unsafe_code)]

use std::net::IpAddr;

use windows::Win32::Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE};
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule, INetFwRules, NET_FW_ACTION, NET_FW_ACTION_ALLOW, NET_FW_ACTION_BLOCK,
    NET_FW_IP_PROTOCOL_ANY, NET_FW_IP_PROTOCOL_TCP, NET_FW_PROFILE_TYPE2, NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN,
    NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC, NET_FW_RULE_DIR_IN, NET_FW_RULE_DIR_OUT, NET_FW_RULE_DIRECTION,
    NetFwPolicy2, NetFwRule,
};
use windows::Win32::Networking::NetworkListManager::{
    INetworkListManager, NLM_NETWORK_CATEGORY, NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED, NetworkListManager,
};
use windows::Win32::System::Com::{CLSCTX_ALL, CLSCTX_INPROC_SERVER, CoCreateInstance};
use windows::core::BSTR;

use crate::machine::gestes::{Acte, ProfilPublic, ReglagePublic, ReseauCategorie, ValeurPublic};

use crate::protection::blocage::ordres::Resultat;
use crate::{tr, trf};

// Les noms sont partagés avec l'équivalent PowerShell et le bilan : une seule fonction pour chacun.
pub(crate) use crate::protection::blocage::pare_feu::{nom_entrante, nom_sortante};

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

// ------------------------------------------------------------- les actes

/// Le magasin local du profil Public (celui de `-PolicyStore PersistentStore`), sous HKLM.
const MAGASIN_PUBLIC: &str = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile";
/// La valeur qu'y écrit BlockAllInboundTraffic (AllowInboundRules de NetSecurity, inversé) : absente, « non
/// configuré ».
const BLOQUER_TOUTES_LES_ENTREES: &str = "DoNotAllowExceptions";

/// Le geste d'un acte du pare-feu ou d'un réseau ; `None` : l'acte n'en est pas un.
pub(crate) fn faire_acte(acte: &Acte) -> Option<Resultat> {
    match acte {
        Acte::PareFeuActif => Some(pare_feu_actif()),
        Acte::PareFeuPublic(p) => Some(profil_public(*p)),
        Acte::ReseauCategorie(r) => Some(categorie(*r)),
        Acte::Service(_) | Acte::Vider(_) | Acte::ViderFileImpression | Acte::MettreDeCote(_) => None,
    }
}

/// Le profil est-il allumé, relu ?
fn allume(p: &INetFwPolicy2, profil: NET_FW_PROFILE_TYPE2) -> bool {
    // SAFETY: objet COM valide ; la lecture rend une copie.
    unsafe { p.get_FirewallEnabled(profil) }.is_ok_and(|e| e == VARIANT_TRUE)
}

/// Le pare-feu en marche sur les trois profils, chacun relu. Une stratégie de groupe peut encore le couper : la
/// valeur locale est celle-ci, l'effet est celui que relira le bilan.
fn pare_feu_actif() -> Resultat {
    dans_com(|p, _| {
        let profils = [
            (NET_FW_PROFILE2_DOMAIN, tr!("domaine", "domain")),
            (NET_FW_PROFILE2_PRIVATE, tr!("privé", "private")),
            (NET_FW_PROFILE2_PUBLIC, tr!("public", "public")),
        ];
        let mut rallumes = Vec::new();
        for (profil, nom) in profils {
            if allume(p, profil) {
                continue;
            }
            // SAFETY: objet COM valide ; un profil et une valeur constants.
            if let Err(e) = unsafe { p.put_FirewallEnabled(profil, VARIANT_TRUE) } {
                return Resultat::echec(trf!(
                    "profil {nom} : refusé par le Pare-feu Windows ({})",
                    "{nom} profile: refused by the Windows Firewall ({})",
                    e.message()
                ));
            }
            if !allume(p, profil) {
                return Resultat::echec(trf!(
                    "profil {nom} : relu coupé après l'avoir allumé",
                    "{nom} profile: read back off after turning it on"
                ));
            }
            rallumes.push(nom);
        }
        if rallumes.is_empty() {
            Resultat::ok_note(tr!(
                "déjà en marche sur les trois profils",
                "already on for the three profiles"
            ))
        } else {
            Resultat::ok_note(trf!("remis en marche : {}", "turned back on: {}", rallumes.join(", ")))
        }
    })
}

/// Un réglage du profil Public : écrit, puis relu.
fn regler_public(p: &INetFwPolicy2, r: ReglagePublic, v: ValeurPublic) -> Resultat {
    let public = NET_FW_PROFILE2_PUBLIC;
    let booleen = |b: bool| if b { VARIANT_TRUE } else { VARIANT_FALSE };
    // SAFETY: objet COM valide ; le profil et les valeurs sont des constantes de l'énumération ; chaque lecture rend
    // une copie.
    let (ecrit, relu) = unsafe {
        match (r, v) {
            (ReglagePublic::Actif, ValeurPublic::Oui) => (
                p.put_FirewallEnabled(public, VARIANT_TRUE),
                p.get_FirewallEnabled(public).is_ok_and(|e| e == VARIANT_TRUE),
            ),
            // La grammaire n'en laisse passer aucune : redit ici, un pare-feu ne se coupe jamais.
            (ReglagePublic::Actif, _) => {
                return Resultat::echec(tr!("couper le pare-feu : refusé", "turning the firewall off: refused"));
            }
            (ReglagePublic::EntrantBloque, _) => {
                let action: NET_FW_ACTION = if v == ValeurPublic::Oui {
                    NET_FW_ACTION_BLOCK
                } else {
                    NET_FW_ACTION_ALLOW
                };
                (
                    p.put_DefaultInboundAction(public, action),
                    p.get_DefaultInboundAction(public).is_ok_and(|a| a == action),
                )
            }
            (ReglagePublic::ReglesEntrantes, _) => {
                // « Non » : les règles des programmes autorisés ignorées, toutes les entrées bloquées. « Absent » :
                // d'abord la valeur de Windows (les règles suivies), écrite par COM pour qu'elle prenne effet
                // tout de suite ; la valeur est ensuite retirée du magasin (`retirer_du_magasin`).
                let voulu: VARIANT_BOOL = booleen(v == ValeurPublic::Non);
                (
                    p.put_BlockAllInboundTraffic(public, voulu),
                    p.get_BlockAllInboundTraffic(public).is_ok_and(|b| b == voulu),
                )
            }
        }
    };
    let nom = r.cle();
    match ecrit {
        Err(e) => Resultat::echec(trf!(
            "{nom} : refusé par le Pare-feu Windows ({})",
            "{nom}: refused by the Windows Firewall ({})",
            e.message()
        )),
        Ok(()) if relu => Resultat::ok(),
        Ok(()) => Resultat::echec(trf!(
            "{nom} : relu autrement qu'écrit",
            "{nom}: read back differently than written"
        )),
    }
}

/// Le profil Public réglé, chaque réglage relu ; « absent » remet ensuite le magasin tel qu'il était : sans la
/// valeur, que PersistentStore relit « NotConfigured ».
fn profil_public(p: ProfilPublic) -> Resultat {
    // Bloquer toutes les entrées couperait le Bureau à distance ou SSH : le mode Wi-Fi public l'a déjà écarté, ce
    // processus le rejuge au moment de le faire (une session ouverte depuis, ou des connexions illisibles), sans rien
    // toucher.
    if p.reglages()
        .any(|(r, v)| r == ReglagePublic::ReglesEntrantes && v == ValeurPublic::Non)
        && crate::protection::blocage::session_a_distance() != Some(false)
    {
        return Resultat::echec(tr!(
            "une session à distance est en cours (ou illisible) : les entrées ne sont pas toutes bloquées, rien n'est changé",
            "a remote session is in progress (or unreadable): inbound is not fully blocked, nothing is changed"
        ));
    }
    let r = dans_com(move |pol, _| {
        for (reglage, valeur) in p.reglages() {
            let fait = regler_public(pol, reglage, valeur);
            if !fait.reussi {
                return fait;
            }
        }
        Resultat::ok()
    });
    if !r.reussi
        || !p
            .reglages()
            .any(|(r, v)| r == ReglagePublic::ReglesEntrantes && v == ValeurPublic::Absent)
    {
        return r;
    }
    retirer_du_magasin()
}

/// Retire DoNotAllowExceptions du magasin local, seulement s'il vaut 0, ce que COM vient d'y écrire (la valeur de
/// Windows) : l'effet ne change pas, absent valant 0. Une autre valeur, ou un magasin qui ne la porte pas là où on
/// l'attend, n'est pas touchée : c'est dit.
fn retirer_du_magasin() -> Resultat {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let cle = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(MAGASIN_PUBLIC, KEY_QUERY_VALUE | KEY_SET_VALUE)
    {
        Ok(c) => c,
        Err(e) => {
            return Resultat::echec(trf!(
                "magasin du profil Public illisible : {e}",
                "Public profile store unreadable: {e}"
            ));
        }
    };
    match cle.get_value::<u32, _>(BLOQUER_TOUTES_LES_ENTREES) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Resultat::ok_note(tr!("déjà non configuré", "already not configured"))
        }
        Ok(0) => match cle.delete_value(BLOQUER_TOUTES_LES_ENTREES) {
            Ok(()) if cle.get_raw_value(BLOQUER_TOUTES_LES_ENTREES).is_err() => {
                Resultat::ok_note(tr!("remis à « non configuré »", "put back to “not configured”"))
            }
            Ok(()) => Resultat::echec(tr!(
                "la valeur est toujours là après son retrait",
                "the value is still there after its removal"
            )),
            Err(e) => Resultat::echec(e.to_string()),
        },
        _ => Resultat::echec(tr!(
            "les entrées des programmes autorisés sont remises, mais le magasin ne relit pas la valeur écrite : laissée telle quelle",
            "inbound for allowed programs is restored, but the store does not read back the written value: left as is"
        )),
    }
}

/// Ce que dit INetworkListManager d'un réseau.
enum Nlm {
    Domaine,
    Fait,
    Relu(i32),
}

/// La catégorie d'un réseau. Le GUID désigne, ce processus juge : le profil doit exister dans NetworkList\Profiles
/// et ne pas être celui d'un domaine (le réseau d'une entreprise est géré par elle). Par INetworkListManager, qui
/// l'applique tout de suite, connecté ou non ; sinon dans le registre, pour la prochaine connexion, comme le faisait
/// le repli d'avant.
fn categorie(r: ReseauCategorie) -> Resultat {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let voulue = r.categorie.valeur();
    let Ok(cle) =
        winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r.cle(), KEY_QUERY_VALUE | KEY_SET_VALUE)
    else {
        return Resultat::echec(tr!(
            "ce réseau n'existe pas sur ce PC (aucun profil réseau de ce GUID) : rien n'est changé",
            "this network does not exist on this PC (no network profile with this GUID): nothing is changed"
        ));
    };
    match cle.get_value::<u32, _>("Category") {
        Ok(2) => return domaine(),
        Ok(c) if c == voulue => return Resultat::ok_note(tr!("déjà dans cette catégorie", "already in this category")),
        _ => {}
    }
    let guid = windows::core::GUID::from_u128(r.guid.0);
    let nlm = super::wmi::com_delai(
        "Réseaux",
        "INetworkListManager",
        std::time::Duration::from_secs(60),
        move || {
            // SAFETY: COM est initialisé dans ce fil (`com_delai`) ; NetworkListManager est la classe de la liste
            // des réseaux. Chaque objet rendu est valide tant qu'il est tenu ; les catégories sont des copies.
            unsafe {
                let liste: INetworkListManager = CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)?;
                let reseau = liste.GetNetwork(guid)?;
                if reseau.GetCategory()? == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED {
                    return Ok(Nlm::Domaine);
                }
                let voulue = NLM_NETWORK_CATEGORY(i32::try_from(voulue).unwrap_or(-1));
                reseau.SetCategory(voulue)?;
                let relue = reseau.GetCategory()?;
                Ok(if relue == voulue { Nlm::Fait } else { Nlm::Relu(relue.0) })
            }
        },
    );
    match nlm {
        Some(Nlm::Domaine) => domaine(),
        Some(Nlm::Fait) => Resultat::ok(),
        Some(Nlm::Relu(c)) => Resultat::echec(trf!(
            "catégorie relue {c} après l'avoir changée",
            "category read back as {c} after changing it"
        )),
        // INetworkListManager ne connaît pas ce réseau ou ne répond pas : le registre, relu.
        None => match cle.set_value("Category", &voulue) {
            Ok(()) if cle.get_value::<u32, _>("Category").is_ok_and(|c| c == voulue) => Resultat::ok_note(tr!(
                "écrit dans le registre : pris en compte à la prochaine connexion à ce réseau",
                "written to the registry: applied at the next connection to this network"
            )),
            Ok(()) => Resultat::echec(tr!(
                "catégorie relue autrement qu'écrite",
                "category read back differently than written"
            )),
            Err(e) => Resultat::echec(e.to_string()),
        },
    }
}

fn domaine() -> Resultat {
    Resultat::echec(tr!(
        "réseau d'entreprise (domaine) : sa catégorie est gérée, pas touchée",
        "company (domain) network: its category is managed, not touched"
    ))
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

    /// Un GUID forgé, d'un réseau qui n'existe pas : refusé avant tout geste, ni COM ni registre écrits (le registre
    /// se lit sous Wine comme sous Windows).
    #[test]
    fn un_reseau_inexistant_est_refuse() {
        use crate::machine::gestes::{self, Categorie, GuidReseau};
        let r = ReseauCategorie {
            guid: GuidReseau::lire("{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}").unwrap(),
            categorie: Categorie::Prive,
        };
        let fait = categorie(r);
        assert!(
            !fait.reussi && (fait.raison.contains("n'existe pas") || fait.raison.contains("does not exist")),
            "{}",
            fait.raison
        );
        let ligne =
            gestes::ligne_reseau_categorie("{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}", Categorie::Public).unwrap();
        let fait = faire_acte(&gestes::analyser_acte(&ligne).unwrap()).unwrap();
        assert!(
            !fait.reussi && (fait.raison.contains("n'existe pas") || fait.raison.contains("does not exist")),
            "{}",
            fait.raison
        );
    }

    /// Les profils du pare-feu se lisent par COM (lecture seule : rien n'est écrit) ; Wine n'a pas de pare-feu.
    #[test]
    fn les_profils_se_lisent() {
        let r = dans_com(|p, _| {
            for profil in [NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC] {
                // SAFETY: objet COM valide ; les lectures rendent des copies.
                let lu = unsafe {
                    p.get_FirewallEnabled(profil).is_ok()
                        && p.get_DefaultInboundAction(profil).is_ok()
                        && p.get_BlockAllInboundTraffic(profil).is_ok()
                };
                if !lu {
                    return Resultat::echec("illisible");
                }
            }
            Resultat::ok()
        });
        if !r.reussi {
            return crate::essais::saute("Pare-feu Windows injoignable ou illisible (Wine)");
        }
        assert!(r.note.is_none());
    }
}
