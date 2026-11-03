//! Les règles de blocage dans le Pare-feu Windows, par son interface COM (INetFwPolicy2::Rules, INetFwRules::Add,
//! Remove, Item), dans le processus élevé : plus de New-NetFirewallRule ni de fenêtre PowerShell. Les noms sont ceux
//! que posaient les versions d'avant (Name de COM = DisplayName de NetSecurity), si bien qu'une règle posée par elles
//! se retire ici et que le bilan (« Vanguard : bloquer <port> ») la reconnaît toujours. Le nom d'une règle ne doit
//! contenir ni « | » ni être « all » (documentation de INetFwRule) : les nôtres sont faits d'une adresse ou d'un
//! port analysés. Après chaque geste, la règle est relue.
//!
//! Aussi les actes du pare-feu et des réseaux (`gestes::Acte`) : le pare-feu remis en marche sur ses trois profils,
//! le profil Public réglé (INetFwPolicy2 écrit le magasin local, celui que `-PolicyStore PersistentStore` lit et
//! écrit), et la catégorie d'un réseau (INetworkListManager, comme Set-NetConnectionProfile ; le registre seulement
//! pour un réseau que Windows ne connaît pas en ce moment, dit non vérifié). Chaque valeur est relue après avoir été
//! écrite.

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
    INetworkListManager, NLM_ENUM_NETWORK_CONNECTED, NLM_NETWORK_CATEGORY, NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED,
    NetworkListManager,
};
use windows::Win32::System::Com::{CLSCTX_ALL, CLSCTX_INPROC_SERVER, CoCreateInstance, IDispatch};
use windows::Win32::System::Ole::IEnumVARIANT;
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

use crate::machine::gestes::{
    self, Acte, EtatProfil, GuidReseau, IdChoix, ProfilPareFeu, ProfilPublic, RefusSession, ReglagePareFeu,
    ReglagePublic, RegleLue, ReseauCategorie, ValeurPublic,
};
use crate::modele::raison::Echec;

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

pub(super) fn politique() -> windows::core::Result<INetFwPolicy2> {
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

/// Le pare-feu coupé sur un profil courant : la règle n'y bloquerait rien. La phrase propose de le rallumer, par
/// son identifiant (`vanguard options-defense --rallumer pare-feu-<profil>-actif`, ou l'écran des Options).
fn coupe_pour_le_reseau(p: &INetFwPolicy2) -> String {
    // SAFETY: objet COM valide ; la lecture rend une copie.
    let courants = unsafe { p.CurrentProfileTypes() }.unwrap_or(0);
    let coupes: Vec<String> = ProfilPareFeu::TOUS
        .into_iter()
        .filter(|x| courants & x.bit() != 0)
        .filter(|x| !allume(p, NET_FW_PROFILE_TYPE2(x.bit())))
        .map(|x| IdChoix::PareFeu(x, ReglagePareFeu::Actif).texte())
        .collect();
    let rallumer = coupes
        .first()
        .map_or_else(|| "pare-feu-prive-actif".to_string(), Clone::clone);
    trf!(
        "le Pare-feu Windows est coupé pour le réseau actif : une règle n'y bloquerait rien, aucune n'est posée. Rallumez-le d'abord : Options de défense › Pare-feu, ou « vanguard options-defense --rallumer {rallumer} »",
        "the Windows Firewall is off for the active network: a rule would block nothing there, none is added. Turn it back on first: Defense options › Firewall, or “vanguard options-defense --rallumer {rallumer}”"
    )
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
        crate::compte_rendu::Contexte::PareFeuWindows,
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
                    // Le plus souvent, le service Pare-feu Windows arrêté : la classe ne se crée pas sans lui.
                    Err(e) => Resultat::echec(trf!(
                        "Pare-feu Windows injoignable (le service Pare-feu Windows, mpssvc, est peut-être arrêté) : {}",
                        "Windows Firewall unreachable (the Windows Firewall service, mpssvc, may be stopped): {}",
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
            return Resultat::echec(coupe_pour_le_reseau(p));
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
        Acte::Service(_)
        | Acte::Vider(_)
        | Acte::ViderFileImpression
        | Acte::MettreDeCote(_)
        | Acte::IfeoDebugger(..)
        | Acte::IfeoSilencieux(..)
        | Acte::ServiceGuillemets(_)
        | Acte::Defender(..)
        | Acte::DefenderAsr(..)
        | Acte::DefenderExclusionRetirer(..)
        | Acte::DefenderMenacesRetirer
        | Acte::DefenderChoix(..)
        | Acte::DefenderAsrChoix(..)
        | Acte::Rallumer(_)
        | Acte::DefenderExclusionAjouter(..)
        | Acte::DefenderDossiersAutoriser(..)
        | Acte::ChoixNoter(..)
        | Acte::HostsEcrire(_)
        | Acte::DnsAuto(_)
        | Acte::DnsServeurs(_)
        | Acte::CompteDesactiver(_)
        | Acte::CertificatRetirer(..)
        | Acte::PartageRetirerAcces(_)
        | Acte::RunRetirer(_)
        | Acte::RunRemettre(_)
        | Acte::TacheDesactiver(_)
        | Acte::TacheReactiver(_)
        | Acte::DemarrageQuarantaine(_)
        | Acte::DemarrageRemettre(_)
        | Acte::LancementDesactiver(..)
        | Acte::LancementReactiver(_)
        | Acte::WmiAbonnementRetirer(_)
        | Acte::WmiAbonnementRemettre(_)
        | Acte::ServiceRetirer(_)
        | Acte::Reglage(_)
        | Acte::ReglageRemettre(_)
        | Acte::CompteMotDePasse(_)
        | Acte::SshDroits(_)
        | Acte::SshDroitsRemettre(_)
        | Acte::SshdReglage(_)
        | Acte::SshdReglageRemettre(_)
        | Acte::ServiceGuillemetsRisque(_)
        | Acte::ServiceCheminRemettre(_)
        // Les choix du pare-feu passent par `choix_avant` (`defender_ecriture::faire_choix`), jamais tout droit ici.
        | Acte::PareFeuProfil(..)
        | Acte::PareFeuRegleEtat(..) => None,
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
    let session = session_maintenant();
    dans_com(move |p, regles| {
        let profils = [
            (ProfilPareFeu::Domaine, NET_FW_PROFILE2_DOMAIN, tr!("domaine", "domain")),
            (ProfilPareFeu::Prive, NET_FW_PROFILE2_PRIVATE, tr!("privé", "private")),
            (ProfilPareFeu::Public, NET_FW_PROFILE2_PUBLIC, tr!("public", "public")),
        ];
        let mut rallumes = Vec::new();
        for (x, profil, nom) in profils {
            if allume(p, profil) {
                continue;
            }
            // Allumer un profil courant pendant une session à distance : la même garde que les choix (un port de la
            // session fermé, des sorties bloquées), rejugée ici sur ce qui est relu.
            if session.is_some()
                && let Some(refus) = garde_allumer(p, regles, session.as_deref(), x)
            {
                let fait = if rallumes.is_empty() {
                    String::new()
                } else {
                    trf!(" (remis en marche : {})", " (turned back on: {})", rallumes.join(", "))
                };
                return Resultat::echec(trf!("profil {nom} : {refus}{fait}", "{nom} profile: {refus}{fait}"));
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
                // L'écriture va au magasin local, la relecture rend l'effet : une stratégie de groupe qui coupe ce
                // profil passe avant.
                return Resultat::echec(trf!(
                    "profil {nom} : relu coupé après l'avoir allumé (une stratégie de groupe impose peut-être ce réglage)",
                    "{nom} profile: read back off after turning it on (a group policy may be enforcing this setting)"
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

/// La garde de session pour allumer ce profil : la phrase du refus, ou `None` s'il peut l'être.
fn garde_allumer(p: &INetFwPolicy2, regles: &INetFwRules, session: Option<&[u16]>, x: ProfilPareFeu) -> Option<String> {
    garde_profil(p, regles, session, x, ReglagePareFeu::Actif, true)
        .err()
        .map(|e| match e {
            PasEcrit::Refus(t) | PasEcrit::Echec(t) => t,
        })
}

/// La garde de la session à distance pour ce réglage d'un profil (`gestes::refus_profil_session`), jugée sur ce qui
/// est relu à l'instant : le profil, le masque courant, les règles. Sans session, rien à garder ; un profil ou des
/// règles illisibles pendant une session : refusé, rien n'est écrit sans savoir.
fn garde_profil(
    pol: &INetFwPolicy2,
    regles: &INetFwRules,
    session: Option<&[u16]>,
    p: ProfilPareFeu,
    r: ReglagePareFeu,
    fermee: bool,
) -> Result<(), PasEcrit> {
    if session.is_none() {
        return Ok(());
    }
    let avant = etat_profil(pol, p).ok_or_else(|| {
        PasEcrit::Refus(tr!("profil illisible, laissé tel quel", "profile unreadable, left as is").to_string())
    })?;
    // SAFETY: objet COM valide ; la lecture rend une copie.
    let courants = unsafe { pol.CurrentProfileTypes() }.ok();
    let (lues, illisibles) = regles_com(regles).map_err(|_| regles_illisibles())?;
    if illisibles > 0 {
        return Err(regles_illisibles());
    }
    let lues: Vec<RegleLue> = lues.into_iter().map(|(l, _)| l).collect();
    match gestes::refus_profil_session(session, courants, p, r, fermee, avant, &lues) {
        Some(refus) => Err(PasEcrit::Refus(texte_refus(refus))),
        None => Ok(()),
    }
}

/// Un réglage du profil Public : écrit, puis relu.
fn regler_public(p: &INetFwPolicy2, r: ReglagePublic, v: ValeurPublic) -> Resultat {
    let public = NET_FW_PROFILE2_PUBLIC;
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
        // Écrit dans le magasin local, relu dans l'effet : une stratégie de groupe contraire passe avant.
        Ok(()) => Resultat::echec(trf!(
            "{nom} : relu autrement qu'écrit (une stratégie de groupe impose peut-être ce réglage)",
            "{nom}: read back differently than written (a group policy may be enforcing this setting)"
        )),
    }
}

/// Le profil Public réglé, chaque réglage relu ; « absent » remet ensuite le magasin tel qu'il était : sans la
/// valeur, que PersistentStore relit « NotConfigured ».
fn profil_public(p: ProfilPublic) -> Resultat {
    let (p, laissee) = match sans_blocage_total(p, crate::protection::blocage::session_a_distance()) {
        Ok(fait) => fait,
        Err(refus) => return refus,
    };
    let session = session_maintenant();
    let r = dans_com(move |pol, regles| {
        for (reglage, valeur) in p.reglages() {
            // Allumer le profil Public, ou bloquer ses entrées, pendant une session : la garde des choix du pare-feu
            // (un port de la session fermé), rejugée ici. Refusé : rien de plus n'est écrit, c'est dit.
            let garde = match (reglage, valeur) {
                (ReglagePublic::Actif, ValeurPublic::Oui) => Some(ReglagePareFeu::Actif),
                (ReglagePublic::EntrantBloque, ValeurPublic::Oui) => Some(ReglagePareFeu::Entrant),
                _ => None,
            };
            if let Some(r) = garde
                && let Err(PasEcrit::Refus(t) | PasEcrit::Echec(t)) =
                    garde_profil(pol, regles, session.as_deref(), ProfilPareFeu::Public, r, true)
            {
                return Resultat::echec(trf!("{} : {t}", "{}: {t}", reglage.cle()));
            }
            let fait = regler_public(pol, reglage, valeur);
            if !fait.reussi {
                return fait;
            }
        }
        Resultat::ok()
    });
    if !r.reussi {
        return r;
    }
    // regles-entrantes ne revient qu'une fois : laissée, elle n'était pas « absent », le magasin n'est pas à revoir.
    if let Some(note) = laissee {
        return Resultat::ok_note(note);
    }
    if !p
        .reglages()
        .any(|(r, v)| r == ReglagePublic::ReglesEntrantes && v == ValeurPublic::Absent)
    {
        return r;
    }
    retirer_du_magasin()
}

/// Bloquer toutes les entrées couperait le Bureau à distance ou SSH : le mode Wi-Fi public l'a déjà écarté, ce
/// processus le rejuge au moment de le faire (une session ouverte depuis, ou des connexions illisibles : `session`
/// n'est pas `Some(false)`). Seule regles-entrantes=non tombe alors : le reste de la ligne (le pare-feu allumé, les
/// entrées bloquées par défaut) ne coupe aucune session établie et reste fait ; la note dit ce qui est laissé et
/// pourquoi, le mode Wi-Fi relit ensuite chaque réglage. Rien d'autre dans la ligne : refusée, rien n'est touché.
fn sans_blocage_total(p: ProfilPublic, session: Option<bool>) -> Result<(ProfilPublic, Option<String>), Resultat> {
    let tout_bloquer =
        |(r, v): &(ReglagePublic, ValeurPublic)| *r == ReglagePublic::ReglesEntrantes && *v == ValeurPublic::Non;
    if session == Some(false) || !p.reglages().any(|x| tout_bloquer(&x)) {
        return Ok((p, None));
    }
    let reste: Vec<(ReglagePublic, ValeurPublic)> = p.reglages().filter(|x| !tout_bloquer(x)).collect();
    match ProfilPublic::nouveau(&reste) {
        Some(q) => Ok((
            q,
            Some(
                tr!(
                    "regles-entrantes=non laissé (les programmes autorisés gardent leurs entrées) : une session à distance est en cours, ou les connexions ne se lisent pas, et tout bloquer la couperait ; le reste de la ligne est fait",
                    "regles-entrantes=non left out (allowed programs keep their inbound): a remote session is in progress, or connections cannot be read, and blocking everything would cut it; the rest of the line is done"
                )
                .to_string(),
            ),
        )),
        None => Err(Resultat::echec(tr!(
            "une session à distance est en cours (ou illisible) : les entrées ne sont pas toutes bloquées, rien n'est changé",
            "a remote session is in progress (or unreadable): inbound is not fully blocked, nothing is changed"
        ))),
    }
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

// ------------------------------------------------------------- les choix de la personne (plan §2.3)

/// Le contexte des échecs d'écriture des choix du pare-feu, stable pour le journal des erreurs.
const CONTEXTE_CHOIX: &str = "pare-feu/choix";
/// Au-delà, la liste des règles n'est pas crue lue en entier : un Windows en a quelques centaines.
const REGLES_MAX: usize = 50_000;

fn booleen(b: bool) -> VARIANT_BOOL {
    if b { VARIANT_TRUE } else { VARIANT_FALSE }
}

fn vrai_faux(v: VARIANT_BOOL) -> Option<bool> {
    if v == VARIANT_TRUE {
        Some(true)
    } else if v == VARIANT_FALSE {
        Some(false)
    } else {
        None
    }
}

fn action(bloquer: bool) -> NET_FW_ACTION {
    if bloquer {
        NET_FW_ACTION_BLOCK
    } else {
        NET_FW_ACTION_ALLOW
    }
}

/// Un profil tel qu'il s'applique, relu ; `None` si l'une de ses quatre valeurs ne se lit pas.
fn etat_profil(pol: &INetFwPolicy2, p: ProfilPareFeu) -> Option<EtatProfil> {
    let profil = NET_FW_PROFILE_TYPE2(p.bit());
    // SAFETY: objet COM valide ; le profil est une constante de l'énumération ; chaque lecture rend une copie.
    unsafe {
        Some(EtatProfil {
            actif: vrai_faux(pol.get_FirewallEnabled(profil).ok()?)?,
            entrant_bloque: pol.get_DefaultInboundAction(profil).ok()? == NET_FW_ACTION_BLOCK,
            sortant_bloque: pol.get_DefaultOutboundAction(profil).ok()? == NET_FW_ACTION_BLOCK,
            tout_bloque: vrai_faux(pol.get_BlockAllInboundTraffic(profil).ok()?)?,
        })
    }
}

/// Une règle relue ; `None` si son nom, son sens, son action, son état ou ses profils ne se lisent pas, ni les ports
/// locaux d'une règle d'autorisation (elle pourrait être celle du Bureau à distance : illisible, elle compte parmi les
/// règles illisibles, que la garde de session refuse). Un champ d'adresse ou d'interface illisible vaut « ? », jamais
/// « partout » ; les ports locaux illisibles d'une règle de blocage valent « tous » : dans le doute, une règle
/// d'autorisation n'ouvre rien et une règle de blocage touche tout (`gestes::RegleLue`).
fn lire_regle(r: &INetFwRule) -> Option<RegleLue> {
    let texte = |b: windows::core::Result<BSTR>, sinon: &str| b.map_or_else(|_| sinon.to_string(), |b| b.to_string());
    // SAFETY: objet COM valide ; chaque lecture rend une copie (BSTR, VARIANT libérés par leur Drop).
    unsafe {
        let interfaces = match r.Interfaces() {
            Ok(v) if v.is_empty() => texte(r.InterfaceTypes(), "?"),
            _ => "?".to_string(),
        };
        let bloque = r.Action().ok()? == NET_FW_ACTION_BLOCK;
        let ports_locaux = match r.LocalPorts() {
            Ok(b) => b.to_string(),
            Err(_) if bloque => String::new(),
            Err(_) => return None,
        };
        Some(RegleLue {
            nom: r.Name().ok()?.to_string(),
            entrante: r.Direction().ok()? == NET_FW_RULE_DIR_IN,
            bloque,
            active: vrai_faux(r.Enabled().ok()?)?,
            profils: r.Profiles().ok()?,
            programme: texte(r.ApplicationName(), "?"),
            protocole: r.Protocol().unwrap_or(NET_FW_IP_PROTOCOL_ANY.0),
            ports_locaux,
            ports_distants: texte(r.RemotePorts(), "?"),
            adresses_distantes: texte(r.RemoteAddresses(), "?"),
            adresses_locales: texte(r.LocalAddresses(), "?"),
            interfaces,
            service: texte(r.ServiceName(), "?"),
            groupe: texte(r.Grouping(), ""),
        })
    }
}

/// Chaque règle du pare-feu, relue, avec son objet COM (dans ce fil seulement), et le nombre de celles qui ne se
/// lisent pas. Une liste qui ne se parcourt pas jusqu'au bout est une erreur, jamais une liste partielle.
fn regles_com(r: &INetFwRules) -> windows::core::Result<(Vec<(RegleLue, INetFwRule)>, usize)> {
    // SAFETY: objet COM valide ; _NewEnum rend un énumérateur à nous ; chaque VARIANT rempli par Next est à nous et
    // libéré par son Drop (VariantClear) ; la règle tirée de son IDispatch est une référence comptée à part.
    unsafe {
        let enumerateur: IEnumVARIANT = r._NewEnum()?.cast()?;
        let (mut lues, mut illisibles) = (Vec::new(), 0usize);
        loop {
            let mut v = [VARIANT::default()];
            let mut n = 0u32;
            enumerateur.Next(&mut v, &raw mut n).ok()?;
            if n == 0 {
                break;
            }
            match IDispatch::try_from(&v[0])
                .and_then(|d| d.cast::<INetFwRule>())
                .ok()
                .and_then(|regle| lire_regle(&regle).map(|l| (l, regle)))
            {
                Some(lue) => lues.push(lue),
                None => illisibles += 1,
            }
            if lues.len() + illisibles > REGLES_MAX {
                return Err(windows::core::Error::from(windows::Win32::Foundation::E_UNEXPECTED));
            }
        }
        Ok((lues, illisibles))
    }
}

/// Une lecture du pare-feu dans un fil COM à part, avec un délai ; `None` : pas de réponse ou COM indisponible.
fn lecture<T: Send + 'static>(
    geste: impl FnOnce(&INetFwPolicy2, &INetFwRules) -> windows::core::Result<T> + Send + 'static,
) -> Option<T> {
    super::wmi::com_delai(
        crate::compte_rendu::Contexte::PareFeuWindows,
        "INetFwPolicy2 (choix)",
        std::time::Duration::from_secs(60),
        move || {
            let p = politique()?;
            // SAFETY: objet COM valide.
            let r = unsafe { p.Rules() }?;
            geste(&p, &r)
        },
    )
}

/// Les règles du pare-feu relues, pour l'écran ; `None` : illisibles.
pub(crate) fn regles_lues() -> Option<Vec<RegleLue>> {
    lecture(|_, r| regles_com(r).map(|(l, _)| l.into_iter().map(|(x, _)| x).collect()))
}

/// Les profils du réseau actuel où le pare-feu est coupé : les blocages de Vanguard n'y s'appliquent pas. `None` :
/// illisible (rien n'est affirmé).
pub(crate) fn profils_courants_coupes() -> Option<Vec<ProfilPareFeu>> {
    lecture(|pol, _| {
        // SAFETY: objet COM valide ; la lecture rend une copie.
        let courants = unsafe { pol.CurrentProfileTypes() }?;
        Ok(ProfilPareFeu::TOUS
            .into_iter()
            .filter(|x| courants & x.bit() != 0)
            .filter(|x| !allume(pol, NET_FW_PROFILE_TYPE2(x.bit())))
            .collect())
    })
}

/// La valeur d'un choix du pare-feu (`IdChoix::pare_feu`) : pour un profil, 1 la valeur fermée ; pour une règle,
/// 1 active (`gestes::etat_des_regles`). `None` : illisible, ou aucune règle de cette empreinte.
#[allow(clippy::option_option)] // None : illisible
pub(crate) fn lire_choix(id: IdChoix) -> Option<Option<i64>> {
    match id {
        IdChoix::PareFeu(p, r) => lecture(move |pol, _| Ok(etat_profil(pol, p)))
            .flatten()
            .map(|e| Some(i64::from(e.valeur(r)))),
        IdChoix::PareFeuRegle(a, _) => lecture(move |_, regles| {
            let (lues, _) = regles_com(regles)?;
            Ok(gestes::etat_des_regles(
                a,
                lues.iter().filter(|(l, _)| l.id() == id).map(|(l, _)| l.active),
            ))
        })
        .flatten()
        .map(Some),
        _ => None,
    }
}

/// Le nom de la règle d'un choix, relu, pour la fenêtre administrateur ; `None` : aucune.
pub(crate) fn nom_regle(id: IdChoix) -> Option<String> {
    lecture(move |_, regles| {
        let (lues, _) = regles_com(regles)?;
        Ok(lues.into_iter().find(|(l, _)| l.id() == id).map(|(l, _)| l.nom))
    })
    .flatten()
}

/// Les ports de la session à distance en cours, relus au moment d'écrire (`gestes::session_pare_feu`) ; `None` :
/// aucune session, sûrement.
fn session_maintenant() -> Option<Vec<u16>> {
    let lues = crate::protection::blocage::gardes::sessions_a_distance();
    let port_rdp = crate::protection::blocage::gardes::port_rdp();
    gestes::session_pare_feu(
        super::session_a_distance(),
        port_rdp,
        lues.as_ref()
            .map(|s| (!s.sessions.is_empty(), s.ports_locaux.as_slice())),
    )
}

/// Ce qu'une écriture refusée ou échouée dit.
enum PasEcrit {
    /// La garde de la session : rien n'est écrit.
    Refus(String),
    Echec(String),
}

/// La phrase d'un refus de la garde de session.
fn texte_refus(r: RefusSession) -> String {
    let quoi = match r {
        RefusSession::ToutBloquer => tr!(
            "bloquer toutes les entrées sur un profil du réseau actuel la couperait",
            "blocking all inbound on a profile of the current network would cut it"
        ),
        RefusSession::Sorties => tr!(
            "bloquer les sorties sur un profil du réseau actuel couperait AnyDesk, TeamViewer, RustDesk ou un VPN",
            "blocking outbound on a profile of the current network would cut AnyDesk, TeamViewer, RustDesk or a VPN"
        ),
        RefusSession::PortFerme => tr!(
            "ce réglage fermerait un port de la session (Bureau à distance 3389, SSH 22, ou celui qu'elle utilise) : aucune règle sûre ne le laisse ouvert",
            "this setting would close a port of the session (Remote Desktop 3389, SSH 22, or the one it uses): no safe rule keeps it open"
        ),
        RefusSession::RegleAutorisation => tr!(
            "désactiver cette règle d'autorisation pourrait la couper",
            "disabling this allow rule could cut it"
        ),
        RefusSession::RegleBlocage => tr!(
            "activer cette règle de blocage pourrait la couper",
            "enabling this block rule could cut it"
        ),
    };
    trf!(
        "une session à distance est en cours (ou les connexions ne se lisent pas) : {quoi}. Refusé, rien d'écrit ; à refaire depuis l'ordinateur lui-même",
        "a remote session is in progress (or connections cannot be read): {quoi}. Refused, nothing written; do it again from the computer itself"
    )
}

fn regles_illisibles() -> PasEcrit {
    PasEcrit::Refus(tr!(
        "une session à distance est en cours (ou les connexions ne se lisent pas) et des règles du pare-feu ne se lisent pas : impossible de dire si ce réglage la couperait. Refusé, rien d'écrit",
        "a remote session is in progress (or connections cannot be read) and some firewall rules cannot be read: impossible to tell whether this setting would cut it. Refused, nothing written"
    )
    .to_string())
}

/// Écrit un choix du pare-feu (`v` : 1 la valeur fermée, ou active) après la garde de la session, rejugée ici sur
/// ce qui est relu à l'instant (la session, le masque courant, le profil, les règles). Jamais de règle effacée :
/// seulement activée ou désactivée. La valeur est ensuite relue par `choix_avant`.
pub(crate) fn ecrire_choix(id: IdChoix, v: i64) -> Result<(), Echec> {
    let fermee = match v {
        0 => false,
        1 => true,
        _ => {
            return Err(Echec::refuse(
                CONTEXTE_CHOIX,
                tr!("valeur refusée pour ce réglage", "value refused for this setting"),
            ));
        }
    };
    let session = session_maintenant();
    let fait = lecture(move |pol, regles| {
        Ok(match id {
            IdChoix::PareFeu(p, r) => ecrire_profil(pol, regles, session.as_deref(), p, r, fermee),
            IdChoix::PareFeuRegle(..) => ecrire_regle(pol, regles, session.as_deref(), id, fermee),
            _ => Err(PasEcrit::Refus(
                tr!("pas un réglage du pare-feu", "not a firewall setting").to_string(),
            )),
        })
    });
    match fait {
        Some(Ok(())) => Ok(()),
        Some(Err(PasEcrit::Refus(t))) => Err(Echec::refuse(CONTEXTE_CHOIX, t)),
        Some(Err(PasEcrit::Echec(t))) => Err(Echec::echoue(CONTEXTE_CHOIX, t)),
        // Le fil laissé derrière peut encore écrire : sort inconnu, la note de la baisse est gardée (`choix_avant`).
        None => Err(Echec::new(CONTEXTE_CHOIX, crate::modele::Raison::Delai).detail(tr!(
            "le Pare-feu Windows n'a pas répondu dans la minute (ou ne s'est pas ouvert) : sort inconnu, l'écriture peut encore se faire ; relisez l'écran du pare-feu",
            "the Windows Firewall did not answer within a minute (or did not open): outcome unknown, the write may still happen; re-read the firewall screen"
        ))),
    }
}

fn ecrire_profil(
    pol: &INetFwPolicy2,
    regles: &INetFwRules,
    session: Option<&[u16]>,
    p: ProfilPareFeu,
    r: ReglagePareFeu,
    fermee: bool,
) -> Result<(), PasEcrit> {
    let illisible = || {
        PasEcrit::Echec(
            tr!(
                "profil du pare-feu illisible, rien d'écrit",
                "firewall profile unreadable, nothing written"
            )
            .to_string(),
        )
    };
    etat_profil(pol, p).ok_or_else(illisible)?;
    garde_profil(pol, regles, session, p, r, fermee)?;
    let profil = NET_FW_PROFILE_TYPE2(p.bit());
    // SAFETY: objet COM valide ; le profil et les valeurs sont des constantes des énumérations.
    let ecrit = unsafe {
        match r {
            ReglagePareFeu::Actif => pol.put_FirewallEnabled(profil, booleen(fermee)),
            ReglagePareFeu::Entrant => pol.put_DefaultInboundAction(profil, action(fermee)),
            ReglagePareFeu::Sortant => pol.put_DefaultOutboundAction(profil, action(fermee)),
            ReglagePareFeu::ToutBloquer => pol.put_BlockAllInboundTraffic(profil, booleen(fermee)),
        }
    };
    ecrit.map_err(|e| {
        PasEcrit::Echec(trf!(
            "refusé par le Pare-feu Windows ({})",
            "refused by the Windows Firewall ({})",
            e.message()
        ))
    })
}

/// Les sorties sont-elles bloquées par défaut sur l'un des profils courants (`None` : un profil ou le masque ne se
/// lit pas) ?
fn sorties_bloquees(pol: &INetFwPolicy2) -> Option<bool> {
    // SAFETY: objet COM valide ; la lecture rend une copie.
    let courants = unsafe { pol.CurrentProfileTypes() }.ok()?;
    let mut bloquees = false;
    for p in ProfilPareFeu::TOUS.into_iter().filter(|p| courants & p.bit() != 0) {
        let e = etat_profil(pol, p)?;
        bloquees |= e.actif && e.sortant_bloque;
    }
    Some(bloquees)
}

fn ecrire_regle(
    pol: &INetFwPolicy2,
    regles: &INetFwRules,
    session: Option<&[u16]>,
    id: IdChoix,
    active: bool,
) -> Result<(), PasEcrit> {
    let (lues, illisibles) = regles_com(regles).map_err(|e| {
        PasEcrit::Echec(trf!(
            "règles du pare-feu illisibles ({}), rien d'écrit",
            "firewall rules unreadable ({}), nothing written",
            e.message()
        ))
    })?;
    // Pendant une session, une règle illisible peut être celle qui la laisse entrer : rien n'est jugé sans elle.
    if session.is_some() && illisibles > 0 {
        return Err(regles_illisibles());
    }
    let cibles: Vec<(RegleLue, INetFwRule)> = lues.into_iter().filter(|(l, _)| l.id() == id).collect();
    if cibles.is_empty() {
        return Err(PasEcrit::Echec(
            tr!(
                "cette règle n'existe plus (retirée ou changée depuis), rien d'écrit",
                "this rule no longer exists (removed or changed since), nothing written"
            )
            .to_string(),
        ));
    }
    if session.is_some() {
        // SAFETY: objet COM valide ; la lecture rend une copie.
        let courants = unsafe { pol.CurrentProfileTypes() }.ok();
        let sorties = sorties_bloquees(pol);
        // Toutes jugées avant d'en toucher une : un refus ne laisse pas la moitié faite.
        if let Some(refus) = cibles
            .iter()
            .find_map(|(l, _)| gestes::refus_regle_session(session, courants, sorties, l, active))
        {
            return Err(PasEcrit::Refus(texte_refus(refus)));
        }
    }
    for (l, regle) in &cibles {
        if l.active == active {
            continue;
        }
        // SAFETY: objet COM valide, de ce fil ; une valeur constante.
        if let Err(e) = unsafe { regle.SetEnabled(booleen(active)) } {
            return Err(PasEcrit::Echec(trf!(
                "règle « {} » refusée par le Pare-feu Windows ({})",
                "rule “{}” refused by the Windows Firewall ({})",
                crate::ui::affichable(&l.nom),
                e.message()
            )));
        }
    }
    Ok(())
}

/// Pourquoi le pare-feu a gardé la valeur écrite sans erreur : une stratégie l'emporte sur le magasin local.
pub(crate) fn pourquoi_garde() -> String {
    tr!(
        "le Pare-feu Windows a gardé la valeur : une stratégie (GPO, ou Intune par le MDM) impose ce réglage, quoi que Vanguard écrive",
        "the Windows Firewall kept the value: a policy (GPO, or Intune through MDM) enforces this setting, whatever Vanguard writes"
    )
    .to_string()
}

/// Ce que dit INetworkListManager (NLM) d'un réseau. Seuls des codes sortent de son fil (voir `wmi::dans_un_fil`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Nlm {
    /// GetNetwork ne connaît pas ce GUID, et aucun réseau connecté ne le porte : le seul cas du registre.
    Inconnu,
    /// GetNetwork ne le rend pas, mais un réseau connecté porte ce GUID : rien n'est écrit sur une réponse
    /// contradictoire.
    InconnuConnecte,
    Domaine,
    Deja,
    Fait,
    Relu(i32),
    /// Un appel refusé : lequel, et son code (HRESULT).
    Refuse(&'static str, i32),
}

/// Ce que `categorie` fait de la réponse de NLM (`None` : pas de réponse, délai ou COM indisponible).
#[derive(Debug, PartialEq, Eq)]
enum Suite {
    Rendre(Resultat),
    /// Écrire dans le registre, pour la prochaine connexion à ce réseau.
    Registre,
}

/// Le registre ne sert que pour un réseau que Windows ne connaît pas en ce moment : écrit pour un réseau connecté
/// dont NLM a refusé le changement, il dirait Public pendant que le pare-feu applique toujours le profil Privé, et le
/// mode Wi-Fi public, qui le relirait, se croirait en place. Un refus, une réponse contradictoire ou pas de réponse :
/// rien n'est écrit, et c'est dit.
fn suite(nlm: Option<Nlm>) -> Suite {
    Suite::Rendre(match nlm {
        Some(Nlm::Inconnu) => return Suite::Registre,
        Some(Nlm::Domaine) => domaine(),
        Some(Nlm::Deja) => Resultat::ok_note(tr!("déjà dans cette catégorie", "already in this category")),
        Some(Nlm::Fait) => Resultat::ok(),
        Some(Nlm::Relu(c)) => Resultat::echec(trf!(
            "catégorie relue {c} après l'avoir changée : celle en usage n'est pas celle voulue",
            "category read back as {c} after changing it: the one in use is not the one wanted"
        )),
        Some(Nlm::InconnuConnecte) => Resultat::echec(tr!(
            "la liste des réseaux de Windows dit ce réseau connecté sans le rendre : rien n'est changé",
            "the Windows network list says this network is connected without returning it: nothing is changed"
        )),
        Some(Nlm::Refuse(geste, code)) => Resultat::echec(trf!(
            "la liste des réseaux de Windows a refusé ({geste}, code 0x{code:08X}) : rien n'est changé, le registre non plus",
            "the Windows network list refused ({geste}, code 0x{code:08X}): nothing is changed, the registry either"
        )),
        None => Resultat::echec(tr!(
            "la liste des réseaux de Windows (service netprofm) n'a pas répondu dans la minute : rien n'est changé",
            "the Windows network list (netprofm service) did not answer within a minute: nothing is changed"
        )),
    })
}

/// Le refus d'un appel de NLM, réduit à son code dans le fil de COM.
fn refus(geste: &'static str) -> impl Fn(windows::core::Error) -> Nlm {
    move |e| Nlm::Refuse(geste, e.code().0)
}

/// Le geste de NLM, dans son fil COM : la catégorie changée tout de suite, connecté ou non, puis relue.
fn par_nlm(guid: windows::core::GUID, voulue: NLM_NETWORK_CATEGORY) -> Result<Nlm, Nlm> {
    // SAFETY: COM est initialisé dans ce fil (`com_delai`) ; NetworkListManager est la classe de la liste des
    // réseaux. Chaque objet rendu est valide tant qu'il est tenu ; les catégories et le GUID sont des copies.
    unsafe {
        let liste: INetworkListManager =
            CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL).map_err(refus("CoCreateInstance"))?;
        let Ok(reseau) = liste.GetNetwork(guid) else {
            return Ok(if connecte(&liste, guid)? {
                Nlm::InconnuConnecte
            } else {
                Nlm::Inconnu
            });
        };
        let avant = reseau.GetCategory().map_err(refus("GetCategory"))?;
        if avant == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED {
            return Ok(Nlm::Domaine);
        }
        if avant == voulue {
            return Ok(Nlm::Deja);
        }
        reseau.SetCategory(voulue).map_err(refus("SetCategory"))?;
        let relue = reseau.GetCategory().map_err(refus("GetCategory"))?;
        Ok(if relue == voulue { Nlm::Fait } else { Nlm::Relu(relue.0) })
    }
}

/// Un réseau connecté porte-t-il ce GUID ? Les réseaux connectés énumérés un à un.
fn connecte(liste: &INetworkListManager, guid: windows::core::GUID) -> Result<bool, Nlm> {
    // SAFETY: objet COM valide, dans son fil ; `un` et `lus` vivent pendant chaque appel de Next, qui y rend au plus
    // un réseau (la taille du tableau) ; chaque réseau rendu est tenu puis libéré ici.
    unsafe {
        let reseaux = liste
            .GetNetworks(NLM_ENUM_NETWORK_CONNECTED)
            .map_err(refus("GetNetworks"))?;
        for _ in 0..256 {
            let mut un = [None];
            let mut lus = 0u32;
            reseaux
                .Next(&mut un, Some(&raw mut lus))
                .map_err(refus("IEnumNetworks::Next"))?;
            let [Some(r)] = un else {
                return Ok(false);
            };
            if lus == 0 {
                return Ok(false);
            }
            if r.GetNetworkId().map_err(refus("GetNetworkId"))? == guid {
                return Ok(true);
            }
        }
        // Plus de 256 réseaux connectés : la liste ne se lit pas jusqu'au bout, compté comme connecté (rien n'est
        // écrit dans le registre).
        Ok(true)
    }
}

/// La catégorie d'un réseau. Le GUID désigne, ce processus juge : le profil doit exister dans NetworkList\Profiles
/// et ne pas être celui d'un domaine (le réseau d'une entreprise est géré par elle). Par INetworkListManager, qui
/// l'applique tout de suite, connecté ou non ; dans le registre seulement si Windows ne connaît pas ce réseau en ce
/// moment (`suite`), pour la prochaine connexion, et c'est dit non vérifié.
fn categorie(r: ReseauCategorie) -> Resultat {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};
    let voulue = r.categorie.valeur();
    let cle = match winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r.cle(), KEY_QUERY_VALUE | KEY_SET_VALUE)
    {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Resultat::echec(tr!(
                "ce réseau n'existe pas sur ce PC (aucun profil réseau de ce GUID) : rien n'est changé",
                "this network does not exist on this PC (no network profile with this GUID): nothing is changed"
            ));
        }
        // Accès refusé (droits de la clé changés) ou autre : le profil existe peut-être, il ne se lit pas.
        Err(e) => {
            return Resultat::echec(trf!(
                "le profil de ce réseau ne se lit pas dans le registre ({e}) : rien n'est changé",
                "this network's profile cannot be read in the registry ({e}): nothing is changed"
            ));
        }
    };
    if cle.get_value::<u32, _>("Category").is_ok_and(|c| c == 2) {
        return domaine();
    }
    let guid = windows::core::GUID::from_u128(r.guid.0);
    let nlm = super::wmi::com_delai(
        crate::compte_rendu::Contexte::Reseaux,
        "INetworkListManager",
        std::time::Duration::from_secs(60),
        move || {
            let voulue = NLM_NETWORK_CATEGORY(i32::try_from(voulue).unwrap_or(-1));
            Ok(par_nlm(guid, voulue).unwrap_or_else(|refus| refus))
        },
    );
    match suite(nlm) {
        Suite::Rendre(fait) => fait,
        Suite::Registre => {
            let note = tr!(
                "Windows ne connaît pas ce réseau en ce moment (pas connecté) : écrit dans le registre, pris en compte à la prochaine connexion ; non vérifié en direct",
                "Windows does not know this network right now (not connected): written to the registry, applied at the next connection; not verified live"
            );
            if cle.get_value::<u32, _>("Category").is_ok_and(|c| c == voulue) {
                return Resultat::ok_note(note);
            }
            match cle.set_value("Category", &voulue) {
                Ok(()) if cle.get_value::<u32, _>("Category").is_ok_and(|c| c == voulue) => Resultat::ok_note(note),
                Ok(()) => Resultat::echec(tr!(
                    "catégorie relue autrement qu'écrite",
                    "category read back differently than written"
                )),
                Err(e) => Resultat::echec(e.to_string()),
            }
        }
    }
}

/// La catégorie en usage d'un réseau (0 Public, 1 Privé, 2 domaine), lue par INetworkListManager sans droits
/// d'administrateur ; `None` si Windows ne connaît pas ce réseau en ce moment ou ne répond pas. Le mode Wi-Fi
/// public y relit ce qu'il vient de faire : le registre, lui, peut dire Public pour un réseau resté Privé.
pub(crate) fn categorie_en_direct(guid: GuidReseau) -> Option<i32> {
    let guid = windows::core::GUID::from_u128(guid.0);
    super::wmi::com_delai(
        crate::compte_rendu::Contexte::Reseaux,
        "INetworkListManager::GetCategory",
        std::time::Duration::from_secs(20),
        move || {
            // SAFETY: COM est initialisé dans ce fil (`com_delai`) ; chaque objet rendu est valide tant qu'il est
            // tenu ; la catégorie est une copie.
            unsafe {
                let liste: INetworkListManager = CoCreateInstance(&NetworkListManager, None, CLSCTX_ALL)?;
                Ok(liste.GetNetwork(guid)?.GetCategory()?.0)
            }
        },
    )
}

/// Le nom d'un réseau tel que le registre le garde (ProfileName), pour le montrer avec son GUID avant d'agir.
pub(crate) enum NomReseau {
    Lu(String),
    /// Aucun profil de ce GUID.
    Absent,
    /// La clé ou le nom ne se lisent pas (accès refusé, nom vide ou d'un autre type).
    Illisible,
}

pub(crate) fn nom_du_reseau(r: &ReseauCategorie) -> NomReseau {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE};
    match winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r.cle(), KEY_QUERY_VALUE) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => NomReseau::Absent,
        Err(_) => NomReseau::Illisible,
        Ok(cle) => match cle.get_value::<String, _>("ProfileName") {
            Ok(n) if !n.trim().is_empty() => NomReseau::Lu(n),
            _ => NomReseau::Illisible,
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
        assert!(matches!(nom_du_reseau(&r), NomReseau::Absent));
        // Le GUID nul, que la grammaire laisse passer : aucun profil ne le porte, refusé de même.
        let nul = ReseauCategorie {
            guid: GuidReseau(0),
            categorie: Categorie::Public,
        };
        let fait = categorie(nul);
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

    /// Le registre seulement pour un réseau que Windows ne connaît pas : un refus de NLM (SetCategory, GetCategory…),
    /// une réponse contradictoire ou pas de réponse rendent un échec dit, jamais le repli ni un « ok ».
    #[test]
    fn le_registre_seulement_pour_un_reseau_inconnu() {
        assert_eq!(suite(Some(Nlm::Inconnu)), Suite::Registre);
        assert_eq!(suite(Some(Nlm::Fait)), Suite::Rendre(Resultat::ok()));
        let Suite::Rendre(deja) = suite(Some(Nlm::Deja)) else {
            panic!("déjà : pas de registre");
        };
        assert!(deja.reussi && deja.note.is_some());
        // 0x80070005 : accès refusé.
        let refuse = i32::from_ne_bytes(0x8007_0005_u32.to_ne_bytes());
        for nlm in [
            Some(Nlm::Refuse("SetCategory", refuse)),
            Some(Nlm::Refuse("GetCategory", refuse)),
            Some(Nlm::Refuse("CoCreateInstance", refuse)),
            Some(Nlm::InconnuConnecte),
            Some(Nlm::Relu(1)),
            Some(Nlm::Domaine),
            None,
        ] {
            let Suite::Rendre(r) = suite(nlm) else {
                panic!("{nlm:?} : pas de registre");
            };
            assert!(!r.reussi && !r.raison.is_empty(), "{nlm:?}");
        }
        let Suite::Rendre(r) = suite(Some(Nlm::Refuse("SetCategory", refuse))) else {
            unreachable!()
        };
        assert!(
            r.raison.contains("SetCategory") && r.raison.contains("0x80070005"),
            "{}",
            r.raison
        );
    }

    /// Une session à distance (ou des connexions illisibles) ne fait tomber que regles-entrantes=non : le reste de la
    /// ligne se fait, la note le dit ; seule dans la ligne, elle la fait refuser.
    #[test]
    fn une_session_ne_fait_tomber_que_le_blocage_total() {
        use crate::machine::gestes::analyser_acte;
        let profil = |l: &str| match analyser_acte(l) {
            Some(Acte::PareFeuPublic(p)) => p,
            autre => panic!("{l} : {autre:?}"),
        };
        let tout = profil("vanguard:pare-feu-public actif=oui,entrant-bloque=oui,regles-entrantes=non");
        assert_eq!(sans_blocage_total(tout, Some(false)), Ok((tout, None)));
        for session in [Some(true), None] {
            let (reste, note) = sans_blocage_total(tout, session).unwrap();
            assert_eq!(reste, profil("vanguard:pare-feu-public actif=oui,entrant-bloque=oui"));
            assert!(note.is_some_and(|n| n.contains("regles-entrantes=non")));
            let seule = profil("vanguard:pare-feu-public regles-entrantes=non");
            assert!(sans_blocage_total(seule, session).is_err());
            // Une remise n'est pas un blocage total : rien ne tombe.
            let remise = profil("vanguard:pare-feu-public regles-entrantes=absent");
            assert_eq!(sans_blocage_total(remise, session), Ok((remise, None)));
        }
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
