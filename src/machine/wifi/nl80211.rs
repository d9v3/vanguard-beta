//! Les bornes Wi-Fi que le noyau Linux a entendues, lues par nl80211 (netlink générique) sans lancer iw ni nmcli :
//! la famille nl80211 demandée au contrôleur de netlink générique, les interfaces (NL80211_CMD_GET_INTERFACE), puis
//! le dernier balayage gardé par le noyau (NL80211_CMD_GET_SCAN), que n'importe quel compte peut relire : ses
//! éléments d'information bruts donnent le chiffrement, WPS et le BSSID de chaque borne, et le noyau dit laquelle
//! est celle de la connexion. Sans balayage récent, la liste est vide : on le dit, sans jamais balayer nous-mêmes
//! (cela demande des droits et coupe le Wi-Fi une seconde). Les lectures des réponses sont pures et testées sur des
//! messages fabriqués ; seule `echanger` parle au noyau.

#[cfg(target_os = "linux")]
use super::Lecture;
#[cfg(any(target_os = "linux", test))]
use super::Voisins;
#[cfg(any(target_os = "linux", test))]
use super::elements::{self, Wps, mac_texte};
#[cfg(any(target_os = "linux", test))]
use super::{Balise, Bande, Borne, Connexion, canal_de_frequence, pourcentage};
#[cfg(any(target_os = "linux", test))]
use crate::ui::affichable;

// Hors Linux, seuls les lecteurs purs sont compilés (pour leurs tests) : les constantes de l'échange avec le noyau
// n'y servent pas.
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod constantes {
    pub const NLMSG_NOOP: u16 = 1;
    pub const NLMSG_ERROR: u16 = 2;
    pub const NLMSG_DONE: u16 = 3;
    pub const NLM_F_REQUEST: u16 = 0x01;
    pub const NLM_F_MULTI: u16 = 0x02;
    pub const NLM_F_DUMP: u16 = 0x300;
    pub const GENL_ID_CTRL: u16 = 0x10;
    pub const CTRL_CMD_GETFAMILY: u8 = 3;
    pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
    pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
    pub const NL80211_CMD_NEW_INTERFACE: u8 = 7;
    pub const NL80211_CMD_GET_SCAN: u8 = 32;
    pub const NL80211_CMD_NEW_SCAN_RESULTS: u8 = 34;
    pub const NL80211_CMD_GET_POWER_SAVE: u8 = 62;
    pub const NL80211_ATTR_IFINDEX: u16 = 3;
    pub const NL80211_ATTR_IFNAME: u16 = 4;
    pub const NL80211_ATTR_IFTYPE: u16 = 5;
    pub const NL80211_ATTR_BSS: u16 = 47;
    pub const NL80211_ATTR_SSID: u16 = 52;
    pub const NL80211_ATTR_PS_STATE: u16 = 93;
    pub const NL80211_PS_ENABLED: u32 = 1;
    pub const NL80211_IFTYPE_STATION: u32 = 2;
    pub const NL80211_BSS_BSSID: u16 = 1;
    pub const NL80211_BSS_FREQUENCY: u16 = 2;
    pub const NL80211_BSS_CAPABILITY: u16 = 5;
    pub const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
    pub const NL80211_BSS_SIGNAL_MBM: u16 = 7;
    pub const NL80211_BSS_SIGNAL_UNSPEC: u16 = 8;
    pub const NL80211_BSS_STATUS: u16 = 9;
    pub const NL80211_BSS_SEEN_MS_AGO: u16 = 10;
    pub const NL80211_BSS_BEACON_IES: u16 = 11;
    pub const NL80211_BSS_STATUS_ASSOCIATED: u32 = 1;
    /// Au-delà, ce n'est plus une liste de bornes.
    pub const TAILLE_MAX: usize = 4 << 20;
}
#[cfg(any(target_os = "linux", test))]
use constantes::*;

/// Une interface Wi-Fi du noyau.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Interface {
    pub index: u32,
    pub nom: String,
    /// Une carte cliente (station), par opposition à un point d'accès ou un moniteur.
    pub station: bool,
    /// Le nom du réseau connecté, que les noyaux récents donnent avec l'interface.
    pub ssid: Option<String>,
}

/// Les messages netlink d'une réponse, un par un : (type, drapeaux, corps après l'en-tête de 16 octets).
#[cfg(any(target_os = "linux", test))]
fn messages(octets: &[u8]) -> impl Iterator<Item = (u16, u16, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let &[l0, l1, l2, l3, g0, g1, d0, d1, ..] = octets.get(pos..pos.checked_add(16)?)?.first_chunk::<16>()?;
        let longueur = usize::try_from(u32::from_ne_bytes([l0, l1, l2, l3])).ok()?;
        if longueur < 16 {
            return None;
        }
        let genre = u16::from_ne_bytes([g0, g1]);
        let drapeaux = u16::from_ne_bytes([d0, d1]);
        let corps = octets.get(pos + 16..pos.checked_add(longueur)?)?;
        pos += longueur.next_multiple_of(4);
        Some((genre, drapeaux, corps))
    })
}

/// Les attributs netlink d'un corps : (type sans ses drapeaux d'imbrication, contenu).
#[cfg(any(target_os = "linux", test))]
fn attributs(corps: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let &[l0, l1, g0, g1] = corps.get(pos..pos + 4)?.first_chunk::<4>()?;
        let longueur = usize::from(u16::from_ne_bytes([l0, l1]));
        if longueur < 4 {
            return None;
        }
        let genre = u16::from_ne_bytes([g0, g1]) & 0x3FFF;
        let contenu = corps.get(pos + 4..pos + longueur)?;
        pos += longueur.next_multiple_of(4);
        Some((genre, contenu))
    })
}

#[cfg(any(target_os = "linux", test))]
fn u32_ne(o: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes([*o.first()?, *o.get(1)?, *o.get(2)?, *o.get(3)?]))
}

#[cfg(any(target_os = "linux", test))]
fn u16_ne(o: &[u8]) -> Option<u16> {
    Some(u16::from_ne_bytes([*o.first()?, *o.get(1)?]))
}

/// Une demande netlink générique : en-tête netlink, en-tête générique (commande, version 1), attributs.
#[cfg(any(target_os = "linux", test))]
fn demande(famille: u16, drapeaux: u16, commande: u8, attributs: &[(u16, &[u8])]) -> Vec<u8> {
    // L'en-tête en tableau : ses champs se posent à des places fixes ; la longueur totale, à la fin.
    let mut entete = [0u8; 16];
    entete[4..6].copy_from_slice(&famille.to_ne_bytes());
    entete[6..8].copy_from_slice(&drapeaux.to_ne_bytes());
    entete[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let mut m = entete.to_vec();
    m.extend_from_slice(&[commande, 1, 0, 0]);
    for (genre, contenu) in attributs {
        // Nos attributs tiennent sur quelques octets (un numéro d'interface, un nom de famille).
        let longueur = u16::try_from(4 + contenu.len()).unwrap_or(4);
        m.extend_from_slice(&longueur.to_ne_bytes());
        m.extend_from_slice(&genre.to_ne_bytes());
        m.extend_from_slice(contenu);
        m.resize(m.len().next_multiple_of(4), 0);
    }
    let total = u32::try_from(m.len()).unwrap_or(0);
    if let Some(longueur) = m.first_chunk_mut::<4>() {
        *longueur = total.to_ne_bytes();
    }
    m
}

/// Le numéro de la famille nl80211, dans la réponse du contrôleur (CTRL_CMD_NEWFAMILY).
#[cfg(any(target_os = "linux", test))]
fn identifiant_famille(reponse: &[u8]) -> Option<u16> {
    messages(reponse)
        .filter(|(genre, _, _)| *genre == GENL_ID_CTRL)
        .find_map(|(_, _, corps)| {
            attributs(corps.get(4..)?)
                .find(|(g, _)| *g == CTRL_ATTR_FAMILY_ID)
                .and_then(|(_, c)| u16_ne(c))
        })
}

/// Les interfaces Wi-Fi des messages NL80211_CMD_NEW_INTERFACE.
#[cfg(any(target_os = "linux", test))]
fn interfaces(reponse: &[u8], famille: u16) -> Vec<Interface> {
    messages(reponse)
        .filter(|(genre, _, _)| *genre == famille)
        .filter_map(|(_, _, corps)| {
            if *corps.first()? != NL80211_CMD_NEW_INTERFACE {
                return None;
            }
            let mut i = Interface {
                index: 0,
                nom: String::new(),
                station: false,
                ssid: None,
            };
            for (genre, contenu) in attributs(corps.get(4..)?) {
                match genre {
                    NL80211_ATTR_IFINDEX => i.index = u32_ne(contenu)?,
                    NL80211_ATTR_IFNAME => {
                        // Jusqu'au zéro final, s'il y en a un.
                        let nom: Vec<u8> = contenu.iter().copied().take_while(|&o| o != 0).collect();
                        i.nom = affichable(&String::from_utf8_lossy(&nom));
                    }
                    NL80211_ATTR_IFTYPE => i.station = u32_ne(contenu) == Some(NL80211_IFTYPE_STATION),
                    NL80211_ATTR_SSID => {
                        i.ssid = Some(affichable(&String::from_utf8_lossy(contenu))).filter(|s| !s.is_empty());
                    }
                    _ => {}
                }
            }
            (i.index != 0).then_some(i)
        })
        .collect()
}

/// Une borne, d'après l'attribut NL80211_ATTR_BSS d'un résultat de balayage. Les éléments de la réponse de sondage
/// (les plus complets : méthodes WPS) d'abord, ceux de la balise à défaut.
#[cfg(any(target_os = "linux", test))]
fn balise(bss: &[u8]) -> Option<Balise> {
    let (mut bssid, mut mhz, mut capacites, mut sondage, mut balise, mut signal, mut actif) =
        (String::new(), None, 0u16, None, None, None, false);
    for (genre, contenu) in attributs(bss) {
        match genre {
            NL80211_BSS_BSSID => bssid = mac_texte(contenu),
            NL80211_BSS_FREQUENCY => mhz = u32_ne(contenu),
            NL80211_BSS_CAPABILITY => capacites = u16_ne(contenu).unwrap_or(0),
            NL80211_BSS_INFORMATION_ELEMENTS => sondage = Some(contenu),
            NL80211_BSS_BEACON_IES => balise = Some(contenu),
            NL80211_BSS_SIGNAL_MBM => signal = u32_ne(contenu).map(|m| pourcentage(m.cast_signed() / 100)),
            NL80211_BSS_SIGNAL_UNSPEC if signal.is_none() => signal = contenu.first().map(|s| (*s).min(100)),
            NL80211_BSS_STATUS => actif = u32_ne(contenu) == Some(NL80211_BSS_STATUS_ASSOCIATED),
            _ => {}
        }
    }
    let mhz = mhz?;
    let principal = elements::lire(sondage.or(balise).unwrap_or(&[]), capacites);
    let wps = match (
        principal.wps,
        sondage.and(balise).map(|b| elements::lire(b, capacites).wps),
    ) {
        (Some(s), Some(Some(b))) => Some(Wps {
            methodes: s.methodes.or(b.methodes),
            ..s
        }),
        (s, b) => s.or(b.flatten()),
    };
    Some(Balise {
        borne: Borne {
            ssid: principal.ssid,
            bssid,
            bande: Bande::de_frequence(mhz)?,
            canal: canal_de_frequence(mhz)?,
            signal,
            actif,
        },
        protection: principal.protection,
        wps,
    })
}

/// Depuis combien de millisecondes le noyau a entendu la borne (NL80211_BSS_SEEN_MS_AGO), à côté de `balise`, qui
/// rend la borne seule.
#[cfg(any(target_os = "linux", test))]
fn vue_il_y_a(bss: &[u8]) -> Option<u32> {
    attributs(bss)
        .find(|(g, _)| *g == NL80211_BSS_SEEN_MS_AGO)
        .and_then(|(_, c)| u32_ne(c))
}

/// Les bornes des messages NL80211_CMD_NEW_SCAN_RESULTS, avec l'âge de chacune.
#[cfg(any(target_os = "linux", test))]
fn balises_vues(reponse: &[u8], famille: u16) -> Vec<(Balise, Option<u32>)> {
    messages(reponse)
        .filter(|(genre, _, _)| *genre == famille)
        .filter_map(|(_, _, corps)| {
            if *corps.first()? != NL80211_CMD_NEW_SCAN_RESULTS {
                return None;
            }
            let bss = attributs(corps.get(4..)?).find(|(g, _)| *g == NL80211_ATTR_BSS)?.1;
            Some((balise(bss)?, vue_il_y_a(bss)))
        })
        .collect()
}

#[cfg(test)]
fn balises(reponse: &[u8], famille: u16) -> Vec<Balise> {
    balises_vues(reponse, famille).into_iter().map(|(b, _)| b).collect()
}

/// Ce que vaut la liste des voisins du noyau : il oublie une borne voisine environ 30 s après l'avoir entendue (la
/// borne de la connexion, elle, reste). Sans voisine, rien ne dit qu'il n'y en a pas : oubliées. Un noyau qui ne dit
/// pas l'âge (avant 3.x) garde de toute façon ce délai : récentes.
#[cfg(any(target_os = "linux", test))]
fn voisins_du_cache(vues: &[(Balise, Option<u32>)]) -> Voisins {
    let voisines: Vec<Option<u32>> = vues
        .iter()
        .filter(|(b, _)| !b.borne.actif)
        .map(|(_, age)| *age)
        .collect();
    if voisines.is_empty() {
        return Voisins::Oublies;
    }
    match voisines.iter().flatten().min() {
        Some(&ms) => Voisins::selon_age(u64::from(ms) / 1000),
        None => Voisins::Recents,
    }
}

/// L'état de l'économie d'énergie dans la réponse à NL80211_CMD_GET_POWER_SAVE.
#[cfg(any(target_os = "linux", test))]
fn etat_economie(reponse: &[u8], famille: u16) -> Option<bool> {
    messages(reponse)
        .filter(|(genre, _, _)| *genre == famille)
        .find_map(|(_, _, corps)| {
            attributs(corps.get(4..)?)
                .find(|(g, _)| *g == NL80211_ATTR_PS_STATE)
                .and_then(|(_, c)| u32_ne(c))
        })
        .map(|etat| etat == NL80211_PS_ENABLED)
}

/// Le morceau reçu finit-il la réponse ? `Some(true)` : fin de liste, ou réponse unique ; `Some(false)` : le noyau
/// refuse (NLMSG_ERROR) ; `None` : la suite vient.
#[cfg(any(target_os = "linux", test))]
fn fin(morceau: &[u8]) -> Option<bool> {
    messages(morceau).find_map(|(genre, drapeaux, corps)| match genre {
        NLMSG_ERROR => Some(corps.first_chunk::<4>().is_some_and(|&e| i32::from_ne_bytes(e) == 0)),
        NLMSG_DONE => Some(true),
        NLMSG_NOOP => None,
        _ if drapeaux & NLM_F_MULTI == 0 => Some(true),
        _ => None,
    })
}

/// Envoie une demande au noyau par netlink générique et rend ses réponses, jusqu'à la fin de la liste. `None` : le
/// noyau refuse la socket, la demande, ou ne répond pas en 3 s.
#[cfg(target_os = "linux")]
fn echanger(demande: &[u8]) -> Option<Vec<u8>> {
    // SAFETY : une socket netlink ouverte ici et refermée une seule fois à la sortie ; chaque appel reçoit un pointeur
    // et la taille exacte d'un objet à nous, vivant pendant l'appel (demande, adresse, délai, tampon). Le délai de
    // réception (3 s) empêche recv de bloquer sans fin si le noyau ne répondait pas.
    unsafe {
        let s = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_GENERIC,
        );
        if s < 0 {
            return None;
        }
        let delai = libc::timeval { tv_sec: 3, tv_usec: 0 };
        let taille = |t: usize| libc::socklen_t::try_from(t).unwrap_or(0);
        libc::setsockopt(
            s,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const delai).cast(),
            taille(std::mem::size_of::<libc::timeval>()),
        );
        let mut adresse: libc::sockaddr_nl = std::mem::zeroed();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        {
            adresse.nl_family = libc::AF_NETLINK as u16;
        }
        let envoye = libc::sendto(
            s,
            demande.as_ptr().cast(),
            demande.len(),
            0,
            (&raw const adresse).cast(),
            taille(std::mem::size_of::<libc::sockaddr_nl>()),
        );
        let mut tout = Vec::new();
        let mut resultat = None;
        if usize::try_from(envoye).ok() == Some(demande.len()) {
            // Le noyau livre un balayage par morceaux de 32 Ko au plus : 64 Ko reçoivent chacun entier.
            let mut tampon = vec![0u8; 64 << 10];
            loop {
                let n = libc::recv(s, tampon.as_mut_ptr().cast(), tampon.len(), 0);
                let Ok(n @ 1..) = usize::try_from(n) else {
                    break;
                };
                // recv n'écrit jamais plus que le tampon.
                let Some(recu) = tampon.get(..n) else {
                    break;
                };
                tout.extend_from_slice(recu);
                match fin(recu) {
                    Some(true) => {
                        resultat = Some(std::mem::take(&mut tout));
                        break;
                    }
                    Some(false) => break,
                    None if tout.len() > TAILLE_MAX => break,
                    None => {}
                }
            }
        }
        libc::close(s);
        resultat
    }
}

/// Le numéro de la famille nl80211, demandé au contrôleur de netlink générique.
#[cfg(target_os = "linux")]
fn famille() -> Result<u16, &'static str> {
    use crate::tr;
    let controleur = demande(
        GENL_ID_CTRL,
        NLM_F_REQUEST,
        CTRL_CMD_GETFAMILY,
        &[(CTRL_ATTR_FAMILY_NAME, b"nl80211\0")],
    );
    let Some(reponse) = echanger(&controleur) else {
        return Err(tr!("le noyau refuse netlink", "the kernel refuses netlink"));
    };
    identifiant_famille(&reponse).ok_or(tr!(
        "pas de pile Wi-Fi dans le noyau (nl80211 absent)",
        "no Wi-Fi stack in the kernel (nl80211 missing)"
    ))
}

/// Les cartes Wi-Fi clientes du noyau.
#[cfg(target_os = "linux")]
fn stations(famille: u16) -> Vec<Interface> {
    let liste = demande(famille, NLM_F_REQUEST | NLM_F_DUMP, NL80211_CMD_GET_INTERFACE, &[]);
    echanger(&liste)
        .map(|r| interfaces(&r, famille))
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.station)
        .collect()
}

/// Ce que le noyau a entendu : les bornes du dernier balayage de chaque carte Wi-Fi cliente, et la connexion en
/// cours. `Err` : pas de Wi-Fi ici, ou netlink refusé, avec la raison à montrer.
#[cfg(target_os = "linux")]
pub(crate) fn lire() -> Result<Lecture, &'static str> {
    use crate::tr;
    let famille = famille()?;
    let stations = stations(famille);
    if stations.is_empty() {
        return Err(tr!(
            "pas de carte Wi-Fi sur cet ordinateur",
            "no Wi-Fi card on this computer"
        ));
    }
    let mut lecture = Lecture::default();
    let mut vues: Vec<(Balise, Option<u32>)> = Vec::new();
    for i in &stations {
        let scan = demande(
            famille,
            NLM_F_REQUEST | NLM_F_DUMP,
            NL80211_CMD_GET_SCAN,
            &[(NL80211_ATTR_IFINDEX, &i.index.to_ne_bytes())],
        );
        let bornes = echanger(&scan).map(|r| balises_vues(&r, famille)).unwrap_or_default();
        if lecture.connexion.is_none() {
            let seules: Vec<Balise> = bornes.iter().map(|(b, _)| b.clone()).collect();
            lecture.connexion = connexion(i, &seules);
        }
        for (b, age) in bornes {
            if !vues
                .iter()
                .any(|(d, _)| d.borne.bssid == b.borne.bssid && d.borne.canal == b.borne.canal)
            {
                vues.push((b, age));
            }
        }
    }
    lecture.voisins = voisins_du_cache(&vues);
    lecture.balises = vues.into_iter().map(|(b, _)| b).collect();
    Ok(lecture)
}

/// Le nom du réseau connecté, que le noyau donne avec l'interface (GET_INTERFACE seul, sans le balayage).
#[cfg(target_os = "linux")]
pub(crate) fn reseau_connecte() -> Option<String> {
    stations(famille().ok()?).into_iter().find_map(|i| i.ssid)
}

/// L'économie d'énergie de la carte `carte` (« wlan0 »), comme `iw dev wlan0 get power_save`, sans droits.
/// `None` : carte inconnue, ou le pilote ne le dit pas.
#[cfg(target_os = "linux")]
pub(crate) fn economie_d_energie(carte: &str) -> Option<bool> {
    let nom = std::ffi::CString::new(carte).ok()?;
    // SAFETY : if_nametoindex lit un nom C terminé par un zéro, à nous et vivant pendant l'appel ; 0 dit l'échec.
    let index = unsafe { libc::if_nametoindex(nom.as_ptr()) };
    if index == 0 {
        return None;
    }
    let famille = famille().ok()?;
    let d = demande(
        famille,
        NLM_F_REQUEST,
        NL80211_CMD_GET_POWER_SAVE,
        &[(NL80211_ATTR_IFINDEX, &index.to_ne_bytes())],
    );
    etat_economie(&echanger(&d)?, famille)
}

/// La connexion d'une carte : la borne que le noyau dit associée (son nom, sinon celui que l'interface porte), ou le
/// seul nom de l'interface quand le balayage ne la montre plus.
#[cfg(any(target_os = "linux", test))]
fn connexion(interface: &Interface, bornes: &[Balise]) -> Option<Connexion> {
    let nom_interface = interface.ssid.clone().unwrap_or_default();
    match bornes.iter().find(|b| b.borne.actif) {
        Some(b) => Some(Connexion {
            ssid: if b.borne.ssid.is_empty() {
                nom_interface
            } else {
                b.borne.ssid.clone()
            },
            bssid: b.borne.bssid.clone(),
            ..Connexion::default()
        }),
        None if !nom_interface.is_empty() => Some(Connexion {
            ssid: nom_interface,
            ..Connexion::default()
        }),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::super::elements::fabrique;
    use super::*;

    fn attribut(genre: u16, contenu: &[u8]) -> Vec<u8> {
        let mut a = u16::try_from(4 + contenu.len()).unwrap().to_ne_bytes().to_vec();
        a.extend_from_slice(&genre.to_ne_bytes());
        a.extend_from_slice(contenu);
        a.resize(a.len().next_multiple_of(4), 0);
        a
    }

    /// Un message netlink générique : type, drapeaux, commande, attributs.
    fn message(genre: u16, drapeaux: u16, commande: u8, attributs: &[Vec<u8>]) -> Vec<u8> {
        let mut m = demande(genre, drapeaux, commande, &[]);
        for a in attributs {
            m.extend_from_slice(a);
        }
        let total = u32::try_from(m.len()).unwrap();
        m[0..4].copy_from_slice(&total.to_ne_bytes());
        m
    }

    fn message_fin() -> Vec<u8> {
        message(NLMSG_DONE, NLM_F_MULTI, 0, &[])
    }

    /// Un résultat de balayage : BSSID, fréquence, capacités, éléments, signal en mBm, associé ou non.
    fn resultat(famille: u16, bssid: [u8; 6], mhz: u32, capacites: u16, ies: &[u8], mbm: i32, actif: bool) -> Vec<u8> {
        let mut bss = [
            attribut(NL80211_BSS_BSSID, &bssid),
            attribut(NL80211_BSS_FREQUENCY, &mhz.to_ne_bytes()),
            attribut(NL80211_BSS_CAPABILITY, &capacites.to_ne_bytes()),
            attribut(NL80211_BSS_INFORMATION_ELEMENTS, ies),
            attribut(NL80211_BSS_SIGNAL_MBM, &mbm.to_ne_bytes()),
        ]
        .concat();
        if actif {
            bss.extend(attribut(
                NL80211_BSS_STATUS,
                &NL80211_BSS_STATUS_ASSOCIATED.to_ne_bytes(),
            ));
        }
        message(
            famille,
            NLM_F_MULTI,
            NL80211_CMD_NEW_SCAN_RESULTS,
            &[attribut(NL80211_ATTR_BSS | 0x8000, &bss)],
        )
    }

    #[test]
    fn demande_bien_formee() {
        let d = demande(
            0x10,
            NLM_F_REQUEST,
            CTRL_CMD_GETFAMILY,
            &[(CTRL_ATTR_FAMILY_NAME, b"nl80211\0")],
        );
        // 16 (netlink) + 4 (générique) + 4 + 8 (attribut, déjà multiple de 4).
        assert_eq!(d.len(), 32);
        assert_eq!(u32_ne(&d), Some(32));
        assert_eq!(u16_ne(&d[4..]), Some(0x10));
        assert_eq!(&d[16..20], &[CTRL_CMD_GETFAMILY, 1, 0, 0]);
        let (genre, contenu) = attributs(&d[20..]).next().unwrap();
        assert_eq!((genre, contenu), (CTRL_ATTR_FAMILY_NAME, &b"nl80211\0"[..]));
        // Un attribut de 5 octets est bourré à 8.
        let d = demande(
            22,
            NLM_F_REQUEST | NLM_F_DUMP,
            NL80211_CMD_GET_SCAN,
            &[(NL80211_ATTR_IFINDEX, &[3, 0, 0, 0, 0])],
        );
        assert_eq!(d.len(), 20 + 12);
    }

    #[test]
    fn famille_interfaces_et_fin() {
        let reponse = message(
            GENL_ID_CTRL,
            0,
            1,
            &[attribut(CTRL_ATTR_FAMILY_ID, &22u16.to_ne_bytes())],
        );
        assert_eq!(identifiant_famille(&reponse), Some(22));
        assert_eq!(fin(&reponse), Some(true));
        assert_eq!(identifiant_famille(&message(GENL_ID_CTRL, 0, 1, &[])), None);
        let station = message(
            22,
            NLM_F_MULTI,
            NL80211_CMD_NEW_INTERFACE,
            &[
                attribut(NL80211_ATTR_IFINDEX, &3u32.to_ne_bytes()),
                attribut(NL80211_ATTR_IFNAME, b"wlan0\0"),
                attribut(NL80211_ATTR_IFTYPE, &NL80211_IFTYPE_STATION.to_ne_bytes()),
                attribut(NL80211_ATTR_SSID, b"Salon"),
            ],
        );
        let moniteur = message(
            22,
            NLM_F_MULTI,
            NL80211_CMD_NEW_INTERFACE,
            &[
                attribut(NL80211_ATTR_IFINDEX, &4u32.to_ne_bytes()),
                attribut(NL80211_ATTR_IFNAME, b"mon0\x1b[2K\0"),
                attribut(NL80211_ATTR_IFTYPE, &6u32.to_ne_bytes()),
            ],
        );
        let tout = [station, moniteur.clone(), message_fin()].concat();
        assert_eq!(fin(&tout[..tout.len() - 20]), None);
        assert_eq!(fin(&tout), Some(true));
        let lues = interfaces(&tout, 22);
        assert_eq!(
            lues,
            [
                Interface {
                    index: 3,
                    nom: "wlan0".into(),
                    station: true,
                    ssid: Some("Salon".into())
                },
                Interface {
                    index: 4,
                    nom: "mon0�[2K".into(),
                    station: false,
                    ssid: None
                }
            ]
        );
        // Une autre famille, ou une autre commande : rien.
        assert_eq!(interfaces(&tout, 23), [] as [Interface; 0]);
        let balayage = message(22, NLM_F_MULTI, NL80211_CMD_NEW_SCAN_RESULTS, &[]);
        assert_eq!(interfaces(&balayage, 22), [] as [Interface; 0]);
        // Un refus du noyau.
        let erreur = message(NLMSG_ERROR, 0, 0, &[]);
        let mut refus = erreur.clone();
        refus.extend_from_slice(&(-19i32).to_ne_bytes());
        let total = u32::try_from(refus.len()).unwrap();
        refus[0..4].copy_from_slice(&total.to_ne_bytes());
        assert_eq!(fin(&refus), Some(false));
        assert_eq!(fin(&[]), None);
    }

    #[test]
    fn balayage_lu() {
        let salon = fabrique::box_ordinaire("Salon");
        let voisin = [fabrique::ssid("Voisin"), fabrique::rsn(2, &[2, 4], &[2], 0)].concat();
        let reponse = [
            resultat(22, [2, 0, 0, 0xAA, 0xBB, 1], 5180, 0x0411, &salon, -4500, true),
            resultat(22, [2, 0, 0, 0xAA, 0xBB, 2], 2437, 0x0411, &voisin, -8100, false),
            resultat(
                22,
                [2, 0, 0, 0xAA, 0xBB, 3],
                2412,
                0x0401,
                &fabrique::ssid("Café"),
                -6000,
                false,
            ),
            message_fin(),
        ]
        .concat();
        let b = balises(&reponse, 22);
        assert_eq!(b.len(), 3);
        assert_eq!(b[0].borne.bssid, "02:00:00:aa:bb:01");
        assert_eq!(
            (b[0].borne.canal, b[0].borne.bande, b[0].borne.signal),
            (36, Bande::G5, Some(100))
        );
        assert!(b[0].borne.actif && b[0].protection.aes && !b[0].protection.tkip);
        assert_eq!(b[0].wps.map(|w| w.etat), Some(2));
        assert!(!b[1].borne.actif && b[1].protection.tkip && b[1].wps.is_none());
        assert_eq!((b[1].borne.canal, b[1].borne.signal), (6, Some(38)));
        assert_eq!(b[2].protection.force(), 0);
        assert_eq!(b[2].borne.ssid, "Café");
        let interface = Interface {
            index: 3,
            nom: "wlan0".into(),
            station: true,
            ssid: None,
        };
        assert_eq!(
            connexion(&interface, &b),
            Some(Connexion {
                ssid: "Salon".into(),
                bssid: "02:00:00:aa:bb:01".into(),
                ..Connexion::default()
            })
        );
        // Sans borne associée : le nom que l'interface porte, sinon rien.
        assert_eq!(connexion(&interface, &b[1..]), None);
        let avec_nom = Interface {
            ssid: Some("Salon".into()),
            ..interface
        };
        assert_eq!(connexion(&avec_nom, &b[1..]).map(|c| c.bssid), Some(String::new()));
    }

    #[test]
    fn balayage_avec_balise_et_sondage() {
        // La réponse de sondage porte les méthodes WPS, la balise seulement l'état : les deux se complètent ; un
        // réseau caché dans le sondage prend le nom de la balise.
        let sondage = fabrique::wps(&[(0x1044, &[2]), (0x1008, &0x0080u16.to_be_bytes())]);
        let balise_ies = [
            fabrique::ssid("Salon"),
            fabrique::rsn(4, &[4], &[2], 0),
            fabrique::wps(&[(0x1044, &[2])]),
        ]
        .concat();
        let bss = [
            attribut(NL80211_BSS_BSSID, &[2, 0, 0, 0xAA, 0xBB, 1]),
            attribut(NL80211_BSS_FREQUENCY, &2437u32.to_ne_bytes()),
            attribut(NL80211_BSS_INFORMATION_ELEMENTS, &sondage),
            attribut(NL80211_BSS_BEACON_IES, &balise_ies),
            attribut(NL80211_BSS_SIGNAL_UNSPEC, &[70]),
        ]
        .concat();
        let b = balise(&bss).unwrap();
        assert_eq!(b.borne.ssid, "");
        assert_eq!(b.borne.signal, Some(70));
        assert_eq!(b.wps.and_then(Wps::pin), Some(false));
        // Sans fréquence : pas de borne.
        assert!(balise(&attribut(NL80211_BSS_BSSID, &[2, 0, 0, 0xAA, 0xBB, 1])).is_none());
        // Un signal « unspec » de plus de 100 est borné.
        let bss = [
            attribut(NL80211_BSS_FREQUENCY, &2437u32.to_ne_bytes()),
            attribut(NL80211_BSS_SIGNAL_UNSPEC, &[255]),
        ]
        .concat();
        assert_eq!(balise(&bss).unwrap().borne.signal, Some(100));
    }

    #[test]
    fn age_des_bornes_et_valeur_de_la_liste() {
        let avec_age = |actif: bool, mac: u8, ms: Option<u32>| {
            let mut bss = [
                attribut(NL80211_BSS_BSSID, &[2, 0, 0, 0xAA, 0xBB, mac]),
                attribut(NL80211_BSS_FREQUENCY, &2437u32.to_ne_bytes()),
                attribut(NL80211_BSS_INFORMATION_ELEMENTS, &fabrique::ssid("Salon")),
            ]
            .concat();
            if let Some(ms) = ms {
                bss.extend(attribut(NL80211_BSS_SEEN_MS_AGO, &ms.to_ne_bytes()));
            }
            if actif {
                bss.extend(attribut(
                    NL80211_BSS_STATUS,
                    &NL80211_BSS_STATUS_ASSOCIATED.to_ne_bytes(),
                ));
            }
            message(
                22,
                NLM_F_MULTI,
                NL80211_CMD_NEW_SCAN_RESULTS,
                &[attribut(NL80211_ATTR_BSS | 0x8000, &bss)],
            )
        };
        let reponse = [
            avec_age(true, 1, Some(900_000)),
            avec_age(false, 2, Some(12_000)),
            avec_age(false, 3, Some(4_000)),
            message_fin(),
        ]
        .concat();
        let vues = balises_vues(&reponse, 22);
        assert_eq!(
            vues.iter().map(|(_, a)| *a).collect::<Vec<_>>(),
            [Some(900_000), Some(12_000), Some(4_000)]
        );
        assert_eq!(voisins_du_cache(&vues), Voisins::Recents);
        // Seule la borne de la connexion reste : les voisines sont oubliées, rien ne dit qu'il n'y en a pas.
        assert_eq!(voisins_du_cache(&vues[..1]), Voisins::Oublies);
        assert_eq!(voisins_du_cache(&[]), Voisins::Oublies);
        // Une voisine entendue il y a longtemps ; une sans âge (vieux noyau).
        let vieille = balises_vues(&[avec_age(false, 2, Some(1_500_000)), message_fin()].concat(), 22);
        assert_eq!(voisins_du_cache(&vieille), Voisins::Anciens { minutes: 25 });
        let sans_age = balises_vues(&[avec_age(false, 2, None), message_fin()].concat(), 22);
        assert_eq!(voisins_du_cache(&sans_age), Voisins::Recents);
    }

    #[test]
    fn economie_d_energie_lue() {
        let reponse = |etat: u32| {
            message(
                22,
                0,
                NL80211_CMD_GET_POWER_SAVE,
                &[attribut(NL80211_ATTR_PS_STATE, &etat.to_ne_bytes())],
            )
        };
        assert_eq!(etat_economie(&reponse(1), 22), Some(true));
        assert_eq!(etat_economie(&reponse(0), 22), Some(false));
        assert_eq!(fin(&reponse(1)), Some(true));
        // Une autre famille, ou sans l'attribut : rien.
        assert_eq!(etat_economie(&reponse(1), 23), None);
        assert_eq!(
            etat_economie(&message(22, 0, NL80211_CMD_GET_POWER_SAVE, &[]), 22),
            None
        );
        let r = reponse(1);
        for n in 0..r.len() {
            let _ = etat_economie(&r[..n], 22);
        }
        // La demande : la commande 62 et le numéro de l'interface.
        let d = demande(
            22,
            NLM_F_REQUEST,
            NL80211_CMD_GET_POWER_SAVE,
            &[(NL80211_ATTR_IFINDEX, &3u32.to_ne_bytes())],
        );
        assert_eq!(d[16], 62);
        assert_eq!(
            attributs(&d[20..]).next(),
            Some((NL80211_ATTR_IFINDEX, &3u32.to_ne_bytes()[..]))
        );
    }

    /// Le vrai noyau contre iw : la même économie d'énergie pour chaque carte. Sauté sans iw ni carte ; rien de lu
    /// n'est affiché.
    #[cfg(target_os = "linux")]
    #[test]
    fn economie_comme_iw() {
        let cartes: Vec<String> = std::fs::read_dir("/sys/class/net")
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| e.path().join("wireless").is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        let mut comparees = 0;
        for carte in cartes {
            let Some(r) = crate::commande::lancer(
                std::process::Command::new("iw")
                    .args(["dev", &carte, "get", "power_save"])
                    .env("LC_ALL", "C"),
                10,
            )
            .filter(|r| r.code == Some(0)) else {
                continue;
            };
            let iw = r.sortie.split(':').nth(1).map(|v| v.trim() == "on");
            assert_eq!(economie_d_energie(&carte), iw);
            comparees += 1;
        }
        if comparees == 0 {
            crate::essais::saute("ni iw ni carte Wi-Fi");
        }
    }

    /// Le réseau connecté selon le noyau, contre celui que nmcli dit actif ; comparés sans être montrés.
    #[cfg(target_os = "linux")]
    #[test]
    fn reseau_connecte_comme_nmcli() {
        let Some(r) = crate::commande::lancer_en_anglais(
            std::process::Command::new("nmcli").args([
                "-t",
                "-e",
                "no",
                "-f",
                "ACTIVE,SSID",
                "dev",
                "wifi",
                "list",
                "--rescan",
                "no",
            ]),
            20,
        )
        .filter(|r| r.code == Some(0)) else {
            return crate::essais::saute("nmcli absent");
        };
        let nmcli = r.sortie.lines().find_map(|l| l.strip_prefix("yes:")).map(affichable);
        // Le noyau ne donne le nom avec l'interface que depuis Linux 4.x ; sans lui, rien à comparer.
        let Some(natif) = reseau_connecte() else {
            return crate::essais::saute("le noyau ne dit pas le réseau connecté");
        };
        assert!(Some(natif) == nmcli, "réseau connecté différent de nmcli");
    }

    #[test]
    fn messages_abimes_sans_plantage() {
        let reponse = [
            resultat(
                22,
                [2, 0, 0, 0xAA, 0xBB, 1],
                5180,
                0x0411,
                &fabrique::box_ordinaire("Salon"),
                -4500,
                true,
            ),
            message_fin(),
        ]
        .concat();
        for n in 0..reponse.len() {
            let _ = balises(&reponse[..n], 22);
            let _ = interfaces(&reponse[..n], 22);
            let _ = identifiant_famille(&reponse[..n]);
            let _ = fin(&reponse[..n]);
        }
        // Une longueur de message nulle, ou démesurée.
        let mut faux = reponse.clone();
        faux[0..4].copy_from_slice(&0u32.to_ne_bytes());
        assert_eq!(balises(&faux, 22), [] as [Balise; 0]);
        faux[0..4].copy_from_slice(&u32::MAX.to_ne_bytes());
        assert_eq!(balises(&faux, 22), [] as [Balise; 0]);
        assert_eq!(messages(&faux).count(), 0);
    }

    /// Le vrai noyau : avec une carte Wi-Fi, chaque borne lue a une adresse, un signal borné et un nom inoffensif ;
    /// sans (serveur, conteneur, espace réseau vide), la raison est dite. Rien de ce qui est lu n'est affiché.
    #[cfg(target_os = "linux")]
    #[test]
    fn lecture_reelle_du_noyau() {
        match lire() {
            Ok(l) => {
                for b in &l.balises {
                    assert_eq!(b.borne.bssid.len(), 17, "BSSID mal formé");
                    assert!(b.borne.signal.is_none_or(|s| s <= 100));
                    assert!(!crate::ui::contient_un_piege(&b.borne.ssid));
                    assert!(b.protection.force() <= 3);
                }
                if let Some(c) = &l.connexion {
                    assert!(!crate::ui::contient_un_piege(&c.ssid));
                }
            }
            Err(raison) => assert_ne!(raison, ""),
        }
    }

    /// `cargo test -- --ignored resume_du_noyau --nocapture` : ce que le noyau donne ici, en nombres seulement.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "lecture de la machine, à lancer à la main"]
    fn resume_du_noyau() {
        match lire() {
            Ok(l) => {
                println!("bornes : {}, connecté : {}", l.balises.len(), l.connexion.is_some());
                for b in &l.balises {
                    println!(
                        "  {} canal {:>3} signal {:?} {} tkip={} wps={:?} pin={:?} actif={}",
                        b.borne.bande.libelle(),
                        b.borne.canal,
                        b.borne.signal,
                        b.protection.libelle(),
                        b.protection.tkip,
                        b.wps.map(|w| w.etat),
                        b.wps.and_then(Wps::pin),
                        b.borne.actif
                    );
                }
            }
            Err(raison) => println!("non vérifié : {raison}"),
        }
    }
}
