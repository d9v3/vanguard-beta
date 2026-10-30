//! Découverte des machines et scan TCP « connect » (aucun privilège root requis).

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::stream::{self, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::risk::PORTS_HTTP;
use crate::ui::affichable;
use crate::{tr, trf};

/// Résultat d'une tentative de connexion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    Ouvert,
    Ferme,
    Filtre,
}

pub async fn sonder(ip: Ipv4Addr, port: u16, delai: Duration) -> (Etat, Option<TcpStream>) {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    match timeout(delai, TcpStream::connect(addr)).await {
        Ok(Ok(flux)) => (Etat::Ouvert, Some(flux)),
        // Un RST prouve que la machine existe, même si le port est fermé.
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => (Etat::Ferme, None),
        _ => (Etat::Filtre, None),
    }
}

/// Nombre de connexions simultanées réellement possible : chaque connexion consomme un descripteur
/// de fichier, et certains systèmes n'en autorisent que 256 par défaut. On relève la limite si le système le permet.
pub fn limite_connexions(demande: usize) -> usize {
    // SAFETY: getrlimit et setrlimit lisent et écrivent la structure locale `lim`, passée par pointeur valide.
    #[cfg(unix)]
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) == 0 {
            let voulu = (demande as libc::rlim_t + 128).min(lim.rlim_max);
            if lim.rlim_cur < voulu {
                lim.rlim_cur = voulu;
                libc::setrlimit(libc::RLIMIT_NOFILE, &raw const lim);
                libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim);
            }
            // On garde une marge pour stdin/stdout, les fichiers lus et les sockets DNS.
            return demande
                .min(usize::try_from(lim.rlim_cur).unwrap_or(usize::MAX).saturating_sub(64))
                .max(16);
        }
    }
    demande
}

/// Plage d'adresses IPv4 à partir de « 10.0.0.5 », « 10.0.0.0/24 » ou « 10.0.0.1-50 ».
pub fn parse_cible(cible: &str) -> Result<Vec<Ipv4Addr>, String> {
    if let Some((ip, pref)) = cible.split_once('/') {
        let ip: Ipv4Addr = ip.parse().map_err(|_| trf!("IP invalide : {ip}", "invalid IP: {ip}"))?;
        let pref: u32 = pref
            .parse()
            .map_err(|_| trf!("préfixe invalide : {pref}", "invalid prefix: {pref}"))?;
        if !(16..=32).contains(&pref) {
            return Err(tr!("préfixe accepté : /16 à /32", "accepted prefix: /16 to /32").into());
        }
        let masque = if pref == 32 { u32::MAX } else { !(u32::MAX >> pref) };
        let reseau = u32::from(ip) & masque;
        let diffusion = reseau | !masque;
        if pref >= 31 {
            return Ok((reseau..=diffusion).map(Ipv4Addr::from).collect());
        }
        return Ok((reseau + 1..diffusion).map(Ipv4Addr::from).collect());
    }
    if let Some((debut, fin)) = cible.split_once('-') {
        let debut: Ipv4Addr = debut
            .parse()
            .map_err(|_| trf!("IP invalide : {debut}", "invalid IP: {debut}"))?;
        let fin: u8 = fin
            .parse()
            .map_err(|_| trf!("fin de plage invalide : {fin}", "invalid end of range: {fin}"))?;
        let o = debut.octets();
        if fin < o[3] {
            return Err(trf!(
                "plage invalide : {cible} (la fin doit être ≥ {})",
                "invalid range: {cible} (the end must be ≥ {})",
                o[3]
            ));
        }
        return Ok((o[3]..=fin).map(|d| Ipv4Addr::new(o[0], o[1], o[2], d)).collect());
    }
    cible
        .parse()
        .map(|ip| vec![ip])
        .map_err(|_| trf!("cible invalide : {cible}", "invalid target: {cible}"))
}

/// Réseau local de l'interface principale (ex. 10.0.0.0/24) et IP de cette machine.
/// On préfère l'interface qui contient la passerelle (évite Docker, Hyper-V, VirtualBox…).
pub fn reseau_local() -> Option<(String, Ipv4Addr)> {
    let gw = passerelle().map(u32::from);
    let candidats: Vec<_> = if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !v4.ip.is_link_local() => Some(v4),
            _ => None,
        })
        .collect();
    let candidats: Vec<(Ipv4Addr, Ipv4Addr)> = candidats.iter().map(|v4| (v4.ip, v4.netmask)).collect();
    choisir_reseau(&candidats, gw)
}

/// Le réseau à scanner parmi les interfaces (adresse, masque) : celle de la passerelle, sinon la première. Une
/// interface en /31 ou /32 (VPN, WireGuard, lien point à point) n'est pas un réseau local : elle est laissée, sinon
/// le calcul du réseau débordait (`u32::MAX >> 32`) et le scan visait 0.0.0.0/32.
fn choisir_reseau(candidats: &[(Ipv4Addr, Ipv4Addr)], gw: Option<u32>) -> Option<(String, Ipv4Addr)> {
    let candidats: Vec<(Ipv4Addr, u32)> = candidats
        .iter()
        .map(|&(ip, masque)| (ip, u32::from(masque)))
        .filter(|(_, masque)| masque.count_ones() <= 30)
        .collect();
    let &(ip, masque) = candidats
        .iter()
        .find(|(ip, masque)| gw.is_some_and(|g| g & masque == u32::from(*ip) & masque))
        .or(candidats.first())?;
    // Réseau plus grand qu'un /16 (10.0.0.0/8…) : on scanne le /16 qui contient cette machine. Le calculer
    // avec le masque d'origine donnait 10.0.0.0/16 même pour l'IP 10.5.3.2, donc le mauvais morceau.
    let pref = masque.count_ones().max(16);
    let reseau = Ipv4Addr::from(u32::from(ip) & !(u32::MAX >> pref));
    Some((format!("{reseau}/{pref}"), ip))
}

#[cfg(not(target_os = "linux"))]
fn commande(cmd: &str, args: &[&str]) -> String {
    crate::commande::lancer(crate::commande::systeme(cmd).args(args), 10)
        .map(|r| r.sortie)
        .unwrap_or_default()
}

/// Passerelle par défaut (la box / le routeur).
pub fn passerelle() -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        passerelle_linux(&table)
    }
    // La table des routes de Windows (GetIpForwardTable2), métriques de route et d'interface additionnées comme
    // route print le fait ; route print seulement si Windows refuse la table.
    #[cfg(windows)]
    if let Some(p) = crate::machine::windows::routes::passerelle() {
        return Some(p);
    }
    #[cfg(windows)]
    {
        // Ligne « 0.0.0.0  0.0.0.0  <passerelle>  <interface>  <métrique> » ; la plus petite métrique gagne.
        commande("route", &["print", "-4", "0.0.0.0"])
            .lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                match c.as_slice() {
                    ["0.0.0.0", "0.0.0.0", passerelle, _, metrique, ..] => {
                        Some((metrique.parse::<u32>().ok()?, passerelle.parse::<Ipv4Addr>().ok()?))
                    }
                    _ => None,
                }
            })
            .min()
            .map(|(_, ip)| ip)
    }
    // macOS : la route par défaut lue dans la table du noyau (sysctl NET_RT_DUMP) ; « gateway: 10.0.0.1 » de
    // `route -n get default` en secours, tant que l'oracle de macos.yml n'a pas prouvé la lecture native.
    #[cfg(target_os = "macos")]
    {
        crate::machine::macos::noyau::passerelle()
            .or_else(
                || match crate::machine::macos::config_reseau::principal()?.passerelle? {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                },
            )
            .or_else(|| {
                commande("route", &["-n", "get", "default"])
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("gateway:"))
                    .and_then(|g| g.trim().parse().ok())
            })
    }
}

/// Route par défaut dans /proc/net/route (Iface Destination Gateway Flags RefCnt Use Metric…).
/// Seules les routes « via une passerelle » comptent (un VPN « default dev tun0 » a la passerelle 0.0.0.0),
/// et avec Ethernet + Wi-Fi, la plus petite métrique gagne, comme pour le système.
#[cfg(any(target_os = "linux", test))]
fn passerelle_linux(table: &str) -> Option<Ipv4Addr> {
    const RTF_UP: u32 = 0x1;
    const RTF_GATEWAY: u32 = 0x2;
    table
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let hex = |i: usize| u32::from_str_radix(c.get(i)?, 16).ok();
            let (dest, gw, drapeaux) = (hex(1)?, hex(2)?, hex(3)?);
            let metrique: u32 = c.get(6)?.parse().ok()?;
            let utile = dest == 0 && gw != 0 && drapeaux & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY;
            utile.then_some((metrique, Ipv4Addr::from(gw.swap_bytes())))
        })
        .min()
        .map(|(_, ip)| ip)
}

/// Normalise une MAC en « aa:bb:cc:dd:ee:ff » (« a:b:… » sans zéros, Windows « aa-bb-… »).
fn normaliser_mac(brut: &str) -> Option<String> {
    let parties: Vec<String> = brut
        .split([':', '-'])
        .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
        .collect();
    let mac = parties.join(":");
    let valide = parties.len() == 6
        && parties
            .iter()
            .all(|p| p.len() == 2 && u8::from_str_radix(p, 16).is_ok());
    // On écarte diffusion et multicast, qui ne sont pas des appareils.
    let multicast = parties
        .first()
        .is_some_and(|p| u8::from_str_radix(p, 16).is_ok_and(|o| o & 1 == 1));
    (valide && !multicast && mac != "00:00:00:00:00:00").then_some(mac)
}

/// Table ARP du système : IP → adresse MAC (entrées complètes seulement).
pub fn table_arp() -> HashMap<Ipv4Addr, String> {
    #[cfg(target_os = "linux")]
    let entrees: Vec<(String, String)> = std::fs::read_to_string("/proc/net/arp")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.get(2) == Some(&"0x2"))
                .then(|| Some((c.first()?.to_string(), c.get(3)?.to_string())))
                .flatten()
        })
        .collect();
    // macOS : la table ARP du noyau (sysctl, RTF_LLINFO), par la même lecture des messages de route que la passerelle
    // (`machine::darwin`) ; `arp -an` en secours (« ? (10.0.0.1) at f8:79:a:d:3:a2 on
    // en0 ifscope [ethernet] », « (incomplete) » sans réponse).
    #[cfg(target_os = "macos")]
    let entrees: Vec<(String, String)> = match crate::machine::macos::noyau::voisins() {
        Some(v) => v
            .into_iter()
            .map(|v| {
                let mac: Vec<String> = v.mac.iter().map(|o| format!("{o:02x}")).collect();
                (v.ip.to_string(), mac.join(":"))
            })
            .collect(),
        None => commande("arp", &["-an"])
            .lines()
            .filter_map(|l| {
                let ip = l.split_once('(')?.1.split_once(')')?.0;
                let mac = l.split_once(" at ")?.1.split_whitespace().next()?;
                Some((ip.to_string(), mac.to_string()))
            })
            .collect(),
    };
    // Windows : la table des voisins (GetIpNetTable2) ; `arp -a` (« 10.0.0.1   f8-79-0a-0d-03-a2   dynamique »)
    // seulement si Windows la refuse.
    #[cfg(windows)]
    let entrees: Vec<(String, String)> = match crate::machine::windows::routes::voisins() {
        Some(v) => v.into_iter().map(|(ip, mac)| (ip.to_string(), mac)).collect(),
        None => commande("arp", &["-a"])
            .lines()
            .filter_map(|l| {
                let c: Vec<&str> = l.split_whitespace().collect();
                Some((c.first()?.to_string(), c.get(1)?.to_string()))
            })
            .collect(),
    };

    entrees
        .into_iter()
        .filter_map(|(ip, mac)| Some((ip.parse().ok()?, normaliser_mac(&mac)?)))
        .collect()
}

/// Trouve les machines actives : une réponse TCP (ouvert ou RST) ou une entrée ARP suffit.
pub async fn decouvrir(ips: &[Ipv4Addr], delai: Duration, parallele: usize) -> Vec<Ipv4Addr> {
    let essais = ips
        .iter()
        .flat_map(|&ip| crate::risk::PORTS_DECOUVERTE.iter().map(move |&p| (ip, p)));
    let mut vivantes: Vec<Ipv4Addr> = stream::iter(essais)
        .map(|(ip, p)| async move { (ip, sonder(ip, p, delai).await.0) })
        .buffer_unordered(parallele)
        .filter_map(|(ip, e)| async move { (e != Etat::Filtre).then_some(ip) })
        .collect()
        .await;

    // Nos tentatives ont rempli la table ARP : les machines qui bloquent tout y apparaissent quand même.
    let arp = table_arp();
    let deja: std::collections::HashSet<Ipv4Addr> = vivantes.iter().copied().collect();
    let seulement_arp: Vec<Ipv4Addr> = ips
        .iter()
        .filter(|ip| arp.contains_key(ip) && !deja.contains(ip))
        .copied()
        .collect();
    #[cfg(target_os = "linux")]
    let seulement_arp = confirmer_voisins(ips, &deja, seulement_arp).await;
    vivantes.extend(seulement_arp);
    vivantes.sort();
    vivantes.dedup();
    vivantes
}

/// État de chaque voisin IPv4, demandé au noyau par netlink (RTM_GETNEIGH), comme `ip -4 neigh show` le fait, sans
/// le lancer : rien à installer (iproute2 manque dans des conteneurs) et quelques microsecondes. Les états gardent les
/// noms qu'ip leur donne (REACHABLE, STALE…). `None` : le noyau refuse.
#[cfg(target_os = "linux")]
pub(crate) fn etats_voisins() -> Option<HashMap<Ipv4Addr, String>> {
    demander_voisins(libc::AF_INET).map(|r| lire_voisins_netlink(&r))
}

/// Envoie la demande des voisins d'une famille (`libc::AF_INET` ou `AF_INET6`) et rend les réponses du noyau,
/// jusqu'à la fin de la liste. La même socket sert à l'IPv4 du scan et à l'IPv6 de l'audit.
#[cfg(target_os = "linux")]
pub(crate) fn demander_voisins(famille: libc::c_int) -> Option<Vec<u8>> {
    const RTM_GETNEIGH: u16 = 30;
    // En-tête netlink (16 octets) puis ndmsg (12) : la famille, rien d'autre.
    let mut demande = [0u8; 28];
    demande[0..4].copy_from_slice(&28u32.to_ne_bytes());
    demande[4..6].copy_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    demande[6..8].copy_from_slice(&((libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16).to_ne_bytes());
    demande[8..12].copy_from_slice(&1u32.to_ne_bytes());
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        demande[16] = famille as u8;
    }
    // SAFETY: une socket netlink ouverte ici et refermée une seule fois à la sortie ; chaque appel reçoit un pointeur
    // et la taille exacte d'un objet à nous, vivant pendant l'appel (demande, adresse, délai, tampon) ; recv écrit au
    // plus `tampon.len()` octets dans le tampon, et seuls les `n` reçus sont lus. Le délai de réception (2 s) empêche
    // recv de bloquer sans fin si le noyau ne répondait pas.
    unsafe {
        let s = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if s < 0 {
            return None;
        }
        let delai = libc::timeval { tv_sec: 2, tv_usec: 0 };
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
            let mut tampon = vec![0u8; 32 << 10];
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
                match fin_netlink(recu) {
                    Some(true) => {
                        resultat = Some(std::mem::take(&mut tout));
                        break;
                    }
                    Some(false) => break,
                    // Une table démesurée n'en est pas une : on s'arrête.
                    None if tout.len() > 16 << 20 => break,
                    None => {}
                }
            }
        }
        libc::close(s);
        resultat
    }
}

/// Les messages netlink d'un morceau de réponse, un par un : (type, corps).
#[cfg(any(target_os = "linux", test))]
pub(crate) fn messages_netlink(octets: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        let &[l0, l1, l2, l3, g0, g1, ..] = octets.get(pos..pos.checked_add(16)?)?.first_chunk::<16>()?;
        let longueur = usize::try_from(u32::from_ne_bytes([l0, l1, l2, l3])).ok()?;
        let genre = u16::from_ne_bytes([g0, g1]);
        let corps = octets.get(pos + 16..pos.checked_add(longueur)?)?;
        if longueur < 16 {
            return None;
        }
        pos += longueur.next_multiple_of(4);
        Some((genre, corps))
    })
}

/// Le morceau finit-il la réponse ? `Some(true)` : NLMSG_DONE ; `Some(false)` : NLMSG_ERROR ; `None` : la suite vient.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn fin_netlink(morceau: &[u8]) -> Option<bool> {
    messages_netlink(morceau).find_map(|(genre, _)| match genre {
        3 => Some(true),
        2 => Some(false),
        _ => None,
    })
}

/// Les voisins IPv4 des messages RTM_NEWNEIGH : l'adresse (attribut NDA_DST) et l'état, nommé comme ip le nomme.
#[cfg(any(target_os = "linux", test))]
fn lire_voisins_netlink(octets: &[u8]) -> HashMap<Ipv4Addr, String> {
    const RTM_NEWNEIGH: u16 = 28;
    // AF_INET de Linux, écrit ici : la lecture est aussi testée sous Windows, sans libc.
    const AF_INET: u8 = 2;
    let mut voisins = HashMap::new();
    for (genre, corps) in messages_netlink(octets) {
        // ndmsg : famille (1), bourrage (3), interface (4), état (2), drapeaux (1), type (1) ; puis les attributs.
        let Some(&[famille, _, _, _, _, _, _, _, e0, e1, _, _]) = corps.first_chunk::<12>() else {
            continue;
        };
        if genre != RTM_NEWNEIGH || famille != AF_INET {
            continue;
        }
        let etat = u16::from_ne_bytes([e0, e1]);
        // Comme ip sans « nud all » : ni les entrées sans ARP (diffusion, multidiffusion), ni celles sans état.
        if etat == 0 || etat & 0x40 != 0 {
            continue;
        }
        let mut pos = 12;
        while let Some(&[l0, l1, g0, g1]) = corps.get(pos..pos + 4) {
            let longueur = usize::from(u16::from_ne_bytes([l0, l1]));
            let genre_attribut = u16::from_ne_bytes([g0, g1]);
            if longueur < 4 {
                break;
            }
            if genre_attribut == 1
                && let Some(ip) = corps
                    .get(pos + 4..pos + longueur)
                    .and_then(|a| <[u8; 4]>::try_from(a).ok())
            {
                voisins.insert(Ipv4Addr::from(ip), nom_d_etat(etat).to_string());
            }
            pos += longueur.next_multiple_of(4);
        }
    }
    voisins
}

/// Le nom d'un état de voisin (NUD_*), celui qu'ip affiche ; plusieurs bits : le plus fort.
#[cfg(any(target_os = "linux", test))]
fn nom_d_etat(etat: u16) -> &'static str {
    [
        (0x80, "PERMANENT"),
        (0x40, "NOARP"),
        (0x20, "FAILED"),
        (0x10, "PROBE"),
        (0x08, "DELAY"),
        (0x04, "STALE"),
        (0x02, "REACHABLE"),
        (0x01, "INCOMPLETE"),
    ]
    .iter()
    .find(|(bit, _)| etat & bit != 0)
    .map_or("NONE", |(_, nom)| nom)
}

/// La sortie de `ip -4 neigh show` : ne sert plus qu'à comparer netlink à ip dans les tests.
#[cfg(test)]
fn lire_etats_voisins(texte: &str) -> HashMap<Ipv4Addr, String> {
    texte
        .lines()
        .filter_map(|l| {
            let mut mots = l.split_whitespace();
            let ip = mots.next()?.parse().ok()?;
            Some((ip, mots.last()?.to_string()))
        })
        .collect()
}

/// État ARP en cours de vérification par le noyau : la réponse n'est pas encore connue.
#[cfg(any(target_os = "linux", test))]
fn etat_en_cours(etat: Option<&str>) -> bool {
    matches!(etat, Some("DELAY" | "PROBE" | "INCOMPLETE"))
}

/// Un voisin compte comme présent, sauf si le noyau a constaté qu'il ne répond plus (ou l'a oublié).
#[cfg(any(target_os = "linux", test))]
fn voisin_present(etat: Option<&str>) -> bool {
    !matches!(etat, None | Some("FAILED" | "INCOMPLETE"))
}

/// Linux garde les entrées ARP périmées (STALE) des appareils partis : sur un petit réseau, rien ne les efface.
/// Elles sont encore « complètes » quand on les lit juste après nos sondes, et l'appareil passait pour présent.
/// À l'inverse, un téléphone en veille répond à l'ARP en une ou deux secondes : lu trop tôt (INCOMPLETE), il
/// passait pour absent. Nos sondes ont lancé la vérification (5 s d'attente puis 3 essais d'1 s pour une entrée
/// périmée, 3 essais d'1 s pour une nouvelle) : on attend son verdict, au plus 10 s, pour les adresses qui n'ont
/// pas répondu en TCP. `repli` = l'ancienne liste, gardée si la commande ip manque.
#[cfg(target_os = "linux")]
async fn confirmer_voisins(
    ips: &[Ipv4Addr],
    deja: &std::collections::HashSet<Ipv4Addr>,
    repli: Vec<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let fin = std::time::Instant::now() + Duration::from_secs(10);
    let mut candidats: Option<Vec<Ipv4Addr>> = None;
    loop {
        let Some(etats) = tokio::task::spawn_blocking(etats_voisins).await.ok().flatten() else {
            return repli;
        };
        let etat = |ip: &Ipv4Addr| etats.get(ip).map(String::as_str);
        // Au premier passage : toute adresse sans réponse TCP que le noyau connaît ou cherche encore.
        let liste = candidats.get_or_insert_with(|| {
            ips.iter()
                .filter(|ip| !deja.contains(ip) && (voisin_present(etat(ip)) || etat_en_cours(etat(ip))))
                .copied()
                .collect()
        });
        if !liste.iter().any(|ip| etat_en_cours(etat(ip))) || std::time::Instant::now() >= fin {
            return liste.iter().filter(|ip| voisin_present(etat(ip))).copied().collect();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// Lit ce que le service annonce (SSH, FTP, SMTP…) ou l'en-tête Server en HTTP.
/// Ce qu'un service répond, ou rien s'il se tait pendant 1,2 s.
async fn lire(flux: &mut TcpStream) -> Option<String> {
    let mut buf = [0u8; 512];
    let n = timeout(Duration::from_millis(1200), flux.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.get(..n)
        .filter(|recu| !recu.is_empty())
        .map(|recu| String::from_utf8_lossy(recu).into_owned())
}

/// Résumé d'une réponse HTTP : l'en-tête Server, sinon la ligne d'état.
fn resume_http(texte: &str) -> String {
    let serveur = texte
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string());
    format!(
        "HTTP · {}",
        serveur.unwrap_or_else(|| texte.lines().next().unwrap_or("").trim().to_string())
    )
}

/// Ce que le service annonce (SSH, FTP, SMTP…). Sur un port web, ou si le service se tait,
/// on lui envoie une requête HTTP : un serveur web caché sur un port inhabituel est ainsi reconnu.
async fn banniere(mut flux: TcpStream, port: u16) -> Option<String> {
    let texte = if PORTS_HTTP.contains(&port) {
        None
    } else {
        lire(&mut flux).await
    };
    let ligne = match texte {
        Some(t) if t.starts_with("HTTP/") => resume_http(&t),
        Some(t) => t.lines().next().unwrap_or("").trim().to_string(),
        None => {
            flux.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await.ok()?;
            let t = lire(&mut flux).await?;
            if !t.starts_with("HTTP/") {
                return None;
            }
            resume_http(&t)
        }
    };
    // Une bannière ne doit pas pouvoir piloter le terminal (`affichable`). Une réponse binaire, faite seulement de
    // contrôles, ne dit rien : pas de bannière, comme avant.
    // Une tabulation dans une bannière est un blanc, comme avant, et non un « � ».
    let propre: String = affichable(&ligne.replace('\t', " ")).chars().take(80).collect();
    propre.chars().any(|c| c != '\u{fffd}').then_some(propre)
}

/// Scanne tous les ports demandés sur toutes les machines. Retourne IP → [(port, bannière)].
pub async fn scanner_ports(
    hotes: &[Ipv4Addr],
    ports: &[u16],
    delai: Duration,
    parallele: usize,
) -> BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>> {
    let essais = hotes.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p)));
    let trouves: Vec<(Ipv4Addr, u16, Option<String>)> = stream::iter(essais)
        .map(|(ip, p)| async move {
            match sonder(ip, p, delai).await {
                (Etat::Ouvert, Some(flux)) => Some((ip, p, banniere(flux, p).await)),
                _ => None,
            }
        })
        .buffer_unordered(parallele)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    let mut resultat: BTreeMap<_, Vec<_>> = hotes.iter().map(|&ip| (ip, Vec::new())).collect();
    for (ip, p, b) in trouves {
        resultat.entry(ip).or_default().push((p, b));
    }
    for ports in resultat.values_mut() {
        ports.sort_by_key(|(p, _)| *p);
    }
    resultat
}

/// Requête envoyée sur chaque port UDP : un service UDP ne répond qu'à un message de son protocole. Sans réponse, on
/// ne sait pas (port fermé ou filtré) : seul un port qui répond est déclaré ouvert.
fn requete_udp(port: u16) -> Option<Vec<u8>> {
    Some(match port {
        // DNS : serveurs de la racine (NS de « . »).
        53 => vec![0x53, 0x45, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1],
        // NTP : client, version 3.
        123 => {
            let mut r = [0u8; 48];
            r[0] = 0x1b;
            r.to_vec()
        }
        // NetBIOS : liste des noms de l'appareil (NBSTAT sur « * »).
        137 => {
            let mut r = vec![0x53, 0x45, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, b'C', b'K'];
            r.extend([b'A'; 30]);
            r.extend([0, 0, 0x21, 0, 1]);
            r
        }
        // SNMP v1 : description du système (sysDescr.0) avec la communauté par défaut « public ».
        161 => vec![
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19, 0x02, 0x01, 0x01,
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
            0x01, 0x00, 0x05, 0x00,
        ],
        // SSDP (UPnP) : recherche des appareils.
        1900 => b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
            .to_vec(),
        // mDNS (Bonjour) : liste des services annoncés, en question directe (réponse renvoyée à notre port).
        5353 => {
            let mut r = vec![0x53, 0x45, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            for etiquette in ["_services", "_dns-sd", "_udp", "local"] {
                r.push(u8::try_from(etiquette.len()).unwrap_or(0));
                r.extend(etiquette.as_bytes());
            }
            r.extend([0, 0, 0x0c, 0, 1]);
            r
        }
        _ => return None,
    })
}

/// Ce que la réponse apprend : nom NetBIOS, description SNMP, serveur UPnP. Chaque appareil choisit ce qu'il y
/// écrit : lu prêt à montrer (`affichable`).
fn resume_udp(port: u16, reponse: &[u8]) -> Option<String> {
    match port {
        // En-tête (12) + nom (34) + type, classe, durée, longueur (10) = 56 : nombre de noms, puis le premier nom,
        // complété par des espaces (des octets nuls chez certains appareils).
        137 => {
            let nom = reponse.get(57..72)?;
            let nom = affichable(String::from_utf8_lossy(nom).trim_matches(|c: char| c.is_whitespace() || c == '\0'));
            (!nom.is_empty()).then(|| trf!("nom : {nom}", "name: {nom}"))
        }
        // La valeur suit l'OID de sysDescr.0 : 0x04 (texte), longueur, texte.
        161 => {
            let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
            let debut = reponse.windows(oid.len()).position(|w| w == oid)? + oid.len();
            let (&type_, reste) = reponse.get(debut..)?.split_first()?;
            if type_ != 0x04 {
                return None;
            }
            let (longueur, texte) = match reste.split_first()? {
                (&0x81, r) => (usize::from(*r.first()?), r.get(1..)?),
                (&n, r) if n < 0x80 => (usize::from(n), r),
                _ => return None,
            };
            let texte = String::from_utf8_lossy(texte.get(..longueur.min(texte.len()))?);
            let texte: String = affichable(&texte.split_whitespace().collect::<Vec<_>>().join(" "))
                .chars()
                .take(70)
                .collect();
            (!texte.is_empty()).then_some(texte)
        }
        1900 => String::from_utf8_lossy(reponse).lines().find_map(|l| {
            let (cle, valeur) = l.split_once(':')?;
            (cle.trim().eq_ignore_ascii_case("server")).then(|| affichable(valeur.trim()).chars().take(70).collect())
        }),
        _ => None,
    }
}

async fn sonder_udp(ip: Ipv4Addr, port: u16, delai: Duration) -> Option<Option<String>> {
    let requete = requete_udp(port)?;
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    // Socket « connectée » : un port fermé renvoie une erreur (ICMP) au lieu de faire attendre tout le délai.
    socket.connect(SocketAddr::new(IpAddr::V4(ip), port)).await.ok()?;
    let mut tampon = [0u8; 1500];
    // Trois envois : un paquet UDP perdu, ou une imprimante lente à répondre (vu en réel : NetBIOS d'une HP), ne doit
    // pas faire passer un port ouvert pour fermé, puis pour « nouveau » au scan suivant.
    for _ in 0..3 {
        socket.send(&requete).await.ok()?;
        match timeout(delai, socket.recv(&mut tampon)).await {
            // recv n'écrit jamais plus que le tampon.
            Ok(Ok(n)) if n > 0 => return tampon.get(..n).map(|recu| resume_udp(port, recu)),
            Ok(_) => return None,
            Err(_) => {}
        }
    }
    None
}

/// Ports UDP qui répondent, par machine (même forme que `scanner_ports`).
pub async fn scanner_udp(
    hotes: &[Ipv4Addr],
    ports: &[u16],
    delai: Duration,
) -> BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>> {
    let essais = hotes.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p)));
    let trouves: Vec<(Ipv4Addr, u16, Option<String>)> = stream::iter(essais)
        .map(|(ip, p)| async move { sonder_udp(ip, p, delai).await.map(|b| (ip, p, b)) })
        .buffer_unordered(128)
        .filter_map(|r| async move { r })
        .collect()
        .await;
    let mut resultat: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (ip, p, b) in trouves {
        resultat.entry(ip).or_default().push((p, b));
    }
    for ports in resultat.values_mut() {
        ports.sort_by_key(|(p, _)| *p);
    }
    resultat
}

/// Nom DNS inverse (box, mDNS via nss…), sans bloquer le runtime.
pub async fn nom_hote(ip: Ipv4Addr) -> Option<String> {
    // Délai maximal : un DNS qui ne répond pas ne doit pas bloquer tout le scan.
    let recherche = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
    let nom = timeout(Duration::from_secs(2), recherche).await.ok()?.ok()?.ok()?;
    nom_inverse(IpAddr::V4(ip), &nom)
}

/// Le nom d'une adresse, d'après le système (DNS inverse de la box, mDNS, NetBIOS ou LLMNR selon le système), prêt à
/// montrer : chaque appareil, chaque serveur choisit le sien. `None` : le système n'a redit que l'adresse.
pub(crate) fn nom_inverse(ip: IpAddr, nom: &str) -> Option<String> {
    (nom != ip.to_string()).then(|| affichable(nom))
}

/// Base des fabricants (préfixe MAC → nom), extraite des registres IEEE (outils/maj-fabricants.sh, relancé par
/// deployer.sh quand elle a plus d'un mois), rangée en tableaux triés à la compilation par build.rs.
#[allow(clippy::all, clippy::pedantic)] // fichier produit, des milliers de nombres
mod base {
    include!(concat!(env!("OUT_DIR"), "/fabricants.rs"));
}

/// Le nom du fabricant pour les `n` premiers chiffres hexadécimaux de la MAC, cherché par dichotomie.
fn nom_du_bloc(hex: &str, n: usize) -> Option<&'static str> {
    let valeur = u64::from_str_radix(hex.get(..n)?, 16).ok()?;
    let numero = match n {
        6 => *base::NOMS_6.get(base::PREFIXES_6.binary_search(&u32::try_from(valeur).ok()?).ok()?)?,
        7 => *base::NOMS_7.get(base::PREFIXES_7.binary_search(&u32::try_from(valeur).ok()?).ok()?)?,
        9 => *base::NOMS_9.get(base::PREFIXES_9.binary_search(&valeur).ok()?)?,
        _ => return None,
    };
    let i = usize::from(numero);
    let debut = usize::try_from(*base::DEBUTS.get(i)?).ok()?;
    let fin = usize::try_from(*base::DEBUTS.get(i + 1)?).ok()?;
    base::NOMS.get(debut..fin)
}

pub fn fabricant(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .collect::<String>()
        .to_ascii_uppercase();
    let premier = u8::from_str_radix(hex.get(..2)?, 16).ok()?;
    // Bit « administré localement » : MAC aléatoire, typique des téléphones et tablettes récents.
    if premier & 0x02 != 0 {
        return Some(tr!("MAC aléatoire (téléphone/tablette ?)", "random MAC (phone/tablet?)").into());
    }
    // Le bloc le plus précis d'abord : MA-S (9 chiffres), MA-M (7), puis MA-L (6). Un grand bloc revendu en petits
    // morceaux porte sinon le nom du registre (« IEEE Registration Authority ») au lieu de celui du fabricant.
    [9, 7, 6].iter().find_map(|&n| nom_du_bloc(&hex, n)).map(str::to_string)
}

/// Fabricant noté dans la base des appareils, redit dans la langue de l'interface : celui d'une adresse MAC
/// aléatoire est écrit dans la langue du scan qui l'a noté (« random MAC » au milieu d'un écran en français).
pub fn fabricant_traduit(note: &str) -> &str {
    if matches!(
        note,
        "MAC aléatoire (téléphone/tablette ?)" | "random MAC (phone/tablet?)"
    ) {
        tr!("MAC aléatoire (téléphone/tablette ?)", "random MAC (phone/tablet?)")
    } else {
        note
    }
}

/// Nom du Wi-Fi auquel on est connecté, pour reconnaître le réseau dans la base (« Salon », « Chez Max »…).
pub fn nom_wifi() -> Option<String> {
    // Le nom que le noyau donne avec l'interface, sans balayage ; sinon la borne associée de son dernier balayage.
    #[cfg(target_os = "linux")]
    let nom = crate::machine::wifi::nl80211::reseau_connecte()
        .or_else(|| crate::machine::wifi::nl80211::lire().ok()?.connexion.map(|c| c.ssid));
    // L'API WLAN, connexion seule : ni la liste des bornes, ni le texte traduit de netsh.
    #[cfg(windows)]
    let nom = crate::machine::wifi::wlanapi::connexion()
        .ok()
        .flatten()
        .map(|c| c.ssid);
    // macOS : « SSID : Salon » dans le résumé de l'interface Wi-Fi (en0 en général). Depuis macOS 14, le nom peut
    // être masqué (« <redacted> ») faute d'autorisation de localisation : le réseau est alors reconnu par sa box.
    #[cfg(target_os = "macos")]
    let nom = ["en0", "en1"]
        .iter()
        .find_map(|i| nom_wifi_ipconfig(&commande_sortie("ipconfig", &["getsummary", i])));
    nom.filter(|n| !n.is_empty())
}

/// Le réseau connecté dans `ipconfig getsummary en0` (« SSID : Salon ») ; un nom masqué (« <redacted> ») ne dit rien.
/// Le nom, que n'importe qui à portée peut choisir, est lu prêt à montrer (`affichable`), comme par les lectures
/// natives de Linux et de Windows.
#[cfg(any(target_os = "macos", test))]
fn nom_wifi_ipconfig(sortie: &str) -> Option<String> {
    sortie
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("SSID : "))
        .filter(|n| !n.starts_with('<'))
        .map(affichable)
}

#[cfg(target_os = "macos")]
fn commande_sortie(cmd: &str, args: &[&str]) -> String {
    crate::commande::lancer(crate::commande::systeme(cmd).args(args), 10)
        .map(|r| r.sortie)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une interface de VPN en /32 n'est jamais prise pour le réseau local, même quand la route par défaut passe
    /// par elle ; le réseau du Wi-Fi l'est.
    #[test]
    fn un_vpn_en_32_n_est_pas_le_reseau_local() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        let vpn = (ip("10.66.0.2"), ip("255.255.255.255"));
        let wifi = (ip("192.168.1.20"), ip("255.255.255.0"));
        assert_eq!(choisir_reseau(&[vpn], Some(u32::from(ip("10.66.0.2")))), None);
        assert_eq!(
            choisir_reseau(&[vpn, wifi], Some(u32::from(ip("192.168.1.1")))),
            Some(("192.168.1.0/24".to_string(), ip("192.168.1.20")))
        );
        assert_eq!(
            choisir_reseau(&[vpn, wifi], Some(u32::from(ip("10.66.0.1")))),
            Some(("192.168.1.0/24".to_string(), ip("192.168.1.20")))
        );
        // Un grand réseau : le /16 qui contient cette machine.
        assert_eq!(
            choisir_reseau(&[(ip("10.5.3.2"), ip("255.0.0.0"))], None),
            Some(("10.5.0.0/16".to_string(), ip("10.5.3.2")))
        );
    }

    #[test]
    fn cible_cidr_exclut_reseau_et_diffusion() {
        let ips = parse_cible("10.0.0.77/24").unwrap();
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[253], Ipv4Addr::new(10, 0, 0, 254));
    }

    #[test]
    fn cible_plage_et_ip_seule() {
        assert_eq!(parse_cible("192.168.1.10-12").unwrap().len(), 3);
        assert_eq!(parse_cible("192.168.1.5").unwrap(), vec![Ipv4Addr::new(192, 168, 1, 5)]);
        assert!(parse_cible("192.168.1.50-10").is_err());
        assert!(parse_cible("10.0.0.0/8").is_err());
        assert!(parse_cible("pas une ip").is_err());
    }

    #[test]
    fn mac_normalisee_quel_que_soit_le_systeme() {
        assert_eq!(normaliser_mac("f8:79:a:d:3:a2").as_deref(), Some("f8:79:0a:0d:03:a2")); // zéros omis
        assert_eq!(
            normaliser_mac("F8-79-0A-0D-03-A2").as_deref(),
            Some("f8:79:0a:0d:03:a2")
        ); // Windows
        assert_eq!(normaliser_mac("ff-ff-ff-ff-ff-ff"), None); // diffusion
        assert_eq!(normaliser_mac("01-00-5e-00-00-fb"), None); // multicast
        assert_eq!(normaliser_mac("incomplete"), None);
    }

    #[test]
    fn reponses_udp() {
        // NetBIOS : le premier nom de la liste.
        let mut nb = vec![0u8; 57];
        nb.extend(b"IMPRIMANTE-HP  ");
        nb.extend([0x00, 0x04, 0x00]);
        assert!(resume_udp(137, &nb).unwrap().ends_with("IMPRIMANTE-HP"));
        // SNMP : sysDescr après son OID.
        let mut snmp = vec![0x30, 0x2a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04, 0x0b];
        snmp.extend(b"HP LaserJet");
        assert_eq!(resume_udp(161, &snmp).as_deref(), Some("HP LaserJet"));
        // SSDP : l'en-tête SERVER.
        let ssdp =
            b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/2.1\r\n\r\n";
        assert_eq!(
            resume_udp(1900, ssdp).as_deref(),
            Some("Linux/3.14 UPnP/1.0 MiniUPnPd/2.1")
        );
        // Requêtes bien formées : SNMP annonce la longueur exacte du message.
        let r = requete_udp(161).unwrap();
        assert_eq!(usize::from(r[1]) + 2, r.len());
        assert_eq!(requete_udp(137).unwrap().len(), 50);
        assert!(requete_udp(80).is_none());
    }

    #[test]
    fn fabricant_et_mac_aleatoire() {
        assert_eq!(fabricant("c4:34:6b:12:34:56").as_deref(), Some("Hewlett Packard"));
        assert!(fabricant("ee:12:34:56:78:9a").unwrap().contains("aléatoire"));
        // Bloc MA-M (28 bits) : son fabricant, pas le registre qui détient le grand bloc.
        assert_eq!(
            fabricant("00:55:da:0a:bc:de").as_deref(),
            Some("Shinko Technos co.,ltd.")
        );
        assert_eq!(fabricant("zz"), None);
    }

    /// Les tableaux produits par build.rs : triés (la dichotomie en dépend), complets, chaque nom trouvable.
    #[test]
    fn base_des_fabricants_rangee() {
        assert!(base::PREFIXES_6.windows(2).all(|w| w[0] < w[1]));
        assert!(base::PREFIXES_7.windows(2).all(|w| w[0] < w[1]));
        assert!(base::PREFIXES_9.windows(2).all(|w| w[0] < w[1]));
        let total = base::PREFIXES_6.len() + base::PREFIXES_7.len() + base::PREFIXES_9.len();
        let lignes = include_str!("../../assets/oui.tsv")
            .lines()
            .filter(|l| l.contains('\t'))
            .count();
        assert_eq!(total, lignes, "un préfixe de oui.tsv manque dans les tableaux");
        assert_eq!(base::DEBUTS.last().copied(), u32::try_from(base::NOMS.len()).ok());
        for (prefixes, n) in [(&base::PREFIXES_6[..], 6), (&base::PREFIXES_7[..], 7)] {
            for &p in prefixes.iter().step_by(997) {
                assert!(nom_du_bloc(&format!("{p:0n$X}"), n).is_some_and(|nom| !nom.is_empty()));
            }
        }
    }

    #[test]
    fn passerelle_par_defaut_linux() {
        let entete = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
        // VPN « default dev tun0 » (passerelle 0), Wi-Fi (métrique 600) et Ethernet (métrique 100).
        let table = format!(
            "{entete}tun0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
             wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n"
        );
        assert_eq!(passerelle_linux(&table), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(passerelle_linux(entete), None);
    }

    /// Ce que répondent les appareils du réseau, et que chacun choisit : nom NetBIOS, description SNMP, serveur UPnP
    /// (SSDP). Piégé (couleur, OSC, effacement de ligne, retour chariot, bidi), il arrive inoffensif, « � » à la place
    /// de chaque caractère piégé.
    #[test]
    fn reponses_udp_piegees() {
        let mut nb = vec![0u8; 57];
        nb.extend("\x1b[2K\rFAUX-PC\u{202e}".as_bytes());
        nb.extend([0x00, 0x04, 0x00]);
        assert_eq!(resume_udp(137, &nb).as_deref(), Some("nom : �[2K�FAUX-PC�"));
        let description = "HP\x1b]0;titre\x07 LaserJet\u{2066}";
        let mut snmp = vec![0x30, 0x2a, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x04];
        snmp.push(u8::try_from(description.len()).unwrap());
        snmp.extend(description.as_bytes());
        assert_eq!(resume_udp(161, &snmp).as_deref(), Some("HP�]0;titre� LaserJet�"));
        let ssdp = "HTTP/1.1 200 OK\r\nSERVER: Linux\x1b]52;c;eA==\x07 UPnP/1.0\u{202e}\r\n\r\n";
        assert_eq!(
            resume_udp(1900, ssdp.as_bytes()).as_deref(),
            Some("Linux�]52;c;eA==� UPnP/1.0�")
        );
    }

    /// La bannière d'un service (ici sur cet ordinateur, 127.0.0.1) : la première ligne, rendue inoffensive. Les
    /// contrôles étaient déjà retirés, pas le retournement bidi ; ils deviennent « � », comme partout.
    #[tokio::test]
    async fn banniere_piegee() {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let serveur = std::thread::spawn(move || {
            use std::io::Write;
            let (mut c, _) = ecoute.accept().unwrap();
            c.write_all("SSH-2.0-\x1b]52;c;ZWNobyBQSVJBVEU=\x07\x1b[2K\rFaux\u{202e}\r\n".as_bytes())
                .unwrap();
        });
        let trouves = scanner_ports(&[Ipv4Addr::LOCALHOST], &[port], Duration::from_secs(2), 4).await;
        serveur.join().unwrap();
        assert_eq!(
            trouves[&Ipv4Addr::LOCALHOST],
            [(port, Some("SSH-2.0-�]52;c;ZWNobyBQSVJBVEU=��[2K�Faux�".to_string()))]
        );
    }

    /// Le nom d'un appareil ou d'un serveur (DNS inverse, mDNS, NetBIOS, LLMNR) : gardé tel quel s'il est normal,
    /// rendu inoffensif s'il est piégé ; l'adresse seule redite n'est pas un nom.
    #[test]
    fn noms_inverses() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(
            nom_inverse(ip, "imprimante-salon.local").as_deref(),
            Some("imprimante-salon.local")
        );
        assert_eq!(nom_inverse(ip, "192.168.1.20"), None);
        assert_eq!(
            nom_inverse(ip, "tele\x1b]52;c;eA==\x07\x1b[2K\r\u{202e}.local").as_deref(),
            Some("tele�]52;c;eA==��[2K��.local")
        );
    }

    /// Le nom du réseau connecté, gardé dans la base et montré en tête du scan : lu tel quel s'il est normal, rendu
    /// inoffensif s'il est piégé (macOS ici ; Linux et Windows le lisent par nl80211 et wlanapi, testés là).
    #[test]
    fn nom_du_wifi_connecte() {
        const PIEGE: &str = "Salon\x1b]52;c;ZWNobyBQSVJBVEU=\x07\x1b[2K\rFaux\u{202e}";
        const VU: &str = "Salon�]52;c;ZWNobyBQSVJBVEU=��[2K�Faux�";
        assert_eq!(nom_wifi_ipconfig("  SSID : Chez Max\n").as_deref(), Some("Chez Max"));
        assert_eq!(nom_wifi_ipconfig(&format!("  SSID : {PIEGE}\n")).as_deref(), Some(VU));
        assert_eq!(nom_wifi_ipconfig("  SSID : <redacted>\n"), None);
    }

    #[test]
    fn voisins_perimes_ecartes() {
        let etats = lire_etats_voisins(
            "10.0.0.1 dev wlan0 lladdr f8:79:0a:0d:03:a2 router REACHABLE\n\
             10.0.0.48 dev wlan0 lladdr f4:6c:68:11:22:33 STALE\n\
             10.0.0.75 dev wlan0 lladdr 08:6a:c5:44:55:66 DELAY\n\
             10.0.0.99 dev wlan0  FAILED\n",
        );
        let etat = |d: u8| etats.get(&Ipv4Addr::new(10, 0, 0, d)).map(String::as_str);
        assert_eq!(etat(1), Some("REACHABLE"));
        assert!(etat_en_cours(etat(75)) && !etat_en_cours(etat(48)));
        // Confirmé pendant le scan puis vieilli (STALE) : présent. Sans réponse (FAILED) ou oublié : absent.
        assert!(voisin_present(etat(1)) && voisin_present(etat(48)));
        assert!(!voisin_present(etat(99)) && !voisin_present(etat(200)));
    }

    /// Une réponse netlink inventée, à la forme de celle du noyau : deux voisins IPv4, un IPv6 ignoré, puis la fin.
    #[test]
    fn voisins_lus_par_netlink() {
        fn voisin(famille: u8, etat: u16, adresse: &[u8]) -> Vec<u8> {
            let mut corps = vec![famille, 0, 0, 0, 2, 0, 0, 0];
            corps.extend_from_slice(&etat.to_ne_bytes());
            corps.extend_from_slice(&[0, 1]);
            let longueur = u16::try_from(4 + adresse.len()).unwrap();
            corps.extend_from_slice(&longueur.to_ne_bytes());
            corps.extend_from_slice(&1u16.to_ne_bytes());
            corps.extend_from_slice(adresse);
            while corps.len() % 4 != 0 {
                corps.push(0);
            }
            message(28, &corps)
        }
        fn message(genre: u16, corps: &[u8]) -> Vec<u8> {
            let mut m = u32::try_from(16 + corps.len()).unwrap().to_ne_bytes().to_vec();
            m.extend_from_slice(&genre.to_ne_bytes());
            m.extend_from_slice(&[0; 10]);
            m.extend_from_slice(corps);
            m
        }
        let mut reponse = voisin(2, 0x02, &[10, 0, 0, 1]);
        reponse.extend(voisin(2, 0x40, &[224, 0, 0, 251]));
        reponse.extend(voisin(2, 0x24, &[10, 0, 0, 48]));
        reponse.extend(voisin(
            10,
            0x02,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ));
        let fin = message(3, &[0, 0, 0, 0]);
        let voisins = lire_voisins_netlink(&reponse);
        assert_eq!(voisins.len(), 2);
        assert_eq!(voisins[&Ipv4Addr::new(10, 0, 0, 1)], "REACHABLE");
        assert_eq!(voisins[&Ipv4Addr::new(10, 0, 0, 48)], "FAILED");
        assert_eq!(fin_netlink(&reponse), None);
        assert_eq!(fin_netlink(&fin), Some(true));
        assert_eq!(fin_netlink(&message(2, &[0; 20])), Some(false));
        // Tronquée ou mensongère : rien de plus, sans paniquer.
        assert!(lire_voisins_netlink(&reponse[..30]).is_empty());
        assert!(lire_voisins_netlink(&message(28, &[2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 2, 0, 1, 0])).is_empty());
    }

    /// Sur cet ordinateur, netlink donne les mêmes voisins que la commande ip, quand elle est là.
    #[cfg(target_os = "linux")]
    #[test]
    fn voisins_comme_ip() {
        let Some(r) = crate::commande::lancer(std::process::Command::new("ip").args(["-4", "neigh", "show"]), 5)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("ip absent");
        };
        let Some(natifs) = etats_voisins() else {
            return crate::essais::saute("voisins illisibles par netlink");
        };
        let par_ip = lire_etats_voisins(&r.sortie);
        // Les états bougent d'un instant à l'autre ; les adresses, elles, sont les mêmes.
        let mut a: Vec<_> = par_ip.keys().collect();
        let mut b: Vec<_> = natifs.keys().collect();
        a.sort();
        b.sort();
        assert_eq!(a, b, "ip : {par_ip:?}, netlink : {natifs:?}");
    }
}

/// Propriétés des réponses UDP (NetBIOS, SNMP, SSDP) : chaque appareil du réseau choisit ce qu'il y écrit. Quels que
/// soient les octets reçus, la lecture ne plante pas, et ce qu'elle rend ne pilote pas le terminal.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn reponses_udp_quelconques(port in prop_oneof![Just(137u16), Just(161), Just(1900), any::<u16>()], octets in prop::collection::vec(any::<u8>(), 0..600)) {
            if let Some(t) = resume_udp(port, &octets) {
                prop_assert!(!crate::ui::contient_un_piege(&t), "{t:?}");
            }
        }
    }
}
