//! Type de NAT pour le jeu : ouvert, modéré ou strict, comme l'affichent les consoles. Le NAT de la box traduit
//! l'adresse de chaque appareil en son adresse publique. Deux serveurs publics (STUN, RFC 5389) disent quelle adresse
//! et quel port ils voient, depuis le même port de cet ordinateur : le même port pour les deux, la box garde une
//! traduction stable (modéré, ouvert avec l'UPnP) ; un port différent par serveur, elle en change à chaque
//! destination (strict, symétrique), et les autres joueurs ne peuvent pas la joindre directement. Lecture seule.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::reseau::upnp::Etat;
use crate::risk::Niveau;
use crate::ui::*;

/// Valeur fixe des messages STUN (« magic cookie »), qui masque aussi les adresses rendues.
const MAGIC: u32 = 0x2112_A442;
const MAGIC_HAUT: u16 = 0x2112;

/// Serveurs STUN publics de deux opérateurs (nom, port, opérateur) : chacun voit l'adresse de la maison, comme
/// n'importe quel site.
const SERVEURS: [(&str, u16, &str); 3] = [
    ("stun.cloudflare.com", 3478, "Cloudflare"),
    ("stun.l.google.com", 19302, "Google"),
    ("stun1.l.google.com", 19302, "Google"),
];

/// Un nombre au hasard, pour les identifiants qui font reconnaître la réponse à un message (STUN, DNS, ONVIF).
pub(crate) fn hasard() -> u64 {
    let mut h = RandomState::new().build_hasher();
    h.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos()));
    h.finish()
}

/// Passe à `lire` chaque message reçu sur `socket` jusqu'à `fin`, et rend la première réponse qu'elle reconnaît.
/// Rien au délai écoulé. Une erreur de réception ne coupe pas l'écoute : sous Windows, un datagramme plus gros que le
/// tampon (WSAEMSGSIZE) ou la réponse ICMP à un envoi précédent (WSAECONNRESET) en sont une, et n'importe quel
/// appareil du réseau en provoquait une juste après la question, pour que la vraie réponse ne soit jamais lue (« UPnP
/// coupé », alors qu'il est actif).
pub(crate) fn recevoir<T>(
    socket: &UdpSocket,
    fin: Instant,
    tampon: &mut [u8],
    lire: impl FnMut(&[u8], SocketAddr) -> Option<T>,
) -> Option<T> {
    recevoir_avec(
        |tampon, reste| {
            socket.set_read_timeout(Some(reste))?;
            socket.recv_from(tampon)
        },
        fin,
        tampon,
        lire,
    )
}

/// Au-delà, des erreurs qui ne consomment rien (une socket hors d'usage) arrêtent l'écoute : elle ne tourne pas à
/// vide jusqu'au délai. Un datagramme trop gros ou un ICMP « port injoignable » (Windows) n'y comptent pas : chacun
/// est retiré de la file, et compté, un appareil du réseau local qui en envoie 257 coupait l'écoute avant la box.
const ERREURS_MAX: u32 = 256;
/// WSAEMSGSIZE : sous Windows, un datagramme plus gros que le tampon, retiré de la file.
const WSAEMSGSIZE: i32 = 10040;

/// `recevoir`, avec la réception donnée (les tests y passent la leur).
fn recevoir_avec<T>(
    mut recevoir_un: impl FnMut(&mut [u8], std::time::Duration) -> std::io::Result<(usize, SocketAddr)>,
    fin: Instant,
    tampon: &mut [u8],
    mut lire: impl FnMut(&[u8], SocketAddr) -> Option<T>,
) -> Option<T> {
    let mut erreurs = 0;
    loop {
        let reste = fin.saturating_duration_since(Instant::now());
        if reste.is_zero() {
            return None;
        }
        match recevoir_un(tampon, reste) {
            Ok((n, de)) => {
                if let Some(reponse) = lire(&tampon[..n.min(tampon.len())], de) {
                    return Some(reponse);
                }
            }
            // Le délai : fini.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return None;
            }
            // WSAEMSGSIZE et WSAECONNRESET consomment un datagramme (ou un ICMP) : l'écoute avance. Seules les autres
            // erreurs (socket hors d'usage) comptent pour le plafond.
            Err(e) if e.raw_os_error() == Some(WSAEMSGSIZE) || e.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => {
                erreurs += 1;
                if erreurs > ERREURS_MAX {
                    return None;
                }
            }
        }
    }
}

/// Identifiant d'une requête : 12 octets au hasard, pour reconnaître sa réponse.
fn identifiant() -> [u8; 12] {
    let octets = [hasard().to_le_bytes(), hasard().to_le_bytes()].concat();
    std::array::from_fn(|i| octets[i])
}

/// Requête « Binding » sans attribut : type, longueur nulle, cookie, identifiant.
fn requete(id: &[u8; 12]) -> Vec<u8> {
    [&[0u8, 1, 0, 0][..], &MAGIC.to_be_bytes(), id].concat()
}

/// Adresse d'un attribut STUN (réservé, famille, port, adresse), démasquée par le cookie (et l'identifiant, en IPv6)
/// pour XOR-MAPPED-ADDRESS.
fn adresse(valeur: &[u8], masque: Option<&[u8; 12]>) -> Option<SocketAddr> {
    let mut port = u16::from_be_bytes([*valeur.get(2)?, *valeur.get(3)?]);
    let mut cle = [0u8; 16];
    if let Some(id) = masque {
        port ^= MAGIC_HAUT;
        cle[..4].copy_from_slice(&MAGIC.to_be_bytes());
        cle[4..].copy_from_slice(id);
    }
    let ip = match (valeur.get(1)?, valeur.get(4..)?) {
        (1, [a, b, c, d, ..]) => IpAddr::from([a ^ cle[0], b ^ cle[1], c ^ cle[2], d ^ cle[3]]),
        (2, o) if o.len() >= 16 => IpAddr::from(std::array::from_fn::<u8, 16, _>(|i| o[i] ^ cle[i])),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// L'adresse vue par le serveur, dans sa réponse « Binding Success » à notre requête : XOR-MAPPED-ADDRESS, sinon
/// MAPPED-ADDRESS (anciens serveurs).
fn lire_reponse(r: &[u8], id: &[u8; 12]) -> Option<SocketAddr> {
    if r.len() < 20 || r[..2] != [0x01, 0x01] || r[4..8] != MAGIC.to_be_bytes() || r[8..20] != id[..] {
        return None;
    }
    let mut attributs = r.get(20..20 + usize::from(u16::from_be_bytes([r[2], r[3]])))?;
    let mut simple = None;
    while let [t1, t2, n1, n2, reste @ ..] = attributs {
        let n = usize::from(u16::from_be_bytes([*n1, *n2]));
        let valeur = reste.get(..n)?;
        match [*t1, *t2] {
            [0x00, 0x20] => return adresse(valeur, Some(id)),
            [0x00, 0x01] => simple = adresse(valeur, None),
            _ => {}
        }
        // Chaque attribut est complété à un multiple de 4 octets.
        attributs = reste.get(n.div_ceil(4) * 4..).unwrap_or_default();
    }
    simple
}

/// Adresse et port vus par un serveur, depuis `socket` : trois essais, une réponse UDP pouvant se perdre.
fn interroger(socket: &UdpSocket, serveur: SocketAddr) -> Option<SocketAddr> {
    let id = identifiant();
    let mut tampon = [0u8; 576];
    let mut lire = |r: &[u8], de: SocketAddr| lire_reponse(r, &id).filter(|_| de == serveur);
    for _ in 0..3 {
        socket.send_to(&requete(&id), serveur).ok()?;
        let fin = Instant::now() + Duration::from_millis(800);
        let vue = recevoir(socket, fin, &mut tampon, &mut lire);
        if vue.is_some() {
            return vue;
        }
    }
    None
}

pub(crate) struct Mesure {
    /// Adresse de cet ordinateur sur son réseau.
    pub(crate) locale: IpAddr,
    pub(crate) port_local: u16,
    /// (serveur, adresse et port vus) : deux serveurs à des adresses différentes, au plus.
    pub(crate) vues: Vec<(&'static str, SocketAddr)>,
}

/// L'adresse et le port vus d'Internet (`v6` : par l'IPv6), aussi pour l'audit du réseau. `None` : pas de socket.
pub(crate) fn mesurer(v6: bool) -> Option<Mesure> {
    let liste: Vec<(&str, SocketAddr)> = SERVEURS
        .iter()
        .filter_map(|&(nom, port, operateur)| {
            let a = (nom, port).to_socket_addrs().ok()?.find(|a| a.is_ipv6() == v6)?;
            Some((operateur, a))
        })
        .collect();
    let lier = || UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).ok();
    let socket = lier()?;
    let port_local = socket.local_addr().ok()?.port();
    // L'adresse de cet ordinateur vers Internet : celle d'un second socket tourné vers un serveur, sans rien envoyer.
    let sonde = lier()?;
    sonde.connect(liste.first()?.1).ok()?;
    let locale = sonde.local_addr().ok()?.ip();
    let mut vues = Vec::new();
    let mut repondu: Vec<IpAddr> = Vec::new();
    for (operateur, serveur) in liste {
        // Deux réponses d'adresses différentes suffisent ; deux serveurs à la même adresse n'en font qu'un.
        if vues.len() == 2 || repondu.contains(&serveur.ip()) {
            continue;
        }
        if let Some(vue) = interroger(&socket, serveur) {
            vues.push((operateur, vue));
            repondu.push(serveur.ip());
        }
    }
    Some(Mesure {
        locale,
        port_local,
        vues,
    })
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum TypeNat {
    Ouvert,
    Modere,
    Strict,
    /// Un seul serveur a répondu : la traduction de la box n'a pas pu se comparer.
    Incertain,
}

/// Le type de NAT, et pourquoi. `upnp` : l'UPnP de la box est-il actif (None : on ne sait pas).
fn juger(m: &Mesure, upnp: Option<bool>) -> Option<(TypeNat, &'static str)> {
    let (_, premiere) = m.vues.first()?;
    Some(match (m.vues.get(1), upnp) {
        _ if premiere.ip() == m.locale => (
            TypeNat::Ouvert,
            tr!(
                "Pas de NAT : cet ordinateur a lui-même l'adresse publique (seul son pare-feu filtre).",
                "No NAT: this computer has the public address itself (only its firewall filters)."
            ),
        ),
        (None, _) => (
            TypeNat::Incertain,
            tr!(
                "Un seul serveur a répondu : la traduction du routeur n'a pas pu être comparée.",
                "Only one server answered: the router's translation could not be compared."
            ),
        ),
        (Some((_, seconde)), _) if seconde != premiere => (
            TypeNat::Strict,
            tr!(
                "Le routeur change de port à chaque destination (NAT symétrique) : les autres joueurs ne peuvent pas vous joindre directement.",
                "The router changes the port for each destination (symmetric NAT): other players cannot reach you directly."
            ),
        ),
        (_, Some(true)) => (
            TypeNat::Ouvert,
            tr!(
                "Même port vu de partout, et l'UPnP du routeur laisse les jeux ouvrir eux-mêmes leurs ports.",
                "Same port seen from everywhere, and the router's UPnP lets games open their ports themselves."
            ),
        ),
        (_, Some(false)) => (
            TypeNat::Modere,
            tr!(
                "Même port vu de partout, mais sans UPnP ni redirection, les autres joueurs ne peuvent pas ouvrir la connexion : certaines parties ne se rejoignent pas.",
                "Same port seen from everywhere, but without UPnP or port forwarding, other players cannot open the connection: some sessions cannot be joined."
            ),
        ),
        (_, None) => (
            TypeNat::Modere,
            tr!(
                "Même port vu de partout. Ouvert si l'UPnP du routeur est actif, ce qui n'a pas pu se lire ici.",
                "Same port seen from everywhere. Open if the router's UPnP is on, which could not be read here."
            ),
        ),
    })
}

/// Double NAT ou adresse partagée par le fournisseur, d'après l'adresse que la box dit avoir sur Internet. Une box sans
/// adresse Internet (0.0.0.0, 169.254.x : lien coupé) ne dit rien du partage.
pub(crate) fn adresse_partagee(box_internet: Option<Ipv4Addr>, publique: IpAddr) -> Option<&'static str> {
    let b = box_internet.filter(|b| !b.is_unspecified() && !b.is_link_local())?;
    match crate::socle::adresses::portee(b.into()) {
        crate::socle::adresses::Portee::Partagee => Some(tr!(
            "Votre fournisseur partage votre adresse Internet avec d'autres abonnés (CGNAT) : aucune redirection de ports ne peut marcher. Demandez-lui une adresse IPv4 publique, ou servez-vous de l'IPv6.",
            "Your provider shares your Internet address with other customers (CGNAT): no port forwarding can work. Ask them for a public IPv4 address, or use IPv6."
        )),
        _ if b.is_private() => Some(tr!(
            "Double NAT : votre routeur est lui-même derrière un autre routeur. Mettez celui du fournisseur en mode « bridge », ou dirigez sa DMZ vers votre propre routeur.",
            "Double NAT: your router is itself behind another router. Put the provider's box in “bridge” mode, or point its DMZ at your router."
        )),
        _ => (IpAddr::V4(b) != publique).then_some(tr!(
            "L'adresse que le routeur dit avoir n'est pas celle que voit Internet : le fournisseur partage sans doute les adresses (CGNAT).",
            "The address the router says it has is not the one the Internet sees: the provider probably shares addresses (CGNAT)."
        )),
    }
}

/// L'IPv6 : absente, directe (pas de NAT : ce que les consoles préfèrent), ou injoignable.
fn afficher_ipv6() {
    // Adresses IPv6 publiques (2000::/3) de cet ordinateur.
    let locales: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .map(if_addrs::Interface::ip)
        .filter(|ip| matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xe000 == 0x2000))
        .collect();
    // Sans adresse, rien à mesurer.
    let vue = (!locales.is_empty()).then(|| mesurer(true).and_then(|m| m.vues.first().map(|v| v.1.ip())));
    println!();
    let directe = |t| afficher_aligne(&format!("  {VERT}✔{RESET} "), t, 4, "");
    let info = |t| afficher_aligne(&format!("  {}ℹ{RESET} ", couleur(Niveau::Info)), t, 4, "");
    match vue {
        None => info(tr!(
            "IPv6 : absente sur ce réseau. Les jeux passent par l'IPv4, et donc par le NAT ci-dessus.",
            "IPv6: absent on this network. Games go through IPv4, hence through the NAT above."
        )),
        Some(Some(ip)) if locales.contains(&ip) => directe(tr!(
            "IPv6 : directe, sans NAT. Les jeux et les consoles qui s'en servent sont joignables, si le pare-feu du routeur les laisse passer.",
            "IPv6: direct, without NAT. Games and consoles that use it are reachable, if the router's firewall lets them through."
        )),
        Some(Some(_)) => info(tr!(
            "IPv6 : présente, mais traduite elle aussi (rare) : comme pour l'IPv4.",
            "IPv6: present, but translated as well (rare): same as IPv4."
        )),
        Some(None) => info(tr!(
            "IPv6 : une adresse, mais Internet ne répond pas par là (bloquée par le routeur ou le fournisseur).",
            "IPv6: an address, but the Internet does not answer that way (blocked by the router or the provider)."
        )),
    }
}

/// Menu Réseau et Internet › Type de NAT, ou `vanguard nat`.
pub fn tester() {
    titre(tr!("Type de NAT pour le jeu", "NAT type for gaming"));
    let intro = tr!(
        "Ouvert, modéré ou strict : c'est ce qui décide si vous pouvez rejoindre les parties des autres, et eux les vôtres. Deux serveurs publics (Cloudflare, Google) disent quelle adresse et quel port ils voient ; ils voient votre adresse, comme n'importe quel site. Rien n'est changé.",
        "Open, moderate or strict: it decides whether you can join other people's sessions, and they yours. Two public servers (Cloudflare, Google) tell which address and port they see; they see your address, like any website. Nothing is changed."
    );
    for ligne in envelopper(intro, LARGEUR - 2) {
        println!("  {ligne}");
    }
    trp!(
        "\n  {GRIS}Interrogation des serveurs…{RESET}",
        "\n  {GRIS}Asking the servers…{RESET}"
    );
    let Some(mesure) = mesurer(false).filter(|m| !m.vues.is_empty()) else {
        let muet = tr!(
            "Aucun serveur n'a répondu : pas d'Internet, ou l'UDP sortant est bloqué (pare-feu, réseau d'entreprise ou d'hôtel). Le jeu en ligne sera alors difficile.",
            "No server answered: no Internet, or outgoing UDP is blocked (firewall, company or hotel network). Online gaming will then be hard."
        );
        afficher_aligne("  ✖ ", muet, 4, "");
        return;
    };
    let (upnp, box_internet) = crate::reseau::upnp::etat_et_adresse();
    let (upnp_actif, etat_upnp) = match upnp {
        Etat::Actif(_) => (Some(true), tr!("actif", "on")),
        Etat::Absent => (Some(false), tr!("coupé ou absent", "off or absent")),
        Etat::OutilAbsent => (
            None,
            tr!("inconnu (routeur non interrogé)", "unknown (router not queried)"),
        ),
        Etat::Usurpee(_) => (
            None,
            tr!(
                "inconnu (un autre appareil se dit routeur)",
                "unknown (another device claims to be the router)"
            ),
        ),
    };
    let publique = mesure.vues[0].1;
    println!();
    let champ = |nom, valeur: &str| afficher_aligne(&format!("  {GRIS}{}{RESET}", ajuster(nom, 18)), valeur, 20, "");
    champ(tr!("Adresse publique", "Public address"), &publique.ip().to_string());
    let ports: Vec<String> = mesure
        .vues
        .iter()
        .map(|(nom, vue)| trf!("{nom} voit le port {}", "{nom} sees port {}", vue.port()))
        .collect();
    let vus = trf!(
        "{} (port de cet ordinateur : {})",
        "{} (this computer's port: {})",
        ports.join(", "),
        mesure.port_local
    );
    champ(tr!("Ports vus", "Ports seen"), &vus);
    champ(tr!("UPnP du routeur", "Router UPnP"), etat_upnp);
    let Some((type_nat, pourquoi)) = juger(&mesure, upnp_actif) else {
        return;
    };
    let (libelle, teinte) = match type_nat {
        TypeNat::Ouvert => (tr!("OUVERT", "OPEN"), VERT),
        TypeNat::Modere => (tr!("MODÉRÉ", "MODERATE"), couleur(Niveau::Info)),
        TypeNat::Strict => (tr!("STRICT", "STRICT"), couleur(Niveau::Moyen)),
        TypeNat::Incertain => (tr!("INCERTAIN", "UNCERTAIN"), couleur(Niveau::Info)),
    };
    let playstation = tr!(
        "(PlayStation : type 2 si modéré, 3 si strict)",
        "(PlayStation: type 2 if moderate, 3 if strict)"
    );
    println!("\n  {GRAS}NAT{RESET} : {teinte}{libelle}{RESET}  {GRIS}{playstation}{RESET}");
    afficher_aligne("  ", pourquoi, 2, "");
    if let Some(partage) = adresse_partagee(box_internet, publique.ip()) {
        afficher_aligne(&format!("  {}⚠{RESET} ", couleur(Niveau::Moyen)), partage, 4, "");
    }
    afficher_ipv6();
    println!();
    let conseil = match type_nat {
        TypeNat::Ouvert => tr!("Rien à faire pour le jeu en ligne.", "Nothing to do for online gaming."),
        TypeNat::Modere | TypeNat::Incertain => tr!(
            "Pour passer en ouvert : activez l'UPnP dans le routeur, ou redirigez les ports du jeu vers cet appareil, après lui avoir donné une adresse fixe (réservation DHCP). L'UPnP laisse tout appareil ouvrir des ports, un appareil infecté aussi : surveillez-les (Scanner le réseau). La DMZ expose l'appareil entier à Internet : seulement pour une console.",
            "To get open: turn UPnP on in the router, or forward the game's ports to this device after giving it a fixed address (DHCP reservation). UPnP lets any device open ports, an infected one too: keep an eye on them (Scan the network). The DMZ exposes the whole device to the Internet: only for a console."
        ),
        TypeNat::Strict => tr!(
            "Une redirection de ports vers cet appareil (adresse fixe d'abord) ou l'UPnP du routeur contournent souvent le NAT symétrique. Sinon, regardez dans le routeur une option « NAT » ou « jeu » (« endpoint-independent »), ou passez par l'IPv6.",
            "Port forwarding to this device (fixed address first) or the router's UPnP often get around symmetric NAT. Otherwise, look in the router for a “NAT” or “gaming” option (“endpoint-independent”), or use IPv6."
        ),
    };
    afficher_aligne(&format!("  {} ", ampoule()), conseil, 5, "");
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Un datagramme trop gros (WSAEMSGSIZE sous Windows) ou un faux « port injoignable » (WSAECONNRESET) juste après
    /// la question : l'écoute continue, et la vraie réponse est lue. Seul le délai l'arrête.
    #[test]
    fn une_erreur_de_reception_ne_coupe_pas_l_ecoute() {
        let box_ = SocketAddr::from(([192, 168, 1, 1], 1900));
        let mut suite = vec![
            Err(std::io::Error::other("WSAEMSGSIZE")),
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
            Ok((2, box_)),
        ]
        .into_iter();
        let fin = Instant::now() + std::time::Duration::from_secs(5);
        let mut tampon = [7u8; 8];
        let lu = recevoir_avec(
            |_, _| suite.next().unwrap(),
            fin,
            &mut tampon,
            |m, de| Some((m.len(), de)),
        );
        assert_eq!(lu, Some((2, box_)));
        // Le délai, lui, arrête.
        let lu = recevoir_avec(
            |_, _| Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            fin,
            &mut tampon,
            |_, _| Some(()),
        );
        assert_eq!(lu, None);
        // Une socket hors d'usage n'est pas écoutée à vide jusqu'au délai.
        let lu = recevoir_avec(
            |_, _| Err(std::io::Error::other("hors d'usage")),
            fin,
            &mut tampon,
            |_, _| Some(()),
        );
        assert_eq!(lu, None);
        assert!(Instant::now() < fin);
    }

    /// Plus de datagrammes trop gros (ou d'ICMP) que le plafond, puis la box : ils ont chacun été retirés de la file,
    /// l'écoute continue et la box est lue (avant, 257 suffisaient à rendre « UPnP coupé »).
    #[test]
    fn datagrammes_trop_gros_au_dela_du_plafond() {
        let box_ = SocketAddr::from(([192, 168, 1, 1], 1900));
        let mut suite = (0..300)
            .map(|_| Err(std::io::Error::from_raw_os_error(WSAEMSGSIZE)))
            .chain((0..300).map(|_| Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))))
            .chain(std::iter::once(Ok((2, box_))));
        let fin = Instant::now() + std::time::Duration::from_secs(5);
        let mut tampon = [7u8; 8];
        let lu = recevoir_avec(
            |_, _| suite.next().unwrap(),
            fin,
            &mut tampon,
            |m, de| Some((m.len(), de)),
        );
        assert_eq!(lu, Some((2, box_)));
    }

    /// Pour de vrai, sur la boucle locale : un datagramme plus gros que le tampon, puis la réponse attendue.
    #[test]
    fn datagramme_trop_gros_puis_reponse() {
        let ecoute = UdpSocket::bind("127.0.0.1:0").unwrap();
        let envoi = UdpSocket::bind("127.0.0.1:0").unwrap();
        let vers = ecoute.local_addr().unwrap();
        envoi.send_to(&[0u8; 8192], vers).unwrap();
        envoi.send_to(b"HTTP/1.1 200 OK", vers).unwrap();
        let mut tampon = vec![0u8; 4096];
        let fin = Instant::now() + std::time::Duration::from_secs(3);
        let lu = recevoir(&ecoute, fin, &mut tampon, |m, _| {
            m.starts_with(b"HTTP/1.1").then_some(())
        });
        assert_eq!(lu, Some(()));
    }

    /// Réponse « Binding Success » avec une XOR-MAPPED-ADDRESS (et un attribut inconnu avant, de longueur impaire).
    pub(super) fn reponse(id: &[u8; 12], vue: SocketAddr) -> Vec<u8> {
        let mut attribut = vec![0x80, 0x22, 0, 3, b'a', b'b', b'c', 0];
        let (famille, octets): (u8, Vec<u8>) = match vue.ip() {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (2, v6.octets().to_vec()),
        };
        let mut cle = MAGIC.to_be_bytes().to_vec();
        cle.extend(id);
        let masquee: Vec<u8> = octets.iter().zip(&cle).map(|(a, k)| a ^ k).collect();
        let longueur = u16::try_from(4 + masquee.len()).unwrap();
        attribut.extend([0x00, 0x20]);
        attribut.extend(longueur.to_be_bytes());
        attribut.extend([0, famille]);
        attribut.extend((vue.port() ^ MAGIC_HAUT).to_be_bytes());
        attribut.extend(masquee);
        let mut r = vec![0x01, 0x01];
        r.extend(u16::try_from(attribut.len()).unwrap().to_be_bytes());
        r.extend(MAGIC.to_be_bytes());
        r.extend(id);
        r.extend(attribut);
        r
    }

    #[test]
    fn requete_et_reponses_stun() {
        let id = identifiant();
        assert_ne!(id, identifiant(), "deux identifiants identiques");
        let r = requete(&id);
        assert_eq!((r[0], r[1], r[2], r[3]), (0, 1, 0, 0));
        for vue in ["203.0.113.7:54321", "[2001:db8::7]:40000"] {
            let vue: SocketAddr = vue.parse().unwrap();
            assert_eq!(lire_reponse(&reponse(&id, vue), &id), Some(vue));
        }
        // Réponse à une autre requête, message tronqué : ignorés.
        let autre = identifiant();
        let vue: SocketAddr = "203.0.113.7:1".parse().unwrap();
        assert_eq!(lire_reponse(&reponse(&autre, vue), &id), None);
        assert_eq!(lire_reponse(&reponse(&id, vue)[..24], &id), None);
        // MAPPED-ADDRESS d'un ancien serveur, en clair.
        let mut ancien = vec![0x01, 0x01, 0, 12];
        ancien.extend(MAGIC.to_be_bytes());
        ancien.extend(id);
        ancien.extend([0x00, 0x01, 0, 8, 0, 1, 0x1f, 0x90, 198, 51, 100, 9]);
        assert_eq!(lire_reponse(&ancien, &id), "198.51.100.9:8080".parse().ok());
    }

    fn mesure(locale: &str, vues: &[&str]) -> Mesure {
        Mesure {
            locale: locale.parse().unwrap(),
            port_local: 50000,
            vues: vues
                .iter()
                .zip(["cloudflare", "google"])
                .map(|(v, n)| (n, v.parse().unwrap()))
                .collect(),
        }
    }

    #[test]
    fn verdicts() {
        let cone = mesure("10.0.0.20", &["203.0.113.7:50000", "203.0.113.7:50000"]);
        assert_eq!(juger(&cone, Some(true)).unwrap().0, TypeNat::Ouvert);
        assert_eq!(juger(&cone, Some(false)).unwrap().0, TypeNat::Modere);
        assert_eq!(juger(&cone, None).unwrap().0, TypeNat::Modere);
        let symetrique = mesure("10.0.0.20", &["203.0.113.7:61000", "203.0.113.7:61004"]);
        assert_eq!(juger(&symetrique, Some(true)).unwrap().0, TypeNat::Strict);
        let direct = mesure("203.0.113.7", &["203.0.113.7:50000", "203.0.113.7:50000"]);
        assert_eq!(juger(&direct, Some(false)).unwrap().0, TypeNat::Ouvert);
        let seul = mesure("10.0.0.20", &["203.0.113.7:50000"]);
        assert_eq!(juger(&seul, None).unwrap().0, TypeNat::Incertain);
        assert!(juger(&mesure("10.0.0.20", &[]), None).is_none());
    }

    #[test]
    fn adresses_partagees() {
        let publique: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(adresse_partagee(Some(Ipv4Addr::new(100, 72, 1, 2)), publique).is_some_and(|t| t.contains("CGNAT")));
        assert!(adresse_partagee(Some(Ipv4Addr::new(192, 168, 1, 2)), publique).is_some());
        assert!(adresse_partagee(Some(Ipv4Addr::new(198, 51, 100, 3)), publique).is_some());
        assert_eq!(adresse_partagee(Some(Ipv4Addr::new(203, 0, 113, 7)), publique), None);
        assert_eq!(adresse_partagee(None, publique), None);
        // Une box sans adresse Internet (lien coupé, 0.0.0.0 ou 169.254.x) ne dit rien du partage d'adresses.
        assert_eq!(adresse_partagee(Some(Ipv4Addr::UNSPECIFIED), publique), None);
        assert_eq!(adresse_partagee(Some(Ipv4Addr::new(169, 254, 3, 4)), publique), None);
    }

    /// L'attente commune au NAT, au DNS et aux caméras, sur cet ordinateur (127.0.0.1) : rien ne sort sur le réseau.
    #[test]
    fn reception_udp() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let envoi = UdpSocket::bind("127.0.0.1:0").unwrap();
        for message in [&b"autre"[..], b"attendu"] {
            envoi.send_to(message, socket.local_addr().unwrap()).unwrap();
        }
        let mut tampon = [0u8; 64];
        // Un message qui n'est pas la réponse attendue est passé : on attend la suivante.
        let fin = Instant::now() + Duration::from_secs(5);
        let de = recevoir(&socket, fin, &mut tampon, |r, de| (r == b"attendu").then_some(de));
        assert_eq!(de, envoi.local_addr().ok());
        // Plus rien n'arrive : rien, au délai écoulé.
        let debut = Instant::now();
        let fin = debut + Duration::from_millis(200);
        assert_eq!(recevoir(&socket, fin, &mut tampon, |_, _| Some(())), None);
        assert!(debut.elapsed() >= Duration::from_millis(150) && debut.elapsed() < Duration::from_secs(3));
        assert_ne!(hasard(), hasard(), "deux tirages identiques");
    }
}

/// Propriétés de la lecture STUN : n'importe quel serveur, ou n'importe qui sur le chemin, peut répondre n'importe
/// quoi. Rien ne plante, et une réponse à une autre requête n'est jamais prise.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn reponses_quelconques(octets in prop::collection::vec(any::<u8>(), 0..200), id in any::<[u8; 12]>()) {
            let _ = lire_reponse(&octets, &id);
        }

        #[test]
        fn reponse_a_une_autre_requete_ignoree(vue in any::<SocketAddr>(), id in any::<[u8; 12]>(), autre in any::<[u8; 12]>()) {
            prop_assume!(id != autre);
            // STUN ne transmet que l'adresse et le port (ni flux ni zone IPv6).
            let vue = SocketAddr::new(vue.ip(), vue.port());
            prop_assert_eq!(lire_reponse(&super::tests::reponse(&id, vue), &id), Some(vue));
            prop_assert_eq!(lire_reponse(&super::tests::reponse(&autre, vue), &id), None);
        }
    }
}
