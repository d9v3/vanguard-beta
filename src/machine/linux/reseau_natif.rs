//! Le réseau de la machine lu par netlink, sans `ss`, `ip` ni `resolvectl` : toutes les prises TCP et UDP (tous
//! états, sock_diag), les voisins (RTM_GETNEIGH), les adresses (RTM_GETADDR) et les routes de toutes les tables
//! (RTM_GETROUTE). Pour les traces d'incident : un binaire remplacé par un rootkit ne cache plus rien ici.
//!
//! Les messages viennent du noyau ; ils restent bornés quand même (attributs lus dans leur message, longueurs
//! vérifiées), et un message d'une forme inattendue est laissé.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::IpAddr;

use super::ecoute::demander_netlink;
use crate::reseau::scan::messages_netlink;

const NETLINK_ROUTE: i32 = 0;
const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;

/// Les états d'une prise, nommés comme ss les nomme (include/net/tcp_states.h).
fn etat(n: u8, udp: bool) -> &'static str {
    match n {
        1 if udp => "ESTAB",
        1 => "ESTAB",
        2 => "SYN-SENT",
        3 => "SYN-RECV",
        4 => "FIN-WAIT-1",
        5 => "FIN-WAIT-2",
        6 => "TIME-WAIT",
        7 => "UNCONN",
        8 => "CLOSE-WAIT",
        9 => "LAST-ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW-SYN-RECV",
        _ => "?",
    }
}

/// Une prise TCP ou UDP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Prise {
    pub udp: bool,
    pub etat: u8,
    pub locale: IpAddr,
    pub port_local: u16,
    pub distante: IpAddr,
    pub port_distant: u16,
    pub uid: u32,
    pub inode: u64,
    /// Le programme (pid, nom), quand ce compte peut le voir.
    pub programme: Option<(u32, String)>,
}

impl Prise {
    /// En écoute : TCP LISTEN, ou UDP ouverte sans pair (UNCONN), comme ss -l les montre.
    pub(crate) fn a_l_ecoute(&self) -> bool {
        if self.udp { self.etat == 7 } else { self.etat == 10 }
    }

    pub(crate) fn ligne(&self) -> String {
        let point = |a: &IpAddr, p: u16| match a {
            IpAddr::V4(a) => format!("{a}:{p}"),
            IpAddr::V6(a) => format!("[{a}]:{p}"),
        };
        format!(
            "{}\t{}\t{}\t{}\tuid {}\tinode {}\t{}",
            if self.udp { "udp" } else { "tcp" },
            etat(self.etat, self.udp),
            point(&self.locale, self.port_local),
            point(&self.distante, self.port_distant),
            self.uid,
            self.inode,
            self.programme
                .as_ref()
                .map(|(pid, nom)| format!("pid {pid} ({nom})"))
                .unwrap_or_default()
        )
    }
}

/// La demande sock_diag de toutes les prises d'une famille et d'un protocole, tous états.
fn demande_toutes(famille: u8, protocole: u8) -> [u8; 72] {
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    let mut d = [0u8; 72];
    d[0..4].copy_from_slice(&72u32.to_ne_bytes());
    d[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    d[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    d[8..12].copy_from_slice(&1u32.to_ne_bytes());
    d[16] = famille;
    d[17] = protocole;
    d[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    d
}

/// Une adresse de 4 ou 16 octets selon la famille.
fn adresse(famille: u8, o: &[u8]) -> Option<IpAddr> {
    match famille {
        AF_INET => Some(IpAddr::from(<[u8; 4]>::try_from(o.get(..4)?).ok()?)),
        AF_INET6 => Some(IpAddr::from(<[u8; 16]>::try_from(o.get(..16)?).ok()?)),
        _ => None,
    }
}

/// Les prises des messages inet_diag_msg : famille, état, ports (ordre du réseau), adresses locale et distante sur
/// 16 octets, puis uid et inode.
fn lire_prises(octets: &[u8], udp: bool) -> Vec<Prise> {
    messages_netlink(octets)
        .filter(|(genre, corps)| *genre == SOCK_DIAG_BY_FAMILY && corps.len() >= 72)
        .filter_map(|(_, c)| {
            Some(Prise {
                udp,
                etat: c[1],
                port_local: u16::from_be_bytes([c[4], c[5]]),
                port_distant: u16::from_be_bytes([c[6], c[7]]),
                locale: adresse(c[0], &c[8..24])?,
                distante: adresse(c[0], &c[24..40])?,
                uid: u32::from_ne_bytes([c[64], c[65], c[66], c[67]]),
                inode: u64::from(u32::from_ne_bytes([c[68], c[69], c[70], c[71]])),
                programme: None,
            })
        })
        .collect()
}

/// Toutes les prises TCP et UDP, IPv4 et IPv6, avec leur programme quand ce compte le voit (`ss -tunap`). `None` :
/// le noyau ne répond pas pour l'une des quatre listes.
pub(crate) fn prises() -> Option<Vec<Prise>> {
    let mut prises = Vec::new();
    for (protocole, udp) in [(IPPROTO_TCP, false), (IPPROTO_UDP, true)] {
        for famille in [AF_INET, AF_INET6] {
            prises.extend(lire_prises(
                &demander_netlink(NETLINK_SOCK_DIAG, &demande_toutes(famille, protocole))?,
                udp,
            ));
        }
    }
    let proprietaires = crate::protection::sortantes::proprietaires();
    for p in &mut prises {
        p.programme = proprietaires
            .get(&p.inode)
            .and_then(|pid| Some((*pid, crate::socle::processus::nom_court(*pid)?)));
    }
    Some(prises)
}

/// Une demande de liste rtnetlink : l'en-tête, puis le message de tête de la famille (`taille` octets, la famille en
/// premier, AF_UNSPEC : toutes).
fn demande_route(genre: u16, taille: usize) -> Vec<u8> {
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    let n = 16 + taille;
    let mut d = vec![0u8; n];
    d[0..4].copy_from_slice(&u32::try_from(n).unwrap_or(0).to_ne_bytes());
    d[4..6].copy_from_slice(&genre.to_ne_bytes());
    d[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    d[8..12].copy_from_slice(&1u32.to_ne_bytes());
    d
}

/// Les attributs rtnetlink (longueur u16, type u16, valeur, alignés sur 4) d'un message, après son en-tête de
/// `debut` octets : type → valeur.
fn attributs(corps: &[u8], debut: usize) -> HashMap<u16, &[u8]> {
    let mut a = HashMap::new();
    let mut pos = debut;
    while let Some(t) = corps.get(pos..pos + 4) {
        let longueur = usize::from(u16::from_ne_bytes([t[0], t[1]]));
        if longueur < 4 {
            break;
        }
        if let Some(v) = corps.get(pos + 4..pos + longueur) {
            // Le bit 15 (NLA_F_NESTED) et 14 ne font pas partie du type.
            a.insert(u16::from_ne_bytes([t[2], t[3]]) & 0x3fff, v);
        }
        pos += longueur.next_multiple_of(4);
    }
    a
}

/// Le nom de chaque interface par son numéro, d'après /sys/class/net.
fn interfaces() -> HashMap<u32, String> {
    std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let n = std::fs::read_to_string(e.path().join("ifindex"))
                .ok()?
                .trim()
                .parse()
                .ok()?;
            Some((n, e.file_name().to_string_lossy().into_owned()))
        })
        .collect()
}

fn nom_interface(noms: &HashMap<u32, String>, n: u32) -> String {
    noms.get(&n).cloned().unwrap_or_else(|| format!("if{n}"))
}

fn adresse_mac(o: &[u8]) -> String {
    o.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Les voisins (IPv4 et IPv6) : adresse, interface, adresse matérielle, état (`ip neigh show`).
pub(crate) fn voisins() -> Option<Vec<String>> {
    let r = demander_netlink(NETLINK_ROUTE, &demande_route(RTM_GETNEIGH, 12))?;
    Some(lire_voisins(&r, &interfaces()))
}

fn lire_voisins(octets: &[u8], noms: &HashMap<u32, String>) -> Vec<String> {
    const ETATS: [(u16, &str); 8] = [
        (0x01, "INCOMPLETE"),
        (0x02, "REACHABLE"),
        (0x04, "STALE"),
        (0x08, "DELAY"),
        (0x10, "PROBE"),
        (0x20, "FAILED"),
        (0x40, "NOARP"),
        (0x80, "PERMANENT"),
    ];
    messages_netlink(octets)
        .filter(|(g, c)| *g == RTM_NEWNEIGH && c.len() >= 12)
        .filter_map(|(_, c)| {
            let a = attributs(c, 12);
            let ip = adresse(c[0], a.get(&1)?)?;
            let index = u32::from_ne_bytes([c[4], c[5], c[6], c[7]]);
            let etat = u16::from_ne_bytes([c[8], c[9]]);
            let etats: Vec<&str> = ETATS.iter().filter(|(b, _)| etat & b != 0).map(|(_, n)| *n).collect();
            Some(format!(
                "{ip}\tdev {}\tlladdr {}\t{}",
                nom_interface(noms, index),
                a.get(&2).map(|m| adresse_mac(m)).unwrap_or_default(),
                etats.join(",")
            ))
        })
        .collect()
}

/// Les adresses de chaque interface (`ip address show`) : interface, adresse/préfixe, portée, étiquette.
pub(crate) fn adresses() -> Option<Vec<String>> {
    let r = demander_netlink(NETLINK_ROUTE, &demande_route(RTM_GETADDR, 8))?;
    Some(lire_adresses(&r, &interfaces()))
}

fn lire_adresses(octets: &[u8], noms: &HashMap<u32, String>) -> Vec<String> {
    messages_netlink(octets)
        .filter(|(g, c)| *g == RTM_NEWADDR && c.len() >= 8)
        .filter_map(|(_, c)| {
            let a = attributs(c, 8);
            // IFA_LOCAL est l'adresse de l'interface ; IFA_ADDRESS, celle du pair d'un lien point à point.
            let ip = adresse(c[0], a.get(&2).or_else(|| a.get(&1))?)?;
            let index = u32::from_ne_bytes([c[4], c[5], c[6], c[7]]);
            let portee = match c[3] {
                0 => "global",
                200 => "site",
                253 => "link",
                254 => "host",
                _ => "?",
            };
            Some(format!(
                "{}\t{ip}/{}\tscope {portee}\t{}",
                nom_interface(noms, index),
                c[1],
                a.get(&3)
                    .map(|l| String::from_utf8_lossy(l.split(|&o| o == 0).next().unwrap_or_default()).into_owned())
                    .unwrap_or_default()
            ))
        })
        .collect()
}

/// Les routes de toutes les tables, IPv4 et IPv6 (`ip route show table all`, et `-6`) : destination, passerelle,
/// interface, table, métrique, source préférée.
pub(crate) fn routes() -> Option<Vec<String>> {
    let r = demander_netlink(NETLINK_ROUTE, &demande_route(RTM_GETROUTE, 12))?;
    Some(lire_routes(&r, &interfaces()))
}

fn lire_routes(octets: &[u8], noms: &HashMap<u32, String>) -> Vec<String> {
    let entier = |v: Option<&&[u8]>| {
        v.and_then(|v| <[u8; 4]>::try_from(v.get(..4)?).ok())
            .map(u32::from_ne_bytes)
    };
    messages_netlink(octets)
        .filter(|(g, c)| *g == RTM_NEWROUTE && c.len() >= 12)
        .map(|(_, c)| {
            let a = attributs(c, 12);
            let famille = c[0];
            let destination = a
                .get(&1)
                .and_then(|d| adresse(famille, d))
                .map_or_else(|| "default".to_string(), |d| format!("{d}/{}", c[1]));
            let table = entier(a.get(&15)).unwrap_or(u32::from(c[4]));
            let mut l = format!("{destination}\ttable {table}");
            if let Some(g) = a.get(&5).and_then(|g| adresse(famille, g)) {
                let _ = write!(l, "\tvia {g}");
            }
            if let Some(i) = entier(a.get(&4)) {
                let _ = write!(l, "\tdev {}", nom_interface(noms, i));
            }
            if let Some(m) = entier(a.get(&6)) {
                let _ = write!(l, "\tmetric {m}");
            }
            if let Some(s) = a.get(&7).and_then(|s| adresse(famille, s)) {
                let _ = write!(l, "\tsrc {s}");
            }
            let _ = write!(l, "\tproto {} type {}", c[5], c[7]);
            l
        })
        .collect()
}

/// Une valeur D-Bus écrite en une ligne : textes et nombres tels quels, booléens en yes/no, une suite de 4 ou 16
/// octets en adresse IP, tableaux et structures entre crochets et parenthèses.
fn valeur_en_ligne(v: &super::dbus::Valeur) -> String {
    use super::dbus::Valeur;
    match v.nue() {
        Valeur::Booleen(b) => if *b { "yes" } else { "no" }.to_string(),
        Valeur::Texte(t) => t.clone(),
        Valeur::Tableau(e) if !e.is_empty() && e.iter().all(|x| matches!(x, Valeur::Octet(_))) => {
            let o: Vec<u8> = e
                .iter()
                .filter_map(|x| match x {
                    Valeur::Octet(o) => Some(*o),
                    _ => None,
                })
                .collect();
            match o.len() {
                4 => IpAddr::from(<[u8; 4]>::try_from(o.as_slice()).unwrap_or_default()).to_string(),
                16 => IpAddr::from(<[u8; 16]>::try_from(o.as_slice()).unwrap_or_default()).to_string(),
                _ => String::from_utf8_lossy(&o).into_owned(),
            }
        }
        Valeur::Tableau(e) => format!("[{}]", e.iter().map(valeur_en_ligne).collect::<Vec<_>>().join(", ")),
        Valeur::Structure(e) => format!("({})", e.iter().map(valeur_en_ligne).collect::<Vec<_>>().join(" ")),
        Valeur::Dictionnaire(e) => format!(
            "{{{}}}",
            e.iter()
                .map(|(k, v)| format!("{}: {}", valeur_en_ligne(k), valeur_en_ligne(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        autre => autre.entier().map_or_else(|| format!("{autre:?}"), |n| n.to_string()),
    }
}

/// L'état de systemd-resolved par D-Bus (`resolvectl status`) : toutes les propriétés du gestionnaire, puis celles
/// de chaque lien (par le numéro d'interface). `Err` : resolved injoignable.
pub(crate) fn resolved() -> Result<Vec<String>, crate::modele::Echec> {
    use super::dbus::Bus;
    const RESOLVE1: &str = "org.freedesktop.resolve1";
    let echec = |e: String| crate::modele::Echec::echoue("reseau/resolved", e);
    let mut bus = Bus::systeme().map_err(echec)?;
    let mut lignes = vec!["Global".to_string()];
    let p = bus
        .proprietes(
            RESOLVE1,
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
        )
        .map_err(echec)?;
    lignes.extend(
        p.entrees()
            .iter()
            .map(|(k, v)| format!("  {} = {}", valeur_en_ligne(k), valeur_en_ligne(v))),
    );
    let mut liens: Vec<(u32, String)> = interfaces().into_iter().collect();
    liens.sort();
    for (n, nom) in liens {
        // Le chemin d'un lien : son numéro, premier chiffre échappé (« 3 » → « _33 »).
        let chemin = format!("/org/freedesktop/resolve1/link/_3{n}");
        let Ok(p) = bus.proprietes(RESOLVE1, &chemin, "org.freedesktop.resolve1.Link") else {
            continue;
        };
        lignes.push(format!("Link {n} ({nom})"));
        lignes.extend(
            p.entrees()
                .iter()
                .map(|(k, v)| format!("  {} = {}", valeur_en_ligne(k), valeur_en_ligne(v))),
        );
    }
    Ok(lignes)
}

/// Les ports à l'écoute d'une sortie de `ss -tunap` : (udp, port), pour la comparer au relevé.
pub(crate) fn ecoutes_de_ss(sortie: &str) -> std::collections::HashSet<(bool, u16)> {
    sortie
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let udp = match *c.first()? {
                "tcp" => false,
                "udp" => true,
                _ => return None,
            };
            let ecoute = if udp { "UNCONN" } else { "LISTEN" };
            if *c.get(1)? != ecoute {
                return None;
            }
            let port = c.get(4)?.rsplit_once(':')?.1.parse().ok()?;
            Some((udp, port))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(genre: u16, corps: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend(u32::try_from(16 + corps.len()).unwrap().to_ne_bytes());
        m.extend(genre.to_ne_bytes());
        m.extend([0u8; 10]);
        m.extend(corps);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    fn attribut(genre: u16, valeur: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend(u16::try_from(4 + valeur.len()).unwrap().to_ne_bytes());
        a.extend(genre.to_ne_bytes());
        a.extend(valeur);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    #[test]
    fn prises_fabriquees() {
        let mut c = vec![0u8; 72];
        c[0] = AF_INET;
        c[1] = 1;
        c[4..6].copy_from_slice(&22u16.to_be_bytes());
        c[6..8].copy_from_slice(&50_000u16.to_be_bytes());
        c[8..12].copy_from_slice(&[192, 0, 2, 1]);
        c[24..28].copy_from_slice(&[203, 0, 113, 9]);
        c[64..68].copy_from_slice(&1000u32.to_ne_bytes());
        c[68..72].copy_from_slice(&4242u32.to_ne_bytes());
        let mut octets = message(SOCK_DIAG_BY_FAMILY, &c);
        // Trop court, puis une famille inconnue : laissés.
        octets.extend(message(SOCK_DIAG_BY_FAMILY, &[0u8; 40]));
        let mut autre = c.clone();
        autre[0] = 99;
        octets.extend(message(SOCK_DIAG_BY_FAMILY, &autre));
        let p = lire_prises(&octets, false);
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].port_local, p[0].port_distant, p[0].uid, p[0].inode),
            (22, 50_000, 1000, 4242)
        );
        assert_eq!(
            p[0].ligne(),
            "tcp\tESTAB\t192.0.2.1:22\t203.0.113.9:50000\tuid 1000\tinode 4242\t"
        );
        assert!(!p[0].a_l_ecoute());
    }

    #[test]
    fn route_voisin_adresse_fabriques() {
        let noms: HashMap<u32, String> = [(2, "wlan0".to_string())].into();
        let mut r = vec![0u8; 12];
        r[0] = AF_INET;
        r[4] = 254;
        r.extend(attribut(5, &[192, 168, 1, 1]));
        r.extend(attribut(4, &2u32.to_ne_bytes()));
        r.extend(attribut(6, &600u32.to_ne_bytes()));
        // Un attribut dont la longueur dépasse le message : laissé, sans lire au-delà.
        r.extend([200, 0, 7, 0]);
        let l = lire_routes(&message(RTM_NEWROUTE, &r), &noms);
        assert_eq!(
            l,
            ["default\ttable 254\tvia 192.168.1.1\tdev wlan0\tmetric 600\tproto 0 type 0"]
        );
        let mut n = vec![0u8; 12];
        n[0] = AF_INET;
        n[4..8].copy_from_slice(&2u32.to_ne_bytes());
        n[8..10].copy_from_slice(&0x04u16.to_ne_bytes());
        n.extend(attribut(1, &[192, 168, 1, 1]));
        n.extend(attribut(2, &[0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]));
        assert_eq!(
            lire_voisins(&message(RTM_NEWNEIGH, &n), &noms),
            ["192.168.1.1\tdev wlan0\tlladdr 00:1a:2b:3c:4d:5e\tSTALE"]
        );
        let mut a = vec![0u8; 8];
        a[0] = AF_INET6;
        a[1] = 64;
        a[3] = 253;
        a[4..8].copy_from_slice(&9u32.to_ne_bytes());
        let mut v6 = [0u8; 16];
        v6[..2].copy_from_slice(&[0xfe, 0x80]);
        v6[15] = 1;
        a.extend(attribut(1, &v6));
        assert_eq!(
            lire_adresses(&message(RTM_NEWADDR, &a), &noms),
            ["if9\tfe80::1/64\tscope link\t"]
        );
        // Un message d'un autre genre, ou vide : rien.
        assert_eq!(lire_routes(&message(RTM_NEWNEIGH, &r), &noms).len(), 0);
        assert_eq!(lire_routes(&[], &noms).len(), 0);
    }

    #[test]
    fn ports_a_l_ecoute_de_ss() {
        let ss = "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
                  udp   UNCONN 0      0      127.0.0.53%lo:53   0.0.0.0:*\n\
                  tcp   LISTEN 0      4096   [::]:22            [::]:*\n\
                  tcp   ESTAB  0      0      192.0.2.1:22       203.0.113.9:50000\n";
        let e = ecoutes_de_ss(ss);
        assert_eq!(e, [(true, 53), (false, 22)].into_iter().collect());
    }

    /// L'oracle : chaque port à l'écoute vu par le noyau (sock_diag) se retrouve dans `ss -tunap`, sur cet
    /// ordinateur (des nombres seulement dans le message).
    #[test]
    fn ecoutes_comme_ss() {
        let Some(natives) = prises() else {
            return crate::essais::saute("sock_diag refusé");
        };
        let Some(ss) = crate::machine::sortie("ss", &["-tunap"]) else {
            return crate::essais::saute("ss absent");
        };
        let outil = ecoutes_de_ss(&ss);
        let absents = natives
            .iter()
            .filter(|p| p.a_l_ecoute() && !outil.contains(&(p.udp, p.port_local)))
            .count();
        assert_eq!(absents, 0, "ports à l'écoute absents de ss");
        assert!(routes().is_some_and(|r| !r.is_empty()));
        assert!(adresses().is_some_and(|a| !a.is_empty()));
        assert!(voisins().is_some());
    }
}
