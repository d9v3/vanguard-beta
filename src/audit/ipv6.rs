//! L'IPv6 de la maison, lue d'ici : les adresses publiques (2000::/3) de cet ordinateur, stables ou temporaires, et
//! le nombre de voisins du réseau local qui en ont une. En IPv6, pas de NAT : chaque appareil a sa propre adresse
//! joignable, et seul un pare-feu (celui de la box, celui de l'appareil) arrête Internet. Lecture seule, sans
//! commande externe : if-addrs partout, /proc/net/if_inet6 et netlink sous Linux ; ailleurs, les voisins et le
//! caractère temporaire d'une adresse ne se lisent pas d'ici, et c'est dit tel quel.

use std::net::Ipv6Addr;

use serde::Serialize;

use crate::ui::affichable;

/// Une adresse publique de cet ordinateur.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub struct Adresse {
    pub interface: String,
    pub ip: Ipv6Addr,
    /// Adresse temporaire (RFC 8981 : changée régulièrement pour ne pas suivre l'appareil) ; `None` : ne se lit
    /// pas sur ce système.
    pub temporaire: Option<bool>,
}

/// Ce qui a été lu.
#[derive(Serialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Lecture {
    /// Les interfaces ont pu être lues ; sinon rien n'est conclu.
    pub lue: bool,
    /// Adresses publiques de cet ordinateur, hors ponts et conteneurs (joignables de cette machine seulement).
    pub adresses: Vec<Adresse>,
    /// Voisins du réseau local (hors cet ordinateur) avec une adresse publique ; `None` : non lus sur ce système.
    pub voisins_publics: Option<usize>,
}

pub fn lire() -> Lecture {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Lecture::default();
    };
    let temporaires = temporaires();
    let adresses = interfaces
        .into_iter()
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V6(v6) if publique(v6.ip) && !virtuelle(&i.name) => Some(Adresse {
                interface: affichable(&i.name),
                ip: v6.ip,
                temporaire: temporaires.as_ref().map(|t| t.contains(&v6.ip)),
            }),
            _ => None,
        })
        .collect();
    Lecture {
        lue: true,
        adresses,
        voisins_publics: voisins_publics(),
    }
}

/// Une adresse IPv6 publique : une adresse mondiale (2000::/3, RFC 4291), joignable d'Internet, à la différence des
/// adresses de lien local (fe80::/10) et des adresses locales uniques (fc00::/7). La règle commune
/// (`socle::adresses`) compte comme Internet tout ce qu'elle ne place pas ailleurs, le côté prudent pour bloquer ;
/// ici, ce serait annoncer l'ordinateur joignable d'Internet pour une adresse « ::192.168.1.5 » de sit0 ou un
/// préfixe de traduction 64:ff9b::/96. D'où la limite à 2000::/3 par-dessus.
pub fn publique(ip: Ipv6Addr) -> bool {
    ip.segments()[0] & 0xe000 == 0x2000 && crate::socle::adresses::sur_internet(ip.into())
}

/// Le préfixe /64 d'une adresse, celui que le fournisseur a donné à la maison : à montrer à la place de l'adresse
/// entière, qui change (adresses temporaires) et désigne l'appareil.
pub fn prefixe(ip: Ipv6Addr) -> String {
    let s = ip.segments();
    let debut = Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0).to_string();
    format!("{}::/64", debut.trim_end_matches("::"))
}

/// Interfaces qui ne mènent pas au réseau local : la boucle locale, les ponts et conteneurs (la même liste que
/// `linux::adresses_exposees`).
pub(crate) fn virtuelle(nom: &str) -> bool {
    [
        "lo", "docker", "br-", "virbr", "veth", "podman", "lxc", "lxdbr", "incusbr", "waydroid", "vnet",
    ]
    .iter()
    .any(|p| nom.starts_with(p))
}

/// Un tunnel (VPN) : son adresse publique vient du fournisseur du VPN, pas de la box.
pub(crate) fn tunnel(nom: &str) -> bool {
    [
        "tun",
        "tap",
        "wg",
        "tailscale",
        "utun",
        "ppp",
        "zt",
        "nebula",
        "proton",
        "nordlynx",
        "mullvad",
    ]
    .iter()
    .any(|p| nom.starts_with(p))
}

/// Les adresses temporaires (drapeau IFA_F_TEMPORARY de /proc/net/if_inet6) ; `None` : ne se lit pas ici.
#[cfg(target_os = "linux")]
fn temporaires() -> Option<std::collections::HashSet<Ipv6Addr>> {
    let texte = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    Some(
        lire_if_inet6(&texte)
            .into_iter()
            .filter(|(_, temporaire, _)| *temporaire)
            .map(|(ip, _, _)| ip)
            .collect(),
    )
}

#[cfg(not(target_os = "linux"))]
fn temporaires() -> Option<std::collections::HashSet<Ipv6Addr>> {
    None
}

/// Les lignes de /proc/net/if_inet6 : « 20010db8000100020000000000000001 02 40 00 80 eth0 » (adresse, numéro
/// d'interface, longueur du préfixe, portée, drapeaux, interface) → (adresse, temporaire, interface). Le drapeau
/// 0x01 est IFA_F_TEMPORARY.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lire_if_inet6(texte: &str) -> Vec<(Ipv6Addr, bool, String)> {
    texte
        .lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            let [hex, _, _, _, drapeaux, nom] = c[..] else {
                return None;
            };
            if hex.len() != 32 || !hex.is_ascii() {
                return None;
            }
            let mut octets = [0u8; 16];
            for (i, o) in octets.iter_mut().enumerate() {
                *o = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
            }
            let drapeaux = u8::from_str_radix(drapeaux, 16).ok()?;
            Some((Ipv6Addr::from(octets), drapeaux & 0x01 != 0, nom.to_string()))
        })
        .collect()
}

/// Les voisins IPv6 publics du réseau local, demandés au noyau par netlink (RTM_GETNEIGH, famille AF_INET6), comme
/// `ip -6 neigh show` le fait, sans le lancer. Un appareil compte une fois, à son adresse matérielle : il a souvent
/// plusieurs adresses publiques (une stable, des temporaires). `None` : le noyau refuse, ou pas de Linux.
#[cfg(target_os = "linux")]
fn voisins_publics() -> Option<usize> {
    // La même demande que le scan fait pour l'IPv4 (`scan::demander_voisins`), avec la famille AF_INET6.
    crate::reseau::scan::demander_voisins(libc::AF_INET6).map(|r| compter_voisins_publics(&r))
}

#[cfg(not(target_os = "linux"))]
fn voisins_publics() -> Option<usize> {
    None
}

/// Le nombre d'appareils voisins avec une adresse IPv6 publique, dans les messages RTM_NEWNEIGH : famille AF_INET6,
/// voisin joignable (ni sans ARP, ni en échec, ni en attente), adresse (attribut NDA_DST) publique, compté une fois
/// par adresse matérielle (attribut NDA_LLADDR).
#[cfg(any(target_os = "linux", test))]
fn compter_voisins_publics(octets: &[u8]) -> usize {
    const RTM_NEWNEIGH: u16 = 28;
    // AF_INET6 de Linux, écrit ici : la lecture est aussi testée sous Windows, sans libc.
    const AF_INET6: u8 = 10;
    const NDA_DST: u16 = 1;
    const NDA_LLADDR: u16 = 2;
    let mut appareils = std::collections::HashSet::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        // ndmsg : famille (1), bourrage (3), interface (4), état (2), drapeaux (1), type (1) ; puis les attributs.
        let [famille, _, _, _, _, _, _, _, e0, e1, _, _, ..] = *corps else {
            continue;
        };
        if genre != RTM_NEWNEIGH || famille != AF_INET6 {
            continue;
        }
        let etat = u16::from_ne_bytes([e0, e1]);
        // NOARP (0x40), FAILED (0x20), INCOMPLETE (0x01) ou sans état : pas un appareil joignable.
        if etat == 0 || etat & 0x61 != 0 {
            continue;
        }
        let mut adresse = None;
        let mut materielle = None;
        let mut pos = 12;
        while let Some(&[l0, l1, g0, g1]) = corps.get(pos..pos + 4) {
            let longueur = usize::from(u16::from_ne_bytes([l0, l1]));
            let genre_attribut = u16::from_ne_bytes([g0, g1]);
            if longueur < 4 {
                break;
            }
            let valeur = corps.get(pos + 4..pos + longueur);
            match genre_attribut {
                NDA_DST => adresse = valeur.and_then(|a| <[u8; 16]>::try_from(a).ok()).map(Ipv6Addr::from),
                NDA_LLADDR => materielle = valeur.map(<[u8]>::to_vec),
                _ => {}
            }
            pos += longueur.next_multiple_of(4);
        }
        if let (Some(ip), Some(mac)) = (adresse, materielle)
            && publique(ip)
        {
            appareils.insert(mac);
        }
    }
    appareils.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adresses_publiques_et_prefixes() {
        let publique_1 = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        assert!(publique(publique_1));
        assert!(publique("2a01:cb00:1:2::1".parse().unwrap()));
        // Hors de 2000::/3 : adresse IPv4 compatible de sit0, traduction NAT64, préfixe à jeter (RFC 6666), plage
        // pas encore attribuée.
        for privee in [
            "fe80::1",
            "fd12:3456::1",
            "::1",
            "::ffff:10.0.0.1",
            "ff02::1",
            "::192.168.1.5",
            "64:ff9b::808:808",
            "100::1",
            "4000::1",
        ] {
            assert!(!publique(privee.parse().unwrap()), "{privee}");
        }
        assert_eq!(prefixe(publique_1), "2001:db8:1:2::/64");
        assert_eq!(prefixe("2001:db8::1".parse().unwrap()), "2001:db8::/64");
        assert_eq!(prefixe("2001:0:0:2::1".parse().unwrap()), "2001:0:0:2::/64");
        assert!(virtuelle("docker0") && virtuelle("br-1a2b") && virtuelle("lo") && !virtuelle("enp5s0"));
        assert!(tunnel("wg0") && tunnel("tun0") && tunnel("tailscale0") && !tunnel("wlan0"));
    }

    #[test]
    fn lignes_de_if_inet6() {
        let texte = "20010db8000100020000000000000001 02 40 00 80     eth0\n\
                     20010db800010002aaaabbbbccccdddd 02 40 00 01     eth0\n\
                     fe800000000000000000000000000001 02 40 20 80     eth0\n\
                     00000000000000000000000000000001 01 80 10 80       lo\n\
                     pas une ligne\n\
                     zz010db8000100020000000000000001 02 40 00 80     eth0\n";
        let lues = lire_if_inet6(texte);
        assert_eq!(lues.len(), 4);
        assert_eq!(lues[0], ("2001:db8:1:2::1".parse().unwrap(), false, "eth0".to_string()));
        assert_eq!(
            lues[1].0,
            "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse::<Ipv6Addr>().unwrap()
        );
        assert!(lues[1].1, "temporaire");
        assert_eq!(lues[3], (Ipv6Addr::LOCALHOST, false, "lo".to_string()));
    }

    /// Une réponse netlink inventée, à la forme de celle du noyau : un appareil à deux adresses publiques, un voisin
    /// de lien local, un voisin IPv4, un voisin en échec, puis la fin.
    #[test]
    fn voisins_publics_comptes() {
        fn voisin(famille: u8, etat: u16, adresse: &[u8], mac: Option<&[u8]>) -> Vec<u8> {
            let mut corps = vec![famille, 0, 0, 0, 2, 0, 0, 0];
            corps.extend_from_slice(&etat.to_ne_bytes());
            corps.extend_from_slice(&[0, 1]);
            let mut attribut = |genre: u16, valeur: &[u8]| {
                corps.extend_from_slice(&u16::try_from(4 + valeur.len()).unwrap().to_ne_bytes());
                corps.extend_from_slice(&genre.to_ne_bytes());
                corps.extend_from_slice(valeur);
                while corps.len() % 4 != 0 {
                    corps.push(0);
                }
            };
            attribut(1, adresse);
            if let Some(mac) = mac {
                attribut(2, mac);
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
        let stable: Ipv6Addr = "2001:db8:1:2::20".parse().unwrap();
        let temporaire: Ipv6Addr = "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let lien: Ipv6Addr = "fe80::1".parse().unwrap();
        let autre: Ipv6Addr = "2001:db8:1:2::30".parse().unwrap();
        let mac_a = [0xf8, 0x79, 0x0a, 0x01, 0x02, 0x03];
        let mac_b = [0x3c, 0x22, 0xfb, 0x04, 0x05, 0x06];
        let mut reponse = voisin(10, 0x02, &stable.octets(), Some(&mac_a));
        reponse.extend(voisin(10, 0x04, &temporaire.octets(), Some(&mac_a)));
        reponse.extend(voisin(10, 0x02, &lien.octets(), Some(&mac_a)));
        reponse.extend(voisin(2, 0x02, &[10, 0, 0, 1], Some(&mac_b)));
        reponse.extend(voisin(10, 0x20, &autre.octets(), None));
        reponse.extend(voisin(10, 0x02, &autre.octets(), Some(&mac_b)));
        reponse.extend(message(3, &[0, 0, 0, 0]));
        assert_eq!(compter_voisins_publics(&reponse), 2);
        // Tronquée ou mensongère : rien de plus, sans paniquer.
        assert_eq!(compter_voisins_publics(&reponse[..40]), 0);
        assert_eq!(
            compter_voisins_publics(&message(28, &[10, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 1, 2, 0, 1, 0])),
            0
        );
    }
}
