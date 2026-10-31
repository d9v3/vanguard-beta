//! Où mène une adresse IP : cette machine, le réseau de la maison, le réseau partagé du fournisseur, ou Internet.
//! Une seule règle pour tout Vanguard : le blocage, le fichier hosts, les DNS, les tentatives SSH, les liens et les
//! journaux la recopiaient chacun, et une même adresse se trouvait jugée « sur Internet » par l'un et « locale » par
//! l'autre. Chaque plage vient de son RFC (cité à côté), et un test les vérifie une à une.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// La portée d'une adresse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Portee {
    /// Cette machine : 127.0.0.0/8 (RFC 1122), ::1 (RFC 4291).
    Machine,
    /// Aucune adresse : 0.0.0.0 (RFC 1122), :: (RFC 4291). Les listes de blocage s'en servent pour « nulle part ».
    NonSpecifiee,
    /// Le réseau de la maison : 10/8, 172.16/12, 192.168/16 (RFC 1918), lien local 169.254/16 (RFC 3927) ;
    /// locales uniques fc00::/7 (RFC 4193), lien local fe80::/10 (RFC 4291), site local fec0::/10 (RFC 3879,
    /// abandonnée mais toujours là : Windows met fec0:0:0:ffff::1 à 3 en DNS quand le réseau n'en annonce aucun).
    Locale,
    /// 100.64.0.0/10 (RFC 6598) : le réseau partagé des fournisseurs (CGNAT), et les VPN maillés (Tailscale). Ni la
    /// maison ni Internet : une box derrière ne reçoit rien d'Internet, et l'adresse est celle d'autres abonnés.
    Partagee,
    /// Plusieurs destinataires : 224.0.0.0/4 (RFC 5771), 255.255.255.255 (RFC 919), ff00::/8 (RFC 4291).
    Groupe,
    /// Réservée aux exemples : 192.0.2/24, 198.51.100/24, 203.0.113/24 (RFC 5737), 198.18/15 (essais de débit,
    /// RFC 2544), 2001:db8::/32 (RFC 3849), 3fff::/20 (RFC 9637). Elle ne traverse pas Internet, mais elle tient
    /// lieu d'une adresse d'Internet dans les exemples et les tests, et certains relais (le mode « fake-ip » des
    /// mandataires) en donnent une de 198.18/15 à chaque site visité : jugée comme Internet.
    Exemple,
    /// Jamais attribuée : 0.0.0.0/8 hors 0.0.0.0 (RFC 1122), 240.0.0.0/4 hors 255.255.255.255 (RFC 1112),
    /// fe00::/9 (RFC 4291 ; « fe00::0 ip6-localnet » des fichiers hosts de Debian).
    Reservee,
    /// Tout le reste : une adresse d'Internet.
    Internet,
}

/// La portée de `ip`. Une adresse IPv4 écrite en IPv6 (::ffff:a.b.c.d, RFC 4291 §2.5.5.2), ce que montrent les
/// serveurs qui écoutent les deux, est jugée comme l'adresse IPv4 qu'elle porte.
pub(crate) fn portee(ip: IpAddr) -> Portee {
    match ip {
        IpAddr::V4(v4) => portee_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => portee_v4(v4),
            None => portee_v6(v6),
        },
    }
}

fn portee_v4(ip: Ipv4Addr) -> Portee {
    let [a, b, ..] = ip.octets();
    if ip.is_loopback() {
        Portee::Machine
    } else if ip.is_unspecified() {
        Portee::NonSpecifiee
    } else if ip.is_private() || ip.is_link_local() {
        Portee::Locale
    } else if a == 100 && b & 0xc0 == 64 {
        Portee::Partagee
    } else if ip.is_multicast() || ip.is_broadcast() {
        Portee::Groupe
    } else if ip.is_documentation() || (a == 198 && b & 0xfe == 18) {
        Portee::Exemple
    } else if a == 0 || a >= 240 {
        Portee::Reservee
    } else {
        Portee::Internet
    }
}

fn portee_v6(ip: Ipv6Addr) -> Portee {
    let s = ip.segments()[0];
    if ip.is_loopback() {
        Portee::Machine
    } else if ip.is_unspecified() {
        Portee::NonSpecifiee
    } else if s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80 || s & 0xffc0 == 0xfec0 {
        Portee::Locale
    } else if ip.is_multicast() {
        Portee::Groupe
    } else if (s == 0x2001 && ip.segments()[1] == 0x0db8) || (s == 0x3fff && ip.segments()[1] & 0xf000 == 0) {
        Portee::Exemple
    } else if s & 0xff80 == 0xfe00 {
        Portee::Reservee
    } else {
        Portee::Internet
    }
}

/// Un serveur sur Internet, pas cette machine ni un appareil de la maison ou du fournisseur. Ce qu'on ne sait pas
/// placer ailleurs (une adresse d'exemple, une plage pas encore attribuée hors de 2000::/3) compte comme Internet :
/// le côté prudent pour le blocage et le fichier hosts.
pub(crate) fn sur_internet(ip: IpAddr) -> bool {
    matches!(portee(ip), Portee::Internet | Portee::Exemple)
}

/// Un appareil du réseau de la maison ou du réseau partagé du fournisseur (box, NAS, résolveur local, VPN maillé) :
/// ni cette machine ni Internet.
pub(crate) fn du_reseau(ip: IpAddr) -> bool {
    matches!(portee(ip), Portee::Locale | Portee::Partagee)
}

/// Une adresse IPv6 de lien local (fe80::/10, ou site local fec0::/10) : elle ne se joint qu'avec le nom de la carte
/// réseau (« fe80::1%3 »), qu'une adresse seule ne dit pas.
pub(crate) fn lien_local_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments()[0];
    s & 0xffc0 == 0xfe80 || s & 0xffc0 == 0xfec0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(texte: &str) -> Portee {
        portee(texte.parse().unwrap())
    }

    /// Chaque plage aux deux bouts, et l'adresse juste à côté, qui n'en est plus.
    #[test]
    fn plages_des_rfc() {
        use Portee::*;
        let attendu = [
            // RFC 1122 : boucle locale et « ce réseau ».
            ("127.0.0.1", Machine),
            ("127.255.255.254", Machine),
            ("0.0.0.0", NonSpecifiee),
            ("0.1.2.3", Reservee),
            // RFC 1918 et RFC 3927.
            ("10.0.0.1", Locale),
            ("10.255.255.255", Locale),
            ("11.0.0.1", Internet),
            ("172.16.0.1", Locale),
            ("172.31.255.255", Locale),
            ("172.32.0.1", Internet),
            ("172.15.255.255", Internet),
            ("192.168.1.10", Locale),
            ("192.169.0.1", Internet),
            ("169.254.10.20", Locale),
            // RFC 6598 : 100.64.0.0 à 100.127.255.255.
            ("100.64.0.1", Partagee),
            ("100.127.255.255", Partagee),
            ("100.63.255.255", Internet),
            ("100.128.0.1", Internet),
            // RFC 5771, RFC 919.
            ("224.0.0.251", Groupe),
            ("239.255.255.250", Groupe),
            ("255.255.255.255", Groupe),
            // RFC 5737, RFC 2544.
            ("192.0.2.7", Exemple),
            ("198.51.100.7", Exemple),
            ("203.0.113.7", Exemple),
            ("198.18.0.1", Exemple),
            ("198.19.255.255", Exemple),
            ("198.20.0.1", Internet),
            // RFC 1112.
            ("240.0.0.1", Reservee),
            ("254.255.255.255", Reservee),
            ("9.9.9.9", Internet),
            // RFC 4291, 4193, 3879, 3849, 9637.
            ("::1", Machine),
            ("::", NonSpecifiee),
            ("fd12:3456::1", Locale),
            ("fc00::1", Locale),
            ("fe80::1", Locale),
            ("febf::1", Locale),
            ("fec0:0:0:ffff::1", Locale),
            ("feff::1", Locale),
            ("fe00::", Reservee),
            ("fe7f::1", Reservee),
            ("ff02::1", Groupe),
            ("2001:db8::1", Exemple),
            ("2001:db9::1", Internet),
            ("3fff::1", Exemple),
            ("3fff:1000::1", Internet),
            ("2606:4700:4700::1111", Internet),
            // Une IPv4 écrite en IPv6 : celle qu'elle porte.
            ("::ffff:192.168.1.5", Locale),
            ("::ffff:100.64.1.2", Partagee),
            ("::ffff:9.9.9.9", Internet),
        ];
        for (texte, portee) in attendu {
            assert_eq!(p(texte), portee, "{texte}");
        }
    }

    #[test]
    fn internet_et_reseau() {
        let oui = |t: &str| sur_internet(t.parse().unwrap());
        assert!(oui("9.9.9.9") && oui("203.0.113.7") && oui("2001:db8::1") && oui("198.18.0.5"));
        assert!(!oui("192.168.1.1") && !oui("100.64.1.2") && !oui("127.0.0.1") && !oui("0.0.0.0"));
        assert!(!oui("fe80::1") && !oui("fec0::1") && !oui("ff02::1") && !oui("fe00::") && !oui("240.0.0.1"));
        // Le défaut des tentatives SSH : une adresse de la maison vue par un serveur qui écoute en IPv6.
        assert!(!oui("::ffff:192.168.1.5"));
        let local = |t: &str| du_reseau(t.parse().unwrap());
        assert!(local("192.168.1.1") && local("100.64.1.2") && local("fd00::1") && local("fec0:0:0:ffff::1"));
        assert!(!local("127.0.0.1") && !local("9.9.9.9") && !local("::1"));
        assert!(lien_local_v6("fe80::1".parse().unwrap()) && lien_local_v6("fec0::1".parse().unwrap()));
        assert!(!lien_local_v6("fd00::1".parse().unwrap()));
    }

    proptest::proptest! {
        /// Une adresse a une seule portée, et « sur Internet » et « du réseau » ne se recouvrent jamais.
        #[test]
        fn exclusives(octets: [u8; 16]) {
            let v6 = IpAddr::V6(Ipv6Addr::from(octets));
            let v4 = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
            for ip in [v4, v6] {
                proptest::prop_assert!(!(sur_internet(ip) && du_reseau(ip)));
            }
        }
    }
}
