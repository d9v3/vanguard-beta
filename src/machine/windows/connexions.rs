//! Les connexions TCP et les ports UDP de Windows, avec leur programme, lus par GetExtendedTcpTable et
//! GetExtendedUdpTable (iphlpapi) sans PowerShell : ce que Get-NetTCPConnection et Get-NetUDPEndpoint donnaient. Les
//! tables rendues sont relues en code sûr, la taille annoncée vérifiée contre ce que Windows a écrit.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Une socket.
#[derive(Debug, PartialEq)]
pub(crate) struct Socket {
    pub tcp: bool,
    /// L'état d'une connexion TCP dans les mots de Get-NetTCPConnection (« Established », « Listen »…) ; vide en UDP.
    pub etat: &'static str,
    pub locale: (IpAddr, u16),
    /// L'autre bout d'une connexion TCP ; `None` en UDP.
    pub distante: Option<(IpAddr, u16)>,
    pub pid: u32,
}

const IPV4: u32 = 2;
const IPV6: u32 = 23;

/// Les sockets TCP (toutes, quel que soit leur état) et UDP, IPv4 puis IPv6 ; `None` si Windows refuse une des
/// tables.
#[cfg(windows)]
pub(crate) fn sockets() -> Option<Vec<Socket>> {
    let mut toutes = Vec::new();
    for famille in [IPV4, IPV6] {
        toutes.extend(lire_tcp(&table(true, famille)?, famille == IPV6));
    }
    for famille in [IPV4, IPV6] {
        toutes.extend(lire_udp(&table(false, famille)?, famille == IPV6));
    }
    Some(toutes)
}

/// Les connexions TCP établies, IPv4 puis IPv6 : le seul lecteur de GetExtendedTcpTable pour les connexions
/// sortantes et la surveillance. `None` : aucune des deux tables ne se lit ; une seule lue suffit.
#[cfg(windows)]
pub(crate) fn tcp_etablies() -> Option<Vec<Socket>> {
    let v4 = table(true, IPV4).map(|t| lire_tcp(&t, false));
    let v6 = table(true, IPV6).map(|t| lire_tcp(&t, true));
    if v4.is_none() && v6.is_none() {
        return None;
    }
    Some(etablies(v4.into_iter().chain(v6).flatten()))
}

/// Les connexions TCP à l'état établi (MIB_TCP_STATE_ESTAB).
fn etablies(sockets: impl Iterator<Item = Socket>) -> Vec<Socket> {
    sockets.filter(|s| s.tcp && s.etat == "Established").collect()
}

/// La table TCP brute d'une famille (2 : IPv4, 23 : IPv6), lue comme `lire_tcp` la lit, pour qui lit d'autres
/// colonnes (le blocage : les ports locaux des sessions à distance).
#[cfg(windows)]
pub(crate) fn table_tcp(famille: u32) -> Option<Vec<u8>> {
    table(true, famille)
}

/// Une table brute (TCP_TABLE_OWNER_PID_ALL ou UDP_TABLE_OWNER_PID), coupée à ce que Windows a écrit.
#[cfg(windows)]
fn table(tcp: bool, famille: u32) -> Option<Vec<u8>> {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(
            table: *mut std::ffi::c_void,
            taille: *mut u32,
            tri: i32,
            famille: u32,
            classe: u32,
            r: u32,
        ) -> u32;
        fn GetExtendedUdpTable(
            table: *mut std::ffi::c_void,
            taille: *mut u32,
            tri: i32,
            famille: u32,
            classe: u32,
            r: u32,
        ) -> u32;
    }
    const TCP_PROPRIETAIRE_TOUTES: u32 = 5;
    const UDP_PROPRIETAIRE: u32 = 1;
    const TROP_PETIT: u32 = 122;
    let mut taille = 64 * 1024u32;
    for _ in 0..4 {
        // Des mots de 32 bits, pour que la table (des DWORD) soit alignée comme Windows l'écrit.
        let mut tampon = vec![0u32; usize::try_from(taille.div_ceil(4)).ok()?];
        let mut ecrit = u32::try_from(tampon.len() * 4).ok()?;
        // SAFETY : `tampon` fait `ecrit` octets, alignés sur 4 ; Windows y écrit au plus `ecrit` octets, ou rien en y
        // mettant la taille voulue s'il en faut plus.
        let code = unsafe {
            if tcp {
                GetExtendedTcpTable(
                    tampon.as_mut_ptr().cast(),
                    &raw mut ecrit,
                    0,
                    famille,
                    TCP_PROPRIETAIRE_TOUTES,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    tampon.as_mut_ptr().cast(),
                    &raw mut ecrit,
                    0,
                    famille,
                    UDP_PROPRIETAIRE,
                    0,
                )
            }
        };
        match code {
            0 => {
                let octets = tampon.iter().flat_map(|m| m.to_ne_bytes());
                return Some(octets.take(usize::try_from(ecrit).ok()?).collect());
            }
            TROP_PETIT => taille = ecrit.max(taille) + 16 * 1024,
            _ => return None,
        }
    }
    None
}

fn u32_a(o: &[u8], d: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(o.get(d..d + 4)?.try_into().ok()?))
}

/// Un port rangé dans un u32, ses deux premiers octets dans l'ordre du réseau.
fn port_a(o: &[u8], d: usize) -> Option<u16> {
    Some(u16::from_be_bytes(o.get(d..d + 2)?.try_into().ok()?))
}

fn ip_a(o: &[u8], d: usize, ipv6: bool) -> Option<IpAddr> {
    Some(if ipv6 {
        IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(o.get(d..d + 16)?).ok()?))
    } else {
        IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(o.get(d..d + 4)?).ok()?))
    })
}

/// Les lignes d'une table : un nombre, puis autant de lignes de `taille` octets qu'en tiennent les octets rendus.
fn lignes(o: &[u8], taille: usize) -> impl Iterator<Item = &[u8]> {
    let n = u32_a(o, 0).and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
    o.get(4..).unwrap_or_default().chunks_exact(taille).take(n)
}

/// MIB_TCPROW_OWNER_PID (état, adresse et port locaux, distants, programme) ou MIB_TCP6ROW_OWNER_PID (adresse, zone,
/// port locaux, distants, état, programme).
fn lire_tcp(o: &[u8], ipv6: bool) -> Vec<Socket> {
    let taille = if ipv6 { 56 } else { 24 };
    lignes(o, taille)
        .filter_map(|l| {
            let (etat, locale, distante, pid) = if ipv6 {
                (
                    u32_a(l, 48)?,
                    (ip_a(l, 0, true)?, port_a(l, 20)?),
                    (ip_a(l, 24, true)?, port_a(l, 44)?),
                    u32_a(l, 52)?,
                )
            } else {
                (
                    u32_a(l, 0)?,
                    (ip_a(l, 4, false)?, port_a(l, 8)?),
                    (ip_a(l, 12, false)?, port_a(l, 16)?),
                    u32_a(l, 20)?,
                )
            };
            Some(Socket {
                tcp: true,
                etat: mot_de_l_etat(etat),
                locale,
                distante: Some(distante),
                pid,
            })
        })
        .collect()
}

/// MIB_UDPROW_OWNER_PID (adresse, port, programme) ou MIB_UDP6ROW_OWNER_PID (adresse, zone, port, programme).
fn lire_udp(o: &[u8], ipv6: bool) -> Vec<Socket> {
    let taille = if ipv6 { 28 } else { 12 };
    lignes(o, taille)
        .filter_map(|l| {
            let (locale, pid) = if ipv6 {
                ((ip_a(l, 0, true)?, port_a(l, 20)?), u32_a(l, 24)?)
            } else {
                ((ip_a(l, 0, false)?, port_a(l, 4)?), u32_a(l, 8)?)
            };
            Some(Socket {
                tcp: false,
                etat: "",
                locale,
                distante: None,
                pid,
            })
        })
        .collect()
}

/// L'état MIB_TCP_STATE dans les mots de Get-NetTCPConnection.
fn mot_de_l_etat(etat: u32) -> &'static str {
    match etat {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTCB",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_relues() {
        // Deux lignes TCP IPv4 annoncées, une seule rendue en entier : la seconde, coupée, est ignorée.
        let mut t = 2u32.to_ne_bytes().to_vec();
        t.extend_from_slice(&5u32.to_ne_bytes());
        t.extend_from_slice(&[192, 0, 2, 10]);
        t.extend_from_slice(&[0x01, 0xbb, 0, 0]);
        t.extend_from_slice(&[198, 51, 100, 7]);
        t.extend_from_slice(&[0xc3, 0x50, 0, 0]);
        t.extend_from_slice(&4242u32.to_ne_bytes());
        t.extend_from_slice(&[0; 10]);
        let l = lire_tcp(&t, false);
        assert_eq!(
            l,
            vec![Socket {
                tcp: true,
                etat: "Established",
                locale: ("192.0.2.10".parse().unwrap(), 443),
                distante: Some(("198.51.100.7".parse().unwrap(), 50000)),
                pid: 4242,
            }]
        );
        // Une ligne UDP IPv6.
        let mut u = 1u32.to_ne_bytes().to_vec();
        u.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        u.extend_from_slice(&0u32.to_ne_bytes());
        u.extend_from_slice(&[0x00, 0x35, 0, 0]);
        u.extend_from_slice(&7u32.to_ne_bytes());
        let l = lire_udp(&u, true);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].locale.1, l[0].pid, l[0].distante), (53, 7, None));
        assert_eq!(lire_tcp(&[1, 0], false), Vec::new());
        assert_eq!(mot_de_l_etat(2), "Listen");
        // Une ligne TCP IPv6 : adresse locale, zone, port, distante, zone, port, état, programme (56 octets).
        let ligne6 = |etat: u32| {
            let mut l = Vec::new();
            l.extend("2001:db8::20".parse::<Ipv6Addr>().unwrap().octets());
            l.extend([0; 4]);
            l.extend([0xc3, 0x51, 0, 0]);
            l.extend("2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
            l.extend([0; 4]);
            l.extend([0x01, 0xbb, 0, 0]);
            l.extend(etat.to_ne_bytes());
            l.extend(777u32.to_ne_bytes());
            l
        };
        let mut t6 = 2u32.to_ne_bytes().to_vec();
        t6.extend(ligne6(5));
        t6.extend(ligne6(2));
        let l = lire_tcp(&t6, true);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].distante, Some(("2606:4700::1111".parse().unwrap(), 443)));
        assert_eq!((l[0].locale.1, l[0].pid), (50001, 777));
        // Seules les établies restent pour les connexions sortantes ; une socket UDP n'en est jamais une.
        let etab = etablies(l.into_iter().chain(lire_udp(&u, true)));
        assert_eq!(etab.len(), 1);
        assert_eq!(etab[0].etat, "Established");
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : les tables se lisent.
    #[cfg(windows)]
    #[test]
    fn sockets_lues_par_windows() {
        let s = sockets().expect("tables TCP et UDP");
        assert!(s.iter().all(|s| s.tcp == s.distante.is_some()));
        assert!(tcp_etablies().is_some() && table_tcp(2).is_some());
    }
}
