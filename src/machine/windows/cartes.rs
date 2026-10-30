//! Les cartes réseau de Windows, lues par GetAdaptersAddresses (iphlpapi) sans PowerShell : index, GUID, état, sorte,
//! IPv6 et serveurs DNS, ce que Get-NetAdapter et Get-DnsClientServerAddress donnaient. Le tampon rendu par Windows est
//! une liste chaînée par pointeurs absolus : il est relu ici en code sûr, chaque pointeur ramené à un décalage dans le
//! tampon et vérifié avant d'être suivi.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IF_TYPE_IEEE80211 : une carte Wi-Fi.
const SANS_FIL: u32 = 71;

impl Carte {
    /// Une carte Wi-Fi : sans aucune, un service WLAN arrêté veut dire « pas de Wi-Fi ».
    pub(crate) fn sans_fil(&self) -> bool {
        self.sorte == SANS_FIL
    }
}

/// Une carte réseau.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Carte {
    /// L'index de l'interface (InterfaceIndex de Get-NetAdapter).
    pub index: u32,
    /// « {GUID} », le nom de la carte dans le registre (InterfaceGuid).
    pub guid: String,
    /// En service (OperStatus « Up »).
    pub active: bool,
    /// Boucle locale ou tunnel (Teredo, 6to4…) : des cartes que Get-NetAdapter ne liste pas.
    pub cachee: bool,
    /// IPv6 activé sur la carte.
    pub ipv6: bool,
    /// La sorte de la carte (IfType : 6 Ethernet, 71 Wi-Fi, 24 boucle locale…).
    pub sorte: u32,
    pub dns: Vec<IpAddr>,
}

// Décalages dans IP_ADAPTER_ADDRESSES (64 bits), jusqu'à Ipv6IfIndex : la seule partie lue.
const IF_INDEX: usize = 4;
const SUIVANTE: usize = 8;
const NOM: usize = 16;
const PREMIER_DNS: usize = 48;
const DRAPEAUX: usize = 92;
const SORTE: usize = 100;
const ETAT: usize = 104;
const IPV6_IF_INDEX: usize = 108;
const TAILLE_LUE: usize = 112;
// IP_ADAPTER_DNS_SERVER_ADDRESS : Length/Reserved, Next, puis SOCKET_ADDRESS (pointeur, longueur).
const DNS_SUIVANT: usize = 8;
const DNS_ADRESSE: usize = 16;
const DNS_LONGUEUR: usize = 24;
const DNS_TAILLE: usize = 28;

/// Les cartes réseau ; `None` si Windows refuse la liste.
#[cfg(windows)]
pub(crate) fn cartes() -> Option<Vec<Carte>> {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetAdaptersAddresses(
            famille: u32,
            drapeaux: u32,
            reserve: *mut std::ffi::c_void,
            adresses: *mut u64,
            taille: *mut u32,
        ) -> u32;
    }
    const SANS_UNICAST_ANYCAST_MULTICAST: u32 = 0x1 | 0x2 | 0x4;
    const TROP_PETIT: u32 = 111;
    let mut taille = 16 * 1024u32;
    for _ in 0..4 {
        // u64 : le tampon est aligné comme les structures que Windows y écrit.
        let mut tampon = vec![0u64; usize::try_from(taille).ok()?.div_ceil(8)];
        let mut ecrit = u32::try_from(tampon.len() * 8).ok()?;
        // SAFETY : Windows écrit au plus `ecrit` octets dans `tampon`, qui les a ; il y met à jour `ecrit`.
        let code = unsafe {
            GetAdaptersAddresses(
                0,
                SANS_UNICAST_ANYCAST_MULTICAST,
                std::ptr::null_mut(),
                tampon.as_mut_ptr(),
                &raw mut ecrit,
            )
        };
        match code {
            0 => {
                let base = tampon.as_ptr() as usize;
                let octets: Vec<u8> = tampon.iter().flat_map(|m| m.to_ne_bytes()).collect();
                return Some(lire(&octets, base));
            }
            TROP_PETIT => taille = ecrit.max(taille * 2),
            _ => return None,
        }
    }
    None
}

fn u32_a(octets: &[u8], decalage: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(octets.get(decalage..decalage + 4)?.try_into().ok()?))
}

fn pointeur_a(octets: &[u8], decalage: usize) -> Option<usize> {
    usize::try_from(u64::from_ne_bytes(octets.get(decalage..decalage + 8)?.try_into().ok()?)).ok()
}

/// Le décalage dans le tampon d'un pointeur de Windows, s'il désigne `taille` octets qui y sont entièrement.
fn dans_le_tampon(pointeur: usize, base: usize, taille: usize, longueur: usize) -> Option<usize> {
    let d = pointeur.checked_sub(base)?;
    (d.checked_add(taille)? <= longueur).then_some(d)
}

/// Relit la liste chaînée écrite par GetAdaptersAddresses dans `octets`, posé en mémoire à l'adresse `base`. Un
/// pointeur hors du tampon arrête la lecture de sa liste ; une boucle aussi (au plus 4 096 maillons).
fn lire(octets: &[u8], base: usize) -> Vec<Carte> {
    let mut cartes = Vec::new();
    let mut d = (octets.len() >= TAILLE_LUE).then_some(0);
    while let Some(c) = d {
        if cartes.len() >= 4096 {
            break;
        }
        let Some(carte) = carte(octets, base, c) else { break };
        cartes.push(carte);
        d = pointeur_a(octets, c + SUIVANTE)
            .filter(|&p| p != 0)
            .and_then(|p| dans_le_tampon(p, base, TAILLE_LUE, octets.len()));
    }
    cartes
}

fn carte(octets: &[u8], base: usize, d: usize) -> Option<Carte> {
    const BOUCLE: u32 = 24;
    const TUNNEL: u32 = 131;
    const IPV6_ACTIF: u32 = 0x100;
    let index = match u32_a(octets, d + IF_INDEX)? {
        0 => u32_a(octets, d + IPV6_IF_INDEX)?,
        i => i,
    };
    let nom = pointeur_a(octets, d + NOM)?;
    let guid = (nom != 0)
        .then(|| {
            let debut = dans_le_tampon(nom, base, 1, octets.len())?;
            let reste = octets.get(debut..)?;
            let fin = reste.iter().position(|&o| o == 0)?;
            Some(String::from_utf8_lossy(reste.get(..fin)?).into_owned())
        })
        .flatten()
        .unwrap_or_default();
    let sorte = u32_a(octets, d + SORTE)?;
    let mut dns = Vec::new();
    let mut maillon = pointeur_a(octets, d + PREMIER_DNS)?;
    // Bornée par les maillons parcourus, pas par les adresses retenues : un maillon sans adresse lisible qui pointe
    // sur lui-même ne doit pas faire tourner la boucle sans fin.
    for _ in 0..64 {
        if maillon == 0 {
            break;
        }
        let Some(m) = dans_le_tampon(maillon, base, DNS_TAILLE, octets.len()) else {
            break;
        };
        let longueur = u32_a(octets, m + DNS_LONGUEUR).and_then(|l| usize::try_from(l).ok())?;
        if let Some(adresse) = pointeur_a(octets, m + DNS_ADRESSE)
            .and_then(|p| dans_le_tampon(p, base, longueur, octets.len()))
            .and_then(|a| octets.get(a..a + longueur))
            .and_then(adresse_ip)
        {
            dns.push(adresse);
        }
        maillon = pointeur_a(octets, m + DNS_SUIVANT)?;
    }
    Some(Carte {
        index,
        guid,
        active: u32_a(octets, d + ETAT)? == 1,
        cachee: matches!(sorte, BOUCLE | TUNNEL),
        ipv6: u32_a(octets, d + DRAPEAUX)? & IPV6_ACTIF != 0,
        sorte,
        dns,
    })
}

/// Une adresse lue dans un SOCKADDR : famille sur deux octets, puis IPv4 (AF_INET, 2) à l'octet 4 ou IPv6 (AF_INET6,
/// 23) à l'octet 8.
fn adresse_ip(s: &[u8]) -> Option<IpAddr> {
    let famille = u16::from_ne_bytes(s.get(..2)?.try_into().ok()?);
    match famille {
        2 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(s.get(4..8)?).ok()?))),
        23 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(s.get(8..24)?).ok()?))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un tampon comme Windows l'écrit, posé à l'adresse `BASE` : une carte Wi-Fi active avec deux DNS (IPv4 et IPv6),
    /// puis une boucle locale.
    const BASE: usize = 0x1_0000;

    fn ecrire_u32(t: &mut [u8], d: usize, v: u32) {
        t[d..d + 4].copy_from_slice(&v.to_ne_bytes());
    }
    fn ecrire_ptr(t: &mut [u8], d: usize, v: usize) {
        t[d..d + 8].copy_from_slice(&(v as u64).to_ne_bytes());
    }

    fn tampon() -> Vec<u8> {
        let mut t = vec![0u8; 1024];
        // Carte 1 à 0, carte 2 à 128, nom à 256, DNS à 320 et 384, adresses à 448 (v4) et 480 (v6).
        ecrire_u32(&mut t, IF_INDEX, 12);
        ecrire_ptr(&mut t, SUIVANTE, BASE + 128);
        ecrire_ptr(&mut t, NOM, BASE + 256);
        ecrire_ptr(&mut t, PREMIER_DNS, BASE + 320);
        ecrire_u32(&mut t, DRAPEAUX, 0x100);
        ecrire_u32(&mut t, SORTE, 71);
        ecrire_u32(&mut t, ETAT, 1);
        t[256..256 + 39].copy_from_slice(b"{11111111-2222-3333-4444-555555555555}\0");
        ecrire_ptr(&mut t, 320 + DNS_SUIVANT, BASE + 384);
        ecrire_ptr(&mut t, 320 + DNS_ADRESSE, BASE + 448);
        ecrire_u32(&mut t, 320 + DNS_LONGUEUR, 16);
        ecrire_ptr(&mut t, 384 + DNS_ADRESSE, BASE + 480);
        ecrire_u32(&mut t, 384 + DNS_LONGUEUR, 28);
        t[448..450].copy_from_slice(&2u16.to_ne_bytes());
        t[452..456].copy_from_slice(&[192, 0, 2, 53]);
        t[480..482].copy_from_slice(&23u16.to_ne_bytes());
        t[488..504].copy_from_slice(&"2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
        ecrire_u32(&mut t, 128 + IF_INDEX, 1);
        ecrire_u32(&mut t, 128 + SORTE, 24);
        ecrire_u32(&mut t, 128 + ETAT, 1);
        t
    }

    #[test]
    fn cartes_relues_dans_le_tampon() {
        let c = lire(&tampon(), BASE);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].index, 12);
        assert_eq!(c[0].guid, "{11111111-2222-3333-4444-555555555555}");
        assert!(c[0].active && c[0].ipv6 && !c[0].cachee);
        assert_eq!(
            c[0].dns,
            vec![
                "192.0.2.53".parse::<IpAddr>().unwrap(),
                "2001:db8::53".parse::<IpAddr>().unwrap()
            ]
        );
        assert!(c[1].cachee && c[1].dns.is_empty() && c[1].guid.is_empty());
    }

    #[test]
    fn pointeurs_hors_du_tampon_ignores() {
        let mut t = tampon();
        // La carte suivante hors du tampon, le nom avant lui, le second DNS à cheval sur la fin.
        ecrire_ptr(&mut t, SUIVANTE, BASE + 1000);
        ecrire_ptr(&mut t, NOM, BASE - 8);
        ecrire_ptr(&mut t, 320 + DNS_SUIVANT, BASE + 1020);
        let c = lire(&t, BASE);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].guid, "");
        assert_eq!(c[0].dns.len(), 1);
        // Une boucle dans la liste des cartes s'arrête.
        let mut boucle = tampon();
        ecrire_ptr(&mut boucle, 128 + SUIVANTE, BASE);
        assert_eq!(lire(&boucle, BASE).len(), 4096);
        assert_eq!(lire(&[0u8; 50], BASE), Vec::new());
        // Un DNS sans adresse lisible (famille 9) qui pointe sur lui-même : la boucle des DNS s'arrête aussi.
        let mut dns_en_boucle = tampon();
        ecrire_ptr(&mut dns_en_boucle, 320 + DNS_SUIVANT, BASE + 320);
        dns_en_boucle[448] = 9;
        let c = lire(&dns_en_boucle, BASE);
        assert_eq!(c[0].dns, Vec::<std::net::IpAddr>::new());
    }

    #[test]
    fn adresses_des_sockaddr() {
        assert_eq!(adresse_ip(&[2, 0, 0, 0, 1, 1, 1, 1]), "1.1.1.1".parse().ok());
        assert_eq!(adresse_ip(&[2, 0, 0, 0, 1]), None);
        assert_eq!(adresse_ip(&[9, 0, 0, 0, 1, 1, 1, 1]), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : la liste se lit et la boucle locale y est cachée.
    #[cfg(windows)]
    #[test]
    fn cartes_lues_par_windows() {
        let c = cartes().expect("GetAdaptersAddresses");
        assert!(c.iter().all(|c| c.index != 0 || c.cachee), "{c:?}");
    }
}
