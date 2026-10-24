//! La passerelle par défaut et la table ARP de macOS, lues dans la table de routage du noyau par sysctl
//! (CTL_NET, PF_ROUTE, NET_RT_FLAGS) au lieu de `route -n get default` et `arp -an` : rien à lancer ni à lire dans un
//! texte. Les messages rendus (rt_msghdr, puis les adresses qu'annonce rtm_addrs, chacune arrondie à 4 octets comme
//! le fait le noyau de macOS) sont relus en code sûr ; la lecture se teste ici sur des messages fabriqués, la vraie
//! table seulement sur un Mac.

use std::net::Ipv4Addr;

/// sizeof(struct rt_msghdr) sous macOS (net/route.h) : l'en-tête de 36 octets et rt_metrics (14 mots).
const ENTETE: usize = 92;
/// RTM_VERSION de macOS.
const VERSION: u8 = 5;
const AF_INET: u8 = 2;
const AF_LINK: u8 = 18;
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
/// Une route « limitée à une interface » : macOS en garde une par carte ; la route par défaut principale ne l'est pas.
const RTF_IFSCOPE: i32 = 0x0100_0000;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
/// Les huit adresses possibles d'un message (RTAX_MAX).
const ADRESSES: u32 = 8;

/// Une adresse d'un message : sa famille et ses octets (sockaddr entier).
struct Adresse<'a> {
    famille: u8,
    octets: &'a [u8],
}

impl Adresse<'_> {
    /// L'adresse IPv4 d'un sockaddr_in (famille, port, adresse) ; une adresse vide (longueur 0, un masque nul) vaut
    /// 0.0.0.0.
    fn ipv4(&self) -> Option<Ipv4Addr> {
        if self.octets.is_empty() {
            return Some(Ipv4Addr::UNSPECIFIED);
        }
        (self.famille == AF_INET).then_some(())?;
        // Un masque peut être écrit plus court que sockaddr_in : les octets manquants valent zéro.
        let mut a = [0u8; 4];
        for (i, o) in self.octets.iter().skip(4).take(4).enumerate() {
            a[i] = *o;
        }
        Some(Ipv4Addr::from(a))
    }

    /// L'adresse matérielle d'un sockaddr_dl (sdl_nlen à 5, sdl_alen à 6, le nom puis l'adresse à partir de 8), en
    /// « aa:bb:cc:dd:ee:ff » ; `None` si ce n'en est pas une de 6 octets (entrée incomplète).
    fn mac(&self) -> Option<String> {
        (self.famille == AF_LINK).then_some(())?;
        let nom = usize::from(*self.octets.get(5)?);
        let longueur = usize::from(*self.octets.get(6)?);
        (longueur == 6).then_some(())?;
        let octets = self.octets.get(8 + nom..8 + nom + 6)?;
        Some(octets.iter().map(|o| format!("{o:02x}")).collect::<Vec<_>>().join(":"))
    }
}

/// Un message de la table : ses drapeaux et ses adresses, rangées par leur bit de rtm_addrs.
struct Route<'a> {
    drapeaux: i32,
    adresses: Vec<(i32, Adresse<'a>)>,
}

impl Route<'_> {
    fn adresse(&self, bit: i32) -> Option<&Adresse<'_>> {
        self.adresses.iter().find(|(b, _)| *b == bit).map(|(_, a)| a)
    }
}

/// Les messages d'un tampon rendu par sysctl, chacun de la longueur qu'il annonce ; un message abîmé arrête la
/// lecture (la suite ne se repère plus).
fn routes(tampon: &[u8]) -> Vec<Route<'_>> {
    let mut v = Vec::new();
    let mut reste = tampon;
    while reste.len() >= ENTETE {
        let longueur = usize::from(u16::from_ne_bytes([reste[0], reste[1]]));
        if longueur < ENTETE || longueur > reste.len() {
            break;
        }
        let (message, suite) = reste.split_at(longueur);
        reste = suite;
        if message[2] != VERSION {
            continue;
        }
        let entier = |d: usize| i32::from_ne_bytes([message[d], message[d + 1], message[d + 2], message[d + 3]]);
        let (drapeaux, presentes) = (entier(8), entier(12));
        let mut adresses = Vec::new();
        let mut d = ENTETE;
        for i in 0..ADRESSES {
            let bit = 1 << i;
            if presentes & bit == 0 {
                continue;
            }
            let Some(&taille) = message.get(d) else {
                break;
            };
            let taille = usize::from(taille);
            let famille = message.get(d + 1).copied().unwrap_or(0);
            let octets = message.get(d..d + taille).unwrap_or_default();
            adresses.push((bit, Adresse { famille, octets }));
            // ROUNDUP32 du noyau de macOS : une adresse vide prend quand même 4 octets.
            d += if taille == 0 { 4 } else { taille.div_ceil(4) * 4 };
        }
        v.push(Route { drapeaux, adresses });
    }
    v
}

/// La passerelle de la route par défaut principale : 0.0.0.0, masque nul, par une passerelle IPv4, et pas limitée à
/// une interface (celles-là doublent la principale pour chaque carte).
fn passerelle_de(tampon: &[u8]) -> Option<Ipv4Addr> {
    routes(tampon).iter().find_map(|r| {
        let utile = r.drapeaux & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY && r.drapeaux & RTF_IFSCOPE == 0;
        let defaut = r.adresse(RTA_DST)?.ipv4()? == Ipv4Addr::UNSPECIFIED
            && r.adresse(RTA_NETMASK)
                .is_none_or(|m| m.ipv4() == Some(Ipv4Addr::UNSPECIFIED));
        let passerelle = r.adresse(RTA_GATEWAY)?.ipv4()?;
        (utile && defaut && !passerelle.is_unspecified()).then_some(passerelle)
    })
}

/// Les voisins de la table ARP dont l'adresse matérielle est connue : (adresse, « aa:bb:… »).
fn voisins_de(tampon: &[u8]) -> Vec<(Ipv4Addr, String)> {
    routes(tampon)
        .iter()
        .filter_map(|r| Some((r.adresse(RTA_DST)?.ipv4()?, r.adresse(RTA_GATEWAY)?.mac()?)))
        .filter(|(ip, _)| !ip.is_unspecified())
        .collect()
}

#[cfg(target_os = "macos")]
mod natif {
    use std::net::Ipv4Addr;

    // La forme de rt_msghdr que la lecture suppose, vérifiée à la compilation pour macOS.
    const _: () = assert!(std::mem::size_of::<libc::rt_msghdr>() == super::ENTETE);

    /// La table de routage IPv4 filtrée sur `drapeaux` (RTF_GATEWAY, RTF_LLINFO), telle que le noyau la rend. Elle
    /// peut grandir entre la demande de sa taille et sa lecture : quelques essais.
    fn table(drapeaux: libc::c_int) -> Option<Vec<u8>> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_ROUTE,
            0,
            libc::AF_INET,
            libc::NET_RT_FLAGS,
            drapeaux,
        ];
        for _ in 0..4 {
            let mut taille: libc::size_t = 0;
            // SAFETY : sans tampon, sysctl écrit seulement la taille nécessaire dans `taille`, à nous.
            if unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    std::ptr::null_mut(),
                    &raw mut taille,
                    std::ptr::null_mut(),
                    0,
                )
            } != 0
            {
                return None;
            }
            // Une marge, pour une route ajoutée entre les deux appels.
            let mut tampon = vec![0u8; taille + 4096];
            let mut ecrit = tampon.len();
            // SAFETY : le tampon fait `ecrit` octets, à nous ; sysctl y écrit au plus autant et rend ce qu'il a écrit.
            let code = unsafe {
                libc::sysctl(
                    mib.as_mut_ptr(),
                    6,
                    tampon.as_mut_ptr().cast(),
                    &raw mut ecrit,
                    std::ptr::null_mut(),
                    0,
                )
            };
            if code == 0 {
                tampon.truncate(ecrit.min(tampon.len()));
                return Some(tampon);
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
                return None;
            }
        }
        None
    }

    pub(crate) fn passerelle() -> Option<Ipv4Addr> {
        super::passerelle_de(&table(libc::RTF_GATEWAY)?)
    }

    pub(crate) fn voisins() -> Option<Vec<(Ipv4Addr, String)>> {
        Some(super::voisins_de(&table(libc::RTF_LLINFO)?))
    }
}

#[cfg(target_os = "macos")]
pub(crate) use natif::{passerelle, voisins};

#[cfg(test)]
mod tests {
    use super::*;

    fn sockaddr_in(ip: [u8; 4]) -> Vec<u8> {
        let mut s = vec![16, AF_INET, 0, 0];
        s.extend(ip);
        s.resize(16, 0);
        s
    }

    /// Un sockaddr_dl : longueur, famille, index, type, longueur du nom, de l'adresse, du sélecteur, le nom puis
    /// l'adresse ; arrondi à 4 par `message`.
    fn sockaddr_dl(nom: &[u8], mac: &[u8]) -> Vec<u8> {
        let mut s = vec![
            0,
            AF_LINK,
            4,
            0,
            6,
            u8::try_from(nom.len()).unwrap(),
            u8::try_from(mac.len()).unwrap(),
            0,
        ];
        s.extend(nom);
        s.extend(mac);
        s.resize(s.len().max(20), 0);
        s[0] = u8::try_from(s.len()).unwrap();
        s
    }

    /// Un message rt_msghdr : longueur, version, drapeaux, adresses présentes, puis chacune arrondie à 4 octets.
    fn message(drapeaux: i32, adresses: &[(i32, Vec<u8>)]) -> Vec<u8> {
        let mut m = vec![0u8; ENTETE];
        m[2] = VERSION;
        m[8..12].copy_from_slice(&drapeaux.to_ne_bytes());
        let presentes = adresses.iter().fold(0, |p, (b, _)| p | b);
        m[12..16].copy_from_slice(&presentes.to_ne_bytes());
        for (_, a) in adresses {
            m.extend(a);
            let arrondi = if a.is_empty() { 4 } else { a.len().div_ceil(4) * 4 };
            m.resize(m.len() + arrondi - a.len(), 0);
        }
        let longueur = u16::try_from(m.len()).unwrap();
        m[0..2].copy_from_slice(&longueur.to_ne_bytes());
        m
    }

    #[test]
    fn passerelle_de_la_table() {
        let defaut = |drapeaux, passerelle| {
            message(
                drapeaux,
                &[
                    (RTA_DST, sockaddr_in([0, 0, 0, 0])),
                    (RTA_GATEWAY, sockaddr_in(passerelle)),
                    // Le masque de la route par défaut : vide.
                    (RTA_NETMASK, Vec::new()),
                ],
            )
        };
        let reseau = message(
            RTF_UP,
            &[
                (RTA_DST, sockaddr_in([192, 168, 1, 0])),
                (RTA_GATEWAY, sockaddr_dl(b"en0", &[])),
            ],
        );
        let t = [
            reseau,
            // La route limitée à une interface vient d'abord, la principale ensuite.
            defaut(RTF_UP | RTF_GATEWAY | RTF_IFSCOPE, [10, 0, 0, 1]),
            defaut(RTF_UP | RTF_GATEWAY, [192, 168, 1, 1]),
        ]
        .concat();
        assert_eq!(passerelle_de(&t), Some(Ipv4Addr::new(192, 168, 1, 1)));
        // Sans route principale : rien plutôt que la passerelle d'une seule carte.
        assert_eq!(
            passerelle_de(&defaut(RTF_UP | RTF_GATEWAY | RTF_IFSCOPE, [10, 0, 0, 1])),
            None
        );
        // Une route par défaut éteinte ne compte pas.
        assert_eq!(passerelle_de(&defaut(RTF_GATEWAY, [192, 168, 1, 1])), None);
        for n in 0..t.len() {
            let _ = passerelle_de(&t[..n]);
        }
    }

    #[test]
    fn voisins_de_la_table_arp() {
        let voisin = |ip, mac: &[u8]| {
            message(
                RTF_UP | 0x400,
                &[(RTA_DST, sockaddr_in(ip)), (RTA_GATEWAY, sockaddr_dl(b"en0", mac))],
            )
        };
        let t = [
            voisin([192, 168, 1, 1], &[0x00, 0x11, 0x22, 0xaa, 0xbb, 0x01]),
            // Incomplète (« (incomplete) » d'arp) : pas d'adresse matérielle.
            voisin([192, 168, 1, 30], &[]),
            voisin([192, 168, 1, 20], &[0x00, 0x11, 0x22, 0xaa, 0xbb, 0x02]),
        ]
        .concat();
        assert_eq!(
            voisins_de(&t),
            [
                (Ipv4Addr::new(192, 168, 1, 1), "00:11:22:aa:bb:01".to_string()),
                (Ipv4Addr::new(192, 168, 1, 20), "00:11:22:aa:bb:02".to_string()),
            ]
        );
        for n in 0..t.len() {
            let _ = voisins_de(&t[..n]);
        }
        // Un message qui annonce plus qu'il n'a : la lecture s'arrête, sans plantage.
        let mut abime = t.clone();
        abime[0] = 0xff;
        abime[1] = 0xff;
        assert_eq!(voisins_de(&abime), Vec::new());
    }
}
