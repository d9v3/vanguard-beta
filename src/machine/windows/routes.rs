//! La passerelle par défaut, la table des voisins (ARP) et l'écho ICMP de Windows, lus par iphlpapi sans lancer
//! `route print`, `arp -a` ni `ping` : rien à traduire, rien d'un texte que la langue de Windows change. Les tables
//! rendues par Windows sont copiées puis relues en code sûr ; les tailles et les places des champs sont celles de
//! netioapi.h et ipexport.h (vérifiées contre les en-têtes de MinGW, et par les essais ci-dessous).

use std::net::Ipv4Addr;

/// AF_INET.
const IPV4: u16 = 2;
/// MIB_IPFORWARD_ROW2 : 104 octets ; la table (MIB_IPFORWARD_TABLE2) les range à partir de l'octet 8.
const LIGNE_ROUTE: usize = 104;
/// MIB_IPNET_ROW2 : 88 octets, à partir de l'octet 8 de MIB_IPNET_TABLE2.
const LIGNE_VOISIN: usize = 88;
const DEBUT_TABLE: usize = 8;

fn u16_a(o: &[u8], d: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(o.get(d..d + 2)?.try_into().ok()?))
}

fn u32_a(o: &[u8], d: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(o.get(d..d + 4)?.try_into().ok()?))
}

fn u64_a(o: &[u8], d: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(o.get(d..d + 8)?.try_into().ok()?))
}

/// Une adresse IPv4 dans un SOCKADDR_INET qui commence à `d` : la famille (2 octets), le port, puis l'adresse
/// (sockaddr_in) ; `None` pour une autre famille.
fn ipv4_a(o: &[u8], d: usize) -> Option<Ipv4Addr> {
    (u16_a(o, d)? == IPV4).then_some(())?;
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(o.get(d + 4..d + 8)?).ok()?))
}

/// Les lignes d'une table de la famille MIB_*_TABLE2 : un nombre (ULONG), puis les lignes, alignées sur 8.
fn lignes(o: &[u8], taille: usize) -> impl Iterator<Item = &[u8]> {
    let n = u32_a(o, 0).and_then(|n| usize::try_from(n).ok()).unwrap_or(0);
    o.get(DEBUT_TABLE..).unwrap_or_default().chunks_exact(taille).take(n)
}

/// Une route par défaut (0.0.0.0/0) par une passerelle : (LUID et numéro de l'interface, passerelle, métrique de la
/// route). Les routes sans passerelle (un VPN « sur le lien », NextHop à zéro) ne comptent pas, comme pour
/// `route print`, qui les montre « On-link ».
fn routes_par_defaut(table: &[u8]) -> Vec<(u64, u32, Ipv4Addr, u32)> {
    lignes(table, LIGNE_ROUTE)
        .filter_map(|l| {
            let destination = ipv4_a(l, 12)?;
            let longueur = *l.get(40)?;
            let passerelle = ipv4_a(l, 44)?;
            (destination.is_unspecified() && longueur == 0 && !passerelle.is_unspecified())
                .then(|| Some((u64_a(l, 0)?, u32_a(l, 8)?, passerelle, u32_a(l, 84)?)))
                .flatten()
        })
        .collect()
}

/// La passerelle de la plus petite métrique complète, celle que `route print` montre : la métrique de la route plus
/// celle de son interface (MIB_IPFORWARD_ROW2, remarque « Metric »). `metrique_interface` : `None` si elle ne se lit
/// pas, la route est alors jugée sur la sienne seule.
fn meilleure(
    routes: &[(u64, u32, Ipv4Addr, u32)],
    metrique_interface: impl Fn(u64, u32) -> Option<u32>,
) -> Option<Ipv4Addr> {
    routes
        .iter()
        .map(|&(luid, index, passerelle, metrique)| {
            let totale = metrique.saturating_add(metrique_interface(luid, index).unwrap_or(0));
            (totale, passerelle)
        })
        .min()
        .map(|(_, passerelle)| passerelle)
}

/// Les voisins IPv4 dont l'adresse matérielle est connue : (adresse, « aa:bb:cc:dd:ee:ff »). Les entrées
/// injoignables ou incomplètes (NL_NEIGHBOR_STATE 0 et 1) n'ont pas d'adresse sûre, comme celles qu'`arp -a` tait.
fn voisins_de(table: &[u8]) -> Vec<(Ipv4Addr, String)> {
    /// NlnsProbe : à partir de là, l'adresse matérielle a été apprise.
    const SONDE: u32 = 2;
    lignes(table, LIGNE_VOISIN)
        .filter_map(|l| {
            let ip = ipv4_a(l, 0)?;
            let longueur = usize::try_from(u32_a(l, 72)?).ok()?;
            let etat = u32_a(l, 76)?;
            let mac = l.get(40..40 + longueur.min(32))?;
            (etat >= SONDE && longueur == 6).then(|| {
                let texte: Vec<String> = mac.iter().map(|o| format!("{o:02x}")).collect();
                (ip, texte.join(":"))
            })
        })
        .collect()
}

/// La réponse d'IcmpSendEcho : `Some(true)` si la cible elle-même a répondu (IP_SUCCESS, depuis son adresse) ;
/// `Some(false)` si Windows dit qu'elle ne répond pas (délai, hôte ou réseau injoignable : les codes IP_* de
/// ipexport.h) ; `None` pour tout autre échec, l'API elle-même, qui ne prouve rien. `reponses` : le nombre rendu ;
/// `tampon` : l'ICMP_ECHO_REPLY (Address à 0, Status à 4) ; `erreur` : GetLastError quand rien n'est rendu.
fn echo_de(reponses: u32, tampon: &[u8], erreur: u32, cible: Ipv4Addr) -> Option<bool> {
    /// Les codes IP_* qui disent la cible injoignable : réseau (11002), hôte (11003), délai (11010), durée de vie
    /// épuisée en route (11013). Les autres (tampon, ressources, matériel, IP_GENERAL_FAILURE) disent un échec d'ici,
    /// qui ne prouve rien sur la cible.
    const INJOIGNABLE: [u32; 4] = [11_002, 11_003, 11_010, 11_013];
    if reponses == 0 {
        return INJOIGNABLE.contains(&erreur).then_some(false);
    }
    let depuis = Ipv4Addr::from(<[u8; 4]>::try_from(tampon.get(0..4)?).ok()?);
    let statut = u32_a(tampon, 4)?;
    // Un « injoignable » rendu par cet ordinateur ou un routeur porte l'adresse de celui qui le dit, et un autre
    // statut : seule la cible avec IP_SUCCESS répond.
    Some(statut == 0 && depuis == cible)
}

#[cfg(windows)]
mod natif {
    use std::ffi::c_void;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        /// netioapi.h : NETIO_STATUS GetIpForwardTable2(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2 *).
        fn GetIpForwardTable2(famille: u16, table: *mut *mut c_void) -> u32;
        /// netioapi.h : NETIO_STATUS GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW).
        fn GetIpInterfaceEntry(ligne: *mut c_void) -> u32;
        /// netioapi.h : NETIO_STATUS GetIpNetTable2(ADDRESS_FAMILY, PMIB_IPNET_TABLE2 *).
        fn GetIpNetTable2(famille: u16, table: *mut *mut c_void) -> u32;
        /// netioapi.h : VOID FreeMibTable(PVOID), pour les tables des deux fonctions précédentes.
        fn FreeMibTable(table: *mut c_void);
        /// icmpapi.h : HANDLE IcmpCreateFile(VOID) ; INVALID_HANDLE_VALUE en cas d'échec.
        fn IcmpCreateFile() -> *mut c_void;
        /// icmpapi.h : BOOL IcmpCloseHandle(HANDLE).
        fn IcmpCloseHandle(poignee: *mut c_void) -> i32;
        /// icmpapi.h : DWORD IcmpSendEcho(HANDLE, IPAddr, LPVOID, WORD, PIP_OPTION_INFORMATION, LPVOID, DWORD,
        /// DWORD).
        fn IcmpSendEcho(
            poignee: *mut c_void,
            destination: u32,
            donnees: *const c_void,
            taille: u16,
            options: *const c_void,
            reponse: *mut c_void,
            taille_reponse: u32,
            delai: u32,
        ) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetLastError() -> u32;
    }

    /// Une table MIB_*_TABLE2 de `taille_ligne` octets par ligne, copiée, puis rendue à Windows.
    fn table(lire: unsafe extern "system" fn(u16, *mut *mut c_void) -> u32, taille_ligne: usize) -> Option<Vec<u8>> {
        let mut table: *mut c_void = std::ptr::null_mut();
        // SAFETY: la fonction écrit un pointeur vers une table qu'elle alloue ; rien n'est lu si elle échoue.
        if unsafe { lire(super::IPV4, &raw mut table) } != 0 || table.is_null() {
            return None;
        }
        // SAFETY: la table commence par son nombre de lignes (ULONG) et en contient autant, chacune de
        // `taille_ligne` octets à partir de l'octet 8 (netioapi.h) : ces octets sont à Windows et vivants jusqu'à
        // FreeMibTable, appelé une seule fois, après la copie.
        unsafe {
            let n = usize::try_from(std::ptr::read_unaligned(table.cast::<u32>())).unwrap_or(0);
            let total = n
                .checked_mul(taille_ligne)
                .and_then(|t| t.checked_add(super::DEBUT_TABLE))
                .filter(|&t| t <= 64 << 20);
            let copie = total.map(|t| std::slice::from_raw_parts(table.cast::<u8>(), t).to_vec());
            FreeMibTable(table);
            copie
        }
    }

    /// MIB_IPINTERFACE_ROW : 168 octets, alignés comme son NET_LUID (8).
    #[repr(C, align(8))]
    struct LigneInterface([u8; 168]);

    /// La métrique d'une interface IPv4 (MIB_IPINTERFACE_ROW.Metric, à l'octet 148).
    fn metrique_interface(luid: u64, index: u32) -> Option<u32> {
        let mut ligne = LigneInterface([0; 168]);
        // Family (ADDRESS_FAMILY) à 0, InterfaceLuid à 8, InterfaceIndex à 16 : ce que la fonction demande en entrée.
        ligne.0[0..2].copy_from_slice(&super::IPV4.to_ne_bytes());
        ligne.0[8..16].copy_from_slice(&luid.to_ne_bytes());
        ligne.0[16..20].copy_from_slice(&index.to_ne_bytes());
        // SAFETY: la ligne fait les 168 octets de MIB_IPINTERFACE_ROW, alignés sur 8, à nous pendant l'appel.
        if unsafe { GetIpInterfaceEntry((&raw mut ligne).cast()) } != 0 {
            return None;
        }
        super::u32_a(&ligne.0, 148)
    }

    /// La passerelle par défaut que Windows choisirait (`route print -4 0.0.0.0`) ; `None` : table refusée, ou
    /// aucune route par défaut par une passerelle.
    pub(crate) fn passerelle() -> Option<Ipv4Addr> {
        let routes = super::routes_par_defaut(&table(GetIpForwardTable2, super::LIGNE_ROUTE)?);
        super::meilleure(&routes, metrique_interface)
    }

    /// Les voisins IPv4 à l'adresse matérielle connue ; `None` : table refusée.
    pub(crate) fn voisins() -> Option<Vec<(Ipv4Addr, String)>> {
        Some(super::voisins_de(&table(GetIpNetTable2, super::LIGNE_VOISIN)?))
    }

    /// Un écho ICMP vers `cible`, comme `ping -n 1` ; voir `echo_de`.
    pub(crate) fn echo(cible: Ipv4Addr, delai: Duration) -> Option<bool> {
        const INVALIDE: isize = -1;
        // SAFETY: sans argument ; le résultat est vérifié avant tout usage.
        let poignee = unsafe { IcmpCreateFile() };
        if poignee.is_null() || poignee as isize == INVALIDE {
            return None;
        }
        let donnees = *b"Vanguard : la box repond-elle ?\0";
        // Au moins un ICMP_ECHO_REPLY (40 octets), les données et 8 octets d'un message d'erreur ICMP ; en mots de
        // 64 bits pour l'alignement du pointeur qu'il contient.
        let mut reponse = [0u64; 16];
        let taille_reponse = u32::try_from(std::mem::size_of_val(&reponse)).ok()?;
        let delai = u32::try_from(delai.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: la poignée vient d'IcmpCreateFile ; les données et le tampon sont à nous, de la taille annoncée,
        // vivants pendant l'appel (synchrone) ; IPAddr est l'adresse dans l'ordre du réseau, telle qu'en mémoire.
        let (n, erreur) = unsafe {
            let n = IcmpSendEcho(
                poignee,
                u32::from_ne_bytes(cible.octets()),
                donnees.as_ptr().cast(),
                u16::try_from(donnees.len()).unwrap_or(0),
                std::ptr::null(),
                reponse.as_mut_ptr().cast(),
                taille_reponse,
                delai,
            );
            let erreur = if n == 0 { GetLastError() } else { 0 };
            IcmpCloseHandle(poignee);
            (n, erreur)
        };
        let octets: Vec<u8> = reponse.iter().flat_map(|m| m.to_ne_bytes()).collect();
        super::echo_de(n, &octets, erreur, cible)
    }
}

#[cfg(windows)]
pub(crate) use natif::{echo, passerelle, voisins};

#[cfg(test)]
mod tests {
    use super::*;

    /// Une SOCKADDR_INET IPv4 : la famille, le port, l'adresse, le reste à zéro (28 octets).
    fn sockaddr(ip: [u8; 4]) -> Vec<u8> {
        let mut s = IPV4.to_ne_bytes().to_vec();
        s.extend([0, 0]);
        s.extend(ip);
        s.resize(28, 0);
        s
    }

    fn table(lignes: &[Vec<u8>]) -> Vec<u8> {
        let mut t = u32::try_from(lignes.len()).unwrap().to_ne_bytes().to_vec();
        t.resize(DEBUT_TABLE, 0);
        for l in lignes {
            t.extend(l);
        }
        t
    }

    /// Une MIB_IPFORWARD_ROW2 : LUID 0, index 8, destination 12 (longueur 40), passerelle 44, métrique 84.
    fn route(luid: u64, index: u32, destination: [u8; 4], longueur: u8, passerelle: [u8; 4], metrique: u32) -> Vec<u8> {
        let mut l = vec![0u8; LIGNE_ROUTE];
        l[0..8].copy_from_slice(&luid.to_ne_bytes());
        l[8..12].copy_from_slice(&index.to_ne_bytes());
        l[12..40].copy_from_slice(&sockaddr(destination));
        l[40] = longueur;
        l[44..72].copy_from_slice(&sockaddr(passerelle));
        l[84..88].copy_from_slice(&metrique.to_ne_bytes());
        l
    }

    #[test]
    fn passerelle_de_la_table_des_routes() {
        let t = table(&[
            route(1, 7, [0, 0, 0, 0], 0, [192, 168, 1, 1], 0),
            // Le Wi-Fi, métrique de route plus petite, mais interface plus chère : route print additionne.
            route(2, 9, [0, 0, 0, 0], 0, [10, 0, 0, 1], 0),
            // Un VPN « sur le lien » (sans passerelle) et une route vers un réseau : ignorés.
            route(3, 12, [0, 0, 0, 0], 0, [0, 0, 0, 0], 0),
            route(1, 7, [192, 168, 1, 0], 24, [0, 0, 0, 0], 256),
        ]);
        let r = routes_par_defaut(&t);
        assert_eq!(r.len(), 2);
        let interface = |_: u64, index: u32| Some(if index == 7 { 25 } else { 50 });
        assert_eq!(meilleure(&r, interface), Some(Ipv4Addr::new(192, 168, 1, 1)));
        let interface = |_: u64, index: u32| Some(if index == 7 { 50 } else { 25 });
        assert_eq!(meilleure(&r, interface), Some(Ipv4Addr::new(10, 0, 0, 1)));
        // Interface illisible : la métrique de la route seule.
        assert!(meilleure(&r, |_, _| None).is_some());
        assert_eq!(meilleure(&[], |_, _| None), None);
        // Une table qui annonce plus de lignes qu'elle n'en a, ou abîmée : rien de faux, pas de plantage.
        let mut coupee = t.clone();
        coupee.truncate(DEBUT_TABLE + LIGNE_ROUTE + 10);
        assert_eq!(routes_par_defaut(&coupee).len(), 1);
        for n in 0..t.len() {
            let _ = routes_par_defaut(&t[..n]);
        }
    }

    /// Une MIB_IPNET_ROW2 : adresse 0, adresse matérielle 40, sa longueur 72, état 76.
    fn voisin(ip: [u8; 4], mac: &[u8], etat: u32) -> Vec<u8> {
        let mut l = vec![0u8; LIGNE_VOISIN];
        l[0..28].copy_from_slice(&sockaddr(ip));
        l[40..40 + mac.len()].copy_from_slice(mac);
        l[72..76].copy_from_slice(&u32::try_from(mac.len()).unwrap().to_ne_bytes());
        l[76..80].copy_from_slice(&etat.to_ne_bytes());
        l
    }

    #[test]
    fn voisins_de_la_table() {
        let t = table(&[
            voisin([192, 168, 1, 1], &[0x00, 0x11, 0x22, 0xaa, 0xbb, 0x01], 5),
            voisin([192, 168, 1, 20], &[0x00, 0x11, 0x22, 0xaa, 0xbb, 0x02], 4),
            // Incomplet : pas d'adresse sûre.
            voisin([192, 168, 1, 30], &[0; 6], 1),
            // Un tunnel sans adresse Ethernet.
            voisin([10, 0, 0, 1], &[], 6),
        ]);
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
    }

    #[test]
    fn reponses_a_l_echo() {
        let boite = Ipv4Addr::new(192, 168, 1, 1);
        let reponse = |depuis: [u8; 4], statut: u32| {
            let mut r = depuis.to_vec();
            r.extend(statut.to_ne_bytes());
            r.resize(40, 0);
            r
        };
        assert_eq!(echo_de(1, &reponse([192, 168, 1, 1], 0), 0, boite), Some(true));
        // « Hôte inaccessible » dit par cet ordinateur : ping rendait 0, ce n'est pas une réponse de la box.
        assert_eq!(echo_de(1, &reponse([192, 168, 1, 20], 11_003), 0, boite), Some(false));
        assert_eq!(echo_de(1, &reponse([192, 168, 1, 20], 0), 0, boite), Some(false));
        // Délai écoulé (IP_REQ_TIMED_OUT) : ne répond pas ; une autre erreur de l'API : rien de prouvé.
        assert_eq!(echo_de(0, &[], 11_010, boite), Some(false));
        assert_eq!(echo_de(0, &[], 87, boite), None);
        // IP_GENERAL_FAILURE (Wine sans ICMP) : un échec d'ici, pas une box muette.
        assert_eq!(echo_de(0, &[], 11_050, boite), None);
        assert_eq!(echo_de(1, &[1, 2], 0, boite), None);
    }

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite) : les tables se lisent sans planter ; l'écho de la
    /// boucle locale répond, sauf si Wine n'a pas d'ICMP (rien de prouvé, jamais « répond »).
    #[cfg(windows)]
    #[test]
    fn tables_et_echo_de_windows() {
        let _ = passerelle();
        let _ = voisins();
        if echo(Ipv4Addr::LOCALHOST, std::time::Duration::from_secs(1)) != Some(true) {
            crate::essais::saute("pas d'écho ICMP de la boucle locale (Wine sans ICMP ?)");
        }
    }
}
