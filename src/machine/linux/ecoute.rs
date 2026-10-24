//! Les prises réseau en écoute, ce que montraient `ss -Htlnpe` (TCP) et `ss -Hulnpe` (UDP), lues sans lancer ss.
//!
//! Pourquoi netlink d'abord (sock_diag, ce que ss interroge lui-même) : le noyau y donne, pour chaque prise, le
//! groupe de contrôle (cgroup) du programme qui l'a ouverte. C'est lui qui nomme un service de root (avahi-daemon,
//! cups-browsed) quand le programme reste invisible sans droits admin, et la règle des ports en dépend (la faille
//! de cups-browsed). /proc/net ne le donne pas : il ne sert que si netlink ne répond pas, et ss en dernier recours.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::ui::affichable;

/// Une prise en écoute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ecoute {
    pub udp: bool,
    pub adresse: IpAddr,
    pub port: u16,
    /// Le numéro de la prise (« socket:[inode] » dans /proc/<pid>/fd).
    pub inode: u64,
    /// Le chemin du groupe de contrôle (« /system.slice/cups.service »), quand le noyau l'a donné.
    pub groupe: Option<String>,
    /// Le nom court du programme, tel qu'il se l'est donné : seulement ceux de ce compte sans droits root.
    pub programme: Option<String>,
}

impl Ecoute {
    /// Le nom à montrer : celui du programme, sinon celui de son service.
    pub fn nom(&self) -> Option<String> {
        self.programme
            .as_deref()
            .map(affichable)
            .or_else(|| self.groupe.as_deref().and_then(super::service_du_groupe))
    }

    /// L'adresse comme ss l'écrivait : IPv6 entre crochets.
    pub fn adresse_ss(&self) -> String {
        match self.adresse {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format!("[{ip}]"),
        }
    }
}

/// Les prises TCP en écoute et UDP ouvertes, programme et groupe compris ; `None` si rien ne se lit, ni netlink, ni
/// /proc/net, ni ss.
pub(crate) fn prises() -> Option<Vec<Ecoute>> {
    let mut prises = par_netlink().or_else(par_proc_net)?;
    if !prises.is_empty() {
        let proprietaires = crate::protection::sortantes::proprietaires();
        for p in &mut prises {
            p.programme = proprietaires
                .get(&p.inode)
                .and_then(|pid| crate::socle::processus::nom_court(*pid));
        }
    }
    Some(prises)
}

/// Le secours : la sortie de ss, quand le noyau ne s'est pas laissé lire directement.
pub(crate) fn prises_ou_ss() -> Option<Vec<Ecoute>> {
    prises().or_else(|| {
        let tcp = crate::machine::sortie("ss", &["-Htlnpe"])?;
        let udp = crate::machine::sortie("ss", &["-Hulnpe"])?;
        Some(lire_ss(&tcp, false).into_iter().chain(lire_ss(&udp, true)).collect())
    })
}

// ---------------------------------------------------------------------------------------------------------------
// netlink (sock_diag)

/// Le protocole netlink de sock_diag (NETLINK_SOCK_DIAG) et son seul type de demande (SOCK_DIAG_BY_FAMILY).
const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// L'attribut qui porte le numéro du groupe de contrôle (INET_DIAG_CGROUP_ID, noyaux 5.7 et plus).
const INET_DIAG_CGROUP_ID: u16 = 21;
/// Les états du noyau : TCP_LISTEN pour TCP ; une prise UDP qu'aucun échange n'a reliée reste TCP_CLOSE, celles que
/// ss -l montre « UNCONN ».
const TCP_LISTEN: u8 = 10;
const TCP_CLOSE: u8 = 7;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Les quatre listes (TCP et UDP, IPv4 et IPv6) ; `None` dès qu'une ne vient pas : mieux vaut alors /proc/net en
/// entier qu'un mélange. Les groupes sont nommés d'après le dossier de cgroup2 qui porte leur numéro.
pub(super) fn par_netlink() -> Option<Vec<Ecoute>> {
    let mut prises = Vec::new();
    for (protocole, etat, udp) in [(IPPROTO_TCP, TCP_LISTEN, false), (IPPROTO_UDP, TCP_CLOSE, true)] {
        for famille in [AF_INET, AF_INET6] {
            let reponse = demander_netlink(NETLINK_SOCK_DIAG, &demande_sock_diag(famille, protocole, etat))?;
            prises.extend(lire_sock_diag(&reponse, udp));
        }
    }
    let groupes = if prises.is_empty() {
        HashMap::new()
    } else {
        racine_cgroup2().map(|r| groupes_par_numero(&r)).unwrap_or_default()
    };
    Some(
        prises
            .into_iter()
            .map(|(e, numero)| Ecoute {
                groupe: numero.and_then(|n| groupes.get(&n).cloned()),
                ..e
            })
            .collect(),
    )
}

/// En-tête netlink (16 octets) puis inet_diag_req_v2 (56) : famille, protocole, extensions (aucune : le groupe vient
/// toujours), bourrage, masque des états voulus, puis l'identifiant de prise, à zéro pour toutes les prendre.
fn demande_sock_diag(famille: u8, protocole: u8, etat: u8) -> [u8; 72] {
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_DUMP: u16 = 0x300;
    let mut d = [0u8; 72];
    d[0..4].copy_from_slice(&72u32.to_ne_bytes());
    d[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    d[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    d[8..12].copy_from_slice(&1u32.to_ne_bytes());
    d[16] = famille;
    d[17] = protocole;
    d[20..24].copy_from_slice(&(1u32 << etat).to_ne_bytes());
    d
}

/// Les prises des messages inet_diag_msg (72 octets puis les attributs) : famille, état, minuterie, renvois,
/// l'identifiant (port local et distant dans l'ordre du réseau, adresses locale et distante sur 16 octets,
/// interface, témoin), puis expiration, files, compte et inode. → (prise, numéro du groupe).
fn lire_sock_diag(octets: &[u8], udp: bool) -> Vec<(Ecoute, Option<u64>)> {
    let mut prises = Vec::new();
    for (genre, corps) in crate::reseau::scan::messages_netlink(octets) {
        if genre != SOCK_DIAG_BY_FAMILY || corps.len() < 72 {
            continue;
        }
        let adresse = match corps[0] {
            AF_INET => IpAddr::from(<[u8; 4]>::try_from(&corps[8..12]).unwrap_or_default()),
            AF_INET6 => IpAddr::from(<[u8; 16]>::try_from(&corps[8..24]).unwrap_or_default()),
            _ => continue,
        };
        let port = u16::from_be_bytes([corps[4], corps[5]]);
        let inode = u32::from_ne_bytes([corps[68], corps[69], corps[70], corps[71]]);
        let mut numero = None;
        let mut pos = 72;
        while let Some(attribut) = corps.get(pos..pos + 4) {
            let longueur = usize::from(u16::from_ne_bytes([attribut[0], attribut[1]]));
            if longueur < 4 {
                break;
            }
            if u16::from_ne_bytes([attribut[2], attribut[3]]) == INET_DIAG_CGROUP_ID
                && let Some(n) = corps
                    .get(pos + 4..pos + longueur)
                    .and_then(|v| <[u8; 8]>::try_from(v).ok())
            {
                numero = Some(u64::from_ne_bytes(n));
            }
            pos += longueur.next_multiple_of(4);
        }
        prises.push((
            Ecoute {
                udp,
                adresse,
                port,
                inode: u64::from(inode),
                groupe: None,
                programme: None,
            },
            numero,
        ));
    }
    prises
}

/// Envoie une demande netlink et rend les réponses du noyau jusqu'à la fin de la liste ; `None` sur une erreur
/// (un protocole que le noyau ne connaît pas, udp_diag absent) ou sans réponse.
pub(crate) fn demander_netlink(protocole: i32, demande: &[u8]) -> Option<Vec<u8>> {
    // SAFETY : une socket netlink ouverte ici et refermée une seule fois à la sortie ; chaque appel reçoit un pointeur
    // et la taille exacte d'un objet à nous, vivant pendant l'appel (demande, adresse, délai, tampon). Le délai de
    // réception (2 s) empêche recv de bloquer sans fin si le noyau ne répondait pas.
    unsafe {
        let s = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, protocole);
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
                tout.extend_from_slice(&tampon[..n]);
                match crate::reseau::scan::fin_netlink(&tampon[..n]) {
                    Some(true) => {
                        resultat = Some(std::mem::take(&mut tout));
                        break;
                    }
                    Some(false) => break,
                    // Une liste démesurée n'en est pas une : on s'arrête.
                    None if tout.len() > 16 << 20 => break,
                    None => {}
                }
            }
        }
        libc::close(s);
        resultat
    }
}

/// Le point de montage de cgroup2 : /sys/fs/cgroup d'habitude, /sys/fs/cgroup/unified sur un système hybride (le
/// numéro donné par le noyau est toujours celui de cgroup2).
fn racine_cgroup2() -> Option<PathBuf> {
    racine_cgroup2_selon(&std::fs::read_to_string("/proc/self/mountinfo").ok()?)
}

fn racine_cgroup2_selon(mountinfo: &str) -> Option<PathBuf> {
    mountinfo.lines().find_map(|l| {
        let (avant, apres) = l.split_once(" - ")?;
        if apres.split(' ').next()? != "cgroup2" {
            return None;
        }
        Some(PathBuf::from(crate::copier::sans_echappements(
            avant.split(' ').nth(4)?,
        )))
    })
}

/// Chaque groupe sous `racine` par son numéro : sur cgroup2, le numéro d'un groupe est celui (inode) de son dossier.
/// → « /system.slice/cups.service », comme ss l'écrit.
fn groupes_par_numero(racine: &Path) -> HashMap<u64, String> {
    use std::os::unix::fs::MetadataExt;
    let mut groupes = HashMap::new();
    let mut a_voir = vec![(racine.to_path_buf(), 0u8)];
    while let Some((dossier, profondeur)) = a_voir.pop() {
        let Ok(m) = std::fs::symlink_metadata(&dossier) else {
            continue;
        };
        let relatif = dossier.strip_prefix(racine).unwrap_or(Path::new(""));
        groupes.insert(m.ino(), format!("/{}", relatif.to_string_lossy()));
        // Aucune vraie hiérarchie n'a trente-deux étages : au-delà, ce serait une boucle.
        if profondeur >= 32 {
            continue;
        }
        for e in std::fs::read_dir(&dossier).into_iter().flatten().flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                a_voir.push((e.path(), profondeur + 1));
            }
        }
    }
    groupes
}

// ---------------------------------------------------------------------------------------------------------------
// /proc/net, puis ss

/// Les prises en écoute de /proc/net/{tcp,tcp6,udp,udp6} ; `None` si aucun ne se lit (tcp6 et udp6 manquent quand
/// IPv6 est coupé : ce n'est pas une panne).
fn par_proc_net() -> Option<Vec<Ecoute>> {
    let mut lisible = false;
    let mut prises = Vec::new();
    for (fichier, udp) in [("tcp", false), ("tcp6", false), ("udp", true), ("udp6", true)] {
        if let Ok(texte) = std::fs::read_to_string(format!("/proc/net/{fichier}")) {
            lisible = true;
            prises.extend(lire_proc_net(&texte, udp));
        }
    }
    lisible.then_some(prises)
}

/// « sl locale distante état … uid délai inode » : état 0A (LISTEN) pour TCP, 07 (CLOSE, « UNCONN ») pour UDP.
fn lire_proc_net(texte: &str, udp: bool) -> Vec<Ecoute> {
    let voulu = if udp { "07" } else { "0A" };
    texte
        .lines()
        .skip(1)
        .filter_map(|l| {
            let champs: Vec<&str> = l.split_whitespace().collect();
            if champs.get(3)? != &voulu {
                return None;
            }
            let (adresse, port) = champs.get(1)?.split_once(':')?;
            if port.len() != 4 || !port.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some(Ecoute {
                udp,
                adresse: crate::protection::sortantes::adresse_proc(adresse)?,
                port: u16::from_str_radix(port, 16).ok()?,
                inode: champs.get(9)?.parse().ok()?,
                groupe: None,
                programme: None,
            })
        })
        .collect()
}

/// Les lignes de `ss -H…lnpe` : « LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("nom",pid=1,fd=5)) uid:974
/// ino:11024 sk:3003 cgroup:/system.slice/systemd-resolved.service <-> ». « * » est l'adresse IPv6 nulle ouverte
/// aussi à IPv4.
pub(super) fn lire_ss(sortie: &str, udp: bool) -> Vec<Ecoute> {
    sortie
        .lines()
        .filter_map(|ligne| {
            let c: Vec<&str> = ligne.split_whitespace().collect();
            let (adresse, port) = c.get(3)?.rsplit_once(':')?;
            let adresse = adresse.split('%').next()?;
            let adresse = match adresse {
                "*" => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                a => a.trim_start_matches('[').trim_end_matches(']').parse().ok()?,
            };
            let valeur = |cle: &str| c.iter().find_map(|m| m.strip_prefix(cle));
            Some(Ecoute {
                udp,
                adresse,
                port: port.parse().ok()?,
                inode: valeur("ino:").and_then(|i| i.parse().ok()).unwrap_or(0),
                groupe: valeur("cgroup:").map(str::to_string),
                programme: c
                    .get(5)
                    .and_then(|u| u.strip_prefix("users:"))
                    .and_then(|u| u.split('"').nth(1))
                    .map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NULLE: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

    /// Un message inet_diag_msg inventé, avec son attribut de groupe.
    fn message(famille: u8, adresse: &[u8], port: u16, inode: u32, groupe: Option<u64>) -> Vec<u8> {
        let mut corps = vec![0u8; 72];
        corps[0] = famille;
        corps[1] = TCP_LISTEN;
        corps[4..6].copy_from_slice(&port.to_be_bytes());
        corps[8..8 + adresse.len()].copy_from_slice(adresse);
        corps[68..72].copy_from_slice(&inode.to_ne_bytes());
        if let Some(g) = groupe {
            corps.extend_from_slice(&12u16.to_ne_bytes());
            corps.extend_from_slice(&INET_DIAG_CGROUP_ID.to_ne_bytes());
            corps.extend_from_slice(&g.to_ne_bytes());
        }
        let mut m = Vec::new();
        m.extend_from_slice(&u32::try_from(16 + corps.len()).unwrap().to_ne_bytes());
        m.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        m.extend_from_slice(&corps);
        m
    }

    #[test]
    fn prises_de_netlink() {
        let mut reponse = message(AF_INET, &[192, 168, 1, 20], 631, 15004, Some(4242));
        reponse.extend(message(AF_INET6, &[0; 16], 22, 7, None));
        let lues = lire_sock_diag(&reponse, false);
        assert_eq!(lues.len(), 2);
        assert_eq!(lues[0].0.adresse, IpAddr::from([192, 168, 1, 20]));
        assert_eq!((lues[0].0.port, lues[0].0.inode, lues[0].1), (631, 15004, Some(4242)));
        assert_eq!(lues[1].0.adresse_ss(), "[::]");
        assert_eq!(lues[1].1, None);
        // Tronquée ou d'une autre famille : rien, sans paniquer.
        assert_eq!(lire_sock_diag(&reponse[..40], false).len(), 0);
        assert_eq!(lire_sock_diag(&message(1, &[], 1, 1, None), false).len(), 0);
    }

    #[test]
    fn demande_pour_les_prises_en_ecoute() {
        let d = demande_sock_diag(AF_INET6, IPPROTO_UDP, TCP_CLOSE);
        assert_eq!(u32::from_ne_bytes([d[0], d[1], d[2], d[3]]), 72);
        assert_eq!(u16::from_ne_bytes([d[4], d[5]]), 20);
        assert_eq!((d[16], d[17]), (10, 17));
        assert_eq!(u32::from_ne_bytes([d[20], d[21], d[22], d[23]]), 1 << 7);
    }

    #[test]
    fn prises_de_proc_net() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2B67 00000000:0000 0A 00000000:00000000 00:00000000 00000000   955        0 22541 1 0
   1: 1401A8C0:D2F0 0401A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0
";
        let lues = lire_proc_net(tcp, false);
        assert_eq!(lues.len(), 1, "seule la prise en écoute compte : {lues:?}");
        assert_eq!(lues[0].adresse, IpAddr::from([127, 0, 0, 1]));
        assert_eq!((lues[0].port, lues[0].inode), (11111, 22541));
        let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  1: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   967        0 9109 2 0 0
";
        let lues = lire_proc_net(udp, true);
        assert_eq!((lues[0].adresse, lues[0].port, lues[0].udp), (NULLE, 5353, true));
    }

    #[test]
    fn prises_de_ss() {
        let ss = "LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* uid:974 ino:11024 sk:3003 cgroup:/system.slice/systemd-resolved.service <->
UNCONN 0 0 *:27036 *:* users:((\"steam\",pid=726611,fd=144)) uid:1000 ino:2777783 sk:7050 cgroup:/user.slice/app.scope v6only:0 <->
LISTEN 0 4096 [::1]:631 [::]:* ino:15003 sk:4001 cgroup:/system.slice/cups.service v6only:1 <->
";
        let lues = lire_ss(ss, false);
        assert_eq!(lues.len(), 3);
        assert_eq!(lues[0].adresse_ss(), "127.0.0.53");
        assert_eq!(lues[0].nom().as_deref(), Some("systemd-resolved"));
        assert_eq!(lues[1].adresse_ss(), "[::]");
        assert_eq!(lues[1].nom().as_deref(), Some("steam"));
        assert_eq!((lues[2].port, lues[2].inode), (631, 15003));
        assert_eq!(lues[2].adresse_ss(), "[::1]");
    }

    #[test]
    fn point_de_montage_de_cgroup2() {
        let hybride = "24 1 0:22 / /sys/fs/cgroup ro,nosuid - tmpfs tmpfs ro,mode=755
25 24 0:23 / /sys/fs/cgroup/unified rw,nosuid - cgroup2 cgroup2 rw,nsdelegate
";
        assert_eq!(
            racine_cgroup2_selon(hybride),
            Some(PathBuf::from("/sys/fs/cgroup/unified"))
        );
        assert_eq!(racine_cgroup2_selon("1 0 8:2 / / rw - ext4 /dev/sda2 rw\n"), None);
    }

    #[test]
    fn groupes_nommes_par_leur_dossier() {
        use std::os::unix::fs::MetadataExt;
        let racine = std::env::temp_dir().join(format!("vanguard-ecoute-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&racine);
        let service = racine.join("system.slice/cups.service");
        std::fs::create_dir_all(&service).unwrap();
        let groupes = groupes_par_numero(&racine);
        let numero = std::fs::metadata(&service).unwrap().ino();
        assert_eq!(
            groupes.get(&numero).map(String::as_str),
            Some("/system.slice/cups.service")
        );
        let numero = std::fs::metadata(&racine).unwrap().ino();
        assert_eq!(groupes.get(&numero).map(String::as_str), Some("/"));
        let _ = std::fs::remove_dir_all(&racine);
    }

    /// Sur cet ordinateur, netlink donne les mêmes prises que ss, avec le même groupe, quand ss est là. Une prise
    /// peut s'ouvrir ou se fermer entre deux lectures : netlink est lu avant et après ss, et chaque prise de ss doit
    /// se trouver dans l'une des deux lectures.
    #[test]
    fn prises_comme_ss() {
        crate::autotest::croisees::essayer("AUT-LNX-006");
    }
}
