//! Couper les connexions déjà ouvertes vers une adresse, à la place de « ss -K dst `<adresse>` » : la liste des prises
//! par sock_diag (SOCK_DIAG_BY_FAMILY), filtrée ici sur la destination, puis un SOCK_DESTROY par prise, avec son
//! identifiant complet (ports, adresses, interface et témoin, pour ne jamais viser une autre prise venue entre-temps)
//! et son accusé lu. Il faut CAP_NET_ADMIN et un noyau avec CONFIG_INET_DIAG_DESTROY : sinon, c'est dit (la
//! connexion déjà ouverte continue), jamais avalé.

use std::net::IpAddr;

use super::netlink::{self, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, Prise, recus};
use crate::modele::Echec;
use crate::{tr, trf};

const OU: &str = "blocage/couper";

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const SOCK_DESTROY: u16 = 21;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// Les états TCP d'une connexion vivante (SYN_SENT à CLOSING, sans TIME_WAIT, CLOSE ni LISTEN) ; pour UDP, une
/// prise reliée à une adresse est ESTABLISHED (1).
const ETATS_TCP: u32 = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 5) | (1 << 8) | (1 << 9) | (1 << 11);
const ETATS_UDP: u32 = 1 << 1;

/// inet_diag_req_v2 (56 octets) : famille, protocole, extensions, bourrage, états, puis l'identifiant de prise
/// (inet_diag_sockid, 48 octets).
fn demande(famille: u8, protocole: u8, etats: u32, id: &[u8; 48]) -> Vec<u8> {
    let mut d = vec![famille, protocole, 0, 0];
    d.extend_from_slice(&etats.to_ne_bytes());
    d.extend_from_slice(id);
    d
}

/// Les prises d'une liste sock_diag dont la destination est `ip` : leur identifiant tel que le noyau l'a donné. Pour
/// une adresse IPv4, une prise IPv6 vers sa forme « ::ffff:a.b.c.d » compte aussi.
pub(crate) fn prises_vers(octets: &[u8], ip: IpAddr) -> Vec<(u8, [u8; 48])> {
    let ip = ip.to_canonical();
    recus(octets)
        .filter(|r| r.genre == SOCK_DIAG_BY_FAMILY && r.corps.len() >= 72)
        .filter_map(|r| {
            // inet_diag_msg : famille, état, minuterie, renvois, puis l'identifiant (48 octets) ; la destination est
            // à l'octet 20 de l'identifiant (après les deux ports et la source).
            let famille = r.corps[0];
            let id: [u8; 48] = r.corps[4..52].try_into().ok()?;
            let destination = match famille {
                AF_INET => IpAddr::from(<[u8; 4]>::try_from(&id[20..24]).ok()?),
                AF_INET6 => IpAddr::from(<[u8; 16]>::try_from(&id[20..36]).ok()?).to_canonical(),
                _ => return None,
            };
            (destination == ip).then_some((famille, id))
        })
        .collect()
}

/// Ce que la coupure a donné.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Coupure {
    pub coupees: usize,
    /// Prises parties d'elles-mêmes entre la liste et la coupure.
    pub deja_fermees: usize,
}

/// Coupe les connexions TCP et UDP ouvertes vers cette adresse. `Err` : pourquoi une connexion ouverte n'a pas pu
/// l'être (noyau sans INET_DIAG_DESTROY, droits manquants).
pub(crate) fn couper_vers(ip: IpAddr) -> Result<Coupure, Echec> {
    let prise = Prise::ouvrir(NETLINK_SOCK_DIAG).map_err(|e| Echec::io(OU, &e))?;
    let familles: &[u8] = if ip.to_canonical().is_ipv4() {
        &[AF_INET, AF_INET6]
    } else {
        &[AF_INET6]
    };
    let mut resultat = Coupure {
        coupees: 0,
        deja_fermees: 0,
    };
    let mut sequence = 1u32;
    for &(protocole, etats) in &[(IPPROTO_TCP, ETATS_TCP), (IPPROTO_UDP, ETATS_UDP)] {
        for &famille in familles {
            sequence += 1;
            let liste = netlink::message(
                SOCK_DIAG_BY_FAMILY,
                NLM_F_REQUEST | NLM_F_DUMP,
                sequence,
                &demande(famille, protocole, etats, &[0; 48]),
            );
            let reponse = match prise.lister(&liste) {
                Ok(r) => r,
                // udp_diag absent : aucune prise UDP ne se liste, donc aucune ne se coupe ; TCP, lui, doit se lire.
                Err(c) if protocole == IPPROTO_UDP && c == -libc::ENOENT => continue,
                Err(c) => {
                    return Err(Echec::echoue(
                        OU,
                        trf!(
                            "connexions illisibles : {}",
                            "connections unreadable: {}",
                            netlink::texte_errno(c)
                        ),
                    ));
                }
            };
            for (f, id) in prises_vers(&reponse, ip) {
                sequence += 1;
                let m = netlink::message(
                    SOCK_DESTROY,
                    NLM_F_REQUEST | NLM_F_ACK,
                    sequence,
                    &demande(f, protocole, u32::MAX, &id),
                );
                match prise.envoyer_et_attendre(&m, &[sequence]) {
                    Ok(()) => resultat.coupees += 1,
                    Err((c, _)) if c == -libc::ENOENT => resultat.deja_fermees += 1,
                    Err((c, _)) => return Err(raison(c)),
                }
            }
        }
    }
    Ok(resultat)
}

fn raison(code: i32) -> Echec {
    Echec::echoue(OU, raison_texte(code))
}

fn raison_texte(code: i32) -> String {
    match code.saturating_neg() {
        libc::EOPNOTSUPP => tr!(
            "ce noyau ne sait pas couper une connexion (CONFIG_INET_DIAG_DESTROY absent) : la connexion déjà ouverte continue jusqu'à sa fin",
            "this kernel cannot cut a connection (CONFIG_INET_DIAG_DESTROY missing): the connection already open lasts until it ends"
        )
        .to_string(),
        libc::EPERM => tr!(
            "droits d'administrateur manquants pour couper la connexion déjà ouverte",
            "administrator rights missing to cut the connection already open"
        )
        .to_string(),
        _ => trf!(
            "connexion déjà ouverte non coupée : {}",
            "connection already open not cut: {}",
            netlink::texte_errno(code)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diag(famille: u8, destination: &[u8]) -> Vec<u8> {
        let mut corps = vec![famille, 1, 0, 0];
        let mut id = [0u8; 48];
        id[0..2].copy_from_slice(&40000u16.to_be_bytes());
        id[2..4].copy_from_slice(&443u16.to_be_bytes());
        id[20..20 + destination.len()].copy_from_slice(destination);
        id[44..48].copy_from_slice(&[1, 2, 3, 4]);
        corps.extend_from_slice(&id);
        corps.resize(72, 0);
        netlink::message(SOCK_DIAG_BY_FAMILY, 2, 1, &corps)
    }

    #[test]
    fn prises_choisies_par_leur_destination() {
        let mut liste = diag(AF_INET, &[203, 0, 113, 7]);
        liste.extend(diag(AF_INET, &[203, 0, 113, 8]));
        let mut mappee = [0u8; 16];
        mappee[10] = 0xff;
        mappee[11] = 0xff;
        mappee[12..].copy_from_slice(&[203, 0, 113, 7]);
        liste.extend(diag(AF_INET6, &mappee));
        let vers = prises_vers(&liste, "203.0.113.7".parse().unwrap());
        assert_eq!(vers.len(), 2);
        // L'identifiant est repris tel quel, témoin compris.
        assert_eq!(&vers[0].1[44..48], &[1, 2, 3, 4]);
        assert_eq!(vers[1].0, AF_INET6);
        assert_eq!(prises_vers(&liste, "2001:db8::7".parse().unwrap()), []);
        // La demande de coupure : 56 octets, l'identifiant à partir de l'octet 8.
        let d = demande(AF_INET, IPPROTO_TCP, u32::MAX, &vers[0].1);
        assert_eq!(d.len(), 56);
        assert_eq!(&d[8..], &vers[0].1[..]);
    }

    /// Dedans un espace de noms réseau à part : une vraie connexion TCP sur la boucle locale, coupée par
    /// SOCK_DESTROY. Lancé par `coupure_dans_un_espace_a_part`, jamais seul.
    #[test]
    #[ignore = "lancé dans un espace de noms à part par coupure_dans_un_espace_a_part"]
    fn coupure_dedans() {
        use std::io::Read;
        assert!(
            std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .is_ok_and(|s| s.success())
        );
        let ecoute = std::net::TcpListener::bind("127.0.0.3:0").unwrap();
        let adresse = ecoute.local_addr().unwrap();
        let mut client = std::net::TcpStream::connect(adresse).unwrap();
        let (_serveur, _) = ecoute.accept().unwrap();
        match couper_vers("127.0.0.3".parse().unwrap()) {
            Ok(c) => assert!(c.coupees >= 1, "{c:?}"),
            // Un noyau sans INET_DIAG_DESTROY le dit : c'est la réponse attendue, jamais un faux vert.
            Err(e) if e.to_string().contains("INET_DIAG_DESTROY") => {
                println!("saute : {e}");
                return;
            }
            Err(e) => panic!("{e}"),
        }
        let mut octet = [0u8; 1];
        client
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        // La prise du client est détruite : la lecture finit en erreur (ECONNABORTED) ou en fin de flux.
        let lu = client.read(&mut octet);
        assert!(matches!(lu, Err(_) | Ok(0)), "{lu:?}");
        // Plus rien vers cette adresse.
        assert_eq!(couper_vers("127.0.0.3".parse().unwrap()).unwrap().coupees, 0);
    }

    /// La coupure éprouvée sur une vraie connexion, dans un espace de noms réseau à part (rien ne touche les
    /// connexions de cet ordinateur). Sauté sans espaces de noms utilisateur.
    #[test]
    fn coupure_dans_un_espace_a_part() {
        let Ok(moi) = std::env::current_exe() else {
            return crate::essais::saute("programme de test introuvable");
        };
        let essai = std::process::Command::new("unshare").args(["-rn", "true"]).status();
        if !essai.is_ok_and(|s| s.success()) {
            return crate::essais::saute("pas d'espace de noms utilisateur ici (unshare -rn)");
        }
        if !std::path::Path::new("/usr/bin/ip").exists() && !std::path::Path::new("/usr/sbin/ip").exists() {
            return crate::essais::saute("« ip » absent : la boucle locale ne se monte pas");
        }
        let sortie = std::process::Command::new("unshare")
            .arg("-rn")
            .arg(moi)
            .args([
                "--ignored",
                "--exact",
                "machine::linux::couper::tests::coupure_dedans",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .unwrap();
        let texte = String::from_utf8_lossy(&sortie.stdout);
        assert!(
            sortie.status.success() && texte.contains("1 passed"),
            "{texte}\n{}",
            String::from_utf8_lossy(&sortie.stderr)
        );
        if texte.contains("saute : ") {
            crate::essais::saute("noyau sans INET_DIAG_DESTROY");
        }
    }
}
