//! Les échanges de clés qu'un serveur SSH propose, lus dans son paquet KEXINIT : il arrive en clair, avant tout
//! chiffrement (RFC 4253 §7.1). Vanguard envoie son identification, lit celle du serveur (en sautant les lignes de
//! bannière qu'un serveur peut envoyer avant « SSH- », RFC 4253 §4.2), puis UN paquet ; il ne répond jamais au
//! KEXINIT et raccroche : aucune authentification, aucune clé calculée. Ce que le serveur envoie est une donnée
//! hostile : tailles bornées, longueurs vérifiées ; illisible, rien n'est conclu.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, Instant};

use crate::modele::{Echec, Raison};

const OU: &str = "audit/kexinit";
/// Plus long qu'un paquet permis par la RFC 4253 (§6.1 : 35 000 octets).
const PAQUET_MAX: usize = 35_000;
/// Les lignes avant l'identification, l'identification et le paquet : au-delà, la lecture s'arrête.
const TOTAL_MAX: usize = 64 << 10;
/// SSH_MSG_KEXINIT.
const KEXINIT: u8 = 20;

/// Où en est la lecture de ce qui a été reçu.
#[derive(Debug, PartialEq, Eq)]
pub enum Lu {
    /// Il faut d'autres octets.
    Incomplet,
    /// Les échanges de clés proposés, dans l'ordre du serveur.
    Kex(Vec<String>),
}

/// Ce que le serveur a envoyé ne se lit pas : pourquoi, dans la langue de l'interface.
fn abime(pourquoi: &str) -> Echec {
    Echec::new(OU, Raison::Illisible(pourquoi.to_string()))
}

/// Lit l'identification puis le paquet KEXINIT dans `o`, tout ce que le serveur a envoyé jusqu'ici.
pub fn lire(o: &[u8]) -> Result<Lu, Echec> {
    // Les lignes de bannière, puis « SSH-2.0-… » ; chaque ligne finit par « \n » (« \r\n » d'après la RFC).
    let mut reste = o;
    loop {
        let mut morceaux = reste.splitn(2, |c| *c == b'\n');
        let (Some(ligne), Some(suite)) = (morceaux.next(), morceaux.next()) else {
            return if reste.len() > 255 {
                Err(abime(crate::tr!(
                    "ligne d'identification trop longue",
                    "identification line too long"
                )))
            } else {
                Ok(Lu::Incomplet)
            };
        };
        reste = suite;
        if ligne.starts_with(b"SSH-") {
            if !(ligne.starts_with(b"SSH-2.0-") || ligne.starts_with(b"SSH-1.99-")) {
                return Err(abime(crate::tr!(
                    "version du protocole SSH non prise en charge",
                    "SSH protocol version not supported"
                )));
            }
            break;
        }
    }
    let [l0, l1, l2, l3, _, ..] = *reste else {
        return Ok(Lu::Incomplet);
    };
    let longueur = usize::try_from(u32::from_be_bytes([l0, l1, l2, l3])).unwrap_or(usize::MAX);
    if !(5..=PAQUET_MAX).contains(&longueur) {
        return Err(abime(crate::tr!(
            "longueur de paquet hors des bornes",
            "packet length out of bounds"
        )));
    }
    let Some(paquet) = reste.get(4..).and_then(|r| r.get(..longueur)) else {
        return Ok(Lu::Incomplet);
    };
    // `longueur` >= 5 : le paquet a toujours son octet de bourrage.
    let bourrage = usize::from(*paquet.first().ok_or_else(|| {
        abime(crate::tr!(
            "longueur de paquet hors des bornes",
            "packet length out of bounds"
        ))
    })?);
    let charge = paquet
        .get(
            1..longueur
                .checked_sub(bourrage)
                .ok_or_else(|| abime(crate::tr!("bourrage trop long", "padding too long")))?,
        )
        .ok_or_else(|| abime(crate::tr!("bourrage trop long", "padding too long")))?;
    if charge.first() != Some(&KEXINIT) {
        return Err(abime(crate::tr!(
            "premier paquet autre qu'un KEXINIT",
            "first packet other than a KEXINIT"
        )));
    }
    // Message, puis 16 octets de cookie, puis la liste des échanges de clés (longueur sur 4 octets).
    let entete: [u8; 4] = charge
        .get(17..21)
        .and_then(|e| e.try_into().ok())
        .ok_or_else(|| abime(crate::tr!("KEXINIT tronqué", "truncated KEXINIT")))?;
    let n = usize::try_from(u32::from_be_bytes(entete)).unwrap_or(usize::MAX);
    let liste = charge
        .get(21..21usize.saturating_add(n))
        .ok_or_else(|| abime(crate::tr!("KEXINIT tronqué", "truncated KEXINIT")))?;
    let texte = std::str::from_utf8(liste)
        .map_err(|_| abime(crate::tr!("liste d'algorithmes illisible", "unreadable algorithm list")))?;
    let noms: Vec<String> = texte.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect();
    if noms.is_empty()
        || noms
            .iter()
            .any(|n| n.len() > 64 || !n.bytes().all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c)))
    {
        return Err(abime(crate::tr!(
            "liste d'algorithmes illisible",
            "unreadable algorithm list"
        )));
    }
    Ok(Lu::Kex(noms))
}

/// Les échanges de clés que le serveur SSH de `ip:port` propose, en moins de `delai`. Seulement une adresse du
/// réseau local (la box) : jamais un serveur d'Internet ni de la personne.
pub fn kexinit(ip: Ipv4Addr, port: u16, delai: Duration) -> Result<Vec<String>, Echec> {
    if !crate::reseau::nmap::locale(ip) || (!cfg!(test) && ip.is_loopback()) {
        return Err(Echec::refuse(
            OU,
            crate::tr!("adresse hors du réseau local", "address outside the local network"),
        ));
    }
    // Un délai qui ferait sortir l'instant limite des bornes d'Instant : aucune réponse ne l'attendra.
    let fin = Instant::now()
        .checked_add(delai)
        .ok_or_else(|| Echec::new(OU, Raison::Delai))?;
    let cible = SocketAddr::V4(SocketAddrV4::new(ip, port));
    let mut flux = TcpStream::connect_timeout(&cible, delai).map_err(|e| {
        Echec::echoue(
            OU,
            crate::trf!(
                "connexion refusée ou sans réponse ({e})",
                "connection refused or unanswered ({e})"
            ),
        )
    })?;
    flux.set_write_timeout(Some(delai)).map_err(|e| Echec::io(OU, &e))?;
    flux.write_all(b"SSH-2.0-Vanguard\r\n").map_err(|e| Echec::io(OU, &e))?;
    let mut recu = Vec::new();
    let mut tampon = [0u8; 4096];
    loop {
        if let Lu::Kex(noms) = lire(&recu)? {
            return Ok(noms);
        }
        let reste = fin.saturating_duration_since(Instant::now());
        if reste.is_zero() || recu.len() > TOTAL_MAX {
            return Err(Echec::new(OU, Raison::Delai));
        }
        flux.set_read_timeout(Some(reste)).map_err(|e| Echec::io(OU, &e))?;
        match flux.read(&mut tampon) {
            Ok(0) => {
                return Err(Echec::echoue(
                    OU,
                    crate::tr!("connexion fermée sans réponse", "connection closed without an answer"),
                ));
            }
            Ok(n) => recu.extend(tampon.iter().take(n)),
            Err(_) => return Err(Echec::new(OU, Raison::Delai)),
        }
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    reason = "essais : y déborder fait échouer l'essai"
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// Un KEXINIT fabriqué comme un serveur l'envoie : identification, puis le paquet.
    pub(crate) fn serveur(avant: &str, ident: &str, kex: &str) -> Vec<u8> {
        let mut charge = vec![KEXINIT];
        charge.extend_from_slice(&[0x5A; 16]);
        for liste in [
            kex,
            "ssh-ed25519",
            "aes128-ctr",
            "aes128-ctr",
            "hmac-sha2-256",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ] {
            charge.extend_from_slice(&u32::try_from(liste.len()).unwrap().to_be_bytes());
            charge.extend_from_slice(liste.as_bytes());
        }
        charge.extend_from_slice(&[0, 0, 0, 0, 0]);
        let bourrage = 8 - (charge.len() + 5) % 8 + 4;
        let longueur = charge.len() + bourrage + 1;
        let mut o = format!("{avant}{ident}\r\n").into_bytes();
        o.extend_from_slice(&u32::try_from(longueur).unwrap().to_be_bytes());
        o.push(u8::try_from(bourrage).unwrap());
        o.extend_from_slice(&charge);
        o.extend(std::iter::repeat_n(0, bourrage));
        o
    }

    const OPENSSH_10: &str = "mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ext-info-s,kex-strict-s-v00@openssh.com";
    const DROPBEAR: &str =
        "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,kexguess2@matt.ucc.asn.au";

    #[test]
    fn kexinit_figes() {
        let o = serveur("", "SSH-2.0-OpenSSH_10.0", OPENSSH_10);
        let Lu::Kex(noms) = lire(&o).unwrap() else { panic!() };
        assert_eq!(noms[0], "mlkem768x25519-sha256");
        assert!(noms.iter().any(|n| crate::machine::nom_pq(n)));
        let o = serveur("Bienvenue sur le routeur\r\n", "SSH-2.0-dropbear_2022.83", DROPBEAR);
        let Lu::Kex(noms) = lire(&o).unwrap() else { panic!() };
        assert!(!noms.iter().any(|n| crate::machine::nom_pq(n)));
        // Morceau par morceau : incomplet jusqu'au bout, jamais une erreur.
        for i in 0..o.len() {
            assert_eq!(lire(&o[..i]).unwrap(), Lu::Incomplet, "{i}");
        }
    }

    #[test]
    fn paquets_abimes_refuses() {
        let bon = serveur("", "SSH-2.0-OpenSSH_9.6", OPENSSH_10);
        let fin_ident = bon.iter().position(|c| *c == b'\n').unwrap() + 1;
        // Longueur géante.
        let mut x = bon.clone();
        x[fin_ident..fin_ident + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(lire(&x).is_err());
        // Pas un KEXINIT.
        let mut x = bon.clone();
        x[fin_ident + 5] = 21;
        assert!(lire(&x).is_err());
        // Liste plus longue que le paquet.
        let mut x = bon.clone();
        x[fin_ident + 5 + 17..fin_ident + 5 + 21].copy_from_slice(&40_000u32.to_be_bytes());
        assert!(lire(&x).is_err());
        // SSH 1, ligne sans fin.
        assert!(lire(b"SSH-1.5-vieux\r\n\0\0\0\0\0\0").is_err());
        assert!(lire(&[b'x'; 300]).is_err());
        // Noms piégés (séquence d'échappement).
        let x = serveur("", "SSH-2.0-x", "curve25519-sha256,\x1b[31m");
        assert!(lire(&x).is_err());
    }

    #[test]
    fn jamais_hors_du_reseau_local() {
        let e = kexinit(Ipv4Addr::new(192, 0, 2, 1), 22, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.code(), "refuse");
        let e = kexinit(Ipv4Addr::new(8, 8, 8, 8), 22, Duration::from_secs(1)).unwrap_err();
        assert_eq!(e.code(), "refuse");
    }

    /// Un faux serveur SSH sur la boucle locale : la vraie connexion lit son KEXINIT, puis raccroche.
    #[test]
    fn essai_reel_sur_la_boucle_locale() {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let fil = std::thread::spawn(move || {
            let (mut c, _) = ecoute.accept().unwrap();
            c.write_all(&serveur("", "SSH-2.0-OpenSSH_10.0", OPENSSH_10)).unwrap();
            let mut recu = [0u8; 64];
            let n = c.read(&mut recu).unwrap_or(0);
            String::from_utf8_lossy(&recu[..n]).into_owned()
        });
        let noms = kexinit(Ipv4Addr::LOCALHOST, port, Duration::from_secs(5)).unwrap();
        assert_eq!(noms[0], "mlkem768x25519-sha256");
        assert!(fil.join().unwrap().starts_with("SSH-2.0-Vanguard\r\n"));
    }
}
