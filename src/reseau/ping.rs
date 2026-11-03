//! Un écho ICMP (« ping ») vers une adresse IPv4, sans lancer `ping` : sous Linux par une prise ICMP
//! « datagramme », qui ne demande aucun droit si net.ipv4.ping_group_range couvre le groupe (ce que systemd règle à
//! tous), sous Windows par IcmpSendEcho (`machine::windows::routes`). `None` : le système
//! refuse la prise ou l'API, rien n'est prouvé, et l'appelant lance `ping` en secours.

// Sous Linux seulement : les parties Windows ne sont pas encore relues ; le lint y viendra avec elles.
#![cfg_attr(target_os = "linux", warn(clippy::arithmetic_side_effects, clippy::as_conversions))]
// FFI de libc : prise ICMP (socket, sendto, recvfrom, poll).
#![allow(unsafe_code)]

use std::net::Ipv4Addr;
use std::time::Duration;

/// `Some(true)` : la cible elle-même a répondu ; `Some(false)` : pas de réponse dans le délai, ou le réseau dit
/// qu'elle est injoignable.
pub(crate) fn echo(cible: Ipv4Addr, delai: Duration) -> Option<bool> {
    #[cfg(unix)]
    {
        unix::echo(cible, delai)
    }
    #[cfg(windows)]
    {
        crate::machine::windows::routes::echo(cible, delai)
    }
}

/// Le paquet de la demande d'écho : type 8, code 0, somme de contrôle, identifiant, numéro, puis `donnees`.
#[cfg(any(not(windows), test))]
fn demande(identifiant: u16, numero: u16, donnees: &[u8]) -> Vec<u8> {
    let mut p = vec![8, 0, 0, 0];
    p.extend(identifiant.to_be_bytes());
    p.extend(numero.to_be_bytes());
    p.extend(donnees);
    let somme = somme_de_controle(&p);
    // Les octets 2 et 3 existent : posés à la création de `p`.
    if let Some(case) = p.get_mut(2..4) {
        case.copy_from_slice(&somme.to_be_bytes());
    }
    p
}

/// La somme de contrôle d'Internet (RFC 1071) : le complément à un de la somme en complément à un des mots de 16
/// bits.
#[cfg(any(not(windows), test))]
fn somme_de_controle(octets: &[u8]) -> u16 {
    // Un octet seul à la fin compte comme un mot complété d'un zéro.
    let (mots, dernier) = octets.as_chunks::<2>();
    let mut somme: u32 = mots
        .iter()
        .map(|&m| u32::from(u16::from_be_bytes(m)))
        .chain(dernier.first().map(|&o| u32::from(u16::from_be_bytes([o, 0]))))
        .sum();
    while somme > 0xffff {
        somme = (somme & 0xffff).saturating_add(somme >> 16);
    }
    // Repliée plus haut sous 0x10000 : elle tient dans un u16.
    let somme = u16::try_from(somme).unwrap_or(u16::MAX);
    !somme
}

/// La réponse reçue est-elle l'écho de notre demande ? Le message ICMP seul (la prise « datagramme » de Linux ne rend
/// pas l'en-tête IP) : une réponse d'écho (type 0) qui porte nos données, venue de la cible ; un autre message (un
/// « injoignable » d'un routeur, l'écho d'un autre programme) ne compte pas.
#[cfg(any(not(windows), test))]
fn est_notre_echo(recu: &[u8], depuis: Ipv4Addr, cible: Ipv4Addr, donnees: &[u8]) -> bool {
    depuis == cible && recu.first() == Some(&0) && recu.get(8..) == Some(donnees)
}

#[cfg(unix)]
mod unix {
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    pub(super) fn echo(cible: Ipv4Addr, delai: Duration) -> Option<bool> {
        // SAFETY: socket ne lit aucun pointeur ; le descripteur rendu est vérifié, puis confié à OwnedFd, qui le
        // ferme une fois.
        let prise = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP);
            if fd < 0 {
                return None;
            }
            OwnedFd::from_raw_fd(fd)
        };
        // Des données propres à cet essai : elles distinguent notre écho de celui d'un autre programme.
        let marque = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
            ^ std::process::id();
        let mut donnees = b"Vanguard, la box repond ?".to_vec();
        donnees.extend(marque.to_be_bytes());
        #[allow(clippy::cast_possible_truncation)]
        // Les 16 bits de poids faible du PID : un identifiant d'écho, pas un nombre.
        let identifiant = u16::try_from(std::process::id() & 0xffff).unwrap_or(0);
        let paquet = super::demande(identifiant, 1, &donnees);
        let adresse = libc::sockaddr_in {
            sin_family: libc::sa_family_t::try_from(libc::AF_INET).ok()?,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(cible.octets()),
            },
            sin_zero: [0; 8],
        };
        let taille_adresse = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_in>()).ok()?;
        // SAFETY: le paquet et l'adresse sont à nous, de la taille annoncée, vivants pendant l'appel.
        let envoye = unsafe {
            libc::sendto(
                prise.as_raw_fd(),
                paquet.as_ptr().cast(),
                paquet.len(),
                0,
                (&raw const adresse).cast(),
                taille_adresse,
            )
        };
        if envoye < 0 {
            let erreur = std::io::Error::last_os_error();
            return match erreur.raw_os_error() {
                // Le système dit lui-même que la cible n'est pas joignable d'ici.
                Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EHOSTDOWN) => Some(false),
                _ => None,
            };
        }
        let fin = Instant::now().checked_add(delai).unwrap_or_else(Instant::now);
        let mut tampon = [0u8; 1500];
        loop {
            let reste = fin.saturating_duration_since(Instant::now());
            if reste.is_zero() {
                return Some(false);
            }
            let mut attente = libc::pollfd {
                fd: prise.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = libc::c_int::try_from(reste.as_millis())
                .unwrap_or(libc::c_int::MAX)
                .max(1);
            // SAFETY: une seule structure pollfd, à nous et vivante pendant l'appel.
            match unsafe { libc::poll(&raw mut attente, 1, ms) } {
                0 => return Some(false),
                n if n < 0 => match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    _ => return None,
                },
                _ => {}
            }
            let mut depuis = libc::sockaddr_in {
                sin_family: 0,
                sin_port: 0,
                sin_addr: libc::in_addr { s_addr: 0 },
                sin_zero: [0; 8],
            };
            let mut taille_depuis = taille_adresse;
            // SAFETY: le tampon et l'adresse sont à nous, de la taille annoncée, vivants pendant l'appel ; recvfrom
            // écrit au plus `tampon.len()` octets et au plus `taille_depuis` octets d'adresse. MSG_DONTWAIT : poll a
            // dit qu'un message attend, rien ne bloque au-delà du délai.
            let recu = unsafe {
                libc::recvfrom(
                    prise.as_raw_fd(),
                    tampon.as_mut_ptr().cast(),
                    tampon.len(),
                    libc::MSG_DONTWAIT,
                    (&raw mut depuis).cast(),
                    &raw mut taille_depuis,
                )
            };
            if recu < 0 {
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR | libc::EAGAIN) => continue,
                    _ => return None,
                }
            }
            let n = usize::try_from(recu).ok()?.min(tampon.len());
            let source = Ipv4Addr::from(depuis.sin_addr.s_addr.to_ne_bytes());
            if tampon
                .get(..n)
                .is_some_and(|recu| super::est_notre_echo(recu, source, cible, &donnees))
            {
                return Some(true);
            }
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

    #[test]
    fn paquet_et_somme_de_controle() {
        let p = demande(0x1234, 1, b"abc");
        assert_eq!(&p[..2], &[8, 0]);
        assert_eq!(&p[4..8], &[0x12, 0x34, 0, 1]);
        // Un paquet juste se vérifie à zéro : sa somme, contrôle compris, vaut 0xffff.
        assert_eq!(somme_de_controle(&p), 0);
        // L'exemple de la RFC 1071 (§ 3) : 0001 f203 f4f5 f6f7 → somme 0xddf2, complément 0x220d.
        assert_eq!(
            somme_de_controle(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            !0xddf2
        );
    }

    #[test]
    fn reconnaitre_notre_echo() {
        let boite = Ipv4Addr::new(192, 168, 1, 1);
        let donnees = b"Vanguard-1";
        let mut reponse = demande(7, 1, donnees);
        reponse[0] = 0;
        assert!(est_notre_echo(&reponse, boite, boite, donnees));
        // Avec un en-tête IP devant, que la prise de Linux ne rend jamais : pas lu comme un écho.
        let mut ip = vec![0x45];
        ip.resize(20, 0);
        ip.extend(&reponse);
        assert!(!est_notre_echo(&ip, boite, boite, donnees));
        // Venu d'ailleurs, les données d'un autre, un « injoignable » (type 3) : pas notre écho.
        assert!(!est_notre_echo(
            &reponse,
            Ipv4Addr::new(192, 168, 1, 20),
            boite,
            donnees
        ));
        assert!(!est_notre_echo(&reponse, boite, boite, b"autre"));
        let mut injoignable = reponse.clone();
        injoignable[0] = 3;
        assert!(!est_notre_echo(&injoignable, boite, boite, donnees));
        assert!(!est_notre_echo(&[], boite, boite, donnees));
    }

    /// La vraie prise de cet ordinateur : la boucle locale répond, sauf si le système refuse la prise ICMP
    /// (ping_group_range), ce qui ne prouve rien.
    #[cfg(unix)]
    #[test]
    fn echo_de_la_boucle_locale() {
        match echo(Ipv4Addr::LOCALHOST, Duration::from_secs(2)) {
            None => crate::essais::saute("prise ICMP refusée (ping_group_range)"),
            Some(r) => assert!(r, "la boucle locale doit répondre"),
        }
    }
}
