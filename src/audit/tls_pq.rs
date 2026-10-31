//! Le serveur accepte-t-il l'échange de clés post-quantique X25519MLKEM768 (groupe 0x11EC) ? Sans aucun calcul :
//! `ring`, le fournisseur de rustls ici, ne connaît pas ML-KEM, et aws-lc est évité. Un ClientHello TLS 1.3 écrit
//! à la main propose ce seul groupe avec une liste de parts de clé vide (RFC 8446 §4.2.8) : un serveur qui le
//! connaît répond par un HelloRetryRequest qui le nomme, sinon par une alerte. La connexion est fermée aussitôt.
//!
//! La sonde porte l'extension « padding » (RFC 7685, des zéros) pour peser autant qu'un vrai ClientHello
//! post-quantique (≈ 1,2 Ko de part de clé, deux paquets TCP) : la panne réelle des boîtiers vient souvent de là, et
//! une sonde de 150 octets ne la reproduirait pas. La réponse du serveur est une donnée hostile : bornée en taille et
//! en temps, longueurs vérifiées ; incompréhensible, elle ne conclut rien.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]
// Ni `unsafe` : refusé sans recours, aucun `allow` intérieur ne le lève (garde : chaque_module_fuzze_refuse_unsafe).
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use crate::modele::{Echec, Raison};

/// X25519MLKEM768 (registre IANA des groupes TLS, 4588).
pub const GROUPE: u16 = 0x11EC;
/// La taille visée sur le fil : au-delà d'un paquet TCP, comme un vrai ClientHello post-quantique.
pub const TAILLE_SONDE: usize = 1600;
/// Au-delà, la réponse n'est plus lue : un HelloRetryRequest fait moins de 200 octets.
pub const TAILLE_MAX: usize = 16 << 10;

/// Le `random` fixe qui fait d'un ServerHello un HelloRetryRequest (RFC 8446 §4.1.3) : SHA-256 de
/// « HelloRetryRequest », écrit en dur.
const RANDOM_HRR: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11,
    0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Ce que le serveur a répondu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReponsePq {
    /// HelloRetryRequest qui choisit X25519MLKEM768.
    Accepte,
    /// Une alerte TLS (40 : handshake_failure, 70 : protocol_version…) : le groupe n'est pas accepté.
    Refuse(u8),
    /// Autre chose : rien n'est conclu.
    Autre,
}

/// Ajoute une extension : type, longueur, contenu.
fn extension(sortie: &mut Vec<u8>, genre: u16, contenu: &[u8]) {
    sortie.extend_from_slice(&genre.to_be_bytes());
    sortie.extend_from_slice(&u16::try_from(contenu.len()).unwrap_or(0).to_be_bytes());
    sortie.extend_from_slice(contenu);
}

/// Le ClientHello de la sonde. `hote` : le nom à mettre dans le SNI ; jamais pour une adresse IP (RFC 6066 §3).
/// `alea` : 64 octets (random, puis identifiant de session de compatibilité) ; fixés par les tests.
pub fn client_hello_avec(hote: Option<&str>, alea: &[u8; 64]) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(h) = hote.filter(|h| h.parse::<std::net::IpAddr>().is_err() && !h.is_empty() && h.len() < 256) {
        let nom = h.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(
            &nom.len()
                .checked_add(3)
                .and_then(|n| u16::try_from(n).ok())
                .unwrap_or(0)
                .to_be_bytes(),
        );
        sni.push(0);
        sni.extend_from_slice(&u16::try_from(nom.len()).unwrap_or(0).to_be_bytes());
        sni.extend_from_slice(nom);
        extension(&mut ext, 0, &sni);
    }
    // supported_versions : TLS 1.3 seulement.
    extension(&mut ext, 43, &[2, 0x03, 0x04]);
    // signature_algorithms : ECDSA, RSA-PSS, Ed25519, RSA PKCS#1 (pour les certificats).
    let signatures: [u16; 11] = [
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0808, 0x0401, 0x0501, 0x0601,
    ];
    let mut sig = Vec::new();
    sig.extend_from_slice(&u16::try_from(size_of_val(&signatures)).unwrap_or(0).to_be_bytes());
    for s in signatures {
        sig.extend_from_slice(&s.to_be_bytes());
    }
    extension(&mut ext, 13, &sig);
    // supported_groups : X25519MLKEM768 seul.
    let mut groupes = vec![0, 2];
    groupes.extend_from_slice(&GROUPE.to_be_bytes());
    extension(&mut ext, 10, &groupes);
    // key_share : liste vide, le serveur choisit (RFC 8446 §4.2.8).
    extension(&mut ext, 51, &[0, 0]);
    // Le reste du message : version, random, session, suites, compression, longueur des extensions.
    let mut corps = vec![0x03, 0x03];
    corps.extend_from_slice(&alea[..32]);
    corps.push(32);
    corps.extend_from_slice(&alea[32..]);
    corps.extend_from_slice(&[0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 1, 0]);
    // padding : ce qui manque pour atteindre la taille visée (en-têtes : 5 d'enregistrement, 4 de message, 2 de
    // longueur des extensions, 4 de l'extension elle-même). Saturer : au-delà, il ne manque rien.
    let deja = corps.len().saturating_add(ext.len()).saturating_add(5 + 4 + 2 + 4);
    extension(&mut ext, 21, &vec![0; TAILLE_SONDE.saturating_sub(deja)]);
    corps.extend_from_slice(&u16::try_from(ext.len()).unwrap_or(0).to_be_bytes());
    corps.extend_from_slice(&ext);
    let mut message = vec![1];
    message.extend_from_slice(&u32::try_from(corps.len()).unwrap_or(0).to_be_bytes()[1..]);
    message.extend_from_slice(&corps);
    let mut enregistrement = vec![0x16, 0x03, 0x01];
    enregistrement.extend_from_slice(&u16::try_from(message.len()).unwrap_or(0).to_be_bytes());
    enregistrement.extend_from_slice(&message);
    enregistrement
}

/// Le ClientHello de la sonde, avec un aléa neuf à chaque fois : rien de secret (la sonde ne calcule aucune clé),
/// il évite seulement qu'un intermédiaire reconnaisse ou rejoue une sonde déjà vue.
pub fn client_hello(hote: Option<&str>) -> Vec<u8> {
    let mut alea = [0u8; 64];
    for morceau in alea.chunks_mut(8) {
        morceau.copy_from_slice(&crate::reseau::nat::hasard().to_le_bytes());
    }
    client_hello_avec(hote, &alea)
}

/// Lit `n` octets à partir de `i`, sans jamais déborder.
fn prendre(o: &[u8], i: &mut usize, n: usize) -> Option<std::ops::Range<usize>> {
    let fin = i.checked_add(n)?;
    if fin > o.len() {
        return None;
    }
    let r = *i..fin;
    *i = fin;
    Some(r)
}

/// Comme `prendre`, mais rend les octets eux-mêmes.
fn prendre_octets<'a>(o: &'a [u8], i: &mut usize, n: usize) -> Option<&'a [u8]> {
    o.get(prendre(o, i, n)?)
}

fn u16_a(o: &[u8], i: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(*prendre_octets(o, i, 2)?.first_chunk::<2>()?))
}

/// La réponse du serveur : le premier enregistrement TLS reçu. `None` : il n'est pas encore entier.
pub fn lire_reponse(o: &[u8]) -> Option<ReponsePq> {
    let [genre, majeur, _, l0, l1, ..] = *o else {
        return None;
    };
    let longueur = usize::from(u16::from_be_bytes([l0, l1]));
    if majeur != 0x03 || longueur > TAILLE_MAX {
        return Some(ReponsePq::Autre);
    }
    let corps = o.get(5..5 + longueur)?;
    Some(match genre {
        0x15 => match *corps {
            [_, raison] => ReponsePq::Refuse(raison),
            _ => ReponsePq::Autre,
        },
        0x16 => lire_server_hello(corps).unwrap_or(ReponsePq::Autre),
        _ => ReponsePq::Autre,
    })
}

/// Un ServerHello : accepté seulement s'il est un HelloRetryRequest (random fixe) dont l'extension key_share nomme
/// X25519MLKEM768.
fn lire_server_hello(o: &[u8]) -> Option<ReponsePq> {
    if o.first() != Some(&2) {
        return Some(ReponsePq::Autre);
    }
    let mut i = 4;
    let _version = u16_a(o, &mut i)?;
    if *prendre_octets(o, &mut i, 32)? != RANDOM_HRR {
        return Some(ReponsePq::Autre);
    }
    let &[session] = prendre_octets(o, &mut i, 1)? else {
        return None;
    };
    prendre(o, &mut i, usize::from(session))?;
    prendre(o, &mut i, 3)?;
    let total = usize::from(u16_a(o, &mut i)?);
    let fin = i.checked_add(total)?;
    while i < fin {
        let genre = u16_a(o, &mut i)?;
        let n = usize::from(u16_a(o, &mut i)?);
        let contenu = prendre(o, &mut i, n)?;
        if genre == 51 {
            let mut j = contenu.start;
            let groupe = u16_a(o, &mut j)?;
            return Some(if groupe == GROUPE && n == 2 {
                ReponsePq::Accepte
            } else {
                ReponsePq::Autre
            });
        }
    }
    Some(ReponsePq::Autre)
}

/// Envoie la sonde à `adresse` et lit la réponse, le tout avant `delai`. L'appelant choisit l'adresse : le site de
/// référence déjà contacté, ou un port d'administration de la box trouvé ouvert par le scan.
pub fn sonder(adresse: SocketAddr, hote: Option<&str>, delai: Duration) -> Result<ReponsePq, Echec> {
    const OU: &str = "audit/tls-pq";
    let muet = || Echec::new(OU, Raison::Delai);
    // Un délai qui ferait sortir l'instant limite des bornes d'Instant : aucune réponse ne l'attendra.
    let fin = Instant::now().checked_add(delai).ok_or_else(muet)?;
    let mut flux = TcpStream::connect_timeout(&adresse, delai).map_err(|e| {
        Echec::echoue(
            OU,
            crate::trf!(
                "connexion refusée ou sans réponse ({e})",
                "connection refused or unanswered ({e})"
            ),
        )
    })?;
    flux.set_write_timeout(Some(delai)).map_err(|e| Echec::io(OU, &e))?;
    flux.write_all(&client_hello(hote)).map_err(|e| Echec::io(OU, &e))?;
    let mut recu = Vec::new();
    let mut tampon = [0u8; 2048];
    loop {
        if let Some(r) = lire_reponse(&recu) {
            return Ok(r);
        }
        let reste = fin.saturating_duration_since(Instant::now());
        if reste.is_zero() || recu.len() > TAILLE_MAX {
            return Err(muet());
        }
        flux.set_read_timeout(Some(reste)).map_err(|e| Echec::io(OU, &e))?;
        match flux.read(&mut tampon) {
            // Fermé sans rien dire : un intermédiaire qui coupe ce qu'il ne comprend pas, sans conclusion possible.
            Ok(0) => {
                return Err(Echec::echoue(
                    OU,
                    crate::tr!("connexion fermée sans réponse", "connection closed without an answer"),
                ));
            }
            Ok(n) => recu.extend(tampon.iter().take(n)),
            Err(_) => return Err(muet()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALEA: [u8; 64] = [7; 64];

    #[test]
    fn client_hello_dore() {
        let o = client_hello_avec(None, &ALEA);
        assert_eq!(o.len(), TAILLE_SONDE, "padding jusqu'à la taille visée");
        assert_eq!(&o[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(usize::from(u16::from_be_bytes([o[3], o[4]])), o.len() - 5);
        assert_eq!(o[5], 1, "ClientHello");
        // Pas de SNI pour une adresse ; le groupe 0x11EC seul ; key_share vide.
        let texte = |o: &[u8], m: &[u8]| o.windows(m.len()).any(|f| f == m);
        assert!(!texte(&o, b"1.1.1.1"));
        assert!(texte(&o, &[0, 10, 0, 4, 0, 2, 0x11, 0xEC]));
        assert!(texte(&o, &[0, 51, 0, 2, 0, 0]));
        assert!(texte(&o, &[0, 43, 0, 3, 2, 3, 4]));
        // Les premiers octets, figés : version, random, session de compatibilité, suites TLS 1.3.
        assert_eq!(&o[9..11], &[3, 3]);
        assert_eq!(&o[11..43], &[7; 32]);
        assert_eq!(o[43], 32);
        assert_eq!(&o[76..86], &[0, 6, 0x13, 1, 0x13, 2, 0x13, 3, 1, 0]);
        let avec = client_hello_avec(Some("www.example.com"), &ALEA);
        assert_eq!(avec.len(), TAILLE_SONDE);
        assert!(texte(&avec, b"\x00\x00\x0fwww.example.com"));
        assert!(!texte(&client_hello_avec(Some("192.0.2.1"), &ALEA), b"192.0.2.1"));
        // La longueur des extensions tombe juste : tout le message est compté.
        let ext = usize::from(u16::from_be_bytes([o[86], o[87]]));
        assert_eq!(88 + ext, o.len());
    }

    /// Un HelloRetryRequest tel que 1.1.1.1 l'envoie (session renvoyée, TLS_AES_128_GCM_SHA256, groupe 0x11EC).
    fn hrr(groupe: u16, random: [u8; 32]) -> Vec<u8> {
        let mut m = vec![3, 3];
        m.extend_from_slice(&random);
        m.push(32);
        m.extend_from_slice(&[7; 32]);
        m.extend_from_slice(&[0x13, 0x01, 0]);
        let mut ext = vec![0, 43, 0, 2, 3, 4, 0, 51, 0, 2];
        ext.extend_from_slice(&groupe.to_be_bytes());
        m.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        m.extend_from_slice(&ext);
        let mut h = vec![2, 0];
        h.extend_from_slice(&u16::try_from(m.len()).unwrap().to_be_bytes());
        h.extend_from_slice(&m);
        let mut e = vec![0x16, 3, 3];
        e.extend_from_slice(&u16::try_from(h.len()).unwrap().to_be_bytes());
        e.extend_from_slice(&h);
        e
    }

    #[test]
    fn reponses_figees() {
        assert_eq!(lire_reponse(&hrr(GROUPE, RANDOM_HRR)), Some(ReponsePq::Accepte));
        assert_eq!(lire_reponse(&hrr(0x001D, RANDOM_HRR)), Some(ReponsePq::Autre));
        // Un ServerHello ordinaire (autre random) : rien n'est conclu.
        assert_eq!(lire_reponse(&hrr(GROUPE, [1; 32])), Some(ReponsePq::Autre));
        assert_eq!(lire_reponse(&[0x15, 3, 3, 0, 2, 2, 40]), Some(ReponsePq::Refuse(40)));
        assert_eq!(lire_reponse(&[0x15, 3, 1, 0, 2, 2, 70]), Some(ReponsePq::Refuse(70)));
        // Incomplet : pas encore de réponse ; ordure : autre.
        let complet = hrr(GROUPE, RANDOM_HRR);
        assert_eq!(lire_reponse(&complet[..20]), None);
        assert_eq!(lire_reponse(b"HTTP/1.1 400 Bad Request\r\n"), Some(ReponsePq::Autre));
        assert_eq!(lire_reponse(&[0x16, 3, 3, 0xFF, 0xFF]), Some(ReponsePq::Autre));
        assert_eq!(lire_reponse(&[0x16, 3, 3, 0, 1, 2]), Some(ReponsePq::Autre));
        assert_eq!(lire_reponse(&[]), None);
    }

    /// Aucune suite d'octets ne fait paniquer la lecture.
    #[test]
    fn lecture_jamais_en_panique() {
        let base = hrr(GROUPE, RANDOM_HRR);
        for i in 0..base.len() {
            let _ = lire_reponse(&base[..i]);
            for o in [0u8, 0xFF, 1] {
                let mut x = base.clone();
                x[i] = o;
                let _ = lire_reponse(&x);
            }
        }
    }

    /// Essai réel hors ligne, sur la boucle locale : « openssl s_server » avec X25519MLKEM768 répond accepté, avec
    /// X25519 seul répond refusé. Sauté si OpenSSL 3.5 ou plus n'est pas là.
    #[test]
    fn essai_reel_avec_openssl() {
        use std::process::{Command, Stdio};
        let Some(v) = crate::commande::lancer(Command::new("openssl").arg("version"), 10) else {
            return crate::essais::saute("openssl absent");
        };
        let version: Vec<u32> = v
            .sortie
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .split('.')
            .filter_map(|n| n.parse().ok())
            .collect();
        if version.len() < 2 || (version[0], version[1]) < (3, 5) {
            return crate::essais::saute("OpenSSL 3.5 ou plus requis pour X25519MLKEM768");
        }
        let d = crate::socle::dossier_local().join("tls-pq");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let (cle, cert) = (d.join("cle.pem"), d.join("cert.pem"));
        let fait = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
            ])
            .args(["-subj", "/CN=example.com", "-days", "1", "-keyout"])
            .arg(&cle)
            .arg("-out")
            .arg(&cert)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !fait {
            return crate::essais::saute("certificat d'essai non créé");
        }
        for (groupes, attendu) in [("X25519MLKEM768", true), ("X25519", false)] {
            let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = ecoute.local_addr().unwrap().port();
            drop(ecoute);
            // L'adresse avec le port : un port seul, sous Windows, n'écoute qu'en IPv6 (::), où 127.0.0.1 ne répond pas.
            // -www : s_server répond lui-même, sans lire son entrée ; sous Windows, la lecture d'un tube vide le
            // figeait avant la poignée de main (« s_server n'a pas répondu », sans un mot de sa part).
            let mut serveur = Command::new("openssl")
                .args(["s_server", "-quiet", "-www", "-tls1_3", "-groups", groupes, "-accept"])
                .arg(format!("127.0.0.1:{port}"))
                .arg("-key")
                .arg(&cle)
                .arg("-cert")
                .arg(&cert)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let adresse: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let (mut r, mut derniere) = (None, None);
            for _ in 0..50 {
                std::thread::sleep(Duration::from_millis(100));
                match sonder(adresse, Some("example.com"), Duration::from_secs(5)) {
                    Ok(x) => {
                        r = Some(x);
                        break;
                    }
                    Err(e) => derniere = Some(e),
                }
            }
            let _ = serveur.kill();
            // Ce que s_server a dit (groupe inconnu, port pris…) : sans lui, un échec ne disait pas pourquoi.
            let dit = serveur
                .wait_with_output()
                .map(|o| String::from_utf8_lossy(&o.stderr).into_owned());
            let r =
                r.unwrap_or_else(|| panic!("s_server n'a pas répondu ({groupes}) : {dit:?} ; sonde : {derniere:?}"));
            if attendu {
                assert_eq!(r, ReponsePq::Accepte, "{groupes}");
            } else {
                assert!(matches!(r, ReponsePq::Refuse(_)), "{groupes} : {r:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
