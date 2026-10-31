//! Un client HTTP/1.1 minuscule pour parler aux appareils du réseau local : la description UPnP d'une box et ses
//! actions SOAP (`igd`). `http.rs` n'accepte que HTTPS, et une box n'a pas de certificat qu'un navigateur
//! accepterait. Borné de partout : seulement une adresse du réseau local écrite en chiffres (jamais Internet, jamais
//! un nom à résoudre), un instant limite pour toute la demande, une taille de réponse ; aucune redirection suivie.

// Ni débordement ni `as` : module lu par le banc de fuzzing, sur des données hostiles (Cargo.toml, [lints.clippy]).
#![warn(clippy::arithmetic_side_effects, clippy::as_conversions)]

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Instant;

/// Taille maximale d'une réponse : une description UPnP fait quelques Ko, une réponse SOAP moins d'un Ko.
pub const TAILLE_MAX: usize = 64 << 10;

/// Une adresse HTTP du réseau local, lue dans « http://10.0.0.1:5000/rootDesc.xml ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adresse {
    pub ip: Ipv4Addr,
    pub port: u16,
    /// Le chemin, avec sa barre de tête (« / » au moins).
    pub chemin: String,
}

impl Adresse {
    /// `None` : pas du HTTP en clair, pas une adresse IPv4 écrite en chiffres, pas une adresse locale, ou un chemin
    /// qui casserait la ligne de demande : Vanguard ne suit jamais une box (ou un appareil qui se fait passer pour
    /// elle) vers Internet.
    pub fn lire(url: &str) -> Option<Adresse> {
        let reste = url.strip_prefix("http://")?;
        let (hote, chemin) = match reste.find('/') {
            Some(i) => (&reste[..i], &reste[i..]),
            None => (reste, "/"),
        };
        let (ip, port) = match hote.rsplit_once(':') {
            Some((ip, port)) => (ip, port.parse().ok()?),
            None => (hote, 80),
        };
        let ip: Ipv4Addr = ip.parse().ok()?;
        if !admise(ip, cfg!(test)) || chemin.chars().any(|c| c.is_ascii_control() || c == ' ') {
            return None;
        }
        Some(Adresse {
            ip,
            port,
            chemin: chemin.to_string(),
        })
    }

    /// L'hôte d'une adresse donnée par la box (absolue, ou relative à celle-ci) : une description, un URLBase ou un
    /// point de contrôle qui mènerait vers un autre appareil que celui qui a répondu n'est pas suivi.
    pub fn meme_hote(&self, url: &str) -> bool {
        Adresse::lire(&self.resoudre(url)).is_some_and(|a| a.ip == self.ip)
    }

    /// « http://10.0.0.1:5000 ».
    pub fn origine(&self) -> String {
        format!("http://{}:{}", self.ip, self.port)
    }

    /// Une adresse donnée par la box, relative ou absolue (« /ctl », « ctl/IPConn », « http://10.0.0.1:5000/ctl »),
    /// résolue par rapport à celle-ci, comme un navigateur le ferait.
    pub fn resoudre(&self, lien: &str) -> String {
        if lien.starts_with("http://") || lien.starts_with("https://") {
            return lien.to_string();
        }
        if lien.starts_with('/') {
            return format!("{}{lien}", self.origine());
        }
        let dossier = self.chemin.rsplit_once('/').map_or("", |(d, _)| d);
        format!("{}{dossier}/{lien}", self.origine())
    }
}

/// Une adresse du réseau local, jamais cet ordinateur (la boucle locale) hors des tests (`boucle`) : une réponse
/// SSDP du réseau qui y menait faisait envoyer à Vanguard un GET puis des POST vers les services de cette machine qui
/// n'écoutent qu'en local (serveur de développement, administration locale).
fn admise(ip: Ipv4Addr, boucle: bool) -> bool {
    crate::reseau::nmap::locale(ip) && (boucle || !ip.is_loopback() && !ip.is_unspecified())
}

/// Une réponse reçue, quel que soit son code (une erreur SOAP arrive en 500).
#[derive(Debug, PartialEq, Eq)]
pub struct Reponse {
    pub code: u16,
    pub corps: Vec<u8>,
}

impl Reponse {
    pub fn texte(&self) -> String {
        String::from_utf8_lossy(&self.corps).into_owned()
    }
}

/// Envoie `methode` (GET, POST) à `url` avec ces en-têtes et ce corps, et reçoit la réponse entière, le tout avant
/// `fin`. `None` : adresse refusée, pas de réponse à temps, réponse trop grosse ou illisible.
pub fn demander(
    methode: &str,
    url: &str,
    entetes: &[(&str, &str)],
    corps: Option<&[u8]>,
    fin: Instant,
) -> Option<Reponse> {
    let adresse = Adresse::lire(url)?;
    let reste = fin.saturating_duration_since(Instant::now());
    if reste.is_zero() {
        return None;
    }
    let cible: SocketAddr = SocketAddrV4::new(adresse.ip, adresse.port).into();
    let mut flux = TcpStream::connect_timeout(&cible, reste).ok()?;
    flux.set_write_timeout(Some(reste)).ok()?;
    let mut demande = format!(
        "{methode} {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: vanguard\r\nConnection: close\r\n",
        adresse.chemin, adresse.ip, adresse.port
    );
    for (nom, valeur) in entetes {
        let _ = write!(demande, "{nom}: {valeur}\r\n");
    }
    if let Some(corps) = corps {
        let _ = write!(demande, "Content-Length: {}\r\n", corps.len());
    }
    demande.push_str("\r\n");
    // En-têtes et corps d'un seul envoi : une box lente à lire ne doit pas attendre le corps dans un second paquet.
    let mut paquet = demande.into_bytes();
    paquet.extend_from_slice(corps.unwrap_or_default());
    flux.write_all(&paquet).ok()?;
    let mut brut = Vec::new();
    let mut tampon = [0u8; 4096];
    loop {
        let reste = fin.saturating_duration_since(Instant::now());
        if reste.is_zero() {
            break;
        }
        flux.set_read_timeout(Some(reste)).ok()?;
        match flux.read(&mut tampon) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                brut.extend(tampon.iter().take(n));
                if brut.len() > TAILLE_MAX {
                    return None;
                }
                if complete(&brut) {
                    break;
                }
            }
        }
    }
    lire_reponse(&brut)
}

/// L'en-tête et le corps sont-ils tous les deux arrivés ? Avec `Connection: close`, la box ferme en général ; celle
/// qui garde la connexion ouverte ne doit pas faire attendre le délai entier : on s'arrête dès que la longueur
/// annoncée (ou le dernier morceau d'une réponse envoyée par morceaux) est là.
fn complete(brut: &[u8]) -> bool {
    let Some((tete, corps)) = fin_entetes(brut).and_then(|i| brut.split_at_checked(i)) else {
        return false;
    };
    let entetes = String::from_utf8_lossy(tete).to_ascii_lowercase();
    if par_morceaux(&entetes) {
        return corps.ends_with(b"0\r\n\r\n");
    }
    longueur_annoncee(&entetes).is_some_and(|n| corps.len() >= n)
}

/// Position du premier octet du corps, après la ligne vide qui finit les en-têtes.
fn fin_entetes(brut: &[u8]) -> Option<usize> {
    brut.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|i| i.checked_add(4))
}

/// « content-length: 1234 », dans des en-têtes déjà en minuscules.
fn longueur_annoncee(entetes: &str) -> Option<usize> {
    entetes
        .lines()
        .find_map(|l| l.strip_prefix("content-length:")?.trim().parse().ok())
}

/// « transfer-encoding: chunked », dans des en-têtes déjà en minuscules.
fn par_morceaux(entetes: &str) -> bool {
    entetes.lines().any(|l| {
        l.strip_prefix("transfer-encoding:")
            .is_some_and(|v| v.trim() == "chunked")
    })
}

/// Lit une réponse HTTP/1.1 brute : son code, puis son corps (de la longueur annoncée, recollé s'il arrive par
/// morceaux, sinon tout ce qui suit les en-têtes).
pub fn lire_reponse(brut: &[u8]) -> Option<Reponse> {
    let (tete, corps) = brut.split_at_checked(fin_entetes(brut)?)?;
    let entetes = String::from_utf8_lossy(tete).to_ascii_lowercase();
    let code = entetes
        .lines()
        .next()?
        .strip_prefix("http/1.")?
        .get(2..)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let corps = if par_morceaux(&entetes) {
        recoller(corps)
    } else {
        match longueur_annoncee(&entetes) {
            Some(n) => corps.get(..n.min(corps.len()))?.to_vec(),
            None => corps.to_vec(),
        }
    };
    Some(Reponse { code, corps })
}

/// Recolle les morceaux d'une réponse « chunked » : chaque morceau commence par sa taille en hexadécimal, le
/// dernier a la taille 0. Un morceau annoncé plus long que ce qui est là finit la lecture.
fn recoller(mut reste: &[u8]) -> Vec<u8> {
    let mut corps = Vec::new();
    while let Some(fin_ligne) = reste.windows(2).position(|w| w == b"\r\n") {
        let Some(ligne) = reste.get(..fin_ligne) else {
            break;
        };
        let taille = String::from_utf8_lossy(ligne);
        let taille = taille.split(';').next().unwrap_or_default().trim();
        let Ok(n) = usize::from_str_radix(taille, 16) else {
            break;
        };
        if n == 0 {
            break;
        }
        let Some(debut) = fin_ligne.checked_add(2) else {
            break;
        };
        let Some(fin_morceau) = debut.checked_add(n) else {
            break;
        };
        let Some(morceau) = reste.get(debut..fin_morceau) else {
            break;
        };
        corps.extend_from_slice(morceau);
        reste = reste.get(fin_morceau.saturating_add(2)..).unwrap_or_default();
    }
    corps
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hors des tests, la boucle locale n'est jamais visée : une box (ou un appareil qui s'en dit une) ne fait pas
    /// parler Vanguard aux services de cette machine ; et un point de contrôle ailleurs que chez elle n'est pas suivi.
    #[test]
    fn jamais_cette_machine_ni_un_autre_hote() {
        assert!(!admise(Ipv4Addr::LOCALHOST, false));
        assert!(!admise(Ipv4Addr::new(127, 1, 2, 3), false));
        assert!(!admise(Ipv4Addr::UNSPECIFIED, false));
        assert!(admise(Ipv4Addr::new(192, 168, 1, 1), false));
        assert!(!admise(Ipv4Addr::new(203, 0, 113, 9), false));
        let base = Adresse::lire("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        assert!(base.meme_hote("/ctl/IPConn") && base.meme_hote("http://192.168.1.1:5000/ctl"));
        assert!(!base.meme_hote("http://192.168.1.20:80/ctl"));
        assert!(!base.meme_hote("http://203.0.113.9/ctl"));
    }
    use std::time::Duration;

    #[test]
    fn adresses_du_reseau_local_seulement() {
        let a = Adresse::lire("http://10.0.0.1:5000/rootDesc.xml").unwrap();
        assert_eq!(
            (a.ip, a.port, a.chemin.as_str()),
            (Ipv4Addr::new(10, 0, 0, 1), 5000, "/rootDesc.xml")
        );
        let b = Adresse::lire("http://192.168.1.1").unwrap();
        assert_eq!((b.port, b.chemin.as_str()), (80, "/"));
        assert_eq!(b.origine(), "http://192.168.1.1:80");
        // Internet, un nom à résoudre, HTTPS, un chemin qui casserait la demande : refusés.
        for url in [
            "http://8.8.8.8/desc.xml",
            "http://box.local/desc.xml",
            "https://10.0.0.1/desc.xml",
            "http://10.0.0.1/a\r\nX: y",
            "http://10.0.0.1:abc/",
            "10.0.0.1/desc.xml",
        ] {
            assert_eq!(Adresse::lire(url), None, "{url}");
        }
        // Liens de la box, relatifs ou absolus, résolus comme un navigateur.
        assert_eq!(a.resoudre("/ctl/IPConn"), "http://10.0.0.1:5000/ctl/IPConn");
        assert_eq!(a.resoudre("ctl/IPConn"), "http://10.0.0.1:5000/ctl/IPConn");
        let c = Adresse::lire("http://10.0.0.1:5000/upnp/desc.xml").unwrap();
        assert_eq!(c.resoudre("ctl"), "http://10.0.0.1:5000/upnp/ctl");
        assert_eq!(c.resoudre("http://10.0.0.1:49152/ctl"), "http://10.0.0.1:49152/ctl");
    }

    #[test]
    fn reponses_lues() {
        let r = lire_reponse(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nabcdefgh").unwrap();
        assert_eq!((r.code, r.corps.as_slice()), (500, &b"abcde"[..]));
        let r = lire_reponse(b"HTTP/1.0 200\r\nServer: box\r\n\r\ntout ce qui suit").unwrap();
        assert_eq!((r.code, r.texte().as_str()), (200, "tout ce qui suit"));
        let r = lire_reponse(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3;x=y\r\nefg\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.texte(), "abcdefg");
        // Un morceau annoncé plus long que ce qui est là : ce qui précède, sans paniquer.
        let r = lire_reponse(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\nffffffffffffffff\r\nx")
            .unwrap();
        assert_eq!(r.texte(), "ab");
        assert_eq!(lire_reponse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"), None);
        assert_eq!(lire_reponse(b"pas du http\r\n\r\n"), None);
        assert!(complete(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nok"));
        assert!(!complete(b"HTTP/1.1 200 OK\r\n\r\nsans longueur"));
    }

    /// La vraie demande, contre un faux serveur sur cet ordinateur : rien ne sort sur le réseau.
    #[test]
    fn demande_contre_un_faux_serveur() {
        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = ecoute.local_addr().unwrap().port();
        let serveur = std::thread::spawn(move || {
            let (mut c, _) = ecoute.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut brut = Vec::new();
            let mut tampon = [0u8; 4096];
            // La demande entière, même arrivée en plusieurs morceaux : jusqu'au corps annoncé (4 octets).
            while let Ok(n @ 1..) = c.read(&mut tampon) {
                brut.extend_from_slice(&tampon[..n]);
                if fin_entetes(&brut).is_some_and(|debut| brut.len() >= debut + 4) {
                    break;
                }
            }
            // La connexion reste ouverte exprès : la réponse par morceaux doit suffire à finir la lecture.
            c.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n<a/\r\n1\r\n>\r\n0\r\n\r\n")
                .unwrap();
            // Gardée ouverte bien plus longtemps que la borne ci-dessous : une machine chargée (Wine, tests en parallèle)
            // ne fait pas passer un client qui attendrait la fermeture.
            std::thread::sleep(Duration::from_millis(1500));
            String::from_utf8_lossy(&brut).into_owned()
        });
        let debut = Instant::now();
        let r = demander(
            "POST",
            &format!("http://127.0.0.1:{port}/ctl"),
            &[("SOAPAction", "\"x#y\"")],
            Some(b"<q/>"),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!((r.code, r.texte().as_str()), (200, "<a/>"));
        assert!(debut.elapsed() < Duration::from_millis(1000), "{:?}", debut.elapsed());
        let demande = serveur.join().unwrap();
        assert!(
            demande.starts_with(&format!("POST /ctl HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n")),
            "{demande}"
        );
        assert!(demande.contains("\r\nSOAPAction: \"x#y\"\r\n") && demande.contains("\r\nContent-Length: 4\r\n"));
        assert!(demande.contains("\r\nConnection: close\r\n") && demande.ends_with("\r\n\r\n<q/>"));
        // Personne n'écoute : pas de réponse, sans attendre l'instant limite (30 s ici). Linux répond au refus tout de
        // suite ; Windows, lui, renvoie sa demande de connexion deux fois après le refus, une demi-seconde puis une
        // seconde plus tard, avant de conclure (environ 2 s, vu sur le Windows de la CI) : la borne en tient compte,
        // et reste loin de l'instant limite, ce que le test doit prouver.
        let libre = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = libre.local_addr().unwrap().port();
        drop(libre);
        let debut = Instant::now();
        let url = format!("http://127.0.0.1:{port}/");
        assert_eq!(
            demander("GET", &url, &[], None, Instant::now() + Duration::from_secs(30)),
            None
        );
        let borne = Duration::from_secs(if cfg!(windows) { 6 } else { 2 });
        assert!(debut.elapsed() < borne, "{:?}", debut.elapsed());
        // Un instant limite déjà passé : rien n'est envoyé.
        assert_eq!(demander("GET", &url, &[], None, Instant::now()), None);
    }
}

/// Ce qu'un appareil du réseau local peut répondre de pire : jamais de panique, un corps jamais plus long que ce qui
/// est arrivé, et une adresse acceptée qui reste locale.
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    /// Une réponse HTTP brute : ligne d'état, en-têtes (longueurs énormes ou fausses, « chunked »), puis des
    /// morceaux annoncés en hexadécimal (tailles démesurées comprises), des fins de morceau, des octets quelconques
    /// et du texte UTF-8 multi-octets. Ou rien que des octets quelconques.
    fn reponse() -> impl Strategy<Value = Vec<u8>> {
        let etat = prop_oneof![
            Just("HTTP/1.1 200 OK".to_string()),
            Just("HTTP/1.0 500 Internal Server Error".to_string()),
            "(HTTP|http|HtTp)/1\\.[0-9é] [0-9]{0,7}[ -~é]{0,10}",
            any::<String>(),
        ];
        let entete = prop_oneof![
            "Content-Length: ?[0-9]{0,25}",
            "content-length:[ -~é]{0,10}",
            Just("Transfer-Encoding: chunked".to_string()),
            "[ -~é😀]{0,30}",
            any::<String>(),
        ];
        let morceau = prop_oneof![
            "[0-9a-fA-F]{1,20}(;[ -~é]{0,5})?\r\n".prop_map(String::into_bytes),
            Just(b"\r\n".to_vec()),
            Just(b"0\r\n\r\n".to_vec()),
            prop::collection::vec(any::<u8>(), 0..40),
            any::<String>().prop_map(String::into_bytes),
        ];
        let construite = (
            etat,
            prop::collection::vec(entete, 0..6),
            prop::collection::vec(morceau, 0..12),
        )
            .prop_map(|(etat, entetes, corps)| {
                let mut brut = format!("{etat}\r\n{}\r\n\r\n", entetes.join("\r\n")).into_bytes();
                brut.extend(corps.concat());
                brut
            });
        prop_oneof![construite, prop::collection::vec(any::<u8>(), 0..300)]
    }

    /// Une adresse d'appareil : http:// suivi de n'importe quoi, d'une adresse IPv4 (locale ou non) avec un port
    /// quelconque, puis d'un chemin quelconque.
    fn url() -> impl Strategy<Value = String> {
        let hote = prop_oneof![
            Just("10.0.0.1".to_string()),
            Just("192.168.1.1".to_string()),
            Just("8.8.8.8".to_string()),
            "[0-9.]{0,16}",
            any::<String>(),
        ];
        let port = prop_oneof![
            Just(String::new()),
            ":[0-9]{0,7}",
            any::<String>().prop_map(|p| format!(":{p}"))
        ];
        (hote, port, any::<String>(), "[ -~é\r\n\t]{0,20}").prop_map(|(h, p, c, d)| format!("http://{h}{p}/{c}{d}"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn reponses_brutes(brut in reponse()) {
            let _ = complete(&brut);
            if let Some(r) = lire_reponse(&brut) {
                prop_assert!(r.corps.len() <= brut.len());
                let _ = r.texte();
            }
            prop_assert!(recoller(&brut).len() <= brut.len());
        }

        /// Des morceaux bien annoncés se recollent exactement, quels que soient leurs octets.
        #[test]
        fn morceaux_recolles(morceaux in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..50), 0..8)) {
            let mut corps = Vec::new();
            for m in &morceaux {
                corps.extend(format!("{:x}\r\n", m.len()).into_bytes());
                corps.extend(m);
                corps.extend(b"\r\n");
            }
            corps.extend(b"0\r\n\r\n");
            let mut brut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            brut.extend(&corps);
            prop_assert!(complete(&brut));
            prop_assert_eq!(lire_reponse(&brut).map(|r| r.corps), Some(morceaux.concat()));
        }

        #[test]
        fn adresses_d_appareil(u in prop_oneof![url(), any::<String>()], lien in any::<String>()) {
            if let Some(a) = Adresse::lire(&u) {
                prop_assert!(crate::reseau::nmap::locale(a.ip), "{u:?}");
                prop_assert!(a.chemin.starts_with('/'));
                prop_assert!(!a.chemin.chars().any(|c| c.is_ascii_control() || c == ' '), "{u:?}");
                let _ = a.resoudre(&lien);
            }
        }
    }
}
