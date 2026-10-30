//! Client DNS maison, en UDP, pour l'audit : une question (A, AAAA, TXT, SVCB, HTTPS) avec ou sans EDNS0 et le bit
//! DO (« j'accepte les signatures DNSSEC »), et la lecture de la réponse : code, drapeaux AD (réponse validée par le
//! résolveur), RA et TC, enregistrements. Tout vient du réseau, donc de n'importe qui : chaque lecture est bornée et
//! une réponse mal formée est simplement ignorée. Aucune bibliothèque DNS : le format tient en quelques dizaines de
//! lignes et Vanguard a besoin de voir les drapeaux, que les résolveurs du système cachent.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::reseau::nat::{hasard, recevoir};

/// Types de questions que l'audit pose.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Genre {
    A = 1,
    Svcb = 64,
    /// Seulement dans les essais (questions fabriquées) ; l'audit demande A et SVCB.
    #[cfg(test)]
    Https = 65,
}

/// Taille de réponse UDP annoncée dans EDNS0 : celle que recommandent les opérateurs de résolveurs (DNS flag day
/// 2020), qui passe sans fragmentation.
const TAILLE_EDNS: u16 = 1232;
/// Enregistrements lus au plus dans une réponse : au-delà, elle n'a rien d'une réponse à nos questions.
const ENREGISTREMENTS_MAX: usize = 64;
/// Délai d'une réponse ; deux envois par question (une réponse UDP peut se perdre).
const DELAI: Duration = Duration::from_millis(1500);
const ESSAIS: usize = 2;

/// Ce que porte un enregistrement, pour les types que l'audit lit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Donnees {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Txt(Vec<String>),
    /// SVCB ou HTTPS (RFC 9460) : priorité (0 = alias), cible, et les paramètres utiles à DDR.
    Svcb {
        priorite: u16,
        cible: String,
        alpn: Vec<String>,
        port: Option<u16>,
        dohpath: Option<String>,
        indices: Vec<IpAddr>,
    },
    /// Un type que l'audit ne lit pas (CNAME, RRSIG…) : son numéro.
    Autre(u16),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Enregistrement {
    pub nom: String,
    pub ttl: u32,
    pub donnees: Donnees,
}

/// Une réponse lue : les drapeaux qui comptent pour l'audit et les enregistrements de la section réponse.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reponse {
    /// 0 = réponse, 2 = panne du serveur (SERVFAIL : c'est ce qu'un résolveur validant répond pour une signature
    /// cassée), 3 = ce nom n'existe pas, 5 = refusé.
    pub rcode: u8,
    /// Réponse validée par DNSSEC (Authenticated Data).
    pub ad: bool,
    /// Le serveur fait la récursion (sinon ce n'est pas un résolveur).
    pub ra: bool,
    /// Tronquée : la réponse ne tenait pas (EDNS absent ou coupé en chemin).
    pub tc: bool,
    pub enregistrements: Vec<Enregistrement>,
}

impl Reponse {
    /// Les adresses IPv4 de la réponse.
    pub fn adresses_v4(&self) -> Vec<Ipv4Addr> {
        self.enregistrements
            .iter()
            .filter_map(|e| match e.donnees {
                Donnees::A(ip) => Some(ip),
                _ => None,
            })
            .collect()
    }

    /// Le nom a bien été résolu : une réponse sans panne ni refus, avec au moins un enregistrement.
    #[cfg(test)]
    pub fn resolu(&self) -> bool {
        self.rcode == 0 && !self.enregistrements.is_empty()
    }
}

/// Une question : identifiant, nom, type, récursion demandée ; avec `edns`, un enregistrement OPT (EDNS0) et, si
/// `dnssec`, le bit DO qui demande les signatures et autorise le drapeau AD. Un nom qui ne tient pas dans le format
/// (étiquette de plus de 63 octets) donne une question que tout serveur refuse : rien de grave.
pub fn question(id: u16, nom: &str, genre: Genre, edns: bool, dnssec: bool) -> Vec<u8> {
    let nombre_ar: u8 = u8::from(edns);
    let mut q = [&id.to_be_bytes()[..], &[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, nombre_ar]].concat();
    for etiquette in nom.trim_end_matches('.').split('.') {
        q.push(u8::try_from(etiquette.len()).unwrap_or(0));
        q.extend(etiquette.as_bytes());
    }
    q.push(0);
    q.extend((genre as u16).to_be_bytes());
    q.extend([0, 1]);
    if edns {
        // OPT : nom racine, type 41, « classe » = taille UDP acceptée, « TTL » = code étendu, version, drapeaux (DO).
        let drapeaux: u16 = if dnssec { 0x8000 } else { 0 };
        q.push(0);
        q.extend(41u16.to_be_bytes());
        q.extend(TAILLE_EDNS.to_be_bytes());
        q.extend([0, 0]);
        q.extend(drapeaux.to_be_bytes());
        q.extend([0, 0]);
    }
    q
}

fn u16_a(message: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*message.get(pos)?, *message.get(pos + 1)?]))
}

fn u32_a(message: &[u8], pos: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *message.get(pos)?,
        *message.get(pos + 1)?,
        *message.get(pos + 2)?,
        *message.get(pos + 3)?,
    ]))
}

/// Un nom à la position `pos` du message : étiquettes, avec les pointeurs de compression (bornés : seize sauts au
/// plus, un nom de 253 caractères au plus). Rend le nom et la position qui suit le nom dans le flux de départ.
fn nom(message: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut texte = String::new();
    let mut suite = None;
    let mut sauts = 0;
    loop {
        let &longueur = message.get(pos)?;
        match longueur {
            0 => {
                pos += 1;
                break;
            }
            l if l & 0xC0 == 0xC0 => {
                let &bas = message.get(pos + 1)?;
                if suite.is_none() {
                    suite = Some(pos + 2);
                }
                sauts += 1;
                if sauts > 16 {
                    return None;
                }
                pos = usize::from(l & 0x3F) << 8 | usize::from(bas);
            }
            // Étiquettes étendues (0x40, 0x80) : jamais vues en pratique, pas lues.
            l if l & 0xC0 != 0 => return None,
            l => {
                let l = usize::from(l);
                let etiquette = message.get(pos + 1..pos + 1 + l)?;
                if !texte.is_empty() {
                    texte.push('.');
                }
                texte.push_str(&String::from_utf8_lossy(etiquette));
                if texte.len() > 253 {
                    return None;
                }
                pos += 1 + l;
            }
        }
    }
    Some((texte, suite.unwrap_or(pos)))
}

/// Une suite de chaînes de caractères DNS (un octet de longueur, puis le texte) : TXT et la liste alpn de SVCB.
fn chaines(mut octets: &[u8]) -> Vec<String> {
    let mut liste = Vec::new();
    while let Some((&l, reste)) = octets.split_first() {
        let l = usize::from(l);
        let Some((texte, suite)) = reste.split_at_checked(l) else {
            break;
        };
        liste.push(String::from_utf8_lossy(texte).into_owned());
        octets = suite;
        if liste.len() >= 32 {
            break;
        }
    }
    liste
}

/// Les données d'un SVCB ou HTTPS : priorité, cible, puis les paramètres (clé, longueur, valeur) : 1 = alpn,
/// 3 = port, 4 et 6 = adresses, 7 = chemin DoH.
fn svcb(message: &[u8], debut: usize, fin: usize) -> Option<Donnees> {
    let priorite = u16_a(message, debut)?;
    let (cible, mut pos) = nom(message, debut + 2)?;
    let (mut alpn, mut port, mut dohpath, mut indices) = (Vec::new(), None, None, Vec::new());
    while pos + 4 <= fin {
        let cle = u16_a(message, pos)?;
        let longueur = usize::from(u16_a(message, pos + 2)?);
        let valeur = message.get(pos + 4..pos + 4 + longueur)?;
        if pos + 4 + longueur > fin {
            return None;
        }
        match cle {
            1 => alpn = chaines(valeur),
            3 => port = u16_a(valeur, 0),
            4 => indices.extend(valeur.as_chunks::<4>().0.iter().map(|o| IpAddr::from(*o))),
            6 => indices.extend(valeur.as_chunks::<16>().0.iter().map(|o| IpAddr::from(*o))),
            7 => dohpath = Some(String::from_utf8_lossy(valeur).into_owned()),
            _ => {}
        }
        pos += 4 + longueur;
    }
    Some(Donnees::Svcb {
        priorite,
        cible,
        alpn,
        port,
        dohpath,
        indices,
    })
}

/// L'enregistrement à la position `pos`, et la position qui le suit.
fn enregistrement(message: &[u8], pos: usize) -> Option<(Enregistrement, usize)> {
    let (nom, apres) = nom(message, pos)?;
    let genre = u16_a(message, apres)?;
    let ttl = u32_a(message, apres + 4)?;
    let longueur = usize::from(u16_a(message, apres + 8)?);
    let debut = apres + 10;
    let fin = debut + longueur;
    let rdata = message.get(debut..fin)?;
    let donnees = match (genre, rdata) {
        (1, &[a, b, c, d]) => Donnees::A(Ipv4Addr::new(a, b, c, d)),
        (28, o) if o.len() == 16 => Donnees::Aaaa(Ipv6Addr::from(<[u8; 16]>::try_from(o).ok()?)),
        (16, o) => Donnees::Txt(chaines(o)),
        (64 | 65, _) => svcb(message, debut, fin)?,
        (autre, _) => Donnees::Autre(autre),
    };
    Some((Enregistrement { nom, ttl, donnees }, fin))
}

/// Lit une réponse à la question `id` : rien si ce n'en est pas une (autre identifiant, question, forme inconnue).
/// Les questions sont passées, la section réponse est lue en entier (bornée), le reste n'est pas lu.
pub fn lire(message: &[u8], id: u16) -> Option<Reponse> {
    if message.len() < 12 || message.first_chunk::<2>() != Some(&id.to_be_bytes()) {
        return None;
    }
    let drapeaux = u16_a(message, 2)?;
    if drapeaux & 0x8000 == 0 {
        return None;
    }
    let questions = usize::from(u16_a(message, 4)?);
    let reponses = usize::from(u16_a(message, 6)?).min(ENREGISTREMENTS_MAX);
    let mut pos = 12;
    for _ in 0..questions.min(4) {
        pos = nom(message, pos)?.1 + 4;
    }
    let mut enregistrements = Vec::new();
    for _ in 0..reponses {
        // Une réponse tronquée peut s'arrêter au milieu de la section : on garde ce qui est entier.
        let Some((e, suite)) = enregistrement(message, pos) else {
            break;
        };
        enregistrements.push(e);
        pos = suite;
    }
    Some(Reponse {
        rcode: u8::try_from(drapeaux & 0x0F).unwrap_or(15),
        ad: drapeaux & 0x0020 != 0,
        ra: drapeaux & 0x0080 != 0,
        tc: drapeaux & 0x0200 != 0,
        enregistrements,
    })
}

/// Pose la question à `serveur` (port 53, UDP) et rend sa réponse, ou rien passé le délai (deux envois). Avec
/// `edns`, EDNS0 est annoncé ; avec `dnssec`, le bit DO en plus. Une adresse IPv6 de lien local n'est pas
/// interrogeable sans le nom de sa carte : rien.
pub fn interroger(serveur: IpAddr, nom: &str, genre: Genre, edns: bool, dnssec: bool) -> Option<Reponse> {
    if let IpAddr::V6(v6) = serveur
        && (v6.segments()[0] & 0xffc0) == 0xfe80
    {
        return None;
    }
    let socket = UdpSocket::bind(if serveur.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    socket.connect(SocketAddr::new(serveur, 53)).ok()?;
    let id = u16::try_from(hasard() & 0xffff).unwrap_or(0);
    let q = question(id, nom, genre, edns, dnssec);
    let mut tampon = [0u8; 4096];
    for _ in 0..ESSAIS {
        socket.send(&q).ok()?;
        let fin = Instant::now() + DELAI;
        let lire_la_notre = |r: &[u8], _: SocketAddr| lire(r, id);
        if let Some(reponse) = recevoir(&socket, fin, &mut tampon, lire_la_notre) {
            return Some(reponse);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une réponse forgée à la question `id` : les drapeaux donnés, la question reprise, puis `reponses` (octets
    /// d'enregistrements, déjà en forme de fil).
    fn reponse(id: u16, drapeaux: u16, question: &[u8], reponses: &[&[u8]]) -> Vec<u8> {
        let mut r = id.to_be_bytes().to_vec();
        r.extend(drapeaux.to_be_bytes());
        r.extend([0, 1]);
        r.extend(u16::try_from(reponses.len()).unwrap().to_be_bytes());
        r.extend([0, 0, 0, 0]);
        r.extend(question);
        for e in reponses {
            r.extend(*e);
        }
        r
    }

    /// Un enregistrement en forme de fil : nom (ou pointeur), type, classe IN, TTL, données.
    fn rr(nom: &[u8], genre: u16, ttl: u32, donnees: &[u8]) -> Vec<u8> {
        let mut e = nom.to_vec();
        e.extend(genre.to_be_bytes());
        e.extend([0, 1]);
        e.extend(ttl.to_be_bytes());
        e.extend(u16::try_from(donnees.len()).unwrap().to_be_bytes());
        e.extend(donnees);
        e
    }

    const QUESTION_A: &[u8] = b"\x03dns\x06google\x00\x00\x01\x00\x01";
    /// Pointeur vers le nom de la question (position 12).
    const POINTEUR: &[u8] = &[0xC0, 0x0C];

    #[test]
    fn question_avec_et_sans_edns() {
        let simple = question(0x1234, "dns.google.", Genre::A, false, false);
        assert_eq!(&simple[..12], &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&simple[12..], QUESTION_A);
        let edns = question(0x1234, "dns.google", Genre::Svcb, true, true);
        assert_eq!(edns[11], 1, "un enregistrement additionnel : OPT");
        assert_eq!(&edns[12..28], b"\x03dns\x06google\x00\x00\x40\x00\x01");
        // OPT : racine, type 41, 1232 octets, code et version 0, bit DO, pas de données.
        assert_eq!(&edns[28..], &[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
        let sans_do = question(1, "a", Genre::A, true, false);
        assert_eq!(&sans_do[sans_do.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn reponse_a_avec_drapeaux() {
        let a = rr(POINTEUR, 1, 300, &[8, 8, 8, 8]);
        let b = rr(POINTEUR, 1, 300, &[8, 8, 4, 4]);
        // Réponse, récursion disponible, AD.
        let r = reponse(7, 0x81A0, QUESTION_A, &[&a, &b]);
        let lue = lire(&r, 7).unwrap();
        assert!(lue.ad && lue.ra && !lue.tc && lue.rcode == 0);
        assert_eq!(
            lue.adresses_v4(),
            [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]
        );
        assert_eq!(lue.enregistrements[0].nom, "dns.google");
        assert_eq!(lue.enregistrements[0].ttl, 300);
        assert!(lue.resolu());
        // Autre identifiant, ou une question : pas notre réponse.
        assert!(lire(&r, 8).is_none());
        assert!(lire(&question(7, "dns.google", Genre::A, false, false), 7).is_none());
        // SERVFAIL et NXDOMAIN se lisent, sans enregistrement.
        let panne = lire(&reponse(7, 0x8182, QUESTION_A, &[]), 7).unwrap();
        assert_eq!((panne.rcode, panne.ad, panne.resolu()), (2, false, false));
        let inexistant = lire(&reponse(7, 0x8183, QUESTION_A, &[]), 7).unwrap();
        assert_eq!(inexistant.rcode, 3);
        // Tronquée.
        assert!(lire(&reponse(7, 0x8380, QUESTION_A, &[]), 7).unwrap().tc);
    }

    #[test]
    fn reponses_aaaa_txt_et_autres() {
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 0x88;
        let aaaa = rr(POINTEUR, 28, 60, &v6);
        let txt = rr(POINTEUR, 16, 60, b"\x05hello\x02v=");
        let cname = rr(POINTEUR, 5, 60, b"\x03www\xC0\x0C");
        let r = reponse(1, 0x8180, QUESTION_A, &[&aaaa, &txt, &cname]);
        let lue = lire(&r, 1).unwrap();
        assert_eq!(
            lue.enregistrements[0].donnees,
            Donnees::Aaaa("2001::88".parse().unwrap())
        );
        assert_eq!(
            lue.enregistrements[1].donnees,
            Donnees::Txt(vec!["hello".into(), "v=".into()])
        );
        assert_eq!(lue.enregistrements[2].donnees, Donnees::Autre(5));
        assert_eq!(lue.adresses_v4(), Vec::<Ipv4Addr>::new());
    }

    #[test]
    fn reponse_svcb_de_ddr() {
        // _dns.resolver.arpa SVCB : priorité 1, cible dns.exemple.invalid, alpn dot+h2, port 853, dohpath, ipv4hint.
        let question = b"\x04_dns\x08resolver\x04arpa\x00\x00\x40\x00\x01";
        let mut donnees = vec![0, 1];
        donnees.extend(b"\x03dns\x07exemple\x07invalid\x00");
        donnees.extend([0, 1, 0, 7, 3, b'd', b'o', b't', 2, b'h', b'2']);
        donnees.extend([0, 3, 0, 2, 0x03, 0x55]);
        let longueur_du_chemin = donnees.len() + 3;
        donnees.extend([0, 7, 0, 10]);
        donnees.extend(b"/dns-query");
        donnees.extend([0, 4, 0, 4, 203, 0, 113, 53]);
        let svcb = rr(POINTEUR, 64, 3600, &donnees);
        let lue = lire(&reponse(2, 0x8180, question, &[&svcb]), 2).unwrap();
        assert_eq!(
            lue.enregistrements[0].donnees,
            Donnees::Svcb {
                priorite: 1,
                cible: "dns.exemple.invalid".into(),
                alpn: vec!["dot".into(), "h2".into()],
                port: Some(853),
                dohpath: Some("/dns-query".into()),
                indices: vec!["203.0.113.53".parse().unwrap()],
            }
        );
        // Longueur de paramètre qui déborde : l'enregistrement est ignoré, sans plantage.
        donnees[longueur_du_chemin] = 200;
        let faux = rr(POINTEUR, 64, 3600, &donnees);
        let lue = lire(&reponse(2, 0x8180, question, &[&faux]), 2).unwrap();
        assert_eq!(lue.enregistrements, Vec::<Enregistrement>::new());
    }

    /// Réponses piégées : pointeurs qui bouclent, nom sans fin, longueurs qui dépassent, compte d'enregistrements
    /// énorme : jamais de plantage, jamais une lecture hors du message.
    #[test]
    fn reponses_piegees() {
        let boucle = rr(&[0xC0, 0x0C], 1, 1, &[1, 2, 3, 4]);
        let mut r = reponse(3, 0x8180, b"\xC0\x0C\x00\x01\x00\x01", &[&boucle]);
        assert!(lire(&r, 3).is_none(), "la question pointe sur elle-même");
        r = reponse(3, 0x8180, QUESTION_A, &[&rr(&[0xC0, 0x1C], 1, 1, &[1, 2, 3, 4])]);
        let lue = lire(&r, 3).unwrap();
        assert_eq!(
            lue.enregistrements,
            Vec::<Enregistrement>::new(),
            "pointeur vers l'enregistrement lui-même"
        );
        // Compte annoncé de 65 535 réponses pour deux présentes : deux lues.
        let a = rr(POINTEUR, 1, 1, &[1, 1, 1, 1]);
        let mut r = reponse(3, 0x8180, QUESTION_A, &[&a, &a]);
        r[6] = 0xFF;
        r[7] = 0xFF;
        assert_eq!(lire(&r, 3).unwrap().enregistrements.len(), 2);
        // Longueur de données qui dépasse : l'enregistrement s'arrête là.
        let mut long = rr(POINTEUR, 1, 1, &[1, 1, 1, 1]);
        long[10] = 0xFF;
        assert_eq!(
            lire(&reponse(3, 0x8180, QUESTION_A, &[&long]), 3)
                .unwrap()
                .enregistrements,
            Vec::<Enregistrement>::new()
        );
        // Étiquette de 64 octets (étendue), nom trop long : rien.
        let mut etiquette = vec![0x40];
        etiquette.extend([b'a'; 64]);
        etiquette.push(0);
        assert!(nom(&etiquette, 0).is_none());
        let mut trop_long = Vec::new();
        for _ in 0..5 {
            trop_long.push(63);
            trop_long.extend([b'a'; 63]);
        }
        trop_long.push(0);
        assert!(nom(&trop_long, 0).is_none());
        assert!(lire(&[0, 3, 0x80], 3).is_none());
        for n in 0..40 {
            let _ = lire(&r[..n], 3);
        }
    }

    #[test]
    fn noms_et_chaines() {
        let m = b"\x07exemple\x07invalid\x00\x03www\xC0\x00";
        assert_eq!(nom(m, 0).unwrap(), ("exemple.invalid".into(), 17));
        assert_eq!(nom(m, 17).unwrap(), ("www.exemple.invalid".into(), 23));
        assert_eq!(nom(b"\x00", 0).unwrap(), (String::new(), 1));
        assert_eq!(chaines(b"\x02ab\x00\x05abc"), ["ab", ""]);
        assert_eq!(chaines(b""), Vec::<String>::new());
    }

    /// La vraie interrogation : hors ligne (unshare -rn, VANGUARD_HORS_LIGNE) ou vers un port fermé, rien, vite ;
    /// une adresse de lien local n'est jamais interrogée.
    #[test]
    fn interrogation_bornee() {
        let debut = Instant::now();
        assert!(interroger("fe80::1".parse().unwrap(), "dns.google", Genre::A, true, true).is_none());
        // Un serveur local muet : un port UDP que personne n'écoute répond par ICMP (refus immédiat) ou se tait.
        let _ = interroger(IpAddr::V4(Ipv4Addr::LOCALHOST), "dns.google", Genre::A, true, true);
        assert!(debut.elapsed() < Duration::from_secs(8), "{:?}", debut.elapsed());
    }
}

/// Ce que n'importe quel serveur (ou un paquet forgé qui se fait passer pour sa réponse) peut envoyer : jamais de
/// panique, une lecture bornée (enregistrements, noms, chaînes).
#[cfg(test)]
mod entrees_hostiles {
    use super::*;
    use proptest::prelude::*;

    const ID: u16 = 0x1234;

    /// Un nom en forme de fil : étiquettes (longueur vraie ou mensongère, octets quelconques), pointeurs de
    /// compression vers n'importe où (y compris vers eux-mêmes), étiquettes étendues, fin ou pas de fin.
    fn nom_brut() -> impl Strategy<Value = Vec<u8>> {
        let morceau = prop_oneof![
            prop::collection::vec(any::<u8>(), 0..70).prop_map(|e| {
                let mut m = vec![u8::try_from(e.len()).unwrap_or(63) & 0x3F];
                m.extend(e);
                m
            }),
            "[a-zé😀]{1,20}".prop_map(|e| {
                let mut m = vec![u8::try_from(e.len()).unwrap_or(63) & 0x3F];
                m.extend(e.into_bytes());
                m
            }),
            (any::<u8>(), any::<u8>()).prop_map(|(h, b)| vec![0xC0 | h, b]),
            Just(vec![0xC0, 0x0C]),
            any::<u8>().prop_map(|o| vec![o]),
        ];
        (prop::collection::vec(morceau, 0..6), any::<bool>()).prop_map(|(m, fin)| {
            let mut n = m.concat();
            if fin {
                n.push(0);
            }
            n
        })
    }

    /// Les données d'un enregistrement : octets quelconques, chaînes TXT, ou un SVCB (priorité, cible, paramètres
    /// alpn, port, adresses, chemin DoH, de longueurs vraies ou fausses).
    fn donnees() -> impl Strategy<Value = Vec<u8>> {
        let parametre = (
            prop::sample::select(vec![1u16, 3, 4, 6, 7, 0, 65535]),
            prop::collection::vec(any::<u8>(), 0..40),
            any::<bool>(),
        )
            .prop_map(|(cle, valeur, ment)| {
                let mut p = cle.to_be_bytes().to_vec();
                let longueur = if ment {
                    u16::MAX
                } else {
                    u16::try_from(valeur.len()).unwrap_or(0)
                };
                p.extend(longueur.to_be_bytes());
                p.extend(valeur);
                p
            });
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..60),
            prop::collection::vec(any::<String>(), 0..40).prop_map(|t| t
                .iter()
                .flat_map(|c| {
                    let c = c.as_bytes();
                    let mut m = vec![u8::try_from(c.len()).unwrap_or(255)];
                    m.extend(c);
                    m
                })
                .collect()),
            (
                any::<u16>(),
                souvent(Just(vec![0]), nom_brut()),
                prop::collection::vec(parametre, 0..6)
            )
                .prop_map(|(priorite, cible, params)| {
                    let mut d = priorite.to_be_bytes().to_vec();
                    d.extend(cible);
                    d.extend(params.concat());
                    d
                }),
        ]
    }

    /// Le plus souvent vrai, parfois quelconque : pour aller loin dans la lecture avant d'y tomber.
    fn souvent<T: std::fmt::Debug + Clone + 'static>(
        vrai: impl Strategy<Value = T> + 'static,
        quelconque: impl Strategy<Value = T> + 'static,
    ) -> BoxedStrategy<T> {
        prop_oneof![3 => vrai, 1 => quelconque].boxed()
    }

    /// Un enregistrement : nom, type (lus ou non), classe, TTL, longueur annoncée (vraie ou fausse), données.
    fn enregistrement_brut() -> impl Strategy<Value = Vec<u8>> {
        (
            souvent(Just(vec![0xC0, 0x0C]), nom_brut()),
            prop::sample::select(vec![1u16, 28, 16, 64, 65, 5, 46, 41]),
            any::<u32>(),
            donnees(),
            souvent(Just(None), any::<u16>().prop_map(Some)),
        )
            .prop_map(|(nom, genre, ttl, d, longueur)| {
                let mut e = nom;
                e.extend(genre.to_be_bytes());
                e.extend([0, 1]);
                e.extend(ttl.to_be_bytes());
                e.extend(longueur.unwrap_or(u16::try_from(d.len()).unwrap_or(0)).to_be_bytes());
                e.extend(d);
                e
            })
    }

    /// Une réponse à la question `ID` : drapeaux quelconques (bit de réponse posé), nombres de questions et de
    /// réponses quelconques, une question, des enregistrements, puis quelques octets changés et une coupe.
    fn message() -> impl Strategy<Value = Vec<u8>> {
        (
            any::<u16>(),
            souvent(Just(1u16), 0u16..8),
            souvent(Just(None), any::<u16>().prop_map(Some)),
            souvent(Just(b"\x03dns\x06google\x00".to_vec()), nom_brut()),
            prop::collection::vec(enregistrement_brut(), 0..10),
            souvent(
                Just(Vec::new()),
                prop::collection::vec((any::<usize>(), any::<u8>()), 1..4),
            ),
            souvent(Just(None), any::<usize>().prop_map(Some)),
        )
            .prop_map(|(drapeaux, questions, reponses, q, enregistrements, changes, coupe)| {
                let mut m = ID.to_be_bytes().to_vec();
                m.extend((drapeaux | 0x8000).to_be_bytes());
                m.extend(questions.to_be_bytes());
                let nombre = reponses.unwrap_or(u16::try_from(enregistrements.len()).unwrap_or(0));
                m.extend(nombre.to_be_bytes());
                m.extend([0, 0, 0, 0]);
                m.extend(q);
                m.extend([0, 1, 0, 1]);
                m.extend(enregistrements.concat());
                let n = m.len();
                for (i, o) in changes {
                    m[i % n] = o;
                }
                if let Some(coupe) = coupe {
                    m.truncate(12 + coupe % (n - 11));
                }
                m
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 1024, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn reponses_forgees(m in prop_oneof![message(), prop::collection::vec(any::<u8>(), 0..200)]) {
            let Some(r) = lire(&m, ID) else { return Ok(()) };
            prop_assert!(r.enregistrements.len() <= ENREGISTREMENTS_MAX);
            for e in &r.enregistrements {
                prop_assert!(e.nom.len() <= 253);
                match &e.donnees {
                    Donnees::Txt(t) => prop_assert!(t.len() <= 32),
                    Donnees::Svcb { cible, alpn, .. } => prop_assert!(cible.len() <= 253 && alpn.len() <= 32),
                    _ => {}
                }
            }
            let _ = (r.adresses_v4(), r.resolu());
        }

        /// Une question n'est jamais lue comme une réponse, quel que soit le nom demandé.
        #[test]
        fn questions(nom in any::<String>(), edns: bool, dnssec: bool) {
            let q = question(ID, &nom, Genre::Https, edns, dnssec);
            prop_assert_eq!(lire(&q, ID), None);
        }

        /// Des réponses A bien formées : chaque adresse est lue, dans l'ordre.
        #[test]
        fn adresses_lues(adresses in prop::collection::vec(any::<[u8; 4]>(), 0..ENREGISTREMENTS_MAX)) {
            let mut m = ID.to_be_bytes().to_vec();
            m.extend([0x81, 0x80, 0, 1]);
            m.extend(u16::try_from(adresses.len()).unwrap().to_be_bytes());
            m.extend([0, 0, 0, 0]);
            m.extend(b"\x03dns\x06google\x00\x00\x01\x00\x01");
            for a in &adresses {
                m.extend([0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
                m.extend(a);
            }
            let lues = lire(&m, ID).map(|r| r.adresses_v4());
            prop_assert_eq!(lues, Some(adresses.into_iter().map(Ipv4Addr::from).collect::<Vec<_>>()));
        }
    }
}
