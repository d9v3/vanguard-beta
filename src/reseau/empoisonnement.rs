//! Empoisonneur de noms sur le réseau local : repère un outil comme Responder. Un tel outil répond à toutes les
//! demandes de noms LLMNR, NetBIOS (NBT-NS) et mDNS du réseau pour se faire passer pour n'importe quel serveur et
//! voler les mots de passe des ordinateurs Windows qui s'y connectent. Personne de légitime ne répond pour un nom qui
//! n'existe pas : Vanguard demande des noms tirés au hasard, et tout appareil qui prétend les résoudre est démasqué.
//!
//! Rien d'Internet : tout se passe sur le réseau local (multicast LLMNR/mDNS, diffusion NetBIOS). Sans réseau local,
//! la sonde s'arrête aussitôt. Lecture seule : rien n'est coupé ni bloqué.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use serde::Serialize;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

use crate::ui::affichable;

/// Groupes multicast et ports des trois protocoles de résolution de noms sur le réseau local.
const LLMNR: &str = "224.0.0.252:5355";
const MDNS: &str = "224.0.0.251:5353";
const PORT_NETBIOS: u16 = 137;

/// Délai d'attente des réponses à un faux nom (ms) : une réponse arrive en quelques millisecondes ; au-delà, personne.
const DELAI: Duration = Duration::from_millis(1500);

/// Un appareil qui répond à des noms qui n'existent pas : un empoisonneur probable.
#[derive(Serialize, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Empoisonneur {
    pub ip: Ipv4Addr,
    /// Protocoles par lesquels il a répondu (« LLMNR », « NetBIOS », « mDNS »).
    pub protocoles: Vec<&'static str>,
}

/// Ce que la sonde a trouvé.
#[derive(Serialize, Debug, PartialEq)]
pub enum Rapport {
    /// Testé : personne, ou la liste des empoisonneurs démasqués.
    Teste(Vec<Empoisonneur>),
    /// Pas de réseau local (VPN seul, aucun réseau) : rien n'a pu être testé, jamais compté comme sain.
    SansReseauLocal,
}

// ───────────────────────────── Construction des requêtes ─────────────────────────────

/// Un nom tiré au hasard et inexistant : « vg » suivi de 12 caractères hexadécimaux. Deux essais, deux noms : un
/// appareil qui répond aux deux n'a pas répondu par hasard.
fn nom_aleatoire() -> String {
    let mut octets = [0u8; 6];
    // Le hasard sert seulement à choisir un nom qui n'existe pas : une source dégradée ne compromet rien.
    let _ = getrandom::fill(&mut octets);
    let mut nom = String::from("vg");
    for o in octets {
        let _ = write!(nom, "{o:02x}");
    }
    nom
}

/// En-tête commun à LLMNR et mDNS (format DNS) : identifiant, drapeaux de requête, une seule question.
fn entete(id: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(12);
    p.extend(id.to_be_bytes());
    p.extend([0x00, 0x00]); // requête standard (QR=0, opcode 0)
    p.extend([0x00, 0x01]); // une question
    p.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // aucune réponse, autorité, additionnel
    p
}

/// Encode un nom en étiquettes DNS (« vg… » → `04 … 00`, « vg….local » → `… 05 local 00`).
fn etiquettes(nom: &str) -> Vec<u8> {
    let mut p = Vec::new();
    for etiquette in nom.split('.') {
        p.push(u8::try_from(etiquette.len()).unwrap_or(0));
        p.extend(etiquette.as_bytes());
    }
    p.push(0);
    p
}

/// Requête LLMNR (RFC 4795) pour un nom en type A, classe IN.
fn requete_llmnr(id: u16, nom: &str) -> Vec<u8> {
    let mut p = entete(id);
    p.extend(etiquettes(nom));
    p.extend([0x00, 0x01, 0x00, 0x01]); // type A, classe IN
    p
}

/// Requête mDNS (RFC 6762) pour « `<nom>.local` », type A : le bit de poids fort de la classe demande une réponse en
/// unicast (QU), qui revient sur notre port au lieu d'être diffusée.
fn requete_mdns(id: u16, nom: &str) -> Vec<u8> {
    let mut p = entete(id);
    p.extend(etiquettes(&format!("{nom}.local")));
    p.extend([0x00, 0x01, 0x80, 0x01]); // type A, classe IN + réponse en unicast
    p
}

/// Un nom NetBIOS de 16 octets : 15 caractères (majuscules, complétés par des espaces) et le suffixe 0x00 (poste de
/// travail).
fn nom_netbios(nom: &str) -> [u8; 16] {
    let mut brut = [b' '; 16];
    for (i, c) in nom.chars().take(15).enumerate() {
        brut[i] = u8::try_from(c.to_ascii_uppercase() as u32).unwrap_or(b' ');
    }
    brut[15] = 0x00;
    brut
}

/// « First-level encoding » (RFC 1002) : chaque octet du nom devient deux lettres (nibble + 'A').
fn encoder_netbios(brut: &[u8; 16]) -> Vec<u8> {
    let mut p = Vec::with_capacity(32);
    for &o in brut {
        p.push(b'A' + (o >> 4));
        p.push(b'A' + (o & 0x0f));
    }
    p
}

/// Décode un nom NetBIOS encodé (32 lettres) en ses 16 octets.
fn decoder_netbios(code: &[u8]) -> Option<[u8; 16]> {
    if code.len() != 32 {
        return None;
    }
    let mut brut = [0u8; 16];
    for (i, paire) in code.as_chunks::<2>().0.iter().enumerate() {
        let haut = paire[0].checked_sub(b'A')?;
        let bas = paire[1].checked_sub(b'A')?;
        if haut > 0x0f || bas > 0x0f {
            return None;
        }
        brut[i] = (haut << 4) | bas;
    }
    Some(brut)
}

/// Requête de nom NetBIOS (RFC 1002) : NB, en diffusion, pour un nom encodé en « first-level encoding ».
fn requete_netbios(id: u16, nom: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(id.to_be_bytes());
    p.extend([0x01, 0x10]); // requête de nom, récursion demandée, diffusion
    p.extend([0x00, 0x01]); // une question
    p.extend([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    let code = encoder_netbios(&nom_netbios(nom));
    p.push(0x20); // 32 octets de nom encodé
    p.extend(&code);
    p.push(0x00); // fin du nom
    p.extend([0x00, 0x20, 0x00, 0x01]); // type NB, classe IN
    p
}

// ───────────────────────────── Décodage des réponses ─────────────────────────────

/// Lit un u16 en gros-boutien à `offset`.
fn u16_be(p: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(offset)?, *p.get(offset + 1)?]))
}

/// Saute un nom DNS à partir de `debut` et rend l'offset qui le suit. Gère les pointeurs de compression (0xC0…), avec
/// une limite d'étapes pour ne jamais boucler sur un paquet piégé.
fn sauter_nom(p: &[u8], debut: usize) -> Option<usize> {
    let mut i = debut;
    for _ in 0..128 {
        let octet = *p.get(i)?;
        match octet & 0xc0 {
            // Pointeur de compression : deux octets, le nom se poursuit ailleurs mais la position d'origine s'arrête là.
            0xc0 => return Some(i + 2),
            0x00 if octet == 0 => return Some(i + 1),
            0x00 => i += 1 + octet as usize,
            _ => return None, // étiquette réservée (0x40, 0x80) : paquet mal formé.
        }
    }
    None
}

/// Lit un nom DNS à partir de `debut` en suivant les pointeurs de compression, et le rend en minuscules, prêt à
/// comparer. Jamais de boucle infinie (limite d'étapes), jamais de panique (tout est borné).
fn lire_nom(p: &[u8], debut: usize) -> Option<String> {
    let mut nom = String::new();
    let mut i = debut;
    for _ in 0..128 {
        let octet = *p.get(i)?;
        match octet & 0xc0 {
            0xc0 => {
                let cible = (usize::from(octet & 0x3f) << 8) | usize::from(*p.get(i + 1)?);
                // Un pointeur doit renvoyer en arrière : sinon il pourrait boucler.
                if cible >= i {
                    return None;
                }
                i = cible;
            }
            0x00 if octet == 0 => return Some(nom),
            0x00 => {
                let fin = i + 1 + octet as usize;
                let etiquette = p.get(i + 1..fin)?;
                if !nom.is_empty() {
                    nom.push('.');
                }
                nom.push_str(&String::from_utf8_lossy(etiquette).to_lowercase());
                i = fin;
            }
            _ => return None,
        }
    }
    None
}

/// Les réponses d'une requête DNS (LLMNR, mDNS) : la première adresse A annoncée pour `nom_attendu`. Un paquet qui ne
/// porte pas notre identifiant, ou qui ne répond pas pour notre nom, est ignoré. Jamais de panique sur un paquet piégé.
fn adresse_dns(p: &[u8], id_attendu: u16, nom_attendu: &str) -> Option<Ipv4Addr> {
    if u16_be(p, 0)? != id_attendu {
        return None;
    }
    let questions = u16_be(p, 4)?;
    let reponses = u16_be(p, 6)?;
    // Sauter les questions (nom + type + classe) pour atteindre les réponses.
    let mut i = 12;
    for _ in 0..questions {
        i = sauter_nom(p, i)?.checked_add(4)?;
    }
    for _ in 0..reponses {
        let nom = lire_nom(p, i)?;
        let apres = sauter_nom(p, i)?;
        let type_ = u16_be(p, apres)?;
        let longueur = usize::from(u16_be(p, apres + 8)?);
        let rdata = apres + 10;
        if type_ == 0x0001 && longueur == 4 && nom.eq_ignore_ascii_case(nom_attendu) {
            let a = p.get(rdata..rdata + 4)?;
            return Some(Ipv4Addr::new(a[0], a[1], a[2], a[3]));
        }
        i = rdata + longueur;
    }
    None
}

/// LLMNR : le nom demandé, sans suffixe.
fn adresse_llmnr(p: &[u8], id: u16, nom: &str) -> Option<Ipv4Addr> {
    adresse_dns(p, id, nom)
}

/// mDNS : le nom demandé porte le suffixe « .local ».
fn adresse_mdns(p: &[u8], id: u16, nom: &str) -> Option<Ipv4Addr> {
    adresse_dns(p, id, &format!("{nom}.local"))
}

/// Une réponse NetBIOS positive pour notre nom : la première adresse de sa réponse. Vérifie l'identifiant et le nom
/// encodé renvoyés ; ignore tout le reste. Jamais de panique.
fn adresse_netbios(p: &[u8], id: u16, nom: &str) -> Option<Ipv4Addr> {
    if u16_be(p, 0)? != id {
        return None;
    }
    if u16_be(p, 6)? == 0 {
        return None; // aucune réponse
    }
    // Réponse : longueur du nom (0x20), 32 lettres, fin (0x00), type NB, classe, TTL (4), longueur, puis les adresses.
    let i = 12;
    if *p.get(i)? != 0x20 {
        return None;
    }
    let code = p.get(i + 1..i + 33)?;
    let attendu = nom_netbios(nom);
    if decoder_netbios(code) != Some(attendu) {
        return None;
    }
    let apres = i + 34; // 0x20 + 32 + 0x00
    let type_ = u16_be(p, apres)?;
    if type_ != 0x0020 {
        return None;
    }
    // type (2) + classe (2) + TTL (4) + longueur (2) = 10 ; chaque adresse : drapeaux (2) + IP (4).
    let a = p.get(apres + 12..apres + 16)?;
    Some(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
}

// ───────────────────────────── Sonde ─────────────────────────────

/// Envoie `requete` à `cible` depuis `local`, puis recueille les adresses des appareils qui ont répondu pour notre
/// nom pendant `DELAI`. `multicast` : envoi multicast (TTL 1, reste sur le réseau local) ; `diffusion` : envoi en
/// diffusion. Lié à `local` : l'envoi sort par l'interface du réseau local, jamais par un VPN.
async fn interroger(
    local: Ipv4Addr,
    cible: SocketAddr,
    requete: Vec<u8>,
    multicast: bool,
    diffusion: bool,
    valider: impl Fn(&[u8]) -> Option<Ipv4Addr>,
) -> BTreeSet<Ipv4Addr> {
    let mut trouves = BTreeSet::new();
    let Ok(socket) = UdpSocket::bind(SocketAddr::new(local.into(), 0)).await else {
        return trouves;
    };
    if multicast && socket.set_multicast_ttl_v4(1).is_err() {
        return trouves;
    }
    if diffusion && socket.set_broadcast(true).is_err() {
        return trouves;
    }
    if socket.send_to(&requete, cible).await.is_err() {
        return trouves;
    }
    let fin = Instant::now() + DELAI;
    let mut tampon = [0u8; 1500];
    while let Some(reste) = fin.checked_duration_since(Instant::now()) {
        match timeout(reste, socket.recv_from(&mut tampon)).await {
            Ok(Ok((n, SocketAddr::V4(src)))) if valider(&tampon[..n]).is_some() => {
                trouves.insert(*src.ip());
            }
            Ok(Ok(_)) => {} // réponse sans rapport (autre nom, autre id) : ignorée.
            Ok(Err(_)) | Err(_) => break,
        }
    }
    trouves
}

/// Un essai : un nom tiré au hasard, demandé par les trois protocoles en même temps. Rend, par appareil, les
/// protocoles par lesquels il a répondu à ce faux nom.
async fn essai(local: Ipv4Addr, diffusion: Ipv4Addr) -> BTreeMap<Ipv4Addr, Vec<&'static str>> {
    let nom = nom_aleatoire();
    // Un identifiant par protocole : une réponse qui ne le porte pas est ignorée.
    let mut id = [0u8; 2];
    let _ = getrandom::fill(&mut id);
    let id = u16::from_be_bytes(id);

    let nom_l = nom.clone();
    let llmnr = interroger(
        local,
        LLMNR.parse().unwrap(),
        requete_llmnr(id, &nom),
        true,
        false,
        move |p| adresse_llmnr(p, id, &nom_l),
    );
    let nom_m = nom.clone();
    let mdns = interroger(
        local,
        MDNS.parse().unwrap(),
        requete_mdns(id, &nom),
        true,
        false,
        move |p| adresse_mdns(p, id, &nom_m),
    );
    let nom_n = nom.clone();
    let netbios = interroger(
        local,
        SocketAddr::new(diffusion.into(), PORT_NETBIOS),
        requete_netbios(id, &nom),
        false,
        true,
        move |p| adresse_netbios(p, id, &nom_n),
    );
    let (llmnr, mdns, netbios) = tokio::join!(llmnr, mdns, netbios);

    let mut par_ip: BTreeMap<Ipv4Addr, Vec<&'static str>> = BTreeMap::new();
    for (proto, ips) in [("LLMNR", llmnr), ("mDNS", mdns), ("NetBIOS", netbios)] {
        for ip in ips {
            par_ip.entry(ip).or_default().push(proto);
        }
    }
    par_ip
}

/// Adresse de diffusion d'un réseau « 10.0.0.0/24 ». `None` si l'écriture est invalide (on se rabat alors sur la
/// diffusion générale 255.255.255.255).
fn diffusion_de(cidr: &str) -> Option<Ipv4Addr> {
    let (ip, pref) = cidr.split_once('/')?;
    let ip: Ipv4Addr = ip.parse().ok()?;
    let pref: u32 = pref.parse().ok()?;
    if pref > 32 {
        return None;
    }
    let masque = if pref == 0 { 0 } else { u32::MAX << (32 - pref) };
    Some(Ipv4Addr::from((u32::from(ip) & masque) | !masque))
}

/// Démasque les empoisonneurs de noms du réseau local. Deux essais avec deux noms différents : seul un appareil qui
/// répond aux deux (pour le même protocole) est accusé, jamais un sur un coup de chance. `local` : l'adresse de cette
/// machine sur le réseau local ; `cidr` : le réseau (pour la diffusion NetBIOS).
pub async fn sonder(local: Ipv4Addr, cidr: &str) -> Rapport {
    let diffusion = diffusion_de(cidr).unwrap_or(Ipv4Addr::BROADCAST);
    let premier = essai(local, diffusion).await;
    let second = essai(local, diffusion).await;

    let mut empoisonneurs = Vec::new();
    for (ip, protos1) in &premier {
        let Some(protos2) = second.get(ip) else { continue };
        // Les protocoles communs aux deux essais : une réponse confirmée, pas un coup de chance.
        let protocoles: Vec<&'static str> = protos1.iter().copied().filter(|p| protos2.contains(p)).collect();
        if !protocoles.is_empty() {
            empoisonneurs.push(Empoisonneur { ip: *ip, protocoles });
        }
    }
    Rapport::Teste(empoisonneurs)
}

// ───────────────────────────── Affichage ─────────────────────────────

/// Décrit un empoisonneur, avec ce que le scan ou le carnet savent de lui (nom, MAC, fabricant).
fn qui(e: &Empoisonneur, hotes: &[super::Hote]) -> String {
    let hote = hotes.iter().find(|h| h.ip == e.ip);
    let titre = hote.map(super::Hote::titre).filter(|t| !t.is_empty());
    let mac = hote.and_then(|h| h.mac.as_deref());
    match (titre, mac) {
        (Some(t), Some(m)) => format!("{} ({}, {m})", e.ip, affichable(&t)),
        (Some(t), None) => format!("{} ({})", e.ip, affichable(&t)),
        (None, Some(m)) => format!("{} ({m})", e.ip),
        (None, None) => e.ip.to_string(),
    }
}

/// La ligne du scan sur les faux noms : rien ne répond (rassurant), ou l'alerte.
pub fn afficher(rapport: &Rapport, hotes: &[super::Hote]) {
    use crate::risk::Niveau;
    use crate::ui::*;
    let empoisonneurs = match rapport {
        // Sans réseau local, rien n'a été testé : on ne dit rien plutôt que de laisser croire que c'est sain.
        Rapport::SansReseauLocal => return,
        Rapport::Teste(e) => e,
    };
    if empoisonneurs.is_empty() {
        println!();
        afficher_aligne(
            &format!("  {VERT}✔{RESET} "),
            tr!(
                "Personne ne répond aux faux noms (LLMNR, NetBIOS, mDNS) : pas d'empoisonneur comme Responder sur ce réseau.",
                "No one answers bogus names (LLMNR, NetBIOS, mDNS): no poisoner like Responder on this network."
            ),
            4,
            "",
        );
        return;
    }
    section(tr!("EMPOISONNEUR DE NOMS", "NAME POISONER"));
    for e in empoisonneurs {
        let protos = e.protocoles.join(", ");
        println!("\n  {}✖{RESET} {GRAS}{}{RESET}", couleur(Niveau::Eleve), qui(e, hotes));
        afficher_aligne(
            "    ",
            &trf!(
                "répond à des noms qui n'existent pas ({protos}) : un outil comme Responder vole ainsi les mots de passe Windows sur ce réseau.",
                "answers names that do not exist ({protos}): a tool like Responder steals Windows passwords on this network this way."
            ),
            4,
            couleur(Niveau::Eleve),
        );
        afficher_aligne(
            "    → ",
            tr!(
                "Débranchez cet appareil. Sur vos PC Windows, coupez LLMNR et NetBIOS (Vanguard le fait au bilan).",
                "Unplug this device. On your Windows PCs, turn off LLMNR and NetBIOS (Vanguard does it in the audit)."
            ),
            6,
            "",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(t: &str) -> Ipv4Addr {
        t.parse().unwrap()
    }

    /// Une réponse DNS (LLMNR/mDNS) construite à la main : une question, une réponse A dont le nom pointe (compression)
    /// vers celui de la question.
    fn reponse_dns(id: u16, nom_complet: &str, adr: [u8; 4]) -> Vec<u8> {
        let mut p = id.to_be_bytes().to_vec();
        p.extend([0x81, 0x80]); // réponse
        p.extend([0, 1, 0, 1, 0, 0, 0, 0]); // 1 question, 1 réponse
        p.extend(etiquettes(nom_complet)); // la question commence à l'offset 12
        p.extend([0, 1, 0, 1]); // type A, classe IN
        p.extend([0xc0, 0x0c]); // nom de la réponse : pointeur vers la question
        p.extend([0, 1, 0, 1, 0, 0, 0, 60, 0, 4]); // type A, classe IN, TTL, longueur 4
        p.extend(adr);
        p
    }

    /// Une réponse NetBIOS positive construite à la main : un nom encodé, une adresse.
    fn reponse_netbios(id: u16, nom: &str, adr: [u8; 4]) -> Vec<u8> {
        let mut p = id.to_be_bytes().to_vec();
        p.extend([0x85, 0x80]); // réponse positive
        p.extend([0, 0, 0, 1, 0, 0, 0, 0]); // 0 question, 1 réponse
        p.push(0x20);
        p.extend(encoder_netbios(&nom_netbios(nom)));
        p.push(0x00);
        p.extend([0x00, 0x20, 0x00, 0x01]); // type NB, classe IN
        p.extend([0, 0, 0, 60, 0, 6]); // TTL, longueur 6
        p.extend([0x00, 0x00]); // drapeaux NB
        p.extend(adr);
        p
    }

    #[test]
    fn llmnr_aller_retour() {
        let paquet = reponse_dns(0x1234, "vgdeadbeef00", [192, 0, 2, 66]);
        assert_eq!(adresse_llmnr(&paquet, 0x1234, "vgdeadbeef00"), Some(ip("192.0.2.66")));
        // Mauvais identifiant ou mauvais nom : ignoré (une autre résolution qui passait par là).
        assert_eq!(adresse_llmnr(&paquet, 0x9999, "vgdeadbeef00"), None);
        assert_eq!(adresse_llmnr(&paquet, 0x1234, "vgautre"), None);
    }

    #[test]
    fn mdns_aller_retour() {
        let paquet = reponse_dns(0x4321, "vgcafe0001.local", [198, 51, 100, 7]);
        assert_eq!(adresse_mdns(&paquet, 0x4321, "vgcafe0001"), Some(ip("198.51.100.7")));
        assert_eq!(adresse_mdns(&paquet, 0x4321, "vgautre"), None);
    }

    #[test]
    fn netbios_aller_retour() {
        let paquet = reponse_netbios(0x0042, "vgcafe0002", [203, 0, 113, 9]);
        assert_eq!(adresse_netbios(&paquet, 0x0042, "vgcafe0002"), Some(ip("203.0.113.9")));
        assert_eq!(adresse_netbios(&paquet, 0x0001, "vgcafe0002"), None);
        assert_eq!(adresse_netbios(&paquet, 0x0042, "VGAUTRE"), None);
    }

    #[test]
    fn nom_netbios_normalise() {
        // 16 octets : 15 caractères en majuscules, complétés d'espaces, suffixe 0x00.
        let brut = nom_netbios("vg12");
        assert_eq!(&brut[..4], b"VG12");
        assert_eq!(&brut[4..15], b"           ");
        assert_eq!(brut[15], 0x00);
        assert_eq!(decoder_netbios(&encoder_netbios(&brut)), Some(brut));
        // Encodage invalide (lettres hors A-P) : rejeté sans planter.
        assert_eq!(decoder_netbios(&[b'Z'; 32]), None);
        assert_eq!(decoder_netbios(b"trop court"), None);
    }

    #[test]
    fn paquets_pieges_sans_panique() {
        // Trop courts, tronqués : None, jamais de panique.
        for p in [&b""[..], &[0u8; 5], &[0xff; 12]] {
            assert_eq!(adresse_llmnr(p, 0, "vg"), None);
            assert_eq!(adresse_netbios(p, 0, "vg"), None);
        }
        // Longueur d'étiquette qui déborde du paquet.
        let deborde = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 200, b'x'];
        assert_eq!(adresse_llmnr(&deborde, 0x1234, "x"), None);
        // Pointeur de compression qui part en avant (boucle possible) : rejeté.
        let boucle = [
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4,
        ];
        assert_eq!(adresse_llmnr(&boucle, 0x1234, "x"), None);
    }

    #[test]
    fn nom_qui_pilote_le_terminal_rendu_inoffensif() {
        // Un empoisonneur pourrait porter dans le carnet un nom piégé (séquence d'échappement) : montré, il est rendu
        // inoffensif par affichable, jamais écrit tel quel.
        let hote = super::super::Hote {
            ip: ip("192.0.2.66"),
            nom: Some("\x1b]0;piège\x07".into()),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role: None,
            nouvelle: false,
            ports: Vec::new(),
            alertes: Vec::new(),
            score: 100,
        };
        let e = Empoisonneur {
            ip: ip("192.0.2.66"),
            protocoles: vec!["LLMNR"],
        };
        let texte = qui(&e, std::slice::from_ref(&hote));
        assert!(!texte.contains('\x1b') && !texte.contains('\x07'));
        assert!(texte.contains("192.0.2.66"));
    }

    #[test]
    fn diffusion_calculee() {
        assert_eq!(diffusion_de("10.0.0.0/24"), Some(ip("10.0.0.255")));
        assert_eq!(diffusion_de("192.0.2.128/25"), Some(ip("192.0.2.255")));
        assert_eq!(diffusion_de("10.0.0.0/16"), Some(ip("10.0.255.255")));
        assert_eq!(diffusion_de("pas un réseau"), None);
    }

    #[test]
    fn requetes_bien_formees() {
        // LLMNR : identifiant, une question, l'étiquette du nom, type A classe IN.
        let r = requete_llmnr(0xabcd, "vgtest");
        assert_eq!(&r[0..2], &[0xab, 0xcd]);
        assert_eq!(&r[4..6], &[0x00, 0x01]); // une question
        assert_eq!(r[12], 6); // longueur de « vgtest »
        assert_eq!(&r[13..19], b"vgtest");
        assert_eq!(&r[r.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
        // mDNS : le bit de réponse en unicast est posé sur la classe.
        let m = requete_mdns(0, "vgtest");
        assert_eq!(&m[m.len() - 2..], &[0x80, 0x01]);
    }
}
