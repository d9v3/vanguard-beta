//! DNS le plus rapide : chaque visite de site commence par une question au DNS (« quelle adresse pour ce nom ? »).
//! Vanguard mesure ici le temps de réponse du DNS actuel et de quatre DNS publics (Cloudflare, Quad9, Google,
//! AdGuard DNS), en douze questions chacun, et retient la médiane. Un DNS qui protège (résolveur sur cet ordinateur
//! comme NextDNS, requêtes chiffrées, DNS filtrant, Pi-hole du réseau) est gardé, même plus lent : le remplacer
//! affaiblirait la protection. Sinon, le plus rapide est proposé ; appliqué après accord, il s'annule exactement
//! (Optimiser › Tout remettre comme avant).

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::audit::dns_client;
use crate::machine::dns::{Actuel, bouclier_canadien, bouclier_canadien_filtrant, service_public};
use crate::reseau::nat::{hasard, recevoir};
use crate::selection::{Ligne, choisir};
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Bloque {
    Rien,
    Malveillants,
    Publicites,
}

/// Un DNS public proposé : son nom, ses adresses (la première est mesurée), ce qu'il bloque.
struct Public {
    nom: &'static str,
    v4: [&'static str; 2],
    v6: [&'static str; 2],
    bloque: Bloque,
}

#[rustfmt::skip] // deux lignes par DNS, que rustfmt étalerait sur six
const PUBLICS: [Public; 5] = [
    Public { nom: "Cloudflare", v4: ["1.1.1.1", "1.0.0.1"], v6: ["2606:4700:4700::1111", "2606:4700:4700::1001"],
        bloque: Bloque::Rien },
    Public { nom: "Quad9", v4: ["9.9.9.9", "149.112.112.112"], v6: ["2620:fe::fe", "2620:fe::9"],
        bloque: Bloque::Malveillants },
    Public { nom: "Google", v4: ["8.8.8.8", "8.8.4.4"], v6: ["2001:4860:4860::8888", "2001:4860:4860::8844"],
        bloque: Bloque::Rien },
    Public { nom: "AdGuard DNS", v4: ["94.140.14.14", "94.140.15.15"], v6: ["2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        bloque: Bloque::Publicites },
    // Le Bouclier canadien de l'ACEI, version « Protégé » (.20) : sans frais, sans profilage, il bloque les logiciels
    // malveillants et l'hameçonnage ; le « Privé » (.10) ne filtre rien et n'est donc pas proposé.
    Public { nom: "Bouclier canadien", v4: ["149.112.121.20", "149.112.122.20"], v6: ["2620:10a:80bb::20", "2620:10a:80bc::20"],
        bloque: Bloque::Malveillants },
];

/// Les adresses du Bouclier canadien « Protégé » (IPv4, IPv6) : le DNS protecteur du mode Wi-Fi public.
pub(crate) fn bouclier_protege() -> (&'static [&'static str; 2], &'static [&'static str; 2]) {
    let p = &PUBLICS[4];
    (&p.v4, &p.v6)
}

/// Des sites très visités, que tout DNS a souvent déjà en mémoire, comme lors d'une vraie navigation.
#[rustfmt::skip] // une ligne de noms, que rustfmt étalerait sur six
const NOMS: [&str; 6] = [
    "www.google.com", "www.wikipedia.org", "www.youtube.com", "www.amazon.com", "www.microsoft.com", "www.apple.com",
];
const TOURS: usize = 2;
/// Délai d'une réponse : au-delà, la question compte comme perdue.
const DELAI: Duration = Duration::from_millis(1500);

/// Question DNS : un nom, type A (IPv4), récursion demandée, sans EDNS (le client de l'audit).
fn question(id: u16, nom: &str) -> Vec<u8> {
    dns_client::question(id, nom, dns_client::Genre::A, false, false)
}

/// Une réponse à notre question : même identifiant, drapeau « réponse », et le serveur a su répondre (« ce nom
/// n'existe pas » compris), pas un refus ni une panne.
fn repond(r: &[u8], id: u16) -> bool {
    dns_client::lire(r, id).is_some_and(|reponse| matches!(reponse.rcode, 0 | 3))
}

fn mediane(mut temps: Vec<Duration>) -> Option<Duration> {
    temps.sort_unstable();
    temps.get(temps.len() / 2).copied()
}

/// Temps de réponse médian d'un serveur sur les sites très visités ; `None` s'il ne répond pas.
fn mesurer(serveur: IpAddr) -> Option<Duration> {
    let noms: Vec<String> = NOMS.iter().map(ToString::to_string).collect();
    mesurer_noms(serveur, &noms)
}

/// Des noms jamais demandés, inventés à chaque mesure, sous « .example » (réservé, il n'existe pas) : aucun cache ne
/// les a. Un résolveur sur cet ordinateur (NextDNS, systemd-resolved, dnsmasq) répond de sa mémoire en moins d'une
/// milliseconde pour un site déjà visité ; pour une question nouvelle, il interroge son serveur par Internet, comme
/// les DNS publics : c'est ce temps-là qui se compare.
fn noms_nouveaux() -> Vec<String> {
    let graine = hasard();
    (0..NOMS.len() * TOURS)
        .map(|i| format!("vanguard-{graine:x}-{i}.example"))
        .collect()
}

/// Temps de réponse médian d'un serveur sur ces noms ; `None` s'il ne répond pas.
fn mesurer_noms(serveur: IpAddr, noms: &[String]) -> Option<Duration> {
    let socket = UdpSocket::bind(if serveur.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    socket.connect(SocketAddr::new(serveur, 53)).ok()?;
    let graine = u16::try_from(hasard() & 0xffff).unwrap_or(0);
    let (mut temps, mut perdues) = (Vec::new(), 0);
    let mut tampon = [0u8; 1500];
    for (i, nom) in noms.iter().cycle().take(NOMS.len() * TOURS).enumerate() {
        let id = graine.wrapping_add(u16::try_from(i).unwrap_or(0));
        let debut = Instant::now();
        // Une réponse tardive à une question d'avant ne compte pas : on attend la nôtre.
        let lire = |r: &[u8], _: SocketAddr| repond(r, id).then_some(());
        let repondu =
            socket.send(&question(id, nom)).is_ok() && recevoir(&socket, debut + DELAI, &mut tampon, lire).is_some();
        if repondu {
            temps.push(debut.elapsed());
        } else {
            perdues += 1;
        }
        // Muet trois fois de suite d'entrée : inutile d'attendre davantage.
        if temps.is_empty() && perdues >= 3 {
            break;
        }
    }
    mediane(temps)
}

/// Adresse d'un réseau local (box, routeur, serveur de la maison), pas d'Internet.
fn locale(ip: IpAddr) -> bool {
    crate::socle::adresses::du_reseau(ip)
}

/// Les adresses de la famille « Cloudflare pour les familles », qui filtrent (1.1.1.2, 1.1.1.3…).
fn cloudflare_famille(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => matches!(v4.octets(), [1, 1, 1, 2 | 3] | [1, 0, 0, 2 | 3]),
        IpAddr::V6(v6) => matches!(v6.segments()[7], 0x1112 | 0x1113 | 0x1002 | 0x1003),
    }
}

/// Un service qui protège : il bloque des sites (malveillants, publicités, contrôle parental), chiffre, ou passe par
/// un VPN. Seuls Cloudflare (hors familles), le Bouclier canadien « Privé » et Google ne filtrent rien.
fn filtrant(ip: IpAddr) -> Option<&'static str> {
    match service_public(ip)? {
        "Cloudflare" => cloudflare_famille(ip).then_some("Cloudflare"),
        nom if nom == bouclier_canadien() => bouclier_canadien_filtrant(ip).then_some(nom),
        "Google" => None,
        autre => Some(autre),
    }
}

/// Pourquoi le DNS actuel est gardé, même plus lent : il protège.
fn protection(a: &Actuel, passerelle: Option<IpAddr>) -> Option<String> {
    if let Some(nom) = a.resolveur_local {
        return Some(trf!(
            "{nom} tourne sur cet ordinateur : il chiffre ou filtre vos requêtes.",
            "{nom} runs on this computer: it encrypts or filters your queries."
        ));
    }
    if a.serveurs.iter().any(|(ip, _)| ip.is_loopback()) {
        return Some(String::from(tr!(
            "un résolveur tourne sur cet ordinateur : il chiffre ou filtre sans doute vos requêtes.",
            "a resolver runs on this computer: it probably encrypts or filters your queries."
        )));
    }
    if a.chiffre == Some(true) {
        return Some(tr!("vos requêtes DNS sont chiffrées.", "your DNS queries are encrypted.").to_string());
    }
    if let Some(nom) = a.serveurs.iter().find_map(|(ip, _)| filtrant(*ip)) {
        return Some(trf!(
            "{nom} protège (sites dangereux ou publicitaires bloqués, ou VPN).",
            "{nom} protects (dangerous or advertising sites blocked, or VPN)."
        ));
    }
    // Un serveur du réseau en IPv4 qui n'est pas la box : Pi-hole, AdGuard Home, ou le DNS d'un VPN. En IPv6, la box
    // se présente souvent par une adresse locale : celle-là n'est pas un filtre.
    let (ip, _) = a
        .serveurs
        .iter()
        .find(|(ip, _)| ip.is_ipv4() && locale(*ip) && Some(*ip) != passerelle)?;
    Some(trf!(
        "{ip} est un serveur DNS de votre réseau qui n'est pas le routeur (Pi-hole, AdGuard Home, VPN ?) : il filtre sans doute.",
        "{ip} is a DNS server on your network that is not the router (Pi-hole, AdGuard Home, VPN?): it probably filters."
    ))
}

/// Le DNS actuel bloque-t-il les sites dangereux ? `None` : rien ne permet de le dire (résolveur sur cet ordinateur,
/// comme NextDNS ; serveur du réseau qui n'est pas la box, comme Pi-hole) ; il peut filtrer, on ne le pousse pas.
/// Chiffrer seul ne bloque rien. Un serveur qui filtre parmi d'autres qui ne filtrent pas ne compte pas : le
/// système passe de l'un à l'autre (`tous_filtrants`).
pub(crate) fn bloque_les_dangereux(a: &Actuel, passerelle: Option<IpAddr>) -> Option<bool> {
    if a.resolveur_local.is_some() || a.serveurs.iter().any(|(ip, _)| ip.is_loopback()) {
        return None;
    }
    if tous_filtrants(a) {
        return Some(true);
    }
    if a.serveurs
        .iter()
        .any(|(ip, _)| ip.is_ipv4() && locale(*ip) && Some(*ip) != passerelle)
    {
        return None;
    }
    Some(false)
}

/// Tous les serveurs DNS actuels sont-ils des services publics qui filtrent ? Un seul serveur filtrant parmi
/// d'autres ne garde rien : le système passe de l'un à l'autre, et celui d'un réseau hostile répond aussi.
pub(crate) fn tous_filtrants(a: &Actuel) -> bool {
    !a.serveurs.is_empty() && a.serveurs.iter().all(|(ip, _)| filtrant(*ip).is_some())
}

/// Le nom d'un serveur DNS actuel, pour l'écran.
fn nom_actuel(ip: IpAddr, a: &Actuel, passerelle: Option<IpAddr>) -> &'static str {
    if ip.is_loopback() {
        a.resolveur_local.unwrap_or(tr!("résolveur local", "local resolver"))
    } else if let Some(nom) = service_public(ip) {
        nom
    } else if Some(ip) == passerelle || (ip.is_ipv6() && locale(ip)) {
        tr!("votre routeur", "your router")
    } else if locale(ip) {
        tr!("votre réseau", "your network")
    } else {
        tr!("votre fournisseur ?", "your provider?")
    }
}

fn millisecondes(d: Option<Duration>) -> String {
    match d {
        None => tr!("ne répond pas", "no answer").to_string(),
        // Un résolveur sur cet ordinateur répond de sa mémoire en moins d'une milliseconde.
        Some(d) if d < Duration::from_millis(1) => "< 1 ms".to_string(),
        Some(d) => format!("{} ms", d.as_millis()),
    }
}

/// Un serveur qu'on sait interroger d'ici. Une adresse IPv6 de lien local (fe80::, ou fec0:: des anciens Windows) a
/// besoin du nom de sa carte (« %wlan0 »), que la configuration lue n'a pas gardé : elle ne se mesure pas.
fn mesurable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => !crate::socle::adresses::lien_local_v6(v6),
    }
}

/// Le DNS actuel ne se mesure pas du tout : aucun de ses serveurs ne s'interroge d'ici. Rien n'est alors conclu,
/// surtout pas qu'il « ne répond pas ».
fn actuel_non_mesurable(serveurs: &[IpAddr]) -> bool {
    !serveurs.is_empty() && serveurs.iter().all(|ip| !mesurable(*ip))
}

/// Faut-il proposer le plus rapide ? Seulement s'il gagne vraiment : un cinquième du temps, et 5 ms au moins.
fn vaut_la_peine(actuel: Option<Duration>, meilleur: Option<Duration>) -> bool {
    match (actuel, meilleur) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(a), Some(m)) => m * 5 <= a * 4 && a.saturating_sub(m) >= Duration::from_millis(5),
    }
}

/// Précision d'un DNS public dans le menu (33 caractères au plus).
fn precision(p: &Public, temps: Option<Duration>, plus_rapide: bool) -> String {
    let ms = millisecondes(temps);
    match (temps.is_some(), p.bloque, plus_rapide) {
        (true, Bloque::Malveillants, _) => trf!("{ms}, sites dangereux bloqués", "{ms}, dangerous sites blocked"),
        (true, Bloque::Publicites, _) => trf!("{ms}, pubs et pisteurs bloqués", "{ms}, ads and trackers blocked"),
        (true, Bloque::Rien, true) => trf!("{ms}, le plus rapide", "{ms}, the fastest"),
        // Muet, ou sans rien à dire de plus que son temps.
        (false, ..) | (true, Bloque::Rien, false) => ms,
    }
}

/// Menu Optimiser › DNS le plus rapide, ou `vanguard dns-rapide`.
pub fn mesurer_et_proposer() {
    titre(tr!("DNS le plus rapide", "Fastest DNS"));
    let intro = tr!(
        "Chaque visite de site commence par une question au DNS. Vanguard mesure ici le DNS actuel et quatre DNS publics, en douze questions chacun. Un DNS qui vous protège est gardé, même plus lent.",
        "Every site visit starts with a question to the DNS. Vanguard measures the current DNS and four public ones here, twelve questions each. A DNS that protects you is kept, even if slower."
    );
    for ligne in envelopper(intro, LARGEUR - 2) {
        println!("  {ligne}");
    }
    let Some(actuel) = crate::machine::dns::actuel() else {
        trp!(
            "\n  ✖ Configuration DNS illisible sur cet ordinateur.",
            "\n  ✖ DNS configuration unreadable on this computer."
        );
        return;
    };
    let passerelle = crate::reseau::scan::passerelle().map(IpAddr::V4);
    let garde = protection(&actuel, passerelle);
    // Les deux premiers serveurs différents.
    let mut a_mesurer: Vec<IpAddr> = actuel.serveurs.iter().map(|(ip, _)| *ip).collect();
    a_mesurer.dedup();
    a_mesurer.truncate(2);
    trp!("\n  {GRIS}Mesure en cours…{RESET}", "\n  {GRIS}Measuring…{RESET}");
    #[allow(clippy::type_complexity)]
    let (temps_actuels, temps_publics): (Vec<(Option<Duration>, Option<Duration>)>, Vec<Option<Duration>>) =
        std::thread::scope(|s| {
            let actuels: Vec<_> = a_mesurer
                .iter()
                .map(|ip| {
                    s.spawn(move || {
                        if !mesurable(*ip) {
                            return (None, None);
                        }
                        // Sur cet ordinateur : aussi une question nouvelle, que son cache ne peut pas avoir.
                        let nouveau = ip.is_loopback().then(|| mesurer_noms(*ip, &noms_nouveaux())).flatten();
                        (mesurer(*ip), nouveau)
                    })
                })
                .collect();
            let publics: Vec<_> = PUBLICS
                .iter()
                .map(|p| s.spawn(move || p.v4[0].parse().ok().and_then(mesurer)))
                .collect();
            (
                actuels.into_iter().map(|f| f.join().unwrap_or((None, None))).collect(),
                publics.into_iter().map(|f| f.join().ok().flatten()).collect(),
            )
        });
    // Comparé aux DNS publics : la question nouvelle pour un résolveur sur cet ordinateur (sa mémoire répond toujours
    // plus vite qu'Internet, ce n'est pas une mesure de son serveur).
    let actuel_ms = temps_actuels
        .iter()
        .filter_map(|(memoire, nouveau)| nouveau.or(*memoire))
        .min();
    let meilleur = temps_publics
        .iter()
        .enumerate()
        .filter_map(|(i, t)| Some((i, (*t)?)))
        .min_by_key(|(_, t)| *t);

    let mut lignes = vec![Ligne::Texte(String::new())];
    for (ip, (t, nouveau)) in a_mesurer.iter().zip(&temps_actuels) {
        let ms = if mesurable(*ip) {
            millisecondes(*t)
        } else {
            tr!("non mesurable (lien local)", "not measurable (link-local)").to_string()
        };
        let quoi = ajuster(tr!("Actuel", "Current"), 8);
        let serveur = ajuster(&format!("{} ({ip})", nom_actuel(*ip, &actuel, passerelle)), 44);
        let ligne = format!("  {GRIS}{quoi}{RESET} {serveur} {GRIS}{ms}{RESET}");
        lignes.push(Ligne::Texte(ligne));
        if ip.is_loopback() && mesurable(*ip) {
            let memoire = trf!(
                "site déjà visité : {ms} (sa mémoire, sur cet ordinateur)",
                "site already visited: {ms} (its memory, on this computer)"
            );
            let nouveau = trf!(
                "site nouveau : {} (envoyé par Internet, comme les autres)",
                "new site: {} (sent over the Internet, like the others)",
                millisecondes(*nouveau)
            );
            for l in [memoire, nouveau] {
                lignes.push(Ligne::Texte(format!("           {GRIS}{l}{RESET}")));
            }
        }
    }
    if a_mesurer.is_empty() {
        let aucun = tr!("Aucun serveur DNS configuré.", "No DNS server configured.");
        lignes.push(Ligne::Texte(format!("  {GRIS}{aucun}{RESET}")));
    }
    if let Some(raison) = &garde {
        let texte = trf!("Gardé : {raison}", "Kept: {raison}");
        let coche = format!("{VERT}✔{RESET} ");
        for (i, ligne) in envelopper(&texte, LARGEUR - 4).into_iter().enumerate() {
            let marque = if i == 0 { coche.as_str() } else { "  " };
            lignes.push(Ligne::Texte(format!("  {marque}{ligne}")));
        }
    }
    lignes.push(Ligne::Texte(String::new()));
    let inconnu = actuel_non_mesurable(&a_mesurer);
    let proposer = garde.is_none() && !inconnu && vaut_la_peine(actuel_ms, meilleur.map(|(_, t)| t));
    // Gardé : les DNS publics sont montrés pour information, sans rien proposer.
    for (i, (p, t)) in PUBLICS.iter().zip(&temps_publics).enumerate() {
        let texte = format!("{} ({})", p.nom, p.v4[0]);
        let precision = precision(p, *t, meilleur.is_some_and(|(m, _)| m == i));
        lignes.push(if garde.is_none() && t.is_some() {
            Ligne::choix(&(i + 1).to_string(), &texte, &precision)
        } else {
            Ligne::Texte(format!("     {}  {GRIS}{precision}{RESET}", ajuster(&texte, 34)))
        });
    }
    lignes.push(Ligne::Texte(String::new()));
    let change = crate::optimiser::dns_change();
    if let Some((date, _)) = &change {
        let remettre = tr!(
            "Remettre le DNS d'avant Vanguard",
            "Restore the DNS from before Vanguard"
        );
        let quand = trf!("changé le {date}", "changed on {date}");
        lignes.push(Ligne::choix("r", remettre, &quand));
    }
    let conclusion = match meilleur {
        _ if garde.is_some() => "",
        _ if inconnu => tr!(
            "Votre DNS actuel a une adresse de lien local, que Vanguard ne sait pas mesurer : rien n'est comparé.",
            "Your current DNS has a link-local address, which Vanguard cannot measure: nothing is compared."
        ),
        None => tr!(
            "Les DNS publics ne répondent pas d'ici (UDP 53 bloqué par le réseau ?) : rien à comparer.",
            "Public DNS servers do not answer from here (UDP 53 blocked by the network?): nothing to compare."
        ),
        Some(_) if proposer => tr!(
            "Un DNS public répond nettement plus vite : choisissez-le, ou gardez l'actuel.",
            "A public DNS answers clearly faster: choose it, or keep the current one."
        ),
        Some(_) => tr!(
            "Votre DNS actuel est déjà rapide : changer ne ferait presque rien gagner.",
            "Your current DNS is already fast: switching would gain almost nothing."
        ),
    };
    for l in envelopper(conclusion, LARGEUR - 2) {
        lignes.push(Ligne::Texte(format!("  {l}")));
    }
    // Rien à choisir : l'écran seul.
    if (garde.is_some() || meilleur.is_none()) && change.is_none() {
        for l in &lignes {
            if let Ligne::Texte(t) = l {
                println!("{t}");
            }
        }
        return;
    }
    let garder = tr!("Garder le DNS actuel", "Keep the current DNS");
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", garder, ""));
    lignes.push(Ligne::Texte(String::new()));
    let depart = match meilleur {
        Some((i, _)) if proposer => (i + 1).to_string(),
        _ => "↵".to_string(),
    };
    let invite = tr!("Choix (Entrée pour garder) : ", "Choice (Enter to keep): ");
    let choix = choisir(&lignes, invite, &depart, tr!("garder", "keep")).unwrap_or_default();
    if choix.eq_ignore_ascii_case("r") && change.is_some() {
        crate::optimiser::remettre_dns();
        return;
    }
    let numero = choix.parse::<usize>().ok().and_then(|n| n.checked_sub(1));
    let Some(p) = numero.and_then(|i| PUBLICS.get(i).filter(|_| temps_publics[i].is_some() && garde.is_none())) else {
        trp!("  DNS gardé.", "  DNS kept.");
        return;
    };
    if p.bloque == Bloque::Publicites {
        let prudence = tr!(
            "AdGuard DNS bloque publicités et pisteurs : quelques sites ou liens d'achat peuvent ne plus s'ouvrir.",
            "AdGuard DNS blocks ads and trackers: a few sites or shopping links may stop opening."
        );
        afficher_aligne("  ⚠ ", prudence, 4, "");
    }
    if let Err(e) = crate::optimiser::appliquer_dns(&p.v4, &p.v6) {
        afficher_aligne("  ✖ ", &e, 4, "");
        let a_la_main = trf!(
            "À régler à la main : {} et {} (IPv6 : {} et {}).",
            "To set by hand: {} and {} (IPv6: {} and {}).",
            p.v4[0],
            p.v4[1],
            p.v6[0],
            p.v6[1]
        );
        afficher_aligne("    ", &a_la_main, 4, GRIS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Un DNS actuel en IPv6 de lien local ne se mesure pas : jamais « il ne répond pas », et rien n'est proposé
    // sur cette base. Un serveur de lien local à côté d'un autre mesurable laisse la comparaison se faire.
    #[test]
    fn lien_local_non_mesurable() {
        let ip = |t: &str| t.parse::<IpAddr>().unwrap();
        assert!(!mesurable(ip("fe80::1")) && !mesurable(ip("fec0:0:0:ffff::1")));
        assert!(mesurable(ip("192.168.1.1")) && mesurable(ip("2606:4700:4700::1111")) && mesurable(ip("fd00::1")));
        assert!(actuel_non_mesurable(&[ip("fe80::1")]));
        assert!(!actuel_non_mesurable(&[ip("fe80::1"), ip("192.168.1.1")]));
        assert!(!actuel_non_mesurable(&[]));
    }

    #[test]
    fn noms_jamais_demandes() {
        // Uniques d'une mesure à l'autre et dans une même mesure, sous « .example », qui n'existe pas : aucun cache ne
        // peut les avoir.
        let (a, b) = (noms_nouveaux(), noms_nouveaux());
        assert_eq!(a.len(), NOMS.len() * TOURS);
        assert!(a.iter().all(|n| n.ends_with(".example") && !b.contains(n)));
        let uniques: std::collections::HashSet<_> = a.iter().collect();
        assert_eq!(uniques.len(), a.len());
        // Chaque étiquette tient dans une question DNS (63 octets au plus).
        assert!(a.iter().all(|n| n.split('.').all(|e| e.len() <= 63)));
    }

    #[test]
    fn questions_et_reponses() {
        let q = question(0x1234, "www.example.org");
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(q.len(), 12 + 17 + 4);
        assert!(q.ends_with(&[3, b'o', b'r', b'g', 0, 0, 1, 0, 1]));
        let mut r = q.clone();
        r[2] |= 0x80;
        assert!(repond(&r, 0x1234));
        assert!(!repond(&q, 0x1234), "une question n'est pas une réponse");
        assert!(!repond(&r, 0x1235), "autre identifiant");
        r[3] = (r[3] & 0xf0) | 3;
        assert!(repond(&r, 0x1234), "« ce nom n'existe pas » est une réponse");
        r[3] = (r[3] & 0xf0) | 5;
        assert!(!repond(&r, 0x1234), "un refus n'en est pas une");
        assert!(!repond(&r[..8], 0x1234));
    }

    #[test]
    fn mediane_et_seuil() {
        let ms = Duration::from_millis;
        assert_eq!(mediane(vec![ms(30), ms(10), ms(20)]), Some(ms(20)));
        assert_eq!(mediane(Vec::new()), None);
        assert!(vaut_la_peine(Some(ms(40)), Some(ms(20))));
        assert!(!vaut_la_peine(Some(ms(12)), Some(ms(10))), "moins d'un cinquième");
        assert!(!vaut_la_peine(Some(ms(6)), Some(ms(3))), "moins de 5 ms");
        assert!(vaut_la_peine(None, Some(ms(20))), "l'actuel ne répond plus");
        assert!(!vaut_la_peine(Some(ms(20)), None));
    }

    fn actuel(serveurs: &[&str], local: Option<&'static str>, chiffre: Option<bool>) -> Actuel {
        Actuel {
            serveurs: serveurs.iter().map(|s| (s.parse().unwrap(), false)).collect(),
            chiffre,
            resolveur_local: local,
        }
    }

    #[test]
    fn dns_qui_bloquent_les_dangereux() {
        let box_ = Some("192.168.1.1".parse().unwrap());
        // La box, Google, Cloudflare sans filtre, même chiffré : rien de bloqué, le bilan le dit.
        assert_eq!(
            bloque_les_dangereux(&actuel(&["192.168.1.1"], None, None), box_),
            Some(false)
        );
        assert_eq!(
            bloque_les_dangereux(&actuel(&["8.8.8.8"], None, None), box_),
            Some(false)
        );
        assert_eq!(
            bloque_les_dangereux(&actuel(&["1.1.1.1"], None, Some(true)), box_),
            Some(false)
        );
        // Quad9, Cloudflare famille, Bouclier canadien « Protégé » : ils bloquent.
        for f in ["9.9.9.9", "1.1.1.2", "149.112.121.20"] {
            assert_eq!(bloque_les_dangereux(&actuel(&[f], None, None), box_), Some(true), "{f}");
        }
        // Bouclier canadien « Privé » (.10) : il ne filtre pas.
        assert_eq!(
            bloque_les_dangereux(&actuel(&["149.112.121.10"], None, None), box_),
            Some(false)
        );
        // NextDNS sur cet ordinateur, résolveur local, Pi-hole du réseau : on ne sait pas, rien n'est poussé.
        assert_eq!(bloque_les_dangereux(&actuel(&["127.0.0.53"], None, None), box_), None);
        assert_eq!(
            bloque_les_dangereux(&actuel(&["8.8.8.8"], Some("NextDNS"), None), box_),
            None
        );
        assert_eq!(bloque_les_dangereux(&actuel(&["192.168.1.53"], None, None), box_), None);
        // Un serveur qui filtre à côté d'un autre qui ne filtre pas : le système passe de l'un à l'autre, rien
        // n'est gardé ; à côté d'un Pi-hole, on ne sait pas.
        assert_eq!(
            bloque_les_dangereux(&actuel(&["9.9.9.9", "8.8.8.8"], None, None), box_),
            Some(false)
        );
        assert_eq!(
            bloque_les_dangereux(&actuel(&["1.1.1.2", "192.168.1.1"], None, None), box_),
            Some(false)
        );
        assert_eq!(
            bloque_les_dangereux(&actuel(&["9.9.9.9", "192.168.1.53"], None, None), box_),
            None
        );
        assert_eq!(
            bloque_les_dangereux(&actuel(&["9.9.9.9", "149.112.121.20"], None, None), box_),
            Some(true)
        );
    }

    #[test]
    fn dns_qui_protegent_gardes() {
        let box_ = Some("10.0.0.1".parse().unwrap());
        // La box (et sa propre adresse IPv6 locale), un fournisseur, Google, Cloudflare : remplaçables.
        for s in [
            &["10.0.0.1", "fe80::1"][..],
            &["203.0.113.53"],
            &["8.8.8.8"],
            &["1.1.1.1"],
        ] {
            assert_eq!(protection(&actuel(s, None, None), box_), None, "{s:?}");
        }
        // NextDNS sur cet ordinateur, un résolveur local inconnu, du chiffré, un DNS filtrant, un Pi-hole : gardés.
        assert!(protection(&actuel(&["127.0.0.1"], Some("NextDNS"), Some(true)), box_).is_some());
        assert!(protection(&actuel(&["127.0.0.1"], None, None), box_).is_some());
        assert!(protection(&actuel(&["10.0.0.1"], None, Some(true)), box_).is_some());
        assert_eq!(protection(&actuel(&["149.112.121.10"], None, None), box_), None);
        for s in [
            "9.9.9.9",
            "45.90.28.1",
            "94.140.14.14",
            "1.1.1.3",
            "100.100.100.100",
            "149.112.121.20",
        ] {
            assert!(protection(&actuel(&[s], None, None), box_).is_some(), "{s}");
        }
        assert!(protection(&actuel(&["10.0.0.53"], None, None), box_).is_some());
        assert_eq!(
            nom_actuel("10.0.0.1".parse().unwrap(), &actuel(&[], None, None), box_),
            tr!("votre routeur", "your router")
        );
    }

    #[test]
    fn precisions_du_menu_courtes() {
        for p in &PUBLICS {
            for t in [None, Some(Duration::from_millis(1499))] {
                for plus_rapide in [false, true] {
                    let texte = precision(p, t, plus_rapide);
                    assert!(largeur_affichee(&texte) <= 33, "{texte}");
                }
            }
        }
        // Les adresses proposées sont toutes valides.
        for p in &PUBLICS {
            for a in p.v4.iter().chain(&p.v6) {
                assert!(a.parse::<IpAddr>().is_ok(), "{a}");
            }
        }
    }
}
