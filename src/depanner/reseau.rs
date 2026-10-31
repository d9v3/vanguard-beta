//! Parcours « Pas d'Internet » et « Le Wi-Fi coupe » : où la connexion s'arrête (cet ordinateur, la box, Internet,
//! les noms de sites), lu par des essais qui ne changent rien : une adresse sur le réseau, la box qui répond, trois
//! serveurs d'Internet joignables (Cloudflare, Quad9, Google), deux noms de sites traduits en adresses.

// FFI de libc : socket et ioctl (état des cartes réseau).
#![allow(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use super::{Etat, conseil, proposer_outil, proposer_reparation, question, verifications};
use crate::machine::wifi::Bande;
use crate::ui::*;

pub(super) fn titre_internet() -> &'static str {
    tr!("Internet ne marche plus", "Internet no longer works")
}

pub(super) fn titre_navigation() -> &'static str {
    tr!(
        "Navigation détournée (proxy, fichier hosts)",
        "Hijacked browsing (proxy, hosts file)"
    )
}

/// L'adresse de cet ordinateur sur le réseau local.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) enum Adresse {
    /// Relié à aucun réseau.
    #[default]
    Aucune,
    /// Seulement une adresse en 169.254.x.x : la box n'en a pas donné.
    Autoattribuee,
    Locale(Ipv4Addr),
}

/// Ce que les essais ont trouvé.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct EtatReseau {
    pub adresse: Adresse,
    pub passerelle: Option<Ipv4Addr>,
    pub passerelle_repond: bool,
    pub internet: bool,
    pub noms: bool,
}

/// Où la connexion s'arrête.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Panne {
    PasConnecte,
    PasDAdresse,
    BoxMuette,
    InternetCoupe,
    Noms,
    Aucune,
}

pub(super) fn panne(e: &EtatReseau) -> Panne {
    match e.adresse {
        Adresse::Aucune => return Panne::PasConnecte,
        Adresse::Autoattribuee => return Panne::PasDAdresse,
        Adresse::Locale(_) => {}
    }
    // Une box qui ne répond à aucun essai mais laisse passer Internet filtre simplement : ce n'est pas une panne.
    if !e.internet {
        return if e.passerelle.is_some() && e.passerelle_repond {
            Panne::InternetCoupe
        } else {
            Panne::BoxMuette
        };
    }
    if !e.noms {
        return Panne::Noms;
    }
    Panne::Aucune
}

pub(super) fn joignable(adresse: SocketAddr, delai: Duration) -> bool {
    match TcpStream::connect_timeout(&adresse, delai) {
        Ok(_) => true,
        // Refusé : l'appareil a répondu (aucun service sur ce port, mais il est là).
        Err(e) => e.kind() == std::io::ErrorKind::ConnectionRefused,
    }
}

/// Plusieurs essais en même temps : vrai dès que l'un réussit.
fn un_seul_suffit(adresses: &[SocketAddr], delai: Duration) -> bool {
    let (envoi, reception) = std::sync::mpsc::channel();
    for &a in adresses {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let _ = envoi.send(joignable(a, delai));
        });
    }
    drop(envoi);
    reception.iter().any(|ok| ok)
}

/// Deux noms de sites traduits en adresses par le DNS du système, en six secondes au plus.
fn noms_resolus() -> bool {
    let (envoi, reception) = std::sync::mpsc::channel();
    for nom in ["www.wikipedia.org", "www.google.com"] {
        let envoi = envoi.clone();
        std::thread::spawn(move || {
            let _ = envoi.send((nom, 443).to_socket_addrs().is_ok_and(|mut a| a.next().is_some()));
        });
    }
    drop(envoi);
    let fin = Instant::now() + Duration::from_secs(6);
    while let Ok(ok) = reception.recv_timeout(fin.saturating_duration_since(Instant::now())) {
        if ok {
            return true;
        }
    }
    false
}

/// La box répond-elle ? Un de ses services, sinon (Linux) une entrée de voisin confirmée à l'instant, sinon un écho
/// ICMP (`reseau::ping`, `ping` en secours).
/// La table ARP seule ne suffit pas : une entrée périmée y reste plusieurs minutes après la panne de la box, et juste
/// après une panne le diagnostic disait « la box répond ».
fn box_repond(box_: Ipv4Addr) -> bool {
    let ports: Vec<SocketAddr> = [80, 443, 53].iter().map(|&p| SocketAddr::from((box_, p))).collect();
    if un_seul_suffit(&ports, Duration::from_millis(1500)) {
        return true;
    }
    let ip = box_.to_string();
    let lancer = |cmd: &str, args: &[&str]| crate::commande::lancer(crate::commande::systeme(cmd).args(args), 6);
    // La table des voisins, demandée au noyau par netlink, comme `ip neigh` le fait, sans le lancer.
    #[cfg(target_os = "linux")]
    if box_confirmee(crate::reseau::scan::etats_voisins().as_ref(), box_) {
        return true;
    }
    // Un écho ICMP envoyé d'ici, sans lancer ping ; `ping` seulement si le système refuse la prise ou l'API.
    if let Some(repond) = crate::reseau::ping::echo(box_, Duration::from_secs(2)) {
        return repond;
    }
    #[cfg(target_os = "linux")]
    let essai = ["-c", "1", "-W", "2", &ip];
    #[cfg(target_os = "macos")]
    let essai = ["-c", "1", "-t", "2", &ip];
    #[cfg(windows)]
    let essai = ["-n", "1", "-w", "2000", &ip];
    lancer("ping", &essai).is_some_and(|r| ping_repond(r.code, &r.sortie, cfg!(windows)))
}

/// Linux : la box est un voisin confirmé à l'instant (REACHABLE). Une entrée périmée (STALE), en échec (FAILED),
/// incomplète, ou en cours de vérification (DELAY, PROBE) ne prouve pas qu'elle est là. Sans table (le noyau
/// refuse) : rien de prouvé, le ping décide.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn box_confirmee(voisins: Option<&std::collections::HashMap<Ipv4Addr, String>>, box_: Ipv4Addr) -> bool {
    voisins
        .and_then(|v| v.get(&box_))
        .is_some_and(|etat| etat == "REACHABLE")
}

/// `ip neigh show <adresse>` : la même chose d'après la sortie d'ip. Ne sert plus qu'à comparer netlink à ip dans
/// les tests.
#[cfg(test)]
fn voisin_confirme(sortie: &str) -> bool {
    sortie.lines().any(|l| l.split_whitespace().last() == Some("REACHABLE"))
}

/// Une réponse au ping. Celui de Windows répond 0 même quand c'est cet ordinateur qui dit « hôte inaccessible » : là,
/// seule une vraie réponse (« TTL= », dans toutes les langues) compte.
#[cfg_attr(target_os = "linux", allow(dead_code))]
fn ping_repond(code: Option<i32>, sortie: &str, windows: bool) -> bool {
    if windows {
        sortie.contains("TTL=")
    } else {
        code == Some(0)
    }
}

fn lire_etat() -> EtatReseau {
    let autoattribuee = || {
        if_addrs::get_if_addrs()
            .unwrap_or_default()
            .iter()
            .filter(|i| !i.is_loopback())
            .any(|i| matches!(&i.addr, if_addrs::IfAddr::V4(v4) if v4.ip.is_link_local()))
    };
    let adresse = match crate::reseau::scan::reseau_local() {
        Some((_, ip)) => Adresse::Locale(ip),
        None if autoattribuee() => Adresse::Autoattribuee,
        None => Adresse::Aucune,
    };
    let relie = matches!(adresse, Adresse::Locale(_));
    let passerelle = crate::reseau::scan::passerelle();
    let passerelle_repond = passerelle.is_some_and(box_repond);
    let serveurs: Vec<SocketAddr> = [[1, 1, 1, 1], [9, 9, 9, 9], [8, 8, 8, 8]]
        .iter()
        .map(|&ip| SocketAddr::from((Ipv4Addr::from(ip), 443)))
        .collect();
    EtatReseau {
        adresse,
        passerelle,
        passerelle_repond,
        internet: relie && un_seul_suffit(&serveurs, Duration::from_secs(3)),
        noms: relie && noms_resolus(),
    }
}

fn afficher_etat(e: &EtatReseau) {
    match e.adresse {
        Adresse::Locale(ip) => Etat::Bon.dire(&trf!(
            "Cet ordinateur a une adresse sur le réseau ({ip}).",
            "This computer has an address on the network ({ip})."
        )),
        Adresse::Autoattribuee => Etat::Mauvais.dire(tr!(
            "Adresse en 169.254.x.x : le routeur n'a pas donné d'adresse à cet ordinateur.",
            "Address in 169.254.x.x: the router gave no address to this computer."
        )),
        Adresse::Aucune => Etat::Mauvais.dire(tr!(
            "Cet ordinateur n'est relié à aucun réseau (câble débranché, Wi-Fi coupé, mode avion).",
            "This computer is connected to no network (cable unplugged, Wi-Fi off, airplane mode)."
        )),
    }
    if !matches!(e.adresse, Adresse::Locale(_)) {
        return;
    }
    match (e.passerelle, e.passerelle_repond) {
        (Some(b), true) => Etat::Bon.dire(&trf!("Le routeur ({b}) répond.", "The router ({b}) answers.")),
        (Some(b), false) => (if e.internet { Etat::Info } else { Etat::Mauvais }).dire(&trf!(
            "Le routeur ({b}) ne répond pas aux essais.",
            "The router ({b}) does not answer the tests."
        )),
        (None, _) => Etat::Mauvais.dire(tr!(
            "Aucun routeur (passerelle) n'est connu de cet ordinateur.",
            "No router (gateway) is known to this computer."
        )),
    }
    Etat::selon(e.internet).dire(if e.internet {
        tr!(
            "Internet répond (Cloudflare, Quad9 ou Google).",
            "The Internet answers (Cloudflare, Quad9 or Google)."
        )
    } else {
        tr!(
            "Internet ne répond pas (ni Cloudflare, ni Quad9, ni Google).",
            "The Internet does not answer (neither Cloudflare, Quad9 nor Google)."
        )
    });
    if e.internet {
        Etat::selon(e.noms).dire(if e.noms {
            tr!(
                "Les noms de sites se traduisent en adresses (DNS).",
                "Site names are translated into addresses (DNS)."
            )
        } else {
            tr!(
                "Les noms de sites ne se traduisent plus en adresses (DNS).",
                "Site names are no longer translated into addresses (DNS)."
            )
        });
    }
}

/// Le début des vérifications : les essais, puis ce qu'ils ont trouvé.
fn essais() -> EtatReseau {
    verifications();
    trp!(
        "  {DISCRET}Essais en cours (quelques secondes)…{RESET}",
        "  {DISCRET}Testing (a few seconds)…{RESET}"
    );
    let e = lire_etat();
    afficher_etat(&e);
    e
}

/// La navigation est-elle détournée (proxy imposé, fichier hosts) ? Lu par la réparation du même nom.
fn navigation_detournee() -> bool {
    crate::reparer::par_titre(titre_navigation()).is_some_and(|r| r.inutile.is_none())
}

/// Propose « Internet ne marche plus » ; sans elle sur ce système, le conseil qui la remplace.
fn reparer_le_reseau() {
    if !proposer_reparation(titre_internet()) {
        conseil(tr!(
            "Redémarrez l'ordinateur : il refait toute la connexion au réseau.",
            "Restart the computer: it redoes the whole network connection."
        ));
    }
}

fn redemarrer_la_box() {
    conseil(tr!(
        "Redémarrez le routeur : débranchez-le 30 secondes, rebranchez-le, attendez que ses voyants soient stables (deux à trois minutes). Si un voyant reste rouge ou orange, le fournisseur d'accès a sans doute une panne : regardez son site ou son application sur votre téléphone, en données mobiles.",
        "Restart the router: unplug it for 30 seconds, plug it back in, wait until its lights are steady (two to three minutes). If a light stays red or orange, the Internet provider probably has an outage: check its website or app on your phone, using mobile data."
    ));
}

/// « Pas d'Internet ».
pub(super) fn internet() {
    let Some(qui) = question(
        tr!(
            "Le problème touche-t-il aussi les autres appareils de votre domicile (téléphone en Wi-Fi, télé…) ?",
            "Does the problem also affect the other devices at home (phone on Wi-Fi, TV…)?"
        ),
        &[
            tr!("Oui, tous les appareils", "Yes, all devices"),
            tr!("Non, seulement cet ordinateur", "No, only this computer"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    let Some(depuis) = question(
        tr!("Depuis quand ?", "Since when?"),
        &[
            tr!("Tout d'un coup", "All of a sudden"),
            tr!(
                "Depuis une mise à jour ou un nouveau programme",
                "Since an update or a new program"
            ),
            tr!("Ça va et ça vient", "It comes and goes"),
        ],
    ) else {
        return;
    };
    let e = essais();
    let detournee = e.internet && navigation_detournee();
    if e.internet {
        Etat::selon(!detournee).dire(if detournee {
            tr!(
                "Un proxy ou le fichier hosts détourne la navigation.",
                "A proxy or the hosts file hijacks browsing."
            )
        } else {
            tr!(
                "Navigation non détournée (ni proxy imposé, ni fichier hosts modifié).",
                "Browsing not hijacked (no forced proxy, no modified hosts file)."
            )
        });
    }
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    let tous = qui == 0;
    match panne(&e) {
        Panne::PasConnecte => {
            Etat::Info.dire(tr!(
                "Cet ordinateur n'est pas sur le réseau : rebranchez le câble, ou rallumez le Wi-Fi (touche ou bouton « avion ») et choisissez votre réseau.",
                "This computer is not on the network: plug the cable back in, or turn Wi-Fi back on (airplane key or button) and choose your network."
            ));
            reparer_le_reseau();
        }
        Panne::PasDAdresse => {
            Etat::Info.dire(tr!(
                "Le routeur ne donne plus d'adresse : souvent, il est planté.",
                "The router no longer gives addresses: often, it has crashed."
            ));
            redemarrer_la_box();
            reparer_le_reseau();
        }
        Panne::BoxMuette if tous => {
            Etat::Info.dire(tr!(
                "Rien ne passe par le routeur, pour aucun appareil : c'est le routeur.",
                "Nothing goes through the router, for any device: it is the router."
            ));
            redemarrer_la_box();
        }
        Panne::BoxMuette => {
            Etat::Info.dire(tr!(
                "Cet ordinateur ne joint pas le routeur.",
                "This computer cannot reach the router."
            ));
            reparer_le_reseau();
        }
        Panne::InternetCoupe if tous => {
            Etat::Info.dire(tr!(
                "Le routeur répond, mais Internet ne passe pas : panne chez le fournisseur d'accès, ou routeur à redémarrer.",
                "The router answers, but the Internet does not get through: outage at the Internet provider, or router to restart."
            ));
            redemarrer_la_box();
        }
        Panne::InternetCoupe => {
            Etat::Info.dire(tr!(
                "Le routeur répond, mais cet ordinateur ne sort pas sur Internet : un VPN, un pare-feu ou un proxy l'en empêche peut-être.",
                "The router answers, but this computer does not get out to the Internet: a VPN, a firewall or a proxy may prevent it."
            ));
            reparer_le_reseau();
        }
        Panne::Noms => {
            Etat::Info.dire(tr!(
                "Internet répond, mais les noms de sites ne se traduisent plus : le DNS est en panne ou mal réglé.",
                "The Internet answers, but site names are no longer translated: DNS is down or misconfigured."
            ));
            conseil(tr!(
                "Un DNS public (Cloudflare 1.1.1.1, Quad9 9.9.9.9) se règle dans le routeur, ou sur cet ordinateur.",
                "A public DNS (Cloudflare 1.1.1.1, Quad9 9.9.9.9) can be set in the router, or on this computer."
            ));
            reparer_le_reseau();
        }
        Panne::Aucune if detournee => {
            Etat::Info.dire(tr!(
                "Internet marche, mais la navigation est détournée : des sites ne s'ouvrent pas, ou pas les vrais.",
                "The Internet works, but browsing is hijacked: some sites do not open, or not the real ones."
            ));
            proposer_reparation(titre_navigation());
        }
        Panne::Aucune => {
            Etat::Bon.dire(tr!(
                "Internet marche depuis cet ordinateur, en ce moment.",
                "The Internet works from this computer, right now."
            ));
            conseil(tr!(
                "Si un site ne s'ouvre pas, essayez un autre navigateur : s'il s'ouvre, une extension ou le cache du premier est en cause. Si c'était passager, le test de connexion (Réseau et Internet) mesure les pertes et les coupures.",
                "If a site does not open, try another browser: if it opens, an extension or the cache of the first one is to blame. If it was temporary, the connection test (Network and Internet) measures losses and drops."
            ));
        }
    }
    if depuis == 1 {
        conseil(tr!(
            "Depuis un nouveau programme : un VPN, un antivirus ou un « optimiseur » coupe parfois Internet. Le désactiver un moment dit si c'est lui.",
            "Since a new program: a VPN, an antivirus or an “optimizer” sometimes cuts the Internet. Turning it off for a moment tells whether it is the culprit."
        ));
    }
    if depuis == 2 {
        conseil(tr!(
            "Coupures par moments : en Wi-Fi, le parcours « Le Wi-Fi coupe » regarde le signal ; le test de connexion mesure les pertes.",
            "Drops at times: on Wi-Fi, the “Wi-Fi keeps dropping” path looks at the signal; the connection test measures losses."
        ));
    }
}

/// Internet lent, depuis le parcours « L'ordinateur est lent » : la connexion marche-t-elle, puis où mesurer.
pub(super) fn internet_lent() {
    let e = essais();
    let s = match signal() {
        Ok(s) => s,
        Err(r) => {
            Etat::Info.dire(&signal_non_verifie(r));
            None
        }
    };
    if let Some(s) = &s {
        afficher_signal(s);
    }
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    if panne(&e) == Panne::Aucune {
        conseil(tr!(
            "La connexion marche. Pour savoir si elle est lente, et pourquoi : le test de connexion (Optimiser et installer › Test de connexion) mesure le débit, le ping et le bufferbloat (la lenteur quand quelqu'un télécharge).",
            "The connection works. To know whether it is slow, and why: the connection test (Optimize and install › Connection test) measures speed, ping and bufferbloat (the slowness when someone downloads)."
        ));
        if s.is_some_and(|s| s.qualite < 60) {
            conseil(tr!(
                "Le signal Wi-Fi est moyen ou faible : il ralentit tout. Le parcours « Le Wi-Fi coupe » dit quoi faire.",
                "The Wi-Fi signal is average or weak: it slows everything down. The “Wi-Fi keeps dropping” path says what to do."
            ));
        }
    } else {
        conseil(tr!(
            "Ce n'est pas de la lenteur : la connexion a un vrai problème. Le parcours « Pas d'Internet » le trouve.",
            "This is not slowness: the connection has a real problem. The “No Internet” path finds it."
        ));
    }
}

/// Le Wi-Fi de la connexion en cours.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Signal {
    /// Qualité du signal, de 0 à 100.
    pub qualite: u8,
    pub canal: Option<u32>,
    /// D'après la fréquence ou ce que dit le système, pas le seul numéro du canal : le 6 GHz reprend les petits
    /// numéros du 2,4 GHz.
    pub bande: Option<Bande>,
    /// Économie d'énergie de la carte Wi-Fi ; `None` : inconnue.
    pub economie: Option<bool>,
}

/// `system_profiler SPAirPortDataType` (macOS) : « Signal / Noise: -58 dBm / -94 dBm » et « Channel: 36 (5GHz,
/// 80MHz) » du réseau en cours (le premier bloc). Qualité : 2 × (dBm + 100), bornée à 0-100, l'usage courant.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn signal_airport(texte: &str) -> Option<Signal> {
    let en_cours = texte.split("Current Network Information:").nth(1)?;
    let dbm: i32 = en_cours
        .lines()
        .find_map(|l| l.trim().strip_prefix("Signal / Noise:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()?;
    let qualite = u8::try_from((2 * (dbm + 100)).clamp(0, 100)).ok()?;
    // « Channel: 37 (6GHz, 160MHz) » : le numéro, puis la bande entre parenthèses.
    let canal = en_cours.lines().find_map(|l| l.trim().strip_prefix("Channel:"));
    Some(Signal {
        qualite,
        canal: canal.and_then(|v| v.split_whitespace().next()?.parse().ok()),
        bande: canal
            .and_then(|v| v.split_once('('))
            .and_then(|(_, b)| Bande::de_texte(b)),
        economie: None,
    })
}

/// Les cartes Wi-Fi : le noyau donne un dossier « wireless » à chacune dans /sys/class/net (ce que listait
/// `iw dev`). Triées, pour que la première soit toujours la même.
#[cfg(target_os = "linux")]
fn cartes_wifi(dossier: &std::path::Path) -> Vec<String> {
    let mut cartes: Vec<String> = std::fs::read_dir(dossier)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().join("wireless").is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    cartes.sort();
    cartes
}

/// `/proc/net/wireless` : deux lignes d'en-tête, puis « wlan0: 0000   47.  -63.  -256 … » (état, qualité du
/// lien, niveau, bruit). Le noyau n'y met une carte que pendant qu'elle est connectée à une borne. Rend la
/// carte et son niveau en dBm ; un niveau positif n'est pas en dBm (pilote sans mesure) : ignoré.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn niveau_wifi(texte: &str, cartes: &[String]) -> Option<(String, i32)> {
    texte.lines().skip(2).find_map(|l| {
        let (nom, reste) = l.split_once(':')?;
        let nom = nom.trim();
        if !cartes.iter().any(|c| c == nom) {
            return None;
        }
        let niveau: i32 = reste.split_whitespace().nth(2)?.trim_end_matches('.').parse().ok()?;
        (niveau < 0).then(|| (nom.to_string(), niveau))
    })
}

/// Le pourcentage que montrait nmcli, avec la formule de NetworkManager : −40 dBm et mieux → 100 %,
/// −100 dBm → 0 %, en ligne droite entre les deux. La garder laisse les seuils (40 %, 60 %) où ils étaient.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn qualite_de_dbm(dbm: i32) -> u8 {
    let ecart = -(dbm.clamp(-100, -40) + 40);
    u8::try_from((100 - ecart * 100 / 60).clamp(0, 100)).unwrap_or(0)
}

/// La fréquence d'une réponse SIOCGIWFREQ, en MHz : m × 10^e hertz. Un petit nombre avec e = 0 est un numéro
/// de canal (vieux pilotes), pas une fréquence : il ne se convertit pas sans connaître la bande.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn mhz_de(m: i32, e: i16) -> Option<u32> {
    if e == 0 && m < 1000 {
        return None;
    }
    let m = u64::try_from(m).ok()?;
    let e = u32::try_from(e).ok()?;
    let hz = m.checked_mul(10u64.checked_pow(e)?)?;
    u32::try_from(hz / 1_000_000).ok().filter(|&f| f > 0)
}

/// La fréquence de la borne connectée, demandée au noyau (SIOCGIWFREQ, que cfg80211 sert à toute carte
/// récente), sans lancer nmcli ni iw.
#[cfg(target_os = "linux")]
fn frequence_wifi(carte: &str) -> Option<u32> {
    const SIOCGIWFREQ: libc::Ioctl = 0x8B05;
    // SAFETY: iwreq est une structure C de nombres et d'unions de nombres : tout à zéro est une valeur valide.
    let mut demande: libc::iwreq = unsafe { std::mem::zeroed() };
    let nom = carte.as_bytes();
    if nom.len() >= libc::IFNAMSIZ {
        return None;
    }
    // SAFETY: on écrit dans le seul champ de l'union, un tableau de IFNAMSIZ octets ; le nom, plus court, y
    // laisse au moins un zéro final.
    unsafe {
        for (case, octet) in demande.ifr_ifrn.ifrn_name.iter_mut().zip(nom) {
            *case = libc::c_char::from_ne_bytes([*octet]);
        }
    }
    // SAFETY: une socket ouverte ici et refermée une seule fois ; ioctl reçoit un pointeur vers la demande, à
    // nous et vivante pendant l'appel, de la taille qu'attend SIOCGIWFREQ. Lire le champ freq après coup est
    // sûr : l'union ne contient que des nombres.
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if s < 0 {
            return None;
        }
        let r = libc::ioctl(s, SIOCGIWFREQ, &raw mut demande);
        libc::close(s);
        if r < 0 {
            return None;
        }
        mhz_de(demande.u.freq.m, demande.u.freq.e)
    }
}

/// Le Wi-Fi connecté, lu sans commande : /proc/net/wireless pour le niveau, le noyau pour la fréquence. Rend
/// aussi la carte, pour l'économie d'énergie.
#[cfg(target_os = "linux")]
fn signal_natif() -> Option<(String, Signal)> {
    let cartes = cartes_wifi(std::path::Path::new("/sys/class/net"));
    let (carte, dbm) = niveau_wifi(&std::fs::read_to_string("/proc/net/wireless").ok()?, &cartes)?;
    let mhz = frequence_wifi(&carte);
    let signal = Signal {
        qualite: qualite_de_dbm(dbm),
        canal: mhz.and_then(crate::machine::wifi::canal_de_frequence).map(u32::from),
        bande: mhz.and_then(Bande::de_frequence),
        economie: None,
    };
    Some((carte, signal))
}

/// Le Wi-Fi de la connexion en cours. `Ok(None)` : pas connecté ; `Err` : le système ne se laisse pas lire (pas
/// connecté n'est alors pas prouvé). Seul Windows peut refuser (sans la localisation) ; Linux et macOS se taisent.
#[cfg_attr(not(windows), allow(clippy::unnecessary_wraps))]
fn signal() -> Result<Option<Signal>, &'static str> {
    #[cfg(target_os = "linux")]
    {
        let natif = signal_natif();
        // NetworkManager seulement en secours : carte absente de /proc/net/wireless (autre espace réseau, pilote sans
        // WEXT) ou fréquence inconnue, sans quoi le conseil sur la bande disparaîtrait.
        let s = match natif.as_ref().filter(|(_, s)| s.canal.is_some()) {
            Some((_, s)) => Some(s.clone()),
            None => signal_networkmanager().or_else(|| natif.as_ref().map(|(_, s)| s.clone())),
        };
        let Some(mut s) = s else {
            return Ok(None);
        };
        // La carte connectée, sinon la première ; son économie d'énergie, demandée au noyau comme iw le fait.
        let carte = natif
            .map(|(c, _)| c)
            .or_else(|| cartes_wifi(std::path::Path::new("/sys/class/net")).into_iter().next());
        s.economie = carte.and_then(|c| crate::machine::wifi::nl80211::economie_d_energie(&c));
        Ok(Some(s))
    }
    #[cfg(windows)]
    {
        Ok(crate::machine::wifi::wlanapi::connexion()?.and_then(|c| signal_de_connexion(&c)))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(crate::commande::lancer(
            std::process::Command::new("system_profiler").arg("SPAirPortDataType"),
            30,
        )
        .and_then(|r| signal_airport(&r.sortie)))
    }
}

/// Le signal d'une connexion lue nativement (Windows, NetworkManager) : sa qualité (sans elle, rien à montrer), son
/// canal et sa bande.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn signal_de_connexion(c: &crate::machine::wifi::Connexion) -> Option<Signal> {
    Some(Signal {
        qualite: c.qualite?,
        canal: c.canal.map(u32::from),
        bande: c.bande.or_else(|| c.canal.and_then(Bande::de_canal)),
        economie: None,
    })
}

/// NetworkManager, sur le bus : la force de la borne connectée, le pourcentage même que montrait nmcli, d'où les
/// mêmes seuils (40 %, 60 %).
#[cfg(target_os = "linux")]
fn signal_networkmanager() -> Option<Signal> {
    let l = crate::machine::wifi::networkmanager::lire().ok()??;
    signal_de_connexion(l.connexion.as_ref()?)
}

fn signal_non_verifie(raison: &str) -> String {
    trf!(
        "Signal Wi-Fi non vérifié : {raison}.",
        "Wi-Fi signal not verified: {raison}."
    )
}

fn afficher_signal(s: &Signal) {
    let (etat, texte) = match s.qualite {
        60.. => (
            Etat::Bon,
            trf!("Signal Wi-Fi bon ({} %).", "Good Wi-Fi signal ({}%).", s.qualite),
        ),
        40..60 => (
            Etat::Info,
            trf!("Signal Wi-Fi moyen ({} %).", "Average Wi-Fi signal ({}%).", s.qualite),
        ),
        _ => (
            Etat::Mauvais,
            trf!("Signal Wi-Fi faible ({} %).", "Weak Wi-Fi signal ({}%).", s.qualite),
        ),
    };
    etat.dire(&texte);
    if let (Some(c), Some(b)) = (s.canal, s.bande) {
        Etat::Info.dire(&if b == Bande::G24 {
            trf!(
                "Bande {}, canal {c} : elle porte loin et traverse les murs, mais elle est plus lente et plus encombrée.",
                "{} band, channel {c}: it reaches far and goes through walls, but it is slower and more crowded.",
                b.libelle()
            )
        } else {
            trf!(
                "Bande {}, canal {c} : rapide, mais elle porte moins loin et traverse mal les murs.",
                "{} band, channel {c}: fast, but it reaches less far and goes poorly through walls.",
                b.libelle()
            )
        });
    }
    if s.economie == Some(true) {
        Etat::Info.dire(tr!(
            "Économie d'énergie du Wi-Fi activée : elle peut couper la connexion après un moment sans activité ou après la veille.",
            "Wi-Fi power saving is on: it can cut the connection after a while without activity or after sleep."
        ));
    }
}

/// Couper l'économie d'énergie de la carte Wi-Fi, sur ce système.
fn economie_d_energie() -> &'static str {
    if cfg!(windows) {
        tr!(
            "Gestionnaire de périphériques › Cartes réseau › votre carte Wi-Fi › Gestion de l'alimentation : décochez « Autoriser l'ordinateur à éteindre ce périphérique pour économiser l'énergie ».",
            "Device Manager › Network adapters › your Wi-Fi card › Power Management: uncheck “Allow the computer to turn off this device to save power”."
        )
    } else if cfg!(target_os = "macos") {
        tr!(
            "Réglages Système › Wi-Fi › Détails du réseau : « Oublier ce réseau », puis s'y reconnecter ; et garder macOS à jour, qui corrige souvent ces coupures.",
            "System Settings › Wi-Fi › network Details: “Forget This Network”, then reconnect; and keep macOS up to date, which often fixes these drops."
        )
    } else {
        tr!(
            "Avec NetworkManager : un fichier /etc/NetworkManager/conf.d/wifi-economie.conf contenant les deux lignes « [connection] » et « wifi.powersave = 2 », puis redémarrer NetworkManager. Supprimer ce fichier remet comme avant.",
            "With NetworkManager: a file /etc/NetworkManager/conf.d/wifi-powersave.conf with the two lines “[connection]” and “wifi.powersave = 2”, then restart NetworkManager. Deleting this file puts things back."
        )
    }
}

/// « Le Wi-Fi coupe ».
pub(super) fn wifi() {
    let Some(quand) = question(
        tr!("Quand le Wi-Fi coupe-t-il ?", "When does Wi-Fi drop?"),
        &[
            tr!("Au hasard, même près du routeur", "Randomly, even near the router"),
            tr!("Quand je m'éloigne du routeur", "When I move away from the router"),
            tr!("Après la mise en veille", "After sleep"),
            tr!("Il ne se connecte plus du tout", "It no longer connects at all"),
        ],
    ) else {
        return;
    };
    let Some(autres) = question(
        tr!(
            "Les autres appareils en Wi-Fi coupent-ils aussi ?",
            "Do the other devices on Wi-Fi drop too?"
        ),
        &[
            tr!("Oui", "Yes"),
            tr!("Non, seulement cet ordinateur", "No, only this computer"),
            tr!("Je ne sais pas", "I don't know"),
        ],
    ) else {
        return;
    };
    verifications();
    trp!(
        "  {DISCRET}Lecture du Wi-Fi et essais (quelques secondes)…{RESET}",
        "  {DISCRET}Reading Wi-Fi and testing (a few seconds)…{RESET}"
    );
    let s = match signal() {
        Ok(Some(s)) => {
            afficher_signal(&s);
            Some(s)
        }
        Ok(None) => {
            Etat::Mauvais.dire(tr!(
                "Cet ordinateur n'est connecté à aucun Wi-Fi en ce moment.",
                "This computer is not connected to any Wi-Fi right now."
            ));
            None
        }
        // Illisible n'est pas « pas connecté » : dit tel quel, sans conclure.
        Err(r) => {
            Etat::Info.dire(&signal_non_verifie(r));
            None
        }
    };
    let e = lire_etat();
    afficher_etat(&e);
    section(tr!("CE QUE ÇA VEUT DIRE", "WHAT IT MEANS"));
    let faible = s.as_ref().is_some_and(|s| s.qualite < 40);
    if autres == 0 {
        conseil(tr!(
            "Tous les appareils coupent : le routeur est en cause (surchauffe, canal encombré par les voisins, logiciel du routeur). Redémarrez-le ; si ça revient, changez son canal Wi-Fi (le moins encombré, d'après l'outil des canaux Wi-Fi de Réseau et Internet) et cherchez une mise à jour du routeur.",
            "All devices drop: the router is to blame (overheating, channel crowded by the neighbors, router software). Restart it; if it comes back, change its Wi-Fi channel (the least crowded, according to the Wi-Fi channels tool in Network and Internet) and look for a router update."
        ));
    }
    if faible || quand == 1 {
        conseil(tr!(
            "Signal trop faible là où vous êtes : rapprochez-vous, mettez le routeur en hauteur, loin du micro-ondes et des murs épais. Un répéteur ou un Wi-Fi maillé (mesh) l'étend. Près du routeur, la bande 5 GHz est plus rapide ; loin, la 2,4 GHz porte mieux.",
            "Signal too weak where you are: move closer, put the router up high, away from the microwave and thick walls. A repeater or a mesh Wi-Fi extends it. Near the router, the 5 GHz band is faster; far away, 2.4 GHz reaches better."
        ));
    }
    if quand == 2 || s.as_ref().is_some_and(|s| s.economie == Some(true)) {
        conseil(economie_d_energie());
    }
    if quand == 3 {
        conseil(tr!(
            "Il ne se connecte plus : oubliez le réseau dans les réglages du Wi-Fi, puis reconnectez-vous avec le mot de passe (il a peut-être changé sur le routeur).",
            "It no longer connects: forget the network in the Wi-Fi settings, then reconnect with the password (it may have changed on the router)."
        ));
    }
    if quand == 0 && autres == 1 {
        conseil(tr!(
            "Au hasard, et seulement cet ordinateur : la carte Wi-Fi ou son pilote. Mettez à jour les pilotes, et coupez l'économie d'énergie du Wi-Fi.",
            "Randomly, and only this computer: the Wi-Fi card or its driver. Update the drivers, and turn off Wi-Fi power saving."
        ));
        if quand != 2 {
            conseil(economie_d_energie());
        }
        proposer_outil(
            tr!(
                "\n  Chercher les mises à jour (pilotes compris) ? [o/N] : ",
                "\n  Look for updates (drivers included)? [y/N]: "
            ),
            crate::maj::executer,
        );
    }
    if autres != 0 {
        reparer_le_reseau();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICI: Adresse = Adresse::Locale(Ipv4Addr::new(192, 168, 1, 20));

    fn etat(adresse: Adresse, box_: bool, internet: bool, noms: bool) -> EtatReseau {
        EtatReseau {
            adresse,
            passerelle: Some(Ipv4Addr::new(192, 168, 1, 1)),
            passerelle_repond: box_,
            internet,
            noms,
        }
    }

    #[test]
    fn ou_la_connexion_s_arrete() {
        assert_eq!(panne(&etat(Adresse::Aucune, false, false, false)), Panne::PasConnecte);
        assert_eq!(
            panne(&etat(Adresse::Autoattribuee, false, false, false)),
            Panne::PasDAdresse
        );
        assert_eq!(panne(&etat(ICI, false, false, false)), Panne::BoxMuette);
        assert_eq!(panne(&etat(ICI, true, false, false)), Panne::InternetCoupe);
        assert_eq!(panne(&etat(ICI, true, true, false)), Panne::Noms);
        assert_eq!(panne(&etat(ICI, true, true, true)), Panne::Aucune);
        // Une box qui ne répond pas aux essais mais laisse passer Internet : rien à signaler.
        assert_eq!(panne(&etat(ICI, false, true, true)), Panne::Aucune);
    }

    #[test]
    fn signal_lu_partout() {
        use crate::machine::wifi::Connexion;
        // Windows et NetworkManager : la connexion lue nativement ; sans qualité, rien à montrer.
        let c = Connexion {
            ssid: "Salon".into(),
            qualite: Some(72),
            canal: Some(36),
            ..Connexion::default()
        };
        assert_eq!(
            signal_de_connexion(&c),
            Some(Signal {
                qualite: 72,
                canal: Some(36),
                bande: Some(Bande::G5),
                economie: None
            })
        );
        assert_eq!(
            signal_de_connexion(&Connexion {
                qualite: None,
                ..c.clone()
            }),
            None
        );
        let airport = "Wi-Fi:\n  Interfaces:\n    en0:\n      Current Network Information:\n        Salon:\n          Channel: 36 (5GHz, 80MHz)\n          Signal / Noise: -58 dBm / -94 dBm\n      Other Local Wi-Fi Networks:\n          Signal / Noise: -80 dBm / -94 dBm\n";
        assert_eq!(
            signal_airport(airport).map(|s| (s.qualite, s.canal)),
            Some((84, Some(36)))
        );
        assert_eq!(signal_airport(airport).and_then(|s| s.bande), Some(Bande::G5));
        assert!(signal_non_verifie("x").contains('x'));
    }

    /// En 6 GHz (Wi-Fi 6E et 7), les canaux reprennent les petits numéros : le canal 5 n'est pas du 2,4 GHz. La bande
    /// vient de la fréquence ou de la borne (Linux, Windows), sinon du texte du canal (macOS).
    #[test]
    fn six_ghz_pas_pris_pour_du_2_4() {
        let c = crate::machine::wifi::Connexion {
            qualite: Some(80),
            canal: Some(5),
            bande: Some(Bande::G6),
            ..crate::machine::wifi::Connexion::default()
        };
        assert_eq!(signal_de_connexion(&c).and_then(|s| s.bande), Some(Bande::G6));
        let airport = "      Current Network Information:\n        Salon:\n          Channel: 37 (6GHz, 160MHz)\n          Signal / Noise: -50 dBm / -94 dBm\n";
        assert_eq!(signal_airport(airport).and_then(|s| s.bande), Some(Bande::G6));
    }

    /// Une entrée de voisin périmée, en échec ou incomplète ne dit pas que la box répond ; seule REACHABLE compte.
    #[test]
    fn voisin_confirme_seulement() {
        let ligne = |etat: &str| format!("192.168.1.1 dev wlan0 lladdr 02:00:00:aa:bb:01 {etat}\n");
        assert!(voisin_confirme(&ligne("REACHABLE")));
        assert!(voisin_confirme(&ligne("router REACHABLE")));
        for etat in ["STALE", "FAILED", "DELAY", "PROBE"] {
            assert!(!voisin_confirme(&ligne(etat)), "{etat}");
        }
        assert!(!voisin_confirme("192.168.1.1 dev wlan0 INCOMPLETE\n"));
        assert!(!voisin_confirme(""));
    }

    /// La table du noyau, inventée : seule une box REACHABLE est confirmée ; sans table, rien n'est prouvé.
    #[test]
    fn box_confirmee_par_le_noyau() {
        let box_ = Ipv4Addr::new(192, 168, 1, 1);
        let table = |etat: &str| std::collections::HashMap::from([(box_, etat.to_string())]);
        assert!(box_confirmee(Some(&table("REACHABLE")), box_));
        for etat in ["STALE", "FAILED", "DELAY", "PROBE", "INCOMPLETE"] {
            assert!(!box_confirmee(Some(&table(etat)), box_), "{etat}");
        }
        assert!(!box_confirmee(
            Some(&table("REACHABLE")),
            Ipv4Addr::new(192, 168, 1, 254)
        ));
        assert!(!box_confirmee(None, box_));
    }

    /// Sur cet ordinateur, netlink et `ip neigh` voient les mêmes voisins ; une box qu'ip dit confirmée est,
    /// d'après netlink, confirmée ou dans un état qui suit (le noyau a pu la revérifier entre les deux).
    #[cfg(target_os = "linux")]
    #[test]
    fn box_comme_ip() {
        let Some(r) = crate::commande::lancer(std::process::Command::new("ip").args(["-4", "neigh", "show"]), 5)
            .filter(|r| r.code == Some(0))
        else {
            return crate::essais::saute("ip absent");
        };
        let Some(natifs) = crate::reseau::scan::etats_voisins() else {
            return crate::essais::saute("voisins illisibles par netlink");
        };
        for ligne in r.sortie.lines().filter(|l| voisin_confirme(l)) {
            let Some(ip) = ligne.split_whitespace().next().and_then(|i| i.parse::<Ipv4Addr>().ok()) else {
                continue;
            };
            let etat = natifs.get(&ip).map(String::as_str);
            assert!(
                box_confirmee(Some(&natifs), ip) || matches!(etat, Some("STALE" | "DELAY" | "PROBE")),
                "{ligne} / {etat:?}"
            );
        }
    }

    /// /proc/net/wireless inventé : la carte connectée et son niveau en dBm ; une carte inconnue de
    /// /sys/class/net ou un niveau positif (pas des dBm) ne comptent pas.
    #[test]
    fn niveau_du_wifi_connecte() {
        let entete = "Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE\n \
                      face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22\n";
        let texte = format!("{entete}wlan0: 0000   47.  -63.  -256        0      0      0     18      0        0\n");
        let cartes = vec!["wlan0".to_string()];
        assert_eq!(niveau_wifi(&texte, &cartes), Some(("wlan0".into(), -63)));
        assert_eq!(niveau_wifi(&texte, &["wlan1".to_string()]), None);
        assert_eq!(niveau_wifi(entete, &cartes), None);
        let sans_dbm = format!("{entete}wlan0: 0000   60    55     0        0      0      0      0      0        0\n");
        assert_eq!(niveau_wifi(&sans_dbm, &cartes), None);
    }

    /// La formule de NetworkManager : −40 dBm et mieux → 100 %, −100 dBm et moins → 0 %.
    #[test]
    fn qualite_comme_networkmanager() {
        assert_eq!(qualite_de_dbm(-30), 100);
        assert_eq!(qualite_de_dbm(-40), 100);
        assert_eq!(qualite_de_dbm(-64), 60);
        assert_eq!(qualite_de_dbm(-76), 40);
        assert_eq!(qualite_de_dbm(-100), 0);
        assert_eq!(qualite_de_dbm(-120), 0);
    }

    /// Une réponse SIOCGIWFREQ : 5180 × 10^6 Hz (cfg80211), 2,412 × 10^9 écrit autrement, un numéro de canal.
    #[test]
    fn frequence_de_la_reponse() {
        assert_eq!(mhz_de(5180, 6), Some(5180));
        assert_eq!(mhz_de(2_412_000, 3), Some(2412));
        assert_eq!(mhz_de(241_200_000, 1), Some(2412));
        assert_eq!(mhz_de(36, 0), None);
        assert_eq!(mhz_de(-5, 6), None);
        assert_eq!(mhz_de(5180, -1), None);
    }

    /// Les cartes Wi-Fi d'un /sys/class/net inventé : seules celles qui ont un dossier « wireless ».
    #[cfg(target_os = "linux")]
    #[test]
    fn cartes_wifi_selon_sys() {
        let d = std::env::temp_dir().join(format!("vanguard-cartes-wifi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for chemin in ["wlan1/wireless", "eth0", "wlan0/wireless", "lo"] {
            std::fs::create_dir_all(d.join(chemin)).unwrap();
        }
        assert_eq!(cartes_wifi(&d), ["wlan0", "wlan1"]);
        assert_eq!(cartes_wifi(&d.join("absent")), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Sur cet ordinateur, connecté en Wi-Fi, la lecture directe donne le canal et la bande de NetworkManager, et une
    /// qualité proche : NetworkManager prend le niveau du dernier balayage, /proc celui du lien à l'instant. Sauté
    /// sans l'un ou l'autre.
    #[cfg(target_os = "linux")]
    #[test]
    fn signal_comme_networkmanager() {
        let (Some(nm), Some((_, natif))) = (signal_networkmanager(), signal_natif()) else {
            return crate::essais::saute("signal Wi-Fi illisible (NetworkManager ou natif)");
        };
        assert_eq!((natif.canal, natif.bande), (nm.canal, nm.bande));
        assert!(
            natif.qualite.abs_diff(nm.qualite) <= 20,
            "{} / {}",
            natif.qualite,
            nm.qualite
        );
    }

    /// Le ping de Windows rend 0 quand cet ordinateur répond lui-même « hôte inaccessible » : seule une réponse avec
    /// « TTL= » compte. Ailleurs, le code de retour suffit.
    #[test]
    fn reponse_au_ping() {
        let inaccessible = "Réponse de 192.168.1.20 : Impossible de joindre l'hôte de destination.\r\n";
        assert!(!ping_repond(Some(0), inaccessible, true));
        let reponse = "Reply from 192.168.1.1: bytes=32 time<1ms TTL=64\r\n";
        assert!(ping_repond(Some(0), reponse, true));
        assert!(ping_repond(Some(0), "", false));
        assert!(!ping_repond(Some(1), "", false));
        assert!(!ping_repond(None, "", false));
    }
}

/// Propriétés des lectures du dépannage, sur des sorties tirées au hasard : rien ne plante ; seule une entrée
/// REACHABLE confirme la box ; un signal lu reste entre 0 et 100.
#[cfg(test)]
mod proprietes {
    use super::*;
    use proptest::prelude::*;

    fn sortie() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop_oneof![
                any::<String>(),
                "[ -~\\t\u{1b}:%()*]{0,60}",
                "\\*?:[0-9]{0,4}:[0-9 MHz]{0,10}:[0-9]{0,4}",
                " *(Signal|Channel|Canal|Band|Bande|Signal / Noise|Channel) ?: ?[ -~]{0,20}",
            ],
            0..10,
        )
        .prop_map(|l| l.join("\n"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

        #[test]
        fn lectures_sans_plantage(t in sortie()) {
            // system_profiler dit des dBm, ramenés à 0-100.
            if let Some(s) = signal_airport(&t) {
                prop_assert!(s.qualite <= 100);
            }
            let _ = voisin_confirme(&t);
        }

        #[test]
        fn seul_reachable_confirme(etat in "(REACHABLE|STALE|FAILED|INCOMPLETE|DELAY|PROBE|PERMANENT|NOARP|router REACHABLE)", mac in "([0-9a-f]{2}:){5}[0-9a-f]{2}") {
            let ligne = format!("192.168.1.1 dev wlan0 lladdr {mac} {etat}\n");
            prop_assert_eq!(voisin_confirme(&ligne), etat.ends_with("REACHABLE"));
        }

        #[test]
        fn signal_airport_borne(dbm in -200i32..100) {
            let texte = format!("      Current Network Information:\n        Salon:\n          Channel: 36 (5GHz, 80MHz)\n          Signal / Noise: {dbm} dBm / -94 dBm\n");
            let s = signal_airport(&texte).unwrap();
            prop_assert!(s.qualite <= 100);
            prop_assert_eq!(s.bande, Some(Bande::G5));
        }
    }
}
