//! Domaine Exposition de l'audit du réseau : ce que la maison montre à Internet. Quatre règles, d'après le scan du
//! réseau (ses appareils et leurs ports, ce que la box a répondu en UPnP), l'adresse vue d'Internet quand elle a
//! été mesurée (STUN, `nat::mesurer`) et l'IPv6 de cet ordinateur (`ipv6`). Fonction pure : tout est lu avant,
//! dans `Entree` ; rien n'est sondé ici. Ce qui ne peut pas se lire d'ici (le pare-feu IPv6 de la box, son
//! administration à distance, les redirections réglées à la main) est dit, jamais compté sain.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::audit::{igd, ipv6};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::reseau::upnp::{self, Etat};
use crate::reseau::{Hote, Rapport};
use crate::risk::{Niveau, info_port};
use crate::ui::*;

/// La catégorie des constats du domaine. Son nom anglais (« Exposure ») s'ajoute à `langue::categorie_en` avec les
/// autres catégories de l'audit du réseau, dans le squelette de l'audit ; d'ici là, l'interface anglaise montre
/// ce nom.
pub const CATEGORIE: &str = "Exposition";

/// Ports internes dont l'ouverture depuis Internet est critique : prise de contrôle ou fichiers (telnet, SMB, RDP,
/// VNC, SSH, FTP, Docker, ADB).
const PORTS_CRITIQUES: [u16; 8] = [23, 445, 3389, 5900, 22, 21, 2375, 5555];

/// Ports de la box jugés côté réseau local (COM-EXP-004) : telnet, FTP, web, TR-069, SNMP, SSDP, IGD, SSH.
const PORTS_BOX: [u16; 8] = [23, 21, 80, 7547, 161, 1900, 49152, 22];

/// L'adresse vue d'Internet, mesurée par STUN (`nat::mesurer`) ; `None` dans un champ : pas de réponse par là.
#[derive(Debug, Clone, Copy, Default)]
pub struct Internet {
    pub v4: Option<IpAddr>,
    pub v6: Option<IpAddr>,
}

/// Ce que les règles lisent. Le squelette de l'audit le remplit depuis son contexte ; le scan du réseau, depuis son
/// seul rapport (`du_scan`).
pub struct Entree<'a> {
    /// Le scan : ses appareils avec leurs ports, les absents du carnet, et la réponse UPnP de la box (`upnp`).
    pub rapport: &'a Rapport,
    pub passerelle: Option<Ipv4Addr>,
    /// L'adresse de cet ordinateur sur le réseau local.
    pub locale: Option<Ipv4Addr>,
    /// L'adresse vue d'Internet ; `None` : pas mesurée (un scan ne demande rien à Internet).
    pub internet: Option<Internet>,
    pub ipv6: ipv6::Lecture,
    /// Le pare-feu de cet ordinateur est actif, d'après le constat `*-PFE-001` du bilan ; `None` : non lu.
    pub pare_feu_local: Option<bool>,
}

impl<'a> Entree<'a> {
    /// D'après le scan seul : la passerelle et l'adresse locale du système, l'IPv6 lue ici ; sans STUN (rien n'est
    /// demandé à Internet pendant un scan) ni pare-feu.
    pub fn du_scan(rapport: &'a Rapport) -> Entree<'a> {
        Entree {
            rapport,
            passerelle: crate::reseau::scan::passerelle(),
            locale: crate::reseau::scan::reseau_local().map(|(_, ip)| ip),
            internet: None,
            ipv6: ipv6::lire(),
            pare_feu_local: None,
        }
    }

    fn hote(&self, ip: Ipv4Addr) -> Option<&Hote> {
        self.rapport.hotes.iter().find(|h| h.ip == ip)
    }

    /// La box dans le scan : l'hôte qui a le rôle de passerelle, sinon celui qui a son adresse.
    fn boite(&self) -> Option<&Hote> {
        self.rapport
            .hotes
            .iter()
            .find(|h| h.role == Some("passerelle"))
            .or_else(|| self.passerelle.and_then(|p| self.hote(p)))
    }

    /// Cet ordinateur dans le scan.
    fn moi(&self) -> Option<&Hote> {
        self.rapport
            .hotes
            .iter()
            .find(|h| h.role == Some("cette machine"))
            .or_else(|| self.locale.and_then(|l| self.hote(l)))
    }
}

/// Les constats du domaine, dans l'ordre des règles.
pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut liste = redirections(e);
    liste.extend(adresse_publique(e));
    liste.extend(adresses_ipv6(e));
    liste.extend(services_de_la_box(e));
    liste
}

/// Un constat de ce domaine, marqué de sa règle.
fn marque(mut c: Constat, regle: &'static str) -> Constat {
    c.regle = regle;
    c
}

/// Une adresse partagée par le fournisseur entre plusieurs abonnés (CGNAT, 100.64.0.0/10) : personne ne la joint
/// d'Internet.
fn partagee(ip: Ipv4Addr) -> bool {
    crate::socle::adresses::portee(ip.into()) == crate::socle::adresses::Portee::Partagee
}

/// « (Box du salon) », ce que la box dit être, pour une phrase.
fn nom_de_box(d: &igd::Description) -> String {
    [d.nom.as_deref(), d.modele.as_deref()]
        .into_iter()
        .flatten()
        .next()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default()
}

/// D'autres appareils que la passerelle ont répondu comme une box IGD : écartés, et dits. `box_aussi` : la vraie box a
/// répondu, et sa lecture est celle qui compte (moyen : un second routeur au réseau, UPnP allumé, répond aussi) ;
/// sinon ses redirections ne sont pas vérifiées (élevé).
fn usurpateurs(ips: &[std::net::Ipv4Addr], box_aussi: bool) -> Constat {
    let liste = ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    let suite = if box_aussi {
        tr!(
            " Seule la réponse du routeur (la passerelle) est lue.",
            " Only the router's answer (the gateway) is read."
        )
    } else {
        tr!(
            " Le routeur lui-même n'a pas répondu : ce qu'il ouvre vers Internet n'est pas vérifié.",
            " The router itself did not answer: what it opens to the Internet is not checked."
        )
    };
    Constat {
        verifie: box_aussi,
        ..alerte(
            CATEGORIE,
            if box_aussi { Niveau::Moyen } else { Niveau::Eleve },
            trf!(
                "{liste} se dit routeur en UPnP sans être la passerelle du réseau : un appareil se fait peut-être passer pour lui, pour cacher les ports qu'il ouvre ou en inventer.{suite}",
                "{liste} claims to be the router over UPnP without being the network's gateway: a device may be impersonating it, to hide the ports it opens or make some up.{suite}"
            ),
        )
        .manuel(
            tr!(
                "Regardez quel appareil a cette adresse (Réseau › appareils) ; s'il n'a rien d'un routeur, débranchez-le du réseau",
                "Check which device has this address (Network › devices); if it is nothing like a router, unplug it from the network"
            ),
            &[],
        )
    }
}

/// COM-EXP-001 : les redirections de ports de la box, lues en UPnP.
fn redirections(e: &Entree) -> Vec<Constat> {
    const REGLE: &str = "COM-EXP-001";
    let Some(etat) = &e.rapport.upnp else {
        return vec![marque(
            impossible(
                CATEGORIE,
                tr!(
                    "UPnP non demandé au routeur : scan d'une cible précise",
                    "UPnP not asked of the router: scan of a single target"
                ),
            ),
            REGLE,
        )];
    };
    let lecture = match etat {
        Etat::Absent => {
            return vec![marque(
                ok(
                    CATEGORIE,
                    tr!(
                        "UPnP coupé ou absent sur le routeur : aucun appareil ne peut ouvrir un port vers Internet tout seul. Les redirections réglées à la main dans le routeur ne se lisent pas d'ici.",
                        "UPnP off or absent on the router: no device can open a port to the Internet by itself. Port forwards set by hand in the router cannot be read from here."
                    ),
                ),
                REGLE,
            )];
        }
        Etat::OutilAbsent => {
            // Ni le client natif ni l'outil de repli n'ont pu lire la box : dire comment installer l'outil.
            let commande = upnp::outil_de_repli();
            let repli = if commande.is_empty() {
                String::new()
            } else {
                trf!(
                    " ; outil de repli absent : {commande}",
                    "; fallback tool missing: {commande}"
                )
            };
            return vec![marque(
                impossible(
                    CATEGORIE,
                    &trf!(
                        "le routeur n'a pas pu être interrogé en UPnP{repli}",
                        "the router could not be queried over UPnP{repli}"
                    ),
                ),
                REGLE,
            )];
        }
        // Personne à la passerelle, mais d'autres se disent box : un appareil se fait peut-être passer pour elle.
        Etat::Usurpee(ips) => return vec![marque(usurpateurs(ips, false), REGLE)],
        Etat::Actif(l) => l,
    };
    let boite = nom_de_box(&lecture.description);
    let n = lecture.redirections.len();
    let compte = if lecture.lues {
        trf!(" {n} redirection(s) en ce moment.", " {n} port forward(s) right now.")
    } else {
        String::new()
    };
    // UPnP ouvert : la box obéit à tout programme du réseau, même sans redirection aujourd'hui.
    let mut liste = vec![marque(
        alerte(
            CATEGORIE,
            Niveau::Moyen,
            trf!(
                "UPnP est actif sur le routeur{boite} : n'importe quel programme du réseau, un appareil infecté aussi, peut lui demander d'ouvrir un port vers Internet sans vous le dire.{compte}",
                "UPnP is on at the router{boite}: any program on the network, an infected device too, can ask it to open a port to the Internet without telling you.{compte}"
            ),
        )
        .manuel(
            tr!(
                "Coupez UPnP dans l'administration du routeur (souvent sous « Avancé », « NAT » ou « Jeux ») ; pour une console, réglez plutôt une redirection à la main.",
                "Turn UPnP off in the router's administration (often under “Advanced”, “NAT” or “Gaming”); for a console, set a port forward by hand instead."
            ),
            &[],
        ),
        REGLE,
    )];
    if !lecture.ailleurs.is_empty() {
        liste.push(marque(usurpateurs(&lecture.ailleurs, true), REGLE));
    }
    if !lecture.lues {
        liste.push(marque(
            impossible(
                CATEGORIE,
                tr!(
                    "le routeur annonce UPnP mais ne dit pas ses redirections",
                    "the router announces UPnP but does not tell its port forwards"
                ),
            ),
            REGLE,
        ));
        return liste;
    }
    // Derrière un partage d'adresse (CGNAT) ou un second routeur, Internet n'atteint pas la box : une redirection
    // n'y expose rien, mais reste à retirer.
    let sans_effet = lecture
        .adresse_externe
        .is_some_and(|ip| partagee(ip) || ip.is_private());
    for r in &lecture.redirections {
        liste.push(marque(constat_redirection(e, r, sans_effet), REGLE));
    }
    if lecture.tronquees {
        liste.push(marque(
            alerte(
                CATEGORIE,
                Niveau::Info,
                trf!(
                    "{n} redirection(s) lue(s) : le routeur en a peut-être d'autres.",
                    "{n} port forward(s) read: the router may have more."
                ),
            ),
            REGLE,
        ));
    }
    liste
}

/// Le constat d'une redirection : critique vers un service de prise de contrôle, élevé vers un appareil que ni le
/// scan ni le carnet ne connaissent (une ouverture oubliée), sinon le niveau du port, au moins moyen (joignable
/// d'Internet). Au plus moyen quand Internet n'atteint pas la box.
fn constat_redirection(e: &Entree, r: &igd::Redirection, sans_effet: bool) -> Constat {
    let service = info_port(r.port_appareil);
    let cible: Option<Ipv4Addr> = r.appareil.parse().ok();
    let hote = cible.and_then(|ip| e.hote(ip));
    let connu = hote.is_some() || cible.is_some_and(|ip| e.rapport.absents.iter().any(|a| a.ip == ip));
    let mut niveau = if !r.active {
        Niveau::Info
    } else if PORTS_CRITIQUES.contains(&r.port_appareil) {
        Niveau::Critique
    } else if !connu {
        Niveau::Eleve
    } else {
        upnp::niveau(r).max(Niveau::Moyen)
    };
    if sans_effet {
        niveau = niveau.min(Niveau::Moyen);
    }
    let appareil = match hote.map(Hote::titre).filter(|t| !t.is_empty()) {
        Some(titre) => format!("{} ({titre})", r.appareil),
        None => r.appareil.clone(),
    };
    let nom_service = if service.service == crate::risk::inconnu() {
        String::new()
    } else {
        format!(" ({})", service.service)
    };
    let mut message = trf!(
        "Le routeur renvoie le port {}/{} d'Internet vers {appareil}:{}{nom_service} : n'importe qui sur Internet peut essayer de s'y connecter.",
        "The router forwards Internet port {}/{} to {appareil}:{}{nom_service}: anyone on the Internet can try to connect to it.",
        r.port_public,
        r.protocole.to_lowercase(),
        r.port_appareil
    );
    if !r.description.is_empty() {
        message += &trf!(" Demandée comme « {} ».", " Requested as “{}”.", r.description);
    }
    if !r.hote_distant.is_empty() {
        message += &trf!(" Depuis {} seulement.", " From {} only.", r.hote_distant);
    }
    if !r.active {
        message += tr!(
            " Désactivée dans le routeur : sans effet tant qu'elle le reste.",
            " Disabled in the router: no effect as long as it stays so."
        );
    } else if !connu {
        message += tr!(
            " L'appareil visé n'est ni dans le scan ni dans le carnet : une ouverture oubliée, à retirer.",
            " The target device is neither in the scan nor in the record: a forgotten opening, to be removed."
        );
    }
    if sans_effet {
        message += tr!(
            " Sans effet derrière le partage d'adresse de votre fournisseur ou un second routeur, mais à retirer quand même.",
            " No effect behind your provider's shared address or a second router, but to be removed anyway."
        );
    }
    alerte(CATEGORIE, niveau, message).manuel(
        tr!(
            "Si vous n'avez pas demandé cette ouverture, coupez UPnP dans l'administration du routeur et retirez la redirection. Si elle sert (console, caméra), mettez l'appareil à jour et donnez-lui un mot de passe fort.",
            "If you did not ask for this opening, turn UPnP off in the router's administration and remove the port forward. If it is needed (console, camera), update the device and give it a strong password."
        ),
        &[],
    )
}

/// COM-EXP-002 : l'adresse publique IPv4, le partage d'adresse du fournisseur (CGNAT) et le double NAT. Information
/// dans tous les cas : ce qui compte, c'est ce que la box laisse passer.
fn adresse_publique(e: &Entree) -> Vec<Constat> {
    const REGLE: &str = "COM-EXP-002";
    let boite = match &e.rapport.upnp {
        Some(Etat::Actif(l)) => l.adresse_externe,
        _ => None,
    };
    let constat = match e.internet {
        Some(Internet { v4: Some(ip), .. }) => {
            let situation = crate::reseau::nat::adresse_partagee(boite, ip).unwrap_or(tr!(
                "Votre routeur est joignable d'Internet : ce qui compte, c'est ce qu'il laisse passer (redirections ci-dessus, IPv6 ci-dessous).",
                "Your router is reachable from the Internet: what matters is what it lets through (port forwards above, IPv6 below)."
            ));
            alerte(
                CATEGORIE,
                Niveau::Info,
                trf!(
                    "Votre adresse Internet est {ip}. {situation}",
                    "Your Internet address is {ip}. {situation}"
                ),
            )
        }
        Some(Internet { v4: None, .. }) => impossible(
            CATEGORIE,
            tr!(
                "adresse publique : pas d'Internet, ou l'UDP sortant est bloqué",
                "public address: no Internet, or outgoing UDP is blocked"
            ),
        ),
        None => match boite {
            Some(ip) => alerte(
                CATEGORIE,
                Niveau::Info,
                trf!(
                    "Le routeur dit avoir l'adresse Internet {ip}. {}",
                    "The router says its Internet address is {ip}. {}",
                    situation_de_la_box(ip)
                ),
            ),
            None => impossible(
                CATEGORIE,
                tr!(
                    "adresse publique non mesurée ici (l'audit du réseau et « Type de NAT » la demandent à Internet)",
                    "public address not measured here (the network audit and “NAT type” ask the Internet for it)"
                ),
            ),
        },
    };
    vec![marque(constat, REGLE)]
}

/// Ce que l'adresse que la box dit avoir révèle, sans la confirmer d'Internet.
fn situation_de_la_box(ip: Ipv4Addr) -> &'static str {
    if partagee(ip) {
        tr!(
            "Adresse partagée par le fournisseur (CGNAT) : personne ne joint votre routeur depuis Internet en IPv4, mais regardez l'IPv6 ci-dessous.",
            "Address shared by the provider (CGNAT): nobody reaches your router from the Internet over IPv4, but look at IPv6 below."
        )
    } else if ip.is_private() {
        tr!(
            "Adresse privée : votre routeur est derrière un autre routeur (double NAT), deux administrations à vérifier.",
            "Private address: your router sits behind another router (double NAT), two administrations to check."
        )
    } else {
        tr!(
            "Adresse publique, non confirmée d'Internet : votre routeur est joignable, ce qui compte est ce qu'il laisse passer.",
            "Public address, not confirmed from the Internet: your router is reachable, what matters is what it lets through."
        )
    }
}

/// COM-EXP-003 : l'IPv6 publique de cet ordinateur. En IPv6, rien ne le cache derrière la box : seul un pare-feu
/// arrête Internet. Celui de la box ne se lit pas d'ici : dit à chaque fois.
fn adresses_ipv6(e: &Entree) -> Vec<Constat> {
    const REGLE: &str = "COM-EXP-003";
    let lecture = &e.ipv6;
    if !lecture.lue {
        return vec![marque(
            impossible(
                CATEGORIE,
                tr!(
                    "interfaces réseau illisibles (IPv6)",
                    "network interfaces unreadable (IPv6)"
                ),
            ),
            REGLE,
        )];
    }
    let autres_non_lus = if lecture.voisins_publics.is_none() {
        tr!(
            " Les autres appareils du réseau : non lus sur ce système.",
            " The other devices on the network: not read on this system."
        )
    } else {
        ""
    };
    let mut liste = Vec::new();
    if lecture.adresses.is_empty() {
        liste.push(marque(
            ok(
                CATEGORIE,
                trf!(
                    "Aucune adresse IPv6 publique sur cet ordinateur : rien à joindre par là.{autres_non_lus}",
                    "No public IPv6 address on this computer: nothing to reach that way.{autres_non_lus}"
                ),
            ),
            REGLE,
        ));
    } else {
        let prefixes: BTreeSet<String> = lecture.adresses.iter().map(|a| ipv6::prefixe(a.ip)).collect();
        let prefixes = prefixes.into_iter().collect::<Vec<_>>().join(", ");
        let n = lecture.adresses.len();
        let temporaires = lecture.adresses.iter().filter(|a| a.temporaire == Some(true)).count();
        let dont = if temporaires > 0 {
            trf!(
                " dont {temporaires} temporaire(s)",
                " including {temporaires} temporary"
            )
        } else {
            String::new()
        };
        let etat = match e.pare_feu_local {
            Some(true) => tr!("actif", "on"),
            Some(false) => tr!("inactif", "off"),
            None => tr!(
                "non vérifié ici (le bilan de la machine le dit)",
                "not checked here (the machine check tells)"
            ),
        };
        // Sans pare-feu, un service déjà jugé moyen ou pire sur cet ordinateur est offert à tout Internet.
        let sensibles = e
            .moi()
            .is_some_and(|h| h.ports.iter().any(|p| p.niveau >= Niveau::Moyen));
        let niveau = match e.pare_feu_local {
            Some(false) if sensibles => Niveau::Eleve,
            Some(false) => Niveau::Moyen,
            _ => Niveau::Info,
        };
        let mut message = trf!(
            "Cet ordinateur a une adresse IPv6 publique ({prefixes}, {n} adresse(s){dont}) : en IPv6, rien ne le cache derrière le routeur ; seul un pare-feu (le sien ou celui du routeur) arrête Internet. Le sien est {etat}.",
            "This computer has a public IPv6 address ({prefixes}, {n} address(es){dont}): in IPv6, nothing hides it behind the router; only a firewall (its own or the router's) stops the Internet. Its own is {etat}."
        );
        let tunnels: BTreeSet<&str> = lecture
            .adresses
            .iter()
            .filter(|a| ipv6::tunnel(&a.interface))
            .map(|a| a.interface.as_str())
            .collect();
        for tunnel in tunnels {
            message += &trf!(
                " {tunnel} est un tunnel (VPN) : son adresse vient de lui, pas du routeur.",
                " {tunnel} is a tunnel (VPN): its address comes from it, not from the router."
            );
        }
        if matches!(e.internet, Some(Internet { v6: None, .. })) {
            message += tr!(
                " Internet ne répond pas par là : adresse sans accès réel.",
                " The Internet does not answer that way: an address without real access."
            );
        }
        message += tr!(
            " Le pare-feu IPv6 du routeur ne se lit pas d'ici : il faudrait qu'un serveur extérieur essaie de vous joindre, ce que Vanguard ne fait pas.",
            " The router's IPv6 firewall cannot be read from here: an outside server would have to try to reach you, which Vanguard does not do."
        );
        message += autres_non_lus;
        liste.push(marque(
            alerte(CATEGORIE, niveau, message).manuel(
                tr!(
                    "Activez le pare-feu de cet ordinateur (Vanguard le propose au bilan) ; dans l'admin du routeur, vérifiez que le pare-feu IPv6 est activé.",
                    "Turn on this computer's firewall (Vanguard offers it in the check); in the router's admin, make sure the IPv6 firewall is on."
                ),
                &[],
            ),
            REGLE,
        ));
    }
    if let Some(n) = lecture.voisins_publics
        && n > 0
    {
        liste.push(marque(
            alerte(
                CATEGORIE,
                Niveau::Info,
                trf!(
                    "{n} autre(s) appareil(s) du réseau ont une adresse IPv6 publique : eux aussi ne dépendent que du pare-feu du routeur.",
                    "{n} other device(s) on the network have a public IPv6 address: they too depend only on the router's firewall."
                ),
            ),
            REGLE,
        ));
    }
    liste
}

/// COM-EXP-004 : les services de la box côté réseau local, d'après ses ports déjà lus par le scan : rien de plus
/// n'est sondé.
fn services_de_la_box(e: &Entree) -> Vec<Constat> {
    const REGLE: &str = "COM-EXP-004";
    let Some(boite) = e.boite() else {
        return vec![marque(
            impossible(
                CATEGORIE,
                tr!("le routeur n'est pas dans le scan", "the router is not in the scan"),
            ),
            REGLE,
        )];
    };
    let tcp = |port: u16| boite.ports.iter().any(|p| !p.udp && p.port == port);
    let marche = tr!(
        "Dans l'admin du routeur, coupez ce qui ne sert pas ; vérifiez que l'administration à distance (depuis Internet) est désactivée.",
        "In the router's admin, turn off what is not needed; make sure remote administration (from the Internet) is off."
    );
    let mut liste = Vec::new();
    for p in boite.ports.iter().filter(|p| PORTS_BOX.contains(&p.port)) {
        // Le web avec HTTPS à côté : la page existe chiffrée, les alertes du scan jugent le reste.
        if p.port == 80 && !p.udp && tcp(443) {
            continue;
        }
        let (niveau, conseil) = match p.port {
            23 => (Niveau::Critique, p.conseil),
            80 if !p.udp => (
                Niveau::Moyen,
                tr!(
                    "Sa page d'administration n'est qu'en HTTP : son mot de passe passe en clair sur le réseau.",
                    "Its admin page is HTTP only: its password travels in clear text on the network."
                ),
            ),
            7547 => (
                Niveau::Info,
                tr!(
                    "Gestion à distance par le fournisseur : normal sur un routeur loué, à savoir.",
                    "Remote management by the provider: normal on a rented router, worth knowing."
                ),
            ),
            _ => (p.niveau, p.conseil),
        };
        let constat = alerte(
            CATEGORIE,
            niveau,
            trf!(
                "Le routeur offre {} ({}) à tout le réseau. {conseil}",
                "The router offers {} ({}) to the whole network. {conseil}",
                p.service,
                p.libelle()
            ),
        );
        let constat = if niveau >= Niveau::Moyen {
            constat.manuel(marche, &[])
        } else {
            constat
        };
        liste.push(marque(constat, REGLE));
    }
    if liste.is_empty() {
        liste.push(marque(
            ok(
                CATEGORIE,
                trf!(
                    "Le routeur n'offre au réseau local aucun service d'administration à risque ({} port(s) vus). Son administration à distance (depuis Internet) ne se voit pas d'ici.",
                    "The router offers the local network no risky administration service ({} port(s) seen). Its remote administration (from the Internet) cannot be seen from here.",
                    boite.ports.len()
                ),
            ),
            REGLE,
        ));
    }
    liste
}

/// La section « Exposition vers Internet » à la fin du scan du réseau : chaque constat avec son niveau, la marche à
/// suivre, et le compte de ce qui n'a pas pu se vérifier d'ici. La note du domaine appartient à l'audit du réseau.
pub fn afficher_section(constats: &[Constat]) {
    section(tr!("EXPOSITION VERS INTERNET", "EXPOSURE TO THE INTERNET"));
    for c in constats {
        let (icone, etiquette, style) = match c.probleme {
            _ if !c.verifie => (format!("{DISCRET}·{RESET}"), String::new(), DISCRET),
            None => (format!("{VERT}✔{RESET}"), String::new(), ""),
            // Une simple information n'est pas un problème : pas de croix.
            Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new(), ""),
            Some(n) => (
                format!("{}✖{RESET}", couleur(n)),
                format!("{}[{}]{RESET} ", couleur(n), n.libelle()),
                "",
            ),
        };
        afficher_aligne(&format!("  {icone} {etiquette}"), &c.message, 4, style);
        if let Some(k) = &c.correctif {
            afficher_aligne(
                "      ",
                &trf!("{} à faire : {}", "{} to do: {}", ampoule(), k.action),
                6,
                GRIS,
            );
        }
    }
    let impossibles = constats.iter().filter(|c| !c.verifie).count();
    if impossibles > 0 {
        afficher_aligne(
            "  ",
            &trf!(
                "{impossibles} vérification(s) impossible(s) d'ici : rien n'en est conclu.",
                "{impossibles} check(s) could not be done from here: nothing is concluded from them."
            ),
            2,
            DISCRET,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reseau::{Absent, PortOuvert};

    fn port(port: u16, udp: bool) -> PortOuvert {
        let i = if udp {
            crate::risk::info_udp(port)
        } else {
            info_port(port)
        };
        PortOuvert {
            port,
            service: i.service,
            niveau: i.niveau,
            banniere: None,
            conseil: i.conseil,
            nouveau: false,
            programme: None,
            udp,
        }
    }

    fn hote(ip: &str, nom: Option<&str>, role: Option<&'static str>, tcp: &[u16], udp: &[u16]) -> Hote {
        let ports = tcp
            .iter()
            .map(|&p| port(p, false))
            .chain(udp.iter().map(|&p| port(p, true)))
            .collect();
        Hote {
            ip: ip.parse().unwrap(),
            nom: nom.map(str::to_string),
            mac: None,
            fabricant: None,
            surnom: None,
            premier_vu: None,
            role,
            nouvelle: false,
            ports,
            alertes: Vec::new(),
            score: 100,
        }
    }

    /// Le réseau « Salon » : la box, cet ordinateur, une caméra, un NAS ; une imprimante absente aujourd'hui.
    fn rapport(upnp: Option<Etat>) -> Rapport {
        Rapport {
            carnet_non_cru: None,
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("Salon".into()),
            absents: vec![Absent {
                ip: "10.0.0.40".parse().unwrap(),
                titre: "Imprimante".into(),
                dernier_vu: Some("2026-10-01".into()),
            }],
            duree_s: 1.0,
            score_global: 100,
            note: "A",
            hotes: vec![
                hote(
                    "10.0.0.1",
                    Some("box"),
                    Some("passerelle"),
                    &[53, 80, 7547],
                    &[53, 1900],
                ),
                hote("10.0.0.10", Some("pc-alice"), Some("cette machine"), &[3389], &[]),
                hote("10.0.0.30", Some("camera-salon"), None, &[80, 554], &[]),
                hote("10.0.0.50", Some("nas"), None, &[445, 5000], &[]),
            ],
            upnp,
            empoisonnement: None,
        }
    }

    fn redirection(proto: &str, public: u16, ip: &str, port: u16, description: &str) -> igd::Redirection {
        igd::Redirection {
            protocole: proto.into(),
            port_public: public,
            appareil: ip.into(),
            port_appareil: port,
            description: description.into(),
            bail: 0,
            hote_distant: String::new(),
            active: true,
        }
    }

    fn lecture(redirections: Vec<igd::Redirection>, externe: Option<Ipv4Addr>) -> Box<igd::Lecture> {
        Box::new(igd::Lecture {
            description: igd::Description {
                adresse: Some("10.0.0.1".parse().unwrap()),
                nom: Some("Box du salon".into()),
                ..igd::Description::default()
            },
            adresse_externe: externe,
            connexion: Some("Connected".into()),
            redirections,
            lues: true,
            tronquees: false,
            ailleurs: Vec::new(),
        })
    }

    fn entree(rapport: &Rapport) -> Entree<'_> {
        Entree {
            rapport,
            passerelle: Some("10.0.0.1".parse().unwrap()),
            locale: Some("10.0.0.10".parse().unwrap()),
            internet: None,
            ipv6: ipv6::Lecture {
                lue: true,
                adresses: Vec::new(),
                voisins_publics: Some(0),
            },
            pare_feu_local: None,
        }
    }

    fn regle<'a>(constats: &'a [Constat], regle: &str) -> Vec<&'a Constat> {
        constats.iter().filter(|c| c.regle == regle).collect()
    }

    /// Les redirections que l'audit retient du scan : lues, aucune quand UPnP est absent, rien de cru sinon.
    #[test]
    fn redirections_du_scan() {
        use crate::audit::redirections_du_scan as du_scan;
        let une = vec![redirection("TCP", 3389, "10.0.0.10", 3389, "Bureau")];
        assert_eq!(
            du_scan(&rapport(Some(Etat::Actif(lecture(une, None))))).map(|l| l.len()),
            Some(1)
        );
        assert_eq!(du_scan(&rapport(Some(Etat::Absent))).map(|l| l.len()), Some(0));
        // Refusées par la box, outil absent, box usurpée, pas de lecture : non lues, pas « aucune ».
        let mut refusees = lecture(vec![redirection("TCP", 22, "10.0.0.50", 22, "")], None);
        refusees.lues = false;
        assert!(du_scan(&rapport(Some(Etat::Actif(refusees)))).is_none());
        assert!(du_scan(&rapport(Some(Etat::OutilAbsent))).is_none());
        assert!(du_scan(&rapport(Some(Etat::Usurpee(vec![Ipv4Addr::new(10, 0, 0, 66)])))).is_none());
        assert!(du_scan(&rapport(None)).is_none());
    }

    #[test]
    fn redirections_jugees() {
        let r = rapport(Some(Etat::Actif(lecture(
            vec![
                redirection("TCP", 3389, "10.0.0.10", 3389, "Bureau"),
                redirection("TCP", 8080, "10.0.0.30", 80, "Camera"),
                redirection("TCP", 25565, "10.0.0.99", 25565, "Minecraft"),
                redirection("UDP", 3074, "10.0.0.40", 3074, ""),
                igd::Redirection {
                    active: false,
                    ..redirection("TCP", 22, "10.0.0.50", 22, "ssh")
                },
            ],
            Some(Ipv4Addr::new(203, 0, 113, 7)),
        ))));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert_eq!(exp.len(), 6, "{:?}", exp.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert!(exp.iter().all(|c| c.categorie == CATEGORIE && c.verifie));
        // L'UPnP lui-même : moyen, avec la marche à suivre.
        assert_eq!(exp[0].probleme, Some(Niveau::Moyen));
        assert!(exp[0].message.contains("(Box du salon)") && exp[0].message.contains("5 redirection(s)"));
        assert!(exp[0].correctif.as_ref().is_some_and(|k| !k.automatique));
        // Bureau à distance ouvert à Internet : critique, l'appareil nommé.
        assert_eq!(exp[1].probleme, Some(Niveau::Critique));
        assert!(
            exp[1]
                .message
                .starts_with("Le routeur renvoie le port 3389/tcp d'Internet vers 10.0.0.10 (pc-alice):3389 (RDP)")
        );
        assert!(exp[1].message.contains("Demandée comme « Bureau »"));
        // Le web d'une caméra : le niveau du port, au moins moyen.
        assert!(
            exp[2]
                .probleme
                .is_some_and(|n| n >= Niveau::Moyen && n < Niveau::Critique)
        );
        // Vers un appareil inconnu du scan et du carnet : élevé, dit oublié.
        assert_eq!(exp[3].probleme, Some(Niveau::Eleve));
        assert!(exp[3].message.contains("ni dans le scan ni dans le carnet"));
        // Vers l'imprimante du carnet, absente aujourd'hui : connue, port inconnu → moyen, sans « (Inconnu) ».
        assert_eq!(exp[4].probleme, Some(Niveau::Moyen));
        assert!(!exp[4].message.contains("Inconnu") && !exp[4].message.contains("Demandée"));
        // Désactivée : information seulement.
        assert_eq!(exp[5].probleme, Some(Niveau::Info));
        assert!(exp[5].message.contains("Désactivée"));
        // Derrière un partage d'adresse : au plus moyen, et dit sans effet.
        let r = rapport(Some(Etat::Actif(lecture(
            vec![redirection("TCP", 3389, "10.0.0.10", 3389, "")],
            Some(Ipv4Addr::new(100, 64, 1, 2)),
        ))));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert_eq!(exp[1].probleme, Some(Niveau::Moyen));
        assert!(exp[1].message.contains("Sans effet derrière"));
        // Liste tronquée : dit.
        let r = rapport(Some(Etat::Actif(Box::new(igd::Lecture {
            tronquees: true,
            ..*lecture(vec![redirection("UDP", 1, "10.0.0.30", 1, "")], None)
        }))));
        let liste = constats(&entree(&r));
        assert!(regle(&liste, "COM-EXP-001")[2].message.contains("peut-être d'autres"));
    }

    #[test]
    fn upnp_absent_ou_non_verifie() {
        let r = rapport(Some(Etat::Absent));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert_eq!(exp.len(), 1);
        assert!(exp[0].probleme.is_none() && exp[0].verifie);
        assert!(exp[0].message.contains("ne se lisent pas d'ici"));
        let r = rapport(Some(Etat::OutilAbsent));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert!(!exp[0].verifie && exp[0].message.contains("interrogé"));
        let r = rapport(None);
        let liste = constats(&entree(&r));
        assert!(!regle(&liste, "COM-EXP-001")[0].verifie);
        // Personne à la passerelle, mais un autre appareil se dit box : élevé, et la box non vérifiée.
        let piege: Ipv4Addr = "10.0.0.66".parse().unwrap();
        let r = rapport(Some(Etat::Usurpee(vec![piege])));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert_eq!(
            (exp.len(), exp[0].probleme, exp[0].verifie),
            (1, Some(Niveau::Eleve), false)
        );
        assert!(exp[0].message.contains("10.0.0.66"), "{}", exp[0].message);
        // La box a répondu, et un autre aussi : sa lecture compte, l'autre est dit.
        let r = rapport(Some(Etat::Actif(Box::new(igd::Lecture {
            ailleurs: vec![piege],
            ..*lecture(Vec::new(), None)
        }))));
        let liste = constats(&entree(&r));
        assert!(
            regle(&liste, "COM-EXP-001")
                .iter()
                .any(|c| c.probleme == Some(Niveau::Moyen) && c.verifie && c.message.contains("10.0.0.66"))
        );
        // La box annonce UPnP mais refuse le SOAP : moyen (UPnP ouvert) et non vérifié (redirections).
        let r = rapport(Some(Etat::Actif(Box::new(igd::Lecture {
            lues: false,
            ..*lecture(Vec::new(), None)
        }))));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-001");
        assert_eq!(exp.len(), 2);
        assert_eq!(exp[0].probleme, Some(Niveau::Moyen));
        assert!(!exp[0].message.contains("redirection(s) en ce moment"));
        assert!(!exp[1].verifie);
    }

    #[test]
    fn adresse_publique_jugee() {
        let publique = Ipv4Addr::new(203, 0, 113, 7);
        let r = rapport(Some(Etat::Actif(lecture(Vec::new(), Some(publique)))));
        let mut e = entree(&r);
        e.internet = Some(Internet {
            v4: Some(IpAddr::V4(publique)),
            v6: None,
        });
        let liste = constats(&e);
        let exp = regle(&liste, "COM-EXP-002");
        assert_eq!(
            (exp.len(), exp[0].probleme, exp[0].verifie),
            (1, Some(Niveau::Info), true)
        );
        assert!(
            exp[0]
                .message
                .starts_with("Votre adresse Internet est 203.0.113.7. Votre routeur est joignable")
        );
        // La box dit une adresse partagée (CGNAT) : le jugement de « Type de NAT ».
        let r = rapport(Some(Etat::Actif(lecture(
            Vec::new(),
            Some(Ipv4Addr::new(100, 64, 1, 2)),
        ))));
        let mut e = entree(&r);
        e.internet = Some(Internet {
            v4: Some(IpAddr::V4(publique)),
            v6: None,
        });
        let liste = constats(&e);
        assert!(regle(&liste, "COM-EXP-002")[0].message.contains("CGNAT"));
        // Sans STUN : ce que la box dit, sans le confirmer ; sans box non plus : non mesurée.
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-002");
        assert!(
            exp[0].verifie
                && exp[0]
                    .message
                    .starts_with("Le routeur dit avoir l'adresse Internet 100.64.1.2. Adresse partagée")
        );
        let r = rapport(Some(Etat::Actif(lecture(
            Vec::new(),
            Some(Ipv4Addr::new(192, 168, 0, 2)),
        ))));
        let liste = constats(&entree(&r));
        assert!(regle(&liste, "COM-EXP-002")[0].message.contains("double NAT"));
        let r = rapport(Some(Etat::Absent));
        let liste = constats(&entree(&r));
        assert!(!regle(&liste, "COM-EXP-002")[0].verifie);
        // STUN muet : pas d'Internet, non vérifié.
        let mut e = entree(&r);
        e.internet = Some(Internet::default());
        let liste = constats(&e);
        let exp = regle(&liste, "COM-EXP-002");
        assert!(!exp[0].verifie && exp[0].message.contains("UDP"));
    }

    #[test]
    fn ipv6_publique() {
        let r = rapport(Some(Etat::Absent));
        let adresses = vec![
            ipv6::Adresse {
                interface: "enp5s0".into(),
                ip: "2001:db8:1:2::10".parse().unwrap(),
                temporaire: Some(false),
            },
            ipv6::Adresse {
                interface: "enp5s0".into(),
                ip: "2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap(),
                temporaire: Some(true),
            },
            ipv6::Adresse {
                interface: "wg0".into(),
                ip: "2001:db8:ffff::2".parse().unwrap(),
                temporaire: Some(false),
            },
        ];
        let mut e = entree(&r);
        e.ipv6 = ipv6::Lecture {
            lue: true,
            adresses: adresses.clone(),
            voisins_publics: Some(3),
        };
        e.pare_feu_local = Some(false);
        let liste = constats(&e);
        let exp = regle(&liste, "COM-EXP-003");
        assert_eq!(exp.len(), 2);
        // Sans pare-feu et le bureau à distance ouvert sur cet ordinateur : élevé.
        assert_eq!(exp[0].probleme, Some(Niveau::Eleve));
        let m = &exp[0].message;
        assert!(
            m.contains("(2001:db8:1:2::/64, 2001:db8:ffff::/64, 3 adresse(s) dont 1 temporaire(s))"),
            "{m}"
        );
        // Jamais l'adresse entière, qui désigne l'appareil.
        assert!(!m.contains("aaaa:bbbb") && !m.contains("::10"));
        assert!(m.contains("Le sien est inactif.") && m.contains("wg0 est un tunnel"));
        assert!(m.contains("ne se lit pas d'ici") && !m.contains("non lus sur ce système"));
        assert!(exp[0].correctif.is_some());
        assert!(exp[1].message.starts_with("3 autre(s) appareil(s)"));
        // Pare-feu actif : information ; non lu : information, dit ; voisins non lus : dit.
        e.pare_feu_local = Some(true);
        let liste = constats(&e);
        let exp = regle(&liste, "COM-EXP-003");
        assert_eq!(exp[0].probleme, Some(Niveau::Info));
        assert!(exp[0].message.contains("Le sien est actif."));
        e.pare_feu_local = None;
        e.ipv6.voisins_publics = None;
        let liste = constats(&e);
        let exp = regle(&liste, "COM-EXP-003");
        assert_eq!((exp.len(), exp[0].probleme), (1, Some(Niveau::Info)));
        assert!(exp[0].message.contains("non vérifié ici") && exp[0].message.contains("non lus sur ce système"));
        // Sans pare-feu mais rien de sensible sur cet ordinateur : moyen.
        let sans_rdp = Rapport {
            hotes: vec![hote("10.0.0.10", None, Some("cette machine"), &[], &[])],
            ..rapport(Some(Etat::Absent))
        };
        let mut e = entree(&sans_rdp);
        e.ipv6.adresses = adresses;
        e.pare_feu_local = Some(false);
        let liste = constats(&e);
        assert_eq!(regle(&liste, "COM-EXP-003")[0].probleme, Some(Niveau::Moyen));
        // Internet muet en IPv6 : dit.
        e.internet = Some(Internet::default());
        let liste = constats(&e);
        assert!(regle(&liste, "COM-EXP-003")[0].message.contains("sans accès réel"));
        // Aucune adresse : rien à joindre ; interfaces illisibles : non vérifié.
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-003");
        assert!(exp[0].probleme.is_none() && exp[0].message.starts_with("Aucune adresse IPv6 publique"));
        let mut e = entree(&r);
        e.ipv6 = ipv6::Lecture::default();
        let liste = constats(&e);
        assert!(!regle(&liste, "COM-EXP-003")[0].verifie);
    }

    #[test]
    fn services_de_la_box_juges() {
        let r = rapport(Some(Etat::Absent));
        let liste = constats(&entree(&r));
        let exp = regle(&liste, "COM-EXP-004");
        // 80 sans 443 (moyen), TR-069 (information), SSDP (son niveau) ; le DNS, normal, n'est pas cité.
        assert_eq!(exp.len(), 3, "{:?}", exp.iter().map(|c| &c.message).collect::<Vec<_>>());
        assert!(
            exp[0]
                .message
                .starts_with("Le routeur offre HTTP (80/tcp) à tout le réseau. Sa page d'administration")
        );
        assert_eq!(exp[0].probleme, Some(Niveau::Moyen));
        assert!(exp[0].correctif.is_some());
        assert_eq!(exp[1].probleme, Some(Niveau::Info));
        assert!(exp[1].message.contains("TR-069 (7547/tcp)") && exp[1].correctif.is_none());
        assert!(exp[2].message.contains("(1900/udp)"));
        assert!(exp.iter().all(|c| c.verifie && c.regle == "COM-EXP-004"));
        // Telnet : critique. Le web avec HTTPS à côté : pas cité.
        let avec_telnet = Rapport {
            hotes: vec![hote("10.0.0.1", Some("box"), Some("passerelle"), &[23, 80, 443], &[])],
            ..rapport(Some(Etat::Absent))
        };
        let liste = constats(&entree(&avec_telnet));
        let exp = regle(&liste, "COM-EXP-004");
        assert_eq!(exp.len(), 1);
        assert_eq!(exp[0].probleme, Some(Niveau::Critique));
        assert!(exp[0].message.starts_with("Le routeur offre Telnet (23/tcp)"));
        // Rien à risque : dit sain, et l'administration à distance dite invisible d'ici.
        let saine = Rapport {
            hotes: vec![hote("10.0.0.1", Some("box"), Some("passerelle"), &[443], &[53])],
            ..rapport(Some(Etat::Absent))
        };
        let liste = constats(&entree(&saine));
        let exp = regle(&liste, "COM-EXP-004");
        assert!(
            exp[0].probleme.is_none()
                && exp[0].message.contains("2 port(s) vus")
                && exp[0].message.contains("ne se voit pas d'ici")
        );
        // La box reconnue à son adresse quand le scan ne lui a pas donné de rôle ; absente : non vérifié.
        let sans_role = Rapport {
            hotes: vec![hote("10.0.0.1", None, None, &[23], &[])],
            ..rapport(Some(Etat::Absent))
        };
        let liste = constats(&entree(&sans_role));
        assert_eq!(regle(&liste, "COM-EXP-004")[0].probleme, Some(Niveau::Critique));
        let sans_box = Rapport {
            hotes: Vec::new(),
            ..rapport(Some(Etat::Absent))
        };
        let liste = constats(&entree(&sans_box));
        assert!(!regle(&liste, "COM-EXP-004")[0].verifie);
    }

    /// Chaque constat porte la catégorie du domaine et l'identifiant d'une des quatre règles.
    #[test]
    fn chaque_constat_a_sa_regle() {
        let r = rapport(Some(Etat::Actif(lecture(
            vec![redirection("TCP", 8080, "10.0.0.30", 80, "Camera")],
            Some(Ipv4Addr::new(203, 0, 113, 7)),
        ))));
        let liste = constats(&entree(&r));
        assert!(liste.len() >= 6);
        for c in &liste {
            assert_eq!(c.categorie, CATEGORIE);
            assert!(
                ["COM-EXP-001", "COM-EXP-002", "COM-EXP-003", "COM-EXP-004"].contains(&c.regle),
                "{}",
                c.regle
            );
            assert_ne!(c.message, "");
        }
    }
}
