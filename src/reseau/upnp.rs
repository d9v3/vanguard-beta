//! Ports ouverts vers Internet par UPnP : les redirections que des appareils du réseau (console, caméra, objet
//! connecté…) ont demandées à la box, sans que personne ne les voie. Lecture seule. D'abord en Rust pur, le même
//! client sur les trois systèmes (`audit::igd` : SSDP, description, SOAP) ; si la question n'a même pas pu partir,
//! les lectures d'avant en repli : `upnpc -l` (miniupnpc) sous Linux et macOS, l'interface UPnP de Windows sous
//! Windows. Les constats (règle COM-EXP-001) sont dans `audit::exposition`.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::audit::igd::{self, Decouverte};
pub use crate::audit::igd::{Lecture, Redirection};
use crate::risk::{Niveau, info_port};
use crate::ui::affichable;

/// Ce qu'on sait de l'UPnP de la box.
#[derive(Serialize, Debug, PartialEq)]
pub enum Etat {
    /// Aucune box UPnP trouvée : UPnP coupé (le mieux) ou absent.
    Absent,
    /// UPnP actif : ce que la box a répondu (ses redirections, peut-être aucune ; peut-être refusées, voir `lues`).
    Actif(Box<Lecture>),
    /// La box n'a pas pu être interrogée, ni en Rust ni par l'outil de repli, qui manque : non vérifié. Jamais sous
    /// Windows, dont l'interface UPnP fait partie du système.
    #[cfg_attr(windows, allow(dead_code))]
    OutilAbsent,
    /// La box n'a pas pu être interrogée : le client natif n'a pas pu partir, et l'outil de repli, installé, a
    /// échoué ou n'a rien lu d'elle. Non vérifié ; l'installer n'y changerait rien, à dire autrement qu'`OutilAbsent`.
    OutilEnEchec,
    /// La passerelle n'a pas répondu en UPnP, mais d'autres appareils du réseau se disent box (leurs adresses) :
    /// suspect, et rien n'est cru d'eux. Ce que la vraie box ouvre n'est pas vérifié.
    Usurpee(Vec<Ipv4Addr>),
}

pub fn etat() -> Etat {
    etat_et_adresse().0
}

/// L'état de l'UPnP, et l'adresse que la box dit avoir sur Internet : une adresse privée ou partagée (100.64.0.0/10)
/// y trahit un double NAT ou le partage d'adresses du fournisseur (CGNAT).
pub fn etat_et_adresse() -> (Etat, Option<Ipv4Addr>) {
    match igd::decouvrir() {
        Decouverte::Trouvee(lecture) => {
            let adresse = lecture.adresse_externe;
            (Etat::Actif(lecture), adresse)
        }
        Decouverte::Aucune => (Etat::Absent, None),
        Decouverte::Ailleurs(ips) => (Etat::Usurpee(ips), None),
        Decouverte::NonVerifie => etat_par_outil(),
    }
}

/// Comment installer l'outil de repli (miniupnpc), quand ni le client natif ni lui n'ont pu interroger la box ; sous
/// Windows, l'interface UPnP fait partie du système : rien à installer (vide).
#[cfg(target_os = "linux")]
pub fn outil_de_repli() -> String {
    crate::machine::linux::commande_installation("miniupnpc")
}

#[cfg(target_os = "macos")]
pub fn outil_de_repli() -> String {
    crate::machine::macos::commande_installation("miniupnpc")
}

#[cfg(windows)]
pub fn outil_de_repli() -> String {
    String::new()
}

/// Une lecture faite par un outil d'avant : les redirections seulement, la box non décrite.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn lecture_d_outil(redirections: Vec<Redirection>, adresse_externe: Option<Ipv4Addr>) -> Etat {
    Etat::Actif(Box::new(Lecture {
        description: igd::Description::default(),
        adresse_externe,
        connexion: None,
        redirections,
        lues: true,
        tronquees: false,
        ailleurs: Vec::new(),
    }))
}

/// Le repli : `upnpc -l` (miniupnpc), qui attend les réponses de la box jusqu'à 8 s. Sans réponse (pas lancé, ou
/// délai dépassé), absent seulement s'il n'est pas dans le PATH.
#[cfg(unix)]
fn etat_par_outil() -> (Etat, Option<Ipv4Addr>) {
    let Some(r) = crate::commande::lancer(std::process::Command::new("upnpc").arg("-l"), 20) else {
        let etat = if crate::machine::unix::present("upnpc") {
            Etat::OutilEnEchec
        } else {
            Etat::OutilAbsent
        };
        return (etat, None);
    };
    juger_upnpc(r.code, &format!("{}\n{}", r.sortie, r.erreurs))
}

/// Ce que dit `upnpc -l`, de code de retour `code` : « pas de box UPnP » quoi qu'il rende (miniupnpc sort alors en
/// erreur) ; une lecture seulement s'il a réussi (code 0). Un échec d'autre chose (réseau, délai de la box, option
/// refusée) n'est pas « UPnP actif, rien d'ouvert » : non vérifié (campagne 6, B1).
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn juger_upnpc(code: Option<i32>, texte: &str) -> (Etat, Option<Ipv4Addr>) {
    let adresse = adresse_externe(texte);
    match lire_upnpc(texte, adresse) {
        Etat::Actif(_) if code != Some(0) => (Etat::OutilEnEchec, None),
        e => (e, adresse),
    }
}

/// Le repli : l'interface UPnP de Windows (HNetCfg.NATUPnP), vide quand la box n'a pas d'UPnP ou l'a coupé ; elle
/// ne donne pas l'adresse de la box sur Internet.
#[cfg(windows)]
fn etat_par_outil() -> (Etat, Option<Ipv4Addr>) {
    let Some(sortie) = crate::machine::windows::ps(
        "$c = (New-Object -ComObject HNetCfg.NATUPnP).StaticPortMappingCollection; \
         if ($null -eq $c) { 'UPNP_ABSENT' } else { 'UPNP_ACTIF'; $c | ForEach-Object { \
         \"UPNP|$($_.Protocol)|$($_.ExternalPort)|$($_.InternalClient)|$($_.InternalPort)|$($_.Description)\" } }",
    ) else {
        return (Etat::OutilEnEchec, None);
    };
    (lire_upnp_windows(&sortie), None)
}

/// Une redirection lue par un outil : ni bail, ni hôte distant, toujours active.
#[cfg_attr(not(any(unix, windows)), allow(dead_code))]
fn redirection_d_outil(proto: &str, public: u16, ip: &str, port: u16, description: &str) -> Redirection {
    Redirection {
        protocole: affichable(proto),
        port_public: public,
        appareil: affichable(ip),
        port_appareil: port,
        description: affichable(description),
        bail: 0,
        hote_distant: String::new(),
        active: true,
    }
}

/// Lignes de `upnpc -l` : « 0 UDP  3074->10.0.0.20:3074  'Xbox' '' 0 ». N'importe quel appareil du réseau peut
/// demander une redirection, avec l'adresse et la description de son choix : lues prêtes à montrer (`affichable`).
/// Une box lue se voit dans la sortie (sa table, son adresse, une redirection) : sans aucune de ces traces (sortie
/// vide, autre message), rien n'a été lu, non vérifié.
#[cfg_attr(windows, allow(dead_code))]
fn lire_upnpc(sortie: &str, adresse: Option<Ipv4Addr>) -> Etat {
    if sortie.contains("No IGD UPnP Device") || sortie.contains("No valid UPNP Internet Gateway Device") {
        return Etat::Absent;
    }
    let lue = adresse.is_some() || sortie.contains("Found valid IGD") || sortie.contains("exPort->inAddr:inPort");
    let mut liste = Vec::new();
    for l in sortie.lines() {
        let c: Vec<&str> = l.split_whitespace().collect();
        let [_, proto, redirection, ..] = c[..] else { continue };
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let Some((public, interne)) = redirection.split_once("->") else {
            continue;
        };
        let Some((ip, port)) = interne.rsplit_once(':') else {
            continue;
        };
        let (Ok(public), Ok(port)) = (public.parse(), port.parse()) else {
            continue;
        };
        let description = l.split('\'').nth(1).unwrap_or("");
        liste.push(redirection_d_outil(proto, public, ip, port, description));
    }
    if !lue && liste.is_empty() {
        return Etat::OutilEnEchec;
    }
    lecture_d_outil(liste, adresse)
}

/// « ExternalIPAddress = 203.0.113.7 » dans `upnpc -l`.
#[cfg_attr(windows, allow(dead_code))]
fn adresse_externe(texte: &str) -> Option<Ipv4Addr> {
    texte.lines().find_map(|l| {
        l.trim()
            .strip_prefix("ExternalIPAddress")?
            .trim_start()
            .strip_prefix('=')?
            .trim()
            .parse()
            .ok()
    })
}

/// Sortie de l'interface UPnP de Windows : « UPNP_ABSENT », ou « UPNP_ACTIF » puis une ligne
/// « UPNP|protocole|port public|appareil|port|description » par redirection, lue comme celles de upnpc.
#[cfg_attr(not(windows), allow(dead_code))]
fn lire_upnp_windows(sortie: &str) -> Etat {
    if sortie.contains("UPNP_ABSENT") {
        return Etat::Absent;
    }
    let liste = sortie
        .lines()
        .filter_map(|l| l.trim().strip_prefix("UPNP|"))
        .filter_map(|l| {
            let c: Vec<&str> = l.splitn(5, '|').collect();
            let [proto, public, ip, port, description] = c[..] else {
                return None;
            };
            Some(redirection_d_outil(
                proto,
                public.parse().ok()?,
                ip,
                port.parse().ok()?,
                description,
            ))
        })
        .collect();
    lecture_d_outil(liste, None)
}

/// Niveau d'une redirection d'après le service du port interne (bureau à distance, partage, SSH… = élevé) : le
/// point de départ du jugement de `audit::exposition`.
pub fn niveau(r: &Redirection) -> Niveau {
    info_port(r.port_appareil).niveau
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirections(e: &Etat) -> &[Redirection] {
        let Etat::Actif(l) = e else {
            panic!("UPnP actif attendu")
        };
        &l.redirections
    }

    #[test]
    fn lecture_de_upnpc() {
        assert_eq!(
            lire_upnpc("No IGD UPnP Device found on the network !\n", None),
            Etat::Absent
        );
        let sortie = "Found valid IGD : http://10.0.0.1:5000/ctl\n i protocol exPort->inAddr:inPort description remoteHost leaseTime\n 0 UDP  3074->10.0.0.20:3074  'Xbox SRA' '' 0\n 1 TCP  8080->10.0.0.30:80  'Camera' '' 3600\nGetGenericPortMappingEntry() returned 713 (SpecifiedArrayIndexInvalid)\n";
        let e = lire_upnpc(sortie, Some(Ipv4Addr::new(203, 0, 113, 7)));
        let l = redirections(&e);
        assert_eq!(l.len(), 2);
        assert_eq!(
            (l[1].port_public, l[1].appareil.as_str(), l[1].port_appareil),
            (8080, "10.0.0.30", 80)
        );
        assert_eq!(l[0].description, "Xbox SRA");
        assert_eq!(niveau(&l[1]), info_port(80).niveau);
        let Etat::Actif(lecture) = &e else {
            panic!("UPnP actif attendu")
        };
        assert!(lecture.lues && !lecture.tronquees);
        assert_eq!(lecture.adresse_externe, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(lecture.description, igd::Description::default());
    }

    /// B1 (campagne 6) : un échec d'`upnpc` autre que « pas de box UPnP » n'est pas « actif, rien d'ouvert ».
    #[test]
    fn echec_de_upnpc_non_verifie() {
        assert_eq!(lire_upnpc("", None), Etat::OutilEnEchec);
        let erreur = "upnpc : miniupnpc library test client, version 2.2.5.\nList of UPNP devices found on the network :\n\
                      UPNP_GetValidIGD() failed: Connection timed out\n";
        assert_eq!(lire_upnpc(erreur, None), Etat::OutilEnEchec);
        assert_eq!(juger_upnpc(Some(0), ""), (Etat::OutilEnEchec, None));
        // Une table lue mais un code d'échec : pas cru.
        let table = "Found valid IGD : http://10.0.0.1:5000/ctl\nExternalIPAddress = 203.0.113.7\n \
                     i protocol exPort->inAddr:inPort description remoteHost leaseTime\n";
        assert_eq!(juger_upnpc(Some(1), table), (Etat::OutilEnEchec, None));
        assert_eq!(juger_upnpc(None, table), (Etat::OutilEnEchec, None));
        // « Pas de box UPnP » : miniupnpc sort en erreur, c'est bien une réponse.
        assert_eq!(
            juger_upnpc(Some(1), "No valid UPNP Internet Gateway Device found.\n"),
            (Etat::Absent, None)
        );
        // Réussi, sans aucune redirection : actif, rien d'ouvert.
        let (e, adresse) = juger_upnpc(Some(0), table);
        assert_eq!(adresse, Some(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(redirections(&e), &[] as &[Redirection]);
    }

    /// N'importe quel appareil du réseau peut demander une redirection à la box, avec la description de son choix :
    /// piégée, elle arrive inoffensive, « � » à la place de chaque caractère piégé.
    #[test]
    fn description_piegee() {
        let sortie = " 0 TCP  8080->10.0.0.30:80  'Cam\x1b]52;c;eA==\x07\x1b[2K\rFaux\u{202e}' '' 0\n";
        let e = lire_upnpc(sortie, None);
        let l = redirections(&e);
        assert_eq!(l[0].description, "Cam�]52;c;eA==��[2K�Faux�");
        assert_eq!((l[0].protocole.as_str(), l[0].appareil.as_str()), ("TCP", "10.0.0.30"));
        // L'interface UPnP de Windows : la même lecture.
        assert_eq!(lire_upnp_windows("UPNP_ABSENT\n"), Etat::Absent);
        let windows = "UPNP_ACTIF\nUPNP|TCP|8080|10.0.0.30|80|Cam\x1b]52;c;eA==\x07\x1b[2K\rFaux\u{202e}\nUPNP|UDP|3074|10.0.0.20|3074|Xbox SRA\n";
        let e = lire_upnp_windows(windows);
        let l = redirections(&e);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].description, "Cam�]52;c;eA==��[2K�Faux�");
        assert_eq!(
            l[1],
            Redirection {
                protocole: "UDP".into(),
                port_public: 3074,
                appareil: "10.0.0.20".into(),
                port_appareil: 3074,
                description: "Xbox SRA".into(),
                bail: 0,
                hote_distant: String::new(),
                active: true,
            }
        );
    }

    #[test]
    fn adresse_de_la_box_sur_internet() {
        let sortie = "Found valid IGD : http://10.0.0.1:5000/ctl\nLocal LAN ip address : 10.0.0.20\n\
                      Connection Type : IP_Routed\nExternalIPAddress = 100.64.12.34\n";
        assert_eq!(adresse_externe(sortie), Some(Ipv4Addr::new(100, 64, 12, 34)));
        assert_eq!(adresse_externe("No IGD UPnP Device found on the network !\n"), None);
    }
}
