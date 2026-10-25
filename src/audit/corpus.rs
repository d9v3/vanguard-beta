//! Les cas du corpus de détection des fiches de l'audit du réseau (`modele::corpus`) : un scan, des carnets, des
//! bornes Wi-Fi et une sonde fabriqués, donnés au jugement de chaque domaine (`constats`, qui juge sans rien relire),
//! dont ne restent que les constats de la fiche du cas (le nom de son dossier).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::machine::Constat;
use crate::machine::wifi::elements::Protection;
use crate::machine::wifi::{Balise, Bande, Borne, Connexion};
use crate::modele::corpus::{Entree, Juge};
use crate::reseau::{Hote, empoisonnement};

pub(crate) const CAS: &[(&str, Juge)] = &[
    ("COM-ARP-002", segmentation),
    ("COM-ARP-004", segmentation),
    ("COM-SEG-004", segmentation),
    ("COM-SEG-005", segmentation),
    ("COM-PST-003", postes),
    ("COM-WIF-003", wifi),
    ("COM-DNS-004", super::dns_tls::corpus_divergence),
    ("COM-TLS-001", super::dns_tls::corpus_certificat),
    ("COM-TLS-003", super::dns_tls::corpus_racines),
    ("COM-ARP-001", crate::reseau::corpus_usurpation),
];

/// La fiche du cas : le nom de son dossier.
pub(crate) fn fiche(e: &Entree) -> String {
    e.dossier.file_name().unwrap().to_string_lossy().into_owned()
}

fn de_la_fiche(e: &Entree, constats: Vec<Constat>) -> Vec<Constat> {
    let id = fiche(e);
    constats.into_iter().filter(|c| c.regle == id).collect()
}

fn rien(v: &str) -> Option<String> {
    (!v.is_empty()).then(|| v.to_string())
}

/// COM-ARP-002, COM-ARP-004, COM-SEG-004, COM-SEG-005, sur le réseau « Salon » (192.168.50.0/24, box en .1) :
/// `appareil|dernier octet|mac|fabricant|nom|ports,…`, `dhcp|serveur`, `routeur6|adresse|interface|mac`,
/// `carnet|mac de la box|nom du Wi-Fi|adresse de la box`.
fn segmentation(e: &Entree) -> Vec<Constat> {
    use super::segmentation::{Carnet, RouteurIpv6};
    let appareils = e
        .de("appareil")
        .iter()
        .map(|c| {
            let ports: Vec<u16> = c[4]
                .split(',')
                .filter(|p| !p.is_empty())
                .map(|p| p.parse().unwrap())
                .collect();
            super::segmentation::tests::appareil(
                c[0].parse().unwrap(),
                c[1],
                Some(c[2]).filter(|f| !f.is_empty()),
                Some(c[3]).filter(|n| !n.is_empty()),
                &ports,
            )
        })
        .collect();
    let mut entree = super::segmentation::tests::entree(appareils);
    if let Some(c) = e.de("dhcp").first() {
        entree.dhcp_serveur = Some(c[0].parse().unwrap());
    }
    entree.routeurs_ipv6 = Some(
        e.de("routeur6")
            .iter()
            .map(|c| RouteurIpv6 {
                adresse: c[0].parse::<Ipv6Addr>().unwrap(),
                interface: c[1].to_string(),
                mac: rien(c[2]),
            })
            .collect(),
    );
    entree.carnets = e
        .de("carnet")
        .iter()
        .map(|c| Carnet {
            mac_boite: c[0].to_string(),
            nom: rien(c[1]),
            ip_boite: c[2].parse::<Ipv4Addr>().ok(),
        })
        .collect();
    let mut constats = super::segmentation::constats(&entree);
    constats.extend(super::arp::constats(&entree));
    de_la_fiche(e, constats)
}

fn hote(ip: Ipv4Addr, role: Option<&'static str>) -> Hote {
    Hote {
        ip,
        nom: None,
        mac: None,
        fabricant: None,
        surnom: None,
        premier_vu: None,
        role,
        nouvelle: false,
        ports: Vec::new(),
        alertes: Vec::new(),
        score: 100,
    }
}

/// COM-PST-003 : `empoisonneur|adresse|protocole,…` (LLMNR, NetBIOS, mDNS), ce que la sonde des faux noms a trouvé ;
/// sans ligne, la sonde a tourné sans réponse.
fn postes(e: &Entree) -> Vec<Constat> {
    let protocole = |p: &str| -> &'static str {
        match p {
            "LLMNR" => "LLMNR",
            "NetBIOS" => "NetBIOS",
            "mDNS" => "mDNS",
            autre => panic!("protocole inconnu : {autre}"),
        }
    };
    let trouves: Vec<empoisonnement::Empoisonneur> = e
        .de("empoisonneur")
        .iter()
        .map(|c| empoisonnement::Empoisonneur {
            ip: c[0].parse().unwrap(),
            protocoles: c[1].split(',').map(protocole).collect(),
        })
        .collect();
    let rapport = empoisonnement::Rapport::Teste(trouves);
    let passerelle = Ipv4Addr::new(192, 168, 50, 1);
    let hotes = [hote(passerelle, Some("passerelle"))];
    let entree = super::postes::Entree {
        hotes: &hotes,
        machine: &[],
        empoisonnement: Some(&rapport),
        botnets: None,
        passerelle: Some(passerelle),
        adresse_locale: Some(Ipv4Addr::new(192, 168, 50, 10)),
    };
    de_la_fiche(e, super::postes::constats(&entree))
}

/// COM-WIF-003 : `borne|nom du Wi-Fi|adresse de l'émetteur|canal|connectée (oui, non)`, toutes en WPA2, et
/// `connexion|nom du Wi-Fi|adresse de l'émetteur`.
fn wifi(e: &Entree) -> Vec<Constat> {
    let wpa2 = Protection {
        chiffree: true,
        rsn: true,
        aes: true,
        psk: true,
        ..Protection::default()
    };
    let bornes: Vec<Balise> = e
        .de("borne")
        .iter()
        .map(|c| {
            let canal: u16 = c[2].parse().unwrap();
            Balise {
                borne: Borne {
                    ssid: c[0].into(),
                    bssid: c[1].into(),
                    bande: Bande::de_canal(canal).unwrap(),
                    canal,
                    signal: Some(70),
                    actif: c[3] == "oui",
                },
                protection: wpa2,
                wps: None,
            }
        })
        .collect();
    let connexion = e.de("connexion").first().map(|c| Connexion {
        ssid: c[0].into(),
        bssid: c[1].into(),
        ..Connexion::default()
    });
    let entree = super::wifi::Entree {
        bornes: Ok(bornes),
        connexion,
        note: None,
        profils: Ok(Vec::new()),
        mac_box: None,
        nouveaux: None,
    };
    de_la_fiche(e, super::wifi::constats(&entree))
}
