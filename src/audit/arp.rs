//! Intégrité de la table ARP du réseau local (règles COM-ARP-002 à 004) : la box a-t-elle changé d'adresse MAC
//! d'un scan à l'autre, répond-elle avec l'adresse d'un fabricant d'ordinateurs ou de téléphones, une même adresse
//! MAC répond-elle pour plusieurs adresses IP. COM-ARP-001 (un autre appareil qui répond avec la MAC de la box)
//! reste au scan (`reseau::usurpation_arp`). Rien n'est envoyé : tout vient du scan déjà fait et des carnets.

use std::collections::BTreeMap;

use super::segmentation::{Appareil, Entree, liste_courte};
use crate::machine::{Constat, alerte, impossible, ok};
use crate::risk::Niveau;
use crate::{tr, trf};

/// Les constats du domaine, dans l'ordre des règles.
pub fn constats(e: &Entree) -> Vec<Constat> {
    vec![
        mac_de_la_box_changee(e),
        fabricant_de_la_box(e),
        mac_pour_plusieurs_adresses(e),
    ]
}

/// COM-ARP-002 : le même Wi-Fi, à la même adresse de box, connu sous une autre adresse MAC de box dans un carnet
/// précédent : un appareil se fait peut-être passer pour la box, ou la box a été remplacée (normal, à déclarer).
fn mac_de_la_box_changee(e: &Entree) -> Constat {
    let boite = e.appareils.iter().find(|a| a.boite);
    let Some(mac) = boite.and_then(|b| b.mac.as_deref()) else {
        return Constat {
            regle: "COM-ARP-002",
            ..impossible(
                "Réseau local",
                tr!("adresse MAC du routeur inconnue", "router MAC address unknown"),
            )
        };
    };
    let nom = e.nom_reseau.as_deref().filter(|n| !n.is_empty());
    let ip = boite.map(|b| b.ip);
    let anciennes: Vec<&str> = e
        .carnets
        .iter()
        .filter(|c| nom.is_some() && c.nom.as_deref() == nom && c.ip_boite == ip)
        .filter(|c| !c.mac_boite.eq_ignore_ascii_case(mac))
        .map(|c| c.mac_boite.as_str())
        .collect();
    if anciennes.is_empty() {
        return Constat {
            regle: "COM-ARP-002",
            ..ok(
                "Réseau local",
                trf!(
                    "Le routeur répond avec l'adresse MAC connue des scans précédents ({mac}).",
                    "The router answers with the MAC address known from previous scans ({mac})."
                ),
            )
        };
    }
    let nom = crate::ui::affichable(nom.unwrap_or_default());
    let boite = ip.map(|i| i.to_string()).unwrap_or_default();
    let liste = liste_courte(anciennes.into_iter());
    Constat {
        regle: "COM-ARP-002",
        ..alerte(
            "Réseau local",
            Niveau::Eleve,
            trf!(
                "Le routeur du Wi-Fi « {nom} » ({boite}) répond avec une autre adresse MAC ({mac}) que lors des scans précédents ({liste}) : un appareil se fait peut-être passer pour lui. Normal si vous venez de changer de routeur ou son module Wi-Fi : déclarez-le (apprentissage) et l'ancien carnet sera mis de côté.",
                "The router of Wi-Fi “{nom}” ({boite}) answers with a different MAC address ({mac}) than in previous scans ({liste}): a device may be posing as it. Normal if you just replaced the router or its Wi-Fi module: declare it (learning) and the old record will be set aside."
            ),
        )
    }
}

/// Fabricants de box, de routeurs et de points d'accès (débuts de nom du registre des adresses MAC, en minuscules).
/// ASUS et Xiaomi font aussi des ordinateurs ou des téléphones : ils restent ici, pour ne pas crier à tort.
const ROUTEURS: &[&str] = &[
    "sagemcom",
    "technicolor",
    "arris",
    "hitron",
    "askey",
    "sercomm",
    "arcadyan",
    "compal",
    "calix",
    "nokia",
    "huawei",
    "zte",
    "zyxel",
    "avm ",
    "avm audiovisuelles",
    "tp-link",
    "netgear",
    "linksys",
    "d-link",
    "asustek",
    "ubiquiti",
    "mikrotik",
    "google",
    "amazon",
    "eero",
    "synology",
    "cisco",
    "juniper",
    "freebox",
    "actiontec",
    "adtran",
    "thomson",
    "dasan",
    "fiberhome",
    "aruba",
    "tenda",
    "mercusys",
    "xiaomi",
    "routerboard",
    "edgecore",
    "cambium",
    "ruckus",
    "commscope",
    "vantiva",
    "sky uk",
    "bt ",
    "orange",
    "bouygues",
    "iliad",
    "sfr",
    "videotron",
    "telus",
    "bell ",
    "shaw ",
    "rogers",
];

/// Fabricants d'ordinateurs, de téléphones et de leurs cartes réseau : une box qui répond avec une telle adresse
/// est peut-être un ordinateur ou un téléphone qui se fait passer pour elle. Apple y est : AirPort n'est plus vendu.
const ORDINATEURS: &[&str] = &[
    "intel corporate",
    "intel corp",
    "apple",
    "samsung electronics",
    "dell",
    "hp inc",
    "hewlett packard",
    "hewlett-packard",
    "lenovo",
    "microsoft",
    "liteon",
    "lite-on",
    "azurewave",
    "oneplus",
    "oppo",
    "vivo mobile",
    "motorola mobility",
    "sony mobile",
    "lg electronics (mobile",
    "htc",
    "nothing technology",
    "fairphone",
    "framework",
    "acer",
    "msi",
    "micro-star",
    "gigabyte",
    "asrock",
    "toshiba",
    "fujitsu",
    "vaio",
];

/// COM-ARP-003 : la box devrait répondre avec l'adresse d'un fabricant de box ou de routeurs. Une MAC aléatoire
/// (téléphone, tablette) ou celle d'un fabricant d'ordinateurs : un appareil se fait peut-être passer pour elle ;
/// normal si l'on partage la connexion d'un téléphone ou si un PC sert de routeur, et c'est dit.
fn fabricant_de_la_box(e: &Entree) -> Constat {
    let Some(boite) = e.appareils.iter().find(|a| a.boite) else {
        return Constat {
            regle: "COM-ARP-003",
            ..impossible(
                "Réseau local",
                tr!("routeur absent du scan", "router missing from the scan"),
            )
        };
    };
    let aleatoire = boite
        .mac
        .as_deref()
        .and_then(|m| u8::from_str_radix(m.get(..2)?, 16).ok())
        .is_some_and(|premier| premier & 0x02 != 0);
    if aleatoire {
        return Constat {
            regle: "COM-ARP-003",
            ..alerte(
                "Réseau local",
                Niveau::Moyen,
                tr!(
                    "Le routeur répond avec une adresse MAC aléatoire, comme un téléphone ou une tablette : un appareil se fait peut-être passer pour lui. Normal si vous partagez la connexion d'un téléphone.",
                    "The router answers with a random MAC address, like a phone or a tablet: a device may be posing as it. Normal if you are sharing a phone's connection."
                ),
            )
        };
    }
    let Some(fabricant) = boite.fabricant.as_deref().filter(|f| !f.is_empty()) else {
        return Constat {
            regle: "COM-ARP-003",
            ..ok(
                "Réseau local",
                tr!(
                    "Le fabricant du routeur n'est pas dans le registre des adresses MAC : rien ne dit qu'un ordinateur ou un téléphone se fait passer pour lui.",
                    "The router's maker is not in the MAC address registry: nothing says a computer or a phone is posing as it."
                ),
            )
        };
    };
    let minuscules = fabricant.to_lowercase();
    let fabricant = crate::ui::affichable(fabricant);
    if ROUTEURS.iter().any(|r| minuscules.starts_with(r)) {
        return Constat {
            regle: "COM-ARP-003",
            ..ok(
                "Réseau local",
                trf!(
                    "Le routeur répond avec une adresse de {fabricant}, un fabricant de routeurs.",
                    "The router answers with an address from {fabricant}, a maker of routers."
                ),
            )
        };
    }
    if ORDINATEURS.iter().any(|o| minuscules.starts_with(o)) {
        return Constat {
            regle: "COM-ARP-003",
            ..alerte(
                "Réseau local",
                Niveau::Moyen,
                trf!(
                    "Le routeur répond avec une adresse de {fabricant} (ordinateurs, téléphones) : un ordinateur ou un téléphone se fait peut-être passer pour lui. Normal si vous partagez la connexion d'un téléphone ou si un PC sert de routeur.",
                    "The router answers with an address from {fabricant} (computers, phones): a computer or a phone may be posing as it. Normal if you are sharing a phone's connection or if a PC acts as the router."
                ),
            )
        };
    }
    Constat {
        regle: "COM-ARP-003",
        ..ok(
            "Réseau local",
            trf!(
                "Le routeur répond avec une adresse de {fabricant} : ni un fabricant d'ordinateurs ni un fabricant de routeurs connu, rien d'anormal.",
                "The router answers with an address from {fabricant}: neither a known computer maker nor a known router maker, nothing unusual."
            ),
        )
    }
}

/// COM-ARP-004 : une même adresse MAC qui répond pour plusieurs adresses IP, hors box (COM-ARP-001) : une machine
/// virtuelle en pont, un répéteur en proxy ARP, ou un appareil qui a changé d'adresse pendant le scan. Information.
fn mac_pour_plusieurs_adresses(e: &Entree) -> Constat {
    let mac_boite = e
        .appareils
        .iter()
        .find(|a| a.boite)
        .and_then(|b| b.mac.as_deref())
        .map(str::to_lowercase);
    let mut par_mac: BTreeMap<String, Vec<&Appareil>> = BTreeMap::new();
    for a in &e.appareils {
        if let Some(mac) = a.mac.as_deref().map(str::to_lowercase)
            && Some(&mac) != mac_boite.as_ref()
        {
            par_mac.entry(mac).or_default().push(a);
        }
    }
    let doublons: Vec<String> = par_mac
        .iter()
        .filter(|(_, appareils)| appareils.len() >= 2)
        .map(|(mac, appareils)| {
            let ips: Vec<String> = appareils.iter().map(|a| a.ip.to_string()).collect();
            let titre = appareils
                .iter()
                .find(|a| !a.titre.is_empty())
                .map(|a| format!(" ({})", crate::ui::affichable(&a.titre)))
                .unwrap_or_default();
            format!("{mac}{titre} → {}", ips.join(", "))
        })
        .collect();
    if doublons.is_empty() {
        return Constat {
            regle: "COM-ARP-004",
            ..ok(
                "Réseau local",
                tr!(
                    "Chaque adresse MAC du réseau ne répond que pour une adresse IP.",
                    "Each MAC address on the network answers for a single IP address."
                ),
            )
        };
    }
    let liste = liste_courte(doublons.iter().map(String::as_str));
    Constat {
        regle: "COM-ARP-004",
        ..alerte(
            "Réseau local",
            Niveau::Info,
            trf!(
                "Une même adresse MAC répond pour plusieurs adresses IP : {liste}. C'est une machine virtuelle en pont, un répéteur Wi-Fi, ou un appareil qui a changé d'adresse pendant le scan ; rien à faire si vous reconnaissez l'appareil.",
                "One MAC address answers for several IP addresses: {liste}. That is a bridged virtual machine, a Wi-Fi repeater, or a device that changed address during the scan; nothing to do if you recognize the device."
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::segmentation::tests::{appareil, entree};
    use super::*;
    use crate::audit::segmentation::Carnet;

    fn boite(mac: &str, fabricant: Option<&str>) -> Appareil {
        appareil(1, mac, fabricant, Some("box"), &[80, 443])
    }

    #[test]
    fn mac_de_la_box_comparee_aux_carnets() {
        let mut e = entree(vec![boite("e4:5d:51:10:20:30", Some("Sagemcom Broadband SAS"))]);
        // Aucun carnet, ou le carnet de cette box seulement : rien.
        assert_eq!(constats(&e)[0].probleme, None);
        e.carnets.push(Carnet {
            mac_boite: "e4:5d:51:10:20:30".into(),
            nom: Some("Salon".into()),
            ip_boite: Some("192.168.50.1".parse().unwrap()),
        });
        assert_eq!(constats(&e)[0].probleme, None);
        // Le même Wi-Fi, à la même adresse, sous une autre MAC de box : élevé, et l'ancienne MAC est nommée.
        e.carnets.push(Carnet {
            mac_boite: "44:e9:dd:00:00:09".into(),
            nom: Some("Salon".into()),
            ip_boite: Some("192.168.50.1".parse().unwrap()),
        });
        let c = &constats(&e)[0];
        assert_eq!((c.regle, c.probleme), ("COM-ARP-002", Some(Niveau::Eleve)));
        assert!(
            c.message.contains("44:e9:dd:00:00:09") && c.message.contains("Salon"),
            "{}",
            c.message
        );
        // Un autre Wi-Fi (chez un ami) à la même adresse de box : pas le même réseau.
        e.carnets[1].nom = Some("Chez Max".into());
        assert_eq!(constats(&e)[0].probleme, None);
        // Sans nom de réseau, rien ne se compare.
        e.carnets[1].nom = Some("Salon".into());
        e.nom_reseau = None;
        assert_eq!(constats(&e)[0].probleme, None);
        // Box sans MAC : non vérifié.
        e.appareils[0].mac = None;
        assert!(!constats(&e)[0].verifie);
    }

    #[test]
    fn fabricant_de_la_box_juge() {
        let juge = |mac: &str, fabricant: Option<&str>| constats(&entree(vec![boite(mac, fabricant)]))[1].probleme;
        assert_eq!(juge("e4:5d:51:10:20:30", Some("Sagemcom Broadband SAS")), None);
        assert_eq!(juge("e4:5d:51:10:20:30", Some("ASUSTek COMPUTER INC.")), None);
        assert_eq!(juge("f0:18:98:aa:bb:cc", Some("Apple, Inc.")), Some(Niveau::Moyen));
        assert_eq!(juge("00:50:56:aa:bb:cc", Some("Dell Inc.")), Some(Niveau::Moyen));
        assert_eq!(
            juge("02:11:22:33:44:55", Some("MAC aléatoire (téléphone/tablette ?)")),
            Some(Niveau::Moyen)
        );
        assert_eq!(juge("00:1b:21:00:00:01", Some("Fabricant Inconnu SA")), None);
        assert_eq!(juge("00:1b:21:00:00:01", None), None);
        // Sans box dans le scan : non vérifié.
        let e = entree(vec![appareil(
            20,
            "24:0a:c4:00:00:02",
            Some("Espressif Inc."),
            None,
            &[80],
        )]);
        assert!(!constats(&e)[1].verifie);
    }

    #[test]
    fn une_mac_pour_plusieurs_adresses() {
        let mut e = entree(vec![
            boite("e4:5d:51:10:20:30", Some("Sagemcom Broadband SAS")),
            appareil(20, "24:0a:c4:00:00:02", Some("Espressif Inc."), None, &[80]),
            appareil(21, "00:50:56:aa:bb:01", Some("VMware, Inc."), Some("vm-essai"), &[22]),
        ]);
        assert_eq!(constats(&e)[2].probleme, None);
        // La même MAC pour deux adresses : information, avec les deux adresses.
        e.appareils
            .push(appareil(22, "00:50:56:AA:BB:01", Some("VMware, Inc."), None, &[]));
        let c = &constats(&e)[2];
        assert_eq!((c.regle, c.probleme), ("COM-ARP-004", Some(Niveau::Info)));
        assert!(
            c.message.contains("192.168.50.21, 192.168.50.22") && c.message.contains("vm-essai"),
            "{}",
            c.message
        );
        // La MAC de la box qui répond ailleurs est l'affaire de COM-ARP-001 : pas comptée ici.
        e.appareils.pop();
        e.appareils.push(appareil(23, "e4:5d:51:10:20:30", None, None, &[]));
        assert_eq!(constats(&e)[2].probleme, None);
    }
}
