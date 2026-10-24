//! Domaine Postes (code PST) : les ordinateurs de la maison. COM-PST-001 cet ordinateur vu du réseau (les constats
//! réseau du bilan de cette machine, repris tels quels : pare-feu, ports en écoute, SSH, découverte, partages,
//! navigation détournée, certificats racine, DNS) ; COM-PST-002 les autres ordinateurs d'après le scan (partage
//! Windows, bureau à distance, VNC, SSH, gestion à distance du Mac) ; COM-PST-003 un poste qui rayonne (empoisonneur
//! de noms démasqué pendant le scan, programmes de cet ordinateur reliés à un serveur de commande connu ; la liste
//! noire de l'adresse publique demande un accord : dite non vérifiée ici, avec l'outil qui la demande). Rien de
//! nouveau n'est sondé.

use std::net::Ipv4Addr;

use super::{avec_regle, non_verifie};
use crate::machine::{Constat, alerte, ok};
use crate::protection::sortantes;
use crate::reseau::{Hote, empoisonnement, objets};
use crate::risk::Niveau;
use crate::ui::*;

/// Ce que le domaine reçoit de l'audit, construit par `audit/mod.rs`.
pub struct Entree<'a> {
    pub hotes: &'a [Hote],
    /// Les constats réseau du bilan de cette machine (`audit::regle_du_reseau`).
    pub machine: &'a [Constat],
    /// La sonde des faux noms faite pendant le scan ; `None` : scan d'une cible précise, rien testé.
    pub empoisonnement: Option<&'a empoisonnement::Rapport>,
    /// Les programmes de cet ordinateur reliés à un serveur de commande ; `None` : connexions illisibles.
    pub botnets: Option<&'a sortantes::EnCours>,
    pub passerelle: Option<Ipv4Addr>,
    pub adresse_locale: Option<Ipv4Addr>,
}

/// « 10.0.0.30 (portable-alice · Hewlett Packard) », ou l'adresse seule.
fn nom(h: &Hote) -> String {
    let t = h.titre();
    if t.is_empty() {
        h.ip.to_string()
    } else {
        format!("{} ({t})", h.ip)
    }
}

/// Les autres ordinateurs de la maison : ni la box, ni cet ordinateur, ni un objet connecté reconnu.
fn autres_ordinateurs<'a>(e: &Entree<'a>) -> Vec<&'a Hote> {
    e.hotes
        .iter()
        .filter(|h| h.role.is_none() && Some(h.ip) != e.passerelle && Some(h.ip) != e.adresse_locale)
        .filter(|h| objets::genre(&super::appareil(h)).is_none())
        .collect()
}

/// COM-PST-001 : les constats réseau du bilan de cette machine, tels quels (chacun garde sa propre règle).
fn cet_ordinateur(machine: &[Constat]) -> Vec<Constat> {
    if machine.is_empty() {
        return vec![non_verifie(
            "Postes",
            "COM-PST-001",
            tr!(
                "Les constats réseau du bilan de cet ordinateur (pare-feu, ports en écoute, SSH, partages, DNS) n'ont pas pu être lus.",
                "This computer's network findings (firewall, listening ports, SSH, shares, DNS) could not be read."
            ),
        )];
    }
    machine.to_vec()
}

const PARTAGE_WINDOWS: [u16; 3] = [445, 139, 135];
const BUREAU_A_DISTANCE: [u16; 3] = [3389, 5900, 5901];
const MAC_A_DISTANCE: [u16; 2] = [3283, 3031];

/// COM-PST-002 : les autres ordinateurs de la maison et ce qu'ils exposent.
fn autres_postes(e: &Entree) -> Vec<Constat> {
    let ordinateurs = autres_ordinateurs(e);
    let tcp = |h: &Hote, liste: &[u16]| -> Vec<u16> {
        h.ports
            .iter()
            .filter(|p| !p.udp && liste.contains(&p.port))
            .map(|p| p.port)
            .collect()
    };
    let mut constats = Vec::new();
    let partages: Vec<String> = ordinateurs
        .iter()
        .filter(|h| !tcp(h, &PARTAGE_WINDOWS).is_empty())
        .map(|h| nom(h))
        .collect();
    if !partages.is_empty() {
        constats.push(
            alerte(
                "Postes",
                Niveau::Moyen,
                trf!(
                    "{} ordinateur(s) du réseau local exposent le partage Windows (445) au réseau ({}) : si l'un est infecté, un rançongiciel passe par là.",
                    "{} computer(s) of the home expose Windows file sharing (445) to the network ({}): if one is infected, ransomware goes through there.",
                    partages.len(),
                    resume(&partages, 4, ", ")
                ),
            )
            .manuel(
                tr!(
                    "Lancez Vanguard sur chacun (SMBv1, pare-feu) ; coupez le partage de fichiers sur ceux qui ne partagent rien",
                    "Run Vanguard on each one (SMBv1, firewall); turn file sharing off on those that share nothing"
                ),
                &[],
            ),
        );
    }
    for h in &ordinateurs {
        for port in tcp(h, &BUREAU_A_DISTANCE) {
            let service = crate::risk::info_port(port).service;
            constats.push(
                alerte(
                    "Postes",
                    Niveau::Eleve,
                    trf!(
                        "{} : bureau à distance ({service}, {port}) ouvert sur le réseau, très attaqué.",
                        "{}: remote desktop ({service}, {port}) open on the network, heavily attacked.",
                        nom(h)
                    ),
                )
                .manuel(
                    tr!(
                        "Sur ce poste : mot de passe fort et NLA pour le Bureau à distance, ou coupez-le ; pour VNC, un mot de passe fort ou un tunnel SSH",
                        "On that computer: a strong password and NLA for Remote Desktop, or turn it off; for VNC, a strong password or an SSH tunnel"
                    ),
                    &[],
                ),
            );
        }
        for port in tcp(h, &MAC_A_DISTANCE) {
            constats.push(alerte(
                "Postes",
                Niveau::Moyen,
                trf!(
                    "{} : gestion à distance du Mac ({}, {port}) ouverte au réseau : à couper si personne ne gère ce Mac.",
                    "{}: Mac remote management ({}, {port}) open to the network: turn it off if nobody manages this Mac.",
                    nom(h),
                    crate::risk::info_port(port).service
                ),
            ));
        }
        if !tcp(h, &[22]).is_empty() {
            constats.push(alerte(
                "Postes",
                Niveau::Info,
                trf!(
                    "{} : SSH ouvert sur le réseau ; bien si l'authentification se fait par clé et que le mot de passe est refusé.",
                    "{}: SSH open on the network; fine if authentication uses a key and passwords are refused.",
                    nom(h)
                ),
            ));
        }
    }
    if constats.is_empty() {
        let autres = e
            .hotes
            .iter()
            .filter(|h| h.role.is_none() && Some(h.ip) != e.passerelle && Some(h.ip) != e.adresse_locale)
            .count();
        constats.push(ok(
            "Postes",
            trf!(
                "Aucun autre ordinateur du réseau local n'expose de partage Windows ni de bureau à distance ({autres} autre(s) appareil(s) vu(s)).",
                "No other computer of the home exposes Windows sharing or a remote desktop ({autres} other device(s) seen)."
            ),
        ));
    }
    constats.into_iter().map(|c| avec_regle(c, "COM-PST-002")).collect()
}

/// L'empoisonneur de noms démasqué pendant le scan (LLMNR, NetBIOS, mDNS).
fn empoisonneur(e: &Entree) -> Vec<Constat> {
    let empoisonneurs = match e.empoisonnement {
        Some(empoisonnement::Rapport::Teste(liste)) => liste,
        Some(empoisonnement::Rapport::SansReseauLocal) | None => {
            return vec![non_verifie(
                "Postes",
                "COM-PST-003",
                tr!(
                    "Empoisonneur de noms non testé : la sonde des faux noms (LLMNR, NetBIOS, mDNS) n'a pas tourné (pas de réseau local).",
                    "Name poisoner not tested: the bogus-name probe (LLMNR, NetBIOS, mDNS) did not run (no local network)."
                ),
            )];
        }
    };
    if empoisonneurs.is_empty() {
        return vec![ok(
            "Postes",
            tr!(
                "Personne ne répond aux faux noms (LLMNR, NetBIOS, mDNS) : pas d'empoisonneur comme Responder sur ce réseau.",
                "No one answers bogus names (LLMNR, NetBIOS, mDNS): no poisoner like Responder on this network."
            ),
        )];
    }
    empoisonneurs
        .iter()
        .map(|p| {
            let qui = e
                .hotes
                .iter()
                .find(|h| h.ip == p.ip)
                .map_or_else(|| p.ip.to_string(), nom);
            alerte(
                "Postes",
                Niveau::Eleve,
                trf!(
                    "{qui} répond à des noms qui n'existent pas ({}) : un outil comme Responder vole ainsi les mots de passe Windows sur ce réseau.",
                    "{qui} answers names that do not exist ({}): a tool like Responder steals Windows passwords on this network this way.",
                    p.protocoles.join(", ")
                ),
            )
            .manuel(
                tr!(
                    "Débranchez cet appareil ; sur vos PC Windows, coupez LLMNR et NetBIOS (Vanguard le fait au bilan)",
                    "Unplug that device; on your Windows PCs, turn off LLMNR and NetBIOS (Vanguard does it in the audit)"
                ),
                &[],
            )
        })
        .collect()
}

/// Les programmes de cet ordinateur reliés à un serveur de commande connu (Feodo Tracker, ThreatFox).
fn botnets(en_cours: Option<&sortantes::EnCours>) -> Vec<Constat> {
    let Some(en_cours) = en_cours else {
        return vec![non_verifie(
            "Postes",
            "COM-PST-003",
            tr!(
                "Les connexions de cet ordinateur ne se lisent pas : programmes reliés à un serveur de commande non vérifiés (« Qui parle à Internet ? » le dit).",
                "This computer's connections cannot be read: programs connected to a command server not checked (“Who talks to the Internet?” says so)."
            ),
        )];
    };
    if en_cours.connexions.is_empty() {
        if en_cours.listes_absentes.is_empty() {
            return vec![ok(
                "Postes",
                tr!(
                    "Aucun programme de cet ordinateur ne parle à un serveur de commande de botnet connu (Feodo Tracker, ThreatFox).",
                    "No program on this computer talks to a known botnet command server (Feodo Tracker, ThreatFox)."
                ),
            )];
        }
        return vec![non_verifie(
            "Postes",
            "COM-PST-003",
            trf!(
                "Programmes reliés à un botnet pas entièrement vérifiés : {}.",
                "Programs connected to a botnet not fully checked: {}.",
                en_cours.listes_absentes.join(" ; ")
            ),
        )];
    }
    en_cours
        .connexions
        .iter()
        .map(|c| {
            alerte(
                "Postes",
                Niveau::Critique,
                trf!(
                    "{c} : un serveur de commande de botnet connu. Cet ordinateur est sans doute infecté.",
                    "{c}: a known botnet command server. This computer is probably infected."
                ),
            )
            .manuel(
                tr!(
                    "Coupez Internet d'abord, puis ouvrez « Après une infection » dans Vanguard (vanguard depanner infection)",
                    "Cut the Internet first, then open “After an infection” in Vanguard (vanguard troubleshoot infection)"
                ),
                &[],
            )
        })
        .collect()
}

/// La liste noire de l'adresse publique : quatre services verraient l'adresse, Vanguard ne la cherche qu'avec un
/// accord donné à l'outil qui le demande.
fn liste_noire() -> Constat {
    non_verifie(
        "Postes",
        "COM-PST-003",
        tr!(
            "L'adresse Internet publique n'est cherchée dans les listes noires qu'avec votre accord : « Adresse sur liste noire ? » (vanguard listes-noires) le demande, et dit si un appareil du réseau local envoie du pourriel ou des attaques.",
            "The home's public address is only looked up in blocklists with your consent: “Address on blocklists?” (vanguard listes-noires) asks for it, and says whether a device of the home sends spam or attacks."
        ),
    )
}

pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut constats = cet_ordinateur(e.machine);
    constats.extend(autres_postes(e));
    let mut rayonne = empoisonneur(e);
    rayonne.extend(botnets(e.botnets));
    rayonne.push(liste_noire());
    constats.extend(rayonne.into_iter().map(|c| avec_regle(c, "COM-PST-003")));
    constats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::appareils::tests::hote;

    /// Le réseau « Salon » inventé : une box, deux PC, un Mac, une caméra (pas un ordinateur), cette machine.
    fn salon() -> Vec<Hote> {
        vec![
            hote(
                "10.0.0.1",
                Some("Sagemcom Broadband SAS"),
                Some("passerelle"),
                &[80, 53],
            ),
            hote("10.0.0.30", Some("Hewlett Packard"), None, &[135, 445, 139]),
            hote("10.0.0.31", Some("Dell Inc."), None, &[3389, 445]),
            hote("10.0.0.32", Some("Apple, Inc."), None, &[22, 3283]),
            hote(
                "10.0.0.9",
                Some("Hangzhou Hikvision Digital Technology Co.,Ltd."),
                None,
                &[445, 554],
            ),
            hote("10.0.0.50", Some("Intel Corporate"), Some("cette machine"), &[22]),
        ]
    }

    fn entree<'a>(
        hotes: &'a [Hote],
        machine: &'a [Constat],
        empoisonnement: Option<&'a empoisonnement::Rapport>,
        botnets: Option<&'a sortantes::EnCours>,
    ) -> Entree<'a> {
        Entree {
            hotes,
            machine,
            empoisonnement,
            botnets,
            passerelle: Some("10.0.0.1".parse().unwrap()),
            adresse_locale: Some("10.0.0.50".parse().unwrap()),
        }
    }

    fn regle<'a>(constats: &'a [Constat], id: &str) -> Vec<&'a Constat> {
        constats.iter().filter(|c| c.regle == id).collect()
    }

    #[test]
    fn cet_ordinateur_repris_tel_quel() {
        let mut pare_feu = ok("Pare-feu", "ufw actif.");
        pare_feu.regle = "LNX-PFE-001";
        let mut port = alerte("Ports en écoute", Niveau::Moyen, "8080/tcp ouvert.");
        port.regle = "LNX-RES-001";
        let hotes = salon();
        let c = constats(&entree(&hotes, &[pare_feu, port], None, None));
        assert_eq!(c[0].regle, "LNX-PFE-001");
        assert_eq!((c[1].regle, c[1].probleme), ("LNX-RES-001", Some(Niveau::Moyen)));
        // Sans constat de la machine : non vérifié, jamais « rien à dire ».
        let c = constats(&entree(&hotes, &[], None, None));
        let pst1 = regle(&c, "COM-PST-001");
        assert!(pst1.len() == 1 && !pst1[0].verifie);
        for c in c.iter().filter(|c| c.regle.starts_with("COM-PST-")) {
            assert!(
                crate::audit::fiches::FICHES.iter().any(|f| f.id == c.regle),
                "{} sans fiche",
                c.regle
            );
        }
    }

    #[test]
    fn autres_ordinateurs_de_la_maison() {
        let hotes = salon();
        let c = constats(&entree(&hotes, &[], None, None));
        let pst2 = regle(&c, "COM-PST-002");
        let niveaux: Vec<Option<Niveau>> = pst2.iter().map(|c| c.probleme).collect();
        // Le partage Windows des deux PC (un seul constat), le bureau à distance de Dell, la gestion à distance et le
        // SSH du Mac ; la caméra, avec son 445, n'est pas un ordinateur.
        assert_eq!(
            niveaux,
            [
                Some(Niveau::Moyen),
                Some(Niveau::Eleve),
                Some(Niveau::Moyen),
                Some(Niveau::Info)
            ]
        );
        assert!(pst2[0].message.starts_with("2 ordinateur(s)"), "{}", pst2[0].message);
        assert!(pst2[0].message.contains("10.0.0.30") && !pst2[0].message.contains("10.0.0.9"));
        assert!(pst2[1].message.contains("10.0.0.31") && pst2[1].message.contains("RDP"));
        assert!(pst2[2].message.contains("10.0.0.32") && pst2[3].message.contains("SSH"));
        // Rien d'exposé : un constat qui va bien, avec le nombre d'autres appareils. Une imprimante HP surnommée
        // « imprimante HP » n'est pas un ordinateur, même avec son partage Windows ouvert (HP fait les deux).
        let mut imprimante = hote("10.0.0.12", Some("Hewlett Packard"), None, &[445, 80]);
        imprimante.surnom = Some("imprimante HP".into());
        let calmes = vec![
            hote("10.0.0.1", None, Some("passerelle"), &[80]),
            hote("10.0.0.30", Some("Hewlett Packard"), None, &[8009]),
            imprimante,
        ];
        let c = regle(&constats(&entree(&calmes, &[], None, None)), "COM-PST-002")
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            c.len() == 1 && c[0].probleme.is_none() && c[0].message.contains("(2 autre"),
            "{}",
            c[0].message
        );
    }

    #[test]
    fn un_poste_qui_rayonne() {
        let hotes = salon();
        let teste = empoisonnement::Rapport::Teste(vec![empoisonnement::Empoisonneur {
            ip: "10.0.0.31".parse().unwrap(),
            protocoles: vec!["LLMNR", "NetBIOS"],
        }]);
        let relie = sortantes::EnCours {
            connexions: ["outil → 192.0.2.7:443 (Emotet, ThreatFox)".to_string()].into(),
            listes_absentes: Vec::new(),
        };
        let c = regle(
            &constats(&entree(&hotes, &[], Some(&teste), Some(&relie))),
            "COM-PST-003",
        )
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].probleme, Some(Niveau::Eleve));
        assert!(c[0].message.contains("10.0.0.31") && c[0].message.contains("LLMNR, NetBIOS"));
        assert_eq!(c[1].probleme, Some(Niveau::Critique));
        assert!(c[1].message.contains("Emotet"));
        // La liste noire demande un accord : toujours dite non vérifiée, avec l'outil qui la demande.
        assert!(!c[2].verifie && c[2].message.contains("listes-noires"));
        // Personne aux faux noms, aucune connexion suspecte, listes lues : tout va bien.
        let calme = empoisonnement::Rapport::Teste(Vec::new());
        let propre = sortantes::EnCours {
            connexions: std::collections::BTreeSet::new(),
            listes_absentes: Vec::new(),
        };
        let c = regle(
            &constats(&entree(&hotes, &[], Some(&calme), Some(&propre))),
            "COM-PST-003",
        )
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
        assert!(c[0].probleme.is_none() && c[1].probleme.is_none());
        // Une liste de botnets manquante, des connexions illisibles, pas de réseau local : non vérifié.
        let partiel = sortantes::EnCours {
            connexions: std::collections::BTreeSet::new(),
            listes_absentes: vec!["liste de Feodo Tracker pas vérifiée (pas d'Internet ?)".into()],
        };
        let c = botnets(Some(&partiel));
        assert!(c.len() == 1 && !c[0].verifie && c[0].message.contains("Feodo"));
        assert!(!botnets(None)[0].verifie);
        let sans = empoisonneur(&entree(
            &hotes,
            &[],
            Some(&empoisonnement::Rapport::SansReseauLocal),
            None,
        ));
        assert!(sans.len() == 1 && !sans[0].verifie);
    }
}
