//! `appareils --json` : le scan du réseau local. Chaque appareil avec ses ports ouverts et ses risques, ceux qui sont
//! nouveaux, ceux qui manquent, puis deux contrôles du réseau entier : les redirections UPnP de la box et les faux
//! noms (empoisonnement LLMNR, NetBIOS, mDNS).
//!
//! La règle de Vanguard tient ici aussi : ce qui n'a pas pu être vu n'est jamais dit sain. Une box qui n'a pas pu
//! être interrogée, une sonde qui n'a pas tourné, une forme écrite par une version plus récente ou un appareil
//! illisible vont dans `manques`. La note globale du scan n'est pas montrée : elle ne compte ni l'UPnP ni les faux
//! noms, et un « 100 » à côté d'un contrôle manqué rassurerait à tort.

use serde::Deserialize;
use serde_json::value::RawValue;

use super::bilan::Gravite;
use super::{Liste, Texte};

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct PortBrut {
    port: Option<u64>,
    service: Texte,
    niveau: Texte,
    nouveau: Option<bool>,
    udp: Option<bool>,
    programme: Texte,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct HoteBrut {
    ip: Texte,
    nom: Texte,
    mac: Texte,
    fabricant: Texte,
    surnom: Texte,
    premier_vu: Texte,
    role: Texte,
    nouvelle: Option<bool>,
    ports: Liste<PortBrut>,
    /// `[niveau, texte]`, comme Vanguard écrit un `(Niveau, String)`.
    alertes: Liste<(Texte, Texte)>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct AbsentBrut {
    ip: Texte,
    titre: Texte,
    dernier_vu: Texte,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Brut {
    reseau: Texte,
    nom_reseau: Texte,
    hotes: Liste<HoteBrut>,
    absents: Liste<AbsentBrut>,
    // Gardés tels qu'écrits, puis lus à part : une forme inconnue ne fait pas tomber tout le scan, elle est dite
    // non vérifiée.
    upnp: Option<Box<RawValue>>,
    empoisonnement: Option<Box<RawValue>>,
    carnet_non_cru: Texte,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct RedirectionBrute {
    protocole: Texte,
    port_public: Option<u64>,
    appareil: Texte,
    port_appareil: Option<u64>,
    description: Texte,
    hote_distant: Texte,
    active: Option<bool>,
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct LectureBrute {
    redirections: Liste<RedirectionBrute>,
    lues: Option<bool>,
    tronquees: Option<bool>,
    ailleurs: Liste<Texte>,
}

/// `upnp::Etat` de Vanguard, tel que serde l'écrit (le nom de la variante, avec son contenu s'il en a un).
#[derive(Deserialize, Debug)]
enum UpnpBrut {
    Absent,
    Actif(LectureBrute),
    OutilAbsent,
    OutilEnEchec,
    Usurpee(Liste<Texte>),
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct EmpoisonneurBrut {
    ip: Texte,
    protocoles: Liste<Texte>,
}

#[derive(Deserialize, Debug)]
enum EmpoisonnementBrut {
    Teste(Liste<EmpoisonneurBrut>),
    SansReseauLocal,
}

/// Un port ouvert prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub numero: Option<u16>,
    pub service: String,
    pub gravite: Option<Gravite>,
    pub nouveau: bool,
    pub udp: bool,
    /// Le programme qui écoute (cet ordinateur seulement).
    pub programme: String,
}

/// Un appareil prêt à montrer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appareil {
    pub ip: String,
    /// Le surnom, le nom et le fabricant, comme `vanguard appareils` les assemble ; à défaut, l'adresse.
    pub titre: String,
    pub mac: String,
    pub role: String,
    pub nouveau: bool,
    pub premier_vu: String,
    pub ports: Vec<Port>,
    pub alertes: Vec<(Option<Gravite>, String)>,
    /// Ports ou alertes qui ne se lisaient pas.
    pub illisibles: usize,
}

impl Appareil {
    /// La plus grave de ses alertes et de ses ports.
    pub fn gravite(&self) -> Option<Gravite> {
        let alertes = self.alertes.iter().filter_map(|(g, _)| *g);
        let ports = self.ports.iter().filter_map(|p| p.gravite);
        alertes.chain(ports).max()
    }

    /// Un risque à dire : au moins moyen.
    pub fn a_risque(&self) -> bool {
        self.gravite().is_some_and(|g| g >= Gravite::Moyenne)
    }

    pub fn passerelle(&self) -> bool {
        self.role == "passerelle"
    }
}

/// Un appareil déjà vu sur ce réseau, absent de ce scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absent {
    pub ip: String,
    pub titre: String,
    pub dernier_vu: String,
}

/// Une redirection UPnP de la box : un port d'Internet envoyé vers un appareil d'ici.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirection {
    pub protocole: String,
    pub port_public: Option<u16>,
    pub appareil: String,
    pub port_appareil: Option<u16>,
    pub description: String,
    /// Le seul hôte d'Internet admis ; vide : tout Internet.
    pub hote_distant: String,
    /// Désactivée dans la box : sans effet tant qu'elle le reste. Absent : dite active, pour ne rien taire.
    pub active: bool,
}

/// Ce qu'on sait de l'UPnP de la box.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Upnp {
    /// Aucune box UPnP : UPnP coupé (le mieux) ou absent.
    Absent,
    Actif {
        redirections: Vec<Redirection>,
        /// La box a répondu aux questions : sinon ses redirections restent non vérifiées.
        lues: bool,
        /// La liste s'est arrêtée avant la fin : la box en a peut-être d'autres.
        tronquees: bool,
        /// D'autres appareils se disent box : écartés, et suspects.
        ailleurs: usize,
        illisibles: usize,
    },
    /// La box n'a pas pu être interrogée, l'outil de repli manque.
    OutilAbsent,
    /// La box n'a pas pu être interrogée, l'outil de repli a échoué.
    OutilEnEchec,
    /// La passerelle n'a pas répondu, d'autres appareils se disent box (combien).
    Usurpee(usize),
    /// Pas écrit (le contrôle n'a pas abouti), ou d'une forme inconnue de cette fenêtre.
    NonLu,
}

/// La sonde des faux noms.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Empoisonnement {
    /// Testé : les appareils qui ont répondu à un nom inventé (adresse, protocoles), peut-être aucun.
    Teste {
        empoisonneurs: Vec<(String, String)>,
        illisibles: usize,
    },
    SansReseauLocal,
    NonLu,
}

/// Le scan relu.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vue {
    /// Le nom du réseau quand il est connu, sinon sa plage d'adresses.
    pub reseau: String,
    pub appareils: Vec<Appareil>,
    pub absents: Vec<Absent>,
    /// Appareils et absents illisibles.
    pub illisibles: usize,
    pub upnp: Upnp,
    pub empoisonnement: Empoisonnement,
    /// Le carnet de cet ordinateur ne pouvait pas être cru : ce qu'en dit Vanguard.
    pub carnet_non_cru: String,
}

fn port(n: Option<u64>) -> Option<u16> {
    n.and_then(|n| u16::try_from(n).ok())
}

fn nom(t: &Texte, max: usize) -> String {
    crate::nettoyage::nom(t.as_str(), max)
}

impl From<HoteBrut> for Appareil {
    fn from(b: HoteBrut) -> Appareil {
        let ip = nom(&b.ip, 40);
        let titre = [&b.surnom, &b.nom, &b.fabricant]
            .into_iter()
            .filter(|t| !t.is_empty())
            .map(|t| nom(t, 60))
            .collect::<Vec<_>>()
            .join(" · ");
        Appareil {
            titre: if titre.is_empty() { ip.clone() } else { titre },
            ip,
            mac: nom(&b.mac, 40),
            role: nom(&b.role, 30),
            nouveau: b.nouvelle == Some(true),
            premier_vu: nom(&b.premier_vu, 32),
            illisibles: b.ports.illisibles.saturating_add(b.alertes.illisibles),
            ports: b
                .ports
                .elements
                .into_iter()
                .map(|p| Port {
                    numero: port(p.port),
                    service: nom(&p.service, 40),
                    gravite: Gravite::lire(p.niveau.as_str()),
                    nouveau: p.nouveau == Some(true),
                    udp: p.udp == Some(true),
                    programme: nom(&p.programme, 60),
                })
                .collect(),
            alertes: b
                .alertes
                .elements
                .into_iter()
                .map(|(n, t)| (Gravite::lire(n.as_str()), nom(&t, 300)))
                .collect(),
        }
    }
}

fn lire_upnp(brut: Option<&RawValue>) -> Upnp {
    let Some(Ok(u)) = brut.map(|r| serde_json::from_str::<UpnpBrut>(r.get())) else {
        return Upnp::NonLu;
    };
    match u {
        UpnpBrut::Absent => Upnp::Absent,
        UpnpBrut::OutilAbsent => Upnp::OutilAbsent,
        UpnpBrut::OutilEnEchec => Upnp::OutilEnEchec,
        UpnpBrut::Usurpee(ips) => Upnp::Usurpee(ips.elements.len().saturating_add(ips.illisibles)),
        UpnpBrut::Actif(l) => Upnp::Actif {
            illisibles: l.redirections.illisibles,
            redirections: l
                .redirections
                .elements
                .into_iter()
                .map(|r| Redirection {
                    protocole: nom(&r.protocole, 10),
                    port_public: port(r.port_public),
                    appareil: nom(&r.appareil, 40),
                    port_appareil: port(r.port_appareil),
                    description: nom(&r.description, 80),
                    hote_distant: nom(&r.hote_distant, 60),
                    active: r.active != Some(false),
                })
                .collect(),
            // Absent : pas prouvé lu.
            lues: l.lues == Some(true),
            tronquees: l.tronquees == Some(true),
            ailleurs: l.ailleurs.elements.len().saturating_add(l.ailleurs.illisibles),
        },
    }
}

fn lire_empoisonnement(brut: Option<&RawValue>) -> Empoisonnement {
    let Some(Ok(e)) = brut.map(|r| serde_json::from_str::<EmpoisonnementBrut>(r.get())) else {
        return Empoisonnement::NonLu;
    };
    match e {
        EmpoisonnementBrut::SansReseauLocal => Empoisonnement::SansReseauLocal,
        EmpoisonnementBrut::Teste(l) => Empoisonnement::Teste {
            illisibles: l.illisibles,
            empoisonneurs: l
                .elements
                .into_iter()
                .map(|e| {
                    let protocoles: Vec<String> = e.protocoles.elements.iter().map(|p| nom(p, 20)).collect();
                    (nom(&e.ip, 40), protocoles.join(", "))
                })
                .collect(),
        },
    }
}

pub fn lire(sortie: &[u8]) -> Result<Vue, String> {
    let b: Brut = super::lire(sortie)?;
    let reseau = if b.nom_reseau.is_empty() {
        &b.reseau
    } else {
        &b.nom_reseau
    };
    Ok(Vue {
        reseau: nom(reseau, 80),
        illisibles: b.hotes.illisibles.saturating_add(b.absents.illisibles),
        appareils: b.hotes.elements.into_iter().map(Appareil::from).collect(),
        absents: b
            .absents
            .elements
            .into_iter()
            .map(|a| Absent {
                ip: nom(&a.ip, 40),
                titre: nom(&a.titre, 120),
                dernier_vu: nom(&a.dernier_vu, 32),
            })
            .collect(),
        upnp: lire_upnp(b.upnp.as_deref()),
        empoisonnement: lire_empoisonnement(b.empoisonnement.as_deref()),
        carnet_non_cru: crate::nettoyage::nom(b.carnet_non_cru.as_str(), 300),
    })
}

impl Vue {
    pub fn nouveaux(&self) -> usize {
        self.appareils.iter().filter(|a| a.nouveau).count()
    }

    pub fn a_risque(&self) -> usize {
        self.appareils.iter().filter(|a| a.a_risque()).count()
    }

    /// Les redirections UPnP qui ouvrent vraiment un port (celles que la box dit désactivées n'ouvrent rien).
    pub fn redirections_actives(&self) -> usize {
        match &self.upnp {
            Upnp::Actif { redirections, .. } => redirections.iter().filter(|r| r.active).count(),
            _ => 0,
        }
    }

    pub fn empoisonneurs(&self) -> usize {
        match &self.empoisonnement {
            Empoisonnement::Teste { empoisonneurs, .. } => empoisonneurs.len(),
            _ => 0,
        }
    }

    /// Quelque chose à regarder : un appareil ou un port nouveau, un risque au moins moyen, une redirection UPnP
    /// active, un appareil qui répond aux faux noms.
    pub fn a_signaler(&self) -> bool {
        self.appareils
            .iter()
            .any(|a| a.nouveau || a.a_risque() || a.ports.iter().any(|p| p.nouveau))
            || self.redirections_actives() > 0
            || self.empoisonneurs() > 0
    }

    /// Ce qui n'a pas pu être vérifié, une phrase par manque.
    pub fn manques(&self) -> Vec<String> {
        let mut m: Vec<String> = Vec::new();
        let mut dire = |s: &str| m.push(s.to_string());
        match &self.upnp {
            Upnp::Absent => {}
            Upnp::Actif {
                lues,
                tronquees,
                ailleurs,
                illisibles,
                ..
            } => {
                if !lues {
                    dire(crate::tr!(
                        "La box a refusé de dire ses redirections UPnP : non vérifié",
                        "The router refused to list its UPnP forwards: not verified"
                    ));
                }
                if *tronquees || *illisibles > 0 {
                    dire(crate::tr!(
                        "La liste des redirections UPnP est incomplète",
                        "The list of UPnP forwards is incomplete"
                    ));
                }
                if *ailleurs > 0 {
                    dire(crate::tr!(
                        "D'autres appareils se disent la box : écartés, suspects",
                        "Other devices claim to be the router: ignored, suspicious"
                    ));
                }
            }
            Upnp::OutilAbsent => dire(crate::tr!(
                "La box n'a pas pu être interrogée en UPnP (outil de repli absent) : non vérifié",
                "The router could not be asked over UPnP (fallback tool missing): not verified"
            )),
            Upnp::OutilEnEchec => dire(crate::tr!(
                "La box n'a pas pu être interrogée en UPnP : non vérifié",
                "The router could not be asked over UPnP: not verified"
            )),
            Upnp::Usurpee(_) => dire(crate::tr!(
                "La box n'a pas répondu en UPnP, mais d'autres appareils se disent box : suspect, non vérifié",
                "The router did not answer over UPnP, but other devices claim to be it: suspicious, not verified"
            )),
            Upnp::NonLu => dire(crate::tr!(
                "UPnP de la box : pas lu, non vérifié",
                "Router UPnP: not read, not verified"
            )),
        }
        match &self.empoisonnement {
            Empoisonnement::Teste { illisibles: 0, .. } => {}
            Empoisonnement::Teste { .. } => dire(crate::tr!(
                "Faux noms : une réponse de la sonde est illisible",
                "Fake names: an answer from the probe is unreadable"
            )),
            Empoisonnement::SansReseauLocal => dire(crate::tr!(
                "Faux noms : rien n'a pu être testé (pas de réseau local)",
                "Fake names: nothing could be tested (no local network)"
            )),
            Empoisonnement::NonLu => dire(crate::tr!(
                "Faux noms : pas lu, non vérifié",
                "Fake names: not read, not verified"
            )),
        }
        if !self.carnet_non_cru.is_empty() {
            m.push(self.carnet_non_cru.clone());
        }
        let illisibles = self
            .appareils
            .iter()
            .map(|a| a.illisibles)
            .fold(self.illisibles, usize::saturating_add);
        if illisibles > 0 {
            m.push(crate::trf!(
                "{} élément(s) du scan illisible(s)",
                "{} unreadable scan item(s)",
                illisibles
            ));
        }
        m
    }

    /// Le résumé d'une ligne, pour la console et l'accueil.
    pub fn resume(&self) -> String {
        crate::trf!(
            "{} appareil(s), {} nouveau(x), {} à risque, {} pas pu vérifier",
            "{} device(s), {} new, {} at risk, {} could not check",
            self.appareils.len(),
            self.nouveaux(),
            self.a_risque(),
            self.manques().len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valeurs inventées : un réseau « Salon », des adresses de 192.168.1.0/24, des MAC au préfixe de fabricant réel
    // et à la fin inventée.
    const SCAN: &str = r#"{
        "reseau": "192.168.1.0/24", "nom_reseau": "Salon", "duree_s": 9.5, "score_global": 85, "note": "bon",
        "absents": [{"ip": "192.168.1.40", "titre": "Tablette", "dernier_vu": "2026-11-01"}],
        "hotes": [
            {"ip": "192.168.1.1", "nom": "box", "mac": "f8:79:0a:00:00:01", "fabricant": "Arris", "surnom": null,
             "premier_vu": "2026-10-01", "role": "passerelle", "nouvelle": false, "score": 90,
             "ports": [{"port": 80, "service": "HTTP", "niveau": "Moyen", "banniere": null, "conseil": "x",
                        "nouveau": false, "programme": null}],
             "alertes": [["Moyen", "Page d'administration sans chiffrement."]]},
            {"ip": "192.168.1.30", "nom": null, "mac": "00:17:88:00:00:02", "fabricant": "Philips",
             "surnom": "Lampe", "premier_vu": null, "role": null, "nouvelle": true, "score": 100,
             "ports": [{"port": 1900, "service": "SSDP", "niveau": "Info", "nouveau": true, "udp": true}],
             "alertes": []}
        ],
        "upnp": {"Actif": {"description": {}, "adresse_externe": "203.0.113.5", "connexion": "Connected",
                 "redirections": [{"protocole": "TCP", "port_public": 3074, "appareil": "192.168.1.50",
                     "port_appareil": 3074, "description": "Console", "bail": 0, "hote_distant": "", "active": true}],
                 "lues": true, "tronquees": false}},
        "empoisonnement": {"Teste": []}
    }"#;

    #[test]
    fn lit_un_scan() {
        let v = lire(SCAN.as_bytes()).unwrap();
        assert_eq!(v.reseau, "Salon");
        assert_eq!(v.appareils.len(), 2);
        let box_ = &v.appareils[0];
        assert!(box_.passerelle());
        assert_eq!(box_.titre, "box · Arris");
        assert_eq!(box_.gravite(), Some(Gravite::Moyenne));
        assert!(box_.a_risque());
        let lampe = &v.appareils[1];
        assert_eq!(lampe.titre, "Lampe · Philips");
        assert!(lampe.nouveau && lampe.ports[0].udp && lampe.ports[0].nouveau);
        assert!(!lampe.a_risque());
        assert_eq!(v.absents[0].titre, "Tablette");
        assert_eq!(v.redirections_actives(), 1);
        assert_eq!(v.empoisonneurs(), 0);
        assert!(v.a_signaler());
        assert_eq!(v.manques(), Vec::<String>::new());
        assert!(v.resume().contains('2'));
    }

    #[test]
    fn ce_qui_n_a_pas_pu_etre_vu_est_dit() {
        let un = r#"{"ip": "192.168.1.20"}"#;
        let scan = |upnp: &str, emp: &str| lire(format!(r#"{{"hotes": [{un}], {upnp}{emp}}}"#).as_bytes()).unwrap();
        // Tout vu, rien à dire.
        let v = scan(r#""upnp": "Absent","#, r#""empoisonnement": {"Teste": []}"#);
        assert!(!v.a_signaler());
        assert_eq!(v.manques(), Vec::<String>::new());
        assert_eq!(v.appareils[0].titre, "192.168.1.20");
        for upnp in [
            r#""upnp": "OutilAbsent","#,
            r#""upnp": "OutilEnEchec","#,
            r#""upnp": {"Usurpee": ["192.168.1.66"]},"#,
            r#""upnp": {"Actif": {"redirections": [], "lues": false}},"#,
            r#""upnp": {"Actif": {"redirections": [], "lues": true, "tronquees": true}},"#,
            r#""upnp": {"Actif": {"redirections": [7], "lues": true}},"#,
            // Écrit par une version plus récente, ou pas écrit du tout : non vérifié.
            r#""upnp": "Autre","#,
            r#""upnp": {"Actif": 3},"#,
            r#""upnp": null,"#,
            "",
        ] {
            let v = scan(upnp, r#""empoisonnement": {"Teste": []}"#);
            assert_eq!(v.manques().len(), 1, "{upnp}");
        }
        for emp in [
            r#""empoisonnement": "SansReseauLocal""#,
            r#""empoisonnement": {"Teste": [{"ip": "x"}, 4]}"#,
            r#""empoisonnement": "Autre""#,
            r#""empoisonnement": 12"#,
            r#""carnet_non_cru": null"#,
        ] {
            let v = scan(r#""upnp": "Absent","#, emp);
            assert_eq!(v.manques().len(), 1, "{emp}");
        }
        // Le carnet qui ne pouvait pas être cru : dit tel que Vanguard l'écrit, propre.
        let v = scan(
            r#""upnp": "Absent","#,
            "\"empoisonnement\": {\"Teste\": []}, \"carnet_non_cru\": \"Carnet \\u001b[31mchangé\"",
        );
        assert_eq!(v.manques(), ["Carnet changé"]);
    }

    #[test]
    fn un_faux_nom_ou_une_redirection_se_signale() {
        let v = lire(
            br#"{"hotes": [], "upnp": "Absent",
                 "empoisonnement": {"Teste": [{"ip": "192.168.1.66", "protocoles": ["LLMNR", "mDNS"]}]}}"#,
        )
        .unwrap();
        assert!(v.a_signaler());
        assert_eq!(
            v.empoisonnement,
            Empoisonnement::Teste {
                empoisonneurs: vec![("192.168.1.66".into(), "LLMNR, mDNS".into())],
                illisibles: 0
            }
        );
        // Une redirection désactivée dans la box n'ouvre rien ; une sans le champ est dite active.
        let r = |active: &str| {
            let json = format!(
                r#"{{"upnp": {{"Actif": {{"lues": true, "redirections": [{{"port_public": 22{active}}}]}}}},
                    "empoisonnement": {{"Teste": []}}}}"#
            );
            lire(json.as_bytes()).unwrap().redirections_actives()
        };
        assert_eq!(r(r#", "active": false"#), 0);
        assert_eq!(r(""), 1);
    }

    #[test]
    fn un_scan_abime_ne_fait_pas_tomber_la_fenetre() {
        assert!(lire(b"").is_err());
        assert!(lire(b"[]").is_err());
        assert!(lire(b"{\"hotes\": [").is_err());
        let v = lire(
            br#"{"hotes": [3, {"ip": 5, "ports": [{"port": 99999999}, "x"], "alertes": [["Eleve"], ["Critique", "y"]]}],
                 "absents": {"x": 1}, "upnp": "Absent", "empoisonnement": {"Teste": []}}"#,
        )
        .unwrap();
        assert_eq!(v.appareils.len(), 1);
        let a = &v.appareils[0];
        assert_eq!(a.ip, "5");
        assert_eq!(a.ports[0].numero, None);
        // Le port illisible et l'alerte à un seul élément : comptés, jamais sains.
        assert_eq!(a.illisibles, 2);
        assert_eq!(a.gravite(), Some(Gravite::Critique));
        // L'appareil illisible et la liste d'absents qui n'en est pas une.
        assert_eq!(v.illisibles, 2);
        assert_eq!(v.manques().len(), 1);
    }
}
