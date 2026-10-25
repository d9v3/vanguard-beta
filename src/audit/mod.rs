//! Audit du réseau par domaine : six notes — Exposition, Wi-Fi, Segmentation, DNS et TLS, Appareils, Postes — tirées
//! du scan du réseau local, des constats réseau du bilan de cette machine et de quelques lectures de plus. Défensif
//! seulement : Vanguard observe et mesure son propre réseau ; il n'envoie jamais d'attaque, d'exploit, de sonde
//! agressive, d'essai de mot de passe ni d'identifiant par défaut. Ce qui n'a pas pu être vérifié est dit
//! (`verifie: false`), exclu de la note et jamais compté comme sain.
//!
//! Contrat des domaines : un fichier par domaine, une fonction `constats(entree: &Entree) -> Vec<Constat>` avec sa
//! propre `Entree`, construite ici à partir du `Contexte` commun ; chaque constat porte l'identifiant de sa règle
//! (`regle`, les fiches du cadrage sont dans `fiches.rs` : sujet, références) et une catégorie stable
//! (`langue::categorie` la traduit). Les six tournent en même temps ; un domaine qui plante ou ne
//! rend rien est dit « non vérifié ». Hors ligne ou sans réseau local, tout finit en moins d'une minute et dit
//! « non vérifié ».

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::machine::Constat;
use crate::reseau::{self, Hote, Rapport, cameras, objets, upnp};
use crate::risk::{Niveau, note};
use crate::ui::*;

pub mod appareils;
pub mod arp;
pub mod bail;
#[cfg(test)]
pub(crate) mod corpus;
pub mod dns_client;
pub mod dns_tls;
pub mod exposition;
pub mod fiches;
pub mod http_local;
pub mod igd;
pub mod ipv6;
pub mod postes;
pub mod score;
pub mod segmentation;
pub mod ssh_kex;
pub mod tls_pq;
pub mod wifi;

/// Les six domaines, dans l'ordre de l'affichage et du rapport.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Domaine {
    Exposition,
    WiFi,
    Segmentation,
    DnsTls,
    Appareils,
    Postes,
}

impl Domaine {
    pub const TOUS: [Domaine; 6] = [
        Domaine::Exposition,
        Domaine::WiFi,
        Domaine::Segmentation,
        Domaine::DnsTls,
        Domaine::Appareils,
        Domaine::Postes,
    ];

    /// Le nom interne, stable et jamais traduit : la clé du JSON, de l'historique et de la surveillance.
    pub fn nom(self) -> &'static str {
        match self {
            Domaine::Exposition => "Exposition",
            Domaine::WiFi => "Wi-Fi",
            Domaine::Segmentation => "Segmentation",
            Domaine::DnsTls => "DNS et TLS",
            Domaine::Appareils => "Appareils",
            Domaine::Postes => "Postes",
        }
    }

    /// Le domaine d'un nom interne (JSON, historique).
    pub fn de(nom: &str) -> Option<Domaine> {
        Domaine::TOUS.into_iter().find(|d| d.nom() == nom)
    }

    pub fn titre(self) -> &'static str {
        match self {
            Domaine::Exposition => tr!("Exposition", "Exposure"),
            Domaine::WiFi => "Wi-Fi",
            Domaine::Segmentation => "Segmentation",
            Domaine::DnsTls => tr!("DNS et TLS", "DNS and TLS"),
            Domaine::Appareils => tr!("Appareils", "Connected devices"),
            Domaine::Postes => tr!("Postes", "Computers"),
        }
    }

    /// Ce que le domaine regarde, en une ligne.
    pub fn precision(self) -> &'static str {
        match self {
            Domaine::Exposition => tr!(
                "ce que le routeur laisse entrer d'Internet : redirections, adresse publique, IPv6, services du routeur",
                "what the router lets in from the Internet: forwardings, public address, IPv6, router services"
            ),
            Domaine::WiFi => tr!(
                "chiffrement, WPS, émetteurs du même nom, réseaux ouverts, appareils inconnus",
                "encryption, WPS, transmitters of the same name, open networks, unknown devices"
            ),
            Domaine::Segmentation => tr!(
                "objets et ordinateurs sur le même réseau, réseau invité, serveur DHCP, routeurs IPv6, routeur usurpé",
                "devices and computers on the same network, guest network, DHCP server, IPv6 routers, impersonated router"
            ),
            Domaine::DnsTls => tr!(
                "DNS distribué par le routeur, DNS chiffré, réponses divergentes, DNSSEC, HTTPS intercepté, post-quantique",
                "DNS handed out by the router, encrypted DNS, diverging answers, DNSSEC, intercepted HTTPS, post-quantum"
            ),
            Domaine::Appareils => tr!(
                "objets connectés : joignables d'Internet, administration ouverte, caméras, mots de passe d'origine",
                "connected devices: reachable from the Internet, open administration, cameras, default passwords"
            ),
            Domaine::Postes => tr!(
                "cet ordinateur vu du réseau, les autres ordinateurs, empoisonneur de noms, botnets",
                "this computer seen from the network, the other computers, name poisoner, botnets"
            ),
        }
    }

    /// La catégorie des constats du domaine quand une règle n'a pas la sienne (traduite à l'affichage).
    pub fn categorie(self) -> &'static str {
        match self {
            Domaine::DnsTls => "DNS",
            d => d.nom(),
        }
    }
}

/// La fiche d'une règle de l'audit : son identifiant du cadrage, son sujet dans les deux langues et les références
/// qu'elle cite (NSA, CCCS, ANSSI, NIST, ETSI, OWASP, CIS, IETF…).
pub struct Fiche {
    pub id: &'static str,
    pub domaine: Domaine,
    pub sujet: (&'static str, &'static str),
    pub references: &'static [&'static str],
}

impl Fiche {
    pub(crate) fn sujet(&self) -> &'static str {
        if crate::langue::anglais() {
            self.sujet.1
        } else {
            self.sujet.0
        }
    }
}

/// Toutes les fiches du cadrage, par domaine.
pub fn fiches() -> impl Iterator<Item = &'static Fiche> {
    fiches::FICHES.iter()
}

/// Le contrat commun : ce que l'audit sait au départ, partagé par les six domaines. Chaque domaine en reçoit la part
/// qui le concerne dans son `Entree`.
pub struct Contexte<'a> {
    /// Le scan du réseau local qui vient de finir (ou celui de la session, s'il a moins de dix minutes).
    pub scan: &'a Rapport,
    /// Les constats réseau du bilan de cette machine (`regle_du_reseau`), tels que le bilan les rend.
    pub machine: &'a [Constat],
    pub passerelle: Option<Ipv4Addr>,
    pub adresse_locale: Option<Ipv4Addr>,
    /// Le carnet de ce réseau : les appareils déjà vus ici par les scans d'avant, box comprise.
    pub carnet: &'a [objets::Appareil],
    pub nom_reseau: Option<&'a str>,
    /// On est sur le réseau invité : déclaré (--invite) ou reconnu au nom du Wi-Fi.
    pub invite: bool,
    /// Passe de la surveillance : seulement les lectures rapides (pas de recherche des caméras, pas de STUN).
    pub rapide: bool,
    /// Les indices de caméras (`cameras::chercher`) ; `None` : pas cherchées (passe rapide) ou recherche impossible.
    pub cameras: Option<&'a BTreeMap<Ipv4Addr, cameras::Indices>>,
    /// Les redirections de ports de la box d'après le scan ; `None` : non lues.
    pub redirections: Option<&'a [upnp::Redirection]>,
    /// Les programmes de cet ordinateur reliés à un serveur de commande connu ; `None` : connexions illisibles.
    pub botnets: Option<&'a crate::protection::sortantes::EnCours>,
    /// L'adresse de cet ordinateur vue d'Internet (STUN) ; `None` : pas mesurée (passe rapide, hors ligne).
    pub internet: Option<exposition::Internet>,
}

/// Hors ligne demandé (VANGUARD_HORS_LIGNE, les essais sans Internet, ou le menu Paramètres) : rien ne part vers
/// Internet.
fn hors_ligne() -> bool {
    crate::parametres::hors_ligne()
}

/// L'adresse de cet ordinateur vue d'Internet, par STUN en IPv4 puis en IPv6 : le domaine Exposition en tire
/// l'adresse publique, le CGNAT et le double NAT. Quelques secondes au plus sans Internet.
fn internet() -> exposition::Internet {
    let vue = |v6| reseau::nat::mesurer(v6).and_then(|m| m.vues.first().map(|(_, adresse)| adresse.ip()));
    exposition::Internet {
        v4: vue(false),
        v6: vue(true),
    }
}

/// Le pare-feu de cet ordinateur, d'après le constat `*-PFE-001` du bilan : actif quand la règle a répondu sans
/// alerte (une information ne compte pas) ; `None` quand elle n'a pas pu vérifier, ou n'a rien rendu.
pub(crate) fn pare_feu_local(machine: &[Constat]) -> Option<bool> {
    let constats: Vec<&Constat> = machine.iter().filter(|c| c.regle.ends_with("-PFE-001")).collect();
    if constats.is_empty() || constats.iter().any(|c| !c.verifie) {
        return None;
    }
    Some(constats.iter().all(|c| c.probleme.is_none_or(|n| n == Niveau::Info)))
}

/// Un constat qui n'a pas pu être vérifié, avec son propre message (le pourquoi, ce qui le vérifierait) : montré,
/// exclu de la note, compté dans les non vérifiés.
pub(crate) fn non_verifie(categorie: &'static str, regle: &'static str, message: impl Into<String>) -> Constat {
    Constat {
        verifie: false,
        regle,
        ..crate::machine::alerte(categorie, Niveau::Info, message)
    }
}

/// Le constat porte l'identifiant de sa règle.
pub(crate) fn avec_regle(mut c: Constat, regle: &'static str) -> Constat {
    c.regle = regle;
    c
}

/// Les règles du bilan de cette machine qui parlent du réseau : pare-feu, ports en écoute, SSH, découverte,
/// partages, navigation détournée, certificats racine, DNS. Le domaine Postes les reprend telles quelles, sans les
/// mises à jour (lentes).
pub fn regle_du_reseau(id: &str) -> bool {
    id.contains("-PFE-")
        || id.contains("-RES-")
        || ["-SSH-001", "-SSH-002", "-SSH-004", "-SSH-005", "-DIS-001"]
            .iter()
            .any(|fin| id.ends_with(fin))
        || matches!(id, "COM-PAR-001" | "COM-NAV-003" | "COM-CRT-001" | "COM-DNS-001")
}

/// Un nom de Wi-Fi qui dit « réseau invité » : invité, guest, visiteur, ou le « -G » des box.
pub fn reseau_invite(nom: &str) -> bool {
    let n = nom.trim().to_lowercase();
    ["invit", "guest", "visit"].iter().any(|m| n.contains(m)) || n.ends_with("-g") || n.ends_with("_guest")
}

/// L'appareil d'un hôte du scan pour `objets::genre`, le surnom donné par la personne compté parmi les mots de son
/// nom : une imprimante surnommée « imprimante HP » est une imprimante, pas un ordinateur (HP fait les deux).
pub(crate) fn appareil(h: &reseau::Hote) -> objets::Appareil {
    let mut a = h.objet();
    if let Some(surnom) = &h.surnom {
        a.nom = Some(match &a.nom {
            Some(n) => format!("{surnom} {n}"),
            None => surnom.clone(),
        });
    }
    a
}

/// Les redirections de ports de la box, d'après ce que le scan a lu : aucune quand UPnP est coupé ou absent (celles
/// réglées à la main dans la box ne se lisent pas d'ici), `None` quand rien n'a pu être lu.
pub fn redirections_du_scan(scan: &Rapport) -> Option<Vec<upnp::Redirection>> {
    match &scan.upnp {
        // Une box qui a répondu à la recherche mais refusé les actions : ses redirections restent non lues.
        Some(upnp::Etat::Actif(l)) if !l.lues => None,
        Some(upnp::Etat::Actif(l)) => Some(l.redirections.clone()),
        Some(upnp::Etat::Absent) => Some(Vec::new()),
        Some(upnp::Etat::OutilAbsent | upnp::Etat::Usurpee(_)) | None => None,
    }
}

/// Le bilan d'un domaine : sa note (aucune si plus du tiers des vérifications n'a pas pu se faire) et ses constats,
/// les plus graves d'abord, les non vérifiés à la fin.
#[derive(Serialize)]
pub struct DomaineAudite {
    pub domaine: &'static str,
    pub score: Option<u32>,
    pub note: Option<&'static str>,
    pub verifies: usize,
    pub non_verifies: usize,
    pub constats: Vec<Constat>,
}

impl DomaineAudite {
    fn de(d: Domaine, mut constats: Vec<Constat>) -> DomaineAudite {
        constats.sort_by_key(|c| (!c.verifie, std::cmp::Reverse(c.probleme)));
        let score = score::noter(&constats);
        let non_verifies = score::non_verifies(&constats);
        DomaineAudite {
            domaine: d.nom(),
            score,
            note: score.map(note),
            verifies: constats.len() - non_verifies,
            non_verifies,
            constats,
        }
    }

    pub fn domaine(&self) -> Option<Domaine> {
        Domaine::de(self.domaine)
    }
}

/// L'audit du réseau : les six domaines et la note de l'ensemble (la plus basse des six, aucune dès qu'un domaine
/// n'en a pas : un domaine non vérifié ne rend pas le réseau sain).
#[derive(Serialize)]
pub struct AuditReseau {
    /// Le réseau scanné (« 10.0.0.0/24 ») ; `None` : aucun réseau local, rien n'a pu être audité.
    pub reseau: Option<String>,
    pub nom_reseau: Option<String>,
    pub invite: bool,
    /// Passe rapide (surveillance) : les lectures lentes sont sautées, et dites non vérifiées.
    pub rapide: bool,
    pub domaines: Vec<DomaineAudite>,
    pub score: Option<u32>,
    pub note: Option<&'static str>,
    pub duree_s: f64,
}

impl AuditReseau {
    fn de(c: &Contexte, duree: Duration) -> AuditReseau {
        let resultats: Vec<(Domaine, Vec<Constat>)> = std::thread::scope(|s| {
            let fils: Vec<_> = Domaine::TOUS
                .into_iter()
                .map(|d| (d, s.spawn(move || constats_du_domaine(d, c))))
                .collect();
            fils.into_iter()
                .map(|(d, f)| (d, f.join().unwrap_or_else(|_| vec![erreur_interne(d)])))
                .collect()
        });
        let domaines: Vec<DomaineAudite> = resultats
            .into_iter()
            .map(|(d, mut constats)| {
                // Alertes déclarées normales : au niveau info, comme au bilan de la machine (apprentissage.rs).
                crate::apprentissage::appliquer(&mut constats);
                DomaineAudite::de(d, constats)
            })
            .collect();
        let score = score::globale(&domaines.iter().map(|d| d.score).collect::<Vec<_>>());
        AuditReseau {
            reseau: Some(c.scan.reseau.clone()),
            nom_reseau: c.nom_reseau.map(str::to_string),
            invite: c.invite,
            rapide: c.rapide,
            domaines,
            score,
            note: score.map(note),
            duree_s: duree.as_secs_f64(),
        }
    }

    /// Aucun réseau local : six domaines non vérifiés, dits tels quels.
    pub fn sans_reseau(raison: &str) -> AuditReseau {
        let domaines = Domaine::TOUS
            .into_iter()
            .map(|d| {
                DomaineAudite::de(
                    d,
                    vec![non_verifie(
                        d.categorie(),
                        "",
                        trf!(
                            "Pas de réseau local à auditer ({raison}).",
                            "No local network to audit ({raison})."
                        ),
                    )],
                )
            })
            .collect();
        AuditReseau {
            reseau: None,
            nom_reseau: None,
            invite: false,
            rapide: false,
            domaines,
            score: None,
            note: None,
            duree_s: 0.0,
        }
    }

    pub fn non_verifies(&self) -> usize {
        self.domaines.iter().map(|d| d.non_verifies).sum()
    }

    /// Les notes des domaines notés, par nom interne : ce que l'historique garde.
    pub fn notes(&self) -> BTreeMap<String, u32> {
        self.domaines
            .iter()
            .filter_map(|d| Some((d.domaine.to_string(), d.score?)))
            .collect()
    }
}

/// Les fiches des règles qui ont alerté (moyen ou plus) dans ce domaine : le pourquoi et ses références, pour
/// l'écran et le rapport.
pub(crate) fn references_du_domaine(d: &DomaineAudite) -> Vec<&'static Fiche> {
    let regles: BTreeSet<&str> = d
        .constats
        .iter()
        .filter(|c| c.verifie && c.probleme.is_some_and(|n| n >= Niveau::Moyen))
        .map(|c| c.regle)
        .filter(|r| !r.is_empty())
        .collect();
    fiches()
        .filter(|f| f.domaine.nom() == d.domaine && regles.contains(f.id) && !f.references.is_empty())
        .collect()
}

fn erreur_interne(d: Domaine) -> Constat {
    non_verifie(
        d.categorie(),
        "",
        trf!(
            "Erreur interne dans le domaine « {} » : rien n'a pu être vérifié.",
            "Internal error in the “{}” domain: nothing could be checked.",
            d.titre()
        ),
    )
}

/// Les constats d'un domaine, son entrée tirée du contexte ; un domaine qui plante ou ne rend rien est dit non
/// vérifié, sans emporter les autres.
fn constats_du_domaine(d: Domaine, c: &Contexte) -> Vec<Constat> {
    let constats = crate::journal::rattraper(std::panic::AssertUnwindSafe(|| match d {
        Domaine::Exposition => {
            let mut e = exposition::Entree::du_scan(c.scan);
            e.passerelle = c.passerelle;
            e.locale = c.adresse_locale;
            e.internet = c.internet;
            e.pare_feu_local = pare_feu_local(c.machine);
            exposition::constats(&e)
        }
        Domaine::WiFi => {
            // Les appareils nouveaux du scan et la MAC de la box : WIF-005 (appareils inconnus) et le fabricant de la
            // box (WPS) en ont besoin ; la lecture des bornes, elle, vient du système.
            let nouveaux = c.scan.hotes.iter().filter(|h| h.nouvelle).map(Hote::titre).collect();
            let mac_box = c
                .scan
                .hotes
                .iter()
                .find(|h| h.role == Some("passerelle"))
                .and_then(|h| h.mac.clone());
            wifi::constats(&wifi::entree().avec_scan(nouveaux, mac_box))
        }
        Domaine::Segmentation => segmentation::constats(&segmentation::entree(c)),
        Domaine::DnsTls => {
            // Les ports TCP de la box trouvés ouverts par le scan : seuls ceux-là sont sondés (post-quantique).
            let ports_box: Option<Vec<u16>> = c
                .scan
                .hotes
                .iter()
                .find(|h| Some(h.ip) == c.passerelle || h.role == Some("passerelle"))
                .map(|h| h.ports.iter().filter(|p| !p.udp).map(|p| p.port).collect());
            dns_tls::constats(&dns_tls::entree(c.passerelle, ports_box.as_deref()))
        }
        Domaine::Appareils => appareils::constats(&appareils::Entree {
            hotes: &c.scan.hotes,
            carnet: c.carnet,
            cameras: c.cameras,
            redirections: c.redirections,
            passerelle: c.passerelle,
            adresse_locale: c.adresse_locale,
        }),
        Domaine::Postes => postes::constats(&postes::Entree {
            hotes: &c.scan.hotes,
            machine: c.machine,
            empoisonnement: c.scan.empoisonnement.as_ref(),
            botnets: c.botnets,
            passerelle: c.passerelle,
            adresse_locale: c.adresse_locale,
        }),
    }));
    let constats = constats.unwrap_or_else(|_| vec![erreur_interne(d)]);
    if constats.is_empty() {
        return vec![non_verifie(
            d.categorie(),
            "",
            trf!(
                "Le domaine « {} » n'a rien rendu : non vérifié.",
                "The “{}” domain returned nothing: not checked.",
                d.titre()
            ),
        )];
    }
    constats
}

/// L'audit à partir d'un scan du réseau local qui vient de finir. `machine` : les constats réseau du bilan de cette
/// machine, s'ils viennent d'être faits (bilan complet, surveillance) ; sinon ils sont relus ici, en même temps que
/// les autres lectures (carnet du réseau, programmes reliés à un botnet, recherche des caméras sauf en passe
/// rapide).
pub async fn auditer(scan: &Rapport, machine: Option<Vec<Constat>>, invite: bool, rapide: bool) -> AuditReseau {
    let debut = Instant::now();
    let local = reseau::scan::reseau_local();
    let adresse_locale = local.as_ref().map(|l| l.1);
    // Les caméras : seulement sur le réseau local scanné (une cible précise n'est pas un réseau), et jamais pendant
    // une passe de la surveillance. Attendue sur place avec les autres lectures (`join!`) : un `spawn` butait sur une
    // limite du compilateur avec les fermetures du scan.
    let cameras = async {
        match (&local, rapide) {
            (Some((cible, moi)), false) if *cible == scan.reseau => {
                cameras::chercher(cible, *moi).await.ok().map(|(_, indices)| indices)
            }
            _ => None,
        }
    };
    let machine = async {
        match machine {
            Some(m) => m,
            None => tokio::task::spawn_blocking(|| crate::machine::auditer_seulement(regle_du_reseau).constats)
                .await
                .unwrap_or_default(),
        }
    };
    // L'adresse vue d'Internet : jamais pendant une passe de la surveillance ni hors ligne.
    let mesurer_internet = !rapide && !hors_ligne();
    let lectures = tokio::task::spawn_blocking(move || {
        std::thread::scope(|s| {
            let carnet = s.spawn(|| reseau::carnet_du_reseau().map(|(_, a)| a).unwrap_or_default());
            let botnets = s.spawn(crate::protection::sortantes::botnets_en_cours);
            let internet = s.spawn(move || mesurer_internet.then(internet));
            (
                carnet.join().unwrap_or_default(),
                botnets.join().ok().flatten(),
                internet.join().ok().flatten(),
            )
        })
    });
    let (cameras, machine, lectures) = tokio::join!(cameras, machine, lectures);
    let (carnet, botnets, internet) = lectures.unwrap_or_default();
    let redirections = redirections_du_scan(scan);
    let nom_reseau = scan.nom_reseau.as_deref();
    let contexte = Contexte {
        scan,
        machine: &machine,
        passerelle: reseau::scan::passerelle(),
        adresse_locale,
        carnet: &carnet,
        nom_reseau,
        invite: invite || nom_reseau.is_some_and(reseau_invite),
        rapide,
        cameras: cameras.as_ref(),
        redirections: redirections.as_deref(),
        botnets: botnets.as_ref(),
        internet,
    };
    AuditReseau::de(&contexte, debut.elapsed())
}

/// Le résultat, en JSON pour un script ou à l'écran.
pub fn rendre(a: &AuditReseau, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(a).unwrap_or_default());
    } else {
        afficher(a);
    }
}

/// Un constat à l'écran : la même ligne qu'au bilan de la machine, en gris quand il n'a pas pu être vérifié.
fn afficher_constat(c: &Constat) {
    let cat = crate::langue::categorie(c.categorie);
    if !c.verifie {
        afficher_aligne(&format!("  {GRIS}? {cat:<16} "), &c.message, 21, GRIS);
        return;
    }
    let (icone, etiquette) = match c.probleme {
        None => (format!("{VERT}✔{RESET}"), String::new()),
        Some(Niveau::Info) => (format!("{}ℹ{RESET}", couleur(Niveau::Info)), String::new()),
        Some(n) => (
            format!("{}✖{RESET}", couleur(n)),
            format!(" {}[{}]{RESET}", couleur(n), n.libelle()),
        ),
    };
    // Le message commence à la 21e colonne ; sa suite s'y aligne.
    afficher_aligne(
        &format!("  {icone} {GRAS}{cat:<16}{RESET}{etiquette} "),
        &c.message,
        21,
        "",
    );
    if let Some(k) = &c.correctif {
        let marque = if k.automatique {
            trf!("{} correction possible", "{} fix available", cle_a_molette())
        } else {
            trf!("{} à faire", "{} to do", ampoule())
        };
        // Comme au bilan de la machine : la phrase seule. Les commandes (PowerShell d'une ligne, souvent bien plus
        // larges que 76 colonnes) sont montrées au moment de corriger, pas dans le rendu de l'audit.
        afficher_aligne(
            &format!("  {:18}", ""),
            &trf!("{marque} : {}", "{marque}: {}", k.action),
            23,
            GRIS,
        );
    }
}

/// Les références des règles qui ont alerté dans ce domaine : le pourquoi, en une ligne grise par règle.
fn afficher_references(d: &DomaineAudite) {
    for f in references_du_domaine(d) {
        afficher_aligne(
            &format!("  {DISCRET}{} · ", f.id),
            &format!("{} · {}", f.sujet(), f.references.join(", ")),
            6,
            DISCRET,
        );
    }
}

pub fn afficher(a: &AuditReseau) {
    let nom = a
        .nom_reseau
        .as_deref()
        .map(|n| trf!(" « {n} »", " “{n}”"))
        .unwrap_or_default();
    titre(&trf!("Audit du réseau{nom}", "Network audit{nom}"));
    if a.invite {
        afficher_aligne(
            "  ",
            tr!(
                "Depuis le réseau invité : Vanguard vérifie qu'il est bien séparé du réseau principal.",
                "From the guest network: Vanguard checks that it is really separated from the main network."
            ),
            2,
            GRIS,
        );
    }
    if a.rapide {
        afficher_aligne(
            "  ",
            tr!(
                "Passe rapide : les lectures lentes sont sautées et dites non vérifiées.",
                "Quick pass: the slow checks are skipped and said not checked."
            ),
            2,
            GRIS,
        );
    }
    for d in &a.domaines {
        let Some(domaine) = d.domaine() else { continue };
        let etat = match d.score {
            Some(s) => etiquette_note(s),
            None => format!(
                "{GRIS}{}{RESET}",
                trf!(
                    "incomplet · {} non vérifié(s)",
                    "incomplete · {} not checked",
                    d.non_verifies
                )
            ),
        };
        section(&format!("{} · {etat}", domaine.titre().to_uppercase()));
        afficher_aligne("  ", domaine.precision(), 2, DISCRET);
        for c in &d.constats {
            afficher_constat(c);
        }
        afficher_references(d);
    }
    println!();
    if let Some(s) = a.score {
        afficher_note(tr!("Note de l'audit", "Audit grade"), s);
    } else {
        let sans_note = a.domaines.iter().filter(|d| d.score.is_none()).count();
        trp!(
            "  Note de l'audit : {}aucune{RESET} ({sans_note} domaine(s) sans note : trop de vérifications impossibles)",
            "  Audit grade: {}none{RESET} ({sans_note} domain(s) without a grade: too many checks could not be done)",
            couleur(Niveau::Eleve)
        );
    }
    if a.non_verifies() > 0 {
        trp!(
            "  {}⚠ {} vérification(s) impossible(s) : résultat incomplet, jamais compté comme sain.{RESET}",
            "  {}⚠ {} check(s) could not be done: incomplete result, never counted as safe.{RESET}",
            couleur(Niveau::Moyen),
            a.non_verifies()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le domaine d'une règle d'après son identifiant (« COM-EXP-001 » → Exposition).
    fn domaine_de_la_regle(id: &str) -> Option<Domaine> {
        Some(match id.get(4..7)? {
            "EXP" => Domaine::Exposition,
            "WIF" => Domaine::WiFi,
            "SEG" | "ARP" => Domaine::Segmentation,
            "DNS" | "TLS" => Domaine::DnsTls,
            "APP" => Domaine::Appareils,
            "PST" => Domaine::Postes,
            _ => return None,
        })
    }

    /// Chaque fiche : un identifiant unique de la forme « COM-XXX-NNN », un sujet dans les deux langues, dans le
    /// domaine qui la déclare.
    #[test]
    fn fiches_bien_formees() {
        let mut vus = std::collections::HashSet::new();
        for f in fiches() {
            assert!(vus.insert(f.id), "{} déclarée deux fois", f.id);
            let morceaux: Vec<&str> = f.id.split('-').collect();
            assert!(
                morceaux.len() == 3
                    && morceaux[0] == "COM"
                    && morceaux[1].len() == 3
                    && morceaux[1].chars().all(|c| c.is_ascii_uppercase())
                    && morceaux[2].len() == 3
                    && morceaux[2].chars().all(|c| c.is_ascii_digit()),
                "identifiant mal formé : {}",
                f.id
            );
            assert!(!f.sujet.0.is_empty() && !f.sujet.1.is_empty(), "{} sans sujet", f.id);
            assert!(!f.references.is_empty(), "{} sans référence", f.id);
            assert_eq!(
                domaine_de_la_regle(f.id),
                Some(f.domaine),
                "{} dans le mauvais domaine",
                f.id
            );
        }
        assert!(vus.len() >= 32);
        assert_eq!(domaine_de_la_regle("LNX-PFE-001"), None);
        for d in Domaine::TOUS {
            assert_eq!(Domaine::de(d.nom()), Some(d));
            assert_ne!(d.precision(), "");
        }
        assert_eq!(Domaine::de("autre"), None);
    }

    /// Le pare-feu local d'après le bilan : actif sans alerte, inactif avec, inconnu sans constat vérifié.
    #[test]
    fn pare_feu_local_d_apres_le_bilan() {
        let regle = |mut c: Constat, id: &'static str| {
            c.regle = id;
            c
        };
        let actif = regle(crate::machine::ok("Pare-feu", "ufw actif."), "LNX-PFE-001");
        let coupe = regle(
            crate::machine::alerte("Pare-feu", Niveau::Eleve, "Aucun pare-feu actif."),
            "LNX-PFE-001",
        );
        let furtif = regle(crate::machine::ok("Pare-feu", "Mode furtif actif."), "MAC-PFE-002");
        let inconnu = regle(crate::machine::impossible("Pare-feu", "systemd absent"), "LNX-PFE-001");
        assert_eq!(pare_feu_local(&[actif.clone(), furtif.clone()]), Some(true));
        assert_eq!(pare_feu_local(&[coupe]), Some(false));
        assert_eq!(pare_feu_local(&[inconnu, actif]), None);
        assert_eq!(pare_feu_local(&[furtif]), None);
    }

    #[test]
    fn regles_du_reseau_et_reseau_invite() {
        for id in [
            "LNX-PFE-001",
            "WIN-RES-002",
            "MAC-SSH-002",
            "LNX-SSH-005",
            "WIN-DIS-001",
            "COM-PAR-001",
            "COM-NAV-003",
            "COM-CRT-001",
            "COM-DNS-001",
        ] {
            assert!(regle_du_reseau(id), "{id}");
        }
        for id in [
            "LNX-MAJ-001",
            "LNX-SSH-003",
            "COM-NAV-001",
            "COM-MDP-001",
            "WIN-CHF-001",
        ] {
            assert!(!regle_du_reseau(id), "{id}");
        }
        assert!(reseau_invite("Salon-Invité") && reseau_invite("Maison Guest") && reseau_invite("Salon-G"));
        assert!(!reseau_invite("Salon") && !reseau_invite("Gaston"));
    }

    /// Sans réseau local : six domaines, tout non vérifié, aucune note, un JSON qui se relit.
    #[test]
    fn sans_reseau_tout_non_verifie() {
        let a = AuditReseau::sans_reseau("hors ligne");
        assert_eq!(a.domaines.len(), 6);
        assert!(
            a.domaines
                .iter()
                .all(|d| d.score.is_none() && d.verifies == 0 && d.non_verifies == 1)
        );
        assert!(a.score.is_none() && a.note.is_none());
        assert_eq!(a.non_verifies(), 6);
        let json: serde_json::Value = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(json["domaines"][0]["domaine"], "Exposition");
        assert_eq!(json["domaines"][0]["constats"][0]["verifie"], false);
        assert!(a.domaines.iter().any(|d| d.domaine == Domaine::Postes.nom()));
    }

    /// Les constats d'un domaine : les plus graves d'abord, ce qui va bien ensuite, les non vérifiés à la fin ; la
    /// note suit ; un domaine qui ne rend rien est dit non vérifié.
    #[test]
    fn tri_et_note_d_un_domaine() {
        let constats = vec![
            crate::machine::ok("Appareils", "bien"),
            non_verifie("Appareils", "", "pas lu"),
            crate::machine::alerte("Appareils", Niveau::Moyen, "moyen"),
            crate::machine::alerte("Appareils", Niveau::Critique, "critique"),
            crate::machine::alerte("Appareils", Niveau::Info, "info"),
        ];
        let d = DomaineAudite::de(Domaine::Appareils, constats);
        let messages: Vec<&str> = d.constats.iter().map(|c| c.message.as_str()).collect();
        assert_eq!(messages, ["critique", "moyen", "info", "bien", "pas lu"]);
        assert_eq!(
            (d.score, d.note, d.verifies, d.non_verifies),
            (Some(65), Some("C"), 4, 1)
        );
        let vide = DomaineAudite::de(Domaine::Postes, Vec::new());
        assert!(vide.score.is_none() && vide.constats.is_empty());
    }
}
