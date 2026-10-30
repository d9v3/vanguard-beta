//! Mode Wi-Fi public : on l'allume en arrivant sur un réseau public (café, hôtel, aéroport) et on l'éteint en partant.
//! Il ferme les entrées de l'ordinateur sur ce réseau, coupe le partage de fichiers et l'annonce de son nom, et pose
//! un DNS protecteur, chiffré là où le système le permet par réseau (Linux avec systemd-resolved). Rien n'est envoyé
//! pour décider : la personne allume le mode, après avoir vu chaque changement et sa valeur d'avant.
//!
//! Tout s'annule exactement : l'état d'avant est relevé et scellé (`sceau::WIFI_PUBLIC`) AVANT la première commande,
//! chaque élément est relu après, l'extinction remet dans l'ordre inverse et ne retire un élément de l'état que relu
//! à sa valeur d'avant. Ce qui peut ne vivre que jusqu'au redémarrage le fait (Linux : table nft, masques runtime) ;
//! le reste est posé sur le profil du réseau public quand le système le permet. Après un plantage ou un
//! redémarrage, l'état le dit (au menu, au bilan) et rien n'est refait sans accord.
//!
//! La remise s'exécute en administrateur à partir d'un fichier que tout programme du compte peut réécrire : seul un
//! état intact est remis, chaque valeur passe encore par un ensemble fermé, et un état changé hors de Vanguard ne
//! déclenche qu'une « extinction sûre » qui n'utilise aucune valeur notée. Un pare-feu trouvé coupé est allumé et
//! jamais recoupé ; une session SSH ou Bureau à distance en cours n'est jamais coupée. L'écriture élevée est celle du
//! projet (`machine::appliquer_chacune` : sudo, ou une seule fenêtre PowerShell administrateur sous Windows).

mod etat;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", test))]
mod macos;
mod portail;
#[cfg(any(windows, test))]
mod windows;

use etat::{Element, Etape, Etat, Reseau};

use crate::langue::Reponse;
use crate::machine::{Constat, alerte};
use crate::risk::Niveau;
use crate::sceau::{self, Lecture};
use crate::selection::{Ligne, choisir};
use crate::ui::*;

/// Le nom du serveur DNS-over-TLS du Bouclier canadien « Protégé » (ses adresses sont celles de « DNS le plus
/// rapide »).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NOM_DOT: &str = "protected.canadianshield.cira.ca";
/// `wifi-public portail` : le DNS chiffré se relâche au plus ce temps-là.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const PORTAIL_SECONDES: i64 = 600;

const CAT: &str = "Wi-Fi";

/// L'état du mode, tel qu'il se lit.
enum Lu {
    Absent,
    /// Intact : ses valeurs peuvent être remises (après validation).
    Fiable(Etat),
    /// Changé hors de Vanguard, adopté sans sceau, illisible : aucune valeur notée n'est crue. Le pourquoi.
    NonFiable(String),
}

fn lire_etat() -> Lu {
    match sceau::lire(sceau::WIFI_PUBLIC) {
        // Inconnu (sceaux refaits) : rien de noté à remettre, comme absent.
        Lecture::Absent | Lecture::Inconnu => Lu::Absent,
        Lecture::Intact(o) => Etat::lire(&o).map_or_else(
            || Lu::NonFiable(tr!("état illisible", "unreadable state").to_string()),
            Lu::Fiable,
        ),
        // Un fichier posé avant la version qui scelle serait sinon adopté tel quel : jamais cru ici.
        Lecture::Adopte(_) => {
            Lu::NonFiable(tr!("accepté sans sceau d'avant", "accepted without an earlier seal").to_string())
        }
        Lecture::Falsifie(_) => Lu::NonFiable(tr!("changé hors de Vanguard", "changed outside Vanguard").to_string()),
        Lecture::Illisible(e) => Lu::NonFiable(e),
    }
}

/// Écrit l'état avant toute commande : s'il ne s'écrit pas, rien n'est lancé.
fn ecrire_etat(e: &Etat) -> bool {
    match sceau::ecrire(sceau::WIFI_PUBLIC, e.octets()) {
        Ok(()) => true,
        Err(err) => {
            trp!(
                "  ✖ État du mode pas écrit ({err}) : rien n'est changé.",
                "  ✖ Mode state not written ({err}): nothing is changed."
            );
            false
        }
    }
}

/// Écrit l'état après des commandes : s'il ne s'écrit pas, celui d'avant reste (il couvre tout ce qui a été lancé), et
/// l'extinction s'en sert.
fn ecrire_etat_apres(e: &Etat) -> bool {
    match sceau::ecrire(sceau::WIFI_PUBLIC, e.octets()) {
        Ok(()) => true,
        Err(err) => {
            afficher_aligne(
                "  ✖ ",
                &trf!(
                    "État du mode pas mis à jour ({err}) : celui d'avant reste, et « vanguard wifi-public off » s'en sert.",
                    "Mode state not updated ({err}): the previous one stays, and “vanguard public-wifi off” uses it."
                ),
                4,
                "",
            );
            false
        }
    }
}

fn maintenant() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()
}

/// Le démarrage en cours du système (Linux : boot_id ; ailleurs, rien d'éphémère n'est posé).
fn demarrage() -> String {
    #[cfg(target_os = "linux")]
    return linux::lecture::demarrage();
    #[cfg(not(target_os = "linux"))]
    String::new()
}

// ---------------------------------------------------------------------------------------------------------------
// Ce que le mode change

/// Les serveurs d'une valeur de DNS notée, pour l'écran : « automatique » s'il n'y en a pas.
fn serveurs_lisibles(valeur: &str) -> String {
    let reste = valeur.split_once('\n').map_or("", |(_, r)| r);
    let serveurs: Vec<&str> = reste
        .split(['|', ','])
        .map(|s| s.split('#').next().unwrap_or(""))
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if serveurs.is_empty() {
        tr!("automatique (celui du réseau)", "automatic (the network's)").to_string()
    } else {
        serveurs.join(", ")
    }
}

/// Ce que le mode fait à cet élément, avec la valeur d'avant.
fn decrire(e: &Element) -> String {
    match e {
        Element::NftTable { interface } => trf!(
            "Entrées bloquées sur {interface} (table nft à part, jusqu'au redémarrage)",
            "Incoming connections blocked on {interface} (separate nft table, until restart)"
        ),
        Element::UniteRuntime { unite, .. } => trf!(
            "{unite} arrêté jusqu'au redémarrage (partage ou annonce du nom)",
            "{unite} stopped until restart (sharing or name announcement)"
        ),
        Element::Nm { propriete, avant, .. } => match propriete.as_str() {
            "connection.mdns" => trf!(
                "mDNS coupé sur ce réseau (avant : {avant})",
                "mDNS off on this network (before: {avant})"
            ),
            "connection.llmnr" => trf!(
                "LLMNR coupé sur ce réseau (avant : {avant})",
                "LLMNR off on this network (before: {avant})"
            ),
            _ => trf!(
                "DNS chiffré exigé sur ce réseau (DNS-over-TLS ; avant : {avant})",
                "Encrypted DNS required on this network (DNS-over-TLS; before: {avant})"
            ),
        },
        Element::Dns { avant } => trf!(
            "DNS : Bouclier canadien « Protégé » (avant : {})",
            "DNS: Canadian Shield “Protected” (before: {})",
            serveurs_lisibles(avant)
        ),
        Element::Categorie { .. } => tr!(
            "Réseau en catégorie Public (avant : Privé)",
            "Network in the Public category (before: Private)"
        )
        .to_string(),
        Element::ProfilPublic { parametre, avant } => match parametre.as_str() {
            "Enabled" => tr!(
                "Pare-feu (profil Public) allumé : il était coupé, il le restera",
                "Firewall (Public profile) turned on: it was off, it will stay on"
            )
            .to_string(),
            "DefaultInboundAction" => trf!(
                "Profil Public : entrées bloquées par défaut (avant : {avant})",
                "Public profile: incoming blocked by default (before: {avant})"
            ),
            _ => trf!(
                "Profil Public : aucune entrée, même pour les programmes autorisés (partage, découverte ; avant : {avant})",
                "Public profile: no incoming, even for allowed programs (sharing, discovery; before: {avant})"
            ),
        },
        Element::NetBios { avant, .. } => trf!(
            "NetBIOS coupé sur la carte Wi-Fi (avant : {})",
            "NetBIOS off on the Wi-Fi adapter (before: {})",
            if *avant == 1 {
                tr!("allumé", "on")
            } else {
                tr!("selon le réseau", "per the network")
            }
        ),
        Element::MacPareFeu { option, .. } => match option.as_str() {
            "globalstate" => tr!(
                "Pare-feu de macOS allumé : il était coupé, il le restera",
                "macOS firewall turned on: it was off, it will stay on"
            ),
            "blockall" => tr!(
                "Pare-feu : tout bloquer sauf l'essentiel (avant : non)",
                "Firewall: block all but essential (before: no)"
            ),
            _ => tr!("Mode furtif (avant : non)", "Stealth mode (before: no)"),
        }
        .to_string(),
    }
}

/// Un groupe de commandes (une seule réussite pour lui) et les éléments qu'il change.
struct Lot {
    commandes: Vec<String>,
    elements: Vec<Element>,
    /// Le DNS chiffré strict : après la page du portail, qu'il empêcherait d'ouvrir.
    dns: bool,
}

/// Ce que le mode changerait ici, relevé sans rien changer.
struct Plan {
    reseau: Reseau,
    lots: Vec<Lot>,
    /// Ce qui ne change pas, et pourquoi (gardé, déjà en place, non disponible, non vérifié).
    notes: Vec<String>,
    signaux: portail::Signaux,
    /// Le mode ne saura pas fermer les entrées ici (pas de nft, pare-feu illisible).
    entrees_ouvertes: bool,
}

impl Plan {
    fn new(reseau: Reseau) -> Self {
        Plan {
            reseau,
            lots: Vec::new(),
            notes: Vec::new(),
            signaux: portail::Signaux::default(),
            entrees_ouvertes: false,
        }
    }

    /// Ajoute un lot ; un élément dont la valeur d'avant ne saurait pas être remise n'est pas changé du tout.
    fn ajouter(&mut self, commandes: Vec<Option<String>>, elements: Vec<Element>, dns: bool) {
        if let Some(e) = elements.iter().find(|e| !e.valide()) {
            self.notes.push(trf!(
                "Pas changé : « {} » ne pourrait pas être remis exactement (valeur d'avant inattendue).",
                "Not changed: “{}” could not be put back exactly (unexpected previous value).",
                decrire(e)
            ));
            return;
        }
        let Some(commandes) = commandes.into_iter().collect::<Option<Vec<String>>>() else {
            return;
        };
        if !commandes.is_empty() && !elements.is_empty() {
            self.lots.push(Lot {
                commandes,
                elements,
                dns,
            });
        }
    }
}

/// Les adresses du DNS protecteur, avec le nom du serveur pour le DNS chiffré quand il est voulu.
fn adresses_dns(chiffre: bool) -> (Vec<String>, Vec<String>) {
    let (v4, v6) = crate::dns_rapide::bouclier_protege();
    let avec = |ip: &&str| {
        if chiffre {
            format!("{ip}#{NOM_DOT}")
        } else {
            (*ip).to_string()
        }
    };
    (v4.iter().map(avec).collect(), v6.iter().map(avec).collect())
}

/// Le DNS actuel est-il gardé ? `Some(pourquoi)` : un résolveur tourne sur cet ordinateur (le DNS de la connexion
/// n'aurait pas d'effet ; ce qu'il fait n'est dit que s'il se lit), ou le DNS est déjà chiffré et filtrant, ou
/// chiffré alors que le Bouclier ne pourrait pas l'être ici (le chiffrement compte plus sur un réseau public).
/// `None` : le Bouclier, qui bloque les sites dangereux. Chiffrer seul ne bloque rien.
fn dns_garde(a: &crate::machine::dns::Actuel, chiffre_possible: bool) -> Option<String> {
    if let Some(nom) = a.resolveur_local {
        return Some(if a.chiffre == Some(true) {
            trf!(
                "DNS gardé : {nom} tourne sur cet ordinateur et chiffre déjà ; s'il filtre, Vanguard ne peut pas le vérifier.",
                "DNS kept: {nom} runs on this computer and already encrypts; whether it filters, Vanguard cannot verify."
            )
        } else {
            trf!(
                "DNS gardé : {nom} tourne sur cet ordinateur ; Vanguard ne peut pas vérifier s'il chiffre ou filtre (non vérifié).",
                "DNS kept: {nom} runs on this computer; Vanguard cannot verify whether it encrypts or filters (not verified)."
            )
        });
    }
    if a.chiffre != Some(true) {
        return None;
    }
    // Tous, pas un seul : un serveur filtrant connu mêlé à celui du réseau laisserait ce dernier répondre.
    if crate::dns_rapide::tous_filtrants(a) {
        return Some(
            tr!(
                "DNS gardé : il est déjà chiffré et bloque les sites dangereux.",
                "DNS kept: it is already encrypted and blocks dangerous sites."
            )
            .to_string(),
        );
    }
    (!chiffre_possible).then(|| {
        tr!(
            "DNS gardé : il est chiffré, mais ne bloque pas les sites dangereux ; le Bouclier ne pourrait pas être chiffré ici, et sur un réseau public le chiffrement compte plus.",
            "DNS kept: it is encrypted but does not block dangerous sites; the Shield could not be encrypted here, and on a public network encryption matters more."
        )
        .to_string()
    })
}

/// Le DNS : gardé quand `dns_garde` le dit, sinon le Bouclier canadien « Protégé » sur cette connexion seulement,
/// par le changement de « DNS le plus rapide ». `chiffre` : le système sait chiffrer le DNS de ce seul réseau. Rend
/// la commande DoT à ajouter (Linux) par `dot`.
fn plan_dns(plan: &mut Plan, chiffre: bool, dot: impl FnOnce() -> Option<(String, Element)>) {
    if let Some(note) = crate::machine::dns::actuel().and_then(|a| dns_garde(&a, chiffre)) {
        plan.notes.push(note);
        return;
    }
    let (v4, v6) = adresses_dns(chiffre);
    let v4: Vec<&str> = v4.iter().map(String::as_str).collect();
    let v6: Vec<&str> = v6.iter().map(String::as_str).collect();
    match crate::optimiser::dns_pour_wifi_public(&v4, &v6) {
        Err(e) => plan.notes.push(trf!("DNS pas changé : {e}", "DNS not changed: {e}")),
        // Sous Windows, le même GUID peut se lire en majuscules ou en minuscules.
        Ok((id, _, _)) if !id.eq_ignore_ascii_case(&plan.reseau.id) => plan.notes.push(
            tr!(
                "DNS pas changé : la route vers Internet ne passe pas par ce Wi-Fi (VPN, câble ?).",
                "DNS not changed: the route to the Internet does not go through this Wi-Fi (VPN, cable?)."
            )
            .to_string(),
        ),
        Ok((_, avant, cible)) => {
            let mut commandes = Vec::new();
            let mut elements = Vec::new();
            if avant != cible {
                commandes.push(crate::optimiser::dns_commande(&cible));
                elements.push(Element::Dns { avant });
            }
            if let Some((c, e)) = dot() {
                commandes.push(Some(c));
                elements.push(e);
            }
            if elements.is_empty() {
                plan.notes.push(
                    tr!(
                        "DNS protecteur déjà en place sur ce réseau.",
                        "Protective DNS already in place on this network."
                    )
                    .to_string(),
                );
            }
            plan.ajouter(commandes, elements, chiffre);
            if !chiffre {
                plan.notes.push(
                    tr!(
                        "Le DNS protecteur n'est pas chiffré ici (Windows, macOS, ou Linux sans systemd-resolved) : le réseau voit encore les noms des sites visités.",
                        "The protective DNS is not encrypted here (Windows, macOS, or Linux without systemd-resolved): the network still sees the names of the sites visited."
                    )
                    .to_string(),
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn relever() -> Result<Plan, String> {
    use linux::lecture;
    let (carte, uuid, nom) = lecture::wifi().ok_or_else(|| {
        tr!(
            "Aucun Wi-Fi connecté par NetworkManager : le mode s'allume une fois connecté au réseau public.",
            "No Wi-Fi connected through NetworkManager: the mode turns on once connected to the public network."
        )
        .to_string()
    })?;
    let mut plan = Plan::new(Reseau {
        nom,
        interface: carte.clone(),
        id: uuid.clone(),
    });
    plan.signaux = portail::Signaux {
        force: lecture::securite().map(|s| crate::machine::wifi::force(&s)),
        deja_public: false,
        portail: lecture::connectivite().map(|c| c == "portal"),
    };
    if lecture::nft_present() {
        plan.ajouter(
            vec![linux::poser_nft(&carte)],
            vec![Element::NftTable { interface: carte }],
            false,
        );
        plan.notes.push(
            tr!(
                "Une session SSH déjà ouverte reste ouverte ; une nouvelle ne passera pas par ce Wi-Fi.",
                "An SSH session already open stays open; a new one will not get through this Wi-Fi."
            )
            .to_string(),
        );
    } else {
        plan.entrees_ouvertes = true;
        plan.notes.push(
            tr!(
                "nft absent : les entrées ne sont pas fermées par le mode (ufw ou firewalld gardent leurs règles).",
                "nft missing: incoming connections are not closed by the mode (ufw or firewalld keep their rules)."
            )
            .to_string(),
        );
    }
    let mut aucun = true;
    for (unite, actif, masque) in lecture::unites() {
        if actif && !masque {
            aucun = false;
            plan.ajouter(
                vec![linux::masquer(unite)],
                vec![Element::UniteRuntime {
                    unite: unite.to_string(),
                    actif_avant: true,
                }],
                false,
            );
        }
    }
    if aucun {
        plan.notes.push(
            tr!(
                "Aucun service de partage ni d'annonce du nom ne tourne (Samba, Avahi, wsdd).",
                "No sharing or name announcement service is running (Samba, Avahi, wsdd)."
            )
            .to_string(),
        );
    }
    let mut proprietes = Vec::new();
    for p in ["connection.mdns", "connection.llmnr"] {
        match lecture::nm(&uuid, p) {
            Some("no") => {}
            Some(v) => proprietes.push(Element::Nm {
                uuid: uuid.clone(),
                propriete: p.to_string(),
                avant: v.to_string(),
            }),
            None => plan
                .notes
                .push(trf!("{p} illisible : pas changé.", "{p} unreadable: not changed.")),
        }
    }
    let paires: Vec<(&str, &str)> = proprietes
        .iter()
        .filter_map(|e| match e {
            Element::Nm { propriete, .. } => Some((propriete.as_str(), "no")),
            _ => None,
        })
        .collect();
    let commande = linux::nm_modifier(&uuid, &paires);
    if commande.is_some() {
        plan.ajouter(vec![commande], proprietes, false);
    }
    let chiffre = lecture::resolved();
    plan_dns(&mut plan, chiffre, || {
        if !chiffre {
            return None;
        }
        match lecture::nm(&uuid, "connection.dns-over-tls")? {
            "yes" => None,
            v => Some((
                linux::nm_modifier(&uuid, &[("connection.dns-over-tls", "yes")])?,
                Element::Nm {
                    uuid: uuid.clone(),
                    propriete: "connection.dns-over-tls".to_string(),
                    avant: v.to_string(),
                },
            )),
        }
    });
    Ok(plan)
}

#[cfg(windows)]
fn relever() -> Result<Plan, String> {
    let lu = windows::lecture::lire();
    let (index, carte) = lu.carte.clone().ok_or_else(|| {
        tr!(
            "Aucune carte Wi-Fi connectée, ou lecture impossible (PowerShell).",
            "No connected Wi-Fi adapter, or reading not possible (PowerShell)."
        )
        .to_string()
    })?;
    let (guid, categorie, nom) = lu.profil.clone().unwrap_or_default();
    let mut plan = Plan::new(Reseau {
        nom,
        interface: index.to_string(),
        id: carte.clone(),
    });
    plan.signaux = portail::Signaux {
        force: force_windows(),
        deja_public: categorie == "Public",
        portail: None,
    };
    match categorie.as_str() {
        "Private" => plan.ajouter(
            vec![Some(windows::rendre_public(index))],
            vec![Element::Categorie {
                guid,
                avant: "Private".to_string(),
            }],
            false,
        ),
        "Public" => {}
        // Le profil Public du pare-feu, seul réglé par le mode, ne s'applique pas à ces réseaux-là.
        "DomainAuthenticated" => {
            plan.entrees_ouvertes = true;
            plan.notes.push(
                tr!(
                    "Réseau d'entreprise (domaine) : sa catégorie est gérée, pas touchée.",
                    "Company (domain) network: its category is managed, not touched."
                )
                .to_string(),
            );
        }
        _ => {
            plan.entrees_ouvertes = true;
            plan.notes.push(
                tr!(
                    "Catégorie du réseau illisible : pas changée.",
                    "Network category unreadable: not changed."
                )
                .to_string(),
            );
        }
    }
    if let Some(f) = &lu.pare_feu {
        let session = crate::protection::blocage::session_a_distance();
        let mut elements = Vec::new();
        let mut parametres = Vec::new();
        for (p, cible, avant) in windows::a_changer_profil(f) {
            if p == "AllowInboundRules" && session != Some(false) {
                plan.notes.push(
                    tr!(
                        "Une session à distance est en cours (ou illisible) : les programmes autorisés gardent leurs entrées, pour ne pas la couper.",
                        "A remote session is in progress (or unreadable): allowed programs keep their incoming connections, so as not to cut it."
                    )
                    .to_string(),
                );
                continue;
            }
            parametres.push((p, cible));
            elements.push(Element::ProfilPublic {
                parametre: p.to_string(),
                avant,
            });
        }
        plan.ajouter(vec![windows::regler_profil(&parametres)], elements, false);
    } else {
        plan.entrees_ouvertes = true;
        plan.notes.push(
            tr!(
                "Profil Public du pare-feu illisible : pas changé.",
                "Firewall Public profile unreadable: not changed."
            )
            .to_string(),
        );
    }
    plan.notes.push(
        tr!(
            "Une stratégie de groupe (ordinateur d'entreprise) passe avant ces réglages : elle n'est pas touchée.",
            "A group policy (company computer) takes precedence over these settings: it is not touched."
        )
        .to_string(),
    );
    match windows::lecture::netbios(&carte) {
        Some(2) => {}
        Some(v) => plan.ajouter(
            vec![windows::netbios(&carte, 2)],
            vec![Element::NetBios {
                carte: carte.clone(),
                avant: v,
            }],
            false,
        ),
        None => plan.notes.push(
            tr!(
                "NetBIOS de la carte illisible : pas changé.",
                "Adapter NetBIOS unreadable: not changed."
            )
            .to_string(),
        ),
    }
    plan_dns(&mut plan, false, || None);
    Ok(plan)
}

#[cfg(target_os = "macos")]
fn relever() -> Result<Plan, String> {
    let (carte, service, ssid, securite) = macos::lecture::wifi().ok_or_else(|| {
        tr!(
            "Aucun Wi-Fi connecté, ou lecture impossible (networksetup, system_profiler).",
            "No Wi-Fi connected, or reading not possible (networksetup, system_profiler)."
        )
        .to_string()
    })?;
    let mut plan = Plan::new(Reseau {
        nom: ssid,
        interface: carte,
        id: service,
    });
    plan.signaux = portail::Signaux {
        force: Some(crate::machine::wifi::force(&securite)),
        deja_public: false,
        portail: None,
    };
    let mut commandes = Vec::new();
    let mut elements = Vec::new();
    for option in etat::OPTIONS_MAC {
        match macos::lecture::option(option) {
            Some("on") => {}
            Some(_) => {
                commandes.push(macos::regler(option, "on"));
                elements.push(Element::MacPareFeu {
                    option: option.to_string(),
                    avant: "off".to_string(),
                });
            }
            None => {
                plan.entrees_ouvertes = true;
                plan.notes.push(trf!(
                    "Pare-feu ({option}) illisible : pas changé.",
                    "Firewall ({option}) unreadable: not changed."
                ));
            }
        }
    }
    plan.ajouter(commandes, elements, false);
    plan.notes.push(
        tr!(
            "AirDrop et Bonjour ne sont pas touchés (le pare-feu laisse passer Bonjour).",
            "AirDrop and Bonjour are not touched (the firewall lets Bonjour through)."
        )
        .to_string(),
    );
    plan_dns(&mut plan, false, || None);
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------------------------
// Relire et remettre

/// Ce qu'il faut savoir une fois pour relire tous les éléments.
struct Relecture {
    meme_demarrage: bool,
    #[cfg(windows)]
    pare_feu: Option<[String; 3]>,
}

impl Relecture {
    fn maintenant(e: &Etat) -> Self {
        Relecture {
            meme_demarrage: e.demarrage == demarrage(),
            #[cfg(windows)]
            pare_feu: windows::lecture::lire().pare_feu,
        }
    }

    /// L'élément est-il à sa valeur d'avant ? `None` : ne se relit pas.
    #[allow(clippy::unused_self)]
    fn a_l_avant(&self, e: &Element) -> Option<bool> {
        #[cfg(target_os = "linux")]
        return linux::lecture::a_l_avant(e, self.meme_demarrage);
        #[cfg(windows)]
        return windows::lecture::a_l_avant(e, self.pare_feu.as_ref());
        #[cfg(target_os = "macos")]
        return macos::lecture::a_l_avant(e);
    }
}

/// La commande qui remet un élément ; `None` : rien à remettre (pare-feu trouvé coupé), ou valeur invalide.
fn commande_remise(e: &Element) -> Option<String> {
    if !e.valide() || e.jamais_remis() {
        return None;
    }
    if let Element::Dns { avant } = e {
        return crate::optimiser::dns_commande(avant);
    }
    #[cfg(target_os = "linux")]
    return linux::remettre(e);
    #[cfg(windows)]
    return windows::remettre(e);
    #[cfg(target_os = "macos")]
    return macos::remettre(e);
}

/// Les remises d'un état fiable, dans l'ordre inverse de l'allumage : (élément, commande). Les éléments invalides
/// (jamais remis) à part.
fn plan_extinction(e: &Etat) -> (Vec<(&Element, Option<String>)>, Vec<&Element>) {
    let (valides, invalides) = etat::a_remettre(e);
    let mut remises: Vec<(&Element, Option<String>)> = valides.into_iter().map(|x| (x, commande_remise(x))).collect();
    unites_dans_l_ordre(&mut remises);
    (remises, invalides)
}

/// Les unités se relancent dans l'ordre de `etat::UNITES`, les sockets d'abord, à leurs places : un service ne
/// démarre pas tant que son socket est masqué (« Unit avahi-daemon.socket is masked »).
fn unites_dans_l_ordre(remises: &mut [(&Element, Option<String>)]) {
    let rang = |x: &Element| match x {
        Element::UniteRuntime { unite, .. } => etat::UNITES.iter().position(|u| u == unite).unwrap_or(usize::MAX),
        _ => usize::MAX,
    };
    let est_unite = |r: &&mut (&Element, Option<String>)| matches!(r.0, Element::UniteRuntime { .. });
    let mut unites: Vec<(&Element, Option<String>)> = remises
        .iter()
        .filter(|r| matches!(r.0, Element::UniteRuntime { .. }))
        .cloned()
        .collect();
    unites.sort_by_key(|(x, _)| rang(x));
    // Remises aux mêmes places, dans le nouvel ordre.
    for (place, u) in remises.iter_mut().filter(est_unite).zip(unites) {
        *place = u;
    }
}

/// Les éléments qui restent dans l'état après une remise : retiré seulement s'il est relu à sa valeur d'avant, ou
/// s'il n'y a rien à remettre (pare-feu laissé allumé). `relu` : la relecture ; `None` (ne se relit pas sans droits,
/// la table nft) se juge sur la commande elle-même, qui relit en administrateur — jamais sous Windows, où la
/// réussite viendrait d'un fichier du compte.
fn restants(remises: &[(&Element, Option<String>)], relus: &[Option<bool>], reussis: &[bool]) -> Vec<Element> {
    remises
        .iter()
        .zip(relus)
        .zip(reussis)
        .filter(|(((e, commande), relu), reussi)| {
            let revenu = match relu {
                Some(r) => *r,
                None => commande.is_some() && **reussi && !cfg!(windows),
            };
            !(e.jamais_remis() || revenu)
        })
        .map(|(((e, _), _), _)| (*e).clone())
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

/// Les commandes de l'extinction sûre sous Linux : seulement ce qui est sans ambiguïté à Vanguard, sa table. Un
/// masque runtime a pu être posé par la personne : il reste, comme les autres réglages plus sûrs. Aucune valeur de
/// l'état n'y entre.
#[cfg(target_os = "linux")]
fn commandes_extinction_sure() -> Vec<String> {
    vec![linux::retirer_nft()]
}

/// Applique des groupes de commandes, en une seule demande administrateur sous Windows ; refusé sous les tests.
fn appliquer(groupes: &[Vec<String>]) -> Vec<bool> {
    if cfg!(test) || groupes.is_empty() {
        return vec![false; groupes.len()];
    }
    crate::machine::appliquer_chacune(groupes)
}

/// Le point de restauration, à l'allumage seulement (l'extinction remet). Sous Windows, il entre dans la même
/// fenêtre administrateur que le reste : rend sa commande. Ailleurs, fait d'abord ; `false` : la personne a préféré
/// arrêter.
fn point_de_restauration() -> Result<Option<String>, ()> {
    let Some((outil, point)) = crate::reparer::point_restauration(tr!("mode Wi-Fi public", "public Wi-Fi mode")) else {
        return Ok(None);
    };
    if cfg!(windows) {
        return Ok(Some(point));
    }
    trp!(
        "    {GRIS}Point de restauration d'abord ({outil}).{RESET}",
        "    {GRIS}Restore point first ({outil}).{RESET}"
    );
    if appliquer(&[vec![point]]) == [true]
        || demander(tr!(
            "    ✖ Point de restauration impossible. Continuer quand même ? [o/N] : ",
            "    ✖ Restore point not possible. Continue anyway? [y/N]: "
        ))
        .oui()
    {
        Ok(None)
    } else {
        Err(())
    }
}

/// Un élément qui ferme les entrées de l'ordinateur. La catégorie Public en est un : les réglages du profil Public
/// du pare-feu ne s'appliquent pas à un réseau resté en Privé, dont le partage et la découverte restent ouverts.
fn ferme_les_entrees(x: &Element) -> bool {
    matches!(
        x,
        Element::NftTable { .. }
            | Element::ProfilPublic { .. }
            | Element::MacPareFeu { .. }
            | Element::Categorie { .. }
    )
}

/// Les entrées restent-elles ouvertes après l'allumage ? Oui si le relevé le disait, si un élément qui les ferme
/// n'a pas été pris, ou s'il a été gardé sans avoir pu être relu (non vérifié, jamais compté comme fermé).
fn entrees_ouvertes<'a>(
    deja: bool,
    elements: impl IntoIterator<Item = &'a Element>,
    changes: &[String],
    non_relus: &[String],
) -> bool {
    deja || elements
        .into_iter()
        .any(|x| ferme_les_entrees(x) && (!changes.contains(&x.cle()) || non_relus.contains(&x.cle())))
}

/// Comment un élément est jugé après sa commande, d'après sa relecture et la réussite de son lot.
#[derive(Debug, PartialEq, Eq)]
enum Pris {
    Oui,
    Non,
    /// Gardé dans l'état pour pouvoir l'éteindre, mais pas relu : rien ne dit qu'il a pris.
    NonVerifie,
}

/// Relu, il se juge sur sa valeur. Pas relu : sous Windows, il reste dans l'état (l'éteindre ne fera que remettre
/// l'avant) mais n'est pas vérifié, même si sa commande a réussi ; ailleurs, il se juge sur sa commande (la table
/// nft, qui ne se relit pas sans droits, est relue par la commande qui la pose).
fn juger(relu: Option<bool>, ok: bool, windows: bool) -> Pris {
    match relu {
        Some(false) => Pris::Oui,
        None if windows => Pris::NonVerifie,
        None if ok => Pris::Oui,
        Some(true) | None => Pris::Non,
    }
}

/// Le message quand il n'y a rien à changer : jamais « tout est en place » si les entrées restent ouvertes.
fn rien_a_changer(entrees_ouvertes: bool) -> &'static str {
    if entrees_ouvertes {
        tr!(
            "Rien à changer ici, mais les entrées ne sont pas fermées : le mode ne sait pas le faire sur ce système (voir ci-dessus).",
            "Nothing to change here, but incoming connections are not closed: the mode cannot do it on this system (see above)."
        )
    } else {
        tr!(
            "Rien à changer : tout est déjà en place.",
            "Nothing to change: everything is already in place."
        )
    }
}

/// Rallumer un mode à moitié : un élément éphémère d'avant (parti au redémarrage), reprévu mais pas repris (commande
/// refusée). Le démarrage noté reste alors l'ancien, pour que le mode se dise encore « à moitié ».
fn rallumage_incomplet(anciens: &[Element], nouveaux: &[String], changes: &[String]) -> bool {
    anciens
        .iter()
        .any(|a| a.ephemere() && nouveaux.contains(&a.cle()) && !changes.contains(&a.cle()))
}

/// L'état du DNS chiffré relâché en « opportuniste » : pour la page du portail jusqu'à une échéance, ou à la demande
/// (sans échéance) quand le réseau bloque le DNS chiffré. Noté avant la commande, pour que le menu et le bilan le
/// disent et proposent le retour au strict.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn relache(e: &Etat, jusqu_a: Option<i64>) -> Etat {
    let mut r = e.clone();
    r.etape = Etape::Portail;
    r.portail_jusqu_a = jusqu_a;
    r
}

/// Le DNS chiffré relâché pour le portail, et son échéance passée : le retour au strict est proposé d'office.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn echeance_depassee(e: &Etat, maintenant: i64) -> bool {
    e.etape == Etape::Portail && e.portail_jusqu_a.is_some_and(|f| f < maintenant)
}

/// Le profil du réseau dont le mode tient le DNS chiffré.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn uuid_dot(e: &Etat) -> Option<String> {
    e.elements.iter().find_map(|x| match x {
        Element::Nm { uuid, propriete, .. } if propriete == "connection.dns-over-tls" => Some(uuid.clone()),
        _ => None,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Allumer, éteindre, portail

fn expliquer() {
    afficher_aligne(
        "  ",
        tr!(
            "Pour un réseau public (café, hôtel, aéroport) : l'ordinateur n'accepte plus aucune connexion venue de ce réseau, ne partage plus ses fichiers ni n'annonce son nom (sous macOS, le pare-feu ferme le partage ; Bonjour et AirDrop restent), et passe par un DNS qui bloque les sites dangereux (un résolveur qui tourne déjà sur l'ordinateur est gardé). Internet marche comme avant ; rien n'est envoyé pour décider. Tout se remet exactement en éteignant le mode.",
            "For a public network (café, hotel, airport): the computer no longer accepts any connection from this network, stops sharing its files and announcing its name (on macOS, the firewall closes sharing; Bonjour and AirDrop stay), and uses a DNS that blocks dangerous sites (a resolver already running on the computer is kept). The Internet works as before; nothing is sent to decide. Everything is put back exactly when the mode is turned off."
        ),
        2,
        "",
    );
}

fn montrer_notes(notes: &[String]) {
    for n in notes {
        afficher_aligne(&format!("    {GRIS}·{RESET} "), n, 6, GRIS);
    }
}

/// Allume le mode (ou le complète, s'il est à moitié), après avoir montré chaque changement.
fn allumer() {
    titre(tr!("Mode Wi-Fi public : allumer", "Public Wi-Fi mode: turn on"));
    expliquer();
    let ancien = match lire_etat() {
        Lu::NonFiable(raison) => {
            afficher_aligne(
                "\n  ✖ ",
                &trf!(
                    "L'état du mode a été {raison} : éteignez-le d'abord (« vanguard wifi-public off », extinction sûre).",
                    "The mode's state was {raison}: turn it off first (“vanguard public-wifi off”, safe shutdown)."
                ),
                4,
                "",
            );
            return;
        }
        Lu::Fiable(e) => Some(e),
        Lu::Absent => None,
    };
    trp!(
        "\n  {GRIS}Lecture de l'état actuel…{RESET}",
        "\n  {GRIS}Reading the current state…{RESET}"
    );
    let plan = match relever() {
        Ok(p) => p,
        Err(e) => {
            afficher_aligne("  ✖ ", &e, 4, "");
            return;
        }
    };
    if let Some(a) = &ancien
        && a.reseau.id != plan.reseau.id
    {
        afficher_aligne(
            "\n  ✖ ",
            &trf!(
                "Le mode est encore allumé pour « {} » : éteignez-le d'abord (« vanguard wifi-public off »).",
                "The mode is still on for “{}”: turn it off first (“vanguard public-wifi off”).",
                affichable(&a.reseau.nom),
            ),
            4,
            "",
        );
        return;
    }
    let nom = affichable(&plan.reseau.nom);
    trp!("\n  {GRAS}Réseau « {nom} »{RESET}", "\n  {GRAS}Network “{nom}”{RESET}");
    if let Some(s) = portail::suggestion(plan.signaux) {
        afficher_aligne("  ", &s, 2, GRIS);
    }
    if plan.lots.is_empty() {
        println!();
        montrer_notes(&plan.notes);
        let marque = if plan.entrees_ouvertes {
            "\n  ⚠ ".to_string()
        } else {
            format!("\n  {VERT}✔{RESET} ")
        };
        afficher_aligne(&marque, rien_a_changer(plan.entrees_ouvertes), 4, "");
        if let Some(mut a) = ancien
            && (a.etape != Etape::Allume || a.entrees_ouvertes != plan.entrees_ouvertes)
        {
            a.etape = Etape::Allume;
            a.entrees_ouvertes = plan.entrees_ouvertes;
            ecrire_etat(&a);
        }
        return;
    }
    trp!("\n  {GRAS}Ce qui change{RESET}", "\n  {GRAS}What changes{RESET}");
    for e in plan.lots.iter().flat_map(|l| &l.elements) {
        afficher_aligne(&format!("    {VERT}+{RESET} "), &decrire(e), 6, "");
    }
    println!();
    montrer_notes(&plan.notes);
    if !demander(tr!(
        "\n  Allumer le mode Wi-Fi public ? [o/N] : ",
        "\n  Turn on public Wi-Fi mode? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé : rien n'a changé.", "  Cancelled: nothing changed.");
        return;
    }
    if cfg!(test) {
        return;
    }
    // L'état d'avant est écrit avant toute commande : un plantage en route laisse de quoi tout remettre.
    let anciens = ancien.as_ref().map(|a| a.elements.clone()).unwrap_or_default();
    let prevus: Vec<Element> = plan.lots.iter().flat_map(|l| l.elements.clone()).collect();
    let mut e = Etat {
        version: etat::VERSION,
        etape: Etape::Allumage,
        depuis: ancien.as_ref().map_or_else(maintenant, |a| a.depuis.clone()),
        demarrage: demarrage(),
        reseau: plan.reseau.clone(),
        portail_jusqu_a: None,
        entrees_ouvertes: plan.entrees_ouvertes,
        elements: etat::fusionner(&anciens, prevus),
    };
    if !ecrire_etat(&e) {
        return;
    }
    let Ok(point) = point_de_restauration() else {
        trp!("  Arrêté : rien n'a changé.", "  Stopped: nothing changed.");
        let _ = remettre_l_etat_d_avant(ancien);
        return;
    };
    // Le DNS chiffré strict empêche d'ouvrir une page de portail : il vient après, quand un portail est signalé.
    let separer = plan.signaux.portail == Some(true) && plan.lots.iter().any(|l| l.dns);
    let (d_abord, ensuite): (Vec<&Lot>, Vec<&Lot>) = plan.lots.iter().partition(|l| !(separer && l.dns));
    let mut groupes: Vec<Vec<String>> = point.iter().map(|p| vec![p.clone()]).collect();
    groupes.extend(d_abord.iter().map(|l| l.commandes.clone()));
    let mut reussis = appliquer(&groupes);
    if point.is_some() {
        reussis.remove(0);
    }
    if separer {
        afficher_aligne(
            "\n  ",
            tr!(
                "Ce réseau demande de se connecter sur sa page : le DNS chiffré viendra juste après.",
                "This network asks you to log in on its page: encrypted DNS comes right after."
            ),
            2,
            "",
        );
        portail::ouvrir_et_attendre(None);
        reussis.extend(appliquer(
            &ensuite.iter().map(|l| l.commandes.clone()).collect::<Vec<_>>(),
        ));
    } else if plan.signaux.portail == Some(true) {
        portail::ouvrir_et_attendre(None);
    }
    let lots: Vec<&Lot> = d_abord.into_iter().chain(ensuite).collect();
    // Relu : un élément confirmé à sa valeur d'avant n'a pas changé et sort de l'état ; un élément qui ne se relit
    // pas se juge sur sa commande, sauf sous Windows, où il reste sans être dit pris (voir `juger`).
    let r = Relecture::maintenant(&e);
    let mut changes = Vec::new();
    let mut non_relus = Vec::new();
    println!();
    for (lot, ok) in lots.iter().zip(reussis.iter().chain(std::iter::repeat(&false))) {
        for x in &lot.elements {
            match juger(r.a_l_avant(x), *ok, cfg!(windows)) {
                Pris::Oui => {
                    println!("  {VERT}✔{RESET} {}", decrire(x));
                    changes.push(x.cle());
                }
                Pris::NonVerifie => {
                    trp!("  ? {} : non vérifié", "  ? {}: not verified", decrire(x));
                    changes.push(x.cle());
                    non_relus.push(x.cle());
                }
                Pris::Non => trp!(
                    "  ✖ {} : pas changé, voir le message ci-dessus",
                    "  ✖ {}: not changed, see the message above",
                    decrire(x)
                ),
            }
        }
    }
    let nouveaux: Vec<String> = lots.iter().flat_map(|l| l.elements.iter().map(Element::cle)).collect();
    let manque = rallumage_incomplet(&anciens, &nouveaux, &changes);
    let ouvertes = entrees_ouvertes(
        plan.entrees_ouvertes,
        lots.iter().flat_map(|l| &l.elements),
        &changes,
        &non_relus,
    );
    e.elements.retain(|x| {
        anciens.iter().any(|a| a.cle() == x.cle()) || !nouveaux.contains(&x.cle()) || changes.contains(&x.cle())
    });
    e.etape = Etape::Allume;
    e.entrees_ouvertes = ouvertes;
    if manque && let Some(a) = &ancien {
        e.demarrage.clone_from(&a.demarrage);
    }
    if e.elements.is_empty() {
        let _ = sceau::effacer(sceau::WIFI_PUBLIC);
        trp!(
            "\n  Rien n'a changé : le mode reste éteint.",
            "\n  Nothing changed: the mode stays off."
        );
        return;
    }
    if !ecrire_etat_apres(&e) {
        return;
    }
    #[cfg(target_os = "linux")]
    verifier_le_dns_chiffre(&e);
    if manque {
        afficher_aligne(
            "\n  ✖ ",
            tr!(
                "Le mode reste à moitié : rallumez-le (« vanguard wifi-public on ») ou éteignez-le.",
                "The mode stays half on: turn it on again (“vanguard public-wifi on”) or turn it off."
            ),
            4,
            "",
        );
    } else if ouvertes {
        afficher_aligne(
            "\n  ⚠ ",
            tr!(
                "Mode Wi-Fi public allumé, mais les entrées ne sont pas fermées (voir ci-dessus). En partant : « vanguard wifi-public off ».",
                "Public Wi-Fi mode on, but incoming connections are not closed (see above). When leaving: “vanguard public-wifi off”."
            ),
            4,
            "",
        );
    } else {
        trp!(
            "\n  {VERT}✔{RESET} Mode Wi-Fi public allumé. En partant : « vanguard wifi-public off ».",
            "\n  {VERT}✔{RESET} Public Wi-Fi mode on. When leaving: “vanguard public-wifi off”."
        );
    }
}

/// Un allumage arrêté avant toute commande : l'état d'avant (ou rien) reprend sa place.
fn remettre_l_etat_d_avant(ancien: Option<Etat>) -> bool {
    match ancien {
        Some(a) => ecrire_etat(&a),
        None => sceau::effacer(sceau::WIFI_PUBLIC).is_ok(),
    }
}

/// Linux : après le DNS chiffré strict, un nom se résout-il encore ? Sinon, le réseau le bloque (ou un portail
/// attend) : la personne choisit, jamais un repli silencieux.
#[cfg(target_os = "linux")]
fn verifier_le_dns_chiffre(e: &Etat) {
    let Some(uuid) = uuid_dot(e) else {
        return;
    };
    if portail::noms_resolus() {
        return;
    }
    afficher_aligne(
        "\n  ⚠ ",
        tr!(
            "Les noms de sites ne se résolvent plus : ce réseau bloque le DNS chiffré, ou sa page de connexion attend (« vanguard wifi-public portail »).",
            "Site names no longer resolve: this network blocks encrypted DNS, or its login page is waiting (“vanguard public-wifi portal”)."
        ),
        4,
        "",
    );
    if demander(tr!(
        "  Passer le DNS chiffré en « opportuniste » (moins sûr : un réseau hostile peut le faire retomber en clair) ? [o/N] : ",
        "  Switch encrypted DNS to “opportunistic” (less safe: a hostile network can make it fall back to plain text)? [y/N]: "
    ))
    .oui()
    {
        // Noté d'abord : le menu et le bilan disent le DNS relâché et proposent le retour au strict.
        if !ecrire_etat(&relache(e, None)) {
            return;
        }
        let ok = appliquer(&[linux::nm_modifier(&uuid, &[("connection.dns-over-tls", "opportunistic")])
            .into_iter()
            .collect()])
            == [true];
        if ok && linux::lecture::nm(&uuid, "connection.dns-over-tls") == Some("opportunistic") {
            afficher_aligne(
                "  ⚠ ",
                tr!(
                    "DNS chiffré passé en opportuniste : il peut retomber en clair sur ce réseau. Retour au strict depuis le menu, ou à l'extinction.",
                    "Encrypted DNS switched to opportunistic: it can fall back to plain text on this network. Back to strict from the menu, or when turning off."
                ),
                4,
                "",
            );
        } else {
            trp!(
                "  ✖ Changement refusé : le DNS chiffré reste exigé.",
                "  ✖ Change refused: encrypted DNS stays required."
            );
            ecrire_etat_apres(e);
        }
    } else {
        afficher_aligne(
            "  ",
            tr!(
                "DNS chiffré gardé : les noms ne se résoudront pas tant que ce réseau le bloque (ou que sa page de connexion attend).",
                "Encrypted DNS kept: names won't resolve while this network blocks it (or its login page is waiting)."
            ),
            2,
            "",
        );
    }
}

/// Éteint le mode : chaque élément remis à sa valeur d'avant, dans l'ordre inverse.
fn eteindre() {
    titre(tr!("Mode Wi-Fi public : éteindre", "Public Wi-Fi mode: turn off"));
    let mut e = match lire_etat() {
        Lu::Absent => {
            trp!(
                "  Le mode Wi-Fi public est éteint : rien à éteindre.",
                "  Public Wi-Fi mode is off: nothing to turn off."
            );
            return;
        }
        Lu::NonFiable(raison) => {
            extinction_sure(&raison);
            return;
        }
        Lu::Fiable(e) => e,
    };
    let nom = affichable(&e.reseau.nom);
    trp!(
        "  Allumé depuis le {} sur « {nom} ».",
        "  On since {} on “{nom}”.",
        e.depuis
    );
    let source = e.clone();
    let (mut remises, invalides) = plan_extinction(&source);
    // Ce qui est déjà revenu (un redémarrage a emporté la table et les masques) sort de l'état sans commande.
    let r = Relecture::maintenant(&source);
    let deja: Vec<&Element> = remises
        .iter()
        .filter(|(x, _)| !x.jamais_remis() && r.a_l_avant(x) == Some(true))
        .map(|(x, _)| *x)
        .collect();
    remises.retain(|(x, _)| !deja.contains(x));
    trp!(
        "\n  {GRAS}Ce qui revient comme avant{RESET}",
        "\n  {GRAS}What goes back as before{RESET}"
    );
    for x in &deja {
        let ou = if profil_supprime(x) {
            tr!("profil du réseau supprimé", "network profile deleted").to_string()
        } else {
            situation(x, Some(true), r.meme_demarrage)
        };
        afficher_aligne("    · ", &format!("{} {GRIS}({ou}){RESET}", decrire(x)), 6, "");
    }
    for (x, commande) in &remises {
        let marque = if commande.is_some() { "−" } else { "·" };
        afficher_aligne(&format!("    {marque} "), &decrire(x), 6, "");
        if x.jamais_remis() {
            afficher_aligne(
                "      ",
                tr!(
                    "laissé allumé : Vanguard ne coupe jamais un pare-feu",
                    "left on: Vanguard never turns a firewall off"
                ),
                6,
                GRIS,
            );
        }
    }
    for x in &invalides {
        afficher_aligne(
            "    ✖ ",
            &trf!(
                "{} : valeur notée hors des valeurs permises, jamais remise ; à vérifier à la main",
                "{}: noted value outside the allowed values, never put back; to check by hand",
                decrire(x)
            ),
            6,
            "",
        );
    }
    // Rien à lancer : l'état s'oublie, sans demande d'administrateur.
    let rien_a_lancer = remises.iter().all(|(_, c)| c.is_none());
    if !rien_a_lancer
        && !demander(tr!(
            "\n  Éteindre le mode Wi-Fi public ? [o/N] : ",
            "\n  Turn off public Wi-Fi mode? [y/N]: "
        ))
        .oui()
    {
        trp!("  Annulé : rien n'a changé.", "  Cancelled: nothing changed.");
        return;
    }
    if cfg!(test) {
        return;
    }
    e.etape = Etape::Extinction;
    if !ecrire_etat(&e) {
        return;
    }
    let groupes: Vec<Vec<String>> = remises.iter().filter_map(|(_, c)| c.clone().map(|c| vec![c])).collect();
    let mut faits = appliquer(&groupes).into_iter();
    let reussis: Vec<bool> = remises
        .iter()
        .map(|(_, c)| c.is_some() && faits.next().unwrap_or(false))
        .collect();
    let r = Relecture::maintenant(&e);
    let relus: Vec<Option<bool>> = remises.iter().map(|(x, _)| r.a_l_avant(x)).collect();
    let reste = restants(&remises, &relus, &reussis);
    println!();
    for (x, _) in &remises {
        if reste.contains(x) {
            trp!(
                "  ✖ {} : pas encore revenu, voir le message ci-dessus",
                "  ✖ {}: not back yet, see the message above",
                decrire(x)
            );
        } else if !x.jamais_remis() {
            trp!(
                "  {VERT}✔{RESET} remis : {}",
                "  {VERT}✔{RESET} put back: {}",
                decrire(x)
            );
        }
    }
    if reste.is_empty() {
        let _ = sceau::effacer(sceau::WIFI_PUBLIC);
        trp!(
            "\n  {VERT}✔{RESET} Mode Wi-Fi public éteint : tout est revenu comme avant.",
            "\n  {VERT}✔{RESET} Public Wi-Fi mode off: everything is back as before."
        );
    } else {
        e.elements = reste;
        ecrire_etat_apres(&e);
        afficher_aligne(
            "\n  ",
            tr!(
                "Le mode n'est pas encore éteint en entier : « vanguard wifi-public off » réessaie.",
                "The mode is not fully off yet: “vanguard public-wifi off” tries again."
            ),
            2,
            "",
        );
    }
}

/// L'état ne peut pas être cru : rien de ce qu'il contient n'est remis. Seul ce qui est sans ambiguïté à Vanguard
/// est retiré (Linux : sa table) ; les réglages plus sûrs restent, masques runtime compris, et c'est dit.
fn extinction_sure(raison: &str) {
    afficher_aligne(
        "  ⚠ ",
        &trf!(
            "L'état du mode a été {raison} : aucune valeur notée n'est remise (un programme du compte aurait pu y écrire de quoi affaiblir l'ordinateur). Extinction sûre à la place.",
            "The mode's state was {raison}: no noted value is put back (a program of the account could have written something there to weaken the computer). Safe shutdown instead."
        ),
        4,
        "",
    );
    #[cfg(target_os = "linux")]
    let commandes = commandes_extinction_sure();
    #[cfg(not(target_os = "linux"))]
    let commandes: Vec<String> = Vec::new();
    if !commandes.is_empty() {
        trp!(
            "\n  {GRAS}Retiré (à Vanguard sans ambiguïté){RESET}",
            "\n  {GRAS}Removed (unambiguously Vanguard's){RESET}"
        );
        for c in &commandes {
            println!("    − {GRIS}{}{RESET}", commande_affichable(c));
        }
    }
    afficher_aligne(
        "\n  ",
        tr!(
            "Restent tels quels, plus sûrs : la catégorie Public, le pare-feu, NetBIOS coupé, le DNS protecteur, les réglages du profil Wi-Fi (mDNS, LLMNR, DNS chiffré) et les services d'annonce et de partage masqués jusqu'au redémarrage (« systemctl unmask --runtime <unité> » pour les rendre avant). À remettre à la main si vous le voulez, dans les réglages réseau du système.",
            "Left as they are, safer: the Public category, the firewall, NetBIOS off, the protective DNS, the Wi-Fi profile settings (mDNS, LLMNR, encrypted DNS) and the announcement and sharing services masked until restart (“systemctl unmask --runtime <unit>” to give them back sooner). Put them back by hand if you want, in the system's network settings."
        ),
        2,
        GRIS,
    );
    if !demander(tr!(
        "\n  Faire l'extinction sûre et oublier cet état ? [o/N] : ",
        "\n  Do the safe shutdown and forget this state? [y/N]: "
    ))
    .oui()
    {
        trp!("  Annulé : rien n'a changé.", "  Cancelled: nothing changed.");
        return;
    }
    if cfg!(test) {
        return;
    }
    let groupes: Vec<Vec<String>> = commandes.into_iter().map(|c| vec![c]).collect();
    if appliquer(&groupes).iter().all(|ok| *ok) {
        let _ = sceau::effacer(sceau::WIFI_PUBLIC);
        trp!(
            "  {VERT}✔{RESET} Extinction sûre faite.",
            "  {VERT}✔{RESET} Safe shutdown done."
        );
    } else {
        trp!(
            "  ✖ Extinction sûre pas finie : voir le message ci-dessus.",
            "  ✖ Safe shutdown not finished: see the message above."
        );
    }
}

/// `wifi-public portail` : la page de connexion revient (session d'hôtel expirée). Pare-feu et partages restent ; sous
/// Linux, seul le DNS chiffré passe en « opportuniste », le temps de se connecter : jusqu'à Entrée, dix minutes au
/// plus ; si Vanguard est fermé avant, le lancement suivant le propose d'office.
fn portail_revenu() {
    titre(tr!(
        "Mode Wi-Fi public : page de connexion",
        "Public Wi-Fi mode: login page"
    ));
    #[cfg(target_os = "linux")]
    if let Lu::Fiable(e) = lire_etat()
        && let Some(uuid) = uuid_dot(&e)
    {
        afficher_aligne(
            "  ",
            tr!(
                "Le DNS chiffré empêche la page de connexion de paraître : il passe en « opportuniste » le temps de vous connecter, jusqu'à Entrée (10 minutes au plus), puis redevient strict ; si Vanguard est fermé avant, son lancement suivant le propose. Le pare-feu et les partages ne bougent pas.",
                "Encrypted DNS keeps the login page from appearing: it switches to “opportunistic” while you log in, until Enter (10 minutes at most), then becomes strict again; if Vanguard is closed before, its next launch offers it. The firewall and sharing do not change."
            ),
            2,
            "",
        );
        if !demander(tr!("\n  Continuer ? [o/N] : ", "\n  Continue? [y/N]: ")).oui() || cfg!(test) {
            trp!("  Annulé : rien n'a changé.", "  Cancelled: nothing changed.");
            return;
        }
        let e = relache(&e, Some(chrono::Local::now().timestamp() + PORTAIL_SECONDES));
        if !ecrire_etat(&e) {
            return;
        }
        let commande = linux::nm_modifier(&uuid, &[("connection.dns-over-tls", "opportunistic")]);
        let _ = appliquer(&[commande.into_iter().collect()]);
        let fin = std::time::Instant::now() + std::time::Duration::from_secs(PORTAIL_SECONDES.unsigned_abs());
        if !portail::ouvrir_et_attendre(Some(fin)) {
            trp!(
                "  Échéance de 10 minutes atteinte : retour au DNS chiffré strict.",
                "  10-minute deadline reached: back to strict encrypted DNS."
            );
        }
        revenir_au_strict(e, &uuid);
        return;
    }
    afficher_aligne(
        "  ",
        tr!(
            "Le mode ne tient pas de DNS chiffré strict ici : la page de connexion peut paraître telle quelle.",
            "The mode holds no strict encrypted DNS here: the login page can appear as it is."
        ),
        2,
        "",
    );
    portail::ouvrir_et_attendre(None);
}

/// Le DNS chiffré redevient strict après la page du portail (ou une échéance dépassée), relu.
#[cfg(target_os = "linux")]
fn revenir_au_strict(mut e: Etat, uuid: &str) {
    let strict = linux::nm_modifier(uuid, &[("connection.dns-over-tls", "yes")]);
    let _ = appliquer(&[strict.into_iter().collect()]);
    if linux::lecture::nm(uuid, "connection.dns-over-tls") == Some("yes") {
        e.etape = Etape::Allume;
        e.portail_jusqu_a = None;
        ecrire_etat_apres(&e);
        trp!(
            "  {VERT}✔{RESET} DNS chiffré de nouveau strict.",
            "  {VERT}✔{RESET} Encrypted DNS strict again."
        );
    } else {
        afficher_aligne(
            "  ✖ ",
            tr!(
                "Le DNS chiffré n'est pas redevenu strict : « vanguard wifi-public » le repropose.",
                "Encrypted DNS did not become strict again: “vanguard public-wifi” offers it again."
            ),
            4,
            "",
        );
    }
}

// ---------------------------------------------------------------------------------------------------------------
// État, menu, bilan

/// Le profil du réseau de cet élément a-t-il été supprimé (« Oublier ce réseau ») ? Linux seulement.
fn profil_supprime(x: &Element) -> bool {
    #[cfg(target_os = "linux")]
    return match x {
        Element::Nm { uuid, .. } => linux::lecture::profil_absent(uuid),
        Element::Dns { avant } => avant
            .split_once('\n')
            .is_some_and(|(u, _)| linux::lecture::profil_absent(u)),
        _ => false,
    };
    #[cfg(not(target_os = "linux"))]
    {
        let _ = x;
        false
    }
}

/// Où en est un élément, pour l'écran.
fn situation(e: &Element, relu: Option<bool>, meme_demarrage: bool) -> String {
    match relu {
        Some(false) => tr!("en place", "in place").to_string(),
        Some(true) if e.ephemere() && !meme_demarrage => tr!("parti au redémarrage", "gone at restart").to_string(),
        Some(true) => tr!(
            "revenu à l'avant (changé ailleurs)",
            "back as before (changed elsewhere)"
        )
        .to_string(),
        None => tr!("non vérifié sans droits", "not checked without rights").to_string(),
    }
}

/// Un réglage du mode allumé a-t-il été défait hors de Vanguard ? `defait` : l'élément relu n'est plus à la valeur
/// du mode (`None` : non vérifié, qui ne compte pas ici). Un élément éphémère parti au redémarrage se dit « à
/// moitié », et un pare-feu trouvé coupé n'est jamais remis : ni l'un ni l'autre n'est un réglage défait.
fn defait_selon(e: &Etat, defait: &dyn Fn(&Element) -> Option<bool>) -> bool {
    e.elements.iter().any(|x| element_defait(x, defait))
}

fn element_defait(x: &Element, defait: &dyn Fn(&Element) -> Option<bool>) -> bool {
    !x.ephemere() && !x.jamais_remis() && defait(x) == Some(true)
}

/// Un élément du mode a-t-il été défait hors de Vanguard ? Relu sous Linux seulement : le compte de la session y
/// modifie le profil NetworkManager sans mot de passe. Ailleurs, ces réglages demandent les droits
/// d'administrateur, et les relire lancerait PowerShell à chaque affichage du menu : non relu (`None`).
fn defait_element(x: &Element) -> Option<bool> {
    #[cfg(target_os = "linux")]
    return linux::lecture::defait(x);
    #[cfg(not(target_os = "linux"))]
    {
        let _ = x;
        None
    }
}

/// Le mode allumé, mais un de ses réglages défait hors de Vanguard : le bilan, la ligne du menu et son en-tête le
/// disent, au lieu de « allumé ».
fn defait_ailleurs(e: &Etat) -> bool {
    defait_selon(e, &defait_element)
}

/// L'état d'un mode allumé est-il à moitié (un redémarrage a emporté le pare-feu du mode) ?
fn a_moitie(e: &Etat) -> bool {
    e.elements.iter().any(Element::ephemere) && e.demarrage != demarrage()
}

/// `vanguard wifi-public` sans argument, et la ligne du menu : l'état, puis ce qu'on peut faire.
fn menu() {
    titre(tr!("Mode Wi-Fi public", "Public Wi-Fi mode"));
    expliquer();
    let lu = lire_etat();
    let mut lignes = vec![Ligne::Texte(String::new())];
    #[allow(unused_mut)]
    let mut depart = "1";
    match &lu {
        Lu::Absent => {
            lignes.push(Ligne::Texte(trf!("  Éteint.", "  Off.")));
            if let Some(s) = suggestion_ici() {
                for l in envelopper(&s, LARGEUR - 4) {
                    lignes.push(Ligne::Texte(format!("  {GRIS}{l}{RESET}")));
                }
            }
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::choix("1", tr!("Allumer le mode", "Turn the mode on"), ""));
            lignes.push(Ligne::choix(
                "2",
                tr!("Ouvrir la page de connexion", "Open the login page"),
                tr!("portail du réseau", "network portal"),
            ));
        }
        Lu::NonFiable(raison) => {
            lignes.push(Ligne::Texte(trf!(
                "  ⚠ État du mode {raison} : rien n'en sera remis.",
                "  ⚠ Mode state {raison}: nothing from it will be put back."
            )));
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::choix(
                "1",
                tr!("Extinction sûre", "Safe shutdown"),
                tr!("sans valeur notée", "without noted values"),
            ));
        }
        Lu::Fiable(e) => {
            let nom = affichable(&e.reseau.nom);
            // Relu une fois : l'en-tête et chaque ligne s'en servent.
            let defaits: Vec<bool> = e
                .elements
                .iter()
                .map(|x| e.etape == Etape::Allume && element_defait(x, &defait_element))
                .collect();
            let defait = defaits.iter().any(|d| *d);
            let entete = match e.etape {
                Etape::Allume if a_moitie(e) => trf!(
                    "  ⚠ À moitié : le pare-feu du mode est parti au redémarrage (« {nom} »).",
                    "  ⚠ Half on: the mode's firewall went away at restart (“{nom}”)."
                ),
                Etape::Allume if defait => trf!(
                    "  ⚠ Allumé sur « {nom} », mais un réglage a été défait ailleurs.",
                    "  ⚠ On for “{nom}”, but a setting was undone elsewhere."
                ),
                Etape::Allume => trf!(
                    "  {VERT}●{RESET} Allumé depuis le {} sur « {nom} ».",
                    "  {VERT}●{RESET} On since {} on “{nom}”.",
                    e.depuis
                ),
                Etape::Allumage => trf!(
                    "  ⚠ Allumage interrompu (« {nom} ») : à finir ou à éteindre.",
                    "  ⚠ Turning on was interrupted (“{nom}”): finish it or turn it off."
                ),
                Etape::Extinction => trf!(
                    "  ⚠ Extinction interrompue (« {nom} ») : à finir.",
                    "  ⚠ Turning off was interrupted (“{nom}”): finish it."
                ),
                Etape::Portail if e.portail_jusqu_a.is_none() => trf!(
                    "  ⚠ DNS chiffré en « opportuniste » sur « {nom} » : il peut retomber en clair.",
                    "  ⚠ Encrypted DNS “opportunistic” on “{nom}”: it can fall back to plain text."
                ),
                Etape::Portail => trf!(
                    "  ⚠ DNS chiffré relâché pour la page de connexion (« {nom} »).",
                    "  ⚠ Encrypted DNS relaxed for the login page (“{nom}”)."
                ),
            };
            lignes.push(Ligne::Texte(entete));
            if e.etape == Etape::Allume && !a_moitie(e) && e.entrees_ouvertes {
                lignes.push(Ligne::Texte(trf!(
                    "  ⚠ Les entrées ne sont pas fermées par le mode.",
                    "  ⚠ Incoming connections are not closed by the mode."
                )));
            }
            let r = Relecture::maintenant(e);
            for (x, defait_ici) in e.elements.iter().zip(&defaits) {
                let relu = r.a_l_avant(x);
                let ou = if e.etape == Etape::Portail
                    && uuid_dot(e).is_some()
                    && matches!(x, Element::Nm { propriete, .. } if propriete == "connection.dns-over-tls")
                {
                    tr!("relâché : opportuniste", "relaxed: opportunistic").to_string()
                } else if *defait_ici && relu != Some(true) {
                    // Ni l'avant ni la valeur du mode : une autre, posée ailleurs.
                    tr!("changé ailleurs", "changed elsewhere").to_string()
                } else {
                    situation(x, relu, r.meme_demarrage)
                };
                let texte = format!("{} {GRIS}({ou}){RESET}", decrire(x));
                for (i, l) in envelopper(&texte, LARGEUR - 6).into_iter().enumerate() {
                    let debut = if i == 0 { "    · " } else { "      " };
                    lignes.push(Ligne::Texte(format!("{debut}{l}")));
                }
            }
            lignes.push(Ligne::Texte(String::new()));
            lignes.push(Ligne::choix(
                "1",
                tr!("Éteindre le mode", "Turn the mode off"),
                tr!("tout remettre comme avant", "put everything back"),
            ));
            lignes.push(Ligne::choix(
                "2",
                tr!("Ouvrir la page de connexion", "Open the login page"),
                tr!("portail revenu", "portal came back"),
            ));
            if e.etape == Etape::Allumage || a_moitie(e) {
                lignes.push(Ligne::choix(
                    "3",
                    tr!("Rallumer le mode", "Turn the mode on again"),
                    tr!("finir l'allumage", "finish turning on"),
                ));
            } else if defait {
                lignes.push(Ligne::choix(
                    "3",
                    tr!("Rallumer le mode", "Turn the mode on again"),
                    tr!("reposer le réglage défait", "put the undone setting back"),
                ));
            }
            #[cfg(target_os = "linux")]
            if e.etape == Etape::Portail {
                depart = "4";
                lignes.push(Ligne::choix(
                    "4",
                    tr!("Revenir au DNS chiffré strict", "Back to strict encrypted DNS"),
                    if echeance_depassee(e, chrono::Local::now().timestamp()) {
                        tr!("échéance dépassée", "deadline passed")
                    } else {
                        ""
                    },
                ));
            }
        }
    }
    lignes.push(Ligne::Texte(String::new()));
    lignes.push(Ligne::choix("↵", tr!("Revenir", "Back"), ""));
    lignes.push(Ligne::Texte(String::new()));
    let invite = tr!("Choix (Entrée pour revenir) : ", "Choice (Enter to go back): ");
    let choix = choisir(&lignes, invite, depart, tr!("revenir", "back")).unwrap_or_default();
    match (&lu, choix.as_str()) {
        (Lu::Absent, "1") => allumer(),
        (Lu::NonFiable(_) | Lu::Fiable(_), "1") => eteindre(),
        (Lu::Absent | Lu::Fiable(_), "2") => portail_revenu(),
        (Lu::Fiable(_), "3") => allumer(),
        #[cfg(target_os = "linux")]
        (Lu::Fiable(e), "4") if e.etape == Etape::Portail => {
            if let Some(uuid) = uuid_dot(e) {
                revenir_au_strict(e.clone(), &uuid);
            }
        }
        _ => {}
    }
}

/// La force de la protection négociée du réseau connecté, lue par l'API WLAN ; `None` : pas connecté, ou Windows ne
/// la dit pas (sans la localisation, algorithme inconnu), jamais comptée comme ouverte.
#[cfg(windows)]
fn force_windows() -> Option<u8> {
    crate::machine::wifi::wlanapi::connexion()
        .ok()
        .flatten()
        .filter(|c| !c.securite.is_empty())
        .map(|c| crate::machine::wifi::force(&c.securite))
}

/// La suggestion pour le réseau connecté maintenant, sans rien envoyer.
fn suggestion_ici() -> Option<String> {
    #[cfg(target_os = "linux")]
    let s = portail::Signaux {
        force: linux::lecture::securite().map(|s| crate::machine::wifi::force(&s)),
        deja_public: false,
        portail: linux::lecture::connectivite().map(|c| c == "portal"),
    };
    #[cfg(windows)]
    let s = portail::Signaux {
        force: force_windows(),
        deja_public: windows::lecture::lire().profil.is_some_and(|(_, c, _)| c == "Public"),
        portail: None,
    };
    #[cfg(target_os = "macos")]
    let s = portail::Signaux {
        force: macos::lecture::wifi().map(|(_, _, _, securite)| crate::machine::wifi::force(&securite)),
        deja_public: false,
        portail: None,
    };
    portail::suggestion(s)
}

/// `vanguard wifi-public [on|off|portail]`.
pub fn commande(etat: Option<&str>) {
    // L'échéance du portail passée (terminal fermé, plantage) : le retour au strict est proposé d'office ; l'extinction,
    // elle, le remet de toute façon.
    #[cfg(target_os = "linux")]
    if etat != Some("off")
        && let Lu::Fiable(e) = lire_etat()
        && echeance_depassee(&e, chrono::Local::now().timestamp())
        && let Some(uuid) = uuid_dot(&e)
    {
        afficher_aligne(
            "  ⚠ ",
            tr!(
                "Le DNS chiffré a été relâché pour la page de connexion, et ses 10 minutes sont passées : retour au strict.",
                "Encrypted DNS was relaxed for the login page, and its 10 minutes are up: back to strict."
            ),
            4,
            "",
        );
        revenir_au_strict(e, &uuid);
    }
    match etat {
        Some("on") => allumer(),
        Some("off") => eteindre(),
        Some("portail" | "portal") => portail_revenu(),
        _ => menu(),
    }
}

/// La précision de la ligne du menu (33 caractères au plus).
pub(crate) fn etat_court() -> &'static str {
    match lire_etat() {
        Lu::Absent => tr!("café, hôtel : allumer, éteindre", "café, hotel: turn on, off"),
        Lu::Fiable(e) if e.etape == Etape::Portail => tr!("DNS chiffré relâché", "encrypted DNS relaxed"),
        Lu::Fiable(e) if e.etape == Etape::Allume && !a_moitie(&e) && e.entrees_ouvertes => {
            tr!("allumé, entrées ouvertes", "on, incoming open")
        }
        Lu::Fiable(e) if e.etape == Etape::Allume && !a_moitie(&e) && defait_ailleurs(&e) => {
            tr!("allumé, réglage défait", "on, setting undone")
        }
        Lu::Fiable(e) if e.etape == Etape::Allume && !a_moitie(&e) => tr!("allumé", "on"),
        Lu::Fiable(_) => tr!("à finir : interrompu ou à moitié", "to finish: interrupted or half"),
        Lu::NonFiable(_) => tr!("état changé hors de Vanguard", "state changed outside Vanguard"),
    }
}

/// Le mode tient-il le DNS d'une connexion ? « DNS le plus rapide » ne le change pas tant qu'il est là : la remise
/// écraserait son choix. Un état qu'on ne peut pas croire compte aussi.
pub(crate) fn tient_le_dns() -> bool {
    match lire_etat() {
        Lu::Absent => false,
        Lu::Fiable(e) => e.elements.iter().any(|x| matches!(x, Element::Dns { .. })),
        Lu::NonFiable(_) => true,
    }
}

/// Avant de tout remettre ou de retirer Vanguard : le mode allumé s'éteint d'abord (sinon sa remise se perdrait),
/// après accord.
pub(crate) fn proposer_d_eteindre() {
    if matches!(lire_etat(), Lu::Absent) {
        return;
    }
    afficher_aligne(
        "  ⚠ ",
        tr!(
            "Le mode Wi-Fi public est allumé (ou à finir) : il vaut mieux l'éteindre d'abord, pour que ses réglages reviennent comme avant.",
            "Public Wi-Fi mode is on (or unfinished): better turn it off first, so its settings go back as before."
        ),
        4,
        "",
    );
    if demander(tr!(
        "  Éteindre d'abord le mode Wi-Fi public ? [o/N] : ",
        "  Turn off public Wi-Fi mode first? [y/N]: "
    ))
    .oui()
    {
        eteindre();
    }
}

/// Au bilan : le mode allumé (Info, à éteindre en partant), interrompu, à moitié ou un réglage défait ailleurs
/// (Moyen), ou un état qu'on ne peut pas croire (Moyen). Rien quand il est éteint.
pub(crate) fn constat() -> Vec<Constat> {
    let c = match lire_etat() {
        Lu::Absent => return Vec::new(),
        Lu::NonFiable(raison) => alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "L'état du mode Wi-Fi public a été {raison} : aucune de ses valeurs ne sera remise ; une extinction sûre est proposée.",
                "The public Wi-Fi mode's state was {raison}: none of its values will be put back; a safe shutdown is offered."
            ),
        ),
        Lu::Fiable(e) if e.etape == Etape::Portail => alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Mode Wi-Fi public : le DNS chiffré est relâché en « opportuniste » (« {} ») ; il peut retomber en clair jusqu'au retour au strict.",
                "Public Wi-Fi mode: encrypted DNS is relaxed to “opportunistic” (“{}”); it can fall back to plain text until back to strict.",
                affichable(&e.reseau.nom)
            ),
        ),
        Lu::Fiable(e) if e.etape == Etape::Allume && !a_moitie(&e) && e.entrees_ouvertes => alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Mode Wi-Fi public allumé (« {} »), mais les entrées de l'ordinateur ne sont pas fermées par le mode.",
                "Public Wi-Fi mode on (“{}”), but the computer's incoming connections are not closed by the mode.",
                affichable(&e.reseau.nom)
            ),
        ),
        Lu::Fiable(e) if e.etape != Etape::Allume || a_moitie(&e) => alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Le mode Wi-Fi public est à finir (« {} ») : allumage ou extinction interrompus, ou pare-feu du mode parti au redémarrage.",
                "Public Wi-Fi mode is unfinished (“{}”): turning on or off was interrupted, or the mode's firewall went away at restart.",
                affichable(&e.reseau.nom)
            ),
        ),
        // Les bras d'avant ont pris le reste : l'étape est forcément Allume ici.
        Lu::Fiable(e) if defait_ailleurs(&e) => alerte(
            CAT,
            Niveau::Moyen,
            trf!(
                "Mode Wi-Fi public allumé (« {} »), mais un de ses réglages (DNS chiffré, mDNS, LLMNR ou DNS) a été défait hors de Vanguard : « vanguard wifi-public on » le repose.",
                "Public Wi-Fi mode on (“{}”), but one of its settings (encrypted DNS, mDNS, LLMNR or DNS) was undone outside Vanguard: “vanguard public-wifi on” puts it back.",
                affichable(&e.reseau.nom)
            ),
        ),
        Lu::Fiable(e) => alerte(
            CAT,
            Niveau::Info,
            trf!(
                "Mode Wi-Fi public allumé depuis le {} (réseau « {} ») : à éteindre en partant de ce réseau.",
                "Public Wi-Fi mode on since {} (network “{}”): turn it off when leaving this network.",
                e.depuis,
                affichable(&e.reseau.nom)
            ),
        ),
    };
    vec![c.manuel(
        tr!(
            "« vanguard wifi-public » : son état, puis l'éteindre ou le finir",
            "“vanguard public-wifi”: its state, then turn it off or finish it"
        ),
        &[],
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "0b8c2f4e-1a2b-4c3d-9e8f-001122334455";

    fn etat(elements: Vec<Element>) -> Etat {
        Etat {
            version: etat::VERSION,
            etape: Etape::Allume,
            depuis: "2026-10-23 10:00".into(),
            demarrage: "b".into(),
            reseau: Reseau {
                nom: "Café du coin".into(),
                interface: "wlan0".into(),
                id: U.into(),
            },
            portail_jusqu_a: None,
            entrees_ouvertes: false,
            elements,
        }
    }

    fn exemple() -> Etat {
        etat(vec![
            Element::NftTable {
                interface: "wlan0".into(),
            },
            Element::UniteRuntime {
                unite: "avahi-daemon.socket".into(),
                actif_avant: true,
            },
            Element::Nm {
                uuid: U.into(),
                propriete: "connection.llmnr".into(),
                avant: "default".into(),
            },
            Element::Dns {
                avant: format!("{U}\n|no||no"),
            },
        ])
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn extinction_dans_l_ordre_inverse_et_rejouable() {
        let e = exemple();
        let (remises, invalides) = plan_extinction(&e);
        assert_eq!(invalides.len(), 0);
        let genres: Vec<String> = remises.iter().map(|(x, _)| x.cle()).collect();
        assert_eq!(genres.first().map(String::as_str), Some(format!("dns:{U}").as_str()));
        assert_eq!(genres.last().map(String::as_str), Some("nft"));
        assert!(remises.iter().all(|(_, c)| c.is_some()), "chaque élément a sa remise");
        let dns = remises[0].1.as_deref().unwrap();
        assert!(
            dns.contains(&format!("sudo nmcli connection modify {U} ipv4.dns ''")),
            "{dns}"
        );
        // Rejouable : le même état donne les mêmes commandes.
        let (encore, _) = plan_extinction(&e);
        assert_eq!(remises, encore);
    }

    /// Tout relu à sa valeur d'avant : plus rien dans l'état, il est effacé. Ce qui ne se relit pas se juge sur sa
    /// commande en administrateur ; un élément pas revenu reste, pour réessayer.
    #[test]
    fn etat_vide_quand_tout_est_revenu() {
        let e = exemple();
        let remises: Vec<(&Element, Option<String>)> =
            e.elements.iter().rev().map(|x| (x, Some("c".to_string()))).collect();
        let tout = vec![true; 4];
        assert_eq!(restants(&remises, &[Some(true); 4], &tout), vec![]);
        let reste = restants(&remises, &[Some(true), Some(false), Some(true), Some(true)], &tout);
        assert_eq!(reste, vec![e.elements[2].clone()]);
        // Un pare-feu trouvé coupé sort de l'état sans commande : il reste allumé.
        let coupe = Element::MacPareFeu {
            option: "globalstate".into(),
            avant: "off".into(),
        };
        assert_eq!(restants(&[(&coupe, None)], &[Some(false)], &[false]), vec![]);
        // La table nft ne se relit pas sans droits : elle se juge sur sa commande en administrateur, qui la relit.
        // Sous Windows, rien ne se juge sur une commande (sa réussite viendrait d'un fichier du compte) : ce qui ne
        // se relit pas reste.
        let relus = [Some(true), Some(true), Some(true), None];
        let reste = restants(&remises, &relus, &tout);
        assert_eq!(reste.len(), usize::from(cfg!(windows)));
        let reste = restants(&remises, &relus, &[true, true, true, false]);
        assert_eq!(reste, vec![e.elements[0].clone()]);
    }

    /// Un état falsifié ou adopté : les commandes de l'extinction sûre ne prennent rien de lui.
    #[cfg(target_os = "linux")]
    #[test]
    fn extinction_sure_sans_aucune_valeur_notee() {
        // Un masque runtime a pu être posé par la personne : l'extinction sûre ne retire que la table de Vanguard.
        let c = commandes_extinction_sure();
        assert_eq!(c, vec![linux::retirer_nft()]);
        assert!(
            c.iter()
                .all(|x| !x.contains("unmask") && !x.contains("start") && !x.contains("nmcli"))
        );
    }

    /// Avahi : socket et service masqués à l'allumage, le socket d'abord. L'extinction relance le socket avant le
    /// service, sinon le `start` du service échoue (« Unit avahi-daemon.socket is masked »).
    #[cfg(target_os = "linux")]
    #[test]
    fn socket_relance_avant_son_service() {
        let mut e = exemple();
        e.elements.insert(
            2,
            Element::UniteRuntime {
                unite: "avahi-daemon.service".into(),
                actif_avant: true,
            },
        );
        let (remises, _) = plan_extinction(&e);
        let place = |u: &str| {
            remises
                .iter()
                .position(|(x, _)| x.cle() == format!("unite:{u}"))
                .unwrap()
        };
        assert!(place("avahi-daemon.socket") < place("avahi-daemon.service"));
        // Le reste garde l'ordre inverse : le DNS d'abord, la table en dernier.
        assert_eq!(remises.first().map(|(x, _)| x.cle()), Some(format!("dns:{U}")));
        assert_eq!(remises.last().map(|(x, _)| x.cle()), Some("nft".to_string()));
    }

    /// Rallumer après un redémarrage, commandes refusées : la table n'est pas reprise, le démarrage noté reste
    /// l'ancien, et le mode se dit encore « à moitié ».
    #[test]
    fn rallumage_refuse_reste_a_moitie() {
        let mut e = exemple();
        e.demarrage = "un-ancien-demarrage".into();
        let nouveaux = vec!["nft".to_string(), "unite:avahi-daemon.socket".to_string()];
        assert!(rallumage_incomplet(&e.elements, &nouveaux, &[]));
        assert!(a_moitie(&e));
        assert!(!rallumage_incomplet(&e.elements, &nouveaux, &nouveaux));
        // Rien d'éphémère reprévu (déjà là) : rien ne manque.
        assert!(!rallumage_incomplet(&e.elements, &[], &[]));
    }

    /// Sans nft (ou pare-feu illisible), le mode ne dit jamais « tout est déjà en place ».
    #[test]
    fn jamais_tout_en_place_quand_les_entrees_restent_ouvertes() {
        let ouvert = rien_a_changer(true);
        assert!(!ouvert.contains(tr!("tout est déjà en place", "everything is already in place")));
        assert!(ouvert.contains(tr!("pas fermées", "not closed")), "{ouvert}");
        assert!(rien_a_changer(false).contains(tr!("tout est déjà en place", "everything is already in place")));
        assert!(ferme_les_entrees(&Element::NftTable {
            interface: "wlan0".into()
        }));
        assert!(!ferme_les_entrees(&Element::Dns { avant: String::new() }));
    }

    /// Windows : la catégorie Public ferme les entrées (le profil Public du pare-feu ne s'applique pas à un réseau
    /// en Privé). Pas prise, ou gardée sans être relue : les entrées restent ouvertes.
    #[test]
    fn categorie_privee_laisse_les_entrees_ouvertes() {
        let categorie = Element::Categorie {
            guid: "{0B8C2F4E-1A2B-4C3D-9E8F-001122334455}".into(),
            avant: "Private".into(),
        };
        let profil = Element::ProfilPublic {
            parametre: "DefaultInboundAction".into(),
            avant: "NotConfigured".into(),
        };
        assert!(ferme_les_entrees(&categorie));
        let tous = [categorie.clone(), profil.clone()];
        let les_deux = [categorie.cle(), profil.cle()];
        // Seul le profil Public a pris : la catégorie est restée Privé.
        assert!(entrees_ouvertes(false, &tous, &[profil.cle()], &[]));
        // Les deux pris et relus.
        assert!(!entrees_ouvertes(false, &tous, &les_deux, &[]));
        // La catégorie gardée sans relecture : non vérifié, jamais compté comme fermé.
        assert!(entrees_ouvertes(false, &tous, &les_deux, &[categorie.cle()]));
        assert!(entrees_ouvertes(true, &tous, &les_deux, &[]));
        // Sous Windows, un élément pas relu n'est jamais dit pris, même si sa commande a réussi ; ailleurs, sa
        // commande le juge.
        assert_eq!(juger(None, false, true), Pris::NonVerifie);
        assert_eq!(juger(None, true, true), Pris::NonVerifie);
        assert_eq!(juger(None, true, false), Pris::Oui);
        assert_eq!(juger(None, false, false), Pris::Non);
        assert_eq!(juger(Some(false), false, true), Pris::Oui);
        assert_eq!(juger(Some(true), true, false), Pris::Non);
    }

    /// Un réglage défait hors de Vanguard (le compte modifie le profil NetworkManager sans mot de passe) : seul un
    /// élément relu hors de la valeur du mode compte, jamais un non vérifié ni un éphémère (« à moitié »).
    #[test]
    fn reglage_defait_ailleurs_seulement_s_il_est_relu() {
        let e = exemple();
        let nm = |x: &Element| matches!(x, Element::Nm { .. });
        assert!(defait_selon(&e, &|x| nm(x).then_some(true)));
        assert!(!defait_selon(&e, &|x| nm(x).then_some(false)));
        assert!(!defait_selon(&e, &|_| None));
        let ephemeres = |x: &Element| x.ephemere().then_some(true);
        assert!(!defait_selon(&e, &ephemeres));
        // Un pare-feu trouvé coupé n'est jamais remis : pas un réglage défait.
        let coupe = etat(vec![Element::ProfilPublic {
            parametre: "Enabled".into(),
            avant: "False".into(),
        }]);
        assert!(!defait_selon(&coupe, &|_| Some(true)));
    }

    /// Le DNS chiffré passé en « opportuniste » (à la demande ou pour le portail) est noté : étape Portail, que le
    /// menu et le bilan disent ; l'échéance du portail se fait respecter au lancement suivant.
    #[test]
    fn dns_relache_note_et_echeance() {
        let e = exemple();
        let a_la_demande = relache(&e, None);
        assert_eq!(a_la_demande.etape, Etape::Portail);
        assert_eq!(a_la_demande.portail_jusqu_a, None);
        assert!(
            !echeance_depassee(&a_la_demande, i64::MAX),
            "sans échéance, rien n'expire"
        );
        let portail = relache(&e, Some(1000));
        assert!(!echeance_depassee(&portail, 999));
        assert!(echeance_depassee(&portail, 1001));
        assert!(!echeance_depassee(&e, 1001), "allumé : pas d'échéance");
    }

    fn actuel(serveurs: &[&str], chiffre: Option<bool>, local: Option<&'static str>) -> crate::machine::dns::Actuel {
        crate::machine::dns::Actuel {
            serveurs: serveurs.iter().map(|s| (s.parse().unwrap(), true)).collect(),
            chiffre,
            resolveur_local: local,
        }
    }

    /// Chiffrer seul ne bloque rien : DoT vers 1.1.1.1 laisse place au Bouclier quand il peut être chiffré ; un
    /// résolveur local est gardé, sans rien affirmer de ce qu'il fait.
    #[test]
    fn dns_garde_seulement_s_il_protege() {
        assert_eq!(dns_garde(&actuel(&["1.1.1.1"], Some(true), None), true), None);
        assert!(dns_garde(&actuel(&["1.1.1.1"], Some(true), None), false).is_some());
        assert_eq!(dns_garde(&actuel(&["192.168.1.1"], Some(false), None), true), None);
        let unbound = dns_garde(&actuel(&["127.0.0.1"], None, Some("Unbound")), true).unwrap();
        assert!(unbound.contains(tr!("non vérifié", "not verified")), "{unbound}");
        let (v4, _) = crate::dns_rapide::bouclier_protege();
        assert!(dns_garde(&actuel(&[v4[0]], Some(true), None), true).is_some());
        // Le DHCP d'un réseau hostile ajoute son serveur à une adresse filtrante connue : le Bouclier est posé.
        assert_eq!(
            dns_garde(&actuel(&[v4[0], "203.0.113.7"], Some(true), None), true),
            None
        );
        assert!(dns_garde(&actuel(&[v4[0], v4[1]], Some(true), None), true).is_some());
    }

    #[test]
    fn descriptions_dans_les_deux_langues_et_sans_valeur_brute() {
        let d = decrire(&Element::Dns {
            avant: format!("{U}\n149.112.121.20#protected.canadianshield.cira.ca|yes|2620:10a:80bb::20|yes"),
        });
        assert!(
            d.contains("149.112.121.20, 2620:10a:80bb::20") && !d.contains('#'),
            "{d}"
        );
        assert!(serveurs_lisibles(&format!("{U}\n|no||no")).contains(tr!("automatique", "automatic")));
        assert!(serveurs_lisibles("{G}\n9.9.9.9|").contains("9.9.9.9"));
        for e in exemple().elements {
            assert_ne!(decrire(&e), "");
        }
    }

    #[test]
    fn precisions_du_menu_dans_la_largeur() {
        for p in [
            "café, hôtel : allumer, éteindre",
            "café, hotel: turn on, off",
            "à finir : interrompu ou à moitié",
            "to finish: interrupted or half",
            "état changé hors de Vanguard",
            "state changed outside Vanguard",
            "tout remettre comme avant",
            "finir l'allumage",
            "échéance dépassée",
            "DNS chiffré relâché",
            "encrypted DNS relaxed",
            "allumé, entrées ouvertes",
            "on, incoming open",
            "relâché : opportuniste",
            "allumé, réglage défait",
            "on, setting undone",
            "reposer le réglage défait",
            "put the undone setting back",
        ] {
            assert!(largeur_affichee(p) <= 33, "{p}");
        }
    }

    #[test]
    fn messages_dans_la_largeur() {
        let larges: Vec<String> = [include_str!("mod.rs"), include_str!("portail.rs")]
            .into_iter()
            .flat_map(crate::ui::textes_trop_larges)
            .collect();
        assert_eq!(larges, Vec::<String>::new());
    }

    #[test]
    fn les_tests_n_appliquent_jamais_rien() {
        assert_eq!(appliquer(&[vec!["false".to_string()]]), vec![false]);
        assert_eq!(appliquer(&[]), Vec::<bool>::new());
    }

    #[test]
    fn situation_d_un_element() {
        let nft = Element::NftTable {
            interface: "wlan0".into(),
        };
        assert_eq!(
            situation(&nft, Some(true), false),
            tr!("parti au redémarrage", "gone at restart")
        );
        assert_eq!(
            situation(&nft, None, true),
            tr!("non vérifié sans droits", "not checked without rights")
        );
        assert_eq!(situation(&nft, Some(false), true), tr!("en place", "in place"));
    }
}
