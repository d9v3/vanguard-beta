//! Scan du réseau : machines, ports ouverts, risques, et comparaison avec les scans précédents.

// Les outils du groupe « Réseau et Internet » du menu.
pub mod cameras;
pub mod canaux;
pub mod connexion;
pub mod empoisonnement;
pub mod listes_noires;
pub mod nat;
pub mod nmap;
pub mod objets;
pub mod scan;
pub mod surveillance;
pub mod tableau;
pub mod upnp;
pub mod wifi_public;

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use serde::{Deserialize, Serialize};

use crate::risk::{Niveau, PORTS_COURANTS, PORTS_UDP, identifier, info_port, info_udp, note};
use crate::ui::*;

// Le socle a quitté ce module ; le relais garde les chemins `crate::reseau::…` des lots écrits en même temps, le
// temps de leur fusion.
pub(crate) use crate::socle::{Verrou, dossier_local, ecrire_atomique};

pub struct Options {
    pub cible: Option<String>,
    pub ports: String,
    pub timeout: u64,
    pub parallele: usize,
    pub json: bool,
    /// Aucun affichage (surveillance en arrière-plan).
    pub silencieux: bool,
}

impl Options {
    pub fn defaut(cible: Option<String>, ports: &str) -> Self {
        Options {
            cible,
            ports: ports.into(),
            timeout: 500,
            parallele: 512,
            json: false,
            silencieux: false,
        }
    }
}

#[derive(Serialize)]
pub struct PortOuvert {
    pub port: u16,
    pub service: &'static str,
    pub niveau: Niveau,
    pub banniere: Option<String>,
    pub conseil: &'static str,
    pub nouveau: bool,
    /// Programme qui écoute (seulement pour cette machine).
    pub programme: Option<String>,
    /// Port UDP (sinon TCP).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub udp: bool,
}

impl PortOuvert {
    /// Un port ouvert, décrit par `i` (service, gravité, conseil).
    fn decrit(
        port: u16,
        i: &crate::risk::InfoPort,
        banniere: Option<String>,
        nouveau: bool,
        programme: Option<String>,
        udp: bool,
    ) -> Self {
        PortOuvert {
            port,
            service: i.service,
            niveau: i.niveau,
            banniere,
            conseil: i.conseil,
            nouveau,
            programme,
            udp,
        }
    }

    /// « 445/tcp », « 161/udp ».
    pub fn libelle(&self) -> String {
        format!("{}/{}", self.port, if self.udp { "udp" } else { "tcp" })
    }
}

#[derive(Serialize)]
pub struct Hote {
    pub ip: Ipv4Addr,
    pub nom: Option<String>,
    pub mac: Option<String>,
    pub fabricant: Option<String>,
    /// Nom donné par l'utilisateur (« imprimante HP »).
    pub surnom: Option<String>,
    /// Date du premier passage, AAAA-MM-JJ.
    pub premier_vu: Option<String>,
    pub role: Option<&'static str>,
    pub nouvelle: bool,
    pub ports: Vec<PortOuvert>,
    pub alertes: Vec<(Niveau, String)>,
    pub score: u32,
}

impl Hote {
    pub fn titre(&self) -> String {
        titre_de([self.surnom.as_deref(), self.nom.as_deref(), self.fabricant.as_deref()])
    }

    /// L'appareil tel que le voit la section « Box et objets connectés » (et l'audit du réseau).
    pub(crate) fn objet(&self) -> objets::Appareil {
        let tcp = self.ports.iter().filter(|p| !p.udp).map(|p| p.port).collect();
        objets::Appareil {
            ip: self.ip,
            titre: self.titre(),
            boite: self.role == Some("passerelle"),
            fabricant: self.fabricant.clone(),
            nom: self.nom.clone(),
            tcp,
            annonces: objets::annonces(&self.ports),
            dernier_vu: None,
        }
    }
}

/// « surnom · nom · fabricant », avec ce qui est connu.
fn titre_de(morceaux: [Option<&str>; 3]) -> String {
    morceaux.into_iter().flatten().collect::<Vec<_>>().join(" · ")
}

/// Appareil déjà vu sur ce réseau mais absent du scan.
#[derive(Serialize)]
pub struct Absent {
    pub ip: Ipv4Addr,
    pub titre: String,
    pub dernier_vu: Option<String>,
}

#[derive(Serialize)]
pub struct Rapport {
    pub reseau: String,
    /// Nom du réseau (Wi-Fi) quand il est connu.
    pub nom_reseau: Option<String>,
    pub absents: Vec<Absent>,
    pub duree_s: f64,
    pub score_global: u32,
    pub note: &'static str,
    pub hotes: Vec<Hote>,
    /// Redirections UPnP de la box (scan du réseau local seulement).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<crate::reseau::upnp::Etat>,
    /// Empoisonneurs de noms du réseau local (Responder…), scan du réseau local seulement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub empoisonnement: Option<crate::reseau::empoisonnement::Rapport>,
}

/// Délai par port de la revérification d'un appareil en veille (ms) : trois fois celui d'un scan.
const DELAI_PATIENT: u64 = 1500;

/// Appareils trouvés sans aucun port ouvert, alors que la base leur en a déjà vu : (adresse, ports déjà vus parmi ceux
/// de ce scan).
fn silencieux_a_revoir(
    resultats: &BTreeMap<Ipv4Addr, Vec<(u16, Option<String>)>>,
    connus: &BTreeMap<String, AppareilConnu>,
    cle: impl Fn(Ipv4Addr) -> String,
    ports: &[u16],
) -> Vec<(Ipv4Addr, Vec<u16>)> {
    resultats
        .iter()
        .filter(|(_, ouverts)| ouverts.is_empty())
        .filter_map(|(&ip, _)| {
            let deja_vus: Vec<u16> = connus
                .get(&cle(ip))?
                .ports
                .iter()
                .copied()
                .filter(|p| ports.contains(p))
                .collect();
            (!deja_vus.is_empty()).then_some((ip, deja_vus))
        })
        .collect()
}

/// Base des appareils, un carnet par réseau : chez toi et chez chaque ami, sans mélange.
/// Un réseau est reconnu à l'adresse MAC de sa box (stable, contrairement à l'IP).
#[derive(Serialize, Deserialize, Default)]
struct Base {
    #[serde(default)]
    reseaux: BTreeMap<String, ReseauConnu>,
    /// Ancien format (avant les carnets par réseau) : repris dans le réseau courant au prochain scan.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    appareils: BTreeMap<String, AppareilConnu>,
}

#[derive(Serialize, Deserialize, Default)]
struct ReseauConnu {
    nom: Option<String>,
    appareils: BTreeMap<String, AppareilConnu>,
    /// Ce réseau a déjà été scanné en UDP (depuis la 0.42) : avant, aucun port UDP n'est « nouveau ».
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    udp: bool,
}

#[derive(Serialize, Deserialize, Clone)]
struct AppareilConnu {
    ip: Ipv4Addr,
    nom: Option<String>,
    fabricant: Option<String>,
    /// Tous les ports déjà vus ouverts (union : un Chromecast en veille ne doit pas déclencher d'alerte au réveil).
    ports: BTreeSet<u16>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    ports_udp: BTreeSet<u16>,
    #[serde(default)]
    surnom: Option<String>,
    /// Quand le surnom a été donné ou retiré (« AAAA-MM-JJ HH:MM:SS ») : à la fusion clé + copie locale,
    /// le plus récent gagne, même s'il a été donné sans la clé.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    surnom_le: Option<String>,
    #[serde(default)]
    premier_vu: Option<String>,
    #[serde(default)]
    dernier_vu: Option<String>,
    /// Ce que l'appareil dit de lui-même (SNMP, UPnP, page web) : le modèle d'une box, le type d'un objet, pour
    /// `objets` sans refaire de scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    annonce: Option<String>,
}

impl AppareilConnu {
    fn titre(&self) -> String {
        let fabricant = self.fabricant.as_deref().map(scan::fabricant_traduit);
        titre_de([self.surnom.as_deref(), self.nom.as_deref(), fabricant])
    }

    /// Les textes de la fiche rendus inoffensifs : voir `Base::rendre_affichable`.
    fn rendre_affichable(&mut self) {
        let textes = [
            &mut self.nom,
            &mut self.fabricant,
            &mut self.surnom,
            &mut self.surnom_le,
            &mut self.premier_vu,
            &mut self.dernier_vu,
            &mut self.annonce,
        ];
        for t in textes.into_iter().flatten() {
            *t = affichable(t);
        }
    }

    /// Fusion de deux fiches du même appareil (base de la clé + copie locale).
    fn fusionner(&mut self, autre: AppareilConnu) {
        self.ports.extend(autre.ports);
        self.ports_udp.extend(autre.ports_udp);
        // None < Some : une fiche datée l'emporte sur une fiche d'avant la v0.9.6.
        if autre.surnom_le > self.surnom_le {
            self.surnom = autre.surnom;
            self.surnom_le = autre.surnom_le;
        } else if self.surnom_le.is_none() {
            self.surnom = self.surnom.take().or(autre.surnom);
        }
        self.premier_vu = [self.premier_vu.take(), autre.premier_vu].into_iter().flatten().min();
        if autre.dernier_vu > self.dernier_vu {
            self.dernier_vu = autre.dernier_vu;
            self.ip = autre.ip;
            self.annonce = autre.annonce.or(self.annonce.take());
        } else {
            self.annonce = self.annonce.take().or(autre.annonce);
        }
    }
}

/// Ajoute les fiches d'un carnet à un autre ; celles d'un même appareil sont fusionnées.
fn absorber_carnet(carnet: &mut BTreeMap<String, AppareilConnu>, autre: BTreeMap<String, AppareilConnu>) {
    for (cle, a) in autre {
        match carnet.get_mut(&cle) {
            Some(connu) => connu.fusionner(a),
            None => drop(carnet.insert(cle, a)),
        }
    }
}

impl Base {
    /// Le carnet d'un dossier `donnees` : en clair, ou chiffré par la phrase (`chiffrement`). `None` : chiffré et pas
    /// ouvert (pas de phrase, mauvaise phrase) ; il ne faut alors rien y réécrire, ce serait l'écraser.
    fn ouvrir_carnet(donnees: &std::path::Path) -> Option<Base> {
        if !crate::chiffrement::protegee(donnees) {
            return Some(Base::lire(&donnees.join("appareils.json")));
        }
        let texte = crate::chiffrement::lire_carnet(donnees)?;
        crate::chiffrement::retenir_carnet(&texte);
        match serde_json::from_str::<Base>(&texte) {
            Ok(mut base) => {
                base.rendre_affichable();
                Some(base)
            }
            Err(e) => {
                tre!(
                    "Attention : carnet chiffré de la clé illisible ({e}) : il n'est ni lu ni réécrit.",
                    "Warning: the key's encrypted record unreadable ({e}): it is neither read nor rewritten."
                );
                None
            }
        }
    }

    fn lire(p: &std::path::Path) -> Base {
        let Ok(texte) = std::fs::read_to_string(p) else {
            return Base::default();
        };
        // Le Bloc-notes et PowerShell 5.1 ajoutent une marque d'ordre des octets (BOM) en tête.
        match serde_json::from_str::<Base>(texte.trim_start_matches('\u{feff}')) {
            Ok(mut base) => {
                base.rendre_affichable();
                base
            }
            Err(e) => {
                // Jamais écraser une base qu'on ne sait pas lire : on la met de côté, intacte.
                let copie = p.with_extension(format!(
                    "illisible-{}.json",
                    chrono::Local::now().format("%Y%m%d-%H%M%S")
                ));
                let _ = std::fs::copy(p, &copie);
                tre!(
                    "Attention : base des appareils illisible ({e}). Copie gardée : {}",
                    "Warning: device database unreadable ({e}). Copy kept: {}",
                    copie.display()
                );
                Base::default()
            }
        }
    }

    /// La base de la clé, enrichie des scans faits sans elle (copie locale).
    /// Le verrou rendu doit être gardé jusqu'à `enregistrer` : la surveillance horaire et un scan manuel
    /// ne doivent pas lire et réécrire la base en même temps (l'une effacerait les ajouts de l'autre).
    fn charger() -> (Base, [PathBuf; 2], Option<Verrou>) {
        let verrou = Verrou::prendre_nomme(&dossier_local(), "appareils.verrou");
        let cle = cle_usb().map(|c| {
            let modifiable = modifiable(&c);
            (c, modifiable)
        });
        let (base, chemins) = Base::charger_depuis(cle, &dossier_local());
        (base, chemins, verrou)
    }

    /// `cle` : la clé reconnue et si elle est modifiable ici ; `local` : le dossier de cet ordinateur. Le carnet de
    /// la clé n'est pris que si rien ne dit qu'il a changé hors de Vanguard (`cles_connues`) : un carnet préparé
    /// déciderait sinon de « Nouvel appareil ».
    fn charger_depuis(cle: Option<(PathBuf, bool)>, local: &std::path::Path) -> (Base, [PathBuf; 2]) {
        let local = local.join("appareils.json");
        let cle = cle.filter(|(racine, modifiable)| {
            match crate::protection::cles_connues::verdict(racine, *modifiable) {
                Ok(()) => true,
                Err(refus) => {
                    tre!(
                        "Attention : {} : il n'est ni lu ni réécrit (vanguard manifeste --accepter si c'est voulu).",
                        "Warning: {}: it is neither read nor rewritten (vanguard manifeste --accepter if intended).",
                        refus.texte()
                    );
                    false
                }
            }
        });
        let donnees = match &cle {
            Some((racine, true)) => racine.join("donnees"),
            _ => local.parent().map(PathBuf::from).unwrap_or_default(),
        };
        let carnet = Base::ouvrir_carnet(&donnees);
        // Carnet chiffré pas ouvert : il n'est pas réécrit, tout reste sur cet ordinateur.
        let chemin_cle = if carnet.is_some() {
            donnees.join("appareils.json")
        } else {
            local.clone()
        };
        let ouvert = carnet.is_some();
        let mut base = carnet.unwrap_or_default();
        // Clé protégée en écriture (autre ordinateur) : sa base sert quand même, les ajouts restent ici.
        if let Some((protegee, false)) = &cle
            && let Some(sienne) = Base::ouvrir_carnet(&protegee.join("donnees"))
        {
            base.absorber(sienne);
        }
        if local != chemin_cle || !ouvert {
            base.absorber(Base::lire(&local));
        }
        (base, [chemin_cle, local])
    }

    /// La base voyage sur la clé : branchée sur un autre ordinateur, copiée ou restaurée à la main, elle a pu être
    /// écrite par autre chose que Vanguard. Ses textes montrés (noms, surnoms, fabricants, dates) sont rendus
    /// inoffensifs dès la lecture : à l'écran, dans le JSON et dans ce que Vanguard y réécrit.
    fn rendre_affichable(&mut self) {
        for r in self.reseaux.values_mut() {
            if let Some(nom) = &mut r.nom {
                *nom = affichable(nom);
            }
        }
        let fiches = self.reseaux.values_mut().flat_map(|r| r.appareils.values_mut());
        for a in fiches.chain(self.appareils.values_mut()) {
            a.rendre_affichable();
        }
    }

    fn absorber(&mut self, autre: Base) {
        absorber_carnet(&mut self.appareils, autre.appareils);
        for (id, r) in autre.reseaux {
            let mien = self.reseaux.entry(id).or_default();
            mien.nom = mien.nom.take().or(r.nom);
            mien.udp |= r.udp;
            absorber_carnet(&mut mien.appareils, r.appareils);
        }
    }

    /// On écrit la base sur la clé ET en local : la copie locale sert quand la clé est absente.
    fn enregistrer(&self, chemins: &[PathBuf; 2]) {
        let json = serde_json::to_string_pretty(self).unwrap_or_default();
        let [cle, local] = chemins;
        for p in chemins {
            // Le carnet d'une clé protégée s'écrit chiffré ; jamais en clair à côté.
            let ecrit = match p.parent().filter(|d| crate::chiffrement::protegee(d)) {
                Some(donnees) => crate::chiffrement::ecrire_carnet(donnees, &json),
                None => ecrire_atomique(p, &json),
            };
            match ecrit {
                Err(e) => tre!(
                    "Attention : base des appareils non enregistrée dans {} ({e}).",
                    "Warning: device database not saved to {} ({e}).",
                    p.display()
                ),
                // Le carnet que Vanguard vient d'écrire sur la clé devient sa référence : à la prochaine lecture, un
                // carnet différent aura été changé par autre chose.
                Ok(()) if p == cle && p != local => {
                    if let Some(racine) = p.parent().and_then(std::path::Path::parent) {
                        crate::protection::cles_connues::noter(racine);
                    }
                }
                Ok(()) => {}
            }
        }
    }
}

/// Les appareils du carnet de ce réseau (son dernier scan gardé) et le nom du réseau, pour `objets` : rien n'est
/// sondé, seule la box est reconnue à son adresse MAC (celle qui désigne le carnet). `None` : aucun scan gardé.
pub(crate) fn carnet_du_reseau() -> Option<(Option<String>, Vec<objets::Appareil>)> {
    let local = scan::reseau_local();
    let gw = scan::passerelle();
    // Même clé que le scan : la MAC de la box, sinon la plage d'adresses.
    let id = gw
        .and_then(|g| scan::table_arp().get(&g).cloned())
        .or_else(|| local.as_ref().map(|(cible, _)| trf!("plage {cible}", "range {cible}")))?;
    let moi = local.map(|(_, ip)| ip);
    let (base, _, _verrou) = Base::charger();
    let reseau = base.reseaux.get(&id).filter(|r| !r.appareils.is_empty())?;
    let appareils = reseau
        .appareils
        .iter()
        .filter(|(_, a)| Some(a.ip) != moi)
        .map(|(cle, a)| objets::Appareil {
            ip: a.ip,
            titre: a.titre(),
            boite: *cle == id,
            fabricant: a.fabricant.clone(),
            nom: a.nom.clone(),
            tcp: a.ports.iter().copied().collect(),
            annonces: a.annonce.iter().cloned().collect(),
            dernier_vu: a.dernier_vu.clone(),
        })
        .collect();
    Some((reseau.nom.clone(), appareils))
}

/// Résumé de chaque carnet de réseau reconnu à la MAC de sa box, pour l'audit (`audit::arp`) : cette MAC (la clé du
/// carnet), le nom du Wi-Fi et l'adresse de la box. Les carnets reconnus à leur plage d'adresses, sans MAC, n'y sont
/// pas. Lecture seule.
pub(crate) fn resumes_des_carnets() -> Vec<(String, Option<String>, Option<Ipv4Addr>)> {
    let (base, _, _verrou) = Base::charger();
    base.reseaux
        .iter()
        .filter(|(id, _)| id.contains(':'))
        .map(|(id, r)| (id.clone(), r.nom.clone(), r.appareils.get(id).map(|a| a.ip)))
        .collect()
}

/// « 0 appareil », « 1 appareil », « 2 appareils » (en français, 0 et 1 sont au singulier).
fn accord(n: usize, singulier: &str, pluriel: &str) -> String {
    format!("{n} {}", if n > 1 { pluriel } else { singulier })
}

/// « 2026-10-16 » → « 16/10/2026 » (en anglais, la date ISO reste telle quelle : pas d'ambiguïté jour/mois).
pub fn date_fr(iso: &str) -> String {
    if crate::langue::anglais() {
        return iso.to_string();
    }
    let mut p = iso.split('-');
    match (p.next(), p.next(), p.next()) {
        (Some(a), Some(m), Some(j)) => format!("{j}/{m}/{a}"),
        _ => iso.to_string(),
    }
}

/// Ce que contient une base : réseaux, appareils, surnoms donnés.
pub struct Contenu {
    pub reseaux: usize,
    pub appareils: usize,
    pub surnoms: usize,
}

impl Base {
    /// Toutes les fiches : celles de chaque réseau, puis celles de l'ancien format.
    fn fiches(&self) -> impl Iterator<Item = &AppareilConnu> {
        self.reseaux
            .values()
            .flat_map(|r| r.appareils.values())
            .chain(self.appareils.values())
    }

    fn contenu(&self) -> Contenu {
        Contenu {
            reseaux: self.reseaux.len(),
            appareils: self.fiches().count(),
            surnoms: self.fiches().filter(|a| a.surnom.is_some()).count(),
        }
    }
}

/// La base des appareils (clé et copie locale fusionnées), pour une sauvegarde.
pub fn base_pour_sauvegarde() -> (serde_json::Value, Contenu) {
    let (base, _, _verrou) = Base::charger();
    (serde_json::to_value(&base).unwrap_or_default(), base.contenu())
}

/// Ajoute une base sauvegardée à la base actuelle : fusion fiche par fiche (ports réunis, surnom le plus
/// récent, première et dernière dates), rien n'est effacé. Rend ce que contenait la sauvegarde.
pub fn restaurer_base(sauvegarde: serde_json::Value) -> Result<Contenu, String> {
    let autre: Base = serde_json::from_value(sauvegarde)
        .map_err(|e| trf!("base des appareils illisible ({e})", "device database unreadable ({e})"))?;
    let contenu = autre.contenu();
    let (mut base, chemins, _verrou) = Base::charger();
    base.absorber(autre);
    base.enregistrer(&chemins);
    Ok(contenu)
}

/// Un appareil de la base, tel que le tableau de bord de la surveillance le montre.
pub struct FicheAppareil {
    /// L'identifiant du réseau (MAC de la box, sinon « plage … ») : deux réseaux peuvent porter le même nom.
    pub reseau: String,
    /// Le nom du réseau, souvent celui du Wi-Fi, quand il est connu.
    pub nom_reseau: Option<String>,
    /// La clé de la fiche : l'adresse MAC, sinon l'adresse IP.
    pub id: String,
    pub ip: Ipv4Addr,
    pub surnom: Option<String>,
    /// Nom et fabricant, sans le surnom, montré à part.
    pub description: String,
    pub premier_vu: Option<String>,
    pub dernier_vu: Option<String>,
}

/// Les appareils de la base (clé et copie locale fusionnées), en lecture seule : rien n'est réécrit.
pub fn appareils_connus() -> Vec<FicheAppareil> {
    let (base, _, _verrou) = Base::charger();
    base.fiches_montrees()
}

impl Base {
    fn fiches_montrees(&self) -> Vec<FicheAppareil> {
        let fiche = |reseau: &str, nom_reseau: Option<&String>, id: &String, a: &AppareilConnu| FicheAppareil {
            reseau: reseau.to_string(),
            nom_reseau: nom_reseau.cloned(),
            id: id.clone(),
            ip: a.ip,
            surnom: a.surnom.clone(),
            description: titre_de([
                None,
                a.nom.as_deref(),
                a.fabricant.as_deref().map(scan::fabricant_traduit),
            ]),
            premier_vu: a.premier_vu.clone(),
            dernier_vu: a.dernier_vu.clone(),
        };
        let mut fiches: Vec<FicheAppareil> = self
            .reseaux
            .iter()
            .flat_map(|(id_reseau, r)| {
                r.appareils
                    .iter()
                    .map(move |(id, a)| fiche(id_reseau, r.nom.as_ref(), id, a))
            })
            .collect();
        // Ancien format, sans carnet par réseau : les fiches restent montrées, sous un réseau sans nom.
        fiches.extend(self.appareils.iter().map(|(id, a)| fiche("", None, id, a)));
        fiches
    }
}

/// Donne (ou retire, avec `None`) un surnom à un appareil, désigné par son IP ou son adresse MAC.
pub fn nommer(qui: &str, surnom: Option<&str>) -> Result<String, String> {
    let (mut base, chemins, _verrou) = Base::charger();
    let mut trouve = None;
    let maintenant = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    // Par IP, seulement dans le réseau où l'on se trouve (la même IP existe chez chacun) ; par MAC, partout.
    // Même identifiant que le scan : MAC de la box, sinon « plage <réseau local> ». Sans ce repli, un réseau
    // dont la box n'a pas de MAC connue ne pouvait jamais nommer un appareil par son IP.
    let ici = scan::passerelle()
        .and_then(|gw| scan::table_arp().get(&gw).cloned())
        .or_else(|| scan::reseau_local().map(|(r, _)| trf!("plage {r}", "range {r}")));
    // La MAC qui répond à cette IP en ce moment : un appareil à deux adresses (box d'une VM, VPN) n'a qu'une fiche,
    // rangée sous sa MAC avec la dernière adresse vue ; nommé par l'autre adresse, il était introuvable (vu en VM).
    let mac_actuelle = qui
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .and_then(|ip| scan::table_arp().get(&ip).cloned());
    for (id, r) in &mut base.reseaux {
        let dans_ce_reseau = ici.as_deref() == Some(id.as_str());
        for (cle, a) in &mut r.appareils {
            let par_mac = cle.eq_ignore_ascii_case(qui);
            let par_ip = dans_ce_reseau
                && (a.ip.to_string() == qui || mac_actuelle.as_deref().is_some_and(|m| cle.eq_ignore_ascii_case(m)));
            if par_mac || par_ip {
                a.surnom = surnom.map(str::to_string);
                a.surnom_le = Some(maintenant.clone());
                trouve = Some(format!("{} ({cle})", a.ip));
            }
        }
    }
    let Some(decrit) = trouve else {
        return Err(trf!(
            "aucun appareil « {qui} » dans la base : lancez d'abord un scan du réseau (vanguard reseau)",
            "no device “{qui}” in the database: first run a network scan (vanguard network)"
        ));
    };
    base.enregistrer(&chemins);
    Ok(decrit)
}

/// Fichier témoin à la racine de la clé USB de Vanguard.
pub const TEMOIN_CLE: &str = "vanguard.cle";

/// Volumes montés pour l'utilisateur, un sous-dossier par clé : /run/media/<utilisateur> (Arch, Fedora, openSUSE…)
/// et /media/<utilisateur> (Debian, Ubuntu, Mint), où udisks range les clés selon la distribution.
#[cfg(target_os = "linux")]
pub fn cles_montees() -> Vec<PathBuf> {
    std::env::var("USER")
        .ok()
        .into_iter()
        .flat_map(|u| [format!("/run/media/{u}"), format!("/media/{u}")])
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .map(|d| d.path())
        .collect()
}

/// Les volumes où une clé peut être montée : ceux de l'utilisateur sous Linux, /Volumes sous macOS, les lecteurs
/// D: à Z: sous Windows.
pub(crate) fn volumes_montes() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        cles_montees()
    }
    #[cfg(target_os = "macos")]
    {
        std::fs::read_dir("/Volumes")
            .into_iter()
            .flatten()
            .flatten()
            .map(|d| d.path())
            .collect()
    }
    #[cfg(windows)]
    {
        ('D'..='Z').map(|l| PathBuf::from(format!("{l}:\\"))).collect()
    }
}

/// Clé USB de Vanguard branchée : celle d'où tourne le programme ; sinon, parmi les volumes montés, une clé dont le
/// jeton est connu de cet ordinateur (`protection::cles_connues`). Un volume qui porte le témoin sans jeton connu
/// n'est pas la clé : rien n'y est lu ni écrit, pas même l'essai d'écriture de `modifiable`.
pub fn cle_usb() -> Option<PathBuf> {
    cle_du_programme().or_else(|| {
        let connues = crate::protection::cles_connues::jetons();
        cle_parmi(volumes_montes(), &connues)
    })
}

/// La clé connue parmi `volumes`. Deux clés connues branchées : la première dans l'ordre des chemins (« /run/media/
/// alice/VANGUARD » avant « …/VANGUARD1 »), le même à chaque lancement ; l'autre n'est pas regardée.
fn cle_parmi(mut volumes: Vec<PathBuf>, connues: &std::collections::BTreeSet<String>) -> Option<PathBuf> {
    volumes.sort();
    volumes
        .into_iter()
        .find(|d| est_une_cle(d) && crate::protection::cles_connues::connue(d, connues))
}

/// Un volume branché porte le témoin sans être une clé reconnue ici.
pub(crate) fn volume_inconnu() -> bool {
    cle_usb().is_none() && volumes_montes().iter().any(|d| est_une_cle(d))
}

/// Ce que la ligne d'état du menu dit de la clé.
pub enum EtatCle {
    Aucune,
    Branchee,
    ProtegeeEnEcriture,
    /// Un volume au témoin sans jeton connu : ignoré.
    Inconnue,
}

pub fn etat_de_la_cle() -> EtatCle {
    match cle_usb() {
        Some(c) if modifiable(&c) => EtatCle::Branchee,
        Some(_) => EtatCle::ProtegeeEnEcriture,
        None if volume_inconnu() => EtatCle::Inconnue,
        None => EtatCle::Aucune,
    }
}

/// La clé d'où tourne le programme (exe dans <clé>/Linux/, <clé>/Windows/…), trouvée par son seul chemin, sans
/// parcourir les lecteurs : un lecteur réseau déconnecté ferait attendre.
pub(crate) fn cle_du_programme() -> Option<PathBuf> {
    // Sous Linux et macOS, le programme peut tourner depuis une copie temporaire (protection de la clé) : on part
    // du programme d'origine.
    #[cfg(unix)]
    let exe = crate::protection::cle::exe_d_origine();
    #[cfg(windows)]
    let exe = std::env::current_exe().ok().and_then(|e| e.canonicalize().ok());
    exe.iter()
        .flat_map(|e| e.ancestors().skip(1).take(2).map(PathBuf::from))
        .find(|d| est_une_cle(d))
}

fn est_une_cle(dossier: &std::path::Path) -> bool {
    dossier.join(TEMOIN_CLE).is_file()
}

/// Ce que la base garde sur les gens : (noms des réseaux, souvent celui du Wi-Fi ; noms et surnoms des appareils),
/// de la clé d'où tourne le programme et de la copie de cet ordinateur. Le journal des erreurs les retire de ce qu'il
/// écrit. Lus sans rien toucher : ni verrou, ni copie d'une base abîmée, ni message, ni lecteur parcouru.
pub fn noms_connus() -> (Vec<String>, Vec<String>) {
    // Pendant les tests, jamais les vraies données (la clé branchée sur l'ordinateur de développement).
    if cfg!(test) {
        return (Vec::new(), Vec::new());
    }
    let textes: Vec<String> = cle_du_programme()
        .map(|c| c.join("donnees"))
        .into_iter()
        .chain([dossier_local()])
        .filter_map(|d| std::fs::read_to_string(d.join("appareils.json")).ok())
        // Le carnet chiffré, s'il a été ouvert pendant ce lancement : ses noms aussi restent hors du journal.
        .chain(crate::chiffrement::carnet_ouvert())
        .collect();
    noms_des_bases(&textes)
}

fn noms_des_bases(textes: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut reseaux, mut appareils) = (Vec::new(), Vec::new());
    for texte in textes {
        let Ok(base) = serde_json::from_str::<Base>(texte.trim_start_matches('\u{feff}')) else {
            continue;
        };
        for fiche in base.fiches() {
            appareils.extend(fiche.nom.iter().chain(&fiche.surnom).cloned());
        }
        reseaux.extend(base.reseaux.into_values().filter_map(|r| r.nom));
    }
    // Montrés, ces noms sont rendus inoffensifs (`affichable`) : un message peut les contenir sous cette forme.
    for noms in [&mut reseaux, &mut appareils] {
        let mut montres: Vec<String> = noms
            .iter()
            .map(|n| affichable(n))
            .filter(|m| !noms.contains(m))
            .collect();
        montres.sort_unstable();
        montres.dedup();
        noms.extend(montres);
    }
    (reseaux, appareils)
}

/// La partition VANGUARD est en lecture seule sur les autres ordinateurs (attribut GPT respecté par Windows) :
/// on essaie d'y écrire plutôt que de deviner. Seulement sur une clé reconnue (`cle_usb`) : c'est une écriture.
pub(crate) fn modifiable(dossier: &std::path::Path) -> bool {
    let essai = dossier.join(format!(".vanguard-ecriture-{}", std::process::id()));
    let ok = std::fs::write(&essai, b"").is_ok();
    let _ = std::fs::remove_file(&essai);
    ok
}

/// Le dossier `donnees` de la clé USB, quand elle est branchée et modifiable (ordinateur du propriétaire).
pub fn donnees_de_la_cle() -> Option<PathBuf> {
    cle_usb().filter(|c| modifiable(c)).map(|c| c.join("donnees"))
}

/// Données (rapport, diagnostic) : sur la clé USB quand elle est branchée et modifiable, pour qu'elles voyagent avec
/// le programme ; sinon, ou quand les données de la clé sont protégées par une phrase (une clé perdue ne doit rien
/// livrer en clair), ou quand son carnet a changé hors de Vanguard (une clé qui a voyagé sans lui ne reçoit pas le
/// bilan de la maison), dans le dossier local de l'ordinateur.
pub fn dossier_donnees() -> PathBuf {
    donnees_de_la_cle()
        .filter(|d| !crate::chiffrement::protegee(d))
        .filter(|d| {
            d.parent()
                .is_some_and(|racine| crate::protection::cles_connues::verdict(racine, true).is_ok())
        })
        .unwrap_or_else(dossier_local)
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    match spec {
        "courants" | "common" => return Ok(PORTS_COURANTS.to_vec()),
        "tous" | "all" => return Ok((1..=u16::MAX).collect()),
        _ => {}
    }
    let mut ports = Vec::new();
    for morceau in spec.split(',') {
        let err = || trf!("port invalide : {morceau}", "invalid port: {morceau}");
        // Port 0 impossible, et une plage à l'envers (« 100-10 ») ne doit pas devenir silencieusement vide.
        let port = |t: &str| t.trim().parse::<u16>().ok().filter(|&p| p > 0).ok_or_else(err);
        match morceau.trim().split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    return Err(trf!(
                        "plage de ports à l'envers : {morceau}",
                        "reversed port range: {morceau}"
                    ));
                }
                ports.extend(a..=b);
            }
            None => ports.push(port(morceau)?),
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// Alertes d'une machine : celles de chaque port, plus celles qui dépendent d'une combinaison.
fn alertes(role: Option<&str>, ports: &[PortOuvert]) -> Vec<(Niveau, String)> {
    let ouverts: Vec<u16> = ports.iter().filter(|p| !p.udp).map(|p| p.port).collect();
    let a = |p| ouverts.contains(&p);
    let mut alertes: Vec<(Niveau, String)> = ports
        .iter()
        .filter(|p| p.niveau >= Niveau::Moyen)
        .map(|p| {
            (
                p.niveau,
                trf!("{} ({}) : {}", "{} ({}): {}", p.service, p.libelle(), p.conseil),
            )
        })
        .collect();
    if role == Some("passerelle") && a(80) && !a(443) {
        alertes.push((
            Niveau::Moyen,
            tr!(
                "Admin du routeur uniquement en HTTP : le mot de passe passe en clair.",
                "Router admin only over HTTP: the password travels in clear text."
            )
            .into(),
        ));
    }
    if a(139) && a(445) {
        alertes.push((
            Niveau::Moyen,
            tr!(
                "NetBIOS + SMB : vérifier que SMBv1 est désactivé.",
                "NetBIOS + SMB: make sure SMBv1 is disabled."
            )
            .into(),
        ));
    }
    for p in ports {
        if let Some(b) = &p.banniere {
            if b.starts_with("SSH-1.") {
                alertes.push((
                    Niveau::Critique,
                    trf!(
                        "Port {} : SSH version 1, cassé depuis 2001.",
                        "Port {}: SSH version 1, broken since 2001.",
                        p.port
                    ),
                ));
            }
            if b.contains("vsFTPd 2.3.4") {
                alertes.push((
                    Niveau::Critique,
                    tr!(
                        "vsFTPd 2.3.4 : version piégée (backdoor connue).",
                        "vsFTPd 2.3.4: trojaned version (known backdoor)."
                    )
                    .into(),
                ));
            }
        }
    }
    if ouverts.len() > 15 {
        alertes.push((
            Niveau::Moyen,
            trf!(
                "{} ports ouverts : surface d'attaque importante.",
                "{} open ports: large attack surface.",
                ouverts.len()
            ),
        ));
    }
    alertes.sort_by_key(|a| std::cmp::Reverse(a.0));
    alertes
}

/// Port dynamique (49152 et plus) tenu par un processus système de Windows.
fn rpc_dynamique_windows(port: u16, programme: Option<&str>) -> bool {
    port >= 49152
        && programme.is_some_and(|p| ["lsass", "wininit", "services", "svchost", "spoolsv", "System"].contains(&p))
}

/// Signe d'usurpation ARP : un autre appareil répond avec l'adresse MAC de la box. Celui qui se fait passer pour
/// la box voit passer tout le trafic du réseau (attaque « de l'homme du milieu »). Rend (IP de la box, MAC, IP qui
/// la partage). Un répéteur Wi-Fi qui relaie pour la box peut donner le même signe : c'est un « possible ».
pub fn usurpation_arp(r: &Rapport) -> Option<(Ipv4Addr, String, Ipv4Addr)> {
    let boite = r.hotes.iter().find(|h| h.role == Some("passerelle"))?;
    let mac = boite.mac.as_deref()?;
    let autre = r
        .hotes
        .iter()
        .find(|h| h.ip != boite.ip && h.mac.as_deref().is_some_and(|m| m.eq_ignore_ascii_case(mac)))?;
    Some((boite.ip, mac.to_string(), autre.ip))
}

/// Phrase d'alerte pour une usurpation ARP possible.
pub fn message_usurpation(boite: Ipv4Addr, mac: &str, autre: Ipv4Addr) -> String {
    trf!(
        "{autre} répond avec l'adresse MAC du routeur ({boite}, {mac}) : quelqu'un se fait peut-être passer pour lui pour intercepter votre trafic (usurpation ARP). Sauf répéteur Wi-Fi connu, débranchez cet appareil et redémarrez le routeur.",
        "{autre} answers with the router's MAC address ({boite}, {mac}): someone may be impersonating it to intercept your traffic (ARP spoofing). Unless it is a known Wi-Fi repeater, unplug that device and restart the router."
    )
}

/// Niveau le plus grave des ports d'un appareil (`None` : aucun port ouvert).
fn pire_niveau(h: &Hote) -> Option<Niveau> {
    h.ports.iter().map(|p| p.niveau).max()
}

/// Pastille de couleur d'un appareil : verte sans port ouvert, sinon de la couleur de son port le plus grave.
fn pastille(h: &Hote) -> String {
    match pire_niveau(h) {
        None => format!("{VERT}●{RESET}"),
        Some(n) => format!("{}●{RESET}", couleur(n)),
    }
}

/// Un message coupé à `largeur` colonnes après `debut` : la marque devant la première ligne, la suite alignée.
fn afficher_marque(debut: &str, marque: &str, texte: &str, largeur: usize) {
    for (i, ligne) in envelopper(texte, largeur).iter().enumerate() {
        println!("{debut}{} {ligne}", if i == 0 { marque } else { " " });
    }
}

fn nom_affiche(h: &Hote) -> String {
    let t = h.titre();
    if t.is_empty() {
        tr!("appareil inconnu", "unknown device").to_string()
    } else {
        t
    }
}

fn afficher(r: &Rapport) {
    let nom = r
        .nom_reseau
        .as_deref()
        .map(|n| trf!(" « {n} »", " “{n}”"))
        .unwrap_or_default();
    println!();
    cadre(
        &format!(
            "{ACCENT}{}{RESET}{GRAS}{nom}{RESET}",
            tr!("RÉSEAU LOCAL", "LOCAL NETWORK")
        ),
        &format!("{GRIS}{} · {:.1} s{RESET}", r.reseau, r.duree_s),
    );
    let compte = |n: Niveau| r.hotes.iter().flat_map(|h| &h.ports).filter(|p| p.niveau == n).count();
    let nouveaux = r.hotes.iter().filter(|h| h.nouvelle).count();
    trp!(
        "  {GRAS}Note du réseau{RESET}  {}  {}  {GRIS}(appareil le plus exposé){RESET}",
        "  {GRAS}Network grade{RESET}   {}  {}  {GRIS}(most exposed device){RESET}",
        etiquette_note(r.score_global),
        barre(r.score_global)
    );
    let mut resume = vec![
        accord(r.hotes.len(), tr!("appareil", "device"), tr!("appareils", "devices")),
        accord(
            r.hotes.iter().map(|h| h.ports.len()).sum::<usize>(),
            tr!("port ouvert", "open port"),
            tr!("ports ouverts", "open ports"),
        ),
    ];
    if nouveaux > 0 {
        resume.push(format!(
            "{}{}{RESET}",
            couleur(Niveau::Moyen),
            accord(nouveaux, tr!("nouveau", "new"), tr!("nouveaux", "new"))
        ));
    }
    for (n, un, plusieurs) in [
        (
            Niveau::Critique,
            tr!("critique", "critical"),
            tr!("critiques", "critical"),
        ),
        (Niveau::Eleve, tr!("élevé", "high"), tr!("élevés", "high")),
        (Niveau::Moyen, tr!("moyen", "medium"), tr!("moyens", "medium")),
    ] {
        if compte(n) > 0 {
            resume.push(format!("{}{}{RESET}", couleur(n), accord(compte(n), un, plusieurs)));
        }
    }
    println!("  {}", resume.join(&format!(" {GRIS}·{RESET} ")));
    if let Some((boite, mac, autre)) = usurpation_arp(r) {
        println!();
        let marque = format!("{}✖{RESET}", couleur(Niveau::Critique));
        afficher_marque("  ", &marque, &message_usurpation(boite, &mac, autre), LARGEUR - 6);
    }

    section(&trf!("APPAREILS ({})", "DEVICES ({})", r.hotes.len()));
    for h in &r.hotes {
        let etiquette = if h.nouvelle {
            format!(
                "{}{}{RESET}",
                couleur(Niveau::Moyen),
                ajuster(tr!("NOUVEAU", "NEW"), 10)
            )
        } else if let Some(role) = h.role {
            let court = match role {
                "passerelle" => tr!("routeur", "router"),
                "cette machine" => tr!("vous", "you"),
                autre => autre,
            };
            format!("{ACCENT}{}{RESET}", ajuster(&format!("[{court}]"), 10))
        } else {
            " ".repeat(10)
        };
        let ports = match h.ports.len() {
            0 => format!("{DISCRET}{}{RESET}", ajuster("—", 8)),
            1 => ajuster(tr!("1 port", "1 port"), 8),
            n => ajuster(&trf!("{n} ports", "{n} ports"), 8),
        };
        println!(
            "  {} {GRAS}{:<15}{RESET} {} {etiquette}{ports}{}",
            pastille(h),
            h.ip.to_string(),
            ajuster(&nom_affiche(h), 31),
            etiquette_note(h.score)
        );
    }

    // Détail des appareils qui demandent une action, le plus exposé d'abord.
    let mut a_regarder: Vec<&Hote> = r
        .hotes
        .iter()
        .filter(|h| pire_niveau(h).is_some_and(|n| n >= Niveau::Moyen) || h.nouvelle)
        .collect();
    a_regarder.sort_by_key(|h| h.score);
    if !a_regarder.is_empty() {
        section(tr!("À REGARDER", "WORTH A LOOK"));
        for h in a_regarder {
            let mac = h.mac.as_deref().map(|m| format!(" · {m}")).unwrap_or_default();
            let depuis = match (&h.premier_vu, h.nouvelle) {
                (Some(d), false) => trf!(" · connu depuis le {}", " · known since {}", date_fr(d)),
                (_, true) => tr!(" · vu pour la première fois", " · seen for the first time").to_string(),
                _ => String::new(),
            };
            println!(
                "\n  {} {GRAS}{}{RESET}  {}  {}",
                pastille(h),
                h.ip,
                nom_affiche(h),
                etiquette_note(h.score)
            );
            let infos = format!("{mac}{depuis}");
            if let Some(infos) = infos.strip_prefix(" · ") {
                println!("    {DISCRET}{infos}{RESET}");
            }
            for p in &h.ports {
                let nouveau = if p.nouveau && !h.nouvelle {
                    format!(" {}{}{RESET}", couleur(Niveau::Moyen), tr!("nouveau", "new"))
                } else {
                    String::new()
                };
                let programme = p
                    .programme
                    .as_deref()
                    .map(|n| format!("  {DISCRET}{n}{RESET}"))
                    .unwrap_or_default();
                println!(
                    "    {:>9}  {}{}{:<8}{RESET}{nouveau}{programme}",
                    p.libelle(),
                    ajuster(p.service, 16),
                    couleur(p.niveau),
                    p.niveau.libelle()
                );
            }
            for (n, msg) in &h.alertes {
                afficher_marque("    ", &format!("{}→{RESET}", couleur(*n)), msg, LARGEUR - 8);
            }
        }
    }

    // Ports sans danger particulier (diffusion, découverte) : une ligne par appareil suffit.
    let autres: Vec<&Hote> = r
        .hotes
        .iter()
        .filter(|h| pire_niveau(h) == Some(Niveau::Info) && !h.nouvelle)
        .collect();
    if !autres.is_empty() {
        section(tr!("AUTRES PORTS OUVERTS", "OTHER OPEN PORTS"));
        for h in autres {
            let ports: Vec<String> = h
                .ports
                .iter()
                .map(|p| format!("{}{} {}", p.port, if p.udp { "/udp" } else { "" }, p.service))
                .collect();
            afficher_aligne(
                &format!(
                    "  {} {:<15} {}  ",
                    pastille(h),
                    h.ip.to_string(),
                    ajuster(&nom_affiche(h), 26)
                ),
                &ports.join(", "),
                48,
                DISCRET,
            );
        }
    }

    let objets: Vec<objets::Appareil> = r
        .hotes
        .iter()
        .filter(|h| h.role != Some("cette machine"))
        .map(Hote::objet)
        .collect();
    objets::afficher(&objets, false);

    if let Some(e) = &r.empoisonnement {
        crate::reseau::empoisonnement::afficher(e, &r.hotes);
    }

    if !r.absents.is_empty() {
        section(&trf!("ABSENTS AUJOURD'HUI ({})", "ABSENT TODAY ({})", r.absents.len()));
        for a in &r.absents {
            let quand = a
                .dernier_vu
                .as_deref()
                .map(|d| trf!("vu le {}", "seen on {}", date_fr(d)))
                .unwrap_or_default();
            println!(
                "  {DISCRET}○ {:<15} {}  {quand}{RESET}",
                a.ip.to_string(),
                ajuster(&a.titre, 30)
            );
        }
    }
    // Ce que la maison montre à Internet, d'après ce scan du réseau local (l'UPnP n'est demandé à la box que pour
    // lui) : les ports que la box renvoie, son adresse, l'IPv6, ses services. Rien n'est demandé à Internet ici.
    if r.upnp.is_some() {
        let entree = crate::audit::exposition::Entree::du_scan(r);
        crate::audit::exposition::afficher_section(&crate::audit::exposition::constats(&entree));
    }
    // Chemins du menu depuis la 0.43 (groupe 5 « Réseau et Internet »), et la même chose en ligne de commande.
    println!();
    afficher_aligne(
        "  ",
        tr!(
            "Astuce : menu 5.3 pour nommer un appareil (vanguard nommer <ip> <surnom>), 5.1.2 pour scanner tous ses ports (vanguard reseau <ip> -p tous).",
            "Tip: menu 5.3 to name a device (vanguard name <ip> <nickname>), 5.1.2 to scan all its ports (vanguard network <ip> -p all)."
        ),
        2,
        DISCRET,
    );
}

/// Lance le scan réseau et retourne le rapport.
pub async fn executer(o: Options) -> Result<Rapport, String> {
    let bavard = !o.json && !o.silencieux;
    let debut = Instant::now();
    let reseau_local = o.cible.is_none();
    let local = scan::reseau_local();
    let moi = local.as_ref().map(|l| l.1);
    let cible = match o.cible {
        Some(c) => c,
        None => {
            local
                .ok_or(tr!(
                    "impossible de détecter le réseau local ; précisez une cible (ex. 192.168.1.0/24)",
                    "cannot detect the local network; give a target (e.g. 192.168.1.0/24)"
                ))?
                .0
        }
    };
    let ips = scan::parse_cible(&cible)?;
    let ports = parse_ports(&o.ports)?;
    let delai = Duration::from_millis(o.timeout);
    let gw = scan::passerelle();
    let parallele = scan::limite_connexions(o.parallele);
    // L'état de l'UPnP : la recherche de la box attend ses réponses 3 s, puis lui demande ses redirections. Demandé
    // dès maintenant, à côté, il est prêt à la fin du scan au lieu de l'allonger d'autant. Après les lectures qui
    // peuvent échouer : rien ne tourne pour rien.
    let upnp = reseau_local.then(|| tokio::task::spawn_blocking(crate::reseau::upnp::etat));
    // Les faux noms sur le réseau local, demandés à côté du scan : la sonde (deux essais d'environ 1,5 s) finit avant
    // le scan (8-10 s) et ne le ralentit pas. Seulement sur le réseau local (pas de cible précise ni de VPN seul) ;
    // rien d'Internet, donc VANGUARD_HORS_LIGNE ne l'empêche pas.
    let empoisonnement = moi.filter(|_| reseau_local).map(|ip| {
        let cidr = cible.clone();
        tokio::spawn(async move { crate::reseau::empoisonnement::sonder(ip, &cidr).await })
    });

    if bavard {
        tre!(
            "{GRAS}Scan réseau{RESET} — {cible} ({} adresse(s), {} ports chacune)",
            "{GRAS}Network scan{RESET} — {cible} ({} address(es), {} ports each)",
            ips.len(),
            ports.len()
        );
        tre!(
            "{GRIS}Découverte des appareils…{RESET}",
            "{GRIS}Discovering devices…{RESET}"
        );
    }
    let mut vivantes = if ips.len() == 1 {
        ips.clone()
    } else {
        scan::decouvrir(&ips, Duration::from_millis(o.timeout.min(400)), parallele).await
    };
    // Cette machine ne répond pas toujours à ses propres sondes sur l'IP du LAN.
    if let Some(m) = moi.filter(|m| ips.contains(m) && !vivantes.contains(m)) {
        vivantes.push(m);
        vivantes.sort();
    }

    if bavard {
        tre!(
            "{GRIS}{} appareil(s) trouvé(s). Scan des ports…{RESET}",
            "{GRIS}{} device(s) found. Scanning ports…{RESET}",
            vivantes.len()
        );
        // La seule demande qui porte un identifiant par défaut est dite (lecture seule ; choix de l'auteur).
        tre!(
            "{GRIS}SNMP : une demande « décris-toi », mot de passe de lecture d'usine « public ».{RESET}",
            "{GRIS}SNMP: one “describe yourself” request, factory read password “public”.{RESET}"
        );
        if ips.iter().all(std::net::Ipv4Addr::is_loopback) {
            tre!(
                "{GRIS}Note : 127.0.0.1 montre aussi les services réservés à cet ordinateur. Pour ce qui est vraiment exposé au réseau : vanguard machine.{RESET}",
                "{GRIS}Note: 127.0.0.1 also shows services reserved for this computer. For what is really exposed to the network: vanguard audit.{RESET}"
            );
        }
    }
    // Listes nommées, en français ou en anglais (comme parse_ports).
    let courants = matches!(o.ports.as_str(), "courants" | "common");
    let tous = matches!(o.ports.as_str(), "tous" | "all");
    // UDP : quelques services qui se taisent en TCP (SNMP, NetBIOS, UPnP…), avec les listes de ports par défaut.
    let avec_udp = courants || tous;
    // Ports TCP, ports UDP et noms des appareils en même temps : chacun attend ses propres réponses (délais fixes),
    // aucun ne dépend des autres. Mêmes sondes qu'une à une, le temps de la plus lente seulement.
    let udp = async {
        if avec_udp {
            scan::scanner_udp(&vivantes, PORTS_UDP, Duration::from_millis(o.timeout.clamp(800, 1500))).await
        } else {
            BTreeMap::new()
        }
    };
    let (mut resultats, mut resultats_udp, noms) = tokio::join!(
        scan::scanner_ports(&vivantes, &ports, delai, parallele),
        udp,
        join_all(vivantes.iter().map(|&ip| scan::nom_hote(ip)))
    );
    let arp = scan::table_arp();

    let (mut base, chemins, _verrou) = Base::charger();
    // Le carnet de ce réseau : reconnu à la MAC de la box, sinon à la plage d'adresses.
    let id_reseau = gw
        .and_then(|g| arp.get(&g).cloned())
        .unwrap_or_else(|| trf!("plage {cible}", "range {cible}"));
    let nom_reseau = scan::nom_wifi();
    let histo = base.reseaux.entry(id_reseau.clone()).or_default();
    for (cle, a) in std::mem::take(&mut base.appareils) {
        histo.appareils.entry(cle).or_insert(a);
    }
    let premier_scan = histo.appareils.is_empty();
    let udp_deja_vu = histo.udp;
    // Seul un scan du réseau entier sur les ports courants se compare aux précédents, et rien n'est « nouveau » au
    // premier scan d'un réseau.
    let scan_comparable = ips.len() > 1 && courants;
    let nouveautes = scan_comparable && !premier_scan;
    // Un port hors de la liste courante n'a jamais pu être vu par les scans précédents : pas de faux « nouveau ».
    let comparable = |port: u16| PORTS_COURANTS.contains(&port);
    // Une machine est reconnue par sa MAC (l'IP DHCP peut changer), sinon par son IP.
    let cle = |ip: Ipv4Addr, mac: &Option<String>| mac.clone().unwrap_or_else(|| ip.to_string());
    // Pour cette machine (ou 127.0.0.1), on sait quel programme tient chaque port.
    let programmes = crate::machine::programmes_en_ecoute();
    // Ce que Vanguard a appris des scans d'avant : un appareil connu qui paraît soudain tout fermé est souvent en
    // veille, lent à répondre. Ses ports déjà vus sont revérifiés avec plus de patience : quelques essais ajoutés,
    // aucun retiré.
    if scan_comparable {
        let a_revoir = silencieux_a_revoir(
            &resultats,
            &histo.appareils,
            |ip| cle(ip, &arp.get(&ip).cloned()),
            &ports,
        );
        if bavard && !a_revoir.is_empty() {
            tre!(
                "{GRIS}{} appareil(s) connu(s) silencieux : leurs ports déjà vus sont revérifiés plus patiemment (veille ?).{RESET}",
                "{GRIS}{} known device(s) silent: their ports seen before are checked again more patiently (asleep?).{RESET}",
                a_revoir.len()
            );
        }
        for (ip, connus) in a_revoir {
            let trouves = scan::scanner_ports(&[ip], &connus, Duration::from_millis(DELAI_PATIENT), parallele).await;
            if let Some(ouverts) = trouves.get(&ip).filter(|o| !o.is_empty()) {
                resultats.insert(ip, ouverts.clone());
            }
        }
    }

    // Scan approfondi d'un seul appareil : les versions de ses services par nmap, s'il est installé, sur les ports
    // déjà trouvés ouverts (rien d'autre n'est sondé).
    let mut versions: BTreeMap<Ipv4Addr, BTreeMap<u16, String>> = BTreeMap::new();
    if ips.len() == 1 && tous && nmap::disponible() {
        for (ip, ouverts) in &resultats {
            let ports: Vec<u16> = ouverts.iter().map(|(p, _)| *p).collect();
            if !ports.is_empty() && nmap::locale(*ip) {
                if bavard {
                    tre!(
                        "{GRIS}Versions des services de {ip} par nmap -sV ({} port(s))…{RESET}",
                        "{GRIS}Service versions of {ip} with nmap -sV ({} port(s))…{RESET}",
                        ports.len()
                    );
                }
                versions.insert(*ip, nmap::versions(*ip, &ports));
            }
        }
    }
    let mut hotes: Vec<Hote> =
        resultats
            .into_iter()
            .zip(noms)
            .map(|((ip, ouverts), nom)| {
                let mac = arp.get(&ip).cloned();
                let connu = histo.appareils.get(&cle(ip, &mac));
                let ports: Vec<PortOuvert> = ouverts
                .into_iter()
                .map(|(port, banniere)| {
                    // La version donnée par nmap passe devant ce que Vanguard a lu, plus court.
                    let banniere = versions.get(&ip).and_then(|v| v.get(&port)).cloned().or(banniere);
                    // Port non répertorié : on se fie à ce que le service annonce (SSH sur 2222, web sur 9999…).
                    let type_port = if info_port(port).service == crate::risk::inconnu() {
                        banniere.as_deref().and_then(identifier).unwrap_or(port)
                    } else {
                        port
                    };
                    let i = info_port(type_port);
                    let nouveau = nouveautes && comparable(port) && !connu.is_some_and(|c| c.ports.contains(&port));
                    let programme = (Some(ip) == moi || ip.is_loopback())
                        .then(|| programmes.get(&port).cloned())
                        .flatten();
                    // Ports dynamiques RPC ouverts par Windows lui-même (vu en test dans la VM : 49664 et suivants,
                    // tenus par lsass, wininit, services, svchost, spoolsv) : normaux, pas « inconnus moyens ».
                    if i.service == crate::risk::inconnu() && rpc_dynamique_windows(port, programme.as_deref()) {
                        let rpc = crate::risk::InfoPort {
                            service: tr!("RPC de Windows", "Windows RPC"),
                            niveau: Niveau::Info,
                            conseil: tr!(
                                "Port dynamique ouvert par Windows pour ses services : normal, filtré par le pare-feu.",
                                "Dynamic port opened by Windows for its services: normal, filtered by the firewall."
                            ),
                        };
                        return PortOuvert::decrit(port, &rpc, banniere, nouveau, programme, false);
                    }
                    PortOuvert::decrit(port, &i, banniere, nouveau, programme, false)
                })
                .chain(resultats_udp.remove(&ip).unwrap_or_default().into_iter().map(|(port, banniere)| {
                    let nouveau = nouveautes && udp_deja_vu && !connu.is_some_and(|c| c.ports_udp.contains(&port));
                    PortOuvert::decrit(port, &info_udp(port), banniere, nouveau, None, true)
                }))
                .collect();
                let role = if Some(ip) == gw {
                    Some("passerelle")
                } else if Some(ip) == moi {
                    Some("cette machine")
                } else {
                    None
                };
                let alertes = alertes(role, &ports);
                let score = 100u32.saturating_sub(alertes.iter().map(|(n, _)| n.penalite()).sum());
                Hote {
                    ip,
                    nom,
                    fabricant: mac.as_deref().and_then(scan::fabricant),
                    surnom: connu.and_then(|c| c.surnom.clone()),
                    premier_vu: connu.and_then(|c| c.premier_vu.clone()),
                    mac,
                    role,
                    nouvelle: nouveautes && connu.is_none(),
                    ports,
                    alertes,
                    score,
                }
            })
            .collect();
    hotes.sort_by_key(|h| h.ip);

    let mut absents = Vec::new();
    // On ne mémorise que les scans du réseau complet avec les ports par défaut, pour comparer ce qui est comparable.
    if scan_comparable {
        let presents: BTreeSet<String> = hotes.iter().map(|h| cle(h.ip, &h.mac)).collect();
        absents = histo
            .appareils
            .iter()
            .filter(|(k, _)| !presents.contains(*k))
            .map(|(_, a)| Absent {
                ip: a.ip,
                titre: a.titre(),
                dernier_vu: a.dernier_vu.clone(),
            })
            .collect();
        let jour = chrono::Local::now().format("%Y-%m-%d").to_string();
        for h in &hotes {
            let a = histo
                .appareils
                .entry(cle(h.ip, &h.mac))
                .or_insert_with(|| AppareilConnu {
                    ip: h.ip,
                    nom: None,
                    fabricant: None,
                    ports: BTreeSet::new(),
                    ports_udp: BTreeSet::new(),
                    surnom: None,
                    surnom_le: None,
                    premier_vu: Some(jour.clone()),
                    dernier_vu: None,
                    annonce: None,
                });
            a.ip = h.ip;
            a.nom = h.nom.clone().or(a.nom.take());
            a.fabricant.clone_from(&h.fabricant);
            a.ports.extend(h.ports.iter().filter(|p| !p.udp).map(|p| p.port));
            a.ports_udp.extend(h.ports.iter().filter(|p| p.udp).map(|p| p.port));
            a.premier_vu.get_or_insert_with(|| jour.clone());
            a.dernier_vu = Some(jour.clone());
            if let Some(annonce) = objets::annonces(&h.ports).into_iter().next() {
                a.annonce = Some(annonce);
            }
        }
        if nom_reseau.is_some() {
            histo.nom.clone_from(&nom_reseau);
        }
        histo.udp |= avec_udp;
        base.enregistrer(&chemins);
    }

    let score_global = hotes.iter().map(|h| h.score).min().unwrap_or(100);
    let rapport = Rapport {
        reseau: cible,
        nom_reseau: nom_reseau.or_else(|| base.reseaux.get(&id_reseau).and_then(|r| r.nom.clone())),
        absents,
        duree_s: debut.elapsed().as_secs_f64(),
        score_global,
        note: note(score_global),
        hotes,
        upnp: match upnp {
            Some(tache) => tache.await.ok(),
            None => None,
        },
        empoisonnement: match empoisonnement {
            Some(tache) => tache.await.ok(),
            // Réseau local scanné mais sonde non lancée (IP locale inconnue) : rien n'a pu être testé.
            None if reseau_local => Some(crate::reseau::empoisonnement::Rapport::SansReseauLocal),
            None => None,
        },
    };

    if o.json {
        println!("{}", serde_json::to_string_pretty(&rapport).unwrap_or_default());
    } else if bavard {
        afficher(&rapport);
    }
    Ok(rapport)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hote(ip: &str, mac: &str, role: Option<&'static str>) -> Hote {
        Hote {
            ip: ip.parse().unwrap(),
            nom: None,
            mac: Some(mac.into()),
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

    fn rapport(hotes: Vec<Hote>) -> Rapport {
        Rapport {
            reseau: "10.0.0.0/24".into(),
            nom_reseau: Some("Maison".into()),
            absents: Vec::new(),
            duree_s: 1.0,
            score_global: 100,
            note: "A",
            hotes,
            upnp: None,
            empoisonnement: None,
        }
    }

    #[test]
    fn ports_rpc_de_windows() {
        assert!(rpc_dynamique_windows(49664, Some("lsass")));
        assert!(!rpc_dynamique_windows(49664, Some("steam")));
        assert!(!rpc_dynamique_windows(8080, Some("svchost")));
        assert!(!rpc_dynamique_windows(49664, None));
    }

    #[test]
    fn usurpation_de_la_box() {
        let sain = rapport(vec![
            hote("10.0.0.1", "f8:79:0a:0d:03:a2", Some("passerelle")),
            hote("10.0.0.50", "aa:bb:cc:dd:ee:ff", None),
        ]);
        assert!(usurpation_arp(&sain).is_none());
        let usurpe = rapport(vec![
            hote("10.0.0.1", "aa:bb:cc:dd:ee:ff", Some("passerelle")),
            hote("10.0.0.50", "AA:BB:CC:DD:EE:FF", None),
        ]);
        let (boite, _, autre) = usurpation_arp(&usurpe).unwrap();
        assert_eq!(
            (boite.to_string(), autre.to_string()),
            ("10.0.0.1".into(), "10.0.0.50".into())
        );
    }

    #[test]
    fn listes_de_ports() {
        assert_eq!(parse_ports("22, 80,8000-8002").unwrap(), vec![22, 80, 8000, 8001, 8002]);
        assert_eq!(parse_ports("tous").unwrap().len(), 65535);
        assert_eq!(parse_ports("courants").unwrap(), PORTS_COURANTS);
        assert!(parse_ports("80,abc").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("100-10").is_err());
    }

    #[test]
    fn absent_dans_la_langue_du_jour() {
        // Noté par un scan en anglais, montré dans un écran en français.
        let note = r#"{"ip":"10.0.0.4","nom":null,"fabricant":"random MAC (phone/tablet?)","ports":[]}"#;
        let a: AppareilConnu = serde_json::from_str(note).unwrap();
        assert_eq!(a.titre(), "MAC aléatoire (téléphone/tablette ?)");
        assert_eq!(scan::fabricant_traduit("Intel Corporate"), "Intel Corporate");
    }

    #[test]
    fn appareils_en_veille_revus() {
        let ip = |d: u8| Ipv4Addr::new(10, 0, 0, d);
        let connu = |ports: &[u16]| AppareilConnu {
            ip: ip(1),
            nom: None,
            fabricant: None,
            ports: ports.iter().copied().collect(),
            ports_udp: BTreeSet::new(),
            surnom: None,
            surnom_le: None,
            premier_vu: None,
            dernier_vu: None,
            annonce: None,
        };
        let resultats = BTreeMap::from([
            (ip(2), vec![]),           // connu, ports déjà vus, muet : à revoir
            (ip(3), vec![(80, None)]), // répond : rien à revoir
            (ip(4), vec![]),           // jamais vu de port ouvert : rien à revoir
            (ip(5), vec![]),           // inconnu de la base
        ]);
        let connus = BTreeMap::from([
            ("aa".to_string(), connu(&[22, 8009, 60000])),
            ("bb".to_string(), connu(&[80])),
            ("cc".to_string(), connu(&[])),
        ]);
        let cle = |i: Ipv4Addr| match i.octets()[3] {
            2 => "aa".to_string(),
            3 => "bb".to_string(),
            4 => "cc".to_string(),
            _ => i.to_string(),
        };
        // 60000 n'est pas dans les ports de ce scan : pas revérifié.
        assert_eq!(
            silencieux_a_revoir(&resultats, &connus, cle, &[22, 80, 8009]),
            [(ip(2), vec![22, 8009])]
        );
    }

    #[test]
    fn ancienne_base_toujours_lisible() {
        // Format de la v0.1 à la v0.3 : un seul carnet, sans surnom ni dates.
        let ancien = r#"{"appareils":{"c4:34:6b:12:34:56":{"ip":"10.0.0.138","nom":null,"fabricant":"Hewlett Packard","ports":[135,445]}}}"#;
        let base: Base = serde_json::from_str(ancien).unwrap();
        let a = &base.appareils["c4:34:6b:12:34:56"];
        assert_eq!(a.ports.len(), 2);
        assert!(a.surnom.is_none() && a.premier_vu.is_none());
        // Une fois migré, l'ancien champ n'est plus écrit.
        let migre = Base {
            reseaux: BTreeMap::from([(
                "box".into(),
                ReseauConnu {
                    nom: None,
                    appareils: base.appareils,
                    udp: false,
                },
            )]),
            appareils: BTreeMap::new(),
        };
        assert!(
            !serde_json::to_value(&migre)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("appareils")
        );
    }

    #[test]
    fn base_avec_bom_ou_abimee() {
        let dossier = std::env::temp_dir().join(format!("vanguard-base-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).unwrap();
        let p = dossier.join("appareils.json");
        std::fs::write(
            &p,
            "\u{feff}{\"reseaux\":{\"box\":{\"nom\":\"Salon\",\"appareils\":{}}}}",
        )
        .unwrap();
        assert_eq!(Base::lire(&p).reseaux["box"].nom.as_deref(), Some("Salon"));
        std::fs::write(&p, "{ abîmé").unwrap();
        assert!(Base::lire(&p).reseaux.is_empty());
        // La base abîmée est gardée de côté, pas perdue.
        let copies = std::fs::read_dir(&dossier)
            .unwrap()
            .filter(|f| f.as_ref().unwrap().file_name().to_string_lossy().contains("illisible"))
            .count();
        assert_eq!(copies, 1);
        std::fs::remove_dir_all(&dossier).unwrap();
    }

    #[test]
    fn noms_gardes_par_la_base() {
        // Le journal des erreurs les retire de ce qu'il écrit : réseaux, appareils et surnoms, des deux formats.
        let base = r#"{"reseaux":{"box":{"nom":"Chez Max","appareils":{"3c:22:fb:65:43:21":{"ip":"192.168.1.20","nom":"iPhone-de-Zoe","fabricant":"Apple","ports":[],"surnom":"tablette de Zoé"}}}}}"#;
        let ancienne = r#"{"appareils":{"c4:34:6b:12:34:56":{"ip":"10.0.0.138","nom":"imprimante-salon","fabricant":"Hewlett Packard","ports":[631]}}}"#;
        let (reseaux, appareils) =
            noms_des_bases(&[format!("\u{feff}{base}"), ancienne.to_string(), "abîmée".to_string()]);
        assert_eq!(reseaux, ["Chez Max"]);
        assert_eq!(appareils, ["iPhone-de-Zoe", "tablette de Zoé", "imprimante-salon"]);
        assert_eq!(
            noms_connus(),
            (Vec::new(), Vec::new()),
            "jamais la vraie base pendant un test"
        );
    }

    /// Clé protégée par une phrase : le carnet s'ouvre avec la clé de données gardée ici (comme chez le propriétaire),
    /// s'enregistre chiffré sur la clé et en clair sur cet ordinateur, et jamais en clair sur la clé.
    #[test]
    fn carnet_chiffre_lu_et_enregistre() {
        let d = std::env::temp_dir().join(format!("vanguard-carnet-chiffre-{}", std::process::id()));
        let donnees = d.join("donnees");
        std::fs::create_dir_all(&donnees).unwrap();
        let carnet = r#"{"reseaux":{"3c:22:fb:00:00:01":{"nom":"Salon","appareils":{}}}}"#;
        std::fs::write(donnees.join("appareils.json"), carnet).unwrap();
        let cle_locale = dossier_local().join("cle-donnees");
        let phrase = "phrase de test assez longue";
        crate::chiffrement::proteger_dans(&donnees, &cle_locale, &d.join("local"), phrase, (64, 1, 1)).unwrap();
        let mut base = Base::ouvrir_carnet(&donnees).unwrap();
        assert_eq!(base.reseaux["3c:22:fb:00:00:01"].nom.as_deref(), Some("Salon"));
        base.reseaux.get_mut("3c:22:fb:00:00:01").unwrap().nom = Some("Cuisine".into());
        let local = d.join("local").join("appareils.json");
        base.enregistrer(&[donnees.join("appareils.json"), local.clone()]);
        assert!(!donnees.join("appareils.json").exists());
        assert!(std::fs::read_to_string(&local).unwrap().contains("Cuisine"));
        let relue = Base::ouvrir_carnet(&donnees).unwrap();
        assert_eq!(relue.reseaux["3c:22:fb:00:00:01"].nom.as_deref(), Some("Cuisine"));
        // Les noms du carnet ouvert restent connus du journal des erreurs.
        assert!(crate::chiffrement::carnet_ouvert().is_some_and(|t| t.contains("Cuisine")));
        let _ = std::fs::remove_file(&cle_locale);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// La base voyage sur la clé : écrite ailleurs (autre ordinateur, copie à la main), ses textes arrivent inoffensifs
    /// à la lecture. Le journal des erreurs, lui, reconnaît les noms sous leurs deux formes.
    #[test]
    fn base_piegee_lue_inoffensive() {
        let dossier = std::env::temp_dir().join(format!("vanguard-base-piegee-{}", std::process::id()));
        let fichier = dossier.join("appareils.json");
        let piege = "Salon\u{1b}]52;c;eA==\u{7}\u{1b}[2K\r\u{202e}";
        let vu = "Salon�]52;c;eA==��[2K��";
        let base = serde_json::json!({
            "reseaux": {"3c:22:fb:00:00:01": {"nom": piege, "appareils": {"3c:22:fb:00:00:02": {
                "ip": "192.168.1.20", "nom": piege, "fabricant": piege, "ports": [], "surnom": piege,
                "surnom_le": "2026-10-18 10:00:00", "premier_vu": piege}}}},
            "appareils": {"c4:34:6b:00:00:03": {"ip": "10.0.0.138", "nom": null, "fabricant": null, "ports": [631],
                "surnom": piege}}
        })
        .to_string();
        ecrire_atomique(&fichier, &base).unwrap();
        let lue = Base::lire(&fichier);
        std::fs::remove_dir_all(&dossier).unwrap();
        let reseau = &lue.reseaux["3c:22:fb:00:00:01"];
        assert_eq!(reseau.nom.as_deref(), Some(vu));
        let a = &reseau.appareils["3c:22:fb:00:00:02"];
        for t in [&a.nom, &a.fabricant, &a.surnom, &a.premier_vu] {
            assert_eq!(t.as_deref(), Some(vu));
        }
        assert_eq!(a.surnom_le.as_deref(), Some("2026-10-18 10:00:00"));
        assert_eq!(lue.appareils["c4:34:6b:00:00:03"].surnom.as_deref(), Some(vu));
        let (reseaux, appareils) = noms_des_bases(&[base]);
        assert_eq!(reseaux, [piege, vu]);
        assert_eq!(appareils, [piege, piege, piege, vu]);
    }

    fn fausse_cle(nom: &str, jeton: Option<&str>) -> PathBuf {
        let cle = std::env::temp_dir().join(format!("vanguard-fausse-cle-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cle);
        std::fs::create_dir_all(cle.join("donnees")).unwrap();
        std::fs::write(cle.join(TEMOIN_CLE), "").unwrap();
        if let Some(j) = jeton {
            std::fs::write(cle.join(crate::protection::cles_connues::JETON), j).unwrap();
        }
        cle
    }

    /// Parmi les volumes montés, seule une clé au jeton connu d'ici est la clé : témoin seul ou jeton inconnu,
    /// rien ; deux connues, toujours la première dans l'ordre des chemins.
    #[test]
    fn cle_reconnue_au_jeton_connu() {
        let (a, b) = ("0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210");
        let sans = fausse_cle("sans-jeton", None);
        let inconnue = fausse_cle("inconnue", Some("ffffffffffffffffffffffffffffffff"));
        let connue_b = fausse_cle("connue-b", Some(b));
        let connue_a = fausse_cle("connue-a", Some(a));
        let pas_une_cle = fausse_cle("pas-une-cle", Some(a));
        std::fs::remove_file(pas_une_cle.join(TEMOIN_CLE)).unwrap();
        let connues: std::collections::BTreeSet<String> = [a.to_string(), b.to_string()].into();
        let volumes = vec![
            pas_une_cle.clone(),
            sans.clone(),
            inconnue.clone(),
            connue_b.clone(),
            connue_a.clone(),
        ];
        assert_eq!(cle_parmi(volumes.clone(), &connues), Some(connue_a.clone()));
        let seule_b: std::collections::BTreeSet<String> = [b.to_string()].into();
        assert_eq!(cle_parmi(volumes.clone(), &seule_b), Some(connue_b.clone()));
        assert_eq!(cle_parmi(volumes, &std::collections::BTreeSet::new()), None);
        assert_eq!(cle_parmi(vec![sans.clone(), inconnue.clone()], &connues), None);
        for d in [sans, inconnue, connue_b, connue_a, pas_une_cle] {
            let _ = std::fs::remove_dir_all(d);
        }
    }

    /// Le carnet d'une clé connue est fusionné et réécrit tant qu'il est celui que Vanguard a écrit en dernier ;
    /// changé hors de Vanguard, il n'est ni lu ni réécrit, jusqu'à ce qu'il soit accepté.
    #[test]
    fn carnet_de_la_cle_modifie_ni_lu_ni_reecrit() {
        let cle = fausse_cle("carnet-modifie", Some("0123456789abcdef0123456789abcdef"));
        let local = std::env::temp_dir().join(format!("vanguard-local-carnet-modifie-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&local);
        std::fs::create_dir_all(&local).unwrap();
        let carnet_cle = cle.join("donnees").join("appareils.json");
        let salon = r#"{"reseaux":{"3c:22:fb:00:00:01":{"nom":"Salon","appareils":{}}}}"#;
        std::fs::write(&carnet_cle, salon).unwrap();
        assert!(crate::protection::cles_connues::noter(&cle));
        // Clé lancée ou connue, intacte : son carnet est pris, et réécrit sur la clé.
        let (base, chemins) = Base::charger_depuis(Some((cle.clone(), true)), &local);
        assert!(base.reseaux.contains_key("3c:22:fb:00:00:01"));
        assert_eq!(chemins[0], carnet_cle);
        base.enregistrer(&chemins);
        // Modifié hors de Vanguard : un appareil « connu » y est ajouté. Ni lu ni réécrit.
        let piege = r#"{"reseaux":{"3c:22:fb:00:00:01":{"nom":"Salon","appareils":{"3c:22:fb:00:00:99":{"ip":"10.0.0.99","nom":null,"fabricant":null,"ports":[],"surnom":"imprimante"}}}}}"#;
        std::fs::write(&carnet_cle, piege).unwrap();
        let (base, chemins) = Base::charger_depuis(Some((cle.clone(), true)), &local);
        assert!(base.fiches().all(|a| a.surnom.as_deref() != Some("imprimante")));
        assert_eq!(chemins[0], local.join("appareils.json"));
        base.enregistrer(&chemins);
        assert_eq!(std::fs::read_to_string(&carnet_cle).unwrap(), piege);
        // Sur un ordinateur où la clé est en lecture seule, l'empreinte ne compte pas : le carnet sert.
        let (base, chemins) = Base::charger_depuis(Some((cle.clone(), false)), &local);
        assert!(base.fiches().any(|a| a.surnom.as_deref() == Some("imprimante")));
        assert_eq!(chemins[0], local.join("appareils.json"));
        // Accepté (copie restaurée) : lu de nouveau.
        assert!(crate::protection::cles_connues::noter(&cle));
        let (_, chemins) = Base::charger_depuis(Some((cle.clone(), true)), &local);
        assert_eq!(chemins[0], carnet_cle);
        let _ = std::fs::remove_dir_all(&cle);
        let _ = std::fs::remove_dir_all(&local);
    }

    /// Une clé connue dont le carnet était chiffré revient sans enveloppe, avec un carnet en clair : il n'est ni
    /// lu ni réécrit, même en lecture seule.
    #[test]
    fn enveloppe_retiree_carnet_en_clair_refuse() {
        let cle = fausse_cle("enveloppe-retiree", Some("fedcba9876543210fedcba9876543210"));
        let donnees = cle.join("donnees");
        let local = std::env::temp_dir().join(format!("vanguard-local-enveloppe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&local);
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(donnees.join("appareils.json"), r#"{"reseaux":{}}"#).unwrap();
        let cle_locale = dossier_local().join("cle-donnees-enveloppe-retiree");
        crate::chiffrement::proteger_dans(&donnees, &cle_locale, &local, "phrase de test assez longue", (64, 1, 1))
            .unwrap();
        assert!(crate::protection::cles_connues::noter(&cle));
        std::fs::remove_file(donnees.join(crate::chiffrement::ENVELOPPE)).unwrap();
        let clair = r#"{"reseaux":{"3c:22:fb:00:00:01":{"nom":"Salon","appareils":{}}}}"#;
        std::fs::write(donnees.join("appareils.json"), clair).unwrap();
        for modifiable in [true, false] {
            let (base, chemins) = Base::charger_depuis(Some((cle.clone(), modifiable)), &local);
            assert!(base.reseaux.is_empty());
            assert_eq!(chemins[0], local.join("appareils.json"));
        }
        assert_eq!(std::fs::read_to_string(donnees.join("appareils.json")).unwrap(), clair);
        let _ = std::fs::remove_file(&cle_locale);
        let _ = std::fs::remove_dir_all(&cle);
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn fusion_cle_et_copie_locale() {
        let fiche = |ports: &[u16], premier: &str, dernier: &str, surnom: Option<&str>, ip: [u8; 4]| AppareilConnu {
            ip: Ipv4Addr::from(ip),
            nom: None,
            fabricant: None,
            ports: ports.iter().copied().collect(),
            ports_udp: BTreeSet::new(),
            surnom: surnom.map(str::to_string),
            surnom_le: None,
            premier_vu: Some(premier.into()),
            dernier_vu: Some(dernier.into()),
            annonce: None,
        };
        let mut cle = fiche(
            &[80],
            "2026-10-16",
            "2026-10-16",
            Some("imprimante HP"),
            [10, 0, 0, 138],
        );
        cle.fusionner(fiche(&[445], "2026-09-01", "2026-10-20", None, [10, 0, 0, 140]));
        assert_eq!(cle.ports.len(), 2);
        assert_eq!(cle.premier_vu.as_deref(), Some("2026-09-01"));
        assert_eq!(cle.dernier_vu.as_deref(), Some("2026-10-20"));
        assert_eq!(cle.ip, Ipv4Addr::new(10, 0, 0, 140)); // l'IP la plus récente
        assert_eq!(cle.surnom.as_deref(), Some("imprimante HP"));
        assert_eq!(date_fr("2026-10-16"), "16/10/2026");

        // Surnom changé sans la clé (copie locale plus récente) : il remplace celui de la clé.
        let date = |mut f: AppareilConnu, le: &str| {
            f.surnom_le = Some(le.into());
            f
        };
        let mut cle = date(
            fiche(&[], "2026-10-16", "2026-10-16", Some("ancien"), [10, 0, 0, 5]),
            "2026-10-16 10:00:00",
        );
        cle.fusionner(date(
            fiche(&[], "2026-10-16", "2026-10-16", Some("nouveau"), [10, 0, 0, 5]),
            "2026-10-17 09:00:00",
        ));
        assert_eq!(cle.surnom.as_deref(), Some("nouveau"));
        // Surnom retiré plus récemment : le retrait gagne aussi.
        cle.fusionner(date(
            fiche(&[], "2026-10-16", "2026-10-16", None, [10, 0, 0, 5]),
            "2026-10-17 12:00:00",
        ));
        assert_eq!(cle.surnom, None);
        // Une fiche plus ancienne ou sans date ne l'écrase pas.
        cle.fusionner(fiche(&[], "2026-10-16", "2026-10-16", Some("vieux"), [10, 0, 0, 5]));
        assert_eq!(cle.surnom, None);
    }

    #[test]
    fn alertes_croisees() {
        let port = |p: u16| {
            let i = info_port(p);
            PortOuvert {
                port: p,
                service: i.service,
                niveau: i.niveau,
                banniere: None,
                conseil: i.conseil,
                nouveau: false,
                programme: None,
                udp: false,
            }
        };
        let routeur = alertes(Some("passerelle"), &[port(80)]);
        assert!(routeur.iter().any(|(_, m)| m.contains("routeur")));
        let windows = alertes(None, &[port(139), port(445)]);
        assert!(windows.iter().any(|(_, m)| m.contains("SMBv1")));
        // La plus grave en premier.
        assert!(windows.windows(2).all(|w| w[0].0 >= w[1].0));
    }
}
