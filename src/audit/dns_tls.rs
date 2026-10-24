//! Domaine DNS et TLS de l'audit du réseau : le DNS que la box distribue à toute la maison (bail DHCP) comparé à
//! celui que cet ordinateur utilise, le DNS chiffré (DoT, DoH, et ce que la box ou le fournisseur en proposent par
//! DDR), les réponses du résolveur comparées à celles de deux résolveurs publics sur des noms dont l'adresse ne
//! change jamais, la validation DNSSEC, le certificat qu'un site connu présente à cet ordinateur (HTTPS intercepté
//! en acte), les exceptions de certificat que Firefox a gardées, les racines poussées dans les navigateurs.
//! Post-quantique, en lecture seule : la box propose-t-elle un échange de clés post-quantique sur son
//! administration (SSH, HTTPS), et quelque chose sur le chemin vers Internet le retire-t-il (`tls_pq`, `ssh_kex`) ?
//! Observer seulement : les seules sorties sont des questions DNS vers le résolveur de la machine, celui de la box
//! et deux résolveurs publics, une demande HTTPS et une sonde TLS vers le même site de référence, et, sur la box
//! seule, une connexion à chacun des ports d'administration que le scan a trouvés ouverts (fermée aussitôt, sans
//! authentification). Rien vers les autres appareils du réseau.
//! Ce qui ne se lit pas, ou pas hors ligne, est dit « non vérifié », jamais compté sain.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::bail::{self, Bail, Configuration};
use super::dns_client::{self, Donnees, Genre, Reponse};
use super::tls_pq::ReponsePq;
use crate::machine::certificats::{Famille, attribut, famille, tlv};
use crate::machine::dns::service_public;
use crate::machine::{Constat, alerte, impossible, ok, sans_objet};
use crate::modele::{Absence, Echec};
use crate::risk::Niveau;
use crate::ui::affichable;
use crate::{tr, trf};

const CAT_DNS: &str = "DNS";
const CAT_TLS: &str = "Certificats";

/// Résolveurs publics de référence ; deux sont interrogés, jamais celui que la machine utilise déjà.
const PUBLICS: [(&str, Ipv4Addr); 3] = [
    ("Cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
    ("Quad9", Ipv4Addr::new(9, 9, 9, 9)),
    ("Google", Ipv4Addr::new(8, 8, 8, 8)),
];

/// Noms dont l'adresse est fixe et mondiale (jamais un CDN) : les résolveurs publics eux-mêmes.
const NOMS_STABLES: [(&str, [Ipv4Addr; 2]); 3] = [
    (
        "one.one.one.one",
        [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
    ),
    ("dns.google", [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)]),
    (
        "dns.quad9.net",
        [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
    ),
];
/// Un nom signé DNSSEC, et un nom dont la signature est cassée exprès (zone de test publique).
const NOM_SIGNE: &str = "internetsociety.org";
const NOM_CASSE: &str = "dnssec-failed.org";
/// Un nom tiré au hasard dans la zone cassée, et un nom qui n'existe pas (tiré au hasard sous .com) : des noms fixes
/// et connus se reconnaissent, et un résolveur hostile pouvait répondre juste pour eux seuls (la bonne adresse, le
/// refus attendu de la signature cassée) puis réécrire tout le reste. Un nom inventé à chaque audit ne se prépare pas.
const ZONE_INEXISTANTS: &str = "com";

/// Une étiquette DNS de 20 lettres tirée au hasard.
fn etiquette_au_hasard() -> String {
    let mut octets = [0u8; 20];
    if getrandom::fill(&mut octets).is_err() {
        // Sans hasard du système : l'horloge, mêlée (rien de secret ici, seulement imprévisible d'avance).
        let h = crate::reseau::nat::hasard().to_le_bytes();
        for (i, o) in octets.iter_mut().enumerate() {
            *o = h[i % 8].rotate_left(u32::try_from(i).unwrap_or(0));
        }
    }
    octets.iter().map(|o| char::from(b'a' + o % 26)).collect()
}
/// La question de DDR (RFC 9462) : le résolveur annonce-t-il du DNS chiffré ?
const NOM_DDR: &str = "_dns.resolver.arpa";
/// Site de référence pour le certificat présenté (une page de diagnostic sans contenu personnel).
const SITE_TLS: &str = "https://1.1.1.1/cdn-cgi/trace";
const DELAI_TLS: Duration = Duration::from_secs(12);
/// Le site de référence pour la sonde post-quantique : le même que ci-dessus (Cloudflare accepte X25519MLKEM768).
/// Un second site, d'un autre opérateur, départagerait le site et le chemin ; il serait contacté en plus : pas sans
/// l'accord de l'auteur. Sans lui, un refus n'est conclu que si l'interception se voit déjà au certificat.
const SITE_PQ: (Ipv4Addr, u16) = (Ipv4Addr::new(1, 1, 1, 1), 443);
const DELAI_PQ: Duration = Duration::from_secs(8);
/// Les ports d'administration de la box sondés, quand le scan les a trouvés ouverts.
const PORT_SSH: u16 = 22;
const PORTS_HTTPS: [u16; 2] = [443, 8443];
const DELAI_BOX: Duration = Duration::from_secs(5);
/// Catégorie des constats post-quantiques, regroupés au rapport.
const CAT_PQ: &str = "Post-quantique";

/// Autorités publiques dont un émetteur de certificat porte le nom : hors de cette liste, l'émetteur accepté par le
/// système est une autorité ajoutée localement, donc une interception.
const AUTORITES_PUBLIQUES: &[&str] = &[
    "digicert",
    "let's encrypt",
    "lets encrypt",
    "google trust services",
    "sectigo",
    "comodo",
    "usertrust",
    "globalsign",
    "amazon",
    "cloudflare",
    "microsoft",
    "entrust",
    "identrust",
    "godaddy",
    "go daddy",
    "starfield",
    "ssl.com",
    "zerossl",
    "buypass",
    "actalis",
    "certum",
    "harica",
    "swisssign",
    "telia",
    "geotrust",
    "thawte",
    "rapidssl",
    "apple",
    "ISRG",
];

/// Le rôle d'un résolveur interrogé.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Celui que cet ordinateur utilise.
    Utilise,
    /// Celui que la box distribue par DHCP (quand il diffère).
    Bail,
    Public(&'static str),
}

/// Ce qu'un résolveur a répondu aux noms stables.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mesure {
    pub role: Role,
    pub serveur: IpAddr,
    /// Par nom stable : la réponse, ou rien (muet).
    pub reponses: Vec<(&'static str, Option<Reponse>)>,
    /// La réponse pour un nom inventé à l'instant, qui n'existe pas : une adresse au lieu de « ce nom n'existe
    /// pas » trahit un résolveur qui réécrit les noms inexistants.
    pub inexistant: Option<Reponse>,
}

/// L'épreuve DNSSEC d'un résolveur : sa réponse (avec le bit DO) au nom signé et au nom à signature cassée.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Dnssec {
    pub role: Role,
    pub serveur: IpAddr,
    pub signe: Option<Reponse>,
    pub casse: Option<Reponse>,
    /// Un nom tiré au hasard dans la zone cassée : un résolveur qui valide le refuse aussi (SERVFAIL).
    pub casse_hasard: Option<Reponse>,
}

/// La réponse d'un résolveur à la question de DDR.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ddr {
    pub role: Role,
    pub serveur: IpAddr,
    pub reponse: Option<Reponse>,
}

/// Le certificat présenté par le site de référence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Tls {
    /// Reçu et accepté par le vérificateur du système : l'émetteur de la feuille pour l'écran (son organisation,
    /// sinon son nom), tous ses noms réunis pour le juger, le sujet, le code de la réponse.
    Presente {
        emetteur: Option<String>,
        noms: Option<String>,
        sujet: Option<String>,
        code: u16,
    },
    /// Refusé par le vérificateur du système : pourquoi.
    Refuse(String),
    /// Pas de réponse.
    Muet,
    /// Pas demandé (hors ligne).
    NonDemande,
}

/// Une exception de certificat gardée par un navigateur de la famille Firefox (cert_override.txt).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Exception {
    pub navigateur: String,
    pub hote: String,
    pub port: u16,
    /// M = nom qui ne correspond pas, U = autorité inconnue, T = date dépassée.
    pub drapeaux: String,
}

/// Des certificats poussés dans Firefox par une politique (policies.json : Certificates › Install).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Politique {
    pub fichier: String,
    pub certificats: Vec<String>,
    pub racines_du_systeme: Option<bool>,
}

/// Le DNS que cet ordinateur utilise (`machine::dns::actuel`).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Utilise {
    /// (adresse, réglée à la main).
    pub serveurs: Vec<(IpAddr, bool)>,
    pub chiffre: Option<bool>,
    pub resolveur_local: Option<&'static str>,
}

/// Tout ce que le domaine a lu et mesuré ; `constats` juge sans rien relire (testable sur des valeurs inventées).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Entree {
    /// Hors ligne demandé (VANGUARD_HORS_LIGNE) : rien n'a été demandé au réseau.
    pub hors_ligne: bool,
    pub baux: Result<Vec<Bail>, String>,
    /// `None` : configuration DNS illisible.
    pub utilise: Option<Utilise>,
    pub configuration: Configuration,
    pub passerelle: Option<IpAddr>,
    pub mesures: Vec<Mesure>,
    /// Les résolveurs dont la mesure s'est interrompue (erreur interne dans son fil) : non vérifiés, pour cette raison.
    pub interrompues: Vec<(Role, IpAddr)>,
    pub dnssec: Vec<Dnssec>,
    pub ddr: Vec<Ddr>,
    /// DNS chiffré des navigateurs : (navigateur, activé / coupé / `None` = par défaut).
    pub navigateurs_doh: Vec<(String, Option<bool>)>,
    pub tls: Tls,
    pub exceptions: Vec<Exception>,
    /// Profils de la famille Firefox trouvés (0 : pas de Firefox).
    pub profils_firefox: usize,
    pub politiques: Vec<Politique>,
    /// La sonde post-quantique vers le site de référence ; `None` : pas envoyée (hors ligne).
    pub pq_site: Option<Result<ReponsePq, Echec>>,
    /// Un proxy du système est réglé (la sonde, en direct, ne suit alors pas le chemin des navigateurs) ; `None` :
    /// réglage illisible.
    pub proxy: Option<bool>,
    /// L'administration de la box : par service sondé (« SSH 22 », « HTTPS 443 »), un échange post-quantique
    /// proposé ou non ; `None` : la box n'est pas dans le scan.
    pub routeur: Option<Vec<(String, Result<bool, Echec>)>>,
}

impl Entree {
    /// Une entrée vide : rien lu, rien mesuré (hors ligne complet).
    #[cfg(test)]
    pub fn vide(hors_ligne: bool) -> Self {
        Entree {
            hors_ligne,
            baux: Err(String::new()),
            utilise: None,
            configuration: Configuration::default(),
            passerelle: None,
            mesures: Vec::new(),
            interrompues: Vec::new(),
            dnssec: Vec::new(),
            ddr: Vec::new(),
            navigateurs_doh: Vec::new(),
            tls: Tls::NonDemande,
            exceptions: Vec::new(),
            profils_firefox: 0,
            politiques: Vec::new(),
            pq_site: None,
            proxy: Some(false),
            routeur: None,
        }
    }
}

/// Une adresse du réseau local (box, Pi-hole, NAS, résolveur local), pas d'Internet.
fn du_reseau(ip: IpAddr) -> bool {
    ip.is_loopback() || crate::socle::adresses::du_reseau(ip)
}

/// Un serveur qu'on sait interroger d'ici : une adresse IPv6 de lien local n'a pas le nom de sa carte.
fn interrogeable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => !crate::socle::adresses::lien_local_v6(v6),
    }
}

/// L'émetteur d'un certificat DER : son organisation, sinon son nom, sinon son unité (le champ qui précède la
/// validité, après le numéro de série et l'algorithme).
pub(crate) fn emetteur(der: &[u8]) -> Option<String> {
    let (_, certificat, _) = tlv(der)?;
    let (_, tbs, _) = tlv(certificat)?;
    let mut champs = tbs;
    if champs.first() == Some(&0xa0) {
        champs = tlv(champs)?.2;
    }
    for _ in 0..2 {
        champs = tlv(champs)?.2;
    }
    let (_, nom, _) = tlv(champs)?;
    attribut(nom, 10)
        .or_else(|| attribut(nom, 3))
        .or_else(|| attribut(nom, 11))
}

/// Les deux noms d'un émetteur réunis (organisation et nom), pour y reconnaître une famille ou une autorité.
fn noms_emetteur(der: &[u8]) -> Option<String> {
    let (_, certificat, _) = tlv(der)?;
    let (_, tbs, _) = tlv(certificat)?;
    let mut champs = tbs;
    if champs.first() == Some(&0xa0) {
        champs = tlv(champs)?.2;
    }
    for _ in 0..2 {
        champs = tlv(champs)?.2;
    }
    let (_, nom, _) = tlv(champs)?;
    let parties: Vec<String> = [10, 3, 11].iter().filter_map(|c| attribut(nom, *c)).collect();
    (!parties.is_empty()).then(|| parties.join(" "))
}

fn autorite_publique(nom: &str) -> bool {
    let bas = nom.to_lowercase();
    AUTORITES_PUBLIQUES.iter().any(|a| bas.contains(&a.to_lowercase()))
}

// ---------------------------------------------------------------------------------------------------------------
// Acquisition
// ---------------------------------------------------------------------------------------------------------------

/// Les dossiers de profils des navigateurs de la famille Firefox : ceux que `machine::extensions::racines`
/// connaît, une seule liste pour tout le programme.
fn racines_firefox() -> Vec<(&'static str, PathBuf)> {
    crate::machine::extensions::racines()
        .into_iter()
        .filter(|(_, _, firefox)| *firefox)
        .map(|(nom, dossier, _)| (nom, dossier))
        .collect()
}

/// Les profils d'une racine : les dossiers qui ont un prefs.js (un profil déjà ouvert).
fn profils(racine: &Path) -> Vec<PathBuf> {
    let mut p: Vec<PathBuf> = std::fs::read_dir(racine)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|c| c.join("prefs.js").is_file())
        .collect();
    p.sort();
    p
}

/// Les exceptions d'un cert_override.txt : une ligne par hôte, « hôte:port[:attributs]<tab>OID<tab>empreinte<tab>
/// drapeaux<tab>clé » ; les lignes « # » sont des commentaires.
fn lire_exceptions(texte: &str) -> Vec<(String, u16, String)> {
    let mut liste = Vec::new();
    for ligne in texte.lines() {
        if ligne.starts_with('#') || ligne.trim().is_empty() {
            continue;
        }
        let champs: Vec<&str> = ligne.split('\t').collect();
        let Some(cible) = champs.first() else { continue };
        // Attributs d'origine après le port : « :^privateBrowsingId=1 » (navigation privée, conteneurs), ou un
        // dernier deux-points seul quand il n'y en a pas.
        let cible = cible.split(":^").next().unwrap_or(cible);
        let cible = cible.strip_suffix(':').unwrap_or(cible);
        let Some((hote, port)) = cible.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.trim().parse::<u16>() else {
            continue;
        };
        let drapeaux = champs
            .get(3)
            .filter(|d| d.len() <= 3 && d.chars().all(|c| matches!(c, 'M' | 'U' | 'T')))
            .map_or(String::new(), |d| (*d).to_string());
        liste.push((hote.trim_matches(['[', ']']).to_string(), port, drapeaux));
        if liste.len() >= 200 {
            break;
        }
    }
    liste
}

/// Valeur d'une préférence Firefox (`user_pref("nom", valeur);`), la dernière écrite.
fn pref(texte: &str, nom: &str) -> Option<String> {
    let debut = format!("user_pref(\"{nom}\",");
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix(debut.as_str()))
        .filter_map(|r| r.trim().strip_suffix(");"))
        .map(|v| v.trim().trim_matches('"').to_string())
        .next_back()
}

/// DNS chiffré de Firefox d'après `network.trr.mode` : 2 ou 3 = activé, 5 = coupé, sinon par défaut.
fn doh_firefox(prefs: &str) -> Option<bool> {
    match pref(prefs, "network.trr.mode").as_deref() {
        Some("2" | "3") => Some(true),
        Some("5") => Some(false),
        _ => None,
    }
}

/// Les certificats qu'une politique Firefox installe (`policies.json`), et si elle importe les racines du système.
fn lire_politique(texte: &str) -> Option<(Vec<String>, Option<bool>)> {
    let v: serde_json::Value = serde_json::from_str(texte).ok()?;
    let certificats = &v["policies"]["Certificates"];
    if certificats.is_null() {
        return None;
    }
    let installes: Vec<String> = certificats["Install"]
        .as_array()
        .map(|t| t.iter().filter_map(|c| c.as_str()).map(affichable).collect())
        .unwrap_or_default();
    Some((installes, certificats["ImportEnterpriseRoots"].as_bool()))
}

/// Les fichiers de politique de Firefox, par système.
fn fichiers_de_politique() -> Vec<PathBuf> {
    let mut liste: Vec<PathBuf> = Vec::new();
    #[cfg(target_os = "linux")]
    liste.extend(
        [
            "/etc/firefox/policies/policies.json",
            "/usr/lib/firefox/distribution/policies.json",
            "/usr/lib64/firefox/distribution/policies.json",
            "/usr/share/firefox/distribution/policies.json",
            "/opt/firefox/distribution/policies.json",
            "/usr/lib/firefox-esr/distribution/policies.json",
            "/etc/librewolf/policies/policies.json",
        ]
        .map(PathBuf::from),
    );
    #[cfg(target_os = "macos")]
    liste.extend(
        [
            "/Applications/Firefox.app/Contents/Resources/distribution/policies.json",
            "/Library/Application Support/Mozilla/policies.json",
        ]
        .map(PathBuf::from),
    );
    #[cfg(windows)]
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(programmes) = std::env::var_os(variable) {
            liste.push(PathBuf::from(programmes).join("Mozilla Firefox\\distribution\\policies.json"));
        }
    }
    liste
}

/// Ce que les navigateurs de la famille Firefox gardent : exceptions de certificat, DNS chiffré, profils vus,
/// politiques.
struct Navigateurs {
    exceptions: Vec<Exception>,
    doh: Vec<(String, Option<bool>)>,
    profils: usize,
    politiques: Vec<Politique>,
}

fn navigateurs() -> Navigateurs {
    let (mut exceptions, mut doh, mut nombre) = (Vec::new(), Vec::new(), 0);
    let mut vus: Vec<PathBuf> = Vec::new();
    for (nom, racine) in racines_firefox() {
        for profil in profils(&racine) {
            let reel = profil.canonicalize().unwrap_or_else(|_| profil.clone());
            if vus.contains(&reel) {
                continue;
            }
            vus.push(reel);
            nombre += 1;
            let lire = |f: &str| std::fs::read_to_string(profil.join(f)).unwrap_or_default();
            doh.push((nom.to_string(), doh_firefox(&(lire("prefs.js") + &lire("user.js")))));
            for (hote, port, drapeaux) in lire_exceptions(&lire("cert_override.txt")) {
                exceptions.push(Exception {
                    navigateur: nom.to_string(),
                    hote,
                    port,
                    drapeaux,
                });
            }
        }
    }
    let mut politiques = Vec::new();
    for fichier in fichiers_de_politique() {
        let Ok(texte) = std::fs::read_to_string(&fichier) else {
            continue;
        };
        if let Some((certificats, racines_du_systeme)) = lire_politique(&texte)
            && (!certificats.is_empty() || racines_du_systeme == Some(true))
        {
            politiques.push(Politique {
                fichier: crate::ui::chemin_affichable(&fichier),
                certificats,
                racines_du_systeme,
            });
        }
    }
    Navigateurs {
        exceptions,
        doh,
        profils: nombre,
        politiques,
    }
}

/// Les trois noms stables demandés à un résolveur, puis, s'il répond, l'épreuve DNSSEC et la question de DDR
/// (pour le résolveur utilisé et celui du bail seulement).
fn interroger(role: Role, serveur: IpAddr) -> (Mesure, Option<Dnssec>, Option<Ddr>) {
    let reponses: Vec<(&'static str, Option<Reponse>)> = NOMS_STABLES
        .iter()
        .map(|(nom, _)| (*nom, dns_client::interroger(serveur, nom, Genre::A, true, false)))
        .collect();
    let inexistant = dns_client::interroger(
        serveur,
        &format!("{}.{ZONE_INEXISTANTS}", etiquette_au_hasard()),
        Genre::A,
        true,
        false,
    );
    let mesure = Mesure {
        role,
        serveur,
        reponses,
        inexistant,
    };
    let muet = mesure.reponses.iter().all(|(_, r)| r.is_none());
    if muet || matches!(role, Role::Public(_)) {
        return (mesure, None, None);
    }
    let dnssec = Dnssec {
        role,
        serveur,
        signe: dns_client::interroger(serveur, NOM_SIGNE, Genre::A, true, true),
        casse: dns_client::interroger(serveur, NOM_CASSE, Genre::A, true, true),
        casse_hasard: dns_client::interroger(
            serveur,
            &format!("{}.{NOM_CASSE}", etiquette_au_hasard()),
            Genre::A,
            true,
            true,
        ),
    };
    let ddr = Ddr {
        role,
        serveur,
        reponse: dns_client::interroger(serveur, NOM_DDR, Genre::Svcb, true, false),
    };
    (mesure, Some(dnssec), Some(ddr))
}

/// Le certificat présenté par le site de référence.
fn certificat_du_site() -> Tls {
    match crate::http::certificat_presente(SITE_TLS, DELAI_TLS) {
        Ok(p) => Tls::Presente {
            emetteur: emetteur(&p.certificat),
            noms: noms_emetteur(&p.certificat),
            sujet: crate::machine::certificats::sujet(&p.certificat),
            code: p.code,
        },
        Err(crate::http::Refus::Certificat(raison)) => Tls::Refuse(raison),
        Err(crate::http::Refus::Reseau) => Tls::Muet,
    }
}

/// Un proxy est-il réglé pour HTTPS, là où le client HTTPS de Vanguard ou les navigateurs le prennent : variables
/// d'environnement partout, le registre sous Windows, les réglages réseau sous macOS, ceux du bureau sous Linux
/// (GNOME, KDE : Chrome et Firefox les suivent, pas la sonde). `None` : illisible (sous Windows et macOS).
#[cfg_attr(target_os = "linux", allow(clippy::unnecessary_wraps))]
fn proxy_du_systeme() -> Option<bool> {
    let variable = ["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|x| !x.is_empty()));
    if variable {
        return Some(true);
    }
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;
        let k = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .ok()?;
        let actif = k.get_value::<u32, _>("ProxyEnable").is_ok_and(|v| v != 0);
        let pac = k
            .get_value::<String, _>("AutoConfigURL")
            .is_ok_and(|v| !v.trim().is_empty());
        Some(actif || pac)
    }
    #[cfg(target_os = "macos")]
    {
        let r = crate::commande::lancer(std::process::Command::new("scutil").arg("--proxy"), 5)?;
        Some(r.sortie.lines().any(|l| {
            let l = l.split_whitespace().collect::<String>();
            l == "HTTPSEnable:1" || l == "ProxyAutoConfigEnable:1"
        }))
    }
    #[cfg(target_os = "linux")]
    {
        let gnome = crate::commande::lancer(
            std::process::Command::new("gsettings").args(["get", "org.gnome.system.proxy", "mode"]),
            5,
        )
        .map(|r| r.sortie);
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map_or_else(|| crate::socle::maison().join(".config"), std::path::PathBuf::from);
        let kde = std::fs::read_to_string(config.join("kioslaverc")).ok();
        Some(proxy_du_bureau(gnome.as_deref(), kde.as_deref()))
    }
}

/// Le bureau Linux règle-t-il un proxy ? `gnome` : la sortie de « gsettings get org.gnome.system.proxy mode »
/// (« 'manual' », « 'auto' » : un proxy ou un PAC) ; `kde` : kioslaverc, où ProxyType 1 à 4 (à la main, PAC,
/// détection, variables) en règle un. Rien de lisible : pas de proxy du bureau, la sonde suit les navigateurs.
#[cfg(any(target_os = "linux", test))]
fn proxy_du_bureau(gnome: Option<&str>, kde: Option<&str>) -> bool {
    let gnome = gnome.is_some_and(|m| m.contains("manual") || m.contains("auto"));
    let kde = kde.is_some_and(|t| {
        t.lines().any(|l| {
            l.split_once('=')
                .is_some_and(|(cle, v)| cle.trim() == "ProxyType" && matches!(v.trim().parse::<u8>(), Ok(1..=4)))
        })
    });
    gnome || kde
}

/// La sonde post-quantique vers le site de référence.
fn sonde_du_site() -> Result<ReponsePq, Echec> {
    // Une adresse, pas un nom : ni SNI (RFC 6066 §3), ni question DNS de plus.
    super::tls_pq::sonder(SocketAddr::from(SITE_PQ), None, DELAI_PQ)
}

/// L'administration de la box : les ports que le scan a trouvés ouverts, sondés chacun une fois. `None` : la box
/// n'est pas dans le scan ou n'a pas d'adresse IPv4 locale.
fn sonde_de_la_box(passerelle: Option<IpAddr>, ports: Option<&[u16]>) -> Option<Vec<(String, Result<bool, Echec>)>> {
    let IpAddr::V4(ip) = passerelle? else { return None };
    let ports = ports?;
    if !crate::reseau::nmap::locale(ip) || ip.is_loopback() {
        return None;
    }
    let mut services: Vec<(String, Result<bool, Echec>)> = Vec::new();
    std::thread::scope(|s| {
        let ssh = ports.contains(&PORT_SSH).then(|| {
            s.spawn(move || {
                super::ssh_kex::kexinit(ip, PORT_SSH, DELAI_BOX)
                    .map(|noms| noms.iter().any(|n| crate::machine::nom_pq(n)))
            })
        });
        let https: Vec<_> = PORTS_HTTPS
            .into_iter()
            .filter(|p| ports.contains(p))
            .map(|p| {
                (
                    p,
                    s.spawn(move || {
                        let adresse = SocketAddr::from((ip, p));
                        super::tls_pq::sonder(adresse, None, DELAI_BOX).and_then(|r| match r {
                            ReponsePq::Accepte => Ok(true),
                            ReponsePq::Refuse(_) => Ok(false),
                            ReponsePq::Autre => Err(Echec::new(
                                "audit/tls-pq",
                                crate::modele::Raison::Illisible(
                                    tr!("réponse TLS incomprise", "TLS answer not understood").into(),
                                ),
                            )),
                        })
                    }),
                )
            })
            .collect();
        let rate = || Err(Echec::new("audit/pq-box", crate::modele::Raison::Panique));
        if let Some(f) = ssh {
            services.push((format!("SSH {PORT_SSH}"), f.join().unwrap_or_else(|_| rate())));
        }
        for (p, f) in https {
            services.push((format!("HTTPS {p}"), f.join().unwrap_or_else(|_| rate())));
        }
    });
    Some(services)
}

/// Lit et mesure tout ce que le domaine juge. `passerelle` : la box, si l'audit la connaît déjà (sinon la route par
/// défaut) ; `ports_box` : ses ports TCP ouverts d'après le scan (`None` : elle n'y est pas). Hors ligne, rien ne
/// part vers Internet ; sinon, les questions DNS, la demande HTTPS et les sondes partent en parallèle et tout finit
/// en quelques secondes.
pub fn entree(passerelle: Option<Ipv4Addr>, ports_box: Option<&[u16]>) -> Entree {
    let hors_ligne = crate::parametres::hors_ligne();
    let baux = bail::lire();
    let configuration = bail::configuration();
    let utilise = crate::machine::dns::actuel().map(|a| Utilise {
        serveurs: a.serveurs,
        chiffre: a.chiffre,
        resolveur_local: a.resolveur_local,
    });
    // La box : celle que l'audit connaît, sinon la route par défaut (lue dans /proc sous Linux ; ailleurs, elle
    // demanderait un programme : le bail la donne).
    #[cfg(target_os = "linux")]
    let passerelle = passerelle.or_else(crate::reseau::scan::passerelle);
    let passerelle = passerelle
        .map(IpAddr::V4)
        .or_else(|| baux.as_ref().ok().and_then(|b| b.iter().find_map(|b| b.passerelle)));
    let navigateurs = navigateurs();
    let mut e = Entree {
        hors_ligne,
        baux,
        utilise,
        configuration,
        passerelle,
        mesures: Vec::new(),
        interrompues: Vec::new(),
        dnssec: Vec::new(),
        ddr: Vec::new(),
        navigateurs_doh: navigateurs.doh,
        tls: Tls::NonDemande,
        exceptions: navigateurs.exceptions,
        profils_firefox: navigateurs.profils,
        politiques: navigateurs.politiques,
        pq_site: None,
        proxy: proxy_du_systeme(),
        routeur: None,
    };
    // La box est sur le réseau local : sondée même hors ligne (rien ne part vers Internet).
    let passerelle_box = e.passerelle;
    if hors_ligne {
        e.routeur = sonde_de_la_box(passerelle_box, ports_box);
        return e;
    }
    // Les résolveurs à interroger : celui de la machine, celui du bail s'il diffère, puis deux publics différents.
    let mut cibles: Vec<(Role, IpAddr)> = Vec::new();
    if let Some(ip) = e
        .utilise
        .as_ref()
        .and_then(|u| u.serveurs.iter().map(|(ip, _)| *ip).find(|ip| interrogeable(*ip)))
    {
        cibles.push((Role::Utilise, ip));
    }
    if let Some(ip) = e
        .baux
        .as_ref()
        .ok()
        .and_then(|b| bail_principal(b, e.passerelle))
        .and_then(|b| b.dns.iter().copied().find(|ip| interrogeable(*ip)))
        && !cibles.iter().any(|(_, c)| *c == ip)
    {
        cibles.push((Role::Bail, ip));
    }
    for (nom, ip) in PUBLICS {
        if cibles.iter().filter(|(r, _)| matches!(r, Role::Public(_))).count() >= 2 {
            break;
        }
        if !cibles.iter().any(|(_, c)| *c == IpAddr::V4(ip)) {
            cibles.push((Role::Public(nom), IpAddr::V4(ip)));
        }
    }
    let (mesures, tls, pq_site, routeur) = std::thread::scope(|s| {
        let tls = s.spawn(certificat_du_site);
        let pq = s.spawn(sonde_du_site);
        let routeur = s.spawn(move || sonde_de_la_box(passerelle_box, ports_box));
        (
            mesurer(&cibles, interroger),
            tls.join().unwrap_or(Tls::Muet),
            pq.join()
                .unwrap_or_else(|_| Err(Echec::new("audit/tls-pq", crate::modele::Raison::Panique))),
            routeur.join().ok().flatten(),
        )
    });
    e.pq_site = Some(pq_site);
    e.routeur = routeur;
    for m in mesures {
        match m {
            Ok((mesure, dnssec, ddr)) => {
                e.mesures.push(mesure);
                e.dnssec.extend(dnssec);
                e.ddr.extend(ddr);
            }
            Err(interrompue) => e.interrompues.push(interrompue),
        }
    }
    e.tls = tls;
    e
}

/// Les résolveurs interrogés en même temps, un fil chacun : ce que chacun a répondu, ou son rôle et son adresse si sa
/// mesure est tombée (une panique dans la lecture d'une réponse). Jetée en silence, la mesure du DNS de la box faisait
/// disparaître le contrôle de ses réponses sans « non vérifié », et celle du DNS utilisé le disait « non interrogeable
/// d'ici ». Chaque mesure a sa garde (journal::rattraper) : la garde du domaine, propre au fil qui l'a ouverte, ne
/// couvre pas ceux-ci, et leur panique s'affichait et se notait encore comme un plantage.
fn mesurer<R: Send>(
    cibles: &[(Role, IpAddr)],
    interroger: impl Fn(Role, IpAddr) -> R + Sync,
) -> Vec<Result<R, (Role, IpAddr)>> {
    let interroger = &interroger;
    std::thread::scope(|s| {
        let fils: Vec<_> = cibles
            .iter()
            .map(|&(role, ip)| {
                let fil =
                    s.spawn(move || crate::journal::rattraper(std::panic::AssertUnwindSafe(|| interroger(role, ip))));
                (role, ip, fil)
            })
            .collect();
        fils.into_iter()
            .map(|(role, ip, fil)| match fil.join() {
                Ok(Ok(mesure)) => Ok(mesure),
                _ => Err((role, ip)),
            })
            .collect()
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Jugement
// ---------------------------------------------------------------------------------------------------------------

fn regle(mut c: Constat, id: &'static str) -> Constat {
    c.regle = id;
    c
}

/// Le nom d'un serveur DNS pour l'écran : service connu, box, réseau, résolveur local, ou l'adresse seule.
fn nommer(ip: IpAddr, e: &Entree) -> String {
    if ip.is_loopback() {
        return match e.utilise.as_ref().and_then(|u| u.resolveur_local) {
            Some(nom) => trf!("{nom} sur cet ordinateur ({ip})", "{nom} on this computer ({ip})"),
            None => trf!("résolveur local ({ip})", "local resolver ({ip})"),
        };
    }
    if let Some(nom) = service_public(ip) {
        return format!("{nom} ({ip})");
    }
    if e.passerelle == Some(ip) {
        return trf!("le routeur ({ip})", "the router ({ip})");
    }
    if du_reseau(ip) {
        return trf!("{ip}, un appareil de votre réseau", "{ip}, a device on your network");
    }
    ip.to_string()
}

/// Le bail qui compte parmi ceux lus : celui dont la passerelle est la route par défaut (deux cartes branchées), sinon
/// le premier qui distribue un DNS.
fn bail_principal(baux: &[Bail], passerelle: Option<IpAddr>) -> Option<&Bail> {
    baux.iter()
        .filter(|b| !b.dns.is_empty())
        .find(|b| passerelle.is_some() && b.passerelle == passerelle)
        .or_else(|| baux.iter().find(|b| !b.dns.is_empty()))
}

/// COM-DNS-002 : le DNS distribué par la box (bail DHCP), et ce que cet ordinateur en fait.
fn constats_bail(e: &Entree) -> Vec<Constat> {
    const ID: &str = "COM-DNS-002";
    let baux = match &e.baux {
        Ok(b) => b,
        Err(raison) => {
            return vec![regle(
                impossible(
                    CAT_DNS,
                    &trf!("bail DHCP illisible : {raison}", "DHCP lease unreadable: {raison}"),
                ),
                ID,
            )];
        }
    };
    let Some(bail) = bail_principal(baux, e.passerelle) else {
        return vec![regle(
            alerte(
                CAT_DNS,
                Niveau::Info,
                tr!(
                    "Le routeur ne distribue aucun serveur DNS par DHCP : chaque appareil doit en avoir un réglé à la main.",
                    "The router hands out no DNS server by DHCP: every device must have one set by hand."
                ),
            ),
            ID,
        )];
    };
    let box_ = [e.passerelle, bail.passerelle, bail.serveur];
    let est_la_box = |ip: IpAddr| box_.contains(&Some(ip));
    let distribue = bail.dns[0];
    let liste = bail.dns.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
    // Le DNS du bail réécrit les réponses (DNS-004 mesuré sur lui) : la maison entière le suit.
    let bail_diverge = e
        .mesures
        .iter()
        .filter(|m| m.role == Role::Bail)
        .any(|m| bilan(m, e).divergents.len() >= 2);
    let mut constats = Vec::new();
    let constat_bail = if est_la_box(distribue) {
        alerte(
            CAT_DNS,
            Niveau::Info,
            trf!(
                "Le routeur ({distribue}) résout les noms pour tout le réseau local et transmet les questions à un serveur qu'on ne voit pas d'ici (celui du fournisseur, normalement).",
                "The router ({distribue}) resolves names for the whole household and forwards questions to a server that cannot be seen from here (the provider's, normally)."
            ),
        )
    } else if let Some(service) = service_public(distribue) {
        ok(
            CAT_DNS,
            trf!(
                "Le routeur distribue {service} ({liste}) à tous vos appareils.",
                "The router hands out {service} ({liste}) to all your devices."
            ),
        )
    } else if du_reseau(distribue) {
        alerte(
            CAT_DNS,
            Niveau::Info,
            trf!(
                "Le routeur distribue le DNS {distribue}, un appareil de votre réseau (Pi-hole, NAS, AdGuard Home ?), à tous vos appareils : normal si c'est à vous.",
                "The router hands out DNS {distribue}, a device on your network (Pi-hole, NAS, AdGuard Home?), to all your devices: normal if it is yours."
            ),
        )
    } else {
        let niveau = if bail_diverge { Niveau::Moyen } else { Niveau::Info };
        let suite = if bail_diverge {
            tr!(
                " Et ce serveur réécrit des réponses (voir plus bas).",
                " And this server rewrites answers (see below)."
            )
        } else {
            ""
        };
        alerte(
            CAT_DNS,
            niveau,
            trf!(
                "Le routeur distribue le DNS {distribue} à tous vos appareils : ce n'est ni lui ni un service connu. Normal si c'est celui de votre fournisseur ; sinon, le routeur a pu être modifié, et tout le réseau local le suit.{suite}",
                "The router hands out DNS {distribue} to all your devices: it is neither itself nor a known service. Normal if it is your provider's; otherwise the router may have been tampered with, and the whole household follows it.{suite}"
            ),
        )
        .manuel(
            tr!(
                "Admin du routeur > DNS : automatique ou un service connu ; changez le mot de passe du routeur et mettez-le à jour",
                "Router admin > DNS: automatic or a known service; change the router password and update it"
            ),
            &[],
        )
    };
    constats.push(regle(constat_bail, ID));
    // Cet ordinateur suit-il le bail ?
    let Some(u) = &e.utilise else {
        return constats;
    };
    let Some((actuel, manuel)) = u.serveurs.first().copied() else {
        return constats;
    };
    if bail.dns.contains(&actuel) || actuel.is_loopback() {
        return constats;
    }
    let constat = if let Some(service) = service_public(actuel) {
        ok(
            CAT_DNS,
            trf!(
                "Cet ordinateur utilise {service} ({actuel}) au lieu du DNS distribué par le routeur ({distribue}) : un choix, pas un problème.",
                "This computer uses {service} ({actuel}) instead of the DNS handed out by the router ({distribue}): a choice, not a problem."
            ),
        )
    } else if du_reseau(actuel) || est_la_box(actuel) {
        alerte(
            CAT_DNS,
            Niveau::Info,
            trf!(
                "Cet ordinateur utilise {actuel} (votre réseau) au lieu du DNS distribué par le routeur ({distribue}).",
                "This computer uses {actuel} (your network) instead of the DNS handed out by the router ({distribue})."
            ),
        )
    } else {
        let comment = if manuel {
            tr!("réglé à la main", "set by hand")
        } else {
            tr!("réglé sur cet ordinateur", "set on this computer")
        };
        alerte(
            CAT_DNS,
            Niveau::Moyen,
            trf!(
                "Cet ordinateur n'utilise pas le DNS distribué par le routeur ({distribue}) mais {actuel}, {comment} : un serveur inconnu. Si vous ne l'avez pas choisi, un programme a pu le changer pour détourner vos visites.",
                "This computer does not use the DNS handed out by the router ({distribue}) but {actuel}, {comment}: an unknown server. If you did not choose it, a program may have changed it to hijack your browsing."
            ),
        )
        .manuel(
            tr!(
                "Remettez le DNS de cet ordinateur en automatique (celui que donne le routeur)",
                "Set this computer's DNS back to automatic (the one the router provides)"
            ),
            &[],
        )
    };
    constats.push(regle(constat, ID));
    constats
}

/// Ce qu'un résolveur a répondu pour un nom stable, comparé aux adresses attendues et à celles des publics.
#[derive(PartialEq, Eq, Debug)]
enum Verdict {
    Muet,
    /// Nom inexistant, refusé, ou renvoyé vers 0.0.0.0 ou 127.0.0.1 : bloqué.
    Filtre,
    Conforme,
    Divergent(Ipv4Addr),
}

fn verdict(reponse: Option<&Reponse>, attendues: &[Ipv4Addr], publiques: &[Ipv4Addr]) -> Verdict {
    let Some(r) = reponse else { return Verdict::Muet };
    if r.rcode == 3 || r.rcode == 5 {
        return Verdict::Filtre;
    }
    let vues = r.adresses_v4();
    if vues.is_empty() {
        // Réponse sans adresse (panne du serveur, ou vide) : rien à comparer.
        return if r.rcode == 0 { Verdict::Filtre } else { Verdict::Muet };
    }
    if vues.iter().all(|ip| ip.is_unspecified() || ip.is_loopback()) {
        return Verdict::Filtre;
    }
    if vues.iter().any(|ip| attendues.contains(ip) || publiques.contains(ip)) {
        return Verdict::Conforme;
    }
    Verdict::Divergent(vues[0])
}

/// Le bilan d'une mesure : les noms conformes, filtrés, divergents (avec l'adresse vue et une attendue), muets.
#[derive(Default, Debug)]
struct Bilan {
    conformes: usize,
    filtres: Vec<&'static str>,
    divergents: Vec<(&'static str, Ipv4Addr, Ipv4Addr)>,
    muets: usize,
}

fn bilan(m: &Mesure, e: &Entree) -> Bilan {
    let mut b = Bilan::default();
    for (nom, reponse) in &m.reponses {
        let attendues = NOMS_STABLES
            .iter()
            .find(|(n, _)| n == nom)
            .map(|(_, a)| a.to_vec())
            .unwrap_or_default();
        // Ce que les résolveurs publics ont répondu pour ce nom : l'attendu vivant, si le service a changé d'adresse.
        let publiques: Vec<Ipv4Addr> = e
            .mesures
            .iter()
            .filter(|p| matches!(p.role, Role::Public(_)))
            .flat_map(|p| p.reponses.iter().filter(|(n, _)| n == nom))
            .filter_map(|(_, r)| r.as_ref())
            .flat_map(Reponse::adresses_v4)
            .collect();
        match verdict(reponse.as_ref(), &attendues, &publiques) {
            Verdict::Muet => b.muets += 1,
            Verdict::Filtre => b.filtres.push(nom),
            Verdict::Conforme => b.conformes += 1,
            Verdict::Divergent(vue) => {
                let attendue = attendues.first().copied().unwrap_or(Ipv4Addr::UNSPECIFIED);
                b.divergents.push((nom, vue, attendue));
            }
        }
    }
    b
}

/// COM-DNS-004 : réponses divergentes sur des noms stables, pour le résolveur utilisé (et celui du bail).
fn constats_divergence(e: &Entree) -> Vec<Constat> {
    const ID: &str = "COM-DNS-004";
    if e.hors_ligne {
        return vec![regle(
            impossible(
                CAT_DNS,
                tr!(
                    "hors ligne : réponses DNS non comparées",
                    "offline: DNS answers not compared"
                ),
            ),
            ID,
        )];
    }
    let mut constats = Vec::new();
    let publics_muets = e
        .mesures
        .iter()
        .filter(|m| matches!(m.role, Role::Public(_)))
        .all(|m| m.reponses.iter().all(|(_, r)| r.is_none()));
    for role in [Role::Utilise, Role::Bail] {
        let Some(m) = e.mesures.iter().find(|m| m.role == role) else {
            if let Some(&(_, ip)) = e.interrompues.iter().find(|(r, _)| *r == role) {
                let message = if role == Role::Bail {
                    trf!(
                        "DNS que le routeur distribue ({ip}) : mesure interrompue par une erreur interne, réponses non comparées",
                        "DNS the router hands out ({ip}): measurement interrupted by an internal error, answers not compared"
                    )
                } else {
                    trf!(
                        "DNS utilisé ({ip}) : mesure interrompue par une erreur interne, réponses non comparées",
                        "DNS in use ({ip}): measurement interrupted by an internal error, answers not compared"
                    )
                };
                constats.push(regle(impossible(CAT_DNS, &message), ID));
            } else if role == Role::Utilise {
                constats.push(regle(
                    impossible(
                        CAT_DNS,
                        tr!(
                            "DNS utilisé non interrogeable d'ici (configuration illisible ou adresse de lien local)",
                            "DNS in use cannot be queried from here (unreadable configuration or link-local address)"
                        ),
                    ),
                    ID,
                ));
            }
            continue;
        };
        let serveur = nommer(m.serveur, e);
        let b = bilan(m, e);
        let total = m.reponses.len();
        let constat = if b.muets == total {
            impossible(
                CAT_DNS,
                &if publics_muets {
                    trf!(
                        "{serveur} ne répond pas d'ici, les résolveurs publics non plus : hors ligne, ou port 53 fermé",
                        "{serveur} does not answer from here, nor do public resolvers: offline, or port 53 closed"
                    )
                } else {
                    trf!("{serveur} ne répond pas d'ici", "{serveur} does not answer from here")
                },
            )
        } else if b.divergents.len() >= 2 {
            let (nom, vu, attendu) = b.divergents[0];
            let meme = b.divergents.iter().all(|(_, v, _)| *v == vu);
            let qui = if role == Role::Bail {
                tr!(
                    "Le DNS que le routeur distribue à tout le réseau local",
                    "The DNS the router hands out to the whole household"
                )
            } else {
                tr!("Votre DNS", "Your DNS")
            };
            let message = if meme {
                trf!(
                    "{qui} ({serveur}) renvoie tous les noms vers la même adresse ({vu}, au lieu de {attendu} pour {nom}) : un portail Wi-Fi (hôtel, café) ou un détournement complet. Chez vous, c'est un détournement.",
                    "{qui} ({serveur}) sends every name to the same address ({vu} instead of {attendu} for {nom}): a Wi-Fi portal (hotel, café) or a complete hijack. At home, it is a hijack."
                )
            } else {
                trf!(
                    "{qui} ({serveur}) répond autre chose que l'adresse connue de {nom} ({vu} au lieu de {attendu}) : quelque chose entre vous et Internet réécrit les réponses DNS.",
                    "{qui} ({serveur}) answers something other than the known address of {nom} ({vu} instead of {attendu}): something between you and the Internet rewrites DNS answers."
                )
            };
            alerte(CAT_DNS, Niveau::Eleve, message).manuel(
                tr!(
                    "Remettez le DNS en automatique ou sur un service connu sur cet ordinateur ET dans le routeur ; changez le mot de passe du routeur ; relancez Vanguard. Si ça revient, le routeur est à mettre à jour ou à remplacer",
                    "Set DNS back to automatic or to a known service on this computer AND in the router; change the router password; run Vanguard again. If it comes back, the router needs an update or a replacement"
                ),
                &[],
            )
        } else if let Some((nom, vu, attendu)) = b.divergents.first() {
            alerte(
                CAT_DNS,
                Niveau::Info,
                trf!(
                    "{serveur} répond {vu} pour {nom} au lieu de {attendu} ; les autres noms sont justes. Un seul écart : à revoir au prochain audit avant d'y croire.",
                    "{serveur} answers {vu} for {nom} instead of {attendu}; the other names are right. A single gap: check again at the next audit before believing it."
                ),
            )
        } else if let Some(vues) = m
            .inexistant
            .as_ref()
            .map(Reponse::adresses_v4)
            .filter(|v| !v.is_empty())
        {
            alerte(
                CAT_DNS,
                Niveau::Moyen,
                trf!(
                    "{serveur} donne une adresse ({}) à un nom inventé à l'instant, qui n'existe pas : il réécrit les noms inexistants (page de publicité du fournisseur, ou détournement). Une faute de frappe mène alors chez lui.",
                    "{serveur} gives an address ({}) to a name made up just now, which does not exist: it rewrites nonexistent names (provider ad page, or hijack). A typo then leads to it.",
                    vues[0]
                ),
            )
            .manuel(
                tr!(
                    "Choisissez un DNS qui ne réécrit rien (Quad9, Cloudflare, Bouclier canadien), sur cet ordinateur ou dans le routeur",
                    "Pick a DNS that rewrites nothing (Quad9, Cloudflare, Canadian Shield), on this computer or in the router"
                ),
                &[],
            )
        } else if !b.filtres.is_empty() {
            let noms = b.filtres.join(", ");
            alerte(
                CAT_DNS,
                Niveau::Info,
                trf!(
                    "{serveur} bloque les autres résolveurs ({noms}) : filtre volontaire (NextDNS, AdGuard, Pi-hole) ou blocage par le routeur. Normal si vous l'avez choisi.",
                    "{serveur} blocks the other resolvers ({noms}): a deliberate filter (NextDNS, AdGuard, Pi-hole) or a block by the router. Normal if you chose it."
                ),
            )
        } else {
            let n = b.conformes;
            let reference = if publics_muets {
                tr!(
                    " (les résolveurs publics ne répondent pas d'ici : comparé aux adresses connues seulement)",
                    " (public resolvers do not answer from here: compared with the known addresses only)"
                )
            } else {
                ""
            };
            ok(
                CAT_DNS,
                trf!(
                    "{serveur} répond les adresses connues pour {n} noms stables, et « n'existe pas » pour un nom inventé : aucune réécriture visible sur les noms testés{reference}.",
                    "{serveur} answers the known addresses for {n} stable names, and “does not exist” for a made-up name: no rewriting visible on the names tested{reference}."
                ),
            )
        };
        constats.push(regle(constat, ID));
    }
    constats
}

/// COM-DNS-005 : DNSSEC validé ou non par le résolveur utilisé.
fn constat_dnssec(e: &Entree) -> Constat {
    const ID: &str = "COM-DNS-005";
    if e.hors_ligne {
        return regle(
            impossible(
                CAT_DNS,
                tr!("hors ligne : DNSSEC non testé", "offline: DNSSEC not tested"),
            ),
            ID,
        );
    }
    let Some(d) = e
        .dnssec
        .iter()
        .find(|d| d.role == Role::Utilise)
        .or_else(|| e.dnssec.iter().find(|d| d.role == Role::Bail))
    else {
        let raison = if e.interrompues.iter().any(|(r, _)| *r == Role::Utilise) {
            tr!(
                "DNSSEC non testé : la mesure du DNS utilisé s'est interrompue (erreur interne)",
                "DNSSEC not tested: the measurement of the DNS in use was interrupted (internal error)"
            )
        } else {
            tr!(
                "DNSSEC non testé : le DNS utilisé n'a pas répondu",
                "DNSSEC not tested: the DNS in use did not answer"
            )
        };
        return regle(impossible(CAT_DNS, raison), ID);
    };
    let serveur = nommer(d.serveur, e);
    let (Some(signe), Some(casse)) = (&d.signe, &d.casse) else {
        return regle(
            impossible(
                CAT_DNS,
                &trf!(
                    "{serveur} ne répond pas aux questions DNSSEC (EDNS bloqué par le routeur ?)",
                    "{serveur} does not answer DNSSEC questions (EDNS blocked by the router?)"
                ),
            ),
            ID,
        );
    };
    if signe.tc || casse.tc {
        return regle(
            impossible(
                CAT_DNS,
                &trf!(
                    "réponses DNSSEC tronquées : votre routeur ne laisse pas passer DNSSEC (EDNS) vers {serveur}",
                    "DNSSEC answers truncated: your router does not let DNSSEC (EDNS) through to {serveur}"
                ),
            ),
            ID,
        );
    }
    // Le nom tiré au hasard dans la zone cassée doit être refusé lui aussi : un résolveur qui ne refuse que le nom
    // connu s'est préparé à l'épreuve. Sans réponse, la validation n'est pas confirmée.
    let Some(casse_hasard) = &d.casse_hasard else {
        return regle(
            impossible(
                CAT_DNS,
                &trf!(
                    "{serveur} ne répond pas à la question DNSSEC tirée au hasard : validation non confirmée",
                    "{serveur} does not answer the randomly drawn DNSSEC question: validation not confirmed"
                ),
            ),
            ID,
        );
    };
    let constat = if signe.ad && casse.rcode == 2 && casse_hasard.rcode == 2 {
        ok(
            CAT_DNS,
            trf!(
                "{serveur} valide DNSSEC : une réponse falsifiée pour un site signé serait rejetée.",
                "{serveur} validates DNSSEC: a forged answer for a signed site would be rejected."
            ),
        )
    } else {
        let precision = if signe.ad && casse.rcode == 2 {
            tr!(
                " (il refuse le nom connu de la zone cassée, mais pas un nom tiré au hasard dans la même zone : il s'est préparé à l'épreuve)",
                " (it refuses the known name of the broken zone, but not a randomly drawn name in the same zone: it was prepared for the test)"
            )
        } else if signe.ad {
            tr!(
                " (il annonce des réponses validées, mais accepte une signature cassée)",
                " (it claims validated answers, yet accepts a broken signature)"
            )
        } else {
            ""
        };
        let marche = if cfg!(target_os = "linux") {
            tr!(
                "Un service qui valide (Quad9, Cloudflare, Google, Bouclier canadien), ou DNSSEC=yes dans systemd-resolved",
                "A validating service (Quad9, Cloudflare, Google, Canadian Shield), or DNSSEC=yes in systemd-resolved"
            )
        } else {
            tr!(
                "Un service qui valide (Quad9, Cloudflare, Google, Bouclier canadien)",
                "A validating service (Quad9, Cloudflare, Google, Canadian Shield)"
            )
        };
        alerte(
            CAT_DNS,
            Niveau::Info,
            trf!(
                "{serveur} ne vérifie pas les signatures DNSSEC{precision} : une réponse falsifiée passerait.",
                "{serveur} does not check DNSSEC signatures{precision}: a forged answer would get through."
            ),
        )
        .manuel(marche, &[])
    };
    regle(constat, ID)
}

/// Les offres de DNS chiffré d'une réponse DDR : « DoT vers dns.exemple.invalid », « DoH (h2) vers … ».
fn offres(r: &Reponse) -> Vec<String> {
    let mut liste = Vec::new();
    for e in &r.enregistrements {
        let Donnees::Svcb {
            priorite, cible, alpn, ..
        } = &e.donnees
        else {
            continue;
        };
        if *priorite == 0 || alpn.is_empty() {
            continue;
        }
        let protocoles: Vec<String> = alpn
            .iter()
            .map(|a| match a.as_str() {
                "dot" => "DoT".to_string(),
                "doq" => "DoQ".to_string(),
                "h2" | "h3" => format!("DoH ({a})"),
                autre => affichable(autre),
            })
            .collect();
        liste.push(trf!("{} vers {}", "{} to {}", protocoles.join(", "), affichable(cible)));
        if liste.len() >= 4 {
            break;
        }
    }
    liste
}

/// COM-DNS-003 : les questions DNS partent-elles chiffrées, et la box ou le fournisseur proposent-ils du chiffré ?
fn constat_chiffrement(e: &Entree) -> Constat {
    const ID: &str = "COM-DNS-003";
    let c = &e.configuration;
    let serveur = e
        .utilise
        .as_ref()
        .and_then(|u| u.serveurs.first())
        .map(|(ip, _)| nommer(*ip, e));
    // Comment on sait que c'est chiffré, s'il y a lieu.
    let mut chiffre: Option<String> = None;
    if let Some(u) = &e.utilise
        && u.chiffre == Some(true)
    {
        chiffre = Some(match u.resolveur_local {
            Some(nom) => trf!("{nom} chiffre les questions", "{nom} encrypts the questions"),
            None => tr!("DNS over TLS du système", "system DNS over TLS").to_string(),
        });
    }
    if let Some(r) = &c.resolved
        && r.dns_over_tls.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("yes"))
    {
        chiffre.get_or_insert_with(|| {
            tr!(
                "DNSOverTLS=yes dans systemd-resolved",
                "DNSOverTLS=yes in systemd-resolved"
            )
            .to_string()
        });
    }
    let serveurs_utilises: Vec<String> = e
        .utilise
        .as_ref()
        .map(|u| u.serveurs.iter().map(|(ip, _)| ip.to_string()).collect())
        .unwrap_or_default();
    if c.doh_windows
        .iter()
        .any(|d| d.drapeaux != 0 && serveurs_utilises.iter().any(|s| s.eq_ignore_ascii_case(&d.serveur)))
    {
        chiffre.get_or_insert_with(|| tr!("DoH de Windows", "Windows DoH").to_string());
    }
    let navigateurs: Vec<&str> = e
        .navigateurs_doh
        .iter()
        .filter(|(_, actif)| *actif == Some(true))
        .map(|(nom, _)| nom.as_str())
        .collect();
    let mut ddr: Vec<String> = Vec::new();
    for d in &e.ddr {
        if let Some(r) = &d.reponse {
            ddr.extend(offres(r));
        }
    }
    ddr.dedup();
    let serveur = serveur.unwrap_or_else(|| tr!("serveur inconnu", "unknown server").to_string());
    if let Some(comment) = chiffre {
        return regle(
            ok(
                CAT_DNS,
                trf!(
                    "Les questions DNS de cet ordinateur partent chiffrées ({comment}, vers {serveur}).",
                    "This computer's DNS questions leave encrypted ({comment}, to {serveur})."
                ),
            ),
            ID,
        );
    }
    // Rien ne dit que c'est chiffré. Sous macOS sans résolveur local connu, on ne sait pas lire un profil de DNS
    // chiffré : non vérifié plutôt que « en clair ».
    if cfg!(target_os = "macos") && e.utilise.as_ref().is_none_or(|u| u.chiffre.is_none()) {
        return regle(
            impossible(
                CAT_DNS,
                tr!(
                    "DNS chiffré du système non lisible sans programme externe (profil macOS)",
                    "system encrypted DNS not readable without an external program (macOS profile)"
                ),
            ),
            ID,
        );
    }
    if e.utilise.is_none() {
        return regle(
            impossible(
                CAT_DNS,
                tr!("configuration DNS illisible", "DNS configuration unreadable"),
            ),
            ID,
        );
    }
    let offre = if !ddr.is_empty() {
        trf!(
            " Votre résolveur propose du DNS chiffré ({}) : activez-le sur vos appareils.",
            " Your resolver offers encrypted DNS ({}): turn it on on your devices.",
            ddr.join(" ; ")
        )
    } else if e.hors_ligne || e.ddr.is_empty() {
        tr!(
            " (Le routeur et le fournisseur n'ont pas pu être questionnés sur le DNS chiffré.)",
            " (The router and the provider could not be asked about encrypted DNS.)"
        )
        .to_string()
    } else {
        tr!(
            " Ni le routeur ni le fournisseur n'en proposent (DDR).",
            " Neither the router nor the provider offers it (DDR)."
        )
        .to_string()
    };
    let opportuniste = if c
        .resolved
        .as_ref()
        .and_then(|r| r.dns_over_tls.as_deref())
        .is_some_and(|v| v.eq_ignore_ascii_case("opportunistic"))
    {
        tr!(
            " (systemd-resolved en DNS over TLS opportuniste : chiffré seulement si le serveur l'accepte, sans garantie.)",
            " (systemd-resolved in opportunistic DNS over TLS: encrypted only if the server accepts it, no guarantee.)"
        )
    } else {
        ""
    };
    let navigateur = if navigateurs.is_empty() {
        String::new()
    } else {
        trf!(
            " {} chiffre les siennes seulement.",
            " {} encrypts its own only.",
            navigateurs.join(", ")
        )
    };
    let windows_10 = if cfg!(windows) && c.windows_11 == Some(false) {
        tr!(
            " (Windows 10 ne sait pas chiffrer le DNS du système.)",
            " (Windows 10 cannot encrypt the system DNS.)"
        )
    } else {
        ""
    };
    regle(
        alerte(
            CAT_DNS,
            Niveau::Info,
            trf!(
                "Les questions DNS partent en clair ({serveur}) : votre fournisseur, et quiconque sur le Wi-Fi, voit les noms des sites visités.{offre}{navigateur}{opportuniste}{windows_10}",
                "DNS questions leave unencrypted ({serveur}): your provider, and anyone on the Wi-Fi, sees the names of the sites you visit.{offre}{navigateur}{opportuniste}{windows_10}"
            ),
        ),
        ID,
    )
}

/// COM-TLS-001 : le certificat que le site de référence présente à cet ordinateur.
fn constat_tls(e: &Entree) -> Constat {
    const ID: &str = "COM-TLS-001";
    let site = "1.1.1.1";
    let constat = match &e.tls {
        Tls::NonDemande => impossible(
            CAT_TLS,
            tr!(
                "hors ligne : certificat du site de référence non lu",
                "offline: reference site certificate not read"
            ),
        ),
        Tls::Muet => impossible(
            CAT_TLS,
            tr!(
                "site de référence injoignable (hors ligne, ou portail Wi-Fi)",
                "reference site unreachable (offline, or Wi-Fi portal)"
            ),
        ),
        Tls::Refuse(raison) => {
            let raison = affichable(raison);
            impossible(
                CAT_TLS,
                &trf!(
                    "connexion HTTPS vers {site} refusée : certificat non reconnu par le système ({raison}), ce qui est bon signe si quelque chose l'intercepte ; un portail Wi-Fi fait pareil",
                    "HTTPS connection to {site} refused: certificate not recognised by the system ({raison}), a good sign if something intercepts it; a Wi-Fi portal does the same"
                ),
            )
        }
        Tls::Presente { noms: None, .. } | Tls::Presente { emetteur: None, .. } => impossible(
            CAT_TLS,
            tr!("certificat présenté illisible", "presented certificate unreadable"),
        ),
        Tls::Presente {
            emetteur: Some(emetteur),
            noms: Some(noms),
            ..
        } => {
            let nom = affichable(emetteur);
            match famille(noms) {
                Famille::Inspection => alerte(
                    CAT_TLS,
                    Niveau::Info,
                    trf!(
                        "Le HTTPS vers {site} est inspecté par un antivirus ou un filtre : le certificat vient de « {nom} ». Normal si vous l'avez installé ; il lit vos pages chiffrées.",
                        "HTTPS to {site} is inspected by an antivirus or a filter: the certificate comes from “{nom}”. Normal if you installed it; it reads your encrypted pages."
                    ),
                ),
                Famille::Developpement => alerte(
                    CAT_TLS,
                    Niveau::Moyen,
                    trf!(
                        "Le HTTPS vers {site} passe par une autorité de développement (« {nom} ») : un outil de test intercepte vos pages chiffrées.",
                        "HTTPS to {site} goes through a development authority (“{nom}”): a test tool intercepts your encrypted pages."
                    ),
                ),
                Famille::Autre if autorite_publique(noms) => ok(
                    CAT_TLS,
                    trf!(
                        "HTTPS vers {site} non intercepté : certificat émis par {nom}, une autorité publique.",
                        "HTTPS to {site} not intercepted: certificate issued by {nom}, a public authority."
                    ),
                ),
                Famille::Compromis | Famille::Interception | Famille::Autre => alerte(
                    CAT_TLS,
                    Niveau::Eleve,
                    trf!(
                        "Le HTTPS vers {site} est intercepté : le certificat vient de « {nom} », pas d'une autorité publique. Quelque chose entre vous et Internet lit vos pages chiffrées (antivirus, proxy, logiciel indésirable).",
                        "HTTPS to {site} is intercepted: the certificate comes from “{nom}”, not a public authority. Something between you and the Internet reads your encrypted pages (antivirus, proxy, unwanted software)."
                    ),
                )
                .manuel(
                    tr!(
                        "Si vous n'avez pas installé d'antivirus qui inspecte le web ni de proxy d'entreprise : retirez le certificat racine ajouté (le bilan les liste, certificats racine ajoutés) et désinstallez le programme qui l'a posé",
                        "If you did not install an antivirus that inspects the web nor a company proxy: remove the added root certificate (the check lists them, added root certificates) and uninstall the program that put it there"
                    ),
                    &[],
                ),
            }
        }
    };
    regle(constat, ID)
}

/// Un hôte du réseau local ou de cette machine : une exception pour lui (NAS, box, imprimante) n'est qu'une
/// information.
fn hote_local(hote: &str) -> bool {
    let h = hote.trim().to_lowercase();
    if let Ok(ip) = h.parse::<IpAddr>() {
        return du_reseau(ip);
    }
    h == "localhost"
        || !h.contains('.')
        || [
            ".local",
            ".lan",
            ".home",
            ".internal",
            ".localdomain",
            ".home.arpa",
            ".localhost",
        ]
        .iter()
        .any(|s| h.ends_with(s))
}

/// COM-TLS-002 : exceptions de certificat gardées par Firefox.
fn constat_exceptions(e: &Entree) -> Constat {
    const ID: &str = "COM-TLS-002";
    if e.exceptions.is_empty() {
        let message = if e.profils_firefox == 0 {
            tr!(
                "Aucun profil Firefox sur cet ordinateur : pas d'exception de certificat gardée (Chrome et Edge n'en gardent pas durablement).",
                "No Firefox profile on this computer: no certificate exception kept (Chrome and Edge keep none durably)."
            )
        } else {
            tr!(
                "Firefox ne garde aucune exception de certificat (Chrome et Edge n'en gardent pas durablement).",
                "Firefox keeps no certificate exception (Chrome and Edge keep none durably)."
            )
        };
        return regle(ok(CAT_TLS, message), ID);
    }
    let n = e.exceptions.len();
    let internet = e.exceptions.iter().any(|x| !hote_local(&x.hote));
    let mut hotes: Vec<String> = Vec::new();
    for x in &e.exceptions {
        let h = affichable(&format!("{}:{}", x.hote, x.port));
        if !hotes.contains(&h) {
            hotes.push(h);
        }
    }
    let plus = if hotes.len() > 5 {
        trf!(" et {} autres", " and {} more", hotes.len() - 5)
    } else {
        String::new()
    };
    hotes.truncate(5);
    let hotes = hotes.join(", ") + &plus;
    let navigateur = affichable(&e.exceptions[0].navigateur);
    let message = if internet {
        trf!(
            "{navigateur} garde {n} exception(s) de certificat ({hotes}) : un site a présenté un faux certificat et quelqu'un a cliqué « accepter le risque ». Pour un site d'Internet, c'est la trace d'une interception possible.",
            "{navigateur} keeps {n} certificate exception(s) ({hotes}): a site presented a wrong certificate and someone clicked “accept the risk”. For an Internet site, that is the trace of a possible interception."
        )
    } else {
        trf!(
            "{navigateur} garde {n} exception(s) de certificat pour votre réseau ({hotes}) : NAS, routeur ou imprimante au certificat maison, sans doute. Normal si c'est vous.",
            "{navigateur} keeps {n} certificate exception(s) for your network ({hotes}): a NAS, router or printer with a home-made certificate, most likely. Normal if it is you."
        )
    };
    let niveau = if internet { Niveau::Moyen } else { Niveau::Info };
    regle(
        alerte(CAT_TLS, niveau, message).manuel(
            tr!(
                "Firefox > Paramètres > Vie privée et sécurité > Certificats > Afficher > Serveurs : supprimez celles que vous n'avez pas voulues",
                "Firefox > Settings > Privacy and security > Certificates > View > Servers: delete the ones you did not want"
            ),
            &[],
        ),
        ID,
    )
}

/// COM-TLS-003 : racines ajoutées dans les magasins des navigateurs. Lu : les politiques qui en installent dans
/// Firefox. Non lu : le magasin NSS (cert9.db) des profils, qui demande NSS.
fn constats_racines_navigateurs(e: &Entree) -> Vec<Constat> {
    const ID: &str = "COM-TLS-003";
    let mut constats = Vec::new();
    for p in &e.politiques {
        let n = p.certificats.len();
        let fichier = &p.fichier;
        let liste = p.certificats.join(", ");
        let message = if n > 0 {
            trf!(
                "Une politique installe {n} certificat(s) dans Firefox ({fichier} : {liste}) : normal en entreprise ou à l'école ; sinon, une autorité ajoutée à votre insu, qui peut lire vos pages chiffrées.",
                "A policy installs {n} certificate(s) into Firefox ({fichier}: {liste}): normal at work or school; otherwise an authority added without your knowledge, able to read your encrypted pages."
            )
        } else {
            trf!(
                "Une politique fait confiance aux racines ajoutées au système dans Firefox ({fichier}) : les certificats racine ajoutés du bilan valent aussi pour lui.",
                "A policy makes Firefox trust the roots added to the system ({fichier}): the check's added root certificates apply to it too."
            )
        };
        constats.push(regle(alerte(CAT_TLS, Niveau::Info, message), ID));
    }
    let raison = if cfg!(target_os = "linux") {
        tr!(
            "magasin de certificats des navigateurs (cert9.db, NSS) non lisible sans NSS",
            "browser certificate store (cert9.db, NSS) not readable without NSS"
        )
    } else {
        tr!(
            "magasin de certificats de Firefox (cert9.db, NSS) non lisible sans NSS ; Chrome, Edge et Safari se fient au magasin du système, déjà vérifié",
            "Firefox certificate store (cert9.db, NSS) not readable without NSS; Chrome, Edge and Safari rely on the system store, already checked"
        )
    };
    constats.push(regle(impossible(CAT_TLS, raison), ID));
    constats
}

/// Le certificat du site de référence montre-t-il une interception (antivirus, proxy, outil de test) ?
fn interception_vue(tls: &Tls) -> bool {
    matches!(tls, Tls::Presente { noms: Some(noms), .. }
        if !(famille(noms) == Famille::Autre && autorite_publique(noms)))
}

/// COM-TLS-004 : l'administration de la box propose-t-elle un échange post-quantique ? Une information regroupée :
/// presque aucune box grand public n'en propose, le geste est une mise à jour du micrologiciel, et ce trafic reste
/// sur le réseau local.
fn constat_box_pq(e: &Entree) -> Constat {
    const ID: &str = "COM-TLS-004";
    let Some(services) = &e.routeur else {
        return regle(
            impossible(
                CAT_PQ,
                tr!(
                    "routeur absent du scan : son administration n'a pas été sondée pour l'échange post-quantique",
                    "router missing from the scan: its administration was not probed for post-quantum key exchange"
                ),
            ),
            ID,
        );
    };
    if services.is_empty() {
        return regle(
            sans_objet(
                CAT_PQ,
                Absence::Inactif,
                tr!(
                    "Administration du routeur en SSH ou en HTTPS non trouvée ouverte par le scan : rien à sonder pour l'échange post-quantique.",
                    "Router administration over SSH or HTTPS not found open by the scan: nothing to probe for post-quantum key exchange."
                ),
            ),
            ID,
        );
    }
    let liste = |garder: &dyn Fn(&Result<bool, Echec>) -> bool| -> Vec<&str> {
        services
            .iter()
            .filter(|(_, r)| garder(r))
            .map(|(n, _)| n.as_str())
            .collect()
    };
    let sans = liste(&|r| matches!(r, Ok(false)));
    let avec = liste(&|r| matches!(r, Ok(true)));
    let inconnus: Vec<String> = services
        .iter()
        .filter_map(|(n, r)| r.as_ref().err().map(|x| format!("{n} : {x}")))
        .collect();
    let non_verifies = if inconnus.is_empty() {
        String::new()
    } else {
        trf!(
            " Non vérifié : {}.",
            " Not checked: {}.",
            affichable(&inconnus.join(", "))
        )
    };
    let c = if !sans.is_empty() {
        alerte(
            CAT_PQ,
            Niveau::Info,
            trf!(
                "Routeur : son administration ({}) ne propose aucun échange de clés post-quantique.{non_verifies}",
                "Router: its administration ({}) offers no post-quantum key exchange.{non_verifies}",
                sans.join(", ")
            ),
        )
        .manuel(
            tr!(
                "Vérifier une mise à jour du micrologiciel du routeur ; ce trafic reste sur le réseau local, où le risque d'enregistrement est faible",
                "Check for a router firmware update; this traffic stays on the local network, where the risk of recording is low"
            ),
            &[],
        )
    } else if !inconnus.is_empty() {
        impossible(
            CAT_PQ,
            &trf!(
                "administration du routeur sondée sans réponse claire : {}",
                "router administration probed without a clear answer: {}",
                affichable(&inconnus.join(", "))
            ),
        )
    } else {
        ok(
            CAT_PQ,
            trf!(
                "Routeur : son administration ({}) propose un échange de clés post-quantique.",
                "Router: its administration ({}) offers a post-quantum key exchange.",
                avec.join(", ")
            ),
        )
    };
    regle(c, ID)
}

/// COM-TLS-005 : quelque chose sur le chemin vers Internet retire-t-il l'échange post-quantique ?
fn constat_chemin_pq(e: &Entree) -> Constat {
    const ID: &str = "COM-TLS-005";
    let site = SITE_PQ.0;
    let c = match (&e.pq_site, e.proxy) {
        (None, _) => impossible(
            CAT_PQ,
            tr!(
                "hors ligne : sonde post-quantique non envoyée",
                "offline: post-quantum probe not sent"
            ),
        ),
        (_, Some(true)) => impossible(
            CAT_PQ,
            tr!(
                "un proxy est réglé : la sonde, envoyée en direct, ne suit pas le chemin des navigateurs",
                "a proxy is set: the probe, sent directly, does not follow the browsers' path"
            ),
        ),
        (_, None) => impossible(
            CAT_PQ,
            tr!(
                "réglage du proxy illisible : la sonde, envoyée en direct, ne suit peut-être pas le chemin des navigateurs",
                "proxy setting unreadable: the probe, sent directly, may not follow the browsers' path"
            ),
        ),
        (Some(Ok(ReponsePq::Accepte)), _) => ok(
            CAT_PQ,
            trf!(
                "Rien ne retire l'échange de clés post-quantique entre cet ordinateur et {site}, vu depuis Vanguard (un antivirus qui n'inspecte que les navigateurs ne se voit pas d'ici).",
                "Nothing removes post-quantum key exchange between this computer and {site}, as seen from Vanguard (an antivirus that inspects only browsers cannot be seen from here)."
            ),
        ),
        (Some(Ok(ReponsePq::Refuse(_))), Some(false)) if interception_vue(&e.tls) => alerte(
            CAT_PQ,
            Niveau::Info,
            trf!(
                "Le HTTPS vers {site} est inspecté (voir le certificat présenté), et ce qui l'inspecte retire l'échange de clés post-quantique : le trafic enregistré sur le chemin serait lisible demain.",
                "HTTPS to {site} is inspected (see the presented certificate), and what inspects it removes post-quantum key exchange: traffic recorded on the way would be readable tomorrow."
            ),
        )
        .manuel(
            tr!(
                "Chercher une mise à jour de l'antivirus ou du filtre qui inspecte le HTTPS, ou couper son inspection du HTTPS",
                "Look for an update of the antivirus or filter that inspects HTTPS, or turn off its HTTPS inspection"
            ),
            &[],
        ),
        (Some(Ok(ReponsePq::Refuse(_))), _) => impossible(
            CAT_PQ,
            &trf!(
                "{site} refuse l'échange post-quantique depuis ce réseau, mais un seul site est sondé : le chemin ou le site lui-même, rien n'est conclu",
                "{site} refuses post-quantum key exchange from this network, but only one site is probed: the path or the site itself, nothing is concluded"
            ),
        ),
        (Some(Ok(ReponsePq::Autre)), _) => impossible(
            CAT_PQ,
            &trf!(
                "réponse TLS de {site} incomprise",
                "TLS answer from {site} not understood"
            ),
        ),
        (Some(Err(x)), _) => impossible(
            CAT_PQ,
            &trf!(
                "sonde post-quantique vers {site} : {x}",
                "post-quantum probe to {site}: {x}"
            ),
        ),
    };
    regle(c, ID)
}

/// Les constats du domaine, dans l'ordre des règles : DNS-002, 003, 004, 005, TLS-001, 002, 003, 004, 005.
pub fn constats(e: &Entree) -> Vec<Constat> {
    let mut constats = constats_bail(e);
    constats.push(constat_chiffrement(e));
    constats.extend(constats_divergence(e));
    constats.push(constat_dnssec(e));
    constats.push(constat_tls(e));
    constats.push(constat_exceptions(e));
    constats.extend(constats_racines_navigateurs(e));
    constats.push(constat_box_pq(e));
    constats.push(constat_chemin_pq(e));
    constats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::certificats;

    fn ip(t: &str) -> IpAddr {
        t.parse().unwrap()
    }

    fn v4(t: &str) -> Ipv4Addr {
        t.parse().unwrap()
    }

    fn reponse(adresses: &[&str], rcode: u8, ad: bool) -> Reponse {
        Reponse {
            rcode,
            ad,
            ra: true,
            tc: false,
            enregistrements: adresses
                .iter()
                .map(|a| super::super::dns_client::Enregistrement {
                    nom: "x".into(),
                    ttl: 60,
                    donnees: Donnees::A(v4(a)),
                })
                .collect(),
        }
    }

    /// Les réponses justes d'un résolveur aux trois noms stables.
    fn justes() -> Vec<(&'static str, Option<Reponse>)> {
        NOMS_STABLES
            .iter()
            .map(|(nom, attendues)| (*nom, Some(reponse(&[&attendues[0].to_string()], 0, false))))
            .collect()
    }

    fn mesure(role: Role, serveur: &str, reponses: Vec<(&'static str, Option<Reponse>)>) -> Mesure {
        Mesure {
            role,
            serveur: ip(serveur),
            reponses,
            inexistant: Some(reponse(&[], 3, false)),
        }
    }

    fn bail(dns: &[&str]) -> Bail {
        Bail {
            interface: Some("wlan0".into()),
            source: Some(bail::Source::NetworkManager),
            adresse: Some(ip("10.0.0.42")),
            serveur: Some(ip("10.0.0.1")),
            passerelle: Some(ip("10.0.0.1")),
            dns: dns.iter().map(|d| ip(d)).collect(),
            domaine: None,
            expire: None,
        }
    }

    /// Une maison ordinaire, en ligne : la box distribue le DNS du fournisseur, cet ordinateur le suit, tout
    /// répond juste, DNSSEC non validé, certificat public, pas d'exception.
    fn maison() -> Entree {
        let mut e = Entree::vide(false);
        e.baux = Ok(vec![bail(&["203.0.113.53"])]);
        e.utilise = Some(Utilise {
            serveurs: vec![(ip("203.0.113.53"), false)],
            chiffre: Some(false),
            resolveur_local: None,
        });
        e.passerelle = Some(ip("10.0.0.1"));
        e.mesures = vec![
            mesure(Role::Utilise, "203.0.113.53", justes()),
            mesure(Role::Public("Cloudflare"), "1.1.1.1", justes()),
            mesure(Role::Public("Quad9"), "9.9.9.9", justes()),
        ];
        e.dnssec = vec![Dnssec {
            role: Role::Utilise,
            serveur: ip("203.0.113.53"),
            signe: Some(reponse(&["198.51.100.7"], 0, false)),
            casse: Some(reponse(&["198.51.100.8"], 0, false)),
            casse_hasard: Some(reponse(&["198.51.100.9"], 0, false)),
        }];
        e.ddr = vec![Ddr {
            role: Role::Utilise,
            serveur: ip("203.0.113.53"),
            reponse: Some(reponse(&[], 3, false)),
        }];
        e.tls = presente("Google Trust Services WE1");
        e.profils_firefox = 1;
        e
    }

    /// Un certificat présenté dont l'émetteur porte ces noms (organisation puis nom).
    fn presente(noms: &str) -> Tls {
        Tls::Presente {
            emetteur: Some(noms.split(' ').next().unwrap_or(noms).to_string()),
            noms: Some(noms.to_string()),
            sujet: Some("cloudflare-dns.com".into()),
            code: 200,
        }
    }

    fn par_regle<'a>(constats: &'a [Constat], id: &str) -> Vec<&'a Constat> {
        constats.iter().filter(|c| c.regle == id).collect()
    }

    #[test]
    fn maison_ordinaire() {
        let c = constats(&maison());
        assert!(c.iter().all(|c| !c.regle.is_empty()), "chaque constat porte sa règle");
        assert!(c.iter().all(|c| !crate::ui::contient_un_piege(&c.message)));
        let bail = par_regle(&c, "COM-DNS-002");
        assert_eq!(bail.len(), 1, "cet ordinateur suit le bail : un seul constat");
        assert_eq!(bail[0].probleme, Some(Niveau::Info));
        assert!(bail[0].message.contains("203.0.113.53") && bail[0].message.contains("fournisseur"));
        let chiffre = par_regle(&c, "COM-DNS-003");
        assert_eq!(chiffre[0].probleme, Some(Niveau::Info));
        assert!(chiffre[0].message.contains("en clair") && chiffre[0].message.contains("Ni le routeur"));
        let divergence = par_regle(&c, "COM-DNS-004");
        assert_eq!(divergence.len(), 1);
        assert_eq!(divergence[0].probleme, None, "{}", divergence[0].message);
        assert!(divergence[0].message.contains("3 noms stables"));
        let dnssec = par_regle(&c, "COM-DNS-005");
        assert_eq!(dnssec[0].probleme, Some(Niveau::Info));
        assert!(dnssec[0].message.contains("ne vérifie pas"));
        let tls = par_regle(&c, "COM-TLS-001");
        assert_eq!(tls[0].probleme, None, "{}", tls[0].message);
        assert!(tls[0].message.contains("émis par Google,"), "{}", tls[0].message);
        let exceptions = par_regle(&c, "COM-TLS-002");
        assert_eq!(exceptions[0].probleme, None);
        let racines = par_regle(&c, "COM-TLS-003");
        assert_eq!(racines.len(), 1);
        assert!(!racines[0].verifie, "cert9.db non lu : non vérifié");
    }

    #[test]
    fn hors_ligne_tout_non_verifie_sauf_les_fichiers() {
        let mut e = Entree::vide(true);
        e.baux = Err("baux DHCP réservés à root (/var/lib/dhcpcd)".into());
        let c = constats(&e);
        for id in ["COM-DNS-002", "COM-DNS-004", "COM-DNS-005", "COM-TLS-001"] {
            let liste = par_regle(&c, id);
            assert!(!liste.is_empty() && liste.iter().all(|c| !c.verifie), "{id}");
        }
        assert!(par_regle(&c, "COM-DNS-002")[0].message.contains("réservés à root"));
        // Configuration illisible : le chiffrement n'est pas conclu non plus.
        assert!(!par_regle(&c, "COM-DNS-003")[0].verifie);
        // Les fichiers, eux, se lisent hors ligne : pas de Firefox, pas d'exception.
        assert!(par_regle(&c, "COM-TLS-002")[0].verifie);
        assert!(par_regle(&c, "COM-TLS-002")[0].message.contains("Aucun profil Firefox"));
    }

    #[test]
    fn dns_du_bail_et_de_cet_ordinateur() {
        // La box elle-même : information.
        let mut e = maison();
        e.baux = Ok(vec![bail(&["10.0.0.1"])]);
        e.utilise.as_mut().unwrap().serveurs = vec![(ip("10.0.0.1"), false)];
        let c = par_regle(&constats(&e), "COM-DNS-002")
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(c.len(), 1);
        assert!(
            c[0].message.contains("Le routeur (10.0.0.1) résout"),
            "{}",
            c[0].message
        );
        // Un service connu distribué : rien à redire.
        e.baux = Ok(vec![bail(&["9.9.9.9", "149.112.112.112"])]);
        let c = constats(&e);
        let b = par_regle(&c, "COM-DNS-002");
        assert_eq!(b[0].probleme, None);
        assert!(b[0].message.contains("Quad9"));
        // Un Pi-hole du réseau distribué : information ; cet ordinateur sur Cloudflare à la main : un choix.
        e.baux = Ok(vec![bail(&["10.0.0.53"])]);
        e.utilise.as_mut().unwrap().serveurs = vec![(ip("1.1.1.1"), true)];
        let c = constats(&e);
        let b = par_regle(&c, "COM-DNS-002");
        assert_eq!(b.len(), 2);
        assert!(b[0].message.contains("Pi-hole"));
        assert_eq!(b[1].probleme, None);
        assert!(b[1].message.contains("Cloudflare"));
        // Cet ordinateur sur un serveur inconnu d'Internet, réglé à la main, pas celui du bail : Moyen.
        e.utilise.as_mut().unwrap().serveurs = vec![(ip("198.51.100.99"), true)];
        let c = constats(&e);
        let b = par_regle(&c, "COM-DNS-002");
        assert_eq!(b[1].probleme, Some(Niveau::Moyen));
        assert!(b[1].message.contains("réglé à la main") && b[1].message.contains("198.51.100.99"));
        assert!(b[1].correctif.as_ref().is_some_and(|k| !k.automatique));
        // NextDNS sur cet ordinateur : le bail ne le concerne pas.
        e.utilise = Some(Utilise {
            serveurs: vec![(ip("127.0.0.1"), false)],
            chiffre: Some(true),
            resolveur_local: Some("NextDNS"),
        });
        let c = constats(&e);
        assert_eq!(par_regle(&c, "COM-DNS-002").len(), 1);
        let chiffre = par_regle(&c, "COM-DNS-003");
        assert_eq!(chiffre[0].probleme, None);
        assert!(chiffre[0].message.contains("NextDNS chiffre"));
        // Aucun DNS dans le bail.
        e.baux = Ok(vec![bail(&[])]);
        assert!(
            par_regle(&constats(&e), "COM-DNS-002")[0]
                .message
                .contains("aucun serveur DNS")
        );
        // Deux cartes : le bail de la route par défaut compte, pas celui de l'autre réseau.
        let mut autre = bail(&["192.168.7.1"]);
        autre.passerelle = Some(ip("192.168.7.1"));
        e.baux = Ok(vec![autre, bail(&["9.9.9.9"])]);
        assert!(par_regle(&constats(&e), "COM-DNS-002")[0].message.contains("Quad9"));
    }

    #[test]
    fn divergence_filtrage_et_portail() {
        let mut e = maison();
        // Deux noms réécrits vers des adresses différentes : Élevé.
        let mut faux = justes();
        faux[0].1 = Some(reponse(&["198.51.100.1"], 0, false));
        faux[1].1 = Some(reponse(&["198.51.100.2"], 0, false));
        e.mesures[0] = mesure(Role::Utilise, "203.0.113.53", faux);
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d[0].probleme, Some(Niveau::Eleve));
        assert!(
            d[0].message.contains("198.51.100.1") && d[0].message.contains("1.1.1.1"),
            "{}",
            d[0].message
        );
        assert!(d[0].message.contains("réécrit"));
        // Tous vers la même adresse : portail ou détournement complet.
        let mut portail = justes();
        for (_, r) in &mut portail {
            *r = Some(reponse(&["10.0.0.1"], 0, false));
        }
        e.mesures[0] = mesure(Role::Utilise, "203.0.113.53", portail);
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d[0].probleme, Some(Niveau::Eleve));
        assert!(d[0].message.contains("portail"));
        // Un seul écart : information seulement.
        let mut un = justes();
        un[2].1 = Some(reponse(&["198.51.100.3"], 0, false));
        e.mesures[0] = mesure(Role::Utilise, "203.0.113.53", un);
        assert_eq!(par_regle(&constats(&e), "COM-DNS-004")[0].probleme, Some(Niveau::Info));
        // Bloqué (0.0.0.0, NXDOMAIN) : filtre volontaire.
        let mut filtre = justes();
        filtre[0].1 = Some(reponse(&["0.0.0.0"], 0, false));
        filtre[1].1 = Some(reponse(&[], 3, false));
        e.mesures[0] = mesure(Role::Utilise, "203.0.113.53", filtre);
        let d = constats(&e);
        let d = par_regle(&d, "COM-DNS-004");
        assert_eq!(d[0].probleme, Some(Niveau::Info));
        assert!(d[0].message.contains("filtre volontaire") && d[0].message.contains("one.one.one.one"));
        // Le service a changé d'adresse : les publics donnent la nouvelle, le résolveur aussi : conforme.
        let mut nouvelle = justes();
        nouvelle[1].1 = Some(reponse(&["198.51.100.42"], 0, false));
        e.mesures[0] = mesure(Role::Utilise, "203.0.113.53", nouvelle.clone());
        e.mesures[1] = mesure(Role::Public("Cloudflare"), "1.1.1.1", nouvelle);
        assert_eq!(par_regle(&constats(&e), "COM-DNS-004")[0].probleme, None);
        // Le résolveur utilisé muet, les publics aussi : port 53 fermé, non vérifié.
        let muet = NOMS_STABLES.iter().map(|(n, _)| (*n, None)).collect::<Vec<_>>();
        e.mesures = vec![
            mesure(Role::Utilise, "203.0.113.53", muet.clone()),
            mesure(Role::Public("Cloudflare"), "1.1.1.1", muet.clone()),
            mesure(Role::Public("Quad9"), "9.9.9.9", muet),
        ];
        let d = constats(&e);
        let d = par_regle(&d, "COM-DNS-004");
        assert!(!d[0].verifie && d[0].message.contains("port 53"));
        // Aucune mesure du résolveur utilisé : non vérifié, dit.
        e.mesures.clear();
        assert!(!par_regle(&constats(&e), "COM-DNS-004")[0].verifie);
    }

    #[test]
    fn dns_du_bail_qui_reecrit() {
        let mut e = maison();
        e.utilise = Some(Utilise {
            serveurs: vec![(ip("1.1.1.1"), true)],
            chiffre: None,
            resolveur_local: None,
        });
        e.mesures[0] = mesure(Role::Utilise, "1.1.1.1", justes());
        let mut faux = justes();
        faux[0].1 = Some(reponse(&["198.51.100.1"], 0, false));
        faux[2].1 = Some(reponse(&["198.51.100.2"], 0, false));
        e.mesures.push(mesure(Role::Bail, "203.0.113.53", faux));
        let c = constats(&e);
        let b = par_regle(&c, "COM-DNS-002");
        assert_eq!(b[0].probleme, Some(Niveau::Moyen), "{}", b[0].message);
        assert!(b[0].message.contains("réécrit des réponses"));
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].probleme, None);
        assert_eq!(d[1].probleme, Some(Niveau::Eleve));
        assert!(d[1].message.contains("tout le réseau local"));
    }

    /// Un fil de mesure qui tombe n'emporte plus sa mesure en silence : le résolveur est rendu avec son rôle, puis jugé
    /// non vérifié pour cette raison. Avant, la mesure du DNS de la box disparaissait sans constat, et son contrôle de
    /// réécriture avec elle ; le DNS utilisé, lui, était dit « non interrogeable d'ici ».
    #[test]
    fn mesure_interrompue_dite_non_verifiee() {
        let cibles = [
            (Role::Utilise, ip("1.1.1.1")),
            (Role::Bail, ip("203.0.113.53")),
            (Role::Public("Quad9"), ip("9.9.9.9")),
        ];
        let resultats = mesurer(&cibles, |role, serveur| {
            assert!(crate::journal::sous_garde(), "mesure hors de toute garde");
            assert!(role != Role::Bail, "réponse illisible");
            serveur
        });
        assert_eq!(
            resultats,
            [
                Ok(ip("1.1.1.1")),
                Err((Role::Bail, ip("203.0.113.53"))),
                Ok(ip("9.9.9.9"))
            ]
        );
        // Le DNS de la box sans mesure : non vérifié, avec la vraie raison.
        let mut e = maison();
        e.utilise = Some(Utilise {
            serveurs: vec![(ip("1.1.1.1"), true)],
            chiffre: None,
            resolveur_local: None,
        });
        e.mesures[0] = mesure(Role::Utilise, "1.1.1.1", justes());
        e.interrompues = vec![(Role::Bail, ip("203.0.113.53"))];
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d.len(), 2);
        assert!(d[0].verifie);
        assert!(
            !d[1].verifie
                && d[1].message.contains("routeur distribue (203.0.113.53)")
                && d[1].message.contains("interrompue"),
            "{}",
            d[1].message
        );
        // Le DNS utilisé sans mesure : la même raison, et plus « non interrogeable d'ici » ; DNSSEC de même.
        e.mesures.remove(0);
        e.dnssec.clear();
        e.interrompues = vec![(Role::Utilise, ip("1.1.1.1"))];
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d.len(), 1);
        assert!(
            !d[0].verifie && d[0].message.contains("interrompue") && !d[0].message.contains("interrogeable"),
            "{}",
            d[0].message
        );
        let s = par_regle(&c, "COM-DNS-005");
        assert!(
            !s[0].verifie && s[0].message.contains("interrompue"),
            "{}",
            s[0].message
        );
    }

    /// Un résolveur qui répond juste pour les noms connus mais donne une adresse à un nom inventé à l'instant :
    /// il réécrit les noms inexistants, ce n'est pas « aucune réécriture ».
    #[test]
    fn nom_invente_reecrit() {
        let mut e = maison();
        let c = constats(&e);
        assert!(par_regle(&c, "COM-DNS-004")[0].message.contains("noms testés"));
        e.mesures[0].inexistant = Some(reponse(&["203.0.113.80"], 0, false));
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-004");
        assert_eq!(d[0].probleme, Some(Niveau::Moyen));
        assert!(d[0].message.contains("203.0.113.80"), "{}", d[0].message);
        // Deux noms inventés de suite ne se ressemblent pas.
        assert_ne!(etiquette_au_hasard(), etiquette_au_hasard());
        assert!(etiquette_au_hasard().chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn dnssec_valide_ou_non() {
        let mut e = maison();
        e.dnssec[0].signe = Some(reponse(&["198.51.100.7"], 0, true));
        e.dnssec[0].casse = Some(reponse(&[], 2, false));
        e.dnssec[0].casse_hasard = Some(reponse(&[], 2, false));
        let c = constats(&e);
        assert_eq!(par_regle(&c, "COM-DNS-005")[0].probleme, None);
        assert!(par_regle(&c, "COM-DNS-005")[0].message.contains("valide DNSSEC"));
        // Un résolveur hostile préparé aux noms connus : AD sur le nom signé, refus du nom cassé connu, mais un nom
        // tiré au hasard dans la même zone passe. Pas un feu vert.
        e.dnssec[0].casse_hasard = Some(reponse(&["198.51.100.9"], 0, false));
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-005");
        assert_eq!(d[0].probleme, Some(Niveau::Info));
        assert!(d[0].message.contains("tiré au hasard"), "{}", d[0].message);
        // Il ne répond pas au nom tiré au hasard : non confirmé, jamais vert.
        e.dnssec[0].casse_hasard = None;
        assert!(!par_regle(&constats(&e), "COM-DNS-005")[0].verifie);
        e.dnssec[0].casse_hasard = Some(reponse(&[], 2, false));
        // AD mais la signature cassée passe : ne vérifie pas vraiment.
        e.dnssec[0].casse = Some(reponse(&["198.51.100.8"], 0, false));
        let c = constats(&e);
        assert!(
            par_regle(&c, "COM-DNS-005")[0]
                .message
                .contains("accepte une signature cassée")
        );
        // Tronqué : la box ne laisse pas passer EDNS.
        e.dnssec[0].signe.as_mut().unwrap().tc = true;
        let c = constats(&e);
        let d = par_regle(&c, "COM-DNS-005");
        assert!(!d[0].verifie && d[0].message.contains("EDNS"));
        // Aucune réponse aux questions DNSSEC.
        e.dnssec[0].signe = None;
        e.dnssec[0].casse = None;
        assert!(!par_regle(&constats(&e), "COM-DNS-005")[0].verifie);
        e.dnssec.clear();
        assert!(!par_regle(&constats(&e), "COM-DNS-005")[0].verifie);
    }

    #[test]
    fn chiffrement_et_ddr() {
        let mut e = maison();
        // La box annonce DoT et DoH par DDR.
        let svcb = Reponse {
            rcode: 0,
            ad: false,
            ra: true,
            tc: false,
            enregistrements: vec![super::super::dns_client::Enregistrement {
                nom: NOM_DDR.into(),
                ttl: 60,
                donnees: Donnees::Svcb {
                    priorite: 1,
                    cible: "dns.exemple\u{202e}.invalid".into(),
                    alpn: vec!["dot".into(), "h2".into()],
                    port: Some(853),
                    dohpath: Some("/dns-query".into()),
                    indices: vec![],
                },
            }],
        };
        e.ddr[0].reponse = Some(svcb);
        e.navigateurs_doh = vec![("Firefox".into(), Some(true)), ("Zen".into(), None)];
        let c = constats(&e);
        let m = &par_regle(&c, "COM-DNS-003")[0];
        assert_eq!(m.probleme, Some(Niveau::Info));
        assert!(
            m.message.contains("DoT, DoH (h2) vers dns.exemple�.invalid"),
            "{}",
            m.message
        );
        assert!(m.message.contains("Firefox chiffre les siennes seulement"));
        assert!(!crate::ui::contient_un_piege(&m.message));
        // DoT de systemd-resolved dans sa configuration.
        e.configuration.resolved = Some(bail::Resolved {
            dns_over_tls: Some("yes".into()),
            dnssec: None,
        });
        let c = constats(&e);
        assert_eq!(par_regle(&c, "COM-DNS-003")[0].probleme, None);
        assert!(par_regle(&c, "COM-DNS-003")[0].message.contains("DNSOverTLS=yes"));
        // DoH de Windows déclaré pour le serveur utilisé.
        e.configuration.resolved = None;
        e.configuration.doh_windows = vec![bail::DohWindows {
            serveur: "203.0.113.53".into(),
            drapeaux: 1,
            modele: Some("https://dns.exemple.invalid/dns-query".into()),
        }];
        let c = constats(&e);
        assert!(par_regle(&c, "COM-DNS-003")[0].message.contains("DoH de Windows"));
        // Déclaré pour un autre serveur : en clair quand même.
        e.configuration.doh_windows[0].serveur = "9.9.9.9".into();
        assert_eq!(par_regle(&constats(&e), "COM-DNS-003")[0].probleme, Some(Niveau::Info));
    }

    #[test]
    fn certificat_presente_juge() {
        let mut e = maison();
        for (emetteur, niveau, mot) in [
            ("Let's Encrypt R11", None, "autorité publique"),
            ("DigiCert Inc", None, "autorité publique"),
            (
                "Kaspersky Anti-Virus Personal Root Certificate",
                Some(Niveau::Info),
                "antivirus",
            ),
            ("mitmproxy", Some(Niveau::Eleve), "intercepté"),
            ("Superfish, Inc.", Some(Niveau::Eleve), "intercepté"),
            ("Proxy Entreprise CA", Some(Niveau::Eleve), "intercepté"),
            ("mkcert alice@portable", Some(Niveau::Moyen), "développement"),
        ] {
            e.tls = presente(emetteur);
            let c = constats(&e);
            let t = &par_regle(&c, "COM-TLS-001")[0];
            assert_eq!(t.probleme, niveau, "{emetteur} : {}", t.message);
            assert!(t.message.contains(mot), "{emetteur} : {}", t.message);
        }
        let c = constats(&e);
        assert!(par_regle(&c, "COM-TLS-001")[0].correctif.is_none());
        e.tls = Tls::Presente {
            emetteur: Some("Proxy\x1b[2K Entreprise".into()),
            noms: Some("Proxy\x1b[2K Entreprise".into()),
            sujet: None,
            code: 200,
        };
        let c = constats(&e);
        let t = &par_regle(&c, "COM-TLS-001")[0];
        assert!(t.correctif.is_some() && !crate::ui::contient_un_piege(&t.message));
        for (tls, mot) in [
            (
                Tls::Refuse("invalid peer certificate: UnknownIssuer".into()),
                "bon signe",
            ),
            (Tls::Muet, "injoignable"),
            (Tls::NonDemande, "hors ligne"),
            (
                Tls::Presente {
                    emetteur: None,
                    noms: None,
                    sujet: None,
                    code: 200,
                },
                "illisible",
            ),
        ] {
            e.tls = tls;
            let c = constats(&e);
            let t = &par_regle(&c, "COM-TLS-001")[0];
            assert!(!t.verifie && t.message.contains(mot), "{}", t.message);
        }
    }

    #[test]
    fn exceptions_de_firefox() {
        let texte = "# PSM Certificate Override Settings file\n# This is a generated file!  Do not edit.\n\
                     www.exemple.invalid:443:^privateBrowsingId=1\tOID.2.16.840.1.101.3.4.2.1\tAB:CD\tU\tAAAA\n\
                     nas.local:5001:\tOID.2.16.840.1.101.3.4.2.1\tAB:CD\tMU\tAAAA\n\
                     10.0.0.1:443\tOID.2.16.840.1.101.3.4.2.1\tAB:CD\tT\tAAAA\n\
                     [fd00::1]:443\tOID.2.16.840.1.101.3.4.2.1\tAB:CD\tU\n\
                     ligne sans tabulation\n\
                     mauvais:port\tx\ty\tz\n";
        let lues = lire_exceptions(texte);
        assert_eq!(
            lues,
            [
                ("www.exemple.invalid".to_string(), 443, "U".to_string()),
                ("nas.local".into(), 5001, "MU".into()),
                ("10.0.0.1".into(), 443, "T".into()),
                ("fd00::1".into(), 443, "U".into()),
            ]
        );
        assert!(hote_local("nas.local") && hote_local("10.0.0.1") && hote_local("fd00::1") && hote_local("freebox"));
        assert!(!hote_local("www.exemple.invalid") && !hote_local("203.0.113.7"));
        let mut e = maison();
        e.exceptions = lues
            .iter()
            .map(|(h, p, d)| Exception {
                navigateur: "Firefox".into(),
                hote: h.clone(),
                port: *p,
                drapeaux: d.clone(),
            })
            .collect();
        let c = constats(&e);
        let x = &par_regle(&c, "COM-TLS-002")[0];
        assert_eq!(x.probleme, Some(Niveau::Moyen));
        assert!(
            x.message.contains("4 exception") && x.message.contains("www.exemple.invalid:443"),
            "{}",
            x.message
        );
        assert!(x.correctif.is_some());
        // Seulement des hôtes du réseau : information.
        e.exceptions.remove(0);
        let c = constants_locaux(&e);
        assert_eq!(c.probleme, Some(Niveau::Info));
        assert!(c.message.contains("votre réseau"));
        // Un hôte piégé reste inoffensif à l'écran.
        e.exceptions.push(Exception {
            navigateur: "Firefox".into(),
            hote: "faux\x1b]52;c;eA==\x07.invalid".into(),
            port: 443,
            drapeaux: String::new(),
        });
        let c = constats(&e);
        assert!(!crate::ui::contient_un_piege(&par_regle(&c, "COM-TLS-002")[0].message));
    }

    fn constants_locaux(e: &Entree) -> Constat {
        constat_exceptions(e)
    }

    #[test]
    fn politiques_et_preferences_de_firefox() {
        let politique = r#"{"policies": {"Certificates": {"Install": ["/etc/pki/ca.pem", "entreprise.der"], "ImportEnterpriseRoots": true}, "DontCheckDefaultBrowser": true}}"#;
        assert_eq!(
            lire_politique(politique),
            Some((
                vec!["/etc/pki/ca.pem".to_string(), "entreprise.der".to_string()],
                Some(true)
            ))
        );
        assert_eq!(
            lire_politique(r#"{"policies": {"DontCheckDefaultBrowser": true}}"#),
            None
        );
        assert_eq!(lire_politique("pas du json"), None);
        assert_eq!(doh_firefox("user_pref(\"network.trr.mode\", 2);\n"), Some(true));
        assert_eq!(doh_firefox("user_pref(\"network.trr.mode\", 5);\n"), Some(false));
        assert_eq!(doh_firefox("user_pref(\"autre\", 5);\n"), None);
        let mut e = maison();
        e.politiques = vec![Politique {
            fichier: "/etc/firefox/policies/policies.json".into(),
            certificats: vec!["entreprise.der".into()],
            racines_du_systeme: Some(true),
        }];
        let c = constats(&e);
        let r = par_regle(&c, "COM-TLS-003");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].probleme, Some(Niveau::Info));
        assert!(r[0].message.contains("entreprise.der"));
        assert!(!r[1].verifie);
    }

    /// Le certificat de test de certificats.rs : autosigné, « CN=Vanguard Test CA, O=Vanguard » (openssl req -x509).
    const PEM: &str = "MIIBsTCCAVegAwIBAgIUNk+0eAFwLwngOVYPiSUQLdrH6QAwCgYIKoZIzj0EAwIw
LjEZMBcGA1UEAwwQVmFuZ3VhcmQgVGVzdCBDQTERMA8GA1UECgwIVmFuZ3VhcmQw
HhcNMjYxMDE5MTUzMjQ5WhcNMzYxMDE2MTUzMjQ5WjAuMRkwFwYDVQQDDBBWYW5n
dWFyZCBUZXN0IENBMREwDwYDVQQKDAhWYW5ndWFyZDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABO6li7wNBvG58cVvUAO8x8MbwLw6+sJSlHQQEF3QihB7tNaTrLHI
1Kjunu34Azac9PL2Vl0qSCQxM6BKoZOLuvajUzBRMB0GA1UdDgQWBBQLNRnjyYUO
MUE4FCSskJprIu4RAzAfBgNVHSMEGDAWgBQLNRnjyYUOMUE4FCSskJprIu4RAzAP
BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIAw1C4ASo9mBvyoQbkIv
zFjhVZCJTZyJMc8UUk87nyaCAiEAwoEfebCe1+tJZhE4ypL4i0uaG6GD06Nd39my
xo1zjuQ=";

    #[test]
    fn emetteur_d_un_certificat() {
        let der = certificats::base64(PEM).unwrap();
        assert_eq!(emetteur(&der).as_deref(), Some("Vanguard"));
        assert_eq!(noms_emetteur(&der).as_deref(), Some("Vanguard Vanguard Test CA"));
        assert_eq!(certificats::sujet(&der).as_deref(), Some("Vanguard Test CA"));
        assert_eq!(emetteur(b"pas un certificat"), None);
        assert!(autorite_publique("Google Trust Services") && autorite_publique("Let's Encrypt"));
        assert!(!autorite_publique("Vanguard"));
    }

    #[test]
    fn post_quantique_de_la_box_et_du_chemin() {
        use crate::modele::{Etat, Raison};
        let mut e = maison();
        // Box absente du scan : non vérifié ; aucun port d'administration : sans objet.
        let c = constats(&e);
        assert!(!par_regle(&c, "COM-TLS-004")[0].verifie);
        e.routeur = Some(Vec::new());
        assert_eq!(
            par_regle(&constats(&e), "COM-TLS-004")[0].etat(),
            Etat::SansObjet(Absence::Inactif)
        );
        // Un seul constat regroupé, en information, même avec plusieurs services.
        e.routeur = Some(vec![
            ("SSH 22".into(), Ok(false)),
            ("HTTPS 443".into(), Ok(false)),
            ("HTTPS 8443".into(), Err(Echec::new("audit/tls-pq", Raison::Delai))),
        ]);
        let c = constats(&e);
        let r = par_regle(&c, "COM-TLS-004");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].probleme, Some(Niveau::Info));
        assert!(
            r[0].message.contains("SSH 22, HTTPS 443") && r[0].message.contains("8443"),
            "{}",
            r[0].message
        );
        assert!(r[0].correctif.as_ref().is_some_and(|k| !k.automatique));
        e.routeur = Some(vec![("SSH 22".into(), Ok(true))]);
        assert_eq!(par_regle(&constats(&e), "COM-TLS-004")[0].probleme, None);
        e.routeur = Some(vec![(
            "HTTPS 443".into(),
            Err(Echec::new("audit/tls-pq", Raison::Delai)),
        )]);
        assert!(!par_regle(&constats(&e), "COM-TLS-004")[0].verifie);
        // Le chemin : hors ligne, accepté, refusé sans interception vue (un seul site : non vérifié), refusé
        // derrière une inspection vue au certificat (information), proxy réglé (non vérifié).
        let chemin = |e: &Entree| {
            let c = constats(e);
            let x = par_regle(&c, "COM-TLS-005")[0].clone();
            (x.verifie, x.probleme, x.message)
        };
        let (verifie, _, _) = chemin(&e);
        assert!(!verifie, "hors ligne");
        e.pq_site = Some(Ok(ReponsePq::Accepte));
        let (verifie, probleme, message) = chemin(&e);
        assert!(verifie && probleme.is_none());
        assert!(
            message.contains("Vanguard"),
            "jamais « le chemin est sain » : {message}"
        );
        // Proxy illisible : la sonde ne suit peut-être pas le chemin des navigateurs, rien n'est conclu.
        e.proxy = None;
        assert!(!chemin(&e).0, "proxy illisible");
        // Le proxy du bureau Linux, que les navigateurs suivent.
        assert!(proxy_du_bureau(Some("'manual'\n"), None) && proxy_du_bureau(Some("'auto'"), None));
        assert!(proxy_du_bureau(None, Some("[Proxy Settings]\nProxyType=1\n")));
        assert!(!proxy_du_bureau(
            Some("'none'\n"),
            Some("[Proxy Settings]\nProxyType=0\n")
        ));
        assert!(!proxy_du_bureau(None, None) && !proxy_du_bureau(Some(""), Some("ProxyType=abc")));
        e.proxy = Some(false);
        e.pq_site = Some(Ok(ReponsePq::Refuse(40)));
        assert!(!chemin(&e).0, "un seul site sondé : rien n'est conclu");
        e.tls = presente("Kaspersky Web Anti-Virus Personal Root");
        let (verifie, probleme, _) = chemin(&e);
        assert!(verifie && probleme == Some(Niveau::Info));
        e.proxy = Some(true);
        assert!(!chemin(&e).0, "proxy réglé");
        e.proxy = Some(false);
        e.pq_site = Some(Ok(ReponsePq::Autre));
        assert!(!chemin(&e).0);
        e.pq_site = Some(Err(Echec::new("audit/tls-pq", Raison::Delai)));
        assert!(!chemin(&e).0);
        assert!(constats(&e).iter().all(|c| !crate::ui::contient_un_piege(&c.message)));
    }

    /// À la demande (`cargo test -- --ignored --nocapture montrer`), pour une passe sur une vraie machine : ce que
    /// le domaine a lu et ce qu'il en conclut, en lecture seule.
    #[test]
    #[ignore = "montre l'état réel de cette machine, à lancer à la main"]
    fn montrer_les_constats_reels() {
        let e = entree(None, None);
        println!("{e:#?}");
        for c in constats(&e) {
            println!("[{}] {:?} vérifié={} : {}", c.regle, c.probleme, c.verifie, c.message);
        }
    }

    /// La vraie acquisition sur cette machine, en lecture seule : bornée, sans plantage ; hors ligne, rien ne part et
    /// tout ce qui dépend du réseau est dit non vérifié.
    #[test]
    fn acquisition_reelle_bornee() {
        let debut = std::time::Instant::now();
        let e = entree(None, None);
        let c = constats(&e);
        assert!(debut.elapsed() < Duration::from_secs(45), "{:?}", debut.elapsed());
        assert!(c.len() >= 9, "{}", c.len());
        assert!(c.iter().all(|c| !c.message.is_empty() && !c.regle.is_empty()));
        if e.hors_ligne {
            assert!(e.mesures.is_empty() && e.tls == Tls::NonDemande && e.pq_site.is_none());
            for id in ["COM-DNS-004", "COM-DNS-005", "COM-TLS-001", "COM-TLS-005"] {
                assert!(par_regle(&c, id).iter().all(|c| !c.verifie), "{id}");
            }
        }
    }
}
