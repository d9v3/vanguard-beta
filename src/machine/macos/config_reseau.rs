//! La configuration réseau de macOS demandée à SystemConfiguration, au lieu de lancer `scutil` et `networksetup` :
//! les serveurs DNS et le proxy en vigueur (SCDynamicStore, l'état que tiennent configd et les VPN), la carte et la
//! passerelle principales, les services réseau et leur DNS réglé à la main (SCPreferences, ce que lit et écrit
//! networksetup).
//!
//! Par les fonctions brutes de `system_configuration::sys`, pas par les fonctions sûres de la crate : en 0.7.0,
//! `SCNetworkService::enabled` rend l'inverse de SCNetworkServiceGetEnabled, et `SCPreferences::default` ou
//! `SCNetworkSet::new` paniquent sur un pointeur nul, qu'Apple documente pour un échec. Ici, chaque pointeur nul est
//! une lecture manquée (`None`), et chaque objet créé (« Create », « Copy ») est libéré par son enveloppe.
//!
//! Les valeurs lues (des listes de propriétés de CoreFoundation) passent en `crate::plist::Valeur`, bornées en
//! profondeur et en nombre : le reste de Vanguard lit déjà ce format.
//!
//! Tant que le test d'oracle de macos.yml (plus bas) n'a pas prouvé ces lectures contre scutil et networksetup, les
//! appelants gardent l'outil en secours.

// FFI de SystemConfiguration et CoreFoundation (system-configuration-sys) : DNS, proxy, services.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::net::IpAddr;

use system_configuration::core_foundation::array::{CFArray, CFArrayRef};
use system_configuration::core_foundation::base::{CFType, TCFType};
use system_configuration::core_foundation::boolean::CFBoolean;
use system_configuration::core_foundation::data::CFData;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::SCDynamicStore;
use system_configuration::sys::dynamic_store::SCDynamicStoreCreate;
use system_configuration::sys::network_configuration as sc;
use system_configuration::sys::preferences::SCPreferencesCreate;

use crate::plist::Valeur;

/// Nom donné à configd pour ses journaux : celui du programme.
const NOM: &str = "Vanguard";
/// Bornes d'une valeur lue : configd n'est pas hostile, mais un VPN ou un profil de configuration y écrit ce qu'il veut.
const PROFONDEUR_MAX: usize = 16;
const VALEURS_MAX: usize = 20_000;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    /// SCNetworkConfiguration.h : le type de protocole DNS d'un service (« DNS »).
    static kSCNetworkProtocolTypeDNS: CFStringRef;
}

/// Une liste de propriétés de CoreFoundation en `Valeur`. `None` : un type que `Valeur` ne connaît pas (une date…),
/// sauté par son contenant sans perdre le reste ; `hors_bornes` : trop profond ou trop de valeurs, et alors toute la
/// lecture est refusée.
fn vers_valeur(t: &CFType, profondeur: usize, compte: &mut usize, hors_bornes: &mut bool) -> Option<Valeur> {
    *compte += 1;
    if profondeur > PROFONDEUR_MAX || *compte > VALEURS_MAX {
        *hors_bornes = true;
        return None;
    }
    // Un pointeur d'une liste ou d'un dictionnaire, en CFType retenu (« Get » : la liste garde le sien).
    let element = |p: *const c_void| -> Option<CFType> {
        // SAFETY: un élément non nul d'une liste ou d'un dictionnaire de CoreFoundation, vivant tant que son
        // contenant l'est ; wrap_under_get_rule le retient pour la durée de l'enveloppe.
        (!p.is_null()).then(|| unsafe { CFType::wrap_under_get_rule(p) })
    };
    if let Some(s) = t.downcast::<CFString>() {
        return Some(Valeur::Texte(s.to_string()));
    }
    if let Some(b) = t.downcast::<CFBoolean>() {
        return Some(Valeur::Booleen(bool::from(b)));
    }
    if let Some(n) = t.downcast::<CFNumber>() {
        return n
            .to_i64()
            .map(|i| Valeur::Entier(i128::from(i)))
            .or_else(|| n.to_f64().map(Valeur::Reel));
    }
    if let Some(d) = t.downcast::<CFData>() {
        // Vide : CFDataGetBytePtr peut rendre un pointeur nul, que bytes() prendrait pour une tranche.
        return Some(Valeur::Donnees(if d.is_empty() {
            Vec::new()
        } else {
            d.bytes().to_vec()
        }));
    }
    if let Some(a) = t.downcast::<CFArray>() {
        let mut v = Vec::new();
        for p in a.get_all_values() {
            if let Some(e) = element(p).and_then(|e| vers_valeur(&e, profondeur + 1, compte, hors_bornes)) {
                v.push(e);
            }
            if *hors_bornes {
                return None;
            }
        }
        return Some(Valeur::Tableau(v));
    }
    if let Some(d) = t.downcast::<CFDictionary>() {
        let (cles, valeurs) = d.get_keys_and_values();
        let mut paires = Vec::with_capacity(cles.len());
        for (k, v) in cles.into_iter().zip(valeurs) {
            let Some(cle) = element(k).and_then(|k| k.downcast::<CFString>()) else {
                continue;
            };
            if let Some(e) = element(v).and_then(|e| vers_valeur(&e, profondeur + 1, compte, hors_bornes)) {
                paires.push((cle.to_string(), e));
            }
            if *hors_bornes {
                return None;
            }
        }
        // CoreFoundation ne garde pas d'ordre : trié, pour une lecture stable.
        paires.sort_by(|a, b| a.0.cmp(&b.0));
        return Some(Valeur::Dico(paires));
    }
    None
}

fn valeur(t: &CFType) -> Option<Valeur> {
    let mut hors_bornes = false;
    let v = vers_valeur(t, 0, &mut 0, &mut hors_bornes);
    if hors_bornes { None } else { v }
}

/// Une session du magasin dynamique de configd. `None` : configd ne répond pas.
fn magasin() -> Option<SCDynamicStore> {
    let nom = CFString::from_static_string(NOM);
    // SAFETY: allocateur nul = celui par défaut ; sans rappel ni contexte. Le magasin rendu est à libérer : son
    // enveloppe le fait (« Create »).
    let brut = unsafe { SCDynamicStoreCreate(std::ptr::null(), nom.as_concrete_TypeRef(), None, std::ptr::null_mut()) };
    // SAFETY: non nul, créé pour nous.
    (!brut.is_null()).then(|| unsafe { SCDynamicStore::wrap_under_create_rule(brut) })
}

/// La valeur d'une clé du magasin dynamique (« State:/Network/Global/DNS »).
fn lire(magasin: &SCDynamicStore, cle: &str) -> Option<Valeur> {
    let v = magasin.get(CFString::new(cle))?;
    valeur(&v.as_CFType())
}

/// Les adresses d'une liste de textes (« ServerAddresses »), dans l'ordre, sans doublon ; les adresses à zone
/// (« fe80::1%en0 ») gardent leur adresse.
fn adresses(v: Option<&Valeur>) -> Vec<IpAddr> {
    let mut liste = Vec::new();
    for t in v
        .and_then(Valeur::tableau)
        .unwrap_or_default()
        .iter()
        .filter_map(Valeur::texte)
    {
        if let Ok(ip) = t.split('%').next().unwrap_or_default().trim().parse::<IpAddr>()
            && !liste.contains(&ip)
        {
            liste.push(ip);
        }
    }
    liste
}

/// Les serveurs DNS en vigueur, comme les liste `scutil --dns` : ceux du résolveur principal (State:/Network/Global/
/// DNS), puis ceux que chaque service publie (un VPN, ses domaines) et ceux des fichiers /etc/resolver/* (un résolveur
/// par domaine). `None` : configd ne répond pas.
pub(crate) fn dns_en_vigueur() -> Option<Vec<IpAddr>> {
    let m = magasin()?;
    let mut liste = adresses(
        lire(&m, "State:/Network/Global/DNS")
            .as_ref()
            .and_then(|d| d.cle("ServerAddresses")),
    );
    let cles = m
        .get_keys("State:/Network/Service/[^/]+/DNS")
        .map(|c| c.iter().map(|k| k.to_string()).collect::<Vec<_>>());
    for cle in cles.unwrap_or_default() {
        for ip in adresses(lire(&m, &cle).as_ref().and_then(|d| d.cle("ServerAddresses"))) {
            if !liste.contains(&ip) {
                liste.push(ip);
            }
        }
    }
    for fichier in std::fs::read_dir("/etc/resolver")
        .into_iter()
        .flatten()
        .flatten()
        .take(200)
    {
        let texte = std::fs::read_to_string(fichier.path()).unwrap_or_default();
        for ip in serveurs_resolver(&texte) {
            if !liste.contains(&ip) {
                liste.push(ip);
            }
        }
    }
    Some(liste)
}

/// Les « nameserver » d'un fichier de /etc/resolver (le format de resolv.conf).
pub(crate) fn serveurs_resolver(texte: &str) -> Vec<IpAddr> {
    texte
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|r| r.trim().split('%').next()?.parse().ok())
        .collect()
}

/// Le proxy en vigueur (SCDynamicStoreCopyProxies), dans le texte de `scutil --proxy` (« HTTPEnable : 1 »), que
/// lisent déjà le bilan et la réparation. Seules les valeurs simples sont écrites, une par ligne. `None` : configd ne
/// répond pas.
pub(crate) fn proxy_comme_scutil() -> Option<String> {
    let m = magasin()?;
    let d = m.get_proxies()?;
    let v = valeur(&d.as_CFType())?;
    Some(texte_scutil(&v))
}

/// Un dictionnaire écrit comme `scutil` : « <dictionary> { », « Clé : valeur » par ligne, les dictionnaires imbriqués
/// (« __SCOPED__ », le proxy de chaque carte) et les listes (exceptions) écrits à leur place et indentés, « } ».
pub(crate) fn texte_scutil(v: &Valeur) -> String {
    fn ecrire(v: &Valeur, retrait: usize, t: &mut String) {
        use std::fmt::Write;
        let marge = "  ".repeat(retrait + 1);
        let (ouverture, elements): (&str, Vec<(String, &Valeur)>) = match v {
            Valeur::Dico(paires) => ("<dictionary> {", paires.iter().map(|(k, e)| (k.clone(), e)).collect()),
            Valeur::Tableau(liste) => (
                "<array> {",
                liste.iter().enumerate().map(|(i, e)| (i.to_string(), e)).collect(),
            ),
            autre => {
                t.push_str(&autre.comme_defaults().unwrap_or_default());
                return;
            }
        };
        t.push_str(ouverture);
        t.push('\n');
        for (cle, e) in elements {
            if matches!(e, Valeur::Dico(_) | Valeur::Tableau(_)) || e.comme_defaults().is_some() {
                let _ = write!(t, "{marge}{cle} : ");
                ecrire(e, retrait + 1, t);
                t.push('\n');
            }
        }
        t.push_str(&"  ".repeat(retrait));
        t.push('}');
    }
    let mut t = String::new();
    ecrire(v, 0, &mut t);
    t.push('\n');
    t
}

/// La carte, la passerelle et le service réseau principaux (State:/Network/Global/IPv4) : ceux de la route par
/// défaut.
#[derive(Debug, Clone, Default)]
pub(crate) struct Principal {
    pub carte: Option<String>,
    pub passerelle: Option<IpAddr>,
    pub service: Option<String>,
}

pub(crate) fn principal() -> Option<Principal> {
    let m = magasin()?;
    let v = lire(&m, "State:/Network/Global/IPv4")?;
    let texte = |cle: &str| v.cle(cle).and_then(Valeur::texte).map(str::to_string);
    Some(Principal {
        carte: texte("PrimaryInterface"),
        passerelle: texte("Router").and_then(|r| r.parse().ok()),
        service: texte("PrimaryService"),
    })
}

/// Un service réseau des réglages (le jeu en cours), ce que liste `networksetup -listallnetworkservices`.
#[derive(Debug, Clone)]
pub(crate) struct Service {
    pub id: String,
    /// Son nom, choisi par l'utilisateur : à rendre inoffensif avant de le montrer, à citer avant le shell.
    pub nom: String,
    pub actif: bool,
    /// La carte BSD (« en0 »), quand il en a une.
    pub carte: Option<String>,
    /// Les serveurs DNS réglés à la main pour ce service (`networksetup -getdnsservers`) ; vide : ceux du DHCP.
    pub dns: Vec<IpAddr>,
}

/// Une chaîne « Get » de SystemConfiguration en texte ; `None` : pointeur nul.
fn texte_get(p: CFStringRef) -> Option<String> {
    // SAFETY: non nul (vérifié), une CFString que son propriétaire garde vivante ; retenue par l'enveloppe.
    (!p.is_null()).then(|| unsafe { CFString::wrap_under_get_rule(p) }.to_string())
}

/// Les serveurs DNS réglés pour un service, d'après son protocole DNS (SCNetworkServiceCopyProtocol).
fn dns_du_service(service: sc::SCNetworkServiceRef) -> Vec<IpAddr> {
    // SAFETY: service vient d'une liste vivante de SCNetworkSetCopyServices ; la constante est celle du framework.
    let protocole = unsafe { sc::SCNetworkServiceCopyProtocol(service, kSCNetworkProtocolTypeDNS) };
    if protocole.is_null() {
        return Vec::new();
    }
    // SAFETY: créé pour nous (« Copy ») : l'enveloppe le libère (CFRelease) en sortant.
    let garde = unsafe { CFType::wrap_under_create_rule(protocole.cast()) };
    // SAFETY: protocole est vivant (garde) ; la configuration rendue lui appartient (« Get »).
    let config = unsafe { sc::SCNetworkProtocolGetConfiguration(protocole) };
    let v = if config.is_null() {
        None
    } else {
        // SAFETY: non nul, un dictionnaire que le protocole garde vivant ; retenu par l'enveloppe.
        valeur(&unsafe { CFType::wrap_under_get_rule(config.cast()) })
    };
    drop(garde);
    adresses(v.as_ref().and_then(|d| d.cle("ServerAddresses")))
}

/// Les services réseau du jeu en cours, dans l'ordre de priorité (`networksetup -listnetworkserviceorder`), ceux
/// qui manquent à l'ordre à la fin. `None` : réglages illisibles.
pub(crate) fn services() -> Option<Vec<Service>> {
    let nom = CFString::from_static_string(NOM);
    // SAFETY: allocateur nul = celui par défaut, identifiant nul = les réglages du système ; à libérer (« Create »).
    let prefs = unsafe { SCPreferencesCreate(std::ptr::null(), nom.as_concrete_TypeRef(), std::ptr::null()) };
    if prefs.is_null() {
        return None;
    }
    // SAFETY: créé pour nous : libéré en sortant.
    let _prefs = unsafe { CFType::wrap_under_create_rule(prefs.cast()) };
    // SAFETY: prefs est vivant ; le jeu rendu est à libérer (« Copy »), nul s'il n'y en a pas.
    let jeu = unsafe { sc::SCNetworkSetCopyCurrent(prefs) };
    if jeu.is_null() {
        return None;
    }
    // SAFETY: créé pour nous : libéré en sortant.
    let _jeu = unsafe { CFType::wrap_under_create_rule(jeu.cast()) };
    // SAFETY: jeu est vivant ; l'ordre lui appartient (« Get »), nul s'il n'est pas réglé.
    let ordre_brut: CFArrayRef = unsafe { sc::SCNetworkSetGetServiceOrder(jeu) };
    let ordre: Vec<String> = if ordre_brut.is_null() {
        Vec::new()
    } else {
        // SAFETY: non nul, une liste que le jeu garde vivante ; retenue par l'enveloppe.
        let liste = unsafe { CFType::wrap_under_get_rule(ordre_brut.cast()) };
        valeur(&liste)
            .as_ref()
            .and_then(Valeur::tableau)
            .unwrap_or_default()
            .iter()
            .filter_map(Valeur::texte)
            .map(str::to_string)
            .collect()
    };
    // SAFETY: jeu est vivant ; la liste rendue est à libérer (« Copy »).
    let brut = unsafe { sc::SCNetworkSetCopyServices(jeu) };
    if brut.is_null() {
        return None;
    }
    // SAFETY: créée pour nous : libérée par l'enveloppe ; ses éléments sont des SCNetworkServiceRef.
    let liste: CFArray = unsafe { CFArray::wrap_under_create_rule(brut) };
    let mut services: Vec<Service> = Vec::new();
    for p in liste.get_all_values().into_iter().take(1000) {
        let s: sc::SCNetworkServiceRef = p.cast();
        if s.is_null() {
            continue;
        }
        // SAFETY: s est un élément vivant de la liste ; les chaînes et la carte rendues lui appartiennent (« Get »).
        let (id, nom, actif, carte) = unsafe {
            let carte = sc::SCNetworkServiceGetInterface(s);
            (
                texte_get(sc::SCNetworkServiceGetServiceID(s)),
                texte_get(sc::SCNetworkServiceGetName(s)),
                sc::SCNetworkServiceGetEnabled(s) != 0,
                if carte.is_null() {
                    None
                } else {
                    texte_get(sc::SCNetworkInterfaceGetBSDName(carte))
                },
            )
        };
        let Some(id) = id else { continue };
        // Un service sans nom ne peut pas être désigné à networksetup : non retenu.
        let Some(nom) = nom.filter(|n| !n.is_empty()) else {
            continue;
        };
        services.push(Service {
            id,
            nom,
            actif,
            carte,
            dns: dns_du_service(s),
        });
    }
    services.sort_by_key(|s| ordre.iter().position(|o| *o == s.id).unwrap_or(usize::MAX));
    Some(services)
}

#[cfg(test)]
mod oracles {
    use std::process::Command;

    use super::*;

    fn outil(programme: &str, args: &[&str]) -> Option<String> {
        crate::commande::lancer(Command::new(programme).args(args).env("LC_ALL", "C"), 60)
            .filter(|r| r.code == Some(0))
            .map(|r| r.sortie)
    }

    /// Le texte écrit comme scutil garde les blocs imbriqués.
    #[test]
    fn texte_scutil_imbrique() {
        let v = Valeur::Dico(vec![
            ("HTTPEnable".into(), Valeur::Entier(0)),
            (
                "__SCOPED__".into(),
                Valeur::Dico(vec![(
                    "en1".into(),
                    Valeur::Dico(vec![("ProxyAutoDiscoveryEnable".into(), Valeur::Entier(1))]),
                )]),
            ),
        ]);
        let t = texte_scutil(&v);
        assert!(
            t.contains("    en1 : <dictionary> {\n      ProxyAutoDiscoveryEnable : 1\n"),
            "{t}"
        );
    }

    /// Les serveurs DNS de `scutil --dns` sont tous dans la lecture native.
    #[test]
    fn dns_contre_scutil() {
        let natifs = dns_en_vigueur().expect("configd");
        let scutil = crate::machine::dns::lire_scutil(&outil("scutil", &["--dns"]).unwrap());
        for ip in &scutil {
            assert!(
                natifs.contains(ip),
                "{ip} : scutil le voit, pas la lecture native ({natifs:?})"
            );
        }
    }

    /// Le proxy : les lignes « Clé : valeur » de `scutil --proxy` et du texte natif, blocs imbriqués (__SCOPED__)
    /// compris, sont les mêmes, comptées (pas une simple inclusion : une valeur répétée dans un bloc imbriqué compte).
    #[test]
    fn proxy_contre_scutil() {
        let lignes = |t: &str| {
            let mut v: Vec<String> = t
                .lines()
                .map(str::trim)
                .filter(|l| l.contains(" : ") && !l.ends_with('{'))
                .map(str::to_string)
                .collect();
            v.sort();
            v
        };
        let natif = proxy_comme_scutil().expect("SCDynamicStoreCopyProxies");
        let scutil = outil("scutil", &["--proxy"]).unwrap();
        // Les scutil récents n'écrivent plus le bloc par carte (__SCOPED__), que Vanguard garde : comparé sans lui.
        let natif_compare = if scutil.contains("__SCOPED__") {
            natif.clone()
        } else {
            sans_bloc(&natif, "__SCOPED__ :")
        };
        assert_eq!(lignes(&natif_compare), lignes(&scutil), "{natif}\n---\n{scutil}");
    }

    /// Le texte sans le bloc qui commence par `debut` (jusqu'à son « } », à la même marge).
    fn sans_bloc(texte: &str, debut: &str) -> String {
        let mut sortie = Vec::new();
        let mut marge: Option<usize> = None;
        for l in texte.lines() {
            let retrait = l.len() - l.trim_start().len();
            match marge {
                Some(m) => {
                    if retrait == m && l.trim() == "}" {
                        marge = None;
                    }
                }
                None if l.trim_start().starts_with(debut) => marge = Some(retrait),
                None => sortie.push(l),
            }
        }
        sortie.join("\n")
    }

    #[test]
    fn sans_bloc_retire_le_bloc_imbrique() {
        let t = "<dictionary> {\n  A : 1\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      A : 1\n    }\n  }\n  B : 2\n}";
        assert_eq!(sans_bloc(t, "__SCOPED__ :"), "<dictionary> {\n  A : 1\n  B : 2\n}");
    }

    /// Les services : mêmes noms, même ordre, mêmes actifs que networksetup ; même DNS réglé à la main.
    #[test]
    fn services_contre_networksetup() {
        let natifs = services().expect("SCPreferences");
        let ordre = outil("networksetup", &["-listnetworkserviceorder"]).unwrap();
        let attendus: Vec<(bool, String)> = ordre
            .lines()
            .filter_map(|l| {
                let (numero, nom) = l.strip_prefix('(')?.split_once(") ")?;
                (numero == "*" || numero.parse::<u32>().is_ok()).then(|| (numero != "*", nom.to_string()))
            })
            .collect();
        // Un service lu en plus doit être reconnu par networksetup (son DNS est comparé plus bas) : les Mac virtuels
        // de GitHub ont « Ethernet Adapter (en1) », que networksetup règle mais ne montre pas dans cette liste.
        for s in natifs.iter().filter(|s| !attendus.iter().any(|(_, n)| *n == s.nom)) {
            let texte = outil("networksetup", &["-getdnsservers", &s.nom]);
            assert!(
                texte
                    .as_deref()
                    .is_some_and(|t| !t.contains("not a recognized network service")),
                "{} : inconnu de networksetup",
                s.nom
            );
        }
        let lus: Vec<(bool, String)> = natifs
            .iter()
            .filter(|s| attendus.iter().any(|(_, n)| *n == s.nom))
            .map(|s| (s.actif, s.nom.clone()))
            .collect();
        let detail: Vec<String> = natifs
            .iter()
            .map(|s| format!("{} {:?} {}", s.id, s.carte, s.nom))
            .collect();
        assert_eq!(lus, attendus, "{ordre}\n{detail:#?}");
        for s in &natifs {
            let texte = outil("networksetup", &["-getdnsservers", &s.nom]).unwrap_or_default();
            let attendu: Vec<IpAddr> = texte.lines().filter_map(|l| l.trim().parse().ok()).collect();
            assert_eq!(s.dns, attendu, "{}", s.nom);
        }
        // La carte principale : celle de `route -n get default`.
        if let Some(route) = outil("route", &["-n", "get", "default"]) {
            let carte = route
                .lines()
                .find_map(|l| l.trim().strip_prefix("interface:"))
                .map(str::trim);
            assert_eq!(principal().and_then(|p| p.carte).as_deref(), carte);
        }
    }
}
