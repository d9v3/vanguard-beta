//! Réglages de macOS : préférences `defaults` (booléens) du compte, ou de la machine pour celles qui demandent les
//! droits administrateur. Le Finder est relancé à la fin quand un de ses réglages a changé.

use std::path::{Path, PathBuf};
use std::process::Command;

use super::demarrage::{Programme, agent_actif, agent_au_demarrage, etats_launchd, label_valide};
use super::{Categorie, Reglage, Valeur};
use crate::commande::sh_chaine;
use crate::ui::*;

pub enum Changement {
    /// Préférence booléenne : domaine (ou fichier .plist), clé, valeur voulue, valeur d'un Mac neuf (`None` : absente),
    /// et s'il faut les droits administrateur pour l'écrire.
    Preference {
        domaine: &'static str,
        cle: &'static str,
        cible: bool,
        defaut: Option<bool>,
        admin: bool,
    },
    /// Serveurs DNS d'un service réseau (« Wi-Fi »), outil « DNS le plus rapide ». Valeur : « service\n1.1.1.1,… »,
    /// vide pour ceux de la box. `cible` : `None` quand le réglage n'est rebâti que pour être annulé.
    Dns { service: String, cible: Option<String> },
    /// Agent de launchd du compte (outil « Programmes au démarrage ») : « enabled » ou « disabled » pour
    /// `launchctl`. Le nom (label) est vérifié : il entre tel quel dans la commande.
    Demarrage { label: String },
    /// Préférence de texte de la liste fermée `TEXTES` (une correction du bilan), avec ses valeurs possibles et la
    /// commande qui la fait prendre.
    Texte { pref: &'static PrefTexte },
    /// Droits d'un fichier du dossier personnel (« 0644 »), remis par chmod, sans sudo.
    Droits { chemin: PathBuf },
}

/// Une préférence de texte qu'une correction du bilan change, et ce qu'une note peut y remettre.
pub struct PrefTexte {
    pub domaine: &'static str,
    pub cle: &'static str,
    pub admises: &'static [&'static str],
    pub apres: &'static str,
}

/// La liste fermée des préférences de texte que Vanguard sait remettre.
static TEXTES: [PrefTexte; 1] = [PrefTexte {
    domaine: "com.apple.sharingd",
    cle: "DiscoverableMode",
    admises: &["Contacts Only", "Everyone", "Off"],
    apres: "killall sharingd 2>/dev/null; true",
}];

/// Les réglages de launchd pour ce compte (`launchctl print-disabled`), nom → désactivé ; `None` : illisible.
fn agents_etats() -> Option<std::collections::HashMap<String, bool>> {
    // SAFETY : getuid n'a ni argument ni échec possible.
    let uid = unsafe { libc::getuid() };
    let r = crate::commande::lancer(
        Command::new("launchctl").args(["print-disabled", &format!("gui/{uid}")]),
        10,
    )?;
    (r.code == Some(0)).then(|| etats_launchd(&r.sortie))
}

fn bool_texte(b: bool) -> String {
    if b { "1" } else { "0" }.to_string()
}

/// `networksetup -getdnsservers` : une adresse par ligne, ou une phrase quand il n'y en a pas (ceux de la box).
fn lire_networksetup(sortie: &str) -> String {
    sortie
        .lines()
        .map(str::trim)
        .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
        .collect::<Vec<_>>()
        .join(",")
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        match self {
            Changement::Preference { domaine, cle, .. } => {
                let r = crate::commande::lancer(Command::new("defaults").args(["read", domaine, cle]), 10)?;
                (r.code == Some(0)).then(|| r.sortie.trim().to_string())
            }
            Changement::Dns { service, .. } => {
                let r = crate::commande::lancer(Command::new("networksetup").args(["-getdnsservers", service]), 10)?;
                // Un service inconnu répond « … is not a recognized network service » : illisible, pas « aucun ».
                (r.code == Some(0) && !r.sortie.contains("not a recognized"))
                    .then(|| format!("{service}\n{}", lire_networksetup(&r.sortie)))
            }
            Changement::Demarrage { label } => {
                // Remettre écrit « enabled » dans launchd, même si l'agent n'y figurait pas avant : le même effet, car
                // seul un agent qui se lançait est proposé (agent_actif tient compte de « Disabled » dans son plist).
                agents_etats().map(|e| {
                    if e.get(label) == Some(&true) {
                        "disabled"
                    } else {
                        "enabled"
                    }
                    .to_string()
                })
            }
            Changement::Texte { pref } => {
                let r = crate::commande::lancer(Command::new("defaults").args(["read", pref.domaine, pref.cle]), 10)?;
                (r.code == Some(0)).then(|| r.sortie.trim().to_string())
            }
            Changement::Droits { chemin } => super::annulables::droits_lus(chemin),
        }
    }

    /// La valeur d'avant, relevée avant une correction : `None` si elle ne se lit pas. Une préférence absente est
    /// une valeur (retirée pour annuler).
    pub fn relever(&self) -> Option<Valeur> {
        match self {
            Changement::Droits { chemin } => super::annulables::droits_lus(chemin).map(Some),
            _ => Some(self.lire()),
        }
    }

    /// Le changement que désigne un geste noté (`annulables::Geste`), s'il vise une cible de la liste fermée.
    pub fn depuis_geste(geste: &str) -> Option<Changement> {
        let (genre, reste) = geste.split_once('|')?;
        match genre {
            "preference" => {
                let (domaine, cle) = reste.split_once('|')?;
                TEXTES
                    .iter()
                    .find(|p| p.domaine == domaine && p.cle == cle)
                    .map(|pref| Changement::Texte { pref })
            }
            "droits" => super::annulables::dans_la_maison(Path::new(reste)).then(|| Changement::Droits {
                chemin: PathBuf::from(reste),
            }),
            _ => None,
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Preference { cible, .. } => bool_texte(*cible),
            // Rebâti pour être annulé : une cible qu'aucune lecture ne donne.
            Changement::Dns { service, cible } => format!("{service}\n{}", cible.as_deref().unwrap_or("?")),
            Changement::Demarrage { .. } => "disabled".to_string(),
            // Rebâtis pour être annulés seulement.
            Changement::Texte { .. } | Changement::Droits { .. } => "?".to_string(),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Preference { defaut, .. } => defaut.map(bool_texte),
            // Les DNS donnés par la box.
            Changement::Dns { service, .. } => Some(format!("{service}\n")),
            Changement::Demarrage { .. } => Some("enabled".to_string()),
            // Pas de « Mac neuf » pour une correction : sans note admise, rien ne se remet.
            Changement::Texte { .. } | Changement::Droits { .. } => Some("?".to_string()),
        }
    }

    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Preference { domaine, cle, .. } => match v {
                Some("1") => format!("defaults write {domaine} {cle} -bool true"),
                Some(_) => format!("defaults write {domaine} {cle} -bool false"),
                None => format!("defaults delete {domaine} {cle}"),
            },
            Changement::Dns { .. } => {
                let serveurs: Vec<&str> = v
                    .and_then(|v| v.split_once('\n'))
                    .map_or("", |(_, l)| l)
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .collect();
                super::texte_dns(&serveurs, false)
            }
            Changement::Demarrage { label } => format!(
                "launchctl {} gui/<uid>/{label}",
                if v == Some("disabled") { "disable" } else { "enable" }
            ),
            Changement::Texte { pref } => match v {
                Some(t) => format!("defaults write {} {} -string \"{t}\"", pref.domaine, pref.cle),
                None => format!("defaults delete {} {}", pref.domaine, pref.cle),
            },
            Changement::Droits { chemin } => format!("chmod {} {}", v.unwrap_or("?"), chemin.display()),
        }
    }

    pub(super) fn commande(&self, v: Option<&str>) -> Option<String> {
        match self {
            Changement::Preference {
                domaine, cle, admin, ..
            } => {
                let sudo = if *admin { "sudo " } else { "" };
                Some(match v {
                    Some(v) => format!(
                        "{sudo}defaults write {} {cle} -bool {}",
                        sh_chaine(domaine),
                        if v == "1" { "true" } else { "false" }
                    ),
                    // Déjà absente : `defaults delete` répond par une erreur, qui n'en est pas une ici.
                    None => format!("{sudo}defaults delete {} {cle} 2>/dev/null; true", sh_chaine(domaine)),
                })
            }
            Changement::Dns { service, .. } => {
                let (id, liste) = v?.split_once('\n')?;
                if id != service {
                    return None;
                }
                // Seules des adresses IP entrent dans la commande ; « empty » rend ceux de la box.
                let serveurs: Vec<String> = liste
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<std::net::IpAddr>().map(|ip| ip.to_string()))
                    .collect::<Result<_, _>>()
                    .ok()?;
                let serveurs = if serveurs.is_empty() {
                    "empty".to_string()
                } else {
                    serveurs.join(" ")
                };
                Some(format!(
                    "sudo networksetup -setdnsservers {} {serveurs}",
                    sh_chaine(service)
                ))
            }
            // Pour le compte, sans sudo ; l'agent qui tourne finit la session, il ne repart simplement plus.
            Changement::Demarrage { label } => {
                if !label_valide(label) {
                    return None;
                }
                let action = match v? {
                    "disabled" => "disable",
                    "enabled" => "enable",
                    _ => return None,
                };
                Some(format!("launchctl {action} \"gui/$(id -u)/{label}\""))
            }
            // Chaque valeur repasse par `valeur_admise` : seule une valeur de la liste entre dans la commande.
            Changement::Texte { pref } => {
                if !self.valeur_admise(v) {
                    return None;
                }
                Some(match v {
                    Some(t) => format!(
                        "defaults write {} {} -string {}; {}",
                        pref.domaine,
                        pref.cle,
                        sh_chaine(t),
                        pref.apres
                    ),
                    None => format!(
                        "defaults delete {} {} 2>/dev/null; {}",
                        pref.domaine, pref.cle, pref.apres
                    ),
                })
            }
            Changement::Droits { chemin } => {
                let v = v.filter(|v| super::annulables::droits_admis(v))?;
                Some(format!("chmod {v} {}", sh_chaine(&chemin.display().to_string())))
            }
        }
    }

    /// La valeur notée `v` a-t-elle une forme que ce changement peut écrire ? Certaines sont remises avec sudo : un
    /// ensemble fermé ou une forme stricte (booléen, adresses IP), jamais un texte libre venu d'un fichier que tout
    /// programme du compte peut réécrire.
    pub fn valeur_admise(&self, v: Option<&str>) -> bool {
        match self {
            Changement::Preference { .. } => v.is_none_or(|v| matches!(v, "0" | "1")),
            Changement::Dns { service, .. } => v.is_some_and(|v| {
                v.split_once('\n')
                    .is_some_and(|(id, liste)| id == service && service_valide(id) && super::adresses_ip(liste))
            }),
            Changement::Demarrage { .. } => v.is_none_or(|v| matches!(v, "enabled" | "disabled")),
            Changement::Texte { pref } => v.is_none_or(|v| pref.admises.contains(&v)),
            Changement::Droits { .. } => v.is_some_and(super::annulables::droits_admis),
        }
    }

    /// Le service réseau d'un réglage de DNS.
    pub fn identite_dns(&self) -> Option<&str> {
        match self {
            Changement::Dns { service, .. } => Some(service),
            Changement::Preference { .. }
            | Changement::Demarrage { .. }
            | Changement::Texte { .. }
            | Changement::Droits { .. } => None,
        }
    }

    /// L'identité stable d'un réglage de démarrage (« launchd|com.exemple.agent »), notée dans l'historique.
    pub fn identite_demarrage(&self) -> Option<String> {
        match self {
            Changement::Demarrage { label } => Some(format!("launchd|{label}")),
            _ => None,
        }
    }

    /// Le réglage de démarrage rebâti d'après son identité notée, pour l'annuler.
    pub fn demarrage_depuis(identite: &str) -> Option<Changement> {
        let label = identite.strip_prefix("launchd|")?;
        label_valide(label).then(|| Changement::Demarrage {
            label: label.to_string(),
        })
    }

    /// Le nom d'un programme d'après l'identité notée : le nom de l'agent.
    pub fn nom_demarrage(identite: &str) -> String {
        identite.strip_prefix("launchd|").unwrap_or(identite).to_string()
    }

    /// La commande qui pose la valeur `v` d'un réglage de DNS (mode Wi-Fi public).
    pub fn commande_dns(&self, v: &str) -> Option<String> {
        matches!(self, Changement::Dns { .. })
            .then(|| self.commande(Some(v)))
            .flatten()
    }

    /// Le réglage de DNS rebâti d'après sa valeur d'avant notée, pour l'annuler.
    pub fn dns_note(avant: &str) -> Option<Changement> {
        let (service, _) = avant.split_once('\n')?;
        service_valide(service).then(|| Changement::Dns {
            service: service.to_string(),
            cible: None,
        })
    }
}

/// Un nom de service réseau (« Wi-Fi », « USB 10/100/1000 LAN ») : il entre, entre guillemets, dans une commande
/// lancée avec sudo ; rien qui ressemble à autre chose qu'un nom.
fn service_valide(t: &str) -> bool {
    !t.is_empty() && t.chars().count() <= 64 && t.chars().all(|c| c.is_alphanumeric() || " -_./()+".contains(c))
}

/// Le service réseau d'une carte, dans `networksetup -listnetworkserviceorder` : « (1) Wi-Fi » puis
/// « (Hardware Port: Wi-Fi, Device: en0) ». Un service coupé commence par « (*) ».
fn service_de(liste: &str, carte: &str) -> Option<String> {
    let mut nom: Option<&str> = None;
    for l in liste.lines().map(str::trim) {
        if let Some(reste) = l.strip_prefix('(')
            && let Some((numero, service)) = reste.split_once(") ")
            && (numero == "*" || numero.parse::<u32>().is_ok())
        {
            nom = (numero != "*").then_some(service);
        } else if l.contains(&format!("Device: {carte})")) {
            return nom.map(str::to_string);
        }
    }
    None
}

/// Le DNS du service réseau de la route par défaut, à régler sur ces serveurs (IPv4 et IPv6 ensemble : macOS ne
/// se sert que de ceux qu'il peut joindre). Erreur : pourquoi il faut le faire à la main.
pub fn dns_principal(v4: &[&str], v6: &[&str]) -> Result<Changement, String> {
    let a_la_main = tr!(
        "Le service réseau principal est illisible : le DNS se règle à la main (Réglages Système > Réseau, ou dans le routeur).",
        "The main network service is unreadable: set the DNS by hand (System Settings > Network, or in the router)."
    );
    let route = crate::commande::lancer(Command::new("route").args(["-n", "get", "default"]), 10)
        .map(|r| r.sortie)
        .unwrap_or_default();
    let carte = route
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .map(str::trim)
        .ok_or_else(|| tr!("Pas de connexion à Internet.", "No Internet connection.").to_string())?;
    let liste = crate::commande::lancer(Command::new("networksetup").arg("-listnetworkserviceorder"), 10)
        .map(|r| r.sortie)
        .unwrap_or_default();
    let service = service_de(&liste, carte).ok_or_else(|| a_la_main.to_string())?;
    let mut serveurs: Vec<&str> = v4.to_vec();
    serveurs.extend(v6);
    Ok(Changement::Dns {
        service,
        cible: Some(serveurs.join(",")),
    })
}

/// Applique des lots de changements (un lot par réglage), puis les groupes de `en_plus` (les commandes d'autres
/// annulations) dans le même passage. Rend la réussite de chaque lot, puis de chaque groupe en plus.
pub fn ecrire_avec(lots: &[Vec<(&Changement, Valeur)>], en_plus: &[Vec<String>]) -> (Vec<bool>, Vec<bool>) {
    let mut commandes: Vec<Vec<String>> = lots
        .iter()
        .map(|lot| lot.iter().filter_map(|(c, v)| c.commande(v.as_deref())).collect())
        .collect();
    commandes.extend(en_plus.iter().cloned());
    let mut resultats = crate::machine::appliquer_chacune(&commandes);
    let plus = resultats.split_off(lots.len().min(resultats.len()));
    (resultats, plus)
}

/// Les programmes lancés à l'ouverture de session de ce compte : ses agents de launchd (~/Library/LaunchAgents) qui
/// partent à la connexion, avec leur état. Ceux de toute la machine (/Library), les éléments de connexion des
/// Réglages et les agents à la demande ou à heure fixe ne sont pas touchés.
pub fn au_demarrage() -> Vec<Programme> {
    let dossier = crate::socle::maison().join("Library/LaunchAgents");
    let etats = agents_etats().unwrap_or_default();
    // Une clé du plist en XML (un booléen, ou les conditions de KeepAlive) ; `None` : absente.
    let xml = |fichier: &Path, cle: &str| -> Option<String> {
        let r = crate::commande::lancer(
            Command::new("plutil")
                .args(["-extract", cle, "xml1", "-o", "-"])
                .arg(fichier),
            10,
        )?;
        (r.code == Some(0)).then_some(r.sortie)
    };
    let plutil = |fichier: &Path, cle: &str| -> Option<String> {
        let r = crate::commande::lancer(
            Command::new("plutil")
                .args(["-extract", cle, "raw", "-o", "-"])
                .arg(fichier),
            10,
        )?;
        let t = r.sortie.trim();
        (r.code == Some(0) && !t.is_empty()).then(|| t.to_string())
    };
    let mut fichiers: Vec<PathBuf> = std::fs::read_dir(&dossier)
        .into_iter()
        .flatten()
        .flatten()
        .map(|f| f.path())
        .filter(|p| p.extension().is_some_and(|e| e == "plist"))
        .collect();
    fichiers.sort();
    fichiers
        .iter()
        .filter_map(|f| {
            // Le plist est lu directement ; plutil ne sert qu'en secours, pour un format que le lecteur ne connaît
            // pas, jamais pour un fichier refusé par ses bornes (il développerait ses références sans limite). Un
            // fichier qui n'en est pas un (tube nommé) est sauté ; le bilan, lui, signale l'agent hostile.
            let lu = match crate::plist::lire_fichier(f).ok()? {
                crate::plist::Lu::Plist(r) => Some(r),
                crate::plist::Lu::TropGros | crate::plist::Lu::Hostile => return None,
                crate::plist::Lu::Inconnu => None,
            };
            let xml = |cle: &str| match &lu {
                Some(r) => en_xml(r.cle(cle)),
                None => xml(f, cle),
            };
            let plutil = |cle: &str| match &lu {
                Some(r) => brut(r, cle),
                None => plutil(f, cle),
            };
            let label = plutil("Label").filter(|l| label_valide(l))?;
            if !agent_au_demarrage(xml("RunAtLoad").as_deref(), xml("KeepAlive").as_deref()) {
                return None;
            }
            let programme = plutil("Program")
                .or_else(|| plutil("ProgramArguments.0"))
                .unwrap_or_else(|| f.display().to_string());
            Some(Programme {
                nom: Path::new(&programme)
                    .file_name()
                    .map_or_else(|| label.clone(), |n| n.to_string_lossy().into_owned()),
                commande: programme,
                actif: agent_actif(etats.get(&label).copied(), xml("Disabled").as_deref()),
                machine: false,
                bureau: label.starts_with("com.apple."),
                changement: Changement::Demarrage { label },
            })
        })
        .collect()
}

/// Une clé en texte, ce que donne `plutil -extract <clé> raw` (« ProgramArguments.0 » : un élément d'un tableau).
fn brut(reglages: &crate::plist::Valeur, chemin: &str) -> Option<String> {
    let mut v = reglages;
    for morceau in chemin.split('.') {
        v = match morceau.parse::<usize>() {
            Ok(i) => v.tableau()?.get(i)?,
            Err(_) => v.cle(morceau)?,
        };
    }
    let t = v.texte()?.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Une clé comme `plutil -extract <clé> xml1` l'écrit, pour les jugements de demarrage.rs, qui ne regardent que son
/// premier élément (« <true/> », « <dict> »…).
fn en_xml(v: Option<&crate::plist::Valeur>) -> Option<String> {
    use crate::plist::Valeur as V;
    let element = match v? {
        V::Booleen(true) => "<true/>",
        V::Booleen(false) => "<false/>",
        V::Entier(_) => "<integer>",
        V::Reel(_) => "<real>",
        V::Date(_) => "<date>",
        V::Donnees(_) => "<data>",
        V::Texte(_) => "<string>",
        V::Tableau(_) => "<array>",
        V::Dico(_) => "<dict>",
    };
    Some(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\">\n{element}\n</plist>\n"
    ))
}

/// Le Finder relit ses préférences à son démarrage : on le relance si l'une d'elles a changé.
pub fn apres(touches: &[&Reglage]) {
    if touches
        .iter()
        .any(|r| matches!(r.id.as_ref(), "extensions" | "fichiers_caches" | "chemin_finder"))
    {
        let _ = crate::commande::lancer(Command::new("killall").arg("Finder"), 10);
    }
}

fn pref(domaine: &'static str, cle: &'static str, cible: bool) -> Changement {
    Changement::Preference {
        domaine,
        cle,
        cible,
        defaut: None,
        admin: false,
    }
}

pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort};
    const DIAGNOSTICS: &str = "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory";
    vec![
        Reglage {
            id: "pub_personnalisee".into(),
            categorie: Confidentialite,
            titre: tr!(
                "Publicités personnalisées d'Apple coupées",
                "Apple personalized ads off"
            )
            .into(),
            effet: tr!(
                "Apple ne se sert plus de ce qu'il sait de vous pour choisir les publicités de l'App Store, d'Apple News et de Bourse.",
                "Apple no longer uses what it knows about you to pick ads in the App Store, Apple News and Stocks."
            ),
            prudence: None,
            recommande: true,
            changements: vec![pref("com.apple.AdLib", "allowApplePersonalizedAdvertising", false)],
        },
        Reglage {
            id: "analyses".into(),
            categorie: Confidentialite,
            titre: tr!("Analyses du Mac gardées pour vous", "Mac analytics kept to yourself").into(),
            effet: tr!(
                "Les rapports d'utilisation et de plantage ne partent plus chez Apple ni chez les développeurs des applications.",
                "Usage and crash reports no longer go to Apple or to app developers."
            ),
            prudence: None,
            recommande: true,
            changements: ["AutoSubmit", "ThirdPartyDataSubmit"]
                .into_iter()
                .map(|cle| Changement::Preference {
                    domaine: DIAGNOSTICS,
                    cle,
                    cible: false,
                    defaut: None,
                    admin: true,
                })
                .collect(),
        },
        Reglage {
            id: "extensions".into(),
            categorie: Confort,
            titre: tr!("Extensions des fichiers visibles", "File extensions shown").into(),
            effet: tr!(
                "Le Finder affiche « facture.pdf.app » au lieu de « facture.pdf » : un programme ne peut plus se faire passer pour un document.",
                "Finder shows “invoice.pdf.app” instead of “invoice.pdf”: a program can no longer pass for a document."
            ),
            prudence: None,
            recommande: true,
            changements: vec![pref("NSGlobalDomain", "AppleShowAllExtensions", true)],
        },
        Reglage {
            id: "ds_store".into(),
            categorie: Confort,
            titre: tr!(
                "Pas de .DS_Store sur les clés et partages",
                "No .DS_Store on drives and shares"
            )
            .into(),
            effet: tr!(
                "Le Mac n'écrit plus ses fichiers cachés .DS_Store sur les clés USB et les dossiers partagés : rien de laissé chez les autres.",
                "The Mac no longer writes its hidden .DS_Store files on USB drives and shared folders: nothing left behind on other people's things."
            ),
            prudence: None,
            recommande: true,
            changements: vec![
                pref("com.apple.desktopservices", "DSDontWriteUSBStores", true),
                pref("com.apple.desktopservices", "DSDontWriteNetworkStores", true),
            ],
        },
        Reglage {
            id: "fichiers_caches".into(),
            categorie: Confort,
            titre: tr!("Fichiers cachés visibles", "Hidden files shown").into(),
            effet: tr!(
                "Le Finder montre aussi les fichiers et dossiers cachés (Cmd-Maj-. les masque à nouveau).",
                "Finder also shows hidden files and folders (Cmd-Shift-. hides them again)."
            ),
            prudence: None,
            recommande: false,
            changements: vec![pref("com.apple.finder", "AppleShowAllFiles", true)],
        },
        Reglage {
            id: "chemin_finder".into(),
            categorie: Confort,
            titre: tr!("Chemin complet dans le Finder", "Full path in Finder").into(),
            effet: tr!(
                "Le titre des fenêtres du Finder montre le chemin complet du dossier.",
                "Finder window titles show the folder's full path."
            ),
            prudence: None,
            recommande: false,
            changements: vec![pref("com.apple.finder", "_FXShowPosixPathInTitle", true)],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_lu_sans_plutil() {
        let lire = |corps: &str| {
            crate::plist::lire(format!("<plist version=\"1.0\"><dict>{corps}</dict></plist>").as_bytes()).unwrap()
        };
        let agent = lire(
            "<key>Label</key><string> com.exemple.agent </string>\
             <key>ProgramArguments</key><array><string>/Applications/A.app/Contents/MacOS/a</string><string>-x</string></array>\
             <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>",
        );
        assert_eq!(brut(&agent, "Label").as_deref(), Some("com.exemple.agent"));
        assert_eq!(brut(&agent, "Program"), None);
        assert_eq!(
            brut(&agent, "ProgramArguments.0").as_deref(),
            Some("/Applications/A.app/Contents/MacOS/a")
        );
        assert!(agent_au_demarrage(
            en_xml(agent.cle("RunAtLoad")).as_deref(),
            en_xml(agent.cle("KeepAlive")).as_deref()
        ));
        let coupe = lire("<key>RunAtLoad</key><false/><key>KeepAlive</key><false/><key>Disabled</key><true/>");
        assert!(!agent_au_demarrage(
            en_xml(coupe.cle("RunAtLoad")).as_deref(),
            en_xml(coupe.cle("KeepAlive")).as_deref()
        ));
        assert!(!agent_actif(None, en_xml(coupe.cle("Disabled")).as_deref()));
        assert!(agent_actif(None, en_xml(agent.cle("Disabled")).as_deref()));
    }

    #[test]
    fn dns_d_un_service_reseau() {
        assert_eq!(lire_networksetup("There aren't any DNS Servers set on Wi-Fi.\n"), "");
        assert_eq!(
            lire_networksetup("1.1.1.1\n2606:4700:4700::1111\n"),
            "1.1.1.1,2606:4700:4700::1111"
        );
        let liste = "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n\
                     (Hardware Port: Wi-Fi, Device: en0)\n\n(*) Ethernet\n(Hardware Port: Ethernet, Device: en1)\n\n\
                     (2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n";
        assert_eq!(service_de(liste, "en0").as_deref(), Some("Wi-Fi"));
        assert_eq!(service_de(liste, "en1"), None, "service coupé");
        assert_eq!(service_de(liste, "en9"), None);
        let c = Changement::Dns {
            service: "Wi-Fi".into(),
            cible: Some("1.1.1.1,1.0.0.1".into()),
        };
        let cible = c.cible().unwrap();
        assert_eq!(
            c.commande(Some(&cible)).as_deref(),
            Some("sudo networksetup -setdnsservers 'Wi-Fi' 1.1.1.1 1.0.0.1")
        );
        assert_eq!(
            c.commande(c.defaut().as_deref()).as_deref(),
            Some("sudo networksetup -setdnsservers 'Wi-Fi' empty")
        );
        // Autre chose qu'une adresse IP, ou un autre service : aucune commande.
        assert_eq!(c.commande(Some("Wi-Fi\n1.1.1.1;reboot")), None);
        assert_eq!(c.commande(Some("Ethernet\n")), None);
        assert!(Changement::dns_note("Wi-Fi\n").is_some_and(|r| r.identite_dns() == Some("Wi-Fi")));
    }
}
