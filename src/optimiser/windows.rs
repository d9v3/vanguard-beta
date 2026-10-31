//! Réglages de Windows. Le registre se lit directement, sans PowerShell (une fraction de seconde pour tout le
//! catalogue). Ce qui est propre au compte (HKCU) s'écrit aussi directement, dans le compte de la personne, même si
//! la fenêtre administrateur s'ouvre sous un autre compte ; le reste (HKLM, stratégies, services) passe par une seule
//! fenêtre administrateur, après un point de restauration.

use std::process::Command;

use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE, REG_BINARY};
use winreg::{RegKey, RegValue};

use super::defender::{self, Pref};
use super::demarrage::{
    APPROUVES, Programme, desactive_windows, hex, liste_approuvee, octets, script_machine, valeur_desactivee,
};
use super::{Categorie, Reglage, Valeur};
use crate::ui::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Racine {
    /// HKCU : le compte de la personne ; Vanguard y écrit lui-même.
    Hkcu,
    /// HKCU\Software\Policies : en lecture seule pour l'utilisateur, écrit par la fenêtre administrateur dans la ruche
    /// de la personne (HKEY_USERS\<SID>), même si la fenêtre s'ouvre sous un autre compte.
    HkcuStrategie,
    /// HKLM : toute la machine, par la fenêtre administrateur.
    Hklm,
}

#[derive(Clone, Copy)]
pub enum Val {
    Dword(u32),
    Texte(&'static str),
}

impl Val {
    fn coder(self) -> String {
        match self {
            Val::Dword(d) => format!("dword:{d}"),
            Val::Texte(t) => format!("sz:{t}"),
        }
    }
}

pub enum Changement {
    /// Valeur du registre. `defaut` : celle d'un Windows neuf (`None` : absente).
    Registre {
        racine: Racine,
        chemin: &'static str,
        nom: &'static str,
        cible: Val,
        defaut: Option<Val>,
    },
    /// Clé du compte créée avec une valeur par défaut vide (présente = fait) ; `retirer`, la clé enlevée pour annuler.
    Cle {
        chemin: &'static str,
        retirer: &'static str,
    },
    /// Type de démarrage d'un service : 2 automatique, 3 manuel, 4 désactivé.
    Service { nom: &'static str, cible: u32, defaut: u32 },
    /// Serveurs DNS d'une carte réseau (outil « DNS le plus rapide »), tels que Windows les écrit dans le registre.
    /// Valeur : « {guid}\nipv4,…|ipv6,… », vide pour ceux de la box. `cible` : `None` quand le réglage n'est rebâti
    /// que pour être annulé.
    Dns { carte: String, cible: Option<String> },
    /// Programme lancé à l'ouverture de session (outil « Programmes au démarrage »), désactivé comme le fait le
    /// Gestionnaire des tâches : sa valeur dans StartupApproved\<liste> (Run, Run32, StartupFolder), de la machine
    /// (fenêtre administrateur) ou du compte. Valeur : ses octets en hexadécimal, vide si elle manque (= activé).
    /// `cible` : `None` quand le réglage n'est rebâti que pour être annulé.
    Demarrage {
        machine: bool,
        liste: &'static str,
        nom: String,
        cible: Option<String>,
    },
    /// Préférence de Microsoft Defender (voir `defender`). Valeur : « mp:1 » ; `None`, une règle ASR jamais réglée.
    Defender { pref: Pref, cible: u32 },
    /// Le mode d'alimentation actif (réglage pour jouer) : son GUID, remis par `powercfg /setactive`, sans fenêtre
    /// administrateur.
    Alimentation,
}

/// Les services qu'une correction du bilan désactive et qu'une note peut faire remettre.
const SERVICES: [&str; 1] = ["SSDPSRV"];

/// Un GUID de mode d'alimentation (« 381b4222-f694-41f0-9685-ff5bb260df2e ») : il entre tel quel dans la commande.
fn mode_valide(t: &str) -> bool {
    let parties: Vec<usize> = t.split('-').map(str::len).collect();
    parties == [8, 4, 4, 4, 12] && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Le mode d'alimentation actif, lu par powercfg ; `None` : illisible.
fn alimentation_lue() -> Option<String> {
    let r = crate::commande::lancer(
        Command::new(crate::commande::systeme32("powercfg")).arg("/getactivescheme"),
        15,
    )?;
    crate::gaming::windows::guid_alimentation(&r.sortie)
}

/// Liste de serveurs normalisée : « 1.1.1.1,1.0.0.1 », quel que soit le séparateur écrit.
fn liste_dns(t: &str) -> String {
    t.split([',', ' ', ';'])
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(",")
}

/// L'identifiant d'une carte réseau (« {xxxxxxxx-…} ») : il entre tel quel dans le registre et dans PowerShell.
fn guid_valide(t: &str) -> bool {
    t.len() == 38
        && t.starts_with('{')
        && t.ends_with('}')
        && t[1..37].chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Les serveurs d'une valeur de DNS, et ce qu'en dit l'écran.
fn decrire_dns(v: Option<&str>) -> String {
    let reste = v.and_then(|v| v.split_once('\n')).map_or("", |(_, r)| r);
    let serveurs: Vec<&str> = reste.split(['|', ',']).filter(|s| !s.is_empty()).collect();
    super::texte_dns(&serveurs, false)
}

/// La ligne « CARTE|guid|IPv6 » de la carte qui porte la route vers Internet, sans PowerShell : GetBestInterface (une
/// recherche dans la table de routage, rien n'est envoyé) puis GetAdaptersAddresses. Vide sans route par défaut ;
/// `None` si Windows refuse la liste des cartes (PowerShell la refait).
// FFI d'iphlpapi : GetBestInterface.
#[allow(unsafe_code)]
fn carte_principale() -> Option<String> {
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetBestInterface(destination: u32, index: *mut u32) -> u32;
    }
    let cartes = crate::machine::windows::cartes::cartes()?;
    let mut index = 0u32;
    // Une adresse publique quelconque (ordre réseau) : sa route est celle par défaut.
    let destination = u32::from_ne_bytes([1, 1, 1, 1]);
    // SAFETY: `index` vit pendant l'appel ; Windows n'y écrit qu'un u32.
    if unsafe { GetBestInterface(destination, &raw mut index) } != 0 {
        return Some(String::new());
    }
    Some(
        cartes
            .iter()
            .find(|c| c.index == index)
            .map(|c| format!("CARTE|{}|{}", c.guid, if c.ipv6 { "True" } else { "False" }))
            .unwrap_or_default(),
    )
}

/// Le DNS de la carte de la route par défaut, à régler sur ces serveurs ; ceux en IPv6 seulement si la carte s'en
/// sert. Erreur : pourquoi il faut le faire à la main.
pub fn dns_principal(v4: &[&str], v6: &[&str]) -> Result<Changement, String> {
    let a_la_main = tr!(
        "La carte réseau principale est illisible : le DNS se règle à la main (Paramètres > Réseau, ou dans le routeur).",
        "The main network adapter is unreadable: set the DNS by hand (Settings > Network, or in the router)."
    );
    let sortie = match carte_principale() {
        Some(ligne) => ligne,
        None => crate::machine::windows::ps(
            "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | \
             Select-Object -First 1; if ($r) { $a = Get-NetAdapter -InterfaceIndex $r.ifIndex -ErrorAction SilentlyContinue; \
             $v6 = (Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue).Enabled; \
             \"CARTE|$($a.InterfaceGuid)|$v6\" }",
        )
        .ok_or_else(|| a_la_main.to_string())?,
    };
    let (carte, ipv6) = sortie
        .lines()
        .find_map(|l| {
            let (guid, v6) = l.trim().strip_prefix("CARTE|")?.split_once('|')?;
            guid_valide(guid).then(|| (guid.to_string(), v6.eq_ignore_ascii_case("true")))
        })
        .ok_or_else(|| tr!("Pas de connexion à Internet.", "No Internet connection.").to_string())?;
    let actuel = Changement::Dns {
        carte: carte.clone(),
        cible: None,
    }
    .lire()
    .ok_or_else(|| a_la_main.to_string())?;
    let v6_actuel = actuel
        .split_once('\n')
        .and_then(|(_, r)| r.split_once('|'))
        .map_or("", |(_, v6)| v6);
    let v6 = if ipv6 && !v6.is_empty() {
        v6.join(",")
    } else {
        v6_actuel.to_string()
    };
    Ok(Changement::Dns {
        carte,
        cible: Some(format!("{}|{v6}", v4.join(","))),
    })
}

/// La ruche de toute la machine (HKLM) ou celle du compte (HKCU).
fn ruche(machine: bool) -> RegKey {
    RegKey::predef(if machine { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER })
}

fn lire_valeur(racine: Racine, chemin: &str, nom: &str) -> Valeur {
    let cle = ruche(racine == Racine::Hklm)
        .open_subkey_with_flags(chemin, KEY_READ)
        .ok()?;
    if let Ok(d) = cle.get_value::<u32, _>(nom) {
        return Some(format!("dword:{d}"));
    }
    cle.get_value::<String, _>(nom).ok().map(|t| format!("sz:{t}"))
}

/// Valeur codée (« dword:0 », « sz:texte ») : le nombre ou le texte.
enum Lue {
    Dword(u32),
    Texte(String),
}

fn decoder(v: &str) -> Option<Lue> {
    if let Some(d) = v.strip_prefix("dword:") {
        return d.parse().ok().map(Lue::Dword);
    }
    v.strip_prefix("sz:").map(|t| Lue::Texte(t.to_string()))
}

fn demarrage(n: u32) -> Option<&'static str> {
    match n {
        2 => Some("Automatic"),
        3 => Some("Manual"),
        4 => Some("Disabled"),
        _ => None,
    }
}

/// Retire une valeur du compte. Déjà absente : rien à faire, c'est réussi.
fn retirer_valeur(hkcu: &RegKey, chemin: &str, nom: &str) -> bool {
    hkcu.open_subkey_with_flags(chemin, KEY_SET_VALUE | KEY_QUERY_VALUE)
        .map_or(true, |k| k.delete_value(nom).is_ok() || k.get_raw_value(nom).is_err())
}

fn chemin_lisible(racine: Racine, chemin: &str) -> String {
    format!("{}\\{chemin}", if racine == Racine::Hklm { "HKLM" } else { "HKCU" })
}

impl Changement {
    pub fn lire(&self) -> Valeur {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => lire_valeur(*racine, chemin, nom),
            Changement::Cle { chemin, .. } => RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey_with_flags(chemin, KEY_READ)
                .ok()
                .map(|_| "cle".to_string()),
            Changement::Service { nom, .. } => lire_valeur(
                Racine::Hklm,
                &format!(r"SYSTEM\CurrentControlSet\Services\{nom}"),
                "Start",
            )
            .map(|v| v.replace("dword:", "start:")),
            Changement::Dns { carte, .. } => {
                let serveurs = |pile: &str| {
                    let cle = RegKey::predef(HKEY_LOCAL_MACHINE)
                        .open_subkey_with_flags(
                            format!(r"SYSTEM\CurrentControlSet\Services\{pile}\Parameters\Interfaces\{carte}"),
                            KEY_READ,
                        )
                        .ok()?;
                    Some(liste_dns(&cle.get_value::<String, _>("NameServer").unwrap_or_default()))
                };
                // Une carte sans IPv6 peut ne pas avoir de clé IPv6 : aucun serveur.
                Some(format!(
                    "{carte}\n{}|{}",
                    serveurs("Tcpip")?,
                    serveurs("Tcpip6").unwrap_or_default()
                ))
            }
            Changement::Demarrage {
                machine, liste, nom, ..
            } => {
                // Clé ou valeur absente : le programme est activé, comme Windows le compte.
                let valeur = ruche(*machine)
                    .open_subkey_with_flags(format!(r"{APPROUVES}\{liste}"), KEY_READ)
                    .ok()
                    .and_then(|k| k.get_raw_value(nom).ok());
                Some(valeur.map_or_else(String::new, |v| hex(&v.bytes)))
            }
            Changement::Defender { pref, .. } => defender::etat().valeur(*pref),
            Changement::Alimentation => alimentation_lue(),
        }
    }

    /// La valeur d'avant, relevée avant une correction ou un réglage pour jouer : `None` si elle ne se lit pas. Un
    /// service ou un mode d'alimentation se lit toujours ; une valeur du registre absente est une valeur (retirée
    /// pour annuler).
    pub fn relever(&self) -> Option<Valeur> {
        let v = self.lire();
        match self {
            Changement::Service { .. } | Changement::Alimentation if v.is_none() => None,
            _ => Some(v),
        }
    }

    /// Le changement que désigne un geste noté (`annulables::Geste`), s'il vise une cible de la liste fermée : un
    /// service de `SERVICES`, une valeur des réglages pour jouer, le mode d'alimentation.
    pub fn depuis_geste(geste: &str) -> Option<Changement> {
        let mut morceaux = geste.split('|');
        match (
            morceaux.next()?,
            morceaux.next(),
            morceaux.next(),
            morceaux.next(),
            morceaux.next(),
        ) {
            ("service", Some(nom), None, None, None) => {
                SERVICES.iter().find(|s| **s == nom).map(|nom| Changement::Service {
                    nom,
                    cible: 4,
                    defaut: 3,
                })
            }
            ("registre", Some(ruche), Some(cle), Some(nom), None) => crate::gaming::windows::VALEURS
                .iter()
                .find(|v| {
                    v.2 == cle
                        && v.3 == nom
                        && (v.1 == crate::gaming::windows::Ruche::Machine) == (ruche == "hklm")
                        && matches!(ruche, "hklm" | "hkcu")
                })
                .map(|&(_, r, chemin, nom, dw)| Changement::Registre {
                    racine: if r == crate::gaming::windows::Ruche::Machine {
                        Racine::Hklm
                    } else {
                        Racine::Hkcu
                    },
                    chemin,
                    nom,
                    cible: if dw { Val::Dword(0) } else { Val::Texte("") },
                    defaut: None,
                }),
            ("alimentation", None, None, None, None) => Some(Changement::Alimentation),
            // Les corrections natives (« natif|… ») et les protections de Defender (« defender|… ») n'y sont plus :
            // ce sont des protections, que Vanguard ne défait pas (`geste_de_protection`).
            _ => None,
        }
    }

    // Même forme que `lire`, pour les comparer.
    #[allow(clippy::unnecessary_wraps)]
    pub fn cible(&self) -> Valeur {
        Some(match self {
            Changement::Registre { cible, .. } => cible.coder(),
            Changement::Cle { .. } => "cle".to_string(),
            Changement::Service { cible, .. } => format!("start:{cible}"),
            // Rebâti pour être annulé : une cible qu'aucune lecture ne donne.
            Changement::Dns { carte, cible } => format!("{carte}\n{}", cible.as_deref().unwrap_or("?")),
            Changement::Demarrage { cible, .. } => cible.clone().unwrap_or_else(|| "?".to_string()),
            Changement::Defender { cible, .. } => format!("mp:{cible}"),
            // Rebâti pour être annulé seulement.
            Changement::Alimentation => "?".to_string(),
        })
    }

    pub fn defaut(&self) -> Valeur {
        match self {
            Changement::Registre { defaut, .. } => defaut.map(Val::coder),
            // Un Windows neuf : pas de clé ; règles ASR jamais réglées.
            Changement::Cle { .. } | Changement::Defender { pref: Pref::Asr(_), .. } => None,
            Changement::Service { defaut, .. } => Some(format!("start:{defaut}")),
            // Les DNS donnés par la box.
            Changement::Dns { carte, .. } => Some(format!("{carte}\n|")),
            // Sans valeur dans StartupApproved, le programme se lance.
            Changement::Demarrage { .. } => Some(String::new()),
            // Defender d'un Windows neuf : coupé.
            Changement::Defender { .. } => Some("mp:0".to_string()),
            // Pas de « Windows neuf » pour un réglage pour jouer : sans note admise, rien ne se remet.
            Changement::Alimentation => Some("?".to_string()),
        }
    }

    /// L'identité stable d'un réglage de démarrage (« hkcu|Run|Discord »), notée dans l'historique.
    pub fn identite_demarrage(&self) -> Option<String> {
        match self {
            Changement::Demarrage {
                machine, liste, nom, ..
            } => Some(format!("{}|{liste}|{nom}", if *machine { "hklm" } else { "hkcu" })),
            _ => None,
        }
    }

    /// Le réglage de démarrage rebâti d'après son identité notée, pour l'annuler. La note ne doit viser qu'une des
    /// listes de StartupApproved.
    pub fn demarrage_depuis(identite: &str) -> Option<Changement> {
        let mut parties = identite.splitn(3, '|');
        let machine = match parties.next()? {
            "hklm" => true,
            "hkcu" => false,
            _ => return None,
        };
        let liste = liste_approuvee(parties.next()?)?;
        let nom = parties.next().filter(|n| !n.is_empty())?;
        Some(Changement::Demarrage {
            machine,
            liste,
            nom: nom.to_string(),
            cible: None,
        })
    }

    /// Le nom d'un programme d'après l'identité notée : la valeur de Run, ou le raccourci sans son extension.
    pub fn nom_demarrage(identite: &str) -> String {
        let nom = identite.splitn(3, '|').nth(2).unwrap_or(identite);
        std::path::Path::new(nom)
            .file_stem()
            .filter(|_| nom.to_lowercase().ends_with(".lnk"))
            .map_or_else(|| nom.to_string(), |s| s.to_string_lossy().into_owned())
    }

    /// La carte réseau d'un réglage de DNS.
    pub fn identite_dns(&self) -> Option<&str> {
        match self {
            Changement::Dns { carte, .. } => Some(carte),
            _ => None,
        }
    }

    /// La valeur notée `v` a-t-elle une forme que ce changement peut écrire ? Elle est remise par la fenêtre
    /// administrateur pour la plupart : un ensemble fermé ou une forme stricte (nombre, adresses IP, octets), jamais
    /// un texte libre venu d'un fichier que tout programme du compte peut réécrire.
    pub fn valeur_admise(&self, v: Option<&str>) -> bool {
        match self {
            Changement::Registre { cible, racine, .. } => match (v.map(decoder), cible) {
                (None, _) | (Some(Some(Lue::Dword(_))), Val::Dword(_)) => true,
                (Some(Some(Lue::Texte(t))), Val::Texte(c)) => {
                    t == *c
                        || (t.len() <= 64 && t.chars().all(|x| x.is_ascii_alphanumeric() || " ._:-".contains(x)))
                        // Dans le compte, écrit par Vanguard lui-même, sans fenêtre administrateur : un texte
                        // court sans caractère de contrôle (« VRROptimizeEnable=0; »).
                        || (*racine == Racine::Hkcu && t.len() <= 256 && !t.chars().any(char::is_control))
                }
                _ => false,
            },
            Changement::Cle { .. } => v.is_none_or(|v| v == "cle"),
            Changement::Service { .. } => v.is_none_or(|v| {
                v.strip_prefix("start:")
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some_and(|n| n <= 4)
            }),
            Changement::Dns { carte, .. } => v.is_some_and(|v| {
                v.split_once('\n').is_some_and(|(id, reste)| {
                    id == carte
                        && guid_valide(id)
                        && reste
                            .split_once('|')
                            .is_some_and(|(quatre, six)| super::adresses_ip(quatre) && super::adresses_ip(six))
                })
            }),
            // Les octets de StartupApproved (12 octets d'ordinaire) : de l'hexadécimal, court.
            Changement::Demarrage { .. } => {
                v.is_none_or(|v| v.len() <= 64 && v.len() % 2 == 0 && v.chars().all(|c| c.is_ascii_hexdigit()))
            }
            Changement::Defender { .. } => v.is_none_or(|v| {
                v.strip_prefix("mp:")
                    .and_then(|n| n.parse::<u32>().ok())
                    .is_some_and(|n| n <= 6)
            }),
            Changement::Alimentation => v.is_some_and(mode_valide),
        }
    }

    /// La commande qui pose la valeur `v` d'un réglage de DNS (mode Wi-Fi public).
    pub fn commande_dns(&self, v: &str) -> Option<String> {
        matches!(self, Changement::Dns { .. })
            .then(|| self.commande_admin(Some(v), None))
            .flatten()
    }

    /// Le réglage de DNS rebâti d'après sa valeur d'avant notée, pour l'annuler.
    pub fn dns_note(avant: &str) -> Option<Changement> {
        let (carte, _) = avant.split_once('\n')?;
        guid_valide(carte).then(|| Changement::Dns {
            carte: carte.to_string(),
            cible: None,
        })
    }

    /// Ce qui est écrit, en clair : « HKCU\…\HideFileExt = 0 », « … : retirée », « service DiagTrack : Disabled ».
    pub fn decrire(&self, v: Option<&str>) -> String {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => {
                let ou = format!("{}\\{nom}", chemin_lisible(*racine, chemin));
                match v.and_then(decoder) {
                    Some(Lue::Dword(d)) => format!("{ou} = {d}"),
                    Some(Lue::Texte(t)) => format!("{ou} = « {t} »"),
                    None => trf!("{ou} : retirée", "{ou}: removed"),
                }
            }
            Changement::Cle { chemin, retirer } => match v {
                Some(_) => trf!("HKCU\\{chemin} : créée", "HKCU\\{chemin}: created"),
                None => trf!("HKCU\\{retirer} : retirée", "HKCU\\{retirer}: removed"),
            },
            Changement::Service { nom, .. } => {
                let mode = v
                    .and_then(|t| t.strip_prefix("start:"))
                    .and_then(|n| n.parse().ok())
                    .and_then(demarrage)
                    .unwrap_or("?");
                trf!("service {nom} : {mode}", "service {nom}: {mode}")
            }
            Changement::Dns { .. } => decrire_dns(v),
            Changement::Demarrage {
                machine, liste, nom, ..
            } => {
                let ou = format!(
                    r"{}\…\StartupApproved\{liste}\{nom}",
                    if *machine { "HKLM" } else { "HKCU" }
                );
                match v.filter(|h| !h.is_empty()) {
                    Some(h) if desactive_windows(h) => trf!(
                        "{ou} : désactivé, comme le fait le Gestionnaire des tâches",
                        "{ou}: disabled, as Task Manager does"
                    ),
                    Some(_) => trf!("{ou} : activé", "{ou}: enabled"),
                    None => trf!("{ou} : valeur retirée (activé)", "{ou}: value removed (enabled)"),
                }
            }
            Changement::Defender { pref, .. } => defender::decrire(*pref, v),
            Changement::Alimentation => format!("powercfg /setactive {}", v.unwrap_or("?")),
        }
    }

    /// Demande la fenêtre administrateur (tout sauf le compte de la personne).
    fn admin(&self) -> bool {
        !matches!(
            self,
            Changement::Registre {
                racine: Racine::Hkcu,
                ..
            } | Changement::Cle { .. }
                | Changement::Demarrage { machine: false, .. }
                | Changement::Alimentation
        )
    }

    /// Écrit dans le compte de la personne, sans fenêtre administrateur.
    fn ecrire_ici(&self, v: Option<&str>) -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        match self {
            Changement::Registre { chemin, nom, .. } => match v.and_then(decoder) {
                None => retirer_valeur(&hkcu, chemin, nom),
                Some(lue) => {
                    let Ok((k, _)) = hkcu.create_subkey(chemin) else {
                        return false;
                    };
                    match lue {
                        Lue::Dword(d) => k.set_value(nom, &d).is_ok(),
                        Lue::Texte(t) => k.set_value(nom, &t).is_ok(),
                    }
                }
            },
            Changement::Cle { chemin, retirer } => match v {
                Some(_) => hkcu
                    .create_subkey(chemin)
                    .is_ok_and(|(k, _)| k.set_value("", &String::new()).is_ok()),
                None => hkcu.delete_subkey_all(retirer).is_ok() || hkcu.open_subkey(retirer).is_err(),
            },
            // Les octets d'avant remis tels quels ; vide : la valeur retirée (le programme se lance).
            Changement::Demarrage {
                machine: false,
                liste,
                nom,
                ..
            } => {
                let chemin = format!(r"{APPROUVES}\{liste}");
                match v.filter(|h| !h.is_empty()) {
                    None => retirer_valeur(&hkcu, &chemin, nom),
                    Some(h) => {
                        let Some(o) = octets(h) else {
                            return false;
                        };
                        hkcu.create_subkey(&chemin).is_ok_and(|(k, _)| {
                            k.set_raw_value(
                                nom,
                                &RegValue {
                                    bytes: o.into(),
                                    vtype: REG_BINARY,
                                },
                            )
                            .is_ok()
                        })
                    }
                }
            }
            // powercfg, sans droits : seul un GUID de la bonne forme entre dans la commande.
            Changement::Alimentation => v.filter(|g| mode_valide(g)).is_some_and(|g| {
                crate::commande::lancer(
                    Command::new(crate::commande::systeme32("powercfg")).args(["/setactive", g]),
                    15,
                )
                .is_some_and(|r| r.code == Some(0))
            }),
            Changement::Service { .. }
            | Changement::Dns { .. }
            | Changement::Demarrage { machine: true, .. }
            | Changement::Defender { .. } => false,
        }
    }

    /// La commande PowerShell pour la fenêtre administrateur ; `sid`, celui de la personne (voir `HkcuStrategie`).
    fn commande_admin(&self, v: Option<&str>, sid: Option<&str>) -> Option<String> {
        match self {
            Changement::Registre {
                racine, chemin, nom, ..
            } => {
                let p = crate::commande::ps_texte(&match racine {
                    Racine::Hklm => format!("HKLM:\\{chemin}"),
                    Racine::Hkcu | Racine::HkcuStrategie => crate::reparer::hkcu_de_la_personne(sid, chemin),
                });
                let nom = crate::commande::ps_texte(nom);
                // Clé créée seulement si elle manque : New-Item -Force sur une clé existante l'écraserait, valeurs
                // comprises.
                let creer =
                    format!("if (-not (Test-Path -LiteralPath '{p}')) {{ New-Item -Path '{p}' -Force | Out-Null }}");
                Some(match v.and_then(decoder) {
                    None => {
                        format!("Remove-ItemProperty -LiteralPath '{p}' -Name '{nom}' -ErrorAction SilentlyContinue")
                    }
                    Some(Lue::Dword(d)) => {
                        format!("{creer}; Set-ItemProperty -LiteralPath '{p}' -Name '{nom}' -Value {d} -Type DWord")
                    }
                    Some(Lue::Texte(t)) => format!(
                        "{creer}; Set-ItemProperty -LiteralPath '{p}' -Name '{nom}' -Value '{}' -Type String",
                        crate::commande::ps_texte(&t)
                    ),
                })
            }
            Changement::Service { nom, .. } => {
                let nom = crate::commande::ps_texte(nom);
                let n: u32 = v?.strip_prefix("start:")?.parse().ok()?;
                // Désactivé : arrêté tout de suite ; remis en automatique : relancé, comme avant le changement.
                let suite = match n {
                    4 => format!("; Stop-Service -Name '{nom}' -Force -ErrorAction SilentlyContinue"),
                    2 => format!("; Start-Service -Name '{nom}' -ErrorAction SilentlyContinue"),
                    _ => String::new(),
                };
                Some(format!(
                    "Set-Service -Name '{nom}' -StartupType {}{suite}",
                    demarrage(n)?
                ))
            }
            // Écrits dans le compte de la personne par Vanguard lui-même (`ecrire_ici`).
            Changement::Cle { .. } | Changement::Demarrage { machine: false, .. } | Changement::Alimentation => None,
            Changement::Dns { carte, .. } => {
                let (id, reste) = v?.split_once('\n')?;
                if id != carte || !guid_valide(carte) {
                    return None;
                }
                // Seules des adresses IP entrent dans la commande.
                let serveurs: Vec<String> = reste
                    .split(['|', ','])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<std::net::IpAddr>().map(|ip| format!("'{ip}'")))
                    .collect::<Result<_, _>>()
                    .ok()?;
                // Remis d'abord en automatique, puis réglé : la liste écrite est exactement celle voulue, en IPv4
                // comme en IPv6.
                let reglage = if serveurs.is_empty() {
                    String::new()
                } else {
                    format!(
                        "; Set-DnsClientServerAddress -InterfaceIndex $carteDns.ifIndex -ServerAddresses @({})",
                        serveurs.join(",")
                    )
                };
                Some(format!(
                    "$carteDns = Get-NetAdapter -IncludeHidden | Where-Object {{ $_.InterfaceGuid -eq '{carte}' }} | \
                     Select-Object -First 1; if (-not $carteDns) {{ throw 'network adapter not found' }}; \
                     Set-DnsClientServerAddress -InterfaceIndex $carteDns.ifIndex -ResetServerAddresses{reglage}"
                ))
            }
            Changement::Demarrage {
                machine: true,
                liste,
                nom,
                ..
            } => script_machine(liste, nom, v),
            Changement::Defender { pref, .. } => defender::commande(*pref, v),
        }
    }
}

/// Les programmes lancés à l'ouverture de session : valeurs de Run (du compte, de la machine, et des programmes 32
/// bits) et dossiers Démarrage (du compte et de toute la machine), avec leur état dans StartupApproved. Lus dans le
/// registre et le dossier, sans PowerShell.
pub fn au_demarrage() -> Vec<Programme> {
    const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
    // Une seule heure pour tout l'écran : la valeur écrite pour désactiver, comme le Gestionnaire des tâches.
    let desactivee = valeur_desactivee(std::time::SystemTime::now());
    // Les états notés par Windows, nom en minuscules (le registre ne distingue pas la casse) → octets.
    let etats = |machine: bool, liste: &str| -> std::collections::HashMap<String, String> {
        ruche(machine)
            .open_subkey_with_flags(format!(r"{APPROUVES}\{liste}"), KEY_READ)
            .map(|k| {
                k.enum_values()
                    .flatten()
                    .map(|(n, v)| (n.to_lowercase(), hex(&v.bytes)))
                    .collect()
            })
            .unwrap_or_default()
    };
    let mut l = Vec::new();
    for (machine, chemin, liste) in [(false, RUN, "Run"), (true, RUN, "Run"), (true, RUN32, "Run32")] {
        let Ok(cle) = ruche(machine).open_subkey_with_flags(chemin, KEY_READ) else {
            continue;
        };
        let notes = etats(machine, liste);
        for (nom, valeur) in cle.enum_values().flatten() {
            l.push(Programme {
                actif: !notes.get(&nom.to_lowercase()).is_some_and(|h| desactive_windows(h)),
                commande: valeur.to_string(),
                machine,
                bureau: false,
                changement: Changement::Demarrage {
                    machine,
                    liste,
                    nom: nom.clone(),
                    cible: Some(desactivee.clone()),
                },
                nom,
            });
        }
    }
    for (machine, variable, dossier) in [
        (false, "APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
        (true, "ProgramData", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
    ] {
        let Some(base) = std::env::var_os(variable) else {
            continue;
        };
        let notes = etats(machine, "StartupFolder");
        for f in std::fs::read_dir(std::path::PathBuf::from(base).join(dossier))
            .into_iter()
            .flatten()
            .flatten()
        {
            let fichier = f.file_name().to_string_lossy().into_owned();
            if fichier.eq_ignore_ascii_case("desktop.ini") || !f.path().is_file() {
                continue;
            }
            l.push(Programme {
                nom: Changement::nom_demarrage(&fichier),
                commande: f.path().display().to_string(),
                actif: !notes.get(&fichier.to_lowercase()).is_some_and(|h| desactive_windows(h)),
                machine,
                bureau: false,
                changement: Changement::Demarrage {
                    machine,
                    liste: "StartupFolder",
                    nom: fichier,
                    cible: Some(desactivee.clone()),
                },
            });
        }
    }
    l
}

/// Applique des lots de changements (un lot par réglage) et dit lesquels ont réussi, puis chaque groupe de `en_plus`
/// (les commandes d'autres annulations, dans la même fenêtre). La fenêtre administrateur passe d'abord, point de
/// restauration en tête : refusée, rien n'est changé, pas même dans le compte de la personne.
pub fn ecrire_avec(lots: &[Vec<(&Changement, Valeur)>], en_plus: &[Vec<String>]) -> (Vec<bool>, Vec<bool>) {
    // Le SID de la personne ne sert (et n'est lu) que pour une stratégie de son compte.
    let sid = lots
        .iter()
        .flatten()
        .any(|(c, _)| matches!(c, Changement::Registre { racine, .. } if *racine == Racine::HkcuStrategie))
        .then(crate::reparer::sid_de_la_personne)
        .flatten();
    let admin: Vec<(usize, Vec<String>)> = lots
        .iter()
        .enumerate()
        .filter_map(|(i, lot)| {
            let commandes: Vec<String> = lot
                .iter()
                .filter(|(c, _)| c.admin())
                .filter_map(|(c, v)| c.commande_admin(v.as_deref(), sid.as_deref()))
                .collect();
            (!commandes.is_empty()).then_some((i, commandes))
        })
        .collect();
    let mut resultats = vec![true; lots.len()];
    let mut plus = vec![true; en_plus.len()];
    if !admin.is_empty() || !en_plus.is_empty() {
        let point = crate::reparer::point_restauration(tr!("réglages", "settings")).map(|(_, p)| p);
        let mut groupes: Vec<Vec<String>> = point.iter().map(|p| vec![p.clone()]).collect();
        groupes.extend(admin.iter().map(|(_, c)| c.clone()));
        groupes.extend(en_plus.iter().cloned());
        let mut r = crate::machine::appliquer_chacune(&groupes);
        if point.is_some() && !r.remove(0) {
            // Point de restauration refusé, ou fenêtre administrateur refusée : on ne touche à rien d'autre.
            return (vec![false; lots.len()], vec![false; en_plus.len()]);
        }
        let reste = r.split_off(admin.len().min(r.len()));
        // `i` vient de `lots.iter().enumerate()`, comme `resultats` : toujours une case.
        for ((i, _), ok) in admin.iter().zip(r) {
            if let Some(resultat) = resultats.get_mut(*i) {
                *resultat = ok;
            }
        }
        for (p, ok) in plus.iter_mut().zip(reste) {
            *p = ok;
        }
    }
    for (lot, resultat) in lots.iter().zip(resultats.iter_mut()) {
        if !*resultat {
            continue;
        }
        for (c, v) in lot.iter().filter(|(c, _)| !c.admin()) {
            println!("    {GRIS}{}{RESET}", c.decrire(v.as_deref()));
            *resultat &= c.ecrire_ici(v.as_deref());
        }
    }
    // Defender relu à la prochaine lecture : c'est elle qui dit si le changement a pris.
    if lots
        .iter()
        .flatten()
        .any(|(c, _)| matches!(c, Changement::Defender { .. }))
    {
        defender::oublier();
    }
    (resultats, plus)
}

/// Un geste d'une correction devenue une protection, tel que la 0.86 et la 0.87 le notaient : une correction native
/// de la table (« natif|wdigest-coupe ») ou une préférence de Defender (« defender|np »). Sa note d'annulation est
/// retirée au chargement (`annulables::retirer_protections`).
pub fn geste_de_protection(geste: &str) -> bool {
    use crate::machine::windows::corrections;
    match geste.split_once('|') {
        Some(("natif", id)) => corrections::analyser(&format!("{}{id}", corrections::PREFIXE)).is_some(),
        Some(("defender", cle)) => defender::pref_de(cle).is_some(),
        _ => false,
    }
}

/// Un réglage du catalogue qui est une protection (celles de Defender) : posé, Vanguard ne le défait plus, ni en le
/// décochant ni par « Tout remettre comme avant ». Une note forgée le coupait en administrateur. Seul le fait qu'il
/// a été posé par Vanguard est retenu, pour que le bilan voie une protection coupée ensuite.
pub fn reglage_protege(id: &str) -> bool {
    protection().iter().any(|r| r.id == id)
}

/// Après coup : l'Explorateur relit ses réglages à son prochain démarrage ; on propose de le relancer.
pub fn apres(touches: &[&Reglage]) {
    const EXPLORATEUR: [&str; 6] = [
        "extensions",
        "fichiers_caches",
        "ce_pc",
        "barre_gauche",
        "menu_classique",
        "fin_de_tache",
    ];
    if !touches.iter().any(|r| EXPLORATEUR.contains(&r.id.as_ref())) {
        return;
    }
    if !demander(tr!(
        "\n  Relancer l'Explorateur pour voir les changements tout de suite ? (les fenêtres de dossiers se ferment) [o/N] : ",
        "\n  Restart File Explorer to see the changes right away? (folder windows will close) [y/N]: "
    ))
    .oui()
    {
        trp!(
            "  {GRIS}Les changements de l'Explorateur apparaîtront à votre prochaine session.{RESET}",
            "  {GRIS}File Explorer changes will show at your next sign-in.{RESET}"
        );
        return;
    }
    let explorateur = || {
        crate::machine::windows::processus::liste()
            .into_iter()
            .filter(|p| p.nom.eq_ignore_ascii_case("explorer"))
            .map(|p| p.pid)
            .collect::<Vec<_>>()
    };
    // Accepté juste au-dessus : comme taskkill /f /im explorer.exe, chaque Explorateur de cette session.
    for pid in explorateur() {
        crate::machine::windows::processus::terminer(pid);
    }
    // Windows relance le bureau tout seul ; sinon on le relance.
    std::thread::sleep(std::time::Duration::from_secs(3));
    if explorateur().is_empty() {
        let _ = Command::new(crate::commande::dossier_systeme().with_file_name("explorer.exe")).spawn();
    }
}

/// Numéro de version de Windows (22000 et plus : Windows 11).
fn build() -> u32 {
    lire_valeur(
        Racine::Hklm,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuildNumber",
    )
    .and_then(|v| v.strip_prefix("sz:")?.parse().ok())
    .unwrap_or(0)
}

fn reg(racine: Racine, chemin: &'static str, nom: &'static str, cible: Val, defaut: Option<Val>) -> Changement {
    Changement::Registre {
        racine,
        chemin,
        nom,
        cible,
        defaut,
    }
}

const ANALYSE: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const EXPLORATEUR_AVANCE: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced";
const CONTENU: &str = r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager";

/// Les réglages qui conviennent à cette version de Windows.
pub fn catalogue() -> Vec<Reglage> {
    use Categorie::{Confidentialite, Confort, Performance};
    use Racine::{Hkcu, HkcuStrategie, Hklm};
    use Val::{Dword, Texte};
    let b = build();
    let windows_11 = b >= 22_000;
    let r = |id: &'static str, categorie, titre: &'static str, effet, prudence, recommande, changements| Reglage {
        id: id.into(),
        categorie,
        titre: titre.into(),
        effet,
        prudence,
        recommande,
        changements,
    };
    let mut l = vec![
        // ── Confidentialité
        r(
            "telemetrie",
            Confidentialite,
            tr!("Télémétrie au minimum", "Telemetry kept to a minimum"),
            tr!(
                "Windows n'envoie plus à Microsoft que les données de diagnostic obligatoires, et son service de collecte est arrêté. Les éditions Famille et Pro gardent ce minimum « requis ».",
                "Windows sends Microsoft only the required diagnostic data, and its collection service is stopped. Home and Pro editions keep that “required” minimum."
            ),
            None,
            true,
            vec![
                reg(Hklm, ANALYSE, "AllowTelemetry", Dword(0), None),
                Changement::Service {
                    nom: "DiagTrack",
                    cible: 4,
                    defaut: 2,
                },
            ],
        ),
        r(
            "publicite",
            Confidentialite,
            tr!("Identifiant de publicité coupé", "Advertising ID turned off"),
            tr!(
                "Les applications ne peuvent plus vous suivre de l'une à l'autre pour vous montrer de la publicité ciblée.",
                "Apps can no longer follow you from one to another to show you targeted ads."
            ),
            None,
            true,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                "Enabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "suggestions",
            Confidentialite,
            tr!("Pas de publicités dans Windows", "No ads inside Windows"),
            tr!(
                "Fini les applications installées sans votre accord (jeux mis en avant) et les suggestions dans le menu Démarrer, les Paramètres et l'écran de verrouillage.",
                "No more apps installed without your consent (promoted games), and no suggestions in Start, Settings and on the lock screen."
            ),
            None,
            true,
            [
                "SilentInstalledAppsEnabled",
                "SystemPaneSuggestionsEnabled",
                "SoftLandingEnabled",
                "SubscribedContent-338388Enabled",
                "SubscribedContent-338389Enabled",
                "SubscribedContent-353694Enabled",
                "SubscribedContent-353696Enabled",
            ]
            .into_iter()
            .map(|nom| reg(Hkcu, CONTENU, nom, Dword(0), Some(Dword(1))))
            .collect(),
        ),
        r(
            "activites",
            Confidentialite,
            tr!("Historique des activités coupé", "Activity history turned off"),
            tr!(
                "Windows ne garde plus la liste de ce que vous ouvrez (documents, sites, applications) et ne l'envoie plus à votre compte Microsoft.",
                "Windows no longer keeps the list of what you open (documents, sites, apps) nor sends it to your Microsoft account."
            ),
            None,
            true,
            ["EnableActivityFeed", "PublishUserActivities", "UploadUserActivities"]
                .into_iter()
                .map(|nom| reg(Hklm, r"SOFTWARE\Policies\Microsoft\Windows\System", nom, Dword(0), None))
                .collect(),
        ),
        r(
            "recherche_web",
            Confidentialite,
            tr!("Recherche du menu Démarrer sans Bing", "Start menu search without Bing"),
            tr!(
                "La recherche du menu Démarrer cherche dans l'ordinateur, plus sur Internet : elle répond plus vite, et ce que vous tapez ne part plus chez Microsoft.",
                "Start menu search looks in the computer, no longer on the Internet: it answers faster, and what you type no longer goes to Microsoft."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Windows\CurrentVersion\Search",
                    "BingSearchEnabled",
                    Dword(0),
                    None,
                ),
                reg(
                    HkcuStrategie,
                    r"Software\Policies\Microsoft\Windows\Explorer",
                    "DisableSearchBoxSuggestions",
                    Dword(1),
                    None,
                ),
            ],
        ),
        r(
            "avis",
            Confidentialite,
            tr!("Plus de demandes d'avis", "No more feedback requests"),
            tr!(
                "Windows ne vous demande plus votre avis par des notifications.",
                "Windows no longer asks for your feedback through notifications."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Siuf\Rules",
                    "NumberOfSIUFInPeriod",
                    Dword(0),
                    None,
                ),
                reg(Hklm, ANALYSE, "DoNotShowFeedbackNotifications", Dword(1), None),
            ],
        ),
        r(
            "saisie",
            Confidentialite,
            tr!("Ce que vous tapez reste chez vous", "What you type stays with you"),
            tr!(
                "Windows n'envoie plus d'exemples de votre frappe et de votre écriture manuscrite pour « améliorer » la reconnaissance, et ne relève plus vos contacts pour cela.",
                "Windows no longer sends samples of your typing and handwriting to “improve” recognition, nor collects your contacts for it."
            ),
            None,
            true,
            vec![
                reg(
                    Hkcu,
                    r"Software\Microsoft\Input\TIPC",
                    "Enabled",
                    Dword(0),
                    Some(Dword(1)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization",
                    "RestrictImplicitInkCollection",
                    Dword(1),
                    Some(Dword(0)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization",
                    "RestrictImplicitTextCollection",
                    Dword(1),
                    Some(Dword(0)),
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\InputPersonalization\TrainedDataStore",
                    "HarvestContacts",
                    Dword(0),
                    Some(Dword(1)),
                ),
            ],
        ),
        r(
            "experiences",
            Confidentialite,
            tr!("Pas de conseils tirés des diagnostics", "No tips based on diagnostics"),
            tr!(
                "Microsoft n'utilise plus vos données de diagnostic pour vous montrer des conseils, des publicités et des recommandations personnalisés.",
                "Microsoft no longer uses your diagnostic data to show you personalized tips, ads and recommendations."
            ),
            None,
            true,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\Privacy",
                "TailoredExperiencesWithDiagnosticDataEnabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "localisation",
            Confidentialite,
            tr!("Localisation coupée", "Location turned off"),
            tr!(
                "Ni Windows ni les applications ne savent plus où se trouve l'ordinateur.",
                "Neither Windows nor apps know where the computer is any more."
            ),
            Some(tr!(
                "La météo, les cartes et « Localiser mon appareil » ne marcheront plus.",
                "Weather, maps and “Find my device” will no longer work."
            )),
            false,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors",
                "DisableLocation",
                Dword(1),
                None,
            )],
        ),
        // ── Performance et fiabilité
        r(
            "demarrage_rapide",
            Performance,
            tr!("Démarrage rapide coupé", "Fast startup turned off"),
            tr!(
                "« Arrêter » éteint vraiment Windows : les mises à jour se terminent, les pilotes repartent à neuf, et un autre système (double démarrage) peut lire le disque sans risque.",
                "“Shut down” really turns Windows off: updates finish, drivers start fresh, and another system (dual boot) can read the disk safely."
            ),
            Some(tr!(
                "Le démarrage prend quelques secondes de plus.",
                "Startup takes a few seconds longer."
            )),
            false,
            vec![reg(
                Hklm,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                "HiberbootEnabled",
                Dword(0),
                Some(Dword(1)),
            )],
        ),
        r(
            "chemins_longs",
            Performance,
            tr!("Chemins de fichiers longs autorisés", "Long file paths allowed"),
            tr!(
                "Les programmes récents peuvent dépasser la vieille limite de 260 caractères par chemin : utile pour les projets de développement et les dossiers très imbriqués.",
                "Recent programs can go past the old 260-character path limit: handy for development projects and deeply nested folders."
            ),
            None,
            false,
            vec![reg(
                Hklm,
                r"SYSTEM\CurrentControlSet\Control\FileSystem",
                "LongPathsEnabled",
                Dword(1),
                Some(Dword(0)),
            )],
        ),
        // ── Confort et fichiers
        r(
            "extensions",
            Confort,
            tr!("Extensions des fichiers visibles", "File extensions shown"),
            tr!(
                "L'Explorateur affiche « facture.pdf.exe » au lieu de « facture.pdf » : un programme ne peut plus se faire passer pour un document.",
                "File Explorer shows “invoice.pdf.exe” instead of “invoice.pdf”: a program can no longer pass for a document."
            ),
            None,
            true,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "HideFileExt", Dword(0), Some(Dword(1)))],
        ),
        r(
            "exec_auto",
            Confort,
            tr!("Pas de lancement automatique des clés", "No autorun from USB drives"),
            tr!(
                "Brancher une clé USB, un disque ou un CD ne lance plus rien tout seul : les vers de clé USB ne peuvent plus démarrer ainsi.",
                "Plugging in a USB drive, disk or CD no longer starts anything by itself: USB worms can no longer start this way."
            ),
            None,
            true,
            vec![
                reg(
                    Hklm,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                    "NoDriveTypeAutoRun",
                    Dword(255),
                    None,
                ),
                reg(
                    Hkcu,
                    r"Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
                    "DisableAutoplay",
                    Dword(1),
                    Some(Dword(0)),
                ),
            ],
        ),
        r(
            "fichiers_caches",
            Confort,
            tr!("Fichiers cachés visibles", "Hidden files shown"),
            tr!(
                "L'Explorateur montre aussi les fichiers et dossiers cachés, comme ceux qu'un virus de clé USB dissimule.",
                "File Explorer also shows hidden files and folders, like the ones a USB virus hides."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "Hidden", Dword(1), Some(Dword(2)))],
        ),
        r(
            "ce_pc",
            Confort,
            tr!(
                "L'Explorateur s'ouvre sur « Ce PC »",
                "File Explorer opens on “This PC”"
            ),
            tr!(
                "Il montre tout de suite les disques et les clés, au lieu de l'accueil et des fichiers récents.",
                "It shows the disks and drives right away, instead of the home page and recent files."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "LaunchTo", Dword(1), None)],
        ),
        r(
            "verr_num",
            Confort,
            tr!("Verr. num. allumé à l'ouverture", "Num Lock on at sign-in"),
            tr!(
                "Le pavé numérique est prêt dès l'ouverture de votre session.",
                "The number pad is ready as soon as you sign in."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Control Panel\Keyboard",
                "InitialKeyboardIndicators",
                Texte("2"),
                Some(Texte("0")),
            )],
        ),
        r(
            "touches_remanentes",
            Confort,
            tr!(
                "Raccourci des touches rémanentes coupé",
                "Sticky Keys shortcut turned off"
            ),
            tr!(
                "Appuyer cinq fois sur Maj (en jeu, par exemple) n'ouvre plus la fenêtre des touches rémanentes. Elles restent dans les paramètres d'accessibilité.",
                "Pressing Shift five times (in a game, for example) no longer opens the Sticky Keys window. They stay available in the accessibility settings."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Control Panel\Accessibility\StickyKeys",
                "Flags",
                Texte("506"),
                Some(Texte("510")),
            )],
        ),
        r(
            "theme_sombre",
            Confort,
            tr!("Thème sombre", "Dark theme"),
            tr!(
                "Windows et les applications passent en couleurs sombres, plus reposantes le soir.",
                "Windows and apps switch to dark colors, easier on the eyes at night."
            ),
            None,
            false,
            ["AppsUseLightTheme", "SystemUsesLightTheme"]
                .into_iter()
                .map(|nom| {
                    reg(
                        Hkcu,
                        r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
                        nom,
                        Dword(0),
                        Some(Dword(1)),
                    )
                })
                .collect(),
        ),
    ];
    if windows_11 {
        l.push(r(
            "recall",
            Confidentialite,
            tr!("Recall : pas de captures de l'écran", "Recall: no screen snapshots"),
            tr!(
                "Sur les PC Copilot+, Recall photographie l'écran toutes les quelques secondes, mots de passe et messages compris. Ce réglage l'en empêche ; ailleurs, il ne change rien.",
                "On Copilot+ PCs, Recall takes a picture of the screen every few seconds, passwords and messages included. This setting prevents it; elsewhere it changes nothing."
            ),
            None,
            true,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                "DisableAIDataAnalysis",
                Dword(1),
                None,
            )],
        ));
        l.push(r(
            "widgets",
            Performance,
            tr!("Widgets retirés", "Widgets removed"),
            tr!(
                "Le panneau Widgets (actualités, météo) disparaît de la barre des tâches et ne tourne plus en arrière-plan.",
                "The Widgets panel (news, weather) leaves the taskbar and no longer runs in the background."
            ),
            None,
            false,
            vec![reg(
                Hklm,
                r"SOFTWARE\Policies\Microsoft\Dsh",
                "AllowNewsAndInterests",
                Dword(0),
                None,
            )],
        ));
        l.push(r(
            "menu_classique",
            Confort,
            tr!("Menu complet au clic droit", "Full right-click menu"),
            tr!(
                "Le clic droit montre tout de suite toutes les options, comme sous Windows 10, sans passer par « Afficher plus d'options ».",
                "Right-click shows every option right away, as on Windows 10, without going through “Show more options”."
            ),
            None,
            false,
            vec![Changement::Cle {
                chemin: r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
                retirer: r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}",
            }],
        ));
        l.push(r(
            "barre_gauche",
            Confort,
            tr!("Barre des tâches alignée à gauche", "Taskbar aligned left"),
            tr!(
                "Le bouton Démarrer et les icônes reviennent à gauche, comme sous Windows 10.",
                "The Start button and the icons go back to the left, as on Windows 10."
            ),
            None,
            false,
            vec![reg(Hkcu, EXPLORATEUR_AVANCE, "TaskbarAl", Dword(0), None)],
        ));
    } else {
        l.push(r(
            "arriere_plan",
            Performance,
            tr!("Applications en arrière-plan coupées", "Background apps turned off"),
            tr!(
                "Les applications du Store ne tournent plus une fois fermées : moins de mémoire et de batterie utilisées.",
                "Store apps no longer run once closed: less memory and battery used."
            ),
            Some(tr!(
                "Courrier, Calendrier et les autres applications du Store n'enverront plus de notifications une fois fermées.",
                "Mail, Calendar and other Store apps will no longer send notifications once closed."
            )),
            false,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
                "GlobalUserDisabled",
                Dword(1),
                Some(Dword(0)),
            )],
        ));
    }
    // « Fin de tâche » : à partir de Windows 11 23H2.
    if b >= 22_631 {
        l.push(r(
            "fin_de_tache",
            Confort,
            tr!("« Fin de tâche » dans la barre des tâches", "“End task” in the taskbar"),
            tr!(
                "Un clic droit sur une application de la barre des tâches peut la fermer de force quand elle ne répond plus (un jeu figé, par exemple).",
                "Right-clicking an app on the taskbar can force it closed when it stops responding (a frozen game, for example)."
            ),
            None,
            false,
            vec![reg(
                Hkcu,
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings",
                "TaskbarEndTask",
                Dword(1),
                None,
            )],
        ));
    }
    l.extend(protection());
    // Un service absent (édition allégée de Windows) n'est pas proposé.
    for reglage in &mut l {
        reglage
            .changements
            .retain(|c| !matches!(c, Changement::Service { .. }) || c.lire().is_some());
    }
    l
}

/// Defender est-il l'antivirus actif ? Sinon (coupé, ou passif derrière un autre antivirus), ses blocages ne
/// s'appliquent pas : rien n'est proposé.
pub fn defender_actif() -> bool {
    defender::etat().actif
}

/// Les protections de Defender qui bloquent elles-mêmes. Aucune n'est « recommandée » : elles ne sont proposées que
/// dans leur catégorie, ouverte seulement si Defender est l'antivirus actif (`defender_actif`). Leur état n'est lu
/// qu'à l'affichage, pour ne pas lancer PowerShell à chaque ouverture d'un autre menu.
fn protection() -> Vec<Reglage> {
    let defender = |pref, cible| Changement::Defender { pref, cible };
    vec![
        Reglage {
            id: "defender_asr_base".into(),
            categorie: Categorie::Protection,
            titre: tr!("Blocages de base de Defender", "Defender basic blocking").into(),
            effet: tr!(
                "Defender bloque trois techniques d'attaque courantes : le vol des mots de passe en mémoire (LSASS), l'installation de pilotes signés mais vulnérables, et la persistance cachée par WMI. Microsoft les dit sans revers. C'est Windows qui bloque, et il se protège lui-même contre la désactivation.",
                "Defender blocks three common attack techniques: stealing passwords from memory (LSASS), installing signed but vulnerable drivers, and hidden persistence through WMI. Microsoft says they have no downside. Windows does the blocking, and protects itself against being turned off."
            ),
            prudence: None,
            recommande: false,
            changements: defender::ASR_BASE.iter().map(|id| defender(Pref::Asr(id), 1)).collect(),
        },
        Reglage {
            id: "defender_asr_bureautique".into(),
            categorie: Categorie::Protection,
            titre: tr!(
                "Documents et pièces jointes piégés",
                "Booby-trapped documents and attachments"
            )
            .into(),
            effet: tr!(
                "Word, Excel, PowerPoint, Outlook et Adobe Reader ne peuvent plus lancer de programmes, créer d'exécutables ni injecter de code ; les exécutables reçus par courriel et les scripts qui lancent un téléchargement sont bloqués. C'est le chemin habituel des pièces jointes piégées.",
                "Word, Excel, PowerPoint, Outlook and Adobe Reader can no longer launch programs, create executables or inject code; executables received by email and scripts that launch a download are blocked. That is the usual path of booby-trapped attachments."
            ),
            prudence: Some(tr!(
                "Une macro ou un module Office qui lance un programme sera bloqué, avec une notification de Windows. Une protection : Vanguard ne la retire pas ensuite, un administrateur le peut (Remove-MpPreference).",
                "An Office macro or add-in that launches a program will be blocked, with a Windows notification. A protection: Vanguard does not remove it afterwards, an administrator can (Remove-MpPreference)."
            )),
            recommande: false,
            changements: defender::ASR_BUREAUTIQUE
                .iter()
                .map(|id| defender(Pref::Asr(id), 1))
                .collect(),
        },
        Reglage {
            id: "defender_reseau".into(),
            categorie: Categorie::Protection,
            titre: tr!("Protection réseau de Defender", "Defender network protection").into(),
            effet: tr!(
                "Tous les programmes, pas seulement Edge, sont empêchés de joindre les sites connus pour l'hameçonnage ou les logiciels malveillants (filtre SmartScreen de Microsoft).",
                "Every program, not only Edge, is kept from reaching sites known for phishing or malware (Microsoft's SmartScreen filter)."
            ),
            prudence: None,
            recommande: false,
            changements: vec![defender(Pref::ProtectionReseau, 1)],
        },
        Reglage {
            id: "defender_pua".into(),
            categorie: Categorie::Protection,
            titre: tr!("Logiciels indésirables bloqués", "Unwanted software blocked").into(),
            effet: tr!(
                "Defender bloque les logiciels potentiellement indésirables : publicitaires, barres d'outils, mineurs de cryptomonnaie, installateurs qui en ajoutent d'autres.",
                "Defender blocks potentially unwanted software: adware, toolbars, cryptocurrency miners, installers that add other programs."
            ),
            prudence: None,
            recommande: false,
            changements: vec![defender(Pref::Pua, 1)],
        },
        Reglage {
            id: "defender_dossiers".into(),
            categorie: Categorie::Protection,
            titre: tr!("Accès contrôlé aux dossiers", "Controlled folder access").into(),
            effet: tr!(
                "Seuls les programmes reconnus par Microsoft peuvent modifier Documents, Images, Vidéos, Musique et Favoris : un rançongiciel ne peut plus les chiffrer.",
                "Only programs Microsoft recognizes can change Documents, Pictures, Videos, Music and Favorites: ransomware can no longer encrypt them."
            ),
            prudence: Some(tr!(
                "Des jeux sauvegardent dans Documents (My Games…) et des programmes peu connus y écrivent : ils seront bloqués, avec une notification. Pour en autoriser un : Sécurité Windows › Protection contre les virus et menaces › Protection contre les rançongiciels › Autoriser une application. Les fichiers-pièges de Vanguard n'y vont plus : ils y seraient inutiles.",
                "Some games save in Documents (My Games…) and lesser-known programs write there: they will be blocked, with a notification. To allow one: Windows Security › Virus & threat protection › Ransomware protection › Allow an app. Vanguard's decoy files no longer go there: they would be useless."
            )),
            recommande: false,
            changements: vec![defender(Pref::DossiersControles, 1)],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les vraies fonctions de Windows (Wine ici, la VM ensuite), sans PowerShell : la ligne de la carte principale
    /// est vide (pas de route) ou de la forme lue par `dns_principal`.
    #[test]
    fn carte_principale_sans_powershell() {
        let ligne = carte_principale().expect("cartes réseau");
        assert!(
            ligne.is_empty() || ligne.starts_with("CARTE|{") && ligne.split('|').count() == 3,
            "{ligne}"
        );
    }

    #[test]
    fn ecrire_puis_remettre_dans_le_compte() {
        // Une clé jetable du compte : écrite, relue, puis remise à son état d'avant (absente).
        let c = reg(
            Racine::Hkcu,
            r"Software\VanguardTest\Optimiser",
            "Essai",
            Val::Dword(7),
            None,
        );
        assert_eq!(c.lire(), None);
        assert!(c.ecrire_ici(c.cible().as_deref()));
        assert_eq!(c.lire().as_deref(), Some("dword:7"));
        assert!(c.ecrire_ici(None));
        assert_eq!(c.lire(), None);
        let texte = reg(
            Racine::Hkcu,
            r"Software\VanguardTest\Optimiser",
            "Texte",
            Val::Texte("506"),
            None,
        );
        assert!(texte.ecrire_ici(texte.cible().as_deref()));
        assert_eq!(texte.lire().as_deref(), Some("sz:506"));
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(r"Software\VanguardTest");
    }

    #[test]
    fn commandes_de_la_fenetre_administrateur() {
        let c = reg(Racine::Hklm, ANALYSE, "AllowTelemetry", Val::Dword(0), None);
        let ecrire = c.commande_admin(Some("dword:0"), None).unwrap();
        assert!(
            ecrire.contains("Test-Path -LiteralPath 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection'")
        );
        assert!(ecrire.ends_with("-Name 'AllowTelemetry' -Value 0 -Type DWord"));
        assert!(c.commande_admin(None, None).unwrap().starts_with("Remove-ItemProperty"));
        // Une stratégie du compte va dans la ruche de la personne, même par la fenêtre d'un autre administrateur.
        let strategie = reg(
            Racine::HkcuStrategie,
            r"Software\Policies\Microsoft\Windows\Explorer",
            "DisableSearchBoxSuggestions",
            Val::Dword(1),
            None,
        );
        let ecrire = strategie
            .commande_admin(Some("dword:1"), Some("S-1-5-21-1-2-3-1001"))
            .unwrap();
        assert!(
            ecrire.contains(
                r"Test-Path -LiteralPath 'Registry::HKEY_USERS\S-1-5-21-1-2-3-1001\Software\Policies\Microsoft\Windows\Explorer'"
            ),
            "{ecrire}"
        );
        assert!(
            strategie
                .commande_admin(Some("dword:1"), None)
                .unwrap()
                .contains(r"'HKCU:\Software\Policies\Microsoft\Windows\Explorer'")
        );
        let s = Changement::Service {
            nom: "DiagTrack",
            cible: 4,
            defaut: 2,
        };
        assert_eq!(
            s.commande_admin(Some("start:4"), None).as_deref(),
            Some(
                "Set-Service -Name 'DiagTrack' -StartupType Disabled; Stop-Service -Name 'DiagTrack' -Force -ErrorAction SilentlyContinue"
            )
        );
        assert_eq!(
            s.commande_admin(Some("start:2"), None).as_deref(),
            Some(
                "Set-Service -Name 'DiagTrack' -StartupType Automatic; Start-Service -Name 'DiagTrack' -ErrorAction SilentlyContinue"
            )
        );
        // Une apostrophe, droite ou typographique, dans un nom ne ferme pas la chaîne PowerShell.
        let valeur = reg(Racine::Hkcu, r"Software\X", "Nom'Q", Val::Dword(0), None);
        let retrait = valeur.commande_admin(None, None).unwrap();
        assert!(retrait.contains("-Name 'Nom''Q' "), "{retrait}");
        let service = Changement::Service {
            nom: "Nom’Q",
            cible: 4,
            defaut: 2,
        };
        let arret = service.commande_admin(Some("start:4"), None).unwrap();
        assert!(arret.starts_with("Set-Service -Name 'Nom’’Q' "), "{arret}");
        assert!(arret.contains("Stop-Service -Name 'Nom’’Q' "), "{arret}");
    }

    /// Les valeurs notées remises par la fenêtre administrateur : seulement des formes fermées ou strictes. Une note
    /// réécrite par un programme du compte (un texte dans une valeur DWORD, un état de service inventé, un DNS qui
    /// n'est pas une adresse, du PowerShell glissé dans des octets) est refusée.
    #[test]
    fn valeurs_notees_validees() {
        let registre = reg(
            Racine::Hklm,
            r"SOFTWARE\Essai",
            "Valeur",
            Val::Dword(0),
            Some(Val::Dword(1)),
        );
        for bonne in [None, Some("dword:0"), Some("dword:4294967295")] {
            assert!(registre.valeur_admise(bonne), "{bonne:?}");
        }
        for mauvaise in ["sz:1", "dword:-1", "dword:1; Remove-Item x", "1"] {
            assert!(!registre.valeur_admise(Some(mauvaise)), "{mauvaise}");
        }
        let service = Changement::Service {
            nom: "DiagTrack",
            cible: 4,
            defaut: 2,
        };
        assert!(service.valeur_admise(Some("start:3")) && !service.valeur_admise(Some("start:9")));
        let carte = "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}";
        let dns = Changement::Dns {
            carte: carte.into(),
            cible: None,
        };
        assert!(dns.valeur_admise(Some(&format!("{carte}\n9.9.9.9|2620:fe::fe"))));
        assert!(dns.valeur_admise(Some(&format!("{carte}\n|"))));
        assert!(!dns.valeur_admise(Some(&format!("{carte}\nevil.example.com|"))));
        assert!(!dns.valeur_admise(Some("{00000000-0000-0000-0000-000000000000}\n9.9.9.9|")));
        let demarrage = Changement::Demarrage {
            machine: true,
            liste: "Run",
            nom: "Essai".into(),
            cible: None,
        };
        assert!(demarrage.valeur_admise(Some("030000000000000000000000")) && demarrage.valeur_admise(Some("")));
        assert!(!demarrage.valeur_admise(Some("03'; Remove-Item x")));
    }

    #[test]
    fn dns_d_une_carte_reseau() {
        let carte = "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}";
        let c = Changement::Dns {
            carte: carte.into(),
            cible: Some("1.1.1.1,1.0.0.1|2606:4700:4700::1111".into()),
        };
        let cible = c.cible().unwrap();
        let commande = c.commande_admin(Some(&cible), None).unwrap();
        assert!(
            commande.contains("-ResetServerAddresses; Set-DnsClientServerAddress"),
            "{commande}"
        );
        assert!(
            commande.contains("@('1.1.1.1','1.0.0.1','2606:4700:4700::1111')"),
            "{commande}"
        );
        let remise = c.commande_admin(c.defaut().as_deref(), None).unwrap();
        assert!(remise.ends_with("-ResetServerAddresses"), "{remise}");
        // Une autre carte, ou autre chose qu'une adresse IP : aucune commande.
        assert_eq!(c.commande_admin(Some("{autre}\n|"), None), None);
        assert_eq!(
            c.commande_admin(Some(&format!("{carte}\n1.1.1.1'; Remove-Item x|")), None),
            None
        );
        assert_eq!(
            Changement::dns_note(&format!("{carte}\n|")).and_then(|r| r.identite_dns().map(str::to_string)),
            Some(carte.to_string())
        );
        assert!(Changement::dns_note("pas une carte\n|").is_none());
        assert!(!guid_valide("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9'}"));
        assert_eq!(
            decrire_dns(Some(&cible)),
            super::super::texte_dns(&["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"], false)
        );
        assert_eq!(liste_dns("1.1.1.1 1.0.0.1,"), "1.1.1.1,1.0.0.1");
    }

    /// Programmes au démarrage : le compte s'écrit sans fenêtre administrateur, la machine par elle ; une note qui
    /// viserait une autre clé est refusée. Rien n'est écrit dans le registre.
    #[test]
    fn reglages_de_demarrage() {
        let compte = Changement::Demarrage {
            machine: false,
            liste: "Run",
            nom: "Discord".to_string(),
            cible: None,
        };
        let id = compte.identite_demarrage().unwrap();
        assert_eq!(id, "hkcu|Run|Discord");
        assert!(matches!(
            Changement::demarrage_depuis(&id),
            Some(Changement::Demarrage {
                machine: false,
                liste: "Run",
                ..
            })
        ));
        assert!(!compte.admin());
        assert_eq!(compte.commande_admin(Some("0300"), None), None);
        let machine = Changement::demarrage_depuis("hklm|StartupFolder|L’appli.lnk").unwrap();
        assert!(machine.admin());
        assert_eq!(Changement::nom_demarrage("hklm|StartupFolder|L’appli.lnk"), "L’appli");
        assert_eq!(Changement::nom_demarrage("hkcu|Run|Appli.v2"), "Appli.v2");
        let script = machine.commande_admin(None, None).unwrap();
        assert!(script.contains("DeleteValue('L’’appli.lnk', $false)"), "{script}");
        for mauvaise in ["hkcu|Policies|x", "hkxx|Run|x", "hkcu|Run|", "hkcu"] {
            assert!(Changement::demarrage_depuis(mauvaise).is_none(), "{mauvaise}");
        }
        assert!(compte.decrire(Some("")).contains("valeur retirée"));
        assert!(
            compte
                .decrire(Some(&valeur_desactivee(std::time::SystemTime::now())))
                .contains("désactivé")
        );
        assert_eq!(compte.defaut().as_deref(), Some(""));
    }
}
